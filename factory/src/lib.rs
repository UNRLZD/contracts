//! Factory (spec: docs/contract-spec.md v1). Creates one trading account per owner at
//! `<hex16(sha256(owner))>.<factory>` running the global contract by code hash.
//!
//! 1.3.0 (docs/owner-v16-spec.md §7): signed creation for key-derived owners
//! (`create_via_intents` + `on_auth` from the verifier, intents.near). The factory verifies the
//! owner's signed creation intent itself (owner-auth), records it, submits it to the verifier,
//! and creates the account in `on_auth` only against that record. Once `on_auth` holds the
//! user's NEAR it never panics: every failure refunds to the user's intents balance.
//! New state lives in raw keys only (`fv`, `fs`, `fp…`, `fo…`); the `Factory` borsh layout is
//! the 1.2.0 one, so an in-place redeploy needs no migration.
use near_sdk::json_types::{Base58CryptoHash, U128, U64};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::store::LookupSet;
use near_sdk::{
    env, near, serde_json, AccountId, Allowance, Gas, GasWeight, NearToken, PanicOnDefault, Promise,
    PromiseError, PublicKey,
};
use owner_auth::{Home, MultiPayload, OwnerAuthInit, OwnerKind};

/// Must equal trading-account DEVICE_METHODS (v1.3 adds the order methods, v1.4 the intents ones).
pub const DEVICE_METHODS: &str = "execute,withdraw_to_owner,lower_caps,place_order,cancel_order,revoke_automation,withdraw_cross_chain,remove_withdraw_destination,withdraw_from_intents,execute_order";
pub const MIN_FUNDING: NearToken = NearToken::from_millinear(200);
pub const MAX_DEVICE_KEYS: usize = 4;
/// v1.2: the account's init temporarily deposits DCL's 0.5 NEAR registration minimum on each
/// DCL-kind DEX (0.4 returns in the same receipt, 0.1 stays locked and is reclaimable).
pub const DCL_REGISTRATION: NearToken = NearToken::from_millinear(500);
const MAX_FEE_BPS: u16 = 100;
// init also schedules wrap.storage_deposit (10 TGas, v1.1) + DCL registration (20 TGas per DCL dex, v1.2)
const GAS_INIT: Gas = Gas::from_tgas(50);
/// v1.4.7: init also installs the automation key (AddKey batch + 5 TGas on_automation_set).
const GAS_INIT_AUTOMATION: Gas = Gas::from_tgas(70);
/// v1.4.7: trading-account MIN_AUTOMATION_ALLOWANCE (the account re-checks it in init).
const MIN_AUTOMATION_ALLOWANCE: u128 = 500_000_000_000_000_000_000_000;
/// v1.4.7: "no cap" (trading-account UNLIMITED); used when create_account gets no caps.
pub const UNLIMITED: u128 = u128::MAX;
const GAS_CALLBACK: Gas = Gas::from_tgas(10);

// ---- 1.3.0 signed creation (spec §7) ----
/// Default verifier (the NEAR Intents contract); `set_verifier` changes it (testnet).
pub const DEFAULT_VERIFIER: &str = "intents.near";
/// `create_via_intents` deposit (the relayer's): pays the pending record's storage, kept.
pub const PENDING_DEPOSIT: NearToken = NearToken::from_millinear(10);
/// The signed `auth_call.min_gas` must be at least this (init + callback + refund reserve).
pub const MIN_AUTH_GAS: Gas = Gas::from_tgas(200);
/// `on_auth` accepts a pending record until its deadline plus this: the auth call lands a few
/// blocks after intents checked the deadline.
pub const PENDING_GRACE_NS: u64 = 5 * 60 * 1_000_000_000;
const GAS_ON_INTENTS_EXECUTED: Gas = Gas::from_tgas(5);
const GAS_ON_CREATE_INTENTS: Gas = Gas::from_tgas(80);
const GAS_WRAP_DEPOSIT: Gas = Gas::from_tgas(5);
const GAS_REFUND_TRANSFER: Gas = Gas::from_tgas(60);
const GAS_ON_REFUND: Gas = Gas::from_tgas(5);
/// What a refund to intents costs (wrap batch + callback); `on_auth` keeps it back.
pub const GAS_REFUND: Gas = Gas::from_tgas(70);
const KEY_VERIFIER: &[u8] = b"fv";
const KEY_SIGNED_CODE: &[u8] = b"fs";
const PREFIX_PENDING: &[u8] = b"fp";
const PREFIX_OWED: &[u8] = b"fo";
// ---- 1.3.0 admin levers (docs/audit/v160-future-proofing.md F-06, F-17, F-20) ----
/// A proposed code hash (`set_code_hash`) takes effect this long after the proposal, unless a
/// fresh factory's `new` set another value (raw key `ft`; absent = this, e.g. the mainnet 1.2.0
/// state after the in-place redeploy).
pub const CODE_TIMELOCK_NS: u64 = 24 * 3_600 * 1_000_000_000;
/// Allowlist size bound for `set_dex_allowlist` (the 1.6 mainnet list has 24 entries).
pub const MAX_DEXES: usize = 32;
const KEY_PENDING_CODE: &[u8] = b"fc";
const KEY_CODE_TIMELOCK: &[u8] = b"ft";
const KEY_PENDING_ADMIN: &[u8] = b"fa";
/// Set once the one-time 1.2.0 → 1.3.0 bootstrap ran (or by a 1.3.0 `new`): `migrate` refuses.
const KEY_BOOTSTRAPPED: &[u8] = b"fb";
// ---- 1.3.0 review-2 fixes (docs/audit/v160-internal-review-2.md R2-07, R2-08, R2-13) ----
/// A proposed allowlist / fee config (same timelock as the code).
const KEY_PENDING_DEXES: &[u8] = b"fl";
const KEY_PENDING_FEE: &[u8] = b"fg";
/// The code hash `revoke_signed_code` pulled: no creation on it until another proposal is effective.
const KEY_REVOKED_CODE: &[u8] = b"fr";
/// Creation pause (`pause_creation`): borsh `Option<u64>` = the timelocked resume eta.
const KEY_PAUSED: &[u8] = b"fz";
/// F4 (external audit): a proposed verifier (`set_verifier`), same timelock as the code.
const KEY_PENDING_VERIFIER: &[u8] = b"fx";
/// At most this many `RheaDcl` entries: every new account's `init` sends DCL_REGISTRATION to
/// each (R2-07 cap: init deposits ≤ 1 N; the other kinds get no deposit at init).
pub const MAX_DCL_ENTRIES: usize = 2;

/// Same JSON shape as trading-account's Caps / Dex (passed through to `init`).
#[near(serializers = [borsh, json])]
#[derive(Clone)]
pub struct Caps {
    pub max_trade_yocto: U128,
    pub daily_cap_yocto: U128,
}

/// v1.4.7: an automation key (24/7 orders) the account installs in `init`. Same JSON shape as
/// trading-account's AutomationInit.
#[near(serializers = [json])]
#[derive(Clone)]
pub struct AutomationInit {
    pub public_key: PublicKey,
    pub allowance: U128,
    /// 1.1.1 (account v1.4.8): None = no weekly relayer limit (the default); Some = opt-in
    pub weekly_yocto: Option<U128>,
}

#[near(serializers = [borsh, json])]
#[derive(Clone)]
pub enum DexKind {
    RheaClassic,
    RheaDcl,
    Plach,
    /// 1.2.0 (account v1.5.0): Shards tokens; `id` = the Shards factory (tokens `<label>.<id>`).
    ShardsToken,
    /// 1.3.0 (account v1.6.0, docs/venues-hooks.md): launchpad curve venues. Appended, so a
    /// stored 1.2.0 allowlist decodes unchanged; same JSON as the account's `DexKind`.
    AidolsCurve(AidolsPad),
    FactoryCurve(FactoryPad),
    /// `id` = the pad's token factory (tokens `<label>.<id>`), as ShardsToken.
    TokenCurve(TokenPad),
    Kelytra,
}

/// Same variants and JSON as trading-account `venues::AidolsPad`.
#[near(serializers = [borsh, json])]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AidolsPad {
    Near,
    Patata,
    /// gaypad.j1-racing.near (quote JAMBO)
    Jambo,
    /// v1/v2.whole-market.near (quote NEARDOG)
    Neardog,
}

/// Same variants and JSON as trading-account `venues::FactoryPad`.
#[near(serializers = [borsh, json])]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FactoryPad {
    VistaLaunch,
    VistaDex,
    Nearrr,
    Nira,
    MemeCooking,
    Dragonpad,
}

/// Same variants and JSON as trading-account `venues::TokenPad`.
#[near(serializers = [borsh, json])]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TokenPad {
    NearFun,
    Umbra,
    RevShare,
    Nearmemefun,
    Token0,
    Chipfi,
    Npad,
}

#[near(serializers = [borsh, json])]
#[derive(Clone)]
pub struct Dex {
    pub id: AccountId,
    pub kind: DexKind,
}

#[near(serializers = [borsh, json])]
#[derive(Clone)]
pub struct FeeConfig {
    pub fee_bps: u16,
    pub fee_recipient: AccountId,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Factory {
    admin: AccountId,
    code_hash: Base58CryptoHash,
    fee_config: FeeConfig,
    dex_allowlist: Vec<Dex>,
    wrap: AccountId,
    /// Accounts created or being created (sync E_EXISTS; removed again on failure).
    created: LookupSet<AccountId>,
}

#[derive(Serialize)]
#[serde(crate = "near_sdk::serde")]
struct InitArgs<'a> {
    owner: &'a AccountId,
    fee_config: &'a FeeConfig,
    caps: &'a Caps,
    dex_allowlist: &'a [Dex],
    wrap: &'a AccountId,
    #[serde(skip_serializing_if = "Option::is_none")]
    automation: Option<&'a AutomationInit>,
    /// 1.3.0: only on the signed path (absent on the NEAR-wallet door).
    #[serde(skip_serializing_if = "Option::is_none")]
    owner_auth: Option<&'a OwnerAuthInit>,
    /// 1.3.0 (R2-11): the code hash this batch installs, so the account's auto-upgrade never
    /// schedules its own code again. Both doors; a ≤ 1.5 account ignores the field.
    code_hash: Base58CryptoHash,
}

#[near(serializers = [json])]
pub struct FactoryConfig {
    pub admin: AccountId,
    pub code_hash: Base58CryptoHash,
    pub fee_config: FeeConfig,
    pub dex_allowlist: Vec<Dex>,
    pub wrap: AccountId,
}

/// 1.3.0: the create message inside the signed `auth_call` (spec §7.2).
#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde", deny_unknown_fields)]
pub struct CreateMsg {
    pub v: u8,
    pub device_public_keys: Vec<PublicKey>,
    pub caps: Option<Caps>,
    pub automation: Option<AutomationInit>,
}

/// The only intent a creation payload may hold (intents `AuthCall`, pinned fa44ede9).
#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde", tag = "intent", rename_all = "snake_case", deny_unknown_fields)]
enum CreateIntent {
    AuthCall { contract_id: AccountId, msg: String, attached_deposit: U128, min_gas: U64 },
}

/// A verified creation waiting for `on_auth` (raw key `fp` ‖ sha256(owner ‖ 0 ‖ msg)).
#[near(serializers = [borsh])]
struct Pending {
    kind: OwnerKind,
    home: Home,
    /// the payload deadline
    expires_ns: u64,
    nonce: [u8; 32],
    deposit: u128,
}

/// A refund intents did not take (raw key `fo` ‖ owner): `near` still native, `wnear` already
/// wrapped in the factory's wNEAR balance. `retry_refund` resends both.
#[near(serializers = [borsh, json])]
#[derive(Default)]
pub struct Owed {
    pub near: U128,
    pub wnear: U128,
}

/// `check_create` result: what `create_via_intents` would create.
#[near(serializers = [json])]
pub struct CreateCheck {
    pub owner: AccountId,
    pub account: AccountId,
    pub kind: OwnerKind,
    pub home: Home,
    pub deposit: U128,
}

#[near(serializers = [json])]
pub struct AdminState {
    pub pending_code: Option<PendingCode>,
    pub code_timelock_ns: U64,
    pub pending_admin: Option<AccountId>,
    pub pending_dex_allowlist: Option<PendingDexes>,
    pub pending_fee_config: Option<PendingFee>,
    /// No creation on either door (`pause_creation`).
    pub creation_paused: bool,
    /// When a proposed resume takes effect (None: paused with no resume pending, or not paused).
    pub resume_eta_ns: Option<U64>,
    /// The revoked code hash while creation is blocked on it.
    pub revoked_code: Option<Base58CryptoHash>,
    /// F4: a proposed verifier not yet effective.
    pub pending_verifier: Option<PendingVerifier>,
}

/// A proposed verifier (`fx`): effective from `eta_ns`.
#[near(serializers = [borsh, json])]
#[derive(Clone)]
pub struct PendingVerifier {
    pub verifier: AccountId,
    pub eta_ns: U64,
}

/// A proposed allowlist (`fl`): effective from `eta_ns`.
#[near(serializers = [borsh, json])]
#[derive(Clone)]
pub struct PendingDexes {
    pub dex_allowlist: Vec<Dex>,
    pub eta_ns: U64,
}

/// A proposed fee config (`fg`): effective from `eta_ns`.
#[near(serializers = [borsh, json])]
#[derive(Clone)]
pub struct PendingFee {
    pub fee_config: FeeConfig,
    pub eta_ns: U64,
}

#[near(serializers = [json])]
pub struct SignedConfig {
    pub verifier: AccountId,
    pub signed_code: bool,
    pub pending_deposit: U128,
}

/// A proposed code hash (`fc`): effective from `eta_ns`.
#[near(serializers = [borsh, json])]
#[derive(Clone)]
pub struct PendingCode {
    pub code_hash: Base58CryptoHash,
    pub signed_code: bool,
    pub eta_ns: U64,
}

/// A verified creation: what the precommit stores and `check_create` reports.
struct Verified {
    owner: AccountId,
    account: AccountId,
    kind: OwnerKind,
    home: Home,
    deadline_ns: u64,
    nonce: [u8; 32],
    deposit: u128,
    msg: String,
}

/// The `create_account` key / automation checks (unchanged codes and order).
fn check_keys(keys: &[PublicKey], automation: Option<&AutomationInit>) -> Result<(), &'static str> {
    if keys.is_empty()
        || keys.len() > MAX_DEVICE_KEYS
        || (1..keys.len()).any(|i| keys[..i].contains(&keys[i]))
    {
        return Err("E_BAD_KEYS");
    }
    if let Some(a) = automation {
        if keys.contains(&a.public_key) {
            return Err("E_BAD_KEYS"); // a device key can't also be the relayer
        }
        if a.allowance.0 < MIN_AUTOMATION_ALLOWANCE {
            return Err("E_ALLOWANCE");
        }
    }
    Ok(())
}

/// `E_BAD_ALLOWLIST` unless: 1..=MAX_DEXES entries, unique ids, at most MAX_DCL_ENTRIES
/// `RheaDcl` (the only kind `init` sends a deposit to), and every id sane: not this factory or
/// an account under it (trading accounts), not `wrap`, not the verifier, not a key-derived
/// (implicit) id. Kinds are the `DexKind` variants (unknown kinds never parse).
fn check_allowlist(l: &[Dex], wrap: &AccountId, verifier: &AccountId) {
    let n = l.len();
    let me = env::current_account_id();
    let under_me = format!(".{me}");
    let dcl = l.iter().filter(|d| matches!(d.kind, DexKind::RheaDcl)).count();
    let bad_id = |id: &AccountId| {
        id == &me
            || id.as_str().ends_with(&under_me)
            || id == wrap
            || id == verifier
            || OwnerKind::from_id(id.as_str()) != OwnerKind::Named
    };
    if n == 0
        || n > MAX_DEXES
        || dcl > MAX_DCL_ENTRIES
        || l.iter().any(|d| bad_id(&d.id))
        || (1..n).any(|i| l[..i].iter().any(|d| d.id == l[i].id))
    {
        env::panic_str("E_BAD_ALLOWLIST");
    }
}

fn parse_create_msg(msg: &str) -> Result<CreateMsg, &'static str> {
    let m: CreateMsg = serde_json::from_str(msg).map_err(|_| "E_MSG")?;
    if m.v != 1 {
        return Err("E_MSG");
    }
    check_keys(&m.device_public_keys, m.automation.as_ref())?;
    Ok(m)
}

fn pending_key(owner: &str, msg: &str) -> Vec<u8> {
    let mut m = Vec::with_capacity(owner.len() + 1 + msg.len());
    m.extend_from_slice(owner.as_bytes());
    m.push(0);
    m.extend_from_slice(msg.as_bytes());
    [PREFIX_PENDING, &env::sha256_array(&m)].concat()
}

fn owed_key(owner: &AccountId) -> Vec<u8> {
    [PREFIX_OWED, owner.as_bytes()].concat()
}

fn read<T: near_sdk::borsh::BorshDeserialize>(key: &[u8]) -> Option<T> {
    env::storage_read(key).and_then(|b| near_sdk::borsh::from_slice(&b).ok())
}

fn write<T: near_sdk::borsh::BorshSerialize>(key: &[u8], v: &T) {
    env::storage_write(key, &near_sdk::borsh::to_vec(v).unwrap_or_else(|_| env::panic_str("E_BORSH")));
}

fn event(name: &str, data: serde_json::Value) {
    env::log_str(&format!(
        "EVENT_JSON:{}",
        serde_json::json!({"standard": "nttrade", "version": "1", "event": name, "data": data})
    ));
}

#[near]
impl Factory {
    #[init]
    pub fn new(
        admin: AccountId,
        code_hash: Base58CryptoHash,
        fee_config: FeeConfig,
        dex_allowlist: Vec<Dex>,
        wrap: AccountId,
        code_timelock_ns: Option<U64>,
    ) -> Self {
        if fee_config.fee_bps > MAX_FEE_BPS {
            env::panic_str("E_FEE");
        }
        // 1.3.0: a fresh factory (testnet, sandbox) may choose its code timelock; absent = 24 h
        if let Some(t) = code_timelock_ns {
            env::storage_write(KEY_CODE_TIMELOCK, &t.0.to_le_bytes());
        }
        // a fresh 1.3.0 factory never had 1.2.0 state: no bootstrap
        env::storage_write(KEY_BOOTSTRAPPED, &[1]);
        Self { admin, code_hash, fee_config, dex_allowlist, wrap, created: LookupSet::new(b"c") }
    }

    /// Affects NEW accounts only; existing accounts change code only by their own upgrade.
    /// 1.3.0: `signed_code` flags the hash as a 1.6.0+ account code (owner signatures). Any hash
    /// set without `Some(true)` is unflagged, so an unflagged hash is never approved.
    /// 1.3.0 (F-20): this only PROPOSES; `(code_hash, signed_code)` takes effect (for creation,
    /// `get_config`, `get_approved_code_hashes`) at now + the code timelock. A new proposal
    /// replaces a pending one; `cancel_code_hash` drops it.
    #[payable]
    pub fn set_code_hash(&mut self, code_hash: Base58CryptoHash, signed_code: Option<bool>) {
        self.assert_admin();
        self.settle_code();
        let eta = env::block_timestamp().saturating_add(self.code_timelock());
        let p = PendingCode { code_hash, signed_code: signed_code == Some(true), eta_ns: U64(eta) };
        write(KEY_PENDING_CODE, &p);
        event("code_hash_proposed", serde_json::json!(p));
    }

    /// 1.3.0: the ONE-TIME bootstrap of the in-place 1.2.0 → 1.3.0 redeploy, called by the
    /// factory account itself in the same tx as the code deploy (`#[private]`: only its
    /// full-access key can, and that key could redeploy any code anyway). Applies the account
    /// code hash + signed flag and the allowlist IMMEDIATELY (no timelock), drops any pending
    /// proposal, and can never run again (`E_BOOTSTRAPPED`, also on a factory made by 1.3.0
    /// `new`). Every later `set_code_hash` is timelocked.
    #[private]
    pub fn migrate(&mut self, code_hash: Base58CryptoHash, signed_code: bool, dex_allowlist: Vec<Dex>) {
        // R2-13: any 1.3.0 raw key means this is not the 1.2.0 state (e.g. a factory made by a
        // 1.3.0 `new` before `fb` existed)
        let v13 = [
            KEY_BOOTSTRAPPED,
            KEY_SIGNED_CODE,
            KEY_CODE_TIMELOCK,
            KEY_PENDING_CODE,
            KEY_VERIFIER,
            KEY_PENDING_ADMIN,
            KEY_PENDING_VERIFIER,
        ];
        if v13.iter().any(|k| env::storage_has_key(k)) {
            env::panic_str("E_BOOTSTRAPPED");
        }
        check_allowlist(&dex_allowlist, &self.wrap, &self.verifier());
        env::storage_write(KEY_BOOTSTRAPPED, &[1]);
        env::storage_remove(KEY_PENDING_CODE);
        self.code_hash = code_hash;
        env::storage_write(KEY_SIGNED_CODE, &[u8::from(signed_code)]);
        self.dex_allowlist = dex_allowlist;
        event(
            "factory_bootstrapped",
            serde_json::json!({ "code_hash": code_hash, "signed_code": signed_code, "dex_allowlist": self.dex_allowlist }),
        );
    }

    /// 1.3.0: drops the pending (not yet effective) code proposal.
    #[payable]
    pub fn cancel_code_hash(&mut self) {
        self.assert_admin();
        self.settle_code();
        let p: PendingCode = read(KEY_PENDING_CODE).unwrap_or_else(|| env::panic_str("E_NO_PENDING"));
        env::storage_remove(KEY_PENDING_CODE);
        event("code_hash_cancelled", serde_json::json!({ "code_hash": p.code_hash }));
    }

    /// 1.3.0: emergency, restrict-only, no delay: withdraws the signed approval of the
    /// effective code and drops any pending proposal. `get_approved_code_hashes` is empty, and
    /// NO account is created on that code by either door (R2-08: `E_CODE_REVOKED`) until a new
    /// proposal passes its timelock.
    #[payable]
    pub fn revoke_signed_code(&mut self) {
        self.assert_admin();
        self.settle_code();
        env::storage_write(KEY_SIGNED_CODE, &[0]);
        env::storage_remove(KEY_PENDING_CODE);
        // R2-08: no new account (either door) on the revoked code until another proposal is
        // effective
        write(KEY_REVOKED_CODE, &self.code_hash);
        event("signed_code_revoked", serde_json::json!({ "code_hash": self.code_hash }));
    }

    /// 1.3.0 (F-06): PROPOSES the venue allowlist NEW accounts get (`check_allowlist`); it
    /// takes effect at now + the timelock (R2-07), like the code. A new proposal replaces the
    /// pending one; `cancel_dex_allowlist` drops it.
    #[payable]
    pub fn set_dex_allowlist(&mut self, dex_allowlist: Vec<Dex>) {
        self.assert_admin();
        self.settle();
        check_allowlist(&dex_allowlist, &self.wrap, &self.verifier());
        // F4: nor the verifier proposed meanwhile
        if let Some(v) = read::<PendingVerifier>(KEY_PENDING_VERIFIER) {
            check_allowlist(&dex_allowlist, &self.wrap, &v.verifier);
        }
        let p = PendingDexes { dex_allowlist, eta_ns: U64(self.eta()) };
        write(KEY_PENDING_DEXES, &p);
        event("dex_allowlist_proposed", serde_json::json!(p));
    }

    #[payable]
    pub fn cancel_dex_allowlist(&mut self) {
        self.assert_admin();
        self.settle();
        if !env::storage_remove(KEY_PENDING_DEXES) {
            env::panic_str("E_NO_PENDING");
        }
        event("dex_allowlist_cancelled", serde_json::json!({}));
    }

    /// 1.3.0 (F-17): PROPOSES the fee NEW accounts get (fee_bps ≤ 100, as in `new`); effective
    /// at now + the timelock (R2-07). `cancel_fee_config` drops it.
    #[payable]
    pub fn set_fee_config(&mut self, fee_config: FeeConfig) {
        self.assert_admin();
        self.settle();
        if fee_config.fee_bps > MAX_FEE_BPS {
            env::panic_str("E_FEE");
        }
        let p = PendingFee { fee_config, eta_ns: U64(self.eta()) };
        write(KEY_PENDING_FEE, &p);
        event("fee_config_proposed", serde_json::json!(p));
    }

    #[payable]
    pub fn cancel_fee_config(&mut self) {
        self.assert_admin();
        self.settle();
        if !env::storage_remove(KEY_PENDING_FEE) {
            env::panic_str("E_NO_PENDING");
        }
        event("fee_config_cancelled", serde_json::json!({}));
    }

    /// 1.3.0 (R2-08): restrict-only, no delay: no account is created by either door
    /// (`E_PAUSED`; a signed creation already paid into `on_auth` is refunded). Also cancels a
    /// pending resume.
    #[payable]
    pub fn pause_creation(&mut self) {
        self.assert_admin();
        write(KEY_PAUSED, &None::<u64>);
        event("creation_paused", serde_json::json!({}));
    }

    /// 1.3.0 (R2-08): proposes the end of the pause, effective at now + the timelock.
    #[payable]
    pub fn resume_creation(&mut self) {
        self.assert_admin();
        if !self.creation_paused() {
            env::panic_str("E_NOT_PAUSED");
        }
        let eta = self.eta();
        write(KEY_PAUSED, &Some(eta));
        event("creation_resume_proposed", serde_json::json!({ "eta_ns": U64(eta) }));
    }

    /// 1.3.0 (F-20): step 1 of an admin change; the new admin must `accept_admin`. A new
    /// proposal replaces the pending one.
    #[payable]
    pub fn propose_admin(&mut self, new_admin: AccountId) {
        self.assert_admin();
        env::storage_write(KEY_PENDING_ADMIN, new_admin.as_bytes());
        event("admin_proposed", serde_json::json!({ "admin": self.admin, "new_admin": new_admin }));
    }

    /// 1.3.0 (F-20): step 2, by the proposed admin (1 yocto).
    #[payable]
    pub fn accept_admin(&mut self) {
        near_sdk::assert_one_yocto();
        let pending = self.pending_admin().unwrap_or_else(|| env::panic_str("E_NO_PENDING"));
        if env::predecessor_account_id() != pending {
            env::panic_str("E_NOT_ADMIN");
        }
        env::storage_remove(KEY_PENDING_ADMIN);
        event("admin_accepted", serde_json::json!({ "old_admin": self.admin, "admin": pending }));
        self.admin = pending;
    }

    /// 1.3.0: the pending code proposal (None once effective or cancelled), the timelock and
    /// the pending admin.
    pub fn get_admin_state(&self) -> AdminState {
        AdminState {
            pending_code: read::<PendingCode>(KEY_PENDING_CODE)
                .filter(|p| p.eta_ns.0 > env::block_timestamp()),
            code_timelock_ns: U64(self.code_timelock()),
            pending_admin: self.pending_admin(),
            pending_dex_allowlist: read::<PendingDexes>(KEY_PENDING_DEXES)
                .filter(|p| p.eta_ns.0 > env::block_timestamp()),
            pending_fee_config: read::<PendingFee>(KEY_PENDING_FEE)
                .filter(|p| p.eta_ns.0 > env::block_timestamp()),
            creation_paused: self.creation_paused(),
            resume_eta_ns: read::<Option<u64>>(KEY_PAUSED)
                .flatten()
                .filter(|e| *e > env::block_timestamp())
                .map(U64),
            revoked_code: self.revoked_code(),
            pending_verifier: read::<PendingVerifier>(KEY_PENDING_VERIFIER)
                .filter(|p| p.eta_ns.0 > env::block_timestamp()),
        }
    }

    /// 1.3.0: PROPOSES the verifier contract (NEAR Intents) that funds signed creations, calls
    /// `on_auth` and receives refunds. F4 (external audit): effective at now + the timelock, like
    /// the code, allowlist and fee (an instant switch let a compromised admin take every owed
    /// refund through the permissionless `retry_refund`). A new proposal replaces the pending one;
    /// `cancel_verifier` drops it. Event `verifier_proposed`; `verifier_set` when an admin call
    /// settles it (the effective value is read lazily, no poke needed).
    #[payable]
    pub fn set_verifier(&mut self, verifier: AccountId) {
        self.assert_admin();
        self.settle();
        // the effective and any pending allowlist must not list it (as `check_allowlist`)
        let listed = |l: &[Dex]| l.iter().any(|d| d.id == verifier);
        if listed(&self.dexes())
            || read::<PendingDexes>(KEY_PENDING_DEXES).is_some_and(|p| listed(&p.dex_allowlist))
        {
            env::panic_str("E_BAD_ALLOWLIST");
        }
        let p = PendingVerifier { verifier, eta_ns: U64(self.eta()) };
        write(KEY_PENDING_VERIFIER, &p);
        event("verifier_proposed", serde_json::json!(p));
    }

    #[payable]
    pub fn cancel_verifier(&mut self) {
        self.assert_admin();
        self.settle();
        if !env::storage_remove(KEY_PENDING_VERIFIER) {
            env::panic_str("E_NO_PENDING");
        }
        event("verifier_cancelled", serde_json::json!({}));
    }

    /// `device_public_key` (single, v1 form) and/or `device_public_keys` (v1.3: 1-4 keys, so
    /// onboarding is one owner signature); all become FunctionCall keys to the account with
    /// DEVICE_METHODS. v1.2.1: the factory's own `created` entry storage is paid from the
    /// deposit (spam can't drain the factory); the rest goes to the account.
    #[payable]
    /// v1.4.7: `caps` optional (default: no cap, UNLIMITED); optional `automation` = the owner's
    /// automation key, installed by the account's `init` in the same batch (one signature).
    /// 1.1.1: `automation.weekly_yocto` optional, None = no weekly relayer limit (v1.4.8 code).
    pub fn create_account(
        &mut self,
        device_public_key: Option<PublicKey>,
        device_public_keys: Option<Vec<PublicKey>>,
        caps: Option<Caps>,
        automation: Option<AutomationInit>,
    ) -> Promise {
        let owner = env::predecessor_account_id();
        let account = self.account_for(owner.clone());
        let full_deposit = env::attached_deposit();
        if let Err(e) = self.check_open() {
            env::panic_str(e);
        }
        if full_deposit < self.min_funding() {
            env::panic_str("E_MIN_FUNDING");
        }
        let mut keys: Vec<PublicKey> = device_public_key.into_iter().collect();
        keys.extend(device_public_keys.unwrap_or_default());
        if let Err(e) = check_keys(&keys, automation.as_ref()) {
            env::panic_str(e);
        }
        if !self.created.insert(account.clone()) {
            env::panic_str("E_EXISTS");
        }
        // on failure the entry is removed again (its storage freed), so the FULL deposit is refunded
        self.create_batch(&owner, &account, keys, caps, automation.as_ref(), full_deposit, None).then(
            Self::ext(env::current_account_id()).with_static_gas(GAS_CALLBACK).on_create(
                owner,
                account,
                U128(full_deposit.as_yoctonear()),
            ),
        )
    }

    #[private]
    pub fn on_create(&mut self, owner: AccountId, account: AccountId, deposit: U128) -> Option<AccountId> {
        let ok = near_sdk::is_promise_success();
        let ev = if ok { "account_created" } else { "create_failed" };
        env::log_str(&format!(
            "EVENT_JSON:{{\"standard\":\"nttrade\",\"version\":\"1\",\"event\":\"{ev}\",\"data\":{{\"owner\":\"{owner}\",\"account\":\"{account}\"}}}}"
        ));
        if ok {
            return Some(account);
        }
        self.created.remove(&account);
        Promise::new(owner).transfer(NearToken::from_yoctonear(deposit.0)).detach();
        None
    }

    // ------------------------------------------------------------ 1.3.0 signed creation

    /// Step 1 (relayer, spec §7.3): verifies the owner's signed creation intent, records it and
    /// submits it to the verifier. Nothing of the user's is held yet, so every check panics.
    #[payable]
    pub fn create_via_intents(&mut self, signed: MultiPayload) -> Promise {
        if env::attached_deposit() < PENDING_DEPOSIT {
            env::panic_str("E_PENDING_DEPOSIT");
        }
        let v = self.verify_create(&signed).unwrap_or_else(|e| env::panic_str(e));
        write(
            &pending_key(v.owner.as_str(), &v.msg),
            &Pending {
                kind: v.kind,
                home: v.home,
                expires_ns: v.deadline_ns,
                nonce: v.nonce,
                deposit: v.deposit,
            },
        );
        let args = serde_json::to_vec(&serde_json::json!({ "signed": [signed] }))
            .unwrap_or_else(|_| env::panic_str("E_JSON"));
        Promise::new(self.verifier())
            .function_call_weight(
                "execute_intents",
                args,
                NearToken::from_yoctonear(0),
                Gas::from_gas(0),
                GasWeight(1),
            )
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_ON_INTENTS_EXECUTED)
                    .with_unused_gas_weight(0)
                    .on_intents_executed(v.owner, v.msg, v.nonce.to_vec().into()),
            )
    }

    /// The checks of `create_via_intents` as a view (engine simulate step).
    pub fn check_create(&self, signed: MultiPayload) -> CreateCheck {
        let v = self.verify_create(&signed).unwrap_or_else(|e| env::panic_str(e));
        CreateCheck {
            owner: v.owner,
            account: v.account,
            kind: v.kind,
            home: v.home,
            deposit: U128(v.deposit),
        }
    }

    /// On failure (nonce used, low balance, paused) the record is dropped; on success nothing:
    /// `on_auth` may land before or after this.
    #[private]
    pub fn on_intents_executed(
        &mut self,
        owner: AccountId,
        msg: String,
        nonce: near_sdk::json_types::Base64VecU8,
    ) {
        if near_sdk::is_promise_success() {
            return;
        }
        let key = pending_key(owner.as_str(), &msg);
        if read::<Pending>(&key).is_some_and(|p| p.nonce[..] == nonce.0[..]) {
            env::storage_remove(&key);
        }
        event("create_intent_failed", serde_json::json!({ "owner": owner }));
    }

    /// Step 2 (the verifier's `auth_call`): `signer_id` signed `msg` and paid the attached
    /// deposit from its intents wNEAR. Only a wrong caller panics; past that, every failure
    /// refunds the deposit to the signer's intents balance.
    #[payable]
    pub fn on_auth(&mut self, signer_id: AccountId, msg: String) {
        if env::predecessor_account_id() != self.verifier() {
            env::panic_str("E_NOT_VERIFIER");
        }
        let d = env::attached_deposit();
        let key = pending_key(signer_id.as_str(), &msg);
        let pending = read::<Pending>(&key);
        let reason = match &pending {
            None => Some("no_precommit"),
            Some(p) if p.expires_ns.saturating_add(PENDING_GRACE_NS) < env::block_timestamp() => {
                Some("no_precommit")
            }
            Some(p) if p.deposit != d.as_yoctonear() => Some("mismatch"),
            Some(_) => None,
        };
        if pending.is_some() {
            env::storage_remove(&key); // single use, whatever happens next
        }
        let parsed = parse_create_msg(&msg);
        let reason = reason.or_else(|| parsed.as_ref().err().map(|_| "bad_msg"));
        let reason = reason.or((d < self.min_funding()).then_some("underfunded"));
        // V16-11: the code flag again (an admin code change between precommit and here must not
        // create a signer-kind account on code that ignores owner_auth)
        let reason = reason.or((!self.signed_code()).then_some("code_not_signed"));
        // R2-08: paused, or the code revoked, since the precommit
        let reason = reason.or(self.check_open().err().map(|_| "paused"));
        let (Some(p), Ok(m), None) = (pending, parsed, reason) else {
            return self.refund_to_intents(signer_id, d.as_yoctonear(), 0, reason.unwrap_or("bad_msg"));
        };
        let account = self.account_for(signer_id.clone());
        if !self.created.insert(account.clone()) {
            return self.refund_to_intents(signer_id, d.as_yoctonear(), 0, "exists");
        }
        let init = OwnerAuthInit { kind: p.kind, home: p.home };
        self.create_batch(
            &signer_id,
            &account,
            m.device_public_keys,
            m.caps,
            m.automation.as_ref(),
            d,
            Some(&init),
        )
        .then(
            Self::ext(env::current_account_id())
                .with_static_gas(GAS_ON_CREATE_INTENTS)
                .with_unused_gas_weight(0)
                .on_create_intents(signer_id, account, U128(d.as_yoctonear())),
        )
        .detach();
    }

    #[private]
    pub fn on_create_intents(&mut self, owner: AccountId, account: AccountId, deposit: U128) {
        if near_sdk::is_promise_success() {
            event("account_created", serde_json::json!({ "owner": owner, "account": account }));
            return;
        }
        event("create_failed", serde_json::json!({ "owner": owner, "account": account }));
        self.created.remove(&account);
        self.refund_to_intents(owner, deposit.0, 0, "create_failed");
    }

    /// Result of the wrap batch (`near_deposit` + `ft_transfer_call`, whose value is the amount
    /// intents used). Whatever intents did not take is owed (`fo`); never panics.
    #[private]
    pub fn on_refund(
        &mut self,
        owner: AccountId,
        near: U128,
        wnear: U128,
        #[callback_result] used: Result<U128, PromiseError>,
    ) {
        let total = near.0.saturating_add(wnear.0);
        let owed = match used {
            // the batch ran: all of it is wNEAR now; intents returned `total - used`
            Ok(u) => Owed { near: U128(0), wnear: U128(total.saturating_sub(u.0.min(total))) },
            // the batch reverted as a whole: `near` is native again, `wnear` still wrapped
            Err(_) => Owed { near, wnear },
        };
        if owed.near.0 == 0 && owed.wnear.0 == 0 {
            return;
        }
        let key = owed_key(&owner);
        let mut o: Owed = read(&key).unwrap_or_default();
        o.near = U128(o.near.0.saturating_add(owed.near.0));
        o.wnear = U128(o.wnear.0.saturating_add(owed.wnear.0));
        write(&key, &o);
        event(
            "refund_owed",
            serde_json::json!({ "owner": owner, "amount": U128(owed.near.0 + owed.wnear.0) }),
        );
    }

    /// Anyone may resend an owed refund; it can only go to `owner`'s intents balance.
    pub fn retry_refund(&mut self, owner: AccountId) {
        let key = owed_key(&owner);
        let o: Owed = read(&key).unwrap_or_else(|| env::panic_str("E_NOTHING_OWED"));
        env::storage_remove(&key);
        self.refund_to_intents(owner, o.near.0, o.wnear.0, "retry");
    }

    pub fn get_owed(&self, owner: AccountId) -> Owed {
        read(&owed_key(&owner)).unwrap_or_default()
    }

    /// Whether a verified creation for (`owner`, `msg`) is waiting for `on_auth`.
    pub fn has_pending(&self, owner: AccountId, msg: String) -> bool {
        env::storage_has_key(&pending_key(owner.as_str(), &msg))
    }

    pub fn get_signed_config(&self) -> SignedConfig {
        SignedConfig {
            verifier: self.verifier(),
            signed_code: self.signed_code(),
            pending_deposit: U128(PENDING_DEPOSIT.as_yoctonear()),
        }
    }

    /// Account code hashes the factory approves for owner-signed upgrades (spec §14): the
    /// configured code hash while it is flagged 1.6.0+ (`signed_code`), else none.
    pub fn get_approved_code_hashes(&self) -> Vec<Base58CryptoHash> {
        let (code_hash, signed) = self.effective_code();
        if signed {
            vec![code_hash]
        } else {
            vec![]
        }
    }

    pub fn account_for(&self, owner: AccountId) -> AccountId {
        let h = env::sha256_array(owner.as_bytes());
        let mut name = String::with_capacity(17 + 64);
        for b in &h[..8] {
            name.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0'));
            name.push(char::from_digit((b & 15) as u32, 16).unwrap_or('0'));
        }
        name.push('.');
        name.push_str(env::current_account_id().as_str());
        name.parse().unwrap_or_else(|_| env::panic_str("E_ACCOUNT_ID"))
    }

    /// 0.2 NEAR + 0.5 NEAR per DCL-kind allowlisted DEX (v1.2).
    pub fn min_funding(&self) -> NearToken {
        let n = self.dexes().iter().filter(|d| matches!(d.kind, DexKind::RheaDcl)).count() as u128;
        MIN_FUNDING.saturating_add(DCL_REGISTRATION.saturating_mul(n))
    }

    pub fn get_config(&self) -> FactoryConfig {
        FactoryConfig {
            admin: self.admin.clone(),
            code_hash: self.effective_code().0,
            fee_config: self.fee(),
            dex_allowlist: self.dexes(),
            wrap: self.wrap.clone(),
        }
    }
}

impl Factory {
    fn assert_admin(&self) {
        if env::predecessor_account_id() != self.admin {
            env::panic_str("E_NOT_ADMIN");
        }
        near_sdk::assert_one_yocto();
    }

    /// The effective verifier: a pending proposal past its eta wins (lazily), else the stored one.
    fn verifier(&self) -> AccountId {
        if let Some(p) =
            read::<PendingVerifier>(KEY_PENDING_VERIFIER).filter(|p| p.eta_ns.0 <= env::block_timestamp())
        {
            return p.verifier;
        }
        env::storage_read(KEY_VERIFIER)
            .and_then(|b| String::from_utf8(b).ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| DEFAULT_VERIFIER.parse().unwrap_or_else(|_| env::panic_str("E_VERIFIER")))
    }

    fn signed_code(&self) -> bool {
        self.effective_code().1
    }

    fn code_timelock(&self) -> u64 {
        env::storage_read(KEY_CODE_TIMELOCK)
            .and_then(|b| b.try_into().ok())
            .map(u64::from_le_bytes)
            .unwrap_or(CODE_TIMELOCK_NS)
    }

    fn pending_admin(&self) -> Option<AccountId> {
        env::storage_read(KEY_PENDING_ADMIN)
            .and_then(|b| String::from_utf8(b).ok())
            .and_then(|s| s.parse().ok())
    }

    /// The code new accounts get and its signed flag: a pending proposal past its eta wins
    /// (read lazily, no poke needed), else the stored pair.
    fn effective_code(&self) -> (Base58CryptoHash, bool) {
        match read::<PendingCode>(KEY_PENDING_CODE) {
            Some(p) if p.eta_ns.0 <= env::block_timestamp() => (p.code_hash, p.signed_code),
            _ => (self.code_hash, env::storage_read(KEY_SIGNED_CODE).is_some_and(|b| b == [1])),
        }
    }

    /// Writes an effective (past-eta) proposal into the stored pair (admin calls only).
    fn settle_code(&mut self) {
        if let Some(p) = read::<PendingCode>(KEY_PENDING_CODE) {
            if p.eta_ns.0 <= env::block_timestamp() {
                self.code_hash = p.code_hash;
                env::storage_write(KEY_SIGNED_CODE, &[u8::from(p.signed_code)]);
                env::storage_remove(KEY_PENDING_CODE);
                env::storage_remove(KEY_REVOKED_CODE); // a new effective proposal lifts a revoke
            }
        }
    }

    /// `settle_code` plus the allowlist / fee proposals (admin calls only).
    fn settle(&mut self) {
        self.settle_code();
        let now = env::block_timestamp();
        if let Some(p) = read::<PendingDexes>(KEY_PENDING_DEXES).filter(|p| p.eta_ns.0 <= now) {
            self.dex_allowlist = p.dex_allowlist;
            env::storage_remove(KEY_PENDING_DEXES);
        }
        if let Some(p) = read::<PendingFee>(KEY_PENDING_FEE).filter(|p| p.eta_ns.0 <= now) {
            self.fee_config = p.fee_config;
            env::storage_remove(KEY_PENDING_FEE);
        }
        if let Some(p) = read::<PendingVerifier>(KEY_PENDING_VERIFIER).filter(|p| p.eta_ns.0 <= now) {
            env::storage_write(KEY_VERIFIER, p.verifier.as_bytes());
            env::storage_remove(KEY_PENDING_VERIFIER);
            event("verifier_set", serde_json::json!({ "verifier": p.verifier }));
        }
    }

    fn eta(&self) -> u64 {
        env::block_timestamp().saturating_add(self.code_timelock())
    }

    /// The allowlist new accounts get: an effective proposal wins (lazily).
    fn dexes(&self) -> Vec<Dex> {
        match read::<PendingDexes>(KEY_PENDING_DEXES) {
            Some(p) if p.eta_ns.0 <= env::block_timestamp() => p.dex_allowlist,
            _ => self.dex_allowlist.clone(),
        }
    }

    fn fee(&self) -> FeeConfig {
        match read::<PendingFee>(KEY_PENDING_FEE) {
            Some(p) if p.eta_ns.0 <= env::block_timestamp() => p.fee_config,
            _ => self.fee_config.clone(),
        }
    }

    /// Paused, unless a proposed resume is past its eta.
    fn creation_paused(&self) -> bool {
        match read::<Option<u64>>(KEY_PAUSED) {
            None => false,
            Some(None) => true,
            Some(Some(eta)) => eta > env::block_timestamp(),
        }
    }

    /// The revoked hash while it is still the creation code (an effective proposal lifts it).
    fn revoked_code(&self) -> Option<Base58CryptoHash> {
        let r: Base58CryptoHash = read(KEY_REVOKED_CODE)?;
        let pending_effective =
            read::<PendingCode>(KEY_PENDING_CODE).is_some_and(|p| p.eta_ns.0 <= env::block_timestamp());
        (!pending_effective && r == self.code_hash).then_some(r)
    }

    /// Creation (either door) is open: not paused (`E_PAUSED`), not on revoked code
    /// (`E_CODE_REVOKED`).
    fn check_open(&self) -> Result<(), &'static str> {
        if self.creation_paused() {
            return Err("E_PAUSED");
        }
        if self.revoked_code().is_some() {
            return Err("E_CODE_REVOKED");
        }
        Ok(())
    }

    /// Spec §7.3 step 1-2 (no writes).
    fn verify_create(&self, signed: &MultiPayload) -> Result<Verified, &'static str> {
        self.check_open()?;
        if !self.signed_code() {
            return Err("E_CODE_NOT_SIGNED"); // a pre-1.6.0 account would ignore owner_auth
        }
        let body = owner_auth::parse_intents::<Vec<CreateIntent>>(signed)?;
        let key = owner_auth::verify(signed)?;
        // creation is by the implicit key only (the factory cannot read intents' added keys)
        if body.signer_id != key.implicit_id() {
            return Err("E_NOT_OWNER");
        }
        if body.verifying_contract != self.verifier().as_str() {
            return Err("E_VERIFYING_CONTRACT");
        }
        owner_auth::check_deadline(
            body.deadline_ns,
            env::block_timestamp(),
            owner_auth::OWNER_PAYLOAD_TTL_NS,
        )?;
        let [CreateIntent::AuthCall { contract_id, msg, attached_deposit, min_gas }] =
            <[CreateIntent; 1]>::try_from(body.items).map_err(|_| "E_INTENT")?;
        if contract_id != env::current_account_id()
            || attached_deposit.0 < self.min_funding().as_yoctonear()
            || min_gas.0 < MIN_AUTH_GAS.as_gas()
        {
            return Err("E_INTENT");
        }
        parse_create_msg(&msg)?;
        let owner: AccountId = body.signer_id.parse().map_err(|_| "E_NOT_OWNER")?;
        let account = self.account_for(owner.clone());
        if self.created.contains(&account) {
            return Err("E_EXISTS");
        }
        Ok(Verified {
            owner,
            account,
            kind: key.kind(),
            home: owner_auth::home_for(signed.standard()),
            deadline_ns: body.deadline_ns,
            nonce: body.nonce,
            deposit: attached_deposit.0,
            msg,
        })
    }

    /// The account-creation batch both paths use: create, fund (minus the `created` entry's
    /// storage), global code, device keys, `init`.
    #[allow(clippy::too_many_arguments)]
    fn create_batch(
        &self,
        owner: &AccountId,
        account: &AccountId,
        keys: Vec<PublicKey>,
        caps: Option<Caps>,
        automation: Option<&AutomationInit>,
        full_deposit: NearToken,
        owner_auth: Option<&OwnerAuthInit>,
    ) -> Promise {
        let caps =
            caps.unwrap_or(Caps { max_trade_yocto: U128(UNLIMITED), daily_cap_yocto: U128(UNLIMITED) });
        // LookupSet record: key = prefix(1) + borsh(AccountId) (4 + len), empty value, plus the
        // protocol's 40 bytes per storage record.
        let entry_bytes = 1 + 4 + account.as_str().len() as u128 + 40;
        let entry_cost = env::storage_byte_cost().saturating_mul(entry_bytes);
        let deposit = full_deposit.saturating_sub(entry_cost);
        let (fee_config, dex_allowlist, code_hash) = (self.fee(), self.dexes(), self.effective_code().0);
        let args = serde_json::to_vec(&InitArgs {
            owner,
            fee_config: &fee_config,
            caps: &caps,
            dex_allowlist: &dex_allowlist,
            wrap: &self.wrap,
            automation,
            owner_auth,
            code_hash,
        })
        .unwrap_or_else(|_| env::panic_str("E_JSON"));
        let mut batch =
            Promise::new(account.clone()).create_account().transfer(deposit).use_global_contract(code_hash);
        for k in keys {
            batch = batch.add_access_key_allowance(k, Allowance::Unlimited, account.clone(), DEVICE_METHODS);
        }
        let gas_init = if automation.is_some() { GAS_INIT_AUTOMATION } else { GAS_INIT };
        batch.function_call("init", args, NearToken::from_yoctonear(0), gas_init)
    }

    /// Sends `near` (wrapped first) + `wnear` to `owner`'s balance at the verifier, as one wrap
    /// batch (atomic: a failing transfer also undoes the wrap), then `on_refund`. Never panics.
    fn refund_to_intents(&mut self, owner: AccountId, near: u128, wnear: u128, reason: &str) {
        let total = near.saturating_add(wnear);
        event(
            "create_refunded",
            serde_json::json!({ "owner": owner, "amount": U128(total), "reason": reason }),
        );
        if total == 0 {
            return;
        }
        let transfer = serde_json::json!({
            "receiver_id": self.verifier(), "amount": U128(total), "msg": owner,
        });
        let mut batch = Promise::new(self.wrap.clone());
        if near > 0 {
            batch = batch.function_call(
                "near_deposit",
                b"{}".to_vec(),
                NearToken::from_yoctonear(near),
                GAS_WRAP_DEPOSIT,
            );
        }
        batch
            .function_call(
                "ft_transfer_call",
                serde_json::to_vec(&transfer).unwrap_or_default(),
                NearToken::from_yoctonear(1),
                GAS_REFUND_TRANSFER,
            )
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(GAS_ON_REFUND)
                    .with_unused_gas_weight(0)
                    .on_refund(owner, U128(near), U128(wnear)),
            )
            .detach();
    }
}
#[cfg(test)]
mod tests_v13;

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;

    fn factory_at(id: &str) -> Factory {
        testing_env!(VMContextBuilder::new().current_account_id(id.parse().unwrap()).build());
        Factory::new(
            "admin.near".parse().unwrap(),
            [7u8; 32].into(),
            FeeConfig { fee_bps: 100, fee_recipient: "fees.near".parse().unwrap() },
            vec![],
            "wrap.near".parse().unwrap(),
            None,
        )
    }

    /// v1.4.5 (INV-69): E_ACCOUNT_ID. `account_for` = 16 hex + "." + factory id, always a valid
    /// account id while the factory id is <= 47 chars (64 - 17); any owner id works.
    #[test]
    fn inv69_account_for_valid_up_to_47_char_factory() {
        let f = factory_at(&format!("{}.near", "f".repeat(42))); // 47 chars
        for owner in [
            "a.near",
            "owner.near",
            &"9".repeat(64),
            "x.y.z.tg",
            "0000000000000000000000000000000000000000000000000000000000000000",
        ] {
            let a = f.account_for(owner.parse().unwrap());
            assert_eq!(a.as_str().len(), 17 + 47);
        }
    }

    /// A factory account id of 48+ chars makes every name too long: E_ACCOUNT_ID (a deploy-config
    /// condition, checked by contracts/scripts/check-factory.sh's pinned factory id in practice).
    #[test]
    fn inv69_account_for_rejects_overlong_factory_id() {
        let f = factory_at(&format!("{}.near", "f".repeat(43))); // 48 chars
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            f.account_for("a.near".parse().unwrap())
        }));
        let e = r.expect_err("expected E_ACCOUNT_ID");
        let m = e.downcast_ref::<String>().cloned().unwrap_or_default();
        assert!(m.contains("E_ACCOUNT_ID"), "{m}");
    }
}
