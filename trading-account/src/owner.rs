//! v1.6 universal owner (docs/owner-v16-spec.md §2–§5, API §6.1): the signed door
//! (`owner_signed`), owner kind + auth keys + salt (`ow`), used nonces (`un`), home withdraws for
//! signer-kind owners, and the cross-chain home destination. The owner action bodies are the ones
//! the predecessor `owner_*` methods run (lib.rs, "owner action bodies").
use crate::*;
use owner_auth::{
    self as oa, Home, MultiPayload, NonceStore, OwnerAuthInit, OwnerKind, PublicKey as AuthKey,
};

pub const K_OWNER_AUTH: &[u8] = b"ow";
pub const K_OWNER_NONCES: &[u8] = b"un";
/// `withdraw_cross_chain(dest_id = HOME_DEST)`: the destination is derived from the owner (§5.2).
pub const HOME_DEST: u32 = u32::MAX;
/// Signed `upgrade`: the factory's `get_approved_code_hashes` read, then `on_upgrade_checked`.
const GAS_FACTORY_VIEW: u64 = 5;
/// on_upgrade_checked: itself + UseGlobalContract + migrate (GAS_MIGRATE) + the guard call.
const GAS_UPGRADE_CB: u64 = 60;

/// The owner's signing setup (spec §4.1), borsh under `ow`.
#[near(serializers = [borsh])]
#[derive(Clone, Debug, PartialEq)]
pub struct OwnerAuth {
    pub kind: OwnerKind,
    pub home: Home,
    pub signed_enabled: bool,
    /// the key the owner id is derived from may sign (off = "my original key leaked")
    pub implicit_enabled: bool,
    pub auth_keys: Vec<AuthKey>,
    pub salt: [u8; 4],
    /// Home = the owner's intents.near balance. Only for owners created through the signed path
    /// (factory 1.3.0 `owner_auth`). NEAR-wallet owners (named, and 64-hex / 0x accounts created
    /// or migrated by the id rule) keep 1.5's native withdraw to the owner account (owner rule:
    /// no existing user's experience gets worse).
    pub intents_home: bool,
}

/// The stored record; absent (code 1.6 without `migrate`, never in practice) = the id rule with
/// signatures off.
pub fn owner_auth(owner: &AccountId) -> OwnerAuth {
    env::storage_read(K_OWNER_AUTH)
        .map(|b| near_sdk::borsh::from_slice(&b).unwrap_or_else(|_| fail("E_STATE")))
        .unwrap_or(OwnerAuth {
            kind: OwnerKind::from_id(owner.as_str()),
            home: Home::Near,
            signed_enabled: false,
            implicit_enabled: true,
            auth_keys: vec![],
            salt: [0; 4],
            intents_home: false,
        })
}

fn save_owner_auth(a: &OwnerAuth) {
    env::storage_write(K_OWNER_AUTH, &near_sdk::borsh::to_vec(a).unwrap_or_else(|_| fail("E_STATE")));
}

/// sha256(random_seed ‖ previous salt)[..4], never equal to the previous salt (a rotation always
/// voids every payload signed under the old one).
fn random_salt(prev: [u8; 4]) -> [u8; 4] {
    let h = env::sha256_array([env::random_seed_array().as_slice(), &prev].concat());
    let mut s = [h[0], h[1], h[2], h[3]];
    if s == prev {
        s[0] ^= 1;
    }
    s
}

/// `init` / `migrate` (spec §3): a verified creation (factory 1.3.0 passes `init`) has signatures
/// on and its kind must fit the id; otherwise the id rule, with signatures on only for `0x`
/// (Secp256k1: an eth-implicit key cannot rotate).
pub(crate) fn write_initial_owner_auth(owner: &AccountId, init: Option<OwnerAuthInit>) {
    let by_id = OwnerKind::from_id(owner.as_str());
    let a = match init {
        Some(i) => {
            let fits = match i.kind {
                OwnerKind::Named => false,
                OwnerKind::Ed25519 => by_id == OwnerKind::Ed25519,
                OwnerKind::Secp256k1 | OwnerKind::P256 => by_id == OwnerKind::Secp256k1,
            };
            if !fits || (i.home == Home::Solana && i.kind != OwnerKind::Ed25519) {
                fail("E_OWNER_KIND");
            }
            OwnerAuth {
                kind: i.kind,
                home: i.home,
                signed_enabled: true,
                implicit_enabled: true,
                auth_keys: vec![],
                salt: random_salt([0; 4]),
                intents_home: true,
            }
        }
        None => OwnerAuth {
            kind: by_id,
            home: Home::Near,
            signed_enabled: by_id == OwnerKind::Secp256k1,
            implicit_enabled: true,
            auth_keys: vec![],
            salt: random_salt([0; 4]),
            intents_home: false,
        },
    };
    save_owner_auth(&a);
}

fn nonces() -> NonceStore {
    env::storage_read(K_OWNER_NONCES)
        .map(|b| near_sdk::borsh::from_slice(&b).unwrap_or_else(|_| fail("E_STATE")))
        .unwrap_or_default()
}

/// One owner op (spec §2.4). Arguments are those of the matching `owner_*` method.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde", tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum OwnerOp {
    AddKey {
        public_key: PublicKey,
    },
    RemoveKey {
        public_key: PublicKey,
    },
    Withdraw {
        token: Option<AccountId>,
        amount: U128,
        to: AccountId,
    },
    WithdrawAll {
        to: AccountId,
        tokens: Vec<AccountId>,
    },
    WithdrawHome {
        token: Option<AccountId>,
        amount: U128,
    },
    SetCaps {
        caps: Caps,
    },
    SetAutomationKey {
        public_key: PublicKey,
        allowance: U128,
    },
    /// (unit ops are empty structs, so `deny_unknown_fields` applies to them too)
    RevokeAutomation {},
    ClearRelayerKey {
        public_key: PublicKey,
    },
    SetRelayerAllowance {
        weekly_yocto: U128,
    },
    ReclaimDexStorage {
        dex: AccountId,
    },
    AddWithdrawDestination {
        label: String,
        asset: String,
        recipient: String,
        recipient_type: String,
    },
    RemoveWithdrawDestination {
        dest_id: u32,
    },
    SetOneclickConfig {
        keys: Vec<String>,
        max_slippage_bps: u16,
        intents: Option<AccountId>,
        max_loss_bps: Option<u16>,
    },
    SetWithdrawCap {
        daily_cap_yocto: Option<U128>,
        daily_cap_usd: Option<U128>,
    },
    WithdrawFromIntents {
        token: AccountId,
        amount: U128,
    },
    WithdrawViaIntents {
        token: AccountId,
        amount: U128,
        deposit_address: String,
    },
    Upgrade {
        code_hash: Base58CryptoHash,
    },
    AddAuthKey {
        public_key: AuthKey,
    },
    RemoveAuthKey {
        public_key: AuthKey,
    },
    SetImplicitKey {
        enabled: bool,
    },
    RotateSalt {},
    /// F-01
    SetAutoUpgrade {
        enabled: bool,
    },
    CancelAutoUpgrade {},
    /// F-19
    Rescue {
        asset: crate::upgrade::RescueAsset,
    },
}

impl OwnerOp {
    pub fn name(&self) -> &'static str {
        match self {
            OwnerOp::AddKey { .. } => "add_key",
            OwnerOp::RemoveKey { .. } => "remove_key",
            OwnerOp::Withdraw { .. } => "withdraw",
            OwnerOp::WithdrawAll { .. } => "withdraw_all",
            OwnerOp::WithdrawHome { .. } => "withdraw_home",
            OwnerOp::SetCaps { .. } => "set_caps",
            OwnerOp::SetAutomationKey { .. } => "set_automation_key",
            OwnerOp::RevokeAutomation {} => "revoke_automation",
            OwnerOp::ClearRelayerKey { .. } => "clear_relayer_key",
            OwnerOp::SetRelayerAllowance { .. } => "set_relayer_allowance",
            OwnerOp::ReclaimDexStorage { .. } => "reclaim_dex_storage",
            OwnerOp::AddWithdrawDestination { .. } => "add_withdraw_destination",
            OwnerOp::RemoveWithdrawDestination { .. } => "remove_withdraw_destination",
            OwnerOp::SetOneclickConfig { .. } => "set_oneclick_config",
            OwnerOp::SetWithdrawCap { .. } => "set_withdraw_cap",
            OwnerOp::WithdrawFromIntents { .. } => "withdraw_from_intents",
            OwnerOp::WithdrawViaIntents { .. } => "withdraw_via_intents",
            OwnerOp::Upgrade { .. } => "upgrade",
            OwnerOp::AddAuthKey { .. } => "add_auth_key",
            OwnerOp::RemoveAuthKey { .. } => "remove_auth_key",
            OwnerOp::SetImplicitKey { .. } => "set_implicit_key",
            OwnerOp::RotateSalt {} => "rotate_salt",
            OwnerOp::SetAutoUpgrade { .. } => "set_auto_upgrade",
            OwnerOp::CancelAutoUpgrade {} => "cancel_auto_upgrade",
            OwnerOp::Rescue { .. } => "rescue",
        }
    }

    /// The op as the summary (event, `owner_signed_check`) names it: key ops carry the key and
    /// its kind, so a monitor sees exactly which key an owner signature installed.
    pub fn summary(&self) -> String {
        match self {
            OwnerOp::AddKey { public_key } => format!("add_key {} device", String::from(public_key)),
            OwnerOp::SetAutomationKey { public_key, .. } => {
                format!("set_automation_key {} automation", String::from(public_key))
            }
            OwnerOp::AddAuthKey { public_key } => format!("add_auth_key {public_key} auth"),
            // outflows name what leaves and where (first word stays the op name)
            OwnerOp::Withdraw { token, amount, to } => {
                format!("withdraw {} {} to {to}", amount.0, token.as_ref().map_or("near", |t| t.as_str()))
            }
            OwnerOp::WithdrawHome { token, amount } => {
                format!("withdraw_home {} {}", amount.0, token.as_ref().map_or("near", |t| t.as_str()))
            }
            OwnerOp::WithdrawViaIntents { token, amount, deposit_address } => {
                format!("withdraw_via_intents {} {token} to {deposit_address}", amount.0)
            }
            op => op.name().to_string(),
        }
    }
}

#[near(serializers = [json])]
pub struct SignedCheck {
    pub owner: AccountId,
    pub standard: String,
    pub key: String,
    pub ops: Vec<String>,
}

#[near(serializers = [json])]
pub struct OwnerAuthView {
    pub kind: OwnerKind,
    pub home: Home,
    pub signed_enabled: bool,
    pub implicit_enabled: bool,
    pub auth_keys: Vec<String>,
    pub salt: String,
    pub nonces_live: u32,
    /// true: withdraw_to_owner / withdraw_home go to the owner's intents.near balance
    pub intents_home: bool,
}

/// Checks 1–6 of spec §4.2 passed (nothing written yet).
struct Checked {
    standard: &'static str,
    key: AuthKey,
    ops: Vec<OwnerOp>,
    nonce: [u8; 32],
    nonce_expires: u64,
}

#[near]
impl TradingAccount {
    /// v1.6 (spec §4.2): runs owner ops the owner signed in a near/intents MultiPayload. Any
    /// caller (the relayer pays gas); the predecessor and deposit are never read.
    pub fn owner_signed(&mut self, signed: MultiPayload) {
        let c = self.check_signed(&signed);
        let now = env::block_timestamp();
        // 6: marked before dispatch; a failing op reverts the receipt, mark included
        let mut st = nonces();
        ok(st.insert(c.nonce, c.nonce_expires, now));
        env::storage_write(K_OWNER_NONCES, &near_sdk::borsh::to_vec(&st).unwrap_or_else(|_| fail("E_STATE")));
        // 8: the envelope event first, then each op's own events
        let names: Vec<String> = c.ops.iter().map(|o| jstr(&o.summary())).collect();
        env::log_str(&format!(
            "EVENT_JSON:{{\"standard\":\"nttrade\",\"version\":\"1\",\"event\":\"owner_signed\",\"data\":{{\"standard\":\"{}\",\"key\":\"{}\",\"ops\":[{}],\"nonce\":\"{}\"}}}}",
            c.standard,
            c.key,
            names.join(","),
            near_sdk::base64::Engine::encode(&near_sdk::base64::engine::general_purpose::STANDARD, c.nonce)
        ));
        // 7
        for op in c.ops {
            self.dispatch_owner_op(op);
        }
    }

    /// v1.6: checks 1–6 of `owner_signed` without writing (the engine's simulate step).
    pub fn owner_signed_check(&self, signed: MultiPayload) -> SignedCheck {
        let c = self.check_signed(&signed);
        SignedCheck {
            owner: self.owner.clone(),
            standard: c.standard.into(),
            key: c.key.to_string(),
            ops: c.ops.iter().map(OwnerOp::summary).collect(),
        }
    }

    pub fn get_owner_auth(&self) -> OwnerAuthView {
        let a = owner_auth(&self.owner);
        OwnerAuthView {
            kind: a.kind,
            home: a.home,
            signed_enabled: a.signed_enabled,
            implicit_enabled: a.implicit_enabled,
            auth_keys: a.auth_keys.iter().map(|k| k.to_string()).collect(),
            salt: oa::hex(&a.salt),
            nonces_live: nonces().live(env::block_timestamp()) as u32,
            intents_home: a.intents_home,
        }
    }

    /// v1.6: the owner's own home (Named: its NEAR account; signer kinds: its intents.near
    /// balance), no caps. Native NEAR keeps RESERVE.
    #[payable]
    pub fn owner_withdraw_home(&mut self, token: Option<AccountId>, amount: U128) {
        self.assert_owner();
        self.withdraw_home(token, amount.0);
    }

    /// v1.6: turn owner signatures on/off (spec §3: off by default for NEAR implicit owners).
    #[payable]
    pub fn owner_set_signed_enabled(&mut self, enabled: bool) {
        self.assert_owner();
        let mut a = owner_auth(&self.owner);
        if !a.kind.is_signer() {
            fail("E_OWNER_KIND");
        }
        a.signed_enabled = enabled;
        save_owner_auth(&a);
        env::log_str(&format!(
            "EVENT_JSON:{{\"standard\":\"nttrade\",\"version\":\"1\",\"event\":\"signed_enabled_set\",\"data\":{{\"enabled\":{enabled}}}}}"
        ));
    }

    /// v1.6: new salt: every signed but unsubmitted payload is void.
    #[payable]
    pub fn owner_rotate_salt(&mut self) {
        self.assert_owner();
        self.rotate_salt();
    }

    /// v1.6: settles a home send into intents.near (`used` as ft_resolve_transfer reports it; a
    /// refund stays in this account). Never panics.
    #[private]
    pub fn on_home_sent(&mut self, token: String, amount: U128) {
        let used = match env::promise_result_checked(0, 128) {
            Err(PromiseError::Failed) => 0,
            Err(_) => amount.0,
            Ok(b) => serde_json::from_slice::<U128>(&b).map_or(amount.0, |u| u.0.min(amount.0)),
        };
        env::log_str(&format!(
            "EVENT_JSON:{{\"standard\":\"nttrade\",\"version\":\"1\",\"event\":\"owner_withdraw\",\"data\":{{\"token\":{},\"amount\":\"{}\",\"to\":{},\"ok\":{},\"used\":\"{used}\"}}}}",
            jstr(&token),
            amount.0,
            jstr(&format!("intents:{}", self.owner)),
            used == amount.0
        ));
    }

    /// v1.6 (signed upgrade): upgrades only to a code hash the factory approves now
    /// (`get_approved_code_hashes()`, factory 1.3.0: the configured hash when it is flagged
    /// signed). A failed read, a foreign or a stale hash, or work in flight (R2-09) is refused
    /// (`upgrade_refused`). The upgrade batch ends with the old-code guard.
    #[private]
    pub fn on_upgrade_checked(&mut self, code_hash: Base58CryptoHash) {
        let want = String::from(&code_hash);
        let approved = env::promise_result_checked(0, 4_096)
            .ok()
            .and_then(|b| serde_json::from_slice::<Vec<String>>(&b).ok());
        let reason = match &approved {
            None => Some("factory_unreadable"),
            Some(v) if !v.contains(&want) => Some("not_approved"),
            // R2-09, as the permissionless apply
            _ if crate::upgrade::in_flight() => Some("in_flight"),
            _ => None,
        };
        if let Some(r) = reason {
            env::log_str(&format!(
                "EVENT_JSON:{{\"standard\":\"nttrade\",\"version\":\"1\",\"event\":\"upgrade_refused\",\"data\":{{\"code_hash\":\"{want}\",\"reason\":\"{r}\"}}}}"
            ));
            return;
        }
        // one batch = atomic: code without on_code_installed (the old-code guard) reverts the
        // whole upgrade; migrate gets all leftover gas (F-02)
        crate::upgrade::guarded_upgrade_batch(code_hash.into());
        env::log_str(&format!(
            "EVENT_JSON:{{\"standard\":\"nttrade\",\"version\":\"1\",\"event\":\"upgrade_started\",\"data\":{{\"code_hash\":\"{want}\"}}}}"
        ));
    }
}

impl TradingAccount {
    fn check_signed(&self, signed: &MultiPayload) -> Checked {
        let owner = self.owner.as_str();
        // 1
        let auth = owner_auth(&self.owner);
        if !auth.kind.is_signer() {
            fail("E_OWNER_KIND");
        }
        if !auth.signed_enabled {
            fail("E_SIGNED_DISABLED");
        }
        // 2
        let body: oa::Body<Vec<OwnerOp>> = ok(oa::parse_ops(signed));
        let n = body.items.len();
        let alone =
            body.items.iter().any(|o| matches!(o, OwnerOp::Upgrade { .. } | OwnerOp::WithdrawAll { .. }));
        if n == 0 || n > MAX_OPS || (alone && n > 1) {
            fail("E_OPS");
        }
        // 3
        let key = ok(oa::verify(signed));
        // 4: an auth key (any curve), else the owner's own implied key
        if !auth.auth_keys.contains(&key) {
            if key.kind() != auth.kind {
                fail("E_OWNER_KIND");
            }
            if !auth.implicit_enabled || key.implicit_id() != owner {
                fail("E_NOT_OWNER");
            }
        }
        // 5
        if body.signer_id != owner {
            fail("E_NOT_OWNER");
        }
        if body.verifying_contract != env::current_account_id().as_str() {
            fail("E_VERIFYING_CONTRACT");
        }
        let now = env::block_timestamp();
        ok(oa::check_deadline(body.deadline_ns, now, oa::OWNER_PAYLOAD_TTL_NS));
        // 6
        let nonce_expires = ok(oa::check_nonce(&body.nonce, &auth.salt, body.deadline_ns, now));
        ok(nonces().check(&body.nonce, now));
        Checked {
            standard: signed.standard().as_str(),
            key,
            ops: body.items,
            nonce: body.nonce,
            nonce_expires,
        }
    }

    /// One op = the body the matching `owner_*` method runs. New ops slot in here.
    fn dispatch_owner_op(&mut self, op: OwnerOp) {
        match op {
            OwnerOp::AddKey { public_key } => self.add_key(public_key, KeyKind::FunctionCall),
            OwnerOp::RemoveKey { public_key } => self.remove_key(public_key),
            OwnerOp::Withdraw { token, amount, to } => self.send(token, amount.0, to, false),
            OwnerOp::WithdrawAll { to, tokens } => self.withdraw_all(to, tokens),
            OwnerOp::WithdrawHome { token, amount } => self.withdraw_home(token, amount.0),
            OwnerOp::SetCaps { caps } => self.set_caps(caps),
            OwnerOp::SetAutomationKey { public_key, allowance } => {
                self.set_automation_key(public_key, allowance)
            }
            OwnerOp::RevokeAutomation {} => self.clear_automation(),
            OwnerOp::ClearRelayerKey { public_key } => self.clear_relayer_key(public_key),
            OwnerOp::SetRelayerAllowance { weekly_yocto } => self.set_relayer_allowance(weekly_yocto),
            OwnerOp::ReclaimDexStorage { dex } => self.reclaim_dex_storage(dex),
            OwnerOp::AddWithdrawDestination { label, asset, recipient, recipient_type } => {
                self.add_withdraw_destination(label, asset, recipient, recipient_type);
            }
            OwnerOp::RemoveWithdrawDestination { dest_id } => remove_dest(dest_id, "owner"),
            OwnerOp::SetOneclickConfig { keys, max_slippage_bps, intents, max_loss_bps } => {
                self.set_oneclick_config(keys, max_slippage_bps, intents, max_loss_bps)
            }
            OwnerOp::SetWithdrawCap { daily_cap_yocto, daily_cap_usd } => {
                self.set_withdraw_cap(daily_cap_yocto, daily_cap_usd)
            }
            OwnerOp::WithdrawFromIntents { token, amount } => self.owner_intents_to_self(token, amount.0),
            OwnerOp::WithdrawViaIntents { token, amount, deposit_address } => {
                self.withdraw_via_intents(token, amount, deposit_address)
            }
            OwnerOp::Upgrade { code_hash } => self.signed_upgrade(code_hash),
            OwnerOp::AddAuthKey { public_key } => self.add_auth_key(public_key),
            OwnerOp::RemoveAuthKey { public_key } => self.remove_auth_key(public_key),
            OwnerOp::SetImplicitKey { enabled } => self.set_implicit_key(enabled),
            OwnerOp::RotateSalt {} => self.rotate_salt(),
            OwnerOp::SetAutoUpgrade { enabled } => self.set_auto_upgrade(enabled),
            OwnerOp::CancelAutoUpgrade {} => crate::upgrade::veto("owner"),
            OwnerOp::Rescue { asset } => self.rescue(asset),
        }
    }

    /// Signed door only: the factory must approve `code_hash` now (checked async).
    fn signed_upgrade(&mut self, code_hash: Base58CryptoHash) {
        // R2-09: never under an in-flight settle, route or pending order fire (again in the
        // callback: work may start meanwhile)
        crate::upgrade::assert_not_in_flight();
        let me = env::current_account_id();
        let factory: AccountId = me
            .as_str()
            .split_once('.')
            .and_then(|(_, f)| f.parse().ok())
            .unwrap_or_else(|| fail("E_NO_FACTORY"));
        Promise::new(factory)
            .function_call(
                "get_approved_code_hashes",
                b"{}".to_vec(),
                NearToken::from_yoctonear(0),
                Gas::from_tgas(GAS_FACTORY_VIEW),
            )
            .then(Promise::new(me).function_call_weight(
                "on_upgrade_checked",
                format!("{{\"code_hash\":\"{}\"}}", String::from(&code_hash)).into_bytes(),
                NearToken::from_yoctonear(0),
                Gas::from_tgas(GAS_UPGRADE_CB),
                GasWeight(1),
            ))
            .detach();
    }

    fn add_auth_key(&mut self, pk: AuthKey) {
        let mut a = owner_auth(&self.owner);
        if !a.kind.is_signer() {
            fail("E_OWNER_KIND");
        }
        let small = matches!(&pk, AuthKey::Ed25519(k) if oa::is_small_order_ed25519(k));
        if small || a.auth_keys.contains(&pk) || pk.implicit_id() == self.owner.as_str() {
            fail("E_BAD_AUTH_KEY");
        }
        if a.auth_keys.len() >= oa::MAX_AUTH_KEYS {
            fail("E_AUTH_KEYS_FULL");
        }
        auth_key_event("auth_key_added", &pk);
        a.auth_keys.push(pk);
        save_owner_auth(&a);
    }

    fn remove_auth_key(&mut self, pk: AuthKey) {
        let mut a = owner_auth(&self.owner);
        let n = a.auth_keys.len();
        a.auth_keys.retain(|k| *k != pk);
        if a.auth_keys.len() == n {
            fail("E_NO_KEY");
        }
        if a.auth_keys.is_empty() && !a.implicit_enabled {
            fail("E_LAST_KEY");
        }
        save_owner_auth(&a);
        auth_key_event("auth_key_removed", &pk);
    }

    fn set_implicit_key(&mut self, enabled: bool) {
        let mut a = owner_auth(&self.owner);
        if !enabled && a.auth_keys.is_empty() {
            fail("E_LAST_KEY");
        }
        a.implicit_enabled = enabled;
        save_owner_auth(&a);
        env::log_str(&format!(
            "EVENT_JSON:{{\"standard\":\"nttrade\",\"version\":\"1\",\"event\":\"implicit_key_set\",\"data\":{{\"enabled\":{enabled}}}}}"
        ));
    }

    fn rotate_salt(&mut self) {
        let mut a = owner_auth(&self.owner);
        a.salt = random_salt(a.salt);
        save_owner_auth(&a);
        env::log_str(
            "EVENT_JSON:{\"standard\":\"nttrade\",\"version\":\"1\",\"event\":\"salt_rotated\",\"data\":{}}",
        );
    }

    /// True only for owners created through the signed path (home = the owner's intents.near
    /// balance); every NEAR-wallet owner keeps the native withdraw of 1.5.
    pub(crate) fn home_is_intents(&self) -> bool {
        owner_auth(&self.owner).intents_home
    }

    /// The `withdraw_home` op / `owner_withdraw_home`: no caps (an owner action).
    fn withdraw_home(&mut self, token: Option<AccountId>, amount: u128) {
        if self.home_is_intents() {
            self.send_home(token, amount);
        } else {
            self.send(token, amount, self.owner.clone(), true);
        }
    }

    /// Static gas `send_home` schedules (charged by the device path like `withdraw_to_owner`).
    pub(crate) fn home_gas(&self, token: &Option<AccountId>) -> u64 {
        let first = if token.is_none() { GAS_NEAR_DEPOSIT } else { GAS_FT_STORAGE };
        first + GAS_INTENTS_TRANSFER + GAS_CALLBACK + 3 * GAS_PER_ACTION
    }

    /// Spec §5.1: into intents.near for the owner id (`msg = owner`, intents' plain-id deposit
    /// form). Native NEAR is wrapped first (RESERVE kept); a non-wNEAR token registers the
    /// verifier first. `on_home_sent` reports; a refund stays here.
    pub(crate) fn send_home(&mut self, token: Option<AccountId>, amount: u128) {
        let me = env::current_account_id();
        if amount == 0 || token.as_ref() == Some(&me) {
            fail("E_BAD_OP");
        }
        // R2-05: no home send of a locked token (withdraw_home, rescue, withdraw_to_owner)
        if let Some(t) = &token {
            crate::chain::assert_free(t.as_str());
        }
        let v = verifier();
        let call = format!(
            "{{\"receiver_id\":\"{v}\",\"amount\":\"{amount}\",\"msg\":{}}}",
            jstr(self.owner.as_str())
        );
        let one = NearToken::from_yoctonear(1);
        let transfer = Gas::from_tgas(GAS_INTENTS_TRANSFER);
        let (last, name) = match token {
            None => {
                // F1 / INDEP-1: expired routes settle first (their fee leaves before the read)
                crate::chain::expire_routes(&self.fee.fee_recipient);
                ok(check_reserve(liquid_balance().saturating_sub(self.owner_hold()), amount));
                let b = env::promise_batch_create(&self.wrap);
                env::promise_batch_action_function_call_weight(
                    b,
                    "near_deposit",
                    b"{}",
                    NearToken::from_yoctonear(amount),
                    Gas::from_tgas(GAS_NEAR_DEPOSIT),
                    GasWeight(0),
                );
                env::promise_batch_action_function_call_weight(
                    b,
                    "ft_transfer_call",
                    call.as_bytes(),
                    one,
                    transfer,
                    GasWeight(0),
                );
                (b, "near".to_string())
            }
            Some(t) if t == self.wrap => (
                env::promise_create(t.clone(), "ft_transfer_call", call.as_bytes(), one, transfer),
                t.to_string(),
            ),
            Some(t) => {
                let reg = env::promise_create(
                    t.clone(),
                    "storage_deposit",
                    format!("{{\"account_id\":\"{v}\",\"registration_only\":true}}").as_bytes(),
                    NearToken::from_yoctonear(MAX_STORAGE_DEPOSIT),
                    Gas::from_tgas(GAS_FT_STORAGE),
                );
                (
                    env::promise_then(reg, t.clone(), "ft_transfer_call", call.as_bytes(), one, transfer),
                    t.to_string(),
                )
            }
        };
        env::promise_then(
            last,
            me,
            "on_home_sent",
            format!("{{\"token\":{},\"amount\":\"{amount}\"}}", jstr(&name)).as_bytes(),
            NearToken::from_yoctonear(0),
            Gas::from_tgas(GAS_CALLBACK),
        );
    }

    /// Spec §5.2: the signed quote's recipient must be the owner's own home. Returns the
    /// destination `check_quote` then enforces exactly (E_HOME_DEST otherwise).
    pub(crate) fn home_dest(&self, signed_quote: &str) -> intents::Dest {
        let a = owner_auth(&self.owner);
        let q = ok(intents::parse_quote(signed_quote));
        let owner = self.owner.as_str();
        let asset = intents::canon_asset(q.destination_asset);
        let ok_home = match (q.recipient_type, a.kind) {
            // only signed-path owners have a derived home; NEAR-wallet owners use the native
            // withdraw_to_owner or registered destinations, as in 1.5
            _ if !a.intents_home => false,
            (_, OwnerKind::Named) => false,
            ("INTENTS", _) => q.recipient == owner,
            ("DESTINATION_CHAIN", OwnerKind::Secp256k1) => {
                q.recipient.to_ascii_lowercase() == owner && is_evm_home_asset(asset)
            }
            ("DESTINATION_CHAIN", OwnerKind::Ed25519) if a.home == Home::Solana => {
                oa::unhex32(owner).map(|k| near_sdk::bs58::encode(k).into_string()).as_deref()
                    == Some(q.recipient)
                    && is_sol_home_asset(asset)
            }
            _ => false,
        };
        if !ok_home {
            fail("E_HOME_DEST");
        }
        intents::Dest {
            label: "home".into(),
            asset: q.destination_asset.into(),
            recipient: q.recipient.into(),
            recipient_type: q.recipient_type.into(),
            active_at_ns: U64(0),
        }
    }
}

fn auth_key_event(name: &str, pk: &AuthKey) {
    env::log_str(&format!(
        "EVENT_JSON:{{\"standard\":\"nttrade\",\"version\":\"1\",\"event\":\"{name}\",\"data\":{{\"public_key\":\"{pk}\"}}}}"
    ));
}

/// 1Click EVM home assets (spec §5.2), from `/v0/tokens` (2026-10-01, fixture
/// `tests/fixtures/oneclick_tokens.json`): eth, base, arb, gnosis, bera, pol as
/// `nep141:<c>.omft.near` / `nep141:<c>-0x<40 hex>.om{ft,dep}.near`; bsc, pol, op, avax as HOT
/// `nep245:v2_1.omni.hot.tg:<id>_<b58>`; `1cs_v1:<chain>:{erc20,bep20}:0x<40 hex>`.
/// Fail closed: anything else is refused.
pub fn is_evm_home_asset(a: &str) -> bool {
    const OMFT: [&str; 6] = ["eth", "base", "arb", "gnosis", "bera", "pol"];
    const HOT: [&str; 4] = ["56", "137", "10", "43114"];
    const ONECS: [&str; 9] = ["eth", "base", "arb", "gnosis", "bera", "bsc", "pol", "op", "avax"];
    if let Some(r) = a.strip_prefix("1cs_v1:") {
        let mut p = r.splitn(3, ':');
        let (c, std, addr) = (p.next().unwrap_or(""), p.next().unwrap_or(""), p.next().unwrap_or(""));
        return ONECS.contains(&c)
            && matches!(std, "erc20" | "bep20")
            && addr
                .strip_prefix("0x")
                .is_some_and(|h| h.len() == 40 && h.bytes().all(|c| c.is_ascii_hexdigit()));
    }
    if let Some(r) = a.strip_prefix("nep141:") {
        return OMFT.iter().any(|c| {
            r.strip_prefix(c).is_some_and(|x| {
                x == ".omft.near"
                    || x.strip_prefix("-0x")
                        .and_then(|y| y.strip_suffix(".omft.near").or_else(|| y.strip_suffix(".omdep.near")))
                        .is_some_and(|h| h.len() == 40 && h.bytes().all(|c| c.is_ascii_hexdigit()))
            })
        });
    }
    a.strip_prefix("nep245:v2_1.omni.hot.tg:")
        .and_then(|r| r.split_once('_'))
        .is_some_and(|(id, t)| HOT.contains(&id) && is_b58_token(t))
}

/// 1Click Solana home assets: `nep141:sol.omft.near`, `nep141:sol-<40 hex>.omft.near`,
/// `nep141:sol-0x<40 hex>.omdep.near`, `1cs_v1:sol:spl:<b58 mint>`.
pub fn is_sol_home_asset(a: &str) -> bool {
    let hex40 = |h: &str| h.len() == 40 && h.bytes().all(|c| c.is_ascii_hexdigit());
    if let Some(m) = a.strip_prefix("1cs_v1:sol:spl:") {
        return (32..=44).contains(&m.len()) && is_b58_token(m);
    }
    match a.strip_prefix("nep141:sol") {
        Some(".omft.near") => true,
        Some(r) => r.strip_prefix('-').is_some_and(|x| {
            x.strip_suffix(".omft.near").is_some_and(hex40)
                || x.strip_prefix("0x").and_then(|y| y.strip_suffix(".omdep.near")).is_some_and(hex40)
        }),
        None => false,
    }
}

fn is_b58_token(t: &str) -> bool {
    (1..=64).contains(&t.len())
        && t.bytes().all(|c| c.is_ascii_alphanumeric() && !matches!(c, b'0' | b'O' | b'I' | b'l'))
}
