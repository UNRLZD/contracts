//! Trading account (spec: docs/contract-spec.md v1.4.3 + docs/intents-spec.md §3 for v1.4). Runs as a NEP-591 global contract.
//! Security-critical: every rule below has a test (unit tests here, sandbox tests in
//! contracts/tests).
use near_sdk::json_types::{Base58CryptoHash, U128, U64};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{
    env, near, require, serde_json, AccountId, Allowance, Gas, GasWeight, NearToken, PanicOnDefault, Promise,
    PromiseError, PublicKey,
};

pub mod chain;
pub mod intents;
pub mod msg;
pub mod msg_venues;
pub mod owner;
pub mod policy;
#[cfg(test)]
mod tests;
pub mod upgrade;
pub mod venues;

use intents::{Dest, OneClickConfig};
use msg::{Ctx, DexKind, Swap};

use policy::*;

/// v1.4 adds withdraw_cross_chain + remove_withdraw_destination (keys added before v1.4 lack
/// them: the owner re-adds the device key with owner_add_key after upgrading).
pub const DEVICE_METHODS: &str = "execute,withdraw_to_owner,lower_caps,place_order,cancel_order,revoke_automation,withdraw_cross_chain,remove_withdraw_destination,withdraw_from_intents,execute_order";
/// v1.3: the automation (24/7 orders) key may call ONLY this.
pub const AUTOMATION_METHODS: &str = "execute_order";
#[cfg(not(feature = "upgrade-test"))]
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
#[cfg(feature = "upgrade-test")]
pub const VERSION: &str = "upgrade-test";

const GAS_NEAR_DEPOSIT: u64 = 3; // TGas
const GAS_NEAR_WITHDRAW: u64 = 10;
const GAS_STORAGE_DEPOSIT: u64 = 10;
const GAS_MIGRATE: u64 = 20;
const GAS_REGISTER_ASSETS: u64 = 5;
/// DCL (dclv2.ref-labs.near v2.3.13) storage_balance_bounds().min. Verified on mainnet and
/// against the live wasm in the sandbox: less fails with E102; swaps do NOT require it.
pub const DCL_REGISTRATION: u128 = 500_000_000_000_000_000_000_000;
const GAS_DCL_STORAGE: u64 = 10;
const GAS_DCL_WITHDRAW: u64 = 60; // DEX schedules ft_transfer + its own callback
const GAS_DCL_UNREGISTER: u64 = 20;
/// Plach withdraw: ft_transfer + after_withdraw callback inside Plach.
const GAS_PLACH_WITHDRAW: u64 = 30;
/// Reserved for `on_swap_settled` inside the E_GAS budget.
pub const GAS_CALLBACK: u64 = 10;
/// v1.1: per scheduled function-call action, the runtime pre-charges send + exec action
/// fees (~4.64 TGas + per-byte) from the caller's prepaid gas; budgeted in E_GAS.
pub const GAS_PER_ACTION: u64 = 5;
/// wrap.near storage_balance_bounds().min; paid once from the account balance in `init`.
pub const WRAP_STORAGE: u128 = 1_250_000_000_000_000_000_000;
const MAX_PLACH_ASSETS: usize = 4;
// v1.3 orders
pub const MAX_OPEN_ORDERS: usize = 64;
pub const MAX_TRIGGER_META: usize = 256;
pub const MAX_ORDER_DEXES: usize = 3;
pub const MAX_ORDER_TTL_NS: u64 = 90 * 86_400 * 1_000_000_000;
/// The automation key's gas allowance bounds what a compromised key can burn in gas.
pub const MIN_AUTOMATION_ALLOWANCE: u128 = 500_000_000_000_000_000_000_000; // 0.5 NEAR
const K_ORDER_INDEX: &[u8] = b"oi";
/// v1.2.1: daily gas tally (start_ns, yocto) kept outside STATE (layout unchanged).
const K_DAY_GAS: &[u8] = b"gd";
/// v1.2.1: attached gas is charged to the daily cap at this conservative price: 2x NEAR's
/// minimum gas price (1e8 yocto/gas, the price both networks run at in all our measurements;
/// the protocol can raise it by <=1%/block only under sustained congestion).
pub const GAS_PRICE_BOUND: u128 = 200_000_000;
/// v1.2.1: max gas a swap op may attach, per DEX kind (router uses 150 Rhea / 100 DCL /
/// 280->clamped 265 Plach). Bounds what a call to an arbitrary token contract can burn.
pub const MAX_SWAP_GAS_RHEA: u64 = 200;
pub const MAX_SWAP_GAS_DCL: u64 = 150;
pub const MAX_SWAP_GAS_PLACH: u64 = 265;
/// A1-F1: a swap op must declare at least this much gas (it gets exactly its declared gas).
pub const MIN_SWAP_GAS: u64 = 20;
/// v1.5 (Shards): max gas of the wrap `ft_transfer_call` of a ShardsBuy (UI: 100 TGas) and of a
/// token's `sell_exact_in` (ShardsSell).
pub const MAX_SWAP_GAS_SHARDS_BUY: u64 = 150;
pub const MAX_SWAP_GAS_SHARDS_SELL: u64 = 100;
/// v1.5: attached to `withdraw_quote` (near_withdraw on wrap + native Transfer + its resolves).
pub const GAS_SHARDS_WITHDRAW: u64 = 150;
/// v1.5: static gas of `on_shards_sold`: itself + withdraw_quote + on_shards_settled + 2 action fees.
pub const GAS_SHARDS_SOLD_CB: u64 = 5 + GAS_SHARDS_WITHDRAW + GAS_CALLBACK + 2 * GAS_PER_ACTION;
/// v1.5: `max_total_fee_bps` sent with every Shards trade: the highest tax a Shards pool allows
/// (10%) + the in-token AMM LP fee (1%). The trade's real bound is its `min_out`.
pub const SHARDS_MAX_TOTAL_FEE_BPS: u16 = 1_100;
const K_ORDER_NEXT: &[u8] = b"on";
const K_AUTOMATION: &[u8] = b"ak";
const GAS_AUTOMATION_CB: u64 = 5;
const MAX_ASSET_ID_LEN: usize = 128;

#[near(serializers = [borsh, json])]
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Caps {
    pub max_trade_yocto: U128,
    pub daily_cap_yocto: U128,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug)]
pub struct FeeConfig {
    pub fee_bps: u16,
    pub fee_recipient: AccountId,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug)]
pub struct Dex {
    pub id: AccountId,
    pub kind: DexKind,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde", deny_unknown_fields)]
pub enum Op {
    NearDeposit {
        amount: U128,
    },
    NearWithdraw {
        amount: U128,
    },
    StorageDeposit {
        token: AccountId,
        amount: U128,
    },
    FtTransferCall {
        token: AccountId,
        receiver_id: AccountId,
        amount: U128,
        msg: String,
        gas: U64,
    },
    /// Plach `register_assets{asset_ids}` for self (1 yocto). v1.1.
    PlachRegisterAssets {
        dex: AccountId,
        asset_ids: Vec<String>,
    },
    /// Plach buy with native NEAR: `deposit_near{operations: <msg>}` with deposit = amount,
    /// where `msg` is the router's `{"operations":[...],"referrer":..}` object. v1.1.
    PlachDepositNear {
        dex: AccountId,
        amount: U128,
        msg: String,
        gas: U64,
    },
    /// Plach `withdraw{asset_id, amount}` of the account's own inner balance, always to
    /// self (`withdraw_to` never sent). `amount: None` = Full. Rescues stuck swap output.
    /// Not spend. v1.1.
    PlachWithdraw {
        dex: AccountId,
        asset_id: String,
        amount: Option<U128>,
    },
    /// v1.2: register self on a DCL-kind DEX (for accounts created before v1.2): one atomic
    /// batch `storage_deposit{registration_only}` (DCL_REGISTRATION) + `storage_withdraw{}`
    /// -> 0.1 NEAR stays locked (asset storage), 0.4 (order/LP slots) comes straight back.
    /// Counted as spend (full 0.5, conservative).
    DexStorageDeposit {
        dex: AccountId,
    },
    /// v1.2: recover the account's OWN undelivered swap output from an allowlisted DEX,
    /// always to self (the DEX pays the caller; no destination parameter). Not spend.
    /// RheaClassic -> `claim_lostfound{token_id}` (1 yocto; full claim, amount must be null);
    /// RheaDcl -> `withdraw_asset{token_id, amount?}` (no deposit). Plach: PlachWithdraw.
    DexWithdraw {
        dex: AccountId,
        token: AccountId,
        amount: Option<U128>,
    },
    /// v1.5: buy a Shards token (curve or in-token AMM) with `amount` wNEAR:
    /// `wrap.ft_transfer_call{receiver_id: token, amount, msg}` where the contract builds msg
    /// `{"v":1,"action":"buy","order_id","min_amount_out":min_out,"max_total_fee_bps","deadline_ns"}`
    /// itself (no caller-supplied field, so no recipient: the token credits the sender = self).
    /// `token` = `<label>.<F>` for an allowlisted ShardsToken factory F. Spend = amount.
    ShardsBuy {
        token: AccountId,
        amount: U128,
        min_out: U128,
        gas: U64,
    },
    /// v1.5: sell `amount` of a Shards token for at least `min_out` wNEAR (net of tax and LP fee):
    /// `token.sell_exact_in` (panics = reverted on any refusal), then `on_shards_sold` asks the
    /// token to pay the exact credit out with `withdraw_quote{amount}` (never a `recipient_id`, so
    /// it pays the caller = self, in native NEAR). Fee on what was credited AND arrived.
    ShardsSell {
        token: AccountId,
        amount: U128,
        min_out: U128,
        gas: U64,
    },
    /// v1.5: pay out the account's own quote credit stuck in a Shards token (a sell whose payout
    /// failed): `token.withdraw_quote{}`, which pays the caller = self. Not spend.
    ShardsWithdrawQuote {
        token: AccountId,
    },
    /// v1.6: buy on a launchpad curve venue (venues/*.rs builds every call; no caller msg,
    /// method or recipient). Last op (one swap).
    CurveBuy(venues::CurveTrade),
    /// v1.6: sell on a launchpad curve venue. Last op (one swap).
    CurveSell(venues::CurveTrade),
    /// v1.6: venue housekeeping that pays this account (claims, withdraws of own balances,
    /// Kelytra register/deposit). Not a swap.
    CurveClaim(venues::CurveClaim),
    /// v1.6 (routing C.1): two on-chain legs, one signature; leg 2's input = min(Q delta
    /// measured inside the route, max_mid). Last op (one swap).
    Chain(Box<chain::Chain>),
    /// v1.6 (routing C.2): NEAR -> Q through a signed 1Click quote into this account's intents
    /// balance; a continuation (`execute_order` on a cont id) pulls and swaps. Device only.
    IntentsSwap(chain::IntentsSwap),
    /// v1.6: continuation step only (`execute_order` on a cont id); refused in `execute`.
    IntentsPull(chain::exec::IntentsPull),
    /// v1.6 (F-01): device veto of the pending auto-upgrade (restrict-only; no swap).
    CancelAutoUpgrade {},
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde", deny_unknown_fields)]
pub enum KeyKind {
    FunctionCall,
    /// NEP-611 gas key restricted to DEVICE_METHODS on self, funded with `balance`.
    /// v1.1: compiled out by default (removing a gas key burns its balance: there is no
    /// WithdrawFromGasKey in near-sdk 5.29). Enable with feature `gas-keys`.
    #[cfg(feature = "gas-keys")]
    GasKey {
        num_nonces: u32,
        balance: U128,
    },
}

/// v1.3 limit/TP/SL order. Stored under its own key (not in STATE), so the v1.2 state layout
/// is unchanged and `migrate` stays a no-op.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq)]
pub struct Order {
    pub token_in: AccountId,
    pub token_out: AccountId,
    pub amount_in: U128,
    pub min_out: U128,
    /// Opaque to the contract (UI/executor trigger description).
    pub trigger_meta: String,
    pub expires_at_ns: U64,
    pub dexes: Vec<AccountId>,
    pub pending: bool,
}

#[near(serializers = [json])]
pub struct OrderView {
    pub id: U64,
    #[serde(flatten)]
    pub order: Order,
    /// v1.6: a Chain order's stored legs (absent for a plain order)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via: Option<chain::OrderVia>,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct TradingAccount {
    owner: AccountId,
    wrap: AccountId,
    dex_allowlist: Vec<Dex>,
    fee: FeeConfig,
    caps: Caps,
    day: Day,
    seen_orders: SeenOrders,
}

#[near(serializers = [json])]
pub struct Config {
    pub owner: AccountId,
    pub wrap: AccountId,
    pub dex_allowlist: Vec<Dex>,
    pub fee_bps: u16,
    pub fee_recipient: AccountId,
    pub caps: Caps,
    pub version: String,
}

fn fail(code: &str) -> ! {
    env::panic_str(code)
}

fn ok<T>(r: Result<T, &'static str>) -> T {
    r.unwrap_or_else(|e| fail(e))
}

#[near]
impl TradingAccount {
    #[init]
    #[allow(clippy::too_many_arguments)]
    pub fn init(
        owner: AccountId,
        fee_config: FeeConfig,
        caps: Caps,
        dex_allowlist: Vec<Dex>,
        wrap: AccountId,
        automation: Option<AutomationInit>,
        owner_auth: Option<owner_auth::OwnerAuthInit>,
        code_hash: Option<Base58CryptoHash>,
    ) -> Self {
        require!(fee_config.fee_bps <= MAX_FEE_BPS, "E_FEE");
        // v1.6: owner kind + salt (factory 1.3.0 passes `owner_auth` for a verified signed
        // creation; absent = the id rule, docs/owner-v16-spec.md §3)
        owner::write_initial_owner_auth(&owner, owner_auth);
        // v1.6 (F-03): state version
        upgrade::write_state_version();
        // v1.6 (R2-11): the code the factory created this account with (factory 1.3.0 passes its
        // effective hash), so auto-upgrade never schedules the code the account already runs
        if let Some(h) = code_hash {
            let c: near_sdk::CryptoHash = h.into();
            env::storage_write(upgrade::K_CODE_HASH, &c);
        }
        // v1.4.7: one-signature onboarding with 24/7 orders on. The factory passes the owner's
        // automation key here (never as a raw AddKey in its batch): the account installs it
        // through the same path as owner_set_automation_key, so it is in the relayer role set
        // before its AddKey lands, and code that doesn't know this argument installs nothing.
        if let Some(a) = automation {
            if a.allowance.0 < MIN_AUTOMATION_ALLOWANCE {
                fail("E_ALLOWANCE");
            }
            // v1.4.8: None (or UNLIMITED) = no weekly allowance: nothing stored
            if let Some(w) = a.weekly_yocto.filter(|w| w.0 != UNLIMITED) {
                env::storage_write(K_RELAYER_ALLOWANCE, &w.0.to_le_bytes());
            }
            schedule_automation_install(a.public_key, None, a.allowance.0);
        }
        let me = env::current_account_id();
        // v1.1: register self on wNEAR so the first near_deposit is not skimmed for storage.
        let mut regs = vec![env::promise_create(
            wrap.clone(),
            "storage_deposit",
            format!("{{\"account_id\":\"{me}\",\"registration_only\":true}}").as_bytes(),
            NearToken::from_yoctonear(WRAP_STORAGE),
            Gas::from_tgas(GAS_STORAGE_DEPOSIT),
        )];
        let mut targets = vec![wrap.clone()];
        // v1.2: lean registration on every DCL-kind DEX (net 0.1 NEAR locked, refundable
        // via owner_reclaim_dex_storage). Lets DCL park undeliverable swap output in our
        // inner balance (recoverable with DexWithdraw) instead of its locked lostfound.
        for d in dex_allowlist.iter().filter(|d| d.kind == DexKind::RheaDcl) {
            let idx = env::promise_batch_create(&d.id);
            dcl_register_actions(idx);
            regs.push(idx);
            targets.push(d.id.clone());
        }
        // v1.4.3 (SC-3): the outcome is reported (event + get_init_registration), not silent.
        let args = serde_json::to_vec(&InitRegArgs { targets }).unwrap_or_else(|_| fail("E_JSON"));
        let cb = env::promise_batch_then(env::promise_and(&regs), &me);
        env::promise_batch_action_function_call_weight(
            cb,
            "on_init_registered",
            &args,
            NearToken::from_yoctonear(0),
            Gas::from_tgas(GAS_INIT_REG_CB),
            GasWeight(1),
        );
        Self {
            owner,
            wrap,
            dex_allowlist,
            fee: fee_config,
            caps,
            day: Day { start_ns: utc_day_start(env::block_timestamp()), spent_yocto: 0 },
            seen_orders: SeenOrders::default(),
        }
    }

    /// v1.4.3 (SC-3): result of init's wNEAR / DCL registrations, in `targets` order. Emits
    /// `init_registration{results: [{target, ok}]}` and stores it for `get_init_registration`.
    /// A failed one leaves the account working but unregistered there: register again with a
    /// `StorageDeposit` (wrap) or `DexStorageDeposit` (DCL) op.
    #[private]
    pub fn on_init_registered(&mut self, targets: Vec<AccountId>) {
        let n = env::promise_results_count();
        let res: Vec<InitRegistration> = targets
            .into_iter()
            .enumerate()
            .map(|(i, target)| {
                let i = i as u64;
                let ok = i < n && !matches!(env::promise_result_checked(i, 0), Err(PromiseError::Failed));
                InitRegistration { target, ok }
            })
            .collect();
        let json = serde_json::to_string(&res).unwrap_or_else(|_| fail("E_JSON"));
        env::log_str(&format!(
            "EVENT_JSON:{{\"standard\":\"nttrade\",\"version\":\"1\",\"event\":\"init_registration\",\"data\":{{\"results\":{json}}}}}"
        ));
        env::storage_write(K_INIT_REG, &near_sdk::borsh::to_vec(&res).unwrap_or_else(|_| fail("E_STATE")));
    }

    /// v1.4.3 (SC-3): what init's registrations did ([] = not reported yet, or an account created
    /// before v1.4.3). `ok: false` = not registered there by init; clients should re-register.
    pub fn get_init_registration(&self) -> Vec<InitRegistration> {
        env::storage_read(K_INIT_REG)
            .map(|b| near_sdk::borsh::from_slice(&b).unwrap_or_else(|_| fail("E_STATE")))
            .unwrap_or_default()
    }

    /// Called by `owner_upgrade` in the same receipt as `UseGlobalContract`. v1 state
    /// layout is unchanged, so this is a read-and-rewrite; later versions map old -> new.
    #[private]
    #[init(ignore_state)]
    pub fn migrate() -> Self {
        let mut s: Self = env::state_read().unwrap_or_else(|| fail("E_NO_STATE"));
        // v1.4.3: materialize the relayer role set of <= v1.4.1 state and put a stored automation
        // key back in it (heals a v1.4.2 account left in the ROLESET-001 state).
        if let Some(k) = s.automation_key() {
            relayer_role_ensure(&k);
        }
        let now = env::block_timestamp();
        let at = now.saturating_add(CAPS_RAISE_DELAY_NS);
        // v1.4.5 (RA-3 + RA4-5): an owner cap raise across an upgrade. If the caps changed since
        // the raise was requested (older code ran and lowered or set them; it could not cancel
        // the raise), the raise is cancelled, as lower_caps / owner_set_caps would have done.
        // Otherwise a matured raise applies now (it already counted as in force) and one still
        // pending gets at least CAPS_RAISE_DELAY_NS from now.
        // v1.4.6 (RA5-1, RA5-4): the base counts only if it is bound to THIS raise (written with
        // it); a raise without one (requested under v1.4.3/v1.4.4, or a stale v1.4.5 base) is
        // never applied here, only re-armed, as v1.4.4 did.
        if let Some(mut p) = pending_caps() {
            let base = env::storage_read(K_PENDING_BASE)
                .and_then(|b| near_sdk::borsh::from_slice::<(Caps, PendingCaps)>(&b).ok())
                .filter(|(_, bound)| *bound == p)
                .map(|(b, _)| b);
            if base.as_ref().is_some_and(|b| *b != s.caps) {
                cancel_caps_raise("migrate");
            } else if base.is_some() && now >= p.active_at_ns.0 {
                s.sync_caps();
            } else {
                if p.active_at_ns.0 < at {
                    p.active_at_ns = U64(at);
                    save_pending_caps(&p);
                    caps_event("caps_raise_pending", &p.caps, Some(at));
                }
                // keep a valid base bound to the (re-armed) raise; drop a stale or absent one
                if let Some(b) = base {
                    let v = near_sdk::borsh::to_vec(&(b, p)).unwrap_or_else(|_| fail("E_STATE"));
                    env::storage_write(K_PENDING_BASE, &v);
                } else {
                    env::storage_remove(K_PENDING_BASE);
                }
            }
        } else {
            // v1.4.6 (RA5-4): a base left by v1.4.3/v1.4.4 sync_caps/cancel (no raise pending)
            env::storage_remove(K_PENDING_BASE);
        }
        // v1.4.5 (RA4-5b): withdraw destinations still pending get at least DEST_DELAY_NS from
        // now, so the device key has a full delay to remove one added before a downgrade.
        let mut d = intents::dests();
        let mut changed = false;
        for (id, dest) in d.list.iter_mut().filter(|(_, x)| x.active_at_ns.0 > now && x.active_at_ns.0 < at) {
            dest.active_at_ns = U64(at);
            changed = true;
            env::log_str(&format!(
                "EVENT_JSON:{{\"standard\":\"nttrade\",\"version\":\"1\",\"event\":\"withdraw_destination_rearmed\",\"data\":{{\"dest_id\":{id},\"active_at_ns\":\"{at}\"}}}}"
            ));
        }
        if changed {
            intents::save_dests(&d);
        }
        // v1.4.5 (RA4-3): an install marker whose key is the current key or no longer a member is
        // stale (its callback ran under older code): drop it, so owner_clear_relayer_key works.
        if let Some(k) =
            env::storage_read(K_INSTALLING).and_then(|b| near_sdk::borsh::from_slice::<PublicKey>(&b).ok())
        {
            if s.automation_key().as_ref() == Some(&k) || !relayer_keys().contains(&k) {
                env::storage_remove(K_INSTALLING);
            }
        }
        // v1.6: owner kind + salt for accounts from before 1.6.0 (idempotent; §3 id rule, owner
        // signatures on only for `0x` owners)
        if !env::storage_has_key(owner::K_OWNER_AUTH) {
            owner::write_initial_owner_auth(&s.owner, None);
        }
        // v1.6 (F2, external audit): records that fail closed (E_STATE) from now on are brought to
        // this layout first: routes from builds before 9a0dd084 are rewritten; a Chain order whose
        // via predates V16-01 (no leg-1 bound, can never fire safely) is cancelled.
        let rewritten = chain::migrate_routes();
        if rewritten > 0 {
            env::log_str(&format!(
                "EVENT_JSON:{{\"standard\":\"nttrade\",\"version\":\"1\",\"event\":\"routes_migrated\",\"data\":{{\"count\":{rewritten}}}}}"
            ));
        }
        // v1.6 (F3, external audit): never install under in-flight work. The doors check before
        // the batch; this re-checks in the batch receipt itself (UseGlobalContract + migrate are one
        // receipt), so a trade that started in between reverts the whole upgrade (code included).
        // After migrate_routes (in_flight reads routes), BEFORE the via cleanup below (INDEP-4: a
        // pending fire of such an order still blocks the install).
        if upgrade::in_flight() {
            fail("E_IN_FLIGHT");
        }
        for (id, _) in order_index() {
            if chain::via_unreadable(id) {
                remove_order(id);
                order_event("order_cancelled", id);
            }
        }
        // v1.6 (F-03): the state version this code leaves (later code dispatches on it)
        upgrade::write_state_version();
        s
    }

    // ---------------- device methods (predecessor == self) ----------------

    pub fn execute(&mut self, ops: Vec<Op>, client_order_id: String, expires_at_ns: U64, max_in_yocto: U128) {
        // 1 (v1.3: and not the automation key)
        self.assert_device();
        // v1.6 (R2-03): a veto-only execute is a safety action like cancel_order / lower_caps:
        // charged, never refused by the daily cap
        if matches!(ops.as_slice(), [Op::CancelAutoUpgrade {}]) {
            self.charge_device_gas(true);
            return upgrade::veto("device");
        }
        let now = env::block_timestamp();
        // F1: settle expired routes' escrow (one read when nothing is escrowed)
        if chain::escrow_total() > 0 {
            chain::expire_routes(&self.fee.fee_recipient);
        }
        // 2
        ok(check_expiry(now, expires_at_ns.0));
        // 3
        ok(self.seen_orders.insert(client_order_id.clone(), expires_at_ns.0, now));
        self.run(ops, &client_order_id, max_in_yocto.0, now, None);
    }

    /// v1.3: execute an open order (predecessor == self). Through the automation key (24/7
    /// relayer): SELL orders (token_out == wrap) and, since v1.4.7, BUY orders (token_in ==
    /// wrap); wrap on neither side is device-only. v1.4.8: no weekly limit by default; with an
    /// owner-set weekly allowance (opt-in) sells charge max(min_out, floor) and buys their whole
    /// spend + gas (at least the floor = allowance / 20) per ISO week. Any order through a device
    /// key (tab runner). The ops must be exactly one swap of the
    /// order's token_in/amount_in on one of its DEXes into its token_out with parsed min_out
    /// >= the order's min_out, optionally preceded by NearDeposit (<= amount_in, buys),
    /// StorageDeposit and PlachRegisterAssets. Caps/fee/reserve/gas as `execute`. The order
    /// goes Pending; the settle callback removes it (filled) or reopens it (swap failed).
    pub fn execute_order(&mut self, order_id: U64, ops: Vec<Op>) {
        self.assert_self();
        // C1-M1: role by an explicit set (current + pending + retired automation keys).
        // v1.4.9 (UNR-A-08): assert_self requires signer == self, so this is the key that signed
        // the call, never the outer signer of a Delegate action.
        // v1.6 (routing C.2.4): continuation ids >= 2^63 (pull + one swap within stored terms)
        if order_id.0 >= chain::CONT_BASE {
            return self.fire_continuation(order_id.0, ops);
        }
        let relayer = is_relayer(&env::signer_account_pk());
        let now = env::block_timestamp();
        let mut order = load_order(order_id.0).unwrap_or_else(|| fail("E_NO_ORDER"));
        // v1.6: an order with stored Chain legs fires only a Chain, a plain order never one
        ok(chain::check_order_kind(chain::load_via(order_id.0).is_some(), &ops));
        if order.pending {
            fail("E_ORDER_PENDING");
        }
        if now > order.expires_at_ns.0 {
            fail("E_EXPIRED");
        }
        let mut relayer_week = None;
        let mut relayer_buy = false;
        // v1.4.7: the relayer also fires limit BUYS (token_in == wrap), exactly as stored. Orders
        // with wrap on neither side stay device-only (E_RELAYER_SELL_ONLY).
        // v1.4.8: the weekly allowance is opt-in. Without one (the default) there is no weekly
        // accounting, no floor and no fire count; every per-fire check below and in `run` still
        // applies. With one, a buy's whole NEAR spend (+ gas) is charged in `run`, once known.
        if relayer && order.token_out != self.wrap {
            if order.token_in != self.wrap {
                fail("E_RELAYER_SELL_ONLY");
            }
            if let Some(allowance) = relayer_allowance() {
                // early refusal (before the order goes Pending): at least amount_in must fit
                let mut w = relayer_week_state();
                roll_week(&mut w, now);
                let min_charge = order.amount_in.0.max(allowance / MAX_RELAYER_FIRES_PER_WEEK);
                if w.spent_yocto.checked_add(min_charge).is_none_or(|x| x > allowance) {
                    fail("E_RELAYER_WEEKLY");
                }
                relayer_buy = true;
            }
        } else if relayer {
            if let Some(allowance) = relayer_allowance() {
                let mut w = relayer_week_state();
                roll_week(&mut w, now);
                // C1-L3: a fire costs max(min_out, allowance / MAX_RELAYER_FIRES_PER_WEEK)
                let floor = allowance / MAX_RELAYER_FIRES_PER_WEEK;
                let charge = order.min_out.0.max(floor);
                let spent = w.spent_yocto.checked_add(charge);
                match spent {
                    Some(x) if x <= allowance => w.spent_yocto = x,
                    _ => fail("E_RELAYER_WEEKLY"),
                }
                save_relayer_week(&w);
                // v1.4.8 (RA7-1): a provably failed fire gives back only what exceeds the floor
                relayer_week = Some((w.start_ns, charge.saturating_sub(floor)));
            }
        }
        order.pending = true;
        save_order(order_id.0, &order);
        self.sync_caps();
        let max_in = self.caps.max_trade_yocto.0;
        self.run(
            ops,
            &format!("order:{}", order_id.0),
            max_in,
            now,
            Some((order_id.0, order, relayer_week, relayer_buy)),
        );
    }

    /// Steps 4-8 of `execute` (spec), shared with `execute_order` (order = constraints).
    fn run(
        &mut self,
        ops: Vec<Op>,
        client_order_id: &str,
        max_in: u128,
        now: u64,
        mut order: Option<OrderRun>,
    ) {
        self.sync_caps();
        let me = env::current_account_id();
        // 4: validate ops, compute spend + fee + native outflow
        let mut spend: u128 = 0;
        let mut native_out: u128 = 0;
        let mut gas: u64 = 0;
        // The (single) swap op: (input amount, part of it counted as spend, max fee).
        let mut swap: Option<(u128, u128, u128)> = None;
        // v1.4.3 (ORDER-001): how the swap's result proves a refund (see on_swap_settled).
        let mut proof = SwapProof::Token;
        // v1.5: the token of a ShardsSell (its settle chain starts with on_shards_sold)
        let mut shards_sell: Option<AccountId> = None;
        // v1.6: the planned curve trade (the swap op), built once here and dispatched below
        let mut curve: Option<venues::Plan> = None;
        // v1.6 (taxed tokens): an order fire whose output token taxes transfers after the DEX's
        // min_out check is gated on the token's own tax view (venues/tax.rs)
        let mut tax_gate: Option<venues::tax::Gate> = None;
        let mut gated: Option<venues::tax::GatedCall> = None;
        // v1.6: a Chain / IntentsSwap op (dispatched with the settle args, step 7)
        let mut route: Option<(Op, Option<chain::exec::IntentsPlan>)> = None;
        if ops.is_empty() {
            fail("E_BAD_OP");
        }
        let last = ops.len() - 1;
        let ord = order.as_ref().map(|(_, o, _, _)| o);
        let mut order_swaps = 0;
        let mut order_wrapped: u128 = 0;
        // v1.2.1: StorageDeposit may only target wrap, an allowlisted DEX, or this execute's
        // swap input/output token (checked after the loop, once the swap is parsed).
        let mut storage_targets: Vec<AccountId> = vec![self.wrap.clone()];
        storage_targets.extend(
            self.dex_allowlist.iter().filter(|d| !venues::is_factory_entry(d.kind)).map(|d| d.id.clone()),
        );
        let mut storage_used: Vec<&AccountId> = Vec::new();
        for (i, op) in ops.iter().enumerate() {
            if let Some(o) = ord {
                ok(check_order_op(o, op, &self.wrap));
                // A1-F5: the TOTAL wrapped by one execute_order is <= amount_in
                if let Op::NearDeposit { amount } = op {
                    order_wrapped = ok(add(order_wrapped, amount.0));
                    if order_wrapped > o.amount_in.0 {
                        fail("E_ORDER_OPS");
                    }
                }
            }
            let is_swap = matches!(
                op,
                Op::FtTransferCall { .. }
                    | Op::PlachDepositNear { .. }
                    | Op::ShardsBuy { .. }
                    | Op::ShardsSell { .. }
                    | Op::CurveBuy(_)
                    | Op::CurveSell(_)
                    | Op::Chain(_)
                    | Op::IntentsSwap(_)
            );
            // v1.1: at most one swap and it is the last op, so it is the last action of its
            // receiver batch and the batch result is the swap result seen by the callback.
            if is_swap && i != last {
                fail("E_BAD_OP");
            }
            let (g, n) = match op {
                Op::NearDeposit { amount } => {
                    if amount.0 == 0 {
                        fail("E_BAD_OP");
                    }
                    (GAS_NEAR_DEPOSIT * TGAS, amount.0)
                }
                Op::NearWithdraw { .. } => (GAS_NEAR_WITHDRAW * TGAS, 1),
                Op::StorageDeposit { token, amount } => {
                    if amount.0 > MAX_STORAGE_DEPOSIT || token == &me {
                        fail("E_BAD_OP");
                    }
                    storage_used.push(token);
                    spend = ok(add(spend, amount.0));
                    (GAS_STORAGE_DEPOSIT * TGAS, amount.0)
                }
                Op::FtTransferCall { token, receiver_id, amount, msg, gas } => {
                    if amount.0 == 0 || token == &me {
                        fail("E_BAD_OP");
                    }
                    // v1.6: a TokenCurve token is a venue by suffix of its allowlisted factory
                    let kind = self
                        .dex_kind(receiver_id)
                        .or_else(|| venues::token_curve_kind(&self.dex_allowlist, receiver_id))
                        .unwrap_or_else(|| fail("E_BAD_DEX"));
                    let ctx = Ctx {
                        self_id: &me,
                        wrap: &self.wrap,
                        token_in: token,
                        referrer: &self.fee.fee_recipient,
                    };
                    let s = match kind {
                        DexKind::RheaClassic | DexKind::RheaDcl | DexKind::Plach | DexKind::ShardsToken => {
                            ok(msg::parse(kind, msg, &ctx))
                        }
                        _ => ok(msg_venues::parse(
                            kind,
                            msg,
                            &msg_venues::VCtx {
                                self_id: &me,
                                wrap: &self.wrap,
                                token_in: token,
                                receiver: receiver_id,
                                referrer: &self.fee.fee_recipient,
                            },
                        )),
                    };
                    let max_gas = match kind {
                        DexKind::RheaClassic => MAX_SWAP_GAS_RHEA,
                        DexKind::RheaDcl => MAX_SWAP_GAS_DCL,
                        DexKind::Plach => MAX_SWAP_GAS_PLACH,
                        // dex_kind never returns it (a ShardsToken entry is a factory, not a venue)
                        DexKind::ShardsToken => fail("E_BAD_DEX"),
                        _ => venues::MAX_CURVE_GAS,
                    };
                    if gas.0 > max_gas * TGAS || gas.0 < MIN_SWAP_GAS * TGAS {
                        fail("E_GAS");
                    }
                    storage_targets.push(token.clone());
                    if let Ok(t) = s.out.parse::<AccountId>() {
                        storage_targets.push(t);
                    }
                    // v1.6 (routing C.3): no swap touches a Q a route holds in flight
                    chain::assert_free(token.as_str());
                    chain::assert_free(&s.out);
                    if let Some(o) = ord {
                        // v1.6: a presale deposit (symbolic min_out) is never an order fire
                        if !venues::orderable_kind(kind) {
                            fail("E_ORDER_OPS");
                        }
                        ok(check_order_swap(o, receiver_id, token, amount.0, &s));
                        order_swaps += 1;
                        tax_gate =
                            venues::tax::gate_for(&s.out, receiver_id.as_str(), o.min_out.0, s.min_out);
                    }
                    let (counted, f) = if token == &self.wrap {
                        proof = SwapProof::Wrap;
                        (amount.0, bps(amount.0, self.fee.fee_bps))
                    } else if s.out_is_near {
                        // v1.4.8 (UNR-A-01): an order fire's sell fee comes from the STORED
                        // order's min_out (the user's bound), never from the msg's min_out that
                        // the firing key chose (check_order_swap bounds that only from below).
                        // The settled wNEAR output is not observable in on_swap_settled, and
                        // an honest swap delivers >= the order's min_out, so this fee is
                        // <= fee_bps x the actual output. Device `execute` keeps its own msg
                        // bound (the device key is trusted with the balance, DR-1).
                        let base = ord.map_or(s.min_out, |o| o.min_out.0.min(s.min_out));
                        (0, bps(base, self.fee.fee_bps))
                    } else {
                        (0, 0)
                    };
                    spend = ok(add(spend, counted));
                    swap = Some((amount.0, counted, f));
                    (gas.0, 1)
                }
                Op::PlachRegisterAssets { dex, asset_ids } => {
                    self.assert_plach(dex);
                    if asset_ids.is_empty()
                        || asset_ids.len() > MAX_PLACH_ASSETS
                        || asset_ids.iter().any(|a| a.is_empty() || a.len() > MAX_ASSET_ID_LEN)
                        || asset_ids.iter().any(|a| names_self(a, &me))
                    {
                        fail("E_BAD_OP");
                    }
                    (GAS_REGISTER_ASSETS * TGAS, 1)
                }
                Op::DexStorageDeposit { dex } => {
                    self.assert_dcl(dex);
                    spend = ok(add(spend, DCL_REGISTRATION));
                    // two actions: second one's action fee budgeted here
                    ((2 * GAS_DCL_STORAGE + GAS_PER_ACTION) * TGAS, DCL_REGISTRATION + 1)
                }
                Op::DexWithdraw { dex, token, amount } => {
                    let kind = self.dex_kind(dex);
                    if !matches!(kind, Some(DexKind::RheaClassic | DexKind::RheaDcl)) {
                        fail("E_BAD_DEX");
                    }
                    let bad_amount = match kind {
                        Some(DexKind::RheaClassic) => amount.is_some(),
                        _ => amount.is_some_and(|a| a.0 == 0),
                    };
                    if token == &me || bad_amount {
                        fail("E_BAD_OP");
                    }
                    // registering on the token being recovered is allowed in the same execute
                    storage_targets.push(token.clone());
                    (GAS_DCL_WITHDRAW * TGAS, 1)
                }
                Op::PlachWithdraw { dex, asset_id, amount } => {
                    self.assert_plach(dex);
                    if asset_id.is_empty()
                        || asset_id.len() > MAX_ASSET_ID_LEN
                        || amount.is_some_and(|a| a.0 == 0)
                        || names_self(asset_id, &me)
                    {
                        fail("E_BAD_OP");
                    }
                    if let Some(t) = asset_id.strip_prefix("nep141:").and_then(|t| t.parse().ok()) {
                        storage_targets.push(t);
                    }
                    (GAS_PLACH_WITHDRAW * TGAS, 1)
                }
                Op::ShardsBuy { token, amount, min_out, gas } => {
                    self.assert_shards(token);
                    chain::assert_free(token.as_str());
                    if amount.0 == 0 || min_out.0 == 0 {
                        fail("E_BAD_OP");
                    }
                    if gas.0 > MAX_SWAP_GAS_SHARDS_BUY * TGAS || gas.0 < MIN_SWAP_GAS * TGAS {
                        fail("E_GAS");
                    }
                    storage_targets.push(token.clone());
                    let s = Swap { out_is_near: false, min_out: min_out.0, out: token.to_string() };
                    if let Some(o) = ord {
                        ok(check_order_swap(o, token, &self.wrap, amount.0, &s));
                        order_swaps += 1;
                    }
                    // wNEAR input through wrap.ft_transfer_call: wrap's resolve reports what was used
                    spend = ok(add(spend, amount.0));
                    swap = Some((amount.0, amount.0, bps(amount.0, self.fee.fee_bps)));
                    proof = SwapProof::Wrap;
                    (gas.0, 1)
                }
                Op::ShardsSell { token, amount, min_out, gas } => {
                    self.assert_shards(token);
                    chain::assert_free(token.as_str());
                    if amount.0 == 0 || min_out.0 == 0 {
                        fail("E_BAD_OP");
                    }
                    if gas.0 > MAX_SWAP_GAS_SHARDS_SELL * TGAS || gas.0 < MIN_SWAP_GAS * TGAS {
                        fail("E_GAS");
                    }
                    storage_targets.push(token.clone());
                    let s = Swap { out_is_near: true, min_out: min_out.0, out: self.wrap.to_string() };
                    if let Some(o) = ord {
                        ok(check_order_swap(o, token, token, amount.0, &s));
                        order_swaps += 1;
                    }
                    // Reserved (maximum pre-check) fee, as for every sell to NEAR: bps of the user's
                    // bound (UNR-A-01: the stored order's min_out for a fire). What is charged is
                    // bps of the credited output that actually arrived (on_shards_settled).
                    let base = ord.map_or(min_out.0, |o| o.min_out.0.min(min_out.0));
                    swap = Some((amount.0, 0, bps(base, self.fee.fee_bps)));
                    proof = SwapProof::ShardsSell;
                    shards_sell = Some(token.clone());
                    // + the settle chain on_shards_sold schedules (withdraw_quote + callback), above
                    // the GAS_CALLBACK the swap callback is budgeted with below; 2 x 1 yocto
                    (gas.0 + (GAS_SHARDS_SOLD_CB - GAS_CALLBACK) * TGAS, 2)
                }
                Op::ShardsWithdrawQuote { token } => {
                    self.assert_shards(token);
                    (GAS_SHARDS_WITHDRAW * TGAS, 1)
                }
                Op::CurveBuy(t) | Op::CurveSell(t) => {
                    let vctx = venues::Ctx {
                        me: &me,
                        wrap: &self.wrap,
                        fee_bps: self.fee.fee_bps,
                        now_ns: now,
                        order_min_out: ord.map(|o| o.min_out.0),
                    };
                    let p = ok(venues::plan(&self.dex_allowlist, matches!(op, Op::CurveBuy(_)), t, &vctx));
                    storage_targets.extend(p.storage.iter().cloned());
                    chain::assert_free(p.token_in.as_str());
                    chain::assert_free(&p.swap.out);
                    // R2-05: a Nearrr buy holds its output token until its settle (refund proof)
                    venues::factory::lock_output(&p, client_order_id);
                    if let Some(o) = ord {
                        if !p.orderable {
                            fail("E_ORDER_OPS");
                        }
                        ok(check_order_swap(o, &p.order_dex, &p.token_in, t.amount.0, &p.swap));
                        order_swaps += 1;
                    }
                    // AUDIT-T0: a token0 buy's fill size is the user's stored max_out
                    if let Some((id, ..)) = order.as_ref() {
                        ok(venues::order_terms::check(*id, t.max_out));
                    }
                    spend = ok(add(spend, p.spend));
                    swap = Some((t.amount.0, p.counted, p.fee));
                    proof = SwapProof::from_curve(p.settle);
                    // A1 review: every planned call beyond the first is one more action (its fee
                    // is pre-charged from the prepaid gas like the per-op GAS_PER_ACTION below)
                    let extra = (p.calls.len() as u64).saturating_sub(1) * GAS_PER_ACTION * TGAS;
                    let r = (p.gas.saturating_add(extra), p.native_out);
                    curve = Some(p);
                    r
                }
                Op::Chain(c) => {
                    let e = self.route_env(&me, now);
                    let p = ok(chain::check_chain(&e, c, ord.is_some(), ord.map(|o| o.min_out.0)));
                    // V16-08: a route id is unique while the route lives
                    ok(chain::check_route_id(client_order_id, ord.is_some()));
                    // v1.6 rev 2: q, the input and the output may be registered in the same execute
                    for t in [c.q.as_str(), &p.token_in, &p.token_out] {
                        chain::assert_free(t);
                        if let Ok(t) = t.parse::<AccountId>() {
                            storage_targets.push(t);
                        }
                    }
                    if let (Some(o), Some((id, ..))) = (ord, order.as_ref()) {
                        ok(chain::check_chain_order(o, chain::load_via(*id).as_ref(), c, &p));
                        // AUDIT-T0: a curve leg 1's max_out is the stored one; leg 2 never has one
                        if let chain::ChainLeg::CurveBuy(t) = &c.leg1 {
                            ok(venues::order_terms::check(*id, t.max_out));
                        }
                        if matches!(&c.leg2, chain::ChainLeg::CurveBuy(t) if t.max_out.is_some()) {
                            fail("E_ORDER_MISMATCH");
                        }
                        order_swaps += 1;
                        let (l2_dex, l2_min) =
                            p.l2.as_ref().map_or((String::new(), 0), |l| (l.dex.to_string(), l.min_out));
                        tax_gate = venues::tax::gate_for(&p.token_out, &l2_dex, o.min_out.0, l2_min)
                            .map(|g| venues::tax::Gate { native_out: U128(p.native_out), ..g });
                    }
                    // AUDIT-S1: a curve leg's storage / buy extra counts too (never returned)
                    spend = ok(add(spend, ok(add(p.counted, p.extra_spend))));
                    swap = Some((p.l1.amount, p.counted, p.fee));
                    proof = SwapProof::of_leg(p.l1.proof);
                    route = Some((op.clone(), None));
                    (p.gas, p.native_out)
                }
                Op::IntentsSwap(s) => {
                    // never from an order fire (owner decision: the relayer can't fund 1Click)
                    let e = self.route_env(&me, now);
                    let ip = ok(chain::exec::check_intents_swap(&e, s, ord.is_some()));
                    // V16-08: a route id is unique while the route lives
                    ok(chain::check_route_id(client_order_id, false));
                    // v1.6 rev 2: a continuation can't register storage, so this signed execute
                    // may (StorageDeposit ops before it: q and the continuation's output)
                    storage_targets.push(s.q.clone());
                    storage_targets.push(s.cont.token_out.clone());
                    let amount = ip.quote.amount;
                    spend = ok(add(spend, amount));
                    swap = Some((amount, amount, ip.fee));
                    proof = SwapProof::Wrap;
                    route = Some((op.clone(), Some(ip)));
                    ((chain::exec::GAS_VERIFIER + chain::GAS_CHAIN_CB + chain::GAS_ACTION) * TGAS, 1)
                }
                Op::IntentsPull(_) => fail("E_BAD_OP"),
                // v1.6 (F-01): restrict-only veto, applied in step 7; moves nothing
                Op::CancelAutoUpgrade {} => (0, 0),
                Op::CurveClaim(cl) => {
                    let vctx = venues::Ctx {
                        me: &me,
                        wrap: &self.wrap,
                        fee_bps: self.fee.fee_bps,
                        now_ns: now,
                        order_min_out: None,
                    };
                    let (c, sp) = ok(venues::plan_claim(&self.dex_allowlist, cl, &vctx));
                    spend = ok(add(spend, sp));
                    if let Some(t) = &cl.token {
                        // R2-05: the only claim that sends its token (`t.ft_transfer_call` to the
                        // exchange); every other claim's token comes in or is a storage target
                        if cl.action == venues::ClaimAction::KelytraDeposit {
                            chain::assert_free(t.as_str());
                        }
                        storage_targets.push(t.clone());
                    }
                    (c.gas, c.deposit)
                }
                Op::PlachDepositNear { dex, amount, msg, gas } => {
                    self.assert_plach(dex);
                    if amount.0 == 0 {
                        fail("E_BAD_OP");
                    }
                    let s = ok(msg::parse_plach_near(msg, &me, &self.wrap, &self.fee.fee_recipient));
                    chain::assert_free(&s.out);
                    if gas.0 > MAX_SWAP_GAS_PLACH * TGAS || gas.0 < MIN_SWAP_GAS * TGAS {
                        fail("E_GAS");
                    }
                    if let Ok(t) = s.out.parse::<AccountId>() {
                        storage_targets.push(t);
                    }
                    if let Some(o) = ord {
                        ok(check_order_swap(o, dex, &self.wrap, amount.0, &s));
                        order_swaps += 1;
                        tax_gate = venues::tax::gate_for(&s.out, dex.as_str(), o.min_out.0, s.min_out);
                    }
                    spend = ok(add(spend, amount.0));
                    swap = Some((amount.0, amount.0, bps(amount.0, self.fee.fee_bps)));
                    proof = SwapProof::PlachNear;
                    (gas.0, amount.0)
                }
            };
            gas = gas
                .checked_add(g)
                .and_then(|x| x.checked_add(GAS_PER_ACTION * TGAS))
                .unwrap_or_else(|| fail("E_GAS"));
            native_out = ok(add(native_out, n));
        }
        if storage_used.iter().any(|t| !storage_targets.contains(t)) {
            fail("E_STORAGE_TARGET");
        }
        if ord.is_some() && order_swaps != 1 {
            fail("E_ORDER_OPS");
        }
        let fee = swap.map_or(0, |s| s.2);
        if swap.is_some() {
            gas = gas.checked_add((GAS_CALLBACK + GAS_PER_ACTION) * TGAS).unwrap_or_else(|| fail("E_GAS"));
        }
        // v1.6 (taxed tokens): a gated fire also attaches the tax view + its gate callback
        if tax_gate.is_some() {
            gas = gas.checked_add(venues::tax::GATE_EXTRA_TGAS * TGAS).unwrap_or_else(|| fail("E_GAS"));
        }
        spend = ok(add(spend, fee));
        // The fee is paid later (on success) but must be affordable now.
        native_out = ok(add(native_out, fee));
        // 5
        let day_start = {
            ok(check_caps(&mut self.day, &self.caps, now, spend, max_in));
            self.day.start_ns
        };
        // 6
        ok(check_gas(ops.len(), gas, env::prepaid_gas().as_gas()));
        // v1.2.1: all attached gas is charged to the daily cap (bounds gas-burn drains).
        // A1-F1: charge the WHOLE prepaid gas of this receipt: it upper-bounds everything the tx
        // can make any receipt burn (every call below gets exactly its declared gas, weight 0).
        let gas_spend = self.charge_gas(env::prepaid_gas().as_gas());
        // v1.4.9 (UNR-A-10): an automation-key fire (assert_self: signer == self, so this is the
        // signing key) passes its gas charge to the callback, which returns it on a reopen.
        let relayer_gas = (order.is_some() && is_relayer(&env::signer_account_pk())).then_some(gas_spend);
        // v1.4.7: a relayer BUY charges its whole spend (wNEAR/NEAR input + storage + max fee) and
        // its gas bound to the weekly relayer allowance (at least allowance / 20 per fire, C1-L3).
        // A provable refund later returns the part that came back (input + fee); storage, gas and
        // (v1.4.8, RA7-1) the floor stay charged. v1.4.8: only with an owner-set allowance
        // (`relayer_buy` is set only then, by execute_order in this same receipt).
        if let Some((_, _, rw, true)) = order.as_mut() {
            if let Some(allowance) = relayer_allowance() {
                let (counted, max_fee) = swap.map_or((0, 0), |s| (s.1, s.2));
                let floor = allowance / MAX_RELAYER_FIRES_PER_WEEK;
                let charge = spend.saturating_add(gas_spend).max(floor);
                let kept = spend.saturating_sub(counted.saturating_add(max_fee)).saturating_add(gas_spend);
                let mut w = relayer_week_state();
                roll_week(&mut w, now);
                match w.spent_yocto.checked_add(charge) {
                    Some(x) if x <= allowance => w.spent_yocto = x,
                    _ => fail("E_RELAYER_WEEKLY"),
                }
                save_relayer_week(&w);
                *rw = Some((w.start_ns, charge.saturating_sub(kept.max(floor))));
            }
        }
        // v1.6: escrowed route fees stay liquid (routing C.2.2)
        ok(check_reserve(liquid_balance().saturating_sub(chain::escrow_total()), native_out));
        // 7: one promise per receiver, all independent; only the swap gets a callback.
        let mut batches: Vec<(AccountId, near_sdk::PromiseIndex)> = Vec::with_capacity(4);
        let mut last_idx = None;
        for op in ops {
            let (rcv, method, args, deposit, g, swap_w) = match op {
                Op::NearDeposit { amount } => {
                    (self.wrap.clone(), "near_deposit", b"{}".to_vec(), amount.0, GAS_NEAR_DEPOSIT * TGAS, 0)
                }
                Op::NearWithdraw { amount } => (
                    self.wrap.clone(),
                    "near_withdraw",
                    format!("{{\"amount\":\"{}\"}}", amount.0).into_bytes(),
                    1,
                    GAS_NEAR_WITHDRAW * TGAS,
                    0,
                ),
                Op::StorageDeposit { token, amount } => (
                    token,
                    "storage_deposit",
                    format!("{{\"account_id\":\"{}\",\"registration_only\":true}}", me).into_bytes(),
                    amount.0,
                    GAS_STORAGE_DEPOSIT * TGAS,
                    0,
                ),
                Op::FtTransferCall { token, receiver_id, amount, msg, gas } => (
                    token,
                    "ft_transfer_call",
                    format!(
                        "{{\"receiver_id\":\"{}\",\"amount\":\"{}\",\"msg\":{}}}",
                        receiver_id,
                        amount.0,
                        jstr(&msg)
                    )
                    .into_bytes(),
                    1,
                    gas.0,
                    1,
                ),
                Op::PlachRegisterAssets { dex, asset_ids } => {
                    let ids: Vec<String> = asset_ids.iter().map(|a| jstr(a)).collect();
                    (
                        dex,
                        "register_assets",
                        format!("{{\"asset_ids\":[{}]}}", ids.join(",")).into_bytes(),
                        1,
                        GAS_REGISTER_ASSETS * TGAS,
                        0,
                    )
                }
                Op::DexStorageDeposit { dex } => {
                    let idx = batch_for(&mut batches, dex);
                    dcl_register_actions(idx);
                    last_idx = Some(idx);
                    continue;
                }
                Op::DexWithdraw { dex, token, amount } => {
                    let a = amount.map_or(String::new(), |a| format!(",\"amount\":\"{}\"", a.0));
                    let args = format!("{{\"token_id\":\"{}\"{}}}", token, a).into_bytes();
                    if self.dex_kind(&dex) == Some(DexKind::RheaClassic) {
                        (dex, "claim_lostfound", args, 1, GAS_DCL_WITHDRAW * TGAS, 0)
                    } else {
                        (dex, "withdraw_asset", args, 0, GAS_DCL_WITHDRAW * TGAS, 0)
                    }
                }
                Op::PlachWithdraw { dex, asset_id, amount } => {
                    let amt = match amount {
                        None => "{\"Full\":{\"at_least\":null}}".to_string(),
                        Some(a) => format!("{{\"Exact\":\"{}\"}}", a.0),
                    };
                    (
                        dex,
                        "withdraw",
                        format!("{{\"asset_id\":{},\"amount\":{}}}", jstr(&asset_id), amt).into_bytes(),
                        1,
                        GAS_PLACH_WITHDRAW * TGAS,
                        0,
                    )
                }
                // v1.5: every field below is ours (no caller-supplied msg or recipient)
                Op::ShardsBuy { token, amount, min_out, gas } => {
                    let m = format!(
                        "{{\"v\":1,\"action\":\"buy\",\"order_id\":{},\"min_amount_out\":\"{}\",\"max_total_fee_bps\":{},\"deadline_ns\":\"{}\"}}",
                        jstr(client_order_id),
                        min_out.0,
                        SHARDS_MAX_TOTAL_FEE_BPS,
                        shards_deadline(now)
                    );
                    (
                        self.wrap.clone(),
                        "ft_transfer_call",
                        format!(
                            "{{\"receiver_id\":\"{}\",\"amount\":\"{}\",\"msg\":{}}}",
                            token,
                            amount.0,
                            jstr(&m)
                        )
                        .into_bytes(),
                        1,
                        gas.0,
                        1,
                    )
                }
                Op::ShardsSell { token, amount, min_out, gas } => (
                    token,
                    "sell_exact_in",
                    format!(
                        "{{\"amount\":\"{}\",\"min_amount_out\":\"{}\",\"max_total_fee_bps\":{},\"deadline_ns\":\"{}\"}}",
                        amount.0,
                        min_out.0,
                        SHARDS_MAX_TOTAL_FEE_BPS,
                        shards_deadline(now)
                    )
                    .into_bytes(),
                    1,
                    gas.0,
                    1,
                ),
                Op::ShardsWithdrawQuote { token } => {
                    (token, "withdraw_quote", b"{}".to_vec(), 1, GAS_SHARDS_WITHDRAW * TGAS, 0)
                }
                // v1.6: the calls planned (and checked) in step 4, in order, one receiver
                Op::CurveBuy(_) | Op::CurveSell(_) => {
                    let p = curve.as_ref().unwrap_or_else(|| fail("E_BAD_OP"));
                    for c in &p.calls {
                        let idx = batch_for(&mut batches, c.receiver.clone());
                        env::promise_batch_action_function_call_weight(
                            idx,
                            c.method,
                            c.args.as_bytes(),
                            NearToken::from_yoctonear(c.deposit),
                            Gas::from_gas(c.gas),
                            GasWeight(0),
                        );
                        last_idx = Some(idx);
                    }
                    continue;
                }
                // v1.6: dispatched after this loop with the settle args
                Op::Chain(_) | Op::IntentsSwap(_) | Op::IntentsPull(_) => continue,
                Op::CancelAutoUpgrade {} => {
                    upgrade::veto("device");
                    continue;
                }
                Op::CurveClaim(cl) => {
                    let vctx = venues::Ctx {
                        me: &me,
                        wrap: &self.wrap,
                        fee_bps: self.fee.fee_bps,
                        now_ns: now,
                        order_min_out: None,
                    };
                    let (c, _) = ok(venues::plan_claim(&self.dex_allowlist, &cl, &vctx));
                    (c.receiver, c.method, c.args.into_bytes(), c.deposit, c.gas, 0)
                }
                // `msg` was fully parsed by serde (no trailing input), so splicing it is exact.
                Op::PlachDepositNear { dex, amount, msg, gas } => (
                    dex,
                    "deposit_near",
                    format!("{{\"operations\":{}}}", msg).into_bytes(),
                    amount.0,
                    gas.0,
                    1,
                ),
            };
            // v1.6 (taxed tokens): a gated fire's swap (the last op) is sent by on_tax_gate, after
            // the output token's tax view, which runs after this receiver's earlier batch
            if let (1, Some(gt)) = (swap_w, tax_gate.as_ref()) {
                let after = batches.iter().find(|(a, _)| a == &rcv).map(|(_, i)| *i);
                last_idx = Some(venues::tax::schedule_view(gt, after));
                gated = Some(venues::tax::GatedCall {
                    receiver: rcv,
                    method: method.to_string(),
                    args: String::from_utf8(args).unwrap_or_else(|_| fail("E_JSON")),
                    deposit: U128(deposit),
                    gas: U64(g),
                });
                continue;
            }
            let idx = batch_for(&mut batches, rcv);
            env::promise_batch_action_function_call_weight(
                idx,
                method,
                &args,
                NearToken::from_yoctonear(deposit),
                Gas::from_gas(g),
                GasWeight(0), // A1-F1: no leftover-gas distribution
            );
            last_idx = Some(idx);
        }
        if let (Some((amount, counted, f)), true) = (swap, last_idx.is_some() || route.is_some()) {
            // v1.6 (R2-09): a settle is in flight; the permissionless auto-upgrade waits for it
            upgrade::mark_in_flight(upgrade::SETTLE_WINDOW_BLOCKS);
            let settle = format!(
                    "{{\"client_order_id\":{},\"amount\":\"{}\",\"counted\":\"{}\",\"fee\":\"{}\",\"day_start\":\"{}\",\"proof\":\"{}\"{}}}",
                    jstr(client_order_id),
                    amount,
                    counted,
                    f,
                    day_start,
                    proof.as_str(),
                    order.as_ref().map_or(String::new(), |(id, _, rw, _)| {
                        let r = rw.map_or(String::new(), |(w, c)| {
                            format!(",\"relayer_week\":\"{w}\",\"relayer_counted\":\"{c}\"")
                        });
                        let g = relayer_gas.map_or(String::new(), |g| format!(",\"relayer_gas\":\"{g}\""));
                        format!(",\"order_id\":\"{id}\"{r}{g}")
                    })
            );
            // v1.6: a route runs its own promise chain and settles itself
            let routed = match route.take() {
                Some((Op::Chain(c), _)) => {
                    // v1.6 (taxed tokens): a gated Chain fire starts after the output's tax view
                    match tax_gate.as_ref() {
                        Some(gt) => {
                            let start = self.budgets(&c).0;
                            venues::tax::gate_chain(gt, *c, start, &settle, client_order_id)
                        }
                        None => self.dispatch_chain(*c, &settle, client_order_id),
                    }
                    true
                }
                Some((Op::IntentsSwap(s), Some(ip))) => {
                    // v1.6: what this execute counted, released if the route is proven refunded
                    save_route_spend(client_order_id, day_start, ip.quote.amount, ip.fee);
                    self.dispatch_intents(s, ip, &settle, client_order_id);
                    true
                }
                Some(_) => fail("E_BAD_OP"),
                None => false,
            };
            // v1.5: a Shards sell settles in two steps (credit -> payout to self -> settle)
            let (method, args, g) = match shards_sell {
                Some(t) => (
                    "on_shards_sold",
                    format!("{{\"token\":\"{}\",\"settle\":{}}}", t, jstr(&settle)),
                    GAS_SHARDS_SOLD_CB,
                ),
                // v1.6: payable curve buys / direct curve sells settle on measured deltas
                None => {
                    match (curve.as_ref().filter(|p| p.settle.measured()), tax_gate.as_ref(), gated.as_ref())
                    {
                        (Some(p), _, _) => {
                            venues::settle::callback(p.settle, &settle, liquid_balance(), p.fee_cap)
                        }
                        (None, Some(gt), Some(call)) => venues::tax::callback(gt, call, &settle),
                        _ => ("on_swap_settled", settle, GAS_CALLBACK),
                    }
                }
            };
            if !routed {
                env::promise_then(
                    last_idx.unwrap_or_else(|| fail("E_BAD_OP")),
                    me,
                    method,
                    args.as_bytes(),
                    NearToken::from_yoctonear(0),
                    Gas::from_tgas(g),
                );
            }
        }
        // 8 (`fee` = maximum; charged in on_swap_settled only if the swap used its input)
        env::log_str(&format!(
            "EVENT_JSON:{{\"standard\":\"nttrade\",\"version\":\"1\",\"event\":\"execute\",\"data\":{{\"client_order_id\":{},\"spend\":\"{}\",\"fee\":\"{}\",\"gas_spend\":\"{}\"}}}}",
            jstr(client_order_id),
            spend,
            fee,
            gas_spend
        ));
    }

    /// v1.1: runs after the swap promise. `used` = what ft_transfer_call reports as used
    /// (0 on failure / full refund); deposit_near: success = all used, failure = 0.
    /// Fee is charged pro-rata on `used`; the unused spend is returned to the daily window.
    /// v1.4.3 (ORDER-001): `proof` names the swap kind. `plach_near` (deposit_near): its only
    /// refund is the runtime revert of a failed receipt, so any non-Failed result is fully used
    /// (a returned "0" is not a refund). `wrap`: wrap.near's resolve is trusted, so 0 used
    /// reopens an order. `token` (any other token_in): only Failed reopens.
    #[private]
    #[allow(clippy::too_many_arguments)]
    pub fn on_swap_settled(
        &mut self,
        client_order_id: String,
        amount: U128,
        counted: U128,
        fee: U128,
        day_start: U64,
        order_id: Option<U64>,
        relayer_week: Option<U64>,
        relayer_counted: Option<U128>,
        proof: Option<String>,
        relayer_gas: Option<U128>,
    ) {
        let failed = matches!(env::promise_result_checked(0, 0), Err(PromiseError::Failed)); // TooLong = success
        let plach_near = proof.as_deref() == Some(SwapProof::PlachNear.as_str());
        let used = match env::promise_result_checked(0, 128) {
            Err(PromiseError::Failed) => 0,
            Err(_) => amount.0,
            Ok(_) if plach_near => amount.0,
            Ok(b) if b.is_empty() => amount.0,
            // unparseable success => treat as fully used (never under-count spend)
            Ok(b) => serde_json::from_slice::<U128>(&b).map_or(amount.0, |u| u.0.min(amount.0)),
        };
        let charged = mul_div(fee.0, used, amount.0);
        let a = SettleArgs {
            client_order_id,
            amount,
            counted,
            fee,
            day_start,
            order_id,
            relayer_week,
            relayer_counted,
            proof,
            relayer_gas,
        };
        self.finish_settle(a, failed, used, charged);
    }

    /// v1.5: step 2 of a ShardsSell, after `token.sell_exact_in`. Failed = the sell reverted (the
    /// token panics on every refusal: slippage, phase, deadline) -> settled as a failed swap
    /// (no fee, spend back, an order reopens). Success = the returned U128 is the wNEAR credited to
    /// this account inside the token -> `token.withdraw_quote{amount}` (no `recipient_id`: the
    /// token pays its caller, this account, in native NEAR), then `on_shards_settled`. A success
    /// with no readable positive credit settles as used with no fee and no payout (whatever was
    /// credited stays recoverable with a ShardsWithdrawQuote op).
    #[private]
    pub fn on_shards_sold(&mut self, token: AccountId, settle: String) {
        let a: SettleArgs = serde_json::from_str(&settle).unwrap_or_else(|_| fail("E_JSON"));
        let credit = match env::promise_result_checked(0, 64) {
            Err(PromiseError::Failed) => {
                return self.finish_settle(a, true, 0, 0);
            }
            Ok(b) => serde_json::from_slice::<U128>(&b).map_or(0, |c| c.0),
            Err(_) => 0,
        };
        if credit == 0 {
            let used = a.amount.0;
            return self.finish_settle(a, false, used, 0);
        }
        // measured before the payout is scheduled: what arrives by on_shards_settled is on top
        let liquid_before = liquid_balance();
        let me = env::current_account_id();
        let args = serde_json::to_string(&ShardsSettleArgs {
            settle: a,
            credit: U128(credit),
            liquid_before: U128(liquid_before),
        })
        .unwrap_or_else(|_| fail("E_JSON"));
        Promise::new(token)
            .function_call(
                "withdraw_quote",
                format!("{{\"amount\":\"{credit}\"}}").into_bytes(),
                NearToken::from_yoctonear(1),
                Gas::from_tgas(GAS_SHARDS_WITHDRAW),
            )
            .then(Promise::new(me).function_call(
                "on_shards_settled",
                args.into_bytes(),
                NearToken::from_yoctonear(0),
                Gas::from_tgas(GAS_CALLBACK),
            ))
            .detach();
    }

    /// v1.5: step 3 of a ShardsSell. The sell happened (its input is used either way). The fee is
    /// fee_bps of min(credit the token reported, liquid NEAR that actually arrived since
    /// `on_shards_sold`): a token can't raise the fee above what it paid, and a failed payout (the
    /// credit stays in the token, see ShardsWithdrawQuote) pays no fee.
    #[private]
    pub fn on_shards_settled(&mut self, settle: SettleArgs, credit: U128, liquid_before: U128) {
        // v1.5 review: a failed payout (the credit stays in the token) pays no fee, whatever other
        // NEAR arrived in the meantime.
        let charged = if matches!(env::promise_result_checked(0, 0), Err(PromiseError::Failed)) {
            0
        } else {
            let arrived = liquid_balance().saturating_sub(liquid_before.0);
            bps(credit.0.min(arrived), self.fee.fee_bps)
        };
        let used = settle.amount.0;
        self.finish_settle(settle, false, used, charged);
    }

    /// Settlement shared by every swap kind: the fee (`charged`, skipped if it would dip below
    /// RESERVE), the daily window, and the order's fate.
    fn finish_settle(&mut self, a: SettleArgs, failed: bool, used: u128, mut charged: u128) {
        let SettleArgs {
            client_order_id,
            amount,
            counted,
            fee,
            day_start,
            order_id,
            relayer_week,
            relayer_counted,
            proof,
            relayer_gas,
        } = a;
        // Accepted, user-favorable race: concurrent executes may have used the headroom the
        // fee was reserved in. Never dip below RESERVE for a fee; skip it and log it.
        if charged > 0 && check_reserve(liquid_balance(), charged).is_err() {
            env::log_str(&format!(
                "EVENT_JSON:{{\"standard\":\"nttrade\",\"version\":\"1\",\"event\":\"fee_skipped\",\"data\":{{\"client_order_id\":{},\"fee\":\"{}\"}}}}",
                jstr(&client_order_id),
                charged
            ));
            charged = 0;
        }
        let back =
            fee.0.saturating_sub(charged).saturating_add(counted.0 - mul_div(counted.0, used, amount.0));
        // v1.5: a Shards sell's fee is on its actual output, which can exceed the reserved maximum
        // (bps of min_out); the excess is paid out of that output and counts as spend.
        let extra = charged.saturating_sub(fee.0);
        if self.day.start_ns == day_start.0 {
            self.day.spent_yocto = self.day.spent_yocto.saturating_sub(back).saturating_add(extra);
        }
        if charged > 0 {
            Promise::new(self.fee.fee_recipient.clone())
                .transfer(NearToken::from_yoctonear(charged))
                .detach();
        }
        // v1.3: filled (anything used) -> order consumed; nothing used -> reopened for retry.
        if let Some(id) = order_id {
            if let Some(mut o) = load_order(id.0) {
                // A1-F4: reopen only on a PROVABLE refund: the swap batch failed (runtime revert),
                // or wrap.near (trusted NEP-141) resolved to 0 used. A user-chosen token_in
                // reporting "0" can't reopen (and so refill) an order: it stays consumed.
                // v1.4.3 (ORDER-001): "wrap resolved 0" only for an ft_transfer_call ON wrap, not
                // for a Plach NEAR buy (token_in == wrap too). Pre-v1.4.3 in-flight callbacks carry
                // no `proof`: the old rule applies to them.
                let wrap_resolved = match proof.as_deref() {
                    Some(p) => p == SwapProof::Wrap.as_str(),
                    None => o.token_in == self.wrap,
                };
                // v1.4.8 (UNR-A-02): a user-chosen token_in resolved to "0" (Successful). An
                // honest NEP-141 does this when the DEX refused the swap (e.g. a min_out the
                // pool can't meet), so consuming the order let a firing key delete stop-losses
                // without a trade: it reopens too. Plach NEAR buys (ORDER-001) and pre-v1.4.3
                // callbacks stay consumed.
                let token_zero = proof.as_deref() == Some(SwapProof::Token.as_str());
                if used == 0 && (failed || wrap_resolved || token_zero) {
                    o.pending = false;
                    save_order(id.0, &o);
                    // v1.4.1: a failed relayer fire gives its weekly allowance back, minus the
                    // allowance / 20 floor (RA7-1). v1.4.9 (UNR-A-09): also on a token "0", so an
                    // honest DEX refusal of a relayer sell no longer costs its whole min_out from
                    // the week. A lying token can't refill the week: the floor stays charged, so
                    // at most 20 such fires a week (as for Failed).
                    if let (Some(wk), Some(c)) = (relayer_week, relayer_counted) {
                        let mut w = relayer_week_state();
                        if w.start_ns == wk.0 {
                            w.spent_yocto = w.spent_yocto.saturating_sub(c.0);
                            save_relayer_week(&w);
                        }
                    }
                    // v1.4.9 (UNR-A-10, A-11): a reopened relayer fire moved nothing, so its gas
                    // charge leaves the daily gas tally again: a looping relayer key can no longer
                    // fill the owner's daily cap and block the device. Its real gas is paid within
                    // the automation key's FC allowance (RD8-1), which bounds such loops.
                    if let Some(g) = relayer_gas.filter(|_| self.day.start_ns == day_start.0) {
                        save_day_gas(day_start.0, day_gas(day_start.0).saturating_sub(g.0));
                    }
                    order_event("order_reopened", id.0);
                } else {
                    remove_order(id.0);
                    order_event(
                        if used == 0 { "order_consumed_unproven_refund" } else { "order_filled" },
                        id.0,
                    );
                }
            }
        }
        env::log_str(&format!(
            "EVENT_JSON:{{\"standard\":\"nttrade\",\"version\":\"1\",\"event\":\"settled\",\"data\":{{\"client_order_id\":{},\"used\":\"{}\",\"fee\":\"{}\",\"spend_returned\":\"{}\"}}}}",
            jstr(&client_order_id),
            used,
            charged,
            back
        ));
    }

    /// NEAR (native, keeps RESERVE) or FT to the owner. Destination is not a parameter.
    pub fn withdraw_to_owner(&mut self, token: Option<AccountId>, amount: U128) {
        self.assert_device();
        if token.as_ref() == Some(&env::current_account_id()) {
            fail("E_BAD_OP");
        }
        // R2-05: a token held by an in-flight route / Nearrr buy can't leave meanwhile
        if let Some(t) = &token {
            chain::assert_free(t.as_str());
        }
        self.sync_caps();
        let now = env::block_timestamp();
        // v1.2.1: its gas counts toward the daily cap too (token may be any contract).
        roll_day(&mut self.day, now);
        // v1.6: a signer-kind owner's home is its intents.near balance (spec §5.1)
        let home = self.home_is_intents();
        // v1.3.2: token path = (register +) transfer/unwrap + report callback
        let g = if home {
            self.home_gas(&token)
        } else if token.is_some() {
            GAS_FT_STORAGE + GAS_FT_SEND + GAS_WITHDRAW_CB + 3 * GAS_PER_ACTION
        } else {
            GAS_PER_ACTION
        };
        // v1.4.3 (CAPACCT-001): the non-wNEAR token path attaches MAX_STORAGE_DEPOSIT to
        // `token.storage_deposit` (any contract the device names; a hostile one keeps it): it is
        // charged to the daily spend and must leave RESERVE, like a StorageDeposit op.
        if token.as_ref().is_some_and(|t| t != &self.wrap) {
            ok(check_caps(&mut self.day, &self.caps, now, MAX_STORAGE_DEPOSIT, self.caps.max_trade_yocto.0));
            self.charge_gas(g * TGAS);
            ok(check_reserve(liquid_balance(), MAX_STORAGE_DEPOSIT + 1));
        } else {
            self.charge_gas(g * TGAS);
        }
        if home {
            self.send_home(token, amount.0);
        } else {
            self.send(token, amount.0, self.owner.clone(), true);
        }
    }

    /// v1.3 (device): register a 24/7 order. Nothing moves and nothing is spent now; the
    /// daily cap is charged only when it executes. Storage (<~0.004 NEAR) is paid by the account.
    #[allow(clippy::too_many_arguments)]
    pub fn place_order(
        &mut self,
        token_in: AccountId,
        token_out: AccountId,
        amount_in: U128,
        min_out: U128,
        trigger_meta: String,
        expires_at_ns: U64,
        dexes: Vec<AccountId>,
    ) -> U64 {
        self.assert_device();
        // v1.6: optional `via` (a Chain order's legs) read from the same JSON args, so the Rust
        // signature and every pre-1.6 caller stay unchanged
        let via = chain::via_from_input();
        // AUDIT-T0: optional `max_out` (a token0 buy's exact-out size), same JSON args
        let max_out = venues::order_terms::max_out_from_input();
        let now = env::block_timestamp();
        // v1.4.3 (SC-2, invariant 10): its gas counts toward the daily cap
        self.charge_device_gas(false);
        let me = env::current_account_id();
        if amount_in.0 == 0
            || min_out.0 == 0
            || token_in == token_out
            || token_in == me
            || token_out == me
            || trigger_meta.len() > MAX_TRIGGER_META
            || dexes.is_empty()
            || dexes.len() > MAX_ORDER_DEXES
            || max_out.is_some_and(|m| m.0 < min_out.0)
        {
            fail("E_BAD_ORDER");
        }
        // v1.5: a Shards order names the token itself as its venue. v1.6: so does a TokenCurve
        // order; a curve venue that is never an order DEX (meme.cooking presale) is refused.
        if dexes.iter().any(|d| match venues::order_venue(&self.dex_allowlist, d) {
            Some(orderable) => !orderable,
            None => self.dex_kind(d).is_none() && !self.is_shards_token(d),
        }) {
            fail("E_BAD_DEX");
        }
        // v1.6 (routing C.1): a Chain order's legs (floor = min_out on the final token)
        if let Some(v) = &via {
            ok(chain::check_via(v, &token_in, &token_out, &dexes, &me));
            // V16-10: no Chain-order leg on a callback-chain venue (Kelytra, Nearrr)
            ok(chain::check_via_venues(v, &self.dex_allowlist));
        }
        if now >= expires_at_ns.0 {
            fail("E_EXPIRED");
        }
        if expires_at_ns.0 > now.saturating_add(MAX_ORDER_TTL_NS) {
            fail("E_EXPIRY_TOO_FAR");
        }
        // prune expired, then bound
        let mut index = order_index();
        for (id, _) in index.iter().filter(|(_, e)| *e < now) {
            env::storage_remove(&order_key(*id));
            // a pruned Chain order's stored legs go with it (as remove_order)
            chain::remove_via(*id);
            // INDEP-3: and its stored max_out (AUDIT-T0)
            venues::order_terms::remove(*id);
        }
        index.retain(|(_, e)| *e >= now);
        if index.len() >= MAX_OPEN_ORDERS {
            fail("E_ORDER_LIMIT");
        }
        let id: u64 = env::storage_read(K_ORDER_NEXT).map_or(1, |b| u64_from(&b));
        env::storage_write(K_ORDER_NEXT, &(id + 1).to_le_bytes());
        index.push((id, expires_at_ns.0));
        set_order_index(&index);
        if let Some(v) = &via {
            chain::save_via(id, v);
        }
        if let Some(m) = max_out {
            venues::order_terms::save(id, m);
        }
        save_order(
            id,
            &Order {
                token_in,
                token_out,
                amount_in,
                min_out,
                trigger_meta,
                expires_at_ns,
                dexes,
                pending: false,
            },
        );
        ok(check_reserve(liquid_balance(), 0));
        order_event("order_placed", id);
        U64(id)
    }

    /// v1.3: device key, or the owner's wallet (1 yocto). Never the automation key.
    #[payable]
    pub fn cancel_order(&mut self, order_id: U64) {
        if env::predecessor_account_id() == self.owner {
            self.assert_owner();
        } else {
            self.assert_device();
            // v1.4.3 (SC-2): charged, never refused (a safety action)
            self.charge_device_gas(true);
        }
        if load_order(order_id.0).is_none() {
            fail("E_NO_ORDER");
        }
        remove_order(order_id.0);
        order_event("order_cancelled", order_id.0);
    }

    /// v1.3 (device): one-click revoke of 24/7 automation (deletes the automation key).
    pub fn revoke_automation(&mut self) {
        self.assert_device();
        // v1.4.3 (SC-2): charged, never refused (a safety action)
        self.charge_device_gas(true);
        self.clear_automation();
    }

    /// Device: lower the caps (applies now). v1.4.3 (OWNERBOUND-001): also cancels a pending
    /// owner raise.
    pub fn lower_caps(&mut self, caps: Caps) {
        self.assert_device();
        self.sync_caps();
        // v1.4.3 (SC-2): charged, never refused (a safety action)
        self.charge_device_gas(true);
        ok(check_lower(&self.caps, &caps));
        self.caps = caps;
        cancel_caps_raise("device");
    }

    // ---------------- owner methods (predecessor == owner, 1 yocto) ----------------

    #[payable]
    pub fn owner_add_key(&mut self, public_key: PublicKey, kind: KeyKind) {
        self.assert_owner();
        self.add_key(public_key, kind);
    }
}

// v1.6: owner action bodies shared by the predecessor door (`owner_*`, assert_owner) and the
// signed door (`owner_signed`). Moved verbatim; no body reads predecessor or deposit.
impl TradingAccount {
    pub(crate) fn add_key(&mut self, public_key: PublicKey, kind: KeyKind) {
        let me = env::current_account_id();
        let p = Promise::new(me.clone());
        match kind {
            // v1.4.1 (B1-L1): an existing key is not a silent no-op: `on_key_added` sees the failed
            // AddKey and replaces the key (DeleteKey + AddKey, one batch) with DEVICE_METHODS.
            KeyKind::FunctionCall => {
                if is_relayer(&public_key) {
                    fail("E_AUTOMATION_KEY");
                }
                p.add_access_key_allowance(
                    public_key.clone(),
                    Allowance::Unlimited,
                    me.clone(),
                    DEVICE_METHODS,
                )
                // callbacks: small static gas + ALL leftover (weight 1), so this works at the
                // wallet / near-workspaces default gas; owner-paid, not a device path.
                .then(Promise::new(me).function_call_weight(
                    "on_key_added",
                    format!("{{\"public_key\":{}}}", jstr(&String::from(&public_key))).into_bytes(),
                    NearToken::from_yoctonear(0),
                    Gas::from_tgas(GAS_KEY_CB),
                    GasWeight(1),
                ))
            }
            #[cfg(feature = "gas-keys")]
            KeyKind::GasKey { num_nonces, balance } => {
                let p = p.add_gas_key_allowance_function_call(
                    public_key.clone(),
                    num_nonces,
                    Allowance::Unlimited,
                    me,
                    DEVICE_METHODS.into(),
                );
                if balance.0 > 0 {
                    p.transfer_to_gas_key(public_key, NearToken::from_yoctonear(balance.0))
                } else {
                    p
                }
            }
        }
        .detach();
    }
}

#[near]
impl TradingAccount {
    /// v1.4.1 (B1-L1): AddKey failed = the key already exists -> replace it in one batch so it
    /// gets the current DEVICE_METHODS; `on_key_replaced` reports the outcome.
    #[private]
    pub fn on_key_added(&mut self, public_key: PublicKey) {
        let pk = jstr(&String::from(&public_key));
        if near_sdk::is_promise_success() {
            key_event(&pk, false, true);
            return;
        }
        let me = env::current_account_id();
        Promise::new(me.clone())
            .delete_key(public_key.clone())
            .add_access_key_allowance(public_key, Allowance::Unlimited, me.clone(), DEVICE_METHODS)
            .then(Promise::new(me).function_call_weight(
                "on_key_replaced",
                format!("{{\"public_key\":{pk}}}").into_bytes(),
                NearToken::from_yoctonear(0),
                Gas::from_tgas(1),
                GasWeight(1),
            ))
            .detach();
    }

    #[private]
    pub fn on_key_replaced(&mut self, public_key: PublicKey) {
        key_event(&jstr(&String::from(&public_key)), true, near_sdk::is_promise_success());
    }

    /// v1.6: `device_key_removed{public_key, ok}` after a device key's DeleteKey (ok: false = the
    /// key did not exist).
    #[private]
    pub fn on_key_removed(&mut self, public_key: PublicKey) {
        let ok = near_sdk::is_promise_success();
        env::log_str(&format!(
            "EVENT_JSON:{{\"standard\":\"nttrade\",\"version\":\"1\",\"event\":\"device_key_removed\",\"data\":{{\"public_key\":{},\"ok\":{ok}}}}}",
            jstr(&String::from(&public_key))
        ));
    }

    /// Note: a gas key's remaining balance is burnt by DeleteKey; near-sdk 5.29 has no
    /// WithdrawFromGasKey action, so the owner should drain it first (see README).
    /// v1.2: unregister from a DCL-kind DEX; DCL refunds the locked storage to the sponsor,
    /// which is this account. Fails on DCL's side while the account still holds DCL assets.
    #[payable]
    pub fn owner_reclaim_dex_storage(&mut self, dex: AccountId) {
        self.assert_owner();
        self.reclaim_dex_storage(dex);
    }

    pub(crate) fn reclaim_dex_storage(&mut self, dex: AccountId) {
        self.assert_dcl(&dex);
        Promise::new(dex)
            .function_call(
                "storage_unregister",
                b"{}".to_vec(),
                NearToken::from_yoctonear(1),
                Gas::from_tgas(GAS_DCL_UNREGISTER),
            )
            .detach();
    }

    /// v1.3: install (or rotate) the automation key: FC key, receiver self, methods
    /// [execute_order] only, gas allowance `allowance` (>= 0.5 NEAR; bounds gas a compromised
    /// key can burn). Replaces any previous automation key.
    #[payable]
    pub fn owner_set_automation_key(&mut self, public_key: PublicKey, allowance: U128) {
        self.assert_owner();
        self.set_automation_key(public_key, allowance);
    }

    pub(crate) fn set_automation_key(&mut self, public_key: PublicKey, allowance: U128) {
        if allowance.0 < MIN_AUTOMATION_ALLOWANCE {
            fail("E_ALLOWANCE");
        }
        let cur = self.automation_key();
        // v1.4.3 (ROLESET-001): one automation change in flight. Any role-set member other than
        // the current key is a pending install or a retired key whose DeleteKey is not confirmed
        // yet; re-setting now could leave an installed key outside the set.
        if relayer_keys().iter().any(|k| Some(k) != cur.as_ref()) {
            fail("E_AUTOMATION_BUSY");
        }
        schedule_automation_install(public_key, cur, allowance.0);
    }

    /// A1-F2: records the automation key after DeleteKey(old)+AddKey(new) succeeded; on failure
    /// nothing changes (the old key, if any, is still installed and stored).
    /// C1-M1: success = DeleteKey(old) + AddKey(new) both landed -> `old` leaves the relayer role
    /// set; failure = nothing changed on chain -> a newly added `public_key` leaves it.
    #[private]
    pub fn on_automation_set(&mut self, public_key: PublicKey, old: Option<PublicKey>, added: Option<bool>) {
        env::storage_remove(K_INSTALLING);
        if !near_sdk::is_promise_success() {
            if added.unwrap_or(false) {
                relayer_role_remove(&public_key);
            }
            env::log_str(
                "EVENT_JSON:{\"standard\":\"nttrade\",\"version\":\"1\",\"event\":\"automation_set_failed\",\"data\":{}}",
            );
            return;
        }
        if let Some(o) = old {
            relayer_role_remove(&o);
        }
        // v1.4.3: the installed key is always a member (defence in depth for ROLESET-001)
        relayer_role_ensure(&public_key);
        env::storage_write(
            K_AUTOMATION,
            &near_sdk::borsh::to_vec(&public_key).unwrap_or_else(|_| fail("E_STATE")),
        );
        env::log_str(
            "EVENT_JSON:{\"standard\":\"nttrade\",\"version\":\"1\",\"event\":\"automation_set\",\"data\":{}}",
        );
    }

    #[payable]
    pub fn owner_revoke_automation(&mut self) {
        self.assert_owner();
        self.clear_automation();
    }

    #[payable]
    pub fn owner_remove_key(&mut self, public_key: PublicKey) {
        self.assert_owner();
        self.remove_key(public_key);
    }

    pub(crate) fn remove_key(&mut self, public_key: PublicKey) {
        // a relayer key: same path as revoke (stays a relayer until deletion is confirmed).
        // v1.4.3 (PROMISEORDER-001): the automation key goes through clear_automation, which puts
        // it in the role set (materializing a legacy <= v1.4.1 set) BEFORE `ak` is removed.
        if self.automation_key().as_ref() == Some(&public_key) {
            self.clear_automation();
            return;
        }
        // v1.4.4 (RA-1): any other role-set member is a pending install or a retirement in flight:
        // one automation change at a time (a stuck entry: owner_clear_relayer_key).
        if relayer_keys().contains(&public_key) {
            fail("E_AUTOMATION_BUSY");
        }
        // device_key_removed{public_key, ok}, reported by on_key_removed (as device_key_added)
        let me = env::current_account_id();
        Promise::new(me.clone())
            .delete_key(public_key.clone())
            .then(Promise::new(me).function_call_weight(
                "on_key_removed",
                format!("{{\"public_key\":{}}}", jstr(&String::from(&public_key))).into_bytes(),
                NearToken::from_yoctonear(0),
                Gas::from_tgas(GAS_KEY_CB),
                GasWeight(1),
            ))
            .detach();
    }

    /// v1.4.4 (SC-8): drops a role-set entry that is not the current automation key and not an
    /// install in flight (a retired key whose DeleteKey failed, e.g. a legacy key whose AddKey
    /// never landed). Proof comes from the chain, not the argument: DeleteKey(pk) runs first, and
    /// the entry leaves the set once it either succeeded (deleted now) or failed (DeleteKey fails
    /// only when the key does not exist). No automation AddKey(pk) can be pending meanwhile: the
    /// only one is owner_set_automation_key, which is refused while pk is a non-current member.
    #[payable]
    pub fn owner_clear_relayer_key(&mut self, public_key: PublicKey) {
        self.assert_owner();
        self.clear_relayer_key(public_key);
    }

    pub(crate) fn clear_relayer_key(&mut self, public_key: PublicKey) {
        if !relayer_keys().contains(&public_key) {
            fail("E_NO_KEY");
        }
        if self.automation_key().as_ref() == Some(&public_key) {
            fail("E_AUTOMATION_KEY"); // the current key: owner_revoke_automation
        }
        if env::storage_has_key(K_INSTALLING) {
            fail("E_AUTOMATION_BUSY");
        }
        let me = env::current_account_id();
        Promise::new(me.clone())
            .delete_key(public_key.clone())
            .then(Promise::new(me).function_call(
                "on_relayer_key_cleared",
                format!("{{\"public_key\":{}}}", jstr(&String::from(&public_key))).into_bytes(),
                NearToken::from_yoctonear(0),
                Gas::from_tgas(GAS_RELAYER_DELETE_CB),
            ))
            .detach();
    }

    /// v1.4.4 (SC-8): the key is gone either way (deleted now, or absent: DeleteKey failed).
    #[private]
    pub fn on_relayer_key_cleared(&mut self, public_key: PublicKey) {
        let existed = near_sdk::is_promise_success();
        // v1.4.5 (RA4-1): never the current automation key (it may have been installed after the
        // clear was accepted, e.g. an install begun on v1.4.3 code without the `ai` marker): the
        // invariant "ak is in the role set" holds under every receipt order.
        if self.automation_key().as_ref() != Some(&public_key) {
            relayer_role_remove(&public_key);
        }
        env::log_str(&format!(
            "EVENT_JSON:{{\"standard\":\"nttrade\",\"version\":\"1\",\"event\":\"relayer_key_cleared\",\"data\":{{\"public_key\":{},\"existed\":{existed}}}}}",
            jstr(&String::from(&public_key))
        ));
    }

    /// C1-M1: DeleteKey of a relayer key confirmed -> it leaves the role set. On failure it stays
    /// (still treated as a relayer: sell-only, weekly allowance, no device methods).
    #[private]
    pub fn on_relayer_key_deleted(&mut self, public_key: PublicKey) {
        let ok = near_sdk::is_promise_success();
        if ok {
            relayer_role_remove(&public_key);
        }
        env::log_str(&format!(
            "EVENT_JSON:{{\"standard\":\"nttrade\",\"version\":\"1\",\"event\":\"relayer_key_deleted\",\"data\":{{\"public_key\":{},\"ok\":{ok}}}}}",
            jstr(&String::from(&public_key))
        ));
    }

    #[payable]
    pub fn owner_withdraw(&mut self, token: Option<AccountId>, amount: U128, to: AccountId) {
        self.assert_owner();
        self.send(token, amount.0, to, false);
    }

    /// v1.3.2: one owner signature empties the account to `to`: every listed token (≤
    /// MAX_WITHDRAW_TOKENS; call again for more), all wNEAR (unwrapped: the destination needs no
    /// wNEAR registration) and then all native NEAR above the storage stake. Phase 1 reads the
    /// balances; phase 2 (`on_withdraw_all_balances`) registers `to` on each token when needed
    /// and transfers; `on_withdraw_all_report` emits one `owner_withdraw` event per token
    /// {token, amount, to, ok} and sweeps the native balance last. The account stays alive
    /// (storage stake + refunded storage leftovers remain); nothing counts toward caps.
    #[payable]
    pub fn owner_withdraw_all(&mut self, to: AccountId, tokens: Vec<AccountId>) {
        self.assert_owner();
        self.withdraw_all(to, tokens);
    }

    pub(crate) fn withdraw_all(&mut self, to: AccountId, tokens: Vec<AccountId>) {
        let me = env::current_account_id();
        let mut list: Vec<AccountId> = Vec::new();
        for t in tokens {
            if t == me || t == self.wrap {
                continue; // wrap is always included (unwrapped)
            }
            if !list.contains(&t) {
                list.push(t);
            }
        }
        if list.len() > MAX_WITHDRAW_TOKENS {
            fail("E_TOO_MANY_TOKENS");
        }
        // R2-05 (owner doors): refused as a whole while any token it would move is locked
        assert_tokens_free(&self.wrap, &list);
        let q = |c: &AccountId, m: &str, who: &AccountId| {
            env::promise_create(
                c.clone(),
                m,
                format!("{{\"account_id\":\"{}\"}}", who).as_bytes(),
                NearToken::from_yoctonear(0),
                Gas::from_tgas(GAS_VIEW),
            )
        };
        let mut idx = vec![q(&self.wrap, "ft_balance_of", &me)];
        for t in &list {
            idx.push(q(t, "ft_balance_of", &me));
        }
        for t in &list {
            idx.push(q(t, "storage_balance_of", &to));
        }
        let all = env::promise_and(&idx);
        let args =
            serde_json::to_vec(&WithdrawAllArgs { to, tokens: list }).unwrap_or_else(|_| fail("E_JSON"));
        env::promise_then(
            all,
            me,
            "on_withdraw_all_balances",
            &args,
            NearToken::from_yoctonear(0),
            Gas::from_tgas(GAS_WITHDRAW_ALL_CB),
        );
    }

    #[private]
    pub fn on_withdraw_all_balances(&mut self, to: AccountId, tokens: Vec<AccountId>) {
        // R2-05: again here, since a lock can be taken between phase 1 and this callback; the
        // whole call is refused (nothing has moved yet: phase 1 only read balances)
        assert_tokens_free(&self.wrap, &tokens);
        let me = env::current_account_id();
        let n = tokens.len() as u64;
        // v1.4.3 (RESDISC-001): an unreadable balance (failed read, > 64 bytes, not a U128) is
        // reported as `owner_withdraw{amount: "0", ok: false}` instead of being skipped silently.
        let bal = |i: u64, t: &AccountId| -> u128 {
            match env::promise_result_checked(i, 64)
                .ok()
                .and_then(|b| serde_json::from_slice::<U128>(&b).ok())
            {
                Some(v) => v.0,
                None => {
                    withdraw_event(t.as_str(), 0, &to, false);
                    0
                }
            }
        };
        let registered = |i: u64| -> bool {
            matches!(env::promise_result_checked(i, 512), Ok(b) if !b.is_empty() && b.as_slice() != b"null")
        };
        let mut finals = Vec::new();
        let mut report: Vec<(AccountId, U128)> = Vec::new();
        // v1.4.8 (UNR-A-03): every deposit below is paid from the native liquid balance NOW (the
        // unwrap lands later). Spend within it, cheapest items first (1 yocto each, then the
        // registrations), and report what doesn't fit instead of reverting the whole receipt.
        // F1 / INDEP-1: expired routes settle first (their fee leaves before the read)
        chain::expire_routes(&self.fee.fee_recipient);
        let mut budget = liquid_balance().saturating_sub(self.owner_hold());
        let mut keep: u128 = 0;
        let w = bal(0, &self.wrap);
        if w > 0 && budget >= 1 {
            budget -= 1;
            finals.push(env::promise_create(
                self.wrap.clone(),
                "near_withdraw",
                format!("{{\"amount\":\"{w}\"}}").as_bytes(),
                NearToken::from_yoctonear(1),
                Gas::from_tgas(GAS_NEAR_WITHDRAW),
            ));
            report.push((self.wrap.clone(), U128(w)));
        } else if w > 0 {
            withdraw_skipped(self.wrap.as_str(), w, &to, 1);
            keep += 1;
        }
        let items: Vec<(&AccountId, u128, bool)> = tokens
            .iter()
            .enumerate()
            .map(|(i, t)| (t, bal(1 + i as u64, t), !registered(1 + n + i as u64)))
            .filter(|(_, b, _)| *b > 0)
            .collect();
        for register in [false, true] {
            for (t, b, _) in items.iter().filter(|x| x.2 == register) {
                let cost = if register { MAX_STORAGE_DEPOSIT + 1 } else { 1 };
                if budget < cost {
                    withdraw_skipped(t.as_str(), *b, &to, cost);
                    keep += cost;
                    continue;
                }
                budget -= cost;
                finals.push(ft_to(t, *b, &to, register));
                report.push(((*t).clone(), U128(*b)));
            }
        }
        let keep = (keep > 0).then_some(U128(keep));
        let args = serde_json::to_vec(&WithdrawReportArgs { to, items: report, keep })
            .unwrap_or_else(|_| fail("E_JSON"));
        let gas = Gas::from_tgas(GAS_REPORT_CB);
        if finals.is_empty() {
            let p = env::promise_batch_create(&me);
            env::promise_batch_action_function_call_weight(
                p,
                "on_withdraw_all_report",
                &args,
                NearToken::from_yoctonear(0),
                gas,
                GasWeight(0),
            );
        } else {
            let all = env::promise_and(&finals);
            env::promise_then(all, me, "on_withdraw_all_report", &args, NearToken::from_yoctonear(0), gas);
        }
    }

    #[private]
    pub fn on_withdraw_all_report(
        &mut self,
        to: AccountId,
        items: Vec<(AccountId, U128)>,
        keep: Option<U128>,
    ) {
        let results = env::promise_results_count();
        for (i, (t, a)) in items.iter().enumerate() {
            let i = i as u64;
            let ok = i < results && !matches!(env::promise_result_checked(i, 0), Err(PromiseError::Failed));
            withdraw_event(t.as_str(), a.0, &to, ok);
        }
        // native last: everything above the storage stake (incl. the unwrapped wNEAR), minus what
        // the skipped items need for a second call (v1.4.8, UNR-A-03)
        // v1.6: minus escrowed route fees and the signed-path state reserve (owner_hold)
        // F1 / INDEP-1: expired routes settle first (their fee leaves before the read)
        chain::expire_routes(&self.fee.fee_recipient);
        let native =
            liquid_balance().saturating_sub(keep.map_or(0, |k| k.0)).saturating_sub(self.owner_hold());
        if native > 0 {
            Promise::new(to.clone()).transfer(NearToken::from_yoctonear(native)).detach();
        }
        withdraw_event("near", native, &to, true);
    }

    /// v1.3.2: settles a single owner_withdraw / withdraw_to_owner of a token.
    /// wrap: the preceding promise was near_withdraw -> forward the NEAR natively.
    #[private]
    pub fn on_withdraw_one(&mut self, token: AccountId, amount: U128, to: AccountId) {
        let ok = near_sdk::is_promise_success();
        if ok && token == self.wrap {
            Promise::new(to.clone()).transfer(NearToken::from_yoctonear(amount.0)).detach();
        }
        withdraw_event(token.as_str(), amount.0, &to, ok);
    }

    /// v1.4.3 (OWNERBOUND-001): a decrease applies now; a raise of either cap is stored as
    /// pending and takes effect CAPS_RAISE_DELAY_NS (1 h, as destinations) later, with the
    /// decreased part applied now (`caps_raise_pending`). A later call replaces a pending raise;
    /// a call without a raise, or a device `lower_caps`, cancels it. Initial caps (init) are
    /// not delayed.
    #[payable]
    pub fn owner_set_caps(&mut self, caps: Caps) {
        self.assert_owner();
        self.set_caps(caps);
    }

    pub(crate) fn set_caps(&mut self, caps: Caps) {
        self.sync_caps();
        let cur = self.caps.clone();
        let now_caps = Caps {
            max_trade_yocto: U128(cur.max_trade_yocto.0.min(caps.max_trade_yocto.0)),
            daily_cap_yocto: U128(cur.daily_cap_yocto.0.min(caps.daily_cap_yocto.0)),
        };
        self.caps = now_caps.clone();
        cancel_caps_raise("owner");
        caps_event("caps_set", &now_caps, None);
        if now_caps != caps {
            let at = env::block_timestamp().saturating_add(CAPS_RAISE_DELAY_NS);
            let pending = PendingCaps { caps, active_at_ns: U64(at) };
            save_pending_caps(&pending);
            // v1.4.5: the caps in force when the raise was requested (migrate detects a change);
            // v1.4.6 (RA5-4): bound to this raise
            env::storage_write(
                K_PENDING_BASE,
                &near_sdk::borsh::to_vec(&(now_caps.clone(), pending.clone()))
                    .unwrap_or_else(|_| fail("E_STATE")),
            );
            caps_event("caps_raise_pending", &pending.caps, Some(at));
        }
    }

    /// v1.4.3: the owner's pending cap raise (None once active or cancelled).
    pub fn get_pending_caps(&self) -> Option<PendingCaps> {
        pending_caps().filter(|p| env::block_timestamp() < p.active_at_ns.0)
    }

    #[payable]
    pub fn owner_upgrade(&mut self, code_hash: Base58CryptoHash) {
        self.assert_owner();
        // v1.6 (R2-09): never under an in-flight settle, route or pending order fire
        upgrade::assert_not_in_flight();
        self.upgrade(code_hash);
    }

    pub(crate) fn upgrade(&mut self, code_hash: Base58CryptoHash) {
        let me = env::current_account_id();
        // v1.6 (R2-12): the state version is unknown until the new code's migrate writes it (older
        // code never does, so a downgrade leaves no stale `sv`)
        env::storage_remove(upgrade::K_STATE_VERSION);
        // v1.6 (F-02): migrate gets all remaining gas (a future migration is not bounded by this
        // code's guess), at least GAS_MIGRATE
        Promise::new(me)
            .use_global_contract(code_hash)
            .function_call_weight(
                "migrate",
                vec![],
                NearToken::from_yoctonear(0),
                Gas::from_tgas(GAS_MIGRATE),
                GasWeight(1),
            )
            .detach();
    }

    // ---------------- v1.4 NEAR Intents (docs/intents-spec.md §3) ----------------

    /// Owner: allow a cross-chain withdrawal destination; usable by the device path only
    /// DEST_DELAY_NS (1 h) later. Returns its id.
    #[payable]
    pub fn owner_add_withdraw_destination(
        &mut self,
        label: String,
        asset: String,
        recipient: String,
        recipient_type: String,
    ) -> u32 {
        self.assert_owner();
        self.add_withdraw_destination(label, asset, recipient, recipient_type)
    }

    pub(crate) fn add_withdraw_destination(
        &mut self,
        label: String,
        asset: String,
        recipient: String,
        recipient_type: String,
    ) -> u32 {
        let active_at = env::block_timestamp().saturating_add(intents::DEST_DELAY_NS);
        let dest = Dest { label, asset, recipient, recipient_type, active_at_ns: U64(active_at) };
        ok(intents::check_dest(&dest));
        let mut d = intents::dests();
        if d.list.len() >= intents::MAX_DESTS {
            fail("E_DEST_LIMIT");
        }
        let id = d.next_id;
        d.next_id = id.checked_add(1).unwrap_or_else(|| fail("E_DEST_LIMIT"));
        // B1-I1: the event carries what was registered (alerting needs no view call).
        env::log_str(&format!(
            "EVENT_JSON:{{\"standard\":\"nttrade\",\"version\":\"1\",\"event\":\"withdraw_destination_added\",\"data\":{{\"dest_id\":{id},\"active_at_ns\":\"{active_at}\",\"label\":{},\"asset\":{},\"recipient\":{},\"recipient_type\":{}}}}}",
            jstr(&dest.label),
            jstr(&dest.asset),
            jstr(&dest.recipient),
            jstr(&dest.recipient_type)
        ));
        d.list.push((id, dest));
        intents::save_dests(&d);
        id
    }

    #[payable]
    pub fn owner_remove_withdraw_destination(&mut self, dest_id: u32) {
        self.assert_owner();
        remove_dest(dest_id, "owner");
    }

    /// Device: may only REMOVE a destination (adding is owner-only).
    pub fn remove_withdraw_destination(&mut self, dest_id: u32) {
        self.assert_device();
        // v1.4.3 (SC-2): charged, never refused (a safety action)
        self.charge_device_gas(true);
        remove_dest(dest_id, "device");
    }

    /// Owner: 1Click quote-signing keys (1..=3, `ed25519:<bs58>` 32 bytes), slippage ceiling
    /// (<= 300 bps), the verifier account (default intents.near) and (v1.4.1) the max signed
    /// USD value loss in bps (v1.4.2: default 50, within [30, 300]).
    #[payable]
    pub fn owner_set_oneclick_config(
        &mut self,
        keys: Vec<String>,
        max_slippage_bps: u16,
        intents: Option<AccountId>,
        max_loss_bps: Option<u16>,
    ) {
        self.assert_owner();
        self.set_oneclick_config(keys, max_slippage_bps, intents, max_loss_bps);
    }

    pub(crate) fn set_oneclick_config(
        &mut self,
        keys: Vec<String>,
        max_slippage_bps: u16,
        intents: Option<AccountId>,
        max_loss_bps: Option<u16>,
    ) {
        let intents =
            intents.unwrap_or_else(|| intents::DEFAULT_INTENTS.parse().unwrap_or_else(|_| fail("E_STATE")));
        let max_loss_bps = max_loss_bps.unwrap_or(intents::DEFAULT_MAX_LOSS_BPS);
        let c = OneClickConfig { keys, max_slippage_bps, intents, max_loss_bps };
        ok(intents::check_config(&c));
        // v1.4.5: `oneclick_config_set{old, new}` (old = null if never set)
        // v1.4.6 (RA5-2): read tolerantly: an unreadable (e.g. v1.4.0-layout) config is reported
        // as null and overwritten; the event never adds a failure mode
        let prev: Option<OneClickConfig> =
            env::storage_read(intents::K_ONECLICK).and_then(|b| near_sdk::borsh::from_slice(&b).ok());
        let old = serde_json::to_string(&prev).unwrap_or_else(|_| fail("E_JSON"));
        let new = serde_json::to_string(&c).unwrap_or_else(|_| fail("E_JSON"));
        intents::save_oneclick(&c);
        env::log_str(&format!(
            "EVENT_JSON:{{\"standard\":\"nttrade\",\"version\":\"1\",\"event\":\"oneclick_config_set\",\"data\":{{\"old\":{old},\"new\":{new}}}}}"
        ));
    }

    /// Owner: daily caps of the cross-chain withdraw window (decision 6). `daily_cap_yocto`:
    /// wNEAR + gas bound (default = trading daily cap). `daily_cap_usd`: v1.4.1, micro-USD of
    /// the signed `amountInUsd` of ALL tokens (v1.4.7: default no cap, was $1,000; the owner
    /// opts in here). Omitted = unchanged.
    #[payable]
    pub fn owner_set_withdraw_cap(&mut self, daily_cap_yocto: Option<U128>, daily_cap_usd: Option<U128>) {
        self.assert_owner();
        self.set_withdraw_cap(daily_cap_yocto, daily_cap_usd);
    }

    pub(crate) fn set_withdraw_cap(&mut self, daily_cap_yocto: Option<U128>, daily_cap_usd: Option<U128>) {
        // v1.4.5: `withdraw_cap_set{old_*, new_*}`. v1.4.6 (RA5-7): null = never set, for both caps
        // (the yocto cap then follows the trading daily cap; the USD cap is none, v1.4.7)
        let q = |v: Option<u128>| v.map_or("null".to_string(), |x| format!("\"{x}\""));
        let (old_y, old_u) = (intents::withdraw_cap(), intents::withdraw_cap_usd_set());
        if let Some(v) = daily_cap_yocto {
            intents::save_withdraw_cap(v.0);
        }
        if let Some(v) = daily_cap_usd {
            intents::save_withdraw_cap_usd(v.0);
        }
        env::log_str(&format!(
            "EVENT_JSON:{{\"standard\":\"nttrade\",\"version\":\"1\",\"event\":\"withdraw_cap_set\",\"data\":{{\"old_daily_cap_yocto\":{},\"new_daily_cap_yocto\":{},\"old_daily_cap_usd\":{},\"new_daily_cap_usd\":{}}}}}",
            q(old_y),
            q(intents::withdraw_cap()),
            q(old_u),
            q(intents::withdraw_cap_usd_set())
        ));
    }

    /// v1.4.1 (B1-L2): pull this account's own balance held INSIDE the verifier (e.g. a 1Click
    /// refund credited in intents.near) back to itself: `ft_withdraw{token, receiver_id: self}`.
    /// Owner (1 yocto) or device; the receiver is always self.
    #[payable]
    pub fn owner_withdraw_from_intents(&mut self, token: AccountId, amount: U128) {
        self.assert_owner();
        self.owner_intents_to_self(token, amount.0);
    }

    /// Owner doors (predecessor and signed): like the device, refused (E_Q_BUSY) for a token a
    /// live route reserves, so the owner can't be led to pull a route's delivery and have its
    /// refund check misread it (escrow released, spend returned). Once the route is stuck
    /// (ROUTE_PENDING_TTL_BLOCKS after a fire whose callback never ran) or expired (F1), it
    /// reserves nothing and the owner recovers freely.
    pub(crate) fn owner_intents_to_self(&mut self, token: AccountId, amount: u128) {
        chain::expire_routes(&self.fee.fee_recipient);
        if chain::intents_token_reserved(&token, &self.wrap) {
            fail("E_Q_BUSY");
        }
        self.intents_to_self(token, amount);
    }

    /// The tokens of this account's intents balance that live routes reserve now: the device's
    /// and the owner's `withdraw_from_intents` and rescue refuse exactly these (E_Q_BUSY).
    pub fn get_intents_reserved(&self) -> Vec<AccountId> {
        chain::intents_reserved_tokens(&self.wrap)
    }

    pub fn withdraw_from_intents(&mut self, token: AccountId, amount: U128) {
        self.assert_device();
        // F1: expired routes are closed first (they reserve nothing)
        chain::expire_routes(&self.fee.fee_recipient);
        // V16-07: a Funded intents route's tokens are its own (pulled by its continuation)
        if chain::intents_token_reserved(&token, &self.wrap) {
            fail("E_Q_BUSY");
        }
        self.sync_caps();
        // its gas counts toward the withdraw window (gas-burn bound, A1-F1)
        let now = env::block_timestamp();
        let mut day = intents::withdraw_day();
        day.roll(now);
        let gas_cost = u128::from(env::prepaid_gas().as_gas()).saturating_mul(GAS_PRICE_BOUND);
        let cap = intents::withdraw_cap().unwrap_or(self.caps.daily_cap_yocto.0);
        match day.spent_yocto.checked_add(gas_cost) {
            Some(x) if x <= cap => day.spent_yocto = x,
            _ => fail("E_WITHDRAW_CAP"),
        }
        intents::save_withdraw_day(&day);
        self.intents_to_self(token, amount.0);
    }

    /// Owner path: fund ANY 1Click INTENTS deposit address (the owner can already withdraw
    /// anywhere). No quote, no caps.
    #[payable]
    pub fn owner_withdraw_via_intents(&mut self, token: AccountId, amount: U128, deposit_address: String) {
        self.assert_owner();
        self.withdraw_via_intents(token, amount, deposit_address);
    }

    pub(crate) fn withdraw_via_intents(&mut self, token: AccountId, amount: U128, deposit_address: String) {
        // R2-05 (owner doors): checked first, before the deposit address is marked
        chain::assert_free(token.as_str());
        if !intents::is_deposit_address(&deposit_address) {
            fail("E_BAD_DEPOSIT_ADDRESS");
        }
        let now = env::block_timestamp();
        // B1-I2: the device path can't fund this address again
        ok(intents::mark_owner_quote(&deposit_address, now.saturating_add(intents::OWNER_ADDR_KEEP_NS), now));
        self.send_intents(token, amount.0, verifier(), &deposit_address, "owner", None, 0, 0, 0);
    }

    /// Device path (spec §3): funds a 1Click quote ONLY if 1Click signed it, it pays a
    /// registered + active destination, and refunds come back to this account (invariant 11).
    #[allow(clippy::too_many_arguments)]
    pub fn withdraw_cross_chain(
        &mut self,
        dest_id: u32,
        token: AccountId,
        amount: U128,
        signed_quote: String,
        signature: String,
        client_order_id: String,
        expires_at_ns: U64,
    ) {
        // 1
        self.assert_device();
        // R2-05: a token held by an in-flight route / Nearrr buy can't leave meanwhile
        chain::assert_free(token.as_str());
        self.sync_caps();
        let now = env::block_timestamp();
        ok(check_expiry(now, expires_at_ns.0));
        ok(self.seen_orders.insert(client_order_id.clone(), expires_at_ns.0, now));
        let cfg = intents::oneclick().unwrap_or_else(|| fail("E_ONECLICK_UNSET"));
        // 2 (v1.6: HOME_DEST = the owner's own home, derived, no delay: spec §5.2)
        let dest = if dest_id == owner::HOME_DEST {
            self.home_dest(&signed_quote)
        } else {
            intents::dests()
                .list
                .into_iter()
                .find(|(i, d)| *i == dest_id && now >= d.active_at_ns.0)
                .map(|(_, d)| d)
                .unwrap_or_else(|| fail("E_DEST_INACTIVE"))
        };
        let me = env::current_account_id();
        if token == me || amount.0 == 0 {
            fail("E_BAD_OP");
        }
        // 3: signature over the exact bytes (never re-canonicalized)
        ok(intents::verify_quote_sig(&signed_quote, &signature, &cfg.keys));
        // 4 (+ v1.4.1 loss bound)
        let q = ok(intents::parse_quote(&signed_quote));
        let c = ok(intents::check_quote(
            &q,
            &intents::Expect {
                self_id: me.as_str(),
                token: token.as_str(),
                amount: amount.0,
                dest: &dest,
                max_slippage_bps: cfg.max_slippage_bps,
                max_loss_bps: cfg.max_loss_bps,
                now_ns: now,
            },
        ));
        let addr = c.deposit_address.to_string();
        if intents::is_quote_used(&addr, now) {
            fail("E_QUOTE_REPLAY");
        }
        // 5: separate withdraw window: wNEAR amount + the whole prepaid gas (A1-F1 bound), and
        // (v1.4.1, B1-M1) the signed USD value of every token.
        let counted = if token == self.wrap { amount.0 } else { 0 };
        let gas_cost = u128::from(env::prepaid_gas().as_gas()).saturating_mul(GAS_PRICE_BOUND);
        let mut day = intents::withdraw_day();
        day.roll(now);
        let cap = intents::withdraw_cap().unwrap_or(self.caps.daily_cap_yocto.0);
        let spent = ok(add(day.spent_yocto, counted)).checked_add(gas_cost);
        let spent_usd = day.spent_usd.checked_add(c.usd_in_micros);
        match (spent, spent_usd) {
            (Some(y), Some(u)) if y <= cap && u <= intents::withdraw_cap_usd() => {
                day.spent_yocto = y;
                day.spent_usd = u;
            }
            _ => fail("E_WITHDRAW_CAP"),
        }
        intents::save_withdraw_day(&day);
        ok(check_reserve(liquid_balance(), 1));
        // exactly-once: marked only once every check passed (E_QUOTES_FULL at the bound)
        let keep = c.issued_ns.saturating_add(intents::MAX_QUOTE_AGE_NS + intents::USED_QUOTE_MARGIN_NS);
        ok(intents::mark_quote_used(&addr, keep, now));
        // 6
        self.send_intents(
            token,
            amount.0,
            cfg.intents,
            &addr,
            &client_order_id,
            Some(dest_id),
            counted,
            c.usd_in_micros,
            day.start_ns,
        );
    }

    /// Settles an intents funding: `used` as ft_resolve_transfer reports it (0 on failure);
    /// the unused part of the counted amount goes back to the withdraw window.
    #[private]
    #[allow(clippy::too_many_arguments)]
    pub fn on_intents_sent(
        &mut self,
        client_order_id: String,
        dest_id: Option<u32>,
        token: AccountId,
        amount: U128,
        counted: U128,
        day_start: U64,
        deposit_address: String,
        counted_usd: Option<U128>,
    ) {
        let used = match env::promise_result_checked(0, 128) {
            Err(PromiseError::Failed) => 0,
            Err(_) => amount.0,
            Ok(b) => serde_json::from_slice::<U128>(&b).map_or(amount.0, |u| u.0.min(amount.0)),
        };
        let back = counted.0 - mul_div(counted.0, used, amount.0);
        let usd = counted_usd.map_or(0, |u| u.0);
        let back_usd = usd - mul_div(usd, used, amount.0);
        if back > 0 || back_usd > 0 {
            let mut day = intents::withdraw_day();
            if day.start_ns == day_start.0 {
                day.spent_yocto = day.spent_yocto.saturating_sub(back);
                day.spent_usd = day.spent_usd.saturating_sub(back_usd);
                intents::save_withdraw_day(&day);
            }
        }
        env::log_str(&format!(
            "EVENT_JSON:{{\"standard\":\"nttrade\",\"version\":\"1\",\"event\":\"intents_withdraw\",\"data\":{{\"client_order_id\":{},\"dest_id\":{},\"token\":\"{}\",\"amount\":\"{}\",\"used\":\"{}\",\"deposit_address\":\"{}\"}}}}",
            jstr(&client_order_id),
            dest_id.map_or("null".to_string(), |d| d.to_string()),
            token,
            amount.0,
            used,
            deposit_address
        ));
    }

    pub fn get_withdraw_destinations(&self) -> Vec<DestView> {
        let now = env::block_timestamp();
        intents::dests()
            .list
            .into_iter()
            .map(|(id, dest)| DestView { dest_id: id, active: now >= dest.active_at_ns.0, dest })
            .collect()
    }

    pub fn get_oneclick_config(&self) -> Option<OneClickConfig> {
        intents::oneclick()
    }

    /// Current cross-chain withdraw window (the UTC day, v1.4.1) and its caps.
    pub fn get_withdraw_day(&self) -> WithdrawDayView {
        let mut d = intents::withdraw_day();
        d.roll(env::block_timestamp());
        WithdrawDayView {
            start_ns: U64(d.start_ns),
            spent_yocto: U128(d.spent_yocto),
            cap_yocto: U128(intents::withdraw_cap().unwrap_or(self.caps_now().daily_cap_yocto.0)),
            spent_usd: U128(d.spent_usd),
            cap_usd: U128(intents::withdraw_cap_usd()),
            resets_at_ns: U64(d.start_ns + DAY_NS),
        }
    }

    /// v1.4.1: is this 1Click deposit address already funded (replay-marked)?
    pub fn is_deposit_address_used(&self, deposit_address: String) -> bool {
        intents::is_quote_used(&deposit_address, env::block_timestamp())
    }

    // ---------------- views ----------------

    pub fn get_config(&self) -> Config {
        Config {
            owner: self.owner.clone(),
            wrap: self.wrap.clone(),
            dex_allowlist: self.dex_allowlist.clone(),
            fee_bps: self.fee.fee_bps,
            fee_recipient: self.fee.fee_recipient.clone(),
            caps: self.caps_now(),
            version: VERSION.into(),
        }
    }

    /// Current window as `execute` would see it: the UTC day (v1.4.1), resetting at 00:00 UTC.
    pub fn get_day(&self) -> DayView {
        let mut d = self.day.clone();
        roll_day(&mut d, env::block_timestamp());
        DayView {
            start_ns: U64(d.start_ns),
            spent_yocto: U128(d.spent_yocto),
            gas_spent_yocto: U128(day_gas(d.start_ns)),
            resets_at_ns: U64(d.start_ns + DAY_NS),
        }
    }

    /// v1.4.1 (D6): the relayer's weekly allowance (ISO week, Monday 00:00 UTC) and what its
    /// fires were charged this week (sells: max(min_out, floor); buys since v1.4.7: spend + gas,
    /// at least the floor). v1.4.8: `allowance_yocto` null = no weekly limit (the default); no
    /// accounting runs then, so `spent_yocto` is not updated.
    pub fn get_relayer_week(&self) -> RelayerWeekView {
        let mut w = relayer_week_state();
        roll_week(&mut w, env::block_timestamp());
        RelayerWeekView {
            start_ns: U64(w.start_ns),
            resets_at_ns: U64(w.start_ns + 7 * DAY_NS),
            spent_yocto: U128(w.spent_yocto),
            allowance_yocto: relayer_allowance().map(U128),
        }
    }

    /// v1.4.1 (D6): owner sets the relayer's weekly allowance (yocto per ISO week, see
    /// get_relayer_week). v1.4.8: opt-in; UNLIMITED (u128::MAX) removes it (no weekly limit,
    /// the default).
    #[payable]
    pub fn owner_set_relayer_allowance(&mut self, weekly_yocto: U128) {
        self.assert_owner();
        self.set_relayer_allowance(weekly_yocto);
    }

    pub(crate) fn set_relayer_allowance(&mut self, weekly_yocto: U128) {
        let old = relayer_allowance();
        if weekly_yocto.0 == UNLIMITED {
            env::storage_remove(K_RELAYER_ALLOWANCE);
        } else {
            env::storage_write(K_RELAYER_ALLOWANCE, &weekly_yocto.0.to_le_bytes());
        }
        // v1.4.5: `relayer_allowance_set{old_weekly_yocto, new_weekly_yocto}`; v1.4.8: null = no
        // weekly limit
        let q = |v: Option<u128>| v.map_or("null".to_string(), |x| format!("\"{x}\""));
        env::log_str(&format!(
            "EVENT_JSON:{{\"standard\":\"nttrade\",\"version\":\"1\",\"event\":\"relayer_allowance_set\",\"data\":{{\"old_weekly_yocto\":{},\"new_weekly_yocto\":{}}}}}",
            q(old),
            q(relayer_allowance())
        ));
    }

    pub fn get_orders(&self) -> Vec<OrderView> {
        order_index()
            .into_iter()
            .filter_map(|(id, _)| {
                load_order(id).map(|order| OrderView { id: U64(id), order, via: chain::load_via(id) })
            })
            .collect()
    }

    pub fn get_order(&self, order_id: U64) -> Option<Order> {
        load_order(order_id.0)
    }

    pub fn get_automation_key(&self) -> Option<PublicKey> {
        self.automation_key()
    }

    /// C1-M1: every key treated as the relayer (current, pending install, awaiting deletion).
    pub fn get_relayer_keys(&self) -> Vec<PublicKey> {
        relayer_keys()
    }

    pub fn is_order_seen(&self, id: String) -> bool {
        self.seen_orders.contains(&id, env::block_timestamp())
    }

    // ---------------- internal ----------------

    /// Key paths (device methods and `execute_order`): the call must come from a transaction
    /// this account signed itself with one of its access keys.
    /// v1.4.9 (UNR-A-08): predecessor == self is not enough. A NEP-366 Delegate action signed by
    /// one of our keys yields an inner receipt with predecessor == self, but its signer_id and
    /// signer_account_pk are the OUTER transaction's. So `is_relayer(signer_account_pk)` misread
    /// a delegated automation-key fire as a device fire. The outer signer of a Delegate to this
    /// account is never this account: every key here is a function-call key, and an FC key can
    /// sign only a FunctionCall, never a Delegate action. With signer == self, signer_account_pk
    /// is the access key that signed the call. Fails closed for every delegated key call.
    fn assert_self(&self) {
        let me = env::current_account_id();
        if env::predecessor_account_id() != me {
            fail("E_NOT_SELF");
        }
        if env::signer_account_id() != me {
            fail("E_NOT_SELF_SIGNED");
        }
    }

    /// Device methods: called through a device key (predecessor == self) that is NOT the
    /// automation key (defence in depth; the automation key's method list already excludes them).
    fn assert_device(&self) {
        self.assert_self();
        if is_relayer(&env::signer_account_pk()) {
            fail("E_AUTOMATION_KEY");
        }
    }

    /// Charges `gas` (after `check_caps`/`roll_day` for the current window) to the daily gas
    /// tally; E_CAP_DAILY if spent + gas tally would exceed the daily cap.
    fn charge_gas(&mut self, gas: u64) -> u128 {
        let cost = (gas as u128).saturating_mul(GAS_PRICE_BOUND);
        let total = day_gas(self.day.start_ns).saturating_add(cost);
        if self.day.spent_yocto.saturating_add(total) > self.caps.daily_cap_yocto.0 {
            fail("E_CAP_DAILY");
        }
        save_day_gas(self.day.start_ns, total);
        cost
    }

    /// v1.4.3 (SC-2, invariant 10): charges this call's whole prepaid gas to the daily gas
    /// tally. `always`: safety actions (cancel, lower caps, revoke, remove destination) are
    /// recorded but never refused, so a spent cap can't block them; like failed transactions,
    /// they are bounded by the transaction rate only. Other calls: E_CAP_DAILY past the cap.
    fn charge_device_gas(&mut self, always: bool) {
        self.sync_caps();
        roll_day(&mut self.day, env::block_timestamp());
        let gas = env::prepaid_gas().as_gas();
        if always {
            let total =
                day_gas(self.day.start_ns).saturating_add((gas as u128).saturating_mul(GAS_PRICE_BOUND));
            save_day_gas(self.day.start_ns, total);
        } else {
            self.charge_gas(gas);
        }
    }

    /// v1.4.3: applies a pending owner cap raise once its delay has passed.
    fn sync_caps(&mut self) {
        if let Some(p) = pending_caps() {
            if env::block_timestamp() >= p.active_at_ns.0 {
                self.caps = p.caps.clone();
                env::storage_remove(K_PENDING_CAPS);
                env::storage_remove(K_PENDING_BASE);
                caps_event("caps_raised", &p.caps, None);
            }
        }
    }

    /// The caps in force now (views; a due raise counts even before it is written).
    fn caps_now(&self) -> Caps {
        match pending_caps() {
            Some(p) if env::block_timestamp() >= p.active_at_ns.0 => p.caps,
            _ => self.caps.clone(),
        }
    }

    fn automation_key(&self) -> Option<PublicKey> {
        env::storage_read(K_AUTOMATION).and_then(|b| near_sdk::borsh::from_slice(&b).ok())
    }

    fn clear_automation(&mut self) {
        if let Some(k) = self.automation_key() {
            // C1-M1: k stays in the relayer role set until on_relayer_key_deleted confirms
            relayer_role_add(&k);
            retire_relayer_key(k);
            env::storage_remove(K_AUTOMATION);
            env::log_str(
                "EVENT_JSON:{\"standard\":\"nttrade\",\"version\":\"1\",\"event\":\"automation_revoked\",\"data\":{}}",
            );
        }
    }

    /// Exact-id venues (Rhea classic / DCL / Plach). v1.5: a ShardsToken entry names a factory,
    /// not a venue, so it never matches here (no ft_transfer_call, storage or order DEX = factory).
    /// v1.6: routing validation context.
    fn route_env<'a>(&'a self, me: &'a AccountId, now: u64) -> chain::Env<'a> {
        chain::Env {
            me,
            wrap: &self.wrap,
            allow: &self.dex_allowlist,
            referrer: &self.fee.fee_recipient,
            fee_bps: self.fee.fee_bps,
            now_ns: now,
        }
    }

    fn dex_kind(&self, id: &AccountId) -> Option<DexKind> {
        self.dex_allowlist.iter().find(|d| &d.id == id && !venues::is_factory_entry(d.kind)).map(|d| d.kind)
    }

    /// v1.5: `token` is a Shards token under an allowlisted ShardsToken factory.
    fn is_shards_token(&self, token: &AccountId) -> bool {
        self.dex_allowlist
            .iter()
            .any(|d| d.kind == DexKind::ShardsToken && msg::shards_token_of(&d.id, token))
    }

    fn assert_dcl(&self, id: &AccountId) {
        if self.dex_kind(id) != Some(DexKind::RheaDcl) {
            fail("E_BAD_DEX");
        }
    }

    fn assert_plach(&self, id: &AccountId) {
        if self.dex_kind(id) != Some(DexKind::Plach) {
            fail("E_BAD_DEX");
        }
    }

    fn assert_shards(&self, token: &AccountId) {
        if !self.is_shards_token(token) {
            fail("E_BAD_DEX");
        }
    }

    fn assert_owner(&self) {
        if env::predecessor_account_id() != self.owner {
            fail("E_NOT_OWNER");
        }
        if env::attached_deposit() != NearToken::from_yoctonear(1) {
            fail("E_ONE_YOCTO");
        }
        // v1.6 (V16-03): "my original key leaked" closes the predecessor door too: that key also
        // controls the owner-id NEAR account. Only a signer-kind owner with an auth key can turn
        // it off (a named owner always passes); the owner then acts through its auth keys.
        if !owner::owner_auth(&self.owner).implicit_enabled {
            fail("E_IMPLICIT_OFF");
        }
    }

    /// v1.4: `token.ft_transfer_call{receiver_id: verifier, amount, msg: deposit_address}`
    /// (1 yocto) then `on_intents_sent`.
    #[allow(clippy::too_many_arguments)]
    fn send_intents(
        &self,
        token: AccountId,
        amount: u128,
        verifier: AccountId,
        deposit_address: &str,
        client_order_id: &str,
        dest_id: Option<u32>,
        counted: u128,
        counted_usd: u128,
        day_start: u64,
    ) {
        if token == env::current_account_id() || amount == 0 {
            fail("E_BAD_OP");
        }
        let p = env::promise_create(
            token.clone(),
            "ft_transfer_call",
            format!(
                "{{\"receiver_id\":\"{verifier}\",\"amount\":\"{amount}\",\"msg\":\"{deposit_address}\"}}"
            )
            .as_bytes(),
            NearToken::from_yoctonear(1),
            Gas::from_tgas(GAS_INTENTS_TRANSFER),
        );
        env::promise_then(
            p,
            env::current_account_id(),
            "on_intents_sent",
            format!(
                "{{\"client_order_id\":{},\"dest_id\":{},\"token\":\"{token}\",\"amount\":\"{amount}\",\"counted\":\"{counted}\",\"day_start\":\"{day_start}\",\"deposit_address\":\"{deposit_address}\",\"counted_usd\":\"{counted_usd}\"}}",
                jstr(client_order_id),
                dest_id.map_or("null".to_string(), |d| d.to_string()),
            )
            .as_bytes(),
            NearToken::from_yoctonear(0),
            Gas::from_tgas(GAS_CALLBACK),
        );
    }

    /// v1.4.1: `verifier.ft_withdraw{token, receiver_id: self, amount}` (1 yocto).
    fn intents_to_self(&self, token: AccountId, amount: u128) {
        let me = env::current_account_id();
        if token == me || amount == 0 {
            fail("E_BAD_OP");
        }
        Promise::new(verifier())
            .function_call(
                "ft_withdraw",
                format!("{{\"token\":\"{token}\",\"receiver_id\":\"{me}\",\"amount\":\"{amount}\"}}")
                    .into_bytes(),
                NearToken::from_yoctonear(1),
                Gas::from_tgas(GAS_INTENTS_TRANSFER),
            )
            .detach();
        env::log_str(&format!(
            "EVENT_JSON:{{\"standard\":\"nttrade\",\"version\":\"1\",\"event\":\"intents_withdraw_to_self\",\"data\":{{\"token\":\"{token}\",\"amount\":\"{amount}\"}}}}"
        ));
    }

    fn send(&self, token: Option<AccountId>, amount: u128, to: AccountId, keep_reserve: bool) {
        match token {
            None => {
                // F1 / INDEP-1: expired routes settle first (their fee leaves before the read)
                chain::expire_routes(&self.fee.fee_recipient);
                // v1.6: escrowed route fees and the signed-path state reserve are never sent
                let free = liquid_balance().saturating_sub(self.owner_hold());
                if keep_reserve {
                    ok(check_reserve(free, amount));
                } else if amount > free && self.owner_hold() > 0 {
                    fail("E_HELD_BALANCE");
                }
                // every native owner outflow is reported, as the token and withdraw_all paths are
                withdraw_event("near", amount, &to, true);
                Promise::new(to).transfer(NearToken::from_yoctonear(amount)).detach();
            }
            Some(t) => {
                let me = env::current_account_id();
                if t == me {
                    fail("E_BAD_OP");
                }
                // R2-05: every door that sends a token here (owner_withdraw, withdraw_home, rescue,
                // withdraw_to_owner) is refused while the token is locked
                chain::assert_free(t.as_str());
                // v1.3.2: wNEAR is unwrapped and sent as NEAR (destinations are often not
                // registered on wrap); other tokens: register `to` (registration_only; excess
                // refunded to us) then ft_transfer. Result reported as an `owner_withdraw` event.
                let last = if t == self.wrap {
                    env::promise_create(
                        t.clone(),
                        "near_withdraw",
                        format!("{{\"amount\":\"{amount}\"}}").as_bytes(),
                        NearToken::from_yoctonear(1),
                        Gas::from_tgas(GAS_NEAR_WITHDRAW),
                    )
                } else {
                    ft_to(&t, amount, &to, true)
                };
                let args = format!("{{\"token\":\"{}\",\"amount\":\"{}\",\"to\":\"{}\"}}", t, amount, to);
                env::promise_then(
                    last,
                    me,
                    "on_withdraw_one",
                    args.as_bytes(),
                    NearToken::from_yoctonear(0),
                    Gas::from_tgas(GAS_WITHDRAW_CB),
                );
            }
        }
    }
}

#[near(serializers = [json])]
pub struct DayView {
    pub start_ns: U64,
    pub spent_yocto: U128,
    /// v1.2.1: attached gas x GAS_PRICE_BOUND charged in this window (also bounded by the
    /// daily cap: spent + gas_spent <= daily_cap).
    pub gas_spent_yocto: U128,
    /// v1.4.1: next 00:00 UTC.
    pub resets_at_ns: U64,
}

#[near(serializers = [json])]
pub struct RelayerWeekView {
    pub start_ns: U64,
    pub resets_at_ns: U64,
    pub spent_yocto: U128,
    /// v1.4.8: null = no weekly limit
    pub allowance_yocto: Option<U128>,
}

/// v1.4.3 (OWNERBOUND-001): an owner cap raise, active at `active_at_ns`.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq)]
pub struct PendingCaps {
    pub caps: Caps,
    pub active_at_ns: U64,
}

const K_PENDING_CAPS: &[u8] = b"cp";
/// v1.4.4 (SC-8): the automation key whose install is in flight (until on_automation_set).
const K_INSTALLING: &[u8] = b"ai";
/// v1.4.5: caps in force when the pending raise was requested.
const K_PENDING_BASE: &[u8] = b"cb";

/// R2-05 (owner doors): E_Q_BUSY while wNEAR or any listed token is locked (`chain::assert_free`:
/// a Nearrr buy's output token until its settle, or a route's Q). A locked token can't leave
/// through an owner withdraw, or the owner could empty it mid-settle and make a fill read as the
/// pad's refund (fee 0). Every lock expires after `chain::LOCK_TTL_BLOCKS` (300 blocks), so owner
/// recovery waits seconds normally and at most ~5 minutes; other tokens and NEAR are unaffected.
fn assert_tokens_free(wrap: &AccountId, tokens: &[AccountId]) {
    chain::assert_free(wrap.as_str());
    for t in tokens {
        chain::assert_free(t.as_str());
    }
}

fn save_pending_caps(p: &PendingCaps) {
    env::storage_write(K_PENDING_CAPS, &near_sdk::borsh::to_vec(p).unwrap_or_else(|_| fail("E_STATE")));
}
/// Same delay as a withdraw destination (intents::DEST_DELAY_NS).
pub const CAPS_RAISE_DELAY_NS: u64 = intents::DEST_DELAY_NS;

fn pending_caps() -> Option<PendingCaps> {
    env::storage_read(K_PENDING_CAPS)
        .map(|b| near_sdk::borsh::from_slice(&b).unwrap_or_else(|_| fail("E_STATE")))
}

/// Drops a not-yet-active raise (`caps_raise_cancelled{by}`); a due one was already applied by
/// sync_caps.
fn cancel_caps_raise(by: &str) {
    env::storage_remove(K_PENDING_BASE);
    if env::storage_remove(K_PENDING_CAPS) {
        env::log_str(&format!(
            "EVENT_JSON:{{\"standard\":\"nttrade\",\"version\":\"1\",\"event\":\"caps_raise_cancelled\",\"data\":{{\"by\":\"{by}\"}}}}"
        ));
    }
}

/// `caps_set` / `caps_raised` / `caps_raise_pending{.., active_at_ns}`.
fn caps_event(name: &str, c: &Caps, active_at_ns: Option<u64>) {
    let at = active_at_ns.map_or(String::new(), |t| format!(",\"active_at_ns\":\"{t}\""));
    env::log_str(&format!(
        "EVENT_JSON:{{\"standard\":\"nttrade\",\"version\":\"1\",\"event\":\"{name}\",\"data\":{{\"max_trade_yocto\":\"{}\",\"daily_cap_yocto\":\"{}\"{at}}}}}",
        c.max_trade_yocto.0, c.daily_cap_yocto.0
    ));
}

/// v1.4.3 (SC-3): one init registration outcome.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq)]
pub struct InitRegistration {
    pub target: AccountId,
    pub ok: bool,
}

#[derive(Serialize)]
#[serde(crate = "near_sdk::serde")]
struct InitRegArgs {
    targets: Vec<AccountId>,
}

const K_INIT_REG: &[u8] = b"ir";
/// Static gas of on_init_registered (it also gets init's unused gas, weight 1).
const GAS_INIT_REG_CB: u64 = 3;

/// v1.4.3 (ORDER-001): what the swap promise's result can prove about a refund.
#[derive(Clone, Copy, PartialEq)]
enum SwapProof {
    /// ft_transfer_call on wrap.near (trusted resolve)
    Wrap,
    /// ft_transfer_call on any other token
    Token,
    /// Plach deposit_near (refund = failed receipt only)
    PlachNear,
    /// v1.5: Shards `sell_exact_in` (refund = failed receipt only; settled via on_shards_sold)
    ShardsSell,
    /// v1.6: payable curve buy (refund = failed receipt; fee on the measured refund)
    CurveNear,
    /// v1.6: direct curve sell (refund = failed receipt; fee on the measured payout)
    CurveOut,
}

impl SwapProof {
    /// v1.6: a Chain's leg-1 proof (routing: a failed leg 1 is a normal failed swap).
    fn of_leg(p: &str) -> Self {
        match p {
            "wrap" => SwapProof::Wrap,
            "token" => SwapProof::Token,
            "plach_near" => SwapProof::PlachNear,
            "curve_near" => SwapProof::CurveNear,
            _ => SwapProof::CurveOut,
        }
    }

    /// v1.6: a curve plan's settle kind (Wrap / Token keep today's on_swap_settled rules).
    fn from_curve(s: venues::Settle) -> Self {
        match s {
            venues::Settle::Wrap => SwapProof::Wrap,
            venues::Settle::Token => SwapProof::Token,
            venues::Settle::NearIn => SwapProof::CurveNear,
            // Out and any later measured kind (refund = failed receipt only)
            _ => SwapProof::CurveOut,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            SwapProof::Wrap => "wrap",
            SwapProof::Token => "token",
            SwapProof::PlachNear => "plach_near",
            SwapProof::ShardsSell => "shards_sell",
            SwapProof::CurveNear => "curve_near",
            SwapProof::CurveOut => "curve_out",
        }
    }
}

/// Arguments of the swap settlement (`on_swap_settled`'s, as JSON), v1.5 also carried by the
/// Shards sell chain.
#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct SettleArgs {
    pub client_order_id: String,
    pub amount: U128,
    pub counted: U128,
    pub fee: U128,
    pub day_start: U64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub order_id: Option<U64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relayer_week: Option<U64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relayer_counted: Option<U128>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relayer_gas: Option<U128>,
}

#[derive(Serialize)]
#[serde(crate = "near_sdk::serde")]
struct ShardsSettleArgs {
    settle: SettleArgs,
    credit: U128,
    liquid_before: U128,
}

/// v1.5: `deadline_ns` of a Shards trade: the latest a device `execute` may be valid.
fn shards_deadline(now: u64) -> u64 {
    now.saturating_add(MAX_EXPIRY_AHEAD_NS)
}

/// (order id, order, relayer fire: (ISO week start, counted min_out)).
/// v1.4.7: an automation key installed at account creation (`init`, from the factory).
#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct AutomationInit {
    pub public_key: PublicKey,
    /// gas allowance of the key (>= MIN_AUTOMATION_ALLOWANCE)
    pub allowance: U128,
    /// weekly relayer allowance; v1.4.8: None (or UNLIMITED) = no weekly limit (was 10 NEAR)
    pub weekly_yocto: Option<U128>,
}

/// v1.4.7: "no cap". Caps are plain u128 and every cap sum is checked or saturating, so
/// u128::MAX is a safe sentinel: `spent + x > UNLIMITED` is never true (checked_add fails
/// closed on the impossible overflow). The factory uses it when no caps are passed.
pub const UNLIMITED: u128 = u128::MAX;

/// v1.4.7: + whether it is a relayer BUY (weekly charge made in `run`).
type OrderRun = (u64, Order, Option<(u64, u128)>, bool);

// v1.4.1 (D6) relayer weekly allowance, raw keys outside STATE
const K_RELAYER_WEEK: &[u8] = b"rw";
const K_RELAYER_ALLOWANCE: &[u8] = b"ra";
/// C1-L3: with an owner-set allowance, each relayer fire costs at least allowance / 20, and
/// (v1.4.8, RA7-1) a failed fire keeps that floor charged: <= 20 fires per week, failures
/// included. v1.4.8: there is no default allowance (was 10 NEAR).
pub const MAX_RELAYER_FIRES_PER_WEEK: u128 = 20;
const K_RELAYER_KEYS: &[u8] = b"ar";
pub const MAX_RELAYER_KEYS: usize = 8;
const GAS_RELAYER_DELETE_CB: u64 = 5;

/// The install / rotate batch of `owner_set_automation_key` (v1.4.7: also used by `init`):
/// DeleteKey(old, if another key) + AddKey(public_key, execute_order only, gas `allowance`), then
/// `on_automation_set`. The key joins the relayer role set BEFORE its AddKey can land.
fn schedule_automation_install(public_key: PublicKey, cur: Option<PublicKey>, allowance: u128) {
    let me = env::current_account_id();
    let mut p = Promise::new(me.clone());
    let old = cur.filter(|o| *o != public_key);
    if let Some(o) = &old {
        p = p.delete_key(o.clone());
    }
    let allowance = near_sdk::Allowance::limited(NearToken::from_yoctonear(allowance))
        .unwrap_or_else(|| fail("E_ALLOWANCE"));
    // C1-M1: the new key is a relayer (role set) BEFORE its AddKey can land; the old one
    // stays in the set until its DeleteKey is confirmed by on_automation_set.
    let added = relayer_role_add(&public_key);
    // v1.4.4 (SC-8): marks the install in flight until on_automation_set.
    env::storage_write(
        K_INSTALLING,
        &near_sdk::borsh::to_vec(&public_key).unwrap_or_else(|_| fail("E_STATE")),
    );
    // A1-F2: the stored key changes only once the key batch has succeeded.
    p.add_access_key_allowance(public_key.clone(), allowance, me.clone(), AUTOMATION_METHODS)
        .then(
            Promise::new(me).function_call(
                "on_automation_set",
                format!(
                    "{{\"public_key\":{},\"old\":{},\"added\":{added}}}",
                    jstr(&String::from(&public_key)),
                    old.as_ref().map_or("null".to_string(), |o| jstr(&String::from(o)))
                )
                .into_bytes(),
                NearToken::from_yoctonear(0),
                Gas::from_tgas(GAS_AUTOMATION_CB),
            ),
        )
        .detach();
}

/// C1-M1: the relayer role set. Legacy (<= v1.4.1) state: just the stored automation key.
fn relayer_keys() -> Vec<PublicKey> {
    match env::storage_read(K_RELAYER_KEYS) {
        Some(b) => near_sdk::borsh::from_slice(&b).unwrap_or_else(|_| fail("E_STATE")),
        None => env::storage_read(K_AUTOMATION)
            .and_then(|b| near_sdk::borsh::from_slice::<PublicKey>(&b).ok())
            .into_iter()
            .collect(),
    }
}

fn save_relayer_keys(v: &Vec<PublicKey>) {
    env::storage_write(K_RELAYER_KEYS, &near_sdk::borsh::to_vec(v).unwrap_or_else(|_| fail("E_STATE")));
}

fn is_relayer(pk: &PublicKey) -> bool {
    relayer_keys().contains(pk)
}

/// Adds `pk`; true if it was not a member. E_AUTOMATION_BUSY past MAX_RELAYER_KEYS.
fn relayer_role_add(pk: &PublicKey) -> bool {
    let mut v = relayer_keys();
    if v.contains(pk) {
        save_relayer_keys(&v); // materialize a legacy set
        return false;
    }
    if v.len() >= MAX_RELAYER_KEYS {
        fail("E_AUTOMATION_BUSY");
    }
    v.push(pk.clone());
    save_relayer_keys(&v);
    true
}

/// Callback/migrate-safe add (never panics): makes `pk` a member and materializes the set.
fn relayer_role_ensure(pk: &PublicKey) {
    let mut v = relayer_keys();
    if !v.contains(pk) {
        v.push(pk.clone());
    }
    save_relayer_keys(&v);
}

fn relayer_role_remove(pk: &PublicKey) {
    let mut v = relayer_keys();
    v.retain(|k| k != pk);
    save_relayer_keys(&v);
}

/// DeleteKey(pk) then on_relayer_key_deleted (pk leaves the role set only once confirmed).
fn retire_relayer_key(pk: PublicKey) {
    let me = env::current_account_id();
    Promise::new(me.clone())
        .delete_key(pk.clone())
        .then(Promise::new(me).function_call(
            "on_relayer_key_deleted",
            format!("{{\"public_key\":{}}}", jstr(&String::from(&pk))).into_bytes(),
            NearToken::from_yoctonear(0),
            Gas::from_tgas(GAS_RELAYER_DELETE_CB),
        ))
        .detach();
}

/// v1.4.8: the owner-set weekly relayer allowance; None = no weekly limit (nothing stored, the
/// default; a stored UNLIMITED, possible under v1.4.7, counts as none too).
fn relayer_allowance() -> Option<u128> {
    env::storage_read(K_RELAYER_ALLOWANCE)
        .and_then(|b| b.try_into().ok().map(u128::from_le_bytes))
        .filter(|&a| a != UNLIMITED)
}

fn relayer_week_state() -> Day {
    env::storage_read(K_RELAYER_WEEK)
        .map(|b| near_sdk::borsh::from_slice(&b).unwrap_or_else(|_| fail("E_STATE")))
        .unwrap_or(Day { start_ns: 0, spent_yocto: 0 })
}

fn save_relayer_week(w: &Day) {
    env::storage_write(K_RELAYER_WEEK, &near_sdk::borsh::to_vec(w).unwrap_or_else(|_| fail("E_STATE")));
}

fn roll_week(w: &mut Day, now: u64) {
    let start = iso_week_start(now);
    if w.start_ns != start {
        *w = Day { start_ns: start, spent_yocto: 0 };
    }
}

const TGAS: u64 = 1_000_000_000_000;
/// v1.4: ft_transfer_call into the intents verifier (its ft_on_transfer + our resolve).
const GAS_INTENTS_TRANSFER: u64 = 50;

#[near(serializers = [json])]
pub struct DestView {
    pub dest_id: u32,
    pub active: bool,
    #[serde(flatten)]
    pub dest: Dest,
}

#[near(serializers = [json])]
pub struct WithdrawDayView {
    pub start_ns: U64,
    pub spent_yocto: U128,
    pub cap_yocto: U128,
    /// v1.4.1: micro-USD (signed amountInUsd, all tokens).
    pub spent_usd: U128,
    pub cap_usd: U128,
    /// v1.4.1: next 00:00 UTC.
    pub resets_at_ns: U64,
}

const GAS_KEY_CB: u64 = 3;

/// v1.4.1: `device_key_added{public_key, replaced, ok}`.
fn key_event(pk_json: &str, replaced: bool, ok: bool) {
    env::log_str(&format!(
        "EVENT_JSON:{{\"standard\":\"nttrade\",\"version\":\"1\",\"event\":\"device_key_added\",\"data\":{{\"public_key\":{pk_json},\"replaced\":{replaced},\"ok\":{ok}}}}}"
    ));
}

/// The configured verifier (default intents.near).
fn verifier() -> AccountId {
    intents::oneclick()
        .map(|c| c.intents)
        .unwrap_or_else(|| intents::DEFAULT_INTENTS.parse().unwrap_or_else(|_| fail("E_STATE")))
}

fn remove_dest(dest_id: u32, by: &str) {
    let mut d = intents::dests();
    let n = d.list.len();
    d.list.retain(|(i, _)| *i != dest_id);
    if d.list.len() == n {
        fail("E_NO_DEST");
    }
    intents::save_dests(&d);
    env::log_str(&format!(
        "EVENT_JSON:{{\"standard\":\"nttrade\",\"version\":\"1\",\"event\":\"withdraw_destination_removed\",\"data\":{{\"dest_id\":{dest_id},\"by\":\"{by}\"}}}}"
    ));
}

// v1.3.2 owner withdrawals
pub const MAX_WITHDRAW_TOKENS: usize = 6;
const GAS_VIEW: u64 = 5;
const GAS_FT_STORAGE: u64 = 8;
const GAS_FT_SEND: u64 = 10;
const GAS_WITHDRAW_CB: u64 = 10;
const GAS_REPORT_CB: u64 = 25;
const GAS_WITHDRAW_ALL_CB: u64 = 180;

#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct WithdrawAllArgs {
    to: AccountId,
    tokens: Vec<AccountId>,
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct WithdrawReportArgs {
    to: AccountId,
    items: Vec<(AccountId, U128)>,
    /// v1.4.8 (UNR-A-03): native NEAR kept back for the skipped items' deposits, so the owner
    /// can call again for them without a top-up (absent in pre-v1.4.8 in-flight callbacks).
    #[serde(default)]
    keep: Option<U128>,
}

/// `ft_transfer(to, amount)` on `token`, optionally after `storage_deposit(to,
/// registration_only)` (chained with .then so the transfer runs even if the token has no
/// storage_deposit). Returns the index of the transfer promise.
fn ft_to(token: &AccountId, amount: u128, to: &AccountId, register: bool) -> near_sdk::PromiseIndex {
    let transfer_args = format!("{{\"receiver_id\":\"{to}\",\"amount\":\"{amount}\"}}");
    if register {
        let reg = env::promise_create(
            token.clone(),
            "storage_deposit",
            format!("{{\"account_id\":\"{to}\",\"registration_only\":true}}").as_bytes(),
            NearToken::from_yoctonear(MAX_STORAGE_DEPOSIT),
            Gas::from_tgas(GAS_FT_STORAGE),
        );
        env::promise_then(
            reg,
            token.clone(),
            "ft_transfer",
            transfer_args.as_bytes(),
            NearToken::from_yoctonear(1),
            Gas::from_tgas(GAS_FT_SEND),
        )
    } else {
        env::promise_create(
            token.clone(),
            "ft_transfer",
            transfer_args.as_bytes(),
            NearToken::from_yoctonear(1),
            Gas::from_tgas(GAS_FT_SEND),
        )
    }
}

/// v1.4.8 (UNR-A-05): a Plach asset id naming this account (`nep141:<self>`), refused like
/// `token == self` in StorageDeposit / FtTransferCall / DexWithdraw (INV-16).
fn names_self(asset_id: &str, me: &AccountId) -> bool {
    asset_id.strip_prefix("nep141:") == Some(me.as_str())
}

/// v1.4.8 (UNR-A-03): an owner_withdraw_all item not sent because the native liquid balance
/// can't pay its deposit (`needed_yocto`: 1 yocto, or + MAX_STORAGE_DEPOSIT to register `to`).
/// Reported as `owner_withdraw{ok: false}` plus this event; top up NEAR and call again.
fn withdraw_skipped(token: &str, amount: u128, to: &AccountId, needed: u128) {
    withdraw_event(token, amount, to, false);
    env::log_str(&format!(
        "EVENT_JSON:{{\"standard\":\"nttrade\",\"version\":\"1\",\"event\":\"owner_withdraw_skipped\",\"data\":{{\"token\":\"{token}\",\"amount\":\"{amount}\",\"to\":\"{to}\",\"reason\":\"low_native\",\"needed_yocto\":\"{needed}\"}}}}"
    ));
}

fn withdraw_event(token: &str, amount: u128, to: &AccountId, ok: bool) {
    env::log_str(&format!(
        "EVENT_JSON:{{\"standard\":\"nttrade\",\"version\":\"1\",\"event\":\"owner_withdraw\",\"data\":{{\"token\":\"{token}\",\"amount\":\"{amount}\",\"to\":\"{to}\",\"ok\":{ok}}}}}"
    ));
}

fn batch_for(
    batches: &mut Vec<(AccountId, near_sdk::PromiseIndex)>,
    rcv: AccountId,
) -> near_sdk::PromiseIndex {
    match batches.iter().find(|(a, _)| a == &rcv) {
        Some((_, i)) => *i,
        None => {
            let i = env::promise_batch_create(&rcv);
            batches.push((rcv, i));
            i
        }
    }
}

/// storage_deposit(DCL_REGISTRATION, registration_only) + storage_withdraw() in ONE receipt:
/// atomic, so either we end registered with the slot deposit returned, or nothing happened.
fn dcl_register_actions(idx: near_sdk::PromiseIndex) {
    let deposit = format!("{{\"account_id\":\"{}\",\"registration_only\":true}}", env::current_account_id());
    for (m, args, dep) in
        [("storage_deposit", deposit.as_bytes(), DCL_REGISTRATION), ("storage_withdraw", b"{}".as_slice(), 1)]
    {
        env::promise_batch_action_function_call_weight(
            idx,
            m,
            args,
            NearToken::from_yoctonear(dep),
            Gas::from_tgas(GAS_DCL_STORAGE),
            GasWeight(0),
        );
    }
}

/// Balance not locked for storage staking (what can actually pay gas and deposits).
fn liquid_balance() -> u128 {
    let locked = (env::storage_usage() as u128).saturating_mul(env::storage_byte_cost().as_yoctonear());
    env::account_balance().as_yoctonear().saturating_sub(locked)
}

/// JSON string literal (quoted + escaped). AccountIds and integers need no escaping.
fn jstr(v: &str) -> String {
    serde_json::to_string(v).unwrap_or_else(|_| fail("E_JSON"))
}

// ---------------- v1.3 order storage (outside STATE) ----------------

fn order_key(id: u64) -> Vec<u8> {
    [b"o".as_slice(), &id.to_le_bytes()].concat()
}

fn u64_from(b: &[u8]) -> u64 {
    b.try_into().map(u64::from_le_bytes).unwrap_or_else(|_| fail("E_STATE"))
}

fn order_index() -> Vec<(u64, u64)> {
    env::storage_read(K_ORDER_INDEX)
        .map(|b| near_sdk::borsh::from_slice(&b).unwrap_or_else(|_| fail("E_STATE")))
        .unwrap_or_default()
}

fn set_order_index(index: &Vec<(u64, u64)>) {
    if index.is_empty() {
        env::storage_remove(K_ORDER_INDEX);
    } else {
        env::storage_write(
            K_ORDER_INDEX,
            &near_sdk::borsh::to_vec(index).unwrap_or_else(|_| fail("E_STATE")),
        );
    }
}

fn load_order(id: u64) -> Option<Order> {
    env::storage_read(&order_key(id))
        .map(|b| near_sdk::borsh::from_slice(&b).unwrap_or_else(|_| fail("E_STATE")))
}

fn save_order(id: u64, o: &Order) {
    env::storage_write(&order_key(id), &near_sdk::borsh::to_vec(o).unwrap_or_else(|_| fail("E_STATE")));
}

fn remove_order(id: u64) {
    env::storage_remove(&order_key(id));
    chain::remove_via(id);
    venues::order_terms::remove(id);
    let mut index = order_index();
    index.retain(|(i, _)| *i != id);
    set_order_index(&index);
}

fn order_event(name: &str, id: u64) {
    env::log_str(&format!(
        "EVENT_JSON:{{\"standard\":\"nttrade\",\"version\":\"1\",\"event\":\"{name}\",\"data\":{{\"order_id\":\"{id}\"}}}}"
    ));
}

/// Ops an automation-triggered order may contain besides its one swap.
fn check_order_op(o: &Order, op: &Op, wrap: &AccountId) -> Result<(), &'static str> {
    match op {
        Op::FtTransferCall { .. } | Op::PlachDepositNear { .. } => Ok(()),
        Op::ShardsBuy { .. } | Op::ShardsSell { .. } => Ok(()),
        // v1.6: checked against the order by check_order_swap in run (never a CurveClaim)
        Op::CurveBuy(_) | Op::CurveSell(_) => Ok(()),
        // v1.6: checked against the stored legs (check_chain_order); never an IntentsSwap
        Op::Chain(_) => Ok(()),
        Op::StorageDeposit { .. } | Op::PlachRegisterAssets { .. } => Ok(()),
        Op::NearDeposit { amount } if &o.token_in == wrap && amount.0 <= o.amount_in.0 => Ok(()),
        _ => Err("E_ORDER_OPS"),
    }
}

/// The swap must be exactly the order: same input token and amount, an order DEX, the order's
/// output token, and a parsed guaranteed output >= the order's min_out.
fn check_order_swap(
    o: &Order,
    dex: &AccountId,
    token_in: &AccountId,
    amount: u128,
    s: &Swap,
) -> Result<(), &'static str> {
    if token_in != &o.token_in
        || amount != o.amount_in.0
        || !o.dexes.contains(dex)
        || s.out != o.token_out.as_str()
    {
        return Err("E_ORDER_MISMATCH");
    }
    if s.min_out < o.min_out.0 {
        return Err("E_ORDER_MIN_OUT");
    }
    Ok(())
}

fn save_day_gas(start_ns: u64, total: u128) {
    let mut v = start_ns.to_le_bytes().to_vec();
    v.extend_from_slice(&total.to_le_bytes());
    env::storage_write(K_DAY_GAS, &v);
}

/// v1.2.1: gas tally of the window starting at `start_ns` (0 if the stored one is older).
/// v1.4.1: a still-live pre-v1.4.1 rolling-window record carries into the current UTC day.
fn day_gas(start_ns: u64) -> u128 {
    let now = env::block_timestamp();
    match env::storage_read(K_DAY_GAS) {
        Some(b)
            if b.len() == 24
                && (u64_from(&b[..8]) == start_ns
                    || (start_ns == utc_day_start(now) && legacy_live(u64_from(&b[..8]), now))) =>
        {
            u128::from_le_bytes(b[8..].try_into().unwrap_or([0; 16]))
        }
        _ => 0,
    }
}

// ---------------- v1.6: balances an owner withdraw never sends ----------------

/// Storage the signed path may still need after the account is emptied: the used-nonce store at
/// its cap (32 x 40 B) + the `ow` record with 4 auth keys + trie overhead. Kept liquid for an
/// owner with signatures on, so the next signed call never needs a top-up.
pub const SIGNED_STATE_BYTES: u128 = 2_048;

impl TradingAccount {
    /// Liquid NEAR an owner withdraw leaves in place: escrowed route fees (routing C.2.2) plus,
    /// with owner signatures on, the signed-path state reserve. 0 for a NEAR-wallet owner with
    /// no route in flight (1.5 behaviour).
    /// Pure (INDEP-1): every door that reads it sweeps expired routes (`expire_routes`) BEFORE
    /// reading `liquid_balance()`, so the paid escrow is neither held nor counted as liquid.
    pub(crate) fn owner_hold(&self) -> u128 {
        let signed = if owner::owner_auth(&self.owner).signed_enabled {
            SIGNED_STATE_BYTES.saturating_mul(env::storage_byte_cost().as_yoctonear())
        } else {
            0
        };
        chain::escrow_total().saturating_add(signed)
    }

    /// v1.6: a refunded IntentsSwap returns its counted spend to the daily window it was charged
    /// in: the escrowed fee, and the input pro rata to what came back (`returned`, capped).
    /// Funding failed (nothing left the account): the input came back through `finish_settle`,
    /// so only the escrowed fee's spend is released here.
    pub(crate) fn release_route_fee(&mut self, rid: &str) {
        let k = [K_ROUTE_SPEND, rid.as_bytes()].concat();
        if let Some((day_start, _, fee)) =
            env::storage_read(&k).and_then(|b| near_sdk::borsh::from_slice::<(u64, u128, u128)>(&b).ok())
        {
            env::storage_remove(&k);
            if self.day.start_ns == day_start {
                self.day.spent_yocto = self.day.spent_yocto.saturating_sub(fee);
            }
        }
    }

    pub(crate) fn release_route_spend(&mut self, rid: &str, returned: u128) {
        let k = [K_ROUTE_SPEND, rid.as_bytes()].concat();
        let Some((day_start, amount, fee)) =
            env::storage_read(&k).and_then(|b| near_sdk::borsh::from_slice::<(u64, u128, u128)>(&b).ok())
        else {
            return;
        };
        env::storage_remove(&k);
        // V16-07: input AND escrowed fee pro rata to what came back (the rest was traded and paid)
        let back = mul_div(amount.saturating_add(fee), returned.min(amount), amount.max(1));
        if self.day.start_ns == day_start {
            self.day.spent_yocto = self.day.spent_yocto.saturating_sub(back);
        }
        env::log_str(&format!(
            "EVENT_JSON:{{\"standard\":\"nttrade\",\"version\":\"1\",\"event\":\"route_spend_released\",\"data\":{{\"id\":{},\"amount\":\"{back}\"}}}}",
            jstr(rid)
        ));
    }
}

/// `rs` + route id: (day start, counted input, escrowed fee) of an IntentsSwap.
const K_ROUTE_SPEND: &[u8] = b"rs";

fn save_route_spend(rid: &str, day_start: u64, amount: u128, fee: u128) {
    let k = [K_ROUTE_SPEND, rid.as_bytes()].concat();
    env::storage_write(
        &k,
        &near_sdk::borsh::to_vec(&(day_start, amount, fee)).unwrap_or_else(|_| fail("E_STATE")),
    );
}

/// The route's spend record once its delivery is proven (nothing to release).
pub(crate) fn drop_route_spend(rid: &str) {
    env::storage_remove(&[K_ROUTE_SPEND, rid.as_bytes()].concat());
}
