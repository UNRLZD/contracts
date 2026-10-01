//! v1.6 future-proofing (docs/audit/v160-future-proofing.md F-01, F-02, F-03, F-19; spec §6.1):
//! opt-in delayed auto-upgrade to factory-approved code, the state-version key, and the owner's
//! rescue of assets no other flow can move.
use crate::*;

/// `au`: the owner's auto-upgrade setting and its pending / vetoed hashes (borsh).
pub const K_AUTO_UPGRADE: &[u8] = b"au";
/// `ch`: the code hash the last signed / auto upgrade installed (written by the new code itself,
/// in the upgrade batch). Absent = unknown (an account created with its code, or upgraded by the
/// predecessor door).
pub const K_CODE_HASH: &[u8] = b"ch";
/// `sv`: state version (u32 LE). 160 = TA 1.6.0 layout; `migrate` dispatches on it from 1.7 on.
pub const K_STATE_VERSION: &[u8] = b"sv";
pub const STATE_VERSION: u32 = 160;
/// A scheduled auto-upgrade applies no earlier than this after it was first seen (owner and
/// every device key can veto meanwhile).
pub const AUTO_UPGRADE_DELAY_NS: u64 = 72 * 3_600 * 1_000_000_000;
/// Vetoed hashes remembered (R2-10: 16, oldest evicted first).
pub const MAX_VETOED: usize = 16;
/// R2-01: `apply_auto_upgrade` and its callback need this much prepaid gas, so `migrate` always
/// gets a large budget (a starved apply can't make the batch fail).
pub const MIN_APPLY_GAS: u64 = 250;
/// R2-01: the callback must still hold this much when it schedules the batch.
pub const MIN_APPLY_CB_GAS: u64 = 200;
/// `ap`: an apply in flight (hash, block height after which it is considered failed): a second
/// apply waits; `on_code_installed` clears it together with the pending entry.
pub const K_APPLYING: &[u8] = b"ap";
const APPLY_TTL_BLOCKS: u64 = 50;
/// `if`: block height until which a callback may still be in flight (swap settles, route locks).
pub const K_IN_FLIGHT: &[u8] = b"if";
/// Blocks a scheduled swap settle may take (every settle chain lands within a few blocks).
pub const SETTLE_WINDOW_BLOCKS: u64 = 100;
const GAS_FACTORY_VIEW: u64 = 5;
/// The check callbacks: static gas + all leftover (weight 1), so `migrate` gets what remains.
const GAS_AUTO_CB: u64 = 30;
/// `migrate` static gas in every upgrade batch; it also gets all leftover gas (F-02).
pub const GAS_MIGRATE_MIN: u64 = 20;
/// The old-code guard + installed-hash record at the end of an upgrade batch.
pub const GAS_CODE_INSTALLED: u64 = 5;
/// F-19: rescue transfer gas.
/// (a `*_transfer_call` runs the receiver's on_transfer and the resolve)
const GAS_RESCUE: u64 = 50;

#[near(serializers = [borsh])]
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AutoUpgrade {
    pub enabled: bool,
    /// (code hash, earliest apply time)
    pub pending: Option<([u8; 32], u64)>,
    pub vetoed: Vec<[u8; 32]>,
}

pub fn auto_upgrade() -> AutoUpgrade {
    env::storage_read(K_AUTO_UPGRADE)
        .map(|b| near_sdk::borsh::from_slice(&b).unwrap_or_else(|_| fail("E_STATE")))
        .unwrap_or_default()
}

fn save_auto(a: &AutoUpgrade) {
    env::storage_write(K_AUTO_UPGRADE, &near_sdk::borsh::to_vec(a).unwrap_or_else(|_| fail("E_STATE")));
}

/// R2-09: a callback of this account may land until block `height`.
pub fn mark_in_flight(blocks: u64) {
    let until = env::block_height().saturating_add(blocks);
    let cur =
        env::storage_read(K_IN_FLIGHT).and_then(|b| b.try_into().ok().map(u64::from_le_bytes)).unwrap_or(0);
    if until > cur {
        env::storage_write(K_IN_FLIGHT, &until.to_le_bytes());
    }
}

pub(crate) fn in_flight() -> bool {
    let until =
        env::storage_read(K_IN_FLIGHT).and_then(|b| b.try_into().ok().map(u64::from_le_bytes)).unwrap_or(0);
    env::block_height() < until
        || crate::order_index().iter().any(|(id, _)| crate::load_order(*id).is_some_and(|o| o.pending))
        || crate::chain::store::route_index().iter().filter_map(|id| crate::chain::store::load_route(id)).any(
            |r| {
                // a continuation in flight (a Chain in flight holds a Q lock: the window above);
                // one whose callback never ran stops counting after ROUTE_PENDING_TTL_BLOCKS
                r.pending_live()
            },
        )
}

/// R2-09 on the owner doors: the predecessor `owner_upgrade` and the signed `upgrade` op refuse
/// (E_IN_FLIGHT) on the same `in_flight()` condition the permissionless apply waits on, so no
/// callback lands on different code mid-trade. Withdraws and recovery are never gated. The owner
/// waits at most: SETTLE_WINDOW_BLOCKS (100) after the last swap, LOCK_TTL_BLOCKS (300 blocks,
/// about 5 minutes) after a route or Nearrr lock was taken, ROUTE_PENDING_TTL_BLOCKS (300) after
/// a continuation fire whose callback never runs (else until it runs, normally seconds), and for
/// a pending order fire until its settle runs, which the owner (or a device) can always end by
/// `cancel_order`: cancel is never refused while the fire is pending, and a late settle then
/// finds no order. Nothing can hold an upgrade forever.
pub(crate) fn assert_not_in_flight() {
    if in_flight() {
        fail("E_IN_FLIGHT");
    }
}

fn applying() -> Option<([u8; 32], u64)> {
    env::storage_read(K_APPLYING)
        .and_then(|b| near_sdk::borsh::from_slice::<([u8; 32], u64)>(&b).ok())
        .filter(|(_, until)| env::block_height() < *until)
}

pub fn installed_hash() -> Option<[u8; 32]> {
    env::storage_read(K_CODE_HASH).and_then(|b| b.try_into().ok())
}

pub fn write_state_version() {
    env::storage_write(K_STATE_VERSION, &STATE_VERSION.to_le_bytes());
}

fn b58(h: &[u8; 32]) -> String {
    near_sdk::bs58::encode(h).into_string()
}

fn hash32(h: &Base58CryptoHash) -> [u8; 32] {
    let c: near_sdk::CryptoHash = (*h).into();
    c
}

fn event(name: &str, data: &str) {
    env::log_str(&format!(
        "EVENT_JSON:{{\"standard\":\"nttrade\",\"version\":\"1\",\"event\":\"{name}\",\"data\":{data}}}"
    ));
}

/// The factory = this account's parent (`<hex16>.<factory>`).
pub fn factory_id() -> AccountId {
    env::current_account_id()
        .as_str()
        .split_once('.')
        .and_then(|(_, f)| f.parse().ok())
        .unwrap_or_else(|| fail("E_NO_FACTORY"))
}

/// `get_approved_code_hashes()` result: the approved hashes, or None (failed / unreadable).
fn approved_result() -> Option<Vec<[u8; 32]>> {
    let v: Vec<Base58CryptoHash> =
        env::promise_result_checked(0, 4_096).ok().and_then(|b| serde_json::from_slice(&b).ok())?;
    Some(v.iter().map(hash32).collect())
}

/// `factory.get_approved_code_hashes()` then `self.<cb>(args)` (static + all leftover gas).
fn ask_factory(cb: &str, args: String) {
    let me = env::current_account_id();
    Promise::new(factory_id())
        .function_call(
            "get_approved_code_hashes",
            b"{}".to_vec(),
            NearToken::from_yoctonear(0),
            Gas::from_tgas(GAS_FACTORY_VIEW),
        )
        .then(Promise::new(me).function_call_weight(
            cb,
            args.into_bytes(),
            NearToken::from_yoctonear(0),
            Gas::from_tgas(GAS_AUTO_CB),
            GasWeight(1),
        ))
        .detach();
}

/// The upgrade batch of every checked path: UseGlobalContract, then migrate (all leftover gas,
/// F-02), then `on_code_installed(hash)`: the old-code guard (code without it reverts the whole
/// batch) that also records the installed hash.
pub fn guarded_upgrade_batch(code_hash: [u8; 32]) {
    let me = env::current_account_id();
    Promise::new(me)
        .use_global_contract(code_hash)
        .function_call_weight(
            "migrate",
            vec![],
            NearToken::from_yoctonear(0),
            Gas::from_tgas(GAS_MIGRATE_MIN),
            GasWeight(1),
        )
        .function_call_weight(
            "on_code_installed",
            format!("{{\"code_hash\":\"{}\"}}", b58(&code_hash)).into_bytes(),
            NearToken::from_yoctonear(0),
            Gas::from_tgas(GAS_CODE_INSTALLED),
            GasWeight(0),
        )
        .detach();
}

/// F-19: an asset no other flow moves. Always to the owner's home, never elsewhere.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde", deny_unknown_fields)]
pub enum RescueAsset {
    /// Any NEP-141 (as withdraw_home: native owner account, or the owner's intents balance).
    Ft { contract: AccountId, amount: U128 },
    /// NEP-245 multi-token (e.g. HOT omni): `mt_transfer`.
    Mt { contract: AccountId, token_id: String, amount: U128 },
    /// NEP-171 NFT: `nft_transfer`.
    Nft { contract: AccountId, token_id: String },
}

#[near(serializers = [json])]
pub struct PendingView {
    pub code_hash: String,
    pub eta_ns: U64,
}

#[near(serializers = [json])]
pub struct AutoUpgradeView {
    pub enabled: bool,
    pub pending: Option<PendingView>,
    pub vetoed: Vec<String>,
    pub installed: Option<String>,
    pub delay_ns: U64,
    pub state_version: u32,
}

#[near]
impl TradingAccount {
    /// F-01: turn opt-in auto-upgrade on or off (owner, 1 yocto). Off clears a pending one.
    #[payable]
    pub fn owner_set_auto_upgrade(&mut self, enabled: bool) {
        self.assert_owner();
        self.set_auto_upgrade(enabled);
    }

    /// F-01 veto by the owner (1 yocto). Devices veto with the `CancelAutoUpgrade` execute op.
    #[payable]
    pub fn owner_cancel_auto_upgrade(&mut self) {
        self.assert_owner();
        veto("owner");
    }

    /// F-19: owner-only rescue to the owner's home (1 yocto).
    #[payable]
    pub fn owner_rescue(&mut self, asset: RescueAsset) {
        self.assert_owner();
        self.rescue(asset);
    }

    /// F-01, permissionless: with auto-upgrade on, read the factory's approved hashes and record
    /// the first one that is neither installed nor vetoed as pending (earliest apply = first seen
    /// + 72 h). A pending hash still approved keeps its time.
    pub fn schedule_auto_upgrade(&mut self) {
        if !auto_upgrade().enabled {
            fail("E_AUTO_OFF");
        }
        ask_factory("on_auto_scheduled", "{}".into());
    }

    #[private]
    pub fn on_auto_scheduled(&mut self) {
        let mut a = auto_upgrade();
        if !a.enabled {
            return event("auto_upgrade_refused", "{\"reason\":\"off\"}");
        }
        let Some(approved) = approved_result() else {
            return event("auto_upgrade_refused", "{\"reason\":\"factory_unreadable\"}");
        };
        let installed = installed_hash();
        // R2-04: a pending hash the factory no longer approves is dropped (a re-approval later
        // gets a fresh 72 h window)
        if let Some((p, _)) = a.pending.filter(|(p, _)| !approved.contains(p)) {
            a.pending = None;
            save_auto(&a);
            event(
                "auto_upgrade_dropped",
                &format!("{{\"code_hash\":\"{}\",\"reason\":\"not_approved\"}}", b58(&p)),
            );
        }
        let next = approved.into_iter().find(|h| Some(*h) != installed && !a.vetoed.contains(h));
        match (next, a.pending) {
            (None, _) => event("auto_upgrade_refused", "{\"reason\":\"nothing_new\"}"),
            (Some(h), Some((p, _))) if p == h => {}
            (Some(h), _) => {
                let eta = env::block_timestamp().saturating_add(AUTO_UPGRADE_DELAY_NS);
                a.pending = Some((h, eta));
                save_auto(&a);
                event(
                    "auto_upgrade_scheduled",
                    &format!("{{\"code_hash\":\"{}\",\"eta_ns\":\"{eta}\"}}", b58(&h)),
                );
            }
        }
    }

    /// F-01, permissionless: after the delay, re-check the pending hash is still approved, then
    /// upgrade (guarded batch). Anything else refuses and changes nothing.
    pub fn apply_auto_upgrade(&mut self) {
        let a = auto_upgrade();
        if !a.enabled {
            fail("E_AUTO_OFF");
        }
        let (h, eta) = a.pending.unwrap_or_else(|| fail("E_AUTO_NONE"));
        if env::block_timestamp() < eta {
            fail("E_AUTO_EARLY");
        }
        // R2-01: enough gas that migrate can't be starved
        if env::prepaid_gas() < Gas::from_tgas(MIN_APPLY_GAS) {
            fail("E_APPLY_GAS");
        }
        if applying().is_some() {
            fail("E_AUTO_APPLYING");
        }
        ask_factory("on_auto_apply_checked", format!("{{\"code_hash\":\"{}\"}}", b58(&h)));
    }

    #[private]
    pub fn on_auto_apply_checked(&mut self, code_hash: Base58CryptoHash) {
        let h = hash32(&code_hash);
        let mut a = auto_upgrade();
        let reason = if !a.enabled {
            Some("off")
        } else if a.pending.map(|p| p.0) != Some(h) || a.vetoed.contains(&h) {
            Some("not_pending")
        } else if a.pending.is_some_and(|p| env::block_timestamp() < p.1) {
            Some("early")
        } else if !approved_result().is_some_and(|v| v.contains(&h)) {
            Some("not_approved")
        } else if env::storage_has_key(K_INSTALLING) {
            // one automation change at a time (an install in flight would be orphaned)
            Some("automation_busy")
        } else if in_flight() {
            // R2-09: never swap code under an in-flight settle, route or pending order fire
            Some("in_flight")
        } else if applying().is_some() {
            Some("applying")
        } else if env::prepaid_gas() < Gas::from_tgas(MIN_APPLY_CB_GAS) {
            Some("low_gas")
        } else {
            None
        };
        if let Some(r) = reason {
            return event(
                "auto_upgrade_refused",
                &format!("{{\"code_hash\":\"{}\",\"reason\":\"{r}\"}}", b58(&h)),
            );
        }
        // R2-01: the pending entry stays until the NEW code confirms the install
        // (on_code_installed); meanwhile a second apply waits (`ap`)
        let _ = &mut a;
        env::storage_write(
            K_APPLYING,
            &near_sdk::borsh::to_vec(&(h, env::block_height().saturating_add(APPLY_TTL_BLOCKS)))
                .unwrap_or_else(|_| fail("E_STATE")),
        );
        guarded_upgrade_batch(h);
        event("auto_upgrade_started", &format!("{{\"code_hash\":\"{}\"}}", b58(&h)));
    }

    /// The last call of every checked upgrade batch, run by the NEW code: it exists from 1.6.0 on
    /// (older code reverts the batch) and records what was installed.
    #[private]
    pub fn on_code_installed(&mut self, code_hash: Base58CryptoHash) {
        let h = hash32(&code_hash);
        env::storage_write(K_CODE_HASH, &h);
        write_state_version();
        env::storage_remove(K_APPLYING);
        let mut a = auto_upgrade();
        if a.pending.is_some_and(|(p, _)| p == h) {
            a.pending = None;
            save_auto(&a);
            event("auto_upgrade_applied", &format!("{{\"code_hash\":\"{}\"}}", b58(&h)));
        }
    }

    pub fn get_auto_upgrade(&self) -> AutoUpgradeView {
        let a = auto_upgrade();
        AutoUpgradeView {
            enabled: a.enabled,
            pending: a.pending.map(|(h, eta)| PendingView { code_hash: b58(&h), eta_ns: U64(eta) }),
            vetoed: a.vetoed.iter().map(b58).collect(),
            installed: installed_hash().map(|h| b58(&h)),
            delay_ns: U64(AUTO_UPGRADE_DELAY_NS),
            state_version: env::storage_read(K_STATE_VERSION)
                .and_then(|b| b.try_into().ok().map(u32::from_le_bytes))
                .unwrap_or(0),
        }
    }
}

/// Veto the pending auto-upgrade: its hash is never scheduled again (a new approved hash is).
pub(crate) fn veto(by: &str) {
    let mut a = auto_upgrade();
    let Some((h, _)) = a.pending.take() else {
        return event("auto_upgrade_vetoed", &format!("{{\"code_hash\":null,\"by\":\"{by}\"}}"));
    };
    a.vetoed.retain(|x| *x != h);
    if a.vetoed.len() >= MAX_VETOED {
        a.vetoed.remove(0);
    }
    a.vetoed.push(h);
    save_auto(&a);
    event("auto_upgrade_vetoed", &format!("{{\"code_hash\":\"{}\",\"by\":\"{by}\"}}", b58(&h)));
}

impl TradingAccount {
    pub(crate) fn set_auto_upgrade(&mut self, enabled: bool) {
        let mut a = auto_upgrade();
        a.enabled = enabled;
        if !enabled {
            a.pending = None;
        }
        save_auto(&a);
        event("auto_upgrade_set", &format!("{{\"enabled\":{enabled}}}"));
    }

    /// F-19. To the owner's home only: its NEAR account, or (signed-path owners) its intents.near
    /// balance through the token's `*_transfer_call` with `msg = owner`. Never self, never the
    /// verifier (intents balances have their own flows), never a token a live route holds.
    pub(crate) fn rescue(&mut self, asset: RescueAsset) {
        let me = env::current_account_id();
        let contract = match &asset {
            RescueAsset::Ft { contract, .. }
            | RescueAsset::Mt { contract, .. }
            | RescueAsset::Nft { contract, .. } => contract.clone(),
        };
        if contract == me || contract == verifier() {
            fail("E_BAD_OP");
        }
        crate::chain::assert_free(contract.as_str());
        // F1: expired routes are closed first (they reserve nothing)
        crate::chain::expire_routes(&self.fee.fee_recipient);
        if crate::chain::intents_token_reserved(&contract, &self.wrap) {
            fail("E_Q_BUSY");
        }
        let home_intents = self.home_is_intents();
        let owner = self.owner.clone();
        let one = NearToken::from_yoctonear(1);
        let (method, args) = match asset {
            RescueAsset::Ft { amount, .. } => {
                if amount.0 == 0 {
                    fail("E_BAD_OP");
                }
                // withdraw_home's rules (registration from the liquid balance, RESERVE kept)
                ok(check_reserve(
                    liquid_balance().saturating_sub(self.owner_hold()),
                    MAX_STORAGE_DEPOSIT + 1,
                ));
                return if home_intents {
                    self.send_home(Some(contract), amount.0)
                } else {
                    self.send(Some(contract), amount.0, owner, true)
                };
            }
            RescueAsset::Mt { token_id, amount, .. } => {
                if amount.0 == 0 || token_id.is_empty() || token_id.len() > 256 {
                    fail("E_BAD_OP");
                }
                if home_intents {
                    (
                        "mt_transfer_call",
                        // NEP-245 single-token form (R2-02)
                        serde_json::json!({"receiver_id": verifier(), "token_id": token_id,
                            "amount": amount.0.to_string(), "approval": null, "memo": null, "msg": owner})
                        .to_string(),
                    )
                } else {
                    (
                        "mt_transfer",
                        serde_json::json!({"receiver_id": owner, "token_id": token_id, "amount": amount.0.to_string()})
                            .to_string(),
                    )
                }
            }
            RescueAsset::Nft { token_id, .. } => {
                if token_id.is_empty() || token_id.len() > 256 {
                    fail("E_BAD_OP");
                }
                if home_intents {
                    (
                        "nft_transfer_call",
                        serde_json::json!({"receiver_id": verifier(), "token_id": token_id, "msg": owner})
                            .to_string(),
                    )
                } else {
                    (
                        "nft_transfer",
                        serde_json::json!({"receiver_id": owner, "token_id": token_id}).to_string(),
                    )
                }
            }
        };
        Promise::new(contract.clone())
            .function_call(method, args.clone().into_bytes(), one, Gas::from_tgas(GAS_RESCUE))
            .detach();
        event(
            "owner_rescue",
            &format!("{{\"contract\":\"{contract}\",\"method\":\"{method}\",\"args\":{}}}", jstr(&args)),
        );
    }
}
