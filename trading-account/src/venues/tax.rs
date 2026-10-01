//! v1.6 taxed tokens on DEXes (V-TAX, measured on the real mainnet code + state, 2026-10-01).
//!
//! Some launchpad templates tax token TRANSFERS, and the tax is taken AFTER the DEX has checked
//! its `min_amount_out`, so a DEX buy delivers `min_out x (1 - tax)`. Measured with the DEX
//! account paying out by `ft_transfer` (what a swap payout is):
//! - nearly.trade taxed template (`*.nearlytrade.near`, `get_tax`): -100 bps (ribbit-2);
//! - NearPaid (`*.nearpaid.near`, `tax_info`): -100 bps (pkat-3e6b47);
//! - Nucleus Broker (`*.nucleusbroker.near`, `get_tax` = [bps, pair, ..]): -699 bps
//!   (nucleus-e27af8); its SELL side charges the sender +7% on top instead;
//! - Nearrr graduated tokens (`*.nearrr-fun.near`, `tax_state`): -149 bps for Tax 50 (50 + 100
//!   platform); `Standard` -50.
//!
//! A 24/7 order fire whose output is one of these tokens is GATED: the token's own tax view is
//! read on chain first (a view + `on_tax_gate`, inside the same execute_order transaction), and the
//! swap is sent only if its guaranteed output covers the stored floor after the tax:
//! `parsed min_out >= ceil(order.min_out x 10000 / (10000 - tax))`. Otherwise (or on an unknown
//! shape, a view result over 16 KiB (R2-06), or a tax above 11%) the fire settles as a failed swap: nothing moved, the order reopens
//! (`tax_gate_refused` event). Device `execute` is not gated (the client sizes the msg from the
//! tax; DR-1), and neither are sells: their NEAR output is untaxed and checked by the DEX.
//!
//! The rate applied is the token's buy-side rate on the DEX the fire uses: nearly.trade and nucleus
//! tax only transfers with their listed pair(s) (0 on another DEX, as the client's `readTokenTax`
//! scopes it, 7aa6f199); NearPaid and Nearrr tax every transfer.
use crate::*;
use near_sdk::serde_json;

/// Max total tax a gated fire accepts (the Nearrr bound; nearly / NearPaid / nucleus seen <= 7%).
pub const MAX_TAX_BPS: u128 = 1_100;
pub const GAS_TAX_VIEW: u64 = 5;
/// Static gas of `on_tax_gate` itself (parse + schedule), on top of what it forwards.
pub const GAS_TAX_GATE_CB: u64 = 8;
/// What a gate adds to an op's gas budget: the view, the gate callback, and two action fees.
pub const GATE_EXTRA_TGAS: u64 = GAS_TAX_VIEW + GAS_TAX_GATE_CB + 2 * GAS_PER_ACTION;

#[near(serializers = [json])]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaxKind {
    /// `*.nearlytrade.near`: `get_tax` -> {"tax":{"buy_bps","sell_bps","pairs",..}}; the untaxed
    /// templates have no `get_tax` (MethodNotFound): a failed view reads as 0 (R2-06: accepted
    /// risk, docs/venues-hooks.md "Taxed tokens").
    Nearly,
    /// `*.nearpaid.near`: `tax_info` -> {"buy_bps","sell_bps",..}; null = refused, a failed view = 0 (R2-06).
    NearPaid,
    /// `*.nucleusbroker.near`: `get_tax` -> [bps, pair, [[recipient, share]]].
    Nucleus,
    /// `*.nearrr-fun.near`: `tax_state` -> {"mode","buy_tax_bps",..} (venues/factory.rs); the
    /// untaxed first template has no `tax_state`: a failed view reads as 0 (R2-06: accepted risk).
    Nearrr,
}

/// Taxed-template factories (mainnet ids). A token is taxed-template when it is exactly one label
/// under one of them (only the factory can create such an account).
pub const TAXED_FACTORIES: [(&str, TaxKind); 4] = [
    ("nearlytrade.near", TaxKind::Nearly),
    ("nearpaid.near", TaxKind::NearPaid),
    ("nucleusbroker.near", TaxKind::Nucleus),
    ("nearrr-fun.near", TaxKind::Nearrr),
];

pub fn taxed_kind(token: &str) -> Option<TaxKind> {
    // any depth under the factory (as the client's readTokenTax): a deeper account can only be
    // made by a token, and is checked rather than trusted
    let t: AccountId = token.parse().ok()?;
    TAXED_FACTORIES.iter().find_map(|(f, k)| t.as_str().strip_suffix(f)?.ends_with('.').then_some(*k))
}

pub fn view_method(k: TaxKind) -> &'static str {
    match k {
        TaxKind::Nearly | TaxKind::Nucleus => "get_tax",
        TaxKind::NearPaid => "tax_info",
        TaxKind::Nearrr => "tax_state",
    }
}

/// The buy-side tax in bps on `dex` from the view result (`None` = the view failed). `None`
/// returned = refuse: unreadable, an unknown shape or mode, or the buy OR sell rate above
/// MAX_TAX_BPS (as the client's readTokenTax). Measured on the real code (venues_tax_probe):
/// every family takes the buy tax from the RECEIVER of the pool's payout (nucleus too: -699 bps;
/// its sells instead charge the sender on top), Nearrr `Standard` included (-50 bps on DCL).
pub fn tax_bps(k: TaxKind, view: Option<&[u8]>, dex: &str) -> Option<u128> {
    #[derive(near_sdk::serde::Deserialize)]
    #[serde(crate = "near_sdk::serde")]
    struct Rates {
        buy_bps: u16,
        sell_bps: u16,
    }
    #[derive(near_sdk::serde::Deserialize)]
    #[serde(crate = "near_sdk::serde")]
    struct NearlyRates {
        buy_bps: u16,
        sell_bps: u16,
        pairs: Vec<String>,
        #[serde(default)]
        exempt: Vec<String>,
    }
    #[derive(near_sdk::serde::Deserialize)]
    #[serde(crate = "near_sdk::serde")]
    struct NearlyTax {
        tax: Option<NearlyRates>,
    }
    let max = MAX_TAX_BPS;
    let (buy, sell) = match (k, view) {
        // a failed view receipt = 0 for every family (owner rule 2026-10-01, = the client): the
        // untaxed nearly (5qScjXG9, B6EjqsNJ) and Nearrr (GtS8LEn8) templates export no tax view.
        // A contract can't tell that from a panic / out of gas; the taxed templates' views can't
        // fail (bounded, immutable: docs/venues-hooks.md "Taxed tokens" R2-06, accepted risk)
        (_, None) => (0, 0),
        (TaxKind::Nearly, Some(b)) => {
            // `tax: null` = untaxed (as the client, 718dabfd)
            let Some(t) = serde_json::from_slice::<NearlyTax>(b).ok()?.tax else {
                return Some(0);
            };
            let on = t.pairs.iter().any(|p| p == dex) && !t.exempt.iter().any(|x| x == dex);
            (if on { u128::from(t.buy_bps) } else { 0 }, u128::from(t.sell_bps))
        }
        (TaxKind::NearPaid, Some(b)) => {
            let r = serde_json::from_slice::<Rates>(b).ok()?;
            (r.buy_bps.into(), r.sell_bps.into())
        }
        (TaxKind::Nucleus, Some(b)) => {
            let v: serde_json::Value = serde_json::from_slice(b).ok()?;
            let bps = u128::from(u16::try_from(v.get(0)?.as_u64()?).ok()?);
            (if v.get(1)?.as_str()? == dex { bps } else { 0 }, bps)
        }
        (TaxKind::Nearrr, Some(b)) => {
            #[derive(near_sdk::serde::Deserialize)]
            #[serde(crate = "near_sdk::serde")]
            struct St {
                mode: String,
                sell_tax_bps: u16,
            }
            let st = serde_json::from_slice::<St>(b).ok()?;
            let sell = match st.mode.as_str() {
                "Standard" => venues::factory::NEARRR_STANDARD_TAX_BPS,
                _ => u128::from(st.sell_tax_bps) + venues::factory::NEARRR_PLATFORM_TAX_BPS,
            };
            // the buy side (and an unknown mode -> None) as the curve path reads it
            (venues::factory::nearrr_tax_bps(b)?, sell)
        }
    };
    (buy <= max && sell <= max).then_some(buy)
}

/// ceil(floor x 10000 / (10000 - tax)): the least pre-tax output that delivers `floor`.
pub fn pre_tax_min(floor: u128, tax: u128) -> Option<u128> {
    if tax > MAX_TAX_BPS {
        return None;
    }
    let keep = 10_000 - tax;
    let q = crate::policy::mul_div(floor, 10_000, keep);
    // (floor x 10000) mod keep, without overflow
    let rem = (floor % keep) * 10_000 % keep;
    Some(if rem == 0 { q } else { q.saturating_add(1) })
}

/// A gated fire: the output token, its kind, the stored floor and the swap's guaranteed output.
#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq)]
pub struct Gate {
    pub token: AccountId,
    /// The DEX the fire swaps on (pair-scoped taxes).
    pub dex: String,
    pub kind: TaxKind,
    pub floor: U128,
    pub min_out: U128,
    /// A gated Chain's native outflow (leg 1's NEAR deposit), re-checked against the reserve
    /// before the Chain starts; 0 elsewhere (on_tax_gate re-checks its call's own deposit).
    #[serde(default)]
    pub native_out: U128,
}

/// For an order fire whose output `out` is a taxed-template token: its gate. None = not taxed.
pub fn gate_for(out: &str, dex: &str, floor: u128, min_out: u128) -> Option<Gate> {
    let kind = taxed_kind(out)?;
    Some(Gate {
        token: out.parse().ok()?,
        dex: dex.to_string(),
        kind,
        floor: U128(floor),
        min_out: U128(min_out),
        native_out: U128(0),
    })
}

/// Max tax-view result read (R2-06): a longer result is refused, never read as "no view".
pub const MAX_VIEW_LEN: usize = 16_384;

/// The view's outcome (R2-06): `Ok(Some)` = a result, `Ok(None)` = the receipt failed (method
/// missing, a panic or out of gas), `Err(None)` = a result over MAX_VIEW_LEN: refused, as `passes`
/// refuses an unreadable view.
pub fn read_view() -> Result<Option<Vec<u8>>, Option<u128>> {
    match env::promise_result_checked(0, MAX_VIEW_LEN) {
        Ok(b) => Ok(Some(b)),
        Err(near_sdk::PromiseError::Failed) => Ok(None),
        Err(_) => Err(None),
    }
}

/// The gate passes: the swap's guaranteed output still covers the floor after the tax.
/// `view` None = the view receipt failed: 0 (R2-06).
pub fn passes(g: &Gate, view: Option<&[u8]>) -> Result<u128, Option<u128>> {
    let tax = tax_bps(g.kind, view, &g.dex).ok_or(None)?;
    match pre_tax_min(g.floor.0, tax) {
        Some(need) if g.min_out.0 >= need => Ok(tax),
        _ => Err(Some(tax)),
    }
}

/// The swap call a gate forwards (what `run` would have scheduled).
#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq)]
pub struct GatedCall {
    pub receiver: AccountId,
    pub method: String,
    pub args: String,
    pub deposit: U128,
    pub gas: U64,
}

/// Schedules the gate's view, after `after` (the swap receiver's earlier batch, e.g. a NearDeposit
/// on wrap, so the forwarded swap can't overtake it). Returns the view promise.
pub fn schedule_view(g: &Gate, after: Option<near_sdk::PromiseIndex>) -> near_sdk::PromiseIndex {
    let (m, gas) = (view_method(g.kind), Gas::from_tgas(GAS_TAX_VIEW));
    match after {
        Some(i) => env::promise_then(i, g.token.clone(), m, b"{}", NearToken::from_yoctonear(0), gas),
        None => env::promise_create(g.token.clone(), m, b"{}", NearToken::from_yoctonear(0), gas),
    }
}

/// The callback `run` attaches to the view: (method, args, static TGas).
pub fn callback(g: &Gate, call: &GatedCall, settle_json: &str) -> (&'static str, String, u64) {
    let args = format!(
        "{{\"settle\":{},\"gate\":{},\"call\":{}}}",
        settle_json,
        serde_json::to_string(g).unwrap_or_else(|_| env::panic_str("E_JSON")),
        serde_json::to_string(call).unwrap_or_else(|_| env::panic_str("E_JSON"))
    );
    let fwd = call.gas.0 / TGAS;
    ("on_tax_gate", args, GAS_TAX_GATE_CB + fwd + GAS_CALLBACK + 2 * GAS_PER_ACTION)
}

fn refused(settle: &SettleArgs, g: &Gate, tax: Option<u128>) {
    env::log_str(&format!(
        "EVENT_JSON:{{\"standard\":\"nttrade\",\"version\":\"1\",\"event\":\"tax_gate_refused\",\"data\":{{\"client_order_id\":{},\"token\":\"{}\",\"tax_bps\":{},\"floor\":\"{}\",\"min_out\":\"{}\"}}}}",
        serde_json::to_string(&settle.client_order_id).unwrap_or_default(),
        g.token,
        tax.map_or("null".to_string(), |x| x.to_string()),
        g.floor.0,
        g.min_out.0
    ));
}

/// A gated Chain order fire: the output's tax view, then `on_tax_gate_chain` starts the Chain as
/// `run` would have (its own lock, views and callbacks). `start` = the Chain's start budget
/// (`TradingAccount::budgets`).
pub fn gate_chain(g: &Gate, c: crate::chain::Chain, start: u64, settle_json: &str, rid: &str) {
    let gas = start + crate::chain::GAS_CHAIN_VIEW + GAS_TAX_GATE_CB + 2 * GAS_PER_ACTION;
    let args = format!(
        "{{\"settle\":{},\"gate\":{},\"chain\":{},\"rid\":{}}}",
        settle_json,
        serde_json::to_string(g).unwrap_or_else(|_| env::panic_str("E_JSON")),
        serde_json::to_string(&c).unwrap_or_else(|_| env::panic_str("E_JSON")),
        serde_json::to_string(rid).unwrap_or_else(|_| env::panic_str("E_JSON"))
    );
    let v = schedule_view(g, None);
    env::promise_then(
        v,
        env::current_account_id(),
        "on_tax_gate_chain",
        args.as_bytes(),
        NearToken::from_yoctonear(0),
        Gas::from_tgas(gas),
    );
}

/// Budget of a gated Chain in `run`: what `gate_chain` adds on top of the Chain's own gas
/// (counted in check_chain's MAX_CHAIN_GAS for order fires with a taxed output).
pub const GATE_CHAIN_EXTRA_TGAS: u64 = GATE_EXTRA_TGAS;

/// A gated Chain order can always fire: V16-10 (`chain::check_via_venues`) already refuses the
/// heavy callback-chain venues (Kelytra, Nearrr) as legs at place_order, and every remaining leg
/// kind declares >= 20 TGas (a Shards sell 20 + GAS_SHARDS_Q_WITHDRAW 50), so the smallest gated
/// Chain is at most 70 + 20 + CHAIN_OVERHEAD 80 + 23 = 193 <= MAX_CHAIN_GAS 265
/// (chain/tests.rs `gated_chain_fire_budgets_the_gate`).
#[near]
impl TradingAccount {
    /// v1.6 (taxed tokens): step 2 of a gated Chain order fire. Pass: the Chain starts. Refuse: a
    /// failed swap (nothing moved, the order reopens), `tax_gate_refused`.
    #[private]
    pub fn on_tax_gate_chain(
        &mut self,
        settle: SettleArgs,
        gate: Gate,
        chain: crate::chain::Chain,
        rid: String,
    ) {
        let tax = match read_view().and_then(|v| passes(&gate, v.as_deref())) {
            Ok(t) => Some(t),
            Err(tax) => {
                refused(&settle, &gate, tax);
                return self.finish_settle(settle, true, 0, 0);
            }
        };
        // run reserved leg 1's NEAR, but a concurrent execute / withdraw may have spent it since:
        // dispatch_chain would then fail after the lock, leaving the order Pending (A1)
        let n = gate.native_out.0;
        if n > 1 && crate::policy::check_reserve(liquid_balance(), n).is_err() {
            refused(&settle, &gate, tax);
            return self.finish_settle(settle, true, 0, 0);
        }
        // R2-05: Q is locked only now (dispatch_chain); taken since the execute (another Chain, a
        // Nearrr buy of it) -> refused like the reserve race, never a panic that leaves it Pending
        if crate::chain::busy(chain.q.as_str()) {
            refused(&settle, &gate, tax);
            return self.finish_settle(settle, true, 0, 0);
        }
        let s = serde_json::to_string(&settle).unwrap_or_else(|_| env::panic_str("E_JSON"));
        self.dispatch_chain(chain, &s, &rid);
    }

    /// v1.6 (taxed tokens): step 2 of a gated order fire, after the output token's tax view. Pass:
    /// the swap exactly as `run` built it, then `on_swap_settled`. Refuse: a failed swap (nothing
    /// moved, spend back, the order reopens), with `tax_gate_refused`.
    #[private]
    pub fn on_tax_gate(&mut self, settle: SettleArgs, gate: Gate, call: GatedCall) {
        match read_view().and_then(|v| passes(&gate, v.as_deref())) {
            Err(tax) => {
                refused(&settle, &gate, tax);
                self.finish_settle(settle, true, 0, 0)
            }
            // a native deposit (Plach deposit_near) is re-checked against the reserve: run reserved
            // it, but a concurrent execute / withdraw may have spent it since
            Ok(_)
                if call.deposit.0 > 1
                    && crate::policy::check_reserve(liquid_balance(), call.deposit.0).is_err() =>
            {
                refused(&settle, &gate, None);
                self.finish_settle(settle, true, 0, 0)
            }
            // R2-05: the swap input leaves only now; locked since the execute (a Nearrr buy's
            // refund proof, a route's Q) -> refused, nothing moved
            Ok(_) if call.method == "ft_transfer_call" && crate::chain::busy(call.receiver.as_str()) => {
                refused(&settle, &gate, None);
                self.finish_settle(settle, true, 0, 0)
            }
            Ok(_) => {
                let idx = env::promise_batch_create(&call.receiver);
                env::promise_batch_action_function_call_weight(
                    idx,
                    &call.method,
                    call.args.as_bytes(),
                    NearToken::from_yoctonear(call.deposit.0),
                    Gas::from_gas(call.gas.0),
                    GasWeight(0),
                );
                let args = serde_json::to_string(&settle).unwrap_or_else(|_| env::panic_str("E_JSON"));
                env::promise_then(
                    idx,
                    env::current_account_id(),
                    "on_swap_settled",
                    args.as_bytes(),
                    NearToken::from_yoctonear(0),
                    Gas::from_tgas(GAS_CALLBACK),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_by_factory() {
        assert_eq!(taxed_kind("ribbit-2.nearlytrade.near"), Some(TaxKind::Nearly));
        assert_eq!(taxed_kind("pkat-3e6b47.nearpaid.near"), Some(TaxKind::NearPaid));
        assert_eq!(taxed_kind("nucleus-e27af8.nucleusbroker.near"), Some(TaxKind::Nucleus));
        assert_eq!(taxed_kind("jensen.nearrr-fun.near"), Some(TaxKind::Nearrr));
        // any depth (checked, as the client does)
        assert_eq!(taxed_kind("a.b.nearlytrade.near"), Some(TaxKind::Nearly));
        assert_eq!(taxed_kind("xnearlytrade.near"), None);
        assert_eq!(taxed_kind("nearlytrade.near"), None);
        assert_eq!(taxed_kind("wrap.near"), None);
        assert_eq!(taxed_kind("not an id"), None);
    }

    const D: &str = "dclv2.ref-labs.near";

    #[test]
    fn pair_scoped_rates() {
        let nearly = br#"{"tax":{"buy_bps":100,"sell_bps":100,"pairs":["dclv2.ref-labs.near"]}}"#;
        assert_eq!(tax_bps(TaxKind::Nearly, Some(nearly), "v2.ref-finance.near"), Some(0));
        let nuc = br#"[700,"dclv2.ref-labs.near",[]]"#;
        assert_eq!(tax_bps(TaxKind::Nucleus, Some(nuc), "v2.ref-finance.near"), Some(0));
        let paid = br#"{"buy_bps":100,"sell_bps":100}"#;
        assert_eq!(tax_bps(TaxKind::NearPaid, Some(paid), "v2.ref-finance.near"), Some(100));
        // an exempt DEX gets no tax (as the client's taxApplies)
        let ex = br#"{"tax":{"buy_bps":100,"sell_bps":100,"pairs":["dclv2.ref-labs.near"],"exempt":["dclv2.ref-labs.near"]}}"#;
        assert_eq!(tax_bps(TaxKind::Nearly, Some(ex), D), Some(0));
    }

    #[test]
    fn either_side_above_the_max_is_refused() {
        let nearly = br#"{"tax":{"buy_bps":100,"sell_bps":1200,"pairs":["x.near"]}}"#;
        assert_eq!(tax_bps(TaxKind::Nearly, Some(nearly), D), None);
        assert_eq!(tax_bps(TaxKind::NearPaid, Some(br#"{"buy_bps":0,"sell_bps":1101}"#), D), None);
        let nrr = br#"{"mode":"Tax","buy_tax_bps":100,"sell_tax_bps":1001}"#;
        assert_eq!(tax_bps(TaxKind::Nearrr, Some(nrr), D), None);
        let nrr = br#"{"mode":"Tax","buy_tax_bps":100,"sell_tax_bps":1000}"#;
        assert_eq!(tax_bps(TaxKind::Nearrr, Some(nrr), D), Some(200));
        // Standard: 0.5% on DEX transfers too (measured: bean-ilgt pool -> account -49 bps)
        let std = br#"{"mode":"Standard","buy_tax_bps":0,"sell_tax_bps":0}"#;
        assert_eq!(tax_bps(TaxKind::Nearrr, Some(std), D), Some(50));
    }

    #[test]
    fn rates_from_real_views() {
        // live mainnet view results, 2026-10-01
        let nearly = br#"{"tax":{"buy_bps":100,"sell_bps":100,"pairs":["dclv2.ref-labs.near"],"admin":"nearlytrade.near","exempt":["lock2.nearlytrade.near","feeswap.near"]},"pending":"0"}"#;
        assert_eq!(tax_bps(TaxKind::Nearly, Some(nearly), D), Some(100));
        assert_eq!(tax_bps(TaxKind::Nearly, None, D), Some(0));
        assert_eq!(tax_bps(TaxKind::Nearly, Some(br#"{"tax":null}"#), D), Some(0));
        let paid = br#"{"buy_bps":100,"sell_bps":100,"burn_bps":0,"creator_bps":10000,"holders_bps":0,"pending_creator":"1","pending_holders":"0","burned":"0"}"#;
        assert_eq!(tax_bps(TaxKind::NearPaid, Some(paid), D), Some(100));
        assert_eq!(tax_bps(TaxKind::NearPaid, Some(b"null"), D), None);
        assert_eq!(tax_bps(TaxKind::NearPaid, None, D), Some(0)); // R2-06: a failed view = 0
        let nuc = br#"[700,"dclv2.ref-labs.near",[["6b70",10000]]]"#;
        assert_eq!(tax_bps(TaxKind::Nucleus, Some(nuc), D), Some(700));
        assert_eq!(tax_bps(TaxKind::Nucleus, Some(br#"[1200,"dclv2.ref-labs.near",[]]"#), D), None);
        assert_eq!(tax_bps(TaxKind::Nucleus, None, D), Some(0));
        let nrr = br#"{"mode":"Tax","buy_tax_bps":50,"sell_tax_bps":50}"#;
        assert_eq!(tax_bps(TaxKind::Nearrr, Some(nrr), D), Some(150));
        assert_eq!(
            tax_bps(TaxKind::Nearrr, Some(br#"{"mode":"Weird","buy_tax_bps":0,"sell_tax_bps":0}"#), D),
            None
        );
        assert_eq!(tax_bps(TaxKind::Nearrr, None, D), Some(0));
    }

    #[test]
    fn pre_tax_min_exact_and_ceil() {
        assert_eq!(pre_tax_min(9_900, 100), Some(10_000));
        assert_eq!(pre_tax_min(9_901, 100), Some(10_002)); // 10001.0101.. -> 10002
        assert_eq!(pre_tax_min(1_000, 0), Some(1_000));
        assert_eq!(pre_tax_min(9_300, 700), Some(10_000));
        assert_eq!(pre_tax_min(1, 1_101), None);
        let big = u128::MAX / 3;
        let m = pre_tax_min(big, 1_100).unwrap();
        assert!(crate::policy::mul_div(m, 8_900, 10_000) >= big);
    }

    #[test]
    fn gate_rule() {
        let g = gate_for("ribbit-2.nearlytrade.near", D, 9_900, 10_000).unwrap();
        let v = br#"{"tax":{"buy_bps":100,"sell_bps":100,"pairs":["dclv2.ref-labs.near"]}}"#;
        assert_eq!(passes(&g, Some(v)), Ok(100));
        let g2 = Gate { min_out: U128(9_999), ..g.clone() };
        assert_eq!(passes(&g2, Some(v)), Err(Some(100)));
        // a failed view (the untaxed nearly templates have no get_tax): the floor itself suffices
        let g3 = Gate { min_out: U128(9_900), ..g };
        assert_eq!(passes(&g3, None), Ok(0));
        assert!(gate_for("wrap.near", D, 1, 1).is_none());
        let n = gate_for("pkat-3e6b47.nearpaid.near", D, 100, 1_000).unwrap();
        assert_eq!(passes(&n, None), Ok(0));
    }

    /// One definition with the client: the recorded views of packages/trade/fixtures/token-tax/
    /// mainnet.json (B's readTokenTax fixture) give, per token and DEX, the buy bps of the client's
    /// model (718dabfd): taxApplies(dex) ? buyBps : 0. Skipped outside the monorepo (the public
    /// contracts repo has no packages/).
    #[test]
    fn same_rates_as_the_client_fixture() {
        let path =
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../packages/trade/fixtures/token-tax/mainnet.json");
        let Ok(raw) = std::fs::read(path) else {
            eprintln!("skipped: {path} not present");
            return;
        };
        let f: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        let views = f["views"].as_object().unwrap();
        let view_of = |token: &str, m: &str| {
            let k = serde_json::to_string(&serde_json::json!([token, m, {}])).unwrap();
            views.get(&k).map(|v| serde_json::to_vec(v).unwrap())
        };
        let (dcl, classic) = ("dclv2.ref-labs.near", "v2.ref-finance.near");
        // (token, buy bps on DCL, on classic): the client model's answer for the same views
        let want = [
            ("test.nearrr-fun.near", 0, 0), // GtS8LEn8: no tax_state (a failed view)
            ("ribbit-2.nearlytrade.near", 100, 0),
            ("aros.nearlytrade.near", 100, 0),
            ("pkat-3e6b47.nearpaid.near", 100, 100),
            ("nucleus-e27af8.nucleusbroker.near", 700, 0),
            ("jensen-i1vg.nearrr-fun.near", 550, 550),
            ("arcova-m6ez.nearrr-fun.near", 200, 200),
        ];
        let accounts = f["accounts"].as_object().unwrap();
        assert_eq!(accounts.len(), want.len(), "a fixture token without an expectation here");
        for (t, d, c) in want {
            assert!(accounts.contains_key(t), "{t}");
            let k = taxed_kind(t).unwrap_or_else(|| panic!("{t} not recognised"));
            let v = view_of(t, view_method(k));
            assert_eq!(tax_bps(k, v.as_deref(), dcl), Some(d), "{t} on DCL");
            assert_eq!(tax_bps(k, v.as_deref(), classic), Some(c), "{t} on classic");
        }
    }

    fn view_ctx(r: near_sdk::PromiseResult) {
        near_sdk::testing_env!(
            near_sdk::test_utils::VMContextBuilder::new().build(),
            near_sdk::test_vm_config(),
            near_sdk::RuntimeFeesConfig::test(),
            Default::default(),
            vec![r]
        );
    }

    /// What `on_tax_gate` / `on_tax_gate_chain` decide for a view outcome `r` on gate `g`.
    fn gate_on(r: near_sdk::PromiseResult, g: &Gate) -> Result<u128, Option<u128>> {
        view_ctx(r);
        read_view().and_then(|v| passes(g, v.as_deref()))
    }

    fn gate(token: &str, kind: TaxKind, min_out: u128) -> Gate {
        Gate {
            token: token.parse().unwrap(),
            dex: D.into(),
            kind,
            floor: U128(1_000),
            min_out: U128(min_out),
            native_out: U128(0),
        }
    }

    /// A 10% nearly view (`exempt` padded with `n` accounts).
    fn nearly_view(n: usize) -> Vec<u8> {
        let exempt: Vec<String> = (0..n).map(|i| format!("exempt-account-number-{i:04}.near")).collect();
        serde_json::json!({"tax": {"buy_bps": 1000, "sell_bps": 1000, "pairs": [D], "admin": "nearlytrade.near",
            "exempt": exempt}, "pending": "0"})
        .to_string()
        .into_bytes()
    }

    use near_sdk::PromiseResult as R;

    /// R2-06 error class 1: a result over MAX_VIEW_LEN (TooLong) is refused, never "no view".
    #[test]
    fn r2_06_oversize_view_is_refused() {
        let long = nearly_view(500);
        assert!(long.len() > MAX_VIEW_LEN);
        assert_eq!(
            gate_on(R::Successful(long), &gate("ribbit-2.nearlytrade.near", TaxKind::Nearly, 10_000)),
            Err(None)
        );
        // the bound itself: MAX_VIEW_LEN bytes are read, one more is refused (same Nearrr view,
        // padded with trailing JSON whitespace)
        let nrr = gate("jensen.nearrr-fun.near", TaxKind::Nearrr, 10_000);
        let mut v = br#"{"mode":"Tax","buy_tax_bps":50,"sell_tax_bps":50}"#.to_vec();
        v.resize(MAX_VIEW_LEN, b' ');
        assert_eq!(gate_on(R::Successful(v.clone()), &nrr), Ok(150));
        v.push(b' ');
        assert_eq!(gate_on(R::Successful(v), &nrr), Err(None));
    }

    /// R2-06 error class 2: an unparsable result is refused.
    #[test]
    fn r2_06_unparsable_view_is_refused() {
        let nearly = gate("ribbit-2.nearlytrade.near", TaxKind::Nearly, 10_000);
        let nearrr = gate("jensen.nearrr-fun.near", TaxKind::Nearrr, 10_000);
        assert_eq!(gate_on(R::Successful(b"{\"tax\":7}".to_vec()), &nearly), Err(None));
        assert_eq!(gate_on(R::Successful(b"not json".to_vec()), &nearly), Err(None));
        assert_eq!(gate_on(R::Successful(Vec::new()), &nearrr), Err(None));
        assert_eq!(gate_on(R::Successful(b"not json".to_vec()), &nearrr), Err(None));
        assert_eq!(
            gate_on(
                R::Successful(b"not json".to_vec()),
                &gate("test.nearrr-fun.near", TaxKind::Nearrr, 10_000)
            ),
            Err(None)
        );
    }

    /// R2-06 error class 3: a failed view receipt (the contract gets the same Failed for a missing
    /// method, a panic and out of gas) reads as 0 for every token of every family: the untaxed
    /// templates have no tax view (owner rule, = the client; the taxed templates can't make their
    /// view fail: docs/venues-hooks.md "Taxed tokens" R2-06, accepted risk).
    #[test]
    fn r2_06_failed_view_reads_0() {
        for (t, k) in [
            ("ribbit-2.nearlytrade.near", TaxKind::Nearly),
            ("aaalex.nearlytrade.near", TaxKind::Nearly),
            ("any-new-launch.nearlytrade.near", TaxKind::Nearly),
            ("jensen.nearrr-fun.near", TaxKind::Nearrr),
            ("test.nearrr-fun.near", TaxKind::Nearrr),
            ("pkat-3e6b47.nearpaid.near", TaxKind::NearPaid),
            ("nucleus-e27af8.nucleusbroker.near", TaxKind::Nucleus),
        ] {
            assert_eq!(gate_on(R::Failed, &gate(t, k, 1_000)), Ok(0), "{t}");
            // 0 tax: the floor is the least the swap may guarantee
            assert_eq!(gate_on(R::Failed, &gate(t, k, 999)), Err(Some(0)), "{t}");
        }
    }

    /// R2-06 error class 4: a valid view is applied, including one between the old 4 KiB limit and
    /// 16 KiB (the review's PoC view: 10% read, pre-tax min_out refused, ceil passes).
    #[test]
    fn r2_06_valid_tax_view_is_applied() {
        let mid = nearly_view(120);
        assert!(mid.len() > 4_096 && mid.len() <= MAX_VIEW_LEN);
        let need = pre_tax_min(1_000, 1_000).unwrap(); // 1112
        let t = "ribbit-2.nearlytrade.near";
        assert_eq!(gate_on(R::Successful(mid.clone()), &gate(t, TaxKind::Nearly, 1_000)), Err(Some(1_000)));
        assert_eq!(
            gate_on(R::Successful(mid.clone()), &gate(t, TaxKind::Nearly, need - 1)),
            Err(Some(1_000))
        );
        assert_eq!(gate_on(R::Successful(mid), &gate(t, TaxKind::Nearly, need)), Ok(1_000));
        let nrr = br#"{"mode":"Tax","buy_tax_bps":50,"sell_tax_bps":50}"#.to_vec();
        assert_eq!(
            gate_on(R::Successful(nrr), &gate("jensen.nearrr-fun.near", TaxKind::Nearrr, 1_016)),
            Ok(150)
        );
    }

    /// R2-06 error class 5: a tax over 11% (buy or sell) is refused, whatever min_out covers.
    #[test]
    fn r2_06_tax_over_11pct_is_refused() {
        let v = |buy: u16, sell: u16| {
            serde_json::json!({"tax": {"buy_bps": buy, "sell_bps": sell, "pairs": [D]}})
                .to_string()
                .into_bytes()
        };
        let rich = gate("ribbit-2.nearlytrade.near", TaxKind::Nearly, 1_000_000);
        assert_eq!(gate_on(R::Successful(v(1_100, 1_100)), &rich), Ok(1_100));
        assert_eq!(gate_on(R::Successful(v(1_101, 0)), &rich), Err(None));
        assert_eq!(gate_on(R::Successful(v(0, 1_101)), &rich), Err(None));
        let nrr = br#"{"mode":"Tax","buy_tax_bps":1001,"sell_tax_bps":0}"#.to_vec();
        assert_eq!(
            gate_on(R::Successful(nrr), &gate("jensen.nearrr-fun.near", TaxKind::Nearrr, 1_000_000)),
            Err(None)
        );
    }
}
