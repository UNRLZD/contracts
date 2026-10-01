//! v1.6 routes (docs/routing-v16-design.md Part C): `Op::Chain` (two on-chain legs, one
//! signature), `Op::IntentsSwap` (NEAR -> Q through a 1Click quote, then a continuation), the
//! continuation fired through `execute_order` on reserved ids >= 2^63, per-route Q accounting and
//! the per-Q in-flight lock.
//!
//! Invariants kept (C.0):
//! - no new device / relayer method names: new `Op` variants inside `execute`, continuations
//!   inside `execute_order`;
//! - `Chain` / `IntentsSwap` are the one swap and the last op;
//! - `Order` borsh unchanged: a stored order's Chain legs live under their own key (`ov` + id);
//! - fee only on the NEAR leg; min_out always on the final token (+ a mid bound on Q);
//! - owner decision 2026-10-01: an order / continuation fire can NEVER fund a 1Click quote.
//!   `IntentsSwap` and a `Chain` whose leg 2 is `IntentsFund` are refused in `execute_order`
//!   (E_ORDER_OPS); a continuation may only `IntentsPull` (+ one swap bounded by the stored
//!   `ContTerms`).
//!
//! Not atomic across contracts: a failed leg 2 leaves Q in the wallet, recorded per route
//! (`route_held`), never spent by another route.
use crate::msg::{self, DexKind, Swap};
use crate::venues::{self, CurveTrade};
use crate::{Dex, Op};
use near_sdk::json_types::{U128, U64};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{near, serde_json, AccountId};

pub mod exec;
pub mod quote;
pub mod store;
#[cfg(test)]
mod tests;

pub use store::*;

pub const E_CHAIN_SAME_DEX: &str = "E_CHAIN_SAME_DEX";
pub const E_CHAIN_LEG2_AMOUNT: &str = "E_CHAIN_LEG2_AMOUNT";
pub const E_CHAIN_OVERLAP: &str = "E_CHAIN_OVERLAP";
pub const E_CHAIN_GAS: &str = "E_CHAIN_GAS";
pub const E_CHAIN_LEG: &str = "E_CHAIN_LEG";
pub const E_CHAIN_MID: &str = "E_CHAIN_MID";
pub const E_CHAIN_MIN: &str = "E_CHAIN_MIN";
pub const E_Q_BUSY: &str = "E_Q_BUSY";
pub const E_ORDER_OPS: &str = "E_ORDER_OPS";
pub const E_ORDER_MISMATCH: &str = "E_ORDER_MISMATCH";
/// V16-01: a Chain order fire outside the user's stored leg-1 bounds.
pub const E_ORDER_MID: &str = "E_ORDER_MID";

pub const TGAS: u64 = 1_000_000_000_000;
/// Gas of a `q.ft_balance_of(self)` view.
pub const GAS_CHAIN_VIEW: u64 = 5;
/// Static gas of each chain callback (on_chain_start / on_chain_leg1 / on_chain_mid).
pub const GAS_CHAIN_CB: u64 = 10;
/// Per scheduled function-call action (send + exec fees), as `GAS_PER_ACTION`.
pub const GAS_ACTION: u64 = 5;
/// Everything a Chain attaches besides its two legs: 2 views, 3 step callbacks, the settle
/// callback, 6 action fees. Measured in the sandbox (venues_chain.rs `chain_gas_probe`).
pub const CHAIN_OVERHEAD_TGAS: u64 = 2 * GAS_CHAIN_VIEW + 3 * GAS_CHAIN_CB + GAS_CHAIN_CB + 6 * GAS_ACTION;
/// Funding a 1Click deposit address (wrap.ft_transfer_call to the verifier) + its callback.
pub const GAS_FUND: u64 = 50 + GAS_CHAIN_CB + GAS_ACTION;
/// `withdraw_quote{}` of a Q-paired Shards token (ft_transfer + resolve_ft_payout). Measured on the
/// real 0.2.0 template (venues_chain.rs `shards_*_quoted_chains`): withdraw 2.4 + Q transfer 1.7
/// TGas; `sell_exact_in` 5.9 TGas; a Q-paid buy (ft_on_transfer) 3.0 TGas.
pub const GAS_SHARDS_Q_WITHDRAW: u64 = 50;
/// Max total gas of a Chain op (legs + overhead): prepaid 300 minus execute's own overhead (15),
/// the swap-callback budget and the op's action fee.
pub const MAX_CHAIN_GAS: u64 = 300 - 15 - 10 - 2 * GAS_ACTION;

/// A leg: exactly one existing swap op body (routing C.1).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(crate = "near_sdk::serde", deny_unknown_fields)]
pub enum ChainLeg {
    FtTransferCall {
        token: AccountId,
        receiver_id: AccountId,
        amount: U128,
        msg: String,
        gas: U64,
    },
    CurveBuy(CurveTrade),
    CurveSell(CurveTrade),
    /// Leg 1 only: sell a Shards token for its quote asset (= the chain's `q`, e.g. SHARDS, ZEC,
    /// an Ondo stock): ONE batch to the token, `sell_exact_in{amount, min_amount_out: min_out}` +
    /// `withdraw_quote{}` (no recipient: the token pays its caller, this account, by ft_transfer).
    /// A refused sell panics and reverts the batch. `gas` = the sell's; the withdraw gets
    /// GAS_SHARDS_Q_WITHDRAW.
    ShardsSell {
        token: AccountId,
        amount: U128,
        min_out: U128,
        gas: U64,
    },
    /// Leg 2 only: buy a Shards token with the chain's `q`: `q.ft_transfer_call{receiver_id: token,
    /// amount: credited, msg: BuyMessage}` (msg built by the contract; the token refuses any payer
    /// but its quote asset and refunds in full). Op amount "0".
    ShardsBuy {
        token: AccountId,
        amount: U128,
        min_out: U128,
        gas: U64,
    },
    /// Leg 1 only: Plach buy with native NEAR.
    PlachDepositNear {
        dex: AccountId,
        amount: U128,
        msg: String,
        gas: U64,
    },
    /// Leg 2 only (a sell to NEAR through 1Click, FLEX_INPUT): funds the quote with `credited` Q.
    IntentsFund {
        signed_quote: String,
        signature: String,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(crate = "near_sdk::serde", deny_unknown_fields)]
pub struct Chain {
    pub leg1: ChainLeg,
    pub leg2: ChainLeg,
    pub q: AccountId,
    pub min_mid: U128,
    pub max_mid: U128,
    pub min_final: U128,
}

/// What a buy's continuation may do (C.2.1).
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ContTerms {
    pub token_out: AccountId,
    pub dexes: Vec<AccountId>,
    pub min_final: U128,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(crate = "near_sdk::serde", deny_unknown_fields)]
pub struct IntentsSwap {
    pub signed_quote: String,
    pub signature: String,
    pub q: AccountId,
    pub cont: ContTerms,
    pub cont_deadline_ns: U64,
}

/// Stored Chain legs of a 24/7 order (`ov` + id). Order.min_out is the floor on min_final.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct OrderVia {
    pub q: AccountId,
    pub leg1_dex: AccountId,
    pub leg2_dex: AccountId,
    /// V16-01: the user's leg-1 bound for the whole `amount_in` (Q units). Every fire needs
    /// `min_mid >=` this (and so a leg-1 msg bound `>=` it): leg 1 never fills below the user's
    /// price, whoever fires.
    pub min_mid: U128,
    /// V16-01: the most Q a fire may hand to leg 2 (`max_mid <=` this).
    pub max_mid: U128,
}

/// A parsed leg.
#[derive(Clone, Debug, PartialEq)]
pub struct LegInfo {
    /// The contract the leg trades at (receiver / venue / Plach dex).
    pub dex: AccountId,
    pub token_in: String,
    pub out: String,
    pub out_is_near: bool,
    pub min_out: u128,
    pub amount: u128,
    pub gas: u64,
    /// Pools / hop tokens (overlap rule 5).
    pub pools: Vec<String>,
    pub hop_tokens: Vec<String>,
    /// NEAR (native or wNEAR) input.
    pub near_in: bool,
    /// Settle proof of this leg as a swap ("wrap" / "token" / "plach_near" / "curve_near" / "curve_out").
    pub proof: &'static str,
    /// V16-04: native NEAR the leg attaches (the venue plan's, 1 yocto for ft_transfer_call legs).
    pub native_out: u128,
    /// V16-04/09: a payable curve buy's settle mode (`near_in` / `near_in_full`): its refund is a
    /// measured NEAR delta (net of the gas allowance). None = the leg reports what it used.
    pub measured: Option<&'static str>,
    /// AUDIT-S1: NEAR the leg's plan spends besides its counted input (an Aidols-family venue
    /// `storage_deposit`, Vista's buy extra): counted as spend, as a single-hop curve op counts it.
    pub extra_spend: u128,
}

pub struct Env<'a> {
    pub me: &'a AccountId,
    pub wrap: &'a AccountId,
    pub allow: &'a [Dex],
    pub referrer: &'a AccountId,
    pub fee_bps: u16,
    pub now_ns: u64,
}

fn dex_kind(allow: &[Dex], id: &AccountId) -> Option<DexKind> {
    allow
        .iter()
        .find(|d| &d.id == id && !venues::is_factory_entry(d.kind))
        .map(|d| d.kind)
        .or_else(|| venues::token_curve_kind(allow, id))
}

fn ctx<'a>(e: &'a Env) -> venues::Ctx<'a> {
    venues::Ctx { me: e.me, wrap: e.wrap, fee_bps: e.fee_bps, now_ns: e.now_ns, order_min_out: None }
}

/// Pools and hop tokens of a Rhea classic / DCL msg (for rule 5), best effort on other kinds.
fn hops(kind: DexKind, m: &str) -> (Vec<String>, Vec<String>) {
    let v: serde_json::Value = serde_json::from_str(m).unwrap_or_default();
    let mut pools = vec![];
    let mut toks = vec![];
    match kind {
        DexKind::RheaClassic => {
            for a in v["actions"].as_array().into_iter().flatten() {
                pools.push(format!("classic:{}", a["pool_id"]));
                for k in ["token_in", "token_out"] {
                    if let Some(t) = a[k].as_str() {
                        toks.push(t.to_string());
                    }
                }
            }
        }
        DexKind::RheaDcl => {
            for p in v["Swap"]["pool_ids"].as_array().into_iter().flatten() {
                if let Some(p) = p.as_str() {
                    pools.push(format!("dcl:{p}"));
                    let mut it = p.split('|');
                    for t in [it.next(), it.next()].into_iter().flatten() {
                        toks.push(t.to_string());
                    }
                }
            }
        }
        _ => {}
    }
    (pools, toks)
}

/// Gas a planned curve leg attaches when scheduled (`exec::leg_promise`), as `run` budgets a
/// curve op: the plan's gas (the trade call(s) at the op's gas plus any registration the venue
/// plans before them, e.g. an Aidols-family `storage_deposit`) and one action fee per planned
/// call beyond the first. Never below the op's `declared` gas.
pub fn curve_leg_gas(p: &venues::Plan, declared: u64) -> u64 {
    p.gas.saturating_add((p.calls.len() as u64).saturating_sub(1) * GAS_ACTION * TGAS).max(declared)
}

/// Parses a leg. `leg2`: its amount is set by the contract, so the op's amount must be "0" and
/// no input amount may be fixed inside the msg (E_CHAIN_LEG2_AMOUNT).
pub fn leg_info(e: &Env, leg: &ChainLeg, leg2: bool) -> Result<LegInfo, &'static str> {
    match leg {
        ChainLeg::FtTransferCall { token, receiver_id, amount, msg: m, gas } => {
            if token == e.me || receiver_id == e.me {
                return Err("E_BAD_OP");
            }
            if leg2 != (amount.0 == 0) {
                return Err(if leg2 { E_CHAIN_LEG2_AMOUNT } else { "E_BAD_OP" });
            }
            let kind = dex_kind(e.allow, receiver_id).ok_or("E_BAD_DEX")?;
            let s: Swap = match kind {
                DexKind::RheaClassic | DexKind::RheaDcl | DexKind::Plach => msg::parse(
                    kind,
                    m,
                    &msg::Ctx { self_id: e.me, wrap: e.wrap, token_in: token, referrer: e.referrer },
                )?,
                DexKind::ShardsToken => return Err("E_BAD_DEX"),
                _ => crate::msg_venues::parse(
                    kind,
                    m,
                    &crate::msg_venues::VCtx {
                        self_id: e.me,
                        wrap: e.wrap,
                        token_in: token,
                        receiver: receiver_id,
                        referrer: e.referrer,
                    },
                )?,
            };
            if leg2 {
                let v: serde_json::Value = serde_json::from_str(m).unwrap_or_default();
                let fixed = match kind {
                    DexKind::RheaClassic => !v["actions"][0]["amount_in"].is_null(),
                    // Plach operations fix or sweep inner balances: never a leg 2
                    DexKind::Plach => true,
                    _ => false,
                };
                if fixed {
                    return Err(E_CHAIN_LEG2_AMOUNT);
                }
            }
            let max = match kind {
                DexKind::RheaClassic => crate::MAX_SWAP_GAS_RHEA,
                DexKind::RheaDcl => crate::MAX_SWAP_GAS_DCL,
                DexKind::Plach => crate::MAX_SWAP_GAS_PLACH,
                _ => venues::MAX_CURVE_GAS,
            };
            if gas.0 > max * TGAS || gas.0 < crate::MIN_SWAP_GAS * TGAS {
                return Err("E_GAS");
            }
            let (pools, hop_tokens) = hops(kind, m);
            let near_in = token == e.wrap;
            Ok(LegInfo {
                dex: receiver_id.clone(),
                token_in: token.to_string(),
                out: s.out,
                out_is_near: s.out_is_near,
                min_out: s.min_out,
                amount: amount.0,
                gas: gas.0,
                pools,
                hop_tokens,
                near_in,
                proof: if near_in { "wrap" } else { "token" },
                native_out: 1,
                measured: None,
                extra_spend: 0,
            })
        }
        ChainLeg::CurveBuy(t) | ChainLeg::CurveSell(t) => {
            let buy = matches!(leg, ChainLeg::CurveBuy(_));
            if leg2 != (t.amount.0 == 0) {
                return Err(if leg2 { E_CHAIN_LEG2_AMOUNT } else { "E_BAD_OP" });
            }
            // leg 2 is planned with a placeholder amount; re-planned with `credited` at dispatch
            let probe = CurveTrade { amount: U128(if leg2 { 1 } else { t.amount.0 }), ..t.clone() };
            let p = venues::plan(e.allow, buy, &probe, &ctx(e))?;
            // V16-10: a venue whose trade runs in its own callback chain (Kelytra round trip,
            // Nearrr tax view -> buy) would only send its first step inside a Chain
            if matches!(p.settle, venues::Settle::Kelytra { .. } | venues::Settle::NearrrTax { .. }) {
                return Err(E_CHAIN_LEG);
            }
            // V16-04: the NEAR leg and its measurement come from the normalised plan (`quote:
            // "wrap.near"` and `None` plan the same), never from re-matching the op's fields
            let near_in = buy
                && matches!(
                    p.settle,
                    venues::Settle::Wrap | venues::Settle::NearIn | venues::Settle::NearInFull
                );
            let measured = match p.settle {
                venues::Settle::NearIn | venues::Settle::NearInFull => Some(p.settle.mode()),
                _ => None,
            };
            Ok(LegInfo {
                dex: p.order_dex.clone(),
                token_in: p.token_in.to_string(),
                out: p.swap.out.clone(),
                out_is_near: p.swap.out_is_near,
                min_out: p.swap.min_out,
                amount: t.amount.0,
                // the whole plan, not only the trade call (an Aidols-family registration)
                gas: curve_leg_gas(&p, t.gas.0),
                pools: vec![],
                hop_tokens: vec![],
                near_in,
                proof: p.settle.proof(),
                native_out: p.native_out,
                measured,
                extra_spend: p.spend.saturating_sub(p.counted),
            })
        }
        ChainLeg::PlachDepositNear { dex, amount, msg: m, gas } => {
            if leg2 {
                return Err(E_CHAIN_LEG);
            }
            if dex_kind(e.allow, dex) != Some(DexKind::Plach) {
                return Err("E_BAD_DEX");
            }
            if amount.0 == 0 {
                return Err("E_BAD_OP");
            }
            let s = msg::parse_plach_near(m, e.me, e.wrap, e.referrer)?;
            if gas.0 > crate::MAX_SWAP_GAS_PLACH * TGAS || gas.0 < crate::MIN_SWAP_GAS * TGAS {
                return Err("E_GAS");
            }
            Ok(LegInfo {
                dex: dex.clone(),
                token_in: e.wrap.to_string(),
                out: s.out,
                out_is_near: s.out_is_near,
                min_out: s.min_out,
                amount: amount.0,
                gas: gas.0,
                pools: vec![],
                hop_tokens: vec![],
                near_in: true,
                proof: "plach_near",
                native_out: amount.0,
                measured: None,
                extra_spend: 0,
            })
        }
        ChainLeg::ShardsSell { token, amount, min_out, gas }
        | ChainLeg::ShardsBuy { token, amount, min_out, gas } => {
            let sell = matches!(leg, ChainLeg::ShardsSell { .. });
            if sell == leg2 {
                return Err(E_CHAIN_LEG);
            }
            if !e.allow.iter().any(|d| d.kind == DexKind::ShardsToken && msg::shards_token_of(&d.id, token)) {
                return Err("E_BAD_DEX");
            }
            if leg2 && amount.0 != 0 {
                return Err(E_CHAIN_LEG2_AMOUNT);
            }
            if (!leg2 && amount.0 == 0) || min_out.0 == 0 {
                return Err("E_BAD_OP");
            }
            let max = if sell { crate::MAX_SWAP_GAS_SHARDS_SELL } else { crate::MAX_SWAP_GAS_SHARDS_BUY };
            if gas.0 > max * TGAS || gas.0 < crate::MIN_SWAP_GAS * TGAS {
                return Err("E_GAS");
            }
            // the Q side is the chain's q (set by check_chain: the token's quote asset is not
            // readable on chain; a token paid in anything else delivers no Q delta -> held)
            Ok(LegInfo {
                dex: token.clone(),
                token_in: if sell { token.to_string() } else { String::new() },
                out: if sell { String::new() } else { token.to_string() },
                out_is_near: false,
                min_out: min_out.0,
                amount: amount.0,
                gas: gas.0 + if sell { GAS_SHARDS_Q_WITHDRAW * TGAS } else { 0 },
                pools: vec![],
                hop_tokens: vec![],
                near_in: false,
                proof: "token",
                native_out: 1,
                measured: None,
                extra_spend: 0,
            })
        }
        ChainLeg::IntentsFund { .. } => Err(E_CHAIN_LEG),
    }
}

/// A validated Chain.
#[derive(Clone, Debug, PartialEq)]
pub struct ChainPlan {
    pub l1: LegInfo,
    /// None when leg 2 is IntentsFund (then `fund` is set).
    pub l2: Option<LegInfo>,
    pub fund: Option<quote::Checked>,
    pub token_in: String,
    pub token_out: String,
    /// NEAR-leg accounting: spend counted (leg 1 NEAR input), reserved fee, native outflow.
    pub counted: u128,
    pub fee: u128,
    pub native_out: u128,
    /// AUDIT-S1: the legs' extra spend (storage, buy extras), counted as spend but never returned
    /// on a refund (as `Plan.spend - Plan.counted` of a single-hop curve op).
    pub extra_spend: u128,
    /// Total gas the op attaches (legs + overhead).
    pub gas: u64,
}

/// Validation of `Op::Chain` (routing C.1 rules 1-6). `order_floor`: an order fire's stored
/// min_out (UNR-A-01: the sell fee base is the stored bound when lower).
pub fn check_chain(
    e: &Env,
    c: &Chain,
    order_fire: bool,
    order_floor: Option<u128>,
) -> Result<ChainPlan, &'static str> {
    if c.min_mid.0 == 0 || c.min_final.0 == 0 {
        return Err(E_CHAIN_MIN);
    }
    if c.min_mid.0 > c.max_mid.0 {
        return Err(E_CHAIN_MID);
    }
    if &c.q == e.me {
        return Err("E_BAD_OP");
    }
    // V16-17: Q = wNEAR is a plain two-hop, not a route (no NEAR leg to fee, and a payable leg 2
    // would attach native NEAR measured from a wNEAR delta)
    if &c.q == e.wrap {
        return Err(E_CHAIN_LEG);
    }
    let mut l1 = leg_info(e, &c.leg1, false)?;
    let q = c.q.as_str();
    if matches!(c.leg1, ChainLeg::ShardsSell { .. }) {
        l1.out = q.to_string();
    }
    // rule 1 + 2 (leg 1)
    if l1.out != q || l1.token_in == q {
        return Err(E_CHAIN_LEG);
    }
    if l1.min_out < c.min_mid.0 {
        return Err(E_CHAIN_MID);
    }
    let (l2, fund, token_out, out_is_near) = match &c.leg2 {
        ChainLeg::IntentsFund { signed_quote, signature } => {
            // a 24/7 fire never funds a 1Click quote (owner decision)
            if order_fire {
                return Err(E_ORDER_OPS);
            }
            let ch = quote::check_sell(e, signed_quote, signature, &c.q, c.min_mid.0, c.min_final.0)?;
            (None, Some(ch), e.wrap.to_string(), true)
        }
        leg => {
            let mut l2 = leg_info(e, leg, true)?;
            if matches!(leg, ChainLeg::ShardsBuy { .. }) {
                l2.token_in = q.to_string();
            }
            if l2.token_in != q {
                return Err(E_CHAIN_LEG);
            }
            if l2.min_out < c.min_final.0 {
                return Err(E_CHAIN_MIN);
            }
            // rule 3
            if l2.dex == l1.dex {
                return Err(E_CHAIN_SAME_DEX);
            }
            let (o, n) = (l2.out.clone(), l2.out_is_near);
            (Some(l2), None, o, n)
        }
    };
    if token_out == q || token_out == l1.token_in {
        return Err(E_CHAIN_LEG);
    }
    // rule 5: disjoint pools; leg 1 never passes through token_out, leg 2 never through token_in
    if let Some(l2) = &l2 {
        if l1.pools.iter().any(|p| l2.pools.contains(p)) {
            return Err(E_CHAIN_OVERLAP);
        }
        if l1.hop_tokens.contains(&token_out) || l2.hop_tokens.contains(&l1.token_in) {
            return Err(E_CHAIN_OVERLAP);
        }
    }
    // rule 6
    let gas = l1
        .gas
        .checked_add(l2.as_ref().map_or(GAS_FUND * TGAS, |l| l.gas))
        .and_then(|g| g.checked_add(CHAIN_OVERHEAD_TGAS * TGAS))
        .ok_or(E_CHAIN_GAS)?;
    // v1.6 (taxed tokens): an order fire with a taxed output also carries the tax gate
    let gate = if order_fire && venues::tax::taxed_kind(&token_out).is_some() {
        venues::tax::GATE_CHAIN_EXTRA_TGAS * TGAS
    } else {
        0
    };
    if gas.checked_add(gate).is_none_or(|g| g > MAX_CHAIN_GAS * TGAS) {
        return Err(E_CHAIN_GAS);
    }
    // NEAR leg: buys = leg 1 input, sells = leg 2 output (fee on the min_final bound)
    let (counted, fee) = if l1.near_in {
        (l1.amount, crate::policy::bps(l1.amount, e.fee_bps))
    } else if out_is_near && fund.is_none() {
        let base = order_floor.map_or(c.min_final.0, |f| f.min(c.min_final.0));
        (0, crate::policy::bps(base, e.fee_bps))
    } else {
        // IntentsFund sells: the fee is charged on the wNEAR pulled (continuation)
        (0, 0)
    };
    // V16-04: the native NEAR leg 1 attaches (the planned deposit). Leg 2 is paid in Q: a
    // payable leg 2 is refused.
    if l2.as_ref().is_some_and(|l| l.native_out > 1) {
        return Err(E_CHAIN_LEG);
    }
    let native_out = l1.native_out.max(1);
    let extra_spend = l1.extra_spend.saturating_add(l2.as_ref().map_or(0, |l| l.extra_spend));
    Ok(ChainPlan {
        token_in: l1.token_in.clone(),
        token_out,
        l1,
        l2,
        fund,
        counted,
        fee,
        native_out,
        extra_spend,
        gas,
    })
}

/// An order fire of a Chain: checked against the stored order and its legs (`ov` + id).
pub fn check_chain_order(
    o: &crate::Order,
    via: Option<&OrderVia>,
    c: &Chain,
    p: &ChainPlan,
) -> Result<(), &'static str> {
    let via = via.ok_or(E_ORDER_MISMATCH)?;
    if p.token_in != o.token_in.as_str()
        || p.l1.amount != o.amount_in.0
        || c.q != via.q
        || p.token_out != o.token_out.as_str()
        || p.l1.dex != via.leg1_dex
        || p.l2.as_ref().is_none_or(|l| l.dex != via.leg2_dex)
    {
        return Err(E_ORDER_MISMATCH);
    }
    if c.min_final.0 < o.min_out.0 {
        return Err("E_ORDER_MIN_OUT");
    }
    // V16-01: leg 1 is bounded by the user's stored terms, never by the firing key
    if c.min_mid.0 < via.min_mid.0 || p.l1.min_out < via.min_mid.0 || c.max_mid.0 > via.max_mid.0 {
        return Err(E_ORDER_MID);
    }
    Ok(())
}

/// A plain order (no stored legs) can never fire a Chain, and a Chain order only a Chain.
pub fn check_order_kind(has_via: bool, ops: &[Op]) -> Result<(), &'static str> {
    let chain = ops.iter().any(|o| matches!(o, Op::Chain(_)));
    if chain != has_via {
        return Err(E_ORDER_OPS);
    }
    Ok(())
}

/// `place_order(via)`: the legs of a Chain order. Both leg DEXes are allowlisted venues among the
/// order's `dexes`, distinct; Q is neither end.
pub fn check_via(
    v: &OrderVia,
    token_in: &AccountId,
    token_out: &AccountId,
    dexes: &[AccountId],
    me: &AccountId,
) -> Result<(), &'static str> {
    if &v.q == token_in || &v.q == token_out || &v.q == me {
        return Err("E_BAD_ORDER");
    }
    // V16-01: the leg-1 bound is the user's (min_mid > 0, max_mid >= min_mid)
    if v.min_mid.0 == 0 || v.max_mid.0 < v.min_mid.0 {
        return Err("E_BAD_ORDER");
    }

    if v.leg1_dex == v.leg2_dex {
        return Err(E_CHAIN_SAME_DEX);
    }
    if !dexes.contains(&v.leg1_dex) || !dexes.contains(&v.leg2_dex) {
        return Err("E_BAD_ORDER");
    }
    Ok(())
}

/// The optional `via` field of `place_order`'s JSON args (absent / null = a plain order).
pub fn via_from_input() -> Option<OrderVia> {
    #[derive(Deserialize)]
    #[serde(crate = "near_sdk::serde")]
    struct A {
        #[serde(default)]
        via: Option<OrderVia>,
    }
    let input = near_sdk::env::input().filter(|i| !i.is_empty())?;
    serde_json::from_slice::<A>(&input).unwrap_or_else(|_| near_sdk::env::panic_str("E_BAD_ORDER")).via
}

/// V16-10: a leg DEX that can't be a Chain / continuation leg: Kelytra (its round trip lives in
/// callbacks a Chain never runs) and Nearrr (buys run the tax view -> buy chain; a Nearrr sell pays
/// native NEAR, which is never a route's Q).
pub fn chain_venue_ok(allow: &[Dex], d: &AccountId) -> bool {
    !matches!(
        venues::resolve(allow, d),
        Some(venues::Venue::Kelytra | venues::Venue::Factory(venues::FactoryPad::Nearrr))
    )
}

/// V16-10: `place_order(via)`: no leg on a venue whose trade is a callback chain (Kelytra;
/// Nearrr NEAR buys). A fire of such a leg is refused anyway (`leg_info`); this refuses the order.
pub fn check_via_venues(v: &OrderVia, allow: &[Dex]) -> Result<(), &'static str> {
    if [&v.leg1_dex, &v.leg2_dex].into_iter().all(|d| chain_venue_ok(allow, d)) {
        Ok(())
    } else {
        Err(E_CHAIN_LEG)
    }
}
