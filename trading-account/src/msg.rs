//! Swap-message parsers for the allowlisted DEXes. Pure functions, no env access.
//!
//! Every parser is strict: unknown fields are rejected (`deny_unknown_fields`) so a
//! field we do not understand (e.g. a future output-recipient field) can never slip
//! through. Each returns the guaranteed minimum output of the final token.
use near_sdk::json_types::U128;
use near_sdk::serde::Deserialize;
use near_sdk::serde_json;
use near_sdk::AccountId;

pub const E_BAD_MSG: &str = "E_BAD_MSG";
pub const E_RECIPIENT: &str = "E_RECIPIENT";
pub const E_MIN_OUT: &str = "E_MIN_OUT";
/// v1.2.1: a DEX referral/referrer other than the platform's (a referrer sets its own fee).
pub const E_REFERRER: &str = "E_REFERRER";

#[near_sdk::near(serializers = [borsh, json])]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DexKind {
    RheaClassic,
    RheaDcl,
    Plach,
    /// v1.5: Shards launchpad tokens. The entry's `id` is the Shards FACTORY
    /// (`factory.shardsmarket.near`); the venue is any token `<label>.<id>` (one label, no dot),
    /// which trades against itself (curve, then in-token AMM). The factory id itself is never a
    /// venue. See `shards_token_of`.
    ShardsToken,
}

/// v1.5: `token` is `<label>.<factory>` with exactly one non-empty label (a Shards token account
/// can only be created by the Shards factory account; a deeper name could be created by a token).
pub fn shards_token_of(factory: &AccountId, token: &AccountId) -> bool {
    token
        .as_str()
        .strip_suffix(factory.as_str())
        .and_then(|l| l.strip_suffix('.'))
        .is_some_and(|l| !l.is_empty() && !l.contains('.'))
}

#[derive(PartialEq, Eq, Debug)]
pub struct Swap {
    /// Final output token is NEAR (wNEAR or native NEAR).
    pub out_is_near: bool,
    /// Guaranteed minimum amount of the final output token.
    pub min_out: u128,
    /// v1.3: final output token contract ("nep141:" stripped; native NEAR = the wrap id).
    pub out: String,
}

pub struct Ctx<'a> {
    pub self_id: &'a AccountId,
    pub wrap: &'a AccountId,
    /// The token contract `ft_transfer_call` is sent to (the swap input).
    pub token_in: &'a AccountId,
    /// v1.2.1: the only referrer/referral_id a msg may name (the platform fee recipient).
    pub referrer: &'a AccountId,
}

fn check_referrer(r: &Option<AccountId>, allowed: &AccountId) -> Result<(), &'static str> {
    match r {
        Some(x) if x != allowed => Err(E_REFERRER),
        _ => Ok(()),
    }
}

pub fn parse(kind: DexKind, msg: &str, ctx: &Ctx) -> Result<Swap, &'static str> {
    let swap = match kind {
        DexKind::RheaClassic => rhea(msg, ctx)?,
        DexKind::RheaDcl => dcl(msg, ctx)?,
        DexKind::Plach => {
            plach(msg, ctx.self_id, ctx.wrap, &["nep141:", ctx.token_in.as_str()].concat(), ctx.referrer)?
        }
        // v1.5: Shards trades are typed ops whose msg the contract builds; no raw msg is accepted
        DexKind::ShardsToken => return Err(E_BAD_MSG),
    };
    nonzero(swap)
}

/// Plach buy paid in native NEAR (`deposit_near{operations: msg}`), input asset "near".
pub fn parse_plach_near(
    msg: &str,
    self_id: &AccountId,
    wrap: &AccountId,
    referrer: &AccountId,
) -> Result<Swap, &'static str> {
    // Buying NEAR with NEAR is rejected as a cycle.
    nonzero(plach(msg, self_id, wrap, "near", referrer)?)
}

fn nonzero(swap: Swap) -> Result<Swap, &'static str> {
    if swap.min_out == 0 {
        return Err(E_MIN_OUT);
    }
    Ok(swap)
}

// ---------- Rhea classic (v2.ref-finance.near) ----------

#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde", deny_unknown_fields)]
struct RheaMsg {
    actions: Vec<RheaAction>,
    #[serde(default)]
    force: Option<u8>,
    #[serde(default)]
    referral_id: Option<AccountId>,
    #[serde(default)]
    skip_unwrap_near: Option<bool>,
    #[serde(default)]
    skip_degen_price_sync: Option<bool>,
    #[serde(default)]
    swap_out_recipient: Option<AccountId>,
}

#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde", deny_unknown_fields)]
struct RheaAction {
    #[allow(dead_code)]
    pool_id: u64,
    token_in: AccountId,
    token_out: AccountId,
    #[serde(default)]
    #[allow(dead_code)]
    amount_in: Option<U128>,
    #[serde(default)]
    amount_out: Option<U128>,
    min_amount_out: U128,
}

fn rhea(msg: &str, ctx: &Ctx) -> Result<Swap, &'static str> {
    let m: RheaMsg = serde_json::from_slice(msg.as_bytes()).map_err(|_| E_BAD_MSG)?;
    let _ = (m.force, m.skip_unwrap_near, m.skip_degen_price_sync);
    check_referrer(&m.referral_id, ctx.referrer)?;
    if let Some(r) = &m.swap_out_recipient {
        if r != ctx.self_id {
            return Err(E_RECIPIENT);
        }
    }
    let last = m.actions.last().ok_or(E_BAD_MSG)?;
    let fin = &last.token_out;
    let mut min_out: u128 = 0;
    for a in &m.actions {
        // amount_out is only accepted as the router's placeholder "0" (swap-by-output
        // actions are not supported).
        if a.amount_out.is_some_and(|x| x.0 != 0) {
            return Err(E_BAD_MSG);
        }
        // Final token consumed again later would make the sum below meaningless.
        if &a.token_in == fin {
            return Err(E_BAD_MSG);
        }
        if &a.token_out == fin {
            min_out = min_out.checked_add(a.min_amount_out.0).ok_or(E_BAD_MSG)?;
        }
    }
    if fin == ctx.token_in {
        return Err(E_BAD_MSG);
    }
    Ok(Swap { out_is_near: fin == ctx.wrap, min_out, out: fin.to_string() })
}

// ---------- Rhea DCL (dclv2.ref-labs.near) ----------

#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde", deny_unknown_fields)]
enum DclMsg {
    Swap(DclSwap),
}

#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde", deny_unknown_fields)]
struct DclSwap {
    pool_ids: Vec<String>,
    output_token: AccountId,
    min_output_amount: U128,
    #[serde(default)]
    skip_unwrap_near: Option<bool>,
    #[serde(default)]
    referral_id: Option<AccountId>,
    #[serde(default)]
    client_id: Option<String>,
}

fn dcl(msg: &str, ctx: &Ctx) -> Result<Swap, &'static str> {
    let DclMsg::Swap(s) = serde_json::from_slice(msg.as_bytes()).map_err(|_| E_BAD_MSG)?;
    let _ = (s.skip_unwrap_near, s.client_id);
    check_referrer(&s.referral_id, ctx.referrer)?;
    if s.pool_ids.is_empty() || &s.output_token == ctx.token_in {
        return Err(E_BAD_MSG);
    }
    Ok(Swap {
        out_is_near: &s.output_token == ctx.wrap,
        min_out: s.min_output_amount.0,
        out: s.output_token.to_string(),
    })
}

// ---------- Plach (dex.intear.near) ----------

#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde", deny_unknown_fields)]
struct PlachMsg {
    operations: Vec<PlachOp>,
    #[serde(default)]
    referrer: Option<AccountId>,
}

#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde", deny_unknown_fields)]
enum PlachOp {
    SwapSimple {
        #[allow(dead_code)]
        dex_id: String,
        #[allow(dead_code)]
        message: String,
        asset_in: String,
        asset_out: String,
        amount: PlachSwapAmount,
        #[serde(default)]
        constraint: Option<U128>,
    },
    Withdraw {
        asset_id: String,
        amount: PlachWithdrawAmount,
        #[serde(default)]
        to: Option<AccountId>,
        #[serde(default)]
        rescue_address: Option<AccountId>,
    },
}

#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde", deny_unknown_fields)]
enum PlachSwapAmount {
    Amount(PlachExact),
    OutputOfLastIn,
    EntireBalanceIn,
}

#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde", deny_unknown_fields)]
enum PlachExact {
    ExactIn(#[allow(dead_code)] U128),
    ExactOut(U128),
}

#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde", deny_unknown_fields)]
enum PlachWithdrawAmount {
    Full {
        #[serde(default)]
        at_least: Option<U128>,
    },
    Exact(U128),
    PreviousSwapOutput,
}

fn plach(
    msg: &str,
    self_id: &AccountId,
    wrap: &AccountId,
    input: &str,
    referrer: &AccountId,
) -> Result<Swap, &'static str> {
    let m: PlachMsg = serde_json::from_slice(msg.as_bytes()).map_err(|_| E_BAD_MSG)?;
    check_referrer(&m.referrer, referrer)?;
    // Final asset = output of the last swap.
    let fin = m
        .operations
        .iter()
        .rev()
        .find_map(|op| match op {
            PlachOp::SwapSimple { asset_out, .. } => Some(asset_out.as_str()),
            _ => None,
        })
        .ok_or(E_BAD_MSG)?;
    if fin == input {
        return Err(E_BAD_MSG);
    }
    let mut swap_min: u128 = 0;
    // Some(Ok(x)) = Exact(x); Some(Err(a)) = Full{at_least: a}.
    let mut withdraw: Option<Result<u128, u128>> = None;
    // A1-F3: the output Withdraw must come AFTER the last swap producing the final asset
    // (Plach executes operations in order; an earlier Withdraw can't deliver the new output).
    let last_fin_swap = m
        .operations
        .iter()
        .rposition(|op| matches!(op, PlachOp::SwapSimple { asset_out, .. } if asset_out == fin));
    for (i, op) in m.operations.iter().enumerate() {
        match op {
            PlachOp::SwapSimple { asset_in, asset_out, amount, constraint, .. } => {
                if asset_in == fin {
                    return Err(E_BAD_MSG);
                }
                if asset_out == fin {
                    let g = match amount {
                        PlachSwapAmount::Amount(PlachExact::ExactOut(x)) => x.0,
                        _ => constraint.map_or(0, |c| c.0),
                    };
                    swap_min = swap_min.checked_add(g).ok_or(E_BAD_MSG)?;
                }
            }
            PlachOp::Withdraw { asset_id, amount, to, rescue_address } => {
                for r in [to, rescue_address].into_iter().flatten() {
                    if r != self_id {
                        return Err(E_RECIPIENT);
                    }
                }
                if asset_id == fin {
                    if withdraw.is_some() || last_fin_swap.is_some_and(|l| i < l) {
                        return Err(E_BAD_MSG);
                    }
                    withdraw = Some(match amount {
                        PlachWithdrawAmount::Full { at_least } => Err(at_least.map_or(0, |a| a.0)),
                        PlachWithdrawAmount::Exact(x) => Ok(x.0),
                        PlachWithdrawAmount::PreviousSwapOutput => return Err(E_BAD_MSG),
                    });
                }
            }
        }
    }
    // Output must actually be withdrawn to us, not left as an inner DEX balance.
    // Exact(x) delivers exactly x; Full delivers the whole balance (>= both bounds).
    let min_out = match withdraw.ok_or(E_BAD_MSG)? {
        Ok(x) => x,
        Err(at_least) => at_least.max(swap_min),
    };
    let wrap_asset = ["nep141:", wrap.as_str()].concat();
    let out_is_near = fin == "near" || fin == wrap_asset;
    let out =
        if out_is_near { wrap.to_string() } else { fin.strip_prefix("nep141:").unwrap_or(fin).to_string() };
    Ok(Swap { out_is_near, min_out, out })
}
