//! Trade-quote checks (routing C.2.2): the 1Click signature and strict flat parser of
//! `withdraw_cross_chain` (intents.rs, reused read-only) with the TRADE field rules: recipient and
//! refund both `INTENTS` to this account, freshness 60 s, loss bound = the quote's slippage (<= the
//! route's, <= 5000 bps), `amountOut` parsed (withdraws ignore it).
use crate::intents::{self, parse_flat, parse_quote, parse_uint, Val};
use near_sdk::AccountId;

pub const TRADE_QUOTE_MAX_AGE_NS: u64 = 60 * 1_000_000_000;
pub const TRADE_MAX_SLIPPAGE_BPS: u16 = 5_000;
const M: &str = "E_QUOTE_MISMATCH";

/// What a passing trade quote binds (owned: stored in the route).
#[derive(Clone, Debug, PartialEq)]
pub struct Checked {
    pub deposit_address: String,
    pub deadline_ns: u64,
    pub issued_ns: u64,
    /// signed `amount` (= amountIn)
    pub amount: u128,
    /// FLEX_INPUT: least input 1Click accepts; EXACT_INPUT: = amount
    pub min_amount_in: u128,
    pub min_amount_out: u128,
    pub amount_out: u128,
    pub slippage_bps: u16,
}

pub struct Rules<'a> {
    pub me: &'a str,
    pub origin: &'a str,
    pub dest: &'a str,
    pub flex: bool,
    pub now_ns: u64,
}

/// Signature + every field rule. The signature is over the exact bytes (never re-canonicalized).
pub fn check(signed: &str, signature: &str, keys: &[String], r: &Rules) -> Result<Checked, &'static str> {
    intents::verify_quote_sig(signed, signature, keys)?;
    check_fields(signed, r)
}

/// Field rules only (unit tested without signatures).
pub fn check_fields(signed: &str, r: &Rules) -> Result<Checked, &'static str> {
    let q = parse_quote(signed)?;
    // amountOut / minAmountIn are in intents' IGNORED list: read them from the same flat parse
    let flat = parse_flat(signed).ok_or(M)?;
    let get = |k: &str| {
        flat.iter().find(|(key, _)| *key == k).and_then(|(_, v)| match v {
            Val::Str(s) => parse_uint(s),
            _ => None,
        })
    };
    let self_asset = |t: &str| ["nep141:", t].concat();
    let amount = parse_uint(q.amount).ok_or(M)?;
    let addr = q.deposit_address.unwrap_or("");
    let ok = !q.dry
        && q.swap_type == if r.flex { "FLEX_INPUT" } else { "EXACT_INPUT" }
        && q.deposit_type == "INTENTS"
        && intents::canon_asset(q.origin_asset) == intents::canon_asset(&self_asset(r.origin))
        && intents::canon_asset(q.destination_asset) == intents::canon_asset(&self_asset(r.dest))
        && q.amount == q.amount_in
        && amount > 0
        && q.recipient == r.me
        && q.recipient_type == "INTENTS"
        && q.refund_to == r.me
        && q.refund_type == "INTENTS"
        && q.custom_recipient_msg.is_none()
        && q.deposit_memo.is_none()
        && intents::is_deposit_address(addr)
        && q.slippage_tolerance <= TRADE_MAX_SLIPPAGE_BPS;
    if !ok {
        return Err(M);
    }
    let min_out = parse_uint(q.min_amount_out).filter(|m| *m > 0).ok_or(M)?;
    let amount_out = get("amountOut").filter(|a| *a >= min_out).ok_or(M)?;
    let min_in =
        if r.flex { get("minAmountIn").filter(|m| *m > 0 && *m <= amount).ok_or(M)? } else { amount };
    let usd_in = intents::parse_usd(q.amount_in_usd).ok_or(M)?;
    let usd_out = intents::parse_usd(q.amount_out_usd).ok_or(M)?;
    let deadline = intents::parse_iso_ns(q.deadline).ok_or(M)?;
    let issued = intents::parse_iso_ns(q.timestamp).ok_or(M)?;
    if deadline <= r.now_ns.saturating_add(intents::MIN_DEADLINE_LEAD_NS) {
        return Err("E_QUOTE_EXPIRED");
    }
    if issued.saturating_add(TRADE_QUOTE_MAX_AGE_NS) < r.now_ns
        || issued > r.now_ns.saturating_add(intents::QUOTE_FUTURE_SKEW_NS)
    {
        return Err("E_QUOTE_DEADLINE");
    }
    // loss bound = the quote's slippage (the user's)
    let floor = usd_in.checked_mul(u128::from(10_000 - q.slippage_tolerance)).ok_or(M)?;
    if usd_in == 0 || usd_out.checked_mul(10_000).ok_or(M)? < floor {
        return Err("E_QUOTE_LOSS");
    }
    Ok(Checked {
        deposit_address: addr.to_string(),
        deadline_ns: deadline,
        issued_ns: issued,
        amount,
        min_amount_in: min_in,
        min_amount_out: min_out,
        amount_out,
        slippage_bps: q.slippage_tolerance,
    })
}

fn keys() -> Result<Vec<String>, &'static str> {
    Ok(intents::oneclick().ok_or("E_ONECLICK_UNSET")?.keys)
}

fn fresh_addr(c: &Checked, now: u64) -> Result<(), &'static str> {
    if intents::is_quote_used(&c.deposit_address, now) {
        return Err("E_QUOTE_REPLAY");
    }
    Ok(())
}

/// Buy: wNEAR -> Q, EXACT_INPUT.
pub fn check_buy(e: &super::Env, signed: &str, sig: &str, q: &AccountId) -> Result<Checked, &'static str> {
    let r =
        Rules { me: e.me.as_str(), origin: e.wrap.as_str(), dest: q.as_str(), flex: false, now_ns: e.now_ns };
    let c = check(signed, sig, &keys()?, &r)?;
    fresh_addr(&c, e.now_ns)?;
    Ok(c)
}

/// Sell leg 2: Q -> wNEAR, FLEX_INPUT; the signed amount must cover min_mid, and the quote's
/// minAmountOut the whole-route bound.
pub fn check_sell(
    e: &super::Env,
    signed: &str,
    sig: &str,
    q: &AccountId,
    min_mid: u128,
    min_final: u128,
) -> Result<Checked, &'static str> {
    let r =
        Rules { me: e.me.as_str(), origin: q.as_str(), dest: e.wrap.as_str(), flex: true, now_ns: e.now_ns };
    let c = check(signed, sig, &keys()?, &r)?;
    if c.amount < min_mid || c.min_amount_out < min_final {
        return Err(M);
    }
    fresh_addr(&c, e.now_ns)?;
    Ok(c)
}

/// FLEX scaling: minAmountOut x funded / amount (floor).
pub fn scaled(x: u128, funded: u128, amount: u128) -> u128 {
    crate::policy::mul_div(x, funded.min(amount), amount)
}

/// q_quoted x (1 + slippage), saturating.
pub fn with_slip(x: u128, bps: u16) -> u128 {
    x.saturating_add(crate::policy::mul_div(x, u128::from(bps), 10_000))
}
