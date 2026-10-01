//! Kelytra (`exchange.kelytradevs.near`), an internal-balance exchange (trading-plan §1.10), in
//! ONE execute (one signature):
//!
//! ```text
//! execute (setup = a first trade): storage_deposit on the launch token (beside) +
//!          exchange.register_balance{wNEAR} + register_balance{launch token}   (planned calls)
//!   -> on_kelytra_registered: failed -> failed swap (deposits back); else the deposit step
//! execute (no setup): the deposit step                                       (planned calls)
//!   deposit step: buy  = wrap batch [near_deposit{amount}, ft_transfer_call{exchange, "deposit"}]
//!                 sell = token.ft_transfer_call{exchange, amount, "deposit"}
//!   -> on_kelytra_deposited: deposited = what the token's resolve reports used (<= amount)
//!        0 / failed -> settled as a failed swap (the deposit was refunded; a buy's NEAR stays
//!        wrapped as wNEAR)
//!        else exchange.swap_curve{launch_id, buy, max_input: deposited, min_out, deadline}
//!   -> on_kelytra_swapped:
//!        failed (slippage, deadline, curve complete) -> withdraw{token_in, deposited} (refund,
//!        as wNEAR for a buy)
//!        ok -> withdraw{token_out, amount_out}      (amount_out as swap_curve returned it)
//!   -> on_kelytra_done: withdraw delivered = its result is `true` (resolve_withdraw)
//!        refund path -> failed swap: no fee, spend returned
//!        buy  -> used = amount_in (min(reported, deposited)), fee pro rata on it (NEAR leg = input)
//!        sell -> fee = min(fee_bps x amount_out, the reserved fee = bps of the min_out bound),
//!                only if the withdraw reports delivered (AUDIT-K1: both are the exchange's word)
//! ```
//! A buy takes native NEAR (wrapped inside the chain, so a first trade needs no NearDeposit op);
//! a sell pays out wNEAR. Anything that could not be withdrawn (unregistered output, a
//! curve-completing buy's unused input) stays in THIS account's internal balance and is logged
//! `kelytra_held`; it is recovered with `CurveClaim{KelytraWithdraw}` (pays this account only).
//!
//! Gas (sandbox, real mainnet wasm 4jqrRK3f + token GnQgLK9T): deposit (wrap ft_transfer_call)
//! burns ~6 TGas in total; swap_curve 3.3 TGas (30 attached is enough); withdraw refuses less than
//! 65 TGas attached ("attach at least 65 Tgas") and burns ~7.4; register_balance ~2.2. A setup buy
//! needs 225 TGas of op gas, a plain buy 175: both fit one 300 TGas execute.
//!
//! Registration: `setup` registers both exchange balances (0.02 N each, the exchange refunds what
//! it doesn't use; a repeat refunds all) and the launch-token storage. The client sets it when
//! `get_balance{account_id, token_id}` is `null` for either token. Without it, a deposit from an
//! unregistered balance is refunded by the exchange (used 0 -> clean failed swap).
use super::*;
use crate::{
    env, near, serde_json, Gas, NearToken, Promise, PromiseError, SettleArgs, TradingAccount,
    TradingAccountExt, U128,
};
use near_sdk::serde_json::json;

/// TGas budgets (see module doc).
pub const GAS_DEPOSIT: u64 = 40;
pub const GAS_SWAP: u64 = 30;
pub const GAS_WITHDRAW: u64 = 65;
pub const GAS_REGISTER: u64 = 10;
/// near_deposit on wrap (burns ~2.5).
pub const GAS_NEAR_DEPOSIT: u64 = 10;
/// on_kelytra_done: finish_settle (+ fee transfer).
pub const GAS_CB_DONE: u64 = 10;
/// on_kelytra_swapped: itself + withdraw + on_kelytra_done + 2 action fees.
pub const GAS_CB_SWAPPED: u64 = 5 + GAS_WITHDRAW + GAS_CB_DONE + 2 * 5;
/// on_kelytra_deposited: itself + swap_curve + on_kelytra_swapped + 2 action fees.
pub const GAS_CB_DEPOSITED: u64 = 5 + GAS_SWAP + GAS_CB_SWAPPED + 2 * 5;
/// on_kelytra_registered (setup): itself + the buy deposit step (near_deposit + ft_transfer_call)
/// + on_kelytra_deposited + 3 action fees.
pub const GAS_CB_REGISTERED: u64 = 5 + GAS_NEAR_DEPOSIT + GAS_DEPOSIT + GAS_CB_DEPOSITED + 3 * 5;

/// Output token of launch `n`: `t<n>.<exchange>` (C: launch 0 = t0.exchange.kelytradevs.near).
pub fn launch_token(n: u64, ex: &AccountId) -> Result<AccountId, &'static str> {
    format!("t{n}.{ex}").parse().map_err(|_| E_MARKET)
}

/// The deposit step: a buy wraps the NEAR and deposits it in ONE wrap batch
/// (`near_deposit` + `ft_transfer_call`); a sell deposits the launch token.
fn deposit_calls(buy: bool, token_in: &AccountId, ex: &AccountId, amount: u128) -> Vec<Call> {
    let dep = ft_call(token_in, ex, amount, "deposit", GAS_DEPOSIT * TGAS);
    if buy {
        vec![fcall(token_in, "near_deposit", "{}".into(), amount, GAS_NEAR_DEPOSIT * TGAS), dep]
    } else {
        vec![dep]
    }
}

/// `setup` calls: storage on the launch token, then both exchange balance registrations.
fn setup_calls(token: &AccountId, wrap: &AccountId, ex: &AccountId, me: &AccountId) -> Vec<Call> {
    let reg = |t: &AccountId| {
        let args = json!({"token_id": t, "account_id": me}).to_string();
        fcall(ex, "register_balance", args, KELYTRA_REGISTER, GAS_REGISTER * TGAS)
    };
    vec![storage_call(token, me), reg(wrap), reg(token)]
}

pub fn plan(buy: bool, t: &CurveTrade, c: &Ctx, dex: u16) -> Result<Plan, &'static str> {
    // curve quote is wNEAR only (`configure_curve_quote` has only wrap.near, trading-plan §1.10)
    if t.quote.is_some() || t.max_out.is_some() {
        return Err(E_QUOTE);
    }
    let n = market_u64(&t.market)?;
    let ex = &t.venue;
    let token = launch_token(n, ex)?;
    let settle = Settle::Kelytra { buy, launch: n, min_out: t.min_out.0, dex, setup: t.setup };
    let token_in = if buy { c.wrap.clone() } else { token.clone() };
    let amount = t.amount.0;
    let deposit = deposit_calls(buy, &token_in, ex, amount);
    let sum = |v: &[Call], f: fn(&Call) -> u128| v.iter().fold(0u128, |a, x| a.saturating_add(f(x)));
    let dep_native = sum(&deposit, |x| x.deposit);
    // setup: the planned calls register; the deposit step runs in on_kelytra_registered
    let (calls, later_native, first_cb) = if t.setup {
        (setup_calls(&token, c.wrap, ex, c.me), dep_native, u128::from(GAS_CB_REGISTERED))
    } else {
        (deposit, 0, u128::from(GAS_CB_DEPOSITED))
    };
    let setup_spend = if t.setup { sum(&calls, |x| x.deposit) } else { 0 };
    let calls_gas = calls.iter().map(|x| x.gas).sum::<u64>();
    let mut p = if buy {
        buy_plan(
            t,
            c,
            BuyShape {
                calls,
                settle,
                extra: 0,
                out: token.clone(),
                order_dex: ex.clone(),
                storage: vec![token],
                orderable: true,
            },
        )
    } else {
        sell_plan(t, c, SellShape { calls, settle, token_in, order_dex: ex.clone(), storage: vec![token] })
    };
    // every NEAR that leaves (planned deposits + the deposit step's, which runs in a callback)
    // is in native_out, so run's reserve check sees it; registrations/storage count as spend
    p.native_out = p.native_out.saturating_add(later_native);
    if buy {
        // NEAR in (wrapped inside the chain): counted spend + reserved fee
        p.spend = amount.saturating_add(setup_spend);
        p.counted = amount;
        p.fee = bps(amount, c.fee_bps);
    } else {
        p.spend = setup_spend;
    }
    // the op's gas covers the whole round trip: run attaches GAS_CALLBACK for the first
    // callback, the rest is on top
    p.gas = calls_gas.saturating_add((first_cb as u64 - crate::GAS_CALLBACK) * TGAS);
    // the op must declare (and so budget in run's E_GAS check) the whole round trip
    if p.gas > t.gas.0 {
        return Err(E_GAS);
    }
    Ok(p)
}

/// The callback `run` attaches to the planned calls (via settle::callback).
pub fn first_callback(
    settle_json: &str,
    buy: bool,
    launch: u64,
    min_out: u128,
    dex: u16,
    setup: bool,
) -> (&'static str, String, u64) {
    let (m, g) = if setup {
        ("on_kelytra_registered", GAS_CB_REGISTERED)
    } else {
        ("on_kelytra_deposited", GAS_CB_DEPOSITED)
    };
    (
        m,
        format!(
            "{{\"settle\":{settle_json},\"k\":{{\"buy\":{buy},\"launch\":\"{launch}\",\"min_out\":\"{min_out}\",\"dex\":{dex}}}}}"
        ),
        g,
    )
}

#[near(serializers = [json])]
#[derive(Clone, Debug)]
pub struct KelArgs {
    pub buy: bool,
    pub launch: near_sdk::json_types::U64,
    pub min_out: U128,
    pub dex: u16,
}

#[derive(near_sdk::serde::Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct SwapOut {
    amount_in: U128,
    amount_out: U128,
}

fn held(token: &AccountId, amount: u128, reason: &str) {
    env::log_str(&format!(
        "EVENT_JSON:{{\"standard\":\"nttrade\",\"version\":\"1\",\"event\":\"kelytra_held\",\"data\":{{\"token\":\"{token}\",\"amount\":\"{amount}\",\"reason\":\"{reason}\"}}}}"
    ));
}

impl TradingAccount {
    /// (exchange, token_in, token_out) of a Kelytra round trip.
    fn kel_ids(&self, k: &KelArgs) -> (AccountId, AccountId, AccountId) {
        let ex = self
            .dex_allowlist
            .get(k.dex as usize)
            .filter(|d| d.kind == DexKind::Kelytra)
            .map(|d| d.id.clone())
            .unwrap_or_else(|| env::panic_str("E_STATE"));
        let tok = launch_token(k.launch.0, &ex).unwrap_or_else(|e| env::panic_str(e));
        if k.buy {
            (ex, self.wrap.clone(), tok)
        } else {
            (ex, tok, self.wrap.clone())
        }
    }

    fn kel_withdraw_then(&self, ex: &AccountId, token: &AccountId, amount: u128, next: String) {
        Promise::new(ex.clone())
            .function_call(
                "withdraw",
                json!({"token_id": token, "amount": amount.to_string()}).to_string().into_bytes(),
                NearToken::from_yoctonear(1),
                Gas::from_tgas(GAS_WITHDRAW),
            )
            .then(Promise::new(env::current_account_id()).function_call(
                "on_kelytra_done",
                next.into_bytes(),
                NearToken::from_yoctonear(0),
                Gas::from_tgas(GAS_CB_DONE),
            ))
            .detach();
    }
}

#[near]
impl TradingAccount {
    /// Kelytra step 1 of a `setup` trade: after the registration batch (storage on the launch
    /// token runs beside it). Failed = reverted, deposits back: a failed swap. Else the deposit
    /// step (a buy wraps its NEAR here) and the round trip continues as without setup.
    #[private]
    pub fn on_kelytra_registered(&mut self, settle: SettleArgs, k: KelArgs) {
        if matches!(env::promise_result_checked(0, 0), Err(PromiseError::Failed)) {
            return self.finish_settle(settle, true, 0, 0);
        }
        let (ex, token_in, _) = self.kel_ids(&k);
        let amount = settle.amount.0;
        // run reserved it (native_out); a concurrent execute may still have spent it
        let need = if k.buy { amount.saturating_add(1) } else { 1 };
        if crate::liquid_balance() < need {
            return self.finish_settle(settle, true, 0, 0);
        }
        let mut p = Promise::new(token_in.clone());
        for c in deposit_calls(k.buy, &token_in, &ex, amount) {
            p = p.function_call(
                c.method,
                c.args.into_bytes(),
                NearToken::from_yoctonear(c.deposit),
                Gas::from_gas(c.gas),
            );
        }
        p.then(Promise::new(env::current_account_id()).function_call(
            "on_kelytra_deposited",
            json!({"settle": settle, "k": k}).to_string().into_bytes(),
            NearToken::from_yoctonear(0),
            Gas::from_tgas(GAS_CB_DEPOSITED),
        ))
        .detach();
    }

    /// Kelytra step 2: after the deposit's ft_transfer_call (its resolve reports what was used).
    #[private]
    pub fn on_kelytra_deposited(&mut self, settle: SettleArgs, k: KelArgs) {
        let used = match env::promise_result_checked(0, 64) {
            Err(PromiseError::Failed) => 0,
            Ok(b) => serde_json::from_slice::<U128>(&b).map_or(0, |u| u.0),
            Err(_) => 0,
        };
        let deposited = used.min(settle.amount.0);
        if deposited == 0 {
            // refunded by the token (unregistered, paused, ...): nothing moved
            return self.finish_settle(settle, true, 0, 0);
        }
        let (ex, _, _) = self.kel_ids(&k);
        let deadline = env::block_timestamp().saturating_add(crate::policy::MAX_EXPIRY_AHEAD_NS);
        let args = json!({"launch_id": k.launch.0.to_string(), "buy": k.buy, "max_input": deposited.to_string(),
            "min_out": k.min_out.0.to_string(), "deadline": deadline.to_string()});
        let next = json!({"settle": settle, "k": k, "deposited": deposited.to_string()});
        Promise::new(ex)
            .function_call(
                "swap_curve",
                args.to_string().into_bytes(),
                NearToken::from_yoctonear(1),
                Gas::from_tgas(GAS_SWAP),
            )
            .then(Promise::new(env::current_account_id()).function_call(
                "on_kelytra_swapped",
                next.to_string().into_bytes(),
                NearToken::from_yoctonear(0),
                Gas::from_tgas(GAS_CB_SWAPPED),
            ))
            .detach();
    }

    /// Kelytra step 3: after swap_curve. Failed -> withdraw the deposit back (refund path).
    #[private]
    pub fn on_kelytra_swapped(&mut self, settle: SettleArgs, k: KelArgs, deposited: U128) {
        let (ex, token_in, token_out) = self.kel_ids(&k);
        let out = match env::promise_result_checked(0, 1024) {
            Ok(b) => serde_json::from_slice::<SwapOut>(&b).ok(),
            Err(_) => None,
        };
        let Some(o) = out.filter(|o| o.amount_out.0 > 0) else {
            let next = json!({"settle": settle, "k": k, "token": token_in, "amount": deposited, "used": "0", "refund": true});
            return self.kel_withdraw_then(&ex, &token_in, deposited.0, next.to_string());
        };
        let amount_in = o.amount_in.0.min(deposited.0);
        let unused = deposited.0 - amount_in;
        if unused > 0 {
            // only at curve completion; kept inside, recoverable (CurveClaim KelytraWithdraw)
            held(&token_in, unused, "unused_input");
        }
        let next = json!({"settle": settle, "k": k, "token": token_out, "amount": o.amount_out,
            "used": amount_in.to_string(), "refund": false});
        self.kel_withdraw_then(&ex, &token_out, o.amount_out.0, next.to_string());
    }

    /// Kelytra step 4: after withdraw (its result = resolve_withdraw: true = delivered).
    #[private]
    pub fn on_kelytra_done(
        &mut self,
        settle: SettleArgs,
        k: KelArgs,
        token: AccountId,
        amount: U128,
        used: U128,
        refund: bool,
    ) {
        let delivered = matches!(env::promise_result_checked(0, 16), Ok(b) if b.as_slice() == b"true");
        if !delivered {
            held(&token, amount.0, if refund { "refund_undelivered" } else { "output_undelivered" });
        }
        if refund {
            return self.finish_settle(settle, true, 0, 0);
        }
        let (charged, used) = if k.buy {
            // input side is the NEAR leg: fee pro rata on the input the swap used
            (mul_div(settle.fee.0, used.0, settle.amount.0), used.0)
        } else if delivered {
            // `amount` is the exchange's own report (swap_curve's amount_out, resolve_withdraw
            // "true"): never charged above the fee reserved in run (AUDIT-K1)
            (bps(amount.0, self.fee.fee_bps).min(settle.fee.0), settle.amount.0)
        } else {
            (0, settle.amount.0)
        };
        self.finish_settle(settle, false, used.max(1), charged);
    }
}

use crate::policy::mul_div;
