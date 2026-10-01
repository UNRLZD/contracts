//! v1.6 settlement of measured curve trades (`Settle::NearIn` / `Settle::Out`). Runs after the
//! trade's receipt chain (the pad's returned promise, if any, included). Ends in the shared
//! `finish_settle` (fee transfer, daily window, order fate).
use super::Settle;
use crate::policy::{bps, mul_div};
use crate::*;

/// Pure fee math of `on_curve_settled` (unit tested). Returns (used, charged).
///
/// `delta` = liquid balance now - liquid balance at the end of `run` - the gas allowance
/// (saturating). Every receipt of the tx refunds its unused gas to the signer = this account,
/// often before this callback runs; those refunds are bounded by prepaid gas x GAS_PRICE_BOUND
/// (the allowance), so they no longer pass as a pad refund or payout (F1). The cost: a real
/// refund below the allowance is not seen (fee over-charge <= fee_bps x allowance, only when a
/// refund happened), and a native payout is under-counted by <= the allowance.
/// - `near_in`: used for the order/spend = amount (spend is never returned on a measured delta,
///   so a concurrent inflow can't free cap room); charged = fee x (amount - min(delta, amount))
///   / amount.
/// - `near_in_full` (`Settle::NearInFull`): a successful receipt is a fill: (amount, fee). No
///   delta is read (V16-02: any inflow, e.g. an unwrap in the same execute, looked like a refund).
/// - `near_out[_reported]`: charged = bps x min(arrived, cap) (cap = reported NEAR or the
///   min_out bound): a pad can't raise the fee above what it paid; a concurrent inflow can't
///   raise it above the cap.
/// - `wnear_out`: charged = bps x cap (the min_out bound, as today's sells to wNEAR).
/// - `q_out`: no fee (not the NEAR leg).
pub fn curve_fee(mode: &str, amount: u128, fee: u128, fee_bps: u16, delta: u128, cap: u128) -> (u128, u128) {
    match mode {
        "near_in" => {
            let refund = delta.min(amount);
            (amount, mul_div(fee, amount - refund, amount))
        }
        // V16-02: a success is a fill; only a failed receipt (handled before) is a refund
        "near_in_full" => (amount, fee),
        "near_out" | "near_out_reported" => (amount, bps(delta.min(cap), fee_bps)),
        "wnear_out" => (amount, bps(cap, fee_bps)),
        _ => (amount, 0),
    }
}

/// The callback `run` attaches for a measured settle: (method, args JSON, static TGas).
/// `settle_json` is the `SettleArgs` object; `liquid` = liquid balance after every promise of the
/// execute was created (deposits already deducted). Adds `gas_allowance` = this receipt's prepaid
/// gas x GAS_PRICE_BOUND: the most the tx's gas refunds can add to the balance (F1).
pub fn callback(s: Settle, settle_json: &str, liquid: u128, cap: u128) -> (&'static str, String, u64) {
    // v1.6 Kelytra: the round trip continues from the deposit's result (kelytra.rs)
    if let Settle::Kelytra { buy, launch, min_out, dex, setup } = s {
        return super::kelytra::first_callback(settle_json, buy, launch, min_out, dex, setup);
    }
    // v1.6 Nearrr: the buy continues from the token's tax view (factory.rs)
    if let Settle::NearrrTax { min_out, dex, label, len } = s {
        return super::factory::nearrr_first_callback(settle_json, min_out, dex, &label[..usize::from(len)]);
    }
    (
        "on_curve_settled",
        format!(
            "{{\"settle\":{},\"liquid_before\":\"{}\",\"mode\":\"{}\",\"cap\":\"{}\",\"gas_allowance\":\"{}\"}}",
            settle_json,
            liquid,
            s.mode(),
            cap,
            gas_allowance()
        ),
        GAS_CALLBACK,
    )
}

/// Upper bound of every gas refund this tx can pay back to the signer (this account): the whole
/// prepaid gas of the receipt that runs `run`, at GAS_PRICE_BOUND.
pub fn gas_allowance() -> u128 {
    u128::from(env::prepaid_gas().as_gas()).saturating_mul(GAS_PRICE_BOUND)
}

#[near]
impl TradingAccount {
    /// v1.6: settles a measured curve trade. Failed = reverted (a payable call's deposit comes
    /// back with the failed receipt): no fee, spend returned, an order reopens.
    #[private]
    pub fn on_curve_settled(
        &mut self,
        settle: SettleArgs,
        liquid_before: U128,
        mode: String,
        cap: U128,
        gas_allowance: Option<U128>,
    ) {
        let failed = matches!(env::promise_result_checked(0, 0), Err(PromiseError::Failed));
        if failed {
            return self.finish_settle(settle, true, 0, 0);
        }
        // F1: gas refunds of the tx (to the signer = this account) are not pad refunds / payouts
        let allowance = gas_allowance.map_or(0, |g| g.0);
        let delta = liquid_balance().saturating_sub(liquid_before.0).saturating_sub(allowance);
        // a reported NEAR payout (token0 `sell` returns it) replaces the min_out cap when readable
        let cap = if mode == "near_out_reported" {
            match env::promise_result_checked(0, 64) {
                Ok(b) => serde_json::from_slice::<U128>(&b).map_or(cap.0, |r| r.0),
                Err(_) => cap.0,
            }
        } else {
            cap.0
        };
        let (used, charged) = curve_fee(&mode, settle.amount.0, settle.fee.0, self.fee.fee_bps, delta, cap);
        self.finish_settle(settle, false, used, charged);
    }
}
