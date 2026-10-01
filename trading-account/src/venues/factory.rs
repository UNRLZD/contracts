//! Factory-held curves (trading-plan §1.4, 1.7, 1.8, 1.9, 1.10 dragonpad):
//!
//! | pad | buy | sell |
//! |---|---|---|
//! | Vista launch | `F.buy{token_id, min_out}`, deposit amount + 0.00125 N | `t.ft_transfer_call{F, {"sell":{"min_out"}}}`, native payout |
//! | Vista DEX | `F.swap_near_for_token{token_id, min_out}`, payable | `t.ft_transfer_call{F, {"swap_to_near":{"min_out"}}}` |
//! | Nearrr | `F.buy{token_id, min_out}`, payable | `t.ft_transfer_call{F, {"sell":{"min_out"}}}` |
//! | Nira | `F.buy{launch_id, min_tokens_out, deadline_ms}`, amount + 0.02 N; Q: `Q.ft_transfer_call{F, {"buy":{..}}}` | `F.sell{launch_id, token_in, min_out, deadline_ms}`, 1 yocto |
//! | meme.cooking | `wrap.ft_transfer_call{F, {"Deposit":{"meme_id"}}}` | none (CurveClaim withdraw) |
//! | dragonpad | `F.buy{token_id, min_tokens_out}`, payable, NEAR only | `t.ft_transfer_call{F, {"sell":{"min_quote_out"}}}` |
//!
//! Every token id must be `<label>.<F>` (Nearrr/dragonpad tokens are created by the factory); Vista
//! tokens (both stages) are `<label>.launch.vistadev.near` or `vista.vistadev.near` (`vista_token`).
//! Nira balances live in the factory until graduation: the order identity of a Nira position is
//! the synthetic `<launch_id>.<F>` (nothing is sent to it).
use super::*;
use crate::{SettleArgs, TradingAccount, TradingAccountExt};
use near_sdk::serde_json::json;
use near_sdk::{env, near, serde_json, Gas, NearToken, Promise};

fn near_only(t: &CurveTrade) -> Result<(), &'static str> {
    if t.quote.is_some() {
        return Err(E_QUOTE);
    }
    Ok(())
}

fn factory_token(t: &CurveTrade) -> Result<AccountId, &'static str> {
    let token = market_token(&t.market)?;
    if !one_label_under(&t.venue, &token) {
        return Err(E_MARKET);
    }
    Ok(token)
}

/// Vista's launch factory: every Vista token is `<label>.launch.vistadev.near` (C: get_launches),
/// and the DEX (`dex.vistadev.near`) also pools the house token `vista.vistadev.near` (C:
/// get_pools). Graduated tokens stay under the LAUNCH factory, never under the DEX. Mainnet ids,
/// hardcoded on purpose: they are the only Vista deployment.
pub const VISTA_LAUNCH: &str = "launch.vistadev.near";
pub const VISTA_TOKEN: &str = "vista.vistadev.near";

/// The token of a Vista trade (launch curve or DEX pool): one label under VISTA_LAUNCH, or the
/// exact VISTA_TOKEN.
fn vista_token(t: &CurveTrade) -> Result<AccountId, &'static str> {
    let token = market_token(&t.market)?;
    if is_vista_token(&token) {
        return Ok(token);
    }
    Err(E_MARKET)
}

pub fn is_vista_token(token: &AccountId) -> bool {
    VISTA_LAUNCH.parse::<AccountId>().is_ok_and(|l| one_label_under(&l, token))
        || token.as_str() == VISTA_TOKEN
}

/// Nearrr buys: the pad checks `min_out` against its curve output BEFORE the token's transfer
/// tax, which the token then takes (memo "tax"). Measured on the real wasm (sandbox, 0.5 N buys,
/// ft_transfer events): `Standard` tokens keep 0.5%; `Tax` tokens keep `buy_tax_bps` + 1%
/// (0 -> 1.0%, 50 -> 1.5%, 100 -> 2.0%, 300 -> 4.0%, 450 -> 5.5%, 500 -> 6.0%). The token wasm
/// (AV2tF8CM) refuses "tax > 10%", so the total is at most 1100 bps.
pub const NEARRR_MAX_TAX_BPS: u128 = 1_100;
/// `Standard` mode's transfer cut (C, measured).
pub const NEARRR_STANDARD_TAX_BPS: u128 = 50;
/// `Tax` mode's platform cut on top of the token's `buy_tax_bps` (C, measured).
pub const NEARRR_PLATFORM_TAX_BPS: u128 = 100;
/// Step 1 (the planned call): the token's `tax_state` view.
pub const GAS_TAX_VIEW: u64 = 5;
/// The pad refuses a buy with less than 180 TGas attached (real wasm: "attach at least 180 TGas").
pub const GAS_NEARRR_BUY: u64 = 185;
/// This account's balance of the output token, read before and after the buy (V16-02).
pub const GAS_BALANCE_VIEW: u64 = 5;
/// `on_nearrr_settled`: reads the after-balance, settles.
pub const GAS_CB_NEARRR_SETTLED: u64 = crate::GAS_CALLBACK;
/// `on_nearrr_before`: its own work + the buy + the after-balance view + the settle callback.
pub const GAS_CB_NEARRR_BEFORE: u64 = 8 + GAS_NEARRR_BUY + GAS_BALANCE_VIEW + GAS_CB_NEARRR_SETTLED;
/// `on_nearrr_tax`: its own work + the before-balance view + everything after it.
pub const GAS_CB_NEARRR: u64 = 8 + GAS_BALANCE_VIEW + GAS_CB_NEARRR_BEFORE;

/// The total bps a buy of this token loses after the pad's check, from its `tax_state` JSON
/// (`{"mode": "Standard" | "Tax" | .., "buy_tax_bps": n, ..}`). None = unreadable, an unknown
/// mode or above NEARRR_MAX_TAX_BPS: the buy is refused (clean refund).
pub fn nearrr_tax_bps(state: &[u8]) -> Option<u128> {
    #[derive(near_sdk::serde::Deserialize)]
    #[serde(crate = "near_sdk::serde")]
    struct TaxState {
        mode: String,
        buy_tax_bps: u16,
    }
    let st: TaxState = near_sdk::serde_json::from_slice(state).ok()?;
    let total = match st.mode.as_str() {
        "Standard" => NEARRR_STANDARD_TAX_BPS,
        "Tax" => u128::from(st.buy_tax_bps) + NEARRR_PLATFORM_TAX_BPS,
        _ => return None,
    };
    (total <= NEARRR_MAX_TAX_BPS).then_some(total)
}

/// The bound sent to the Nearrr pad so that the post-tax delivery is >= the user's `min_out`:
/// ceil(min_out x 10_000 / (10_000 - tax_bps)). Fail-closed: the pad refunds the whole buy when it
/// can't meet it. Sells are not affected: the pad checks the NEAR it pays out natively (untaxed).
pub fn nearrr_pad_min(min_out: u128, tax_bps: u128) -> Result<u128, &'static str> {
    if tax_bps > NEARRR_MAX_TAX_BPS {
        return Err(E_BAD_OP);
    }
    let n = min_out.checked_mul(10_000).ok_or(E_BAD_OP)?;
    Ok(n.div_ceil(10_000 - tax_bps))
}

fn nearrr_buy_plan(t: &CurveTrade, c: &Ctx, token: AccountId, dex: u16) -> Result<Plan, &'static str> {
    let f = &t.venue;
    let label = token.as_str().strip_suffix(&format!(".{f}")).ok_or(E_MARKET)?.as_bytes();
    let mut buf = [0u8; 48];
    buf.get_mut(..label.len()).ok_or(E_MARKET)?.copy_from_slice(label);
    let len = u8::try_from(label.len()).map_err(|_| E_MARKET)?;
    let view = fcall(&token, "tax_state", "{}".to_string(), 0, GAS_TAX_VIEW * TGAS);
    let mut p = buy_plan(
        t,
        c,
        BuyShape {
            calls: vec![view],
            settle: Settle::NearrrTax { min_out: t.min_out.0, dex, label: buf, len },
            extra: 0,
            out: token.clone(),
            order_dex: f.clone(),
            storage: vec![token],
            orderable: true,
        },
    );
    // the NEAR leaves in the callback's buy: counted here so run's reserve check sees it
    p.native_out = p.native_out.saturating_add(t.amount.0);
    // the op declares (and run budgets) the whole chain: view + callback (buy + settle inside)
    p.gas = (GAS_TAX_VIEW + GAS_CB_NEARRR - crate::GAS_CALLBACK) * TGAS;
    if p.gas > t.gas.0 {
        return Err(E_GAS);
    }
    Ok(p)
}

/// The callback `run` attaches to the tax view (via settle::callback).
pub fn nearrr_first_callback(
    settle_json: &str,
    min_out: u128,
    dex: u16,
    label: &[u8],
) -> (&'static str, String, u64) {
    let label = String::from_utf8_lossy(label);
    (
        "on_nearrr_tax",
        format!("{{\"settle\":{settle_json},\"min_out\":\"{min_out}\",\"dex\":{dex},\"label\":\"{label}\"}}"),
        GAS_CB_NEARRR,
    )
}

#[near]
impl TradingAccount {
    /// Nearrr buy step 2: after the token's `tax_state`. Read as the order-fire gate reads it
    /// (R2-06 owner rule, venues/tax.rs): a failed view receipt = 0 (the untaxed template has no
    /// tax_state); a result over 16 KiB, unparsable, an unknown mode or above the max -> a clean
    /// failed swap (no NEAR left: no fee, spend back, an order reopens). Else the pad buy with the
    /// tax-adjusted bound, settled as NearInFull.
    #[private]
    pub fn on_nearrr_tax(&mut self, settle: SettleArgs, min_out: U128, dex: u16, label: String) {
        let tax = match super::tax::read_view() {
            Ok(Some(b)) => nearrr_tax_bps(&b),
            Ok(None) => Some(0),
            Err(_) => None,
        };
        let pad_min = tax.and_then(|x| nearrr_pad_min(min_out.0, x).ok());
        let token = format!("{label}.{}", self.nearrr_factory(dex));
        let token: AccountId = token.parse().unwrap_or_else(|_| env::panic_str("E_STATE"));
        let Some(pad_min) = pad_min else {
            return self.nearrr_refused(settle, &token, tax.map_or("null".to_string(), |x| x.to_string()));
        };
        // step 3 needs this account's token balance BEFORE the buy (the refund proof, V16-02)
        let next = json!({"settle": settle, "token": token, "pad_min": pad_min.to_string(), "dex": dex});
        Promise::new(token.clone())
            .function_call(
                "ft_balance_of",
                json!({"account_id": env::current_account_id()}).to_string().into_bytes(),
                NearToken::from_yoctonear(0),
                Gas::from_tgas(GAS_BALANCE_VIEW),
            )
            .then(Promise::new(env::current_account_id()).function_call(
                "on_nearrr_before",
                next.to_string().into_bytes(),
                NearToken::from_yoctonear(0),
                Gas::from_tgas(GAS_CB_NEARRR_BEFORE),
            ))
            .detach();
    }

    /// Nearrr buy step 3: after the before-balance view. Sends the pad buy with the NEAR, then
    /// reads the balance again for `on_nearrr_settled`. Unreadable balance / no longer funded ->
    /// a clean failed swap (no NEAR left).
    #[private]
    pub fn on_nearrr_before(&mut self, settle: SettleArgs, token: AccountId, pad_min: U128, dex: u16) {
        let before = match env::promise_result_checked(0, 64) {
            Ok(b) => serde_json::from_slice::<U128>(&b).ok(),
            Err(_) => None,
        };
        let amount = settle.amount.0;
        // run reserved it (native_out), but a concurrent execute / withdraw may have spent it since:
        // the same reserve rule as run, checked before the deposit is scheduled (a callback that
        // attached more than it holds would fail after the fact, with no settle)
        let funded = crate::policy::check_reserve(crate::liquid_balance(), amount).is_ok();
        let (Some(before), true) = (before, funded) else {
            return self.nearrr_refused(settle, &token, "\"unfunded_or_no_balance\"".to_string());
        };
        let f = self.nearrr_factory(dex);
        let me = env::current_account_id();
        Promise::new(f)
            .function_call(
                "buy",
                json!({"token_id": token, "min_out": pad_min}).to_string().into_bytes(),
                NearToken::from_yoctonear(amount),
                Gas::from_tgas(GAS_NEARRR_BUY),
            )
            .then(Promise::new(token.clone()).function_call(
                "ft_balance_of",
                json!({"account_id": me}).to_string().into_bytes(),
                NearToken::from_yoctonear(0),
                Gas::from_tgas(GAS_BALANCE_VIEW),
            ))
            .then(Promise::new(me).function_call(
                "on_nearrr_settled",
                json!({"settle": settle, "before": before, "token": token}).to_string().into_bytes(),
                NearToken::from_yoctonear(0),
                Gas::from_tgas(GAS_CB_NEARRR_SETTLED),
            ))
            .detach();
    }

    /// Nearrr buy step 4. The pad's buy never panics on slippage: it refunds the whole NEAR by
    /// Transfer inside a successful receipt, and its result is the same ("") either way (sandbox,
    /// real wasm). The refund is proven by the OUTPUT TOKEN, never by a NEAR delta (V16-02): run
    /// took this token's lock (`lock_output`) for the whole buy, so no swap, Chain, device
    /// withdraw or cross-chain withdraw of it can run meanwhile (E_Q_BUSY), and nothing but the
    /// pad moves it down. No token received (after <= before) = refunded: nothing used, no fee,
    /// spend back, an order REOPENS (R2-05, UNR-A-02). Tokens received, or an unreadable
    /// after-balance: a fill with the full reserved fee. Tokens can only ARRIVE from elsewhere,
    /// which reads as a fill (the safe side).
    #[private]
    pub fn on_nearrr_settled(&mut self, settle: SettleArgs, before: U128, token: AccountId) {
        let mut settle = settle;
        // the proof holds only while this buy held the token the whole time (run's lock, not
        // expired and not re-taken): otherwise a no-token result is treated as V16-02 did
        let holder = lock_holder(&settle.client_order_id);
        let locked = crate::chain::lock_of(token.as_str()).is_some_and(|(h, _)| h == holder);
        crate::chain::unlock(token.as_str(), &holder);
        let after = match env::promise_result_checked(0, 64) {
            Ok(b) => serde_json::from_slice::<U128>(&b).ok(),
            Err(_) => None,
        };
        let received = after.map_or(1, |a| a.0.saturating_sub(before.0));
        if received == 0 {
            env::log_str(&format!(
                "EVENT_JSON:{{\"standard\":\"nttrade\",\"version\":\"1\",\"event\":\"nearrr_refunded\",\"data\":{{\"client_order_id\":{}}}}}",
                serde_json::to_string(&settle.client_order_id).unwrap_or_default()
            ));
            if locked {
                // an honest venue reporting "0" (UNR-A-02): spend back, an order reopens
                settle.proof = Some("token".into());
                return self.finish_settle(settle, false, 0, 0);
            }
            // unproven: used (spend kept, an order consumed), no fee
            let amount = settle.amount.0;
            return self.finish_settle(settle, false, amount, 0);
        }
        let (amount, fee) = (settle.amount.0, settle.fee.0);
        self.finish_settle(settle, false, amount, fee);
    }
}

/// The holder id of a Nearrr buy's output-token lock.
pub fn lock_holder(client_order_id: &str) -> String {
    format!("nearrr:{client_order_id}")
}

/// v1.6 hook for `run` (R2-05): a Nearrr buy locks its output token from the execute until
/// `on_nearrr_settled`, so the token-balance proof of a refund can't be faked by another op on
/// the same token. E_Q_BUSY if a route or another Nearrr buy holds it.
pub fn lock_output(p: &Plan, client_order_id: &str) {
    if matches!(p.settle, Settle::NearrrTax { .. }) {
        crate::chain::lock(&p.swap.out, &lock_holder(client_order_id));
    }
}

impl TradingAccount {
    fn nearrr_factory(&self, dex: u16) -> AccountId {
        self.dex_allowlist
            .get(usize::from(dex))
            .filter(|d| d.kind == DexKind::FactoryCurve(FactoryPad::Nearrr))
            .map(|d| d.id.clone())
            .unwrap_or_else(|| env::panic_str("E_STATE"))
    }

    /// Nothing sent to the pad: a clean failed swap (no fee, spend back, an order reopens).
    fn nearrr_refused(&mut self, settle: SettleArgs, token: &AccountId, why: String) {
        crate::chain::unlock(token.as_str(), &lock_holder(&settle.client_order_id));
        env::log_str(&format!(
            "EVENT_JSON:{{\"standard\":\"nttrade\",\"version\":\"1\",\"event\":\"nearrr_tax_refused\",\"data\":{{\"client_order_id\":{},\"tax_bps\":{}}}}}",
            serde_json::to_string(&settle.client_order_id).unwrap_or_default(),
            why
        ));
        self.finish_settle(settle, true, 0, 0);
    }
}

/// Deadline in ms (Nira).
fn deadline_ms(c: &Ctx) -> String {
    (c.deadline_ns() / 1_000_000).to_string()
}

pub fn nira_buy_msg(launch_id: &str, min_out: u128, deadline_ms: &str) -> String {
    json!({"buy": {"launch_id": launch_id, "min_tokens_out": min_out.to_string(), "deadline_ms": deadline_ms}})
        .to_string()
}

pub fn plan(pad: FactoryPad, buy: bool, t: &CurveTrade, c: &Ctx) -> Result<Plan, &'static str> {
    if t.max_out.is_some() {
        return Err(E_BAD_OP);
    }
    let f = &t.venue;
    let (a, m, g) = (t.amount.0, t.min_out.0, t.gas.0);
    let sell_ft = |token: AccountId, msg: String| -> Plan {
        let call = ft_call(&token, f, a, &msg, g);
        sell_plan(
            t,
            c,
            SellShape {
                calls: vec![call],
                settle: Settle::Token,
                token_in: token.clone(),
                order_dex: f.clone(),
                storage: vec![token],
            },
        )
    };
    // `full`: the pad never refunds part of a SUCCESSFUL buy (slippage panics, or refunds all of it
    // by Transfer as Nearrr does): Settle::NearInFull charges the whole fee on success (gas
    // refunds can't shave it) and treats a measured full refund as an honest "0". Otherwise
    // (Vista's curve-completion `refund`): Settle::NearIn, fee on amount - measured refund.
    let payable_buy =
        |method: &'static str, args: String, extra: u128, token: AccountId, full: bool| -> Plan {
            buy_plan(
                t,
                c,
                BuyShape {
                    calls: vec![fcall(f, method, args, a.saturating_add(extra), g)],
                    settle: if full { Settle::NearInFull } else { Settle::NearIn },
                    extra,
                    out: token.clone(),
                    order_dex: f.clone(),
                    storage: vec![token],
                    orderable: true,
                },
            )
        };
    Ok(match (pad, buy) {
        (FactoryPad::VistaLaunch, true) => {
            near_only(t)?;
            let token = vista_token(t)?;
            let args = json!({"token_id": token, "min_out": m.to_string()}).to_string();
            payable_buy("buy", args, VISTA_BUY_STORAGE, token, false)
        }
        (FactoryPad::VistaLaunch, false) => {
            near_only(t)?;
            sell_ft(vista_token(t)?, json!({"sell": {"min_out": m.to_string()}}).to_string())
        }
        (FactoryPad::VistaDex, true) => {
            near_only(t)?;
            let token = vista_token(t)?;
            let args = json!({"token_id": token, "min_out": m.to_string()}).to_string();
            payable_buy("swap_near_for_token", args, 0, token, true)
        }
        (FactoryPad::VistaDex, false) => {
            near_only(t)?;
            sell_ft(vista_token(t)?, json!({"swap_to_near": {"min_out": m.to_string()}}).to_string())
        }
        (FactoryPad::Nearrr, true) => {
            near_only(t)?;
            let token = factory_token(t)?;
            // `dex` is set by venues::plan (the allowlist index of this factory)
            nearrr_buy_plan(t, c, token, 0)?
        }
        (FactoryPad::Nearrr, false) => {
            near_only(t)?;
            sell_ft(factory_token(t)?, json!({"sell": {"min_out": m.to_string()}}).to_string())
        }
        (FactoryPad::Dragonpad, true) => {
            // dragonpad buys are NEAR only (no ft_on_transfer buy variant, trading-plan §1.10)
            near_only(t)?;
            let token = factory_token(t)?;
            let args = json!({"token_id": token, "min_tokens_out": m.to_string()}).to_string();
            payable_buy("buy", args, 0, token, true)
        }
        (FactoryPad::Dragonpad, false) => {
            near_only(t)?;
            sell_ft(factory_token(t)?, json!({"sell": {"min_quote_out": m.to_string()}}).to_string())
        }
        (FactoryPad::Nira, true) => {
            let launch = market_str(&t.market)?;
            let pos = synthetic(launch, f)?;
            match &t.quote {
                None => {
                    let args = json!({"launch_id": launch, "min_tokens_out": m.to_string(),
                        "deadline_ms": deadline_ms(c)})
                    .to_string();
                    let mut p = payable_buy("buy", args, NIRA_BUY_STORAGE, pos, true);
                    // internal balance: nothing to register (the synthetic id is not an account)
                    p.storage = vec![];
                    p
                }
                Some(q) => {
                    let call = ft_call(q, f, a, &nira_buy_msg(launch, m, &deadline_ms(c)), g);
                    buy_plan(
                        t,
                        c,
                        BuyShape {
                            calls: vec![call],
                            settle: Settle::Token,
                            extra: 0,
                            out: pos,
                            order_dex: f.clone(),
                            storage: vec![],
                            orderable: true,
                        },
                    )
                }
            }
        }
        (FactoryPad::Nira, false) => {
            let launch = market_str(&t.market)?;
            let args = json!({"launch_id": launch, "token_in": a.to_string(), "min_out": m.to_string(),
                "deadline_ms": deadline_ms(c)})
            .to_string();
            let native = t.quote.is_none();
            let mut storage = vec![];
            if let Some(q) = &t.quote {
                storage.push(q.clone());
            }
            sell_plan(
                t,
                c,
                SellShape {
                    calls: vec![fcall(f, "sell", args, 1, g)],
                    settle: Settle::Out { native, reported: false, wnear: false },
                    token_in: synthetic(launch, f)?,
                    order_dex: f.clone(),
                    storage,
                },
            )
        }
        (FactoryPad::MemeCooking, true) => {
            // presale deposit (wNEAR); no price, refundable with CurveClaim withdraw; never an order
            near_only(t)?;
            let meme = super::market_u64(&t.market)?;
            let msg = json!({"Deposit": {"meme_id": meme}}).to_string();
            let call = ft_call(c.wrap, f, a, &msg, g);
            let out = synthetic(&meme.to_string(), f)?;
            buy_plan(
                t,
                c,
                BuyShape {
                    calls: vec![call],
                    settle: Settle::Wrap,
                    extra: 0,
                    out,
                    order_dex: f.clone(),
                    storage: vec![],
                    orderable: false,
                },
            )
        }
        (FactoryPad::MemeCooking, false) => return Err(E_BAD_OP),
    })
}
