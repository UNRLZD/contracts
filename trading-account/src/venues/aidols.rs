//! Aidols codebase factories (aidols.near, gra-fun.near, gaypad.j1-racing.near,
//! v1/v2.whole-market.near, patata-monster.near). The curve is held by the factory
//! (trading-plan §1.3, all (C)):
//! - buy: `Q.ft_transfer_call{receiver_id: factory, msg: {"token":"<t>","min_swap_amount"}}`,
//!   the factory `ft_transfer`s the token to the sender (= self);
//! - sell: `t.ft_transfer_call{receiver_id: factory, msg: {"token":null,"min_swap_amount"}}`,
//!   the factory `ft_transfer`s Q to the sender.
//!
//! Q is the factory's one quote: wNEAR (aidols, gra-fun), PATATA (patata-monster), JAMBO
//! (gaypad), NEARDOG (whole-market v1/v2). `referral` / `refferal` are never sent.
//! aidols doesn't check registration before its output ft_transfer: the planned storage target
//! lets a `StorageDeposit` op on the output token precede the trade.
use super::*;
use near_sdk::serde_json::json;

/// The msg the contract builds (also what `msg_venues` accepts).
pub fn msg(token: Option<&AccountId>, min_out: u128) -> String {
    json!({"token": token, "min_swap_amount": min_out.to_string()}).to_string()
}

pub fn plan(pad: AidolsPad, buy: bool, t: &CurveTrade, c: &Ctx) -> Result<Plan, &'static str> {
    let q = aidols_quote(pad, c.wrap);
    // the op's quote (None = NEAR = wNEAR) must be the pad's only quote
    if t.quote.clone().unwrap_or_else(|| c.wrap.clone()) != q || t.max_out.is_some() {
        return Err(E_QUOTE);
    }
    let token = market_token(&t.market)?;
    if !one_label_under(&t.venue, &token) {
        return Err(E_MARKET);
    }
    if buy {
        let call = ft_call(&q, &t.venue, t.amount.0, &msg(Some(&token), t.min_out.0), t.gas.0);
        let settle = if &q == c.wrap { Settle::Wrap } else { Settle::Token };
        Ok(buy_plan(
            t,
            c,
            BuyShape {
                // registration first: the factory keeps the input of an unregistered buyer
                calls: vec![storage_call(&token, c.me), call],
                settle,
                extra: 0,
                out: token.clone(),
                order_dex: t.venue.clone(),
                storage: vec![token],
                orderable: true,
            },
        ))
    } else {
        let call = ft_call(&token, &t.venue, t.amount.0, &msg(None, t.min_out.0), t.gas.0);
        // a Q payout to an unregistered account would be lost the same way (wNEAR: registered by init)
        let calls = if &q == c.wrap { vec![call] } else { vec![storage_call(&q, c.me), call] };
        Ok(sell_plan(
            t,
            c,
            SellShape {
                calls,
                // the sold token's resolve reports what was used; the output is Q by ft_transfer
                settle: Settle::Token,
                token_in: token.clone(),
                order_dex: t.venue.clone(),
                storage: vec![token, q],
            },
        ))
    }
}
