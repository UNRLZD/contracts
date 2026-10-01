//! Token-held curves: the venue is the token `<label>.<factory>` itself (trading-plan §1.1, 1.2,
//! 1.5, 1.6, 1.10 token0 / chipfi / npad).
//!
//! | pad | buy (NEAR) | buy (Q) | sell |
//! |---|---|---|---|
//! | NearFun | `buy{min_tokens_out}` payable | – | `sell{amount, min_near_out}` 1 yocto, native |
//! | Umbra | `buy{min_out}` payable | `Q.ft_transfer_call{T, {"action":"buy","min_out"}}` | `sell{amount, min_out}` 1 yocto, native or Q |
//! | RevShare | `wrap.ft_transfer_call{T, {"buy":{min_tokens_out, deadline_ns}}}` | – | `sell{amount, min_quote_out, deadline_ns}` 1 yocto, wNEAR payout |
//! | nearmemefun | `buy{min_tokens_out, deadline_sec}` payable | – | `sell{tokens_in, min_near_out, deadline_sec}` 1 yocto (credits) + `withdraw_near{amount: min_out}` 1 yocto, one batch |
//! | token0 | `buy{max_token_amount, min_token_amount, receiver_id: self, referral_id: null}` payable, exact-out + refund | – | `sell{token_amount, min_near_output_amount, receiver_id: self}` deposit 0, returns NEAR |
//! | chipfi | `buy{min_out, for_account: null}` payable | `Q.ft_transfer_call{T, {"min_out"}}` | `sell{amount, min_out}` + `claim{}` one batch, deposit 0 |
//! | npad | `buy{min_tokens_out}` payable | – | `sell{amount, min_near_out}` 1 yocto (min_near_out always sent) |
use super::*;
use near_sdk::serde_json::json;

/// Gas of nearmemefun's `withdraw_near` (it refuses < 60 TGas: "ATTACH_60_TGAS"; 59 fails).
pub const NEARMEMEFUN_WITHDRAW_TGAS: u64 = 80;

pub fn umbra_buy_msg(min_out: u128) -> String {
    json!({"action": "buy", "min_out": min_out.to_string()}).to_string()
}
pub fn revshare_buy_msg(min_out: u128, deadline_ns: u64) -> String {
    json!({"buy": {"min_tokens_out": min_out.to_string(), "deadline_ns": deadline_ns.to_string()}})
        .to_string()
}
pub fn chipfi_buy_msg(min_out: u128) -> String {
    json!({"min_out": min_out.to_string()}).to_string()
}

pub fn plan(pad: TokenPad, buy: bool, t: &CurveTrade, c: &Ctx) -> Result<Plan, &'static str> {
    let tok = &t.venue;
    if t.market.is_some() || (t.max_out.is_some() && !(buy && pad == TokenPad::Token0)) {
        return Err(E_BAD_OP);
    }
    let (a, m, g) = (t.amount.0, t.min_out.0, t.gas.0);
    let dl_ns = c.deadline_ns();
    let q = t.quote.clone();
    // pads with a quote-token path
    let q_ok = matches!(pad, TokenPad::Umbra | TokenPad::Chipfi);
    if q.is_some() && !q_ok {
        return Err(E_QUOTE);
    }
    if buy {
        let (calls, settle) = match (pad, &q) {
            (TokenPad::Umbra, Some(q)) => (vec![ft_call(q, tok, a, &umbra_buy_msg(m), g)], Settle::Token),
            (TokenPad::Chipfi, Some(q)) => (vec![ft_call(q, tok, a, &chipfi_buy_msg(m), g)], Settle::Token),
            (TokenPad::RevShare, None) => {
                (vec![ft_call(c.wrap, tok, a, &revshare_buy_msg(m, dl_ns), g)], Settle::Wrap)
            }
            (_, None) => {
                let (method, args) = match pad {
                    TokenPad::NearFun | TokenPad::Npad => ("buy", json!({"min_tokens_out": m.to_string()})),
                    TokenPad::Umbra => ("buy", json!({"min_out": m.to_string()})),
                    TokenPad::Nearmemefun => (
                        "buy",
                        json!({"min_tokens_out": m.to_string(), "deadline_sec": dl_ns / 1_000_000_000}),
                    ),
                    TokenPad::Token0 => {
                        let max = t.max_out.ok_or(E_BAD_OP)?.0;
                        if max < m {
                            return Err(E_BAD_OP);
                        }
                        (
                            "buy",
                            json!({"max_token_amount": max.to_string(), "min_token_amount": m.to_string(),
                                "receiver_id": c.me, "referral_id": null}),
                        )
                    }
                    TokenPad::Chipfi => ("buy", json!({"min_out": m.to_string(), "for_account": null})),
                    TokenPad::RevShare => return Err(E_BAD_OP),
                };
                (vec![fcall(tok, method, args.to_string(), a, g)], Settle::NearIn)
            }
            _ => return Err(E_QUOTE),
        };
        return Ok(buy_plan(
            t,
            c,
            BuyShape {
                calls,
                settle,
                extra: 0,
                out: tok.clone(),
                order_dex: tok.clone(),
                storage: vec![tok.clone()],
                orderable: true,
            },
        ));
    }
    // sells: the token is the input; payout native NEAR unless noted
    let native = q.is_none();
    let out = |reported: bool| Settle::Out { native, reported, wnear: false };
    let (calls, settle) = match pad {
        TokenPad::NearFun | TokenPad::Npad => (
            vec![fcall(tok, "sell", json!({"amount": a.to_string(), "min_near_out": m.to_string()}).to_string(), 1, g)],
            out(false),
        ),
        TokenPad::Umbra => (
            vec![fcall(tok, "sell", json!({"amount": a.to_string(), "min_out": m.to_string()}).to_string(), 1, g)],
            out(false),
        ),
        TokenPad::RevShare => (
            vec![fcall(
                tok,
                "sell",
                json!({"amount": a.to_string(), "min_quote_out": m.to_string(), "deadline_ns": dl_ns.to_string()})
                    .to_string(),
                1,
                g,
            )],
            // wNEAR by ft_transfer (not measurable as native): fee on the min_out bound
            Settle::Out { native: false, reported: false, wnear: true },
        ),
        TokenPad::Nearmemefun => {
            // Sandbox (real 4esYjDAn token): `sell` only CREDITS the NEAR (`get_claim.available`,
            // returns the amount); `withdraw_near{amount}` (exactly 1 yocto, >= 60 TGas, one
            // pending withdrawal at a time) pays it. Same batch: withdraw exactly min_out (the
            // credited amount is >= min_out when the sell succeeds); any excess stays as the pad's
            // claim of this account (recoverable with another withdraw_near).
            let wd_g = NEARMEMEFUN_WITHDRAW_TGAS * TGAS;
            let sell_g = g.checked_sub(wd_g).filter(|x| *x >= MIN_CURVE_GAS * TGAS).ok_or(E_GAS)?;
            (
                vec![
                    fcall(
                        tok,
                        "sell",
                        json!({"tokens_in": a.to_string(), "min_near_out": m.to_string(),
                            "deadline_sec": dl_ns / 1_000_000_000})
                        .to_string(),
                        1,
                        sell_g,
                    ),
                    fcall(tok, "withdraw_near", json!({"amount": m.to_string()}).to_string(), 1, wd_g),
                ],
                out(false),
            )
        }
        TokenPad::Token0 => (
            vec![fcall(
                tok,
                "sell",
                json!({"token_amount": a.to_string(), "min_near_output_amount": m.to_string(), "receiver_id": c.me})
                    .to_string(),
                0,
                g,
            )],
            // returns the NEAR amount paid (C 6jG9AQWN)
            out(true),
        ),
        TokenPad::Chipfi => {
            // proceeds are only credited; claim{} in the same batch pays them (C AoxWzw9j, FeugVkBL).
            // Gas: the op's gas is split, the claim gets GAS_CURVE_CLAIM.
            let claim_g = GAS_CURVE_CLAIM * TGAS;
            let sell_g = g.checked_sub(claim_g).filter(|x| *x >= MIN_CURVE_GAS * TGAS).ok_or(E_GAS)?;
            (
                vec![
                    fcall(tok, "sell", json!({"amount": a.to_string(), "min_out": m.to_string()}).to_string(), 0, sell_g),
                    fcall(tok, "claim", "{}".to_string(), 0, claim_g),
                ],
                out(false),
            )
        }
    };
    let mut storage = vec![tok.clone()];
    if let Some(q) = &q {
        storage.push(q.clone());
    }
    Ok(sell_plan(t, c, SellShape { calls, settle, token_in: tok.clone(), order_dex: tok.clone(), storage }))
}
