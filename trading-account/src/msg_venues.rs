//! v1.6 FtTransferCall parsers for launchpad venues (trading-plan §4.3). Pure, strict:
//! `deny_unknown_fields` everywhere (so no recipient / `buy_for` / `for_account` / referral key can
//! slip through), `min > 0`, output token derived from the venue, never from the msg alone.
//!
//! `receiver` = the ft_transfer_call `receiver_id` (factory, or the token for TokenCurve);
//! `token_in` = the token the call is made on.
use crate::msg::{DexKind, Swap, E_BAD_MSG, E_MIN_OUT, E_REFERRER};
use crate::venues::{self, FactoryPad, TokenPad};
use near_sdk::json_types::U128;
use near_sdk::serde::Deserialize;
use near_sdk::serde_json;
use near_sdk::AccountId;

pub struct VCtx<'a> {
    pub self_id: &'a AccountId,
    pub wrap: &'a AccountId,
    pub token_in: &'a AccountId,
    pub receiver: &'a AccountId,
    pub referrer: &'a AccountId,
}

fn swap(out: &AccountId, out_is_near: bool, min: u128) -> Result<Swap, &'static str> {
    if min == 0 {
        return Err(E_MIN_OUT);
    }
    Ok(Swap { out_is_near, min_out: min, out: out.to_string() })
}

fn from<'a, T: Deserialize<'a>>(msg: &'a str) -> Result<T, &'static str> {
    serde_json::from_str(msg).map_err(|_| E_BAD_MSG)
}

// Aidols family: {"token": "<t>" | null, "min_swap_amount"}
#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde", deny_unknown_fields)]
struct AidolsMsg {
    token: Option<AccountId>,
    min_swap_amount: U128,
}

// {"sell":{"min_out"}} (Nearrr, Vista launch)
#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde", deny_unknown_fields)]
struct MinOut {
    min_out: U128,
}
#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde", deny_unknown_fields)]
struct SellMsg {
    sell: MinOut,
}
#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde", deny_unknown_fields)]
struct SwapToNear {
    swap_to_near: MinOut,
}
#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde", deny_unknown_fields)]
struct MinQuoteOut {
    min_quote_out: U128,
}
#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde", deny_unknown_fields)]
struct DragonSell {
    sell: MinQuoteOut,
}
#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde", deny_unknown_fields)]
struct NiraBuyBody {
    launch_id: String,
    min_tokens_out: U128,
    deadline_ms: U128,
}
#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde", deny_unknown_fields)]
struct NiraBuy {
    buy: NiraBuyBody,
}
#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde", deny_unknown_fields)]
struct MemeDepositBody {
    meme_id: u64,
    #[serde(default)]
    referrer: Option<AccountId>,
}
#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde", deny_unknown_fields)]
enum MemeMsg {
    Deposit(MemeDepositBody),
}
#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde", deny_unknown_fields)]
struct UmbraBuy {
    action: String,
    min_out: U128,
}
#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde", deny_unknown_fields)]
struct RevBuyBody {
    min_tokens_out: U128,
    deadline_ns: U128,
}
#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde", deny_unknown_fields)]
struct RevBuy {
    buy: RevBuyBody,
}

fn under(f: &AccountId, t: &AccountId) -> Result<(), &'static str> {
    if venues::one_label_under(f, t) {
        Ok(())
    } else {
        Err(E_BAD_MSG)
    }
}

/// Parses the msg of `token_in.ft_transfer_call{receiver_id: receiver, msg}` for a curve venue.
pub fn parse(kind: DexKind, msg: &str, c: &VCtx) -> Result<Swap, &'static str> {
    let (r, t) = (c.receiver, c.token_in);
    if t == c.self_id || r == c.self_id {
        return Err(E_BAD_MSG);
    }
    match kind {
        DexKind::AidolsCurve(pad) => {
            let q: AccountId = venues::aidols_quote(pad, c.wrap);
            let m: AidolsMsg = from(msg)?;
            match m.token {
                // buy: pay Q, receive <token>
                Some(tok) => {
                    if t != &q {
                        return Err(E_BAD_MSG);
                    }
                    under(r, &tok)?;
                    swap(&tok, false, m.min_swap_amount.0)
                }
                // sell: pay the factory's token, receive Q
                None => {
                    under(r, t)?;
                    swap(&q, &q == c.wrap, m.min_swap_amount.0)
                }
            }
        }
        DexKind::FactoryCurve(pad) => match pad {
            FactoryPad::Nearrr => {
                under(r, t)?;
                let m: SellMsg = from(msg)?;
                swap(c.wrap, true, m.sell.min_out.0)
            }
            // Vista tokens live under the launch factory (or are vista.vistadev.near), both stages
            FactoryPad::VistaLaunch => {
                if !venues::factory::is_vista_token(t) {
                    return Err(E_BAD_MSG);
                }
                let m: SellMsg = from(msg)?;
                swap(c.wrap, true, m.sell.min_out.0)
            }
            FactoryPad::VistaDex => {
                if !venues::factory::is_vista_token(t) {
                    return Err(E_BAD_MSG);
                }
                let m: SwapToNear = from(msg)?;
                swap(c.wrap, true, m.swap_to_near.min_out.0)
            }
            FactoryPad::Dragonpad => {
                under(r, t)?;
                let m: DragonSell = from(msg)?;
                swap(c.wrap, true, m.sell.min_quote_out.0)
            }
            FactoryPad::Nira => {
                // pair buy (Q -> internal balance of launch_id)
                let m: NiraBuy = from(msg)?;
                venues::check_market(&m.buy.launch_id)?;
                if m.buy.deadline_ms.0 == 0 {
                    return Err(E_BAD_MSG);
                }
                let pos = venues::synthetic(&m.buy.launch_id, r)?;
                swap(&pos, false, m.buy.min_tokens_out.0)
            }
            FactoryPad::MemeCooking => {
                // presale deposit of wNEAR; no output price (min_out symbolic 1, never an order)
                if t != c.wrap {
                    return Err(E_BAD_MSG);
                }
                let MemeMsg::Deposit(d) = from(msg)?;
                if d.referrer.as_ref().is_some_and(|x| x != c.referrer) {
                    return Err(E_REFERRER);
                }
                let pos = venues::synthetic(&d.meme_id.to_string(), r)?;
                swap(&pos, false, 1)
            }
        },
        DexKind::TokenCurve(pad) => match pad {
            TokenPad::Umbra => {
                let m: UmbraBuy = from(msg)?;
                if m.action != "buy" || t == c.wrap {
                    return Err(E_BAD_MSG);
                }
                swap(r, false, m.min_out.0)
            }
            TokenPad::RevShare => {
                if t != c.wrap {
                    return Err(E_BAD_MSG);
                }
                let m: RevBuy = from(msg)?;
                if m.buy.deadline_ns.0 == 0 {
                    return Err(E_BAD_MSG);
                }
                swap(r, false, m.buy.min_tokens_out.0)
            }
            TokenPad::Chipfi => {
                if t == c.wrap {
                    return Err(E_BAD_MSG);
                }
                let m: MinOut = from(msg)?;
                swap(r, false, m.min_out.0)
            }
            _ => Err(E_BAD_MSG),
        },
        // Kelytra: a deposit has no output bound; typed ops only (CurveBuy/CurveSell + claims)
        _ => Err(E_BAD_MSG),
    }
}
