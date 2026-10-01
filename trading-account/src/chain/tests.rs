//! v1.6 routes: every validation code of routing C.1 / C.2.2 / C.2.4, the per-Q lock, the route
//! table bound and the owner rule "the relayer can never fund 1Click" (mocked chain).
use super::exec::*;
use super::quote::{self, Rules};
use super::*;
use crate::policy::NS_PER_SEC;
use crate::{Caps, FeeConfig, Order, TradingAccount};
use ed25519_dalek::{Signer, SigningKey};
use near_sdk::mock::MockAction;
use near_sdk::serde_json::{json, Map, Value};
use near_sdk::test_utils::{get_created_receipts, get_logs, VMContextBuilder};
use near_sdk::{env, testing_env, Gas, NearToken, PromiseResult, PublicKey};

const NEAR: u128 = 1_000_000_000_000_000_000_000_000;
const T0: u64 = 1_800_000_000_000_000_000;
const ADDR: &str = "1f2e3d4c5b6a79881f2e3d4c5b6a79881f2e3d4c5b6a79881f2e3d4c5b6a7988";

fn a(s: &str) -> AccountId {
    s.parse().unwrap()
}
fn me() -> AccountId {
    a("abcd.tt.near")
}
fn wrap() -> AccountId {
    a("wrap.near")
}
fn q() -> AccountId {
    a("zec.omft.near")
}

fn allow() -> Vec<Dex> {
    vec![
        Dex { id: a("v2.ref-finance.near"), kind: DexKind::RheaClassic },
        Dex { id: a("dclv2.ref-labs.near"), kind: DexKind::RheaDcl },
        Dex { id: a("dex.intear.near"), kind: DexKind::Plach },
        Dex { id: a("nearrr-fun.near"), kind: DexKind::FactoryCurve(venues::FactoryPad::Nearrr) },
        Dex { id: a("umbrafun.near"), kind: DexKind::TokenCurve(venues::TokenPad::Umbra) },
        Dex { id: a("factory.shardsmarket.near"), kind: DexKind::ShardsToken },
    ]
}

fn env_at<'a>(m: &'a AccountId, w: &'a AccountId, al: &'a [Dex], r: &'a AccountId, now: u64) -> Env<'a> {
    Env { me: m, wrap: w, allow: al, referrer: r, fee_bps: 100, now_ns: now }
}

fn classic(pool: u64, tin: &str, tout: &str, amount_in: Option<u128>, min: u128) -> String {
    let mut act = json!({"pool_id": pool, "token_in": tin, "token_out": tout, "amount_out": "0",
        "min_amount_out": min.to_string()});
    if let Some(x) = amount_in {
        act["amount_in"] = json!(x.to_string());
    }
    json!({"force": 0, "actions": [act], "skip_unwrap_near": true}).to_string()
}

fn dcl(pools: &[&str], out: &str, min: u128) -> String {
    json!({"Swap": {"pool_ids": pools, "output_token": out, "min_output_amount": min.to_string()}})
        .to_string()
}

fn leg1(amount: u128, min: u128) -> ChainLeg {
    ChainLeg::FtTransferCall {
        token: wrap(),
        receiver_id: a("v2.ref-finance.near"),
        amount: U128(amount),
        msg: classic(6065, "wrap.near", "zec.omft.near", Some(amount), min),
        gas: U64(80 * TGAS),
    }
}

fn leg2(min: u128) -> ChainLeg {
    ChainLeg::FtTransferCall {
        token: q(),
        receiver_id: a("dclv2.ref-labs.near"),
        amount: U128(0),
        msg: dcl(&["zec.omft.near|jensen.near|10000"], "jensen.near", min),
        gas: U64(80 * TGAS),
    }
}

fn chain(min_mid: u128, max_mid: u128, min_final: u128) -> Chain {
    Chain {
        leg1: leg1(NEAR, min_mid),
        leg2: leg2(min_final),
        q: q(),
        min_mid: U128(min_mid),
        max_mid: U128(max_mid),
        min_final: U128(min_final),
    }
}

fn check(c: &Chain) -> Result<ChainPlan, &'static str> {
    let (m, w, al, r) = (me(), wrap(), allow(), a("fees.near"));
    check_chain(&env_at(&m, &w, &al, &r, T0), c, false, None)
}

// ======================= C.1 validation =======================

#[test]
fn chain_happy_path_plan() {
    let p = check(&chain(100, 110, 50)).unwrap();
    assert_eq!(p.token_in, "wrap.near");
    assert_eq!(p.token_out, "jensen.near");
    assert_eq!(p.counted, NEAR, "the NEAR leg is leg 1's input");
    assert_eq!(p.fee, NEAR / 100);
    assert_eq!(p.gas, (160 + CHAIN_OVERHEAD_TGAS) * TGAS);
    assert!(p.l2.is_some() && p.fund.is_none());
}

#[test]
fn chain_rule_codes() {
    // min bounds
    assert_eq!(check(&chain(0, 110, 50)), Err(E_CHAIN_MIN));
    assert_eq!(check(&chain(100, 110, 0)), Err(E_CHAIN_MIN));
    assert_eq!(check(&chain(111, 110, 50)), Err(E_CHAIN_MID), "min_mid > max_mid");
    // leg 1 bound below min_mid
    let mut c = chain(100, 200, 50);
    c.leg1 = leg1(NEAR, 99);
    assert_eq!(check(&c), Err(E_CHAIN_MID));
    // leg 2 bound below min_final
    let mut c = chain(100, 110, 50);
    c.leg2 = leg2(49);
    assert_eq!(check(&c), Err(E_CHAIN_MIN));
    // leg 1 output is not q
    let mut c = chain(100, 110, 50);
    c.q = a("usdc.near");
    assert_eq!(check(&c), Err(E_CHAIN_LEG));
    // leg 2 input is not q
    let mut c = chain(100, 110, 50);
    c.leg2 = ChainLeg::FtTransferCall {
        token: a("usdc.near"),
        receiver_id: a("dclv2.ref-labs.near"),
        amount: U128(0),
        msg: dcl(&["usdc.near|jensen.near|10000"], "jensen.near", 50),
        gas: U64(80 * TGAS),
    };
    assert_eq!(check(&c), Err(E_CHAIN_LEG));
    // IntentsFund as leg 1; Plach NEAR buy as leg 2
    let mut c = chain(100, 110, 50);
    c.leg1 = ChainLeg::IntentsFund { signed_quote: "{}".into(), signature: "x".into() };
    assert_eq!(check(&c), Err(E_CHAIN_LEG));
    let mut c = chain(100, 110, 50);
    c.leg2 = ChainLeg::PlachDepositNear {
        dex: a("dex.intear.near"),
        amount: U128(0),
        msg: "{}".into(),
        gas: U64(80 * TGAS),
    };
    assert_eq!(check(&c), Err(E_CHAIN_LEG));
}

#[test]
fn chain_same_dex_refused() {
    let mut c = chain(100, 110, 50);
    c.leg2 = ChainLeg::FtTransferCall {
        token: q(),
        receiver_id: a("v2.ref-finance.near"),
        amount: U128(0),
        msg: classic(7000, "zec.omft.near", "jensen.near", None, 50),
        gas: U64(80 * TGAS),
    };
    assert_eq!(check(&c), Err(E_CHAIN_SAME_DEX));
}

#[test]
fn chain_leg2_amount_is_the_contracts() {
    // op amount must be "0"
    let mut c = chain(100, 110, 50);
    if let ChainLeg::FtTransferCall { amount, .. } = &mut c.leg2 {
        *amount = U128(5);
    }
    assert_eq!(check(&c), Err(E_CHAIN_LEG2_AMOUNT));
    // a classic leg 2 fixing amount_in in its first action
    let mut c = chain(100, 110, 50);
    c.leg1 = ChainLeg::FtTransferCall {
        token: wrap(),
        receiver_id: a("dclv2.ref-labs.near"),
        amount: U128(NEAR),
        msg: dcl(&["wrap.near|zec.omft.near|2000"], "zec.omft.near", 100),
        gas: U64(80 * TGAS),
    };
    c.leg2 = ChainLeg::FtTransferCall {
        token: q(),
        receiver_id: a("v2.ref-finance.near"),
        amount: U128(0),
        msg: classic(7000, "zec.omft.near", "jensen.near", Some(5), 50),
        gas: U64(80 * TGAS),
    };
    assert_eq!(check(&c), Err(E_CHAIN_LEG2_AMOUNT));
    // leg 1 amount 0
    let mut c = chain(100, 110, 50);
    c.leg1 = leg1(0, 100);
    assert_eq!(check(&c), Err("E_BAD_OP"));
    // curve leg 2 with a nonzero op amount
    let mut c = chain(100, 110, 50);
    c.leg2 = ChainLeg::CurveBuy(venues::CurveTrade {
        venue: a("apple.umbrafun.near"),
        market: None,
        quote: Some(q()),
        amount: U128(7),
        min_out: U128(50),
        max_out: None,
        gas: U64(80 * TGAS),
        setup: false,
    });
    assert_eq!(check(&c), Err(E_CHAIN_LEG2_AMOUNT));
}

#[test]
fn chain_curve_leg2_ok() {
    let mut c = chain(100, 110, 50);
    c.leg2 = ChainLeg::CurveBuy(venues::CurveTrade {
        venue: a("apple.umbrafun.near"),
        market: None,
        quote: Some(q()),
        amount: U128(0),
        min_out: U128(50),
        max_out: None,
        gas: U64(80 * TGAS),
        setup: false,
    });
    let p = check(&c).unwrap();
    assert_eq!(p.token_out, "apple.umbrafun.near");
    assert_eq!(p.l2.unwrap().dex, a("apple.umbrafun.near"));
}

#[test]
fn chain_overlap_refused() {
    // leg 1's DCL pool passes through token_out
    let mut c = chain(100, 110, 50);
    c.leg1 = ChainLeg::FtTransferCall {
        token: wrap(),
        receiver_id: a("dclv2.ref-labs.near"),
        amount: U128(NEAR),
        msg: dcl(&["wrap.near|jensen.near|2000", "jensen.near|zec.omft.near|2000"], "zec.omft.near", 100),
        gas: U64(80 * TGAS),
    };
    c.leg2 = ChainLeg::FtTransferCall {
        token: q(),
        receiver_id: a("v2.ref-finance.near"),
        amount: U128(0),
        msg: classic(7000, "zec.omft.near", "jensen.near", None, 50),
        gas: U64(80 * TGAS),
    };
    assert_eq!(check(&c), Err(E_CHAIN_OVERLAP));
}

#[test]
fn chain_gas_budget() {
    let mut c = chain(100, 110, 50);
    if let ChainLeg::FtTransferCall { gas, .. } = &mut c.leg1 {
        *gas = U64(200 * TGAS);
    }
    if let ChainLeg::FtTransferCall { gas, .. } = &mut c.leg2 {
        *gas = U64(150 * TGAS);
    }
    assert_eq!(check(&c), Err(E_CHAIN_GAS));
    // the limit itself passes: leg1 + leg2 + overhead == MAX_CHAIN_GAS
    let mut c = chain(100, 110, 50);
    let room = MAX_CHAIN_GAS - CHAIN_OVERHEAD_TGAS - 80;
    if let ChainLeg::FtTransferCall { gas, .. } = &mut c.leg1 {
        *gas = U64(room * TGAS);
    }
    assert_eq!(check(&c).unwrap().gas, MAX_CHAIN_GAS * TGAS);
}

#[test]
fn chain_order_fire_cannot_fund_1click() {
    let (m, w, al, r) = (me(), wrap(), allow(), a("fees.near"));
    let mut c = chain(100, 110, 50);
    c.leg2 = ChainLeg::IntentsFund { signed_quote: "{}".into(), signature: "ed25519:x".into() };
    assert_eq!(check_chain(&env_at(&m, &w, &al, &r, T0), &c, true, Some(50)), Err(E_ORDER_OPS));
}

fn order(min_out: u128) -> Order {
    Order {
        token_in: wrap(),
        token_out: a("jensen.near"),
        amount_in: U128(NEAR),
        min_out: U128(min_out),
        trigger_meta: String::new(),
        expires_at_ns: U64(T0 + 1),
        dexes: vec![a("v2.ref-finance.near"), a("dclv2.ref-labs.near")],
        pending: false,
    }
}

fn via() -> OrderVia {
    OrderVia {
        q: q(),
        leg1_dex: a("v2.ref-finance.near"),
        leg2_dex: a("dclv2.ref-labs.near"),
        min_mid: U128(100),
        max_mid: U128(110),
    }
}

#[test]
fn chain_order_checked_against_stored_legs() {
    let c = chain(100, 110, 50);
    let p = check(&c).unwrap();
    assert_eq!(check_chain_order(&order(50), Some(&via()), &c, &p), Ok(()));
    assert_eq!(check_chain_order(&order(50), None, &c, &p), Err(E_ORDER_MISMATCH));
    assert_eq!(check_chain_order(&order(51), Some(&via()), &c, &p), Err("E_ORDER_MIN_OUT"));
    let mut v = via();
    v.q = a("usdc.near");
    assert_eq!(check_chain_order(&order(50), Some(&v), &c, &p), Err(E_ORDER_MISMATCH));
    let mut v = via();
    v.leg2_dex = a("dex.intear.near");
    assert_eq!(check_chain_order(&order(50), Some(&v), &c, &p), Err(E_ORDER_MISMATCH));
    let mut o = order(50);
    o.amount_in = U128(NEAR - 1);
    assert_eq!(check_chain_order(&o, Some(&via()), &c, &p), Err(E_ORDER_MISMATCH));
    let mut o = order(50);
    o.token_out = a("other.near");
    assert_eq!(check_chain_order(&o, Some(&via()), &c, &p), Err(E_ORDER_MISMATCH));
    // kind: a Chain order only fires a Chain, a plain order never one
    assert_eq!(check_order_kind(true, &[Op::Chain(Box::new(c.clone()))]), Ok(()));
    assert_eq!(check_order_kind(false, &[Op::Chain(Box::new(c))]), Err(E_ORDER_OPS));
    assert_eq!(check_order_kind(true, &[Op::NearDeposit { amount: U128(1) }]), Err(E_ORDER_OPS));
}

#[test]
fn via_rules() {
    let d = vec![a("v2.ref-finance.near"), a("dclv2.ref-labs.near")];
    assert_eq!(check_via(&via(), &wrap(), &a("jensen.near"), &d, &me()), Ok(()));
    let mut v = via();
    v.leg2_dex = v.leg1_dex.clone();
    assert_eq!(check_via(&v, &wrap(), &a("jensen.near"), &d, &me()), Err(E_CHAIN_SAME_DEX));
    assert_eq!(check_via(&via(), &q(), &a("jensen.near"), &d, &me()), Err("E_BAD_ORDER"));
    assert_eq!(check_via(&via(), &wrap(), &a("jensen.near"), &d[..1], &me()), Err("E_BAD_ORDER"));
}

// ======================= C.2.2 trade quotes =======================

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

fn iso(ns: u64) -> String {
    let s = ns / NS_PER_SEC;
    let (y, m, d) = civil_from_days((s / 86_400) as i64);
    let r = s % 86_400;
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.000Z", r / 3600, r % 3600 / 60, r % 60)
}

fn stable(v: &Value) -> String {
    match v {
        Value::Object(m) => {
            let mut ks: Vec<&String> = m.keys().collect();
            ks.sort();
            let body: Vec<String> = ks
                .iter()
                .map(|k| format!("{}:{}", near_sdk::serde_json::to_string(k).unwrap(), stable(&m[*k])))
                .collect();
            format!("{{{}}}", body.join(","))
        }
        x => near_sdk::serde_json::to_string(x).unwrap(),
    }
}

/// A trade quote NEAR -> Q (buy) as 1Click signs it, `now` = its issue time.
fn buy_quote(amount: u128, now: u64) -> Map<String, Value> {
    json!({
        "dry": false, "swapType": "EXACT_INPUT", "depositType": "INTENTS",
        "originAsset": "nep141:wrap.near", "destinationAsset": "nep141:zec.omft.near",
        "amount": amount.to_string(), "amountIn": amount.to_string(),
        "refundTo": "abcd.tt.near", "refundType": "INTENTS",
        "recipient": "abcd.tt.near", "recipientType": "INTENTS",
        "slippageTolerance": 100, "minAmountOut": "990", "amountOut": "1000",
        "amountInUsd": "5.00", "amountOutUsd": "4.97",
        "deadline": iso(now + 600 * NS_PER_SEC), "timestamp": iso(now),
        "depositAddress": ADDR, "depositMemo": null, "customRecipientMsg": null,
        "timeEstimate": 10, "amountInFormatted": "1.0"
    })
    .as_object()
    .unwrap()
    .clone()
}

fn fields(m: &Map<String, Value>, flex: bool, now: u64) -> Result<quote::Checked, &'static str> {
    let s = stable(&Value::Object(m.clone()));
    let (o, d) = if flex { ("zec.omft.near", "wrap.near") } else { ("wrap.near", "zec.omft.near") };
    quote::check_fields(&s, &Rules { me: "abcd.tt.near", origin: o, dest: d, flex, now_ns: now })
}

#[test]
fn trade_quote_happy_and_every_row_negative() {
    let now = T0;
    let c = fields(&buy_quote(NEAR, now), false, now).unwrap();
    assert_eq!((c.amount, c.min_amount_out, c.amount_out, c.slippage_bps), (NEAR, 990, 1000, 100));
    assert_eq!(c.deposit_address, ADDR);
    let bad = |f: &dyn Fn(&mut Map<String, Value>)| {
        let mut m = buy_quote(NEAR, now);
        f(&mut m);
        fields(&m, false, now).err().unwrap_or("OK")
    };
    let m = "E_QUOTE_MISMATCH";
    assert_eq!(
        bad(&|q| {
            q["dry"] = json!(true);
        }),
        m
    );
    assert_eq!(
        bad(&|q| {
            q["swapType"] = json!("FLEX_INPUT");
        }),
        m
    );
    assert_eq!(
        bad(&|q| {
            q["depositType"] = json!("ORIGIN_CHAIN");
        }),
        m
    );
    assert_eq!(
        bad(&|q| {
            q["originAsset"] = json!("nep141:usdc.near");
        }),
        m
    );
    assert_eq!(
        bad(&|q| {
            q["destinationAsset"] = json!("nep141:usdc.near");
        }),
        m
    );
    assert_eq!(
        bad(&|q| {
            q["amountIn"] = json!("5");
        }),
        m
    );
    assert_eq!(
        bad(&|q| {
            q["recipient"] = json!("evil.near");
        }),
        m
    );
    assert_eq!(
        bad(&|q| {
            q["recipientType"] = json!("DESTINATION_CHAIN");
        }),
        m
    );
    assert_eq!(
        bad(&|q| {
            q["refundTo"] = json!("evil.near");
        }),
        m
    );
    assert_eq!(
        bad(&|q| {
            q["refundType"] = json!("ORIGIN_CHAIN");
        }),
        m
    );
    assert_eq!(
        bad(&|q| {
            q["customRecipientMsg"] = json!("x");
        }),
        m
    );
    assert_eq!(
        bad(&|q| {
            q["depositMemo"] = json!("x");
        }),
        m
    );
    assert_eq!(
        bad(&|q| {
            q["depositAddress"] = json!("ABC");
        }),
        m
    );
    assert_eq!(
        bad(&|q| {
            q["slippageTolerance"] = json!(5001);
        }),
        m
    );
    assert_eq!(
        bad(&|q| {
            q["slippageTolerance"] = json!(5000);
            q["amountOutUsd"] = json!("4.00");
        }),
        "OK"
    );
    assert_eq!(
        bad(&|q| {
            q["minAmountOut"] = json!("0");
        }),
        m
    );
    assert_eq!(
        bad(&|q| {
            q["amountOut"] = json!("989");
        }),
        m,
        "amountOut < minAmountOut"
    );
    assert_eq!(
        bad(&|q| {
            q.remove("amountOut");
        }),
        m
    );
    // freshness: 60 s, not 1 h
    assert_eq!(
        bad(&|q| {
            q["timestamp"] = json!(iso(now - 61 * NS_PER_SEC));
        }),
        "E_QUOTE_DEADLINE"
    );
    assert_eq!(
        bad(&|q| {
            q["timestamp"] = json!(iso(now - 60 * NS_PER_SEC));
        }),
        "OK"
    );
    assert_eq!(
        bad(&|q| {
            q["timestamp"] = json!(iso(now + 301 * NS_PER_SEC));
        }),
        "E_QUOTE_DEADLINE"
    );
    assert_eq!(
        bad(&|q| {
            q["deadline"] = json!(iso(now + 60 * NS_PER_SEC));
        }),
        "E_QUOTE_EXPIRED"
    );
    // loss bound = the quote's slippage (100 bps): 4.95 ok, 4.94 not
    assert_eq!(
        bad(&|q| {
            q["amountOutUsd"] = json!("4.95");
        }),
        "OK"
    );
    assert_eq!(
        bad(&|q| {
            q["amountOutUsd"] = json!("4.94");
        }),
        "E_QUOTE_LOSS"
    );
    // FLEX sells need minAmountIn in (0, amount]
    let mut s = buy_quote(NEAR, now);
    s["swapType"] = json!("FLEX_INPUT");
    s["originAsset"] = json!("nep141:zec.omft.near");
    s["destinationAsset"] = json!("nep141:wrap.near");
    assert_eq!(fields(&s, true, now).err(), Some(m));
    s.insert("minAmountIn".into(), json!("500"));
    assert_eq!(fields(&s, true, now).unwrap().min_amount_in, 500);
    s["minAmountIn"] = json!((NEAR + 1).to_string());
    assert_eq!(fields(&s, true, now).err(), Some(m));
}

// ======================= C.2.4 continuation bounds =======================

fn route(kind: RouteKind) -> Route {
    Route {
        kind,
        q: q(),
        origin: if kind == RouteKind::IntentsBuy { wrap() } else { q() },
        deposit_address: ADDR.into(),
        funded: U128(NEAR),
        quote_amount: U128(NEAR),
        q_min: U128(990),
        q_quoted: U128(1000),
        slippage_bps: 100,
        fee_escrow: U128(NEAR / 100),
        cont: Some(ContTerms {
            token_out: a("jensen.near"),
            dexes: vec![a("dclv2.ref-labs.near")],
            min_final: U128(50),
        }),
        cont_deadline_ns: U64(T0 + 600 * NS_PER_SEC),
        quote_deadline_ns: U64(T0 + 900 * NS_PER_SEC),
        credited: U128(0),
        spent: U128(0),
        state: RouteState::Funded,
        cont_id: U64(CONT_BASE),
        pending: false,
        pending_height: U64(0),
    }
}

fn pull(t: AccountId, x: u128) -> IntentsPull {
    IntentsPull { token: t, amount: U128(x) }
}

#[test]
fn continuation_amount_and_deadline_edges() {
    let r = route(RouteKind::IntentsBuy);
    let w = wrap();
    let dl = r.cont_deadline_ns.0;
    // q_min .. q_quoted x (1 + 1%) = 990 ..= 1010
    assert_eq!(cont_step(&r, &pull(q(), 989), true, T0, &w), Err("E_CONT_AMOUNT"));
    assert_eq!(cont_step(&r, &pull(q(), 990), true, T0, &w), Ok(ContStep::PullSwap));
    assert_eq!(cont_step(&r, &pull(q(), 1010), true, T0, &w), Ok(ContStep::PullSwap));
    assert_eq!(cont_step(&r, &pull(q(), 1011), true, T0, &w), Err("E_CONT_AMOUNT"));
    // deadline edge: <= deadline pull+swap only; after it pull-to-hold only
    assert_eq!(cont_step(&r, &pull(q(), 1000), true, dl, &w), Ok(ContStep::PullSwap));
    assert_eq!(cont_step(&r, &pull(q(), 1000), false, dl, &w), Err(E_ORDER_OPS));
    assert_eq!(cont_step(&r, &pull(q(), 1000), true, dl + 1, &w), Err(E_ORDER_OPS));
    assert_eq!(cont_step(&r, &pull(q(), 1000), false, dl + 1, &w), Ok(ContStep::PullHold));
    // refund: only after the quote deadline, <= funded, never with a swap
    let qd = r.quote_deadline_ns.0;
    assert_eq!(cont_step(&r, &pull(w.clone(), NEAR), false, qd, &w), Err(E_ORDER_OPS));
    assert_eq!(cont_step(&r, &pull(w.clone(), NEAR), false, qd + 1, &w), Ok(ContStep::PullRefund));
    assert_eq!(cont_step(&r, &pull(w.clone(), NEAR + 1), false, qd + 1, &w), Err(E_ORDER_OPS));
    assert_eq!(cont_step(&r, &pull(w.clone(), NEAR), true, qd + 1, &w), Err(E_ORDER_OPS));
    // other tokens / zero / states
    assert_eq!(cont_step(&r, &pull(a("usdc.near"), 1000), true, T0, &w), Err(E_ORDER_OPS));
    assert_eq!(cont_step(&r, &pull(q(), 0), true, T0, &w), Err("E_BAD_OP"));
    for st in [RouteState::Pulled, RouteState::Done, RouteState::Held, RouteState::Refunded] {
        let mut r2 = r.clone();
        r2.state = st;
        assert_eq!(cont_step(&r2, &pull(q(), 1000), true, T0, &w), Err("E_NO_ORDER"));
    }
    // sell: pull wNEAR within [q_min, q_quoted x (1+slip)], never a swap
    let s = route(RouteKind::IntentsSell);
    assert_eq!(cont_step(&s, &pull(w.clone(), 990), false, T0, &w), Ok(ContStep::PullSell));
    assert_eq!(cont_step(&s, &pull(w.clone(), 989), false, T0, &w), Err("E_CONT_AMOUNT"));
    assert_eq!(cont_step(&s, &pull(w.clone(), 1011), false, T0, &w), Err("E_CONT_AMOUNT"));
    assert_eq!(cont_step(&s, &pull(w.clone(), 1000), true, T0, &w), Err(E_ORDER_OPS));
    assert_eq!(cont_step(&s, &pull(q(), NEAR), false, qd + 1, &w), Ok(ContStep::PullRefund));
}

// ======================= mocked contract: lock, routes, relayer rule =======================

const STORAGE_BYTES: u64 = 1_000;

fn ctx_at(pred: &str, pk: Option<PublicKey>, now: u64, height: u64) {
    let mut b = VMContextBuilder::new();
    b.current_account_id(me())
        .predecessor_account_id(a(pred))
        .signer_account_id(a(pred))
        .account_balance(NearToken::from_yoctonear(10 * NEAR))
        .block_timestamp(now)
        .block_height(height)
        .storage_usage(STORAGE_BYTES)
        .prepaid_gas(Gas::from_tgas(300));
    if let Some(pk) = pk {
        b.signer_account_pk(pk);
    }
    testing_env!(b.build());
}

fn cb_ctx(results: Vec<PromiseResult>, height: u64) {
    testing_env!(
        VMContextBuilder::new()
            .current_account_id(me())
            .predecessor_account_id(me())
            .signer_account_id(me())
            .account_balance(NearToken::from_yoctonear(10 * NEAR))
            .block_timestamp(T0 + 10)
            .block_height(height)
            .storage_usage(STORAGE_BYTES)
            .prepaid_gas(Gas::from_tgas(300))
            .build(),
        near_sdk::test_vm_config(),
        near_sdk::RuntimeFeesConfig::test(),
        Default::default(),
        results
    );
}

fn account() -> TradingAccount {
    ctx_at("tt.near", None, T0, 100);
    near_sdk::mock::with_mocked_blockchain(|b| {
        b.take_storage();
    });
    ctx_at("tt.near", None, T0, 100);
    TradingAccount::init(
        a("owner.near"),
        FeeConfig { fee_bps: 100, fee_recipient: a("fees.near") },
        Caps { max_trade_yocto: U128(3 * NEAR), daily_cap_yocto: U128(9 * NEAR) },
        allow(),
        wrap(),
        None,
        None,
        None,
    )
}

fn panics<F: FnOnce() + std::panic::UnwindSafe>(f: F) -> String {
    let e = std::panic::catch_unwind(f).expect_err("expected panic");
    let m = e
        .downcast_ref::<String>()
        .cloned()
        .or(e.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_default();
    match m.split_once("panic_msg: \"") {
        Some((_, rest)) => rest.split('"').next().unwrap_or_default().to_string(),
        None => m,
    }
}

fn exec(c: &mut TradingAccount, ops: Vec<Op>, id: &str) {
    c.execute(ops, id.into(), U64(env::block_timestamp() + 60 * NS_PER_SEC), U128(3 * NEAR));
}

fn chain_ops() -> Vec<Op> {
    vec![Op::NearDeposit { amount: U128(NEAR) }, Op::Chain(Box::new(chain(100, 110, 50)))]
}

fn st_of(rid: &str) -> ChainSt {
    // the chain state the execute scheduled (on_chain_start's args)
    let rs = get_created_receipts();
    let r = rs.iter().rev().find(|r| r.receiver_id == me()).expect("callback receipt");
    match &r.actions[0] {
        MockAction::FunctionCallWeight { method_name, args, .. } => {
            assert_eq!(method_name, b"on_chain_start");
            let v: Value = near_sdk::serde_json::from_slice(args).unwrap();
            let st: ChainSt = near_sdk::serde_json::from_value(v["st"].clone()).unwrap();
            assert_eq!(st.rid, rid);
            st
        }
        x => panic!("{x:?}"),
    }
}

fn ok_u(v: u128) -> PromiseResult {
    PromiseResult::Successful(format!("\"{v}\"").into_bytes())
}

#[test]
fn chain_execute_takes_lock_and_q_busy_refuses_other_trades() {
    let mut c = account();
    ctx_at(me().as_str(), None, T0 + 1, 100);
    exec(&mut c, chain_ops(), "r1");
    assert_eq!(c.get_q_lock(q()).map(|x| x.0), Some("r1".to_string()));
    let rs = get_created_receipts();
    // view on q, then on_chain_start
    assert!(rs.iter().any(|r| r.receiver_id == q()));
    let _ = st_of("r1");
    // a second Chain on the same q, and a plain swap touching q: E_Q_BUSY, nothing moved
    ctx_at(me().as_str(), None, T0 + 2, 101);
    let mut c2 = c;
    assert_eq!(panics(std::panic::AssertUnwindSafe(|| exec(&mut c2, chain_ops(), "r2"))), E_Q_BUSY);
    let sell_q = vec![Op::FtTransferCall {
        token: q(),
        receiver_id: a("v2.ref-finance.near"),
        amount: U128(10),
        msg: classic(6065, "zec.omft.near", "wrap.near", None, 5),
        gas: U64(80 * TGAS),
    }];
    assert_eq!(panics(std::panic::AssertUnwindSafe(|| exec(&mut c2, sell_q.clone(), "r3"))), E_Q_BUSY);
    // the lock expires after LOCK_TTL_BLOCKS
    ctx_at(me().as_str(), None, T0 + 3, 100 + LOCK_TTL_BLOCKS);
    exec(&mut c2, sell_q, "r4");
    assert!(c2.get_q_lock(q()).is_none());
}

fn run_to_start() -> (TradingAccount, ChainSt) {
    let mut c = account();
    ctx_at(me().as_str(), None, T0 + 1, 100);
    exec(&mut c, chain_ops(), "r1");
    let st = st_of("r1");
    (c, st)
}

#[test]
fn chain_unlocks_on_every_terminal_path() {
    // 1: view failed -> failed swap, spend back
    let (mut c, st) = run_to_start();
    cb_ctx(vec![PromiseResult::Failed], 101);
    c.on_chain_start(st);
    assert!(c.get_q_lock(q()).is_none());
    assert!(get_logs().iter().any(|l| l.contains("\"settled\"") && l.contains("\"used\":\"0\"")));

    // 2: leg 1 failed
    let (mut c, st) = run_to_start();
    cb_ctx(vec![ok_u(7)], 101);
    c.on_chain_start(st);
    let st = next_st("on_chain_leg1");
    cb_ctx(vec![PromiseResult::Failed], 102);
    c.on_chain_leg1(st);
    assert!(c.get_q_lock(q()).is_none());

    // 3: leg 1 ok, delta below min_mid -> held (route stored), unlocked, leg-1 fee earned
    let (mut c, st) = run_to_start();
    cb_ctx(vec![ok_u(7)], 101);
    c.on_chain_start(st);
    let st = next_st("on_chain_leg1");
    cb_ctx(vec![ok_u(NEAR)], 102);
    c.on_chain_leg1(st);
    let st = next_st("on_chain_mid");
    cb_ctx(vec![ok_u(7 + 99)], 103);
    c.on_chain_mid(st);
    assert!(c.get_q_lock(q()).is_none());
    let r = c.get_route("r1".into()).unwrap();
    assert_eq!((r.state, r.credited.0), (RouteState::Held, 99));
    assert!(get_logs().iter().any(|l| l.contains("route_held") && l.contains("below_mid")));
    assert!(get_logs()
        .iter()
        .any(|l| l.contains("\"settled\"") && l.contains(&format!("\"fee\":\"{}\"", NEAR / 100))));

    // 4: delta above max_mid is capped (a third-party transfer mid-route is never spent)
    let (mut c, st) = run_to_start();
    cb_ctx(vec![ok_u(7)], 101);
    c.on_chain_start(st);
    let st = next_st("on_chain_leg1");
    cb_ctx(vec![ok_u(NEAR)], 102);
    c.on_chain_leg1(st);
    let st = next_st("on_chain_mid");
    cb_ctx(vec![ok_u(7 + 5_000)], 103);
    c.on_chain_mid(st);
    let rs = get_created_receipts();
    let leg2 = rs.iter().find(|r| r.receiver_id == q()).unwrap();
    match &leg2.actions[0] {
        MockAction::FunctionCallWeight { args, .. } => {
            let v: Value = near_sdk::serde_json::from_slice(args).unwrap();
            assert_eq!(v["amount"], "110", "credited = min(delta, max_mid)");
            assert_eq!(v["receiver_id"], "dclv2.ref-labs.near");
        }
        x => panic!("{x:?}"),
    }
    let st = next_st("on_chain_settled");
    assert_eq!(c.get_q_lock(q()).map(|x| x.0), Some("r1".into()), "held through leg 2");
    // 5: leg 2 failed -> held(leg2_failed), unlocked
    cb_ctx(vec![PromiseResult::Failed], 104);
    let mut c5 = c;
    c5.on_chain_settled(st.clone());
    assert!(c5.get_q_lock(q()).is_none());
    assert_eq!(c5.get_route("r1".into()).unwrap().credited.0, 110);
    assert!(get_logs().iter().any(|l| l.contains("leg2_failed")));
}

#[test]
fn chain_done_path_unlocks_and_charges_leg1_fee() {
    let (mut c, st) = run_to_start();
    cb_ctx(vec![ok_u(0)], 101);
    c.on_chain_start(st);
    let st = next_st("on_chain_leg1");
    cb_ctx(vec![ok_u(NEAR / 2)], 102);
    c.on_chain_leg1(st);
    let st = next_st("on_chain_mid");
    cb_ctx(vec![ok_u(105)], 103);
    c.on_chain_mid(st);
    let st = next_st("on_chain_settled");
    cb_ctx(vec![ok_u(105)], 104);
    c.on_chain_settled(st);
    assert!(c.get_q_lock(q()).is_none());
    assert!(c.get_route("r1".into()).is_none(), "a finished chain stores no route");
    // leg 1 used half: fee pro rata
    assert!(get_logs()
        .iter()
        .any(|l| l.contains("\"settled\"") && l.contains(&format!("\"fee\":\"{}\"", NEAR / 200))));
    assert!(get_logs().iter().any(|l| l.contains("route_done")));
}

fn next_st(method: &str) -> ChainSt {
    let rs = get_created_receipts();
    let r = rs
        .iter()
        .rev()
        .find(|r| r.receiver_id == me() && matches!(&r.actions[0], MockAction::FunctionCallWeight { method_name, .. } if method_name == method.as_bytes()))
        .unwrap_or_else(|| panic!("no {method} in {rs:?}"));
    match &r.actions[0] {
        MockAction::FunctionCallWeight { args, .. } => {
            let v: Value = near_sdk::serde_json::from_slice(args).unwrap();
            near_sdk::serde_json::from_value(v["st"].clone()).unwrap()
        }
        _ => unreachable!(),
    }
}

#[test]
fn routes_table_bounded_at_16() {
    let _c = account();
    for i in 0..MAX_OPEN_ROUTES {
        save_route(&format!("r{i}"), &route(RouteKind::IntentsBuy)).unwrap();
    }
    assert_eq!(save_route("r16", &route(RouteKind::IntentsBuy)), Err("E_ROUTES_FULL"));
    // a finished route frees its slot
    let mut done = route(RouteKind::IntentsBuy);
    done.state = RouteState::Done;
    save_route("r0", &done).unwrap();
    save_route("r16", &route(RouteKind::IntentsBuy)).unwrap();
    assert_eq!(route_index().len(), MAX_OPEN_ROUTES);
}

fn relayer_pk() -> PublicKey {
    "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp".parse().unwrap()
}

fn with_relayer() -> TradingAccount {
    let mut c = account();
    ctx_at("owner.near", None, T0, 100);
    testing_env!(VMContextBuilder::new()
        .current_account_id(me())
        .predecessor_account_id(a("owner.near"))
        .signer_account_id(a("owner.near"))
        .attached_deposit(NearToken::from_yoctonear(1))
        .account_balance(NearToken::from_yoctonear(10 * NEAR))
        .block_timestamp(T0)
        .storage_usage(STORAGE_BYTES)
        .build());
    c.owner_set_automation_key(relayer_pk(), U128(NEAR));
    cb_ctx(vec![PromiseResult::Successful(vec![])], 100);
    c.on_automation_set(relayer_pk(), None, None);
    c
}

fn intents_swap() -> IntentsSwap {
    IntentsSwap {
        signed_quote: stable(&Value::Object(buy_quote(NEAR, T0))),
        signature: "ed25519:1111111111111111111111111111111111111111111111111111111111111111".into(),
        q: q(),
        cont: ContTerms {
            token_out: a("jensen.near"),
            dexes: vec![a("dclv2.ref-labs.near")],
            min_final: U128(50),
        },
        cont_deadline_ns: U64(T0 + 600 * NS_PER_SEC),
    }
}

#[test]
fn relayer_can_never_fund_1click() {
    let mut c = with_relayer();
    // a plain buy order the relayer may fire
    ctx_at(me().as_str(), None, T0 + 1, 100);
    let id = c.place_order(
        wrap(),
        a("jensen.near"),
        U128(NEAR),
        U128(50),
        String::new(),
        U64(T0 + 3_600 * NS_PER_SEC),
        vec![a("dclv2.ref-labs.near")],
    );
    // IntentsSwap in an order fire: E_ORDER_OPS (before any quote check)
    ctx_at(me().as_str(), Some(relayer_pk()), T0 + 2, 100);
    let mut c2 = c;
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| c2.execute_order(
            id,
            vec![Op::NearDeposit { amount: U128(NEAR) }, Op::IntentsSwap(intents_swap())]
        ))),
        E_ORDER_OPS
    );
    // from a device fire too (a fresh order: a mocked panic doesn't revert `pending`)
    ctx_at(me().as_str(), None, T0 + 3, 100);
    let id2 = c2.place_order(
        wrap(),
        a("jensen.near"),
        U128(NEAR),
        U128(50),
        String::new(),
        U64(T0 + 3_600 * NS_PER_SEC),
        vec![a("dclv2.ref-labs.near")],
    );
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| c2.execute_order(id2, vec![Op::IntentsSwap(intents_swap())]))),
        E_ORDER_OPS
    );
    // a continuation can't carry one either
    let rid = "cont-route";
    save_route(rid, &route(RouteKind::IntentsBuy)).unwrap();
    let cid = new_cont(rid);
    ctx_at(me().as_str(), Some(relayer_pk()), T0 + 4, 100);
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(
            || c2.execute_order(U64(cid), vec![Op::IntentsSwap(intents_swap())])
        )),
        E_ORDER_OPS
    );
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| c2.execute_order(
            U64(cid),
            vec![Op::IntentsPull(pull(q(), 1000)), Op::IntentsSwap(intents_swap())]
        ))),
        E_ORDER_OPS
    );
    // IntentsPull is continuation-only
    ctx_at(me().as_str(), None, T0 + 5, 100);
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| exec(&mut c2, vec![Op::IntentsPull(pull(q(), 1))], "p"))),
        "E_BAD_OP"
    );
}

#[test]
fn continuation_relayer_pull_swap_then_pending_then_done() {
    let c = with_relayer();
    let rid = "buy-1";
    save_route(rid, &route(RouteKind::IntentsBuy)).unwrap();
    escrow_add(NEAR / 100);
    let cid = new_cont(rid);
    assert!(cid >= CONT_BASE);
    let swap = Op::FtTransferCall {
        token: q(),
        receiver_id: a("dclv2.ref-labs.near"),
        amount: U128(1000),
        msg: dcl(&["zec.omft.near|jensen.near|10000"], "jensen.near", 50),
        gas: U64(80 * TGAS),
    };
    // outside the stored terms: another DEX, another output, a lower bound, another amount
    ctx_at(me().as_str(), Some(relayer_pk()), T0 + 1, 100);
    let bad_dex = Op::FtTransferCall {
        token: q(),
        receiver_id: a("v2.ref-finance.near"),
        amount: U128(1000),
        msg: classic(7000, "zec.omft.near", "jensen.near", None, 50),
        gas: U64(80 * TGAS),
    };
    let mut c1 = c;
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(
            || c1.execute_order(U64(cid), vec![Op::IntentsPull(pull(q(), 1000)), bad_dex.clone()])
        )),
        E_ORDER_MISMATCH
    );
    let low = Op::FtTransferCall {
        token: q(),
        receiver_id: a("dclv2.ref-labs.near"),
        amount: U128(1000),
        msg: dcl(&["zec.omft.near|jensen.near|10000"], "jensen.near", 49),
        gas: U64(80 * TGAS),
    };
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(
            || c1.execute_order(U64(cid), vec![Op::IntentsPull(pull(q(), 1000)), low.clone()])
        )),
        "E_ORDER_MIN_OUT"
    );
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(
            || c1.execute_order(U64(cid), vec![Op::IntentsPull(pull(q(), 999)), swap.clone()])
        )),
        E_ORDER_MISMATCH
    );
    // the stored terms: pull + swap
    c1.execute_order(U64(cid), vec![Op::IntentsPull(pull(q(), 1000)), swap.clone()]);
    let rs = get_created_receipts();
    assert!(rs.iter().any(|r| r.receiver_id == a("intents.near")));
    assert_eq!(c1.get_q_lock(q()).map(|x| x.0), Some(rid.to_string()));
    // a second fire while in flight
    ctx_at(me().as_str(), None, T0 + 2, 100);
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(
            || c1.execute_order(U64(cid), vec![Op::IntentsPull(pull(q(), 1000)), swap.clone()])
        )),
        "E_ORDER_PENDING"
    );
    // pull ok (intents returns the amount withdrawn) -> escrowed fee paid, swap scheduled
    cb_ctx(vec![ok_u(1000)], 101);
    let leg = ChainLeg::FtTransferCall {
        token: q(),
        receiver_id: a("dclv2.ref-labs.near"),
        amount: U128(1000),
        msg: dcl(&["zec.omft.near|jensen.near|10000"], "jensen.near", 50),
        gas: U64(80 * TGAS),
    };
    c1.on_cont_pulled(rid.into(), pull(q(), 1000), Some(leg.clone()));
    assert_eq!(escrow_total(), 0);
    assert!(get_created_receipts().iter().any(|r| r.receiver_id == a("fees.near")));
    // swap ok -> Done, unlocked
    cb_ctx(vec![ok_u(1000)], 102);
    c1.on_cont_swapped(rid.into(), U128(1000), leg);
    let r = c1.get_route(rid.into()).unwrap();
    assert_eq!((r.state, r.credited.0, r.spent.0), (RouteState::Done, 1000, 1000));
    assert!(c1.get_q_lock(q()).is_none());
    // Done routes can't be fired again
    ctx_at(me().as_str(), Some(relayer_pk()), T0 + 3, 102);
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(
            || c1.execute_order(U64(cid), vec![Op::IntentsPull(pull(q(), 1000)), swap.clone()])
        )),
        "E_NO_ORDER"
    );
}

#[test]
fn continuation_failed_pull_keeps_route_and_unlocks() {
    let mut c = with_relayer();
    let rid = "buy-2";
    save_route(rid, &route(RouteKind::IntentsBuy)).unwrap();
    let cid = new_cont(rid);
    ctx_at(me().as_str(), Some(relayer_pk()), T0 + 1, 100);
    let swap = Op::FtTransferCall {
        token: q(),
        receiver_id: a("dclv2.ref-labs.near"),
        amount: U128(1000),
        msg: dcl(&["zec.omft.near|jensen.near|10000"], "jensen.near", 50),
        gas: U64(80 * TGAS),
    };
    c.execute_order(U64(cid), vec![Op::IntentsPull(pull(q(), 1000)), swap]);
    cb_ctx(vec![PromiseResult::Failed], 101);
    c.on_cont_pulled(rid.into(), pull(q(), 1000), None);
    let r = c.get_route(rid.into()).unwrap();
    assert_eq!((r.state, r.pending, r.credited.0), (RouteState::Funded, false, 0));
    assert!(c.get_q_lock(q()).is_none());
    // after the deadline: pull-to-hold only
    ctx_at(me().as_str(), Some(relayer_pk()), T0 + 601 * NS_PER_SEC, 102);
    c.execute_order(U64(cid), vec![Op::IntentsPull(pull(q(), 1000))]);
    cb_ctx(vec![ok_u(1000)], 103);
    c.on_cont_pulled(rid.into(), pull(q(), 1000), None);
    let r = c.get_route(rid.into()).unwrap();
    assert_eq!((r.state, r.credited.0), (RouteState::Held, 1000));
    assert!(c.get_q_lock(q()).is_none());
}

#[test]
fn intents_swap_device_execute_funds_and_escrows() {
    let mut c = account();
    // unsigned by a configured key -> E_ONECLICK_UNSET / E_QUOTE_SIG, nothing written
    ctx_at(me().as_str(), None, T0 + 1, 100);
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| exec(&mut c, vec![Op::IntentsSwap(intents_swap())], "i0"))),
        "E_ONECLICK_UNSET"
    );
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let pk = format!("ed25519:{}", near_sdk::bs58::encode(sk.verifying_key().to_bytes()).into_string());
    testing_env!(VMContextBuilder::new()
        .current_account_id(me())
        .predecessor_account_id(a("owner.near"))
        .signer_account_id(a("owner.near"))
        .attached_deposit(NearToken::from_yoctonear(1))
        .account_balance(NearToken::from_yoctonear(10 * NEAR))
        .block_timestamp(T0)
        .storage_usage(STORAGE_BYTES)
        .build());
    c.owner_set_oneclick_config(vec![pk], 300, None, None);
    let mut s = intents_swap();
    let msg = crate::intents::signed_message(s.signed_quote.as_bytes());
    s.signature =
        format!("ed25519:{}", near_sdk::bs58::encode(sk.sign(msg.as_bytes()).to_bytes()).into_string());
    // a bad signature
    let mut bad = s.clone();
    bad.signature = "ed25519:1111111111111111111111111111111111111111111111111111111111111111".into();
    ctx_at(me().as_str(), None, T0 + 1, 100);
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| exec(&mut c, vec![Op::IntentsSwap(bad.clone())], "i1"))),
        "E_QUOTE_SIG"
    );
    // cont rules
    let mut b2 = s.clone();
    b2.cont_deadline_ns = U64(T0 + CONT_MAX_NS + 2);
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| exec(&mut c, vec![Op::IntentsSwap(b2.clone())], "i2"))),
        "E_BAD_OP"
    );
    let mut b3 = s.clone();
    b3.cont.dexes = vec![a("unknown.near")];
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| exec(&mut c, vec![Op::IntentsSwap(b3.clone())], "i3"))),
        "E_BAD_DEX"
    );
    // good: counts toward trade caps (not the withdraw window), escrows the fee, funds the address
    exec(&mut c, vec![Op::NearDeposit { amount: U128(NEAR) }, Op::IntentsSwap(s.clone())], "i4");
    assert_eq!(escrow_total(), NEAR / 100);
    assert_eq!(c.get_day().spent_yocto.0, NEAR + NEAR / 100, "a trade: the funded wNEAR + the escrowed fee");
    let r = c.get_route("i4".into()).unwrap();
    assert_eq!(
        (r.kind, r.state, r.q_min.0, r.q_quoted.0),
        (RouteKind::IntentsBuy, RouteState::Funded, 990, 1000)
    );
    assert!(r.cont_id.0 >= CONT_BASE);
    let rs = get_created_receipts();
    let f = rs.iter().find(|r| r.receiver_id == wrap() && matches!(&r.actions[0], MockAction::FunctionCallWeight{method_name,..} if method_name == b"ft_transfer_call")).unwrap();
    match &f.actions[0] {
        MockAction::FunctionCallWeight { args, .. } => {
            let v: Value = near_sdk::serde_json::from_slice(args).unwrap();
            assert_eq!((v["receiver_id"].as_str(), v["msg"].as_str()), (Some("intents.near"), Some(ADDR)));
        }
        _ => unreachable!(),
    }
    assert_eq!(c.get_withdraw_day().spent_yocto.0, 0, "not the withdraw window");
    // replay of the same quote
    ctx_at(me().as_str(), None, T0 + 2, 100);
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| exec(&mut c, vec![Op::IntentsSwap(s.clone())], "i5"))),
        "E_QUOTE_REPLAY"
    );
    // funding failed -> refunded, escrow released
    cb_ctx(vec![PromiseResult::Failed], 101);
    let settle: crate::SettleArgs =
        near_sdk::serde_json::from_value(json!({"client_order_id": "i4", "amount": NEAR.to_string(),
        "counted": NEAR.to_string(), "fee": (NEAR / 100).to_string(), "day_start": "0", "proof": "wrap"}))
        .unwrap();
    c.on_route_funded("i4".into(), settle);
    assert_eq!(escrow_total(), 0);
    assert_eq!(c.get_route("i4".into()).unwrap().state, RouteState::Refunded);
}

#[test]
fn chain_order_place_with_via_and_fire() {
    let mut c = with_relayer();
    // place_order{..., via} (the optional arg rides in the same JSON args)
    let args = json!({"token_in": "wrap.near", "token_out": "jensen.near", "amount_in": NEAR.to_string(),
        "min_out": "50", "trigger_meta": "", "expires_at_ns": (T0 + 3_600 * NS_PER_SEC).to_string(),
        "dexes": ["v2.ref-finance.near", "dclv2.ref-labs.near"],
        "via": {"q": "zec.omft.near", "leg1_dex": "v2.ref-finance.near", "leg2_dex": "dclv2.ref-labs.near", "min_mid": "100", "max_mid": "110"}});
    input_ctx(&args, T0 + 1);
    let id = c.place_order(
        wrap(),
        a("jensen.near"),
        U128(NEAR),
        U128(50),
        String::new(),
        U64(T0 + 3_600 * NS_PER_SEC),
        vec![a("v2.ref-finance.near"), a("dclv2.ref-labs.near")],
    );
    assert_eq!(c.get_order_via(id), Some(via()));
    // a plain swap can't fire a Chain order
    ctx_at(me().as_str(), Some(relayer_pk()), T0 + 2, 100);
    let plain = vec![Op::FtTransferCall {
        token: wrap(),
        receiver_id: a("v2.ref-finance.near"),
        amount: U128(NEAR),
        msg: classic(1, "wrap.near", "jensen.near", None, 50),
        gas: U64(80 * TGAS),
    }];
    let mut c2 = c;
    assert_eq!(panics(std::panic::AssertUnwindSafe(|| c2.execute_order(id, plain.clone()))), E_ORDER_OPS);
    // min_final below the order's floor
    let mut low = chain(100, 110, 50);
    low.min_final = U128(49);
    low.leg2 = leg2(49);
    // (order floor 50) -> E_ORDER_MIN_OUT; the stored legs fire
    let r = panics(std::panic::AssertUnwindSafe(|| {
        c2.execute_order(id, vec![Op::NearDeposit { amount: U128(NEAR) }, Op::Chain(Box::new(low.clone()))])
    }));
    assert_eq!(r, "E_ORDER_MIN_OUT");
    // (a mocked panic keeps `pending`: a fresh order for the good fire)
    ctx_at(me().as_str(), None, T0 + 3, 100);
    input_ctx(&args, T0 + 3);
    let id2 = c2.place_order(
        wrap(),
        a("jensen.near"),
        U128(NEAR),
        U128(50),
        String::new(),
        U64(T0 + 3_600 * NS_PER_SEC),
        vec![a("v2.ref-finance.near"), a("dclv2.ref-labs.near")],
    );
    ctx_at(me().as_str(), Some(relayer_pk()), T0 + 4, 100);
    c2.execute_order(
        id2,
        vec![Op::NearDeposit { amount: U128(NEAR) }, Op::Chain(Box::new(chain(100, 110, 50)))],
    );
    assert_eq!(c2.get_q_lock(q()).map(|x| x.0), Some(format!("order:{}", id2.0)));
    // cancel removes the stored legs
    ctx_at(me().as_str(), None, T0 + 5, 100);
    c2.cancel_order(id);
    assert_eq!(c2.get_order_via(id), None);
}

fn input_ctx(args: &Value, now: u64) {
    let mut vc = VMContextBuilder::new()
        .current_account_id(me())
        .predecessor_account_id(me())
        .signer_account_id(me())
        .account_balance(NearToken::from_yoctonear(10 * NEAR))
        .block_timestamp(now)
        .storage_usage(STORAGE_BYTES)
        .prepaid_gas(Gas::from_tgas(300))
        .build();
    vc.input = args.to_string().into_bytes().into();
    testing_env!(vc);
}

// ======================= rev 2: Shards legs (tokens paired with a non-NEAR quote) =======================

const SH: &str = "l000105.factory.shardsmarket.near";

fn shards_buy_leg(amount: u128, min: u128, gas: u64) -> ChainLeg {
    ChainLeg::ShardsBuy { token: a(SH), amount: U128(amount), min_out: U128(min), gas: U64(gas * TGAS) }
}

fn shards_sell_leg(amount: u128, min: u128, gas: u64) -> ChainLeg {
    ChainLeg::ShardsSell { token: a(SH), amount: U128(amount), min_out: U128(min), gas: U64(gas * TGAS) }
}

fn q_to_wrap(min: u128) -> ChainLeg {
    ChainLeg::FtTransferCall {
        token: q(),
        receiver_id: a("v2.ref-finance.near"),
        amount: U128(0),
        msg: classic(6065, "zec.omft.near", "wrap.near", None, min),
        gas: U64(80 * TGAS),
    }
}

#[test]
fn shards_legs_plan_both_ways() {
    // NEAR -> Q (Rhea) -> Shards token (paid in Q)
    let mut c = chain(100, 110, 50);
    c.leg2 = shards_buy_leg(0, 50, 50);
    let p = check(&c).unwrap();
    assert_eq!((p.token_in.as_str(), p.token_out.as_str()), ("wrap.near", SH));
    let l2 = p.l2.unwrap();
    assert_eq!((l2.dex.as_str(), l2.token_in.as_str()), (SH, "zec.omft.near"));
    assert_eq!((p.counted, p.fee), (NEAR, NEAR / 100), "fee on the NEAR leg");
    // Shards token -> Q (sell + withdraw_quote batch) -> NEAR (Rhea)
    let c = Chain {
        leg1: shards_sell_leg(1_000, 100, 40),
        leg2: q_to_wrap(50),
        q: q(),
        min_mid: U128(100),
        max_mid: U128(200),
        min_final: U128(50),
    };
    let p = check(&c).unwrap();
    assert_eq!((p.token_in.as_str(), p.token_out.as_str()), (SH, "wrap.near"));
    assert_eq!(p.l1.out, "zec.omft.near");
    assert_eq!(p.l1.gas, (40 + GAS_SHARDS_Q_WITHDRAW) * TGAS, "the withdraw is budgeted");
    assert_eq!((p.counted, p.fee), (0, 0), "sell fee: bps x min_final (50 x 1% = 0)");
}

#[test]
fn shards_legs_rules() {
    // wrong side
    let mut c = chain(100, 110, 50);
    c.leg1 = shards_buy_leg(NEAR, 100, 50);
    assert_eq!(check(&c), Err(E_CHAIN_LEG), "ShardsBuy is leg 2 only");
    let mut c = chain(100, 110, 50);
    c.leg2 = shards_sell_leg(0, 50, 40);
    assert_eq!(check(&c), Err(E_CHAIN_LEG), "ShardsSell is leg 1 only");
    // leg 2 amount is the contract's
    let mut c = chain(100, 110, 50);
    c.leg2 = shards_buy_leg(1, 50, 50);
    assert_eq!(check(&c), Err(E_CHAIN_LEG2_AMOUNT));
    // not under an allowlisted ShardsToken factory
    let mut c = chain(100, 110, 50);
    c.leg2 = ChainLeg::ShardsBuy {
        token: a("l1.factory-shardsmarket.near"),
        amount: U128(0),
        min_out: U128(50),
        gas: U64(50 * TGAS),
    };
    assert_eq!(check(&c), Err("E_BAD_DEX"));
    let mut c = chain(100, 110, 50);
    c.leg2 = ChainLeg::ShardsBuy {
        token: a("a.b.factory.shardsmarket.near"),
        amount: U128(0),
        min_out: U128(50),
        gas: U64(50 * TGAS),
    };
    assert_eq!(check(&c), Err("E_BAD_DEX"), "one label only");
    // bounds
    let mut c = chain(100, 110, 50);
    c.leg2 = shards_buy_leg(0, 0, 50);
    assert_eq!(check(&c), Err("E_BAD_OP"));
    let mut c = chain(100, 110, 50);
    c.leg2 = shards_buy_leg(0, 50, crate::MAX_SWAP_GAS_SHARDS_BUY + 1);
    assert_eq!(check(&c), Err("E_GAS"));
    let mut c = chain(100, 110, 50);
    c.leg2 = shards_buy_leg(0, 50, crate::MIN_SWAP_GAS - 1);
    assert_eq!(check(&c), Err("E_GAS"));
    let sell = |amount: u128, min: u128, gas: u64| Chain {
        leg1: shards_sell_leg(amount, min, gas),
        leg2: q_to_wrap(50),
        q: q(),
        min_mid: U128(100),
        max_mid: U128(200),
        min_final: U128(50),
    };
    assert_eq!(check(&sell(0, 100, 40)), Err("E_BAD_OP"));
    assert_eq!(check(&sell(1_000, 99, 40)), Err(E_CHAIN_MID), "sell bound below min_mid");
    assert_eq!(check(&sell(1_000, 100, crate::MAX_SWAP_GAS_SHARDS_SELL + 1)), Err("E_GAS"));
    // the same token on both legs (sell it for Q, buy it back): same venue
    let mut c = sell(1_000, 100, 40);
    c.leg2 = shards_buy_leg(0, 50, 50);
    assert_eq!(check(&c), Err(E_CHAIN_SAME_DEX));
}

#[test]
fn shards_sell_leg_is_one_batch_to_the_token() {
    let mut c = account();
    ctx_at(me().as_str(), None, T0 + 1, 100);
    let ch = Chain {
        leg1: shards_sell_leg(1_000, 100, 40),
        leg2: q_to_wrap(50),
        q: q(),
        min_mid: U128(100),
        max_mid: U128(200),
        min_final: U128(50),
    };
    exec(&mut c, vec![Op::Chain(Box::new(ch))], "sx");
    let st = st_of("sx");
    cb_ctx(vec![ok_u(0)], 101);
    c.on_chain_start(st);
    let rs = get_created_receipts();
    let r = rs.iter().find(|r| r.receiver_id == a(SH)).expect("a receipt to the token");
    let names: Vec<String> = r
        .actions
        .iter()
        .map(|x| match x {
            MockAction::FunctionCallWeight { method_name, args, attached_deposit, .. } => {
                assert_eq!(attached_deposit.as_yoctonear(), 1);
                let v: Value = near_sdk::serde_json::from_slice(args).unwrap();
                assert!(v.get("recipient_id").is_none(), "never a recipient");
                String::from_utf8(method_name.clone()).unwrap()
            }
            x => panic!("{x:?}"),
        })
        .collect();
    assert_eq!(names, ["sell_exact_in", "withdraw_quote"]);
}

#[test]
fn chain_and_intents_swap_tokens_are_storage_targets() {
    // rev 2: a StorageDeposit for the Chain's output / the IntentsSwap continuation's output
    let mut c = account();
    ctx_at(me().as_str(), None, T0 + 1, 100);
    let mut ch = chain(100, 110, 50);
    ch.leg2 = shards_buy_leg(0, 50, 50);
    let reg = |t: &str| Op::StorageDeposit { token: a(t), amount: U128(1_250_000_000_000_000_000_000) };
    exec(
        &mut c,
        vec![
            reg(SH),
            reg("zec.omft.near"),
            Op::NearDeposit { amount: U128(NEAR) },
            Op::Chain(Box::new(ch.clone())),
        ],
        "st1",
    );
    ctx_at(me().as_str(), None, T0 + 2, 100 + LOCK_TTL_BLOCKS);
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| exec(
            &mut c,
            vec![reg("other.near"), Op::NearDeposit { amount: U128(NEAR) }, Op::Chain(Box::new(ch.clone()))],
            "st2"
        ))),
        "E_STORAGE_TARGET"
    );
}

// ======================= v1.6.0 internal review (docs/audit/v160-internal-review.md) =======================
// Each test is the review's PoC (docs/audit/v160-internal-review-pocs/review-pocs.patch) with its
// assertion flipped to the fixed behaviour: it fails on 020c6cd1 and passes with the fix.
mod review_v160 {
    use super::*;

    fn cb_at(results: Vec<PromiseResult>, height: u64, now: u64, balance: u128) {
        testing_env!(
            VMContextBuilder::new()
                .current_account_id(me())
                .predecessor_account_id(me())
                .signer_account_id(me())
                .account_balance(NearToken::from_yoctonear(balance))
                .block_timestamp(now)
                .block_height(height)
                .storage_usage(STORAGE_BYTES)
                .prepaid_gas(Gas::from_tgas(300))
                .build(),
            near_sdk::test_vm_config(),
            near_sdk::RuntimeFeesConfig::test(),
            Default::default(),
            results
        );
    }

    fn fee_paid() -> bool {
        get_created_receipts().iter().any(|r| r.receiver_id == a("fees.near"))
    }

    fn place_chain_order(c: &mut TradingAccount, via: Value, now: u64) -> U64 {
        let args = json!({"token_in": "wrap.near", "token_out": "jensen.near", "amount_in": NEAR.to_string(),
            "min_out": "50", "trigger_meta": "", "expires_at_ns": (T0 + 3_600 * NS_PER_SEC).to_string(),
            "dexes": ["v2.ref-finance.near", "dclv2.ref-labs.near"], "via": via});
        input_ctx(&args, now);
        c.place_order(
            wrap(),
            a("jensen.near"),
            U128(NEAR),
            U128(50),
            String::new(),
            U64(T0 + 3_600 * NS_PER_SEC),
            vec![a("v2.ref-finance.near"), a("dclv2.ref-labs.near")],
        )
    }

    fn via_json(min_mid: u128, max_mid: u128) -> Value {
        json!({"q": "zec.omft.near", "leg1_dex": "v2.ref-finance.near", "leg2_dex": "dclv2.ref-labs.near",
            "min_mid": min_mid.to_string(), "max_mid": max_mid.to_string()})
    }

    /// V16-01 (High): the relayer can't pick the leg-1 bound of a Chain order. min_mid below the
    /// stored one, a leg-1 msg bound below it, or max_mid above the stored one = E_ORDER_MID, and
    /// the order stays open. A fire within the stored terms runs.
    #[test]
    fn r01_relayer_chain_order_leg1_bound_is_stored() {
        let mut c = with_relayer();
        // (a mocked panic doesn't revert `pending`: one order per refused fire)
        let fire = |c: &mut TradingAccount, ch: Chain| {
            let id = place_chain_order(c, via_json(100, 110), T0 + 1);
            ctx_at(me().as_str(), Some(relayer_pk()), T0 + 2, 100);
            panics(std::panic::AssertUnwindSafe(|| {
                c.execute_order(id, vec![Op::NearDeposit { amount: U128(NEAR) }, Op::Chain(Box::new(ch))])
            }))
        };
        // the PoC fire: min_mid = 1, leg-1 bound 1, max_mid = u128::MAX / 2
        let poc = Chain {
            leg1: leg1(NEAR, 1),
            leg2: leg2(50),
            q: q(),
            min_mid: U128(1),
            max_mid: U128(u128::MAX / 2),
            min_final: U128(50),
        };
        assert_eq!(fire(&mut c, poc), E_ORDER_MID);
        let mut high = chain(100, 111, 50);
        high.max_mid = U128(111);
        assert_eq!(fire(&mut c, high), E_ORDER_MID, "max_mid above the stored bound");
        assert_eq!(c.get_orders().len(), 2, "the orders stay open");
        // the stored terms fire
        let id = place_chain_order(&mut c, via_json(100, 110), T0 + 1);
        ctx_at(me().as_str(), Some(relayer_pk()), T0 + 3, 100);
        c.execute_order(
            id,
            vec![Op::NearDeposit { amount: U128(NEAR) }, Op::Chain(Box::new(chain(100, 110, 50)))],
        );
        assert_eq!(c.get_q_lock(q()).map(|x| x.0), Some(format!("order:{}", id.0)));
    }

    #[test]
    fn r01_via_needs_the_leg1_bound() {
        let mut c = with_relayer();
        for bad in [via_json(0, 110), via_json(100, 99)] {
            let r = panics(std::panic::AssertUnwindSafe(|| {
                place_chain_order(&mut c, bad.clone(), T0 + 1);
            }));
            assert_eq!(r, "E_BAD_ORDER", "{bad}");
        }
        // an old-shape via (no bound) is refused as malformed JSON
        let old = json!({"q": "zec.omft.near", "leg1_dex": "v2.ref-finance.near", "leg2_dex": "dclv2.ref-labs.near"});
        let r = panics(std::panic::AssertUnwindSafe(|| {
            place_chain_order(&mut c, old.clone(), T0 + 1);
        }));
        assert_eq!(r, "E_BAD_ORDER");
    }

    fn curve_chain(quote: Option<AccountId>) -> Chain {
        let tok = "abc.umbrafun.near";
        Chain {
            leg1: ChainLeg::CurveBuy(venues::CurveTrade {
                venue: a(tok),
                market: None,
                quote,
                amount: U128(NEAR),
                min_out: U128(100),
                max_out: None,
                gas: U64(80 * TGAS),
                setup: false,
            }),
            leg2: ChainLeg::FtTransferCall {
                token: a(tok),
                receiver_id: a("dclv2.ref-labs.near"),
                amount: U128(0),
                msg: dcl(&[&format!("{tok}|jensen.near|10000")], "jensen.near", 50),
                gas: U64(80 * TGAS),
            },
            q: a(tok),
            min_mid: U128(100),
            max_mid: U128(110),
            min_final: U128(50),
        }
    }

    /// Runs a Chain to on_chain_mid; `refund(allowance)` = liquid NEAR that came back after leg 1.
    fn leg1_charged(ch: Chain, id: &str, refund: impl Fn(u128) -> u128) -> Option<u128> {
        let mut c = account();
        ctx_at(me().as_str(), None, T0 + 1, 100);
        exec(&mut c, vec![Op::Chain(Box::new(ch))], id);
        let st = st_of(id);
        cb_ctx(vec![ok_u(0)], 101);
        c.on_chain_start(st);
        let st = next_st("on_chain_leg1");
        let liquid = st.liquid.unwrap().0;
        let allowance = st.allowance.expect("set at dispatch").0;
        assert!(allowance > 0);
        let locked = u128::from(STORAGE_BYTES) * env::storage_byte_cost().as_yoctonear();
        cb_at(vec![PromiseResult::Successful(vec![])], 102, T0 + 10, liquid + locked + refund(allowance));
        c.on_chain_leg1(st);
        let st = next_st("on_chain_mid");
        st.charged.map(|x| x.0)
    }

    /// V16-04 (Medium): `quote: "wrap.near"` on a Chain curve buy is the same NEAR leg as
    /// `quote: None`: the fee is charged and the reserve check sees the whole deposit.
    #[test]
    fn r04_chain_curve_buy_quote_wrap_pays_fee_and_reserve() {
        let (m, w, al, r) = (me(), wrap(), allow(), a("fees.near"));
        let e = env_at(&m, &w, &al, &r, T0);
        let p = check_chain(&e, &curve_chain(Some(wrap())), false, None).unwrap();
        assert_eq!((p.counted, p.fee), (NEAR, NEAR / 100));
        assert_eq!(p.native_out, NEAR, "run's reserve check sees the planned deposit");
        assert_eq!(leg1_charged(curve_chain(Some(wrap())), "fw", |_| 0), Some(NEAR / 100), "fee charged");
        assert_eq!(leg1_charged(curve_chain(None), "fw0", |_| 0), Some(NEAR / 100), "control: quote None");
    }

    /// V16-09 (Low): the tx's own gas refunds (<= the allowance) no longer lower the leg-1 fee.
    #[test]
    fn r09_chain_leg1_gas_refunds_are_not_a_pad_refund() {
        // the PoC's 0.03 N, and the whole allowance: the fee is not lowered
        let gas_refund = 30_000_000_000_000_000_000_000;
        assert_eq!(leg1_charged(curve_chain(None), "g1", |_| gas_refund), Some(NEAR / 100));
        assert_eq!(leg1_charged(curve_chain(None), "g0", |a| a), Some(NEAR / 100));
        // a real pad refund on top of the allowance still lowers it pro rata
        assert_eq!(leg1_charged(curve_chain(None), "g2", |a| NEAR / 2 + a), Some(NEAR / 200));
    }

    /// V16-17 (Info): q = wNEAR Chains are refused (no NEAR leg; a payable leg 2 would attach
    /// native NEAR measured from a wNEAR delta).
    #[test]
    fn r17_q_wnear_chain_refused() {
        let mut ch = chain(100, 110, 50);
        ch.q = wrap();
        assert_eq!(check(&ch), Err(E_CHAIN_LEG));
    }

    fn held_chain(c: &mut TradingAccount, id: &str, h: u64) {
        ctx_at(me().as_str(), None, T0 + h, h);
        let mut ch = chain(100, 110, 50);
        ch.leg1 = leg1(NEAR / 10, 100);
        exec(c, vec![Op::NearDeposit { amount: U128(NEAR / 10) }, Op::Chain(Box::new(ch))], id);
        let st = st_of(id);
        cb_ctx(vec![ok_u(0)], h + 1);
        c.on_chain_start(st);
        let st = next_st("on_chain_leg1");
        cb_ctx(vec![ok_u(NEAR / 10)], h + 2);
        c.on_chain_leg1(st);
        let st = next_st("on_chain_mid");
        cb_ctx(vec![ok_u(99)], h + 3); // below min_mid -> held
        c.on_chain_mid(st);
    }

    fn signed_swap(c: &mut TradingAccount, now: u64) -> IntentsSwap {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk = format!("ed25519:{}", near_sdk::bs58::encode(sk.verifying_key().to_bytes()).into_string());
        testing_env!(VMContextBuilder::new()
            .current_account_id(me())
            .predecessor_account_id(a("owner.near"))
            .signer_account_id(a("owner.near"))
            .attached_deposit(NearToken::from_yoctonear(1))
            .account_balance(NearToken::from_yoctonear(10 * NEAR))
            .block_timestamp(now)
            .storage_usage(STORAGE_BYTES)
            .build());
        c.owner_set_oneclick_config(vec![pk], 300, None, None);
        let mut s = intents_swap();
        s.signed_quote = stable(&Value::Object(buy_quote(NEAR, now)));
        s.cont_deadline_ns = U64(now + 600 * NS_PER_SEC);
        let msg = crate::intents::signed_message(s.signed_quote.as_bytes());
        s.signature =
            format!("ed25519:{}", near_sdk::bs58::encode(sk.sign(msg.as_bytes()).to_bytes()).into_string());
        s
    }

    /// V16-05 (Medium): held routes take no slot: after 16 (and more) held Chains an IntentsSwap
    /// still runs. The held listing is capped (oldest unlisted, still readable).
    #[test]
    fn r05_held_routes_do_not_brick_intents_swap() {
        let mut c = account();
        for i in 0..(MAX_OPEN_ROUTES as u64 + 2) {
            held_chain(&mut c, &format!("h{i}"), 200 + i * 10);
        }
        assert!(c.get_routes().iter().all(|(_, r)| r.state == RouteState::Held));
        let now = T0 + 1_000;
        let s = signed_swap(&mut c, now);
        ctx_at(me().as_str(), None, now, 900);
        exec(&mut c, vec![Op::NearDeposit { amount: U128(NEAR) }, Op::IntentsSwap(s)], "i-new");
        assert_eq!(c.get_route("i-new".into()).unwrap().state, RouteState::Funded);
    }

    #[test]
    fn r05_in_flight_slots_and_held_listing_cap() {
        let _c = account();
        for i in 0..MAX_OPEN_ROUTES {
            save_route(&format!("f{i}"), &route(RouteKind::IntentsBuy)).unwrap();
        }
        assert!(!route_slot_free());
        assert_eq!(save_route("f16", &route(RouteKind::IntentsBuy)), Err("E_ROUTES_FULL"));
        // held routes still fit, the listing keeps at most MAX_HELD_LISTED of them
        let mut held = route(RouteKind::Chain);
        held.state = RouteState::Held;
        for i in 0..(MAX_HELD_LISTED + 3) {
            save_route(&format!("held{i}"), &held).unwrap();
        }
        let idx = route_index();
        assert_eq!(idx.len(), MAX_OPEN_ROUTES + MAX_HELD_LISTED);
        assert!(!idx.contains(&"held0".to_string()), "oldest held unlisted");
        assert!(load_route("held0").is_some(), "its record stays readable");
        // an in-flight route that ends frees its slot
        let mut done = route(RouteKind::IntentsBuy);
        done.state = RouteState::Done;
        save_route("f0", &done).unwrap();
        assert!(route_slot_free());
    }

    fn buy_route_fired(c: &mut TradingAccount, rid: &str, ops: Vec<Op>, now: u64) -> u64 {
        save_route(rid, &route(RouteKind::IntentsBuy)).unwrap();
        escrow_add(NEAR / 100);
        crate::save_route_spend(rid, c.day.start_ns, NEAR, NEAR / 100);
        let cid = new_cont(rid);
        ctx_at(me().as_str(), None, now, 100);
        c.execute_order(U64(cid), ops);
        cid
    }

    /// V16-06 (Medium): ft_withdraw returning "0" (a failed transfer refunded inside intents) is
    /// not a delivery: route unchanged, escrow kept, no fee, no leg-2 spend.
    #[test]
    fn r06_ft_withdraw_zero_is_not_delivery() {
        let mut c = account();
        let swap = Op::FtTransferCall {
            token: q(),
            receiver_id: a("dclv2.ref-labs.near"),
            amount: U128(1000),
            msg: dcl(&["zec.omft.near|jensen.near|10000"], "jensen.near", 50),
            gas: U64(80 * TGAS),
        };
        buy_route_fired(&mut c, "buy-zero", vec![Op::IntentsPull(pull(q(), 1000)), swap], T0 + 1);
        let leg = ChainLeg::FtTransferCall {
            token: q(),
            receiver_id: a("dclv2.ref-labs.near"),
            amount: U128(1000),
            msg: dcl(&["zec.omft.near|jensen.near|10000"], "jensen.near", 50),
            gas: U64(80 * TGAS),
        };
        cb_ctx(vec![PromiseResult::Successful(b"\"0\"".to_vec())], 101);
        c.on_cont_pulled("buy-zero".into(), pull(q(), 1000), Some(leg));
        assert_eq!(escrow_total(), NEAR / 100, "escrow kept");
        assert!(!fee_paid());
        let r = c.get_route("buy-zero".into()).unwrap();
        assert_eq!((r.state, r.credited.0, r.pending), (RouteState::Funded, 0, false));
        assert!(c.get_q_lock(q()).is_none());
        assert!(get_created_receipts().iter().all(|x| x.receiver_id != q()), "no leg-2 spend");
        assert!(get_logs().iter().any(|l| l.contains("route_pull_failed")));
    }

    /// V16-06: a partial return pulls and swaps only what arrived.
    #[test]
    fn r06_partial_pull_uses_the_returned_amount() {
        let mut c = account();
        let swap = Op::FtTransferCall {
            token: q(),
            receiver_id: a("dclv2.ref-labs.near"),
            amount: U128(1000),
            msg: dcl(&["zec.omft.near|jensen.near|10000"], "jensen.near", 50),
            gas: U64(80 * TGAS),
        };
        buy_route_fired(&mut c, "buy-part", vec![Op::IntentsPull(pull(q(), 1000)), swap], T0 + 1);
        let leg = ChainLeg::FtTransferCall {
            token: q(),
            receiver_id: a("dclv2.ref-labs.near"),
            amount: U128(1000),
            msg: dcl(&["zec.omft.near|jensen.near|10000"], "jensen.near", 50),
            gas: U64(80 * TGAS),
        };
        cb_ctx(vec![ok_u(400)], 101);
        c.on_cont_pulled("buy-part".into(), pull(q(), 1000), Some(leg));
        assert_eq!(c.get_route("buy-part".into()).unwrap().credited.0, 400);
        let rs = get_created_receipts();
        let t = rs.iter().find(|x| x.receiver_id == q()).expect("leg 2");
        match &t.actions[0] {
            MockAction::FunctionCallWeight { args, .. } => {
                let v: Value = near_sdk::serde_json::from_slice(args).unwrap();
                assert_eq!(v["amount"], "400");
            }
            x => panic!("{x:?}"),
        }
    }

    /// V16-07 (Medium): a 1-yocto (or any partial) refund pull is refused at fire time: it must
    /// bring back >= funded x (1 - slippage).
    #[test]
    fn r07_one_yocto_refund_pull_refused() {
        let mut c = account();
        let rid = "buy-dodge";
        save_route(rid, &route(RouteKind::IntentsBuy)).unwrap();
        escrow_add(NEAR / 100);
        crate::save_route_spend(rid, c.day.start_ns, NEAR, NEAR / 100);
        let cid = new_cont(rid);
        let after_quote = route(RouteKind::IntentsBuy).quote_deadline_ns.0 + 1;
        ctx_at(me().as_str(), None, after_quote, 100);
        let min = NEAR - NEAR / 100; // slippage 100 bps
        for x in [1, min - 1] {
            assert_eq!(
                panics(std::panic::AssertUnwindSafe(
                    || c.execute_order(U64(cid), vec![Op::IntentsPull(pull(wrap(), x))])
                )),
                E_ORDER_OPS
            );
        }
        assert_eq!(escrow_total(), NEAR / 100);
        assert!(!fee_paid());
        assert_eq!(c.get_route(rid.into()).unwrap().state, RouteState::Funded);
    }

    fn refund_setup(c: &mut TradingAccount, rid: &str) -> (u64, u64) {
        save_route(rid, &route(RouteKind::IntentsBuy)).unwrap();
        escrow_add(NEAR / 100);
        crate::save_route_spend(rid, c.day.start_ns, NEAR, NEAR / 100);
        let cid = new_cont(rid);
        let t = route(RouteKind::IntentsBuy).quote_deadline_ns.0 + 1;
        (cid, t)
    }

    /// V16-07: a full refund pull first checks the delivery (Q) is absent from the intents
    /// balance; Q there (>= q_min) = refused, the route unchanged.
    #[test]
    fn r07_refund_refused_while_delivery_present() {
        let mut c = account();
        let (cid, t) = refund_setup(&mut c, "rq");
        ctx_at(me().as_str(), None, t, 100);
        c.execute_order(U64(cid), vec![Op::IntentsPull(pull(wrap(), NEAR))]);
        let rs = get_created_receipts();
        let v = rs.iter().find(|x| x.receiver_id == a("intents.near")).unwrap();
        match &v.actions[0] {
            MockAction::FunctionCallWeight { method_name, args, .. } => {
                assert_eq!(method_name, b"mt_balance_of");
                let j: Value = near_sdk::serde_json::from_slice(args).unwrap();
                assert_eq!(j["token_id"], "nep141:zec.omft.near");
            }
            x => panic!("{x:?}"),
        }
        cb_at(vec![ok_u(990)], 101, t + 10, 10 * NEAR);
        c.on_cont_refund_check("rq".into(), pull(wrap(), NEAR));
        let r = c.get_route("rq".into()).unwrap();
        assert_eq!((r.state, r.pending), (RouteState::Funded, false));
        assert!(get_created_receipts().iter().all(|x| x.receiver_id != a("intents.near")), "no pull");
        assert!(get_logs().iter().any(|l| l.contains("route_refund_refused")));
        assert_eq!(escrow_total(), NEAR / 100);
    }

    /// V16-10 (Low): Kelytra (and Nearrr buys) can't be Chain / continuation / Chain-order legs.
    #[test]
    fn r10_callback_chain_venues_refused_as_legs() {
        let mut al = allow();
        al.push(Dex { id: a("exchange.kelytradevs.near"), kind: DexKind::Kelytra });
        let (m, w, r) = (me(), wrap(), a("fees.near"));
        let e = env_at(&m, &w, &al, &r, T0);
        let kel = venues::CurveTrade {
            venue: a("exchange.kelytradevs.near"),
            market: Some("0".into()),
            quote: None,
            amount: U128(1000),
            min_out: U128(100),
            max_out: None,
            gas: U64(165 * TGAS),
            setup: false,
        };
        // the PoC Chain (Kelytra sell, q = wNEAR)
        let poc = Chain {
            leg1: ChainLeg::CurveSell(kel.clone()),
            leg2: ChainLeg::FtTransferCall {
                token: wrap(),
                receiver_id: a("dclv2.ref-labs.near"),
                amount: U128(0),
                msg: dcl(&["wrap.near|jensen.near|2000"], "jensen.near", 50),
                gas: U64(20 * TGAS),
            },
            q: wrap(),
            min_mid: U128(100),
            max_mid: U128(110),
            min_final: U128(50),
        };
        assert_eq!(check_chain(&e, &poc, false, None).err(), Some(E_CHAIN_LEG));
        // the leg itself, whatever q
        assert_eq!(leg_info(&e, &ChainLeg::CurveSell(kel.clone()), false).err(), Some(E_CHAIN_LEG));
        let kel_buy = venues::CurveTrade { gas: U64(175 * TGAS), ..kel }; // Kelytra buy floor
        assert_eq!(leg_info(&e, &ChainLeg::CurveBuy(kel_buy), false).err(), Some(E_CHAIN_LEG));
        // a Nearrr buy (tax view -> buy chain)
        let nearrr = venues::CurveTrade {
            venue: a("nearrr-fun.near"),
            market: Some("tok.nearrr-fun.near".into()),
            quote: None,
            amount: U128(NEAR),
            min_out: U128(100),
            max_out: None,
            gas: U64(220 * TGAS), // V16-02: the chain declares 216
            setup: false,
        };
        assert_eq!(leg_info(&e, &ChainLeg::CurveBuy(nearrr), false).err(), Some(E_CHAIN_LEG));
        // Chain orders and continuation terms
        let d = vec![a("exchange.kelytradevs.near"), a("dclv2.ref-labs.near")];
        let v = OrderVia {
            q: q(),
            leg1_dex: a("exchange.kelytradevs.near"),
            leg2_dex: a("dclv2.ref-labs.near"),
            min_mid: U128(100),
            max_mid: U128(110),
        };
        assert_eq!(check_via(&v, &wrap(), &a("jensen.near"), &d, &me()), Ok(()));
        assert_eq!(check_via_venues(&v, &al), Err(E_CHAIN_LEG));
        let mut s = intents_swap();
        s.cont.dexes = vec![a("exchange.kelytradevs.near")];
        assert_eq!(super::super::exec::check_intents_swap(&e, &s, false).err(), Some(E_CHAIN_LEG));
    }

    // V16-07 / V16-08: need the lib.rs review-fix hunks (docs/venues-hooks.md "Review fixes (V16-xx)")
    /// V16-07: a proven refund releases fee and spend pro rata to what came back (the part
    /// 1Click kept is paid).
    #[test]
    fn r07_proven_refund_releases_pro_rata() {
        let mut c = account();
        c.day.spent_yocto = 5 * NEAR;
        let (cid, t) = refund_setup(&mut c, "rp");
        ctx_at(me().as_str(), None, t, 100);
        c.execute_order(U64(cid), vec![Op::IntentsPull(pull(wrap(), NEAR))]);
        cb_at(vec![ok_u(0)], 101, t + 10, 10 * NEAR);
        c.on_cont_refund_check("rp".into(), pull(wrap(), NEAR));
        assert!(get_created_receipts().iter().any(|x| x.receiver_id == a("intents.near")), "pull sent");
        // intents returns 99.5% of the funded amount
        let back = NEAR - NEAR / 200;
        cb_at(vec![ok_u(back)], 102, t + 20, 10 * NEAR);
        let spent = c.day.spent_yocto;
        c.on_cont_pulled("rp".into(), pull(wrap(), NEAR), None);
        assert_eq!(c.get_route("rp".into()).unwrap().state, RouteState::Refunded);
        assert_eq!(escrow_total(), 0);
        let kept_fee = NEAR / 100 - crate::policy::mul_div(NEAR / 100, back, NEAR);
        let paid: u128 = get_created_receipts()
            .iter()
            .filter(|r| r.receiver_id == a("fees.near"))
            .flat_map(|r| r.actions.iter())
            .map(|x| match x {
                MockAction::Transfer { deposit, .. } => deposit.as_yoctonear(),
                _ => 0,
            })
            .sum();
        assert_eq!(paid, kept_fee, "the unrefunded part of the fee is paid");
        let released = crate::policy::mul_div(NEAR + NEAR / 100, back, NEAR);
        assert_eq!(spent - c.day.spent_yocto, released, "spend back pro rata");
    }

    /// V16-07: while a buy route is Funded, the device can't move its tokens out of intents.
    #[test]
    fn r07_withdraw_from_intents_blocked_for_route_tokens() {
        let mut c = account();
        save_route("live", &route(RouteKind::IntentsBuy)).unwrap();
        ctx_at(me().as_str(), None, T0 + 1, 100);
        for t in [q(), wrap()] {
            assert_eq!(
                panics(std::panic::AssertUnwindSafe(|| c.withdraw_from_intents(t.clone(), U128(1)))),
                "E_Q_BUSY"
            );
        }
        c.withdraw_from_intents(a("usdc.near"), U128(1));
    }

    /// V16-08 (Low): a live route's id can't be reused (its escrow would be orphaned), and a
    /// device execute can't take the `order:` id space.
    #[test]
    fn r08_route_id_reuse_refused() {
        let mut c = account();
        save_route("x", &route(RouteKind::IntentsBuy)).unwrap();
        escrow_add(NEAR / 100);
        ctx_at(me().as_str(), None, T0 + 200 * NS_PER_SEC, 300);
        assert_eq!(panics(std::panic::AssertUnwindSafe(|| exec(&mut c, chain_ops(), "x"))), "E_ROUTE_EXISTS");
        assert_eq!(c.get_route("x".into()).unwrap().kind, RouteKind::IntentsBuy, "not overwritten");
        ctx_at(me().as_str(), None, T0 + 201 * NS_PER_SEC, 301);
        assert_eq!(panics(std::panic::AssertUnwindSafe(|| exec(&mut c, chain_ops(), "order:7"))), "E_BAD_OP");
        // a finished route's id may be reused
        let mut done = route(RouteKind::IntentsBuy);
        done.state = RouteState::Done;
        save_route("y", &done).unwrap();
        ctx_at(me().as_str(), None, T0 + 202 * NS_PER_SEC, 302);
        exec(&mut c, chain_ops(), "y");
    }
}

// ======================= V16-02 regression (docs/audit/v160-internal-review.md) =======================
// The review PoC `r02_near_in_full_inflow_fakes_full_refund` flipped: an unwrap in the same execute
// (a NEAR inflow landing before the settle) must never turn a real buy into "refunded".
mod review_v16_02 {
    use super::*;

    fn cb_at(results: Vec<PromiseResult>, height: u64, balance: u128) {
        testing_env!(
            VMContextBuilder::new()
                .current_account_id(me())
                .predecessor_account_id(me())
                .signer_account_id(me())
                .account_balance(NearToken::from_yoctonear(balance))
                .block_timestamp(T0 + 10)
                .block_height(height)
                .storage_usage(STORAGE_BYTES)
                .prepaid_gas(Gas::from_tgas(300))
                .build(),
            near_sdk::test_vm_config(),
            near_sdk::RuntimeFeesConfig::test(),
            Default::default(),
            results
        );
    }

    fn fee_paid() -> bool {
        get_created_receipts().iter().any(|r| r.receiver_id == a("fees.near"))
    }

    fn self_call(method: &str) -> Value {
        let rs = get_created_receipts();
        let r = rs
            .iter()
            .rev()
            .find(|r| {
                r.receiver_id == me()
                    && matches!(&r.actions[0], MockAction::FunctionCallWeight { method_name, .. } if method_name == method.as_bytes())
            })
            .unwrap_or_else(|| panic!("no {method}"));
        match &r.actions[0] {
            MockAction::FunctionCallWeight { args, .. } => near_sdk::serde_json::from_slice(args).unwrap(),
            _ => unreachable!(),
        }
    }

    fn arg<T: near_sdk::serde::de::DeserializeOwned>(v: &Value, k: &str) -> T {
        near_sdk::serde_json::from_value(v[k].clone()).unwrap()
    }

    /// A device Nearrr buy of 1 N, preceded by NearWithdraw{`inflow`} whose NEAR lands before every
    /// callback. The pad fills (`received` tokens). Returns (settled log, day spent, fee paid).
    fn nearrr_buy_with_inflow(inflow: u128, received: u128) -> (String, u128, bool) {
        let mut c = account();
        ctx_at(me().as_str(), None, T0 + 1, 100);
        let buy = venues::CurveTrade {
            venue: a("nearrr-fun.near"),
            market: Some("tok.nearrr-fun.near".into()),
            quote: None,
            amount: U128(NEAR),
            min_out: U128(100),
            max_out: None,
            gas: U64(230 * TGAS),
            setup: false,
        };
        let mut ops = vec![];
        if inflow > 0 {
            ops.push(Op::NearWithdraw { amount: U128(inflow) });
        }
        ops.push(Op::CurveBuy(buy));
        exec(&mut c, ops, "nb");
        assert_eq!(c.get_day().spent_yocto.0, NEAR + NEAR / 100, "execute counted spend + fee");
        let rich = 10 * NEAR + inflow;
        let v = self_call("on_nearrr_tax");
        cb_at(vec![PromiseResult::Successful(br#"{"mode":"Standard","buy_tax_bps":0}"#.to_vec())], 101, rich);
        c.on_nearrr_tax(arg(&v, "settle"), arg(&v, "min_out"), arg(&v, "dex"), arg(&v, "label"));
        let v = self_call("on_nearrr_before");
        cb_at(vec![PromiseResult::Successful(b"\"0\"".to_vec())], 102, rich);
        c.on_nearrr_before(arg(&v, "settle"), arg(&v, "token"), arg(&v, "pad_min"), arg(&v, "dex"));
        let v = self_call("on_nearrr_settled");
        cb_at(vec![PromiseResult::Successful(format!("\"{received}\"").into_bytes())], 103, rich);
        c.on_nearrr_settled(arg(&v, "settle"), arg(&v, "before"), arg(&v, "token"));
        let log = get_logs().into_iter().find(|l| l.contains("\"settled\"")).unwrap();
        (log, c.get_day().spent_yocto.0, fee_paid())
    }

    #[test]
    fn v16_02_unwrap_in_the_same_execute_is_not_a_refund() {
        let (log, spent, fee) = nearrr_buy_with_inflow(NEAR + NEAR / 10, 5_000);
        assert!(log.contains(&format!("\"used\":\"{NEAR}\"")), "{log}");
        assert_eq!(spent, NEAR + NEAR / 100, "spend kept");
        assert!(fee, "fee charged");
    }

    #[test]
    fn v16_02_control_no_inflow() {
        let (log, spent, fee) = nearrr_buy_with_inflow(0, 5_000);
        assert!(log.contains(&format!("\"used\":\"{NEAR}\"")), "{log}");
        assert_eq!(spent, NEAR + NEAR / 100);
        assert!(fee);
    }

    /// The pad refunded (no tokens: the LOCKED output token is the proof, R2-05) while an unwrap
    /// landed: nothing used, no fee, spend back. The NEAR inflow is never read.
    #[test]
    fn v16_02_real_refund_proven_by_the_locked_token() {
        let (log, spent, fee) = nearrr_buy_with_inflow(NEAR + NEAR / 10, 0);
        assert!(log.contains("\"used\":\"0\"") && log.contains("\"fee\":\"0\""), "{log}");
        assert_eq!(spent, 0, "spend back");
        assert!(!fee);
    }

    /// The review-2 PoC `r2_05_nearrr_order_refund_reopens_the_order`, now green: a relayer fire
    /// the pad refunds (no token arrived) reopens the order (UNR-A-02); a fill consumes it.
    fn relayer_fire(received: u128) -> (TradingAccount, U64) {
        let mut c = with_relayer();
        ctx_at(me().as_str(), None, T0 + 1, 100);
        let id = c.place_order(
            wrap(),
            a("tok.nearrr-fun.near"),
            U128(NEAR),
            U128(100),
            String::new(),
            U64(T0 + 3_600 * NS_PER_SEC),
            vec![a("nearrr-fun.near")],
        );
        ctx_at(me().as_str(), Some(relayer_pk()), T0 + 2, 100);
        c.execute_order(
            id,
            vec![Op::CurveBuy(venues::CurveTrade {
                venue: a("nearrr-fun.near"),
                market: Some("tok.nearrr-fun.near".into()),
                quote: None,
                amount: U128(NEAR),
                min_out: U128(100),
                max_out: None,
                gas: U64(230 * TGAS),
                setup: false,
            })],
        );
        let v = self_call("on_nearrr_tax");
        cb_ctx(vec![PromiseResult::Successful(br#"{"mode":"Standard","buy_tax_bps":0}"#.to_vec())], 101);
        c.on_nearrr_tax(arg(&v, "settle"), arg(&v, "min_out"), arg(&v, "dex"), arg(&v, "label"));
        let v = self_call("on_nearrr_before");
        cb_ctx(vec![PromiseResult::Successful(b"\"0\"".to_vec())], 102);
        c.on_nearrr_before(arg(&v, "settle"), arg(&v, "token"), arg(&v, "pad_min"), arg(&v, "dex"));
        let v = self_call("on_nearrr_settled");
        cb_ctx(vec![PromiseResult::Successful(format!("\"{received}\"").into_bytes())], 103);
        c.on_nearrr_settled(arg(&v, "settle"), arg(&v, "before"), arg(&v, "token"));
        (c, id)
    }

    #[test]
    fn r2_05_nearrr_order_refund_reopens_the_order() {
        let (c, id) = relayer_fire(0);
        assert!(get_logs().iter().any(|l| l.contains("nearrr_refunded")));
        let o = c.get_order(id).expect("order kept");
        assert!(!o.pending, "reopened");
        assert!(get_logs().iter().any(|l| l.contains("order_reopened")));
        assert_eq!(c.get_day().spent_yocto.0, 0, "spend back");
        assert!(!fee_paid());
        assert!(lock_of("tok.nearrr-fun.near").is_none(), "unlocked");
    }

    #[test]
    fn r2_05_control_fill_consumes_the_order() {
        let (c, id) = relayer_fire(5_000);
        assert!(c.get_order(id).is_none(), "filled");
        assert!(fee_paid());
        assert!(lock_of("tok.nearrr-fun.near").is_none(), "unlocked");
    }

    /// While a Nearrr buy is in flight its output token is locked: a sell of it, a device
    /// withdraw and a cross-chain withdraw of it are refused (E_Q_BUSY), so the balance proof
    /// can't be faked; a second buy of it too. Other tokens are unaffected.
    #[test]
    fn r2_05_output_token_locked_until_settle() {
        let mut c = account();
        ctx_at(me().as_str(), None, T0 + 1, 100);
        let buy = |_id: &str| venues::CurveTrade {
            venue: a("nearrr-fun.near"),
            market: Some("tok.nearrr-fun.near".into()),
            quote: None,
            amount: U128(NEAR / 10),
            min_out: U128(100),
            max_out: None,
            gas: U64(230 * TGAS),
            setup: false,
        };
        exec(&mut c, vec![Op::CurveBuy(buy("b1"))], "b1");
        assert_eq!(lock_of("tok.nearrr-fun.near").map(|(h, _)| h), Some("nearrr:b1".to_string()));
        let v = self_call("on_nearrr_tax");
        let sell = venues::CurveTrade { amount: U128(5), min_out: U128(1), ..buy("s") };
        assert_eq!(
            panics(std::panic::AssertUnwindSafe(|| {
                let c = &mut c;
                ctx_at(me().as_str(), None, T0 + 2, 100);
                exec(c, vec![Op::CurveSell(sell.clone())], "s1");
            })),
            "E_Q_BUSY"
        );
        assert_eq!(
            panics(std::panic::AssertUnwindSafe(|| {
                let c = &mut c;
                ctx_at(me().as_str(), None, T0 + 2, 100);
                exec(c, vec![Op::CurveBuy(buy("b2"))], "b2");
            })),
            "E_Q_BUSY"
        );
        assert_eq!(
            panics(std::panic::AssertUnwindSafe(|| {
                let c = &mut c;
                ctx_at(me().as_str(), None, T0 + 2, 100);
                c.withdraw_to_owner(Some(a("tok.nearrr-fun.near")), U128(5));
            })),
            "E_Q_BUSY"
        );
        // a refused view (unparsable; R2-06: a failed receipt now reads 0 and buys) releases it
        cb_ctx(vec![PromiseResult::Successful(b"not json".to_vec())], 101);
        c.on_nearrr_tax(arg(&v, "settle"), arg(&v, "min_out"), arg(&v, "dex"), arg(&v, "label"));
        assert!(lock_of("tok.nearrr-fun.near").is_none());
    }
}

// ======================= v1.6 taxed outputs (venues/tax.rs) =======================

fn taxed_chain() -> Chain {
    let mut c = chain(100, 110, 50);
    c.leg2 = ChainLeg::FtTransferCall {
        token: q(),
        receiver_id: a("dclv2.ref-labs.near"),
        amount: U128(0),
        msg: dcl(&["zec.omft.near|jensen.nearrr-fun.near|10000"], "jensen.nearrr-fun.near", 50),
        gas: U64(80 * TGAS),
    };
    c
}

#[test]
fn gated_chain_fire_budgets_the_gate() {
    let (m, w, al, r) = (me(), wrap(), allow(), a("fees.near"));
    let e = env_at(&m, &w, &al, &r, T0);
    // legs at the ungated limit: a device execute passes, an order fire (gated) does not
    let mut c = taxed_chain();
    let room = MAX_CHAIN_GAS - CHAIN_OVERHEAD_TGAS - 80;
    if let ChainLeg::FtTransferCall { gas, .. } = &mut c.leg1 {
        *gas = U64(room * TGAS);
    }
    assert!(check_chain(&e, &c, false, None).is_ok());
    assert_eq!(check_chain(&e, &c, true, Some(50)), Err(E_CHAIN_GAS));
    // 23 TGas less: the gated fire fits exactly
    if let ChainLeg::FtTransferCall { gas, .. } = &mut c.leg1 {
        *gas = U64((room - venues::tax::GATE_CHAIN_EXTRA_TGAS) * TGAS);
    }
    let p = check_chain(&e, &c, true, Some(50)).unwrap();
    assert_eq!(p.gas + venues::tax::GATE_CHAIN_EXTRA_TGAS * TGAS, MAX_CHAIN_GAS * TGAS);
    // an untaxed output is never charged the gate
    let mut u = chain(100, 110, 50);
    if let ChainLeg::FtTransferCall { gas, .. } = &mut u.leg1 {
        *gas = U64(room * TGAS);
    }
    assert!(check_chain(&e, &u, true, Some(50)).is_ok());
}

#[test]
fn gated_chain_orders_always_have_room() {
    // V16-10 refuses Kelytra / Nearrr legs at place_order; the heaviest remaining leg minimum
    // (a Shards sell: 20 + the Q withdraw 50) plus a 20 TGas leg 2 still fits a gated fire
    let heaviest_min = crate::MIN_SWAP_GAS + GAS_SHARDS_Q_WITHDRAW;
    assert!(
        heaviest_min + crate::MIN_SWAP_GAS + CHAIN_OVERHEAD_TGAS + venues::tax::GATE_CHAIN_EXTRA_TGAS
            <= MAX_CHAIN_GAS
    );
    let al = allow();
    let heavy = OrderVia { leg1_dex: a("nearrr-fun.near"), ..via() };
    assert_eq!(check_via_venues(&heavy, &al), Err(E_CHAIN_LEG));
}

fn gate_chain_cb(native_out: u128) -> (TradingAccount, Vec<String>) {
    let mut c = account();
    cb_ctx(
        vec![PromiseResult::Successful(br#"{"mode":"Tax","buy_tax_bps":50,"sell_tax_bps":50}"#.to_vec())],
        101,
    );
    let settle: crate::SettleArgs = near_sdk::serde_json::from_value(json!({"client_order_id": "g1",
        "amount": NEAR.to_string(), "counted": NEAR.to_string(), "fee": "0", "day_start": "0", "proof": "wrap"}))
    .unwrap();
    let gate = venues::tax::Gate {
        token: a("jensen.nearrr-fun.near"),
        dex: "dclv2.ref-labs.near".into(),
        kind: venues::tax::TaxKind::Nearrr,
        floor: U128(100),
        min_out: U128(200),
        native_out: U128(native_out),
    };
    c.on_tax_gate_chain(settle, gate, taxed_chain(), "g1".into());
    let started =
        get_created_receipts().iter().filter(|r| r.receiver_id == q()).map(|_| "q".to_string()).collect();
    (c, started)
}

#[test]
fn gated_chain_rechecks_the_reserve_before_starting() {
    // the balance no longer covers leg 1's NEAR (+ reserve): refused, settled as failed, no lock
    let (_, started) = gate_chain_cb(10 * NEAR);
    assert!(started.is_empty(), "{started:?}");
    let logs = get_logs();
    assert!(logs.iter().any(|l| l.contains("tax_gate_refused")), "{logs:?}");
    assert!(logs.iter().any(|l| l.contains("\"settled\"") && l.contains("\"used\":\"0\"")), "{logs:?}");
    // covered: the Chain starts (its Q balance view)
    let (_, started) = gate_chain_cb(NEAR);
    assert_eq!(started.len(), 1);
    assert!(!get_logs().iter().any(|l| l.contains("tax_gate_refused")));
}

// ======================= R2-06 regression (docs/audit/v160-internal-review-2.md) =======================
// The review PoC (review2-pocs.patch) as a regression test: a taxed view over the old 4 KiB read
// limit must be read (up to 16 KiB) or refused, never taken as "no view" (= untaxed).
mod review2_r2_06 {
    use super::*;

    fn gate_and_call() -> (crate::SettleArgs, venues::tax::Gate, venues::tax::GatedCall) {
        let settle: crate::SettleArgs = near_sdk::serde_json::from_value(json!({"client_order_id": "order:0",
            "amount": NEAR.to_string(), "counted": NEAR.to_string(), "fee": "0", "day_start": "0", "proof": "wrap"}))
        .unwrap();
        let gate = venues::tax::Gate {
            token: a("ribbit-2.nearlytrade.near"),
            dex: "dclv2.ref-labs.near".into(),
            kind: venues::tax::TaxKind::Nearly,
            floor: U128(1_000),
            min_out: U128(1_000), // the order's floor, pre-tax: 10% tax -> 900 delivered
            native_out: U128(0),
        };
        let call = venues::tax::GatedCall {
            receiver: wrap(),
            method: "ft_transfer_call".into(),
            args: "{}".into(),
            deposit: U128(1),
            gas: U64(80 * TGAS),
        };
        (settle, gate, call)
    }

    fn view_with(exempt: usize) -> String {
        let exempt: Vec<String> = (0..exempt).map(|i| format!("exempt-account-number-{i:04}.near")).collect();
        json!({"tax": {"buy_bps": 1000, "sell_bps": 1000, "pairs": ["dclv2.ref-labs.near"],
            "admin": "nearlytrade.near", "exempt": exempt}, "pending": "0"})
        .to_string()
    }

    /// R2-06 (Low): a 10% taxed Nearly view padded past 4 KiB passed the gate as untaxed.
    #[test]
    fn r2_06_tax_gate_long_view_is_refused() {
        let mut c = account();
        let view = view_with(120);
        assert!(view.len() > 4_096);
        let (settle, gate, call) = gate_and_call();
        cb_ctx(vec![PromiseResult::Successful(view.into_bytes())], 101);
        c.on_tax_gate(settle, gate, call);
        let swapped = get_created_receipts().iter().any(|r| r.receiver_id == wrap());
        assert!(!swapped, "a 10% taxed token passed the gate as untaxed (view > 4 KiB)");
        assert!(get_logs().iter().any(|l| l.contains("tax_gate_refused")));
    }

    /// R2-06 (owner decision): a failed view receipt reads as 0 for any Nearly token (the untaxed
    /// templates have no get_tax): the swap goes out at the floor.
    #[test]
    fn r2_06_failed_view_reads_0_and_forwards_the_swap() {
        let mut c = account();
        let (settle, gate, call) = gate_and_call(); // ribbit-2, min_out == floor
        cb_ctx(vec![PromiseResult::Failed], 101);
        c.on_tax_gate(settle, gate, call);
        assert!(get_created_receipts().iter().any(|r| r.receiver_id == wrap()), "swap not sent");
        assert!(!get_logs().iter().any(|l| l.contains("tax_gate_refused")));
    }

    /// R2-06 on the Chain path (`on_tax_gate_chain`): an over-size view refuses before the Chain
    /// starts; a failed view reads as 0 and starts it.
    #[test]
    fn r2_06_gated_chain_view_rules() {
        let run = |token: &str, r: PromiseResult| {
            let mut c = account();
            cb_ctx(vec![r], 101);
            let settle: crate::SettleArgs = near_sdk::serde_json::from_value(json!({"client_order_id": "g1",
                "amount": NEAR.to_string(), "counted": NEAR.to_string(), "fee": "0", "day_start": "0", "proof": "wrap"}))
            .unwrap();
            let gate = venues::tax::Gate {
                token: a(token),
                dex: "dclv2.ref-labs.near".into(),
                kind: venues::tax::TaxKind::Nearrr,
                floor: U128(100),
                min_out: U128(200),
                native_out: U128(NEAR),
            };
            c.on_tax_gate_chain(settle, gate, taxed_chain(), "g1".into());
            let started = get_created_receipts().iter().any(|r| r.receiver_id == q());
            (started, get_logs().iter().any(|l| l.contains("tax_gate_refused")))
        };
        assert_eq!(run("jensen.nearrr-fun.near", PromiseResult::Failed), (true, false));
        let mut long = br#"{"mode":"Tax","buy_tax_bps":50,"sell_tax_bps":50}"#.to_vec();
        long.resize(venues::tax::MAX_VIEW_LEN + 1, b' ');
        assert_eq!(run("jensen.nearrr-fun.near", PromiseResult::Successful(long)), (false, true));
    }

    /// Control for R2-06: the same 10% view under 4 KiB is refused.
    #[test]
    fn r2_06_control_short_view_is_refused() {
        let mut c = account();
        let (settle, gate, call) = gate_and_call();
        cb_ctx(vec![PromiseResult::Successful(view_with(0).into_bytes())], 101);
        c.on_tax_gate(settle, gate, call);
        assert!(!get_created_receipts().iter().any(|r| r.receiver_id == wrap()));
        assert!(get_logs().iter().any(|l| l.contains("tax_gate_refused")));
    }
}

// ======================= a curve leg's own storage call is budgeted =======================

fn patata() -> AccountId {
    a(venues::PATATA)
}

/// `allow()` + the PATATA-paired Aidols pad.
fn aidols_allow() -> Vec<Dex> {
    let mut al = allow();
    al.push(Dex { id: a("patata-monster.near"), kind: DexKind::AidolsCurve(venues::AidolsPad::Patata) });
    al
}

/// `account()` with the PATATA-paired Aidols pad allowlisted.
fn aidols_account() -> TradingAccount {
    ctx_at("tt.near", None, T0, 100);
    near_sdk::mock::with_mocked_blockchain(|b| {
        b.take_storage();
    });
    ctx_at("tt.near", None, T0, 100);
    TradingAccount::init(
        a("owner.near"),
        FeeConfig { fee_bps: 100, fee_recipient: a("fees.near") },
        Caps { max_trade_yocto: U128(3 * NEAR), daily_cap_yocto: U128(9 * NEAR) },
        aidols_allow(),
        wrap(),
        None,
        None,
        None,
    )
}

/// The static gas the last created self-call `method` was given.
fn cb_gas_of(method: &str) -> u64 {
    get_created_receipts()
        .iter()
        .flat_map(|r| r.actions.iter())
        .filter_map(|x| match x {
            MockAction::FunctionCallWeight { method_name, prepaid_gas, .. }
                if method_name == method.as_bytes() =>
            {
                Some(prepaid_gas.as_gas())
            }
            _ => None,
        })
        .next_back()
        .unwrap_or_else(|| panic!("no {method}"))
}

/// What a scheduling callback needs by the contract's own budget rule (`budgets`, the
/// continuation's `cb`): itself (GAS_CHAIN_CB), all the gas it attaches, and GAS_ACTION per
/// function call it schedules. Plain legs meet it exactly. (The mocked runtime's fee schedule is
/// not mainnet's, so the static gas is checked against this rule, not by running out of it.)
fn needed_by_created() -> u64 {
    let fcs: Vec<u64> = get_created_receipts()
        .iter()
        .flat_map(|r| r.actions.iter())
        .filter_map(|x| match x {
            MockAction::FunctionCallWeight { prepaid_gas, .. } => Some(prepaid_gas.as_gas()),
            _ => None,
        })
        .collect();
    GAS_CHAIN_CB * TGAS + fcs.iter().sum::<u64>() + fcs.len() as u64 * GAS_ACTION * TGAS
}

/// A trade on the PATATA Aidols pad (the pad's only quote): a Q-paid buy or a sell for PATATA.
fn aidols_trade(amount: u128) -> venues::CurveTrade {
    venues::CurveTrade {
        venue: a("patata-monster.near"),
        market: Some("x.patata-monster.near".into()),
        quote: Some(patata()),
        amount: U128(amount),
        min_out: U128(50),
        max_out: None,
        gas: U64(60 * TGAS),
        setup: false,
    }
}

/// An Aidols-family trade plans a `storage_deposit` (GAS_VENUE_STORAGE) before its trade call
/// (the output token for a buy, the quote for a Q-paid sell), on top of the op's declared gas;
/// `run` budgets `Plan.gas`, which includes it, plus an action per extra call. A Chain's leg 1
/// (sent from on_chain_start) and a continuation's swap (from on_cont_pulled) are scheduled by a
/// callback whose static gas must cover the same: the storage call, the trade, its next callback
/// and an action fee each. Before the fix both budgeted only the op's gas (10 TGas + an action
/// short: on chain the callback runs out of gas while scheduling; a continuation then stays
/// `pending` with its pull delivered). An Aidols Q-buy can't be a leg 2 (its storage deposit makes
/// it payable, E_CHAIN_LEG).
#[test]
fn aidols_chain_leg1_storage_call_is_budgeted() {
    // Chain: x.patata-monster.near -> PATATA (Aidols sell, leg 1) -> NEAR (Rhea classic)
    let mut c = aidols_account();
    let ch = Chain {
        leg1: ChainLeg::CurveSell(aidols_trade(NEAR)),
        leg2: ChainLeg::FtTransferCall {
            token: patata(),
            receiver_id: a("v2.ref-finance.near"),
            amount: U128(0),
            msg: classic(6066, venues::PATATA, "wrap.near", None, 50),
            gas: U64(80 * TGAS),
        },
        q: patata(),
        min_mid: U128(50),
        max_mid: U128(110),
        min_final: U128(50),
    };
    let leg2 = Chain {
        leg1: ChainLeg::FtTransferCall {
            token: wrap(),
            receiver_id: a("v2.ref-finance.near"),
            amount: U128(NEAR),
            msg: classic(6066, "wrap.near", venues::PATATA, Some(NEAR), 100),
            gas: U64(80 * TGAS),
        },
        leg2: ChainLeg::CurveBuy(aidols_trade(0)),
        min_mid: U128(100),
        ..ch.clone()
    };
    let (m, w, al, rf) = (me(), wrap(), aidols_allow(), a("fees.near"));
    let e = env_at(&m, &w, &al, &rf, T0);
    assert!(check_chain(&e, &ch, false, None).is_ok());
    assert_eq!(check_chain(&e, &leg2, false, None).err(), Some(E_CHAIN_LEG), "a payable leg 2");
    ctx_at(me().as_str(), None, T0 + 1, 100);
    exec(&mut c, vec![Op::Chain(Box::new(ch))], "ap1");
    let st = st_of("ap1");
    let have = cb_gas_of("on_chain_start");
    cb_ctx(vec![ok_u(0)], 101);
    c.on_chain_start(st);
    assert!(have >= needed_by_created(), "on_chain_start: {} < {}", have / TGAS, needed_by_created() / TGAS);
    let rs = get_created_receipts();
    assert!(rs.iter().any(|r| r.receiver_id == patata()), "storage call on the quote");
    assert!(rs.iter().any(|r| r.receiver_id == a("x.patata-monster.near")), "the sell");
    let _ = next_st("on_chain_leg1");
}

/// The continuation side of `aidols_chain_leg1_storage_call_is_budgeted`: pull PATATA, then an
/// Aidols Q-buy within the stored terms (scheduled by on_cont_pulled).
#[test]
fn aidols_continuation_swap_storage_call_is_budgeted() {
    let mut c = aidols_account();
    let rid = "ap2";
    let r = Route {
        q: patata(),
        cont: Some(ContTerms {
            token_out: a("x.patata-monster.near"),
            dexes: vec![a("patata-monster.near")],
            min_final: U128(50),
        }),
        ..route(RouteKind::IntentsBuy)
    };
    save_route(rid, &r).unwrap();
    escrow_add(NEAR / 100);
    let cid = new_cont(rid);
    ctx_at(me().as_str(), None, T0 + 1, 100);
    c.execute_order(U64(cid), vec![Op::IntentsPull(pull(patata(), 1000)), Op::CurveBuy(aidols_trade(1000))]);
    let have = cb_gas_of("on_cont_pulled");
    cb_ctx(vec![ok_u(1000)], 101);
    c.on_cont_pulled(rid.into(), pull(patata(), 1000), Some(ChainLeg::CurveBuy(aidols_trade(1000))));
    assert!(have >= needed_by_created(), "on_cont_pulled: {} < {}", have / TGAS, needed_by_created() / TGAS);
    let rs = get_created_receipts();
    assert!(rs.iter().any(|r| r.receiver_id == a("x.patata-monster.near")), "storage call");
    assert!(rs.iter().any(|r| r.receiver_id == patata()), "the Q-paid buy");
    assert_eq!(cb_gas_of("on_cont_swapped"), GAS_CHAIN_CB * TGAS);
}

/// Control: plain legs (a Rhea leg 1; a DCL continuation swap) meet the same rule exactly.
#[test]
fn plain_legs_meet_the_budget_rule_exactly() {
    let (mut c, st) = run_to_start();
    let have = cb_gas_of("on_chain_start");
    cb_ctx(vec![ok_u(0)], 101);
    c.on_chain_start(st);
    assert_eq!(have, needed_by_created(), "on_chain_start");
    let mut c = account();
    save_route("pl", &route(RouteKind::IntentsBuy)).unwrap();
    escrow_add(NEAR / 100);
    let cid = new_cont("pl");
    let leg = ChainLeg::FtTransferCall {
        token: q(),
        receiver_id: a("dclv2.ref-labs.near"),
        amount: U128(1000),
        msg: dcl(&["zec.omft.near|jensen.near|10000"], "jensen.near", 50),
        gas: U64(80 * TGAS),
    };
    let ChainLeg::FtTransferCall { token, receiver_id, amount, msg, gas } = leg.clone() else {
        unreachable!()
    };
    ctx_at(me().as_str(), None, T0 + 1, 100);
    c.execute_order(
        U64(cid),
        vec![Op::IntentsPull(pull(q(), 1000)), Op::FtTransferCall { token, receiver_id, amount, msg, gas }],
    );
    let have = cb_gas_of("on_cont_pulled");
    cb_ctx(vec![ok_u(1000)], 101);
    c.on_cont_pulled("pl".into(), pull(q(), 1000), Some(leg));
    assert_eq!(have, needed_by_created(), "on_cont_pulled");
}

// ======================= R2-05 send-time lock re-check (external audit F-1, F-2) =======================
// A token `run` checked free at the execute may be locked by the time a CALLBACK sends it (a Chain's
// leg 1 in on_chain_start, a gated swap in on_tax_gate, a gated Chain's Q in on_tax_gate_chain).
// Each now settles as a failed swap (spend back, an order reopens) instead of moving a locked token
// (F-1: a Nearrr buy's fill then read as a refund, V16-02) or panicking (F-2: order stuck Pending).
mod review_r2_05_send_time {
    use super::*;

    const T: &str = "tok.nearrr-fun.near";

    fn self_call(method: &str) -> Value {
        let rs = get_created_receipts();
        let r = rs
            .iter()
            .rev()
            .find(|r| {
                r.receiver_id == me()
                    && matches!(&r.actions[0], MockAction::FunctionCallWeight { method_name, .. } if method_name == method.as_bytes())
            })
            .unwrap_or_else(|| panic!("no {method}"));
        match &r.actions[0] {
            MockAction::FunctionCallWeight { args, .. } => near_sdk::serde_json::from_slice(args).unwrap(),
            _ => unreachable!(),
        }
    }

    fn arg<X: near_sdk::serde::de::DeserializeOwned>(v: &Value, k: &str) -> X {
        near_sdk::serde_json::from_value(v[k].clone()).unwrap()
    }

    fn sends_token(token: &str) -> bool {
        get_created_receipts().iter().any(|r| {
            r.receiver_id == a(token)
                && r.actions.iter().any(|x| matches!(x, MockAction::FunctionCallWeight { method_name, .. } if method_name == b"ft_transfer_call"))
        })
    }

    fn settled(id: &str) -> String {
        get_logs()
            .into_iter()
            .find(|l| l.contains("\"settled\"") && l.contains(&format!("\"client_order_id\":\"{id}\"")))
            .unwrap_or_else(|| panic!("no settle for {id}: {:?}", get_logs()))
    }

    /// A device Chain selling `T` on Rhea for q (leg 1 sends T in on_chain_start).
    fn sell_t_chain(c: &mut TradingAccount, rid: &str) -> ChainSt {
        ctx_at(me().as_str(), None, T0 + 1, 100);
        let ch = Chain {
            leg1: ChainLeg::FtTransferCall {
                token: a(T),
                receiver_id: a("v2.ref-finance.near"),
                amount: U128(5_000),
                msg: classic(7001, T, "zec.omft.near", Some(5_000), 100),
                gas: U64(80 * TGAS),
            },
            leg2: leg2(50),
            q: q(),
            min_mid: U128(100),
            max_mid: U128(110),
            min_final: U128(50),
        };
        exec(c, vec![Op::Chain(Box::new(ch))], rid);
        st_of(rid)
    }

    /// F-1 (the PoC): the Chain executes first (T free), then a Nearrr buy of T takes T's lock;
    /// when on_chain_start runs, T is locked: the Chain is refused (nothing sent, Q unlocked,
    /// settled as failed) and the buy's fill reads as the fill it is (used, fee). The same check
    /// closes the relayer-only variant (a stored Chain sell order fired next to a Nearrr buy
    /// order): on_chain_start doesn't care who fired it.
    #[test]
    fn r2_05_chain_leg1_input_locked_since_execute_is_refused() {
        let mut c = account();
        let st = sell_t_chain(&mut c, "sell");
        ctx_at(me().as_str(), None, T0 + 1, 100);
        let buy = venues::CurveTrade {
            venue: a("nearrr-fun.near"),
            market: Some(T.into()),
            quote: None,
            amount: U128(NEAR / 10),
            min_out: U128(100),
            max_out: None,
            gas: U64(230 * TGAS),
            setup: false,
        };
        exec(&mut c, vec![Op::CurveBuy(buy)], "b1");
        assert_eq!(lock_of(T).map(|(h, _)| h), Some("nearrr:b1".to_string()));
        let v = self_call("on_nearrr_tax");
        cb_ctx(vec![PromiseResult::Successful(br#"{"mode":"Standard","buy_tax_bps":0}"#.to_vec())], 101);
        c.on_nearrr_tax(arg(&v, "settle"), arg(&v, "min_out"), arg(&v, "dex"), arg(&v, "label"));
        let vb = self_call("on_nearrr_before");
        cb_ctx(vec![ok_u(5_000)], 102);
        c.on_nearrr_before(arg(&vb, "settle"), arg(&vb, "token"), arg(&vb, "pad_min"), arg(&vb, "dex"));
        let vs = self_call("on_nearrr_settled");
        // the Chain's step 1 while T is locked by the buy
        cb_ctx(vec![ok_u(7)], 103);
        c.on_chain_start(st);
        assert!(!sends_token(T), "T must not leave while locked");
        assert!(get_logs().iter().any(|l| l.contains("q_busy") && l.contains(T)));
        assert!(c.get_q_lock(q()).is_none(), "the Chain released Q");
        let s = settled("sell");
        assert!(s.contains("\"used\":\"0\"") && s.contains("\"fee\":\"0\""), "{s}");
        // the pad filled 5000 T and nothing else moved T: a fill, fee charged
        cb_ctx(vec![ok_u(10_000)], 104);
        c.on_nearrr_settled(arg(&vs, "settle"), arg(&vs, "before"), arg(&vs, "token"));
        let s = settled("b1");
        assert!(s.contains(&format!("\"used\":\"{}\"", NEAR / 10)), "{s}");
        assert!(!s.contains("\"fee\":\"0\""), "{s}");
    }

    /// Control: leg 1's input is free -> the Chain sends it as before.
    #[test]
    fn r2_05_control_chain_leg1_free_input_is_sent() {
        let mut c = account();
        let st = sell_t_chain(&mut c, "sell");
        cb_ctx(vec![ok_u(7)], 101);
        c.on_chain_start(st);
        assert!(sends_token(T));
        assert_eq!(c.get_q_lock(q()).map(|x| x.0), Some("sell".to_string()));
        assert!(!get_logs().iter().any(|l| l.contains("q_busy")));
    }

    fn gated_swap(locked: bool) -> bool {
        let mut c = account();
        if locked {
            ctx_at(me().as_str(), None, T0 + 1, 100);
            lock(T, "nearrr:b1");
        }
        cb_ctx(
            vec![PromiseResult::Successful(br#"{"mode":"Tax","buy_tax_bps":50,"sell_tax_bps":50}"#.to_vec())],
            101,
        );
        let settle: crate::SettleArgs = near_sdk::serde_json::from_value(json!({"client_order_id": "g1",
            "amount": "5000", "counted": "0", "fee": "0", "day_start": "0", "proof": "token"}))
        .unwrap();
        let gate = venues::tax::Gate {
            token: a("jensen.nearrr-fun.near"),
            dex: "dclv2.ref-labs.near".into(),
            kind: venues::tax::TaxKind::Nearrr,
            floor: U128(100),
            min_out: U128(200),
            native_out: U128(1),
        };
        let call = venues::tax::GatedCall {
            receiver: a(T),
            method: "ft_transfer_call".into(),
            args: json!({"receiver_id": "dclv2.ref-labs.near", "amount": "5000",
                "msg": dcl(&[&format!("{T}|jensen.nearrr-fun.near|10000")], "jensen.nearrr-fun.near", 200)})
            .to_string(),
            deposit: U128(1),
            gas: U64(80 * TGAS),
        };
        c.on_tax_gate(settle, gate, call);
        let refused = get_logs().iter().any(|l| l.contains("tax_gate_refused"));
        assert_eq!(refused, locked);
        if locked {
            let s = settled("g1");
            assert!(s.contains("\"used\":\"0\""), "{s}");
        }
        sends_token(T)
    }

    /// F-1 on the gated swap path: the swap's input locked since the execute -> refused, nothing
    /// sent; free -> sent as before.
    #[test]
    fn r2_05_gated_swap_input_locked_since_execute_is_refused() {
        assert!(!gated_swap(true), "a locked input must not be sent");
        assert!(gated_swap(false), "control: a free input is sent");
    }

    /// A gated Chain order fire (taxed output) whose Q is taken between the execute and
    /// on_tax_gate_chain (here the device's own Chain on Q).
    fn gated_chain_fire(q_taken: bool) -> (TradingAccount, U64) {
        let mut c = with_relayer();
        let tout = "jensen.nearrr-fun.near";
        let via = json!({"q": "zec.omft.near", "leg1_dex": "v2.ref-finance.near", "leg2_dex": "dclv2.ref-labs.near",
            "min_mid": "100", "max_mid": "110"});
        let args = json!({"token_in": "wrap.near", "token_out": tout, "amount_in": NEAR.to_string(),
            "min_out": "50", "trigger_meta": "", "expires_at_ns": (T0 + 3_600 * NS_PER_SEC).to_string(),
            "dexes": ["v2.ref-finance.near", "dclv2.ref-labs.near"], "via": via});
        input_ctx(&args, T0 + 1);
        let id = c.place_order(
            wrap(),
            a(tout),
            U128(NEAR),
            U128(50),
            String::new(),
            U64(T0 + 3_600 * NS_PER_SEC),
            vec![a("v2.ref-finance.near"), a("dclv2.ref-labs.near")],
        );
        let mut ch = taxed_chain();
        ch.leg2 = ChainLeg::FtTransferCall {
            token: q(),
            receiver_id: a("dclv2.ref-labs.near"),
            amount: U128(0),
            msg: dcl(&["zec.omft.near|jensen.nearrr-fun.near|10000"], "jensen.nearrr-fun.near", 60),
            gas: U64(40 * TGAS),
        };
        if let ChainLeg::FtTransferCall { gas, .. } = &mut ch.leg1 {
            *gas = U64(40 * TGAS);
        }
        ctx_at(me().as_str(), Some(relayer_pk()), T0 + 2, 100);
        c.execute_order(id, vec![Op::NearDeposit { amount: U128(NEAR) }, Op::Chain(Box::new(ch))]);
        assert!(c.get_q_lock(q()).is_none(), "a gated fire locks Q only in its callback");
        let g = self_call("on_tax_gate_chain");
        if q_taken {
            ctx_at(me().as_str(), None, T0 + 3, 101);
            exec(&mut c, chain_ops(), "dev");
        }
        // the tax view passes (0.5% tax, 60 x 0.995 >= 50)
        cb_ctx(
            vec![PromiseResult::Successful(br#"{"mode":"Tax","buy_tax_bps":50,"sell_tax_bps":50}"#.to_vec())],
            102,
        );
        c.on_tax_gate_chain(arg(&g, "settle"), arg(&g, "gate"), arg(&g, "chain"), arg(&g, "rid"));
        (c, id)
    }

    /// F-2 (the PoC): Q taken meanwhile -> refused like the reserve race: the order reopens, its
    /// spend comes back, Q stays with its holder. Before: E_Q_BUSY panic, order Pending for good.
    #[test]
    fn r2_05_gated_chain_q_taken_meanwhile_reopens_the_order() {
        let (c, id) = gated_chain_fire(true);
        assert!(get_logs().iter().any(|l| l.contains("tax_gate_refused")));
        assert!(get_logs().iter().any(|l| l.contains("order_reopened")));
        assert!(!c.get_order(id).unwrap().pending, "reopened, not Pending");
        let s = settled(&format!("order:{}", id.0));
        assert!(s.contains("\"used\":\"0\""), "{s}");
        assert_eq!(c.get_q_lock(q()).map(|x| x.0), Some("dev".to_string()), "Q stays with its holder");
        assert!(!get_created_receipts().iter().any(|r| r.receiver_id == q()), "the Chain never started");
    }

    /// Control: Q free -> the gated Chain starts (locks Q, reads its balance).
    #[test]
    fn r2_05_control_gated_chain_free_q_starts() {
        let (c, id) = gated_chain_fire(false);
        assert_eq!(c.get_q_lock(q()).map(|x| x.0), Some(format!("order:{}", id.0)));
        assert!(c.get_order(id).unwrap().pending);
        assert!(get_created_receipts().iter().any(|r| r.receiver_id == q()));
        assert!(!get_logs().iter().any(|l| l.contains("tax_gate_refused")));
    }

    // ---- CurveClaim{KelytraDeposit}: the one claim that sends its token (access/accounting
    // reviewer's PoCs `ext_kelytra_deposit_*`, ported) ----

    const KEL: &str = "exchange.kelytradevs.near";

    fn kel_deposit(token: &str, amount: u128) -> Op {
        Op::CurveClaim(venues::CurveClaim {
            venue: a(KEL),
            action: venues::ClaimAction::KelytraDeposit,
            market: None,
            token: Some(a(token)),
            amount: Some(U128(amount)),
        })
    }

    /// A relayer fire of a stored Nearrr buy order, up to the pad buy: T locked, `before` = 0 read.
    fn fire_until_pad_buy() -> (TradingAccount, U64) {
        let mut c = with_relayer();
        c.dex_allowlist.push(Dex { id: a(KEL), kind: DexKind::Kelytra });
        ctx_at(me().as_str(), None, T0 + 1, 100);
        let id = c.place_order(
            wrap(),
            a(T),
            U128(NEAR),
            U128(100),
            String::new(),
            U64(T0 + 3_600 * NS_PER_SEC),
            vec![a("nearrr-fun.near")],
        );
        ctx_at(me().as_str(), Some(relayer_pk()), T0 + 2, 100);
        c.execute_order(
            id,
            vec![Op::CurveBuy(venues::CurveTrade {
                venue: a("nearrr-fun.near"),
                market: Some(T.into()),
                quote: None,
                amount: U128(NEAR),
                min_out: U128(100),
                max_out: None,
                gas: U64(230 * TGAS),
                setup: false,
            })],
        );
        let v = self_call("on_nearrr_tax");
        cb_ctx(vec![PromiseResult::Successful(br#"{"mode":"Standard","buy_tax_bps":0}"#.to_vec())], 101);
        c.on_nearrr_tax(arg(&v, "settle"), arg(&v, "min_out"), arg(&v, "dex"), arg(&v, "label"));
        let v = self_call("on_nearrr_before");
        cb_ctx(vec![ok_u(0)], 102);
        c.on_nearrr_before(arg(&v, "settle"), arg(&v, "token"), arg(&v, "pad_min"), arg(&v, "dex"));
        assert_eq!(lock_of(T).map(|(h, _)| h), Some(format!("nearrr:order:{}", id.0)));
        (c, id)
    }

    /// A device KelytraDeposit of the locked token is E_Q_BUSY, like a plain sell of it.
    #[test]
    fn r2_05_kelytra_deposit_respects_the_lock() {
        let (mut c, _) = fire_until_pad_buy();
        ctx_at(me().as_str(), None, T0 + 3, 103);
        let sell = Op::FtTransferCall {
            token: a(T),
            receiver_id: a("v2.ref-finance.near"),
            amount: U128(5_000),
            msg: classic(1, T, "wrap.near", None, 1),
            gas: U64(150 * TGAS),
        };
        assert_eq!(panics(std::panic::AssertUnwindSafe(|| exec(&mut c, vec![sell], "s1"))), E_Q_BUSY);
        ctx_at(me().as_str(), None, T0 + 4, 104);
        assert_eq!(
            panics(std::panic::AssertUnwindSafe(|| exec(&mut c, vec![kel_deposit(T, 5_000)], "k1"))),
            E_Q_BUSY
        );
        assert!(!sends_token(T));
    }

    /// Consequence before the fix: the pad filled, the deposit took the tokens before the
    /// after-read, and the settle read "refunded" (no fee, the order reopened). Now refused: the
    /// fill settles as a fill.
    #[test]
    fn r2_05_kelytra_deposit_cannot_fake_a_nearrr_refund() {
        let (mut c, id) = fire_until_pad_buy();
        let v = self_call("on_nearrr_settled");
        ctx_at(me().as_str(), None, T0 + 4, 103);
        let deposited = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            exec(&mut c, vec![kel_deposit(T, 5_000)], "k1")
        }))
        .is_ok();
        let after = if deposited { 0 } else { 5_000 };
        cb_ctx(vec![ok_u(after)], 104);
        c.on_nearrr_settled(arg(&v, "settle"), arg(&v, "before"), arg(&v, "token"));
        let fee = get_created_receipts().iter().any(|r| r.receiver_id == a("fees.near"));
        assert!(fee && c.get_order(id).is_none(), "a filled buy must settle as filled");
    }

    /// Control: a free token's KelytraDeposit is sent as before.
    #[test]
    fn r2_05_control_kelytra_deposit_free_token_is_sent() {
        let mut c = account();
        c.dex_allowlist.push(Dex { id: a(KEL), kind: DexKind::Kelytra });
        ctx_at(me().as_str(), None, T0 + 1, 100);
        exec(&mut c, vec![kel_deposit(T, 5_000)], "k1");
        assert!(sends_token(T));
    }
}
/// AUDIT-S1: a curve leg 1 whose plan attaches NEAR besides the trade input (an Aidols-family
/// `storage_deposit`, 0.0125 N; Vista launch's 0.00125 N buy extra) counts it as spend when it is
/// a single-hop CurveBuy (`Plan.spend`, 448fdc9a mirrors it in the signer), but a Chain counts
/// only `l1.amount` (`ChainPlan.counted`). The NEAR still leaves (it is in `native_out`).
/// Safe behaviour: the Chain counts at least what the same trade counts alone.
#[test]
fn audit_s1_chain_counts_the_curve_legs_storage_spend() {
    let (m, w, rf) = (me(), wrap(), a("fees.near"));
    let mut al = allow();
    al.push(Dex { id: a("aidols.near"), kind: DexKind::AidolsCurve(venues::AidolsPad::Near) });
    let buy = venues::CurveTrade {
        venue: a("aidols.near"),
        market: Some("x.aidols.near".into()),
        quote: None,
        amount: U128(NEAR),
        min_out: U128(100),
        max_out: None,
        gas: U64(60 * TGAS),
        setup: false,
    };
    let c = Chain {
        leg1: ChainLeg::CurveBuy(buy.clone()),
        leg2: ChainLeg::FtTransferCall {
            token: a("x.aidols.near"),
            receiver_id: a("v2.ref-finance.near"),
            amount: U128(0),
            msg: classic(9, "x.aidols.near", "jensen.near", None, 50),
            gas: U64(80 * TGAS),
        },
        q: a("x.aidols.near"),
        min_mid: U128(100),
        max_mid: U128(200),
        min_final: U128(50),
    };
    let e = env_at(&m, &w, &al, &rf, T0);
    let p = check_chain(&e, &c, false, None).unwrap();
    let alone = venues::plan(&al, true, &buy, &ctx(&e)).unwrap();
    // the input is wNEAR (counted); the storage deposit is native NEAR that leaves
    assert!(p.native_out >= venues::VENUE_STORAGE, "the storage NEAR leaves");
    assert_eq!(
        p.counted + p.extra_spend,
        alone.spend,
        "the Chain counts what the same buy counts alone (input + venue storage)"
    );
    // only the input is returned pro rata on a refund (as a single-hop curve op's `counted`)
    assert_eq!((p.counted, p.extra_spend), (NEAR, venues::VENUE_STORAGE));
    // and the execute charges it to the day
    ctx_at("tt.near", None, T0, 100);
    near_sdk::mock::with_mocked_blockchain(|b| {
        b.take_storage();
    });
    ctx_at("tt.near", None, T0, 100);
    let mut c2 = TradingAccount::init(
        a("owner.near"),
        FeeConfig { fee_bps: 100, fee_recipient: a("fees.near") },
        Caps { max_trade_yocto: U128(3 * NEAR), daily_cap_yocto: U128(9 * NEAR) },
        al.clone(),
        wrap(),
        None,
        None,
        None,
    );
    ctx_at(me().as_str(), None, T0 + 1, 100);
    exec(&mut c2, vec![Op::Chain(Box::new(c))], "s1");
    let want = NEAR + venues::VENUE_STORAGE + NEAR / 100;
    assert!(
        get_logs()
            .iter()
            .any(|l| l.contains("\"event\":\"execute\"") && l.contains(&format!("\"spend\":\"{want}\""))),
        "execute spend = input + storage + max fee: {:?}",
        get_logs()
    );
}

/// AUDIT-S1: a continuation's swap leg that attaches native NEAR (an Aidols-family
/// `storage_deposit`, 0.0125 N) is reserve-checked before the fire, not only 1 yocto.
#[test]
fn audit_s1_continuation_reserve_checks_the_legs_native_out() {
    let mut c = aidols_account();
    let rid = "ap3";
    let r = Route {
        q: patata(),
        cont: Some(ContTerms {
            token_out: a("x.patata-monster.near"),
            dexes: vec![a("patata-monster.near")],
            min_final: U128(50),
        }),
        ..route(RouteKind::IntentsBuy)
    };
    save_route(rid, &r).unwrap();
    escrow_add(NEAR / 100);
    let cid = new_cont(rid);
    // liquid = RESERVE + escrow + half the storage deposit
    let liquid = crate::policy::RESERVE + NEAR / 100 + venues::VENUE_STORAGE / 2;
    let locked = u128::from(STORAGE_BYTES) * env::storage_byte_cost().as_yoctonear();
    testing_env!(VMContextBuilder::new()
        .current_account_id(me())
        .predecessor_account_id(me())
        .signer_account_id(me())
        .account_balance(NearToken::from_yoctonear(locked + liquid))
        .block_timestamp(T0 + 1)
        .block_height(100)
        .storage_usage(STORAGE_BYTES)
        .prepaid_gas(Gas::from_tgas(300))
        .build());
    let ops = vec![Op::IntentsPull(pull(patata(), 1000)), Op::CurveBuy(aidols_trade(1000))];
    assert_eq!(panics(std::panic::AssertUnwindSafe(|| c.execute_order(U64(cid), ops.clone()))), "E_RESERVE");
    assert!(!c.get_route(rid.into()).unwrap().pending, "nothing fired");
    // control: a plain (DCL) continuation swap still fires on the same balance
    let mut c = account();
    save_route("pl2", &route(RouteKind::IntentsBuy)).unwrap();
    escrow_add(NEAR / 100);
    let cid = new_cont("pl2");
    testing_env!(VMContextBuilder::new()
        .current_account_id(me())
        .predecessor_account_id(me())
        .signer_account_id(me())
        .account_balance(NearToken::from_yoctonear(locked + liquid))
        .block_timestamp(T0 + 1)
        .block_height(100)
        .storage_usage(STORAGE_BYTES)
        .prepaid_gas(Gas::from_tgas(300))
        .build());
    c.execute_order(
        U64(cid),
        vec![
            Op::IntentsPull(pull(q(), 1000)),
            Op::FtTransferCall {
                token: q(),
                receiver_id: a("dclv2.ref-labs.near"),
                amount: U128(1000),
                msg: dcl(&["zec.omft.near|jensen.near|10000"], "jensen.near", 50),
                gas: U64(80 * TGAS),
            },
        ],
    );
    assert!(c.get_route("pl2".into()).unwrap().pending);
}
