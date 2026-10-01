//! v1.6 24/7 orders on curve venues (place_order / execute_order hooks): TokenCurve tokens and
//! exact curve venues are order DEXes; meme.cooking (presale, symbolic min_out) never is, on
//! either the typed or the raw FtTransferCall path; housekeeping claims are never order ops.
use super::*;
use crate::*;
use near_sdk::test_utils::{get_created_receipts, VMContextBuilder};
use near_sdk::{testing_env, Gas, NearToken};

const NEAR: u128 = 1_000_000_000_000_000_000_000_000;
const T0: u64 = 1_800_000_000_000_000_000;

fn a(s: &str) -> AccountId {
    s.parse().unwrap()
}
fn me() -> AccountId {
    a("abcd.tt.near")
}
fn ctx(pred: &str) {
    testing_env!(VMContextBuilder::new()
        .current_account_id(me())
        .predecessor_account_id(a(pred))
        .signer_account_id(a(pred))
        .account_balance(NearToken::from_yoctonear(20 * NEAR))
        .block_timestamp(T0)
        .storage_usage(5_000)
        .prepaid_gas(Gas::from_tgas(300))
        .build());
}

fn account() -> TradingAccount {
    ctx("tt.near");
    near_sdk::mock::with_mocked_blockchain(|b| {
        b.take_storage();
    });
    ctx("tt.near");
    let c = TradingAccount::init(
        a("owner.near"),
        FeeConfig { fee_bps: 100, fee_recipient: a("fees.near") },
        Caps { max_trade_yocto: U128(5 * NEAR), daily_cap_yocto: U128(10 * NEAR) },
        vec![
            Dex { id: a("umbrafun.near"), kind: DexKind::TokenCurve(TokenPad::Umbra) },
            Dex { id: a("nearrr-fun.near"), kind: DexKind::FactoryCurve(FactoryPad::Nearrr) },
            Dex { id: a("meme-cooking.near"), kind: DexKind::FactoryCurve(FactoryPad::MemeCooking) },
        ],
        a("wrap.near"),
        None,
        None,
        None,
    );
    ctx(me().as_str());
    c
}

fn place(c: &mut TradingAccount, tin: &str, tout: &str, dexes: &[&str]) -> u64 {
    c.place_order(
        a(tin),
        a(tout),
        U128(NEAR),
        U128(5),
        String::new(),
        U64(T0 + 86_400 * 1_000_000_000),
        dexes.iter().map(|d| a(d)).collect(),
    )
    .0
}

fn umbra_buy(amount: u128, min_out: u128) -> Op {
    Op::CurveBuy(CurveTrade {
        venue: a("t.umbrafun.near"),
        market: None,
        quote: None,
        amount: U128(amount),
        min_out: U128(min_out),
        max_out: None,
        gas: U64(100 * super::TGAS),
        setup: false,
    })
}

#[test]
fn place_order_accepts_curve_venues() {
    let mut c = account();
    place(&mut c, "wrap.near", "t.umbrafun.near", &["t.umbrafun.near"]);
    place(&mut c, "wrap.near", "x.nearrr-fun.near", &["nearrr-fun.near"]);
}

#[test]
#[should_panic(expected = "E_BAD_DEX")]
fn place_order_refuses_token_curve_factory_itself() {
    let mut c = account();
    place(&mut c, "wrap.near", "t.umbrafun.near", &["umbrafun.near"]);
}

#[test]
#[should_panic(expected = "E_BAD_DEX")]
fn place_order_refuses_two_labels_under_factory() {
    let mut c = account();
    place(&mut c, "wrap.near", "a.t.umbrafun.near", &["a.t.umbrafun.near"]);
}

#[test]
#[should_panic(expected = "E_BAD_DEX")]
fn place_order_refuses_meme_cooking() {
    let mut c = account();
    place(&mut c, "wrap.near", "1.meme-cooking.near", &["meme-cooking.near"]);
}

#[test]
fn token_curve_order_fires_exactly_as_stored() {
    let mut c = account();
    let id = place(&mut c, "wrap.near", "t.umbrafun.near", &["t.umbrafun.near"]);
    c.execute_order(U64(id), vec![umbra_buy(NEAR, 5)]);
    let r = get_created_receipts();
    let buy = r.iter().find(|x| x.receiver_id == a("t.umbrafun.near")).expect("a receipt to the token");
    match &buy.actions[..] {
        [near_sdk::mock::MockAction::FunctionCallWeight { method_name, args, attached_deposit, .. }] => {
            assert_eq!(method_name, b"buy");
            assert_eq!(args, br#"{"min_out":"5"}"#);
            assert_eq!(attached_deposit.as_yoctonear(), NEAR);
        }
        x => panic!("unexpected actions {x:?}"),
    }
    assert!(c.get_order(U64(id)).unwrap().pending);
}

#[test]
#[should_panic(expected = "E_ORDER_MIN_OUT")]
fn token_curve_order_min_out_below_stored() {
    let mut c = account();
    let id = place(&mut c, "wrap.near", "t.umbrafun.near", &["t.umbrafun.near"]);
    c.execute_order(U64(id), vec![umbra_buy(NEAR, 4)]);
}

#[test]
#[should_panic(expected = "E_ORDER_MISMATCH")]
fn token_curve_order_other_token() {
    let mut c = account();
    let id = place(&mut c, "wrap.near", "t.umbrafun.near", &["t.umbrafun.near"]);
    let mut op = umbra_buy(NEAR, 5);
    if let Op::CurveBuy(t) = &mut op {
        t.venue = a("u.umbrafun.near");
    }
    c.execute_order(U64(id), vec![op]);
}

fn stored_meme_order(c: &mut TradingAccount) -> u64 {
    // an order naming meme-cooking.near can't be placed (above); written directly to prove the
    // fire-time refusal holds on its own (defence in depth)
    let _ = c;
    crate::save_order(
        99,
        &Order {
            token_in: a("wrap.near"),
            token_out: a("1.meme-cooking.near"),
            amount_in: U128(NEAR),
            min_out: U128(1),
            trigger_meta: String::new(),
            expires_at_ns: U64(T0 + 1_000_000_000_000),
            dexes: vec![a("meme-cooking.near")],
            pending: false,
        },
    );
    99
}

#[test]
#[should_panic(expected = "E_ORDER_OPS")]
fn meme_deposit_never_fires_raw() {
    let mut c = account();
    let id = stored_meme_order(&mut c);
    c.execute_order(
        U64(id),
        vec![Op::FtTransferCall {
            token: a("wrap.near"),
            receiver_id: a("meme-cooking.near"),
            amount: U128(NEAR),
            msg: r#"{"Deposit":{"meme_id":1}}"#.to_string(),
            gas: U64(100 * super::TGAS),
        }],
    );
}

#[test]
#[should_panic(expected = "E_ORDER_OPS")]
fn meme_deposit_never_fires_typed() {
    let mut c = account();
    let id = stored_meme_order(&mut c);
    c.execute_order(
        U64(id),
        vec![Op::CurveBuy(CurveTrade {
            venue: a("meme-cooking.near"),
            market: Some("1".into()),
            quote: None,
            amount: U128(NEAR),
            min_out: U128(1),
            max_out: None,
            gas: U64(100 * super::TGAS),
            setup: false,
        })],
    );
}

#[test]
#[should_panic(expected = "E_ORDER_OPS")]
fn claims_are_never_order_ops() {
    let mut c = account();
    let id = stored_meme_order(&mut c);
    c.execute_order(
        U64(id),
        vec![Op::CurveClaim(CurveClaim {
            venue: a("meme-cooking.near"),
            action: ClaimAction::MemeCookingWithdraw,
            market: Some("1".into()),
            token: None,
            amount: Some(U128(NEAR)),
        })],
    );
}

#[test]
fn order_venue_rules() {
    let allow = vec![
        Dex { id: a("umbrafun.near"), kind: DexKind::TokenCurve(TokenPad::Umbra) },
        Dex { id: a("meme-cooking.near"), kind: DexKind::FactoryCurve(FactoryPad::MemeCooking) },
        Dex { id: a("v2.ref-finance.near"), kind: DexKind::RheaClassic },
    ];
    assert_eq!(order_venue(&allow, &a("t.umbrafun.near")), Some(true));
    assert_eq!(order_venue(&allow, &a("umbrafun.near")), None);
    assert_eq!(order_venue(&allow, &a("meme-cooking.near")), Some(false));
    assert_eq!(order_venue(&allow, &a("v2.ref-finance.near")), None);
}

// ======================= AUDIT-T0: a token0 order's fill size is the user's =======================

/// token0 buys are exact-out: `max_out` (tokens minted, the unused NEAR refunded inside a
/// successful receipt) sets the fill size. Before the fix the FIRING key chose it, so a relayer
/// fire of a 1 N limit buy with `max_out = min_out` filled a sliver and consumed the order. Now
/// the order stores it (`place_order`'s JSON `max_out`) and a fire must carry exactly that.
fn t0_account() -> TradingAccount {
    ctx("tt.near");
    near_sdk::mock::with_mocked_blockchain(|b| {
        b.take_storage();
    });
    ctx("tt.near");
    let c = TradingAccount::init(
        a("owner.near"),
        FeeConfig { fee_bps: 100, fee_recipient: a("fees.near") },
        Caps { max_trade_yocto: U128(5 * NEAR), daily_cap_yocto: U128(10 * NEAR) },
        vec![Dex { id: a("tkn0.near"), kind: DexKind::TokenCurve(TokenPad::Token0) }],
        a("wrap.near"),
        None,
        None,
        None,
    );
    ctx(me().as_str());
    c
}

/// place_order with the raw JSON args (`max_out` is read from them, as `via`).
fn t0_place(c: &mut TradingAccount, max_out: Option<u128>) -> u64 {
    let mut args = near_sdk::serde_json::json!({"token_in": "wrap.near", "token_out": "t.tkn0.near",
        "amount_in": NEAR.to_string(), "min_out": "5", "trigger_meta": "",
        "expires_at_ns": (T0 + 86_400 * 1_000_000_000).to_string(), "dexes": ["t.tkn0.near"]});
    if let Some(m) = max_out {
        args["max_out"] = near_sdk::serde_json::json!(m.to_string());
    }
    let mut vc = VMContextBuilder::new()
        .current_account_id(me())
        .predecessor_account_id(me())
        .signer_account_id(me())
        .account_balance(NearToken::from_yoctonear(20 * NEAR))
        .block_timestamp(T0)
        .storage_usage(5_000)
        .prepaid_gas(Gas::from_tgas(300))
        .build();
    vc.input = args.to_string().into_bytes().into();
    testing_env!(vc);
    let id = c
        .place_order(
            a("wrap.near"),
            a("t.tkn0.near"),
            U128(NEAR),
            U128(5),
            String::new(),
            U64(T0 + 86_400 * 1_000_000_000),
            vec![a("t.tkn0.near")],
        )
        .0;
    ctx(me().as_str());
    id
}

fn t0_buy(max_out: Option<u128>) -> Op {
    Op::CurveBuy(CurveTrade {
        venue: a("t.tkn0.near"),
        market: None,
        quote: None,
        amount: U128(NEAR),
        min_out: U128(5),
        max_out: max_out.map(U128),
        gas: U64(100 * super::TGAS),
        setup: false,
    })
}

#[test]
#[should_panic(expected = "E_ORDER_MISMATCH")]
fn audit_t0_fire_cannot_choose_the_fill_size_without_a_stored_one() {
    let mut c = t0_account();
    let id = t0_place(&mut c, None);
    // the firing key picks max_out = min_out: a 5-token fill of a 1 N order
    c.execute_order(U64(id), vec![t0_buy(Some(5))]);
}

#[test]
#[should_panic(expected = "E_ORDER_MISMATCH")]
fn audit_t0_fire_with_another_max_out_is_refused() {
    let mut c = t0_account();
    let id = t0_place(&mut c, Some(1_000));
    c.execute_order(U64(id), vec![t0_buy(Some(5))]);
}

#[test]
fn audit_t0_fire_with_the_stored_max_out() {
    let mut c = t0_account();
    let id = t0_place(&mut c, Some(1_000));
    assert_eq!(c.get_order_max_out(U64(id)), Some(U128(1_000)));
    c.execute_order(U64(id), vec![t0_buy(Some(1_000))]);
    let r = get_created_receipts();
    let buy = r.iter().find(|x| x.receiver_id == a("t.tkn0.near")).expect("the buy");
    match &buy.actions[..] {
        [near_sdk::mock::MockAction::FunctionCallWeight { args, .. }] => {
            let v: near_sdk::serde_json::Value = near_sdk::serde_json::from_slice(args).unwrap();
            assert_eq!(v["max_token_amount"], "1000");
        }
        x => panic!("unexpected actions {x:?}"),
    }
    assert!(c.get_order(U64(id)).unwrap().pending);
}

#[test]
#[should_panic(expected = "E_BAD_ORDER")]
fn audit_t0_stored_max_out_below_min_out_is_refused() {
    let mut c = t0_account();
    t0_place(&mut c, Some(4));
}

/// The stored value goes with the order; a plain (non-token0) curve order stores none and fires
/// as before (`token_curve_order_fires_exactly_as_stored`).
#[test]
fn audit_t0_stored_max_out_is_removed_with_the_order() {
    let mut c = t0_account();
    let id = t0_place(&mut c, Some(1_000));
    c.cancel_order(U64(id));
    assert_eq!(c.get_order_max_out(U64(id)), None);
}

// ======================= Independent review INDEP-3 =======================

/// place_order at `now` with raw JSON args, expiring at `exp`.
fn indep_place_at(c: &mut TradingAccount, now: u64, exp: u64, max_out: Option<u128>) -> u64 {
    let mut args = near_sdk::serde_json::json!({"token_in": "wrap.near", "token_out": "t.tkn0.near",
        "amount_in": NEAR.to_string(), "min_out": "5", "trigger_meta": "",
        "expires_at_ns": exp.to_string(), "dexes": ["t.tkn0.near"]});
    if let Some(m) = max_out {
        args["max_out"] = near_sdk::serde_json::json!(m.to_string());
    }
    let mut vc = VMContextBuilder::new()
        .current_account_id(me())
        .predecessor_account_id(me())
        .signer_account_id(me())
        .account_balance(NearToken::from_yoctonear(20 * NEAR))
        .block_timestamp(now)
        .storage_usage(5_000)
        .prepaid_gas(Gas::from_tgas(300))
        .build();
    vc.input = args.to_string().into_bytes().into();
    testing_env!(vc);
    c.place_order(
        a("wrap.near"),
        a("t.tkn0.near"),
        U128(NEAR),
        U128(5),
        String::new(),
        U64(exp),
        vec![a("t.tkn0.near")],
    )
    .0
}

/// INDEP-3 (regression): place_order's prune loop dropped an expired order's record and via, not its
/// stored max_out (`om` + id): the key leaks and the view still reports it for a gone order.
#[test]
fn indep3_pruned_order_takes_its_max_out_along() {
    let mut c = t0_account();
    let h = 3_600 * 1_000_000_000u64;
    let id = indep_place_at(&mut c, T0, T0 + h, Some(1_000));
    // a later place_order prunes the expired one
    indep_place_at(&mut c, T0 + 2 * h, T0 + 3 * h, None);
    assert!(c.get_order(U64(id)).is_none(), "pruned");
    assert_eq!(c.get_order_max_out(U64(id)), None, "the pruned order's max_out must go with it");
}
