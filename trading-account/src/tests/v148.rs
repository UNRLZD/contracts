//! v1.4.8: no default weekly relayer allowance (24/7 orders unlimited by default); the owner can
//! opt into one (then the v1.4.7 accounting + the C1-L3 floor, with RA7-1 fixed).
use super::*;
use near_sdk::serde_json::Value;

const MEME: u128 = 1_000_000_000_000_000_000_000_000; // 1 token (24 decimals)

fn week(c: &TradingAccount) -> RelayerWeekView {
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 3);
    c.get_relayer_week()
}

/// The on_swap_settled args scheduled by the last fire.
fn settle_args() -> Value {
    get_created_receipts()
        .iter()
        .flat_map(|r| r.actions.iter())
        .find_map(|x| match x {
            MockAction::FunctionCallWeight { method_name, args, .. } if method_name == b"on_swap_settled" => {
                Some(serde_json::from_slice::<Value>(args).unwrap())
            }
            _ => None,
        })
        .expect("on_swap_settled scheduled")
}

/// Replays the scheduled on_swap_settled with `result` at `now`.
fn settle(c: &mut TradingAccount, result: PromiseResult, now: u64) {
    let args = settle_args();
    let s = |k: &str| args[k].as_str().map(String::from);
    let u = |k: &str| s(k).map(|v| U128(v.parse().unwrap()));
    let u64_ = |k: &str| s(k).map(|v| U64(v.parse().unwrap()));
    testing_env!(
        VMContextBuilder::new()
            .current_account_id(me())
            .predecessor_account_id(me())
            .storage_usage(STORAGE_BYTES)
            .account_balance(NearToken::from_yoctonear(10 * NEAR))
            .block_timestamp(now)
            .build(),
        near_sdk::test_vm_config(),
        near_sdk::RuntimeFeesConfig::test(),
        Default::default(),
        vec![result],
    );
    c.on_swap_settled(
        s("client_order_id").unwrap(),
        u("amount").unwrap(),
        u("counted").unwrap(),
        u("fee").unwrap(),
        u64_("day_start").unwrap(),
        u64_("order_id"),
        u64_("relayer_week"),
        u("relayer_counted"),
        s("proof"),
    );
}

/// The product default: automation on, no caps, no weekly allowance.
fn unlimited() -> TradingAccount {
    let mut c = with_automation();
    c.caps = caps(UNLIMITED, UNLIMITED);
    c
}

fn fire_buy(c: &mut TradingAccount, id: u64, now: u64) {
    ctx_pk(me().as_str(), Some(auto_pk()), 0, now);
    c.execute_order(U64(id), order_buy_ops(NEAR, 5));
}

/// No allowance set: the view says null, a fire is not week-accounted and its callback carries
/// no weekly refund.
#[test]
fn v148_default_is_unlimited_no_accounting() {
    let mut c = unlimited();
    let v = week(&c);
    assert_eq!(v.allowance_yocto, None);
    assert_eq!(serde_json::to_value(&v).unwrap()["allowance_yocto"], Value::Null);
    // a sell whose min_out is far above the old 10 NEAR default fires
    let id = place_sell(&mut c, MEME, 50 * NEAR);
    relayer_fire(&mut c, id, MEME, 50 * NEAR, T0 + 2);
    assert!(c.get_order(U64(id)).unwrap().pending);
    let args = settle_args();
    assert!(args.get("relayer_week").is_none() && args.get("relayer_counted").is_none(), "{args}");
    assert_eq!(week(&c).spent_yocto.0, 0);
    // a buy too
    let id = place_buy(&mut c, NEAR, 5);
    fire_buy(&mut c, id, T0 + 4);
    assert!(settle_args().get("relayer_counted").is_none());
    assert_eq!(week(&c).spent_yocto.0, 0);
}

/// No fire-count limit: > 20 sells in one ISO week, and one failing buy re-fired > 20 times.
#[test]
fn v148_unlimited_fires_more_than_20_per_week() {
    let mut c = unlimited();
    for i in 0..30u64 {
        let id = place_sell(&mut c, MEME, 1);
        relayer_fire(&mut c, id, MEME, 1, T0 + 10 + i);
    }
    let id = place_buy(&mut c, NEAR, 5);
    for i in 0..30u64 {
        fire_buy(&mut c, id, T0 + 100 + 2 * i);
        settle(&mut c, ok_json(0), T0 + 101 + 2 * i); // wrap resolved 0: reopened
        assert!(!c.get_order(U64(id)).unwrap().pending);
    }
    assert_eq!(week(&c).spent_yocto.0, 0);
}

/// Unlimited removes only the weekly accounting: every per-fire check stays.
#[test]
fn v148_unlimited_keeps_per_fire_safety() {
    let err = |c: &mut TradingAccount, id: u64, ops: Vec<Op>| {
        ctx_pk(me().as_str(), Some(auto_pk()), 0, T0 + 2);
        panics(std::panic::AssertUnwindSafe(|| c.execute_order(U64(id), ops)))
    };
    // exactly as stored: amount, min_out, output token
    let mut c = unlimited();
    let id = place_buy(&mut c, NEAR, 5);
    assert_eq!(err(&mut c, id, order_buy_ops(NEAR / 2, 5)), "E_ORDER_MISMATCH");
    // (a refused fire leaves the mock order Pending, no revert: a fresh order per check)
    let id = place_buy(&mut c, NEAR, 5);
    assert_eq!(err(&mut c, id, order_buy_ops(NEAR, 4)), "E_ORDER_MIN_OUT");
    let id = place_sell(&mut c, MEME, 3 * NEAR);
    assert_eq!(err(&mut c, id, order_sell_ops(MEME, 3 * NEAR - 1)), "E_ORDER_MIN_OUT");
    let id = place_sell(&mut c, MEME, 3 * NEAR);
    // output only to self
    let bad = vec![Op::FtTransferCall {
        token: a("meme.near"),
        receiver_id: a("v2.ref-finance.near"),
        amount: U128(MEME),
        msg: format!(
            r#"{{"force":0,"actions":[{{"pool_id":1,"token_in":"meme.near","token_out":"wrap.near","min_amount_out":"{}"}}],"swap_out_recipient":"evil.near"}}"#,
            3 * NEAR
        ),
        gas: U64(150 * TGAS),
    }];
    assert_eq!(err(&mut c, id, bad), "E_RECIPIENT");
    // buys only with wrap as input: token -> token stays device-only
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
    let t2t = c
        .place_order(
            a("meme.near"),
            a("usdc.near"),
            U128(1_000),
            U128(5),
            "{}".into(),
            U64(T0 + 3_600 * NS_PER_SEC),
            vec![a("v2.ref-finance.near")],
        )
        .0;
    let ops = vec![Op::FtTransferCall {
        token: a("meme.near"),
        receiver_id: a("v2.ref-finance.near"),
        amount: U128(1_000),
        msg: rhea_msg("meme.near", "usdc.near", 5),
        gas: U64(150 * TGAS),
    }];
    assert_eq!(err(&mut c, t2t, ops), "E_RELAYER_SELL_ONLY");
    // once while Pending; not after expiry
    let mut c = unlimited();
    let id = place_buy(&mut c, NEAR, 5);
    fire_buy(&mut c, id, T0 + 2);
    assert_eq!(err(&mut c, id, order_buy_ops(NEAR, 5)), "E_ORDER_PENDING");
    let mut c = unlimited();
    let id = place_sell(&mut c, MEME, 1);
    ctx_pk(me().as_str(), Some(auto_pk()), 0, T0 + 31 * DAY);
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| c.execute_order(U64(id), order_sell_ops(MEME, 1)))),
        "E_EXPIRED"
    );
    // the reserve: a buy the liquid balance can't cover is refused (ctx_pk: 10 NEAR balance)
    let mut c = unlimited();
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
    let id = c
        .place_order(
            a("wrap.near"),
            a("meme.near"),
            U128(10 * NEAR),
            U128(5),
            "{}".into(),
            U64(T0 + DAY),
            vec![a("v2.ref-finance.near")],
        )
        .0;
    assert_eq!(err(&mut c, id, order_buy_ops(10 * NEAR, 5)), "E_RESERVE");
}

/// Opt-in: the owner sets an allowance; the v1.4.7 accounting and the floor apply; UNLIMITED
/// removes it again (view null, event null).
#[test]
fn v148_opt_in_enforced_then_back_to_unlimited() {
    let mut c = unlimited();
    ctx("owner.near", 1, 10 * NEAR, T0 + 1);
    c.owner_set_relayer_allowance(U128(10 * NEAR));
    assert!(get_logs()[0]
        .contains("\"old_weekly_yocto\":null,\"new_weekly_yocto\":\"10000000000000000000000000\""));
    assert_eq!(week(&c).allowance_yocto, Some(U128(10 * NEAR)));
    // min_out > allowance: refused, stays open
    let big = place_sell(&mut c, MEME, 50 * NEAR);
    ctx_pk(me().as_str(), Some(auto_pk()), 0, T0 + 2);
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| c.execute_order(U64(big), order_sell_ops(MEME, 50 * NEAR)))),
        "E_RELAYER_WEEKLY"
    );
    // the floor: 20 fires of tiny orders, the 21st refused
    let mut fired = 0;
    for i in 0..25u64 {
        let id = place_sell(&mut c, MEME, 1);
        ctx_pk(me().as_str(), Some(auto_pk()), 0, T0 + 10 + i);
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            c.execute_order(U64(id), order_sell_ops(MEME, 1))
        }))
        .is_ok()
        {
            fired += 1;
        }
    }
    assert_eq!(fired, MAX_RELAYER_FIRES_PER_WEEK as usize);
    assert_eq!(week(&c).spent_yocto.0, 10 * NEAR);
    // back to unlimited
    ctx("owner.near", 1, 10 * NEAR, T0 + 50);
    c.owner_set_relayer_allowance(U128(UNLIMITED));
    assert!(get_logs()[0]
        .contains("\"old_weekly_yocto\":\"10000000000000000000000000\",\"new_weekly_yocto\":null"));
    assert_eq!(week(&c).allowance_yocto, None);
    assert!(!near_sdk::env::storage_has_key(b"ra"));
    relayer_fire(&mut c, big, MEME, 50 * NEAR, T0 + 51);
    assert!(c.get_order(U64(big)).unwrap().pending);
}

/// RA7-1 fixed (opt-in only): a failing buy re-fired keeps the floor charged, so at most 20
/// fires a week, failures included (v1.4.7: 60 fires and more).
#[test]
fn v148_ra7_1_failed_fires_keep_the_floor() {
    let mut c = unlimited();
    ctx("owner.near", 1, 10 * NEAR, T0 + 1);
    c.owner_set_relayer_allowance(U128(10 * NEAR));
    let floor = 10 * NEAR / MAX_RELAYER_FIRES_PER_WEEK;
    let id = place_buy(&mut c, NEAR, 5);
    let mut fired = 0u128;
    for i in 0..30u64 {
        ctx_pk(me().as_str(), Some(auto_pk()), 0, T0 + 10 + 2 * i);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            c.execute_order(U64(id), order_buy_ops(NEAR, 5))
        }));
        match r {
            Ok(()) => {
                fired += 1;
                settle(&mut c, ok_json(0), T0 + 11 + 2 * i);
                assert_eq!(week(&c).spent_yocto.0, fired * floor);
            }
            Err(_) => break,
        }
    }
    // the last fire needs amount_in (1 NEAR) of headroom, so fewer than 20 fit
    assert!((18..MAX_RELAYER_FIRES_PER_WEEK).contains(&fired), "{fired}");
    // a failed sell also keeps the floor
    let s = place_sell(&mut c, MEME, 1);
    let before = week(&c).spent_yocto.0;
    if before + floor <= 10 * NEAR {
        relayer_fire(&mut c, s, MEME, 1, T0 + 200);
        settle(&mut c, PromiseResult::Failed, T0 + 201);
        assert_eq!(week(&c).spent_yocto.0, before + floor);
    }
}

/// init / factory: weekly_yocto None or UNLIMITED = unlimited; Some = opt-in. Upgrade: a stored
/// allowance is kept; none stored (the v1.4.7 implicit 10 NEAR) = unlimited; a stored u128::MAX
/// (v1.4.7 allowed it: 20 fires/week, RA7-2) = unlimited.
#[test]
fn v148_init_and_upgrade_semantics() {
    let init = |w: Option<U128>| {
        ctx("tt.near", 0, NEAR, T0);
        near_sdk::mock::with_mocked_blockchain(|b| {
            b.take_storage();
        });
        ctx("tt.near", 0, NEAR, T0);
        let c = TradingAccount::init(
            a("owner.near"),
            FeeConfig { fee_bps: 100, fee_recipient: a("fees.near") },
            caps(UNLIMITED, UNLIMITED),
            vec![Dex { id: a("v2.ref-finance.near"), kind: DexKind::RheaClassic }],
            a("wrap.near"),
            Some(AutomationInit { public_key: auto_pk(), allowance: U128(NEAR), weekly_yocto: w }),
        );
        week(&c).allowance_yocto
    };
    assert_eq!(init(None), None);
    assert_eq!(init(Some(U128(UNLIMITED))), None);
    assert_eq!(init(Some(U128(4 * NEAR))), Some(U128(4 * NEAR)));
    // raw v1.4.7 state (same key, same encoding)
    let c = new_account();
    near_sdk::env::storage_write(b"ra", &(4 * NEAR).to_le_bytes());
    assert_eq!(week(&c).allowance_yocto, Some(U128(4 * NEAR)));
    near_sdk::env::storage_write(b"ra", &u128::MAX.to_le_bytes());
    assert_eq!(week(&c).allowance_yocto, None);
    near_sdk::env::storage_remove(b"ra");
    assert_eq!(week(&c).allowance_yocto, None);
}

/// Unlimited never overflows: an opt-in of u128::MAX - 1 (finite, huge) keeps checked math.
#[test]
fn v148_huge_finite_allowance_no_overflow() {
    let mut c = unlimited();
    ctx("owner.near", 1, 10 * NEAR, T0 + 1);
    c.owner_set_relayer_allowance(U128(u128::MAX - 1));
    let id = place_sell(&mut c, MEME, 50 * NEAR);
    relayer_fire(&mut c, id, MEME, 50 * NEAR, T0 + 2);
    assert_eq!(week(&c).spent_yocto.0, (u128::MAX - 1) / MAX_RELAYER_FIRES_PER_WEEK);
    let id = place_buy(&mut c, NEAR, 5);
    fire_buy(&mut c, id, T0 + 4);
    settle(&mut c, PromiseResult::Failed, T0 + 5);
    assert_eq!(week(&c).spent_yocto.0, 2 * ((u128::MAX - 1) / MAX_RELAYER_FIRES_PER_WEEK));
}
