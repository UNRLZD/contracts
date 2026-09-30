//! v1.4.7 product changes: relayer limit BUYS (weekly-bounded) and unlimited caps. These use only
//! pre-v1.4.7 entry points, so they also run (red) against the v1.4.6 source.
use super::*;
use near_sdk::serde_json::Value;

const STORAGE_OP: u128 = 1_250_000_000_000_000_000_000; // order_buy_ops' StorageDeposit
const GAS300: u128 = 300 * TGAS as u128 * GAS_PRICE_BOUND; // ctx_pk prepays 300 TGas

fn relayer_buy(c: &mut TradingAccount, id: u64, amount: u128, min_out: u128) {
    ctx_pk(me().as_str(), Some(auto_pk()), 0, T0 + 2);
    c.execute_order(U64(id), order_buy_ops(amount, min_out));
}

fn week(c: &TradingAccount) -> u128 {
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 3);
    c.get_relayer_week().spent_yocto.0
}

/// Replays the scheduled on_swap_settled with its real arguments.
fn settle_scheduled(c: &mut TradingAccount, result: PromiseResult) {
    let args = get_created_receipts()
        .iter()
        .flat_map(|r| r.actions.iter())
        .find_map(|x| match x {
            MockAction::FunctionCallWeight { method_name, args, .. } if method_name == b"on_swap_settled" => {
                Some(serde_json::from_slice::<Value>(args).unwrap())
            }
            _ => None,
        })
        .expect("on_swap_settled scheduled");
    let s = |k: &str| args[k].as_str().map(String::from);
    let u = |k: &str| s(k).map(|v| U128(v.parse().unwrap()));
    let u64_ = |k: &str| s(k).map(|v| U64(v.parse().unwrap()));
    testing_env!(
        VMContextBuilder::new()
            .current_account_id(me())
            .predecessor_account_id(me())
            .signer_account_id(me())
            .storage_usage(STORAGE_BYTES)
            .account_balance(NearToken::from_yoctonear(10 * NEAR))
            .block_timestamp(T0 + 3)
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
        u("relayer_gas"),
    );
}

/// The relayer fires a stored limit BUY exactly as stored; the whole spend (input + storage +
/// max fee) plus the gas bound is charged to the weekly allowance.
#[test]
fn v147_relayer_fires_limit_buy_charged_in_full() {
    // v1.4.8: weekly accounting is opt-in
    let mut c = with_automation_weekly(V147_DEFAULT_WEEKLY);
    let id = place_buy(&mut c, NEAR, 5);
    relayer_buy(&mut c, id, NEAR, 5);
    assert!(c.get_order(U64(id)).unwrap().pending);
    let spend = STORAGE_OP + NEAR + NEAR / 100;
    assert_eq!(week(&c), spend + GAS300);
    // the daily window also counts it (as for any execute_order)
    assert_eq!(c.day.spent_yocto, spend);
}

/// Exactly as stored: another amount, DEX or min_out is refused like a device fire would be.
#[test]
fn v147_relayer_buy_must_match_order() {
    let mut c = with_automation();
    let id = place_buy(&mut c, NEAR, 5);
    ctx_pk(me().as_str(), Some(auto_pk()), 0, T0 + 2);
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| c.execute_order(U64(id), order_buy_ops(NEAR / 2, 5)))),
        "E_ORDER_MISMATCH"
    );
    let mut c = with_automation();
    let id = place_buy(&mut c, NEAR, 5);
    ctx_pk(me().as_str(), Some(auto_pk()), 0, T0 + 2);
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| c.execute_order(U64(id), order_buy_ops(NEAR, 4)))),
        "E_ORDER_MIN_OUT"
    );
    // once: a second fire while Pending is refused
    let mut c = with_automation();
    let id = place_buy(&mut c, NEAR, 5);
    relayer_buy(&mut c, id, NEAR, 5);
    ctx_pk(me().as_str(), Some(auto_pk()), 0, T0 + 3);
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| c.execute_order(U64(id), order_buy_ops(NEAR, 5)))),
        "E_ORDER_PENDING"
    );
}

/// The weekly allowance bounds relayer buys: a buy that does not fit is refused before the order
/// goes Pending (the order stays open for the device / next week).
#[test]
fn v147_relayer_buy_bounded_by_weekly_allowance() {
    let mut c = with_automation();
    ctx("owner.near", 1, 10 * NEAR, T0 + 1);
    c.owner_set_relayer_allowance(U128(NEAR));
    let id = place_buy(&mut c, NEAR, 5); // 1 NEAR + fee + storage + gas > 1 NEAR allowance
    ctx_pk(me().as_str(), Some(auto_pk()), 0, T0 + 2);
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| c.execute_order(U64(id), order_buy_ops(NEAR, 5)))),
        "E_RELAYER_WEEKLY"
    );
    assert_eq!(week(&c), 0);
    // total over a week: 3 NEAR allowance, 1 NEAR buys -> 2 fire, the third is refused
    let mut c = with_automation();
    ctx("owner.near", 1, 10 * NEAR, T0 + 1);
    c.owner_set_relayer_allowance(U128(3 * NEAR));
    let mut fired = 0;
    for _ in 0..3 {
        let id = place_buy(&mut c, NEAR, 5);
        ctx_pk(me().as_str(), Some(auto_pk()), 0, T0 + 2);
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            c.execute_order(U64(id), order_buy_ops(NEAR, 5))
        }))
        .is_ok()
        {
            fired += 1;
        }
    }
    assert_eq!(fired, 2);
    assert!(week(&c) <= 3 * NEAR);
}

/// A provable refund (wrap resolved 0) reopens the buy and returns input + fee to the week;
/// storage and gas stay charged. v1.4.8 (RA7-1): so does the floor (allowance / 20).
#[test]
fn v147_relayer_buy_refund_keeps_storage_and_gas() {
    let mut c = with_automation_weekly(V147_DEFAULT_WEEKLY);
    let id = place_buy(&mut c, NEAR, 5);
    relayer_buy(&mut c, id, NEAR, 5);
    settle_scheduled(&mut c, ok_json(0));
    assert!(!c.get_order(U64(id)).unwrap().pending, "reopened");
    let floor = V147_DEFAULT_WEEKLY / MAX_RELAYER_FIRES_PER_WEEK;
    assert_eq!(week(&c), (STORAGE_OP + GAS300).max(floor));
    // with an allowance whose floor is below storage + gas, storage + gas is what stays
    // (its floor, 0.06 NEAR, is below storage + gas, 0.06125 NEAR)
    let mut c = with_automation_weekly(12 * NEAR / 10);
    let id = place_buy(&mut c, NEAR, 5);
    relayer_buy(&mut c, id, NEAR, 5);
    settle_scheduled(&mut c, ok_json(0));
    assert_eq!(week(&c), STORAGE_OP + GAS300);
}

/// Wrap on neither side: still device-only for the relayer.
#[test]
fn v147_relayer_token_to_token_refused() {
    let mut c = with_automation();
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
    let id = c
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
    ctx_pk(me().as_str(), Some(auto_pk()), 0, T0 + 2);
    let ops = vec![Op::FtTransferCall {
        token: a("meme.near"),
        receiver_id: a("v2.ref-finance.near"),
        amount: U128(1_000),
        msg: rhea_msg("meme.near", "usdc.near", 5),
        gas: U64(150 * TGAS),
    }];
    assert_eq!(panics(std::panic::AssertUnwindSafe(|| c.execute_order(U64(id), ops))), "E_RELAYER_SELL_ONLY");
}

// ---------------- unlimited caps (u128::MAX) ----------------

/// With caps = u128::MAX every cap path works without overflow: large executes, gas tally,
/// settle refunds, the withdraw window default, a delayed raise to unlimited (waits 1 h) and an
/// instant lower from unlimited.
#[test]
fn v147_unlimited_caps_math() {
    let max = u128::MAX;
    let mut c = new_account();
    c.caps = caps(max, max);
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
    exec(&mut c, buy(8 * NEAR), "big", max);
    assert_eq!(c.day.spent_yocto, 8 * NEAR + 8 * NEAR / 100);
    settle_scheduled(&mut c, PromiseResult::Failed);
    assert_eq!(c.day.spent_yocto, 0, "refund");
    assert_eq!(c.get_withdraw_day().cap_yocto.0, max);
    // policy: a spend that would overflow the window fails closed, not wraps
    let mut d = Day { start_ns: D0, spent_yocto: max - 1 };
    assert_eq!(check_caps(&mut d, &caps(max, max), T0, 2, max), Err("E_CAP_DAILY"));
    assert_eq!(check_caps(&mut d, &caps(max, max), T0, 1, max), Ok(()));
    // raise to unlimited waits 1 h; lowering from unlimited is immediate
    let mut c = new_account();
    ctx("owner.near", 1, 10 * NEAR, T0 + 1);
    c.owner_set_caps(caps(max, max));
    assert_eq!(c.get_config().caps, caps(2 * NEAR, 5 * NEAR));
    assert_eq!(c.get_pending_caps().unwrap().caps, caps(max, max));
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 1 + CAPS_RAISE_DELAY_NS);
    assert_eq!(c.get_config().caps, caps(max, max));
    exec(&mut c, buy(NEAR), "after", max);
    assert_eq!(c.caps, caps(max, max));
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 2 + CAPS_RAISE_DELAY_NS);
    c.lower_caps(caps(NEAR, 2 * NEAR));
    assert_eq!(c.get_config().caps, caps(NEAR, 2 * NEAR));
}
