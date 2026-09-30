//! v1.4.9: external fix review (UNR-A-08). A NEP-366 Delegate action signed by one of the
//! account's keys runs with predecessor == self, but signer_id / signer_account_pk are the OUTER
//! transaction's. Every key path now requires signer == self (fails closed).
//! RED on v1.4.8 (28cc75f): the delegated relayer fire goes Pending (device path) and the
//! delegated device calls run.
use super::*;

/// The outer signer's key (e.g. mallory.near, or any public meta-tx relayer).
const OUTER_PK: &str = "ed25519:US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx";

/// The inner receipt of a Delegate action from this account: predecessor = self, signer = the
/// outer account and its key.
fn delegated(outer: &str, now: u64) {
    testing_env!(VMContextBuilder::new()
        .current_account_id(me())
        .predecessor_account_id(me())
        .signer_account_id(a(outer))
        .signer_account_pk(OUTER_PK.parse().unwrap())
        .account_balance(NearToken::from_yoctonear(10 * NEAR))
        .block_timestamp(now)
        .storage_usage(STORAGE_BYTES)
        .prepaid_gas(Gas::from_tgas(300))
        .build());
}

fn place_token_to_token(c: &mut TradingAccount) -> u64 {
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
    c.place_order(
        a("meme.near"),
        a("usdc.near"),
        U128(NEAR),
        U128(5),
        String::new(),
        U64(T0 + 3_600 * NS_PER_SEC),
        vec![a("v2.ref-finance.near")],
    )
    .0
}

/// The auditors' fr_h2 unit PoCs, inverted: a delegated automation-key fire used to skip the
/// opt-in weekly allowance and E_RELAYER_SELL_ONLY. Now it is refused before any role check,
/// and the order stays open.
#[test]
fn unr_a08_delegated_relayer_fire_refused() {
    let mut c = with_automation_weekly(NEAR);
    // opt-in week: a 4 NEAR min_out sell is over the 1 NEAR allowance
    let sell = place_sell(&mut c, NEAR, 4 * NEAR);
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| relayer_fire(&mut c, sell, NEAR, 4 * NEAR, T0 + 2))),
        "E_RELAYER_WEEKLY"
    );
    delegated("mallory.near", T0 + 2);
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| c.execute_order(U64(sell), order_sell_ops(NEAR, 4 * NEAR)))),
        "E_NOT_SELF_SIGNED"
    );
    // token -> token: device-only for the relayer
    let t2t = place_token_to_token(&mut c);
    let ops = vec![Op::FtTransferCall {
        token: a("meme.near"),
        receiver_id: a("v2.ref-finance.near"),
        amount: U128(NEAR),
        msg: rhea_msg("meme.near", "usdc.near", 5),
        gas: U64(150 * TGAS),
    }];
    ctx_pk(me().as_str(), Some(auto_pk()), 0, T0 + 2);
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| c.execute_order(U64(t2t), ops.clone()))),
        "E_RELAYER_SELL_ONLY"
    );
    delegated("mallory.near", T0 + 2);
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| c.execute_order(U64(t2t), ops.clone()))),
        "E_NOT_SELF_SIGNED"
    );
    // nothing went Pending, the week is untouched
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 3);
    assert!(c.get_orders().iter().all(|o| !o.order.pending));
    assert_eq!(c.get_relayer_week().spent_yocto.0, 0);
}

/// Every method a function-call key on the account can reach (DEVICE_METHODS; the automation
/// key's list is a subset) refuses a delegated call, whoever the outer signer is (a stranger,
/// or the owner's own wallet).
#[test]
fn unr_a08_every_key_path_refuses_delegate() {
    let mut c = with_automation();
    let id = place_buy(&mut c, NEAR, 5);
    type Call = Box<dyn Fn(&mut TradingAccount)>;
    let calls: Vec<(&str, Call)> = vec![
        (
            "execute",
            Box::new(|c| {
                c.execute(order_buy_ops(NEAR, 5), "d1".into(), U64(T0 + 60 * NS_PER_SEC), U128(NEAR))
            }),
        ),
        ("withdraw_to_owner", Box::new(|c| c.withdraw_to_owner(None, U128(1)))),
        ("lower_caps", Box::new(|c| c.lower_caps(caps(1, 1)))),
        (
            "place_order",
            Box::new(|c| {
                c.place_order(
                    a("wrap.near"),
                    a("meme.near"),
                    U128(1),
                    U128(1),
                    String::new(),
                    U64(T0 + 60 * NS_PER_SEC),
                    vec![a("v2.ref-finance.near")],
                );
            }),
        ),
        ("cancel_order", Box::new(move |c| c.cancel_order(U64(id)))),
        ("revoke_automation", Box::new(|c| c.revoke_automation())),
        (
            "withdraw_cross_chain",
            Box::new(|c| {
                c.withdraw_cross_chain(
                    0,
                    a("wrap.near"),
                    U128(1),
                    "{}".into(),
                    String::new(),
                    "x1".into(),
                    U64(T0 + 60 * NS_PER_SEC),
                )
            }),
        ),
        ("remove_withdraw_destination", Box::new(|c| c.remove_withdraw_destination(0))),
        ("withdraw_from_intents", Box::new(|c| c.withdraw_from_intents(a("wrap.near"), U128(1)))),
        ("execute_order", Box::new(move |c| c.execute_order(U64(id), order_buy_ops(NEAR, 5)))),
    ];
    // the list is exactly the key-reachable surface
    let mut names: Vec<&str> = calls.iter().map(|(n, _)| *n).collect();
    let mut device: Vec<&str> = DEVICE_METHODS.split(',').collect();
    names.sort_unstable();
    device.sort_unstable();
    assert_eq!(names, device);
    assert!(AUTOMATION_METHODS.split(',').all(|m| device.contains(&m)));
    for outer in ["mallory.near", "owner.near"] {
        for (name, f) in &calls {
            delegated(outer, T0 + 2);
            assert_eq!(
                panics(std::panic::AssertUnwindSafe(|| f(&mut c))),
                "E_NOT_SELF_SIGNED",
                "{name} via a Delegate from {outer}"
            );
        }
    }
    // still there, still armed
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 3);
    assert_eq!(c.get_automation_key(), Some(auto_pk()));
    assert!(c.get_order(U64(id)).is_some_and(|o| !o.pending));
}

/// Self-signed calls are unchanged: the automation key is still classified as the relayer and
/// a device key still fires any order.
#[test]
fn unr_a08_self_signed_paths_unchanged() {
    let mut c = with_automation();
    let t2t = place_token_to_token(&mut c);
    let ops = vec![Op::FtTransferCall {
        token: a("meme.near"),
        receiver_id: a("v2.ref-finance.near"),
        amount: U128(NEAR),
        msg: rhea_msg("meme.near", "usdc.near", 5),
        gas: U64(150 * TGAS),
    }];
    ctx_pk(me().as_str(), Some(auto_pk()), 0, T0 + 2);
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| c.execute_order(U64(t2t), ops.clone()))),
        "E_RELAYER_SELL_ONLY"
    );
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 2);
    c.execute_order(U64(t2t), ops);
    assert!(c.get_order(U64(t2t)).is_some_and(|o| o.pending));
    let sell = place_sell(&mut c, NEAR, 5);
    relayer_fire(&mut c, sell, NEAR, 5, T0 + 2);
    assert!(c.get_order(U64(sell)).is_some_and(|o| o.pending));
}

// ---------------- UNR-A-09 / A-10 / A-11: reopened relayer fires ----------------

use super::v148::settle;

fn token_zero() -> PromiseResult {
    PromiseResult::Successful(b"\"0\"".to_vec())
}

fn day(c: &TradingAccount, now: u64) -> DayView {
    ctx(me().as_str(), 0, 10 * NEAR, now);
    c.get_day()
}

/// UNR-A-09 (the auditors' fr_h1_optin_honest_refusal_burns_week): opt-in 10 NEAR, a 4 NEAR
/// min_out stop refused twice by the pool (honest token "0"). v1.4.8 kept 8 NEAR charged and the
/// third fire was E_RELAYER_WEEKLY. Now only the floor (0.5 NEAR) stays per fire, like Failed.
/// A lying token still can't refill the week: each "0" keeps the floor, so <= 20 fires a week.
#[test]
fn unr_a09_honest_refusal_keeps_only_the_floor() {
    let mut c = with_automation_weekly(10 * NEAR);
    let floor = 10 * NEAR / 20;
    let id = place_sell(&mut c, NEAR, 4 * NEAR);
    for i in 1..=3u128 {
        relayer_fire(&mut c, id, NEAR, 4 * NEAR, T0 + 2);
        settle(&mut c, token_zero(), T0 + 3);
        ctx(me().as_str(), 0, 10 * NEAR, T0 + 3);
        assert!(c.get_order(U64(id)).is_some_and(|o| !o.pending), "reopened");
        assert_eq!(c.get_relayer_week().spent_yocto.0, i * floor, "fire {i}");
    }
    // still bounded: each fire needs max(min_out, floor) of room and keeps the floor, so a lying
    // token gets at most (allowance - min_out) / floor + 1 <= 20 fires a week
    let fires = (10 * NEAR - 4 * NEAR) / floor + 1;
    assert!(fires <= 20);
    for _ in 3..fires {
        relayer_fire(&mut c, id, NEAR, 4 * NEAR, T0 + 2);
        settle(&mut c, token_zero(), T0 + 3);
    }
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| relayer_fire(&mut c, id, NEAR, 4 * NEAR, T0 + 2))),
        "E_RELAYER_WEEKLY"
    );
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 3);
    assert_eq!(c.get_relayer_week().spent_yocto.0, fires * floor);
}

/// UNR-A-10 / A-11 (the auditors' fr_h1_reopen_loop_exhausts_owner_daily_cap and
/// fr_a02_v4b_device_blocked_after_relayer_loop): a 5 NEAR daily cap, no weekly allowance, a
/// relayer re-firing one sell with an unmeetable msg min_out. v1.4.8: 82 fires filled the gas
/// tally, then E_CAP_DAILY for the relayer and the device. Now a reopened relayer fire gives its
/// gas charge back: 200 fires later the tally is where it started and the device still trades.
#[test]
fn unr_a10_reopen_loop_does_not_fill_the_daily_cap() {
    let mut c = with_automation();
    c.caps = caps(UNLIMITED, 5 * NEAR);
    let id = place_sell(&mut c, NEAR, 5);
    let before = day(&c, T0 + 2).gas_spent_yocto.0;
    for _ in 0..200 {
        relayer_fire(&mut c, id, NEAR, 1_000 * NEAR, T0 + 2);
        settle(&mut c, token_zero(), T0 + 3);
    }
    assert_eq!(day(&c, T0 + 3).gas_spent_yocto.0, before);
    // a failed (runtime revert) reopen gives it back too
    relayer_fire(&mut c, id, NEAR, 1_000 * NEAR, T0 + 2);
    settle(&mut c, PromiseResult::Failed, T0 + 3);
    assert_eq!(day(&c, T0 + 3).gas_spent_yocto.0, before);
    // the device still fires the stop-loss and withdraws
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 4);
    c.execute_order(U64(id), order_sell_ops(NEAR, 5));
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 4);
    c.withdraw_to_owner(Some(a("meme.near")), U128(1));
}

/// What stays charged: a relayer fire that fills, a device fire that reopens (the device path is
/// unchanged, SC-2), and a refund for another UTC day (the tally is per day).
#[test]
fn unr_a10_filled_device_and_stale_fires_stay_charged() {
    let mut c = with_automation();
    c.caps = caps(UNLIMITED, 5 * NEAR);
    let charge = (300 * TGAS) as u128 * GAS_PRICE_BOUND;
    let id = place_sell(&mut c, NEAR, 5);
    let before = day(&c, T0 + 2).gas_spent_yocto.0;
    // device fire, reopened: charged
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 2);
    c.execute_order(U64(id), order_sell_ops(NEAR, 5));
    settle(&mut c, token_zero(), T0 + 3);
    assert_eq!(day(&c, T0 + 3).gas_spent_yocto.0, before + charge);
    // relayer fire, filled: charged
    relayer_fire(&mut c, id, NEAR, 5, T0 + 2);
    settle(&mut c, PromiseResult::Successful(format!("\"{NEAR}\"").into_bytes()), T0 + 3);
    assert_eq!(day(&c, T0 + 3).gas_spent_yocto.0, before + 2 * charge);
    // relayer fire, reopened the next UTC day: that day's tally is not touched by the old fire
    let id = place_sell(&mut c, NEAR, 5);
    relayer_fire(&mut c, id, NEAR, 5, T0 + 2);
    let next = T0 + DAY + 1;
    settle(&mut c, token_zero(), next);
    assert_eq!(day(&c, next).gas_spent_yocto.0, 0);
}

/// Known residual of UNR-A-10 (RD9-1, documented, not changed): a relayer fire may carry up to
/// MAX_OPS - 1 = 3 StorageDeposit ops (<= 0.0125 NEAR each, to wrap / an allowlisted DEX / the
/// order's tokens). They are daily *spend*, not gas, and stay charged on a reopen, because a
/// hostile order token can keep the deposit (CAPACCT-001). A looping key can still fill a small
/// owner-set daily cap this way, at <= 0.0375 NEAR a fire (was 0.06 NEAR of gas + that).
#[test]
fn rd9_1_storage_ops_on_a_reopened_relayer_fire_stay_charged() {
    let mut c = with_automation();
    c.caps = caps(UNLIMITED, 5 * NEAR);
    let id = place_sell(&mut c, NEAR, 5);
    let spent0 = day(&c, T0 + 2).spent_yocto.0;
    let gas0 = day(&c, T0 + 2).gas_spent_yocto.0;
    let mut ops = vec![Op::StorageDeposit { token: a("wrap.near"), amount: U128(MAX_STORAGE_DEPOSIT) }; 3];
    ops.extend(order_sell_ops(NEAR, 1_000 * NEAR));
    ctx_pk(me().as_str(), Some(auto_pk()), 0, T0 + 2);
    c.execute_order(U64(id), ops);
    settle(&mut c, token_zero(), T0 + 3);
    let d = day(&c, T0 + 3);
    assert_eq!(d.gas_spent_yocto.0, gas0, "gas charge returned");
    assert_eq!(d.spent_yocto.0, spent0 + 3 * MAX_STORAGE_DEPOSIT, "storage spend kept");
}
