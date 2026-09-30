//! v1.4.3 regressions (docs/audit/tob-contracts-*.md). Each test fails on e7dc586 (v1.4.2).
use super::*;
use near_sdk::serde_json::Value;

fn pk(i: u8) -> PublicKey {
    format!("ed25519:{}", near_sdk::bs58::encode([i; 32]).into_string()).parse().unwrap()
}

fn owner_ctx(now: u64) {
    ctx("owner.near", 1, 10 * NEAR, now);
}

/// Replays the `on_swap_settled` callback that the last execute / execute_order scheduled,
/// with its real arguments, against `result`.
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

// ---------------- ROLESET-001 (High) ----------------

/// Worker-10 repro (revoke, then re-set the SAME key while its DeleteKey is pending): refused.
#[test]
fn v143_roleset_revoke_then_reset_same_key_is_busy() {
    let mut c = with_automation();
    owner_ctx(T0 + 1);
    c.owner_revoke_automation();
    owner_ctx(T0 + 1);
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| c.owner_set_automation_key(auto_pk(), U128(NEAR)))),
        "E_AUTOMATION_BUSY"
    );
    // once the DeleteKey is confirmed, installing (the same key) works again
    key_cb(PromiseResult::Successful(vec![]));
    c.on_relayer_key_deleted(auto_pk());
    assert!(c.get_relayer_keys().is_empty());
    owner_ctx(T0 + 2);
    c.owner_set_automation_key(auto_pk(), U128(NEAR));
    assert_eq!(c.get_relayer_keys(), vec![auto_pk()]);
}

/// Worker-10 repro (rotate A -> B, then back to A before the first callback): refused.
#[test]
fn v143_roleset_rotate_and_back_is_busy() {
    let mut c = with_automation();
    let id = place_buy(&mut c, NEAR, 5);
    owner_ctx(T0 + 1);
    c.owner_set_automation_key(pk(7), U128(NEAR));
    owner_ctx(T0 + 1);
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| c.owner_set_automation_key(auto_pk(), U128(NEAR)))),
        "E_AUTOMATION_BUSY"
    );
    key_cb(PromiseResult::Successful(vec![]));
    c.on_automation_set(pk(7), Some(auto_pk()), Some(true));
    assert_eq!(c.get_relayer_keys(), vec![pk(7)]);
    assert_eq!(buy_fire_by(&mut c, pk(7), id), "E_RELAYER_WEEKLY");
}

/// Defence in depth: a successful install always leaves the key in the role set, even after its
/// earlier DeleteKey confirmation removed it (the v1.4.2 interleaving).
#[test]
fn v143_roleset_installed_key_is_always_member() {
    let mut c = with_automation();
    let id = place_buy(&mut c, NEAR, 5);
    key_cb(PromiseResult::Successful(vec![]));
    c.on_relayer_key_deleted(auto_pk()); // the stale confirmation lands first
    key_cb(PromiseResult::Successful(vec![]));
    c.on_automation_set(auto_pk(), None, Some(false)); // then the (re-)install succeeds
    assert_eq!(c.get_automation_key(), Some(auto_pk()));
    assert_eq!(c.get_relayer_keys(), vec![auto_pk()]);
    assert_eq!(buy_fire_by(&mut c, auto_pk(), id), "E_RELAYER_WEEKLY");
}

/// migrate heals a v1.4.2 account already in the ROLESET-001 state and materializes a legacy set.
#[test]
fn v143_migrate_puts_automation_key_in_role_set() {
    for legacy in [true, false] {
        let c = new_account();
        near_sdk::env::storage_write(b"ak", &near_sdk::borsh::to_vec(&auto_pk()).unwrap());
        if !legacy {
            // v1.4.2 ROLESET-001 end state: installed + stored, but the set is empty
            near_sdk::env::storage_write(b"ar", &near_sdk::borsh::to_vec(&Vec::<PublicKey>::new()).unwrap());
        }
        near_sdk::env::state_write(&c);
        ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
        let _ = TradingAccount::migrate();
        assert!(near_sdk::env::storage_has_key(b"ar"), "set materialized");
        assert_eq!(relayer_keys(), vec![auto_pk()]);
    }
}

// ---------------- PROMISEORDER-001 (Medium) ----------------

/// Worker-9 repro, inverted: on legacy (<= v1.4.1) state, owner_remove_key(automation key) keeps
/// the key a relayer until its DeleteKey is confirmed.
#[test]
fn v143_legacy_owner_remove_key_keeps_relayer_until_deleted() {
    let mut c = new_account();
    let id = place_buy(&mut c, NEAR, 5);
    near_sdk::env::storage_write(b"ak", &near_sdk::borsh::to_vec(&auto_pk()).unwrap());
    assert!(!near_sdk::env::storage_has_key(b"ar"));
    owner_ctx(T0 + 1);
    c.owner_remove_key(auto_pk());
    let rs = get_created_receipts();
    assert!(format!("{:?}", rs[0].actions[0]).starts_with("DeleteKey"), "{rs:?}");
    assert_eq!(c.get_automation_key(), None);
    assert_eq!(c.get_relayer_keys(), vec![auto_pk()]);
    assert_eq!(buy_fire_by(&mut c, auto_pk(), id), "E_RELAYER_WEEKLY");
    assert!(!c.get_order(U64(id)).unwrap().pending);
    key_cb(PromiseResult::Successful(vec![]));
    c.on_relayer_key_deleted(auto_pk());
    assert!(c.get_relayer_keys().is_empty());
}

// ---------------- CAPACCT-001 / TI-1 / SC-1 (Medium) ----------------

/// A hostile token that keeps every storage deposit gains at most the daily cap per UTC day.
#[test]
fn v143_capacct_withdraw_storage_deposits_within_daily_cap() {
    let mut c = new_account();
    c.caps = caps(NEAR, NEAR / 5);
    let mut deposited: u128 = 0;
    // (the mock does not revert a refused call's writes: read the day after each accepted call)
    let mut d = c.get_day();
    for i in 0..200u64 {
        ctx(me().as_str(), 0, 10 * NEAR, T0 + 10 + i);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            c.withdraw_to_owner(Some(a("evil.near")), U128(1))
        }));
        if r.is_err() {
            break;
        }
        deposited += get_created_receipts()
            .iter()
            .filter(|r| r.receiver_id == a("evil.near"))
            .flat_map(|r| r.actions.iter())
            .map(|x| match x {
                MockAction::FunctionCallWeight { attached_deposit, .. } => attached_deposit.as_yoctonear(),
                _ => 0,
            })
            .sum::<u128>();
        d = c.get_day();
    }
    println!("CAPACCT: evil.near received {deposited}; cap {}", NEAR / 5);
    assert!(deposited > 0);
    assert!(deposited <= NEAR / 5, "storage deposits {deposited} leak past the daily cap");
    assert!(d.spent_yocto.0 + d.gas_spent_yocto.0 <= NEAR / 5);
    // the reserve is kept on the token path
    ctx(me().as_str(), 0, LOCKED + RESERVE + MAX_STORAGE_DEPOSIT / 2, T0 + DAY_NS);
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| c.withdraw_to_owner(Some(a("evil.near")), U128(1)))),
        "E_RESERVE"
    );
}

// ---------------- ORDER-001 (Medium) ----------------

/// A Plach NEAR buy settled with "0" (hostile Plach) is fully used: the order is consumed and
/// the daily spend keeps its amount. A failed receipt (runtime refund) still reopens it.
#[test]
fn v143_order_plach_zero_is_not_a_refund() {
    for failed in [false, true] {
        let mut c = new_account();
        ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
        let id = c
            .place_order(
                a("wrap.near"),
                a("meme.near"),
                U128(NEAR),
                U128(5),
                "{}".into(),
                U64(T0 + 3_600 * NS_PER_SEC),
                vec![a("dex.intear.near")],
            )
            .0;
        exec_order(&mut c, id, plach_buy_ops(NEAR, 5));
        let spent = c.day.spent_yocto;
        assert!(spent >= NEAR);
        settle_scheduled(&mut c, if failed { PromiseResult::Failed } else { ok_json(0) });
        if failed {
            assert!(!c.get_order(U64(id)).unwrap().pending, "failed receipt = refund: reopened");
            assert!(c.day.spent_yocto < NEAR);
        } else {
            assert!(c.get_order(U64(id)).is_none(), "Plach \"0\" must not reopen the order");
            assert!(c.day.spent_yocto >= NEAR, "Plach \"0\" must not refund the daily spend");
            assert!(get_logs().iter().any(|l| l.contains("order_filled")));
        }
    }
}

/// Plain execute: a Plach buy reporting "0" keeps its spend (the cap is not refilled).
#[test]
fn v143_order_plach_zero_keeps_execute_spend() {
    let mut c = new_account();
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
    exec(&mut c, plach_buy_ops(NEAR, 5), "p0", 2 * NEAR);
    let spent = c.day.spent_yocto;
    settle_scheduled(&mut c, ok_json(0));
    assert_eq!(c.day.spent_yocto, spent, "no spend returned for a Plach \"0\"");
    // wrap.near's resolve stays trusted: 0 used returns the spend
    let mut c = new_account();
    let id = place_buy(&mut c, NEAR, 5);
    exec_order(&mut c, id, order_buy_ops(NEAR, 5));
    settle_scheduled(&mut c, ok_json(0));
    assert!(!c.get_order(U64(id)).unwrap().pending, "wrap resolved 0: reopened");
}

// ---------------- SC-2 (Low): every device call is charged ----------------

#[test]
fn v143_sc2_every_device_call_charges_gas() {
    let per = 300 * TGAS as u128 * GAS_PRICE_BOUND; // ctx prepays 300 TGas
    let mut c = new_account();
    let gas = |c: &TradingAccount| c.get_day().gas_spent_yocto.0;
    // place_order
    let g0 = gas(&c);
    let id = place_buy(&mut c, NEAR, 5);
    assert_eq!(gas(&c) - g0, per, "place_order");
    // cancel_order (device)
    let g0 = gas(&c);
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 2);
    c.cancel_order(U64(id));
    assert_eq!(gas(&c) - g0, per, "cancel_order");
    // lower_caps
    let g0 = gas(&c);
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 3);
    c.lower_caps(caps(2 * NEAR, 5 * NEAR));
    assert_eq!(gas(&c) - g0, per, "lower_caps");
    // revoke_automation
    let g0 = gas(&c);
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 4);
    c.revoke_automation();
    assert_eq!(gas(&c) - g0, per, "revoke_automation");
    // remove_withdraw_destination
    owner_ctx(T0 + 5);
    let dest = c.owner_add_withdraw_destination(
        "sol".into(),
        "nep141:sol.omft.near".into(),
        "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin".into(),
        "DESTINATION_CHAIN".into(),
    );
    let g0 = gas(&c);
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 6);
    c.remove_withdraw_destination(dest);
    assert_eq!(gas(&c) - g0, per, "remove_withdraw_destination");
}

/// Safety actions are recorded but never refused on a spent cap; place_order is refused.
#[test]
fn v143_sc2_safety_actions_never_blocked_by_cap() {
    let mut c = new_account();
    let id = place_buy(&mut c, NEAR, 5);
    c.caps = caps(NEAR, 1); // cap already exceeded by the tally
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 2);
    c.lower_caps(caps(NEAR, 1));
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 3);
    c.cancel_order(U64(id));
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 4);
    c.revoke_automation();
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 5);
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| {
            c.place_order(
                a("wrap.near"),
                a("meme.near"),
                U128(NEAR),
                U128(5),
                "{}".into(),
                U64(T0 + 3_600 * NS_PER_SEC),
                vec![a("v2.ref-finance.near")],
            );
        })),
        "E_CAP_DAILY"
    );
}

// ---------------- SC-3 (Low): init registration outcome ----------------

#[test]
fn v143_sc3_init_registration_reported() {
    let c = new_account();
    assert!(c.get_init_registration().is_empty(), "not reported before the callback");
    testing_env!(
        VMContextBuilder::new()
            .current_account_id(me())
            .predecessor_account_id(me())
            .signer_account_id(me())
            .build(),
        near_sdk::test_vm_config(),
        near_sdk::RuntimeFeesConfig::test(),
        Default::default(),
        vec![PromiseResult::Successful(vec![]), PromiseResult::Failed],
    );
    let mut c = c;
    c.on_init_registered(vec![a("wrap.near"), a("dclv2.ref-labs.near")]);
    assert_eq!(
        c.get_init_registration(),
        vec![
            InitRegistration { target: a("wrap.near"), ok: true },
            InitRegistration { target: a("dclv2.ref-labs.near"), ok: false },
        ]
    );
    let logs = get_logs();
    assert!(
        logs.iter().any(|l| l.contains(r#""event":"init_registration""#)
            && l.contains(r#"{"target":"dclv2.ref-labs.near","ok":false}"#)),
        "{logs:?}"
    );
}

// ---------------- OWNERBOUND-001: delayed cap raises ----------------

#[test]
fn v143_ownerbound_cap_raise_delayed_decrease_immediate() {
    let mut c = new_account(); // init caps (2, 5) apply at once
    assert_eq!(c.get_config().caps, caps(2 * NEAR, 5 * NEAR));
    // raise: pending for 1 h
    owner_ctx(T0 + 1);
    c.owner_set_caps(caps(100 * NEAR, 200 * NEAR));
    assert!(get_logs().iter().any(|l| l.contains("caps_raise_pending")));
    assert_eq!(c.get_config().caps, caps(2 * NEAR, 5 * NEAR));
    let p = c.get_pending_caps().expect("pending");
    assert_eq!((p.caps, p.active_at_ns.0), (caps(100 * NEAR, 200 * NEAR), T0 + 1 + CAPS_RAISE_DELAY_NS));
    // a 3 NEAR execute inside the hour is refused by the old cap
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 2);
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| exec(&mut c, buy(3 * NEAR), "r1", 4 * NEAR))),
        "E_CAP_TRADE"
    );
    // after the delay it applies (view first, then state on the next call)
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 1 + CAPS_RAISE_DELAY_NS);
    assert_eq!(c.get_config().caps, caps(100 * NEAR, 200 * NEAR));
    assert!(c.get_pending_caps().is_none());
    exec(&mut c, buy(3 * NEAR), "r2", 4 * NEAR);
    assert_eq!(c.caps, caps(100 * NEAR, 200 * NEAR));
    // decrease: immediate, no pending
    owner_ctx(T0 + 2 + CAPS_RAISE_DELAY_NS);
    c.owner_set_caps(caps(NEAR, 4 * NEAR));
    assert_eq!(c.get_config().caps, caps(NEAR, 4 * NEAR));
    assert!(c.get_pending_caps().is_none());
    // mixed: the decrease applies now, the raise waits
    owner_ctx(T0 + 3 + CAPS_RAISE_DELAY_NS);
    c.owner_set_caps(caps(NEAR / 2, 9 * NEAR));
    assert_eq!(c.get_config().caps, caps(NEAR / 2, 4 * NEAR));
    assert_eq!(c.get_pending_caps().unwrap().caps, caps(NEAR / 2, 9 * NEAR));
}

#[test]
fn v143_ownerbound_lower_caps_cancels_raise() {
    let mut c = new_account();
    owner_ctx(T0 + 1);
    c.owner_set_caps(caps(100 * NEAR, 200 * NEAR));
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 2);
    c.lower_caps(caps(2 * NEAR, 5 * NEAR));
    assert!(get_logs().iter().any(|l| l.contains("caps_raise_cancelled")));
    assert!(c.get_pending_caps().is_none());
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 2 + CAPS_RAISE_DELAY_NS);
    assert_eq!(c.get_config().caps, caps(2 * NEAR, 5 * NEAR), "cancelled raise never applies");
    // an owner call without a raise also cancels
    owner_ctx(T0 + 3 + CAPS_RAISE_DELAY_NS);
    c.owner_set_caps(caps(100 * NEAR, 200 * NEAR));
    owner_ctx(T0 + 4 + CAPS_RAISE_DELAY_NS);
    c.owner_set_caps(caps(NEAR, 5 * NEAR));
    assert!(c.get_pending_caps().is_none());
}

// ---------------- RESDISC-001 (Low): unreadable balances are reported ----------------

#[test]
fn v143_withdraw_all_reports_unreadable_token() {
    let mut c = new_account();
    testing_env!(
        VMContextBuilder::new()
            .current_account_id(me())
            .predecessor_account_id(me())
            .signer_account_id(me())
            .account_balance(NearToken::from_yoctonear(10 * NEAR))
            .storage_usage(STORAGE_BYTES)
            .build(),
        near_sdk::test_vm_config(),
        near_sdk::RuntimeFeesConfig::test(),
        Default::default(),
        vec![
            PromiseResult::Successful(b"\"0\"".to_vec()), // wrap: empty (silent)
            PromiseResult::Failed,                        // paused.near: unreadable
            PromiseResult::Successful(b"\"5\"".to_vec()), // meme.near: 5
            PromiseResult::Successful(b"null".to_vec()),
            PromiseResult::Successful(b"null".to_vec()),
        ],
    );
    c.on_withdraw_all_balances(a("owner.near"), vec![a("paused.near"), a("meme.near")]);
    let logs = get_logs();
    assert!(
        logs.iter().any(|l| l.contains(r#""event":"owner_withdraw","data":{"token":"paused.near","amount":"0","to":"owner.near","ok":false}"#)),
        "{logs:?}"
    );
    assert!(!logs.iter().any(|l| l.contains(r#""token":"wrap.near""#)), "a readable 0 stays silent");
}
