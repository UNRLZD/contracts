//! v1.4.5 regressions (docs/audit/tob-contracts-v144-reaudit.md). Each test fails on 06b1f47.
use super::*;

fn pk(i: u8) -> PublicKey {
    format!("ed25519:{}", near_sdk::bs58::encode([i; 32]).into_string()).parse().unwrap()
}

fn owner_ctx(now: u64) {
    ctx("owner.near", 1, 10 * NEAR, now);
}

fn upgrade_at(c: &TradingAccount, now: u64) -> TradingAccount {
    near_sdk::env::state_write(c);
    ctx(me().as_str(), 0, 10 * NEAR, now);
    TradingAccount::migrate()
}

// ---------------- RA4-1 (Low) ----------------

/// The re-audit's sketch: clear accepted for an install begun without the `ai` marker (v1.4.3
/// code), the install lands, then the clear's callback: the current key stays in the role set.
#[test]
fn v145_ra4_1_clear_never_removes_current_key() {
    let mut c = new_account();
    owner_ctx(T0 + 1);
    c.owner_set_automation_key(pk(3), U128(NEAR));
    near_sdk::env::storage_remove(b"ai"); // v1.4.3-era install
    owner_ctx(T0 + 1);
    c.owner_clear_relayer_key(pk(3));
    key_cb(PromiseResult::Successful(vec![]));
    c.on_automation_set(pk(3), None, Some(true));
    key_cb(PromiseResult::Failed);
    c.on_relayer_key_cleared(pk(3));
    let ak = c.get_automation_key().expect("stored");
    assert!(c.get_relayer_keys().contains(&ak), "ak outside the role set");
}

// ---------------- RA4-5 (Info) ----------------

/// A raise that matured (caps unchanged since) is applied by migrate, not pushed back.
#[test]
fn v145_ra4_5_matured_raise_applied_not_rearmed() {
    let mut c = new_account();
    owner_ctx(T0 + 1);
    c.owner_set_caps(caps(100 * NEAR, 200 * NEAR));
    let c = upgrade_at(&c, T0 + 2 * CAPS_RAISE_DELAY_NS);
    assert_eq!(c.get_config().caps, caps(100 * NEAR, 200 * NEAR));
    assert!(c.get_pending_caps().is_none());
    assert_eq!(c.caps, caps(100 * NEAR, 200 * NEAR), "written, not only shown");
}

/// Caps changed by older code while the raise waited (a device lower_caps there could not cancel
/// it): migrate cancels the raise, matured or not.
#[test]
fn v145_ra4_5_caps_changed_by_older_code_cancel_raise() {
    for later in [T0 + CAPS_RAISE_DELAY_NS / 2, T0 + 2 * CAPS_RAISE_DELAY_NS] {
        let mut c = new_account();
        owner_ctx(T0 + 1);
        c.owner_set_caps(caps(100 * NEAR, 200 * NEAR));
        c.caps = caps(NEAR / 2, NEAR); // older code's lower_caps
        let c = upgrade_at(&c, later);
        assert_eq!(c.get_config().caps, caps(NEAR / 2, NEAR));
        assert!(c.get_pending_caps().is_none());
        assert!(get_logs().iter().any(|l| l.contains("caps_raise_cancelled") && l.contains("migrate")));
    }
}

/// Withdraw destinations still pending at migrate get a full delay from now; active ones stay.
#[test]
fn v145_ra4_5b_pending_destinations_rearmed() {
    let mut c = new_account();
    owner_ctx(T0);
    let active = c.owner_add_withdraw_destination(
        "a".into(),
        "nep141:sol.omft.near".into(),
        "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin".into(),
        "DESTINATION_CHAIN".into(),
    );
    owner_ctx(T0 + crate::intents::DEST_DELAY_NS / 2);
    let pending = c.owner_add_withdraw_destination(
        "b".into(),
        "nep141:sol.omft.near".into(),
        "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin".into(),
        "DESTINATION_CHAIN".into(),
    );
    let now = T0 + crate::intents::DEST_DELAY_NS + 1;
    let c = upgrade_at(&c, now);
    let v = c.get_withdraw_destinations();
    let at = |id: u32| v.iter().find(|d| d.dest_id == id).unwrap().dest.active_at_ns.0;
    assert_eq!(at(active), T0 + crate::intents::DEST_DELAY_NS, "active one untouched");
    assert_eq!(at(pending), now + crate::intents::DEST_DELAY_NS, "pending one re-armed");
    assert!(get_logs().iter().any(|l| l.contains("withdraw_destination_rearmed")));
}

// ---------------- RA4-3 (Info) ----------------

/// A stale `ai` (its install finished under older code) plus a stuck entry: after migrate the
/// owner can clear the stuck entry again.
#[test]
fn v145_ra4_3_stale_marker_dropped_by_migrate() {
    let mut c = new_account();
    owner_ctx(T0 + 1);
    c.owner_set_automation_key(pk(3), U128(NEAR));
    // older code's callback: ak = pk(3), marker left behind; plus a stuck legacy entry pk(5)
    near_sdk::env::storage_write(b"ak", &near_sdk::borsh::to_vec(&pk(3)).unwrap());
    near_sdk::env::storage_write(b"ar", &near_sdk::borsh::to_vec(&vec![pk(3), pk(5)]).unwrap());
    owner_ctx(T0 + 2);
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| c.owner_clear_relayer_key(pk(5)))),
        "E_AUTOMATION_BUSY"
    );
    let mut c = upgrade_at(&c, T0 + 3);
    owner_ctx(T0 + 4);
    c.owner_clear_relayer_key(pk(5));
    assert!(format!("{:?}", get_created_receipts()[0].actions[0]).starts_with("DeleteKey"));
}

// ---------------- INV-69: defensive codes need corrupted state ----------------

/// Corrupted state reaches each defensive code of the account: E_NO_STATE (migrate with no
/// STATE), E_STATE (undecodable raw keys). E_JSON: see the property below. E_ACCOUNT_ID is the
/// factory's (factory/src/lib.rs tests).
#[test]
fn inv69_corrupted_state_reaches_defensive_codes() {
    ctx(me().as_str(), 0, NEAR, T0);
    near_sdk::mock::with_mocked_blockchain(|b| {
        b.take_storage();
    });
    assert_eq!(panics(|| drop(TradingAccount::migrate())), "E_NO_STATE");
    for (key, view) in [
        (b"ar".as_slice(), 0u8), // relayer role set
        (b"oi".as_slice(), 1),   // order index
        (b"cp".as_slice(), 2),   // pending caps
        (b"rw".as_slice(), 3),   // relayer week
        (b"ir".as_slice(), 4),   // init registration
    ] {
        let c = new_account();
        near_sdk::env::storage_write(key, b"\xff\xff\xff");
        let r = panics(std::panic::AssertUnwindSafe(|| match view {
            0 => drop(c.get_relayer_keys()),
            1 => drop(c.get_orders()),
            2 => drop(c.get_pending_caps()),
            3 => drop(c.get_relayer_week()),
            _ => drop(c.get_init_registration()),
        }));
        assert_eq!(r, "E_STATE", "key {:?}", String::from_utf8_lossy(key));
    }
}

const DEFENSIVE: [&str; 4] = ["E_NO_STATE", "E_STATE", "E_JSON", "E_ACCOUNT_ID"];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// E_JSON is raised only if serializing a Rust string / struct fails: jstr round-trips every
    /// string (control characters, quotes, unicode) without error.
    #[test]
    fn inv69_jstr_never_fails(s in "\\PC*|[\\x00-\\x1f\"\\\\]{0,64}") {
        let j = jstr(&s);
        prop_assert_eq!(serde_json::from_str::<String>(&j).unwrap(), s);
    }

    /// Valid inputs never reach a defensive code: random sequences of owner / device / callback
    /// calls with valid arguments (orders, automation install / rotate / revoke / clear and their
    /// callbacks, caps, destinations, views) either succeed or fail with a policy code.
    #[test]
    fn inv69_valid_sequences_never_reach_defensive_codes(ops in proptest::collection::vec((0u8..12, 0u8..4, any::<bool>()), 1..40)) {
        let mut c = new_account();
        let mut t = T0 + 1;
        for (op, k, flag) in ops {
            t += 1;
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match op {
                0 => { ctx(me().as_str(), 0, 10 * NEAR, t); c.place_order(a("wrap.near"), a("meme.near"), U128(NEAR), U128(5), "{}".into(), U64(t + 3_600 * NS_PER_SEC), vec![a("v2.ref-finance.near")]); }
                1 => { ctx(me().as_str(), 0, 10 * NEAR, t); c.cancel_order(U64(k as u64 + 1)); }
                2 => { owner_ctx(t); c.owner_set_automation_key(pk(k + 1), U128(NEAR)); }
                3 => { key_cb(if flag { PromiseResult::Successful(vec![]) } else { PromiseResult::Failed }); c.on_automation_set(pk(k + 1), None, Some(flag)); }
                4 => { owner_ctx(t); c.owner_revoke_automation(); }
                5 => { key_cb(if flag { PromiseResult::Successful(vec![]) } else { PromiseResult::Failed }); c.on_relayer_key_deleted(pk(k + 1)); }
                6 => { owner_ctx(t); c.owner_clear_relayer_key(pk(k + 1)); }
                7 => { key_cb(if flag { PromiseResult::Successful(vec![]) } else { PromiseResult::Failed }); c.on_relayer_key_cleared(pk(k + 1)); }
                8 => { owner_ctx(t); c.owner_set_caps(caps((k as u128 + 1) * NEAR, (k as u128 + 2) * NEAR)); }
                9 => { ctx(me().as_str(), 0, 10 * NEAR, t); c.lower_caps(caps(NEAR, 2 * NEAR)); }
                10 => { owner_ctx(t); c.owner_remove_key(pk(k + 1)); }
                _ => { ctx(me().as_str(), 0, 10 * NEAR, t); let _ = (c.get_relayer_keys(), c.get_orders(), c.get_pending_caps(), c.get_config(), c.get_relayer_week(), c.get_init_registration()); }
            }));
            if let Err(e) = r {
                let m = e.downcast_ref::<String>().cloned().unwrap_or_default();
                prop_assert!(!DEFENSIVE.iter().any(|d| m.contains(&format!("\"{d}\""))), "op {} reached a defensive code: {}", op, m);
            }
        }
        // migrate over the resulting (valid) state never fails either
        near_sdk::env::state_write(&c);
        ctx(me().as_str(), 0, 10 * NEAR, t + 1);
        let _ = TradingAccount::migrate();
    }
}

// ---------------- owner setter events (MATURITY) ----------------

#[test]
fn v145_owner_setters_emit_old_and_new() {
    let mut c = new_account();
    owner_ctx(T0 + 1);
    c.owner_set_relayer_allowance(U128(3 * NEAR));
    let ev = |name: &str| {
        get_logs().into_iter().find(|l| l.contains(&format!("\"event\":\"{name}\""))).unwrap_or_default()
    };
    assert!(
        ev("relayer_allowance_set").contains(&format!(
            // v1.4.8: no default allowance: old = null
            "\"old_weekly_yocto\":null,\"new_weekly_yocto\":\"{}\"",
            3 * NEAR
        )),
        "{:?}",
        get_logs()
    );
    owner_ctx(T0 + 2);
    c.owner_set_withdraw_cap(Some(U128(7)), None);
    let e = ev("withdraw_cap_set");
    assert!(
        e.contains("\"old_daily_cap_yocto\":null,\"new_daily_cap_yocto\":\"7\"")
            && e.contains("\"old_daily_cap_usd\":null,\"new_daily_cap_usd\":null"), // v1.4.6: unset = null
        "{e}"
    );
    owner_ctx(T0 + 3);
    c.owner_set_withdraw_cap(None, Some(U128(5)));
    let e = ev("withdraw_cap_set");
    assert!(
        e.contains("\"old_daily_cap_yocto\":\"7\",\"new_daily_cap_yocto\":\"7\"")
            && e.contains("\"new_daily_cap_usd\":\"5\""),
        "{e}"
    );
    let key = "ed25519:reYaWhvwu8Jzo3WUM3zhn6VrhuMEF4eADL17qtRVifc".to_string();
    owner_ctx(T0 + 4);
    c.owner_set_oneclick_config(vec![key.clone()], 100, None, None);
    let e = ev("oneclick_config_set");
    assert!(
        e.contains("\"old\":null")
            && e.contains(&format!("\"new\":{{\"keys\":[\"{key}\"],\"max_slippage_bps\":100")),
        "{e}"
    );
    owner_ctx(T0 + 5);
    c.owner_set_oneclick_config(vec![key.clone()], 200, None, Some(60));
    let e = ev("oneclick_config_set");
    assert!(
        e.contains("\"old\":{\"keys\"")
            && e.contains("\"max_slippage_bps\":200")
            && e.contains("\"max_loss_bps\":60"),
        "{e}"
    );
}
