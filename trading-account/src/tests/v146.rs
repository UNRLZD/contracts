//! v1.4.6 regressions (docs/audit/tob-contracts-v145-reaudit.md; RA6-1 from tob-contracts-v146-reaudit.md). Each
//! test fails on 16ad536 (v1.4.5); v146_ra6_1 fails with the RA5-4 binding filter removed.
use super::*;

fn owner_ctx(now: u64) {
    ctx("owner.near", 1, 10 * NEAR, now);
}

fn upgrade_at(c: &TradingAccount, now: u64) -> TradingAccount {
    near_sdk::env::state_write(c);
    ctx(me().as_str(), 0, 10 * NEAR, now);
    TradingAccount::migrate()
}

// ---------------- RA5-1 (Low) ----------------

/// A matured raise with no base (requested under v1.4.3/v1.4.4 code) after the caps were
/// lowered under older code: re-armed as in v1.4.4, never applied at once.
#[test]
fn v146_ra5_1_matured_raise_without_base_rearmed() {
    let mut c = new_account();
    owner_ctx(T0 + 1);
    c.owner_set_caps(caps(100 * NEAR, 200 * NEAR));
    near_sdk::env::storage_remove(b"cb"); // written by v1.4.3/v1.4.4 code: no base
    c.caps = caps(NEAR / 2, NEAR); // a device lower_caps under <= v1.4.2 code
    let later = T0 + 2 * CAPS_RAISE_DELAY_NS;
    let c = upgrade_at(&c, later);
    assert_eq!(c.get_config().caps, caps(NEAR / 2, NEAR), "the device's lower was undone");
    assert_eq!(c.get_pending_caps().expect("re-armed").active_at_ns.0, later + CAPS_RAISE_DELAY_NS);
}

// ---------------- RA5-4 (Info) ----------------

/// A stale base in the v1.4.5 format (left by v1.4.3/v1.4.4 sync or cancel after a downgrade)
/// that happens to equal the current caps must not make a newer, base-less raise apply.
#[test]
fn v146_ra5_4_stale_base_equal_by_coincidence_not_applied() {
    let mut c = new_account();
    owner_ctx(T0 + 1);
    c.owner_set_caps(caps(100 * NEAR, 200 * NEAR));
    // v1.4.4 code rewrote the raise (no base) and left a v1.4.5 base equal to today's caps
    near_sdk::env::storage_write(b"cb", &near_sdk::borsh::to_vec(&caps(2 * NEAR, 5 * NEAR)).unwrap());
    let later = T0 + 2 * CAPS_RAISE_DELAY_NS;
    let c = upgrade_at(&c, later);
    assert_eq!(c.get_config().caps, caps(2 * NEAR, 5 * NEAR));
    assert!(c.get_pending_caps().is_some(), "re-armed, not applied");
    assert!(!near_sdk::env::storage_has_key(b"cb"), "stale base dropped");
}

/// With no raise pending, a leftover base is removed by migrate; a bound base survives a re-arm
/// and still cancels the raise if the caps change before the next upgrade.
#[test]
fn v146_ra5_4_base_bound_to_its_raise() {
    let c = new_account();
    near_sdk::env::storage_write(b"cb", &near_sdk::borsh::to_vec(&caps(1, 1)).unwrap());
    let _ = upgrade_at(&c, T0 + 1);
    assert!(!near_sdk::env::storage_has_key(b"cb"));
    let mut c = new_account();
    owner_ctx(T0 + 1);
    c.owner_set_caps(caps(100 * NEAR, 200 * NEAR));
    let mut c = upgrade_at(&c, T0 + 2); // pending: re-armed, base re-bound
    assert!(c.get_pending_caps().is_some());
    c.caps = caps(NEAR / 2, NEAR); // older code lowers them before the next upgrade
    let c = upgrade_at(&c, T0 + 3 * CAPS_RAISE_DELAY_NS);
    assert!(c.get_pending_caps().is_none(), "cancelled");
    assert_eq!(c.get_config().caps, caps(NEAR / 2, NEAR));
}

// ---------------- RA5-2 (Low) ----------------

/// A v1.4.0-layout 1Click config (no max_loss_bps) can still be overwritten by the owner.
#[test]
fn v146_ra5_2_setter_overwrites_legacy_oneclick_layout() {
    let mut c = new_account();
    let key = "ed25519:reYaWhvwu8Jzo3WUM3zhn6VrhuMEF4eADL17qtRVifc".to_string();
    let legacy = near_sdk::borsh::to_vec(&(vec![key.clone()], 100u16, a("intents.near"))).unwrap();
    near_sdk::env::storage_write(b"1c", &legacy);
    owner_ctx(T0 + 1);
    c.owner_set_oneclick_config(vec![key], 200, None, None);
    assert!(get_logs().iter().any(|l| l.contains("oneclick_config_set") && l.contains("\"old\":null")));
    assert_eq!(c.get_oneclick_config().unwrap().max_slippage_bps, 200);
}

// ---------------- RA5-7 (Info) ----------------

/// `withdraw_cap_set`: an unset cap is null for both the yocto and the USD cap.
#[test]
fn v146_ra5_7_withdraw_cap_event_null_when_unset() {
    let mut c = new_account();
    owner_ctx(T0 + 1);
    c.owner_set_withdraw_cap(None, Some(U128(5)));
    let e = get_logs().into_iter().find(|l| l.contains("withdraw_cap_set")).unwrap();
    assert!(
        e.contains("\"old_daily_cap_yocto\":null,\"new_daily_cap_yocto\":null")
            && e.contains("\"old_daily_cap_usd\":null,\"new_daily_cap_usd\":\"5\""),
        "{e}"
    );
}

/// RA6-1: the base must belong to the CURRENT raise. A v1.4.6 raise A leaves a base bound to A;
/// older code then replaces the pending raise with B (no base of its own). B matures; at the
/// upgrade it must be re-armed (not applied, not cancelled) and A's base dropped. Fails with the
/// `.filter(|(_, bound)| *bound == p)` line in `migrate` removed.
#[test]
fn v146_ra6_1_base_bound_to_replaced_raise_ignored() {
    let mut c = new_account();
    let before = c.get_config().caps;
    owner_ctx(T0 + 1);
    c.owner_set_caps(caps(100 * NEAR, 200 * NEAR)); // raise A, base bound to A
    let b = PendingCaps { caps: caps(300 * NEAR, 400 * NEAR), active_at_ns: U64(T0 + 5) };
    near_sdk::env::storage_write(b"cp", &near_sdk::borsh::to_vec(&b).unwrap()); // older code: raise B
    let later = T0 + 2 * CAPS_RAISE_DELAY_NS;
    let c = upgrade_at(&c, later);
    assert_eq!(c.caps, before, "raise B applied through A's base");
    let p = c.get_pending_caps().expect("B re-armed");
    assert_eq!((p.caps, p.active_at_ns.0), (caps(300 * NEAR, 400 * NEAR), later + CAPS_RAISE_DELAY_NS));
    assert!(!near_sdk::env::storage_has_key(b"cb"), "A's base dropped");
}
