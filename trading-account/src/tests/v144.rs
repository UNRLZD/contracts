//! v1.4.4 regressions (docs/audit/tob-contracts-v143-reaudit.md). Each test fails on 0c166d8.
use super::*;

fn pk(i: u8) -> PublicKey {
    format!("ed25519:{}", near_sdk::bs58::encode([i; 32]).into_string()).parse().unwrap()
}

fn owner_ctx(now: u64) {
    ctx("owner.near", 1, 10 * NEAR, now);
}

fn remove(c: &mut TradingAccount, k: PublicKey) -> String {
    owner_ctx(T0 + 1);
    panics(std::panic::AssertUnwindSafe(|| c.owner_remove_key(k)))
}

// ---------------- RA-1 (Low) ----------------

/// [owner_set_automation_key(A), owner_remove_key(A)]: the remove of a pending install is refused
/// (the batch reverts), as is removing a key whose retirement is in flight.
#[test]
fn v144_ra1_remove_of_non_current_member_is_busy() {
    let mut c = new_account();
    owner_ctx(T0 + 1);
    c.owner_set_automation_key(pk(3), U128(NEAR));
    assert_eq!(remove(&mut c, pk(3)), "E_AUTOMATION_BUSY");
    // install confirmed: now it's the current key and goes through the revoke path
    key_cb(PromiseResult::Successful(vec![]));
    c.on_automation_set(pk(3), None, Some(true));
    owner_ctx(T0 + 2);
    c.owner_remove_key(pk(3));
    assert_eq!(c.get_automation_key(), None);
    assert_eq!(c.get_relayer_keys(), vec![pk(3)]);
    // its DeleteKey is in flight: removing it again is refused too
    assert_eq!(remove(&mut c, pk(3)), "E_AUTOMATION_BUSY");
    // an ordinary (device) key is still removable
    owner_ctx(T0 + 3);
    c.owner_remove_key(pk(9));
    assert!(format!("{:?}", get_created_receipts()[0].actions[0]).starts_with("DeleteKey"));
}

// ---------------- SC-8 (Low) ----------------

/// A stuck entry (a key that never existed, e.g. a legacy `ak` whose AddKey failed) blocks
/// installs; owner_clear_relayer_key drops it only after the chain's DeleteKey proves it absent.
#[test]
fn v144_sc8_stuck_entry_cleared_by_chain_proof() {
    let mut c = new_account();
    // stuck: in the set, not the current key, its DeleteKey already failed
    near_sdk::env::storage_write(b"ar", &near_sdk::borsh::to_vec(&vec![pk(5)]).unwrap());
    owner_ctx(T0 + 1);
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| c.owner_set_automation_key(pk(6), U128(NEAR)))),
        "E_AUTOMATION_BUSY"
    );
    // guards: non-member, current key, install in flight
    owner_ctx(T0 + 1);
    assert_eq!(panics(std::panic::AssertUnwindSafe(|| c.owner_clear_relayer_key(pk(7)))), "E_NO_KEY");
    owner_ctx(T0 + 1);
    c.owner_clear_relayer_key(pk(5));
    let rs = get_created_receipts();
    assert!(format!("{:?}", rs[0].actions[0]).starts_with("DeleteKey"), "{rs:?}");
    assert_eq!(c.get_relayer_keys(), vec![pk(5)], "stays until the chain answers");
    key_cb(PromiseResult::Failed); // DeleteKeyDoesNotExist
    c.on_relayer_key_cleared(pk(5));
    assert!(c.get_relayer_keys().is_empty());
    assert!(get_logs().iter().any(|l| l.contains("relayer_key_cleared") && l.contains("\"existed\":false")));
    owner_ctx(T0 + 2);
    c.owner_set_automation_key(pk(6), U128(NEAR));
    assert_eq!(c.get_relayer_keys(), vec![pk(6)]);
    // an install in flight can't be cleared
    owner_ctx(T0 + 3);
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| c.owner_clear_relayer_key(pk(6)))),
        "E_AUTOMATION_BUSY"
    );
    key_cb(PromiseResult::Successful(vec![]));
    c.on_automation_set(pk(6), None, Some(true));
    // nor the current key
    owner_ctx(T0 + 4);
    assert_eq!(panics(std::panic::AssertUnwindSafe(|| c.owner_clear_relayer_key(pk(6)))), "E_AUTOMATION_KEY");
}

// ---------------- RA-3 (Info) ----------------

/// A raise pending across a downgrade + re-upgrade is re-armed by migrate, never applied at once.
#[test]
fn v144_ra3_migrate_rearms_pending_raise() {
    let mut c = new_account();
    owner_ctx(T0 + 1);
    c.owner_set_caps(caps(100 * NEAR, 200 * NEAR));
    // (older code runs meanwhile and can't see or cancel it); re-upgrade 30 min later.
    // v1.4.5: a raise that already matured is applied instead (tests/v145.rs).
    let later = T0 + CAPS_RAISE_DELAY_NS / 2;
    near_sdk::env::state_write(&c);
    ctx(me().as_str(), 0, 10 * NEAR, later);
    let c = TradingAccount::migrate();
    assert_eq!(c.get_config().caps, caps(2 * NEAR, 5 * NEAR), "not applied at once");
    let p = c.get_pending_caps().expect("still pending");
    assert_eq!(p.active_at_ns.0, later + CAPS_RAISE_DELAY_NS);
    assert!(get_logs().iter().any(|l| l.contains("caps_raise_pending")));
}
