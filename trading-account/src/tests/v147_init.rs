//! v1.4.7: `init` installs an automation key passed by the factory (one-signature onboarding).
use super::*;

fn init_with(auto: Option<AutomationInit>) -> TradingAccount {
    ctx("tt.near", 0, NEAR, T0);
    near_sdk::mock::with_mocked_blockchain(|b| {
        b.take_storage();
    });
    ctx("tt.near", 0, NEAR, T0);
    TradingAccount::init(
        a("owner.near"),
        FeeConfig { fee_bps: 100, fee_recipient: a("fees.near") },
        caps(UNLIMITED, UNLIMITED),
        vec![Dex { id: a("v2.ref-finance.near"), kind: DexKind::RheaClassic }],
        a("wrap.near"),
        auto,
    )
}

#[test]
fn v147_init_installs_automation_key_through_role_set() {
    let mut c = init_with(Some(AutomationInit {
        public_key: auto_pk(),
        allowance: U128(NEAR),
        weekly_yocto: Some(U128(4 * NEAR)),
    }));
    // in the role set BEFORE its AddKey lands; marked in flight; not stored yet (A1-F2)
    assert_eq!(c.get_relayer_keys(), vec![auto_pk()]);
    assert_eq!(c.get_automation_key(), None);
    assert!(near_sdk::env::storage_has_key(b"ai"));
    let rs = get_created_receipts();
    let add = rs.iter().flat_map(|r| r.actions.iter()).find(|x| format!("{x:?}").starts_with("AddKey"));
    let add = format!("{:?}", add.expect("AddKey scheduled"));
    assert!(add.contains("execute_order") && !add.contains("execute,"), "{add}");
    ctx(me().as_str(), 0, NEAR, T0 + 1);
    assert_eq!(c.get_relayer_week().allowance_yocto, Some(U128(4 * NEAR)));
    assert_eq!(c.get_config().caps, caps(UNLIMITED, UNLIMITED));
    // the callback stores it, as for owner_set_automation_key
    testing_env!(
        VMContextBuilder::new().current_account_id(me()).predecessor_account_id(me()).build(),
        near_sdk::test_vm_config(),
        near_sdk::RuntimeFeesConfig::test(),
        Default::default(),
        vec![PromiseResult::Successful(vec![])],
    );
    c.on_automation_set(auto_pk(), None, Some(true));
    assert_eq!(c.get_automation_key(), Some(auto_pk()));
    assert!(!near_sdk::env::storage_has_key(b"ai"));
}

#[test]
fn v147_init_rejects_small_automation_allowance_and_none_installs_nothing() {
    let r = panics(|| {
        init_with(Some(AutomationInit {
            public_key: auto_pk(),
            allowance: U128(NEAR / 10),
            weekly_yocto: None,
        }));
    });
    assert_eq!(r, "E_ALLOWANCE");
    let c = init_with(None);
    assert!(c.get_relayer_keys().is_empty());
    assert!(!get_created_receipts()
        .iter()
        .flat_map(|r| r.actions.iter())
        .any(|x| format!("{x:?}").starts_with("AddKey")));
}
