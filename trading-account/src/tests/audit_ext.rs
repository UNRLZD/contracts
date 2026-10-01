//! External access/accounting audit 2026-10-01 (docs/audit/v160-ext-access-delta.md): F2, I1, I2
//! regressions. Each failed before its fix.
use super::*;
use crate::owner::OwnerOp;

fn withdraw_events() -> Vec<String> {
    get_logs().into_iter().filter(|l| l.contains("\"event\":\"owner_withdraw\"")).collect()
}

fn self_cb(result: PromiseResult) {
    testing_env!(
        VMContextBuilder::new()
            .current_account_id(me())
            .predecessor_account_id(me())
            .account_balance(NearToken::from_yoctonear(10 * NEAR))
            .storage_usage(STORAGE_BYTES)
            .build(),
        near_sdk::test_vm_config(),
        near_sdk::RuntimeFeesConfig::test(),
        Default::default(),
        vec![result],
    );
}

fn sent_to(to: &str) -> u128 {
    get_created_receipts()
        .iter()
        .filter(|r| r.receiver_id == a(to))
        .flat_map(|r| r.actions.iter())
        .map(|x| match x {
            MockAction::Transfer { deposit, .. } => deposit.as_yoctonear(),
            _ => 0,
        })
        .sum()
}

/// F2: native NEAR through `send(None, ..)` (owner_withdraw, the signed `withdraw` op,
/// owner_withdraw_home of a NEAR-wallet owner, device withdraw_to_owner) reports
/// `owner_withdraw{token: "near", amount, to, ok: true}`, like the wNEAR / FT / withdraw_all paths,
/// so the watcher's owner_withdraw_volume alert sees it.
#[test]
fn ext_native_owner_withdraw_emits_owner_withdraw_event() {
    let mut c = new_account();
    // control: the wNEAR path reports (after its unwrap callback)
    ctx("owner.near", 1, 10 * NEAR, T0 + 1);
    c.owner_withdraw(Some(a("wrap.near")), U128(NEAR), a("attacker.near"));
    self_cb(PromiseResult::Successful(vec![]));
    c.on_withdraw_one(a("wrap.near"), U128(NEAR), a("attacker.near"));
    assert_eq!(withdraw_events().len(), 1, "wNEAR withdraw reported");
    // native NEAR to an arbitrary destination (logs are per context: only this call's)
    ctx("owner.near", 1, 10 * NEAR, T0 + 2);
    c.owner_withdraw(None, U128(5 * NEAR), a("attacker.near"));
    assert_eq!(sent_to("attacker.near"), 5 * NEAR, "the transfer is scheduled");
    let ev = withdraw_events();
    assert_eq!(ev.len(), 1, "5 NEAR native owner_withdraw to attacker.near emitted no owner_withdraw event");
    assert!(
        ev[0].contains(&format!(
            r#""data":{{"token":"near","amount":"{}","to":"attacker.near","ok":true}}"#,
            5 * NEAR
        )),
        "{}",
        ev[0]
    );
    // the device's native withdraw_to_owner reports too
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 3);
    c.withdraw_to_owner(None, U128(NEAR));
    assert_eq!(sent_to("owner.near"), NEAR);
    assert!(withdraw_events().iter().any(|l| l.contains(r#""to":"owner.near","ok":true"#)));
}

/// F2: the signed door's envelope event names what an outflow moves and where (the first word stays
/// the op name the engine reads).
#[test]
fn ext_signed_outflow_summaries_name_amount_and_destination() {
    let w = OwnerOp::Withdraw { token: None, amount: U128(5), to: a("attacker.near") };
    assert_eq!(w.summary(), "withdraw 5 near to attacker.near");
    let w = OwnerOp::Withdraw { token: Some(a("usdc.near")), amount: U128(7), to: a("x.near") };
    assert_eq!(w.summary(), "withdraw 7 usdc.near to x.near");
    let h = OwnerOp::WithdrawHome { token: None, amount: U128(9) };
    assert_eq!(h.summary(), "withdraw_home 9 near");
    let v = OwnerOp::WithdrawViaIntents {
        token: a("wrap.near"),
        amount: U128(3),
        deposit_address: "ab".repeat(32),
    };
    assert_eq!(v.summary(), format!("withdraw_via_intents 3 wrap.near to {}", "ab".repeat(32)));
    // unchanged ops keep the bare name
    assert_eq!(OwnerOp::RotateSalt {}.summary(), "rotate_salt");
}

/// I1: `place_order` prunes an expired Chain order together with its `ov` record (its stored legs),
/// as `remove_order` does.
#[test]
fn ext_prune_removes_the_chain_order_via() {
    let mut c = new_account();
    let place = |c: &mut TradingAccount, now: u64, via: bool| -> U64 {
        let mut args = near_sdk::serde_json::json!({"token_in": "wrap.near", "token_out": "jensen.near",
            "amount_in": NEAR.to_string(), "min_out": "50", "trigger_meta": "",
            "expires_at_ns": (now + 3_600 * NS_PER_SEC).to_string(),
            "dexes": ["v2.ref-finance.near", "dclv2.ref-labs.near"]});
        if via {
            args["via"] = near_sdk::serde_json::json!({"q": "zec.omft.near", "leg1_dex": "v2.ref-finance.near",
                "leg2_dex": "dclv2.ref-labs.near", "min_mid": "100", "max_mid": "110"});
        }
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
        c.place_order(
            a("wrap.near"),
            a("jensen.near"),
            U128(NEAR),
            U128(50),
            String::new(),
            U64(now + 3_600 * NS_PER_SEC),
            vec![a("v2.ref-finance.near"), a("dclv2.ref-labs.near")],
        )
    };
    let id = place(&mut c, T0 + 1, true);
    assert!(c.get_order_via(id).is_some());
    // two hours later the device places any order: the expired Chain order is pruned
    place(&mut c, T0 + 7_200 * NS_PER_SEC, false);
    assert!(c.get_order(id).is_none(), "pruned");
    assert!(c.get_order_via(id).is_none(), "orphaned `ov` record of pruned order {} still stored", id.0);
}

/// I2: removing a device key reports `device_key_removed{public_key, ok}` from its callback, as
/// adding one reports `device_key_added`.
#[test]
fn ext_device_key_removal_is_reported() {
    let mut c = new_account();
    let pk: PublicKey = "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp".parse().unwrap();
    ctx("owner.near", 1, 10 * NEAR, T0 + 1);
    c.owner_remove_key(pk.clone());
    let rs = get_created_receipts();
    assert!(rs.iter().any(
        |r| r.receiver_id == me() && r.actions.iter().any(|x| matches!(x, MockAction::DeleteKey { .. }))
    ));
    assert!(
        rs.iter().any(|r| r.actions.iter().any(
            |x| matches!(x, MockAction::FunctionCallWeight { method_name, .. } if method_name == b"on_key_removed")
        )),
        "no on_key_removed callback"
    );
    for (res, ok) in [(PromiseResult::Successful(vec![]), true), (PromiseResult::Failed, false)] {
        self_cb(res);
        c.on_key_removed(pk.clone());
        let want = format!(
            r#""event":"device_key_removed","data":{{"public_key":"{}","ok":{ok}}}"#,
            String::from(&pk)
        );
        assert!(get_logs().iter().any(|l| l.contains(&want)), "{:?}", get_logs());
    }
}
