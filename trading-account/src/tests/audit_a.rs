//! External audit of v1.4.7 (docs/audit/external/UNRLZD-audit-report.md, Engagement A):
//! regressions built from the auditor's PoCs (study/unrlzd/poc/UNR-A-*). They use only entry
//! points and test helpers that exist in v1.4.7, so this file also runs (red) on the v1.4.7
//! source.
use super::*;
use near_sdk::serde_json::Value;

/// Replays the scheduled on_swap_settled with its real arguments (auditor's PoC helper).
fn settle_scheduled(c: &mut TradingAccount, result: PromiseResult) -> Value {
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
    args
}

/// Default caps (UNLIMITED), automation key, weekly allowance 1 NEAR (the PoC's setup).
fn poc_account() -> TradingAccount {
    ctx("tt.near", 0, NEAR, T0);
    near_sdk::mock::with_mocked_blockchain(|b| {
        b.take_storage();
    });
    ctx("tt.near", 0, NEAR, T0);
    let mut c = TradingAccount::init(
        a("owner.near"),
        FeeConfig { fee_bps: 100, fee_recipient: a("fees.near") },
        caps(UNLIMITED, UNLIMITED),
        vec![Dex { id: a("v2.ref-finance.near"), kind: DexKind::RheaClassic }],
        a("wrap.near"),
        None,
    );
    ctx("owner.near", 1, 10 * NEAR, T0);
    c.owner_set_automation_key(auto_pk(), U128(NEAR));
    automation_cb(&mut c, auto_pk(), true);
    ctx("owner.near", 1, 10 * NEAR, T0);
    c.owner_set_relayer_allowance(U128(NEAR));
    c
}

// ---------------- UNR-A-01 (Medium) ----------------

/// UNR-A-01: a relayer fire with an inflated msg min_out (990 NEAR on a 0.5 NEAR order) and a
/// token that reports full use paid bps(990 NEAR) = 9.9 NEAR to fee_recipient (v1.4.7). Fixed:
/// an order fire's sell fee is bps(the stored order's min_out).
#[test]
fn unr_a01_relayer_min_out_does_not_set_the_sell_fee() {
    let mut c = poc_account();
    let id = place_sell(&mut c, 1_000, NEAR / 2);
    ctx_pk(me().as_str(), Some(auto_pk()), 0, T0 + 2);
    c.execute_order(U64(id), order_sell_ops(1_000, 990 * NEAR));
    let args = settle_scheduled(&mut c, PromiseResult::Successful(b"\"1000\"".to_vec()));
    let paid = fee_paid();
    assert_eq!(args["fee"], (NEAR / 2 / 100).to_string(), "fee reserved from the order's min_out");
    assert_eq!(paid, NEAR / 2 / 100, "fee paid: 1% of the order's 0.5 NEAR, was 9.9 NEAR");
}

/// UNR-A-01, the same pattern on a DEVICE fire of an order (tab runner): the stored min_out too.
#[test]
fn unr_a01_device_order_fire_fee_from_stored_min_out() {
    let mut c = poc_account();
    let id = place_sell(&mut c, 1_000, NEAR / 2);
    exec_order(&mut c, id, order_sell_ops(1_000, 990 * NEAR));
    let args = settle_scheduled(&mut c, PromiseResult::Successful(b"\"1000\"".to_vec()));
    assert_eq!(args["fee"], (NEAR / 2 / 100).to_string());
    assert_eq!(fee_paid(), NEAR / 2 / 100);
}

/// UNR-A-01 re-check of the buy path: a limit buy's fee is bps(amount_in) (the order's input,
/// bound by check_order_swap), whatever min_out the firing key writes.
#[test]
fn unr_a01_limit_buy_fee_independent_of_msg_min_out() {
    let mut c = poc_account();
    ctx("owner.near", 1, 10 * NEAR, T0);
    c.owner_set_relayer_allowance(U128(10 * NEAR));
    let id = place_buy(&mut c, NEAR, 5);
    ctx_pk(me().as_str(), Some(auto_pk()), 0, T0 + 2);
    c.execute_order(U64(id), order_buy_ops(NEAR, 10u128.pow(30)));
    let args = settle_scheduled(&mut c, ok_json(NEAR));
    assert_eq!(args["fee"], (NEAR / 100).to_string());
    assert_eq!(fee_paid(), NEAR / 100);
}
// ---------------- UNR-A-02 (Low) ----------------

/// UNR-A-02: a relayer fire with an unreachable min_out made an honest token resolve to "0"
/// (Successful) and the SELL order was deleted (v1.4.7). Fixed: a Successful "0" reopens the
/// order; the weekly allowance keeps the floor (v1.4.9, UNR-A-09: the rest comes back).
#[test]
fn unr_a02_relayer_cannot_delete_a_sell_order() {
    let amt = 10u128.pow(24);
    let mut c = with_automation();
    ctx("owner.near", 1, 10 * NEAR, T0);
    c.owner_set_relayer_allowance(U128(10 * NEAR));
    let id = place_sell(&mut c, amt, NEAR);
    relayer_fire(&mut c, id, amt, 100 * NEAR, T0 + 2);
    settle_scheduled(&mut c, ok_json(0));
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 4);
    let o = c.get_order(U64(id)).expect("order still stored");
    assert!(!o.pending, "reopened");
    // v1.4.9 (UNR-A-09): like a Failed fire, only the allowance / 20 floor stays charged
    assert_eq!(c.get_relayer_week().spent_yocto.0, 10 * NEAR / 20, "the floor stays charged");
    // the device (tab runner) can still fire the stop-loss
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 5);
    c.execute_order(U64(id), order_sell_ops(amt, NEAR));
    assert!(c.get_order(U64(id)).unwrap().pending);
}

/// UNR-A-02 repetition: 40 such fires delete nothing (v1.4.7: >= 10 orders a week).
#[test]
fn unr_a02_relayer_mass_fires_delete_nothing() {
    let amt = 10u128.pow(24);
    let mut c = with_automation();
    let mut ids = vec![];
    for _ in 0..40 {
        let id = place_sell(&mut c, amt, 1);
        ids.push(id);
        ctx_pk(me().as_str(), Some(auto_pk()), 0, T0 + 2);
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            c.execute_order(U64(id), order_sell_ops(amt, 100 * NEAR))
        }))
        .is_err()
        {
            break;
        }
        settle_scheduled(&mut c, ok_json(0));
    }
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 4);
    let deleted = ids.iter().filter(|id| c.get_order(U64(**id)).is_none()).count();
    assert_eq!(deleted, 0, "orders deleted by unproven refunds");
}

// ---------------- UNR-A-05 (Info) ----------------

/// UNR-A-05: PlachWithdraw / PlachRegisterAssets accepted `nep141:<self>` (v1.4.7), unlike the
/// other ops' `token == self` rule. Now E_BAD_OP.
#[test]
fn unr_a05_plach_asset_naming_self_refused() {
    let self_asset = format!("nep141:{}", me());
    let mut c = new_account();
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
    let ops =
        vec![Op::PlachWithdraw { dex: a("dex.intear.near"), asset_id: self_asset.clone(), amount: None }];
    assert_eq!(panics(std::panic::AssertUnwindSafe(|| exec(&mut c, ops, "w", NEAR))), "E_BAD_OP");
    let mut c = new_account();
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
    let ops = vec![Op::PlachRegisterAssets {
        dex: a("dex.intear.near"),
        asset_ids: vec!["nep141:usdc.near".into(), self_asset],
    }];
    assert_eq!(panics(std::panic::AssertUnwindSafe(|| exec(&mut c, ops, "r", NEAR))), "E_BAD_OP");
    // other assets still pass
    let mut c = new_account();
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
    let ops = vec![Op::PlachRegisterAssets {
        dex: a("dex.intear.near"),
        asset_ids: vec!["nep141:usdc.near".into()],
    }];
    exec(&mut c, ops, "ok", NEAR);
}

// ---------------- UNR-A-06 (Info) ----------------

/// UNR-A-06: owner-path intents markers shared the device bound (128) but live 7 days, so the
/// 129th owner_withdraw_via_intents in a week was E_QUOTES_FULL (v1.4.7). Now the owner space has
/// its own bound of 512 (still a bound: the 513th in a week is refused).
#[test]
fn unr_a06_owner_intents_markers_own_bound() {
    // mock storage_usage is per-context: give the growing marker list a realistic figure
    let owner_at = |now: u64| {
        testing_env!(VMContextBuilder::new()
            .current_account_id(me())
            .predecessor_account_id(a("owner.near"))
            .attached_deposit(NearToken::from_yoctonear(1))
            .account_balance(NearToken::from_yoctonear(100 * NEAR))
            .storage_usage(100_000)
            .block_timestamp(now)
            .prepaid_gas(Gas::from_tgas(300))
            .build());
    };
    let mut c = new_account();
    for n in 0..512u64 {
        owner_at(T0 + n);
        c.owner_withdraw_via_intents(a("usdc.near"), U128(5), format!("{n:064x}"));
    }
    owner_at(T0 + 600);
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| c.owner_withdraw_via_intents(
            a("usdc.near"),
            U128(5),
            format!("{:064x}", 9_999)
        ))),
        "E_QUOTES_FULL"
    );
}
