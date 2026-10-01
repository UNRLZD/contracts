//! F1 (gas refunds are not pad refunds) + `Settle::NearInFull`: the pure fee math and the native
//! `on_curve_settled` path with a mocked promise result and balance.
use super::settle::{self, curve_fee};
use super::*;
use crate::policy::{bps, utc_day_start};
use crate::{Caps, FeeConfig, Order, SettleArgs, TradingAccount, GAS_PRICE_BOUND};
use near_sdk::mock::MockAction;
use near_sdk::test_utils::{get_created_receipts, get_logs, VMContextBuilder};
use near_sdk::{testing_env, Gas, NearToken, PromiseResult};

const NEAR: u128 = 1_000_000_000_000_000_000_000_000;
const T0: u64 = 1_800_000_000_000_000_000;
const STORAGE_BYTES: u64 = 1_000;
const LOCKED: u128 = STORAGE_BYTES as u128 * 10_000_000_000_000_000_000;
const F: u128 = NEAR / 100; // reserved fee on a 1 N buy at 100 bps

fn a(s: &str) -> AccountId {
    s.parse().unwrap()
}

fn builder(balance: u128, prepaid_tgas: u64) -> VMContextBuilder {
    let mut b = VMContextBuilder::new();
    b.current_account_id(a("user.tt.near"))
        .predecessor_account_id(a("user.tt.near"))
        .signer_account_id(a("user.tt.near"))
        .account_balance(NearToken::from_yoctonear(balance))
        .block_timestamp(T0)
        .storage_usage(STORAGE_BYTES)
        .prepaid_gas(Gas::from_tgas(prepaid_tgas));
    b
}

fn account() -> TradingAccount {
    testing_env!(builder(10 * NEAR, 300).build());
    near_sdk::mock::with_mocked_blockchain(|b| {
        b.take_storage();
    });
    testing_env!(builder(10 * NEAR, 300).build());
    TradingAccount::init(
        a("owner.near"),
        FeeConfig { fee_bps: 100, fee_recipient: a("fees.near") },
        Caps { max_trade_yocto: U128(2 * NEAR), daily_cap_yocto: U128(5 * NEAR) },
        vec![Dex { id: a("nearrr-fun.near"), kind: DexKind::FactoryCurve(FactoryPad::Nearrr) }],
        a("wrap.near"),
        None,
        None,
        None,
    )
}

fn settle_args(order_id: Option<u64>) -> SettleArgs {
    SettleArgs {
        client_order_id: "c1".into(),
        amount: U128(NEAR),
        counted: U128(NEAR),
        fee: U128(F),
        day_start: U64(utc_day_start(T0)),
        order_id: order_id.map(U64),
        relayer_week: None,
        relayer_counted: None,
        proof: Some("curve_near".into()),
        relayer_gas: None,
    }
}

/// Runs `on_curve_settled` with the balance showing `arrived` more than at the end of `run`.
fn settle_with(
    c: &mut TradingAccount,
    mode: &str,
    arrived: u128,
    allowance: Option<u128>,
    order: Option<u64>,
) {
    let before = 5 * NEAR;
    testing_env!(
        builder(LOCKED + before + arrived, 10).build(),
        near_sdk::test_vm_config(),
        near_sdk::RuntimeFeesConfig::test(),
        Default::default(),
        vec![PromiseResult::Successful(b"\"7\"".to_vec())],
    );
    c.on_curve_settled(settle_args(order), U128(before), mode.into(), U128(NEAR / 2), allowance.map(U128));
}

fn fee_paid() -> u128 {
    get_created_receipts()
        .iter()
        .filter(|r| r.receiver_id == a("fees.near"))
        .flat_map(|r| r.actions.iter())
        .map(|x| match x {
            MockAction::Transfer { deposit, .. } => deposit.as_yoctonear(),
            _ => 0,
        })
        .sum()
}

const ALLOW: u128 = 300 * 1_000_000_000_000 * GAS_PRICE_BOUND; // 300 TGas at the bound = 0.06 N

#[test]
fn callback_carries_the_gas_allowance() {
    testing_env!(builder(10 * NEAR, 300).build());
    assert_eq!(settle::gas_allowance(), ALLOW);
    let (m, args, _) = settle::callback(Settle::NearInFull, "{}", 1, 2);
    assert_eq!(m, "on_curve_settled");
    let v: near_sdk::serde_json::Value = near_sdk::serde_json::from_str(&args).unwrap();
    assert_eq!(v["gas_allowance"], ALLOW.to_string());
    assert_eq!(v["mode"], "near_in_full");
    assert_eq!(Settle::NearInFull.proof(), "curve_near");
    assert!(Settle::NearInFull.measured());
}

/// V16-02: NearInFull never reads a delta: any inflow is a fill with the full fee.
#[test]
fn near_in_full_math_ignores_any_inflow() {
    for delta in [0, NEAR / 2, NEAR - NEAR / 100, NEAR, 3 * NEAR] {
        assert_eq!(curve_fee("near_in_full", NEAR, F, 100, delta, 0), (NEAR, F), "{delta}");
    }
}

/// Gas refunds only (delta = the allowance): NearIn charges the full fee, a native sell charges 0.
#[test]
fn gas_refund_only_is_not_a_refund_or_payout() {
    let mut c = account();
    settle_with(&mut c, "near_in", ALLOW, Some(ALLOW), None);
    assert_eq!(fee_paid(), F, "near_in: no pad refund -> full fee");
    let mut c = account();
    settle_with(&mut c, "near_out", ALLOW, Some(ALLOW), None);
    assert_eq!(fee_paid(), 0, "near_out: nothing arrived beyond gas refunds -> no fee");
    // pre-F1 in-flight callback (no allowance): the old measurement
    let mut c = account();
    settle_with(&mut c, "near_in", ALLOW, None, None);
    assert_eq!(fee_paid(), crate::policy::mul_div(F, NEAR - ALLOW, NEAR));
}

#[test]
fn near_in_real_refund_and_payout_exact() {
    // a real 0.25 N refund on top of the gas refunds
    let mut c = account();
    settle_with(&mut c, "near_in", ALLOW + NEAR / 4, Some(ALLOW), None);
    assert_eq!(fee_paid(), F * 3 / 4);
    // a 0.3 N native payout (cap = 0.5 N min_out bound)
    let mut c = account();
    settle_with(&mut c, "near_out", ALLOW + 3 * NEAR / 10, Some(ALLOW), None);
    assert_eq!(fee_paid(), bps(3 * NEAR / 10, 100));
}

/// V16-02: a NearInFull buy (dragonpad, Nira, Vista DEX) whose settle sees a big inflow (an unwrap in
/// the same execute, a concurrent sell payout) is still a fill: full fee, spend kept, the order
/// consumed. Only a failed receipt reopens it.
#[test]
fn near_in_full_inflow_never_returns_spend() {
    let order = |pending| Order {
        token_in: a("wrap.near"),
        token_out: a("ember.dragonpad.near"),
        amount_in: U128(NEAR),
        min_out: U128(5),
        trigger_meta: String::new(),
        expires_at_ns: U64(T0 + 1_000_000_000_000),
        dexes: vec![a("dragonpad.near")],
        pending,
    };
    let mut c = account();
    crate::save_order(7, &order(true));
    c.day.spent_yocto = NEAR + F;
    settle_with(&mut c, "near_in_full", ALLOW + NEAR + NEAR / 10, Some(ALLOW), Some(7));
    assert_eq!(fee_paid(), F);
    assert!(c.get_order(U64(7)).is_none(), "consumed, not reopened");
    assert!(!get_logs().iter().any(|l| l.contains("order_reopened")));
    assert_eq!(c.day.spent_yocto, NEAR + F, "spend kept");
}

/// Mocked callback context: `results` in, liquid balance `liquid`.
fn cb(liquid: u128, results: Vec<PromiseResult>) {
    testing_env!(
        // the mock charges more for its own work than the real callbacks (sandbox-measured)
        builder(LOCKED + liquid, 300).build(),
        near_sdk::test_vm_config(),
        near_sdk::RuntimeFeesConfig::test(),
        Default::default(),
        results,
    );
}

fn calls_to(receiver: &str) -> Vec<(u128, String)> {
    get_created_receipts()
        .iter()
        .filter(|r| r.receiver_id == a(receiver))
        .flat_map(|r| r.actions.iter())
        .filter_map(|x| match x {
            MockAction::FunctionCallWeight { method_name, args, attached_deposit, .. } => Some((
                attached_deposit.as_yoctonear(),
                format!("{}:{}", String::from_utf8_lossy(method_name), String::from_utf8_lossy(args)),
            )),
            _ => None,
        })
        .collect()
}

const TOK: &str = "arcova-m6ez.nearrr-fun.near";

#[test]
fn nearrr_tax_callback_reads_the_token_balance_first() {
    let mut c = account();
    cb(5 * NEAR, vec![PromiseResult::Successful(br#"{"mode":"Tax","buy_tax_bps":100}"#.to_vec())]);
    c.on_nearrr_tax(settle_args(None), U128(9_800), 0, "arcova-m6ez".into());
    // nothing to the pad yet, no NEAR attached: the before-balance view on the token
    assert!(calls_to("nearrr-fun.near").is_empty());
    let v = calls_to(TOK);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].0, 0);
    assert!(v[0].1.starts_with("ft_balance_of:") && v[0].1.contains("user.tt.near"), "{}", v[0].1);
    // 1% tax + 1% platform: ceil(9_800 / 0.98) = 10_000 carried to the next step
    let next = calls_to("user.tt.near");
    assert!(
        next.iter().any(|(_, x)| x.starts_with("on_nearrr_before:") && x.contains(r#""pad_min":"10000""#)),
        "{next:?}"
    );
    // an unreadable tax view (unparsable): refused, nothing scheduled
    let mut c = account();
    cb(5 * NEAR, vec![PromiseResult::Successful(b"not json".to_vec())]);
    crate::chain::lock(TOK, &crate::venues::factory::lock_holder("c1"));
    c.on_nearrr_tax(settle_args(None), U128(9_800), 0, "arcova-m6ez".into());
    assert!(calls_to(TOK).is_empty() && calls_to("nearrr-fun.near").is_empty());
    assert!(crate::chain::lock_of(TOK).is_none(), "R2-05: a refused buy releases its lock");
    assert!(get_logs().iter().any(|l| l.contains("\"settled\"") && l.contains("\"used\":\"0\"")));
}

/// R2-06 owner rule on the Nearrr CURVE path (= the order-fire gate, venues/tax.rs): a failed
/// `tax_state` receipt reads 0 (pad_min = min_out); a result up to 16 KiB is read (was 2 KiB); over
/// 16 KiB, unparsable / an unknown mode, or a total buy tax over 11% refuses (lock released).
#[test]
fn r2_06_nearrr_curve_tax_view_rules() {
    // (view result, Some(pad_min) = the buy goes on, None = refused)
    let pad = |r: PromiseResult| -> Option<String> {
        let mut c = account();
        cb(5 * NEAR, vec![r]);
        crate::chain::lock(TOK, &crate::venues::factory::lock_holder("c1"));
        c.on_nearrr_tax(settle_args(None), U128(9_800), 0, "arcova-m6ez".into());
        let next = calls_to("user.tt.near");
        let go = next.iter().find(|(_, x)| x.starts_with("on_nearrr_before:")).map(|(_, x)| {
            let i = x.find("\"pad_min\":\"").unwrap() + 11;
            x[i..i + x[i..].find('"').unwrap()].to_string()
        });
        if go.is_none() {
            assert!(calls_to(TOK).is_empty() && calls_to("nearrr-fun.near").is_empty());
            assert!(crate::chain::lock_of(TOK).is_none(), "R2-05: a refused buy releases its lock");
            assert!(get_logs().iter().any(|l| l.contains("nearrr_tax_refused")));
        } else {
            assert_eq!(crate::chain::lock_of(TOK).map(|x| x.0), Some("nearrr:c1".to_string()), "lock kept");
        }
        go
    };
    let ok = |v: &[u8]| PromiseResult::Successful(v.to_vec());
    // a failed receipt (no tax_state, a panic, out of gas): 0 -> pad_min = min_out
    assert_eq!(pad(PromiseResult::Failed).as_deref(), Some("9800"));
    // a valid view between the old 2 KiB and 16 KiB is read: 1% + 1% platform -> 10_000
    let mut mid = br#"{"mode":"Tax","buy_tax_bps":100,"sell_tax_bps":100}"#.to_vec();
    mid.resize(4_096, b' ');
    assert_eq!(pad(ok(&mid)).as_deref(), Some("10000"));
    mid.resize(crate::venues::tax::MAX_VIEW_LEN, b' ');
    assert_eq!(pad(ok(&mid)).as_deref(), Some("10000"));
    // over 16 KiB: refused
    mid.push(b' ');
    assert_eq!(pad(ok(&mid)), None);
    // unparsable / an unknown mode: refused
    assert_eq!(pad(ok(b"not json")), None);
    assert_eq!(pad(ok(br#"{"mode":"Weird","buy_tax_bps":0}"#)), None);
    // over 11% in total (1001 + 100 platform): refused; 1000 + 100 = 11% exactly: read
    assert_eq!(pad(ok(br#"{"mode":"Tax","buy_tax_bps":1001}"#)), None);
    assert_eq!(pad(ok(br#"{"mode":"Tax","buy_tax_bps":1000}"#)).as_deref(), Some("11012"));
}

fn before_step(liquid: u128, before: Option<&str>) -> TradingAccount {
    before_step_lock(liquid, before, false)
}

/// `locked`: run's R2-05 hook took the output token's lock ("nearrr:c1"; its storage lowers liquid).
fn before_step_lock(liquid: u128, before: Option<&str>, locked: bool) -> TradingAccount {
    let mut c = account();
    let r = before.map_or(PromiseResult::Failed, |b| PromiseResult::Successful(b.as_bytes().to_vec()));
    cb(liquid, vec![r]);
    if locked {
        crate::chain::lock(TOK, &crate::venues::factory::lock_holder("c1"));
    }
    c.on_nearrr_before(settle_args(None), a(TOK), U128(10_000), 0);
    c
}

#[test]
fn nearrr_before_sends_the_buy_then_reads_again() {
    let _ = before_step(5 * NEAR, Some("\"123\""));
    let b = calls_to("nearrr-fun.near");
    assert_eq!(b.len(), 1);
    assert_eq!(b[0].0, NEAR);
    assert!(b[0].1.starts_with("buy:") && b[0].1.contains(r#""min_out":"10000""#), "{}", b[0].1);
    assert!(calls_to(TOK).iter().any(|(d, x)| *d == 0 && x.starts_with("ft_balance_of:")));
    assert!(calls_to("user.tt.near")
        .iter()
        .any(|(_, x)| x.starts_with("on_nearrr_settled:") && x.contains(r#""before":"123""#)));
}

#[test]
fn nearrr_before_refuses_when_unfunded_or_unreadable() {
    // a concurrent execute / withdraw left less than amount + RESERVE, or the balance view failed:
    // nothing is sent, the swap settles as failed (spend back, no fee)
    for (liquid, before) in
        [(NEAR / 2, Some("\"0\"")), (NEAR + crate::policy::RESERVE - 1, Some("\"0\"")), (5 * NEAR, None)]
    {
        let _ = before_step_lock(liquid, before, true);
        assert!(calls_to("nearrr-fun.near").is_empty(), "{liquid}");
        let logs = get_logs();
        assert!(logs.iter().any(|l| l.contains("nearrr_tax_refused")), "{logs:?}");
        assert!(logs.iter().any(|l| l.contains("\"settled\"") && l.contains("\"used\":\"0\"")), "{logs:?}");
        assert!(crate::chain::lock_of(TOK).is_none(), "R2-05: released ({liquid})");
    }
    let _ = before_step(NEAR + crate::policy::RESERVE, Some("\"0\""));
    assert_eq!(calls_to("nearrr-fun.near").len(), 1, "exactly amount + RESERVE: funded");
    // a funded buy is in flight: its lock stays until on_nearrr_settled
    let _ = before_step_lock(5 * NEAR, Some("\"0\""), true);
    assert_eq!(calls_to("nearrr-fun.near").len(), 1);
    assert_eq!(crate::chain::lock_of(TOK).map(|x| x.0), Some("nearrr:c1".to_string()));
}

/// Step 4 with `after` tokens read (None = the view failed); returns (fee paid, spent, order kept).
fn settled(before: u128, after: Option<u128>, order: bool) -> (u128, u128, bool) {
    settled_lock(before, after, order, true)
}

/// `locked`: run's R2-05 hook took the output token's lock for this buy ("nearrr:c1").
fn settled_lock(before: u128, after: Option<u128>, order: bool, locked: bool) -> (u128, u128, bool) {
    let mut c = account();
    if order {
        crate::save_order(
            9,
            &Order {
                token_in: a("wrap.near"),
                token_out: a(TOK),
                amount_in: U128(NEAR),
                min_out: U128(5),
                trigger_meta: String::new(),
                expires_at_ns: U64(T0 + 1_000_000_000_000),
                dexes: vec![a("nearrr-fun.near")],
                pending: true,
            },
        );
    }
    c.day.spent_yocto = NEAR + F;
    let r =
        after.map_or(PromiseResult::Failed, |x| PromiseResult::Successful(format!("\"{x}\"").into_bytes()));
    // a big NEAR inflow in the same window changes nothing (never read)
    cb(5 * NEAR + 3 * NEAR, vec![r]);
    if locked {
        crate::chain::lock(TOK, &crate::venues::factory::lock_holder("c1"));
    }
    c.on_nearrr_settled(settle_args(order.then_some(9)), U128(before), a(TOK));
    (fee_paid(), c.day.spent_yocto, c.get_order(U64(9)).is_some())
}

#[test]
fn nearrr_settle_follows_the_output_token_never_a_near_delta() {
    // tokens arrived: a fill, full fee, spend kept, order consumed
    assert_eq!(settled(100, Some(600), true), (F, NEAR + F, false));
    assert!(crate::chain::lock_of(TOK).is_none(), "released on a fill");
    // no tokens (the pad's slippage refund; the output token is locked, so nothing else moved it:
    // R2-05): nothing used, no fee, spend back, the order reopens
    assert_eq!(settled(100, Some(100), true), (0, 0, true));
    assert!(get_logs().iter().any(|l| l.contains("nearrr_refunded")));
    assert!(get_logs().iter().any(|l| l.contains("order_reopened")));
    assert!(crate::chain::lock_of(TOK).is_none(), "released");
    // no lock held (expired, or taken by someone else): no proof -> used, no fee, order consumed
    assert_eq!(settled_lock(100, Some(100), true, false), (0, NEAR, false));
    // the after-balance unreadable: a fill
    assert_eq!(settled(100, None, false), (F, NEAR + F, false));
    assert!(crate::chain::lock_of(TOK).is_none(), "released on an unreadable after-balance");
}

/// R2-05 (owner doors): while a Nearrr buy holds its output token's lock, no owner outflow can
/// move that token (both doors: the `owner_*` method and the same op in `owner_signed`), or the
/// owner could empty it mid-settle and make a fill read as the pad's refund (fee 0). Other
/// tokens and NEAR still move; the token moves again once the settle unlocks it or the lock
/// expires (LOCK_TTL_BLOCKS).
mod owner_outflows {
    use super::{a, FactoryPad, NEAR, T0, TOK};
    use crate::chain::{self, LOCK_TTL_BLOCKS};
    use crate::upgrade::RescueAsset;
    use crate::venues::factory::lock_holder;
    use crate::{Caps, Dex, DexKind, FeeConfig, TradingAccount};
    use near_sdk::json_types::U128;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::{testing_env, AccountId, Gas, NearToken, PromiseResult};
    use owner_auth::testkit::{BodySpec, Signer};
    use owner_auth::{self as oa, Home, OwnerAuthInit, Standard};

    const TA: &str = "0123456789abcdef.trade.unrlzd.near";
    const OTHER: &str = "other.near";
    const H0: u64 = 1_000;

    fn ctx(pred: &str, deposit: u128, height: u64) -> VMContextBuilder {
        let mut b = VMContextBuilder::new();
        b.current_account_id(a(TA))
            .predecessor_account_id(a(pred))
            .signer_account_id(a(pred))
            .attached_deposit(NearToken::from_yoctonear(deposit))
            .account_balance(NearToken::from_yoctonear(10 * NEAR))
            .block_timestamp(T0 + height)
            .block_height(height)
            .storage_usage(100_000)
            .prepaid_gas(Gas::from_tgas(300));
        b
    }

    fn at(pred: &str, deposit: u128, height: u64) {
        testing_env!(ctx(pred, deposit, height).build());
    }

    /// A fresh TA owned by `owner` (`kind`: a signer-kind owner, home = its intents balance).
    fn ta(owner: &str, kind: Option<OwnerAuthInit>) -> TradingAccount {
        at("tt.near", 0, H0);
        near_sdk::mock::with_mocked_blockchain(|b| {
            b.take_storage();
        });
        at("tt.near", 0, H0);
        TradingAccount::init(
            a(owner),
            FeeConfig { fee_bps: 100, fee_recipient: a("fees.near") },
            Caps { max_trade_yocto: U128(2 * NEAR), daily_cap_yocto: U128(5 * NEAR) },
            vec![Dex { id: a("nearrr-fun.near"), kind: DexKind::FactoryCurve(FactoryPad::Nearrr) }],
            a("wrap.near"),
            None,
            kind,
            None,
        )
    }

    fn k1() -> Signer {
        Signer::secp256k1("o-k1")
    }

    fn signer_ta() -> TradingAccount {
        let s = k1();
        ta(&s.owner_id(), Some(OwnerAuthInit { kind: s.kind(), home: Home::Near }))
    }

    /// run's R2-05 hook: the in-flight buy "c1" holds TOK from block H0.
    fn lock_tok() {
        at(TA, 0, H0);
        chain::lock(TOK, &lock_holder("c1"));
    }

    /// "ok", or the panic code.
    fn outcome<F: FnOnce()>(f: F) -> String {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
            Ok(()) => "ok".into(),
            Err(e) => {
                let m = e
                    .downcast_ref::<String>()
                    .cloned()
                    .or(e.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_default();
                match m.split_once("panic_msg: \"") {
                    Some((_, rest)) => rest.split('"').next().unwrap_or_default().to_string(),
                    None => m,
                }
            }
        }
    }

    /// The op through the predecessor door (owner, 1 yocto).
    fn pred(c: &mut TradingAccount, owner: &str, op: &Door, token: &str, height: u64, i: u8) -> String {
        at(owner, 1, height);
        let t: AccountId = a(token);
        outcome(|| match op {
            Door::Withdraw => c.owner_withdraw(Some(t), U128(7), a("bob.near")),
            Door::WithdrawAll => c.owner_withdraw_all(a("bob.near"), vec![t]),
            Door::WithdrawHome => c.owner_withdraw_home(Some(t), U128(9)),
            Door::ViaIntents => c.owner_withdraw_via_intents(t, U128(3), addr(i)),
            Door::Rescue => c.owner_rescue(RescueAsset::Ft { contract: t, amount: U128(5) }),
        })
    }

    /// The same op signed by the owner, sent by a relayer through `owner_signed`.
    fn signed(c: &mut TradingAccount, op: &Door, token: &str, height: u64, i: u8) -> String {
        let s = k1();
        let j = match op {
            Door::Withdraw => {
                format!(r#"{{"op":"withdraw","token":"{token}","amount":"7","to":"bob.near"}}"#)
            }
            Door::WithdrawAll => format!(r#"{{"op":"withdraw_all","to":"bob.near","tokens":["{token}"]}}"#),
            Door::WithdrawHome => format!(r#"{{"op":"withdraw_home","token":"{token}","amount":"9"}}"#),
            Door::ViaIntents => format!(
                r#"{{"op":"withdraw_via_intents","token":"{token}","amount":"3","deposit_address":"{}"}}"#,
                addr(i)
            ),
            Door::Rescue => {
                format!(r#"{{"op":"rescue","asset":{{"Ft":{{"contract":"{token}","amount":"5"}}}}}}"#)
            }
        };
        at("relayer.near", 0, height);
        let salt = crate::owner::owner_auth(&a(&s.owner_id())).salt;
        let dl = (T0 + height + 60_000_000_000) / 1_000_000 * 1_000_000;
        let mp = s.sign_ops(
            Standard::Erc191,
            &BodySpec {
                signer_id: s.owner_id(),
                verifying_contract: TA.into(),
                deadline_ns: dl,
                nonce: oa::versioned_nonce(salt, dl, [i; 15]),
                items_json: format!("[{j}]"),
            },
        );
        outcome(|| c.owner_signed(mp))
    }

    fn addr(i: u8) -> String {
        format!("{i:02x}").repeat(32)
    }

    #[derive(Debug)]
    enum Door {
        Withdraw,
        WithdrawAll,
        WithdrawHome,
        ViaIntents,
        Rescue,
    }

    const DOORS: [Door; 5] =
        [Door::Withdraw, Door::WithdrawAll, Door::WithdrawHome, Door::ViaIntents, Door::Rescue];

    /// Every owner outflow, both doors: the locked token is refused; another token goes through
    /// while it is locked; the locked token goes through after the settle's unlock and after
    /// the lock expires.
    #[test]
    fn r2_05_owner_outflows_refuse_a_locked_token() {
        let owner = k1().owner_id();
        for (n, door) in DOORS.iter().enumerate() {
            let i = n as u8 * 8;
            for via_signed in [false, true] {
                let run = |c: &mut TradingAccount, token: &str, height: u64, k: u8| {
                    if via_signed {
                        signed(c, door, token, height, i + k)
                    } else {
                        pred(c, &owner, door, token, height, i + k)
                    }
                };
                let tag = format!("{door:?} signed={via_signed}");
                // in flight: the locked token is refused, another token moves
                let mut c = signer_ta();
                lock_tok();
                assert_eq!(run(&mut c, TOK, H0 + 1, 1), "E_Q_BUSY", "{tag}");
                assert_eq!(run(&mut c, OTHER, H0 + 1, 2), "ok", "{tag}: other token");
                // the settle released it
                at(TA, 0, H0 + 2);
                chain::unlock(TOK, &lock_holder("c1"));
                assert_eq!(run(&mut c, TOK, H0 + 2, 3), "ok", "{tag}: after the settle");
                // a lock never released expires after LOCK_TTL_BLOCKS
                let mut c = signer_ta();
                lock_tok();
                assert_eq!(run(&mut c, TOK, H0 + LOCK_TTL_BLOCKS - 1, 4), "E_Q_BUSY", "{tag}: last block");
                assert_eq!(run(&mut c, TOK, H0 + LOCK_TTL_BLOCKS, 5), "ok", "{tag}: expired");
            }
        }
    }

    /// A NEAR-wallet owner (home = its NEAR account: withdraw_home goes through `send`), and
    /// native NEAR while a token is locked.
    #[test]
    fn r2_05_named_owner_and_native_near() {
        let mut c = ta("owner.near", None);
        lock_tok();
        for door in [Door::Withdraw, Door::WithdrawHome, Door::WithdrawAll] {
            assert_eq!(pred(&mut c, "owner.near", &door, TOK, H0 + 1, 0), "E_Q_BUSY", "{door:?}");
            assert_eq!(pred(&mut c, "owner.near", &door, OTHER, H0 + 1, 0), "ok", "{door:?}");
        }
        at("owner.near", 1, H0 + 1);
        assert_eq!(outcome(|| c.owner_withdraw(None, U128(NEAR), a("bob.near"))), "ok");
        at("owner.near", 1, H0 + 1);
        assert_eq!(outcome(|| c.owner_withdraw_home(None, U128(NEAR))), "ok");
        // withdraw_all sweeps wNEAR too: a lock on it refuses the whole call
        at(TA, 0, H0 + 1);
        chain::lock("wrap.near", "r1");
        assert_eq!(pred(&mut c, "owner.near", &Door::WithdrawAll, OTHER, H0 + 1, 0), "E_Q_BUSY");
    }

    /// owner_withdraw_all phase 2: a lock taken after phase 1 read the balances refuses the whole
    /// call there (nothing has moved yet).
    #[test]
    fn r2_05_withdraw_all_rechecks_in_its_callback() {
        let mut c = ta("owner.near", None);
        let cb = |c: &mut TradingAccount| {
            let bal = |x: &str| PromiseResult::Successful(format!("\"{x}\"").into_bytes());
            testing_env!(
                ctx(TA, 0, H0 + 1).build(),
                near_sdk::test_vm_config(),
                near_sdk::RuntimeFeesConfig::test(),
                Default::default(),
                vec![bal("0"), bal("50"), PromiseResult::Successful(b"null".to_vec())],
            );
            outcome(|| c.on_withdraw_all_balances(a("bob.near"), vec![a(TOK)]))
        };
        assert_eq!(cb(&mut c), "ok");
        lock_tok();
        assert_eq!(cb(&mut c), "E_Q_BUSY");
        assert!(near_sdk::test_utils::get_created_receipts().is_empty(), "nothing sent");
    }
}

/// AUDIT-K1: a Kelytra sell's fee is `bps x amount_out`, where `amount_out` is what the exchange's
/// `swap_curve` RETURNED and "delivered" is the exchange's own `resolve_withdraw` result. Nothing
/// bounds it by the reserved fee (bps of the min_out bound) or by wNEAR that actually arrived (cf.
/// Shards: min(credit, arrived)). A hostile / compromised exchange reporting a huge amount_out
/// makes `finish_settle` pay up to every liquid NEAR above RESERVE to the fee recipient.
/// Safe behaviour: charged <= the reserved fee.
#[test]
fn audit_k1_kelytra_sell_fee_is_bounded() {
    testing_env!(builder(10 * NEAR, 300).build());
    near_sdk::mock::with_mocked_blockchain(|b| {
        b.take_storage();
    });
    testing_env!(builder(10 * NEAR, 300).build());
    let mut c = TradingAccount::init(
        a("owner.near"),
        FeeConfig { fee_bps: 100, fee_recipient: a("fees.near") },
        Caps { max_trade_yocto: U128(2 * NEAR), daily_cap_yocto: U128(5 * NEAR) },
        vec![Dex { id: a("exchange.kelytradevs.near"), kind: DexKind::Kelytra }],
        a("wrap.near"),
        None,
        None,
        None,
    );
    // a sell of 1000 launch tokens with min_out 0.1 wNEAR: reserved fee = 1% of 0.1 N
    let reserved = bps(NEAR / 10, 100);
    let settle = SettleArgs {
        amount: U128(1_000),
        counted: U128(0),
        fee: U128(reserved),
        proof: Some("curve_out".into()),
        ..settle_args(None)
    };
    testing_env!(
        builder(LOCKED + 10 * NEAR, 10).build(),
        near_sdk::test_vm_config(),
        near_sdk::RuntimeFeesConfig::test(),
        Default::default(),
        vec![PromiseResult::Successful(b"true".to_vec())],
    );
    let k = super::kelytra::KelArgs { buy: false, launch: U64(0), min_out: U128(NEAR / 10), dex: 0 };
    // the exchange reported amount_out = 900 wNEAR (and "true" for its withdraw)
    c.on_kelytra_done(settle, k, a("wrap.near"), U128(900 * NEAR), U128(1_000), false);
    assert!(fee_paid() <= reserved, "fee paid {} yocto vs reserved {} yocto", fee_paid(), reserved);
}
