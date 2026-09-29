//! v1.4.3 regressions on the real runtime (docs/audit/tob-contracts-*.md). RED on e7dc586
//! (v1.4.2) with
//!   NT_ACCOUNT_WASM=../out/trading_account_v1_4_2.wasm NT_FACTORY_WASM=../out/factory_v1_4_2.wasm \
//!   NT_UPGRADE_WASM=../out/trading_account_v1_4_2.wasm cargo test --test v143 -- --nocapture
//! GREEN on this build. Paths are relative to contracts/tests.
use integration_tests::*;
use near_workspaces::operations::Function;
use near_workspaces::result::ExecutionFinalResult;
use near_workspaces::types::{Gas, KeyType, NearToken, SecretKey};
use near_workspaces::Account;
use serde_json::{json, Value};
use std::task::Poll;

const GAS_PRICE_BOUND: u128 = 200_000_000;

fn yocto(v: &Value) -> u128 {
    v.as_str().unwrap_or("0").parse().unwrap_or(0)
}

async fn set_automation(env: &Env, u: &User, sk: &SecretKey) -> anyhow::Result<Account> {
    ok(u.owner
        .call(&u.account, "owner_set_automation_key")
        .args_json(json!({"public_key": sk.public_key(), "allowance": (2 * NEAR).to_string()}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(50))
        .transact()
        .await?)?;
    Ok(Account::from_secret_key(u.account.clone(), sk.clone(), &env.worker))
}

async fn place(
    env: &Env,
    u: &User,
    tin: &str,
    tout: &str,
    amount: u128,
    dex: &str,
) -> anyhow::Result<String> {
    let exp = env.now_ns().await? + 3_600_000_000_000;
    let r = okr(u
        .device
        .call(&u.account, "place_order")
        .args_json(json!({"token_in": tin, "token_out": tout, "amount_in": amount.to_string(),
            "min_out": "1", "trigger_meta": "{}", "expires_at_ns": exp.to_string(), "dexes": [dex]}))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?)?;
    Ok(r.json::<String>()?)
}

async fn buy_orders(env: &Env, u: &User, n: usize) -> anyhow::Result<Vec<String>> {
    let mut ids = vec![];
    for _ in 0..n {
        ids.push(
            place(env, u, env.wrap.id().as_str(), env.meme.id().as_str(), NEAR / 100, env.rhea.id().as_str())
                .await?,
        );
    }
    Ok(ids)
}

async fn fire_buy(env: &Env, by: &Account, u: &User, id: &str) -> anyhow::Result<ExecutionFinalResult> {
    Ok(by
        .call(&u.account, "execute_order")
        .args_json(json!({"order_id": id, "ops": env.buy_ops(NEAR / 100, 1, false)}))
        .gas(Gas::from_tgas(250))
        .transact()
        .await?)
}

async fn view(env: &Env, u: &User, m: &str) -> anyhow::Result<Value> {
    Ok(env.worker.view(&u.account, m).await?.json()?)
}

async fn has_key(env: &Env, u: &User, sk: &SecretKey) -> anyhow::Result<bool> {
    let pk = sk.public_key().to_string();
    Ok(env.access_keys(&u.account).await?.iter().any(|k| k["public_key"] == pk))
}

/// Invariant (C1-M1): an installed automation key is in the relayer role set, so a BUY fired
/// with it is refused (E_RELAYER_SELL_ONLY).
async fn assert_installed_keys_are_relayers(
    env: &Env,
    u: &User,
    keys: &[(&str, &SecretKey)],
    order: &str,
) -> anyhow::Result<()> {
    let set: Vec<String> = serde_json::from_value(view(env, u, "get_relayer_keys").await?)?;
    for (name, sk) in keys {
        if !has_key(env, u, sk).await? {
            println!("  {name}: not installed");
            continue;
        }
        let member = set.contains(&sk.public_key().to_string());
        let by = Account::from_secret_key(u.account.clone(), (*sk).clone(), &env.worker);
        let r = fire_buy(env, &by, u, order).await?;
        println!("  {name}: installed, in role set: {member}, BUY fire succeeded: {}", r.is_success());
        assert!(member, "{name} is installed but outside the relayer role set");
        fails_with(&r, "E_RELAYER_SELL_ONLY");
    }
    Ok(())
}

// ---------------- ROLESET-001 (High): the one-tx variants ----------------

/// `[owner_revoke_automation, owner_set_automation_key(K)]` in ONE owner transaction.
#[tokio::test]
async fn v143_roleset_one_tx_revoke_and_reset() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let u = env.user("rs1", 6 * NEAR, (NEAR, 5 * NEAR)).await?;
    let sk = SecretKey::from_random(KeyType::ED25519);
    set_automation(&env, &u, &sk).await?;
    let order = buy_orders(&env, &u, 1).await?.remove(0);
    let r = u
        .owner
        .batch(&u.account)
        .call(
            Function::new("owner_revoke_automation")
                .deposit(NearToken::from_yoctonear(1))
                .gas(Gas::from_tgas(40)),
        )
        .call(
            Function::new("owner_set_automation_key")
                .args_json(json!({"public_key": sk.public_key(), "allowance": (2 * NEAR).to_string()}))
                .deposit(NearToken::from_yoctonear(1))
                .gas(Gas::from_tgas(40)),
        )
        .transact()
        .await?;
    env.worker.fast_forward(3).await?;
    println!(
        "ROLESET one-tx revoke+reset: tx ok={} failed receipts={}; ak={} set={}",
        r.is_success(),
        r.receipt_failures().len(),
        view(&env, &u, "get_automation_key").await?,
        view(&env, &u, "get_relayer_keys").await?
    );
    if r.is_failure() {
        fails_with(&r, "E_AUTOMATION_BUSY");
    }
    assert_installed_keys_are_relayers(&env, &u, &[("K", &sk)], &order).await
}

/// `[owner_set_automation_key(B), owner_set_automation_key(A)]` (rotate and roll back) in ONE tx.
#[tokio::test]
async fn v143_roleset_one_tx_rotate_and_back() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let u = env.user("rs2", 6 * NEAR, (NEAR, 5 * NEAR)).await?;
    let (a, b) = (SecretKey::from_random(KeyType::ED25519), SecretKey::from_random(KeyType::ED25519));
    set_automation(&env, &u, &a).await?;
    let order = buy_orders(&env, &u, 1).await?.remove(0);
    let set = |sk: &SecretKey| {
        Function::new("owner_set_automation_key")
            .args_json(json!({"public_key": sk.public_key(), "allowance": (2 * NEAR).to_string()}))
            .deposit(NearToken::from_yoctonear(1))
            .gas(Gas::from_tgas(40))
    };
    let r = u.owner.batch(&u.account).call(set(&b)).call(set(&a)).transact().await?;
    env.worker.fast_forward(3).await?;
    println!(
        "ROLESET one-tx rotate+back: tx ok={}; ak={} set={}",
        r.is_success(),
        view(&env, &u, "get_automation_key").await?,
        view(&env, &u, "get_relayer_keys").await?
    );
    if r.is_failure() {
        fails_with(&r, "E_AUTOMATION_BUSY");
    }
    assert_installed_keys_are_relayers(&env, &u, &[("A", &a), ("B", &b)], &order).await
}

// ---------------- PROMISEORDER-001 (Medium): migrated account ----------------

async fn wait(s: near_workspaces::operations::TransactionStatus) -> anyhow::Result<ExecutionFinalResult> {
    for _ in 0..200 {
        if let Poll::Ready(r) = s.status().await? {
            return Ok(r);
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    anyhow::bail!("not executed (key gone)")
}

/// An account created on v1.4.1 (no role set on chain), upgraded; the owner then removes the
/// automation key with owner_remove_key while it streams BUY fires. None may fill.
#[tokio::test]
async fn v143_promiseorder_migrated_owner_remove_key() -> anyhow::Result<()> {
    let env = Env::new_with(Some(out("trading_account_v1_4_1")), Some(out("factory_v1_4_1"))).await?;
    let u = env.user("po", 6 * NEAR, (NEAR, 5 * NEAR)).await?;
    let sk = SecretKey::from_random(KeyType::ED25519);
    let auto = set_automation(&env, &u, &sk).await?;
    let ids = buy_orders(&env, &u, 24).await?;
    let target = std::env::var("NT_UPGRADE_WASM")
        .map(|p| std::fs::read(p).expect("NT_UPGRADE_WASM"))
        .unwrap_or_else(|_| out("trading_account"));
    let hash = env.deploy_global(target).await?;
    ok(u.owner
        .call(&u.account, "owner_upgrade")
        .args_json(json!({"code_hash": hash}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(50))
        .transact()
        .await?)?;
    println!("upgraded v1.4.1 -> {}", env.config(&u.account).await?["version"]);
    let pk = sk.public_key().to_string();
    let set: Vec<String> = serde_json::from_value(view(&env, &u, "get_relayer_keys").await?)?;
    assert_eq!(set, vec![pk.clone()]);
    let remove = u
        .owner
        .call(&u.account, "owner_remove_key")
        .args_json(json!({"public_key": pk}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(30))
        .transact_async()
        .await?;
    let mut pending = vec![];
    for id in &ids {
        let tx = auto
            .call(&u.account, "execute_order")
            .args_json(json!({"order_id": id, "ops": env.buy_ops(NEAR / 100, 1, false)}))
            .gas(Gas::from_tgas(250))
            .transact_async()
            .await;
        if let Ok(s) = tx {
            pending.push((id.clone(), s));
        }
        tokio::time::sleep(std::time::Duration::from_millis(120)).await;
    }
    assert!(wait(remove).await?.is_success());
    let (mut fired, mut refused) = (vec![], 0);
    for (id, s) in pending {
        if let Ok(r) = wait(s).await {
            if r.is_success() {
                fired.push(id);
            } else if format!("{:?}", r.into_result().err()).contains("E_RELAYER_SELL_ONLY") {
                refused += 1;
            }
        }
    }
    println!("PROMISEORDER migrated remove race: {refused} refused, {} fired {fired:?}", fired.len());
    assert!(fired.is_empty(), "the removed automation key filled BUY orders: {fired:?}");
    assert!(refused > 0, "race window not exercised");
    env.worker.fast_forward(3).await?;
    assert!(!has_key(&env, &u, &sk).await?, "key deleted");
    let set: Vec<String> = serde_json::from_value(view(&env, &u, "get_relayer_keys").await?)?;
    assert!(set.is_empty(), "{set:?}");
    Ok(())
}

// ---------------- CAPACCT-001 / TI-1 / SC-1 (Medium) ----------------

/// A token that keeps every storage deposit (mocks/gas-burner) gains at most the daily cap in a
/// UTC day from `withdraw_to_owner{token}` loops; the account keeps RESERVE.
#[tokio::test]
async fn v143_capacct_hostile_token_gains_at_most_daily_cap() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let burner = sub(&env.root, "keeper", 5 * NEAR).await?.deploy(&out("gas_burner")).await?.into_result()?;
    let cap = NEAR / 5;
    let u = env.user("ca", 3 * NEAR, (NEAR, cap)).await?;
    env.worker.fast_forward(3).await?;
    let e0 = env.near_balance(burner.id()).await?;
    let mut n = 0;
    for _ in 0..60 {
        let r = u
            .device
            .call(&u.account, "withdraw_to_owner")
            .args_json(json!({"token": burner.id(), "amount": "1"}))
            .gas(Gas::from_tgas(100))
            .transact()
            .await?;
        if r.is_failure() {
            fails_with(&r, "E_CAP_DAILY");
            break;
        }
        n += 1;
    }
    env.worker.fast_forward(3).await?;
    let gained = env.near_balance(burner.id()).await? - e0;
    let day = view(&env, &u, "get_day").await?;
    println!(
        "CAPACCT: {n} withdraw_to_owner calls; hostile token gained {:.4} NEAR (cap {:.4}); spent {} gas {}",
        gained as f64 / 1e24,
        cap as f64 / 1e24,
        day["spent_yocto"],
        day["gas_spent_yocto"]
    );
    assert!(n > 0 && n < 60, "loop not bounded");
    assert!(gained <= cap, "hostile token gained {gained} > daily cap {cap}");
    Ok(())
}

// ---------------- ORDER-001 (Medium): hostile Plach reports "0" ----------------

fn plach_buy(env: &Env, amt: u128) -> Value {
    let m = json!({"operations": [
        {"SwapSimple": {"dex_id": "slimedragon.near/xyk", "message": "AA==", "asset_in": "near", "asset_out": format!("nep141:{}", env.meme.id()), "amount": {"Amount": {"ExactIn": amt.to_string()}}, "constraint": "5"}},
        {"Withdraw": {"asset_id": format!("nep141:{}", env.meme.id()), "amount": {"Full": {"at_least": "5"}}, "to": null, "rescue_address": null}}],
        "referrer": env.fees.id()}).to_string();
    json!([{"PlachDepositNear": {"dex": env.plach.id(), "amount": amt.to_string(), "msg": m, "gas": (100 * TGAS).to_string()}}])
}

#[tokio::test]
async fn v143_order_hostile_plach_zero_is_not_a_refund() -> anyhow::Result<()> {
    let env = Env::new().await?;
    ok(env.root.transfer_near(env.plach.id(), NearToken::from_near(3)).await?)?;
    let plach = env.plach.deploy(&out("mock_plach")).await?.into_result()?;
    ok(plach.call("new").transact().await?)?;
    let u = env.user("op", 6 * NEAR, (2 * NEAR, 5 * NEAR)).await?;
    let amt = NEAR / 5;
    // plain execute: Plach keeps the NEAR and says "0" -> the daily spend is NOT returned
    ok(env.exec(&u.device, &u.account, plach_buy(&env, amt), "p0", amt + fee(amt)).await?)?;
    let spent = env.day_spent(&u).await?;
    println!("ORDER-001 execute: day spent after a Plach \"0\" = {spent} (amount {amt})");
    assert!(spent >= amt, "a hostile Plach \"0\" refilled the daily cap");
    // order: consumed, not reopened for another fire
    let id =
        place(&env, &u, env.wrap.id().as_str(), env.meme.id().as_str(), amt, env.plach.id().as_str()).await?;
    let r = okr(u
        .device
        .call(&u.account, "execute_order")
        .args_json(json!({"order_id": id, "ops": plach_buy(&env, amt)}))
        .gas(Gas::from_tgas(250))
        .transact()
        .await?)?;
    let reopened = r.logs().iter().any(|l| l.contains("order_reopened"));
    let o =
        env.worker.view(&u.account, "get_order").args_json(json!({"order_id": id})).await?.json::<Value>()?;
    println!("ORDER-001 order: reopened={reopened} order={o}");
    assert!(!reopened && o.is_null(), "a hostile Plach \"0\" reopened the order");
    Ok(())
}

// ---------------- SC-2 (Low): gas of every device call is charged ----------------

#[tokio::test]
async fn v143_sc2_device_calls_charge_gas() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let u = env.user("sc2", 3 * NEAR, (NEAR, 2 * NEAR)).await?;
    let gas = |v: Value| yocto(&v["gas_spent_yocto"]);
    let g0 = gas(view(&env, &u, "get_day").await?);
    let id =
        place(&env, &u, env.wrap.id().as_str(), env.meme.id().as_str(), NEAR / 100, env.rhea.id().as_str())
            .await?;
    let g1 = gas(view(&env, &u, "get_day").await?);
    ok(u.device
        .call(&u.account, "cancel_order")
        .args_json(json!({"order_id": id}))
        .gas(Gas::from_tgas(20))
        .transact()
        .await?)?;
    let g2 = gas(view(&env, &u, "get_day").await?);
    ok(u.device
        .call(&u.account, "lower_caps")
        .args_json(json!({"caps": caps_json((NEAR, 2 * NEAR))}))
        .gas(Gas::from_tgas(20))
        .transact()
        .await?)?;
    let g3 = gas(view(&env, &u, "get_day").await?);
    println!("SC-2: place_order {} cancel_order {} lower_caps {}", g1 - g0, g2 - g1, g3 - g2);
    assert_eq!(g1 - g0, 30 * TGAS as u128 * GAS_PRICE_BOUND, "place_order");
    assert_eq!(g2 - g1, 20 * TGAS as u128 * GAS_PRICE_BOUND, "cancel_order");
    assert_eq!(g3 - g2, 20 * TGAS as u128 * GAS_PRICE_BOUND, "lower_caps");
    Ok(())
}

// ---------------- SC-3 (Low): init registration outcome is visible ----------------

/// Happy path (real DCL wasm): both registrations reported ok. Failure path: a factory whose
/// DCL-kind entry has no code, so init's DCL registration fails: reported, not silent, and the
/// account is still created. Also proves create_account still fits in 100 TGas.
#[tokio::test]
async fn v143_sc3_init_registration_reported() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let u = env.user("sc3", 3 * NEAR, (NEAR, 2 * NEAR)).await?;
    env.worker.fast_forward(3).await?;
    let v = view(&env, &u, "get_init_registration").await?;
    println!("SC-3 real DCL: get_init_registration = {v}");
    assert_eq!(v, json!([{"target": env.wrap.id(), "ok": true}, {"target": env.dcl.id(), "ok": true}]));
    // a factory whose DCL-kind DEX is an account without code
    let nodcl = sub(&env.root, "nodcl", NEAR).await?;
    let f2 = sub(&env.root, "tt2", 50 * NEAR).await?.deploy(&out("factory")).await?.into_result()?;
    ok(f2
        .call("new")
        .args_json(json!({"admin": env.admin.id(), "code_hash": env.code_hash,
            "fee_config": {"fee_bps": FEE_BPS, "fee_recipient": env.fees.id()},
            "dex_allowlist": [{"id": env.rhea.id(), "kind": "RheaClassic"}, {"id": nodcl.id(), "kind": "RheaDcl"}],
            "wrap": env.wrap.id()}))
        .transact()
        .await?)?;
    let owner = sub(&env.root, "sc3b", 10 * NEAR).await?;
    let sk = SecretKey::from_random(KeyType::ED25519);
    let r = owner
        .call(f2.id(), "create_account")
        .args_json(json!({"device_public_key": sk.public_key(), "caps": caps_json((NEAR, 2 * NEAR))}))
        .deposit(NearToken::from_near(3))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?;
    assert!(r.is_success(), "{:?}", r.clone().into_result().err());
    assert!(r.logs().iter().any(|l| l.contains("account_created")));
    let ev = format!(r#"{{"target":"{}","ok":false}}"#, nodcl.id());
    assert!(
        r.logs().iter().any(|l| l.contains(r#""event":"init_registration""#) && l.contains(&ev)),
        "{:?}",
        r.logs()
    );
    let acc: near_workspaces::AccountId =
        f2.view("account_for").args_json(json!({"owner": owner.id()})).await?.json()?;
    let v: Value = env.worker.view(&acc, "get_init_registration").await?.json()?;
    println!("SC-3 DCL without code: get_init_registration = {v}");
    assert_eq!(v, json!([{"target": env.wrap.id(), "ok": true}, {"target": nodcl.id(), "ok": false}]));
    Ok(())
}

// ---------------- OWNERBOUND-001: cap raises are delayed 1 h ----------------

#[tokio::test]
async fn v143_ownerbound_cap_raise_delayed() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let u = env.user("ob", 40 * NEAR, (NEAR, 2 * NEAR)).await?;
    let set_caps = |c: (u128, u128)| {
        u.owner
            .call(&u.account, "owner_set_caps")
            .args_json(json!({"caps": caps_json(c)}))
            .deposit(NearToken::from_yoctonear(1))
            .gas(Gas::from_tgas(20))
            .transact()
    };
    let r = okr(set_caps((30 * NEAR, 60 * NEAR)).await?)?;
    assert!(r.logs().iter().any(|l| l.contains("caps_raise_pending")));
    let pending = view(&env, &u, "get_pending_caps").await?;
    println!("OWNERBOUND pending = {pending}");
    assert_eq!(pending["caps"], caps_json((30 * NEAR, 60 * NEAR)));
    assert_eq!(env.config(&u.account).await?["caps"], caps_json((NEAR, 2 * NEAR)));
    // a 2 NEAR buy inside the hour is refused by the old max trade
    fails_with(
        &env.exec(&u.device, &u.account, env.buy_ops(2 * NEAR, 1, true), "ob1", 3 * NEAR).await?,
        "E_CAP_TRADE",
    );
    // lower_caps cancels the raise
    let r = okr(u
        .device
        .call(&u.account, "lower_caps")
        .args_json(json!({"caps": caps_json((NEAR, 2 * NEAR))}))
        .gas(Gas::from_tgas(20))
        .transact()
        .await?)?;
    assert!(r.logs().iter().any(|l| l.contains("caps_raise_cancelled")));
    assert!(view(&env, &u, "get_pending_caps").await?.is_null());
    // raise again and let the hour pass (fast-forward by measured block time)
    ok(set_caps((30 * NEAR, 60 * NEAR)).await?)?;
    let at: u64 = view(&env, &u, "get_pending_caps").await?["active_at_ns"].as_str().unwrap().parse()?;
    let t0 = env.now_ns().await?;
    env.worker.fast_forward(100).await?;
    let per_block = (env.now_ns().await? - t0) / 100;
    let blocks = (at.saturating_sub(env.now_ns().await?) / per_block.max(1)) + 5;
    env.worker.fast_forward(blocks).await?;
    // block time varies: step on until the hour has passed
    for _ in 0..20 {
        if env.now_ns().await? >= at {
            break;
        }
        env.worker.fast_forward(200).await?;
    }
    assert!(env.now_ns().await? >= at);
    assert_eq!(env.config(&u.account).await?["caps"], caps_json((30 * NEAR, 60 * NEAR)));
    ok(env.exec(&u.device, &u.account, env.buy_ops(2 * NEAR, 1, true), "ob2", 3 * NEAR).await?)?;
    Ok(())
}

// ---------------- RESDISC-001 (Low): unreadable tokens are reported ----------------

#[tokio::test]
async fn v143_withdraw_all_reports_unreadable_token() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let u = env.user("wa", 3 * NEAR, (NEAR, 2 * NEAR)).await?;
    let nocode = sub(&env.root, "nocode", NEAR).await?;
    // the balance read of `nocode` fails (a failed receipt by design): the tx itself succeeds
    let r = u
        .owner
        .call(&u.account, "owner_withdraw_all")
        .args_json(json!({"to": u.owner.id(), "tokens": [nocode.id()]}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(300))
        .transact()
        .await?;
    assert!(r.is_success(), "{:?}", r.clone().into_result().err());
    let ev = format!(
        r#""event":"owner_withdraw","data":{{"token":"{}","amount":"0","to":"{}","ok":false}}"#,
        nocode.id(),
        u.owner.id()
    );
    assert!(r.logs().iter().any(|l| l.contains(&ev)), "no event for the unreadable token: {:?}", r.logs());
    Ok(())
}
