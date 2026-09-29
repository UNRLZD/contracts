//! v1.2.1 hardening (independent audit). Each test asserts the FIXED behavior and must FAIL
//! against the frozen v1.2 build:
//!   NT_ACCOUNT_WASM=../../audit/contract/wasm/trading_account.wasm \
//!   NT_FACTORY_WASM=../../audit/contract/wasm/factory.wasm cargo test --test hardening
use integration_tests::*;
use near_workspaces::types::{Gas, KeyType, NearToken, SecretKey};
use serde_json::json;

/// Fix 1 (HIGH): gas burnt through a hostile "token" (spend 0, non-NEAR output) is charged to
/// the daily cap, so a compromised device key can burn at most the daily cap in gas; and a
/// swap op can't attach more gas than its DEX kind needs.
#[tokio::test]
async fn fix1a_gas_burn_bounded_by_daily_cap() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let burner = sub(&env.root, "burner", 5 * NEAR).await?.deploy(&out("gas_burner")).await?.into_result()?;
    let u = env.user("gb", 3 * NEAR, (NEAR, NEAR / 5)).await?;
    let op = |gas: u64| {
        json!([{"FtTransferCall": {"token": burner.id(), "receiver_id": env.rhea.id(), "amount": "1",
            "msg": env.rhea_msg(burner.id(), env.meme.id(), 1, 1, false), "gas": (gas * TGAS).to_string()}}])
    };
    env.worker.fast_forward(3).await?; // let create's DCL storage refund land first
    let b0 = env.near_balance(&u.account).await?;
    let mut refused_at = None;
    for i in 0..12 {
        let r = env.exec(&u.device, &u.account, op(200), &format!("burn{i}"), 0).await?;
        if r.is_failure() {
            fails_with(&r, "E_CAP_DAILY");
            refused_at = Some(i);
            break;
        }
    }
    env.worker.fast_forward(5).await?; // pessimistic gas prepay (~10x) is refunded a few blocks later
    let burnt = b0 - env.near_balance(&u.account).await?;
    println!("gas-burn executes accepted before the cap: {refused_at:?}; NEAR burnt {}", burnt as f64 / 1e24);
    assert!(refused_at.is_some(), "gas burn not bounded by the daily cap");
    let day: serde_json::Value = env.worker.view(&u.account, "get_day").await?.json()?;
    let gas_spent: u128 = day["gas_spent_yocto"].as_str().expect("gas_spent_yocto").parse()?;
    println!("gas_spent {gas_spent} burnt {burnt}");
    assert!(gas_spent <= NEAR / 5 && burnt <= NEAR / 5, "burnt {burnt} > daily cap");
    // withdraw_to_owner(token = burner) is charged too (20 TGas each): refused within the headroom
    let mut refused = false;
    for _ in 0..8 {
        let r = u
            .device
            .call(&u.account, "withdraw_to_owner")
            .args_json(json!({"token": burner.id(), "amount": "1"}))
            .gas(Gas::from_tgas(100))
            .transact()
            .await?;
        if r.is_failure() {
            fails_with(&r, "E_CAP_DAILY");
            refused = true;
            break;
        }
    }
    assert!(refused, "withdraw_to_owner gas not capped");
    Ok(())
}

/// Fix 1b: a swap op can't attach more gas than its DEX kind needs (Rhea <= 200 TGas).
#[tokio::test]
async fn fix1b_swap_gas_capped_per_dex_kind() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let burner = sub(&env.root, "burner", 5 * NEAR).await?.deploy(&out("gas_burner")).await?.into_result()?;
    let u = env.user("gc", 3 * NEAR, (NEAR, 2 * NEAR)).await?;
    let op = json!([{"FtTransferCall": {"token": burner.id(), "receiver_id": env.rhea.id(), "amount": "1",
        "msg": env.rhea_msg(burner.id(), env.meme.id(), 1, 1, false), "gas": (250 * TGAS).to_string()}}]);
    fails_with(&env.exec(&u.device, &u.account, op, "big", 0).await?, "E_GAS");
    Ok(())
}

/// Fix 2 (MEDIUM): StorageDeposit can't pay an arbitrary account; only wrap, allowlisted DEXes
/// and the tokens of the same execute's swap / recovery are valid targets.
#[tokio::test]
async fn fix2_storage_deposit_only_to_known_targets() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let evil = sub(&env.root, "evilsd", 5 * NEAR).await?.deploy(&out("gas_burner")).await?.into_result()?;
    let u = env.user("sd", 3 * NEAR, (NEAR, 2 * NEAR)).await?;
    let e0 = env.near_balance(evil.id()).await?;
    let pay = json!([{"StorageDeposit": {"token": evil.id(), "amount": "12500000000000000000000"}}]);
    let r = env.exec(&u.device, &u.account, pay, "pay", NEAR).await?;
    assert!(env.near_balance(evil.id()).await? <= e0 + NEAR / 1000, "arbitrary account was paid");
    fails_with(&r, "E_STORAGE_TARGET");
    // the swap's own output token is still allowed (router shape)
    ok(env.exec(&u.device, &u.account, env.buy_ops(NEAR / 10, 1, true), "buy", NEAR).await?)?;
    Ok(())
}

/// Fix 3 (LOW): a msg may only name the platform as referrer/referral (a third-party referrer
/// sets its own fee).
#[tokio::test]
async fn fix3_referrer_must_be_platform() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let u = env.user("rf", 3 * NEAR, (NEAR, 2 * NEAR)).await?;
    let mut ops = env.buy_ops(NEAR / 10, 1, false);
    let m = ops[1]["FtTransferCall"]["msg"]
        .as_str()
        .unwrap()
        .replace("\"force\":0", "\"force\":0,\"referral_id\":\"evil.near\"");
    ops[1]["FtTransferCall"]["msg"] = json!(m);
    fails_with(&env.exec(&u.device, &u.account, ops, "r1", NEAR).await?, "E_REFERRER");
    let mut ops = env.buy_ops(NEAR / 10, 1, false);
    let m = ops[1]["FtTransferCall"]["msg"]
        .as_str()
        .unwrap()
        .replace("\"force\":0", &format!("\"force\":0,\"referral_id\":\"{}\"", env.fees.id()));
    ops[1]["FtTransferCall"]["msg"] = json!(m);
    // accepted by the contract (no E_REFERRER). Note: Rhea v1.9.20 itself then rejects a
    // referral from a trader not registered on Ref -> clients omit referral_id on Rhea.
    let r = env.exec(&u.device, &u.account, ops, "r2", NEAR).await?;
    assert!(r.is_success(), "{:?}", r.clone().into_result().err());
    Ok(())
}

/// Fix 4 (LOW): create_account spam can't drain the factory: its `created` entry storage is
/// paid from the deposit, i.e. the account receives deposit - entry cost and the factory keeps
/// >= the storage its entry locks. (Gas rewards alone would hide the drain.)
#[tokio::test]
async fn fix4_factory_storage_paid_by_deposit() -> anyhow::Result<()> {
    let env = Env::new().await?;
    for i in 0..3 {
        let s0 = env.worker.view_account(env.factory.id()).await?.storage_usage;
        let owner = sub(&env.root, &format!("spam{i}"), 3 * NEAR).await?;
        let pk = SecretKey::from_random(KeyType::ED25519).public_key();
        let dep = 7 * NEAR / 10;
        let r = okr(owner
            .call(env.factory.id(), "create_account")
            .args_json(json!({"device_public_key": pk, "caps": caps_json((NEAR, NEAR))}))
            .deposit(NearToken::from_yoctonear(dep))
            .gas(Gas::from_tgas(100))
            .transact()
            .await?)?;
        let locked =
            (env.worker.view_account(env.factory.id()).await?.storage_usage - s0) as u128 * 10u128.pow(19);
        // the Transfer action of the create batch
        let st = env.tx_status(&r.outcome().transaction_hash.to_string(), owner.id()).await?;
        let transferred: u128 = st["receipts"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|rc| rc["receipt"]["Action"]["actions"].as_array())
            .flatten()
            .find_map(|a| a["Transfer"]["deposit"].as_str().map(|d| d.parse::<u128>().unwrap()))
            .expect("Transfer action");
        println!("create #{i}: factory storage locked {locked} yocto, account got {transferred} of {dep}");
        assert!(transferred + locked <= dep, "factory pays its own entry storage ({locked}) out of pocket");
    }
    Ok(())
}
