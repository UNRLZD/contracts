//! v1.4.8 on the real runtime: 24/7 (relayer) orders have no weekly limit by default; an owner
//! opt-in restores the weekly accounting and the C1-L3 floor (failed fires included, RA7-1).
//! RED on v1.4.7 (4419f18): NT_ACCOUNT_WASM=../out/trading_account_v1_4_7.wasm \
//!   NT_FACTORY_WASM=../out/factory_v1_4_7.wasm cargo test --test v148 -- --nocapture
use integration_tests::*;
use near_workspaces::result::ExecutionFinalResult;
use near_workspaces::types::{Gas, KeyType, NearToken, SecretKey};
use near_workspaces::{Account, AccountId};
use serde_json::{json, Value};

const MAX: u128 = u128::MAX;

async fn place(
    env: &Env,
    u: &User,
    tin: &AccountId,
    tout: &AccountId,
    amount: u128,
    min_out: u128,
) -> anyhow::Result<String> {
    let exp = env.now_ns().await? + 3_600_000_000_000;
    let r = okr(u
        .device
        .call(&u.account, "place_order")
        .args_json(json!({"token_in": tin, "token_out": tout, "amount_in": amount.to_string(),
            "min_out": min_out.to_string(), "trigger_meta": "{}", "expires_at_ns": exp.to_string(),
            "dexes": [env.rhea.id()]}))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?)?;
    Ok(r.json::<String>()?)
}

async fn fire(by: &Account, u: &User, id: &str, ops: Value) -> anyhow::Result<ExecutionFinalResult> {
    Ok(by
        .call(&u.account, "execute_order")
        .args_json(json!({"order_id": id, "ops": ops}))
        .gas(Gas::from_tgas(250))
        .transact()
        .await?)
}

async fn week(env: &Env, acc: &AccountId) -> anyhow::Result<Value> {
    Ok(env.worker.view(acc, "get_relayer_week").await?.json()?)
}

async fn set_allowance(u: &User, weekly: u128) -> anyhow::Result<ExecutionFinalResult> {
    okr(u
        .owner
        .call(&u.account, "owner_set_relayer_allowance")
        .args_json(json!({"weekly_yocto": weekly.to_string()}))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?)
}

/// Default (no allowance): > 20 relayer fills in one week and a sell whose min_out is far above
/// the old 10 NEAR default are accepted. Then the owner opts in: the same sell is refused, and a
/// failing buy re-fired keeps the floor charged (RA7-1), so <= 20 fires.
#[tokio::test]
async fn v148_unlimited_by_default_then_opt_in() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let u = env.user("unl", 12 * NEAR, (MAX, MAX)).await?;
    let sk = SecretKey::from_random(KeyType::ED25519);
    ok(u.owner
        .call(&u.account, "owner_set_automation_key")
        .args_json(json!({"public_key": sk.public_key(), "allowance": (3 * NEAR).to_string()}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(50))
        .transact()
        .await?)?;
    let auto = Account::from_secret_key(u.account.clone(), sk, &env.worker);
    let w = week(&env, &u.account).await?;
    println!("week (default) = {w}");
    assert_eq!(w["allowance_yocto"], Value::Null);

    // 22 relayer buy fills (> 20 = the v1.4.7 fire bound at any allowance)
    let (wrap, meme) = (env.wrap.id().clone(), env.meme.id().clone());
    let amt = NEAR / 100;
    for i in 0..22 {
        let id = place(&env, &u, &wrap, &meme, amt, 1).await?;
        let r = fire(&auto, &u, &id, env.buy_ops(amt, 1, i == 0)).await?;
        assert!(r.logs().iter().any(|l| l.contains("order_filled")), "fire {i}: {:?}", r.failures());
    }
    assert_eq!(week(&env, &u.account).await?["spent_yocto"], "0");
    println!("22 relayer fills accepted, week spent 0");

    // a sell with min_out 50 NEAR (>> 10 NEAR): accepted (the pool can't meet it, so no fill)
    let held = env.ft_balance(&meme, &u.account).await?;
    let part = held / 4;
    let big = place(&env, &u, &meme, &wrap, part, 50 * NEAR).await?;
    let r = fire(&auto, &u, &big, env.sell_ops(part, 50 * NEAR, false)).await?;
    assert!(r.is_success(), "{:?}", r.failures());
    assert!(r.logs().iter().any(|l| l.contains("\"event\":\"execute\"")), "{:?}", r.logs());
    assert!(!r.logs().iter().any(|l| l.contains("order_filled")), "{:?}", r.logs());
    assert_eq!(week(&env, &u.account).await?["spent_yocto"], "0");

    // opt in: 10 NEAR a week
    let r = set_allowance(&u, 10 * NEAR).await?;
    assert!(r.logs().iter().any(|l| l.contains("\"old_weekly_yocto\":null")), "{:?}", r.logs());
    assert_eq!(week(&env, &u.account).await?["allowance_yocto"], (10 * NEAR).to_string());
    let big = place(&env, &u, &meme, &wrap, part, 50 * NEAR).await?;
    fails_with(&fire(&auto, &u, &big, env.sell_ops(part, 50 * NEAR, false)).await?, "E_RELAYER_WEEKLY");
    // RA7-1: a failing buy (unreachable min_out) re-fired keeps the 0.5 NEAR floor each time
    let unreachable = 10u128.pow(36);
    let id = place(&env, &u, &wrap, &meme, NEAR / 10, unreachable).await?;
    let mut fired = 0u128;
    for _ in 0..25 {
        let r = fire(&auto, &u, &id, env.buy_ops(NEAR / 10, unreachable, false)).await?;
        if !r.is_success() {
            fails_with(&r, "E_RELAYER_WEEKLY");
            break;
        }
        fired += 1;
        env.worker.fast_forward(1).await?;
    }
    let spent: u128 = week(&env, &u.account).await?["spent_yocto"].as_str().unwrap().parse()?;
    println!("opt-in 10 NEAR: {fired} failing fires, week spent {spent}");
    assert!(fired <= 20, "{fired}");
    assert_eq!(spent, fired * (10 * NEAR / 20));

    // back to unlimited (u128::MAX): the big sell fires again
    let r = set_allowance(&u, MAX).await?;
    assert!(r.logs().iter().any(|l| l.contains("\"new_weekly_yocto\":null")), "{:?}", r.logs());
    assert_eq!(week(&env, &u.account).await?["allowance_yocto"], Value::Null);
    let r = fire(&auto, &u, &big, env.sell_ops(part, 50 * NEAR, false)).await?;
    assert!(r.is_success(), "{:?}", r.failures());
    Ok(())
}

/// Gas griefing with no weekly limit: the automation key's FC gas allowance (non-replenishing)
/// still bounds how many fires a stolen key can send. At the 0.5 NEAR minimum, failing buys
/// re-fired until the runtime refuses the key (NotEnoughAllowance).
#[tokio::test]
async fn v148_key_allowance_bounds_unlimited_fires() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let u = env.user("gasb", 12 * NEAR, (MAX, MAX)).await?;
    let sk = SecretKey::from_random(KeyType::ED25519);
    ok(u.owner
        .call(&u.account, "owner_set_automation_key")
        .args_json(json!({"public_key": sk.public_key(), "allowance": (NEAR / 2).to_string()}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(50))
        .transact()
        .await?)?;
    let pk = sk.public_key().to_string();
    let auto = Account::from_secret_key(u.account.clone(), sk, &env.worker);
    let allowance = |keys: Vec<Value>| -> u128 {
        let k = keys.iter().find(|k| k["public_key"] == pk).expect("key");
        k["access_key"]["permission"]["FunctionCall"]["allowance"].as_str().unwrap().parse().unwrap()
    };
    let (wrap, meme) = (env.wrap.id().clone(), env.meme.id().clone());
    let unreachable = 10u128.pow(36);
    let id = place(&env, &u, &wrap, &meme, NEAR / 100, unreachable).await?;
    // native + wNEAR (failing buys wrap NEAR: RA7-1's side effect, no loss)
    let total = |n: u128, w: u128| n + w;
    let before = total(env.near_balance(&u.account).await?, env.ft_balance(&wrap, &u.account).await?);
    let (mut fired, mut refused) = (0u32, None);
    for _ in 0..200 {
        match auto
            .call(&u.account, "execute_order")
            .args_json(json!({"order_id": id, "ops": env.buy_ops(NEAR / 100, unreachable, fired == 0)}))
            .gas(Gas::from_tgas(250))
            .transact()
            .await
        {
            Ok(r) if r.is_success() => fired += 1,
            Ok(r) => {
                refused = Some(format!("{:?}", r.into_result().err()));
                break;
            }
            Err(e) => {
                refused = Some(format!("{e:?}"));
                break;
            }
        }
    }
    let left = allowance(env.access_keys(&u.account).await?);
    env.worker.fast_forward(3).await?;
    let after = total(env.near_balance(&u.account).await?, env.ft_balance(&wrap, &u.account).await?);
    println!(
        "0.5 NEAR key allowance: {fired} fires, then refused: {:?}; allowance left {left}; account NEAR+wNEAR {before} -> {after}",
        refused.as_deref().map(|s| s.chars().take(160).collect::<String>())
    );
    let refused = refused.expect("the key allowance never ran out");
    assert!(refused.contains("NotEnoughAllowance"), "{refused}");
    assert!(fired > 0 && fired < 200);
    // what left the account: gas (<= the key allowance) + one storage deposit
    assert!(before - after <= NEAR / 2 + STORAGE, "{before} -> {after}");
    Ok(())
}

/// Factory create_account with an automation key and no weekly_yocto: unlimited (was 10 NEAR).
#[tokio::test]
async fn v148_factory_automation_without_weekly_is_unlimited() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let owner = sub(&env.root, "fac", 25 * NEAR).await?;
    let device = SecretKey::from_random(KeyType::ED25519);
    let ak = SecretKey::from_random(KeyType::ED25519);
    ok(owner
        .call(env.factory.id(), "create_account")
        .args_json(json!({"device_public_key": device.public_key(),
            "automation": {"public_key": ak.public_key(), "allowance": NEAR.to_string()}}))
        .deposit(NearToken::from_near(5))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?)?;
    let acc = env.account_for(owner.id()).await?;
    env.worker.fast_forward(3).await?;
    let set: Value = env.worker.view(&acc, "get_relayer_keys").await?.json()?;
    assert_eq!(set, json!([ak.public_key().to_string()]));
    let w = week(&env, &acc).await?;
    println!("factory, no weekly_yocto: {w}");
    assert_eq!(w["allowance_yocto"], Value::Null);
    Ok(())
}
