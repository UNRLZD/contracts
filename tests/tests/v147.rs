//! v1.4.7 product changes on the real runtime. RED on 956c2a3 (v1.4.6) with
//!   NT_ACCOUNT_WASM=../out/trading_account_v1_4_6.wasm NT_FACTORY_WASM=../out/factory_v1_4_6.wasm \
//!   cargo test --test v147 -- --nocapture
//! GREEN on this build. Paths are relative to contracts/tests.
use integration_tests::*;
use near_workspaces::types::{Gas, KeyType, NearToken, SecretKey};
use near_workspaces::{Account, AccountId};
use serde_json::{json, Value};

const MAX: &str = "340282366920938463463374607431768211455";

/// create_account with raw args (no caps / an automation key), one owner signature.
async fn create(
    env: &Env,
    name: &str,
    args: Value,
    fund: u128,
) -> anyhow::Result<(Account, AccountId, SecretKey)> {
    let owner = sub(&env.root, name, fund + 20 * NEAR).await?;
    let device_sk = SecretKey::from_random(KeyType::ED25519);
    let mut a = args;
    a["device_public_key"] = json!(device_sk.public_key());
    let r = owner
        .call(env.factory.id(), "create_account")
        .args_json(a)
        .deposit(NearToken::from_yoctonear(fund))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?;
    println!(
        "create_account: ok={} burnt {:.2} TGas",
        r.is_success(),
        r.total_gas_burnt.as_gas() as f64 / 1e12
    );
    ok(r)?;
    let acc = env.account_for(owner.id()).await?;
    Ok((owner, acc, device_sk))
}

async fn place_buy(env: &Env, dev: &Account, acc: &AccountId, amount: u128) -> anyhow::Result<String> {
    let exp = env.now_ns().await? + 3_600_000_000_000;
    let r = okr(dev
        .call(acc, "place_order")
        .args_json(json!({"token_in": env.wrap.id(), "token_out": env.meme.id(), "amount_in": amount.to_string(),
            "min_out": "1", "trigger_meta": "{\"kind\":\"limit\"}", "expires_at_ns": exp.to_string(), "dexes": [env.rhea.id()]}))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?)?;
    Ok(r.json::<String>()?)
}

/// 24/7 limit BUY by the relayer, exactly as stored, charged in full to the weekly allowance.
#[tokio::test]
async fn v147_relayer_fires_limit_buy() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let u = env.user("rb", 5 * NEAR, (2 * NEAR, 5 * NEAR)).await?;
    let sk = SecretKey::from_random(KeyType::ED25519);
    ok(u.owner
        .call(&u.account, "owner_set_automation_key")
        .args_json(json!({"public_key": sk.public_key(), "allowance": (2 * NEAR).to_string()}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(50))
        .transact()
        .await?)?;
    // v1.4.8: no default weekly allowance; opt into the former 10 NEAR default
    ok(u.owner
        .call(&u.account, "owner_set_relayer_allowance")
        .args_json(json!({"weekly_yocto": (10 * NEAR).to_string()}))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?)?;
    let relayer = Account::from_secret_key(u.account.clone(), sk, &env.worker);
    let amount = NEAR / 10;
    let id = place_buy(&env, &u.device, &u.account, amount).await?;
    let r = relayer
        .call(&u.account, "execute_order")
        .args_json(json!({"order_id": id, "ops": env.buy_ops(amount, 1, true)}))
        .gas(Gas::from_tgas(250))
        .transact()
        .await?;
    println!(
        "relayer buy: ok={} {:?}",
        r.is_success(),
        r.clone().into_result().err().map(|e| format!("{e:?}").chars().take(200).collect::<String>())
    );
    assert!(r.is_success(), "the relayer could not fire a limit buy");
    assert!(r.logs().iter().any(|l| l.contains("order_filled")), "{:?}", r.logs());
    assert!(env.ft_balance(env.meme.id(), &u.account).await? > 0);
    let w: Value = env.worker.view(&u.account, "get_relayer_week").await?.json()?;
    let spent: u128 = w["spent_yocto"].as_str().unwrap().parse()?;
    println!("weekly spent {spent} for a {amount} buy");
    assert!(spent > amount + fee(amount), "weekly allowance not charged with the buy's spend");
    Ok(())
}

/// No caps passed: the account has no cap (u128::MAX) and trades large amounts.
#[tokio::test]
async fn v147_create_account_without_caps_is_unlimited() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let (_owner, acc, sk) = create(&env, "nocap", json!({}), 20 * NEAR).await?;
    let cfg = env.config(&acc).await?;
    println!("caps = {}", cfg["caps"]);
    assert_eq!(cfg["caps"], json!({"max_trade_yocto": MAX, "daily_cap_yocto": MAX}));
    let dev = Account::from_secret_key(acc.clone(), sk, &env.worker);
    let amt = 12 * NEAR;
    let r = env.exec(&dev, &acc, env.buy_ops(amt, 1, true), "big", amt + fee(amt) + NEAR).await?;
    assert!(r.is_success(), "{:?}", r.clone().into_result().err());
    let wd: Value = env.worker.view(&acc, "get_withdraw_day").await?.json()?;
    assert_eq!(wd["cap_yocto"], MAX);
    Ok(())
}

/// One owner signature creates the account AND installs the automation key (24/7 on).
#[tokio::test]
async fn v147_create_account_with_automation_key() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let ak = SecretKey::from_random(KeyType::ED25519);
    let (_owner, acc, sk) = create(
        &env,
        "onesig",
        json!({"automation": {"public_key": ak.public_key(), "allowance": NEAR.to_string(),
            "weekly_yocto": (5 * NEAR).to_string()}}),
        5 * NEAR,
    )
    .await?;
    env.worker.fast_forward(3).await?;
    let keys = env.access_keys(&acc).await?;
    let entry = keys.iter().find(|k| k["public_key"] == ak.public_key().to_string()).cloned();
    println!("automation key on chain: {entry:?}");
    let entry = entry.expect("automation key not installed");
    assert_eq!(entry["access_key"]["permission"]["FunctionCall"]["method_names"], json!(["execute_order"]));
    let got: Value = env.worker.view(&acc, "get_automation_key").await?.json()?;
    assert_eq!(got, json!(ak.public_key().to_string()));
    let set: Value = env.worker.view(&acc, "get_relayer_keys").await?.json()?;
    assert_eq!(set, json!([ak.public_key().to_string()]));
    let w: Value = env.worker.view(&acc, "get_relayer_week").await?.json()?;
    assert_eq!(w["allowance_yocto"], (5 * NEAR).to_string());
    // and it fires a stored limit buy
    let dev = Account::from_secret_key(acc.clone(), sk, &env.worker);
    let id = place_buy(&env, &dev, &acc, NEAR / 10).await?;
    let relayer = Account::from_secret_key(acc.clone(), ak, &env.worker);
    ok(relayer
        .call(&acc, "execute_order")
        .args_json(json!({"order_id": id, "ops": env.buy_ops(NEAR / 10, 1, true)}))
        .gas(Gas::from_tgas(250))
        .transact()
        .await?)?;
    // a device key can't double as the relayer
    let owner2 = sub(&env.root, "dup", 10 * NEAR).await?;
    let k = SecretKey::from_random(KeyType::ED25519);
    let r = owner2
        .call(env.factory.id(), "create_account")
        .args_json(json!({"device_public_key": k.public_key(), "automation": {"public_key": k.public_key(), "allowance": NEAR.to_string()}}))
        .deposit(NearToken::from_near(2))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?;
    fails_with(&r, "E_BAD_KEYS");
    Ok(())
}
