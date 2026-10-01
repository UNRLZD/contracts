//! Owner flows: recovery on a fresh device key, gas keys (NEP-611), withdrawals, caps,
//! and the upgrade path via owner_upgrade.
use integration_tests::*;
use near_workspaces::types::{Gas, KeyType, NearToken, SecretKey};
use near_workspaces::Account;
use serde_json::json;

async fn owner_call(u: &User, m: &str, args: serde_json::Value) -> anyhow::Result<()> {
    ok(u.owner
        .call(&u.account, m)
        .args_json(args)
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?)
}

#[tokio::test]
async fn recovery_on_new_device_key_then_trade() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let u = env.user("rec", 5 * NEAR, (2 * NEAR, 5 * NEAR)).await?;
    // Device "lost" (browser storage evicted): owner removes the old key, adds a new one.
    owner_call(&u, "owner_remove_key", json!({"public_key": u.device_sk.public_key()})).await?;
    let new_sk = SecretKey::from_random(KeyType::ED25519);
    owner_call(&u, "owner_add_key", json!({"public_key": new_sk.public_key(), "kind": "FunctionCall"}))
        .await?;
    let keys = env.access_keys(&u.account).await?;
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["public_key"], json!(pk_str(&new_sk.public_key())));
    let p = &keys[0]["access_key"]["permission"]["FunctionCall"];
    assert_eq!(p["receiver_id"], json!(u.account));
    assert_eq!(
        p["method_names"],
        json!([
            "execute",
            "withdraw_to_owner",
            "lower_caps",
            "place_order",
            "cancel_order",
            "revoke_automation",
            "withdraw_cross_chain",
            "remove_withdraw_destination",
            "withdraw_from_intents",
            "execute_order"
        ])
    );
    assert!(p["allowance"].is_null());
    // old key can no longer sign
    let old = env.exec(&u.device, &u.account, env.buy_ops(NEAR / 10, 1, true), "old", NEAR).await;
    assert!(old.is_err() || old.unwrap().is_failure());
    // new key trades through real Rhea
    let dev2 = Account::from_secret_key(u.account.clone(), new_sk, &env.worker);
    let amt = NEAR / 2;
    let min = env.expected_out(env.wrap.id(), amt, env.meme.id()).await? * 98 / 100;
    ok(env.exec(&dev2, &u.account, env.buy_ops(amt, min, true), "new-1", amt + fee(amt) + STORAGE).await?)?;
    assert!(env.ft_balance(env.meme.id(), &u.account).await? >= min);
    Ok(())
}

/// v1.1: gas keys are compiled out (feature `gas-keys` off): owner_add_key(GasKey) is
/// rejected at argument parsing, so no gas key (whose balance DeleteKey would burn) can exist.
#[tokio::test]
async fn gas_key_kind_disabled() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let u = env.user("gk", 5 * NEAR, (NEAR, 2 * NEAR)).await?;
    let sk = SecretKey::from_random(KeyType::ED25519);
    let r = u
        .owner
        .call(&u.account, "owner_add_key")
        .args_json(json!({"public_key": sk.public_key(), "kind": {"GasKey": {"num_nonces": 16, "balance": (NEAR / 2).to_string()}}}))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?;
    assert!(format!("{:?}", r.into_result().err()).contains("Failed to deserialize input"));
    assert_eq!(env.access_keys(&u.account).await?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn withdrawals_and_caps() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let u = env.user("wd", 5 * NEAR, (NEAR, 2 * NEAR)).await?;
    let (d, acc) = (&u.device, &u.account);
    // get some MEME and wNEAR into the account
    let min = env.expected_out(env.wrap.id(), NEAR / 2, env.meme.id()).await? * 98 / 100;
    ok(env.exec(d, acc, env.buy_ops(NEAR / 2, min, true), "b", NEAR).await?)?;
    ok(env.exec(d, acc, json!([{"NearDeposit": {"amount": (NEAR / 4).to_string()}}]), "w", 0).await?)?;
    // withdraw_to_owner (device key): NEAR and FT land at the owner
    let o0 = env.near_balance(u.owner.id()).await?;
    ok(d.call(acc, "withdraw_to_owner")
        .args_json(json!({"token": null, "amount": (NEAR / 10).to_string()}))
        .transact()
        .await?)?;
    assert_eq!(env.near_balance(u.owner.id()).await? - o0, NEAR / 10);
    ok(u.owner
        .call(env.meme.id(), "storage_deposit")
        .args_json(json!({}))
        .deposit(NearToken::from_millinear(10))
        .transact()
        .await?)?;
    let m = env.ft_balance(env.meme.id(), acc).await?;
    ok(d.call(acc, "withdraw_to_owner")
        .args_json(json!({"token": env.meme.id(), "amount": (m / 2).to_string()}))
        .gas(Gas::from_tgas(50))
        .transact()
        .await?)?;
    assert_eq!(env.ft_balance(env.meme.id(), u.owner.id()).await?, m / 2);
    // owner_withdraw may send anywhere (NEAR + FT)
    let dest = sub(&env.root, "dest", NEAR).await?;
    let d0 = env.near_balance(dest.id()).await?;
    owner_call(&u, "owner_withdraw", json!({"token": null, "amount": NEAR.to_string(), "to": dest.id()}))
        .await?;
    assert_eq!(env.near_balance(dest.id()).await? - d0, NEAR);
    ok(dest
        .call(env.wrap.id(), "storage_deposit")
        .args_json(json!({}))
        .deposit(NearToken::from_yoctonear(STORAGE))
        .transact()
        .await?)?;
    // v1.3.2: wNEAR is unwrapped and arrives as native NEAR
    env.worker.fast_forward(5).await?; // dest's own gas refunds land first
    let n0 = env.near_balance(dest.id()).await?;
    owner_call(
        &u,
        "owner_withdraw",
        json!({"token": env.wrap.id(), "amount": (NEAR / 4).to_string(), "to": dest.id()}),
    )
    .await?;
    assert_eq!(env.ft_balance(env.wrap.id(), dest.id()).await?, 0);
    assert_eq!(env.near_balance(dest.id()).await? - n0, NEAR / 4);
    // owner may raise caps (v1.4.3: pending for 1 h, see v143.rs); device may only lower
    let before = env.config(acc).await?["caps"].clone();
    owner_call(&u, "owner_set_caps", json!({"caps": caps_json((10 * NEAR, 20 * NEAR))})).await?;
    assert_eq!(env.config(acc).await?["caps"], before);
    let p: serde_json::Value = env.worker.view(acc, "get_pending_caps").await?.json()?;
    assert_eq!(p["caps"], caps_json((10 * NEAR, 20 * NEAR)));
    ok(d.call(acc, "lower_caps").args_json(json!({"caps": caps_json((NEAR, NEAR))})).transact().await?)?;
    fails_with(
        &d.call(acc, "lower_caps").args_json(json!({"caps": caps_json((NEAR, 2 * NEAR))})).transact().await?,
        "E_CAP_RAISE",
    );
    Ok(())
}

#[tokio::test]
async fn upgrade_path_via_owner_upgrade() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let u = env.user("upg", 5 * NEAR, (2 * NEAR, 5 * NEAR)).await?;
    let (d, acc) = (&u.device, &u.account);
    ok(env.exec(d, acc, env.buy_ops(NEAR / 2, 1, true), "pre", NEAR).await?)?;
    let spent = env.day_spent(&u).await?;
    assert_eq!(env.global_hash(acc).await?, Some(env.code_hash.clone()));
    assert_eq!(env.config(acc).await?["version"], "1.6.0");

    let v2 = env.deploy_global(out("trading_account_upgrade_test")).await?;
    // only the owner, with 1 yocto; device key can't even call it
    let s =
        format!("{:?}", d.call(acc, "owner_upgrade").args_json(json!({"code_hash": v2})).transact().await);
    assert!(s.contains("MethodNameMismatch"));
    // factory set_code_hash does not move existing accounts
    ok(env
        .admin
        .call(env.factory.id(), "set_code_hash")
        .args_json(json!({"code_hash": v2}))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?)?;
    assert_eq!(env.global_hash(acc).await?, Some(env.code_hash.clone()));

    // R2-09: the owner doors wait out the "pre" swap's settle window (100 blocks)
    fails_with(
        &u.owner
            .call(acc, "owner_upgrade")
            .args_json(json!({"code_hash": v2}))
            .deposit(NearToken::from_yoctonear(1))
            .gas(Gas::from_tgas(100))
            .transact()
            .await?,
        "E_IN_FLIGHT",
    );
    env.worker.fast_forward(100).await?;
    owner_call(&u, "owner_upgrade", json!({"code_hash": v2})).await?;
    assert_eq!(env.global_hash(acc).await?, Some(v2.clone()));
    let cfg = env.config(acc).await?;
    assert_eq!(cfg["version"], "upgrade-test");
    assert_eq!(cfg["owner"], json!(u.owner.id()));
    assert_eq!(cfg["caps"], caps_json((2 * NEAR, 5 * NEAR)));
    assert_eq!(env.day_spent(&u).await?, spent);
    let seen: bool = env.worker.view(acc, "is_order_seen").args_json(json!({"id": "pre"})).await?.json()?;
    assert!(seen, "seen_orders preserved across migrate");
    // dedupe still enforced and trading continues on the new code with the same key
    fails_with(&env.exec(d, acc, env.buy_ops(NEAR / 10, 1, false), "pre", NEAR).await?, "E_DUPLICATE");
    ok(env.exec(d, acc, env.buy_ops(NEAR / 10, 1, false), "post", NEAR).await?)?;
    // bad hash: whole receipt fails atomically, code unchanged
    let r = u
        .owner
        .call(acc, "owner_upgrade")
        .args_json(json!({"code_hash": "11111111111111111111111111111111"}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?;
    assert!(!r.receipt_failures().is_empty());
    assert_eq!(env.global_hash(acc).await?, Some(v2));
    assert_eq!(env.config(acc).await?["version"], "upgrade-test");
    Ok(())
}
