//! Factory: create (one batch), E_EXISTS, E_MIN_FUNDING, refund on failure, admin codes.
use integration_tests::*;
use near_workspaces::types::{Gas, KeyType, NearToken, SecretKey};
use serde_json::json;
use sha2::{Digest, Sha256};

#[tokio::test]
async fn create_account_shape() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let u = env.user("fac", 2 * NEAR, (NEAR, 3 * NEAR)).await?;
    // name = hex16(sha256(owner)).factory
    let h = Sha256::digest(u.owner.id().as_bytes());
    let hex: String = h[..8].iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(u.account.as_str(), format!("{hex}.{}", env.factory.id()));
    assert_eq!(env.global_hash(&u.account).await?, Some(env.code_hash.clone()));
    let bal = env.near_balance(&u.account).await?;
    // whole deposit (+ small gas reward) minus the wNEAR registration paid from it in init
    // v1.2: also 0.1 NEAR locked on the DCL-kind DEX (0.5 deposited, 0.4 withdrawn)
    // v1.2.1: minus the factory entry storage (~0.00074 NEAR) kept by the factory
    let lo = 2 * NEAR - STORAGE - NEAR / 10 - NEAR / 1000;
    assert!((lo..lo + 2 * NEAR / 1000).contains(&bal), "whole deposit transferred: {bal}");
    let sb: serde_json::Value =
        env.wrap.view("storage_balance_of").args_json(json!({"account_id": u.account})).await?.json()?;
    assert_eq!(sb["total"], json!(STORAGE.to_string()), "v1.1: init registered the account on wNEAR");
    let cfg = env.config(&u.account).await?;
    assert_eq!(cfg["owner"], json!(u.owner.id()));
    assert_eq!(cfg["wrap"], json!(env.wrap.id()));
    assert_eq!(cfg["fee_bps"], json!(FEE_BPS));
    assert_eq!(cfg["fee_recipient"], json!(env.fees.id()));
    assert_eq!(cfg["dex_allowlist"].as_array().unwrap().len(), 3);
    assert_eq!(cfg["caps"], caps_json((NEAR, 3 * NEAR)));
    // exactly one key: FC, receiver self, DEVICE_METHODS, unlimited allowance
    let keys = env.access_keys(&u.account).await?;
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["public_key"], json!(pk_str(&u.device_sk.public_key())));
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
    let storage = env.worker.view_account(&u.account).await?.storage_usage;
    println!("trading account storage_usage after create: {storage} bytes");
    Ok(())
}

#[tokio::test]
async fn create_errors_and_refund() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let owner = sub(&env.root, "own2", 10 * NEAR).await?;
    let pk = SecretKey::from_random(KeyType::ED25519).public_key();
    let create = |dep: u128| {
        owner
            .call(env.factory.id(), "create_account")
            .args_json(json!({"device_public_key": pk, "caps": caps_json((NEAR, NEAR))}))
            .deposit(NearToken::from_yoctonear(dep))
            .gas(Gas::from_tgas(100))
            .transact()
    };
    fails_with(&create(NEAR / 5 - 1).await?, "E_MIN_FUNDING");

    // Refund on failure: point the factory at a hash with no global code.
    ok(env
        .admin
        .call(env.factory.id(), "set_code_hash")
        .args_json(json!({"code_hash": "11111111111111111111111111111111"}))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?)?;
    let b0 = env.near_balance(owner.id()).await?;
    let r = create(NEAR).await?;
    assert!(r.is_success(), "outer call + callback succeed");
    assert!(!r.receipt_failures().is_empty(), "create batch failed");
    assert!(r.logs().iter().any(|l| l.contains("\"create_failed\"")), "{:?}", r.logs());
    let v: Option<String> = r.json()?;
    assert!(v.is_none());
    let spent = b0 - env.near_balance(owner.id()).await?;
    assert!(spent < NEAR / 100, "deposit refunded, only gas spent: {spent}");
    let acct = env.account_for(owner.id()).await?;
    assert!(env.worker.view_account(&acct).await.is_err(), "account not created");
    // factory still solvent-neutral and the owner can retry once the hash is fixed
    ok(env
        .admin
        .call(env.factory.id(), "set_code_hash")
        .args_json(json!({"code_hash": env.code_hash}))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?)?;
    let r = create(NEAR).await?;
    ok(r.clone())?;
    assert!(r.logs().iter().any(|l| l.contains("\"account_created\"")));
    assert_eq!(r.json::<Option<String>>()?.as_deref(), Some(acct.as_str()));
    // E_EXISTS on a second create
    fails_with(&create(NEAR).await?, "E_EXISTS");
    Ok(())
}

#[tokio::test]
async fn factory_admin_codes() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let stranger = sub(&env.root, "str", 5 * NEAR).await?;
    fails_with(
        &stranger
            .call(env.factory.id(), "set_code_hash")
            .args_json(json!({"code_hash": env.code_hash}))
            .deposit(NearToken::from_yoctonear(1))
            .transact()
            .await?,
        "E_NOT_ADMIN",
    );
    let r = env
        .admin
        .call(env.factory.id(), "set_code_hash")
        .args_json(json!({"code_hash": env.code_hash}))
        .transact()
        .await?;
    assert!(r.is_failure());
    // fee_bps > 100 rejected at factory init
    let f2 = sub(&env.root, "tt2", 20 * NEAR).await?.deploy(&out("factory")).await?.into_result()?;
    let r = f2.call("new").args_json(json!({"admin": env.admin.id(), "code_hash": env.code_hash,
        "fee_config": {"fee_bps": 101, "fee_recipient": env.fees.id()}, "dex_allowlist": [], "wrap": env.wrap.id()})).transact().await?;
    fails_with(&r, "E_FEE");
    // set_code_hash only affects NEW accounts
    let u1 = env.user("early", NEAR, (NEAR, NEAR)).await?;
    let v2 = env.deploy_global(out("trading_account_upgrade_test")).await?;
    ok(env
        .admin
        .call(env.factory.id(), "set_code_hash")
        .args_json(json!({"code_hash": v2}))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?)?;
    let u2 = env.user("late", NEAR, (NEAR, NEAR)).await?;
    assert_eq!(env.global_hash(&u1.account).await?, Some(env.code_hash.clone()));
    assert_eq!(env.global_hash(&u2.account).await?, Some(v2));
    Ok(())
}
