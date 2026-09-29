//! v1.2: Rhea DCL storage, against the REAL DCL wasm (mainnet dclv2.ref-labs.near v2.3.13).
//! Verified: min registration 0.5 NEAR (E102 below), 0.4 of it (order/LP slots) withdrawable
//! at once, 0.1 stays; unregister refunds the sponsor (= the depositor); swaps work without
//! registration, but undeliverable output then goes to DCL's *locked* lostfound, whereas a
//! registered account gets it in its own inner balance (recoverable via DexWithdraw).
use integration_tests::*;
use near_workspaces::types::{Gas, NearToken};
use serde_json::json;

#[tokio::test]
async fn init_registers_lean_on_dcl_and_min_funding() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let mf: String = env.factory.view("min_funding").await?.json()?;
    assert_eq!(mf, (NEAR / 5 + NEAR / 2).to_string(), "0.2 + 0.5 per DCL-kind DEX");
    let owner = sub(&env.root, "poor", 5 * NEAR).await?;
    let r = owner.call(env.factory.id(), "create_account")
        .args_json(json!({"device_public_key": near_workspaces::types::SecretKey::from_random(near_workspaces::types::KeyType::ED25519).public_key(), "caps": caps_json((NEAR, NEAR))}))
        .deposit(NearToken::from_yoctonear(7 * NEAR / 10 - 1)).gas(Gas::from_tgas(100)).transact().await?;
    fails_with(&r, "E_MIN_FUNDING");
    let u = env.user("dclu", 7 * NEAR / 10, (NEAR, 2 * NEAR)).await?;
    assert_eq!(
        env.dcl_storage(&u.account).await?,
        json!({"total": (NEAR / 10).to_string(), "available": "0"})
    );
    let bal = env.near_balance(&u.account).await?;
    // v1.2.1: minus the factory entry storage (~0.00074 NEAR) kept by the factory
    let expect = 7 * NEAR / 10 - STORAGE - NEAR / 10 - NEAR / 1000;
    assert!(
        (expect..expect + NEAR / 1000).contains(&bal) || (expect..expect + 2 * NEAR / 1000).contains(&bal),
        "0.5 deposited, 0.4 returned: {bal}"
    );
    Ok(())
}

#[tokio::test]
async fn dcl_swap_fee_rescue_reclaim_reregister() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let pid = env.dcl_pool().await?;
    let u = env.user("dcls", 3 * NEAR, (NEAR, 3 * NEAR)).await?;
    let (d, acc) = (&u.device, &u.account);
    // 1. buy through real DCL, fee on success
    let f0 = env.near_balance(env.fees.id()).await?;
    let r = okr(env
        .exec(d, acc, env.dcl_buy_ops(&pid, NEAR / 2, 1, true), "b1", NEAR / 2 + fee(NEAR / 2) + STORAGE)
        .await?)?;
    assert!(r
        .logs()
        .iter()
        .any(|l| l.contains("\"settled\"") && l.contains("\"used\":\"500000000000000000000000\"")));
    assert!(env.ft_balance(env.meme.id(), acc).await? > 0);
    assert_eq!(env.near_balance(env.fees.id()).await? - f0, fee(NEAR / 2));

    // 2. undeliverable output (not registered on MEME) -> parked in our DCL inner balance
    let u2 = env.user("dcls2", 3 * NEAR, (NEAR, 3 * NEAR)).await?;
    let r = env.exec(&u2.device, &u2.account, env.dcl_buy_ops(&pid, NEAR / 2, 1, false), "b2", NEAR).await?;
    assert!(
        r.logs().iter().any(|l| l.contains("lostfound") && l.contains("\"locked\":false")),
        "{:?}",
        r.logs()
    );
    let inner: serde_json::Value = env
        .worker
        .view(env.dcl.id(), "list_user_assets")
        .args_json(json!({"account_id": u2.account}))
        .await?
        .json()?;
    let parked: u128 = inner[env.meme.id().as_str()].as_str().unwrap().parse()?;
    assert!(parked > 0);
    //    rescue: register on MEME, DexWithdraw (to self, not spend)
    let spent = env.day_spent(&u2).await?;
    // (v1.2.1: registering on a token is allowed in the same execute that recovers it)
    let ops = json!([{"StorageDeposit": {"token": env.meme.id(), "amount": STORAGE.to_string()}},
        {"DexWithdraw": {"dex": env.dcl.id(), "token": env.meme.id(), "amount": null}}]);
    ok(env.exec(&u2.device, &u2.account, ops, "rescue", STORAGE).await?)?;
    assert_eq!(env.ft_balance(env.meme.id(), &u2.account).await?, parked);
    assert_eq!(env.day_spent(&u2).await?, spent + STORAGE, "withdraw not spend");

    // 3. owner reclaims DCL storage (0.1 back to the account); only the owner, only DCL-kind
    let b0 = env.near_balance(acc).await?;
    fails_with(
        &u.owner
            .call(acc, "owner_reclaim_dex_storage")
            .args_json(json!({"dex": env.rhea.id()}))
            .deposit(NearToken::from_yoctonear(1))
            .transact()
            .await?,
        "E_BAD_DEX",
    );
    let s = format!(
        "{:?}",
        d.call(acc, "owner_reclaim_dex_storage").args_json(json!({"dex": env.dcl.id()})).transact().await
    );
    assert!(s.contains("MethodNameMismatch"));
    ok(u.owner
        .call(acc, "owner_reclaim_dex_storage")
        .args_json(json!({"dex": env.dcl.id()}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(50))
        .transact()
        .await?)?;
    assert!(env.dcl_storage(acc).await?.is_null());
    let got = env.near_balance(acc).await? - b0;
    assert!(got > NEAR / 10 - NEAR / 1000, "0.1 NEAR returned to the account: {got}");

    // 4. device re-registers with DexStorageDeposit (pre-v1.2 path): spend 0.5, net lock 0.1
    let spent = env.day_spent(&u).await?;
    fails_with(
        &env.exec(d, acc, json!([{"DexStorageDeposit": {"dex": env.rhea.id()}}]), "x", NEAR).await?,
        "E_BAD_DEX",
    );
    ok(env.exec(d, acc, json!([{"DexStorageDeposit": {"dex": env.dcl.id()}}]), "re", NEAR / 2).await?)?;
    assert_eq!(env.dcl_storage(acc).await?, json!({"total": (NEAR / 10).to_string(), "available": "0"}));
    assert_eq!(env.day_spent(&u).await?, spent + NEAR / 2);
    // and the account still trades on DCL
    ok(env
        .exec(d, acc, env.dcl_buy_ops(&pid, NEAR / 10, 1, false), "b3", NEAR / 10 + fee(NEAR / 10))
        .await?)?;
    Ok(())
}
