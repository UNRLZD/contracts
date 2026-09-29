//! Every E_ code of the trading account on-chain (sandbox), plus device-key restrictions
//! (invariants 2 and 5) and bounded seen_orders (invariants 3 and 6).
use integration_tests::*;
use near_workspaces::types::{Gas, KeyType, NearToken, SecretKey};
use near_workspaces::Account;
use serde_json::json;

#[tokio::test]
async fn execute_error_codes_on_chain() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let u = env.user("pol", 10 * NEAR, (2 * NEAR, 5 * NEAR)).await?;
    let (d, acc) = (&u.device, &u.account);
    let now = env.now_ns().await?;
    let buy = env.buy_ops(NEAR, 1, false);
    let max = NEAR + fee(NEAR);

    // E_NOT_SELF: the owner's wallet calling execute directly (predecessor != self)
    fails_with(&env.exec(&u.owner, acc, buy.clone(), "a", max).await?, "E_NOT_SELF");
    // E_EXPIRED / E_EXPIRY_TOO_FAR
    fails_with(&env.exec_at(d, acc, buy.clone(), "a", max, now - 1).await?, "E_EXPIRED");
    fails_with(&env.exec_at(d, acc, buy.clone(), "a", max, now + 300_000_000_000).await?, "E_EXPIRY_TOO_FAR");
    // E_BAD_ORDER_ID
    fails_with(&env.exec(d, acc, buy.clone(), &"x".repeat(65), max).await?, "E_BAD_ORDER_ID");
    fails_with(&env.exec(d, acc, buy.clone(), "", max).await?, "E_BAD_ORDER_ID");
    // E_BAD_OP: empty ops, zero wrap, oversize storage, token == self
    fails_with(&env.exec(d, acc, json!([]), "a", 0).await?, "E_BAD_OP");
    fails_with(&env.exec(d, acc, json!([{"NearDeposit": {"amount": "0"}}]), "a", 0).await?, "E_BAD_OP");
    let big_storage = json!([{"StorageDeposit": {"token": env.meme.id(), "amount": (12_500_000_000_000_000_000_001u128).to_string()}}]);
    fails_with(&env.exec(d, acc, big_storage, "a", NEAR).await?, "E_BAD_OP");
    let self_tok = json!([{"StorageDeposit": {"token": acc, "amount": "1"}}]);
    fails_with(&env.exec(d, acc, self_tok, "a", NEAR).await?, "E_BAD_OP");
    // E_BAD_DEX: receiver not allowlisted
    let mut bad = buy.clone();
    bad[1]["FtTransferCall"]["receiver_id"] = json!(env.fees.id());
    fails_with(&env.exec(d, acc, bad, "a", max).await?, "E_BAD_DEX");
    // E_BAD_MSG / E_RECIPIENT / E_MIN_OUT
    let mut bad = buy.clone();
    bad[1]["FtTransferCall"]["msg"] = json!("{\"actions\":[],\"force\":0}");
    fails_with(&env.exec(d, acc, bad, "a", max).await?, "E_BAD_MSG");
    let mut bad = buy.clone();
    let m = bad[1]["FtTransferCall"]["msg"]
        .as_str()
        .unwrap()
        .replace("\"force\":0", &format!("\"force\":0,\"swap_out_recipient\":\"{}\"", env.fees.id()));
    bad[1]["FtTransferCall"]["msg"] = json!(m);
    fails_with(&env.exec(d, acc, bad, "a", max).await?, "E_RECIPIENT");
    fails_with(&env.exec(d, acc, env.buy_ops(NEAR, 0, false), "a", max).await?, "E_MIN_OUT");
    // E_CAP_TRADE: spend > max_in, and max_in > caps.max_trade
    fails_with(&env.exec(d, acc, buy.clone(), "a", NEAR).await?, "E_CAP_TRADE");
    fails_with(&env.exec(d, acc, env.buy_ops(NEAR / 10, 1, false), "a", 2 * NEAR + 1).await?, "E_CAP_TRADE");
    // E_GAS: >4 ops, and op gas > prepaid - 15T
    let five: Vec<_> = (0..5).map(|_| json!({"NearDeposit": {"amount": "1"}})).collect();
    fails_with(&env.exec(d, acc, json!(five), "a", 0).await?, "E_GAS");
    let mut bad = buy.clone();
    bad[1]["FtTransferCall"]["gas"] = json!((283 * TGAS).to_string());
    fails_with(&env.exec(d, acc, bad, "a", max).await?, "E_GAS");
    // E_BAD_OP: two swaps in one execute (v1.1: one swap, last)
    let half = (u128::MAX / 2 + 1).to_string();
    let leg = |amt: &str| {
        json!({"FtTransferCall": {"token": env.wrap.id(), "receiver_id": env.rhea.id(), "amount": amt,
        "msg": env.rhea_msg(env.wrap.id(), env.meme.id(), 1, 1, false), "gas": (10 * TGAS).to_string()}})
    };
    fails_with(&env.exec(d, acc, json!([leg(&half), leg(&half)]), "a", u128::MAX).await?, "E_BAD_OP");
    // E_OVERFLOW: native outflow of two wraps summing past u128
    let wrap_half = json!({"NearDeposit": {"amount": half}});
    fails_with(&env.exec(d, acc, json!([wrap_half, wrap_half]), "a", 0).await?, "E_OVERFLOW");
    // nothing above consumed an order id or cap
    let seen: bool = env.worker.view(acc, "is_order_seen").args_json(json!({"id": "a"})).await?.json()?;
    assert!(!seen);
    assert_eq!(env.day_spent(&u).await?, 0);

    // E_DUPLICATE: first succeeds, replay with a fresh tx fails
    ok(env
        .exec(d, acc, env.buy_ops(NEAR / 10, 1, true), "dup", NEAR / 10 + fee(NEAR / 10) + STORAGE)
        .await?)?;
    fails_with(&env.exec(d, acc, env.buy_ops(NEAR / 10, 1, false), "dup", NEAR).await?, "E_DUPLICATE");
    // E_CAP_DAILY: 5 NEAR/day; spend 1.8 + 1.8 then 1.8 fails
    let spent0 = env.day_spent(&u).await?;
    for i in 0..2 {
        ok(env.exec(d, acc, env.buy_ops(18 * NEAR / 10, 1, false), &format!("c{i}"), 2 * NEAR).await?)?;
    }
    assert_eq!(env.day_spent(&u).await?, spent0 + 2 * (18 * NEAR / 10 + fee(18 * NEAR / 10)));
    fails_with(
        &env.exec(d, acc, env.buy_ops(18 * NEAR / 10, 1, false), "c3", 2 * NEAR).await?,
        "E_CAP_DAILY",
    );
    Ok(())
}

#[tokio::test]
async fn reserve_and_withdraw_codes() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let u = env.user("res", NEAR, (100 * NEAR, 100 * NEAR)).await?;
    let (d, acc) = (&u.device, &u.account);
    let bal = env.near_balance(acc).await?;
    // E_RESERVE: wrapping + fee would leave < 0.05 NEAR
    let amt = bal - RESERVE;
    fails_with(&env.exec(d, acc, env.buy_ops(amt, 1, false), "r1", 100 * NEAR).await?, "E_RESERVE");
    fails_with(
        &env.exec(d, acc, json!([{"NearDeposit": {"amount": (bal - RESERVE / 2).to_string()}}]), "r2", 0)
            .await?,
        "E_RESERVE",
    );
    // withdraw_to_owner: E_RESERVE, E_BAD_OP, E_NOT_SELF
    let call = |who: &Account, args: serde_json::Value| {
        who.call(acc, "withdraw_to_owner").args_json(args).gas(Gas::from_tgas(50)).transact()
    };
    fails_with(&call(d, json!({"token": null, "amount": bal.to_string()})).await?, "E_RESERVE");
    fails_with(&call(d, json!({"token": acc, "amount": "1"})).await?, "E_BAD_OP");
    fails_with(&call(&u.owner, json!({"token": null, "amount": "1"})).await?, "E_NOT_SELF");
    // destination is fixed: an injected "to" is ignored or rejected, never honoured
    let evil = sub(&env.root, "evil", NEAR).await?;
    let (e0, o0) = (env.near_balance(evil.id()).await?, env.near_balance(u.owner.id()).await?);
    let r = call(d, json!({"token": null, "amount": (NEAR / 10).to_string(), "to": evil.id()})).await?;
    assert_eq!(env.near_balance(evil.id()).await?, e0);
    if r.is_success() {
        assert_eq!(env.near_balance(u.owner.id()).await? - o0, NEAR / 10);
    }
    // lower_caps: E_CAP_RAISE / E_NOT_SELF; lowering works
    let lc = |who: &Account, t: u128, dd: u128| {
        who.call(acc, "lower_caps").args_json(json!({"caps": caps_json((t, dd))})).transact()
    };
    fails_with(&lc(d, 101 * NEAR, NEAR).await?, "E_CAP_RAISE");
    fails_with(&lc(d, NEAR, 101 * NEAR).await?, "E_CAP_RAISE");
    fails_with(&lc(&u.owner, NEAR, NEAR).await?, "E_NOT_SELF");
    ok(lc(d, NEAR, 2 * NEAR).await?)?;
    assert_eq!(env.config(acc).await?["caps"], caps_json((NEAR, 2 * NEAR)));
    Ok(())
}

#[tokio::test]
async fn owner_codes_and_device_key_restrictions() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let u = env.user("own", 5 * NEAR, (NEAR, 2 * NEAR)).await?;
    let (d, acc) = (&u.device, &u.account);
    let pk = SecretKey::from_random(KeyType::ED25519).public_key();
    let owner_calls = vec![
        ("owner_add_key", json!({"public_key": pk, "kind": "FunctionCall"})),
        ("owner_remove_key", json!({"public_key": u.device_sk.public_key()})),
        ("owner_withdraw", json!({"token": null, "amount": "1", "to": env.fees.id()})),
        ("owner_set_caps", json!({"caps": caps_json((100 * NEAR, 100 * NEAR))})),
        ("owner_upgrade", json!({"code_hash": env.code_hash})),
    ];
    let stranger = sub(&env.root, "stranger", 5 * NEAR).await?;
    for (m, args) in &owner_calls {
        // E_NOT_OWNER (stranger), E_ONE_YOCTO (owner without / with 2 yocto)
        let r = stranger
            .call(acc, m)
            .args_json(args.clone())
            .deposit(NearToken::from_yoctonear(1))
            .transact()
            .await?;
        fails_with(&r, "E_NOT_OWNER");
        let r = u.owner.call(acc, m).args_json(args.clone()).transact().await?;
        fails_with(&r, "E_ONE_YOCTO");
        let r = u
            .owner
            .call(acc, m)
            .args_json(args.clone())
            .deposit(NearToken::from_yoctonear(2))
            .transact()
            .await?;
        fails_with(&r, "E_ONE_YOCTO");
        // Invariant 2: the device key cannot call owner methods at all (runtime rejects)
        let r = d.call(acc, m).args_json(args.clone()).transact().await;
        let s = format!("{r:?}");
        assert!(s.contains("MethodNameMismatch"), "{m}: {}", &s[..s.len().min(300)]);
    }
    // v1.1: on_swap_settled is #[private] (external callers) and not a device method
    let settle = json!({"client_order_id": "x", "amount": "1", "counted": "1", "fee": "1", "day_start": "0"});
    for who in [&u.owner, &stranger] {
        let r = who.call(acc, "on_swap_settled").args_json(settle.clone()).transact().await?;
        assert!(format!("{:?}", r.into_result().err()).contains("Method on_swap_settled is private"));
    }
    // device key can't call migrate/init/on_swap_settled, nor attach a deposit
    for m in ["migrate", "init", "get_config", "on_swap_settled"] {
        let s = format!("{:?}", d.call(acc, m).args_json(json!({})).transact().await);
        assert!(s.contains("MethodNameMismatch"), "{m}");
    }
    let s = format!(
        "{:?}",
        d.call(acc, "execute").args_json(json!({})).deposit(NearToken::from_yoctonear(1)).transact().await
    );
    assert!(s.contains("DepositWithFunctionCall") || s.contains("deposit"), "{}", &s[..s.len().min(300)]);
    // no full-access key variant exists
    let r = u
        .owner
        .call(acc, "owner_add_key")
        .args_json(json!({"public_key": pk, "kind": "FullAccess"}))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?;
    assert!(r.is_failure());
    // Invariant 5: only function-call keys on the account
    for k in env.access_keys(acc).await? {
        let p = &k["access_key"]["permission"];
        assert!(p.get("FunctionCall").is_some(), "unexpected key {k}");
        assert_eq!(p["FunctionCall"]["receiver_id"], json!(acc));
    }
    Ok(())
}

/// E_ORDERS_FULL on-chain: 256 unexpired orders (sent from 8 parallel device keys so they
/// land within the 120 s expiry window), then the 257th is rejected; after expiry, accepted.
#[tokio::test]
async fn seen_orders_capacity_on_chain() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let u = env.user("cap", 10 * NEAR, (NEAR, 2 * NEAR)).await?;
    let acc = u.account.clone();
    let mut devices = vec![u.device.clone()];
    for _ in 0..7 {
        let sk = SecretKey::from_random(KeyType::ED25519);
        ok(u.owner
            .call(&acc, "owner_add_key")
            .args_json(json!({"public_key": sk.public_key(), "kind": "FunctionCall"}))
            .deposit(NearToken::from_yoctonear(1))
            .transact()
            .await?)?;
        devices.push(Account::from_secret_key(acc.clone(), sk, &env.worker));
    }
    let exp = env.now_ns().await? + 119_000_000_000;
    let tiny = json!([{"NearDeposit": {"amount": "1"}}]);
    let t0 = std::time::Instant::now();
    let mut tasks = vec![];
    for (k, dev) in devices.into_iter().enumerate() {
        let (acc, tiny) = (acc.clone(), tiny.clone());
        tasks.push(tokio::spawn(async move {
            for i in 0..32 {
                let r = dev.call(&acc, "execute")
                    .args_json(json!({"ops": tiny, "client_order_id": format!("k{k}-{i}"), "expires_at_ns": exp.to_string(), "max_in_yocto": "0"}))
                    .gas(Gas::from_tgas(30)).transact().await.unwrap();
                assert!(r.is_success(), "k{k}-{i}: {:?}", r.into_result().err());
            }
        }));
    }
    for t in tasks {
        t.await?;
    }
    println!("256 executes in {:?}", t0.elapsed());
    let r = env.exec_at(&u.device, &acc, tiny.clone(), "overflow", 0, exp).await?;
    fails_with(&r, "E_ORDERS_FULL");
    // storage stays bounded: 256 entries of <=64-byte ids
    let usage = env.worker.view_account(&acc).await?.storage_usage;
    println!("storage_usage with 256 seen orders: {usage} bytes");
    assert!(usage < 30_000);
    // after they expire, new orders are accepted and old entries evicted
    while env.now_ns().await? <= exp {
        env.worker.fast_forward(20).await?;
    }
    assert!(env.exec(&u.device, &acc, tiny, "after", 0).await?.is_success());
    let usage2 = env.worker.view_account(&acc).await?.storage_usage;
    println!("storage_usage after eviction: {usage2} bytes");
    assert!(usage2 < usage);
    Ok(())
}
