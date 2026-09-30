//! v1.3 automated orders (24/7): sandbox invariants against real Rhea + wrap.near.
//! (a) the automation key can ONLY call execute_order
//! (b) execute_order enforces the order's stored min_out / token_in / amount_in
//! (c) bounded order count; order amounts count toward caps only when executed
//! (d) cancel / revoke take effect before in-flight settlement (no fill or reopen after cancel)
//! (e) exactly-once per order under concurrent execute_order calls
//! plus: v1.2 -> v1.3 upgrade keeps state and trading; factory with several device keys.
//! v1.4.1 (D6): the automation key (relayer) is SELL-only; BUY orders are executed by a device
//! key (tab runner), so (b)-(e) fire their buy orders through the device key.
use integration_tests::*;
use near_workspaces::types::{Gas, KeyType, NearToken, SecretKey};
use near_workspaces::Account;
use serde_json::{json, Value};

async fn automation(env: &Env, u: &User) -> anyhow::Result<Account> {
    let sk = SecretKey::from_random(KeyType::ED25519);
    ok(u.owner
        .call(&u.account, "owner_set_automation_key")
        .args_json(json!({"public_key": sk.public_key(), "allowance": NEAR.to_string()}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(50))
        .transact()
        .await?)?;
    Ok(Account::from_secret_key(u.account.clone(), sk, &env.worker))
}

async fn place(env: &Env, u: &User, amount: u128, min_out: u128) -> anyhow::Result<u64> {
    let exp = env.now_ns().await? + 3_600_000_000_000;
    let r = okr(u.device.call(&u.account, "place_order")
        .args_json(json!({"token_in": env.wrap.id(), "token_out": env.meme.id(), "amount_in": amount.to_string(), "min_out": min_out.to_string(),
            "trigger_meta": "{\"kind\":\"limit\"}", "expires_at_ns": exp.to_string(), "dexes": [env.rhea.id()]}))
        .gas(Gas::from_tgas(30)).transact().await?)?;
    let id: String = r.json()?;
    Ok(id.parse()?)
}

/// Router-shaped buy ops for an order (the executor builds exactly this).
fn order_ops(env: &Env, amount: u128, min_out: u128) -> Value {
    env.buy_ops(amount, min_out, true)
}

/// v1.4.1 (D6): buy orders run through a device key (tab runner).
fn runner(u: &User) -> Account {
    u.device.clone()
}

async fn exec_order(
    auto: &Account,
    u: &User,
    id: u64,
    ops: Value,
) -> anyhow::Result<near_workspaces::result::ExecutionFinalResult> {
    Ok(auto
        .call(&u.account, "execute_order")
        .args_json(json!({"order_id": id.to_string(), "ops": ops}))
        .gas(Gas::from_tgas(300))
        .transact()
        .await?)
}

async fn order(env: &Env, u: &User, id: u64) -> anyhow::Result<Value> {
    Ok(env
        .worker
        .view(&u.account, "get_order")
        .args_json(json!({"order_id": id.to_string()}))
        .await?
        .json()?)
}

fn method_mismatch<T: std::fmt::Debug>(r: &T) -> bool {
    format!("{r:?}").contains("MethodNameMismatch")
}

#[tokio::test]
async fn a_automation_key_only_execute_order() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let u = env.user("oa", 3 * NEAR, (NEAR, 2 * NEAR)).await?;
    let auto = automation(&env, &u).await?;
    let id = place(&env, &u, NEAR / 10, 1).await?;
    let pk = SecretKey::from_random(KeyType::ED25519).public_key();
    let calls = [
        (
            "execute",
            json!({"ops": env.buy_ops(NEAR / 10, 1, false), "client_order_id": "x", "expires_at_ns": (env.now_ns().await? + 60_000_000_000).to_string(), "max_in_yocto": NEAR.to_string()}),
        ),
        ("withdraw_to_owner", json!({"token": null, "amount": "1"})),
        ("lower_caps", json!({"caps": caps_json((1, 1))})),
        ("place_order", json!({})),
        ("cancel_order", json!({"order_id": id.to_string()})),
        ("revoke_automation", json!({})),
        ("withdraw_cross_chain", json!({})),
        ("remove_withdraw_destination", json!({"dest_id": 0})),
        ("withdraw_from_intents", json!({})),
        ("owner_add_key", json!({"public_key": pk, "kind": "FunctionCall"})),
        ("owner_withdraw", json!({"token": null, "amount": "1", "to": env.fees.id()})),
        ("owner_set_caps", json!({"caps": caps_json((100 * NEAR, 100 * NEAR))})),
        ("owner_set_automation_key", json!({"public_key": pk, "allowance": NEAR.to_string()})),
        ("owner_upgrade", json!({"code_hash": env.code_hash})),
        ("on_swap_settled", json!({})),
        ("migrate", json!({})),
    ];
    for (m, args) in calls {
        let r = auto.call(&u.account, m).args_json(args).gas(Gas::from_tgas(100)).transact().await;
        assert!(method_mismatch(&r), "automation key reached {m}: {:?}", r.map(|x| x.is_success()));
    }
    // the key is a FunctionCall key with a bounded allowance (gas burn bound)
    let keys = env.access_keys(&u.account).await?;
    let ak = keys
        .iter()
        .find(|k| k["access_key"]["permission"]["FunctionCall"]["method_names"] == json!(["execute_order"]))
        .expect("automation key");
    assert_eq!(ak["access_key"]["permission"]["FunctionCall"]["allowance"], json!(NEAR.to_string()));
    // it reaches execute_order. v1.4.7: a BUY order fires (weekly-charged; tests/v147.rs); at a 0
    // weekly allowance it is refused with E_RELAYER_WEEKLY (was E_RELAYER_SELL_ONLY)
    ok(u.owner
        .call(&u.account, "owner_set_relayer_allowance")
        .args_json(json!({"weekly_yocto": "0"}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?)?;
    fails_with(&exec_order(&auto, &u, id, order_ops(&env, NEAR / 10, 1)).await?, "E_RELAYER_WEEKLY");
    Ok(())
}

#[tokio::test]
async fn b_execute_order_enforces_stored_terms() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let u = env.user("ob", 3 * NEAR, (NEAR, 2 * NEAR)).await?;
    let auto = runner(&u);
    let quote = env.expected_out(env.wrap.id(), NEAR / 2, env.meme.id()).await?;
    let min = quote * 95 / 100;
    let id = place(&env, &u, NEAR / 2, min).await?;
    let before = order(&env, &u, id).await?;
    // lower min_out, different amount, different output token, sell instead of buy
    fails_with(&exec_order(&auto, &u, id, order_ops(&env, NEAR / 2, min - 1)).await?, "E_ORDER_MIN_OUT");
    fails_with(&exec_order(&auto, &u, id, order_ops(&env, NEAR / 3, min)).await?, "E_ORDER_MISMATCH");
    let mut other = order_ops(&env, NEAR / 2, min);
    let m = env.rhea_msg(env.wrap.id(), env.fees.id(), NEAR / 2, min, false);
    other[2]["FtTransferCall"]["msg"] = json!(m);
    fails_with(&exec_order(&auto, &u, id, other).await?, "E_ORDER_MISMATCH");
    fails_with(&exec_order(&auto, &u, id, env.sell_ops(1000, min, false)).await?, "E_ORDER_MISMATCH");
    // extra non-order ops (a withdrawal) are refused
    let mut extra = order_ops(&env, NEAR / 2, min);
    extra.as_array_mut().unwrap().insert(0, json!({"NearWithdraw": {"amount": "1"}}));
    fails_with(&exec_order(&auto, &u, id, extra).await?, "E_ORDER_OPS");
    // the stored order is unchanged (rejected attempts roll back; there is no update API)
    assert_eq!(order(&env, &u, id).await?, before);
    // the real fill honours the stored min_out
    let r = okr(exec_order(&auto, &u, id, order_ops(&env, NEAR / 2, min)).await?)?;
    assert!(r.logs().iter().any(|l| l.contains("order_filled")), "{:?}", r.logs());
    assert!(env.ft_balance(env.meme.id(), &u.account).await? >= min);
    assert!(order(&env, &u, id).await?.is_null());
    Ok(())
}

#[tokio::test]
async fn c_bounded_orders_and_caps_at_execution() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let u = env.user("oc", 5 * NEAR, (NEAR, 2 * NEAR)).await?;
    let auto = runner(&u);
    // orders spend nothing when placed, even far beyond the caps
    let big = place(&env, &u, 3 * NEAR, 1).await?;
    assert_eq!(env.day_spent(&u).await?, 0);
    // ...and are capped when executed
    fails_with(&exec_order(&auto, &u, big, order_ops(&env, 3 * NEAR, 1)).await?, "E_CAP_TRADE");
    let small = place(&env, &u, NEAR / 2, 1).await?;
    ok(exec_order(&auto, &u, small, order_ops(&env, NEAR / 2, 1)).await?)?;
    assert_eq!(env.day_spent(&u).await?, NEAR / 2 + fee(NEAR / 2) + STORAGE, "counted when executed");
    // bounded: at most 64 open orders
    let open: Vec<Value> = env.worker.view(&u.account, "get_orders").await?.json()?;
    for _ in open.len()..64 {
        place(&env, &u, 1, 1).await?;
    }
    let exp = env.now_ns().await? + 3_600_000_000_000;
    let r = u
        .device
        .call(&u.account, "place_order")
        .args_json(
            json!({"token_in": env.wrap.id(), "token_out": env.meme.id(), "amount_in": "1", "min_out": "1",
            "trigger_meta": "", "expires_at_ns": exp.to_string(), "dexes": [env.rhea.id()]}),
        )
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;
    fails_with(&r, "E_ORDER_LIMIT");
    let usage = env.worker.view_account(&u.account).await?.storage_usage;
    println!("storage with 64 open orders: {usage} bytes");
    assert!(usage < 40_000);
    Ok(())
}

#[tokio::test]
async fn d_cancel_and_revoke_before_settlement() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let u = env.user("od", 5 * NEAR, (NEAR, 3 * NEAR)).await?;
    let auto = automation(&env, &u).await?;
    // an unreachable min_out: the swap fails (E68) and settlement would REOPEN the order,
    // but a cancel that lands first must win: no reopen, no fill.
    let quote = env.expected_out(env.wrap.id(), NEAR / 2, env.meme.id()).await?;
    let id = place(&env, &u, NEAR / 2, quote * 2).await?;
    let (auto2, u_acc) = (runner(&u), u.account.clone());
    let ops = order_ops(&env, NEAR / 2, quote * 2);
    let fire = tokio::spawn(async move {
        auto2
            .call(&u_acc, "execute_order")
            .args_json(json!({"order_id": id.to_string(), "ops": ops}))
            .gas(Gas::from_tgas(300))
            .transact()
            .await
    });
    // cancel concurrently (device key)
    let cancel = u
        .device
        .call(&u.account, "cancel_order")
        .args_json(json!({"order_id": id.to_string()}))
        .transact()
        .await?;
    let r = fire.await??;
    println!("execute_order ok={} cancel ok={}", r.is_success(), cancel.is_success());
    assert!(cancel.is_success() || r.is_success());
    // whatever the interleaving: the order is gone and never reopened / filled after cancel
    assert!(order(&env, &u, id).await?.is_null());
    assert!(
        !r.logs().iter().any(|l| l.contains("order_reopened") || l.contains("order_filled"))
            || !cancel.is_success(),
        "settled an order after its cancel: {:?}",
        r.logs()
    );
    // cancelled orders can't be executed
    fails_with(&exec_order(&runner(&u), &u, id, order_ops(&env, NEAR / 2, quote * 2)).await?, "E_NO_ORDER");
    // owner cancel (wallet, 1 yocto) works too
    let id2 = place(&env, &u, NEAR / 10, 1).await?;
    ok(u.owner
        .call(&u.account, "cancel_order")
        .args_json(json!({"order_id": id2.to_string()}))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?)?;
    assert!(order(&env, &u, id2).await?.is_null());
    // revoke: the automation key is deleted; it can't execute anything afterwards
    let id3 = place(&env, &u, NEAR / 10, 1).await?;
    ok(u.device.call(&u.account, "revoke_automation").transact().await?)?;
    let r = exec_order(&auto, &u, id3, order_ops(&env, NEAR / 10, 1)).await;
    assert!(r.is_err() || r.unwrap().is_failure(), "revoked key still executes");
    assert_eq!(order(&env, &u, id3).await?["pending"], json!(false));
    let v: Option<String> = env.worker.view(&u.account, "get_automation_key").await?.json()?;
    assert!(v.is_none());
    Ok(())
}

#[tokio::test]
async fn e_exactly_once_under_concurrency() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let u = env.user("oe", 5 * NEAR, (2 * NEAR, 5 * NEAR)).await?;
    let auto = runner(&u);
    let id = place(&env, &u, NEAR / 2, 1).await?;
    // warm the automation key's nonce cache with one (rejected) call, so the concurrent txs
    // below get distinct nonces (a cold cache makes identical, RPC-deduplicated txs)
    fails_with(&exec_order(&auto, &u, id + 1, order_ops(&env, NEAR / 2, 1)).await?, "E_NO_ORDER");
    let mut tasks = vec![];
    let mut hashes = std::collections::HashSet::new();
    for _ in 0..6 {
        let (a, acc, ops) = (auto.clone(), u.account.clone(), order_ops(&env, NEAR / 2, 1));
        tasks.push(tokio::spawn(async move {
            a.call(&acc, "execute_order")
                .args_json(json!({"order_id": id.to_string(), "ops": ops}))
                .gas(Gas::from_tgas(300))
                .transact()
                .await
        }));
    }
    let mut filled = 0;
    let mut accepted = 0;
    for t in tasks {
        let r = t.await??;
        hashes.insert(r.outcome().transaction_hash);
        if r.is_failure() {
            // in flight -> E_ORDER_PENDING; already filled -> E_NO_ORDER
            let e = format!("{:?}", r.clone().into_result().err());
            assert!(e.contains("E_ORDER_PENDING") || e.contains("E_NO_ORDER"), "{e}");
        }
        if r.is_success() {
            accepted += 1;
        }
        if r.logs().iter().any(|l| l.contains("order_filled")) {
            filled += 1;
        }
    }
    println!("concurrent execute_order: {} distinct txs, accepted {accepted}, filled {filled}", hashes.len());
    assert_eq!(hashes.len(), 6, "txs must be distinct");
    assert_eq!(filled, 1, "order filled more than once");
    assert_eq!(accepted, 1);
    let spent = env.day_spent(&u).await?;
    assert_eq!(spent, NEAR / 2 + fee(NEAR / 2) + STORAGE, "spent once");
    Ok(())
}

/// v1.2 -> v1.3 via owner_upgrade: state preserved, old device key keeps trading, the order
/// methods need a re-keyed device (method lists are fixed at AddKey).
#[tokio::test]
async fn upgrade_from_v1_2_keeps_state() -> anyhow::Result<()> {
    let env = Env::new_with(Some(out("trading_account_v1_2")), Some(out("factory_v1_2"))).await?;
    let u = env.user("up", 3 * NEAR, (NEAR, 2 * NEAR)).await?;
    ok(env.exec(&u.device, &u.account, env.buy_ops(NEAR / 10, 1, true), "pre", NEAR).await?)?;
    let spent = env.day_spent(&u).await?;
    let v13 = env.deploy_global(out("trading_account")).await?;
    ok(u.owner
        .call(&u.account, "owner_upgrade")
        .args_json(json!({"code_hash": v13}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?)?;
    assert_eq!(env.global_hash(&u.account).await?, Some(v13));
    assert_eq!(env.config(&u.account).await?["version"], "1.5.0");
    assert_eq!(env.day_spent(&u).await?, spent);
    fails_with(
        &env.exec(&u.device, &u.account, env.buy_ops(NEAR / 10, 1, false), "pre", NEAR).await?,
        "E_DUPLICATE",
    );
    ok(env.exec(&u.device, &u.account, env.buy_ops(NEAR / 10, 1, false), "post", NEAR).await?)?;
    // old device key lacks place_order; re-key through the owner, then orders work
    let exp = (env.now_ns().await? + 3_600_000_000_000).to_string();
    let args = json!({"token_in": env.wrap.id(), "token_out": env.meme.id(), "amount_in": "1", "min_out": "1", "trigger_meta": "", "expires_at_ns": exp, "dexes": [env.rhea.id()]});
    assert!(method_mismatch(
        &u.device.call(&u.account, "place_order").args_json(args.clone()).transact().await
    ));
    let sk = SecretKey::from_random(KeyType::ED25519);
    ok(u.owner
        .call(&u.account, "owner_add_key")
        .args_json(json!({"public_key": sk.public_key(), "kind": "FunctionCall"}))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?)?;
    let dev2 = Account::from_secret_key(u.account.clone(), sk, &env.worker);
    ok(dev2.call(&u.account, "place_order").args_json(args).gas(Gas::from_tgas(30)).transact().await?)?;
    Ok(())
}

/// Factory: several device keys in the one create_account call (one owner signature).
#[tokio::test]
async fn factory_multiple_device_keys() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let owner = sub(&env.root, "multi", 5 * NEAR).await?;
    let sks: Vec<SecretKey> = (0..3).map(|_| SecretKey::from_random(KeyType::ED25519)).collect();
    let pks: Vec<_> = sks.iter().map(|k| k.public_key()).collect();
    let create = |args: Value| {
        owner
            .call(env.factory.id(), "create_account")
            .args_json(args)
            .deposit(NearToken::from_millinear(700))
            .gas(Gas::from_tgas(100))
            .transact()
    };
    fails_with(
        &create(json!({"device_public_keys": [], "caps": caps_json((NEAR, NEAR))})).await?,
        "E_BAD_KEYS",
    );
    fails_with(
        &create(json!({"device_public_keys": [pks[0], pks[0]], "caps": caps_json((NEAR, NEAR))})).await?,
        "E_BAD_KEYS",
    );
    let five: Vec<_> = (0..5).map(|_| SecretKey::from_random(KeyType::ED25519).public_key()).collect();
    fails_with(
        &create(json!({"device_public_keys": five, "caps": caps_json((NEAR, NEAR))})).await?,
        "E_BAD_KEYS",
    );
    ok(create(json!({"device_public_keys": pks, "caps": caps_json((NEAR, NEAR))})).await?)?;
    let acc = env.account_for(owner.id()).await?;
    let keys = env.access_keys(&acc).await?;
    assert_eq!(keys.len(), 3);
    for k in &keys {
        let p = &k["access_key"]["permission"]["FunctionCall"];
        assert_eq!(p["receiver_id"], json!(acc));
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
    }
    // every key trades
    for (i, sk) in sks.into_iter().enumerate() {
        let dev = Account::from_secret_key(acc.clone(), sk, &env.worker);
        ok(env.exec(&dev, &acc, json!([{"NearDeposit": {"amount": "1"}}]), &format!("k{i}"), 0).await?)?;
    }
    Ok(())
}
