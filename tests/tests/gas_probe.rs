//! Gas probe (ignored): burnt gas of representative calls, for comparing two builds
//! (NT_ACCOUNT_WASM / NT_FACTORY_WASM). Used for the v1.4.2 wee_alloc removal.
//! `cargo test -p integration-tests --test gas_probe -- --ignored --nocapture`
use integration_tests::*;
use near_workspaces::types::{Gas, NearToken};
use serde_json::json;

fn tg(r: &near_workspaces::result::ExecutionFinalResult) -> f64 {
    r.total_gas_burnt.as_gas() as f64 / 1e12
}

#[tokio::test]
#[ignore]
async fn gas_probe() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let owner = sub(&env.root, "gp", 30 * NEAR).await?;
    let sk = near_workspaces::types::SecretKey::from_random(near_workspaces::types::KeyType::ED25519);
    let r = owner
        .call(env.factory.id(), "create_account")
        .args_json(json!({"device_public_key": sk.public_key(), "caps": caps_json((5 * NEAR, 10 * NEAR))}))
        .deposit(NearToken::from_near(10))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?;
    let create = tg(&r);
    ok(r)?;
    let acc = env.account_for(owner.id()).await?;
    let dev = near_workspaces::Account::from_secret_key(acc.clone(), sk, &env.worker);
    let buy = env.exec(&dev, &acc, env.buy_ops(NEAR, 1, true), "b1", 2 * NEAR).await?;
    let (buy_g, _) = (tg(&buy), ok(buy)?);
    let held = env.ft_balance(env.meme.id(), &acc).await?;
    let sell = env.exec(&dev, &acc, env.sell_ops(held / 2, 1, false), "s1", NEAR).await?;
    let (sell_g, _) = (tg(&sell), ok(sell)?);
    let exp = env.now_ns().await? + 3_600_000_000_000;
    let r = dev
        .call(&acc, "place_order")
        .args_json(
            json!({"token_in": env.wrap.id(), "token_out": env.meme.id(), "amount_in": "1000", "min_out": "1",
            "trigger_meta": "{}", "expires_at_ns": exp.to_string(), "dexes": [env.rhea.id()]}),
        )
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;
    let place = tg(&r);
    let oid: String = okr(r)?.json()?;
    let r = dev
        .call(&acc, "cancel_order")
        .args_json(json!({"order_id": oid}))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;
    let cancel = tg(&r);
    ok(r)?;
    let r = dev
        .call(&acc, "withdraw_to_owner")
        .args_json(json!({"token": env.meme.id(), "amount": "1"}))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?;
    let wto = tg(&r);
    ok(r)?;
    let r = owner
        .call(&acc, "owner_set_caps")
        .args_json(json!({"caps": caps_json((6 * NEAR, 12 * NEAR))}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;
    let setcaps = tg(&r);
    ok(r)?;
    let r = owner
        .call(&acc, "owner_withdraw_all")
        .args_json(json!({"to": owner.id(), "tokens": [env.meme.id()]}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(300))
        .transact()
        .await?;
    let wall = tg(&r);
    ok(r)?;
    println!(
        "GAS_PROBE create_account {create:.3} | execute buy {buy_g:.3} | execute sell {sell_g:.3} | place_order {place:.3} | cancel_order {cancel:.3} | withdraw_to_owner(ft) {wto:.3} | owner_set_caps(raise) {setcaps:.3} | owner_withdraw_all {wall:.3} TGas"
    );
    // per-deploy cost: a global deploy of fresh code (the upgrade-test build: same code, a
    // different hash), paid by the deployer (storage burn + gas); scaled per byte.
    let code = out("trading_account_upgrade_test");
    let (len, d0) = (code.len(), env.near_balance(env.deployer.id()).await?);
    env.deploy_global(code).await?;
    let d1 = env.near_balance(env.deployer.id()).await?;
    println!(
        "GAS_PROBE global deploy {len} B: deployer paid {:.4} NEAR ({:.3e} yocto/B)",
        (d0 - d1) as f64 / 1e24,
        (d0 - d1) as f64 / len as f64
    );
    Ok(())
}
