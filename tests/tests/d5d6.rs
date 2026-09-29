//! v1.4.1 design changes (docs/design-gap-analysis.md):
//! D5: daily windows are UTC days (reset 00:00 UTC); a live pre-v1.4.1 rolling window's spend
//!     is carried into the current UTC day on upgrade.
//! D6: the automation key (24/7 relayer) is SELL-only (token_out == wrap) and bounded by a
//!     weekly allowance (Σ order.min_out per ISO week, owner-set, default 10 NEAR).
//! RED on v1.4.0 (NT_ACCOUNT_WASM / NT_FACTORY_WASM = out/*_v1_4_0.wasm), GREEN on v1.4.1.
use integration_tests::*;
use near_workspaces::types::{Gas, KeyType, NearToken, SecretKey};
use near_workspaces::Account;
use serde_json::{json, Value};

const DAY_NS: u64 = 86_400_000_000_000;

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

async fn place(
    env: &Env,
    u: &User,
    tin: &str,
    tout: &str,
    amount: u128,
    min_out: u128,
) -> anyhow::Result<u64> {
    let exp = env.now_ns().await? + 3_600_000_000_000;
    let r = okr(u
        .device
        .call(&u.account, "place_order")
        .args_json(json!({"token_in": tin, "token_out": tout, "amount_in": amount.to_string(), "min_out": min_out.to_string(),
            "trigger_meta": "{}", "expires_at_ns": exp.to_string(), "dexes": [env.rhea.id()]}))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?)?;
    Ok(r.json::<String>()?.parse()?)
}

async fn fire(
    by: &Account,
    u: &User,
    id: u64,
    ops: Value,
) -> anyhow::Result<near_workspaces::result::ExecutionFinalResult> {
    Ok(by
        .call(&u.account, "execute_order")
        .args_json(json!({"order_id": id.to_string(), "ops": ops}))
        .gas(Gas::from_tgas(300))
        .transact()
        .await?)
}

#[tokio::test]
async fn d6_relayer_sell_only_weekly_allowance() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let u = env.user("d6", 5 * NEAR, (2 * NEAR, 5 * NEAR)).await?;
    let auto = automation(&env, &u).await?;
    let (wrap, meme) = (env.wrap.id().to_string(), env.meme.id().to_string());
    // hold some MEME (device buy)
    ok(env.exec(&u.device, &u.account, env.buy_ops(NEAR, 1, true), "b", 2 * NEAR).await?)?;
    let held = env.ft_balance(env.meme.id(), &u.account).await?;
    // BUY orders: refused to the relayer, executed by the device key (tab runner)
    let buy = place(&env, &u, &wrap, &meme, NEAR / 10, 1).await?;
    fails_with(&fire(&auto, &u, buy, env.buy_ops(NEAR / 10, 1, false)).await?, "E_RELAYER_SELL_ONLY");
    ok(fire(&u.device, &u, buy, env.buy_ops(NEAR / 10, 1, false)).await?)?;
    // SELL orders: the relayer fires them; min_out counts toward the weekly allowance
    let part = held / 4;
    let exp_out = env.expected_out(env.meme.id(), part, env.wrap.id()).await?;
    let min = exp_out * 9 / 10;
    ok(u.owner
        .call(&u.account, "owner_set_relayer_allowance")
        .args_json(json!({"weekly_yocto": (min * 3 / 2).to_string()}))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?)?;
    let s1 = place(&env, &u, &meme, &wrap, part, min).await?;
    let r = fire(&auto, &u, s1, env.sell_ops(part, min, false)).await?;
    assert!(r.logs().iter().any(|l| l.contains("order_filled")), "{:?}", r.failures());
    let w: Value = env.worker.view(&u.account, "get_relayer_week").await?.json()?;
    assert_eq!(w["spent_yocto"], min.to_string());
    assert_eq!(w["allowance_yocto"], (min * 3 / 2).to_string());
    let (start, reset): (u64, u64) =
        (w["start_ns"].as_str().unwrap().parse()?, w["resets_at_ns"].as_str().unwrap().parse()?);
    assert_eq!(reset - start, 7 * DAY_NS);
    assert_eq!((start / DAY_NS + 3) % 7, 0, "ISO week starts on Monday 00:00 UTC");
    // a second sell over the allowance: refused, nothing counted; the device key may run it
    let s2 = place(&env, &u, &meme, &wrap, part, min).await?;
    fails_with(&fire(&auto, &u, s2, env.sell_ops(part, min, false)).await?, "E_RELAYER_WEEKLY");
    let w: Value = env.worker.view(&u.account, "get_relayer_week").await?.json()?;
    assert_eq!(w["spent_yocto"], min.to_string());
    ok(fire(&u.device, &u, s2, env.sell_ops(part, min, false)).await?)?;
    Ok(())
}

#[tokio::test]
async fn d5_utc_day_window_and_upgrade_migration() -> anyhow::Result<()> {
    // new account: the window is the UTC day
    let env = Env::new().await?;
    let u = env.user("d5", 3 * NEAR, (NEAR, 2 * NEAR)).await?;
    ok(env.exec(&u.device, &u.account, env.buy_ops(NEAR / 10, 1, true), "b", NEAR).await?)?;
    let d: Value = env.worker.view(&u.account, "get_day").await?.json()?;
    let start: u64 = d["start_ns"].as_str().unwrap().parse()?;
    let now = env.now_ns().await?;
    assert_eq!(start, now - now % DAY_NS, "window starts at 00:00 UTC");
    assert_eq!(d["resets_at_ns"], (start + DAY_NS).to_string());
    let wd: Value = env.worker.view(&u.account, "get_withdraw_day").await?.json()?;
    assert_eq!(wd["resets_at_ns"], (start + DAY_NS).to_string());

    // v1.3.2 account (rolling window from its first spend) upgraded to v1.4.1: spend and gas
    // tally carried into the current UTC day, window aligned
    let env = Env::new_with(Some(out("trading_account_v1_3_2")), Some(out("factory_v1_3_2"))).await?;
    let u = env.user("d5u", 3 * NEAR, (NEAR, 2 * NEAR)).await?;
    ok(env.exec(&u.device, &u.account, env.buy_ops(NEAR / 10, 1, true), "b", NEAR).await?)?;
    let before: Value = env.worker.view(&u.account, "get_day").await?.json()?;
    let code = std::env::var("NT_ACCOUNT_WASM")
        .map(|p| std::fs::read(p).unwrap())
        .unwrap_or_else(|_| out("trading_account"));
    let v = env.deploy_global(code).await?;
    ok(u.owner
        .call(&u.account, "owner_upgrade")
        .args_json(json!({"code_hash": v}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?)?;
    let after: Value = env.worker.view(&u.account, "get_day").await?.json()?;
    let now = env.now_ns().await?;
    assert_eq!(after["spent_yocto"], before["spent_yocto"]);
    assert_eq!(after["gas_spent_yocto"], before["gas_spent_yocto"]);
    assert_eq!(after["start_ns"], (now - now % DAY_NS).to_string(), "aligned to the UTC day");
    Ok(())
}
