//! v1.3.2: owner withdrawals to FRESH, unregistered destinations (QA soak C1). Before: wNEAR and
//! tokens were ft_transfer'ed to an owner not registered on them -> failed silently, stayed.
use integration_tests::*;
use near_workspaces::types::{Gas, NearToken};
use serde_json::{json, Value};

fn events(r: &near_workspaces::result::ExecutionFinalResult) -> Vec<Value> {
    r.logs()
        .iter()
        .filter_map(|l| l.strip_prefix("EVENT_JSON:"))
        .filter_map(|j| serde_json::from_str::<Value>(j).ok())
        .filter(|v| v["event"] == "owner_withdraw")
        .map(|v| v["data"].clone())
        .collect()
}

async fn mint_token(
    env: &Env,
    name: &str,
    to: &near_workspaces::AccountId,
    amount: u128,
) -> anyhow::Result<near_workspaces::Contract> {
    let t = sub(&env.root, name, 5 * NEAR).await?.deploy(&out("mock_ft")).await?.into_result()?;
    ok(t.call("new").transact().await?)?;
    ok(t.call("mint").args_json(json!({"account_id": to, "amount": amount.to_string()})).transact().await?)?;
    Ok(t)
}

#[tokio::test]
async fn withdraw_all_to_fresh_destination_recovers_everything() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let u = env.user("wa", 5 * NEAR, (2 * NEAR, 5 * NEAR)).await?;
    let (d, acc) = (&u.device, &u.account);
    // positions: MEME from a real Rhea buy, spare wNEAR, 5 more tokens (6 = MAX), 1 broken token
    ok(env.exec(d, acc, env.buy_ops(NEAR / 2, 1, true), "b", NEAR).await?)?;
    ok(env.exec(d, acc, json!([{"NearDeposit": {"amount": NEAR.to_string()}}]), "w", 0).await?)?;
    let mut tokens = vec![env.meme.clone()];
    for i in 0..4 {
        tokens.push(mint_token(&env, &format!("tk{i}"), acc, 1_000 + i).await?);
    }
    let broken = sub(&env.root, "broken", 5 * NEAR).await?.deploy(&out("gas_burner")).await?.into_result()?;
    let meme_bal = env.ft_balance(env.meme.id(), acc).await?;
    let wnear = env.ft_balance(env.wrap.id(), acc).await?;
    assert!(meme_bal > 0 && wnear >= NEAR);
    // a brand-new destination, registered nowhere
    let dest = sub(&env.root, "freshdest", NEAR).await?;
    let d0 = env.near_balance(dest.id()).await?;
    let a0 = env.near_balance(acc).await?;
    let mut list: Vec<String> = tokens.iter().map(|t| t.id().to_string()).collect();
    list.push(broken.id().to_string());
    let r = u
        .owner
        .call(acc, "owner_withdraw_all")
        .args_json(json!({"to": dest.id(), "tokens": list}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(300))
        .transact()
        .await?;
    assert!(r.is_success(), "{:?}", r.clone().into_result().err());
    let ev = events(&r);
    println!("owner_withdraw events: {ev:#?}");
    env.worker.fast_forward(3).await?;
    // every token reached the fresh destination
    for t in &tokens {
        assert_eq!(env.ft_balance(t.id(), acc).await?, 0, "{} left behind", t.id());
        assert!(env.ft_balance(t.id(), dest.id()).await? > 0, "{} not received", t.id());
        assert!(ev.iter().any(|e| e["token"] == json!(t.id()) && e["ok"] == json!(true)));
    }
    assert_eq!(env.ft_balance(env.meme.id(), dest.id()).await?, meme_bal);
    // wNEAR unwrapped: account has none left, destination got native NEAR, no wNEAR registration needed
    assert_eq!(env.ft_balance(env.wrap.id(), acc).await?, 0);
    assert!(ev.iter().any(|e| e["token"] == json!(env.wrap.id())
        && e["ok"] == json!(true)
        && e["amount"] == json!(wnear.to_string())));
    // the broken token is REPORTED as failed, not silently dropped
    assert!(ev.iter().any(|e| e["token"] == json!(broken.id()) && e["ok"] == json!(false)), "{ev:?}");
    // native: everything above the storage stake left
    let got = env.near_balance(dest.id()).await? - d0;
    let v = env.worker.view_account(acc).await?;
    let left = v.balance.as_yoctonear() - v.storage_usage as u128 * 10u128.pow(19);
    println!(
        "destination got {:.4} NEAR (account had {:.4}); account liquid left {:.5} NEAR",
        got as f64 / 1e24,
        a0 as f64 / 1e24,
        left as f64 / 1e24
    );
    assert!(got >= wnear + a0 / 2, "native + unwrapped NEAR not received");
    assert!(left < NEAR / 20, "left {left} (only storage-deposit refunds may trail in)");
    Ok(())
}

#[tokio::test]
async fn owner_withdraw_wrap_and_token_to_unregistered() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let u = env.user("wo", 5 * NEAR, (2 * NEAR, 5 * NEAR)).await?;
    let (d, acc) = (&u.device, &u.account);
    ok(env.exec(d, acc, env.buy_ops(NEAR / 2, 1, true), "b", NEAR).await?)?;
    ok(env.exec(d, acc, json!([{"NearDeposit": {"amount": NEAR.to_string()}}]), "w", 0).await?)?;
    let dest = sub(&env.root, "dst2", NEAR).await?;
    let d0 = env.near_balance(dest.id()).await?;
    // wNEAR -> native NEAR
    let r = u
        .owner
        .call(acc, "owner_withdraw")
        .args_json(json!({"token": env.wrap.id(), "amount": (NEAR / 2).to_string(), "to": dest.id()}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?;
    assert!(events(&r).iter().any(|e| e["ok"] == json!(true)), "{:?}", r.logs());
    assert_eq!(env.near_balance(dest.id()).await? - d0, NEAR / 2);
    assert_eq!(env.ft_balance(env.wrap.id(), acc).await?, NEAR / 2);
    // token -> registered on the fly
    let m = env.ft_balance(env.meme.id(), acc).await?;
    let r = u
        .owner
        .call(acc, "owner_withdraw")
        .args_json(json!({"token": env.meme.id(), "amount": m.to_string(), "to": dest.id()}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?;
    assert!(events(&r).iter().any(|e| e["ok"] == json!(true)), "{:?}", r.logs());
    assert_eq!(env.ft_balance(env.meme.id(), dest.id()).await?, m);
    // device withdraw_to_owner(wrap): the (unregistered) owner gets native NEAR
    env.worker.fast_forward(5).await?; // owner's own earlier gas refunds land first
    let o0 = env.near_balance(u.owner.id()).await?;
    let r = d
        .call(acc, "withdraw_to_owner")
        .args_json(json!({"token": env.wrap.id(), "amount": (NEAR / 4).to_string()}))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?;
    assert!(events(&r).iter().any(|e| e["ok"] == json!(true)), "{:?}", r.logs());
    let got = env.near_balance(u.owner.id()).await? - o0;
    assert!((NEAR / 4..NEAR / 4 + NEAR / 1000).contains(&got), "owner got {got}");
    // too many tokens
    let many: Vec<String> = (0..7).map(|i| format!("t{i}.near")).collect();
    fails_with(
        &u.owner
            .call(acc, "owner_withdraw_all")
            .args_json(json!({"to": dest.id(), "tokens": many}))
            .deposit(NearToken::from_yoctonear(1))
            .gas(Gas::from_tgas(300))
            .transact()
            .await?,
        "E_TOO_MANY_TOKENS",
    );
    Ok(())
}
