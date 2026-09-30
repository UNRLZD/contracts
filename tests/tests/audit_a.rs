//! External audit of v1.4.7 (docs/audit/external/UNRLZD-audit-report.md, Engagement A) on the
//! real runtime, from the auditor's PoCs (study/unrlzd/poc/UNR-A-*). RED on v1.4.7:
//!   NT_ACCOUNT_WASM=../out/trading_account_v1_4_7.wasm NT_FACTORY_WASM=../out/factory_v1_4_7.wasm \
//!   cargo test --test audit_a -- --nocapture
use integration_tests::*;
use near_workspaces::result::ExecutionFinalResult;
use near_workspaces::types::{Gas, NearToken};
use near_workspaces::{AccountId, Contract};
use serde_json::{json, Value};

fn events(r: &ExecutionFinalResult) -> Vec<Value> {
    r.logs()
        .iter()
        .filter_map(|l| l.strip_prefix("EVENT_JSON:"))
        .filter_map(|j| serde_json::from_str::<Value>(j).ok())
        .collect()
}

async fn mint_token(env: &Env, name: &str, to: &AccountId, amount: u128) -> anyhow::Result<Contract> {
    let t = sub(&env.root, name, 5 * NEAR).await?.deploy(&out("mock_ft")).await?.into_result()?;
    ok(t.call("new").transact().await?)?;
    ok(t.call("mint").args_json(json!({"account_id": to, "amount": amount.to_string()})).transact().await?)?;
    Ok(t)
}

async fn liquid_of(env: &Env, id: &AccountId) -> anyhow::Result<u128> {
    let v = env.worker.view_account(id).await?;
    Ok(v.balance.as_yoctonear() - v.storage_usage as u128 * 10u128.pow(19))
}

async fn withdraw_all(
    u: &User,
    to: &AccountId,
    tokens: &[&Contract],
) -> anyhow::Result<ExecutionFinalResult> {
    let list: Vec<String> = tokens.iter().map(|t| t.id().to_string()).collect();
    Ok(u.owner
        .call(&u.account, "owner_withdraw_all")
        .args_json(json!({"to": to, "tokens": list}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(300))
        .transact()
        .await?)
}

/// UNR-A-03 (auditor's g2_b_low_liquid_six_tokens): liquid NEAR at RESERVE + 0.01 and 6 tokens
/// to a fresh destination. v1.4.7: phase 2 reverted ("Exceeded the account balance"), no event,
/// nothing moved, top-level success. v1.4.8: no receipt fails, every item is reported (sent, or
/// skipped with `owner_withdraw_skipped`), and a second call sends the skipped ones from the
/// NEAR kept back.
#[tokio::test]
async fn unr_a03_withdraw_all_low_native_reports_and_completes() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let u = env.user("lq", 5 * NEAR, (5 * NEAR, 5 * NEAR)).await?;
    let acc = u.account.clone();
    ok(env
        .exec(&u.device, &acc, json!([{"NearDeposit": {"amount": (2 * NEAR).to_string()}}]), "w", 0)
        .await?)?;
    let mut tokens = vec![];
    for i in 0..6 {
        tokens.push(mint_token(&env, &format!("lt{i}"), &acc, 1_000_000 + i).await?);
    }
    let l = liquid_of(&env, &acc).await?;
    ok(u.owner
        .call(&acc, "owner_withdraw")
        .args_json(
            json!({"token": null, "amount": (l - RESERVE - NEAR / 100).to_string(), "to": u.owner.id()}),
        )
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(50))
        .transact()
        .await?)?;
    println!("TA liquid before sweep {:.5} NEAR", liquid_of(&env, &acc).await? as f64 / 1e24);
    let dest = sub(&env.root, "ldest", NEAR).await?;
    let d0 = env.near_balance(dest.id()).await?;
    let all: Vec<&Contract> = tokens.iter().collect();
    let r = withdraw_all(&u, dest.id(), &all).await?;
    let ev = events(&r);
    let failures = r.receipt_failures().len();
    println!("first call: success={} receipt_failures={failures} events={}", r.is_success(), ev.len());
    for e in &ev {
        println!("  {} {}", e["event"], e["data"]);
    }
    assert_eq!(failures, 0, "phase 2 must not revert");
    let skipped: Vec<String> = ev
        .iter()
        .filter(|e| e["event"] == "owner_withdraw_skipped")
        .map(|e| e["data"]["token"].as_str().unwrap().to_string())
        .collect();
    for t in &tokens {
        let reported =
            ev.iter().any(|e| e["event"] == "owner_withdraw" && e["data"]["token"] == t.id().as_str());
        assert!(reported, "{} not reported", t.id());
    }
    assert!(env.near_balance(dest.id()).await? > d0 + NEAR, "the unwrapped wNEAR reached the destination");
    // second call for the skipped tokens: paid from the NEAR kept back
    let rest: Vec<&Contract> = tokens.iter().filter(|t| skipped.contains(&t.id().to_string())).collect();
    println!("skipped {skipped:?}");
    if !rest.is_empty() {
        let r = withdraw_all(&u, dest.id(), &rest).await?;
        assert_eq!(r.receipt_failures().len(), 0);
        assert!(!events(&r).iter().any(|e| e["event"] == "owner_withdraw_skipped"), "{:?}", events(&r));
    }
    env.worker.fast_forward(3).await?;
    for t in &tokens {
        assert_eq!(env.ft_balance(t.id(), &acc).await?, 0, "{} left in the TA", t.id());
        assert!(env.ft_balance(t.id(), dest.id()).await? > 0, "{} not delivered", t.id());
    }
    Ok(())
}
