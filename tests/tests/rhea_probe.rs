//! Evidence probe (ignored): live Rhea v1.9.20 undelivered-output + withdraw semantics.
use integration_tests::*;
use near_workspaces::types::{Gas, NearToken};
use serde_json::json;
fn err(r: &near_workspaces::result::ExecutionFinalResult) -> String {
    let s = format!("{:?}", r.clone().into_result().err());
    s.split("panicked: ").nth(1).unwrap_or("-").chars().take(200).collect()
}
#[tokio::test]
#[ignore]
async fn rhea_probe() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let v: serde_json::Value = env.rhea.view("storage_balance_bounds").await?.json()?;
    println!("rhea storage bounds {v}");
    for (name, register_ref) in [("unrega", false), ("rega", true)] {
        let s = sub(&env.root, name, 10 * NEAR).await?;
        if register_ref {
            let r = s
                .call(env.rhea.id(), "storage_deposit")
                .args_json(json!({"registration_only": true}))
                .deposit(NearToken::from_millinear(100))
                .transact()
                .await?;
            let b: serde_json::Value =
                env.rhea.view("storage_balance_of").args_json(json!({"account_id": s.id()})).await?.json()?;
            println!("{name} ref registration ok={} balance_of={b}", r.is_success());
        }
        ok(s.call(env.wrap.id(), "storage_deposit")
            .args_json(json!({}))
            .deposit(NearToken::from_yoctonear(STORAGE))
            .transact()
            .await?)?;
        ok(s.call(env.wrap.id(), "near_deposit")
            .args_json(json!({}))
            .deposit(NearToken::from_near(1))
            .transact()
            .await?)?;
        // NOT registered on MEME -> output ft_transfer fails
        let msg = env.rhea_msg(env.wrap.id(), env.meme.id(), NEAR / 2, 1, false);
        let r = s
            .call(env.wrap.id(), "ft_transfer_call")
            .args_json(json!({"receiver_id": env.rhea.id(), "amount": (NEAR/2).to_string(), "msg": msg}))
            .deposit(NearToken::from_yoctonear(1))
            .gas(Gas::from_tgas(200))
            .transact()
            .await?;
        let logs: Vec<String> = r
            .logs()
            .iter()
            .filter(|l| l.contains("lostfound") || l.contains("Deposit"))
            .map(|l| l.chars().take(160).collect())
            .collect();
        println!("{name} swap logs {logs:?}");
        let dep: serde_json::Value = env
            .rhea
            .view("get_deposits")
            .args_json(json!({"account_id": s.id()}))
            .await
            .map(|x| x.json().unwrap_or_default())
            .unwrap_or_default();
        println!("{name} inner deposits {dep}");
        for (m, a) in [
            ("list_lostfound_tokens", json!({"account_id": s.id()})),
            ("get_lostfound_token", json!({"account_id": s.id(), "token_id": env.meme.id()})),
        ] {
            let v = env
                .rhea
                .view(m)
                .args_json(a.clone())
                .await
                .map(|x| x.json::<serde_json::Value>().unwrap_or_default());
            println!(
                "{name} {m} -> {:?}",
                v.map_err(|e| e.to_string().chars().take(200).collect::<String>())
            );
        }
        ok(env.meme.call("mint").args_json(json!({"account_id": s.id(), "amount": "0"})).transact().await?)?;
        for a in [json!({}), json!({"token_id": env.meme.id()}), json!({"token_ids": [env.meme.id()]})] {
            for dep in [0u128, 1] {
                let r = s
                    .call(env.rhea.id(), "claim_lostfound")
                    .args_json(a.clone())
                    .deposit(NearToken::from_yoctonear(dep))
                    .gas(Gas::from_tgas(100))
                    .transact()
                    .await?;
                let bal = env.ft_balance(env.meme.id(), s.id()).await?;
                println!(
                    "{name} claim_lostfound {a} dep={dep}: ok={} fails={} {} meme={bal}",
                    r.is_success(),
                    r.receipt_failures().len(),
                    err(&r)
                );
                if bal > 0 {
                    break;
                }
            }
        }
        for a in [
            json!({"token_id": env.meme.id()}),
            json!({"token_id": env.meme.id(), "amount": "0"}),
            json!({"token_id": env.meme.id(), "amount": "1"}),
        ] {
            let r = s
                .call(env.rhea.id(), "withdraw")
                .args_json(a.clone())
                .deposit(NearToken::from_yoctonear(1))
                .gas(Gas::from_tgas(100))
                .transact()
                .await?;
            println!(
                "{name} withdraw {a}: ok={} fails={} {} meme={}",
                r.is_success(),
                r.receipt_failures().len(),
                err(&r),
                env.ft_balance(env.meme.id(), s.id()).await?
            );
        }
    }
    Ok(())
}
