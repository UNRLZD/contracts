//! Evidence probe (ignored): live DCL v2.3.13 storage/swap semantics, see docs/contract-report.md.
use integration_tests::*;
use near_workspaces::types::{Gas, NearToken};
use serde_json::json;
fn err(r: &near_workspaces::result::ExecutionFinalResult) -> String {
    let s = format!("{:?}", r.clone().into_result().err());
    s.split("panicked: ").nth(1).unwrap_or(&s[..s.len().min(200)]).chars().take(160).collect()
}
#[tokio::test]
#[ignore]
async fn dcl_probe2() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let w = &env.worker;
    let dcl = install_mainnet(w, "dclv2.ref-labs.near").await?;
    let owner = sub(&env.root, "dclown", 100 * NEAR).await?;
    ok(dcl
        .call("new")
        .args_json(
            json!({"owner_id": owner.id(), "wnear_id": env.wrap.id(), "farming_contract_id": owner.id()}),
        )
        .transact()
        .await?)?;
    for t in [env.wrap.id(), env.meme.id()] {
        if t == env.meme.id() {
            ok(env
                .meme
                .call("mint")
                .args_json(json!({"account_id": dcl.id(), "amount": "0"}))
                .transact()
                .await?)?;
        } else {
            ok(owner
                .call(t, "storage_deposit")
                .args_json(json!({"account_id": dcl.id()}))
                .deposit(NearToken::from_yoctonear(STORAGE))
                .transact()
                .await?)?;
        }
    }
    let r = owner
        .call(dcl.id(), "create_pool")
        .args_json(json!({"token_a": env.wrap.id(), "token_b": env.meme.id(), "fee": 2000, "init_point": 0}))
        .deposit(NearToken::from_near(1))
        .transact()
        .await?;
    println!(
        "create_pool: ok={} {} ret={:?}",
        r.is_success(),
        err(&r),
        r.clone().json::<serde_json::Value>().ok()
    );
    let pools: serde_json::Value = dcl
        .view("list_pools")
        .args_json(json!({}))
        .await
        .map(|v| v.json().unwrap_or_default())
        .unwrap_or_default();
    println!("pools {}", pools.to_string().chars().take(300).collect::<String>());
    let pid = pools[0]["pool_id"].as_str().unwrap_or("").to_string();
    // LP: register, deposit both tokens, add liquidity
    ok(owner
        .call(dcl.id(), "storage_deposit")
        .args_json(json!({}))
        .deposit(NearToken::from_near(1))
        .transact()
        .await?)?;
    ok(owner
        .call(env.wrap.id(), "near_deposit")
        .args_json(json!({}))
        .deposit(NearToken::from_near(50))
        .transact()
        .await?)?;
    ok(env
        .meme
        .call("mint")
        .args_json(json!({"account_id": owner.id(), "amount": (10u128.pow(24)*1000).to_string()}))
        .transact()
        .await?)?;
    for (t, amt) in [(env.wrap.id(), 49 * NEAR), (env.meme.id(), 10u128.pow(24) * 1000)] {
        let r = owner
            .call(t, "ft_transfer_call")
            .args_json(json!({"receiver_id": dcl.id(), "amount": amt.to_string(), "msg": "\"Deposit\""}))
            .deposit(NearToken::from_yoctonear(1))
            .gas(Gas::from_tgas(100))
            .transact()
            .await?;
        println!("deposit {t}: ok={} fails={}", r.is_success(), r.receipt_failures().len());
    }
    let (tx, ty) = if env.wrap.id() < env.meme.id() {
        (env.wrap.id(), env.meme.id())
    } else {
        (env.meme.id(), env.wrap.id())
    };
    println!("x={tx} y={ty}");
    let r = owner.call(dcl.id(), "add_liquidity").args_json(json!({"pool_id": pid, "left_point": -8000, "right_point": 8000, "amount_x": (40*NEAR).to_string(), "amount_y": (40*NEAR).to_string(), "min_amount_x": "0", "min_amount_y": "0"})).gas(Gas::from_tgas(200)).transact().await?;
    println!("add_liquidity ok={} {} fails={}", r.is_success(), err(&r), r.receipt_failures().len());
    // swappers: unregistered, and registered-then-withdrawn (0.1 locked)
    let unreg = sub(&env.root, "unreg", 10 * NEAR).await?;
    let lean = sub(&env.root, "lean", 10 * NEAR).await?;
    ok(lean
        .call(dcl.id(), "storage_deposit")
        .args_json(json!({"registration_only": true}))
        .deposit(NearToken::from_millinear(500))
        .transact()
        .await?)?;
    ok(lean
        .call(dcl.id(), "storage_withdraw")
        .args_json(json!({}))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?)?;
    for s in [&unreg, &lean] {
        ok(s.call(env.wrap.id(), "storage_deposit")
            .args_json(json!({}))
            .deposit(NearToken::from_yoctonear(STORAGE))
            .transact()
            .await?)?;
        ok(env.meme.call("mint").args_json(json!({"account_id": s.id(), "amount": "0"})).transact().await?)?;
        ok(s.call(env.wrap.id(), "near_deposit")
            .args_json(json!({}))
            .deposit(NearToken::from_near(1))
            .transact()
            .await?)?;
        let msg = json!({"Swap": {"pool_ids": [pid], "output_token": env.meme.id(), "min_output_amount": "1", "skip_unwrap_near": true}}).to_string();
        let r = s
            .call(env.wrap.id(), "ft_transfer_call")
            .args_json(json!({"receiver_id": dcl.id(), "amount": (NEAR/2).to_string(), "msg": msg}))
            .deposit(NearToken::from_yoctonear(1))
            .gas(Gas::from_tgas(150))
            .transact()
            .await?;
        let fails: Vec<String> = r
            .receipt_failures()
            .iter()
            .map(|f| format!("{f:?}").split("panicked: ").nth(1).unwrap_or("?").chars().take(80).collect())
            .collect();
        let got: String =
            env.meme.view("ft_balance_of").args_json(json!({"account_id": s.id()})).await?.json()?;
        let back: String =
            env.wrap.view("ft_balance_of").args_json(json!({"account_id": s.id()})).await?.json()?;
        println!(
            "swap by {}: meme_out={got} wnear_left={back} fails={fails:?} logs={:?}",
            s.id(),
            r.logs().iter().map(|l| l.chars().take(90).collect::<String>()).collect::<Vec<_>>()
        );
    }
    // output ft_transfer fails (not registered on MEME): unregistered vs lean-registered on DCL
    let u2 = sub(&env.root, "unreg2", 10 * NEAR).await?;
    let l2 = sub(&env.root, "lean2", 10 * NEAR).await?;
    ok(l2
        .call(dcl.id(), "storage_deposit")
        .args_json(json!({"registration_only": true}))
        .deposit(NearToken::from_millinear(500))
        .transact()
        .await?)?;
    ok(l2
        .call(dcl.id(), "storage_withdraw")
        .args_json(json!({}))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?)?;
    for s in [&u2, &l2] {
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
        let msg = json!({"Swap": {"pool_ids": [pid], "output_token": env.meme.id(), "min_output_amount": "1", "skip_unwrap_near": true}}).to_string();
        let r = s
            .call(env.wrap.id(), "ft_transfer_call")
            .args_json(json!({"receiver_id": dcl.id(), "amount": (NEAR/2).to_string(), "msg": msg}))
            .deposit(NearToken::from_yoctonear(1))
            .gas(Gas::from_tgas(150))
            .transact()
            .await?;
        let back: String =
            env.wrap.view("ft_balance_of").args_json(json!({"account_id": s.id()})).await?.json()?;
        let inner: serde_json::Value = dcl
            .view("list_user_assets")
            .args_json(json!({"account_id": s.id()}))
            .await
            .map(|v| v.json().unwrap_or_default())
            .unwrap_or_default();
        let logs: Vec<String> = r.logs().iter().map(|l| l.chars().take(140).collect()).collect();
        println!(
            "failed-output swap by {}: wnear_left={back} dcl_inner={inner} fails={} logs={logs:?}",
            s.id(),
            r.receipt_failures().len()
        );
    }
    let l2 = sub(&env.root, "lean3", 10 * NEAR).await?;
    for args in
        [json!({}), json!({"token_id": env.meme.id()}), json!({"token_id": env.meme.id(), "amount": "1"})]
    {
        let r = l2
            .call(dcl.id(), "withdraw_asset")
            .args_json(args.clone())
            .gas(Gas::from_tgas(100))
            .transact()
            .await?;
        println!("withdraw_asset {args}: {}", err(&r));
    }
    // lean2 rescues its inner MEME after registering on MEME
    // lean2-style rescue: lean account with inner MEME registers on MEME, then withdraw_asset
    let l4 = sub(&env.root, "lean4", 10 * NEAR).await?;
    ok(l4
        .call(dcl.id(), "storage_deposit")
        .args_json(json!({"registration_only": true}))
        .deposit(NearToken::from_millinear(500))
        .transact()
        .await?)?;
    ok(l4
        .call(dcl.id(), "storage_withdraw")
        .args_json(json!({}))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?)?;
    ok(l4
        .call(env.wrap.id(), "storage_deposit")
        .args_json(json!({}))
        .deposit(NearToken::from_yoctonear(STORAGE))
        .transact()
        .await?)?;
    ok(l4
        .call(env.wrap.id(), "near_deposit")
        .args_json(json!({}))
        .deposit(NearToken::from_near(1))
        .transact()
        .await?)?;
    let msg = json!({"Swap": {"pool_ids": [pid], "output_token": env.meme.id(), "min_output_amount": "1", "skip_unwrap_near": true}}).to_string();
    let _ = l4
        .call(env.wrap.id(), "ft_transfer_call")
        .args_json(json!({"receiver_id": dcl.id(), "amount": (NEAR/2).to_string(), "msg": msg}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(150))
        .transact()
        .await?;
    ok(env.meme.call("mint").args_json(json!({"account_id": l4.id(), "amount": "0"})).transact().await?)?;
    let inner: serde_json::Value =
        dcl.view("list_user_assets").args_json(json!({"account_id": l4.id()})).await?.json()?;
    let r = l4
        .call(dcl.id(), "withdraw_asset")
        .args_json(json!({"token_id": env.meme.id()}))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?;
    let got: String =
        env.meme.view("ft_balance_of").args_json(json!({"account_id": l4.id()})).await?.json()?;
    let inner2: serde_json::Value =
        dcl.view("list_user_assets").args_json(json!({"account_id": l4.id()})).await?.json()?;
    println!(
        "rescue: inner_before={inner} withdraw ok={} {} got={got} inner_after={inner2}",
        r.is_success(),
        err(&r)
    );
    // unregister from a full 0.5 registration: how much comes back?
    let full = sub(&env.root, "full", 10 * NEAR).await?;
    ok(full
        .call(dcl.id(), "storage_deposit")
        .args_json(json!({"registration_only": true}))
        .deposit(NearToken::from_millinear(500))
        .transact()
        .await?)?;
    let b = full.view_account().await?.balance.as_yoctonear();
    let r = full
        .call(dcl.id(), "storage_unregister")
        .args_json(json!({}))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?;
    println!(
        "unregister from full: ok={} {} delta={}",
        r.is_success(),
        err(&r),
        (full.view_account().await?.balance.as_yoctonear() as f64 - b as f64) / 1e24
    );
    // batch deposit(0.5)+withdraw in ONE receipt from a contract-like caller (same predecessor)
    let batch = sub(&env.root, "batch", 10 * NEAR).await?;
    let b = batch.view_account().await?.balance.as_yoctonear();
    let r = batch
        .batch(dcl.id())
        .call(
            near_workspaces::operations::Function::new("storage_deposit")
                .args_json(json!({"registration_only": true}))
                .deposit(NearToken::from_millinear(500))
                .gas(Gas::from_tgas(10)),
        )
        .call(
            near_workspaces::operations::Function::new("storage_withdraw")
                .args_json(json!({}))
                .deposit(NearToken::from_yoctonear(1))
                .gas(Gas::from_tgas(10)),
        )
        .transact()
        .await?;
    let d: serde_json::Value =
        dcl.view("storage_balance_of").args_json(json!({"account_id": batch.id()})).await?.json()?;
    println!(
        "batch deposit+withdraw: ok={} {} net_cost={} balance_of={d}",
        r.is_success(),
        err(&r),
        (b as f64 - batch.view_account().await?.balance.as_yoctonear() as f64) / 1e24
    );
    Ok(())
}
