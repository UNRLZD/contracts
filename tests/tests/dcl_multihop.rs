//! v1.4 check (quote-token routing): is MAX_SWAP_GAS_DCL (150 TGas per swap op) enough for
//! 2-3 hop DCL `Swap{pool_ids}` on the real DCL v2.3.13 wasm? Pools wNEAR/MEME, MEME/T2, T2/T3,
//! each with 4 nested liquidity ranges so large swaps cross several ticks. Measures the minimum
//! prepaid gas that still delivers the output (binary search, plain trader) and runs the
//! 3-hop swap through a trading account at the 150 TGas cap.
use integration_tests::*;
use near_workspaces::types::{Gas, NearToken};
use near_workspaces::{Account, AccountId};
use serde_json::json;

async fn token(env: &Env, name: &str) -> anyhow::Result<AccountId> {
    let acc = sub(&env.root, name, 50 * NEAR).await?;
    let c = acc.deploy(&out("mock_ft")).await?.into_result()?;
    ok(c.call("new").transact().await?)?;
    Ok(c.id().clone())
}

async fn mint(env: &Env, t: &AccountId, to: &AccountId, amount: u128) -> anyhow::Result<()> {
    ok(env
        .root
        .call(t, "mint")
        .args_json(json!({"account_id": to, "amount": amount.to_string()}))
        .transact()
        .await?)
}

/// DCL pool a/b (fee 2000, point_delta 40) with 4 nested ranges, thin inside, so larger
/// swaps cross several initialized ticks.
async fn pool(env: &Env, lp: &Account, a: &AccountId, b: &AccountId) -> anyhow::Result<String> {
    let dcl = env.dcl.id();
    let r = lp
        .call(dcl, "create_pool")
        .args_json(json!({"token_a": a, "token_b": b, "fee": 2000, "init_point": 0}))
        .deposit(NearToken::from_near(1))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?;
    let pid: String = okr(r)?.json()?;
    for t in [a, b] {
        ok(lp
            .call(t, "ft_transfer_call")
            .args_json(json!({"receiver_id": dcl, "amount": (400 * NEAR).to_string(), "msg": "\"Deposit\""}))
            .deposit(NearToken::from_yoctonear(1))
            .gas(Gas::from_tgas(100))
            .transact()
            .await?)?;
    }
    for (w, n) in [(40, 1), (400, 5), (2000, 20), (8000, 300)] {
        ok(lp
            .call(dcl, "add_liquidity")
            .args_json(
                json!({"pool_id": pid, "left_point": -w, "right_point": w, "amount_x": (n * NEAR).to_string(),
                "amount_y": (n * NEAR).to_string(), "min_amount_x": "0", "min_amount_y": "0"}),
            )
            .gas(Gas::from_tgas(200))
            .transact()
            .await?)?;
    }
    Ok(pid)
}

fn swap_msg(pids: &[String], out: &AccountId) -> String {
    json!({"Swap": {"pool_ids": pids, "output_token": out, "min_output_amount": "1", "skip_unwrap_near": true}})
        .to_string()
}

/// Plain trader: wNEAR ft_transfer_call to DCL with exactly `tgas` prepaid. Output delivered?
async fn try_swap(
    env: &Env,
    trader: &Account,
    pids: &[String],
    out: &AccountId,
    amount: u128,
    tgas: u64,
) -> anyhow::Result<(bool, u64)> {
    let before = env.ft_balance(out, trader.id()).await?;
    let r = trader
        .call(env.wrap.id(), "ft_transfer_call")
        .args_json(
            json!({"receiver_id": env.dcl.id(), "amount": amount.to_string(), "msg": swap_msg(pids, out)}),
        )
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(tgas))
        .transact()
        .await?;
    let burnt: u64 = r.receipt_outcomes().iter().map(|o| o.gas_burnt.as_gas()).sum();
    Ok((env.ft_balance(out, trader.id()).await? > before, burnt / TGAS))
}

#[tokio::test]
async fn dcl_multihop_gas() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let (t2, t3) = (token(&env, "t2").await?, token(&env, "t3").await?);
    let meme = env.meme.id().clone();
    let lp = sub(&env.root, "mlp", 1_000 * NEAR).await?;
    let trader = sub(&env.root, "trader", 300 * NEAR).await?;
    let dcl = env.dcl.id().clone();
    for who in [&dcl, lp.id(), trader.id()] {
        ok(lp
            .call(env.wrap.id(), "storage_deposit")
            .args_json(json!({"account_id": who}))
            .deposit(NearToken::from_yoctonear(STORAGE))
            .transact()
            .await?)?;
        for t in [&meme, &t2, &t3] {
            mint(&env, t, who, 0).await?;
        }
    }
    ok(lp
        .call(&dcl, "storage_deposit")
        .args_json(json!({}))
        .deposit(NearToken::from_near(2))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?)?;
    ok(lp
        .call(env.wrap.id(), "near_deposit")
        .args_json(json!({}))
        .deposit(NearToken::from_near(450))
        .transact()
        .await?)?;
    for t in [&meme, &t2, &t3] {
        mint(&env, t, lp.id(), 1_000 * NEAR).await?;
    }
    let p1 = pool(&env, &lp, env.wrap.id(), &meme).await?;
    let p2 = pool(&env, &lp, &meme, &t2).await?;
    let p3 = pool(&env, &lp, &t2, &t3).await?;
    ok(trader
        .call(env.wrap.id(), "near_deposit")
        .args_json(json!({}))
        .deposit(NearToken::from_near(200))
        .transact()
        .await?)?;

    let routes: [(Vec<String>, &AccountId); 3] = [
        (vec![p1.clone()], &meme),
        (vec![p1.clone(), p2.clone()], &t2),
        (vec![p1.clone(), p2.clone(), p3.clone()], &t3),
    ];
    let mut report = vec![];
    for (pids, out) in &routes {
        // small: stays in the narrowest range; large: crosses the inner ranges
        for (label, amount) in [("0.1 NEAR", NEAR / 10), ("10 NEAR", 10 * NEAR)] {
            let (ok300, burnt) = try_swap(&env, &trader, pids, out, amount, 300).await?;
            assert!(ok300, "{} hops {label} fails even at 300 TGas", pids.len());
            let (mut lo, mut hi) = (40u64, 300u64);
            while hi - lo > 4 {
                let mid = (lo + hi) / 2;
                if try_swap(&env, &trader, pids, out, amount, mid).await?.0 {
                    hi = mid;
                } else {
                    lo = mid;
                }
            }
            report
                .push(format!("{} hop(s), {label}: min prepaid ~{hi} TGas, burnt {burnt} TGas", pids.len()));
        }
    }
    for l in &report {
        println!("DCL multihop: {l}");
    }

    // Through a trading account at the 150 TGas cap: 3 hops, large swap, output delivered.
    let u = env.user("mh", 30 * NEAR, (25 * NEAR, 25 * NEAR)).await?;
    let amount = 20 * NEAR;
    let ops = json!([
        {"StorageDeposit": {"token": t3, "amount": STORAGE.to_string()}},
        {"NearDeposit": {"amount": amount.to_string()}},
        {"FtTransferCall": {"token": env.wrap.id(), "receiver_id": dcl, "amount": amount.to_string(),
            "msg": swap_msg(&[p1, p2, p3], &t3), "gas": (150 * TGAS).to_string()}}
    ]);
    ok(env.exec(&u.device, &u.account, ops, "mh3", amount + fee(amount) + STORAGE).await?)?;
    assert!(env.ft_balance(&t3, &u.account).await? > 0, "3-hop output delivered at the 150 TGas cap");
    Ok(())
}
