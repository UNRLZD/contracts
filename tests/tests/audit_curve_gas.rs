//! AUDIT (external, curve area): a curve trade at the LOW end of the gas the account accepts
//! (MIN_CURVE_GAS = 20 TGas; the venues-hooks table's "min" for Aidols is 38 buy / 31 sell).
//! Invariant checked: after a trade either its output arrived, or its input came back. The op's
//! `gas` is chosen by whoever signs the fire (device, or the relayer for an order).
mod venues_common;
use anyhow::Result;
use integration_tests::*;
use near_workspaces::types::NearToken;
use serde_json::{json, Value};
use venues_common::*;

fn op(side: &str, venue: &str, market: &str, amount: u128, g: u64) -> Value {
    json!({ side: {"venue": venue, "market": market, "amount": amount.to_string(), "min_out": "1",
        "gas": (g * TGAS).to_string()} })
}

#[tokio::test]
async fn audit_aidols_low_gas_conserves_input() -> Result<()> {
    let e = venv().await?;
    let fac =
        import_mainnet(&e.worker, "aidols.near", Some("Csh7LRonCe1f7ndcizg8a3RqY2Huour6yHDeBcmHm43")).await?;
    let atok = "aidol100.aidols.near";
    import_mainnet(&e.worker, atok, Some("6RAJutV3eS21LHnrXaVN27hwn1K8ZJko59MUxEgLrpSp")).await?;
    fund_wnear(&e, &fac, 1_000 * NEAR).await?;
    for p in ["aidols-treasury.near", "wallet.intear.near"] {
        let aid: near_workspaces::AccountId = p.parse()?;
        if e.worker.view_account(&aid).await.is_err() {
            e.worker
                .patch(&aid)
                .account(
                    near_workspaces::types::AccountDetailsPatch::default().balance(NearToken::from_near(1)),
                )
                .transact()
                .await?;
        }
        ok(e.root
            .call(e.wrap.id(), "storage_deposit")
            .args_json(json!({"account_id": p, "registration_only": true}))
            .deposit(NearToken::from_millinear(13))
            .transact()
            .await?)?;
    }
    let t = e
        .ta(
            "ag",
            50 * NEAR,
            (20 * NEAR, 1_000 * NEAR),
            vec![json!({"id": "aidols.near", "kind": {"AidolsCurve": "Near"}})],
        )
        .await?;
    ok(e.exec(&t, json!([{"NearDeposit": {"amount": (10 * NEAR).to_string()}}]), "wrap10", 11 * NEAR)
        .await?)?;
    let tid: near_workspaces::AccountId = atok.parse()?;
    let w = e.wrap.id().clone();
    // a normal buy first (registers the account on the token, gives tokens to sell)
    let r = e.exec(&t, json!([op("CurveBuy", "aidols.near", atok, NEAR / 10, 150)]), "seed", NEAR).await?;
    println!("seed buy: settled {:?} failures {}", VEnv::settled(&r), r.receipt_failures().len());
    let mut report = vec![];
    for g in [20u64, 22, 25, 28, 30, 33, 36, 38] {
        let (w0, t0) = (e.ft(&w, &t.id).await?, e.ft(&tid, &t.id).await?);
        let r = e
            .exec(&t, json!([op("CurveBuy", "aidols.near", atok, NEAR / 10, g)]), &format!("b{g}"), NEAR)
            .await?;
        let (w1, t1) = (e.ft(&w, &t.id).await?, e.ft(&tid, &t.id).await?);
        let lost = w1 < w0 && t1 <= t0;
        let line = format!(
            "BUY  gas {g:>3}: wNEAR -{} token +{} settled {:?} failures {} LOST={lost}",
            w0.saturating_sub(w1),
            t1.saturating_sub(t0),
            VEnv::settled(&r).map(|v| v["used"].clone()),
            r.receipt_failures().len()
        );
        println!("{line}");
        report.push((lost, line));
    }
    let sell = e.ft(&tid, &t.id).await? / 40;
    for g in [20u64, 22, 25, 28, 31] {
        let (w0, t0) = (e.ft(&w, &t.id).await?, e.ft(&tid, &t.id).await?);
        let r = e
            .exec(&t, json!([op("CurveSell", "aidols.near", atok, sell, g)]), &format!("s{g}"), NEAR)
            .await?;
        let (w1, t1) = (e.ft(&w, &t.id).await?, e.ft(&tid, &t.id).await?);
        let lost = t1 < t0 && w1 <= w0;
        let line = format!(
            "SELL gas {g:>3}: token -{} wNEAR +{} settled {:?} failures {} LOST={lost}",
            t0.saturating_sub(t1),
            w1.saturating_sub(w0),
            VEnv::settled(&r).map(|v| v["used"].clone()),
            r.receipt_failures().len()
        );
        println!("{line}");
        report.push((lost, line));
    }
    let lost: Vec<_> = report.iter().filter(|(l, _)| *l).map(|(_, s)| s.clone()).collect();
    assert!(lost.is_empty(), "input left with no output:\n{}", lost.join("\n"));
    Ok(())
}

async fn fixture_state(id: &str) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    use base64::Engine;
    let path = format!("{}/fixtures/venues/{id}.state.json", env!("CARGO_MANIFEST_DIR"));
    let v: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    let b64 = base64::engine::general_purpose::STANDARD;
    v["values"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("bad state"))?
        .iter()
        .map(|kv| {
            Ok((
                b64.decode(kv["key"].as_str().unwrap_or(""))?,
                b64.decode(kv["value"].as_str().unwrap_or(""))?,
            ))
        })
        .collect()
}

async fn ensure(e: &VEnv, id: &str) -> Result<()> {
    let aid: near_workspaces::AccountId = id.parse()?;
    if e.worker.view_account(&aid).await.is_err() {
        e.worker
            .patch(&aid)
            .account(near_workspaces::types::AccountDetailsPatch::default().balance(NearToken::from_near(1)))
            .transact()
            .await?;
    }
    Ok(())
}

async fn import(e: &VEnv, id: &str, hash: &str) -> Result<near_workspaces::Contract> {
    let code = pinned(id, Some(hash)).await?;
    let c = install_code(&e.worker, id, &code).await?;
    let st = fixture_state(id).await?;
    let bytes: Vec<u8> = st.iter().flat_map(|(_, v)| v.clone()).collect();
    let total: usize = st.iter().map(|(k, v)| k.len() + v.len() + 40).sum();
    let mut p = e.worker.patch(c.id()).account(
        near_workspaces::types::AccountDetailsPatch::default()
            .balance(NearToken::from_near(100_000))
            .storage_usage((code.len() + total + 1_000) as u64),
    );
    p = p.code(&code);
    for (k, v) in &st {
        p = p.state(k, v);
    }
    p.transact().await?;
    let s = String::from_utf8_lossy(&bytes).to_string();
    let mut seen = std::collections::BTreeSet::new();
    for w in s.split(|c: char| !(c.is_ascii_lowercase() || c.is_ascii_digit() || "._-".contains(c))) {
        if (w.ends_with(".near") && w.len() > 5 && w.parse::<near_workspaces::AccountId>().is_ok()
            || w.len() == 64 && w.bytes().all(|b| b.is_ascii_hexdigit()))
            && w != id
            && w != "wrap.near"
        {
            seen.insert(w.to_string());
        }
    }
    for w in seen {
        ensure(e, &w).await?;
    }
    Ok(c)
}

/// RevShare sell (wNEAR payout; hooks table min 70) below its measured minimum: input conserved?
#[tokio::test]
async fn audit_revshare_low_gas_sell_conserves_input() -> Result<()> {
    let e = venv().await?;
    let rs = "l0.revshare-launch.near";
    let rsc = import(&e, rs, "9gNvjBnKKuvujP6LwynYjqhDJ92fRkN2ozjZvzFjVapX").await?;
    let launch: Value = e.worker.view(&rs.parse()?, "get_launch").args_json(json!({})).await?.json()?;
    let reserve: u128 = launch["curve_quote"].as_str().unwrap().parse()?;
    ok(rsc
        .as_account()
        .call(e.wrap.id(), "storage_deposit")
        .args_json(json!({"account_id": rs}))
        .deposit(NearToken::from_yoctonear(STORAGE))
        .transact()
        .await?)?;
    ok(rsc
        .as_account()
        .call(e.wrap.id(), "near_deposit")
        .args_json(json!({}))
        .deposit(NearToken::from_yoctonear(reserve))
        .transact()
        .await?)?;
    let t = e
        .ta(
            "rsg",
            30 * NEAR,
            (10 * NEAR, 100 * NEAR),
            vec![json!({"id": "revshare-launch.near", "kind": {"TokenCurve": "RevShare"}})],
        )
        .await?;
    let bounds: Value =
        e.worker.view(&rs.parse()?, "storage_balance_bounds").args_json(json!({})).await?.json()?;
    let reg: u128 = bounds["min"].as_str().unwrap().parse()?;
    let tid: near_workspaces::AccountId = rs.parse()?;
    let w = e.wrap.id().clone();
    let r = e
        .exec(
            &t,
            json!([{"StorageDeposit": {"token": rs, "amount": reg.to_string()}},
                {"NearDeposit": {"amount": (3 * NEAR).to_string()}},
                {"CurveBuy": {"venue": rs, "amount": NEAR.to_string(), "min_out": "1", "gas": (100 * TGAS).to_string()}}]),
            "rs-seed",
            5 * NEAR,
        )
        .await?;
    println!("revshare seed: {:?} fails {}", VEnv::settled(&r), r.receipt_failures().len());
    let sell = e.ft(&tid, &t.id).await? / 20;
    let mut lost = vec![];
    for g in [20u64, 30, 40, 50, 60, 69] {
        let (w0, t0) = (e.ft(&w, &t.id).await?, e.ft(&tid, &t.id).await?);
        let op = json!([{"CurveSell": {"venue": rs, "amount": sell.to_string(), "min_out": "1",
            "gas": (g * TGAS).to_string()}}]);
        let r = e.exec(&t, op, &format!("rs{g}"), NEAR).await?;
        e.worker.fast_forward(5).await?;
        let (w1, t1) = (e.ft(&w, &t.id).await?, e.ft(&tid, &t.id).await?);
        let l = t1 < t0 && w1 <= w0;
        println!(
            "REVSHARE SELL gas {g}: token -{} wNEAR +{} used {:?} fails {} LOST={l}",
            t0.saturating_sub(t1),
            w1.saturating_sub(w0),
            VEnv::settled(&r).map(|v| v["used"].clone()),
            r.receipt_failures().len()
        );
        if l {
            lost.push(format!("revshare sell at {g} TGas"));
        }
    }
    assert!(lost.is_empty(), "{lost:?}");
    Ok(())
}
