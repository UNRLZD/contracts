//! V-TAX probe: does a taxed token's transfer tax cut a DEX delivery (pool -> account) below what
//! the DEX checked? Real mainnet code + state of each token; the DEX account (dclv2.ref-labs.near)
//! signs plain ft_transfer / ft_transfer_call as the pool does on a swap payout.
mod venues_common;
use anyhow::{anyhow, Result};
use integration_tests::*;
use near_workspaces::types::{Gas, NearToken};
use near_workspaces::AccountId;
use serde_json::{json, Value};
use venues_common::*;

async fn state(id: &str) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    use base64::Engine;
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "query", "params": {"request_type": "view_state",
        "finality": "final", "account_id": id, "prefix_base64": ""}});
    let v: Value =
        reqwest::Client::new().post("https://free.rpc.fastnear.com").json(&body).send().await?.json().await?;
    let r = v.get("result").cloned().ok_or_else(|| anyhow!("view_state {id}: {v}"))?;
    let b64 = base64::engine::general_purpose::STANDARD;
    r["values"]
        .as_array()
        .ok_or_else(|| anyhow!("bad"))?
        .iter()
        .map(|kv| Ok((b64.decode(kv["key"].as_str().unwrap())?, b64.decode(kv["value"].as_str().unwrap())?)))
        .collect()
}

async fn keyed(e: &VEnv, id: &str) -> Result<near_workspaces::Account> {
    let aid: AccountId = id.parse()?;
    let sk = near_workspaces::types::SecretKey::from_random(near_workspaces::types::KeyType::ED25519);
    e.worker
        .patch(&aid)
        .account(near_workspaces::types::AccountDetailsPatch::default().balance(NearToken::from_near(100)))
        .access_key(sk.public_key(), near_workspaces::AccessKey::full_access())
        .transact()
        .await?;
    Ok(near_workspaces::Account::from_secret_key(aid, sk, &e.worker))
}

async fn bal(e: &VEnv, t: &AccountId, a: &AccountId) -> u128 {
    e.ft(t, a).await.unwrap_or(0)
}

#[tokio::test]
#[ignore = "probe: cargo test --test venues_tax_probe -- --ignored --nocapture"]
async fn tax_probe() -> Result<()> {
    let mut out = String::new();
    let only = std::env::var("PROBE").ok();
    for (tok, pair, view) in [
        ("bean-ilgt.nearrr-fun.near", "dclv2.ref-labs.near", "tax_state"),
        ("bean-ilgt.nearrr-fun.near", "v2.ref-finance.near", "tax_state"),
        ("ribbit-2.nearlytrade.near", "dclv2.ref-labs.near", "get_tax"),
        ("pkat-3e6b47.nearpaid.near", "dclv2.ref-labs.near", "tax_info"),
        ("nucleus-e27af8.nucleusbroker.near", "dclv2.ref-labs.near", "get_tax"),
        ("jensen.nearrr-fun.near", "dclv2.ref-labs.near", "tax_state"),
        ("jensen.nearrr-fun.near", "v2.ref-finance.near", "tax_state"),
    ] {
        if only.as_deref().is_some_and(|o| !tok.starts_with(o)) {
            continue;
        }
        let e = venv().await?;
        let code = mainnet_code(tok).await?;
        let c = install_code(&e.worker, tok, &code).await?;
        let st = state(tok).await?;
        let mut p = e.worker.patch(c.id());
        for (k, v) in st {
            p = p.state(&k, &v);
        }
        p.transact().await?;
        // every account the tax may pay (creator, platform, lockers, exempt) as a plain account
        let raw: String = e
            .worker
            .view(c.id(), view)
            .await
            .map(|r| String::from_utf8_lossy(&r.result).to_string())
            .unwrap_or_default();
        for w in raw.split(|ch: char| !(ch.is_ascii_lowercase() || ch.is_ascii_digit() || "._-".contains(ch)))
        {
            if (w.ends_with(".near") && w.len() > 5)
                || (w.len() == 64 && w.bytes().all(|b| b.is_ascii_hexdigit()))
            {
                if let Ok(a) = w.parse::<AccountId>() {
                    if e.worker.view_account(&a).await.is_err() {
                        let _ = keyed(&e, w).await;
                    }
                }
            }
        }
        // the gate's view budget (GAS_TAX_VIEW = 5 TGas): what the view burns as a receipt
        let caller = e
            .root
            .create_subaccount("g")
            .initial_balance(NearToken::from_near(1))
            .transact()
            .await?
            .into_result()?;
        let r = caller.call(c.id(), view).args_json(json!({})).gas(Gas::from_tgas(5)).transact().await?;
        let burnt = r
            .receipt_outcomes()
            .iter()
            .filter(|o| o.executor_id == *c.id())
            .map(|o| o.gas_burnt.as_gas())
            .sum::<u64>();
        out += &format!(
            "   VIEW {view} at 5 TGas: ok={} token receipt burnt {:.2} TGas\n",
            r.is_success(),
            burnt as f64 / 1e12
        );
        let pool = keyed(&e, pair).await?;
        let user = e
            .root
            .create_subaccount("u")
            .initial_balance(NearToken::from_near(20))
            .transact()
            .await?
            .into_result()?;
        let r = user
            .call(c.id(), "storage_deposit")
            .args_json(json!({"account_id": user.id()}))
            .deposit(NearToken::from_millinear(50))
            .transact()
            .await?;
        // a curve-stage token (supply in its pad): seed the pool from the pad first (a pad -> pool
        // transfer; the measured leg is the pool's own payout below)
        if bal(&e, c.id(), pool.id()).await == 0 {
            let pad = keyed(&e, "nearrr-fun.near").await?;
            let have = bal(&e, c.id(), pad.id()).await;
            let r = pad
                .call(c.id(), "ft_transfer")
                .args_json(json!({"receiver_id": pool.id(), "amount": (have / 100).to_string()}))
                .deposit(NearToken::from_yoctonear(1))
                .gas(Gas::from_tgas(100))
                .transact()
                .await?;
            out += &format!(
                "   seed pad->pool {}: ok={} pool now {}\n",
                have / 100,
                r.is_success(),
                bal(&e, c.id(), pool.id()).await
            );
        }
        let pb0 = bal(&e, c.id(), pool.id()).await;
        let amt = pb0 / 1000;
        out += &format!(
            "== {tok} via {pair}: view {view} = {}\n   reg ok={} pool balance {pb0}\n",
            &raw[..raw.len().min(160)],
            r.is_success()
        );
        // BUY delivery: pool -> user ft_transfer(amt)
        let u0 = bal(&e, c.id(), user.id()).await;
        let r = pool
            .call(c.id(), "ft_transfer")
            .args_json(json!({"receiver_id": user.id(), "amount": amt.to_string()}))
            .deposit(NearToken::from_yoctonear(1))
            .gas(Gas::from_tgas(100))
            .transact()
            .await?;
        let u1 = bal(&e, c.id(), user.id()).await;
        let pb1 = bal(&e, c.id(), pool.id()).await;
        out += &format!(
            "   BUY pool->user ft_transfer {amt}: ok={} user got {} ({} bps short), pool paid {}\n",
            r.is_success(),
            u1 - u0,
            (amt.saturating_sub(u1 - u0)) * 10_000 / amt.max(1),
            pb0 - pb1
        );
        if !r.is_success() {
            out += &format!("     {:?}\n", r.clone().into_result().err());
        }
        // SELL input: user -> pool ft_transfer(half of what arrived)
        let s = (u1 - u0) / 2;
        let r = user
            .call(c.id(), "ft_transfer")
            .args_json(json!({"receiver_id": pool.id(), "amount": s.to_string()}))
            .deposit(NearToken::from_yoctonear(1))
            .gas(Gas::from_tgas(100))
            .transact()
            .await?;
        let pb2 = bal(&e, c.id(), pool.id()).await;
        let u2 = bal(&e, c.id(), user.id()).await;
        out += &format!(
            "   SELL user->pool ft_transfer {s}: ok={} pool got {} user paid {}\n",
            r.is_success(),
            pb2 - pb1,
            u1 - u2
        );
        println!("{out}");
    }
    Ok(())
}
