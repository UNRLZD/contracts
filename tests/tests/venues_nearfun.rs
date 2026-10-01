//! v1.6 NearFun (`*.nearfunio.near`, curve inside the token) with the REAL token template
//! (global code 7bPoEt3N…, fetched read-only from ncat.nearfunio.near and pinned by hash),
//! initialised with ncat's own mainnet `new` args (tx BQa5RQ2V, icon dropped).
//!
//! Quote tokens: the template exports no `ft_on_transfer` (see `nearfun_has_no_quote_token_entry`):
//! a curve buy is always the payable `buy{min_tokens_out}` in NEAR, whatever the launch's
//! `quote_id` (the factory config's quotes each carry a `near_route_pool_id`, used for the
//! graduation / tax legs). So NearFun needs no quote-token buy path; a Q-quoted launch's curve is
//! bought with NEAR and after graduation trades on its DCL pool (Chain).
mod venues_common;
use anyhow::Result;
use integration_tests::*;
use near_workspaces::types::{Gas, NearToken};
use near_workspaces::{Account, AccountId};
use serde_json::{json, Value};
use venues_common::*;

const TEMPLATE_HASH: &str = "7bPoEt3NG3QeJ2kifTjYT14yCXSJ9yzrFEcvWADtopYu";
const TOK: &str = "ncat.nearfunio.near";

fn u(v: &Value) -> u128 {
    v.as_str().and_then(|s| s.parse().ok()).unwrap_or(0)
}
fn bps(x: u128) -> u128 {
    x / 10_000 * 100 + x % 10_000 * 100 / 10_000
}

async fn named(e: &VEnv, id: &str, near: u128) -> Result<Account> {
    let aid: AccountId = id.parse()?;
    let sk = near_workspaces::types::SecretKey::from_random(near_workspaces::types::KeyType::ED25519);
    e.worker
        .patch(&aid)
        .account(near_workspaces::types::AccountDetailsPatch::default().balance(NearToken::from_near(near)))
        .access_key(sk.public_key(), near_workspaces::AccessKey::full_access())
        .transact()
        .await?;
    Ok(Account::from_secret_key(aid, sk, &e.worker))
}

/// The token, initialised by the factory account as on mainnet (`new` + wrap registration).
async fn nearfun(e: &VEnv) -> Result<AccountId> {
    let factory = named(e, "nearfunio.near", 1_000).await?;
    let code = pinned(TOK, Some(TEMPLATE_HASH)).await?;
    let token = install_code(&e.worker, TOK, &code).await?;
    let args: Value = serde_json::from_str(include_str!("nearfun_new_args.json"))?;
    let r = factory.call(token.id(), "new").args_json(args).gas(Gas::from_tgas(100)).transact().await?;
    let _ = okr(r).map_err(|x| anyhow::anyhow!("new: {x}"))?;
    ok(factory
        .call(e.wrap.id(), "storage_deposit")
        .args_json(json!({"account_id": TOK, "registration_only": true}))
        .deposit(NearToken::from_yoctonear(STORAGE))
        .transact()
        .await?)?;
    Ok(token.id().clone())
}

fn dex() -> Value {
    json!({"id": "nearfunio.near", "kind": {"TokenCurve": "NearFun"}})
}

/// Buy and sell through the trading account on the real template: calls, payout, fee exactness.
#[tokio::test]
async fn nearfun_buy_sell() -> Result<()> {
    let e = venv().await?;
    let tok = nearfun(&e).await?;
    let t = e.ta("nfa", 20 * NEAR, (5 * NEAR, 20 * NEAR), vec![dex()]).await?;
    let amount = NEAR;
    let q: Value =
        e.worker.view(&tok, "quote_buy").args_json(json!({"near_in": amount.to_string()})).await?.json()?;
    println!("quote_buy {q}");
    let storage: Value = e.worker.view(&tok, "storage_balance_bounds").await?.json()?;
    let fees0 = e.near(e.fees.id()).await?;
    let ops = json!([{"StorageDeposit": {"token": tok, "amount": u(&storage["min"]).to_string()}},
        {"CurveBuy": {"venue": tok, "amount": amount.to_string(), "min_out": (u(&q["amount_out"]) * 99 / 100).to_string(),
        "gas": (100 * TGAS).to_string()}}]);
    let r = e.exec(&t, ops, "nb1", 2 * NEAR).await?;
    println!("buy gas {:?}", gas_by_receipt(&r));
    let r = okr(r)?;
    let got = e.ft(&tok, &t.id).await?;
    assert_eq!(got, u(&q["amount_out"]), "tokens = quote");
    let fee = e.near(e.fees.id()).await? - fees0;
    let s = VEnv::settled(&r).expect("settled");
    println!("buy fee {fee} (max {}), settled {s}", bps(amount));
    // fee = 1% x (input - measured refund) <= 1% x input; see nearfun_buy_fee_exact for the gap
    assert!(fee <= bps(amount), "{fee}");
    assert_eq!(u(&s["fee"]), fee);
    // sell all back (early-sell fee applies in the first hour; the quote includes it)
    let qs: Value =
        e.worker.view(&tok, "quote_sell").args_json(json!({"tokens_in": got.to_string()})).await?.json()?;
    println!("quote_sell {qs}");
    let min_out = u(&qs["amount_out"]) * 99 / 100;
    let n0 = e.near(&t.id).await?;
    let fees1 = e.near(e.fees.id()).await?;
    let r = e
        .exec(
            &t,
            json!([{"CurveSell": {"venue": tok, "amount": got.to_string(), "min_out": min_out.to_string(),
        "gas": (100 * TGAS).to_string()}}]),
            "ns1",
            NEAR,
        )
        .await?;
    println!("sell gas {:?}", gas_by_receipt(&r));
    let r = okr(r)?;
    assert_eq!(e.ft(&tok, &t.id).await?, 0);
    let fee = e.near(e.fees.id()).await? - fees1;
    // no reported amount: fee = 1% x min(arrived, min_out) = 1% x min_out when the payout arrived
    assert_eq!(fee, bps(min_out), "sell fee exact");
    let n1 = e.near(&t.id).await?;
    println!("native delta {} (quote {}), fee {fee}", n1 as i128 - n0 as i128, u(&qs["amount_out"]));
    assert!(n1 + fee + NEAR / 100 > n0 + u(&qs["amount_out"]), "native payout arrived");
    assert_eq!(u(&VEnv::settled(&r).expect("settled")["fee"]), fee);
    Ok(())
}

/// Slippage: min_out above the curve -> the token panics, the NEAR deposit comes back, no fee.
#[tokio::test]
async fn nearfun_slippage_refund() -> Result<()> {
    let e = venv().await?;
    let tok = nearfun(&e).await?;
    let t = e.ta("nfa", 20 * NEAR, (5 * NEAR, 20 * NEAR), vec![dex()]).await?;
    let q: Value =
        e.worker.view(&tok, "quote_buy").args_json(json!({"near_in": NEAR.to_string()})).await?.json()?;
    let fees0 = e.near(e.fees.id()).await?;
    let n0 = e.near(&t.id).await?;
    let r = e
        .exec(
            &t,
            json!([{"CurveBuy": {"venue": tok, "amount": NEAR.to_string(),
        "min_out": (u(&q["amount_out"]) * 2).to_string(), "gas": (100 * TGAS).to_string()}}]),
            "nslip",
            2 * NEAR,
        )
        .await?;
    assert!(r.is_success());
    assert_eq!(e.ft(&tok, &t.id).await.unwrap_or(0), 0);
    assert_eq!(e.near(e.fees.id()).await?, fees0, "no fee");
    assert_eq!(u(&VEnv::settled(&r).expect("settled")["used"]), 0);
    assert!(e.near(&t.id).await? + NEAR / 20 > n0, "deposit refunded");
    Ok(())
}

/// Evidence for the quote-token question: the template has no ft_on_transfer, so a Q transfer
/// to it is refunded in full (the receiver call fails), and the op path refuses a quote.
#[tokio::test]
async fn nearfun_has_no_quote_token_entry() -> Result<()> {
    let e = venv().await?;
    let tok = nearfun(&e).await?;
    let u1 = sub(&e.root, "qbuyer", 10 * NEAR).await?;
    ok(u1
        .call(e.wrap.id(), "near_deposit")
        .args_json(json!({}))
        .deposit(NearToken::from_near(2))
        .transact()
        .await?)?;
    let r = u1
        .call(e.wrap.id(), "ft_transfer_call")
        .args_json(json!({"receiver_id": tok, "amount": NEAR.to_string(), "msg": "{\"buy\":{\"min_tokens_out\":\"1\"}}"}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?;
    let s = format!("{:?}", r.receipt_failures());
    assert!(s.contains("MethodNotFound") || s.contains("MethodResolveError"), "{}", &s[..s.len().min(400)]);
    assert_eq!(r.json::<String>()?, "0", "nothing used: refunded");
    let t = e.ta("nfa", 5 * NEAR, (2 * NEAR, 4 * NEAR), vec![dex()]).await?;
    let r = e
        .exec(
            &t,
            json!([{"CurveBuy": {"venue": tok, "quote": "usdc.near", "amount": "5", "min_out": "1",
        "gas": (100 * TGAS).to_string()}}]),
            "nq",
            NEAR,
        )
        .await?;
    fails_with(&r, "E_CURVE_QUOTE");
    Ok(())
}

/// Fee exactness of a NearIn buy (NearFun refunds nothing here, quote `refund: 0`). Fixed by F1:
/// the settle subtracts the tx's gas-refund allowance (prepaid gas x GAS_PRICE_BOUND = 0.06 N at
/// 300 TGas), which covers every gas refund at the mainnet gas price (1e8). The sandbox runs at a
/// 1e9 gas price, so its gas refunds exceed the allowance (measured: 0.229 N left after it, fee
/// 0.0077 instead of 0.01 N): exactness can only be asserted at a mainnet-like gas price; the
/// exact values are unit tested in venues/settle_tests.rs.
#[tokio::test]
#[ignore = "exact only at a gas price <= GAS_PRICE_BOUND (sandbox runs 1e9); see settle_tests.rs"]
async fn nearfun_buy_fee_exact() -> Result<()> {
    let e = venv().await?;
    let tok = nearfun(&e).await?;
    let t = e.ta("nfa", 20 * NEAR, (5 * NEAR, 20 * NEAR), vec![dex()]).await?;
    let q: Value =
        e.worker.view(&tok, "quote_buy").args_json(json!({"near_in": NEAR.to_string()})).await?.json()?;
    assert_eq!(u(&q["refund"]), 0);
    let storage: Value = e.worker.view(&tok, "storage_balance_bounds").await?.json()?;
    let fees0 = e.near(e.fees.id()).await?;
    let ops = json!([{"StorageDeposit": {"token": tok, "amount": u(&storage["min"]).to_string()}},
        {"CurveBuy": {"venue": tok, "amount": NEAR.to_string(), "min_out": "1", "gas": (100 * TGAS).to_string()}}]);
    ok(e.exec(&t, ops, "nbx", 2 * NEAR).await?)?;
    assert_eq!(e.near(e.fees.id()).await? - fees0, bps(NEAR));
    Ok(())
}
