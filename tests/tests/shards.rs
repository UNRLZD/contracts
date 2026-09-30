//! v1.5: Shards launchpad tokens (curve + in-token AMM) with the REAL Shards token wasm
//! (mainnet templates 0.1.0 BqWmwKZ5, 0.2.0 2nD3b7Y9, v2.5 6uqYcTCa / EzdS4z28; fetched into
//! tests/.cache). Interface: docs/launchpads/shards.md.
//!
//! Gas, measured with `shards_probe_plain_all_templates` (all 4 templates; curve and AMM equal):
//! - buy (`wrap.ft_transfer_call` -> `ft_on_transfer`): 30 TGas attached fails, 35 works; burns
//!   7.5-8.6 TGas in total (the graduating buy 8.6). ShardsBuy caps it at 150.
//! - `sell_exact_in`: works with 5 TGas attached; burns 3.1 (0.1.0) - 3.7 (v2.5) TGas.
//! - `withdraw_quote{amount}`: 75 TGas attached fails (panic, credit kept), 80 works; it
//!   pre-attaches fixed gas to near_withdraw / resolve_unwrap / resolve_payout but burns only
//!   11.5 (0.1.0) - 12.8 (v2.5) TGas. The account attaches GAS_SHARDS_WITHDRAW = 150.
//! - `graduate()`: 2.4-2.8 TGas.
//!
//! Behaviour on every template: an unregistered buyer is refunded in full (no panic); `order_id`
//! is deduplicated per account, only by a buy that FILLED (a refused buy leaves it unused, another
//! account may use it); a past `deadline_ns` refunds; a buy past the curve's end is clamped (used <
//! amount) and latches `ready_to_graduate`, where buys refund and sells panic until `graduate()`.
use anyhow::Result;
use integration_tests::*;
use near_workspaces::types::{Gas, NearToken};
use near_workspaces::{Account, AccountId, Contract};
use serde_json::{json, Value};

const TOK: &str = "l000001.factory.shardsmarket.near";

async fn state(
    t: &AccountId,
    w: &near_workspaces::Worker<near_workspaces::network::Sandbox>,
) -> Result<Value> {
    Ok(w.view(t, "get_state").await?.json()?)
}

async fn quote(
    w: &near_workspaces::Worker<near_workspaces::network::Sandbox>,
    t: &AccountId,
    side: &str,
    amount: u128,
) -> Result<Value> {
    Ok(w.view(t, if side == "buy" { "quote_buy" } else { "quote_sell" })
        .args_json(json!({"amount_in": amount.to_string()}))
        .await?
        .json()?)
}

fn u(v: &Value) -> u128 {
    v.as_str().and_then(|s| s.parse().ok()).unwrap_or(0)
}

/// A plain (non-trading-account) Shards buy: wrap.ft_transfer_call → token.ft_on_transfer.
#[allow(clippy::too_many_arguments)]
async fn plain_buy(
    buyer: &Account,
    oid: &str,
    wrap: &AccountId,
    token: &AccountId,
    amount: u128,
    min_out: u128,
    gas_tgas: u64,
    deadline: u64,
) -> Result<near_workspaces::result::ExecutionFinalResult> {
    Ok(buyer
        .call(wrap, "ft_transfer_call")
        .args_json(json!({"receiver_id": token, "amount": amount.to_string(),
            "msg": shards_buy_msg(oid, min_out, deadline)}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(gas_tgas))
        .transact()
        .await?)
}

/// Probe (plain accounts, no trading account): init every template, buy/sell on the curve,
/// unregistered buy, graduation (clamped final buy), AMM buy/sell, and the minimum attached gas of
/// ft_transfer_call(buy) / sell_exact_in / withdraw_quote. Results go to stdout and
/// $SHARDS_GAS_OUT (scratch). Run with `--nocapture`.
#[tokio::test]
#[ignore = "measurement probe (~150 s): cargo test --test shards shards_probe -- --ignored --nocapture"]
async fn shards_probe_plain_all_templates() -> Result<()> {
    let mut report = String::new();
    for (t, _, _, _) in SHARDS_TEMPLATES {
        let worker = near_workspaces::sandbox().await?;
        let root = worker.root_account()?;
        let wrap = install_mainnet(&worker, "wrap.near").await?;
        ok(wrap.call("new").args_json(json!({})).transact().await?)?;
        let factory = shards_factory(&worker).await?;
        let token: Contract =
            shards_token_on(&worker, wrap.id(), root.id(), &factory, TOK, t, (100, 100)).await?;
        let tid = token.id().clone();
        let st = state(&tid, &worker).await?;
        report += &format!("== {t}: phase after init {}\n", st["phase"]);
        let buyer = sub(&root, "buyer", 6_000 * NEAR).await?;
        let unreg = sub(&root, "unreg", 20 * NEAR).await?;
        for b in [&buyer, &unreg] {
            ok(b.call(wrap.id(), "storage_deposit")
                .args_json(json!({}))
                .deposit(NearToken::from_yoctonear(STORAGE))
                .transact()
                .await?)?;
            ok(b.call(wrap.id(), "near_deposit")
                .args_json(json!({}))
                .deposit(NearToken::from_near(if b.id() == buyer.id() { 5_500 } else { 10 }))
                .transact()
                .await?)?;
        }
        ok(buyer
            .call(&tid, "storage_deposit")
            .args_json(json!({"account_id": buyer.id(), "registration_only": true}))
            .deposit(NearToken::from_yoctonear(SHARDS_STORAGE))
            .transact()
            .await?)?;
        let dl = worker.view_block().await?.timestamp() + 600_000_000_000;

        // unregistered buyer: refund or panic?
        let w0 = u(&wrap.view("ft_balance_of").args_json(json!({"account_id": unreg.id()})).await?.json()?);
        let r = plain_buy(&unreg, "p1", wrap.id(), &tid, NEAR, 1, 100, dl).await?;
        let w1 = u(&wrap.view("ft_balance_of").args_json(json!({"account_id": unreg.id()})).await?.json()?);
        report += &format!(
            "unregistered buy: tx_ok={} ret={:?} wnear_delta={} receipt_failures={}\n",
            r.is_success(),
            r.clone().json::<String>().ok(),
            w0 as i128 - w1 as i128,
            r.receipt_failures().len()
        );

        // curve buy, min attached gas
        for g in [20u64, 25, 30, 35, 40, 50, 60, 80, 100] {
            let q = quote(&worker, &tid, "buy", NEAR / 10).await?;
            let r =
                plain_buy(&buyer, &format!("p2-{g}"), wrap.id(), &tid, NEAR / 10, u(&q["amount_out"]), g, dl)
                    .await?;
            let used: Option<String> = r.clone().json().ok();
            report += &format!(
                "curve buy 0.1 NEAR gas {g}: ok={} used={:?} total_burnt={:.1}T {:?}\n",
                r.is_success(),
                used,
                r.total_gas_burnt.as_gas() as f64 / 1e12,
                gas_by_receipt(&r)
            );
        }
        // order_id dedupe: same id twice (same account), same id from another account, and an id
        // whose first use was refused (min_out) then retried.
        {
            let used = |r: &near_workspaces::result::ExecutionFinalResult| r.clone().json::<String>().ok();
            let r1 = plain_buy(&buyer, "dup", wrap.id(), &tid, NEAR / 10, 1, 100, dl).await?;
            let r2 = plain_buy(&buyer, "dup", wrap.id(), &tid, NEAR / 10, 1, 100, dl).await?;
            report +=
                &format!("dedupe same account: first used={:?} second used={:?}\n", used(&r1), used(&r2));
            let other = sub(&root, "other", 20 * NEAR).await?;
            ok(other
                .call(wrap.id(), "storage_deposit")
                .args_json(json!({}))
                .deposit(NearToken::from_yoctonear(STORAGE))
                .transact()
                .await?)?;
            ok(other
                .call(wrap.id(), "near_deposit")
                .args_json(json!({}))
                .deposit(NearToken::from_near(5))
                .transact()
                .await?)?;
            ok(other
                .call(&tid, "storage_deposit")
                .args_json(json!({"account_id": other.id(), "registration_only": true}))
                .deposit(NearToken::from_yoctonear(SHARDS_STORAGE))
                .transact()
                .await?)?;
            let r3 = plain_buy(&other, "dup", wrap.id(), &tid, NEAR / 10, 1, 100, dl).await?;
            report += &format!("dedupe other account same id: used={:?}\n", used(&r3));
            let q = quote(&worker, &tid, "buy", NEAR / 10).await?;
            let r4 = plain_buy(&buyer, "retry", wrap.id(), &tid, NEAR / 10, u(&q["amount_out"]) * 2, 100, dl)
                .await?;
            let r5 = plain_buy(&buyer, "retry", wrap.id(), &tid, NEAR / 10, 1, 100, dl).await?;
            report += &format!(
                "refused then retried same id: first used={:?} retry used={:?}\n",
                used(&r4),
                used(&r5)
            );
            let far = worker.view_block().await?.timestamp() + 3_600_000_000_000;
            let r6 = plain_buy(&buyer, "far", wrap.id(), &tid, NEAR / 10, 1, 100, far).await?;
            let past = worker.view_block().await?.timestamp() - 1;
            let r7 = plain_buy(&buyer, "past", wrap.id(), &tid, NEAR / 10, 1, 100, past).await?;
            report += &format!("deadline +1h used={:?}; deadline past used={:?}\n", used(&r6), used(&r7));
            let logs: Vec<String> = r1.logs().iter().map(|l| l.to_string()).collect();
            report += &format!(
                "buy logs: {:?}\n",
                logs.iter().map(|l| l.chars().take(300).collect::<String>()).collect::<Vec<_>>()
            );
        }
        // slippage refusal: min_out above the quote
        let q = quote(&worker, &tid, "buy", NEAR).await?;
        let r = plain_buy(&buyer, "p3", wrap.id(), &tid, NEAR, u(&q["amount_out"]) + 1, 100, dl).await?;
        report += &format!(
            "curve buy min_out+1: ok={} used={:?}\n",
            r.is_success(),
            r.clone().json::<String>().ok()
        );

        let bal =
            u(&token.view("ft_balance_of").args_json(json!({"account_id": buyer.id()})).await?.json()?);
        report += &format!("buyer token balance {bal}\n");
        // curve sell: min attached gas of sell_exact_in, then withdraw_quote
        let piece = bal / 40;
        for g in [5u64, 8, 10, 15, 20, 30] {
            let q = quote(&worker, &tid, "sell", piece).await?;
            let r = buyer
                .call(&tid, "sell_exact_in")
                .args_json(json!({"amount": piece.to_string(), "min_amount_out": q["amount_out"],
                    "max_total_fee_bps": 1100, "deadline_ns": dl.to_string()}))
                .deposit(NearToken::from_yoctonear(1))
                .gas(Gas::from_tgas(g))
                .transact()
                .await?;
            report += &format!(
                "curve sell_exact_in gas {g}: ok={} ret={:?} quote={} burnt={:.1}T\n",
                r.is_success(),
                r.clone().json::<String>().ok(),
                q["amount_out"],
                r.total_gas_burnt.as_gas() as f64 / 1e12
            );
        }
        let sell_slip = {
            let q = quote(&worker, &tid, "sell", piece).await?;
            buyer
                .call(&tid, "sell_exact_in")
                .args_json(json!({"amount": piece.to_string(), "min_amount_out": (u(&q["amount_out"]) + 1).to_string(),
                    "max_total_fee_bps": 1100, "deadline_ns": dl.to_string()}))
                .deposit(NearToken::from_yoctonear(1))
                .gas(Gas::from_tgas(30))
                .transact()
                .await?
        };
        report += &format!(
            "curve sell min_out+1: ok={} err={:?}\n",
            sell_slip.is_success(),
            sell_slip
                .clone()
                .into_result()
                .err()
                .map(|e| format!("{e:?}").chars().take(200).collect::<String>())
        );
        for g in [60u64, 65, 70, 75, 80, 100] {
            let acct: Value =
                token.view("get_account").args_json(json!({"account_id": buyer.id()})).await?.json()?;
            let credit = u(&acct["quote_credit"]);
            if credit == 0 {
                break;
            }
            let part = credit / 4;
            let n0 = worker.view_account(buyer.id()).await?.balance.as_yoctonear();
            let r = buyer
                .call(&tid, "withdraw_quote")
                .args_json(json!({"amount": part.to_string()}))
                .deposit(NearToken::from_yoctonear(1))
                .gas(Gas::from_tgas(g))
                .transact()
                .await?;
            let n1 = worker.view_account(buyer.id()).await?.balance.as_yoctonear();
            let acct2: Value =
                token.view("get_account").args_json(json!({"account_id": buyer.id()})).await?.json()?;
            if g == 80 && t == "v0_1_0" {
                for o in r.receipt_outcomes() {
                    report += &format!(
                        "   [{}] {:?} logs={:?}\n",
                        o.executor_id,
                        format!("{:?}", o.clone().into_result()).chars().take(200).collect::<String>(),
                        o.logs.iter().map(|l| l.chars().take(160).collect::<String>()).collect::<Vec<_>>()
                    );
                }
            }
            report += &format!(
                "withdraw_quote({part}) gas {g}: ok={} failures={} near_delta={} credit_after={} burnt={:.1}T {:?}\n",
                r.is_success(),
                r.receipt_failures().len(),
                n1 as i128 - n0 as i128,
                acct2["quote_credit"],
                r.total_gas_burnt.as_gas() as f64 / 1e12,
                gas_by_receipt(&r)
            );
        }

        // graduation: a buy larger than the rest of the curve is clamped
        let q = quote(&worker, &tid, "buy", 2_500 * NEAR).await?;
        report += &format!("quote_buy 2500 NEAR: {q}\n");
        let wb0 =
            u(&wrap.view("ft_balance_of").args_json(json!({"account_id": buyer.id()})).await?.json()?);
        let r = plain_buy(&buyer, "p4", wrap.id(), &tid, 2_500 * NEAR, u(&q["amount_out"]), 100, dl).await?;
        let wb1 =
            u(&wrap.view("ft_balance_of").args_json(json!({"account_id": buyer.id()})).await?.json()?);
        let st = state(&tid, &worker).await?;
        report += &format!(
            "graduating buy: ok={} used={:?} wnear_spent={} phase={} burnt={:.1}T\n",
            r.is_success(),
            r.clone().json::<String>().ok(),
            wb0 - wb1,
            st["phase"],
            r.total_gas_burnt.as_gas() as f64 / 1e12
        );
        let r = plain_buy(&buyer, "p5", wrap.id(), &tid, NEAR, 1, 100, dl).await?;
        report +=
            &format!("buy while latched: ok={} used={:?}\n", r.is_success(), r.clone().json::<String>().ok());
        let r = buyer
            .call(&tid, "sell_exact_in")
            .args_json(json!({"amount": piece.to_string(), "min_amount_out": "1", "max_total_fee_bps": 1100, "deadline_ns": dl.to_string()}))
            .deposit(NearToken::from_yoctonear(1))
            .gas(Gas::from_tgas(30))
            .transact()
            .await?;
        report += &format!("sell while latched: ok={}\n", r.is_success());
        let r = root.call(&tid, "graduate").args_json(json!({})).gas(Gas::from_tgas(300)).transact().await?;
        report += &format!(
            "graduate: ok={} ret={:?} burnt={:.1}T phase={}\n",
            r.is_success(),
            r.clone().json::<bool>().ok(),
            r.total_gas_burnt.as_gas() as f64 / 1e12,
            state(&tid, &worker).await?["phase"]
        );
        // AMM
        for g in [30u64, 35, 40, 50] {
            let q = quote(&worker, &tid, "buy", NEAR).await?;
            let r = plain_buy(&buyer, &format!("p6-{g}"), wrap.id(), &tid, NEAR, u(&q["amount_out"]), g, dl)
                .await?;
            report += &format!(
                "amm buy 1 NEAR gas {g}: ok={} used={:?} burnt={:.1}T\n",
                r.is_success(),
                r.clone().json::<String>().ok(),
                r.total_gas_burnt.as_gas() as f64 / 1e12
            );
        }
        for g in [10u64, 15, 20, 30] {
            let q = quote(&worker, &tid, "sell", piece).await?;
            let r = buyer
                .call(&tid, "sell_exact_in")
                .args_json(json!({"amount": piece.to_string(), "min_amount_out": q["amount_out"], "max_total_fee_bps": 1100, "deadline_ns": dl.to_string()}))
                .deposit(NearToken::from_yoctonear(1))
                .gas(Gas::from_tgas(g))
                .transact()
                .await?;
            report += &format!(
                "amm sell_exact_in gas {g}: ok={} ret={:?} burnt={:.1}T\n",
                r.is_success(),
                r.clone().json::<String>().ok(),
                r.total_gas_burnt.as_gas() as f64 / 1e12
            );
        }
        let r = buyer
            .call(&tid, "withdraw_quote")
            .args_json(json!({}))
            .deposit(NearToken::from_yoctonear(1))
            .gas(Gas::from_tgas(100))
            .transact()
            .await?;
        report += &format!(
            "amm withdraw_quote({{}}) gas 100: ok={} burnt={:.1}T {:?}\n",
            r.is_success(),
            r.total_gas_burnt.as_gas() as f64 / 1e12,
            gas_by_receipt(&r)
        );
        let r = buyer
            .call(&tid, "withdraw_quote")
            .args_json(json!({}))
            .deposit(NearToken::from_yoctonear(1))
            .gas(Gas::from_tgas(100))
            .transact()
            .await?;
        report += &format!("withdraw_quote with no credit: ok={}\n", r.is_success());
    }
    println!("{report}");
    if let Ok(p) = std::env::var("SHARDS_GAS_OUT") {
        std::fs::write(p, &report)?;
    }
    Ok(())
}

// ======================= trading account (v1.5 typed Shards ops) =======================

/// floor(a * b / c), 256-bit intermediate (the contract's pro-rata fee: policy::mul_div).
fn mul_div(a: u128, b: u128, c: u128) -> u128 {
    let (hi, lo) = {
        const M: u128 = u64::MAX as u128;
        let (a0, a1, b0, b1) = (a & M, a >> 64, b & M, b >> 64);
        let (p00, p01, p10, p11) = (a0 * b0, a0 * b1, a1 * b0, a1 * b1);
        let mid = (p00 >> 64) + (p01 & M) + (p10 & M);
        (p11 + (p01 >> 64) + (p10 >> 64) + (mid >> 64), (p00 & M) | (mid << 64))
    };
    let (mut rem, mut q) = (0u128, 0u128);
    for i in (0..256u32).rev() {
        let bit = if i >= 128 { (hi >> (i - 128)) & 1 } else { (lo >> i) & 1 };
        let carry = rem >> 127;
        rem = (rem << 1) | bit;
        if carry == 1 || rem >= c {
            rem = rem.wrapping_sub(c);
            if i < 128 {
                q |= 1 << i;
            }
        }
    }
    q
}

const BIG: (u128, u128) = (5_000 * NEAR, 50_000 * NEAR);
const BUY_GAS: u64 = 100;
const SELL_GAS: u64 = 30;

struct Sx {
    env: Env,
    factory: Account,
    token: Contract,
    u: User,
}

async fn setup(t: &str, fund: u128) -> Result<Sx> {
    let env = Env::new_shards().await?;
    let factory = shards_factory(&env.worker).await?;
    let token = shards_token(&env, &factory, TOK, t, (100, 200)).await?;
    let u = env.user("alice", fund, BIG).await?;
    Ok(Sx { env, factory, token, u })
}

fn buy_ops(token: &AccountId, amount: u128, min_out: u128, register: bool) -> Value {
    let mut ops = vec![];
    if register {
        ops.push(json!({"StorageDeposit": {"token": token, "amount": SHARDS_STORAGE.to_string()}}));
    }
    ops.push(json!({"NearDeposit": {"amount": amount.to_string()}}));
    ops.push(
        json!({"ShardsBuy": {"token": token, "amount": amount.to_string(), "min_out": min_out.to_string(),
        "gas": (BUY_GAS * TGAS).to_string()}}),
    );
    Value::Array(ops)
}

fn sell_ops(token: &AccountId, amount: u128, min_out: u128) -> Value {
    json!([{"ShardsSell": {"token": token, "amount": amount.to_string(), "min_out": min_out.to_string(),
        "gas": (SELL_GAS * TGAS).to_string()}}])
}

/// (used, fee) of the account's `settled` event.
fn settled(r: &near_workspaces::result::ExecutionFinalResult) -> (u128, u128) {
    for l in r.logs() {
        if let Some(j) = l.strip_prefix("EVENT_JSON:") {
            let v: Value = serde_json::from_str(j).unwrap_or_default();
            if v["standard"] == "nttrade" && v["event"] == "settled" {
                return (u(&v["data"]["used"]), u(&v["data"]["fee"]));
            }
        }
    }
    panic!("no settled event in {:?}", r.logs());
}

/// The token's `trade_executed` event data (the last one in `r`).
fn trade(r: &near_workspaces::result::ExecutionFinalResult) -> Option<Value> {
    r.logs().iter().rev().find_map(|l| {
        let v: Value = serde_json::from_str(l.strip_prefix("EVENT_JSON:")?).ok()?;
        (v["standard"] == "nearlaunch" && v["event"] == "trade_executed").then(|| v["data"][0].clone())
    })
}

async fn tok_bal(sx: &Sx) -> Result<u128> {
    sx.env.ft_balance(sx.token.id(), &sx.u.account).await
}

async fn wnear(sx: &Sx) -> Result<u128> {
    sx.env.ft_balance(sx.env.wrap.id(), &sx.u.account).await
}

async fn phase(sx: &Sx) -> Result<String> {
    Ok(state(sx.token.id(), &sx.env.worker).await?["phase"].as_str().unwrap_or("").to_string())
}

async fn credit(sx: &Sx) -> Result<u128> {
    let a: Value =
        sx.token.view("get_account").args_json(json!({"account_id": sx.u.account})).await?.json()?;
    Ok(u(&a["quote_credit"]))
}

/// Buy `amount` wNEAR of the token through the account at the exact quote; checks output to self,
/// the fee on the used input, and that the unused wNEAR stays on the account.
async fn check_buy(sx: &Sx, id: &str, amount: u128, register: bool) -> Result<u128> {
    let q = quote(&sx.env.worker, sx.token.id(), "buy", amount).await?;
    let out = u(&q["amount_out"]);
    let (t0, w0, f0) = (tok_bal(sx).await?, wnear(sx).await?, sx.env.near_balance(sx.env.fees.id()).await?);
    let r = okr(sx
        .env
        .exec(&sx.u.device, &sx.u.account, buy_ops(sx.token.id(), amount, out, register), id, BIG.0)
        .await?)?;
    let (used, fee_paid) = settled(&r);
    assert_eq!(used, amount - u(&q["refund"]), "{id}: used");
    assert_eq!(fee_paid, mul_div(fee(amount), used, amount), "{id}: fee = fee_bps x used (pro-rata)");
    assert_eq!(
        sx.env.near_balance(sx.env.fees.id()).await? - f0,
        fee_paid,
        "{id}: fee reaches fee_recipient"
    );
    let tr = trade(&r).expect("trade_executed");
    assert_eq!(tr["account_id"], json!(sx.u.account), "{id}: buyer = the account");
    assert_eq!(tr["recipient_id"], json!(sx.u.account), "{id}: output to self");
    assert_eq!(tok_bal(sx).await? - t0, out, "{id}: tokens land on the account");
    assert_eq!(wnear(sx).await? + used, w0 + amount, "{id}: unused wNEAR back on the account");
    Ok(out)
}

/// Sell `amount` tokens through the account at the exact quote; checks native NEAR arrives, the
/// fee is on the credited output, and no credit is left in the token.
async fn check_sell(sx: &Sx, id: &str, amount: u128) -> Result<u128> {
    let q = quote(&sx.env.worker, sx.token.id(), "sell", amount).await?;
    let out = u(&q["amount_out"]);
    let (t0, n0, f0) = (
        tok_bal(sx).await?,
        sx.env.near_balance(&sx.u.account).await?,
        sx.env.near_balance(sx.env.fees.id()).await?,
    );
    let r = okr(sx
        .env
        .exec(&sx.u.device, &sx.u.account, sell_ops(sx.token.id(), amount, out), id, BIG.0)
        .await?)?;
    let (used, fee_paid) = settled(&r);
    assert_eq!(used, amount, "{id}: sell used");
    assert_eq!(fee_paid, fee(out), "{id}: fee = fee_bps x credited output");
    assert!(fee_paid > fee(out / 2), "{id}: fee is on the actual output, not a lower bound");
    assert_eq!(
        sx.env.near_balance(sx.env.fees.id()).await? - f0,
        fee_paid,
        "{id}: fee reaches fee_recipient"
    );
    assert_eq!(t0 - tok_bal(sx).await?, amount, "{id}: tokens sold");
    assert_eq!(credit(sx).await?, 0, "{id}: whole credit paid out");
    let n1 = sx.env.near_balance(&sx.u.account).await?;
    // native NEAR arrived on the account: output − fee − this tx's gas (≤ 0.05 NEAR)
    assert!(
        n1 + fee_paid + NEAR / 20 >= n0 + out && n1 + fee_paid <= n0 + out,
        "{id}: {n0} -> {n1}, out {out}"
    );
    let tr = trade(&r).expect("trade_executed");
    assert_eq!(tr["account_id"], json!(sx.u.account), "{id}: seller = the account");
    Ok(out)
}

/// A plain account buys the curve to its end (clamped) and `graduate()` opens the AMM.
async fn graduate_by_whale(sx: &Sx) -> Result<()> {
    let whale = sub(&sx.env.root, "whale", 3_000 * NEAR).await?;
    ok(whale
        .call(sx.env.wrap.id(), "storage_deposit")
        .args_json(json!({}))
        .deposit(NearToken::from_yoctonear(STORAGE))
        .transact()
        .await?)?;
    ok(whale
        .call(sx.env.wrap.id(), "near_deposit")
        .args_json(json!({}))
        .deposit(NearToken::from_near(2_600))
        .transact()
        .await?)?;
    ok(whale
        .call(sx.token.id(), "storage_deposit")
        .args_json(json!({"account_id": whale.id(), "registration_only": true}))
        .deposit(NearToken::from_yoctonear(SHARDS_STORAGE))
        .transact()
        .await?)?;
    let dl = sx.env.now_ns().await? + 600_000_000_000;
    ok(plain_buy(&whale, "whale", sx.env.wrap.id(), sx.token.id(), 2_500 * NEAR, 1, 100, dl).await?)?;
    assert_eq!(phase(sx).await?, "ready_to_graduate");
    ok(sx
        .env
        .root
        .call(sx.token.id(), "graduate")
        .args_json(json!({}))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?)?;
    assert_eq!(phase(sx).await?, "live_amm");
    Ok(())
}

async fn basic_curve_and_amm(t: &str) -> Result<()> {
    let sx = setup(t, 50 * NEAR).await?;
    assert_eq!(phase(&sx).await?, "live_curve");
    let got = check_buy(&sx, "b1", 2 * NEAR, true).await?;
    check_buy(&sx, "b2", NEAR, false).await?;
    check_sell(&sx, "s1", got / 2).await?;
    graduate_by_whale(&sx).await?;
    let got = check_buy(&sx, "amm-b1", 2 * NEAR, false).await?;
    check_sell(&sx, "amm-s1", got).await?;
    Ok(())
}

#[tokio::test]
async fn shards_v010_curve_and_amm_buy_sell() -> Result<()> {
    basic_curve_and_amm("v0_1_0").await
}

#[tokio::test]
async fn shards_v020_curve_and_amm_buy_sell() -> Result<()> {
    basic_curve_and_amm("v0_2_0").await
}

#[tokio::test]
async fn shards_v25_6uqy_curve_and_amm_buy_sell() -> Result<()> {
    basic_curve_and_amm("v0_2_0_6uqY").await
}

/// Current template (EzdS4z28, v2.5): slippage refusals on both sides, graduation mid-trade by the
/// account itself (clamped buy: used < amount, fee pro-rata, the rest of the wNEAR back), trades
/// while latched, then the AMM.
#[tokio::test]
async fn shards_ezds_slippage_graduation_mid_trade_and_amm() -> Result<()> {
    let sx = setup("v0_2_0_EzdS", 2_700 * NEAR).await?;
    let got = check_buy(&sx, "b1", 5 * NEAR, true).await?;

    // buy slippage: min_out above what the token gives -> full wNEAR refund, no fee, no tokens
    let q = quote(&sx.env.worker, sx.token.id(), "buy", NEAR).await?;
    let (t0, w0, f0) = (tok_bal(&sx).await?, wnear(&sx).await?, sx.env.near_balance(sx.env.fees.id()).await?);
    let r = okr(sx
        .env
        .exec(
            &sx.u.device,
            &sx.u.account,
            buy_ops(sx.token.id(), NEAR, u(&q["amount_out"]) + 1, false),
            "slip-b",
            BIG.0,
        )
        .await?)?;
    assert_eq!(settled(&r), (0, 0));
    assert_eq!(tok_bal(&sx).await?, t0);
    assert_eq!(wnear(&sx).await?, w0 + NEAR, "wrapped input stays on the account as wNEAR");
    assert_eq!(sx.env.near_balance(sx.env.fees.id()).await?, f0);

    // sell slippage: the token panics -> the sell receipt fails, tokens kept, no fee, no credit
    let q = quote(&sx.env.worker, sx.token.id(), "sell", got / 4).await?;
    let r = sx
        .env
        .exec(
            &sx.u.device,
            &sx.u.account,
            sell_ops(sx.token.id(), got / 4, u(&q["amount_out"]) + 1),
            "slip-s",
            BIG.0,
        )
        .await?;
    assert!(r.is_success() && !r.receipt_failures().is_empty(), "sell receipt fails, execute itself ok");
    assert_eq!(settled(&r), (0, 0));
    assert_eq!(tok_bal(&sx).await?, t0);
    assert_eq!(credit(&sx).await?, 0);
    assert_eq!(sx.env.near_balance(sx.env.fees.id()).await?, f0);

    // graduation mid-trade: the account's 2500 NEAR buy is clamped at the end of the curve
    let amount = 2_500 * NEAR;
    let q = quote(&sx.env.worker, sx.token.id(), "buy", amount).await?;
    let refund = u(&q["refund"]);
    assert!(refund > 0, "quote says the buy is clamped: {q}");
    let (w0, f0) = (wnear(&sx).await?, sx.env.near_balance(sx.env.fees.id()).await?);
    let r = okr(sx
        .env
        .exec(
            &sx.u.device,
            &sx.u.account,
            buy_ops(sx.token.id(), amount, u(&q["amount_out"]), false),
            "grad",
            BIG.0,
        )
        .await?)?;
    let (used, fee_paid) = settled(&r);
    assert_eq!(used, amount - refund, "used = the part that filled the curve");
    assert_eq!(fee_paid, mul_div(fee(amount), used, amount), "fee pro-rata on the used part only");
    assert_eq!(sx.env.near_balance(sx.env.fees.id()).await? - f0, fee_paid);
    assert_eq!(wnear(&sx).await?, w0 + refund, "the clamped remainder comes back as wNEAR");
    assert_eq!(phase(&sx).await?, "ready_to_graduate");

    // latched: a buy is refunded, a sell reverts
    let bal = tok_bal(&sx).await?;
    let r = okr(sx
        .env
        .exec(&sx.u.device, &sx.u.account, buy_ops(sx.token.id(), NEAR, 1, false), "latched-b", BIG.0)
        .await?)?;
    assert_eq!(settled(&r), (0, 0));
    let r = sx
        .env
        .exec(&sx.u.device, &sx.u.account, sell_ops(sx.token.id(), bal / 10, 1), "latched-s", BIG.0)
        .await?;
    assert!(!r.receipt_failures().is_empty());
    assert_eq!(settled(&r), (0, 0));
    assert_eq!(tok_bal(&sx).await?, bal);

    ok(sx
        .env
        .root
        .call(sx.token.id(), "graduate")
        .args_json(json!({}))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?)?;
    assert_eq!(phase(&sx).await?, "live_amm");
    check_buy(&sx, "amm-b", 3 * NEAR, false).await?;
    check_sell(&sx, "amm-s", bal / 5).await?;
    // AMM sell slippage reverts too
    let q = quote(&sx.env.worker, sx.token.id(), "sell", bal / 5).await?;
    let r = sx
        .env
        .exec(
            &sx.u.device,
            &sx.u.account,
            sell_ops(sx.token.id(), bal / 5, u(&q["amount_out"]) + 1),
            "amm-slip",
            BIG.0,
        )
        .await?;
    assert!(!r.receipt_failures().is_empty());
    assert_eq!(settled(&r), (0, 0));
    Ok(())
}

/// Only `<one label>.<allowlisted ShardsToken factory>` is a venue: the same real wasm anywhere
/// else, a deeper name, the factory itself, and the raw FtTransferCall shape (whose msg could
/// carry a recipient) are refused before anything moves. Also: an account without a ShardsToken
/// entry refuses every Shards op, and orders can't name the factory.
#[tokio::test]
async fn shards_hostile_venues_refused() -> Result<()> {
    let sx = setup("v0_2_0", 20 * NEAR).await?;
    let code = shards_wasm("v0_2_0").await?;
    let evil = install_code(&sx.env.worker, "evil.near", &code).await?;
    let deep = install_code(&sx.env.worker, &format!("x.{TOK}"), &code).await?;
    let lookalike = install_code(&sx.env.worker, "l1.factory-shardsmarket.near", &code).await?;
    for bad in [evil.id().clone(), deep.id().clone(), lookalike.id().clone(), SHARDS_FACTORY.parse()?] {
        let spent = sx.env.day_spent(&sx.u).await?;
        for (name, ops) in [
            ("buy", buy_ops(&bad, NEAR, 1, false)),
            ("sell", sell_ops(&bad, NEAR, 1)),
            ("withdraw", json!([{"ShardsWithdrawQuote": {"token": bad}}])),
        ] {
            let r = sx.env.exec(&sx.u.device, &sx.u.account, ops, &format!("{bad}-{name}"), BIG.0).await?;
            fails_with(&r, "E_BAD_DEX");
        }
        // storage on a non-venue: not this execute's token
        let r = sx
            .env
            .exec(
                &sx.u.device,
                &sx.u.account,
                json!([{"StorageDeposit": {"token": bad, "amount": SHARDS_STORAGE.to_string()}}]),
                &format!("{bad}-st"),
                BIG.0,
            )
            .await?;
        fails_with(&r, "E_STORAGE_TARGET");
        assert_eq!(sx.env.day_spent(&sx.u).await?, spent);
    }
    // the raw shape with a caller-supplied msg (a recipient could hide in it) is never a Shards path
    let msg =
        json!({"v": 1, "action": "buy", "order_id": "x", "min_amount_out": "1", "max_total_fee_bps": 1100,
        "deadline_ns": "1", "recipient_id": "evil.near"})
        .to_string();
    let r = sx.env.exec(&sx.u.device, &sx.u.account, json!([{"NearDeposit": {"amount": NEAR.to_string()}},
        {"FtTransferCall": {"token": sx.env.wrap.id(), "receiver_id": sx.token.id(), "amount": NEAR.to_string(), "msg": msg,
        "gas": (100 * TGAS).to_string()}}]), "raw", BIG.0).await?;
    fails_with(&r, "E_BAD_DEX");
    // orders: the token is a valid order venue, the factory is not
    let exp = sx.env.now_ns().await? + 3_600_000_000_000;
    for (dex, good) in [
        (sx.token.id().to_string(), true),
        (SHARDS_FACTORY.to_string(), false),
        (evil.id().to_string(), false),
    ] {
        let r = sx.u.device.call(&sx.u.account, "place_order")
            .args_json(json!({"token_in": sx.env.wrap.id(), "token_out": sx.token.id(), "amount_in": NEAR.to_string(),
                "min_out": "1", "trigger_meta": "{}", "expires_at_ns": exp.to_string(), "dexes": [dex]}))
            .gas(Gas::from_tgas(30)).transact().await?;
        if good {
            ok(r)?;
        } else {
            fails_with(&r, "E_BAD_DEX");
        }
    }
    // an account whose allowlist has no ShardsToken entry (factory without it) refuses Shards ops
    let plain = Env::new().await?;
    let pf = shards_factory(&plain.worker).await?;
    let t = shards_token(&plain, &pf, TOK, "v0_2_0", (100, 100)).await?;
    let u2 = plain.user("bob", 20 * NEAR, BIG).await?;
    let r = plain.exec(&u2.device, &u2.account, buy_ops(t.id(), NEAR, 1, true), "no-entry", BIG.0).await?;
    fails_with(&r, "E_BAD_DEX");
    let _ = &sx.factory;
    Ok(())
}

/// Unregistered buy (no StorageDeposit first): the token refunds in full, no fee, nothing lost.
/// ShardsWithdrawQuote with no credit: accepted (not spend), the token's panic moves nothing.
#[tokio::test]
async fn shards_unregistered_buy_and_withdraw_quote_recovery() -> Result<()> {
    let sx = setup("v0_2_0_EzdS", 20 * NEAR).await?;
    let (w0, f0) = (wnear(&sx).await?, sx.env.near_balance(sx.env.fees.id()).await?);
    let r = okr(sx
        .env
        .exec(&sx.u.device, &sx.u.account, buy_ops(sx.token.id(), NEAR, 1, false), "unreg", BIG.0)
        .await?)?;
    assert_eq!(settled(&r), (0, 0));
    assert_eq!(wnear(&sx).await?, w0 + NEAR, "refunded as wNEAR");
    assert_eq!(tok_bal(&sx).await?, 0);
    assert_eq!(sx.env.near_balance(sx.env.fees.id()).await?, f0);
    // the same client msg shape then works once registered (the refused id stayed unused)
    check_buy(&sx, "after-reg", NEAR, true).await?;

    let spent = sx.env.day_spent(&sx.u).await?;
    let r = sx
        .env
        .exec(
            &sx.u.device,
            &sx.u.account,
            json!([{"ShardsWithdrawQuote": {"token": sx.token.id()}}]),
            "wq",
            BIG.0,
        )
        .await?;
    assert!(r.is_success(), "execute accepted");
    assert!(!r.receipt_failures().is_empty(), "no credit: the token panics, nothing moves");
    // only the gas tally moves (not spend)
    let spent2 = sx.env.day_spent(&sx.u).await?;
    assert_eq!(spent2, spent, "withdraw_quote is not spend");
    Ok(())
}

async fn automation(sx: &Sx) -> Result<Account> {
    let sk = near_workspaces::types::SecretKey::from_random(near_workspaces::types::KeyType::ED25519);
    ok(sx
        .u
        .owner
        .call(&sx.u.account, "owner_set_automation_key")
        .args_json(json!({"public_key": sk.public_key(), "allowance": NEAR.to_string()}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(50))
        .transact()
        .await?)?;
    Ok(Account::from_secret_key(sx.u.account.clone(), sk, &sx.env.worker))
}

async fn place(
    sx: &Sx,
    token_in: &AccountId,
    token_out: &AccountId,
    amount: u128,
    min_out: u128,
) -> Result<u64> {
    let exp = sx.env.now_ns().await? + 3_600_000_000_000;
    let r = okr(sx.u.device.call(&sx.u.account, "place_order")
        .args_json(json!({"token_in": token_in, "token_out": token_out, "amount_in": amount.to_string(),
            "min_out": min_out.to_string(), "trigger_meta": "{\"kind\":\"limit\"}", "expires_at_ns": exp.to_string(),
            "dexes": [sx.token.id()]}))
        .gas(Gas::from_tgas(30)).transact().await?)?;
    Ok(r.json::<String>()?.parse()?)
}

async fn fire(
    auto: &Account,
    sx: &Sx,
    id: u64,
    ops: Value,
) -> Result<near_workspaces::result::ExecutionFinalResult> {
    Ok(auto
        .call(&sx.u.account, "execute_order")
        .args_json(json!({"order_id": id.to_string(), "ops": ops}))
        .gas(Gas::from_tgas(300))
        .transact()
        .await?)
}

async fn order_of(sx: &Sx, id: u64) -> Result<Value> {
    Ok(sx
        .env
        .worker
        .view(&sx.u.account, "get_order")
        .args_json(json!({"order_id": id.to_string()}))
        .await?
        .json()?)
}

/// 24/7 orders on a Shards token through the relayer (automation) key: a BUY refused by the token
/// (msg min_out above the market) reopens, and the refire under the SAME "order:N" order_id fills
/// (the token dedupes only filled ids); a SELL fills (native NEAR to self, fee on the credited
/// output) and a refused SELL (reverted) reopens. Terms are enforced: other token / amount / a
/// min_out below the stored one are refused.
#[tokio::test]
async fn shards_relayer_orders_buy_refire_and_sell() -> Result<()> {
    let sx = setup("v0_2_0_EzdS", 50 * NEAR).await?;
    check_buy(&sx, "seed", 5 * NEAR, true).await?;
    let auto = automation(&sx).await?;
    let wrap = sx.env.wrap.id().clone();
    let tok = sx.token.id().clone();

    // BUY order
    let q = quote(&sx.env.worker, &tok, "buy", NEAR).await?;
    let out = u(&q["amount_out"]);
    let id = place(&sx, &wrap, &tok, NEAR, out / 2).await?;
    // stored terms enforced
    fails_with(&fire(&auto, &sx, id, buy_ops(&tok, NEAR, out / 2 - 1, false)).await?, "E_ORDER_MIN_OUT");
    fails_with(&fire(&auto, &sx, id, buy_ops(&tok, NEAR - 1, out, false)).await?, "E_ORDER_MISMATCH");
    // refused by the token (min_out above the market): wNEAR back, order reopens
    let w0 = wnear(&sx).await?;
    let r = okr(fire(&auto, &sx, id, buy_ops(&tok, NEAR, out * 2, false)).await?)?;
    assert_eq!(settled(&r), (0, 0));
    assert!(r.logs().iter().any(|l| l.contains("order_reopened")), "{:?}", r.logs());
    assert_eq!(order_of(&sx, id).await?["pending"], json!(false));
    assert_eq!(wnear(&sx).await?, w0 + NEAR);
    // refire, same order_id "order:N" at the token: fills
    let t0 = tok_bal(&sx).await?;
    let q = quote(&sx.env.worker, &tok, "buy", NEAR).await?;
    let r = okr(fire(&auto, &sx, id, buy_ops(&tok, NEAR, u(&q["amount_out"]), false)).await?)?;
    assert_eq!(settled(&r), (NEAR, fee(NEAR)));
    assert!(r.logs().iter().any(|l| l.contains("order_filled")));
    assert_eq!(trade(&r).unwrap()["order_id"], json!(format!("order:{id}")));
    assert_eq!(tok_bal(&sx).await? - t0, u(&q["amount_out"]));
    assert_eq!(order_of(&sx, id).await?, Value::Null);

    // SELL order
    let bal = tok_bal(&sx).await?;
    let amt = bal / 3;
    let q = quote(&sx.env.worker, &tok, "sell", amt).await?;
    let out = u(&q["amount_out"]);
    let id = place(&sx, &tok, &wrap, amt, out / 2).await?;
    // refused (min_out above the market): the sell reverts, the order reopens, tokens kept
    let r = fire(&auto, &sx, id, sell_ops(&tok, amt, out + 1)).await?;
    assert_eq!(settled(&r), (0, 0));
    assert!(r.logs().iter().any(|l| l.contains("order_reopened")));
    assert_eq!(tok_bal(&sx).await?, bal);
    let f0 = sx.env.near_balance(sx.env.fees.id()).await?;
    let r = okr(fire(&auto, &sx, id, sell_ops(&tok, amt, out)).await?)?;
    let (used, fee_paid) = settled(&r);
    assert_eq!(used, amt);
    assert_eq!(fee_paid, fee(out), "fee on the credited output (not the order's min_out)");
    assert_eq!(sx.env.near_balance(sx.env.fees.id()).await? - f0, fee_paid);
    assert!(r.logs().iter().any(|l| l.contains("order_filled")));
    assert_eq!(credit(&sx).await?, 0);
    assert_eq!(tok_bal(&sx).await?, bal - amt);
    Ok(())
}

/// A device execute that reuses a client_order_id after its expiry passes the account's dedupe
/// (expired ids are pruned) but the token already used that order_id for a filled buy: the token
/// refunds in full, and the account charges no fee.
#[tokio::test]
async fn shards_client_order_id_reuse_after_expiry_refunds() -> Result<()> {
    let sx = setup("v0_2_0", 20 * NEAR).await?;
    let now = sx.env.now_ns().await?;
    let q = quote(&sx.env.worker, sx.token.id(), "buy", NEAR).await?;
    ok(sx
        .env
        .exec_at(
            &sx.u.device,
            &sx.u.account,
            buy_ops(sx.token.id(), NEAR, u(&q["amount_out"]), true),
            "same",
            BIG.0,
            now + 5_000_000_000,
        )
        .await?)?;
    // let the id expire
    while sx.env.now_ns().await? <= now + 6_000_000_000 {
        sx.env.worker.fast_forward(10).await?;
    }
    let (t0, w0, f0) = (tok_bal(&sx).await?, wnear(&sx).await?, sx.env.near_balance(sx.env.fees.id()).await?);
    let r = okr(sx
        .env
        .exec(&sx.u.device, &sx.u.account, buy_ops(sx.token.id(), NEAR, 1, false), "same", BIG.0)
        .await?)?;
    assert_eq!(settled(&r), (0, 0), "token dedupes its order_id: refunded, no fee");
    assert_eq!(tok_bal(&sx).await?, t0);
    assert_eq!(wnear(&sx).await?, w0 + NEAR);
    assert_eq!(sx.env.near_balance(sx.env.fees.id()).await?, f0);
    Ok(())
}
