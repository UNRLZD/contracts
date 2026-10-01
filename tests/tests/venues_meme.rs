//! v1.6 meme.cooking (presale auction, FactoryCurve::MemeCooking) through the trading account on
//! the REAL mainnet wasm (meme-cooking.near, pinned 4fiHyHn5…).
//!
//! Pad state: no mainnet state (6 MB, TOO_LARGE on every public RPC). The real wasm is deployed
//! fresh at its mainnet id and `new`ed with its mainnet config (fees 50 / 200 bps, guardians,
//! Rhea / locker / rewarder ids; the 10th init field `launch_fee` found by a sandbox probe), then
//! one auction is created with `create_meme` in its current (post-upgrade) shape (soft_cap,
//! hard_cap, team_allocation). Rhea (v2.ref-finance.near) is the real mainnet wasm (finalize
//! creates the pool there).
//!
//! Interface verified here (and fixed in venues/mod.rs):
//! - Deposit = `wrap.ft_transfer_call{meme-cooking, {"Deposit":{"meme_id"}}}`; meme.cooking takes a
//!   0.5% deposit fee inside. An UNREGISTERED account's deposit is refunded (AccountNotRegistered):
//!   `CurveClaim{MemeCookingRegister, amount}` = `storage_deposit{}` for self (0.02 N + 0.005 N per
//!   meme, above the generic StorageDeposit cap).
//! - `withdraw{meme_id, amount}` 1 yocto: wNEAR back minus meme.cooking's 2% withdraw fee.
//! - `claim{meme_id}` needs EXACTLY 1 yocto (0 = "Requires attached deposit of exactly 1
//!   yoctoNEAR"; the planner sent 0 before this suite).
mod venues_common;
use anyhow::Result;
use integration_tests::*;
use near_workspaces::result::ExecutionFinalResult;
use near_workspaces::types::{Gas, NearToken};
use near_workspaces::{Account, Contract};
use serde_json::{json, Value};
use venues_common::*;

const MC: &str = "meme-cooking.near";
const MC_HASH: &str = "4fiHyHn5RuEoywt4dhnwDrcsqLSC9R5Xxfk9DNQL2kii";
const G: u64 = 100 * TGAS;
/// meme.cooking fees (bps), as on mainnet
const DEPOSIT_FEE: u128 = 50;
const WITHDRAW_FEE: u128 = 200;
const REG: u128 = 25 * NEAR / 1000;
/// the token finalize creates for auction 0 (`<symbol>-<id>.meme-cooking.near`)
const TOKEN: &str = "prb-0.meme-cooking.near";

fn errs(r: &ExecutionFinalResult) -> String {
    let s = format!("{:?} {:?}", r.clone().into_result().err(), r.receipt_failures());
    s.split("ExecutionError(")
        .skip(1)
        .map(|p| p.chars().take(220).collect::<String>())
        .collect::<Vec<_>>()
        .join(" | ")
}

struct M {
    e: VEnv,
    mc: Contract,
    owner: Account,
    rhea: Contract,
}

/// meme.cooking fresh on its real wasm + one auction (id 0), soft cap `soft`, 300 s long.
async fn setup(soft: u128) -> Result<M> {
    let e = venv().await?;
    let mc = install_code(&e.worker, MC, &pinned(MC, Some(MC_HASH)).await?).await?;
    let owner = sub(&e.root, "mcowner", 200 * NEAR).await?;
    ok(mc
        .call("new")
        .args_json(
            json!({"owner": owner.id(), "guardians": [owner.id()], "ref_contract_id": "v2.ref-finance.near",
            "ref_locker_id": "token-locker.ref-labs.near", "rewarder_id": "rewards.0xshitzu.near",
            "deposit_fee": DEPOSIT_FEE, "withdraw_fee": WITHDRAW_FEE,
            "required_stakes": [[e.wrap.id(), NEAR.to_string()]],
            "shitstar_multipliers": [[e.wrap.id(), "69", "1000000"]], "launch_fee": 0}),
        )
        .transact()
        .await?)?;
    ok(owner
        .call(e.wrap.id(), "storage_deposit")
        .args_json(json!({"account_id": MC, "registration_only": true}))
        .deposit(NearToken::from_yoctonear(STORAGE))
        .transact()
        .await?)?;
    let rhea = install_mainnet(&e.worker, "v2.ref-finance.near").await?;
    ok(rhea
        .call("new")
        .args_json(json!({"owner_id": owner.id(), "boost_farm_id": owner.id(), "burrowland_id": owner.id(),
            "exchange_fee": 4, "referral_fee": 1}))
        .transact()
        .await?)?;
    // as on mainnet: Rhea registered on wrap, meme-cooking registered on Rhea (finalize creates the
    // pool and adds liquidity there)
    ok(owner
        .call(e.wrap.id(), "storage_deposit")
        .args_json(json!({"account_id": rhea.id(), "registration_only": true}))
        .deposit(NearToken::from_yoctonear(STORAGE))
        .transact()
        .await?)?;
    ok(owner
        .call(rhea.id(), "storage_deposit")
        .args_json(json!({"account_id": MC, "registration_only": false}))
        .deposit(NearToken::from_near(1))
        .transact()
        .await?)?;
    ok(owner
        .call(rhea.id(), "extend_whitelisted_tokens")
        .args_json(json!({"tokens": [e.wrap.id(), TOKEN]}))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?)?;
    let creator = sub(&e.root, "creator", 20 * NEAR).await?;
    ok(creator
        .call(mc.id(), "storage_deposit")
        .args_json(json!({}))
        .deposit(NearToken::from_yoctonear(REG))
        .transact()
        .await?)?;
    let r = creator
        .call(mc.id(), "create_meme")
        .args_json(json!({"duration_ms": "300000", "name": "Probe", "symbol": "PRB", "icon": "data:image/png;base64,AA==",
            "decimals": 18, "total_supply": "1000000000000000000000000000",
            "reference": "QmW1aCyxJKDHS2xAL5mTx38Z28pneWbWcPGUssea1z6Tcc",
            "reference_hash": "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=", "deposit_token_id": e.wrap.id(),
            "soft_cap": soft.to_string(), "hard_cap": (100 * NEAR).to_string(), "team_allocation": null}))
        .deposit(NearToken::from_millinear(500))
        .gas(Gas::from_tgas(250))
        .transact()
        .await?;
    assert_eq!(okr(r)?.json::<u64>()?, 0);
    Ok(M { e, mc, owner, rhea })
}

fn dexes() -> Vec<Value> {
    vec![json!({"id": MC, "kind": {"FactoryCurve": "MemeCooking"}})]
}

fn deposit_ops(a: u128) -> Value {
    json!([{"NearDeposit": {"amount": a.to_string()}},
        {"CurveBuy": {"venue": MC, "market": "0", "amount": a.to_string(), "min_out": "1", "gas": G.to_string()}}])
}

fn register_op() -> Value {
    json!({"CurveClaim": {"venue": MC, "action": "MemeCookingRegister", "amount": REG.to_string()}})
}

fn claim_op() -> Value {
    json!([{"CurveClaim": {"venue": MC, "action": "MemeCookingClaim", "market": "0"}}])
}

async fn staked(m: &M, t: &Ta) -> Result<u128> {
    let v: Value =
        m.e.worker.view(m.mc.id(), "get_account").args_json(json!({"account_id": t.id})).await?.json()?;
    Ok(v["deposits"]
        .as_array()
        .and_then(|d| d.iter().find(|x| x[0] == 0))
        .and_then(|x| x[1].as_str())
        .map_or(0, |s| s.parse().unwrap_or(0)))
}

/// Past the auction end (300 s; the sandbox advances ~0.3 s per block).
async fn past_end(m: &M) -> Result<()> {
    m.e.worker.fast_forward(1_200).await?;
    Ok(())
}

#[tokio::test]
async fn meme_deposit_withdraw_finalize_claim() -> Result<()> {
    let m = setup(2 * NEAR).await?;
    let e = &m.e;
    let t = e.ta("mta", 20 * NEAR, (10 * NEAR, 20 * NEAR), dexes()).await?;

    // 1. unregistered: the pad refunds the deposit (no fee, spend back)
    let f0 = e.near(e.fees.id()).await?;
    let r = e.exec(&t, deposit_ops(NEAR), "d0", 5 * NEAR).await?;
    let s = VEnv::settled(&r).expect("settled");
    assert_eq!(s["used"], "0", "{}", errs(&r));
    assert_eq!(e.near(e.fees.id()).await?, f0);
    assert_eq!(staked(&m, &t).await?, 0);

    // 2. register (our op, counted as spend) + deposit in one execute: fee exactly bps x amount
    let mut ops = deposit_ops(4 * NEAR);
    ops.as_array_mut().unwrap().insert(0, register_op());
    let spent0 = e.day_spent(&t).await?;
    let r = e.exec(&t, ops, "d1", 5 * NEAR).await?;
    let s = VEnv::settled(&r).expect("settled");
    assert_eq!(s["used"], (4 * NEAR).to_string(), "{}", errs(&r));
    assert_eq!(s["fee"], fee(4 * NEAR).to_string());
    assert!(e.day_spent(&t).await? >= spent0 + 4 * NEAR + fee(4 * NEAR) + REG);
    let st = 4 * NEAR - 4 * NEAR * DEPOSIT_FEE / 10_000;
    assert_eq!(staked(&m, &t).await?, st, "the pad keeps its 0.5% deposit fee");

    // 3. withdraw part (1 yocto): wNEAR back to self, minus meme.cooking's 2%; no platform fee
    let f1 = e.near(e.fees.id()).await?;
    let w0 = e.ft(e.wrap.id(), &t.id).await?;
    let wd = json!([{"CurveClaim": {"venue": MC, "action": "MemeCookingWithdraw", "market": "0", "amount": NEAR.to_string()}}]);
    ok(e.exec(&t, wd, "w1", NEAR).await?)?;
    assert_eq!(e.ft(e.wrap.id(), &t.id).await? - w0, NEAR - NEAR * WITHDRAW_FEE / 10_000);
    assert_eq!(e.near(e.fees.id()).await?, f1);
    assert_eq!(staked(&m, &t).await?, st - NEAR);

    // 4. claim before the end is refused by the pad (receipt fails, nothing moves)
    let r = e.exec(&t, claim_op(), "c0", NEAR).await?;
    assert!(!r.receipt_failures().is_empty());

    // 5. past the end, soft cap met: finalize (anyone) creates the token; the claim pays by
    // ft_transfer, so an unregistered account's claim fails at the token and stays claimable
    past_end(&m).await?;
    let fin = m
        .owner
        .call(m.mc.id(), "finalize")
        .args_json(json!({"meme_id": 0}))
        .gas(Gas::from_tgas(300))
        .transact()
        .await?;
    assert!(fin.logs().iter().any(|l| l.contains("\"create_token\"") && l.contains(TOKEN)), "{}", errs(&fin));
    let claimable = |m: &M, id: near_workspaces::AccountId| {
        let (w, mc) = (m.e.worker.clone(), m.mc.id().clone());
        async move {
            let v: Value = w
                .view(&mc, "get_claimable")
                .args_json(json!({"account_id": id, "meme_id": 0}))
                .await?
                .json()?;
            anyhow::Ok(v.as_str().unwrap_or("0").parse::<u128>()?)
        }
    };
    let owed = claimable(&m, t.id.clone()).await?;
    assert!(owed > 0);
    let token: near_workspaces::AccountId = TOKEN.parse()?;
    let r = e.exec(&t, claim_op(), "c1", NEAR).await?;
    assert!(!r.receipt_failures().is_empty(), "unregistered claim must fail at the token");
    assert_eq!(claimable(&m, t.id.clone()).await?, owed, "a failed claim stays claimable");

    // 6. StorageDeposit on the token (a storage target through the claim's `token`) + claim, one
    // execute: the tokens arrive, nothing stays claimable, no platform fee
    let f2 = e.near(e.fees.id()).await?;
    let ops = json!([{"StorageDeposit": {"token": TOKEN, "amount": STORAGE.to_string()}},
        {"CurveClaim": {"venue": MC, "action": "MemeCookingClaim", "market": "0", "token": TOKEN}}]);
    ok(e.exec(&t, ops, "c2", NEAR).await?)?;
    assert_eq!(e.ft(&token, &t.id).await?, owed);
    assert_eq!(claimable(&m, t.id.clone()).await?, 0);
    assert_eq!(e.near(e.fees.id()).await?, f2);
    // a StorageDeposit on the token without the claim naming it is refused (not a target)
    let r = e
        .exec(&t, json!([{"StorageDeposit": {"token": TOKEN, "amount": STORAGE.to_string()}}]), "c3", NEAR)
        .await?;
    fails_with(&r, "E_STORAGE_TARGET");
    let _ = &m.rhea;
    Ok(())
}

/// Soft cap missed: finalize closes the auction without a token; `claim` (1 yocto) refunds the
/// whole stake in wNEAR; no platform fee on the refund.
#[tokio::test]
async fn meme_failed_auction_refund() -> Result<()> {
    let m = setup(50 * NEAR).await?;
    let e = &m.e;
    let t = e.ta("mta", 20 * NEAR, (10 * NEAR, 20 * NEAR), dexes()).await?;
    let mut ops = deposit_ops(2 * NEAR);
    ops.as_array_mut().unwrap().insert(0, register_op());
    ok(e.exec(&t, ops, "d1", 5 * NEAR).await?)?;
    let st = staked(&m, &t).await?;
    assert_eq!(st, 2 * NEAR - 2 * NEAR * DEPOSIT_FEE / 10_000);
    past_end(&m).await?;
    let fin = m
        .owner
        .call(m.mc.id(), "finalize")
        .args_json(json!({"meme_id": 0}))
        .gas(Gas::from_tgas(300))
        .transact()
        .await?;
    assert!(fin.logs().iter().all(|l| !l.contains("create_token")), "no token for a failed auction");
    let (w0, f0) = (e.ft(e.wrap.id(), &t.id).await?, e.near(e.fees.id()).await?);
    ok(e.exec(&t, claim_op(), "c1", NEAR).await?)?;
    assert_eq!(e.ft(e.wrap.id(), &t.id).await? - w0, st, "the full stake comes back");
    assert_eq!(staked(&m, &t).await?, 0);
    assert_eq!(e.near(e.fees.id()).await?, f0);
    Ok(())
}

/// Never an order; typed and raw negatives on the real account.
#[tokio::test]
async fn meme_never_an_order_and_negatives() -> Result<()> {
    let m = setup(2 * NEAR).await?;
    let e = &m.e;
    let t = e.ta("mta", 20 * NEAR, (10 * NEAR, 20 * NEAR), dexes()).await?;
    // place_order naming meme-cooking.near: refused (a presale deposit has no price)
    let exp = e.worker.view_block().await?.timestamp() + 86_400 * 1_000_000_000;
    let r = t
        .device
        .call(&t.id, "place_order")
        .args_json(
            json!({"token_in": e.wrap.id(), "token_out": "0.meme-cooking.near", "amount_in": NEAR.to_string(),
            "min_out": "1", "trigger_meta": "", "expires_at_ns": exp.to_string(), "dexes": [MC]}),
        )
        .transact()
        .await?;
    fails_with(&r, "E_BAD_DEX");
    // typed: min_out 0, sell, register over the cap / missing amount
    let op = |min: &str| json!([{"CurveBuy": {"venue": MC, "market": "0", "amount": NEAR.to_string(), "min_out": min, "gas": G.to_string()}}]);
    fails_with(&e.exec(&t, op("0"), "n1", 2 * NEAR).await?, "E_BAD_OP");
    let sell = json!([{"CurveSell": {"venue": MC, "market": "0", "amount": NEAR.to_string(), "min_out": "1", "gas": G.to_string()}}]);
    fails_with(&e.exec(&t, sell, "n2", 2 * NEAR).await?, "E_BAD_OP");
    let reg = |a: u128| json!([{"CurveClaim": {"venue": MC, "action": "MemeCookingRegister", "amount": a.to_string()}}]);
    fails_with(&e.exec(&t, reg(50 * NEAR / 1000 + 1), "n3", NEAR).await?, "E_BAD_OP");
    fails_with(
        &e.exec(&t, json!([{"CurveClaim": {"venue": MC, "action": "MemeCookingRegister"}}]), "n4", NEAR)
            .await?,
        "E_BAD_OP",
    );
    // raw FtTransferCall Deposit: unknown field, foreign referrer, a non-wNEAR token
    let raw = |token: &str, msg: Value| {
        json!([{"FtTransferCall": {"token": token, "receiver_id": MC, "amount": NEAR.to_string(),
        "msg": msg.to_string(), "gas": G.to_string()}}])
    };
    ok(e.exec(&t, reg(REG), "r0", NEAR).await?)?;
    e.wrap_for(&t, 3 * NEAR).await?;
    fails_with(
        &e.exec(
            &t,
            raw(e.wrap.id().as_str(), json!({"Deposit": {"meme_id": 0, "recipient": "x.near"}})),
            "n5",
            2 * NEAR,
        )
        .await?,
        "E_BAD_MSG",
    );
    fails_with(
        &e.exec(
            &t,
            raw(e.wrap.id().as_str(), json!({"Deposit": {"meme_id": 0, "referrer": "mhga.near"}})),
            "n6",
            2 * NEAR,
        )
        .await?,
        "E_REFERRER",
    );
    fails_with(
        &e.exec(&t, raw("usdc.near", json!({"Deposit": {"meme_id": 0}})), "n7", 2 * NEAR).await?,
        "E_BAD_MSG",
    );
    // the raw Deposit (no referrer) works like the typed op: fee exactly bps x amount
    let f0 = e.near(e.fees.id()).await?;
    let r = e.exec(&t, raw(e.wrap.id().as_str(), json!({"Deposit": {"meme_id": 0}})), "d1", 2 * NEAR).await?;
    let s = VEnv::settled(&r).expect("settled");
    assert_eq!(s["used"], NEAR.to_string(), "{}", errs(&r));
    assert_eq!(e.near(e.fees.id()).await? - f0, fee(NEAR));
    assert_eq!(staked(&m, &t).await?, NEAR - NEAR * DEPOSIT_FEE / 10_000);
    Ok(())
}
