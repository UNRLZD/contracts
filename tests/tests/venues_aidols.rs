//! v1.6 Aidols-codebase curves (aidols.near, gra-fun.near, gaypad.j1-racing.near,
//! v1/v2.whole-market.near, patata-monster.near) through the trading account, with the REAL mainnet
//! factory + token wasm AND their mainnet state (imported with `import_mainnet`: view_state of the
//! factory and one of its tokens; code pinned by hash). The sandbox wrap.near is fresh, so the
//! factory's wNEAR (its sell liquidity) is re-created with `fund_wnear`.
mod venues_common;
use anyhow::Result;
use integration_tests::*;
use near_workspaces::types::NearToken;
use serde_json::{json, Value};
use venues_common::*;

const G: u64 = 150 * TGAS;
/// `thash` marker: the factory is replayed from its mainnet init instead of imported.
const REPLAY: &str = "replay";
/// The Rhea classic pool gra-fun reads for its NEAR/USD price (`get_pool{pool_id: 5470}`, mainnet
/// launch tx 2TVdMbPvzJqzJ1tZj2397Kt5yC5QvKhDW9r6kwCKD6Qq).
const GRAFUN_PRICE_POOL: u64 = 5470;

/// The real v2.ref-finance.near with a wNEAR/USDT simple pool at id GRAFUN_PRICE_POOL: pool 0 is
/// created through the contract, then its storage record is copied to index 5470 (Vector key =
/// b"\0" + u64 LE index) with reserves set, and the pools Vector length (in STATE) raised to 5471.
/// Only `get_pool` reads it (gra-fun's price view); nothing swaps against it.
async fn rhea_with_price_pool(e: &VEnv) -> Result<()> {
    let rhea = install_mainnet(&e.worker, "v2.ref-finance.near").await?;
    let ro = sub(&e.root, "rheaowner", 50 * NEAR).await?;
    ok(rhea
        .call("new")
        .args_json(json!({"owner_id": ro.id(), "boost_farm_id": ro.id(), "burrowland_id": ro.id(),
            "exchange_fee": 4, "referral_fee": 1}))
        .transact()
        .await?)?;
    let usdt = install_code(&e.worker, "usdt.tether-token.near", &out("mock_ft")).await?;
    ok(usdt.call("new").args_json(json!({})).transact().await?)?;
    ok(ro
        .call(rhea.id(), "add_simple_pool")
        .args_json(json!({"tokens": [e.wrap.id(), usdt.id()], "fee": 30}))
        .deposit(NearToken::from_millinear(100))
        .transact()
        .await?)?;
    let st = e.worker.view_state(rhea.id()).await?;
    let key0: Vec<u8> = [&[0u8][..], &0u64.to_le_bytes()].concat();
    let mut pool = st.get(&key0).cloned().ok_or_else(|| anyhow::anyhow!("pool 0 record"))?;
    // SimplePool: tag, Vec<AccountId> (2), then amounts Vec<u128> (2): 1M NEAR / 1.3M USDT (6 dp)
    let ids_end = 1 + 4 + (4 + 9) + (4 + 22);
    assert_eq!(&pool[ids_end..ids_end + 4], &2u32.to_le_bytes());
    pool[ids_end + 4..ids_end + 20].copy_from_slice(&(1_000_000 * NEAR).to_le_bytes());
    pool[ids_end + 20..ids_end + 36].copy_from_slice(&1_300_000_000_000u128.to_le_bytes());
    let mut state = st.get(b"STATE".as_slice()).cloned().ok_or_else(|| anyhow::anyhow!("STATE"))?;
    // Vector { len: 1u64, prefix: vec![0] }
    let pat: Vec<u8> = [&1u64.to_le_bytes()[..], &1u32.to_le_bytes(), &[0u8]].concat();
    let at = state
        .windows(pat.len())
        .position(|w| w == pat.as_slice())
        .ok_or_else(|| anyhow::anyhow!("pools Vector"))?;
    state[at..at + 8].copy_from_slice(&(GRAFUN_PRICE_POOL + 1).to_le_bytes());
    let key: Vec<u8> = [&[0u8][..], &GRAFUN_PRICE_POOL.to_le_bytes()].concat();
    e.worker.patch(rhea.id()).state(&key, &pool).state(b"STATE", &state).transact().await?;
    let v: Value = e
        .worker
        .view(rhea.id(), "get_pool")
        .args_json(json!({"pool_id": GRAFUN_PRICE_POOL}))
        .await?
        .json()?;
    assert_eq!(v["amounts"][1], "1300000000000", "{v}");
    Ok(())
}
/// 0.5 NEARDOG (24 decimals), the fixture's buy size.
const NEARDOG_HALF: u128 = 5 * 10u128.pow(23);

async fn emulate(e: &VEnv, f: &str, input: &str, output: &str, amount: u128) -> Result<u128> {
    let v: Value = e
        .worker
        .view(&f.parse()?, "emulate_swap")
        .args_json(json!({"input_token": input, "output_token": output, "amount": amount.to_string()}))
        .await?
        .json()?;
    Ok(v[0].as_str().unwrap().parse()?)
}

async fn create(e: &VEnv, id: &str) -> Result<()> {
    let aid: near_workspaces::AccountId = id.parse()?;
    e.worker
        .patch(&aid)
        .account(near_workspaces::types::AccountDetailsPatch::default().balance(NearToken::from_near(1)))
        .transact()
        .await?;
    Ok(())
}

async fn register(e: &VEnv, token: &near_workspaces::AccountId, who: &str) -> Result<()> {
    ok(e.root
        .call(token, "storage_deposit")
        .args_json(json!({"account_id": who, "registration_only": true}))
        .deposit(NearToken::from_millinear(13))
        .transact()
        .await?)
}

/// The panic messages of a result's failed receipts.
pub fn errs(r: &near_workspaces::result::ExecutionFinalResult) -> String {
    let s = format!("{:?}", r.clone().into_result().err());
    let f = format!("{:?}", r.receipt_failures());
    let mut out = vec![];
    for src in [s, f] {
        for part in src.split("ExecutionError(").skip(1) {
            out.push(part.chars().take(220).collect::<String>());
        }
        for part in src.split("kind: ").skip(1) {
            if !part.starts_with("FunctionCallError") {
                out.push(part.chars().take(160).collect::<String>());
            }
        }
    }
    out.join(" | ")
}

pub enum QSrc {
    /// wNEAR (sandbox wrap)
    Wrap,
    /// the real Q token, code pinned + mainnet state imported; the TA is funded by the factory
    Import(&'static str, Option<&'static str>),
    /// Q's mainnet state is too large to import: a standard NEP-141 stand-in (mock_ft) at Q's id
    Mock(&'static str),
}

/// Happy buy + sell, unregistered buy, slippage refunds, raw FtTransferCall, negatives and fee
/// exactness on one Aidols-codebase factory.
#[allow(clippy::too_many_arguments)]
async fn pad_case(
    f: &str,
    fhash: &str,
    pad: &str,
    token: &str,
    thash: Option<&str>,
    q: QSrc,
    payees: &[&str],
    q_amount: u128,
) -> Result<String> {
    let e = venv().await?;
    let (fac, tid) = if thash == Some(REPLAY) {
        replay_grafun(&e, fhash, token).await?
    } else {
        let fac = import_mainnet(&e.worker, f, Some(fhash)).await?;
        let tok = import_mainnet(&e.worker, token, thash).await?;
        (fac, tok.id().clone())
    };
    let mut log = String::new();
    // the quote token and who holds it
    let (qid, qstr): (near_workspaces::AccountId, Option<String>) = match q {
        QSrc::Wrap => {
            fund_wnear(&e, &fac, 1_000 * NEAR).await?;
            for p in payees {
                create(&e, p).await?;
                register(&e, e.wrap.id(), p).await?;
            }
            (e.wrap.id().clone(), None)
        }
        QSrc::Import(id, h) => {
            let c = import_mainnet(&e.worker, id, h).await?;
            (c.id().clone(), Some(id.to_string()))
        }
        QSrc::Mock(id) => {
            let c = install_code(&e.worker, id, &out("mock_ft")).await?;
            ok(c.call("new").args_json(json!({})).transact().await?)?;
            ok(c.call("mint")
                .args_json(json!({"account_id": f, "amount": (10u128.pow(36)).to_string()}))
                .transact()
                .await?)?;
            for p in payees {
                create(&e, p).await?;
                ok(c.call("mint").args_json(json!({"account_id": p, "amount": "1"})).transact().await?)?;
            }
            (c.id().clone(), Some(id.to_string()))
        }
    };
    let qs = qstr.as_deref();
    let kind = json!({"id": f, "kind": {"AidolsCurve": pad}});
    let t = e.ta("u", 20 * NEAR, (10 * NEAR, 50 * NEAR), vec![kind]).await?;
    // Q for the TA: wNEAR by wrapping, else a transfer from the factory's own (imported) Q balance
    let fac_q = e.ft(&qid, fac.id()).await?;
    let a = if qs.is_none() { NEAR / 2 } else { q_amount.min(fac_q / 10) };
    if qs.is_none() {
        e.wrap_for(&t, 3 * NEAR).await?;
    } else {
        register(&e, &qid, t.id.as_str()).await?;
        ok(fac
            .as_account()
            .call(&qid, "ft_transfer")
            .args_json(json!({"receiver_id": t.id, "amount": (4 * a).to_string()}))
            .deposit(NearToken::from_yoctonear(1))
            .transact()
            .await?)?;
    }
    let qin = qid.to_string();
    let buy = |amount: u128, min: u128| {
        json!({"CurveBuy": {"venue": f, "market": token, "quote": qs, "amount": amount.to_string(),
        "min_out": min.to_string(), "gas": G.to_string()}})
    };
    let sell = |amount: u128, min: u128| {
        json!({"CurveSell": {"venue": f, "market": token, "quote": qs, "amount": amount.to_string(),
        "min_out": min.to_string(), "gas": G.to_string()}})
    };
    let fee_q = |x: u128| if qs.is_none() { fee_of(x) } else { 0 };
    // max_in: the NEAR spend bound (Q buys spend only the venue-planned registration)
    let max_in = if qs.is_none() { a + NEAR } else { NEAR };
    let q = emulate(&e, f, &qin, token, a).await?;
    let fees0 = e.near(e.fees.id()).await?;
    let w0 = e.ft(&qid, &t.id).await?;

    // unregistered TA on the token (no StorageDeposit): measured, the input must not be lost
    let r = e.exec(&t, json!([buy(a / 10, 1)]), "unreg", max_in).await?;
    let (w_u, t_u) = (e.ft(&qid, &t.id).await?, e.ft(&tid, &t.id).await?);
    log += &format!(
        "unregistered buy: ok={} q_delta={} tokens={} settled={:?} failures={} {}\n",
        r.is_success(),
        w0 as i128 - w_u as i128,
        t_u,
        VEnv::settled(&r),
        r.receipt_failures().len(),
        errs(&r)
    );
    let w0 = w_u;
    let fees0b = e.near(e.fees.id()).await?;
    let _ = fees0;

    // slippage: min_out above the quote -> refund, no fee, spend back
    let r = e.exec(&t, json!([buy(a, q * 2)]), "slip", max_in).await?;
    log += &format!("slippage buy: ok={} settled={:?}\n", r.is_success(), VEnv::settled(&r));
    if VEnv::settled(&r).is_none() {
        println!("{log}\nslippage tx: {}", errs(&r));
    }
    assert_eq!(e.ft(&qid, &t.id).await?, w0, "Q refunded");
    assert_eq!(e.near(e.fees.id()).await?, fees0b, "no fee");
    assert_eq!(VEnv::settled(&r).unwrap()["used"], "0");

    // happy buy with StorageDeposit first
    let q = emulate(&e, f, &qin, token, a).await?;
    let before = e.ft(&tid, &t.id).await?;
    let ops = json!([{"StorageDeposit": {"token": token, "amount": "1250000000000000000000"}}, buy(a, q * 99 / 100)]);
    let r = e.exec(&t, ops, "buy1", max_in).await?;
    let got = e.ft(&tid, &t.id).await? - before;
    log += &format!(
        "buy: ok={} out={} quote={} settled={:?} gas_total={:.1}T\n",
        r.is_success(),
        got,
        q,
        VEnv::settled(&r),
        r.total_gas_burnt.as_gas() as f64 / 1e12
    );
    assert!(r.is_success() && got >= q * 99 / 100, "buy delivered: {got}\n{log}\n{}", errs(&r));
    assert_eq!(e.near(e.fees.id()).await? - fees0b, fee_q(a), "fee = 1% of the NEAR input, 0 for Q");
    assert_eq!(e.ft(&qid, &t.id).await?, w0 - a);

    // sell half: slippage first, then happy
    let s = got / 2;
    let qo = emulate(&e, f, token, &qin, s).await?;
    let fees1 = e.near(e.fees.id()).await?;
    let r = e.exec(&t, json!([sell(s, qo * 2)]), "sslip", NEAR).await?;
    log += &format!("slippage sell: ok={} settled={:?}\n", r.is_success(), VEnv::settled(&r));
    assert_eq!(e.ft(&tid, &t.id).await?, before + got, "tokens back");
    assert_eq!(e.near(e.fees.id()).await?, fees1);
    let w1 = e.ft(&qid, &t.id).await?;
    let r = e.exec(&t, json!([sell(s, qo * 99 / 100)]), "sell1", NEAR).await?;
    let w2 = e.ft(&qid, &t.id).await?;
    log += &format!(
        "sell: ok={} q_in={} quote={} settled={:?} gas_total={:.1}T\n",
        r.is_success(),
        w2 - w1,
        qo,
        VEnv::settled(&r),
        r.total_gas_burnt.as_gas() as f64 / 1e12
    );
    assert!(r.is_success() && w2 - w1 >= qo * 99 / 100);
    // sells to wNEAR: fee = bps x min_out (today's FtTransferCall-sell rule); Q: none
    assert_eq!(e.near(e.fees.id()).await? - fees1, fee_q(qo * 99 / 100));

    // the same trade as a raw FtTransferCall (msg_venues parser)
    let m = json!({"token": null, "min_swap_amount": "1"}).to_string();
    let raw = json!([{"FtTransferCall": {"token": token, "receiver_id": f, "amount": (s / 4).to_string(), "msg": m, "gas": G.to_string()}}]);
    let r = e.exec(&t, raw, "raw1", NEAR).await?;
    log += &format!("raw FtTransferCall sell: ok={}\n", r.is_success());
    assert!(r.is_success());
    let m = json!({"token": token, "min_swap_amount": "1"}).to_string();
    let raw = json!([{"FtTransferCall": {"token": qin, "receiver_id": f, "amount": (a / 10).to_string(), "msg": m, "gas": G.to_string()}}]);
    let r = e.exec(&t, raw, "raw2", max_in).await?;
    log += &format!("raw FtTransferCall buy: ok={}\n", r.is_success());
    assert!(r.is_success());

    // negatives
    let bad = |m: &str| json!([{"FtTransferCall": {"token": token, "receiver_id": f, "amount": "1000", "msg": m, "gas": G.to_string()}}]);
    fails_with(
        &e.exec(
            &t,
            bad(&json!({"token": null, "min_swap_amount": "1", "referral": "x.near"}).to_string()),
            "n1",
            NEAR,
        )
        .await?,
        "E_BAD_MSG",
    );
    fails_with(
        &e.exec(
            &t,
            bad(&json!({"token": null, "min_swap_amount": "1", "refferal": "x.near"}).to_string()),
            "n1b",
            NEAR,
        )
        .await?,
        "E_BAD_MSG",
    );
    fails_with(
        &e.exec(
            &t,
            bad(&json!({"token": null, "min_swap_amount": "1", "receiver_id": "x.near"}).to_string()),
            "n2",
            NEAR,
        )
        .await?,
        "E_BAD_MSG",
    );
    fails_with(
        &e.exec(&t, bad(&json!({"token": null, "min_swap_amount": "0"}).to_string()), "n3", NEAR).await?,
        "E_MIN_OUT",
    );
    // a buy paid in a token that is not the factory's quote
    let wrongq = if qs.is_none() { "usdc.near" } else { e.wrap.id().as_str() };
    let m = json!({"token": token, "min_swap_amount": "1"}).to_string();
    fails_with(&e.exec(&t, json!([{"FtTransferCall": {"token": wrongq, "receiver_id": f, "amount": "1000", "msg": m, "gas": G.to_string()}}]), "n3b", NEAR).await?, "E_BAD_MSG");
    fails_with(&e.exec(&t, json!([buy(a, 0)]), "n4", NEAR).await?, "E_BAD_OP");
    let other = json!([{"CurveBuy": {"venue": "other-pad.near", "market": token, "quote": qs, "amount": "1000", "min_out": "1", "gas": G.to_string()}}]);
    fails_with(&e.exec(&t, other, "n5", NEAR).await?, "E_BAD_DEX");
    let notunder = json!([{"CurveBuy": {"venue": f, "market": "x.other.near", "quote": qs, "amount": "1000", "min_out": "1", "gas": G.to_string()}}]);
    fails_with(&e.exec(&t, notunder, "n6", NEAR).await?, "E_CURVE_MARKET");
    let wrongquote = json!([{"CurveSell": {"venue": f, "market": token, "quote": wrongq, "amount": "1000", "min_out": "1", "gas": G.to_string()}}]);
    fails_with(&e.exec(&t, wrongquote, "n7", NEAR).await?, "E_CURVE_QUOTE");
    Ok(log)
}

#[tokio::test]
async fn venues_aidols_near() -> Result<()> {
    let log = pad_case(
        "aidols.near",
        "Csh7LRonCe1f7ndcizg8a3RqY2Huour6yHDeBcmHm43",
        "Near",
        "aidol100.aidols.near",
        Some("6RAJutV3eS21LHnrXaVN27hwn1K8ZJko59MUxEgLrpSp"),
        QSrc::Wrap,
        &["aidols-treasury.near", "wallet.intear.near"],
        0,
    )
    .await?;
    println!("{log}");
    Ok(())
}

#[tokio::test]
async fn venues_aidols_patata() -> Result<()> {
    let log = pad_case(
        "patata-monster.near",
        "HKXkvQaFLw9F3d44c29w8WJAjbcGcr6iuSbXFsV16v9S",
        "Patata",
        "poop.patata-monster.near",
        None,
        QSrc::Import("patata.gaypad.j1-racing.near", None),
        &[],
        500 * 10u128.pow(24),
    )
    .await?;
    println!("{log}");
    Ok(())
}

#[tokio::test]
async fn venues_aidols_gaypad_jambo() -> Result<()> {
    let log = pad_case(
        "gaypad.j1-racing.near",
        "EqPfurdRxqtXv6wWkGcrqjeBehba5o6f51yz5VbADtdh",
        "Jambo",
        "jhoot.gaypad.j1-racing.near",
        None,
        QSrc::Mock("jambo-1679.meme-cooking.near"),
        &["treasury.j1-racing.near", "mhga.near"],
        10_000 * 10u128.pow(18),
    )
    .await?;
    println!("{log}");
    Ok(())
}

#[tokio::test]
async fn venues_aidols_wholemarket_v2() -> Result<()> {
    let log = pad_case(
        "v2.whole-market.near",
        "4WdSFh6pUsfnnjNhkyY74C2g1KntkdhDifoZumNSDwd8",
        "Neardog",
        "test.v2.whole-market.near",
        None,
        // NEARDOG holders' balances are not importable usefully (the factory holds 0.55): stand-in
        QSrc::Mock("neardog.tkn.near"),
        &["whole-market.near", "tre.whole-market.near"],
        NEARDOG_HALF,
    )
    .await?;
    println!("{log}");
    Ok(())
}

#[tokio::test]
async fn venues_aidols_wholemarket_v1() -> Result<()> {
    let log = pad_case(
        "v1.whole-market.near",
        "JBrFUe5CjAjCY9Y9NrZwqKK1qEyVQhBVah7EuW2jRuNX",
        "Neardog",
        "test.v1.whole-market.near",
        None,
        // NEARDOG holders' balances are not importable usefully (the factory holds 0.55): stand-in
        QSrc::Mock("neardog.tkn.near"),
        &["whole-market.near", "tre.whole-market.near"],
        NEARDOG_HALF / 10, // v1 refuses 0.5 ("Buy amount is not allowed": a per-buy cap)
    )
    .await?;
    println!("{log}");
    Ok(())
}

/// gra-fun.near stood up in the sandbox: its real code (pinned), `new` + a launch replayed.
async fn replay_grafun(
    e: &VEnv,
    fhash: &str,
    token: &str,
) -> Result<(near_workspaces::Contract, near_workspaces::AccountId)> {
    let f = "gra-fun.near";
    // gra-fun.near: state TOO_LARGE to import -> replay its mainnet init (gra-fun.near's own
    // txs: new{treasury_id} + wrap registration) and a launch_new_token (2.6 N, as on mainnet)
    let code = pinned(f, Some(fhash)).await?;
    let fac = install_code(&e.worker, f, &code).await?;
    rhea_with_price_pool(e).await?;
    ok(fac.call("new").args_json(json!({"treasury_id": "grafuntreasury.near"})).transact().await?)?;
    ok(fac
        .as_account()
        .call(e.wrap.id(), "storage_deposit")
        .args_json(json!({"account_id": fac.id()}))
        .deposit(NearToken::from_micronear(1_250))
        .transact()
        .await?)?;
    let creator = sub(&e.root, "creator", 20 * NEAR).await?;
    let label = token.split('.').next().unwrap_or("x");
    let r = creator
        .call(fac.id(), "launch_new_token")
        .args_json(json!({"account_name": label, "name": "Sandbox", "symbol": "SBX",
            "icon": "bafybeiazphehp4nch5z4imo57v4uztzsvld3sks7a3ttwuqwwljlyiwisy.jpg", "refferal": null,
            "tokensale_metadata": "bafybeig55gdp42ctgb7x7jmrhauefhfa5vvmf6veoqjdm2kmfegdkfy2om"}))
        .deposit(NearToken::from_millinear(2_600))
        .gas(near_workspaces::types::Gas::from_tgas(300))
        .transact()
        .await?;
    println!("gra-fun launch_new_token: ok={} {}", r.is_success(), errs(&r));
    let _ = okr(r)?;
    Ok((fac, token.parse::<near_workspaces::AccountId>()?))
}

/// gra-fun.near (Aidols codebase, wNEAR, flat 0.1 N commission to grafuntreasury.near taken
/// inside the pad): factory replayed (state too large), its price pool stood up on the real Rhea.
#[tokio::test]
async fn venues_aidols_grafun() -> Result<()> {
    let log = pad_case(
        "gra-fun.near",
        "G8Le84yFiM8hgUfMJ2cYmfTJ4GRjpVCX514nA2xmRspm",
        "Near",
        "sbx.gra-fun.near",
        Some(REPLAY),
        QSrc::Wrap,
        &["grafuntreasury.near"],
        0,
    )
    .await?;
    println!("{log}");
    Ok(())
}

/// gra-fun specifics: an account never registered on the token buys with no StorageDeposit op (the
/// venue-planned registration lands first), the pad's flat 0.1 wNEAR commission goes to
/// grafuntreasury.near inside a buy and on top of a sell, and our 1% is exact on each leg.
#[tokio::test]
async fn venues_grafun_fees_and_registration() -> Result<()> {
    let e = venv().await?;
    let (_fac, tid) =
        replay_grafun(&e, "G8Le84yFiM8hgUfMJ2cYmfTJ4GRjpVCX514nA2xmRspm", "sbx.gra-fun.near").await?;
    create(&e, "grafuntreasury.near").await?;
    register(&e, e.wrap.id(), "grafuntreasury.near").await?;
    let tre: near_workspaces::AccountId = "grafuntreasury.near".parse()?;
    let t = e
        .ta(
            "u",
            20 * NEAR,
            (10 * NEAR, 50 * NEAR),
            vec![json!({"id": "gra-fun.near", "kind": {"AidolsCurve": "Near"}})],
        )
        .await?;
    e.wrap_for(&t, 3 * NEAR).await?;
    let (f, token, wrap) = ("gra-fun.near", "sbx.gra-fun.near", e.wrap.id().to_string());
    let a = NEAR;
    let q = emulate(&e, f, &wrap, token, a).await?;
    let (fees0, tre0) = (e.near(e.fees.id()).await?, e.ft(e.wrap.id(), &tre).await?);
    let buy = json!([{"CurveBuy": {"venue": f, "market": token, "amount": a.to_string(), "min_out": (q * 99 / 100).to_string(), "gas": G.to_string()}}]);
    let r = e.exec(&t, buy, "gb", a + NEAR).await?;
    let got = e.ft(&tid, &t.id).await?;
    let tre_b = e.ft(e.wrap.id(), &tre).await? - tre0;
    println!(
        "gra-fun unregistered buy 1 N: ok={} out={got} quote={q} treasury={tre_b} fee={} {}",
        r.is_success(),
        e.near(e.fees.id()).await? - fees0,
        errs(&r)
    );
    assert!(got >= q * 99 / 100, "delivered to a never-registered account");
    assert_eq!(tre_b, NEAR / 10, "flat 0.1 wNEAR commission inside the buy");
    assert_eq!(e.near(e.fees.id()).await? - fees0, fee_of(a), "our fee: 1% of the whole input");
    // sell half: 0.1 wNEAR on top to the treasury; our fee = 1% x the op's min_out
    let s_ = got / 2;
    let qs = emulate(&e, f, token, &wrap, s_).await?;
    let (fees1, tre1, w1) =
        (e.near(e.fees.id()).await?, e.ft(e.wrap.id(), &tre).await?, e.ft(e.wrap.id(), &t.id).await?);
    let min = qs * 99 / 100;
    let sell = json!([{"CurveSell": {"venue": f, "market": token, "amount": s_.to_string(), "min_out": min.to_string(), "gas": G.to_string()}}]);
    let r = e.exec(&t, sell, "gs", NEAR).await?;
    let tre_s = e.ft(e.wrap.id(), &tre).await? - tre1;
    let w_in = e.ft(e.wrap.id(), &t.id).await? - w1;
    println!(
        "gra-fun sell: ok={} wnear_in={w_in} quote={qs} treasury={tre_s} fee={} {}",
        r.is_success(),
        e.near(e.fees.id()).await? - fees1,
        errs(&r)
    );
    assert!(w_in >= min);
    assert_eq!(tre_s, NEAR / 10, "flat 0.1 wNEAR commission on the sell");
    assert_eq!(e.near(e.fees.id()).await? - fees1, fee_of(min));
    // the pad's own `refferal` key (its spelling) is never accepted in a raw msg
    let m = json!({"token": null, "min_swap_amount": "1", "refferal": "x.near"}).to_string();
    let raw = json!([{"FtTransferCall": {"token": token, "receiver_id": f, "amount": "1000", "msg": m, "gas": G.to_string()}}]);
    fails_with(&e.exec(&t, raw, "gr", NEAR).await?, "E_BAD_MSG");
    Ok(())
}
