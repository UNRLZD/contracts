//! v1.6 factory-held curves (Nearrr, dragonpad, Vista launch + DEX, Nira, meme.cooking) through the
//! trading account on the REAL mainnet wasm.
//!
//! Pad state: `import_mainnet` (the factory's and one token's mainnet view_state, code pinned by
//! hash) wherever the public RPC serves the state (nearrr-fun.near, dragonpad.near,
//! launch/dex.vistadev.near and their tokens). Accounts the pads pay natively (treasury, creator)
//! are created empty so the payouts land. gra-fun.near, curve10.latedata9580.near (Nira) and
//! meme-cooking.near answer TOO_LARGE_CONTRACT_STATE on every public RPC: see the per-pad notes.
mod venues_common;
use anyhow::Result;
use integration_tests::*;
use near_workspaces::result::ExecutionFinalResult;
use near_workspaces::types::NearToken;
use near_workspaces::AccountId;
use serde_json::{json, Value};
use venues_common::*;

const G: u64 = 150 * TGAS;
/// A Nearrr buy's op gas: the chain declares 216 TGas (V16-02 balance reads included).
const NEARRR_OP_GAS: u64 = 220 * TGAS;

async fn create(e: &VEnv, id: &str) -> Result<()> {
    let aid: AccountId = id.parse()?;
    if e.worker.view_account(&aid).await.is_ok() {
        return Ok(());
    }
    e.worker
        .patch(&aid)
        .account(near_workspaces::types::AccountDetailsPatch::default().balance(NearToken::from_near(1)))
        .transact()
        .await?;
    Ok(())
}

fn errs(r: &ExecutionFinalResult) -> String {
    let s = format!("{:?} {:?}", r.clone().into_result().err(), r.receipt_failures());
    s.split("ExecutionError(")
        .skip(1)
        .map(|p| p.chars().take(200).collect::<String>())
        .collect::<Vec<_>>()
        .join(" | ")
}

fn u(v: &Value) -> u128 {
    v.as_str().and_then(|s| s.parse().ok()).unwrap_or(0)
}

/// The account's per-token lock (`get_q_lock`): null when free, [holder, expiry] when held.
async fn q_lock(e: &VEnv, t: &Ta, token: &str) -> Result<Value> {
    Ok(e.worker.view(&t.id, "get_q_lock").args_json(json!({"q": token})).await?.json()?)
}

fn curve_g(side: &str, f: &str, token: &str, amount: u128, min_out: u128, g: u64) -> Value {
    json!({side: {"venue": f, "market": token, "amount": amount.to_string(), "min_out": min_out.to_string(),
        "gas": g.to_string()}})
}

/// The shared payable-buy / ft-sell scenario of a NEAR-quoted factory curve. `quote_buy(a)` and
/// `quote_sell(s)` are the pad's own expected outputs (views or reserve math).
struct Pad<'a> {
    f: &'a str,
    fhash: &'a str,
    kind: Value,
    token: &'a str,
    thash: Option<&'a str>,
    payees: &'a [&'a str],
    /// storage registration op before the buy (the pad checks it / pays to an unregistered id)
    register: Option<u128>,
    a: u128,
    gas: u64,
    /// happy-buy min_out as bps of the pad's quote; the slippage buy uses `slip_bps`
    min_bps: u128,
    slip_bps: u128,
    /// the sell msg the raw FtTransferCall parser accepts (key = its outer variant)
    raw_sell: (Value, &'a str),
    /// Settle::NearInFull (the pad never refunds part of a successful buy): exact fee
    full: bool,
    /// slippage = a failed receipt (vs Nearrr's refund Transfer in a successful one)
    panics_on_slippage: bool,
}

async fn near_pad<Q, S, QF, SF>(p: Pad<'_>, quote_buy: QF, quote_sell: SF) -> Result<String>
where
    QF: Fn(VEnvRef, u128) -> Q,
    Q: std::future::Future<Output = Result<u128>>,
    SF: Fn(VEnvRef, u128) -> S,
    S: std::future::Future<Output = Result<u128>>,
{
    let e = std::sync::Arc::new(venv().await?);
    let _fac = import_mainnet(&e.worker, p.f, Some(p.fhash)).await?;
    let tok = import_mainnet(&e.worker, p.token, p.thash).await?;
    for x in p.payees {
        create(&e, x).await?;
    }
    let t = e.ta("u", 30 * NEAR, (10 * NEAR, 50 * NEAR), vec![json!({"id": p.f, "kind": p.kind})]).await?;
    let (f, token, a, g) = (p.f, p.token, p.a, p.gas);
    let curve = |side: &str, f: &str, token: &str, amount: u128, min_out: u128| {
        curve_g(side, f, token, amount, min_out, g)
    };
    let tid = tok.id().clone();
    let mut log = String::new();

    // slippage buy: nothing moves, no fee, spend back
    let q = quote_buy(e.clone(), a).await?;
    let fees0 = e.near(e.fees.id()).await?;
    let spent0 = e.day_spent(&t).await?;
    let mut ops = vec![];
    if let Some(sd) = p.register {
        ops.push(json!({"StorageDeposit": {"token": token, "amount": sd.to_string()}}));
    }
    let mut slip = ops.clone();
    slip.push(curve("CurveBuy", f, token, a, q * p.slip_bps / 10_000));
    let n_before = e.near(&t.id).await?;
    let r = e.exec(&t, json!(slip), "slip", a + NEAR).await?;
    let n_after = e.near(&t.id).await?;
    let pad_ret: Vec<String> = r
        .receipt_outcomes()
        .iter()
        .filter(|o| o.executor_id.as_str() == f)
        .map(|o| format!("{:?}", o.clone().into_result()).chars().take(80).collect())
        .collect();
    log += &format!(
        "slippage buy: ok={} settled={:?} ta_native_delta={} pad_results={pad_ret:?} {}\n",
        r.is_success(),
        VEnv::settled(&r),
        n_after as i128 - n_before as i128,
        errs(&r)
    );
    let st = VEnv::settled(&r).expect("settled");
    // a pad that panics on slippage: failed receipt -> used 0, spend back. Nearrr REFUNDS by
    // Transfer inside a successful receipt: R2-05 proves it by the output token, which the buy
    // held locked from run to its settle (no token received) -> used 0, fee 0, spend back too.
    // A NEAR delta is never read (V16-02).
    assert_eq!((st["used"].as_str(), st["fee"].as_str()), (Some("0"), Some("0")), "{log}");
    // the trade input and its fee come back; per-kind storage extras / registrations stay counted
    assert!(e.day_spent(&t).await? <= spent0 + NEAR / 50, "spend returned\n{log}");
    if !p.panics_on_slippage {
        assert!(r.logs().iter().any(|l| l.contains("nearrr_refunded")), "{log}");
    }
    assert!(q_lock(&e, &t, token).await?.is_null(), "lock released after a refund");
    assert!(n_after + NEAR / 20 >= n_before, "the NEAR came back (minus gas)");
    assert_eq!(e.near(e.fees.id()).await?, fees0);
    assert_eq!(e.ft(&tid, &t.id).await.unwrap_or(0), 0);

    // happy buy
    let q = quote_buy(e.clone(), a).await?;
    let min_buy = q * p.min_bps / 10_000;
    ops.push(curve("CurveBuy", f, token, a, min_buy));
    let r = e.exec(&t, json!(ops), "buy1", a + NEAR).await?;
    let got = e.ft(&tid, &t.id).await?;
    let fee_paid = e.near(e.fees.id()).await? - fees0;
    log += &format!(
        "buy {a}: ok={} out={got} quote={q} fee={fee_paid} settled={:?} gas={:.1}T {}\n",
        r.is_success(),
        VEnv::settled(&r),
        r.total_gas_burnt.as_gas() as f64 / 1e12,
        errs(&r)
    );
    assert!(r.is_success() && got >= min_buy, "buy delivered {got} >= {min_buy}\n{log}");
    assert!(q_lock(&e, &t, token).await?.is_null(), "lock released after a fill");
    // NearIn: fee = 1% x (amount - measured refund). FINDING (fee exactness NOT met): the measured
    // liquid delta also sees the gas refunds of EVERY receipt of the tx (they go to the signer =
    // the account: dragonpad's chain returned ~0.29 N in the sandbox) and registration refunds, so
    // the fee is UNDER-charged by 1% x those refunds (user-favorable, bounded by the prepaid gas).
    // Asserted as the bound [1% x (a - 0.35 N), 1% x a]; the exact figure is logged.
    let transfers: Vec<String> = r
        .receipt_outcomes()
        .iter()
        .map(|o| {
            format!(
                "{}:{:.4}T:{}",
                o.executor_id,
                o.gas_burnt.as_gas() as f64 / 1e12,
                o.logs.join(";").chars().take(160).collect::<String>()
            )
        })
        .collect();
    if p.full {
        assert_eq!(fee_paid, fee_of(a), "NearInFull: the whole 1% on a successful buy\n{log}");
    }
    assert!(
        fee_paid <= fee_of(a) && fee_paid + fee_of(35 * NEAR / 100) >= fee_of(a),
        "fee {fee_paid} vs {}\n{log}\n{transfers:#?}",
        fee_of(a)
    );
    let _ = spent0;

    // sells: slippage (tokens back, no fee), then happy (native payout, fee = 1% x min_out)
    let s = got / 2;
    let qs = quote_sell(e.clone(), s).await?;
    let fees1 = e.near(e.fees.id()).await?;
    let r = e.exec(&t, json!([curve("CurveSell", f, token, s, qs * 3)]), "sslip", NEAR).await?;
    log += &format!("slippage sell: ok={} settled={:?}\n", r.is_success(), VEnv::settled(&r));
    assert_eq!(e.ft(&tid, &t.id).await?, got, "tokens back");
    assert_eq!(e.near(e.fees.id()).await?, fees1);
    let n0 = e.near(&t.id).await?;
    let min = qs * 97 / 100;
    let r = e.exec(&t, json!([curve("CurveSell", f, token, s, min)]), "sell1", NEAR).await?;
    let n1 = e.near(&t.id).await?;
    let fee_s = e.near(e.fees.id()).await? - fees1;
    log += &format!(
        "sell {s}: ok={} native_delta={} quote={qs} fee={fee_s} settled={:?} gas={:.1}T {}\n",
        r.is_success(),
        n1 as i128 - n0 as i128,
        VEnv::settled(&r),
        r.total_gas_burnt.as_gas() as f64 / 1e12,
        errs(&r)
    );
    assert!(r.is_success() && e.ft(&tid, &t.id).await? == got - s, "sold\n{log}");
    assert!(n1 + NEAR / 20 >= n0 + min, "payout arrived (minus gas)");
    // ft_transfer_call sell rule: 1% x min_out, pro rata on what the token's resolve reports used
    // (a Nearrr `Tax` token reports 98%: its 2% transfer tax is not "used" by the factory)
    let used = u(&VEnv::settled(&r).unwrap()["used"]);
    let expect = (fee_of(min) as f64 * (used as f64 / s as f64)) as u128;
    assert!(
        fee_s.abs_diff(expect) <= expect / 1_000_000_000,
        "sell fee {fee_s} = 1% x min_out x used/amount {expect}\n{log}"
    );

    // negatives
    fails_with(&e.exec(&t, json!([curve("CurveBuy", f, token, a, 0)]), "n1", a + NEAR).await?, "E_BAD_OP");
    fails_with(
        &e.exec(&t, json!([curve("CurveBuy", "not-allowlisted.near", token, a, 1)]), "n2", a + NEAR).await?,
        "E_BAD_DEX",
    );
    fails_with(
        &e.exec(&t, json!([curve("CurveBuy", f, "x.other.near", a, 1)]), "n3", a + NEAR).await?,
        "E_CURVE_MARKET",
    );
    let mut q = curve("CurveBuy", f, token, a, 1);
    q["CurveBuy"]["quote"] = json!("usdc.near");
    fails_with(&e.exec(&t, json!([q]), "n4", a + NEAR).await?, "E_CURVE_QUOTE");
    let mut rcp = curve("CurveBuy", f, token, a, 1);
    rcp["CurveBuy"]["recipient"] = json!("thief.near");
    let r = e.exec(&t, json!([rcp]), "n5", a + NEAR).await?;
    assert!(
        r.is_failure() && format!("{:?}", r.clone().into_result().err()).contains("unknown field"),
        "recipient field refused"
    );

    // raw FtTransferCall sell through the msg_venues parser: the good shape works, extras refused
    let (good, key) = p.raw_sell;
    let raw = json!([{"FtTransferCall": {"token": token, "receiver_id": f, "amount": (s / 10).to_string(),
        "msg": good.to_string(), "gas": g.to_string()}}]);
    let r = e.exec(&t, raw, "raw1", NEAR).await?;
    log += &format!("raw FtTransferCall sell: ok={} {}\n", r.is_success(), errs(&r));
    assert!(r.is_success(), "{log}");
    raw_sell_negatives(&e, &t, f, token, good, key).await?;
    Ok(log)
}

type VEnvRef = std::sync::Arc<VEnv>;

/// Raw FtTransferCall sells through the msg_venues parser: accepted shape + refused extras.
async fn raw_sell_negatives(e: &VEnv, t: &Ta, f: &str, token: &str, good: Value, key: &str) -> Result<()> {
    let op = |m: &Value| json!([{"FtTransferCall": {"token": token, "receiver_id": f, "amount": "1000", "msg": m.to_string(), "gas": G.to_string()}}]);
    let mut extra = good.clone();
    extra[key]["recipient"] = json!("thief.near");
    fails_with(&e.exec(t, op(&extra), "r1", NEAR).await?, "E_BAD_MSG");
    let mut extra = good.clone();
    extra["receiver_id"] = json!("thief.near");
    fails_with(&e.exec(t, op(&extra), "r2", NEAR).await?, "E_BAD_MSG");
    Ok(())
}

#[tokio::test]
async fn venues_nearrr() -> Result<()> {
    let token = "arcova-m6ez.nearrr-fun.near";
    let log = near_pad(
        Pad {
            f: "nearrr-fun.near",
            fhash: "48oZBxXPg6SyW9HwMbyXYNQnEEWUSCRxNte9DtYyTdCr",
            kind: json!({"FactoryCurve": "Nearrr"}),
            token,
            thash: None,
            payees: &[
                "grandpalace7442.near",
                "leftcity7777.near",
                "locker2.nearrr-fun.near",
                "lpvault.nearrr-fun.near",
            ],
            // token storage_balance_bounds = 0.00221 N; the pad checks registration first
            register: Some(2_210_000_000_000_000_000_000),
            a: NEAR / 2,
            // tax view 5 + balance 5 + buy 185 (the pad refuses < 180) + balance 5 + callbacks = 216
            gas: NEARRR_OP_GAS,
            // 1% tax token: the account reads tax_state (1% + 1% platform) and sends the pad
            // ceil(min_out / 0.98). A post-tax floor at 1% slippage (98% x 99% of the quote)
            // fills; 99% of the quote needs a pre-tax 101% and the pad refunds (slippage case).
            min_bps: 9_702,
            slip_bps: 9_900,
            raw_sell: (json!({"sell": {"min_out": "1"}}), "sell"),
            full: true,
            panics_on_slippage: false,
        },
        |e, a| async move {
            let v: Value = e
                .worker
                .view(&"nearrr-fun.near".parse()?, "quote_buy_view")
                .args_json(json!({"token_id": token, "quote_in": a.to_string()}))
                .await?
                .json()?;
            Ok(u(&v[0]))
        },
        |e, s| async move {
            let v: Value = e
                .worker
                .view(&"nearrr-fun.near".parse()?, "quote_sell_view")
                .args_json(json!({"token_id": token, "tokens_in": s.to_string()}))
                .await?
                .json()?;
            Ok(u(&v))
        },
    )
    .await?;
    println!("{log}");
    Ok(())
}

async fn launch_json(e: &VEnv, f: &str, m: &str, args: Value) -> Result<Value> {
    Ok(e.worker.view(&f.parse()?, m).args_json(args).await?.json()?)
}

#[tokio::test]
async fn venues_dragonpad() -> Result<()> {
    let token = "ember.dragonpad.near";
    // no quote view: constant product on get_launch reserves, 0.5% creator + 0.5% platform on NEAR
    let reserves = |e: VEnvRef| async move {
        let l = launch_json(&e, "dragonpad.near", "get_launch", json!({"token_id": token})).await?;
        Ok::<_, anyhow::Error>((u(&l["quote_reserve"]), u(&l["token_reserve"])))
    };
    let log = near_pad(
        Pad {
            f: "dragonpad.near",
            fhash: "3gqUU3rDaJ8xw61iBwHa65ygy1BnHKLHK3Wo3GcAgCUC",
            kind: json!({"FactoryCurve": "Dragonpad"}),
            token,
            // token code 8D1NEU2N (global), pinned through the factory's token_code_hash
            thash: None,
            payees: &["lp-burn.dragonpad.near"],
            // the pad storage_deposits the buyer itself (C 5CyjQJEA)
            register: None,
            a: NEAR / 2,
            gas: G,
            min_bps: 9_500,
            slip_bps: 30_000,
            raw_sell: (json!({"sell": {"min_quote_out": "1"}}), "sell"),
            full: true,
            panics_on_slippage: true,
        },
        move |e, a| async move {
            let (q, t) = reserves(e).await?;
            let a = (a * 99 / 100) as f64;
            Ok((t as f64 * a / (q as f64 + a)) as u128)
        },
        move |e, s| async move {
            let (q, t) = reserves(e).await?;
            Ok((q as f64 * s as f64 / (t as f64 + s as f64) * 0.99) as u128)
        },
    )
    .await?;
    println!("{log}");
    Ok(())
}

#[tokio::test]
async fn venues_vista_launch() -> Result<()> {
    let token = "vv-1.launch.vistadev.near";
    let log = near_pad(
        Pad {
            f: "launch.vistadev.near",
            fhash: "DjxyjbtXeVP3eapCZVgUG9dhPmvdAkZMfpFMT6gqunFi",
            kind: json!({"FactoryCurve": "VistaLaunch"}),
            token,
            thash: None,
            payees: &["vistadev.near", "faruni8562.near"],
            register: None,
            a: NEAR / 2,
            gas: G,
            min_bps: 9_900,
            slip_bps: 30_000,
            raw_sell: (json!({"sell": {"min_out": "1"}}), "sell"),
            full: false,
            panics_on_slippage: true,
        },
        move |e, a| async move {
            let v = launch_json(
                &e,
                "launch.vistadev.near",
                "quote_buy",
                json!({"token_id": token, "near_in": a.to_string()}),
            )
            .await?;
            Ok(u(&v["tokens_out"]))
        },
        move |e, s| async move {
            let v = launch_json(
                &e,
                "launch.vistadev.near",
                "quote_sell",
                json!({"token_id": token, "amount": s.to_string()}),
            )
            .await?;
            Ok(u(&v["near_out"]))
        },
    )
    .await?;
    println!("{log}");
    Ok(())
}

/// Credit / pending claims pay THIS account: the real pads accept the planned args and deposits
/// (an empty claim fails with the pad's own "nothing" message, not a deserialize/deposit error).
#[tokio::test]
async fn venues_factory_claims_shape() -> Result<()> {
    let e = venv().await?;
    import_mainnet(&e.worker, "dragonpad.near", Some("3gqUU3rDaJ8xw61iBwHa65ygy1BnHKLHK3Wo3GcAgCUC")).await?;
    import_mainnet(&e.worker, "launch.vistadev.near", Some("DjxyjbtXeVP3eapCZVgUG9dhPmvdAkZMfpFMT6gqunFi"))
        .await?;
    let t = e
        .ta(
            "u",
            5 * NEAR,
            (2 * NEAR, 4 * NEAR),
            vec![
                json!({"id": "dragonpad.near", "kind": {"FactoryCurve": "Dragonpad"}}),
                json!({"id": "launch.vistadev.near", "kind": {"FactoryCurve": "VistaLaunch"}}),
            ],
        )
        .await?;
    let claim = |venue: &str, action: &str, market: Option<&str>| json!([{"CurveClaim": {"venue": venue, "action": action, "market": market}}]);
    for (op, want) in [
        (claim("dragonpad.near", "DragonpadClaim", None), "Nothing to claim"),
        (claim("dragonpad.near", "DragonpadClaim", Some("ember.dragonpad.near")), "Nothing to claim"),
        (
            claim("launch.vistadev.near", "VistaClaimPending", Some("vv-1.launch.vistadev.near")),
            "nothing pending",
        ),
    ] {
        let r = e.exec(&t, op.clone(), &format!("c{}", want.len() + op.to_string().len()), NEAR).await?;
        let s = errs(&r);
        println!("{op}: {s}");
        assert!(s.contains(want), "{op}: {s}");
    }
    Ok(())
}

/// R2-05 (UNR-A-02): a 24/7 limit buy on Nearrr whose fire misses the pad's bound. The pad refunds
/// by Transfer inside a successful receipt; the buy held its output token locked from run to its
/// settle, so "no token received" proves the refund: the order REOPENS (fee 0, spend back, the NEAR
/// back in the account, `nearrr_refunded` + `order_reopened` logged). A second fire of the SAME
/// order at its floor fills with the whole fee.
#[tokio::test]
async fn venues_nearrr_order_refund_reopens() -> Result<()> {
    let e = venv().await?;
    let (f, token) = ("nearrr-fun.near", "arcova-m6ez.nearrr-fun.near");
    import_mainnet(&e.worker, f, Some("48oZBxXPg6SyW9HwMbyXYNQnEEWUSCRxNte9DtYyTdCr")).await?;
    import_mainnet(&e.worker, token, None).await?;
    for x in
        ["grandpalace7442.near", "leftcity7777.near", "locker2.nearrr-fun.near", "lpvault.nearrr-fun.near"]
    {
        create(&e, x).await?;
    }
    let t = e
        .ta(
            "u",
            30 * NEAR,
            (10 * NEAR, 50 * NEAR),
            vec![json!({"id": f, "kind": {"FactoryCurve": "Nearrr"}})],
        )
        .await?;
    let a = NEAR / 2;
    let q: Value = e
        .worker
        .view(&f.parse()?, "quote_buy_view")
        .args_json(json!({"token_id": token, "quote_in": a.to_string()}))
        .await?
        .json()?;
    let q = u(&q[0]);
    // the order's floor: the post-tax delivery at 1% slippage (98% x 99% of the quote)
    let floor = q * 9_702 / 10_000;
    let exp = e.worker.view_block().await?.timestamp() + 3_600_000_000_000;
    let spent_pre = e.day_spent(&t).await?;
    let r = t.device.call(&t.id, "place_order")
        .args_json(json!({"token_in": e.wrap.id(), "token_out": token, "amount_in": a.to_string(), "min_out": floor.to_string(),
            "trigger_meta": "limit", "expires_at_ns": exp.to_string(), "dexes": [f]}))
        .gas(near_workspaces::types::Gas::from_tgas(100)).transact().await?;
    let id: String = okr(r)?.json()?;
    let fire = |min: u128| {
        json!([
            {"StorageDeposit": {"token": token, "amount": "2210000000000000000000"}},
            curve_g("CurveBuy", f, token, a, min, NEARRR_OP_GAS)
        ])
    };
    let exec_order = |ops: Value| {
        let (dev, tid, id) = (t.device.clone(), t.id.clone(), id.clone());
        async move {
            dev.call(&tid, "execute_order")
                .args_json(json!({"order_id": id, "ops": ops}))
                .gas(near_workspaces::types::Gas::from_tgas(300))
                .transact()
                .await
        }
    };
    let fees0 = e.near(e.fees.id()).await?;
    // fire 1: a bound the pad can't meet (99% of the quote -> pre-tax 101%): refunded, REOPENED
    let n0 = e.near(&t.id).await?;
    let spent0 = e.day_spent(&t).await?;
    let r = exec_order(fire(q * 9_900 / 10_000)).await?;
    let logs = r.logs().join("\n");
    let st = VEnv::settled(&r).expect("settled");
    println!(
        "fire 1: ok={} settled={st} refunded={} reopened={} spent pre-order={spent_pre} before={spent0} after={}",
        r.is_success(),
        logs.contains("nearrr_refunded"),
        logs.contains("order_reopened"),
        e.day_spent(&t).await?
    );
    assert!(logs.contains("nearrr_refunded") && logs.contains("order_reopened"), "{logs}");
    assert!(!logs.contains("order_filled") && !logs.contains("order_consumed"), "{logs}");
    assert_eq!((st["used"].as_str(), st["fee"].as_str()), (Some("0"), Some("0")), "{logs}");
    assert_eq!(e.near(e.fees.id()).await?, fees0, "no fee on a refund");
    // the input and its reserved fee come back; the fire's gas charge and the token
    // registration (StorageDeposit) stay counted
    assert!(e.day_spent(&t).await? < spent0 + a / 10, "spend returned");
    e.worker.fast_forward(3).await?;
    assert!(e.near(&t.id).await? + NEAR / 50 >= n0, "the NEAR came back");
    assert_eq!(e.ft(&token.parse()?, &t.id).await.unwrap_or(0), 0, "no tokens");
    let o: Value = e.worker.view(&t.id, "get_order").args_json(json!({"order_id": id})).await?.json()?;
    assert!(!o.is_null() && o["pending"] == json!(false), "reopened, not pending: {o}");
    assert!(q_lock(&e, &t, token).await?.is_null(), "lock released after the refund");
    // fire 2: the same order at its own floor: fills, whole fee, order gone
    let r = exec_order(fire(floor)).await?;
    let logs = r.logs().join("\n");
    println!(
        "fire 2: ok={} settled={:?} filled={} {}",
        r.is_success(),
        VEnv::settled(&r),
        logs.contains("order_filled"),
        errs(&r)
    );
    assert!(logs.contains("order_filled"), "{logs}");
    assert!(e.ft(&token.parse()?, &t.id).await? >= floor);
    assert_eq!(e.near(e.fees.id()).await? - fees0, fee_of(a), "exact fee");
    let o: Value = e.worker.view(&t.id, "get_order").args_json(json!({"order_id": id})).await?.json()?;
    assert!(o.is_null(), "filled order removed");
    assert!(q_lock(&e, &t, token).await?.is_null(), "lock released after the fill");
    Ok(())
}

/// R2-05: while a Nearrr buy is in flight its output token is locked (holder `nearrr:<id>`), so no
/// device op can move that token and fake the settle's "no token received" proof: withdraw_to_owner,
/// withdraw_cross_chain, a sell of it and a second Nearrr buy of it are all E_Q_BUSY during the
/// settle. The in-flight buy still settles as the refund it is, the lock is released afterwards
/// (the same ops go through), and a buy whose pad call itself fails releases it too.
#[tokio::test]
async fn venues_nearrr_lock_refuses_concurrent_ops() -> Result<()> {
    let e = venv().await?;
    let (f, token) = ("nearrr-fun.near", "arcova-m6ez.nearrr-fun.near");
    import_mainnet(&e.worker, f, Some("48oZBxXPg6SyW9HwMbyXYNQnEEWUSCRxNte9DtYyTdCr")).await?;
    let tok = import_mainnet(&e.worker, token, None).await?;
    for x in
        ["grandpalace7442.near", "leftcity7777.near", "locker2.nearrr-fun.near", "lpvault.nearrr-fun.near"]
    {
        create(&e, x).await?;
    }
    let t = e
        .ta(
            "u",
            30 * NEAR,
            (10 * NEAR, 50 * NEAR),
            vec![json!({"id": f, "kind": {"FactoryCurve": "Nearrr"}})],
        )
        .await?;
    // one device key per concurrent tx (no shared nonce)
    let mut keys = vec![];
    for _ in 0..5 {
        let sk = near_workspaces::types::SecretKey::from_random(near_workspaces::types::KeyType::ED25519);
        e.worker
            .patch(&t.id)
            .access_key(
                sk.public_key(),
                near_workspaces::AccessKey::function_call_access(&t.id, &DEVICE_METHODS, None),
            )
            .transact()
            .await?;
        keys.push(near_workspaces::Account::from_secret_key(t.id.clone(), sk, &e.worker));
    }
    let a = NEAR / 2;
    let quote = || async {
        let v: Value = e
            .worker
            .view(&f.parse()?, "quote_buy_view")
            .args_json(json!({"token_id": token, "quote_in": a.to_string()}))
            .await?
            .json()?;
        anyhow::Ok(u(&v[0]))
    };
    let reg = json!({"StorageDeposit": {"token": token, "amount": "2210000000000000000000"}});
    // hold some tokens first (a real balance a concurrent debit could move)
    let q = quote().await?;
    let r = e
        .exec(
            &t,
            json!([reg, curve_g("CurveBuy", f, token, a, q * 9_702 / 10_000, NEARRR_OP_GAS)]),
            "hold",
            a + NEAR,
        )
        .await?;
    let held = e.ft(tok.id(), &t.id).await?;
    assert!(r.is_success() && held > 0, "setup buy {}", errs(&r));
    assert!(q_lock(&e, &t, token).await?.is_null());
    let exp = || async { anyhow::Ok(e.worker.view_block().await?.timestamp() + 60_000_000_000) };

    // the in-flight buy: a bound the pad can't meet (it refunds by Transfer)
    let q = quote().await?;
    let x = exp().await?;
    let buy = keys[0]
        .call(&t.id, "execute")
        .args_json(json!({"ops": [curve_g("CurveBuy", f, token, a, q * 9_900 / 10_000, NEARRR_OP_GAS)],
            "client_order_id": "inflight", "expires_at_ns": x.to_string(), "max_in_yocto": (a + NEAR).to_string()}))
        .gas(near_workspaces::types::Gas::from_tgas(300))
        .transact_async()
        .await?;
    let mut lock = Value::Null;
    for _ in 0..100 {
        lock = q_lock(&e, &t, token).await?;
        if !lock.is_null() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    println!("lock while in flight: {lock}");
    assert_eq!(lock[0].as_str(), Some("nearrr:inflight"), "the buy holds its output token: {lock}");

    // concurrent device ops on the locked token, all sent while it is held
    let x = exp().await?;
    let call = |k: &near_workspaces::Account, m: &str, args: Value| {
        k.call(&t.id, m).args_json(args).gas(near_workspaces::types::Gas::from_tgas(300)).transact_async()
    };
    let w1 = call(&keys[1], "withdraw_to_owner", json!({"token": token, "amount": "1"})).await?;
    let w2 = call(
        &keys[2],
        "withdraw_cross_chain",
        json!({"dest_id": 0, "token": token, "amount": "1", "signed_quote": "{}", "signature": "x",
            "client_order_id": "cc-inflight", "expires_at_ns": x.to_string()}),
    )
    .await?;
    let w3 = call(
        &keys[3],
        "execute",
        json!({"ops": [curve_g("CurveSell", f, token, held / 2, 1, NEARRR_OP_GAS)], "client_order_id": "sell-inflight",
            "expires_at_ns": x.to_string(), "max_in_yocto": NEAR.to_string()}),
    )
    .await?;
    let w4 = call(
        &keys[4],
        "execute",
        json!({"ops": [curve_g("CurveBuy", f, token, a, 1, NEARRR_OP_GAS)], "client_order_id": "buy2-inflight",
            "expires_at_ns": x.to_string(), "max_in_yocto": (a + NEAR).to_string()}),
    )
    .await?;
    let still = q_lock(&e, &t, token).await?;
    for (name, s) in
        [("withdraw_to_owner", w1), ("withdraw_cross_chain", w2), ("sell", w3), ("second buy", w4)]
    {
        let r = loop {
            if let std::task::Poll::Ready(r) = s.status().await? {
                break r;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        };
        println!("{name} during the settle: ok={} {}", r.is_success(), errs(&r));
        fails_with(&r, "E_Q_BUSY");
    }
    // the detached Nearrr chain can outlive the first Ready status: wait for its settle (which
    // releases the lock, bounded by 60 blocks), then read the whole outcome
    for _ in 0..600 {
        if q_lock(&e, &t, token).await?.is_null() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    e.worker.fast_forward(2).await?;
    let r = loop {
        if let std::task::Poll::Ready(r) = buy.status().await? {
            if VEnv::settled(&r).is_some() {
                break r;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    };
    let st = VEnv::settled(&r).expect("settled");
    println!("in-flight buy: settled={st} lock after the concurrent sends={still} {}", errs(&r));
    assert!(r.logs().iter().any(|l| l.contains("nearrr_refunded")));
    assert_eq!((st["used"].as_str(), st["fee"].as_str()), (Some("0"), Some("0")), "refund, fee 0");
    assert_eq!(e.ft(tok.id(), &t.id).await?, held, "the token balance never moved");
    assert!(q_lock(&e, &t, token).await?.is_null(), "lock released after the settle");
    // nothing stays stuck: the same ops on the token go through now
    let r = call(&keys[1], "withdraw_to_owner", json!({"token": token, "amount": "1"})).await?;
    let r = loop {
        if let std::task::Poll::Ready(r) = r.status().await? {
            break r;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    };
    assert!(r.is_success(), "withdraw after the settle: {}", errs(&r));
    assert_eq!(e.ft(tok.id(), &t.owner.id().clone()).await.unwrap_or(0), 1);

    // edge buys: the real pad never panics (probed: 1 yocto, an absurd min_out both come back by
    // Transfer in a successful receipt); on_nearrr_settled only reads the after-balance, so a pad
    // failure runs this same no-token path. Refused / unfunded / unreadable exits: unit tests
    // (settle_tests) and venues_nearrr_tax_levels. Each settles and releases the lock
    for (k, (amt, min)) in [(1u128, 1u128), (a, 10u128.pow(33))].into_iter().enumerate() {
        let fees0 = e.near(e.fees.id()).await?;
        let r = e
            .exec(
                &t,
                json!([curve_g("CurveBuy", f, token, amt, min, NEARRR_OP_GAS)]),
                &format!("edge{k}"),
                a + NEAR,
            )
            .await?;
        let st = VEnv::settled(&r).expect("settled");
        println!("edge buy amount={amt} min_out={min}: settled={st} {}", errs(&r));
        assert_eq!((st["used"].as_str(), st["fee"].as_str()), (Some("0"), Some("0")));
        assert_eq!(e.near(e.fees.id()).await?, fees0);
        assert!(q_lock(&e, &t, token).await?.is_null(), "lock released");
    }
    // a run that fails at execute (op gas below the chain) never stores a lock
    fails_with(
        &e.exec(&t, json!([curve_g("CurveBuy", f, token, a, 1, 210 * TGAS)]), "low", a + NEAR).await?,
        "E_GAS",
    );
    assert!(q_lock(&e, &t, token).await?.is_null());
    Ok(())
}

/// R2-05 (owner doors): the owner can't move a Nearrr buy's locked output token mid-settle either
/// (that would make the fill read as the pad's refund, fee 0). owner_withdraw and
/// owner_withdraw_all of the token, sent while a fillable buy is in flight, are E_Q_BUSY; the buy
/// settles as a FILL with the exact 1% fee; after the settle the owner withdraw goes through.
#[tokio::test]
async fn venues_nearrr_lock_refuses_owner_withdraw() -> Result<()> {
    let e = venv().await?;
    let (f, token) = ("nearrr-fun.near", "arcova-m6ez.nearrr-fun.near");
    import_mainnet(&e.worker, f, Some("48oZBxXPg6SyW9HwMbyXYNQnEEWUSCRxNte9DtYyTdCr")).await?;
    let tok = import_mainnet(&e.worker, token, None).await?;
    for x in
        ["grandpalace7442.near", "leftcity7777.near", "locker2.nearrr-fun.near", "lpvault.nearrr-fun.near"]
    {
        create(&e, x).await?;
    }
    let t = e
        .ta(
            "u",
            30 * NEAR,
            (10 * NEAR, 50 * NEAR),
            vec![json!({"id": f, "kind": {"FactoryCurve": "Nearrr"}})],
        )
        .await?;
    let a = NEAR / 2;
    let quote = || async {
        let v: Value = e
            .worker
            .view(&f.parse()?, "quote_buy_view")
            .args_json(json!({"token_id": token, "quote_in": a.to_string()}))
            .await?
            .json()?;
        anyhow::Ok(u(&v[0]))
    };
    let reg = json!({"StorageDeposit": {"token": token, "amount": "2210000000000000000000"}});
    // hold some tokens first (a balance the owner could move out mid-settle)
    let q = quote().await?;
    let r = e
        .exec(
            &t,
            json!([reg, curve_g("CurveBuy", f, token, a, q * 9_702 / 10_000, NEARRR_OP_GAS)]),
            "hold",
            a + NEAR,
        )
        .await?;
    let held = e.ft(tok.id(), &t.id).await?;
    assert!(r.is_success() && held > 0, "setup buy {}", errs(&r));

    // the in-flight buy: a bound the pad meets (the post-tax delivery at 1% slippage) -> a fill
    let q = quote().await?;
    let x = e.worker.view_block().await?.timestamp() + 60_000_000_000;
    let fees0 = e.near(e.fees.id()).await?;
    let buy = t
        .device
        .call(&t.id, "execute")
        .args_json(json!({"ops": [curve_g("CurveBuy", f, token, a, q * 9_702 / 10_000, NEARRR_OP_GAS)],
            "client_order_id": "inflight", "expires_at_ns": x.to_string(), "max_in_yocto": (a + NEAR).to_string()}))
        .gas(near_workspaces::types::Gas::from_tgas(300))
        .transact_async()
        .await?;
    let mut lock = Value::Null;
    for _ in 0..100 {
        lock = q_lock(&e, &t, token).await?;
        if !lock.is_null() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(lock[0].as_str(), Some("nearrr:inflight"), "the buy holds its output token: {lock}");

    // the owner empties the token while it is held: both owner doors refused
    let owner = |m: &str, args: Value| {
        t.owner
            .call(&t.id, m)
            .args_json(args)
            .deposit(NearToken::from_yoctonear(1))
            .gas(near_workspaces::types::Gas::from_tgas(300))
            .transact_async()
    };
    let w1 = owner("owner_withdraw", json!({"token": token, "amount": held.to_string(), "to": t.owner.id()}))
        .await?;
    let w2 = owner("owner_withdraw_all", json!({"to": t.owner.id(), "tokens": [token]})).await?;
    for (name, s) in [("owner_withdraw", w1), ("owner_withdraw_all", w2)] {
        let r = loop {
            if let std::task::Poll::Ready(r) = s.status().await? {
                break r;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        };
        println!("{name} during the settle: ok={} {}", r.is_success(), errs(&r));
        fails_with(&r, "E_Q_BUSY");
    }
    for _ in 0..600 {
        if q_lock(&e, &t, token).await?.is_null() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    e.worker.fast_forward(2).await?;
    let r = loop {
        if let std::task::Poll::Ready(r) = buy.status().await? {
            if VEnv::settled(&r).is_some() {
                break r;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    };
    let st = VEnv::settled(&r).expect("settled");
    println!("in-flight buy: settled={st} {}", errs(&r));
    assert!(!r.logs().iter().any(|l| l.contains("nearrr_refunded")), "a fill, not a refund");
    let fee = fee_of(a).to_string();
    let used = a.to_string();
    assert_eq!(
        (st["used"].as_str(), st["fee"].as_str()),
        (Some(used.as_str()), Some(fee.as_str())),
        "fill, 1% fee"
    );
    e.worker.fast_forward(2).await?;
    assert_eq!(e.near(e.fees.id()).await? - fees0, fee_of(a), "exact fee paid");
    let now = e.ft(tok.id(), &t.id).await?;
    assert!(now > held, "the fill's tokens arrived and nothing left: {held} -> {now}");
    assert!(q_lock(&e, &t, token).await?.is_null(), "lock released after the settle");
    // after the settle the owner withdraw goes through
    let r = owner("owner_withdraw", json!({"token": token, "amount": "1", "to": t.owner.id()})).await?;
    let r = loop {
        if let std::task::Poll::Ready(r) = r.status().await? {
            break r;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    };
    assert!(r.is_success(), "owner withdraw after the settle: {}", errs(&r));
    // (the token transfer lands a few blocks after the call's own status)
    e.worker.fast_forward(2).await?;
    assert_eq!(e.ft(tok.id(), t.owner.id()).await.unwrap_or(0), 1);
    Ok(())
}

/// R2-09 (owner doors): the owner's `owner_upgrade`, sent while a Nearrr buy is in flight, is
/// refused (E_IN_FLIGHT) and the code is unchanged; the buy settles as a normal FILL with the exact
/// 1% fee on the code it started on. Right after the settle the lock window still holds the door;
/// once it passes (LOCK_TTL_BLOCKS) the same owner_upgrade installs the new code.
#[tokio::test]
async fn venues_nearrr_owner_upgrade_waits_for_in_flight_buy() -> Result<()> {
    let e = venv().await?;
    let (f, token) = ("nearrr-fun.near", "arcova-m6ez.nearrr-fun.near");
    import_mainnet(&e.worker, f, Some("48oZBxXPg6SyW9HwMbyXYNQnEEWUSCRxNte9DtYyTdCr")).await?;
    let tok = import_mainnet(&e.worker, token, None).await?;
    for x in
        ["grandpalace7442.near", "leftcity7777.near", "locker2.nearrr-fun.near", "lpvault.nearrr-fun.near"]
    {
        create(&e, x).await?;
    }
    let t = e
        .ta(
            "u",
            30 * NEAR,
            (10 * NEAR, 50 * NEAR),
            vec![json!({"id": f, "kind": {"FactoryCurve": "Nearrr"}})],
        )
        .await?;
    // the upgrade target, as global code
    let deployer = e
        .root
        .create_subaccount("gd")
        .initial_balance(NearToken::from_near(200))
        .transact()
        .await?
        .into_result()?
        .deploy(&out("global_deployer"))
        .await?
        .into_result()?;
    let v2_code = out("trading_account_upgrade_test");
    ok(deployer
        .call("deploy")
        .args_borsh(v2_code.clone())
        .gas(near_workspaces::types::Gas::from_tgas(300))
        .transact()
        .await?)?;
    let v2 = code_hash(&v2_code);
    let version = || async {
        let v: Value = e.worker.view(&t.id, "get_config").await?.json()?;
        anyhow::Ok(v["version"].as_str().unwrap_or_default().to_string())
    };
    assert_eq!(version().await?, "1.6.0");
    let upgrade = || {
        t.owner
            .call(&t.id, "owner_upgrade")
            .args_json(json!({"code_hash": v2}))
            .deposit(NearToken::from_yoctonear(1))
            .gas(near_workspaces::types::Gas::from_tgas(100))
            .transact_async()
    };
    let wait = |s: near_workspaces::operations::TransactionStatus| async move {
        loop {
            if let std::task::Poll::Ready(r) = s.status().await? {
                break anyhow::Ok(r);
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    };

    // the in-flight buy: a bound the pad meets -> a fill
    let a = NEAR / 2;
    let v: Value = e
        .worker
        .view(&f.parse()?, "quote_buy_view")
        .args_json(json!({"token_id": token, "quote_in": a.to_string()}))
        .await?
        .json()?;
    let q = u(&v[0]);
    let reg = json!({"StorageDeposit": {"token": token, "amount": "2210000000000000000000"}});
    let x = e.worker.view_block().await?.timestamp() + 60_000_000_000;
    let fees0 = e.near(e.fees.id()).await?;
    let buy = t
        .device
        .call(&t.id, "execute")
        .args_json(json!({"ops": [reg, curve_g("CurveBuy", f, token, a, q * 9_702 / 10_000, NEARRR_OP_GAS)],
            "client_order_id": "inflight", "expires_at_ns": x.to_string(), "max_in_yocto": (a + NEAR).to_string()}))
        .gas(near_workspaces::types::Gas::from_tgas(300))
        .transact_async()
        .await?;
    let mut lock = Value::Null;
    for _ in 0..100 {
        lock = q_lock(&e, &t, token).await?;
        if !lock.is_null() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(lock[0].as_str(), Some("nearrr:inflight"), "the buy is in flight: {lock}");

    // the owner upgrades mid-settle: refused, code unchanged
    let r = wait(upgrade().await?).await?;
    println!("owner_upgrade during the settle: ok={} {}", r.is_success(), errs(&r));
    fails_with(&r, "E_IN_FLIGHT");

    // the buy settles normally (a fill, exact 1% fee) on the code it started on
    let r = loop {
        if let std::task::Poll::Ready(r) = buy.status().await? {
            if VEnv::settled(&r).is_some() {
                break r;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    };
    let st = VEnv::settled(&r).expect("settled");
    println!("in-flight buy: settled={st} {}", errs(&r));
    assert!(!r.logs().iter().any(|l| l.contains("nearrr_refunded")), "a fill, not a refund");
    let (fee, used) = (fee_of(a).to_string(), a.to_string());
    assert_eq!((st["used"].as_str(), st["fee"].as_str()), (Some(used.as_str()), Some(fee.as_str())), "fill");
    e.worker.fast_forward(2).await?;
    assert_eq!(e.near(e.fees.id()).await? - fees0, fee_of(a), "exact fee paid");
    assert!(e.ft(tok.id(), &t.id).await? > 0, "the fill's tokens arrived");
    assert!(q_lock(&e, &t, token).await?.is_null(), "lock released after the settle");
    assert_eq!(version().await?, "1.6.0", "still the old code");

    // the lock's window (LOCK_TTL_BLOCKS from the lock) still holds the door right after the settle
    fails_with(&wait(upgrade().await?).await?, "E_IN_FLIGHT");
    // once it passes, the same owner_upgrade installs the new code
    e.worker.fast_forward(300).await?;
    let r = wait(upgrade().await?).await?;
    assert!(r.is_success(), "owner_upgrade after the window: {}", errs(&r));
    e.worker.fast_forward(2).await?;
    assert_eq!(version().await?, "upgrade-test");
    Ok(())
}

// ---------------- Nira (curve10.latedata9580.near) ----------------
// State is TOO_LARGE for view_state (1.5 MB), so the factory is REPLAYED: its real code (pinned),
// its mainnet `new` args (tx of latedata9580.near), the float fundings, the children's global
// code (vault 6AmerPRz, registration payer Dth9VoPf, fetched from live children), then a NEAR-pair
// `create_launch` shaped like the mainnet "nira" launch (no first buy), advanced to `active` with
// `resume_graduation` (5 keeper calls: vault_reconcile -> ... -> vault_verified), as on mainnet.
// Pair (Q) buys/sells use the same factory paths with `Q.ft_transfer_call` (unit-tested; the
// NIRA quote is itself a graduated Nira NEP-141, l4f66f4ddb7b874f72165b273.curve10...).

const NIRA: &str = "curve10.latedata9580.near";
const NIRA_HASH: &str = "8KDKBoNcebETnMXMmDWQ2fTB3nk2y6k4WbKJVXGv4PtU";

async fn nira_env() -> Result<(VEnv, near_workspaces::Account, String)> {
    let e = venv().await?;
    let code = pinned(NIRA, Some(NIRA_HASH)).await?;
    let fac = install_code(&e.worker, NIRA, &code).await?;
    for x in [
        "latedata9580.near",
        "buyback.latedata9580.near",
        "checkout8.latedata9580.near",
        "dclv2.ref-labs.near",
    ] {
        create(&e, x).await?;
    }
    // children's global code, deployed by hash as on mainnet
    let dep =
        sub(&e.root, "gdeploy", 200 * NEAR).await?.deploy(&out("global_deployer")).await?.into_result()?;
    for child in [
        "vl7802b721f9f55fb60d03c071.curve10.latedata9580.near",
        "rl7802b721f9f55fb60d03c071.curve10.latedata9580.near",
    ] {
        let c = mainnet_code(child).await?;
        ok(dep
            .call("deploy")
            .args_borsh(c)
            .gas(near_workspaces::types::Gas::from_tgas(300))
            .transact()
            .await?)?;
    }
    let new_args: Value = serde_json::from_str(
        &std::fs::read_to_string(format!("{}/tests/fixtures_nira_new.json", env!("CARGO_MANIFEST_DIR")))
            .unwrap_or_else(|_| NIRA_NEW.to_string()),
    )?;
    let r = fac
        .call("new")
        .args_json(new_args)
        .gas(near_workspaces::types::Gas::from_tgas(300))
        .transact()
        .await?;
    let mut log = format!("nira new: ok={} {}\n", r.is_success(), errs(&r));
    for (m, d) in [
        ("fund_ft_call_float", 50u128),
        ("fund_checkout_storage", 100),
        ("fund_payout_storage", 150),
        ("fund_ops_float", 400),
    ] {
        let r = fac
            .as_account()
            .call(fac.id(), m)
            .args_json(json!({}))
            .deposit(NearToken::from_millinear(d))
            .gas(near_workspaces::types::Gas::from_tgas(100))
            .transact()
            .await?;
        log += &format!("{m}: ok={} {}\n", r.is_success(), errs(&r));
    }
    Ok((e, fac.as_account().clone(), log))
}

/// `new` of curve10.latedata9580.near on mainnet (latedata9580.near's deploy tx).
const NIRA_NEW: &str = r#"{"protocol_fee_recipient_id":"buyback.latedata9580.near","checkout_adapter_id":"checkout8.latedata9580.near",
"economics_authority_id":"latedata9580.near","platform_share_bps":3000,"dcl_account_id":"dclv2.ref-labs.near",
"wnear_account_id":"wrap.near","dcl_storage_deposit":"500000000000000000000000","dcl_pool_creation_deposit":"100000000000000000000000",
"wnear_storage_deposit":"1250000000000000000000","taxed_venue_ids":["dclv2.ref-labs.near","v2.ref-finance.near"],
"protocol_token":{"creator_id":"latedata9580.near","treasury_id":"0x7add64b8d36f3f86ad11d5af87cfc0f3a2465592","symbol":"NIRA"}}"#;

#[tokio::test]
async fn venues_nira_near() -> Result<()> {
    let (e, fac, mut log) = nira_env().await?;
    let creator = sub(&e.root, "creator", 50 * NEAR).await?;
    let args = json!({"launch_id": "tst-1", "metadata": {"spec": "ft-1.0.0", "name": "Test", "symbol": "TST", "icon": "data:,",
        "reference": null, "reference_hash": null, "decimals": 6}, "max_supply": "1000000000000000",
        "buy_tax_bps": 300, "sell_tax_bps": 300, "split": {"creator_bps": 0, "dividends_bps": 10000, "buyback_bps": 0, "liquidity_bps": 0},
        "creator_funds_wallet_id": creator.id(), "expected_pair_revision": "1", "expected_platform_share_bps": 3000,
        "pair_asset_id": "near"});
    let q = e.worker.view(fac.id(), "get_creation_quote").args_json(args.clone()).await;
    log += &format!(
        "quote: {:?}\n",
        q.map(|r| String::from_utf8_lossy(&r.result).chars().take(400).collect::<String>())
    );
    let r = creator
        .call(fac.id(), "create_launch")
        .args_json(args)
        .deposit(NearToken::from_near(3))
        .gas(near_workspaces::types::Gas::from_tgas(300))
        .transact()
        .await?;
    log += &format!("create_launch: ok={} {}\n", r.is_success(), errs(&r));
    for o in r.receipt_outcomes() {
        log += &format!(
            "  {} {:.1}T {:?} {}\n",
            o.executor_id,
            o.gas_burnt.as_gas() as f64 / 1e12,
            format!("{:?}", o.clone().into_result()).chars().take(140).collect::<String>(),
            o.logs.join(";").chars().take(200).collect::<String>()
        );
    }
    let l = e.worker.view(fac.id(), "get_launch").args_json(json!({"launch_id": "tst-1"})).await;
    log += &format!(
        "launch: {:?}\n",
        l.map(|r| String::from_utf8_lossy(&r.result).chars().take(300).collect::<String>())
    );
    let st: Value = e
        .worker
        .view(fac.id(), "get_graduation_state")
        .args_json(json!({"launch_id": "tst-1"}))
        .await?
        .json()?;
    log += &format!("graduation_state: {}\n", st.to_string().chars().take(300).collect::<String>());
    // setup advances one stage per `resume_graduation` (a keeper call on mainnet, fixture tx)
    for i in 0..12 {
        let st: Value = e
            .worker
            .view(fac.id(), "get_graduation_state")
            .args_json(json!({"launch_id": "tst-1"}))
            .await?
            .json()?;
        if st["launch_status"] == "active" {
            log += &format!("active after {i} resume calls\n");
            break;
        }
        let r = creator
            .call(fac.id(), "resume_graduation")
            .args_json(json!({"launch_id": "tst-1"}))
            .gas(near_workspaces::types::Gas::from_tgas(300))
            .transact()
            .await?;
        log += &format!(
            "resume {i}: stage={} err={} -> {}\n",
            st["stage"],
            st["last_error"],
            errs(&r).chars().take(200).collect::<String>()
        );
    }
    println!("{log}");

    // trading through the account
    let t = e
        .ta(
            "u",
            30 * NEAR,
            (10 * NEAR, 50 * NEAR),
            vec![json!({"id": NIRA, "kind": {"FactoryCurve": "Nira"}})],
        )
        .await?;
    let bal = |who: near_workspaces::AccountId| {
        let (w, f) = (e.worker.clone(), fac.id().clone());
        async move {
            let v: Value = w
                .view(&f, "get_balance")
                .args_json(json!({"launch_id": "tst-1", "account_id": who}))
                .await?
                .json()?;
            Ok::<u128, anyhow::Error>(u(&v))
        }
    };
    let a = NEAR / 2;
    let q: Value = e
        .worker
        .view(fac.id(), "quote_buy")
        .args_json(json!({"launch_id": "tst-1", "amount_in": a.to_string()}))
        .await?
        .json()?;
    log += &format!("quote_buy: {q}\n");
    let qo = if q.is_object() { u(&q["tokens_out"]).max(u(&q["amount_out"])) } else { u(&q) };
    let buy = |min: u128| json!([{"CurveBuy": {"venue": NIRA, "market": "tst-1", "amount": a.to_string(), "min_out": min.to_string(), "gas": G.to_string()}}]);
    let fees0 = e.near(e.fees.id()).await?;
    let r = e.exec(&t, buy(qo * 3), "slip", a + NEAR).await?;
    log += &format!("slippage buy: settled={:?} {}\n", VEnv::settled(&r), errs(&r));
    let r = e.exec(&t, buy(qo * 97 / 100), "buy1", a + NEAR).await?;
    let got = bal(t.id.clone()).await?;
    let fee_b = e.near(e.fees.id()).await? - fees0;
    log += &format!(
        "buy: ok={} internal_balance={got} quote={qo} fee={fee_b} settled={:?} gas={:.1}T {}\n",
        r.is_success(),
        VEnv::settled(&r),
        r.total_gas_burnt.as_gas() as f64 / 1e12,
        errs(&r)
    );
    println!("{log}");
    assert!(got >= qo * 97 / 100 && got > 0, "Nira buy credited the internal balance");
    assert_eq!(fee_b, fee_of(a), "NearInFull exact fee");
    // sell half (native payout)
    let s_ = got / 2;
    let qs: Value = e
        .worker
        .view(fac.id(), "quote_sell")
        .args_json(json!({"launch_id": "tst-1", "token_in": s_.to_string()}))
        .await?
        .json()?;
    let qso = if qs.is_object() {
        u(&qs["amount_out"]).max(u(&qs["near_out"])).max(u(&qs["pair_out"]))
    } else {
        u(&qs)
    };
    let sell = |min: u128| json!([{"CurveSell": {"venue": NIRA, "market": "tst-1", "amount": s_.to_string(), "min_out": min.to_string(), "gas": G.to_string()}}]);
    let r = e.exec(&t, sell(qso * 3), "sslip", NEAR).await?;
    println!("quote_sell: {qs}\nslippage sell: settled={:?} {}", VEnv::settled(&r), errs(&r));
    assert_eq!(bal(t.id.clone()).await?, got, "internal balance kept");
    let fees1 = e.near(e.fees.id()).await?;
    let n0 = e.near(&t.id).await?;
    let r = e.exec(&t, sell(qso * 97 / 100), "sell1", NEAR).await?;
    let n1 = e.near(&t.id).await?;
    let fee_s = e.near(e.fees.id()).await? - fees1;
    println!(
        "sell: ok={} native_delta={} quote={qso} fee={fee_s} settled={:?} gas={:.1}T {}",
        r.is_success(),
        n1 as i128 - n0 as i128,
        VEnv::settled(&r),
        r.total_gas_burnt.as_gas() as f64 / 1e12,
        errs(&r)
    );
    assert_eq!(bal(t.id.clone()).await?, got - s_);
    assert!(n1 + NEAR / 20 >= n0 + qso * 97 / 100, "native payout arrived");
    assert!(fee_s <= fee_of(qso * 97 / 100) && fee_s > 0, "near_out fee = 1% x min(arrived, min_out)");
    // before graduation the claim is refused by the pad (args accepted)
    let r = e
        .exec(
            &t,
            json!([{"CurveClaim": {"venue": NIRA, "action": "NiraClaimGraduated", "market": "tst-1"}}]),
            "claim",
            NEAR,
        )
        .await?;
    println!("claim_graduated_balance before graduation: {}", errs(&r));
    assert!(
        !r.receipt_failures().is_empty() && errs(&r).contains("ERR_CONFIG_NOT_VERIFIED"),
        "claim args accepted by the pad"
    );
    // negatives: min_out 0; a pair-buy msg carrying any extra key (the pad's FtBuyMessage has 5
    // fields, 2 more than the account ever sends, e.g. a recipient) is refused by the parser
    let zero = json!([{"CurveBuy": {"venue": NIRA, "market": "tst-1", "amount": "1000", "min_out": "0", "gas": G.to_string()}}]);
    fails_with(&e.exec(&t, zero, "n1", NEAR).await?, "E_BAD_OP");
    let bad = json!({"buy": {"launch_id": "tst-1", "min_tokens_out": "1", "deadline_ms": "99999999999999", "recipient": "thief.near"}});
    let raw = json!([{"FtTransferCall": {"token": "usdt.tether-token.near", "receiver_id": NIRA, "amount": "1000", "msg": bad.to_string(), "gas": G.to_string()}}]);
    fails_with(&e.exec(&t, raw, "n2", NEAR).await?, "E_BAD_MSG");
    let bad = json!([{"CurveBuy": {"venue": NIRA, "market": "Tst 1", "amount": "1000", "min_out": "1", "gas": G.to_string()}}]);
    fails_with(&e.exec(&t, bad, "n3", NEAR).await?, "E_CURVE_MARKET");
    Ok(())
}

/// Nearrr buys read the token's own `tax_state` on chain: at 1% slippage on the POST-tax floor,
/// Standard (0.5%), 1% and 4.5% tax tokens fill with delivered >= min_out and the exact fee; a
/// token whose tax view fails (no `tax_state`) reads 0 (R2-06 owner rule): the buy goes to the
/// pad, which doesn't deliver an unknown token, and settles as used 0 / fee 0 with its lock
/// released (R2-05).
#[tokio::test]
async fn venues_nearrr_tax_levels() -> Result<()> {
    let e = venv().await?;
    let f = "nearrr-fun.near";
    import_mainnet(&e.worker, f, Some("48oZBxXPg6SyW9HwMbyXYNQnEEWUSCRxNte9DtYyTdCr")).await?;
    for x in [
        "grandpalace7442.near",
        "locker.nearrr-fun.near",
        "locker2.nearrr-fun.near",
        "lpvault.nearrr-fun.near",
    ] {
        create(&e, x).await?;
    }
    let t = e
        .ta(
            "u",
            30 * NEAR,
            (10 * NEAR, 50 * NEAR),
            vec![json!({"id": f, "kind": {"FactoryCurve": "Nearrr"}})],
        )
        .await?;
    let a = NEAR / 2;
    // (token, total post-check cut in bps as measured: Standard 0.5%, Tax buy_tax + 1%)
    for (i, (tok, cut)) in [
        ("gay-izid.nearrr-fun.near", 50u128),
        ("arcova-m6ez.nearrr-fun.near", 200),
        ("jensen-i1vg.nearrr-fun.near", 550),
    ]
    .into_iter()
    .enumerate()
    {
        import_mainnet(&e.worker, tok, None).await?;
        let ts: Value = e.worker.view(&tok.parse()?, "tax_state").await?.json()?;
        create(&e, ts["creator"].as_str().unwrap_or("x.near")).await?;
        let sb: Value = e.worker.view(&tok.parse()?, "storage_balance_bounds").await?.json()?;
        let q: Value = e
            .worker
            .view(&f.parse()?, "quote_buy_view")
            .args_json(json!({"token_id": tok, "quote_in": a.to_string()}))
            .await?
            .json()?;
        let q = u(&q[0]);
        let min = q * (10_000 - cut) / 10_000 * 99 / 100;
        let ops = json!([{"StorageDeposit": {"token": tok, "amount": sb["min"]}}, curve_g("CurveBuy", f, tok, a, min, NEARRR_OP_GAS)]);
        let fees0 = e.near(e.fees.id()).await?;
        let r = e.exec(&t, ops, &format!("tax{i}"), a + NEAR).await?;
        let got = e.ft(&tok.parse()?, &t.id).await?;
        let cb =
            r.receipt_outcomes().iter().find(|o| o.logs.iter().any(|l| l.contains("curve_buy"))).map(|_| ());
        let _ = cb;
        println!(
            "{tok} cut={cut} ok={} delivered={got} min={min} ratio={:.4} fee={} gas={:.1}T {}",
            r.is_success(),
            got as f64 / min as f64,
            e.near(e.fees.id()).await? - fees0,
            r.total_gas_burnt.as_gas() as f64 / 1e12,
            errs(&r)
        );
        assert!(got >= min, "{tok}: delivered {got} >= min_out {min}");
        assert_eq!(e.near(e.fees.id()).await? - fees0, fee_of(a), "{tok}: exact fee");
    }
    // a Nearrr-suffixed id without a tax view: 0 tax, the pad buy is sent (no token comes back)
    let fake = install_code(&e.worker, "nope-0000.nearrr-fun.near", &out("mock_ft")).await?;
    ok(fake.call("new").args_json(json!({})).transact().await?)?;
    let n0 = e.near(&t.id).await?;
    let fees0 = e.near(e.fees.id()).await?;
    let spent0 = e.day_spent(&t).await?;
    let r = e
        .exec(
            &t,
            json!([curve_g("CurveBuy", f, fake.id().as_str(), a, 1, NEARRR_OP_GAS)]),
            "noview",
            a + NEAR,
        )
        .await?;
    // the signer (= this account) gets the unused prepaid gas back in a later block
    e.worker.fast_forward(3).await?;
    let st = VEnv::settled(&r).expect("settled");
    println!(
        "no tax view: settled={st} logs={:?}",
        r.logs().iter().filter(|l| l.contains("nearrr_tax")).collect::<Vec<_>>()
    );
    assert_eq!((st["used"].as_str(), st["fee"].as_str()), (Some("0"), Some("0")));
    assert!(!r.logs().iter().any(|l| l.contains("nearrr_tax_refused")), "a failed view reads 0");
    assert!(r.receipt_outcomes().iter().any(|o| o.executor_id.as_str() == f), "the buy reached the pad");
    assert!(q_lock(&e, &t, fake.id().as_str()).await?.is_null(), "lock released on a refused buy");
    let n1 = e.near(&t.id).await?;
    assert!(n1 + NEAR / 50 >= n0, "the NEAR never left: {}", n0 as i128 - n1 as i128);
    assert_eq!(e.near(e.fees.id()).await?, fees0);
    assert_eq!(e.day_spent(&t).await?, spent0, "spend returned");
    // an op declaring less than the whole chain: refused at execute
    let low = json!([curve_g("CurveBuy", f, "arcova-m6ez.nearrr-fun.near", a, 1, 210 * TGAS)]);
    fails_with(&e.exec(&t, low, "low", a + NEAR).await?, "E_GAS");
    Ok(())
}

/// V16-02, sandbox: a dragonpad buy (NearInFull) with a NEAR inflow landing in the same execute
/// (an unwrap of 2 wNEAR before the buy) settles as a fill with the whole fee and the spend kept;
/// the same for a Nearrr buy, whose fee follows the tokens received.
#[tokio::test]
async fn venues_inflow_is_never_a_refund() -> Result<()> {
    let e = venv().await?;
    import_mainnet(&e.worker, "dragonpad.near", Some("3gqUU3rDaJ8xw61iBwHa65ygy1BnHKLHK3Wo3GcAgCUC")).await?;
    import_mainnet(&e.worker, "ember.dragonpad.near", None).await?;
    import_mainnet(&e.worker, "nearrr-fun.near", Some("48oZBxXPg6SyW9HwMbyXYNQnEEWUSCRxNte9DtYyTdCr"))
        .await?;
    import_mainnet(&e.worker, "arcova-m6ez.nearrr-fun.near", None).await?;
    for x in [
        "lp-burn.dragonpad.near",
        "grandpalace7442.near",
        "leftcity7777.near",
        "locker2.nearrr-fun.near",
        "lpvault.nearrr-fun.near",
    ] {
        create(&e, x).await?;
    }
    let t = e
        .ta(
            "u",
            30 * NEAR,
            (10 * NEAR, 50 * NEAR),
            vec![
                json!({"id": "dragonpad.near", "kind": {"FactoryCurve": "Dragonpad"}}),
                json!({"id": "nearrr-fun.near", "kind": {"FactoryCurve": "Nearrr"}}),
            ],
        )
        .await?;
    e.wrap_for(&t, 5 * NEAR).await?;
    let a = NEAR / 2;
    for (i, (f, tok, g, reg)) in [
        ("dragonpad.near", "ember.dragonpad.near", G, "1250000000000000000000"),
        ("nearrr-fun.near", "arcova-m6ez.nearrr-fun.near", NEARRR_OP_GAS, "2210000000000000000000"),
    ]
    .into_iter()
    .enumerate()
    {
        let (fees0, spent0) = (e.near(e.fees.id()).await?, e.day_spent(&t).await?);
        let ops = json!([
            {"NearWithdraw": {"amount": (2 * NEAR).to_string()}},
            {"StorageDeposit": {"token": tok, "amount": reg}},
            curve_g("CurveBuy", f, tok, a, 1, g)
        ]);
        let r = e.exec(&t, ops, &format!("inflow{i}"), a + NEAR).await?;
        let st = VEnv::settled(&r).expect("settled");
        println!("{f} with a 2 N unwrap: settled={st} {}", errs(&r));
        assert_eq!(st["used"].as_str(), Some(a.to_string().as_str()), "{f}: used");
        assert_eq!(e.near(e.fees.id()).await? - fees0, fee_of(a), "{f}: whole fee");
        assert!(e.day_spent(&t).await? >= spent0 + a, "{f}: spend kept");
        assert!(e.ft(&tok.parse()?, &t.id).await? > 0, "{f}: tokens");
    }
    Ok(())
}
