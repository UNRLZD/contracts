//! v1.6 Kelytra (`exchange.kelytradevs.near`, internal balances) with the REAL mainnet exchange
//! wasm (4jqrRK3f…) and its launch-token global code (GnQgLK9T…), both fetched read-only via
//! view_code and pinned by hash. The sandbox exchange is initialised exactly as mainnet was
//! (`new{owner, treasury}` → `admit_token(wrap, quote)` → `configure_curve_quote` →
//! `set_creation_fee` → `launch_curve_token_with_metadata`, txs 217401665…217782564).
mod venues_common;
use anyhow::Result;
use integration_tests::*;
use near_workspaces::types::{Gas, NearToken};
use near_workspaces::{Account, AccountId, Contract};
use serde_json::{json, Value};
use venues_common::*;

const EX: &str = "exchange.kelytradevs.near";
const EX_HASH: &str = "4jqrRK3fLRFuTyxruNFe4teQSGtahTdx3jo1GSSGTaos";
const TOKEN_HASH: &str = "GnQgLK9T3ryRJyqAav8hztcSuBBwDhnZosWSezCZ75vF";
const VQ: &str = "862166287209043987756113807";

pub struct Kel {
    pub ex: Contract,
    pub admin: Account,
    pub t0: AccountId,
}

/// A top-level mainnet-named account with a full-access key (state patch).
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

fn kel_dex() -> Value {
    json!({"id": EX, "kind": "Kelytra"})
}

/// Mainnet-identical exchange + one launch (t0) on the sandbox.
pub async fn kelytra(e: &VEnv) -> Result<Kel> {
    let token_code = pinned("t0.exchange.kelytradevs.near", Some(TOKEN_HASH)).await?;
    let deployer =
        sub(&e.root, "gdeploy", 50 * NEAR).await?.deploy(&out("global_deployer")).await?.into_result()?;
    ok(deployer.call("deploy").args_borsh(token_code).gas(Gas::from_tgas(300)).transact().await?)?;
    let ex = install_code(&e.worker, EX, &pinned(EX, Some(EX_HASH)).await?).await?;
    // the exchange hardcodes its developer wallet ("developer wallet only")
    let admin = named(e, "kelytradevs.near", 100).await?;
    // as on mainnet, the exchange holds a wNEAR storage registration
    ok(admin
        .call(e.wrap.id(), "storage_deposit")
        .args_json(json!({"account_id": EX, "registration_only": true}))
        .deposit(NearToken::from_yoctonear(STORAGE))
        .transact()
        .await?)?;
    ok(ex
        .call("new")
        .args_json(json!({"owner": admin.id(), "treasury": admin.id()}))
        .gas(Gas::from_tgas(80))
        .transact()
        .await?)?;
    for (m, args, dep) in [
        ("admit_token", json!({"token_id": e.wrap.id(), "decimals": 24, "quote": true}), NEAR / 100),
        ("configure_curve_quote", json!({"quote_id": e.wrap.id(), "virtual_quote": VQ}), NEAR / 100),
        ("set_creation_fee", json!({"amount": NEAR.to_string()}), 1),
    ] {
        let r = admin
            .call(ex.id(), m)
            .args_json(args)
            .deposit(NearToken::from_yoctonear(dep))
            .gas(Gas::from_tgas(40))
            .transact()
            .await?;
        let _ = okr(r).map_err(|x| anyhow::anyhow!("{m}: {x}"))?;
    }
    let dl = e.worker.view_block().await?.timestamp() + 600_000_000_000;
    let r = admin
        .call(ex.id(), "launch_curve_token_with_metadata")
        .args_json(json!({"name": "Kelytra Test", "symbol": "KTEST", "quote_id": e.wrap.id(),
            "expected_virtual_quote": VQ, "tax": {"extra_bps": 50, "destination": "developer"},
            "expected_creation_fee": NEAR.to_string(),
            "project": {"image": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=",
                "description": "sandbox", "website": null, "x": null, "telegram": null},
            "deadline": dl.to_string()}))
        .deposit(NearToken::from_yoctonear(1_414_970_000_000_000_000_000_000))
        .gas(Gas::from_tgas(300))
        .transact()
        .await?;
    let _ = okr(r).map_err(|x| anyhow::anyhow!("launch: {x}"))?;
    Ok(Kel { ex, admin, t0: format!("t0.{EX}").parse()? })
}

async fn bal(e: &VEnv, k: &Kel, tok: &AccountId, who: &AccountId) -> Result<u128> {
    let v: Value = e
        .worker
        .view(k.ex.id(), "get_balance")
        .args_json(json!({"account_id": who, "token_id": tok}))
        .await?
        .json()?;
    Ok(v["available"].as_str().and_then(|s| s.parse().ok()).unwrap_or(0))
}

/// Probe: plain account deposit / register / swap_curve / withdraw, measured gas per receipt.
#[tokio::test]
#[ignore = "measurement probe: cargo test --test venues_kelytra kelytra_probe -- --ignored --nocapture"]
async fn kelytra_probe() -> Result<()> {
    let e = venv().await?;
    let k = kelytra(&e).await?;
    let u = sub(&e.root, "trader", 50 * NEAR).await?;
    let launch: Value =
        e.worker.view(k.ex.id(), "get_launch").args_json(json!({"launch_id": "0"})).await?.json()?;
    println!("launch: {launch}");
    for tok in [e.wrap.id().clone(), k.t0.clone()] {
        let r = u
            .call(k.ex.id(), "register_balance")
            .args_json(json!({"token_id": tok, "account_id": u.id()}))
            .deposit(NearToken::from_yoctonear(NEAR / 50))
            .gas(Gas::from_tgas(100))
            .transact()
            .await?;
        println!("register {tok}: ok={} {:?}", r.is_success(), gas_by_receipt(&r));
    }
    ok(u.call(e.wrap.id(), "near_deposit")
        .args_json(json!({}))
        .deposit(NearToken::from_near(10))
        .transact()
        .await?)?;
    ok(u.call(e.wrap.id(), "storage_deposit")
        .args_json(json!({}))
        .deposit(NearToken::from_yoctonear(STORAGE))
        .transact()
        .await?)
    .ok();
    let r = u
        .call(e.wrap.id(), "ft_transfer_call")
        .args_json(json!({"receiver_id": EX, "amount": NEAR.to_string(), "msg": "deposit"}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(150))
        .transact()
        .await?;
    println!(
        "deposit: ok={} ret={:?} {:?} {:?}",
        r.is_success(),
        r.clone().json::<String>().ok(),
        gas_by_receipt(&r),
        r.clone()
            .into_result()
            .err()
            .map(|x| format!("{x:?}"))
            .map(|s| s[s.len().saturating_sub(400)..].to_string())
    );
    println!("bal wrap {}", bal(&e, &k, e.wrap.id(), u.id()).await?);
    let q: Value = e
        .worker
        .view(k.ex.id(), "quote_curve_swap")
        .args_json(json!({"launch_id": "0", "buy": true, "max_input": NEAR.to_string()}))
        .await?
        .json()?;
    println!("quote {q}");
    let dl = e.worker.view_block().await?.timestamp() + 600_000_000_000;
    for g in [30u64, 60, 100, 150] {
        let r = u.call(k.ex.id(), "swap_curve").args_json(json!({"launch_id": "0", "buy": true, "max_input": (NEAR/10).to_string(), "min_out": "1", "deadline": dl.to_string()}))
            .deposit(NearToken::from_yoctonear(1)).gas(Gas::from_tgas(g)).transact().await?;
        println!(
            "swap_curve buy gas {g}: ok={} ret={:?} burnt={:.1} {:?}",
            r.is_success(),
            r.clone().json::<Value>().ok(),
            r.total_gas_burnt.as_gas() as f64 / 1e12,
            gas_by_receipt(&r)
        );
    }
    let tb = bal(&e, &k, &k.t0, u.id()).await?;
    println!("bal t0 {tb}");
    for g in [30u64, 65, 100] {
        let r = u
            .call(k.ex.id(), "withdraw")
            .args_json(json!({"token_id": k.t0, "amount": (tb/10).to_string()}))
            .deposit(NearToken::from_yoctonear(1))
            .gas(Gas::from_tgas(g))
            .transact()
            .await?;
        println!(
            "withdraw t0 gas {g}: ok={} burnt={:.1} {:?} {:?}",
            r.is_success(),
            r.total_gas_burnt.as_gas() as f64 / 1e12,
            gas_by_receipt(&r),
            r.receipt_failures().first().map(|f| {
                let s = format!("{f:?}");
                s[s.find("status").unwrap_or(0)..].chars().take(300).collect::<String>()
            })
        );
    }
    println!("ft t0 {}", e.ft(&k.t0, u.id()).await.unwrap_or(0));
    let r = u.call(k.ex.id(), "swap_curve").args_json(json!({"launch_id": "0", "buy": false, "max_input": (tb/2).to_string(), "min_out": "1", "deadline": dl.to_string()}))
        .deposit(NearToken::from_yoctonear(1)).gas(Gas::from_tgas(100)).transact().await?;
    println!(
        "swap_curve sell: ok={} ret={:?} burnt={:.1}",
        r.is_success(),
        r.clone().json::<Value>().ok(),
        r.total_gas_burnt.as_gas() as f64 / 1e12
    );
    // slippage fail
    let r = u.call(k.ex.id(), "swap_curve").args_json(json!({"launch_id": "0", "buy": true, "max_input": (NEAR/10).to_string(), "min_out": "999999999999999999", "deadline": dl.to_string()}))
        .deposit(NearToken::from_yoctonear(1)).gas(Gas::from_tgas(100)).transact().await?;
    println!(
        "swap_curve slippage: ok={} {:?}",
        r.is_success(),
        r.clone().into_result().err().map(|x| format!("{x:?}")).map(|s| s[..s.len().min(300)].to_string())
    );
    // deposit from an unregistered account
    let v = sub(&e.root, "unreg", 20 * NEAR).await?;
    ok(v.call(e.wrap.id(), "near_deposit")
        .args_json(json!({}))
        .deposit(NearToken::from_near(2))
        .transact()
        .await?)?;
    let r = v
        .call(e.wrap.id(), "ft_transfer_call")
        .args_json(json!({"receiver_id": EX, "amount": NEAR.to_string(), "msg": "deposit"}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(150))
        .transact()
        .await?;
    println!(
        "unregistered deposit: ok={} ret={:?} wnear left {}",
        r.is_success(),
        r.clone().json::<String>().ok(),
        e.ft(e.wrap.id(), v.id()).await?
    );
    Ok(())
}

// ---------------- trading account (v1.6) against the real exchange ----------------

const FEE_BPS_T: u128 = 100;
fn bps(x: u128) -> u128 {
    x / 10_000 * FEE_BPS_T + x % 10_000 * FEE_BPS_T / 10_000
}

async fn quote(e: &VEnv, buy: bool, amount: u128) -> Result<Value> {
    Ok(e.worker
        .view(&EX.parse()?, "quote_curve_swap")
        .args_json(json!({"launch_id": "0", "buy": buy, "max_input": amount.to_string()}))
        .await?
        .json()?)
}

fn u(v: &Value) -> u128 {
    v.as_str().and_then(|s| s.parse().ok()).unwrap_or(0)
}

fn trade(buy: bool, amount: u128, min_out: u128) -> Value {
    trade_s(buy, amount, min_out, false)
}

/// `setup` = a first trade (registrations inside the same execute).
fn trade_s(buy: bool, amount: u128, min_out: u128, setup: bool) -> Value {
    let g = if setup { 230 } else { 200 };
    let body = json!({"venue": EX, "market": "0", "amount": amount.to_string(), "min_out": min_out.to_string(),
        "gas": (g * TGAS).to_string(), "setup": setup});
    if buy {
        json!({"CurveBuy": body})
    } else {
        json!({"CurveSell": body})
    }
}

fn register(tok: &AccountId) -> Value {
    json!({"CurveClaim": {"venue": EX, "action": "KelytraRegister", "token": tok}})
}

fn events(r: &near_workspaces::result::ExecutionFinalResult, name: &str) -> Vec<Value> {
    r.logs()
        .iter()
        .filter_map(|l| l.strip_prefix("EVENT_JSON:"))
        .filter_map(|s| serde_json::from_str::<Value>(s).ok())
        .filter(|v| v["event"] == name)
        .map(|v| v["data"].clone())
        .collect()
}

async fn t0_storage(e: &VEnv, k: &Kel) -> Result<u128> {
    let b: Value = e.worker.view(&k.t0, "storage_balance_bounds").await?.json()?;
    Ok(u(&b["min"]))
}

async fn registered(e: &VEnv, tok: &AccountId, who: &AccountId) -> Result<bool> {
    let v: Value = e
        .worker
        .view(&EX.parse()?, "get_balance")
        .args_json(json!({"account_id": who, "token_id": tok}))
        .await?
        .json()?;
    Ok(!v.is_null())
}

/// FRESH account holding NEAR only (nothing registered, no wNEAR): the first buy is ONE execute
/// with ONE op (`setup`: storage + both registrations + wrap + deposit + swap + withdraw), the
/// sell is one execute, a second buy (no setup) is one execute; fee exact on each; gas < 300 TGas.
#[tokio::test]
async fn kelytra_fresh_account_one_click() -> Result<()> {
    let e = venv().await?;
    let k = kelytra(&e).await?;
    let t = e.ta("kta", 20 * NEAR, (5 * NEAR, 20 * NEAR), vec![kel_dex()]).await?;
    assert_eq!(e.ft(e.wrap.id(), &t.id).await?, 0, "no wNEAR");
    assert!(!registered(&e, e.wrap.id(), &t.id).await? && !registered(&e, &k.t0, &t.id).await?);
    let amount = NEAR;
    let q = quote(&e, true, amount).await?;
    let fees0 = e.near(e.fees.id()).await?;
    let r = e
        .exec(&t, json!([trade_s(true, amount, u(&q["amount_out"]) * 99 / 100, true)]), "kb1", 2 * NEAR)
        .await?;
    println!("setup buy burnt {:.1} TGas", r.total_gas_burnt.as_gas() as f64 / 1e12);
    let r = okr(r)?;
    let got = e.ft(&k.t0, &t.id).await?;
    assert_eq!(got, u(&q["amount_out"]), "delivered exactly the quoted output");
    assert_eq!(e.near(e.fees.id()).await? - fees0, bps(amount), "fee = 1% of the NEAR input, exact");
    assert_eq!(u(&VEnv::settled(&r).expect("settled")["fee"]), bps(amount));
    assert!(events(&r, "kelytra_held").is_empty());
    assert!(registered(&e, e.wrap.id(), &t.id).await? && registered(&e, &k.t0, &t.id).await?);
    assert_eq!(bal(&e, &k, &k.t0, &t.id).await?, 0, "nothing left inside");
    assert_eq!(bal(&e, &k, e.wrap.id(), &t.id).await?, 0);
    assert_eq!(e.ft(e.wrap.id(), &t.id).await?, 0, "all wrapped NEAR went in");
    // sell half back: one execute, wNEAR out
    let sell = got / 2;
    let qs = quote(&e, false, sell).await?;
    let fees1 = e.near(e.fees.id()).await?;
    let min_s = u(&qs["amount_out"]) * 99 / 100;
    let r = okr(e.exec(&t, json!([trade(false, sell, min_s)]), "ks1", NEAR).await?)?;
    let out = e.ft(e.wrap.id(), &t.id).await?;
    assert_eq!(out, u(&qs["amount_out"]), "wNEAR delivered = quoted");
    // AUDIT-K1: the delivered amount is the exchange's report: the fee never exceeds the one
    // reserved on the min_out bound
    assert_eq!(e.near(e.fees.id()).await? - fees1, bps(out).min(bps(min_s)), "fee = 1% of min(out, min_out)");
    assert_eq!(e.ft(&k.t0, &t.id).await?, got - sell);
    assert!(events(&r, "kelytra_held").is_empty());
    // a second buy needs no setup
    let q2 = quote(&e, true, NEAR / 2).await?;
    let fees2 = e.near(e.fees.id()).await?;
    ok(e.exec(&t, json!([trade(true, NEAR / 2, u(&q2["amount_out"]) * 99 / 100)]), "kb2", NEAR).await?)?;
    assert_eq!(e.ft(&k.t0, &t.id).await?, got - sell + u(&q2["amount_out"]));
    assert_eq!(e.near(e.fees.id()).await? - fees2, bps(NEAR / 2));
    assert_eq!(e.ft(e.wrap.id(), &t.id).await?, out, "the buy took native NEAR, not the wNEAR");
    Ok(())
}

/// Slippage on a fresh account's setup buy: the deposit is withdrawn back in the same execute
/// (as wNEAR); no fee, trade spend returned, nothing left inside.
#[tokio::test]
async fn kelytra_slippage_refunds() -> Result<()> {
    let e = venv().await?;
    let k = kelytra(&e).await?;
    let t = e.ta("kta", 20 * NEAR, (5 * NEAR, 20 * NEAR), vec![kel_dex()]).await?;
    let fees0 = e.near(e.fees.id()).await?;
    let day0 = e.day_spent(&t).await?;
    let q = quote(&e, true, NEAR).await?;
    let r =
        e.exec(&t, json!([trade_s(true, NEAR, u(&q["amount_out"]) * 2, true)]), "kslip", 2 * NEAR).await?;
    assert!(r.is_success());
    assert_eq!(e.ft(e.wrap.id(), &t.id).await?, NEAR, "the NEAR is back (wrapped)");
    assert_eq!(bal(&e, &k, e.wrap.id(), &t.id).await?, 0, "nothing stranded inside");
    assert_eq!(e.ft(&k.t0, &t.id).await?, 0);
    assert_eq!(e.near(e.fees.id()).await?, fees0, "no fee");
    assert_eq!(u(&VEnv::settled(&r).expect("settled")["used"]), 0);
    // only the registrations + storage and gas stay counted, not the trade input + max fee
    let day1 = e.day_spent(&t).await?;
    assert!(day1 - day0 < NEAR / 10, "spend returned: {day0} -> {day1}");
    Ok(())
}

/// Unregistered and no setup: the exchange refunds the deposit (used 0) -> clean failed swap
/// (the NEAR stays wrapped). A setup buy then works.
#[tokio::test]
async fn kelytra_unregistered_then_setup() -> Result<()> {
    let e = venv().await?;
    let k = kelytra(&e).await?;
    let t = e.ta("kta", 20 * NEAR, (5 * NEAR, 20 * NEAR), vec![kel_dex()]).await?;
    let fees0 = e.near(e.fees.id()).await?;
    let q = quote(&e, true, NEAR / 2).await?;
    let min_out = u(&q["amount_out"]) * 99 / 100;
    let r = e.exec(&t, json!([trade(true, NEAR / 2, min_out)]), "kun", NEAR).await?;
    assert!(r.is_success());
    assert_eq!(e.ft(e.wrap.id(), &t.id).await?, NEAR / 2, "deposit refunded (wrapped)");
    assert_eq!(e.near(e.fees.id()).await?, fees0, "no fee");
    assert_eq!(u(&VEnv::settled(&r).expect("settled")["used"]), 0);
    let q = quote(&e, true, NEAR / 2).await?;
    ok(e.exec(&t, json!([trade_s(true, NEAR / 2, u(&q["amount_out"]) * 99 / 100, true)]), "kreg", NEAR)
        .await?)?;
    assert_eq!(e.ft(&k.t0, &t.id).await?, u(&q["amount_out"]));
    assert_eq!(e.near(e.fees.id()).await? - fees0, bps(NEAR / 2));
    Ok(())
}

/// Output undelivered (exchange balances registered, but no storage on the launch token): the
/// swap happened, the output stays in this account's internal balance (kelytra_held), the fee on
/// the NEAR input is charged; CurveClaim KelytraWithdraw (after StorageDeposit) recovers it.
#[tokio::test]
async fn kelytra_output_held_then_claimed() -> Result<()> {
    let e = venv().await?;
    let k = kelytra(&e).await?;
    let t = e.ta("kta", 20 * NEAR, (5 * NEAR, 20 * NEAR), vec![kel_dex()]).await?;
    let st = t0_storage(&e, &k).await?;
    let fees0 = e.near(e.fees.id()).await?;
    let q = quote(&e, true, NEAR).await?;
    let ops =
        json!([register(e.wrap.id()), register(&k.t0), trade(true, NEAR, u(&q["amount_out"]) * 99 / 100)]);
    let r = e.exec(&t, ops, "kheld", 2 * NEAR).await?;
    assert!(r.is_success());
    let h = events(&r, "kelytra_held");
    assert_eq!(h.len(), 1, "{:?}", r.logs());
    assert_eq!(h[0]["reason"], "output_undelivered");
    let inside = bal(&e, &k, &k.t0, &t.id).await?;
    assert_eq!(inside, u(&q["amount_out"]));
    assert_eq!(e.near(e.fees.id()).await? - fees0, bps(NEAR));
    let ops = json!([{"StorageDeposit": {"token": k.t0, "amount": st.to_string()}},
        {"CurveClaim": {"venue": EX, "action": "KelytraWithdraw", "token": k.t0, "amount": inside.to_string()}}]);
    ok(e.exec(&t, ops, "kclaim", NEAR).await?)?;
    assert_eq!(e.ft(&k.t0, &t.id).await?, inside);
    assert_eq!(bal(&e, &k, &k.t0, &t.id).await?, 0);
    Ok(())
}

/// Negative: wrong venue (a Kelytra-shaped id not allowlisted), quote token, bad market, zero
/// min_out, recipient-free by construction.
#[tokio::test]
async fn kelytra_negative() -> Result<()> {
    let e = venv().await?;
    let t = e.ta("kta", 5 * NEAR, (2 * NEAR, 4 * NEAR), vec![kel_dex()]).await?;
    let bad = |v: Value| json!([{"CurveBuy": v}]);
    let base = json!({"venue": EX, "market": "0", "amount": NEAR.to_string(), "min_out": "1", "gas": (200 * TGAS).to_string()});
    let cases: Vec<(Value, &str)> = vec![
        (
            {
                let mut b = base.clone();
                b["venue"] = json!("exchange2.kelytradevs.near");
                b
            },
            "E_BAD_DEX",
        ),
        (
            {
                let mut b = base.clone();
                b["quote"] = json!("token.rhealab.near");
                b
            },
            "E_CURVE_QUOTE",
        ),
        (
            {
                let mut b = base.clone();
                b["market"] = json!("00");
                b
            },
            "E_CURVE_MARKET",
        ),
        (
            {
                let mut b = base.clone();
                b["market"] = json!(null);
                b
            },
            "E_CURVE_MARKET",
        ),
        (
            {
                let mut b = base.clone();
                b["min_out"] = json!("0");
                b
            },
            "E_BAD_OP",
        ),
        (
            {
                let mut b = base.clone();
                b["gas"] = json!((100 * TGAS).to_string());
                b
            },
            "E_GAS",
        ),
    ];
    // setup under-declares its larger budget
    let mut cases = cases;
    let mut b = base.clone();
    b["setup"] = json!(true);
    cases.push((b, "E_GAS"));
    for (i, (v, code)) in cases.into_iter().enumerate() {
        let r = e.exec(&t, bad(v), &format!("n{i}"), 2 * NEAR).await?;
        if std::env::var("KEL_DEBUG").is_ok() {
            let s = format!("{:?}", r.clone().into_result().err());
            println!("case {i}: {}", s.find("panicked").map_or("?".into(), |p| s[p..p + 60].to_string()));
        }
        fails_with(&r, code);
    }
    // an unknown field (e.g. a recipient) is refused by the op's deny_unknown_fields
    let mut b = base.clone();
    b["receiver_id"] = json!("thief.near");
    let r = e.exec(&t, bad(b), "nr", NEAR).await?;
    assert!(r.is_failure());
    Ok(())
}

#[tokio::test]
#[ignore = "probe: register_balance twice + get_balance of registered-empty"]
async fn kelytra_probe_register() -> Result<()> {
    let e = venv().await?;
    let k = kelytra(&e).await?;
    let u = sub(&e.root, "trader", 50 * NEAR).await?;
    let v: Value = e
        .worker
        .view(k.ex.id(), "get_balance")
        .args_json(json!({"account_id": u.id(), "token_id": e.wrap.id()}))
        .await?
        .json()?;
    println!("unregistered view: {v}");
    for i in 0..2 {
        let r = u
            .call(k.ex.id(), "register_balance")
            .args_json(json!({"token_id": e.wrap.id(), "account_id": u.id()}))
            .deposit(NearToken::from_yoctonear(NEAR / 50))
            .gas(Gas::from_tgas(10))
            .transact()
            .await?;
        let s = format!("{:?}", r.receipt_failures());
        println!(
            "register #{i}: ok={} ret={:?} near={} fail={}",
            r.is_success(),
            r.clone().json::<Value>().ok(),
            e.near(u.id()).await?,
            s.find("panicked").map_or(String::new(), |p| s[p..p + 80].to_string())
        );
        let v: Value = e
            .worker
            .view(k.ex.id(), "get_balance")
            .args_json(json!({"account_id": u.id(), "token_id": e.wrap.id()}))
            .await?
            .json()?;
        println!("  view: {v}");
    }
    Ok(())
}
