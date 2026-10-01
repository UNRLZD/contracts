//! v1.6 TokenCurve venues (curve inside the token) against the REAL mainnet wasm, pinned by hash,
//! with the token's REAL mainnet state imported (view_state at block ~217.95M, 2026-10-01, pinned in
//! tests/fixtures/venues/<id>.state.json so reruns are reproducible) or, where the live tokens are graduated/closed, a fresh token made
//! by the real code (`init` / the real factory's `create_token`).
//!
//! | pad | token (template hash) | buy | sell |
//! |---|---|---|---|
//! | Umbra v2 | si.umbrafun.near (7RtxE5da…), NEAR | `buy{min_out}` payable | `sell{amount, min_out}` 1 yocto, native payout |
//! | Umbra first-gen | ai.umbrafun.near (GY1UqaLH…), NVDAon | `Q.ft_transfer_call{T, {"action":"buy","min_out"}}` | `sell` pays Q by ft_transfer |
//! | RevShare | l0.revshare-launch.near (9gNvjBnK…) | `wrap.ft_transfer_call{T, {"buy":{min_tokens_out, deadline_ns}}}` | `sell{amount, min_quote_out, deadline_ns}` 1 yocto, wNEAR payout |
//! | nearmemefun | fresh `create_token` on nearmemefun.near (BXR7dvrg…) | `buy{min_tokens_out, deadline_sec}` payable | `sell{tokens_in, min_near_out, deadline_sec}` |
//! | token0 | fresh `init` of the 3psgWikm… template | `buy{max_token_amount, min_token_amount, receiver_id: self, referral_id: null}` payable, exact-out + refund | `sell{token_amount, min_near_output_amount, receiver_id: self}` deposit 0, returns NEAR |
//! | chipfi | c1.chipfi.near NEAR pair, c3.chipfi.near NVDAon pair (EqJ9ZeUm…) | `buy{min_out, for_account: null}` payable / `Q.ft_transfer_call{T, {"min_out"}}` | `sell{amount, min_out}` + `claim{}` one batch, deposit 0 |
//! | npad | npad.npad.near (8VmiuZ3L…) | `buy{min_tokens_out}` payable | `sell{amount, min_near_out}` 1 yocto |
//! | NearFun | ncat.nearfunio.near (7bPoEt3N…) | `buy{min_tokens_out}` payable | `sell{amount, min_near_out}` 1 yocto |
//!
//! Run: `cargo test --test venues_token -- --test-threads 4` (needs contracts/out-v or
//! NT_VENUES_WASM; mainnet RPC on the first run to fill tests/.cache).
mod venues_common;
use anyhow::{anyhow, Result};
use integration_tests::*;
use near_workspaces::result::ExecutionFinalResult;
use near_workspaces::types::{Gas, NearToken};
use near_workspaces::{AccountId, Contract};
use serde_json::{json, Value};
use venues_common::*;

const G: u64 = 100 * TGAS;
const NVDA: &str = "bnb-0xa9ee28c80f960b889dfbd1902055218cba016f75.omdep.near";

// ---------------- helpers ----------------

/// Mainnet state of `id` (all keys), pinned in tests/fixtures/venues/<id>.state.json (committed;
/// fetched from mainnet view_state only if missing, then commit it).
async fn mainnet_state(id: &str) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    use base64::Engine;
    let path = format!("{}/fixtures/venues/{id}.state.json", env!("CARGO_MANIFEST_DIR"));
    let v: Value = match std::fs::read(&path) {
        Ok(b) => serde_json::from_slice(&b)?,
        Err(_) => {
            let body = json!({"jsonrpc": "2.0", "id": 1, "method": "query", "params": {"request_type": "view_state",
                "finality": "final", "account_id": id, "prefix_base64": ""}});
            let v: Value = reqwest::Client::new()
                .post("https://free.rpc.fastnear.com")
                .json(&body)
                .send()
                .await?
                .json()
                .await?;
            let r = v.get("result").cloned().ok_or_else(|| anyhow!("view_state {id}: {v}"))?;
            std::fs::write(&path, serde_json::to_vec(&r)?)?;
            r
        }
    };
    let b64 = base64::engine::general_purpose::STANDARD;
    v["values"]
        .as_array()
        .ok_or_else(|| anyhow!("bad state"))?
        .iter()
        .map(|kv| {
            Ok((
                b64.decode(kv["key"].as_str().unwrap_or(""))?,
                b64.decode(kv["value"].as_str().unwrap_or(""))?,
            ))
        })
        .collect()
}

/// Creates `id` as a plain account (fee recipients / creators the pad pays) if missing.
async fn ensure(e: &VEnv, id: &str) -> Result<()> {
    let aid: AccountId = id.parse()?;
    if e.worker.view_account(&aid).await.is_err() {
        e.worker
            .patch(&aid)
            .account(near_workspaces::types::AccountDetailsPatch::default().balance(NearToken::from_near(1)))
            .transact()
            .await?;
    }
    Ok(())
}

/// A plain account at a mainnet id with a full-access key (to act as a pad's deployer/holder).
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

/// Every NEAR account id named in `bytes` (fee recipients, creators, …), created as plain accounts
/// so the pad's transfers land as on mainnet.
async fn ensure_named(e: &VEnv, bytes: &[u8], skip: &[&str]) -> Result<()> {
    let s = String::from_utf8_lossy(bytes).to_string();
    let mut seen = std::collections::BTreeSet::new();
    for w in s.split(|c: char| !(c.is_ascii_lowercase() || c.is_ascii_digit() || "._-".contains(c))) {
        let ok_id =
            (w.ends_with(".near") || w.ends_with(".tg")) && w.len() > 5 && w.parse::<AccountId>().is_ok();
        let hex = w.len() == 64 && w.bytes().all(|b| b.is_ascii_hexdigit());
        if (ok_id || hex) && !skip.contains(&w) {
            seen.insert(w.to_string());
        }
    }
    for id in seen {
        ensure(e, &id).await?;
    }
    Ok(())
}

/// Real code (pinned) + real mainnet state at the same id.
async fn import(e: &VEnv, id: &str, hash: &str) -> Result<Contract> {
    let code = pinned(id, Some(hash)).await?;
    let c = install_code(&e.worker, id, &code).await?;
    let st = mainnet_state(id).await?;
    let bytes: Vec<u8> = st.iter().flat_map(|(_, v)| v.clone()).collect();
    let mut p = e.worker.patch(c.id());
    let total: usize = st.iter().map(|(k, v)| k.len() + v.len() + 40).sum();
    p = p.account(
        near_workspaces::types::AccountDetailsPatch::default()
            .balance(NearToken::from_near(100_000))
            .storage_usage((code.len() + total + 1_000) as u64),
    );
    p = p.code(&code);
    for (k, v) in &st {
        p = p.state(k, v);
    }
    p.transact().await?;
    ensure_named(e, &bytes, &[id, "wrap.near"]).await?;
    Ok(c)
}

/// A mock NEP-141 at a mainnet id (e.g. NVDAon), minting `amounts`.
async fn mock_q(e: &VEnv, id: &str, amounts: &[(&AccountId, u128)]) -> Result<Contract> {
    let c = install_code(&e.worker, id, &out("mock_ft")).await?;
    ok(c.call("new").transact().await?)?;
    for (a, n) in amounts {
        ok(c.call("mint").args_json(json!({"account_id": a, "amount": n.to_string()})).transact().await?)?;
    }
    Ok(c)
}

fn trade(side: &str, venue: &str, amount: u128, min_out: u128, extra: Value) -> Value {
    let mut b = json!({"venue": venue, "amount": amount.to_string(), "min_out": min_out.to_string(), "gas": G.to_string()});
    if let (Some(m), Some(x)) = (b.as_object_mut(), extra.as_object()) {
        for (k, v) in x {
            m.insert(k.clone(), v.clone());
        }
    }
    json!({ side: b })
}

fn storage(token: &str, amount: u128) -> Value {
    json!({"StorageDeposit": {"token": token, "amount": amount.to_string()}})
}

fn u(v: &Value) -> u128 {
    v.as_str().and_then(|s| s.parse().ok()).or_else(|| v.as_u64().map(u128::from)).unwrap_or(0)
}

fn bps(x: u128) -> u128 {
    fee(x)
}

/// Upper bound of the execute tx's own gas refund (300 TGas prepaid x the sandbox gas price
/// 1e9): it is paid to the signer = the trading account and lands BEFORE on_curve_settled, so a
/// measured delta includes it (finding F1: a NearIn fee is under-charged by at most bps of it).
const GAS_REFUND_MAX: u128 = 300 * TGAS as u128 * 1_000_000_000;

/// NearIn fee: bps x (amount - measured refund), where the measured refund = real refund + the
/// tx's gas refund (<= GAS_REFUND_MAX).
fn assert_near_in_fee(fee_: u128, amount: u128, real_refund: u128) {
    let hi = bps(amount - real_refund);
    let lo = bps(amount.saturating_sub(real_refund + GAS_REFUND_MAX));
    assert!(fee_ <= hi && fee_ >= lo, "NearIn fee {fee_} not in [{lo}, {hi}]");
}

async fn view(e: &VEnv, id: &str, m: &str, args: Value) -> Result<Value> {
    let aid: AccountId = id.parse()?;
    Ok(e.worker.view(&aid, m).args_json(args).await?.json()?)
}

struct Snap {
    near: u128,
    fees: u128,
    tok: u128,
    spent: u128,
}

async fn snap(e: &VEnv, t: &Ta, tok: &str) -> Result<Snap> {
    let tid: AccountId = tok.parse()?;
    Ok(Snap {
        near: e.near(&t.id).await?,
        fees: e.near(e.fees.id()).await?,
        tok: e.ft(&tid, &t.id).await.unwrap_or(0),
        spent: e.day_spent(t).await?,
    })
}

fn settled(r: &ExecutionFinalResult) -> Value {
    VEnv::settled(r).unwrap_or(Value::Null)
}

/// chipfi: the live NEAR coins are retired (c1, c3: buys refused) or busy; a FRESH factory
/// (real chipfi.near code B32sfu9v…) with the real coin template (EqJ9ZeUm…) as global code,
/// `new` / `register_version` / `set_pair` / `create` exactly as on mainnet. Returns
/// (NEAR coin, NVDAon coin).
async fn chipfi_fresh(e: &VEnv) -> Result<(String, String)> {
    let coin = pinned("c1.chipfi.near", Some("EqJ9ZeUmrHrLtjCHJ4UVGtkYaGcgqVFGX1KhWQQ6qiFv")).await?;
    let gd =
        sub(&e.root, "gdeploy", 100 * NEAR).await?.deploy(&out("global_deployer")).await?.into_result()?;
    ok(gd.call("deploy").args_borsh(coin.clone()).gas(Gas::from_tgas(300)).transact().await?)?;
    let f = install_code(
        &e.worker,
        "chipfi.near",
        &pinned("chipfi.near", Some("B32sfu9v9ZtiGCz8TXKVXAxkeq4qMpiRAXjFCBZpb6Et")).await?,
    )
    .await?;
    let owner = keyed(e, "richgoat3540.near").await?;
    ok(f.call("new")
        .args_json(
            json!({"owner": owner.id(), "treasury": owner.id(), "launch_fee": "500000000000000000000000",
        "near_virtual_reserve": "1000000000000000000000000000"}),
        )
        .transact()
        .await?)?;
    let r = owner
        .call(f.id(), "register_version")
        .args_json(json!({"version": "0.2.0", "code_hash": code_hash(&coin)}))
        .transact()
        .await?;
    println!(
        "chipfi register_version: {:?}",
        r.clone().into_result().err().map(|x| format!("{x:?}").chars().take(200).collect::<String>())
    );
    ok(r)?;
    let _ =
        owner.call(f.id(), "set_current_version").args_json(json!({"version": "0.2.0"})).transact().await?;
    ok(owner.call(f.id(), "set_pair").args_json(json!({"key": "NVDAon", "asset": {"Token": {"account_id": NVDA, "symbol": "NVDAon", "decimals": 18}},
        "name": "NVIDIA (Ondo)", "virtual_reserve": "4998000000000000000", "enabled": true})).transact().await?)?;
    let mut ids = vec![];
    for (pair, dep, ib) in [
        (Value::Null, 2 * NEAR, json!("1000000000000000000000000")),
        (json!("NVDAon"), 1_012_500_000_000_000_000_000_000u128, Value::Null),
    ] {
        let r = owner
            .call(f.id(), "create")
            .args_json(json!({"params": {"name": "Sandbox", "symbol": "SBX", "icon": null, "description": "", "links": {"website": null, "x": null, "telegram": null},
                "pair": pair, "buy_tax_bps": 100, "sell_tax_bps": 100, "split": {"creator_bps": 0, "dividends_bps": 10000, "burn_bps": 0, "liquidity_bps": 0},
                "fee_wallet": null, "initial_buy": ib}}))
            .deposit(NearToken::from_yoctonear(dep))
            .gas(Gas::from_tgas(300))
            .transact()
            .await?;
        println!(
            "chipfi create: ok={} ret={:?} fails={:?}",
            r.is_success(),
            r.clone().json::<Value>().ok(),
            r.receipt_failures()
                .iter()
                .map(|f| format!("{:?}", (*f).clone().into_result().err())
                    .chars()
                    .take(250)
                    .collect::<String>())
                .collect::<Vec<_>>()
        );
        ok(r)?;
        let n = ids.len() + 1;
        ids.push(format!("c{n}.chipfi.near"));
    }
    Ok((ids[0].clone(), ids[1].clone()))
}

// ======================= Umbra =======================

/// Umbra v2, NEAR quote (si.umbrafun.near): buy, sell, slippage refund, fee exactness.
#[tokio::test]
async fn umbra_near_buy_sell() -> Result<()> {
    let e = venv().await?;
    let tok = "si.umbrafun.near";
    import(&e, tok, "7RtxE5daMenAJDnJHJGg6t3C53XmA8TmwFx8MTkWy6hd").await?;
    let t = e
        .ta(
            "u1",
            20 * NEAR,
            (10 * NEAR, 20 * NEAR),
            vec![json!({"id": "umbrafun.near", "kind": {"TokenCurve": "Umbra"}})],
        )
        .await?;
    let sb: Value = view(&e, tok, "storage_balance_bounds", json!({})).await?;
    let reg = u(&sb["min"]);
    // buy 1 N (register first: the output is an ft balance in the token)
    let s0 = snap(&e, &t, tok).await?;
    let r = e
        .exec(&t, json!([storage(tok, reg), trade("CurveBuy", tok, NEAR, 1, json!({}))]), "b1", 2 * NEAR)
        .await?;
    let st = settled(&r);
    println!("umbra buy: ok={} settled={st} failures={:?}", r.is_success(), r.receipt_failures().len());
    ok(r.clone())?;
    let s1 = snap(&e, &t, tok).await?;
    assert!(s1.tok > s0.tok, "tokens received");
    // NearIn, no refund on this pad: fee = 1% x (amount - measured delta)
    assert_near_in_fee(u(&st["fee"]), NEAR, 0);
    assert_eq!(s1.fees - s0.fees, u(&st["fee"]));
    assert_eq!(s1.spent - s0.spent, reg + NEAR + u(&st["fee"]), "spend = storage + input + fee charged");
    let got = s1.tok - s0.tok;

    // slippage: min_out above what 1 N can buy -> the buy panics, deposit back, no fee, spend back
    let s2 = snap(&e, &t, tok).await?;
    let r = e.exec(&t, json!([trade("CurveBuy", tok, NEAR, got * 10, json!({}))]), "b2", 2 * NEAR).await?;
    let st = settled(&r);
    assert_eq!(u(&st["used"]), 0, "{st}");
    assert_eq!(u(&st["fee"]), 0);
    let s3 = snap(&e, &t, tok).await?;
    assert_eq!(s3.tok, s2.tok);
    assert_eq!(s3.fees, s2.fees);
    assert_eq!(s3.spent, s2.spent, "spend returned");
    assert!(s2.near - s3.near < NEAR / 50, "deposit came back (only gas lost)");

    // sell half; min_out = a floor we know the curve pays (fee on min(arrived, min_out bound))
    let half = got / 2;
    let floor = NEAR / 3;
    let r = e.exec(&t, json!([trade("CurveSell", tok, half, floor, json!({}))]), "s1", 2 * NEAR).await?;
    let st = settled(&r);
    println!("umbra sell: settled={st}");
    ok(r.clone())?;
    let s4 = snap(&e, &t, tok).await?;
    assert_eq!(s3.tok - s4.tok, half);
    // arrived >= floor at callback time => fee = bps(floor) exactly (payout arrived first)
    assert_eq!(u(&st["fee"]), bps(floor), "payout must arrive before on_curve_settled");
    assert_eq!(s4.fees - s3.fees, bps(floor));

    // sell slippage: min_out way above -> panic, tokens kept, no fee
    let r =
        e.exec(&t, json!([trade("CurveSell", tok, half, 1_000 * NEAR, json!({}))]), "s2", 2 * NEAR).await?;
    let st = settled(&r);
    assert_eq!(u(&st["used"]), 0);
    assert_eq!(snap(&e, &t, tok).await?.tok, s4.tok);
    Ok(())
}

/// Umbra first-gen, NVDAon quote (ai.umbrafun.near): Q buy via ft_transfer_call (no fee, not the
/// NEAR leg), Q sell (Q payout, no fee), raw FtTransferCall parser negatives.
#[tokio::test]
async fn umbra_q_buy_sell() -> Result<()> {
    let e = venv().await?;
    let tok = "ai.umbrafun.near";
    import(&e, tok, "GY1UqaLHhXZCNpXAg4RCbGfhG1wocMvoEYTQSzJKC43z").await?;
    let t = e
        .ta(
            "u2",
            10 * NEAR,
            (10 * NEAR, 20 * NEAR),
            vec![json!({"id": "umbrafun.near", "kind": {"TokenCurve": "Umbra"}})],
        )
        .await?;
    let tid: AccountId = tok.parse()?;
    let q = mock_q(&e, NVDA, &[(&t.id, 10u128.pow(18)), (&tid, 5 * 10u128.pow(18))]).await?;
    let sb: Value = view(&e, tok, "storage_balance_bounds", json!({})).await?;
    let reg = u(&sb["min"]);
    let s0 = snap(&e, &t, tok).await?;
    let qin = 10u128.pow(17);
    let r = e
        .exec(
            &t,
            json!([storage(tok, reg), trade("CurveBuy", tok, qin, 1, json!({"quote": NVDA}))]),
            "qb1",
            NEAR,
        )
        .await?;
    let st = settled(&r);
    println!("umbra Q buy: settled={st}");
    ok(r.clone())?;
    let s1 = snap(&e, &t, tok).await?;
    assert!(s1.tok > s0.tok);
    assert_eq!(e.ft(q.id(), &t.id).await?, 10u128.pow(18) - qin);
    assert_eq!(u(&st["fee"]), 0, "no fee on a Q leg");
    assert_eq!(s1.fees, s0.fees);
    assert_eq!(s1.spent - s0.spent, reg, "Q input is not NEAR spend (only the storage deposit)");

    // Q sell: payout Q by ft_transfer, no fee
    let got = s1.tok - s0.tok;
    let r =
        e.exec(&t, json!([trade("CurveSell", tok, got / 2, 1, json!({"quote": NVDA}))]), "qs1", NEAR).await?;
    let st = settled(&r);
    println!("umbra Q sell: settled={st}");
    ok(r.clone())?;
    assert!(e.ft(q.id(), &t.id).await? > 10u128.pow(18) - qin, "Q paid out");
    assert_eq!(u(&st["fee"]), 0);

    // raw FtTransferCall to the token: the only accepted msg is {"action":"buy","min_out"}
    let raw = |msg: &str| {
        json!([{"FtTransferCall": {"token": NVDA, "receiver_id": tok, "amount": "1000", "msg": msg,
            "gas": G.to_string()}}])
    };
    let r =
        e.exec(&t, raw(r#"{"action":"buy","min_out":"1","receiver_id":"evil.near"}"#), "qr1", NEAR).await?;
    fails_with(&r, "E_BAD_MSG");
    let r = e.exec(&t, raw(r#"{"action":"buy","min_out":"0"}"#), "qr2", NEAR).await?;
    fails_with(&r, "E_MIN_OUT");
    let r = e.exec(&t, raw(r#"{"action":"sell","min_out":"1"}"#), "qr3", NEAR).await?;
    fails_with(&r, "E_BAD_MSG");
    let r = e.exec(&t, raw(r#"{"action":"buy","min_out":"1"}"#), "qr4", NEAR).await?;
    ok(r)?;
    Ok(())
}

/// Venue checks that need no pad state: wrong factory / deeper names, min_out 0, bad quote,
/// token0 max_out, market on a token pad.
#[tokio::test]
async fn token_curve_negatives() -> Result<()> {
    let e = venv().await?;
    let t = e
        .ta(
            "neg",
            5 * NEAR,
            (2 * NEAR, 4 * NEAR),
            vec![
                json!({"id": "umbrafun.near", "kind": {"TokenCurve": "Umbra"}}),
                json!({"id": "token0.near", "kind": {"TokenCurve": "Token0"}}),
                json!({"id": "npad.near", "kind": {"TokenCurve": "Npad"}}),
            ],
        )
        .await?;
    let cases: Vec<(Value, &str)> = vec![
        // not under an allowlisted factory
        (trade("CurveBuy", "si.umbrafun2.near", NEAR / 10, 1, json!({})), "E_BAD_DEX"),
        // two labels deep (could be created by a token)
        (trade("CurveBuy", "x.si.umbrafun.near", NEAR / 10, 1, json!({})), "E_BAD_DEX"),
        // the factory itself is not a venue
        (trade("CurveBuy", "umbrafun.near", NEAR / 10, 1, json!({})), "E_BAD_DEX"),
        (trade("CurveBuy", "si.umbrafun.near", NEAR / 10, 0, json!({})), "E_BAD_OP"),
        (trade("CurveSell", "si.umbrafun.near", 0, 1, json!({})), "E_BAD_OP"),
        // quote tokens only on Umbra / chipfi
        (trade("CurveBuy", "npad.npad.near", NEAR / 10, 1, json!({"quote": NVDA})), "E_CURVE_QUOTE"),
        // token0: max_out required and >= min_out; never on another pad
        (trade("CurveBuy", "sfv.token0.near", NEAR / 10, 10, json!({})), "E_BAD_OP"),
        (trade("CurveBuy", "sfv.token0.near", NEAR / 10, 10, json!({"max_out": "9"})), "E_BAD_OP"),
        (trade("CurveBuy", "si.umbrafun.near", NEAR / 10, 10, json!({"max_out": "20"})), "E_BAD_OP"),
        (trade("CurveSell", "sfv.token0.near", 10, 10, json!({"max_out": "20"})), "E_BAD_OP"),
        // a market id on a token pad
        (trade("CurveBuy", "si.umbrafun.near", NEAR / 10, 1, json!({"market": "x"})), "E_BAD_OP"),
        // gas bounds
        (
            json!({"CurveBuy": {"venue": "si.umbrafun.near", "amount": "1", "min_out": "1", "gas": (10 * TGAS).to_string()}}),
            "E_GAS",
        ),
        (
            json!({"CurveBuy": {"venue": "si.umbrafun.near", "amount": "1", "min_out": "1", "gas": (260 * TGAS).to_string()}}),
            "E_GAS",
        ),
    ];
    for (i, (op, code)) in cases.into_iter().enumerate() {
        let r = e.exec(&t, json!([op]), &format!("n{i}"), NEAR).await?;
        fails_with(&r, code);
    }
    // unknown field in the typed op (deny_unknown_fields): a recipient can't be smuggled in
    let r = e
        .exec(
            &t,
            json!([{"CurveBuy": {"venue": "si.umbrafun.near", "amount": "1", "min_out": "1", "gas": G.to_string(),
                "receiver_id": "evil.near"}}]),
            "nu",
            NEAR,
        )
        .await?;
    assert!(r.is_failure(), "unknown field must be refused");
    // curve op not last
    let r = e
        .exec(
            &t,
            json!([trade("CurveBuy", "si.umbrafun.near", 1, 1, json!({})), {"NearDeposit": {"amount": "1"}}]),
            "nl",
            NEAR,
        )
        .await?;
    fails_with(&r, "E_BAD_OP");
    // StorageDeposit on a token that is not this execute's venue
    let r = e
        .exec(
            &t,
            json!([
                storage("other.umbrafun.near", 1),
                trade("CurveBuy", "si.umbrafun.near", 1, 1, json!({}))
            ]),
            "ns",
            NEAR,
        )
        .await?;
    fails_with(&r, "E_STORAGE_TARGET");
    Ok(())
}

// ======================= NEAR payable-buy / native-sell pads =======================

/// A number out of a quote view result: a U128 string, or the first known output field.
fn qnum(v: &Value) -> u128 {
    if v.is_string() {
        return u(v);
    }
    for k in ["amount_out", "tokens_out", "near_out", "out", "amount"] {
        if !v[k].is_null() {
            return u(&v[k]);
        }
    }
    0
}

async fn quote(e: &VEnv, pad: &str, tok: &str, buy: bool, amount: u128) -> Result<u128> {
    let a = amount.to_string();
    let (m, args) = match (pad, buy) {
        ("npad", true) | ("nearfun", true) | ("nearmemefun", true) => ("quote_buy", json!({"near_in": a})),
        ("npad", false) => ("quote_sell", json!({"amount": a})),
        ("nearfun", false) | ("chipfi", false) | ("nearmemefun", false) => {
            ("quote_sell", json!({"tokens_in": a}))
        }
        ("chipfi", true) => ("quote_buy", json!({"pair_in": a})),
        ("revshare", true) => ("quote_buy", json!({"amount": a})),
        ("revshare", false) => ("quote_sell", json!({"amount": a})),
        _ => return Err(anyhow!("no quote view for {pad}")),
    };
    let v = view(e, tok, m, args).await?;
    println!("{pad} {m}({a}) = {v}");
    Ok(qnum(&v))
}

/// Happy buy (min_out = 99% of the quote) + slippage buy (min_out 2x) + happy sell of half (min_out
/// = 99% of the quote: fee = bps x min_out exactly, which also proves the payout arrived before
/// on_curve_settled) + slippage sell, through `execute`, for a NEAR-quoted token pad.
async fn near_roundtrip(e: &VEnv, t: &Ta, pad: &str, tok: &str, reg: u128, amount: u128) -> Result<()> {
    let s0 = snap(e, t, tok).await?;
    let qb = quote(e, pad, tok, true, amount).await?;
    let mut ops = vec![];
    if reg > 0 {
        ops.push(storage(tok, reg));
    }
    ops.push(trade("CurveBuy", tok, amount, qb * 99 / 100, json!({})));
    let r = e.exec(t, Value::Array(ops), &format!("{pad}-b1"), 5 * amount).await?;
    let st = settled(&r);
    println!("{pad} buy: settled={st} fails={}", r.receipt_failures().len());
    ok(r.clone())?;
    let s1 = snap(e, t, tok).await?;
    let got = s1.tok - s0.tok;
    assert!(got >= qb * 99 / 100, "{pad}: got {got} < min_out");
    assert_near_in_fee(u(&st["fee"]), amount, 0);
    assert_eq!(s1.fees - s0.fees, u(&st["fee"]));

    // slippage buy: nothing moves, no fee, spend returned
    let r = e
        .exec(t, json!([trade("CurveBuy", tok, amount, qb * 2, json!({}))]), &format!("{pad}-b2"), 5 * amount)
        .await?;
    let st = settled(&r);
    println!("{pad} slippage buy: settled={st}");
    assert_eq!(u(&st["used"]), 0, "{pad}: slippage buy must fail");
    assert_eq!(u(&st["fee"]), 0);
    let s2 = snap(e, t, tok).await?;
    assert_eq!(s2.tok, s1.tok);
    assert_eq!(s2.spent, s1.spent, "{pad}: spend returned");
    assert!(s1.near - s2.near < NEAR / 10, "{pad}: deposit back");

    // sell half
    let half = got / 2;
    let qs = quote(e, pad, tok, false, half).await?;
    let floor = qs * 99 / 100;
    let sg = json!({"gas": (200 * TGAS).to_string()});
    let r = e
        .exec(t, json!([trade("CurveSell", tok, half, floor, sg.clone())]), &format!("{pad}-s1"), 5 * amount)
        .await?;
    let st = settled(&r);
    println!("{pad} sell: settled={st} fails={}", r.receipt_failures().len());
    ok(r.clone())?;
    let s3 = snap(e, t, tok).await?;
    assert_eq!(s2.tok - s3.tok, half);
    assert!(s3.near + NEAR / 10 > s2.near + floor, "{pad}: NEAR paid out");
    assert_eq!(u(&st["fee"]), bps(floor), "{pad}: payout must be in before on_curve_settled");
    assert_eq!(s3.fees - s2.fees, bps(floor));

    // slippage sell
    let r = e
        .exec(t, json!([trade("CurveSell", tok, half, qs * 2, sg)]), &format!("{pad}-s2"), 5 * amount)
        .await?;
    let st = settled(&r);
    assert_eq!(u(&st["used"]), 0, "{pad}: slippage sell must fail");
    assert_eq!(snap(e, t, tok).await?.tok, s3.tok);
    Ok(())
}

/// npad (npad.npad.near): buy registers the buyer from the deposit (storage_fee in the quote);
/// no npad sell exists on mainnet: this is its first run.
#[tokio::test]
async fn npad_buy_sell() -> Result<()> {
    let e = venv().await?;
    let tok = "npad.npad.near";
    import(&e, tok, "8VmiuZ3L4p3ZtyJGXrL6VQgXeFygVFJYXQ9rLC1roDPU").await?;
    let t = e
        .ta(
            "np",
            20 * NEAR,
            (10 * NEAR, 20 * NEAR),
            vec![json!({"id": "npad.near", "kind": {"TokenCurve": "Npad"}})],
        )
        .await?;
    near_roundtrip(&e, &t, "npad", tok, 0, NEAR).await
}

/// NearFun (ncat.nearfunio.near, curve phase): NEAR buy + sell (no curve sell ever on mainnet).
#[tokio::test]
async fn nearfun_buy_sell() -> Result<()> {
    let e = venv().await?;
    let tok = "ncat.nearfunio.near";
    import(&e, tok, "7bPoEt3NG3QeJ2kifTjYT14yCXSJ9yzrFEcvWADtopYu").await?;
    let t = e
        .ta(
            "nf",
            20 * NEAR,
            (10 * NEAR, 20 * NEAR),
            vec![json!({"id": "nearfunio.near", "kind": {"TokenCurve": "NearFun"}})],
        )
        .await?;
    let reg = u(&view(&e, tok, "storage_balance_bounds", json!({})).await?["min"]);
    near_roundtrip(&e, &t, "nearfun", tok, reg, NEAR).await
}

/// chipfi NEAR pair (c1.chipfi.near): buy{min_out, for_account: null}; sell + claim in one batch
/// (deposit 0 both); the claim pays credit (+ dividends) as native NEAR.
#[tokio::test]
async fn chipfi_near_buy_sell_claim() -> Result<()> {
    let e = venv().await?;
    let _q = mock_q(&e, NVDA, &[]).await?;
    let (tok, _) = chipfi_fresh(&e).await?;
    let tok = tok.as_str();
    let t = e
        .ta(
            "cf",
            20 * NEAR,
            (10 * NEAR, 20 * NEAR),
            vec![json!({"id": "chipfi.near", "kind": {"TokenCurve": "Chipfi"}})],
        )
        .await?;
    let reg = u(&view(&e, tok, "storage_balance_bounds", json!({})).await?["min"]);
    near_roundtrip(&e, &t, "chipfi", tok, reg, NEAR).await?;
    // the credit is claimed in the same tx: nothing left
    let h: Value = view(&e, tok, "get_holder", json!({"account_id": t.id})).await?;
    println!("chipfi holder after sell+claim: {h}");
    assert_eq!(u(&h["credit"]), 0, "claim in the sell batch paid the credit");
    // CurveClaim ChipfiClaim (housekeeping) is accepted and pays self
    let r =
        e.exec(&t, json!([{"CurveClaim": {"venue": tok, "action": "ChipfiClaim"}}]), "cf-c", NEAR).await?;
    println!("chipfi claim op: ok={} {:?}", r.is_success(), r.receipt_failures().len());
    assert!(r.is_success());
    Ok(())
}

/// chipfi NVDAon pair (c3.chipfi.near): pair buy `Q.ft_transfer_call{T, {"min_out"}}` (Settle
/// Token, no fee), Q sell (+claim) paid in Q, no fee.
#[tokio::test]
async fn chipfi_q_buy_sell() -> Result<()> {
    let e = venv().await?;
    let q = mock_q(&e, NVDA, &[]).await?;
    let (_, tok) = chipfi_fresh(&e).await?;
    let tok = tok.as_str();
    let t = e
        .ta(
            "cq",
            10 * NEAR,
            (10 * NEAR, 20 * NEAR),
            vec![json!({"id": "chipfi.near", "kind": {"TokenCurve": "Chipfi"}})],
        )
        .await?;
    let tid: AccountId = tok.parse()?;
    for (a, n) in [(&t.id, 10u128.pow(18)), (&tid, 0)] {
        ok(q.call("mint").args_json(json!({"account_id": a, "amount": n.to_string()})).transact().await?)?;
    }
    for a in ["richgoat3540.near"] {
        ok(q.call("mint").args_json(json!({"account_id": a, "amount": "0"})).transact().await?)?;
    }
    let reg = u(&view(&e, tok, "storage_balance_bounds", json!({})).await?["min"]);
    let qin = 6 * 10u128.pow(15);
    let qb = quote(&e, "chipfi", tok, true, qin).await?;
    let s0 = snap(&e, &t, tok).await?;
    let r = e
        .exec(
            &t,
            json!([storage(tok, reg), trade("CurveBuy", tok, qin, qb * 99 / 100, json!({"quote": NVDA}))]),
            "cq-b",
            NEAR,
        )
        .await?;
    let st = settled(&r);
    println!("chipfi Q buy: {st} fails={:?}", r.receipt_failures());
    ok(r.clone())?;
    let s1 = snap(&e, &t, tok).await?;
    assert!(s1.tok - s0.tok >= qb * 99 / 100);
    assert_eq!(u(&st["fee"]), 0);
    let got = s1.tok - s0.tok;
    let q0 = e.ft(q.id(), &t.id).await?;
    let qs = quote(&e, "chipfi", tok, false, got / 2).await?;
    let r = e
        .exec(
            &t,
            json!([trade("CurveSell", tok, got / 2, qs * 99 / 100, json!({"quote": NVDA}))]),
            "cq-s",
            NEAR,
        )
        .await?;
    let st = settled(&r);
    println!("chipfi Q sell: {st} fails={:?}", r.receipt_failures());
    ok(r.clone())?;
    assert!(e.ft(q.id(), &t.id).await? >= q0 + qs * 99 / 100, "Q paid by claim");
    assert_eq!(u(&st["fee"]), 0);
    // raw FtTransferCall pair buy: only {"min_out"}; for_account / unknown fields refused
    let raw = |msg: &str| json!([{"FtTransferCall": {"token": NVDA, "receiver_id": tok, "amount": "1000", "msg": msg, "gas": G.to_string()}}]);
    fails_with(
        &e.exec(&t, raw(r#"{"min_out":"1","for_account":"evil.near"}"#), "cq-r1", NEAR).await?,
        "E_BAD_MSG",
    );
    fails_with(&e.exec(&t, raw(r#"{"min_out":"0"}"#), "cq-r2", NEAR).await?, "E_MIN_OUT");
    // wNEAR is never a chipfi pair input through FtTransferCall (NEAR buys are payable)
    let r = e
        .exec(
            &t,
            json!([{"FtTransferCall": {"token": e.wrap.id(), "receiver_id": tok, "amount": "1000",
            "msg": r#"{"min_out":"1"}"#, "gas": G.to_string()}}]),
            "cq-r3",
            NEAR,
        )
        .await?;
    fails_with(&r, "E_BAD_MSG");
    Ok(())
}

/// token0: a FRESH token (`init` of the real 3psgWikm… template; every live token0 token sampled
/// is graduated). Exact-out buy: max_token_amount minted, unused NEAR refunded ("refund amount:"
/// log) -> fee on (amount - refund), measured; sell deposit 0, returns the NEAR paid (reported).
#[tokio::test]
async fn token0_exact_out_buy_sell() -> Result<()> {
    let e = venv().await?;
    // token0.near (the deployer, fee recipient) calls init as on mainnet: init registers both the
    // token and its predecessor, so the token can't init itself ("already registered")
    let caller = keyed(&e, "token0.near").await?;
    let code = pinned("sfv.token0.near", Some("3psgWikmZZhJcFJ8dkZAJutwnntkCbNCLRdvkRXTGXVa")).await?;
    let tok = "tst.token0.near";
    let c = install_code(&e.worker, tok, &code).await?;
    let r = caller
        .call(c.id(), "init")
        .args_json(
            json!({"initial_buy": "0", "name": "Test", "symbol": "TST", "description": "", "img_src": "",
            "twitter_link": "", "telegram_link": "", "website_link": "", "creator": e.root.id(),
            "a": "0.0000002681", "b": "0.0000000032", "max_token_amount": "0", "min_token_amount": "0"}),
        )
        .gas(Gas::from_tgas(100))
        .transact()
        .await?;
    println!("token0 init: {:?}", r.clone().into_result().err());
    ok(r)?;
    println!("token0 info: {}", view(&e, tok, "get_bonding_curve_info", json!({})).await?);
    let t = e
        .ta(
            "t0",
            20 * NEAR,
            (10 * NEAR, 20 * NEAR),
            vec![json!({"id": "token0.near", "kind": {"TokenCurve": "Token0"}})],
        )
        .await?;
    let reg = u(&view(&e, tok, "storage_balance_bounds", json!({})).await?["min"]);
    let want = 1_000_000u128 * 10u128.pow(18);
    let amount = NEAR;
    let s0 = snap(&e, &t, tok).await?;
    let r = e
        .exec(
            &t,
            json!([
                storage(tok, reg),
                trade("CurveBuy", tok, amount, want * 9 / 10, json!({"max_out": want.to_string()}))
            ]),
            "t0-b",
            2 * NEAR,
        )
        .await?;
    let st = settled(&r);
    let refund: u128 = r
        .logs()
        .iter()
        .find_map(|l| l.strip_prefix("refund amount: ").and_then(|x| x.trim().parse().ok()))
        .unwrap_or(0);
    println!("token0 buy: {st} refund={refund} logs={:?}", r.logs());
    ok(r.clone())?;
    let s1 = snap(&e, &t, tok).await?;
    assert!(s1.tok - s0.tok >= want * 9 / 10 && s1.tok - s0.tok <= want);
    assert!(refund > 0, "exact-out refund expected (amount >> cost)");
    // the refund arrived before on_curve_settled: fee is on (amount - refund) (+ gas-refund slack)
    assert_near_in_fee(u(&st["fee"]), amount, refund);
    // slippage (max_out above what 0.01 N buys and min_out too): panics, NEAR back
    let r = e
        .exec(
            &t,
            json!([trade("CurveBuy", tok, NEAR / 1000, want, json!({"max_out": want.to_string()}))]),
            "t0-b2",
            2 * NEAR,
        )
        .await?;
    assert_eq!(u(&settled(&r)["used"]), 0, "{:?}", settled(&r));
    // sell half: deposit 0; fee = bps x min(arrived, reported NEAR)
    let half = (s1.tok - s0.tok) / 2;
    let s2 = snap(&e, &t, tok).await?;
    let r = e.exec(&t, json!([trade("CurveSell", tok, half, 1, json!({}))]), "t0-s", 2 * NEAR).await?;
    let st = settled(&r);
    println!("token0 sell: {st} fails={:?}", r.receipt_failures());
    ok(r.clone())?;
    let reported: u128 = r.json::<String>().ok().and_then(|x| x.parse().ok()).unwrap_or(0);
    let s3 = snap(&e, &t, tok).await?;
    assert_eq!(s2.tok - s3.tok, half);
    let paid = s3.near + NEAR / 10 - s2.near; // + gas slack
    assert!(paid > 0);
    // reported = the token's return (the NEAR it paid); not the execute's own return (this is
    // the callback's), so read it from the fee instead: fee = bps(reported) when it arrived
    let _ = reported;
    assert!(u(&st["fee"]) > 0, "near_out_reported: fee on the reported payout (min_out bound was 1)");
    assert!(u(&st["fee"]) <= bps(paid), "fee <= bps x arrived");
    Ok(())
}

// ======================= RevShare =======================

/// RevShare bonding (l0.revshare-launch.near): wNEAR buy by ft_transfer_call (Settle Wrap, wrap's
/// resolve is trusted); sell = escrow -> wNEAR ft_transfer -> on_sell (never seen on mainnet: first
/// run here); a second sell while one is in flight panics "Sell in flight" (-> refund, no fee).
#[tokio::test]
async fn revshare_buy_sell() -> Result<()> {
    let e = venv().await?;
    let tok = "l0.revshare-launch.near";
    let c = import(&e, tok, "9gNvjBnKKuvujP6LwynYjqhDJ92fRkN2ozjZvzFjVapX").await?;
    // the token's wNEAR reserve lives in wrap.near's state: seed it in the sandbox wrap
    let launch = view(&e, tok, "get_launch", json!({})).await?;
    let reserve = u(&launch["curve_quote"]);
    ok(c.as_account()
        .call(e.wrap.id(), "storage_deposit")
        .args_json(json!({"account_id": tok}))
        .deposit(NearToken::from_yoctonear(STORAGE))
        .transact()
        .await?)?;
    ok(c.as_account()
        .call(e.wrap.id(), "near_deposit")
        .args_json(json!({}))
        .deposit(NearToken::from_yoctonear(reserve))
        .transact()
        .await?)?;
    let t = e
        .ta(
            "rs",
            20 * NEAR,
            (10 * NEAR, 20 * NEAR),
            vec![json!({"id": "revshare-launch.near", "kind": {"TokenCurve": "RevShare"}})],
        )
        .await?;
    let reg = u(&view(&e, tok, "storage_balance_bounds", json!({})).await?["min"]);
    let amount = NEAR;
    let qb = quote(&e, "revshare", tok, true, amount).await?;
    let s0 = snap(&e, &t, tok).await?;
    let r = e
        .exec(
            &t,
            json!([storage(tok, reg), {"NearDeposit": {"amount": amount.to_string()}},
            trade("CurveBuy", tok, amount, qb * 99 / 100, json!({}))]),
            "rs-b",
            3 * NEAR,
        )
        .await?;
    let st = settled(&r);
    println!("revshare buy: {st} fails={:?}", r.receipt_failures().len());
    ok(r.clone())?;
    let s1 = snap(&e, &t, tok).await?;
    assert!(s1.tok - s0.tok >= qb * 99 / 100);
    assert_eq!(u(&st["fee"]), bps(amount), "Wrap settle: fee on the wNEAR used, exact");
    assert_eq!(s1.fees - s0.fees, bps(amount));
    // slippage buy: wrap resolve refunds all; no fee; spend back
    let r = e
        .exec(&t, json!([{"NearDeposit": {"amount": amount.to_string()}}, trade("CurveBuy", tok, amount, qb * 3, json!({}))]), "rs-b2", 3 * NEAR)
        .await?;
    let st = settled(&r);
    println!("revshare slippage buy: {st}");
    assert_eq!(u(&st["used"]), 0);
    assert_eq!(u(&st["fee"]), 0);

    // sell a third: wNEAR payout
    let got = s1.tok - s0.tok;
    let part = got / 3;
    let qs = quote(&e, "revshare", tok, false, part).await?;
    let w0 = e.ft(e.wrap.id(), &t.id).await?;
    let s2 = snap(&e, &t, tok).await?;
    let r = e
        .exec(&t, json!([trade("CurveSell", tok, part, qs * 99 / 100, json!({}))]), "rs-s", 3 * NEAR)
        .await?;
    let st = settled(&r);
    println!("revshare sell: {st} fails={:?} logs={:?}", r.receipt_failures(), r.logs());
    ok(r.clone())?;
    let s3 = snap(&e, &t, tok).await?;
    assert_eq!(s2.tok - s3.tok, part);
    assert!(e.ft(e.wrap.id(), &t.id).await? >= w0 + qs * 99 / 100, "wNEAR paid to the account");
    assert_eq!(u(&st["fee"]), bps(qs * 99 / 100), "wnear_out: fee on the min_out bound");
    println!("revshare after sell: {}", view(&e, tok, "get_launch", json!({})).await?["sell_in_flight"]);

    // two sells in parallel: the second must not double-spend; "Sell in flight" -> refund
    let exp = e.worker.view_block().await?.timestamp() + 60_000_000_000;
    let mk = |id: &str| {
        t.device
            .call(&t.id, "execute")
            .args_json(
                json!({"ops": [trade("CurveSell", tok, part / 2, 1, json!({}))], "client_order_id": id,
                "expires_at_ns": exp.to_string(), "max_in_yocto": NEAR.to_string()}),
            )
            .gas(Gas::from_tgas(300))
            .transact()
    };
    let before = snap(&e, &t, tok).await?;
    let (a, b) = tokio::join!(mk("rs-p1"), mk("rs-p2"));
    let (a, b) = (a?, b?);
    let (sa, sb) = (settled(&a), settled(&b));
    let fl = |r: &ExecutionFinalResult| format!("{:?}", r.receipt_failures()).contains("Sell in flight");
    println!("parallel sells: a={sa} inflight={} b={sb} inflight={}", fl(&a), fl(&b));
    for r in [&a, &b] {
        for f in r.receipt_failures() {
            println!(
                "  failure: {}",
                format!("{:?}", f.clone().into_result().err()).chars().take(300).collect::<String>()
            );
        }
    }
    let after = snap(&e, &t, tok).await?;
    let sold = u(&sa["used"]) + u(&sb["used"]);
    assert_eq!(before.tok - after.tok, sold, "tokens leave only for a sell that settled as used");
    if fl(&a) || fl(&b) {
        assert!(u(&sa["used"]) == 0 || u(&sb["used"]) == 0);
    }
    Ok(())
}

// ======================= nearmemefun =======================

/// nearmemefun: every live token is Closed, so a FRESH token from the real factory
/// (nearmemefun.near BXR7dvrg…: new_with_config + create_token, as on mainnet), then the round trip.
#[tokio::test]
async fn nearmemefun_buy_sell() -> Result<()> {
    let e = venv().await?;
    let f = install_code(
        &e.worker,
        "nearmemefun.near",
        &pinned("nearmemefun.near", Some("BXR7dvrgJ3WGw8w4M6RF1T9TW5DzZvm43itopUDUmHui")).await?,
    )
    .await?;
    ensure(&e, "nearmemefunn.near").await?;
    let r = f
        .call("new_with_config")
        .args_json(json!({"owner_id": "nearmemefunn.near", "treasury_id": "nearmemefunn.near",
            "initial_market_cap_near": "600000000000000000000000000", "graduation_market_cap_near": "8300000000000000000000000000", "fee_bps": 50}))
        .transact()
        .await?;
    println!(
        "nmf new: {:?}",
        r.clone().into_result().err().map(|x| format!("{x:?}").chars().take(300).collect::<String>())
    );
    ok(r)?;
    let creator = sub(&e.root, "nmfcreator", 20 * NEAR).await?;
    let cost: Value =
        f.view("get_creation_cost").await.map(|v| v.json().unwrap_or(Value::Null)).unwrap_or(Value::Null);
    println!("nmf creation cost: {cost}");
    let r = creator
        .call(f.id(), "create_token")
        .args_json(json!({"name": "Sandbox", "symbol": "SBX", "icon": null, "tax_bps": 100, "tax_recipient_id": creator.id()}))
        .deposit(NearToken::from_yoctonear(2_069_820_000_000_000_000_000_000))
        .gas(Gas::from_tgas(300))
        .transact()
        .await?;
    println!("nmf create: ok={} logs={:?} fails={:?}", r.is_success(), r.logs(), r.receipt_failures().len());
    ok(r)?;
    let list: Value = f.view("list_tokens").args_json(json!({})).await?.json()?;
    println!("nmf tokens: {list}");
    let tok = list
        .as_array()
        .and_then(|a| a.first())
        .and_then(|x| x["token_account_id"].as_str().map(String::from))
        .ok_or_else(|| anyhow!("no token"))?;
    println!("nmf market: {}", view(&e, &tok, "get_market", json!({})).await?);
    let t = e
        .ta(
            "nm",
            20 * NEAR,
            (10 * NEAR, 20 * NEAR),
            vec![json!({"id": "nearmemefun.near", "kind": {"TokenCurve": "Nearmemefun"}})],
        )
        .await?;
    let reg = u(&view(&e, &tok, "storage_balance_bounds", json!({})).await?["min"]);
    near_roundtrip(&e, &t, "nearmemefun", &tok, reg, NEAR).await?;

    // a sell credits its full proceeds but the batch withdraws only min_out: the excess stays as
    // this account's claim, recovered by CurveClaim NearmemefunWithdraw
    let bal = snap(&e, &t, &tok).await?.tok;
    let qs = quote(&e, "nearmemefun", &tok, false, bal / 2).await?;
    let floor = qs / 2;
    let sg = json!({"gas": (200 * TGAS).to_string()});
    ok(e.exec(&t, json!([trade("CurveSell", &tok, bal / 2, floor, sg)]), "nm-low", NEAR).await?)?;
    let left = u(&view(&e, &tok, "get_claim", json!({"account_id": t.id})).await?["available"]);
    println!("nearmemefun credit left after a min_out withdraw: {left}");
    assert!(left >= qs - floor - qs / 1000 && left > 0, "excess credit stays in the pad");
    let n0 = e.near(&t.id).await?;
    let f0 = e.near(e.fees.id()).await?;
    let cl =
        json!([{"CurveClaim": {"venue": tok, "action": "NearmemefunWithdraw", "amount": left.to_string()}}]);
    let r = e.exec(&t, cl, "nm-claim", NEAR).await?;
    println!("nearmemefun claim: ok={} logs={:?}", r.is_success(), r.logs());
    // the execute's own gas_spend (paid from the account) is in its event
    let gas_spend: u128 = r
        .logs()
        .iter()
        .find_map(|l| l.strip_prefix("EVENT_JSON:").filter(|x| x.contains("\"execute\"")))
        .and_then(|x| serde_json::from_str::<Value>(x).ok())
        .map_or(0, |v| u(&v["data"]["gas_spend"]));
    ok(r)?;
    assert_eq!(u(&view(&e, &tok, "get_claim", json!({"account_id": t.id})).await?["available"]), 0);
    // sandbox gas price 1e9: the tx's own burn is ~0.02 N on top of gas_spend
    assert!(e.near(&t.id).await? + gas_spend + NEAR / 20 > n0 + left, "credit paid to the account");
    assert_eq!(e.near(e.fees.id()).await?, f0, "a claim charges no fee");
    // more than the credit: the pad refuses, nothing moves
    let cl = json!([{"CurveClaim": {"venue": tok, "action": "NearmemefunWithdraw", "amount": "1"}}]);
    let r = e.exec(&t, cl, "nm-claim2", NEAR).await?;
    assert!(!r.receipt_failures().is_empty(), "withdraw of an empty credit fails at the pad");
    Ok(())
}

// ======================= gas probe =======================

/// One measured op kind: `mk(op_gas)` builds the ops; success = settled `used` > 0 and no failed
/// receipt. Returns (pad-tree gas of a success at 250 TGas, per-receipt list, min working op gas).
async fn gas_case(
    e: &VEnv,
    t: &Ta,
    label: &str,
    lo: u64,
    mk: &dyn Fn(u64) -> Value,
    max_in: u128,
) -> Result<(f64, Vec<(String, f64)>, u64)> {
    let mut n = 0u32;
    let mut run = |g: u64| {
        n += 1;
        let id = format!("gp-{label}-{g}-{n}");
        let ops = mk(g);
        async move {
            let r = e.exec(t, ops, &id, max_in).await?;
            let ok_ = u(&settled(&r)["used"]) > 0 && r.receipt_failures().is_empty();
            Ok::<_, anyhow::Error>((ok_, r))
        }
    };
    let (ok_, r) = run(MAX_TGAS).await?;
    if !ok_ {
        return Err(anyhow!(
            "{label}: fails even at {MAX_TGAS} TGas: {:?} {:?}",
            settled(&r),
            r.receipt_failures()
        ));
    }
    let per: Vec<(String, f64)> =
        gas_by_receipt(&r).into_iter().filter(|(x, _)| x != t.id.as_str()).collect();
    let tree: f64 = per.iter().map(|(_, g)| g).sum();
    // bisect the smallest op gas that works (1 TGas resolution)
    let mut good = MAX_TGAS;
    if run(lo).await?.0 {
        good = lo;
    } else {
        let mut bad = lo;
        while good - bad > 1 {
            let mid = (bad + good) / 2;
            if run(mid).await?.0 {
                good = mid;
            } else {
                bad = mid;
            }
        }
    }
    Ok((tree, per, good))
}

const MAX_TGAS: u64 = 250;
// sells whose planner splits the op gas: the sell part keeps >= MIN_CURVE_GAS (20) next to
// withdraw_near (token::NEARMEMEFUN_WITHDRAW_TGAS = 80) / claim (GAS_CURVE_CLAIM = 60)

fn rec(min: u64) -> u64 {
    (min * 13).div_ceil(10).div_ceil(5) * 5
}

fn gtrade(side: &str, venue: &str, amount: u128, min_out: u128, g: u64, extra: Value) -> Value {
    let mut x = extra;
    x["gas"] = json!((g * TGAS).to_string());
    trade(side, venue, amount, min_out, x)
}

/// Measurement probe: per TokenCurve pad and op, the gas burnt by the pad's receipt tree (at 250
/// TGas attached), per receipt, and the minimum op gas that works (bisected through `execute`),
/// plus a real Chain NEAR -> NVDAon (Rhea classic) -> Umbra Q buy. Prints a markdown table.
#[tokio::test]
#[ignore = "measurement probe (~10 min): cargo test --test venues_token gas_probe -- --ignored --nocapture"]
async fn gas_probe_token_pads() -> Result<()> {
    let e = venv().await?;
    // pads (same setups as the suites above), all in one sandbox and one trading account
    let umb = "si.umbrafun.near";
    import(&e, umb, "7RtxE5daMenAJDnJHJGg6t3C53XmA8TmwFx8MTkWy6hd").await?;
    let umq = "ai.umbrafun.near";
    import(&e, umq, "GY1UqaLHhXZCNpXAg4RCbGfhG1wocMvoEYTQSzJKC43z").await?;
    let npad = "npad.npad.near";
    import(&e, npad, "8VmiuZ3L4p3ZtyJGXrL6VQgXeFygVFJYXQ9rLC1roDPU").await?;
    let nf = "ncat.nearfunio.near";
    import(&e, nf, "7bPoEt3NG3QeJ2kifTjYT14yCXSJ9yzrFEcvWADtopYu").await?;
    let rs = "l0.revshare-launch.near";
    let rsc = import(&e, rs, "9gNvjBnKKuvujP6LwynYjqhDJ92fRkN2ozjZvzFjVapX").await?;
    let reserve = u(&view(&e, rs, "get_launch", json!({})).await?["curve_quote"]);
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
    let q = mock_q(&e, NVDA, &[]).await?;
    let (cf, cfq) = chipfi_fresh(&e).await?;
    // nearmemefun fresh token
    let f = install_code(
        &e.worker,
        "nearmemefun.near",
        &pinned("nearmemefun.near", Some("BXR7dvrgJ3WGw8w4M6RF1T9TW5DzZvm43itopUDUmHui")).await?,
    )
    .await?;
    ensure(&e, "nearmemefunn.near").await?;
    ok(f.call("new_with_config").args_json(json!({"owner_id": "nearmemefunn.near", "treasury_id": "nearmemefunn.near",
        "initial_market_cap_near": "600000000000000000000000000", "graduation_market_cap_near": "8300000000000000000000000000", "fee_bps": 50}))
        .transact().await?)?;
    let creator = sub(&e.root, "nmfcreator", 20 * NEAR).await?;
    ok(creator.call(f.id(), "create_token")
        .args_json(json!({"name": "Sandbox", "symbol": "SBX", "icon": null, "tax_bps": 100, "tax_recipient_id": creator.id()}))
        .deposit(NearToken::from_yoctonear(2_069_820_000_000_000_000_000_000)).gas(Gas::from_tgas(300)).transact().await?)?;
    let nm = "t0.nearmemefun.near";
    // token0 fresh
    let caller = keyed(&e, "token0.near").await?;
    let t0 = "tst.token0.near";
    let c0 = install_code(
        &e.worker,
        t0,
        &pinned("sfv.token0.near", Some("3psgWikmZZhJcFJ8dkZAJutwnntkCbNCLRdvkRXTGXVa")).await?,
    )
    .await?;
    ok(caller
        .call(c0.id(), "init")
        .args_json(
            json!({"initial_buy": "0", "name": "Test", "symbol": "TST", "description": "", "img_src": "",
            "twitter_link": "", "telegram_link": "", "website_link": "", "creator": e.root.id(),
            "a": "0.0000002681", "b": "0.0000000032", "max_token_amount": "0", "min_token_amount": "0"}),
        )
        .gas(Gas::from_tgas(100))
        .transact()
        .await?)?;
    // Rhea classic wNEAR/NVDAon for the Chain's leg 1
    let rhea = install_mainnet(&e.worker, "v2.ref-finance.near").await?;
    let rowner = sub(&e.root, "rheaowner", 50 * NEAR).await?;
    ok(rhea
        .call("new")
        .args_json(
            json!({"owner_id": rowner.id(), "boost_farm_id": rowner.id(), "burrowland_id": rowner.id(),
        "exchange_fee": 4, "referral_fee": 1}),
        )
        .transact()
        .await?)?;
    let lp = sub(&e.root, "qlp", 400 * NEAR).await?;
    for a in [rhea.id(), lp.id()] {
        ok(q.call("mint").args_json(json!({"account_id": a, "amount": "0"})).transact().await?)?;
    }
    ok(q.call("mint")
        .args_json(json!({"account_id": lp.id(), "amount": (10u128.pow(18) * 100).to_string()}))
        .transact()
        .await?)?;
    ok(lp
        .call(e.wrap.id(), "storage_deposit")
        .args_json(json!({}))
        .deposit(NearToken::from_yoctonear(STORAGE))
        .transact()
        .await?)?;
    ok(lp
        .call(e.wrap.id(), "storage_deposit")
        .args_json(json!({"account_id": rhea.id()}))
        .deposit(NearToken::from_yoctonear(STORAGE))
        .transact()
        .await?)?;
    ok(lp
        .call(e.wrap.id(), "near_deposit")
        .args_json(json!({}))
        .deposit(NearToken::from_near(200))
        .transact()
        .await?)?;
    ok(lp
        .call(rhea.id(), "storage_deposit")
        .args_json(json!({}))
        .deposit(NearToken::from_near(1))
        .transact()
        .await?)?;
    ok(lp
        .call(rhea.id(), "register_tokens")
        .args_json(json!({"token_ids": [e.wrap.id(), q.id()]}))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?)?;
    let pool: u64 = okr(lp
        .call(rhea.id(), "add_simple_pool")
        .args_json(json!({"tokens": [e.wrap.id(), q.id()], "fee": 25}))
        .deposit(NearToken::from_millinear(100))
        .transact()
        .await?)?
    .json()?;
    // 100 N : 100 NVDAon (1e20 each 18 dec)
    let qliq = 100 * 10u128.pow(18);
    for (tk, amt) in [(e.wrap.id(), 100 * NEAR), (q.id(), qliq)] {
        ok(lp
            .call(tk, "ft_transfer_call")
            .args_json(json!({"receiver_id": rhea.id(), "amount": amt.to_string(), "msg": ""}))
            .deposit(NearToken::from_yoctonear(1))
            .gas(Gas::from_tgas(100))
            .transact()
            .await?)?;
    }
    ok(lp
        .call(rhea.id(), "add_liquidity")
        .args_json(json!({"pool_id": pool, "amounts": [(100 * NEAR).to_string(), qliq.to_string()]}))
        .deposit(NearToken::from_millinear(10))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?)?;

    let dexes = vec![
        json!({"id": "v2.ref-finance.near", "kind": "RheaClassic"}),
        json!({"id": "umbrafun.near", "kind": {"TokenCurve": "Umbra"}}),
        json!({"id": "npad.near", "kind": {"TokenCurve": "Npad"}}),
        json!({"id": "nearfunio.near", "kind": {"TokenCurve": "NearFun"}}),
        json!({"id": "revshare-launch.near", "kind": {"TokenCurve": "RevShare"}}),
        json!({"id": "chipfi.near", "kind": {"TokenCurve": "Chipfi"}}),
        json!({"id": "nearmemefun.near", "kind": {"TokenCurve": "Nearmemefun"}}),
        json!({"id": "token0.near", "kind": {"TokenCurve": "Token0"}}),
    ];
    let t = e.ta("gp", 150 * NEAR, (50 * NEAR, 1_000 * NEAR), dexes).await?;
    let tid: AccountId = cfq.parse()?;
    // richgoat3540.near = the chipfi fee wallet (pair-token tax transfer; unregistered = failed receipt)
    for (a, n) in [
        (&t.id, 10u128.pow(19)),
        (&tid, 0),
        (&"ai.umbrafun.near".parse::<AccountId>()?, 5 * 10u128.pow(18)),
        (&"richgoat3540.near".parse::<AccountId>()?, 0),
    ] {
        ok(q.call("mint").args_json(json!({"account_id": a, "amount": n.to_string()})).transact().await?)?;
    }
    // register the account on every pad token (outside the measured ops)
    for tok in [umb, umq, nf, rs, cf.as_str(), cfq.as_str(), nm, t0] {
        // a StorageDeposit op must target the execute's venue (E_STORAGE_TARGET): register directly
        let reg = u(&view(&e, tok, "storage_balance_bounds", json!({})).await?["min"]);
        ok(e.root
            .call(&tok.parse()?, "storage_deposit")
            .args_json(json!({"account_id": t.id}))
            .deposit(NearToken::from_yoctonear(reg))
            .transact()
            .await?)?;
    }
    // wNEAR for RevShare buys
    ok(e.exec(&t, json!([{"NearDeposit": {"amount": (5 * NEAR).to_string()}}]), "wrap5", 6 * NEAR).await?)?;

    let b = NEAR / 10;
    let qin = 10u128.pow(15);
    let none = json!({});
    let nvda = json!({"quote": NVDA});
    let mut rows: Vec<String> = vec![];
    let mut add = |pad: &str, op: &str, res: (f64, Vec<(String, f64)>, u64)| {
        let (tree, per, min) = res;
        let per_s = per
            .iter()
            .map(|(x, g)| format!("{}:{g:.1}", x.split('.').next().unwrap_or(x)))
            .collect::<Vec<_>>()
            .join(" ");
        let row = format!("| {pad} | {op} | {tree:.1} | {min} | {} | {per_s} |", rec(min));
        println!("{row}");
        rows.push(row);
    };
    // buys (each success leaves tokens for the sells)
    let buy = |tok: &'static str, x: Value| {
        move |g: u64| json!([gtrade("CurveBuy", tok, NEAR / 10, 1, g, x.clone())])
    };
    add("Umbra v2", "buy (NEAR)", gas_case(&e, &t, "umb-b", 20, &buy(umb, none.clone()), NEAR).await?);
    add("npad", "buy (NEAR)", gas_case(&e, &t, "np-b", 20, &buy(npad, none.clone()), NEAR).await?);
    add("NearFun", "buy (NEAR)", gas_case(&e, &t, "nf-b", 20, &buy(nf, none.clone()), NEAR).await?);
    add("nearmemefun", "buy (NEAR)", gas_case(&e, &t, "nm-b", 20, &buy(nm, none.clone()), NEAR).await?);
    let cf_s: &'static str = Box::leak(cf.clone().into_boxed_str());
    let cfq_s: &'static str = Box::leak(cfq.clone().into_boxed_str());
    add("chipfi", "buy (NEAR)", gas_case(&e, &t, "cf-b", 20, &buy(cf_s, none.clone()), NEAR).await?);
    let t0max = 100_000u128 * 10u128.pow(18);
    add(
        "token0",
        "buy (NEAR, exact-out + refund)",
        gas_case(
            &e,
            &t,
            "t0-b",
            20,
            &|g| json!([gtrade("CurveBuy", t0, NEAR / 10, 1, g, json!({"max_out": t0max.to_string()}))]),
            NEAR,
        )
        .await?,
    );
    add(
        "RevShare",
        "buy (wNEAR ft_transfer_call)",
        gas_case(&e, &t, "rs-b", 20, &|g| json!([gtrade("CurveBuy", rs, b, 1, g, none.clone())]), NEAR)
            .await?,
    );
    add(
        "Umbra first-gen",
        "Q-buy (NVDAon ft_transfer_call)",
        gas_case(&e, &t, "umq-b", 20, &|g| json!([gtrade("CurveBuy", umq, qin, 1, g, nvda.clone())]), NEAR)
            .await?,
    );
    add(
        "chipfi",
        "Q-buy (pair ft_transfer_call)",
        gas_case(&e, &t, "cfq-b", 20, &|g| json!([gtrade("CurveBuy", cfq_s, qin, 1, g, nvda.clone())]), NEAR)
            .await?,
    );
    // sells: a small fixed slice of what the buys left
    let slice = |tok: &str| {
        let tok = tok.to_string();
        let e = &e;
        let t = &t;
        async move { Ok::<u128, anyhow::Error>(e.ft(&tok.parse()?, &t.id).await? / 40) }
    };
    for (pad, tok, lo, x) in [
        ("Umbra v2", umb, 20u64, none.clone()),
        ("npad", npad, 20, none.clone()),
        ("NearFun", nf, 20, none.clone()),
        ("nearmemefun", nm, 20 + 80, none.clone()),
        ("chipfi", cf_s, 20 + 60, none.clone()),
        ("token0", t0, 20, none.clone()),
        ("RevShare", rs, 20, none.clone()),
        ("Umbra first-gen", umq, 20, nvda.clone()),
        ("chipfi pair", cfq_s, 20 + 60, nvda.clone()),
    ] {
        let a = slice(tok).await?;
        let op = match pad {
            "nearmemefun" => "sell + withdraw_near (one batch)",
            "chipfi" | "chipfi pair" => "sell + claim (one batch)",
            "RevShare" => "sell (wNEAR payout)",
            "Umbra first-gen" => "sell (Q payout)",
            _ => "sell (native NEAR)",
        };
        add(
            pad,
            op,
            gas_case(
                &e,
                &t,
                &format!("{tok}-s"),
                lo,
                &|g| json!([gtrade("CurveSell", tok, a, 1, g, x.clone())]),
                NEAR,
            )
            .await?,
        );
    }

    // a real Chain: NEAR -> NVDAon (Rhea classic) -> Umbra first-gen Q buy as leg 2
    let mid: u128 = rhea
        .view("get_return")
        .args_json(json!({"pool_id": pool, "token_in": e.wrap.id(), "amount_in": b.to_string(),
        "token_out": q.id()}))
        .await?
        .json::<String>()?
        .parse()?;
    let chain = |l2: u64| {
        let leg1 = json!({"FtTransferCall": {"token": e.wrap.id(), "receiver_id": rhea.id(), "amount": b.to_string(),
            "msg": json!({"force": 0, "actions": [{"pool_id": pool, "token_in": e.wrap.id(), "token_out": q.id(), "amount_in": b.to_string(),
                "amount_out": "0", "min_amount_out": (mid * 99 / 100).to_string()}], "skip_unwrap_near": true}).to_string(),
            "gas": (80 * TGAS).to_string()}});
        let leg2 = json!({"CurveBuy": {"venue": umq, "quote": NVDA, "amount": "0", "min_out": "1", "gas": (l2 * TGAS).to_string()}});
        json!([{"NearDeposit": {"amount": b.to_string()}}, {"Chain": {"leg1": leg1, "leg2": leg2, "q": NVDA,
            "min_mid": (mid * 99 / 100).to_string(), "max_mid": (mid * 101 / 100).to_string(), "min_final": "1"}}])
    };
    let mut chain_rows = vec![];
    for l2 in [150u64, 60, 40, 30, 25, 20] {
        let r = e.exec(&t, chain(l2), &format!("chain-{l2}"), NEAR).await?;
        let ev = |n: &str| r.logs().iter().filter(|l| l.contains(&format!("\"event\":\"{n}\""))).count();
        let leg2_umbra: f64 =
            gas_by_receipt(&r).iter().filter(|(x, _)| x == umq || x == NVDA).map(|(_, g)| g).sum();
        let row = format!(
            "chain leg2 {l2} TGas: ok={} done={} held={} total_burnt={:.1}T leg2(NVDAon+umbra receipts)={leg2_umbra:.1}T fails={}",
            r.is_success(), ev("route_done"), ev("route_held"), r.total_gas_burnt.as_gas() as f64 / 1e12, r.receipt_failures().len()
        );
        println!("{row}");
        chain_rows.push(row);
        if !r.is_success() {
            println!(
                "  {:?}",
                r.failures()
                    .iter()
                    .map(|f| format!("{:?}", (*f).clone().into_result().err())
                        .chars()
                        .take(300)
                        .collect::<String>())
                    .collect::<Vec<_>>()
            );
        }
    }
    let out = format!(
        "| pad | op | pad-tree burnt (TGas, at 250 attached) | min op gas (TGas) | recommended (min x1.3, /5) | per receipt |\n|---|---|---|---|---|---|\n{}\n\n{}\n",
        rows.join("\n"),
        chain_rows.join("\n")
    );
    if let Ok(p) = std::env::var("VENUES_GAS_OUT") {
        std::fs::write(p, &out)?;
    }
    println!("{out}");
    Ok(())
}

/// Measurement probe, second sandbox: Kelytra (real exchange 4jqrRK3f + launch token GnQgLK9T,
/// set up exactly as venues_kelytra.rs `kelytra`) and Aidols (aidols.near + aidol100, real code
/// and mainnet state, as venues_aidols.rs `pad_case`). Kelytra's op gas covers deposit ->
/// swap_curve -> withdraw with its #[private] callbacks.
#[tokio::test]
#[ignore = "measurement probe (~5 min): cargo test --test venues_token gas_probe -- --ignored --nocapture"]
async fn gas_probe_kelytra_aidols() -> Result<()> {
    let e = venv().await?;
    // --- Kelytra (copy of venues_kelytra.rs `kelytra`) ---
    const EX: &str = "exchange.kelytradevs.near";
    const VQ: &str = "862166287209043987756113807";
    let token_code =
        pinned("t0.exchange.kelytradevs.near", Some("GnQgLK9T3ryRJyqAav8hztcSuBBwDhnZosWSezCZ75vF")).await?;
    let gd =
        sub(&e.root, "gdeploy", 50 * NEAR).await?.deploy(&out("global_deployer")).await?.into_result()?;
    ok(gd.call("deploy").args_borsh(token_code).gas(Gas::from_tgas(300)).transact().await?)?;
    let ex =
        install_code(&e.worker, EX, &pinned(EX, Some("4jqrRK3fLRFuTyxruNFe4teQSGtahTdx3jo1GSSGTaos")).await?)
            .await?;
    let admin = keyed(&e, "kelytradevs.near").await?;
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
        ok(admin
            .call(ex.id(), m)
            .args_json(args)
            .deposit(NearToken::from_yoctonear(dep))
            .gas(Gas::from_tgas(40))
            .transact()
            .await?)?;
    }
    let dl = e.worker.view_block().await?.timestamp() + 600_000_000_000;
    ok(admin.call(ex.id(), "launch_curve_token_with_metadata")
        .args_json(json!({"name": "Kelytra Test", "symbol": "KTEST", "quote_id": e.wrap.id(),
            "expected_virtual_quote": VQ, "tax": {"extra_bps": 50, "destination": "developer"},
            "expected_creation_fee": NEAR.to_string(),
            "project": {"image": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=",
                "description": "sandbox", "website": null, "x": null, "telegram": null},
            "deadline": dl.to_string()}))
        .deposit(NearToken::from_yoctonear(1_414_970_000_000_000_000_000_000)).gas(Gas::from_tgas(300)).transact().await?)?;
    let kt0 = format!("t0.{EX}");
    // --- Aidols (aidols.near + aidol100.aidols.near, as venues_aidols.rs) ---
    let fac =
        import_mainnet(&e.worker, "aidols.near", Some("Csh7LRonCe1f7ndcizg8a3RqY2Huour6yHDeBcmHm43")).await?;
    let atok = "aidol100.aidols.near";
    import_mainnet(&e.worker, atok, Some("6RAJutV3eS21LHnrXaVN27hwn1K8ZJko59MUxEgLrpSp")).await?;
    fund_wnear(&e, &fac, 1_000 * NEAR).await?;
    for p in ["aidols-treasury.near", "wallet.intear.near"] {
        ensure(&e, p).await?;
        ok(e.root
            .call(e.wrap.id(), "storage_deposit")
            .args_json(json!({"account_id": p, "registration_only": true}))
            .deposit(NearToken::from_millinear(13))
            .transact()
            .await?)?;
    }
    let t = e
        .ta(
            "gk",
            50 * NEAR,
            (20 * NEAR, 1_000 * NEAR),
            vec![
                json!({"id": EX, "kind": "Kelytra"}),
                json!({"id": "aidols.near", "kind": {"AidolsCurve": "Near"}}),
            ],
        )
        .await?;
    ok(e.exec(&t, json!([{"NearDeposit": {"amount": (10 * NEAR).to_string()}}]), "wrap10", 11 * NEAR)
        .await?)?;
    let st: Value = e.worker.view(&kt0.parse()?, "storage_balance_bounds").await?.json()?;
    ok(e.exec(
        &t,
        json!([storage(&kt0, u(&st["min"])),
        {"CurveClaim": {"venue": EX, "action": "KelytraRegister", "token": e.wrap.id()}},
        {"CurveClaim": {"venue": EX, "action": "KelytraRegister", "token": kt0}}]),
        "kreg",
        NEAR,
    )
    .await?)?;
    ok(e.root
        .call(&atok.parse()?, "storage_deposit")
        .args_json(json!({"account_id": t.id, "registration_only": true}))
        .deposit(NearToken::from_millinear(13))
        .transact()
        .await?)?;

    let mut rows = vec![];
    let mut add = |pad: &str, op: &str, res: (f64, Vec<(String, f64)>, u64)| {
        let (tree, per, min) = res;
        let per_s = per
            .iter()
            .map(|(x, g)| format!("{}:{g:.1}", x.split('.').next().unwrap_or(x)))
            .collect::<Vec<_>>()
            .join(" ");
        let row = format!("| {pad} | {op} | {tree:.1} | {min} | {} | {per_s} |", rec(min));
        println!("{row}");
        rows.push(row);
    };
    let kt = |side: &str, a: u128, g: u64| json!([gtrade(side, EX, a, 1, g, json!({"market": "0"}))]);
    add(
        "Kelytra",
        "buy (deposit -> swap_curve -> withdraw)",
        gas_case(&e, &t, "k-b", 20, &|g| kt("CurveBuy", NEAR / 10, g), NEAR).await?,
    );
    let ks = e.ft(&kt0.parse()?, &t.id).await? / 40;
    add(
        "Kelytra",
        "sell (deposit -> swap_curve -> withdraw)",
        gas_case(&e, &t, "k-s", 20, &|g| kt("CurveSell", ks, g), NEAR).await?,
    );
    // setup (first trade from a NEAR-only account, ONE op; contract >= 413a6368): a fresh account
    // per trial, since a success registers it. Checked at 225 and 224.
    for g in [225u64, 224] {
        let f = e
            .ta(
                &format!("gks{g}"),
                10 * NEAR,
                (5 * NEAR, 100 * NEAR),
                vec![json!({"id": EX, "kind": "Kelytra"})],
            )
            .await?;
        let op = gtrade("CurveBuy", EX, NEAR / 10, 1, g, json!({"market": "0", "setup": true}));
        let r = e.exec(&f, json!([op]), &format!("ks-{g}"), NEAR).await?;
        let ok_ = u(&settled(&r)["used"]) > 0 && r.receipt_failures().is_empty();
        let tree: f64 =
            gas_by_receipt(&r).into_iter().filter(|(x, _)| x != f.id.as_str()).map(|(_, x)| x).sum();
        let err = format!("{:?}", r.clone().into_result().err())
            .split("ExecutionError(")
            .nth(1)
            .map(|x| x.chars().take(60).collect::<String>())
            .unwrap_or_default();
        println!("KELYTRA SETUP buy at {g} TGas: ok={ok_} burnt={tree:.1} {err}");
    }
    let ad =
        |side: &str, a: u128, g: u64| json!([gtrade(side, "aidols.near", a, 1, g, json!({"market": atok}))]);
    add(
        "Aidols (aidols.near)",
        "buy (wNEAR ft_transfer_call)",
        gas_case(&e, &t, "a-b", 20, &|g| ad("CurveBuy", NEAR / 10, g), NEAR).await?,
    );
    let asell = e.ft(&atok.parse()?, &t.id).await? / 40;
    add(
        "Aidols (aidols.near)",
        "sell (token ft_transfer_call, wNEAR out)",
        gas_case(&e, &t, "a-s", 20, &|g| ad("CurveSell", asell, g), NEAR).await?,
    );
    let out = format!("{}\n", rows.join("\n"));
    if let Ok(p) = std::env::var("VENUES_GAS_OUT2") {
        std::fs::write(p, &out)?;
    }
    println!("{out}");
    Ok(())
}

/// (name, factory, factory code hash, DexKind JSON, payees created empty, registration before a buy)
type FactoryPadSpec =
    (&'static str, &'static str, &'static str, Value, &'static [&'static str], Option<u128>);

/// Measurement probe, third sandbox: factory-held curves with the real code + mainnet state, set
/// up as venues_factory.rs `near_pad` (Nearrr arcova-m6ez 48oZBxXP, dragonpad ember 3gqUU3rD,
/// Vista launch vv-1 DjxyjbtX; payees created empty).
#[tokio::test]
#[ignore = "measurement probe (~5 min): cargo test --test venues_token gas_probe -- --ignored --nocapture"]
async fn gas_probe_factory_pads() -> Result<()> {
    let e = venv().await?;
    let pads: [FactoryPadSpec; 3] = [
        (
            "Nearrr",
            "nearrr-fun.near",
            "48oZBxXPg6SyW9HwMbyXYNQnEEWUSCRxNte9DtYyTdCr",
            json!({"FactoryCurve": "Nearrr"}),
            &[
                "grandpalace7442.near",
                "leftcity7777.near",
                "locker2.nearrr-fun.near",
                "lpvault.nearrr-fun.near",
            ],
            Some(2_210_000_000_000_000_000_000),
        ),
        (
            "dragonpad",
            "dragonpad.near",
            "3gqUU3rDaJ8xw61iBwHa65ygy1BnHKLHK3Wo3GcAgCUC",
            json!({"FactoryCurve": "Dragonpad"}),
            &["lp-burn.dragonpad.near"],
            None,
        ),
        (
            "Vista launch",
            "launch.vistadev.near",
            "DjxyjbtXeVP3eapCZVgUG9dhPmvdAkZMfpFMT6gqunFi",
            json!({"FactoryCurve": "VistaLaunch"}),
            &["vistadev.near", "faruni8562.near"],
            None,
        ),
    ];
    let tokens = ["arcova-m6ez.nearrr-fun.near", "ember.dragonpad.near", "vv-1.launch.vistadev.near"];
    let mut dexes = vec![];
    for ((_, f, h, kind, payees, _), tok) in pads.iter().zip(tokens) {
        import_mainnet(&e.worker, f, Some(h)).await?;
        import_mainnet(&e.worker, tok, None).await?;
        for p in payees.iter() {
            ensure(&e, p).await?;
        }
        dexes.push(json!({"id": f, "kind": kind}));
    }
    let t = e.ta("gf", 50 * NEAR, (20 * NEAR, 1_000 * NEAR), dexes).await?;
    let mut rows = vec![];
    for ((name, f, _, _, _, reg), tok) in pads.iter().zip(tokens) {
        // a registration the pad requires goes with the first buy (same venue: allowed)
        if let Some(sd) = reg {
            ok(e.exec(
                &t,
                json!([storage(tok, *sd), gtrade("CurveBuy", f, NEAR / 10, 1, 250, json!({"market": tok}))]),
                &format!("{name}-first"),
                NEAR,
            )
            .await?)?;
        }
        // dragonpad fully refunds a 0.1 N buy (used 0, no failed receipt): 0.5 N as venues_factory.rs
        let a = if *name == "dragonpad" { NEAR / 2 } else { NEAR / 10 };
        let res = gas_case(
            &e,
            &t,
            &format!("{name}-b"),
            20,
            &|g| json!([gtrade("CurveBuy", f, a, 1, g, json!({"market": tok}))]),
            NEAR,
        )
        .await?;
        rows.push(row(name, "buy (NEAR, payable)", res));
        let a = e.ft(&tok.parse()?, &t.id).await? / 40;
        let res = gas_case(
            &e,
            &t,
            &format!("{name}-s"),
            20,
            &|g| json!([gtrade("CurveSell", f, a, 1, g, json!({"market": tok}))]),
            NEAR,
        )
        .await?;
        rows.push(row(name, "sell (token ft_transfer_call, native payout)", res));
    }
    let out = format!("{}\n", rows.join("\n"));
    if let Ok(p) = std::env::var("VENUES_GAS_OUT3") {
        std::fs::write(p, &out)?;
    }
    println!("{out}");
    Ok(())
}

fn row(pad: &str, op: &str, res: (f64, Vec<(String, f64)>, u64)) -> String {
    let (tree, per, min) = res;
    let per_s = per
        .iter()
        .map(|(x, g)| format!("{}:{g:.1}", x.split('.').next().unwrap_or(x)))
        .collect::<Vec<_>>()
        .join(" ");
    let r = format!("| {pad} | {op} | {tree:.1} | {min} | {} | {per_s} |", rec(min));
    println!("{r}");
    r
}
