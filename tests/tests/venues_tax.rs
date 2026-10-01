//! v1.6 taxed tokens (venues/tax.rs): a 24/7 order fire whose output token taxes transfers after
//! the DEX's min_out check is gated on the token's REAL tax view (mainnet code + state of
//! jensen.nearrr-fun.near, Tax mode 50 = 150 bps delivered short; measured in tax_probe).
//! The DEX is an allowlisted account without code: a passing gate forwards the swap (it fails there
//! and wrap refunds), a refusing gate never sends it. Both reopen the order; only the refusal logs
//! `tax_gate_refused`.
mod venues_common;
use anyhow::{anyhow, Result};
use integration_tests::*;
use near_workspaces::types::{Gas, NearToken};
use near_workspaces::AccountId;
use serde_json::{json, Value};
use venues_common::*;

const TOK: &str = "jensen.nearrr-fun.near";

async fn install_taxed(e: &VEnv) -> Result<AccountId> {
    use base64::Engine;
    let path = format!("{}/fixtures/venues/{TOK}.state.json", env!("CARGO_MANIFEST_DIR"));
    let v: Value = match std::fs::read(&path) {
        Ok(b) => serde_json::from_slice(&b)?,
        Err(_) => {
            let body = json!({"jsonrpc": "2.0", "id": 1, "method": "query", "params": {"request_type": "view_state",
                "finality": "final", "account_id": TOK, "prefix_base64": ""}});
            let v: Value = reqwest::Client::new()
                .post("https://free.rpc.fastnear.com")
                .json(&body)
                .send()
                .await?
                .json()
                .await?;
            let r = v.get("result").cloned().ok_or_else(|| anyhow!("view_state: {v}"))?;
            std::fs::write(&path, serde_json::to_vec(&r)?)?;
            r
        }
    };
    let c = install_code(&e.worker, TOK, &mainnet_code(TOK).await?).await?;
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut p = e.worker.patch(c.id());
    for kv in v["values"].as_array().ok_or_else(|| anyhow!("bad state"))? {
        p = p.state(
            &b64.decode(kv["key"].as_str().unwrap_or(""))?,
            &b64.decode(kv["value"].as_str().unwrap_or(""))?,
        );
    }
    p.transact().await?;
    Ok(c.id().clone())
}

fn rhea_msg(wrap: &AccountId, out: &AccountId, amount: u128, min_out: u128) -> String {
    json!({"force": 0, "actions": [{"pool_id": 1, "token_in": wrap, "token_out": out,
        "amount_in": amount.to_string(), "amount_out": "0", "min_amount_out": min_out.to_string()}],
        "skip_unwrap_near": true})
    .to_string()
}

#[tokio::test]
async fn taxed_output_order_is_gated_on_the_real_tax_view() -> Result<()> {
    let e = venv().await?;
    let tok = install_taxed(&e).await?;
    let tax: Value = e.worker.view(&tok, "tax_state").await?.json()?;
    assert_eq!((tax["mode"].as_str(), tax["buy_tax_bps"].as_u64()), (Some("Tax"), Some(50)), "pinned state");
    let dex = sub(&e.root, "fakedex", NEAR).await?;
    // registered on wrap, so wrap forwards ft_on_transfer to it (which fails: no code)
    ok(dex
        .call(e.wrap.id(), "storage_deposit")
        .args_json(json!({}))
        .deposit(NearToken::from_yoctonear(STORAGE))
        .transact()
        .await?)?;
    let t = e
        .ta("tx", 10 * NEAR, (5 * NEAR, 10 * NEAR), vec![json!({"id": dex.id(), "kind": "RheaClassic"})])
        .await?;
    e.wrap_for(&t, 2 * NEAR).await?;
    let floor: u128 = 1_000_000_000_000_000_000_000; // order.min_out (post-tax floor)
    let exp = e.worker.view_block().await?.timestamp() + 3_600_000_000_000;
    let r = t
        .device
        .call(&t.id, "place_order")
        .args_json(json!({"token_in": e.wrap.id(), "token_out": tok, "amount_in": NEAR.to_string(),
            "min_out": floor.to_string(), "trigger_meta": "", "expires_at_ns": exp.to_string(), "dexes": [dex.id()]}))
        .gas(Gas::from_tgas(50))
        .transact()
        .await?;
    let id: String = okr(r)?.json()?;
    let fire = |min_out: u128| {
        json!([{"FtTransferCall": {"token": e.wrap.id(), "receiver_id": dex.id(), "amount": NEAR.to_string(),
            "msg": rhea_msg(e.wrap.id(), &tok, NEAR, min_out), "gas": (100 * TGAS).to_string()}}])
    };
    let w0 = e.ft(e.wrap.id(), &t.id).await?;

    // A: msg min_out == the floor -> the TA would get floor x 0.985: refused before any swap
    let r = t
        .device
        .call(&t.id, "execute_order")
        .args_json(json!({"order_id": id, "ops": fire(floor)}))
        .gas(Gas::from_tgas(300))
        .transact()
        .await?;
    assert!(r.is_success(), "{:?}", r.clone().into_result().err());
    let logs = r.logs().join("\n");
    assert!(logs.contains("\"tax_gate_refused\"") && logs.contains("\"tax_bps\":150"), "{logs}");
    assert!(logs.contains("\"order_reopened\""), "{logs}");
    assert!(!r.receipt_outcomes().iter().any(|o| o.executor_id == *dex.id()), "swap must not be sent");
    assert_eq!(e.ft(e.wrap.id(), &t.id).await?, w0, "nothing moved");

    // B: msg min_out = ceil(floor / 0.985) - 1 -> still refused (edge)
    let need = (floor * 10_000).div_ceil(9_850);
    let r = t
        .device
        .call(&t.id, "execute_order")
        .args_json(json!({"order_id": id, "ops": fire(need - 1)}))
        .gas(Gas::from_tgas(300))
        .transact()
        .await?;
    assert!(r.logs().join("\n").contains("\"tax_gate_refused\""));

    // C: msg min_out = ceil(floor / 0.985) -> the gate passes and forwards the swap to the DEX
    // (no code there: wrap refunds, the order reopens as a provable wrap refund)
    let r = t
        .device
        .call(&t.id, "execute_order")
        .args_json(json!({"order_id": id, "ops": fire(need)}))
        .gas(Gas::from_tgas(300))
        .transact()
        .await?;
    assert!(r.is_success(), "{:?}", r.clone().into_result().err());
    let logs = r.logs().join("\n");
    assert!(!logs.contains("tax_gate_refused"), "{logs}");
    assert!(
        r.receipt_outcomes().iter().any(|o| o.executor_id == *dex.id()),
        "the swap reached the DEX after the gate"
    );
    assert!(logs.contains("\"order_reopened\""), "{logs}");
    assert_eq!(e.ft(e.wrap.id(), &t.id).await?, w0, "refunded");

    // C2: a gated fire at the Rhea op maximum (200 TGas) on a 300 TGas prepay still fits (op 200 +
    // action 5 + settle callback 15 + gate 23 = 243 <= 285): the swap is forwarded
    let at_max = json!([{"FtTransferCall": {"token": e.wrap.id(), "receiver_id": dex.id(), "amount": NEAR.to_string(),
        "msg": rhea_msg(e.wrap.id(), &tok, NEAR, need), "gas": (200 * TGAS).to_string()}}]);
    let r = t
        .device
        .call(&t.id, "execute_order")
        .args_json(json!({"order_id": id, "ops": at_max}))
        .gas(Gas::from_tgas(300))
        .transact()
        .await?;
    assert!(r.is_success(), "{:?}", r.clone().into_result().err());
    assert!(r.receipt_outcomes().iter().any(|o| o.executor_id == *dex.id()), "forwarded at max op gas");
    println!("gated fire at 200 TGas op gas: burnt {:.1} TGas", r.total_gas_burnt.as_gas() as f64 / 1e12);

    // D: device execute is not gated (DR-1: the client sizes the msg)
    let r = e.exec(&t, fire(floor), "dev1", 2 * NEAR).await?;
    assert!(!r.logs().join("\n").contains("tax_gate_refused"));
    assert!(r.receipt_outcomes().iter().any(|o| o.executor_id == *dex.id()));
    println!("gated fire gas burnt: {:.1} TGas", r.total_gas_burnt.as_gas() as f64 / 1e12);
    Ok(())
}

/// R2-06: the gate reads a tax view up to 16 KiB (MAX_VIEW_LEN) and refuses a longer one. Real
/// code of ribbit-2.nearlytrade.near (nearly taxed template, 1uGuBEpx), with its stored tax
/// config (key "t") padded by `exempt` accounts to a get_tax result just under 16 KiB. Measures
/// that such a view fits GAS_TAX_VIEW (5 TGas) and that on_tax_gate parses it in its budget:
/// the 1% tax is read (refused at the floor, forwarded at the pre-tax min).
#[tokio::test]
async fn r2_06_near_16k_tax_view_fits_the_gate() -> Result<()> {
    const NTOK: &str = "ribbit-2.nearlytrade.near";
    const MAX_VIEW_LEN: usize = 16_384;
    let e = venv().await?;
    let tok = install_code(&e.worker, NTOK, &mainnet_code(NTOK).await?).await?;
    let dex = sub(&e.root, "fakedex", NEAR).await?;
    ok(dex
        .call(e.wrap.id(), "storage_deposit")
        .args_json(json!({}))
        .deposit(NearToken::from_yoctonear(STORAGE))
        .transact()
        .await?)?;
    // the stored config, as on mainnet (2026-10-01) but with the fake DEX as the taxed pair and
    // `n` padding accounts in `exempt`
    let set_tax = |n: usize| {
        let mut exempt: Vec<String> = vec!["lock2.nearlytrade.near".into(), "feeswap.near".into()];
        exempt.extend((0..n).map(|i| format!("exempt-account-number-{i:05}.near")));
        let t = json!({"buy_bps": 100, "sell_bps": 100, "pairs": [dex.id()], "admin": "nearlytrade.near",
            "exempt": exempt});
        e.worker.patch(tok.id()).state(b"t", t.to_string().as_bytes()).transact()
    };
    // get_tax = {"tax":<t>,"pending":"<u128>"}
    let view_len =
        || async { Ok::<usize, anyhow::Error>(e.worker.view(tok.id(), "get_tax").await?.result.len()) };
    // the largest padding whose get_tax result is <= MAX_VIEW_LEN (each entry is 34 bytes + comma)
    set_tax(0).await?;
    let base = view_len().await?;
    let fit = (MAX_VIEW_LEN - base) / 35;
    set_tax(fit).await?;
    let near_max = view_len().await?;
    assert!(near_max <= MAX_VIEW_LEN && near_max > MAX_VIEW_LEN - 64, "view is {near_max} bytes");
    let tax: Value = e.worker.view(tok.id(), "get_tax").await?.json()?;
    assert_eq!(tax["tax"]["buy_bps"].as_u64(), Some(100), "{}", &tax.to_string()[..200]);

    let t = e
        .ta("tx", 10 * NEAR, (5 * NEAR, 10 * NEAR), vec![json!({"id": dex.id(), "kind": "RheaClassic"})])
        .await?;
    e.wrap_for(&t, 2 * NEAR).await?;
    let floor: u128 = 1_000_000_000_000_000_000_000;
    let need = (floor * 10_000).div_ceil(9_900);
    let exp = e.worker.view_block().await?.timestamp() + 3_600_000_000_000;
    let r = t
        .device
        .call(&t.id, "place_order")
        .args_json(json!({"token_in": e.wrap.id(), "token_out": tok.id(), "amount_in": NEAR.to_string(),
            "min_out": floor.to_string(), "trigger_meta": "", "expires_at_ns": exp.to_string(), "dexes": [dex.id()]}))
        .gas(Gas::from_tgas(50))
        .transact()
        .await?;
    let id: String = okr(r)?.json()?;
    let fire = |min_out: u128| {
        json!([{"FtTransferCall": {"token": e.wrap.id(), "receiver_id": dex.id(), "amount": NEAR.to_string(),
            "msg": rhea_msg(e.wrap.id(), tok.id(), NEAR, min_out), "gas": (100 * TGAS).to_string()}}])
    };
    let run = |min_out: u128| {
        t.device
            .call(&t.id, "execute_order")
            .args_json(json!({"order_id": id, "ops": fire(min_out)}))
            .gas(Gas::from_tgas(300))
            .transact()
    };
    let view_gas = |r: &near_workspaces::result::ExecutionFinalResult| {
        let o = r
            .receipt_outcomes()
            .iter()
            .find(|o| o.executor_id == *tok.id())
            .expect("the tax view ran")
            .clone();
        assert!(o.is_success(), "the ~16 KiB view failed: {:?}", o);
        o.gas_burnt.as_gas() as f64 / 1e12
    };
    // on_tax_gate on a refusal: the receipt that logs tax_gate_refused (parse + settle)
    let gate_gas = |r: &near_workspaces::result::ExecutionFinalResult| {
        let o = r
            .receipt_outcomes()
            .iter()
            .find(|o| o.logs.iter().any(|l| l.contains("tax_gate_refused")))
            .unwrap();
        o.gas_burnt.as_gas() as f64 / 1e12
    };

    // A: min_out == floor: the 1% is read from the ~16 KiB view -> refused with tax_bps 100
    let r = run(floor).await?;
    assert!(r.is_success(), "{:?}", r.clone().into_result().err());
    let logs = r.logs().join("\n");
    assert!(logs.contains("\"tax_gate_refused\"") && logs.contains("\"tax_bps\":100"), "{logs}");
    assert!(!r.receipt_outcomes().iter().any(|o| o.executor_id == *dex.id()), "swap must not be sent");
    let (vg, gg) = (view_gas(&r), gate_gas(&r));
    println!(
        "view of {near_max} B: view burnt {vg:.2} TGas (GAS_TAX_VIEW 5), on_tax_gate {gg:.2} TGas (static 8)"
    );
    assert!(vg < 5.0 && gg < 8.0);

    // B: min_out = the pre-tax min: the gate passes and forwards the swap
    let r = run(need).await?;
    assert!(r.is_success(), "{:?}", r.clone().into_result().err());
    let logs = r.logs().join("\n");
    assert!(!logs.contains("tax_gate_refused"), "{logs}");
    assert!(r.receipt_outcomes().iter().any(|o| o.executor_id == *dex.id()), "forwarded after the gate");
    assert!(logs.contains("\"order_reopened\""), "{logs}");
    println!("pass: view burnt {:.2} TGas", view_gas(&r));

    // C: one entry more (> 16 KiB): refused as unreadable (tax_bps null), never read as untaxed
    set_tax(fit + 1).await?;
    let over = view_len().await?;
    assert!(over > MAX_VIEW_LEN, "{over}");
    let r = run(need).await?;
    assert!(r.is_success(), "{:?}", r.clone().into_result().err());
    let logs = r.logs().join("\n");
    assert!(logs.contains("\"tax_gate_refused\"") && logs.contains("\"tax_bps\":null"), "{logs}");
    assert!(!r.receipt_outcomes().iter().any(|o| o.executor_id == *dex.id()), "swap must not be sent");
    println!("over ({over} B): view burnt {:.2} TGas", view_gas(&r));
    Ok(())
}

/// R2-06 (owner decision): a failed tax view reads as 0. Real code of aaalex.nearlytrade.near
/// (B6EjqsNJ, nearly's current untaxed template, no get_tax): the view fails with MethodNotFound
/// and the gate forwards the swap at the plain floor.
#[tokio::test]
async fn r2_06_untaxed_template_failed_view_reads_0() -> Result<()> {
    const UTOK: &str = "aaalex.nearlytrade.near";
    let e = venv().await?;
    let tok = install_code(&e.worker, UTOK, &mainnet_code(UTOK).await?).await?;
    let dex = sub(&e.root, "fakedex", NEAR).await?;
    ok(dex
        .call(e.wrap.id(), "storage_deposit")
        .args_json(json!({}))
        .deposit(NearToken::from_yoctonear(STORAGE))
        .transact()
        .await?)?;
    let t = e
        .ta("tx", 10 * NEAR, (5 * NEAR, 10 * NEAR), vec![json!({"id": dex.id(), "kind": "RheaClassic"})])
        .await?;
    e.wrap_for(&t, 2 * NEAR).await?;
    let floor: u128 = 1_000_000_000_000_000_000_000;
    let exp = e.worker.view_block().await?.timestamp() + 3_600_000_000_000;
    let r = t
        .device
        .call(&t.id, "place_order")
        .args_json(json!({"token_in": e.wrap.id(), "token_out": tok.id(), "amount_in": NEAR.to_string(),
            "min_out": floor.to_string(), "trigger_meta": "", "expires_at_ns": exp.to_string(), "dexes": [dex.id()]}))
        .gas(Gas::from_tgas(50))
        .transact()
        .await?;
    let id: String = okr(r)?.json()?;
    let ops = json!([{"FtTransferCall": {"token": e.wrap.id(), "receiver_id": dex.id(), "amount": NEAR.to_string(),
        "msg": rhea_msg(e.wrap.id(), tok.id(), NEAR, floor), "gas": (100 * TGAS).to_string()}}]);
    let r = t
        .device
        .call(&t.id, "execute_order")
        .args_json(json!({"order_id": id, "ops": ops}))
        .gas(Gas::from_tgas(300))
        .transact()
        .await?;
    assert!(r.is_success(), "{:?}", r.clone().into_result().err());
    let view =
        r.receipt_outcomes().iter().find(|o| o.executor_id == *tok.id()).expect("the tax view ran").clone();
    assert!(view.is_failure(), "get_tax must not exist on the untaxed template");
    let logs = r.logs().join("\n");
    assert!(!logs.contains("tax_gate_refused"), "{logs}");
    assert!(r.receipt_outcomes().iter().any(|o| o.executor_id == *dex.id()), "forwarded at the floor");
    Ok(())
}
