//! v1.6 routes (docs/routing-v16-design.md Part C) in the sandbox with REAL wrap.near, Rhea classic
//! (v2.ref-finance.near), Rhea DCL (dclv2.ref-labs.near) and intents.near mainnet code:
//! - `Chain` NEAR -> Q (Rhea classic) -> MEME (DCL): done path, fee on the NEAR leg, Q lock released;
//! - leg 2 refused (min_final above the pool) -> `route_held`, Q stays in the wallet for the route;
//! - `IntentsSwap` funds a 1Click deposit address in intents.near (test key as 1Click), a solver
//!   delivers Q to the account's intents balance, the continuation (`execute_order` on the cont id)
//!   pulls and swaps within the stored terms; an out-of-terms continuation is refused;
//! - gas: CHAIN_OVERHEAD_TGAS vs what a Chain actually burns (printed; `--nocapture`).
//!
//! Account wasm: NT_ACCOUNT_WASM (the v1.6 build with hook sets 1 + 2).
use anyhow::Result;
use ed25519_dalek::{Signer, SigningKey};
use integration_tests::*;
use near_workspaces::types::{Gas, NearToken};
use near_workspaces::{AccountId, Contract};
use serde_json::{json, Map, Value};

fn stable(m: &Map<String, Value>) -> String {
    let mut ks: Vec<&String> = m.keys().collect();
    ks.sort();
    let body: Vec<String> = ks
        .iter()
        .map(|k| format!("{}:{}", serde_json::to_string(k).unwrap(), serde_json::to_string(&m[*k]).unwrap()))
        .collect();
    format!("{{{}}}", body.join(","))
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

fn iso(ns: u64) -> String {
    let s = ns / 1_000_000_000;
    let (y, m, d) = civil_from_days((s / 86_400) as i64);
    let r = s % 86_400;
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.000Z", r / 3600, r / 60 % 60, r % 60)
}

fn key() -> SigningKey {
    SigningKey::from_bytes(&[11u8; 32])
}

fn pk_str(sk: &SigningKey) -> String {
    format!("ed25519:{}", bs58::encode(sk.verifying_key().to_bytes()).into_string())
}

fn sign(sk: &SigningKey, s: &str) -> String {
    use sha2::Digest;
    let msg = bs58::encode(sha2::Sha256::digest(s.as_bytes())).into_string();
    format!("ed25519:{}", bs58::encode(sk.sign(msg.as_bytes()).to_bytes()).into_string())
}

async fn account_env() -> Result<Env> {
    let wasm = std::env::var("NT_ACCOUNT_WASM").ok().map(|p| std::fs::read(p).expect("NT_ACCOUNT_WASM"));
    Env::new_with(wasm, None).await
}

/// This build + the Shards factory allowlisted (ShardsToken entry).
async fn shards_env() -> Result<Env> {
    let wasm = std::env::var("NT_ACCOUNT_WASM").ok().map(|p| std::fs::read(p).expect("NT_ACCOUNT_WASM"));
    Env::new_with_dexes(wasm, None, vec![json!({"id": SHARDS_FACTORY, "kind": "ShardsToken"})]).await
}

/// A second mock NEP-141 `q` with pools wNEAR/Q (Rhea classic, 100 N : 1e24 Q) and Q/MEME (DCL).
async fn q_pools(env: &Env) -> Result<(Contract, u64, String)> {
    let qa = sub(&env.root, "q", 50 * NEAR).await?;
    let q = qa.deploy(&out("mock_ft")).await?.into_result()?;
    ok(q.call("new").transact().await?)?;
    q_pools_for(env, q).await
}

/// Pools for an existing mock NEP-141 `q` (e.g. installed at a real quote id).
async fn q_pools_for(env: &Env, q: Contract) -> Result<(Contract, u64, String)> {
    let lp = sub(&env.root, "qlp", 400 * NEAR).await?;
    let big = 1_000_000 * NEAR;
    for acc in [env.rhea.id(), lp.id(), env.dcl.id()] {
        ok(q.call("mint").args_json(json!({"account_id": acc, "amount": "0"})).transact().await?)?;
    }
    ok(q.call("mint")
        .args_json(json!({"account_id": lp.id(), "amount": big.to_string()}))
        .transact()
        .await?)?;
    ok(env
        .meme
        .call("mint")
        .args_json(json!({"account_id": lp.id(), "amount": big.to_string()}))
        .transact()
        .await?)?;
    ok(env
        .meme
        .call("mint")
        .args_json(json!({"account_id": env.dcl.id(), "amount": "0"}))
        .transact()
        .await?)?;
    ok(lp
        .call(env.wrap.id(), "storage_deposit")
        .args_json(json!({}))
        .deposit(NearToken::from_yoctonear(STORAGE))
        .transact()
        .await?)?;
    ok(lp
        .call(env.wrap.id(), "near_deposit")
        .args_json(json!({}))
        .deposit(NearToken::from_near(200))
        .transact()
        .await?)?;
    // classic wNEAR/Q
    let owner = &lp;
    ok(owner
        .call(env.rhea.id(), "storage_deposit")
        .args_json(json!({}))
        .deposit(NearToken::from_near(1))
        .transact()
        .await?)?;
    ok(owner
        .call(env.rhea.id(), "register_tokens")
        .args_json(json!({"token_ids": [env.wrap.id(), q.id()]}))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?)?;
    let pid = owner
        .call(env.rhea.id(), "add_simple_pool")
        .args_json(json!({"tokens": [env.wrap.id(), q.id()], "fee": 25}))
        .deposit(NearToken::from_millinear(100))
        .transact()
        .await?;
    let pool: u64 = okr(pid)?.json()?;
    for (t, amt) in [(env.wrap.id(), 100 * NEAR), (q.id(), 100 * NEAR)] {
        ok(owner
            .call(t, "ft_transfer_call")
            .args_json(json!({"receiver_id": env.rhea.id(), "amount": amt.to_string(), "msg": ""}))
            .deposit(NearToken::from_yoctonear(1))
            .gas(Gas::from_tgas(100))
            .transact()
            .await?)?;
    }
    ok(owner
        .call(env.rhea.id(), "add_liquidity")
        .args_json(json!({"pool_id": pool, "amounts": [(100 * NEAR).to_string(), (100 * NEAR).to_string()]}))
        .deposit(NearToken::from_millinear(10))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?)?;
    // DCL Q/MEME
    let dcl = env.dcl.id();
    let r = lp
        .call(dcl, "create_pool")
        .args_json(json!({"token_a": q.id(), "token_b": env.meme.id(), "fee": 2000, "init_point": 0}))
        .deposit(NearToken::from_near(1))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?;
    let dpid: String = okr(r)?.json()?;
    ok(lp
        .call(dcl, "storage_deposit")
        .args_json(json!({}))
        .deposit(NearToken::from_near(1))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?)?;
    for t in [q.id(), env.meme.id()] {
        ok(lp
            .call(t, "ft_transfer_call")
            .args_json(json!({"receiver_id": dcl, "amount": (100 * NEAR).to_string(), "msg": "\"Deposit\""}))
            .deposit(NearToken::from_yoctonear(1))
            .gas(Gas::from_tgas(100))
            .transact()
            .await?)?;
    }
    ok(lp.call(dcl, "add_liquidity").args_json(json!({"pool_id": dpid, "left_point": -8000, "right_point": 8000,
        "amount_x": (90 * NEAR).to_string(), "amount_y": (90 * NEAR).to_string(), "min_amount_x": "0", "min_amount_y": "0"}))
        .gas(Gas::from_tgas(200)).transact().await?)?;
    Ok((q, pool, dpid))
}

#[allow(clippy::too_many_arguments)]
fn chain_op(
    env: &Env,
    q: &AccountId,
    pool: u64,
    dpid: &str,
    amount: u128,
    min_mid: u128,
    max_mid: u128,
    min_final: u128,
) -> Value {
    let leg1 = json!({"FtTransferCall": {"token": env.wrap.id(), "receiver_id": env.rhea.id(), "amount": amount.to_string(),
        "msg": json!({"force": 0, "actions": [{"pool_id": pool, "token_in": env.wrap.id(), "token_out": q, "amount_in": amount.to_string(),
            "amount_out": "0", "min_amount_out": min_mid.to_string()}], "skip_unwrap_near": true}).to_string(),
        "gas": (80 * TGAS).to_string()}});
    let leg2 = json!({"FtTransferCall": {"token": q, "receiver_id": env.dcl.id(), "amount": "0",
        "msg": json!({"Swap": {"pool_ids": [dpid], "output_token": env.meme.id(), "min_output_amount": min_final.to_string()}}).to_string(),
        "gas": (80 * TGAS).to_string()}});
    json!({"Chain": {"leg1": leg1, "leg2": leg2, "q": q, "min_mid": min_mid.to_string(), "max_mid": max_mid.to_string(),
        "min_final": min_final.to_string()}})
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

/// Prints every EVENT_JSON log of `r` with its emitter (delivery evidence, `--nocapture`).
fn evidence(what: &str, r: &near_workspaces::result::ExecutionFinalResult) {
    println!("=== {what}");
    for o in r.receipt_outcomes() {
        for l in o.logs.iter().filter(|l| l.starts_with("EVENT_JSON:")) {
            println!("  [{}] {}", o.executor_id, l);
        }
    }
}

fn burnt(r: &near_workspaces::result::ExecutionFinalResult) -> f64 {
    r.total_gas_burnt.as_gas() as f64 / 1e12
}

#[tokio::test]
async fn chain_buy_done_and_held() -> Result<()> {
    let env = account_env().await?;
    let (q, pool, dpid) = q_pools(&env).await?;
    let u = env.user("ch", 10 * NEAR, (5 * NEAR, 20 * NEAR)).await?;
    let ta = &u.account;
    // storage on the output token (mock ft needs none) and the account's Q registration
    ok(q.call("mint").args_json(json!({"account_id": ta, "amount": "0"})).transact().await?)?;
    ok(env.meme.call("mint").args_json(json!({"account_id": ta, "amount": "0"})).transact().await?)?;
    let fees0 = env.near_balance(env.fees.id()).await?;
    let amount = NEAR;
    let mid: String = env
        .rhea
        .view("get_return")
        .args_json(json!({"pool_id": pool, "token_in": env.wrap.id(), "amount_in": amount.to_string(), "token_out": q.id()}))
        .await?
        .json()?;
    let mid: u128 = mid.parse()?;
    let ops = json!([{"NearDeposit": {"amount": amount.to_string()}}, chain_op(&env, q.id(), pool, &dpid, amount, mid * 99 / 100, mid * 101 / 100, mid / 2)]);
    let r = env.exec(&u.device, ta, ops, "c1", 2 * NEAR).await?;
    assert!(r.is_success(), "{:?}", r.failures());
    assert!(r.receipt_failures().is_empty(), "{:?}", r.receipt_failures());
    let meme = env.ft_balance(env.meme.id(), ta).await?;
    assert!(meme >= mid / 2, "MEME out {meme}");
    assert_eq!(env.ft_balance(q.id(), ta).await?, 0, "all of leg 1's Q was spent by leg 2");
    assert_eq!(events(&r, "route_done").len(), 1);
    let settled = &events(&r, "settled")[0];
    assert_eq!(settled["fee"], (amount / 100).to_string(), "fee on the NEAR leg (leg 1 input)");
    assert_eq!(env.near_balance(env.fees.id()).await? - fees0, amount / 100);
    let lock: Value = env.worker.view(ta, "get_q_lock").args_json(json!({"q": q.id()})).await?.json()?;
    assert!(lock.is_null(), "unlocked");
    println!("CHAIN done: total burnt {:.1} TGas; per receipt {:?}", burnt(&r), gas_by_receipt(&r));

    // leg 2 refused: min_final far above what the DCL pool gives -> held, Q stays for the route
    let ops = json!([{"NearDeposit": {"amount": amount.to_string()}}, chain_op(&env, q.id(), pool, &dpid, amount, 1, mid * 2, 1000 * NEAR)]);
    let r = env.exec(&u.device, ta, ops, "c2", 2 * NEAR).await?;
    assert!(r.is_success(), "{:?}", r.failures());
    let held = events(&r, "route_held");
    assert_eq!(held.len(), 1, "{:?}", r.logs());
    assert_eq!(held[0]["reason"], "leg2_failed");
    let q_bal = env.ft_balance(q.id(), ta).await?;
    assert!(q_bal > 0 && held[0]["amount"] == q_bal.to_string(), "held Q {q_bal} vs {:?}", held[0]);
    let route: Value = env.worker.view(ta, "get_route").args_json(json!({"id": "c2"})).await?.json()?;
    assert_eq!(route["state"], "Held");
    assert_eq!(route["credited"], q_bal.to_string());
    let lock: Value = env.worker.view(ta, "get_q_lock").args_json(json!({"q": q.id()})).await?.json()?;
    assert!(lock.is_null(), "unlocked after held");
    // leg 1's NEAR fee is earned (leg 1 happened)
    assert_eq!(events(&r, "settled")[0]["fee"], (amount / 100).to_string());
    // a plain sell of the held Q works again (no lock)
    Ok(())
}

async fn install_intents(env: &Env) -> Result<AccountId> {
    let c = install_mainnet(&env.worker, "intents.near").await?;
    ok(c.call("new")
        .args_json(json!({"config": {"wnear_id": env.wrap.id(), "fees": {"fee": 0, "fee_collector": env.fees.id()}, "roles": {}}}))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?)?;
    ok(env
        .root
        .call(env.wrap.id(), "storage_deposit")
        .args_json(json!({"account_id": c.id()}))
        .deposit(NearToken::from_millinear(125))
        .transact()
        .await?)?;
    Ok(c.id().clone())
}

async fn mt_balance(env: &Env, intents: &AccountId, who: &str, token: &AccountId) -> Result<u128> {
    let v: String = env
        .worker
        .view(intents, "mt_balance_of")
        .args_json(json!({"account_id": who, "token_id": format!("nep141:{token}")}))
        .await?
        .json()?;
    Ok(v.parse()?)
}

#[tokio::test]
async fn intents_swap_then_continuation() -> Result<()> {
    let env = account_env().await?;
    let intents = install_intents(&env).await?;
    let (q, _pool, dpid) = q_pools(&env).await?;
    let u = env.user("ix", 10 * NEAR, (5 * NEAR, 20 * NEAR)).await?;
    let ta = u.account.clone();
    // a fresh account: registered on neither Q nor the output token (never held)
    ok(q.call("mint").args_json(json!({"account_id": intents, "amount": "0"})).transact().await?)?;
    for t in [q.id(), env.meme.id()] {
        let sb: Value =
            env.worker.view(t, "storage_balance_of").args_json(json!({"account_id": ta})).await?.json()?;
        assert!(sb.is_null(), "fresh account");
    }
    ok(u.owner
        .call(&ta, "owner_set_oneclick_config")
        .args_json(json!({"keys": [pk_str(&key())], "max_slippage_bps": 300, "intents": intents}))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?)?;
    let addr = "ab".repeat(32);
    let now = env.now_ns().await?;
    let amount = NEAR;
    let q_quoted = NEAR / 2;
    let quote = json!({
        "dry": false, "swapType": "EXACT_INPUT", "depositType": "INTENTS",
        "originAsset": format!("nep141:{}", env.wrap.id()), "destinationAsset": format!("nep141:{}", q.id()),
        "amount": amount.to_string(), "amountIn": amount.to_string(),
        "refundTo": ta, "refundType": "INTENTS", "recipient": ta, "recipientType": "INTENTS",
        "slippageTolerance": 100, "minAmountOut": (q_quoted * 99 / 100).to_string(), "amountOut": q_quoted.to_string(),
        "amountInUsd": "5.00", "amountOutUsd": "4.97", "deadline": iso(now + 600_000_000_000), "timestamp": iso(now),
        "depositAddress": addr, "depositMemo": null, "customRecipientMsg": null});
    let s = stable(quote.as_object().unwrap());
    let sig = sign(&key(), &s);
    let cont = json!({"token_out": env.meme.id(), "dexes": [env.dcl.id()], "min_final": "1"});
    let op = json!({"IntentsSwap": {"signed_quote": s, "signature": sig, "q": q.id(), "cont": cont,
        "cont_deadline_ns": (now + 600_000_000_000).to_string()}});
    // the signed execute registers Q and the continuation's output (rev 2: both are storage
    // targets of an IntentsSwap); a continuation can't register anything itself
    let reg = |t: &AccountId| json!({"StorageDeposit": {"token": t, "amount": STORAGE.to_string()}});
    let unrelated: AccountId = "unrelated-token.near".parse()?;
    fails_with(
        &env.exec(
            &u.device,
            &ta,
            json!([reg(&unrelated), {"NearDeposit": {"amount": amount.to_string()}}, op.clone()]),
            "i0",
            3 * NEAR,
        )
        .await?,
        "E_STORAGE_TARGET",
    );
    let r = env
        .exec(
            &u.device,
            &ta,
            json!([reg(q.id()), reg(env.meme.id()), {"NearDeposit": {"amount": amount.to_string()}}, op]),
            "i1",
            3 * NEAR,
        )
        .await?;
    assert!(r.is_success() && r.receipt_failures().is_empty(), "{:?}", r.failures());
    evidence("IntentsSwap funding (TA execute)", &r);
    assert_eq!(mt_balance(&env, &intents, &addr, env.wrap.id()).await?, amount, "funded the deposit address");
    let route: Value = env.worker.view(&ta, "get_route").args_json(json!({"id": "i1"})).await?.json()?;
    assert_eq!(route["state"], "Funded");
    let cont_id: String = route["cont_id"].as_str().unwrap().to_string();
    // 1Click (a solver) delivers Q to the account's intents balance
    let solver = sub(&env.root, "solver", 5 * NEAR).await?;
    ok(q.call("mint")
        .args_json(json!({"account_id": solver.id(), "amount": NEAR.to_string()}))
        .transact()
        .await?)?;
    let d = solver
        .call(q.id(), "ft_transfer_call")
        .args_json(json!({"receiver_id": intents, "amount": q_quoted.to_string(), "msg": ta.to_string()}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?;
    evidence("SIMULATED delivery (solver ft_transfer_call to intents.near, msg = TA)", &d);
    ok(d)?;
    assert_eq!(mt_balance(&env, &intents, ta.as_str(), q.id()).await?, q_quoted);
    let swap = |amt: u128, min: u128| {
        json!({"FtTransferCall": {"token": q.id(), "receiver_id": env.dcl.id(), "amount": amt.to_string(),
            "msg": json!({"Swap": {"pool_ids": [dpid], "output_token": env.meme.id(), "min_output_amount": min.to_string()}}).to_string(),
            "gas": (80 * TGAS).to_string()}})
    };
    let fire = |ops: Value| {
        u.device
            .call(&ta, "execute_order")
            .args_json(json!({"order_id": cont_id, "ops": ops}))
            .gas(Gas::from_tgas(300))
            .transact()
    };
    // outside the stored terms: pull above q_quoted x (1 + 1%)
    fails_with(&fire(json!([{"IntentsPull": {"token": q.id(), "amount": (q_quoted * 102 / 100).to_string()}}, swap(q_quoted * 102 / 100, 1)])).await?, "E_CONT_AMOUNT");
    // an IntentsSwap in a continuation: never
    fails_with(&fire(json!([{"IntentsSwap": {"signed_quote": "{}", "signature": "x", "q": q.id(), "cont": cont, "cont_deadline_ns": "1"}}])).await?, "E_ORDER_OPS");
    let fees0 = env.near_balance(env.fees.id()).await?;
    let r =
        fire(json!([{"IntentsPull": {"token": q.id(), "amount": q_quoted.to_string()}}, swap(q_quoted, 1)]))
            .await?;
    assert!(r.is_success() && r.receipt_failures().is_empty(), "{:?}", r.failures());
    evidence("continuation pull + swap", &r);
    assert!(env.ft_balance(env.meme.id(), &ta).await? > 0, "leg 2 delivered MEME to a fresh account");
    assert_eq!(env.ft_balance(q.id(), &ta).await?, 0);
    let route: Value = env.worker.view(&ta, "get_route").args_json(json!({"id": "i1"})).await?.json()?;
    assert_eq!(route["state"], "Done");
    assert_eq!(env.near_balance(env.fees.id()).await? - fees0, amount / 100, "escrowed fee paid on delivery");
    println!("CONTINUATION pull+swap: burnt {:.1} TGas", burnt(&r));
    // done: a second fire is refused
    fails_with(
        &fire(json!([{"IntentsPull": {"token": q.id(), "amount": q_quoted.to_string()}}, swap(q_quoted, 1)]))
            .await?,
        "E_NO_ORDER",
    );
    Ok(())
}

/// R2-09 escape (stuck continuation): a real IntentsSwap route whose continuation fire never got
/// its callback (out of gas, a panic) keeps `pending` for good. SIMULATED failure: the fire's own
/// state write (`pending` = true, `pending_height` = the fire's height, the last 9 bytes of the
/// route's borsh) is patched onto the real Funded route; nothing else changes. The owner's
/// `owner_upgrade` is refused (E_IN_FLIGHT) until ROUTE_PENDING_TTL_BLOCKS (300) after that
/// height, then installs the new code. The route stays as it was: pending (its continuation is
/// still E_ORDER_PENDING, nothing can pull twice), Funded, its fee still escrowed.
#[tokio::test]
async fn stuck_continuation_upgrade_after_the_bound() -> Result<()> {
    let env = account_env().await?;
    let intents = install_intents(&env).await?;
    let (q, _pool, _dpid) = q_pools(&env).await?;
    let u = env.user("sx", 10 * NEAR, (5 * NEAR, 20 * NEAR)).await?;
    let ta = u.account.clone();
    ok(q.call("mint").args_json(json!({"account_id": intents, "amount": "0"})).transact().await?)?;
    ok(u.owner
        .call(&ta, "owner_set_oneclick_config")
        .args_json(json!({"keys": [pk_str(&key())], "max_slippage_bps": 300, "intents": intents}))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?)?;
    let addr = "cd".repeat(32);
    let now = env.now_ns().await?;
    let (amount, q_quoted) = (NEAR, NEAR / 2);
    let quote = json!({
        "dry": false, "swapType": "EXACT_INPUT", "depositType": "INTENTS",
        "originAsset": format!("nep141:{}", env.wrap.id()), "destinationAsset": format!("nep141:{}", q.id()),
        "amount": amount.to_string(), "amountIn": amount.to_string(),
        "refundTo": ta, "refundType": "INTENTS", "recipient": ta, "recipientType": "INTENTS",
        "slippageTolerance": 100, "minAmountOut": (q_quoted * 99 / 100).to_string(), "amountOut": q_quoted.to_string(),
        "amountInUsd": "5.00", "amountOutUsd": "4.97", "deadline": iso(now + 600_000_000_000), "timestamp": iso(now),
        "depositAddress": addr, "depositMemo": null, "customRecipientMsg": null});
    let s = stable(quote.as_object().unwrap());
    let cont = json!({"token_out": env.meme.id(), "dexes": [env.dcl.id()], "min_final": "1"});
    let op = json!({"IntentsSwap": {"signed_quote": s, "signature": sign(&key(), &s), "q": q.id(), "cont": cont,
        "cont_deadline_ns": (now + 600_000_000_000).to_string()}});
    let reg = |t: &AccountId| json!({"StorageDeposit": {"token": t, "amount": STORAGE.to_string()}});
    let r = env
        .exec(
            &u.device,
            &ta,
            json!([reg(q.id()), reg(env.meme.id()), {"NearDeposit": {"amount": amount.to_string()}}, op]),
            "s1",
            3 * NEAR,
        )
        .await?;
    assert!(r.is_success() && r.receipt_failures().is_empty(), "{:?}", r.failures());
    let route = |id: &'static str| {
        let w = env.worker.clone();
        let ta = ta.clone();
        async move { anyhow::Ok(w.view(&ta, "get_route").args_json(json!({"id": id})).await?.json::<Value>()?) }
    };
    let r0 = route("s1").await?;
    assert_eq!((r0["state"].as_str(), r0["pending"].as_bool()), (Some("Funded"), Some(false)));
    let cont_id = r0["cont_id"].as_str().unwrap().to_string();
    // the upgrade target, as global code
    let deployer = env
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
    ok(deployer.call("deploy").args_borsh(v2_code.clone()).gas(Gas::from_tgas(300)).transact().await?)?;
    let v2 = code_hash(&v2_code);
    let upgrade = || {
        u.owner
            .call(&ta, "owner_upgrade")
            .args_json(json!({"code_hash": v2}))
            .deposit(NearToken::from_yoctonear(1))
            .gas(Gas::from_tgas(100))
            .transact()
    };
    let fire = || {
        u.device
            .call(&ta, "execute_order")
            .args_json(json!({"order_id": cont_id, "ops": [{"IntentsPull": {"token": q.id(), "amount": q_quoted.to_string()}}]}))
            .gas(Gas::from_tgas(300))
            .transact()
    };
    // the execute's own settle window (SETTLE_WINDOW_BLOCKS) passes first: only the route is left
    env.worker.fast_forward(110).await?;
    // SIMULATED: a continuation fired at height h whose callback never ran
    let h = env.worker.view_block().await?.height();
    let key = b"rts1".to_vec();
    let mut raw = env.worker.view_state(&ta).await?.get(&key).cloned().expect("route record");
    let n = raw.len();
    assert_eq!((raw[n - 9], &raw[n - 8..]), (0, &[0u8; 8][..]), "pending = false, pending_height = 0");
    raw[n - 9] = 1;
    raw[n - 8..].copy_from_slice(&h.to_le_bytes());
    env.worker.patch_state(&ta, &key, &raw).await?;
    let r1 = route("s1").await?;
    assert_eq!(
        (r1["pending"].as_bool(), r1["pending_height"].as_str()),
        (Some(true), Some(h.to_string().as_str()))
    );
    fails_with(&upgrade().await?, "E_IN_FLIGHT");
    fails_with(&fire().await?, "E_ORDER_PENDING");
    // the bound: 300 blocks after the fire
    env.worker.fast_forward(300).await?;
    assert!(env.worker.view_block().await?.height() >= h + 300);
    fails_with(&fire().await?, "E_ORDER_PENDING");
    let r2 = route("s1").await?;
    assert_eq!(r2, r1, "the route is untouched (pending, Funded, fee escrowed)");
    assert_eq!(r2["fee_escrow"].as_str(), Some((amount / 100).to_string().as_str()));
    let r = upgrade().await?;
    assert!(r.is_success(), "owner_upgrade after the bound: {:?}", r.failures());
    env.worker.fast_forward(2).await?;
    let v: Value = env.worker.view(&ta, "get_config").await?.json()?;
    assert_eq!(v["version"], "upgrade-test");
    Ok(())
}

// ======================= Shards tokens paired with a non-NEAR quote =======================

/// A Q-paired Shards token `id` on the REAL template `t`, as mainnet's factory creates it
/// (`get_quote_terms` of l000105 / l000112: quote_kind "nep141"; quote_unit = Q per 1 NEAR, here 1:1
/// raw like the sandbox pool; virtual quote reserve = 1000 quote units). Q is registered for it.
async fn q_shards_token(
    env: &Env,
    factory: &near_workspaces::Account,
    id: &str,
    t: &str,
    q: &Contract,
) -> Result<Contract> {
    let token = install_code(&env.worker, id, &shards_wasm(t).await?).await?;
    let config = json!({"schema_version": 2, "market_model": "VIRTUAL_CURVE_TO_LOCAL_AMM",
        "quote_asset_id": q.id(), "token_decimals": 18,
        "initial_supply": "1000000000000000000000000000", "sale_inventory": "750000000000000000000000000",
        "amm_inventory": "250000000000000000000000000", "virtual_token_reserve": "1125000000000000000000000000",
        "virtual_quote_reserve": "1000000000000000000000000000", "buy_tax_bps": 100, "sell_tax_bps": 200,
        "platform_share_of_tax_bps": 2000,
        "allocation": {"creator_bps": 10000, "buyback_burn_bps": 0, "dividends_bps": 0, "liquidity_bps": 0},
        "curve_lp_fee_bps": 0, "amm_lp_fee_bps": 100, "lp_fee_accounting": "SEGREGATED",
        "payout_asset_policy": "SAME_AS_QUOTE", "opening_surcharge": {"enabled": false},
        "cto_policy": "PLATFORM_ASSISTED_FUTURE_FEES", "core_upgrade_policy": "IMMUTABLE_AFTER_ACTIVATION",
        "creator_id": env.root.id(), "fee_recipient_id": env.root.id(), "public_lp_enabled": false,
        "metadata": {"name": "Sandbox", "symbol": "SBX", "image_ref": "ipfs://bafybeic54ldquk22pdjq6lq6mj7ipegalti3gv7ymlhhren3rbtk5rots4", "image_hash":
            "51c74f69a6f0455f4091f2c62042bd00bee139915101431a1fd4adf0a7be4138", "description": null,
            "website": null, "twitter": null, "telegram": null}});
    let args = json!({"config": config, "factory_id": factory.id(), "request_id": format!("req-{id}"),
        "terms": {"quote_asset_id": q.id(), "quote_decimals": 18, "quote_kind": "nep141",
            "quote_unit": "1000000000000000000000000", "min_buy": "1", "burner_id": "burn.shardsmarket.near"}});
    ok(factory.call(token.id(), "new").args_json(args).gas(Gas::from_tgas(100)).transact().await?)?;
    ok(q.call("mint").args_json(json!({"account_id": token.id(), "amount": "0"})).transact().await?)?;
    ok(factory.call(token.id(), "activate").args_json(json!({})).gas(Gas::from_tgas(30)).transact().await?)?;
    Ok(token)
}

fn classic_msg(pool: u64, tin: &AccountId, tout: &AccountId, amount_in: Option<u128>, min: u128) -> String {
    let mut a = json!({"pool_id": pool, "token_in": tin, "token_out": tout, "amount_out": "0", "min_amount_out": min.to_string()});
    if let Some(x) = amount_in {
        a["amount_in"] = json!(x.to_string());
    }
    json!({"force": 0, "actions": [a], "skip_unwrap_near": true}).to_string()
}

async fn shards_q_suite(t: &str, q_id: &str, tok_id: &str) -> Result<()> {
    let env = shards_env().await?;
    let factory = shards_factory(&env.worker).await?;
    let q = install_code(&env.worker, q_id, &out("mock_ft")).await?;
    ok(q.call("new").transact().await?)?;
    let (q, pool, _dpid) = q_pools_for(&env, q).await?;
    let token = q_shards_token(&env, &factory, tok_id, t, &q).await?;
    let u = env.user("sq", 10 * NEAR, (5 * NEAR, 20 * NEAR)).await?;
    let ta = u.account.clone();
    ok(q.call("mint").args_json(json!({"account_id": ta, "amount": "0"})).transact().await?)?;
    let fees0 = env.near_balance(env.fees.id()).await?;
    let amount = NEAR;
    let mid: String = env
        .rhea
        .view("get_return")
        .args_json(json!({"pool_id": pool, "token_in": env.wrap.id(), "amount_in": amount.to_string(), "token_out": q.id()}))
        .await?
        .json()?;
    let mid: u128 = mid.parse()?;
    let buy = |min_final: u128, mid: u128, id: &'static str| {
        let leg1 = json!({"FtTransferCall": {"token": env.wrap.id(), "receiver_id": env.rhea.id(), "amount": amount.to_string(),
            "msg": classic_msg(pool, env.wrap.id(), q.id(), Some(amount), mid * 99 / 100), "gas": (80 * TGAS).to_string()}});
        let leg2 = json!({"ShardsBuy": {"token": token.id(), "amount": "0", "min_out": min_final.to_string(), "gas": (50 * TGAS).to_string()}});
        let ops = json!([
            {"StorageDeposit": {"token": token.id(), "amount": SHARDS_STORAGE.to_string()}},
            {"NearDeposit": {"amount": amount.to_string()}},
            {"Chain": {"leg1": leg1, "leg2": leg2, "q": q.id(), "min_mid": (mid * 99 / 100).to_string(),
                "max_mid": (mid * 101 / 100).to_string(), "min_final": min_final.to_string()}}]);
        env.exec(&u.device, &ta, ops, id, 2 * NEAR)
    };
    // ---- NEAR -> Q -> token ----
    let r = buy(1, mid, "b1").await?;
    assert!(r.is_success() && r.receipt_failures().is_empty(), "{:?} {:?}", r.failures(), r.logs());
    let tok = env.ft_balance(token.id(), &ta).await?;
    assert!(tok > 0, "token bought");
    assert_eq!(env.ft_balance(q.id(), &ta).await?, 0, "all Q spent by the Shards buy");
    assert_eq!(events(&r, "route_done").len(), 1, "{:?}", r.logs());
    assert_eq!(events(&r, "settled")[0]["fee"], (amount / 100).to_string(), "fee on the NEAR leg");
    assert_eq!(env.near_balance(env.fees.id()).await? - fees0, amount / 100);
    println!("[{t}/{q_id}] NEAR->Q->token: burnt {:.1} TGas; {:?}", burnt(&r), gas_by_receipt(&r));
    // ---- leg 2 slippage: the token refunds Q in full -> held ----
    let mid: String = env
        .rhea
        .view("get_return")
        .args_json(json!({"pool_id": pool, "token_in": env.wrap.id(), "amount_in": amount.to_string(), "token_out": q.id()}))
        .await?
        .json()?;
    let r = buy(u128::MAX / 4, mid.parse()?, "b2").await?;
    assert!(r.is_success(), "{:?}", r.failures());
    let held = events(&r, "route_held");
    assert_eq!(held.len(), 1, "{:?}", r.logs());
    assert_eq!(held[0]["reason"], "leg2_failed");
    let q_held = env.ft_balance(q.id(), &ta).await?;
    assert!(q_held > 0 && held[0]["amount"] == q_held.to_string());
    assert_eq!(env.ft_balance(token.id(), &ta).await?, tok, "no token from the refused buy");
    // ---- token -> Q -> NEAR ----
    let sell_amt = tok / 2;
    let quote: Value =
        token.view("quote_sell").args_json(json!({"amount_in": sell_amt.to_string()})).await?.json()?;
    let q_out: u128 = quote["amount_out"].as_str().unwrap().parse()?;
    let sell = |min_q: u128, min_final: u128, id: &'static str| {
        let leg1 = json!({"ShardsSell": {"token": token.id(), "amount": sell_amt.to_string(), "min_out": min_q.to_string(), "gas": (40 * TGAS).to_string()}});
        let leg2 = json!({"FtTransferCall": {"token": q.id(), "receiver_id": env.rhea.id(), "amount": "0",
            "msg": classic_msg(pool, q.id(), env.wrap.id(), None, min_final), "gas": (80 * TGAS).to_string()}});
        let ops = json!([{"Chain": {"leg1": leg1, "leg2": leg2, "q": q.id(), "min_mid": min_q.max(1).to_string(),
            "max_mid": (q_out + q_held).to_string(), "min_final": min_final.to_string()}}]);
        env.exec(&u.device, &ta, ops, id, 2 * NEAR)
    };
    // slippage on the sell: the batch reverts, nothing moved
    let r = sell(q_out * 2, 1, "s0").await?;
    assert!(r.is_success(), "{:?}", r.failures());
    assert_eq!(env.ft_balance(token.id(), &ta).await?, tok, "sell reverted");
    assert!(events(&r, "settled")[0]["used"] == "0", "{:?}", r.logs());
    let w0 = env.ft_balance(env.wrap.id(), &ta).await?;
    let fees1 = env.near_balance(env.fees.id()).await?;
    let r = sell(q_out * 99 / 100, 1_000, "s1").await?;
    assert!(r.is_success() && r.receipt_failures().is_empty(), "{:?} {:?}", r.failures(), r.logs());
    assert_eq!(env.ft_balance(token.id(), &ta).await?, tok - sell_amt);
    assert!(env.ft_balance(env.wrap.id(), &ta).await? > w0, "wNEAR out");
    assert_eq!(events(&r, "route_done").len(), 1, "{:?}", r.logs());
    assert!(env.near_balance(env.fees.id()).await? > fees1, "sell fee on the NEAR leg");
    println!("[{t}/{q_id}] token->Q->NEAR: burnt {:.1} TGas; {:?}", burnt(&r), gas_by_receipt(&r));
    // leg 2 refused (min_final above the pool) -> the sold Q is held for the route
    let q_before = env.ft_balance(q.id(), &ta).await?;
    let r = sell(1, 50 * NEAR, "s2").await?;
    assert!(r.is_success(), "{:?}", r.failures());
    let held = events(&r, "route_held");
    assert_eq!(held.len(), 1, "{:?}", r.logs());
    assert_eq!(held[0]["reason"], "leg2_failed");
    let got: u128 = held[0]["amount"].as_str().unwrap().parse()?;
    assert_eq!(env.ft_balance(q.id(), &ta).await? - q_before, got, "held Q = the sell's Q");
    let route: Value = env.worker.view(&ta, "get_route").args_json(json!({"id": "s2"})).await?.json()?;
    assert_eq!(route["state"], "Held");
    Ok(())
}

#[tokio::test]
async fn shards_zec_quoted_chains() -> Result<()> {
    shards_q_suite("v0_2_0", "zec.omft.near", "l000105.factory.shardsmarket.near").await
}

#[tokio::test]
async fn shards_shards_quoted_chains() -> Result<()> {
    shards_q_suite("v0_2_0", "l000000.factory.shardsmarket.near", "l000112.factory.shardsmarket.near").await
}

// ======================= IntentsSell: token -> Q -> 1Click (FLEX) -> NEAR =======================

#[allow(clippy::too_many_arguments)]
fn sell_quote(
    ta: &AccountId,
    q: &AccountId,
    wrap: &AccountId,
    amount: u128,
    min_in: u128,
    out: u128,
    min_out: u128,
    addr: &str,
    now: u64,
    deadline: u64,
) -> (String, String) {
    let quote = json!({
        "dry": false, "swapType": "FLEX_INPUT", "depositType": "INTENTS",
        "originAsset": format!("nep141:{q}"), "destinationAsset": format!("nep141:{wrap}"),
        "amount": amount.to_string(), "amountIn": amount.to_string(), "minAmountIn": min_in.to_string(),
        "refundTo": ta, "refundType": "INTENTS", "recipient": ta, "recipientType": "INTENTS",
        "slippageTolerance": 100, "minAmountOut": min_out.to_string(), "amountOut": out.to_string(),
        "amountInUsd": "5.00", "amountOutUsd": "4.97", "deadline": iso(deadline), "timestamp": iso(now),
        "depositAddress": addr, "depositMemo": null, "customRecipientMsg": null});
    let s = stable(quote.as_object().unwrap());
    let sig = sign(&key(), &s);
    (s, sig)
}

#[tokio::test]
async fn intents_sell_fund_pull_and_refund() -> Result<()> {
    let env = account_env().await?;
    let intents = install_intents(&env).await?;
    let (q, _pool, dpid) = q_pools(&env).await?;
    let u = env.user("xs", 10 * NEAR, (5 * NEAR, 20 * NEAR)).await?;
    let ta = u.account.clone();
    ok(q.call("mint").args_json(json!({"account_id": intents, "amount": "0"})).transact().await?)?;
    ok(env
        .meme
        .call("mint")
        .args_json(json!({"account_id": ta, "amount": (10 * NEAR).to_string()}))
        .transact()
        .await?)?;
    ok(u.owner
        .call(&ta, "owner_set_oneclick_config")
        .args_json(json!({"keys": [pk_str(&key())], "max_slippage_bps": 300, "intents": intents}))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?)?;
    let sell = |addr: String, deadline_ahead: u64, id: &'static str| {
        let (env, u, ta, q, dpid) = (&env, &u, ta.clone(), q.id().clone(), dpid.clone());
        async move {
            let now = env.now_ns().await?;
            let (s, sig) = sell_quote(
                &ta,
                &q,
                env.wrap.id(),
                2 * NEAR,
                NEAR / 10,
                NEAR,
                NEAR * 99 / 100,
                &addr,
                now,
                now + deadline_ahead,
            );
            let leg1 = json!({"FtTransferCall": {"token": env.meme.id(), "receiver_id": env.dcl.id(), "amount": NEAR.to_string(),
                "msg": json!({"Swap": {"pool_ids": [dpid], "output_token": q, "min_output_amount": (NEAR / 2).to_string()}}).to_string(),
                "gas": (80 * TGAS).to_string()}});
            let chain = json!({"Chain": {"leg1": leg1, "leg2": {"IntentsFund": {"signed_quote": s, "signature": sig}}, "q": q,
                "min_mid": (NEAR / 2).to_string(), "max_mid": (2 * NEAR).to_string(), "min_final": (NEAR / 100).to_string()}});
            let ops = json!([{"StorageDeposit": {"token": q, "amount": STORAGE.to_string()}}, chain]);
            env.exec(&u.device, &ta, ops, id, 2 * NEAR).await
        }
    };
    // ---- sell -> Q -> fund the FLEX quote ----
    let addr = "cd".repeat(32);
    let r = sell(addr.clone(), 600_000_000_000, "x1").await?;
    assert!(r.is_success() && r.receipt_failures().is_empty(), "{:?} {:?}", r.failures(), r.logs());
    evidence("IntentsSell: leg 1 + funding (TA execute)", &r);
    let route: Value = env.worker.view(&ta, "get_route").args_json(json!({"id": "x1"})).await?.json()?;
    assert_eq!(route["kind"], "IntentsSell", "{route}");
    assert_eq!(route["state"], "Funded");
    let funded: u128 = route["funded"].as_str().unwrap().parse()?;
    assert_eq!(
        mt_balance(&env, &intents, &addr, q.id()).await?,
        funded,
        "the deposit address holds the sold Q"
    );
    assert_eq!(env.ft_balance(q.id(), &ta).await?, 0, "all of leg 1's Q funded the quote");
    let q_quoted: u128 = route["q_quoted"].as_str().unwrap().parse()?;
    let q_min: u128 = route["q_min"].as_str().unwrap().parse()?;
    // mul_div(x, funded, 2 NEAR), floor
    assert_eq!(q_quoted, funded / 2, "FLEX-scaled amountOut");
    assert_eq!(q_min, funded / 200 * 99 + funded % 200 * 99 / 200, "FLEX-scaled minAmountOut");
    let cont_id = route["cont_id"].as_str().unwrap().to_string();
    // 1Click delivers wNEAR to the account's intents balance (simulated by a solver deposit)
    let solver = sub(&env.root, "solver", 20 * NEAR).await?;
    ok(solver
        .call(env.wrap.id(), "near_deposit")
        .args_json(json!({}))
        .deposit(NearToken::from_near(5))
        .transact()
        .await?)?;
    let d = solver
        .call(env.wrap.id(), "ft_transfer_call")
        .args_json(json!({"receiver_id": intents, "amount": q_quoted.to_string(), "msg": ta.to_string()}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?;
    evidence("SIMULATED wNEAR delivery (solver ft_transfer_call to intents.near, msg = TA)", &d);
    ok(d)?;
    let fire = |ops: Value| {
        let cid = cont_id.clone();
        u.device
            .call(&ta, "execute_order")
            .args_json(json!({"order_id": cid, "ops": ops}))
            .gas(Gas::from_tgas(300))
            .transact()
    };
    // a sell continuation never swaps, and stays inside [q_min, q_quoted x 1.01]
    fails_with(
        &fire(json!([{"IntentsPull": {"token": env.wrap.id(), "amount": (q_min - 1).to_string()}}])).await?,
        "E_CONT_AMOUNT",
    );
    let w0 = env.ft_balance(env.wrap.id(), &ta).await?;
    let fees0 = env.near_balance(env.fees.id()).await?;
    let r = fire(json!([{"IntentsPull": {"token": env.wrap.id(), "amount": q_quoted.to_string()}}])).await?;
    assert!(r.is_success() && r.receipt_failures().is_empty(), "{:?}", r.failures());
    evidence("IntentsSell continuation pull (wNEAR)", &r);
    assert_eq!(env.ft_balance(env.wrap.id(), &ta).await? - w0, q_quoted, "wNEAR pulled into the wallet");
    assert_eq!(
        env.near_balance(env.fees.id()).await? - fees0,
        q_quoted / 100,
        "fee on the NEAR leg (pulled wNEAR)"
    );
    let route: Value = env.worker.view(&ta, "get_route").args_json(json!({"id": "x1"})).await?.json()?;
    assert_eq!(route["state"], "Done");

    // ---- refund: the quote expires unfilled, 1Click refunds Q to the account's intents balance ----
    let addr2 = "ef".repeat(32);
    let r = sell(addr2.clone(), 90_000_000_000, "x2").await?;
    assert!(r.is_success() && r.receipt_failures().is_empty(), "{:?} {:?}", r.failures(), r.logs());
    let route: Value = env.worker.view(&ta, "get_route").args_json(json!({"id": "x2"})).await?.json()?;
    let funded2: u128 = route["funded"].as_str().unwrap().parse()?;
    let qdl: u64 = route["quote_deadline_ns"].as_str().unwrap().parse()?;
    let cont2 = route["cont_id"].as_str().unwrap().to_string();
    let fire2 = |ops: Value| {
        let cid = cont2.clone();
        u.device
            .call(&ta, "execute_order")
            .args_json(json!({"order_id": cid, "ops": ops}))
            .gas(Gas::from_tgas(300))
            .transact()
    };
    // before the deadline: no refund pull
    fails_with(
        &fire2(json!([{"IntentsPull": {"token": q.id(), "amount": funded2.to_string()}}])).await?,
        "E_ORDER_OPS",
    );
    while env.now_ns().await? <= qdl {
        env.worker.fast_forward(200).await?;
    }
    let refunder = sub(&env.root, "refunder", 5 * NEAR).await?;
    ok(q.call("mint")
        .args_json(json!({"account_id": refunder.id(), "amount": (10 * NEAR).to_string()}))
        .transact()
        .await?)?;
    let d = refunder
        .call(q.id(), "ft_transfer_call")
        .args_json(json!({"receiver_id": intents, "amount": funded2.to_string(), "msg": ta.to_string()}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?;
    evidence("SIMULATED refund (Q back to the TA's intents balance)", &d);
    ok(d)?;
    fails_with(
        &fire2(json!([{"IntentsPull": {"token": q.id(), "amount": (funded2 + 1).to_string()}}])).await?,
        "E_ORDER_OPS",
    );
    let q0 = env.ft_balance(q.id(), &ta).await?;
    let r = fire2(json!([{"IntentsPull": {"token": q.id(), "amount": funded2.to_string()}}])).await?;
    assert!(r.is_success() && r.receipt_failures().is_empty(), "{:?}", r.failures());
    evidence("refund pull (Q)", &r);
    assert_eq!(env.ft_balance(q.id(), &ta).await? - q0, funded2);
    let route: Value = env.worker.view(&ta, "get_route").args_json(json!({"id": "x2"})).await?.json()?;
    assert_eq!(route["state"], "Refunded");
    assert_eq!(events(&r, "route_refunded").len(), 1);
    Ok(())
}
