//! TESTNET end-to-end (ignored by default; needs faucet accounts in contracts/.keys/):
//!   cargo test --test testnet_e2e -- --ignored --nocapture
//! Deploys global code + factory, creates a trading account, buys ref.fakes.testnet with
//! wNEAR on Ref testnet (pool 17) via `execute` signed by the device FC key, sells back to
//! native NEAR, checks fees + caps. Writes tx hashes to contracts/testnet-e2e.json.
use integration_tests::{caps_json, code_hash, fee, out, NEAR, STORAGE, TGAS};
use near_workspaces::network::Testnet;
use near_workspaces::result::ExecutionFinalResult;
use near_workspaces::types::{Gas, KeyType, NearToken, SecretKey};
use near_workspaces::{Account, AccountId, Worker};
use serde_json::{json, Value};

const REF: &str = "ref-finance-101.testnet";
const WRAP: &str = "wrap.testnet";
const OUT: &str = "ref.fakes.testnet";
const POOL: u64 = 17;

fn key(name: &str) -> anyhow::Result<(AccountId, SecretKey)> {
    let p = format!("{}/../.keys/{name}.json", env!("CARGO_MANIFEST_DIR"));
    let v: Value = serde_json::from_str(&std::fs::read_to_string(p)?)?;
    Ok((v["account_id"].as_str().unwrap().parse()?, v["private_key"].as_str().unwrap().parse()?))
}

fn acct(w: &Worker<Testnet>, name: &str) -> anyhow::Result<Account> {
    let (id, sk) = key(name)?;
    Ok(Account::from_secret_key(id, sk, w))
}

struct Log(Vec<Value>);
impl Log {
    fn rec(&mut self, step: &str, r: &ExecutionFinalResult) {
        let h = r.outcome().transaction_hash.to_string();
        let fails: Vec<String> =
            r.receipt_failures().iter().map(|f| format!("{f:?}").chars().take(200).collect()).collect();
        println!("{step}: {h} success={} receipt_failures={}", r.is_success(), fails.len());
        self.0.push(json!({"step": step, "tx": h, "success": r.is_success(), "receipt_failures": fails,
            "explorer": format!("https://testnet.nearblocks.io/txns/{h}")}));
    }
}

async fn view(w: &Worker<Testnet>, c: &str, m: &str, a: Value) -> anyhow::Result<Value> {
    Ok(w.view(&c.parse()?, m).args_json(a).await?.json()?)
}

async fn ft(w: &Worker<Testnet>, t: &str, id: &AccountId) -> anyhow::Result<u128> {
    Ok(view(w, t, "ft_balance_of", json!({"account_id": id})).await?.as_str().unwrap().parse()?)
}

async fn bal(w: &Worker<Testnet>, id: &AccountId) -> anyhow::Result<u128> {
    Ok(w.view_account(id).await?.balance.as_yoctonear())
}

async fn settled(r: &ExecutionFinalResult) -> String {
    r.logs().iter().find(|l| l.contains("\"settled\"")).map(|l| l.to_string()).unwrap_or_default()
}

/// v1.1 run. First-run state (v1 global code, factory, owner's v1 account) is reused:
/// the factory is redeployed + pointed at the new hash, the v1 account is moved with
/// owner_upgrade, and a fresh owner (ntt-owner2) exercises create + trades.
#[tokio::test]
#[ignore]
async fn testnet_e2e() -> anyhow::Result<()> {
    let w = near_workspaces::testnet().rpc_addr("https://test.rpc.fastnear.com").await?;
    let mut log = Log(vec![]);
    let deploy = acct(&w, "ntt-deploy")?;
    let factory = acct(&w, "ntt-factory")?;
    let owner1 = acct(&w, "ntt-owner")?;
    let owner = acct(&w, &std::env::var("E2E_OWNER").unwrap_or("ntt-owner2".into()))?;
    let fees = acct(&w, "ntt-fees")?;

    // 1. Global code v1.1 (burns ~1e-4 NEAR/byte).
    let code = out("trading_account");
    let hash = code_hash(&code);
    // Faucet accounts (and spare balances) top the deployer up; the fee recipient keeps 2 NEAR.
    let sources = std::env::var("E2E_FUND").unwrap_or("ntt-fund3,ntt-fund4".into());
    for f in sources.split(',') {
        if bal(&w, deploy.id()).await? > 22 * NEAR {
            break;
        }
        let a = acct(&w, f)?;
        let keep = if f == "ntt-fees" { 2 * NEAR } else { NEAR / 10 };
        let b = bal(&w, a.id()).await?;
        if b > keep + NEAR / 10 {
            let r = a.transfer_near(deploy.id(), NearToken::from_yoctonear(b - keep)).await?;
            println!("fund from {f}: {}", r.is_success());
        }
    }
    if w.view_code(deploy.id()).await.is_err() {
        deploy.deploy(&out("global_deployer")).await?.into_result()?;
    }
    let r = deploy
        .call(deploy.id(), "deploy")
        .args_borsh(code.clone())
        .gas(Gas::from_tgas(300))
        .transact()
        .await?;
    log.rec("deploy_global_contract_v1_1", &r);
    assert!(r.is_success(), "{:?}", r.clone().into_result().err());
    println!("global code hash {hash} ({} bytes)", code.len());

    // 2. Factory: redeploy (init gas 30 TGas in v1.1), point at the new code (new accounts only).
    let fr = factory.deploy(&out("factory")).await?;
    println!("factory redeploy {}", fr.is_success());
    if view(&w, factory.id().as_str(), "get_config", json!({})).await.is_err() {
        let r = factory
            .call(factory.id(), "new")
            .args_json(json!({"admin": factory.id(), "code_hash": hash,
            "fee_config": {"fee_bps": 100, "fee_recipient": fees.id()},
            "dex_allowlist": [{"id": REF, "kind": "RheaClassic"}], "wrap": WRAP}))
            .transact()
            .await?;
        log.rec("factory_new", &r);
    }
    let r = factory
        .call(factory.id(), "set_code_hash")
        .args_json(json!({"code_hash": hash}))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?;
    log.rec("factory_set_code_hash", &r);
    assert!(r.is_success());

    // 3. Existing v1 account moves to v1.1 only because its owner signs owner_upgrade.
    let old: AccountId = view(&w, factory.id().as_str(), "account_for", json!({"owner": owner1.id()}))
        .await?
        .as_str()
        .unwrap()
        .parse()?;
    if w.view_account(&old).await.is_ok() {
        let r = owner1
            .call(&old, "owner_upgrade")
            .args_json(json!({"code_hash": hash}))
            .deposit(NearToken::from_yoctonear(1))
            .gas(Gas::from_tgas(100))
            .transact()
            .await?;
        log.rec("owner_upgrade_v1_account", &r);
        assert!(r.is_success() && r.receipt_failures().is_empty(), "{:?}", r.receipt_failures());
        let cfg = view(&w, old.as_str(), "get_config", json!({})).await?;
        println!("upgraded v1 account {old}: version {}", cfg["version"]);
    }

    // 4. New owner creates a trading account (one tx). init registers it on wNEAR.
    let device_sk = SecretKey::from_random(KeyType::ED25519);
    std::fs::write(
        format!("{}/../.keys/ntt-device2.json", env!("CARGO_MANIFEST_DIR")),
        json!({"public_key": device_sk.public_key(), "private_key": device_sk.to_string()}).to_string(),
    )?;
    let caps = (NEAR, 3 * NEAR / 2);
    let r = owner
        .call(factory.id(), "create_account")
        .args_json(json!({"device_public_key": device_sk.public_key(), "caps": caps_json(caps)}))
        .deposit(NearToken::from_near(3))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?;
    log.rec("factory_create_account", &r);
    assert!(r.is_success() && r.receipt_failures().is_empty(), "{:?}", r.receipt_failures());
    let account: AccountId = view(&w, factory.id().as_str(), "account_for", json!({"owner": owner.id()}))
        .await?
        .as_str()
        .unwrap()
        .parse()?;
    let sb = view(&w, WRAP, "storage_balance_of", json!({"account_id": account})).await?;
    println!("trading account {account}; wrap storage_balance_of = {sb}");
    assert!(!sb.is_null(), "init registered the account on wNEAR");
    let device = Account::from_secret_key(account.clone(), device_sk, &w);

    let exec = |ops: Value, id: &str, max_in: u128| {
        let (device, account, id) = (device.clone(), account.clone(), id.to_string());
        let w = w.clone();
        async move {
            let now = w.view_block().await?.timestamp();
            anyhow::Ok(device.call(&account, "execute")
                .args_json(json!({"ops": ops, "client_order_id": id, "expires_at_ns": (now + 100_000_000_000).to_string(), "max_in_yocto": max_in.to_string()}))
                .gas(Gas::from_tgas(300)).transact().await?)
        }
    };
    let msg = |tin: &str, tout: &str, amt: u128, min: u128, unwrap: bool| {
        json!({"force": 0, "actions": [{"pool_id": POOL, "token_in": tin, "token_out": tout, "amount_in": amt.to_string(), "min_amount_out": min.to_string()}], "skip_unwrap_near": !unwrap}).to_string()
    };
    let day = |w: Worker<Testnet>, a: AccountId| async move {
        let d = view(&w, a.as_str(), "get_day", json!({})).await?;
        anyhow::Ok(d["spent_yocto"].as_str().unwrap().parse::<u128>()?)
    };

    // 5. BUY 0.5 NEAR (success): fee charged by the callback.
    let amt = NEAR / 2;
    let q: u128 = view(
        &w,
        REF,
        "get_return",
        json!({"pool_id": POOL, "token_in": WRAP, "amount_in": amt.to_string(), "token_out": OUT}),
    )
    .await?
    .as_str()
    .unwrap()
    .parse()?;
    let f0 = bal(&w, fees.id()).await?;
    let ops = json!([
        {"StorageDeposit": {"token": OUT, "amount": STORAGE.to_string()}},
        {"NearDeposit": {"amount": amt.to_string()}},
        {"FtTransferCall": {"token": WRAP, "receiver_id": REF, "amount": amt.to_string(), "msg": msg(WRAP, OUT, amt, q * 95 / 100, false), "gas": (150 * TGAS).to_string()}}
    ]);
    let r = exec(ops, "v11-buy-ok", amt + fee(amt) + STORAGE).await?;
    log.rec("execute_buy_success", &r);
    assert!(r.is_success() && r.receipt_failures().is_empty(), "{:?}", r.receipt_failures());
    println!("  {}", settled(&r).await);
    let got = ft(&w, OUT, &account).await?;
    let fee_buy = bal(&w, fees.id()).await? - f0;
    assert_eq!(fee_buy, fee(amt));
    let spent1 = day(w.clone(), account.clone()).await?;
    assert_eq!(spent1, amt + fee(amt) + STORAGE);

    // 6. Forced slippage failure: min_out = 2x quote. Rhea E68 -> refund -> no fee, spend restored.
    let q: u128 = view(
        &w,
        REF,
        "get_return",
        json!({"pool_id": POOL, "token_in": WRAP, "amount_in": amt.to_string(), "token_out": OUT}),
    )
    .await?
    .as_str()
    .unwrap()
    .parse()?;
    let (f1, w0) = (bal(&w, fees.id()).await?, ft(&w, WRAP, &account).await?);
    let ops = json!([
        {"NearDeposit": {"amount": amt.to_string()}},
        {"FtTransferCall": {"token": WRAP, "receiver_id": REF, "amount": amt.to_string(), "msg": msg(WRAP, OUT, amt, q * 2, false), "gas": (150 * TGAS).to_string()}}
    ]);
    let r = exec(ops, "v11-buy-slippage", amt + fee(amt)).await?;
    log.rec("execute_buy_slippage_fail", &r);
    let fails = format!("{:?}", r.receipt_failures());
    println!("  failure: {}", &fails[..fails.len().min(300)]);
    println!("  {}", settled(&r).await);
    assert!(fails.contains("E68") || fails.contains("ERR_MIN_AMOUNT"), "{fails}");
    assert_eq!(bal(&w, fees.id()).await?, f1, "no fee on failed swap");
    assert_eq!(ft(&w, WRAP, &account).await? - w0, amt, "wNEAR refunded");
    assert_eq!(day(w.clone(), account.clone()).await?, spent1, "spend restored");

    // 7. Caps enforced on-chain.
    let ops = json!([{"FtTransferCall": {"token": WRAP, "receiver_id": REF, "amount": NEAR.to_string(), "msg": msg(WRAP, OUT, NEAR, 1, false), "gas": (150 * TGAS).to_string()}}]);
    let r = exec(ops, "v11-cap", NEAR + fee(NEAR)).await?;
    log.rec("execute_over_cap_rejected", &r);
    assert!(format!("{:?}", r.clone().into_result().err()).contains("E_CAP_TRADE"));

    // 8. SELL everything back to native NEAR.
    let q: u128 = view(
        &w,
        REF,
        "get_return",
        json!({"pool_id": POOL, "token_in": OUT, "amount_in": got.to_string(), "token_out": WRAP}),
    )
    .await?
    .as_str()
    .unwrap()
    .parse()?;
    let min_near = q * 95 / 100;
    let (f2, b1) = (bal(&w, fees.id()).await?, bal(&w, &account).await?);
    let ops = json!([{"FtTransferCall": {"token": OUT, "receiver_id": REF, "amount": got.to_string(), "msg": msg(OUT, WRAP, got, min_near, true), "gas": (150 * TGAS).to_string()}}]);
    let r = exec(ops, "v11-sell", fee(min_near)).await?;
    log.rec("execute_sell", &r);
    assert!(r.is_success() && r.receipt_failures().is_empty(), "{:?}", r.receipt_failures());
    println!("  {}", settled(&r).await);
    let fee_sell = bal(&w, fees.id()).await? - f2;
    let b2 = bal(&w, &account).await?;
    println!("sold {got} -> native NEAR delta {} (min {min_near}); fee {fee_sell}", b2 as i128 - b1 as i128);
    assert_eq!(fee_sell, fee(min_near));
    assert_eq!(ft(&w, OUT, &account).await?, 0);
    let dayv = view(&w, account.as_str(), "get_day", json!({})).await?;

    let summary = json!({"network": "testnet", "version": "1.1", "code_hash": hash, "wasm_bytes": code.len(), "factory": factory.id(),
        "trading_account": account, "owner": owner.id(), "upgraded_v1_account": old, "fee_recipient": fees.id(),
        "fee_buy": fee_buy.to_string(), "fee_sell": fee_sell.to_string(), "bought": got.to_string(), "day": dayv, "steps": log.0});
    std::fs::write(
        format!("{}/../testnet-e2e.json", env!("CARGO_MANIFEST_DIR")),
        serde_json::to_string_pretty(&summary)?,
    )?;
    Ok(())
}

/// v1.3 testnet deployment (ignored): global code v1.3 (this build), factory redeployed IN PLACE
/// (same id, v1.3 factory: multi device keys, entry storage from deposit) + set_code_hash, a fresh
/// owner creates an account with 2 device keys in ONE call, and installs an automation key.
/// Writes `v1_3` + top-level `code_hash` into contracts/testnet-e2e.json (other fields kept) and
/// the device/automation keys into contracts/.keys/ for services/executor/scripts/testnet-e2e.ts.
///   E2E_OWNER=<.keys name> E2E_FUND=<.keys names> cargo test --test testnet_e2e v13 -- --ignored --nocapture
#[tokio::test]
#[ignore]
async fn testnet_v13_deploy() -> anyhow::Result<()> {
    let w = near_workspaces::testnet().rpc_addr("https://test.rpc.fastnear.com").await?;
    let mut log = Log(vec![]);
    let deploy = acct(&w, "ntt-deploy")?;
    let factory = acct(&w, "ntt-factory")?;
    let owner = acct(&w, &std::env::var("E2E_OWNER").unwrap_or("ntt-owner4".into()))?;
    let code = out("trading_account");
    let hash = code_hash(&code);
    for f in std::env::var("E2E_FUND").unwrap_or_default().split(',').filter(|s| !s.is_empty()) {
        if bal(&w, deploy.id()).await? > code.len() as u128 * 10u128.pow(20) + 2 * NEAR {
            break;
        }
        let a = acct(&w, f)?;
        let keep = if f == "ntt-fees" { 2 * NEAR } else { NEAR / 10 };
        let b = bal(&w, a.id()).await?;
        if b > keep + NEAR / 10 {
            let r = a.transfer_near(deploy.id(), NearToken::from_yoctonear(b - keep)).await?;
            println!("fund from {f}: {}", r.is_success());
        }
    }
    let r = deploy
        .call(deploy.id(), "deploy")
        .args_borsh(code.clone())
        .gas(Gas::from_tgas(300))
        .transact()
        .await?;
    log.rec("deploy_global_contract_v1_3", &r);
    assert!(r.is_success(), "{:?}", r.clone().into_result().err());
    let fr = factory.deploy(&out("factory")).await?;
    println!("factory redeployed in place (v1.3): {}", fr.is_success());
    assert!(fr.is_success());
    let r = factory
        .call(factory.id(), "set_code_hash")
        .args_json(json!({"code_hash": hash}))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?;
    log.rec("factory_set_code_hash_v1_3", &r);
    let min: String =
        view(&w, factory.id().as_str(), "min_funding", json!({})).await?.as_str().unwrap().into();
    println!("factory min_funding {min}");

    // one owner signature: account + 2 device keys
    let dev: Vec<SecretKey> = (0..2).map(|_| SecretKey::from_random(KeyType::ED25519)).collect();
    let r = owner.call(factory.id(), "create_account")
        .args_json(json!({"device_public_keys": dev.iter().map(|k| k.public_key()).collect::<Vec<_>>(), "caps": caps_json((NEAR, 3 * NEAR))}))
        .deposit(NearToken::from_near(3)).gas(Gas::from_tgas(100)).transact().await?;
    log.rec("factory_create_account_2_keys", &r);
    assert!(r.is_success() && r.receipt_failures().is_empty(), "{:?}", r.receipt_failures());
    let account: AccountId = view(&w, factory.id().as_str(), "account_for", json!({"owner": owner.id()}))
        .await?
        .as_str()
        .unwrap()
        .parse()?;
    let keys_dir = format!("{}/../.keys", env!("CARGO_MANIFEST_DIR"));
    for (i, k) in dev.iter().enumerate() {
        std::fs::write(
            format!("{keys_dir}/ntt-v13-device{i}.json"),
            json!({"account_id": account, "public_key": k.public_key(), "private_key": k.to_string()})
                .to_string(),
        )?;
    }
    // automation key (execute_order only, 1 NEAR gas allowance)
    let ak = SecretKey::from_random(KeyType::ED25519);
    let r = owner
        .call(&account, "owner_set_automation_key")
        .args_json(json!({"public_key": ak.public_key(), "allowance": NEAR.to_string()}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(50))
        .transact()
        .await?;
    log.rec("owner_set_automation_key", &r);
    assert!(r.is_success());
    std::fs::create_dir_all(format!("{keys_dir}/automation"))?;
    std::fs::write(
        format!("{keys_dir}/automation/{account}.json"),
        json!({"account_id": account, "public_key": ak.public_key(), "private_key": ak.to_string()})
            .to_string(),
    )?;
    let cfg = view(&w, account.as_str(), "get_config", json!({})).await?;
    println!("v1.3 account {account} version {}", cfg["version"]);

    let path = format!("{}/../testnet-e2e.json", env!("CARGO_MANIFEST_DIR"));
    let mut doc: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap_or("{}".into()))?;
    doc["code_hash"] = json!(hash);
    doc["factory"] = json!(factory.id());
    doc["v1_3"] = json!({"factory": factory.id(), "code_hash": hash, "wasm_bytes": code.len(), "min_funding": min,
        "trading_account": account, "owner": owner.id(), "device_key_files": ["ntt-v13-device0", "ntt-v13-device1"],
        "automation_key_file": format!("automation/{account}.json"), "steps": log.0});
    std::fs::write(&path, serde_json::to_string_pretty(&doc)?)?;
    Ok(())
}

/// v1.3.2 testnet verification WITHOUT a new global deploy (faucet rate-limited; a 272 KB
/// global deploy burns ~27 NEAR): the same wasm deployed directly on a fresh account in one
/// batch (CreateAccount + Transfer + DeployContract + AddKey(FC device) + init: no full-access
/// key), then a Ref buy via the device key and owner_withdraw_all to a fresh, unregistered
/// destination. Merges `v1_3_2_direct` into contracts/testnet-e2e.json.
#[tokio::test]
#[ignore]
async fn testnet_v132_direct() -> anyhow::Result<()> {
    let w = near_workspaces::testnet().rpc_addr("https://test.rpc.fastnear.com").await?;
    let mut log = Log(vec![]);
    let deploy = acct(&w, "ntt-deploy")?;
    let owner = acct(&w, "ntt-owner4")?;
    let fees = acct(&w, "ntt-fees")?;
    for (f, keep) in [("ntt-factory", NEAR / 2), ("ntt-fees", 2 * NEAR / 5)] {
        let a = acct(&w, f)?;
        let v = w.view_account(a.id()).await?;
        let free = v.balance.as_yoctonear().saturating_sub(v.storage_usage as u128 * 10u128.pow(19) + keep);
        if free > NEAR / 10 {
            let r = a.transfer_near(deploy.id(), NearToken::from_yoctonear(free)).await?;
            println!("fund from {f}: {:.3} {}", free as f64 / 1e24, r.is_success());
        }
    }
    let code = out("trading_account");
    let hash = code_hash(&code);
    let account: AccountId = format!("v132.{}", deploy.id()).parse()?;
    let dev = SecretKey::from_random(KeyType::ED25519);
    let init = json!({"owner": owner.id(), "fee_config": {"fee_bps": 100, "fee_recipient": fees.id()},
        "caps": caps_json((NEAR, 3 * NEAR)), "dex_allowlist": [{"id": REF, "kind": "RheaClassic"}], "wrap": WRAP});
    let fund = code.len() as u128 * 10u128.pow(19) + 11 * NEAR / 10;
    let r = deploy
        .batch(&account)
        .create_account()
        .transfer(NearToken::from_yoctonear(fund))
        .deploy(&code)
        .add_key(
            dev.public_key(),
            near_workspaces::AccessKey::function_call_access(
                &account,
                &[
                    "execute",
                    "withdraw_to_owner",
                    "lower_caps",
                    "place_order",
                    "cancel_order",
                    "revoke_automation",
                ],
                None,
            ),
        )
        .call(near_workspaces::operations::Function::new("init").args_json(init).gas(Gas::from_tgas(50)))
        .transact()
        .await?;
    log.rec("create_deploy_v1_3_2_direct", &r);
    assert!(r.is_success() && r.receipt_failures().is_empty(), "{:?}", r.receipt_failures());
    let device = Account::from_secret_key(account.clone(), dev, &w);
    let cfg = view(&w, account.as_str(), "get_config", json!({})).await?;
    println!("v1.3.2 account {account} version {}", cfg["version"]);
    // buy 0.3 NEAR of ref.fakes + keep 0.2 NEAR as wNEAR
    let amt = 3 * NEAR / 10;
    let q: u128 = view(
        &w,
        REF,
        "get_return",
        json!({"pool_id": POOL, "token_in": WRAP, "amount_in": amt.to_string(), "token_out": OUT}),
    )
    .await?
    .as_str()
    .unwrap()
    .parse()?;
    let msg = json!({"force": 0, "actions": [{"pool_id": POOL, "token_in": WRAP, "token_out": OUT, "amount_in": amt.to_string(), "min_amount_out": (q * 95 / 100).to_string()}], "skip_unwrap_near": true}).to_string();
    let now = w.view_block().await?.timestamp();
    let r = device.call(&account, "execute")
        .args_json(json!({"ops": [
            {"StorageDeposit": {"token": OUT, "amount": STORAGE.to_string()}},
            {"NearDeposit": {"amount": (amt + 2 * NEAR / 10).to_string()}},
            {"FtTransferCall": {"token": WRAP, "receiver_id": REF, "amount": amt.to_string(), "msg": msg, "gas": (150 * TGAS).to_string()}}],
            "client_order_id": "v132-buy", "expires_at_ns": (now + 100_000_000_000).to_string(), "max_in_yocto": (amt + fee(amt) + STORAGE).to_string()}))
        .gas(Gas::from_tgas(230)).transact().await?;
    log.rec("execute_buy", &r);
    assert!(r.is_success() && r.receipt_failures().is_empty(), "{:?}", r.receipt_failures());
    let got = ft(&w, OUT, &account).await?;
    let wnear = ft(&w, WRAP, &account).await?;
    println!("holding {got} ref.fakes + {wnear} wNEAR");
    // owner_withdraw_all to the owner (a fresh account registered on neither wrap nor ref.fakes)
    let reg = view(&w, OUT, "storage_balance_of", json!({"account_id": owner.id()})).await?;
    let regw = view(&w, WRAP, "storage_balance_of", json!({"account_id": owner.id()})).await?;
    println!("owner registered on ref.fakes: {} wrap: {}", !reg.is_null(), !regw.is_null());
    let o0 = bal(&w, owner.id()).await?;
    let r = owner
        .call(&account, "owner_withdraw_all")
        .args_json(json!({"to": owner.id(), "tokens": [OUT]}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(300))
        .transact()
        .await?;
    log.rec("owner_withdraw_all", &r);
    let evs: Vec<String> =
        r.logs().iter().filter(|l| l.contains("owner_withdraw")).map(|l| l.to_string()).collect();
    for e in &evs {
        println!("  {e}");
    }
    assert!(r.is_success());
    let v = w.view_account(&account).await?;
    let left = v.balance.as_yoctonear() - v.storage_usage as u128 * 10u128.pow(19);
    let owner_tok = ft(&w, OUT, owner.id()).await?;
    println!("owner got {owner_tok} ref.fakes (had {got}); account wNEAR {} ; account liquid left {:.5}; owner NEAR delta {:.4}",
        ft(&w, WRAP, &account).await?, left as f64 / 1e24, (bal(&w, owner.id()).await? as f64 - o0 as f64) / 1e24);
    assert_eq!(owner_tok, got);
    assert_eq!(ft(&w, WRAP, &account).await?, 0);
    assert!(evs.iter().all(|e| e.contains("\"ok\":true")));
    let path = format!("{}/../testnet-e2e.json", env!("CARGO_MANIFEST_DIR"));
    let mut doc: Value = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
    doc["v1_3_2_direct"] = json!({"code_hash": hash, "wasm_bytes": code.len(), "trading_account": account,
        "owner": owner.id(), "note": "direct (non-global) deployment for verification; global deploy pending testnet funds",
        "steps": log.0});
    std::fs::write(&path, serde_json::to_string_pretty(&doc)?)?;
    Ok(())
}

/// After `testnet_v13_deploy` (factory switched to this build): device key 0 of the fresh
/// factory account buys ref.fakes (+ keeps wNEAR), then the owner (registered on neither wrap
/// nor ref.fakes) calls owner_withdraw_all to itself: 100% recovered, every event ok:true.
///   E2E_OWNER=<same .keys name> cargo test --test testnet_e2e testnet_v132_verify -- --ignored --nocapture
#[tokio::test]
#[ignore]
async fn testnet_v132_verify() -> anyhow::Result<()> {
    let w = near_workspaces::testnet().rpc_addr("https://test.rpc.fastnear.com").await?;
    let mut log = Log(vec![]);
    let path = format!("{}/../testnet-e2e.json", env!("CARGO_MANIFEST_DIR"));
    let mut doc: Value = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
    let account: AccountId = doc["v1_3"]["trading_account"].as_str().unwrap().parse()?;
    let owner = acct(&w, &std::env::var("E2E_OWNER")?)?;
    assert_eq!(doc["v1_3"]["owner"], json!(owner.id()));
    let device = acct(&w, "ntt-v13-device0")?;
    let device = Account::from_secret_key(account.clone(), device.secret_key().clone(), &w);
    let cfg = view(&w, account.as_str(), "get_config", json!({})).await?;
    assert_eq!(cfg["version"], "1.3.2");
    let amt = 3 * NEAR / 10;
    let q: u128 = view(
        &w,
        REF,
        "get_return",
        json!({"pool_id": POOL, "token_in": WRAP, "amount_in": amt.to_string(), "token_out": OUT}),
    )
    .await?
    .as_str()
    .unwrap()
    .parse()?;
    let msg = json!({"force": 0, "actions": [{"pool_id": POOL, "token_in": WRAP, "token_out": OUT, "amount_in": amt.to_string(), "min_amount_out": (q * 95 / 100).to_string()}], "skip_unwrap_near": true}).to_string();
    let now = w.view_block().await?.timestamp();
    let r = device.call(&account, "execute")
        .args_json(json!({"ops": [
            {"StorageDeposit": {"token": OUT, "amount": STORAGE.to_string()}},
            {"NearDeposit": {"amount": (amt + 2 * NEAR / 10).to_string()}},
            {"FtTransferCall": {"token": WRAP, "receiver_id": REF, "amount": amt.to_string(), "msg": msg, "gas": (150 * TGAS).to_string()}}],
            "client_order_id": "v132-factory-buy", "expires_at_ns": (now + 100_000_000_000).to_string(), "max_in_yocto": (amt + fee(amt) + STORAGE).to_string()}))
        .gas(Gas::from_tgas(230)).transact().await?;
    log.rec("execute_buy", &r);
    assert!(r.is_success() && r.receipt_failures().is_empty(), "{:?}", r.receipt_failures());
    let got = ft(&w, OUT, &account).await?;
    let wnear = ft(&w, WRAP, &account).await?;
    let unreg = view(&w, OUT, "storage_balance_of", json!({"account_id": owner.id()})).await?.is_null()
        && view(&w, WRAP, "storage_balance_of", json!({"account_id": owner.id()})).await?.is_null();
    println!("holding {got} ref.fakes + {wnear} wNEAR; owner unregistered on both: {unreg}");
    assert!(unreg);
    let o0 = bal(&w, owner.id()).await?;
    let r = owner
        .call(&account, "owner_withdraw_all")
        .args_json(json!({"to": owner.id(), "tokens": [OUT]}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(300))
        .transact()
        .await?;
    log.rec("owner_withdraw_all", &r);
    let evs: Vec<String> =
        r.logs().iter().filter(|l| l.contains("\"owner_withdraw\"")).map(|l| l.to_string()).collect();
    for e in &evs {
        println!("  {e}");
    }
    let v = w.view_account(&account).await?;
    let left = v.balance.as_yoctonear() - v.storage_usage as u128 * 10u128.pow(19);
    let owner_tok = ft(&w, OUT, owner.id()).await?;
    let delta = bal(&w, owner.id()).await? as i128 - o0 as i128;
    println!("owner got {owner_tok}/{got} ref.fakes; account wNEAR {}, ref.fakes {}, liquid left {left}; owner NEAR delta {:.4}",
        ft(&w, WRAP, &account).await?, ft(&w, OUT, &account).await?, delta as f64 / 1e24);
    assert!(r.is_success() && evs.len() == 3 && evs.iter().all(|e| e.contains("\"ok\":true")));
    assert_eq!(owner_tok, got);
    assert_eq!(ft(&w, WRAP, &account).await?, 0);
    assert_eq!(ft(&w, OUT, &account).await?, 0);
    assert!(left < NEAR / 100);
    doc["v1_3"]["verify_v1_3_2"] = json!({"steps": log.0, "recovered_tokens": got.to_string(), "recovered_wnear_as_near": wnear.to_string(), "events": evs});
    std::fs::write(&path, serde_json::to_string_pretty(&doc)?)?;
    Ok(())
}

/// TESTNET PLAYGROUND (docs/testnet-playground.md): the current `out/trading_account.wasm` as a
/// global contract + a NEW factory `play.<deployer>` (RheaClassic Ref testnet only, fee 100 bps to
/// ntt-fees, admin = the factory itself). Nothing is sent unless the deployer holds the whole
/// cost first (global deploy at 1e-4 NEAR/byte + 2.5 NEAR factory account + 1 NEAR margin);
/// otherwise it prints the exact shortfall and fails. Writes `playground` into
/// contracts/testnet-e2e.json and the factory key to contracts/.keys/ntt-play-factory.json.
///   cargo test --test testnet_e2e testnet_playground_deploy -- --ignored --nocapture
#[tokio::test]
#[ignore]
async fn testnet_playground_deploy() -> anyhow::Result<()> {
    let w = near_workspaces::testnet().rpc_addr("https://test.rpc.fastnear.com").await?;
    let mut log = Log(vec![]);
    let deploy = acct(&w, "ntt-deploy")?;
    let fees = acct(&w, "ntt-fees")?;
    let code = out("trading_account");
    let hash = code_hash(&code);
    let factory_code = out("factory");
    let factory_id: AccountId = format!("play.{}", deploy.id()).parse()?;
    let factory_near = 5 * NEAR / 2;
    let need = code.len() as u128 * 10u128.pow(20) + factory_near + NEAR;
    let have = bal(&w, deploy.id()).await?;
    let spent0 = have;
    println!(
        "global code {hash} ({} bytes); deployer has {:.4} NEAR, needs {:.4}",
        code.len(),
        have as f64 / 1e24,
        need as f64 / 1e24
    );
    if have < need {
        anyhow::bail!(
            "deployer {} is short by {:.4} NEAR (send it that much; nothing was sent)",
            deploy.id(),
            (need - have) as f64 / 1e24
        );
    }
    if w.view_code(deploy.id()).await.is_err() {
        deploy.deploy(&out("global_deployer")).await?.into_result()?;
    }
    let r = deploy
        .call(deploy.id(), "deploy")
        .args_borsh(code.clone())
        .gas(Gas::from_tgas(300))
        .transact()
        .await?;
    log.rec("deploy_global_contract", &r);
    assert!(r.is_success(), "{:?}", r.clone().into_result().err());
    let after_global = bal(&w, deploy.id()).await?;

    let keys_dir = format!("{}/../.keys", env!("CARGO_MANIFEST_DIR"));
    let key_path = format!("{keys_dir}/ntt-play-factory.json");
    let factory = if bal(&w, &factory_id).await.is_ok() {
        acct(&w, "ntt-play-factory")?
    } else {
        let sk = SecretKey::from_random(KeyType::ED25519);
        anyhow::ensure!(!std::path::Path::new(&key_path).exists(), "{key_path} exists");
        std::fs::write(
            &key_path,
            json!({"account_id": factory_id, "public_key": sk.public_key(),
            "private_key": sk.to_string()})
            .to_string(),
        )?;
        let r = deploy
            .create_subaccount("play")
            .initial_balance(NearToken::from_yoctonear(factory_near))
            .keys(sk)
            .transact()
            .await?;
        println!("factory account {factory_id}: {}", r.is_success());
        r.into_result()?
    };
    let fr = factory.deploy(&factory_code).await?;
    println!("factory code deployed: {}", fr.is_success());
    assert!(fr.is_success());
    if view(&w, factory.id().as_str(), "get_config", json!({})).await.is_err() {
        let r = factory
            .call(factory.id(), "new")
            .args_json(json!({"admin": factory.id(), "code_hash": hash,
                "fee_config": {"fee_bps": 100, "fee_recipient": fees.id()},
                "dex_allowlist": [{"id": REF, "kind": "RheaClassic"}], "wrap": WRAP}))
            .transact()
            .await?;
        log.rec("factory_new", &r);
        assert!(r.is_success());
    } else {
        let r = factory
            .call(factory.id(), "set_code_hash")
            .args_json(json!({"code_hash": hash}))
            .deposit(NearToken::from_yoctonear(1))
            .transact()
            .await?;
        log.rec("factory_set_code_hash", &r);
        assert!(r.is_success());
    }
    let cfg = view(&w, factory.id().as_str(), "get_config", json!({})).await?;
    let min: Value = view(&w, factory.id().as_str(), "min_funding", json!({})).await?;
    let spent = spent0 - bal(&w, deploy.id()).await?;
    println!(
        "factory {} code_hash {} min_funding {min}; spent {:.4} NEAR (global {:.4})",
        factory.id(),
        cfg["code_hash"],
        spent as f64 / 1e24,
        (spent0 - after_global) as f64 / 1e24
    );
    let path = format!("{}/../testnet-e2e.json", env!("CARGO_MANIFEST_DIR"));
    let mut doc: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap_or("{}".into()))?;
    doc["playground"] = json!({"factory": factory.id(), "code_hash": hash, "wasm_bytes": code.len(),
        "global_deployer": deploy.id(), "min_funding": min, "fee_bps": 100, "fee_recipient": fees.id(),
        "dex_allowlist": [{"id": REF, "kind": "RheaClassic"}], "wrap": WRAP,
        "spent_yocto": spent.to_string(), "steps": log.0});
    std::fs::write(&path, serde_json::to_string_pretty(&doc)?)?;
    Ok(())
}
