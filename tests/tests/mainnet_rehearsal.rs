//! v1.6 mainnet deploy rehearsal (docs/MAINNET-GO.md §3 C2–C5) in a sandbox that mirrors mainnet.
//!
//! Mirrored from mainnet with READ-ONLY RPC views (nothing is ever sent to mainnet):
//! trade.unrlzd.near (factory 1.2.0 code + its whole state + its exact balance and storage, one
//! full-access key), the live TA 1.5.0 global code, deploy./admin./fees.unrlzd.near with their
//! exact balances, wrap.near, Rhea classic + DCL at their mainnet ids, and the admin DAO
//! unrlzd.sputnik-dao.near created through the mainnet sputnik-dao.near factory code with the
//! live `get_policy` (council cudam321.near + unrlzd.near, proposer = the live implicit id).
//! Every key is a fresh sandbox key.
//!
//! Then every transaction of scripts/mainnet-contract-deploy.sh is sent 1:1 (same signer,
//! receiver, actions, gas and deposit as the near-cli-rs command the script prints), with the
//! script itself run before each step against the sandbox RPC (its read-only gates) and its
//! `check` step at the end. A user account created by factory 1.2.0 on TA 1.5.0 is upgraded to
//! the new TA and trades.
//!
//! The script cannot SEND to a sandbox: it hard-codes `network-config mainnet-fastnear` and
//! `sign-with-keychain` (near-cli-rs has no config-dir override other than $HOME), so the
//! transactions are built here from the printed commands.
//!
//! Run (needs mainnet RPC for the views and `contracts/build.sh` or a wasm dir):
//!   REHEARSAL_WASM_DIR=$OUT cargo test --test mainnet_rehearsal -- --ignored --nocapture
use base64::Engine;
use integration_tests::*;
use near_primitives::action::{
    Action, DeleteKeyAction, DeployContractAction, DeployGlobalContractAction, FunctionCallAction,
    GlobalContractDeployMode, TransferAction,
};
use near_primitives::transaction::{SignedTransaction, Transaction, TransactionV0};
use near_workspaces::network::Sandbox;
use near_workspaces::types::{AccountDetailsPatch, Gas, KeyType, NearToken, SecretKey};
use near_workspaces::{Account, AccountId, Worker};
use serde_json::{json, Value};
use std::process::Command;

const MAINNET_RPC: &str = "https://free.rpc.fastnear.com";
const F: &str = "trade.unrlzd.near";
const DEP: &str = "deploy.unrlzd.near";
const ADMIN: &str = "admin.unrlzd.near";
const FEES: &str = "fees.unrlzd.near";
const DAO: &str = "unrlzd.sputnik-dao.near";
const PREV_FACTORY: &str = "AK2VXZnsFvJgK6XX9y5RoFEx985wq41nL3VEg2cp77dC";
const YOCTO: u128 = 1;

fn n(y: u128) -> String {
    format!("{:.6}", y as f64 / NEAR as f64)
}

async fn rpc_at(url: &str, method: &str, params: Value) -> anyhow::Result<Value> {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    let mut last = Value::Null;
    for i in 0..6u64 {
        if let Ok(r) = reqwest::Client::new().post(url).json(&body).send().await {
            let v: Value = r.json().await.unwrap_or_default();
            if v.get("result").is_some() {
                return Ok(v["result"].clone());
            }
            last = v;
            if url != MAINNET_RPC {
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(700 * (i + 1))).await;
    }
    anyhow::bail!("{method} on {url}: {last}")
}

/// Read-only mainnet view (never a transaction).
async fn main_query(params: Value) -> anyhow::Result<Value> {
    let mut p = params;
    p["finality"] = json!("final");
    rpc_at(MAINNET_RPC, "query", p).await
}

async fn main_view(acc: &str, method: &str, args: Value) -> anyhow::Result<Value> {
    let a = base64::engine::general_purpose::STANDARD.encode(args.to_string());
    let r = main_query(
        json!({"request_type": "call_function", "account_id": acc, "method_name": method, "args_base64": a}),
    )
    .await?;
    let bytes: Vec<u8> = serde_json::from_value(r["result"].clone())?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Mainnet global code by hash, cached under tests/.cache/ like `mainnet_code`.
async fn main_global_code(hash: &str) -> anyhow::Result<Vec<u8>> {
    let path = format!("{}/.cache/global-{hash}.wasm", env!("CARGO_MANIFEST_DIR"));
    if let Ok(b) = std::fs::read(&path) {
        return Ok(b);
    }
    let r = main_query(json!({"request_type": "view_global_contract_code", "code_hash": hash})).await?;
    let code = base64::engine::general_purpose::STANDARD.decode(r["code_base64"].as_str().unwrap())?;
    assert_eq!(code_hash(&code), hash);
    std::fs::create_dir_all(format!("{}/.cache", env!("CARGO_MANIFEST_DIR")))?;
    std::fs::write(&path, &code)?;
    Ok(code)
}

struct Key {
    id: String,
    sk: SecretKey,
}

/// A mainnet account mirrored into the sandbox: same id, balance and storage usage, a fresh
/// full-access key.
async fn mirror(
    w: &Worker<Sandbox>,
    id: &str,
    code: Option<&[u8]>,
    state: &[(Vec<u8>, Vec<u8>)],
) -> anyhow::Result<Key> {
    let v = main_query(json!({"request_type": "view_account", "account_id": id})).await?;
    let bal: u128 = v["amount"].as_str().unwrap().parse()?;
    let mut acct = AccountDetailsPatch::default().balance(NearToken::from_yoctonear(bal));
    acct.storage_usage = Some(v["storage_usage"].as_u64().unwrap());
    let aid: AccountId = id.parse()?;
    let sk = SecretKey::from_random(KeyType::ED25519);
    let mut p = w.patch(&aid).account(acct);
    if let Some(c) = code {
        p = p.code(c);
    }
    for (k, val) in state {
        p = p.state(k, val);
    }
    p.access_key(sk.public_key(), near_workspaces::AccessKey::full_access()).transact().await?;
    Ok(Key { id: id.into(), sk })
}

/// One signed transaction (the near-cli-rs command of the script, built 1:1), sent with
/// send_tx(FINAL). Returns the RPC result.
async fn send(w: &Worker<Sandbox>, k: &Key, receiver: &str, actions: Vec<Action>) -> anyhow::Result<Value> {
    let rpc = w.rpc_addr();
    let sk: near_crypto::SecretKey = k.sk.to_string().parse()?;
    let signer: near_primitives::types::AccountId = k.id.parse()?;
    let ak = rpc_at(
        &rpc,
        "query",
        json!({"request_type": "view_access_key", "finality": "optimistic", "account_id": k.id, "public_key": sk.public_key().to_string()}),
    )
    .await?;
    let head = rpc_at(&rpc, "block", json!({"finality": "final"})).await?;
    let tx = Transaction::V0(TransactionV0 {
        signer_id: signer.clone(),
        public_key: sk.public_key(),
        nonce: ak["nonce"].as_u64().unwrap() + 1,
        receiver_id: receiver.parse()?,
        block_hash: head["header"]["hash"].as_str().unwrap().parse().unwrap(),
        actions,
    });
    let (h, _) = tx.get_hash_and_size();
    let stx =
        SignedTransaction::new(near_crypto::InMemorySigner::from_secret_key(signer, sk).sign(h.as_ref()), tx);
    let b64 = base64::engine::general_purpose::STANDARD.encode(borsh::to_vec(&stx)?);
    rpc_at(&rpc, "send_tx", json!({"signed_tx_base64": b64, "wait_until": "FINAL"})).await
}

fn failures(r: &Value) -> Vec<String> {
    let mut f = vec![];
    if r["status"].get("Failure").is_some() {
        f.push(r["status"].to_string());
    }
    for ro in r["receipts_outcome"].as_array().unwrap() {
        if ro["outcome"]["status"].get("Failure").is_some() {
            f.push(ro["outcome"]["status"].to_string());
        }
    }
    f
}

fn burnt(r: &Value) -> (u128, f64) {
    let mut t: u128 = r["transaction_outcome"]["outcome"]["tokens_burnt"].as_str().unwrap().parse().unwrap();
    let mut g = r["transaction_outcome"]["outcome"]["gas_burnt"].as_u64().unwrap();
    for ro in r["receipts_outcome"].as_array().unwrap() {
        t += ro["outcome"]["tokens_burnt"].as_str().unwrap().parse::<u128>().unwrap();
        g += ro["outcome"]["gas_burnt"].as_u64().unwrap();
    }
    (t, g as f64 / 1e12)
}

fn logs(r: &Value) -> Vec<String> {
    r["receipts_outcome"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|ro| {
            ro["outcome"]["logs"].as_array().unwrap().iter().map(|l| l.as_str().unwrap().to_string())
        })
        .collect()
}

fn call(method: &str, args: Value, tgas: u64, deposit: u128) -> Action {
    Action::FunctionCall(Box::new(FunctionCallAction {
        method_name: method.into(),
        args: serde_json::to_vec(&args).unwrap(),
        gas: near_primitives::gas::Gas::from_gas(tgas * TGAS),
        deposit: NearToken::from_yoctonear(deposit),
    }))
}

async fn bal(w: &Worker<Sandbox>, id: &str) -> anyhow::Result<(u128, u64)> {
    let a = w.view_account(&id.parse()?).await?;
    Ok((a.balance.as_yoctonear(), a.storage_usage))
}

async fn view(w: &Worker<Sandbox>, id: &str, method: &str, args: Value) -> anyhow::Result<Value> {
    Ok(w.view(&id.parse()?, method).args_json(args).await?.json()?)
}

/// scripts/mainnet-contract-deploy.sh against the sandbox RPC (never --send: the dry run runs
/// the read-only gates and prints the command). NEAR_CLI is a command that always fails, so
/// nothing could ever be signed by it.
fn script(rpc: &str, wasm_dir: &str, expected: &str, step: &str) -> (bool, String) {
    let root = format!("{}/../..", env!("CARGO_MANIFEST_DIR"));
    let o = Command::new("sh")
        .arg(format!("{root}/scripts/mainnet-contract-deploy.sh"))
        .args([wasm_dir, step])
        .env("RPC", rpc)
        .env("EXPECTED_FILE", expected)
        .env("NEAR_CLI", "false")
        .output()
        .expect("sh");
    let s = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    println!("---- script {step}\n{s}");
    (o.status.success(), s)
}

struct Row {
    step: &'static str,
    signer: String,
    signer_delta: i128,
    burnt: u128,
    tgas: f64,
    note: String,
}

#[tokio::test]
#[ignore = "mainnet RPC views + local wasm; run with --ignored (see the file header)"]
async fn mainnet_v16_deploy_rehearsal() -> anyhow::Result<()> {
    let wasm_dir = std::env::var("REHEARSAL_WASM_DIR")
        .unwrap_or_else(|_| format!("{}/../out", env!("CARGO_MANIFEST_DIR")));
    let ta_new = std::fs::read(format!("{wasm_dir}/trading_account.wasm"))?;
    let factory_new = std::fs::read(format!("{wasm_dir}/factory.wasm"))?;
    let (ta_hash, factory_hash) = (code_hash(&ta_new), code_hash(&factory_new));
    println!(
        "wasm: trading_account {} B {ta_hash}, factory {} B {factory_hash}",
        ta_new.len(),
        factory_new.len()
    );

    // ---- the pinned values with this build's hashes (the script's EXPECTED_FILE)
    let exp_src = format!("{}/../../deploy/contracts/mainnet.expected.json", env!("CARGO_MANIFEST_DIR"));
    let mut exp: Value = serde_json::from_str(&std::fs::read_to_string(&exp_src)?)?;
    exp["account_code_hash"] = json!(ta_hash);
    exp["factory_code_hash"] = json!(factory_hash);
    exp["_source"] = json!(format!("rehearsal build {wasm_dir}"));
    let expected = format!("{}/rehearsal.expected.json", env!("CARGO_TARGET_TMPDIR"));
    std::fs::write(&expected, serde_json::to_string_pretty(&exp)?)?;
    let dao_id = exp["admin_multisig"].as_str().unwrap().to_string();
    assert_eq!(dao_id, DAO);

    // ---- mainnet, read-only
    let mcfg = main_view(F, "get_config", json!({})).await?;
    let ta_old_hash = mcfg["code_hash"].as_str().unwrap().to_string();
    let ta_old = main_global_code(&ta_old_hash).await?;
    let f_code = mainnet_code(F).await?;
    assert_eq!(code_hash(&f_code), PREV_FACTORY, "mainnet factory is no longer 1.2.0");
    let st = main_query(json!({"request_type": "view_state", "account_id": F, "prefix_base64": ""})).await?;
    let b64 = base64::engine::general_purpose::STANDARD;
    let f_state: Vec<(Vec<u8>, Vec<u8>)> = st["values"]
        .as_array()
        .unwrap()
        .iter()
        .map(|kv| {
            (
                b64.decode(kv["key"].as_str().unwrap()).unwrap(),
                b64.decode(kv["value"].as_str().unwrap()).unwrap(),
            )
        })
        .collect();
    let policy = main_view(DAO, "get_policy", json!({})).await?;
    let dao_cfg = main_view(DAO, "get_config", json!({})).await?;
    let gas_price = rpc_at(MAINNET_RPC, "gas_price", json!([null])).await?;
    println!(
        "mainnet: factory state {} keys, TA global {ta_old_hash}, gas price {}",
        f_state.len(),
        gas_price["gas_price"]
    );
    let council: Vec<String> = serde_json::from_value(
        policy["roles"].as_array().unwrap().iter().find(|r| r["name"] == "council").unwrap()["kind"]["Group"]
            .clone(),
    )?;
    let proposer: String =
        policy["roles"].as_array().unwrap().iter().find(|r| r["name"] == "proposer").unwrap()["kind"]
            ["Group"][0]
            .as_str()
            .unwrap()
            .into();
    println!(
        "DAO policy: council {council:?}, proposer {proposer}, default {}",
        policy["default_vote_policy"]
    );

    // ---- sandbox mirror
    let w = near_workspaces::sandbox().await?;
    let rpc = w.rpc_addr();
    let root = w.root_account()?;
    println!("sandbox gas price {}", rpc_at(&rpc, "gas_price", json!([null])).await?["gas_price"]);
    let wrap = install_mainnet(&w, "wrap.near").await?;
    ok(wrap.call("new").args_json(json!({})).transact().await?)?;
    let rhea = install_mainnet(&w, "v2.ref-finance.near").await?;
    let rhea_owner = sub(&root, "rheaowner", 5_000 * NEAR).await?;
    ok(rhea
        .call("new")
        .args_json(json!({"owner_id": rhea_owner.id(), "boost_farm_id": rhea_owner.id(), "burrowland_id": rhea_owner.id(), "exchange_fee": 4, "referral_fee": 1}))
        .transact()
        .await?)?;
    let dcl = install_mainnet(&w, "dclv2.ref-labs.near").await?;
    ok(dcl
        .call("new")
        .args_json(json!({"owner_id": rhea_owner.id(), "wnear_id": wrap.id(), "farming_contract_id": rhea_owner.id()}))
        .transact()
        .await?)?;
    // Rhea classic pool wNEAR/MEME (1000 N : 1M MEME)
    let meme = sub(&root, "meme", 50 * NEAR).await?.deploy(&out("mock_ft")).await?.into_result()?;
    ok(meme.call("new").transact().await?)?;
    let meme_liq: u128 = 1_000_000 * 10u128.pow(18);
    for acc in [rhea.id(), rhea_owner.id()] {
        ok(rhea_owner
            .call(wrap.id(), "storage_deposit")
            .args_json(json!({"account_id": acc}))
            .deposit(NearToken::from_millinear(125))
            .transact()
            .await?)?;
        ok(meme.call("mint").args_json(json!({"account_id": acc, "amount": "0"})).transact().await?)?;
    }
    ok(meme
        .call("mint")
        .args_json(json!({"account_id": rhea_owner.id(), "amount": meme_liq.to_string()}))
        .transact()
        .await?)?;
    ok(rhea_owner
        .call(rhea.id(), "storage_deposit")
        .args_json(json!({}))
        .deposit(NearToken::from_near(1))
        .transact()
        .await?)?;
    ok(rhea_owner
        .call(rhea.id(), "extend_whitelisted_tokens")
        .args_json(json!({"tokens": [wrap.id(), meme.id()]}))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?)?;
    let pool_id: u64 = okr(rhea_owner
        .call(rhea.id(), "add_simple_pool")
        .args_json(json!({"tokens": [wrap.id(), meme.id()], "fee": 25}))
        .deposit(NearToken::from_millinear(100))
        .transact()
        .await?)?
    .json()?;
    ok(rhea_owner
        .call(wrap.id(), "near_deposit")
        .args_json(json!({}))
        .deposit(NearToken::from_near(1000))
        .transact()
        .await?)?;
    for (tok, amt) in [(wrap.id(), 1000 * NEAR), (meme.id(), meme_liq)] {
        ok(rhea_owner
            .call(tok, "ft_transfer_call")
            .args_json(json!({"receiver_id": rhea.id(), "amount": amt.to_string(), "msg": ""}))
            .deposit(NearToken::from_yoctonear(1))
            .gas(Gas::from_tgas(100))
            .transact()
            .await?)?;
    }
    ok(rhea_owner
        .call(rhea.id(), "add_liquidity")
        .args_json(json!({"pool_id": pool_id, "amounts": [(1000 * NEAR).to_string(), meme_liq.to_string()]}))
        .deposit(NearToken::from_millinear(10))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?)?;
    for id in ["dex.intear.near", "factory.shardsmarket.near"] {
        w.patch(&id.parse()?)
            .account(AccountDetailsPatch::default().balance(NearToken::from_near(10)))
            .transact()
            .await?;
    }

    // the TA 1.5.0 global code (the live hash), deployed by a helper account
    let gdep = sub(&root, "gdep", 1_000 * NEAR).await?;
    let gk = Key { id: gdep.id().to_string(), sk: gdep.secret_key().clone() };
    let r = send(
        &w,
        &gk,
        gdep.id().as_str(),
        vec![Action::DeployGlobalContract(DeployGlobalContractAction {
            code: ta_old.clone().into(),
            deploy_mode: GlobalContractDeployMode::CodeHash,
        })],
    )
    .await?;
    assert!(failures(&r).is_empty(), "{:?}", failures(&r));

    // the unrlzd accounts, mirrored
    let fk = mirror(&w, F, Some(&f_code), &f_state).await?;
    let dk = mirror(&w, DEP, None, &[]).await?;
    let ak = mirror(&w, ADMIN, None, &[]).await?;
    mirror(&w, FEES, None, &[]).await?;
    let pk = mirror(&w, "unrlzd.near", None, &[]).await?;
    let ck = mirror(&w, "cudam321.near", None, &[]).await?;
    let prk = mirror(&w, &proposer, None, &[]).await?;
    assert_eq!(view(&w, F, "get_config", json!({})).await?, mcfg, "mirrored factory config != mainnet");
    // wrap.near registrations as on mainnet
    for id in [F, FEES] {
        let m = main_view("wrap.near", "storage_balance_of", json!({"account_id": id})).await?;
        println!("mainnet wrap.near storage_balance_of({id}) = {m}");
        if !m.is_null() {
            ok(root
                .call(wrap.id(), "storage_deposit")
                .args_json(json!({"account_id": id}))
                .deposit(NearToken::from_micronear(1250))
                .transact()
                .await?)?;
        }
    }

    // the admin DAO, through the mainnet sputnik-dao.near factory code
    let sf = install_mainnet(&w, "sputnik-dao.near").await?;
    let dao_code = mainnet_code(DAO).await?;
    let dao_hash = code_hash(&dao_code);
    let main_default: String =
        serde_json::from_value(main_view("sputnik-dao.near", "get_default_code_hash", json!({})).await?)?;
    assert_eq!(dao_hash, main_default, "the DAO runs the factory's default code");
    let r = sf.call("new").args_json(json!({})).gas(Gas::from_tgas(300)).transact().await?;
    println!("sputnik factory new: {:?}", r.clone().into_result().err());
    let r = sf
        .as_account()
        .call(sf.id(), "store")
        .args(dao_code.clone())
        .deposit(NearToken::from_near(60))
        .gas(Gas::from_tgas(300))
        .transact()
        .await?;
    println!(
        "sputnik factory store: ok={} {:?}",
        r.is_success(),
        r.clone().into_result().err().map(|e| format!("{e:?}").chars().take(300).collect::<String>())
    );
    let r = sf
        .as_account()
        .call(sf.id(), "set_default_code_hash")
        .args_json(json!({"code_hash": dao_hash}))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?;
    println!("sputnik factory set_default_code_hash: ok={}", r.is_success());
    let dao_args = b64.encode(json!({"config": dao_cfg, "policy": policy}).to_string());
    // created from the sandbox root (the live unrlzd.near balance is already net of the 6 N)
    let r = root
        .call(sf.id(), "create")
        .args_json(json!({"name": "unrlzd", "args": dao_args}))
        .deposit(NearToken::from_near(6))
        .gas(Gas::from_tgas(300))
        .transact()
        .await?;
    let via_factory = r.is_success() && r.receipt_failures().is_empty();
    if !via_factory {
        // fallback (reported): the DAO code installed directly + the same new(config, policy)
        println!(
            "sputnik factory create failed: {:?}",
            r.into_result().err().map(|e| format!("{e:?}").chars().take(400).collect::<String>())
        );
        let d = install_code(&w, DAO, &dao_code).await?;
        ok(d.call("new").args_json(json!({"config": dao_cfg, "policy": policy})).transact().await?)?;
    }
    let dv = w.view_account(&DAO.parse()?).await?;
    println!("DAO created via factory: {via_factory}; account code {:?}", dv.contract_state);
    assert_eq!(view(&w, DAO, "get_policy", json!({})).await?, policy, "sandbox DAO policy != mainnet");

    // ---- a user created by factory 1.2.0 on TA 1.5.0 (none exist on mainnet yet), trades
    let alice = sub(&root, "alice", 40 * NEAR).await?;
    let dsk = SecretKey::from_random(KeyType::ED25519);
    ok(alice
        .call(&F.parse()?, "create_account")
        .args_json(json!({"device_public_key": dsk.public_key(), "caps": caps_json((NEAR, 5 * NEAR))}))
        .deposit(NearToken::from_near(5))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?)?;
    let acc: AccountId =
        view(&w, F, "account_for", json!({"owner": alice.id()})).await?.as_str().unwrap().parse()?;
    let device = Account::from_secret_key(acc.clone(), dsk.clone(), &w);
    let gh = w.view_account(&acc).await?.contract_state;
    println!("alice's account {acc} runs {gh:?}");
    let buy = |amount: u128| {
        json!([
            {"StorageDeposit": {"token": meme.id(), "amount": STORAGE.to_string()}},
            {"NearDeposit": {"amount": amount.to_string()}},
            {"FtTransferCall": {"token": wrap.id(), "receiver_id": rhea.id(), "amount": amount.to_string(),
              "msg": json!({"force": 0, "actions": [{"pool_id": pool_id, "token_in": wrap.id(), "token_out": meme.id(),
                "amount_in": amount.to_string(), "amount_out": "0", "min_amount_out": "1"}], "skip_unwrap_near": true}).to_string(),
              "gas": (150 * TGAS).to_string()}}
        ])
    };
    let exec = |ops: Value, id: &str, max_in: u128| {
        let device = device.clone();
        let acc = acc.clone();
        let id = id.to_string();
        let w = w.clone();
        async move {
            let exp = w.view_block().await?.timestamp() + 60_000_000_000;
            anyhow::Ok(
                device
                    .call(&acc, "execute")
                    .args_json(json!({"ops": ops, "client_order_id": id, "expires_at_ns": exp.to_string(), "max_in_yocto": max_in.to_string()}))
                    .gas(Gas::from_tgas(300))
                    .transact()
                    .await?,
            )
        }
    };
    ok(exec(buy(NEAR / 2), "pre-1", NEAR).await?)?;
    let meme_bal = |id: AccountId| {
        let meme = meme.clone();
        async move {
            anyhow::Ok(
                meme.view("ft_balance_of")
                    .args_json(json!({"account_id": id}))
                    .await?
                    .json::<String>()?
                    .parse::<u128>()?,
            )
        }
    };
    let m0 = meme_bal(acc.clone()).await?;
    assert!(m0 > 0);
    println!("TA 1.5.0 buy ok: {m0} MEME");

    // ---- the deploy, step by step
    let mut rows: Vec<Row> = vec![];
    println!("\n==== plan (dry run against the sandbox)");
    script(&rpc, &wasm_dir, &expected, "plan");

    // preflight accounts (deployer balance gate), against the sandbox mirror
    let pre = Command::new("node")
        .current_dir(format!("{}/../..", env!("CARGO_MANIFEST_DIR")))
        .args([
            "scripts/mainnet-preflight.mts",
            "accounts",
            "--deployer",
            DEP,
            "--factory",
            F,
            "--rpc",
            &rpc,
            "--expected",
            &expected,
            "--wasm-dir",
            &wasm_dir,
        ])
        .output()?;
    println!("---- preflight accounts (sandbox)\n{}", String::from_utf8_lossy(&pre.stdout));

    // C2 global
    let (okg, s) = script(&rpc, &wasm_dir, &expected, "global");
    assert!(okg && !s.contains("FAIL"), "global gate");
    let (b0, _) = bal(&w, DEP).await?;
    let r = send(
        &w,
        &dk,
        DEP,
        vec![Action::DeployGlobalContract(DeployGlobalContractAction {
            code: ta_new.clone().into(),
            deploy_mode: GlobalContractDeployMode::CodeHash,
        })],
    )
    .await?;
    let fl = failures(&r);
    let (b1, _) = bal(&w, DEP).await?;
    let (t, g) = burnt(&r);
    rows.push(Row {
        step: "C2 global",
        signer: DEP.into(),
        signer_delta: b1 as i128 - b0 as i128,
        burnt: t,
        tgas: g,
        note: format!("{} B; left {} N; {:?}", ta_new.len(), n(b1), fl),
    });
    assert!(fl.is_empty(), "global deploy failed: {fl:?}");
    let (_, s) = script(&rpc, &wasm_dir, &expected, "global");
    assert!(s.contains("SKIP"), "global not seen as live");

    // C3 factory: DeployContract + migrate in one tx, signed by the factory account
    let (okf, s) = script(&rpc, &wasm_dir, &expected, "factory");
    assert!(
        okf && s.contains("PASS trade.unrlzd.near runs factory 1.2.0")
            && s.contains("is live as global code"),
        "factory gate"
    );
    let short = s.contains("WARN trade.unrlzd.near holds");
    let migrate = json!({"code_hash": exp["account_code_hash"], "signed_code": exp["signed_code"], "dex_allowlist": exp["dex_allowlist"]});
    let (b0, s0) = bal(&w, F).await?;
    let r = send(
        &w,
        &fk,
        F,
        vec![
            Action::DeployContract(DeployContractAction { code: factory_new.clone() }),
            call("migrate", migrate.clone(), 100, 0),
        ],
    )
    .await?;
    let mut fl = failures(&r);
    assert_eq!(short, !fl.is_empty(), "the script's factory balance gate must predict the deploy outcome");
    let (b1, s1) = bal(&w, F).await?;
    let (t, g) = burnt(&r);
    let mut note = format!(
        "storage {s0} -> {s1} B (needs {} N locked), balance {} -> {} N; {fl:?}",
        n(s1 as u128 * 10u128.pow(19)),
        n(b0),
        n(b1)
    );
    if !fl.is_empty() {
        // the mirrored balance is short: top up from unrlzd.near (as the owner would) and retry
        println!("C3 failed with the mainnet balance: {fl:?}; topping up 1 N");
        let rk = Key { id: root.id().to_string(), sk: root.secret_key().clone() };
        let top =
            send(&w, &rk, F, vec![Action::Transfer(TransferAction { deposit: NearToken::from_near(1) })])
                .await?;
        assert!(failures(&top).is_empty());
        let (b0b, _) = bal(&w, F).await?;
        let (_, s) = script(&rpc, &wasm_dir, &expected, "factory");
        assert!(s.contains("PASS trade.unrlzd.near holds"), "the balance gate passes after the top-up");
        let r2 = send(
            &w,
            &fk,
            F,
            vec![
                Action::DeployContract(DeployContractAction { code: factory_new.clone() }),
                call("migrate", migrate.clone(), 100, 0),
            ],
        )
        .await?;
        fl = failures(&r2);
        let (b2, s2) = bal(&w, F).await?;
        note = format!(
            "FAILED at the mainnet balance {} N ({note}); after a top-up to {} N: storage {s2} B (locks {} N), balance {} N; {fl:?}",
            n(b0),
            n(b0b),
            n(s2 as u128 * 10u128.pow(19)),
            n(b2)
        );
    }
    rows.push(Row {
        step: "C3 factory+migrate",
        signer: F.into(),
        signer_delta: bal(&w, F).await?.0 as i128 - b0 as i128,
        burnt: t,
        tgas: g,
        note,
    });
    assert!(fl.is_empty(), "factory deploy failed: {fl:?}");
    assert!(logs(&r).iter().any(|l| l.contains("factory_bootstrapped")) || fl.is_empty());
    let cfg = view(&w, F, "get_config", json!({})).await?;
    let adm = view(&w, F, "get_admin_state", json!({})).await?;
    let approved = view(&w, F, "get_approved_code_hashes", json!({})).await?;
    let signed = view(&w, F, "get_signed_config", json!({})).await?;
    println!("after C3: code_hash {} | allowlist {} | fee {} | approved {approved} | admin_state {adm} | signed {signed}", cfg["code_hash"], cfg["dex_allowlist"].as_array().unwrap().len(), cfg["fee_config"]);
    assert_eq!(cfg["code_hash"], ta_hash.as_str(), "code hash applied at once (no timelock)");
    assert_eq!(approved, json!([ta_hash]), "signed code approved at once");
    assert_eq!(cfg["dex_allowlist"].as_array().unwrap().len(), 24);
    for k in
        ["pending_code", "pending_admin", "pending_dex_allowlist", "pending_fee_config", "pending_verifier"]
    {
        assert_eq!(adm[k], Value::Null, "{k}");
    }
    assert_eq!(adm["code_timelock_ns"], "86400000000000");

    // C3 wrap
    let (okw, _) = script(&rpc, &wasm_dir, &expected, "wrap");
    assert!(okw);
    let (b0, _) = bal(&w, F).await?;
    let r = send(
        &w,
        &fk,
        "wrap.near",
        vec![call(
            "storage_deposit",
            json!({"account_id": F, "registration_only": true}),
            30,
            1_250_000_000_000_000_000_000,
        )],
    )
    .await?;
    let fl = failures(&r);
    let (b1, _) = bal(&w, F).await?;
    let (t, g) = burnt(&r);
    rows.push(Row {
        step: "C3 wrap",
        signer: F.into(),
        signer_delta: b1 as i128 - b0 as i128,
        burnt: t,
        tgas: g,
        note: format!("{fl:?}"),
    });
    assert!(fl.is_empty());

    // C4: a DAO proposal approved BEFORE propose_admin executes accept_admin too early
    let kind = json!({"FunctionCall": {"receiver_id": F, "actions": [{"method_name": "accept_admin", "args": "e30=", "deposit": "1", "gas": "30000000000000"}]}});
    let proposal = json!({"proposal": {"description": "UNRLZD factory trade.unrlzd.near: accept_admin (admin -> unrlzd.sputnik-dao.near)", "kind": kind}});
    let add = |k: &Key| {
        let (w, k, proposal) = (w.clone(), Key { id: k.id.clone(), sk: k.sk.clone() }, proposal.clone());
        async move { send(&w, &k, DAO, vec![call("add_proposal", proposal, 30, 0)]).await }
    };
    let vote = |k: &Key, id: u64, tgas: u64| {
        let (w, k, kind) = (w.clone(), Key { id: k.id.clone(), sk: k.sk.clone() }, kind.clone());
        async move {
            send(
                &w,
                &k,
                DAO,
                vec![call(
                    "act_proposal",
                    json!({"id": id, "action": "VoteApprove", "proposal": kind}),
                    tgas,
                    0,
                )],
            )
            .await
        }
    };
    let r = add(&prk).await?;
    assert!(failures(&r).is_empty(), "early proposal: {:?}", failures(&r));
    let early: u64 = view(&w, DAO, "get_last_proposal_id", json!({})).await?.as_u64().unwrap() - 1;
    let council_keys: Vec<&Key> = council.iter().map(|c| if *c == ck.id { &ck } else { &pk }).collect();
    assert_eq!(council_keys.len(), 2);
    ok_v(vote(council_keys[0], early, 200).await?)?;
    let r = vote(council_keys[1], early, 200).await?;
    let p = view(&w, DAO, "get_proposal", json!({"id": early})).await?;
    println!(
        "early proposal #{early} (approved before propose_admin): status {} | failures {:?}",
        p["status"],
        failures(&r)
    );
    assert_eq!(cfg_admin(&w).await?, ADMIN, "accept before propose must not change the admin");

    // C4 propose (admin.unrlzd.near, 1 yocto)
    let (okp, _) = script(&rpc, &wasm_dir, &expected, "propose");
    assert!(okp);
    let (b0, _) = bal(&w, ADMIN).await?;
    let r = send(&w, &ak, F, vec![call("propose_admin", json!({"new_admin": DAO}), 30, YOCTO)]).await?;
    let fl = failures(&r);
    let (b1, _) = bal(&w, ADMIN).await?;
    let (t, g) = burnt(&r);
    rows.push(Row {
        step: "C4 propose_admin",
        signer: ADMIN.into(),
        signer_delta: b1 as i128 - b0 as i128,
        burnt: t,
        tgas: g,
        note: format!("{fl:?}"),
    });
    assert!(fl.is_empty());
    assert_eq!(view(&w, F, "get_admin_state", json!({})).await?["pending_admin"], DAO);
    let (okd, s) = script(&rpc, &wasm_dir, &expected, "dao");
    assert!(okd && s.contains("PASS pending_admin") && s.contains(&proposer), "dao step");

    // C4 DAO: the proposer key adds, both council members approve; the second vote executes
    let (b0, _) = bal(&w, &prk.id).await?;
    let r = add(&prk).await?;
    let fl = failures(&r);
    let (b1, _) = bal(&w, &prk.id).await?;
    let (t, g) = burnt(&r);
    rows.push(Row {
        step: "C4 DAO add_proposal",
        signer: format!("proposer {}…", &prk.id[..8]),
        signer_delta: b1 as i128 - b0 as i128,
        burnt: t,
        tgas: g,
        note: format!("{fl:?}"),
    });
    assert!(fl.is_empty());
    let pid: u64 = view(&w, DAO, "get_last_proposal_id", json!({})).await?.as_u64().unwrap() - 1;
    // the proposer cannot vote
    let r = vote(&prk, pid, 100).await?;
    assert!(!failures(&r).is_empty(), "the proposer voted");
    for (i, k) in council_keys.iter().enumerate() {
        let (b0, _) = bal(&w, &k.id).await?;
        let r = vote(k, pid, 100).await?;
        let fl = failures(&r);
        let (b1, _) = bal(&w, &k.id).await?;
        let (t, g) = burnt(&r);
        let p = view(&w, DAO, "get_proposal", json!({"id": pid})).await?;
        rows.push(Row {
            step: if i == 0 { "C4 DAO vote 1" } else { "C4 DAO vote 2 (executes)" },
            signer: k.id.clone(),
            signer_delta: b1 as i128 - b0 as i128,
            burnt: t,
            tgas: g,
            note: format!("status {} {fl:?}", p["status"]),
        });
        if i == 0 {
            assert_eq!(p["status"], "InProgress", "one council vote must not pass");
            assert_eq!(cfg_admin(&w).await?, ADMIN);
        } else {
            assert_eq!(p["status"], "Approved");
            assert!(fl.is_empty(), "{fl:?}");
        }
    }
    assert_eq!(cfg_admin(&w).await?, DAO);
    assert_eq!(view(&w, F, "get_admin_state", json!({})).await?["pending_admin"], Value::Null);

    // C5 keys: the script's gate (check-factory with the DAO admin + wrap registered), then delete
    let (okk, _) = script(&rpc, &wasm_dir, &expected, "keys");
    assert!(okk);
    let cf = Command::new("sh")
        .arg(format!("{}/../scripts/check-factory.sh", env!("CARGO_MANIFEST_DIR")))
        .args([F, &expected])
        .env("RPC", &rpc)
        .env("EXPECTED_ADMIN", DAO)
        .output()?;
    println!("---- check-factory before keys\n{}", String::from_utf8_lossy(&cf.stdout));
    assert!(cf.status.success(), "check-factory gate");
    let (b0, _) = bal(&w, F).await?;
    let pkc: near_crypto::SecretKey = fk.sk.to_string().parse()?;
    let r =
        send(&w, &fk, F, vec![Action::DeleteKey(Box::new(DeleteKeyAction { public_key: pkc.public_key() }))])
            .await?;
    let fl = failures(&r);
    let (b1, s_end) = bal(&w, F).await?;
    let (t, g) = burnt(&r);
    rows.push(Row {
        step: "C5 delete keys",
        signer: F.into(),
        signer_delta: b1 as i128 - b0 as i128,
        burnt: t,
        tgas: g,
        note: format!(
            "{fl:?}; factory ends at {} N, storage {s_end} B = {} N locked, {} N free",
            n(b1),
            n(s_end as u128 * 10u128.pow(19)),
            n(b1.saturating_sub(s_end as u128 * 10u128.pow(19)))
        ),
    });
    assert!(fl.is_empty());

    // C5 check: the script's own read-only check step + the preflight
    let (okc, s) = script(&rpc, &wasm_dir, &expected, "check");
    assert!(
        okc && s.contains("OK")
            && s.contains("PASS no full-access key")
            && s.contains("registered on wrap.near"),
        "check step"
    );
    let pre = Command::new("node")
        .current_dir(format!("{}/../..", env!("CARGO_MANIFEST_DIR")))
        .env("EXPECTED_ADMIN", DAO)
        .args([
            "scripts/mainnet-preflight.mts",
            "factory",
            "accounts",
            "--factory",
            F,
            "--deployer",
            DEP,
            "--rpc",
            &rpc,
            "--expected",
            &expected,
            "--wasm-dir",
            &wasm_dir,
        ])
        .output()?;
    println!("---- preflight factory accounts (sandbox, after C5)\n{}", String::from_utf8_lossy(&pre.stdout));

    // ---- alice: upgrade 1.5.0 -> new TA with the owner wallet, then trade
    let r = alice
        .call(&acc, "owner_upgrade")
        .args_json(json!({"code_hash": ta_hash}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(300))
        .transact()
        .await?;
    println!(
        "alice owner_upgrade: success={} failures={:?} gas {:.1} Tgas",
        r.is_success(),
        r.receipt_failures().len(),
        r.total_gas_burnt.as_gas() as f64 / 1e12
    );
    ok(r)?;
    let cs = w.view_account(&acc).await?.contract_state;
    println!(
        "alice's account now runs {cs:?}; auto_upgrade {}",
        view(&w, acc.as_str(), "get_auto_upgrade", json!({})).await?
    );
    let r = exec(buy(NEAR / 2), "post-1", NEAR).await?;
    ok(r)?;
    let m1 = meme_bal(acc.clone()).await?;
    assert!(m1 > m0, "post-upgrade buy");
    let sell = json!([{"FtTransferCall": {"token": meme.id(), "receiver_id": rhea.id(), "amount": (m1 / 2).to_string(),
        "msg": json!({"force": 0, "actions": [{"pool_id": pool_id, "token_in": meme.id(), "token_out": wrap.id(),
            "amount_in": (m1 / 2).to_string(), "amount_out": "0", "min_amount_out": "1"}], "skip_unwrap_near": false}).to_string(),
        "gas": (150 * TGAS).to_string()}}]);
    ok(exec(sell, "post-2", 0).await?)?;
    let m2 = meme_bal(acc.clone()).await?;
    assert!(m2 < m1, "post-upgrade sell");
    println!("TA after upgrade: buy {} -> {m1} MEME, sell -> {m2} MEME", m0);
    // a NEW account through factory 1.3.0 gets the new code and the 24-entry allowlist
    let bob = sub(&root, "bob", 20 * NEAR).await?;
    let d2 = SecretKey::from_random(KeyType::ED25519);
    ok(bob
        .call(&F.parse()?, "create_account")
        .args_json(json!({"device_public_key": d2.public_key(), "caps": caps_json((NEAR, 5 * NEAR))}))
        .deposit(NearToken::from_near(1))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?)?;
    let bacc: AccountId =
        view(&w, F, "account_for", json!({"owner": bob.id()})).await?.as_str().unwrap().parse()?;
    println!(
        "bob's new account {bacc} runs {:?}, allowlist {}",
        w.view_account(&bacc).await?.contract_state,
        view(&w, bacc.as_str(), "get_config", json!({})).await?["dex_allowlist"].as_array().unwrap().len()
    );

    println!("\n==== REHEARSAL STEP TABLE");
    println!("step | signer | signer balance delta (N) | tokens burnt (N) | gas burnt (Tgas) | note");
    for r in &rows {
        println!(
            "{} | {} | {} | {} | {:.2} | {}",
            r.step,
            r.signer,
            if r.signer_delta < 0 {
                format!("-{}", n((-r.signer_delta) as u128))
            } else {
                n(r.signer_delta as u128)
            },
            n(r.burnt),
            r.tgas,
            r.note
        );
    }
    Ok(())
}

fn ok_v(r: Value) -> anyhow::Result<()> {
    let f = failures(&r);
    anyhow::ensure!(f.is_empty(), "{f:?}");
    Ok(())
}

async fn cfg_admin(w: &Worker<Sandbox>) -> anyhow::Result<String> {
    Ok(view(w, F, "get_config", json!({})).await?["admin"].as_str().unwrap().to_string())
}
