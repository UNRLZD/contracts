//! Sandbox harness: real wrap.near + Rhea (v2.ref-finance.near) imported from mainnet,
//! a mock NEP-141 "MEME" token, global trading-account code, and the factory.
use anyhow::{anyhow, Result};
use near_workspaces::network::Sandbox;
use near_workspaces::result::ExecutionFinalResult;
use near_workspaces::types::{Gas, KeyType, NearToken, PublicKey, SecretKey};
use near_workspaces::{Account, AccountId, Contract, Worker};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const NEAR: u128 = 1_000_000_000_000_000_000_000_000;
pub const TGAS: u64 = 1_000_000_000_000;
pub const FEE_BPS: u128 = 100;
pub const RESERVE: u128 = NEAR / 20;
pub const STORAGE: u128 = 1_250_000_000_000_000_000_000; // 0.00125 NEAR
/// v1.5: the Shards launchpad factory (mainnet id; tokens are `<label>.factory.shardsmarket.near`).
pub const SHARDS_FACTORY: &str = "factory.shardsmarket.near";
/// Shards token `storage_balance_bounds` (min = max = 0.005 NEAR).
pub const SHARDS_STORAGE: u128 = 5_000_000_000_000_000_000_000;

/// A wasm from `contracts/out/` (built by `build.sh`), or, for the frozen older releases the
/// upgrade/migrate tests need (v1.2 … v1.4.4), from `tests/fixtures/` (v1.4.8, UNR-A-07: committed
/// with `SHA256SUMS`, so the suite runs from a clean public checkout; `out/` wins if present).
pub fn out(name: &str) -> Vec<u8> {
    let dir = env!("CARGO_MANIFEST_DIR");
    let p = format!("{dir}/../out/{name}.wasm");
    let f = format!("{dir}/fixtures/{name}.wasm");
    std::fs::read(&p).or_else(|_| std::fs::read(&f)).unwrap_or_else(|_| {
        panic!("{p} missing: run contracts/build.sh first (legacy releases: tests/fixtures/{name}.wasm)")
    })
}

pub fn code_hash(code: &[u8]) -> String {
    bs58::encode(Sha256::digest(code)).into_string()
}

pub struct Env {
    pub worker: Worker<Sandbox>,
    pub root: Account,
    pub wrap: Contract,
    pub rhea: Contract,
    pub meme: Contract,
    pub factory: Contract,
    pub deployer: Contract,
    pub fees: Account,
    pub admin: Account,
    /// Allowlisted as DCL / Plach but with no contract (shape + refund tests).
    pub dcl: Account,
    pub plach: Account,
    pub code_hash: String,
    pub pool_id: u64,
}

pub struct User {
    pub owner: Account,
    pub account: AccountId,
    pub device: Account,
    pub device_sk: SecretKey,
}

pub async fn sub(root: &Account, name: &str, near: u128) -> Result<Account> {
    Ok(root
        .create_subaccount(name)
        .initial_balance(NearToken::from_yoctonear(near))
        .transact()
        .await?
        .into_result()?)
}

/// Tx and every receipt succeeded.
pub fn okr(r: ExecutionFinalResult) -> Result<ExecutionFinalResult> {
    if !r.is_success() {
        return Err(anyhow!("tx failed: {:?}", r.into_result().err()));
    }
    if let Some(f) = r.receipt_failures().first() {
        return Err(anyhow!("receipt failed: {f:?}"));
    }
    Ok(r)
}

pub fn ok(r: ExecutionFinalResult) -> Result<()> {
    okr(r).map(|_| ())
}

/// Asserts the tx failed with a contract panic carrying exactly `code`.
pub fn fails_with(r: &ExecutionFinalResult, code: &str) {
    assert!(r.is_failure(), "expected {code}, tx succeeded");
    let s = format!("{:?}", r.clone().into_result().err());
    let pat = format!("Smart contract panicked: {code}");
    let exact = s
        .match_indices(&pat)
        .any(|(i, _)| !s[i + pat.len()..].starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_'));
    assert!(exact, "expected {code}, got {}", &s[..s.len().min(600)]);
}

impl Env {
    pub async fn new() -> Result<Self> {
        let var = |k: &str| std::env::var(k).ok().map(|p| std::fs::read(p).expect(k));
        Self::new_with(var("NT_ACCOUNT_WASM"), var("NT_FACTORY_WASM")).await
    }

    /// Same environment with explicit account / factory wasm (default: this build's out/).
    pub async fn new_with(account_wasm: Option<Vec<u8>>, factory_wasm: Option<Vec<u8>>) -> Result<Self> {
        Self::new_with_dexes(account_wasm, factory_wasm, vec![]).await
    }

    /// v1.5: this build + the Shards factory allowlisted as a `ShardsToken` entry (factory 1.2.0).
    pub async fn new_shards() -> Result<Self> {
        Self::new_with_dexes(None, None, vec![json!({"id": SHARDS_FACTORY, "kind": "ShardsToken"})]).await
    }

    /// `extra_dexes` are appended to the factory's allowlist (v1.5: ShardsToken entries).
    pub async fn new_with_dexes(
        account_wasm: Option<Vec<u8>>,
        factory_wasm: Option<Vec<u8>>,
        extra_dexes: Vec<Value>,
    ) -> Result<Self> {
        let worker = near_workspaces::sandbox().await?;
        let root = worker.root_account()?;
        let wrap = install_mainnet(&worker, "wrap.near").await?;
        // Red->green: NT_ACCOUNT_WASM / NT_FACTORY_WASM swap in other builds (e.g. the frozen
        // v1.2 audit copy in audit/contract/wasm/) for the same tests.
        ok(wrap.call("new").args_json(json!({})).transact().await?)?;
        let rhea = install_mainnet(&worker, "v2.ref-finance.near").await?;
        let rhea_owner = sub(&root, "rheaowner", 5_000 * NEAR).await?;
        ok(rhea
            .call("new")
            .args_json(json!({"owner_id": rhea_owner.id(), "boost_farm_id": rhea_owner.id(), "burrowland_id": rhea_owner.id(), "exchange_fee": 4, "referral_fee": 1}))
            .transact()
            .await?)?;
        let meme_acc = sub(&root, "meme", 50 * NEAR).await?;
        let meme = meme_acc.deploy(&out("mock_ft")).await?.into_result()?;
        ok(meme.call("new").transact().await?)?;

        // Rhea pool wNEAR/MEME with liquidity 1000 NEAR : 1_000_000 MEME (1e18 decimals).
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
        let pid = rhea_owner
            .call(rhea.id(), "add_simple_pool")
            .args_json(json!({"tokens": [wrap.id(), meme.id()], "fee": 25}))
            .deposit(NearToken::from_millinear(100))
            .transact()
            .await?;
        let pool_id: u64 = okr(pid)?.json()?;
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
            .args_json(
                json!({"pool_id": pool_id, "amounts": [(1000 * NEAR).to_string(), meme_liq.to_string()]}),
            )
            .deposit(NearToken::from_millinear(10))
            .gas(Gas::from_tgas(100))
            .transact()
            .await?)?;

        // Global code + factory.
        let deployer =
            sub(&root, "gdeploy", 100 * NEAR).await?.deploy(&out("global_deployer")).await?.into_result()?;
        let code = account_wasm.unwrap_or_else(|| out("trading_account"));
        ok(deployer.call("deploy").args_borsh(code.clone()).gas(Gas::from_tgas(300)).transact().await?)?;
        let code_hash = code_hash(&code);
        let fees = sub(&root, "fees", NEAR).await?;
        let admin = sub(&root, "admin", 10 * NEAR).await?;
        // Real Rhea DCL code (mainnet dclv2.ref-labs.near v2.3.13) at dcl.<root>.
        let dcl_c =
            install_code(&worker, &format!("dcl.{}", root.id()), &mainnet_code("dclv2.ref-labs.near").await?)
                .await?;
        ok(dcl_c
            .call("new")
            .args_json(json!({"owner_id": rhea_owner.id(), "wnear_id": wrap.id(), "farming_contract_id": rhea_owner.id()}))
            .transact()
            .await?)?;
        let dcl = dcl_c.as_account().clone();
        let plach = sub(&root, "plach", NEAR).await?;
        let factory_code = factory_wasm.unwrap_or_else(|| out("factory"));
        let dexes: Vec<Value> = [
            vec![
                json!({"id": rhea.id(), "kind": "RheaClassic"}),
                json!({"id": dcl.id(), "kind": "RheaDcl"}),
                json!({"id": plach.id(), "kind": "Plach"}),
            ],
            extra_dexes,
        ]
        .concat();
        let factory = sub(&root, "tt", 50 * NEAR).await?.deploy(&factory_code).await?.into_result()?;
        ok(factory
            .call("new")
            .args_json(json!({
                "admin": admin.id(),
                "code_hash": code_hash,
                "fee_config": {"fee_bps": FEE_BPS, "fee_recipient": fees.id()},
                "dex_allowlist": dexes,
                "wrap": wrap.id(),
            }))
            .transact()
            .await?)?;
        Ok(Self {
            worker,
            root,
            wrap,
            rhea,
            meme,
            factory,
            deployer,
            fees,
            admin,
            dcl,
            plach,
            code_hash,
            pool_id,
        })
    }

    /// DCL pool wNEAR/MEME (fee 2000) with liquidity around point 0; returns the pool id.
    pub async fn dcl_pool(&self) -> Result<String> {
        let lp = sub(&self.root, "dcllp", 200 * NEAR).await?;
        let dcl = self.dcl.id();
        ok(self.meme.call("mint").args_json(json!({"account_id": dcl, "amount": "0"})).transact().await?)?;
        ok(lp
            .call(self.wrap.id(), "storage_deposit")
            .args_json(json!({"account_id": dcl}))
            .deposit(NearToken::from_yoctonear(STORAGE))
            .transact()
            .await?)?;
        let r = lp
            .call(dcl, "create_pool")
            .args_json(
                json!({"token_a": self.wrap.id(), "token_b": self.meme.id(), "fee": 2000, "init_point": 0}),
            )
            .deposit(NearToken::from_near(1))
            .gas(Gas::from_tgas(100))
            .transact()
            .await?;
        let pid: String = okr(r)?.json()?;
        ok(lp
            .call(dcl, "storage_deposit")
            .args_json(json!({}))
            .deposit(NearToken::from_near(1))
            .gas(Gas::from_tgas(100))
            .transact()
            .await?)?;
        ok(lp
            .call(self.wrap.id(), "storage_deposit")
            .args_json(json!({}))
            .deposit(NearToken::from_yoctonear(STORAGE))
            .transact()
            .await?)?;
        ok(lp
            .call(self.wrap.id(), "near_deposit")
            .args_json(json!({}))
            .deposit(NearToken::from_near(100))
            .transact()
            .await?)?;
        ok(self
            .meme
            .call("mint")
            .args_json(json!({"account_id": lp.id(), "amount": (100 * NEAR).to_string()}))
            .transact()
            .await?)?;
        for t in [self.wrap.id(), self.meme.id()] {
            ok(lp
                .call(t, "ft_transfer_call")
                .args_json(
                    json!({"receiver_id": dcl, "amount": (100 * NEAR).to_string(), "msg": "\"Deposit\""}),
                )
                .deposit(NearToken::from_yoctonear(1))
                .gas(Gas::from_tgas(100))
                .transact()
                .await?)?;
        }
        ok(lp.call(dcl, "add_liquidity").args_json(json!({"pool_id": pid, "left_point": -8000, "right_point": 8000,
            "amount_x": (90 * NEAR).to_string(), "amount_y": (90 * NEAR).to_string(), "min_amount_x": "0", "min_amount_y": "0"}))
            .gas(Gas::from_tgas(200)).transact().await?)?;
        Ok(pid)
    }

    pub fn dcl_buy_ops(&self, pid: &str, amount: u128, min_out: u128, register_out: bool) -> Value {
        let mut ops = vec![];
        if register_out {
            ops.push(json!({"StorageDeposit": {"token": self.meme.id(), "amount": STORAGE.to_string()}}));
        }
        ops.push(json!({"NearDeposit": {"amount": amount.to_string()}}));
        let msg = json!({"Swap": {"pool_ids": [pid], "output_token": self.meme.id(), "min_output_amount": min_out.to_string(), "skip_unwrap_near": true}}).to_string();
        ops.push(json!({"FtTransferCall": {"token": self.wrap.id(), "receiver_id": self.dcl.id(), "amount": amount.to_string(), "msg": msg, "gas": (100 * TGAS).to_string()}}));
        Value::Array(ops)
    }

    pub async fn dcl_storage(&self, id: &AccountId) -> Result<Value> {
        Ok(self
            .worker
            .view(self.dcl.id(), "storage_balance_of")
            .args_json(json!({"account_id": id}))
            .await?
            .json()?)
    }

    pub async fn account_for(&self, owner: &AccountId) -> Result<AccountId> {
        Ok(self.factory.view("account_for").args_json(json!({"owner": owner})).await?.json()?)
    }

    /// Owner wallet + trading account created through the factory with a fresh device key.
    pub async fn user(&self, name: &str, fund: u128, caps: (u128, u128)) -> Result<User> {
        let owner = sub(&self.root, name, fund + 20 * NEAR).await?;
        let device_sk = SecretKey::from_random(KeyType::ED25519);
        let r = owner
            .call(self.factory.id(), "create_account")
            .args_json(json!({"device_public_key": device_sk.public_key(), "caps": caps_json(caps)}))
            .deposit(NearToken::from_yoctonear(fund))
            .gas(Gas::from_tgas(100))
            .transact()
            .await?;
        ok(r)?;
        // v1.1: `init` registers the account on wNEAR itself; no separate step.
        let account = self.account_for(owner.id()).await?;
        let device = Account::from_secret_key(account.clone(), device_sk.clone(), &self.worker);
        Ok(User { owner, account, device, device_sk })
    }

    pub async fn near_balance(&self, id: &AccountId) -> Result<u128> {
        Ok(self.worker.view_account(id).await?.balance.as_yoctonear())
    }

    pub async fn ft_balance(&self, token: &AccountId, id: &AccountId) -> Result<u128> {
        let v: String =
            self.worker.view(token, "ft_balance_of").args_json(json!({"account_id": id})).await?.json()?;
        Ok(v.parse()?)
    }

    pub async fn now_ns(&self) -> Result<u64> {
        Ok(self.worker.view_block().await?.timestamp())
    }

    pub async fn day_spent(&self, u: &User) -> Result<u128> {
        let v: Value = self.worker.view(&u.account, "get_day").await?.json()?;
        Ok(v["spent_yocto"].as_str().unwrap().parse()?)
    }

    pub async fn config(&self, id: &AccountId) -> Result<Value> {
        Ok(self.worker.view(id, "get_config").await?.json()?)
    }

    /// Raw RPC access-key list (near-workspaces cannot decode gas keys).
    pub async fn access_keys(&self, id: &AccountId) -> Result<Vec<Value>> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": "query",
            "params": {"request_type": "view_access_key_list", "finality": "optimistic", "account_id": id}});
        let v: Value =
            reqwest::Client::new().post(self.worker.rpc_addr()).json(&body).send().await?.json().await?;
        v["result"]["keys"].as_array().cloned().ok_or_else(|| anyhow!("bad rpc: {v}"))
    }

    pub async fn tx_status(&self, hash: &str, sender: &AccountId) -> Result<Value> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": "EXPERIMENTAL_tx_status",
            "params": {"tx_hash": hash, "sender_account_id": sender, "wait_until": "FINAL"}});
        let v: Value =
            reqwest::Client::new().post(self.worker.rpc_addr()).json(&body).send().await?.json().await?;
        v.get("result").cloned().ok_or_else(|| anyhow!("bad rpc: {v}"))
    }

    pub async fn global_hash(&self, id: &AccountId) -> Result<Option<String>> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": "query",
            "params": {"request_type": "view_account", "finality": "optimistic", "account_id": id}});
        let v: Value =
            reqwest::Client::new().post(self.worker.rpc_addr()).json(&body).send().await?.json().await?;
        Ok(v["result"]["global_contract_hash"].as_str().map(String::from))
    }

    /// Deploys extra global code (e.g. the upgrade-test build); returns its hash.
    pub async fn deploy_global(&self, code: Vec<u8>) -> Result<String> {
        ok(self
            .deployer
            .call("deploy")
            .args_borsh(code.clone())
            .gas(Gas::from_tgas(300))
            .transact()
            .await?)?;
        Ok(code_hash(&code))
    }

    pub async fn expected_out(
        &self,
        token_in: &AccountId,
        amount: u128,
        token_out: &AccountId,
    ) -> Result<u128> {
        let v: String = self
            .rhea
            .view("get_return")
            .args_json(json!({"pool_id": self.pool_id, "token_in": token_in, "amount_in": amount.to_string(), "token_out": token_out}))
            .await?
            .json()?;
        Ok(v.parse()?)
    }

    pub fn rhea_msg(
        &self,
        token_in: &AccountId,
        token_out: &AccountId,
        amount: u128,
        min_out: u128,
        unwrap: bool,
    ) -> String {
        json!({"force": 0, "actions": [{"pool_id": self.pool_id, "token_in": token_in, "token_out": token_out,
            "amount_in": amount.to_string(), "amount_out": "0", "min_amount_out": min_out.to_string()}],
            "skip_unwrap_near": !unwrap})
        .to_string()
    }

    /// Router-shaped buy: storage for output token + wrap + ft_transfer_call.
    pub fn buy_ops(&self, amount: u128, min_out: u128, with_storage: bool) -> Value {
        let mut ops = vec![];
        if with_storage {
            ops.push(json!({"StorageDeposit": {"token": self.meme.id(), "amount": STORAGE.to_string()}}));
        }
        ops.push(json!({"NearDeposit": {"amount": amount.to_string()}}));
        ops.push(json!({"FtTransferCall": {"token": self.wrap.id(), "receiver_id": self.rhea.id(), "amount": amount.to_string(),
            "msg": self.rhea_msg(self.wrap.id(), self.meme.id(), amount, min_out, false), "gas": (150 * TGAS).to_string()}}));
        Value::Array(ops)
    }

    pub fn sell_ops(&self, amount: u128, min_out: u128, unwrap: bool) -> Value {
        json!([{"FtTransferCall": {"token": self.meme.id(), "receiver_id": self.rhea.id(), "amount": amount.to_string(),
            "msg": self.rhea_msg(self.meme.id(), self.wrap.id(), amount, min_out, unwrap), "gas": (150 * TGAS).to_string()}}])
    }

    /// `execute` signed by `signer` (normally the device key) with a fresh 60s expiry.
    pub async fn exec(
        &self,
        signer: &Account,
        account: &AccountId,
        ops: Value,
        id: &str,
        max_in: u128,
    ) -> Result<ExecutionFinalResult> {
        let exp = self.now_ns().await? + 60_000_000_000;
        self.exec_at(signer, account, ops, id, max_in, exp).await
    }

    pub async fn exec_at(
        &self,
        signer: &Account,
        account: &AccountId,
        ops: Value,
        id: &str,
        max_in: u128,
        expires_at_ns: u64,
    ) -> Result<ExecutionFinalResult> {
        Ok(signer
            .call(account, "execute")
            .args_json(json!({"ops": ops, "client_order_id": id, "expires_at_ns": expires_at_ns.to_string(), "max_in_yocto": max_in.to_string()}))
            .gas(Gas::from_tgas(300))
            .transact()
            .await?)
    }
}

/// Mainnet code for `id`, fetched once from RPC and cached under tests/.cache/.
pub async fn mainnet_code(id: &str) -> Result<Vec<u8>> {
    let dir = format!("{}/.cache", env!("CARGO_MANIFEST_DIR"));
    let path = format!("{dir}/{id}.wasm");
    if let Ok(b) = std::fs::read(&path) {
        return Ok(b);
    }
    std::fs::create_dir_all(&dir)?;
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "query",
        "params": {"request_type": "view_code", "finality": "final", "account_id": id}});
    let mut last = String::new();
    for attempt in 0..8u64 {
        let r = reqwest::Client::new().post("https://free.rpc.fastnear.com").json(&body).send().await;
        if let Ok(r) = r {
            let v: Value = r.json().await.unwrap_or_default();
            if let Some(b64) = v["result"]["code_base64"].as_str() {
                use base64::Engine;
                let code = base64::engine::general_purpose::STANDARD.decode(b64)?;
                let tmp = format!("{path}.{}", std::process::id());
                std::fs::write(&tmp, &code)?;
                std::fs::rename(&tmp, &path)?;
                return Ok(code);
            }
            last = v.to_string();
        }
        tokio::time::sleep(std::time::Duration::from_millis(500 * (attempt + 1))).await;
    }
    Err(anyhow!("could not fetch {id} code: {last}"))
}

/// Installs mainnet code at the same account id in the sandbox (state patch, no data).
pub async fn install_mainnet(worker: &Worker<Sandbox>, id: &str) -> Result<Contract> {
    install_code(worker, id, &mainnet_code(id).await?).await
}

/// Installs `code` at `id` (created if missing) with a big balance and a fresh full-access key.
pub async fn install_code(worker: &Worker<Sandbox>, id: &str, code: &[u8]) -> Result<Contract> {
    let aid: AccountId = id.parse()?;
    let mut acct =
        near_workspaces::types::AccountDetailsPatch::default().balance(NearToken::from_near(100_000));
    acct.storage_usage = Some(code.len() as u64 + 1_000);
    worker.patch(&aid).account(acct).code(code).transact().await?;
    let sk = SecretKey::from_random(KeyType::ED25519);
    worker
        .patch(&aid)
        .access_key(sk.public_key(), near_workspaces::AccessKey::full_access())
        .transact()
        .await?;
    Ok(Contract::from_secret_key(aid, sk, worker))
}

pub fn caps_json((t, d): (u128, u128)) -> Value {
    json!({"max_trade_yocto": t.to_string(), "daily_cap_yocto": d.to_string()})
}

pub fn fee(x: u128) -> u128 {
    x / 10_000 * FEE_BPS + x % 10_000 * FEE_BPS / 10_000
}

pub fn pk_str(pk: &PublicKey) -> String {
    serde_json::to_value(pk).unwrap().as_str().unwrap().to_string()
}

// ---------------- v1.5 Shards (real token wasm) ----------------

/// Shards token templates: (cache name, mainnet token that runs it, has `activate`, v2.5).
pub const SHARDS_TEMPLATES: [(&str, &str, bool, bool); 4] = [
    ("v0_1_0", "l000001.factory.shardsmarket.near", false, false), // BqWmwKZ5…
    ("v0_2_0", "l000101.factory.shardsmarket.near", true, false),  // 2nD3b7Y9…
    ("v0_2_0_6uqY", "l000230.factory.shardsmarket.near", true, true), // 6uqYcTCa… (v2.5)
    ("v0_2_0_EzdS", "l000233.factory.shardsmarket.near", true, true), // EzdS4z28… (v2.5, current)
];

/// Real Shards token code (`tests/.cache/shards_token_<t>.wasm`, fetched from mainnet if missing).
pub async fn shards_wasm(t: &str) -> Result<Vec<u8>> {
    let path = format!("{}/.cache/shards_token_{t}.wasm", env!("CARGO_MANIFEST_DIR"));
    if let Ok(b) = std::fs::read(&path) {
        return Ok(b);
    }
    let src = SHARDS_TEMPLATES.iter().find(|x| x.0 == t).ok_or_else(|| anyhow!("unknown template {t}"))?.1;
    let code = mainnet_code(src).await?;
    std::fs::write(&path, &code)?;
    Ok(code)
}

/// `factory.shardsmarket.near` (no code, full-access key): the only account that may `new` a
/// Shards token, as on mainnet.
pub async fn shards_factory(worker: &Worker<Sandbox>) -> Result<Account> {
    let aid: AccountId = SHARDS_FACTORY.parse()?;
    let sk = SecretKey::from_random(KeyType::ED25519);
    worker
        .patch(&aid)
        .account(near_workspaces::types::AccountDetailsPatch::default().balance(NearToken::from_near(10_000)))
        .access_key(sk.public_key(), near_workspaces::AccessKey::full_access())
        .transact()
        .await?;
    // v2.5 terms name a burner; create it so payouts to it can land.
    let bid: AccountId = "burn.shardsmarket.near".parse()?;
    worker
        .patch(&bid)
        .account(near_workspaces::types::AccountDetailsPatch::default().balance(NearToken::from_near(1)))
        .transact()
        .await?;
    Ok(Account::from_secret_key(aid, sk, worker))
}

/// A NEAR-paired Shards token `id` (any id: the suffix rule is the trading account's business)
/// running template `t`, initialised by `factory` as mainnet's `create_launch` does
/// (`new{config, factory_id, request_id, terms?, venue?, upgrade_deadline_ns?}`, wrap registration,
/// `activate`). `taxes` = (buy_tax_bps, sell_tax_bps).
pub async fn shards_token(
    env: &Env,
    factory: &Account,
    id: &str,
    t: &str,
    taxes: (u16, u16),
) -> Result<Contract> {
    shards_token_on(&env.worker, env.wrap.id(), env.root.id(), factory, id, t, taxes).await
}

/// `shards_token` without an `Env` (wrap = `wrap`, creator/fee recipient = `creator`).
pub async fn shards_token_on(
    worker: &Worker<Sandbox>,
    wrap: &AccountId,
    creator: &AccountId,
    factory: &Account,
    id: &str,
    t: &str,
    taxes: (u16, u16),
) -> Result<Contract> {
    let (_, _, activate, v25) =
        *SHARDS_TEMPLATES.iter().find(|x| x.0 == t).ok_or_else(|| anyhow!("unknown template {t}"))?;
    let token = install_code(worker, id, &shards_wasm(t).await?).await?;
    let config = json!({"schema_version": 2, "market_model": "VIRTUAL_CURVE_TO_LOCAL_AMM",
        "quote_asset_id": wrap, "token_decimals": 18,
        "initial_supply": "1000000000000000000000000000", "sale_inventory": "750000000000000000000000000",
        "amm_inventory": "250000000000000000000000000", "virtual_token_reserve": "1125000000000000000000000000",
        "virtual_quote_reserve": "1000000000000000000000000000", "buy_tax_bps": taxes.0, "sell_tax_bps": taxes.1,
        "platform_share_of_tax_bps": 2000,
        "allocation": {"creator_bps": 10000, "buyback_burn_bps": 0, "dividends_bps": 0, "liquidity_bps": 0},
        "curve_lp_fee_bps": 0, "amm_lp_fee_bps": 100, "lp_fee_accounting": "SEGREGATED",
        "payout_asset_policy": "SAME_AS_QUOTE", "opening_surcharge": {"enabled": false},
        "cto_policy": "PLATFORM_ASSISTED_FUTURE_FEES",
        "core_upgrade_policy": if v25 { "OWNER_UPGRADEABLE_UNTIL_DEADLINE" } else { "IMMUTABLE_AFTER_ACTIVATION" },
        "creator_id": creator, "fee_recipient_id": creator, "public_lp_enabled": false,
        "metadata": {"name": "Sandbox", "symbol": "SBX", "image_ref": "ipfs://bafybeic54ldquk22pdjq6lq6mj7ipegalti3gv7ymlhhren3rbtk5rots4", "image_hash":
            "51c74f69a6f0455f4091f2c62042bd00bee139915101431a1fd4adf0a7be4138", "description": null,
            "website": null, "twitter": null, "telegram": null}});
    let mut args = json!({"config": config, "factory_id": factory.id(), "request_id": format!("req-{id}")});
    if t != "v0_1_0" {
        args["terms"] = json!({"quote_asset_id": wrap, "quote_decimals": 24, "quote_kind": "wrapped_near",
            "quote_unit": NEAR.to_string(), "min_buy": "1", "burner_id": "burn.shardsmarket.near"});
    }
    if v25 {
        args["venue"] = json!({"intents_id": "intents.near", "refused_venues": [], "pool": null});
        let deadline = worker.view_block().await?.timestamp() + 6 * 86_400 * 1_000_000_000;
        args["upgrade_deadline_ns"] = json!(deadline.to_string());
    }
    ok(factory.call(token.id(), "new").args_json(args).gas(Gas::from_tgas(100)).transact().await?)?;
    ok(factory
        .call(wrap, "storage_deposit")
        .args_json(json!({"account_id": token.id(), "registration_only": true}))
        .deposit(NearToken::from_yoctonear(STORAGE))
        .transact()
        .await?)?;
    if activate {
        ok(factory
            .call(token.id(), "activate")
            .args_json(json!({}))
            .gas(Gas::from_tgas(30))
            .transact()
            .await?)?;
    }
    Ok(token)
}

/// The msg the trading account builds for a Shards buy (`BuyMessage`, 6 fields).
pub fn shards_buy_msg(order_id: &str, min_out: u128, deadline_ns: u64) -> String {
    json!({"v": 1, "action": "buy", "order_id": order_id, "min_amount_out": min_out.to_string(),
        "max_total_fee_bps": 1100, "deadline_ns": deadline_ns.to_string()})
    .to_string()
}

/// Gas burnt per receipt of `r` as `(executor, TGas)` (gas measurements).
pub fn gas_by_receipt(r: &ExecutionFinalResult) -> Vec<(String, f64)> {
    r.receipt_outcomes()
        .iter()
        .map(|o| (o.executor_id.to_string(), o.gas_burnt.as_gas() as f64 / 1e12))
        .collect()
}
