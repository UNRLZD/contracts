//! Shared sandbox harness for the v1.6 venue suites (venues_*.rs). The trading account is
//! deployed DIRECTLY (not through the factory: factory 1.3.0's DexKind gains the venue kinds in
//! A2's work) with `init` called by a deployer, and a device function-call key patched in
//! (DEVICE_METHODS, like the factory adds). Pads run their REAL mainnet wasm (`mainnet_code`,
//! cached in tests/.cache and pinned by hash in each suite).
//!
//! Account wasm: $NT_VENUES_WASM, else contracts/out-v/trading_account.wasm (V's worktree build),
//! else contracts/out/trading_account.wasm.
#![allow(dead_code)]
use anyhow::Result;
use integration_tests::*;
use near_workspaces::network::Sandbox;
use near_workspaces::result::ExecutionFinalResult;
use near_workspaces::types::{Gas, KeyType, NearToken, SecretKey};
use near_workspaces::{Account, AccountId, Contract, Worker};
use serde_json::{json, Value};

pub const DEVICE_METHODS: [&str; 10] = [
    "execute",
    "withdraw_to_owner",
    "lower_caps",
    "place_order",
    "cancel_order",
    "revoke_automation",
    "withdraw_cross_chain",
    "remove_withdraw_destination",
    "withdraw_from_intents",
    "execute_order",
];

pub fn account_wasm() -> Vec<u8> {
    if let Ok(p) = std::env::var("NT_VENUES_WASM") {
        return std::fs::read(p).expect("NT_VENUES_WASM");
    }
    let dir = env!("CARGO_MANIFEST_DIR");
    std::fs::read(format!("{dir}/../out-v/trading_account.wasm")).unwrap_or_else(|_| out("trading_account"))
}

pub struct VEnv {
    pub worker: Worker<Sandbox>,
    pub root: Account,
    pub wrap: Contract,
    pub fees: Account,
}

pub struct Ta {
    pub owner: Account,
    pub id: AccountId,
    pub device: Account,
}

/// Sandbox with the real wrap.near.
pub async fn venv() -> Result<VEnv> {
    let worker = near_workspaces::sandbox().await?;
    let root = worker.root_account()?;
    let wrap = install_mainnet(&worker, "wrap.near").await?;
    ok(wrap.call("new").args_json(json!({})).transact().await?)?;
    let fees = sub(&root, "fees", 5 * NEAR).await?;
    Ok(VEnv { worker, root, wrap, fees })
}

impl VEnv {
    /// A trading account `<name>.<root>` with `fund` NEAR, caps (max_trade, daily), fee 100 bps to
    /// `fees`, allowlist `dexes` (JSON `Dex` entries), registered on wrap by `init`.
    pub async fn ta(&self, name: &str, fund: u128, caps: (u128, u128), dexes: Vec<Value>) -> Result<Ta> {
        let owner = sub(&self.root, &format!("{name}-owner"), 20 * NEAR).await?;
        let acc = self
            .root
            .create_subaccount(name)
            .initial_balance(NearToken::from_yoctonear(fund + 10 * NEAR))
            .transact()
            .await?
            .into_result()?;
        let c = acc.deploy(&account_wasm()).await?.into_result()?;
        ok(c.call("init")
            .args_json(
                json!({"owner": owner.id(), "fee_config": {"fee_bps": 100, "fee_recipient": self.fees.id()},
                "caps": caps_json(caps), "dex_allowlist": dexes, "wrap": self.wrap.id()}),
            )
            .gas(Gas::from_tgas(100))
            .transact()
            .await?)?;
        let sk = SecretKey::from_random(KeyType::ED25519);
        self.worker
            .patch(c.id())
            .access_key(
                sk.public_key(),
                near_workspaces::AccessKey::function_call_access(c.id(), &DEVICE_METHODS, None),
            )
            .transact()
            .await?;
        let device = Account::from_secret_key(c.id().clone(), sk, &self.worker);
        Ok(Ta { owner, id: c.id().clone(), device })
    }

    pub async fn exec(&self, t: &Ta, ops: Value, id: &str, max_in: u128) -> Result<ExecutionFinalResult> {
        let exp = self.worker.view_block().await?.timestamp() + 60_000_000_000;
        Ok(t.device
            .call(&t.id, "execute")
            .args_json(json!({"ops": ops, "client_order_id": id, "expires_at_ns": exp.to_string(),
                "max_in_yocto": max_in.to_string()}))
            .gas(Gas::from_tgas(300))
            .transact()
            .await?)
    }

    pub async fn near(&self, id: &AccountId) -> Result<u128> {
        Ok(self.worker.view_account(id).await?.balance.as_yoctonear())
    }

    pub async fn ft(&self, token: &AccountId, id: &AccountId) -> Result<u128> {
        let v: String =
            self.worker.view(token, "ft_balance_of").args_json(json!({"account_id": id})).await?.json()?;
        Ok(v.parse()?)
    }

    pub async fn day_spent(&self, t: &Ta) -> Result<u128> {
        let v: Value = self.worker.view(&t.id, "get_day").await?.json()?;
        Ok(v["spent_yocto"].as_str().unwrap_or("0").parse()?)
    }

    /// wNEAR for `t`: near_deposit from the account itself (via execute NearDeposit is also fine).
    pub async fn wrap_for(&self, t: &Ta, amount: u128) -> Result<()> {
        let r = self
            .exec(t, json!([{"NearDeposit": {"amount": amount.to_string()}}]), &format!("w{amount}"), amount)
            .await?;
        ok(r)
    }

    /// Settlement event data of the last `settled` log in `r` (used, fee, spend_returned).
    pub fn settled(r: &ExecutionFinalResult) -> Option<Value> {
        r.logs()
            .iter()
            .rev()
            .find_map(|l| l.strip_prefix("EVENT_JSON:").filter(|s| s.contains("\"settled\"")))
            .and_then(|s| serde_json::from_str::<Value>(s).ok())
            .map(|v| v["data"].clone())
    }
}

/// Real mainnet code of `id`, asserting its sha256 (bs58) equals `hash` when given (pin).
pub async fn pinned(id: &str, hash: Option<&str>) -> Result<Vec<u8>> {
    let code = mainnet_code(id).await?;
    if let Some(h) = hash {
        assert_eq!(code_hash(&code), h, "mainnet code of {id} changed: re-verify the interface");
    }
    Ok(code)
}

// ---------------- mainnet state import (V-FACTORY) ----------------

async fn rpc(body: Value) -> Result<Value> {
    let mut last = String::new();
    for attempt in 0..6u64 {
        match reqwest::Client::new().post("https://free.rpc.fastnear.com").json(&body).send().await {
            Ok(r) => {
                let v: Value = r.json().await.unwrap_or_default();
                if v.get("result").is_some() {
                    return Ok(v);
                }
                last = v.to_string();
                if last.contains("TOO_LARGE") || last.contains("UNKNOWN_ACCOUNT") {
                    break;
                }
            }
            Err(e) => last = e.to_string(),
        }
        tokio::time::sleep(std::time::Duration::from_millis(700 * (attempt + 1))).await;
    }
    Err(anyhow::anyhow!("rpc {body}: {last}"))
}

/// Mainnet contract state of `id` (all keys; fails on TOO_LARGE_CONTRACT_STATE), cached as
/// tests/.cache/state_<id>.json (first fetch pins it; delete the file to refresh).
pub async fn mainnet_state(id: &str) -> Result<(Vec<(Vec<u8>, Vec<u8>)>, u64)> {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;
    let dir = format!("{}/.cache", env!("CARGO_MANIFEST_DIR"));
    let path = format!("{dir}/state_{id}.json");
    let v: Value = if let Ok(s) = std::fs::read_to_string(&path) {
        serde_json::from_str(&s)?
    } else {
        std::fs::create_dir_all(&dir)?;
        let st = rpc(
            json!({"jsonrpc": "2.0", "id": 1, "method": "query", "params": {"request_type": "view_state",
            "finality": "final", "account_id": id, "prefix_base64": ""}}),
        )
        .await?;
        let acc = rpc(
            json!({"jsonrpc": "2.0", "id": 1, "method": "query", "params": {"request_type": "view_account",
            "finality": "final", "account_id": id}}),
        )
        .await?;
        let v = json!({"values": st["result"]["values"], "storage_usage": acc["result"]["storage_usage"]});
        std::fs::write(&path, v.to_string())?;
        v
    };
    let mut out = vec![];
    for kv in v["values"].as_array().cloned().unwrap_or_default() {
        out.push((
            b64.decode(kv["key"].as_str().unwrap_or(""))?,
            b64.decode(kv["value"].as_str().unwrap_or(""))?,
        ));
    }
    Ok((out, v["storage_usage"].as_u64().unwrap_or(0)))
}

/// Installs `id` with its mainnet code (pinned by `hash`) AND its mainnet state, a big balance and a
/// fresh full-access key (so the test can act as the pad's own account, e.g. to wrap NEAR it held
/// as wNEAR on mainnet).
pub async fn import_mainnet(worker: &Worker<Sandbox>, id: &str, hash: Option<&str>) -> Result<Contract> {
    let code = pinned(id, hash).await?;
    let (state, usage) = mainnet_state(id).await?;
    let aid: AccountId = id.parse()?;
    let mut acct =
        near_workspaces::types::AccountDetailsPatch::default().balance(NearToken::from_near(100_000));
    acct.storage_usage = Some(usage + code.len() as u64 + 10_000);
    worker.patch(&aid).account(acct).code(&code).transact().await?;
    for chunk in state.chunks(200) {
        worker.patch(&aid).states(chunk.iter().map(|(k, v)| (k.as_slice(), v.as_slice()))).transact().await?;
    }
    let sk = SecretKey::from_random(KeyType::ED25519);
    worker
        .patch(&aid)
        .access_key(sk.public_key(), near_workspaces::AccessKey::full_access())
        .transact()
        .await?;
    Ok(Contract::from_secret_key(aid, sk, worker))
}

/// Gives `holder` (an imported pad) `amount` wNEAR on the sandbox wrap (its mainnet wNEAR balance
/// is not imported).
pub async fn fund_wnear(e: &VEnv, holder: &Contract, amount: u128) -> Result<()> {
    ok(holder
        .as_account()
        .call(e.wrap.id(), "storage_deposit")
        .args_json(json!({"account_id": holder.id(), "registration_only": true}))
        .deposit(NearToken::from_yoctonear(STORAGE))
        .transact()
        .await?)?;
    ok(holder
        .as_account()
        .call(e.wrap.id(), "near_deposit")
        .args_json(json!({}))
        .deposit(NearToken::from_yoctonear(amount))
        .transact()
        .await?)
}

pub fn fee_of(x: u128) -> u128 {
    x / 10_000 * 100 + x % 10_000 * 100 / 10_000
}
