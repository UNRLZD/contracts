//! v1.4.9 on the real runtime (UNR-A-08): a NEP-366 Delegate action signed by one of the
//! account's keys and submitted by another account runs with predecessor == self but with the
//! OUTER signer's id and key. v1.4.8 read a delegated automation-key fire as a device fire
//! (skipping the opt-in weekly allowance, E_RELAYER_SELL_ONLY and the key's gas allowance).
//! v1.4.9 requires signer == self on every key path, so every delegated call is refused.
//! Built from the auditors' fr_h2_delegate.rs (real SignedDelegateAction, sent with send_tx).
//! RED on v1.4.8: NT_ACCOUNT_WASM=../out/trading_account_v1_4_8.wasm cargo test --test v149
use base64::Engine;
use integration_tests::*;
use near_primitives::action::delegate::{DelegateAction, NonDelegateAction, SignedDelegateAction};
use near_primitives::action::{Action, FunctionCallAction};
use near_primitives::transaction::{SignedTransaction, Transaction, TransactionV0};
use near_workspaces::types::{Gas, KeyType, NearToken, SecretKey};
use near_workspaces::{Account, AccountId};
use serde_json::{json, Value};

async fn rpc(env: &Env, method: &str, params: Value) -> anyhow::Result<Value> {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    let r: Value =
        reqwest::Client::new().post(env.worker.rpc_addr()).json(&body).send().await?.json().await?;
    if let Some(e) = r.get("error") {
        anyhow::bail!("{method}: {e}");
    }
    Ok(r["result"].clone())
}

async fn key_view(env: &Env, acc: &str, pk: &str) -> anyhow::Result<Value> {
    rpc(
        env,
        "query",
        json!({"request_type": "view_access_key", "finality": "optimistic", "account_id": acc, "public_key": pk}),
    )
    .await
}

/// Outcome of a delegated call: every receipt's logs and failures.
struct Delegated {
    logs: Vec<String>,
    failures: Vec<String>,
}

impl Delegated {
    fn refused_with(&self, code: &str) -> bool {
        self.failures.iter().any(|f| f.contains(&format!("Smart contract panicked: {code}")))
    }
    fn logged(&self, s: &str) -> bool {
        self.logs.iter().any(|l| l.contains(s))
    }
}

/// `method(args)` on `ta`, authorised by `key` (one of `ta`'s access keys) inside a NEP-366
/// Delegate action, in a transaction signed and paid by `outer` with its own key.
async fn delegate(
    env: &Env,
    ta: &AccountId,
    key: &SecretKey,
    outer: &Account,
    method: &str,
    args: Value,
) -> anyhow::Result<Delegated> {
    let ta_p: near_primitives::types::AccountId = ta.as_str().parse()?;
    let sk: near_crypto::SecretKey = key.to_string().parse()?;
    let nonce = key_view(env, ta.as_str(), &sk.public_key().to_string()).await?["nonce"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("no access key"))?;
    let head = rpc(env, "block", json!({"finality": "final"})).await?;
    let height = head["header"]["height"].as_u64().unwrap();
    let block_hash: near_primitives::hash::CryptoHash =
        head["header"]["hash"].as_str().unwrap().parse().unwrap();
    let inner = Action::FunctionCall(Box::new(FunctionCallAction {
        method_name: method.into(),
        args: serde_json::to_vec(&args)?,
        gas: near_primitives::gas::Gas::from_gas(250 * TGAS),
        deposit: NearToken::from_yoctonear(0),
    }));
    let da = DelegateAction {
        sender_id: ta_p.clone(),
        receiver_id: ta_p.clone(),
        actions: vec![NonDelegateAction::try_from(inner).map_err(|_| anyhow::anyhow!("nested delegate"))?],
        nonce: nonce + 1,
        max_block_height: height + 100,
        public_key: sk.public_key(),
    };
    let sda = SignedDelegateAction::sign(&near_crypto::InMemorySigner::from_secret_key(ta_p.clone(), sk), da);
    let out_sk: near_crypto::SecretKey = outer.secret_key().to_string().parse()?;
    let out_id: near_primitives::types::AccountId = outer.id().as_str().parse()?;
    let out_nonce = key_view(env, outer.id().as_str(), &out_sk.public_key().to_string()).await?["nonce"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("no outer key"))?;
    let tx = Transaction::V0(TransactionV0 {
        signer_id: out_id.clone(),
        public_key: out_sk.public_key(),
        nonce: out_nonce + 1,
        receiver_id: ta_p,
        block_hash,
        actions: vec![Action::Delegate(Box::new(sda))],
    });
    let (h, _) = tx.get_hash_and_size();
    let stx = SignedTransaction::new(
        near_crypto::InMemorySigner::from_secret_key(out_id, out_sk).sign(h.as_ref()),
        tx,
    );
    let b64 = base64::engine::general_purpose::STANDARD.encode(borsh::to_vec(&stx)?);
    let res = rpc(env, "send_tx", json!({"signed_tx_base64": b64, "wait_until": "FINAL"})).await?;
    // the outer tx is the stranger's: not the account, not the account's key
    assert_eq!(res["transaction"]["signer_id"], outer.id().as_str());
    let (mut logs, mut failures) = (vec![], vec![]);
    if res["status"].get("Failure").is_some() {
        failures.push(res["status"].to_string());
    }
    for ro in res["receipts_outcome"].as_array().unwrap() {
        for l in ro["outcome"]["logs"].as_array().unwrap() {
            logs.push(l.as_str().unwrap().to_string());
        }
        if ro["outcome"]["status"].get("Failure").is_some() {
            failures.push(ro["outcome"]["status"].to_string());
        }
    }
    Ok(Delegated { logs, failures })
}

async fn with_automation(env: &Env, name: &str) -> anyhow::Result<(User, SecretKey, Account)> {
    let u = env.user(name, 12 * NEAR, (u128::MAX, u128::MAX)).await?;
    let ak = SecretKey::from_random(KeyType::ED25519);
    ok(u.owner
        .call(&u.account, "owner_set_automation_key")
        .args_json(json!({"public_key": ak.public_key(), "allowance": NEAR.to_string()}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(50))
        .transact()
        .await?)?;
    let auto = Account::from_secret_key(u.account.clone(), ak.clone(), &env.worker);
    Ok((u, ak, auto))
}

async fn place_buy(env: &Env, u: &User, amount: u128) -> anyhow::Result<String> {
    let exp = env.now_ns().await? + 3_600_000_000_000;
    Ok(okr(u
        .device
        .call(&u.account, "place_order")
        .args_json(json!({"token_in": env.wrap.id(), "token_out": env.meme.id(), "amount_in": amount.to_string(),
            "min_out": "1", "trigger_meta": "{}", "expires_at_ns": exp.to_string(), "dexes": [env.rhea.id()]}))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?)?
    .json()?)
}

async fn order(env: &Env, acc: &AccountId, id: &str) -> anyhow::Result<Value> {
    Ok(env.worker.view(acc, "get_order").args_json(json!({"order_id": id})).await?.json()?)
}

/// The auditors' exploit: the owner opted into a 1 NEAR week, a direct relayer fire of a 2 NEAR
/// buy is refused (E_RELAYER_WEEKLY). The same execute_order in a Delegate signed by the
/// automation key and sent by mallory filled on v1.4.8 (week spent 0, key allowance untouched).
/// v1.4.9: refused, the order stays open, nothing moved.
#[tokio::test]
async fn v149_delegated_relayer_fire_refused() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let (u, ak, auto) = with_automation(&env, "dlgr").await?;
    ok(u.owner
        .call(&u.account, "owner_set_relayer_allowance")
        .args_json(json!({"weekly_yocto": NEAR.to_string()}))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?)?;
    let amount = 2 * NEAR;
    let id = place_buy(&env, &u, amount).await?;
    let args = json!({"order_id": id, "ops": env.buy_ops(amount, 1, true)});
    let r =
        auto.call(&u.account, "execute_order").args_json(&args).gas(Gas::from_tgas(250)).transact().await?;
    fails_with(&r, "E_RELAYER_WEEKLY");

    let mallory = sub(&env.root, "mallory", 5 * NEAR).await?;
    let pk = ak.public_key().to_string();
    let perm0 = key_view(&env, u.account.as_str(), &pk).await?["permission"].clone();
    let wnear0 = env.ft_balance(env.wrap.id(), &u.account).await?;
    let d = delegate(&env, &u.account, &ak, &mallory, "execute_order", args).await?;
    println!("delegated relayer fire: failures {:?}\nlogs {:?}", d.failures, d.logs);
    assert!(!d.logged("order_filled"), "UNR-A-08: a delegated relayer fire filled");
    assert!(d.refused_with("E_NOT_SELF_SIGNED"), "{:?}", d.failures);
    env.worker.fast_forward(2).await?;
    let o = order(&env, &u.account, &id).await?;
    assert_eq!(o["pending"], false, "order stays open: {o}");
    let w: Value = env.worker.view(&u.account, "get_relayer_week").await?.json()?;
    assert_eq!(w["spent_yocto"], "0");
    assert_eq!(env.ft_balance(env.wrap.id(), &u.account).await?, wnear0);
    // the delegate did use the automation key (nonce), not its FC gas allowance
    let perm1 = key_view(&env, u.account.as_str(), &pk).await?["permission"].clone();
    println!("automation key permission before {perm0} after {perm1}");
    // the runtime checks the key's method list on a Delegate: the automation key can't reach a
    // device method or a callback that way either
    for m in ["withdraw_to_owner", "on_swap_settled"] {
        let d = delegate(&env, &u.account, &ak, &mallory, m, json!({})).await?;
        assert!(
            d.failures
                .iter()
                .any(|f| f.contains("DelegateActionAccessKeyError") || f.contains("MethodNameMismatch")),
            "{m}: {:?}",
            d.failures
        );
    }
    // the premise of the fix: no key on the account can be the OUTER signer of a Delegate (all are
    // function-call keys; a Delegate action needs a full-access key), so signer == self never
    // holds for a delegated call
    let err = delegate(&env, &u.account, &ak, &u.device, "execute_order", json!({"order_id": id, "ops": []}))
        .await
        .err()
        .map(|e| e.to_string())
        .expect("a device key signed a Delegate transaction");
    println!("device key as outer signer: {err}");
    assert!(err.contains("RequiresFullAccess"), "{err}");
    Ok(())
}

/// A device key authorising device calls inside a Delegate (a stranger, or any meta-tx relayer,
/// submits it): refused on every path; the runtime's method-list check keeps callbacks out.
#[tokio::test]
async fn v149_delegated_device_calls_refused() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let (u, _ak, _auto) = with_automation(&env, "dlgd").await?;
    let mallory = sub(&env.root, "mallory", 5 * NEAR).await?;
    let id = place_buy(&env, &u, NEAR / 10).await?;
    let exp = env.now_ns().await? + 60_000_000_000;
    let calls = [
        (
            "execute",
            json!({"ops": env.buy_ops(NEAR / 10, 1, true), "client_order_id": "dlg-1",
                "expires_at_ns": exp.to_string(), "max_in_yocto": NEAR.to_string()}),
        ),
        ("execute_order", json!({"order_id": id, "ops": env.buy_ops(NEAR / 10, 1, true)})),
        ("withdraw_to_owner", json!({"token": null, "amount": (NEAR / 10).to_string()})),
        (
            "place_order",
            json!({"token_in": env.wrap.id(), "token_out": env.meme.id(), "amount_in": "1", "min_out": "1",
                "trigger_meta": "{}", "expires_at_ns": exp.to_string(), "dexes": [env.rhea.id()]}),
        ),
        ("cancel_order", json!({"order_id": id})),
        ("revoke_automation", json!({})),
    ];
    let near0 = env.near_balance(&u.account).await?;
    for (m, args) in calls {
        let d = delegate(&env, &u.account, &u.device_sk, &mallory, m, args).await?;
        println!("delegated device {m}: {:?}", d.failures);
        assert!(d.refused_with("E_NOT_SELF_SIGNED"), "{m}: {:?} {:?}", d.failures, d.logs);
    }
    let d = delegate(&env, &u.account, &u.device_sk, &mallory, "on_swap_settled", json!({})).await?;
    assert!(
        d.failures
            .iter()
            .any(|f| f.contains("DelegateActionAccessKeyError") || f.contains("MethodNameMismatch")),
        "{:?}",
        d.failures
    );
    env.worker.fast_forward(2).await?;
    assert_eq!(order(&env, &u.account, &id).await?["pending"], false);
    let keys: Vec<Value> = env.access_keys(&u.account).await?;
    assert_eq!(keys.len(), 2, "device + automation key still installed");
    // nothing left the account (mallory paid the gas)
    assert!(env.near_balance(&u.account).await? >= near0);
    Ok(())
}

/// Normal self-signed transactions are unchanged: device execute / place / cancel / revoke and
/// a direct relayer fire all work.
#[tokio::test]
async fn v149_self_signed_device_and_relayer_work() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let (u, _ak, auto) = with_automation(&env, "dlgn").await?;
    // device execute (buy)
    let r = env.exec(&u.device, &u.account, env.buy_ops(NEAR / 10, 1, true), "n-1", NEAR).await?;
    assert!(r.is_success(), "{:?}", r.failures());
    assert!(r.receipt_failures().is_empty(), "{:?}", r.receipt_failures());
    // relayer fire (default: no weekly limit)
    let id = place_buy(&env, &u, NEAR / 10).await?;
    let r = auto
        .call(&u.account, "execute_order")
        .args_json(json!({"order_id": id, "ops": env.buy_ops(NEAR / 10, 1, false)}))
        .gas(Gas::from_tgas(250))
        .transact()
        .await?;
    assert!(r.logs().iter().any(|l| l.contains("order_filled")), "{:?}", r.failures());
    // device execute_order, cancel, revoke
    let id = place_buy(&env, &u, NEAR / 10).await?;
    let r = u
        .device
        .call(&u.account, "execute_order")
        .args_json(json!({"order_id": id, "ops": env.buy_ops(NEAR / 10, 1, false)}))
        .gas(Gas::from_tgas(250))
        .transact()
        .await?;
    assert!(r.logs().iter().any(|l| l.contains("order_filled")), "{:?}", r.failures());
    let id = place_buy(&env, &u, NEAR / 10).await?;
    ok(u.device
        .call(&u.account, "cancel_order")
        .args_json(json!({"order_id": id}))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?)?;
    ok(u.device.call(&u.account, "revoke_automation").gas(Gas::from_tgas(50)).transact().await?)?;
    ok(u.device
        .call(&u.account, "withdraw_to_owner")
        .args_json(json!({"token": null, "amount": (NEAR / 10).to_string()}))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?)?;
    Ok(())
}
