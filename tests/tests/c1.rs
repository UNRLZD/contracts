//! v1.4.2 re-audit C1 regressions on the real runtime (RED on 47b87f3 / v1.4.1 via
//! NT_ACCOUNT_WASM + NT_FACTORY_WASM, GREEN on v1.4.2):
//!  M1 revoke window: the owner revokes the relayer while it streams BUY fires; none may fill.
//!  M1 rotation window: the owner rotates the relayer while BOTH keys stream BUY fires; none
//!     may fill.
use integration_tests::*;
use near_workspaces::types::{Gas, KeyType, NearToken, SecretKey};
use near_workspaces::Account;
use serde_json::{json, Value};
use std::task::Poll;

async fn wait(
    s: near_workspaces::operations::TransactionStatus,
) -> anyhow::Result<near_workspaces::result::ExecutionFinalResult> {
    // a tx whose access key was deleted before inclusion never executes: give up after 20 s
    for _ in 0..200 {
        if let Poll::Ready(r) = s.status().await? {
            return Ok(r);
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    anyhow::bail!("not executed (key gone)")
}

async fn set_automation(env: &Env, u: &User, sk: &SecretKey) -> anyhow::Result<Account> {
    ok(u.owner
        .call(&u.account, "owner_set_automation_key")
        .args_json(json!({"public_key": sk.public_key(), "allowance": (2 * NEAR).to_string()}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(50))
        .transact()
        .await?)?;
    Ok(Account::from_secret_key(u.account.clone(), sk.clone(), &env.worker))
}

async fn buy_orders(env: &Env, u: &User, n: usize) -> anyhow::Result<Vec<String>> {
    let exp = env.now_ns().await? + 3_600_000_000_000;
    let mut ids = vec![];
    for _ in 0..n {
        let r = okr(u
            .device
            .call(&u.account, "place_order")
            .args_json(json!({"token_in": env.wrap.id(), "token_out": env.meme.id(), "amount_in": (NEAR / 100).to_string(),
                "min_out": "1", "trigger_meta": "{}", "expires_at_ns": exp.to_string(), "dexes": [env.rhea.id()]}))
            .gas(Gas::from_tgas(30))
            .transact()
            .await?)?;
        ids.push(r.json::<String>()?);
    }
    Ok(ids)
}

/// Streams BUY fires from `keys` (round robin, ~120 ms apart) while `owner_tx` executes;
/// returns (ids that FIRED, refused count).
async fn race(
    env: &Env,
    u: &User,
    keys: &[Account],
    ids: &[String],
    owner_tx: near_workspaces::operations::TransactionStatus,
) -> anyhow::Result<(Vec<String>, usize)> {
    let mut pending = vec![];
    for (i, id) in ids.iter().enumerate() {
        let k = &keys[i % keys.len()];
        let tx = k
            .call(&u.account, "execute_order")
            .args_json(json!({"order_id": id, "ops": env.buy_ops(NEAR / 100, 1, false)}))
            .gas(Gas::from_tgas(250))
            .transact_async()
            .await;
        if let Ok(s) = tx {
            pending.push((id.clone(), s));
        }
        tokio::time::sleep(std::time::Duration::from_millis(120)).await;
    }
    assert!(wait(owner_tx).await?.is_success());
    let (mut fired, mut refused) = (vec![], 0);
    for (id, s) in pending {
        if let Ok(r) = wait(s).await {
            if r.is_success() {
                fired.push(id);
            } else if format!("{:?}", r.into_result().err()).contains("E_RELAYER_SELL_ONLY") {
                refused += 1;
            }
        }
    }
    Ok((fired, refused))
}

#[tokio::test]
async fn c1_m1_revoke_window_no_buy_fires() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let u = env.user("c1r", 6 * NEAR, (NEAR, 5 * NEAR)).await?;
    let sk = SecretKey::from_random(KeyType::ED25519);
    let auto = set_automation(&env, &u, &sk).await?;
    let ids = buy_orders(&env, &u, 24).await?;
    let revoke = u
        .owner
        .call(&u.account, "owner_revoke_automation")
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(30))
        .transact_async()
        .await?;
    let (fired, refused) = race(&env, &u, &[auto], &ids, revoke).await?;
    println!("C1-M1 revoke race: {} refused, {} fired {:?}", refused, fired.len(), fired);
    assert!(fired.is_empty(), "a revoked relayer filled BUY orders: {fired:?}");
    assert!(refused > 0, "race window not exercised");
    // once the DeleteKey is confirmed, the key leaves the role set
    env.worker.fast_forward(3).await?;
    let v: Vec<Value> = env.worker.view(&u.account, "get_relayer_keys").await?.json()?;
    assert!(v.is_empty(), "{v:?}");
    Ok(())
}

#[tokio::test]
async fn c1_m1_rotation_window_no_buy_fires() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let u = env.user("c1t", 6 * NEAR, (NEAR, 5 * NEAR)).await?;
    let (sk1, sk2) = (SecretKey::from_random(KeyType::ED25519), SecretKey::from_random(KeyType::ED25519));
    let old = set_automation(&env, &u, &sk1).await?;
    let new = Account::from_secret_key(u.account.clone(), sk2.clone(), &env.worker);
    let ids = buy_orders(&env, &u, 24).await?;
    let rotate = u
        .owner
        .call(&u.account, "owner_set_automation_key")
        .args_json(json!({"public_key": sk2.public_key(), "allowance": (2 * NEAR).to_string()}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(50))
        .transact_async()
        .await?;
    let (fired, refused) = race(&env, &u, &[new, old], &ids, rotate).await?;
    println!("C1-M1 rotation race: {} refused, {} fired {:?}", refused, fired.len(), fired);
    assert!(fired.is_empty(), "a rotating relayer filled BUY orders: {fired:?}");
    assert!(refused > 0, "race window not exercised");
    env.worker.fast_forward(3).await?;
    let v: Vec<String> = env.worker.view(&u.account, "get_relayer_keys").await?.json()?;
    assert_eq!(v, vec![sk2.public_key().to_string()]);
    Ok(())
}

/// C1-L3: a relayer fire costs max(min_out, allowance / 20): a sell with min_out = 1 yocto
/// uses 0.5 NEAR of the default 10 NEAR weekly allowance (was 1 yocto).
#[tokio::test]
async fn c1_l3_relayer_fire_floor() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let u = env.user("c1f", 6 * NEAR, (2 * NEAR, 5 * NEAR)).await?;
    let sk = SecretKey::from_random(KeyType::ED25519);
    let auto = set_automation(&env, &u, &sk).await?;
    ok(env.exec(&u.device, &u.account, env.buy_ops(NEAR, 1, true), "b", 2 * NEAR).await?)?;
    let held = env.ft_balance(env.meme.id(), &u.account).await?;
    let exp = env.now_ns().await? + 3_600_000_000_000;
    let r = okr(u
        .device
        .call(&u.account, "place_order")
        .args_json(json!({"token_in": env.meme.id(), "token_out": env.wrap.id(), "amount_in": (held / 4).to_string(),
            "min_out": "1", "trigger_meta": "{}", "expires_at_ns": exp.to_string(), "dexes": [env.rhea.id()]}))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?)?;
    let id: String = r.json()?;
    ok(auto
        .call(&u.account, "execute_order")
        .args_json(json!({"order_id": id, "ops": env.sell_ops(held / 4, 1, false)}))
        .gas(Gas::from_tgas(300))
        .transact()
        .await?)?;
    let w: Value = env.worker.view(&u.account, "get_relayer_week").await?.json()?;
    assert_eq!(w["spent_yocto"], (10 * NEAR / 20).to_string(), "{w}");
    Ok(())
}
