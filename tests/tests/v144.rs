//! v1.4.4 regressions on the real runtime (docs/audit/tob-contracts-v143-reaudit.md). RED on
//! 0c166d8 (v1.4.3) with
//!   NT_ACCOUNT_WASM=../out/trading_account_v1_4_3.wasm NT_FACTORY_WASM=../out/factory_v1_4_3.wasm \
//!   NT_UPGRADE_WASM=../out/trading_account_v1_4_3.wasm cargo test --test v144 -- --nocapture
//! GREEN on this build. Paths are relative to contracts/tests.
use integration_tests::*;
use near_workspaces::operations::Function;
use near_workspaces::result::ExecutionFinalResult;
use near_workspaces::types::{Gas, KeyType, NearToken, SecretKey};
use serde_json::{json, Value};

async fn view(env: &Env, u: &User, m: &str) -> anyhow::Result<Value> {
    Ok(env.worker.view(&u.account, m).await?.json()?)
}

fn set_fn(pk: &near_workspaces::types::PublicKey) -> Function {
    Function::new("owner_set_automation_key")
        .args_json(json!({"public_key": pk, "allowance": (2 * NEAR).to_string()}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(40))
}

async fn owner(u: &User, m: &str, args: Value) -> anyhow::Result<ExecutionFinalResult> {
    Ok(u.owner
        .call(&u.account, m)
        .args_json(args)
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(60))
        .transact()
        .await?)
}

/// The code to upgrade to (default: this build).
fn target() -> Vec<u8> {
    std::env::var("NT_UPGRADE_WASM")
        .map(|p| std::fs::read(p).expect("NT_UPGRADE_WASM"))
        .unwrap_or_else(|_| out("trading_account"))
}

async fn upgrade(env: &Env, u: &User, code: Vec<u8>) -> anyhow::Result<()> {
    // (a code already deployed as global, e.g. the env's own, is reused by hash)
    let hash = if code_hash(&code) == env.code_hash {
        env.code_hash.clone()
    } else {
        env.deploy_global(code).await?
    };
    ok(owner(u, "owner_upgrade", json!({"code_hash": hash})).await?)
}

/// Stuck state (RA-1 on v1.4.3 code): [set(K), remove(K)] then revoke. Returns K.
async fn stick(env: &Env, u: &User) -> anyhow::Result<SecretKey> {
    let sk = SecretKey::from_random(KeyType::ED25519);
    let rm = Function::new("owner_remove_key")
        .args_json(json!({"public_key": sk.public_key()}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(40));
    let r = u.owner.batch(&u.account).call(set_fn(&sk.public_key())).call(rm).transact().await?;
    assert!(r.is_success(), "v1.4.3 accepts the batch");
    env.worker.fast_forward(3).await?;
    // its DeleteKey receipt fails (the key is gone): the tx itself succeeds
    assert!(owner(u, "owner_revoke_automation", json!({})).await?.is_success());
    env.worker.fast_forward(3).await?;
    Ok(sk)
}

// ---------------- RA-1 (Low): [set(A), remove(A)] ----------------

#[tokio::test]
async fn v144_ra1_set_then_remove_batch_refused() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let u = env.user("ra1", 6 * NEAR, (NEAR, 5 * NEAR)).await?;
    let sk = SecretKey::from_random(KeyType::ED25519);
    let rm = Function::new("owner_remove_key")
        .args_json(json!({"public_key": sk.public_key()}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(40));
    let r = u.owner.batch(&u.account).call(set_fn(&sk.public_key())).call(rm).transact().await?;
    env.worker.fast_forward(3).await?;
    println!(
        "RA-1 [set,remove]: tx ok={} ak={} set={}",
        r.is_success(),
        view(&env, &u, "get_automation_key").await?,
        view(&env, &u, "get_relayer_keys").await?
    );
    fails_with(&r, "E_AUTOMATION_BUSY");
    // nothing changed: automation still installable, and revocable
    let sk2 = SecretKey::from_random(KeyType::ED25519);
    ok(owner(
        &u,
        "owner_set_automation_key",
        json!({"public_key": sk2.public_key(), "allowance": (2 * NEAR).to_string()}),
    )
    .await?)?;
    ok(owner(&u, "owner_revoke_automation", json!({})).await?)?;
    env.worker.fast_forward(3).await?;
    assert_eq!(view(&env, &u, "get_relayer_keys").await?, json!([]));
    Ok(())
}

// ---------------- SC-8 (Low): a stuck entry can be cleared ----------------

/// The RA-1 stuck state, reached on v1.4.3 code, then an upgrade: the owner clears the entry
/// (chain-proven absent) and automation can be installed again.
#[tokio::test]
async fn v144_sc8_stuck_entry_cleared_after_upgrade() -> anyhow::Result<()> {
    let env = Env::new_with(Some(out("trading_account_v1_4_3")), Some(out("factory_v1_4_3"))).await?;
    let u = env.user("sc8", 6 * NEAR, (NEAR, 5 * NEAR)).await?;
    let k = stick(&env, &u).await?;
    let set = view(&env, &u, "get_relayer_keys").await?;
    println!("SC-8 stuck on v1.4.3: set={set}");
    assert_eq!(set, json!([k.public_key().to_string()]));
    upgrade(&env, &u, target()).await?;
    let fresh = SecretKey::from_random(KeyType::ED25519);
    let set_fresh = json!({"public_key": fresh.public_key(), "allowance": (2 * NEAR).to_string()});
    fails_with(&owner(&u, "owner_set_automation_key", set_fresh.clone()).await?, "E_AUTOMATION_BUSY");
    let r = owner(&u, "owner_clear_relayer_key", json!({"public_key": k.public_key()})).await?;
    println!(
        "SC-8 clear: ok={} logs={:?}",
        r.is_success(),
        r.logs().iter().filter(|l| l.contains("cleared")).collect::<Vec<_>>()
    );
    assert!(r.is_success(), "{:?}", r.clone().into_result().err());
    assert!(r.logs().iter().any(|l| l.contains("relayer_key_cleared") && l.contains("\"existed\":false")));
    assert_eq!(view(&env, &u, "get_relayer_keys").await?, json!([]));
    ok(owner(&u, "owner_set_automation_key", set_fresh).await?)?;
    assert_eq!(view(&env, &u, "get_relayer_keys").await?, json!([fresh.public_key().to_string()]));
    Ok(())
}

// ---------------- RA-3 (Info): pending raise across downgrade + re-upgrade ----------------

#[tokio::test]
async fn v144_ra3_pending_raise_rearmed_after_downgrade() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let u = env.user("ra3", 10 * NEAR, (NEAR, 2 * NEAR)).await?;
    ok(owner(&u, "owner_set_caps", json!({"caps": caps_json((30 * NEAR, 60 * NEAR))})).await?)?;
    // downgrade to v1.4.2 (no delayed raises); the device lowers caps there, which can't cancel it
    upgrade(&env, &u, out("trading_account_v1_4_2")).await?;
    assert_eq!(env.config(&u.account).await?["version"], "1.4.2");
    let t0 = env.now_ns().await?;
    env.worker.fast_forward(100).await?;
    let per_block = ((env.now_ns().await? - t0) / 100).max(1);
    env.worker.fast_forward(3_600_000_000_000 / per_block + 10).await?;
    ok(u.device
        .call(&u.account, "lower_caps")
        .args_json(json!({"caps": caps_json((NEAR / 2, NEAR))}))
        .gas(Gas::from_tgas(20))
        .transact()
        .await?)?;
    // re-upgrade: the stale raise must not apply at once
    upgrade(&env, &u, target()).await?;
    let caps = env.config(&u.account).await?["caps"].clone();
    let p = view(&env, &u, "get_pending_caps").await?;
    println!("RA-3 after re-upgrade: caps={caps} pending={p}");
    assert_eq!(caps, caps_json((NEAR / 2, NEAR)), "stale raise applied at once");
    // v1.4.4 re-armed it; v1.4.5 cancels it (the caps changed under older code, RA4-5)
    let now = env.now_ns().await?;
    assert!(p.is_null() || p["active_at_ns"].as_str().unwrap().parse::<u64>()? > now, "{p}");
    Ok(())
}
