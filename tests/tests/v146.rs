//! v1.4.6 regressions on the real runtime (docs/audit/tob-contracts-v145-reaudit.md). RED on
//! v1.4.5 (16ad536) with
//!   NT_UPGRADE_WASM=../out/trading_account_v1_4_5.wasm cargo test --test v146 -- --nocapture
//! GREEN on this build. Paths are relative to contracts/tests.
use integration_tests::*;
use near_workspaces::types::{Gas, NearToken};
use serde_json::{json, Value};

fn target() -> Vec<u8> {
    std::env::var("NT_UPGRADE_WASM")
        .map(|p| std::fs::read(p).expect("NT_UPGRADE_WASM"))
        .unwrap_or_else(|_| out("trading_account"))
}

async fn owner(u: &User, m: &str, a: Value) -> anyhow::Result<near_workspaces::result::ExecutionFinalResult> {
    Ok(u.owner
        .call(&u.account, m)
        .args_json(a)
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(60))
        .transact()
        .await?)
}

async fn upgrade(env: &Env, u: &User, code: Vec<u8>) -> anyhow::Result<()> {
    let hash = if code_hash(&code) == env.code_hash {
        env.code_hash.clone()
    } else {
        env.deploy_global(code).await?
    };
    ok(owner(u, "owner_upgrade", json!({"code_hash": hash})).await?)
}

/// RA5-1: a raise requested on v1.4.4 code (no base), a downgrade to v1.4.2 where the device
/// lowers the caps after the hour, then an upgrade: the raise must not undo the lower.
#[tokio::test]
async fn v146_ra5_1_baseless_matured_raise_not_applied() -> anyhow::Result<()> {
    let env = Env::new_with(Some(out("trading_account_v1_4_4")), Some(out("factory_v1_4_4"))).await?;
    let u = env.user("ra51", 10 * NEAR, (NEAR, 2 * NEAR)).await?;
    // two more global deploys (~37 NEAR each): top up the deployer
    ok(env.root.transfer_near(env.deployer.id(), NearToken::from_near(200)).await?)?;
    ok(owner(&u, "owner_set_caps", json!({"caps": caps_json((30 * NEAR, 60 * NEAR))})).await?)?;
    upgrade(&env, &u, out("trading_account_v1_4_2")).await?;
    let t0 = env.now_ns().await?;
    env.worker.fast_forward(100).await?;
    let per_block = ((env.now_ns().await? - t0) / 100).max(1);
    env.worker.fast_forward(3_600_000_000_000 / per_block + 10).await?;
    for _ in 0..20 {
        if env.now_ns().await? >= t0 + 3_600_000_000_000 {
            break;
        }
        env.worker.fast_forward(200).await?;
    }
    ok(u.device
        .call(&u.account, "lower_caps")
        .args_json(json!({"caps": caps_json((NEAR / 2, NEAR))}))
        .gas(Gas::from_tgas(20))
        .transact()
        .await?)?;
    upgrade(&env, &u, target()).await?;
    let caps = env.config(&u.account).await?["caps"].clone();
    let p: Value = env.worker.view(&u.account, "get_pending_caps").await?.json()?;
    println!("RA5-1: caps={caps} pending={p}");
    assert_eq!(caps, caps_json((NEAR / 2, NEAR)), "the device's lower was undone");
    assert!(!p.is_null(), "re-armed");
    Ok(())
}

/// RA5-2: an account that set its 1Click config on v1.4.0 (layout without max_loss_bps), then
/// upgraded: the owner can still overwrite it.
#[tokio::test]
async fn v146_ra5_2_legacy_oneclick_config_overwritable() -> anyhow::Result<()> {
    let env = Env::new_with(Some(out("trading_account_v1_4_0")), Some(out("factory_v1_4_0"))).await?;
    let u = env.user("ra52", 5 * NEAR, (NEAR, 2 * NEAR)).await?;
    let key = "ed25519:reYaWhvwu8Jzo3WUM3zhn6VrhuMEF4eADL17qtRVifc";
    ok(owner(&u, "owner_set_oneclick_config", json!({"keys": [key], "max_slippage_bps": 100})).await?)?;
    upgrade(&env, &u, target()).await?;
    let r = owner(&u, "owner_set_oneclick_config", json!({"keys": [key], "max_slippage_bps": 200})).await?;
    println!(
        "RA5-2: setter ok={} {:?}",
        r.is_success(),
        r.clone().into_result().err().map(|e| format!("{e:?}").chars().take(160).collect::<String>())
    );
    assert!(r.is_success(), "setter refused on a v1.4.0-layout config");
    assert!(r.logs().iter().any(|l| l.contains("oneclick_config_set") && l.contains("\"old\":null")));
    let c: Value = env.worker.view(&u.account, "get_oneclick_config").await?.json()?;
    assert_eq!(c["max_slippage_bps"], 200);
    Ok(())
}
