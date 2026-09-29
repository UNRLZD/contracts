//! v1.4.5 regressions on the real runtime (docs/audit/tob-contracts-v144-reaudit.md). RED on
//! 06b1f47 (v1.4.4) with
//!   NT_ACCOUNT_WASM=../out/trading_account_v1_4_4.wasm NT_FACTORY_WASM=../out/factory_v1_4_4.wasm \
//!   NT_UPGRADE_WASM=../out/trading_account_v1_4_4.wasm cargo test --test v145 -- --nocapture
//! GREEN on this build. Paths are relative to contracts/tests.
use integration_tests::*;
use near_workspaces::types::{Gas, KeyType, NearToken, SecretKey};
use serde_json::{json, Value};

fn target() -> Vec<u8> {
    std::env::var("NT_UPGRADE_WASM")
        .map(|p| std::fs::read(p).expect("NT_UPGRADE_WASM"))
        .unwrap_or_else(|_| out("trading_account"))
}

async fn view(env: &Env, acc: &near_workspaces::AccountId, m: &str) -> anyhow::Result<Value> {
    Ok(env.worker.view(acc, m).await?.json()?)
}

/// RA4-1: a v1.4.3 install in flight, the upgrade and a stream of owner_clear_relayer_key calls,
/// all submitted at once (the re-audit's race, 6 accounts). Invariant: the stored automation key
/// is always in the relayer role set (and so is any live automation key).
#[tokio::test]
async fn v145_ra4_1_upgrade_race_keeps_ak_in_role_set() -> anyhow::Result<()> {
    let env = Env::new_with(Some(out("trading_account_v1_4_3")), Some(out("factory_v1_4_3"))).await?;
    let new_hash = env.deploy_global(target()).await?;
    let mut bad = vec![];
    for i in 0..6u64 {
        let u = env.user(&format!("race{i}"), 6 * NEAR, (NEAR, 5 * NEAR)).await?;
        let k = SecretKey::from_random(KeyType::ED25519);
        let call = |m: &str, a: Value| {
            u.owner
                .call(&u.account, m)
                .args_json(a)
                .deposit(NearToken::from_yoctonear(1))
                .gas(Gas::from_tgas(100))
        };
        let s = call(
            "owner_set_automation_key",
            json!({"public_key": k.public_key(), "allowance": (2 * NEAR).to_string()}),
        )
        .transact_async()
        .await?;
        let up = call("owner_upgrade", json!({"code_hash": new_hash})).transact_async().await?;
        let mut clears = vec![];
        for _ in 0..12 {
            tokio::time::sleep(std::time::Duration::from_millis(40 + 40 * i)).await;
            clears.push(
                call("owner_clear_relayer_key", json!({"public_key": k.public_key()}))
                    .transact_async()
                    .await?,
            );
        }
        let _ = (s.await?, up.await?);
        let mut accepted = 0;
        for c in clears {
            if c.await?.is_success() {
                accepted += 1;
            }
        }
        env.worker.fast_forward(4).await?;
        let ak = view(&env, &u.account, "get_automation_key").await?;
        let set = view(&env, &u.account, "get_relayer_keys").await?;
        let pk = k.public_key().to_string();
        let on_chain = env.access_keys(&u.account).await?.iter().any(|x| x["public_key"] == pk);
        let in_set = set.as_array().unwrap().iter().any(|x| x == &json!(pk));
        let ak_ok = ak.is_null() || set.as_array().unwrap().contains(&ak);
        println!("RACE{i}: clears accepted={accepted} ak={ak} in_set={in_set} on_chain={on_chain} ak_in_set={ak_ok}");
        if !ak_ok || (on_chain && !in_set) {
            bad.push(i);
        }
    }
    assert!(bad.is_empty(), "runs with ak (or a live key) outside the role set: {bad:?}");
    Ok(())
}

/// RA4-5: a raise that matured before an upgrade is applied, not pushed back; a destination
/// still pending at the upgrade gets a full delay from then.
#[tokio::test]
async fn v145_ra4_5_matured_raise_applied_pending_dest_rearmed() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let u = env.user("ra45", 10 * NEAR, (NEAR, 2 * NEAR)).await?;
    let owner = |m: &str, a: Value| {
        u.owner.call(&u.account, m).args_json(a).deposit(NearToken::from_yoctonear(1)).gas(Gas::from_tgas(60))
    };
    ok(owner("owner_set_caps", json!({"caps": caps_json((30 * NEAR, 60 * NEAR))})).transact().await?)?;
    let t0 = env.now_ns().await?;
    env.worker.fast_forward(100).await?;
    let per_block = ((env.now_ns().await? - t0) / 100).max(1);
    env.worker.fast_forward(3_600_000_000_000 / per_block + 10).await?;
    assert_eq!(env.config(&u.account).await?["caps"], caps_json((30 * NEAR, 60 * NEAR)), "matured");
    let r = okr(owner(
        "owner_add_withdraw_destination",
        json!({"label": "sol", "asset": "nep141:sol.omft.near",
        "recipient": "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin", "recipient_type": "DESTINATION_CHAIN"}),
    )
    .transact()
    .await?)?;
    let dest: u32 = r.json()?;
    let before: u64 = view(&env, &u.account, "get_withdraw_destinations").await?[0]["active_at_ns"]
        .as_str()
        .unwrap()
        .parse()?;
    env.worker.fast_forward(5).await?;
    let code = target();
    let hash = if code_hash(&code) == env.code_hash {
        env.code_hash.clone()
    } else {
        env.deploy_global(code).await?
    };
    let r = okr(owner("owner_upgrade", json!({"code_hash": hash})).transact().await?)?;
    let caps = env.config(&u.account).await?["caps"].clone();
    let pending = view(&env, &u.account, "get_pending_caps").await?;
    let after: u64 = view(&env, &u.account, "get_withdraw_destinations").await?[0]["active_at_ns"]
        .as_str()
        .unwrap()
        .parse()?;
    println!(
        "RA4-5: caps={caps} pending={pending} dest {dest} active_at {before} -> {after}; logs {:?}",
        r.logs().iter().filter(|l| l.contains("caps_") || l.contains("rearmed")).collect::<Vec<_>>()
    );
    assert_eq!(caps, caps_json((30 * NEAR, 60 * NEAR)), "a matured raise was pushed back");
    assert!(pending.is_null(), "{pending}");
    assert!(after > before, "pending destination not re-armed");
    Ok(())
}
