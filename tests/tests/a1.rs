//! A1 audit regressions (ported from audit/a1-contracts/invariants/tests/sandbox.rs). Each asserts
//! the FIXED behaviour; red on the 9d20c54 build (audit/a1-contracts/wasm/), green now:
//!   NT_ACCOUNT_WASM=$PWD/../../audit/a1-contracts/wasm/trading_account.wasm \
//!   NT_FACTORY_WASM=$PWD/../../audit/a1-contracts/wasm/factory.wasm cargo test --test a1
use integration_tests::*;
use near_workspaces::types::{Gas, KeyType, NearToken, SecretKey};
use near_workspaces::Account;
use serde_json::{json, Value};

/// A1-F1 (s1): a compromised device key making a hostile token burn gas is bounded by the daily
/// cap: the whole prepaid gas is charged and the swap gets only its declared gas (weight 0).
#[tokio::test]
async fn a1_s1_gas_burn_bounded_by_daily_cap() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let burner = sub(&env.root, "burner", 5 * NEAR).await?.deploy(&out("gas_burner")).await?.into_result()?;
    let cap = NEAR / 5;
    let u = env.user("gw", 3 * NEAR, (NEAR, cap)).await?;
    // smallest declaration the fixed contract accepts (20 TGas); v1.3 accepted 0-1 TGas too
    let op = json!([{"FtTransferCall": {"token": burner.id(), "receiver_id": env.rhea.id(), "amount": "1",
        "msg": env.rhea_msg(burner.id(), env.meme.id(), 1, 1, false), "gas": (20 * TGAS).to_string()}}]);
    env.worker.fast_forward(3).await?;
    let (b0, r0) = (env.near_balance(&u.account).await?, env.near_balance(burner.id()).await?);
    let mut accepted = 0;
    for i in 0..120 {
        let r = env.exec(&u.device, &u.account, op.clone(), &format!("w{i}"), 0).await?;
        if r.is_failure() {
            fails_with(&r, "E_CAP_DAILY");
            break;
        }
        accepted += 1;
    }
    env.worker.fast_forward(5).await?;
    let burnt = b0 - env.near_balance(&u.account).await?;
    let reward = env.near_balance(burner.id()).await?.saturating_sub(r0);
    let day: Value = env.worker.view(&u.account, "get_day").await?.json()?;
    println!(
        "A1-S1: executes accepted {accepted}; account lost {:.4} NEAR; gas_spent charged {}; hostile token earned {:.4} NEAR; cap {:.2}",
        burnt as f64 / 1e24,
        day["gas_spent_yocto"],
        reward as f64 / 1e24,
        cap as f64 / 1e24
    );
    assert!(burnt <= cap, "gas burn {burnt} exceeded the daily cap {cap}");
    Ok(())
}

/// A1-F2 (s2): a failed automation-key install changes nothing: the stored key is always an
/// on-chain execute_order key and the device key keeps working.
#[tokio::test]
async fn a1_s2_automation_key_state_matches_chain_after_failed_install() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let u = env.user("ak", 3 * NEAR, (NEAR, 2 * NEAR)).await?;
    let sk = SecretKey::from_random(KeyType::ED25519);
    ok(u.owner
        .call(&u.account, "owner_set_automation_key")
        .args_json(json!({"public_key": sk.public_key(), "allowance": NEAR.to_string()}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(50))
        .transact()
        .await?)?;
    let old = Account::from_secret_key(u.account.clone(), sk, &env.worker);
    // owner mistakenly installs a pk that already exists on the account (the device key)
    let r = u
        .owner
        .call(&u.account, "owner_set_automation_key")
        .args_json(json!({"public_key": u.device_sk.public_key(), "allowance": NEAR.to_string()}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(50))
        .transact()
        .await?;
    println!("A1-S2: tx success={} receipt failures={}", r.is_success(), r.receipt_failures().len());
    let stored: Option<String> = env.worker.view(&u.account, "get_automation_key").await?.json()?;
    let keys = env.access_keys(&u.account).await?;
    let on_chain = stored.as_ref().and_then(|s| keys.iter().find(|k| k["public_key"] == json!(s)));
    let methods = on_chain.map(|k| k["access_key"]["permission"]["FunctionCall"]["method_names"].clone());
    let dev = env.exec(&u.device, &u.account, json!([{"NearDeposit": {"amount": "1"}}]), "d1", 0).await?;
    println!("A1-S2: stored={stored:?} methods={methods:?} device ok={}", dev.is_success());
    assert!(dev.is_success(), "device key locked out: {:?}", dev.clone().into_result().err());
    assert_eq!(methods, Some(json!(["execute_order"])), "stored automation key is not an execute_order key");
    assert_eq!(
        stored,
        Some(pk_str(&old.secret_key().public_key())),
        "previous automation key must stay stored"
    );
    Ok(())
}
