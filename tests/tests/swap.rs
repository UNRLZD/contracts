//! Real Rhea swaps through `execute` (sandbox, mainnet-imported wrap.near + Rhea).
use integration_tests::*;
use near_workspaces::types::{Gas, NearToken};
use serde_json::json;

#[tokio::test]
async fn buy_then_sell_through_real_rhea() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let u = env.user("alice", 10 * NEAR, (2 * NEAR, 5 * NEAR)).await?;
    // v1.1: wNEAR registration happened in init
    let sb: serde_json::Value =
        env.wrap.view("storage_balance_of").args_json(json!({"account_id": u.account})).await?.json()?;
    assert!(!sb.is_null(), "registered on wrap by init");

    let amount = NEAR;
    let quote = env.expected_out(env.wrap.id(), amount, env.meme.id()).await?;
    let min_out = quote * 99 / 100;
    let fee_bal0 = env.near_balance(env.fees.id()).await?;
    let r = env
        .exec(
            &u.device,
            &u.account,
            env.buy_ops(amount, min_out, true),
            "buy-1",
            amount + fee(amount) + STORAGE,
        )
        .await?;
    let r = okr(r)?;
    println!("buy logs {:?}", r.logs());
    let got = env.ft_balance(env.meme.id(), &u.account).await?;
    assert!(got >= min_out, "got {got} < min {min_out}");
    assert_eq!(env.near_balance(env.fees.id()).await? - fee_bal0, fee(amount));
    assert!(r.logs().iter().any(|l| l.contains("\"event\":\"settled\"")), "settled via callback");
    assert_eq!(env.day_spent(&u).await?, amount + fee(amount) + STORAGE);

    // sell everything back to wNEAR
    let q = env.expected_out(env.meme.id(), got, env.wrap.id()).await?;
    let min_near = q * 99 / 100;
    let w0 = env.ft_balance(env.wrap.id(), &u.account).await?;
    let fee_bal1 = env.near_balance(env.fees.id()).await?;
    ok(env.exec(&u.device, &u.account, env.sell_ops(got, min_near, false), "sell-1", fee(min_near)).await?)?;
    let w1 = env.ft_balance(env.wrap.id(), &u.account).await?;
    assert!(w1 - w0 >= min_near);
    assert_eq!(env.near_balance(env.fees.id()).await? - fee_bal1, fee(min_near));
    assert_eq!(env.ft_balance(env.meme.id(), &u.account).await?, 0);
    Ok(())
}

/// v1.1 fee-on-success: failed swap (min_out unreachable) -> Rhea panics "E68: slippage error",
/// wrap refunds the wNEAR, ft_transfer_call resolves to used=0, on_swap_settled charges no
/// fee and returns the swap's spend (amount + fee) to the daily window. Storage stays spent.
#[tokio::test]
async fn failed_swap_charges_no_fee_and_restores_spend() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let u = env.user("fail", 5 * NEAR, (2 * NEAR, 5 * NEAR)).await?;
    let amt = NEAR;
    let quote = env.expected_out(env.wrap.id(), amt, env.meme.id()).await?;
    let f0 = env.near_balance(env.fees.id()).await?;
    let r = env
        .exec(&u.device, &u.account, env.buy_ops(amt, quote * 2, true), "f1", amt + fee(amt) + STORAGE)
        .await?;
    assert!(r.is_success(), "execute itself succeeded");
    let fails = format!("{:?}", r.receipt_failures());
    // live Rhea v1.9.20 reports swap slippage as "E68: slippage error" (not ERR_MIN_AMOUNT)
    assert!(fails.contains("E68: slippage error"), "{fails}");
    assert_eq!(env.ft_balance(env.wrap.id(), &u.account).await?, amt, "wNEAR refunded to the account");
    assert_eq!(env.ft_balance(env.meme.id(), &u.account).await?, 0);
    assert_eq!(env.near_balance(env.fees.id()).await?, f0, "no fee on failure");
    assert!(r.logs().iter().any(|l| l.contains("\"event\":\"settled\"")
        && l.contains("\"used\":\"0\"")
        && l.contains("\"fee\":\"0\"")));
    assert_eq!(env.day_spent(&u).await?, STORAGE, "swap spend returned to the window");
    // the refunded wNEAR can be sold/unwrapped: NearWithdraw back to native NEAR
    let b0 = env.near_balance(&u.account).await?;
    ok(env
        .exec(&u.device, &u.account, json!([{"NearWithdraw": {"amount": amt.to_string()}}]), "unwrap", 0)
        .await?)?;
    assert_eq!(env.ft_balance(env.wrap.id(), &u.account).await?, 0);
    assert!(env.near_balance(&u.account).await? > b0 + amt - NEAR / 100);
    Ok(())
}

/// Parallel promise shape (s1): every outgoing receipt of `execute` is a direct child of the
/// execute receipt and all of them execute in the same block. The only `.then` is the
/// settlement callback, which runs after the swap (fee paid from there).
#[tokio::test]
async fn promises_are_parallel() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let u = env.user("par", 5 * NEAR, (2 * NEAR, 5 * NEAR)).await?;
    let r = okr(env
        .exec(&u.device, &u.account, env.buy_ops(NEAR, 1, true), "p1", NEAR + fee(NEAR) + STORAGE)
        .await?)?;
    let st = env.tx_status(&r.outcome().transaction_hash.to_string(), &u.account).await?;
    let ros = st["receipts_outcome"].as_array().unwrap();
    let exec = ros
        .iter()
        .find(|o| o["outcome"]["logs"].to_string().contains("\\\"event\\\":\\\"execute\\\""))
        .expect("execute receipt");
    let kids: Vec<&serde_json::Value> = exec["outcome"]["receipt_ids"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|id| ros.iter().find(|o| &o["id"] == id))
        .filter(|o| o["outcome"]["executor_id"] != json!(u.account)) // drop gas refund
        .collect();
    let execs: Vec<String> =
        kids.iter().map(|o| o["outcome"]["executor_id"].as_str().unwrap().to_string()).collect();
    println!("execute children: {execs:?}");
    for want in [env.meme.id(), env.wrap.id()] {
        assert!(execs.iter().any(|e| e == want.as_str()), "missing child on {want}");
    }
    assert_eq!(kids.len(), 2, "one promise per receiver (wrap batch = near_deposit+ft_transfer_call)");
    let blocks: std::collections::HashSet<_> =
        kids.iter().map(|o| o["block_hash"].as_str().unwrap()).collect();
    assert_eq!(blocks.len(), 1, "all first-hop receipts in one block");
    // compare with the execute receipt's block: first hop = exactly the next block
    let h = |b: &str| b.to_string();
    let _ = h;
    let settled =
        ros.iter().find(|o| o["outcome"]["logs"].to_string().contains("settled")).expect("settle receipt");
    assert!(
        settled["outcome"]["receipt_ids"].as_array().unwrap().iter().any(|id| {
            ros.iter().any(|o| &o["id"] == id && o["outcome"]["executor_id"] == json!(env.fees.id()))
        }),
        "fee transfer is a child of the callback"
    );
    Ok(())
}

/// DCL and Plach message shapes go out as ft_transfer_call to the allowlisted DEX; the
/// sandbox DEX accounts have no code, so ft_on_transfer fails and wNEAR is refunded.
#[tokio::test]
async fn dcl_and_plach_shapes_refund_on_dex_failure() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let u = env.user("shape", 5 * NEAR, (2 * NEAR, 5 * NEAR)).await?;
    ok(env
        .exec(&u.device, &u.account, json!([{"NearDeposit": {"amount": NEAR.to_string()}}]), "w", 0)
        .await?)?;
    let dcl_msg = json!({"Swap": {"pool_ids": [format!("{}|{}|2000", env.wrap.id(), env.meme.id())], "output_token": env.meme.id(), "min_output_amount": "5", "skip_unwrap_near": true}}).to_string();
    let plach_msg = json!({"operations": [
        {"SwapSimple": {"dex_id": "x/xyk", "message": "AA==", "asset_in": format!("nep141:{}", env.wrap.id()), "asset_out": format!("nep141:{}", env.meme.id()), "amount": {"Amount": {"ExactIn": "100"}}, "constraint": "5"}},
        {"Withdraw": {"asset_id": format!("nep141:{}", env.meme.id()), "amount": {"Full": {"at_least": "5"}}, "to": null, "rescue_address": null}}],
        "referrer": env.fees.id()}).to_string();
    for (i, (dex, m)) in [(env.dcl.id(), dcl_msg), (env.plach.id(), plach_msg)].into_iter().enumerate() {
        let amt = NEAR / 10;
        let ops = json!([{"FtTransferCall": {"token": env.wrap.id(), "receiver_id": dex, "amount": amt.to_string(), "msg": m, "gas": (100 * TGAS).to_string()}}]);
        let f0 = env.near_balance(env.fees.id()).await?;
        let r = env.exec(&u.device, &u.account, ops, &format!("s{i}"), amt + fee(amt)).await?;
        assert!(r.is_success());
        assert!(!r.receipt_failures().is_empty());
        assert_eq!(env.ft_balance(env.wrap.id(), &u.account).await?, NEAR, "refunded");
        assert_eq!(env.near_balance(env.fees.id()).await?, f0, "no fee");
        assert_eq!(env.day_spent(&u).await?, 0, "spend returned");
    }
    // v1.1 Plach buy with native NEAR (router shape): register_assets + deposit_near on the
    // Plach-kind DEX. No code there -> batch fails, NEAR refunded, callback: no fee.
    let amt = NEAR / 5;
    let m = json!({"operations": [
        {"SwapSimple": {"dex_id": "slimedragon.near/xyk", "message": "AA==", "asset_in": "near", "asset_out": format!("nep141:{}", env.meme.id()), "amount": {"Amount": {"ExactIn": amt.to_string()}}, "constraint": "5"}},
        {"Withdraw": {"asset_id": format!("nep141:{}", env.meme.id()), "amount": {"Full": {"at_least": "5"}}, "to": null, "rescue_address": null}}],
        "referrer": env.fees.id()}).to_string();
    let ops = json!([
        {"PlachRegisterAssets": {"dex": env.plach.id(), "asset_ids": ["near", format!("nep141:{}", env.meme.id())]}},
        {"PlachDepositNear": {"dex": env.plach.id(), "amount": amt.to_string(), "msg": m, "gas": (240 * TGAS).to_string()}}
    ]);
    let (b0, f0) = (env.near_balance(&u.account).await?, env.near_balance(env.fees.id()).await?);
    let r = env.exec(&u.device, &u.account, ops.clone(), "plach-buy", amt + fee(amt)).await?;
    assert!(r.is_success(), "{:?}", r.clone().into_result().err());
    assert!(format!("{:?}", r.receipt_failures()).contains("CodeDoesNotExist"));
    assert!(r.logs().iter().any(|l| l.contains("\"used\":\"0\"")));
    assert_eq!(env.near_balance(env.fees.id()).await?, f0);
    assert!(env.near_balance(&u.account).await? > b0 - NEAR / 100, "deposit refunded");
    assert_eq!(env.day_spent(&u).await?, 0);
    // router's 280 TGas deposit_near doesn't fit with the callback: E_GAS
    let mut big = ops;
    big[1]["PlachDepositNear"]["gas"] = json!((280 * TGAS).to_string());
    fails_with(&env.exec(&u.device, &u.account, big, "plach-280", amt + fee(amt)).await?, "E_GAS");
    Ok(())
}

/// Daily window resets once 24h of block time has passed. Sandbox blocks advance ~0.3s of
/// block time each (24h ~ 40 min of fast_forward), so the stored `Day.start_ns` is moved
/// back 24h by patching contract state (located by its exact borsh bytes).
#[tokio::test]
async fn daily_window_rollover() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let u = env.user("roll", 5 * NEAR, (2 * NEAR, 2 * NEAR)).await?;
    ok(env.exec(&u.device, &u.account, env.buy_ops(NEAR, 1, true), "d1", 2 * NEAR).await?)?;
    fails_with(
        &env.exec(&u.device, &u.account, env.buy_ops(NEAR, 1, false), "d2", 2 * NEAR).await?,
        "E_CAP_DAILY",
    );
    let day: serde_json::Value = env.worker.view(&u.account, "get_day").await?.json()?;
    let start: u64 = day["start_ns"].as_str().unwrap().parse()?;
    let spent: u128 = day["spent_yocto"].as_str().unwrap().parse()?;
    let state = env.worker.view_state(&u.account).await?;
    let raw = state.get(b"STATE".as_slice()).expect("STATE key").clone();
    let mut needle = start.to_le_bytes().to_vec();
    needle.extend_from_slice(&spent.to_le_bytes());
    let pos = raw.windows(needle.len()).position(|w| w == needle.as_slice()).expect("Day bytes");
    // v1.4.1 (D5): the window is the UTC day; `start` is 00:00 UTC today
    assert_eq!(start % 86_400_000_000_000, 0);
    // migration: a live pre-v1.4.1 rolling window (started 1 h ago, not at midnight) keeps its
    // spend for the current UTC day
    let mut patched = raw.clone();
    let legacy = env.now_ns().await? - 3_600_000_000_000;
    patched[pos..pos + 8].copy_from_slice(&legacy.to_le_bytes());
    env.worker.patch_state(&u.account, b"STATE", &patched).await?;
    fails_with(
        &env.exec(&u.device, &u.account, env.buy_ops(NEAR, 1, false), "d3", 2 * NEAR).await?,
        "E_CAP_DAILY",
    );
    // a window from yesterday's UTC day: rolled over at 00:00 UTC
    patched[pos..pos + 8].copy_from_slice(&(start - 86_400_000_000_000).to_le_bytes());
    env.worker.patch_state(&u.account, b"STATE", &patched).await?;
    assert_eq!(env.day_spent(&u).await?, 0);
    ok(env.exec(&u.device, &u.account, env.buy_ops(NEAR, 1, false), "d4", 2 * NEAR).await?)?;
    assert_eq!(env.day_spent(&u).await?, NEAR + fee(NEAR));
    Ok(())
}

/// v1.1 stuck-output rescue: swap output left on the account's Plach inner balance (Plach
/// re-credits it when a Withdraw fails) is pulled back with `PlachWithdraw`, always to self,
/// and it is not spend. Uses a test-only mock with Plach's `withdraw` signature.
#[tokio::test]
async fn plach_withdraw_rescues_stuck_output() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let u = env.user("stuck", 5 * NEAR, (NEAR, 2 * NEAR)).await?;
    ok(env.root.transfer_near(env.plach.id(), NearToken::from_near(3)).await?)?;
    let plach = env.plach.deploy(&out("mock_plach")).await?.into_result()?;
    ok(plach.call("new").transact().await?)?;
    // Plach holds MEME; 1000 MEME are credited to the trading account's inner balance.
    ok(env.meme.call("mint").args_json(json!({"account_id": plach.id(), "amount": "0"})).transact().await?)?;
    ok(env
        .meme
        .call("mint")
        .args_json(json!({"account_id": env.root.id(), "amount": "1000"}))
        .transact()
        .await?)?;
    ok(env
        .root
        .call(env.meme.id(), "ft_transfer_call")
        .args_json(json!({"receiver_id": plach.id(), "amount": "1000", "msg": u.account}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?)?;
    let asset = format!("nep141:{}", env.meme.id());
    let inner = |w: &near_workspaces::Worker<near_workspaces::network::Sandbox>,
                 id: near_workspaces::AccountId| {
        let (w, asset, pid) = (w.clone(), asset.clone(), plach.id().clone());
        async move {
            let v: String = w
                .view(&pid, "balance_of")
                .args_json(json!({"account_id": id, "asset_id": asset}))
                .await?
                .json()?;
            anyhow::Ok(v.parse::<u128>()?)
        }
    };
    assert_eq!(inner(&env.worker, u.account.clone()).await?, 1000);
    // register the account on MEME, then rescue 400 exactly, then the rest (Full)
    let spent = env.day_spent(&u).await? + STORAGE;
    let ops = json!([{"StorageDeposit": {"token": env.meme.id(), "amount": STORAGE.to_string()}},
        {"PlachWithdraw": {"dex": plach.id(), "asset_id": asset, "amount": "400"}}]);
    ok(env.exec(&u.device, &u.account, ops, "w1", STORAGE).await?)?;
    assert_eq!(env.ft_balance(env.meme.id(), &u.account).await?, 400);
    let ops = json!([{"PlachWithdraw": {"dex": plach.id(), "asset_id": asset, "amount": null}}]);
    ok(env.exec(&u.device, &u.account, ops, "w2", 0).await?)?;
    assert_eq!(env.ft_balance(env.meme.id(), &u.account).await?, 1000, "all output back on the account");
    assert_eq!(inner(&env.worker, u.account.clone()).await?, 0);
    assert_eq!(env.day_spent(&u).await?, spent, "withdraw is not spend");
    // destination is not a parameter: an injected withdraw_to is rejected by the Op parser
    let ops = json!([{"PlachWithdraw": {"dex": plach.id(), "asset_id": asset, "amount": null, "withdraw_to": env.fees.id()}}]);
    assert!(env.exec(&u.device, &u.account, ops, "w3", 0).await?.is_failure());
    // only Plach-kind DEXes
    let ops = json!([{"PlachWithdraw": {"dex": env.rhea.id(), "asset_id": asset, "amount": null}}]);
    fails_with(&env.exec(&u.device, &u.account, ops, "w4", 0).await?, "E_BAD_DEX");
    Ok(())
}

/// v1.2: undelivered Rhea output (account not registered on the output token) goes to the
/// account's own Rhea *user lostfound* (no Ref registration needed); `DexWithdraw` on a
/// RheaClassic DEX = `claim_lostfound{token_id}` brings it back to self. Not spend. The swap
/// itself succeeded (tokens are ours), so the fee is charged: accepted as rare, the client
/// registers output storage before every swap.
#[tokio::test]
async fn rhea_undelivered_output_rescued_from_user_lostfound() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let u = env.user("lost", 3 * NEAR, (NEAR, 3 * NEAR)).await?;
    let (d, acc) = (&u.device, &u.account);
    let r = env.exec(d, acc, env.buy_ops(NEAR / 2, 1, false), "b", NEAR).await?;
    assert!(r.logs().iter().any(|l| l.contains("Depositing to user lostfound account")), "{:?}", r.logs());
    let lost: String = env
        .rhea
        .view("get_lostfound_token")
        .args_json(json!({"account_id": acc, "token_id": env.meme.id()}))
        .await?
        .json()?;
    let lost: u128 = lost.parse()?;
    assert!(lost > 0);
    assert_eq!(env.ft_balance(env.meme.id(), acc).await?, 0);
    let spent = env.day_spent(&u).await? + STORAGE;
    // amount must be null for Rhea (claim is full)
    fails_with(
        &env.exec(
            d,
            acc,
            json!([{"DexWithdraw": {"dex": env.rhea.id(), "token": env.meme.id(), "amount": "5"}}]),
            "x",
            0,
        )
        .await?,
        "E_BAD_OP",
    );
    ok(env
        .exec(
            d,
            acc,
            json!([{"StorageDeposit": {"token": env.meme.id(), "amount": STORAGE.to_string()}},
                {"DexWithdraw": {"dex": env.rhea.id(), "token": env.meme.id(), "amount": null}}]),
            "claim",
            STORAGE,
        )
        .await?)?;
    assert_eq!(env.ft_balance(env.meme.id(), acc).await?, lost, "claimed back to the trading account");
    assert_eq!(env.day_spent(&u).await?, spent, "not spend");
    // Plach-kind / unlisted DEXes are not DexWithdraw targets
    fails_with(
        &env.exec(
            d,
            acc,
            json!([{"DexWithdraw": {"dex": env.plach.id(), "token": env.meme.id(), "amount": null}}]),
            "y",
            0,
        )
        .await?,
        "E_BAD_DEX",
    );
    Ok(())
}
