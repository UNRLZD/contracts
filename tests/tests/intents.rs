//! v1.4 NEAR Intents cross-chain withdrawals against the REAL intents.near (mainnet code
//! v0.4.2, cached in tests/.cache) and real wrap.near. Every new E_ code, invariant 11,
//! exactly-once funding, the separate withdraw cap, and the live 1Click signature vectors.
use ed25519_dalek::{Signer, SigningKey};
use integration_tests::*;
use near_workspaces::result::ExecutionFinalResult;
use near_workspaces::types::{Gas, KeyType, NearToken, SecretKey};
use near_workspaces::{Account, AccountId};
use serde_json::{json, Map, Value};

const MANAGER: &str = "ed25519:reYaWhvwu8Jzo3WUM3zhn6VrhuMEF4eADL17qtRVifc";
const SOL: &str = "nep141:sol-5ce3bf3a31af18be40ba30f721101b4341690186.omft.near";
const SOL_RCPT: &str = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
const HOUR_NS: u64 = 3_600_000_000_000;

fn vectors() -> Vec<Value> {
    serde_json::from_str(include_str!("../../trading-account/tests/fixtures/oneclick_quotes.json")).unwrap()
}

fn live(name: &str) -> (String, String) {
    let v = vectors().into_iter().find(|v| v["name"] == name).unwrap();
    (v["signed_quote"].as_str().unwrap().into(), v["signature"].as_str().unwrap().into())
}

/// SDK stableStringify (sorted keys, compact) of a flat object.
fn stable(m: &Map<String, Value>) -> String {
    let mut ks: Vec<&String> = m.keys().collect();
    ks.sort();
    let body: Vec<String> = ks
        .iter()
        .map(|k| format!("{}:{}", serde_json::to_string(k).unwrap(), serde_json::to_string(&m[*k]).unwrap()))
        .collect();
    format!("{{{}}}", body.join(","))
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

fn iso(ns: u64) -> String {
    let s = ns / 1_000_000_000;
    let (y, m, d) = civil_from_days((s / 86_400) as i64);
    let r = s % 86_400;
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.000Z", r / 3600, r / 60 % 60, r % 60)
}

fn test_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn pk_str(sk: &SigningKey) -> String {
    format!("ed25519:{}", bs58::encode(sk.verifying_key().to_bytes()).into_string())
}

fn sign(sk: &SigningKey, s: &str) -> String {
    use sha2::Digest;
    let msg = bs58::encode(sha2::Sha256::digest(s.as_bytes())).into_string();
    format!("ed25519:{}", bs58::encode(sk.sign(msg.as_bytes()).to_bytes()).into_string())
}

fn addr(n: u8) -> String {
    format!("{:02x}", n).repeat(32)
}

/// The live 1Click withdraw quote re-targeted at `ta` (refund to self on ORIGIN_CHAIN).
fn quote(ta: &AccountId, amount: u128, deposit: &str, deadline_ns: u64) -> Map<String, Value> {
    let mut m =
        serde_json::from_str::<Value>(&live("quote-live-wd-intents").0).unwrap().as_object().unwrap().clone();
    m["refundTo"] = ta.to_string().into();
    m["refundType"] = "ORIGIN_CHAIN".into();
    m["amount"] = amount.to_string().into();
    m["amountIn"] = amount.to_string().into();
    m["depositAddress"] = deposit.into();
    m["deadline"] = iso(deadline_ns).into();
    // v1.4.2 (C1-L2): fresh signed issue time (deadline - 1 h = "now" for now + 1 h deadlines)
    m["timestamp"] = iso(deadline_ns.saturating_sub(HOUR_NS)).into();
    m
}

fn events(r: &ExecutionFinalResult, name: &str) -> Vec<Value> {
    r.logs()
        .iter()
        .filter_map(|l| l.strip_prefix("EVENT_JSON:"))
        .filter_map(|j| serde_json::from_str::<Value>(j).ok())
        .filter(|v| v["event"] == name)
        .map(|v| v["data"].clone())
        .collect()
}

struct Ctx<'a> {
    env: &'a Env,
    u: &'a User,
    intents: AccountId,
    n: std::cell::Cell<u32>,
}

impl Ctx<'_> {
    async fn owner(&self, m: &str, args: Value) -> anyhow::Result<ExecutionFinalResult> {
        Ok(self
            .u
            .owner
            .call(&self.u.account, m)
            .args_json(args)
            .deposit(NearToken::from_yoctonear(1))
            .gas(Gas::from_tgas(100))
            .transact()
            .await?)
    }

    async fn device(&self, m: &str, args: Value) -> anyhow::Result<ExecutionFinalResult> {
        Ok(self.u.device.call(&self.u.account, m).args_json(args).gas(Gas::from_tgas(100)).transact().await?)
    }

    async fn withdraw_args(
        &self,
        dest: u32,
        token: &AccountId,
        amount: u128,
        q: &str,
        sig: &str,
    ) -> anyhow::Result<Value> {
        self.n.set(self.n.get() + 1);
        Ok(json!({"dest_id": dest, "token": token, "amount": amount.to_string(), "signed_quote": q,
            "signature": sig, "client_order_id": format!("x{}", self.n.get()),
            "expires_at_ns": (self.env.now_ns().await? + 60_000_000_000).to_string()}))
    }

    async fn withdraw(
        &self,
        dest: u32,
        amount: u128,
        q: &str,
        sig: &str,
    ) -> anyhow::Result<ExecutionFinalResult> {
        let args = self.withdraw_args(dest, self.env.wrap.id(), amount, q, sig).await?;
        self.device("withdraw_cross_chain", args).await
    }

    /// Signs `m` with the test 1Click key and withdraws `amount` wNEAR to dest 0.
    async fn signed_withdraw(
        &self,
        amount: u128,
        m: &Map<String, Value>,
    ) -> anyhow::Result<ExecutionFinalResult> {
        let s = stable(m);
        self.withdraw(0, amount, &s, &sign(&test_key(), &s)).await
    }

    async fn credited(&self, deposit: &str) -> anyhow::Result<u128> {
        let v: String = self
            .env
            .worker
            .view(&self.intents, "mt_balance_of")
            .args_json(json!({"account_id": deposit, "token_id": format!("nep141:{}", self.env.wrap.id())}))
            .await?
            .json()?;
        Ok(v.parse()?)
    }

    async fn wday(&self) -> anyhow::Result<Value> {
        Ok(self.env.worker.view(&self.u.account, "get_withdraw_day").await?.json()?)
    }
}

/// intents.near: real mainnet code, fresh state, registered on wrap.
async fn install_intents(env: &Env) -> anyhow::Result<AccountId> {
    let c = install_mainnet(&env.worker, "intents.near").await?;
    ok(c
        .call("new")
        .args_json(json!({"config": {"wnear_id": env.wrap.id(), "fees": {"fee": 0, "fee_collector": env.fees.id()}, "roles": {}}}))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?)?;
    ok(env
        .root
        .call(env.wrap.id(), "storage_deposit")
        .args_json(json!({"account_id": c.id()}))
        .deposit(NearToken::from_millinear(125))
        .transact()
        .await?)?;
    Ok(c.id().clone())
}

async fn wrap(env: &Env, u: &User, amount: u128) -> anyhow::Result<()> {
    ok(env
        .exec(&u.device, &u.account, json!([{"NearDeposit": {"amount": amount.to_string()}}]), "wrap", amount)
        .await?)
}

#[tokio::test]
async fn intents_device_path() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let intents = install_intents(&env).await?;
    let u = env.user("ix", 8 * NEAR, (5 * NEAR, 5 * NEAR)).await?;
    let c = Ctx { env: &env, u: &u, intents: intents.clone(), n: Default::default() };
    let ta = u.account.clone();
    let now = env.now_ns().await?;
    let (lq, lsig) = live("quote-live-wd-intents");

    // ---- config (owner only) ----
    fails_with(&c.withdraw(0, NEAR, &lq, &lsig).await?, "E_ONECLICK_UNSET");
    for bad in [
        json!({"keys": [], "max_slippage_bps": 100}),
        json!({"keys": [MANAGER], "max_slippage_bps": 301}),
        json!({"keys": ["ed25519:abc"], "max_slippage_bps": 100}),
        json!({"keys": [MANAGER, MANAGER, MANAGER, MANAGER], "max_slippage_bps": 100}),
    ] {
        fails_with(&c.owner("owner_set_oneclick_config", bad).await?, "E_BAD_ONECLICK");
    }
    let cfg = |keys: Vec<String>| json!({"keys": keys, "max_slippage_bps": 300, "intents": intents});
    ok(c.owner("owner_set_oneclick_config", cfg(vec![MANAGER.into()])).await?)?;
    let stranger = sub(&env.root, "stranger", NEAR).await?;
    fails_with(
        &stranger
            .call(&ta, "owner_set_oneclick_config")
            .args_json(cfg(vec![pk_str(&test_key())]))
            .deposit(NearToken::from_yoctonear(1))
            .transact()
            .await?,
        "E_NOT_OWNER",
    );
    let got: Value = env.worker.view(&ta, "get_oneclick_config").await?.json()?;
    assert_eq!(got["keys"], json!([MANAGER]));

    // ---- destinations: owner adds (1h delay), device may only remove ----
    let add = |label: &str, rt: &str| json!({"label": label, "asset": SOL, "recipient": SOL_RCPT, "recipient_type": rt});
    let r = c.owner("owner_add_withdraw_destination", add("sol", "DESTINATION_CHAIN")).await?;
    assert_eq!(okr(r)?.json::<u32>()?, 0);
    fails_with(&c.owner("owner_add_withdraw_destination", add("", "DESTINATION_CHAIN")).await?, "E_BAD_DEST");
    fails_with(&c.owner("owner_add_withdraw_destination", add("x", "EVM")).await?, "E_BAD_DEST");
    for i in 1..16 {
        ok(c.owner("owner_add_withdraw_destination", add(&format!("d{i}"), "INTENTS")).await?)?;
    }
    fails_with(&c.owner("owner_add_withdraw_destination", add("d16", "INTENTS")).await?, "E_DEST_LIMIT");
    for i in 1..15 {
        ok(c.owner("owner_remove_withdraw_destination", json!({"dest_id": i})).await?)?;
    }
    ok(c.device("remove_withdraw_destination", json!({"dest_id": 15})).await?)?;
    fails_with(&c.device("remove_withdraw_destination", json!({"dest_id": 15})).await?, "E_NO_DEST");
    let ds: Value = env.worker.view(&ta, "get_withdraw_destinations").await?.json()?;
    assert_eq!(ds.as_array().unwrap().len(), 1);
    assert_eq!(ds[0]["dest_id"], 0);
    assert_eq!(ds[0]["active"], false);
    let active_at: u64 = ds[0]["active_at_ns"].as_str().unwrap().parse()?;
    assert!(active_at >= now + HOUR_NS, "1h activation delay");
    // inactive for the first hour
    fails_with(&c.withdraw(0, NEAR, &lq, &lsig).await?, "E_DEST_INACTIVE");
    fails_with(&c.withdraw(9, NEAR, &lq, &lsig).await?, "E_DEST_INACTIVE");
    // the device cannot add destinations (not in its key's method list)
    let r =
        u.device.call(&ta, "owner_add_withdraw_destination").args_json(add("x", "INTENTS")).transact().await;
    assert!(format!("{r:?}").contains("MethodNameMismatch"));

    // ---- one hour later ----
    while env.now_ns().await? < active_at {
        env.worker.fast_forward(2_000).await?;
    }
    let ds: Value = env.worker.view(&ta, "get_withdraw_destinations").await?.json()?;
    assert_eq!(ds[0]["active"], true);
    wrap(&env, &u, 4 * NEAR).await?;
    let trading_spent = env.day_spent(&u).await?;

    // ---- live 1Click signature vectors (manager key) ----
    // genuine signature, but refund goes to alice.near via INTENTS -> signature passes, checks fail
    fails_with(&c.withdraw(0, NEAR, &lq, &lsig).await?, "E_QUOTE_MISMATCH");
    // tampered live quote (recipient swapped)
    let tampered = lq.replace(SOL_RCPT, "AttackerSo1ana1111111111111111111111111111111");
    fails_with(&c.withdraw(0, NEAR, &tampered, &lsig).await?, "E_QUOTE_SIG");
    // every other live vector's signature on this payload
    for v in vectors().iter().filter(|v| v["name"] != "quote-live-wd-intents").take(3) {
        fails_with(&c.withdraw(0, NEAR, &lq, v["signature"].as_str().unwrap()).await?, "E_QUOTE_SIG");
    }
    // our test key's quotes are rejected while only the manager key is configured (wrong key)
    let now = env.now_ns().await?;
    let good = quote(&ta, NEAR, &addr(1), now + HOUR_NS);
    fails_with(&c.signed_withdraw(NEAR, &good).await?, "E_QUOTE_SIG");
    // rotation: manager + test key
    ok(c.owner("owner_set_oneclick_config", cfg(vec![MANAGER.into(), pk_str(&test_key())])).await?)?;

    // ---- signed but mismatching: each field ----
    let mismatches: Vec<(&str, Value)> = vec![
        ("recipient", "AttackerSo1ana1111111111111111111111111111111".into()),
        ("destinationAsset", "nep141:eth.omft.near".into()),
        ("recipientType", "INTENTS".into()),
        ("refundTo", stranger.id().to_string().into()),
        ("refundType", "INTENTS".into()),
        ("amount", (NEAR - 1).to_string().into()),
        ("originAsset", "nep141:usdc.near".into()),
        ("depositType", "ORIGIN_CHAIN".into()),
        ("swapType", "FLEX_INPUT".into()),
        ("dry", true.into()),
        ("slippageTolerance", 301.into()),
        ("minAmountOut", "0".into()),
        ("depositAddress", stranger.id().to_string().into()),
        ("customRecipientMsg", "{}".into()),
        ("depositMemo", "1".into()),
        ("virtualChainRecipient", "x".into()),
    ];
    for (k, v) in mismatches {
        let mut m = good.clone();
        m.insert(k.into(), v);
        let r = c.signed_withdraw(NEAR, &m).await?;
        assert!(format!("{:?}", r.failures()).contains("E_QUOTE_MISMATCH"), "{k}: {:?}", r.failures());
    }
    // signed, then tampered: each checked field
    let s = stable(&good);
    let sig = sign(&test_key(), &s);
    for (from, to) in
        [(SOL_RCPT, "Attacker"), (&*ta.to_string(), "stranger.test.near"), (&*addr(1), &*addr(2))]
    {
        fails_with(&c.withdraw(0, NEAR, &s.replace(from, to), &sig).await?, "E_QUOTE_SIG");
    }
    // expired: deadline within the 60 s lead
    let now = env.now_ns().await?;
    fails_with(
        &c.signed_withdraw(NEAR, &quote(&ta, NEAR, &addr(3), now + 30_000_000_000)).await?,
        "E_QUOTE_EXPIRED",
    );
    fails_with(
        &c.signed_withdraw(NEAR, &quote(&ta, NEAR, &addr(3), now - HOUR_NS)).await?,
        "E_QUOTE_EXPIRED",
    );
    // the owner's methods need the owner; the device's need the device
    fails_with(
        &stranger
            .call(&ta, "withdraw_cross_chain")
            .args_json(c.withdraw_args(0, env.wrap.id(), NEAR, &s, &sig).await?)
            .transact()
            .await?,
        "E_NOT_SELF",
    );
    assert_eq!(c.credited(&addr(1)).await?, 0);
    assert_eq!(c.wday().await?["spent_yocto"], "0", "failed attempts leave the window untouched");

    // ---- valid: funds reach intents.near credited to the 1Click deposit address ----
    let w_before = env.ft_balance(env.wrap.id(), &ta).await?;
    let r = c.withdraw(0, NEAR, &s, &sig).await?;
    ok(r.clone())?;
    let ev = events(&r, "intents_withdraw");
    assert_eq!(ev.len(), 1, "{:?}", r.logs());
    assert_eq!(ev[0]["used"], NEAR.to_string());
    assert_eq!(ev[0]["dest_id"], 0);
    assert_eq!(ev[0]["deposit_address"], addr(1));
    assert_eq!(c.credited(&addr(1)).await?, NEAR);
    // invariant 11: exactly `amount` left, all of it to intents.near for the signed address
    assert_eq!(w_before - env.ft_balance(env.wrap.id(), &ta).await?, NEAR);
    assert!(r.receipt_outcomes().iter().all(|o| {
        let e = o.executor_id.as_str();
        e == ta.as_str() || e == env.wrap.id().as_str() || e == intents.as_str()
    }));
    // separate window: amount + prepaid gas bound; the trading window is untouched
    let gas = 100 * TGAS as u128 * 200_000_000;
    assert_eq!(c.wday().await?["spent_yocto"], (NEAR + gas).to_string());
    assert_eq!(c.wday().await?["cap_yocto"], (5 * NEAR).to_string(), "default = trading daily cap");
    assert_eq!(env.day_spent(&u).await?, trading_spent);
    // no on-chain platform fee (decision 2: 1Click appFees)
    assert!(r.receipt_outcomes().iter().all(|o| o.executor_id != *env.fees.id()));

    // ---- exactly-once: replay and concurrent submissions of one quote ----
    fails_with(&c.withdraw(0, NEAR, &s, &sig).await?, "E_QUOTE_REPLAY");
    let s2 = stable(&quote(&ta, NEAR / 2, &addr(4), env.now_ns().await? + HOUR_NS));
    let sig2 = sign(&test_key(), &s2);
    let (a1, a2, a3) = (
        c.withdraw_args(0, env.wrap.id(), NEAR / 2, &s2, &sig2).await?,
        c.withdraw_args(0, env.wrap.id(), NEAR / 2, &s2, &sig2).await?,
        c.withdraw_args(0, env.wrap.id(), NEAR / 2, &s2, &sig2).await?,
    );
    let call = |a: Value| {
        u.device.call(&ta, "withdraw_cross_chain").args_json(a).gas(Gas::from_tgas(100)).transact()
    };
    let (r1, r2, r3) = tokio::join!(call(a1), call(a2), call(a3));
    let rs = [r1?, r2?, r3?];
    assert_eq!(rs.iter().filter(|r| r.is_success()).count(), 1);
    for r in rs.iter().filter(|r| !r.is_success()) {
        fails_with(r, "E_QUOTE_REPLAY");
    }
    assert_eq!(c.credited(&addr(4)).await?, NEAR / 2);

    // ---- withdraw cap (owner-adjustable) ----
    fails_with(
        &c.signed_withdraw(4 * NEAR, &quote(&ta, 4 * NEAR, &addr(5), env.now_ns().await? + HOUR_NS)).await?,
        "E_WITHDRAW_CAP",
    );
    ok(c.owner("owner_set_withdraw_cap", json!({"daily_cap_yocto": (10 * NEAR).to_string()})).await?)?;
    assert_eq!(c.wday().await?["cap_yocto"], (10 * NEAR).to_string());
    fails_with(
        &stranger
            .call(&ta, "owner_set_withdraw_cap")
            .args_json(json!({"daily_cap_yocto": "1"}))
            .deposit(NearToken::from_yoctonear(1))
            .transact()
            .await?,
        "E_NOT_OWNER",
    );

    // ---- refund path: the transfer fails -> used 0 -> the amount returns to the window ----
    ok(c.owner(
        "owner_set_oneclick_config",
        json!({"keys": [pk_str(&test_key())], "max_slippage_bps": 300, "intents": "nobody.test.near"}),
    )
    .await?)?;
    let before: u128 = c.wday().await?["spent_yocto"].as_str().unwrap().parse()?;
    let r = c.signed_withdraw(NEAR, &quote(&ta, NEAR, &addr(6), env.now_ns().await? + HOUR_NS)).await?;
    let ev = events(&r, "intents_withdraw");
    assert_eq!(ev[0]["used"], "0", "{:?}", r.logs());
    let after: u128 = c.wday().await?["spent_yocto"].as_str().unwrap().parse()?;
    assert_eq!(after - before, gas, "only the gas bound stays counted");
    assert_eq!(env.ft_balance(env.wrap.id(), &ta).await?, w_before - NEAR - NEAR / 2, "refunded");
    Ok(())
}

/// Owner path (any deposit address, uncapped) and the v1.3.2 -> v1.4 upgrade (state kept, old
/// device keys lack the new methods until the owner re-adds them).
#[tokio::test]
async fn intents_owner_path_and_upgrade() -> anyhow::Result<()> {
    let env = Env::new_with(Some(out("trading_account_v1_3_2")), Some(out("factory_v1_3_2"))).await?;
    let intents = install_intents(&env).await?;
    let u = env.user("iu", 5 * NEAR, (2 * NEAR, 3 * NEAR)).await?;
    let ta = u.account.clone();
    wrap(&env, &u, 2 * NEAR).await?;
    let spent = env.day_spent(&u).await?;
    assert_eq!(env.config(&ta).await?["version"], "1.3.2");
    let v14 = env.deploy_global(out("trading_account")).await?;
    ok(u.owner
        .call(&ta, "owner_upgrade")
        .args_json(json!({"code_hash": v14}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?)?;
    assert_eq!(env.config(&ta).await?["version"], "1.4.6");
    assert_eq!(env.day_spent(&u).await?, spent);
    let c = Ctx { env: &env, u: &u, intents: intents.clone(), n: Default::default() };
    assert_eq!(env.worker.view(&ta, "get_oneclick_config").await?.json::<Option<Value>>()?, None);
    assert_eq!(c.wday().await?["cap_yocto"], (3 * NEAR).to_string());

    // owner path: any 64-hex deposit address, no quote, default verifier = intents.near
    fails_with(
        &c.owner(
            "owner_withdraw_via_intents",
            json!({"token": env.wrap.id(), "amount": "1", "deposit_address": "alice.near"}),
        )
        .await?,
        "E_BAD_DEPOSIT_ADDRESS",
    );
    let stranger = sub(&env.root, "stranger", NEAR).await?;
    fails_with(
        &stranger
            .call(&ta, "owner_withdraw_via_intents")
            .args_json(json!({"token": env.wrap.id(), "amount": "1", "deposit_address": addr(9)}))
            .deposit(NearToken::from_yoctonear(1))
            .transact()
            .await?,
        "E_NOT_OWNER",
    );
    let r = c
        .owner(
            "owner_withdraw_via_intents",
            json!({"token": env.wrap.id(), "amount": NEAR.to_string(), "deposit_address": addr(9)}),
        )
        .await?;
    ok(r.clone())?;
    assert_eq!(events(&r, "intents_withdraw")[0]["used"], NEAR.to_string());
    assert_eq!(c.credited(&addr(9)).await?, NEAR);
    assert_eq!(c.wday().await?["spent_yocto"], "0", "owner path is uncapped");

    // old device key: the new device methods are not in its method list
    let r =
        u.device.call(&ta, "remove_withdraw_destination").args_json(json!({"dest_id": 0})).transact().await;
    assert!(format!("{r:?}").contains("MethodNameMismatch"));
    let sk = SecretKey::from_random(KeyType::ED25519);
    ok(u.owner
        .call(&ta, "owner_add_key")
        .args_json(json!({"public_key": sk.public_key(), "kind": "FunctionCall"}))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?)?;
    let dev2 = Account::from_secret_key(ta.clone(), sk, &env.worker);
    ok(c.owner(
        "owner_add_withdraw_destination",
        json!({"label": "sol", "asset": SOL, "recipient": SOL_RCPT, "recipient_type": "DESTINATION_CHAIN"}),
    )
    .await?)?;
    ok(dev2.call(&ta, "remove_withdraw_destination").args_json(json!({"dest_id": 0})).transact().await?)?;
    // keys added by v1.4 carry the new methods
    let keys = env.access_keys(&ta).await?;
    assert!(keys.iter().any(|k| k.to_string().contains("withdraw_cross_chain")), "{keys:?}");
    Ok(())
}

// ======================= v1.4.1: audit B1 / B2-H2 regressions =======================
// Each is RED on v1.4.0 (d934ca0; NT_ACCOUNT_WASM=out/trading_account_v1_4_0.wasm
// NT_FACTORY_WASM=out/factory_v1_4_0.wasm) and GREEN on v1.4.1. Evidence: audit-evidence/b1/.

/// Configured account (test 1Click key) with an active SOL destination 0 and 4 NEAR wrapped.
async fn b1_setup(env: &Env, name: &str) -> anyhow::Result<(User, AccountId)> {
    let intents = install_intents(env).await?;
    let u = env.user(name, 8 * NEAR, (5 * NEAR, 5 * NEAR)).await?;
    let own = |m: &'static str, a: Value| {
        u.owner
            .call(&u.account, m)
            .args_json(a)
            .deposit(NearToken::from_yoctonear(1))
            .gas(Gas::from_tgas(100))
            .transact()
    };
    ok(own(
        "owner_set_oneclick_config",
        json!({"keys": [pk_str(&test_key())], "max_slippage_bps": 300, "intents": intents}),
    )
    .await?)?;
    ok(own(
        "owner_add_withdraw_destination",
        json!({"label": "sol", "asset": SOL, "recipient": SOL_RCPT, "recipient_type": "DESTINATION_CHAIN"}),
    )
    .await?)?;
    ok(own("owner_add_withdraw_destination", json!({"label": "btc", "asset": "nep141:btc.omft.near", "recipient": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "recipient_type": "DESTINATION_CHAIN"})).await?)?;
    let active_at = env.now_ns().await? + HOUR_NS;
    while env.now_ns().await? < active_at {
        env.worker.fast_forward(2_000).await?;
    }
    wrap(env, &u, 4 * NEAR).await?;
    Ok((u, intents))
}

/// B1-M1: (a) a genuine quote that hides ~4.75 % unsigned appFees shows as signed USD loss ->
/// E_QUOTE_LOSS; (b) a non-wNEAR token worth $5M is bounded by the USD daily cap.
#[tokio::test]
async fn b1_m1_loss_bound_and_usd_cap() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let (u, intents) = b1_setup(&env, "bm1").await?;
    let c = Ctx { env: &env, u: &u, intents, n: Default::default() };
    let ta = u.account.clone();
    let now = env.now_ns().await?;
    let mut m = quote(&ta, NEAR, &addr(20), now + HOUR_NS);
    m["amountInUsd"] = "4.980000000000".into();
    m["amountOutUsd"] = "4.743450000000".into(); // 475 bps less
    fails_with(&c.signed_withdraw(NEAR, &m).await?, "E_QUOTE_LOSS");
    // the same quote without the skim is funded
    let good = quote(&ta, NEAR, &addr(21), now + HOUR_NS);
    ok(c.signed_withdraw(NEAR, &good).await?)?;
    // 5M USDC (6 decimals) signed at $5M: over the default $1,000 USD cap, not wNEAR-counted
    let usdc: AccountId = "usdc.test.near".parse()?;
    let mut m = quote(&ta, 5_000_000_000_000, &addr(22), now + HOUR_NS);
    m["originAsset"] = format!("nep141:{usdc}").into();
    m["amountInUsd"] = "5000000.000000000000".into();
    m["amountOutUsd"] = "4999000.000000000000".into();
    let s = stable(&m);
    let args = c.withdraw_args(0, &usdc, 5_000_000_000_000, &s, &sign(&test_key(), &s)).await?;
    fails_with(&c.device("withdraw_cross_chain", args).await?, "E_WITHDRAW_CAP");
    let d = c.wday().await?;
    assert_eq!(d["cap_usd"], "1000000000");
    assert_eq!(d["spent_usd"], "4980000", "the funded $4.98 quote");
    Ok(())
}

/// B2-H2: 1Click signs `1cs_v1:btc:native:coin` for `nep141:btc.omft.near`; a destination
/// registered in the request form must still match.
#[tokio::test]
async fn b2_h2_btc_destination() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let (u, intents) = b1_setup(&env, "bh2").await?;
    let c = Ctx { env: &env, u: &u, intents, n: Default::default() };
    let now = env.now_ns().await?;
    let mut m = quote(&u.account, 2 * NEAR, &addr(30), now + HOUR_NS);
    m["destinationAsset"] = "1cs_v1:btc:native:coin".into();
    m["recipient"] = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".into();
    // BTC's network fee shows as signed USD loss: a $25 BTC quote loses 5.6 % -> needs size
    m["amountInUsd"] = "100.000000000000".into();
    m["amountOutUsd"] = "99.600000000000".into(); // 40 bps (default bound 50, v1.4.2)
    let s = stable(&m);
    ok(c.withdraw(1, 2 * NEAR, &s, &sign(&test_key(), &s)).await?)?;
    assert_eq!(c.credited(&addr(30)).await?, 2 * NEAR);
    // registering the signed form directly also works
    ok(c.owner("owner_add_withdraw_destination", json!({"label": "zec", "asset": "1cs_v1:sol:spl:A7bdiYdS5GjqGFtxf17", "recipient": SOL_RCPT, "recipient_type": "DESTINATION_CHAIN"})).await?)?;
    Ok(())
}

/// B1-L1 (upgrade path): re-adding an existing device key gives it the current method list.
#[tokio::test]
async fn b1_l1_readd_existing_key_updates_methods() -> anyhow::Result<()> {
    let env = Env::new_with(Some(out("trading_account_v1_3_2")), Some(out("factory_v1_3_2"))).await?;
    let u = env.user("bl1", 3 * NEAR, (NEAR, 2 * NEAR)).await?;
    let v = env
        .deploy_global(
            std::env::var("NT_ACCOUNT_WASM")
                .map(|p| std::fs::read(p).unwrap())
                .unwrap_or_else(|_| out("trading_account")),
        )
        .await?;
    ok(u.owner
        .call(&u.account, "owner_upgrade")
        .args_json(json!({"code_hash": v}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?)?;
    let pk = u.device_sk.public_key();
    let r = u
        .owner
        .call(&u.account, "owner_add_key")
        .args_json(json!({"public_key": pk, "kind": "FunctionCall"}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?;
    // the first AddKey fails by design (key exists); the callback replaces it
    assert!(r.is_success(), "{:?}", r.failures());
    let keys = env.access_keys(&u.account).await?;
    assert_eq!(keys.len(), 1);
    let methods = keys[0]["access_key"]["permission"]["FunctionCall"]["method_names"].to_string();
    assert!(methods.contains("withdraw_cross_chain"), "key not updated: {methods}");
    assert!(
        events(&r, "device_key_added").iter().any(|e| e["replaced"] == true && e["ok"] == true),
        "{:?}",
        r.logs()
    );
    Ok(())
}

/// B1-L2: value credited to the account INSIDE intents.near (e.g. a 1Click refund for an
/// INTENTS deposit) comes back to the account (device path, to self only).
#[tokio::test]
async fn b1_l2_pull_back_from_intents() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let (u, intents) = b1_setup(&env, "bl2").await?;
    let c = Ctx { env: &env, u: &u, intents: intents.clone(), n: Default::default() };
    let ta = u.account.clone();
    // a refund credited to the TA inside the verifier (what 1Click's refund to an intents
    // account looks like): anyone's ft_transfer_call{msg: "<ta>"}
    let refunder = sub(&env.root, "refunder", 5 * NEAR).await?;
    ok(refunder
        .call(env.wrap.id(), "near_deposit")
        .args_json(json!({}))
        .deposit(NearToken::from_near(2))
        .transact()
        .await?)?;
    ok(refunder
        .call(env.wrap.id(), "ft_transfer_call")
        .args_json(json!({"receiver_id": intents, "amount": NEAR.to_string(), "msg": ta.to_string()}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?)?;
    assert_eq!(c.credited(ta.as_str()).await?, NEAR);
    let before = env.ft_balance(env.wrap.id(), &ta).await?;
    let r = c
        .device("withdraw_from_intents", json!({"token": env.wrap.id(), "amount": NEAR.to_string()}))
        .await?;
    assert!(r.is_success() && r.receipt_failures().is_empty(), "{:?}", r.failures());
    assert_eq!(env.ft_balance(env.wrap.id(), &ta).await? - before, NEAR);
    assert_eq!(c.credited(ta.as_str()).await?, 0);
    // owner path too
    ok(refunder
        .call(env.wrap.id(), "ft_transfer_call")
        .args_json(json!({"receiver_id": intents, "amount": (NEAR / 2).to_string(), "msg": ta.to_string()}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?)?;
    ok(c.owner(
        "owner_withdraw_from_intents",
        json!({"token": env.wrap.id(), "amount": (NEAR / 2).to_string()}),
    )
    .await?)?;
    assert_eq!(env.ft_balance(env.wrap.id(), &ta).await? - before, NEAR + NEAR / 2);
    Ok(())
}

/// B1-L3: replay markers are pruned after the signed deadline + 1 h: storage returns.
#[tokio::test]
async fn b1_l3_markers_pruned() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let (u, intents) = b1_setup(&env, "bl3").await?;
    let c = Ctx { env: &env, u: &u, intents, n: Default::default() };
    let ta = u.account.clone();
    let storage = || async { anyhow::Ok(env.worker.view_account(&ta).await?.storage_usage) };
    let now = env.now_ns().await?;
    for i in 0..3 {
        ok(c.signed_withdraw(NEAR / 10, &quote(&ta, NEAR / 10, &addr(40 + i), now + 90_000_000_000)).await?)?;
    }
    let with3 = storage().await?;
    let until = env.now_ns().await? + 2 * HOUR_NS;
    while env.now_ns().await? < until {
        env.worker.fast_forward(2_000).await?;
    }
    let now = env.now_ns().await?;
    ok(c.signed_withdraw(NEAR / 10, &quote(&ta, NEAR / 10, &addr(50), now + HOUR_NS)).await?)?;
    let after = storage().await?;
    assert!(after < with3, "markers pruned: {with3} -> {after}");
    let used: bool = env
        .worker
        .view(&ta, "is_deposit_address_used")
        .args_json(json!({"deposit_address": addr(40)}))
        .await?
        .json()?;
    assert!(!used);
    Ok(())
}

// ======================= v1.4.2: re-audit C1 L1/L2 (RED on v1.4.1) =======================

/// C1-L1: default max_loss_bps is 50 (was 100): a 60 bps signed loss is refused by default.
/// C1-L2: a quote issued > 1 h ago is refused (E_QUOTE_DEADLINE) even with a 72 h deadline.
#[tokio::test]
async fn c1_l1_l2_default_loss_and_freshness() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let (u, intents) = b1_setup(&env, "cl2").await?;
    let c = Ctx { env: &env, u: &u, intents, n: Default::default() };
    let ta = u.account.clone();
    let cfg: Value = env.worker.view(&ta, "get_oneclick_config").await?.json()?;
    assert_eq!(cfg["max_loss_bps"], 50);
    let now = env.now_ns().await?;
    let mut m = quote(&ta, NEAR, &addr(60), now + HOUR_NS);
    m["amountInUsd"] = "100.000000000000".into();
    m["amountOutUsd"] = "99.400000000000".into(); // 60 bps
    fails_with(&c.signed_withdraw(NEAR, &m).await?, "E_QUOTE_LOSS");
    // a genuine-looking quote with the usual +72 h signed deadline, issued 2 h ago
    let mut m = quote(&ta, NEAR, &addr(61), now + 72 * HOUR_NS);
    m["timestamp"] = iso(now - 2 * HOUR_NS).into();
    fails_with(&c.signed_withdraw(NEAR, &m).await?, "E_QUOTE_DEADLINE");
    // issued now: fine
    let mut m = quote(&ta, NEAR, &addr(62), now + 72 * HOUR_NS);
    m["timestamp"] = iso(env.now_ns().await?).into();
    ok(c.signed_withdraw(NEAR, &m).await?)?;
    Ok(())
}
