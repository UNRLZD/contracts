//! TA 1.6.0 owner signatures on a real chain (docs/owner-v16-spec.md §4–§5): every owner op
//! through `owner_signed` via every standard its owner kind signs with, the negative matrix,
//! home withdraws into the REAL mainnet intents.near wasm, the factory-approved signed upgrade
//! with the old-code guard, migrate from pre-1.6 code, and gas per arm.
use integration_tests::*;
use near_workspaces::types::{Gas, KeyType, NearToken, SecretKey};
use near_workspaces::{Account, AccountId, Contract};
use owner_auth::testkit::{with_high_s, with_v27, BodySpec, Signer};
use owner_auth::{MultiPayload, Standard};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};

/// mainnet intents.near 0.4.2 (near/intents fa44ede9), the pinned fixture (factory_v13.rs).
const INTENTS_HASH: &str = "HUJ89jxFhsXF17XS8L5kmxz7te8AKfdWw2xzrVYo7aoj";
const MANAGER: &str = "ed25519:reYaWhvwu8Jzo3WUM3zhn6VrhuMEF4eADL17qtRVifc";
const TA_FUND: u128 = 30 * NEAR;

static RND: AtomicU64 = AtomicU64::new(1);

fn wasm(var: &str, fallback: &str) -> Vec<u8> {
    std::env::var(var).ok().map(|p| std::fs::read(p).expect(var)).unwrap_or_else(|| out(fallback))
}

struct Ctx {
    env: Env,
    intents: Contract,
    relayer: Account,
    bob: Account,
}

async fn setup() -> anyhow::Result<Ctx> {
    let env = Env::new().await?;
    let p = format!("{}/fixtures/intents/intents.near.wasm", env!("CARGO_MANIFEST_DIR"));
    let code = std::fs::read(&p)?;
    assert_eq!(code_hash(&code), INTENTS_HASH);
    let intents = install_code(&env.worker, "intents.near", &code).await?;
    let root = env.root.id();
    ok(intents
        .call("new")
        .args_json(
            json!({"config": {"wnear_id": env.wrap.id(), "fees": {"fee": 0, "fee_collector": env.fees.id()},
            "roles": {"super_admins": [root], "admins": {}, "grantees": {}}}}),
        )
        .gas(Gas::from_tgas(100))
        .transact()
        .await?)?;
    for a in [intents.id(), env.root.id()] {
        ok(env
            .root
            .call(env.wrap.id(), "storage_deposit")
            .args_json(json!({"account_id": a}))
            .deposit(NearToken::from_millinear(125))
            .transact()
            .await?)?;
    }
    ok(env
        .root
        .call(env.wrap.id(), "near_deposit")
        .args_json(json!({}))
        .deposit(NearToken::from_near(100))
        .transact()
        .await?)?;
    let relayer = sub(&env.root, "relayer", 50 * NEAR).await?;
    let bob = sub(&env.root, "bob", NEAR).await?;
    Ok(Ctx { env, intents, relayer, bob })
}

impl Ctx {
    /// A TA for a signer-kind owner at `<label>.<factory>` (its parent is the factory, as a
    /// factory-created account's is), initialised as factory 1.3.0 would (`owner_auth`).
    async fn signer_ta(&self, label: &str, s: &Signer, home: &str) -> anyhow::Result<AccountId> {
        let f = self.env.factory.id();
        assert!(self
            .env
            .root
            .transfer_near(f, NearToken::from_yoctonear(TA_FUND + NEAR))
            .await?
            .is_success());
        let acc = self
            .env
            .factory
            .as_account()
            .create_subaccount(label)
            .initial_balance(NearToken::from_yoctonear(TA_FUND))
            .transact()
            .await?
            .into_result()?;
        let c = acc.deploy(&wasm("NT_ACCOUNT_WASM", "trading_account")).await?.into_result()?;
        let kind = serde_json::to_value(s.kind())?;
        ok(c.call("init")
            .args_json(json!({
                "owner": s.owner_id(),
                "fee_config": {"fee_bps": FEE_BPS, "fee_recipient": self.env.fees.id()},
                "caps": caps_json((100 * NEAR, 100 * NEAR)),
                "dex_allowlist": [
                    {"id": self.env.rhea.id(), "kind": "RheaClassic"},
                    {"id": self.env.dcl.id(), "kind": "RheaDcl"},
                    {"id": self.env.plach.id(), "kind": "Plach"},
                ],
                "wrap": self.env.wrap.id(),
                "automation": null,
                "owner_auth": {"kind": kind, "home": home},
            }))
            .gas(Gas::from_tgas(300))
            .transact()
            .await?)?;
        Ok(c.id().clone())
    }

    async fn owner_auth(&self, acc: &AccountId) -> anyhow::Result<Value> {
        Ok(self.env.worker.view(acc, "get_owner_auth").await?.json()?)
    }

    async fn salt(&self, acc: &AccountId) -> anyhow::Result<[u8; 4]> {
        let v = self.owner_auth(acc).await?;
        let s = v["salt"].as_str().unwrap();
        Ok(std::array::from_fn(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()))
    }

    /// `ops` signed by `s` with `std` for `vc` (the TA id unless a negative case), fresh nonce,
    /// deadline `now + ttl_s` (seconds, may be negative).
    #[allow(clippy::too_many_arguments)]
    async fn sign_for(
        &self,
        s: &Signer,
        std: Standard,
        acc: &AccountId,
        vc: &str,
        signer_id: &str,
        ops: &Value,
        ttl_s: i64,
    ) -> anyhow::Result<MultiPayload> {
        let now = self.env.now_ns().await? as i64;
        let dl = ((now + ttl_s * 1_000_000_000) / 1_000_000 * 1_000_000) as u64;
        let r = RND.fetch_add(1, Ordering::SeqCst).to_le_bytes();
        let mut rnd = [0u8; 15];
        rnd[..8].copy_from_slice(&r);
        let salt = self.salt(acc).await?;
        Ok(s.sign_ops(
            std,
            &BodySpec {
                signer_id: signer_id.into(),
                verifying_contract: vc.into(),
                deadline_ns: dl,
                nonce: owner_auth::versioned_nonce(salt, dl, rnd),
                items_json: ops.to_string(),
            },
        ))
    }

    async fn sign(
        &self,
        s: &Signer,
        std: Standard,
        acc: &AccountId,
        ops: Value,
    ) -> anyhow::Result<MultiPayload> {
        self.sign_for(s, std, acc, acc.as_str(), &s.owner_id(), &ops, 600).await
    }

    async fn submit_gas(
        &self,
        acc: &AccountId,
        mp: &MultiPayload,
        tgas: u64,
    ) -> anyhow::Result<near_workspaces::result::ExecutionFinalResult> {
        Ok(self
            .relayer
            .call(acc, "owner_signed")
            .args_json(json!({"signed": mp}))
            .gas(Gas::from_tgas(tgas))
            .transact()
            .await?)
    }

    async fn submit(
        &self,
        acc: &AccountId,
        mp: &MultiPayload,
    ) -> anyhow::Result<near_workspaces::result::ExecutionFinalResult> {
        self.submit_gas(acc, mp, 300).await
    }

    /// Signs and submits one op; the whole tx (every receipt) must succeed.
    async fn run(&self, s: &Signer, std: Standard, acc: &AccountId, op: Value) -> anyhow::Result<()> {
        let mp = self.sign(s, std, acc, json!([op])).await?;
        let r = self.submit(acc, &mp).await?;
        okr(r).map(|_| ()).map_err(|e| anyhow::anyhow!("{op}: {e}"))
    }

    async fn intents_balance(&self, id: &str) -> anyhow::Result<u128> {
        let v: String = self
            .env
            .worker
            .view(self.intents.id(), "mt_balance_of")
            .args_json(json!({"account_id": id, "token_id": format!("nep141:{}", self.env.wrap.id())}))
            .await?
            .json()?;
        Ok(v.parse()?)
    }

    async fn give_wnear(&self, to: &AccountId, amount: u128) -> anyhow::Result<()> {
        ok(self
            .env
            .root
            .call(self.env.wrap.id(), "ft_transfer")
            .args_json(json!({"receiver_id": to, "amount": amount.to_string()}))
            .deposit(NearToken::from_yoctonear(1))
            .transact()
            .await?)
    }

    /// wNEAR credited to `id` inside intents (plain deposit, msg = id).
    async fn fund_intents(&self, id: &str, amount: u128) -> anyhow::Result<()> {
        ok(self
            .env
            .root
            .call(self.env.wrap.id(), "ft_transfer_call")
            .args_json(json!({"receiver_id": self.intents.id(), "amount": amount.to_string(), "msg": id}))
            .deposit(NearToken::from_yoctonear(1))
            .gas(Gas::from_tgas(100))
            .transact()
            .await?)
    }

    async fn has_key(&self, acc: &AccountId, pk: &str) -> anyhow::Result<bool> {
        Ok(self.env.access_keys(acc).await?.iter().any(|k| k["public_key"] == json!(pk)))
    }
}

fn logs_have(r: &near_workspaces::result::ExecutionFinalResult, needle: &str) -> bool {
    r.logs().iter().any(|l| l.contains(needle))
}

fn tgas(r: &near_workspaces::result::ExecutionFinalResult) -> (f64, f64) {
    let rs = gas_by_receipt(r);
    let first = rs.first().map_or(0.0, |x| x.1);
    (first, r.total_gas_burnt.as_gas() as f64 / 1e12)
}

/// Every owner op through `owner_signed`, signed by `s` with `std`, on a fresh signer-kind TA.
async fn every_op(label: &str, s: Signer, std: Standard, home: &str) -> anyhow::Result<()> {
    let c = setup().await?;
    let env = &c.env;
    let acc = c.signer_ta(label, &s, home).await?;
    let v = c.owner_auth(&acc).await?;
    assert_eq!(v["kind"], serde_json::to_value(s.kind())?);
    assert_eq!(v["signed_enabled"], json!(true));
    let tag = format!("{label}/{std:?}");

    // gas: single-op calls at the relayer's 100 TGas default
    let mp = c.sign(&s, std, &acc, json!([{"op": "rotate_salt"}])).await?;
    let salt0 = c.salt(&acc).await?;
    let r = okr(c.submit_gas(&acc, &mp, 100).await?)?;
    assert_ne!(c.salt(&acc).await?, salt0);
    let g_rot = tgas(&r);
    let b0 = env.near_balance(c.bob.id()).await?;
    let mp = c
        .sign(
            &s,
            std,
            &acc,
            json!([{"op": "withdraw", "token": null, "amount": NEAR.to_string(), "to": c.bob.id()}]),
        )
        .await?;
    let r = okr(c.submit_gas(&acc, &mp, 100).await?)?;
    let g_wd = tgas(&r);
    assert_eq!(env.near_balance(c.bob.id()).await? - b0, NEAR, "{tag} native withdraw");

    // add_key / remove_key (device key)
    let dev = SecretKey::from_random(KeyType::ED25519).public_key();
    let devs = pk_str(&dev);
    let mp = c.sign(&s, std, &acc, json!([{"op": "add_key", "public_key": devs}])).await?;
    let r = okr(c.submit_gas(&acc, &mp, 100).await?)?;
    let g_add = tgas(&r);
    assert!(c.has_key(&acc, &devs).await?, "{tag} add_key");
    assert!(logs_have(&r, "add_key ed25519:") && logs_have(&r, "device\""), "{tag} summary names the key");

    // caps (a decrease applies now), relayer allowance
    c.run(&s, std, &acc, json!({"op": "set_caps", "caps": caps_json((NEAR, 2 * NEAR))})).await?;
    assert_eq!(env.config(&acc).await?["caps"], caps_json((NEAR, 2 * NEAR)));
    c.run(&s, std, &acc, json!({"op": "set_relayer_allowance", "weekly_yocto": "5"})).await?;
    let w: Value = env.worker.view(&acc, "get_relayer_week").await?.json()?;
    assert_eq!(w["allowance_yocto"], json!("5"));

    // automation: set, revoke; then clear_relayer_key of a non-member fails (and the failed
    // payload's nonce stays unused: the same payload fails the same way, not E_NONCE_USED)
    let auto = SecretKey::from_random(KeyType::ED25519).public_key();
    c.run(
        &s,
        std,
        &acc,
        json!({"op": "set_automation_key", "public_key": pk_str(&auto), "allowance": NEAR.to_string()}),
    )
    .await?;
    let k: Value = env.worker.view(&acc, "get_automation_key").await?.json()?;
    assert_eq!(k, json!(pk_str(&auto)));
    c.run(&s, std, &acc, json!({"op": "revoke_automation"})).await?;
    let k: Value = env.worker.view(&acc, "get_automation_key").await?.json()?;
    assert_eq!(k, Value::Null);
    let stranger = SecretKey::from_random(KeyType::ED25519).public_key();
    let mp =
        c.sign(&s, std, &acc, json!([{"op": "clear_relayer_key", "public_key": pk_str(&stranger)}])).await?;
    fails_with(&c.submit(&acc, &mp).await?, "E_NO_KEY");
    fails_with(&c.submit(&acc, &mp).await?, "E_NO_KEY");

    // DCL storage back
    c.run(&s, std, &acc, json!({"op": "reclaim_dex_storage", "dex": env.dcl.id()})).await?;

    // withdraw destinations, 1Click config, withdraw cap
    c.run(
        &s,
        std,
        &acc,
        json!({"op": "add_withdraw_destination", "label": "sol", "asset": "nep141:sol.omft.near",
        "recipient": "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM", "recipient_type": "DESTINATION_CHAIN"}),
    )
    .await?;
    let d: Vec<Value> = env.worker.view(&acc, "get_withdraw_destinations").await?.json()?;
    assert_eq!(d.len(), 1);
    c.run(&s, std, &acc, json!({"op": "remove_withdraw_destination", "dest_id": 0})).await?;
    let d: Vec<Value> = env.worker.view(&acc, "get_withdraw_destinations").await?.json()?;
    assert!(d.is_empty());
    c.run(&s, std, &acc, json!({"op": "set_oneclick_config", "keys": [MANAGER], "max_slippage_bps": 100}))
        .await?;
    let o: Value = env.worker.view(&acc, "get_oneclick_config").await?.json()?;
    assert_eq!(o["intents"], json!("intents.near"));
    c.run(&s, std, &acc, json!({"op": "set_withdraw_cap", "daily_cap_usd": "9"})).await?;
    let wd: Value = env.worker.view(&acc, "get_withdraw_day").await?.json()?;
    assert_eq!(wd["cap_usd"], json!("9"));

    // withdraw wNEAR (unwrapped to native) and an FT
    c.give_wnear(&acc, 2 * NEAR).await?;
    let b0 = env.near_balance(c.bob.id()).await?;
    c.run(
        &s,
        std,
        &acc,
        json!({"op": "withdraw", "token": env.wrap.id(), "amount": (NEAR / 2).to_string(), "to": c.bob.id()}),
    )
    .await?;
    assert_eq!(env.near_balance(c.bob.id()).await? - b0, NEAR / 2, "{tag} wNEAR withdraw");
    ok(env.meme.call("mint").args_json(json!({"account_id": acc, "amount": "1000"})).transact().await?)?;
    c.run(&s, std, &acc, json!({"op": "withdraw", "token": env.meme.id(), "amount": "7", "to": c.bob.id()}))
        .await?;
    assert_eq!(env.ft_balance(env.meme.id(), c.bob.id()).await?, 7);

    // home: native and wNEAR land in the owner's intents balance (never a native 0x transfer)
    let owner = s.owner_id();
    let h0 = c.intents_balance(&owner).await?;
    c.run(&s, std, &acc, json!({"op": "withdraw_home", "token": null, "amount": NEAR.to_string()})).await?;
    assert_eq!(c.intents_balance(&owner).await? - h0, NEAR, "{tag} native home");
    c.run(
        &s,
        std,
        &acc,
        json!({"op": "withdraw_home", "token": env.wrap.id(), "amount": (NEAR / 4).to_string()}),
    )
    .await?;
    assert_eq!(c.intents_balance(&owner).await? - h0, NEAR + NEAR / 4, "{tag} wNEAR home");

    // intents: fund a deposit address; pull the account's own intents balance back
    let addr = owner_auth::hex(&Sha256::digest(label.as_bytes()));
    c.run(&s, std, &acc, json!({"op": "withdraw_via_intents", "token": env.wrap.id(), "amount": "1000", "deposit_address": addr}))
        .await?;
    assert_eq!(c.intents_balance(&addr).await?, 1000);
    c.fund_intents(acc.as_str(), 3000).await?;
    let w0 = env.ft_balance(env.wrap.id(), &acc).await?;
    c.run(&s, std, &acc, json!({"op": "withdraw_from_intents", "token": env.wrap.id(), "amount": "3000"}))
        .await?;
    assert_eq!(env.ft_balance(env.wrap.id(), &acc).await? - w0, 3000);

    // auth keys: a P-256 backup (or an ed25519 one for a P-256 owner) signs; implicit key off/on
    let backup = if matches!(s, Signer::P256(_)) {
        Signer::ed25519(&format!("{label}-bk"))
    } else {
        Signer::p256(&format!("{label}-bk"))
    };
    let bstd = if matches!(backup, Signer::P256(_)) { Standard::WebAuthn } else { Standard::RawEd25519 };
    let bk = backup.public_key().to_string();
    c.run(&s, std, &acc, json!({"op": "add_auth_key", "public_key": bk})).await?;
    assert_eq!(c.owner_auth(&acc).await?["auth_keys"], json!([bk]));
    let mp = c
        .sign_for(
            &backup,
            bstd,
            &acc,
            acc.as_str(),
            &owner,
            &json!([{"op": "set_implicit_key", "enabled": false}]),
            600,
        )
        .await?;
    ok(c.submit(&acc, &mp).await?)?;
    let mp = c.sign(&s, std, &acc, json!([{"op": "rotate_salt"}])).await?;
    fails_with(&c.submit(&acc, &mp).await?, "E_NOT_OWNER");
    let mp = c
        .sign_for(
            &backup,
            bstd,
            &acc,
            acc.as_str(),
            &owner,
            &json!([{"op": "set_implicit_key", "enabled": true}]),
            600,
        )
        .await?;
    ok(c.submit(&acc, &mp).await?)?;
    c.run(&s, std, &acc, json!({"op": "remove_auth_key", "public_key": bk})).await?;
    assert_eq!(c.owner_auth(&acc).await?["auth_keys"], json!([]));

    // remove the device key; then empty the account (alone in its payload)
    c.run(&s, std, &acc, json!({"op": "remove_key", "public_key": devs})).await?;
    assert!(!c.has_key(&acc, &devs).await?, "{tag} remove_key");
    // signed upgrade to the factory-approved code
    let v2 = env.deploy_global(wasm("NT_UPGRADE_WASM", "trading_account_upgrade_test")).await?;
    ok(env
        .admin
        .call(env.factory.id(), "set_code_hash")
        .args_json(json!({"code_hash": v2, "signed_code": true}))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?)?;
    c.run(&s, std, &acc, json!({"op": "upgrade", "code_hash": v2})).await?;
    assert_eq!(env.global_hash(&acc).await?, Some(v2));
    assert_eq!(env.config(&acc).await?["version"], "upgrade-test");
    assert_eq!(c.owner_auth(&acc).await?["kind"], serde_json::to_value(s.kind())?, "ow kept by migrate");
    // empty the account last (alone in its payload). The signed-path state reserve stays, so
    // the next signed calls store their nonces with no top-up.
    let m0 = env.ft_balance(env.meme.id(), c.bob.id()).await?;
    c.run(&s, std, &acc, json!({"op": "withdraw_all", "to": c.bob.id(), "tokens": [env.meme.id()]})).await?;
    env.worker.fast_forward(3).await?;
    assert_eq!(env.ft_balance(env.meme.id(), c.bob.id()).await? - m0, 993);
    assert_eq!(env.ft_balance(env.wrap.id(), &acc).await?, 0);
    for _ in 0..2 {
        c.run(&s, std, &acc, json!({"op": "rotate_salt"})).await?;
    }

    println!(
        "GAS {tag}: rotate_salt receipt {:.2} / total {:.2} TGas; withdraw native {:.2} / {:.2}; add_key {:.2} / {:.2}",
        g_rot.0, g_rot.1, g_wd.0, g_wd.1, g_add.0, g_add.1
    );
    Ok(())
}

#[tokio::test]
async fn v160_every_op_raw_ed25519() -> anyhow::Result<()> {
    every_op("sraw", Signer::ed25519("sb-raw"), Standard::RawEd25519, "Solana").await
}

#[tokio::test]
async fn v160_every_op_nep413() -> anyhow::Result<()> {
    every_op("snep", Signer::ed25519("sb-nep"), Standard::Nep413, "Near").await
}

#[tokio::test]
async fn v160_every_op_webauthn_ed25519() -> anyhow::Result<()> {
    every_op("swed", Signer::ed25519("sb-wed"), Standard::WebAuthn, "Near").await
}

#[tokio::test]
async fn v160_every_op_erc191() -> anyhow::Result<()> {
    every_op("sk1", Signer::secp256k1("sb-k1"), Standard::Erc191, "Near").await
}

#[tokio::test]
async fn v160_every_op_webauthn_p256() -> anyhow::Result<()> {
    every_op("sr1", Signer::p256("sb-r1"), Standard::WebAuthn, "Near").await
}

/// The negative matrix on chain (spec §12.3), every refusal a clean contract panic.
#[tokio::test]
async fn v160_negative_matrix_on_chain() -> anyhow::Result<()> {
    let c = setup().await?;
    let k1 = Signer::secp256k1("nm-k1");
    let r1 = Signer::p256("nm-r1");
    let ed = Signer::ed25519("nm-ed");
    let a_k1 = c.signer_ta("nk1", &k1, "Near").await?;
    let a_r1 = c.signer_ta("nr1", &r1, "Near").await?;
    let a_ed = c.signer_ta("ned", &ed, "Near").await?;
    let rot = json!([{"op": "rotate_salt"}]);
    // replay
    let mp = c.sign(&k1, Standard::Erc191, &a_k1, rot.clone()).await?;
    ok(c.submit(&a_k1, &mp).await?)?;
    fails_with(&c.submit(&a_k1, &mp).await?, "E_NONCE_SALT"); // rotate_salt voided it first
    let mp = c
        .sign(&k1, Standard::Erc191, &a_k1, json!([{"op": "set_relayer_allowance", "weekly_yocto": "7"}]))
        .await?;
    ok(c.submit(&a_k1, &mp).await?)?;
    fails_with(&c.submit(&a_k1, &mp).await?, "E_NONCE_USED");
    // cross-TA, testnet-bound, intents-bound
    let testnet = a_ed.as_str().replace(".near", ".testnet").replace(".test.", ".x.");
    for vc in [a_k1.as_str(), testnet.as_str(), "intents.near"] {
        let mp = c.sign_for(&ed, Standard::RawEd25519, &a_ed, vc, &ed.owner_id(), &rot, 600).await?;
        fails_with(&c.submit(&a_ed, &mp).await?, "E_VERIFYING_CONTRACT");
    }
    // expired; over the 15 min cap
    for (ttl, code) in [(-5, "E_DEADLINE"), (16 * 60, "E_DEADLINE")] {
        let mp = c.sign_for(&ed, Standard::Nep413, &a_ed, a_ed.as_str(), &ed.owner_id(), &rot, ttl).await?;
        fails_with(&c.submit(&a_ed, &mp).await?, code);
    }
    // secp256k1 high-s twin and v = 27: clean E_SIG (never the host's ecrecover abort)
    let mp = c.sign(&k1, Standard::Erc191, &a_k1, rot.clone()).await?;
    fails_with(&c.submit(&a_k1, &with_high_s(&mp)).await?, "E_SIG");
    fails_with(&c.submit(&a_k1, &with_v27(&mp)).await?, "E_SIG");
    // P-256 high-s, missing UV
    let mp = c.sign(&r1, Standard::WebAuthn, &a_r1, rot.clone()).await?;
    fails_with(&c.submit(&a_r1, &with_high_s(&mp)).await?, "E_HIGH_S");
    fails_with(&c.submit(&a_r1, &r1.webauthn_with(mp.text(), 0x01, "webauthn.get")).await?, "E_WEBAUTHN");
    ok(c.submit(&a_r1, &mp).await?)?;
    // wrong owner kind: a P-256 key claiming the k1 owner (both `0x`)
    let mp = c.sign_for(&r1, Standard::WebAuthn, &a_k1, a_k1.as_str(), &k1.owner_id(), &rot, 600).await?;
    fails_with(&c.submit(&a_k1, &mp).await?, "E_OWNER_KIND");
    // another key of the right curve
    let mp = c
        .sign_for(
            &Signer::ed25519("nm-other"),
            Standard::RawEd25519,
            &a_ed,
            a_ed.as_str(),
            &ed.owner_id(),
            &rot,
            600,
        )
        .await?;
    fails_with(&c.submit(&a_ed, &mp).await?, "E_NOT_OWNER");
    // a failing op reverts the nonce mark: the same payload can be sent again once it can pass
    let dev = SecretKey::from_random(KeyType::ED25519).public_key();
    let mp = c
        .sign(&ed, Standard::RawEd25519, &a_ed, json!([{"op": "remove_key", "public_key": pk_str(&dev)}]))
        .await?;
    let r = c.submit(&a_ed, &mp).await?;
    assert!(r.is_success() && !r.receipt_failures().is_empty() || r.is_failure());
    let mp2 = c
        .sign(&ed, Standard::RawEd25519, &a_ed, json!([{"op": "remove_withdraw_destination", "dest_id": 9}]))
        .await?;
    fails_with(&c.submit(&a_ed, &mp2).await?, "E_NO_DEST");
    ok(c.submit(
        &a_ed,
        &c.sign(
            &ed,
            Standard::RawEd25519,
            &a_ed,
            json!([{"op": "add_withdraw_destination", "label": "x",
        "asset": "nep141:sol.omft.near", "recipient": "r", "recipient_type": "INTENTS"}]),
        )
        .await?,
    )
    .await?)?;
    // dest 0 exists now; dest 9 still does not: the payload is still valid and unused
    fails_with(&c.submit(&a_ed, &mp2).await?, "E_NO_DEST");
    let v: Value = c.owner_auth(&a_ed).await?;
    assert!(v["nonces_live"].as_u64().unwrap() >= 1);
    Ok(())
}

/// Signed upgrade: refused unless the factory approves the hash now; code without owner
/// signatures (pre-1.6) reverts as a whole (the old-code guard); the predecessor path of a named
/// owner is unchanged.
#[tokio::test]
async fn v160_signed_upgrade_rules() -> anyhow::Result<()> {
    let c = setup().await?;
    let env = &c.env;
    let s = Signer::secp256k1("up-k1");
    let acc = c.signer_ta("up1", &s, "Near").await?;
    let v2 = env.deploy_global(wasm("NT_UPGRADE_WASM", "trading_account_upgrade_test")).await?;
    let up = |h: &str| json!([{"op": "upgrade", "code_hash": h}]);
    // not flagged signed: nothing approved
    let mp = c.sign(&s, Standard::Erc191, &acc, up(&v2)).await?;
    let r = okr(c.submit(&acc, &mp).await?)?;
    assert!(logs_have(&r, "\"reason\":\"not_approved\""), "{:?}", r.logs());
    assert_eq!(env.global_hash(&acc).await?, None);
    // flagged: another hash is still refused
    let set = |h: String| {
        env.admin
            .call(env.factory.id(), "set_code_hash")
            .args_json(json!({"code_hash": h, "signed_code": true}))
            .deposit(NearToken::from_yoctonear(1))
            .transact()
    };
    ok(set(v2.clone()).await?)?;
    let mp = c.sign(&s, Standard::Erc191, &acc, up(&env.code_hash)).await?;
    let r = okr(c.submit(&acc, &mp).await?)?;
    assert!(logs_have(&r, "not_approved"));
    assert_eq!(env.global_hash(&acc).await?, None);
    // old-code guard: pre-1.6 code approved by the factory -> the upgrade batch reverts whole
    let old = env.deploy_global(out("trading_account_v1_4_4")).await?;
    ok(set(old.clone()).await?)?;
    let mp = c.sign(&s, Standard::Erc191, &acc, up(&old)).await?;
    let r = c.submit(&acc, &mp).await?;
    assert!(logs_have(&r, "upgrade_started"));
    assert!(!r.receipt_failures().is_empty(), "the guard call must fail on old code");
    assert_eq!(env.global_hash(&acc).await?, None, "code unchanged");
    assert_eq!(env.config(&acc).await?["version"], "1.6.0");
    // approved: switches
    ok(set(v2.clone()).await?)?;
    let mp = c.sign(&s, Standard::Erc191, &acc, up(&v2)).await?;
    ok(c.submit(&acc, &mp).await?)?;
    assert_eq!(env.global_hash(&acc).await?, Some(v2));
    assert_eq!(env.config(&acc).await?["version"], "upgrade-test");
    Ok(())
}

/// Pre-1.6 accounts: `migrate` writes the owner record by the id rule. A named owner stays
/// predecessor-only; a NEAR implicit owner has signatures off until it opts in with a wallet tx.
#[tokio::test]
async fn v160_migrate_from_pre_16_code() -> anyhow::Result<()> {
    let env = Env::new_with(Some(out("trading_account_v1_4_4")), None).await?;
    let v16 = env.deploy_global(wasm("NT_ACCOUNT_WASM", "trading_account")).await?;
    let relayer = sub(&env.root, "relayer", 10 * NEAR).await?;
    // named owner
    let u = env.user("named", 2 * NEAR, (NEAR, NEAR)).await?;
    ok(u.owner
        .call(&u.account, "owner_upgrade")
        .args_json(json!({"code_hash": v16}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?)?;
    assert_eq!(env.config(&u.account).await?["version"], "1.6.0");
    let v: Value = env.worker.view(&u.account, "get_owner_auth").await?.json()?;
    assert_eq!((v["kind"].clone(), v["signed_enabled"].clone()), (json!("Named"), json!(false)));
    // NEAR implicit owner (64 hex): an implicit account created by a transfer
    let s = Signer::ed25519("mig-implicit");
    let seed: [u8; 32] = Sha256::digest(b"nt-owner-v16-test/mig-implicit").into();
    let pk = match s.public_key() {
        owner_auth::PublicKey::Ed25519(k) => k,
        _ => unreachable!(),
    };
    let sk: SecretKey =
        format!("ed25519:{}", bs58::encode([seed.as_slice(), &pk].concat()).into_string()).parse()?;
    let implicit: AccountId = s.owner_id().parse()?;
    assert!(env.root.transfer_near(&implicit, NearToken::from_near(10)).await?.is_success());
    let owner = Account::from_secret_key(implicit.clone(), sk, &env.worker);
    let dev = SecretKey::from_random(KeyType::ED25519);
    ok(owner
        .call(env.factory.id(), "create_account")
        .args_json(json!({"device_public_key": dev.public_key(), "caps": caps_json((NEAR, NEAR))}))
        .deposit(NearToken::from_near(2))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?)?;
    let acc = env.account_for(&implicit).await?;
    ok(owner
        .call(&acc, "owner_upgrade")
        .args_json(json!({"code_hash": v16}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?)?;
    let v: Value = env.worker.view(&acc, "get_owner_auth").await?.json()?;
    assert_eq!((v["kind"].clone(), v["signed_enabled"].clone()), (json!("Ed25519"), json!(false)));
    let salt = |v: &Value| -> [u8; 4] {
        let s = v["salt"].as_str().unwrap();
        std::array::from_fn(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
    };
    let body = |salt: [u8; 4], now: u64| BodySpec {
        signer_id: s.owner_id(),
        verifying_contract: acc.to_string(),
        deadline_ns: (now + 600_000_000_000) / 1_000_000 * 1_000_000,
        nonce: owner_auth::versioned_nonce(salt, (now + 600_000_000_000) / 1_000_000 * 1_000_000, [3; 15]),
        items_json: r#"[{"op":"set_relayer_allowance","weekly_yocto":"1"}]"#.into(),
    };
    let mp = s.sign_ops(Standard::RawEd25519, &body(salt(&v), env.now_ns().await?));
    let send = |mp: MultiPayload| {
        relayer
            .call(&acc, "owner_signed")
            .args_json(json!({"signed": mp}))
            .gas(Gas::from_tgas(100))
            .transact()
    };
    fails_with(&send(mp.clone()).await?, "E_SIGNED_DISABLED");
    // opt in with a wallet tx (1 yocto), then the same key signs
    ok(owner
        .call(&acc, "owner_set_signed_enabled")
        .args_json(json!({"enabled": true}))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?)?;
    ok(send(mp).await?)?;
    let w: Value = env.worker.view(&acc, "get_relayer_week").await?.json()?;
    assert_eq!(w["allowance_yocto"], json!("1"));
    Ok(())
}

/// Gas reference: the predecessor `owner_add_key` of a named owner (compare with the signed
/// `add_key` printed by the every_op tests).
#[tokio::test]
async fn v160_gas_predecessor_add_key() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let u = env.user("gasadd", 2 * NEAR, (NEAR, NEAR)).await?;
    let pk = SecretKey::from_random(KeyType::ED25519).public_key();
    let r = okr(u
        .owner
        .call(&u.account, "owner_add_key")
        .args_json(json!({"public_key": pk, "kind": "FunctionCall"}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?)?;
    let g = tgas(&r);
    println!("GAS predecessor owner_add_key: receipt {:.2} / total {:.2} TGas", g.0, g.1);
    Ok(())
}

/// F-01 on chain: opt-in (signed), a permissionless schedule, the 72 h wait (early apply
/// refused), a device veto, a re-approval, then a permissionless apply of a still-approved hash
/// (code switches, `installed` recorded, a replayed apply refused), and a hash revoked before its
/// eta is refused. F-19: an FT rescue lands in the signed-path owner's intents balance.
#[tokio::test]
async fn v160_auto_upgrade_and_rescue() -> anyhow::Result<()> {
    let c = setup().await?;
    let env = &c.env;
    let s = Signer::p256("au-r1");
    let acc = c.signer_ta("au1", &s, "Near").await?;
    let v2 = env.deploy_global(wasm("NT_UPGRADE_WASM", "trading_account_upgrade_test")).await?;
    let set = |h: &str| {
        env.admin
            .call(env.factory.id(), "set_code_hash")
            .args_json(json!({"code_hash": h, "signed_code": true}))
            .deposit(NearToken::from_yoctonear(1))
            .transact()
    };
    let poke =
        |m: &'static str| c.relayer.call(&acc, m).args_json(json!({})).gas(Gas::from_tgas(300)).transact();
    let view = || async { anyhow::Ok(env.worker.view(&acc, "get_auto_upgrade").await?.json::<Value>()?) };
    // off by default: permissionless calls refused
    fails_with(&poke("schedule_auto_upgrade").await?, "E_AUTO_OFF");
    c.run(&s, Standard::WebAuthn, &acc, json!({"op": "set_auto_upgrade", "enabled": true})).await?;
    assert_eq!(view().await?["state_version"], 160);
    // schedule: the factory approves v2
    ok(set(&v2).await?)?;
    let r = okr(poke("schedule_auto_upgrade").await?)?;
    assert!(logs_have(&r, "auto_upgrade_scheduled"), "{:?}", r.logs());
    let eta: u64 = view().await?["pending"]["eta_ns"].as_str().unwrap().parse()?;
    assert_eq!(view().await?["pending"]["code_hash"], json!(v2));
    fails_with(&poke("apply_auto_upgrade").await?, "E_AUTO_EARLY");
    // the owner vetoes (signed); a reschedule of the same hash does nothing
    c.run(&s, Standard::WebAuthn, &acc, json!({"op": "cancel_auto_upgrade"})).await?;
    assert_eq!(view().await?["vetoed"], json!([v2]));
    let r = okr(poke("schedule_auto_upgrade").await?)?;
    assert!(logs_have(&r, "nothing_new"));
    // a new approved code (v3 = the 1.6.0 build again) is scheduled
    let v3 = env.deploy_global(wasm("NT_ACCOUNT_WASM", "trading_account")).await?;
    ok(set(&v3).await?)?;
    let r = okr(poke("schedule_auto_upgrade").await?)?;
    assert!(logs_have(&r, "auto_upgrade_scheduled"), "{:?}", r.logs());
    assert_eq!(view().await?["pending"]["code_hash"], json!(v3));
    let eta3: u64 = view().await?["pending"]["eta_ns"].as_str().unwrap().parse()?;
    assert!(eta3 > eta);
    // 72 h later: the sandbox can't fast-forward 72 h (~400 s of chain time per 1000 blocks), so
    // the stored eta is moved to now by a state patch (only the eta: hash, flag and vetoes as
    // stored, same borsh layout: enabled, Some((hash, eta)), vetoed)
    let _ = eta3;
    let now = env.now_ns().await?;
    let mut au = vec![1u8, 1];
    au.extend_from_slice(&bs58::decode(&v3).into_vec()?);
    au.extend_from_slice(&now.to_le_bytes());
    au.extend_from_slice(&1u32.to_le_bytes());
    au.extend_from_slice(&bs58::decode(&v2).into_vec()?);
    env.worker.patch_state(&acc, b"au", &au).await?;
    assert_eq!(view().await?["pending"]["eta_ns"], json!(now.to_string()), "patched layout matches");
    assert_eq!(view().await?["vetoed"], json!([v2]));
    // revoked in the meantime (the factory now approves v2, which is vetoed): refused
    ok(set(&v2).await?)?;
    let r = okr(poke("apply_auto_upgrade").await?)?;
    assert!(logs_have(&r, "\"reason\":\"not_approved\""), "{:?}", r.logs());
    assert_eq!(env.global_hash(&acc).await?, None, "code unchanged");
    // approved again: applies once, in one guarded batch
    ok(set(&v3).await?)?;
    let r = okr(poke("apply_auto_upgrade").await?)?;
    assert!(logs_have(&r, "auto_upgrade_applied"), "{:?}", r.logs());
    assert_eq!(env.global_hash(&acc).await?, Some(v3.clone()));
    let v = view().await?;
    assert_eq!((v["installed"].clone(), v["pending"].clone()), (json!(v3), Value::Null));
    fails_with(&poke("apply_auto_upgrade").await?, "E_AUTO_NONE");
    let r = okr(poke("schedule_auto_upgrade").await?)?;
    assert!(logs_have(&r, "nothing_new"), "installed code is not rescheduled");
    // F-19: an FT the flows don't use, rescued into the owner's intents balance
    ok(env.meme.call("mint").args_json(json!({"account_id": acc, "amount": "500"})).transact().await?)?;
    c.run(
        &s,
        Standard::WebAuthn,
        &acc,
        json!({"op": "rescue", "asset": {"Ft": {"contract": env.meme.id(), "amount": "500"}}}),
    )
    .await?;
    let b: String = env
        .worker
        .view(c.intents.id(), "mt_balance_of")
        .args_json(json!({"account_id": s.owner_id(), "token_id": format!("nep141:{}", env.meme.id())}))
        .await?
        .json()?;
    assert_eq!(b, "500");
    Ok(())
}

/// R2-02 on chain: a NEP-245 token (a second instance of the real intents.near code, so its
/// `mt_transfer_call` is the real NEP-245 one) held by a signed-path TA is rescued into the
/// owner's intents.near balance with the single-token `mt_transfer_call` args.
#[tokio::test]
async fn v160_rescue_nep245_into_intents() -> anyhow::Result<()> {
    let c = setup().await?;
    let env = &c.env;
    let s = Signer::p256("mt-r1");
    let acc = c.signer_ta("mt1", &s, "Near").await?;
    // mt.test.near: another intents deployment, holding wNEAR for the TA
    let code = std::fs::read(format!("{}/fixtures/intents/intents.near.wasm", env!("CARGO_MANIFEST_DIR")))?;
    let mt = install_code(&env.worker, &format!("mt.{}", env.root.id()), &code).await?;
    ok(mt
        .call("new")
        .args_json(
            json!({"config": {"wnear_id": env.wrap.id(), "fees": {"fee": 0, "fee_collector": env.fees.id()},
            "roles": {"super_admins": [env.root.id()], "admins": {}, "grantees": {}}}}),
        )
        .gas(Gas::from_tgas(100))
        .transact()
        .await?)?;
    ok(env
        .root
        .call(env.wrap.id(), "storage_deposit")
        .args_json(json!({"account_id": mt.id()}))
        .deposit(NearToken::from_millinear(125))
        .transact()
        .await?)?;
    ok(env
        .root
        .call(env.wrap.id(), "ft_transfer_call")
        .args_json(json!({"receiver_id": mt.id(), "amount": "700", "msg": acc}))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?)?;
    let tid = format!("nep141:{}", env.wrap.id());
    c.run(
        &s,
        Standard::WebAuthn,
        &acc,
        json!({"op": "rescue", "asset": {"Mt": {"contract": mt.id(), "token_id": tid, "amount": "700"}}}),
    )
    .await?;
    let left: String = env
        .worker
        .view(mt.id(), "mt_balance_of")
        .args_json(json!({"account_id": acc, "token_id": tid}))
        .await?
        .json()?;
    assert_eq!(left, "0", "moved out of the MT contract");
    let home: String = env
        .worker
        .view(c.intents.id(), "mt_balance_of")
        .args_json(json!({"account_id": s.owner_id(), "token_id": format!("nep245:{}:{tid}", mt.id())}))
        .await?
        .json()?;
    assert_eq!(home, "700", "credited to the owner's intents home");
    Ok(())
}
