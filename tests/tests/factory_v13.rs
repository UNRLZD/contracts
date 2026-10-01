//! Factory 1.3.0 (docs/owner-v16-spec.md §7) against the REAL mainnet intents.near wasm
//! (tests/fixtures/intents/intents.near.wasm, code hash pinned below = mainnet on 2026-10-01):
//! signed creation per standard, the gas-headroom gate, every refund path reachable on chain,
//! replay / forgery / cross-network negatives, and the in-place 1.2.0 → 1.3.0 redeploy (mainnet
//! trade.unrlzd.near code, pinned). Refund reasons that cannot be produced on chain (mismatch,
//! bad_msg, underfunded, expired) are covered by factory/src/tests_v13.rs.
use integration_tests::*;
use near_workspaces::types::{Gas, KeyType, NearToken, SecretKey};
use near_workspaces::{Account, AccountId, Contract};
use owner_auth::testkit::{BodySpec, Signer};
use owner_auth::{MultiPayload, Standard};
use serde_json::{json, Value};

/// mainnet intents.near 0.4.2 (near/intents fa44ede9), read with view_code 2026-10-01.
const INTENTS_HASH: &str = "HUJ89jxFhsXF17XS8L5kmxz7te8AKfdWw2xzrVYo7aoj";
/// mainnet trade.unrlzd.near = factory 1.2.0 (deploy/contracts/mainnet.expected.json).
const FACTORY_120_HASH: &str = "AK2VXZnsFvJgK6XX9y5RoFEx985wq41nL3VEg2cp77dC";
const DEPOSIT: u128 = NEAR; // ≥ min_funding (0.7 N with the harness's one DCL dex)
const PENDING: u128 = NEAR / 100;
const MIN: u64 = 60_000_000_000;

fn fixture(name: &str, hash: &str) -> Vec<u8> {
    let p = format!("{}/fixtures/intents/{name}", env!("CARGO_MANIFEST_DIR"));
    let code = std::fs::read(&p).unwrap_or_else(|_| panic!("{p} missing"));
    assert_eq!(code_hash(&code), hash, "{name} is not the pinned mainnet code");
    code
}

struct Ctx {
    env: Env,
    intents: Contract,
    relayer: Account,
}

/// Harness factory with its code timelock at 0 (raw key `ft`, what `new(code_timelock_ns: 0)`
/// writes): the sandbox cannot wait 24 h. The timelock itself is tested in the migration test.
async fn setup_with(env: Env, flag: bool) -> anyhow::Result<Ctx> {
    env.worker.patch_state(env.factory.id(), b"ft", &0u64.to_le_bytes()).await?;
    setup_raw(env, flag).await
}

async fn setup_raw(env: Env, flag: bool) -> anyhow::Result<Ctx> {
    let intents =
        install_code(&env.worker, "intents.near", &fixture("intents.near.wasm", INTENTS_HASH)).await?;
    let root = env.root.id();
    ok(intents
        .call("new")
        .args_json(json!({"config": {"wnear_id": env.wrap.id(), "fees": {"fee": 0, "fee_collector": env.fees.id()},
            "roles": {"super_admins": [root], "admins": {}, "grantees": {"PauseManager": [root], "UnpauseManager": [root]}}}}))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?)?;
    for a in [intents.id(), env.root.id(), env.factory.id()] {
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
    if flag {
        set_code(&env, &env.code_hash.clone(), Some(true)).await?;
    }
    let relayer = sub(&env.root, "relayer", 20 * NEAR).await?;
    Ok(Ctx { env, intents, relayer })
}

async fn setup() -> anyhow::Result<Ctx> {
    setup_with(Env::new().await?, true).await
}

async fn set_code(env: &Env, hash: &str, signed: Option<bool>) -> anyhow::Result<()> {
    let mut args = json!({"code_hash": hash});
    if let Some(s) = signed {
        args["signed_code"] = json!(s);
    }
    ok(env
        .admin
        .call(env.factory.id(), "set_code_hash")
        .args_json(args)
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?)
}

impl Ctx {
    /// wNEAR credited to `owner` inside intents (a plain deposit, msg = owner).
    async fn fund(&self, owner: &str, amount: u128) -> anyhow::Result<()> {
        ok(self
            .env
            .root
            .call(self.env.wrap.id(), "ft_transfer_call")
            .args_json(json!({"receiver_id": self.intents.id(), "amount": amount.to_string(), "msg": owner}))
            .deposit(NearToken::from_yoctonear(1))
            .gas(Gas::from_tgas(100))
            .transact()
            .await?)
    }

    async fn balance(&self, owner: &str) -> anyhow::Result<u128> {
        let v: String = self
            .env
            .worker
            .view(self.intents.id(), "mt_balance_of")
            .args_json(json!({"account_id": owner, "token_id": format!("nep141:{}", self.env.wrap.id())}))
            .await?
            .json()?;
        Ok(v.parse()?)
    }

    async fn salt(&self) -> anyhow::Result<[u8; 4]> {
        let s: String = self.env.worker.view(self.intents.id(), "current_salt").await?.json()?;
        let b: Vec<u8> = (0..4).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect();
        Ok(b.try_into().unwrap())
    }

    /// A creation payload signed by `s` with `std` (fresh intents nonce).
    async fn payload(
        &self,
        s: &Signer,
        std: Standard,
        msg: &str,
        f: impl FnOnce(&mut BodySpec),
    ) -> anyhow::Result<MultiPayload> {
        let deadline = self.env.now_ns().await? + 5 * MIN;
        let rnd: [u8; 15] = rand_bytes();
        let items = json!([{"intent": "auth_call", "contract_id": self.env.factory.id(), "msg": msg,
            "attached_deposit": DEPOSIT.to_string(), "min_gas": "200000000000000"}])
        .to_string();
        let mut b = BodySpec {
            signer_id: s.owner_id(),
            verifying_contract: self.intents.id().to_string(),
            deadline_ns: deadline,
            nonce: owner_auth::versioned_nonce(self.salt().await?, deadline, rnd),
            items_json: items,
        };
        f(&mut b);
        Ok(s.sign_intents(std, &b))
    }

    async fn create(
        &self,
        mp: &MultiPayload,
        gas_tgas: u64,
    ) -> anyhow::Result<near_workspaces::result::ExecutionFinalResult> {
        self.create_by(&self.relayer, mp, gas_tgas).await
    }

    async fn create_by(
        &self,
        who: &Account,
        mp: &MultiPayload,
        gas_tgas: u64,
    ) -> anyhow::Result<near_workspaces::result::ExecutionFinalResult> {
        Ok(who
            .call(self.env.factory.id(), "create_via_intents")
            .args_json(json!({"signed": mp}))
            .deposit(NearToken::from_yoctonear(PENDING))
            .gas(Gas::from_tgas(gas_tgas))
            .transact()
            .await?)
    }

    async fn check(&self, mp: &MultiPayload) -> Result<Value, String> {
        match self
            .env
            .worker
            .view(self.env.factory.id(), "check_create")
            .args_json(json!({"signed": mp}))
            .await
        {
            Ok(r) => Ok(r.json().unwrap()),
            Err(e) => Err(format!("{e:?}")),
        }
    }

    async fn check_fails(&self, mp: &MultiPayload, code: &str) {
        let e = self.check(mp).await.expect_err(code);
        // view errors carry the panic as `GuestPanic { panic_msg: "<code>" }`
        assert!(e.contains(&format!("panic_msg: \\\"{code}\\\"")), "expected {code}, got {e}");
    }

    async fn exists(&self, id: &AccountId) -> bool {
        self.env.worker.view_account(id).await.is_ok()
    }

    async fn owed(&self, owner: &str) -> anyhow::Result<(u128, u128)> {
        let v: Value = self
            .env
            .worker
            .view(self.env.factory.id(), "get_owed")
            .args_json(json!({"owner": owner}))
            .await?
            .json()?;
        Ok((v["near"].as_str().unwrap().parse()?, v["wnear"].as_str().unwrap().parse()?))
    }

    async fn pause(&self, key: &str, on: bool) -> anyhow::Result<()> {
        let m = if on { "pa_pause_feature" } else { "pa_unpause_feature" };
        ok(self.env.root.call(self.intents.id(), m).args_json(json!({"key": key})).transact().await?)
    }

    async fn has_pending(&self, owner: &str, msg: &str) -> anyhow::Result<bool> {
        Ok(self
            .env
            .worker
            .view(self.env.factory.id(), "has_pending")
            .args_json(json!({"owner": owner, "msg": msg}))
            .await?
            .json()?)
    }
}

fn rand_bytes() -> [u8; 15] {
    let k = SecretKey::from_random(KeyType::ED25519).public_key();
    let s = pk_str(&k);
    let d = bs58::decode(&s["ed25519:".len()..]).into_vec().unwrap();
    d[..15].try_into().unwrap()
}

fn device() -> (SecretKey, String) {
    let sk = SecretKey::from_random(KeyType::ED25519);
    let pk = pk_str(&sk.public_key());
    (sk, pk)
}

fn msg_for(keys: &[&str]) -> String {
    json!({"v": 1, "device_public_keys": keys, "caps": null, "automation": null}).to_string()
}

fn events(r: &near_workspaces::result::ExecutionFinalResult) -> Vec<String> {
    r.logs().into_iter().filter(|l| l.starts_with("EVENT_JSON")).map(String::from).collect()
}

fn has_event(r: &near_workspaces::result::ExecutionFinalResult, ev: &str, part: &str) -> bool {
    events(r).iter().any(|l| l.contains(&format!("\"event\":\"{ev}\"")) && l.contains(part))
}

fn total_tgas(r: &near_workspaces::result::ExecutionFinalResult) -> f64 {
    r.total_gas_burnt.as_gas() as f64 / 1e12
}

// ------------------------------------------------------------------ happy path

/// One creation per standard, with the real intents.near: the account exists with the device
/// key and owner_auth (kind/home, signatures on), the user paid exactly the signed deposit,
/// the pending record is gone. Gas per receipt is printed (docs/contract-report.md).
#[tokio::test]
async fn signed_create_every_standard() -> anyhow::Result<()> {
    let c = setup().await?;
    let cases = [
        (Signer::p256("sb-p256"), Standard::WebAuthn, "P256", "Near"),
        (Signer::secp256k1("sb-k1"), Standard::Erc191, "Secp256k1", "Near"),
        (Signer::ed25519("sb-sol"), Standard::RawEd25519, "Ed25519", "Solana"),
        (Signer::ed25519("sb-nep413"), Standard::Nep413, "Ed25519", "Near"),
        (Signer::ed25519("sb-wa-ed"), Standard::WebAuthn, "Ed25519", "Near"),
    ];
    for (s, std, kind, home) in cases {
        let owner = s.owner_id();
        c.fund(&owner, 3 * NEAR).await?;
        let (dsk, dpk) = device();
        let m = msg_for(&[&dpk]);
        let mp = c.payload(&s, std, &m, |_| {}).await?;
        let chk = c.check(&mp).await.map_err(anyhow::Error::msg)?;
        let account: AccountId = chk["account"].as_str().unwrap().parse()?;
        assert_eq!(account, c.env.account_for(&owner.parse()?).await?);
        assert_eq!((chk["kind"].as_str(), chk["home"].as_str()), (Some(kind), Some(home)));
        let r = c.create(&mp, 300).await?;
        let gas = gas_by_receipt(&r);
        let r = okr(r)?;
        println!("create {std:?}/{kind}: total {:.2} TGas; receipts {gas:?}", total_tgas(&r));
        assert!(has_event(&r, "account_created", &owner), "{:?}", events(&r));
        assert!(c.exists(&account).await);
        assert_eq!(c.balance(&owner).await?, 2 * NEAR, "exactly the signed deposit left intents");
        assert!(!c.has_pending(&owner, &m).await?);
        let oa: Value = c.env.worker.view(&account, "get_owner_auth").await?.json()?;
        assert_eq!((oa["kind"].as_str(), oa["home"].as_str()), (Some(kind), Some(home)), "{oa}");
        assert_eq!(oa["signed_enabled"], true);
        let cfg = c.env.config(&account).await?;
        assert_eq!(cfg["owner"], owner);
        let keys = c.env.access_keys(&account).await?;
        assert!(keys.iter().any(|k| k["public_key"] == dpk), "device key installed");
        assert_eq!(keys.len(), 1);
        // the device key works: it can call a device method on the new account
        let dev = Account::from_secret_key(account.clone(), dsk, &c.env.worker);
        let r = dev
            .call(&account, "lower_caps")
            .args_json(json!({"caps": caps_json((NEAR, NEAR))}))
            .transact()
            .await?;
        ok(r)?;
        // replay of the same payload: the factory refuses (exists) before intents is touched
        c.check_fails(&mp, "E_EXISTS").await;
        fails_with(&c.create(&mp, 300).await?, "E_EXISTS");
        assert_eq!(c.balance(&owner).await?, 2 * NEAR);
    }
    Ok(())
}

/// Build gate (spec §7.4): the P-256 arm (the costliest, intents verifies it in wasm) and every
/// other arm still create with 20 TGas less than the relayer's 300; the smallest tx gas that
/// works is printed.
#[tokio::test]
async fn gas_headroom_gate() -> anyhow::Result<()> {
    let c = setup().await?;
    let cases = [
        (Signer::p256("gh-p256"), Standard::WebAuthn),
        (Signer::secp256k1("gh-k1"), Standard::Erc191),
        (Signer::ed25519("gh-sol"), Standard::RawEd25519),
        (Signer::ed25519("gh-nep413"), Standard::Nep413),
        (Signer::ed25519("gh-wa-ed"), Standard::WebAuthn),
    ];
    for (s, std) in cases {
        let owner = s.owner_id();
        c.fund(&owner, 2 * NEAR).await?;
        let (_, dpk) = device();
        let m = msg_for(&[&dpk]);
        let mp = c.payload(&s, std, &m, |_| {}).await?;
        let r = c.create(&mp, 280).await?;
        println!(
            "{std:?} at 280 TGas: total burnt {:.2} TGas, receipts {:?}",
            total_tgas(&r),
            gas_by_receipt(&r)
        );
        assert!(
            has_event(&r, "account_created", &owner),
            "{std:?}: must create with 280 TGas (>= 20 TGas headroom)"
        );
        assert_eq!(c.balance(&owner).await?, NEAR);
    }
    // the minimum for the P-256 arm, stepping with fresh owners
    let mut min_ok = 300;
    for tgas in (200..=270).rev().step_by(10) {
        let s = Signer::p256(&format!("gh-min-{tgas}"));
        c.fund(&s.owner_id(), 2 * NEAR).await?;
        let (_, dpk) = device();
        let m = msg_for(&[&dpk]);
        let mp = c.payload(&s, Standard::WebAuthn, &m, |_| {}).await?;
        let r = c.create(&mp, tgas).await?;
        if !has_event(&r, "account_created", &s.owner_id()) {
            assert_eq!(c.balance(&s.owner_id()).await?, 2 * NEAR, "a failed attempt costs nothing");
            assert!(!c.has_pending(&s.owner_id(), &m).await?);
            break;
        }
        min_ok = tgas;
    }
    println!("P-256 signed create: smallest working tx gas {min_ok} TGas (relayer attaches 300)");
    assert!(min_ok <= 280);
    Ok(())
}

// ------------------------------------------------------------------ refund paths

/// Front-run (payload sent straight to intents.near, no precommit) → full refund; the relayer's
/// later submission fails at intents (nonce used) and leaves no record. Intents paused for
/// deposits → the refund is owed (`fo`) and `retry_refund` (anyone) delivers it later.
#[tokio::test]
async fn refund_front_run_and_owed_retry() -> anyhow::Result<()> {
    let c = setup().await?;
    let s = Signer::secp256k1("fr");
    let owner = s.owner_id();
    c.fund(&owner, 2 * NEAR).await?;
    let (_, dpk) = device();
    let m = msg_for(&[&dpk]);
    let mp = c.payload(&s, Standard::Erc191, &m, |_| {}).await?;
    let attacker = sub(&c.env.root, "attacker", 5 * NEAR).await?;
    let r = attacker
        .call(c.intents.id(), "execute_intents")
        .args_json(json!({"signed": [mp]}))
        .gas(Gas::from_tgas(300))
        .transact()
        .await?;
    assert!(has_event(&r, "create_refunded", "\"reason\":\"no_precommit\""), "{:?}", events(&r));
    assert_eq!(c.balance(&owner).await?, 2 * NEAR, "refunded in full");
    let account = c.env.account_for(&owner.parse()?).await?;
    assert!(!c.exists(&account).await);
    let r = c.create(&mp, 300).await?;
    assert!(has_event(&r, "create_intent_failed", &owner), "{:?}", events(&r));
    assert!(!c.has_pending(&owner, &m).await?);
    assert!(!c.exists(&account).await);
    assert_eq!(c.balance(&owner).await?, 2 * NEAR);

    // intents refuses the refund deposit (ft_on_transfer paused) → owed, then retried
    c.pause("ft_on_transfer", true).await?;
    let mp2 = c.payload(&s, Standard::Erc191, &m, |_| {}).await?;
    let r = attacker
        .call(c.intents.id(), "execute_intents")
        .args_json(json!({"signed": [mp2]}))
        .gas(Gas::from_tgas(300))
        .transact()
        .await?;
    assert!(has_event(&r, "refund_owed", &owner), "{:?}", events(&r));
    assert_eq!(c.balance(&owner).await?, NEAR);
    assert_eq!(c.owed(&owner).await?, (0, DEPOSIT), "held as wNEAR by the factory");
    assert_eq!(c.env.ft_balance(c.env.wrap.id(), c.env.factory.id()).await?, DEPOSIT);
    // retry while still paused: owed again, nothing lost
    let r = attacker
        .call(c.env.factory.id(), "retry_refund")
        .args_json(json!({"owner": owner}))
        .gas(Gas::from_tgas(150))
        .transact()
        .await?;
    assert!(has_event(&r, "refund_owed", &owner));
    assert_eq!(c.owed(&owner).await?, (0, DEPOSIT));
    c.pause("ft_on_transfer", false).await?;
    let r = attacker
        .call(c.env.factory.id(), "retry_refund")
        .args_json(json!({"owner": owner}))
        .gas(Gas::from_tgas(150))
        .transact()
        .await?;
    ok(r)?;
    assert_eq!(c.balance(&owner).await?, 2 * NEAR, "owed refund delivered");
    assert_eq!(c.owed(&owner).await?, (0, 0));
    assert_eq!(c.env.ft_balance(c.env.wrap.id(), c.env.factory.id()).await?, 0);
    fails_with(
        &attacker
            .call(c.env.factory.id(), "retry_refund")
            .args_json(json!({"owner": owner}))
            .transact()
            .await?,
        "E_NOTHING_OWED",
    );
    Ok(())
}

/// Two creations for one owner in flight at once (both precommitted before either on_auth):
/// one account, the other deposit refunded (`exists`). Then the account's init fails (the
/// factory points at code whose `init` panics): `create_failed` refund, the id is free again.
#[tokio::test]
async fn refund_exists_and_create_failed() -> anyhow::Result<()> {
    let c = setup().await?;
    let s = Signer::p256("ex");
    let owner = s.owner_id();
    c.fund(&owner, 3 * NEAR).await?;
    let (_, d1) = device();
    let (_, d2) = device();
    let mp1 = c.payload(&s, Standard::WebAuthn, &msg_for(&[&d1]), |_| {}).await?;
    let mp2 = c.payload(&s, Standard::WebAuthn, &msg_for(&[&d2]), |_| {}).await?;
    let relayer2 = sub(&c.env.root, "relayer2", 5 * NEAR).await?;
    let (r1, r2) = tokio::join!(c.create(&mp1, 300), c.create_by(&relayer2, &mp2, 300));
    let (r1, r2) = (r1?, r2?);
    let created = [&r1, &r2].iter().filter(|r| has_event(r, "account_created", &owner)).count();
    let exists =
        [&r1, &r2].iter().filter(|r| has_event(r, "create_refunded", "\"reason\":\"exists\"")).count();
    println!("{:?}\n{:?}", events(&r1), events(&r2));
    assert_eq!((created, exists), (1, 1), "one account, one refund");
    assert_eq!(c.balance(&owner).await?, 2 * NEAR);

    // create_failed: code whose init panics (mock_ft has no `init`)
    let bad = c.env.deploy_global(out("mock_ft")).await?;
    set_code(&c.env, &bad, Some(true)).await?;
    let s2 = Signer::secp256k1("cf");
    let o2 = s2.owner_id();
    c.fund(&o2, 2 * NEAR).await?;
    let (_, dpk) = device();
    let mp = c.payload(&s2, Standard::Erc191, &msg_for(&[&dpk]), |_| {}).await?;
    let r = c.create(&mp, 300).await?;
    assert!(has_event(&r, "create_failed", &o2), "{:?}", events(&r));
    assert!(has_event(&r, "create_refunded", "\"reason\":\"create_failed\""));
    let account = c.env.account_for(&o2.parse()?).await?;
    assert!(!c.exists(&account).await);
    assert_eq!(c.balance(&o2).await?, 2 * NEAR, "refunded in full");
    // the id is free again: with good code the same owner creates
    set_code(&c.env, &c.env.code_hash.clone(), Some(true)).await?;
    let mp = c.payload(&s2, Standard::Erc191, &msg_for(&[&dpk]), |_| {}).await?;
    let r = okr(c.create(&mp, 300).await?)?;
    assert!(has_event(&r, "account_created", &o2));
    assert_eq!(c.balance(&o2).await?, NEAR);
    Ok(())
}

/// Intents paused / low balance: `execute_intents` fails, the record is dropped, the user
/// keeps everything, the relayer loses only its pending deposit.
#[tokio::test]
async fn intents_failure_costs_the_user_nothing() -> anyhow::Result<()> {
    let c = setup().await?;
    let s = Signer::ed25519("pz");
    let owner = s.owner_id();
    let (_, dpk) = device();
    let m = msg_for(&[&dpk]);
    // low balance
    c.fund(&owner, DEPOSIT - 1).await?;
    let mp = c.payload(&s, Standard::RawEd25519, &m, |_| {}).await?;
    let r = c.create(&mp, 300).await?;
    assert!(has_event(&r, "create_intent_failed", &owner), "{:?}", events(&r));
    assert!(!c.has_pending(&owner, &m).await?);
    assert_eq!(c.balance(&owner).await?, DEPOSIT - 1);
    // paused
    c.fund(&owner, 1).await?;
    c.pause("intents", true).await?;
    let mp = c.payload(&s, Standard::RawEd25519, &m, |_| {}).await?;
    let r = c.create(&mp, 300).await?;
    assert!(has_event(&r, "create_intent_failed", &owner));
    assert!(!c.has_pending(&owner, &m).await?);
    assert_eq!(c.balance(&owner).await?, DEPOSIT);
    c.pause("intents", false).await?;
    // the same payload works once intents is back (its nonce was never consumed)
    let r = okr(c.create(&mp, 300).await?)?;
    assert!(has_event(&r, "account_created", &owner));
    assert_eq!(c.balance(&owner).await?, 0);
    Ok(())
}

// ------------------------------------------------------------------ negatives

#[tokio::test]
async fn signed_create_negatives() -> anyhow::Result<()> {
    let env = Env::new().await?;
    let c = setup_with(env, false).await?;
    let s = Signer::p256("neg");
    let owner = s.owner_id();
    c.fund(&owner, 2 * NEAR).await?;
    let (_, dpk) = device();
    let m = msg_for(&[&dpk]);
    let mp = c.payload(&s, Standard::WebAuthn, &m, |_| {}).await?;
    // old-code guard: the configured code is not flagged 1.6.0+
    c.check_fails(&mp, "E_CODE_NOT_SIGNED").await;
    fails_with(&c.create(&mp, 300).await?, "E_CODE_NOT_SIGNED");
    let approved: Vec<String> = c.env.factory.view("get_approved_code_hashes").await?.json()?;
    assert!(approved.is_empty());
    set_code(&c.env, &c.env.code_hash.clone(), Some(true)).await?;
    let approved: Vec<String> = c.env.factory.view("get_approved_code_hashes").await?.json()?;
    assert_eq!(approved, vec![c.env.code_hash.clone()]);

    // forgery: another key signs for this owner id
    let other = Signer::p256("neg-other");
    let forged = c.payload(&other, Standard::WebAuthn, &m, |b| b.signer_id = owner.clone()).await?;
    c.check_fails(&forged, "E_NOT_OWNER").await;
    fails_with(&c.create(&forged, 300).await?, "E_NOT_OWNER");
    // tampered body after signing
    let mut tampered = mp.clone();
    if let MultiPayload::WebAuthn { payload, .. } = &mut tampered {
        *payload = payload.replace(&dpk, &device().1);
    }
    c.check_fails(&tampered, "E_WEBAUTHN").await;
    // malleability
    c.check_fails(&owner_auth::testkit::with_high_s(&mp), "E_HIGH_S").await;
    let k1 = Signer::secp256k1("neg-k1");
    let k1mp = c.payload(&k1, Standard::Erc191, &m, |_| {}).await?;
    c.check_fails(&owner_auth::testkit::with_v27(&k1mp), "E_SIG").await;
    c.check_fails(&owner_auth::testkit::with_high_s(&k1mp), "E_SIG").await;
    // cross-network / cross-contract replay: testnet intents, a TA, the factory itself
    for vc in ["intents.testnet", c.env.factory.id().as_str()] {
        let x = c.payload(&s, Standard::WebAuthn, &m, |b| b.verifying_contract = vc.into()).await?;
        c.check_fails(&x, "E_VERIFYING_CONTRACT").await;
    }
    // an intent for another factory (e.g. the testnet one)
    let x = c
        .payload(&s, Standard::WebAuthn, &m, |b| {
            b.items_json = b.items_json.replace(c.env.factory.id().as_str(), "tt.testnet")
        })
        .await?;
    c.check_fails(&x, "E_INTENT").await;
    // expired
    let x = c.payload(&s, Standard::WebAuthn, &m, |b| b.deadline_ns -= 10 * MIN).await?;
    c.check_fails(&x, "E_DEADLINE").await;
    // pending deposit
    let r = c
        .relayer
        .call(c.env.factory.id(), "create_via_intents")
        .args_json(json!({"signed": mp}))
        .deposit(NearToken::from_yoctonear(PENDING - 1))
        .gas(Gas::from_tgas(300))
        .transact()
        .await?;
    fails_with(&r, "E_PENDING_DEPOSIT");
    // on_auth from anyone but intents.near panics (their deposit bounces to them)
    let mallory = sub(&c.env.root, "mallory", 5 * NEAR).await?;
    let r = mallory
        .call(c.env.factory.id(), "on_auth")
        .args_json(json!({"signer_id": owner, "msg": m}))
        .deposit(NearToken::from_near(1))
        .gas(Gas::from_tgas(250))
        .transact()
        .await?;
    fails_with(&r, "E_NOT_VERIFIER");
    // private callbacks
    for (method, args) in [
        ("on_intents_executed", json!({"owner": owner, "msg": m, "nonce": "AA=="})),
        ("on_create_intents", json!({"owner": owner, "account": owner, "deposit": "1"})),
        ("on_refund", json!({"owner": owner, "near": "1", "wnear": "0"})),
    ] {
        let r = mallory.call(c.env.factory.id(), method).args_json(args).transact().await?;
        assert!(r.is_failure(), "{method} is private");
    }
    // nothing was created or charged
    assert_eq!(c.balance(&owner).await?, 2 * NEAR);
    assert!(!c.exists(&c.env.account_for(&owner.parse()?).await?).await);
    // the valid payload still works after all of that
    let r = okr(c.create(&mp, 300).await?)?;
    assert!(has_event(&r, "account_created", &owner));
    // a NEAR wallet (named owner) cannot use the signed path for its own id: signer_id must be
    // the key's implicit id
    let named = c.payload(&s, Standard::WebAuthn, &m, |b| b.signer_id = "alice.near".into()).await?;
    c.check_fails(&named, "E_NOT_OWNER").await;
    Ok(())
}

// ------------------------------------------------------------------ 1.2.0 → 1.3.0

async fn admin_call(env: &Env, who: &Account, method: &str, args: Value) -> anyhow::Result<()> {
    ok(who
        .call(env.factory.id(), method)
        .args_json(args)
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(50))
        .transact()
        .await?)
}

/// Fast-forwards until the `field` proposal of `get_admin_state` is effective (null).
async fn wait_pending(env: &Env, field: &str) -> anyhow::Result<()> {
    let eta: u64 = admin_state(env).await?[field]["eta_ns"].as_str().unwrap().parse()?;
    while env.now_ns().await? < eta {
        env.worker.fast_forward(10).await?;
    }
    assert_eq!(admin_state(env).await?[field], Value::Null);
    Ok(())
}

async fn admin_state(env: &Env) -> anyhow::Result<Value> {
    Ok(env.factory.view("get_admin_state").await?.json()?)
}

/// The 24 mainnet entries of 1.6: the 4 of 1.2.0 + the 20 venue entries (venues-hooks rev 3).
fn full_allowlist(env: &Env) -> Value {
    let mut v = vec![
        json!({"id": env.rhea.id(), "kind": "RheaClassic"}),
        json!({"id": env.dcl.id(), "kind": "RheaDcl"}),
        json!({"id": env.plach.id(), "kind": "Plach"}),
        json!({"id": SHARDS_FACTORY, "kind": "ShardsToken"}),
    ];
    for (id, kind) in [
        ("aidols.near", json!({"AidolsCurve": "Near"})),
        ("gra-fun.near", json!({"AidolsCurve": "Near"})),
        ("gaypad.j1-racing.near", json!({"AidolsCurve": "Jambo"})),
        ("v1.whole-market.near", json!({"AidolsCurve": "Neardog"})),
        ("v2.whole-market.near", json!({"AidolsCurve": "Neardog"})),
        ("patata-monster.near", json!({"AidolsCurve": "Patata"})),
        ("launch.vistadev.near", json!({"FactoryCurve": "VistaLaunch"})),
        ("dex.vistadev.near", json!({"FactoryCurve": "VistaDex"})),
        ("nearrr-fun.near", json!({"FactoryCurve": "Nearrr"})),
        ("curve10.latedata9580.near", json!({"FactoryCurve": "Nira"})),
        ("meme-cooking.near", json!({"FactoryCurve": "MemeCooking"})),
        ("dragonpad.near", json!({"FactoryCurve": "Dragonpad"})),
        ("nearfunio.near", json!({"TokenCurve": "NearFun"})),
        ("umbrafun.near", json!({"TokenCurve": "Umbra"})),
        ("revshare-launch.near", json!({"TokenCurve": "RevShare"})),
        ("nearmemefun.near", json!({"TokenCurve": "Nearmemefun"})),
        ("token0.near", json!({"TokenCurve": "Token0"})),
        ("chipfi.near", json!({"TokenCurve": "Chipfi"})),
        ("npad.near", json!({"TokenCurve": "Npad"})),
        ("exchange.kelytradevs.near", json!("Kelytra")),
    ] {
        v.push(json!({"id": id, "kind": kind}));
    }
    Value::Array(v)
}

/// The mainnet factory 1.2.0 code (pinned), redeployed in place with 1.3.0: config, account ids
/// and the `created` set survive; `create_account` (NEAR wallets) works unchanged before and
/// after; the signed path stays closed until the admin flags the code hash; the 1.2.0
/// `set_code_hash(code_hash)` call shape still works (and clears the flag).
#[tokio::test]
async fn migrate_120_to_130_in_place() -> anyhow::Result<()> {
    let env = Env::new_with(None, Some(fixture("factory_1_2_0_mainnet.wasm", FACTORY_120_HASH))).await?;
    let before_cfg = env.factory.view("get_config").await?.json::<Value>()?;
    let alice = env.user("alice", 2 * NEAR, (NEAR, 5 * NEAR)).await?;
    // 1.2.0 has no 1.3.0 views
    assert!(env.factory.view("get_approved_code_hashes").await.is_err());

    let c = setup_raw(env, false).await?;
    c.env.factory.as_account().deploy(&out("factory")).await?.into_result()?;
    assert_eq!(c.env.factory.view("get_config").await?.json::<Value>()?, before_cfg);
    assert_eq!(c.env.account_for(alice.owner.id()).await?, alice.account);
    let sc: Value = c.env.factory.view("get_signed_config").await?.json()?;
    assert_eq!(
        sc,
        json!({"verifier": "intents.near", "signed_code": false, "pending_deposit": PENDING.to_string()})
    );
    let approved: Vec<String> = c.env.factory.view("get_approved_code_hashes").await?.json()?;
    assert!(approved.is_empty());
    // created set kept: alice cannot create again
    let (_, dpk) = device();
    let r = alice
        .owner
        .call(c.env.factory.id(), "create_account")
        .args_json(json!({"device_public_key": dpk}))
        .deposit(NearToken::from_near(1))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?;
    fails_with(&r, "E_EXISTS");
    // existing account untouched and working
    ok(c.env
        .exec(
            &alice.device,
            &alice.account,
            json!([{"NearDeposit": {"amount": NEAR.to_string()}}]),
            "w",
            NEAR,
        )
        .await?)?;
    // a new NEAR-wallet user creates as before (1.2.0 args)
    let bob = c.env.user("bob", 2 * NEAR, (NEAR, 5 * NEAR)).await?;
    assert!(c.exists(&bob.account).await);
    let cfg = c.env.config(&bob.account).await?;
    assert_eq!(cfg["owner"], bob.owner.id().as_str());
    let oa: Value = c.env.worker.view(&bob.account, "get_owner_auth").await?.json()?;
    assert_eq!((oa["kind"].as_str(), oa["signed_enabled"].as_bool()), (Some("Named"), Some(false)));
    // signed path closed until flagged
    let s = Signer::p256("mig");
    c.fund(&s.owner_id(), 2 * NEAR).await?;
    let m = msg_for(&[&dpk]);
    let mp = c.payload(&s, Standard::WebAuthn, &m, |_| {}).await?;
    fails_with(&c.create(&mp, 300).await?, "E_CODE_NOT_SIGNED");

    // ---- F-20: the mainnet state has no `ft` key: the code timelock is 24 h ----
    let st = admin_state(&c.env).await?;
    assert_eq!(
        st,
        json!({"pending_code": null, "code_timelock_ns": (24u64 * 3600 * 1_000_000_000).to_string(), "pending_admin": null,
            "pending_dex_allowlist": null, "pending_fee_config": null, "creation_paused": false, "resume_eta_ns": null, "revoked_code": null,
            "pending_verifier": null})
    );
    set_code(&c.env, &c.env.code_hash.clone(), Some(true)).await?;
    let st = admin_state(&c.env).await?;
    assert_eq!(st["pending_code"]["code_hash"], c.env.code_hash.as_str());
    let eta: u64 = st["pending_code"]["eta_ns"].as_str().unwrap().parse()?;
    assert!(eta >= c.env.now_ns().await? + 24 * 3600 * 1_000_000_000 - 60_000_000_000);
    let approved: Vec<String> = c.env.factory.view("get_approved_code_hashes").await?.json()?;
    assert!(approved.is_empty(), "a pending hash is never approved");
    fails_with(&c.create(&mp, 300).await?, "E_CODE_NOT_SIGNED");
    admin_call(&c.env, &c.env.admin, "cancel_code_hash", json!({})).await?;
    assert_eq!(admin_state(&c.env).await?["pending_code"], Value::Null);
    // 24 h cannot pass in the sandbox (1000 blocks = ~7 min of chain time): shorten the
    // timelock to 20 s by state patch, then wait it out for real
    c.env.worker.patch_state(c.env.factory.id(), b"ft", &20_000_000_000u64.to_le_bytes()).await?;
    set_code(&c.env, &c.env.code_hash.clone(), Some(true)).await?;
    fails_with(&c.create(&mp, 300).await?, "E_CODE_NOT_SIGNED");
    let eta: u64 = admin_state(&c.env).await?["pending_code"]["eta_ns"].as_str().unwrap().parse()?;
    while c.env.now_ns().await? < eta {
        c.env.worker.fast_forward(10).await?;
    }
    let approved: Vec<String> = c.env.factory.view("get_approved_code_hashes").await?.json()?;
    assert_eq!(approved, vec![c.env.code_hash.clone()], "approved after the timelock, no poke");

    // ---- F-06: the full 1.6 allowlist right after the redeploy ----
    let full = full_allowlist(&c.env);
    assert_eq!(full.as_array().unwrap().len(), 24);
    let stranger = sub(&c.env.root, "stranger", 5 * NEAR).await?;
    let r = stranger
        .call(c.env.factory.id(), "set_dex_allowlist")
        .args_json(json!({"dex_allowlist": full}))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?;
    fails_with(&r, "E_NOT_ADMIN");
    admin_call(&c.env, &c.env.admin, "set_dex_allowlist", json!({"dex_allowlist": full})).await?;
    // R2-07: timelocked like the code (20 s here)
    assert_ne!(c.env.factory.view("get_config").await?.json::<Value>()?["dex_allowlist"], full);
    wait_pending(&c.env, "pending_dex_allowlist").await?;
    assert_eq!(c.env.factory.view("get_config").await?.json::<Value>()?["dex_allowlist"], full);
    // a new NEAR-wallet account and a new signed account both get every venue
    let carol = c.env.user("carol", 2 * NEAR, (NEAR, 5 * NEAR)).await?;
    assert_eq!(c.env.config(&carol.account).await?["dex_allowlist"], full);
    let mp = c.payload(&s, Standard::WebAuthn, &m, |_| {}).await?;
    let r = okr(c.create(&mp, 300).await?)?;
    assert!(has_event(&r, "account_created", &s.owner_id()));
    let acc = c.env.account_for(&s.owner_id().parse()?).await?;
    assert_eq!(c.env.config(&acc).await?["dex_allowlist"], full);
    // accounts created before keep their list (the factory never touches existing accounts)
    assert_eq!(c.env.config(&bob.account).await?["dex_allowlist"].as_array().unwrap().len(), 3);

    // ---- F-17: fee config for new accounts ----
    admin_call(
        &c.env,
        &c.env.admin,
        "set_fee_config",
        json!({"fee_config": {"fee_bps": 50, "fee_recipient": c.env.fees.id()}}),
    )
    .await?;
    wait_pending(&c.env, "pending_fee_config").await?;
    let dave = c.env.user("dave", 2 * NEAR, (NEAR, 5 * NEAR)).await?;
    assert_eq!(c.env.config(&dave.account).await?["fee_bps"], 50);
    assert_eq!(c.env.config(&carol.account).await?["fee_bps"], FEE_BPS as u64);

    // ---- F-20: two-step admin transfer ----
    let multisig = sub(&c.env.root, "multisig", 5 * NEAR).await?;
    admin_call(&c.env, &c.env.admin, "propose_admin", json!({"new_admin": multisig.id()})).await?;
    assert_eq!(admin_state(&c.env).await?["pending_admin"], multisig.id().as_str());
    let r = stranger
        .call(c.env.factory.id(), "accept_admin")
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?;
    fails_with(&r, "E_NOT_ADMIN");
    admin_call(&c.env, &multisig, "accept_admin", json!({})).await?;
    assert_eq!(c.env.factory.view("get_config").await?.json::<Value>()?["admin"], multisig.id().as_str());
    let r = c
        .env
        .admin
        .call(c.env.factory.id(), "revoke_signed_code")
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?;
    fails_with(&r, "E_NOT_ADMIN");
    // the new admin: revoke is immediate
    admin_call(&c.env, &multisig, "revoke_signed_code", json!({})).await?;
    let approved: Vec<String> = c.env.factory.view("get_approved_code_hashes").await?.json()?;
    assert!(approved.is_empty());
    // the 1.2.0 set_code_hash call shape still works (an unflagged proposal)
    let r = multisig
        .call(c.env.factory.id(), "set_code_hash")
        .args_json(json!({"code_hash": c.env.code_hash}))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?;
    ok(r)?;
    assert_eq!(admin_state(&c.env).await?["pending_code"]["signed_code"], false);
    Ok(())
}

/// The mainnet go-live path: the real 1.2.0 factory is redeployed in place with the one-time
/// bootstrap `migrate{code_hash, signed_code, dex_allowlist}` in the SAME tx (deploy + call,
/// atomic). The code hash, signed flag and 24-entry allowlist apply at once (no 24 h wait);
/// a failed bootstrap reverts the deploy too; a second bootstrap is refused; `migrate` is
/// private; every later `set_code_hash` is timelocked (24 h, the mainnet default).
#[tokio::test]
async fn bootstrap_120_to_130_in_one_tx() -> anyhow::Result<()> {
    let env = Env::new_with(None, Some(fixture("factory_1_2_0_mainnet.wasm", FACTORY_120_HASH))).await?;
    let alice = env.user("alice", 2 * NEAR, (NEAR, 5 * NEAR)).await?;
    let c = setup_raw(env, false).await?;
    let full = full_allowlist(&c.env);
    let code = out("factory");
    let boot = |list: Value| {
        c.env
            .factory
            .as_account()
            .batch(c.env.factory.id())
            .deploy(&code)
            .call(
                near_workspaces::operations::Function::new("migrate")
                    .args_json(
                        json!({"code_hash": c.env.code_hash, "signed_code": true, "dex_allowlist": list}),
                    )
                    .gas(Gas::from_tgas(50)),
            )
            .transact()
    };
    // a bad bootstrap fails the whole tx: the 1.2.0 code stays
    fails_with(&boot(json!([])).await?, "E_BAD_ALLOWLIST");
    assert!(c.env.factory.view("get_admin_state").await.is_err(), "still 1.2.0 code");
    let r = boot(full.clone()).await?;
    let r = okr(r)?;
    assert!(r.logs().iter().any(|l| l.contains("\"factory_bootstrapped\"")));
    // immediate
    let approved: Vec<String> = c.env.factory.view("get_approved_code_hashes").await?.json()?;
    assert_eq!(approved, vec![c.env.code_hash.clone()]);
    let cfg = c.env.factory.view("get_config").await?.json::<Value>()?;
    assert_eq!(
        (cfg["dex_allowlist"].clone(), cfg["code_hash"].clone()),
        (full.clone(), json!(c.env.code_hash))
    );
    let st = admin_state(&c.env).await?;
    assert_eq!(st["code_timelock_ns"], (24u64 * 3600 * 1_000_000_000).to_string(), "mainnet default kept");
    assert_eq!(st["pending_code"], Value::Null);
    // new accounts at once: NEAR wallet and signed, both with every venue
    let carol = c.env.user("carol", 2 * NEAR, (NEAR, 5 * NEAR)).await?;
    assert_eq!(c.env.config(&carol.account).await?["dex_allowlist"], full);
    let s = Signer::secp256k1("boot");
    c.fund(&s.owner_id(), 2 * NEAR).await?;
    let (_, dpk) = device();
    let mp = c.payload(&s, Standard::Erc191, &msg_for(&[&dpk]), |_| {}).await?;
    let r = okr(c.create(&mp, 300).await?)?;
    assert!(has_event(&r, "account_created", &s.owner_id()));
    let acc = c.env.account_for(&s.owner_id().parse()?).await?;
    assert_eq!(c.env.config(&acc).await?["dex_allowlist"], full);
    assert_eq!(c.env.worker.view(&acc, "get_owner_auth").await?.json::<Value>()?["kind"], "Secp256k1");
    // the 1.2.0 state survived
    assert_eq!(c.env.account_for(alice.owner.id()).await?, alice.account);
    let r = alice
        .owner
        .call(c.env.factory.id(), "create_account")
        .args_json(json!({"device_public_key": dpk}))
        .deposit(NearToken::from_near(1))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?;
    fails_with(&r, "E_EXISTS");
    // once only, and only by the factory account itself
    let again = c
        .env
        .factory
        .as_account()
        .call(c.env.factory.id(), "migrate")
        .args_json(json!({"code_hash": c.env.code_hash, "signed_code": true, "dex_allowlist": full}))
        .transact()
        .await?;
    fails_with(&again, "E_BOOTSTRAPPED");
    let r = c
        .env
        .admin
        .call(c.env.factory.id(), "migrate")
        .args_json(json!({"code_hash": c.env.code_hash, "signed_code": true, "dex_allowlist": full}))
        .transact()
        .await?;
    assert!(r.is_failure() && format!("{:?}", r.into_result().err()).contains("is private"));
    // later code changes are timelocked
    let v2 = c.env.deploy_global(out("mock_ft")).await?;
    set_code(&c.env, &v2, Some(true)).await?;
    let approved: Vec<String> = c.env.factory.view("get_approved_code_hashes").await?.json()?;
    assert_eq!(approved, vec![c.env.code_hash.clone()], "the proposal waits 24 h");
    assert_eq!(admin_state(&c.env).await?["pending_code"]["code_hash"], v2.as_str());
    assert_eq!(
        c.env.factory.view("get_config").await?.json::<Value>()?["code_hash"],
        c.env.code_hash.as_str()
    );
    // R2-07: a later allowlist change is timelocked too (24 h)
    admin_call(&c.env, &c.env.admin, "set_dex_allowlist", json!({"dex_allowlist": [full[0]]})).await?;
    assert_eq!(c.env.factory.view("get_config").await?.json::<Value>()?["dex_allowlist"], full);
    // R2-08: pause stops both doors at once; resume waits 24 h
    admin_call(&c.env, &c.env.admin, "pause_creation", json!({})).await?;
    let (_, d2) = device();
    let r = sub(&c.env.root, "erin", 5 * NEAR)
        .await?
        .call(c.env.factory.id(), "create_account")
        .args_json(json!({"device_public_key": d2}))
        .deposit(NearToken::from_near(2))
        .gas(Gas::from_tgas(100))
        .transact()
        .await?;
    fails_with(&r, "E_PAUSED");
    let s2 = Signer::p256("boot-paused");
    c.fund(&s2.owner_id(), 2 * NEAR).await?;
    let mp2 = c.payload(&s2, Standard::WebAuthn, &msg_for(&[&d2]), |_| {}).await?;
    fails_with(&c.create(&mp2, 300).await?, "E_PAUSED");
    admin_call(&c.env, &c.env.admin, "resume_creation", json!({})).await?;
    assert_eq!(admin_state(&c.env).await?["creation_paused"], true, "resume waits 24 h");
    Ok(())
}
