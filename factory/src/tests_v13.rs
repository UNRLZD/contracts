//! 1.3.0 unit tests: signed creation (spec §7), refunds, approved hashes, `create_account`
//! unchanged.
use super::*;
use near_sdk::mock::MockAction;
use near_sdk::test_utils::{get_created_receipts, get_logs, VMContextBuilder};
use near_sdk::{testing_env, PromiseResult};
use owner_auth::testkit::{BodySpec, Signer};
use owner_auth::Standard;

const NEAR: u128 = 1_000_000_000_000_000_000_000_000;
const T0: u64 = 1_790_000_000_000_000_000;
const FACTORY: &str = "trade.unrlzd.near";
const DEVICE: &str = "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp";
const DEVICE2: &str = "ed25519:DcA2MzgpJbrUATQLLceocVckhhAqrkingax4oJ9kZ847";

fn aid(s: &str) -> AccountId {
    s.parse().unwrap()
}

fn ctx(pred: &str, deposit: u128, now: u64) -> VMContextBuilder {
    let mut b = VMContextBuilder::new();
    b.current_account_id(aid(FACTORY))
        .predecessor_account_id(aid(pred))
        .signer_account_id(aid(pred))
        .attached_deposit(NearToken::from_yoctonear(deposit))
        .account_balance(NearToken::from_near(100))
        .prepaid_gas(Gas::from_tgas(300))
        .block_timestamp(now);
    b
}

fn set(pred: &str, deposit: u128) {
    testing_env!(ctx(pred, deposit, T0).build());
}

fn set_results(pred: &str, results: Vec<PromiseResult>) {
    testing_env!(
        ctx(pred, 0, T0).build(),
        near_sdk::test_vm_config(),
        near_sdk::RuntimeFeesConfig::test(),
        Default::default(),
        results,
    );
}

/// Factory with no DCL dex (min funding 0.2 N), code flagged signed.
fn factory(signed: bool) -> Factory {
    // fresh storage per factory (testing_env! carries storage over)
    env::set_blockchain_interface(near_sdk::MockedBlockchain::new(
        ctx("admin.near", 0, T0).build(),
        near_sdk::test_vm_config(),
        near_sdk::RuntimeFeesConfig::test(),
        vec![],
        Default::default(),
        Default::default(),
        None,
    ));
    let mut f = Factory::new(
        aid("admin.near"),
        [7u8; 32].into(),
        FeeConfig { fee_bps: 75, fee_recipient: aid("fees.near") },
        vec![],
        aid("wrap.near"),
        Some(U64(0)), // no code timelock: set_code_hash is effective at once (timelock tests below)
    );
    set("admin.near", 1);
    f.set_code_hash([7u8; 32].into(), Some(signed));
    f
}

fn msg(keys: &[&str]) -> String {
    serde_json::json!({"v": 1, "device_public_keys": keys, "caps": null, "automation": null}).to_string()
}

fn intents(m: &str, deposit: u128, min_gas_tgas: u64) -> String {
    serde_json::json!([{"intent": "auth_call", "contract_id": FACTORY, "msg": m,
        "attached_deposit": deposit.to_string(), "min_gas": (min_gas_tgas * 1_000_000_000_000).to_string()}])
    .to_string()
}

fn spec(s: &Signer, items: String) -> BodySpec {
    BodySpec {
        signer_id: s.owner_id(),
        verifying_contract: "intents.near".into(),
        deadline_ns: T0 + 60_000_000_000,
        nonce: owner_auth::versioned_nonce([1, 2, 3, 4], T0 + 60_000_000_000, [9; 15]),
        items_json: items,
    }
}

fn signed(s: &Signer, std: Standard) -> MultiPayload {
    s.sign_intents(std, &spec(s, intents(&msg(&[DEVICE]), NEAR, 200)))
}

fn signers() -> Vec<(Signer, Standard)> {
    vec![
        (Signer::p256("p"), Standard::WebAuthn),
        (Signer::secp256k1("k"), Standard::Erc191),
        (Signer::ed25519("sol"), Standard::RawEd25519),
        (Signer::ed25519("n"), Standard::Nep413),
        (Signer::ed25519("wa"), Standard::WebAuthn),
    ]
}

fn panics<R>(f: impl FnOnce() -> R) -> String {
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    let e = r.err().expect("expected a panic");
    e.downcast_ref::<String>()
        .cloned()
        .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_default()
}

fn assert_code<R>(code: &str, f: impl FnOnce() -> R) {
    let m = panics(f);
    assert!(m == code || m.ends_with(&format!(": {code}")) || m.contains(code), "expected {code}, got {m}");
}

/// (receiver, method, args, deposit) of every function call created.
fn calls() -> Vec<(String, String, String, u128)> {
    let mut out = vec![];
    for r in get_created_receipts() {
        for a in r.actions {
            if let MockAction::FunctionCallWeight { method_name, args, attached_deposit, .. } = a {
                out.push((
                    r.receiver_id.to_string(),
                    String::from_utf8(method_name).unwrap(),
                    String::from_utf8(args).unwrap(),
                    attached_deposit.as_yoctonear(),
                ));
            }
        }
    }
    out
}

fn has_event(name: &str) -> bool {
    get_logs().iter().any(|l| l.contains(&format!("\"event\":\"{name}\"")))
}

fn precommit(f: &mut Factory, s: &Signer, std: Standard) -> MultiPayload {
    let mp = signed(s, std);
    set("relayer.near", PENDING_DEPOSIT.as_yoctonear());
    f.create_via_intents(mp.clone()).detach();
    mp
}

// ------------------------------------------------------------ config

#[test]
fn approved_hashes_follow_the_signed_flag() {
    let mut f = factory(false);
    assert!(f.get_approved_code_hashes().is_empty());
    set("admin.near", 1);
    f.set_code_hash([8u8; 32].into(), Some(true));
    assert_eq!(f.get_approved_code_hashes(), vec![Base58CryptoHash::from([8u8; 32])]);
    // a hash set without the flag (the 1.2.0 call shape) clears it
    set("admin.near", 1);
    f.set_code_hash([9u8; 32].into(), None);
    assert!(f.get_approved_code_hashes().is_empty());
    assert!(!f.get_signed_config().signed_code);
    assert_eq!(f.get_config().code_hash, Base58CryptoHash::from([9u8; 32]));
}

#[test]
fn admin_setters_need_admin_and_one_yocto() {
    let mut f = factory(true);
    set("mallory.near", 1);
    assert_code("E_NOT_ADMIN", || f.set_code_hash([1u8; 32].into(), Some(true)));
    set("mallory.near", 1);
    assert_code("E_NOT_ADMIN", || f.set_verifier(aid("evil.near")));
    set("admin.near", 0);
    assert_code("Requires attached deposit of exactly 1 yoctoNEAR", || {
        f.set_verifier(aid("intents.testnet"))
    });
    assert_eq!(f.get_signed_config().verifier, aid(DEFAULT_VERIFIER));
    set("admin.near", 1);
    f.set_verifier(aid("intents.testnet"));
    assert_eq!(f.get_signed_config().verifier, aid("intents.testnet"));
}

// ------------------------------------------------------------ precommit (spec §7.3)

#[test]
fn every_standard_precommits_and_submits_to_intents() {
    for (s, std) in signers() {
        let mut f = factory(true);
        let mp = signed(&s, std);
        set("relayer.near", 0);
        let c = f.check_create(mp.clone());
        assert_eq!(c.owner.as_str(), s.owner_id());
        assert_eq!(c.kind, s.kind());
        assert_eq!(c.home, if std == Standard::RawEd25519 { Home::Solana } else { Home::Near });
        assert_eq!(c.account, f.account_for(c.owner.clone()));
        assert_eq!(c.deposit.0, NEAR);
        precommit(&mut f, &s, std);
        assert!(f.has_pending(aid(&s.owner_id()), msg(&[DEVICE])), "{std:?}");
        let cs = calls();
        let (rcv, method, args, dep) = &cs[0];
        assert_eq!((rcv.as_str(), method.as_str(), *dep), ("intents.near", "execute_intents", 0));
        // the payload goes to intents unchanged
        let v: serde_json::Value = serde_json::from_str(args).unwrap();
        assert_eq!(v["signed"][0], serde_json::to_value(&mp).unwrap());
        assert_eq!(cs[1].1, "on_intents_executed");
    }
}

#[test]
fn precommit_negatives() {
    let s = Signer::p256("p");
    let std = Standard::WebAuthn;
    let at = |f: &Factory, mp: MultiPayload, code: &str| {
        set("relayer.near", 0);
        assert_code(code, || f.check_create(mp));
    };
    // old-code guard
    let f = factory(false);
    at(&f, signed(&s, std), "E_CODE_NOT_SIGNED");
    let mut f = factory(true);
    set("relayer.near", PENDING_DEPOSIT.as_yoctonear() - 1);
    assert_code("E_PENDING_DEPOSIT", || f.create_via_intents(signed(&s, std)));

    let mk = |sp: BodySpec| s.sign_intents(std, &sp);
    let base = spec(&s, intents(&msg(&[DEVICE]), NEAR, 200));
    // forged: another key signs for this owner id / body signed by someone else
    let other = Signer::p256("other");
    at(&f, other.sign_intents(std, &base), "E_NOT_OWNER");
    let mut forged = signed(&s, std);
    if let MultiPayload::WebAuthn { payload, .. } = &mut forged {
        *payload = payload.replace("\"v\\\":1", "\"v\\\":1 ");
    }
    at(&f, forged, "E_WEBAUTHN");
    at(&f, owner_auth::testkit::with_high_s(&signed(&s, std)), "E_HIGH_S");
    let k1 = Signer::secp256k1("k");
    at(&f, owner_auth::testkit::with_v27(&signed(&k1, Standard::Erc191)), "E_SIG");
    // cross-network / cross-contract: wrong verifying contract
    for vc in ["intents.testnet", FACTORY, "abcdef0123456789.trade.unrlzd.near"] {
        at(&f, mk(BodySpec { verifying_contract: vc.into(), ..base.clone() }), "E_VERIFYING_CONTRACT");
    }
    // deadline: passed, beyond the 15 min TTL
    at(&f, mk(BodySpec { deadline_ns: T0 - 1, ..base.clone() }), "E_DEADLINE");
    at(&f, mk(BodySpec { deadline_ns: T0 + 16 * 60_000_000_000, ..base.clone() }), "E_DEADLINE");
    // the intent: another contract, under-funded, low gas, two intents, another intent kind
    let bad_items = [
        intents(&msg(&[DEVICE]), NEAR, 200).replace(FACTORY, "evil.near"),
        intents(&msg(&[DEVICE]), 199 * NEAR / 1000, 200),
        intents(&msg(&[DEVICE]), NEAR, 199),
    ];
    for items in bad_items {
        at(&f, mk(BodySpec { items_json: items, ..base.clone() }), "E_INTENT");
    }
    let one = intents(&msg(&[DEVICE]), NEAR, 200);
    let two = format!("[{0},{0}]", &one[1..one.len() - 1]);
    at(&f, mk(BodySpec { items_json: two, ..base.clone() }), "E_INTENT");
    let transfer = r#"[{"intent":"transfer","receiver_id":"evil.near","tokens":{"nep141:wrap.near":"1"}}]"#;
    at(&f, mk(BodySpec { items_json: transfer.into(), ..base.clone() }), "E_PAYLOAD");
    // an extra field on the auth_call (e.g. a future state_init) is refused
    let extra = one.replace("\"intent\":", "\"extra\":1,\"intent\":");
    at(&f, mk(BodySpec { items_json: extra, ..base.clone() }), "E_PAYLOAD");
    // msg rules = create_account's
    for (m, code) in [
        (msg(&[]), "E_BAD_KEYS"),
        (msg(&[DEVICE, DEVICE]), "E_BAD_KEYS"),
        (msg(&[DEVICE, DEVICE2, DEVICE, DEVICE2, DEVICE]), "E_BAD_KEYS"),
        (msg(&[DEVICE]).replace("\"v\":1", "\"v\":2"), "E_MSG"),
        (msg(&[DEVICE]).replace("\"caps\":null", "\"caps\":null,\"x\":1"), "E_MSG"),
        ("not json".to_string(), "E_MSG"),
    ] {
        at(&f, mk(BodySpec { items_json: intents(&m, NEAR, 200), ..base.clone() }), code);
    }
    let auto = |allowance: &str, key: &str| {
        serde_json::json!({"v": 1, "device_public_keys": [DEVICE], "caps": null,
            "automation": {"public_key": key, "allowance": allowance, "weekly_yocto": null}})
        .to_string()
    };
    at(
        &f,
        mk(BodySpec { items_json: intents(&auto("1", DEVICE2), NEAR, 200), ..base.clone() }),
        "E_ALLOWANCE",
    );
    let ok_allow = MIN_AUTOMATION_ALLOWANCE.to_string();
    at(
        &f,
        mk(BodySpec { items_json: intents(&auto(&ok_allow, DEVICE), NEAR, 200), ..base.clone() }),
        "E_BAD_KEYS",
    );
    // valid automation passes
    set("relayer.near", 0);
    f.check_create(mk(BodySpec {
        items_json: intents(&auto(&ok_allow, DEVICE2), NEAR, 200),
        ..base.clone()
    }));
    // already created
    let owner = aid(&s.owner_id());
    let account = f.account_for(owner);
    f.created.insert(account);
    at(&f, signed(&s, std), "E_EXISTS");
    set("relayer.near", PENDING_DEPOSIT.as_yoctonear());
    assert_code("E_EXISTS", || f.create_via_intents(signed(&s, std)));
}

#[test]
fn intents_failure_drops_the_record_only_for_its_nonce() {
    let s = Signer::secp256k1("k");
    let mut f = factory(true);
    precommit(&mut f, &s, Standard::Erc191);
    let owner = aid(&s.owner_id());
    let nonce = spec(&s, String::new()).nonce;
    // another attempt's failure (other nonce) leaves this record alone
    set_results(FACTORY, vec![PromiseResult::Failed]);
    f.on_intents_executed(owner.clone(), msg(&[DEVICE]), vec![0u8; 32].into());
    assert!(f.has_pending(owner.clone(), msg(&[DEVICE])));
    set_results(FACTORY, vec![PromiseResult::Successful(vec![])]);
    f.on_intents_executed(owner.clone(), msg(&[DEVICE]), nonce.to_vec().into());
    assert!(f.has_pending(owner.clone(), msg(&[DEVICE])), "success keeps it for on_auth");
    set_results(FACTORY, vec![PromiseResult::Failed]);
    f.on_intents_executed(owner.clone(), msg(&[DEVICE]), nonce.to_vec().into());
    assert!(!f.has_pending(owner, msg(&[DEVICE])));
    assert!(has_event("create_intent_failed"));
}

// ------------------------------------------------------------ on_auth (spec §7.4)

fn on_auth(f: &mut Factory, pred: &str, owner: &str, m: &str, deposit: u128) {
    set(pred, deposit);
    f.on_auth(aid(owner), m.to_string());
}

/// The refund batch: wrap near_deposit(amount) + ft_transfer_call(intents, amount, msg=owner).
fn assert_refund(owner: &str, amount: u128, reason: &str) {
    let cs = calls();
    let dep = cs.iter().find(|c| c.1 == "near_deposit").expect("near_deposit");
    assert_eq!((dep.0.as_str(), dep.3), ("wrap.near", amount));
    let t = cs.iter().find(|c| c.1 == "ft_transfer_call").expect("ft_transfer_call");
    let v: serde_json::Value = serde_json::from_str(&t.2).unwrap();
    assert_eq!(t.0, "wrap.near");
    assert_eq!(t.3, 1);
    assert_eq!(v["receiver_id"], "intents.near");
    assert_eq!(v["amount"], amount.to_string());
    assert_eq!(v["msg"], owner);
    assert!(cs.iter().any(|c| c.1 == "on_refund"));
    assert!(
        get_logs()
            .iter()
            .any(|l| l.contains("\"create_refunded\"") && l.contains(&format!("\"reason\":\"{reason}\""))),
        "{:?}",
        get_logs()
    );
    assert!(!cs.iter().any(|c| c.1 == "init"), "no account on a refund");
}

#[test]
fn on_auth_creates_only_against_a_matching_record() {
    for (s, std) in signers() {
        let mut f = factory(true);
        precommit(&mut f, &s, std);
        let owner = s.owner_id();
        on_auth(&mut f, "intents.near", &owner, &msg(&[DEVICE]), NEAR);
        let cs = calls();
        let init = cs.iter().find(|c| c.1 == "init").expect("init");
        let v: serde_json::Value = serde_json::from_str(&init.2).unwrap();
        assert_eq!(v["owner"], owner);
        let home = if std == Standard::RawEd25519 { "Solana" } else { "Near" };
        let kind = format!("{:?}", s.kind());
        assert_eq!(v["owner_auth"], serde_json::json!({"kind": kind, "home": home}));
        assert!(cs.iter().any(|c| c.1 == "on_create_intents"));
        assert!(!cs.iter().any(|c| c.1 == "ft_transfer_call"));
        assert!(!f.has_pending(aid(&owner), msg(&[DEVICE])), "single use");
        assert!(f.created.contains(&f.account_for(aid(&owner))));
        // a second on_auth for the same (replayed / resubmitted) intent refunds
        on_auth(&mut f, "intents.near", &owner, &msg(&[DEVICE]), NEAR);
        assert_refund(&owner, NEAR, "no_precommit");
    }
}

#[test]
fn on_auth_from_anyone_but_the_verifier_panics() {
    let s = Signer::p256("p");
    let mut f = factory(true);
    precommit(&mut f, &s, Standard::WebAuthn);
    assert_code("E_NOT_VERIFIER", || on_auth(&mut f, "evil.near", &s.owner_id(), &msg(&[DEVICE]), NEAR));
    assert!(f.has_pending(aid(&s.owner_id()), msg(&[DEVICE])));
    // after set_verifier, the old verifier is refused
    set("admin.near", 1);
    f.set_verifier(aid("intents2.near"));
    assert_code("E_NOT_VERIFIER", || on_auth(&mut f, "intents.near", &s.owner_id(), &msg(&[DEVICE]), NEAR));
}

#[test]
fn on_auth_refund_reasons_never_panic() {
    let s = Signer::p256("p");
    let owner = s.owner_id();
    // no precommit (front-run: payload sent straight to intents)
    let mut f = factory(true);
    on_auth(&mut f, "intents.near", &owner, &msg(&[DEVICE]), NEAR);
    assert_refund(&owner, NEAR, "no_precommit");
    // another msg than the one precommitted
    let mut f = factory(true);
    precommit(&mut f, &s, Standard::WebAuthn);
    on_auth(&mut f, "intents.near", &owner, &msg(&[DEVICE2]), NEAR);
    assert_refund(&owner, NEAR, "no_precommit");
    // another signer with the same msg
    on_auth(&mut f, "intents.near", &Signer::p256("x").owner_id(), &msg(&[DEVICE]), NEAR);
    assert_refund(&Signer::p256("x").owner_id(), NEAR, "no_precommit");
    // expired (deadline + grace passed)
    let mut f = factory(true);
    precommit(&mut f, &s, Standard::WebAuthn);
    testing_env!(ctx("intents.near", NEAR, T0 + 60_000_000_000 + PENDING_GRACE_NS + 1).build());
    f.on_auth(aid(&owner), msg(&[DEVICE]));
    assert_refund(&owner, NEAR, "no_precommit");
    assert!(!f.has_pending(aid(&owner), msg(&[DEVICE])));
    // within the grace it still creates
    let mut f = factory(true);
    precommit(&mut f, &s, Standard::WebAuthn);
    testing_env!(ctx("intents.near", NEAR, T0 + 60_000_000_000 + PENDING_GRACE_NS).build());
    f.on_auth(aid(&owner), msg(&[DEVICE]));
    assert!(calls().iter().any(|c| c.1 == "init"));
    // deposit other than the signed one
    let mut f = factory(true);
    precommit(&mut f, &s, Standard::WebAuthn);
    on_auth(&mut f, "intents.near", &owner, &msg(&[DEVICE]), NEAR - 1);
    assert_refund(&owner, NEAR - 1, "mismatch");
    // bad msg (can only come without a precommit, which already refunds; also checked alone)
    let mut f = factory(true);
    on_auth(&mut f, "intents.near", &owner, "garbage", NEAR);
    assert_refund(&owner, NEAR, "no_precommit");
    // under-funded: min_funding raised after the precommit (a DCL dex added is not possible,
    // so the record's deposit is forged below min here)
    let mut f = factory(true);
    precommit(&mut f, &s, Standard::WebAuthn);
    let key = pending_key(&owner, &msg(&[DEVICE]));
    let mut p: Pending = read(&key).unwrap();
    p.deposit = NEAR / 10;
    write(&key, &p);
    on_auth(&mut f, "intents.near", &owner, &msg(&[DEVICE]), NEAR / 10);
    assert_refund(&owner, NEAR / 10, "underfunded");
    // exists (created in between, e.g. by a NEAR-wallet create_account of the same id)
    let mut f = factory(true);
    precommit(&mut f, &s, Standard::WebAuthn);
    let account = f.account_for(aid(&owner));
    f.created.insert(account);
    on_auth(&mut f, "intents.near", &owner, &msg(&[DEVICE]), NEAR);
    assert_refund(&owner, NEAR, "exists");
    assert!(!f.has_pending(aid(&owner), msg(&[DEVICE])));
}

#[test]
fn on_auth_bad_msg_with_a_record_refunds() {
    // a record whose msg no longer passes (defence in depth: records are only written for
    // passing msgs, so this writes one by hand)
    let s = Signer::p256("p");
    let owner = s.owner_id();
    let mut f = factory(true);
    set("relayer.near", 0);
    write(
        &pending_key(&owner, "garbage"),
        &Pending {
            kind: OwnerKind::P256,
            home: Home::Near,
            expires_ns: T0 + 1,
            nonce: [0; 32],
            deposit: NEAR,
        },
    );
    on_auth(&mut f, "intents.near", &owner, "garbage", NEAR);
    assert_refund(&owner, NEAR, "bad_msg");
}

#[test]
fn create_failure_refunds_to_intents_and_frees_the_id() {
    let s = Signer::p256("p");
    let owner = aid(&s.owner_id());
    let mut f = factory(true);
    let account = f.account_for(owner.clone());
    f.created.insert(account.clone());
    set_results(FACTORY, vec![PromiseResult::Failed]);
    f.on_create_intents(owner.clone(), account.clone(), U128(NEAR));
    assert_refund(owner.as_str(), NEAR, "create_failed");
    assert!(has_event("create_failed"));
    assert!(!f.created.contains(&account));
    set_results(FACTORY, vec![PromiseResult::Successful(vec![])]);
    f.created.insert(account.clone());
    f.on_create_intents(owner, account.clone(), U128(NEAR));
    assert!(has_event("account_created"));
    assert!(calls().is_empty());
    assert!(f.created.contains(&account));
}

// ------------------------------------------------------------ owed refunds

#[test]
fn on_refund_records_what_intents_did_not_take() {
    let owner = aid(&Signer::p256("p").owner_id());
    let mut f = factory(true);
    // all taken
    set_results(FACTORY, vec![PromiseResult::Successful(format!("\"{NEAR}\"").into_bytes())]);
    f.on_refund(owner.clone(), U128(NEAR), U128(0), Ok(U128(NEAR)));
    assert_eq!(f.get_owed(owner.clone()).wnear.0 + f.get_owed(owner.clone()).near.0, 0);
    // intents refunded part (e.g. paused): the rest is wNEAR in the factory
    f.on_refund(owner.clone(), U128(NEAR), U128(0), Ok(U128(NEAR / 4)));
    assert_eq!((f.get_owed(owner.clone()).near.0, f.get_owed(owner.clone()).wnear.0), (0, 3 * NEAR / 4));
    assert!(has_event("refund_owed"));
    // the batch reverted: native stays native, wrapped stays wrapped (accumulates)
    f.on_refund(owner.clone(), U128(NEAR), U128(5), Err(PromiseError::Failed));
    assert_eq!(
        (f.get_owed(owner.clone()).near.0, f.get_owed(owner.clone()).wnear.0),
        (NEAR, 3 * NEAR / 4 + 5)
    );
    // retry sends both in one batch, clears the record first
    set("anyone.near", 0);
    f.retry_refund(owner.clone());
    let total = NEAR + 3 * NEAR / 4 + 5;
    let cs = calls();
    assert_eq!(cs.iter().find(|c| c.1 == "near_deposit").unwrap().3, NEAR);
    let t: serde_json::Value =
        serde_json::from_str(&cs.iter().find(|c| c.1 == "ft_transfer_call").unwrap().2).unwrap();
    assert_eq!((t["amount"].clone(), t["msg"].clone()), (total.to_string().into(), owner.to_string().into()));
    assert_eq!(f.get_owed(owner.clone()).near.0 + f.get_owed(owner.clone()).wnear.0, 0);
    set("anyone.near", 0);
    assert_code("E_NOTHING_OWED", || f.retry_refund(owner.clone()));
    // wNEAR-only retry: no near_deposit
    f.on_refund(owner.clone(), U128(0), U128(7), Err(PromiseError::Failed));
    set("anyone.near", 0);
    f.retry_refund(owner);
    assert!(!calls().iter().any(|c| c.1 == "near_deposit"));
}

// ------------------------------------------------------------ create_account unchanged

#[test]
fn create_account_args_unchanged() {
    let mut f = factory(true);
    set("alice.near", NEAR);
    let pk: PublicKey = DEVICE.parse().unwrap();
    f.create_account(Some(pk), None, None, None).detach();
    let cs = calls();
    let init = cs.iter().find(|c| c.1 == "init").unwrap();
    let v: serde_json::Value = serde_json::from_str(&init.2).unwrap();
    // the 1.2.0 init args (no owner_auth key)
    let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    // the 1.2.0 init args + `code_hash` (R2-11; a ≤ 1.5 account ignores unknown init fields)
    assert_eq!(keys, ["owner", "fee_config", "caps", "dex_allowlist", "wrap", "code_hash"]);
    assert_eq!(v["code_hash"], b58(&Base58CryptoHash::from([7u8; 32])));
    assert!(cs.iter().any(|c| c.1 == "on_create"));
    set("bob.near", NEAR);
    assert_code("E_BAD_KEYS", || f.create_account(None, None, None, None));
    set("bob.near", NEAR / 10);
    assert_code("E_MIN_FUNDING", || f.create_account(Some(DEVICE.parse().unwrap()), None, None, None));
    set("alice.near", NEAR);
    assert_code("E_EXISTS", || f.create_account(Some(DEVICE.parse().unwrap()), None, None, None));
    // signed creation for a NEAR wallet's own account id is impossible (implicit ids only)
}

// ------------------------------------------------------------ v1.6 venue allowlist entries

/// docs/venues-hooks.md rev 3: the mainnet allowlist entries of the four venue kinds.
const VENUE_ENTRIES: &str = r#"[
{"id":"aidols.near","kind":{"AidolsCurve":"Near"}},
{"id":"gra-fun.near","kind":{"AidolsCurve":"Near"}},
{"id":"gaypad.j1-racing.near","kind":{"AidolsCurve":"Jambo"}},
{"id":"v1.whole-market.near","kind":{"AidolsCurve":"Neardog"}},
{"id":"v2.whole-market.near","kind":{"AidolsCurve":"Neardog"}},
{"id":"patata-monster.near","kind":{"AidolsCurve":"Patata"}},
{"id":"launch.vistadev.near","kind":{"FactoryCurve":"VistaLaunch"}},
{"id":"dex.vistadev.near","kind":{"FactoryCurve":"VistaDex"}},
{"id":"nearrr-fun.near","kind":{"FactoryCurve":"Nearrr"}},
{"id":"curve10.latedata9580.near","kind":{"FactoryCurve":"Nira"}},
{"id":"meme-cooking.near","kind":{"FactoryCurve":"MemeCooking"}},
{"id":"dragonpad.near","kind":{"FactoryCurve":"Dragonpad"}},
{"id":"nearfunio.near","kind":{"TokenCurve":"NearFun"}},
{"id":"umbrafun.near","kind":{"TokenCurve":"Umbra"}},
{"id":"revshare-launch.near","kind":{"TokenCurve":"RevShare"}},
{"id":"nearmemefun.near","kind":{"TokenCurve":"Nearmemefun"}},
{"id":"token0.near","kind":{"TokenCurve":"Token0"}},
{"id":"chipfi.near","kind":{"TokenCurve":"Chipfi"}},
{"id":"npad.near","kind":{"TokenCurve":"Npad"}},
{"id":"exchange.kelytradevs.near","kind":"Kelytra"}
]"#;

/// The factory allowlist accepts every venue entry and passes it into TA init unchanged (both
/// doors: `create_account` and the signed `on_auth`); min funding counts only RheaDcl.
#[test]
fn allowlist_accepts_every_venue_entry_and_passes_it_to_init_unchanged() {
    let base = serde_json::json!([
        {"id": "v2.ref-finance.near", "kind": "RheaClassic"},
        {"id": "dclv2.ref-labs.near", "kind": "RheaDcl"},
        {"id": "dex.intear.near", "kind": "Plach"},
        {"id": "factory.shardsmarket.near", "kind": "ShardsToken"}
    ]);
    let venues: serde_json::Value = serde_json::from_str(VENUE_ENTRIES).unwrap();
    let all: Vec<serde_json::Value> =
        [base.as_array().unwrap().clone(), venues.as_array().unwrap().clone()].concat();
    let dexes: Vec<Dex> = serde_json::from_value(serde_json::Value::Array(all.clone())).unwrap();
    assert_eq!(dexes.len(), 24);
    // JSON round trip is exact (same shape the account parses)
    assert_eq!(serde_json::to_value(&dexes).unwrap(), serde_json::Value::Array(all.clone()));
    set("admin.near", 0);
    let mut f = Factory::new(
        aid("admin.near"),
        [7u8; 32].into(),
        FeeConfig { fee_bps: 75, fee_recipient: aid("fees.near") },
        dexes,
        aid("wrap.near"),
        Some(U64(0)),
    );
    assert_eq!(f.min_funding().as_yoctonear(), MIN_FUNDING.as_yoctonear() + DCL_REGISTRATION.as_yoctonear());
    assert_eq!(
        serde_json::to_value(f.get_config().dex_allowlist).unwrap(),
        serde_json::Value::Array(all.clone())
    );
    // create_account → init args carry the list verbatim
    set("alice.near", NEAR);
    f.create_account(Some(DEVICE.parse().unwrap()), None, None, None).detach();
    let init = calls().into_iter().find(|c| c.1 == "init").unwrap();
    let v: serde_json::Value = serde_json::from_str(&init.2).unwrap();
    assert_eq!(v["dex_allowlist"], serde_json::Value::Array(all.clone()));
    // signed path too
    set("admin.near", 1);
    f.set_code_hash([7u8; 32].into(), Some(true));
    let s = Signer::p256("venues");
    precommit(&mut f, &s, Standard::WebAuthn);
    on_auth(&mut f, "intents.near", &s.owner_id(), &msg(&[DEVICE]), NEAR);
    let init = calls().into_iter().find(|c| c.1 == "init").unwrap();
    let v: serde_json::Value = serde_json::from_str(&init.2).unwrap();
    assert_eq!(v["dex_allowlist"], serde_json::Value::Array(all));
    // an unknown pad is refused at parse (no silent default)
    let bad = r#"[{"id":"x.near","kind":{"TokenCurve":"Pump"}}]"#;
    assert!(serde_json::from_str::<Vec<Dex>>(bad).is_err());
}

/// Migration: a stored 1.2.0 allowlist (variants 0-3, borsh) decodes unchanged under 1.3.0,
/// and the venue variants take the next borsh tags (4-7), so 1.2.0 state stays readable.
#[test]
fn stored_120_allowlist_decodes_unchanged() {
    // borsh of 1.2.0 Vec<Dex>: [RheaClassic, RheaDcl, Plach, ShardsToken] with ids a/b/c/d
    let mut old = 4u32.to_le_bytes().to_vec();
    for (i, id) in ["a.near", "b.near", "c.near", "d.near"].iter().enumerate() {
        old.extend_from_slice(&(id.len() as u32).to_le_bytes());
        old.extend_from_slice(id.as_bytes());
        old.push(i as u8);
    }
    let v: Vec<Dex> = near_sdk::borsh::from_slice(&old).unwrap();
    let kinds: Vec<String> = v.iter().map(|d| serde_json::to_string(&d.kind).unwrap()).collect();
    assert_eq!(kinds, ["\"RheaClassic\"", "\"RheaDcl\"", "\"Plach\"", "\"ShardsToken\""]);
    assert_eq!(near_sdk::borsh::to_vec(&v).unwrap(), old, "re-encodes byte for byte");
    let tag = |k: DexKind| near_sdk::borsh::to_vec(&k).unwrap();
    assert_eq!(tag(DexKind::AidolsCurve(AidolsPad::Near)), [4, 0]);
    assert_eq!(tag(DexKind::AidolsCurve(AidolsPad::Patata)), [4, 1]);
    // rev 3: appended pads keep Near = 0 / Patata = 1
    assert_eq!(tag(DexKind::AidolsCurve(AidolsPad::Jambo)), [4, 2]);
    assert_eq!(tag(DexKind::AidolsCurve(AidolsPad::Neardog)), [4, 3]);
    // a stored rev-2 venue entry (Patata) still decodes
    let e: Dex =
        near_sdk::borsh::from_slice(&[&6u32.to_le_bytes()[..], b"p.near", &[4, 1]].concat()).unwrap();
    assert_eq!(serde_json::to_string(&e.kind).unwrap(), r#"{"AidolsCurve":"Patata"}"#);
    assert_eq!(tag(DexKind::FactoryCurve(FactoryPad::Dragonpad)), [5, 5]);
    assert_eq!(tag(DexKind::TokenCurve(TokenPad::Npad)), [6, 6]);
    assert_eq!(tag(DexKind::Kelytra), [7]);
}

/// V16-11 (internal review): the admin switches to an unflagged code hash between the
/// precommit and on_auth (e.g. a rollback to 1.5 code). on_auth refunds instead of creating a
/// signer-kind account on code that ignores `owner_auth`. RED before: init was called.
#[test]
fn v16_11_on_auth_rechecks_signed_code() {
    let s = Signer::p256("p");
    let mut f = factory(true);
    precommit(&mut f, &s, Standard::WebAuthn);
    set("admin.near", 1);
    f.set_code_hash([9u8; 32].into(), None);
    on_auth(&mut f, "intents.near", &s.owner_id(), &msg(&[DEVICE]), NEAR);
    assert_refund(&s.owner_id(), NEAR, "code_not_signed");
    assert!(!f.created.contains(&f.account_for(aid(&s.owner_id()))));
}

// ------------------------------------------------------------ admin levers (F-06, F-17, F-20)

/// A factory as the mainnet 1.2.0 state is after the in-place redeploy: no `ft` key (default
/// 24 h timelock), `code_hash` [7; 32], not flagged.
fn factory_default_timelock() -> Factory {
    let f = factory(false);
    env::storage_remove(KEY_CODE_TIMELOCK);
    env::storage_remove(KEY_SIGNED_CODE);
    env::storage_remove(KEY_PENDING_CODE); // factory(false)'s set_code_hash([7; 32]) = the stored hash
    f
}

fn b58(h: &Base58CryptoHash) -> String {
    serde_json::to_value(h).unwrap().as_str().unwrap().to_string()
}

fn at(pred: &str, deposit: u128, now: u64) {
    testing_env!(ctx(pred, deposit, now).build());
}

/// The code hash in the created account's UseGlobalContract action.
fn used_code() -> String {
    get_created_receipts()
        .into_iter()
        .flat_map(|r| r.actions)
        .find_map(|a| match a {
            MockAction::UseGlobalContract { contract_id, .. } => Some(format!("{contract_id:?}")),
            _ => None,
        })
        .expect("UseGlobalContract")
}

#[test]
fn code_hash_timelock_default_24h() {
    let mut f = factory_default_timelock();
    let (old, new) = (Base58CryptoHash::from([7u8; 32]), Base58CryptoHash::from([8u8; 32]));
    assert_eq!(f.get_admin_state().code_timelock_ns.0, CODE_TIMELOCK_NS);
    at("admin.near", 1, T0);
    f.set_code_hash(new, Some(true));
    assert!(has_event("code_hash_proposed"));
    let eta = T0 + CODE_TIMELOCK_NS;
    // pending: nothing changes before the eta
    for now in [T0, eta - 1] {
        at("relayer.near", 0, now);
        assert_eq!(f.get_config().code_hash, old);
        assert!(f.get_approved_code_hashes().is_empty(), "a pending hash is never approved");
        assert!(!f.get_signed_config().signed_code);
        let p = f.get_admin_state().pending_code.expect("pending");
        assert_eq!((p.code_hash, p.signed_code, p.eta_ns.0), (new, true, eta));
        assert_code("E_CODE_NOT_SIGNED", || f.check_create(signed(&Signer::p256("p"), Standard::WebAuthn)));
    }
    at("alice.near", NEAR, eta - 1);
    f.create_account(Some(DEVICE.parse().unwrap()), None, None, None).detach();
    assert!(used_code().contains(&b58(&old)), "{}", used_code());
    // effective at the eta, lazily (no poke)
    at("relayer.near", 0, eta);
    assert_eq!(f.get_config().code_hash, new);
    assert_eq!(f.get_approved_code_hashes(), vec![new]);
    assert!(f.get_admin_state().pending_code.is_none());
    assert!(f.get_signed_config().signed_code, "signed creation opens with it");
    at("bob.near", NEAR, eta);
    f.create_account(Some(DEVICE.parse().unwrap()), None, None, None).detach();
    assert!(used_code().contains(&b58(&new)), "{}", used_code());
    // the next admin call settles it into the stored pair
    at("admin.near", 1, eta + 1);
    f.set_code_hash([9u8; 32].into(), None);
    assert_eq!(f.code_hash, new);
    assert_eq!(f.get_approved_code_hashes(), vec![new], "still the settled flagged hash until the eta");
}

#[test]
fn code_hash_cancel_and_revoke() {
    let mut f = factory_default_timelock();
    let (h8, h9) = (Base58CryptoHash::from([8u8; 32]), Base58CryptoHash::from([9u8; 32]));
    at("admin.near", 0, T0);
    assert_code("Requires attached deposit of exactly 1 yoctoNEAR", || f.cancel_code_hash());
    at("admin.near", 1, T0);
    assert_code("E_NO_PENDING", || f.cancel_code_hash());
    at("admin.near", 1, T0);
    f.set_code_hash(h8, Some(true));
    at("mallory.near", 1, T0);
    assert_code("E_NOT_ADMIN", || f.cancel_code_hash());
    at("mallory.near", 1, T0);
    assert_code("E_NOT_ADMIN", || f.revoke_signed_code());
    at("admin.near", 1, T0 + 5);
    f.cancel_code_hash();
    assert!(has_event("code_hash_cancelled"));
    at("relayer.near", 0, T0 + CODE_TIMELOCK_NS + 1);
    assert!(f.get_approved_code_hashes().is_empty(), "cancelled never takes effect");
    assert_eq!(f.get_config().code_hash, Base58CryptoHash::from([7u8; 32]));
    // effective, then revoked at once (and a pending proposal with it)
    at("admin.near", 1, T0 + CODE_TIMELOCK_NS + 1);
    f.set_code_hash(h8, Some(true));
    let t1 = T0 + 2 * CODE_TIMELOCK_NS + 1;
    at("admin.near", 1, t1);
    f.set_code_hash(h9, Some(true)); // settles h8, proposes h9
    at("relayer.near", 0, t1);
    assert_eq!(f.get_approved_code_hashes(), vec![h8]);
    at("admin.near", 1, t1 + 1);
    f.revoke_signed_code();
    assert!(has_event("signed_code_revoked"));
    assert!(f.get_approved_code_hashes().is_empty(), "revoked immediately");
    assert!(f.get_admin_state().pending_code.is_none());
    at("relayer.near", 0, t1 + 2 * CODE_TIMELOCK_NS);
    assert!(f.get_approved_code_hashes().is_empty(), "the pending h9 went with the revoke");
    assert_eq!(f.get_config().code_hash, h8, "the config still names it; creation on it is refused (R2-08)");
    assert_code("E_CODE_REVOKED", || f.check_create(signed(&Signer::p256("p"), Standard::WebAuthn)));
    // an effective-but-unsettled proposal is revoked too
    at("admin.near", 1, t1 + 3);
    f.set_code_hash(h9, Some(true));
    at("admin.near", 1, t1 + 3 + CODE_TIMELOCK_NS);
    f.revoke_signed_code();
    assert_eq!(f.get_config().code_hash, h9);
    assert!(f.get_approved_code_hashes().is_empty());
}

#[test]
fn new_sets_the_timelock_for_fresh_factories() {
    set("admin.near", 0);
    let mut f = Factory::new(
        aid("admin.near"),
        [7u8; 32].into(),
        FeeConfig { fee_bps: 75, fee_recipient: aid("fees.near") },
        vec![],
        aid("wrap.near"),
        Some(U64(60_000_000_000)),
    );
    assert_eq!(f.get_admin_state().code_timelock_ns.0, 60_000_000_000);
    at("admin.near", 1, T0);
    f.set_code_hash([8u8; 32].into(), Some(true));
    at("x.near", 0, T0 + 59_999_999_999);
    assert!(f.get_approved_code_hashes().is_empty());
    at("x.near", 0, T0 + 60_000_000_000);
    assert_eq!(f.get_approved_code_hashes().len(), 1);
}

#[test]
fn set_dex_allowlist_and_fee_config() {
    let mut f = factory(true);
    let venues: Vec<Dex> = serde_json::from_str(VENUE_ENTRIES).unwrap();
    let base: Vec<Dex> = serde_json::from_value(serde_json::json!([
        {"id": "v2.ref-finance.near", "kind": "RheaClassic"},
        {"id": "dclv2.ref-labs.near", "kind": "RheaDcl"},
        {"id": "dex.intear.near", "kind": "Plach"},
        {"id": "factory.shardsmarket.near", "kind": "ShardsToken"}
    ]))
    .unwrap();
    let full = [base.clone(), venues].concat();
    at("mallory.near", 1, T0);
    assert_code("E_NOT_ADMIN", || f.set_dex_allowlist(full.clone()));
    at("admin.near", 0, T0);
    assert_code("Requires attached deposit of exactly 1 yoctoNEAR", || f.set_dex_allowlist(full.clone()));
    for bad in
        [vec![], [full.clone(), full[..1].to_vec()].concat(), [full.clone(), full[..9].to_vec()].concat()]
    {
        at("admin.near", 1, T0);
        assert_code("E_BAD_ALLOWLIST", || f.set_dex_allowlist(bad));
    }
    at("admin.near", 1, T0);
    f.set_dex_allowlist(full.clone());
    assert!(has_event("dex_allowlist_proposed"));
    let want = serde_json::to_value(&full).unwrap();
    assert_eq!(serde_json::to_value(f.get_config().dex_allowlist).unwrap(), want);
    assert_eq!(f.min_funding().as_yoctonear(), MIN_FUNDING.as_yoctonear() + DCL_REGISTRATION.as_yoctonear());
    at("alice.near", NEAR, T0);
    f.create_account(Some(DEVICE.parse().unwrap()), None, None, None).detach();
    let init = calls().into_iter().find(|c| c.1 == "init").unwrap();
    let v: serde_json::Value = serde_json::from_str(&init.2).unwrap();
    assert_eq!(v["dex_allowlist"], want, "new accounts get the new list");
    // fee config
    let fee = |bps: u16| FeeConfig { fee_bps: bps, fee_recipient: aid("treasury.near") };
    at("mallory.near", 1, T0);
    assert_code("E_NOT_ADMIN", || f.set_fee_config(fee(50)));
    at("admin.near", 1, T0);
    assert_code("E_FEE", || f.set_fee_config(fee(101)));
    at("admin.near", 1, T0);
    f.set_fee_config(fee(50));
    assert!(has_event("fee_config_proposed"));
    at("bob.near", NEAR, T0);
    f.create_account(Some(DEVICE.parse().unwrap()), None, None, None).detach();
    let init = calls().into_iter().find(|c| c.1 == "init").unwrap();
    let v: serde_json::Value = serde_json::from_str(&init.2).unwrap();
    assert_eq!(v["fee_config"], serde_json::json!({"fee_bps": 50, "fee_recipient": "treasury.near"}));
    // an invalid recipient id never parses (JSON AccountId)
    assert!(serde_json::from_str::<FeeConfig>(r#"{"fee_bps":1,"fee_recipient":"NOT VALID"}"#).is_err());
}

#[test]
fn two_step_admin_transfer() {
    let mut f = factory(true);
    at("admin.near", 1, T0);
    assert_code("E_NO_PENDING", || f.accept_admin());
    at("mallory.near", 1, T0);
    assert_code("E_NOT_ADMIN", || f.propose_admin(aid("mallory.near")));
    at("admin.near", 1, T0);
    f.propose_admin(aid("multisig.near"));
    assert!(has_event("admin_proposed"));
    assert_eq!(f.get_admin_state().pending_admin, Some(aid("multisig.near")));
    assert_eq!(f.get_config().admin, aid("admin.near"), "nothing changes before accept");
    at("mallory.near", 1, T0);
    assert_code("E_NOT_ADMIN", || f.accept_admin());
    at("multisig.near", 0, T0);
    assert_code("Requires attached deposit of exactly 1 yoctoNEAR", || f.accept_admin());
    // a new proposal replaces the old one
    at("admin.near", 1, T0);
    f.propose_admin(aid("multisig2.near"));
    at("multisig.near", 1, T0);
    assert_code("E_NOT_ADMIN", || f.accept_admin());
    at("multisig2.near", 1, T0);
    f.accept_admin();
    assert!(has_event("admin_accepted"));
    assert_eq!(f.get_config().admin, aid("multisig2.near"));
    assert!(f.get_admin_state().pending_admin.is_none());
    // the old admin is out, the new one in
    at("admin.near", 1, T0);
    assert_code("E_NOT_ADMIN", || f.set_fee_config(FeeConfig { fee_bps: 1, fee_recipient: aid("x.near") }));
    at("multisig2.near", 1, T0);
    f.set_fee_config(FeeConfig { fee_bps: 1, fee_recipient: aid("x.near") });
}

/// The one-time bootstrap of the in-place 1.2.0 → 1.3.0 redeploy: immediate, once, self only.
#[test]
fn bootstrap_migrate_once() {
    let mut f = factory_default_timelock(); // 24 h timelock, code [7; 32], unflagged
    let full: Vec<Dex> = serde_json::from_str(VENUE_ENTRIES).unwrap();
    let h = Base58CryptoHash::from([8u8; 32]);
    // a factory made by 1.3.0 `new` never bootstraps
    at(FACTORY, 0, T0);
    assert_code("E_BOOTSTRAPPED", || f.migrate(h, true, full.clone()));
    env::storage_remove(KEY_BOOTSTRAPPED); // = the mainnet 1.2.0 state
                                           // (#[private] is enforced by the wasm entry point: sandbox bootstrap_120_to_130_in_one_tx)
    at(FACTORY, 0, T0);
    assert_code("E_BAD_ALLOWLIST", || f.migrate(h, true, vec![]));
    // R2-13: any 1.3.0 raw key (here a code proposal, or the timelock a 649427c1 `new` wrote)
    // means this is not the 1.2.0 state: refused even without `fb`
    at("admin.near", 1, T0);
    f.set_code_hash([9u8; 32].into(), Some(true));
    at(FACTORY, 0, T0 + 1);
    assert_code("E_BOOTSTRAPPED", || f.migrate(h, true, full.clone()));
    env::storage_remove(KEY_PENDING_CODE);
    env::storage_write(KEY_CODE_TIMELOCK, &0u64.to_le_bytes());
    at(FACTORY, 0, T0 + 1);
    assert_code("E_BOOTSTRAPPED", || f.migrate(h, true, full.clone()));
    env::storage_remove(KEY_CODE_TIMELOCK);
    at(FACTORY, 0, T0 + 1);
    f.migrate(h, true, full.clone());
    assert!(has_event("factory_bootstrapped"));
    // immediate: creation code, approval, signed creation, allowlist
    assert_eq!(f.get_config().code_hash, h);
    assert_eq!(f.get_approved_code_hashes(), vec![h]);
    assert!(f.get_signed_config().signed_code);
    assert!(f.get_admin_state().pending_code.is_none());
    assert_eq!(
        serde_json::to_value(f.get_config().dex_allowlist).unwrap(),
        serde_json::to_value(&full).unwrap()
    );
    at(FACTORY, 0, T0 + 2);
    assert_code("E_BOOTSTRAPPED", || f.migrate([10u8; 32].into(), true, full.clone()));
    // every later code change is timelocked
    at("admin.near", 1, T0 + 3);
    f.set_code_hash([10u8; 32].into(), Some(true));
    at("x.near", 0, T0 + 3 + CODE_TIMELOCK_NS - 1);
    assert_eq!(f.get_approved_code_hashes(), vec![h]);
    at("x.near", 0, T0 + 3 + CODE_TIMELOCK_NS);
    assert_eq!(f.get_approved_code_hashes(), vec![Base58CryptoHash::from([10u8; 32])]);
}

// ------------------------------------------------------------ internal review 2
// (docs/audit/v160-internal-review-2.md; PoCs from its patch, green after the fixes)

/// R2-07 (Medium) PoC. The review's hostile list of 32 `RheaDcl` entries is now refused at
/// once (MAX_DCL_ENTRIES = 2), so the PoC body runs with the largest list the cap allows (2
/// hostile DCL entries); it must still not reach `init` one block later (24 h timelock).
#[test]
fn r2_07_allowlist_change_waits_for_the_timelock() {
    let mut f = factory_default_timelock();
    let hostile32: Vec<Dex> = (0..MAX_DEXES)
        .map(|i| Dex { id: aid(&format!("dcl{i}.attacker.near")), kind: DexKind::RheaDcl })
        .collect();
    at("admin.near", 1, T0);
    assert_code("E_BAD_ALLOWLIST", || f.set_dex_allowlist(hostile32.clone()));
    let hostile = hostile32[..MAX_DCL_ENTRIES].to_vec();
    at("admin.near", 1, T0);
    f.set_dex_allowlist(hostile);
    at("alice.near", 0, T0);
    let funding = f.min_funding().as_yoctonear();
    assert_eq!(funding, MIN_FUNDING.as_yoctonear(), "min funding unchanged before the eta");
    at("alice.near", funding, T0 + 1);
    f.create_account(Some(DEVICE.parse().unwrap()), None, None, None).detach();
    let init = calls().into_iter().find(|c| c.1 == "init").unwrap();
    let v: serde_json::Value = serde_json::from_str(&init.2).unwrap();
    let hostile_now =
        v["dex_allowlist"].as_array().unwrap().iter().filter(|d| d["kind"] == "RheaDcl").count();
    assert_eq!(hostile_now, 0, "{hostile_now} hostile DCL entries (0.5 N each) reached init one block later");
    // visible while pending, cancellable
    at("x.near", 0, T0 + 2);
    assert!(f.get_admin_state().pending_dex_allowlist.is_some());
    at("admin.near", 1, T0 + 2);
    f.cancel_dex_allowlist();
    at("x.near", 0, T0 + CODE_TIMELOCK_NS + 5);
    assert!(f.get_config().dex_allowlist.is_empty(), "cancelled never takes effect");
    at("admin.near", 1, T0 + CODE_TIMELOCK_NS + 5);
    assert_code("E_NO_PENDING", || f.cancel_dex_allowlist());
}

/// R2-07: the fee config waits for the timelock too, and is effective lazily at the eta.
#[test]
fn r2_07_fee_change_waits_for_the_timelock() {
    let mut f = factory_default_timelock();
    let fee = FeeConfig { fee_bps: 100, fee_recipient: aid("attacker.near") };
    at("admin.near", 1, T0);
    f.set_fee_config(fee);
    let eta = T0 + CODE_TIMELOCK_NS;
    at("x.near", 0, eta - 1);
    assert_eq!(f.get_config().fee_config.fee_recipient, aid("fees.near"));
    assert_eq!(f.get_admin_state().pending_fee_config.unwrap().eta_ns.0, eta);
    at("alice.near", NEAR, eta - 1);
    f.create_account(Some(DEVICE.parse().unwrap()), None, None, None).detach();
    let init = calls().into_iter().find(|c| c.1 == "init").unwrap();
    assert!(init.2.contains("\"fees.near\""), "old fee before the eta");
    at("x.near", 0, eta);
    assert_eq!(f.get_config().fee_config.fee_recipient, aid("attacker.near"));
    assert!(f.get_admin_state().pending_fee_config.is_none());
    // cancel before the eta
    at("admin.near", 1, eta);
    f.set_fee_config(FeeConfig { fee_bps: 1, fee_recipient: aid("x.near") });
    at("admin.near", 1, eta + 1);
    f.cancel_fee_config();
    assert!(has_event("fee_config_cancelled"));
    at("x.near", 0, eta + 2 * CODE_TIMELOCK_NS);
    assert_eq!(f.get_config().fee_config.fee_recipient, aid("attacker.near"));
}

/// R2-07: strict entries (and the bootstrap uses the same check).
#[test]
fn r2_07_allowlist_entries_are_validated() {
    let mut f = factory(true);
    let d = |id: &str, kind: DexKind| Dex { id: aid(id), kind };
    let ok = d("v2.ref-finance.near", DexKind::RheaClassic);
    for bad in [
        vec![
            ok.clone(),
            d("a.near", DexKind::RheaDcl),
            d("b.near", DexKind::RheaDcl),
            d("c.near", DexKind::RheaDcl),
        ],
        vec![ok.clone(), d(FACTORY, DexKind::Plach)],
        vec![ok.clone(), d("abcdef0123456789.trade.unrlzd.near", DexKind::Plach)],
        vec![ok.clone(), d("wrap.near", DexKind::RheaClassic)],
        vec![ok.clone(), d("intents.near", DexKind::Plach)],
        vec![ok.clone(), d(&"a".repeat(64), DexKind::Plach)],
        vec![ok.clone(), d("0x1111111111111111111111111111111111111111", DexKind::Plach)],
    ] {
        at("admin.near", 1, T0);
        assert_code("E_BAD_ALLOWLIST", || f.set_dex_allowlist(bad));
    }
    at("admin.near", 1, T0);
    f.set_dex_allowlist(vec![
        ok,
        d("dclv2.ref-labs.near", DexKind::RheaDcl),
        d("dcl2.near", DexKind::RheaDcl),
    ]);
    assert_eq!(
        f.min_funding().as_yoctonear(),
        MIN_FUNDING.as_yoctonear() + 2 * DCL_REGISTRATION.as_yoctonear()
    );
    // the documented bound on init deposits holds for any accepted list
    assert!(
        f.min_funding().as_yoctonear()
            <= MIN_FUNDING.as_yoctonear() + MAX_DCL_ENTRIES as u128 * DCL_REGISTRATION.as_yoctonear()
    );
}

/// R2-08 PoC (verbatim).
#[test]
fn r2_08_revoked_code_is_not_used_for_new_accounts() {
    let mut f = factory_default_timelock();
    let bad = Base58CryptoHash::from([8u8; 32]);
    at("admin.near", 1, T0);
    f.set_code_hash(bad, Some(true));
    let t = T0 + CODE_TIMELOCK_NS;
    at("admin.near", 1, t);
    f.revoke_signed_code();
    at("alice.near", NEAR, t + 1);
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        f.create_account(Some(DEVICE.parse().unwrap()), None, None, None).detach()
    }));
    assert!(
        r.is_err() || !used_code().contains(&b58(&bad)),
        "new account created on the revoked code {}",
        used_code()
    );
    // the refusal is E_CODE_REVOKED, and a new effective proposal (even the same hash) lifts it
    at("alice.near", NEAR, t + 1);
    assert_code("E_CODE_REVOKED", || f.create_account(Some(DEVICE.parse().unwrap()), None, None, None));
    assert_eq!(f.get_admin_state().revoked_code, Some(bad));
    at("admin.near", 1, t + 2);
    f.set_code_hash([9u8; 32].into(), None);
    at("alice.near", NEAR, t + 2 + CODE_TIMELOCK_NS);
    assert!(f.get_admin_state().revoked_code.is_none());
    f.create_account(Some(DEVICE.parse().unwrap()), None, None, None).detach();
    assert!(used_code().contains(&b58(&Base58CryptoHash::from([9u8; 32]))));
}

/// R2-08: pause is instant on both doors (on_auth refunds), resume waits for the timelock.
#[test]
fn r2_08_pause_instant_resume_timelocked() {
    let mut f = factory_default_timelock();
    at("mallory.near", 1, T0);
    assert_code("E_NOT_ADMIN", || f.pause_creation());
    at("admin.near", 1, T0);
    assert_code("E_NOT_PAUSED", || f.resume_creation());
    // a signed creation precommitted before the pause (flag the code first, 24 h)
    at("admin.near", 1, T0);
    f.set_code_hash([7u8; 32].into(), Some(true));
    let t = T0 + CODE_TIMELOCK_NS;
    let s = Signer::p256("pause");
    let mp = s.sign_intents(
        Standard::WebAuthn,
        &BodySpec {
            deadline_ns: t + 60_000_000_000,
            nonce: owner_auth::versioned_nonce([1; 4], t + 60_000_000_000, [3; 15]),
            ..spec(&s, intents(&msg(&[DEVICE]), NEAR, 200))
        },
    );
    at("relayer.near", PENDING_DEPOSIT.as_yoctonear(), t);
    f.create_via_intents(mp.clone()).detach();
    at("admin.near", 1, t + 1);
    f.pause_creation();
    assert!(has_event("creation_paused"));
    assert!(f.get_admin_state().creation_paused);
    at("alice.near", NEAR, t + 1);
    assert_code("E_PAUSED", || f.create_account(Some(DEVICE.parse().unwrap()), None, None, None));
    at("relayer.near", 0, t + 1);
    assert_code("E_PAUSED", || f.check_create(mp.clone()));
    testing_env!(ctx("intents.near", NEAR, t + 2).build());
    f.on_auth(aid(&s.owner_id()), msg(&[DEVICE]));
    assert_refund(&s.owner_id(), NEAR, "paused");
    // resume: timelocked
    at("admin.near", 1, t + 3);
    f.resume_creation();
    let eta = t + 3 + CODE_TIMELOCK_NS;
    at("x.near", 0, eta - 1);
    assert!(f.get_admin_state().creation_paused);
    assert_eq!(f.get_admin_state().resume_eta_ns.unwrap().0, eta);
    at("alice.near", NEAR, eta - 1);
    assert_code("E_PAUSED", || f.create_account(Some(DEVICE.parse().unwrap()), None, None, None));
    // pausing again cancels the pending resume
    at("admin.near", 1, eta - 1);
    f.pause_creation();
    at("alice.near", NEAR, eta + 1);
    assert_code("E_PAUSED", || f.create_account(Some(DEVICE.parse().unwrap()), None, None, None));
    at("admin.near", 1, eta + 1);
    f.resume_creation();
    at("alice.near", NEAR, eta + 1 + CODE_TIMELOCK_NS);
    assert!(!f.get_admin_state().creation_paused);
    f.create_account(Some(DEVICE.parse().unwrap()), None, None, None).detach();
    assert!(calls().iter().any(|c| c.1 == "init"));
}

/// R2-11: both doors pass the installed code hash (the effective one) to `init`.
#[test]
fn r2_11_init_args_carry_the_installed_code_hash() {
    let mut f = factory_default_timelock();
    at("admin.near", 1, T0);
    f.set_code_hash([8u8; 32].into(), Some(true));
    let t = T0 + CODE_TIMELOCK_NS;
    at("alice.near", NEAR, t);
    f.create_account(Some(DEVICE.parse().unwrap()), None, None, None).detach();
    let init = calls().into_iter().find(|c| c.1 == "init").unwrap();
    let v: serde_json::Value = serde_json::from_str(&init.2).unwrap();
    let h8 = b58(&Base58CryptoHash::from([8u8; 32]));
    assert_eq!(v["code_hash"], h8);
    assert!(used_code().contains(&h8), "init's code_hash = the installed code");
    // signed door
    let s = Signer::p256("r211");
    let mp = s.sign_intents(
        Standard::WebAuthn,
        &BodySpec {
            deadline_ns: t + 60_000_000_000,
            nonce: owner_auth::versioned_nonce([1; 4], t + 60_000_000_000, [4; 15]),
            ..spec(&s, intents(&msg(&[DEVICE]), NEAR, 200))
        },
    );
    at("relayer.near", PENDING_DEPOSIT.as_yoctonear(), t);
    f.create_via_intents(mp).detach();
    testing_env!(ctx("intents.near", NEAR, t + 1).build());
    f.on_auth(aid(&s.owner_id()), msg(&[DEVICE]));
    let init = calls().into_iter().find(|c| c.1 == "init").unwrap();
    let v: serde_json::Value = serde_json::from_str(&init.2).unwrap();
    assert_eq!(v["code_hash"], h8);
    assert!(v["owner_auth"].is_object());
}

/// F4 (external audit; was the PoC `ext_audit_set_verifier_waits_for_the_timelock`):
/// `set_verifier` only proposes. Until the eta the old verifier stays in force everywhere: owed
/// refunds (the permissionless `retry_refund`) still go to it, and `on_auth` still accepts only
/// it. At the eta the proposal is effective (lazily) and the next admin call records it
/// (`verifier_set`). `cancel_verifier` drops a proposal; a verifier the allowlist lists is refused.
#[test]
fn ext_audit_set_verifier_waits_for_the_timelock() {
    const H24: u64 = 24 * 3_600 * 1_000_000_000;
    let owner = aid(&Signer::p256("p").owner_id());
    let mut f = Factory::new(
        aid("admin.near"),
        [7u8; 32].into(),
        FeeConfig { fee_bps: 75, fee_recipient: aid("fees.near") },
        vec![Dex { id: aid("v2.ref-finance.near"), kind: DexKind::RheaClassic }],
        aid("wrap.near"),
        None, // the mainnet 24 h timelock
    );
    set_results(FACTORY, vec![]);
    f.on_refund(owner.clone(), U128(0), U128(3 * NEAR), Err(PromiseError::Failed));
    set("admin.near", 1);
    f.set_verifier(aid("evil.near"));
    assert!(has_event("verifier_proposed"));
    let p = f.get_admin_state().pending_verifier.unwrap();
    assert_eq!((p.verifier, p.eta_ns.0), (aid("evil.near"), T0 + H24));
    // same block: the refund still goes to intents.near, and only intents.near may call on_auth
    set("anyone.near", 0);
    f.retry_refund(owner.clone());
    let to = calls().into_iter().find(|c| c.1 == "ft_transfer_call").unwrap();
    let t: serde_json::Value = serde_json::from_str(&to.2).unwrap();
    assert_eq!(t["receiver_id"], "intents.near");
    assert_eq!(f.get_signed_config().verifier, aid(DEFAULT_VERIFIER));
    testing_env!(ctx("evil.near", NEAR, T0 + H24 - 1).build());
    assert_code("E_NOT_VERIFIER", || f.on_auth(owner.clone(), msg(&[DEVICE])));
    // cancel drops it; nothing to cancel twice
    at("admin.near", 1, T0 + 1);
    f.cancel_verifier();
    assert!(f.get_admin_state().pending_verifier.is_none());
    at("admin.near", 1, T0 + 2);
    assert_code("E_NO_PENDING", || f.cancel_verifier());
    // a verifier the allowlist lists is refused
    at("admin.near", 1, T0 + 3);
    assert_code("E_BAD_ALLOWLIST", || f.set_verifier(aid("v2.ref-finance.near")));
    // a new proposal: effective at its eta (lazily), recorded by the next admin call
    at("admin.near", 1, T0 + 4);
    f.set_verifier(aid("intents2.near"));
    at("anyone.near", 0, T0 + 4 + H24 - 1);
    assert_eq!(f.get_signed_config().verifier, aid(DEFAULT_VERIFIER));
    at("anyone.near", 0, T0 + 4 + H24);
    assert_eq!(f.get_signed_config().verifier, aid("intents2.near"));
    assert!(f.get_admin_state().pending_verifier.is_none());
    at("admin.near", 1, T0 + 4 + H24);
    f.pause_creation();
    assert!(!has_event("verifier_set"), "pause doesn't settle");
    at("admin.near", 1, T0 + 5 + H24);
    f.set_fee_config(FeeConfig { fee_bps: 75, fee_recipient: aid("fees.near") });
    assert!(has_event("verifier_set"));
    assert_eq!(f.get_signed_config().verifier, aid("intents2.near"));
}
