//! v1.6.0 universal owner (docs/owner-v16-spec.md): the signed door, its negative matrix, the
//! byte-for-byte equivalence of both doors, owner kind/init/migrate, auth keys, home withdraws,
//! HOME_DEST and the factory-approved signed upgrade. Mocked chain with the real host crypto.
use super::intents::{pk_str, signed as signed_quote, test_sk, wcc};
use super::*;
use crate::owner::{self as ow, OwnerAuth, HOME_DEST, K_OWNER_AUTH};
use near_sdk::serde_json::{json, Value};
use owner_auth::testkit::{with_high_s, with_v27, BodySpec, Signer};
use owner_auth::{self as oa, Home, MultiPayload, OwnerAuthInit, OwnerKind, PublicKey as AuthKey, Standard};

const TA: &str = "0123456789abcdef.trade.unrlzd.near";
const RELAYER: &str = "relayer.unrlzd.near";

/// `current_account_id = account`, caller `pred` with `deposit`.
fn at(account: &str, pred: &str, deposit: u128, now: u64) {
    testing_env!(VMContextBuilder::new()
        .current_account_id(a(account))
        .predecessor_account_id(a(pred))
        .signer_account_id(a(pred))
        .attached_deposit(NearToken::from_yoctonear(deposit))
        .account_balance(NearToken::from_yoctonear(10 * NEAR))
        .block_timestamp(now)
        // headroom: the mock resets usage per context while raw storage persists (a pruned
        // nonce store would otherwise underflow it)
        .storage_usage(100_000)
        .prepaid_gas(Gas::from_tgas(300))
        .build());
}

/// A fresh TA at `account` owned by `owner` (init as factory 1.2/1.3 would call it).
fn ta_at(account: &str, owner: &str, init: Option<OwnerAuthInit>, now: u64) -> TradingAccount {
    at(account, "tt.near", 0, now);
    near_sdk::mock::with_mocked_blockchain(|b| {
        b.take_storage();
    });
    at(account, "tt.near", 0, now);
    TradingAccount::init(
        a(owner),
        FeeConfig { fee_bps: 100, fee_recipient: a("fees.near") },
        caps(2 * NEAR, 5 * NEAR),
        vec![
            Dex { id: a("v2.ref-finance.near"), kind: DexKind::RheaClassic },
            Dex { id: a("dclv2.ref-labs.near"), kind: DexKind::RheaDcl },
        ],
        a("wrap.near"),
        None,
        init,
        None,
    )
}

fn set_auth(a: &OwnerAuth) {
    env::storage_write(K_OWNER_AUTH, &near_sdk::borsh::to_vec(a).unwrap());
}

fn auth_of(c: &TradingAccount) -> OwnerAuth {
    ow::owner_auth(&c.get_config().owner)
}

fn salt_of(c: &TradingAccount) -> [u8; 4] {
    auth_of(c).salt
}

/// Signs `ops` (JSON array) for the TA at `account` with `std`, deadline now + 60 s.
fn sign(s: &Signer, std: Standard, account: &str, c: &TradingAccount, ops: &str, now: u64) -> MultiPayload {
    sign_with(s, std, account, &s.owner_id(), salt_of(c), ops, now, now + 60 * NS_PER_SEC, 1)
}

#[allow(clippy::too_many_arguments)]
fn sign_with(
    s: &Signer,
    std: Standard,
    account: &str,
    signer_id: &str,
    salt: [u8; 4],
    ops: &str,
    now: u64,
    deadline: u64,
    rnd: u8,
) -> MultiPayload {
    let _ = now;
    let dl = deadline / 1_000_000 * 1_000_000;
    s.sign_ops(
        std,
        &BodySpec {
            signer_id: signer_id.into(),
            verifying_contract: account.into(),
            deadline_ns: dl,
            nonce: oa::versioned_nonce(salt, dl, [rnd; 15]),
            items_json: ops.into(),
        },
    )
}

fn relayer(account: &str, now: u64) {
    at(account, RELAYER, 0, now);
}

/// "ok", or the panic code.
fn outcome<F: FnOnce()>(f: F) -> String {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(()) => "ok".into(),
        Err(e) => {
            let m = e
                .downcast_ref::<String>()
                .cloned()
                .or(e.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_default();
            match m.split_once("panic_msg: \"") {
                Some((_, rest)) => rest.split('"').next().unwrap_or_default().to_string(),
                None => m,
            }
        }
    }
}

fn run_signed(c: &mut TradingAccount, account: &str, mp: MultiPayload, now: u64) -> String {
    relayer(account, now);
    outcome(|| c.owner_signed(mp))
}

fn check_err(c: &TradingAccount, account: &str, mp: MultiPayload, now: u64) -> String {
    relayer(account, now);
    outcome(|| {
        c.owner_signed_check(mp);
    })
}

/// Every signer kind with the standards it signs through.
fn owners() -> Vec<(Signer, Vec<Standard>)> {
    vec![
        (Signer::ed25519("o-ed"), vec![Standard::RawEd25519, Standard::Nep413, Standard::WebAuthn]),
        (Signer::secp256k1("o-k1"), vec![Standard::Erc191]),
        (Signer::p256("o-r1"), vec![Standard::WebAuthn]),
    ]
}

fn signer_ta(s: &Signer, now: u64) -> TradingAccount {
    let home = if matches!(s, Signer::Ed25519(_)) { Home::Solana } else { Home::Near };
    ta_at(TA, &s.owner_id(), Some(OwnerAuthInit { kind: s.kind(), home }), now)
}

// ============================================================ A3 cross-language vectors

#[derive(near_sdk::serde::Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct TaVectors {
    vectors: Vec<TaVector>,
}

#[derive(near_sdk::serde::Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct TaVector {
    name: String,
    expect: String,
    ctx: Value,
    signed: Value,
}

/// packages/owner-payload/fixtures/ta-vectors.json (A3, @noble-signed; mainnet simulate proved
/// the arms): the TA reaches exactly the TS verifier's verdict for every vector.
#[test]
fn v160_ts_vectors_same_verdict() {
    let v: TaVectors =
        serde_json::from_str(include_str!("../../tests/fixtures/owner_ta_vectors.json")).unwrap();
    let mut n = 0;
    for x in v.vectors {
        let c = &x.ctx;
        if c.get("expect").is_some() {
            continue; // creation intents / sign-in: not TA payloads
        }
        let now = c["nowMs"].as_u64().unwrap() * 1_000_000;
        let account = c["verifyingContract"].as_str().unwrap();
        let owner = c["owner"].as_str().unwrap();
        let kind: OwnerKind = serde_json::from_value(c["ownerKind"].clone()).unwrap();
        let mut ta = ta_at(account, owner, None, now);
        let salt = oa::unhex32(&format!("{}{}", c["salt"].as_str().unwrap(), "0".repeat(56))).unwrap();
        set_auth(&OwnerAuth {
            kind,
            home: Home::Near,
            signed_enabled: c["signedEnabled"].as_bool().unwrap(),
            implicit_enabled: c["implicitEnabled"].as_bool().unwrap(),
            auth_keys: c
                .get("authKeys")
                .map(|k| serde_json::from_value::<Vec<AuthKey>>(k.clone()).unwrap())
                .unwrap_or_default(),
            salt: [salt[0], salt[1], salt[2], salt[3]],
            intents_home: true,
        });
        let got = match serde_json::from_value::<MultiPayload>(x.signed.clone()) {
            Err(_) => "E_PAYLOAD".to_string(), // near-sdk's argument parser refuses it
            Ok(mp) => {
                let r = check_err(&ta, account, mp.clone(), now);
                if r == "ok" {
                    // and the write path agrees (the ops run on this bare account)
                    assert_eq!(run_signed(&mut ta, account, mp, now), "ok", "{}", x.name);
                }
                r
            }
        };
        assert_eq!(got, x.expect, "{}", x.name);
        n += 1;
    }
    assert!(n >= 45, "{n}");
}

// ============================================================ every arm, every owner kind

#[test]
fn v160_every_standard_runs_rotate_salt() {
    for (s, stds) in owners() {
        for std in stds {
            let mut c = signer_ta(&s, T0);
            let before = salt_of(&c);
            let mp = sign(&s, std, TA, &c, r#"[{"op":"rotate_salt"}]"#, T0);
            relayer(TA, T0);
            let chk = c.owner_signed_check(mp.clone());
            assert_eq!(
                (chk.standard.as_str(), chk.ops.clone()),
                (std.as_str(), vec!["rotate_salt".to_string()])
            );
            assert_eq!(chk.key, s.public_key().to_string());
            c.owner_signed(mp);
            assert_ne!(salt_of(&c), before, "{std:?}");
            let logs = get_logs();
            assert!(
                logs[0].contains("\"event\":\"owner_signed\"") && logs[0].contains(std.as_str()),
                "{logs:?}"
            );
            assert!(logs[1].contains("salt_rotated"));
            assert_eq!(c.get_owner_auth().nonces_live, 1);
        }
    }
}

// ============================================================ negative matrix (spec §12.3 + A1)

/// Replay, cross-TA, testnet, intents-bound, expiry, TTL cap, wrong salt, nonce deadline, other
/// key, other signer_id, signatures off, a named owner, E_NONCES_FULL, and nonce reuse after
/// pruning: for every owner kind through every standard it signs with.
#[test]
fn v160_negative_matrix() {
    let now = T0;
    let ops = r#"[{"op":"rotate_salt"}]"#;
    let min = 60 * NS_PER_SEC;
    for (s, stds) in owners() {
        for std in stds {
            let mut c = signer_ta(&s, now);
            let salt = salt_of(&c);
            let id = s.owner_id();
            let mk = |acct: &str, signer: &str, salt: [u8; 4], dl: u64, rnd: u8| {
                sign_with(&s, std, acct, signer, salt, ops, now, dl, rnd)
            };
            let tag = format!("{std:?}/{:?}", s.kind());
            let testnet = "0123456789abcdef.trade.unrlzd.testnet";
            let cases: Vec<(MultiPayload, &str)> = vec![
                (mk("fedcba9876543210.trade.unrlzd.near", &id, salt, now + min, 2), "E_VERIFYING_CONTRACT"),
                (mk(testnet, &id, salt, now + min, 3), "E_VERIFYING_CONTRACT"),
                (mk("intents.near", &id, salt, now + min, 4), "E_VERIFYING_CONTRACT"),
                (mk(TA, "alice.near", salt, now + min, 5), "E_NOT_OWNER"),
                (mk(TA, &id, salt, now - 1_000_000, 6), "E_DEADLINE"),
                (mk(TA, &id, salt, now + oa::OWNER_PAYLOAD_TTL_NS + 1_000_000, 7), "E_DEADLINE"),
                (mk(TA, &id, [salt[0] ^ 1, salt[1], salt[2], salt[3]], now + min, 8), "E_NONCE_SALT"),
            ];
            for (mp, want) in cases {
                assert_eq!(check_err(&c, TA, mp.clone(), now), want, "{tag}");
                assert_eq!(run_signed(&mut c, TA, mp, now), want, "{tag}");
            }
            // nonce deadline < payload deadline
            let dl = (now + min) / 1_000_000 * 1_000_000;
            let short = s.sign_ops(
                std,
                &BodySpec {
                    signer_id: id.clone(),
                    verifying_contract: TA.into(),
                    deadline_ns: dl,
                    nonce: oa::versioned_nonce(salt, dl - 1, [9; 15]),
                    items_json: ops.into(),
                },
            );
            assert_eq!(run_signed(&mut c, TA, short, now), "E_NONCE_DEADLINE", "{tag}");
            // another key of the same curve
            let other = match s {
                Signer::Ed25519(_) => Signer::ed25519("intruder"),
                Signer::Secp256k1(_) => Signer::secp256k1("intruder"),
                Signer::P256(_) => Signer::p256("intruder"),
            };
            let forged = sign_with(&other, std, TA, &id, salt, ops, now, now + min, 10);
            assert_eq!(run_signed(&mut c, TA, forged, now), "E_NOT_OWNER", "{tag}");
            // the good one runs once; its replay is refused (salt rotated too: re-sign with it)
            let good = mk(TA, &id, salt, now + min, 1);
            assert_eq!(run_signed(&mut c, TA, good.clone(), now), "ok", "{tag}");
            let mut a = auth_of(&c);
            a.salt = salt; // put the old salt back so only the nonce store stands between
            set_auth(&a);
            assert_eq!(run_signed(&mut c, TA, good.clone(), now + 1), "E_NONCE_USED", "{tag}");
            // reuse after pruning: once the nonce expired and was pruned, the payload is past its
            // deadline, so it still cannot run
            let later = now + min + 1_000_000;
            let fill = mk(TA, &id, salt, later + min, 11);
            assert_eq!(run_signed(&mut c, TA, fill, later), "ok", "{tag}");
            set_auth(&a);
            assert_eq!(c.get_owner_auth().nonces_live, 1, "old entry pruned");
            assert_eq!(run_signed(&mut c, TA, good, later), "E_DEADLINE", "{tag}");
            // signatures off
            let mut off = auth_of(&c);
            off.signed_enabled = false;
            set_auth(&off);
            assert_eq!(
                run_signed(&mut c, TA, mk(TA, &id, salt, later + min, 12), later),
                "E_SIGNED_DISABLED"
            );
        }
    }
}

#[test]
fn v160_signature_malleability_and_webauthn_rules() {
    let now = T0;
    let ops = r#"[{"op":"rotate_salt"}]"#;
    let k1 = Signer::secp256k1("o-k1");
    let mut c = signer_ta(&k1, now);
    let mp = sign(&k1, Standard::Erc191, TA, &c, ops, now);
    assert_eq!(run_signed(&mut c, TA, with_v27(&mp), now), "E_SIG");
    assert_eq!(run_signed(&mut c, TA, with_high_s(&mp), now), "E_SIG");
    let r1 = Signer::p256("o-r1");
    let mut c = signer_ta(&r1, now);
    let mp = sign(&r1, Standard::WebAuthn, TA, &c, ops, now);
    assert_eq!(run_signed(&mut c, TA, with_high_s(&mp), now), "E_HIGH_S");
    let text = mp.text().to_string();
    for flags in [0x01u8, 0x04, 0x15] {
        assert_eq!(run_signed(&mut c, TA, r1.webauthn_with(&text, flags, "webauthn.get"), now), "E_WEBAUTHN");
    }
    assert_eq!(run_signed(&mut c, TA, r1.webauthn_with(&text, 0x05, "webauthn.create"), now), "E_WEBAUTHN");
    assert_eq!(run_signed(&mut c, TA, mp, now), "ok");
}

/// `0x` is shared: a P-256 key on a Secp256k1 owner (and the reverse) is refused by kind before
/// any derivation; an ed25519 key on either, too.
#[test]
fn v160_wrong_owner_kind() {
    let now = T0;
    let ops = r#"[{"op":"rotate_salt"}]"#;
    let k1 = Signer::secp256k1("o-k1");
    let r1 = Signer::p256("o-r1");
    let ed = Signer::ed25519("o-ed");
    let mut c = signer_ta(&k1, now);
    let salt = salt_of(&c);
    let p = sign_with(&r1, Standard::WebAuthn, TA, &k1.owner_id(), salt, ops, now, now + 60 * NS_PER_SEC, 1);
    assert_eq!(run_signed(&mut c, TA, p, now), "E_OWNER_KIND");
    let e =
        sign_with(&ed, Standard::RawEd25519, TA, &k1.owner_id(), salt, ops, now, now + 60 * NS_PER_SEC, 2);
    assert_eq!(run_signed(&mut c, TA, e, now), "E_OWNER_KIND");
    let mut c = signer_ta(&r1, now);
    let salt = salt_of(&c);
    let k = sign_with(&k1, Standard::Erc191, TA, &r1.owner_id(), salt, ops, now, now + 60 * NS_PER_SEC, 3);
    assert_eq!(run_signed(&mut c, TA, k, now), "E_OWNER_KIND");
    // a named owner never takes signatures
    let mut n = ta_at(TA, "alice.near", None, now);
    let salt = salt_of(&n);
    let x = sign_with(&ed, Standard::RawEd25519, TA, "alice.near", salt, ops, now, now + 60 * NS_PER_SEC, 4);
    assert_eq!(run_signed(&mut n, TA, x, now), "E_OWNER_KIND");
}

#[test]
fn v160_ops_bounds_and_nonce_store_full() {
    let now = T0;
    let s = Signer::ed25519("o-ed");
    let mut c = signer_ta(&s, now);
    let rs = r#"{"op":"rotate_salt"}"#;
    let five = format!("[{}]", [rs; 5].join(","));
    let up = r#"{"op":"upgrade","code_hash":"11111111111111111111111111111111"}"#;
    let wa = r#"{"op":"withdraw_all","to":"alice.near","tokens":[]}"#;
    for (ops, want) in [
        ("[]".to_string(), "E_OPS"),
        (five, "E_OPS"),
        (format!("[{up},{rs}]"), "E_OPS"),
        (format!("[{rs},{wa}]"), "E_OPS"),
        (r#"[{"op":"rotate_salt","x":1}]"#.to_string(), "E_PAYLOAD"),
        (r#"[{"op":"launch_rocket"}]"#.to_string(), "E_PAYLOAD"),
        (r#"[{"op":"withdraw_home","token":null,"amount":5}]"#.to_string(), "E_PAYLOAD"),
    ] {
        let mp = sign(&s, Standard::RawEd25519, TA, &c, &ops, now);
        assert_eq!(run_signed(&mut c, TA, mp, now), want, "{ops}");
    }
    // 32 live nonces, then E_NONCES_FULL; each call rotates the salt, so read it every time
    for i in 0..oa::MAX_OWNER_NONCES {
        let mp = sign_with(
            &s,
            Standard::RawEd25519,
            TA,
            &s.owner_id(),
            salt_of(&c),
            &format!("[{rs}]"),
            now,
            now + 600 * NS_PER_SEC,
            i as u8,
        );
        assert_eq!(run_signed(&mut c, TA, mp, now + i as u64), "ok");
    }
    let mp = sign_with(
        &s,
        Standard::RawEd25519,
        TA,
        &s.owner_id(),
        salt_of(&c),
        &format!("[{rs}]"),
        now,
        now + 600 * NS_PER_SEC,
        200,
    );
    assert_eq!(run_signed(&mut c, TA, mp.clone(), now + 40), "E_NONCES_FULL");
    // entries expire with their nonce deadline: pruned, room again
    let later = now + 600 * NS_PER_SEC + 1_000_000;
    let mp = sign_with(
        &s,
        Standard::RawEd25519,
        TA,
        &s.owner_id(),
        salt_of(&c),
        &format!("[{rs}]"),
        later,
        later + 60 * NS_PER_SEC,
        201,
    );
    assert_eq!(run_signed(&mut c, TA, mp, later), "ok");
    assert_eq!(c.get_owner_auth().nonces_live, 1);
}

// ============================================================ both doors: same effects

fn k1_owner() -> Signer {
    Signer::secp256k1("o-k1")
}

/// (op JSON, the predecessor call with the same arguments). Receipts and events of both doors
/// must be identical (the signed door adds only its `owner_signed` event first).
#[allow(clippy::type_complexity)]
fn door_pairs() -> Vec<(String, Box<dyn Fn(&mut TradingAccount)>)> {
    let dev: PublicKey = "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp".parse().unwrap();
    let d = dev.clone();
    let d2 = dev.clone();
    let d3 = dev.clone();
    let d4 = dev.clone();
    let caps_j = r#"{"max_trade_yocto":"3","daily_cap_yocto":"4"}"#;
    let ock = pk_str(&test_sk());
    let ock2 = ock.clone();
    vec![
        (json!({"op":"add_key","public_key":String::from(&dev)}).to_string(), Box::new(move |c: &mut TradingAccount| c.owner_add_key(d.clone(), KeyKind::FunctionCall))),
        (json!({"op":"remove_key","public_key":String::from(&dev)}).to_string(), Box::new(move |c: &mut TradingAccount| c.owner_remove_key(d2.clone()))),
        (r#"{"op":"withdraw","token":null,"amount":"1000","to":"bob.near"}"#.into(), Box::new(|c: &mut TradingAccount| c.owner_withdraw(None, U128(1000), a("bob.near")))),
        (r#"{"op":"withdraw","token":"wrap.near","amount":"1000","to":"bob.near"}"#.into(), Box::new(|c: &mut TradingAccount| c.owner_withdraw(Some(a("wrap.near")), U128(1000), a("bob.near")))),
        (r#"{"op":"withdraw","token":"meme.near","amount":"7","to":"bob.near"}"#.into(), Box::new(|c: &mut TradingAccount| c.owner_withdraw(Some(a("meme.near")), U128(7), a("bob.near")))),
        (r#"{"op":"withdraw_all","to":"bob.near","tokens":["meme.near"]}"#.into(), Box::new(|c: &mut TradingAccount| c.owner_withdraw_all(a("bob.near"), vec![a("meme.near")]))),
        (format!(r#"{{"op":"set_caps","caps":{caps_j}}}"#), Box::new(|c: &mut TradingAccount| c.owner_set_caps(caps(3, 4)))),
        (json!({"op":"set_automation_key","public_key":String::from(&dev),"allowance":NEAR.to_string()}).to_string(), Box::new(move |c: &mut TradingAccount| c.owner_set_automation_key(d3.clone(), U128(NEAR)))),
        (r#"{"op":"revoke_automation"}"#.into(), Box::new(|c: &mut TradingAccount| c.owner_revoke_automation())),
        (json!({"op":"clear_relayer_key","public_key":String::from(&dev)}).to_string(), Box::new(move |c: &mut TradingAccount| c.owner_clear_relayer_key(d4.clone()))),
        (r#"{"op":"set_relayer_allowance","weekly_yocto":"5"}"#.into(), Box::new(|c: &mut TradingAccount| c.owner_set_relayer_allowance(U128(5)))),
        (r#"{"op":"reclaim_dex_storage","dex":"dclv2.ref-labs.near"}"#.into(), Box::new(|c: &mut TradingAccount| c.owner_reclaim_dex_storage(a("dclv2.ref-labs.near")))),
        (r#"{"op":"reclaim_dex_storage","dex":"v2.ref-finance.near"}"#.into(), Box::new(|c: &mut TradingAccount| c.owner_reclaim_dex_storage(a("v2.ref-finance.near")))),
        (r#"{"op":"add_withdraw_destination","label":"l","asset":"nep141:sol.omft.near","recipient":"r","recipient_type":"INTENTS"}"#.into(), Box::new(|c: &mut TradingAccount| { c.owner_add_withdraw_destination("l".into(), "nep141:sol.omft.near".into(), "r".into(), "INTENTS".into()); })),
        (r#"{"op":"remove_withdraw_destination","dest_id":0}"#.into(), Box::new(|c: &mut TradingAccount| c.owner_remove_withdraw_destination(0))),
        (json!({"op":"set_oneclick_config","keys":[ock],"max_slippage_bps":100}).to_string(), Box::new(move |c: &mut TradingAccount| c.owner_set_oneclick_config(vec![ock2.clone()], 100, None, None))),
        (r#"{"op":"set_withdraw_cap","daily_cap_usd":"9"}"#.into(), Box::new(|c: &mut TradingAccount| c.owner_set_withdraw_cap(None, Some(U128(9))))),
        (r#"{"op":"withdraw_from_intents","token":"wrap.near","amount":"3"}"#.into(), Box::new(|c: &mut TradingAccount| c.owner_withdraw_from_intents(a("wrap.near"), U128(3)))),
        (json!({"op":"withdraw_via_intents","token":"wrap.near","amount":"3","deposit_address":"ab".repeat(32)}).to_string(), Box::new(|c: &mut TradingAccount| c.owner_withdraw_via_intents(a("wrap.near"), U128(3), "ab".repeat(32)))),
        (r#"{"op":"withdraw_home","token":null,"amount":"1000"}"#.into(), Box::new(|c: &mut TradingAccount| c.owner_withdraw_home(None, U128(1000)))),
        (r#"{"op":"withdraw_home","token":"meme.near","amount":"9"}"#.into(), Box::new(|c: &mut TradingAccount| c.owner_withdraw_home(Some(a("meme.near")), U128(9)))),
        (r#"{"op":"rotate_salt"}"#.into(), Box::new(|c: &mut TradingAccount| c.owner_rotate_salt())),
    ]
}

type Effects = (String, Vec<String>, Vec<String>);

fn effects(r: String) -> Effects {
    let rs = get_created_receipts().iter().map(|x| format!("{x:?}")).collect();
    let logs = get_logs().into_iter().filter(|l| !l.contains("\"event\":\"owner_signed\"")).collect();
    (r, rs, logs)
}

/// Spec §4.3: `owner_signed` runs the same bodies as the predecessor `owner_*` methods, with the
/// same receipts, events, errors and state.
#[test]
fn v160_both_doors_same_effects() {
    let s = k1_owner();
    let id = s.owner_id();
    for (op, pred) in door_pairs() {
        let mut p = signer_ta(&s, T0);
        at(TA, &id, 1, T0 + 1);
        let pe = effects(outcome(|| pred(&mut p)));
        let mut q = signer_ta(&s, T0);
        let mp = sign(&s, Standard::Erc191, TA, &q, &format!("[{op}]"), T0 + 1);
        let qe = effects(run_signed(&mut q, TA, mp, T0 + 1));
        assert_eq!(pe, qe, "{op}");
        // the state the op wrote is the same too (the nonce store aside)
        assert_eq!(
            serde_json::to_string(&p.get_config()).unwrap(),
            serde_json::to_string(&q.get_config()).unwrap()
        );
        assert_eq!(p.get_owner_auth().auth_keys, q.get_owner_auth().auth_keys, "{op}");
    }
}

/// The predecessor door still needs owner + 1 yocto for the new methods (and is not reachable
/// by the relayer).
#[test]
fn v160_new_predecessor_methods_guarded() {
    let s = k1_owner();
    let mut c = signer_ta(&s, T0);
    for (pred, dep, want) in [(s.owner_id(), 0, "E_ONE_YOCTO"), (RELAYER.to_string(), 1, "E_NOT_OWNER")] {
        at(TA, &pred, dep, T0);
        assert_eq!(outcome(|| c.owner_withdraw_home(None, U128(1))), want);
        assert_eq!(outcome(|| c.owner_rotate_salt()), want);
        assert_eq!(outcome(|| c.owner_set_signed_enabled(false)), want);
    }
}

// ============================================================ init / migrate / owner kind

#[test]
fn v160_init_owner_kind_rules() {
    let hexid = "ab".repeat(32);
    let ox = format!("0x{}", "cd".repeat(20));
    // no owner_auth: the id rule (signatures on only for 0x)
    for (owner, kind, on) in [
        ("alice.near", OwnerKind::Named, false),
        (hexid.as_str(), OwnerKind::Ed25519, false),
        (ox.as_str(), OwnerKind::Secp256k1, true),
    ] {
        let c = ta_at(TA, owner, None, T0);
        let v = c.get_owner_auth();
        assert_eq!(
            (v.kind, v.signed_enabled, v.implicit_enabled, v.home),
            (kind, on, true, Home::Near),
            "{owner}"
        );
        assert_eq!(v.salt.len(), 8);
    }
    // factory 1.3.0: verified kind, signatures on
    for (owner, kind, home) in [
        (hexid.as_str(), OwnerKind::Ed25519, Home::Solana),
        (hexid.as_str(), OwnerKind::Ed25519, Home::Near),
        (ox.as_str(), OwnerKind::Secp256k1, Home::Near),
        (ox.as_str(), OwnerKind::P256, Home::Near),
    ] {
        let c = ta_at(TA, owner, Some(OwnerAuthInit { kind, home }), T0);
        let v = c.get_owner_auth();
        assert_eq!((v.kind, v.home, v.signed_enabled), (kind, home, true));
    }
    // a kind that does not fit the id, a named kind, Solana home on a 0x owner
    for (owner, kind, home) in [
        ("alice.near", OwnerKind::Ed25519, Home::Near),
        ("alice.near", OwnerKind::Named, Home::Near),
        (hexid.as_str(), OwnerKind::P256, Home::Near),
        (ox.as_str(), OwnerKind::Ed25519, Home::Near),
        (ox.as_str(), OwnerKind::P256, Home::Solana),
    ] {
        assert_eq!(
            outcome(|| {
                ta_at(TA, owner, Some(OwnerAuthInit { kind, home }), T0);
            }),
            "E_OWNER_KIND",
            "{owner} {kind:?}"
        );
    }
}

/// migrate (from 1.5.0 state, no `ow`) writes the id-rule record once and never overwrites it.
#[test]
fn v160_migrate_writes_owner_auth_once() {
    let hexid = "ab".repeat(32);
    let c = ta_at(TA, &hexid, None, T0);
    env::storage_remove(K_OWNER_AUTH);
    env::state_write(&c);
    at(TA, TA, 0, T0);
    let m = TradingAccount::migrate();
    let v = m.get_owner_auth();
    assert_eq!(
        (v.kind, v.signed_enabled),
        (OwnerKind::Ed25519, false),
        "1.5 implicit owner: off until opt-in"
    );
    // opt in, then migrate again: unchanged
    at(TA, &hexid, 1, T0);
    let mut m = m;
    m.owner_set_signed_enabled(true);
    let before = auth_of(&m);
    env::state_write(&m);
    at(TA, TA, 0, T0 + 1);
    let m2 = TradingAccount::migrate();
    assert_eq!(auth_of(&m2), before);
    // a named owner cannot turn signatures on
    let mut n = ta_at(TA, "alice.near", None, T0);
    at(TA, "alice.near", 1, T0);
    assert_eq!(outcome(|| n.owner_set_signed_enabled(true)), "E_OWNER_KIND");
}

// ============================================================ auth keys

#[test]
fn v160_auth_keys() {
    let now = T0;
    let s = Signer::ed25519("o-ed");
    let mut c = signer_ta(&s, now);
    let add = |k: &AuthKey| json!({"op":"add_auth_key","public_key":k.to_string()}).to_string();
    let rm = |k: &AuthKey| json!({"op":"remove_auth_key","public_key":k.to_string()}).to_string();
    let run = |c: &mut TradingAccount, signer: &Signer, std: Standard, op: &str, rnd: u8| {
        let mp = sign_with(
            signer,
            std,
            TA,
            &s.owner_id(),
            salt_of(c),
            &format!("[{op}]"),
            now,
            now + 60 * NS_PER_SEC,
            rnd,
        );
        run_signed(c, TA, mp, now)
    };
    let passkey = Signer::p256("backup-passkey");
    let evm = Signer::secp256k1("backup-evm");
    // implicit key disabled with no auth key: refused (would lock the owner out)
    assert_eq!(
        run(&mut c, &s, Standard::RawEd25519, r#"{"op":"set_implicit_key","enabled":false}"#, 1),
        "E_LAST_KEY"
    );
    // add a P-256 and a secp256k1 backup key (any curve for any signer-kind owner)
    assert_eq!(run(&mut c, &s, Standard::RawEd25519, &add(&passkey.public_key()), 2), "ok");
    assert!(get_logs().iter().any(|l| l.contains("auth_key_added")));
    assert_eq!(run(&mut c, &s, Standard::RawEd25519, &add(&evm.public_key()), 3), "ok");
    // the passkey and the EVM key now sign for the ed25519 owner
    assert_eq!(run(&mut c, &passkey, Standard::WebAuthn, r#"{"op":"rotate_salt"}"#, 4), "ok");
    assert_eq!(run(&mut c, &evm, Standard::Erc191, r#"{"op":"rotate_salt"}"#, 5), "ok");
    // duplicate, the owner's own implied key, a small-order key
    assert_eq!(run(&mut c, &s, Standard::RawEd25519, &add(&passkey.public_key()), 6), "E_BAD_AUTH_KEY");
    assert_eq!(run(&mut c, &s, Standard::RawEd25519, &add(&s.public_key()), 7), "E_BAD_AUTH_KEY");
    assert_eq!(run(&mut c, &s, Standard::RawEd25519, &add(&AuthKey::Ed25519([0; 32])), 8), "E_BAD_AUTH_KEY");
    let mut one = [0u8; 32];
    one[0] = 1;
    assert_eq!(run(&mut c, &s, Standard::RawEd25519, &add(&AuthKey::Ed25519(one)), 9), "E_BAD_AUTH_KEY");
    // cap 4
    for (i, l) in ["b3", "b4"].iter().enumerate() {
        assert_eq!(
            run(&mut c, &s, Standard::RawEd25519, &add(&Signer::ed25519(l).public_key()), 10 + i as u8),
            "ok"
        );
    }
    assert_eq!(
        run(&mut c, &s, Standard::RawEd25519, &add(&Signer::ed25519("b5").public_key()), 12),
        "E_AUTH_KEYS_FULL"
    );
    assert_eq!(c.get_owner_auth().auth_keys.len(), 4);
    // the original key leaked: switch it off with the passkey; it no longer signs
    assert_eq!(
        run(&mut c, &passkey, Standard::WebAuthn, r#"{"op":"set_implicit_key","enabled":false}"#, 13),
        "ok"
    );
    assert_eq!(run(&mut c, &s, Standard::RawEd25519, r#"{"op":"rotate_salt"}"#, 14), "E_NOT_OWNER");
    // remove keys down to the last one: the last usable key stays
    for (i, k) in [evm.public_key(), Signer::ed25519("b3").public_key(), Signer::ed25519("b4").public_key()]
        .iter()
        .enumerate()
    {
        assert_eq!(run(&mut c, &passkey, Standard::WebAuthn, &rm(k), 15 + i as u8), "ok");
    }
    assert_eq!(run(&mut c, &passkey, Standard::WebAuthn, &rm(&passkey.public_key()), 20), "E_LAST_KEY");
    assert_eq!(run(&mut c, &passkey, Standard::WebAuthn, &rm(&evm.public_key()), 21), "E_NO_KEY");
    // a removed key no longer signs
    assert_eq!(run(&mut c, &evm, Standard::Erc191, r#"{"op":"rotate_salt"}"#, 22), "E_OWNER_KIND");
    // re-enable the implicit key; now the passkey may go
    assert_eq!(
        run(&mut c, &passkey, Standard::WebAuthn, r#"{"op":"set_implicit_key","enabled":true}"#, 23),
        "ok"
    );
    assert_eq!(run(&mut c, &s, Standard::RawEd25519, &rm(&passkey.public_key()), 24), "ok");
    assert!(c.get_owner_auth().auth_keys.is_empty());
}

#[test]
fn v160_rotate_salt_voids_signed_payloads() {
    let now = T0;
    let s = Signer::p256("o-r1");
    let mut c = signer_ta(&s, now);
    let pending =
        sign(&s, Standard::WebAuthn, TA, &c, r#"[{"op":"set_relayer_allowance","weekly_yocto":"1"}]"#, now);
    at(TA, &s.owner_id(), 1, now); // (a P-256 owner has no NEAR key: this is the id, for the test)
    c.owner_rotate_salt();
    assert_eq!(run_signed(&mut c, TA, pending, now), "E_NONCE_SALT");
}

/// The payload summary names an installed key and its role (owner decision 2026-10-01).
#[test]
fn v160_summary_names_keys() {
    let s = k1_owner();
    let c = signer_ta(&s, T0);
    let dev = "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp";
    let pk = Signer::p256("bk").public_key().to_string();
    let ops = json!([
        {"op":"add_key","public_key":dev},
        {"op":"set_automation_key","public_key":dev,"allowance":NEAR.to_string()},
        {"op":"add_auth_key","public_key":pk},
        {"op":"withdraw","token":null,"amount":"1","to":"bob.near"}
    ])
    .to_string();
    let mp = sign(&s, Standard::Erc191, TA, &c, &ops, T0);
    relayer(TA, T0);
    let chk = c.owner_signed_check(mp);
    assert_eq!(
        chk.ops,
        vec![
            format!("add_key {dev} device"),
            format!("set_automation_key {dev} automation"),
            format!("add_auth_key {pk} auth"),
            // ext audit F2: an outflow names its amount, token and destination
            "withdraw 1 near to bob.near".to_string()
        ]
    );
}

// ============================================================ home withdraws (spec §5.1)

fn fc(r: &near_sdk::mock::Receipt, i: usize) -> (String, Value, u128, u64) {
    match &r.actions[i] {
        MockAction::FunctionCallWeight { method_name, args, attached_deposit, prepaid_gas, .. } => (
            String::from_utf8(method_name.clone()).unwrap(),
            serde_json::from_slice(args).unwrap_or(Value::Null),
            attached_deposit.as_yoctonear(),
            prepaid_gas.as_gas() / TGAS,
        ),
        x => panic!("{x:?}"),
    }
}

#[test]
fn v160_withdraw_to_owner_signer_kind_goes_to_intents() {
    let s = Signer::p256("o-r1");
    let owner = s.owner_id();
    // native NEAR: wrap then ft_transfer_call(intents.near, msg = owner), one batch, + callback
    let mut c = signer_ta(&s, T0);
    at(TA, TA, 0, T0 + 1);
    c.withdraw_to_owner(None, U128(NEAR));
    let rs = get_created_receipts();
    assert_eq!(rs.len(), 2, "{rs:?}");
    assert_eq!(rs[0].receiver_id, a("wrap.near"));
    let (m0, _, d0, _) = fc(&rs[0], 0);
    let (m1, args, d1, g1) = fc(&rs[0], 1);
    assert_eq!((m0.as_str(), d0), ("near_deposit", NEAR));
    assert_eq!((m1.as_str(), d1, g1), ("ft_transfer_call", 1, 50));
    assert_eq!(args, json!({"receiver_id":"intents.near","amount":NEAR.to_string(),"msg":owner}));
    assert_eq!(fc(&rs[1], 0).0, "on_home_sent");
    assert!(rs.iter().all(|r| r.receiver_id.as_str() != owner), "never a native transfer to a 0x id");
    // RESERVE kept
    let mut c = signer_ta(&s, T0);
    at(TA, TA, 0, T0 + 1);
    assert_eq!(outcome(|| c.withdraw_to_owner(None, U128(10 * NEAR))), "E_RESERVE");
    // an FT: register intents.near, then ft_transfer_call
    let mut c = signer_ta(&s, T0);
    at(TA, TA, 0, T0 + 1);
    c.withdraw_to_owner(Some(a("meme.near")), U128(5));
    let rs = get_created_receipts();
    assert_eq!(fc(&rs[0], 0).0, "storage_deposit");
    assert_eq!(fc(&rs[0], 0).1["account_id"], "intents.near");
    assert_eq!(fc(&rs[1], 0).0, "ft_transfer_call");
    assert_eq!(fc(&rs[1], 0).1["msg"], owner);
    // wNEAR: straight ft_transfer_call
    let mut c = signer_ta(&s, T0);
    at(TA, TA, 0, T0 + 1);
    c.withdraw_to_owner(Some(a("wrap.near")), U128(5));
    let rs = get_created_receipts();
    assert_eq!((rs[0].receiver_id.as_str(), fc(&rs[0], 0).0.as_str()), ("wrap.near", "ft_transfer_call"));
    // a named owner: byte-for-byte the old path (native transfer to the owner)
    let mut n = ta_at(TA, "alice.near", None, T0);
    at(TA, TA, 0, T0 + 1);
    n.withdraw_to_owner(None, U128(NEAR));
    let rs = get_created_receipts();
    assert_eq!(rs.len(), 1);
    assert_eq!(rs[0].receiver_id, a("alice.near"));
    assert!(matches!(rs[0].actions[0], MockAction::Transfer { .. }));
}

fn native_to(owner: &str) {
    let rs = get_created_receipts();
    assert_eq!(rs.len(), 1, "{rs:?}");
    assert_eq!(rs[0].receiver_id, a(owner));
    assert!(matches!(rs[0].actions[0], MockAction::Transfer { .. }));
}

/// Owner rule "no existing user's experience gets worse": a NEAR-wallet owner (named, 64-hex
/// implicit from Meteor/HOT/Intear, or a 0x account created by the id rule) keeps 1.5's native
/// withdraw_to_owner, when created by 1.6 code without `owner_auth` and after a 1.5 -> 1.6
/// migrate. Only signed-path owners (factory 1.3.0) have the intents home.
#[test]
fn v160_near_wallet_owners_keep_native_home() {
    let hexid = "ab".repeat(32);
    let ox = format!("0x{}", "cd".repeat(20));
    for owner in ["alice.near", hexid.as_str(), ox.as_str()] {
        // created by 1.6 code through factory create_account (no owner_auth)
        let mut c = ta_at(TA, owner, None, T0);
        assert!(!c.get_owner_auth().intents_home);
        at(TA, TA, 0, T0 + 1);
        c.withdraw_to_owner(None, U128(NEAR));
        native_to(owner);
        // the owner's own withdraw_home is native too
        at(TA, owner, 1, T0 + 2);
        c.owner_withdraw_home(None, U128(NEAR));
        native_to(owner);
        // a 1.5 account (no `ow`) before migrate reads as native, and after migrate stays native
        env::storage_remove(K_OWNER_AUTH);
        env::state_write(&c);
        at(TA, TA, 0, T0 + 3);
        c.withdraw_to_owner(None, U128(NEAR));
        native_to(owner);
        let mut m = TradingAccount::migrate();
        assert!(!m.get_owner_auth().intents_home);
        at(TA, TA, 0, T0 + 4);
        m.withdraw_to_owner(None, U128(NEAR));
        native_to(owner);
        // opting in to owner signatures does not move the home
        if owner != "alice.near" {
            at(TA, owner, 1, T0 + 5);
            m.owner_set_signed_enabled(true);
            at(TA, TA, 0, T0 + 6);
            m.withdraw_to_owner(None, U128(NEAR));
            native_to(owner);
        }
    }
    // signed-path owners of every kind: intents home
    for s in [Signer::ed25519("o-ed"), Signer::secp256k1("o-k1"), Signer::p256("o-r1")] {
        let mut c = signer_ta(&s, T0);
        assert!(c.get_owner_auth().intents_home);
        at(TA, TA, 0, T0 + 1);
        c.withdraw_to_owner(None, U128(NEAR));
        assert_eq!(get_created_receipts()[0].receiver_id, a("wrap.near"));
    }
}

#[test]
fn v160_on_home_sent_reports_refunds() {
    let s = Signer::secp256k1("o-k1");
    let mut c = signer_ta(&s, T0);
    for (r, used, ok) in [
        (PromiseResult::Successful(format!("\"{NEAR}\"").into_bytes()), NEAR, true),
        (PromiseResult::Successful(b"\"0\"".to_vec()), 0, false),
        (PromiseResult::Failed, 0, false),
    ] {
        testing_env!(
            VMContextBuilder::new().current_account_id(a(TA)).predecessor_account_id(a(TA)).build(),
            near_sdk::test_vm_config(),
            near_sdk::RuntimeFeesConfig::test(),
            Default::default(),
            vec![r],
        );
        c.on_home_sent("near".into(), U128(NEAR));
        let l = &get_logs()[0];
        assert!(l.contains(&format!("\"to\":\"intents:{}\"", s.owner_id())), "{l}");
        assert!(l.contains(&format!("\"ok\":{ok},\"used\":\"{used}\"")), "{l}");
    }
}

// ============================================================ HOME_DEST (spec §5.2)

fn home_quote(recipient: &str, rtype: &str, asset: &str, now: u64) -> (String, String) {
    let (r, t, s) = (recipient.to_string(), rtype.to_string(), asset.to_string());
    signed_quote(NEAR, now, move |m| {
        m["refundTo"] = Value::from(TA);
        m["recipient"] = Value::from(r.clone());
        m["recipientType"] = Value::from(t.clone());
        m["destinationAsset"] = Value::from(s.clone());
    })
}

fn home_ta(owner: &str, init: Option<OwnerAuthInit>) -> TradingAccount {
    let mut c = ta_at(TA, owner, init, T0);
    at(TA, owner, 1, T0);
    c.owner_set_oneclick_config(vec![pk_str(&test_sk())], 300, None, None);
    c
}

#[test]
fn v160_home_dest_rules() {
    let base_usdc = "nep141:base-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near";
    let sol_usdc = "nep141:sol-5ce3bf3a31af18be40ba30f721101b4341690186.omft.near";
    let k1 = Signer::secp256k1("o-k1");
    let r1 = Signer::p256("o-r1");
    let ed = Signer::ed25519("o-ed");
    let ed_b58 = near_sdk::bs58::encode(oa::unhex32(&ed.owner_id()).unwrap()).into_string();
    let now = T0 + 10;
    let run = |owner: &str, init: Option<OwnerAuthInit>, q: (String, String)| {
        let mut c = home_ta(owner, init);
        at(TA, TA, 0, now);
        outcome(|| wcc(&mut c, "h1", HOME_DEST, "wrap.near", NEAR, &q))
    };
    let kinit = Some(OwnerAuthInit { kind: OwnerKind::Secp256k1, home: Home::Near });
    let rinit = Some(OwnerAuthInit { kind: OwnerKind::P256, home: Home::Near });
    let sinit = Some(OwnerAuthInit { kind: OwnerKind::Ed25519, home: Home::Solana });
    let ninit = Some(OwnerAuthInit { kind: OwnerKind::Ed25519, home: Home::Near });
    // INTENTS to the owner id: every signer kind, no activation delay
    for (s, i) in [(&k1, kinit), (&r1, rinit), (&ed, sinit)] {
        assert_eq!(run(&s.owner_id(), i, home_quote(&s.owner_id(), "INTENTS", base_usdc, now)), "ok");
    }
    // EVM native address (1Click echoes lowercase; a checksummed quote compares lowercase)
    assert_eq!(
        run(&k1.owner_id(), kinit, home_quote(&k1.owner_id(), "DESTINATION_CHAIN", base_usdc, now)),
        "ok"
    );
    let upper = format!("0x{}", k1.owner_id()[2..].to_uppercase());
    assert_eq!(run(&k1.owner_id(), kinit, home_quote(&upper, "DESTINATION_CHAIN", base_usdc, now)), "ok");
    // Solana home: base58(pk) on a Solana asset
    assert_eq!(run(&ed.owner_id(), sinit, home_quote(&ed_b58, "DESTINATION_CHAIN", sol_usdc, now)), "ok");
    // refused: another recipient, an EVM owner to Solana, a Solana owner to Base, P-256 or
    // NEAR-home ed25519 to any chain, a named owner, an unlisted asset
    let bad: Vec<(String, Option<OwnerAuthInit>, (String, String))> = vec![
        (k1.owner_id(), kinit, home_quote(&r1.owner_id(), "INTENTS", base_usdc, now)),
        (k1.owner_id(), kinit, home_quote(&r1.owner_id(), "DESTINATION_CHAIN", base_usdc, now)),
        (k1.owner_id(), kinit, home_quote(&k1.owner_id(), "DESTINATION_CHAIN", sol_usdc, now)),
        (ed.owner_id(), sinit, home_quote(&ed_b58, "DESTINATION_CHAIN", base_usdc, now)),
        (ed.owner_id(), ninit, home_quote(&ed_b58, "DESTINATION_CHAIN", sol_usdc, now)),
        (r1.owner_id(), rinit, home_quote(&r1.owner_id(), "DESTINATION_CHAIN", base_usdc, now)),
        ("alice.near".into(), None, home_quote("alice.near", "INTENTS", base_usdc, now)),
        (k1.owner_id(), kinit, home_quote(&k1.owner_id(), "DESTINATION_CHAIN", "nep141:tron.omft.near", now)),
    ];
    for (o, i, q) in bad {
        assert_eq!(run(&o, i, q.clone()), "E_HOME_DEST", "{o} {}", q.0);
    }
    // every other check still applies: the quote must still refund to self
    let q = signed_quote(NEAR, now, |m| {
        m["refundTo"] = Value::from("evil.near");
        m["recipient"] = Value::from(k1.owner_id());
        m["recipientType"] = Value::from("INTENTS");
    });
    assert_eq!(run(&k1.owner_id(), kinit, q), "E_QUOTE_MISMATCH");
}

/// The compiled-in allowlists against 1Click /v0/tokens (2026-10-01 snapshot): every asset of
/// the listed EVM chains and of Solana is accepted by its list, nothing else by either.
#[test]
fn v160_home_asset_lists_match_oneclick_tokens() {
    let t: Vec<Value> =
        serde_json::from_str(include_str!("../../tests/fixtures/oneclick_tokens.json")).unwrap();
    let evm = ["eth", "base", "arb", "gnosis", "bera", "bsc", "pol", "op", "avax"];
    let mut n = (0, 0);
    for x in &t {
        let (chain, id) = (x["blockchain"].as_str().unwrap(), x["assetId"].as_str().unwrap());
        assert_eq!(ow::is_evm_home_asset(id), evm.contains(&chain), "{chain} {id}");
        assert_eq!(ow::is_sol_home_asset(id), chain == "sol", "{chain} {id}");
        n.0 += usize::from(evm.contains(&chain));
        n.1 += usize::from(chain == "sol");
    }
    assert!(n.0 > 50 && n.1 > 10, "{n:?}");
}

// ============================================================ signed upgrade (factory-approved)

const HASH: &str = "3ya9mmnX9uNJ6NcJKWHMS1pv2Dnv8jEXCMLuTxCpCz1V";

fn upgrade_cb(c: &mut TradingAccount, r: PromiseResult) {
    testing_env!(
        VMContextBuilder::new().current_account_id(a(TA)).predecessor_account_id(a(TA)).build(),
        near_sdk::test_vm_config(),
        near_sdk::RuntimeFeesConfig::test(),
        Default::default(),
        vec![r],
    );
    c.on_upgrade_checked(HASH.parse().unwrap());
}

#[test]
fn v160_signed_upgrade_only_to_factory_approved_code() {
    let s = Signer::ed25519("o-ed");
    let mut c = signer_ta(&s, T0);
    let mp = sign(&s, Standard::Nep413, TA, &c, &format!(r#"[{{"op":"upgrade","code_hash":"{HASH}"}}]"#), T0);
    assert_eq!(run_signed(&mut c, TA, mp, T0), "ok");
    // step 1: the factory (the TA's parent account) is asked, nothing else happens yet
    let rs = get_created_receipts();
    assert_eq!(rs.len(), 2);
    assert_eq!(rs[0].receiver_id, a("trade.unrlzd.near"));
    assert_eq!(fc(&rs[0], 0).0, "get_approved_code_hashes");
    assert!(rs.iter().all(|r| !r.actions.iter().any(|x| matches!(x, MockAction::UseGlobalContract { .. }))));
    assert_eq!(fc(&rs[1], 0).0, "on_upgrade_checked");
    // approved: one batch UseGlobalContract + migrate + the get_owner_auth guard
    upgrade_cb(&mut c, PromiseResult::Successful(format!("[\"x\",\"{HASH}\"]").into_bytes()));
    let rs = get_created_receipts();
    assert_eq!(rs.len(), 1);
    assert_eq!(rs[0].receiver_id, a(TA));
    assert!(matches!(rs[0].actions[0], MockAction::UseGlobalContract { .. }));
    assert_eq!(fc(&rs[0], 1).0, "migrate");
    assert_eq!(fc(&rs[0], 2).0, "on_code_installed");
    // refused: stale/foreign hash, empty list (code not flagged signed), failed or garbage read
    for (r, why) in [
        (
            PromiseResult::Successful(b"[\"4ya9mmnX9uNJ6NcJKWHMS1pv2Dnv8jEXCMLuTxCpCz1V\"]".to_vec()),
            "not_approved",
        ),
        (PromiseResult::Successful(b"[]".to_vec()), "not_approved"),
        (PromiseResult::Failed, "factory_unreadable"),
        (PromiseResult::Successful(b"{\"code_hash\":\"x\"}".to_vec()), "factory_unreadable"),
    ] {
        upgrade_cb(&mut c, r);
        assert!(get_created_receipts().is_empty());
        assert!(get_logs()[0].contains(&format!("\"reason\":\"{why}\"")), "{:?}", get_logs());
    }
    // the predecessor owner_upgrade is unchanged (direct, no factory check)
    let mut n = ta_at(TA, "alice.near", None, T0);
    at(TA, "alice.near", 1, T0);
    n.owner_upgrade(HASH.parse().unwrap());
    let rs = get_created_receipts();
    assert_eq!(rs.len(), 1);
    assert!(matches!(rs[0].actions[0], MockAction::UseGlobalContract { .. }));
    assert_eq!(rs[0].actions.len(), 2);
}

/// HOME_DEST only for signed-path owners (intents_home): every NEAR-wallet id shape is refused,
/// on 1.6 creation and after a 1.5 -> 1.6 migrate (also with signatures opted in).
#[test]
fn v160_home_dest_only_signed_path() {
    let base_usdc = "nep141:base-0x833589fcd6edb6e08f4c7c32d4f71b54bda02913.omft.near";
    let hexid = "ab".repeat(32);
    let ox = format!("0x{}", "cd".repeat(20));
    let now = T0 + 10;
    for owner in ["alice.near", hexid.as_str(), ox.as_str()] {
        for migrated in [false, true] {
            let mut c = home_ta(owner, None);
            if migrated {
                env::storage_remove(K_OWNER_AUTH);
                env::state_write(&c);
                at(TA, TA, 0, T0 + 1);
                c = TradingAccount::migrate();
                if owner != "alice.near" {
                    at(TA, owner, 1, T0 + 2);
                    c.owner_set_signed_enabled(true);
                }
            }
            for (r, t) in [(owner, "INTENTS"), (owner, "DESTINATION_CHAIN")] {
                let q = home_quote(r, t, base_usdc, now);
                at(TA, TA, 0, now);
                assert_eq!(
                    outcome(|| wcc(&mut c, t, HOME_DEST, "wrap.near", NEAR, &q)),
                    "E_HOME_DEST",
                    "{owner} {t} {migrated}"
                );
            }
        }
    }
    let k1 = Signer::secp256k1("o-k1");
    let mut c = home_ta(&k1.owner_id(), Some(OwnerAuthInit { kind: OwnerKind::Secp256k1, home: Home::Near }));
    let q = home_quote(&k1.owner_id(), "INTENTS", base_usdc, now);
    at(TA, TA, 0, now);
    assert_eq!(outcome(|| wcc(&mut c, "h", HOME_DEST, "wrap.near", NEAR, &q)), "ok");
}

// ============================================================ held balances (A1, hook set 2)

fn report_native(c: &mut TradingAccount) -> u128 {
    testing_env!(
        VMContextBuilder::new()
            .current_account_id(a(TA))
            .predecessor_account_id(a(TA))
            .account_balance(NearToken::from_yoctonear(10 * NEAR))
            .storage_usage(100_000)
            .build(),
        near_sdk::test_vm_config(),
        near_sdk::RuntimeFeesConfig::test(),
        Default::default(),
        vec![],
    );
    c.on_withdraw_all_report(a("bob.near"), vec![], None);
    let rs = get_created_receipts();
    match rs.first().map(|r| &r.actions[0]) {
        Some(MockAction::Transfer { deposit, .. }) => deposit.as_yoctonear(),
        _ => 0,
    }
}

const LIQUID: u128 = 10 * NEAR - 100_000 * 10_000_000_000_000_000_000;

/// Escrowed IntentsSwap fees are never sent by an owner withdraw (native withdraw, withdraw_all
/// sweep, device withdraw_to_owner); a NEAR-wallet owner with no route in flight is unchanged.
#[test]
fn v160_owner_withdraws_keep_route_escrow() {
    let mut c = ta_at(TA, "alice.near", None, T0);
    assert_eq!(report_native(&mut c), LIQUID, "no escrow: 1.5 sweep");
    let esc = 3 * NEAR;
    crate::chain::escrow_add(esc);
    assert_eq!(report_native(&mut c), LIQUID - esc);
    // (the 1 yocto attached is liquid too)
    at(TA, "alice.near", 1, T0 + 1);
    assert_eq!(outcome(|| c.owner_withdraw(None, U128(LIQUID - esc + 2), a("bob.near"))), "E_HELD_BALANCE");
    at(TA, "alice.near", 1, T0 + 1);
    assert_eq!(outcome(|| c.owner_withdraw(None, U128(LIQUID - esc + 1), a("bob.near"))), "ok");
    at(TA, TA, 0, T0 + 2);
    assert_eq!(outcome(|| c.withdraw_to_owner(None, U128(LIQUID - esc - RESERVE + 1))), "E_RESERVE");
    at(TA, TA, 0, T0 + 2);
    assert_eq!(outcome(|| c.withdraw_to_owner(None, U128(LIQUID - esc - RESERVE))), "ok");
}

/// With owner signatures on, withdraw_all (and a whole-balance withdraw) keeps the signed-path
/// state reserve, so the next signed call can always store its nonce without a top-up.
#[test]
fn v160_withdraw_all_keeps_signed_state_reserve() {
    let hold = SIGNED_STATE_BYTES * 10_000_000_000_000_000_000;
    let s = Signer::p256("o-r1");
    let mut c = signer_ta(&s, T0);
    assert_eq!(report_native(&mut c), LIQUID - hold);
    at(TA, &s.owner_id(), 1, T0 + 1);
    assert_eq!(outcome(|| c.owner_withdraw(None, U128(LIQUID), a("bob.near"))), "E_HELD_BALANCE");
    // signatures off (e.g. a 64-hex owner before opting in): nothing held
    let mut h = ta_at(TA, &"ab".repeat(32), None, T0);
    assert_eq!(report_native(&mut h), LIQUID);
}

/// A proven IntentsSwap refund returns its counted spend (fee + input pro rata to what came
/// back) to the window it was charged in, once; a later window is untouched.
#[test]
fn v160_refunded_route_releases_spend() {
    let mut c = ta_at(TA, "alice.near", None, T0);
    c.day.spent_yocto = 5 * NEAR;
    let day = c.day.start_ns;
    save_route_spend("r1", day, 2 * NEAR, NEAR / 100);
    c.release_route_spend("r1", NEAR); // half came back
                                       // V16-07: input AND escrowed fee pro rata (half of each)
    assert_eq!(c.day.spent_yocto, 5 * NEAR - NEAR / 200 - NEAR);
    assert!(get_logs().iter().any(|l| l.contains("route_spend_released")));
    c.release_route_spend("r1", NEAR); // once only
    assert_eq!(c.day.spent_yocto, 5 * NEAR - NEAR / 200 - NEAR);
    save_route_spend("r2", day, 2 * NEAR, 7);
    c.release_route_spend("r2", 9 * NEAR); // capped at the input
    assert_eq!(c.day.spent_yocto, 5 * NEAR - NEAR / 200 - NEAR - 2 * NEAR - 7);
    save_route_spend("r3", day - 1, NEAR, 0);
    let before = c.day.spent_yocto;
    c.release_route_spend("r3", NEAR);
    assert_eq!(c.day.spent_yocto, before, "another window is untouched");
    save_route_spend("r4", day, NEAR, 5);
    drop_route_spend("r4");
    c.release_route_spend("r4", NEAR);
    assert_eq!(c.day.spent_yocto, before, "delivered: nothing to release");
}

/// V16-03 (internal review): the PoC flipped. After the "my original key leaked" switch
/// (`set_implicit_key(false)`, signed by a backup passkey), the leaked key is refused on BOTH
/// doors: E_NOT_OWNER on the signed door, E_IMPLICIT_OFF on every predecessor `owner_*` from
/// the owner-id account. The backup key still acts, and re-enabling opens both doors again.
/// RED before: `owner_withdraw` from the owner-id account paid out.
#[test]
fn v16_03_implicit_off_closes_both_doors() {
    let now = T0;
    for (s, std0) in
        [(Signer::ed25519("o-ed"), Standard::RawEd25519), (Signer::secp256k1("o-k1"), Standard::Erc191)]
    {
        let mut c = signer_ta(&s, now);
        let passkey = Signer::p256("backup-passkey");
        let add = json!({"op":"add_auth_key","public_key":passkey.public_key().to_string()}).to_string();
        let dl = now + 60 * NS_PER_SEC;
        let mp = sign_with(&s, std0, TA, &s.owner_id(), salt_of(&c), &format!("[{add}]"), now, dl, 1);
        assert_eq!(run_signed(&mut c, TA, mp, now), "ok");
        // before the switch the predecessor door works (NEAR-wallet behaviour kept)
        at(TA, &s.owner_id(), 1, now);
        assert_eq!(outcome(|| c.owner_set_relayer_allowance(U128(5))), "ok");
        let off = r#"[{"op":"set_implicit_key","enabled":false}]"#;
        let mp = sign_with(&passkey, Standard::WebAuthn, TA, &s.owner_id(), salt_of(&c), off, now, dl, 2);
        assert_eq!(run_signed(&mut c, TA, mp, now), "ok");
        let mp = sign_with(&s, std0, TA, &s.owner_id(), salt_of(&c), r#"[{"op":"rotate_salt"}]"#, now, dl, 3);
        assert_eq!(run_signed(&mut c, TA, mp, now), "E_NOT_OWNER");
        at(TA, &s.owner_id(), 1, now);
        assert_eq!(outcome(|| c.owner_withdraw(None, U128(NEAR), a("attacker.near"))), "E_IMPLICIT_OFF");
        assert!(!get_created_receipts().iter().any(|r| r.receiver_id == a("attacker.near")));
        at(TA, &s.owner_id(), 1, now);
        assert_eq!(outcome(|| c.owner_withdraw_all(a("attacker.near"), vec![])), "E_IMPLICIT_OFF");
        at(TA, &s.owner_id(), 1, now);
        assert_eq!(outcome(|| c.owner_set_signed_enabled(false)), "E_IMPLICIT_OFF");
        at(TA, &s.owner_id(), 1, now);
        assert_eq!(outcome(|| c.cancel_order(U64(1))), "E_IMPLICIT_OFF");
        // the passkey still withdraws
        let w = json!([{"op":"withdraw","token":null,"amount":"1000","to":"bob.near"}]).to_string();
        let mp = sign_with(&passkey, Standard::WebAuthn, TA, &s.owner_id(), salt_of(&c), &w, now, dl, 4);
        assert_eq!(run_signed(&mut c, TA, mp, now), "ok");
        // re-enabled: both doors open again
        let on = r#"[{"op":"set_implicit_key","enabled":true}]"#;
        let mp = sign_with(&passkey, Standard::WebAuthn, TA, &s.owner_id(), salt_of(&c), on, now, dl, 5);
        assert_eq!(run_signed(&mut c, TA, mp, now), "ok");
        at(TA, &s.owner_id(), 1, now);
        assert_eq!(outcome(|| c.owner_set_relayer_allowance(U128(6))), "ok");
    }
}

/// Funding failed: the input already came back through finish_settle; the escrowed fee's spend is
/// released too (V16-07's pro-rata formula would release nothing for `returned = 0`).
#[test]
fn v160_fund_failed_releases_the_fee_spend() {
    let mut c = ta_at(TA, "alice.near", None, T0);
    c.day.spent_yocto = 5 * NEAR;
    let day = c.day.start_ns;
    save_route_spend("f1", day, 2 * NEAR, NEAR / 100);
    c.release_route_fee("f1");
    assert_eq!(c.day.spent_yocto, 5 * NEAR - NEAR / 100);
    c.release_route_spend("f1", 2 * NEAR); // record gone: nothing more
    assert_eq!(c.day.spent_yocto, 5 * NEAR - NEAR / 100);
}

// ============================================================ F-01 auto-upgrade, F-02/03, F-19

const H1: &str = "3ya9mmnX9uNJ6NcJKWHMS1pv2Dnv8jEXCMLuTxCpCz1V";
const H2: &str = "4ya9mmnX9uNJ6NcJKWHMS1pv2Dnv8jEXCMLuTxCpCz1V";

/// A callback context carrying one promise result.
fn cb_ctx(now: u64, r: PromiseResult) {
    testing_env!(
        VMContextBuilder::new()
            .current_account_id(a(TA))
            .predecessor_account_id(a(TA))
            .account_balance(NearToken::from_yoctonear(10 * NEAR))
            .storage_usage(100_000)
            .block_timestamp(now)
            .prepaid_gas(Gas::from_tgas(300))
            .build(),
        near_sdk::test_vm_config(),
        near_sdk::RuntimeFeesConfig::test(),
        Default::default(),
        vec![r],
    );
}

fn approved(hs: &[&str]) -> PromiseResult {
    PromiseResult::Successful(serde_json::to_vec(hs).unwrap())
}

fn auto_on(c: &mut TradingAccount, owner: &str, now: u64) {
    at(TA, owner, 1, now);
    c.owner_set_auto_upgrade(true);
}

fn schedule(c: &mut TradingAccount, now: u64, r: PromiseResult) {
    at(TA, "anyone.near", 0, now);
    c.schedule_auto_upgrade();
    let rs = get_created_receipts();
    assert_eq!(
        (rs[0].receiver_id.as_str(), fc(&rs[0], 0).0.as_str()),
        ("trade.unrlzd.near", "get_approved_code_hashes")
    );
    assert_eq!(fc(&rs[1], 0).0, "on_auto_scheduled");
    cb_ctx(now, r);
    c.on_auto_scheduled();
}

fn apply(c: &mut TradingAccount, now: u64, r: PromiseResult) -> String {
    at(TA, "anyone.near", 0, now);
    let first = outcome(|| c.apply_auto_upgrade());
    if first != "ok" {
        return first;
    }
    let h = c.get_auto_upgrade().pending.map(|p| p.code_hash).unwrap_or_default();
    cb_ctx(now, r);
    c.on_auto_apply_checked(h.parse().unwrap());
    "ok".into()
}

fn upgraded_to(h: &str) -> bool {
    let rs = get_created_receipts();
    rs.len() == 1
        && matches!(rs[0].actions[0], MockAction::UseGlobalContract { .. })
        && fc(&rs[0], 1).0 == "migrate"
        && matches!(&rs[0].actions[1], MockAction::FunctionCallWeight { gas_weight, .. } if gas_weight.0 == 1)
        && fc(&rs[0], 2) == ("on_code_installed".into(), json!({"code_hash": h}), 0, GAS_CODE_INSTALLED)
}

use crate::upgrade::{RescueAsset, AUTO_UPGRADE_DELAY_NS, GAS_CODE_INSTALLED};

#[test]
fn f01_auto_upgrade_off_by_default_and_permissionless_calls_refused() {
    let mut c = ta_at(TA, "alice.near", None, T0);
    let v = c.get_auto_upgrade();
    assert!(!v.enabled && v.pending.is_none() && v.installed.is_none());
    assert_eq!(v.delay_ns.0, 72 * 3_600 * NS_PER_SEC);
    at(TA, "anyone.near", 0, T0);
    assert_eq!(outcome(|| c.schedule_auto_upgrade()), "E_AUTO_OFF");
    assert_eq!(outcome(|| c.apply_auto_upgrade()), "E_AUTO_OFF");
    // only the owner sets it (1 yocto)
    at(TA, "mallory.near", 1, T0);
    assert_eq!(outcome(|| c.owner_set_auto_upgrade(true)), "E_NOT_OWNER");
    at(TA, "alice.near", 0, T0);
    assert_eq!(outcome(|| c.owner_set_auto_upgrade(true)), "E_ONE_YOCTO");
}

#[test]
fn f01_schedule_wait_apply_once() {
    let mut c = ta_at(TA, "alice.near", None, T0);
    auto_on(&mut c, "alice.near", T0);
    schedule(&mut c, T0 + 1, approved(&[H1]));
    let p = c.get_auto_upgrade().pending.unwrap();
    assert_eq!((p.code_hash.as_str(), p.eta_ns.0), (H1, T0 + 1 + AUTO_UPGRADE_DELAY_NS));
    assert!(get_logs().iter().any(|l| l.contains("auto_upgrade_scheduled")));
    // a re-schedule of the same approved hash keeps the eta (no pushing it back)
    schedule(&mut c, T0 + 100, approved(&[H1]));
    assert_eq!(c.get_auto_upgrade().pending.unwrap().eta_ns, p.eta_ns);
    // early
    assert_eq!(apply(&mut c, p.eta_ns.0 - 1, approved(&[H1])), "E_AUTO_EARLY");
    // due, still approved: one guarded batch, migrate with all leftover gas
    assert_eq!(apply(&mut c, p.eta_ns.0, approved(&[H1])), "ok");
    assert!(upgraded_to(H1), "{:?}", get_created_receipts());
    // R2-01: pending stays until the new code confirms the install
    assert!(c.get_auto_upgrade().pending.is_some());
    // double apply while the batch is in flight: refused (the call and a late callback)
    cb_ctx(p.eta_ns.0, approved(&[H1]));
    c.on_auto_apply_checked(H1.parse().unwrap());
    assert!(get_created_receipts().is_empty());
    assert!(get_logs()[0].contains("\"reason\":\"applying\""), "{:?}", get_logs());
    at(TA, "anyone.near", 0, p.eta_ns.0 + 1);
    assert_eq!(outcome(|| c.apply_auto_upgrade()), "E_AUTO_APPLYING");
    // the new code records what it installed and clears the pending entry
    cb_ctx(p.eta_ns.0 + 2, PromiseResult::Successful(vec![]));
    c.on_code_installed(H1.parse().unwrap());
    assert!(get_logs().iter().any(|l| l.contains("auto_upgrade_applied")));
    assert_eq!(c.get_auto_upgrade().installed.as_deref(), Some(H1));
    assert!(c.get_auto_upgrade().pending.is_none());
    at(TA, "anyone.near", 0, p.eta_ns.0 + 3);
    assert_eq!(outcome(|| c.apply_auto_upgrade()), "E_AUTO_NONE");
    schedule(&mut c, p.eta_ns.0 + 3, approved(&[H1]));
    assert!(c.get_auto_upgrade().pending.is_none());
    assert!(get_logs()[0].contains("nothing_new"));
}

#[test]
fn f01_revoked_foreign_unreadable_vetoed_off() {
    let mut c = ta_at(TA, "alice.near", None, T0);
    auto_on(&mut c, "alice.near", T0);
    schedule(&mut c, T0 + 1, approved(&[H1]));
    let eta = c.get_auto_upgrade().pending.unwrap().eta_ns.0;
    // revoked before the eta: refused at apply, nothing scheduled
    for (r, why) in [
        (approved(&[]), "not_approved"),
        (approved(&[H2]), "not_approved"),
        (PromiseResult::Failed, "not_approved"),
        (PromiseResult::Successful(b"{\"x\":1}".to_vec()), "not_approved"),
    ] {
        assert_eq!(apply(&mut c, eta, r), "ok");
        assert!(get_created_receipts().is_empty());
        assert!(get_logs()[0].contains(&format!("\"reason\":\"{why}\"")), "{:?}", get_logs());
        assert!(c.get_auto_upgrade().pending.is_some(), "a refusal keeps the pending entry");
    }
    // a foreign hash in a callback (not the pending one) is refused
    cb_ctx(eta, approved(&[H1, H2]));
    c.on_auto_apply_checked(H2.parse().unwrap());
    assert!(get_created_receipts().is_empty());
    assert!(get_logs()[0].contains("not_pending"));
    // device veto through execute (no new device method): cleared, and never scheduled again
    at(TA, TA, 0, eta);
    c.execute(vec![Op::CancelAutoUpgrade {}], "veto".into(), U64(eta + NS_PER_SEC), U128(0));
    let v = c.get_auto_upgrade();
    assert!(v.pending.is_none());
    assert_eq!(v.vetoed, vec![H1.to_string()]);
    assert!(get_logs().iter().any(|l| l.contains("auto_upgrade_vetoed") && l.contains("\"by\":\"device\"")));
    schedule(&mut c, eta + 1, approved(&[H1]));
    assert!(c.get_auto_upgrade().pending.is_none(), "a vetoed hash is not rescheduled");
    // a newer approved hash is
    schedule(&mut c, eta + 2, approved(&[H1, H2]));
    assert_eq!(c.get_auto_upgrade().pending.unwrap().code_hash, H2);
    // the owner vetoes too
    at(TA, "alice.near", 1, eta + 3);
    c.owner_cancel_auto_upgrade();
    assert!(c.get_auto_upgrade().pending.is_none());
    // turning it off clears a pending one; a callback after that refuses
    schedule(&mut c, eta + 4, approved(&["5ya9mmnX9uNJ6NcJKWHMS1pv2Dnv8jEXCMLuTxCpCz1V"]));
    assert!(c.get_auto_upgrade().pending.is_some());
    at(TA, "alice.near", 1, eta + 5);
    c.owner_set_auto_upgrade(false);
    assert!(c.get_auto_upgrade().pending.is_none());
    cb_ctx(eta + 6, approved(&[H1]));
    c.on_auto_scheduled();
    assert!(get_logs()[0].contains("\"reason\":\"off\""));
    // a relayer (automation) key can't veto: execute is device-only
    let mut r = with_automation();
    ctx_pk(me().as_str(), Some(auto_pk()), 0, T0 + 1);
    assert_eq!(
        outcome(|| r.execute(vec![Op::CancelAutoUpgrade {}], "v".into(), U64(T0 + NS_PER_SEC), U128(0))),
        "E_AUTOMATION_KEY"
    );
}

/// The signed door sets auto-upgrade and vetoes too; an order fire can't carry the veto op.
#[test]
fn f01_signed_ops_and_never_in_an_order_fire() {
    let s = Signer::p256("o-r1");
    let mut c = signer_ta(&s, T0);
    let mp = sign(&s, Standard::WebAuthn, TA, &c, r#"[{"op":"set_auto_upgrade","enabled":true}]"#, T0);
    assert_eq!(run_signed(&mut c, TA, mp, T0), "ok");
    assert!(c.get_auto_upgrade().enabled);
    schedule(&mut c, T0 + 1, approved(&[H1]));
    let mp = sign_with(
        &s,
        Standard::WebAuthn,
        TA,
        &s.owner_id(),
        salt_of(&c),
        r#"[{"op":"cancel_auto_upgrade"}]"#,
        T0 + 2,
        T0 + 60 * NS_PER_SEC,
        9,
    );
    assert_eq!(run_signed(&mut c, TA, mp, T0 + 2), "ok");
    assert_eq!(c.get_auto_upgrade().vetoed, vec![H1.to_string()]);
    let o = Order {
        token_in: a("wrap.near"),
        token_out: a("meme.near"),
        amount_in: U128(1),
        min_out: U128(1),
        trigger_meta: String::new(),
        expires_at_ns: U64(u64::MAX),
        dexes: vec![],
        pending: false,
    };
    assert_eq!(check_order_op(&o, &Op::CancelAutoUpgrade {}, &a("wrap.near")), Err("E_ORDER_OPS"));
}

/// F-02: every upgrade path gives migrate all leftover gas; F-03: the state version is written.
#[test]
fn f02_f03_migrate_gas_and_state_version() {
    let mut c = ta_at(TA, "alice.near", None, T0);
    assert_eq!(c.get_auto_upgrade().state_version, 160);
    at(TA, "alice.near", 1, T0);
    c.owner_upgrade(H1.parse().unwrap());
    let rs = get_created_receipts();
    assert!(
        matches!(&rs[0].actions[1], MockAction::FunctionCallWeight { method_name, gas_weight, prepaid_gas, .. }
        if method_name == b"migrate" && gas_weight.0 == 1 && *prepaid_gas == Gas::from_tgas(20))
    );
    // the signed upgrade's callback forwards all leftover gas too
    let s = Signer::ed25519("o-ed");
    let mut d = signer_ta(&s, T0);
    let mp =
        sign(&s, Standard::RawEd25519, TA, &d, &format!(r#"[{{"op":"upgrade","code_hash":"{H1}"}}]"#), T0);
    assert_eq!(run_signed(&mut d, TA, mp, T0), "ok");
    let rs = get_created_receipts();
    assert!(matches!(&rs[1].actions[0], MockAction::FunctionCallWeight { method_name, gas_weight, .. }
        if method_name == b"on_upgrade_checked" && gas_weight.0 == 1));
    // migrate (from a pre-1.6 state without `sv`) writes it
    env::storage_remove(crate::upgrade::K_STATE_VERSION);
    env::state_write(&c);
    at(TA, TA, 0, T0 + 1);
    let m = TradingAccount::migrate();
    assert_eq!(m.get_auto_upgrade().state_version, 160);
}

/// F-03: the raw storage key space is collision-free. Every key the account writes is listed
/// with its length rule (a fixed total length, or a variable suffix); two entries can collide
/// only if one prefix is a prefix of the other and their length sets meet.
#[test]
fn f03_raw_storage_keys_never_collide() {
    #[derive(Clone, Copy, Debug)]
    enum L {
        Fixed(usize),
        Var,
    }
    use L::*;
    let keys: Vec<(&[u8], L)> = vec![
        (b"STATE", Fixed(5)), // near-sdk contract state
        (crate::intents::K_ONECLICK, Fixed(2)),
        (K_INSTALLING, Fixed(2)),
        (K_AUTOMATION, Fixed(2)),
        (K_RELAYER_KEYS, Fixed(2)),
        (crate::upgrade::K_AUTO_UPGRADE, Fixed(2)),
        (K_PENDING_BASE, Fixed(2)),
        (crate::upgrade::K_CODE_HASH, Fixed(2)),
        (K_PENDING_CAPS, Fixed(2)),
        (b"fe", Fixed(2)), // chain escrow
        (K_DAY_GAS, Fixed(2)),
        (K_INIT_REG, Fixed(2)),
        (b"lk", Var),     // chain lock + q
        (b"o", Fixed(9)), // order + u64
        (K_ORDER_INDEX, Fixed(2)),
        (K_ORDER_NEXT, Fixed(2)),
        (b"ov", Fixed(10)), // chain order via + u64
        (owner::K_OWNER_AUTH, Fixed(2)),
        (crate::intents::K_OWNER_QUOTES, Fixed(2)),
        (crate::intents::K_USED_QUOTES, Fixed(2)),
        (K_RELAYER_ALLOWANCE, Fixed(2)),
        (b"ri", Fixed(2)),    // route index
        (b"rk", Fixed(10)),   // continuation + u64
        (b"rn", Fixed(2)),    // continuation counter
        (K_ROUTE_SPEND, Var), // + route id
        (b"rt", Var),         // route + id
        (K_RELAYER_WEEK, Fixed(2)),
        (crate::upgrade::K_STATE_VERSION, Fixed(2)),
        (crate::upgrade::K_APPLYING, Fixed(2)),
        (crate::upgrade::K_IN_FLIGHT, Fixed(2)),
        (owner::K_OWNER_NONCES, Fixed(2)),
        (crate::intents::K_WITHDRAW_CAP, Fixed(2)),
        (crate::intents::K_DESTS, Fixed(3)),
        (crate::intents::K_WITHDRAW_DAY, Fixed(2)),
        (crate::intents::K_WITHDRAW_CAP_USD, Fixed(2)),
    ];
    let meets = |a: L, b: L, min: usize| match (a, b) {
        (Fixed(x), Fixed(y)) => x == y,
        (Fixed(x), Var) | (Var, Fixed(x)) => x >= min,
        (Var, Var) => true,
    };
    for (i, (pa, la)) in keys.iter().enumerate() {
        if let Fixed(n) = la {
            assert!(*n >= pa.len());
        }
        for (pb, lb) in keys.iter().skip(i + 1) {
            let (short, long) = if pa.len() <= pb.len() { (pa, pb) } else { (pb, pa) };
            if long.starts_with(short) {
                assert!(
                    !meets(*la, *lb, long.len()),
                    "{:?} / {:?} can collide",
                    String::from_utf8_lossy(pa),
                    String::from_utf8_lossy(pb)
                );
            }
        }
    }
    // every 2-letter constant in the list is distinct (a duplicate would show above as equal)
    assert_eq!(keys.len(), 35);
}

/// F-19: owner-only rescue to the owner's home, both doors; never self / the verifier / a
/// locked route token.
#[test]
fn f19_rescue_to_home_only() {
    let mut c = ta_at(TA, "alice.near", None, T0);
    let run = |c: &mut TradingAccount, asset: RescueAsset| {
        at(TA, "alice.near", 1, T0);
        outcome(|| c.owner_rescue(asset))
    };
    // NEP-245 and NFT to the NEAR-wallet owner's account
    assert_eq!(
        run(
            &mut c,
            RescueAsset::Mt { contract: a("v2_1.omni.hot.tg"), token_id: "56_111".into(), amount: U128(5) }
        ),
        "ok"
    );
    let rs = get_created_receipts();
    assert_eq!(rs[0].receiver_id, a("v2_1.omni.hot.tg"));
    assert_eq!(
        fc(&rs[0], 0),
        ("mt_transfer".into(), json!({"receiver_id":"alice.near","token_id":"56_111","amount":"5"}), 1, 50)
    );
    assert!(get_logs().iter().any(|l| l.contains("owner_rescue")));
    assert_eq!(run(&mut c, RescueAsset::Nft { contract: a("nft.near"), token_id: "7".into() }), "ok");
    assert_eq!(fc(&get_created_receipts()[0], 0).0, "nft_transfer");
    assert_eq!(fc(&get_created_receipts()[0], 0).1["receiver_id"], "alice.near");
    // an FT: withdraw_home's path (register the owner, then transfer)
    assert_eq!(run(&mut c, RescueAsset::Ft { contract: a("airdrop.near"), amount: U128(9) }), "ok");
    assert_eq!(fc(&get_created_receipts()[0], 0).0, "storage_deposit");
    // refused: self, the verifier, a locked route token, zero, non-owner, no yocto
    for (asset, want) in [
        (RescueAsset::Nft { contract: a(TA), token_id: "1".into() }, "E_BAD_OP"),
        (
            RescueAsset::Mt {
                contract: a("intents.near"),
                token_id: "nep141:wrap.near".into(),
                amount: U128(1),
            },
            "E_BAD_OP",
        ),
        (RescueAsset::Mt { contract: a("x.near"), token_id: "t".into(), amount: U128(0) }, "E_BAD_OP"),
        (RescueAsset::Nft { contract: a("x.near"), token_id: String::new() }, "E_BAD_OP"),
    ] {
        assert_eq!(run(&mut c, asset), want);
    }
    at(TA, TA, 0, T0);
    crate::chain::store::lock("zec.omft.near", "r1");
    assert_eq!(run(&mut c, RescueAsset::Ft { contract: a("zec.omft.near"), amount: U128(1) }), "E_Q_BUSY");
    at(TA, "mallory.near", 1, T0);
    assert_eq!(
        outcome(|| c.owner_rescue(RescueAsset::Nft { contract: a("n.near"), token_id: "1".into() })),
        "E_NOT_OWNER"
    );
    at(TA, "alice.near", 0, T0);
    assert_eq!(
        outcome(|| c.owner_rescue(RescueAsset::Nft { contract: a("n.near"), token_id: "1".into() })),
        "E_ONE_YOCTO"
    );
    // a signed-path owner's home is its intents balance: *_transfer_call to intents, msg = owner
    let s = Signer::p256("o-r1");
    let mut d = signer_ta(&s, T0);
    let op = r#"[{"op":"rescue","asset":{"Mt":{"contract":"v2_1.omni.hot.tg","token_id":"56_111","amount":"5"}}}]"#;
    let mp = sign(&s, Standard::WebAuthn, TA, &d, op, T0);
    assert_eq!(run_signed(&mut d, TA, mp, T0), "ok");
    let rs = get_created_receipts();
    assert_eq!(
        fc(&rs[0], 0),
        (
            "mt_transfer_call".into(),
            json!({"receiver_id":"intents.near","token_id":"56_111","amount":"5","approval":null,"memo":null,"msg": s.owner_id()}),
            1,
            50
        )
    );
    let op = r#"[{"op":"rescue","asset":{"Nft":{"contract":"nft.near","token_id":"7"}}}]"#;
    let mp = sign_with(
        &s,
        Standard::WebAuthn,
        TA,
        &s.owner_id(),
        salt_of(&d),
        op,
        T0 + 1,
        T0 + 60 * NS_PER_SEC,
        9,
    );
    assert_eq!(run_signed(&mut d, TA, mp, T0 + 1), "ok");
    assert_eq!(fc(&get_created_receipts()[0], 0).0, "nft_transfer_call");
}

// ============================================================ internal review 2 (A1 items)
// The PoCs of docs/audit/v160-internal-review-2-pocs flipped into regression tests (each failed on
// 6307b1b1).
mod review2 {
    use super::*;

    fn cb_gas(now: u64, tgas: u64, r: PromiseResult) {
        testing_env!(
            VMContextBuilder::new()
                .current_account_id(a(TA))
                .predecessor_account_id(a(TA))
                .account_balance(NearToken::from_yoctonear(10 * NEAR))
                .storage_usage(100_000)
                .block_timestamp(now)
                .prepaid_gas(Gas::from_tgas(tgas))
                .build(),
            near_sdk::test_vm_config(),
            near_sdk::RuntimeFeesConfig::test(),
            Default::default(),
            vec![r],
        );
    }

    fn sched(c: &mut TradingAccount, now: u64, hs: &[&str]) {
        at(TA, "anyone.near", 0, now);
        c.schedule_auto_upgrade();
        cb_ctx(now, approved(hs));
        c.on_auto_scheduled();
    }

    fn scheduled(now: u64) -> TradingAccount {
        let mut c = ta_at(TA, "alice.near", None, T0);
        auto_on(&mut c, "alice.near", T0);
        sched(&mut c, now, &[H1]);
        c
    }

    fn call_gas(pred: &str, now: u64, tgas: u64) {
        testing_env!(VMContextBuilder::new()
            .current_account_id(a(TA))
            .predecessor_account_id(a(pred))
            .signer_account_id(a(pred))
            .account_balance(NearToken::from_yoctonear(10 * NEAR))
            .storage_usage(100_000)
            .block_timestamp(now)
            .prepaid_gas(Gas::from_tgas(tgas))
            .build());
    }

    /// R2-01: a starved apply is refused (the call below MIN_APPLY_GAS; a callback left with
    /// less than MIN_APPLY_CB_GAS schedules nothing); pending and its eta survive.
    #[test]
    fn r2_01_low_gas_apply_does_not_consume_the_pending_upgrade() {
        let mut c = scheduled(T0 + 1);
        let eta = c.get_auto_upgrade().pending.unwrap().eta_ns.0;
        call_gas("griefer.near", eta, 60);
        assert_eq!(outcome(|| c.apply_auto_upgrade()), "E_APPLY_GAS");
        call_gas("griefer.near", eta, 250);
        c.apply_auto_upgrade();
        cb_gas(eta, 37, approved(&[H1]));
        c.on_auto_apply_checked(H1.parse().unwrap());
        assert!(get_created_receipts().is_empty(), "no batch with a starved callback");
        assert!(get_logs()[0].contains("\"reason\":\"low_gas\""), "{:?}", get_logs());
        assert_eq!(c.get_auto_upgrade().pending.unwrap().eta_ns.0, eta);
    }

    /// R2-01b: a batch that failed (on_code_installed never ran) leaves pending and its eta;
    /// after the `ap` window a re-schedule keeps the eta and a new apply is possible.
    #[test]
    fn r2_01b_failed_apply_keeps_the_eta() {
        let mut c = scheduled(T0 + 1);
        let eta = c.get_auto_upgrade().pending.unwrap().eta_ns.0;
        call_gas("griefer.near", eta, 300);
        c.apply_auto_upgrade();
        cb_gas(eta, 250, approved(&[H1]));
        c.on_auto_apply_checked(H1.parse().unwrap());
        assert!(upgraded_to(H1));
        // the batch failed: nothing installed; the keeper schedules again
        sched(&mut c, eta + 1, &[H1]);
        assert_eq!(c.get_auto_upgrade().pending.unwrap().eta_ns.0, eta);
        assert!(c.get_auto_upgrade().installed.is_none());
        // after the in-flight window (block height advanced) a new apply goes through
        testing_env!(VMContextBuilder::new()
            .current_account_id(a(TA))
            .predecessor_account_id(a("keeper.near"))
            .block_height(1_000)
            .block_timestamp(eta + 2)
            .account_balance(NearToken::from_yoctonear(10 * NEAR))
            .storage_usage(100_000)
            .prepaid_gas(Gas::from_tgas(300))
            .build());
        assert_eq!(outcome(|| c.apply_auto_upgrade()), "ok");
    }

    /// R2-02: the intents-home MT rescue uses NEP-245 single-token `mt_transfer_call` args.
    #[test]
    fn r2_02_mt_rescue_to_intents_uses_nep245_single_args() {
        #[derive(near_sdk::serde::Deserialize)]
        #[serde(crate = "near_sdk::serde", deny_unknown_fields)]
        #[allow(dead_code)]
        struct MtTransferCall {
            receiver_id: AccountId,
            token_id: String,
            amount: U128,
            approval: Option<(AccountId, u64)>,
            memo: Option<String>,
            msg: String,
        }
        let s = Signer::p256("o-r1");
        let mut d = signer_ta(&s, T0);
        let op = r#"[{"op":"rescue","asset":{"Mt":{"contract":"v2_1.omni.hot.tg","token_id":"56_111","amount":"5"}}}]"#;
        let mp = sign(&s, Standard::WebAuthn, TA, &d, op, T0);
        assert_eq!(run_signed(&mut d, TA, mp, T0), "ok");
        let (method, args, _, gas) = fc(&get_created_receipts()[0], 0);
        assert_eq!((method.as_str(), gas), ("mt_transfer_call", 50));
        let p = near_sdk::serde_json::from_value::<MtTransferCall>(args.clone()).expect("NEP-245 args");
        assert_eq!((p.token_id.as_str(), p.amount.0, p.msg), ("56_111", 5, s.owner_id()));
    }

    /// R2-03: the device veto works past the daily cap (charged, never refused).
    #[test]
    fn r2_03_device_veto_works_past_the_daily_cap() {
        let mut c = scheduled(T0 + 1);
        c.day.spent_yocto = c.caps.daily_cap_yocto.0;
        at(TA, TA, 0, T0 + 2);
        let r = outcome(|| {
            c.execute(vec![Op::CancelAutoUpgrade {}], "veto".into(), U64(T0 + NS_PER_SEC), U128(0))
        });
        assert_eq!(r, "ok");
        assert!(c.get_auto_upgrade().pending.is_none());
        assert!(c.get_day().gas_spent_yocto.0 > 0, "charged");
    }

    /// R2-04: a pending hash the factory stops approving is dropped; a re-approval gets a fresh
    /// 72 h window.
    #[test]
    fn r2_04_reapproved_hash_gets_a_fresh_window() {
        let mut c = scheduled(T0 + 1);
        let eta = c.get_auto_upgrade().pending.unwrap().eta_ns.0;
        sched(&mut c, T0 + 2, &[]);
        assert!(c.get_auto_upgrade().pending.is_none());
        assert!(get_logs().iter().any(|l| l.contains("auto_upgrade_dropped")));
        let later = eta + 10 * 24 * 3_600 * NS_PER_SEC;
        sched(&mut c, later, &[H1]);
        assert!(c.get_auto_upgrade().pending.unwrap().eta_ns.0 >= later + AUTO_UPGRADE_DELAY_NS);
    }

    /// R2-09: apply waits for a route lock, a settle in flight, a pending order fire and a
    /// continuation in flight; nothing is cancelled (pending kept).
    #[test]
    fn r2_09_apply_waits_for_in_flight_routes_and_orders() {
        let mut c = scheduled(T0 + 1);
        let eta = c.get_auto_upgrade().pending.unwrap().eta_ns.0;
        let try_apply = |c: &mut TradingAccount, h: u64| {
            testing_env!(
                VMContextBuilder::new()
                    .current_account_id(a(TA))
                    .predecessor_account_id(a(TA))
                    .block_height(h)
                    .block_timestamp(eta)
                    .account_balance(NearToken::from_yoctonear(10 * NEAR))
                    .storage_usage(100_000)
                    .prepaid_gas(Gas::from_tgas(300))
                    .build(),
                near_sdk::test_vm_config(),
                near_sdk::RuntimeFeesConfig::test(),
                Default::default(),
                vec![approved(&[H1])],
            );
            c.on_auto_apply_checked(H1.parse().unwrap());
            get_created_receipts().is_empty()
        };
        // a Chain between its legs (Q lock)
        at(TA, TA, 0, eta);
        crate::chain::store::lock("zec.omft.near", "r1");
        assert!(try_apply(&mut c, 1), "waits for the lock");
        assert!(get_logs()[0].contains("in_flight"));
        // lock window over: goes through
        assert!(!try_apply(&mut c, 2_000));
        // a pending order fire (settle not landed yet)
        let mut c = scheduled(T0 + 1);
        crate::save_order(
            7,
            &Order {
                token_in: a("wrap.near"),
                token_out: a("meme.near"),
                amount_in: U128(NEAR),
                min_out: U128(1),
                trigger_meta: String::new(),
                expires_at_ns: U64(u64::MAX),
                dexes: vec![a("v2.ref-finance.near")],
                pending: true,
            },
        );
        let mut idx = crate::order_index();
        idx.push((7, u64::MAX));
        crate::set_order_index(&idx);
        assert!(try_apply(&mut c, 5_000), "waits for the order fire");
        assert!(c.get_auto_upgrade().pending.is_some(), "not cancelled");
        // a device swap whose settle is in flight
        let mut d = scheduled(T0 + 1);
        testing_env!(VMContextBuilder::new()
            .current_account_id(a(TA))
            .predecessor_account_id(a(TA))
            .signer_account_id(a(TA))
            .block_height(10)
            .block_timestamp(T0 + 5)
            .account_balance(NearToken::from_yoctonear(10 * NEAR))
            .storage_usage(100_000)
            .prepaid_gas(Gas::from_tgas(300))
            .build());
        d.execute(buy(NEAR / 10), "s1".into(), U64(T0 + 60 * NS_PER_SEC), U128(NEAR));
        assert!(try_apply(&mut d, 20), "waits for the settle");
        assert!(!try_apply(&mut d, 10 + crate::upgrade::SETTLE_WINDOW_BLOCKS));
    }

    /// R2-10: 16 vetoes kept; R2-11: init's code_hash is the installed code (never scheduled);
    /// R2-12: an upgrade through the predecessor door removes `sv` until the new code writes it.
    #[test]
    fn r2_10_11_12_vetoes_installed_code_and_state_version() {
        assert_eq!(crate::upgrade::MAX_VETOED, 16);
        at(TA, "tt.near", 0, T0);
        near_sdk::mock::with_mocked_blockchain(|b| {
            b.take_storage();
        });
        at(TA, "tt.near", 0, T0);
        let mut c = TradingAccount::init(
            a("alice.near"),
            FeeConfig { fee_bps: 100, fee_recipient: a("fees.near") },
            caps(2 * NEAR, 5 * NEAR),
            vec![],
            a("wrap.near"),
            None,
            None,
            Some(H1.parse().unwrap()),
        );
        assert_eq!(c.get_auto_upgrade().installed.as_deref(), Some(H1));
        auto_on(&mut c, "alice.near", T0);
        sched(&mut c, T0 + 1, &[H1]);
        assert!(c.get_auto_upgrade().pending.is_none(), "its own code is never scheduled");
        at(TA, "alice.near", 1, T0 + 2);
        c.owner_upgrade(H2.parse().unwrap());
        assert_eq!(c.get_auto_upgrade().state_version, 0, "sv unknown until the new code's migrate");
        cb_ctx(T0 + 3, PromiseResult::Successful(vec![]));
        c.on_code_installed(H2.parse().unwrap());
        assert_eq!(c.get_auto_upgrade().state_version, 160);
    }
}

// ============================================================ R2-09 on the owner upgrade doors
// The owner's own upgrades wait for in-flight work exactly like the permissionless apply: the
// predecessor `owner_upgrade` and the signed `upgrade` op (its entry and its callback).
mod owner_doors_in_flight {
    use super::*;
    use crate::chain::{
        store, ContTerms, Route, RouteKind, RouteState, CONT_BASE, LOCK_TTL_BLOCKS, ROUTE_PENDING_TTL_BLOCKS,
    };
    use crate::upgrade::SETTLE_WINDOW_BLOCKS;

    /// The block height the in-flight work starts at.
    const H0: u64 = 10;
    const NOW: u64 = T0 + 10;

    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Busy {
        /// a Chain between its legs / a Nearrr buy (Q lock)
        Lock,
        /// a device swap whose settle has not landed
        Settle,
        /// an order fire whose settle has not landed
        Order,
        /// an IntentsSwap continuation in flight
        Route,
    }
    const ALL: [Busy; 4] = [Busy::Lock, Busy::Settle, Busy::Order, Busy::Route];

    fn ctx(pred: &str, deposit: u128, height: u64, r: Option<PromiseResult>) {
        testing_env!(
            VMContextBuilder::new()
                .current_account_id(a(TA))
                .predecessor_account_id(a(pred))
                .signer_account_id(a(pred))
                .attached_deposit(NearToken::from_yoctonear(deposit))
                .account_balance(NearToken::from_yoctonear(10 * NEAR))
                .storage_usage(100_000)
                .block_height(height)
                .block_timestamp(NOW)
                .prepaid_gas(Gas::from_tgas(300))
                .build(),
            near_sdk::test_vm_config(),
            near_sdk::RuntimeFeesConfig::test(),
            Default::default(),
            r.into_iter().collect(),
        );
    }

    /// Puts the account in state `b` at H0. Returns the height from which a window state is over
    /// (None: over only once its callback lands).
    fn busy(c: &mut TradingAccount, b: Busy) -> Option<u64> {
        ctx(TA, 0, H0, None);
        match b {
            Busy::Lock => {
                store::lock("zec.omft.near", "r1");
                Some(H0 + LOCK_TTL_BLOCKS)
            }
            Busy::Settle => {
                c.execute(buy(NEAR / 10), "s1".into(), U64(NOW + 60 * NS_PER_SEC), U128(NEAR));
                Some(H0 + SETTLE_WINDOW_BLOCKS)
            }
            Busy::Order => {
                crate::save_order(7, &order(true));
                let mut idx = crate::order_index();
                idx.push((7, u64::MAX));
                crate::set_order_index(&idx);
                None
            }
            Busy::Route => {
                // a continuation fired at H0 (its callback not landed): ROUTE_PENDING_TTL_BLOCKS
                store::save_route("r2", &route(true)).unwrap();
                Some(H0 + ROUTE_PENDING_TTL_BLOCKS)
            }
        }
    }

    /// The order fire's settle landed (a continuation's: `landed_continuation_...`).
    fn landed(b: Busy) {
        ctx(TA, 0, H0 + 1, None);
        if b == Busy::Order {
            crate::save_order(7, &order(false));
        }
    }

    fn order(pending: bool) -> Order {
        Order {
            token_in: a("wrap.near"),
            token_out: a("meme.near"),
            amount_in: U128(NEAR),
            min_out: U128(1),
            trigger_meta: String::new(),
            expires_at_ns: U64(u64::MAX),
            dexes: vec![a("v2.ref-finance.near")],
            pending,
        }
    }

    fn route(pending: bool) -> Route {
        Route {
            kind: RouteKind::IntentsBuy,
            q: a("zec.omft.near"),
            origin: a("wrap.near"),
            deposit_address: "addr".into(),
            funded: U128(NEAR),
            quote_amount: U128(NEAR),
            q_min: U128(990),
            q_quoted: U128(1000),
            slippage_bps: 100,
            fee_escrow: U128(0),
            cont: Some(ContTerms {
                token_out: a("meme.near"),
                dexes: vec![a("v2.ref-finance.near")],
                min_final: U128(1),
            }),
            cont_deadline_ns: U64(NOW + 600 * NS_PER_SEC),
            quote_deadline_ns: U64(NOW + 900 * NS_PER_SEC),
            credited: U128(0),
            spent: U128(0),
            state: RouteState::Funded,
            cont_id: U64(CONT_BASE),
            pending,
            // the fire that set it, at H0
            pending_height: U64(H0),
        }
    }

    fn installs() -> bool {
        get_created_receipts()
            .iter()
            .any(|r| r.actions.iter().any(|x| matches!(x, MockAction::UseGlobalContract { .. })))
    }

    /// Predecessor door: "ok" + the install receipt, or the refusal code with nothing scheduled.
    fn pred_upgrade(c: &mut TradingAccount, height: u64) -> String {
        ctx("alice.near", 1, height, None);
        let r = outcome(|| c.owner_upgrade(H1.parse().unwrap()));
        assert_eq!(r == "ok", installs(), "{r}");
        r
    }

    /// Signed door, entry: "ok" + the factory read, or the refusal code with nothing scheduled.
    fn signed_upgrade(c: &mut TradingAccount, s: &Signer, height: u64, rnd: u8) -> String {
        let ops = format!(r#"[{{"op":"upgrade","code_hash":"{H1}"}}]"#);
        let mp = sign_with(
            s,
            Standard::Nep413,
            TA,
            &s.owner_id(),
            salt_of(c),
            &ops,
            NOW,
            NOW + 60 * NS_PER_SEC,
            rnd,
        );
        ctx(RELAYER, 0, height, None);
        let r = outcome(|| c.owner_signed(mp));
        let asked = get_created_receipts().iter().any(|x| fc(x, 0).0 == "get_approved_code_hashes");
        assert_eq!(r == "ok", asked, "{r}");
        r
    }

    /// Signed door, callback (the factory approved H1): installs, or logs `upgrade_refused`.
    fn signed_checked(c: &mut TradingAccount, height: u64) -> bool {
        ctx(TA, 0, height, Some(approved(&[H1])));
        c.on_upgrade_checked(H1.parse().unwrap());
        let ok = installs();
        assert_eq!(
            !ok,
            get_logs().iter().any(|l| l.contains("\"upgrade_refused\"") && l.contains("\"in_flight\""))
        );
        ok
    }

    /// Predecessor door: refused (E_IN_FLIGHT, nothing scheduled) in every in-flight state while
    /// an owner withdraw still goes through; it upgrades once the window passes or the callback
    /// lands.
    #[test]
    fn r2_09_owner_upgrade_waits_for_in_flight_work() {
        let mut refused = vec![];
        for b in ALL {
            let mut c = ta_at(TA, "alice.near", None, T0);
            busy(&mut c, b);
            refused.push((b, pred_upgrade(&mut c, H0 + 1)));
        }
        assert_eq!(refused, ALL.map(|b| (b, "E_IN_FLIGHT".to_string())));
        for b in ALL {
            let mut c = ta_at(TA, "alice.near", None, T0);
            let over = busy(&mut c, b);
            ctx("alice.near", 1, H0 + 1, None);
            c.owner_withdraw(None, U128(1), a("alice.near"));
            if let Some(h) = over {
                assert_eq!(pred_upgrade(&mut c, h - 1), "E_IN_FLIGHT", "{b:?}: last block");
                assert_eq!(pred_upgrade(&mut c, h), "ok", "{b:?}: window over");
            } else {
                assert_eq!(pred_upgrade(&mut c, 100_000), "E_IN_FLIGHT", "{b:?}: no expiry");
                landed(b);
                assert_eq!(pred_upgrade(&mut c, H0 + 2), "ok", "{b:?}: landed");
            }
        }
    }

    /// Signed door: the entry refuses (E_IN_FLIGHT) and the callback logs
    /// `upgrade_refused{reason: in_flight}`, nothing scheduled, in every in-flight state; both go
    /// through once the window passes or the callback lands.
    #[test]
    fn r2_09_signed_upgrade_waits_for_in_flight_work() {
        let s = Signer::ed25519("o-ed");
        let mut refused = vec![];
        for b in ALL {
            let mut c = signer_ta(&s, T0);
            busy(&mut c, b);
            let entry = signed_upgrade(&mut c, &s, H0 + 1, 1);
            refused.push((b, entry, signed_checked(&mut c, H0 + 1)));
        }
        assert_eq!(refused, ALL.map(|b| (b, "E_IN_FLIGHT".to_string(), false)));
        for b in ALL {
            let mut c = signer_ta(&s, T0);
            let later = match busy(&mut c, b) {
                Some(h) => {
                    assert_eq!(signed_upgrade(&mut c, &s, h - 1, 2), "E_IN_FLIGHT", "{b:?}: last block");
                    assert!(!signed_checked(&mut c, h - 1), "{b:?}: callback, last block");
                    h
                }
                None => {
                    landed(b);
                    H0 + 2
                }
            };
            assert_eq!(signed_upgrade(&mut c, &s, later, 3), "ok", "{b:?}: over");
            assert!(signed_checked(&mut c, later), "{b:?}: callback, over");
        }
    }

    /// Control: nothing in flight, both doors upgrade at once.
    #[test]
    fn r2_09_owner_doors_upgrade_when_idle() {
        let mut c = ta_at(TA, "alice.near", None, T0);
        assert_eq!(pred_upgrade(&mut c, H0), "ok");
        let s = Signer::ed25519("o-ed");
        let mut c = signer_ta(&s, T0);
        assert_eq!(signed_upgrade(&mut c, &s, H0, 1), "ok");
        assert!(signed_checked(&mut c, H0));
    }

    // ------------------------------------------------ a continuation whose callback never ran

    use crate::chain::exec::IntentsPull;

    /// What `stuck_continuation` fires: wNEAR within the sell route's bounds.
    fn pull() -> IntentsPull {
        IntentsPull { token: a("wrap.near"), amount: U128(1000) }
    }

    /// An IntentsSell route whose continuation is fired at H0 by the real `fire_continuation`
    /// (no lock, no settle window: only `pending` holds the account in flight) and whose callback
    /// never runs (out of gas, a panic). Returns the continuation id.
    fn stuck_continuation(c: &mut TradingAccount) -> u64 {
        ctx(TA, 0, H0, None);
        let r =
            Route { kind: RouteKind::IntentsSell, origin: a("zec.omft.near"), cont: None, ..route(false) };
        store::save_route("r9", &r).unwrap();
        let cid = store::new_cont("r9");
        c.execute_order(U64(cid), vec![Op::IntentsPull(pull())]);
        assert!(store::load_route("r9").unwrap().pending);
        assert!(store::lock_of("zec.omft.near").is_none());
        cid
    }

    /// The bound is the Q lock's (see ROUTE_PENDING_TTL_BLOCKS).
    #[test]
    fn route_pending_bound_is_the_lock_ttl() {
        assert_eq!(ROUTE_PENDING_TTL_BLOCKS, LOCK_TTL_BLOCKS);
    }

    /// Stuck route: both owner doors (and the apply, same `in_flight()`) wait until
    /// ROUTE_PENDING_TTL_BLOCKS after the fire, then upgrade. The route itself is untouched: still
    /// pending (its continuation can't fire again, so nothing is pulled twice), nothing credited
    /// or released, and a late callback still lands on exactly the state it expects, once.
    #[test]
    fn stuck_continuation_holds_upgrades_only_until_the_bound() {
        let s = Signer::ed25519("o-ed");
        let end = H0 + ROUTE_PENDING_TTL_BLOCKS;
        for signed in [false, true] {
            let mut c = if signed { signer_ta(&s, T0) } else { ta_at(TA, "alice.near", None, T0) };
            let cid = stuck_continuation(&mut c);
            if signed {
                assert_eq!(signed_upgrade(&mut c, &s, end - 1, 1), "E_IN_FLIGHT", "last block");
                assert!(!signed_checked(&mut c, end - 1), "callback, last block");
                ctx(TA, 0, end - 1, None);
                assert!(crate::upgrade::in_flight());
                ctx(TA, 0, end, None);
                assert!(!crate::upgrade::in_flight(), "the apply's condition too");
                assert_eq!(signed_upgrade(&mut c, &s, end, 2), "ok", "bound reached");
                assert!(signed_checked(&mut c, end), "callback, bound reached");
            } else {
                assert_eq!(pred_upgrade(&mut c, H0 + 1), "E_IN_FLIGHT");
                assert_eq!(pred_upgrade(&mut c, end - 1), "E_IN_FLIGHT", "last block");
                assert_eq!(pred_upgrade(&mut c, end), "ok", "bound reached");
            }
            let r = store::load_route("r9").unwrap();
            assert_eq!((r.state, r.pending, r.credited.0, r.spent.0), (RouteState::Funded, true, 0, 0));
            ctx(TA, 0, end + 1, None);
            assert_eq!(
                outcome(|| c.execute_order(U64(cid), vec![Op::IntentsPull(pull())])),
                "E_ORDER_PENDING"
            );
            // the late callback (e.g. on the new code): the route settles once, from its own state
            ctx(TA, 0, end + 2, Some(PromiseResult::Successful(b"\"1000\"".to_vec())));
            c.on_cont_pulled("r9".into(), pull(), None);
            let r = store::load_route("r9").unwrap();
            assert_eq!((r.state, r.pending, r.credited.0), (RouteState::Done, false, 1000));
            ctx(TA, 0, end + 3, None);
            assert_eq!(outcome(|| c.execute_order(U64(cid), vec![Op::IntentsPull(pull())])), "E_NO_ORDER");
        }
    }

    /// Control: a continuation whose callback lands (here a failed pull: route unchanged, pending
    /// cleared) releases the doors at once; the bound is only for one that never lands.
    #[test]
    fn landed_continuation_releases_upgrades_at_once() {
        let mut c = ta_at(TA, "alice.near", None, T0);
        stuck_continuation(&mut c);
        assert_eq!(pred_upgrade(&mut c, H0 + 1), "E_IN_FLIGHT");
        ctx(TA, 0, H0 + 1, Some(PromiseResult::Failed));
        c.on_cont_pulled("r9".into(), pull(), None);
        let r = store::load_route("r9").unwrap();
        assert_eq!((r.state, r.pending), (RouteState::Funded, false));
        assert_eq!(pred_upgrade(&mut c, H0 + 2), "ok");
    }

    /// Orders: a pending fire whose settle never lands holds the doors with no expiry, but the
    /// owner (predecessor, 1 yocto) or any device can always cancel it, pending or not; the late
    /// settle then finds no order and changes nothing.
    #[test]
    fn stuck_order_fire_is_cleared_by_cancel() {
        for by_owner in [true, false] {
            let mut c = ta_at(TA, "alice.near", None, T0);
            busy(&mut c, Busy::Order);
            assert_eq!(pred_upgrade(&mut c, 100_000), "E_IN_FLIGHT", "no expiry");
            if by_owner {
                ctx("alice.near", 1, 100_000, None);
            } else {
                ctx(TA, 0, 100_000, None);
            }
            c.cancel_order(U64(7));
            assert!(crate::load_order(7).is_none());
            assert_eq!(pred_upgrade(&mut c, 100_001), "ok", "by_owner {by_owner}");
        }
    }

    /// External audit F1 / F2 / F3 (docs/audit/v160-external-r209-delta.md). The PoCs, flipped into
    /// regression tests: each failed before the fix.
    mod ext_audit_routes {
        use super::*;
        use crate::chain::exec::IntentsPull;
        use crate::chain::ROUTE_EXPIRY_GRACE_NS;

        const DAY: u64 = 86_400 * NS_PER_SEC;
        const FEE: u128 = NEAR / 100;
        /// Past both deadlines of `route()` (cont NOW + 600 s, quote NOW + 900 s), not yet expired.
        const LATE: u64 = NOW + 3_600 * NS_PER_SEC;
        /// The first instant `route()` counts as expired.
        const EXPIRY: u64 = NOW + 900 * NS_PER_SEC + ROUTE_EXPIRY_GRACE_NS + 1;

        fn at_time(pred: &str, deposit: u128, height: u64, now: u64, r: Option<PromiseResult>) {
            testing_env!(
                VMContextBuilder::new()
                    .current_account_id(a(TA))
                    .predecessor_account_id(a(pred))
                    .signer_account_id(a(pred))
                    .attached_deposit(NearToken::from_yoctonear(deposit))
                    .account_balance(NearToken::from_yoctonear(10 * NEAR))
                    .storage_usage(100_000)
                    .block_height(height)
                    .block_timestamp(now)
                    .prepaid_gas(Gas::from_tgas(300))
                    .build(),
                near_sdk::test_vm_config(),
                near_sdk::RuntimeFeesConfig::test(),
                Default::default(),
                r.into_iter().collect(),
            );
        }

        /// An IntentsBuy route funded at NOW with an escrowed fee (as `dispatch_intents` writes it).
        fn funded(id: &str, q_min: u128) -> u64 {
            let cid = store::new_cont(id);
            let r = Route { q_min: U128(q_min), fee_escrow: U128(FEE), cont_id: U64(cid), ..route(false) };
            store::save_route(id, &r).unwrap();
            store::escrow_add(FEE);
            cid
        }

        fn pull(token: &str, amount: u128) -> IntentsPull {
            IntentsPull { token: a(token), amount: U128(amount) }
        }

        fn ok_result(x: u128) -> Option<PromiseResult> {
            Some(PromiseResult::Successful(format!("\"{x}\"").into_bytes()))
        }

        /// Fee transfers to the fee recipient scheduled by the last call.
        fn fee_transfers() -> Vec<u128> {
            get_created_receipts()
                .iter()
                .filter(|r| r.receiver_id.as_str() == "fees.near")
                .flat_map(|r| r.actions.iter())
                .filter_map(|x| match x {
                    MockAction::Transfer { deposit, .. } => Some(deposit.as_yoctonear()),
                    _ => None,
                })
                .collect()
        }

        fn expired_events() -> usize {
            get_logs().iter().filter(|l| l.contains("\"event\":\"route_expired\"")).count()
        }

        /// F1 (was `owner_recovery_leaves_the_route_funded_forever`): the documented recovery
        /// (`owner_withdraw_from_intents`, no reservation check) moves the delivery out of intents,
        /// so no pull can end the route. Before its expiry the route still reserves its tokens;
        /// from `max(deadlines) + ROUTE_EXPIRY_GRACE_NS` it reserves nothing, and the first sweep
        /// closes it once: escrow paid to the fee recipient, `route_expired`, slot freed, owner_hold 0.
        #[test]
        fn undeliverable_route_expires_and_settles_once() {
            let mut c = ta_at(TA, "alice.near", None, T0);
            at_time(TA, 0, H0, NOW, None);
            let cid = funded("rb", 990);
            // the delivery is not in the intents balance (moved before the guard below existed, or
            // taken by a sibling's continuation, `stranded_sibling_expires`)
            // after both deadlines: the hold pull gets "0", the refund finds no wNEAR
            at_time(TA, 0, H0 + 2, LATE, None);
            c.execute_order(U64(cid), vec![Op::IntentsPull(pull("zec.omft.near", 1000))]);
            at_time(TA, 0, H0 + 3, LATE, ok_result(0));
            c.on_cont_pulled("rb".into(), pull("zec.omft.near", 1000), None);
            at_time(TA, 0, H0 + 4, LATE, None);
            c.execute_order(U64(cid), vec![Op::IntentsPull(pull("wrap.near", NEAR))]);
            at_time(TA, 0, H0 + 5, LATE, ok_result(0));
            c.on_cont_refund_check("rb".into(), pull("wrap.near", NEAR));
            at_time(TA, 0, H0 + 6, LATE, ok_result(0));
            c.on_cont_pulled("rb".into(), pull("wrap.near", NEAR), None);
            assert_eq!(store::load_route("rb").unwrap().state, RouteState::Funded);
            // the last instant before expiry: still the route's own tokens
            at_time(TA, 0, H0 + 7, EXPIRY - 1, None);
            assert_eq!(outcome(|| c.withdraw_from_intents(a("wrap.near"), U128(1))), "E_Q_BUSY");
            assert_eq!(store::load_route("rb").unwrap().state, RouteState::Funded);
            // expired: the device's pull closes it first, then goes through
            at_time(TA, 0, H0 + 8, EXPIRY, None);
            assert_eq!(outcome(|| c.withdraw_from_intents(a("wrap.near"), U128(1))), "ok");
            let r = store::load_route("rb").unwrap();
            assert_eq!((r.state, r.fee_escrow.0), (RouteState::Expired, 0));
            assert_eq!(fee_transfers(), vec![FEE], "escrow paid once");
            assert_eq!(expired_events(), 1);
            assert_eq!(store::escrow_total(), 0);
            assert!(!store::route_index().contains(&"rb".to_string()), "left the index");
            assert_eq!(c.owner_hold(), 0);
            // idempotent: nothing settles twice, the continuation finds no Funded route
            at_time(TA, 0, H0 + 9, EXPIRY + DAY, None);
            assert_eq!(c.owner_hold(), 0);
            assert!(fee_transfers().is_empty());
            assert_eq!(expired_events(), 0);
            assert_eq!(
                outcome(|| c.execute_order(U64(cid), vec![Op::IntentsPull(pull("zec.omft.near", 1000))])),
                "E_NO_ORDER"
            );
            assert!(!store::route_live("rb"), "its id may be used again");
        }

        /// F1: an expired route reserves nothing and holds no slot even before any sweep (pure
        /// reads), and the owner's NEAR doors settle it first (owner_hold sweeps).
        #[test]
        fn expired_route_is_free_before_and_settled_by_the_owner_door() {
            let mut c = ta_at(TA, "alice.near", None, T0);
            at_time(TA, 0, H0, NOW, None);
            funded("rb", 990);
            at_time(TA, 0, H0 + 1, EXPIRY - 1, None);
            assert!(store::intents_token_reserved(&a("wrap.near"), &a("wrap.near")));
            assert_eq!(store::in_flight_count(), 1);
            at_time(TA, 0, H0 + 2, EXPIRY, None);
            assert!(!store::intents_token_reserved(&a("wrap.near"), &a("wrap.near")));
            assert!(!store::intents_token_reserved(&a("zec.omft.near"), &a("wrap.near")));
            assert_eq!(store::in_flight_count(), 0);
            assert_eq!(store::load_route("rb").unwrap().state, RouteState::Funded, "not swept yet");
            // the owner's NEAR withdraw: escrow settled first, nothing held back
            at_time("alice.near", 1, H0 + 3, EXPIRY, None);
            c.owner_withdraw(None, U128(NEAR), a("alice.near"));
            assert_eq!(store::load_route("rb").unwrap().state, RouteState::Expired);
            assert_eq!(fee_transfers(), vec![FEE]);
            assert_eq!(store::escrow_total(), 0);
        }

        /// F1 control: a pending route (a continuation in flight or stuck) and a Held / Done route
        /// never expire; only Funded and not pending does.
        #[test]
        fn only_funded_not_pending_routes_expire() {
            let mut c = ta_at(TA, "alice.near", None, T0);
            at_time(TA, 0, H0, NOW, None);
            store::save_route("p", &Route { fee_escrow: U128(FEE), ..route(true) }).unwrap();
            store::escrow_add(FEE);
            store::save_route("h", &Route { state: RouteState::Held, ..route(false) }).unwrap();
            at_time("alice.near", 1, H0 + 1, NOW + 365 * DAY, None);
            assert_eq!(c.owner_hold(), FEE, "a pending route keeps its escrow");
            assert_eq!(store::load_route("p").unwrap().state, RouteState::Funded);
            assert_eq!(store::load_route("h").unwrap().state, RouteState::Held);
            assert!(fee_transfers().is_empty());
            let _ = &mut c;
        }

        /// F1 (was `sibling_overpull_strands_a_route_forever`): a continuation may pull up to
        /// q_quoted x (1 + slippage), so it can take part of a sibling's delivery on the same Q and
        /// leave the sibling below its q_min (routing C.3). The stranded sibling now expires: its
        /// slot is free and 16 of them no longer brick IntentsSwap.
        #[test]
        fn stranded_sibling_expires() {
            let mut c = ta_at(TA, "alice.near", None, T0);
            at_time(TA, 0, H0, NOW, None);
            let ca = funded("ra", 990);
            let cb = funded("rb", 990);
            let bound = 1000 + 1000 * 100 / 10_000; // q_quoted x (1 + 1%)
            at_time(TA, 0, H0 + 1, LATE, None);
            c.execute_order(U64(ca), vec![Op::IntentsPull(pull("zec.omft.near", bound))]);
            at_time(TA, 0, H0 + 2, LATE, ok_result(bound));
            c.on_cont_pulled("ra".into(), pull("zec.omft.near", bound), None);
            assert_eq!(store::load_route("ra").unwrap().state, RouteState::Held);
            let left = 1980 - bound;
            at_time(TA, 0, H0 + 3, LATE, None);
            assert_eq!(
                outcome(|| c.execute_order(U64(cb), vec![Op::IntentsPull(pull("zec.omft.near", left))])),
                "E_CONT_AMOUNT"
            );
            c.execute_order(U64(cb), vec![Op::IntentsPull(pull("wrap.near", NEAR))]);
            at_time(TA, 0, H0 + 4, LATE, ok_result(left));
            c.on_cont_refund_check("rb".into(), pull("wrap.near", NEAR));
            at_time(TA, 0, H0 + 5, LATE, ok_result(0));
            c.on_cont_pulled("rb".into(), pull("wrap.near", NEAR), None);
            assert_eq!(store::load_route("rb").unwrap().state, RouteState::Funded);
            for i in 0..15 {
                funded(&format!("x{i}"), 990);
            }
            assert!(!store::route_slot_free());
            at_time(TA, 0, H0 + 1_000, EXPIRY, None);
            assert!(store::route_slot_free(), "expired routes hold no slot");
            // the next sweep (here a device pull of another token) closes all 16, each once; the
            // Held one is untouched
            c.withdraw_from_intents(a("usdc.near"), U128(1));
            // INDEP-2: one transfer for the sweep's paid fees (each still has its route_expired)
            assert_eq!(fee_transfers(), vec![16 * FEE]);
            assert_eq!(expired_events(), 16);
            assert_eq!(store::load_route("ra").unwrap().state, RouteState::Held);
            assert_eq!(store::escrow_total(), 0);
        }

        /// Owner guard: `owner_withdraw_from_intents` refuses (E_Q_BUSY) a token a live route
        /// reserves (its Q, its origin, wNEAR), so the owner can't be led to pull a delivery the
        /// route's refund check would then misread. Other tokens always pass.
        #[test]
        fn owner_pull_refuses_a_live_routes_tokens() {
            let mut c = ta_at(TA, "alice.near", None, T0);
            at_time(TA, 0, H0, NOW, None);
            funded("rb", 990);
            for t in ["zec.omft.near", "wrap.near"] {
                at_time("alice.near", 1, H0 + 1, LATE, None);
                assert_eq!(outcome(|| c.owner_withdraw_from_intents(a(t), U128(1))), "E_Q_BUSY", "{t}");
            }
            at_time("alice.near", 1, H0 + 1, LATE, None);
            assert_eq!(outcome(|| c.owner_withdraw_from_intents(a("usdc.near"), U128(1))), "ok");
            assert_eq!(c.get_intents_reserved(), vec![a("wrap.near"), a("zec.omft.near")]);
        }

        /// Owner guard, signed door: the `withdraw_from_intents` op runs the same body (E_Q_BUSY
        /// on a live route's token; recovers once it expired).
        #[test]
        fn signed_owner_pull_follows_the_same_rule() {
            let s = Signer::ed25519("o-ed");
            let mut c = signer_ta(&s, T0);
            at_time(TA, 0, H0, NOW, None);
            funded("rb", 990);
            let ops = r#"[{"op":"withdraw_from_intents","token":"zec.omft.near","amount":"1"}]"#;
            for (rnd, now, want) in [(1u8, LATE, "E_Q_BUSY"), (2, EXPIRY, "ok")] {
                at_time(TA, 0, H0 + 1, now, None);
                let mp = sign_with(
                    &s,
                    Standard::Nep413,
                    TA,
                    &s.owner_id(),
                    salt_of(&c),
                    ops,
                    now,
                    now + 60 * NS_PER_SEC,
                    rnd,
                );
                at_time(RELAYER, 0, H0 + 1, now, None);
                assert_eq!(outcome(|| c.owner_signed(mp)), want);
            }
            assert_eq!(store::load_route("rb").unwrap().state, RouteState::Expired);
        }

        /// Owner guard: the owner always recovers once the route is expired (F1: closed first,
        /// escrow paid) or stuck (a continuation fired ROUTE_PENDING_TTL_BLOCKS ago whose callback
        /// never ran: it can't fire again, so it protects nothing). The view follows the same rule.
        #[test]
        fn owner_pull_recovers_once_the_route_is_stuck_or_expired() {
            // expired
            let mut c = ta_at(TA, "alice.near", None, T0);
            at_time(TA, 0, H0, NOW, None);
            funded("rb", 990);
            at_time("alice.near", 1, H0 + 1, EXPIRY, None);
            assert!(c.get_intents_reserved().is_empty());
            assert_eq!(outcome(|| c.owner_withdraw_from_intents(a("zec.omft.near"), U128(1000))), "ok");
            assert_eq!(store::load_route("rb").unwrap().state, RouteState::Expired);
            assert_eq!(fee_transfers(), vec![FEE]);
            // stuck: pending since H0, nothing expires it (its escrow stays, R2-09 decision)
            let mut c = ta_at(TA, "alice.near", None, T0);
            at_time(TA, 0, H0, NOW, None);
            store::save_route("rs", &route(true)).unwrap();
            let end = H0 + ROUTE_PENDING_TTL_BLOCKS;
            at_time("alice.near", 1, end - 1, NOW + 365 * DAY, None);
            assert_eq!(c.get_intents_reserved(), vec![a("wrap.near"), a("zec.omft.near")], "fire may land");
            assert_eq!(outcome(|| c.owner_withdraw_from_intents(a("zec.omft.near"), U128(1))), "E_Q_BUSY");
            at_time("alice.near", 1, end, NOW + 365 * DAY, None);
            assert!(c.get_intents_reserved().is_empty());
            assert_eq!(outcome(|| c.owner_withdraw_from_intents(a("zec.omft.near"), U128(1000))), "ok");
            at_time(TA, 0, end, NOW + 365 * DAY, None);
            assert_eq!(outcome(|| c.withdraw_from_intents(a("wrap.near"), U128(1))), "ok", "device too");
            assert_eq!(
                store::load_route("rs").unwrap().state,
                RouteState::Funded,
                "the route itself untouched"
            );
        }

        /// F1: a signed quote deadline far ahead can't hold a route open: it counts at most
        /// ROUTE_QUOTE_SPAN_NS past the continuation deadline.
        #[test]
        fn far_quote_deadline_is_capped() {
            let r = Route { quote_deadline_ns: U64(u64::MAX), ..route(false) };
            let cont = r.cont_deadline_ns.0;
            assert_eq!(r.expires_at(), cont + crate::chain::ROUTE_QUOTE_SPAN_NS + ROUTE_EXPIRY_GRACE_NS);
            assert_eq!(route(false).expires_at(), EXPIRY - 1);
        }

        /// F2 (was `old_layout_route_is_not_silently_dropped`): an undecodable route fails closed
        /// (E_STATE) instead of reading as absent, and `migrate` rewrites the pre-9a0dd084 layout
        /// (the same borsh minus `pending_height`), keeping escrow and state.
        #[test]
        fn old_layout_route_fails_closed_and_migrate_rewrites_it() {
            let c = ta_at(TA, "alice.near", None, T0);
            at_time(TA, 0, H0, NOW, None);
            let r = Route { fee_escrow: U128(FEE), ..route(true) };
            store::save_route("old", &r).unwrap();
            store::escrow_add(FEE);
            let k = [b"rt".as_slice(), b"old"].concat();
            let b = env::storage_read(&k).unwrap();
            env::storage_write(&k, &b[..b.len() - 8]);
            assert_eq!(outcome(|| drop(store::load_route("old"))), "E_STATE");
            assert_eq!(
                outcome(|| {
                    let _ = crate::upgrade::in_flight();
                }),
                "E_STATE"
            );
            // migrate (on a real chain every height is past the bound from height 0)
            env::state_write(&c);
            at_time(TA, 0, ROUTE_PENDING_TTL_BLOCKS, NOW, None);
            let _m = TradingAccount::migrate();
            assert!(get_logs().iter().any(|l| l.contains("\"event\":\"routes_migrated\"")));
            let got = store::load_route("old").unwrap();
            assert_eq!(got, Route { pending_height: U64(0), ..r });
            assert!(!crate::upgrade::in_flight());
            assert_eq!(store::escrow_total(), FEE);
        }

        /// F2: a Chain order whose via predates V16-01 (no leg-1 bounds) fails closed on read and
        /// is cancelled by `migrate`; a current via is kept.
        #[test]
        fn old_layout_via_is_cancelled_by_migrate() {
            let c = ta_at(TA, "alice.near", None, T0);
            at_time(TA, 0, H0, NOW, None);
            let via = crate::chain::OrderVia {
                q: a("zec.omft.near"),
                leg1_dex: a("v2.ref-finance.near"),
                leg2_dex: a("dclv2.ref-labs.near"),
                min_mid: U128(1),
                max_mid: U128(2),
            };
            for id in [7u64, 8] {
                crate::save_order(id, &order(false));
                store::save_via(id, &via);
            }
            crate::set_order_index(&vec![(7, u64::MAX), (8, u64::MAX)]);
            // order 7's via in the pre-V16-01 layout: the same borsh minus min_mid / max_mid
            let k = [b"ov".as_slice(), &7u64.to_le_bytes()].concat();
            let b = env::storage_read(&k).unwrap();
            env::storage_write(&k, &b[..b.len() - 32]);
            assert_eq!(outcome(|| drop(store::load_via(7))), "E_STATE");
            env::state_write(&c);
            at_time(TA, 0, H0 + 1, NOW, None);
            let _m = TradingAccount::migrate();
            assert!(crate::load_order(7).is_none() && store::load_via(7).is_none());
            assert_eq!(store::load_via(8), Some(via));
            assert_eq!(crate::order_index().iter().map(|(i, _)| *i).collect::<Vec<_>>(), vec![8]);
        }

        /// F3: `migrate` runs in the upgrade batch's receipt (with UseGlobalContract), so work that
        /// started between the doors' check and the batch makes it panic: the whole upgrade, code
        /// included, reverts. Every in-flight kind refuses; an idle account migrates.
        #[test]
        fn migrate_refuses_under_in_flight_work() {
            for b in ALL {
                let mut c = ta_at(TA, "alice.near", None, T0);
                busy(&mut c, b);
                env::state_write(&c);
                at_time(TA, 0, H0 + 1, NOW, None);
                assert_eq!(outcome(|| drop(TradingAccount::migrate())), "E_IN_FLIGHT", "{b:?}");
            }
            let c = ta_at(TA, "alice.near", None, T0);
            env::state_write(&c);
            at_time(TA, 0, H0 + 1, NOW, None);
            assert_eq!(outcome(|| drop(TradingAccount::migrate())), "ok");
        }

        // ============ Independent review INDEP-1..5 (regressions; fail before the fix) ============

        /// An expired route "old" (escrow FEE, unswept) and a live route "live" (escrow FEE).
        fn expired_and_live() -> TradingAccount {
            let c = ta_at(TA, "alice.near", None, T0);
            at_time(TA, 0, H0, NOW, None);
            funded("old", 990);
            // funded a day later: live at the first one's EXPIRY
            at_time(TA, 0, H0 + 1, NOW + DAY, None);
            let cid = store::new_cont("live");
            let r = Route {
                fee_escrow: U128(FEE),
                cont_id: U64(cid),
                cont_deadline_ns: U64(NOW + DAY + 600 * NS_PER_SEC),
                quote_deadline_ns: U64(NOW + DAY + 900 * NS_PER_SEC),
                q: a("other.omft.near"),
                ..route(false)
            };
            store::save_route("live", &r).unwrap();
            store::escrow_add(FEE);
            c
        }

        /// INDEP-1: `liquid_balance().saturating_sub(self.owner_hold())` read the balance BEFORE
        /// owner_hold's sweep paid the expired route's escrow out, and the hold AFTER it: the free
        /// NEAR was overstated by the paid fee, so an owner NEAR withdraw took the live route's
        /// escrow (its fee later skipped). Now the door sweeps first and owner_hold is pure.
        #[test]
        fn indep1_owner_withdraw_keeps_a_live_routes_escrow_across_a_sweep() {
            let mut c = expired_and_live();
            at_time("alice.near", 1, H0 + 2, EXPIRY, None);
            let l = crate::liquid_balance();
            // free before the sweep minus the live escrow; the old route's FEE is about to leave
            let amount = l - FEE;
            let got = outcome(|| c.owner_withdraw(None, U128(amount), a("alice.near")));
            assert_eq!(got, "E_HELD_BALANCE");
            // what is really free goes through, the live escrow stays
            at_time("alice.near", 1, H0 + 3, EXPIRY, None);
            let free = crate::liquid_balance() - 2 * FEE;
            c.owner_withdraw(None, U128(free), a("alice.near"));
            // (the mock keeps the refused call's sweep: on chain it reverts and this call sweeps)
            assert_eq!(store::load_route("old").unwrap().state, RouteState::Expired);
            assert_eq!(store::escrow_total(), FEE, "the live route still escrows FEE");
            assert!(crate::liquid_balance() >= FEE, "left {}", crate::liquid_balance());
        }

        /// INDEP-1, callback site: withdraw_all's final native sweep (on_withdraw_all_report) must
        /// leave the live route's escrow when an expiry is settled in the same receipt.
        #[test]
        fn indep1_withdraw_all_report_keeps_a_live_routes_escrow_across_a_sweep() {
            let mut c = expired_and_live();
            at_time(TA, 0, H0 + 2, EXPIRY, None);
            c.on_withdraw_all_report(a("alice.near"), vec![], None);
            assert_eq!(fee_transfers(), vec![FEE]);
            assert_eq!(store::escrow_total(), FEE);
            assert!(crate::liquid_balance() >= FEE, "left {} < live escrow {FEE}", crate::liquid_balance());
        }

        /// INDEP-1: owner_hold is a pure read (no sweep, no transfer).
        #[test]
        fn indep1_owner_hold_is_pure() {
            let c = expired_and_live();
            at_time(TA, 0, H0 + 2, EXPIRY, None);
            assert_eq!(c.owner_hold(), 2 * FEE);
            assert!(fee_transfers().is_empty());
            assert_eq!(store::load_route("old").unwrap().state, RouteState::Funded);
        }

        /// INDEP-4: migrate cancelled an old-layout-via order BEFORE the F3 in-flight check, so an
        /// order fire in flight under the old code no longer blocked the install (its settle then
        /// landed on the new code). Now the check runs first: E_IN_FLIGHT.
        #[test]
        fn indep4_migrate_refuses_under_a_pending_old_via_fire() {
            let c = ta_at(TA, "alice.near", None, T0);
            at_time(TA, 0, H0, NOW, None);
            let via = crate::chain::OrderVia {
                q: a("zec.omft.near"),
                leg1_dex: a("v2.ref-finance.near"),
                leg2_dex: a("dclv2.ref-labs.near"),
                min_mid: U128(1),
                max_mid: U128(2),
            };
            crate::save_order(7, &order(true)); // a fire in flight (pending)
            store::save_via(7, &via);
            crate::set_order_index(&vec![(7, u64::MAX)]);
            let k = [b"ov".as_slice(), &7u64.to_le_bytes()].concat();
            let b = env::storage_read(&k).unwrap();
            env::storage_write(&k, &b[..b.len() - 32]);
            env::state_write(&c);
            at_time(TA, 0, H0 + 1, NOW, None);
            assert_eq!(outcome(|| drop(TradingAccount::migrate())), "E_IN_FLIGHT");
        }

        /// INDEP-2: the worst sweep (16 expired routes, 32 Held listed) was quadratic (save_route
        /// re-read every listed route per expired one): 65 TGas of host calls alone, more than the
        /// 25 TGas on_withdraw_all_report runs it in. Now one pass, one index / escrow write, one
        /// fee transfer: bounded at 10 TGas of host calls (measured 7), leaving room for the wasm.
        #[test]
        fn indep2_sweep_gas_worst_case_fits_the_smallest_budget() {
            let _c = ta_at(TA, "alice.near", None, T0);
            at_time(TA, 0, H0, NOW, None);
            for i in 0..32 {
                store::save_route(&format!("h{i}"), &Route { state: RouteState::Held, ..route(false) })
                    .unwrap();
            }
            for i in 0..16 {
                funded(&format!("x{i}"), 990);
            }
            at_time(TA, 0, H0 + 1, EXPIRY, None);
            let g0 = env::used_gas().as_gas();
            store::expire_routes(&a("fees.near"));
            let g = env::used_gas().as_gas() - g0;
            assert_eq!(expired_events(), 16);
            assert_eq!(fee_transfers(), vec![16 * FEE], "one transfer");
            assert_eq!(store::escrow_total(), 0);
            assert_eq!(store::route_index().len(), 32, "the 32 Held stay listed");
            assert!(store::route_index().iter().all(|id| id.starts_with('h')));
            assert!(g < 10 * 1_000_000_000_000, "sweep host gas {} TGas", g / 1_000_000_000_000);
        }

        /// INDEP-2: the paid-or-skipped rule still applies per route within one sweep (fees paid
        /// earlier in the sweep count out of liquid): with room for one fee, one is paid.
        #[test]
        fn indep2_sweep_pays_only_what_the_reserve_allows() {
            let _c = ta_at(TA, "alice.near", None, T0);
            at_time(TA, 0, H0, NOW, None);
            funded("a1", 990);
            funded("a2", 990);
            // liquid = RESERVE + 1.5 x FEE: a1 (the other's escrow still held) doesn't fit, a2
            // (nothing held any more) does
            let locked = 100_000u128 * env::storage_byte_cost().as_yoctonear();
            let bal = locked + crate::policy::RESERVE + FEE + FEE / 2;
            testing_env!(VMContextBuilder::new()
                .current_account_id(a(TA))
                .predecessor_account_id(a(TA))
                .signer_account_id(a(TA))
                .account_balance(NearToken::from_yoctonear(bal))
                .storage_usage(100_000)
                .block_height(H0 + 1)
                .block_timestamp(EXPIRY)
                .prepaid_gas(Gas::from_tgas(300))
                .build());
            store::expire_routes(&a("fees.near"));
            let paid: Vec<bool> = get_logs()
                .iter()
                .filter(|l| l.contains("route_expired"))
                .map(|l| l.contains("\"fee_paid\":true"))
                .collect();
            assert_eq!(paid, vec![false, true]);
            assert_eq!(fee_transfers(), vec![FEE]);
            assert!(crate::liquid_balance() >= crate::policy::RESERVE, "reserve kept");
            assert_eq!(store::escrow_total(), 0);
        }

        /// INDEP-5: migrate rewrites only LISTED routes; a Done / Refunded (or unlisted Held) route
        /// in the pre-9a0dd084 layout stayed undecodable, so get_route panicked and a new route
        /// couldn't reuse its id (check_route_id -> route_live -> E_STATE). Now an unlisted
        /// undecodable record reads as absent there; a listed one still fails closed.
        #[test]
        fn indep5_unlisted_old_route_reads_as_absent_listed_fails_closed() {
            let c = ta_at(TA, "alice.near", None, T0);
            at_time(TA, 0, H0, NOW, None);
            store::save_route("done", &Route { state: RouteState::Done, ..route(false) }).unwrap();
            let k = [b"rt".as_slice(), b"done"].concat();
            let b = env::storage_read(&k).unwrap();
            env::storage_write(&k, &b[..b.len() - 8]);
            env::state_write(&c);
            at_time(TA, 0, ROUTE_PENDING_TTL_BLOCKS, NOW, None);
            let c = TradingAccount::migrate();
            assert_eq!(
                outcome(|| {
                    let _ = store::route_live("done");
                }),
                "ok"
            );
            assert!(!store::route_live("done"));
            assert!(store::check_route_id("done", false).is_ok(), "its id may be used again");
            assert!(c.get_route("done".into()).is_none());
            // a listed undecodable record still fails closed
            store::save_route("live", &route(false)).unwrap();
            let k = [b"rt".as_slice(), b"live"].concat();
            let b = env::storage_read(&k).unwrap();
            env::storage_write(&k, &b[..b.len() - 8]);
            assert_eq!(
                outcome(|| {
                    let _ = store::route_live("live");
                }),
                "E_STATE"
            );
            assert_eq!(outcome(|| drop(c.get_route("live".into()))), "E_STATE");
        }
    }
}
