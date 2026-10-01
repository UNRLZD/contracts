//! Unit + property tests (native, mocked host: the real ed25519 / P-256 / ecrecover host logic).
use super::testkit::{iso, with_high_s, with_v27, BodySpec, Signer, FLAGS_UP_UV};
use super::*;
use proptest::prelude::*;

const TA: &str = "0123456789abcdef.trade.unrlzd.near";
const SALT: [u8; 4] = [0x25, 0x28, 0x12, 0xb3];
/// 2026-09-30T17:41:52Z, 5 min before the spike vectors' deadline
const NOW: u64 = 1_790_790_112_602_000_000;

fn signers() -> Vec<(Signer, Vec<Standard>)> {
    vec![
        (Signer::ed25519("ed"), vec![Standard::RawEd25519, Standard::Nep413, Standard::WebAuthn]),
        (Signer::secp256k1("k1"), vec![Standard::Erc191]),
        (Signer::p256("r1"), vec![Standard::WebAuthn]),
    ]
}

fn spec(s: &Signer, deadline_ns: u64, nonce: [u8; 32]) -> BodySpec {
    BodySpec {
        signer_id: s.owner_id(),
        verifying_contract: TA.into(),
        deadline_ns,
        nonce,
        items_json: r#"[{"op":"rotate_salt"}]"#.into(),
    }
}

fn nonce(dl: u64) -> [u8; 32] {
    versioned_nonce(SALT, dl, [7; 15])
}

type Ops = Vec<near_sdk::serde_json::Value>;

// ---------------------------------------------------------------- golden vectors (mainnet-proven)

#[derive(near_sdk::serde::Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct Vectors {
    ta: String,
    salt: String,
    vectors: Vec<Vector>,
}
#[derive(near_sdk::serde::Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct Vector {
    signer: String,
    hash: String,
    mp: MultiPayload,
}

/// spikes/intents-owner/out/vectors.json: signed by @noble (independent of this crate) and
/// accepted by mainnet intents.near `simulate_intents` (spec §12.1).
#[test]
fn golden_vectors_verify_and_bind() {
    let v: Vectors =
        near_sdk::serde_json::from_str(include_str!("../fixtures/intents_vectors.json")).unwrap();
    assert_eq!(v.salt, hex(&SALT));
    assert_eq!(v.vectors.len(), 5);
    let mut seen = vec![];
    for x in &v.vectors {
        let key = verify(&x.mp).unwrap_or_else(|e| panic!("{}: {e}", x.signer));
        assert_eq!(key.implicit_id(), x.signer);
        let b: Body<Ops> = parse_ops(&x.mp).unwrap();
        assert_eq!((b.signer_id.as_str(), b.verifying_contract.as_str()), (x.signer.as_str(), v.ta.as_str()));
        assert_eq!(b.items, vec![near_sdk::serde_json::json!({"op": "rotate_salt"})]);
        assert_eq!(iso_ns("2026-09-30T17:46:52.602Z"), Some(b.deadline_ns));
        assert_eq!(check_nonce(&b.nonce, &SALT, b.deadline_ns, NOW), Ok(b.deadline_ns));
        match &x.mp {
            MultiPayload::Erc191 { payload, .. } => assert_eq!(hex(&erc191_hash(payload)), x.hash),
            MultiPayload::Nep413 { payload, .. } => {
                assert_eq!(hex(&nep413_hash(payload, &b.nonce)), x.hash);
                assert_eq!(nep413_hash(payload, &b.nonce), testkit::nep413_native_hash(payload, &b.nonce));
            }
            _ => {}
        }
        seen.push((x.mp.standard(), key.kind()));
    }
    for want in [
        (Standard::RawEd25519, OwnerKind::Ed25519),
        (Standard::Erc191, OwnerKind::Secp256k1),
        (Standard::Nep413, OwnerKind::Ed25519),
        (Standard::WebAuthn, OwnerKind::P256),
        (Standard::WebAuthn, OwnerKind::Ed25519),
    ] {
        assert!(seen.contains(&want), "{want:?}");
    }
}

#[test]
fn golden_vector_tamper_fails() {
    let v: Vectors =
        near_sdk::serde_json::from_str(include_str!("../fixtures/intents_vectors.json")).unwrap();
    for x in v.vectors {
        let mut mp = x.mp.clone();
        match &mut mp {
            MultiPayload::Nep413 { payload, .. } => {
                payload.message = payload.message.replace("rotate", "rotatE")
            }
            MultiPayload::Erc191 { payload, .. }
            | MultiPayload::RawEd25519 { payload, .. }
            | MultiPayload::WebAuthn { payload, .. } => *payload = payload.replace("rotate", "rotatE"),
        }
        let want = if matches!(mp, MultiPayload::WebAuthn { .. }) { E_WEBAUTHN } else { E_SIG };
        match (verify(&mp), &mp) {
            // erc191 recovers SOME key from any hash: it just is not the signer's
            (Ok(k), MultiPayload::Erc191 { .. }) => assert_ne!(k.implicit_id(), x.signer),
            (r, _) => assert_eq!(r, Err(want), "{}", x.signer),
        }
    }
}

// ---------------------------------------------------------------- every arm, testkit round trip

#[test]
fn every_arm_round_trips() {
    let dl = NOW + 60_000_000_000;
    for (s, stds) in signers() {
        for std in stds {
            let mp = s.sign_ops(std, &spec(&s, dl, nonce(dl)));
            assert_eq!(mp.standard(), std);
            assert_eq!(verify(&mp), Ok(s.public_key()), "{std:?}");
            assert_eq!(s.public_key().implicit_id(), s.owner_id());
            let b: Body<Ops> = parse_ops(&mp).unwrap();
            assert_eq!(b.signer_id, s.owner_id());
            assert_eq!(b.verifying_contract, TA);
            assert_eq!(b.deadline_ns, dl / 1_000_000 * 1_000_000);
            assert_eq!(b.nonce, nonce(dl));
            // serde round trip of the envelope (what the relayer forwards)
            let j = near_sdk::serde_json::to_string(&mp).unwrap();
            assert_eq!(near_sdk::serde_json::from_str::<MultiPayload>(&j).unwrap(), mp);
        }
    }
}

#[test]
fn intents_body_for_the_factory() {
    let s = Signer::p256("creator");
    let mut b = spec(&s, NOW + 1, nonce(NOW + 1));
    b.verifying_contract = "intents.near".into();
    b.items_json = r#"[{"intent":"auth_call","contract_id":"trade.unrlzd.near","msg":"{}","attached_deposit":"1","min_gas":"200000000000000"}]"#.into();
    let mp = s.sign_intents(Standard::WebAuthn, &b);
    assert_eq!(verify(&mp), Ok(s.public_key()));
    let body: Body<Ops> = parse_intents(&mp).unwrap();
    assert_eq!(body.verifying_contract, "intents.near");
    assert_eq!(body.items.len(), 1);
    // an intents body is not an ops body and vice versa (spec §10: schemas differ)
    assert_eq!(parse_ops::<Ops>(&mp).err(), Some(E_PAYLOAD));
    let ta = s.sign_ops(Standard::WebAuthn, &spec(&s, NOW + 1, nonce(NOW + 1)));
    assert_eq!(parse_intents::<Ops>(&ta).err(), Some(E_PAYLOAD));
    let e = Signer::ed25519("n");
    let mut b = spec(&e, NOW + 1, nonce(NOW + 1));
    b.verifying_contract = "intents.near".into();
    let n = e.sign_intents(Standard::Nep413, &b);
    assert_eq!(parse_intents::<Ops>(&n).map(|b| b.verifying_contract), Ok("intents.near".into()));
}

// ---------------------------------------------------------------- negative signatures

#[test]
fn erc191_v27_and_high_s_refused() {
    let s = Signer::secp256k1("k1");
    let mp = s.erc191(&spec(&s, NOW, nonce(NOW)).text("ops"));
    assert!(verify(&mp).is_ok());
    // v = 27/28: our own E_SIG before the host (which would abort the call)
    assert_eq!(verify(&with_v27(&mp)), Err(E_SIG));
    // the high-s twin is a valid ECDSA signature; the host malleability flag refuses it
    assert_eq!(verify(&with_high_s(&mp)), Err(E_SIG));
    let MultiPayload::Erc191 { signature, .. } = &mp else { unreachable!() };
    let mut b = near_sdk::bs58::decode(&signature[10..]).into_vec().unwrap();
    for v in [2u8, 3, 4, 255] {
        b[64] = v;
        let m = MultiPayload::Erc191 {
            payload: mp.text().into(),
            signature: format!("secp256k1:{}", near_sdk::bs58::encode(&b).into_string()),
        };
        assert_eq!(verify(&m), Err(E_SIG), "v={v}");
    }
}

#[test]
fn p256_high_s_refused_low_s_accepted() {
    let s = Signer::p256("r1");
    let mp = s.webauthn(&spec(&s, NOW, nonce(NOW)).text("ops"));
    assert_eq!(verify(&mp), Ok(s.public_key()));
    assert_eq!(verify(&with_high_s(&mp)), Err(E_HIGH_S));
    // and the twin of the twin (low again) passes
    assert_eq!(verify(&with_high_s(&with_high_s(&mp))), Ok(s.public_key()));
}

#[test]
fn webauthn_flags_type_and_challenge() {
    let text = spec(&Signer::p256("r1"), NOW, nonce(NOW)).text("ops");
    for s in [Signer::p256("r1"), Signer::ed25519("ed")] {
        assert!(verify(&s.webauthn_with(&text, FLAGS_UP_UV, "webauthn.get")).is_ok());
        // UV missing (UP only), UP missing, BS without BE: refused (intents ignores UV)
        for flags in [0x01, 0x04, 0x00, 0x15] {
            assert_eq!(verify(&s.webauthn_with(&text, flags, "webauthn.get")), Err(E_WEBAUTHN), "{flags:#x}");
        }
        // BE + BS (a synced passkey) and BE alone: fine
        for flags in [0x1d, 0x0d, 0x45] {
            assert!(verify(&s.webauthn_with(&text, flags, "webauthn.get")).is_ok(), "{flags:#x}");
        }
        assert_eq!(verify(&s.webauthn_with(&text, FLAGS_UP_UV, "webauthn.create")), Err(E_WEBAUTHN));
        // challenge bound to the payload: swap the payload
        let mut mp = s.webauthn(&text);
        if let MultiPayload::WebAuthn { payload, .. } = &mut mp {
            payload.push(' ');
        }
        assert_eq!(verify(&mp), Err(E_WEBAUTHN));
        // short authenticator data
        let mut mp = s.webauthn(&text);
        if let MultiPayload::WebAuthn { authenticator_data, .. } = &mut mp {
            *authenticator_data = URL_SAFE_NO_PAD.encode([5u8; 36]);
        }
        assert_eq!(verify(&mp), Err(E_WEBAUTHN));
        // padded base64 is not base64url-nopad
        let mut mp = s.webauthn(&text);
        if let MultiPayload::WebAuthn { authenticator_data, .. } = &mut mp {
            authenticator_data.push('=');
        }
        assert_eq!(verify(&mp), Err(E_WEBAUTHN));
    }
}

#[test]
fn wrong_key_and_encodings_refused() {
    let text = spec(&Signer::ed25519("ed"), NOW, nonce(NOW)).text("ops");
    let a = Signer::ed25519("ed");
    let b = Signer::ed25519("other");
    let mut mp = a.raw_ed25519(&text);
    if let MultiPayload::RawEd25519 { public_key, .. } = &mut mp {
        *public_key = b.public_key().to_string();
    }
    assert_eq!(verify(&mp), Err(E_SIG));
    for bad in ["ed25519:", "ed25519:1111", "secp256k1:abc", "p256:zz", "", "ED25519:x"] {
        let mut m = a.raw_ed25519(&text);
        if let MultiPayload::RawEd25519 { public_key, .. } = &mut m {
            *public_key = bad.into();
        }
        assert_eq!(verify(&m), Err(E_SIG), "{bad}");
        assert_eq!(PublicKey::parse(bad), Err(E_KEY_FORMAT));
    }
    // a P-256 signature string on an ed25519 key, and the reverse
    let r = Signer::p256("r1").webauthn(&text);
    let e = a.webauthn(&text);
    if let (MultiPayload::WebAuthn { signature: rs, .. }, MultiPayload::WebAuthn { signature: es, .. }) =
        (&r, &e)
    {
        let mut x = r.clone();
        if let MultiPayload::WebAuthn { signature, .. } = &mut x {
            *signature = es.clone();
        }
        assert_eq!(verify(&x), Err(E_SIG));
        let mut y = e.clone();
        if let MultiPayload::WebAuthn { signature, .. } = &mut y {
            *signature = rs.clone();
        }
        assert_eq!(verify(&y), Err(E_SIG));
    }
}

// ---------------------------------------------------------------- body shape

fn raw(text: &str) -> MultiPayload {
    Signer::ed25519("ed").raw_ed25519(text)
}

#[test]
fn body_shape_rules() {
    let s = Signer::ed25519("ed");
    let good = spec(&s, NOW, nonce(NOW)).text("ops");
    assert!(parse_ops::<Ops>(&raw(&good)).is_ok());
    // key order is free (the TA parses as-is, never re-serialises)
    let n = STANDARD.encode(nonce(NOW));
    let reordered = format!(
        r#"{{"ops":[{{"op":"rotate_salt"}}],"nonce":"{n}","deadline":"{}","verifying_contract":"{TA}","signer_id":"{}"}}"#,
        iso(NOW),
        s.owner_id()
    );
    assert!(parse_ops::<Ops>(&raw(&reordered)).is_ok());
    let cases: Vec<(String, &str)> = vec![
        (good.replace(r#""ops""#, r#""ops":[],"extra":1,"x""#), E_PAYLOAD), // unknown key
        (good.replace(r#""signer_id":"#, r#""signer_id":"a","signer_id":"#), E_PAYLOAD), // duplicate
        (good.replacen('{', "[", 1), E_PAYLOAD),
        (good.replace(&n, "AAAA"), E_PAYLOAD), // nonce 3 bytes
        (good.replace(&n, &STANDARD.encode([1u8; 33])), E_PAYLOAD), // 33 bytes
        (good.replace(&n, &URL_SAFE_NO_PAD.encode(nonce(NOW))), E_PAYLOAD), // base64url
        (good.replace(&iso(NOW), "2026-09-30T17:41:52+00:00"), E_DEADLINE),
        (good.replace(&iso(NOW), "2026-02-30T00:00:00Z"), E_DEADLINE),
        (good.replace(&iso(NOW), "2026-09-30 17:41:52Z"), E_DEADLINE),
        (good.replace(&iso(NOW), "2026-09-30T17:41:52.1234567890Z"), E_DEADLINE),
        (good.replace(r#""ops""#, r#""op""#), E_PAYLOAD),
    ];
    for (t, want) in cases {
        assert_eq!(parse_ops::<Ops>(&raw(&t)).err(), Some(want), "{t}");
    }
    let big = good.replace(r#"[{"op":"rotate_salt"}]"#, &format!("[\"{}\"]", "x".repeat(MAX_PAYLOAD_LEN)));
    assert_eq!(parse_ops::<Ops>(&raw(&big)).err(), Some(E_PAYLOAD_SIZE));
    // nep413: callbackUrl refused, recipient = verifying_contract
    let mut mp = s.nep413(&spec(&s, NOW, nonce(NOW)).nep413_message("ops"), nonce(NOW), TA);
    assert!(parse_ops::<Ops>(&mp).is_ok());
    if let MultiPayload::Nep413 { payload, .. } = &mut mp {
        payload.callback_url = Some("https://x".into());
    }
    assert_eq!(parse_ops::<Ops>(&mp).err(), Some(E_PAYLOAD));
    // a full body inside a nep413 message is refused (verifying_contract/nonce are not message keys)
    let nm = s.nep413(&good, nonce(NOW), TA);
    assert_eq!(parse_ops::<Ops>(&nm).err(), Some(E_PAYLOAD));
}

#[test]
fn envelope_deny_unknown_fields() {
    let s = Signer::ed25519("ed");
    let mp = s.raw_ed25519(&spec(&s, NOW, nonce(NOW)).text("ops"));
    let mut v = near_sdk::serde_json::to_value(&mp).unwrap();
    v["extra"] = 1.into();
    assert!(near_sdk::serde_json::from_value::<MultiPayload>(v.clone()).is_err());
    v.as_object_mut().unwrap().remove("extra");
    v["standard"] = "tip191".into();
    assert!(near_sdk::serde_json::from_value::<MultiPayload>(v).is_err());
    let n = s.nep413("{}", nonce(NOW), TA);
    let mut v = near_sdk::serde_json::to_value(&n).unwrap();
    v["payload"]["callback_url"] = "x".into(); // snake_case is unknown (camelCase only)
    assert!(near_sdk::serde_json::from_value::<MultiPayload>(v).is_err());
}

// ---------------------------------------------------------------- deadline and nonce

#[test]
fn deadline_window() {
    let ttl = OWNER_PAYLOAD_TTL_NS;
    assert_eq!(check_deadline(NOW, NOW, ttl), Ok(()));
    assert_eq!(check_deadline(NOW + ttl, NOW, ttl), Ok(()));
    assert_eq!(check_deadline(NOW - 1, NOW, ttl), Err(E_DEADLINE));
    assert_eq!(check_deadline(NOW + ttl + 1, NOW, ttl), Err(E_DEADLINE));
}

#[test]
fn nonce_rules() {
    let dl = NOW + 60_000_000_000;
    let n = versioned_nonce(SALT, dl, [9; 15]);
    assert_eq!(check_nonce(&n, &SALT, dl, NOW), Ok(dl));
    assert_eq!(check_nonce(&n, &[0, 0, 0, 0], dl, NOW), Err(E_NONCE_SALT));
    let mut m = n;
    m[0] ^= 1;
    assert_eq!(check_nonce(&m, &SALT, dl, NOW), Err(E_NONCE_SALT)); // magic
    let mut m = n;
    m[4] = 1;
    assert_eq!(check_nonce(&m, &SALT, dl, NOW), Err(E_NONCE_SALT)); // version
                                                                    // nonce deadline < payload deadline, > now + TTL, negative
    assert_eq!(check_nonce(&n, &SALT, dl + 1, NOW), Err(E_NONCE_DEADLINE));
    let far = versioned_nonce(SALT, NOW + OWNER_PAYLOAD_TTL_NS + 1, [9; 15]);
    assert_eq!(check_nonce(&far, &SALT, dl, NOW), Err(E_NONCE_DEADLINE));
    let mut neg = n;
    neg[9..17].copy_from_slice(&(-1i64).to_le_bytes());
    assert_eq!(check_nonce(&neg, &SALT, 0, NOW), Err(E_NONCE_DEADLINE));
    // a legacy (unversioned, random) nonce is refused
    assert_eq!(check_nonce(&[7; 32], &SALT, dl, NOW), Err(E_NONCE_SALT));
}

#[test]
fn nonce_store_prune_bound_and_no_reuse() {
    let mut st = NonceStore::default();
    for i in 0..MAX_OWNER_NONCES as u64 {
        st.insert(versioned_nonce(SALT, NOW + 10 + i, [i as u8; 15]), NOW + 10 + i, NOW).unwrap();
    }
    let first = versioned_nonce(SALT, NOW + 10, [0; 15]);
    assert_eq!(st.insert(first, NOW + 10, NOW), Err(E_NONCE_USED));
    assert_eq!(st.insert([1; 32], NOW + 99, NOW), Err(E_NONCES_FULL));
    assert_eq!(st.live(NOW), MAX_OWNER_NONCES);
    // time passes: the first entry expires and is pruned; its nonce can no longer pass the
    // deadline checks, so pruning never makes it reusable
    let later = NOW + 11;
    assert_eq!(st.check(&[1; 32], later), Ok(()));
    st.insert([1; 32], later + 5, later).unwrap();
    assert!(!st.contains(&first));
    assert_eq!(check_nonce(&first, &SALT, NOW + 10, later), Ok(NOW + 10));
    assert_eq!(check_deadline(NOW + 10, later, OWNER_PAYLOAD_TTL_NS), Err(E_DEADLINE));
    assert_eq!(st.0.len(), MAX_OWNER_NONCES);
}

// ---------------------------------------------------------------- ids, kinds, keys

#[test]
fn owner_kind_id_rule() {
    assert_eq!(OwnerKind::from_id(&"a".repeat(64)), OwnerKind::Ed25519);
    assert_eq!(OwnerKind::from_id(&format!("0x{}", "0".repeat(40))), OwnerKind::Secp256k1);
    for named in [
        "alice.near",
        &"A".repeat(64),
        &"a".repeat(63),
        &format!("0x{}", "A".repeat(40)),
        "0x12",
        &format!("0X{}", "0".repeat(40)),
    ] {
        assert_eq!(OwnerKind::from_id(named), OwnerKind::Named, "{named}");
    }
    assert!(!OwnerKind::Named.is_signer() && OwnerKind::P256.is_signer());
    assert_eq!(home_for(Standard::RawEd25519), Home::Solana);
    for s in [Standard::Nep413, Standard::WebAuthn, Standard::Erc191] {
        assert_eq!(home_for(s), Home::Near);
    }
    // json shape the factory sends
    let j =
        near_sdk::serde_json::to_string(&OwnerAuthInit { kind: OwnerKind::P256, home: Home::Near }).unwrap();
    assert_eq!(j, r#"{"kind":"P256","home":"Near"}"#);
}

#[test]
fn key_strings_round_trip_and_ids_match_host() {
    for (s, _) in signers() {
        let k = s.public_key();
        assert_eq!(PublicKey::parse(&k.to_string()), Ok(k.clone()));
        // host keccak (implicit_id) == native keccak (testkit)
        assert_eq!(k.implicit_id(), s.owner_id());
        assert!(OwnerKind::from_id(&s.owner_id()).is_signer());
        let j = near_sdk::serde_json::to_string(&k).unwrap();
        assert_eq!(near_sdk::serde_json::from_str::<PublicKey>(&j).unwrap(), k);
    }
    // the p256 id differs from the k1 id of the same 64 bytes (domain "p256")
    let b = [3u8; 64];
    assert_ne!(PublicKey::P256(b).implicit_id(), PublicKey::Secp256k1(b).implicit_id());
    assert_eq!(unhex32(&"ab".repeat(32)), Some([0xab; 32]));
    assert_eq!(unhex32(&"AB".repeat(32)), None);
}

#[test]
fn small_order_ed25519_matches_dalek() {
    use curve25519_dalek::constants::EIGHT_TORSION;
    for p in EIGHT_TORSION {
        let mut e = p.compress().to_bytes();
        assert!(is_small_order_ed25519(&e), "{e:?}");
        e[31] ^= 0x80; // other sign bit
        assert!(is_small_order_ed25519(&e));
    }
    // non-canonical encodings of y = 0, 1 (y + p)
    let mut p0 = [0xff; 32];
    p0[31] = 0x7f;
    p0[0] = 0xed;
    assert!(is_small_order_ed25519(&p0));
    p0[0] = 0xee;
    assert!(is_small_order_ed25519(&p0));
    for (s, _) in signers() {
        if let PublicKey::Ed25519(k) = s.public_key() {
            assert!(!is_small_order_ed25519(&k));
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Random 32-byte encodings: ours == dalek's is_small_order for every decodable point.
    #[test]
    fn prop_small_order_agrees_with_dalek(b in any::<[u8; 32]>()) {
        if let Some(p) = curve25519_dalek::edwards::CompressedEdwardsY(b).decompress() {
            prop_assert_eq!(is_small_order_ed25519(&b), p.is_small_order());
        }
    }

    /// iso_ns(testkit::iso(t)) == t (ms precision) for every ms in 1970..2500.
    #[test]
    fn prop_iso_round_trip(ms in 0u64..16_725_225_600_000) {
        let t = ms * 1_000_000;
        prop_assert_eq!(iso_ns(&iso(t)), Some(t));
    }

    /// Arbitrary strings never panic the parsers; anything accepted re-validates.
    #[test]
    fn prop_iso_never_panics(s in "\\PC{0,40}") {
        let _ = iso_ns(&s);
    }

    /// Flipping any byte of any signed text breaks the signature (or the challenge).
    #[test]
    fn prop_tamper_any_byte(i in 0usize..200, arm in 0usize..5) {
        // Fresh mocked chain per case: gas is metered per thread, so 20k cases of real signature
        // checks on one mock hit GasLimitExceeded (~7.2k cases) in the harness, not the code.
        near_sdk::testing_env!(near_sdk::test_utils::VMContextBuilder::new().build());
        let (s, std) = [
            (Signer::ed25519("ed"), Standard::RawEd25519),
            (Signer::ed25519("ed"), Standard::Nep413),
            (Signer::ed25519("ed"), Standard::WebAuthn),
            (Signer::secp256k1("k1"), Standard::Erc191),
            (Signer::p256("r1"), Standard::WebAuthn),
        ][arm].clone();
        let mp = s.sign_ops(std, &spec(&s, NOW, nonce(NOW)));
        let mut t = mp.clone();
        let text = match &mut t {
            MultiPayload::Nep413 { payload, .. } => &mut payload.message,
            MultiPayload::Erc191 { payload, .. } | MultiPayload::RawEd25519 { payload, .. } | MultiPayload::WebAuthn { payload, .. } => payload,
        };
        let i = i % text.len();
        let c = text.as_bytes()[i];
        let r = if c.is_ascii_alphanumeric() { if c == b'a' { 'b' } else { 'a' } } else { return Ok(()) };
        text.replace_range(i..i + 1, &r.to_string());
        match verify(&t) {
            Ok(k) => prop_assert_ne!(k, s.public_key()),
            Err(e) => prop_assert!(e == E_SIG || e == E_WEBAUTHN),
        }
    }

    /// Random JSON-ish noise as a payload never panics parse_ops.
    #[test]
    fn prop_parse_never_panics(t in "\\PC{0,300}") {
        let _ = parse_ops::<Ops>(&raw(&t));
    }
}

/// V16-14 (internal review): the PoC flipped. A P-256 key with the real X and a different Y of
/// the same parity is off the curve: refused by `verify` (E_SIG) and by `PublicKey::parse`.
/// RED before: `verify` returned the forged key.
#[test]
fn v16_14_p256_off_curve_key_refused() {
    let s = Signer::p256("r1");
    let mp = s.webauthn(&spec(&s, NOW, nonce(NOW)).text("ops"));
    let MultiPayload::WebAuthn { payload, public_key, signature, client_data_json, authenticator_data } = mp
    else {
        panic!()
    };
    let PublicKey::P256(mut k) = PublicKey::parse(&public_key).unwrap() else { panic!() };
    k[40] ^= 0x55;
    let forged = PublicKey::P256(k);
    let mp2 = MultiPayload::WebAuthn {
        payload,
        public_key: forged.to_string(),
        signature,
        client_data_json,
        authenticator_data,
    };
    assert_eq!(verify(&mp2), Err(E_SIG));
    assert_eq!(PublicKey::parse(&forged.to_string()), Err(E_KEY_FORMAT));
    assert!(!p256_on_curve(&[0u8; 64]));
    assert!(!p256_on_curve(&[0xff; 64]));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Every real P-256 public key (and its negation, x ‖ p − y) is on the curve; a changed
    /// coordinate is not.
    #[test]
    fn prop_p256_on_curve_matches_real_keys(seed in any::<[u8; 32]>(), flip in 0usize..64, bit in 0u8..8) {
        let Ok(sk) = p256::ecdsa::SigningKey::from_slice(&seed) else { return Ok(()) };
        let pt = sk.verifying_key().to_encoded_point(false);
        let xy: [u8; 64] = pt.as_bytes()[1..].try_into().unwrap();
        prop_assert!(p256_on_curve(&xy));
        let mut t = xy;
        t[flip] ^= 1 << bit;
        prop_assert!(!p256_on_curve(&t));
    }
}
