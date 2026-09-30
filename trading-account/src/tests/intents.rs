//! v1.4 NEAR Intents: 1Click signature vectors (recorded LIVE quotes, spikes/intents/out),
//! quote checks, ISO time, parser properties, and the contract methods on a mocked chain.
use super::*;
use crate::intents::{self as ix, Dest, Expect, OneClickConfig};
use ed25519_dalek::{Signer, SigningKey};
use near_sdk::serde_json::{self, Map, Value};

#[derive(near_sdk::serde::Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct Vector {
    name: String,
    signed_quote: String,
    signature: String,
    message: String,
}

fn vectors() -> Vec<Vector> {
    serde_json::from_str(include_str!("../../tests/fixtures/oneclick_quotes.json")).unwrap()
}

fn manager() -> Vec<String> {
    vec![ix::ONECLICK_MANAGER_KEY.to_string()]
}

/// SDK stableStringify: keys sorted recursively, compact.
fn stable(v: &Value) -> String {
    match v {
        Value::Object(m) => {
            let mut ks: Vec<&String> = m.keys().collect();
            ks.sort();
            let body: Vec<String> = ks
                .iter()
                .map(|k| format!("{}:{}", serde_json::to_string(k).unwrap(), stable(&m[*k])))
                .collect();
            format!("{{{}}}", body.join(","))
        }
        Value::Array(a) => format!("[{}]", a.iter().map(stable).collect::<Vec<_>>().join(",")),
        x => serde_json::to_string(x).unwrap(),
    }
}

fn obj(s: &str) -> Map<String, Value> {
    serde_json::from_str::<Value>(s).unwrap().as_object().unwrap().clone()
}

/// Test signing key (stands in for 1Click in the contract-flow tests).
fn test_sk() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn pk_str(sk: &SigningKey) -> String {
    format!("ed25519:{}", near_sdk::bs58::encode(sk.verifying_key().to_bytes()).into_string())
}

fn sign(sk: &SigningKey, signed_quote: &str) -> String {
    let msg = ix::signed_message(signed_quote.as_bytes());
    format!("ed25519:{}", near_sdk::bs58::encode(sk.sign(msg.as_bytes()).to_bytes()).into_string())
}

// ---------------- ISO time ----------------

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

fn fmt_iso(ns: u64) -> String {
    let s = ns / NS_PER_SEC;
    let (y, m, d) = civil_from_days((s / 86_400) as i64);
    let r = s % 86_400;
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
        r / 3600,
        r / 60 % 60,
        r % 60,
        ns % NS_PER_SEC / 1_000_000
    )
}

#[test]
fn iso_known_values() {
    let ms = |x: u64| Some(x * 1_000_000);
    assert_eq!(ix::parse_iso_ns("2026-10-01T11:29:50.000Z"), ms(1_790_854_190_000));
    assert_eq!(ix::parse_iso_ns("2026-09-28T10:29:50.810Z"), ms(1_790_591_390_810));
    assert_eq!(ix::parse_iso_ns("2000-02-29T00:00:00Z"), ms(951_782_400_000));
    assert_eq!(ix::parse_iso_ns("2100-03-01T23:59:59.999999999Z"), Some(4_107_628_799_999_999_999));
    assert_eq!(ix::parse_iso_ns("1970-01-01T00:00:00Z"), Some(0));
    for bad in [
        "",
        "2026-10-01T11:29:50",
        "2026-10-01 11:29:50Z",
        "2026-13-01T11:29:50Z",
        "2026-02-29T00:00:00Z",
        "2100-02-29T00:00:00Z",
        "2026-10-00T11:29:50Z",
        "2026-10-01T24:00:00Z",
        "2026-10-01T11:60:00Z",
        "2026-10-01T11:29:60Z",
        "2026-10-01T11:29:50.Z",
        "2026-10-01T11:29:50.1234567890Z",
        "2026-10-01T11:29:50+00:00",
        "1969-12-31T23:59:59Z",
        "+026-10-01T11:29:50Z",
        "2026-1a-01T11:29:50Z",
        "2026-10-01T11:29:50.00aZ",
    ] {
        assert_eq!(ix::parse_iso_ns(bad), None, "{bad}");
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]
    #[test]
    fn iso_roundtrip(ms in 0u64..16_725_225_600_000) { // 1970 ..= 2500
        let ns = ms * 1_000_000;
        prop_assert_eq!(ix::parse_iso_ns(&fmt_iso(ns)), Some(ns));
    }

    #[test]
    fn iso_never_panics(s in ".{0,40}") {
        let _ = ix::parse_iso_ns(&s);
    }

    #[test]
    fn iso_is_monotonic(a_ in 0u64..16_725_225_600_000, b in 0u64..16_725_225_600_000) {
        let (pa, pb) = (ix::parse_iso_ns(&fmt_iso(a_ * 1_000_000)), ix::parse_iso_ns(&fmt_iso(b * 1_000_000)));
        prop_assert_eq!(a_.cmp(&b), pa.cmp(&pb));
    }
}

// ---------------- signature vectors (live 1Click quotes) ----------------

#[test]
fn manager_key_format() {
    let pk = ix::parse_pk(ix::ONECLICK_MANAGER_KEY).expect("ed25519:<bs58> of 32 bytes");
    let sdk: near_sdk::PublicKey = ix::ONECLICK_MANAGER_KEY.parse().unwrap();
    assert_eq!(sdk.as_bytes()[0], 0, "ed25519 curve");
    assert_eq!(&sdk.as_bytes()[1..], &pk[..]);
    ctx("tt.near", 0, NEAR, T0);
    assert_eq!(
        ix::check_config(&OneClickConfig {
            keys: manager(),
            max_slippage_bps: 300,
            intents: a("intents.near"),
            max_loss_bps: 100
        }),
        Ok(())
    );
    for bad in [
        "reYaWhvwu8Jzo3WUM3zhn6VrhuMEF4eADL17qtRVifc", // no prefix
        "secp256k1:reYaWhvwu8Jzo3WUM3zhn6VrhuMEF4eADL17qtRVifc", // wrong curve
        "ed25519:reYaWhvwu8Jzo3WUM3zhn6VrhuMEF4eADL17qtRVif", // 31 bytes
        "ed25519:reYaWhvwu8Jzo3WUM3zhn6VrhuMEF4eADL17qtRVifc0", // bad bs58 char
        "ed25519:",
    ] {
        assert_eq!(ix::parse_pk(bad), None, "{bad}");
    }
}

#[test]
fn live_vectors_verify_on_chain_path() {
    ctx("tt.near", 0, NEAR, T0);
    let v = vectors();
    assert!(v.len() >= 10, "all recorded live quotes whose signature node verified");
    for x in &v {
        assert_eq!(ix::signed_message(x.signed_quote.as_bytes()), x.message, "{}", x.name);
        assert_eq!(ix::verify_quote_sig(&x.signed_quote, &x.signature, &manager()), Ok(()), "{}", x.name);
        // the payload is exactly the SDK's stable form (sorted keys, compact)
        assert_eq!(stable(&serde_json::from_str(&x.signed_quote).unwrap()), x.signed_quote, "{}", x.name);
        // every live payload parses (dry and non-dry, memo chains, all deposit types)
        assert!(ix::parse_quote(&x.signed_quote).is_ok(), "{}", x.name);
        // rotation: the manager key may be any of up to 3
        let keys = vec![pk_str(&test_sk()), ix::ONECLICK_MANAGER_KEY.to_string()];
        assert_eq!(ix::verify_quote_sig(&x.signed_quote, &x.signature, &keys), Ok(()));
    }
}

/// Tamper every field of every live quote (re-serialized in stable form, as an attacker
/// would): the manager signature never verifies.
#[test]
fn live_vectors_tampered_each_field_rejected() {
    ctx("tt.near", 0, NEAR, T0);
    let mut n = 0;
    for x in vectors() {
        let m = obj(&x.signed_quote);
        for k in m.keys() {
            let mut t = m.clone();
            t[k] = match &m[k] {
                Value::String(s) => Value::String(format!("{s}0")),
                Value::Number(v) => Value::from(v.as_u64().unwrap_or(0) + 1),
                Value::Bool(b) => Value::Bool(!b),
                x => panic!("{x:?}"),
            };
            let s = stable(&Value::Object(t));
            assert_eq!(
                ix::verify_quote_sig(&s, &x.signature, &manager()),
                Err("E_QUOTE_SIG"),
                "{} {k}",
                x.name
            );
            n += 1;
        }
        // removed field / added field
        let mut t = m.clone();
        t.remove("recipient");
        assert_eq!(
            ix::verify_quote_sig(&stable(&Value::Object(t)), &x.signature, &manager()),
            Err("E_QUOTE_SIG")
        );
        let mut t = m.clone();
        t.insert("customRecipientMsg".into(), Value::from("x"));
        assert_eq!(
            ix::verify_quote_sig(&stable(&Value::Object(t)), &x.signature, &manager()),
            Err("E_QUOTE_SIG")
        );
        // same content, different bytes (whitespace): not the signed bytes
        let spaced = x.signed_quote.replacen(':', ": ", 1);
        assert_eq!(ix::verify_quote_sig(&spaced, &x.signature, &manager()), Err("E_QUOTE_SIG"));
    }
    assert!(n > 250, "{n}");
}

#[test]
fn live_vector_every_byte_flip_rejected() {
    ctx("tt.near", 0, NEAR, T0);
    let x = vectors().into_iter().find(|x| x.name == "quote-live-wd-intents").unwrap();
    let b = x.signed_quote.as_bytes();
    for i in 0..b.len() {
        let mut t = b.to_vec();
        t[i] ^= 0x01;
        if let Ok(s) = String::from_utf8(t) {
            assert_eq!(ix::verify_quote_sig(&s, &x.signature, &manager()), Err("E_QUOTE_SIG"), "byte {i}");
        }
    }
}

#[test]
fn wrong_key_and_bad_signatures_rejected() {
    ctx("tt.near", 0, NEAR, T0);
    let v = vectors();
    let x = &v[0];
    // wrong key
    assert_eq!(
        ix::verify_quote_sig(&x.signed_quote, &x.signature, &[pk_str(&test_sk())]),
        Err("E_QUOTE_SIG")
    );
    assert_eq!(ix::verify_quote_sig(&x.signed_quote, &x.signature, &[]), Err("E_QUOTE_SIG"));
    // another quote's genuine signature
    assert_eq!(ix::verify_quote_sig(&x.signed_quote, &v[1].signature, &manager()), Err("E_QUOTE_SIG"));
    // signature over the raw JSON instead of bs58(sha256(json))
    let raw = format!(
        "ed25519:{}",
        near_sdk::bs58::encode(test_sk().sign(x.signed_quote.as_bytes()).to_bytes()).into_string()
    );
    assert_eq!(ix::verify_quote_sig(&x.signed_quote, &raw, &[pk_str(&test_sk())]), Err("E_QUOTE_SIG"));
    // malformed signature strings
    let bare = x.signature.trim_start_matches("ed25519:");
    for s in
        [bare.to_string(), "ed25519:".into(), format!("ed25519:{}", &bare[1..]), format!("ed25519:{bare}1")]
    {
        assert_eq!(ix::verify_quote_sig(&x.signed_quote, &s, &manager()), Err("E_QUOTE_SIG"), "{s}");
    }
    // our test key signing the same bytes verifies under our key only
    let ours = sign(&test_sk(), &x.signed_quote);
    assert_eq!(ix::verify_quote_sig(&x.signed_quote, &ours, &[pk_str(&test_sk())]), Ok(()));
    assert_eq!(ix::verify_quote_sig(&x.signed_quote, &ours, &manager()), Err("E_QUOTE_SIG"));
}

// ---------------- quote checks ----------------

const SOL: &str = "nep141:sol-5ce3bf3a31af18be40ba30f721101b4341690186.omft.near";
const SOL_RCPT: &str = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
const ADDR: &str = "e58cd49e954da6bb6d2403822ef329bd2e9f67da80cb40706febfada0583d097";

fn sol_dest(active_at: u64) -> Dest {
    Dest {
        label: "my sol".into(),
        asset: SOL.into(),
        recipient: SOL_RCPT.into(),
        recipient_type: "DESTINATION_CHAIN".into(),
        active_at_ns: U64(active_at),
    }
}

/// The live withdraw quote (quote-live-wd-intents) re-targeted at this account: refund to
/// self on ORIGIN_CHAIN, deadline `deadline_ns`. Everything else is the real 1Click payload.
fn synthetic(amount: u128, deadline_ns: u64) -> Map<String, Value> {
    let x = vectors().into_iter().find(|x| x.name == "quote-live-wd-intents").unwrap();
    let mut m = obj(&x.signed_quote);
    m["refundTo"] = Value::from(me().to_string());
    m["refundType"] = Value::from("ORIGIN_CHAIN");
    m["amount"] = Value::from(amount.to_string());
    m["amountIn"] = Value::from(amount.to_string());
    m["deadline"] = Value::from(fmt_iso(deadline_ns));
    // v1.4.2 (C1-L2): the signed issue time must be fresh; tests use deadline - 1 h (= "now"
    // for the usual now + 1 h deadline)
    m["timestamp"] = Value::from(fmt_iso(deadline_ns.saturating_sub(3_600 * NS_PER_SEC)));
    m
}

fn expect(dest: &Dest, amount: u128, now: u64) -> Expect<'_> {
    Expect {
        self_id: "abcd.tt.near",
        token: "wrap.near",
        amount,
        dest,
        max_slippage_bps: 300,
        max_loss_bps: 100,
        now_ns: now,
    }
}

fn check(m: &Map<String, Value>, e: &Expect) -> Result<String, &'static str> {
    let s = stable(&Value::Object(m.clone()));
    let q = ix::parse_quote(&s)?;
    ix::check_quote(&q, e).map(|x| x.deposit_address.to_string())
}

#[test]
fn check_quote_accepts_matching_and_rejects_each_mismatch() {
    let dest = sol_dest(0);
    let now = T0;
    let e = expect(&dest, NEAR, now);
    let good = synthetic(NEAR, now + 3_600 * NS_PER_SEC);
    assert_eq!(check(&good, &e), Ok(ADDR.to_string()));
    // the unmodified live quote: refund goes to alice.near via INTENTS -> rejected
    let live = obj(&vectors().into_iter().find(|x| x.name == "quote-live-wd-intents").unwrap().signed_quote);
    assert_eq!(check(&live, &e), Err("E_QUOTE_MISMATCH"));
    let cases: Vec<(&str, Value)> = vec![
        ("dry", Value::Bool(true)),
        ("swapType", "EXACT_OUTPUT".into()),
        ("swapType", "FLEX_INPUT".into()),
        ("depositType", "ORIGIN_CHAIN".into()),
        ("originAsset", "nep141:usdc.near".into()),
        ("originAsset", "wrap.near".into()),
        ("originAsset", "nep245:wrap.near".into()),
        ("amount", (NEAR - 1).to_string().into()),
        ("amount", format!("0{NEAR}").into()),
        ("amountIn", (NEAR + 1).to_string().into()),
        ("destinationAsset", "nep141:eth.omft.near".into()),
        ("recipient", "attacker111111111111111111111111111111111111".into()),
        ("recipient", SOL_RCPT.to_lowercase().into()),
        ("recipientType", "INTENTS".into()),
        ("refundTo", "attacker.near".into()),
        ("refundType", "INTENTS".into()),
        ("slippageTolerance", 301.into()),
        ("minAmountOut", "0".into()),
        ("minAmountOut", "abc".into()),
        ("depositAddress", ADDR.to_uppercase().into()),
        ("depositAddress", "attacker.near".into()),
        ("depositAddress", ADDR[..62].into()),
        ("deadline", "tomorrow".into()),
    ];
    for (k, v) in cases {
        let mut m = good.clone();
        m[k] = v.clone();
        assert_eq!(check(&m, &e), Err("E_QUOTE_MISMATCH"), "{k}={v}");
    }
    for (k, v) in [
        ("customRecipientMsg", Value::from("{}")),
        ("depositMemo", "186792106".into()),
        ("virtualChainRecipient", "x".into()),
        ("appFees", Value::Array(vec![])),
    ] {
        let mut m = good.clone();
        m.insert(k.into(), v);
        assert_eq!(check(&m, &e), Err("E_QUOTE_MISMATCH"), "{k}");
    }
    for k in ["depositAddress", "recipient", "refundTo", "deadline", "minAmountOut", "dry"] {
        let mut m = good.clone();
        m.remove(k);
        assert_eq!(check(&m, &e), Err("E_QUOTE_MISMATCH"), "missing {k}");
    }
    // slippage at the configured ceiling passes; a lower ceiling rejects it
    let mut m = good.clone();
    m["slippageTolerance"] = 300.into();
    assert!(check(&m, &e).is_ok());
    assert_eq!(
        check(&m, &Expect { max_slippage_bps: 299, ..expect(&dest, NEAR, now) }),
        Err("E_QUOTE_MISMATCH")
    );
    // token must match originAsset
    assert_eq!(
        check(&good, &Expect { token: "usdc.near", ..expect(&dest, NEAR, now) }),
        Err("E_QUOTE_MISMATCH")
    );
    // refundTo must be THIS account
    assert_eq!(
        check(&good, &Expect { self_id: "other.tt.near", ..expect(&dest, NEAR, now) }),
        Err("E_QUOTE_MISMATCH")
    );
    // duplicate key (parser differential): rejected
    let s = stable(&Value::Object(good.clone()));
    let dup = s.replacen('{', &format!("{{\"recipient\":\"{SOL_RCPT}\","), 1);
    assert!(ix::parse_quote(&dup).is_err());
    // oversize
    assert!(ix::parse_quote(&" ".repeat(ix::MAX_SIGNED_QUOTE_LEN + 1)).is_err());
}

#[test]
fn check_quote_deadline() {
    let dest = sol_dest(0);
    let now = T0;
    let lead = ix::MIN_DEADLINE_LEAD_NS;
    let ok_ = synthetic(NEAR, now + lead + NS_PER_SEC / 1000);
    assert!(check(&ok_, &expect(&dest, NEAR, now)).is_ok());
    for d in [now + lead, now, now - NS_PER_SEC, 0] {
        assert_eq!(check(&synthetic(NEAR, d), &expect(&dest, NEAR, now)), Err("E_QUOTE_EXPIRED"), "{d}");
    }
    // a mismatching expired quote reports the mismatch
    let mut m = synthetic(NEAR, now);
    m["refundTo"] = "x.near".into();
    assert_eq!(check(&m, &expect(&dest, NEAR, now)), Err("E_QUOTE_MISMATCH"));
}

#[test]
fn dest_and_config_validation() {
    assert_eq!(ix::check_dest(&sol_dest(0)), Ok(()));
    let bad = |f: &dyn Fn(&mut Dest)| {
        let mut d = sol_dest(0);
        f(&mut d);
        ix::check_dest(&d)
    };
    assert_eq!(bad(&|d| d.label = String::new()), Err("E_BAD_DEST"));
    assert_eq!(bad(&|d| d.label = "x".repeat(33)), Err("E_BAD_DEST"));
    assert_eq!(bad(&|d| d.asset = String::new()), Err("E_BAD_DEST"));
    assert_eq!(bad(&|d| d.recipient = "x".repeat(129)), Err("E_BAD_DEST"));
    assert_eq!(bad(&|d| d.recipient = "a\nb".into()), Err("E_BAD_DEST"));
    assert_eq!(bad(&|d| d.recipient_type = "ORIGIN_CHAIN".into()), Err("E_BAD_DEST"));
    assert_eq!(bad(&|d| d.recipient_type = "INTENTS".into()), Ok(()));
    ctx("tt.near", 0, NEAR, T0);
    let cfg = |keys: Vec<String>, s: u16| OneClickConfig {
        keys,
        max_slippage_bps: s,
        intents: a("intents.near"),
        max_loss_bps: 100,
    };
    assert_eq!(ix::check_config(&cfg(vec![], 100)), Err("E_BAD_ONECLICK"));
    assert_eq!(ix::check_config(&cfg(vec![ix::ONECLICK_MANAGER_KEY.into(); 4], 100)), Err("E_BAD_ONECLICK"));
    assert_eq!(ix::check_config(&cfg(manager(), 301)), Err("E_BAD_ONECLICK"));
    assert_eq!(ix::check_config(&cfg(vec!["ed25519:abc".into()], 100)), Err("E_BAD_ONECLICK"));
    assert_eq!(ix::check_config(&cfg(vec![ix::ONECLICK_MANAGER_KEY.into(); 3], 0)), Ok(()));
}

proptest! {
    #[test]
    fn quote_parser_never_panics(s in ".{0,600}") {
        let _ = ix::parse_quote(&s);
    }

    /// Byte-mutated live payloads: never panic; any that still parse and pass the checks
    /// are field-for-field what the checks demand.
    #[test]
    fn quote_parser_mutations(idx in 0usize..64, pos in any::<prop::sample::Index>(), byte in any::<u8>()) {
        let v = vectors();
        let x = &v[idx % v.len()];
        let mut b = x.signed_quote.clone().into_bytes();
        let i = pos.index(b.len());
        b[i] = byte;
        if let Ok(s) = String::from_utf8(b) {
            if let Ok(q) = ix::parse_quote(&s) {
                let dest = sol_dest(0);
                if let Ok(addr) = ix::check_quote(&q, &expect(&dest, NEAR, T0)) {
                    prop_assert!(!q.dry && q.refund_to == "abcd.tt.near" && q.recipient == SOL_RCPT);
                    prop_assert!(ix::is_deposit_address(addr.deposit_address));
                }
            }
        }
    }

    /// Arbitrary well-formed quotes: accepted iff every checked field matches.
    #[test]
    fn check_quote_iff_all_fields_match(
        flip in prop::collection::vec(any::<bool>(), 12),
        slip in 0u16..600,
        amount in 1u128..u128::MAX,
        lead_s in 0u64..7200,
    ) {
        let dest = sol_dest(0);
        let mut m = synthetic(amount, T0 + lead_s * NS_PER_SEC);
        m["timestamp"] = fmt_iso(T0).into();
        m["slippageTolerance"] = slip.into();
        let fields = ["dry", "swapType", "depositType", "originAsset", "amount", "amountIn",
            "destinationAsset", "recipient", "recipientType", "refundTo", "refundType", "depositAddress"];
        for (f, k) in flip.iter().zip(fields) {
            if *f {
                m[k] = match &m[k] { Value::Bool(b) => Value::Bool(!b), Value::String(s) => format!("{s}x").into(), x => x.clone() };
            }
        }
        let r = check(&m, &expect(&dest, amount, T0));
        let should = !flip.iter().any(|f| *f) && slip <= 300;
        if should {
            prop_assert_eq!(r.is_ok(), lead_s * NS_PER_SEC > ix::MIN_DEADLINE_LEAD_NS);
        } else {
            prop_assert_eq!(r, Err("E_QUOTE_MISMATCH"));
        }
    }
}

// ---------------- contract methods (mocked chain) ----------------

fn owner_ctx(now: u64) {
    ctx("owner.near", 1, 10 * NEAR, now);
}

fn device_ctx(now: u64) {
    ctx(me().as_str(), 0, 10 * NEAR, now);
}

/// Account with the test key + manager configured and one SOL destination (id 0) added at T0.
fn intents_account() -> TradingAccount {
    let mut c = new_account();
    owner_ctx(T0);
    c.owner_set_oneclick_config(vec![pk_str(&test_sk()), ix::ONECLICK_MANAGER_KEY.into()], 300, None, None);
    assert_eq!(
        c.owner_add_withdraw_destination(
            "sol".into(),
            SOL.into(),
            SOL_RCPT.into(),
            "DESTINATION_CHAIN".into()
        ),
        0
    );
    c
}

fn signed(amount: u128, now: u64, f: impl Fn(&mut Map<String, Value>)) -> (String, String) {
    let mut m = synthetic(amount, now + 3_600 * NS_PER_SEC);
    f(&mut m);
    let s = stable(&Value::Object(m));
    let sig = sign(&test_sk(), &s);
    (s, sig)
}

fn wcc(c: &mut TradingAccount, id: &str, dest: u32, token: &str, amount: u128, q: &(String, String)) {
    c.withdraw_cross_chain(
        dest,
        a(token),
        U128(amount),
        q.0.clone(),
        q.1.clone(),
        id.into(),
        U64(env::block_timestamp() + 60 * NS_PER_SEC),
    );
}

const ACTIVE: u64 = T0 + ix::DEST_DELAY_NS;

#[test]
fn withdraw_cross_chain_happy_path_shape() {
    let mut c = intents_account();
    device_ctx(ACTIVE);
    let q = signed(NEAR, ACTIVE, |_| {});
    wcc(&mut c, "w1", 0, "wrap.near", NEAR, &q);
    let rs = get_created_receipts();
    assert_eq!(rs.len(), 2, "{rs:?}");
    assert_eq!(rs[0].receiver_id, a("wrap.near"));
    match &rs[0].actions[0] {
        MockAction::FunctionCallWeight { method_name, attached_deposit, args, prepaid_gas, .. } => {
            assert_eq!(method_name, b"ft_transfer_call");
            assert_eq!(attached_deposit.as_yoctonear(), 1);
            assert_eq!(*prepaid_gas, Gas::from_tgas(50));
            let v: Value = serde_json::from_slice(args).unwrap();
            assert_eq!(v["receiver_id"], "intents.near");
            assert_eq!(v["amount"], NEAR.to_string());
            assert_eq!(v["msg"], ADDR);
        }
        x => panic!("{x:?}"),
    }
    assert_eq!(rs[1].receiver_id, me());
    assert_eq!(rs[1].receipt_indices, vec![0]);
    // separate window: amount + whole prepaid gas; trading window untouched
    let gas = (300 * TGAS) as u128 * GAS_PRICE_BOUND;
    assert_eq!(c.get_withdraw_day().spent_yocto.0, NEAR + gas);
    assert_eq!(c.get_withdraw_day().cap_yocto.0, 5 * NEAR, "default = trading daily cap");
    assert_eq!(c.get_day().spent_yocto.0, 0);
    assert_eq!(c.get_day().gas_spent_yocto.0, 0);
    // no platform fee on-chain (decision 2: 1Click appFees)
    assert!(rs.iter().all(|r| r.receiver_id != a("fees.near")));
    // exactly-once: the same quote again (new client id) is a replay
    device_ctx(ACTIVE + 1);
    assert_eq!(panics(move || wcc(&mut c, "w2", 0, "wrap.near", NEAR, &q)), "E_QUOTE_REPLAY");
}

#[test]
fn withdraw_cross_chain_rejections() {
    let run = |now: u64, dest: u32, token: &str, amount: u128, q: (String, String)| {
        let mut c = intents_account();
        device_ctx(now);
        panics(move || wcc(&mut c, "w", dest, token, amount, &q))
    };
    let q = || signed(NEAR, ACTIVE, |_| {});
    // 1h activation delay
    assert_eq!(run(ACTIVE - 1, 0, "wrap.near", NEAR, signed(NEAR, ACTIVE - 1, |_| {})), "E_DEST_INACTIVE");
    assert_eq!(run(ACTIVE, 7, "wrap.near", NEAR, q()), "E_DEST_INACTIVE");
    // signature
    let (s, _) = q();
    let other = SigningKey::from_bytes(&[9u8; 32]);
    assert_eq!(run(ACTIVE, 0, "wrap.near", NEAR, (s.clone(), sign(&other, &s))), "E_QUOTE_SIG");
    let (_, sig) = q();
    assert_eq!(run(ACTIVE, 0, "wrap.near", NEAR, (s.replace(SOL_RCPT, "Attacker"), sig)), "E_QUOTE_SIG");
    // signed but mismatching
    let bad = signed(NEAR, ACTIVE, |m| m["recipient"] = "Attacker".into());
    assert_eq!(run(ACTIVE, 0, "wrap.near", NEAR, bad), "E_QUOTE_MISMATCH");
    assert_eq!(run(ACTIVE, 0, "wrap.near", NEAR - 1, q()), "E_QUOTE_MISMATCH");
    assert_eq!(run(ACTIVE, 0, "usdc.near", NEAR, q()), "E_QUOTE_MISMATCH");
    // expired
    let exp = signed(NEAR, ACTIVE, |m| m["deadline"] = fmt_iso(ACTIVE + 30 * NS_PER_SEC).into());
    assert_eq!(run(ACTIVE, 0, "wrap.near", NEAR, exp), "E_QUOTE_EXPIRED");
    // caps: withdraw cap (default 5 NEAR) incl. gas
    let big = signed(5 * NEAR, ACTIVE, |_| {});
    assert_eq!(run(ACTIVE, 0, "wrap.near", 5 * NEAR, big), "E_WITHDRAW_CAP");
    // not device / automation
    let mut c = intents_account();
    ctx("owner.near", 0, 10 * NEAR, ACTIVE);
    assert_eq!(panics(move || wcc(&mut c, "w", 0, "wrap.near", NEAR, &q())), "E_NOT_SELF");
    // unconfigured
    let mut c = new_account();
    owner_ctx(T0);
    c.owner_add_withdraw_destination("sol".into(), SOL.into(), SOL_RCPT.into(), "DESTINATION_CHAIN".into());
    device_ctx(ACTIVE);
    assert_eq!(panics(move || wcc(&mut c, "w", 0, "wrap.near", NEAR, &q())), "E_ONECLICK_UNSET");
}

#[test]
fn non_wnear_token_uncounted_but_gas_is() {
    let mut c = intents_account();
    device_ctx(ACTIVE);
    let q = signed(1_000_000, ACTIVE, |m| m["originAsset"] = "nep141:usdc.near".into());
    wcc(&mut c, "w1", 0, "usdc.near", 1_000_000, &q);
    assert_eq!(c.get_withdraw_day().spent_yocto.0, (300 * TGAS) as u128 * GAS_PRICE_BOUND);
    assert_eq!(get_created_receipts()[0].receiver_id, a("usdc.near"));
}

fn settle_intents(c: &mut TradingAccount, r: PromiseResult, amount: u128, counted: u128, day_start: u64) {
    testing_env!(
        VMContextBuilder::new()
            .current_account_id(me())
            .predecessor_account_id(me())
            .signer_account_id(me())
            .storage_usage(STORAGE_BYTES)
            .account_balance(NearToken::from_yoctonear(10 * NEAR))
            .block_timestamp(ACTIVE + 5)
            .build(),
        near_sdk::test_vm_config(),
        near_sdk::RuntimeFeesConfig::test(),
        Default::default(),
        vec![r],
    );
    c.on_intents_sent(
        "w1".into(),
        Some(0),
        a("wrap.near"),
        U128(amount),
        U128(counted),
        U64(day_start),
        ADDR.into(),
        None,
    );
}

#[test]
fn settle_returns_unused_to_withdraw_window() {
    let gas = (300 * TGAS) as u128 * GAS_PRICE_BOUND;
    for (r, used) in [
        (ok_json(NEAR), NEAR),
        (ok_json(NEAR / 4), NEAR / 4),
        (ok_json(0), 0),
        (PromiseResult::Failed, 0),
        (ok_json(5 * NEAR), NEAR), // over-report clamps
    ] {
        let mut c = intents_account();
        device_ctx(ACTIVE);
        wcc(&mut c, "w1", 0, "wrap.near", NEAR, &signed(NEAR, ACTIVE, |_| {}));
        let start = c.get_withdraw_day().start_ns.0;
        settle_intents(&mut c, r, NEAR, NEAR, start);
        assert_eq!(c.get_withdraw_day().spent_yocto.0, used + gas, "used {used}");
        let log = get_logs().pop().unwrap();
        assert!(
            log.contains("\"event\":\"intents_withdraw\"") && log.contains(&format!("\"used\":\"{used}\"")),
            "{log}"
        );
        assert!(log.contains(ADDR) && log.contains("\"dest_id\":0"));
        // a settle for an older window doesn't touch the current one
        settle_intents(&mut c, ok_json(0), NEAR, NEAR, start - 1);
        assert_eq!(c.get_withdraw_day().spent_yocto.0, used + gas);
    }
}

#[test]
fn destinations_owner_adds_device_only_removes() {
    let mut c = intents_account();
    let v = c.get_withdraw_destinations();
    assert_eq!(v.len(), 1);
    assert!(!v[0].active);
    assert_eq!(v[0].dest.active_at_ns.0, ACTIVE);
    ctx(me().as_str(), 0, 10 * NEAR, ACTIVE);
    assert!(c.get_withdraw_destinations()[0].active);
    // device cannot add (owner-only) nor configure
    let mut c2 = intents_account();
    ctx(me().as_str(), 0, 10 * NEAR, ACTIVE);
    assert_eq!(
        panics(move || {
            c2.owner_add_withdraw_destination(
                "x".into(),
                SOL.into(),
                "Attacker".into(),
                "DESTINATION_CHAIN".into(),
            );
        }),
        "E_NOT_OWNER"
    );
    let mut c3 = intents_account();
    ctx(me().as_str(), 0, 10 * NEAR, ACTIVE);
    assert_eq!(
        panics(move || c3.owner_set_oneclick_config(vec![pk_str(&test_sk())], 300, None, None)),
        "E_NOT_OWNER"
    );
    let mut c4 = intents_account();
    ctx(me().as_str(), 0, 10 * NEAR, ACTIVE);
    assert_eq!(panics(move || c4.owner_set_withdraw_cap(Some(U128(u128::MAX)), None)), "E_NOT_OWNER");
    // owner needs 1 yocto
    let mut c5 = intents_account();
    ctx("owner.near", 0, 10 * NEAR, ACTIVE);
    assert_eq!(panics(move || c5.owner_remove_withdraw_destination(0)), "E_ONE_YOCTO");
    // device removes; then the destination is unusable
    device_ctx(ACTIVE);
    c.remove_withdraw_destination(0);
    assert!(c.get_withdraw_destinations().is_empty());
    let q = signed(NEAR, ACTIVE, |_| {});
    assert_eq!(panics(move || wcc(&mut c, "w", 0, "wrap.near", NEAR, &q)), "E_DEST_INACTIVE");
    let mut c = intents_account();
    device_ctx(ACTIVE);
    assert_eq!(panics(move || c.remove_withdraw_destination(3)), "E_NO_DEST");
    // limits
    let mut c = intents_account();
    owner_ctx(T0);
    for i in 1..ix::MAX_DESTS {
        assert_eq!(
            c.owner_add_withdraw_destination(format!("d{i}"), SOL.into(), SOL_RCPT.into(), "INTENTS".into()),
            i as u32
        );
    }
    assert_eq!(
        panics(move || {
            c.owner_add_withdraw_destination("x".into(), SOL.into(), SOL_RCPT.into(), "INTENTS".into());
        }),
        "E_DEST_LIMIT"
    );
    let mut c = intents_account();
    owner_ctx(T0);
    assert_eq!(
        panics(move || {
            c.owner_add_withdraw_destination("x".into(), SOL.into(), SOL_RCPT.into(), "EVM".into());
        }),
        "E_BAD_DEST"
    );
    let mut c = intents_account();
    owner_ctx(T0);
    assert_eq!(panics(move || c.owner_set_oneclick_config(vec![], 300, None, None)), "E_BAD_ONECLICK");
}

#[test]
fn withdraw_cap_separate_and_owner_adjustable() {
    let mut c = intents_account();
    owner_ctx(T0);
    c.owner_set_withdraw_cap(Some(U128(10 * NEAR)), None);
    assert_eq!(c.get_withdraw_day().cap_yocto.0, 10 * NEAR);
    // exhaust the TRADING cap: withdrawals still work
    device_ctx(ACTIVE);
    c.day.spent_yocto = 5 * NEAR;
    c.day.start_ns = ACTIVE;
    wcc(&mut c, "w1", 0, "wrap.near", 5 * NEAR, &signed(5 * NEAR, ACTIVE, |_| {}));
    assert_eq!(c.get_day().spent_yocto.0, 5 * NEAR);
    // and the withdraw window rolls after 24h
    device_ctx(ACTIVE + DAY_NS);
    assert_eq!(c.get_withdraw_day().spent_yocto.0, 0);
    let q = signed(9 * NEAR, ACTIVE + DAY_NS, |m| m["depositAddress"] = ADDR.replace('e', "a").into());
    wcc(&mut c, "w2", 0, "wrap.near", 9 * NEAR, &q);
    let q = signed(NEAR, ACTIVE + DAY_NS, |m| m["depositAddress"] = ADDR.replace('e', "f").into());
    assert_eq!(panics(move || wcc(&mut c, "w3", 0, "wrap.near", NEAR, &q)), "E_WITHDRAW_CAP");
}

#[test]
fn owner_withdraw_via_intents_any_address() {
    let mut c = new_account();
    owner_ctx(T0);
    c.owner_withdraw_via_intents(a("usdc.near"), U128(5), ADDR.into());
    let rs = get_created_receipts();
    match &rs[0].actions[0] {
        MockAction::FunctionCallWeight { method_name, args, .. } => {
            assert_eq!(method_name, b"ft_transfer_call");
            let v: Value = serde_json::from_slice(args).unwrap();
            assert_eq!(v["receiver_id"], "intents.near", "default verifier");
            assert_eq!(v["msg"], ADDR);
        }
        x => panic!("{x:?}"),
    }
    assert_eq!(c.get_withdraw_day().spent_yocto.0, 0, "owner path uncapped");
    owner_ctx(T0);
    assert_eq!(
        panics(move || c.owner_withdraw_via_intents(a("usdc.near"), U128(5), "alice.near".into())),
        "E_BAD_DEPOSIT_ADDRESS"
    );
    let mut c = new_account();
    device_ctx(T0);
    assert_eq!(
        panics(move || c.owner_withdraw_via_intents(a("usdc.near"), U128(5), ADDR.into())),
        "E_NOT_OWNER"
    );
}

// ---------------- flat parser ----------------

#[test]
fn flat_parser_rejects_non_flat_and_ambiguous() {
    use ix::Val::*;
    assert_eq!(
        ix::parse_flat(r#" { "a" : "x" , "b":-1.5e+3,"c":true,"d":false,"e":null,"f":0 } "#),
        Some(vec![
            ("a", Str("x")),
            ("b", Num("-1.5e+3")),
            ("c", Bool(true)),
            ("d", Bool(false)),
            ("e", Null),
            ("f", Num("0"))
        ])
    );
    assert_eq!(ix::parse_flat("{}"), Some(vec![]));
    for bad in [
        "",
        "{",
        "}",
        "[]",
        r#"{"a":"x",}"#,
        r#"{"a":"x""b":"y"}"#,
        r#"{"a":"x"} x"#,
        r#"{"a":"x"}{"#,
        r#"{"a":{"b":"c"}}"#,
        r#"{"a":["b"]}"#,
        r#"{"a":"x","a":"x"}"#,
        concat!(r#"{"a":""#, "\\", r#"u0078"}"#),
        r#"{"a\"":"x"}"#,
        "{\"a\":\"x\ny\"}",
        r#"{"a":01}"#,
        r#"{"a":1.}"#,
        r#"{"a":.5}"#,
        r#"{"a":1e}"#,
        r#"{"a":-}"#,
        r#"{"a":+1}"#,
        r#"{"a":tru}"#,
        r#"{"a":True}"#,
        r#"{a:"x"}"#,
        r#"{'a':"x"}"#,
        r#"{"a":"x"#,
    ] {
        assert_eq!(ix::parse_flat(bad), None, "{bad}");
    }
}

fn scalar() -> impl Strategy<Value = Value> {
    prop_oneof![
        "[ -!#-\\[\\]-~]{0,12}".prop_map(Value::from), // printable ASCII minus '"' and '\'
        any::<i64>().prop_map(Value::from),
        any::<bool>().prop_map(Value::from),
        Just(Value::Null),
    ]
}

proptest! {
    /// On escape-free flat objects the parser agrees with serde_json exactly.
    #[test]
    fn flat_parser_matches_serde_json(m in prop::collection::btree_map("[a-zA-Z]{1,8}", scalar(), 0..12)) {
        let s = stable(&Value::Object(m.clone().into_iter().collect()));
        let got = ix::parse_flat(&s).expect("valid flat object");
        prop_assert_eq!(got.len(), m.len());
        for (k, v) in got {
            let want = &m[k];
            match v {
                ix::Val::Str(x) => prop_assert_eq!(&Value::from(x), want),
                ix::Val::Num(x) => prop_assert_eq!(&serde_json::from_str::<Value>(x).unwrap(), want),
                ix::Val::Bool(x) => prop_assert_eq!(&Value::from(x), want),
                ix::Val::Null => prop_assert_eq!(&Value::Null, want),
            }
        }
    }

    /// Whatever it accepts, serde_json accepts as the same object (no differential).
    #[test]
    fn flat_parser_accepts_only_valid_json(s in "[{}\\[\\]\":,a-c0-9 .eE+\\-tfnulrs\\\\]{0,40}") {
        if let Some(got) = ix::parse_flat(&s) {
            let v: Value = serde_json::from_str(&s).expect("serde_json accepts");
            let o = v.as_object().expect("object");
            prop_assert_eq!(o.len(), got.len());
            for (k, _) in got {
                prop_assert!(o.contains_key(k));
            }
        }
    }

    #[test]
    fn flat_parser_never_panics(s in ".{0,300}") {
        let _ = ix::parse_flat(&s);
    }
}

#[test]
fn quote_parser_types_and_required_fields() {
    let x = vectors().into_iter().find(|x| x.name == "quote-live-wd-intents").unwrap();
    let m = obj(&x.signed_quote);
    let q = ix::parse_quote(&x.signed_quote).unwrap();
    assert_eq!(
        (q.dry, q.slippage_tolerance, q.recipient, q.deposit_address),
        (false, 100, SOL_RCPT, Some(ADDR))
    );
    assert_eq!(q.deadline, "2026-10-01T11:29:50.000Z", "the quote's deadline, not the request's");
    // wrong types
    for (k, v) in [
        ("dry", Value::from("false")),
        ("slippageTolerance", "100".into()),
        ("slippageTolerance", Value::from(1.5)),
        ("slippageTolerance", Value::from(70000)),
        ("slippageTolerance", Value::from(-1)),
        ("amount", Value::from(1)),
        ("recipient", Value::Null),
        ("depositAddress", Value::from(1)),
        ("depositMemo", Value::Bool(true)),
    ] {
        let mut t = m.clone();
        t.insert(k.into(), v.clone());
        assert!(ix::parse_quote(&stable(&Value::Object(t))).is_err(), "{k}={v}");
    }
    // optional fields may be null
    let mut t = m.clone();
    t["depositAddress"] = Value::Null;
    t.insert("depositMemo".into(), Value::Null);
    let s = stable(&Value::Object(t));
    let q = ix::parse_quote(&s).unwrap();
    assert_eq!((q.deposit_address, q.deposit_memo), (None, None));
    // every required field is required
    for k in [
        "dry",
        "swapType",
        "depositType",
        "originAsset",
        "destinationAsset",
        "amount",
        "amountIn",
        "refundTo",
        "refundType",
        "recipient",
        "recipientType",
        "slippageTolerance",
        "minAmountOut",
        "deadline",
        "amountInUsd",
        "amountOutUsd",
        "timestamp",
    ] {
        let mut t = m.clone();
        t.remove(k);
        assert!(ix::parse_quote(&stable(&Value::Object(t))).is_err(), "missing {k}");
    }
    // ignored fields are optional
    let mut t = m.clone();
    for k in ["amountInFormatted", "amountOutFormatted", "refundFee", "withdrawFee", "timeEstimate"] {
        t.remove(k);
    }
    assert!(ix::parse_quote(&stable(&Value::Object(t))).is_ok());
}

// ======================= v1.4.1 (audit B1 + B2-H2) =======================

fn with_usd(m: &mut Map<String, Value>, usd_in: &str, usd_out: &str) {
    m["amountInUsd"] = usd_in.into();
    m["amountOutUsd"] = usd_out.into();
}

#[test]
fn b1_m1_loss_bound_from_signed_usd() {
    let dest = sol_dest(0);
    let e = expect(&dest, NEAR, T0);
    let base = synthetic(NEAR, T0 + 3_600 * NS_PER_SEC);
    let run = |i: &str, o: &str| {
        let mut m = base.clone();
        with_usd(&mut m, i, o);
        check(&m, &e)
    };
    assert!(run("100", "99").is_ok(), "exactly 100 bps");
    assert_eq!(run("100", "98.999999999999"), Err("E_QUOTE_LOSS"));
    assert_eq!(run("100.000000000001", "99"), Err("E_QUOTE_LOSS"));
    assert!(run("100", "101").is_ok(), "gain");
    // the audit's appFees evidence: 490 bps appFees show as ~5.6 % signed USD loss
    assert_eq!(run("19.996640000000", "18.876828160000"), Err("E_QUOTE_LOSS"));
    // no USD price -> no bound -> rejected
    assert_eq!(run("0", "0"), Err("E_QUOTE_LOSS"));
    assert_eq!(run("0.000000000000", "1"), Err("E_QUOTE_LOSS"));
    for bad in ["", "-1", "+1", "1.", ".5", "1e3", "1,5", " 1", "1234567890123456789"] {
        assert_eq!(run(bad, "1"), Err("E_QUOTE_MISMATCH"), "{bad:?}");
        assert_eq!(run("1", bad), Err("E_QUOTE_MISMATCH"), "{bad:?}");
    }
    // configured bound
    let strict = Expect { max_loss_bps: 50, ..expect(&dest, NEAR, T0) };
    let mut m = base.clone();
    with_usd(&mut m, "100", "99.4");
    assert_eq!(check(&m, &strict), Err("E_QUOTE_LOSS"));
    assert!(check(&m, &e).is_ok());
    // every live withdraw vector passes at the default bound except BTC ($25, network fee)
    let x = vectors();
    for v in x.iter().filter(|v| v.name.contains("wd")) {
        let q = obj(&v.signed_quote);
        let mut m = base.clone();
        with_usd(&mut m, q["amountInUsd"].as_str().unwrap(), q["amountOutUsd"].as_str().unwrap());
        let r = check(&m, &e);
        assert_eq!(r.is_ok(), !v.name.contains("BTC"), "{} {r:?}", v.name);
    }
}

#[test]
fn b1_m1_usd_parser() {
    assert_eq!(ix::parse_usd("4.980000000000"), Some(4_980_000_000_000));
    assert_eq!(ix::parse_usd("0"), Some(0));
    assert_eq!(ix::parse_usd("12"), Some(12_000_000_000_000));
    assert_eq!(ix::parse_usd("1.0000000000009"), Some(1_000_000_000_000), "truncated past 1e-12");
    assert_eq!(ix::parse_usd("999999999999999999"), Some(999_999_999_999_999_999_000_000_000_000));
    for bad in ["", ".", "1.", ".1", "-1", "+1", "1e2", "0x1", "1.2.3", "1 ", "١"] {
        assert_eq!(ix::parse_usd(bad), None, "{bad:?}");
    }
    assert_eq!(ix::parse_uint("0"), Some(0));
    for bad in ["+5", "007", "", "-1", " 1", "1e3"] {
        assert_eq!(ix::parse_uint(bad), None, "{bad:?}");
    }
}

proptest! {
    #[test]
    fn usd_parser_matches_decimal(i in 0u64..1_000_000_000_000, f in "[0-9]{0,15}") {
        let s = if f.is_empty() { i.to_string() } else { format!("{i}.{f}") };
        let f12: String = f.chars().chain(std::iter::repeat('0')).take(12).collect();
        let want = u128::from(i) * 1_000_000_000_000 + f12.parse::<u128>().unwrap();
        prop_assert_eq!(ix::parse_usd(&s), Some(want));
    }

    #[test]
    fn usd_parser_never_panics(s in ".{0,40}") {
        let _ = ix::parse_usd(&s);
        let _ = ix::parse_uint(&s);
    }

    /// Loss bound holds exactly: accept <=> out * 1e4 >= in * (1e4 - max_loss).
    #[test]
    fn loss_bound_exact(inp in 1u64..1_000_000_000, out in 0u64..2_000_000_000, loss in 50u16..=300) {
        let dest = sol_dest(0);
        let mut m = synthetic(NEAR, T0 + 3_600 * NS_PER_SEC);
        with_usd(&mut m, &format!("{}.{:06}", inp / 1_000_000, inp % 1_000_000), &format!("{}.{:06}", out / 1_000_000, out % 1_000_000));
        let r = check(&m, &Expect { max_loss_bps: loss, ..expect(&dest, NEAR, T0) });
        let ok = u128::from(out) * 10_000 >= u128::from(inp) * u128::from(10_000 - loss);
        prop_assert_eq!(r.is_ok(), ok, "{:?}", r);
        if !ok { prop_assert_eq!(r, Err("E_QUOTE_LOSS")); }
    }
}

#[test]
fn b1_m1_config_loss_range() {
    for v in [Some(29), Some(301), Some(0)] {
        let mut c = new_account();
        owner_ctx(T0);
        assert_eq!(
            panics(move || c.owner_set_oneclick_config(vec![pk_str(&test_sk())], 300, None, v)),
            "E_BAD_ONECLICK"
        );
    }
    for (v, want) in [(Some(30), 30), (Some(300), 300), (None, 50)] {
        let mut c = new_account();
        owner_ctx(T0);
        c.owner_set_oneclick_config(vec![pk_str(&test_sk())], 300, None, v);
        assert_eq!(c.get_oneclick_config().unwrap().max_loss_bps, want);
    }
}

#[test]
fn b1_m1_usd_cap_covers_all_tokens() {
    let mut c = intents_account();
    assert_eq!(c.get_withdraw_day().cap_usd.0, ix::DEFAULT_WITHDRAW_CAP_USD);
    owner_ctx(T0);
    c.owner_set_withdraw_cap(None, Some(U128(100_000_000))); // $100
    assert_eq!(c.get_withdraw_day().cap_yocto.0, 5 * NEAR, "yocto cap unchanged");
    // 5M USDC (the audit case) worth $5M: rejected by the USD cap although wNEAR-uncounted
    device_ctx(ACTIVE);
    let q = signed(5_000_000_000_000, ACTIVE, |m| {
        m["originAsset"] = "nep141:usdc.near".into();
        with_usd(m, "5000000", "4990000");
    });
    let mut c2 = intents_account();
    owner_ctx(T0);
    c2.owner_set_withdraw_cap(None, Some(U128(100_000_000)));
    device_ctx(ACTIVE);
    assert_eq!(panics(move || wcc(&mut c2, "w", 0, "usdc.near", 5_000_000_000_000, &q)), "E_WITHDRAW_CAP");
    // $60 of USDC then $40.000001 more: the second is over
    let q1 = signed(60_000_000, ACTIVE, |m| {
        m["originAsset"] = "nep141:usdc.near".into();
        m["depositAddress"] = ADDR.replace('e', "1").into();
        with_usd(m, "60", "59.9");
    });
    wcc(&mut c, "w1", 0, "usdc.near", 60_000_000, &q1);
    let d = c.get_withdraw_day();
    assert_eq!((d.spent_usd.0, d.spent_yocto.0), (60_000_000, (300 * TGAS) as u128 * GAS_PRICE_BOUND));
    let q2 = signed(40_000_001, ACTIVE, |m| {
        m["originAsset"] = "nep141:usdc.near".into();
        m["depositAddress"] = ADDR.replace('e', "2").into();
        with_usd(m, "40.000001", "40");
    });
    device_ctx(ACTIVE);
    assert_eq!(panics(move || wcc(&mut c, "w2", 0, "usdc.near", 40_000_001, &q2)), "E_WITHDRAW_CAP");
}

/// v1.4.7: no default USD withdraw cap (was $1,000). A fresh account withdraws well over $1,000
/// in one UTC day; a cap the owner sets still enforces.
#[test]
fn v147_no_default_withdraw_cap_owner_cap_enforces() {
    // `usd` whole dollars of USDC, signed at $usd in / $(usd - 0.1) out
    let usdc = |usd: u128, n: &str| {
        signed(usd * 1_000_000, ACTIVE, |m| {
            m["originAsset"] = "nep141:usdc.near".into();
            m["depositAddress"] = ADDR.replace('e', n).into();
            with_usd(m, &usd.to_string(), &format!("{}.9", usd - 1));
        })
    };
    let mut c = intents_account();
    let d = c.get_withdraw_day();
    assert_eq!((d.cap_usd.0, d.cap_yocto.0), (u128::MAX, 5 * NEAR));
    device_ctx(ACTIVE);
    wcc(&mut c, "w1", 0, "usdc.near", 900_000_000, &usdc(900, "1"));
    wcc(&mut c, "w2", 0, "usdc.near", 5_000_000_000_000, &usdc(5_000_000, "2"));
    assert_eq!(c.get_withdraw_day().spent_usd.0, 5_000_900_000_000, "$5,000,900 in one day, no cap");
    // the owner opts in to $1,000: $900 passes, $100.000001 more does not
    let mut c = intents_account();
    owner_ctx(T0);
    c.owner_set_withdraw_cap(None, Some(U128(1_000_000_000)));
    assert_eq!(c.get_withdraw_day().cap_usd.0, 1_000_000_000);
    device_ctx(ACTIVE);
    wcc(&mut c, "w1", 0, "usdc.near", 900_000_000, &usdc(900, "1"));
    let q = signed(100_000_001, ACTIVE, |m| {
        m["originAsset"] = "nep141:usdc.near".into();
        m["depositAddress"] = ADDR.replace('e', "3").into();
        with_usd(m, "100.000001", "100");
    });
    device_ctx(ACTIVE);
    assert_eq!(panics(move || wcc(&mut c, "w2", 0, "usdc.near", 100_000_001, &q)), "E_WITHDRAW_CAP");
}

#[test]
fn b1_m1_usd_settle_returns_unused() {
    let mut c = intents_account();
    device_ctx(ACTIVE);
    wcc(&mut c, "w1", 0, "wrap.near", NEAR, &signed(NEAR, ACTIVE, |m| with_usd(m, "5", "4.99")));
    let d = c.get_withdraw_day();
    assert_eq!(d.spent_usd.0, 5_000_000);
    // settle: nothing used -> USD back; wNEAR back; gas stays
    testing_env!(
        VMContextBuilder::new()
            .current_account_id(me())
            .predecessor_account_id(me())
            .signer_account_id(me())
            .storage_usage(STORAGE_BYTES)
            .account_balance(NearToken::from_yoctonear(10 * NEAR))
            .block_timestamp(ACTIVE + 5)
            .build(),
        near_sdk::test_vm_config(),
        near_sdk::RuntimeFeesConfig::test(),
        Default::default(),
        vec![ok_json(NEAR / 4)],
    );
    c.on_intents_sent(
        "w1".into(),
        Some(0),
        a("wrap.near"),
        U128(NEAR),
        U128(NEAR),
        U64(d.start_ns.0),
        ADDR.into(),
        Some(U128(5_000_000)),
    );
    let d2 = c.get_withdraw_day();
    assert_eq!(d2.spent_usd.0, 1_250_000);
    assert_eq!(d2.spent_yocto.0, NEAR / 4 + (300 * TGAS) as u128 * GAS_PRICE_BOUND);
}

#[test]
fn b2_h2_btc_canonical_asset() {
    let signed_btc = "1cs_v1:btc:native:coin";
    assert_eq!(ix::canon_asset("nep141:btc.omft.near"), signed_btc);
    assert_eq!(ix::canon_asset(signed_btc), signed_btc);
    assert_eq!(ix::canon_asset(SOL), SOL);
    // the recorded BTC withdraw quote: 1Click signed the 1cs_v1 form (manager key verifies)
    ctx("tt.near", 0, NEAR, T0);
    let v = vectors().into_iter().find(|v| v.name == "b2-wd-BTC-btc").unwrap();
    assert_eq!(ix::verify_quote_sig(&v.signed_quote, &v.signature, &manager()), Ok(()));
    let rec = obj(&v.signed_quote);
    assert_eq!(rec["destinationAsset"], signed_btc);
    // a destination registered in EITHER form matches it
    for asset in ["nep141:btc.omft.near", signed_btc] {
        let dest = Dest {
            label: "btc".into(),
            asset: asset.into(),
            recipient: rec["recipient"].as_str().unwrap().into(),
            recipient_type: "DESTINATION_CHAIN".into(),
            active_at_ns: U64(0),
        };
        assert_eq!(ix::check_dest(&dest), Ok(()));
        let mut m = synthetic(NEAR, T0 + 3_600 * NS_PER_SEC);
        m["destinationAsset"] = signed_btc.into();
        m["recipient"] = rec["recipient"].clone();
        assert!(check(&m, &expect(&dest, NEAR, T0)).is_ok(), "{asset}");
        // other assets still mismatch
        m["destinationAsset"] = "nep141:nbtc.bridge.near".into();
        assert_eq!(check(&m, &expect(&dest, NEAR, T0)), Err("E_QUOTE_MISMATCH"));
    }
    // other 1cs_v1 ids register and compare verbatim
    let zec = "1cs_v1:sol:spl:A7bdiYdS5GjqGFtxf17";
    let dest = Dest { asset: zec.into(), ..sol_dest(0) };
    assert_eq!(ix::check_dest(&dest), Ok(()));
    let mut m = synthetic(NEAR, T0 + 3_600 * NS_PER_SEC);
    m["destinationAsset"] = zec.into();
    assert!(check(&m, &expect(&dest, NEAR, T0)).is_ok());
}

#[test]
fn b1_l3_replay_markers_pruned_and_bounded() {
    let mut c = intents_account();
    owner_ctx(T0);
    c.owner_set_withdraw_cap(Some(U128(u128::MAX)), Some(U128(u128::MAX)));
    let deadline = |now: u64| now + 2 * 3_600 * NS_PER_SEC;
    let addr_n = |n: usize| format!("{n:064x}");
    let usdc = |n: usize, now: u64| {
        let mut m = synthetic(1, deadline(now));
        m["timestamp"] = fmt_iso(now).into();
        m["originAsset"] = "nep141:usdc.near".into();
        m["depositAddress"] = addr_n(n).into();
        let s = stable(&Value::Object(m));
        let sig = sign(&test_sk(), &s);
        (s, sig)
    };
    for n in 0..ix::MAX_USED_QUOTES {
        big_ctx(me().as_str(), ACTIVE);
        wcc(&mut c, &format!("w{n}"), 0, "usdc.near", 1, &usdc(n, ACTIVE));
    }
    assert!(c.is_deposit_address_used(addr_n(0)));
    big_ctx(me().as_str(), ACTIVE + 1);
    let q = usdc(1000, ACTIVE);
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| wcc(&mut c, "full", 0, "usdc.near", 1, &q))),
        "E_QUOTES_FULL"
    );
    // after deadline + margin every marker is pruned: one entry left after the next withdraw
    let later = deadline(ACTIVE) + ix::USED_QUOTE_MARGIN_NS + 1;
    big_ctx(me().as_str(), later);
    assert!(!c.is_deposit_address_used(addr_n(0)));
    wcc(&mut c, "after", 0, "usdc.near", 1, &usdc(2000, later));
    assert_eq!(ix::used_quotes().len(), 1);
    // replay within the window is still refused
    big_ctx(me().as_str(), later + 1);
    let q = usdc(2000, later);
    assert_eq!(panics(move || wcc(&mut c, "again", 0, "usdc.near", 1, &q)), "E_QUOTE_REPLAY");
}

#[test]
fn b1_i2_owner_path_marks_address() {
    let mut c = intents_account();
    owner_ctx(ACTIVE);
    c.owner_withdraw_via_intents(a("usdc.near"), U128(5), ADDR.into());
    assert!(c.is_deposit_address_used(ADDR.into()));
    device_ctx(ACTIVE);
    let q = signed(NEAR, ACTIVE, |_| {});
    assert_eq!(panics(move || wcc(&mut c, "w", 0, "wrap.near", NEAR, &q)), "E_QUOTE_REPLAY");
}

#[test]
fn b1_i1_i3_events_and_strictness() {
    let mut c = intents_account();
    owner_ctx(T0);
    c.owner_add_withdraw_destination(
        "e\"th".into(),
        "nep141:eth.omft.near".into(),
        "0xabc".into(),
        "DESTINATION_CHAIN".into(),
    );
    let log = get_logs().pop().unwrap();
    let v: Value = serde_json::from_str(log.strip_prefix("EVENT_JSON:").unwrap()).unwrap();
    assert_eq!(v["data"]["asset"], "nep141:eth.omft.near");
    assert_eq!(v["data"]["recipient"], "0xabc");
    assert_eq!(v["data"]["label"], "e\"th");
    device_ctx(T0);
    c.remove_withdraw_destination(1);
    assert!(get_logs().pop().unwrap().contains("\"by\":\"device\""));
    for bad in ["0x\"abc", "0x\\abc"] {
        let mut c2 = intents_account();
        owner_ctx(T0);
        let b = bad.to_string();
        assert_eq!(
            panics(move || {
                c2.owner_add_withdraw_destination("x".into(), SOL.into(), b, "DESTINATION_CHAIN".into());
            }),
            "E_BAD_DEST"
        );
    }
    let dest = sol_dest(0);
    for bad in ["+5", "007", "0"] {
        let mut m = synthetic(NEAR, T0 + 3_600 * NS_PER_SEC);
        m["minAmountOut"] = bad.into();
        assert_eq!(check(&m, &expect(&dest, NEAR, T0)), Err("E_QUOTE_MISMATCH"), "{bad}");
    }
}

#[test]
fn b1_l1_existing_key_is_replaced() {
    let mut c = new_account();
    owner_ctx(T0);
    let pk: near_sdk::PublicKey = "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp".parse().unwrap();
    c.owner_add_key(pk.clone(), KeyKind::FunctionCall);
    // AddKey failed (key exists) -> one batch DeleteKey + AddKey(DEVICE_METHODS)
    testing_env!(
        VMContextBuilder::new()
            .current_account_id(me())
            .predecessor_account_id(me())
            .signer_account_id(me())
            .build(),
        near_sdk::test_vm_config(),
        near_sdk::RuntimeFeesConfig::test(),
        Default::default(),
        vec![PromiseResult::Failed],
    );
    c.on_key_added(pk.clone());
    let rs = get_created_receipts();
    let acts: Vec<String> = rs[0].actions.iter().map(|x| format!("{x:?}")).collect();
    assert_eq!(rs[0].receiver_id, me());
    assert!(acts[0].starts_with("DeleteKey"), "{acts:?}");
    assert!(
        acts[1].starts_with("AddKeyWithFunctionCall") && acts[1].contains("withdraw_from_intents"),
        "{acts:?}"
    );
    assert_eq!(rs.len(), 2, "+ on_key_replaced");
    // success path: event, no replacement
    testing_env!(
        VMContextBuilder::new()
            .current_account_id(me())
            .predecessor_account_id(me())
            .signer_account_id(me())
            .build(),
        near_sdk::test_vm_config(),
        near_sdk::RuntimeFeesConfig::test(),
        Default::default(),
        vec![PromiseResult::Successful(vec![])],
    );
    c.on_key_added(pk.clone());
    assert!(get_created_receipts().is_empty());
    assert!(get_logs()[0].contains("\"replaced\":false,\"ok\":true"));
    // the automation key can't be turned into a device key
    let mut c2 = new_account();
    testing_env!(
        VMContextBuilder::new()
            .current_account_id(me())
            .predecessor_account_id(me())
            .signer_account_id(me())
            .build(),
        near_sdk::test_vm_config(),
        near_sdk::RuntimeFeesConfig::test(),
        Default::default(),
        vec![PromiseResult::Successful(vec![])],
    );
    c2.on_automation_set(pk.clone(), None, None);
    owner_ctx(T0);
    assert_eq!(panics(move || c2.owner_add_key(pk, KeyKind::FunctionCall)), "E_AUTOMATION_KEY");
}

#[test]
fn b1_l2_withdraw_from_intents_to_self_only() {
    let mut c = intents_account();
    device_ctx(ACTIVE);
    c.withdraw_from_intents(a("wrap.near"), U128(NEAR));
    let rs = get_created_receipts();
    assert_eq!(rs.len(), 1);
    assert_eq!(rs[0].receiver_id, a("intents.near"));
    match &rs[0].actions[0] {
        MockAction::FunctionCallWeight { method_name, args, attached_deposit, .. } => {
            assert_eq!(method_name, b"ft_withdraw");
            assert_eq!(attached_deposit.as_yoctonear(), 1);
            let v: Value = serde_json::from_slice(args).unwrap();
            assert_eq!(
                v,
                serde_json::json!({"token": "wrap.near", "receiver_id": me().to_string(), "amount": NEAR.to_string()})
            );
        }
        x => panic!("{x:?}"),
    }
    assert_eq!(c.get_withdraw_day().spent_yocto.0, (300 * TGAS) as u128 * GAS_PRICE_BOUND, "gas counted");
    owner_ctx(ACTIVE);
    c.owner_withdraw_from_intents(a("usdc.near"), U128(7));
    let mut c2 = intents_account();
    ctx("stranger.near", 1, NEAR, ACTIVE);
    assert_eq!(panics(move || c2.owner_withdraw_from_intents(a("usdc.near"), U128(7))), "E_NOT_OWNER");
    let mut c3 = intents_account();
    device_ctx(ACTIVE);
    assert_eq!(panics(move || c3.withdraw_from_intents(me(), U128(7))), "E_BAD_OP");
}

// ======================= v1.4.2: re-audit C1 =======================

/// C1-L2: signed issue time must be fresh (<= 1 h old, <= 5 min ahead): E_QUOTE_DEADLINE.
#[test]
fn c1_l2_quote_freshness() {
    let dest = sol_dest(0);
    let now = T0;
    let e = expect(&dest, NEAR, now);
    let at = |ts: u64| {
        let mut m = synthetic(NEAR, now + 3_600 * NS_PER_SEC);
        m["timestamp"] = fmt_iso(ts).into();
        check(&m, &e)
    };
    assert!(at(now).is_ok());
    assert!(at(now - ix::MAX_QUOTE_AGE_NS).is_ok(), "exactly 1 h old");
    assert_eq!(at(now - ix::MAX_QUOTE_AGE_NS - 1_000_000), Err("E_QUOTE_DEADLINE"));
    assert!(at(now + ix::QUOTE_FUTURE_SKEW_NS).is_ok());
    assert_eq!(at(now + ix::QUOTE_FUTURE_SKEW_NS + 1_000_000), Err("E_QUOTE_DEADLINE"));
    let mut m = synthetic(NEAR, now + 3_600 * NS_PER_SEC);
    m["timestamp"] = "yesterday".into();
    assert_eq!(check(&m, &e), Err("E_QUOTE_MISMATCH"));
    // the live vectors' long signed deadline (+72 h) is fine; only the issue time is bounded
    let mut m = synthetic(NEAR, now + 73 * 3_600 * NS_PER_SEC);
    m["timestamp"] = fmt_iso(now).into();
    assert!(check(&m, &e).is_ok());
}

/// C1-L2: 128 live device markers no longer block the owner path; markers live ~2 h.
#[test]
fn c1_l2_owner_path_not_blocked_by_device_markers() {
    let mut c = intents_account();
    owner_ctx(T0);
    c.owner_set_withdraw_cap(Some(U128(u128::MAX)), Some(U128(u128::MAX)));
    let addr_n = |n: usize| format!("{n:064x}");
    for n in 0..ix::MAX_USED_QUOTES {
        big_ctx(me().as_str(), ACTIVE);
        let mut m = synthetic(1, ACTIVE + 73 * 3_600 * NS_PER_SEC);
        m["timestamp"] = fmt_iso(ACTIVE).into();
        m["originAsset"] = "nep141:usdc.near".into();
        m["depositAddress"] = addr_n(n).into();
        let s = stable(&Value::Object(m));
        let sig = sign(&test_sk(), &s);
        wcc(&mut c, &format!("w{n}"), 0, "usdc.near", 1, &(s, sig));
    }
    // device full
    big_ctx(me().as_str(), ACTIVE + 1);
    let q = {
        let mut m = synthetic(1, ACTIVE + 3_600 * NS_PER_SEC);
        m["originAsset"] = "nep141:usdc.near".into();
        m["depositAddress"] = addr_n(999).into();
        let s = stable(&Value::Object(m));
        let sig = sign(&test_sk(), &s);
        (s, sig)
    };
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| wcc(&mut c, "full", 0, "usdc.near", 1, &q))),
        "E_QUOTES_FULL"
    );
    // owner path unaffected
    ctx("owner.near", 1, 100 * NEAR, ACTIVE + 2);
    c.owner_withdraw_via_intents(a("usdc.near"), U128(5), addr_n(5000));
    // markers expire issue time + 1 h + 1 h margin (not deadline + 1 h, 73 h later)
    let later = ACTIVE + ix::MAX_QUOTE_AGE_NS + ix::USED_QUOTE_MARGIN_NS + 1;
    big_ctx(me().as_str(), later);
    assert!(!c.is_deposit_address_used(addr_n(0)));
    // the owner-funded address is still refused to the device path (B1-I2)
    assert!(c.is_deposit_address_used(addr_n(5000)));
}

/// v1.4.5 (INV-58, SC-6): `execute` and `withdraw_cross_chain` share the `seen_orders` id
/// namespace (a client_order_id used by one path is a duplicate for the other, both ways) and its
/// 256-entry bound (entries from either path fill it for both).
#[test]
fn inv58_execute_and_withdraw_share_seen_orders() {
    let quote = |i: u8, now: u64| {
        signed(NEAR, now, move |m| {
            m["depositAddress"] = Value::from(format!("{:02x}", i).repeat(32));
        })
    };
    // execute id, then the same id on the withdraw path; and the reverse
    let mut c = intents_account();
    c.caps = caps(NEAR, 1_000 * NEAR);
    device_ctx(ACTIVE);
    exec(&mut c, buy(1_000), "shared-1", NEAR);
    device_ctx(ACTIVE);
    let q = quote(1, ACTIVE);
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| wcc(&mut c, "shared-1", 0, "wrap.near", NEAR, &q))),
        "E_DUPLICATE"
    );
    device_ctx(ACTIVE);
    wcc(&mut c, "shared-2", 0, "wrap.near", NEAR, &quote(2, ACTIVE));
    device_ctx(ACTIVE);
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| exec(&mut c, buy(1_000), "shared-2", NEAR))),
        "E_DUPLICATE"
    );
    // the bound: fill to 255 with executes + 1 withdrawal = 256; then both paths are full
    for i in 2..MAX_SEEN_ORDERS - 1 {
        device_ctx(ACTIVE);
        exec(&mut c, buy(1_000), &format!("e{i}"), NEAR);
    }
    assert_eq!(c.seen_orders.0.len(), MAX_SEEN_ORDERS - 1);
    device_ctx(ACTIVE);
    wcc(&mut c, "w-last", 0, "wrap.near", NEAR, &quote(3, ACTIVE));
    assert_eq!(c.seen_orders.0.len(), MAX_SEEN_ORDERS);
    device_ctx(ACTIVE);
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| exec(&mut c, buy(1_000), "e-full", NEAR))),
        "E_ORDERS_FULL"
    );
    device_ctx(ACTIVE);
    let q = quote(4, ACTIVE);
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| wcc(&mut c, "w-full", 0, "wrap.near", NEAR, &q))),
        "E_ORDERS_FULL"
    );
}
