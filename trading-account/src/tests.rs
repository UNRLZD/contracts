//! Unit + property tests (native, mocked blockchain). Sandbox tests live in contracts/tests.
use super::msg::{self, Ctx, DexKind, Swap};
use super::policy::*;
use super::*;
use near_sdk::mock::MockAction;
use near_sdk::test_utils::{get_created_receipts, get_logs, VMContextBuilder};
use near_sdk::testing_env;
use near_sdk::PromiseResult;
use proptest::prelude::*;

const NEAR: u128 = 1_000_000_000_000_000_000_000_000;
const T0: u64 = 1_800_000_000_000_000_000;
/// v1.4.1 (D5): 00:00 UTC of T0's day (the daily window start).
const D0: u64 = T0 - T0 % (86_400 * 1_000_000_000);
/// Mocked storage usage; LOCKED yocto of the balance is storage stake (not liquid).
const STORAGE_BYTES: u64 = 1_000;
const LOCKED: u128 = STORAGE_BYTES as u128 * 10_000_000_000_000_000_000;
/// v1.2.1: the daily gas tally record ("gd" + 24 bytes + 40 per record) locks this much.
const GD_LOCK: u128 = (2 + 24 + 40) * 10_000_000_000_000_000_000;

fn a(s: &str) -> AccountId {
    s.parse().unwrap()
}

// ======================= msg parsers: real router fixtures =======================

#[derive(near_sdk::serde::Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct Fixture {
    name: String,
    /// RheaClassic | RheaDcl | Plach (ft_transfer_call msg) | PlachNear (deposit_near operations)
    kind: String,
    token: String,
    msg: String,
    expect_min_out: String,
    out_is_near: bool,
}

fn kind_of(k: &str) -> Option<DexKind> {
    match k {
        "RheaClassic" => Some(DexKind::RheaClassic),
        "RheaDcl" => Some(DexKind::RheaDcl),
        "Plach" => Some(DexKind::Plach),
        _ => None,
    }
}

/// The referrer/referral_id a captured router msg names (router default: intear's).
fn referrer_of(msg: &str) -> AccountId {
    let v: near_sdk::serde_json::Value = near_sdk::serde_json::from_str(msg).unwrap_or_default();
    let r = v.get("referral_id").or(v.get("referrer")).or(v.get("Swap").and_then(|s| s.get("referral_id")));
    a(r.and_then(|x| x.as_str()).unwrap_or("none.near"))
}

fn parse_fixture(f: &Fixture, m: &str, me: &AccountId) -> Result<Swap, &'static str> {
    let r = referrer_of(&f.msg);
    match kind_of(&f.kind) {
        Some(k) => {
            let (wrap, t) = (a("wrap.near"), a(&f.token));
            msg::parse(k, m, &Ctx { self_id: me, wrap: &wrap, token_in: &t, referrer: &r })
        }
        None => msg::parse_plach_near(m, me, &a("wrap.near"), &r),
    }
}

fn fixtures() -> Vec<Fixture> {
    near_sdk::serde_json::from_str(include_str!("../tests/fixtures/router_msgs.json")).unwrap()
}

#[test]
fn real_router_msgs_parse_to_router_worst_case() {
    let fx = fixtures();
    assert!(fx.len() >= 20);
    let me = a("aaaa.near");
    let mut kinds = std::collections::BTreeMap::new();
    for f in &fx {
        let s = parse_fixture(f, &f.msg, &me).unwrap_or_else(|e| panic!("{}: {e}", f.name));
        assert_eq!(s.min_out.to_string(), f.expect_min_out, "{}", f.name);
        assert_eq!(s.out_is_near, f.out_is_near, "{}", f.name);
        *kinds.entry(f.kind.clone()).or_insert(0) += 1;
    }
    assert_eq!(kinds.len(), 4, "every DEX kind + Plach deposit_near covered: {kinds:?}");
}

#[test]
fn real_msgs_rejected_by_wrong_dex_parser() {
    let (me, wrap) = (a("aaaa.near"), a("wrap.near"));
    for f in fixtures() {
        let t = if f.token == "near" { a("wrap.near") } else { a(&f.token) };
        for k in [DexKind::RheaClassic, DexKind::RheaDcl] {
            if Some(k) != kind_of(&f.kind) {
                let rf = referrer_of(&f.msg);
                let r =
                    msg::parse(k, &f.msg, &Ctx { self_id: &me, wrap: &wrap, token_in: &t, referrer: &rf });
                assert_eq!(r, Err("E_BAD_MSG"), "{} as {k:?}", f.name);
            }
        }
        if !f.kind.starts_with("Plach") {
            assert_eq!(
                msg::parse_plach_near(&f.msg, &me, &a("wrap.near"), &referrer_of(&f.msg)),
                Err("E_BAD_MSG"),
                "{}",
                f.name
            );
        }
    }
}

#[test]
fn plach_near_buy_rules() {
    let me = a("me.near");
    let buy = |ops: &str| format!(r#"{{"operations":[{ops}],"referrer":"r.near"}}"#);
    let sw = r#"{"SwapSimple":{"dex_id":"d/xyk","message":"AA==","asset_in":"near","asset_out":"nep141:m.near","amount":{"Amount":{"ExactIn":"10"}},"constraint":"7"}}"#;
    let wd = |to: &str, at: &str| {
        format!(
            r#"{{"Withdraw":{{"asset_id":"nep141:m.near","amount":{{"Full":{{"at_least":{at}}}}},"to":{to},"rescue_address":null}}}}"#
        )
    };
    assert_eq!(
        msg::parse_plach_near(
            &buy(&[sw, &wd("null", r#""7""#)].join(",")),
            &me,
            &a("wrap.near"),
            &a("r.near")
        ),
        Ok(Swap { out_is_near: false, min_out: 7, out: "m.near".into() })
    );
    assert_eq!(
        msg::parse_plach_near(
            &buy(&[sw, &wd(r#""evil.near""#, r#""7""#)].join(",")),
            &me,
            &a("wrap.near"),
            &a("r.near")
        ),
        Err("E_RECIPIENT")
    );
    assert_eq!(msg::parse_plach_near(&buy(sw), &me, &a("wrap.near"), &a("r.near")), Err("E_BAD_MSG")); // output never withdrawn
    let sw0 = sw.replace(r#""constraint":"7""#, r#""constraint":null"#);
    assert_eq!(
        msg::parse_plach_near(
            &buy(&[sw0.as_str(), &wd("null", "null")].join(",")),
            &me,
            &a("wrap.near"),
            &a("r.near")
        ),
        Err("E_MIN_OUT")
    );
    let cyc = sw.replace("nep141:m.near", "near");
    assert_eq!(msg::parse_plach_near(&buy(&cyc), &me, &a("wrap.near"), &a("r.near")), Err("E_BAD_MSG"));
    // untagged bare-array DepositMessage form is not accepted (router never sends it)
    assert_eq!(
        msg::parse_plach_near(&format!("[{sw}]"), &me, &a("wrap.near"), &a("r.near")),
        Err("E_BAD_MSG")
    );
    // trailing garbage after the object is rejected (msg is spliced raw into args)
    let ok = buy(&[sw, &wd("null", r#""7""#)].join(","));
    assert_eq!(
        msg::parse_plach_near(&format!(r#"{ok},"x":1"#), &me, &a("wrap.near"), &a("r.near")),
        Err("E_BAD_MSG")
    );
}

fn ctx_parse(kind: DexKind, m: &str, token: &str) -> Result<Swap, &'static str> {
    let (me, wrap, t) = (a("me.near"), a("wrap.near"), a(token));
    msg::parse(kind, m, &Ctx { self_id: &me, wrap: &wrap, token_in: &t, referrer: &a("r.near") })
}

const RHEA_SELL: &str = r#"{"force":0,"actions":[{"pool_id":1,"token_in":"x.near","token_out":"y.near","amount_in":"10","amount_out":"0","min_amount_out":"0"},{"pool_id":2,"token_in":"y.near","token_out":"wrap.near","amount_out":"0","min_amount_out":"7"},{"pool_id":3,"token_in":"x.near","token_out":"wrap.near","amount_in":"5","min_amount_out":"3"}],"skip_unwrap_near":false,"referral_id":"r.near"}"#;

#[test]
fn rhea_sums_final_token_outputs() {
    assert_eq!(
        ctx_parse(DexKind::RheaClassic, RHEA_SELL, "x.near"),
        Ok(Swap { out_is_near: true, min_out: 10, out: "wrap.near".into() })
    );
}

#[test]
fn rhea_rejections() {
    let k = DexKind::RheaClassic;
    let one = |extra: &str, act_extra: &str, min: &str, tin: &str, tout: &str| {
        format!(
            r#"{{"actions":[{{"pool_id":1,"token_in":"{tin}","token_out":"{tout}","min_amount_out":"{min}"{act_extra}}}]{extra}}}"#
        )
    };
    assert!(ctx_parse(k, &one("", "", "5", "x.near", "wrap.near",), "x.near").is_ok());
    // unknown top-level / action fields
    assert_eq!(
        ctx_parse(k, &one(r#","client_echo":"x""#, "", "5", "x.near", "wrap.near"), "x.near"),
        Err("E_BAD_MSG")
    );
    assert_eq!(
        ctx_parse(k, &one("", r#","max_amount_in":"5""#, "5", "x.near", "wrap.near"), "x.near"),
        Err("E_BAD_MSG")
    );
    // output recipient must be self
    assert_eq!(
        ctx_parse(k, &one(r#","swap_out_recipient":"evil.near""#, "", "5", "x.near", "wrap.near"), "x.near"),
        Err("E_RECIPIENT")
    );
    assert!(ctx_parse(
        k,
        &one(r#","swap_out_recipient":"me.near""#, "", "5", "x.near", "wrap.near"),
        "x.near"
    )
    .is_ok());
    // min_out 0
    assert_eq!(ctx_parse(k, &one("", "", "0", "x.near", "wrap.near"), "x.near"), Err("E_MIN_OUT"));
    // swap-by-output amount_out != 0
    assert_eq!(
        ctx_parse(k, &one("", r#","amount_out":"9""#, "5", "x.near", "wrap.near"), "x.near"),
        Err("E_BAD_MSG")
    );
    // output == input token (cycle)
    assert_eq!(ctx_parse(k, &one("", "", "5", "x.near", "x.near"), "x.near"), Err("E_BAD_MSG"));
    assert_eq!(ctx_parse(k, &one("", "", "5", "wrap.near", "y.near"), "y.near"), Err("E_BAD_MSG"));
    // empty actions, malformed, duplicate key, number instead of string
    assert_eq!(ctx_parse(k, r#"{"actions":[]}"#, "x.near"), Err("E_BAD_MSG"));
    assert_eq!(ctx_parse(k, "{", "x.near"), Err("E_BAD_MSG"));
    assert_eq!(ctx_parse(k, "", "x.near"), Err("E_BAD_MSG"));
    assert_eq!(
        ctx_parse(
            k,
            r#"{"actions":[{"pool_id":1,"token_in":"x.near","token_out":"wrap.near","min_amount_out":"5","min_amount_out":"6"}]}"#,
            "x.near"
        ),
        Err("E_BAD_MSG")
    );
    assert_eq!(
        ctx_parse(
            k,
            r#"{"actions":[{"pool_id":1,"token_in":"x.near","token_out":"wrap.near","min_amount_out":5}]}"#,
            "x.near"
        ),
        Err("E_BAD_MSG")
    );
    // overflowing sum
    let max = u128::MAX;
    let m = format!(
        r#"{{"actions":[{{"pool_id":1,"token_in":"x.near","token_out":"wrap.near","min_amount_out":"{max}"}},{{"pool_id":2,"token_in":"x.near","token_out":"wrap.near","min_amount_out":"1"}}]}}"#
    );
    assert_eq!(ctx_parse(k, &m, "x.near"), Err("E_BAD_MSG"));
    // final token consumed by a later hop
    let m = r#"{"actions":[{"pool_id":1,"token_in":"x.near","token_out":"y.near","min_amount_out":"5"},{"pool_id":2,"token_in":"y.near","token_out":"z.near","min_amount_out":"0"},{"pool_id":3,"token_in":"z.near","token_out":"y.near","min_amount_out":"1"}]}"#;
    assert_eq!(ctx_parse(k, m, "x.near"), Err("E_BAD_MSG"));
}

#[test]
fn dcl_cases() {
    let k = DexKind::RheaDcl;
    let ok = r#"{"Swap":{"pool_ids":["a|b|100"],"output_token":"wrap.near","min_output_amount":"42","skip_unwrap_near":false}}"#;
    assert_eq!(
        ctx_parse(k, ok, "x.near"),
        Ok(Swap { out_is_near: true, min_out: 42, out: "wrap.near".into() })
    );
    let buy = r#"{"Swap":{"pool_ids":["a"],"output_token":"x.near","min_output_amount":"42","referral_id":"r.near","client_id":"c"}}"#;
    assert_eq!(
        ctx_parse(k, buy, "wrap.near"),
        Ok(Swap { out_is_near: false, min_out: 42, out: "x.near".into() })
    );
    for bad in [
        r#"{"SwapByOutput":{"pool_ids":["a"],"output_token":"wrap.near","output_amount":"5"}}"#,
        r#"{"Swap":{"pool_ids":[],"output_token":"wrap.near","min_output_amount":"42"}}"#,
        r#"{"Swap":{"pool_ids":["a"],"output_token":"wrap.near","min_output_amount":"42","recipient":"evil.near"}}"#,
        r#"{"Swap":{"pool_ids":["a"],"output_token":"x.near","min_output_amount":"42"}}"#, // output == input
        r#"{"Swap":{"pool_ids":["a"],"output_token":"wrap.near"}}"#,
        r#"{"LimitOrder":{}}"#,
    ] {
        assert_eq!(ctx_parse(k, bad, "x.near"), Err("E_BAD_MSG"), "{bad}");
    }
    let zero = r#"{"Swap":{"pool_ids":["a"],"output_token":"wrap.near","min_output_amount":"0"}}"#;
    assert_eq!(ctx_parse(k, zero, "x.near"), Err("E_MIN_OUT"));
}

fn plach(ops: &str) -> String {
    format!(r#"{{"operations":[{ops}],"referrer":"r.near"}}"#)
}
const P_SWAP: &str = r#"{"SwapSimple":{"dex_id":"d/xyk","message":"AA==","asset_in":"nep141:x.near","asset_out":"near","amount":{"Amount":{"ExactIn":"10"}},"constraint":"7"}}"#;

#[test]
fn plach_cases() {
    let k = DexKind::Plach;
    let w = |amount: &str, extra: &str| {
        format!(
            r#"{{"Withdraw":{{"asset_id":"near","amount":{amount},"to":null,"rescue_address":null{extra}}}}}"#
        )
    };
    let full = w(r#"{"Full":{"at_least":"5"}}"#, "");
    assert_eq!(
        ctx_parse(k, &plach(&[P_SWAP, &full].join(",")), "x.near"),
        Ok(Swap { out_is_near: true, min_out: 7, out: "wrap.near".into() })
    );
    let full9 = w(r#"{"Full":{"at_least":"9"}}"#, "");
    assert_eq!(ctx_parse(k, &plach(&[P_SWAP, &full9].join(",")), "x.near").unwrap().min_out, 9);
    let exact = w(r#"{"Exact":"3"}"#, "");
    assert_eq!(ctx_parse(k, &plach(&[P_SWAP, &exact].join(",")), "x.near").unwrap().min_out, 3);
    // no withdraw of output -> tokens would stay on the DEX
    assert_eq!(ctx_parse(k, &plach(P_SWAP), "x.near"), Err("E_BAD_MSG"));
    // recipients
    let to_evil = w(r#"{"Full":{"at_least":"5"}}"#, "").replace(r#""to":null"#, r#""to":"evil.near""#);
    assert_eq!(ctx_parse(k, &plach(&[P_SWAP, &to_evil].join(",")), "x.near"), Err("E_RECIPIENT"));
    let rescue_evil = full.replace(r#""rescue_address":null"#, r#""rescue_address":"evil.near""#);
    assert_eq!(ctx_parse(k, &plach(&[P_SWAP, &rescue_evil].join(",")), "x.near"), Err("E_RECIPIENT"));
    let to_me = full.replace(r#""to":null"#, r#""to":"me.near""#);
    assert!(ctx_parse(k, &plach(&[P_SWAP, &to_me].join(",")), "x.near").is_ok());
    // other op types, PreviousSwapOutput, double withdraw, unknown fields
    for bad in [
        plach(
            &[
                P_SWAP,
                &full,
                r#"{"TransferAsset":{"to":{"Account":"evil.near"},"asset_id":"near","amount":"1"}}"#,
            ]
            .join(","),
        ),
        plach(
            &[P_SWAP, &full, r#"{"DexCall":{"dex_id":"d","method":"m","args":"","attached_assets":{}}}"#]
                .join(","),
        ),
        plach(&[P_SWAP, &w(r#""PreviousSwapOutput""#, "")].join(",")),
        plach(&[P_SWAP, &full, &full].join(",")),
        plach(&[P_SWAP, &w(r#"{"Full":{"at_least":"5"}}"#, r#","extra":1"#)].join(",")),
        r#"{"operations":[],"referrer":null}"#.to_string(),
        format!(r#"{{"operations":[{P_SWAP},{full}],"evil":1}}"#),
    ] {
        assert_eq!(ctx_parse(k, &bad, "x.near"), Err("E_BAD_MSG"), "{bad}");
    }
    // zero guarantee
    let none = w(r#"{"Full":{"at_least":null}}"#, "");
    let s0 = P_SWAP.replace(r#""constraint":"7""#, r#""constraint":null"#);
    assert_eq!(ctx_parse(k, &plach(&[s0.as_str(), &none].join(",")), "x.near"), Err("E_MIN_OUT"));
    // wrap asset counts as NEAR; ExactOut guarantees its amount
    let s_wrap = P_SWAP
        .replace(r#""asset_out":"near""#, r#""asset_out":"nep141:wrap.near""#)
        .replace(r#"{"ExactIn":"10"}"#, r#"{"ExactOut":"11"}"#);
    let w_wrap = none.replace(r#""asset_id":"near""#, r#""asset_id":"nep141:wrap.near""#);
    assert_eq!(
        ctx_parse(k, &plach(&[s_wrap.as_str(), &w_wrap].join(",")), "x.near"),
        Ok(Swap { out_is_near: true, min_out: 11, out: "wrap.near".into() })
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3000))]
    #[test]
    fn parsers_never_panic_on_arbitrary_input(s in ".{0,400}", k in 0u8..4) {
        if k == 3 {
            let _ = msg::parse_plach_near(&s, &a("me.near"), &a("wrap.near"), &a("r.near"));
        } else {
            let kind = [DexKind::RheaClassic, DexKind::RheaDcl, DexKind::Plach][k as usize];
            let _ = ctx_parse(kind, &s, "x.near");
        }
    }

    #[test]
    fn parsers_never_panic_on_mutated_real_msgs(idx in 0usize..64, pos in any::<prop::sample::Index>(),
                                              byte in any::<u8>(), mode in 0u8..3) {
        let fx = fixtures();
        let f = &fx[idx % fx.len()];
        let mut b = f.msg.clone().into_bytes();
        let i = pos.index(b.len());
        match mode { 0 => b[i] = byte, 1 => { b.remove(i); }, _ => b.insert(i, byte) }
        if let Ok(m) = String::from_utf8(b) {
            if let Ok(s) = parse_fixture(f, &m, &a("aaaa.near")) {
                prop_assert!(s.min_out > 0);
            }
        }
    }

    #[test]
    fn rhea_recipient_never_other_than_self(r in "[a-z]{2,10}\\.near") {
        let m = format!(r#"{{"actions":[{{"pool_id":1,"token_in":"x.near","token_out":"wrap.near","min_amount_out":"5"}}],"swap_out_recipient":"{r}"}}"#);
        let res = ctx_parse(DexKind::RheaClassic, &m, "x.near");
        prop_assert_eq!(res.is_ok(), r == "me.near");
    }
}

// ======================= policy =======================

fn caps(t: u128, d: u128) -> Caps {
    Caps { max_trade_yocto: U128(t), daily_cap_yocto: U128(d) }
}

#[test]
fn expiry_bounds() {
    assert_eq!(check_expiry(100, 99), Err("E_EXPIRED"));
    assert_eq!(check_expiry(100, 100), Ok(()));
    assert_eq!(check_expiry(100, 100 + MAX_EXPIRY_AHEAD_NS), Ok(()));
    assert_eq!(check_expiry(100, 101 + MAX_EXPIRY_AHEAD_NS), Err("E_EXPIRY_TOO_FAR"));
    assert_eq!(check_expiry(u64::MAX - 1, u64::MAX), Ok(()));
}

#[test]
fn dedupe_and_eviction() {
    let mut s = SeenOrders::default();
    assert_eq!(s.insert("a".into(), 200, 100), Ok(()));
    assert_eq!(s.insert("a".into(), 250, 150), Err("E_DUPLICATE"));
    assert_eq!(s.insert("a".into(), 250, 200), Err("E_DUPLICATE")); // expiry inclusive
    assert!(s.contains("a", 200) && !s.contains("a", 201));
    assert_eq!(s.insert("".into(), 250, 100), Err("E_BAD_ORDER_ID"));
    assert_eq!(s.insert("x".repeat(65), 250, 100), Err("E_BAD_ORDER_ID"));
    assert_eq!(s.insert("x".repeat(64), 250, 100), Ok(()));
    // fill to capacity with unexpired entries -> reject
    let mut s = SeenOrders::default();
    for i in 0..MAX_SEEN_ORDERS {
        s.insert(format!("o{i}"), 1000, 10).unwrap();
    }
    assert_eq!(s.insert("new".into(), 1000, 10), Err("E_ORDERS_FULL"));
    // once they expire they are evicted and storage shrinks
    assert_eq!(s.insert("new".into(), 2000, 1001), Ok(()));
    assert_eq!(s.0.len(), 1);
}

#[test]
fn caps_trade_daily_and_rollover() {
    let c = caps(10, 25);
    let mut d = Day { start_ns: 0, spent_yocto: 0 };
    assert_eq!(check_caps(&mut d, &c, 1, 11, 11), Err("E_CAP_TRADE")); // max_in > cap
    assert_eq!(check_caps(&mut d, &c, 1, 6, 5), Err("E_CAP_TRADE")); // spend > max_in
    assert_eq!(check_caps(&mut d, &c, 1, 10, 10), Ok(()));
    assert_eq!(check_caps(&mut d, &c, 2, 10, 10), Ok(()));
    assert_eq!(check_caps(&mut d, &c, 3, 6, 10), Err("E_CAP_DAILY"));
    assert_eq!(d.spent_yocto, 20); // failed check does not commit
    assert_eq!(check_caps(&mut d, &c, 3, 5, 10), Ok(()));
    assert_eq!(check_caps(&mut d, &c, DAY_NS - 1, 1, 10), Err("E_CAP_DAILY"));
    assert_eq!(check_caps(&mut d, &c, DAY_NS, 10, 10), Ok(())); // window rolls at exactly +24h
    assert_eq!(d, Day { start_ns: DAY_NS, spent_yocto: 10 });
    let mut d = Day { start_ns: 0, spent_yocto: u128::MAX };
    assert_eq!(check_caps(&mut d, &caps(u128::MAX, u128::MAX), 1, 1, 1), Err("E_CAP_DAILY"));
}

#[test]
fn gas_reserve_lower() {
    let p = 300 * TGAS;
    assert_eq!(check_gas(4, 285 * TGAS, p), Ok(()));
    assert_eq!(check_gas(4, 285 * TGAS + 1, p), Err("E_GAS"));
    assert_eq!(check_gas(5, 1, p), Err("E_GAS"));
    assert_eq!(check_gas(1, 1, 10 * TGAS), Err("E_GAS"));
    assert_eq!(check_reserve(RESERVE + 5, 5), Ok(()));
    assert_eq!(check_reserve(RESERVE + 5, 6), Err("E_RESERVE"));
    assert_eq!(check_reserve(1, 2), Err("E_RESERVE"));
    assert_eq!(check_lower(&caps(10, 20), &caps(10, 20)), Ok(()));
    assert_eq!(check_lower(&caps(10, 20), &caps(5, 1)), Ok(()));
    assert_eq!(check_lower(&caps(10, 20), &caps(11, 1)), Err("E_CAP_RAISE"));
    assert_eq!(check_lower(&caps(10, 20), &caps(1, 21)), Err("E_CAP_RAISE"));
}

#[test]
fn mul_div_edges() {
    assert_eq!(mul_div(u128::MAX, u128::MAX, u128::MAX), u128::MAX);
    assert_eq!(mul_div(u128::MAX, 1, u128::MAX), 1);
    assert_eq!(mul_div(u128::MAX, u128::MAX - 1, u128::MAX), u128::MAX - 1);
    assert_eq!(mul_div(10u128.pow(22), 10u128.pow(32) / 3, 10u128.pow(32)), 10u128.pow(22) / 3);
    assert_eq!(mul_div(5, 0, 7), 0);
    assert_eq!(mul_div(5, 7, 0), 0);
}

#[test]
fn fee_math() {
    assert_eq!(bps(10_000, 100), 100);
    assert_eq!(bps(9_999, 100), 99); // floor
    assert_eq!(bps(99, 100), 0);
    assert_eq!(bps(NEAR, 30), NEAR * 30 / 10_000);
    assert_eq!(bps(u128::MAX, 100), u128::MAX / 100); // no overflow
    assert_eq!(bps(12345, 0), 0);
}

proptest! {
    #[test]
    fn bps_is_exact_floor(x in any::<u128>(), b in 0u16..=100) {
        let exact = x.checked_mul(b as u128).map(|p| p / 10_000);
        if let Some(e) = exact { prop_assert_eq!(bps(x, b), e); }
        prop_assert!(bps(x, b) <= x / 100);
    }

    #[test]
    fn mul_div_exact(a_ in any::<u128>(), b in any::<u128>(), c in 1u128..) {
        let (b, c) = if b <= c { (b, c) } else { (c, b) };
        let r = mul_div(a_, b, c);
        prop_assert!(r <= a_);
        if let Some(p) = a_.checked_mul(b) { prop_assert_eq!(r, p / c); }
        if b == c { prop_assert_eq!(r, a_); }
    }

    #[test]
    fn day_spent_never_exceeds_cap(steps in prop::collection::vec((0u64..(3 * DAY_NS / 2), 0u128..40), 1..60),
                                   t in 1u128..40, dcap in 1u128..100) {
        let c = caps(t, dcap);
        let mut d = Day { start_ns: 0, spent_yocto: 0 };
        let mut now = 0u64;
        for (dt, spend) in steps {
            now += dt;
            let before = d.clone();
            let r = check_caps(&mut d, &c, now, spend, spend);
            prop_assert!(d.spent_yocto <= dcap);
            if r.is_err() { prop_assert!(d.spent_yocto == before.spent_yocto || d.start_ns != before.start_ns); }
        }
    }

    #[test]
    fn seen_orders_bounded(ops in prop::collection::vec((0u16..300, 0u64..500), 1..800)) {
        let mut s = SeenOrders::default();
        let mut now = 0u64;
        for (id, dt) in ops {
            now += dt / 50;
            let exp = now + dt;
            let was = s.contains(&id.to_string(), now);
            let r = s.insert(id.to_string(), exp, now);
            if was { prop_assert_eq!(r, Err("E_DUPLICATE")); }
            prop_assert!(s.0.len() <= MAX_SEEN_ORDERS);
        }
    }
}

// ======================= contract (mocked env) =======================

fn me() -> AccountId {
    a("abcd.tt.near")
}

fn ctx(pred: &str, deposit: u128, balance: u128, now: u64) {
    testing_env!(VMContextBuilder::new()
        .current_account_id(me())
        .predecessor_account_id(a(pred))
        .signer_account_id(a(pred))
        .attached_deposit(NearToken::from_yoctonear(deposit))
        .account_balance(NearToken::from_yoctonear(balance))
        .block_timestamp(now)
        .storage_usage(STORAGE_BYTES)
        .prepaid_gas(Gas::from_tgas(300))
        .build());
}

fn new_account() -> TradingAccount {
    ctx("tt.near", 0, NEAR, T0);
    // fresh account: drop raw storage (v1.3 orders live outside the struct) from earlier cases
    near_sdk::mock::with_mocked_blockchain(|b| {
        b.take_storage();
    });
    ctx("tt.near", 0, NEAR, T0);
    TradingAccount::init(
        a("owner.near"),
        FeeConfig { fee_bps: 100, fee_recipient: a("fees.near") },
        caps(2 * NEAR, 5 * NEAR),
        vec![
            Dex { id: a("v2.ref-finance.near"), kind: DexKind::RheaClassic },
            Dex { id: a("dclv2.ref-labs.near"), kind: DexKind::RheaDcl },
            Dex { id: a("dex.intear.near"), kind: DexKind::Plach },
        ],
        a("wrap.near"),
        None,
    )
}

fn rhea_msg(tin: &str, tout: &str, min: u128) -> String {
    format!(
        r#"{{"force":0,"actions":[{{"pool_id":1,"token_in":"{tin}","token_out":"{tout}","amount_in":"1","amount_out":"0","min_amount_out":"{min}"}}],"skip_unwrap_near":true}}"#
    )
}

fn buy(amount: u128) -> Vec<Op> {
    vec![
        Op::NearDeposit { amount: U128(amount) },
        Op::FtTransferCall {
            token: a("wrap.near"),
            receiver_id: a("v2.ref-finance.near"),
            amount: U128(amount),
            msg: rhea_msg("wrap.near", "meme.near", 5),
            gas: U64(150 * TGAS),
        },
    ]
}

fn sell(min_out: u128) -> Vec<Op> {
    vec![Op::FtTransferCall {
        token: a("meme.near"),
        receiver_id: a("v2.ref-finance.near"),
        amount: U128(10u128.pow(30)),
        msg: rhea_msg("meme.near", "wrap.near", min_out),
        gas: U64(150 * TGAS),
    }]
}

fn exec(c: &mut TradingAccount, ops: Vec<Op>, id: &str, max_in: u128) {
    c.execute(ops, id.into(), U64(env::block_timestamp() + 60 * NS_PER_SEC), U128(max_in));
}

fn panics<F: FnOnce() + std::panic::UnwindSafe>(f: F) -> String {
    let e = std::panic::catch_unwind(f).expect_err("expected panic");
    let m = e
        .downcast_ref::<String>()
        .cloned()
        .or(e.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_default();
    // mocked env wraps contract panics: ...GuestPanic { panic_msg: "E_X" }...
    match m.split_once("panic_msg: \"") {
        Some((_, rest)) => rest.split('"').next().unwrap_or_default().to_string(),
        None => m,
    }
}

/// The swap batch is scheduled immediately; the only `.then` is the settlement callback
/// after it. No fee transfer at execute time (v1.1).
#[test]
fn execute_buy_shape_fee_deferred_to_callback() {
    let mut c = new_account();
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
    exec(&mut c, buy(NEAR), "o1", NEAR + NEAR / 100);
    assert_eq!(c.get_day().spent_yocto.0, NEAR + NEAR / 100);
    let rs = get_created_receipts();
    assert_eq!(rs.len(), 2, "{rs:?}");
    assert_eq!(rs[0].receiver_id, a("wrap.near"));
    assert!(rs[0].receipt_indices.is_empty(), "swap not delayed");
    assert_eq!(rs[0].actions.len(), 2);
    match &rs[0].actions[1] {
        MockAction::FunctionCallWeight { method_name, attached_deposit, args, .. } => {
            assert_eq!(method_name, b"ft_transfer_call");
            assert_eq!(attached_deposit.as_yoctonear(), 1);
            let v: near_sdk::serde_json::Value = near_sdk::serde_json::from_slice(args).unwrap();
            assert_eq!(v["receiver_id"], "v2.ref-finance.near");
            assert_eq!(v["amount"], NEAR.to_string());
            assert_eq!(v["msg"], rhea_msg("wrap.near", "meme.near", 5));
        }
        x => panic!("{x:?}"),
    }
    assert_eq!(rs[1].receiver_id, me());
    assert_eq!(rs[1].receipt_indices, vec![0], "callback depends on the swap only");
    match &rs[1].actions[0] {
        MockAction::FunctionCallWeight { method_name, args, prepaid_gas, attached_deposit, .. } => {
            assert_eq!(method_name, b"on_swap_settled");
            assert_eq!(attached_deposit.as_yoctonear(), 0);
            assert_eq!(*prepaid_gas, Gas::from_tgas(GAS_CALLBACK));
            let v: near_sdk::serde_json::Value = near_sdk::serde_json::from_slice(args).unwrap();
            assert_eq!(v["amount"], NEAR.to_string());
            assert_eq!(v["counted"], NEAR.to_string());
            assert_eq!(v["fee"], (NEAR / 100).to_string());
            assert_eq!(v["day_start"], D0.to_string());
        }
        x => panic!("{x:?}"),
    }
    assert!(rs.iter().all(|r| r.receiver_id != a("fees.near")));
    assert_eq!(
        get_logs()[0],
        format!(
            r#"EVENT_JSON:{{"standard":"nttrade","version":"1","event":"execute","data":{{"client_order_id":"o1","spend":"{}","fee":"{}","gas_spend":"{}"}}}}"#,
            NEAR + NEAR / 100,
            NEAR / 100,
            // A1-F1: the whole prepaid gas (300 TGas in the mock) x GAS_PRICE_BOUND
            (300 * TGAS) as u128 * GAS_PRICE_BOUND
        )
    );
}

fn settle(
    c: &mut TradingAccount,
    result: PromiseResult,
    amount: u128,
    counted: u128,
    fee: u128,
    day_start: u64,
) {
    settle_bal(c, result, amount, counted, fee, day_start, 10 * NEAR)
}

fn settle_bal(
    c: &mut TradingAccount,
    result: PromiseResult,
    amount: u128,
    counted: u128,
    fee: u128,
    day_start: u64,
    balance: u128,
) {
    testing_env!(
        VMContextBuilder::new()
            .current_account_id(me())
            .predecessor_account_id(me())
            .storage_usage(STORAGE_BYTES)
            .account_balance(NearToken::from_yoctonear(balance))
            .block_timestamp(T0 + 5)
            .build(),
        near_sdk::test_vm_config(),
        near_sdk::RuntimeFeesConfig::test(),
        Default::default(),
        vec![result],
    );
    c.on_swap_settled(
        "o1".into(),
        U128(amount),
        U128(counted),
        U128(fee),
        U64(day_start),
        None,
        None,
        None,
        None,
    );
}

fn fee_paid() -> u128 {
    get_created_receipts()
        .iter()
        .filter(|r| r.receiver_id == a("fees.near"))
        .flat_map(|r| r.actions.iter())
        .map(|x| match x {
            MockAction::Transfer { deposit, .. } => deposit.as_yoctonear(),
            _ => 0,
        })
        .sum()
}

fn ok_json(v: u128) -> PromiseResult {
    PromiseResult::Successful(format!("\"{v}\"").into_bytes())
}

#[test]
fn settle_success_charges_fee_keeps_spend() {
    let mut c = new_account();
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
    exec(&mut c, buy(NEAR), "o1", 2 * NEAR);
    let spent = c.get_day().spent_yocto.0;
    settle(&mut c, ok_json(NEAR), NEAR, NEAR, NEAR / 100, D0);
    assert_eq!(fee_paid(), NEAR / 100);
    assert_eq!(c.day.spent_yocto, spent);
    assert!(
        get_logs()[0].contains(r#""event":"settled""#) && get_logs()[0].contains(r#""spend_returned":"0""#)
    );
    // deposit_near-style success (empty result) = all used
    settle(&mut c, PromiseResult::Successful(vec![]), NEAR, NEAR, NEAR / 100, D0);
    assert_eq!(fee_paid(), NEAR / 100);
}

#[test]
fn settle_failure_no_fee_and_restores_spend() {
    let mut c = new_account();
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
    exec(&mut c, buy(NEAR), "o1", 2 * NEAR);
    assert_eq!(c.day.spent_yocto, NEAR + NEAR / 100);
    // slippage: ft_transfer_call resolves to used = 0
    settle(&mut c, ok_json(0), NEAR, NEAR, NEAR / 100, D0);
    assert_eq!(fee_paid(), 0);
    assert!(get_created_receipts().is_empty());
    assert_eq!(c.day.spent_yocto, 0);
    // batch failed outright (e.g. deposit_near panicked): same
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 2);
    exec(&mut c, buy(NEAR), "o2", 2 * NEAR);
    settle(&mut c, PromiseResult::Failed, NEAR, NEAR, NEAR / 100, D0);
    assert_eq!((fee_paid(), c.day.spent_yocto), (0, 0));
}

#[test]
fn settle_partial_is_pro_rata_and_sell_counts_only_fee() {
    let mut c = new_account();
    c.day.spent_yocto = 5 * NEAR;
    settle(&mut c, ok_json(NEAR / 4), NEAR, NEAR, NEAR / 100, D0);
    assert_eq!(fee_paid(), NEAR / 400);
    assert_eq!(c.day.spent_yocto, 5 * NEAR - (3 * NEAR / 4) - (NEAR / 100 - NEAR / 400));
    // sell: 1e30 tokens in, counted 0, fee on min_out; failed -> only fee returned
    let mut c = new_account();
    c.day.spent_yocto = NEAR / 10;
    settle(&mut c, ok_json(0), 10u128.pow(30), 0, NEAR / 100, D0);
    assert_eq!((fee_paid(), c.day.spent_yocto), (0, NEAR / 10 - NEAR / 100));
    // garbage / oversized result from an arbitrary token: treated as fully used (no free refund)
    let mut c = new_account();
    c.day.spent_yocto = NEAR;
    settle(&mut c, PromiseResult::Successful(b"not json".to_vec()), NEAR, NEAR, NEAR / 100, D0);
    assert_eq!((fee_paid(), c.day.spent_yocto), (NEAR / 100, NEAR));
    // result above amount is clamped
    settle(&mut c, ok_json(u128::MAX), NEAR, NEAR, NEAR / 100, D0);
    assert_eq!((fee_paid(), c.day.spent_yocto), (NEAR / 100, NEAR));
}

/// Accepted race: concurrent executes ate the RESERVE headroom -> fee skipped (never dip
/// below RESERVE), `fee_skipped` logged, and the fee's spend is returned to the window.
#[test]
fn settle_skips_fee_below_reserve() {
    let mut c = new_account();
    c.day.spent_yocto = NEAR + NEAR / 100;
    settle_bal(&mut c, ok_json(NEAR), NEAR, NEAR, NEAR / 100, D0, LOCKED + RESERVE + NEAR / 100 - 1);
    assert_eq!(fee_paid(), 0);
    let logs = get_logs();
    assert!(
        logs[0].contains(r#""event":"fee_skipped""#)
            && logs[0].contains(&format!(r#""fee":"{}""#, NEAR / 100)),
        "{logs:?}"
    );
    assert!(logs[1].contains(r#""event":"settled""#) && logs[1].contains(r#""fee":"0""#));
    assert_eq!(c.day.spent_yocto, NEAR);
    // exactly enough headroom: charged
    settle_bal(&mut c, ok_json(NEAR), NEAR, NEAR, NEAR / 100, D0, LOCKED + RESERVE + NEAR / 100);
    assert_eq!(fee_paid(), NEAR / 100);
}

/// v1.2: init registers on wNEAR and (lean) on every DCL-kind DEX.
#[test]
fn init_registers_wrap_and_dcl() {
    let _c = new_account();
    let rs = get_created_receipts();
    // v1.4.3 (SC-3): + one on_init_registered callback joined on both
    assert_eq!(rs.len(), 3, "{rs:?}");
    assert_eq!(rs[0].receiver_id, a("wrap.near"));
    assert_eq!(rs[1].receiver_id, a("dclv2.ref-labs.near"));
    assert_eq!(rs[2].receiver_id, me());
    assert_eq!(rs[2].receipt_indices.len(), 2);
    let acts: Vec<(String, u128, String)> = rs[1]
        .actions
        .iter()
        .map(|x| match x {
            MockAction::FunctionCallWeight { method_name, attached_deposit, args, .. } => (
                String::from_utf8(method_name.clone()).unwrap(),
                attached_deposit.as_yoctonear(),
                String::from_utf8(args.clone()).unwrap(),
            ),
            _ => panic!(),
        })
        .collect();
    assert_eq!(
        acts,
        vec![
            (
                "storage_deposit".into(),
                DCL_REGISTRATION,
                r#"{"account_id":"abcd.tt.near","registration_only":true}"#.into()
            ),
            ("storage_withdraw".into(), 1, "{}".into())
        ]
    );
}

#[test]
fn dcl_storage_and_dex_withdraw_ops() {
    let mut c = new_account();
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
    let dcl = a("dclv2.ref-labs.near");
    let ops = vec![
        Op::DexStorageDeposit { dex: dcl.clone() },
        Op::DexWithdraw { dex: dcl.clone(), token: a("meme.near"), amount: None },
        Op::DexWithdraw { dex: dcl.clone(), token: a("meme.near"), amount: Some(U128(5)) },
        Op::DexWithdraw { dex: a("v2.ref-finance.near"), token: a("meme.near"), amount: None },
    ];
    exec(&mut c, ops, "d", NEAR);
    assert_eq!(c.day.spent_yocto, DCL_REGISTRATION, "registration counted as spend, withdraw is not");
    let rs = get_created_receipts();
    assert_eq!(rs.len(), 2);
    assert_eq!(rs[1].receiver_id, a("v2.ref-finance.near"));
    match &rs[1].actions[0] {
        MockAction::FunctionCallWeight { method_name, attached_deposit, args, .. } => {
            assert_eq!(method_name, b"claim_lostfound");
            assert_eq!(attached_deposit.as_yoctonear(), 1);
            assert_eq!(std::str::from_utf8(args).unwrap(), r#"{"token_id":"meme.near"}"#);
        }
        x => panic!("{x:?}"),
    }
    let m: Vec<(String, u128, String)> = rs[0]
        .actions
        .iter()
        .map(|x| match x {
            MockAction::FunctionCallWeight { method_name, attached_deposit, args, .. } => (
                String::from_utf8(method_name.clone()).unwrap(),
                attached_deposit.as_yoctonear(),
                String::from_utf8(args.clone()).unwrap(),
            ),
            _ => panic!(),
        })
        .collect();
    assert_eq!(m[0].0, "storage_deposit");
    assert_eq!(m[0].1, DCL_REGISTRATION);
    assert_eq!(m[1], ("storage_withdraw".into(), 1, "{}".into()));
    assert_eq!(m[2], ("withdraw_asset".into(), 0, r#"{"token_id":"meme.near"}"#.into()));
    assert_eq!(m[3], ("withdraw_asset".into(), 0, r#"{"token_id":"meme.near","amount":"5"}"#.into()));
    for (op, code, max) in [
        (Op::DexStorageDeposit { dex: a("v2.ref-finance.near") }, "E_BAD_DEX", NEAR),
        (Op::DexStorageDeposit { dex: a("dex.intear.near") }, "E_BAD_DEX", NEAR),
        (Op::DexStorageDeposit { dex: dcl.clone() }, "E_CAP_TRADE", DCL_REGISTRATION - 1),
        (Op::DexWithdraw { dex: a("dex.intear.near"), token: a("meme.near"), amount: None }, "E_BAD_DEX", 0),
        (Op::DexWithdraw { dex: a("evil.near"), token: a("meme.near"), amount: None }, "E_BAD_DEX", 0),
        (Op::DexWithdraw { dex: dcl.clone(), token: me(), amount: None }, "E_BAD_OP", 0),
        (Op::DexWithdraw { dex: dcl.clone(), token: a("meme.near"), amount: Some(U128(0)) }, "E_BAD_OP", 0),
        (
            Op::DexWithdraw { dex: a("v2.ref-finance.near"), token: a("meme.near"), amount: Some(U128(5)) },
            "E_BAD_OP",
            0,
        ),
    ] {
        let mut c = new_account();
        ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
        assert_eq!(panics(std::panic::AssertUnwindSafe(|| exec(&mut c, vec![op.clone()], "x", max))), code);
    }
    // reserve: the temporary 0.5 must be affordable
    let mut c = new_account();
    ctx(me().as_str(), 0, LOCKED + RESERVE + DCL_REGISTRATION, T0 + 1);
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| exec(
            &mut c,
            vec![Op::DexStorageDeposit { dex: dcl.clone() }],
            "r",
            NEAR
        ))),
        "E_RESERVE"
    );
}

#[test]
fn owner_reclaim_dex_storage_rules() {
    let mut c = new_account();
    ctx("owner.near", 1, 10 * NEAR, T0 + 1);
    c.owner_reclaim_dex_storage(a("dclv2.ref-labs.near"));
    let rs = get_created_receipts();
    assert_eq!(rs[0].receiver_id, a("dclv2.ref-labs.near"));
    assert!(matches!(&rs[0].actions[0], MockAction::FunctionCallWeight { method_name, attached_deposit, .. }
        if method_name == b"storage_unregister" && attached_deposit.as_yoctonear() == 1));
    for (pred, dep, dex, code) in [
        ("owner.near", 1, "v2.ref-finance.near", "E_BAD_DEX"),
        ("owner.near", 1, "dex.intear.near", "E_BAD_DEX"),
        ("abcd.tt.near", 1, "dclv2.ref-labs.near", "E_NOT_OWNER"),
        ("owner.near", 0, "dclv2.ref-labs.near", "E_ONE_YOCTO"),
    ] {
        ctx(pred, dep, 10 * NEAR, T0 + 1);
        assert_eq!(panics(std::panic::AssertUnwindSafe(|| c.owner_reclaim_dex_storage(a(dex)))), code);
    }
}

#[test]
fn plach_withdraw_to_self_not_spend() {
    let mut c = new_account();
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
    let ops = vec![
        Op::PlachWithdraw { dex: a("dex.intear.near"), asset_id: "nep141:meme.near".into(), amount: None },
        Op::PlachWithdraw { dex: a("dex.intear.near"), asset_id: "near".into(), amount: Some(U128(7)) },
    ];
    exec(&mut c, ops, "w", 0);
    assert_eq!(c.day.spent_yocto, 0, "not spend");
    let rs = get_created_receipts();
    assert_eq!(rs.len(), 1, "no callback (not a swap)");
    assert_eq!(rs[0].receiver_id, a("dex.intear.near"));
    let args: Vec<String> = rs[0]
        .actions
        .iter()
        .map(|x| match x {
            MockAction::FunctionCallWeight { method_name, args, attached_deposit, .. } => {
                assert_eq!(method_name, b"withdraw");
                assert_eq!(attached_deposit.as_yoctonear(), 1);
                String::from_utf8(args.clone()).unwrap()
            }
            _ => panic!(),
        })
        .collect();
    assert_eq!(
        args,
        vec![
            r#"{"asset_id":"nep141:meme.near","amount":{"Full":{"at_least":null}}}"#.to_string(),
            r#"{"asset_id":"near","amount":{"Exact":"7"}}"#.to_string()
        ]
    );
    for (op, code) in [
        (
            Op::PlachWithdraw { dex: a("v2.ref-finance.near"), asset_id: "near".into(), amount: None },
            "E_BAD_DEX",
        ),
        (Op::PlachWithdraw { dex: a("dex.intear.near"), asset_id: "".into(), amount: None }, "E_BAD_OP"),
        (
            Op::PlachWithdraw { dex: a("dex.intear.near"), asset_id: "near".into(), amount: Some(U128(0)) },
            "E_BAD_OP",
        ),
    ] {
        let mut c = new_account();
        ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
        assert_eq!(panics(std::panic::AssertUnwindSafe(|| exec(&mut c, vec![op.clone()], "x", 0))), code);
    }
}

#[test]
fn settle_after_window_rollover_does_not_touch_new_window() {
    let mut c = new_account();
    c.day = Day { start_ns: T0 + DAY_NS, spent_yocto: 7 };
    settle(&mut c, ok_json(0), NEAR, NEAR, NEAR / 100, D0);
    assert_eq!(c.day.spent_yocto, 7);
}

// `#[private]` on on_swap_settled is enforced by the generated wasm entrypoint, not the
// Rust method, so it is tested in the sandbox (tests/tests/swap.rs).

#[test]
fn execute_sell_fee_on_min_out_and_prewrap_not_spend() {
    let mut c = new_account();
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
    exec(&mut c, sell(3 * NEAR), "s1", 3 * NEAR / 100);
    assert_eq!(c.get_day().spent_yocto.0, 3 * NEAR / 100); // only the fee counts
    let rs = get_created_receipts();
    assert_eq!(rs.len(), 2);
    match &rs[1].actions[0] {
        MockAction::FunctionCallWeight { args, .. } => {
            let v: near_sdk::serde_json::Value = near_sdk::serde_json::from_slice(args).unwrap();
            assert_eq!(
                (v["counted"].as_str(), v["fee"].clone()),
                (Some("0"), (3 * NEAR / 100).to_string().into())
            );
        }
        x => panic!("{x:?}"),
    }
    // pre-wrapping is not spend and has no callback
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 2);
    exec(&mut c, vec![Op::NearDeposit { amount: U128(NEAR) }], "w1", 0);
    assert_eq!(c.get_day().spent_yocto.0, 3 * NEAR / 100);
    assert_eq!(get_created_receipts().len(), 1);
}

fn plach_buy_ops(amount: u128, min: u128) -> Vec<Op> {
    let m = format!(
        r#"{{"operations":[{{"SwapSimple":{{"dex_id":"slimedragon.near/xyk","message":"AA==","asset_in":"near","asset_out":"nep141:meme.near","amount":{{"Amount":{{"ExactIn":"{amount}"}}}},"constraint":"{min}"}}}},{{"Withdraw":{{"asset_id":"nep141:meme.near","amount":{{"Full":{{"at_least":"{min}"}}}},"to":null,"rescue_address":null}}}}],"referrer":"fees.near"}}"#
    );
    vec![
        Op::StorageDeposit { token: a("dex.intear.near"), amount: U128(5 * 10u128.pow(21)) },
        Op::PlachRegisterAssets {
            dex: a("dex.intear.near"),
            asset_ids: vec!["near".into(), "nep141:meme.near".into()],
        },
        Op::StorageDeposit { token: a("meme.near"), amount: U128(1_250_000_000_000_000_000_000) },
        Op::PlachDepositNear {
            dex: a("dex.intear.near"),
            amount: U128(amount),
            msg: m,
            gas: U64(200 * TGAS),
        },
    ]
}

#[test]
fn plach_buy_shape_and_spend() {
    let mut c = new_account();
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
    let st = 5 * 10u128.pow(21) + 1_250_000_000_000_000_000_000;
    exec(&mut c, plach_buy_ops(NEAR, 7), "p1", NEAR + NEAR / 100 + st);
    assert_eq!(c.day.spent_yocto, NEAR + NEAR / 100 + st);
    let rs = get_created_receipts();
    // dex batch (storage + register + deposit_near), meme storage, callback on the dex batch
    assert_eq!(rs.len(), 3, "{rs:?}");
    assert_eq!(rs[0].receiver_id, a("dex.intear.near"));
    let names: Vec<(String, u128)> = rs[0]
        .actions
        .iter()
        .map(|x| match x {
            MockAction::FunctionCallWeight { method_name, attached_deposit, .. } => {
                (String::from_utf8(method_name.clone()).unwrap(), attached_deposit.as_yoctonear())
            }
            _ => panic!(),
        })
        .collect();
    assert_eq!(
        names,
        vec![
            ("storage_deposit".into(), 5 * 10u128.pow(21)),
            ("register_assets".into(), 1),
            ("deposit_near".into(), NEAR)
        ]
    );
    match (&rs[0].actions[1], &rs[0].actions[2]) {
        (MockAction::FunctionCallWeight { args: r, .. }, MockAction::FunctionCallWeight { args: d, .. }) => {
            assert_eq!(std::str::from_utf8(r).unwrap(), r#"{"asset_ids":["near","nep141:meme.near"]}"#);
            let v: near_sdk::serde_json::Value = near_sdk::serde_json::from_slice(d).unwrap();
            assert_eq!(v["operations"]["referrer"], "fees.near");
            assert_eq!(v["operations"]["operations"][1]["Withdraw"]["to"], near_sdk::serde_json::Value::Null);
        }
        _ => panic!(),
    }
    assert_eq!(rs[2].receiver_id, me());
    assert_eq!(rs[2].receipt_indices, vec![0]);
}

#[test]
fn plach_buy_real_router_msgs_accepted() {
    for f in fixtures().into_iter().filter(|f| f.kind == "PlachNear") {
        let mut c = new_account();
        ctx(me().as_str(), 0, 100 * NEAR, T0 + 1);
        let amount: u128 = 10u128.pow(23);
        // 265 = max for a lone deposit_near: 300 - 15 overhead - 10 callback - 2x5 action fees
        // v1.2.1: the router must be asked for our referrer (fee_recipient)
        let msg = f.msg.replace(referrer_of(&f.msg).as_str(), "fees.near");
        let ops = vec![Op::PlachDepositNear {
            dex: a("dex.intear.near"),
            amount: U128(amount),
            msg,
            gas: U64(265 * TGAS),
        }];
        exec(&mut c, ops, "p", 2 * NEAR);
        assert_eq!(c.day.spent_yocto, amount + amount / 100, "{}", f.name);
    }
}

#[test]
fn execute_other_pair_zero_fee_and_storage_is_spend() {
    let mut c = new_account();
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
    let mut ops =
        vec![Op::StorageDeposit { token: a("meme.near"), amount: U128(1_250_000_000_000_000_000_000) }];
    ops.push(Op::FtTransferCall {
        token: a("usdt.near"),
        receiver_id: a("v2.ref-finance.near"),
        amount: U128(100),
        msg: rhea_msg("usdt.near", "meme.near", 7),
        gas: U64(100 * TGAS),
    });
    exec(&mut c, ops, "x1", 1_250_000_000_000_000_000_000);
    assert_eq!(c.get_day().spent_yocto.0, 1_250_000_000_000_000_000_000);
    let rs = get_created_receipts();
    assert_eq!(rs.len(), 3); // storage (meme) + swap (usdt) + settle callback; no fee transfer
    assert!(rs.iter().all(|r| r.receiver_id != a("fees.near")));
}

#[test]
fn execute_error_codes() {
    type Case = (&'static str, Box<dyn Fn(&mut TradingAccount)>);
    let cases: Vec<Case> = vec![
        (
            "E_BAD_OP",
            Box::new(|c| {
                // swap must be the last op (and so at most one swap)
                ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
                let mut ops = buy(NEAR / 10);
                ops.push(Op::NearDeposit { amount: U128(1) });
                exec(c, ops, "a", NEAR);
            }),
        ),
        (
            "E_BAD_OP",
            Box::new(|c| {
                ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
                let mut ops = sell(NEAR);
                ops.extend(sell(NEAR));
                exec(c, ops, "a", NEAR);
            }),
        ),
        (
            "E_BAD_DEX",
            Box::new(|c| {
                // Plach ops only to a Plach-kind DEX
                ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
                let mut ops = plach_buy_ops(NEAR, 7);
                if let Op::PlachDepositNear { dex, .. } = &mut ops[3] {
                    *dex = a("v2.ref-finance.near");
                }
                exec(c, ops, "a", 2 * NEAR);
            }),
        ),
        (
            "E_BAD_DEX",
            Box::new(|c| {
                ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
                exec(
                    c,
                    vec![Op::PlachRegisterAssets { dex: a("evil.near"), asset_ids: vec!["near".into()] }],
                    "a",
                    0,
                );
            }),
        ),
        (
            "E_BAD_OP",
            Box::new(|c| {
                ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
                let ids = (0..5).map(|i| format!("nep141:t{i}.near")).collect();
                exec(c, vec![Op::PlachRegisterAssets { dex: a("dex.intear.near"), asset_ids: ids }], "a", 0);
            }),
        ),
        (
            "E_RECIPIENT",
            Box::new(|c| {
                ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
                let mut ops = plach_buy_ops(NEAR, 7);
                if let Op::PlachDepositNear { msg, .. } = &mut ops[3] {
                    *msg = msg.replace(r#""to":null"#, r#""to":"evil.near""#);
                }
                exec(c, ops, "a", 2 * NEAR);
            }),
        ),
        (
            "E_MIN_OUT",
            Box::new(|c| {
                ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
                exec(c, plach_buy_ops(NEAR, 0), "a", 2 * NEAR);
            }),
        ),
        (
            "E_GAS",
            Box::new(|c| {
                // router's 280 TGas deposit_near + 10 callback + 15 overhead > 300
                ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
                let mut ops = plach_buy_ops(NEAR, 7);
                if let Op::PlachDepositNear { gas, .. } = &mut ops[3] {
                    *gas = U64(280 * TGAS);
                }
                exec(c, ops, "a", 2 * NEAR);
            }),
        ),
        (
            "E_CAP_TRADE",
            Box::new(|c| {
                // deposit_near amount is spend
                ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
                exec(c, vec![plach_buy_ops(NEAR, 7).pop().unwrap()], "a", NEAR);
            }),
        ),
        (
            "E_NOT_SELF",
            Box::new(|c| {
                ctx("owner.near", 0, 10 * NEAR, T0 + 1);
                exec(c, buy(NEAR), "a", 2 * NEAR);
            }),
        ),
        (
            "E_EXPIRED",
            Box::new(|c| {
                ctx(me().as_str(), 0, 10 * NEAR, T0 + 10);
                c.execute(buy(NEAR), "a".into(), U64(T0 + 9), U128(2 * NEAR));
            }),
        ),
        (
            "E_EXPIRY_TOO_FAR",
            Box::new(|c| {
                ctx(me().as_str(), 0, 10 * NEAR, T0 + 10);
                c.execute(buy(NEAR), "a".into(), U64(T0 + 11 + MAX_EXPIRY_AHEAD_NS), U128(2 * NEAR));
            }),
        ),
        (
            "E_DUPLICATE",
            Box::new(|c| {
                ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
                exec(c, buy(NEAR / 10), "dup", NEAR);
                ctx(me().as_str(), 0, 10 * NEAR, T0 + 2);
                exec(c, buy(NEAR / 10), "dup", NEAR);
            }),
        ),
        (
            "E_BAD_ORDER_ID",
            Box::new(|c| {
                ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
                exec(c, buy(NEAR), &"z".repeat(65), 2 * NEAR);
            }),
        ),
        (
            "E_BAD_OP",
            Box::new(|c| {
                ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
                exec(c, vec![], "a", 0);
            }),
        ),
        (
            "E_BAD_OP",
            Box::new(|c| {
                ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
                exec(c, vec![Op::NearDeposit { amount: U128(0) }], "a", 0);
            }),
        ),
        (
            "E_BAD_OP",
            Box::new(|c| {
                ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
                exec(
                    c,
                    vec![Op::StorageDeposit { token: a("t.near"), amount: U128(MAX_STORAGE_DEPOSIT + 1) }],
                    "a",
                    NEAR,
                );
            }),
        ),
        (
            "E_BAD_OP",
            Box::new(|c| {
                ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
                exec(c, vec![Op::StorageDeposit { token: me(), amount: U128(1) }], "a", NEAR);
            }),
        ),
        (
            "E_BAD_DEX",
            Box::new(|c| {
                ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
                let mut ops = buy(NEAR);
                if let Op::FtTransferCall { receiver_id, .. } = &mut ops[1] {
                    *receiver_id = a("evil.near");
                }
                exec(c, ops, "a", 2 * NEAR);
            }),
        ),
        (
            "E_BAD_MSG",
            Box::new(|c| {
                ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
                let mut ops = buy(NEAR);
                if let Op::FtTransferCall { msg, .. } = &mut ops[1] {
                    *msg = "{}".into();
                }
                exec(c, ops, "a", 2 * NEAR);
            }),
        ),
        (
            "E_RECIPIENT",
            Box::new(|c| {
                ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
                let mut ops = buy(NEAR);
                if let Op::FtTransferCall { msg, .. } = &mut ops[1] {
                    *msg = msg.replace(r#""force":0"#, r#""force":0,"swap_out_recipient":"evil.near""#);
                }
                exec(c, ops, "a", 2 * NEAR);
            }),
        ),
        (
            "E_MIN_OUT",
            Box::new(|c| {
                ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
                exec(c, sell(0), "a", 2 * NEAR);
            }),
        ),
        (
            "E_CAP_TRADE",
            Box::new(|c| {
                ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
                exec(c, buy(NEAR), "a", NEAR); // spend = 1.01 > max_in
            }),
        ),
        (
            "E_CAP_TRADE",
            Box::new(|c| {
                ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
                exec(c, buy(NEAR), "a", 2 * NEAR + 1); // max_in > caps.max_trade
            }),
        ),
        (
            "E_CAP_DAILY",
            Box::new(|c| {
                for i in 0..3 {
                    ctx(me().as_str(), 0, 100 * NEAR, T0 + 1);
                    exec(c, buy(3 * NEAR / 2), &format!("d{i}"), 2 * NEAR);
                }
                ctx(me().as_str(), 0, 100 * NEAR, T0 + 1);
                exec(c, buy(3 * NEAR / 2), "d4", 2 * NEAR);
            }),
        ),
        (
            "E_GAS",
            Box::new(|c| {
                ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
                let ops = (0..5).map(|_| Op::NearDeposit { amount: U128(1) }).collect();
                exec(c, ops, "a", 0);
            }),
        ),
        (
            "E_GAS",
            Box::new(|c| {
                ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
                let mut ops = buy(NEAR);
                if let Op::FtTransferCall { gas, .. } = &mut ops[1] {
                    *gas = U64(258 * TGAS);
                } // + 3 near_deposit + 10 callback + 3x5 action fees = 286 > 285
                exec(c, ops, "a", 2 * NEAR);
            }),
        ),
        (
            "E_RESERVE",
            Box::new(|c| {
                ctx(me().as_str(), 0, LOCKED + NEAR + NEAR / 100 + RESERVE, T0 + 1); // missing the 1 yocto
                exec(c, buy(NEAR), "a", 2 * NEAR);
            }),
        ),
    ];
    for (code, f) in cases {
        let mut c = new_account();
        let msg = panics(std::panic::AssertUnwindSafe(|| f(&mut c)));
        assert_eq!(msg, code);
    }
}

#[test]
fn reserve_boundary_passes() {
    let mut c = new_account();
    ctx(me().as_str(), 0, LOCKED + GD_LOCK + NEAR + NEAR / 100 + 1 + RESERVE, T0 + 1);
    exec(&mut c, buy(NEAR), "a", 2 * NEAR);
}

#[test]
fn withdraw_to_owner_and_lower_caps() {
    let mut c = new_account();
    ctx(me().as_str(), 0, LOCKED + GD_LOCK + NEAR, T0 + 1);
    c.withdraw_to_owner(None, U128(NEAR - RESERVE));
    // v1.4.3 (CAPACCT-001): the token path's storage deposit must leave RESERVE too
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| c.withdraw_to_owner(Some(a("meme.near")), U128(77)))),
        "E_RESERVE"
    );
    ctx(me().as_str(), 0, LOCKED + GD_LOCK + NEAR, T0 + 1);
    c.withdraw_to_owner(None, U128(NEAR - RESERVE - MAX_STORAGE_DEPOSIT - 1));
    c.withdraw_to_owner(Some(a("meme.near")), U128(77));
    let rs = get_created_receipts();
    assert_eq!(rs[0].receiver_id, a("owner.near"));
    // v1.3.2: register the owner on the token, then ft_transfer, then report
    let calls: Vec<(String, String, u128, String)> = rs[1..]
        .iter()
        .flat_map(|r| r.actions.iter().map(move |x| (r.receiver_id.to_string(), x)))
        .filter_map(|(rcv, x)| match x {
            MockAction::FunctionCallWeight { method_name, args, attached_deposit, .. } => Some((
                rcv,
                String::from_utf8(method_name.clone()).unwrap(),
                attached_deposit.as_yoctonear(),
                String::from_utf8(args.clone()).unwrap(),
            )),
            _ => None,
        })
        .collect();
    assert_eq!(
        calls,
        vec![
            (
                "meme.near".into(),
                "storage_deposit".into(),
                MAX_STORAGE_DEPOSIT,
                r#"{"account_id":"owner.near","registration_only":true}"#.into()
            ),
            (
                "meme.near".into(),
                "ft_transfer".into(),
                1,
                r#"{"receiver_id":"owner.near","amount":"77"}"#.into()
            ),
            (
                me().to_string(),
                "on_withdraw_one".into(),
                0,
                r#"{"token":"meme.near","amount":"77","to":"owner.near"}"#.into()
            ),
        ]
    );
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| c.withdraw_to_owner(None, U128(NEAR - RESERVE + 1)))),
        "E_RESERVE"
    );
    assert_eq!(panics(std::panic::AssertUnwindSafe(|| c.withdraw_to_owner(Some(me()), U128(1)))), "E_BAD_OP");
    c.lower_caps(caps(NEAR, NEAR));
    assert_eq!(c.get_config().caps, caps(NEAR, NEAR));
    assert_eq!(panics(std::panic::AssertUnwindSafe(|| c.lower_caps(caps(NEAR + 1, NEAR)))), "E_CAP_RAISE");
    ctx("owner.near", 0, NEAR, T0 + 1);
    assert_eq!(panics(std::panic::AssertUnwindSafe(|| c.withdraw_to_owner(None, U128(1)))), "E_NOT_SELF");
    assert_eq!(panics(std::panic::AssertUnwindSafe(|| c.lower_caps(caps(1, 1)))), "E_NOT_SELF");
}

#[test]
fn owner_methods_require_owner_and_one_yocto() {
    let mut c = new_account();
    let pk: PublicKey = "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp".parse().unwrap();
    type F = Box<dyn Fn(&mut TradingAccount)>;
    let pk2 = pk.clone();
    let pk3 = pk.clone();
    let calls: Vec<F> = vec![
        Box::new(move |c| c.owner_add_key(pk.clone(), KeyKind::FunctionCall)),
        Box::new(move |c| c.owner_remove_key(pk2.clone())),
        Box::new(|c| c.owner_withdraw(None, U128(1), a("x.near"))),
        Box::new(|c| c.owner_set_caps(caps(1, 1))),
        Box::new(|c| c.owner_upgrade([0u8; 32].into())),
        Box::new(move |c| c.owner_add_key(pk3.clone(), KeyKind::FunctionCall)),
    ];
    for f in &calls {
        for (pred, dep, code) in [
            (me().as_str(), 1, "E_NOT_OWNER"),
            ("evil.near", 1, "E_NOT_OWNER"),
            ("owner.near", 0, "E_ONE_YOCTO"),
            ("owner.near", 2, "E_ONE_YOCTO"),
        ] {
            ctx(pred, dep, 10 * NEAR, T0 + 1);
            assert_eq!(panics(std::panic::AssertUnwindSafe(|| f(&mut c))), code);
        }
        ctx("owner.near", 1, 10 * NEAR, T0 + 1);
        f(&mut c);
    }
    // owner_set_caps may raise
    assert_eq!(c.get_config().caps, caps(1, 1));
}

#[test]
fn owner_add_key_never_full_access() {
    let mut c = new_account();
    let pk: PublicKey = "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp".parse().unwrap();
    ctx("owner.near", 1, 10 * NEAR, T0 + 1);
    let mut seen = 0;
    c.owner_add_key(pk.clone(), KeyKind::FunctionCall);
    #[cfg(feature = "gas-keys")]
    c.owner_add_key(pk, KeyKind::GasKey { num_nonces: 16, balance: U128(NEAR / 2) });
    #[cfg(not(feature = "gas-keys"))]
    {
        let _ = pk;
        seen += 1;
    }
    let rs = get_created_receipts();
    for r in &rs {
        assert_eq!(r.receiver_id, me());
        for act in &r.actions {
            match act {
                MockAction::AddKeyWithFunctionCall { receiver_id, method_names, allowance, .. } => {
                    assert_eq!(receiver_id, &me());
                    assert_eq!(method_names.join(","), DEVICE_METHODS);
                    assert!(allowance.is_none());
                    seen += 1;
                }
                MockAction::AddGasKeyWithFunctionCall { receiver_id, method_names, num_nonces, .. } => {
                    assert_eq!(receiver_id, &me());
                    let m: Vec<String> =
                        method_names.iter().map(|m| String::from_utf8(m.clone()).unwrap()).collect();
                    assert_eq!(m.join(","), DEVICE_METHODS);
                    assert_eq!(*num_nonces, 16);
                    seen += 1;
                }
                MockAction::TransferToGasKey { deposit, .. } => assert_eq!(deposit.as_yoctonear(), NEAR / 2),
                // v1.4.1 (B1-L1): the AddKey result callback
                MockAction::FunctionCallWeight { method_name, .. } => {
                    assert_eq!(method_name, b"on_key_added")
                }
                MockAction::AddKeyWithFullAccess { .. } | MockAction::AddGasKeyWithFullAccess { .. } => {
                    panic!("full access")
                }
                x => panic!("unexpected {x:?}"),
            }
        }
    }
    assert_eq!(seen, 2);
}

// ---------- invariant property test over random execute sequences ----------

fn arb_op() -> impl Strategy<Value = Op> {
    let tok = prop::sample::select(vec!["wrap.near", "meme.near", "usdt.near", "abcd.tt.near"]);
    let dex = prop::sample::select(vec![
        "v2.ref-finance.near",
        "dclv2.ref-labs.near",
        "dex.intear.near",
        "evil.near",
    ]);
    let out = prop::sample::select(vec!["wrap.near", "meme.near", "usdt.near"]);
    let recip = prop::sample::select(vec![None, Some("abcd.tt.near"), Some("evil.near")]);
    prop_oneof![
        (0u128..3 * NEAR).prop_map(|x| Op::NearDeposit { amount: U128(x) }),
        (0u128..3 * NEAR).prop_map(|x| Op::NearWithdraw { amount: U128(x) }),
        (tok.clone(), 0u128..MAX_STORAGE_DEPOSIT * 2).prop_map(|(t, x)| Op::StorageDeposit { token: a(t), amount: U128(x) }),
        (tok, dex, out, 0u128..3 * NEAR, 0u128..3 * NEAR, recip, 0u64..300).prop_map(|(t, d, o, amt, min, r, g)| {
            let msg = match d {
                "dclv2.ref-labs.near" => format!(r#"{{"Swap":{{"pool_ids":["p"],"output_token":"{o}","min_output_amount":"{min}"}}}}"#),
                "dex.intear.near" => {
                    let to = r.map_or("null".to_string(), |x| format!("\"{x}\""));
                    format!(r#"{{"operations":[{{"SwapSimple":{{"dex_id":"d","message":"","asset_in":"nep141:{t}","asset_out":"nep141:{o}","amount":{{"Amount":{{"ExactIn":"{amt}"}}}},"constraint":"{min}"}}}},{{"Withdraw":{{"asset_id":"nep141:{o}","amount":{{"Full":{{"at_least":null}}}},"to":{to}}}}}]}}"#)
                }
                _ => {
                    let rr = r.map_or(String::new(), |x| format!(r#","swap_out_recipient":"{x}""#));
                    format!(r#"{{"actions":[{{"pool_id":1,"token_in":"{t}","token_out":"{o}","min_amount_out":"{min}"}}]{rr}}}"#)
                }
            };
            Op::FtTransferCall { token: a(t), receiver_id: a(d), amount: U128(amt), msg, gas: U64(g * TGAS) }
        }),
        (prop::sample::select(vec!["dex.intear.near", "v2.ref-finance.near"]), 0usize..6).prop_map(|(d, n)| Op::PlachRegisterAssets {
            dex: a(d),
            asset_ids: (0..n).map(|i| format!("nep141:t{i}\"x.near")).collect(),
        }),
        prop::sample::select(vec!["dclv2.ref-labs.near", "dex.intear.near"]).prop_map(|d| Op::DexStorageDeposit { dex: a(d) }),
        (prop::sample::select(vec!["dclv2.ref-labs.near", "v2.ref-finance.near", "dex.intear.near"]), prop::option::of(0u128..10)).prop_map(|(d, x)| Op::DexWithdraw {
            dex: a(d),
            token: a("meme.near"),
            amount: x.map(U128),
        }),
        (prop::sample::select(vec!["dex.intear.near", "v2.ref-finance.near"]), prop::option::of(0u128..10)).prop_map(|(d, x)| Op::PlachWithdraw {
            dex: a(d),
            asset_id: "nep141:meme\",\"withdraw_to\":\"evil.near".into(),
            amount: x.map(U128),
        }),
        (prop::sample::select(vec!["dex.intear.near", "evil.near"]), 0u128..3 * NEAR, 0u128..NEAR, prop::sample::select(vec!["null", "\"abcd.tt.near\"", "\"evil.near\""]), 0u64..300)
            .prop_map(|(d, amt, min, to, g)| Op::PlachDepositNear {
                dex: a(d),
                amount: U128(amt),
                msg: format!(r#"{{"operations":[{{"SwapSimple":{{"dex_id":"d","message":"","asset_in":"near","asset_out":"nep141:meme.near","amount":{{"Amount":{{"ExactIn":"{amt}"}}}},"constraint":"{min}"}}}},{{"Withdraw":{{"asset_id":"nep141:meme.near","amount":{{"Full":{{"at_least":null}}}},"to":{to}}}}}]}}"#),
                gas: U64(g * TGAS),
            }),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(300))]
    /// Invariants 1, 3, 4, 6 over random sequences of (mostly hostile) execute calls.
    #[test]
    fn execute_invariants(calls in prop::collection::vec((prop::collection::vec(arb_op(), 0..6), 0u64..(DAY_NS / 4), 0u8..40, 0u128..4 * NEAR), 1..25)) {
        let mut c = new_account();
        let allowed = ["wrap.near", "meme.near", "usdt.near", "dex.intear.near", "v2.ref-finance.near", "dclv2.ref-labs.near"];
        let dexes = ["v2.ref-finance.near", "dclv2.ref-labs.near", "dex.intear.near"];
        let mut now = T0;
        for (ops, dt, id, max_in) in calls {
            now += dt;
            ctx(me().as_str(), 0, 20 * NEAR, now);
            let id = format!("id{id}");
            let spent_before = c.get_day().spent_yocto.0;
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut c2 = TradingAccount { seen_orders: c.seen_orders.clone(), day: c.day.clone(), caps: c.caps.clone(), fee: c.fee.clone(), dex_allowlist: c.dex_allowlist.clone(), wrap: c.wrap.clone(), owner: c.owner.clone() };
                c2.execute(ops.clone(), id.clone(), U64(now + 60 * NS_PER_SEC), U128(max_in));
                c2
            }));
            if let Ok(c2) = r {
                c = c2;
                let rs = get_created_receipts();
                let mut callbacks = 0;
                let mut wrap_in = 0u128;
                for r in &rs {
                    // (1) receivers only: wrap, token contracts, Plach (NEAR deposit), self (callback).
                    // No fee transfer at execute time: fees move only in on_swap_settled.
                    prop_assert!(allowed.contains(&r.receiver_id.as_str()) || r.receiver_id == me(), "receiver {}", r.receiver_id);
                    if r.receiver_id == me() {
                        callbacks += 1;
                        prop_assert_eq!(r.receipt_indices.len(), 1);
                    } else {
                        prop_assert!(r.receipt_indices.is_empty(), "swap never delayed");
                    }
                    for act in &r.actions {
                        match act {
                            MockAction::FunctionCallWeight { method_name, args, attached_deposit, .. } => {
                                let m = std::str::from_utf8(method_name).unwrap();
                                if r.receiver_id == me() {
                                    prop_assert_eq!(m, "on_swap_settled");
                                    let v: near_sdk::serde_json::Value = near_sdk::serde_json::from_slice(args).unwrap();
                                    let fee: u128 = v["fee"].as_str().unwrap().parse().unwrap();
                                    prop_assert!(fee <= c.get_day().spent_yocto.0);
                                    continue;
                                }
                                prop_assert!(["near_deposit", "near_withdraw", "storage_deposit", "ft_transfer_call", "register_assets", "deposit_near", "withdraw", "storage_withdraw", "withdraw_asset", "claim_lostfound"].contains(&m));
                                if m == "claim_lostfound" {
                                    prop_assert_eq!(r.receiver_id.as_str(), "v2.ref-finance.near");
                                }
                                if m == "storage_withdraw" || m == "withdraw_asset" {
                                    prop_assert_eq!(r.receiver_id.as_str(), "dclv2.ref-labs.near");
                                }
                                if m == "withdraw" {
                                    let v: near_sdk::serde_json::Value = near_sdk::serde_json::from_slice(args).unwrap();
                                    let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
                                    prop_assert_eq!(keys, vec!["asset_id", "amount"], "Plach withdraw only to self (no withdraw_to key)");
                                }
                                if m == "ft_transfer_call" {
                                    let v: near_sdk::serde_json::Value = near_sdk::serde_json::from_slice(args).unwrap();
                                    prop_assert!(dexes.contains(&v["receiver_id"].as_str().unwrap()));
                                    if r.receiver_id.as_str() == "wrap.near" {
                                        wrap_in += v["amount"].as_str().unwrap().parse::<u128>().unwrap();
                                    }
                                }
                                if m == "deposit_near" || m == "register_assets" {
                                    prop_assert_eq!(r.receiver_id.as_str(), "dex.intear.near");
                                }
                                if m == "register_assets" {
                                    prop_assert_eq!(attached_deposit.as_yoctonear(), 1);
                                    prop_assert!(!std::str::from_utf8(args).unwrap().contains("\"for\""));
                                }
                                if m == "storage_deposit" {
                                    prop_assert!(std::str::from_utf8(args).unwrap().contains(r#""account_id":"abcd.tt.near""#));
                                }
                            }
                            x => prop_assert!(false, "unexpected action {:?}", x),
                        }
                    }
                }
                prop_assert!(callbacks <= 1);
                let day = c.get_day().spent_yocto.0;
                if wrap_in > 0 { prop_assert!(day >= wrap_in + bps(wrap_in, 100)); }
                // (4) daily cap
                prop_assert!(day <= c.caps.daily_cap_yocto.0);
                prop_assert!(day >= spent_before || day <= max_in);
                // (6) bounded storage
                prop_assert!(c.seen_orders.0.len() <= MAX_SEEN_ORDERS);
                // (3) the same id cannot execute again while its order is still valid
                let again = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut c3 = TradingAccount { seen_orders: c.seen_orders.clone(), day: c.day.clone(), caps: c.caps.clone(), fee: c.fee.clone(), dex_allowlist: c.dex_allowlist.clone(), wrap: c.wrap.clone(), owner: c.owner.clone() };
                    c3.execute(vec![Op::NearDeposit { amount: U128(1) }], id.clone(), U64(now + 60 * NS_PER_SEC), U128(0));
                }));
                prop_assert!(again.is_err());
            }
        }
    }
}

// ======================= v1.3 orders + automation key =======================

const AUTO_PK: &str = "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp";

fn auto_pk() -> PublicKey {
    AUTO_PK.parse().unwrap()
}

/// Context signed by `pk` (device default pk vs automation pk).
fn ctx_pk(pred: &str, pk: Option<PublicKey>, deposit: u128, now: u64) {
    let mut b = VMContextBuilder::new();
    b.current_account_id(me())
        .predecessor_account_id(a(pred))
        .signer_account_id(a(pred))
        .attached_deposit(NearToken::from_yoctonear(deposit))
        .account_balance(NearToken::from_yoctonear(10 * NEAR))
        .block_timestamp(now)
        .storage_usage(STORAGE_BYTES)
        .prepaid_gas(Gas::from_tgas(300));
    if let Some(pk) = pk {
        b.signer_account_pk(pk);
    }
    testing_env!(b.build());
}

/// Mock storage_usage is per-context; order-heavy tests need a realistic figure.
fn big_ctx(pred: &str, now: u64) {
    testing_env!(VMContextBuilder::new()
        .current_account_id(me())
        .predecessor_account_id(a(pred))
        .account_balance(NearToken::from_yoctonear(100 * NEAR))
        .storage_usage(100_000)
        .block_timestamp(now)
        .build());
}

fn with_automation() -> TradingAccount {
    let mut c = new_account();
    ctx("owner.near", 1, 10 * NEAR, T0);
    c.owner_set_automation_key(auto_pk(), U128(NEAR));
    automation_cb(&mut c, auto_pk(), true);
    c
}

/// v1.4.8: no default weekly relayer allowance; tests of the weekly accounting opt into the
/// former default (10 NEAR) explicitly.
const V147_DEFAULT_WEEKLY: u128 = 10 * NEAR;

fn with_automation_weekly(weekly: u128) -> TradingAccount {
    let mut c = with_automation();
    ctx("owner.near", 1, 10 * NEAR, T0);
    c.owner_set_relayer_allowance(U128(weekly));
    c
}

/// A1-F2: the key is stored by the success callback of the AddKey batch.
fn automation_cb(c: &mut TradingAccount, pk: PublicKey, success: bool) {
    let rs = get_created_receipts();
    testing_env!(
        VMContextBuilder::new().current_account_id(me()).predecessor_account_id(me()).build(),
        near_sdk::test_vm_config(),
        near_sdk::RuntimeFeesConfig::test(),
        Default::default(),
        vec![if success { PromiseResult::Successful(vec![]) } else { PromiseResult::Failed }],
    );
    let _ = rs;
    c.on_automation_set(pk, None, None);
}

fn place_buy(c: &mut TradingAccount, amount: u128, min_out: u128) -> u64 {
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
    c.place_order(
        a("wrap.near"),
        a("meme.near"),
        U128(amount),
        U128(min_out),
        r#"{"kind":"limit","price":"0.001"}"#.into(),
        U64(T0 + 3_600 * NS_PER_SEC),
        vec![a("v2.ref-finance.near")],
    )
    .0
}

/// v1.4.1 (D6): buy orders are executed by a device key (tab runner); the relayer is sell-only.
fn exec_order(c: &mut TradingAccount, id: u64, ops: Vec<Op>) {
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 2);
    c.execute_order(U64(id), ops);
}

fn order_buy_ops(amount: u128, min_out: u128) -> Vec<Op> {
    vec![
        Op::StorageDeposit { token: a("meme.near"), amount: U128(1_250_000_000_000_000_000_000) },
        Op::NearDeposit { amount: U128(amount) },
        Op::FtTransferCall {
            token: a("wrap.near"),
            receiver_id: a("v2.ref-finance.near"),
            amount: U128(amount),
            msg: rhea_msg("wrap.near", "meme.near", min_out),
            gas: U64(150 * TGAS),
        },
    ]
}

#[test]
fn automation_key_install_rotate_revoke() {
    let mut c = new_account();
    ctx("owner.near", 1, 10 * NEAR, T0);
    c.owner_set_automation_key(auto_pk(), U128(NEAR));
    let rs = get_created_receipts();
    assert_eq!(rs.len(), 2, "key batch + on_automation_set callback");
    assert_eq!(c.get_automation_key(), None, "A1-F2: not stored before the batch succeeded");
    automation_cb(&mut c, auto_pk(), true);
    match &rs[0].actions[..] {
        [MockAction::AddKeyWithFunctionCall { receiver_id, method_names, allowance, .. }] => {
            assert_eq!(receiver_id, &me());
            assert_eq!(method_names, &vec!["execute_order".to_string()]);
            assert_eq!(allowance.map(|x| x.as_yoctonear()), Some(NEAR), "allowance bounds gas burn");
        }
        x => panic!("{x:?}"),
    }
    assert_eq!(c.get_automation_key(), Some(auto_pk()));
    // rotate: old key deleted in the same batch
    let pk2: PublicKey = "ed25519:DcA2MzgpJbrUATQLLceocVckhhAqrkingax4oJ9kZ847".parse().unwrap();
    ctx("owner.near", 1, 10 * NEAR, T0);
    c.owner_set_automation_key(pk2.clone(), U128(NEAR));
    let acts = get_created_receipts()[0].actions.clone();
    assert!(
        matches!(acts[0], MockAction::DeleteKey { .. })
            && matches!(acts[1], MockAction::AddKeyWithFunctionCall { .. })
    );
    // A1-F2: a FAILED batch (e.g. pk already on the account) changes nothing
    automation_cb(&mut c, pk2.clone(), false);
    assert_eq!(c.get_automation_key(), Some(auto_pk()));
    automation_cb(&mut c, pk2.clone(), true);
    assert_eq!(c.get_automation_key(), Some(pk2));
    // rules
    for (pred, dep, allow, code) in [
        ("owner.near", 1, NEAR / 10, "E_ALLOWANCE"),
        ("abcd.tt.near", 1, NEAR, "E_NOT_OWNER"),
        ("owner.near", 0, NEAR, "E_ONE_YOCTO"),
    ] {
        ctx(pred, dep, 10 * NEAR, T0);
        assert_eq!(
            panics(std::panic::AssertUnwindSafe(|| c.owner_set_automation_key(auto_pk(), U128(allow)))),
            code
        );
    }
    // device one-click revoke
    ctx(me().as_str(), 0, 10 * NEAR, T0);
    c.revoke_automation();
    assert!(matches!(get_created_receipts()[0].actions[0], MockAction::DeleteKey { .. }));
    assert_eq!(c.get_automation_key(), None);
}

type OrderArgs = (AccountId, AccountId, u128, u128, String, u64, Vec<AccountId>);

#[test]
fn place_order_rules_and_bounds() {
    let mut c = new_account();
    // v1.4.3 (SC-2): each placement's prepaid gas is charged; room for ~80 calls at 300 TGas
    c.caps = caps(2 * NEAR, 1_000 * NEAR);
    let base = |c: &mut TradingAccount, f: &dyn Fn(&mut OrderArgs)| {
        let mut p = (
            a("wrap.near"),
            a("meme.near"),
            NEAR,
            5,
            String::new(),
            T0 + 60 * NS_PER_SEC,
            vec![a("v2.ref-finance.near")],
        );
        f(&mut p);
        big_ctx(me().as_str(), T0 + 1);
        c.place_order(p.0, p.1, U128(p.2), U128(p.3), p.4, U64(p.5), p.6)
    };
    type Mut = Box<dyn Fn(&mut OrderArgs)>;
    let cases: Vec<(&str, Mut)> = vec![
        ("E_BAD_ORDER", Box::new(|p| p.2 = 0)),
        ("E_BAD_ORDER", Box::new(|p| p.3 = 0)),
        ("E_BAD_ORDER", Box::new(|p| p.1 = a("wrap.near"))),
        ("E_BAD_ORDER", Box::new(|p| p.1 = me())),
        ("E_BAD_ORDER", Box::new(|p| p.4 = "x".repeat(MAX_TRIGGER_META + 1))),
        ("E_BAD_ORDER", Box::new(|p| p.6 = vec![])),
        ("E_BAD_ORDER", Box::new(|p| p.6 = vec![a("v2.ref-finance.near"); 4])),
        ("E_BAD_DEX", Box::new(|p| p.6 = vec![a("evil.near")])),
        ("E_EXPIRED", Box::new(|p| p.5 = T0)),
        ("E_EXPIRY_TOO_FAR", Box::new(|p| p.5 = T0 + 2 + MAX_ORDER_TTL_NS)),
    ];
    for (code, f) in cases {
        assert_eq!(
            panics(std::panic::AssertUnwindSafe(|| {
                base(&mut c, &*f);
            })),
            code
        );
    }
    // bounded: 64 open orders, then E_ORDER_LIMIT; nothing spent by placing
    for _ in 0..MAX_OPEN_ORDERS {
        base(&mut c, &|_| {});
    }
    assert_eq!(c.get_orders().len(), MAX_OPEN_ORDERS);
    assert_eq!(c.day.spent_yocto, 0);
    assert!(c.get_day().gas_spent_yocto.0 > 0, "SC-2: place_order gas is charged");
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| {
            base(&mut c, &|_| {});
        })),
        "E_ORDER_LIMIT"
    );
    // expired orders are pruned on the next placement
    // (mock: storage_usage is per-context, so give this call a realistic figure)
    testing_env!(VMContextBuilder::new()
        .current_account_id(me())
        .predecessor_account_id(me())
        .account_balance(NearToken::from_yoctonear(100 * NEAR))
        .storage_usage(100_000)
        .block_timestamp(T0 + 61 * NS_PER_SEC)
        .build());
    let id = c.place_order(
        a("wrap.near"),
        a("meme.near"),
        U128(1),
        U128(1),
        String::new(),
        U64(T0 + 120 * NS_PER_SEC),
        vec![a("v2.ref-finance.near")],
    );
    assert_eq!(c.get_orders().len(), 1);
    assert_eq!(c.get_orders()[0].id, id);
    // only device keys (not owner directly, not the automation key)
    let mut c = with_automation();
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        ctx("owner.near", 0, 10 * NEAR, T0 + 1);
        c.place_order(
            a("wrap.near"),
            a("meme.near"),
            U128(1),
            U128(1),
            String::new(),
            U64(T0 + NS_PER_SEC * 60),
            vec![a("v2.ref-finance.near")],
        );
    }));
    assert!(format!("{:?}", r.err().and_then(|e| e.downcast_ref::<String>().cloned())).contains("E_NOT_SELF"));
    ctx_pk(me().as_str(), Some(auto_pk()), 0, T0 + 1);
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| {
            c.place_order(
                a("wrap.near"),
                a("meme.near"),
                U128(1),
                U128(1),
                String::new(),
                U64(T0 + NS_PER_SEC * 60),
                vec![a("v2.ref-finance.near")],
            );
        })),
        "E_AUTOMATION_KEY"
    );
}

#[test]
fn cancel_order_rules() {
    let mut c = with_automation();
    let id = place_buy(&mut c, NEAR, 5);
    let id2 = place_buy(&mut c, NEAR, 5);
    // automation key may not cancel; strangers may not; owner needs 1 yocto
    ctx_pk(me().as_str(), Some(auto_pk()), 0, T0 + 1);
    assert_eq!(panics(std::panic::AssertUnwindSafe(|| c.cancel_order(U64(id)))), "E_AUTOMATION_KEY");
    ctx("evil.near", 1, 10 * NEAR, T0 + 1);
    assert_eq!(panics(std::panic::AssertUnwindSafe(|| c.cancel_order(U64(id)))), "E_NOT_SELF");
    ctx("owner.near", 0, 10 * NEAR, T0 + 1);
    assert_eq!(panics(std::panic::AssertUnwindSafe(|| c.cancel_order(U64(id)))), "E_ONE_YOCTO");
    ctx("owner.near", 1, 10 * NEAR, T0 + 1);
    c.cancel_order(U64(id));
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
    c.cancel_order(U64(id2));
    assert!(c.get_orders().is_empty());
    assert_eq!(panics(std::panic::AssertUnwindSafe(|| c.cancel_order(U64(id)))), "E_NO_ORDER");
    // a cancelled order can't be executed
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| exec_order(&mut c, id, order_buy_ops(NEAR, 5)))),
        "E_NO_ORDER"
    );
}

#[test]
fn execute_order_happy_path_and_settle() {
    let mut c = with_automation();
    let id = place_buy(&mut c, NEAR, 5);
    exec_order(&mut c, id, order_buy_ops(NEAR, 6)); // better than the order's min_out is fine
    assert!(c.get_order(U64(id)).unwrap().pending);
    assert_eq!(c.day.spent_yocto, NEAR + NEAR / 100 + 1_250_000_000_000_000_000_000, "counted when executed");
    let rs = get_created_receipts();
    let cb = rs.iter().find(|r| r.receiver_id == me()).unwrap();
    match &cb.actions[0] {
        MockAction::FunctionCallWeight { args, .. } => {
            let v: near_sdk::serde_json::Value = near_sdk::serde_json::from_slice(args).unwrap();
            assert_eq!(v["order_id"], id.to_string());
            assert_eq!(v["client_order_id"], format!("order:{id}"));
        }
        x => panic!("{x:?}"),
    }
    // exactly once: pending order can't be executed again
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| exec_order(&mut c, id, order_buy_ops(NEAR, 6)))),
        "E_ORDER_PENDING"
    );
    // swap failed (used 0) -> reopened, spend returned
    settle_order(&mut c, ok_json(0), id);
    assert!(!c.get_order(U64(id)).unwrap().pending);
    assert_eq!(c.day.spent_yocto, 1_250_000_000_000_000_000_000);
    // retry succeeds -> filled and removed
    exec_order(&mut c, id, order_buy_ops(NEAR, 5));
    settle_order(&mut c, ok_json(NEAR), id);
    assert!(c.get_order(U64(id)).is_none());
    assert!(get_logs().iter().any(|l| l.contains("order_filled")));
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| exec_order(&mut c, id, order_buy_ops(NEAR, 5)))),
        "E_NO_ORDER"
    );
}

fn settle_order(c: &mut TradingAccount, result: PromiseResult, id: u64) {
    testing_env!(
        VMContextBuilder::new()
            .current_account_id(me())
            .predecessor_account_id(me())
            .storage_usage(STORAGE_BYTES)
            .account_balance(NearToken::from_yoctonear(10 * NEAR))
            .block_timestamp(T0 + 3)
            .build(),
        near_sdk::test_vm_config(),
        near_sdk::RuntimeFeesConfig::test(),
        Default::default(),
        vec![result],
    );
    c.on_swap_settled(
        format!("order:{id}"),
        U128(NEAR),
        U128(NEAR),
        U128(NEAR / 100),
        U64(D0),
        Some(U64(id)),
        None,
        None,
        None,
    );
}

#[test]
fn execute_order_rejections() {
    type Case = (&'static str, Box<dyn Fn(&mut TradingAccount, u64)>);
    let cases: Vec<Case> = vec![
        (
            // v1.4.1 (D6) sell-only; v1.4.7: relayer buys are bounded by the weekly allowance
            "E_RELAYER_WEEKLY",
            Box::new(|c, id| {
                ctx_pk(me().as_str(), Some(auto_pk()), 0, T0 + 2);
                near_sdk::env::storage_write(b"ra", &0u128.to_le_bytes());
                c.execute_order(U64(id), order_buy_ops(NEAR, 5));
            }),
        ),
        (
            "E_NOT_SELF",
            Box::new(|c, id| {
                ctx_pk("evil.near", Some(auto_pk()), 0, T0 + 2);
                c.execute_order(U64(id), order_buy_ops(NEAR, 5));
            }),
        ),
    ];
    for (code, f) in cases {
        let mut c = with_automation();
        let id = place_buy(&mut c, NEAR, 5);
        let msg = panics(std::panic::AssertUnwindSafe(|| f(&mut c, id)));
        assert_eq!(msg, code);
        let _ = c.get_order(U64(id));
    }
    // a device key (tab runner) may execute a buy order, with or without a relayer installed
    let mut c = new_account();
    let id = place_buy(&mut c, NEAR, 5);
    exec_order(&mut c, id, order_buy_ops(NEAR, 5));
    assert!(c.get_order(U64(id)).unwrap().pending);
}

// ======================= v1.4.1: D5 (UTC day) and D6 (sell-only relayer) =======================

const DAY: u64 = 86_400 * NS_PER_SEC;

fn place_sell(c: &mut TradingAccount, amount: u128, min_out: u128) -> u64 {
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
    c.place_order(
        a("meme.near"),
        a("wrap.near"),
        U128(amount),
        U128(min_out),
        r#"{"kind":"tp"}"#.into(),
        U64(T0 + 30 * DAY),
        vec![a("v2.ref-finance.near")],
    )
    .0
}

fn order_sell_ops(amount: u128, min_out: u128) -> Vec<Op> {
    vec![Op::FtTransferCall {
        token: a("meme.near"),
        receiver_id: a("v2.ref-finance.near"),
        amount: U128(amount),
        msg: rhea_msg("meme.near", "wrap.near", min_out),
        gas: U64(150 * TGAS),
    }]
}

fn relayer_fire(c: &mut TradingAccount, id: u64, amount: u128, min_out: u128, now: u64) {
    ctx_pk(me().as_str(), Some(auto_pk()), 0, now);
    c.execute_order(U64(id), order_sell_ops(amount, min_out));
}

#[test]
fn d5_utc_day_window_and_migration() {
    // pure rules
    let midnight = D0 + DAY;
    let mut d = Day { start_ns: D0, spent_yocto: 7 };
    roll_day(&mut d, midnight - 1);
    assert_eq!(d, Day { start_ns: D0, spent_yocto: 7 }, "same UTC day");
    roll_day(&mut d, midnight);
    assert_eq!(d, Day { start_ns: midnight, spent_yocto: 0 }, "resets exactly at 00:00 UTC");
    // legacy (pre-v1.4.1) rolling window started yesterday 20:00, still live: spent kept today
    let legacy = D0 - 4 * 3_600 * NS_PER_SEC;
    let mut d = Day { start_ns: legacy, spent_yocto: 9 };
    roll_day(&mut d, D0 + 3_600 * NS_PER_SEC);
    assert_eq!(d, Day { start_ns: D0, spent_yocto: 9 });
    roll_day(&mut d, midnight);
    assert_eq!(d.spent_yocto, 0);
    // expired legacy window: reset
    let mut d = Day { start_ns: D0 - DAY - 1, spent_yocto: 9 };
    roll_day(&mut d, D0 + 1);
    assert_eq!(d, Day { start_ns: D0, spent_yocto: 0 });
    // contract: a new account's window starts at 00:00 UTC; view shows the reset time
    let mut c = new_account();
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
    exec(&mut c, buy(NEAR), "o1", 2 * NEAR);
    let v = c.get_day();
    assert_eq!((v.start_ns.0, v.resets_at_ns.0), (D0, midnight));
    ctx(me().as_str(), 0, 10 * NEAR, midnight);
    assert_eq!(c.get_day().spent_yocto.0, 0, "reset at 00:00 UTC, not 24 h after the first spend");
    // withdraw window too
    assert_eq!(c.get_withdraw_day().resets_at_ns.0, midnight + DAY);
}

#[test]
fn d5_legacy_gas_tally_carries_into_utc_day() {
    let mut c = new_account();
    // simulate a v1.3.2 state: rolling window from yesterday 20:00 with spend + gas tally
    let legacy = D0 - 4 * 3_600 * NS_PER_SEC;
    c.day = Day { start_ns: legacy, spent_yocto: NEAR };
    let mut v = legacy.to_le_bytes().to_vec();
    v.extend_from_slice(&(NEAR / 10).to_le_bytes());
    env::storage_write(b"gd", &v);
    ctx(me().as_str(), 0, 10 * NEAR, D0 + 1);
    let d = c.get_day();
    assert_eq!((d.start_ns.0, d.spent_yocto.0, d.gas_spent_yocto.0), (D0, NEAR, NEAR / 10));
    ctx(me().as_str(), 0, 10 * NEAR, D0 + DAY);
    let d = c.get_day();
    assert_eq!((d.spent_yocto.0, d.gas_spent_yocto.0), (0, 0));
}

#[test]
fn d6_relayer_sell_only_and_weekly_allowance() {
    let mut c = with_automation_weekly(V147_DEFAULT_WEEKLY);
    ctx(me().as_str(), 0, 10 * NEAR, T0);
    let v = c.get_relayer_week();
    assert_eq!(v.allowance_yocto, Some(U128(V147_DEFAULT_WEEKLY)));
    // T0 is a Friday: the ISO week starts Monday 00:00 UTC
    assert_eq!(v.start_ns.0, iso_week_start(T0));
    assert_eq!((v.start_ns.0 / DAY + 3) % 7, 0, "Monday");
    assert!(v.start_ns.0 <= T0 && T0 < v.resets_at_ns.0 && v.resets_at_ns.0 - v.start_ns.0 == 7 * DAY);
    // sells fire; min_out counts
    let s1 = place_sell(&mut c, 10u128.pow(24), 6 * NEAR);
    relayer_fire(&mut c, s1, 10u128.pow(24), 6 * NEAR, T0 + 2);
    assert_eq!(c.get_relayer_week().spent_yocto.0, 6 * NEAR);
    // 6 + 5 > 10: refused, nothing counted
    let s2 = place_sell(&mut c, 10u128.pow(24), 5 * NEAR);
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| relayer_fire(&mut c, s2, 10u128.pow(24), 5 * NEAR, T0 + 3))),
        "E_RELAYER_WEEKLY"
    );
    assert_eq!(c.get_relayer_week().spent_yocto.0, 6 * NEAR);
    // the device key can still run it (tab runner), uncounted
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 4);
    c.execute_order(U64(s2), order_sell_ops(10u128.pow(24), 5 * NEAR));
    assert_eq!(c.get_relayer_week().spent_yocto.0, 6 * NEAR);
    // owner raises the allowance
    ctx("owner.near", 1, 10 * NEAR, T0 + 5);
    c.owner_set_relayer_allowance(U128(20 * NEAR));
    assert_eq!(c.get_relayer_week().allowance_yocto, Some(U128(20 * NEAR)));
    // resets next Monday 00:00 UTC
    let next = c.get_relayer_week().resets_at_ns.0;
    ctx(me().as_str(), 0, 10 * NEAR, next);
    assert_eq!(c.get_relayer_week().spent_yocto.0, 0);
    // device may not set the allowance
    let mut c2 = with_automation();
    ctx(me().as_str(), 0, 10 * NEAR, T0);
    assert_eq!(panics(move || c2.owner_set_relayer_allowance(U128(u128::MAX))), "E_NOT_OWNER");
}

#[test]
fn d6_failed_relayer_fire_returns_allowance() {
    let mut c = with_automation_weekly(V147_DEFAULT_WEEKLY);
    let floor = V147_DEFAULT_WEEKLY / MAX_RELAYER_FIRES_PER_WEEK;
    let s1 = place_sell(&mut c, 10u128.pow(24), 4 * NEAR);
    relayer_fire(&mut c, s1, 10u128.pow(24), 4 * NEAR, T0 + 2);
    let rs = get_created_receipts();
    let cb = rs.iter().find(|r| r.receiver_id == me()).unwrap();
    let args: near_sdk::serde_json::Value = match &cb.actions[0] {
        MockAction::FunctionCallWeight { args, .. } => near_sdk::serde_json::from_slice(args).unwrap(),
        x => panic!("{x:?}"),
    };
    // v1.4.8 (RA7-1): only the part above the floor is refundable
    assert_eq!(args["relayer_counted"], (4 * NEAR - floor).to_string());
    let wk = args["relayer_week"].as_str().unwrap().parse::<u64>().unwrap();
    // swap failed (provable) -> order reopened and the allowance returned
    testing_env!(
        VMContextBuilder::new()
            .current_account_id(me())
            .predecessor_account_id(me())
            .storage_usage(STORAGE_BYTES)
            .account_balance(NearToken::from_yoctonear(10 * NEAR))
            .block_timestamp(T0 + 5)
            .build(),
        near_sdk::test_vm_config(),
        near_sdk::RuntimeFeesConfig::test(),
        Default::default(),
        vec![PromiseResult::Failed],
    );
    c.on_swap_settled(
        format!("order:{s1}"),
        U128(10u128.pow(24)),
        U128(0),
        U128(NEAR / 100),
        U64(D0),
        Some(U64(s1)),
        Some(U64(wk)),
        Some(U128(4 * NEAR - floor)),
        None,
    );
    assert!(!c.get_order(U64(s1)).unwrap().pending, "reopened");
    // the floor stays charged (<= 20 fires per week, failures included)
    assert_eq!(c.get_relayer_week().spent_yocto.0, floor);
}

#[test]
fn automation_key_cannot_use_device_methods() {
    let mut c = with_automation();
    ctx_pk(me().as_str(), Some(auto_pk()), 0, T0 + 1);
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| exec(&mut c, buy(NEAR), "x", 2 * NEAR))),
        "E_AUTOMATION_KEY"
    );
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| c.withdraw_to_owner(None, U128(1)))),
        "E_AUTOMATION_KEY"
    );
    assert_eq!(panics(std::panic::AssertUnwindSafe(|| c.lower_caps(caps(1, 1)))), "E_AUTOMATION_KEY");
    assert_eq!(panics(std::panic::AssertUnwindSafe(|| c.revoke_automation())), "E_AUTOMATION_KEY");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]
    /// A compromised automation key can only execute EXISTING open orders, exactly as placed
    /// (input token/amount, order DEX, output token, parsed min_out >= order.min_out), once
    /// at a time; nothing else moves.
    #[test]
    fn compromised_automation_key(attempts in prop::collection::vec((0u64..6, prop::collection::vec(arb_op(), 0..5)), 1..30)) {
        let mut c = with_automation();
        let placed: Vec<(u64, Order)> = (0..3).map(|i| {
            let id = place_buy(&mut c, NEAR / 2 + i as u128, 1_000 + i as u128);
            (id, c.get_order(U64(id)).unwrap())
        }).collect();
        for (oid, ops) in attempts {
            let before = c.get_order(U64(oid));
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut c2 = TradingAccount { seen_orders: c.seen_orders.clone(), day: c.day.clone(), caps: c.caps.clone(), fee: c.fee.clone(), dex_allowlist: c.dex_allowlist.clone(), wrap: c.wrap.clone(), owner: c.owner.clone() };
                exec_order(&mut c2, oid, ops.clone());
                c2
            }));
            match r {
                Ok(c2) => {
                    let o = before.expect("executed a non-existent order");
                    prop_assert!(!o.pending, "executed a pending order twice");
                    prop_assert!(placed.iter().any(|(i, p)| *i == oid && p == &o));
                    let swaps: Vec<&Op> = ops.iter().filter(|op| matches!(op, Op::FtTransferCall { .. } | Op::PlachDepositNear { .. })).collect();
                    prop_assert_eq!(swaps.len(), 1);
                    if let Op::FtTransferCall { token, receiver_id, amount, msg, .. } = swaps[0] {
                        prop_assert_eq!(token, &o.token_in);
                        prop_assert_eq!(amount.0, o.amount_in.0);
                        prop_assert!(o.dexes.contains(receiver_id));
                        let kind = c.dex_kind(receiver_id).unwrap();
                        let s = msg::parse(kind, msg, &Ctx { self_id: &me(), wrap: &a("wrap.near"), token_in: token, referrer: &a("fees.near") }).unwrap();
                        prop_assert!(s.min_out >= o.min_out.0 && s.out == o.token_out.as_str());
                    }
                    for op in &ops {
                        let allowed = matches!(op, Op::FtTransferCall { .. } | Op::PlachDepositNear { .. } | Op::StorageDeposit { .. } | Op::PlachRegisterAssets { .. } | Op::NearDeposit { .. });
                        prop_assert!(allowed, "op kind not allowed for orders");
                    }
                    prop_assert!(c2.day.spent_yocto <= c2.caps.daily_cap_yocto.0);
                    c = c2;
                }
                Err(_) => {
                    // mocked storage is not rolled back on panic; restore the order record
                    if let Some(o) = &before { save_order(oid, o); }
                }
            }
        }
    }
}

#[test]
fn compromised_key_valid_execution_is_reachable() {
    // sanity for the proptest above: a matching attempt does succeed
    let mut c = with_automation();
    let id = place_buy(&mut c, NEAR / 2, 1_000);
    exec_order(&mut c, id, order_buy_ops(NEAR / 2, 1_000));
    assert!(c.get_order(U64(id)).unwrap().pending);
}

// ======================= v1.2.1 hardening (audit) =======================

#[test]
fn hardening_storage_deposit_targets() {
    let st = U128(1_250_000_000_000_000_000_000);
    // alone: only wrap / allowlisted DEXes
    for (tok, ok_) in
        [("evil.near", false), ("meme.near", false), ("wrap.near", true), ("dex.intear.near", true)]
    {
        let mut c = new_account();
        ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            exec(&mut c, vec![Op::StorageDeposit { token: a(tok), amount: st }], "s", NEAR)
        }));
        assert_eq!(r.is_ok(), ok_, "{tok}");
    }
    // with a swap: its input and output token become valid targets, others don't
    let mut c = new_account();
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
    let mut ops = vec![Op::StorageDeposit { token: a("meme.near"), amount: st }];
    ops.extend(buy(NEAR / 10));
    exec(&mut c, ops, "b", NEAR);
    let mut ops = vec![Op::StorageDeposit { token: a("evil.near"), amount: st }];
    ops.extend(buy(NEAR / 10));
    assert_eq!(panics(std::panic::AssertUnwindSafe(|| exec(&mut c, ops, "c", NEAR))), "E_STORAGE_TARGET");
}

#[test]
fn hardening_referrer_must_be_platform() {
    for (m, ok_) in [
        (
            rhea_msg("wrap.near", "meme.near", 5)
                .replace(r#""force":0"#, r#""force":0,"referral_id":"evil.near""#),
            false,
        ),
        (
            rhea_msg("wrap.near", "meme.near", 5)
                .replace(r#""force":0"#, r#""force":0,"referral_id":"fees.near""#),
            true,
        ),
        (rhea_msg("wrap.near", "meme.near", 5), true),
    ] {
        let mut c = new_account();
        ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
        let mut ops = buy(NEAR / 10);
        if let Op::FtTransferCall { msg, .. } = &mut ops[1] {
            *msg = m.clone();
        }
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| exec(&mut c, ops, "r", NEAR)));
        assert_eq!(r.is_ok(), ok_, "{m}");
    }
    let mut c = new_account();
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
    let mut ops = plach_buy_ops(NEAR / 10, 7);
    if let Op::PlachDepositNear { msg, .. } = &mut ops[3] {
        *msg = msg.replace("fees.near", "evil.near");
    }
    assert_eq!(panics(std::panic::AssertUnwindSafe(|| exec(&mut c, ops, "p", NEAR))), "E_REFERRER");
    let dcl = r#"{"Swap":{"pool_ids":["p"],"output_token":"meme.near","min_output_amount":"5","referral_id":"evil.near"}}"#;
    assert_eq!(ctx_parse(DexKind::RheaDcl, dcl, "wrap.near"), Err("E_REFERRER"));
}

#[test]
fn hardening_swap_gas_caps_per_kind() {
    for (dex, g, ok_) in [
        ("v2.ref-finance.near", MAX_SWAP_GAS_RHEA, true),
        ("v2.ref-finance.near", MAX_SWAP_GAS_RHEA + 1, false),
        ("dclv2.ref-labs.near", MAX_SWAP_GAS_DCL + 1, false),
    ] {
        let mut c = new_account();
        ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
        let msg = if dex.starts_with("dcl") {
            r#"{"Swap":{"pool_ids":["p"],"output_token":"x.near","min_output_amount":"5"}}"#.to_string()
        } else {
            rhea_msg("meme.near", "x.near", 5)
        };
        let ops = vec![Op::FtTransferCall {
            token: a("meme.near"),
            receiver_id: a(dex),
            amount: U128(1),
            msg,
            gas: U64(g * TGAS),
        }];
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| exec(&mut c, ops, "g", 0)));
        assert_eq!(r.is_ok(), ok_, "{dex} {g}");
    }
}

#[test]
fn hardening_gas_counts_toward_daily_cap() {
    // a zero-spend op sequence (sell into a non-NEAR token) still consumes the daily cap
    let mut c = new_account();
    ctx("owner.near", 1, 10 * NEAR, T0);
    c.owner_set_caps(caps(NEAR, NEAR / 10));
    let ops = || {
        vec![Op::FtTransferCall {
            token: a("gasburner.near"),
            receiver_id: a("v2.ref-finance.near"),
            amount: U128(1),
            msg: rhea_msg("gasburner.near", "x.near", 5),
            gas: U64(200 * TGAS),
        }]
    };
    let mut n = 0;
    loop {
        ctx(me().as_str(), 0, 10 * NEAR, T0 + 1 + n);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            exec(&mut c, ops(), &format!("g{n}"), 0)
        }));
        if r.is_err() {
            break;
        }
        n += 1;
        assert!(n < 100, "gas burn not bounded by the daily cap");
    }
    let d = c.get_day();
    assert_eq!(d.spent_yocto.0, 0);
    assert!(d.gas_spent_yocto.0 <= NEAR / 10 && d.gas_spent_yocto.0 > 0);
    let per = 300 * TGAS as u128 * GAS_PRICE_BOUND; // A1-F1: whole prepaid gas
    assert_eq!(n as u128, NEAR / 10 / per, "exactly floor(cap / per-execute gas) executes");
    // withdraw_to_owner(ft) is charged too (43 TGas each) and refused once the cap is used;
    // v1.4.3 (CAPACCT-001): so is its storage deposit to the token (MAX_STORAGE_DEPOSIT)
    let left = NEAR / 10 - d.gas_spent_yocto.0;
    let w = 43 * TGAS as u128 * GAS_PRICE_BOUND; // v1.3.2: register + transfer + report
    for i in 0..(left / (w + MAX_STORAGE_DEPOSIT)) {
        ctx(me().as_str(), 0, 10 * NEAR, T0 + 1_000 + i as u64);
        c.withdraw_to_owner(Some(a("gasburner.near")), U128(1));
    }
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 2_000);
    assert_eq!(
        panics(std::panic::AssertUnwindSafe(|| c.withdraw_to_owner(Some(a("gasburner.near")), U128(1)))),
        "E_CAP_DAILY"
    );
    // new window: tally resets
    ctx(me().as_str(), 0, 10 * NEAR, T0 + DAY_NS + 5);
    c.withdraw_to_owner(Some(a("gasburner.near")), U128(1));
    assert_eq!(c.get_day().gas_spent_yocto.0, 43 * TGAS as u128 * GAS_PRICE_BOUND);
    assert_eq!(c.get_day().spent_yocto.0, MAX_STORAGE_DEPOSIT);
}

// ======================= A1 audit regressions (ported from audit/a1-contracts) =======================

/// A1-F1 (u01): the swap receives exactly its declared gas (weight 0) and the WHOLE prepaid
/// gas is charged, so nothing reachable by a hostile token escapes the daily cap.
#[test]
fn a1_u01_swap_leftover_gas_is_charged() {
    let mut c = new_account();
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
    let ops = vec![Op::FtTransferCall {
        token: a("burner.near"),
        receiver_id: a("v2.ref-finance.near"),
        amount: U128(1),
        msg: rhea_msg("burner.near", "x.near", 1),
        gas: U64(MIN_SWAP_GAS * TGAS),
    }];
    exec(&mut c, ops, "g", 0);
    let mut weights = vec![];
    for r in get_created_receipts() {
        for act in r.actions {
            if let MockAction::FunctionCallWeight { gas_weight, .. } = act {
                weights.push(gas_weight.0);
            }
        }
    }
    assert!(weights.iter().all(|w| *w == 0), "no call may receive leftover gas: {weights:?}");
    assert_eq!(c.get_day().gas_spent_yocto.0, 300 * TGAS as u128 * GAS_PRICE_BOUND, "whole prepaid charged");
    // declarations below the minimum are refused
    let mut c = new_account();
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
    let ops = vec![Op::FtTransferCall {
        token: a("burner.near"),
        receiver_id: a("v2.ref-finance.near"),
        amount: U128(1),
        msg: rhea_msg("burner.near", "x.near", 1),
        gas: U64(TGAS),
    }];
    assert_eq!(panics(std::panic::AssertUnwindSafe(|| exec(&mut c, ops, "h", 0))), "E_GAS");
}

/// A1-F5 (u02): one execute_order wraps at most amount_in in total.
#[test]
fn a1_u02_order_total_wrap_bounded_by_amount_in() {
    let mut c = with_automation();
    let id = place_buy(&mut c, NEAR / 2, 5);
    let mut ops = vec![Op::NearDeposit { amount: U128(NEAR / 4) }; 3];
    ops.push(Op::FtTransferCall {
        token: a("wrap.near"),
        receiver_id: a("v2.ref-finance.near"),
        amount: U128(NEAR / 2),
        msg: rhea_msg("wrap.near", "meme.near", 5),
        gas: U64(150 * TGAS),
    });
    assert_eq!(panics(std::panic::AssertUnwindSafe(|| exec_order(&mut c, id, ops))), "E_ORDER_OPS");
    // exactly amount_in split over two wraps is fine
    let mut c = with_automation();
    let id = place_buy(&mut c, NEAR / 2, 5);
    let mut ops = vec![Op::NearDeposit { amount: U128(NEAR / 4) }; 2];
    ops.push(Op::FtTransferCall {
        token: a("wrap.near"),
        receiver_id: a("v2.ref-finance.near"),
        amount: U128(NEAR / 2),
        msg: rhea_msg("wrap.near", "meme.near", 5),
        gas: U64(150 * TGAS),
    });
    exec_order(&mut c, id, ops);
}

/// A1-F3 (u03): Plach final-asset Withdraw must follow the final swap.
#[test]
fn a1_u03_plach_withdraw_must_follow_final_swap() {
    let (me_, wrap, r) = (me(), a("wrap.near"), a("fees.near"));
    let swap = r#"{"SwapSimple":{"dex_id":"d","message":"","asset_in":"near","asset_out":"nep141:meme.near","amount":{"Amount":{"ExactIn":"100"}},"constraint":"1000"}}"#;
    for w in [
        r#"{"Withdraw":{"asset_id":"nep141:meme.near","amount":{"Full":{"at_least":null}}}}"#,
        r#"{"Withdraw":{"asset_id":"nep141:meme.near","amount":{"Exact":"1000"}}}"#,
    ] {
        let m = format!(r#"{{"operations":[{w},{swap}]}}"#);
        assert_eq!(msg::parse_plach_near(&m, &me_, &wrap, &r), Err("E_BAD_MSG"), "{m}");
        let ok_ = format!(r#"{{"operations":[{swap},{w}]}}"#);
        assert!(msg::parse_plach_near(&ok_, &me_, &wrap, &r).is_ok());
    }
}

/// A1-F6 (u04), clamp semantics: lower_caps below the current window's spend is allowed (the
/// device may always lower); `spent` is kept (it is history) and NO further execute is
/// accepted in that window (effective remaining = max(0, cap - spent - gas_spent)).
#[test]
fn a1_u04_lower_caps_below_spent_blocks_further_spend() {
    let mut c = new_account();
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
    exec(&mut c, buy(NEAR), "b", 2 * NEAR);
    let spent = c.get_day().spent_yocto.0;
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 2);
    c.lower_caps(caps(1, 1));
    assert_eq!(c.get_day().spent_yocto.0, spent);
    for (i, ops) in [buy(1), vec![Op::NearDeposit { amount: U128(1) }]].into_iter().enumerate() {
        ctx(me().as_str(), 0, 10 * NEAR, T0 + 3 + i as u64);
        let m = panics(std::panic::AssertUnwindSafe(|| exec(&mut c, ops, &format!("c{i}"), 1)));
        assert!(m == "E_CAP_DAILY" || m == "E_CAP_TRADE", "{m}");
    }
}

/// A1-F4 (u07): an order reopens only on a PROVABLE refund. A user-chosen token_in reporting
/// "0" leaves the order consumed (can't be refilled); wrap.near "0" or a failed batch reopens.
#[test]
fn a1_u07_order_reopens_only_on_provable_refund() {
    // sell order of a (possibly non-standard) token
    let sell_order = |c: &mut TradingAccount| {
        big_ctx(me().as_str(), T0 + 1);
        c.place_order(
            a("meme.near"),
            a("wrap.near"),
            U128(1000),
            U128(5),
            String::new(),
            U64(T0 + 3_600 * NS_PER_SEC),
            vec![a("v2.ref-finance.near")],
        )
        .0
    };
    let sell_ops = || {
        vec![Op::FtTransferCall {
            token: a("meme.near"),
            receiver_id: a("v2.ref-finance.near"),
            amount: U128(1000),
            msg: rhea_msg("meme.near", "wrap.near", 5),
            gas: U64(150 * TGAS),
        }]
    };
    let mut c = with_automation();
    let id = sell_order(&mut c);
    exec_order(&mut c, id, sell_ops());
    settle_order(&mut c, ok_json(0), id);
    assert!(c.get_order(U64(id)).is_none(), "non-wrap token_in reporting 0 must not reopen");
    assert!(get_logs().iter().any(|l| l.contains("order_consumed_unproven_refund")));
    // failed batch (runtime revert) is a provable refund -> reopened
    let mut c = with_automation();
    let id = sell_order(&mut c);
    exec_order(&mut c, id, sell_ops());
    settle_order(&mut c, PromiseResult::Failed, id);
    assert!(!c.get_order(U64(id)).unwrap().pending);
    // wrap.near (buy order) reporting 0 -> reopened
    let mut c = with_automation();
    let id = place_buy(&mut c, NEAR, 5);
    exec_order(&mut c, id, order_buy_ops(NEAR, 5));
    settle_order(&mut c, ok_json(0), id);
    assert!(!c.get_order(U64(id)).unwrap().pending);
}

/// A1 u05 (ported): settlement completes whatever size the swap result is (order never stuck).
#[test]
fn a1_u05_settle_completes_for_any_result_size() {
    for size in [128usize, 100_000, 1_000_000, 3_000_000] {
        let mut c = with_automation();
        let id = place_buy(&mut c, NEAR / 2, 5);
        exec_order(&mut c, id, order_buy_ops(NEAR / 2, 5));
        let mut big = vec![b'0'; size];
        big[0] = b'"';
        big[size - 1] = b'"';
        testing_env!(
            VMContextBuilder::new()
                .current_account_id(me())
                .predecessor_account_id(me())
                .storage_usage(STORAGE_BYTES)
                .account_balance(NearToken::from_yoctonear(10 * NEAR))
                .block_timestamp(T0 + 3)
                .prepaid_gas(Gas::from_tgas(GAS_CALLBACK))
                .build(),
            near_sdk::test_vm_config(),
            near_sdk::RuntimeFeesConfig::test(),
            Default::default(),
            vec![PromiseResult::Successful(big)],
        );
        c.on_swap_settled(
            format!("order:{id}"),
            U128(NEAR / 2),
            U128(NEAR / 2),
            U128(NEAR / 200),
            U64(D0),
            Some(U64(id)),
            None,
            None,
            None,
        );
        // settlement ran: never left Pending ("000..0" = 0 used -> wNEAR order reopened;
        // oversized result = success, all used -> filled)
        assert!(c.get_order(U64(id)).is_none_or(|o| !o.pending), "{size}: order left Pending");
    }
}

/// A1 u06 (ported): a Pending order pruned after expiry is never reopened by a late settle.
#[test]
fn a1_u06_pruned_pending_order_is_not_resurrected() {
    let mut c = with_automation();
    big_ctx(me().as_str(), T0 + 1);
    let id = c
        .place_order(
            a("wrap.near"),
            a("meme.near"),
            U128(NEAR / 2),
            U128(5),
            String::new(),
            U64(T0 + 10),
            vec![a("v2.ref-finance.near")],
        )
        .0;
    exec_order(&mut c, id, order_buy_ops(NEAR / 2, 5));
    big_ctx(me().as_str(), T0 + 100);
    c.place_order(
        a("wrap.near"),
        a("meme.near"),
        U128(1),
        U128(1),
        String::new(),
        U64(T0 + 3_600 * NS_PER_SEC),
        vec![a("v2.ref-finance.near")],
    );
    assert!(c.get_order(U64(id)).is_none());
    for res in [PromiseResult::Failed, ok_json(0)] {
        settle_order(&mut c, res, id);
        assert!(c.get_order(U64(id)).is_none(), "reopened a pruned order");
    }
}

mod audit_a;
mod intents;
mod v143;
mod v144;
mod v145;
mod v146;
mod v147;
mod v147_init;
mod v148;

// ======================= v1.4.2: re-audit C1 =======================

/// Fires a stored BUY with `pk`. v1.4.7: relayer buys are allowed but charged in full to the
/// weekly relayer allowance, which is set to 0 here: a relayer (role-set member) gets
/// E_RELAYER_WEEKLY, a device key is never weekly-charged.
fn buy_fire_by(c: &mut TradingAccount, pk: PublicKey, id: u64) -> String {
    ctx_pk(me().as_str(), Some(pk), 0, T0 + 2);
    near_sdk::env::storage_write(b"ra", &0u128.to_le_bytes());
    panics(std::panic::AssertUnwindSafe(|| c.execute_order(U64(id), order_buy_ops(NEAR, 5))))
}

fn key_cb(result: PromiseResult) {
    testing_env!(
        VMContextBuilder::new().current_account_id(me()).predecessor_account_id(me()).build(),
        near_sdk::test_vm_config(),
        near_sdk::RuntimeFeesConfig::test(),
        Default::default(),
        vec![result],
    );
}

/// C1-M1 (revoke window): the revoked key stays a relayer (sell-only, no device methods) until
/// its DeleteKey is confirmed by on_relayer_key_deleted.
#[test]
fn c1_m1_revoked_relayer_stays_relayer_until_deletion_confirmed() {
    for by_owner in [true, false] {
        let mut c = with_automation();
        let id = place_buy(&mut c, NEAR, 5);
        if by_owner {
            ctx("owner.near", 1, 10 * NEAR, T0 + 1);
            c.owner_revoke_automation();
        } else {
            ctx(me().as_str(), 0, 10 * NEAR, T0 + 1);
            c.revoke_automation();
        }
        let rs = get_created_receipts();
        assert!(format!("{:?}", rs[0].actions[0]).starts_with("DeleteKey"), "{rs:?}");
        assert_eq!(rs.len(), 2, "DeleteKey + on_relayer_key_deleted");
        assert_eq!(c.get_automation_key(), None);
        assert_eq!(c.get_relayer_keys(), vec![auto_pk()]);
        // in the window: still the relayer
        assert_eq!(buy_fire_by(&mut c, auto_pk(), id), "E_RELAYER_WEEKLY");
        ctx_pk(me().as_str(), Some(auto_pk()), 0, T0 + 3);
        assert_eq!(panics(std::panic::AssertUnwindSafe(|| c.lower_caps(caps(0, 0)))), "E_AUTOMATION_KEY");
        // deletion failed -> still a relayer
        key_cb(PromiseResult::Failed);
        c.on_relayer_key_deleted(auto_pk());
        assert_eq!(c.get_relayer_keys(), vec![auto_pk()]);
        // deletion confirmed -> leaves the set
        key_cb(PromiseResult::Successful(vec![]));
        c.on_relayer_key_deleted(auto_pk());
        assert!(c.get_relayer_keys().is_empty());
    }
}

/// C1-M1 (rotation window): the NEW key is a relayer before on_automation_set; the OLD one
/// stays a relayer until the batch that deletes it is confirmed.
#[test]
fn c1_m1_rotation_pending_and_retired_keys_are_relayers() {
    let new_pk: PublicKey = "ed25519:DcA2MzgpJbrUATQLLceocVckhhAqrkingax4oJ9kZ847".parse().unwrap();
    for success in [true, false] {
        let mut c = with_automation();
        let id = place_buy(&mut c, NEAR, 5);
        ctx("owner.near", 1, 10 * NEAR, T0 + 1);
        c.owner_set_automation_key(new_pk.clone(), U128(NEAR));
        assert_eq!(c.get_relayer_keys(), vec![auto_pk(), new_pk.clone()]);
        assert_eq!(buy_fire_by(&mut c, new_pk.clone(), id), "E_RELAYER_WEEKLY");
        assert_eq!(buy_fire_by(&mut c, auto_pk(), id), "E_RELAYER_WEEKLY");
        // the owner can't make a relayer key a device key meanwhile
        ctx("owner.near", 1, 10 * NEAR, T0 + 1);
        let pk = new_pk.clone();
        assert_eq!(
            panics(std::panic::AssertUnwindSafe(|| c.owner_add_key(pk, KeyKind::FunctionCall))),
            "E_AUTOMATION_KEY"
        );
        key_cb(if success { PromiseResult::Successful(vec![]) } else { PromiseResult::Failed });
        c.on_automation_set(new_pk.clone(), Some(auto_pk()), Some(true));
        if success {
            assert_eq!(c.get_relayer_keys(), vec![new_pk.clone()]);
            assert_eq!(c.get_automation_key(), Some(new_pk.clone()));
        } else {
            assert_eq!(c.get_relayer_keys(), vec![auto_pk()]);
            assert_eq!(c.get_automation_key(), Some(auto_pk()));
        }
    }
}

/// C1-M1: the role set is bounded. v1.4.3 (ROLESET-001): only one change may be in flight, so
/// a second install before the first callback is refused (the set holds current + pending).
#[test]
fn c1_m1_role_set_bounded() {
    let mut c = with_automation();
    let pk = |i: u8| -> PublicKey {
        format!("ed25519:{}", near_sdk::bs58::encode([i; 32]).into_string()).parse().unwrap()
    };
    ctx("owner.near", 1, 10 * NEAR, T0 + 1);
    c.owner_set_automation_key(pk(1), U128(NEAR)); // callback never arrives
    assert_eq!(c.get_relayer_keys().len(), 2);
    for i in 2..MAX_RELAYER_KEYS as u8 + 2 {
        ctx("owner.near", 1, 10 * NEAR, T0 + 1);
        assert_eq!(
            panics(std::panic::AssertUnwindSafe(|| c.owner_set_automation_key(pk(i), U128(NEAR)))),
            "E_AUTOMATION_BUSY"
        );
    }
    assert_eq!(c.get_relayer_keys().len(), 2);
    // the bound itself still holds for sets written before v1.4.3
    let full: Vec<PublicKey> = (1..=MAX_RELAYER_KEYS as u8).map(pk).collect();
    near_sdk::env::storage_write(b"ar", &near_sdk::borsh::to_vec(&full).unwrap());
    near_sdk::env::storage_remove(b"ak");
    assert_eq!(
        panics(|| {
            relayer_role_add(&pk(99));
        }),
        "E_AUTOMATION_BUSY"
    );
}

/// C1-L3: a relayer fire costs max(min_out, allowance / 20): tiny-min_out orders can't fire
/// without limit.
#[test]
fn c1_l3_relayer_fire_floor() {
    let mut c = with_automation_weekly(V147_DEFAULT_WEEKLY);
    let floor = V147_DEFAULT_WEEKLY / MAX_RELAYER_FIRES_PER_WEEK;
    let mut fired = 0;
    for i in 0..25u64 {
        let id = place_sell(&mut c, 10u128.pow(24), 1);
        ctx_pk(me().as_str(), Some(auto_pk()), 0, T0 + 10 + i);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            c.execute_order(U64(id), order_sell_ops(10u128.pow(24), 1))
        }));
        if r.is_ok() {
            fired += 1;
        }
    }
    assert_eq!(fired, MAX_RELAYER_FIRES_PER_WEEK as usize);
    ctx(me().as_str(), 0, 10 * NEAR, T0 + 100);
    assert_eq!(c.get_relayer_week().spent_yocto.0, floor * MAX_RELAYER_FIRES_PER_WEEK);
    // a large order counts its min_out
    let mut c = with_automation_weekly(V147_DEFAULT_WEEKLY);
    let id = place_sell(&mut c, 10u128.pow(24), 3 * NEAR);
    relayer_fire(&mut c, id, 10u128.pow(24), 3 * NEAR, T0 + 2);
    assert_eq!(c.get_relayer_week().spent_yocto.0, 3 * NEAR);
}
