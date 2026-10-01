//! v1.6 venue unit tests + fuzz: every pad x buy/sell x NEAR/Q planned call (method, args,
//! deposit, gas, receiver, settle, spend/fee), negatives, claims, FtTransferCall parsers and the
//! settlement fee math. Native, no env.
use super::*;
use crate::msg::{DexKind, E_BAD_MSG, E_MIN_OUT, E_REFERRER};
use crate::msg_venues::{self, VCtx};
use crate::policy::bps;
use crate::venues::factory::{GAS_CB_NEARRR, GAS_NEARRR_BUY, GAS_TAX_VIEW};
use near_sdk::serde_json::{self, json, Value};
use proptest::prelude::*;

const NEAR: u128 = 1_000_000_000_000_000_000_000_000;
const T: u64 = 1_800_000_000_000_000_000;
const G: u64 = 100 * TGAS;
const FEE_BPS: u16 = 100;
const NEARRR_G: u64 = 230 * TGAS;

fn a(s: &str) -> AccountId {
    s.parse().unwrap()
}
fn me() -> AccountId {
    a("user.tt.near")
}
fn wrap() -> AccountId {
    a("wrap.near")
}
fn feer() -> AccountId {
    a("fees.near")
}

fn allow() -> Vec<Dex> {
    let d = |id: &str, kind: DexKind| Dex { id: a(id), kind };
    vec![
        d("v2.ref-finance.near", DexKind::RheaClassic),
        d("factory.shardsmarket.near", DexKind::ShardsToken),
        d("aidols.near", DexKind::AidolsCurve(AidolsPad::Near)),
        d("gra-fun.near", DexKind::AidolsCurve(AidolsPad::Near)),
        d("patata-monster.near", DexKind::AidolsCurve(AidolsPad::Patata)),
        d("launch.vistadev.near", DexKind::FactoryCurve(FactoryPad::VistaLaunch)),
        d("dex.vistadev.near", DexKind::FactoryCurve(FactoryPad::VistaDex)),
        d("nearrr-fun.near", DexKind::FactoryCurve(FactoryPad::Nearrr)),
        d("curve10.latedata9580.near", DexKind::FactoryCurve(FactoryPad::Nira)),
        d("meme-cooking.near", DexKind::FactoryCurve(FactoryPad::MemeCooking)),
        d("dragonpad.near", DexKind::FactoryCurve(FactoryPad::Dragonpad)),
        d("nearfunio.near", DexKind::TokenCurve(TokenPad::NearFun)),
        d("umbrafun.near", DexKind::TokenCurve(TokenPad::Umbra)),
        d("revshare-launch.near", DexKind::TokenCurve(TokenPad::RevShare)),
        d("nearmemefun.near", DexKind::TokenCurve(TokenPad::Nearmemefun)),
        d("token0.near", DexKind::TokenCurve(TokenPad::Token0)),
        d("chipfi.near", DexKind::TokenCurve(TokenPad::Chipfi)),
        d("npad.near", DexKind::TokenCurve(TokenPad::Npad)),
        d("exchange.kelytradevs.near", DexKind::Kelytra),
        // appended (indices above are referenced by Kelytra's DexIdx tests)
        d("gaypad.j1-racing.near", DexKind::AidolsCurve(AidolsPad::Jambo)),
        d("v1.whole-market.near", DexKind::AidolsCurve(AidolsPad::Neardog)),
        d("v2.whole-market.near", DexKind::AidolsCurve(AidolsPad::Neardog)),
    ]
}

fn ctx<'a>(me: &'a AccountId, wrap: &'a AccountId, order: Option<u128>) -> Ctx<'a> {
    Ctx { me, wrap, fee_bps: FEE_BPS, now_ns: T, order_min_out: order }
}

fn tr(venue: &str, market: Option<&str>, quote: Option<&str>, amount: u128, min_out: u128) -> CurveTrade {
    // a Nearrr buy chains view -> buy (185 TGas) -> settle: its op declares the whole chain
    let gas = if venue == "nearrr-fun.near" { NEARRR_G } else { G };
    CurveTrade {
        venue: a(venue),
        market: market.map(String::from),
        quote: quote.map(a),
        amount: U128(amount),
        min_out: U128(min_out),
        max_out: None,
        gas: U64(gas),
        setup: false,
    }
}

fn plan_t(buy: bool, t: &CurveTrade) -> Result<Plan, &'static str> {
    let (m, w) = (me(), wrap());
    plan(&allow(), buy, t, &ctx(&m, &w, None))
}

fn args(c: &Call) -> Value {
    serde_json::from_str(&c.args).unwrap()
}

/// Inner msg of an ft_transfer_call, parsed if JSON.
fn inner(c: &Call) -> Value {
    let s = args(c)["msg"].as_str().unwrap().to_string();
    serde_json::from_str(&s).unwrap_or(Value::String(s))
}

const DL_NS: u64 = T + 120_000_000_000;

fn one(p: &Plan) -> &Call {
    assert_eq!(p.calls.len(), 1);
    &p.calls[0]
}

// ======================= Aidols family =======================

/// The venue-planned registration that precedes an output (sandbox finding: an unregistered
/// Aidols buyer's input is kept by the factory and the output is lost).
fn assert_storage_call(c: &Call, token: &str) {
    assert_eq!(
        (c.receiver.as_str(), c.method, c.deposit, c.gas),
        (token, "storage_deposit", VENUE_STORAGE, GAS_VENUE_STORAGE * TGAS)
    );
    assert_eq!(args(c), json!({"account_id": "user.tt.near", "registration_only": true}));
}

#[test]
fn aidols_buy_near() {
    let p = plan_t(true, &tr("aidols.near", Some("aidol100.aidols.near"), None, NEAR, 5)).unwrap();
    assert_eq!(p.calls.len(), 2);
    assert_storage_call(&p.calls[0], "aidol100.aidols.near");
    let c = &p.calls[1];
    assert_eq!((c.receiver.as_str(), c.method, c.deposit, c.gas), ("wrap.near", "ft_transfer_call", 1, G));
    assert_eq!(
        args(c),
        json!({"receiver_id": "aidols.near", "amount": NEAR.to_string(),
            "msg": json!({"token": "aidol100.aidols.near", "min_swap_amount": "5"}).to_string()})
    );
    assert_eq!(p.settle, Settle::Wrap);
    assert_eq!(
        (p.spend, p.counted, p.fee, p.fee_cap, p.native_out),
        (NEAR + VENUE_STORAGE, NEAR, bps(NEAR, FEE_BPS), 0, 1 + VENUE_STORAGE)
    );
    assert_eq!(p.order_dex, a("aidols.near"));
    assert_eq!(p.token_in, wrap());
    assert_eq!(p.swap, Swap { out_is_near: false, min_out: 5, out: "aidol100.aidols.near".into() });
    assert!(p.orderable);
    assert_eq!(p.storage, vec![a("aidol100.aidols.near")]);
    assert_eq!(p.gas, G + GAS_VENUE_STORAGE * TGAS);
    // explicit wNEAR quote == NEAR
    let p2 =
        plan_t(true, &tr("aidols.near", Some("aidol100.aidols.near"), Some("wrap.near"), NEAR, 5)).unwrap();
    assert_eq!(p2, p);
}

#[test]
fn aidols_sell_near() {
    let p = plan_t(false, &tr("gra-fun.near", Some("fot.gra-fun.near"), None, 777, NEAR)).unwrap();
    let c = one(&p);
    assert_eq!((c.receiver.as_str(), c.method, c.deposit), ("fot.gra-fun.near", "ft_transfer_call", 1));
    assert_eq!(args(c)["receiver_id"], "gra-fun.near");
    assert_eq!(args(c)["amount"], "777");
    assert_eq!(inner(c), json!({"token": null, "min_swap_amount": NEAR.to_string()}));
    assert_eq!(p.settle, Settle::Token);
    assert_eq!((p.spend, p.counted, p.fee, p.fee_cap), (0, 0, bps(NEAR, FEE_BPS), NEAR));
    assert_eq!(p.token_in, a("fot.gra-fun.near"));
    assert_eq!(p.swap, Swap { out_is_near: true, min_out: NEAR, out: "wrap.near".into() });
    assert_eq!(p.storage, vec![a("fot.gra-fun.near"), wrap()]);
}

#[test]
fn aidols_sell_order_fee_uses_order_min_out() {
    let (m, w) = (me(), wrap());
    let t = tr("aidols.near", Some("x.aidols.near"), None, 777, 10 * NEAR);
    let p = plan(&allow(), false, &t, &ctx(&m, &w, Some(3 * NEAR))).unwrap();
    assert_eq!(p.fee, bps(3 * NEAR, FEE_BPS));
    assert_eq!(p.fee_cap, 3 * NEAR);
}

#[test]
fn patata_buy_sell_quote_patata() {
    let p = plan_t(true, &tr("patata-monster.near", Some("poop.patata-monster.near"), Some(PATATA), 5, 9))
        .unwrap();
    assert_eq!(p.calls.len(), 2);
    assert_storage_call(&p.calls[0], "poop.patata-monster.near");
    let c = &p.calls[1];
    assert_eq!(c.receiver.as_str(), PATATA);
    assert_eq!(args(c)["receiver_id"], "patata-monster.near");
    assert_eq!(inner(c), json!({"token": "poop.patata-monster.near", "min_swap_amount": "9"}));
    assert_eq!(p.settle, Settle::Token);
    // a Q buy counts only the registration as spend; no fee (not the NEAR leg)
    assert_eq!((p.spend, p.counted, p.fee), (VENUE_STORAGE, 0, 0));
    assert_eq!(p.token_in, a(PATATA));
    let s = plan_t(false, &tr("patata-monster.near", Some("poop.patata-monster.near"), Some(PATATA), 5, 9))
        .unwrap();
    // the PATATA payout needs a registration too (a wNEAR payout doesn't: init registers wrap)
    assert_eq!(s.calls.len(), 2);
    assert_storage_call(&s.calls[0], PATATA);
    assert_eq!(s.swap, Swap { out_is_near: false, min_out: 9, out: PATATA.into() });
    assert_eq!((s.fee, s.fee_cap, s.spend), (0, 0, VENUE_STORAGE));
    // NEAR is not patata's quote, PATATA is not aidols'
    assert_eq!(
        plan_t(true, &tr("patata-monster.near", Some("poop.patata-monster.near"), None, 5, 9)).unwrap_err(),
        E_QUOTE
    );
    assert_eq!(
        plan_t(true, &tr("aidols.near", Some("x.aidols.near"), Some(PATATA), 5, 9)).unwrap_err(),
        E_QUOTE
    );
}

#[test]
fn jambo_and_neardog_quotes() {
    for (f, tok, q) in [
        ("gaypad.j1-racing.near", "jhoot.gaypad.j1-racing.near", JAMBO),
        ("v1.whole-market.near", "test.v1.whole-market.near", NEARDOG),
        ("v2.whole-market.near", "test.v2.whole-market.near", NEARDOG),
    ] {
        let p = plan_t(true, &tr(f, Some(tok), Some(q), 5, 9)).unwrap();
        assert_eq!(p.calls[1].receiver.as_str(), q, "{f}");
        assert_eq!(args(&p.calls[1])["receiver_id"], f);
        assert_eq!((p.settle, p.fee, p.token_in.as_str()), (Settle::Token, 0, q));
        let s = plan_t(false, &tr(f, Some(tok), Some(q), 5, 9)).unwrap();
        assert_eq!(s.swap, Swap { out_is_near: false, min_out: 9, out: q.into() });
        assert_storage_call(&s.calls[0], q);
        // their only quote: NEAR, wNEAR and another pad's Q are refused
        for bad in [None, Some("wrap.near"), Some(PATATA)] {
            assert_eq!(plan_t(true, &tr(f, Some(tok), bad, 5, 9)).unwrap_err(), E_QUOTE, "{f} {bad:?}");
        }
        // the parser: buy paid in Q, sell pays Q
        let (m, w) = (me(), wrap());
        let (fid, qid, tid) = (a(f), a(q), a(tok));
        let buy = json!({"token": tok, "min_swap_amount": "9"}).to_string();
        let vc = VCtx { self_id: &m, wrap: &w, token_in: &qid, receiver: &fid, referrer: &w };
        assert_eq!(msg_venues::parse(DexKind::AidolsCurve(aidols_pad(f)), &buy, &vc).unwrap().out, tok);
        let vc = VCtx { self_id: &m, wrap: &w, token_in: &w, receiver: &fid, referrer: &w };
        assert_eq!(msg_venues::parse(DexKind::AidolsCurve(aidols_pad(f)), &buy, &vc).unwrap_err(), E_BAD_MSG);
        let sell = json!({"token": null, "min_swap_amount": "9"}).to_string();
        let vc = VCtx { self_id: &m, wrap: &w, token_in: &tid, receiver: &fid, referrer: &w };
        let sw = msg_venues::parse(DexKind::AidolsCurve(aidols_pad(f)), &sell, &vc).unwrap();
        assert_eq!((sw.out.as_str(), sw.out_is_near), (q, false));
    }
}

fn aidols_pad(f: &str) -> AidolsPad {
    match f {
        "gaypad.j1-racing.near" => AidolsPad::Jambo,
        "patata-monster.near" => AidolsPad::Patata,
        "aidols.near" | "gra-fun.near" => AidolsPad::Near,
        _ => AidolsPad::Neardog,
    }
}

#[test]
fn aidols_market_must_be_factory_token() {
    for m in
        [None, Some("x.gra-fun.near"), Some("a.b.aidols.near"), Some("aidols.near"), Some("X.aidols.near")]
    {
        assert_eq!(plan_t(true, &tr("aidols.near", m, None, 5, 9)).unwrap_err(), E_MARKET, "{m:?}");
    }
    let mut t = tr("aidols.near", Some("x.aidols.near"), None, 5, 9);
    t.max_out = Some(U128(10));
    assert_eq!(plan_t(true, &t).unwrap_err(), E_QUOTE);
}

// ======================= factory curves =======================

#[test]
fn vista_launch_buy_sell() {
    let p = plan_t(true, &tr("launch.vistadev.near", Some("v.launch.vistadev.near"), None, NEAR, 3)).unwrap();
    let c = one(&p);
    assert_eq!(
        (c.receiver.as_str(), c.method, c.deposit),
        ("launch.vistadev.near", "buy", NEAR + VISTA_BUY_STORAGE)
    );
    assert_eq!(args(c), json!({"token_id": "v.launch.vistadev.near", "min_out": "3"}));
    assert_eq!(p.settle, Settle::NearIn);
    assert_eq!(
        (p.spend, p.counted, p.fee, p.native_out),
        (NEAR + VISTA_BUY_STORAGE, NEAR, bps(NEAR, FEE_BPS), NEAR + VISTA_BUY_STORAGE)
    );
    assert_eq!(p.token_in, wrap());
    assert_eq!(p.swap.out, "v.launch.vistadev.near");
    let s = plan_t(false, &tr("launch.vistadev.near", Some("v.launch.vistadev.near"), None, 50, 7)).unwrap();
    let c = one(&s);
    assert_eq!((c.receiver.as_str(), c.method, c.deposit), ("v.launch.vistadev.near", "ft_transfer_call", 1));
    assert_eq!(args(c)["receiver_id"], "launch.vistadev.near");
    assert_eq!(inner(c), json!({"sell": {"min_out": "7"}}));
    assert_eq!(s.settle, Settle::Token);
    assert!(s.swap.out_is_near);
    assert_eq!(s.fee, bps(7, FEE_BPS));
}

fn vista_dex_market() -> &'static str {
    "v.launch.vistadev.near"
}

#[test]
fn vista_token_rule_both_stages() {
    // graduated tokens stay under the LAUNCH factory; the DEX also pools vista.vistadev.near
    for venue in ["launch.vistadev.near", "dex.vistadev.near"] {
        for ok_m in ["vv-1.launch.vistadev.near", "vista.vistadev.near"] {
            assert!(plan_t(true, &tr(venue, Some(ok_m), None, NEAR, 1)).is_ok(), "{venue} {ok_m}");
            assert!(plan_t(false, &tr(venue, Some(ok_m), None, 5, 1)).is_ok(), "{venue} {ok_m}");
        }
        for bad in [
            "v.dex.vistadev.near",
            "a.b.launch.vistadev.near",
            "launch.vistadev.near",
            "x.vistadev.near",
            "x.near",
        ] {
            assert_eq!(
                plan_t(true, &tr(venue, Some(bad), None, NEAR, 1)).unwrap_err(),
                E_MARKET,
                "{venue} {bad}"
            );
        }
    }
    // parsers: a sell of a non-Vista token to either Vista venue is refused
    let (m, w) = (me(), wrap());
    for (venue, pad, msg) in [
        ("launch.vistadev.near", FactoryPad::VistaLaunch, json!({"sell": {"min_out": "7"}})),
        ("dex.vistadev.near", FactoryPad::VistaDex, json!({"swap_to_near": {"min_out": "7"}})),
    ] {
        let r = a(venue);
        for (tok, ok) in [
            ("vv-1.launch.vistadev.near", true),
            ("vista.vistadev.near", true),
            ("v.dex.vistadev.near", false),
        ] {
            let t = a(tok);
            let vc = VCtx { self_id: &m, wrap: &w, token_in: &t, receiver: &r, referrer: &w };
            let res = msg_venues::parse(DexKind::FactoryCurve(pad), &msg.to_string(), &vc);
            assert_eq!(res.is_ok(), ok, "{venue} {tok}");
        }
    }
}

#[test]
fn vista_dex_buy_sell() {
    let vm = vista_dex_market();
    let p = plan_t(true, &tr("dex.vistadev.near", Some(vm), None, NEAR, 3)).unwrap();
    let c = one(&p);
    assert_eq!((c.method, c.deposit), ("swap_near_for_token", NEAR));
    assert_eq!(args(c), json!({"token_id": vm, "min_out": "3"}));
    assert_eq!(p.spend, NEAR);
    let s = plan_t(false, &tr("dex.vistadev.near", Some(vm), None, 50, 7)).unwrap();
    assert_eq!(inner(one(&s)), json!({"swap_to_near": {"min_out": "7"}}));
}

#[test]
fn nearrr_buy_sell() {
    let p = plan_t(true, &tr("nearrr-fun.near", Some("arcova-m6ez.nearrr-fun.near"), None, NEAR, 3)).unwrap();
    // step 1 is the token's own tax view (no NEAR leaves yet); the buy runs in on_nearrr_tax
    let c = one(&p);
    assert_eq!(
        (c.receiver.as_str(), c.method, c.deposit, c.gas),
        ("arcova-m6ez.nearrr-fun.near", "tax_state", 0, GAS_TAX_VIEW * TGAS)
    );
    let mut label = [0u8; 48];
    label[..11].copy_from_slice(b"arcova-m6ez");
    let dex = allow().iter().position(|d| d.id.as_str() == "nearrr-fun.near").unwrap() as u16;
    assert_eq!(p.settle, Settle::NearrrTax { min_out: 3, dex, label, len: 11 });
    // the later deposit is reserved, counted and fee'd as a NEAR buy
    assert_eq!((p.spend, p.counted, p.fee, p.native_out), (NEAR, NEAR, bps(NEAR, FEE_BPS), NEAR));
    assert_eq!(p.gas, (GAS_TAX_VIEW + GAS_CB_NEARRR - crate::GAS_CALLBACK) * TGAS);
    assert!(p.gas <= MAX_CURVE_GAS * TGAS && GAS_NEARRR_BUY >= 180);
    assert_eq!(p.swap.min_out, 3);
    assert_eq!(p.storage, vec![a("arcova-m6ez.nearrr-fun.near")]);
    // an op declaring less than the chain: refused before anything moves
    let low = CurveTrade {
        gas: U64(p.gas - 1),
        ..tr("nearrr-fun.near", Some("arcova-m6ez.nearrr-fun.near"), None, NEAR, 3)
    };
    assert_eq!(plan_t(true, &low).unwrap_err(), E_GAS);
    // the callback
    let (m, args_s, g) = settle::callback(p.settle, "{\"x\":1}", 7, 0);
    assert_eq!((m, g), ("on_nearrr_tax", GAS_CB_NEARRR));
    assert_eq!(
        serde_json::from_str::<Value>(&args_s).unwrap(),
        json!({"settle": {"x": 1}, "min_out": "3", "dex": dex, "label": "arcova-m6ez"})
    );
    let s = plan_t(false, &tr("nearrr-fun.near", Some("arcova-m6ez.nearrr-fun.near"), None, 50, 7)).unwrap();
    assert_eq!(inner(one(&s)), json!({"sell": {"min_out": "7"}}));
    assert_eq!(
        plan_t(true, &tr("nearrr-fun.near", Some("x.nearrr-fun.near"), Some("usdc.near"), 1, 1)).unwrap_err(),
        E_QUOTE
    );
}

#[test]
fn nearrr_tax_from_the_tokens_view() {
    use crate::venues::factory::nearrr_tax_bps as t;
    let j = |v: Value| v.to_string().into_bytes();
    // measured on the real wasm: Standard keeps 0.5%, Tax keeps buy_tax + 1%
    assert_eq!(t(&j(json!({"mode": "Standard", "buy_tax_bps": 0, "sell_tax_bps": 0}))), Some(50));
    assert_eq!(t(&j(json!({"mode": "Tax", "buy_tax_bps": 0}))), Some(100));
    assert_eq!(
        t(&j(json!({"mode": "Tax", "buy_tax_bps": 450, "creator": "c.near", "allocation": {}}))),
        Some(550)
    );
    assert_eq!(t(&j(json!({"mode": "Tax", "buy_tax_bps": 1000}))), Some(1100));
    // above the max, an unknown mode or an unreadable view: refused
    for bad in [
        j(json!({"mode": "Tax", "buy_tax_bps": 1001})),
        j(json!({"mode": "Legacy", "buy_tax_bps": 0})),
        j(json!({"buy_tax_bps": 0})),
        j(json!({"mode": "Tax", "buy_tax_bps": "100"})),
        b"null".to_vec(),
        vec![],
    ] {
        assert_eq!(t(&bad), None, "{}", String::from_utf8_lossy(&bad));
    }
}

#[test]
fn nearrr_pad_min_is_post_tax_safe() {
    use crate::venues::factory::{nearrr_pad_min, NEARRR_MAX_TAX_BPS};
    for m in [1u128, 3, 8_899, 8_900, 10u128.pow(24), 551_193_216_535_560_139_804_396, 10u128.pow(32)] {
        let pm = nearrr_pad_min(m, NEARRR_MAX_TAX_BPS).unwrap();
        // the worst post-tax delivery of a pad output >= pm is >= m
        assert!(pm * (10_000 - NEARRR_MAX_TAX_BPS) / 10_000 >= m, "{m}");
        // and pm is the smallest such bound (ceil)
        assert!((pm - 1) * (10_000 - NEARRR_MAX_TAX_BPS) < m * 10_000, "{m}");
    }
    assert_eq!(nearrr_pad_min(u128::MAX, 0), Err(E_BAD_OP));
    assert_eq!(nearrr_pad_min(1, NEARRR_MAX_TAX_BPS + 1), Err(E_BAD_OP));
    // a Standard token (0.5%): 9_950 needs a pad output of 10_000; a 5.5% token: ceil(9_450/0.945)
    assert_eq!(nearrr_pad_min(9_950, 50), Ok(10_000));
    assert_eq!(nearrr_pad_min(9_450, 550), Ok(10_000));
}

#[test]
fn factory_buys_settle_kind() {
    // pads that never refund part of a successful buy: whole fee on success (NearInFull)
    let p = plan_t(true, &tr("nearrr-fun.near", Some("arcova-m6ez.nearrr-fun.near"), None, NEAR, 3)).unwrap();
    assert!(matches!(p.settle, Settle::NearrrTax { .. }) && p.settle.mode() == "near_in_full");
    for (f, m) in [
        ("dragonpad.near", "ember.dragonpad.near"),
        ("dex.vistadev.near", "vista.vistadev.near"),
        ("curve10.latedata9580.near", "nevar-84da8f65"),
    ] {
        let p = plan_t(true, &tr(f, Some(m), None, NEAR, 3)).unwrap();
        assert_eq!(p.settle, Settle::NearInFull, "{f}");
        assert!(p.spend >= NEAR && p.counted == NEAR && p.fee == bps(NEAR, FEE_BPS), "{f}");
    }
    // Vista's curve can refund part of a buy that completes it: measured
    let p =
        plan_t(true, &tr("launch.vistadev.near", Some("vv-1.launch.vistadev.near"), None, NEAR, 3)).unwrap();
    assert_eq!(p.settle, Settle::NearIn);
}

#[test]
fn factory_claims_dragonpad_and_vista() {
    let (m, w) = (me(), wrap());
    let c = ctx(&m, &w, None);
    let cl = |venue: &str, action: ClaimAction, market: Option<&str>| CurveClaim {
        venue: a(venue),
        action,
        market: market.map(String::from),
        token: None,
        amount: None,
    };
    // dragonpad: a failed NEAR payout ("near") or a failed token delivery (the token), deposit 0
    let (call, spend) =
        plan_claim(&allow(), &cl("dragonpad.near", ClaimAction::DragonpadClaim, None), &c).unwrap();
    assert_eq!((call.method, call.deposit, spend), ("claim", 0, 0));
    assert_eq!(args(&call), json!({"asset": "near"}));
    let (call, _) = plan_claim(
        &allow(),
        &cl("dragonpad.near", ClaimAction::DragonpadClaim, Some("ember.dragonpad.near")),
        &c,
    )
    .unwrap();
    assert_eq!(args(&call), json!({"asset": "nep141:ember.dragonpad.near"}));
    assert_eq!(
        plan_claim(&allow(), &cl("dragonpad.near", ClaimAction::DragonpadClaim, Some("x.other.near")), &c)
            .unwrap_err(),
        E_MARKET
    );
    // Vista launch: claim_pending{token_id}, exactly 1 yocto
    let (call, _) = plan_claim(
        &allow(),
        &cl("launch.vistadev.near", ClaimAction::VistaClaimPending, Some("vv-1.launch.vistadev.near")),
        &c,
    )
    .unwrap();
    assert_eq!(
        (call.receiver.as_str(), call.method, call.deposit),
        ("launch.vistadev.near", "claim_pending", 1)
    );
    assert_eq!(args(&call), json!({"token_id": "vv-1.launch.vistadev.near"}));
    for bad in [None, Some("v.dex.vistadev.near")] {
        assert!(plan_claim(&allow(), &cl("launch.vistadev.near", ClaimAction::VistaClaimPending, bad), &c)
            .is_err());
    }
    // wrong venue for the action
    assert_eq!(
        plan_claim(
            &allow(),
            &cl("dex.vistadev.near", ClaimAction::VistaClaimPending, Some("vv-1.launch.vistadev.near")),
            &c
        )
        .unwrap_err(),
        E_BAD_OP
    );
    let mut x = cl("dragonpad.near", ClaimAction::DragonpadClaim, None);
    x.amount = Some(U128(1));
    assert_eq!(plan_claim(&allow(), &x, &c).unwrap_err(), E_BAD_OP);
}

#[test]
fn dragonpad_buy_sell_near_only() {
    let p = plan_t(true, &tr("dragonpad.near", Some("ember.dragonpad.near"), None, NEAR, 3)).unwrap();
    let c = one(&p);
    assert_eq!((c.method, c.deposit), ("buy", NEAR));
    assert_eq!(args(c), json!({"token_id": "ember.dragonpad.near", "min_tokens_out": "3"}));
    let s = plan_t(false, &tr("dragonpad.near", Some("ember.dragonpad.near"), None, 50, 7)).unwrap();
    assert_eq!(inner(one(&s)), json!({"sell": {"min_quote_out": "7"}}));
    for buy in [true, false] {
        assert_eq!(
            plan_t(buy, &tr("dragonpad.near", Some("ember.dragonpad.near"), Some("usdc.near"), 5, 5))
                .unwrap_err(),
            E_QUOTE
        );
    }
}

#[test]
fn nira_buy_near_and_q() {
    let f = "curve10.latedata9580.near";
    let p = plan_t(true, &tr(f, Some("nevar-84da8f65"), None, NEAR, 3)).unwrap();
    let c = one(&p);
    assert_eq!((c.receiver.as_str(), c.method, c.deposit), (f, "buy", NEAR + NIRA_BUY_STORAGE));
    assert_eq!(
        args(c),
        json!({"launch_id": "nevar-84da8f65", "min_tokens_out": "3", "deadline_ms": (DL_NS / 1_000_000).to_string()})
    );
    assert_eq!(p.settle, Settle::NearInFull);
    assert_eq!(p.spend, NEAR + NIRA_BUY_STORAGE);
    assert_eq!(p.swap.out, format!("nevar-84da8f65.{f}"));
    let q = "bnb-0xa9ee28c80f960b889dfbd1902055218cba016f75.omdep.near";
    let p = plan_t(true, &tr(f, Some("si-3bf5e448"), Some(q), 5, 3)).unwrap();
    let c = one(&p);
    assert_eq!((c.receiver.as_str(), c.method, c.deposit), (q, "ft_transfer_call", 1));
    assert_eq!(args(c)["receiver_id"], f);
    assert_eq!(
        inner(c),
        json!({"buy": {"launch_id": "si-3bf5e448", "min_tokens_out": "3", "deadline_ms": (DL_NS / 1_000_000).to_string()}})
    );
    assert_eq!(p.settle, Settle::Token);
    assert_eq!((p.spend, p.fee), (0, 0));
    assert_eq!(p.token_in, a(q));
    assert!(p.storage.is_empty());
}

#[test]
fn nira_sell_near_and_q() {
    let f = "curve10.latedata9580.near";
    let s = plan_t(false, &tr(f, Some("ncat-5b16a7ca"), None, 15, 19)).unwrap();
    let c = one(&s);
    assert_eq!((c.receiver.as_str(), c.method, c.deposit), (f, "sell", 1));
    assert_eq!(
        args(c),
        json!({"launch_id": "ncat-5b16a7ca", "token_in": "15", "min_out": "19", "deadline_ms": (DL_NS / 1_000_000).to_string()})
    );
    assert_eq!(s.settle, Settle::Out { native: true, reported: false, wnear: false });
    assert_eq!((s.fee, s.fee_cap), (bps(19, FEE_BPS), 19));
    assert_eq!(s.token_in, a(&format!("ncat-5b16a7ca.{f}")));
    let q = "usdc.near";
    let s = plan_t(false, &tr(f, Some("ncat-5b16a7ca"), Some(q), 15, 19)).unwrap();
    assert_eq!(s.settle, Settle::Out { native: false, reported: false, wnear: false });
    assert_eq!(s.settle.mode(), "q_out");
    assert_eq!((s.fee, s.fee_cap), (0, 0));
    assert_eq!(s.swap, Swap { out_is_near: false, min_out: 19, out: q.into() });
    assert_eq!(s.storage, vec![a(q)]);
}

#[test]
fn meme_cooking_deposit_only() {
    let p = plan_t(true, &tr("meme-cooking.near", Some("42"), None, NEAR, 1)).unwrap();
    let c = one(&p);
    assert_eq!((c.receiver.as_str(), c.method, c.deposit), ("wrap.near", "ft_transfer_call", 1));
    assert_eq!(args(c)["receiver_id"], "meme-cooking.near");
    assert_eq!(inner(c), json!({"Deposit": {"meme_id": 42}}));
    assert_eq!(p.settle, Settle::Wrap);
    assert!(!p.orderable);
    assert_eq!((p.spend, p.fee), (NEAR, bps(NEAR, FEE_BPS)));
    assert_eq!(plan_t(false, &tr("meme-cooking.near", Some("42"), None, 1, 1)).unwrap_err(), E_BAD_OP);
    for m in ["042", "x", "-1", "18446744073709551616", ""] {
        assert_eq!(plan_t(true, &tr("meme-cooking.near", Some(m), None, 1, 1)).unwrap_err(), E_MARKET, "{m}");
    }
    assert_eq!(
        plan_t(true, &tr("meme-cooking.near", Some("42"), Some("usdc.near"), 1, 1)).unwrap_err(),
        E_QUOTE
    );
}

#[test]
fn factory_rejects_max_out() {
    let mut t = tr("nearrr-fun.near", Some("x.nearrr-fun.near"), None, 1, 1);
    t.max_out = Some(U128(5));
    assert_eq!(plan_t(true, &t).unwrap_err(), E_BAD_OP);
}

// ======================= token curves =======================

fn tok(venue: &str, quote: Option<&str>, amount: u128, min: u128) -> CurveTrade {
    tr(venue, None, quote, amount, min)
}

#[test]
fn token_payable_buys() {
    let cases: [(&str, Value); 5] = [
        ("ncat.nearfunio.near", json!({"min_tokens_out": "3"})),
        ("npad.npad.near", json!({"min_tokens_out": "3"})),
        ("apple.umbrafun.near", json!({"min_out": "3"})),
        ("m.nearmemefun.near", json!({"min_tokens_out": "3", "deadline_sec": DL_NS / 1_000_000_000})),
        ("c1.chipfi.near", json!({"min_out": "3", "for_account": null})),
    ];
    for (v, want) in cases {
        let p = plan_t(true, &tok(v, None, NEAR, 3)).unwrap();
        let c = one(&p);
        assert_eq!((c.receiver.as_str(), c.method, c.deposit, c.gas), (v, "buy", NEAR, G), "{v}");
        assert_eq!(args(c), want, "{v}");
        assert_eq!(p.settle, Settle::NearIn);
        assert_eq!((p.spend, p.counted, p.fee, p.native_out), (NEAR, NEAR, bps(NEAR, FEE_BPS), NEAR));
        assert_eq!((p.order_dex.as_str(), p.token_in.as_str()), (v, "wrap.near"));
        assert_eq!(p.swap, Swap { out_is_near: false, min_out: 3, out: v.into() });
        assert_eq!(p.storage, vec![a(v)]);
    }
}

#[test]
fn token0_buy_exact_out() {
    let mut t = tok("sfv.token0.near", None, NEAR, 3);
    assert_eq!(plan_t(true, &t).unwrap_err(), E_BAD_OP, "max_out required");
    t.max_out = Some(U128(2));
    assert_eq!(plan_t(true, &t).unwrap_err(), E_BAD_OP, "max_out < min_out");
    t.max_out = Some(U128(9));
    let p = plan_t(true, &t).unwrap();
    let c = one(&p);
    assert_eq!((c.method, c.deposit), ("buy", NEAR));
    assert_eq!(
        args(c),
        json!({"max_token_amount": "9", "min_token_amount": "3", "receiver_id": "user.tt.near", "referral_id": null})
    );
    assert_eq!(p.settle, Settle::NearIn);
    // max_out on a token0 SELL is refused
    let mut s = tok("sfv.token0.near", None, 5, 3);
    s.max_out = Some(U128(9));
    assert_eq!(plan_t(false, &s).unwrap_err(), E_BAD_OP);
}

#[test]
fn token_q_buys() {
    let q = "zec.omft.near";
    let p = plan_t(true, &tok("apple.umbrafun.near", Some(q), 5, 3)).unwrap();
    let c = one(&p);
    assert_eq!((c.receiver.as_str(), c.method, c.deposit), (q, "ft_transfer_call", 1));
    assert_eq!(args(c)["receiver_id"], "apple.umbrafun.near");
    assert_eq!(inner(c), json!({"action": "buy", "min_out": "3"}));
    assert_eq!(p.settle, Settle::Token);
    assert_eq!((p.spend, p.fee, p.native_out), (0, 0, 1));
    assert_eq!(p.token_in, a(q));
    let p = plan_t(true, &tok("c3.chipfi.near", Some(q), 5, 3)).unwrap();
    assert_eq!(inner(one(&p)), json!({"min_out": "3"}));
    // pads with no Q path
    for v in [
        "ncat.nearfunio.near",
        "l0.revshare-launch.near",
        "m.nearmemefun.near",
        "sfv.token0.near",
        "npad.npad.near",
    ] {
        assert_eq!(plan_t(true, &tok(v, Some(q), 5, 3)).unwrap_err(), E_QUOTE, "{v}");
        assert_eq!(plan_t(false, &tok(v, Some(q), 5, 3)).unwrap_err(), E_QUOTE, "{v}");
    }
}

#[test]
fn revshare_buy_wnear() {
    let p = plan_t(true, &tok("l0.revshare-launch.near", None, NEAR, 3)).unwrap();
    let c = one(&p);
    assert_eq!((c.receiver.as_str(), c.method, c.deposit), ("wrap.near", "ft_transfer_call", 1));
    assert_eq!(args(c)["receiver_id"], "l0.revshare-launch.near");
    assert_eq!(inner(c), json!({"buy": {"min_tokens_out": "3", "deadline_ns": DL_NS.to_string()}}));
    assert_eq!(p.settle, Settle::Wrap);
    assert_eq!((p.spend, p.counted, p.fee), (NEAR, NEAR, bps(NEAR, FEE_BPS)));
}

#[test]
fn token_sells() {
    let n = Settle::Out { native: true, reported: false, wnear: false };
    // nearmemefun: sell + withdraw_near, see nearmemefun_sell_and_withdraw_one_batch
    let cases: [(&str, Value, u128, Settle); 4] = [
        ("ncat.nearfunio.near", json!({"amount": "50", "min_near_out": "7"}), 1, n),
        ("npad.npad.near", json!({"amount": "50", "min_near_out": "7"}), 1, n),
        ("apple.umbrafun.near", json!({"amount": "50", "min_out": "7"}), 1, n),
        (
            "sfv.token0.near",
            json!({"token_amount": "50", "min_near_output_amount": "7", "receiver_id": "user.tt.near"}),
            0,
            Settle::Out { native: true, reported: true, wnear: false },
        ),
    ];
    for (v, want, dep, st) in cases {
        let s = plan_t(false, &tok(v, None, 50, 7)).unwrap();
        let c = one(&s);
        assert_eq!((c.receiver.as_str(), c.method, c.deposit, c.gas), (v, "sell", dep, G), "{v}");
        assert_eq!(args(c), want, "{v}");
        assert_eq!(s.settle, st, "{v}");
        assert_eq!((s.spend, s.counted, s.fee, s.fee_cap, s.native_out), (0, 0, bps(7, FEE_BPS), 7, dep));
        assert_eq!((s.order_dex.as_str(), s.token_in.as_str()), (v, v));
        assert_eq!(s.swap, Swap { out_is_near: true, min_out: 7, out: "wrap.near".into() });
    }
    assert_eq!(Settle::Out { native: true, reported: true, wnear: false }.mode(), "near_out_reported");
    assert_eq!(n.mode(), "near_out");
}

#[test]
fn revshare_sell_wnear_payout() {
    let s = plan_t(false, &tok("l0.revshare-launch.near", None, 50, 7)).unwrap();
    let c = one(&s);
    assert_eq!((c.method, c.deposit), ("sell", 1));
    assert_eq!(args(c), json!({"amount": "50", "min_quote_out": "7", "deadline_ns": DL_NS.to_string()}));
    assert_eq!(s.settle, Settle::Out { native: false, reported: false, wnear: true });
    assert_eq!(s.settle.mode(), "wnear_out");
    assert_eq!((s.fee, s.fee_cap), (bps(7, FEE_BPS), 7));
}

#[test]
fn umbra_sell_q_payout_no_fee() {
    let s = plan_t(false, &tok("apple.umbrafun.near", Some("usdc.near"), 50, 7)).unwrap();
    assert_eq!(s.settle.mode(), "q_out");
    assert_eq!((s.fee, s.fee_cap), (0, 0));
    assert_eq!(s.storage, vec![a("apple.umbrafun.near"), a("usdc.near")]);
}

#[test]
fn nearmemefun_sell_and_withdraw_one_batch() {
    // the real token's `sell` only credits the NEAR; `withdraw_near{amount: min_out}` pays it
    let v = "m.nearmemefun.near";
    let s = plan_t(false, &tok(v, None, 50, 7)).unwrap();
    assert_eq!(s.calls.len(), 2);
    let (sell, wd) = (&s.calls[0], &s.calls[1]);
    assert_eq!((sell.receiver.as_str(), sell.method, sell.deposit), (v, "sell", 1));
    assert_eq!(
        args(sell),
        json!({"tokens_in": "50", "min_near_out": "7", "deadline_sec": DL_NS / 1_000_000_000})
    );
    assert_eq!((wd.receiver.as_str(), wd.method, wd.deposit), (v, "withdraw_near", 1));
    assert_eq!(args(wd), json!({"amount": "7"}));
    assert_eq!(wd.gas, token::NEARMEMEFUN_WITHDRAW_TGAS * TGAS);
    assert_eq!(sell.gas + wd.gas, G);
    assert_eq!(s.settle, Settle::Out { native: true, reported: false, wnear: false });
    assert_eq!((s.fee, s.fee_cap), (bps(7, FEE_BPS), 7));
    // the sell part must keep >= MIN_CURVE_GAS
    let mut t = tok(v, None, 50, 7);
    t.gas = U64((token::NEARMEMEFUN_WITHDRAW_TGAS + MIN_CURVE_GAS) * TGAS - 1);
    assert_eq!(plan_t(false, &t).unwrap_err(), E_GAS);
    t.gas = U64((token::NEARMEMEFUN_WITHDRAW_TGAS + MIN_CURVE_GAS) * TGAS);
    assert!(plan_t(false, &t).is_ok());
}

#[test]
fn chipfi_sell_and_claim_one_batch() {
    let s = plan_t(false, &tok("c1.chipfi.near", None, 50, 7)).unwrap();
    assert_eq!(s.calls.len(), 2);
    let (sell, claim) = (&s.calls[0], &s.calls[1]);
    assert_eq!((sell.receiver.as_str(), sell.method, sell.deposit), ("c1.chipfi.near", "sell", 0));
    assert_eq!(args(sell), json!({"amount": "50", "min_out": "7"}));
    assert_eq!(
        (claim.receiver.as_str(), claim.method, claim.deposit, claim.args.as_str()),
        ("c1.chipfi.near", "claim", 0, "{}")
    );
    assert_eq!(claim.gas, GAS_CURVE_CLAIM * TGAS);
    assert_eq!(sell.gas + claim.gas, G);
    assert_eq!(s.gas, G);
    assert_eq!(s.native_out, 0);
    assert_eq!(s.settle, Settle::Out { native: true, reported: false, wnear: false });
    // the sell part must keep >= MIN_CURVE_GAS
    let mut t = tok("c1.chipfi.near", None, 50, 7);
    t.gas = U64((GAS_CURVE_CLAIM + MIN_CURVE_GAS) * TGAS - 1);
    assert_eq!(plan_t(false, &t).unwrap_err(), E_GAS);
    t.gas = U64((GAS_CURVE_CLAIM + MIN_CURVE_GAS) * TGAS);
    assert!(plan_t(false, &t).is_ok());
}

#[test]
fn token_curve_rejects_market() {
    assert_eq!(plan_t(true, &tr("apple.umbrafun.near", Some("x"), None, 1, 1)).unwrap_err(), E_BAD_OP);
}

// ======================= Kelytra =======================

/// Kelytra trade with the round-trip gas budget.
fn trk(market: Option<&str>, quote: Option<&str>, amount: u128, min_out: u128) -> CurveTrade {
    CurveTrade { gas: U64(200 * TGAS), ..tr("exchange.kelytradevs.near", market, quote, amount, min_out) }
}

#[test]
fn kelytra_buy_sell() {
    let ex = "exchange.kelytradevs.near";
    let p = plan_t(true, &trk(Some("0"), None, NEAR, 3)).unwrap();
    // a buy takes native NEAR: one wrap batch [near_deposit, ft_transfer_call "deposit"]; the rest
    // runs in the callbacks
    assert_eq!(p.calls.len(), 2);
    let (w, d) = (&p.calls[0], &p.calls[1]);
    assert_eq!(
        (w.receiver.as_str(), w.method, w.deposit, w.gas),
        ("wrap.near", "near_deposit", NEAR, 10 * TGAS)
    );
    assert_eq!(args(w), json!({}));
    assert_eq!(
        (d.receiver.as_str(), d.method, d.deposit, d.gas),
        ("wrap.near", "ft_transfer_call", 1, kelytra::GAS_DEPOSIT * TGAS)
    );
    assert_eq!(args(d), json!({"receiver_id": ex, "amount": NEAR.to_string(), "msg": "deposit"}));
    assert_eq!((p.spend, p.counted, p.fee, p.native_out), (NEAR, NEAR, bps(NEAR, FEE_BPS), NEAR + 1));
    assert_eq!(p.settle, Settle::Kelytra { buy: true, launch: 0, min_out: 3, dex: 18, setup: false });
    assert!(p.settle.measured());
    assert!(p.orderable);
    assert_eq!(p.swap.out, format!("t0.{ex}"));
    assert_eq!(p.order_dex, a(ex));
    assert_eq!(p.token_in, wrap());
    assert_eq!(p.gas, (10 + kelytra::GAS_DEPOSIT + kelytra::GAS_CB_DEPOSITED - crate::GAS_CALLBACK) * TGAS);
    let s = plan_t(false, &trk(Some("1"), None, 50, 7)).unwrap();
    let c = one(&s);
    assert_eq!((c.receiver.as_str(), c.method), ("t1.exchange.kelytradevs.near", "ft_transfer_call"));
    assert_eq!(args(c)["msg"], "deposit");
    assert_eq!(s.token_in, a(&format!("t1.{ex}")));
    assert!(s.orderable);
    assert!(s.swap.out_is_near);
    assert_eq!((s.spend, s.fee, s.fee_cap, s.native_out), (0, bps(7, FEE_BPS), 7, 1));
    assert_eq!(s.settle, Settle::Kelytra { buy: false, launch: 1, min_out: 7, dex: 18, setup: false });
    assert_eq!(plan_t(true, &trk(Some("0"), Some("usdc.near"), 1, 1)).unwrap_err(), E_QUOTE);
    assert_eq!(plan_t(true, &trk(Some("t0"), None, 1, 1)).unwrap_err(), E_MARKET);
    // the op must budget the whole round trip
    assert_eq!(plan_t(true, &tr(ex, Some("0"), None, 1, 1)).unwrap_err(), E_GAS);
    // the first callback carries the round trip's terms
    let (m, a_, g) = settle::callback(p.settle, "{}", 0, 0);
    assert_eq!((m, g), ("on_kelytra_deposited", kelytra::GAS_CB_DEPOSITED));
    assert_eq!(
        serde_json::from_str::<Value>(&a_).unwrap(),
        json!({"settle": {}, "k": {"buy": true, "launch": "0", "min_out": "3", "dex": 18}})
    );
}

/// `setup` (a first trade): the planned calls register (storage on the launch token beside, both
/// exchange balances); the NEAR of the deposit step is reserved (native_out) and counted.
#[test]
fn kelytra_setup_first_trade() {
    let ex = "exchange.kelytradevs.near";
    let t = CurveTrade { setup: true, gas: U64(kelytra_setup_gas()), ..trk(Some("0"), None, NEAR, 3) };
    let p = plan_t(true, &t).unwrap();
    let m: Vec<(&str, &str, u128)> =
        p.calls.iter().map(|c| (c.receiver.as_str(), c.method, c.deposit)).collect();
    assert_eq!(
        m,
        vec![
            ("t0.exchange.kelytradevs.near", "storage_deposit", VENUE_STORAGE),
            (ex, "register_balance", KELYTRA_REGISTER),
            (ex, "register_balance", KELYTRA_REGISTER),
        ]
    );
    assert_eq!(args(&p.calls[1]), json!({"token_id": "wrap.near", "account_id": "user.tt.near"}));
    assert_eq!(
        args(&p.calls[2]),
        json!({"token_id": "t0.exchange.kelytradevs.near", "account_id": "user.tt.near"})
    );
    let reg = VENUE_STORAGE + 2 * KELYTRA_REGISTER;
    assert_eq!((p.spend, p.counted, p.fee), (NEAR + reg, NEAR, bps(NEAR, FEE_BPS)));
    assert_eq!(p.native_out, reg + NEAR + 1, "the callback's wrap deposit is reserved up front");
    assert_eq!(p.settle, Settle::Kelytra { buy: true, launch: 0, min_out: 3, dex: 18, setup: true });
    assert_eq!(p.gas, kelytra_setup_gas());
    let (m, _, g) = settle::callback(p.settle, "{}", 0, 0);
    assert_eq!((m, g), ("on_kelytra_registered", kelytra::GAS_CB_REGISTERED));
    // a setup sell: registrations only (spend), the token deposit runs in the callback
    let s = plan_t(
        false,
        &CurveTrade { setup: true, gas: U64(kelytra_setup_gas()), ..trk(Some("0"), None, 50, 7) },
    )
    .unwrap();
    assert_eq!((s.spend, s.native_out), (reg, reg + 1));
    // under-declared gas; setup on any other pad
    assert_eq!(
        plan_t(true, &CurveTrade { setup: true, ..trk(Some("0"), None, NEAR, 3) }).unwrap_err(),
        E_GAS
    );
    for (buy, t) in all_valid() {
        if t.venue.as_str() != ex {
            assert_eq!(plan_t(buy, &CurveTrade { setup: true, ..t }).unwrap_err(), E_BAD_OP);
        }
    }
    // JSON: absent = false
    let j = r#"{"venue":"exchange.kelytradevs.near","market":"0","amount":"5","min_out":"3","gas":"1"}"#;
    assert!(!serde_json::from_str::<CurveTrade>(j).unwrap().setup);
}

fn kelytra_setup_gas() -> u64 {
    (10 + 2 * kelytra::GAS_REGISTER + kelytra::GAS_CB_REGISTERED - crate::GAS_CALLBACK) * TGAS
}

/// The whole Kelytra chain fits one execute: run's budget (op gas + an action fee per extra
/// planned call + the op's action + callback) is <= 300 TGas, for a setup buy (the largest).
#[test]
fn kelytra_gas_fits_one_execute() {
    let (m, w) = (me(), wrap());
    let t = CurveTrade { setup: true, gas: U64(kelytra_setup_gas()), ..trk(Some("0"), None, NEAR, 3) };
    let p = plan(&allow(), true, &t, &ctx(&m, &w, None)).unwrap();
    assert!(p.gas <= MAX_CURVE_GAS * TGAS);
    let extra = (p.calls.len() as u64 - 1) * crate::GAS_PER_ACTION * TGAS;
    let total =
        p.gas + extra + crate::GAS_PER_ACTION * TGAS + (crate::GAS_CALLBACK + crate::GAS_PER_ACTION) * TGAS;
    assert!(crate::policy::check_gas(1, total, 300 * TGAS).is_ok(), "{}", total / TGAS);
}

/// A Kelytra 24/7 order: the planned fire matches the stored order through the same
/// check_order_swap as every other venue (buy: wNEAR in; sell: wNEAR out).
#[test]
fn kelytra_orderable() {
    let ex = a("exchange.kelytradevs.near");
    let t0 = a("t0.exchange.kelytradevs.near");
    let order = |ti: &AccountId, to: &AccountId, amount: u128, min: u128| crate::Order {
        token_in: ti.clone(),
        token_out: to.clone(),
        amount_in: U128(amount),
        min_out: U128(min),
        trigger_meta: String::new(),
        expires_at_ns: U64(T + 1),
        dexes: vec![ex.clone()],
        pending: false,
    };
    let (m, w) = (me(), wrap());
    let b = plan(&allow(), true, &trk(Some("0"), None, NEAR, 10), &ctx(&m, &w, Some(10))).unwrap();
    assert!(
        crate::check_order_swap(&order(&w, &t0, NEAR, 10), &b.order_dex, &b.token_in, NEAR, &b.swap).is_ok()
    );
    assert!(
        crate::check_order_swap(&order(&w, &t0, NEAR, 11), &b.order_dex, &b.token_in, NEAR, &b.swap).is_err()
    );
    assert!(crate::check_order_swap(&order(&w, &t0, NEAR + 1, 10), &b.order_dex, &b.token_in, NEAR, &b.swap)
        .is_err());
    let s = plan(&allow(), false, &trk(Some("0"), None, 50, 7), &ctx(&m, &w, Some(5))).unwrap();
    assert!(crate::check_order_swap(&order(&t0, &w, 50, 7), &s.order_dex, &s.token_in, 50, &s.swap).is_ok());
    // a fire's sell fee comes from the stored order's bound (UNR-A-01)
    assert_eq!(s.fee, bps(5, FEE_BPS));
}

// ======================= generic negatives =======================

fn all_valid() -> Vec<(bool, CurveTrade)> {
    let mut v = vec![];
    for buy in [true, false] {
        v.push((buy, tr("aidols.near", Some("x.aidols.near"), None, 5, 5)));
        v.push((buy, tr("nearrr-fun.near", Some("x.nearrr-fun.near"), None, 5, 5)));
        v.push((buy, tr("curve10.latedata9580.near", Some("l-1"), None, 5, 5)));
        v.push((buy, tr("apple.umbrafun.near", None, None, 5, 5)));
        v.push((buy, tr("c1.chipfi.near", None, None, 5, 5)));
        v.push((buy, trk(Some("0"), None, 5, 5)));
    }
    v.push((true, tr("meme-cooking.near", Some("1"), None, 5, 5)));
    v
}

#[test]
fn zero_amount_or_min_out() {
    for (buy, t) in all_valid() {
        assert!(plan_t(buy, &t).is_ok(), "{t:?}");
        let mut z = t.clone();
        z.amount = U128(0);
        assert_eq!(plan_t(buy, &z).unwrap_err(), E_BAD_OP);
        let mut z = t.clone();
        z.min_out = U128(0);
        assert_eq!(plan_t(buy, &z).unwrap_err(), E_BAD_OP);
    }
}

#[test]
fn gas_bounds() {
    for (buy, t) in all_valid() {
        let mut g = t.clone();
        g.gas = U64(MAX_CURVE_GAS * TGAS);
        assert!(plan_t(buy, &g).is_ok());
        g.gas = U64(MAX_CURVE_GAS * TGAS + 1);
        assert_eq!(plan_t(buy, &g).unwrap_err(), E_GAS);
        g.gas = U64(MIN_CURVE_GAS * TGAS - 1);
        assert_eq!(plan_t(buy, &g).unwrap_err(), E_GAS);
    }
}

#[test]
fn venue_resolution() {
    for v in [
        "unknown.near",
        "a.b.umbrafun.near",           // two labels deep
        "umbrafun.near",               // the TokenCurve factory itself
        "xumbrafun.near",              // suffix without the dot
        "x.factory.shardsmarket.near", // ShardsToken is not a curve venue
        "v2.ref-finance.near",
        "x.aidols.near", // a token under an exact-id factory is not a venue
    ] {
        for buy in [true, false] {
            assert_eq!(plan_t(buy, &tr(v, Some("x.aidols.near"), None, 5, 5)).unwrap_err(), E_BAD_DEX, "{v}");
        }
    }
    assert_eq!(resolve(&allow(), &a("x.umbrafun.near")), Some(Venue::Token(TokenPad::Umbra)));
    assert!(is_factory_entry(DexKind::TokenCurve(TokenPad::Umbra)));
    assert!(is_factory_entry(DexKind::ShardsToken));
    assert!(!is_factory_entry(DexKind::FactoryCurve(FactoryPad::Nira)));
    assert!(!is_factory_entry(DexKind::AidolsCurve(AidolsPad::Near)));
    assert_eq!(token_curve_kind(&allow(), &a("x.chipfi.near")), Some(DexKind::TokenCurve(TokenPad::Chipfi)));
    assert_eq!(token_curve_kind(&allow(), &a("chipfi.near")), None);
    assert_eq!(token_curve_kind(&allow(), &a("x.aidols.near")), None);
}

#[test]
fn self_as_venue_or_quote() {
    let m = me();
    let mut al = allow();
    al.push(Dex { id: m.clone(), kind: DexKind::FactoryCurve(FactoryPad::Nearrr) });
    let w = wrap();
    let t = tr(m.as_str(), Some("x.user.tt.near"), None, 5, 5);
    assert_eq!(plan(&al, true, &t, &ctx(&m, &w, None)).unwrap_err(), E_BAD_OP);
    let t = tr("apple.umbrafun.near", None, Some(m.as_str()), 5, 5);
    assert_eq!(plan(&al, true, &t, &ctx(&m, &w, None)).unwrap_err(), E_BAD_OP);
}

#[test]
fn market_rules() {
    for m in ["", "A.aidols.near", "x y", "x/y", "é", &"a".repeat(MAX_MARKET_LEN + 1)] {
        assert_eq!(check_market(m).unwrap_err(), E_MARKET, "{m:?}");
    }
    assert!(check_market(&"a".repeat(MAX_MARKET_LEN)).is_ok());
    assert!(check_market("nevar-84da8f65").is_ok());
    assert_eq!(plan_t(true, &tr("curve10.latedata9580.near", None, None, 5, 5)).unwrap_err(), E_MARKET);
    assert_eq!(
        plan_t(true, &tr("curve10.latedata9580.near", Some("Bad"), None, 5, 5)).unwrap_err(),
        E_MARKET
    );
}

/// Every recipient-like field any planned call (or its inner msg) carries names self or null;
/// `receiver_id` of an ft_transfer_call names the venue (the pad), nothing else.
fn check_recipients(p: &Plan, t: &CurveTrade) {
    fn walk(v: &Value, venue: &str, me: &str) {
        match v {
            Value::Object(m) => {
                for (k, x) in m {
                    match k.as_str() {
                        "receiver_id" => assert!(x == venue || x == me, "receiver_id {x}"),
                        "account_id" | "recipient" | "recipient_id" | "to" | "swap_out_recipient" => {
                            assert_eq!(x, me, "{k}")
                        }
                        "for_account" | "referral_id" | "referral" | "refferal" | "referrer" | "buy_for" => {
                            assert!(x.is_null(), "{k} must be null")
                        }
                        _ => walk(x, venue, me),
                    }
                }
            }
            Value::Array(xs) => xs.iter().for_each(|x| walk(x, venue, me)),
            _ => {}
        }
    }
    for c in &p.calls {
        let v = args(c);
        walk(&v, t.venue.as_str(), me().as_str());
        if c.method == "ft_transfer_call" {
            assert_eq!(v["receiver_id"], t.venue.as_str());
            walk(&inner(c), t.venue.as_str(), me().as_str());
        }
        assert!(!["buy_for", "ft_transfer", "withdraw"].contains(&c.method));
    }
}

#[test]
fn no_foreign_recipient_anywhere() {
    let mut all = all_valid();
    let mut t0 = tok("sfv.token0.near", None, 5, 3);
    t0.max_out = Some(U128(5));
    all.push((true, t0));
    all.push((false, tok("sfv.token0.near", None, 5, 3)));
    for v in ["ncat.nearfunio.near", "l0.revshare-launch.near", "m.nearmemefun.near", "npad.npad.near"] {
        all.push((true, tok(v, None, 5, 3)));
        all.push((false, tok(v, None, 5, 3)));
    }
    for (v, m) in [
        ("launch.vistadev.near", "x.launch.vistadev.near"),
        ("dex.vistadev.near", vista_dex_market()),
        ("dragonpad.near", "x.dragonpad.near"),
        ("gra-fun.near", "x.gra-fun.near"),
    ] {
        all.push((true, tr(v, Some(m), None, 5, 3)));
        all.push((false, tr(v, Some(m), None, 5, 3)));
    }
    all.push((true, tr("patata-monster.near", Some("p.patata-monster.near"), Some(PATATA), 5, 3)));
    all.push((true, tr("curve10.latedata9580.near", Some("l-1"), Some("usdc.near"), 5, 3)));
    all.push((true, tok("c1.chipfi.near", Some("usdc.near"), 5, 3)));
    all.push((true, tok("x.umbrafun.near", Some("usdc.near"), 5, 3)));
    for (buy, t) in all {
        let p = plan_t(buy, &t).unwrap_or_else(|e| panic!("{e} {t:?}"));
        check_recipients(&p, &t);
        assert!(p.swap.min_out > 0);
    }
}

// ======================= claims =======================

fn claim(
    venue: &str,
    action: ClaimAction,
    market: Option<&str>,
    token: Option<&str>,
    amount: Option<u128>,
) -> CurveClaim {
    CurveClaim {
        venue: a(venue),
        action,
        market: market.map(String::from),
        token: token.map(a),
        amount: amount.map(U128),
    }
}

fn pc(c: &CurveClaim) -> Result<(Call, u128), &'static str> {
    let (m, w) = (me(), wrap());
    plan_claim(&allow(), c, &ctx(&m, &w, None))
}

#[test]
fn claims_happy() {
    let g = GAS_CURVE_CLAIM * TGAS;
    let nira = "curve10.latedata9580.near";
    let (c, s) = pc(&claim(nira, ClaimAction::NiraClaimGraduated, Some("l-1"), None, None)).unwrap();
    assert_eq!(
        (c.receiver.as_str(), c.method, c.deposit, c.gas, s),
        (nira, "claim_graduated_balance", 0, g, 0)
    );
    assert_eq!(args(&c), json!({"launch_id": "l-1"}));
    let (c, s) =
        pc(&claim("meme-cooking.near", ClaimAction::MemeCookingWithdraw, Some("7"), None, Some(9))).unwrap();
    assert_eq!((c.method, c.deposit, s), ("withdraw", 1, 0));
    assert_eq!(args(&c), json!({"meme_id": 7, "amount": "9"}));
    let (c, _) =
        pc(&claim("meme-cooking.near", ClaimAction::MemeCookingClaim, Some("7"), None, None)).unwrap();
    // exactly 1 yocto (mainnet `claim` and the real wasm refuse 0)
    assert_eq!((c.method, c.deposit), ("claim", 1));
    assert_eq!(args(&c), json!({"meme_id": 7}));
    let reg =
        |a: Option<u128>| pc(&claim("meme-cooking.near", ClaimAction::MemeCookingRegister, None, None, a));
    let (c, s) = reg(Some(25 * NEAR / 1000)).unwrap();
    assert_eq!(
        (c.receiver.as_str(), c.method, c.deposit, s),
        ("meme-cooking.near", "storage_deposit", 25 * NEAR / 1000, 25 * NEAR / 1000)
    );
    // no account_id: registers the predecessor (self) only
    assert_eq!(c.args, "{}");
    assert_eq!(reg(Some(MEME_STORAGE_MAX)).unwrap().1, MEME_STORAGE_MAX);
    assert_eq!(reg(Some(MEME_STORAGE_MAX + 1)).unwrap_err(), E_BAD_OP);
    assert_eq!(reg(None).unwrap_err(), E_BAD_OP);
    assert_eq!(reg(Some(0)).unwrap_err(), E_BAD_OP);
    assert!(
        pc(&claim("meme-cooking.near", ClaimAction::MemeCookingRegister, Some("7"), None, Some(5))).is_err()
    );
    assert!(pc(&claim("meme-cooking.near", ClaimAction::MemeCookingRegister, None, Some("x.near"), Some(5)))
        .is_err());
    // claim: the auction token may be named (storage target only, never sent), one label deep
    let mcl =
        |t: Option<&str>| pc(&claim("meme-cooking.near", ClaimAction::MemeCookingClaim, Some("7"), t, None));
    assert_eq!(args(&mcl(Some("prb-7.meme-cooking.near")).unwrap().0), json!({"meme_id": 7}));
    assert!(mcl(Some("x.near")).is_err());
    assert!(mcl(Some("a.b.meme-cooking.near")).is_err());
    let (c, _) = pc(&claim("dragonpad.near", ClaimAction::DragonpadClaim, None, None, None)).unwrap();
    assert_eq!((c.method, c.deposit), ("claim", 0));
    assert_eq!(args(&c), json!({"asset": "near"}));
    let (c, _) = pc(&claim("c1.chipfi.near", ClaimAction::ChipfiClaim, None, None, None)).unwrap();
    assert_eq!(
        (c.receiver.as_str(), c.method, c.deposit, c.args.as_str()),
        ("c1.chipfi.near", "claim", 0, "{}")
    );
    let ex = "exchange.kelytradevs.near";
    let (c, s) =
        pc(&claim(ex, ClaimAction::KelytraWithdraw, None, Some("t0.exchange.kelytradevs.near"), Some(5)))
            .unwrap();
    assert_eq!((c.method, c.deposit, s), ("withdraw", 1, 0));
    assert_eq!(args(&c), json!({"token_id": "t0.exchange.kelytradevs.near", "amount": "5"}));
    let (c, s) = pc(&claim(ex, ClaimAction::KelytraRegister, None, Some("wrap.near"), None)).unwrap();
    assert_eq!((c.method, c.deposit, s), ("register_balance", KELYTRA_REGISTER, KELYTRA_REGISTER));
    assert_eq!(args(&c), json!({"token_id": "wrap.near", "account_id": "user.tt.near"}));
    let (c, s) = pc(&claim(ex, ClaimAction::KelytraDeposit, None, Some("wrap.near"), Some(NEAR))).unwrap();
    assert_eq!((c.receiver.as_str(), c.method, c.deposit, s), ("wrap.near", "ft_transfer_call", 1, NEAR));
    assert_eq!(args(&c), json!({"receiver_id": ex, "amount": NEAR.to_string(), "msg": "deposit"}));
    let (_, s) = pc(&claim(ex, ClaimAction::KelytraDeposit, None, Some("usdc.near"), Some(5))).unwrap();
    assert_eq!(s, 0);
    let nm = "t0.nearmemefun.near";
    let (c, s) = pc(&claim(nm, ClaimAction::NearmemefunWithdraw, None, None, Some(7))).unwrap();
    assert_eq!(
        (c.receiver.as_str(), c.method, c.deposit, c.gas, s),
        (nm, "withdraw_near", 1, token::NEARMEMEFUN_WITHDRAW_TGAS * TGAS, 0)
    );
    assert_eq!(args(&c), json!({"amount": "7"}));
}

#[test]
fn claims_wrong_combinations() {
    use ClaimAction::*;
    let actions = [
        NiraClaimGraduated,
        MemeCookingWithdraw,
        MemeCookingClaim,
        DragonpadClaim,
        ChipfiClaim,
        KelytraWithdraw,
        KelytraRegister,
        KelytraDeposit,
        NearmemefunWithdraw,
        MemeCookingRegister,
    ];
    let venues = [
        "curve10.latedata9580.near",
        "meme-cooking.near",
        "dragonpad.near",
        "c1.chipfi.near",
        "exchange.kelytradevs.near",
        "nearrr-fun.near",
        "aidols.near",
        "apple.umbrafun.near",
        "t0.nearmemefun.near",
    ];
    let home = |x: ClaimAction| match x {
        NiraClaimGraduated => 0,
        MemeCookingWithdraw | MemeCookingClaim | MemeCookingRegister => 1,
        DragonpadClaim => 2,
        ChipfiClaim => 3,
        NearmemefunWithdraw => 8,
        _ => 4,
    };
    for act in actions {
        for (i, v) in venues.iter().enumerate() {
            if i == home(act) {
                continue;
            }
            // with every shape of optional fields: never accepted on the wrong venue
            for (m, t, am) in [
                (None, None, None),
                (Some("7"), None, None),
                (Some("7"), None, Some(5)),
                (None, Some("wrap.near"), Some(5)),
                (None, Some("wrap.near"), None),
            ] {
                let r = pc(&claim(v, act, m, t, am));
                assert!(matches!(r, Err(E_BAD_OP) | Err(E_BAD_DEX)), "{act:?} on {v}: {r:?}");
            }
        }
    }
    // extra / missing fields on the right venue
    let nira = "curve10.latedata9580.near";
    assert!(pc(&claim(nira, NiraClaimGraduated, Some("l"), Some("x.near"), None)).is_err());
    assert!(pc(&claim(nira, NiraClaimGraduated, Some("l"), None, Some(5))).is_err());
    assert_eq!(pc(&claim(nira, NiraClaimGraduated, None, None, None)).unwrap_err(), E_MARKET);
    assert_eq!(
        pc(&claim("meme-cooking.near", MemeCookingWithdraw, Some("7"), None, None)).unwrap_err(),
        E_BAD_OP
    );
    assert!(pc(&claim("meme-cooking.near", MemeCookingWithdraw, Some("7"), Some("x.near"), Some(5))).is_err());
    assert!(pc(&claim("meme-cooking.near", MemeCookingClaim, Some("7"), None, Some(5))).is_err());
    assert!(pc(&claim("dragonpad.near", DragonpadClaim, Some("7"), None, None)).is_err());
    assert!(pc(&claim("c1.chipfi.near", ChipfiClaim, None, None, Some(5))).is_err());
    let ex = "exchange.kelytradevs.near";
    assert!(pc(&claim(ex, KelytraWithdraw, None, None, Some(5))).is_err());
    assert!(pc(&claim(ex, KelytraWithdraw, None, Some("wrap.near"), None)).is_err());
    assert!(pc(&claim(ex, KelytraWithdraw, Some("0"), Some("wrap.near"), Some(5))).is_err());
    assert!(pc(&claim(ex, KelytraRegister, None, None, None)).is_err());
    assert!(pc(&claim(ex, KelytraRegister, None, Some("wrap.near"), Some(5))).is_err());
    assert!(pc(&claim(ex, KelytraDeposit, None, Some("wrap.near"), None)).is_err());
    let nm = "t0.nearmemefun.near";
    assert_eq!(pc(&claim(nm, NearmemefunWithdraw, None, None, None)).unwrap_err(), E_BAD_OP);
    assert_eq!(pc(&claim(nm, NearmemefunWithdraw, None, None, Some(0))).unwrap_err(), E_BAD_OP);
    assert!(pc(&claim(nm, NearmemefunWithdraw, Some("7"), None, Some(5))).is_err());
    assert!(pc(&claim(nm, NearmemefunWithdraw, None, Some("wrap.near"), Some(5))).is_err());
    // the factory itself and a two-label name are not nearmemefun tokens
    assert!(pc(&claim("nearmemefun.near", NearmemefunWithdraw, None, None, Some(5))).is_err());
    assert!(pc(&claim("x.t0.nearmemefun.near", NearmemefunWithdraw, None, None, Some(5))).is_err());
    // amount 0, self as venue or token
    assert_eq!(pc(&claim(ex, KelytraWithdraw, None, Some("wrap.near"), Some(0))).unwrap_err(), E_BAD_OP);
    assert_eq!(pc(&claim(ex, KelytraWithdraw, None, Some("user.tt.near"), Some(5))).unwrap_err(), E_BAD_OP);
    assert_eq!(pc(&claim("user.tt.near", ChipfiClaim, None, None, None)).unwrap_err(), E_BAD_OP);
    // unknown venue
    assert_eq!(pc(&claim("x.near", ChipfiClaim, None, None, None)).unwrap_err(), E_BAD_DEX);
}

#[test]
fn op_json_is_strict() {
    let ok = r#"{"venue":"x.umbrafun.near","amount":"5","min_out":"3","gas":"100000000000000"}"#;
    assert!(serde_json::from_str::<CurveTrade>(ok).is_ok());
    for bad in [
        r#"{"venue":"x.umbrafun.near","amount":"5","min_out":"3","gas":"1","receiver_id":"evil.near"}"#,
        r#"{"venue":"x.umbrafun.near","amount":"5","min_out":"3","gas":"1","msg":"{}"}"#,
        r#"{"venue":"x.umbrafun.near","amount":"5","min_out":"3"}"#,
    ] {
        assert!(serde_json::from_str::<CurveTrade>(bad).is_err(), "{bad}");
    }
    let c = r#"{"venue":"dragonpad.near","action":"DragonpadClaim","to":"evil.near"}"#;
    assert!(serde_json::from_str::<CurveClaim>(c).is_err());
}

// ======================= msg_venues parsers =======================

fn vp(kind: DexKind, msg: &str, token_in: &str, receiver: &str) -> Result<Swap, &'static str> {
    let (s, w, t, r, f) = (me(), wrap(), a(token_in), a(receiver), feer());
    msg_venues::parse(kind, msg, &VCtx { self_id: &s, wrap: &w, token_in: &t, receiver: &r, referrer: &f })
}

const AID: DexKind = DexKind::AidolsCurve(AidolsPad::Near);
const PAT: DexKind = DexKind::AidolsCurve(AidolsPad::Patata);

#[test]
fn parse_golden_patata_and_aidols() {
    // C 6dK2BQtZ / Ec37YMYf
    let buy = r#"{"token":"poop.patata-monster.near","min_swap_amount":"353707217775461406372678117882"}"#;
    assert_eq!(
        vp(PAT, buy, PATATA, "patata-monster.near").unwrap(),
        Swap {
            out_is_near: false,
            min_out: 353707217775461406372678117882,
            out: "poop.patata-monster.near".into()
        }
    );
    let sell = r#"{"token":null,"min_swap_amount":"4429892785167031353375257560"}"#;
    assert_eq!(
        vp(PAT, sell, "poop.patata-monster.near", "patata-monster.near").unwrap(),
        Swap { out_is_near: false, min_out: 4429892785167031353375257560, out: PATATA.into() }
    );
    // aidols sell, C 4VeohxeaqA (no referral)
    let s = r#"{"token":null,"min_swap_amount":"357375000000000000000000"}"#;
    let sw = vp(AID, s, "aidol100.aidols.near", "aidols.near").unwrap();
    assert!(sw.out_is_near);
    assert_eq!(sw.out, "wrap.near");
    // wrong quote per pad
    assert_eq!(vp(PAT, buy, "wrap.near", "patata-monster.near").unwrap_err(), E_BAD_MSG);
    assert_eq!(
        vp(AID, r#"{"token":"x.aidols.near","min_swap_amount":"5"}"#, PATATA, "aidols.near").unwrap_err(),
        E_BAD_MSG
    );
}

/// Finding (expected): router-built Aidols msgs carry `referral` (Intear) / `refferal` (gra.fun
/// UI); the raw FtTransferCall path refuses them (unknown field). CurveBuy never sends them.
#[test]
fn parse_refuses_referral_fields() {
    for m in [
        r#"{"amount":"1","msg":"x"}"#,
        r#"{"min_swap_amount":"178167929772640907324936945664","referral":"wallet.intear.near","token":"aidol100.aidols.near"}"#,
        r#"{"token":null,"min_swap_amount":"1670998309240148404932081","refferal":null}"#,
        r#"{"min_swap_amount":"25699545620577866299211776","referral":"dex-aggregator.intear.near","token":null}"#,
    ] {
        let t = if m.contains("\"token\":null") { "x.aidols.near" } else { "wrap.near" };
        assert_eq!(vp(AID, m, t, "aidols.near").unwrap_err(), E_BAD_MSG, "{m}");
    }
}

#[test]
fn parse_factory_sells() {
    let n = DexKind::FactoryCurve(FactoryPad::Nearrr);
    let s = vp(
        n,
        r#"{"sell":{"min_out":"6086459180888255778020234"}}"#,
        "arcova-m6ez.nearrr-fun.near",
        "nearrr-fun.near",
    )
    .unwrap();
    assert_eq!(s, Swap { out_is_near: true, min_out: 6086459180888255778020234, out: "wrap.near".into() });
    let v = DexKind::FactoryCurve(FactoryPad::VistaLaunch);
    assert!(vp(v, r#"{"sell":{"min_out":"5"}}"#, "x.launch.vistadev.near", "launch.vistadev.near").is_ok());
    let vd = DexKind::FactoryCurve(FactoryPad::VistaDex);
    let vm = vista_dex_market();
    assert!(vp(vd, r#"{"swap_to_near":{"min_out":"5"}}"#, vm, "dex.vistadev.near").is_ok());
    assert_eq!(vp(vd, r#"{"sell":{"min_out":"5"}}"#, vm, "dex.vistadev.near").unwrap_err(), E_BAD_MSG);
    let d = DexKind::FactoryCurve(FactoryPad::Dragonpad);
    let s = vp(
        d,
        r#"{"sell":{"min_quote_out":"4631995236987187395929000"}}"#,
        "ember.dragonpad.near",
        "dragonpad.near",
    );
    assert_eq!(s.unwrap().min_out, 4631995236987187395929000);
    // token not under the factory
    assert_eq!(
        vp(n, r#"{"sell":{"min_out":"5"}}"#, "x.other.near", "nearrr-fun.near").unwrap_err(),
        E_BAD_MSG
    );
    assert_eq!(
        vp(d, r#"{"sell":{"min_quote_out":"5"}}"#, "a.b.dragonpad.near", "dragonpad.near").unwrap_err(),
        E_BAD_MSG
    );
    // min 0
    assert_eq!(
        vp(n, r#"{"sell":{"min_out":"0"}}"#, "x.nearrr-fun.near", "nearrr-fun.near").unwrap_err(),
        E_MIN_OUT
    );
    assert_eq!(
        vp(d, r#"{"sell":{"min_quote_out":"0"}}"#, "x.dragonpad.near", "dragonpad.near").unwrap_err(),
        E_MIN_OUT
    );
    // dragonpad has no buy by ft_transfer_call
    assert_eq!(vp(d, r#"{"buy":{"min_out":"5"}}"#, "wrap.near", "dragonpad.near").unwrap_err(), E_BAD_MSG);
}

#[test]
fn parse_nira_pair_buy() {
    let k = DexKind::FactoryCurve(FactoryPad::Nira);
    let f = "curve10.latedata9580.near";
    let q = "bnb-0xa9ee28c80f960b889dfbd1902055218cba016f75.omdep.near";
    let m = r#"{"buy":{"launch_id":"si-3bf5e448","min_tokens_out":"5464472121452","deadline_ms":"1790537328073"}}"#;
    assert_eq!(
        vp(k, m, q, f).unwrap(),
        Swap { out_is_near: false, min_out: 5464472121452, out: format!("si-3bf5e448.{f}") }
    );
    for bad in [
        r#"{"buy":{"launch_id":"si","min_tokens_out":"0","deadline_ms":"1"}}"#,
        r#"{"buy":{"launch_id":"si","min_tokens_out":"5","deadline_ms":"0"}}"#,
        r#"{"buy":{"launch_id":"SI","min_tokens_out":"5","deadline_ms":"1"}}"#,
        r#"{"buy":{"launch_id":"si","min_tokens_out":"5"}}"#,
        r#"{"buy":{"launch_id":"si","min_tokens_out":"5","deadline_ms":"1","account_id":"evil.near"}}"#,
        r#"{"buy":{"launch_id":"si","min_tokens_out":"5","deadline_ms":"1"},"receiver_id":"evil.near"}"#,
    ] {
        assert!(vp(k, bad, q, f).is_err(), "{bad}");
    }
}

#[test]
fn parse_meme_deposit() {
    let k = DexKind::FactoryCurve(FactoryPad::MemeCooking);
    let r = "meme-cooking.near";
    let s = vp(k, r#"{"Deposit":{"meme_id":42}}"#, "wrap.near", r).unwrap();
    assert_eq!(s, Swap { out_is_near: false, min_out: 1, out: format!("42.{r}") });
    assert!(vp(k, r#"{"Deposit":{"meme_id":42,"referrer":"fees.near"}}"#, "wrap.near", r).is_ok());
    assert_eq!(
        vp(k, r#"{"Deposit":{"meme_id":42,"referrer":"evil.near"}}"#, "wrap.near", r).unwrap_err(),
        E_REFERRER
    );
    assert_eq!(vp(k, r#"{"Deposit":{"meme_id":42}}"#, "usdc.near", r).unwrap_err(), E_BAD_MSG);
    assert!(vp(k, r#"{"Deposit":{"meme_id":42,"account_id":"evil.near"}}"#, "wrap.near", r).is_err());
    assert!(vp(k, r#"{"Withdraw":{"meme_id":42}}"#, "wrap.near", r).is_err());
}

#[test]
fn parse_token_curve_buys() {
    let um = DexKind::TokenCurve(TokenPad::Umbra);
    let s = vp(
        um,
        r#"{"action":"buy","min_out":"9410272399388175458000000"}"#,
        "usdc.near",
        "apple.umbrafun.near",
    )
    .unwrap();
    assert_eq!(
        s,
        Swap { out_is_near: false, min_out: 9410272399388175458000000, out: "apple.umbrafun.near".into() }
    );
    assert_eq!(
        vp(um, r#"{"action":"sell","min_out":"5"}"#, "usdc.near", "apple.umbrafun.near").unwrap_err(),
        E_BAD_MSG
    );
    assert_eq!(
        vp(um, r#"{"action":"buy","min_out":"5"}"#, "wrap.near", "apple.umbrafun.near").unwrap_err(),
        E_BAD_MSG
    );
    let rv = DexKind::TokenCurve(TokenPad::RevShare);
    let m = r#"{"buy":{"min_tokens_out":"8152606193242112988485607","deadline_ns":"1790564564242000000"}}"#;
    assert_eq!(vp(rv, m, "wrap.near", "l0.revshare-launch.near").unwrap().min_out, 8152606193242112988485607);
    assert_eq!(vp(rv, m, "usdc.near", "l0.revshare-launch.near").unwrap_err(), E_BAD_MSG);
    assert!(vp(
        rv,
        r#"{"buy":{"min_tokens_out":"5","deadline_ns":"0"}}"#,
        "wrap.near",
        "l0.revshare-launch.near"
    )
    .is_err());
    let cf = DexKind::TokenCurve(TokenPad::Chipfi);
    assert_eq!(
        vp(cf, r#"{"min_out":"1243075290478074750890319"}"#, "usdc.near", "c3.chipfi.near").unwrap().out,
        "c3.chipfi.near"
    );
    assert_eq!(vp(cf, r#"{"min_out":"5"}"#, "wrap.near", "c3.chipfi.near").unwrap_err(), E_BAD_MSG);
    assert!(vp(cf, r#"{"min_out":"5","for_account":"evil.near"}"#, "usdc.near", "c3.chipfi.near").is_err());
    // no FtTransferCall path for the rest (typed ops only)
    for p in [TokenPad::NearFun, TokenPad::Nearmemefun, TokenPad::Token0, TokenPad::Npad] {
        assert_eq!(
            vp(DexKind::TokenCurve(p), r#"{"min_out":"5"}"#, "wrap.near", "x.near").unwrap_err(),
            E_BAD_MSG
        );
    }
    assert_eq!(
        vp(DexKind::Kelytra, "deposit", "wrap.near", "exchange.kelytradevs.near").unwrap_err(),
        E_BAD_MSG
    );
    assert_eq!(vp(DexKind::RheaClassic, "{}", "wrap.near", "v2.ref-finance.near").unwrap_err(), E_BAD_MSG);
}

#[test]
fn parse_refuses_recipient_keys_everywhere() {
    let keys = ["receiver_id", "account_id", "for_account", "buy_for", "recipient", "referral", "to"];
    let cases: [(DexKind, &str, &str, &str); 7] = [
        (AID, r#"{"token":"x.aidols.near","min_swap_amount":"5"}"#, "wrap.near", "aidols.near"),
        (AID, r#"{"token":null,"min_swap_amount":"5"}"#, "x.aidols.near", "aidols.near"),
        (
            DexKind::FactoryCurve(FactoryPad::Nearrr),
            r#"{"sell":{"min_out":"5"}}"#,
            "x.nearrr-fun.near",
            "nearrr-fun.near",
        ),
        (
            DexKind::FactoryCurve(FactoryPad::Dragonpad),
            r#"{"sell":{"min_quote_out":"5"}}"#,
            "x.dragonpad.near",
            "dragonpad.near",
        ),
        (
            DexKind::TokenCurve(TokenPad::Umbra),
            r#"{"action":"buy","min_out":"5"}"#,
            "usdc.near",
            "x.umbrafun.near",
        ),
        (DexKind::TokenCurve(TokenPad::Chipfi), r#"{"min_out":"5"}"#, "usdc.near", "c1.chipfi.near"),
        (
            DexKind::FactoryCurve(FactoryPad::MemeCooking),
            r#"{"Deposit":{"meme_id":1}}"#,
            "wrap.near",
            "meme-cooking.near",
        ),
    ];
    for (k, m, t, r) in cases {
        assert!(vp(k, m, t, r).is_ok(), "{m}");
        let mut v: Value = serde_json::from_str(m).unwrap();
        for key in keys {
            let mut w = v.clone();
            w.as_object_mut().unwrap().insert(key.into(), json!("user.tt.near"));
            assert!(vp(k, &w.to_string(), t, r).is_err(), "{key} in {m}");
            // nested too
            if let Some((_, inner)) = v.as_object_mut().unwrap().iter_mut().find(|(_, x)| x.is_object()) {
                let mut i2 = inner.clone();
                i2.as_object_mut().unwrap().insert(key.into(), json!("user.tt.near"));
                let mut w2 = serde_json::from_str::<Value>(m).unwrap();
                let first = w2
                    .as_object()
                    .unwrap()
                    .iter()
                    .find(|(_, x)| x.is_object())
                    .map(|(k, _)| k.clone())
                    .unwrap();
                w2[&first] = i2;
                assert!(vp(k, &w2.to_string(), t, r).is_err(), "nested {key} in {m}");
            }
        }
    }
    // self as token_in or receiver
    assert_eq!(
        vp(AID, r#"{"token":null,"min_swap_amount":"5"}"#, "user.tt.near", "aidols.near").unwrap_err(),
        E_BAD_MSG
    );
    assert_eq!(
        vp(DexKind::TokenCurve(TokenPad::Chipfi), r#"{"min_out":"5"}"#, "usdc.near", "user.tt.near")
            .unwrap_err(),
        E_BAD_MSG
    );
}

// ======================= settlement fee math =======================

#[test]
fn curve_fee_exact() {
    use settle::curve_fee;
    let f = bps(NEAR, FEE_BPS);
    // near_in: fee on amount - refund; used = amount (spend never returned on a delta)
    assert_eq!(curve_fee("near_in", NEAR, f, FEE_BPS, 0, 0), (NEAR, f));
    assert_eq!(curve_fee("near_in", NEAR, f, FEE_BPS, NEAR / 4, 0), (NEAR, f * 3 / 4));
    assert_eq!(curve_fee("near_in", NEAR, f, FEE_BPS, NEAR, 0), (NEAR, 0));
    assert_eq!(curve_fee("near_in", NEAR, f, FEE_BPS, 5 * NEAR, 0), (NEAR, 0), "refund > amount clamps");
    // near_out: bps x min(arrived, cap)
    assert_eq!(curve_fee("near_out", 50, 0, FEE_BPS, 3 * NEAR, NEAR), (50, bps(NEAR, FEE_BPS)));
    assert_eq!(curve_fee("near_out", 50, 0, FEE_BPS, NEAR / 2, NEAR), (50, bps(NEAR / 2, FEE_BPS)));
    assert_eq!(curve_fee("near_out_reported", 50, 0, FEE_BPS, 0, NEAR), (50, 0));
    // wnear_out: bps x cap
    assert_eq!(curve_fee("wnear_out", 50, 0, FEE_BPS, 0, NEAR), (50, bps(NEAR, FEE_BPS)));
    // q_out / unknown: nothing
    assert_eq!(curve_fee("q_out", 50, 7, FEE_BPS, NEAR, NEAR), (50, 0));
    assert_eq!(curve_fee("bogus", 50, 7, FEE_BPS, NEAR, NEAR), (50, 0));
}

#[test]
fn settle_callback_args() {
    let (m, a2, g) = settle::callback(Settle::NearIn, r#"{"x":1}"#, 123, 456);
    assert_eq!((m, g), ("on_curve_settled", crate::GAS_CALLBACK));
    let v: Value = serde_json::from_str(&a2).unwrap();
    // F1: + the gas allowance (prepaid gas of the mocked receipt x GAS_PRICE_BOUND)
    assert_eq!(
        v,
        json!({"settle": {"x": 1}, "liquid_before": "123", "mode": "near_in", "cap": "456",
            "gas_allowance": settle::gas_allowance().to_string()})
    );
    assert_eq!(Settle::Wrap.proof(), "wrap");
    assert_eq!(Settle::Token.proof(), "token");
    assert_eq!(Settle::NearIn.proof(), "curve_near");
    assert_eq!(Settle::Out { native: false, reported: false, wnear: true }.proof(), "curve_out");
    assert!(!Settle::Wrap.measured() && !Settle::Token.measured());
    assert!(Settle::NearIn.measured());
}

proptest! {
    #[test]
    fn prop_curve_fee_bounds(amount in 1u128..=u128::MAX / 2, delta: u128, cap: u128, fb in 0u16..=100) {
        let fee = bps(amount, fb);
        let (u, c) = settle::curve_fee("near_in", amount, fee, fb, delta, cap);
        prop_assert_eq!(u, amount);
        prop_assert!(c <= fee);
        for mode in ["near_out", "near_out_reported"] {
            let (_, c) = settle::curve_fee(mode, amount, fee, fb, delta, cap);
            prop_assert!(c <= bps(cap, fb) && c <= bps(delta, fb));
        }
        let (_, c) = settle::curve_fee("wnear_out", amount, fee, fb, delta, cap);
        prop_assert_eq!(c, bps(cap, fb));
        let (_, c) = settle::curve_fee("q_out", amount, fee, fb, delta, cap);
        prop_assert_eq!(c, 0);
    }

    #[test]
    fn prop_parse_arbitrary_never_panics(msg in ".{0,200}", k in 0usize..12) {
        let kinds = [
            AID, PAT,
            DexKind::FactoryCurve(FactoryPad::Nearrr), DexKind::FactoryCurve(FactoryPad::VistaLaunch),
            DexKind::FactoryCurve(FactoryPad::VistaDex), DexKind::FactoryCurve(FactoryPad::Dragonpad),
            DexKind::FactoryCurve(FactoryPad::Nira), DexKind::FactoryCurve(FactoryPad::MemeCooking),
            DexKind::TokenCurve(TokenPad::Umbra), DexKind::TokenCurve(TokenPad::RevShare),
            DexKind::TokenCurve(TokenPad::Chipfi), DexKind::Kelytra,
        ];
        if let Ok(s) = vp(kinds[k], &msg, "x.aidols.near", "aidols.near") {
            prop_assert!(s.min_out > 0);
        }
    }

    #[test]
    fn prop_parse_mutated(
        which in 0usize..9,
        min in any::<u128>(),
        tok_label in "[a-z0-9]{1,8}",
        extra in proptest::option::of(("[a-z_]{1,12}", "[a-z.]{1,12}")),
        token_is_null in any::<bool>(),
    ) {
        let t = format!("{tok_label}.aidols.near");
        let (k, mut v, tin, rcv): (DexKind, Value, String, String) = match which {
            0 => (AID, json!({"token": if token_is_null { Value::Null } else { json!(t) }, "min_swap_amount": min.to_string()}),
                if token_is_null { t.clone() } else { "wrap.near".into() }, "aidols.near".into()),
            1 => (DexKind::FactoryCurve(FactoryPad::Nearrr), json!({"sell": {"min_out": min.to_string()}}),
                format!("{tok_label}.nearrr-fun.near"), "nearrr-fun.near".into()),
            2 => (DexKind::FactoryCurve(FactoryPad::Dragonpad), json!({"sell": {"min_quote_out": min.to_string()}}),
                format!("{tok_label}.dragonpad.near"), "dragonpad.near".into()),
            3 => (DexKind::FactoryCurve(FactoryPad::Nira),
                json!({"buy": {"launch_id": tok_label, "min_tokens_out": min.to_string(), "deadline_ms": "1"}}),
                "usdc.near".into(), "curve10.latedata9580.near".into()),
            4 => (DexKind::TokenCurve(TokenPad::Umbra), json!({"action": "buy", "min_out": min.to_string()}),
                "usdc.near".into(), format!("{tok_label}.umbrafun.near")),
            5 => (DexKind::TokenCurve(TokenPad::Chipfi), json!({"min_out": min.to_string()}),
                "usdc.near".into(), format!("{tok_label}.chipfi.near")),
            6 => (DexKind::TokenCurve(TokenPad::RevShare), json!({"buy": {"min_tokens_out": min.to_string(), "deadline_ns": "1"}}),
                "wrap.near".into(), format!("{tok_label}.revshare-launch.near")),
            7 => (DexKind::FactoryCurve(FactoryPad::VistaLaunch), json!({"sell": {"min_out": min.to_string()}}),
                format!("{tok_label}.launch.vistadev.near"), "launch.vistadev.near".into()),
            _ => (PAT, json!({"token": null, "min_swap_amount": min.to_string()}),
                format!("{tok_label}.patata-monster.near"), "patata-monster.near".into()),
        };
        let with_extra = extra.is_some();
        if let Some((ek, ev)) = extra {
            v.as_object_mut().unwrap().insert(ek, json!(ev));
        }
        let r = vp(k, &v.to_string(), &tin, &rcv);
        if with_extra {
            prop_assert!(r.is_err(), "unknown field accepted: {}", v);
        } else if min == 0 {
            prop_assert_eq!(r.unwrap_err(), E_MIN_OUT);
        } else {
            let s = r.unwrap();
            prop_assert_eq!(s.min_out, min);
            let out: AccountId = s.out.parse().unwrap();
            let rid: AccountId = rcv.parse().unwrap();
            prop_assert!(one_label_under(&rid, &out) || out == rid || s.out == "wrap.near" || s.out == PATATA,
                "out {} not under {}", s.out, rcv);
        }
    }

    #[test]
    fn prop_plan_invariants(
        vi in 0usize..14,
        market in proptest::option::of("[a-z0-9.\\-]{0,20}"),
        qi in 0usize..4,
        amount: u128,
        min_out: u128,
        max_out in proptest::option::of(any::<u128>()),
        gas in 0u64..400 * TGAS,
        buy: bool,
    ) {
        plan_invariants(vi, market, qi, amount, min_out, max_out, gas, buy)?;
    }

    /// Siblings of the pinned Kelytra case: every VALID trade (all_valid: one per pad and side,
    /// incl. Nearrr buys and Kelytra) with random gas, bounds and `setup`. The random-market
    /// generator above almost never hits a valid market, so the callback-chain venues need this.
    #[test]
    fn prop_plan_gas_valid_trades(
        i in 0usize..64,
        amount in 1u128..=u128::MAX,
        min_out in 1u128..=u128::MAX,
        gas in 0u64..400 * TGAS,
        setup: bool,
    ) {
        let v = sibling_trades();
        let (buy, t) = v[i % v.len()].clone();
        let t = CurveTrade { amount: U128(amount), min_out: U128(min_out), gas: U64(gas), setup, ..t };
        plan_gas_invariants(buy, &t)?;
    }
}

/// `all_valid` plus one valid trade per remaining pad / quote / side (the sibling search).
fn sibling_trades() -> Vec<(bool, CurveTrade)> {
    let mut v = all_valid();
    for buy in [true, false] {
        v.push((buy, tr("patata-monster.near", Some("poop.patata-monster.near"), Some(PATATA), 5, 5)));
        v.push((buy, tr("gra-fun.near", Some("fot.gra-fun.near"), None, 5, 5)));
        v.push((buy, tr("dragonpad.near", Some("ember.dragonpad.near"), None, 5, 5)));
        v.push((buy, tr("launch.vistadev.near", Some("v.launch.vistadev.near"), None, 5, 5)));
        for tok in [
            "x.nearfunio.near",
            "x.revshare-launch.near",
            "x.token0.near",
            "x.npad.near",
            "x.nearmemefun.near",
        ] {
            v.push((buy, tr(tok, None, None, 5, 5)));
        }
    }
    // token0 buys are exact-out only (max_out): dropped; every other trade plans at MAX gas
    v.retain(|(buy, t)| !(*buy && t.venue.as_str() == "x.token0.near"));
    assert!(v.iter().all(|(buy, t)| plan_t(
        *buy,
        &CurveTrade { gas: U64(MAX_CURVE_GAS * TGAS), ..t.clone() }
    )
    .is_ok()));
    v
}

const VENUES: [&str; 14] = [
    "aidols.near",
    "patata-monster.near",
    "launch.vistadev.near",
    "dex.vistadev.near",
    "nearrr-fun.near",
    "curve10.latedata9580.near",
    "meme-cooking.near",
    "dragonpad.near",
    "x.nearfunio.near",
    "x.umbrafun.near",
    "x.revshare-launch.near",
    "x.token0.near",
    "c1.chipfi.near",
    "exchange.kelytradevs.near",
];

/// The body of `prop_plan_invariants` (also replayed on pinned inputs).
#[allow(clippy::too_many_arguments)]
fn plan_invariants(
    vi: usize,
    market: Option<String>,
    qi: usize,
    amount: u128,
    min_out: u128,
    max_out: Option<u128>,
    gas: u64,
    buy: bool,
) -> Result<(), TestCaseError> {
    let quotes = [None, Some("wrap.near"), Some(PATATA), Some("usdc.near")];
    let t = CurveTrade {
        venue: a(VENUES[vi]),
        market,
        quote: quotes[qi].map(a),
        amount: U128(amount),
        min_out: U128(min_out),
        max_out: max_out.map(U128),
        gas: U64(gas),
        setup: false,
    };
    if let Ok(p) = plan_t(buy, &t) {
        prop_assert!(!p.calls.is_empty());
        prop_assert!(p.calls.iter().all(|c| c.receiver == p.calls[0].receiver));
        plan_gas_ok(&p, &t)?;
        prop_assert!(p.swap.min_out > 0 && min_out > 0 && amount > 0);
        let dep: u128 = p.calls.iter().map(|c| c.deposit).sum();
        prop_assert_eq!(dep, p.native_out);
        let extra = VISTA_BUY_STORAGE.max(NIRA_BUY_STORAGE);
        for c in &p.calls {
            prop_assert!(
                c.deposit <= 1 || (buy && c.deposit >= amount && c.deposit - amount <= extra),
                "deposit {} for amount {}",
                c.deposit,
                amount
            );
        }
        prop_assert!(p.fee <= bps(amount.max(min_out), FEE_BPS));
        check_recipients(&p, &t);
    }
    Ok(())
}

/// Gas of a plan. The op's `gas` is what its trade attaches: the trade call(s) at the venue (the
/// batch whose result settles) and, for a venue whose trade continues in callbacks (Kelytra's
/// round trip incl. its `setup` registrations, a Nearrr buy's view -> buy), the rest of that
/// chain. Elsewhere a registration the venue plans before the trade (an Aidols-family
/// `storage_deposit`, another receiver) is on top (`declared`).
/// `p.gas` (what `run` budgets, plus GAS_CALLBACK for the settle callback) covers all of it:
/// calls + first callback == p.gas + GAS_CALLBACK, and the op alone fits one 300 TGas execute.
fn plan_gas_ok(p: &Plan, t: &CurveTrade) -> Result<(), TestCaseError> {
    let calls: u64 = p.calls.iter().map(|c| c.gas).sum();
    let pre = p.gas - declared(p);
    let cb = if p.settle.measured() { settle::callback(p.settle, "{}", 0, 0).2 } else { crate::GAS_CALLBACK };
    prop_assert!(p.gas - pre <= t.gas.0, "plan gas {} (registrations {}) declared {}", p.gas, pre, t.gas.0);
    prop_assert_eq!(
        p.gas + crate::GAS_CALLBACK * TGAS,
        calls + cb * TGAS,
        "plan gas vs calls + first callback"
    );
    // run's budget for this op alone: op gas + an action per extra call + the op's action +
    // the callback and its action
    let n = p.calls.len() as u64;
    let total =
        p.gas + n * crate::GAS_PER_ACTION * TGAS + (crate::GAS_CALLBACK + crate::GAS_PER_ACTION) * TGAS;
    prop_assert!(crate::policy::check_gas(1, total, 300 * TGAS).is_ok(), "{} TGas", total / TGAS);
    Ok(())
}

/// The part of `p.gas` the op declares: a callback-chain venue (Kelytra, a Nearrr buy) declares
/// its whole chain, registrations included; any other venue all but the registrations planned
/// before the trade (calls to another receiver than the trade's).
fn declared(p: &Plan) -> u64 {
    if matches!(p.settle, Settle::Kelytra { .. } | Settle::NearrrTax { .. }) {
        return p.gas;
    }
    let last = &p.calls.last().expect("calls").receiver;
    p.gas - p.calls.iter().filter(|c| &c.receiver != last).map(|c| c.gas).sum::<u64>()
}

/// A valid trade (venue, market, side) either plans within the declared gas or is refused up
/// front: E_GAS only when the declared gas is out of [MIN, MAX] or below what the trade needs
/// (what it plans at MAX_CURVE_GAS); `setup` off Kelytra is E_BAD_OP once the gas is in range.
fn plan_gas_invariants(buy: bool, t: &CurveTrade) -> Result<(), TestCaseError> {
    let kel = t.venue.as_str() == "exchange.kelytradevs.near";
    let in_range = (MIN_CURVE_GAS * TGAS..=MAX_CURVE_GAS * TGAS).contains(&t.gas.0);
    match plan_t(buy, t) {
        Ok(p) => {
            prop_assert!(kel || !t.setup);
            plan_gas_ok(&p, t)?;
        }
        Err(e) if !in_range => prop_assert_eq!(e, E_GAS),
        Err(e) if t.setup && !kel => prop_assert_eq!(e, E_BAD_OP),
        Err(e) => {
            prop_assert_eq!(e, E_GAS);
            let need = plan_t(buy, &CurveTrade { gas: U64(MAX_CURVE_GAS * TGAS), ..t.clone() })
                .map_err(|e| TestCaseError::fail(format!("valid trade refused at MAX gas: {e}")))?;
            let need = declared(&need);
            prop_assert!(t.gas.0 < need, "refused at {} TGas, needs {}", t.gas.0 / TGAS, need / TGAS);
        }
    }
    Ok(())
}

/// Pinned regression (proptest input): Kelytra sell, launch "0", amount 1, min_out 1, declared
/// gas 165 TGas = exactly the round trip (deposit 40 + on_kelytra_deposited's chain 135, minus
/// the GAS_CALLBACK run budgets separately).
#[test]
fn prop_plan_invariants_pinned_kelytra_sell_165_tgas() {
    plan_invariants(13, Some("0".into()), 0, 1, 1, None, 165 * TGAS, false).unwrap();
    // its siblings at the boundary: a buy (+ near_deposit 10) and both setup trades
    for (buy, setup) in [(false, false), (true, false), (false, true), (true, true)] {
        let t = CurveTrade { setup, gas: U64(MAX_CURVE_GAS * TGAS), ..trk(Some("0"), None, 1, 1) };
        let need = declared(&plan_t(buy, &t).unwrap());
        for g in [need - 1, need, need + 1] {
            plan_gas_invariants(buy, &CurveTrade { gas: U64(g), ..t.clone() }).unwrap();
        }
    }
}
