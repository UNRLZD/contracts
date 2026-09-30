//! v1.4 NEAR Intents (1Click) cross-chain withdrawals (spec: docs/intents-spec.md §3).
//! Pure logic here (quote parser, signature message, checks, ISO time) is unit/property
//! tested natively; the contract methods live in lib.rs. All state is stored under its own
//! raw keys (not in STATE), so the v1.3 layout is unchanged and `migrate` stays a no-op.
use near_sdk::{env, near, AccountId};

use crate::policy::{DAY_NS, NS_PER_SEC};

/// Decision 3: a destination activates 1 h after the owner-signed add.
pub const DEST_DELAY_NS: u64 = 3_600 * NS_PER_SEC;
pub const MAX_DESTS: usize = 16;
pub const MAX_LABEL_LEN: usize = 32;
pub const MAX_DEST_FIELD_LEN: usize = 128;
pub const MAX_ONECLICK_KEYS: usize = 3;
pub const MAX_SLIPPAGE_BPS: u16 = 300;
/// The quote must stay valid at least this long after execution.
pub const MIN_DEADLINE_LEAD_NS: u64 = 60 * NS_PER_SEC;
pub const MAX_SIGNED_QUOTE_LEN: usize = 2_048;
pub const DEFAULT_INTENTS: &str = "intents.near";
/// v1.4.1 (B1-M1): signed `amountOutUsd / amountInUsd >= 1 - max_loss_bps` (1Click fee + our
/// appFees + spread + network fee). Owner-set within [MIN, MAX].
/// v1.4.2 (C1-L1): default 50 bps (was 100), owner range 30..=300.
pub const DEFAULT_MAX_LOSS_BPS: u16 = 50;
pub const MIN_MAX_LOSS_BPS: u16 = 30;
pub const MAX_MAX_LOSS_BPS: u16 = 300;
/// v1.4.1 (B1-M1): default daily withdraw cap in micro-USD (signed `amountInUsd`, all tokens).
/// v1.4.7: no default cap (was $1,000): u128::MAX, the UNLIMITED sentinel (the sum is checked,
/// so `spent + x <= u128::MAX` always holds; an impossible overflow fails closed). The owner
/// can still opt in to a cap with `owner_set_withdraw_cap`.
pub const DEFAULT_WITHDRAW_CAP_USD: u128 = u128::MAX;
/// v1.4.1 (B1-L3): funded deposit addresses kept (pruned after deadline + margin).
pub const MAX_USED_QUOTES: usize = 128;
pub const USED_QUOTE_MARGIN_NS: u64 = 3_600 * NS_PER_SEC;
/// v1.4.2 (C1-L2): a quote is fundable only while its signed `timestamp` (issue time) is at
/// most this old (and at most QUOTE_FUTURE_SKEW_NS ahead of block time): E_QUOTE_DEADLINE.
/// 1Click's signed `deadline` is request + 72 h, so the freshness bound is on `timestamp`.
/// Device markers then live timestamp + MAX_QUOTE_AGE + margin (~2 h) instead of ~73 h.
pub const MAX_QUOTE_AGE_NS: u64 = 3_600 * NS_PER_SEC;
pub const QUOTE_FUTURE_SKEW_NS: u64 = 300 * NS_PER_SEC;
/// Owner path: no signed deadline; 1Click deadlines are +72 h, keep a week.
pub const OWNER_ADDR_KEEP_NS: u64 = 7 * DAY_NS;
/// v1.4.8 (UNR-A-06): the owner space's own bound. Its markers live 7 days (device ones ~2 h),
/// so the shared 128 capped the owner at 128 intents withdrawals per rolling week. 512 entries
/// of 40 bytes (~20 KB, owner-paid storage) = ~73 a day.
pub const MAX_OWNER_QUOTES: usize = 512;
/// B2-H2: asset ids 1Click rewrites in the SIGNED `destinationAsset`/`originAsset` (request
/// form -> signed form). Destinations may be registered in either form; both compare equal.
pub const ASSET_ALIASES: [(&str, &str); 1] = [("nep141:btc.omft.near", "1cs_v1:btc:native:coin")];
/// 1Click manager key (SDK 0.1.26; verified 5/5 live quotes, spikes/intents).
pub const ONECLICK_MANAGER_KEY: &str = "ed25519:reYaWhvwu8Jzo3WUM3zhn6VrhuMEF4eADL17qtRVifc";

pub const K_DESTS: &[u8] = b"wds";
pub const K_ONECLICK: &[u8] = b"1c";
pub const K_WITHDRAW_CAP: &[u8] = b"wc";
pub const K_WITHDRAW_DAY: &[u8] = b"wt";
pub const K_WITHDRAW_CAP_USD: &[u8] = b"wu";
pub const K_USED_QUOTES: &[u8] = b"qs";
/// v1.4.2 (C1-L2): owner-path markers, a separate space (device markers never block the owner).
pub const K_OWNER_QUOTES: &[u8] = b"qo";

pub const RECIPIENT_TYPES: [&str; 2] = ["DESTINATION_CHAIN", "INTENTS"];

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq)]
pub struct Dest {
    pub label: String,
    /// 1Click `destinationAsset`, e.g. `nep141:sol-…omft.near`.
    pub asset: String,
    pub recipient: String,
    /// `DESTINATION_CHAIN` | `INTENTS`
    pub recipient_type: String,
    pub active_at_ns: near_sdk::json_types::U64,
}

#[near(serializers = [borsh])]
#[derive(Default)]
pub struct Dests {
    pub next_id: u32,
    pub list: Vec<(u32, Dest)>,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq)]
pub struct OneClickConfig {
    /// `ed25519:<bs58>` 1Click quote-signing keys (1..=3; rotation overlap).
    pub keys: Vec<String>,
    pub max_slippage_bps: u16,
    /// Verifier contract receiving `ft_transfer_call{msg: depositAddress}`.
    pub intents: AccountId,
    /// v1.4.1: max signed USD value loss (bps).
    pub max_loss_bps: u16,
}

/// v1.4.1: the cross-chain withdraw window: wNEAR yocto + prepaid-gas bound, and the signed
/// USD value (micro-USD) of every token.
#[near(serializers = [borsh])]
#[derive(Clone, Debug, Default, PartialEq)]
pub struct WDay {
    pub start_ns: u64,
    pub spent_yocto: u128,
    pub spent_usd: u128,
}

impl WDay {
    /// v1.4.1 (D5): UTC-day window, resets at 00:00 UTC.
    pub fn roll(&mut self, now: u64) {
        let today = crate::policy::utc_day_start(now);
        if self.start_ns != today {
            *self = WDay { start_ns: today, ..WDay::default() };
        }
    }
}

/// The checked fields of the signed payload (`stableStringify({...request, ...quote,
/// timestamp})`, SDK 0.1.26), borrowed from it.
#[derive(Debug, Default)]
pub struct Quote<'a> {
    pub dry: bool,
    pub swap_type: &'a str,
    pub deposit_type: &'a str,
    pub origin_asset: &'a str,
    pub destination_asset: &'a str,
    pub amount: &'a str,
    pub amount_in: &'a str,
    pub refund_to: &'a str,
    pub refund_type: &'a str,
    pub recipient: &'a str,
    pub recipient_type: &'a str,
    pub slippage_tolerance: u16,
    pub min_amount_out: &'a str,
    /// v1.4.1: signed USD values (decimal strings) used for the loss bound and the USD cap.
    pub amount_in_usd: &'a str,
    pub amount_out_usd: &'a str,
    /// Non-dry quotes: the quote's deadline (it overrides the request's in the spread).
    pub deadline: &'a str,
    /// v1.4.2: signed issue time.
    pub timestamp: &'a str,
    pub deposit_address: Option<&'a str>,
    pub deposit_memo: Option<&'a str>,
    pub custom_recipient_msg: Option<&'a str>,
}

/// Signed but not checked (any scalar value accepted).
const IGNORED: [&str; 10] = [
    "amountInFormatted",
    "minAmountIn",
    "amountOut",
    "amountOutFormatted",
    "timeWhenInactive",
    "timeEstimate",
    "refundFee",
    "withdrawFee",
    "quoteWaitingTimeMs",
    "referral",
];

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Val<'a> {
    Str(&'a str),
    Num(&'a str),
    Bool(bool),
    Null,
}

/// Strict parser for a FLAT JSON object of scalars (what 1Click signs). Fail-closed subset of
/// RFC 8259: no nesting, no escape sequences, no control chars, no duplicate keys. Anything
/// else is None (a parser differential can't be exploited: only 1Click-signed bytes reach it).
pub fn parse_flat(s: &str) -> Option<Vec<(&str, Val<'_>)>> {
    let b = s.as_bytes();
    let mut i = 0;
    let ws = |i: &mut usize| {
        while *i < b.len() && matches!(b[*i], b' ' | b'\t' | b'\n' | b'\r') {
            *i += 1;
        }
    };
    let string = |i: &mut usize| -> Option<&str> {
        if b.get(*i) != Some(&b'"') {
            return None;
        }
        let st = *i + 1;
        let mut j = st;
        loop {
            match *b.get(j)? {
                b'"' => break,
                b'\\' => return None,
                c if c < 0x20 => return None,
                _ => j += 1,
            }
        }
        *i = j + 1;
        s.get(st..j)
    };
    let digits = |i: &mut usize| -> usize {
        let st = *i;
        while *i < b.len() && b[*i].is_ascii_digit() {
            *i += 1;
        }
        *i - st
    };
    let mut out: Vec<(&str, Val)> = Vec::new();
    ws(&mut i);
    if b.get(i) != Some(&b'{') {
        return None;
    }
    i += 1;
    ws(&mut i);
    if b.get(i) == Some(&b'}') {
        i += 1;
    } else {
        loop {
            ws(&mut i);
            let k = string(&mut i)?;
            ws(&mut i);
            if b.get(i) != Some(&b':') {
                return None;
            }
            i += 1;
            ws(&mut i);
            let v = match *b.get(i)? {
                b'"' => Val::Str(string(&mut i)?),
                b't' if b[i..].starts_with(b"true") => {
                    i += 4;
                    Val::Bool(true)
                }
                b'f' if b[i..].starts_with(b"false") => {
                    i += 5;
                    Val::Bool(false)
                }
                b'n' if b[i..].starts_with(b"null") => {
                    i += 4;
                    Val::Null
                }
                b'-' | b'0'..=b'9' => {
                    let st = i;
                    if b[i] == b'-' {
                        i += 1;
                    }
                    let n = digits(&mut i);
                    if n == 0 || (n > 1 && b[i - n] == b'0') {
                        return None;
                    }
                    if b.get(i) == Some(&b'.') {
                        i += 1;
                        if digits(&mut i) == 0 {
                            return None;
                        }
                    }
                    if matches!(b.get(i), Some(b'e' | b'E')) {
                        i += 1;
                        if matches!(b.get(i), Some(b'+' | b'-')) {
                            i += 1;
                        }
                        if digits(&mut i) == 0 {
                            return None;
                        }
                    }
                    Val::Num(&s[st..i])
                }
                _ => return None,
            };
            if out.iter().any(|(x, _)| *x == k) {
                return None;
            }
            out.push((k, v));
            ws(&mut i);
            match *b.get(i)? {
                b',' => i += 1,
                b'}' => {
                    i += 1;
                    break;
                }
                _ => return None,
            }
        }
    }
    ws(&mut i);
    (i == b.len()).then_some(out)
}

/// E_QUOTE_MISMATCH unless `s` is a flat object with every required field of the right type
/// and no field outside the SDK 0.1.26 signed set (fail closed: a new signed field might change
/// semantics, e.g. virtualChain*).
pub fn parse_quote(s: &str) -> Result<Quote<'_>, &'static str> {
    const E: &str = "E_QUOTE_MISMATCH";
    if s.len() > MAX_SIGNED_QUOTE_LEN {
        return Err(E);
    }
    let mut q = Quote::default();
    let mut seen: u32 = 0;
    for (k, v) in parse_flat(s).ok_or(E)? {
        let (bit, slot): (u32, Option<&mut &str>) = match k {
            "swapType" => (1, Some(&mut q.swap_type)),
            "depositType" => (2, Some(&mut q.deposit_type)),
            "originAsset" => (3, Some(&mut q.origin_asset)),
            "destinationAsset" => (4, Some(&mut q.destination_asset)),
            "amount" => (5, Some(&mut q.amount)),
            "amountIn" => (6, Some(&mut q.amount_in)),
            "refundTo" => (7, Some(&mut q.refund_to)),
            "refundType" => (8, Some(&mut q.refund_type)),
            "recipient" => (9, Some(&mut q.recipient)),
            "recipientType" => (10, Some(&mut q.recipient_type)),
            "minAmountOut" => (11, Some(&mut q.min_amount_out)),
            "deadline" => (12, Some(&mut q.deadline)),
            "dry" => (13, None),
            "slippageTolerance" => (14, None),
            "amountInUsd" => (15, Some(&mut q.amount_in_usd)),
            "amountOutUsd" => (16, Some(&mut q.amount_out_usd)),
            "timestamp" => (17, Some(&mut q.timestamp)),
            _ => (0, None),
        };
        match (k, v, slot) {
            (_, Val::Str(x), Some(slot)) => *slot = x,
            ("dry", Val::Bool(x), _) => q.dry = x,
            ("slippageTolerance", Val::Num(x), _) => q.slippage_tolerance = x.parse().map_err(|_| E)?,
            ("depositAddress", Val::Str(x), _) => q.deposit_address = Some(x),
            ("depositMemo", Val::Str(x), _) => q.deposit_memo = Some(x),
            ("customRecipientMsg", Val::Str(x), _) => q.custom_recipient_msg = Some(x),
            ("depositAddress" | "depositMemo" | "customRecipientMsg", Val::Null, _) => {}
            (k, _, None) if bit == 0 && IGNORED.contains(&k) => {}
            _ => return Err(E),
        }
        seen |= 1 << bit;
    }
    // all 16 required fields present (bit 0 = optional/ignored ones)
    if seen | 1 != (1 << 18) - 1 {
        return Err(E);
    }
    Ok(q)
}

/// What 1Click signs: the UTF-8 of `bs58(sha256(signed_quote))`.
pub fn signed_message(signed_quote: &[u8]) -> String {
    near_sdk::bs58::encode(env::sha256_array(signed_quote)).into_string()
}

fn b58_prefixed<const N: usize>(s: &str) -> Option<[u8; N]> {
    let b = near_sdk::bs58::decode(s.strip_prefix("ed25519:")?).into_vec().ok()?;
    b.try_into().ok()
}

pub fn parse_pk(s: &str) -> Option<[u8; 32]> {
    b58_prefixed(s)
}

pub fn parse_sig(s: &str) -> Option<[u8; 64]> {
    b58_prefixed(s)
}

/// E_QUOTE_SIG unless one of `keys` signed `signed_quote`.
pub fn verify_quote_sig(signed_quote: &str, signature: &str, keys: &[String]) -> Result<(), &'static str> {
    let sig = parse_sig(signature).ok_or("E_QUOTE_SIG")?;
    let msg = signed_message(signed_quote.as_bytes());
    if keys.iter().filter_map(|k| parse_pk(k)).any(|pk| env::ed25519_verify(&sig, msg.as_bytes(), &pk)) {
        Ok(())
    } else {
        Err("E_QUOTE_SIG")
    }
}

pub fn check_config(c: &OneClickConfig) -> Result<(), &'static str> {
    if c.keys.is_empty()
        || c.keys.len() > MAX_ONECLICK_KEYS
        || c.keys.iter().any(|k| parse_pk(k).is_none())
        || c.max_slippage_bps > MAX_SLIPPAGE_BPS
        || !(MIN_MAX_LOSS_BPS..=MAX_MAX_LOSS_BPS).contains(&c.max_loss_bps)
    {
        return Err("E_BAD_ONECLICK");
    }
    Ok(())
}

pub fn check_dest(d: &Dest) -> Result<(), &'static str> {
    // B1-I3: '"' / '\\' would need a JSON escape, which parse_flat rejects (never usable).
    let bad = |s: &str, max: usize| {
        s.is_empty() || s.len() > max || s.chars().any(|c| c.is_control() || c == '"' || c == '\\')
    };
    let bad_label = |s: &str| s.is_empty() || s.len() > MAX_LABEL_LEN || s.chars().any(|c| c.is_control());
    if bad_label(&d.label)
        || bad(&d.asset, MAX_DEST_FIELD_LEN)
        || bad(&d.recipient, MAX_DEST_FIELD_LEN)
        || !RECIPIENT_TYPES.contains(&d.recipient_type.as_str())
    {
        return Err("E_BAD_DEST");
    }
    Ok(())
}

/// 1Click INTENTS deposit address: 64 lowercase hex chars (an implicit intents account).
pub fn is_deposit_address(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub struct Expect<'a> {
    pub self_id: &'a str,
    pub token: &'a str,
    pub amount: u128,
    pub dest: &'a Dest,
    pub max_slippage_bps: u16,
    pub max_loss_bps: u16,
    pub now_ns: u64,
}

/// What a passing quote binds, for the caller: deposit address, signed deadline and the signed
/// input value in micro-USD (rounded up).
#[derive(Debug, PartialEq)]
pub struct Checked<'q> {
    pub deposit_address: &'q str,
    pub deadline_ns: u64,
    /// v1.4.2: signed issue time; the replay marker lives until issued + MAX_QUOTE_AGE + margin.
    pub issued_ns: u64,
    pub usd_in_micros: u128,
}

/// B2-H2: the signed form of an asset id (aliases resolved); anything else unchanged.
pub fn canon_asset(a: &str) -> &str {
    ASSET_ALIASES.iter().find(|(req, _)| *req == a).map_or(a, |(_, signed)| signed)
}

/// Strict unsigned integer: `0` or `[1-9][0-9]*` (B1-I3: no '+', no leading zeros).
pub fn parse_uint(s: &str) -> Option<u128> {
    let b = s.as_bytes();
    if b.is_empty() || !b.iter().all(u8::is_ascii_digit) || (b.len() > 1 && b[0] == b'0') {
        return None;
    }
    s.parse().ok()
}

/// Signed USD decimal (`[0-9]{1,18}(\.[0-9]+)?`) -> pico-USD (1e-12), extra digits truncated.
pub fn parse_usd(s: &str) -> Option<u128> {
    let (i, f) = s.split_once('.').unwrap_or((s, ""));
    if i.is_empty() || i.len() > 18 || !i.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if s.contains('.') && (f.is_empty() || !f.bytes().all(|b| b.is_ascii_digit())) {
        return None;
    }
    let frac = f.bytes().take(12).fold(0u128, |a, c| a * 10 + u128::from(c - b'0'));
    let scale = 10u128.pow(12 - f.len().min(12) as u32);
    Some(i.parse::<u128>().ok()? * 1_000_000_000_000 + frac * scale)
}

/// Spec §3 step 4 (+ v1.4.1 loss bound). Order: E_QUOTE_MISMATCH, E_QUOTE_EXPIRED,
/// E_QUOTE_LOSS.
pub fn check_quote<'q>(q: &Quote<'q>, e: &Expect) -> Result<Checked<'q>, &'static str> {
    const M: &str = "E_QUOTE_MISMATCH";
    let amount = e.amount.to_string();
    let addr = q.deposit_address.unwrap_or("");
    let token_asset = format!("nep141:{}", e.token);
    let ok = !q.dry
        && q.swap_type == "EXACT_INPUT"
        && q.deposit_type == "INTENTS"
        && canon_asset(q.origin_asset) == canon_asset(&token_asset)
        && q.amount == amount
        && q.amount_in == amount
        && canon_asset(q.destination_asset) == canon_asset(&e.dest.asset)
        && q.recipient == e.dest.recipient
        && q.recipient_type == e.dest.recipient_type
        && q.refund_to == e.self_id
        && q.refund_type == "ORIGIN_CHAIN"
        && q.slippage_tolerance <= e.max_slippage_bps
        && parse_uint(q.min_amount_out).is_some_and(|m| m > 0)
        && q.custom_recipient_msg.is_none()
        && q.deposit_memo.is_none()
        && is_deposit_address(addr);
    if !ok {
        return Err(M);
    }
    let (usd_in, usd_out) = (parse_usd(q.amount_in_usd).ok_or(M)?, parse_usd(q.amount_out_usd).ok_or(M)?);
    let deadline = parse_iso_ns(q.deadline).ok_or(M)?;
    let issued = parse_iso_ns(q.timestamp).ok_or(M)?;
    if deadline <= e.now_ns.saturating_add(MIN_DEADLINE_LEAD_NS) {
        return Err("E_QUOTE_EXPIRED");
    }
    // C1-L2: freshness (bounds how long a replay marker must live)
    if issued.saturating_add(MAX_QUOTE_AGE_NS) < e.now_ns
        || issued > e.now_ns.saturating_add(QUOTE_FUTURE_SKEW_NS)
    {
        return Err("E_QUOTE_DEADLINE");
    }
    // B1-M1: unsigned appFees etc. show up as signed USD value lost. No USD price => no bound.
    let floor = usd_in.checked_mul(u128::from(10_000 - e.max_loss_bps.min(10_000))).ok_or(M)?;
    if usd_in == 0 || usd_out.checked_mul(10_000).ok_or(M)? < floor {
        return Err("E_QUOTE_LOSS");
    }
    Ok(Checked {
        deposit_address: addr,
        deadline_ns: deadline,
        issued_ns: issued,
        usd_in_micros: usd_in.div_ceil(1_000_000),
    })
}

/// `YYYY-MM-DDTHH:MM:SS[.f{1,9}]Z` (UTC, years 1970..=2500) -> unix ns. Strict: anything
/// else is None.
pub fn parse_iso_ns(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' {
        return None;
    }
    if *b.last()? != b'Z' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<u64> {
        let d = b.get(r)?;
        if !d.iter().all(u8::is_ascii_digit) {
            return None;
        }
        Some(d.iter().fold(0u64, |a, c| a * 10 + u64::from(c - b'0')))
    };
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    let frac = &b[19..b.len() - 1];
    let nanos = match frac {
        [] => 0,
        [b'.', digits @ ..] if (1..=9).contains(&digits.len()) => {
            num(20..20 + digits.len())? * 10u64.pow(9 - digits.len() as u32)
        }
        _ => return None,
    };
    if !(1970..=2500).contains(&y) || !(1..=12).contains(&mo) || h > 23 || mi > 59 || sec > 59 {
        return None;
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let mdays = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if d == 0 || d > mdays[(mo - 1) as usize] {
        return None;
    }
    let days = days_from_civil(y, mo, d);
    ((days * 86_400 + h * 3_600 + mi * 60 + sec) * NS_PER_SEC).checked_add(nanos)
}

/// Days since 1970-01-01 (H. Hinnant's algorithm), y >= 1970.
fn days_from_civil(y: u64, m: u64, d: u64) -> u64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

// ---------------- storage (raw keys) ----------------

fn read<T: near_sdk::borsh::BorshDeserialize>(k: &[u8]) -> Option<T> {
    env::storage_read(k)
        .map(|b| near_sdk::borsh::from_slice(&b).unwrap_or_else(|_| env::panic_str("E_STATE")))
}

fn write<T: near_sdk::borsh::BorshSerialize>(k: &[u8], v: &T) {
    env::storage_write(k, &near_sdk::borsh::to_vec(v).unwrap_or_else(|_| env::panic_str("E_STATE")));
}

pub fn dests() -> Dests {
    read(K_DESTS).unwrap_or_default()
}

pub fn save_dests(d: &Dests) {
    write(K_DESTS, d)
}

pub fn oneclick() -> Option<OneClickConfig> {
    read(K_ONECLICK)
}

pub fn save_oneclick(c: &OneClickConfig) {
    write(K_ONECLICK, c)
}

/// Owner-set withdraw cap, else None (= the trading daily cap, decision 6).
pub fn withdraw_cap() -> Option<u128> {
    read(K_WITHDRAW_CAP)
}

pub fn save_withdraw_cap(v: u128) {
    write(K_WITHDRAW_CAP, &v)
}

/// v1.4.1: daily USD cap (micro-USD), default DEFAULT_WITHDRAW_CAP_USD (v1.4.7: no cap).
/// v1.4.6: the owner-set USD cap, None if never set.
pub fn withdraw_cap_usd_set() -> Option<u128> {
    read(K_WITHDRAW_CAP_USD)
}

pub fn withdraw_cap_usd() -> u128 {
    read(K_WITHDRAW_CAP_USD).unwrap_or(DEFAULT_WITHDRAW_CAP_USD)
}

pub fn save_withdraw_cap_usd(v: u128) {
    write(K_WITHDRAW_CAP_USD, &v)
}

pub fn withdraw_day() -> WDay {
    read(K_WITHDRAW_DAY).unwrap_or_default()
}

pub fn save_withdraw_day(d: &WDay) {
    write(K_WITHDRAW_DAY, d)
}

fn addr_bytes(addr: &str) -> [u8; 32] {
    // addr is 64 lowercase hex (checked by the caller)
    let h = addr.as_bytes();
    let nib = |c: u8| if c.is_ascii_digit() { c - b'0' } else { c.wrapping_sub(b'a').wrapping_add(10) };
    let mut k = [0u8; 32];
    for (i, p) in h.chunks(2).take(32).enumerate() {
        k[i] = nib(p[0]) << 4 | nib(p[1]);
    }
    k
}

/// Funded deposit addresses with the time after which they are pruned (B1-L3). v1.4.2: device
/// path in `qs`, owner path in `qo` (C1-L2: the owner is never blocked by device markers).
pub fn used_quotes() -> Vec<([u8; 32], u64)> {
    read(K_USED_QUOTES).unwrap_or_default()
}

pub fn owner_quotes() -> Vec<([u8; 32], u64)> {
    read(K_OWNER_QUOTES).unwrap_or_default()
}

fn live_in(v: &[([u8; 32], u64)], key: &[u8; 32], now: u64) -> bool {
    v.iter().any(|(a, t)| a == key && *t >= now)
}

/// Funded by either path and not yet pruned.
pub fn is_quote_used(addr: &str, now: u64) -> bool {
    is_deposit_address(addr) && {
        let k = addr_bytes(addr);
        live_in(&used_quotes(), &k, now) || live_in(&owner_quotes(), &k, now)
    }
}

fn mark_in(store: &[u8], addr: &str, keep_until: u64, now: u64, max: usize) -> Result<(), &'static str> {
    let key = addr_bytes(addr);
    let mut v: Vec<([u8; 32], u64)> = read(store).unwrap_or_default();
    v.retain(|(_, t)| *t >= now);
    if v.iter().any(|(a, _)| *a == key) {
        return Err("E_QUOTE_REPLAY");
    }
    if v.len() >= max {
        return Err("E_QUOTES_FULL");
    }
    v.push((key, keep_until));
    write(store, &v);
    Ok(())
}

/// Device path: exactly-once per deposit address; also refused if the OWNER funded it (B1-I2).
/// Prunes expired entries first; E_QUOTES_FULL at MAX_USED_QUOTES live entries. Safe to prune:
/// after keep_until a replay fails E_QUOTE_DEADLINE (issued + MAX_QUOTE_AGE < now).
pub fn mark_quote_used(addr: &str, keep_until: u64, now: u64) -> Result<(), &'static str> {
    if live_in(&owner_quotes(), &addr_bytes(addr), now) {
        return Err("E_QUOTE_REPLAY");
    }
    mark_in(K_USED_QUOTES, addr, keep_until, now, MAX_USED_QUOTES)
}

/// Owner path: its own marker space, checked only against itself.
pub fn mark_owner_quote(addr: &str, keep_until: u64, now: u64) -> Result<(), &'static str> {
    mark_in(K_OWNER_QUOTES, addr, keep_until, now, MAX_OWNER_QUOTES)
}
