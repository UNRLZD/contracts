//! Pure policy logic: expiry, dedupe, caps window, gas budget, reserve, fee math.
//! No env access, so everything here is unit/property tested natively.
use crate::Caps;
use near_sdk::near;

pub const NS_PER_SEC: u64 = 1_000_000_000;
pub const MAX_EXPIRY_AHEAD_NS: u64 = 120 * NS_PER_SEC;
pub const DAY_NS: u64 = 86_400 * NS_PER_SEC;
pub const MAX_ORDER_ID_LEN: usize = 64;
pub const MAX_SEEN_ORDERS: usize = 256;
pub const MAX_OPS: usize = 4;
pub const GAS_OVERHEAD: u64 = 15_000_000_000_000; // 15 TGas kept for execute itself
pub const RESERVE: u128 = 50_000_000_000_000_000_000_000; // 0.05 NEAR
pub const MAX_STORAGE_DEPOSIT: u128 = 12_500_000_000_000_000_000_000; // 0.0125 NEAR
pub const MAX_FEE_BPS: u16 = 100;

#[near(serializers = [borsh])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Day {
    pub start_ns: u64,
    pub spent_yocto: u128,
}

/// Bounded `client_order_id -> expires_at_ns` set. Expired entries are pruned on every
/// insert (a replay after expiry already fails E_EXPIRED), so storage stays small and is
/// hard-capped at MAX_SEEN_ORDERS entries of <= 64 bytes.
#[near(serializers = [borsh])]
#[derive(Default, Clone, Debug)]
pub struct SeenOrders(pub Vec<(String, u64)>);

impl SeenOrders {
    pub fn insert(&mut self, id: String, expires_at_ns: u64, now: u64) -> Result<(), &'static str> {
        if id.is_empty() || id.len() > MAX_ORDER_ID_LEN {
            return Err("E_BAD_ORDER_ID");
        }
        if self.0.iter().any(|(k, e)| k == &id && *e >= now) {
            return Err("E_DUPLICATE");
        }
        self.0.retain(|(_, e)| *e >= now);
        if self.0.len() >= MAX_SEEN_ORDERS {
            return Err("E_ORDERS_FULL");
        }
        self.0.push((id, expires_at_ns));
        Ok(())
    }

    pub fn contains(&self, id: &str, now: u64) -> bool {
        self.0.iter().any(|(k, e)| k == id && *e >= now)
    }
}

pub fn check_expiry(now: u64, expires_at_ns: u64) -> Result<(), &'static str> {
    if now > expires_at_ns {
        return Err("E_EXPIRED");
    }
    if expires_at_ns > now.saturating_add(MAX_EXPIRY_AHEAD_NS) {
        return Err("E_EXPIRY_TOO_FAR");
    }
    Ok(())
}

/// 00:00 UTC of `now`'s day.
pub fn utc_day_start(now: u64) -> u64 {
    now - now % DAY_NS
}

/// Monday 00:00 UTC of `now`'s ISO week (1970-01-01 was a Thursday).
pub fn iso_week_start(now: u64) -> u64 {
    let d = now / DAY_NS;
    d.saturating_sub((d + 3) % 7) * DAY_NS
}

/// A pre-v1.4.1 rolling window (start not at 00:00 UTC) that has not expired yet.
pub fn legacy_live(start_ns: u64, now: u64) -> bool {
    !start_ns.is_multiple_of(DAY_NS) && now < start_ns.saturating_add(DAY_NS)
}

/// v1.4.1 (design D5): the daily window is the UTC day; it resets at 00:00 UTC. Migration: a
/// still-live pre-v1.4.1 rolling window keeps its spent value for the current UTC day
/// (conservative), then resets at the next 00:00 UTC.
pub fn roll_day(day: &mut Day, now: u64) {
    let today = utc_day_start(now);
    if day.start_ns == today {
        return;
    }
    if !legacy_live(day.start_ns, now) {
        day.spent_yocto = 0;
    }
    day.start_ns = today;
}

/// spend <= max_in <= caps.max_trade, then day.spent + spend <= daily cap; commits spend.
pub fn check_caps(
    day: &mut Day,
    caps: &Caps,
    now: u64,
    spend: u128,
    max_in: u128,
) -> Result<(), &'static str> {
    if spend > max_in || max_in > caps.max_trade_yocto.0 {
        return Err("E_CAP_TRADE");
    }
    roll_day(day, now);
    let total = day.spent_yocto.checked_add(spend).ok_or("E_CAP_DAILY")?;
    if total > caps.daily_cap_yocto.0 {
        return Err("E_CAP_DAILY");
    }
    day.spent_yocto = total;
    Ok(())
}

pub fn check_gas(n_ops: usize, op_gas: u64, prepaid: u64) -> Result<(), &'static str> {
    if n_ops > MAX_OPS || op_gas > prepaid.saturating_sub(GAS_OVERHEAD) {
        return Err("E_GAS");
    }
    Ok(())
}

pub fn check_reserve(balance: u128, outflow: u128) -> Result<(), &'static str> {
    match balance.checked_sub(outflow) {
        Some(left) if left >= RESERVE => Ok(()),
        _ => Err("E_RESERVE"),
    }
}

pub fn check_lower(cur: &Caps, new: &Caps) -> Result<(), &'static str> {
    if new.max_trade_yocto.0 > cur.max_trade_yocto.0 || new.daily_cap_yocto.0 > cur.daily_cap_yocto.0 {
        return Err("E_CAP_RAISE");
    }
    Ok(())
}

/// floor(amount * bps / 10_000) without overflow for any u128 amount.
pub fn bps(amount: u128, bps: u16) -> u128 {
    let b = bps as u128;
    (amount / 10_000) * b + (amount % 10_000) * b / 10_000
}

pub fn add(a: u128, b: u128) -> Result<u128, &'static str> {
    a.checked_add(b).ok_or("E_OVERFLOW")
}

/// floor(a * b / c) with a 256-bit intermediate. Requires b <= c (then the result <= a).
pub fn mul_div(a: u128, b: u128, c: u128) -> u128 {
    if c == 0 || a == 0 || b == 0 {
        return 0;
    }
    let (hi, lo) = mul_wide(a, b);
    let (mut rem, mut q) = (0u128, 0u128);
    for i in (0..256u32).rev() {
        let bit = if i >= 128 { (hi >> (i - 128)) & 1 } else { (lo >> i) & 1 };
        let carry = rem >> 127;
        rem = (rem << 1) | bit;
        if carry == 1 || rem >= c {
            rem = rem.wrapping_sub(c);
            if i < 128 {
                q |= 1 << i;
            }
        }
    }
    q
}

fn mul_wide(a: u128, b: u128) -> (u128, u128) {
    const M: u128 = u64::MAX as u128;
    let (a0, a1, b0, b1) = (a & M, a >> 64, b & M, b >> 64);
    let (p00, p01, p10, p11) = (a0 * b0, a0 * b1, a1 * b0, a1 * b1);
    let mid = (p00 >> 64) + (p01 & M) + (p10 & M);
    let lo = (p00 & M) | (mid << 64);
    let hi = p11 + (p01 >> 64) + (p10 >> 64) + (mid >> 64);
    (hi, lo)
}
