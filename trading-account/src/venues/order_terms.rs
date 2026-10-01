//! AUDIT-T0: a token0 buy is exact-out: its `max_out` (the tokens minted; the unused NEAR is
//! refunded inside a successful receipt) sets the fill size. On a 24/7 order fire it must never be
//! the firing key's choice (a fire with `max_out = min_out` filled a sliver of the order and
//! consumed it). The user stores it with the order: `place_order`'s optional JSON field
//! `max_out` (read from the same args as `via`, so the Rust signature and `Order` borsh are
//! unchanged), under its own raw key `om` + id. A fire's CurveBuy (or a Chain's curve leg 1) must
//! carry exactly the stored value; an order stored without one can't fire a `max_out` at all.
use crate::{TradingAccount, TradingAccountExt};
use near_sdk::json_types::{U128, U64};
use near_sdk::serde::Deserialize;
use near_sdk::{env, near, serde_json};

const K_MAX_OUT: &[u8] = b"om";

fn key(id: u64) -> Vec<u8> {
    [K_MAX_OUT, &id.to_le_bytes()].concat()
}

/// The optional `max_out` of `place_order`'s JSON args (absent / null = none).
pub fn max_out_from_input() -> Option<U128> {
    #[derive(Deserialize)]
    #[serde(crate = "near_sdk::serde")]
    struct A {
        #[serde(default)]
        max_out: Option<U128>,
    }
    let input = env::input().filter(|i| !i.is_empty())?;
    serde_json::from_slice::<A>(&input).unwrap_or_else(|_| env::panic_str("E_BAD_ORDER")).max_out
}

pub fn save(id: u64, v: U128) {
    env::storage_write(&key(id), &v.0.to_le_bytes());
}

pub fn load(id: u64) -> Option<U128> {
    env::storage_read(&key(id)).and_then(|b| b.try_into().ok()).map(|b| U128(u128::from_le_bytes(b)))
}

pub fn remove(id: u64) {
    env::storage_remove(&key(id));
}

/// An order fire's curve buy: `max_out` must be exactly what the user stored (both absent, or
/// equal). E_ORDER_MISMATCH otherwise.
pub fn check(id: u64, max_out: Option<U128>) -> Result<(), &'static str> {
    if load(id).map(|x| x.0) != max_out.map(|x| x.0) {
        return Err("E_ORDER_MISMATCH");
    }
    Ok(())
}

#[near]
impl TradingAccount {
    /// AUDIT-T0: the `max_out` stored with an order (a token0 buy's exact-out size), if any.
    pub fn get_order_max_out(&self, order_id: U64) -> Option<U128> {
        load(order_id.0)
    }
}
