//! Raw-key storage of routes, the per-Q lock, the fee escrow and a Chain order's legs (routing
//! C.2.3, C.3). Nothing here is in `STATE`: pre-1.6 state and `Order` borsh are unchanged.
use super::{ContTerms, OrderVia, E_Q_BUSY};
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::json_types::{U128, U64};
use near_sdk::{env, near, AccountId};

pub const MAX_OPEN_ROUTES: usize = 16;
/// A lock whose holder's callback never ran (out of gas) expires after this many blocks.
pub const LOCK_TTL_BLOCKS: u64 = 300;
/// R2-09 escape for a continuation whose callback never ran (out of gas, a panic): its route keeps
/// `pending` forever (nothing may clear it, see `Route::pending`), and `upgrade::in_flight` stops
/// counting it this many blocks after the fire, so neither the owner's upgrade doors nor the
/// auto-apply stay blocked. Derived from the code, not guessed:
/// - `pending` is set only by `fire_continuation` and covers only that fire's own receipt chain:
///   [mt_balance_of view -> on_cont_refund_check ->] verifier.ft_withdraw (token ft_transfer +
///   resolve) -> on_cont_pulled [-> the swap leg (ft_transfer_call / curve batch, its DEX receipts
///   and resolve) -> on_cont_swapped]: about a dozen receipts, each normally in the next block.
///   The 1Click windows (quote deadline, CONT_MAX_NS 30 min, the refund after the deadline) fall
///   between fires, while the route is Funded and NOT pending, so they hold nothing here.
/// - The same fire's Q lock already treats its holder as dead after LOCK_TTL_BLOCKS (another route
///   may then take Q), so the bound is that one: > 20x the longest legit chain.
pub const ROUTE_PENDING_TTL_BLOCKS: u64 = LOCK_TTL_BLOCKS;
/// Continuation ids: `execute_order(order_id >= CONT_BASE)`; ordinary order ids stay below.
pub const CONT_BASE: u64 = 1 << 63;
/// A continuation may be fired at most this long after its IntentsSwap.
pub const CONT_MAX_NS: u64 = 30 * 60 * 1_000_000_000;
/// F1 (external audit): a Funded, not pending intents route is closed (`Expired`) this long after
/// the later of its quote and continuation deadlines. By then 1Click has delivered or refunded
/// (its refund follows the quote deadline), so a route still Funded can't be ended by a pull any
/// more: its delivery was moved by `owner_withdraw_from_intents`, or a sibling continuation took
/// part of it (routing C.3).
pub const ROUTE_EXPIRY_GRACE_NS: u64 = 24 * 3_600 * 1_000_000_000;
/// F1: the quote deadline counts at most this long after the continuation deadline (itself at
/// most CONT_MAX_NS after funding), so a far signed deadline can't hold a route (and the tokens
/// it reserves, also from the owner) open: a route expires at most ~48.5 h after funding.
pub const ROUTE_QUOTE_SPAN_NS: u64 = 24 * 3_600 * 1_000_000_000;

const K_ROUTE: &[u8] = b"rt";
const K_ROUTE_INDEX: &[u8] = b"ri";
const K_CONT: &[u8] = b"rk";
const K_CONT_NEXT: &[u8] = b"rn";
const K_LOCK: &[u8] = b"lk";
const K_ESCROW: &[u8] = b"fe";
const K_VIA: &[u8] = b"ov";

#[near(serializers = [borsh, json])]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteKind {
    IntentsBuy,
    IntentsSell,
    Chain,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteState {
    Funded,
    Pulled,
    Done,
    Held,
    Refunded,
    /// F1: closed by `expire_routes` (appended: borsh index 5; earlier states keep theirs).
    Expired,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq)]
pub struct Route {
    pub kind: RouteKind,
    pub q: AccountId,
    /// What was funded into 1Click (intents kinds) or credited by leg 1 (Chain, held).
    pub origin: AccountId,
    pub deposit_address: String,
    pub funded: U128,
    pub quote_amount: U128,
    pub q_min: U128,
    pub q_quoted: U128,
    pub slippage_bps: u16,
    pub fee_escrow: U128,
    pub cont: Option<ContTerms>,
    pub cont_deadline_ns: U64,
    pub quote_deadline_ns: U64,
    /// Q (or wNEAR for sells / refunds) pulled into the wallet for THIS route.
    pub credited: U128,
    /// Q spent by this route's leg 2.
    pub spent: U128,
    pub state: RouteState,
    pub cont_id: U64,
    /// A continuation is in flight (second fire: E_ORDER_PENDING). Only that fire's callbacks
    /// clear it. A fire whose callback never ran keeps it for good: its pull may have delivered
    /// (untracked Q / wNEAR now in the wallet), so a re-fire could pull or spend twice and a
    /// clear could release its escrowed fee or credit a refund wrongly. Its funds stay reachable
    /// by the owner's own doors (withdraw once the Q lock expires, `owner_withdraw_from_intents`).
    pub pending: bool,
    /// Block height of the fire that set `pending` (`ROUTE_PENDING_TTL_BLOCKS`).
    pub pending_height: U64,
}

impl Route {
    /// A continuation of this route may still be in flight: `pending`, fired less than
    /// ROUTE_PENDING_TTL_BLOCKS ago. Only the upgrade gate reads this; the route is unchanged.
    pub fn pending_live(&self) -> bool {
        self.pending && env::block_height() < self.pending_height.0.saturating_add(ROUTE_PENDING_TTL_BLOCKS)
    }

    /// F1: when a Funded, not pending route expires: `max(quote, cont deadline)` (the quote's
    /// at most ROUTE_QUOTE_SPAN_NS past the continuation's) + ROUTE_EXPIRY_GRACE_NS.
    pub fn expires_at(&self) -> u64 {
        let cont = self.cont_deadline_ns.0;
        let quote = self.quote_deadline_ns.0.min(cont.saturating_add(ROUTE_QUOTE_SPAN_NS));
        quote.max(cont).saturating_add(ROUTE_EXPIRY_GRACE_NS)
    }

    /// F1: a Funded, not pending route past `expires_at`. It reserves nothing and holds no slot
    /// from then on, even before `expire_routes` settles it.
    pub fn expired(&self, now: u64) -> bool {
        self.state == RouteState::Funded && !self.pending && now > self.expires_at()
    }

    /// V16-07 + F1: this route's tokens in the intents balance are its own (refused to the
    /// device's and the owner's `withdraw_from_intents`, and to rescue): Funded, not expired, and
    /// either not pending or with its continuation still possibly in flight (a stuck fire past
    /// ROUTE_PENDING_TTL_BLOCKS can never fire again, so it protects nothing).
    pub fn reserves(&self, now: u64) -> bool {
        self.state == RouteState::Funded && !self.expired(now) && (!self.pending || self.pending_live())
    }
}

fn key(prefix: &[u8], id: &[u8]) -> Vec<u8> {
    [prefix, id].concat()
}

/// F2 (external audit): a record that doesn't decode fails closed (E_STATE). Read as absent, a
/// route in an older layout vanished: no longer in flight, nothing reserved, its escrow orphaned.
fn read<T: BorshDeserialize>(k: &[u8]) -> Option<T> {
    env::storage_read(k).map(|b| borsh::from_slice(&b).unwrap_or_else(|_| env::panic_str("E_STATE")))
}

fn write<T: BorshSerialize>(k: &[u8], v: &T) {
    env::storage_write(k, &borsh::to_vec(v).unwrap_or_else(|_| env::panic_str("E_STATE")));
}

pub fn route_index() -> Vec<String> {
    read(K_ROUTE_INDEX).unwrap_or_default()
}

pub fn load_route(id: &str) -> Option<Route> {
    read(&key(K_ROUTE, id.as_bytes()))
}

/// Held routes kept in the index (for views / the UI's Convert) beyond the in-flight ones; the
/// oldest Held route is unlisted when a newer one needs the room (its record stays readable).
pub const MAX_HELD_LISTED: usize = 32;

fn in_flight(st: RouteState) -> bool {
    matches!(st, RouteState::Funded | RouteState::Pulled)
}

/// In-flight routes (Funded / Pulled): the only ones that take one of the 16 slots (V16-05). An
/// expired route (F1) takes none.
pub fn in_flight_count() -> usize {
    let now = env::block_timestamp();
    route_index()
        .iter()
        .filter(|id| load_route(id).is_some_and(|r| in_flight(r.state) && !r.expired(now)))
        .count()
}

/// A new in-flight route fits (checked BEFORE anything is funded).
pub fn route_slot_free() -> bool {
    in_flight_count() < MAX_OPEN_ROUTES
}

/// INDEP-5: a route by id for `route_live` / `get_route`. A listed record fails closed (E_STATE,
/// F2); an unlisted one (Done / Refunded / Expired / an unlisted Held, which `migrate_routes`
/// doesn't rewrite) that doesn't decode is a finished pre-9a0dd084 route: read as absent.
pub fn load_route_by_id(id: &str) -> Option<Route> {
    if route_index().iter().any(|x| x == id) {
        return load_route(id);
    }
    env::storage_read(&key(K_ROUTE, id.as_bytes())).and_then(|b| borsh::from_slice(&b).ok())
}

/// V16-08: a stored route that is still live (in flight or held) under this id.
pub fn route_live(id: &str) -> bool {
    load_route_by_id(id)
        .is_some_and(|r| !matches!(r.state, RouteState::Done | RouteState::Refunded | RouteState::Expired))
}

/// V16-08: the id of a NEW route. Refused while a live route has it (ids are unique for a
/// route's life: overwriting would orphan its escrow / spend / continuation), and a device execute
/// can't use the `order:` prefix of order fires.
pub fn check_route_id(id: &str, order_fire: bool) -> Result<(), &'static str> {
    if !order_fire && id.starts_with("order:") {
        return Err("E_BAD_OP");
    }
    if route_live(id) {
        return Err("E_ROUTE_EXISTS");
    }
    Ok(())
}

/// Writes a route. V16-05: only in-flight routes (Funded / Pulled) take one of the 16 slots
/// (E_ROUTES_FULL); a Held route needs no slot (nothing fires it) and stays listed up to
/// MAX_HELD_LISTED (oldest unlisted first). Done / Refunded routes leave the index (the record
/// stays readable).
pub fn save_route(id: &str, r: &Route) -> Result<(), &'static str> {
    let mut idx = route_index();
    let listed = !matches!(r.state, RouteState::Done | RouteState::Refunded | RouteState::Expired);
    let pos = idx.iter().position(|x| x == id);
    let now = env::block_timestamp();
    let was_in_flight =
        pos.is_some() && load_route(id).is_some_and(|o| in_flight(o.state) && !o.expired(now));
    if in_flight(r.state) && !was_in_flight && in_flight_count() >= MAX_OPEN_ROUTES {
        return Err("E_ROUTES_FULL");
    }
    match (pos, listed) {
        (None, true) => idx.push(id.to_string()),
        (Some(p), false) => {
            idx.remove(p);
        }
        _ => {}
    }
    // cap the Held listing: unlist the oldest Held routes beyond MAX_HELD_LISTED. Only a Held
    // save can add one (INDEP-2: no scan of every listed route on other saves)
    if r.state != RouteState::Held {
        write(K_ROUTE_INDEX, &idx);
        write(&key(K_ROUTE, id.as_bytes()), r);
        return Ok(());
    }
    let held: Vec<String> = idx
        .iter()
        .filter(|x| x.as_str() != id && load_route(x).is_some_and(|o| o.state == RouteState::Held))
        .cloned()
        .collect();
    let mine_held = usize::from(r.state == RouteState::Held);
    let over = (held.len() + mine_held).saturating_sub(MAX_HELD_LISTED);
    for old in held.iter().take(over) {
        idx.retain(|x| x != old);
        route_event("route_unlisted", &format!("{{\"id\":{}}}", crate::jstr(old)));
    }
    write(K_ROUTE_INDEX, &idx);
    write(&key(K_ROUTE, id.as_bytes()), r);
    Ok(())
}

/// Next continuation id (>= CONT_BASE), mapped to route `id`.
pub fn new_cont(id: &str) -> u64 {
    let n: u64 = read(K_CONT_NEXT).unwrap_or(CONT_BASE);
    write(K_CONT_NEXT, &(n + 1));
    write(&key(K_CONT, &n.to_le_bytes()), &id.to_string());
    n
}

pub fn cont_route(cont_id: u64) -> Option<String> {
    read(&key(K_CONT, &cont_id.to_le_bytes()))
}

// ---------- per-Q lock ----------

/// (holder route id, expiry block height)
pub fn lock_of(q: &str) -> Option<(String, u64)> {
    read::<(String, u64)>(&key(K_LOCK, q.as_bytes())).filter(|(_, exp)| env::block_height() < *exp)
}

/// E_Q_BUSY while another route holds `q` (expired locks don't count).
pub fn assert_free(q: &str) {
    if busy(q) {
        env::panic_str(E_Q_BUSY);
    }
}

/// True (with a `q_busy` event) while a lock holds `q`. R2-05 send-time re-check: a callback that
/// sends a token `run` checked free only at the execute (a Chain's leg 1, a gated swap, a gated
/// Chain's Q) settles as a failed swap instead of moving a token locked since.
pub fn busy(q: &str) -> bool {
    let Some((holder, _)) = lock_of(q) else {
        return false;
    };
    env::log_str(&format!(
        "EVENT_JSON:{{\"standard\":\"nttrade\",\"version\":\"1\",\"event\":\"q_busy\",\"data\":{{\"q\":\"{q}\",\"holder\":{}}}}}",
        crate::jstr(&holder)
    ));
    true
}

pub fn lock(q: &str, holder: &str) {
    assert_free(q);
    write(&key(K_LOCK, q.as_bytes()), &(holder.to_string(), env::block_height() + LOCK_TTL_BLOCKS));
    // A1 (R2-09): the permissionless auto-upgrade waits while a route holds a lock
    crate::upgrade::mark_in_flight(LOCK_TTL_BLOCKS);
}

/// Releases `q` if `holder` still holds it (an expired lock re-taken by another route stays).
pub fn unlock(q: &str, holder: &str) {
    let k = key(K_LOCK, q.as_bytes());
    if read::<(String, u64)>(&k).is_some_and(|(h, _)| h == holder) {
        env::storage_remove(&k);
    }
}

// ---------- fee escrow (kept liquid, counted by the reserve check) ----------

pub fn escrow_total() -> u128 {
    read(K_ESCROW).unwrap_or(0)
}

pub fn escrow_add(x: u128) {
    write(K_ESCROW, &escrow_total().saturating_add(x));
}

pub fn escrow_sub(x: u128) {
    write(K_ESCROW, &escrow_total().saturating_sub(x));
}

// ---------- a Chain order's legs ----------

pub fn load_via(order_id: u64) -> Option<OrderVia> {
    read(&key(K_VIA, &order_id.to_le_bytes()))
}

pub fn save_via(order_id: u64, v: &OrderVia) {
    write(&key(K_VIA, &order_id.to_le_bytes()), v);
}

pub fn remove_via(order_id: u64) {
    env::storage_remove(&key(K_VIA, &order_id.to_le_bytes()));
}

pub fn route_event(name: &str, data: &str) {
    env::log_str(&format!(
        "EVENT_JSON:{{\"standard\":\"nttrade\",\"version\":\"1\",\"event\":\"{name}\",\"data\":{data}}}"
    ));
}

/// V16-07: while an intents route is Funded, its tokens in this account's intents balance belong
/// to it (the delivery, or the refund of the origin): the device's `withdraw_from_intents` can't
/// move them, so a refund pull can't be faked and a delivery can't be pulled around the route.
/// Buy: q (delivery) and wNEAR (origin); sell: Q (origin) and wNEAR (delivery).
pub fn intents_token_reserved(token: &AccountId, wrap: &AccountId) -> bool {
    let now = env::block_timestamp();
    route_index().iter().filter_map(|id| load_route(id)).any(|r| {
        r.reserves(now)
            && matches!(r.kind, RouteKind::IntentsBuy | RouteKind::IntentsSell)
            && (token == &r.q || token == &r.origin || token == wrap)
    })
}

/// Exactly the tokens `intents_token_reserved` protects now (view `get_intents_reserved`): wNEAR
/// and each reserving route's Q and origin, first-seen order, no duplicates.
pub fn intents_reserved_tokens(wrap: &AccountId) -> Vec<AccountId> {
    let now = env::block_timestamp();
    let mut out: Vec<AccountId> = vec![];
    for r in route_index().iter().filter_map(|id| load_route(id)) {
        if r.reserves(now) && matches!(r.kind, RouteKind::IntentsBuy | RouteKind::IntentsSell) {
            for t in [wrap, &r.q, &r.origin] {
                if !out.contains(t) {
                    out.push(t.clone());
                }
            }
        }
    }
    out
}

/// F1: closes every expired route once (`Funded` -> `Expired`, event `route_expired`). Its escrowed
/// fee is paid (conservative: the delivery may have happened; the same reserve rule as `pay_fee`),
/// its spend record dropped (the spend stays counted, as for a paid route), and it leaves the
/// index. Idempotent: an `Expired` route is never expired again. A later delivery or refund is
/// plain intents balance (`withdraw_from_intents` / `owner_withdraw_from_intents`).
///
/// INDEP-2: one pass. Each listed route is read once; the index and the escrow total are written
/// once at the end (an Expired route is unlisted and takes no slot, so `save_route`'s slot and
/// Held-cap logic has nothing to do for it).
pub fn expire_routes(fee_recipient: &AccountId) {
    let now = env::block_timestamp();
    let idx = route_index();
    let mut keep: Vec<String> = Vec::with_capacity(idx.len());
    let mut escrow: Option<u128> = None;
    // fees paid in this sweep: one transfer at the end (INDEP-2), counted out of liquid meanwhile
    let mut pay: u128 = 0;
    for id in idx.iter() {
        let Some(mut r) = load_route(id).filter(|r| r.expired(now)) else {
            keep.push(id.clone());
            continue;
        };
        let x = r.fee_escrow.0;
        let mut paid = false;
        if x > 0 {
            let e = escrow.unwrap_or_else(escrow_total).saturating_sub(x);
            escrow = Some(e);
            r.fee_escrow = U128(0);
            let liquid = crate::liquid_balance().saturating_sub(pay);
            paid = crate::policy::check_reserve(liquid.saturating_sub(e), x).is_ok();
            if paid {
                pay += x;
            }
        }
        crate::drop_route_spend(id);
        r.state = RouteState::Expired;
        write(&key(K_ROUTE, id.as_bytes()), &r);
        route_event(
            "route_expired",
            &format!("{{\"id\":{},\"q\":\"{}\",\"fee\":\"{x}\",\"fee_paid\":{paid}}}", crate::jstr(id), r.q),
        );
    }
    if keep.len() != idx.len() {
        write(K_ROUTE_INDEX, &keep);
    }
    if let Some(e) = escrow {
        write(K_ESCROW, &e);
    }
    if pay > 0 {
        near_sdk::Promise::new(fee_recipient.clone())
            .transfer(near_sdk::NearToken::from_yoctonear(pay))
            .detach();
    }
}

/// F2: the Route layout before 9a0dd084 (no `pending_height`), written by earlier 1.6 builds
/// (testnet). 1.5 has no routes.
#[derive(BorshDeserialize)]
#[borsh(crate = "near_sdk::borsh")]
struct RoutePre {
    kind: RouteKind,
    q: AccountId,
    origin: AccountId,
    deposit_address: String,
    funded: U128,
    quote_amount: U128,
    q_min: U128,
    q_quoted: U128,
    slippage_bps: u16,
    fee_escrow: U128,
    cont: Option<ContTerms>,
    cont_deadline_ns: U64,
    quote_deadline_ns: U64,
    credited: U128,
    spent: U128,
    state: RouteState,
    cont_id: U64,
    pending: bool,
}

/// F2 (`migrate`): rewrites every listed route stored in the pre-9a0dd084 layout into the current
/// one (`pending_height` 0: a pending one stops counting as in flight at once, as a stuck fire would
/// after ROUTE_PENDING_TTL_BLOCKS). Anything else that doesn't decode stays E_STATE. Returns how
/// many were rewritten.
pub fn migrate_routes() -> u32 {
    let mut n = 0;
    for id in route_index() {
        let k = key(K_ROUTE, id.as_bytes());
        let Some(b) = env::storage_read(&k) else { continue };
        if borsh::from_slice::<Route>(&b).is_ok() {
            continue;
        }
        let o: RoutePre = borsh::from_slice(&b).unwrap_or_else(|_| env::panic_str("E_STATE"));
        let r = Route {
            kind: o.kind,
            q: o.q,
            origin: o.origin,
            deposit_address: o.deposit_address,
            funded: o.funded,
            quote_amount: o.quote_amount,
            q_min: o.q_min,
            q_quoted: o.q_quoted,
            slippage_bps: o.slippage_bps,
            fee_escrow: o.fee_escrow,
            cont: o.cont,
            cont_deadline_ns: o.cont_deadline_ns,
            quote_deadline_ns: o.quote_deadline_ns,
            credited: o.credited,
            spent: o.spent,
            state: o.state,
            cont_id: o.cont_id,
            pending: o.pending,
            pending_height: U64(0),
        };
        write(&k, &r);
        n += 1;
    }
    n
}

/// F2 (`migrate`): a stored Chain-order via that doesn't decode (the layout before V16-01, without
/// the leg-1 bounds; earlier 1.6 builds). Such an order can never fire safely.
pub fn via_unreadable(order_id: u64) -> bool {
    env::storage_read(&key(K_VIA, &order_id.to_le_bytes()))
        .is_some_and(|b| borsh::from_slice::<OrderVia>(&b).is_err())
}
