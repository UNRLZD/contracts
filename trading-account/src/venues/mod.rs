//! v1.6 launchpad curve venues (docs/launchpads/trading-plan.md §1, §4). Pure planning: every
//! function here maps a typed op to the exact calls the account makes, with no env access, so
//! each rule is unit tested natively. `settle` holds the one settlement callback.
//!
//! Rules every pad kind keeps (trading-plan §4.2):
//! - the contract builds every method name and argument itself; no caller-supplied msg, method
//!   or recipient ever reaches a pad. Where a pad REQUIRES a recipient (token0 `receiver_id`) it
//!   is always this account; `buy_for` / `for_account` / `referral` are never sent;
//! - `min_out > 0` on every trade; deadlines where the pad supports them (now + 120 s);
//! - deposits are fixed per kind: payable buys attach `amount` (+ a capped per-kind storage
//!   extra), non-payable calls (token0 / chipfi sell, chipfi claim) attach 0, others 1 yocto;
//! - the fee is only ever on the NEAR leg (wNEAR or native NEAR in or out).
//!
//! Families (the allowlist entry's `DexKind`):
//! - `AidolsCurve(pad)`: exact factory id; the curve is in the factory, trades are
//!   `Q.ft_transfer_call{receiver_id: factory}` (buy) / `token.ft_transfer_call` (sell).
//! - `FactoryCurve(pad)`: exact factory id; a per-pad method set (see `factory.rs`).
//! - `TokenCurve(pad)`: the entry names the FACTORY; the venue is any token `<label>.<factory>`
//!   (one label, as `ShardsToken`); the curve is inside the token.
//! - `Kelytra`: exact exchange id; internal balances (deposit -> swap -> withdraw, `kelytra.rs`).
//!   portalpad is not a venue (factory wasm wiped, trading-plan §1.10).
use crate::msg::{DexKind, Swap};
use crate::policy::{bps, MAX_EXPIRY_AHEAD_NS};
use crate::Dex;
use near_sdk::json_types::{U128, U64};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{near, AccountId};

pub mod aidols;
pub mod factory;
pub mod kelytra;
pub mod order_terms;
pub mod settle;
pub mod tax;
pub mod token;

pub const E_BAD_OP: &str = "E_BAD_OP";
pub const E_BAD_DEX: &str = "E_BAD_DEX";
pub const E_GAS: &str = "E_GAS";
pub const E_QUOTE: &str = "E_CURVE_QUOTE";
pub const E_MARKET: &str = "E_CURVE_MARKET";
pub const E_NOT_ORDERABLE: &str = "E_ORDER_OPS";

pub const TGAS: u64 = 1_000_000_000_000;
/// Max gas a curve trade may attach (Nira pair buys forward ~290 TGas on mainnet; 250 fits one
/// execute with the callback and overhead).
pub const MAX_CURVE_GAS: u64 = 250;
pub const MIN_CURVE_GAS: u64 = 20;
/// Static gas of a housekeeping claim / withdraw call.
pub const GAS_CURVE_CLAIM: u64 = 60;
/// Per-kind storage extras (native NEAR attached on top of a payable buy's amount). Capped here,
/// never caller-chosen.
pub const VISTA_BUY_STORAGE: u128 = 1_250_000_000_000_000_000_000; // 0.00125 N (C 3Na2ztR1)
pub const NIRA_BUY_STORAGE: u128 = 20_000_000_000_000_000_000_000; // 0.02 N (C Hr4K6RwdhE)
/// Kelytra `register_balance` deposit per token (C).
/// meme.cooking registration cap: the account (0.02 N) + 6 memes (0.005 N each).
pub const MEME_STORAGE_MAX: u128 = 50_000_000_000_000_000_000_000; // 0.05 N
pub const KELYTRA_REGISTER: u128 = 20_000_000_000_000_000_000_000; // 0.02 N
/// Max length of a market id (launch id / meme id / token id string).
pub const MAX_MARKET_LEN: usize = 64;

#[near(serializers = [borsh, json])]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AidolsPad {
    /// aidols.near, gra-fun.near: quote wNEAR.
    Near,
    /// patata-monster.near: quote PATATA (`patata.gaypad.j1-racing.near`) only.
    Patata,
    /// gaypad.j1-racing.near: quote JAMBO (`jambo-1679.meme-cooking.near`) only (fixture
    /// aidols-gaypad.json, C).
    Jambo,
    /// v1/v2.whole-market.near: quote NEARDOG (`neardog.tkn.near`) only (fixture
    /// aidols-wholemarket.json, C).
    Neardog,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FactoryPad {
    VistaLaunch,
    VistaDex,
    Nearrr,
    Nira,
    MemeCooking,
    Dragonpad,
}

#[near(serializers = [borsh, json])]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TokenPad {
    NearFun,
    Umbra,
    RevShare,
    Nearmemefun,
    Token0,
    Chipfi,
    Npad,
}

/// PATATA, the only quote of patata-monster.near (trading-plan §1.3, C).
pub const PATATA: &str = "patata.gaypad.j1-racing.near";
/// JAMBO, the only quote of gaypad.j1-racing.near (C).
pub const JAMBO: &str = "jambo-1679.meme-cooking.near";
/// NEARDOG, the only quote of v1/v2.whole-market.near (C).
pub const NEARDOG: &str = "neardog.tkn.near";

/// The one quote token of an Aidols-codebase factory (wNEAR for `Near`).
pub fn aidols_quote(pad: AidolsPad, wrap: &AccountId) -> AccountId {
    let q = match pad {
        AidolsPad::Near => return wrap.clone(),
        AidolsPad::Patata => PATATA,
        AidolsPad::Jambo => JAMBO,
        AidolsPad::Neardog => NEARDOG,
    };
    q.parse().unwrap_or_else(|_| wrap.clone())
}

/// `Op::CurveBuy` / `Op::CurveSell` body.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(crate = "near_sdk::serde", deny_unknown_fields)]
pub struct CurveTrade {
    /// The account the trade is made at: the factory / exchange (exact allowlisted id), or the
    /// token itself for a `TokenCurve` pad (`<label>.<allowlisted factory>`).
    pub venue: AccountId,
    /// Factory pads: the token id (Aidols family buy, Vista, Nearrr, dragonpad, and the token
    /// being sold for ft_transfer_call sells), the launch id (Nira, Kelytra) or the meme id
    /// (meme.cooking). `TokenCurve`: none.
    #[serde(default)]
    pub market: Option<String>,
    /// The quote asset: None = NEAR (native or wNEAR, per pad); Some(Q) = a quote token.
    #[serde(default)]
    pub quote: Option<AccountId>,
    /// Input amount: NEAR / Q for a buy, the token for a sell.
    pub amount: U128,
    /// Guaranteed minimum output (> 0).
    pub min_out: U128,
    /// token0 buys only (exact-out): tokens minted at most (>= min_out); the unused NEAR is
    /// refunded by the token.
    #[serde(default)]
    pub max_out: Option<U128>,
    pub gas: U64,
    /// Kelytra only (refused elsewhere): a first trade. Registers this account's exchange balances
    /// (wNEAR + the launch token) and its storage on the launch token inside the same execute,
    /// before the deposit (kelytra.rs). Idempotent on chain: a repeat refunds the deposits.
    #[serde(default)]
    pub setup: bool,
}

/// `Op::CurveClaim` body: housekeeping that pays THIS account (no recipient field exists on any
/// of these calls). Not a swap; may precede one.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(crate = "near_sdk::serde", deny_unknown_fields)]
pub struct CurveClaim {
    pub venue: AccountId,
    pub action: ClaimAction,
    #[serde(default)]
    pub market: Option<String>,
    #[serde(default)]
    pub token: Option<AccountId>,
    #[serde(default)]
    pub amount: Option<U128>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(crate = "near_sdk::serde")]
pub enum ClaimAction {
    /// Nira: `claim_graduated_balance{launch_id}` (internal balance -> the graduated NEP-141).
    NiraClaimGraduated,
    /// meme.cooking: `withdraw{meme_id, amount}` (1 yocto; wNEAR back to self).
    MemeCookingWithdraw,
    /// meme.cooking: `claim{meme_id}` (exactly 1 yocto, as on mainnet: 0 is refused with "Requires
    /// attached deposit of exactly 1 yoctoNEAR"): the tokens after a successful `finalize`, or the
    /// wNEAR refund of a failed auction (soft cap missed). Optional `token` = the auction's token
    /// (one label under the venue), a StorageDeposit target only.
    MemeCookingClaim,
    /// dragonpad: `claim{asset}` (deposit 0): a failed NEAR payout ("near", `market` None) or a
    /// failed token delivery (`market` = the token `<label>.dragonpad.near`, sent as
    /// `"nep141:<token>"`: the real wasm parses that, not the bare id), kept as a credit.
    DragonpadClaim,
    /// chipfi: `claim{}` on the coin (sell credit + dividends; deposit 0).
    ChipfiClaim,
    /// Kelytra: `withdraw{token_id, amount}` of this account's internal balance (1 yocto).
    KelytraWithdraw,
    /// Kelytra: `register_balance{token_id, account_id: self}` (0.02 N, counted as spend).
    KelytraRegister,
    /// Kelytra: `token.ft_transfer_call{receiver_id: exchange, amount, msg: "deposit"}` into this
    /// account's internal balance (wNEAR counted as spend; no fee: the fee is on the swap).
    KelytraDeposit,
    /// nearmemefun: `withdraw_near{amount}` on the token (exactly 1 yocto, >= 60 TGas): NEAR a
    /// `sell` credited above the min_out that the sell batch withdrew (token.rs).
    NearmemefunWithdraw,
    /// Vista launch: `claim_pending{token_id}` (1 yocto): tokens whose delivery failed
    /// ("delivery_failed"), kept pending for this account.
    VistaClaimPending,
    /// meme.cooking: `storage_deposit{}` for this account (the predecessor; no account_id sent).
    /// meme.cooking refuses a Deposit from an unregistered account (AccountNotRegistered, refunded)
    /// and charges 0.02 N per account + 0.005 N per meme (`storage_costs`), more than the
    /// generic StorageDeposit cap: `amount` is required, <= MEME_STORAGE_MAX, counted as spend.
    MemeCookingRegister,
}

/// One function call the account makes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Call {
    pub receiver: AccountId,
    pub method: &'static str,
    pub args: String,
    pub deposit: u128,
    pub gas: u64,
}

/// How a planned trade settles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Settle {
    /// `ft_transfer_call` on wrap.near: today's `SwapProof::Wrap` + `on_swap_settled` (wrap's
    /// resolve reports what was used; fee pro rata).
    Wrap,
    /// `ft_transfer_call` on any other token: today's `SwapProof::Token` + `on_swap_settled`.
    Token,
    /// Payable buy with native NEAR: fee = fee_bps x (amount - measured refund), measured as the
    /// liquid-balance delta in `on_curve_settled`; spend stays counted (never returned on a
    /// measured delta). Failed receipt = nothing used.
    NearIn,
    /// Direct sell with a payout. `native`: native NEAR payout, fee = fee_bps x min(arrived, cap)
    /// where cap = the pad's reported NEAR (when `reported`) else the user's min_out bound.
    /// Not native: a wNEAR payout (fee = fee_bps x min_out bound, as today's sells to wNEAR) or a
    /// Q payout (no fee: not the NEAR leg).
    Out { native: bool, reported: bool, wnear: bool },
    /// Kelytra round trip in ONE execute (kelytra.rs): deposit (the planned call) ->
    /// `on_kelytra_deposited` -> `swap_curve` -> `on_kelytra_swapped` -> `withdraw` ->
    /// `on_kelytra_done` -> finish_settle. `dex` = index of the Kelytra entry in the allowlist.
    /// `setup`: the planned calls are the registrations, and `on_kelytra_registered` runs first.
    Kelytra { buy: bool, launch: u64, min_out: u128, dex: u16, setup: bool },
    /// Payable buy on a pad that panics on slippage (dragonpad, Nira, Vista DEX): a failed
    /// receipt is the refund (nothing used, an order reopens); a successful one is a fill: the
    /// whole amount used, the full reserved fee. No balance delta is read (V16-02).
    NearInFull,
    /// Nearrr buy (factory.rs): the planned call is the token's own `tax_state` view; its
    /// callback `on_nearrr_tax` reads this account's token balance, `on_nearrr_before` sends the
    /// pad `buy{min_out: ceil(min_out / (1 - tax))}` with the NEAR and reads it again, and
    /// `on_nearrr_settled` settles (used = amount; fee only if tokens arrived, V16-02). `dex` = index of the Nearrr entry in the allowlist;
    /// the token is `<label[..len]>.<that factory>` (kept inline: Settle is Copy).
    NearrrTax { min_out: u128, dex: u16, label: [u8; 48], len: u8 },
}

impl Settle {
    /// The `SettleArgs.proof` string (finish_settle reopens an order on a provable refund only).
    pub fn proof(self) -> &'static str {
        match self {
            Settle::Wrap => "wrap",
            Settle::Token => "token",
            Settle::NearIn | Settle::NearInFull | Settle::NearrrTax { .. } => "curve_near",
            Settle::Out { .. } | Settle::Kelytra { .. } => "curve_out",
        }
    }
    /// Uses `on_curve_settled` (vs today's `on_swap_settled`).
    pub fn measured(self) -> bool {
        matches!(
            self,
            Settle::NearIn
                | Settle::NearInFull
                | Settle::NearrrTax { .. }
                | Settle::Out { .. }
                | Settle::Kelytra { .. }
        )
    }
    pub fn mode(self) -> &'static str {
        match self {
            Settle::NearIn => "near_in",
            Settle::NearInFull | Settle::NearrrTax { .. } => "near_in_full",
            Settle::Out { native: true, reported: true, .. } => "near_out_reported",
            Settle::Out { native: true, reported: false, .. } => "near_out",
            Settle::Out { wnear: true, .. } => "wnear_out",
            _ => "q_out",
        }
    }
}

/// What `run` needs from a planned curve trade.
#[derive(Debug, PartialEq, Eq)]
pub struct Plan {
    /// All to ONE receiver (one batch), in order; the last one's result is the swap result.
    pub calls: Vec<Call>,
    pub settle: Settle,
    /// Counted toward the caps (NEAR/wNEAR input + storage extras).
    pub spend: u128,
    /// Part of `spend` returned pro rata on a provable refund (the NEAR/wNEAR trade input).
    pub counted: u128,
    /// Reserved maximum fee.
    pub fee: u128,
    /// Fee base cap for a measured native sell without a reported amount (the min_out bound).
    pub fee_cap: u128,
    /// Native NEAR the calls attach.
    pub native_out: u128,
    /// Order matching: the order DEX (venue), its token_in and the parsed swap.
    pub order_dex: AccountId,
    pub token_in: AccountId,
    pub swap: Swap,
    /// False: never part of a 24/7 order (presale deposit).
    pub orderable: bool,
    /// Tokens a StorageDeposit op in the same execute may register on.
    pub storage: Vec<AccountId>,
    /// Gas the op declares and `run` budgets (with GAS_CALLBACK for the settle callback): the
    /// calls' gas, plus, for a trade that continues in callbacks (Kelytra, Nearrr buys), its first
    /// callback's static gas beyond GAS_CALLBACK. A registration the venue plans before the
    /// trade (an Aidols-family `storage_deposit`) is on top of the op's `gas`; the rest never
    /// exceeds it (E_GAS).
    pub gas: u64,
}

pub struct Ctx<'a> {
    pub me: &'a AccountId,
    pub wrap: &'a AccountId,
    pub fee_bps: u16,
    pub now_ns: u64,
    /// An order fire: the stored order's min_out (the user's bound; UNR-A-01).
    pub order_min_out: Option<u128>,
}

impl Ctx<'_> {
    pub fn deadline_ns(&self) -> u64 {
        self.now_ns.saturating_add(MAX_EXPIRY_AHEAD_NS)
    }
    /// The min_out a sell-to-NEAR fee is reserved on (UNR-A-01: an order fire uses the stored
    /// order's bound when lower).
    pub fn fee_base(&self, min_out: u128) -> u128 {
        self.order_min_out.map_or(min_out, |o| o.min(min_out))
    }
}

/// The resolved venue of a trade.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Venue {
    Aidols(AidolsPad),
    Factory(FactoryPad),
    Token(TokenPad),
    Kelytra,
}

/// `token` is `<label>.<factory>` with exactly one non-empty label (same rule as Shards).
pub fn one_label_under(factory: &AccountId, token: &AccountId) -> bool {
    crate::msg::shards_token_of(factory, token)
}

/// Resolves a venue account against the allowlist: exact id for factory-held curves and
/// Kelytra, one-label-under-factory for token-held curves. None = not a curve venue.
pub fn resolve(allow: &[Dex], venue: &AccountId) -> Option<Venue> {
    allow.iter().find_map(|d| match d.kind {
        DexKind::AidolsCurve(p) if &d.id == venue => Some(Venue::Aidols(p)),
        DexKind::FactoryCurve(p) if &d.id == venue => Some(Venue::Factory(p)),
        DexKind::Kelytra if &d.id == venue => Some(Venue::Kelytra),
        DexKind::TokenCurve(p) if one_label_under(&d.id, venue) => Some(Venue::Token(p)),
        _ => None,
    })
}

/// v1.6 hook for `dex_kind`: kinds whose allowlist id is a factory, never a venue itself.
pub fn is_factory_entry(kind: DexKind) -> bool {
    matches!(kind, DexKind::ShardsToken | DexKind::TokenCurve(_))
}

/// v1.6: may a trade on this kind be (part of) a 24/7 order? A meme.cooking presale deposit has
/// no price (its min_out is symbolic), so a relayer could fire it at any time: never an order.
pub fn orderable_kind(kind: DexKind) -> bool {
    !matches!(kind, DexKind::FactoryCurve(FactoryPad::MemeCooking))
}

/// v1.6 hook for `place_order`: `d` as an order DEX. Some(true) = a curve venue an order may name
/// (exact factory/exchange id, or a TokenCurve token); Some(false) = a curve venue that is never
/// an order DEX (meme.cooking); None = not a curve venue (the pre-1.6 rules apply).
pub fn order_venue(allow: &[Dex], d: &AccountId) -> Option<bool> {
    allow
        .iter()
        .find_map(|x| match x.kind {
            DexKind::AidolsCurve(_) | DexKind::FactoryCurve(_) | DexKind::Kelytra if &x.id == d => {
                Some(x.kind)
            }
            DexKind::TokenCurve(_) if one_label_under(&x.id, d) => Some(x.kind),
            _ => None,
        })
        .map(orderable_kind)
}

/// v1.6 hook for the FtTransferCall arm: a `TokenCurve` token as `receiver_id`.
pub fn token_curve_kind(allow: &[Dex], receiver: &AccountId) -> Option<DexKind> {
    allow.iter().find_map(|d| match d.kind {
        DexKind::TokenCurve(_) if one_label_under(&d.id, receiver) => Some(d.kind),
        _ => None,
    })
}

pub fn check_gas(gas: u64) -> Result<(), &'static str> {
    if !(MIN_CURVE_GAS * TGAS..=MAX_CURVE_GAS * TGAS).contains(&gas) {
        return Err(E_GAS);
    }
    Ok(())
}

/// A market id: 1..=64 chars of [a-z0-9_.-] (every launch / meme / token id seen on chain).
pub fn check_market(m: &str) -> Result<(), &'static str> {
    if m.is_empty()
        || m.len() > MAX_MARKET_LEN
        || !m.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_.-".contains(&b))
    {
        return Err(E_MARKET);
    }
    Ok(())
}

/// A numeric market id (meme.cooking meme_id, Kelytra launch_id): canonical u64.
pub fn market_u64(m: &Option<String>) -> Result<u64, &'static str> {
    let s = m.as_deref().ok_or(E_MARKET)?;
    let v: u64 = s.parse().map_err(|_| E_MARKET)?;
    if v.to_string() != s {
        return Err(E_MARKET);
    }
    Ok(v)
}

pub fn market_str(m: &Option<String>) -> Result<&str, &'static str> {
    let s = m.as_deref().ok_or(E_MARKET)?;
    check_market(s)?;
    Ok(s)
}

pub fn market_token(m: &Option<String>) -> Result<AccountId, &'static str> {
    market_str(m)?.parse().map_err(|_| E_MARKET)
}

/// Synthetic token id of an internal-balance position (Nira curve, before graduation):
/// `<launch_id>.<factory>`. Used only to match orders; nothing is ever sent to it.
pub fn synthetic(market: &str, factory: &AccountId) -> Result<AccountId, &'static str> {
    format!("{market}.{factory}").parse().map_err(|_| E_MARKET)
}

/// v1.6 (sandbox finding, aidols.near real wasm): an Aidols-codebase factory `ft_transfer`s the
/// output without checking registration; an unregistered buyer's input is KEPT by the factory and
/// the output transfer fails (tokens lost). Every trade whose output token (or Q payout) may be
/// unregistered is therefore preceded by `storage_deposit{account_id: self, registration_only}` on
/// that token, planned by the venue itself (an already registered account gets it refunded).
/// Receipt order: this call is depth 1, the pad's output transfer is depth >= 3 on the same token,
/// and receipts to one account execute in order, so the registration lands first.
pub const VENUE_STORAGE: u128 = 12_500_000_000_000_000_000_000; // 0.0125 N (MAX_STORAGE_DEPOSIT)
pub const GAS_VENUE_STORAGE: u64 = 10;

/// Venue-planned registrations count as spend (native NEAR out, like a StorageDeposit op).
pub fn storage_spend(calls: &[Call]) -> u128 {
    calls.iter().filter(|x| x.method == "storage_deposit").fold(0u128, |a, x| a.saturating_add(x.deposit))
}

pub fn storage_call(token: &AccountId, me: &AccountId) -> Call {
    let args = near_sdk::serde_json::json!({"account_id": me, "registration_only": true}).to_string();
    fcall(token, "storage_deposit", args, VENUE_STORAGE, GAS_VENUE_STORAGE * TGAS)
}

pub fn fcall(receiver: &AccountId, method: &'static str, args: String, deposit: u128, gas: u64) -> Call {
    Call { receiver: receiver.clone(), method, args, deposit, gas }
}

/// `token.ft_transfer_call{receiver_id, amount, msg}` (1 yocto). `msg` is built here, never taken
/// from the caller.
pub fn ft_call(token: &AccountId, receiver: &AccountId, amount: u128, msg: &str, gas: u64) -> Call {
    let args = near_sdk::serde_json::json!({
        "receiver_id": receiver, "amount": amount.to_string(), "msg": msg
    })
    .to_string();
    fcall(token, "ft_transfer_call", args, 1, gas)
}

/// Common plan fields for a buy paid in NEAR/wNEAR (`counted` = amount) or Q (nothing counted).
pub struct BuyShape {
    pub calls: Vec<Call>,
    pub settle: Settle,
    pub extra: u128,
    pub out: AccountId,
    pub order_dex: AccountId,
    pub storage: Vec<AccountId>,
    pub orderable: bool,
}

pub fn buy_plan(t: &CurveTrade, c: &Ctx, s: BuyShape) -> Plan {
    let near_in =
        matches!(s.settle, Settle::Wrap | Settle::NearIn | Settle::NearInFull | Settle::NearrrTax { .. });
    let amount = t.amount.0;
    let (spend, counted, fee) =
        if near_in { (amount.saturating_add(s.extra), amount, bps(amount, c.fee_bps)) } else { (0, 0, 0) };
    let spend = spend.saturating_add(storage_spend(&s.calls));
    let native_out = s.calls.iter().map(|x| x.deposit).fold(0u128, |a, d| a.saturating_add(d));
    let gas = s.calls.iter().map(|x| x.gas).sum();
    let token_in = t.quote.clone().unwrap_or_else(|| c.wrap.clone());
    Plan {
        calls: s.calls,
        settle: s.settle,
        spend,
        counted,
        fee,
        fee_cap: 0,
        native_out,
        order_dex: s.order_dex,
        token_in,
        swap: Swap { out_is_near: false, min_out: t.min_out.0, out: s.out.to_string() },
        orderable: s.orderable,
        storage: s.storage,
        gas,
    }
}

pub struct SellShape {
    pub calls: Vec<Call>,
    pub settle: Settle,
    pub token_in: AccountId,
    pub order_dex: AccountId,
    pub storage: Vec<AccountId>,
}

pub fn sell_plan(t: &CurveTrade, c: &Ctx, s: SellShape) -> Plan {
    let out_near = t.quote.is_none() || t.quote.as_ref() == Some(c.wrap);
    let base = c.fee_base(t.min_out.0);
    let fee = if out_near { bps(base, c.fee_bps) } else { 0 };
    let native_out = s.calls.iter().map(|x| x.deposit).fold(0u128, |a, d| a.saturating_add(d));
    let gas = s.calls.iter().map(|x| x.gas).sum();
    let out = t.quote.clone().unwrap_or_else(|| c.wrap.clone());
    let spend = storage_spend(&s.calls);
    Plan {
        calls: s.calls,
        settle: s.settle,
        spend,
        counted: 0,
        fee,
        fee_cap: if out_near { base } else { 0 },
        native_out,
        order_dex: s.order_dex,
        token_in: s.token_in,
        swap: Swap { out_is_near: out_near, min_out: t.min_out.0, out: out.to_string() },
        orderable: true,
        storage: s.storage,
        gas,
    }
}

/// Plans a `CurveBuy` (`buy`) or `CurveSell`. Every check that can fail happens here, before any
/// promise exists.
pub fn plan(allow: &[Dex], buy: bool, t: &CurveTrade, c: &Ctx) -> Result<Plan, &'static str> {
    if t.amount.0 == 0 || t.min_out.0 == 0 {
        return Err(E_BAD_OP);
    }
    check_gas(t.gas.0)?;
    if &t.venue == c.me || t.quote.as_ref() == Some(c.me) {
        return Err(E_BAD_OP);
    }
    // an explicit wNEAR quote is the same as NEAR
    let t = &CurveTrade { quote: t.quote.clone().filter(|q| q != c.wrap), ..t.clone() };
    let v = resolve(allow, &t.venue).ok_or(E_BAD_DEX)?;
    // `setup` is Kelytra's first-trade registration; no other pad has one
    if t.setup && v != Venue::Kelytra {
        return Err(E_BAD_OP);
    }
    let p = match v {
        Venue::Aidols(pad) => aidols::plan(pad, buy, t, c)?,
        Venue::Factory(pad) => {
            let mut p = factory::plan(pad, buy, t, c)?;
            // a Nearrr buy's callback re-derives the factory from its allowlist index
            if let Settle::NearrrTax { ref mut dex, .. } = p.settle {
                let i = allow
                    .iter()
                    .position(|d| d.kind == DexKind::FactoryCurve(FactoryPad::Nearrr) && d.id == t.venue)
                    .ok_or(E_BAD_DEX)?;
                *dex = u16::try_from(i).map_err(|_| E_BAD_DEX)?;
            }
            p
        }
        Venue::Token(pad) => token::plan(pad, buy, t, c)?,
        Venue::Kelytra => {
            let dex =
                allow.iter().position(|d| d.kind == DexKind::Kelytra && d.id == t.venue).ok_or(E_BAD_DEX)?;
            kelytra::plan(buy, t, c, u16::try_from(dex).map_err(|_| E_BAD_DEX)?)?
        }
    };
    // shape: [storage_deposit on other receivers]* then the trade call(s), all to ONE receiver;
    // the last call's batch result is the swap result the settle callback reads
    let last = p.calls.last().ok_or(E_BAD_OP)?;
    let (pre, trade): (Vec<&Call>, Vec<&Call>) = p.calls.iter().partition(|x| x.receiver != last.receiver);
    if p.swap.min_out == 0
        || pre.iter().any(|x| x.method != "storage_deposit" || x.deposit > VENUE_STORAGE)
        || p.calls.iter().take(pre.len()).any(|x| x.receiver == last.receiver)
    {
        return Err(E_BAD_OP);
    }
    // the trade calls attach at most the op's declared gas
    if trade.iter().map(|x| x.gas).sum::<u64>() > t.gas.0 {
        return Err(E_GAS);
    }
    Ok(p)
}

/// Plans a `CurveClaim` (housekeeping; pays this account). Returns the call and its spend.
pub fn plan_claim(allow: &[Dex], cl: &CurveClaim, c: &Ctx) -> Result<(Call, u128), &'static str> {
    if &cl.venue == c.me || cl.token.as_ref() == Some(c.me) || cl.amount.is_some_and(|a| a.0 == 0) {
        return Err(E_BAD_OP);
    }
    let v = resolve(allow, &cl.venue).ok_or(E_BAD_DEX)?;
    let g = GAS_CURVE_CLAIM * TGAS;
    let j = |v: near_sdk::serde_json::Value| v.to_string();
    use near_sdk::serde_json::json;
    let no_extra = cl.token.is_none() && cl.amount.is_none();
    let call = match (cl.action, v) {
        (ClaimAction::NiraClaimGraduated, Venue::Factory(FactoryPad::Nira))
            if cl.token.is_none() && cl.amount.is_none() =>
        {
            fcall(
                &cl.venue,
                "claim_graduated_balance",
                j(json!({"launch_id": market_str(&cl.market)?})),
                0,
                g,
            )
        }
        (ClaimAction::MemeCookingWithdraw, Venue::Factory(FactoryPad::MemeCooking)) if cl.token.is_none() => {
            let amount = cl.amount.ok_or(E_BAD_OP)?.0;
            fcall(
                &cl.venue,
                "withdraw",
                j(json!({"meme_id": market_u64(&cl.market)?, "amount": amount.to_string()})),
                1,
                g,
            )
        }
        // `token` (optional, never sent): the auction's token `<symbol>-<id>.meme-cooking.near`, only so
        // a StorageDeposit op in the same execute may register this account on it (the claim pays by
        // ft_transfer; unregistered = the claim fails and the pad keeps it claimable)
        (ClaimAction::MemeCookingClaim, Venue::Factory(FactoryPad::MemeCooking))
            if cl.amount.is_none() && cl.token.as_ref().is_none_or(|t| one_label_under(&cl.venue, t)) =>
        {
            fcall(&cl.venue, "claim", j(json!({"meme_id": market_u64(&cl.market)?})), 1, g)
        }
        (ClaimAction::MemeCookingRegister, Venue::Factory(FactoryPad::MemeCooking))
            if cl.token.is_none() && cl.market.is_none() =>
        {
            let amount = cl.amount.ok_or(E_BAD_OP)?.0;
            if amount > MEME_STORAGE_MAX {
                return Err(E_BAD_OP);
            }
            return Ok((fcall(&cl.venue, "storage_deposit", "{}".to_string(), amount, g), amount));
        }
        (ClaimAction::DragonpadClaim, Venue::Factory(FactoryPad::Dragonpad)) if no_extra => {
            let asset = match &cl.market {
                None => "near".to_string(),
                Some(_) => {
                    let t = market_token(&cl.market)?;
                    if !one_label_under(&cl.venue, &t) {
                        return Err(E_MARKET);
                    }
                    format!("nep141:{t}")
                }
            };
            fcall(&cl.venue, "claim", j(json!({"asset": asset})), 0, g)
        }
        (ClaimAction::VistaClaimPending, Venue::Factory(FactoryPad::VistaLaunch)) if no_extra => {
            let t = market_token(&cl.market)?;
            if !factory::is_vista_token(&t) {
                return Err(E_MARKET);
            }
            fcall(&cl.venue, "claim_pending", j(json!({"token_id": t})), 1, g)
        }
        (ClaimAction::ChipfiClaim, Venue::Token(TokenPad::Chipfi)) if no_extra && cl.market.is_none() => {
            fcall(&cl.venue, "claim", "{}".to_string(), 0, g)
        }
        (ClaimAction::KelytraWithdraw, Venue::Kelytra) if cl.market.is_none() => {
            let token = cl.token.as_ref().ok_or(E_BAD_OP)?;
            let amount = cl.amount.ok_or(E_BAD_OP)?.0;
            // the exchange refuses less than 65 TGas attached (real wasm, kelytra.rs)
            let wg = kelytra::GAS_WITHDRAW * TGAS;
            fcall(&cl.venue, "withdraw", j(json!({"token_id": token, "amount": amount.to_string()})), 1, wg)
        }
        (ClaimAction::KelytraRegister, Venue::Kelytra) if cl.market.is_none() && cl.amount.is_none() => {
            let token = cl.token.as_ref().ok_or(E_BAD_OP)?;
            let args = j(json!({"token_id": token, "account_id": c.me}));
            // register_balance burns ~2.2 TGas (sandbox, real wasm): a small budget keeps a first
            // buy (StorageDeposit + 2 registers + CurveBuy) inside one 300 TGas execute
            let rg = kelytra::GAS_REGISTER * TGAS;
            return Ok((fcall(&cl.venue, "register_balance", args, KELYTRA_REGISTER, rg), KELYTRA_REGISTER));
        }
        (ClaimAction::KelytraDeposit, Venue::Kelytra) if cl.market.is_none() => {
            let token = cl.token.as_ref().ok_or(E_BAD_OP)?;
            let amount = cl.amount.ok_or(E_BAD_OP)?.0;
            let spend = if token == c.wrap { amount } else { 0 };
            return Ok((ft_call(token, &cl.venue, amount, "deposit", g), spend));
        }
        (ClaimAction::NearmemefunWithdraw, Venue::Token(TokenPad::Nearmemefun))
            if cl.market.is_none() && cl.token.is_none() =>
        {
            let amount = cl.amount.ok_or(E_BAD_OP)?.0;
            let wg = token::NEARMEMEFUN_WITHDRAW_TGAS * TGAS;
            fcall(&cl.venue, "withdraw_near", j(json!({"amount": amount.to_string()})), 1, wg)
        }
        _ => return Err(E_BAD_OP),
    };
    Ok((call, 0))
}

#[cfg(test)]
mod order_tests;
#[cfg(test)]
mod settle_tests;
#[cfg(test)]
mod tests;
