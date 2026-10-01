//! Promise chains of `Chain`, `IntentsSwap` and the continuation (routing C.1, C.2.4). Every
//! callback is `#[private]` (no new device / relayer method). Every terminal path unlocks Q and
//! ends in `finish_settle` (execute paths) or a route state change (continuations).
use super::quote::{self, Checked};
use super::*;
use crate::policy::{bps, check_reserve, mul_div};
use crate::{
    batch_for, fail, liquid_balance, ok, SettleArgs, TradingAccount, TradingAccountExt, GAS_CALLBACK,
};
use near_sdk::{env, near, Gas, GasWeight, NearToken, Promise, PromiseError};

/// Funding / pulling on the verifier (`ft_transfer_call` / `ft_withdraw`), as GAS_INTENTS_TRANSFER.
pub const GAS_VERIFIER: u64 = 50;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct ChainSt {
    pub settle: SettleArgs,
    pub chain: Chain,
    pub rid: String,
    #[serde(default)]
    pub before: Option<U128>,
    /// liquid balance right after leg 1 was scheduled (a payable curve leg 1's refund)
    #[serde(default)]
    pub liquid: Option<U128>,
    /// leg 1: amount used and the NEAR-leg fee earned (buys)
    #[serde(default)]
    pub used1: Option<U128>,
    #[serde(default)]
    pub charged: Option<U128>,
    #[serde(default)]
    pub credited: Option<U128>,
    /// V16-09 (F1): the execute receipt's prepaid gas x GAS_PRICE_BOUND, the most this tx's gas
    /// refunds can add to the balance; never counted as a payable leg 1's refund.
    #[serde(default)]
    pub allowance: Option<U128>,
}

fn tg(t: u64) -> Gas {
    Gas::from_tgas(t)
}

fn u128_result(max_len: usize) -> Result<Option<u128>, ()> {
    match env::promise_result_checked(0, max_len) {
        Err(PromiseError::Failed) => Err(()),
        Ok(b) => Ok(near_sdk::serde_json::from_slice::<U128>(&b).ok().map(|x| x.0)),
        Err(_) => Ok(None),
    }
}

fn view_balance(q: &AccountId) -> near_sdk::PromiseIndex {
    let me = env::current_account_id();
    env::promise_create(
        q.clone(),
        "ft_balance_of",
        format!("{{\"account_id\":\"{me}\"}}").as_bytes(),
        NearToken::from_yoctonear(0),
        tg(GAS_CHAIN_VIEW),
    )
}

fn then_self(idx: near_sdk::PromiseIndex, method: &str, args: &str, gas: u64) -> near_sdk::PromiseIndex {
    env::promise_then(
        idx,
        env::current_account_id(),
        method,
        args.as_bytes(),
        NearToken::from_yoctonear(0),
        tg(gas),
    )
}

fn st_json(st: &ChainSt) -> String {
    near_sdk::serde_json::to_string(st).unwrap_or_else(|_| fail("E_JSON"))
}

impl TradingAccount {
    /// TGas a leg attaches when scheduled (`leg_promise`). A curve leg attaches its whole plan:
    /// the trade call(s) at the op's gas, any registration the venue plans before them (an
    /// Aidols-family storage_deposit, GAS_VENUE_STORAGE) and an action fee per extra call
    /// (`curve_leg_gas`, as `run` budgets a curve op), not only the op's `gas`.
    fn leg_gas(&self, l: &ChainLeg) -> u64 {
        match l {
            ChainLeg::FtTransferCall { gas, .. } | ChainLeg::PlachDepositNear { gas, .. } => gas.0 / TGAS,
            ChainLeg::CurveBuy(t) | ChainLeg::CurveSell(t) => {
                let me = env::current_account_id();
                // leg 2 / a continuation swap is planned with a placeholder amount, as leg_info
                let tr = CurveTrade { amount: U128(t.amount.0.max(1)), ..t.clone() };
                let e = self.venv(&me, env::block_timestamp());
                venues::plan(&self.dex_allowlist, matches!(l, ChainLeg::CurveBuy(_)), &tr, &ctx(&e))
                    .map_or(t.gas.0, |p| curve_leg_gas(&p, t.gas.0))
                    / TGAS
            }
            ChainLeg::IntentsFund { .. } => GAS_VERIFIER + GAS_CHAIN_CB + GAS_ACTION,
            ChainLeg::ShardsSell { gas, .. } => gas.0 / TGAS + GAS_SHARDS_Q_WITHDRAW,
            ChainLeg::ShardsBuy { gas, .. } => gas.0 / TGAS,
        }
    }

    /// Gas budgets of the three step callbacks (each covers everything it schedules).
    pub(crate) fn budgets(&self, c: &Chain) -> (u64, u64, u64) {
        let mid = GAS_CHAIN_CB + self.leg_gas(&c.leg2) + GAS_CHAIN_CB + 2 * GAS_ACTION;
        let leg1 = GAS_CHAIN_CB + GAS_CHAIN_VIEW + mid + 2 * GAS_ACTION;
        let start = GAS_CHAIN_CB + self.leg_gas(&c.leg1) + leg1 + 2 * GAS_ACTION;
        (start, leg1, mid)
    }

    fn venv<'a>(&'a self, me: &'a AccountId, now: u64) -> Env<'a> {
        Env {
            me,
            wrap: &self.wrap,
            allow: &self.dex_allowlist,
            referrer: &self.fee.fee_recipient,
            fee_bps: self.fee.fee_bps,
            now_ns: now,
        }
    }

    /// What a leg used of `amount`: ft_transfer_call legs report it (resolve), other calls are
    /// all-or-nothing (a failed receipt is caught before this).
    fn leg_used(&self, l: &ChainLeg, amount: u128, r: Option<u128>) -> u128 {
        let reports = match l {
            ChainLeg::FtTransferCall { .. } | ChainLeg::ShardsBuy { .. } => true,
            ChainLeg::CurveBuy(t) | ChainLeg::CurveSell(t) => {
                let me = env::current_account_id();
                let tr = CurveTrade { amount: U128(amount.max(1)), ..t.clone() };
                venues::plan(
                    &self.dex_allowlist,
                    matches!(l, ChainLeg::CurveBuy(_)),
                    &tr,
                    &ctx(&self.venv(&me, env::block_timestamp())),
                )
                .is_ok_and(|p| matches!(p.settle, venues::Settle::Wrap | venues::Settle::Token))
            }
            _ => false,
        };
        if reports {
            r.map_or(amount, |u| u.min(amount))
        } else {
            amount
        }
    }

    /// Schedules one leg with input `amount` (`q` = the route's quote token, `rid` its id);
    /// returns its last promise.
    fn leg_promise(&self, l: &ChainLeg, amount: u128, q: &AccountId, rid: &str) -> near_sdk::PromiseIndex {
        let me = env::current_account_id();
        let now = env::block_timestamp();
        match l {
            ChainLeg::FtTransferCall { token, receiver_id, msg: m, gas, .. } => env::promise_create(
                token.clone(),
                "ft_transfer_call",
                format!(
                    "{{\"receiver_id\":\"{}\",\"amount\":\"{}\",\"msg\":{}}}",
                    receiver_id,
                    amount,
                    crate::jstr(m)
                )
                .as_bytes(),
                NearToken::from_yoctonear(1),
                Gas::from_gas(gas.0),
            ),
            ChainLeg::CurveBuy(t) | ChainLeg::CurveSell(t) => {
                let tr = CurveTrade { amount: U128(amount), ..t.clone() };
                let p = ok(venues::plan(
                    &self.dex_allowlist,
                    matches!(l, ChainLeg::CurveBuy(_)),
                    &tr,
                    &ctx(&self.venv(&me, now)),
                ));
                let mut batches = vec![];
                let mut last = None;
                for c in &p.calls {
                    let idx = batch_for(&mut batches, c.receiver.clone());
                    env::promise_batch_action_function_call_weight(
                        idx,
                        c.method,
                        c.args.as_bytes(),
                        NearToken::from_yoctonear(c.deposit),
                        Gas::from_gas(c.gas),
                        GasWeight(0),
                    );
                    last = Some(idx);
                }
                last.unwrap_or_else(|| fail("E_BAD_OP"))
            }
            ChainLeg::PlachDepositNear { dex, msg: m, gas, .. } => env::promise_create(
                dex.clone(),
                "deposit_near",
                format!("{{\"operations\":{m}}}").as_bytes(),
                NearToken::from_yoctonear(amount),
                Gas::from_gas(gas.0),
            ),
            ChainLeg::ShardsSell { token, min_out, gas, .. } => {
                let idx = env::promise_batch_create(token);
                let sell = format!(
                    "{{\"amount\":\"{amount}\",\"min_amount_out\":\"{}\",\"max_total_fee_bps\":{},\"deadline_ns\":\"{}\"}}",
                    min_out.0,
                    crate::SHARDS_MAX_TOTAL_FEE_BPS,
                    crate::shards_deadline(now)
                );
                for (m, a, g) in [
                    ("sell_exact_in", sell, Gas::from_gas(gas.0)),
                    ("withdraw_quote", "{}".to_string(), tg(GAS_SHARDS_Q_WITHDRAW)),
                ] {
                    env::promise_batch_action_function_call_weight(
                        idx,
                        m,
                        a.as_bytes(),
                        NearToken::from_yoctonear(1),
                        g,
                        GasWeight(0),
                    );
                }
                idx
            }
            ChainLeg::ShardsBuy { token, min_out, gas, .. } => {
                let m = format!(
                    "{{\"v\":1,\"action\":\"buy\",\"order_id\":{},\"min_amount_out\":\"{}\",\"max_total_fee_bps\":{},\"deadline_ns\":\"{}\"}}",
                    crate::jstr(rid),
                    min_out.0,
                    crate::SHARDS_MAX_TOTAL_FEE_BPS,
                    crate::shards_deadline(now)
                );
                env::promise_create(
                    q.clone(),
                    "ft_transfer_call",
                    format!(
                        "{{\"receiver_id\":\"{token}\",\"amount\":\"{amount}\",\"msg\":{}}}",
                        crate::jstr(&m)
                    )
                    .as_bytes(),
                    NearToken::from_yoctonear(1),
                    Gas::from_gas(gas.0),
                )
            }
            ChainLeg::IntentsFund { .. } => fail(E_CHAIN_LEG),
        }
    }

    /// NEAR fee transfer (skipped, and logged, if it would dip below RESERVE, as finish_settle).
    fn pay_fee(&self, rid: &str, x: u128) {
        if x == 0 {
            return;
        }
        if check_reserve(liquid_balance().saturating_sub(escrow_total()), x).is_err() {
            route_event(
                "fee_skipped",
                &format!("{{\"client_order_id\":{},\"fee\":\"{x}\"}}", crate::jstr(rid)),
            );
            return;
        }
        Promise::new(self.fee.fee_recipient.clone()).transfer(NearToken::from_yoctonear(x)).detach();
    }

    /// `run` step 7 for `Op::Chain` (validated by check_chain): lock Q, read its balance, go.
    pub(crate) fn dispatch_chain(&mut self, c: Chain, settle: &str, rid: &str) {
        lock(c.q.as_str(), rid);
        let (start, _, _) = self.budgets(&c);
        let settle: SettleArgs = near_sdk::serde_json::from_str(settle).unwrap_or_else(|_| fail("E_JSON"));
        let q = c.q.clone();
        let st = ChainSt {
            settle,
            chain: c,
            rid: rid.to_string(),
            before: None,
            liquid: None,
            used1: None,
            charged: None,
            credited: None,
            allowance: Some(U128(venues::settle::gas_allowance())),
        };
        let v = view_balance(&q);
        then_self(v, "on_chain_start", &format!("{{\"st\":{}}}", st_json(&st)), start);
    }

    /// A terminal failure before anything reached Q: settle as a failed swap, unlock.
    fn chain_failed(&mut self, st: ChainSt, used: u128) {
        unlock(st.chain.q.as_str(), &st.rid);
        let failed = used == 0;
        self.finish_settle(st.settle, failed, used, 0);
    }

    /// Q stays in the wallet for this route (`route_held`); the NEAR leg's fee (buys) is earned.
    fn chain_held(&mut self, st: ChainSt, credited: u128, reason: &str) {
        let q = st.chain.q.clone();
        unlock(q.as_str(), &st.rid);
        if credited > 0 {
            let r = Route {
                kind: RouteKind::Chain,
                q: q.clone(),
                origin: q.clone(),
                deposit_address: String::new(),
                funded: U128(0),
                quote_amount: U128(0),
                q_min: st.chain.min_mid,
                q_quoted: st.chain.max_mid,
                slippage_bps: 0,
                fee_escrow: U128(0),
                cont: None,
                cont_deadline_ns: U64(0),
                quote_deadline_ns: U64(0),
                credited: U128(credited),
                spent: U128(0),
                state: RouteState::Held,
                cont_id: U64(0),
                pending: false,
                pending_height: U64(0),
            };
            // a full route table must not lose the settlement: log only
            if let Err(e) = save_route(&st.rid, &r) {
                route_event(
                    "route_not_stored",
                    &format!("{{\"id\":{},\"error\":\"{e}\"}}", crate::jstr(&st.rid)),
                );
            }
        }
        route_event(
            "route_held",
            &format!(
                "{{\"id\":{},\"q\":\"{q}\",\"amount\":\"{credited}\",\"reason\":\"{reason}\"}}",
                crate::jstr(&st.rid)
            ),
        );
        let used1 = st.used1.map_or(st.settle.amount.0, |u| u.0);
        let charged = st.charged.map_or(0, |c| c.0);
        self.finish_settle(st.settle, false, used1, charged);
    }
}

#[near]
impl TradingAccount {
    /// Chain step 1: Q balance before -> leg 1.
    #[private]
    pub fn on_chain_start(&mut self, st: ChainSt) {
        let mut st = st;
        // R2-05: leg 1 sends its input only now; a lock taken on it since the execute (a Nearrr
        // buy's refund proof, another route's Q) refuses the Chain before anything moved
        let me = env::current_account_id();
        let input =
            leg_info(&self.venv(&me, env::block_timestamp()), &st.chain.leg1, false).map(|l| l.token_in);
        if input.is_ok_and(|t| busy(&t)) {
            return self.chain_failed(st, 0);
        }
        let before = match u128_result(64) {
            Ok(Some(b)) => b,
            // Q is not a readable NEP-141: nothing moved
            _ => return self.chain_failed(st, 0),
        };
        st.before = Some(U128(before));
        let (_, g1, _) = self.budgets(&st.chain);
        let amount = match &st.chain.leg1 {
            ChainLeg::FtTransferCall { amount, .. } | ChainLeg::PlachDepositNear { amount, .. } => amount.0,
            ChainLeg::CurveBuy(t) | ChainLeg::CurveSell(t) => t.amount.0,
            ChainLeg::ShardsSell { amount, .. } => amount.0,
            ChainLeg::IntentsFund { .. } | ChainLeg::ShardsBuy { .. } => fail(E_CHAIN_LEG),
        };
        let idx = self.leg_promise(&st.chain.leg1, amount, &st.chain.q, &st.rid);
        st.liquid = Some(U128(liquid_balance()));
        then_self(idx, "on_chain_leg1", &format!("{{\"st\":{}}}", st_json(&st)), g1);
    }

    /// Chain step 2: leg 1's result -> Q balance after.
    #[private]
    pub fn on_chain_leg1(&mut self, st: ChainSt) {
        let mut st = st;
        let amount = st.settle.amount.0;
        let r = match u128_result(128) {
            Err(()) => return self.chain_failed(st, 0),
            Ok(r) => r,
        };
        let used = self.leg_used(&st.chain.leg1, amount, r);
        if used == 0 {
            return self.chain_failed(st, 0);
        }
        // the NEAR leg (buys), from the normalised plan (V16-04): a payable curve leg 1's refund
        // is a measured delta net of the gas allowance (V16-09), settled by the same rule as a
        // single-hop curve buy (`curve_fee`); a reporting leg charges pro rata on what it used
        let me = env::current_account_id();
        let li = leg_info(&self.venv(&me, env::block_timestamp()), &st.chain.leg1, false).ok();
        let fee = st.settle.fee.0;
        let (used, charged) = match li.as_ref().and_then(|l| l.measured) {
            Some(mode) => {
                let delta = liquid_balance()
                    .saturating_sub(st.liquid.map_or(u128::MAX, |l| l.0))
                    .saturating_sub(st.allowance.map_or(0, |a| a.0));
                let (u, c) = venues::settle::curve_fee(mode, amount, fee, self.fee.fee_bps, delta, 0);
                (u.min(used), c)
            }
            None if li.as_ref().is_some_and(|l| l.near_in) => (used, mul_div(fee, used, amount)),
            None => (used, 0),
        };
        if used == 0 {
            // the pad refunded the whole buy (near_in_full): nothing reached Q
            return self.chain_failed(st, 0);
        }
        st.used1 = Some(U128(used));
        st.charged = Some(U128(charged));
        let (_, _, gm) = self.budgets(&st.chain);
        let v = view_balance(&st.chain.q);
        then_self(v, "on_chain_mid", &format!("{{\"st\":{}}}", st_json(&st)), gm);
    }

    /// Chain step 3: credited = min(delta, max_mid) -> leg 2 (or hold).
    #[private]
    pub fn on_chain_mid(&mut self, st: ChainSt) {
        let mut st = st;
        let after = match u128_result(64) {
            Ok(Some(a)) => a,
            _ => return self.chain_held(st, 0, "not_delivered"),
        };
        let delta = after.saturating_sub(st.before.map_or(u128::MAX, |b| b.0));
        let credited = delta.min(st.chain.max_mid.0);
        if credited == 0 {
            return self.chain_held(st, 0, "not_delivered");
        }
        if credited < st.chain.min_mid.0 {
            return self.chain_held(st, credited, "below_mid");
        }
        st.credited = Some(U128(credited));
        if let ChainLeg::IntentsFund { signed_quote, signature } = st.chain.leg2.clone() {
            // V16-05: never fund a quote whose route (and continuation id) can't be stored
            if !route_slot_free() {
                return self.chain_held(st, credited, "routes_full");
            }
            // re-check at funding time (the quote must still be valid and unused)
            let me = env::current_account_id();
            let now = env::block_timestamp();
            let e = self.venv(&me, now);
            let ch = match quote::check_sell(
                &e,
                &signed_quote,
                &signature,
                &st.chain.q,
                st.chain.min_mid.0,
                st.chain.min_final.0,
            ) {
                Ok(c) => c,
                Err(_) => return self.chain_held(st, credited, "quote_invalid"),
            };
            if credited < ch.min_amount_in
                || credited > ch.amount
                || quote::scaled(ch.min_amount_out, credited, ch.amount) < st.chain.min_final.0
            {
                return self.chain_held(st, credited, "below_mid");
            }
            if crate::intents::mark_quote_used(
                &ch.deposit_address,
                ch.deadline_ns.saturating_add(crate::intents::USED_QUOTE_MARGIN_NS),
                now,
            )
            .is_err()
            {
                return self.chain_held(st, credited, "quote_invalid");
            }
            let p = env::promise_create(
                st.chain.q.clone(),
                "ft_transfer_call",
                format!(
                    "{{\"receiver_id\":\"{}\",\"amount\":\"{}\",\"msg\":\"{}\"}}",
                    crate::verifier(),
                    credited,
                    ch.deposit_address
                )
                .as_bytes(),
                NearToken::from_yoctonear(1),
                tg(GAS_VERIFIER),
            );
            let args = near_sdk::serde_json::json!({"st": st, "quote": QuoteRec::from(&ch)}).to_string();
            then_self(p, "on_chain_funded", &args, GAS_CHAIN_CB);
            return;
        }
        let idx = self.leg_promise(&st.chain.leg2, credited, &st.chain.q, &st.rid);
        then_self(idx, "on_chain_settled", &format!("{{\"st\":{}}}", st_json(&st)), GAS_CALLBACK);
    }

    /// Chain step 4: leg 2's result. Failed / nothing used -> held; else done.
    #[private]
    pub fn on_chain_settled(&mut self, st: ChainSt) {
        let credited = st.credited.map_or(0, |c| c.0);
        let used2 = match u128_result(128) {
            Err(()) => 0,
            Ok(r) => self.leg_used(&st.chain.leg2, credited, r),
        };
        if used2 < credited {
            return self.chain_held(st, credited - used2, "leg2_failed");
        }
        let q = st.chain.q.clone();
        unlock(q.as_str(), &st.rid);
        route_event(
            "route_done",
            &format!("{{\"id\":{},\"out\":\"{}\"}}", crate::jstr(&st.rid), st.chain.min_final.0),
        );
        let used1 = st.used1.map_or(st.settle.amount.0, |u| u.0);
        // sells: the reserved fee (bps of the min_final bound) is earned once leg 2 delivered NEAR
        let charged =
            st.charged.map_or(0, |c| c.0).max(if st.settle.counted.0 == 0 { st.settle.fee.0 } else { 0 });
        self.finish_settle(st.settle, false, used1, charged);
    }

    /// Chain sell through 1Click: the funding's result -> an IntentsSell route (continuation pull).
    #[private]
    pub fn on_chain_funded(&mut self, st: ChainSt, quote: QuoteRec) {
        let credited = st.credited.map_or(0, |c| c.0);
        let used = match u128_result(128) {
            Err(()) => 0,
            Ok(r) => r.map_or(credited, |u| u.min(credited)),
        };
        if used == 0 {
            return self.chain_held(st, credited, "fund_failed");
        }
        let now = env::block_timestamp();
        let cont_id = new_cont(&st.rid);
        let r = Route {
            kind: RouteKind::IntentsSell,
            q: st.chain.q.clone(),
            origin: st.chain.q.clone(),
            deposit_address: quote.deposit_address.clone(),
            funded: U128(used),
            quote_amount: U128(quote.amount),
            q_min: U128(quote::scaled(quote.min_amount_out, used, quote.amount)),
            q_quoted: U128(quote::scaled(quote.amount_out, used, quote.amount)),
            slippage_bps: quote.slippage_bps,
            fee_escrow: U128(0),
            cont: None,
            cont_deadline_ns: U64(now.saturating_add(CONT_MAX_NS)),
            quote_deadline_ns: U64(quote.deadline_ns),
            credited: U128(0),
            spent: U128(0),
            state: RouteState::Funded,
            cont_id: U64(cont_id),
            pending: false,
            pending_height: U64(0),
        };
        if let Err(e) = save_route(&st.rid, &r) {
            route_event(
                "route_not_stored",
                &format!("{{\"id\":{},\"error\":\"{e}\"}}", crate::jstr(&st.rid)),
            );
        }
        unlock(st.chain.q.as_str(), &st.rid);
        route_event(
            "route_started",
            &format!(
                "{{\"id\":{},\"kind\":\"IntentsSell\",\"q\":\"{}\",\"funded\":\"{used}\",\"q_min\":\"{}\",\"deposit_address\":\"{}\",\"cont_id\":\"{cont_id}\"}}",
                crate::jstr(&st.rid),
                st.chain.q,
                r.q_min.0,
                quote.deposit_address
            ),
        );
        let used1 = st.used1.map_or(st.settle.amount.0, |u| u.0);
        // the NEAR leg is the later pull: no fee here
        self.finish_settle(st.settle, false, used1, 0);
    }
}

/// The quote fields a route keeps (JSON through the callback).
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct QuoteRec {
    pub deposit_address: String,
    pub deadline_ns: u64,
    #[serde(with = "u128s")]
    pub amount: u128,
    #[serde(with = "u128s")]
    pub min_amount_out: u128,
    #[serde(with = "u128s")]
    pub amount_out: u128,
    pub slippage_bps: u16,
}

impl From<&Checked> for QuoteRec {
    fn from(c: &Checked) -> Self {
        QuoteRec {
            deposit_address: c.deposit_address.clone(),
            deadline_ns: c.deadline_ns,
            amount: c.amount,
            min_amount_out: c.min_amount_out,
            amount_out: c.amount_out,
            slippage_bps: c.slippage_bps,
        }
    }
}

mod u128s {
    use near_sdk::serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(x: &u128, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&x.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u128, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(near_sdk::serde::de::Error::custom)
    }
}

// ======================= IntentsSwap (buy) and the continuation =======================

/// A validated IntentsSwap (run step 4).
pub struct IntentsPlan {
    pub quote: Checked,
    pub fee: u128,
}

/// `Op::IntentsSwap` rules besides the quote (C.2.1). `order_fire` = refused (owner decision).
pub fn check_intents_swap(e: &Env, s: &IntentsSwap, order_fire: bool) -> Result<IntentsPlan, &'static str> {
    if order_fire {
        return Err(E_ORDER_OPS);
    }
    if &s.q == e.wrap || &s.q == e.me {
        return Err("E_BAD_OP");
    }
    let c = &s.cont;
    if c.min_final.0 == 0
        || c.dexes.is_empty()
        || c.dexes.len() > crate::MAX_ORDER_DEXES
        || c.token_out == s.q
        || &c.token_out == e.me
    {
        return Err("E_BAD_OP");
    }
    if c.dexes.iter().any(|d| dex_kind(e.allow, d).is_none() && venues::resolve(e.allow, d).is_none()) {
        return Err("E_BAD_DEX");
    }
    // V16-10: no continuation leg on a callback-chain venue
    if c.dexes.iter().any(|d| !chain_venue_ok(e.allow, d)) {
        return Err(E_CHAIN_LEG);
    }
    if s.cont_deadline_ns.0 <= e.now_ns || s.cont_deadline_ns.0 > e.now_ns.saturating_add(CONT_MAX_NS) {
        return Err("E_BAD_OP");
    }
    let q = quote::check_buy(e, &s.signed_quote, &s.signature, &s.q)?;
    let fee = bps(q.amount, e.fee_bps);
    Ok(IntentsPlan { quote: q, fee })
}

impl TradingAccount {
    /// `run` step 7 for `Op::IntentsSwap`: write the route, then fund the deposit address.
    pub(crate) fn dispatch_intents(&mut self, s: IntentsSwap, p: IntentsPlan, settle: &str, rid: &str) {
        let now = env::block_timestamp();
        ok(crate::intents::mark_quote_used(
            &p.quote.deposit_address,
            p.quote.deadline_ns.saturating_add(crate::intents::USED_QUOTE_MARGIN_NS),
            now,
        ));
        let cont_id = new_cont(rid);
        let r = Route {
            kind: RouteKind::IntentsBuy,
            q: s.q.clone(),
            origin: self.wrap.clone(),
            deposit_address: p.quote.deposit_address.clone(),
            funded: U128(p.quote.amount),
            quote_amount: U128(p.quote.amount),
            q_min: U128(p.quote.min_amount_out),
            q_quoted: U128(p.quote.amount_out),
            slippage_bps: p.quote.slippage_bps,
            fee_escrow: U128(p.fee),
            cont: Some(s.cont.clone()),
            cont_deadline_ns: s.cont_deadline_ns,
            quote_deadline_ns: U64(p.quote.deadline_ns),
            credited: U128(0),
            spent: U128(0),
            state: RouteState::Funded,
            cont_id: U64(cont_id),
            pending: false,
            pending_height: U64(0),
        };
        ok(save_route(rid, &r));
        escrow_add(p.fee);
        route_event(
            "route_started",
            &format!(
                "{{\"id\":{},\"kind\":\"IntentsBuy\",\"q\":\"{}\",\"funded\":\"{}\",\"q_min\":\"{}\",\"deposit_address\":\"{}\",\"cont_id\":\"{cont_id}\"}}",
                crate::jstr(rid),
                s.q,
                p.quote.amount,
                p.quote.min_amount_out,
                p.quote.deposit_address
            ),
        );
        let f = env::promise_create(
            self.wrap.clone(),
            "ft_transfer_call",
            format!(
                "{{\"receiver_id\":\"{}\",\"amount\":\"{}\",\"msg\":\"{}\"}}",
                crate::verifier(),
                p.quote.amount,
                p.quote.deposit_address
            )
            .as_bytes(),
            NearToken::from_yoctonear(1),
            tg(GAS_VERIFIER),
        );
        then_self(
            f,
            "on_route_funded",
            &format!("{{\"rid\":{},\"settle\":{settle}}}", crate::jstr(rid)),
            GAS_CALLBACK,
        );
    }
}

/// `Op::IntentsPull` (continuations only): `verifier.ft_withdraw{token, receiver_id: self, amount}`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(crate = "near_sdk::serde", deny_unknown_fields)]
pub struct IntentsPull {
    pub token: AccountId,
    pub amount: U128,
}

/// What a continuation fire may do (C.2.4). Pure: unit tested at every edge.
#[derive(Debug, PartialEq)]
pub enum ContStep {
    /// pull Q then swap it (buy, before the deadline)
    PullSwap,
    /// pull Q and hold it (buy, after the deadline)
    PullHold,
    /// pull wNEAR (sell)
    PullSell,
    /// pull the origin back (quote expired: refund)
    PullRefund,
}

pub fn cont_step(
    r: &Route,
    pull: &IntentsPull,
    has_swap: bool,
    now: u64,
    wrap: &AccountId,
) -> Result<ContStep, &'static str> {
    if r.state != RouteState::Funded {
        return Err("E_NO_ORDER");
    }
    if pull.amount.0 == 0 {
        return Err("E_BAD_OP");
    }
    // V16-07: a refund pull must bring back (nearly) the whole funded amount: the intents
    // balance is shared, so a small pull of the origin proves nothing about this route. The
    // delivery token is also checked absent before the pull (on_cont_refund_check).
    let refund_min = r.funded.0 - mul_div(r.funded.0, u128::from(r.slippage_bps), 10_000);
    let refund_ok = now > r.quote_deadline_ns.0
        && pull.token == r.origin
        && pull.amount.0 <= r.funded.0
        && pull.amount.0 >= refund_min.max(1);
    match r.kind {
        RouteKind::IntentsBuy if pull.token == r.q => {
            if pull.amount.0 < r.q_min.0 || pull.amount.0 > quote::with_slip(r.q_quoted.0, r.slippage_bps) {
                return Err("E_CONT_AMOUNT");
            }
            match (now <= r.cont_deadline_ns.0, has_swap) {
                (true, true) => Ok(ContStep::PullSwap),
                (false, false) => Ok(ContStep::PullHold),
                _ => Err(E_ORDER_OPS),
            }
        }
        RouteKind::IntentsSell if &pull.token == wrap && pull.token != r.origin => {
            if has_swap {
                return Err(E_ORDER_OPS);
            }
            // FLEX scaling was applied when the route was written (q_min / q_quoted = wNEAR bounds)
            if pull.amount.0 < r.q_min.0 || pull.amount.0 > quote::with_slip(r.q_quoted.0, r.slippage_bps) {
                return Err("E_CONT_AMOUNT");
            }
            Ok(ContStep::PullSell)
        }
        _ if refund_ok && !has_swap => Ok(ContStep::PullRefund),
        _ => Err(E_ORDER_OPS),
    }
}

impl TradingAccount {
    /// `execute_order(order_id >= CONT_BASE, ops)`: a continuation (relayer or device). Only
    /// `[IntentsPull]` or `[IntentsPull, <swap>]` within the stored terms; never an IntentsSwap.
    pub(crate) fn fire_continuation(&mut self, cont_id: u64, ops: Vec<Op>) {
        let now = env::block_timestamp();
        // F1: an expired route is closed first (its continuation then finds no Funded route)
        expire_routes(&self.fee.fee_recipient);
        let rid = cont_route(cont_id).unwrap_or_else(|| fail("E_NO_ORDER"));
        let mut r = load_route(&rid).unwrap_or_else(|| fail("E_NO_ORDER"));
        if r.pending {
            fail("E_ORDER_PENDING");
        }
        let mut it = ops.into_iter();
        let pull = match it.next() {
            Some(Op::IntentsPull(p)) => p,
            _ => fail(E_ORDER_OPS),
        };
        let swap = it.next();
        if it.next().is_some() {
            fail(E_ORDER_OPS);
        }
        let step = ok(cont_step(&r, &pull, swap.is_some(), now, &self.wrap));
        let me = env::current_account_id();
        // AUDIT-S1: native NEAR the swap leg attaches (an Aidols-family storage_deposit)
        let mut leg_native: u128 = 1;
        let leg = match (&step, swap) {
            (ContStep::PullSwap, Some(op)) => {
                let leg = match op {
                    Op::FtTransferCall { token, receiver_id, amount, msg, gas } => {
                        ChainLeg::FtTransferCall { token, receiver_id, amount, msg, gas }
                    }
                    Op::CurveBuy(t) => ChainLeg::CurveBuy(t),
                    Op::CurveSell(t) => ChainLeg::CurveSell(t),
                    _ => fail(E_ORDER_OPS),
                };
                let e = self.venv(&me, now);
                let li = ok(leg_info(&e, &leg, false));
                let c = r.cont.as_ref().unwrap_or_else(|| fail(E_ORDER_OPS));
                if li.token_in != r.q.as_str()
                    || li.amount != pull.amount.0
                    || !c.dexes.contains(&li.dex)
                    || li.out != c.token_out.as_str()
                {
                    fail(E_ORDER_MISMATCH);
                }
                if li.min_out < c.min_final.0 {
                    fail("E_ORDER_MIN_OUT");
                }
                leg_native = li.native_out.max(1);
                Some(leg)
            }
            (_, None) => None,
            _ => fail(E_ORDER_OPS),
        };
        // the pull (and the swap) touch the wallet's Q: per-Q lock
        if matches!(step, ContStep::PullSwap | ContStep::PullHold) {
            lock(r.q.as_str(), &rid);
        }
        // gas: the continuation's whole prepaid gas counts toward the day's gas tally (as a fire)
        self.sync_caps();
        crate::policy::roll_day(&mut self.day, now);
        self.charge_gas(env::prepaid_gas().as_gas());
        ok(check_reserve(liquid_balance().saturating_sub(escrow_total()), leg_native));
        r.pending = true;
        r.pending_height = U64(env::block_height());
        ok(save_route(&rid, &r));
        let lg = leg.as_ref().map_or(0, |l| self.leg_gas(l));
        let cb = GAS_CHAIN_CB + if leg.is_some() { lg + GAS_CALLBACK + 2 * GAS_ACTION } else { 0 };
        if step == ContStep::PullRefund {
            // V16-07: first prove the delivery is absent: the route's delivery token must not be
            // in this account's intents balance (>= q_min) before a refund may be pulled
            let delivery = if r.kind == RouteKind::IntentsSell { self.wrap.clone() } else { r.q.clone() };
            let v = env::promise_create(
                crate::verifier(),
                "mt_balance_of",
                format!("{{\"account_id\":\"{me}\",\"token_id\":\"nep141:{delivery}\"}}").as_bytes(),
                NearToken::from_yoctonear(0),
                tg(GAS_CHAIN_VIEW),
            );
            let args = near_sdk::serde_json::json!({"rid": rid, "pull": pull}).to_string();
            then_self(v, "on_cont_refund_check", &args, GAS_CHAIN_CB + GAS_VERIFIER + cb + 2 * GAS_ACTION);
            return;
        }
        self.pull_then(&rid, &pull, leg, cb);
    }

    /// `verifier.ft_withdraw{token, receiver_id: self, amount}` then `on_cont_pulled`.
    fn pull_then(&self, rid: &str, pull: &IntentsPull, leg: Option<ChainLeg>, cb: u64) {
        let me = env::current_account_id();
        let p = env::promise_create(
            crate::verifier(),
            "ft_withdraw",
            format!(
                "{{\"token\":\"{}\",\"receiver_id\":\"{me}\",\"amount\":\"{}\"}}",
                pull.token, pull.amount.0
            )
            .as_bytes(),
            NearToken::from_yoctonear(1),
            tg(GAS_VERIFIER),
        );
        let args = near_sdk::serde_json::json!({"rid": rid, "pull": pull, "swap": leg}).to_string();
        then_self(p, "on_cont_pulled", &args, cb);
    }

    /// V16-07: releases `returned / funded` of a buy route's escrowed fee unpaid (a proven
    /// refund) and pays the rest (the part 1Click kept was traded).
    fn settle_escrow_refund(&mut self, rid: &str, r: &mut Route, returned: u128) {
        let x = r.fee_escrow.0;
        if x == 0 {
            return;
        }
        escrow_sub(x);
        r.fee_escrow = U128(0);
        let released = mul_div(x, returned.min(r.funded.0), r.funded.0.max(1));
        self.pay_fee(rid, x - released);
    }

    fn route_done(&mut self, rid: &str, mut r: Route, state: RouteState, reason: &str) {
        r.state = state;
        r.pending = false;
        let _ = save_route(rid, &r);
        let name = match state {
            RouteState::Held => "route_held",
            RouteState::Refunded => "route_refunded",
            _ => "route_done",
        };
        route_event(
            name,
            &format!(
                "{{\"id\":{},\"q\":\"{}\",\"amount\":\"{}\",\"reason\":\"{reason}\"}}",
                crate::jstr(rid),
                r.q,
                r.credited.0.saturating_sub(r.spent.0)
            ),
        );
    }

    /// Pays (delivery proven) or releases (refund) a buy route's escrowed fee, once.
    fn settle_escrow(&mut self, rid: &str, r: &mut Route, pay: bool) {
        let x = r.fee_escrow.0;
        if x == 0 {
            return;
        }
        escrow_sub(x);
        r.fee_escrow = U128(0);
        if pay {
            self.pay_fee(rid, x);
            crate::drop_route_spend(rid);
        }
    }
}

#[near]
impl TradingAccount {
    /// IntentsSwap funding result. Nothing funded -> Refunded (escrow released, spend returned).
    #[private]
    pub fn on_route_funded(&mut self, rid: String, settle: SettleArgs) {
        let mut settle = settle;
        let amount = settle.amount.0;
        let used = match u128_result(128) {
            Err(()) => 0,
            Ok(r) => r.map_or(amount, |u| u.min(amount)),
        };
        // the reserved fee stays counted as spend (it is escrowed, paid on delivery)
        settle.fee = U128(0);
        if let Some(mut r) = load_route(&rid) {
            if used == 0 {
                self.settle_escrow(&rid, &mut r, false);
                // A1: the escrowed fee leaves the daily window (the input came back via finish_settle)
                self.release_route_fee(&rid);
                r.credited = U128(0);
                self.route_done(&rid, r, RouteState::Refunded, "fund_failed");
            } else if used < r.funded.0 {
                // partly funded: 1Click refunds a short deposit into the intents balance (INTENTS
                // refund) -> the continuation's refund pull recovers it
                r.funded = U128(used);
                let _ = save_route(&rid, &r);
            }
        }
        self.finish_settle(settle, used == 0, used, 0);
    }

    /// V16-07: a refund pull runs only when the route's delivery token is absent from this
    /// account's intents balance (below the route's q_min). Else refused: the route is unchanged.
    #[private]
    pub fn on_cont_refund_check(&mut self, rid: String, pull: IntentsPull) {
        let Some(mut r) = load_route(&rid) else { return };
        let bal = match env::promise_result_checked(0, 64) {
            Ok(b) => near_sdk::serde_json::from_slice::<U128>(&b).ok().map(|x| x.0),
            Err(_) => None,
        };
        if bal.is_none_or(|b| b >= r.q_min.0) {
            r.pending = false;
            let _ = save_route(&rid, &r);
            route_event(
                "route_refund_refused",
                &format!(
                    "{{\"id\":{},\"delivered\":\"{}\"}}",
                    crate::jstr(&rid),
                    bal.map_or("unknown".to_string(), |b| b.to_string())
                ),
            );
            return;
        }
        self.pull_then(&rid, &pull, None, GAS_CHAIN_CB);
    }

    /// Continuation: the pull's result.
    #[private]
    pub fn on_cont_pulled(&mut self, rid: String, pull: IntentsPull, swap: Option<ChainLeg>) {
        let Some(mut r) = load_route(&rid) else { return };
        // V16-06: intents.near's ft_withdraw reports a failed token transfer as a SUCCESSFUL "0"
        // (refunded inside intents): what arrived is the returned amount; 0 = not delivered
        let pulled = match env::promise_result_checked(0, 64) {
            Ok(b) => near_sdk::serde_json::from_slice::<U128>(&b).map_or(0, |x| x.0.min(pull.amount.0)),
            Err(_) => 0,
        };
        if pulled == 0 {
            // not arrived yet / intents paused: the route is unchanged, retry later
            r.pending = false;
            let _ = save_route(&rid, &r);
            unlock(r.q.as_str(), &rid);
            route_event(
                "route_pull_failed",
                &format!("{{\"id\":{},\"token\":\"{}\"}}", crate::jstr(&rid), pull.token),
            );
            return;
        }
        let amount = pulled;
        route_event(
            "route_pulled",
            &format!("{{\"id\":{},\"token\":\"{}\",\"amount\":\"{amount}\"}}", crate::jstr(&rid), pull.token),
        );
        r.credited = U128(r.credited.0.saturating_add(amount));
        if pull.token == r.origin && r.kind == RouteKind::IntentsBuy {
            // V16-07: fee and spend released pro rata to what actually came back
            self.settle_escrow_refund(&rid, &mut r, amount);
            // A1: a proven refund returns its spend (fee + input pro rata) to the daily window
            self.release_route_spend(&rid, amount);
            return self.route_done(&rid, r, RouteState::Refunded, "refund");
        }
        match r.kind {
            RouteKind::IntentsSell if pull.token == r.origin => {
                return self.route_done(&rid, r, RouteState::Refunded, "refund");
            }
            RouteKind::IntentsSell => {
                // the NEAR leg: fee on the wNEAR pulled
                let fee = bps(amount, self.fee.fee_bps);
                self.pay_fee(&rid, fee);
                return self.route_done(&rid, r, RouteState::Done, "pulled");
            }
            _ => {}
        }
        // buy: delivery proven -> the escrowed fee is earned
        self.settle_escrow(&rid, &mut r, true);
        let q = r.q.clone();
        match swap {
            None => {
                unlock(q.as_str(), &rid);
                self.route_done(&rid, r, RouteState::Held, "deadline");
            }
            Some(leg) => {
                r.state = RouteState::Pulled;
                let _ = save_route(&rid, &r);
                let idx = self.leg_promise(&leg, amount, &q, &rid);
                let args =
                    near_sdk::serde_json::json!({"rid": rid, "amount": U128(amount), "leg": leg}).to_string();
                then_self(idx, "on_cont_swapped", &args, GAS_CHAIN_CB);
            }
        }
    }

    /// Continuation: leg 2's result -> Done, or Held (Q stays, per route).
    #[private]
    pub fn on_cont_swapped(&mut self, rid: String, amount: U128, leg: ChainLeg) {
        let Some(mut r) = load_route(&rid) else { return };
        let used = match u128_result(128) {
            Err(()) => 0,
            Ok(x) => self.leg_used(&leg, amount.0, x),
        };
        unlock(r.q.as_str(), &rid);
        r.spent = U128(r.spent.0.saturating_add(used));
        r.state = RouteState::Funded; // route_done sets the final state
        if used < amount.0 {
            self.route_done(&rid, r, RouteState::Held, "leg2_failed");
        } else {
            self.route_done(&rid, r, RouteState::Done, "swapped");
        }
    }

    /// v1.6 views (routing C.4).
    pub fn get_route(&self, id: String) -> Option<Route> {
        // INDEP-5: an unlisted pre-9a0dd084 record reads as absent; a listed one fails closed
        super::store::load_route_by_id(&id)
    }

    pub fn get_routes(&self) -> Vec<(String, Route)> {
        route_index().into_iter().filter_map(|id| load_route(&id).map(|r| (id, r))).collect()
    }

    pub fn get_q_lock(&self, q: AccountId) -> Option<(String, U64)> {
        lock_of(q.as_str()).map(|(h, e)| (h, U64(e)))
    }

    pub fn get_order_via(&self, order_id: U64) -> Option<OrderVia> {
        load_via(order_id.0)
    }
}
