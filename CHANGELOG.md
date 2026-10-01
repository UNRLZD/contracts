# Changelog

Versions before 1.4.8 are described in `docs/contract-report.md` (one section per version).

## trading_account 1.6.0 / factory 1.3.0 / owner-auth 1.0.0 (2026-10-01, frozen: universal owner, every launchpad and quote token, NEAR Intents routes; includes the internal audit fixes; external audit to follow)

Spec: `docs/owner-v16-spec.md` (API §6.1). Built on 1.5.0 (every fix above is kept). Factory 1.3.0
(signed creation) is described with the factory.

### Added
- **`contracts/owner-auth` 1.0.0** (new crate, used by the account and the factory). It verifies
  near/intents `MultiPayload`s (pinned `fa44ede9`) with host functions:
  - `erc191`: `ecrecover`, malleability flag on, v ∈ {0,1} checked first;
  - `raw_ed25519` and `nep413`: `ed25519_verify`;
  - `webauthn` P-256: `p256_verify`, plus an explicit low-s check;
  - `webauthn` ed25519: UP **and** UV required, BS⇒BE, `type == "webauthn.get"`,
    challenge = sha256(payload).

  It also covers the salted `VersionedNonce` checks, the used-nonce store, the owner kind/id
  rules and the small-order ed25519 check. The only reason it needs near-sdk `unstable` is
  `ecrecover`.
- **`owner_signed(signed)`**: any caller (the relayer). The check order is spec §4.2:
  1. signatures on and a signer kind;
  2. size and shape;
  3. signature;
  4. key binding (auth key, else the implied key with a kind check);
  5. `signer_id`, `verifying_contract` and deadline (≤ 15 min);
  6. salt, nonce deadline, and nonce not used (32 live, pruned).

  Then up to 4 ops (`upgrade` and `withdraw_all` must be alone) run through the **same bodies**
  as the `owner_*` methods. Event `owner_signed{standard, key, ops, nonce}`.
- **`owner_signed_check`** (view: checks 1–6) and **`get_owner_auth`**.
- New predecessor methods: `owner_withdraw_home`, `owner_set_signed_enabled`,
  `owner_rotate_salt`.
- **Owner kind (`ow`)**:
  - `init(owner_auth: Option<OwnerAuthInit>)`, from factory 1.3.0. A kind must fit the id.
  - `migrate` writes `ow` once by the id rule. Signatures are **off** for named and 64-hex
    owners, on for `0x` owners.
- **Auth keys (cap 4)**: any curve, for signer-kind owners.
  - Refused: duplicates, the owner's implied key, small-order ed25519 keys.
  - `E_LAST_KEY` protects the last usable key.
  - `set_implicit_key(false)` is the "my original key leaked" switch.
- **Home for signer-kind owners** is the owner's intents.near balance.
  - `withdraw_to_owner` and `withdraw_home` send there: `ft_transfer_call{receiver_id:
    intents.near, msg: owner}`; native NEAR is wrapped first and RESERVE is kept.
  - `on_home_sent` reports `owner_withdraw{to: "intents:<owner>", ok, used}`. A refund stays in
    the account.
- **`withdraw_cross_chain(HOME_DEST = u32::MAX)`**: the destination is derived from the owner
  (INTENTS to the owner, the EVM address on a listed EVM asset, or the Solana key on a Solana
  asset), with no activation delay. Every other check is unchanged.
- **Signed `upgrade`** goes only to a hash in the factory's `get_approved_code_hashes()`. The
  upgrade batch ends with a `get_owner_auth` call (old-code guard), so an upgrade to code without
  owner signatures reverts as a whole.
- Venue hook set 1 (curve venues; V's files `venues/*`, `msg_venues.rs`). The 1.6.0 venue scope
  is described in `docs/venues-hooks.md` and completed there.

### Unchanged (spec §11)
- Every `owner_*` method: name, arguments, 1 yocto, events. Its body moved verbatim into a
  shared internal function.
- `DEVICE_METHODS`, `AUTOMATION_METHODS`, every device and relayer method, the named-owner
  `withdraw_to_owner`, the `STATE` layout. New raw keys: `ow`, `un`.

### Owner decisions
- Signed withdraws to any destination are instant: there is no delay path.
- A signed `add_key` is instant, and the op summary names the key.
- R2-05: an owner outflow of a locked token (a Nearrr buy's output token until its settle, or a route's Q) is `E_Q_BUSY` on both doors (`withdraw`, `withdraw_all` as a whole incl. its callback, `withdraw_home`, `withdraw_via_intents`, `rescue`); other tokens and NEAR still move, and a lock expires after 300 blocks (≤ ~5 min).
- R2-09 on the owner doors: `owner_upgrade` and the signed `upgrade` op refuse (`E_IN_FLIGHT`; the signed op's callback logs `upgrade_refused{reason: in_flight}`) on the same in-flight condition the permissionless apply waits on (a Q / Nearrr lock, a swap settle window, a pending order fire or continuation); withdraws and recovery are not gated. The wait is ≤ 100 blocks after the last swap, ≤ 300 blocks (~5 min) after a lock, and until the callback for a pending fire.
- R2-09 has no forever: a continuation whose callback never runs (out of gas, a panic) keeps its route `pending` for good (no re-fire, no clear: its pull may have delivered, so a re-fire or a clear could pull, spend, release the escrowed fee or credit a refund twice), but stops counting as in flight `ROUTE_PENDING_TTL_BLOCKS` (= `LOCK_TTL_BLOCKS`, 300) after the fire. `Route` gains `pending_height` (the fire's block height; also in `get_route`). `pending` only spans the fire's own receipt chain (≈ a dozen receipts); the 1Click windows fall between fires. A pending order fire has no bound: the owner or a device can always `cancel_order` it.

### Fixed (pre-freeze)
- External audit, R2-09 area (`docs/audit/v160-external-r209-delta.md`; PoCs flipped into regression tests, `tests/v160.rs` `ext_audit_routes`, factory `ext_audit_set_verifier_waits_for_the_timelock`):
  - **F1 (Medium) a Funded intents route had no end.** Only a pull within its bounds ended it, and nothing expired it. If its delivery left the intents balance (pulled by `owner_withdraw_from_intents`, or partly taken by a sibling continuation within its slippage band), the route stayed Funded forever: its escrowed fee was held out of every owner NEAR withdraw, the device's `withdraw_from_intents` of wNEAR and Q was refused, and it held one of 16 slots (16 such routes brick IntentsSwap). Now:
    - A Funded, not pending route **expires** at `max(quote deadline, cont deadline) + ROUTE_EXPIRY_GRACE_NS` (24 h). The quote deadline counts at most `ROUTE_QUOTE_SPAN_NS` (24 h) past the continuation deadline, so a route ends at most ~48.5 h after funding.
    - From that instant it reserves nothing and holds no slot (pure reads). The first sweep closes it once: escrowed fee **paid** (conservative; `fee_skipped` under the reserve rule), spend record dropped, `RouteState::Expired` (appended, borsh index 5), it leaves the index, and logs `route_expired{id, q, fee, fee_paid}`.
    - Sweeps run at the start of every owner NEAR outflow door (`send`, `send_home`, both `withdraw_all` callbacks; `owner_hold` itself is a pure read, INDEP-1) and rescue, both `withdraw_from_intents` doors, `rescue`, a continuation fire, and an `execute` while any escrow is held. A later delivery or refund is plain intents balance.
    - A continuation stuck past `ROUTE_PENDING_TTL_BLOCKS` also reserves nothing (it can never fire again). Its escrow and slot stay, as the R2-09 decision keeps it.
    - **Owner guard:** `owner_withdraw_from_intents` and the signed `withdraw_from_intents` op now refuse (`E_Q_BUSY`) a token a live route reserves (its Q, its origin, wNEAR). Before, the owner could be led to pull a delivery that the route's refund check then misread (escrow released, spend returned). Once the route is stuck or expired the owner recovers freely.
    - New view **`get_intents_reserved() -> Vec<AccountId>`**: exactly the set both doors refuse now.
  - **F2 (Low) unreadable route records read as absent.** `chain::store::read` mapped a borsh error to None, so a route in an older layout vanished: no longer in flight (an upgrade went ahead), nothing reserved, its escrow orphaned. Routes, the route index, locks, escrow, continuations and vias now fail closed (`E_STATE`). `migrate` rewrites routes stored before 9a0dd084 (no `pending_height`, written as 0) with `routes_migrated{count}`. It cancels a Chain order whose via predates V16-01 (no leg-1 bound, it can never fire safely) with `order_cancelled`. Mainnet 1.5 accounts hold no route records (routes are new in 1.6).
  - **F3 (Low) the in-flight check was not atomic with the code swap.** The doors checked `in_flight()` in one receipt, and the `UseGlobalContract` batch ran in the next block. A device or relayer transaction in that block (a local receipt, run first) could start a trade whose callbacks then landed on the new code. `migrate` now fails with `E_IN_FLIGHT` under in-flight work. It runs in the same receipt as `UseGlobalContract`, so the whole upgrade (code included) reverts and the owner or keeper retries. Release rule: every later `migrate` keeps this check.
- R2-05 send-time re-check (external audit F-1, High): `run` checked a swap input free only at the execute, but a Chain's leg 1 (`on_chain_start`) and a gated swap (`on_tax_gate`) send that input from a callback, blocks later. A lock taken in between (a Nearrr buy's output token) was not seen, so the token left mid-settle and the buy's fill read as the pad's refund: used 0, no fee, spend back, an order reopened (V16-02 again; also reachable by a relayer firing a stored Chain sell next to a Nearrr buy order). Both callbacks now settle as a failed swap (nothing sent; the Chain also releases Q) when the input is locked, with `q_busy` (+ `tax_gate_refused` on the gated path). `chain::busy` is the non-panicking `assert_free`.
- R2-05 Kelytra deposit (external access/accounting audit, same class as F-1): `CurveClaim{KelytraDeposit}` sends its token (`token.ft_transfer_call` to the exchange) but skipped `assert_free`, so the device could move a Nearrr buy's locked output token mid-settle and fake the refund. Now `E_Q_BUSY` like every other outflow; it is the only claim that sends its token.
- R2-05 gated Chain (external audit F-2, Medium): a gated Chain order fire takes Q's lock only in `on_tax_gate_chain`; Q taken since the execute (another Chain, a Nearrr buy of it) made it panic `E_Q_BUSY`, leaving the order Pending for good with its spend counted. Now refused like the reserve race (`tax_gate_refused`, failed settle, the order reopens).
- A Chain leg or continuation swap on an Aidols-family pad (a buy, or a sell for a non-wNEAR quote) attaches the venue's own `storage_deposit` (10 TGas + an action) on top of the op's `gas`, which `run` budgets (`Plan.gas`) but the Chain's check (rule 6), its step-callback budgets and the continuation's `on_cont_pulled` budget did not: the callback ran out of gas while scheduling (a Chain then held Q locked until expiry with no settle; a continuation stayed `pending` with its pull delivered). Both now budget a curve leg's whole plan plus an action per extra call (`chain::curve_leg_gas`), as `run` does. Clients: add 15 TGas per Aidols-family curve leg to a Chain's gas.
- Curve audit K1 (Low/Medium): a Kelytra sell's fee was `fee_bps × amount_out`, where `amount_out` is `swap_curve`'s own return and "delivered" the exchange's own `resolve_withdraw`; nothing bounded it, so a hostile exchange could make `finish_settle` pay every liquid NEAR above RESERVE as fee. Now `min(fee_bps × amount_out, the reserved fee)` (bps of the min_out bound): a Kelytra sell never charges more than any other sell to NEAR. Tests: `audit_k1_kelytra_sell_fee_is_bounded` (fails before: 9 N paid vs 0.001 N reserved); sandbox `venues_kelytra` fee = bps(min(out, min_out)).
- Curve audit T0 (Low): a token0 buy is exact-out, and on an order fire the FIRING key chose `max_out` (the tokens minted; the unused NEAR is refunded in a successful receipt), so a relayer could fill a sliver of a limit buy and consume it. `place_order` takes an optional JSON `max_out` (same args as `via`; Rust signature and `Order` borsh unchanged; raw key `om` + id, removed with the order; `max_out >= min_out`), view `get_order_max_out(order_id)`. An order fire's CurveBuy (or a Chain order's curve leg 1) must carry exactly the stored value (none stored = none allowed), else `E_ORDER_MISMATCH`. Clients: a token0 buy order stores its `max_out` at placement and every fire sends it unchanged. Tests: `audit_t0_*` (5).
- Curve audit S1 (Info/Low): a Chain counted only leg 1's input as spend, not its plan's extra NEAR (an Aidols-family venue `storage_deposit` 0.0125 N, Vista's 0.00125 N buy extra), which a single-hop curve op counts (`Plan.spend`). `LegInfo.extra_spend` / `ChainPlan.extra_spend` (= `Plan.spend − Plan.counted`) is now counted by `run` (never returned on a refund, like a single-hop op's storage); `counted` is unchanged. A continuation's swap leg is reserve-checked for its native NEAR (`li.native_out`), not 1 yocto. Tests: `audit_s1_chain_counts_the_curve_legs_storage_spend`, `audit_s1_continuation_reserve_checks_the_legs_native_out`.
- Access audit F2 (Low, monitoring): native NEAR through `send(None)` emitted no event: `owner_withdraw(None)`, the signed `withdraw{token: null}`, `owner_withdraw_home` (NEAR-wallet owner) and the device `withdraw_to_owner(None)`. The watcher's `owner_withdraw_volume` alert never counted native NEAR. Each now logs `owner_withdraw{token: "near", amount, to, ok: true}`, as `withdraw_all`'s sweep does. `OwnerOp::summary` (`owner_signed` event, `owner_signed_check`) names outflows: `withdraw <amount> <token|near> to <to>`, `withdraw_home <amount> <token|near>`, `withdraw_via_intents <amount> <token> to <deposit_address>`; the first word is still the op name. Tests: `ext_native_owner_withdraw_emits_owner_withdraw_event`, `ext_signed_outflow_summaries_name_amount_and_destination`. Clients: a summary string is no longer always a bare op name.
- Access audit I1 (Info): `place_order`'s prune of expired orders also removes a Chain order's `ov` record (it stayed stored). Test: `ext_prune_removes_the_chain_order_via`.
- Access audit I2 (Info): removing a device key (non-relayer `remove_key`) reports `device_key_removed{public_key, ok}` from a new `#[private]` callback `on_key_removed` (like `device_key_added`). Test: `ext_device_key_removal_is_reported`. Delta note: `docs/audit/v160-ext-access-delta.md` (I3, a signed `cancel_order` op, is deferred there).
- Independent review of the fixes above, INDEP-1..5 (all Low; `docs/audit/v160-external-r209-delta.md` §Independent review; regression tests `indep*`, each fails before):
  - **INDEP-1** the expiry sweep ran inside `owner_hold()`, evaluated after `liquid_balance()` in `liquid_balance().saturating_sub(self.owner_hold())`, so the fee it paid out was still counted as liquid: an owner NEAR outflow (`send`, `send_home`, `withdraw_all`'s callbacks) could take that much of a live route's escrow (its fee later skipped) or of RESERVE. Every such door now sweeps first; `owner_hold` is a pure read.
  - **INDEP-2** the sweep re-saved each expired route through `save_route`, which re-read every listed route (Held cap): quadratic, 65 TGas of host calls for 16 expired + 32 Held, more than the 25 TGas `on_withdraw_all_report` runs it in. Now one pass: each listed route read once, the index and escrow written once, and the fees it pays sent as ONE transfer (each route still logs `route_expired{fee, fee_paid}`; the reserve rule is applied per route with earlier payments counted out). Measured 7 TGas host for the worst case (test bound 10). `save_route` skips the Held-cap scan unless the saved route is Held.
  - **INDEP-3** `place_order`'s prune left an expired order's stored `max_out` (`om` + id); now removed with it.
  - **INDEP-4** `migrate` cancelled old-via Chain orders before the F3 `in_flight()` check, so a pending fire of such an order did not block the install. The check now runs right after `migrate_routes`, before that cleanup.
  - **INDEP-5** `migrate_routes` rewrites listed routes only; an unlisted (Done / Refunded / unlisted Held) pre-9a0dd084 record stayed undecodable, so `get_route` panicked and `check_route_id` refused its id with `E_STATE`. `route_live` and `get_route` now read an undecodable UNLISTED record as absent (`store::load_route_by_id`); a listed one still fails closed.
  - Off-chain: an expiry sweep's fee is one Transfer to the fee recipient carrying the sum of the `route_expired` events with `fee_paid: true` in that receipt.
- `venues::Plan.gas` documented as what the op declares and `run` budgets (Kelytra / Nearrr buys: the callback chain too; Aidols family: plus its registration). The plan proptest asserted `gas == Σ calls` and failed on valid Kelytra trades (pinned: a sell at exactly 165 TGas); it now checks calls + first callback == `Plan.gas` + GAS_CALLBACK, the declared bound, and a sibling search over a valid trade per pad (20 000 cases each).

### Factory 1.3.0: fixed (pre-freeze)
- **F4 (external audit, Low) `set_verifier` had no timelock and no event.** Code, allowlist, fee and resume all wait for the code timelock, but the verifier switched at once. The verifier is who may call `on_auth` and where every refund goes, so a compromised admin could point it at its own contract and drain every owed refund in the same block with the permissionless `retry_refund`.
  - `set_verifier` now only **proposes** (`verifier_proposed{verifier, eta_ns}`). The proposal takes effect at now + the code timelock (24 h on mainnet), read lazily. The next admin call records it (`verifier_set{verifier}`).
  - New `cancel_verifier()` (admin, 1 yocto, `verifier_cancelled`; `E_NO_PENDING`).
  - `get_admin_state` gains `pending_verifier: {verifier, eta_ns} | null`.
  - A verifier the effective or pending allowlist lists is refused (`E_BAD_ALLOWLIST`), and `set_dex_allowlist` also checks a pending verifier.
  - New raw key `fx`. The one-time bootstrap refuses if it is present.

## trading_account 1.5.0 / factory 1.2.0 (pending: Shards venue; first mainnet deployment)

Interface: `docs/launchpads/shards.md`. Delta self-review: `docs/audit/tob-contracts-v150-shards-delta.md`.
Built on 1.4.9 (every fix above is kept).

### Added
- **`DexKind::ShardsToken`** (account and factory):
  - The allowlist entry names the Shards factory (mainnet: `factory.shardsmarket.near`). The venue
    is any token `<one label>.<factory>`.
  - The factory id itself is never a venue, storage target or order DEX (`dex_kind` skips such
    entries).
  - Factory 1.2.0 only adds the enum variant. The mainnet factory's `new` gets the entry
    (`deploy/contracts/mainnet.expected.json`).
- **`ShardsBuy{token, amount, min_out, gas}`:**
  - Calls `wrap.ft_transfer_call{receiver_id: token, amount, msg}`. The account builds the msg
    itself: `{"v":1,"action":"buy","order_id","min_amount_out","max_total_fee_bps":1100,"deadline_ns"}`.
    There is no caller-supplied field and no recipient, so the token credits the sender, i.e. self.
  - Spend is `amount`. The fee is pro-rata on the wNEAR used, as wrap's resolve reports it; the
    graduation clamp is covered by that.
  - Gas 20–150 TGas.
- **`ShardsSell{token, amount, min_out, gas}`:**
  - Calls `token.sell_exact_in` (20–100 TGas). The token reverts every refusal.
  - Then `on_shards_sold` calls `token.withdraw_quote{amount: credit}` with no `recipient_id`, so
    the payout is native NEAR to self. `on_shards_settled` follows.
  - The fee is `fee_bps × min(credit, NEAR that arrived)`, i.e. on the actual output. It is
    reserved as `bps(min_out)` (for an order, the stored `min_out`, UNR-A-01). An excess above the
    reservation counts as spend at settle.
  - The static gas of the chain is 175 TGas (`GAS_SHARDS_SOLD_CB`).
  - A `withdraw_quote` that fails pays no fee (independent review, Low: fixed), whatever other
    NEAR arrived meanwhile. The credit stays in the token and can be recovered.
- **`ShardsWithdrawQuote{token}`:** a recovery op. `token.withdraw_quote{}` pays the account's own
  stuck credit to self. It is not spend.
- **Orders:** a Shards token may be an order's venue (`dexes = [token]`). Relayer buys and sells
  work as for other venues. A reverted sell or a refunded buy reopens the order.

### Unchanged
- State layout, `migrate`, `DEVICE_METHODS`, `AUTOMATION_METHODS`, the `on_swap_settled` signature
  (its body is now shared as `finish_settle`), and every other op.

### Residual trust (documented)
- A contract cannot read another account's code hash. The client, executor and watcher pin the 4
  Shards template hashes through an independent RPC before every sign and fire, and fail closed.
- Shards' factory keys and the v2.5 upgrade window (until 2026-10-06 16:14 UTC) are accepted venue
  trust. The gap between our check and execution is bounded by one trade's input.

## trading_account 1.4.9 / factory 1.1.1 (pending: fixes for the external fix review of 1.4.8)

Source: `docs/audit/external/fix-review-round/UNRLZD-audit-report.md` (UNR-A-08 … A-13). Delta
self-review: `docs/audit/tob-contracts-v149-delta.md`. The factory is unchanged (1.1.1).

### Fixed
- **UNR-A-08 (lead: Low, refuters and D-1: High; the mainnet blocker):** every key path
  (`execute_order` and every device method) now requires `signer_account_id == current account`
  (`E_NOT_SELF_SIGNED`), in addition to `predecessor == current account`. A NEP-366 Delegate
  action signed by one of the account's keys ran with predecessor == self but with the outer
  transaction's signer and key, so a delegated automation-key fire was read as a device fire. It
  skipped the opt-in weekly allowance, the `allowance / 20` floor, `E_RELAYER_SELL_ONLY` and the
  key's gas allowance, and the watcher's transaction filter could not see it. Every delegated call
  to the account's key paths now fails, whoever submits it. Self-signed device and relayer
  transactions are unchanged.
- **UNR-A-09 (Low, opt-in allowance only):** when a user-chosen `token_in` resolves to `"0"`
  (an honest DEX refusal of a relayer sell), the week gets back everything above the
  `allowance / 20` floor, as for a Failed fire. Before, the order's whole `min_out` stayed
  charged. A lying token still keeps the floor charged on each fire, so it gets at most 20 fires a
  week.
- **UNR-A-10 / A-11 (Low / Info, owner-set daily cap only):** when a relayer fire is reopened
  (Failed, wrap `"0"` or token `"0"`: nothing was swapped), its gas charge goes back to that UTC
  day's gas tally. A leaked automation key looping failing fires can no longer fill the owner's
  daily cap and block the device's trades, stop-loss fires and withdrawals. Fills, device fires
  and refunds for another day stay charged. The gas those loops really burn is still bounded by
  the key's FC allowance (RD8-1).
- `on_swap_settled` takes an optional `relayer_gas` argument. A v1.4.8 callback still in flight
  omits it and deserializes as before (no gas refund).

### Documented, not changed
- **UNR-A-12 (Info):** a hostile `token_in` that reports `"0"` gets its order reopened. The
  correct statement of the A-02 trade-off is: "a re-fill moves only that token's own balance;
  the NEAR cost per re-fill is at most storage + gas". A `"0"` also sets the protocol fee to 0,
  so an issuer whose token reports `"0"` after a real fill avoids the fee on its own orders.
  Limiting relayer `StorageDeposit` to wrap / allowlisted DEXes (RD8-1) needs executor route
  changes, so it is deferred.
- **UNR-A-13 (Info), the exact "no limit" semantics for clients:** the weekly relayer allowance
  is "no limit" **only** when it is absent: never set, set to exactly `u128::MAX`
  (`340282366920938463463374607431768211455`), or `create_account` / `init` without
  `weekly_yocto`. The view `get_relayer_week().allowance_yocto` and the
  `relayer_allowance_set` event fields are then `null`. Any other value, including
  `u128::MAX − 1` and anything ≥ 2^127, is a real allowance with an `allowance / 20` floor
  (≤ 20 fires a week). Clients must send exactly `u128::MAX` (or omit the field) to mean "no
  limit", and must treat only `null` as "no limit". The client-side mappings (`isNoWeeklyLimit`
  ≥ 2^127, the wallet's factory-default text) are off-chain follow-ups, not part of this change.

## trading_account 1.4.8 / factory 1.1.1 (2026-09-30, frozen: includes the fixes for the external audit of 1.4.7; auditors' fix review pending)

Product decision: automated (relayer, 24/7) orders are not limited by default.

### Changed
- **No default weekly relayer allowance** (was 10 NEAR/week). With no allowance set, relayer
  fires (`execute_order` by the automation key) have no weekly accounting, no
  `allowance / 20` floor and no fire count. Every per-fire check stays: the order runs exactly
  as stored (token pair, `amount_in`, DEX set, `min_out`, expiry, once while Pending), output
  goes to self only, the reserve and the DEX allowlist apply, relayer buys use wrap as input
  only, token→token orders stay device-only (`E_RELAYER_SELL_ONLY`), and the automation key
  still can't call device methods.
- **Opt-in allowance:** `owner_set_relayer_allowance(weekly_yocto)` sets a weekly allowance, which
  then works as in 1.4.7 (sells charged `max(min_out, floor)`, buys their whole spend + gas
  bound, at least the floor). `weekly_yocto = u128::MAX` removes the allowance again.
- **RA7-1 fixed (opt-in only):** a provably failed relayer fire keeps the `allowance / 20` floor
  charged (buys: storage + gas or the floor, whichever is larger; sells: the floor), so with an
  allowance there are at most 20 fires a week, failed fires included.
- **Views and events:** `get_relayer_week().allowance_yocto` is `null` when there is no
  allowance. `relayer_allowance_set.old_weekly_yocto` / `new_weekly_yocto` are `null` for
  "no allowance".
- **Factory 1.1.1:** `create_account(..., automation: {public_key, allowance, weekly_yocto?})`:
  `weekly_yocto` omitted (or `u128::MAX`) = no weekly limit. Only doc comments changed in the
  factory code; the behaviour change is in the account's `init`.

### Fixed (external audit of 1.4.7, Engagement A: `docs/audit/external/UNRLZD-audit-report.md`)
- **UNR-A-01 (Medium):** the sell fee of an order fire (relayer or device) is `bps(order.min_out)`,
  the user's stored bound, no longer `bps(msg min_out)`, which the firing key chose (a relayer
  plus a lying token could pay up to liquid − RESERVE in fees).
- **UNR-A-02 (Low):** a user-chosen `token_in` resolving to `"0"` (Successful) reopens the order
  instead of consuming it, so a firing key can no longer delete stop-losses. The relayer week is
  not refunded in that case.
- **UNR-A-03 (Low):** `owner_withdraw_all` phase 2 spends within the native liquid balance
  (registered tokens first). Items that don't fit are reported (`owner_withdraw{ok:false}` +
  new `owner_withdraw_skipped` event), and that much NEAR is kept back so a second call completes.
- **UNR-A-05 (Info):** `PlachWithdraw` / `PlachRegisterAssets` refuse `nep141:<self>` (`E_BAD_OP`).
- **UNR-A-06 (Info):** the owner-path intents markers have their own bound of 512 per 7 days
  (was the shared 128).
- **UNR-A-07 (Info):** the legacy wasm the upgrade tests load are in `tests/fixtures/`
  (+ `SHA256SUMS`), so the sandbox suite runs from a clean checkout.
- UNR-A-04 (Info) is documented, not changed (INV-15 wording; see the delta review §8.2).

### Migration (`owner_upgrade` from 1.4.7)
- No state layout change and no `migrate` change: the allowance is still the raw `ra` key.
- An account that stored an explicit allowance keeps it until the owner changes it.
- An account on the implicit default (no `ra` key, i.e. 10 NEAR/week in 1.4.7) becomes
  unlimited as soon as the new code runs.
- An account that stored `u128::MAX` (possible in 1.4.7, where it meant "20 fires a week",
  RA7-2) becomes unlimited.
- In-flight 1.4.7 fires settle under 1.4.8 as before (a failed 1.4.7 sell still gets its full
  charge back, once).

### Client follow-ups (not in this change)
- `get_relayer_week().allowance_yocto` / `relayer_allowance_set` can be `null`. At the freeze
  the terminal and the wallet read `null` / `u128::MAX` as "no limit"; the engine's `ta-state.ts`
  still keeps the old value on a `null` `new_weekly_yocto`.
- The automation key's gas allowance is now the only on-chain bound on how often a stolen
  relayer key can fire (measured: 174 failing fires on a 0.5 NEAR key at 250 TGas). See
  `docs/audit/tob-contracts-v148-delta.md`.
