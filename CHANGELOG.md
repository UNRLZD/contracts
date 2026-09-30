# Changelog

Versions before 1.4.8 are described in `docs/contract-report.md` (one section per version).

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
