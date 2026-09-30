# Changelog

Versions before 1.4.8 are described in `docs/contract-report.md` (one section per version).

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
