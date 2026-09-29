# UNRLZD contracts

NEAR smart contracts for UNRLZD trading accounts.

| Crate | What it is |
|---|---|
| `trading-account/` | A per-user smart account. It is deployed once as a NEP-591 global contract and referenced by code hash. The owner's device keys trade through an allowlisted set of DEXes (Rhea classic, Rhea DCL, Intear/Plach). Policy limits apply: fee cap, max loss, daily withdraw caps, and automation-key budgets. Withdrawals can also go cross-chain through NEAR Intents (1Click). |
| `factory/` | `create_account` creates `<hex16(sha256(owner))>.<factory>` in one batch (CreateAccount, Transfer, UseGlobalContract, AddKey, `init`). If creation fails, it refunds the deposit. |
| `mocks/` | Test-only contracts: `mock-ft`, `global-deployer`, `mock-plach` and `gas-burner`. They are never deployed to mainnet. |
| `tests/` | near-workspaces sandbox tests. `testnet_e2e.rs` is `#[ignore]`d and only runs against testnet. |
| `scripts/check-factory.sh` | A read-only check that a deployed factory matches the audited code and configuration pinned in an expected-values file (published with each release, outside this tree, since it holds this tree's own build hashes). |

Status: **v1.4.7, not yet deployed to mainnet.**

## Build (reproducible)

Requirements: Docker and [cargo-near](https://github.com/near/cargo-near) 0.22.0.

```sh
cd trading-account && cargo near build reproducible-wasm   # -> target/near/trading_account/trading_account.wasm
cd ../factory       && cargo near build reproducible-wasm   # -> target/near/factory/factory.wasm
```

The image is pinned by digest in each crate's `Cargo.toml` (`[package.metadata.near.reproducible_build]`: `sourcescan/cargo-near:0.22.0-rust-1.97.1`). The build runs from a clean checkout of a commit that has been pushed to this repository. It embeds NEP-330 build metadata: this repository URL, the commit and the build command.

Hashes change with any source edit, `cargo fmt` included, because panic locations embed line numbers.

For development builds (not reproducible), run `./build.sh`. It writes every artifact, mocks included, to `out/` and prints sizes and base58 sha256 hashes.

## Test

```sh
cd trading-account && cargo test --lib            # unit and property tests
./build.sh && cd tests && cargo test --tests      # sandbox tests (need out/*.wasm)
cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all --check
```

On the first run, the sandbox tests download the real mainnet `wrap.near` and Rhea wasm into `tests/.cache/`.

## Verify a deployment

1. Build reproducibly (see above) at the tagged release commit. Compute the base58 sha256 of each wasm:
   `python3 -c "import hashlib,sys;d=hashlib.sha256(open(sys.argv[1],'rb').read()).digest();A='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';n=int.from_bytes(d,'big');s=''
   while n: n,r=divmod(n,58);s=A[r]+s
   print(s)" factory.wasm`
2. Compare the factory's hash with the `code_hash` returned by `view_account` on the factory account. Compare the trading account's hash with the global code hash in the factory's `get_config().code_hash`.
3. Run `RPC=https://rpc.mainnet.near.org ./scripts/check-factory.sh <factory> <expected.json> [<trading_account_code_hash>]`, where `<expected.json>` holds the release's pinned values (admin, fee recipient and exact fee, wrap, DEX allowlist, the factory's and the trading account's code hashes). It fails closed unless all of them match.
4. Optional: call `contract_source_metadata` on the factory or on any trading account. It returns the repository link and the commit that the code was built from.

## Audits

Audit reports will be linked here once they are published.

## Security

Please do not open a public issue for a vulnerability. Report it privately through GitHub's **Security → Report a vulnerability** on this repository.

## License

[Business Source License 1.1](LICENSE), with no Additional Use Grant: you may read, audit, build and verify this code against what is on chain, but not run it in production. Each version converts to GPL-2.0-or-later on its Change Date.
