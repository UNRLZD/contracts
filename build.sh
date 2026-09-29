#!/bin/sh
# Builds all wasm artifacts into contracts/out/ with cargo-near (strips, checks wasm
# features NEAR supports). Usage: ./build.sh
set -e
cd "$(dirname "$0")"
mkdir -p out
b() { # <crate dir> <out name> [extra cargo-near args]
  dir=$1; name=$2; shift 2
  (cd "$dir" && cargo near build non-reproducible-wasm --no-abi --locked "$@" --out-dir ../out/.tmp >/dev/null)
  mv out/.tmp/*.wasm "out/$name.wasm"
}
b trading-account trading_account
b trading-account trading_account_upgrade_test --features upgrade-test
b factory factory
(cd mocks && for m in mock-ft global-deployer mock-plach gas-burner; do (cd $m && cargo near build non-reproducible-wasm --no-abi --locked --out-dir ../../out/.tmp >/dev/null); done)
mv out/.tmp/mock_ft.wasm out/mock_ft.wasm; mv out/.tmp/global_deployer.wasm out/global_deployer.wasm; mv out/.tmp/mock_plach.wasm out/mock_plach.wasm; mv out/.tmp/gas_burner.wasm out/gas_burner.wasm
rmdir out/.tmp 2>/dev/null || true
for f in out/*.wasm; do
  printf '%-40s %8d bytes  sha256(bs58)=%s\n' "$f" "$(wc -c < "$f")" "$(python3 -c "import hashlib,sys;d=hashlib.sha256(open(sys.argv[1],'rb').read()).digest();A='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';n=int.from_bytes(d,'big');s='';
while n: n,r=divmod(n,58); s=A[r]+s
print(s)" "$f")"
done
