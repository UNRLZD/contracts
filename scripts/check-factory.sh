#!/bin/sh
# Read-only factory deploy check (docs/mainnet-runbook.md §2). Fails closed (exit 1) unless ALL of:
#  - the factory account's own code hash == expected factory_code_hash (the audited factory.wasm),
#  - get_config().code_hash == the expected file's account_code_hash (the audited
#    trading_account.wasm build record; v1.4.6: pinned, so passing get_config's own hash can't
#    pass by definition). An <account_code_hash> argument, if given, must ALSO equal it,
#  - admin, wrap, fee_recipient, the exact fee_bps and the exact dex_allowlist (ids + kinds, any
#    order) == expected,
#  - at most ONE RheaDcl entry (init's fixed 50 TGas fits one DCL registration + report callback),
#  - fee_bps <= max_fee_bps, and the factory id is <= 47 chars (else every account name is invalid).
# Usage: RPC=https://rpc.mainnet.near.org ./check-factory.sh <factory> <expected.json> [account_code_hash|-]
#   <expected.json>: the pinned values (required; kept OUTSIDE this published tree, e.g. the
#   monorepo's deploy/contracts/mainnet.expected.json, because it holds this tree's own build
#   hashes). EXPECTED_ADMIN overrides its admin.
# Offline: FACTORY_CONFIG_JSON=<file with get_config output> FACTORY_ACCOUNT_CODE_HASH=<hash> \
#   ./check-factory.sh - <expected.json> [hash]
set -e
fail() { echo "FAIL: $*"; exit 1; }
factory=$1
[ -n "$factory" ] || fail "usage: check-factory.sh <factory> <expected.json> [account_code_hash|-]"
expected=$2
[ -n "$expected" ] || fail "missing <expected.json> (the pinned deploy values)"
account_hash=${3:--}
[ -f "$expected" ] || fail "expected-values file not found: $expected"
if [ -n "$FACTORY_CONFIG_JSON" ]; then
  cfg=$(cat "$FACTORY_CONFIG_JSON") || fail "cannot read $FACTORY_CONFIG_JSON"
  code=${FACTORY_ACCOUNT_CODE_HASH:-}
else
  [ -n "$RPC" ] || fail "set RPC to the network RPC URL"
  fin=${FINALITY:-final}
  q() { curl -sf -H 'content-type: application/json' -d "$1" "$RPC" || fail "RPC request failed"; }
  cfg=$(q "$(printf '{"jsonrpc":"2.0","id":1,"method":"query","params":{"request_type":"call_function","finality":"%s","account_id":"%s","method_name":"get_config","args_base64":"e30="}}' "$fin" "$factory")" |
    python3 -c 'import json,sys; print(bytes(json.load(sys.stdin)["result"]["result"]).decode())') || fail "get_config failed"
  code=$(q "$(printf '{"jsonrpc":"2.0","id":1,"method":"query","params":{"request_type":"view_account","finality":"%s","account_id":"%s"}}' "$fin" "$factory")" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["code_hash"])') || fail "view_account failed"
fi
printf '%s' "$cfg" | FACTORY_ID="$factory" ACCOUNT_HASH="$account_hash" FACTORY_CODE="$code" EXPECTED_FILE="$expected" python3 -c '
import json, os, sys
c = json.load(sys.stdin)
e = json.load(open(os.environ["EXPECTED_FILE"]))
admin = os.environ.get("EXPECTED_ADMIN") or e.get("admin") or ""
problems = []
factory = os.environ.get("FACTORY_ID", "")
if factory != "-" and len(factory) > 47:
    problems.append("factory id %s is %d chars (max 47: 16 hex + \".\" + id must fit 64)" % (factory, len(factory)))
def norm(lst):
    return sorted((d["id"], d["kind"]) for d in lst)
if not admin:
    problems.append("expected admin not set (fill it in the expected file or set EXPECTED_ADMIN)")
elif c.get("admin") != admin:
    problems.append("admin %s != expected %s" % (c.get("admin"), admin))
if c.get("wrap") != e["wrap"]:
    problems.append("wrap %s != expected %s" % (c.get("wrap"), e["wrap"]))
if norm(c["dex_allowlist"]) != norm(e["dex_allowlist"]):
    problems.append("dex_allowlist %s != expected %s" % (norm(c["dex_allowlist"]), norm(e["dex_allowlist"])))
n_dcl = sum(1 for d in c["dex_allowlist"] if d["kind"] == "RheaDcl")
if n_dcl > 1:
    problems.append("%d RheaDcl entries (max 1: GAS_INIT is fixed at 50 TGas)" % n_dcl)
fee = c["fee_config"]
if int(fee["fee_bps"]) > int(e.get("max_fee_bps", 100)):
    problems.append("fee_bps %s > %s" % (fee["fee_bps"], e.get("max_fee_bps", 100)))
# v1.4.6 (RA6-5): the expected fee_bps must be a JSON integer (no "75" / 75.9 coercion)
if type(e.get("fee_bps")) is not int or type(fee.get("fee_bps")) is not int or fee["fee_bps"] != e["fee_bps"]:
    problems.append("fee_bps %s != expected %s" % (fee["fee_bps"], e.get("fee_bps", "(not pinned)")))
if not e.get("fee_recipient") or fee["fee_recipient"] != e["fee_recipient"]:
    problems.append("fee_recipient %s != expected %s" % (fee["fee_recipient"], e.get("fee_recipient") or "(not pinned)"))
pinned = e.get("account_code_hash") or ""
arg = os.environ["ACCOUNT_HASH"]
if not pinned:
    problems.append("account_code_hash not pinned in the expected file (the audited build record)")
elif c.get("code_hash") != pinned:
    problems.append("account code_hash %s != pinned %s" % (c.get("code_hash"), pinned))
if arg != "-" and arg != pinned:
    problems.append("account code_hash argument %s != pinned %s" % (arg, pinned or "(none)"))
if os.environ.get("FACTORY_CODE") != e["factory_code_hash"]:
    problems.append("factory code %s != audited factory.wasm %s" % (os.environ.get("FACTORY_CODE") or "(unknown)", e["factory_code_hash"]))
print("admin:", c.get("admin"), "| wrap:", c.get("wrap"), "| fee_bps:", c["fee_config"]["fee_bps"])
print("allowlist:", ", ".join(d["id"] + "=" + d["kind"] for d in c["dex_allowlist"]))
print("account code_hash:", c.get("code_hash"), "| factory code:", os.environ.get("FACTORY_CODE"))
for p in problems:
    print("FAIL:", p)
sys.exit(1 if problems else 0)
' || exit 1
echo OK
