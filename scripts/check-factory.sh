#!/bin/sh
# Read-only factory deploy check (docs/mainnet-runbook.md §2). Fails closed (exit 1) unless ALL of:
#  - the factory account's own code hash == expected factory_code_hash (the audited factory.wasm),
#  - get_config().code_hash == the expected file's account_code_hash (the audited
#    trading_account.wasm build record; v1.4.6: pinned, so passing get_config's own hash can't
#    pass by definition). An <account_code_hash> argument, if given, must ALSO equal it,
#  - admin, wrap, fee_recipient, the exact fee_bps and the exact dex_allowlist (ids + kinds, any
#    order) == expected,
#  - at most TWO RheaDcl entries (the factory 1.3.0 rule),
#  - fee_bps <= max_fee_bps, and the factory id is <= 47 chars (else every account name is invalid).
#  - factory 1.3.0 (get_admin_state): no pending code proposal, no pending admin or verifier, and the code-hash
#    timelock == the expected `code_timelock_ns` (default 86400000000000 = 24 h); the approved
#    signed-upgrade list (get_approved_code_hashes) == [account_code_hash] when the expected file
#    says "signed_code": true, else []. Allowlist kinds may be objects ({"AidolsCurve":"Near"}).
# Usage: RPC=https://rpc.mainnet.near.org ./check-factory.sh <factory> <expected.json> [account_code_hash|-]
#   <expected.json>: the pinned values (required; kept OUTSIDE this published tree, e.g. the
#   monorepo's deploy/contracts/mainnet.expected.json, because it holds this tree's own build
#   hashes). EXPECTED_ADMIN overrides its admin.
# Offline: FACTORY_CONFIG_JSON=<file with get_config output> FACTORY_ACCOUNT_CODE_HASH=<hash> \
#   FACTORY_ADMIN_STATE_JSON=<file> FACTORY_APPROVED_JSON=<file> ./check-factory.sh - <expected.json> [hash]
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
  adm=$(cat "${FACTORY_ADMIN_STATE_JSON:-/dev/null}" 2>/dev/null || true)
  appr=$(cat "${FACTORY_APPROVED_JSON:-/dev/null}" 2>/dev/null || true)
else
  [ -n "$RPC" ] || fail "set RPC to the network RPC URL"
  fin=${FINALITY:-final}
  q() { curl -sf -H 'content-type: application/json' -d "$1" "$RPC" || fail "RPC request failed"; }
  cfg=$(q "$(printf '{"jsonrpc":"2.0","id":1,"method":"query","params":{"request_type":"call_function","finality":"%s","account_id":"%s","method_name":"get_config","args_base64":"e30="}}' "$fin" "$factory")" |
    python3 -c 'import json,sys; print(bytes(json.load(sys.stdin)["result"]["result"]).decode())') || fail "get_config failed"
  code=$(q "$(printf '{"jsonrpc":"2.0","id":1,"method":"query","params":{"request_type":"view_account","finality":"%s","account_id":"%s"}}' "$fin" "$factory")" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["code_hash"])') || fail "view_account failed"
  # 1.3.0 views; an older factory has none (empty = a problem reported below, fail closed)
  view() { curl -sf -H 'content-type: application/json' -d "$(printf '{"jsonrpc":"2.0","id":1,"method":"query","params":{"request_type":"call_function","finality":"%s","account_id":"%s","method_name":"%s","args_base64":"e30="}}' "$fin" "$factory" "$1")" "$RPC" |
    python3 -c 'import json,sys; r=json.load(sys.stdin).get("result") or {}; print(bytes(r["result"]).decode() if "result" in r else "")' 2>/dev/null || true; }
  adm=$(view get_admin_state)
  appr=$(view get_approved_code_hashes)
fi
printf '%s' "$cfg" | ADMIN_STATE="$adm" APPROVED="$appr" FACTORY_ID="$factory" ACCOUNT_HASH="$account_hash" FACTORY_CODE="$code" EXPECTED_FILE="$expected" python3 -c '
import json, os, sys
c = json.load(sys.stdin)
e = json.load(open(os.environ["EXPECTED_FILE"]))
admin = os.environ.get("EXPECTED_ADMIN") or e.get("admin") or ""
problems = []
factory = os.environ.get("FACTORY_ID", "")
if factory != "-" and len(factory) > 47:
    problems.append("factory id %s is %d chars (max 47: 16 hex + \".\" + id must fit 64)" % (factory, len(factory)))
def norm(lst):
    return sorted((d["id"], json.dumps(d["kind"], sort_keys=True)) for d in lst)
if not admin:
    problems.append("expected admin not set (fill it in the expected file or set EXPECTED_ADMIN)")
elif c.get("admin") != admin:
    problems.append("admin %s != expected %s" % (c.get("admin"), admin))
if c.get("wrap") != e["wrap"]:
    problems.append("wrap %s != expected %s" % (c.get("wrap"), e["wrap"]))
if norm(c["dex_allowlist"]) != norm(e["dex_allowlist"]):
    problems.append("dex_allowlist %s != expected %s" % (norm(c["dex_allowlist"]), norm(e["dex_allowlist"])))
n_dcl = sum(1 for d in c["dex_allowlist"] if d["kind"] == "RheaDcl")
if n_dcl > 2:
    problems.append("%d RheaDcl entries (max 2, the factory 1.3.0 rule)" % n_dcl)
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
# factory 1.3.0 admin state (F-20 / code-hash timelock)
try:
    st = json.loads(os.environ.get("ADMIN_STATE") or "null")
except ValueError:
    st = None
if not isinstance(st, dict):
    problems.append("get_admin_state unreadable (not a 1.3.0 factory?)")
else:
    want_tl = str(e.get("code_timelock_ns", "86400000000000"))
    if str(st.get("code_timelock_ns")) != want_tl:
        problems.append("code_timelock_ns %s != expected %s" % (st.get("code_timelock_ns"), want_tl))
    if st.get("pending_code") is not None:
        problems.append("pending code proposal %s" % json.dumps(st.get("pending_code")))
    if st.get("pending_admin") is not None:
        problems.append("pending admin %s" % st.get("pending_admin"))
    # F4 (external audit): a verifier change is a timelocked proposal too
    if st.get("pending_verifier") is not None:
        problems.append("pending verifier %s" % json.dumps(st.get("pending_verifier")))
    # factory 1.3.0 review 2 (d18b5b2f): timelocked allowlist / fee proposals, creation pause,
    # revoked code: all must be absent at deploy
    for k in ("pending_dex_allowlist", "pending_fee_config", "resume_eta_ns", "revoked_code"):
        if k in st and st.get(k) is not None:
            problems.append("%s %s" % (k, json.dumps(st.get(k))))
    if st.get("creation_paused") is True:
        problems.append("creation_paused")
try:
    approved = json.loads(os.environ.get("APPROVED") or "null")
except ValueError:
    approved = None
want_appr = [pinned] if e.get("signed_code") is True and pinned else []
if approved != want_appr:
    problems.append("approved code hashes %s != expected %s" % (json.dumps(approved), json.dumps(want_appr)))
if os.environ.get("FACTORY_CODE") != e["factory_code_hash"]:
    problems.append("factory code %s != audited factory.wasm %s" % (os.environ.get("FACTORY_CODE") or "(unknown)", e["factory_code_hash"]))
print("admin:", c.get("admin"), "| wrap:", c.get("wrap"), "| fee_bps:", c["fee_config"]["fee_bps"])
print("allowlist:", ", ".join(d["id"] + "=" + (d["kind"] if isinstance(d["kind"], str) else json.dumps(d["kind"], sort_keys=True)) for d in c["dex_allowlist"]))
print("account code_hash:", c.get("code_hash"), "| factory code:", os.environ.get("FACTORY_CODE"))
for p in problems:
    print("FAIL:", p)
sys.exit(1 if problems else 0)
' || exit 1
echo OK
