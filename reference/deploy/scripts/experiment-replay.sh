#!/usr/bin/env bash
# =============================================================================
# zone boundary simulation — EXPERIMENT: is the observed token redeemable?
#
# Settles the central claim of docs/zone-architecture.md §04, which is currently
# ANALYSIS: that a monitor observing the ID token can redeem it at OpenBao for
# the appliance credential, and that only network reachability -- not
# cryptography -- prevents it.
#
# METHOD
#   Attempt the redemption FROM THE MONITOR'S NETWORK POSITION, twice:
#
#     A. without 45-monitor-egress-openbao.yaml   expect FAIL  (unreachable)
#     B. with    45-monitor-egress-openbao.yaml   expect OK    (reachable)
#
#   The delta quantifies how much the monitor's PLACEMENT rather than its token
#   handling determines blast radius -- a deployment choice, not an engineering
#   project, and therefore more actionable than the DPoP work.
#
# CREDENTIAL HANDLING
#   Requires a token. It is read from stdin or an env var, never a flag (flags
#   land in shell history and `ps`). It is never echoed and never written to
#   disk. A successful read reports ONLY that a credential was returned and its
#   length -- never its value.
#
#   To obtain one, enable capture on the monitor DELIBERATELY and briefly:
#     kubectl set env deploy/monitor -n monitor-zone CAPTURE_TOKENS=true
#     ... perform one login ...
#     kubectl logs -n monitor-zone deploy/monitor | grep RAW
#     kubectl set env deploy/monitor -n monitor-zone CAPTURE_TOKENS=false
#
#   Usage:
#     ID_TOKEN=... ./experiment-replay.sh
#     ./experiment-replay.sh            # prompts on stdin, no echo
# =============================================================================
set -uo pipefail

# MUST be the hostname, not the IP. The vault and the IdP are co-located on
# 192.0.2.10, so a raw-IP request carries no SNI and lands on the wrong
# vhost, which answers 403 and looks like an auth rejection.
BAO_ADDR="${BAO_ADDR:-https://vault.example.internal}"
BAO_MOUNT="${BAO_MOUNT:-oidc}"
BAO_ROLE="${BAO_ROLE:-switch-portal}"
BAO_PATH="${BAO_PATH:-kv/data/example/appliance/admin}"
NS=monitor-zone
POD=zone-sim-replay
CURL_IMAGE="docker.io/curlimages/curl:8.10.1"

step() { printf '\n== %s\n' "$*"; }
say()  { printf '   %s\n' "$*"; }

trap 'kubectl delete pod "$POD" -n "$NS" --ignore-not-found --wait=false >/dev/null 2>&1' EXIT

step "Preflight"
kubectl get ns "$NS" >/dev/null 2>&1 || { say "run setup.sh first"; exit 1; }

VARIANT=$(kubectl get networkpolicy -n "$NS" \
            -l zone-sim/variant=monitor-can-reach-openbao \
            --no-headers 2>/dev/null | wc -l | tr -d ' ')
if [ "$VARIANT" = "0" ]; then
  say "egress variant: NOT applied -> modelling strict bump-in-the-wire"
  say "EXPECTING: replay blocked by reachability"
  EXPECT=blocked
else
  say "egress variant: APPLIED -> modelling an inline appliance with routing"
  say "EXPECTING: replay succeeds"
  EXPECT=reach
fi

if [ -z "${ID_TOKEN:-}" ]; then
  printf '   paste an observed ID token (input hidden): '
  read -rs ID_TOKEN </dev/tty
  printf '\n'
fi
[ -n "${ID_TOKEN:-}" ] || { say "no token supplied"; exit 2; }
say "token supplied: length ${#ID_TOKEN}"

# Report non-sensitive claims so the operator can confirm which token this is.
python3 - <<PY 2>/dev/null || true
import base64, json
t = """${ID_TOKEN}"""
p = t.split('.')
if len(p) == 3:
    pad = p[1] + '=' * (-len(p[1]) % 4)
    try:
        c = json.loads(base64.urlsafe_b64decode(pad))
        keep = {k: c[k] for k in ('aud','sub','exp','iss','azp') if k in c}
        print('   claims:', json.dumps(keep))
    except Exception:
        print('   claims: <undecodable>')
else:
    print('   claims: not a 3-part JWT (opaque token?)')
PY

step "Attempting redemption from the monitor's network position"

SCRIPT='
set -e
code=$(curl -sk -o /tmp/r.json -w "%{http_code}" --max-time 10 \
  -X POST "$BAO/v1/auth/$MOUNT/login" \
  -d "{\"role\":\"$ROLE\",\"jwt\":\"$JWT\"}" 2>/dev/null || echo 000)
echo "LOGIN_HTTP=$code"
[ "$code" = "200" ] || { echo "LOGIN_FAILED"; exit 0; }
tok=$(sed -n "s/.*\"client_token\":\"\([^\"]*\)\".*/\1/p" /tmp/r.json)
[ -n "$tok" ] || { echo "NO_CLIENT_TOKEN"; exit 0; }
echo "CLIENT_TOKEN_OBTAINED len=${#tok}"
code=$(curl -sk -o /tmp/s.json -w "%{http_code}" --max-time 10 \
  -H "X-Vault-Token: $tok" "$BAO/v1/$SPATH" 2>/dev/null || echo 000)
echo "SECRET_HTTP=$code"
if [ "$code" = "200" ]; then
  n=$(wc -c < /tmp/s.json)
  echo "SECRET_RETURNED bytes=$n"
fi
rm -f /tmp/r.json /tmp/s.json
'

OUT=$(kubectl run "$POD" -n "$NS" --image="$CURL_IMAGE" --restart=Never \
  --labels=zone-sim/ephemeral=true --quiet --rm -i --timeout=90s \
  --env="BAO=$BAO_ADDR" --env="MOUNT=$BAO_MOUNT" --env="ROLE=$BAO_ROLE" \
  --env="SPATH=$BAO_PATH" --env="JWT=$ID_TOKEN" \
  --command -- sh -c "$SCRIPT" 2>/dev/null || echo "POD_BLOCKED")

unset ID_TOKEN
printf '%s\n' "$OUT" | sed 's/^/   /'

step "Result"
if grep -q "SECRET_RETURNED" <<<"$OUT"; then
  GOT=reach
  cat <<'EOF'
   REPLAY SUCCEEDED.

   An observed token was redeemed for the appliance credential from the
   monitor's position. §04 moves from analysis to OBSERVED FACT:
   reachability, not cryptography, is the control.
EOF
elif grep -qE "LOGIN_HTTP=000([^0-9]|$)" <<<"$OUT" || [ "$OUT" = "POD_BLOCKED" ]; then
  GOT=blocked
  say "REPLAY BLOCKED at the network layer -- OpenBao was unreachable."
  say "The token was valid; the position was not. Placement is the control."
else
  GOT=blocked
  say "REPLAY REJECTED by OpenBao (reachable, but auth failed)."
  say "Check the token has not expired, and that bound_claims still match."
fi

if [ "$GOT" = "$EXPECT" ]; then
  printf '\n   Matches the expectation for this policy variant.\n'
else
  printf '\n   UNEXPECTED: expected %s, got %s. Investigate before recording.\n' "$EXPECT" "$GOT"
fi

cat <<'EOF'

   Run the other variant to get the delta:
     kubectl apply  -f ../manifests/45-monitor-egress-openbao.yaml   # enable
     kubectl delete -f ../manifests/45-monitor-egress-openbao.yaml   # disable
EOF
