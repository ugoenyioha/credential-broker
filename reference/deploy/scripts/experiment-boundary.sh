#!/usr/bin/env bash
# =============================================================================
# zone boundary simulation — EXPERIMENT: does the boundary hold?
#
# Four assertions. Runs entirely against stubs; the live broker is not involved.
#
#   T1  high -> low, DIRECT            must FAIL     (bypass is refused)
#   T2  high -> monitor -> low         must SUCCEED  (sanctioned path works)
#   T3  spoofer(app=warpgate) -> weak  must SUCCEED  (podSelector is forgeable)
#   T4  spoofer(app=warpgate) -> strong must FAIL    (namespace is not forgeable)
#
# T3/T4 are the empirical form of finding 3.4: pod labels are mutable by anyone
# with pod-create in the namespace; namespace membership is not. Demonstrated
# here rather than against the live warpgate namespace.
#
#   ./experiment-boundary.sh
# =============================================================================
set -uo pipefail

CURL_IMAGE="docker.io/curlimages/curl:8.10.1"
TIMEOUT=8
PASS=0; FAIL=0

hdr()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
info() { printf '   %s\n' "$*"; }

cleanup() {
  kubectl delete pod -n identity-zone  sim-identity-client --ignore-not-found --wait=false >/dev/null 2>&1
  kubectl delete pod -n credential-zone   sim-spoofer     --ignore-not-found --wait=false >/dev/null 2>&1
}
trap cleanup EXIT

# probe <ns> <podname> <labels> <url>
#   prints an HTTP code on success, "BLOCKED" on a network denial, or
#   "ERROR:<reason>" if the pod never ran.
#
# The last case matters. These namespaces enforce PodSecurity `restricted`, and
# a bare `kubectl run` is rejected at ADMISSION -- the pod never starts. Left
# undetected that looks identical to a network denial, so every
# expect-blocked assertion would pass without testing anything. Hence the
# explicit securityContext, and the distinct ERROR result.
probe() {
  local ns="$1" pod="$2" labels="$3" url="$4"
  local err out rc
  err="$(mktemp)"

  out=$(kubectl run "$pod" -n "$ns" --image="$CURL_IMAGE" --restart=Never \
    --labels="$labels" --quiet --rm -i --timeout=90s \
    --overrides="$(cat <<JSON
{"spec":{"securityContext":{"runAsNonRoot":true,"runAsUser":65532,
"seccompProfile":{"type":"RuntimeDefault"}},
"containers":[{"name":"$pod","image":"$CURL_IMAGE",
"securityContext":{"allowPrivilegeEscalation":false,
"capabilities":{"drop":["ALL"]}},
"command":["curl","-s","-o","/dev/null","-w","%{http_code}",
"--max-time","$TIMEOUT","$url"]}]}}
JSON
)" 2>"$err")
  rc=$?

  if grep -qiE 'forbidden|violates PodSecurity|error from server' "$err"; then
    printf 'ERROR:%s' "$(head -1 "$err" | cut -c1-90)"
    rm -f "$err"; return
  fi
  rm -f "$err"

  # kubectl run --rm -i can emit the container's stdout more than once; take
  # the last 3-digit group rather than concatenating every digit seen.
  out="$(printf '%s' "$out" | grep -oE '[0-9]{3}' | tail -1)"
  if [ -n "$out" ] && [ "$out" != "000" ]; then
    printf '%s' "$out"
  else
    printf 'BLOCKED'
  fi
}

assert() {
  local name="$1" expect="$2" got="$3" why="$4"
  # A pod that never ran is not evidence of anything. Fail regardless of
  # expectation -- otherwise expect-blocked tests pass without testing.
  if [[ "$got" == ERROR:* ]]; then
    printf '   \033[31mVOID\033[0m  %s -- probe never ran\n' "$name"
    printf '         %s\n' "${got#ERROR:}"
    FAIL=$((FAIL+1)); return
  fi
  if [ "$expect" = "reach" ]; then
    if [[ "$got" =~ ^[23] ]]; then
      printf '   \033[32mPASS\033[0m  %s (HTTP %s)\n' "$name" "$got"; PASS=$((PASS+1))
    else
      printf '   \033[31mFAIL\033[0m  %s -- expected to reach, got "%s"\n' "$name" "$got"; FAIL=$((FAIL+1))
    fi
  else
    if [[ "$got" =~ ^[23] ]]; then
      printf '   \033[31mFAIL\033[0m  %s -- expected blocked, but reached (HTTP %s)\n' "$name" "$got"; FAIL=$((FAIL+1))
      printf '         %s\n' "$why"
    else
      printf '   \033[32mPASS\033[0m  %s (blocked)\n' "$name"; PASS=$((PASS+1))
    fi
  fi
}

hdr "Preflight"
for ns in identity-zone monitor-zone credential-zone; do
  kubectl get ns "$ns" >/dev/null 2>&1 || { echo "   missing namespace $ns -- run setup.sh"; exit 1; }
done
info "namespaces present"
kubectl get networkpolicy -A -l zone-sim/ephemeral=true --no-headers 2>/dev/null \
  | awk '{printf "   policy: %s/%s\n", $1, $2}'

# --------------------------------------------------------------------------
hdr "T1  high -> low, DIRECT (expect BLOCKED)"
info "target: stub-upstream.credential-zone:80, bypassing the monitor entirely"
got=$(probe identity-zone sim-identity-client "zone-sim/ephemeral=true,app=sim-client" \
        "http://stub-upstream.credential-zone.svc.cluster.local:80/healthz")
assert "direct high->low bypass" block "$got" \
  "The boundary does not hold. Check identity-egress and low default-deny."
info "note: blocked by BOTH identity-egress and low ingress -- belt and braces"

# --------------------------------------------------------------------------
hdr "T2  high -> monitor -> low (expect REACHABLE)"
info "target: monitor.monitor-zone:8080, which reverse-proxies to the stub"
got=$(probe identity-zone sim-identity-client "zone-sim/ephemeral=true,app=sim-client" \
        "http://monitor.monitor-zone.svc.cluster.local:8080/healthz")
assert "sanctioned path via monitor" reach "$got" ""

# --------------------------------------------------------------------------
hdr "T3  spoofer wearing app=warpgate -> WEAK policy (expect REACHABLE)"
info "a pod in credential-zone relabelled app=warpgate, hitting the podSelector-guarded"
info "service -- this is the deployed control's shape"
got=$(probe credential-zone sim-spoofer "zone-sim/ephemeral=true,app=warpgate" \
        "http://stub-weak.credential-zone.svc.cluster.local:80/healthz")
assert "podSelector is forgeable" reach "$got" ""
info "=> anyone with pod-create in the namespace satisfies this control"

# --------------------------------------------------------------------------
hdr "T4  same spoofer -> STRONG policy (expect BLOCKED)"
info "same forged label, hitting the namespaceSelector-guarded service"
got=$(probe credential-zone sim-spoofer "zone-sim/ephemeral=true,app=warpgate" \
        "http://stub-upstream.credential-zone.svc.cluster.local:80/healthz")
assert "namespaceSelector resists forgery" block "$got" \
  "Unexpected: check that the weak and strong policies target DIFFERENT pods."

# --------------------------------------------------------------------------
hdr "Result"
printf '   passed: %d   failed: %d\n' "$PASS" "$FAIL"
if [ "$FAIL" -eq 0 ]; then
  cat <<'EOF'

   The boundary holds, and the label-spoof finding is reproduced:
   a forged pod label satisfies the DEPLOYED control and fails the
   PROPOSED one. That is the empirical case for namespace-as-anchor.

   Monitor transcript (what a middlebox on this hop can read):
     kubectl logs -n monitor-zone deploy/monitor --tail=40
EOF
else
  printf '\n   Investigate before proceeding to the move.\n'
fi
exit "$FAIL"
