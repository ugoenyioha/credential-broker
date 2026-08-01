#!/usr/bin/env bash
# =============================================================================
# zone boundary simulation — SETUP  (STAGE 1: stub only, live broker untouched)
#
# Brings up the three namespaces, the stubs, the monitor
# gateway and the boundary policies. The monitor points at the STUB, so the
# boundary policies can be validated before the live Warpgate is moved.
#
# This script does NOT touch the live `warpgate` namespace and does NOT move
# anything. The move is a separate, explicit step.
#
#   ./setup.sh            # apply and wait
#   ./setup.sh --dry-run  # render only
# =============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFESTS="${HERE}/../manifests"
DRY_RUN=0
[ "${1:-}" = "--dry-run" ] && DRY_RUN=1

step() { printf '\n== %s\n' "$*"; }
say()  { printf '   %s\n' "$*"; }

step "Preflight"
if ! kubectl get ns warpgate >/dev/null 2>&1; then
  say "WARNING: live warpgate namespace not found. Continuing (stub-only stage)."
else
  say "live warpgate namespace: present and will NOT be modified"
fi
cni=$(kubectl get ds -n kube-system -o name 2>/dev/null | grep -ciE 'cilium|calico' || true)
if [ "$cni" = "0" ]; then
  say "ERROR: no policy-enforcing CNI detected. NetworkPolicy would be decorative."
  say "Refusing to proceed -- the boundary would be unenforced and results meaningless."
  exit 1
fi
say "policy-enforcing CNI detected: NetworkPolicy will be enforced"

step "Applying manifests"
# 20-monitor.yaml hardcodes UPSTREAM_URL to the STUB, because stage 1 validates
# the boundary before the real broker exists. After cutover the monitor points at
# the real portal instead -- and re-running this script silently reverts that.
# The tell is nasty: the portal's logs go quiet and every response becomes a
# 200 of ~145 bytes from the stub, so the chain looks alive while testing nothing.
# Capture it here and restore it at the end rather than relying on anyone
# remembering. Cost ~90 minutes the first time and recurred on the rename.
PREV_UPSTREAM="$(kubectl get deploy monitor -n monitor-zone \
  -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="UPSTREAM_URL")].value}' 2>/dev/null || true)"

# Apply EVERY manifest except opt-in experiment variants, which carry a
# `zone-sim/variant:` label and their own apply/revert instructions.
#
# This used to be an explicit list of numeric prefixes (00,10,20,30,40), which
# silently skipped 50-fqdn-egress.yaml — the only policy permitting egress to the
# IdP. The rig came up looking healthy and every OIDC login hung until TCP
# timeout, because the summary this script prints listed the policies it DID
# apply and nothing named the one it did not. A prefix list re-arms that trap
# every time a file is added, so match broadly and exclude by intent instead.
for f in "$MANIFESTS"/*.yaml; do
  [ -e "$f" ] || continue
  if grep -q 'zone-sim/variant:' "$f" 2>/dev/null; then
    say "   $(basename "$f"): opt-in variant, skipping (apply manually if needed)"
    continue
  fi
  say "$(basename "$f")"
  if [ "$DRY_RUN" = 1 ]; then
    kubectl apply --dry-run=client -f "$f" >/dev/null && say "   rendered OK"
  else
    kubectl apply -f "$f" 2>&1 | sed 's/^/      /'
  fi
done

say ""
say "NOT applied (deliberate, it is the replay knob):"
say "  45-monitor-egress-openbao.yaml"

[ "$DRY_RUN" = 1 ] && { printf '\nDry run only.\n'; exit 0; }

# Restore a post-cutover monitor upstream that this script's own apply reverted.
if [ -n "${PREV_UPSTREAM:-}" ]; then
  NOW_UPSTREAM="$(kubectl get deploy monitor -n monitor-zone \
    -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="UPSTREAM_URL")].value}' 2>/dev/null || true)"
  if [ "$NOW_UPSTREAM" != "$PREV_UPSTREAM" ]; then
    say "   monitor upstream was reverted by the manifest; restoring $PREV_UPSTREAM"
    kubectl set env deploy/monitor -n monitor-zone "UPSTREAM_URL=$PREV_UPSTREAM" >/dev/null 2>&1
  fi
fi

step "Waiting for rollouts"
for d in credential-zone/stub-upstream credential-zone/stub-weak monitor-zone/monitor; do
  ns="${d%%/*}"; name="${d##*/}"
  printf '   %-28s ' "$d"
  if kubectl rollout status "deploy/$name" -n "$ns" --timeout=120s >/dev/null 2>&1; then
    echo "ready"
  else
    echo "NOT READY"
    kubectl get pods -n "$ns" -l "app=$name" --no-headers 2>/dev/null | sed 's/^/      /'
  fi
done

step "State"
kubectl get ns -l zone-sim/ephemeral=true --no-headers 2>/dev/null | sed 's/^/   /'
echo
kubectl get pods -A -l zone-sim/ephemeral=true \
  -o custom-columns='NS:.metadata.namespace,POD:.metadata.name,STATUS:.status.phase' \
  --no-headers 2>/dev/null | sed 's/^/   /'
echo
kubectl get networkpolicy -A -l zone-sim/ephemeral=true \
  -o custom-columns='NS:.metadata.namespace,NAME:.metadata.name' --no-headers 2>/dev/null | sed 's/^/   /'

cat <<'EOF'

Next:
  scripts/experiment-boundary.sh    validate the boundary before risking the broker
  scripts/teardown.sh               remove everything, incl. the OpenBao revert

The monitor currently proxies to the STUB. After the move, repoint it:
  kubectl set env deploy/monitor -n monitor-zone \
    UPSTREAM_URL=http://warpgate-switch-portal.credential-zone.svc.cluster.local:80
EOF
