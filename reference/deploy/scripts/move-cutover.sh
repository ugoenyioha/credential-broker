#!/usr/bin/env bash
# =============================================================================
# zone boundary simulation — STEP 2 of the move: CUT OVER
#
#   warpgate/warpgate       -> identity-zone     (broker, identity side)
#   warpgate/switch-portal  -> credential-zone      (exchange service, credential side)
#   monitor                 -> repointed at the real portal
#
# DRY RUN BY DEFAULT. Requires --cut-over to change anything.
#
# SAFETY
#   - Refuses to run without a verified backup from move-backup.sh
#   - Refuses to run unless experiment-boundary.sh has passed (stage 1 first)
#   - The portal is pointed at the STUB, never the live switch
#   - The old PVC is left intact in the warpgate namespace
#   - move-rollback.sh reverses this
#
# EXPECTED TO BREAK, and that is a result, not a bug:
#   The OpenBao Kubernetes-auth role binds
#       bound_service_account_names=warpgate
#       bound_service_account_namespaces=warpgate
#   A portal in credential-zone will NOT satisfy it. The user-token path should still
#   work; the pod-identity fallback should not. Observe before fixing --
#   this is finding 3.4 in a second location.
# =============================================================================
set -uo pipefail

# Overridable — see the note in move-rollback.sh. After a namespace rename the
# live release may sit in a namespace this script no longer names by default, and
# every call would silently address an empty namespace.
#   e.g.  SRC_NS=<old-namespace> ./move-cutover.sh --cut-over
SRC_NS="${SRC_NS:-warpgate}"
IDENTITY_NS="${IDENTITY_NS:-identity-zone}"
CREDENTIAL_NS="${CREDENTIAL_NS:-credential-zone}"
RELEASE=warpgate
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "${HERE}/../../../.." && pwd)"
CHART="${REPO}/charts/warpgate"
VALUES="${REPO}/config/example/"
BACKUP="${HERE}/../backup"
STUB_URL="http://stub-upstream.credential-zone.svc.cluster.local:80"

COMMIT=0; ASSUME_YES=0
for a in "$@"; do
  case "$a" in
    --cut-over) COMMIT=1 ;;
    --yes|-y)   ASSUME_YES=1 ;;
    --dry-run)  COMMIT=0 ;;
    -h|--help)  sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "unknown flag: $a" >&2; exit 2 ;;
  esac
done

step() { printf '\n== %s\n' "$*"; }
say()  { printf '   %s\n' "$*"; }
run()  { if [ "$COMMIT" = 1 ]; then "$@"; else say "[dry-run] $*"; fi; }

# --------------------------------------------------------------------------
step "Preflight"

fatal() { say "REFUSING: $*"; exit 1; }

[ -d "$CHART" ]   || fatal "chart not found at $CHART"
[ -f "$VALUES" ]  || fatal "values not found at $VALUES"

if [ ! -f "$BACKUP/warpgate-data-latest.tar.gz" ]; then
  fatal "no backup found. Run move-backup.sh first."
fi
if ! tar tzf "$BACKUP/warpgate-data-latest.tar.gz" >/dev/null 2>&1; then
  fatal "backup archive is unreadable. Re-run move-backup.sh."
fi
say "backup present and readable"

for ns in "$IDENTITY_NS" "$CREDENTIAL_NS" monitor-zone; do
  kubectl get ns "$ns" >/dev/null 2>&1 || fatal "namespace $ns missing -- run setup.sh"
done
say "simulation namespaces present"

if ! kubectl get deploy monitor -n monitor-zone >/dev/null 2>&1; then
  fatal "monitor not deployed -- run setup.sh"
fi
say "monitor present"

say ""
say "Stage 1 gate: experiment-boundary.sh should be green before cutting over."
if [ "$COMMIT" = 1 ] && [ "$ASSUME_YES" = 0 ]; then
  printf '   Have T1-T4 passed? [y/N] '
  read -r r </dev/tty || true
  [[ "$r" =~ ^[Yy]$ ]] || fatal "run scripts/experiment-boundary.sh first"
elif [ "$COMMIT" = 1 ]; then
  say "--yes given; skipping the T1-T4 confirmation prompt"
fi

LBIP=$(cat "$BACKUP/loadbalancer-ip.txt" 2>/dev/null || true)
say "loadBalancerIP to reclaim: ${LBIP:-<none>}"

# --------------------------------------------------------------------------
step "1/5  Render the portal for credential-zone (pointed at the STUB)"

PORTAL_YAML="$(mktemp)"
helm template "$RELEASE" "$CHART" -f "$VALUES" \
  --namespace "$CREDENTIAL_NS" \
  --set switchPortal.enabled=true \
  --set switchPortal.upstreamUrl="$STUB_URL" \
  --set switchPortal.upstreamInsecureTls="false" \
  --show-only templates/switch-portal.yaml 2>/dev/null > "$PORTAL_YAML" || {
    say "helm template failed"; rm -f "$PORTAL_YAML"; exit 1; }

# Drop the chart's own NetworkPolicy -- 40-networkpolicies.yaml owns the
# boundary now, and two competing ingress rules would union and confuse results.
python3 - "$PORTAL_YAML" <<'PY'
import sys, re
p = sys.argv[1]
docs = open(p).read().split('\n---\n')
keep, dropped = [], []
for d in docs:
    if not d.strip():
        continue
    kind = re.search(r'^kind:\s*(\S+)', d, re.M)
    kind = kind.group(1) if kind else '?'
    if kind == 'NetworkPolicy':
        dropped.append(kind); continue
    # tag for teardown
    d = re.sub(r'(\nmetadata:\n(?:  .*\n)*?  labels:\n)',
               r'\1    zone-sim/ephemeral: "true"\n', d, count=1)
    if 'zone-sim/ephemeral' not in d:
        d = re.sub(r'(\nmetadata:\n)', r'\1  labels:\n    zone-sim/ephemeral: "true"\n',
                   d, count=1)
    keep.append(d)
open(p, 'w').write('\n---\n'.join(keep))
print(f'   kept {len(keep)} object(s); dropped {len(dropped)} NetworkPolicy')
PY

say "objects to be created in $CREDENTIAL_NS:"
grep -E '^(kind|  name):' "$PORTAL_YAML" | paste - - 2>/dev/null | sed 's/^/      /' || true
say "upstream pinned to the stub: $STUB_URL"

# --------------------------------------------------------------------------
step "2/5  Uninstall the live release from $SRC_NS"
say "this releases LB IP ${LBIP:-<none>} and stops the broker"
say "the PVC data-warpgate-0 is NOT deleted and remains the rollback path"
run helm uninstall "$RELEASE" -n "$SRC_NS" --wait

# --------------------------------------------------------------------------
step "3/5  Install the broker into $IDENTITY_NS (portal disabled here)"
HELM_ARGS=(upgrade --install "$RELEASE" "$CHART" -f "$VALUES"
           --namespace "$IDENTITY_NS"
           --set switchPortal.enabled=false
           --wait --timeout 5m)
if [ "$COMMIT" = 1 ]; then
  helm "${HELM_ARGS[@]}" 2>&1 | sed 's/^/      /'
else
  say "[dry-run] helm ${HELM_ARGS[*]}"
  helm template "$RELEASE" "$CHART" -f "$VALUES" --namespace "$IDENTITY_NS" \
    --set switchPortal.enabled=false >/dev/null 2>&1 \
    && say "   renders cleanly"
fi

step "3b/5  Restore the SQLite data into the new PVC"
if [ "$COMMIT" = 1 ]; then
  kubectl scale sts "$RELEASE" -n "$IDENTITY_NS" --replicas=0 >/dev/null
  kubectl wait --for=delete "pod/${RELEASE}-0" -n "$IDENTITY_NS" --timeout=120s >/dev/null 2>&1 || true
  kubectl run zone-sim-restore -n "$IDENTITY_NS" --restart=Never \
    --image=docker.io/library/busybox:1.36 \
    --labels=zone-sim/ephemeral=true \
    --overrides='{"spec":{"securityContext":{"runAsNonRoot":true,"runAsUser":1000,"fsGroup":1000,"seccompProfile":{"type":"RuntimeDefault"}},"containers":[{"name":"helper","image":"docker.io/library/busybox:1.36","securityContext":{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}},"command":["sh","-c","sleep 600"],"volumeMounts":[{"name":"data","mountPath":"/data"}]}],"volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"data-warpgate-0"}}]}}' >/dev/null
  kubectl wait --for=condition=Ready pod/zone-sim-restore -n "$IDENTITY_NS" --timeout=120s >/dev/null
  kubectl exec -i -n "$IDENTITY_NS" zone-sim-restore -- tar xzf - -C /data < "$BACKUP/warpgate-data-latest.tar.gz"
  say "data restored"
  kubectl delete pod zone-sim-restore -n "$IDENTITY_NS" --wait=false >/dev/null 2>&1
  kubectl scale sts "$RELEASE" -n "$IDENTITY_NS" --replicas=1 >/dev/null
  kubectl rollout status sts/"$RELEASE" -n "$IDENTITY_NS" --timeout=5m 2>&1 | sed 's/^/      /'
else
  say "[dry-run] would scale to 0, untar backup into data-warpgate-0, scale to 1"
fi

# --------------------------------------------------------------------------
step "4/5  Install the portal into $CREDENTIAL_NS"
if [ "$COMMIT" = 1 ]; then
  kubectl apply -n "$CREDENTIAL_NS" -f "$PORTAL_YAML" 2>&1 | sed 's/^/      /'
else
  kubectl apply --dry-run=client -n "$CREDENTIAL_NS" -f "$PORTAL_YAML" >/dev/null 2>&1 \
    && say "[dry-run] portal manifests render and validate"
fi

# --------------------------------------------------------------------------
step "5/5  Repoint the monitor at the real portal"
PORTAL_SVC="http://${RELEASE}-switch-portal.${CREDENTIAL_NS}.svc.cluster.local:80"
run kubectl set env deploy/monitor -n monitor-zone "UPSTREAM_URL=$PORTAL_SVC"
say "monitor upstream -> $PORTAL_SVC"

rm -f "$PORTAL_YAML"

# --------------------------------------------------------------------------
step "Result"
if [ "$COMMIT" = 0 ]; then
  cat <<'EOF'
   DRY RUN. Nothing changed.

   To commit:  ./move-cutover.sh --cut-over
   To reverse: ./move-rollback.sh
EOF
  exit 0
fi

kubectl get pods -n "$IDENTITY_NS" --no-headers 2>/dev/null | sed 's/^/   /'
kubectl get pods -n "$CREDENTIAL_NS"  --no-headers 2>/dev/null | sed 's/^/   /'
echo
kubectl get svc -n "$IDENTITY_NS" --no-headers 2>/dev/null | sed 's/^/   /'

cat <<'EOF'

   NOW CHECK, in this order:

   1. Did the LoadBalancer IP come back?
        kubectl get svc warpgate -n identity-zone

   2. Does the OIDC login still work? The WSO2 callback is unchanged, so it
      should -- if the hostname resolves to the reclaimed IP.

   3. Did the OpenBao Kubernetes-auth fallback break? EXPECTED YES.
        kubectl logs -n credential-zone deploy/warpgate-switch-portal | grep -i openbao
      bound_service_account_namespaces=warpgate will not match credential-zone.
      Record it before fixing. That is the finding.

   4. What does the monitor see now?
        kubectl logs -n monitor-zone deploy/monitor --tail=40

   If anything is wrong:  ./move-rollback.sh
EOF
