#!/usr/bin/env bash
# =============================================================================
# zone boundary simulation — STEP 1 of the move: BACK UP
#
# Must run before move-cutover.sh. Captures everything needed to reconstruct
# the live Warpgate deployment if the move goes wrong:
#
#   - /data (the SQLite DB: users, roles, targets, known SSH host keys)
#   - the Helm release values and the rendered manifest
#   - the Service's pinned LoadBalancer IP
#
# The DB is copied with the StatefulSet scaled to 0 so SQLite is closed
# cleanly. A hot copy risks a torn read of the WAL. The pod is scaled back up
# afterwards, so the broker is only down for the duration of the copy.
#
# NOTE: the PVC comes from a volumeClaimTemplate, so `helm uninstall` will NOT
# delete it. `data-warpgate-0` survives in the warpgate namespace and is the
# primary rollback path. This archive is the belt to that pair of braces.
# =============================================================================
set -euo pipefail

NS=warpgate
STS=warpgate
PVC=data-warpgate-0
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${HERE}/../backup"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
HELPER=zone-sim-backup-helper

step() { printf '\n== %s\n' "$*"; }
say()  { printf '   %s\n' "$*"; }

mkdir -p "$OUT"

step "Preflight"
kubectl get ns "$NS" >/dev/null 2>&1 || { say "namespace $NS missing -- nothing to back up"; exit 1; }
kubectl get sts "$STS" -n "$NS" >/dev/null 2>&1 || { say "statefulset $STS missing"; exit 1; }
REPLICAS=$(kubectl get sts "$STS" -n "$NS" -o jsonpath='{.spec.replicas}')
say "statefulset replicas: $REPLICAS"

step "Helm release + values"
helm get values "$NS" -n "$NS" -a > "$OUT/helm-values-${STAMP}.yaml" 2>/dev/null \
  && say "values  -> $(basename "$OUT/helm-values-${STAMP}.yaml")"
helm get manifest "$NS" -n "$NS" > "$OUT/helm-manifest-${STAMP}.yaml" 2>/dev/null \
  && say "manifest -> $(basename "$OUT/helm-manifest-${STAMP}.yaml")"
helm list -n "$NS" -o json > "$OUT/helm-release-${STAMP}.json" 2>/dev/null || true

step "Service / LoadBalancer"
kubectl get svc "$STS" -n "$NS" -o json > "$OUT/service-${STAMP}.json"
LBIP=$(kubectl get svc "$STS" -n "$NS" -o jsonpath='{.spec.loadBalancerIP}' 2>/dev/null || true)
say "pinned loadBalancerIP: ${LBIP:-<none>}"
printf '%s\n' "${LBIP:-}" > "$OUT/loadbalancer-ip.txt"

step "Quiescing the broker for a clean SQLite copy"
say "scaling $STS to 0 (broker briefly unavailable)"
kubectl scale sts "$STS" -n "$NS" --replicas=0 >/dev/null
kubectl wait --for=delete "pod/${STS}-0" -n "$NS" --timeout=120s >/dev/null 2>&1 || true
say "pod gone"

cleanup_helper() {
  kubectl delete pod "$HELPER" -n "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
}
restore_scale() {
  say "scaling $STS back to ${REPLICAS:-1}"
  kubectl scale sts "$STS" -n "$NS" --replicas="${REPLICAS:-1}" >/dev/null 2>&1 || true
}
trap 'cleanup_helper; restore_scale' EXIT

step "Copying /data out of $PVC"
kubectl run "$HELPER" -n "$NS" --restart=Never --image=docker.io/library/busybox:1.36 \
  --overrides="$(cat <<JSON
{"spec":{"securityContext":{"runAsNonRoot":true,"runAsUser":1000,"fsGroup":1000,"seccompProfile":{"type":"RuntimeDefault"}},
"containers":[{"name":"helper","image":"docker.io/library/busybox:1.36",
"securityContext":{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}},
"command":["sh","-c","sleep 600"],
"volumeMounts":[{"name":"data","mountPath":"/data"}]}],
"volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"$PVC"}}]}}
JSON
)" >/dev/null

kubectl wait --for=condition=Ready "pod/$HELPER" -n "$NS" --timeout=120s >/dev/null
say "helper pod ready"

ARCHIVE="$OUT/warpgate-data-${STAMP}.tar.gz"
kubectl exec -n "$NS" "$HELPER" -- tar czf - -C /data . > "$ARCHIVE"
SIZE=$(du -h "$ARCHIVE" | cut -f1)
say "archive -> $(basename "$ARCHIVE") ($SIZE)"

say "contents:"
tar tzf "$ARCHIVE" 2>/dev/null | head -10 | sed 's/^/      /'

if ! tar tzf "$ARCHIVE" >/dev/null 2>&1; then
  say "ERROR: archive failed verification. DO NOT PROCEED TO CUTOVER."
  exit 1
fi
say "archive verified readable"

ln -sf "$(basename "$ARCHIVE")" "$OUT/warpgate-data-latest.tar.gz"
say "symlinked as warpgate-data-latest.tar.gz"

step "Done"
cat <<EOF
   Backup complete. The broker is being scaled back up.

   Rollback material now exists in:
     $(cd "$OUT" && pwd)

   Primary rollback remains the PVC itself: helm uninstall does NOT delete
   volumeClaimTemplate PVCs, so $PVC survives in the $NS namespace.

   Next:  scripts/move-cutover.sh --dry-run
EOF
