#!/usr/bin/env bash
# =============================================================================
# zone boundary simulation — REVERSE the move
#
# Puts Warpgate and switch-portal back in the `warpgate` namespace exactly as
# they were, and repoints the monitor at the stub.
#
# Written at the same time as the cutover, deliberately, so rollback is never
# improvised under pressure.
#
# The original PVC `data-warpgate-0` in the warpgate namespace was never
# deleted (volumeClaimTemplate PVCs survive helm uninstall), so in the normal
# case the data is still there and no restore is needed. --restore forces a
# restore from the archive if that PVC was lost.
#
#   ./move-rollback.sh              # dry run
#   ./move-rollback.sh --commit     # do it
#   ./move-rollback.sh --commit --restore
# =============================================================================
set -uo pipefail

# Overridable so the script can act on a rig deployed under an EARLIER generation
# of namespace names. Namespaces cannot be renamed in place, so after a rename the
# live release may sit in namespaces this script no longer names by default —
# in which case every kubectl/helm call silently addresses an empty namespace and
# the rollback reports success while changing nothing.
#   e.g.  IDENTITY_NS=<old-a> CREDENTIAL_NS=<old-b> ./move-rollback.sh --commit
SRC_NS="${SRC_NS:-warpgate}"
IDENTITY_NS="${IDENTITY_NS:-identity-zone}"
CREDENTIAL_NS="${CREDENTIAL_NS:-credential-zone}"
RELEASE="${RELEASE:-warpgate}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "${HERE}/../../../.." && pwd)"
CHART="${REPO}/charts/warpgate"
VALUES="${REPO}/config/example/"
BACKUP="${HERE}/../backup"

COMMIT=0; RESTORE=0
for a in "$@"; do
  case "$a" in
    --commit)  COMMIT=1 ;;
    --restore) RESTORE=1 ;;
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
    *) echo "unknown flag: $a" >&2; exit 2 ;;
  esac
done

step() { printf '\n== %s\n' "$*"; }
say()  { printf '   %s\n' "$*"; }
run()  { if [ "$COMMIT" = 1 ]; then "$@"; else say "[dry-run] $*"; fi; }

step "State"
say "warpgate ns PVC : $(kubectl get pvc data-warpgate-0 -n $SRC_NS --no-headers 2>/dev/null | awk '{print $2}' || echo MISSING)"
say "identity-zone release: $(helm list -n $IDENTITY_NS --no-headers 2>/dev/null | awk '{print $1}' || echo none)"
say "credential-zone portal  : $(kubectl get deploy -n $CREDENTIAL_NS -o name 2>/dev/null | grep -c switch-portal || echo 0)"

if ! kubectl get pvc data-warpgate-0 -n "$SRC_NS" >/dev/null 2>&1; then
  say ""
  say "WARNING: the original PVC is gone. A restore from archive is required."
  RESTORE=1
  [ -f "$BACKUP/warpgate-data-latest.tar.gz" ] || {
    say "FATAL: no archive either. Data cannot be recovered by this script."; exit 1; }
fi

step "1/4  Remove the simulation-side deployments"
run helm uninstall "$RELEASE" -n "$IDENTITY_NS" --wait
run kubectl delete deploy,svc,serviceaccount -n "$CREDENTIAL_NS" \
      -l app.kubernetes.io/component=switch-portal --ignore-not-found --wait=false

step "2/4  Reinstall into $SRC_NS"
if [ "$COMMIT" = 1 ]; then
  helm upgrade --install "$RELEASE" "$CHART" -f "$VALUES" \
    --namespace "$SRC_NS" --wait --timeout 5m 2>&1 | sed 's/^/      /'
else
  say "[dry-run] helm upgrade --install $RELEASE $CHART -f $VALUES -n $SRC_NS"
fi

step "3/4  Data"
if [ "$RESTORE" = 1 ]; then
  if [ "$COMMIT" = 1 ]; then
    kubectl scale sts "$RELEASE" -n "$SRC_NS" --replicas=0 >/dev/null
    kubectl wait --for=delete "pod/${RELEASE}-0" -n "$SRC_NS" --timeout=120s >/dev/null 2>&1 || true
    kubectl run zone-sim-restore -n "$SRC_NS" --restart=Never \
      --image=docker.io/library/busybox:1.36 --labels=zone-sim/ephemeral=true \
      --overrides='{"spec":{"securityContext":{"runAsNonRoot":true,"runAsUser":1000,"fsGroup":1000,"seccompProfile":{"type":"RuntimeDefault"}},"containers":[{"name":"helper","image":"docker.io/library/busybox:1.36","securityContext":{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}},"command":["sh","-c","sleep 600"],"volumeMounts":[{"name":"data","mountPath":"/data"}]}],"volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"data-warpgate-0"}}]}}' >/dev/null
    kubectl wait --for=condition=Ready pod/zone-sim-restore -n "$SRC_NS" --timeout=120s >/dev/null
    kubectl exec -i -n "$SRC_NS" zone-sim-restore -- tar xzf - -C /data < "$BACKUP/warpgate-data-latest.tar.gz"
    kubectl delete pod zone-sim-restore -n "$SRC_NS" --wait=false >/dev/null 2>&1
    kubectl scale sts "$RELEASE" -n "$SRC_NS" --replicas=1 >/dev/null
    kubectl rollout status sts/"$RELEASE" -n "$SRC_NS" --timeout=5m 2>&1 | sed 's/^/      /'
    say "restored from archive"
  else
    say "[dry-run] would restore from archive"
  fi
else
  say "original PVC intact -- no restore needed"
fi

step "4/4  Repoint the monitor back at the stub"
run kubectl set env deploy/monitor -n monitor-zone \
      UPSTREAM_URL=http://stub-upstream.credential-zone.svc.cluster.local:80

step "Result"
if [ "$COMMIT" = 0 ]; then
  printf '   DRY RUN. Nothing changed. Re-run with --commit.\n'
  exit 0
fi
kubectl get pods,svc -n "$SRC_NS" --no-headers 2>/dev/null | sed 's/^/   /'
cat <<'EOF'

   Verify:
     kubectl get svc warpgate -n warpgate      # LB IP reclaimed?
     open https://gateway.example.internal  # login works?

   The simulation namespaces are still up. To remove them:
     ./teardown.sh
EOF
