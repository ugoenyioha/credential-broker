#!/usr/bin/env bash
# =============================================================================
# zone boundary simulation — TEARDOWN
#
# Removes every trace of the simulation:
#   1. All objects labelled zone-sim/ephemeral=true, cluster-wide
#   2. The three simulation namespaces
#   3. The additive OpenBao bound_audiences change, restored from the snapshot
#      taken before it was applied
#
# Idempotent. Safe to run repeatedly, and safe to run if setup half-failed.
#
# It deliberately does NOT touch:
#   - the live `warpgate` namespace
#   - anything in OpenBao except the one role field this simulation changed
#
#   ./teardown.sh              # tear down, prompt before the OpenBao revert
#   ./teardown.sh --yes        # no prompts
#   ./teardown.sh --keep-bao   # leave the OpenBao role alone
#   ./teardown.sh --dry-run    # show what would be removed
# =============================================================================
set -uo pipefail

# If a rig is running under an EARLIER generation of namespace names, add them
# here or pass NAMESPACES — otherwise teardown is a silent no-op against exactly
# the deployment it needs to remove ("namespace absent, skipping" for all three,
# exit 0, rig still running).
#
# Overridable so a SINGLE generation can be cleaned up without destroying a live
# rig running under the current names. Namespaces cannot be renamed in place, so
# a rename leaves an old generation running; scope this to it rather than running
# unscoped, which would remove the new rig too.
#   e.g.  NAMESPACES="old-a old-b" ./teardown.sh --yes --keep-bao
if [ -n "${NAMESPACES:-}" ]; then
  read -r -a NAMESPACES <<< "$NAMESPACES"
else
  NAMESPACES=(identity-zone monitor-zone credential-zone)
fi
LABELS=("zone-sim/ephemeral=true")
LABEL="${LABELS[0]}"   # retained for messages that name a single label
BAO_ADDR="${BAO_ADDR:-https://vault.example.internal}"
BAO_ROLE_PATH="v1/auth/oidc/role/switch-portal"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNAPSHOT="${HERE}/../rollback/openbao-role-switch-portal.before.json"

ASSUME_YES=0; DRY_RUN=0; KEEP_BAO=0
for a in "$@"; do
  case "$a" in
    --yes|-y)   ASSUME_YES=1 ;;
    --dry-run)  DRY_RUN=1 ;;
    --keep-bao) KEEP_BAO=1 ;;
    -h|--help)  sed -n '2,25p' "$0"; exit 0 ;;
    *) echo "unknown flag: $a" >&2; exit 2 ;;
  esac
done

say()  { printf '%s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }
run()  { if [ "$DRY_RUN" = 1 ]; then say "   [dry-run] $*"; else "$@"; fi; }

confirm() {
  [ "$ASSUME_YES" = 1 ] && return 0
  [ "$DRY_RUN" = 1 ] && return 0
  printf '   %s [y/N] ' "$1"
  read -r reply </dev/tty || return 1
  [[ "$reply" =~ ^[Yy]$ ]]
}

# --------------------------------------------------------------------------
step "1/3  Labelled objects (zone-sim/ephemeral=true)"

# Namespaced kinds the simulation actually creates. Enumerated rather than
# using `all` because `all` silently omits NetworkPolicy, ConfigMap, Secret
# and ExternalSecret -- exactly the objects that matter here.
KINDS="deployment,service,configmap,secret,networkpolicy,pod,serviceaccount,externalsecret"

found_any=0
for ns in "${NAMESPACES[@]}"; do
  if ! kubectl get ns "$ns" >/dev/null 2>&1; then
    say "   namespace $ns: absent, skipping"
    continue
  fi
  for lbl in "${LABELS[@]}"; do
    n=$(kubectl get "$KINDS" -n "$ns" -l "$lbl" \
          --no-headers --ignore-not-found 2>/dev/null | wc -l | tr -d ' ')
    [ "$n" = "0" ] && continue
    say "   namespace $ns [$lbl]: $n labelled object(s)"
    found_any=1
    kubectl get "$KINDS" -n "$ns" -l "$lbl" \
      --no-headers --ignore-not-found 2>/dev/null | sed 's/^/      /'
    run kubectl delete "$KINDS" -n "$ns" -l "$lbl" --ignore-not-found --wait=false
  done
done

# Catch anything mislabelled into another namespace.
stray=$(for lbl in "${LABELS[@]}"; do
          kubectl get "$KINDS" -A -l "$lbl" --no-headers --ignore-not-found 2>/dev/null
        done | grep -vE "^(identity-zone|monitor-zone|credential-zone) " || true)
if [ -n "$stray" ]; then
  say "   WARNING: labelled objects outside the simulation namespaces:"
  printf '%s\n' "$stray" | sed 's/^/      /'
  if confirm "Delete these too?"; then
    while read -r ns kind rest; do
      [ -z "$ns" ] && continue
      run kubectl delete "$kind" -n "$ns" --ignore-not-found --wait=false 2>/dev/null
    done <<< "$stray"
  fi
fi
[ "$found_any" = 0 ] && say "   nothing labelled found"

# --------------------------------------------------------------------------
step "2/3  Namespaces"
for ns in "${NAMESPACES[@]}"; do
  if kubectl get ns "$ns" >/dev/null 2>&1; then
    say "   deleting $ns"
    run kubectl delete ns "$ns" --ignore-not-found --wait=false
  else
    say "   $ns: already gone"
  fi
done

# --------------------------------------------------------------------------
step "3/3  OpenBao bound_audiences revert"

if [ "$KEEP_BAO" = 1 ]; then
  say "   --keep-bao given; leaving the role as-is"
elif [ ! -f "$SNAPSHOT" ]; then
  say "   no snapshot at $SNAPSHOT"
  say "   NOT reverting -- refusing to guess the previous value."
  say "   Restore by hand if the simulation added an audience:"
  say "     bound_audiences should contain ONLY the Warpgate client_id"
else
  say "   snapshot found: $(basename "$SNAPSHOT")"
  if confirm "Restore bound_audiences from the snapshot?"; then
    TOKEN="$(security find-generic-password \
              -s example.openbao.root-token \
              -a vault.example.internal -w 2>/dev/null || true)"
    if [ -z "$TOKEN" ]; then
      say "   ERROR: no OpenBao token in Keychain; cannot revert."
      say "   Revert by hand before considering this teardown complete."
    else
      BODY=$(python3 - "$SNAPSHOT" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
keep = ("role_type", "user_claim", "bound_audiences", "bound_claims",
        "token_policies", "token_ttl", "token_max_ttl")
print(json.dumps({k: d[k] for k in keep if k in d}))
PY
)
      if [ "$DRY_RUN" = 1 ]; then
        say "   [dry-run] would POST the snapshot back to $BAO_ROLE_PATH"
      else
        code=$(curl -sk --max-time 15 -X POST \
                 -H "X-Vault-Token: $TOKEN" -d "$BODY" \
                 "$BAO_ADDR/$BAO_ROLE_PATH" -o /dev/null -w '%{http_code}')
        say "   restore status: $code"
        curl -sk --max-time 15 -H "X-Vault-Token: $TOKEN" \
          "$BAO_ADDR/$BAO_ROLE_PATH" 2>/dev/null \
          | python3 -c "import sys,json;print('   bound_audiences now =', json.load(sys.stdin).get('data',{}).get('bound_audiences'))" 2>/dev/null
      fi
      unset TOKEN
    fi
  else
    say "   skipped; the extra audience is still present"
  fi
fi

# --------------------------------------------------------------------------
step "Verification"
left=$(kubectl get "$KINDS" -A -l "$LABEL" --no-headers --ignore-not-found 2>/dev/null | wc -l | tr -d ' ')
ns_left=0
for ns in "${NAMESPACES[@]}"; do kubectl get ns "$ns" >/dev/null 2>&1 && ns_left=$((ns_left+1)); done
say "   labelled objects remaining : $left"
say "   simulation namespaces left : $ns_left  (terminating counts here)"
say "   live warpgate namespace    : $(kubectl get ns warpgate >/dev/null 2>&1 && echo present || echo MISSING)"

if [ "$DRY_RUN" = 1 ]; then
  printf '\nDry run only. Nothing was changed.\n'
elif [ "$left" = "0" ] && [ "$ns_left" = "0" ]; then
  printf '\nTeardown complete.\n'
else
  printf '\nNamespaces may still be Terminating. Re-run to confirm.\n'
fi
