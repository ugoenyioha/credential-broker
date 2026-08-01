# zone boundary simulation — TEMPORARY

> **This is scaffolding, not infrastructure.** It exists to convert claims in
> `../docs/zone-architecture.md` from analysis into observation. When we have
> what we need, it gets deleted.
>
> **Teardown:** `scripts/teardown.sh`

Every object carries `zone-sim/ephemeral: "true"`. That label is the single
teardown handle. **If you add anything, add the label**, or teardown will leave
it behind.

---

## What it is for

The PoC never deployed the boundary — Warpgate and `switch-portal` ran as pods
in one namespace, so everything the document says about a monitor is reasoning,
not evidence. This rig makes the boundary real enough to test.

| Namespace | Stands in for | Holds |
|---|---|---|
| `identity-zone` | Operator, IdP, broker | token-exchange gateway; later, Warpgate |
| `monitor-zone` | The boundary | mitmproxy + observation addon |
| `credential-zone` | Everything needed to auth to the switch | stubs; later, `switch-portal` |

OpenBao is **not** simulated. It is reached at its real address and treated as
credential-side *by position* — its config does not change with placement, so the
portal→OpenBao hop simply never crosses the monitor.

The switch **is** stubbed, for safety: the cluster is cabled through it.

---

## Staging

Deliberately staged so failures stay attributable and the live broker is risked
last.

**Stage 1 — boundary only (current).** Monitor proxies to the stub. No live
component involved. Validates the policies.

```
scripts/setup.sh
scripts/experiment-boundary.sh
```

**Stage 2 — move the real components.** Warpgate → `identity-zone`,
`switch-portal` → `credential-zone`. The portal is pointed at the **stub**, never the
live switch.

```
scripts/move-backup.sh                 # REQUIRED FIRST. Quiesces, archives /data
scripts/move-cutover.sh --dry-run      # inspect
scripts/move-cutover.sh --cut-over     # commit
scripts/move-rollback.sh --commit      # reverse, if needed
```

`move-cutover.sh` **refuses to run** without a verified backup, and prompts to
confirm T1–T4 passed. It repoints the monitor itself.

Expect the OpenBao Kubernetes-auth fallback to break — the role binds
`bound_service_account_namespaces=warpgate`, which `credential-zone` will not satisfy.
**Record it before fixing.** That is finding 3.4 in a second location.

**Stage 3 — token exchange.** Flip `EXCHANGE_ENABLED=true` on the gateway and
read its logs for the decoded `aud` on both sides of the exchange.

**Stage 4 — replay.** The experiment that moves §04 from analysis to fact.

```
scripts/experiment-replay.sh                                   # variant A: expect blocked
kubectl apply -f manifests/45-monitor-egress-openbao.yaml
scripts/experiment-replay.sh                                   # variant B: expect success
kubectl delete -f manifests/45-monitor-egress-openbao.yaml
```

The token is read from stdin or `ID_TOKEN`, never a flag — flags land in shell
history and `ps`. It is never echoed and never written to disk.

---

## What each experiment settles

| Test | Settles |
|---|---|
| T1 direct high→low | Whether the boundary holds at all |
| T2 via monitor | Whether the sanctioned path works |
| T3 forged label → weak policy | That the **deployed** control is satisfiable by anyone with pod-create |
| T4 forged label → strong policy | That the **proposed** control is not |
| Replay, egress on vs off | How much the monitor's *network placement* — not its token handling — determines blast radius |

T3/T4 are the empirical form of finding 3.4, demonstrated here instead of
against the live `warpgate` namespace.

---

## Live-infrastructure changes

Only one, and teardown reverses it.

| Change | Why | Revert |
|---|---|---|
| `bound_audiences` on OpenBao role `switch-portal` gained `switch-portal` | RFC 8693 exchange produces a downscoped `aud` the original pin would reject. **Additive**, so the live path is unaffected | `scripts/teardown.sh`, from `rollback/openbao-role-switch-portal.before.json` |

Nothing else outside the three namespaces is touched.

---

## Handling notes

**The monitor is the most sensitive pod here.** It can read everything on the
inspected hop. It defaults to `CAPTURE_TOKENS=false` — fingerprints and decoded
non-sensitive claims only, which is enough to prove observability without
creating a credential store. Enabling capture is a deliberate act, needed only
for the replay test. Flows are in memory; **do not add a volume or `-w`**.

**The stubs are credential-blind.** `switch-portal` fetches from real OpenBao,
so the real appliance password reaches the stub switch. It never compares,
echoes, or logs any bytes of it — only `<present len=N>`.

**There is no TLS on the inspected hop.** The portal serves plain HTTP
(`LISTEN_ADDR=":8080"`), so the monitor decrypts nothing. That is itself a
finding the document does not yet carry: the threat model assumes TLS on a hop
that lacks it. Adding TLS is Stage 5, not a prerequisite.

**Residual gap.** Pod NetworkPolicy does not constrain `hostNetwork` pods or
node-level access. Cilium could extend to host policies; deliberately not
enabled. Anything with a node is outside this model.

---

## Files

```
manifests/
  00-namespaces.yaml               three namespaces, ephemeral-labelled
  10-stub-upstream.yaml            stub switch; strong + weak pods
  20-monitor.yaml                  mitmproxy, UPSTREAM_URL env-driven
  30-token-exchange.yaml           RFC 8693 gateway (passthrough by default)
  40-networkpolicies.yaml          the boundary
  45-monitor-egress-openbao.yaml   replay knob — apply deliberately
scripts/
  setup.sh                         stage 1: stubs + monitor + policies
  experiment-boundary.sh           T1-T4, no live component involved
  move-backup.sh                   stage 2a: quiesce + archive /data  (RUN FIRST)
  move-cutover.sh                  stage 2b: --dry-run default, --cut-over commits
  move-rollback.sh                 stage 2c: reverse the move
  experiment-replay.sh             stage 4: is the observed token redeemable?
  teardown.sh                      remove everything + revert OpenBao
rollback/
  openbao-role-switch-portal.before.json
backup/                            created by move-backup.sh (gitignored)
```
