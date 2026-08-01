# Requirements under review

The architecture under test:

```
| operator -> warpgate (-> idp) |  ->  | monitor |  ->  | switch-portal (-> vault) -> switch |
            IDENTITY SIDE                   BOUNDARY                    CREDENTIAL SIDE
```

A TLS-decrypting **monitor** sits on the boundary. Everything crossing it must be
assumed **read, retained, and replayable** by an adversary who has compromised it.

These are the claims the deployment and the traffic must actually satisfy. Each is
stated so it can be **falsified**.

---

## R1 — The long-lived secret never crosses the boundary

The appliance admin credential MUST NOT appear on any hop that traverses the
monitor, in either direction, at any point in the session lifecycle.

*Falsified by:* the credential appearing in a monitor-observable request or response.

## R2 — Per-user authorisation and attribution

The authorisation decision for fetching the appliance credential MUST be made
against the **human operator's identity**, not the pod's, and the audit record MUST
name the human.

*Falsified by:* the credential being obtainable using only pod/service identity, or
audit records that name only the service account.

## R3 — The operator never holds the real device credential

The operator's browser MUST receive only an opaque, revocable handle. The real
appliance session token MUST NOT reach the client.

*Falsified by:* the real device token appearing in a response to the browser.

## R4 — Exactly one hop crosses the boundary

Only the broker -> exchange-service hop (and its return path) may traverse the
monitor. No other component may reach across.

*Falsified by:* any additional component-to-component path crossing, e.g. the broker
reaching the secret store directly.

## R5 — Bounded and revocable exposure

Anything that does cross MUST be short-lived and revocable. Its compromise MUST NOT
yield an unbounded-lifetime credential.

*Falsified by:* a crossing credential that is redeemable for a non-expiring secret.

## R6 — The boundary is enforced, not assumed

Traffic from the identity side MUST be unable to reach the credential side except through the
monitor, and that MUST be enforced by a control, not by convention or routing luck.

*Falsified by:* any successful high -> low path that bypasses the monitor.

## R7 — Controls resist forgery by an in-cluster adversary

The control that admits traffic to the credential side MUST NOT be satisfiable by an
attacker who can create a workload in the same namespace.

*Falsified by:* a pod with attacker-chosen labels reaching a protected service.

## R8 — Failure is closed

If the credential exchange, the identity check, or the boundary control fails, the
system MUST deny access rather than degrade to an unauthenticated or
unbrokered path.

*Falsified by:* any failure mode that yields device access without a successful
per-user exchange.

---

## Threat model

**In scope**
- The monitor is fully compromised: it reads, retains and replays anything crossing.
- An adversary can create a workload in the credential-side namespace.
- An adversary can observe all traffic on the boundary hop in both directions.

**Out of scope**
- Compromise of the IdP itself.
- Compromise of the secret store itself.
- Node-level or hypervisor compromise (pod NetworkPolicy does not constrain
  `hostNetwork` pods or node-level access — acknowledged gap, not defended here).
- Physical access to the appliance.

## Known deviations, declared up front

These are already known and must NOT be reported as new findings. Reviewers should
instead judge whether they are correctly characterised and whether their
consequences are fully drawn out.

1. **The appliance is a stub.** The real switch is not in the path, deliberately —
   the cluster is cabled through it.
2. **The boundary hop is plain HTTP.** `switch-portal` serves `:8080` with no TLS,
   so the monitor decrypts nothing. The threat model assumes TLS on a hop that does
   not have it.
3. **The IdP and the secret store share one IP** (`192.0.2.10`). WSO2 must be
   identity-side, the vault credential-side; no IP-based control can separate them. Cilium
   `toFQDNs` was tested and does NOT fix it (it is IP-based underneath).
4. **The SSH target path is not brokered.** `warpgate` resolves that credential
   itself via its vault backend, so it is not subject to R1-R5. Only the HTTP path
   is under review here.
5. **OpenBao k8s-auth role** was extended to accept the `credential-zone` namespace. This is
   a simulation accommodation, snapshotted for rollback.
