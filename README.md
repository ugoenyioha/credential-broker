# Brokered credential access across an inspecting trust boundary

A design pattern, and a working reference implementation, for giving a person
per-user access to a device whose credential cannot be per-user — across a
boundary where everything that crosses is recorded.

The paper is in [`docs/credential-broker-pattern.md`](docs/credential-broker-pattern.md).
It was built and deployed against a real network appliance, and the boundary
property was measured rather than asserted. Claims carry markers; where a control
was not proven, it says so.

---

## The problem

Network appliances mostly authenticate with a shared, long-lived, non-expiring
credential. An operator needs to use one. Between the operator and the device
sits a boundary that decrypts and records traffic.

Handing the operator the credential fails on attribution and revocation. Sending
the credential across the boundary fails worse: **a recording of a credential is
not a record of an event, it is an unexpired key held by whoever holds the
recording.** The appliance password does not expire; the recording outlives every
control placed around it.

## The shape of the answer

Split the path at the boundary:

```
operator ──▶ gateway (identity zone) ──▶ [inspecting boundary] ──▶ broker (credential zone) ──▶ appliance
                  │                                                     │
          authenticates the person,                            exchanges that identity for a
          records the session,                                 credential, using the OPERATOR's
          forwards identity ONLY                               token — never its own
```

Two rules do most of the work:

1. **Only expiring, bound, scoped material crosses the boundary.** An assertion
   may cross; a credential may not.
2. **The secret store authorises the operator, not the broker's workload identity.** The broker
   presents the caller's token to the secret store, so the vault sees the person.

The zones are named for the rule they enforce — `identity-zone`, `monitor-zone` and `credential-zone` — rather than for a trust level. A credential appearing in the
identity zone is self-evidently a violation, with no convention to remember.
(§10 of the paper explains why "high/low" was considered and rejected.)

## Why the broker is not a header injector

The obvious implementation injects an `Authorization` header into a proxied
request. For browser-facing targets that cannot work, and the reason is structural:

> A single-page admin UI decides whether it is logged in by reading **its own
> browser storage**. That check happens before any request exists, so an injected
> header is invisible to it and the operator is shown a login form — asking them
> to type the very credential you are concealing.

So the broker *answers* the login instead: it holds one authenticated upstream
session, replies to the SPA's login request with the appliance's own response body
but with the token replaced by an opaque synthetic token, and swaps that token
back on every subsequent request. Neither the password nor the real session token
ever reaches the browser.

This is also why an API gateway is a poor fit for the broker role — see
[`docs/gateway-evaluation.md`](docs/gateway-evaluation.md), which evaluates Kong
and Apigee against the real requirements and concludes that both can *host* this
and neither *provides* it.

## What is here

| Path | Contents |
|---|---|
| `docs/credential-broker-pattern.md` | the pattern, its failure modes, and where it does not help |
| `docs/gateway-evaluation.md` | Kong and Apigee assessed against the real requirement set |
| `docs/` | the published site (GitHub Pages serves from here) |
| `docs/diagrams/` | C4 views, trust zones and a sequence — PlantUML source plus rendered SVG |
| `reference/broker/` | the broker: assertion verification, vault exchange, SPA login interception, synthetic tokens |
| `reference/deploy/` | manifests and scripts for the zone simulation, incl. the boundary experiment |

## Verification posture

Claims in the paper carry provenance markers — measured, verified-from-source,
documented, or explicitly open. Where a control was not proven, it says so.

Two habits are worth stealing regardless of whether you use this pattern:

- **A watchlist proves presence, never absence.** A five-header watchlist reported
  a clean boundary; a full census then found an unsigned identity header on
  115/115 requests that the watchlist had never been told to look for.
- **Verify a negative against a known positive.** A scan reporting "clean" is
  meaningless unless the same scan has been shown to catch a planted canary. The
  sanitiser in this repo (`sanitize.py`) refuses to report a pass unless its own
  canaries are detected first.

## Status and honesty

This is a reference implementation, not a product.

- The broker **verifies the caller's assertion on every request** — signature,
  issuer, audience, expiry — and refuses to start in per-user mode without a key
  set and issuer. That is defence in depth, not a licence to expose it: it must
  still be reachable only from the gateway in front of it, enforced by
  NetworkPolicy.
- One upstream appliance session is shared across operators. Per-operator
  upstream sessions would be a materially harder build.
- Class C targets (SNMP, SSH-only devices) are out of scope. No broker design
  here solves them.
- Identifiers in this repository are documentation placeholders
  (`example.internal`, RFC 5737 addresses). Nothing here is a live endpoint.

## Licence

The broker and deployment material are provided as a reference. The upstream
gateway patches this work depends on were contributed separately to that
project.
