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
| `docs/diagrams/` | trust-zone and deployment views — reproducible source plus rendered artifacts |
| `reference/broker/` | the broker: assertion verification, vault exchange, SPA login interception, synthetic tokens |
| `reference/deploy/` | manifests and scripts for the zone simulation, incl. the boundary experiment |

Regenerate the static diagrams with:

```bash
plantuml -tsvg docs/diagrams/c0-trustzones.puml
# Graphviz reads the icons as PNG, so regenerate them before the deployment view.
for f in docs/diagrams/icons/*.svg; do
  magick -background none -density 300 "$f" -resize 256x256 "${f%.svg}.png"
done
uv run docs/diagrams/d1-deployment-diagrams.py
```

## Verification posture

Claims in the paper carry provenance markers — measured, verified-from-source,
documented, or explicitly open. Where a control was not proven, it says so.

Two habits are worth stealing regardless of whether you use this pattern:

- **A watchlist proves presence, never absence.** A five-header watchlist reported
  a clean boundary; a full census then found an unsigned identity header on every
  request, which the watchlist had never been told to look for.
- **A prescribed control is not an implemented one.** The paper's §11 requires
  refusing redirects. The reference implementation did not, and the request that
  carries the appliance password is exactly the one a redirect replays — so the
  password reached the redirect target. Nobody argued against the control; it was
  written down and never wired in. It is fixed, with a regression test that
  asserts the redirect target received nothing.
- **Verify a negative against a known positive.** A scan reporting "clean" is
  meaningless unless the same scan has been shown to catch a planted canary. The
  sanitiser in this repo (`sanitize.py`) refuses to report a pass unless its own
  canaries are detected first.
- **A clean working tree is not a clean push.** `sanitize.py` scanned the tree
  and reported PASS while three commits still carried the real vault path — the
  substitution rule had missed it (KV v2 puts `/data/` in the middle of the
  path), the tree was fixed, and the commits that already had it were not. It
  now scans every blob in every commit, and refuses to pass on history it has
  not cleared.
- **A checker must refuse what it cannot read, not skip it.** `sanitize.py` scans
  text. It cannot read a screen recording, where an operator name or a product
  identifier lives in pixels — so it now *fails* on video rather than skipping
  it, and its self-test plants a real `.mp4` to prove that path fires. Skipping
  would have reported PASS on a file it never opened.
- **An index goes stale silently.** Every claim carries an evidence marker, and
  the table defining them is the index to that scheme. `check-markers.py` asserts
  both directions — every marker used is declared, every marker declared is used,
  and the paper's table matches the evaluation's — so adding evidence of a new
  kind fails the check until the table is updated to match.

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
