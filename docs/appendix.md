---
layout: default
title: Appendix
---

# The test that found what architecture review missed

A full census of one boundary hop found two live defects that architecture review had not: a
24-hour gateway session cookie and an unsigned identity header, both crossing on every request
observed at the time. **[U]** The same test now reports no credential-bearing material in any
header or cookie across 469 consecutive requests, with payload contents unexamined. **[M]**

This page is how to run that test against any implementation, how to reproduce that result, and
what a pass does and does not prove. It also records the risks the design leaves behind and the
questions still open.

## How the claims are marked

Every claim carries a marker saying how it is known, on one ordered scale.

| Marker | Meaning | Strength |
|---|---|---|
| **[M]** | Measured in the deployed rig against the real appliance | observed |
| **[V]** | Verified from source — the named repository at a pinned commit | read the code |
| **[G]** | Verified from the GitHub API | checked externally |
| **[D]** | Vendor documentation — the ceiling for a closed-source product | vendor's claim |
| **[C]** | Community or practitioner example | weaker than vendor documentation |
| **[A]** | Reasoned but unverified — an architectural consequence, not an observation | argument only |
| **[U]** | Open question, stated as such | not known |

**[M]** and **[V]** are things someone looked at. **[A]** is something someone worked out. A
design argument that reads as convincingly as a measurement is exactly why they are kept apart —
every finding that changed this design came from watching a running system do something nobody
had thought to look for.

## The conformance test

The safety property is measurable, so the measurement can be published — and a published test
runs against implementations you did not write. This is the part worth having even if nobody
ever funds a broker.

1. Place an observer on the boundary hop.
2. Record **every header name** — not a watchlist. Names only, never values.
3. Record cookie **names** within cookie headers. A header staying present says nothing about
   which cookies crossed.
4. Record request and response **body sizes**, and state plainly that contents are unexamined.
5. Drive **controlled probes** — deliberately send the credential you expect to be stripped.
   A chosen input proves more than passive observation.
6. Verify the **response side**.

### What a pass establishes

The observation covers header names, cookie names and body sizes. It can **disprove** the
property conclusively — one credential-bearing header is a failure. It cannot **prove** it,
because a secret inside a body is invisible to it.

State the result as it is: *"no credential-bearing material was observed in any header or
cookie across N requests; payload contents were not examined."* That is a strong claim and a
true one. *"Only tokens cross"* claims more than the evidence supports.

The forgery rejection is asserted by a regression test against a locally generated key pair,
not by a transcript from the deployed rig. **[V]** means source and tests here, not a rig
observation.

### Reproducing our numbers

On a deployment of `reference/deploy`, with the monitor pointed at the broker rather than the
stub, the observer emits one JSON record per request carrying `all_header_names` and, within
`observed`, the `cookie_names` that crossed. Aggregating those records over a run reproduces
the shape of the claim.

Two cautions, which apply to our evidence as much as anyone's. Confirm the monitor's
`UPSTREAM_URL` names the broker, not the stub, or the run observes a chain that is not the one
under test. And read `all_header_names` rather than the watchlist, because the watchlist can
only speak to the headers it was told to watch.

## Which numbers you can re-derive, and which you cannot

The **0 of 469** figure is a property of the current deployment and regenerates on demand. It
is marked **[M]** and the method above reproduces it.

The pre-fix counts — the gateway cookie on 1001 of 1001 requests, the unsigned identity header
on 115 of 115 — are historical. They were observed on a deployment that no longer exists and
no transcript was kept, so a reader cannot re-derive them. They are **[U]**: reported, not
reproducible. The cookie fix itself was contributed upstream to the gateway and is not in this
repository. **[U]**

Publishing a frozen transcript would only evidence the day it was captured. The useful artefact
is a test that can be re-run.

## Residual risks

| Risk | Status |
|---|---|
| Identity visible at the boundary | **[M]** the subject appears in the token. Needs pairwise or pseudonymous subject identifiers at the IdP — outside the broker's control. The subject may be a personal email even for administrative accounts |
| Capability outliving its session | the bound is implemented and observable — **[V]** `mintUntil`, **[M]** both branches (`capability_ttl` and `assertion_expiry`) appear in the deployment's logs. That an unbounded capability **[A]** widens the replay window is the reasoning the bound answers, not something measured |
| Revocation lag | **[V]** logout deliberately leaves the shared target session standing. That a warm session therefore **[A]** outlives revoked authorisation for the remainder of its TTL follows from that, but was not demonstrated |
| Shared target session | **[V]** one upstream session is shared across operators. That this **[A]** dilutes per-user attribution *at the target* is inference — confirming it means reading the appliance's own logs, which was not done |
| Bodies not observed | **[M]** the measurement covers header names, cookie names and body sizes. Payload *contents* are **[U]** |
| Extendable session credentials | **[D]** some platforms let the holder extend a session — on one, from 1,200 s to a 36,000 s ceiling. Treat the ceiling, not the default, as the exposure |
| Destination binding is not least privilege | **[A]** a grant binds credential and destination, not *operation*. If the underlying credential is administrative, so is the capability. Treat each capability as equivalent to the full privilege of the underlying credential unless something in front of the target demonstrably narrows it. Note the ceremony does not: it describes how to *obtain* a session, not what may be done with one |
| Workload-identity fallback exists | **[V]** a machine-identity path remains for callers that cannot present an assertion. Off by default and mutually exclusive with per-user mode — enabling both refuses to start — but an operator who enables it loses the attributability the pattern is for |
| Renewal implemented, firing unobserved | **[M]** capture is verified: a session records a refresh grant and a true expiry. Firing has not been observed, because it is request-driven and both attempts ran against idle sessions |
| A ceremony is still a supply chain | **[A]** the grammar bounds what a contributed login body can *do* — literal text and two substitutions, the credential exactly once, no way to name a destination. **[V]** It does not make review unnecessary. A ceremony pointed at the wrong `LOGIN_PATH`, or naming a field the target treats specially, is a configuration mistake the grammar cannot see, and it arrives through the same channel as a correct one |
| A second path breaks the zone rule | **[M]** see below |

## The contradiction in our own deployment

The zone rule says the identity zone holds *assertions only — never a credential*. In the
deployment measured here, that is true of the broker path and false of the deployment as a
whole.

The gateway also offers SSH to the same appliance, and for that it resolves the credential
through its own vault integration: the secret is fetched **to** the identity side, by a route
the monitor never sees. The network policy permitting it is in `reference/deploy/manifests`,
and its own comment calls this the documented contradiction.

Three things follow.

**The rule is a property of a path, not of a namespace.** Putting a workload in a zone does not
make the zone's rule true. The rule holds only where every credential-bearing path has been
moved, and one unmoved path falsifies it. SSH was left in place so the behaviour could be
observed rather than argued about.

**"Out of scope" is the weakest possible answer.** SSH is Class C and no design here serves it.
But a reader inspecting the rig finds an appliance credential on the identity side, and "Class
C is out of scope" explains why the path exists, not why the zone rule reads as unconditional.

**It sharpens what the pattern is worth.** The HTTP path demonstrably keeps the credential on
the far side. The SSH path beside it demonstrably does not. That contrast is the clearest
statement of both the value and the limit: this is a property of traffic that has been brought
inside the pattern, not of the estate.

## Operations

Rotation is at least four different problems wearing one word. **[D]**

| Shape | Consequence |
|---|---|
| Cascading — changing the password invalidates derived keys | rotation is an outage unless sequenced |
| Independent — session credentials expire alone | cheap |
| Manual-only — permanent keys | needs a human process |
| Per-device localised keys | rotation is fan-out, not a write |

**Renewal does not apply retroactively.** Session state is written once, at establishment.
Sessions created before renewal was deployed cannot acquire it and still expire at the
original lifetime, so during a rollout both behaviours run side by side — which reads as
intermittent rather than as a version boundary. **[A]**

**Availability.** The broker is in-path for every request, not just logins. An outage stops all
work, not merely new sessions. Size it knowing it is on the critical path for the entire estate
behind it.

**Audit.** Record subject, target, capability id, grant, decision, and the reason for a denial.
Attribute from the verified assertion, never from a header.

## Who should build it

If every team builds its own, you get many implementations of uneven quality, no common audit,
and no way to tell which ones hold the property they claim. If one is built and shared, teams
onboard by configuration rather than construction.

The pattern is usually already permitted, because what crosses the boundary in the
authentication path is a token rather than a password. **[A]** The interesting question is not
*may we* but *who owns it*.

There is a third option that costs far less than either and is useful even if nothing is ever
funded: publish the test.

## Still open

- Whether an operation-level grant is expressible without the broker interpreting requests.
  Currently it is not.
- Whether renewal fires as implemented. Capture is verified; firing is not.
- Whether request bodies can be brought inside the measured property without content
  inspection, and what that would cost.
- How to clear material a text scan cannot read. A screen recording of the working system is
  published on the landing page. It carries what no rule in the sanitiser can see: identity and
  product names rendered as pixels. The gate refuses video by default and admits this one by the
  SHA-256 of its reviewed bytes, so re-encoding forces re-review — but the clearing step is a
  human watching frames, and that does not scale.
