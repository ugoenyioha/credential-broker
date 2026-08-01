---
layout: default
title: The pattern
---

# The Credential Broker Pattern

### Letting modern identity reach systems that only understand passwords, across a boundary that reads everything

An engineer needs to change a firewall rule.

The firewall is old in spirit if not in years. It knows exactly one way to decide who you
are: a username and a password, shared by everyone who administers it, written down
somewhere, unchanged since the last audit made someone change it. The engineer, meanwhile,
has a proper corporate identity — single sign-on, multi-factor, a token that expires in an
hour and is useless to anyone else.

Between the engineer and the firewall sits a device that decrypts every connection passing
through it, inspects the contents, and keeps a copy.

Read that sentence again and you will find a password crossing a recorder.

That is the whole problem. Everything below is about what to do with it.

### How to read the claims

Every claim carries a marker saying how it is known. Where a control was not proven, it says
so. That distinction turns out to matter more than any argument in the paper: the findings
that changed the design were not deduced from it — they were things a working system was
doing that nobody had thought to look for, and one thing the design permitted that nobody
had thought to try.

| Marker | Meaning | Strength |
|---|---|---|
| **[M]** | Measured in the deployed rig against the real appliance | observed |
| **[V]** | Verified from source — the named repository at a pinned commit | read the code |
| **[G]** | Verified from the GitHub API | checked externally |
| **[D]** | Vendor documentation — the ceiling for a closed-source product | vendor's claim |
| **[C]** | Community or practitioner example | weaker than vendor documentation |
| **[A]** | Reasoned but unverified — an architectural consequence, not an observation | argument only |
| **[U]** | Open question, stated as such | not known |

The scale is ordered. **[M]** and **[V]** are things someone looked at; **[A]** is something
someone worked out. A design argument that reads as convincingly as a measurement is exactly
the thing this table exists to keep apart. This paper uses **[M]**, **[D]** and **[A]**; the
[gateway evaluation](gateway-evaluation.html) exercises the rest, because assessing a
closed-source product forces the weaker end of the scale into use.

---

# Part I — The problem

## 1. Three reasonable facts, and the problem they make together

**The equipment will not change.** Firewalls, switches, load balancers, storage arrays,
vendor appliances on multi-year support contracts. They authenticate with a shared,
long-lived password because that is what they were built to do, and the vendor's roadmap is
not yours.

**The boundary will not stop recording.** It decrypts and inspects for good reasons, and
those records are retained indefinitely and are not selectively editable after the fact.
This is a control someone fought to get funded. It is doing its job.

**Somebody still has to manage the equipment.** Which means sending it that password.

Put the three together and routine work requires moving a password across something that
keeps a permanent copy of it.

The reflexive objection is that the traffic is encrypted. It is — and then it is decrypted
at the boundary, deliberately, because that inspection *is* the security control. Turning
it off for this traffic is not a fix. It is removing the thing that made the boundary worth
building.

## 2. Why a password is not just a weaker token

It is tempting to file this under "secrets in transit" and move on. That would be a
mistake, because a password and a token behave completely differently once they are sitting
in an archive.

| | A short-lived token | A password |
|---|---|---|
| Lifetime in a recording | useless within minutes | valid until someone rotates it |
| Tied to a person | yes | no — shared |
| Revocable | expires by itself | only by changing it everywhere |

The difference is not one of degree.

> A recording of a token is an artefact. A recording of a password is **an unexpired key,
> held indefinitely, by anyone who can read the archive.**

A token in a capture is a historical record of something that happened. A password in a
capture is a door that is still open, and will stay open until somebody notices and
changes it everywhere it is used — which, for a shared credential on a device with no
inventory of who holds it, is a project rather than a task.

Everything else in this paper follows from that single asymmetry.

## 3. The four answers that do not work

Anyone who has sat with this problem for ten minutes arrives at one of these.

**Give the operator the password.** Now nobody knows who did anything — the device logs a
shared account, not a person — and revoking one engineer's access means rotating a
credential that everything else using it also depends on.

**Put a proxy in front and have it inject the password.** Reasonable, and it is half the
answer. But if the proxy sits on the near side of the boundary, the password still crosses,
and the recording problem is untouched. For browser-facing targets, injection does not work
at all — see §9.

**Exempt this traffic from inspection.** Removes a control that exists for good reasons,
and in most places is simply not permitted. Worth saying out loud so nobody spends a month
on the paperwork.

**Use a jump host.** Better for attribution. The password still lives somewhere a person
can reach, and it still crosses to the device.

## 4. The idea

Split the path at the boundary.

![Trust zones and the material permitted to cross between them](diagrams/c0-trustzones.svg)

The gateway authenticates the person and forwards **only their identity**. On the far side
of the boundary, a broker takes that identity, exchanges it for the device's credential,
and uses the credential entirely on that side. It is never sent back.

What crosses the recorder is a token: short-lived, bound to one person, worthless once it
expires. What the recorder does not see, in the places credentials normally travel, is a
password.

Two rules carry the whole design:

1. **Only expiring, bound, scoped material crosses the boundary.** An assertion may cross.
   A credential may not.
2. **The secret store authorises the operator, not the broker's workload identity.**

The second rule is the one that gets skipped, and it is the one that makes access
attributable. A vault that authenticates the broker's workload identity knows that a
machine asked for a credential. A vault that authenticates the person knows *who* asked.
That is the difference between an audit trail and a log file.

## 5. What this is worth, and what it is not

**It removes the password from the headers and cookies of the boundary's record** — the
places credentials normally travel. That is the difference between an incident and a
non-event. §13 is precise about what that evidence covers and what it does not.

**It makes access attributable.** Today a shared password says an application connected.
This says which person, because the secret store authorised a human.

**It makes revocation mean something**, because the capability the operator holds is
short-lived and individual — not a shared password that must be changed everywhere before
anyone's access actually ends.

**You do not get a guarantee that nothing sensitive ever crosses.** The broker does not
read request bodies and does not restrict what a caller puts in one — whether the caller
does so by accident, by misconfiguration, or deliberately. Against a careless or hostile caller this is a partial
control. Anyone who tells you otherwise has over-sold it.

**It does not cover equipment that cannot speak through the boundary at all.** SNMP, SSH,
anything that is not HTTP. That is a real and separate problem, and no design here solves
it — see Class C in §8.

**It does not hide who is asking.** The boundary still sees the identity and the timing.
Identity is not a secret that expires.

## 6. So who builds it

The pattern is usually already permitted, because what crosses the boundary in the
authentication path is a token rather than a password. **[A]** The interesting question is not *may we* but *who owns it.*

If every team builds its own, you get many implementations of uneven quality, no common
audit, and no way to tell which ones actually hold the property they claim. If one is built
and shared, teams onboard by configuration rather than construction.

Before choosing, settle the question most people ask first: can an API gateway you already
own do this? The assessment is in [gateway evaluation](gateway-evaluation.html); the short
answer is that both products examined can host such a broker and neither supplies the parts
that make it hard.

There is a third option that costs far less than either and is useful even if nothing is
ever funded: **publish the test.** The safety property here is measurable (§13). A
conformance test can be applied to any independent implementation, including ones you did
not build.

On cost, the useful thing to know is what it scales with. **Effort scales with distinct
target types, not target count.** Onboarding the fifth device of a type you already support
is configuration. The first device of a new type is integration. Most estates have five to
fifteen distinct types, which is a very different number from how many devices they have.
**[A]**

---

# Part II — The pattern

## 7. Give out a capability, never a credential

The caller never receives the credential. It receives a **capability** — something that
works for one person, against one destination, for a short time, and is useless anywhere
else.

| Bound to | Meaning |
|---|---|
| **Subject** | the authenticated person, taken from the verified assertion — never from a header or a request field |
| **Destination** | one target, canonicalised as late as the implementation allows — at the moment of connection if it can, at configuration time at minimum (§11) |
| **Expiry** | short, and **not extendable by the holder** |

One rule governs the expiry, and it is easy to get wrong: a capability must not outlive the
assertion that authorised it. Mint for `min(capability_ttl, assertion_remaining)`. A
ten-minute capability issued against an assertion with three minutes left is seven minutes
of authorisation the caller no longer holds.

And the trap that swallows otherwise-good designs:

> **A design where the credential stays put but the caller ends up holding something
> equivalent — a long-lived session key, a non-expiring API key — has moved the problem,
> not solved it.**

### The lifecycle, end to end

```mermaid
sequenceDiagram
    autonumber
    participant OP as Operator
    participant IDP as Identity<br/>Provider
    participant MON as Monitor<br/>(inspecting)
    participant BR as Credential<br/>Broker
    participant SS as Secret<br/>Store
    participant TG as Target

    rect rgb(238, 243, 250)
    Note over OP,IDP: identity zone — assertions only
    OP->>IDP: authenticate
    IDP-->>OP: assertion
    end

    OP->>MON: request + assertion
    Note right of MON: retained indefinitely.<br/>This request contains only the assertion.
    MON->>BR: forwarded

    rect rgb(237, 245, 238)
    Note over BR,TG: credential zone — fetched, used, and kept here
    BR->>BR: verify assertion
    BR->>SS: authorise as THE OPERATOR
    SS-->>BR: target credential
    BR->>TG: native login
    TG-->>BR: target session
    end

    BR-->>MON: capability
    MON-->>OP: capability

    Note over OP,BR: capability — bound to subject, destination, expiry

    loop each subsequent request
        OP->>MON: request + assertion + capability
        MON->>BR: forwarded
        BR->>BR: re-verify assertion and binding
        BR->>TG: request on held session
        TG-->>BR: response
        BR-->>MON: response
        MON-->>OP: response
    end
```

*Steps 1–11 establish: the operator authenticates, only the assertion crosses on the
authentication request, and the broker exchanges it for the credential on the far side.
Steps 12–18 are every request after that. Note step 14 — the assertion is re-verified on
each use, not once at login. §11 explains why that distinction is load-bearing.*

## 8. Classify the target before you design for it

Most of the apparent variety in managed equipment collapses once you ask the right
question. The single most useful thing to know about a device is **what you get back when
you authenticate to it.**

Two questions classify almost anything:

> Does the credential exchange for a session? Is it HTTP?

| Class | Exchange | What you get | Broker behaviour |
|---|---|---|---|
| **A1** | yes | genuinely short-lived session | ideal — broker issues capabilities |
| **A2** | yes | session long-lived **by default** | safe only after the target is reconfigured |
| **B** | none | the credential *is* the bearer token | broker stays in-path for every call |
| **B-conn** | none | authentication binds to the **connection** | dedicated connection per caller |
| **C** | n/a | not HTTP — SNMP, SSH | cannot cross the boundary at all |

### A1 — the common case, and it is genuinely common [D]

Most managed HTTP estate has one shape. A long-lived secret is presented at a login
endpoint and exchanged for a short-lived session credential carried in a header.

| Platform | Exchange | Session credential |
|---|---|---|
| PAN-OS / Panorama | `POST /api/?type=keygen` | API key → `X-PAN-KEY` |
| FortiManager | `sys/login/user` | session ID |
| F5 BIG-IP | `POST /mgmt/shared/authn/login` | token → `X-F5-Auth-Token` |
| Reference target | `PATCH /api/system/login` | session token, target-supplied TTL **[M]** |

Four vendors, one shape. Per-target knowledge reduces to five parameters:

```
login path · request shape · where the session credential goes · TTL · refresh
```

That is why this generalises: a handful of parameters rather than an integration project.

One honest qualification. The reference implementation parameterises four of the five — it
hardcodes the login **request shape**, so a target whose login body differs needs code
rather than configuration. The claim holds for targets sharing a shape and overstates for
the rest. **[V]**

### A2 — the one that will catch you [D]

PAN-OS documents its API key lifetime as **defaulting to `0`: never expires.**

Read that again in the context of the table above. A target that looks like the ideal
case — credential exchanges for a session, session goes in a header — can silently hand
you a permanent credential instead. You have built a capability system on top of something
that never expires.

So classification depends on the target's **configuration**, not just its product.
**Treat A2 as Class B until the lifetime is proven to be set**, and prove it by looking at
a real device. Documentation will tell you the shape; only the device will tell you the
value.

### B — the credential is the token [D]

Some API tokens cannot be exchanged for anything. The secret must be presented on every
request, so the broker stays in-path permanently and can issue no capability at all. Some
vendor predefined keys are explicitly permanent, so the credential the broker handles never
expires on its own at all.

### B-conn — authentication that binds to the connection [D]

NTLM and Negotiate authenticate a **connection**, not a request. Once the handshake
completes, the server stops challenging and treats that connection as authenticated. There
is no artefact to inject into subsequent requests, which means a transparent proxy cannot
work here at all — there is nothing for it to inject.

It also breaks session sharing. RFC 4559 §6 (Security Considerations; the RFC is Informational) says an intermediary *"must
take care to not share authenticated connections between different authenticated clients to
the same server"*. So B-conn
targets need a **dedicated connection per caller**; sharing is not merely inefficient, it
is incorrect. Concurrency at the target then scales with the number of callers, which is a
capacity conversation you want to have early.

### C — honestly outside the pattern [D]

SNMP and SSH are not HTTP and generally cannot traverse an HTTPS-only inspected boundary.
SNMPv2c community strings have no session and no identity — a shared secret in every
packet.

**No broker design solves Class C.** The honest options are relocating that tooling inside
the zone, or building a purpose-built API per application. Say that plainly rather than
letting a diagram imply coverage that does not exist.

**Excluded deliberately:** targets authenticating by TLS client certificate. The
classifying question is not answerable above HTTP, and the credential is not a password.
Named here so its absence is a decision rather than an oversight.

## 9. Two properties that change what you can build

### A single-page admin UI cannot be served by header injection

This one is worth dwelling on, because it looks like an implementation detail and is
actually a boundary on what is possible.

A single-page application decides whether it is logged in by reading **its own browser
storage**. That check happens inside the operator's browser before any request exists. An
injected header is therefore invisible to it — the SPA concludes it is logged out and shows
a login form, asking the operator to type the very credential you are concealing. **[M]**

So for those targets the broker cannot inject. It must *answer* the login: hold an
authenticated upstream session, reply to the login request with the target's own response
body but with the session token replaced by an opaque synthetic one, then swap it back on
every subsequent request. Neither the password nor the real session token ever reaches the
browser. What was measured is that header injection fails; the interception design above is
a response to that finding, not itself a measured result. **[A]**

Machine callers do not need any of this. Browser callers cannot work without it. That is a
line between two kinds of broker, not a wrinkle in one.

```mermaid
sequenceDiagram
    autonumber
    participant B as Browser<br/>(the SPA)
    participant BR as Credential<br/>Broker
    participant TG as Appliance

    Note over B,TG: the SPA has already decided it is logged out —<br/>it read its own storage before any request existed

    B->>BR: GET / (the app document)
    BR->>TG: GET /
    TG-->>BR: HTML
    BR->>BR: inject session bootstrap
    BR-->>B: HTML + bootstrap

    rect rgb(237, 245, 238)
    Note over BR,TG: the broker answers the login rather than forwarding it
    B->>BR: PATCH /login
    BR->>BR: discard what was submitted
    BR->>TG: PATCH /login with the fetched credential
    TG-->>BR: token = REAL
    BR->>BR: keep REAL, mint SYNTHETIC
    BR-->>B: the appliance's own body,<br/>token replaced by SYNTHETIC
    end

    Note over B,BR: the browser holds a handle that is<br/>meaningless anywhere else

    loop every subsequent request
        B->>BR: request + SYNTHETIC
        BR->>BR: swap SYNTHETIC for REAL
        BR->>TG: request + REAL
        TG-->>BR: response
        BR-->>B: response
    end
```

*Read steps 7–11 together. The broker discards the browser's submitted login material,
performs its own upstream login, and replaces the appliance's real token before replying.
Neither the password nor the session it unlocks reaches the browser. That is why a
transparent proxy cannot serve this class of target: there is no point in the flow where
injecting a header would have helped.*

### Where the vault sits matters as much as where the broker sits

Moving the broker to the far side of the boundary feels like the whole job. It is not.

If the broker then reaches back across the boundary to fetch the credential, the secret
crosses in the other direction and the recording problem returns unchanged. The vault must
be reachable from the broker **without traversing the boundary.**

This is easy to miss precisely because "the broker has moved" reads as sufficient.

## 10. Name the zones for the rule, not the trust level

| Zone | Contains | Rule |
|---|---|---|
| **identity zone** | operator, IdP, gateway | assertions only — never a credential |
| **monitor zone** | the inspecting middlebox | everything visible here is retained; assume disclosure |
| **credential zone** | vault, broker, target | credentials live here and stay here |

Named this way, a credential appearing in the identity zone is self-evidently a violation.
Nobody has to remember which side is privileged.

The monitor zone earns its place on that list. It is not scenery — it is the reason the
pattern exists, and naming it keeps *"what is visible at the boundary?"* a structural
question rather than an afterthought.

![Reference deployment showing Kubernetes namespaces, workloads, and external peers](diagrams/d1-deployment-diagrams.png)

*The reference rig as actually built. The zones above are a trust model; the namespaces here
are the thing that enforces it, and the two are not the same object — the identity provider,
secret store and appliance sit in a zone but outside the cluster, so they appear as peers
rather than workloads. Two details are the rig rather than the pattern: the inspected hop is
plain HTTP, because the broker has no serving certificate, and the monitor holds flows in
memory only. Both are deliberate, and §14's measurements were taken under exactly these
conditions. The policies are the boundary: they are what stops traffic when a workload lands
in the wrong namespace, and they are the thing to inspect when the property is in doubt.
Every policy below exists under that name in `reference/deploy/manifests`.*

| Zone | Policy | What it enforces |
|---|---|---|
| identity | `identity-ingress` | operators connect from outside the cluster |
| identity | `identity-egress-via-monitor-only` | the only in-cluster egress is to the monitor zone |
| identity | `identity-egress-idp-by-fqdn` | the identity provider is reachable by name, not address; an address rule would also expose the co-located secret store |
| monitor | `monitor-ingress-from-identity-only` | nothing but the identity zone may reach it |
| monitor | `monitor-egress` | forwards to the credential zone |
| credential | `default-deny-ingress` | denies first, before explicit allowances |
| credential | `allow-portal-from-monitor-namespace` | the broker is reachable only through the monitor |
| credential | `allow-stub-from-portal` | permits the broker's test path to the target stub |
| credential | `credential-egress` | limits egress to DNS, the secret store, and the target |

Those are the policies that carry the argument, not the complete set: the namespaces also
hold rules for intra-namespace traffic and a deliberately weak, forgeable one kept as a
demonstration. Read the manifests for the whole picture.

And a caution about the zone rule those policies enforce. **It holds for the broker path,
not automatically for everything deployed in the zone.** The same rig runs a second path to
the same appliance — SSH — on which the credential is resolved *into* the identity zone
without crossing the monitor at all. §15 sets out that contradiction. A zone rule is a claim
about paths that have been moved, and it stays false for every path that has not been.

You may be wondering why not "high side / low side", which is standard and available. The
canonical usage is that high means *more sensitive* — which would put the appliance
credential, the most sensitive thing in the design, in the zone called *low*. The naming
would invert the thing being protected.

---

# Part III — Building it

## 11. The rules that must hold

Each of these marks a place where an implementation that looks correct is not. They are
reasoned rather than measured — **[A]** — except where a clause carries its own marker.

### Verify the assertion on every use

Signature, issuer, audience, expiry, not-before — **on every request**, not only when the
session is established. Pin the algorithm. Fetch signing keys from the issuer's published
key set, cache them with a bounded lifetime, refresh on an unknown key id.

The failure mode to design against is specific: an assertion that is well-formed,
unexpired, from the right issuer, and whose **signature was never checked**. It looks
correct in every log you have. It is correct in every respect except the one that matters.

This is not hypothetical. A reference implementation checked the forwarded token for shape,
expiry and the presence of a subject — on the reasoning that the secret store was the
authority and had verified the signature at login. That is true of the login path. It is
not true of the steady-state path, which every proxied request takes.

The consequence is reachable. A capability is bound to a subject so that a captured
capability cannot be used by anyone else. But if the steady-state path compares that bound
subject against a subject read from an *unsigned* assertion, the binding is decorative. An
observer of the boundary sees both the capability and the subject — `sub` travels in clear
— and could forge `header.{"sub":<victim>,"exp":<future>}.anything`, present it with the
captured capability, and be accepted for the capability's remaining life. **[A]**

> **Binding to a subject means nothing unless the claim of that subject is authenticated.
> Subject equality is not proof of subject possession.**

With verification added on every use, a forgery carrying the correct shape, a victim
subject, a future expiry, the correct issuer and audience, and the real published key id
was rejected: `signature does not verify`. **[V]** — the rejection is asserted by a
regression test against a locally generated key pair, not by a transcript from the deployed
rig.

Note where this was found. It came from reading the authorisation path, not from measuring
the boundary — the complement of §14, and the reason both activities are needed.

### Fail closed, and decide the cases before you need them

| Failure | Required behaviour |
|---|---|
| Signing keys unfetchable, or key id unknown | **Deny.** Never fall back to a stale or unverified key. A bounded cache is permitted; its expiry denies. |
| Secret store unavailable or slow | **Deny.** No cached-credential reuse to paper over an outage — that decouples the fetch from the authorisation decision it depends on. |
| Target session opened but its capability record did not persist | **Close the target session.** Never leave it orphaned, never return a capability whose record is not durable. |
| Audit unavailable | **Deny by default.** A tightly bounded durable spool is the only alternative, isolated so audit backpressure cannot itself become the outage. |

Naming these cases without choosing an answer is not a requirement. It is a to-do list
handed to whoever is on call.

### Guard the destination at dial time, not at config time

Comparing a hostname against an allowlist is not enough. Names resolve to addresses the
grant never intended, and redirects move the destination after the check has passed.

Canonicalise `(scheme, host, port, resolved address)` at the moment of connection, refuse
redirects, and ignore caller-supplied `Host` or absolute-form request targets. Block
loopback, link-local and control-plane ranges unless explicitly granted.

Of those, **refusing redirects is the one with teeth, and the reference implementation
originally did not do it. [M]** The login request carries the fetched credential in its
*body*. A default Go HTTP client follows up to ten redirects and, for 307 and 308, replays
the method and body on each hop — so a redirect from the login endpoint hands the appliance
password to whatever host the redirect names. That was demonstrated against a client
configured exactly as the broker's, and the credential arrived at the second hop intact.

It is fixed: every client that carries credential material now refuses redirects, and a
regression test asserts the redirect target received **nothing** — not merely that an error
came back, since an error is also what you get *after* a leak. **[V]**

Two things are worth taking from that beyond the fix. The control was written down as a rule
that must hold and then not implemented, which is the ordinary way security controls go
missing: nobody argued against it. And a network policy that confines egress to known hosts
limits the blast radius, which is why this was survivable here — but the reference is what
other deployments inherit, and they do not inherit that policy.

Blocking implausible destinations is implemented too, though only at startup. **[V]** The
reference refuses to start on a non-HTTP scheme, a URL with no host, or an address that is
loopback, link-local, unspecified or multicast. `url.Parse` alone is not a check: it accepts
`file:///etc/passwd`, `javascript:alert(1)`, a bare `not-a-url` and the empty string without
error, so a service configured with any of them starts and fails later — while holding the
credential. The link-local case is the one that earns its place: `169.254.169.254` is the
cloud instance metadata service, and a broker pointed there would present the appliance
credential to an endpoint that returns the node's own identity.

**Dial-time canonicalisation remains unimplemented. [A]** The check above runs once, against
a configured value. A hostname that resolves to a permitted address at startup and a blocked
one later is not caught — that is DNS rebinding, and defeating it requires enforcement in the
transport at connection time, binding the resolved address rather than the name. The
reference does not do this; `reference/README.md` records it among the known limits.

Worth noting what made the difference between the two. The redirect and destination controls
were both written down here as rules that must hold. One was implemented and one was not, and
nothing in the document distinguished them — which is why the marker now carries that
distinction rather than the prose alone.

### Order revocation correctly

Revoke the capability **first** and atomically, refuse new work, bound and drain what was
already dispatched, and end the target session only when the last capability referencing it
is gone.

Shared upstream sessions are usually necessary, because many targets limit concurrent
sessions — which is part of why this pattern exists at all. Sharing has consequences, and
they should be stated rather than discovered:

- revocation cannot undo an operation already dispatched
- a shared session outlives any single capability, so target-side revocation is not per-caller
- compromise of a shared session affects the whole cohort
- **B-conn targets are excluded from sharing entirely** (§8)

### Bound everything

The broker is in-path for every request. Per-subject and per-target quotas, deadlines on
every dependency, bounded capability state. Without them, one tenant denies the whole
estate.

### Decide who owns the caller's assertion lifetime

The assertion expires — typically within the hour. Somebody has to renew it, and pretending
otherwise produces a system that mysteriously stops working mid-afternoon.

| Model | Suits |
|---|---|
| Caller renews and presents a fresh assertion | machine callers with their own credential |
| Broker holds a renewal grant | convenient, but see the condition below |
| Neither — access ends with the assertion | honest; acceptable only for interactive use |

If the broker renews, one condition governs whether that is safe:

> **A broker may hold a renewal grant only if that grant cannot outlive, or be renewed
> beyond, the session it belongs to.**

Meet that and the broker gains nothing it did not already have. Miss it — the grant
outlives the session, or rolls indefinitely — and the broker has quietly acquired a durable
credential for every caller it has ever served. It is now a more valuable target than the
credentials it was built to protect.

Three consequences follow, none of them obvious in advance:

**Renewal is lazy and request-driven.** It happens when the token is about to be used, not
on a timer. An idle session does not renew, and should not — a session doing nothing needs
no token. Two consequences follow: you cannot verify renewal by waiting, only by driving
traffic through the path; and the identity provider lands on the critical path of one
request per renewal interval.

**Decide whether renewal failure is loud or soft.** Returning the stale token avoids turning
a recoverable expiry into an outage. But then an identity-provider outage presents as *the
target* rejecting an expired token, and the operator goes looking at the wrong component.
If you choose soft, emit the refresh failure as a first-class event.

**Renewal does not apply retroactively.** Session state is written once, at establishment.
Sessions created before renewal was deployed cannot acquire it and still expire at the
original lifetime. During a rollout both behaviours run side by side, which reads as
intermittent rather than as a version boundary.

### Make security events distinguishable

`token expired` and `signature does not verify` are the same HTTP status to a caller and
completely different events to an operator. One is routine. The other is someone attempting
a forgery. If they look alike in what you emit, the second will be lost in the noise of the
first — and the second is the one you built the audit trail for.

## 12. What a compromised broker means

It is worth being blunt. A compromised broker can read whatever credential material is in
its memory — the live target session, and any credential it fetches from that point on — and
can alter its own gates, scrubbing and audit. **[A]**

The distinction matters for what an attacker gets. The appliance password is a transient
local value on the login path, not a store the broker accumulates — so "every credential it
has ever fetched" overstates it. What a compromised broker holds is the current session, and
the ability to fetch again for as long as callers keep presenting assertions.

"It authorises as the caller" limits it **only if** the secret store enforces exact-path
grants independently, and the delegation is not a replayable bearer token. That is a
requirement on the store, not a property of the broker, and it should be written down as
one.

Note the reference implementation does **not** meet the second condition: it forwards the
caller's assertion to the secret store as a bearer token, so anything that can read it can
replay it for that token's remaining life. **[V]** Sender-constrained delegation would close
that, and is not implemented here.

---

# Part IV — Proving it

## 13. The conformance test

This is the deliverable that is useful **whether or not a platform is ever built.** The
safety property is measurable, which means the measurement can be published — and a
published test can be applied to implementations you did not build.

**Method**

1. Place an observer on the boundary hop.
2. Record **every header name** — not a watchlist. Names only, never values.
3. Record cookie **names** within cookie headers. A header staying present says nothing
   about which cookies crossed.
4. Record request and response **body sizes**, and state plainly that contents are
   unexamined.
5. Drive **controlled probes** — deliberately send the credential you expect to be
   stripped. A chosen input proves more than passive observation.
6. Verify the **response side.**

**What a pass establishes, and what it does not**

This observes header names, cookie names and body sizes. It can therefore **disprove** the
property conclusively — one credential-bearing header is a failure. It cannot **prove** it,
because a secret inside a body is invisible to it.

So state the result as it is: *"no credential-bearing material was observed in any header
or cookie across N requests; payload contents were not examined."* That is a strong claim
and a true one. *"Only tokens cross"* claims more than this evidence supports, and the
difference will matter to whoever relies on it.

**Two rules that decide whether the result means anything at all**

> **A watchlist proves presence, never absence.** Instrumentation that watches five named
> headers can tell you those five were absent. It can say nothing whatever about the sixth
> — which is precisely the claim being made. Only a full census answers it. **[M]** that a
> five-header watchlist reported a clean boundary while a census then found an unwatched
> header on every request; **[A]** for the general rule that follows from it.

> **Boundary observations are recorded before forwarding.** They look completely healthy
> even when the downstream has been replaced by a stub, or is entirely broken. A conformance
> run is valid only alongside a **response-side signal** proving the real chain executed.
> Header evidence can prove a leak. It cannot prove a chain works. **[V]** the observer
> records the request before it forwards; **[M]** a re-applied manifest silently repointed
> the monitor at a stub and the boundary observations went on looking correct.

## 14. What measurement found that review did not

Both of the following were present in a working, reviewed implementation of this exact
pattern. Both are invisible to architecture review, and both were found by measuring the
boundary rather than by reviewing the design. The crossing counts below are measured
**[M]**; the fixes that follow each are recommendations.

The counts come from an observer on the boundary hop of a deployed rig, against a real
appliance, with a response-side signal confirming the chain executed — §13 rule 2 requires
that, and it applies to this paper's own evidence as much as to anyone else's.

**On the provenance of the two kinds of number below.** The *pre-fix* counts are historical:
they were observed on a deployment that no longer exists, and no transcript was kept, so a
reader cannot re-derive them. They are marked **[U]** — reported, not reproducible — and
they are the weaker half of this section. The *post-fix* behaviour is different: it is a
property of the current deployment and regenerates on demand, so it is marked **[M]** and
the figures quoted are from a run anyone with the rig can repeat. Publishing a frozen
transcript would only evidence the day it was captured; §13's argument is that the useful
artefact is a test that can be re-run.

**The gateway's own session cookie crossed on every request observed — 1001 of 1001 at the
time. [U]**

The broker fronted its targets on its own origin, so the browser attached the gateway's
session cookie to every request, and the proxy forwarded it verbatim. Nothing downstream
read it. It was an unbound 24-hour bearer for the gateway itself — and the gateway could
reach targets whose credentials resolve on the trusted side.

Which is to say: **the boundary was carrying something more valuable than the secret the
design existed to protect.**

The fix is to strip it by matching **name and value together**. Matching the name alone
breaks a second gateway deployed behind the first, which legitimately uses the same cookie
name. The fix itself is not in this repository — it was contributed upstream to the
gateway, and this paper's reference implementation is downstream of it. **[U]** for the
change; what is verifiable here is its effect.

That effect regenerates on the current deployment. Across **469 consecutive requests** on
the boundary hop, with the monitor proxying to the real broker rather than a stub:
**0 carried the gateway's session cookie.** The target's own cookies were passed through
untouched — 308 requests carried all five (`accepts-cookies`, `null`, `publicKeyId`,
`publicKeyIdSignatureBase64`, `ui_lang`) and 161 carried the two the browser had at that
point in the session. **[M]**

That second figure matters more than it looks. "The target's five cookies were preserved"
would have been a tidier sentence and a false one: cookie sets vary by session phase, and a
claim that every request carried five would fail the first time somebody checked. What is
being asserted is that the broker passes the target's cookies through *as presented* and
strips the gateway's — not that a fixed set appears every time.

**An unsigned identity header crossed on every request observed — 115 of 115 at the
time. [U]**

The broker injected an identity header carrying the same identity as the token, but
unsigned, with no configuration available to disable it.

That is worse than redundant. The receiving service **authorised** on the signed token but
**attributed its audit log** to the unsigned header. Authorisation used the strong channel;
attribution used the weak one — and the audit log is the artefact everyone relies on after
an incident. Attribute from the verified token, and suppress the headers wherever a signed
token is present.

### Checking this yourself

The **[M]** figure above is the only one a reader can re-derive, and that is deliberate. On
a deployment of `reference/deploy`, with the monitor pointed at the broker rather than the
stub, the observer emits one JSON record per request carrying `all_header_names` and, within
`observed`, the `cookie_names` that crossed. Aggregating those records over a run reproduces
the shape of the claim: how many requests carried the gateway's session cookie, and which of
the target's own cookies were passed through.

Two cautions carried over from §13, which apply to this paper's evidence as much as anyone
else's. Confirm the monitor's `UPSTREAM_URL` names the broker, not the stub, or the run
observes a chain that is not the one under test. And read `all_header_names` rather than the
watchlist, because the watchlist can only speak to the headers it was told to watch.

## 15. What is left over

No design is free of residue. These are the parts that remain after the pattern has done
its work.

| Risk | Status |
|---|---|
| Identity visible at the boundary | **[M]** the subject appears in the token. Needs pairwise or pseudonymous subject identifiers at the IdP — outside the broker's control. Note the subject may be a personal email even for administrative accounts |
| Capability outliving its session | the bound is implemented and observable — **[V]** `mintUntil`, **[M]** both branches (`capability_ttl` and `assertion_expiry`) appear in the deployment's own logs. That an unbounded capability **[A]** widens the replay window is the reasoning the bound exists to answer, not something measured |
| Revocation lag | **[V]** logout deliberately leaves the shared target session standing. That a warm session therefore **[A]** outlives revoked authorisation for the remainder of its TTL follows from that, but was not demonstrated: nobody revoked mid-session and watched service continue |
| Shared target session | **[V]** one upstream session is shared across operators. That this **[A]** dilutes per-user attribution *at the target* is inference — confirming it means reading the appliance's own logs, which was not done |
| Bodies not observed | **[M]** the measurement covers header names, cookie names and body sizes — that is what the instrument records. Payload *contents* are **[U]**: "nothing else crossed" is established for headers and **unproven for payloads** |
| Extendable session credentials | **[D]** some platforms let the holder extend a session — on one, from 1,200 s up to a 36,000 s ceiling. Treat the ceiling, not the default, as the exposure |
| Destination binding is not least privilege | **[A]** a grant binds credential and destination, not *operation*. If the underlying credential is administrative, so is the capability. **Treat each capability as equivalent to the full privilege of the underlying credential** unless an adapter demonstrably narrows it. Prefer separate least-privilege target credentials where the target supports them |
| Workload-identity fallback exists | **[V]** the reference implementation retains a machine-identity path for callers that cannot present an assertion. It is off by default and mutually exclusive with per-user mode — enabling both refuses to start, which is a startup guard and a regression test, not a rig observation — but it exists, and an operator who enables it loses the attributability the pattern is for |
| Renewal implemented, firing unobserved | **[M]** capture is verified — a session records a refresh grant and a true expiry. Renewal firing has not been observed, because it is request-driven and both attempts ran against idle sessions |
| A second path in the same deployment breaks the zone rule | **[M]** the rig's identity zone holds an egress rule permitting SSH directly to the appliance, and the gateway resolves that credential *itself* from its own vault backend — so on that path the appliance credential reaches the identity side by a route that never crosses the monitor. It is the pattern's own inverse, running beside it. See below |

### The contradiction in the same deployment

That last row deserves more than a table cell, because it undercuts §10's rule as stated.

§10 says the identity zone holds *assertions only — never a credential*. In the deployment
this paper measures, that is true of the **broker path** and false of the deployment as a
whole. The gateway also offers SSH to the same appliance, and for that it resolves the
credential through its own vault integration: the secret is fetched **to** the identity
side, by a route the monitor never sees. The network policy permitting it is in
`reference/deploy/manifests`, and its own comment calls this the documented contradiction.

Three honest observations follow.

**The rule is a property of a path, not of a namespace.** Putting a workload in a zone does
not make the zone's rule true; the rule holds only where every credential-bearing path has
been moved. One unmoved path is enough to falsify it, and SSH was left in place precisely so
the behaviour could be observed rather than argued about.

**It is out of scope in the sense that matters least.** §8 excludes SSH as Class C, and no
design here serves it. But a reader inspecting the rig will find an appliance credential on
the identity side, and "Class C is out of scope" does not answer that — it explains why the
path exists, not why the zone rule still reads as unconditional.

**It sharpens what the pattern is worth.** The HTTP path demonstrably keeps the credential
on the far side. The SSH path beside it demonstrably does not. That contrast is the clearest
statement of the pattern's value and its limit: it is not a property of the estate, only of
the traffic that has been brought inside it.

## 16. Operations

**Rotation is at least four different problems** wearing one word. **[D]**

| Shape | Consequence |
|---|---|
| Cascading — changing the password invalidates derived keys | rotation is an outage unless sequenced |
| Independent — session credentials expire alone | cheap |
| Manual-only — permanent keys | needs a human process |
| Per-device localised keys | rotation is fan-out, not a write |

**Availability.** The broker is in-path for every request, not just logins. An outage stops
all work, not merely new sessions. Size it knowing it is on the critical path for the
entire estate behind it.

**Audit.** Record subject, target, capability id, grant, decision, and the reason for a
denial. Attribute from the verified assertion, never from a header — see §14 for what
happens when that rule is broken quietly.

---

## 17. Onboarding a target

1. Classify it (§8). If Class C, stop — this pattern does not cover it.
2. For A2 candidates, verify the configured session lifetime **on a real device.**
3. Capture the five parameters: login path, request shape, credential location, TTL, refresh.
4. Decide whether callers are machines or browsers (§9) — browsers need login interception.
5. Create the grant: subject set, destination, capability TTL.
6. Run the conformance test (§13) against the new path, with a response-side signal.

## 18. What is still open

- Whether an operation-level grant is expressible without the broker interpreting requests.
  Currently it is not, and §15 records what that costs.
- Whether renewal fires as implemented. Capture is verified; firing is not.
- Whether request bodies can be brought inside the measured property without content
  inspection, and what that would cost.
- How to clear material a text scan cannot read. A screen recording of the working system
  **is** published, on the landing page. It carries what no rule in the sanitiser can see:
  identity and product names rendered as pixels. The gate therefore refuses video by
  default and admits this one by the SHA-256 of its reviewed bytes, so re-encoding forces
  re-review — but the clearing step itself is a human watching frames, and that does not
  scale. What would is unresolved.

---

*A working reference implementation — assertion verification, per-user vault exchange,
login interception and synthetic tokens — is under `reference/` in this repository. An
assessment of whether commodity API gateways can fill the broker role is in
[gateway evaluation](gateway-evaluation.html).*
