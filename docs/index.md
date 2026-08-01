---
layout: default
title: Overview
---

# Brokered credential access across an inspecting boundary

An engineer needs to change a firewall rule. The firewall knows one way to authenticate: a username and a password, shared by everyone who administers it. The engineer has a modern identity — single sign-on, a token that expires in an hour. Between them sits a device that decrypts every connection, inspects it, and keeps a copy.

Somewhere in that arrangement, a password crosses a recorder.

> A recording of a token is an artefact. A recording of a **password** is an unexpired key, held indefinitely, by anyone who can read the archive.

That asymmetry is the whole problem. A token in a capture is a record of something that happened. A password in a capture is a door that is still open.

## The pattern, working

<video controls muted playsinline preload="metadata" width="100%"
       style="max-width:900px;border:1px solid #eaecef;border-radius:6px;">
  <source src="demo.mp4" type="video/mp4">
  Your browser cannot play embedded video.
  <a href="demo.mp4">Download the recording</a> instead.
</video>

An operator signs in with single sign-on, selects the appliance, and reaches its administrative interface — **without ever being sent, or typing, the appliance's password.** The broker exchanged the operator's identity for that credential on the far side of the boundary and used it there.

The appliance's own login form never appears, because the broker answered it. The operator's display name and the device's serial, MAC and address are blurred; nothing else is edited.

## Read

- **[The pattern](credential-broker-pattern.html)** — the problem, the design, how to build it, and how to prove it. Includes an explicit account of where it does not help.
- **[Gateway evaluation](gateway-evaluation.html)** — Kong and Apigee assessed against the requirements a working implementation actually produced.
- **[Appendix](appendix.html)** — the conformance test, the residual risks, how the claims are marked, and what is still open.

## The shape of the answer

Split the path at the boundary. The gateway authenticates the person and forwards **only their identity**. On the far side, a broker exchanges that identity for the device's credential and uses it there. The credential is never sent back.

Two rules carry the design:

1.  Only expiring, bound, scoped material crosses the boundary. An assertion may cross; a credential may not.
2.  The secret store authorises **the operator, not the broker's workload identity.**

The second is what makes access attributable. A vault that authenticates the workload knows a machine asked. A vault that authenticates the person knows who asked.

Three zones, named for the rule each enforces — **identity**, **monitor**, **credential**. Named that way, a credential appearing in the identity zone is self-evidently a violation. The monitor zone is named deliberately: it is the reason the pattern exists. (The pattern explains why "high side / low side" was rejected — the canonical usage would place the appliance credential in the zone called *low*.)

## Why this is not header injection

The obvious implementation injects an `Authorization` header into a proxied request. For **browser-facing** targets that cannot work, and the reason is structural:

> A single-page admin UI decides whether it is logged in by reading **its own browser storage**. That check happens before any request exists, so an injected header is invisible to it and the operator is shown a login form — asking them to type the very credential you are concealing.

So the broker *answers* the login instead, replacing the token in the appliance's own response with an opaque synthetic one and swapping it back on every subsequent request. Machine callers need none of this; browser callers cannot work without it.

## How to read the claims

Every claim carries a marker saying how it is known, on one ordered scale: **[M]** measured, **[V]** verified from source, **[G]** verified from the GitHub API, **[D]** vendor documentation, **[C]** community or practitioner example, **[A]** reasoned but unverified, **[U]** open question. The full table is in [the appendix](appendix.html#how-the-claims-are-marked). Where a control was not proven, it says so.

## On API gateways

Both Kong and Apigee were assessed against the requirements the implementation produced, not against the pattern in the abstract. The short version: the difficulty sits in answering a login, rewriting a response, and holding synthetic-token state — and neither product provides any of that. Both can host it.

They fail differently. Kong's secret subsystem has no caller dimension at all — its cache key is `config_hash + reference`, resolved on a background timer **[V]** — so it can resolve *a* credential but never *this caller's*. Apigee appears able to express the exchange declaratively **[D]/[C]**, on documentation and practitioner evidence rather than a proof of concept; its runtime also depends on a vendor control plane the credential zone would have to egress to, and whether it can run with that plane unreachable is an open question. The evaluation is explicit about which claims rest on which kind of source.

## What was measured

- A gateway session cookie was crossing the boundary on every request observed — carrying, on that hop, something more valuable than the secret the design existed to protect. On the current deployment it crosses on **0 of 469** consecutive requests, while the target's own cookies pass through as presented. **[M]** The pre-fix figure is reported from a deployment that no longer exists and cannot be re-derived. **[U]**
- A full header census found an unsigned identity header on every request observed. **[U]** The receiving service authorised on the signed token but attributed its audit log to the unsigned one.
- A forged assertion — correct shape, victim subject, future expiry, correct issuer and audience, and the real published key id — is rejected with `signature does not verify`, once signature checking is applied on **every** use rather than at login only. **[V]** That defect was found by reading the authorisation path rather than by measuring the boundary; the two activities catch different things.
- The reference implementation followed HTTP redirects on the request that carries the appliance password, so a redirect from the login endpoint replayed that password to the redirect target. **[M]** Demonstrated, then fixed, with a regression test asserting the redirect target receives nothing.

## Two rules worth stealing

**A watchlist proves presence, never absence.** Instrumentation that watches five named headers can tell you those five were absent. It can say nothing about the sixth — which is exactly the claim being made. **[M]**

**Boundary observations are recorded before forwarding.** They look healthy even when the downstream has been replaced by a stub. Header evidence can prove a leak; it cannot prove a chain works. **[M]**

## Status

A reference implementation, not a product.

The broker verifies the caller's assertion on every request and refuses to start in per-user mode without a key set and issuer — but that is defence in depth, not a licence to expose it. It must still sit behind the gateway, enforced by NetworkPolicy. One upstream appliance session is shared across operators. SNMP and SSH-only targets are out of scope; no design here solves them.

Identifiers throughout are documentation placeholders (`example.internal`, RFC 5737 addresses). Nothing here is a live endpoint.
