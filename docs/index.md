---
layout: default
title: Overview
---

# Brokered credential access across an inspecting boundary

A device needs a credential. The credential is shared, long-lived, and cannot be
made per-user. A person needs to use it. Between them sits a boundary that
decrypts and records everything crossing.

Handing the person the credential fails on attribution and revocation. Sending it
across the boundary fails worse:

> A recording of a credential is not a record of an event. It is an unexpired key,
> held by whoever holds the recording.

The appliance password does not expire. The recording outlives every control you
put around it.

## Read

- **[The pattern](credential-broker-pattern.html)** — the design, its failure
  modes, and an explicit account of where it does not help.
- **[Gateway evaluation](gateway-evaluation.html)** — Kong and Apigee assessed
  against the real requirements. Both can *host* this; neither *provides* it.

## The shape of the answer

Split the path at the boundary. The gateway authenticates the person and forwards
**identity only**. The broker, on the far side, exchanges that identity for a
credential — presenting *the operator's* token to the secret store, so the vault
sees the person rather than the pod.

Two rules carry most of the weight:

1. Only expiring, bound, scoped material crosses the boundary. An assertion may
   cross; a credential may not.
2. The zone holding credentials authorises the operator, not the workload.

The zones are named for the rule they enforce — `identity-zone` and
`credential-zone` — rather than for a trust level. A credential appearing in the
identity zone is self-evidently a violation, with no convention to remember.
(§1 of the paper explains why "high side / low side" was considered and rejected:
the canonical usage would have placed the appliance credential in the zone called
"low".)

## Why this is not header injection

The obvious implementation injects an `Authorization` header into a proxied
request. For the common case that cannot work, and the reason is structural:

> A single-page admin UI decides whether it is logged in by reading **its own
> browser storage**. That check happens before any request exists, so an injected
> header is invisible to it and the operator is shown a login form — asking them
> to type the very credential you are concealing.

So the broker *answers* the login instead, replacing the token in the appliance's
own response with an opaque synthetic one and swapping it back on every
subsequent request. Neither the password nor the real session token reaches the
browser.

This is also why an API gateway is a poor fit for the broker role. Kong's secret
subsystem has no caller dimension at all — its cache key is
`config_hash + reference`, resolved on a background timer — so it can inject *a*
credential but never *this caller's*. Apigee can express the exchange
declaratively, but its runtime depends on a vendor control plane the restricted
zone would have to egress to.

## What was actually measured

Claims carry provenance markers: measured, verified-from-source, documented, or
explicitly open. Where a control was not proven, it says so.

- The gateway session cookie crossed on **1001 of 1001** requests before the fix,
  **0 of 365** after.
- A full header census then found an unsigned identity header on **115 of 115**
  requests — one a five-header watchlist had never been told to look for.
- A forged capability with the correct shape, a victim subject, a future expiry,
  the correct issuer and audience, and **the real published key id** was rejected:
  `signature does not verify`.

## Two habits worth stealing

**A watchlist proves presence, never absence.** The watchlist reported a clean
boundary. The census disagreed.

**Verify a negative against a known positive.** A scan reporting "clean" means
nothing until the same scan has been shown to catch a planted canary. During this
work a word-boundary search returned a confident zero against a file that
contained nine matches, because git's regex engine silently ignores `\b` — no
error, just an empty result that reads exactly like "clean". The same class of
error, in a publish step, is irreversible.

## Status

A reference implementation, not a product. The broker has no authentication of
its own by design and must sit behind the gateway, enforced by NetworkPolicy.
One upstream appliance session is shared across operators. SNMP and SSH-only
targets are out of scope — no design here solves them.

Identifiers throughout are documentation placeholders (`example.internal`,
RFC 5737 addresses). Nothing here is a live endpoint.
