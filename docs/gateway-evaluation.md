---
layout: default
title: Gateway evaluation
---

# Kong and Apigee can host this broker. Neither replaces it.

Before building anything, we asked whether a gateway already in the estate could do the job. We assessed Kong and Apigee against twelve requirements produced by a working broker, not against the pattern in the abstract.

They fail at different hard constraints. Kong cannot authenticate to a vault as the operator: its secret cache is keyed by configuration hash with no caller dimension, and that is three lines of Lua, not a setting. **[V]** Apigee appears able to express that exchange, but its hybrid runtime depends on a Google-hosted management plane and egresses to it — which a zone defined by controlling what leaves has to weigh against the open questions below. **[D]**

Both can implement the browser-specific broker flow only as custom code and custom state. The difficulty is concentrated in five requirements — answering a login, rewriting a response body, holding synthetic-token state, substituting bidirectionally, and maintaining an upstream session — and neither product supplies any of them. You end up writing exactly the code you were trying to avoid, in a language and lifecycle you did not choose.

Kong's findings here are source-verified against `Kong/kong` at tag `3.9.3`, commit `a643428`. Apigee is closed-source, so its findings rest on vendor documentation and sit one confidence level lower throughout. The [appendix](appendix.html) explains the markers. That asymmetry is not a courtesy — Kong's decisive finding was three lines of Lua no documentation would have exposed.

## What the requirement set actually is

Two placement rules come before any capability question, and both are hard filters.

**Credential injection must happen in the credential zone.** If the gateway injects from the identity zone, the credential crosses the recorder. A recording of a credential is not a record of an event — it is an unexpired key held by whoever holds the recording.

**The vault must not be reached across the boundary either.** Moving the broker to the far side is defeated if its vault call drags the credential back the other way. This is easy to miss, because "the broker has moved" reads as sufficient. In the prototype that path does not traverse the monitor; a manifest exists — `45-monitor-egress-openbao.yaml` — that deliberately violates it as a labelled experiment, not as the baseline. **[V]**

The consequence for procurement is blunt: **a PAM product that injects credentials from the identity zone is unusable here**, however good its session recording. That is easy to discover late, because injection is marketed as a capability rather than as a placement decision.

The rest come from the prototype in `reference/broker/main.go` — a reverse proxy built on `httputil.ReverseProxy` — and its deployment: **[V]**

| \# | Requirement | Source |
|----|----|----|
| R1 | Run in the **credential zone**; no credential in the identity or monitor zones | architecture |
| R2 | Verify the caller's assertion on **every use** — signature, issuer, audience, expiry; fail closed | **[V]** `verify.go` |
| R3 | Authenticate to the vault **as the operator**, never as the pod or gateway | requirement |
| R4 | Bound the capability by `min(capability_ttl, assertion_remaining)` | **[V]** `mintUntil` |
| R5 | **Synthesize a response** to the SPA's login request | **[V]** |
| R6 | **Rewrite the response body**, substituting a synthetic token | **[V]** |
| R7 | Hold **server-side synthetic↔︎real token state** | **[V]** |
| R8 | Bidirectional substitution on **every** subsequent request | **[V]** |
| R9 | Maintain a long-lived upstream appliance session | **[V]** |
| R10 | Telemetry distinguishing expiry from forgery | **[V]** |
| R11 | No standing **appliance** credential held in the identity or monitor zones | architecture |
| R12 | No vendor egress out of the credential zone | environment |

R5 through R9 decide this evaluation. R5 through R8 exist because the caller is a browser; R9 exists because many targets limit concurrent sessions.

A single-page admin UI decides whether it is logged in by reading its own browser storage, before any request exists. An injected header is invisible to it, so the SPA shows a login form and asks the operator to type the credential you are concealing. Header injection — a gateway's most natural capability — is structurally incapable of producing a logged-in session for these targets. The broker has to *answer* the login instead.

That narrows where a transparent proxy helps considerably. It also means the target classification in [the pattern](credential-broker-pattern.html) can be read too optimistically: a device in the class where the credential exchanges for a session still cannot be served by header injection if its admin UI is a browser application. Classify by caller as well as by target.

## Kong: the caller never reaches the vault

Kong holds the caller's identity. Kong has a vault client. They are on different planes and are not connected.

Identity is data-plane, per request. Secrets are configuration-plane, resolved out of band and cached node-wide by configuration hash. Here is the whole finding, from `kong/pdk/vault.lua`: **[V]**

``` lua
local function build_cache_key(reference, config_hash)
  return config_hash .. "." .. reference
end
```

No caller, no subject, no session. The cache is `ngx.shared.kong_secrets`, a node-wide 5 MB zone. **[V]** Resolution runs on a background timer with a default `ROTATION_INTERVAL` of 60 s. **[V]** Kong's own documentation says this *"decouples the secret rotation process from proxying."* **[D]** And the entire per-request API is `kong.vault.get(reference)`, which accepts a reference and nothing else. **[V]**

Enterprise adds backends, not a different model. Kong authenticates to HashiCorp Vault via `token`, `approle`, `cert`, or `kubernetes` — the last using *"the service account JWT token mounted in the pod."* **[D]** That is the pod-identity anti-pattern R3 exists to forbid. The same shape recurs in the Enterprise `upstream-oauth` plugin, which caches by a hash of its `config.oauth` values, so instances with identical configuration **share cached tokens**. **[D]**

One plausible hypothesis is worth killing: running Kong DB-less does not foreclose per-user state — the `session` plugin still stores it. Deployment mode is irrelevant, because the constraint lives in the vault subsystem. **[V]**

**On R5–R9, everything is achievable and all of it is Lua.** `resty.http` is available to plugins, so outbound calls, response synthesis and token substitution are all writable. **[V]** Possibility is not the obstacle.

The obstacle is R7 meeting Kong's caching model. Every caching helper offered to a plugin author is node-wide shared memory — `kong.cache` is backed by `ngx.shared` dicts — `lua_shared_dict kong 5m`, `kong_db_cache`, and the rest. **[V]** The idiomatic way to hold synthetic↔︎real token state caches it in a dictionary shared across every worker and every plugin on the node. Key it without the subject and it is a cross-user credential leak. Key it correctly and the material still sits in shared memory readable by any other plugin on that node.

That is the first thing a competent Lua author reaches for, and it is wrong here in a way that would not surface in testing.

Two product facts also matter. OSS ships exactly one vault backend, `env`, has no `openid-connect` plugin at all, and carries no OpenBao integration — which is the vault this deployment actually uses. **[V]** And the version gap is wide: the latest OSS release is 3.9.3, the last OSS *minor* was 3.9.0 in December 2024, `master` declares 3.10.0, while Enterprise documentation describes 3.14 and 3.15 features. **[G]/[D]** So R2 requires Enterprise, roughly five minors ahead of anything Apache-2.0 — and R3 is unreachable in either edition.

**Kong's real advantage is R12.** It is fully self-hosted, needs no external control plane, and in DB-less mode has no outbound dependency. It can live in a credential zone with zero egress.

## Apigee: the right shape, in the wrong place

Apigee appears genuinely better at the thing Kong cannot do. It exposes `ServiceCallout`, an arbitrary HTTP call mid-flow with access to the incoming request — including the caller's token: **[D]/[C]**

``` xml
<Header name="Authorization">{request.header.Authorization}</Header>
```

On that configuration the vault would see the operator, not the gateway — and on this evidence, without custom code. R2 is `VerifyJWT` or `OAuthV2`, R4 is arithmetic over flow variables. **[D]**

Two caveats on that snippet, since it carries Apigee's one advantage. The braces are load-bearing: `<Header>` content is a message template, so a bare variable name is sent as a literal string. And the snippet is illustrative and untested — no proof of concept was built. It shows the mechanism exists, not that a working configuration was demonstrated. That is the difference between **[D]/[C]** here and the **[V]** on every Kong finding.

**Past R3 the declarative story stops.** R5 is `AssignMessage`, but R6 needs a `JavaScript` policy in practice, R7 needs cache or KVM, and R8 and R9 are custom flow logic. Against R5–R9 Apigee is where Kong is — custom code plus cached state — with better ergonomics and a reviewable artefact, but no categorical advantage.

The cache hazard is present here too, milder. Keys compose as `scope | prefix__keyfragment`, with `Scope` one of Global, Application, Proxy, Target or Exclusive — and even the default `Exclusive` resolves to `org__env__proxy__revision__endpoint` — **no user component**. **[D]** Caching per-operator state without an explicit `<KeyFragment ref="…subject…"/>` shares it across every caller of that proxy. Better than Kong on two counts — the key composition is declarative and reviewable, and the default is the most specific scope — but it is the same failure. Invalidation also broadcasts to all message processors in all regions, and **if the broadcast fails the stale value survives in L1 until TTL expiry** **[D]** — a revocation gap for cached credential state.

**Where it fails outright is R12.** Only Apigee hybrid is admissible for a credential zone, and hybrid splits into a Google-hosted management plane and a customer-managed runtime plane. Traffic locality is correct — *"All API traffic passes through and is processed within the runtime plane"* **[D]** — but three flows cross outward:

1.  **Proxy bundles come from Google.** The Synchronizer pulls runtime contracts down from the management plane. **[D]** In this design the proxy bundle *is the broker logic*, so the brokering ceremony is authored and stored outside the zone, then synced in.
2.  **Truststores and keystores are management-plane data.** **[D]**
3.  **Debug and analytics egress asynchronously** to the management plane. **[D]**

On a boundary whose entire premise is controlling what leaves and who records it, an asynchronous egress channel to a vendor cloud is not an operational detail.

### The debug channel is the sharp edge

We treated this as the blocking question, and the documented answer is *yes by default, preventable only by non-obvious configuration, with a trap specific to the exact mechanism a broker uses.*

Debug captures *"the entire request/response flow… including all request/response parameters along with transformations applied to them."* It is cached on gateway nodes, transmitted to the control plane, persisted there for up to 24 hours, and readable by Apigee Support. **[D]** So a credential captured in a debug session leaves the credential zone and sits in a vendor cloud for a day.

The mitigation is real and correctly designed — masking happens on the gateway node *before* transmission, so masked data never leaves. **[D]** But the trap lands exactly on this use case:

> *"If you use the ServiceCallout policy to make a request, the information in the request and response for that callout **will not be masked** using the configuration elements like `requestXPaths` or `responseJSONPaths`."* **[D]**

Standard payload masking does not cover `ServiceCallout` — the mechanism that carries the operator's token to the vault and the credential back. An engineer who correctly masks their main request and response has not masked the broker's callouts, and nothing signals the omission.

Safe configuration takes four non-obvious steps: name the callout's request and response message variables, add them to the `DebugMask` `variables` element, mask the reserved default `servicecallout.request.header.Authorization` (the documented example for an inbound `Authorization` header) if the variable is unnamed, or prefix variables with `private.` to hide them entirely. **[D]** And encrypted storage buys nothing here — *"variables without the `private.` prefix are displayed in clear text in Trace and debug sessions even if the data comes from an encrypted key value map."* **[D]**

In fairness, debug is not a standing channel: only customers can trigger a session. **[D]** Which means it opens precisely when an operator is troubleshooting — the moment a credential is most likely to be flowing.

Not disqualifying on its own. But the default is unsafe, the most natural masking configuration silently misses the callout, and the failure mode is a live appliance credential in a vendor cloud for 24 hours. That is a control to prove by test, not to assert by configuration.

So the honest summary for Apigee is conditional: **apparently strong on R3, equal to Kong on R5–R9, and disqualified on R12 unless the egress question resolves favourably and the zone can tolerate a vendor control-plane dependency.** The open questions at the end of this page are what would settle it.

## Head to head

|  | Kong | Apigee | Prototype |
|----|----|----|----|
| R1 credential-zone placement | yes | runtime yes, control plane no | yes |
| R2 verify every use | EE plugin | native | **[V]** yes, alg pinned, fails closed |
| **R3 vault as the operator** | **impossible natively** | **declarative [D]/[C]** | yes |
| R4 bound by assertion | custom | flow variables | **[V]** `mintUntil` |
| R5 synthesize login response | Lua | AssignMessage | yes |
| R6 rewrite response body | Lua | JavaScript policy | yes |
| R7 synthetic↔︎real state | **node-wide shared dict** | cache/KVM, explicit key | in-process, subject-bound **[V]** |
| R8 bidirectional swap | Lua | custom | yes |
| R9 upstream session | Lua | custom | yes |
| R10 expiry vs forgery telemetry | custom | custom | **[V]** yes |
| R11 no standing **appliance** credential in identity or monitor zones | yes | yes | **[V]** on the broker path; **not** on the SSH path in the same deployment (below) |
| **R12 no vendor egress** | **yes** | **no** | yes |

The prototype uses a subject-bound map in one process's memory. **[V]** State dies with the process, so operators log in again, and it cannot span replicas; scaling out would require shared state and reintroduce the same keying hazard Kong has by default.

Two words in R11 are doing real work. The row once read "no standing credential" and was marked **[M]**, and both were wrong.

Possession is not transit. The boundary method observes what *crosses* a hop; it cannot establish what a zone *holds*. What establishes R11 is source — the appliance credential is fetched only through the credential-zone vault path, used only on the broker→appliance hop, and never written to a response. That is **[V]**. The transit half is genuinely **[M]**.

Unqualified, "no standing credential" also claims the identity zone holds no bearer material at all, which is false by construction: the gateway holds its own sessions, and one of them turned out to be the more valuable prize. A separate SSH path in the same deployment does hold an appliance credential on the identity side — that contradiction is in the [appendix](appendix.html).

## What a gateway is actually good for here

Two things, both complementary to a broker rather than replacing one.

**Operation-level authorisation.** A PAM grants a session to a *target*; once it exists, the device decides what may be done. A gateway in the path constrains *operations* — `GET /api/system/*` but not `POST /api/config/*`. For appliance management that is exactly where the risk sits: "read-only operator" versus "may change VLAN configuration" is not expressible in a session model. This is the strongest remaining case for putting one in the path.

**Token downscoping before the boundary.** Kong EE supports RFC 8693 token exchange from 3.14; Apigee can do it with policies. **[D]** Converting a broad assertion into a narrow, audience-bound, short-lived one before it crosses reduces what a recording is worth.

But there is a cheaper alternative that adds no service and no failure domain: have the identity provider issue a target-scoped token at authentication time. Whether it can is **[U]** and untested — and it is the cheapest available falsifier, worth running before any gateway work.

## Where this does not help

Neither product solves the credential problem. Both can carry out a broker flow; neither makes it safe. TTL bounding, capability-to-assertion binding, per-use verification and legible failure remain the designer's job.

Neither helps with targets whose credential *is* the bearer token — declarative bespoke is still bespoke. Neither touches SNMP or SSH. Neither reduces the identity visible at the boundary, because claim-to-header mapping reproduces it identically. Caching credential state is hazardous in both, by different mechanisms. Neither decides who renews the caller's assertion. And neither addresses the shared upstream session: the prototype holds one appliance session across operators, and any reimplementation inherits that.

## What we still do not know

- Whether *analytics* — as distinct from debug — can carry callout content. The documentation says masking *"does not affect the data that gets sent to"* analytics, which is at minimum a second channel needing its own answer. **[U]**
- Whether the identity provider can issue target-scoped, audience-bound tokens at login. **[U]**
- Whether Apigee hybrid's runtime can operate with the management plane unreachable, and for how long. **[U]**
- Whether a given environment's PAM injects in the identity zone. If it does, it is disqualified before any of this matters. **[U]**
- Licensing and cost for both, at the relevant scale. **[U]**

------------------------------------------------------------------------

**Further reading.** [The pattern](credential-broker-pattern.html) sets out the design these requirements come from. The [appendix](appendix.html) covers the evidence markers, the conformance test, and the residual risks.
