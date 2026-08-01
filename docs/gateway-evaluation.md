---
layout: default
title: Gateway evaluation
---

# API gateways in the brokered-credential pattern — Kong and Apigee

Supersedes `kong-evaluation.md` and `apigee-evaluation.md`, both of which evaluated
a simpler problem than the one that actually exists. Evaluation only — no
implementation.

## Why this was rewritten

The earlier documents asked "can a gateway inject a per-user credential into an
upstream request?" That is not the requirement. The working prototype does not
inject a header, and the reason it cannot is structural rather than incidental.
The requirement set in §2 is derived from the shipped code, not from a
conceptualisation of it — and against that set, both products score very
differently.

A log of the wrong turns is kept in §9 rather than being quietly removed, because
two of them were reversals that would have produced a confident wrong
recommendation.

## Evidence markers

| Marker | Meaning |
|---|---|
| **[V]** | Verified from source — `Kong/kong` @ tag `3.9.3`, commit `a643428`, or the prototype's own source |
| **[G]** | Verified from the GitHub API |
| **[D]** | Vendor documentation (Apigee is closed-source; documentation is the ceiling) |
| **[M]** | Measured in the deployed rig against the real appliance |
| **[U]** | Open question, stated as such |

Kong's findings are source-verified. Apigee's cannot be, and are one confidence
level lower throughout. That asymmetry matters: Kong's decisive finding was three
lines of Lua that no documentation would have exposed.

---

## 1. The architecture the requirement sits in

```
operator ──▶ PAM (high side)  ──▶ [inspecting boundary] ──▶ broker (low side) ──▶ appliance
                 │                                              │
         OIDC login, session                          vault (must NOT be reached
         recording, forwards                           across the boundary)
         identity only
```

Two placement rules follow, and they are prior to any capability question.

**Credential injection must happen below the boundary.** If PAM injects from the
high side, the credential crosses the inspector. A recording of a credential is not
a record of an event — it is an unexpired key held by whoever holds the recording.
The appliance password does not expire; the recording outlives every control around
it. Only expiring, bound, scoped material may cross.

**The vault must not be reached across the boundary either.** Moving the broker
low-side is defeated if its vault call drags the credential back across in the
opposite direction. This is easy to miss because "the broker is now low-side" reads
as sufficient. In the prototype the vault path does not traverse the monitor;
a manifest exists (`45-monitor-egress-openbao.yaml`) that deliberately violates this
as a labelled experiment variant, not as the baseline. **[V]**

**Consequence for procurement:** a PAM product that performs credential injection
from the high side is architecturally unusable here, regardless of the quality of
its session recording. That is a hard filter, and an easy one to discover late,
because injection is marketed as a capability rather than as a placement decision.

---

## 2. What is actually required

Derived from `services/switch-portal/main.go` (1,184 lines) and the surrounding
deployment. **[V]**

The prototype is a **reverse proxy** (`httputil.ReverseProxy`) — it does forward
traffic. But it does not inject a credential into a forwarded request. It
*answers* the login request:

1. It holds one authenticated upstream session, logging in itself with a credential
   fetched from OpenBao at runtime.
2. When the SPA posts to the login endpoint, it ignores what was submitted and
   replies with the upstream's own login response, **token field replaced by an
   opaque synthetic token**.
3. On every subsequent request it swaps the synthetic token back to the real one
   before forwarding.

### Why header injection cannot work

Stated in the source, and general beyond this appliance:

> A SPA decides whether it is logged in by reading its **own browser storage**. That
> check happens inside the operator's browser before any request exists, so an
> injected header is invisible to it and the operator is shown a login form —
> forcing them to type the very credential we are concealing.

This is not "works poorly." For a single-page-application admin UI, header
injection is structurally incapable of producing a logged-in session. The class of
targets where a gateway's natural capability — header manipulation on a proxied
request — actually applies is therefore **narrower than the pattern paper currently
implies**, and §16's Class A should be qualified accordingly.

### The requirement set

| # | Requirement | Source |
|---|---|---|
| R1 | Run **below** the inspecting boundary, no credential above it | architecture |
| R2 | Verify the caller's assertion on **every use** — signature, `iss`, `aud`, `exp`, `nbf`, algorithm **pinned**, fail closed | **[V]** `verify.go` |
| R3 | Authenticate to the vault **as the operator**, never as the pod or gateway | requirement |
| R4 | Bound the capability by `min(capability_ttl, assertion_remaining)` | **[V]** `mintUntil` |
| R5 | **Synthesize a response** to the SPA's login POST | **[V]** |
| R6 | **Rewrite the response body**, substituting a synthetic token | **[V]** |
| R7 | Hold **server-side synthetic↔real token state** | **[V]** |
| R8 | Bidirectional substitution on **every** subsequent request | **[V]** |
| R9 | Maintain a long-lived upstream appliance session | **[V]** |
| R10 | Telemetry distinguishing expiry from forgery | **[V]** |
| R11 | No standing credential held above the boundary | architecture |
| R12 | No vendor egress out of the low zone | environment |

R5–R9 are the ones that decide this evaluation, and none of them appeared in the
earlier documents.

---

## 3. Kong

### The structural finding, unchanged

Kong's vault subsystem cannot satisfy **R3**, and this is verifiable in three lines.
`kong/pdk/vault.lua`: **[V]**

```lua
local function build_cache_key(reference, config_hash)
  return config_hash .. "." .. reference
end
```

No caller, no subject, no session. The cache is `ngx.shared.kong_secrets` — a
node-wide 5 MB zone **[V]** — resolution runs on a background timer with a default
`ROTATION_INTERVAL` of 60 s **[V]**, and Kong's documentation states this
*"decouples the secret rotation process from proxying."* **[D]** The entire
per-request API is `kong.vault.get(reference)`, which accepts a reference and
nothing else. **[V]**

Enterprise adds backends, not a different model. Kong authenticates to HashiCorp
Vault via `token`, `approle`, `cert`, or `kubernetes` — the last using *"the service
account JWT token mounted in the pod."* **[D]** That is the pod-identity
anti-pattern R3 exists to forbid.

The same shape recurs in the Enterprise `upstream-oauth` plugin: it uses the client
credentials grant and caches by *"a hash of all values configured under the
`config.oauth` key"*, such that instances with identical configuration **share
cached tokens**. **[D]**

> Kong holds the caller's identity, and Kong has a vault client. They are on
> different planes and are not connected. Identity is data-plane, per request.
> Secrets are configuration-plane, resolved out-of-band, cached node-wide by
> configuration hash.

### Product reality

- Latest OSS release **3.9.3**; last OSS *minor* was **3.9.0, Dec 2024**. **[G]**
- `master` declares **3.10.0**. **[G]** Enterprise documentation describes **3.14**
  and **3.15** features. **[D]**
- OSS ships **one** vault backend: `env`. **[V]** No OpenBao integration exists in OSS.
- There is **no `openid-connect` plugin in OSS**. **[V]**

So R2 and R3 both require Enterprise, on a version line roughly five minors ahead
of anything Apache-2.0.

### Against R5–R9

All achievable, all in Lua. `resty.http` is available to plugins **[V]**, so
outbound calls, response synthesis and token substitution are all writable. The
obstacle is not possibility.

The obstacle is **R7 combined with Kong's caching model**. Every caching helper
offered to a plugin author is node-wide shared memory — `kong.cache` is backed by
`ngx.shared` dicts (`lua_shared_dict kong 5m`, `kong_db_cache`, …). **[V]** The
idiomatic way to hold synthetic↔real token state caches it in a dictionary shared
across every worker and every plugin on the node. Key it without the subject and it
is a cross-user credential leak; key it correctly and the material still sits in
shared memory readable by any other plugin on that node.

That is the first thing a competent Lua author reaches for, and it is wrong here in
a way that would not surface in testing.

### Verdict

**Can host the broker; provides none of it.** Kong contributes its proxy runtime and
plugin lifecycle. R2–R9 are all custom code. R3 is impossible through Kong's own
mechanisms and must be written around them.

**Kong's one decisive advantage is R12:** it is fully self-hosted, needs no external
control plane, and in DB-less mode has no outbound dependency at all. It can live in
a restricted zone with zero egress.

---

## 4. Apigee

### Where it is genuinely better

**R3 is satisfied declaratively.** Apigee does not attempt credential retrieval via
a vault-reference mechanism; it exposes `ServiceCallout`, an arbitrary HTTP call
mid-flow with access to the incoming request — including the caller's token: **[D]/[C]**

```xml
<Header name="Authorization">request.header.Authorization</Header>
```

The vault sees the operator, not the gateway. This is the requirement Kong cannot
meet, met without custom code.

**R2** is `VerifyJWT`/`OAuthV2`. **R4** is arithmetic over flow variables. **[D]**

### Where it stops being declarative

**R5** (synthesize the login response) is expressible with `AssignMessage`. **R6**
(rewrite the response body to substitute a token) needs a `JavaScript` policy in
practice. **R7** (synthetic↔real state) needs cache or KVM. **R8** and **R9** are
custom flow logic.

So the "six declarative policies" claim from the superseded document holds only for
the header-injection problem, which is not the problem. Against R5–R9, Apigee is in
the same position as Kong — custom code plus cached state — with better ergonomics
and a reviewable artefact, but not a categorical advantage.

**The cache hazard is present here too**, in a milder form. Apigee composes keys as
`scope | prefix__keyfragment[…]`, with `Scope` ∈ {Global, Application, Proxy, Target,
**Exclusive** (default)}. **[D]** Even `Exclusive` resolves to
`org__env__proxy__revision__endpoint` — **no user component**. Caching per-operator
state without an explicit `<KeyFragment ref="…subject…"/>` shares it across every
caller of that proxy. Better than Kong on two counts — the key composition is
declarative and reviewable, and the default is the *most* specific scope — but the
failure is the same failure.

Also documented: invalidation broadcasts to all message processors in all regions,
and **if the broadcast fails the stale value remains in L1 cache until TTL expiry**.
**[D]** For cached credential state that is a revocation gap.

### Where it fails outright

**R12.** Only Apigee hybrid is admissible for a restricted zone, and hybrid splits
into a Google-hosted management plane and a customer-managed runtime plane. **[D]**
Traffic locality is correct — *"All API traffic passes through and is processed
within the runtime plane"* **[D]** — but three flows cross outward:

1. **Proxy bundles come from Google.** The Synchronizer polls the management plane
   and pulls down runtime contracts. **[D]** In this design the proxy bundle *is the
   broker logic* — so the credential-brokering ceremony is authored and stored
   outside the zone, then synced in.
2. **Truststores and keystores are management-plane data.** **[D]**
3. **Debug and analytics egress asynchronously** to the management plane. **[D]**

On a boundary whose entire premise is controlling what leaves and who records it, an
asynchronous egress channel to a vendor cloud is not an operational detail.

### The debug-egress question — investigated, and answered

This was flagged as the blocking question. It is now settled, and the answer is
**"yes by default, preventable only by non-obvious configuration, with a trap
specific to the exact mechanism the broker uses."** **[D]**

**What debug captures.** *"Apigee lets you collect debug data, which shows the
entire request/response flow of your API proxies. This includes all
request/response parameters along with transformations applied to them at policy
execution time."* **[D]**

**Where it goes and for how long.** *"Apigee gateway nodes collect debug session
data and cache it internally, before transmitting that data to the control plane in
the Cloud."* **[D]** *"Debug data is persisted in the management plane for up to 24
hours."* **[D]** *"Apigee Support has read-only permission to Debug data."* **[D]**

So a credential captured in a debug session leaves the restricted zone, lands in
Google's control plane, persists 24 hours, and is readable by vendor support staff.

**The mitigation is real.** Masking happens *before* egress: *"Apigee performs the
masking in the gateway nodes, before transmitting the debug session data to the
control plane."* **[D]** That is the right design — masked data never leaves.

**But the trap is precise, and it lands exactly on this use case:**

> *"If you use the ServiceCallout policy to make a request, the information in the
> request and response for that callout **will not be masked** using the
> configuration elements like `requestXPaths` or `responseJSONPaths`."* **[D]**

Standard payload masking does not cover `ServiceCallout` — the mechanism that both
carries the operator's token to the vault and carries the credential back. An
engineer who correctly masks their main request and response has **not** masked the
broker's callouts, and nothing in that configuration signals the omission.

Correct configuration requires all of:

1. Explicitly naming the `ServiceCallout` request and response message variables.
2. Adding those variable names to the `variables` element of the `DebugMask`.
3. If the variable is left unnamed, masking the *reserved default* —
   `servicecallout.request.header.Authorization` is the documented example for
   hiding an inbound `Authorization` header. **[D]**
4. Or prefixing variables with `private.`, which hides them entirely rather than
   masking them. **[D]**

**And one more sharp edge:** *"Variables without the `private.` prefix are displayed
in clear text in Trace and debug sessions even if the data comes from an encrypted
data store such as an encrypted key value map."* **[D]** Encrypted KVM storage does
**not** protect a value in debug output. Encryption at rest buys nothing here.

**Mitigating factor, stated fairly:** debug is not continuous. *"Only customers can
trigger a debug session."* **[D]** This is not a standing egress channel — it is an
egress channel that opens when an operator troubleshoots. Which is precisely the
moment a credential is most likely to be flowing.

**Verdict on the question:** not disqualifying on its own, because the mitigation
exists and runs before transmission. But the safe configuration is four
non-obvious steps, the default is unsafe, the most natural masking configuration
silently misses the callout, and the failure mode is a live appliance credential
sitting in a vendor cloud for 24 hours. In a zone whose defining property is
controlling what leaves, that is a control that must be proven by test rather than
asserted by configuration.

**Still open:** whether *analytics* — as distinct from debug — can carry callout
content. The documentation notes masking *"does not affect the data that gets sent
to"* analytics, which is at minimum a second channel needing its own answer. **[U]**

### Verdict

**Strong on R3, equal to Kong on R5–R9, disqualified on R12** unless the egress
question resolves favourably and the zone can tolerate a vendor control-plane
dependency.

---

## 5. Head-to-head against the real requirements

| | Kong | Apigee | Prototype |
|---|---|---|---|
| R1 low-side placement | yes | runtime yes, control plane no | yes |
| R2 verify every use | EE plugin | native | **[V]** yes, alg pinned, fails closed |
| **R3 vault as the operator** | **impossible natively** | **declarative** | yes |
| R4 bound by assertion | custom | flow variables | **[V]** `mintUntil` |
| R5 synthesize login response | Lua | AssignMessage | yes |
| R6 rewrite response body | Lua | JavaScript policy | yes |
| R7 synthetic↔real state | **node-wide shared dict** | cache/KVM, explicit key | in-process |
| R8 bidirectional swap | Lua | custom | yes |
| R9 upstream session | Lua | custom | yes |
| R10 expiry vs forgery telemetry | custom | custom | **[V]** yes |
| R11 no credential above boundary | yes | yes | **[M]** yes |
| **R12 no vendor egress** | **yes** | **no** | yes |

---

## 6. Verdict

**This is not a gateway-shaped problem.**

It is a stateful protocol adapter that happens to sit in a request path. Its
difficulty is concentrated in R5–R9, and neither product provides any of them —
both merely host them. The purpose-built proxy already built and measured is closer
to correct than either, and its size is mostly a consequence of the SPA constraint
rather than incidental complexity.

The two products fail differently, and neither failure is repairable by
configuration:

- **Kong** cannot express R3 through its own mechanisms, and its state model is
  actively hazardous for R7. It wins decisively on R12.
- **Apigee** expresses R3 cleanly and is the better authoring environment, but
  requires a vendor control-plane dependency and outbound egress from the
  restricted zone, which R12 forbids.

**Recommendation: retain a purpose-built broker.** Adopt a gateway only for the
roles below, where one genuinely adds something.

---

## 7. What a gateway is actually good for here

Two things, both complementary to the broker rather than replacing it.

**Operation-level authorisation.** PAM is coarse-grained — it grants a session to a
*target*. Once the session exists, the device decides what may be done. A gateway in
the path constrains *operations*: `GET /api/system/*` but not `POST /api/config/*`.
For appliance management that is exactly where the risk sits — "read-only operator"
versus "may change VLAN configuration" is not expressible in PAM's session model.
This is the strongest remaining case, and neither evaluation document previously
made it.

**Token downscoping before the boundary.** Kong EE supports RFC 8693 token exchange
(3.14+) **[D]**; Apigee can do it via policies. Converting a broad assertion into a
narrow, audience-bound, short-lived one before it crosses reduces what a recording
is worth.

But this must clear the "do not add services" bar, and there is a cheaper
alternative: have the IdP issue a target-scoped token at authentication time — no
new service, no new failure domain. Whether WSO2 can do this is **[U]** and
untested. It is the cheapest falsifier available and should be run before any
gateway work.

---

## 8. Where this does not help

- **Neither product solves the credential problem.** Both can carry out a broker
  flow; neither makes it safe. TTL bounding, capability-to-assertion binding,
  per-use verification and legible failure remain the designer's job.
- **Neither helps with Class B ceremonies.** Declarative bespoke is still bespoke.
- **Class C (SNMP, SSH) is untouched.**
- **PII is untouched** — claim-to-header mapping reproduces it identically.
- **Caching credential state is hazardous in both**, by different mechanisms.
- **Neither decides who renews the caller's assertion.**
- **Neither addresses the shared upstream session.** The prototype holds one
  appliance session across operators; any reimplementation inherits that, and
  per-operator upstream sessions would be a materially harder build.

---

## 9. Corrections log

Kept because two of these were reversals that would have produced a confident wrong
recommendation, and because the pattern of error is informative.

1. **"Apigee reverses the verdict on Role B."** Overstated. It reverses it for
   header injection, which is not the requirement. Against R5–R9 the two products
   are close.
2. **"PAM ownership makes the broker role irrelevant."** Wrong. PAM sits *upstream*
   of the broker and does session recording and authentication; the vault retrieval
   remains a distinct component. The broker was never a PAM replacement.
3. **"Kong cannot do Role B in any edition."** Too strong without qualification. Its
   *built-in* mechanisms cannot; custom Lua can. The correct claim is that Kong
   provides nothing toward it.
4. **H4 (DB-less forecloses per-user state)** — falsified. The `session` plugin
   still stores state. Deployment mode is irrelevant to the binding constraint.
5. **Evaluating header injection at all** — the root error. It came from reasoning
   about the pattern rather than reading the implementation. The SPA constraint was
   documented in the first 30 lines of `main.go` throughout.

The common thread: four of five errors came from evaluating a model of the system
instead of the system. The prototype's source settled each one in minutes.

---

## 10. Open items

- ~~Whether an Apigee `ServiceCallout` response containing a credential can surface
  in debug egress.~~ **Answered — see §4.** Yes by default; preventable by explicit
  `DebugMask` `variables` entries naming the callout messages, or a `private.`
  prefix. Standard payload masking does **not** cover ServiceCallout. Encrypted KVM
  does not protect values in debug output.
- **[U]** Whether *analytics* (distinct from debug) can carry callout content.
  Documentation states masking does not affect data sent to analytics. Second
  channel, unanswered.
- **[U]** Whether WSO2 can issue target-scoped, audience-bound tokens at login.
  Cheapest available falsifier; would settle §7's second case without deploying
  anything.
- **[U]** Whether Apigee hybrid's runtime can operate with the management plane
  unreachable, and for how long.
- **[U]** Whether the target environment's PAM performs injection high-side. If so
  it is disqualified by §1 before any of this matters.
- **[U]** Licensing and cost for both, at the relevant scale.
