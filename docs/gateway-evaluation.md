---
layout: default
title: Gateway evaluation
---

# Can Kong or Apigee replace the credential broker?

Before building a new service, it is reasonable to ask whether an API gateway already in the estate can do the job.

The short answer is **no**. Kong and Apigee can both run custom code that implements a broker. Neither removes the need to build the browser-specific login, token substitution, per-person state, and upstream-session logic. Under the current network rules, Apigee also introduces a vendor-cloud dependency that the credential zone does not permit.

That distinction — **replace** versus **host** — is the decision this page explains:

- **Replace the broker:** use supported gateway capabilities and ordinary configuration instead of rebuilding the broker as product-specific custom code.
- **Host the broker:** write the same application-specific broker logic as a plugin, policy script, or flow running inside the gateway.

Hosting may still be operationally useful. It is not the simplification this evaluation was looking for.

Evidence markers distinguish what was proved from what was documented: **[V]** verified from source, **[D]** vendor documentation, **[C]** community or practitioner evidence, and **[U]** still unknown. The [appendix](appendix.html#how-the-claims-are-marked) defines the complete scale.

## What does the broker have to do?

The appliance accepts a shared password. The engineer authenticates with single sign-on. The path has three trust zones: the **identity zone** authenticates the engineer, the **monitor zone** records traffic, and the **credential zone** contains the broker, secret-store access, and appliance-side password use. The password must remain in the credential zone.

The working broker therefore does more than forward HTTP requests:

1.  It verifies the engineer's signed identity on every request.
2.  It asks the secret store to authorize that engineer, not merely the gateway service or pod.
3.  It obtains and uses the appliance password inside the credential zone.
4.  It answers the browser application's login request in the shape the appliance expects.
5.  It keeps the appliance's real session token and gives the browser a separate short-lived opaque token.
6.  It maps between those tokens on every later request.
7.  It maintains the upstream appliance session and distinguishes routine expiry from forged identity.

The browser behavior is the part ordinary gateway features do not solve. A single-page administration interface often checks its own browser storage before sending an authenticated request. A header added later by a gateway is invisible to that check, so the page displays the appliance login form and asks the engineer for the shared password. The broker must complete and answer the login, not merely inject a header.

## What counts as a gateway solution?

The products are evaluated in three categories:

- **Native:** a supplied product capability configured in the ordinary way.
- **Declarative composition:** supplied policies can express the behavior without general-purpose application code.
- **Custom implementation:** Lua, JavaScript, or equivalent code implements product-specific broker behavior and state.

A feature being possible through custom code does not mean the product replaces the broker. It means the product can host one.

Two environmental rules are hard admission criteria before product features matter:

1.  **Credential use happens in the credential zone.** If a gateway injects the password from the identity side, the password still crosses the recorder.
2.  **The credential zone has no vendor-cloud egress.** Broker configuration, debug captures, credentials, and telemetry must not require an external vendor control plane.

The secret store also has to be reachable from the broker without crossing the recorder. Moving the broker while pulling the password back across the boundary would recreate the original problem in the opposite direction.

## The requirements used for the decision

The requirements come from the working reference broker and its deployment. **[V]** They are grouped here by the question they answer.

### Can the product run in the required trust zone?

| Requirement | Meaning |
|---|---|
| **R1** | Runtime operates in the credential zone; the password does not enter the identity or monitor zones |
| **R11** | No standing appliance password is held in the identity or monitor zones |
| **R12** | No vendor-cloud egress leaves the credential zone |

### Does authorization remain tied to the engineer?

| Requirement | Meaning |
|---|---|
| **R2** | Verify signature, issuer, audience, and expiry on every use; fail closed |
| **R3** | The secret store authorizes the engineer, never only the pod or gateway |
| **R4** | Broker access expires no later than the identity statement that authorized it |
| **R10** | Telemetry distinguishes ordinary expiry from forged or invalid identity |

### Can it support the browser login and session?

| Requirement | Meaning |
|---|---|
| **R5** | Answer the browser application's login request rather than merely forwarding it |
| **R6** | Rewrite the login response, replacing the real appliance token with an opaque browser token |
| **R7** | Hold a per-person mapping between opaque browser tokens and real appliance sessions |
| **R8** | Substitute in both directions on every later request |
| **R9** | Maintain the upstream appliance session independently of one browser request |

R1 and R12 determine whether the product runtime can be deployed in this environment. R2 through R11 determine whether it is admissible *as a replacement* for the broker. R5 through R9 distinguish native replacement from a runtime that merely hosts custom broker code.

## Kong

### What Kong does well

Kong is fully self-hosted and can run without an external control plane. In DB-less mode it has no standing outbound configuration dependency, so it fits the no-vendor-egress rule. **[V]**

Its plugin system exposes primitives for outbound calls, response synthesis, body rewriting, and shared state. **[V]** Those primitives make a custom Lua implementation plausible; no complete Kong broker or conformance run was built here. The decisive question is whether Kong's native identity and secret systems supply the per-engineer behavior the broker requires.

### Why Kong's vault cannot authorize as the engineer

Kong receives the engineer's identity on the per-request data plane. Its vault resolves configuration secrets out of band and caches them for the node. Those two systems do not meet.

The decisive cache key in Kong 3.9.3 is: **[V]**

```lua
local function build_cache_key(reference, config_hash)
  return config_hash .. "." .. reference
end
```

There is no engineer, subject, or session in that key. The per-request API is `kong.vault.get(reference)`: it accepts a secret reference and no caller identity. **[V]** Resolution occurs on a background timer and is deliberately decoupled from request proxying. **[V]/[D]**

Enterprise editions add vault backends, but not a caller dimension. The documented HashiCorp Vault authentication methods are token, AppRole, certificate, and Kubernetes service-account identity. **[D]** Those authenticate Kong or its pod, not the engineer whose request is being handled.

Kong can bypass its vault subsystem and implement an engineer-aware secret-store exchange in custom Lua. At that point it is hosting the broker rather than replacing it.

### The state hazard in a Kong implementation

Kong's standard plugin caches use node-wide shared memory. **[V]** A custom implementation must key every opaque-to-real token mapping by the verified engineer as well as the token and target. Omitting the engineer creates a cross-user credential leak. Even with a correct key, sensitive session material resides in memory shared with other plugins on the same node.

This does not make a Kong implementation impossible. It makes the safe state model application code that must be designed, reviewed, and tested — exactly the broker work the evaluation hoped the product would eliminate.

### Edition limits

Kong OSS 3.9.3 ships only the `env` vault backend and does not include the `openid-connect` plugin. **[V]** The identity features needed for R2 require Enterprise, while R3 remains unavailable through the native vault model in either edition.

**Kong decision:** its runtime is environmentally deployable and can host custom broker code; it is not admissible as a native replacement because its vault subsystem cannot authorize per engineer.

## Apigee hybrid

### What Apigee does well

Apigee policies appear able to forward the engineer's incoming authorization token to the secret store through `ServiceCallout`: **[D]/[C]**

```xml
<Header name="Authorization">{request.header.Authorization}</Header>
```

That gives Apigee a plausible declarative route to caller-aware secret-store authorization, the requirement Kong's native vault cannot meet. `VerifyJWT` or `OAuthV2` can verify identity, and flow variables can calculate an expiry bound. **[D]**

This exact configuration was not built as a proof of concept. The documentation establishes that the mechanism exists, not that a complete working broker configuration was demonstrated.

### Why the browser flow still becomes custom implementation

Apigee can synthesize a response with `AssignMessage`. Rewriting an appliance-specific JSON body requires JavaScript in practice. Per-person token mappings require cache or key-value state, and bidirectional substitution plus upstream-session management require custom flow logic. **[D]**

Apigee's cache keys are explicit and reviewable, which is better than an opaque custom cache. They still contain no person by default. A safe implementation must add a verified subject as a key fragment. **[D]** Cache invalidation also has a residual risk: if cross-region invalidation fails, stale L1 values remain until their time to live expires. **[D]**

Again, this is broker application logic expressed in Apigee's runtime rather than functionality Apigee supplies as a broker.

### Why Apigee hybrid does not meet the no-egress rule

Apigee hybrid keeps API traffic in a customer-managed runtime plane, but that runtime depends on a Google-hosted management plane. **[D]** Three outward flows matter:

1.  The runtime synchronizer pulls proxy bundles from the management plane.
2.  Truststores and keystores are management-plane data.
3.  Debug and analytics data leave the runtime asynchronously.

In this design the proxy bundle contains the broker logic. It is authored and stored outside the credential zone, then synchronized into it. That is a vendor control-plane dependency even if ordinary appliance traffic stays local.

### The debug channel needs its own security proof

Apigee debug captures the request and response flow, including parameters and transformations. Captures are transmitted to the control plane, retained for up to 24 hours, and may be read by support personnel. **[D]**

Masking occurs in the runtime before transmission, which is the right design. **[D]** The dangerous exception is `ServiceCallout` — the mechanism that would carry the engineer's token to the secret store and receive the password. Apigee documents that standard request and response path masks do **not** mask callout request and response content. **[D]**

Safe configuration therefore has to mask the callout's named message variables, cover the default callout authorization variable, or use `private.` variables. Encrypted key-value storage does not solve this by itself; non-private variables still appear in trace and debug output. **[D]**

Debug is customer-triggered rather than continuous. That means the risky channel opens during troubleshooting — exactly when a credential is likely to be flowing. This control must be demonstrated with a debug capture, not inferred from configuration.

**Apigee decision:** plausible caller-aware authorization and capable of hosting custom broker logic, but not admissible while no vendor-cloud egress is a hard requirement. Even if that rule changed, the browser flow would remain custom implementation.

## Decision table

| Question | Kong | Apigee hybrid | Reference broker |
|---|---|---|---|
| Runs in credential zone | yes | runtime yes; management plane external | yes |
| No vendor-cloud egress | **yes** | **no** | yes |
| Verifies identity on every use | Enterprise identity plugin or custom | native policies | **[V]** yes |
| Secret store authorizes the engineer | custom exchange; not native vault | plausible declarative callout **[D]/[C]** | **[V]** yes |
| Access expires with the authorizing identity | custom lifetime logic | flow-variable logic | **[V]** yes |
| Answers browser login | custom Lua | policies plus custom logic | **[V]** yes |
| Rewrites appliance response | custom Lua | JavaScript policy | **[V]** yes |
| Holds per-person token state | custom, shared-memory hazards | explicit cache key required | **[V]** in-process and person-bound |
| Substitutes on every later request | custom Lua | custom flow logic | **[V]** yes |
| Maintains upstream session | custom Lua | custom flow logic | **[V]** yes |
| Distinguishes expiry from invalid identity | custom telemetry | custom telemetry | **[V]** yes |
| Keeps appliance password out of identity and monitor zones | possible with correct placement | runtime possible; management dependencies remain | **[V]** on broker path |
| Replaces the broker | **no** | **no** | n/a |
| Can host broker code | **yes** | **yes** | n/a |

The reference broker's state model is not production-complete. It stores person-bound mappings in one process. **[V]** State disappears when the process restarts, and it cannot span replicas. Scaling requires a shared store designed so one person's session can never be returned to another.

## What a gateway is still useful for

Rejecting a gateway as the broker does not make gateways irrelevant.

### Restricting operations

The broker grants access to a target session. Once that session exists, the appliance decides which operations the shared account may perform. A gateway can add path- or method-level controls — for example, permit `GET /api/system/*` but deny `POST /api/config/*`.

That is complementary to brokering. It narrows what may be done after access is granted; it does not solve how the shared password is obtained and concealed.

### Narrowing identity before it crosses the recorder

Both products can support token exchange or policy-based downscoping in suitable editions. **[D]** A broad company identity token can be exchanged for a shorter-lived token intended only for the broker.

The simpler alternative is to have the identity provider issue that target-scoped token directly at login. Whether the current identity provider can do so remains untested. **[U]** It is the cheapest option to investigate before adding another in-path service.

## What this evaluation does not establish

- Kong findings were verified against open source at tag `3.9.3`, commit `a643428`. Later versions may differ. **[V]**
- Apigee is closed-source. Its findings rest on vendor documentation and practitioner examples, and no complete proof of concept was built. **[D]/[C]**
- It is unknown whether Apigee analytics, distinct from debug, can carry callout content. The documentation says debug masking does not affect analytics. **[U]**
- It is unknown how long an Apigee hybrid runtime can operate while its management plane is unreachable. **[U]**
- Licensing and cost at the required scale were not evaluated. **[U]**
- Neither product changes the pattern's non-HTTP limit. SNMP and SSH remain outside this HTTPS broker design.
- Neither product removes the shared upstream appliance session. Reimplementing the broker inside either product inherits that operational and attribution limit.

## Final recommendation

Keep the credential broker as a distinct, small service with a declarative per-appliance login ceremony.

Use a gateway only for a separate, clearly stated reason: operation-level policy, identity-token downscoping, or an organizational decision to host custom broker code inside an existing runtime. Do not describe that hosting choice as replacing the broker; the security-critical behavior and state still have to be designed and implemented.

---

**Further reading.** [The pattern](credential-broker-pattern.html) explains the design these requirements come from. The [appendix](appendix.html) defines the evidence markers, conformance test, residual risks, and open questions.
