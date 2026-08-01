# Reference implementation

A working broker for the pattern in [`docs/`](../docs/credential-broker-pattern.md), and
the zone simulation used to measure it.

This is a reference, not a product. It exists so the pattern's claims can be checked against
something that runs, and so the conformance test has something to run against.

```
broker/    the broker itself — assertion verification, per-user vault exchange,
           SPA login interception, synthetic tokens
deploy/    manifests and scripts for the three-zone simulation, plus the
           boundary experiment
```

---

## What the broker actually does

Read `main.go`'s header comment first, then `verify.go`'s. Between them they explain the two
things that are not obvious from the code:

**It answers the login rather than injecting a header.** A single-page admin UI decides
whether it is logged in by reading its own browser storage, before any request exists — so an
injected header is invisible to it. The broker holds one authenticated upstream session,
replies to the SPA's login with the appliance's own response body but with the session token
replaced by an opaque synthetic one, and swaps it back on every subsequent request.

**It verifies the caller's assertion on every request, not at login.** `verify.go` documents
why: checking shape and expiry alone left the subject binding decorative, because an observer
of the boundary can see both the capability and the `sub` claim and forge an unsigned
assertion carrying a victim's subject.

## Build order

If you are reimplementing this rather than reading it, this is the order in which each piece
becomes testable.

**1. Assertion verification.** `verify.go` plus `verify_test.go`. Signature, issuer,
audience, expiry; algorithm pinned; keys fetched from the issuer's published key set and
cached with a bounded TTL. Get this working before anything touches a secret store — every
later decision depends on the subject being authenticated rather than merely present.

**2. Per-user credential fetch.** `openbao.loginWithUserToken` → `readSecretWith`. The caller's
token is exchanged for a store token; the store authorises the *operator*. The
machine-identity path (`fetchCredential`) exists as a fallback and is gated behind
`ALLOW_MACHINE_CREDENTIAL` — if you are writing this fresh, do not implement it first, or the
per-user path will never be exercised.

**3. Upstream session.** `upstreamSession.ensure` / `loginLocked`. One authenticated session
against the appliance, established with the fetched credential. Note it is shared across
callers; see the residual risk in the paper's §15.

**4. Synthetic token substitution.** The login interception and the bidirectional swap. This
is the part with no equivalent in any API gateway, and the part that makes browser callers
work.

**5. The proxy.** Everything above is reachable through an ordinary reverse proxy once the
pieces exist.

## What this was tested against

The pattern names roles, not products — a PAM gateway, an identity provider, a vault, a
monitor, an appliance. Any implementation of those roles should work. But claims in the
paper are only checkable if you know what produced them, so the stack behind the measured
results was:

| Role | Product |
|---|---|
| PAM gateway | Warpgate, with two patches contributed upstream — do not forward the gateway's own session cookie, and forward the SSO access token |
| Identity provider | WSO2 Identity Server |
| Vault | OpenBao (the code speaks the Vault HTTP API) |
| Monitor | mitmproxy |
| Appliance | a TRENDnet managed switch, whose admin UI is a single-page application — which is why §9 of the paper exists |

Environment variables retain the `OPENBAO_` prefix because the code speaks that API
specifically; renaming them to `VAULT_` would imply a portability the implementation has not
been tested for.

## Prerequisites

- **Go 1.24** or later (`go.mod` sets the floor)
- For the simulation only: a Kubernetes cluster with a CNI that enforces
  `NetworkPolicy`. The FQDN egress rule in `50-fqdn-egress.yaml` is a
  `CiliumNetworkPolicy` — on a cluster without Cilium, that one policy will not
  apply and the identity zone's egress will be broader than the design intends.
- An OIDC issuer publishing a JWKS endpoint, and a secret store speaking the
  OpenBao/Vault HTTP API.

## Running it

```bash
cd broker
go build -o broker .

REQUIRE_USER_TOKEN=true \
OIDC_JWKS_URL=https://idp.example.internal/oauth2/jwks \
OIDC_ISSUER=https://idp.example.internal/oauth2/token \
OIDC_AUDIENCE=urn:example:appliance-credential \
OPENBAO_ADDR=https://vault.example.internal \
UPSTREAM_URL=https://192.0.2.20 \
./broker
```

It will refuse to start if `REQUIRE_USER_TOKEN` is set without a key set, an
issuer and an audience, or if `UPSTREAM_URL` names a destination no appliance
could plausibly live on. That is deliberate — see the guards below. With those
six set it listens on `:8080` and expects the caller's assertion in
`X-Portal-User-Token`.

To exercise it you need an assertion the configured issuer would sign. The tests
do this with a local key pair; see `verify_testhelpers_test.go` for the shape.

## Configuration

The full surface is in `loadConfig`. The ones that change behaviour rather than endpoints:

Defaults below are the values in `loadConfig`. Blank means required.

| Variable | Default | Effect |
|---|---|---|
| `REQUIRE_USER_TOKEN` | `true` | per-user mode. With this set, `OIDC_JWKS_URL` and `OIDC_ISSUER` are mandatory and startup **fails** without them |
| `USER_TOKEN_HEADER` | `X-Portal-User-Token` | where the forwarded assertion arrives |
| `OIDC_JWKS_URL`, `OIDC_ISSUER`, `OIDC_AUDIENCE` | — | verification inputs. All three are **required** in per-user mode and startup fails without them. Audience was once optional, and unset it did not weaken verification loudly — the check was skipped, so a token minted for a different relying party verified here with the correct signature and issuer |
| `OPENBAO_JWT_MOUNT`, `OPENBAO_JWT_ROLE` | `oidc`, `switch-portal` | the per-user exchange |
| `ALLOW_MACHINE_CREDENTIAL` | `false` | enables the workload-identity fallback. Defaults to false, and is **mutually exclusive** with `REQUIRE_USER_TOKEN` — setting both refuses to start, because pre-warming the shared session with machine identity stops per-user authorisation gating the fetch |
| `ALLOW_NO_GATEWAY_AUTH` | `false` | removes the requirement for a shared secret from the gateway |
| `LOGIN_PATH`, `TOKEN_FIELD`, `TIMEOUT_FIELD`, `REFRESH_PATH` | `/api/system/login`, `token`, `timeout`, `/api/token_refresh` | four of the five per-target parameters in the paper's §8. The fifth — **request shape** — is not configurable here: the login body is hardcoded as `{"user":…,"password":…}` JSON and the method as `PATCH`. A target using a different shape needs code, not configuration |
| `SYNTHETIC_TOKEN_TTL` | `15m` | lifetime of the handle given to the browser |

Four guards are worth knowing because they are the ones that will stop you at startup:

- `REQUIRE_USER_TOKEN` set without a key set or issuer → refuses to start rather than falling
  back to an unverified check
- `REQUIRE_USER_TOKEN` set without an audience → refuses to start. Unset, the audience check
  is skipped rather than failed, so a token minted for a different relying party is accepted
- `REQUIRE_USER_TOKEN` false without `GATEWAY_SHARED_SECRET` → refuses to start, because the
  broker would then be trusting anything that can reach it
- `UPSTREAM_URL` naming a non-HTTP scheme, no host, or a loopback / link-local / unspecified
  / multicast address → refuses to start. `169.254.169.254` is the case that matters: it is
  the cloud metadata service, and a broker pointed there would send it the appliance
  credential

All four exist because the failure they prevent is silent. A broker that starts and serves is
indistinguishable from a broker that starts and serves *safely*.

## Running the tests

```
cd broker && go test ./...
```

The verification tests are the ones to read: `verify_test.go` covers rejection of a forged
assertion carrying a valid-looking subject, which is the defect the whole file exists to
close.

## The simulation

`deploy/` brings up three namespaces — identity, monitor, credential — with the network
policies that enforce the boundary, a stub target, and an inspecting middlebox.

```
deploy/scripts/setup.sh              stand up the zones and stubs
deploy/scripts/experiment-boundary.sh  run the boundary tests (T1–T4)
deploy/scripts/teardown.sh           remove it
```

`setup.sh` applies every manifest except those carrying a `zone-sim/variant:` label, which are
opt-in experiments with their own apply/revert instructions. One of those variants
deliberately lets the monitor reach the secret store — it exists to demonstrate the failure,
not to be enabled.

Two things the scripts do that are worth copying:

- **`teardown.sh` accepts a `NAMESPACES` override**, so an older generation can be removed
  without destroying a current deployment. Namespaces cannot be renamed in place, so a rename
  leaves a live rig under names the current manifests no longer mention.
- **`setup.sh` preserves the monitor's upstream** across re-runs. The manifest hardcodes the
  stub, so re-applying it silently reverts a monitor that had been pointed at the real broker
  — and the symptom is that everything looks healthy while nothing real is being tested.

## Conformance

The paper's §13 defines the test this simulation exists to support. Two rules decide whether a
run means anything:

- record **every** header name, not a watchlist — a watchlist can prove presence, never absence
- pair the boundary observation with a **response-side signal**, because observations are
  recorded before forwarding and therefore look healthy against a stub

## Known limits of this implementation

- one upstream appliance session is shared across operators
- a workload-identity fallback exists (`ALLOW_MACHINE_CREDENTIAL`). It is off by default and
  cannot be combined with per-user mode — the two are mutually exclusive at startup
- §8 of the paper claims a new target costs five parameters. This implementation
  parameterises four; the login request shape is hardcoded. The claim holds for targets
  matching that shape and overstates for the rest
- renewal of the caller's assertion is implemented; its capture is verified, its firing is not
- **§11's destination guard is implemented at startup, not at dial time.** Redirects are
  refused on every credential-carrying client (`refuseRedirects`, with a regression test
  asserting the redirect target received nothing), and `validateUpstreamURL` rejects a
  non-HTTP scheme, a missing host, and loopback / link-local / unspecified / multicast
  addresses — including `169.254.169.254`, the cloud metadata service. What is **not**
  implemented is dial-time canonicalisation: a hostname that resolves to a permitted address
  at startup and a blocked one later is not caught. Defeating DNS rebinding requires binding
  the resolved address in the transport at connection time. Deployments needing that must
  supply it at the network layer
- **the fail-closed and revocation rules in §11 are partial.** Signing-key refresh fails
  closed and there is no credential cache, but capability state is in process memory only,
  there is no audit-availability gate, and revocation is not atomic with draining in-flight
  work. Treat that table as requirements, not as a description of this code
- SNMP, SSH and other non-HTTP targets are out of scope entirely — see Class C in the
  paper's §8. Note the deployment in `deploy/` also runs an SSH path to the same appliance
  that resolves its credential on the identity side; it is outside this pattern and is
  documented in the paper's §15 as a contradiction rather than a feature
- identifiers throughout are documentation placeholders — nothing here is a live endpoint
