package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

// THE REGRESSION TEST FOR THE DEFECT THIS BUILD REMOVES.
//
// An observer of the boundary sees both artefacts: the capability (in the
// Authorization header) and the caller's subject (the `sub` claim, in clear).
// Before this change the steady-state path checked the token's SHAPE but not its
// SIGNATURE, so forging an assertion of the victim's subject and presenting it
// with a genuinely captured capability was accepted for the capability's
// remaining life.
//
// The request must be refused AND must never reach the target.
func TestForgedSubjectWithCapturedCapabilityIsRefusedAndNeverReachesTarget(t *testing.T) {
	var reached atomic.Int32
	appliance := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer appliance.Close()
	bao := fakeOpenBao(t)
	defer bao.Close()

	p := newTestPortal(t, appliance.URL, bao.URL)
	p.cfg.requireUserToken = true
	p.cfg.allowMachineCredential = false
	jwks := withVerifier(t, p)
	defer jwks.Close()
	srv := httptest.NewServer(p)
	defer srv.Close()

	victim := "victim@example.invalid"
	// A genuinely issued capability, as an observer would have captured it.
	captured, err := p.tokens.mint(victim)
	if err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/system/utilization", nil)
	req.Header.Set("Authorization", "Bearer "+captured)
	// The forgery: right subject, right shape, unexpired — wrong signature.
	req.Header.Set("X-Portal-User-Token", forgedJWT(t, victim, time.Now().Add(time.Hour)))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("SECURITY FAILURE: forged subject + captured capability returned %d, want 403", resp.StatusCode)
	}
	if n := reached.Load(); n != 0 {
		t.Fatalf("SECURITY FAILURE: the forged request reached the target %d time(s)", n)
	}
}

// The genuine article must still work, or the fix is just an outage.
func TestProperlySignedTokenIsAccepted(t *testing.T) {
	appliance := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer appliance.Close()
	bao := fakeOpenBao(t)
	defer bao.Close()

	p := newTestPortal(t, appliance.URL, bao.URL)
	p.cfg.requireUserToken = true
	p.cfg.allowMachineCredential = false
	jwks := withVerifier(t, p)
	defer jwks.Close()

	tok := signedJWT(t, "real@example.invalid", time.Now().Add(time.Hour))
	vc, err := p.verifyUserToken(tok)
	if err != nil {
		t.Fatalf("a correctly signed token was rejected: %v", err)
	}
	if vc.Subject != "real@example.invalid" {
		t.Fatalf("verified subject = %q", vc.Subject)
	}
}

// A valid signature from an issuer we do not trust is not an authorisation.
func TestSignedTokenFromWrongIssuerIsRefused(t *testing.T) {
	p := newTestPortal(t, "http://unused.invalid", "http://unused.invalid")
	jwks := withVerifier(t, p)
	defer jwks.Close()

	tok := signedJWTWithIssuer(t, "a@b.invalid", time.Now().Add(time.Hour),
		"https://attacker.example.invalid/oauth2/token")
	if _, err := p.verifyUserToken(tok); err == nil {
		t.Fatal("SECURITY FAILURE: accepted a validly-signed token from an untrusted issuer")
	}
}

// The algorithm must be pinned. Honouring the token's own `alg` is the classic
// confusion defect: a forged header could select "none" or a weaker family.
func TestAlgorithmIsPinnedAndNoneIsRefused(t *testing.T) {
	p := newTestPortal(t, "http://unused.invalid", "http://unused.invalid")
	jwks := withVerifier(t, p)
	defer jwks.Close()

	for _, alg := range []string{"none", "HS256", "RS512"} {
		tok := jwtWithAlg(t, alg, "a@b.invalid", time.Now().Add(time.Hour))
		if _, err := p.verifyUserToken(tok); err == nil {
			t.Fatalf("SECURITY FAILURE: accepted a token with alg=%q", alg)
		}
	}
}

// Expiry must still be enforced after the signature checks out.
func TestExpiredButCorrectlySignedTokenIsRefused(t *testing.T) {
	p := newTestPortal(t, "http://unused.invalid", "http://unused.invalid")
	jwks := withVerifier(t, p)
	defer jwks.Close()

	tok := signedJWT(t, "a@b.invalid", time.Now().Add(-time.Minute))
	if _, err := p.verifyUserToken(tok); err == nil {
		t.Fatal("SECURITY FAILURE: accepted an expired token")
	}
}

// Per-user mode without a verifier must refuse to START, rather than silently
// serving the unverified path this build exists to remove.
//
// Each omission is tested in ISOLATION. An earlier version omitted both and so
// could not tell which check fired -- mutation testing showed that disabling the
// JWKS check alone left every test passing, because the issuer check masked it.
func TestPerUserModeWithoutVerifierRefusesToStart(t *testing.T) {
	base := func(t *testing.T) {
		t.Setenv("REQUIRE_USER_TOKEN", "true")
		t.Setenv("ALLOW_MACHINE_CREDENTIAL", "false")
		t.Setenv("UPSTREAM_URL", "https://appliance.invalid")
		t.Setenv("OPENBAO_ADDR", "https://bao.invalid")
	}

	t.Run("no jwks url", func(t *testing.T) {
		base(t)
		t.Setenv("OIDC_ISSUER", "https://idp.invalid/oauth2/token") // present
		t.Setenv("OIDC_AUDIENCE", "urn:example:appliance-credential")
		t.Setenv("OIDC_JWKS_URL", "") // the omission under test
		if _, err := loadConfig(); err == nil {
			t.Fatal("SECURITY FAILURE: started in per-user mode with no signature verification")
		}
	})

	t.Run("no issuer", func(t *testing.T) {
		base(t)
		t.Setenv("OIDC_JWKS_URL", "https://idp.invalid/oauth2/jwks") // present
		t.Setenv("OIDC_AUDIENCE", "urn:example:appliance-credential")
		t.Setenv("OIDC_ISSUER", "") // the omission under test
		if _, err := loadConfig(); err == nil {
			t.Fatal("SECURITY FAILURE: started with no trusted issuer; a valid signature from any issuer would pass")
		}
	})

	// Audience is the third of the three. Unset, verification does not fail
	// loudly -- audienceContains returns true and the check is skipped -- so a
	// token the issuer minted for a DIFFERENT relying party verifies here with
	// the correct signature and the correct issuer. That is precisely the
	// token-substitution case the audience claim exists to answer.
	t.Run("no audience", func(t *testing.T) {
		base(t)
		t.Setenv("OIDC_JWKS_URL", "https://idp.invalid/oauth2/jwks") // present
		t.Setenv("OIDC_ISSUER", "https://idp.invalid/oauth2/token")  // present
		t.Setenv("OIDC_AUDIENCE", "")                                // the omission under test
		if _, err := loadConfig(); err == nil {
			t.Fatal("SECURITY FAILURE: started with audience checking disabled; a token minted for another relying party would be accepted")
		}
	})

	t.Run("all three present starts", func(t *testing.T) {
		base(t)
		t.Setenv("OIDC_JWKS_URL", "https://idp.invalid/oauth2/jwks")
		t.Setenv("OIDC_ISSUER", "https://idp.invalid/oauth2/token")
		t.Setenv("OIDC_AUDIENCE", "urn:example:appliance-credential")
		if _, err := loadConfig(); err != nil {
			t.Fatalf("refused to start with a complete configuration: %v", err)
		}
	})
}

// A capability must not outlive the assertion that authorised it. If the
// caller's token expires in two minutes, a fifteen-minute capability is
// authorisation the caller no longer holds.
func TestCapabilityCannotOutliveTheAssertion(t *testing.T) {
	p := newTestPortal(t, "http://unused.invalid", "http://unused.invalid")
	p.tokens = newTokenStore(15 * time.Minute)

	shortly := time.Now().Add(2 * time.Minute)
	tok, _, err := p.tokens.mintUntil("someone@example.invalid", shortly)
	if err != nil {
		t.Fatal(err)
	}
	p.tokens.mu.Lock()
	got := p.tokens.issued[tok].expires
	p.tokens.mu.Unlock()

	if got.After(shortly) {
		t.Fatalf("SECURITY FAILURE: capability expires %v, after the assertion at %v", got, shortly)
	}

	// The store's own TTL still applies when the assertion outlasts it.
	far := time.Now().Add(time.Hour)
	tok2, _, err := p.tokens.mintUntil("someone@example.invalid", far)
	if err != nil {
		t.Fatal(err)
	}
	p.tokens.mu.Lock()
	got2 := p.tokens.issued[tok2].expires
	p.tokens.mu.Unlock()
	if got2.After(time.Now().Add(16 * time.Minute)) {
		t.Fatalf("capability outlived the store TTL: %v", got2)
	}
}

// Guards the WIRING, not just the helper. Mutation testing showed the deadline
// could be dropped on the way from the verified token to mintUntil with every
// test still passing, because the helper was tested in isolation.
func TestLoginBoundsTheCapabilityByTheTokensExpiry(t *testing.T) {
	appliance := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"restful_res":{"token":"appliance-tok","timeout":1800}}`))
	}))
	defer appliance.Close()
	bao := fakeOpenBao(t)
	defer bao.Close()

	p := newTestPortal(t, appliance.URL, bao.URL)
	p.cfg.requireUserToken = true
	p.cfg.allowMachineCredential = false
	p.tokens = newTokenStore(15 * time.Minute) // deliberately longer than the token
	srv := httptest.NewServer(p)
	defer srv.Close()

	// An assertion with far less life than the capability TTL.
	tokenExpiry := time.Now().Add(90 * time.Second)
	req, _ := http.NewRequest(http.MethodPatch, srv.URL+p.cfg.loginPath, nil)
	req.Header.Set("X-Portal-User-Token", signedJWT(t, "someone@example.invalid", tokenExpiry))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	p.tokens.mu.Lock()
	defer p.tokens.mu.Unlock()
	if len(p.tokens.issued) == 0 {
		t.Fatal("login minted no capability")
	}
	for tok, rec := range p.tokens.issued {
		if rec.expires.After(tokenExpiry) {
			t.Fatalf("SECURITY FAILURE: capability %s… expires %v, after the assertion at %v",
				tok[:8], rec.expires.Format(time.TimeOnly), tokenExpiry.Format(time.TimeOnly))
		}
	}
}

// §11 requires refusing a destination the grant cannot have intended. url.Parse
// is not that check: it accepts "file:///etc/passwd", "javascript:alert(1)", a
// bare "not-a-url" and the empty string without error, so a service configured
// with any of them starts and fails later -- while holding the appliance
// password.
//
// The addresses matter more than the shapes. 169.254.169.254 is the cloud
// instance metadata service; a broker pointed there would present the appliance
// credential to an endpoint that returns the node's own identity.
func TestUpstreamURLRefusesImplausibleDestinations(t *testing.T) {
	refuse := []struct{ raw, why string }{
		{"file:///etc/passwd", "a file URL is not an appliance"},
		{"javascript:alert(1)", "not an HTTP scheme"},
		{"not-a-url", "no scheme and no host"},
		{"https://", "no host"},
		{"http://169.254.169.254", "cloud metadata service -- would receive the appliance credential"},
		{"http://169.254.169.254:80/latest/meta-data/", "metadata service with a path"},
		{"https://127.0.0.1:8443", "loopback reaches this pod, not an appliance"},
		{"https://[::1]:8443", "IPv6 loopback"},
		{"https://0.0.0.0", "the unspecified address"},
	}
	for _, c := range refuse {
		t.Run(c.raw, func(t *testing.T) {
			u, err := url.Parse(c.raw)
			if err != nil {
				return // rejected before us; fine
			}
			if err := validateUpstreamURL(u); err == nil {
				t.Fatalf("SECURITY FAILURE: accepted %q as an upstream (%s)", c.raw, c.why)
			}
		})
	}

	// Plausible destinations must still work, or the guard is a denial of
	// service rather than a control. A hostname is NOT resolved here: startup
	// would then depend on DNS, and resolving would not bind the result anyway.
	for _, raw := range []string{
		"https://192.0.2.20",
		"https://192.0.2.20:8443",
		"https://appliance.example.internal",
		"http://appliance.example.internal:8080/base",
	} {
		t.Run("allow "+raw, func(t *testing.T) {
			u, err := url.Parse(raw)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if err := validateUpstreamURL(u); err != nil {
				t.Fatalf("refused a plausible upstream %q: %v", raw, err)
			}
		})
	}
}

// The guard above tests the RULE. This tests that the rule is WIRED IN.
//
// Written after a mutation check embarrassed the first version: deleting the
// validateUpstreamURL call from loadConfig left the rule's own test passing,
// because that test calls the function directly. A control that is implemented
// but not invoked is not a control, and only a test that goes through the real
// configuration path can tell the difference.
func TestLoadConfigRefusesAnImplausibleUpstream(t *testing.T) {
	base := func(t *testing.T) {
		t.Setenv("REQUIRE_USER_TOKEN", "true")
		t.Setenv("ALLOW_MACHINE_CREDENTIAL", "false")
		t.Setenv("OPENBAO_ADDR", "https://bao.invalid")
		t.Setenv("OIDC_JWKS_URL", "https://idp.invalid/oauth2/jwks")
		t.Setenv("OIDC_ISSUER", "https://idp.invalid/oauth2/token")
		t.Setenv("OIDC_AUDIENCE", "urn:example:appliance-credential")
	}

	t.Run("metadata service", func(t *testing.T) {
		base(t)
		t.Setenv("UPSTREAM_URL", "http://169.254.169.254")
		if _, err := loadConfig(); err == nil {
			t.Fatal("SECURITY FAILURE: started with the cloud metadata service as its upstream; the appliance credential would be sent there")
		}
	})

	t.Run("non-http scheme", func(t *testing.T) {
		base(t)
		t.Setenv("UPSTREAM_URL", "file:///etc/passwd")
		if _, err := loadConfig(); err == nil {
			t.Fatal("started with a file:// upstream")
		}
	})

	t.Run("plausible appliance starts", func(t *testing.T) {
		base(t)
		t.Setenv("UPSTREAM_URL", "https://192.0.2.20")
		if _, err := loadConfig(); err != nil {
			t.Fatalf("refused a plausible appliance: %v", err)
		}
	})
}
