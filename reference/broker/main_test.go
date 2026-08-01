package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	realToken       = "REAL-APPLIANCE-TOKEN-do-not-leak"
	appliancePasswd = "sup3r-secret-switch-password"
)

// fakeAppliance mimics a single-page appliance API: PATCH /api/system/login returns a
// bearer token, and every other endpoint demands that exact token.
func fakeAppliance(t *testing.T, hits *[]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch && r.URL.Path == "/api/system/login" {
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["password"] != appliancePasswd {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"token":               realToken,
				"timeout":             1800,
				"forceChangePassword": 0,
			})
			return
		}
		*hits = append(*hits, r.Header.Get("Authorization"))
		if r.Header.Get("Authorization") != "Bearer "+realToken {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"bad token"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"vlans":[1,10,20]}`))
	}))
}

// fakeOpenBao mimics Kubernetes auth login plus a KV v2 read.
func fakeOpenBao(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/login"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"auth": map[string]any{"client_token": "openbao-token"},
			})
		case strings.Contains(r.URL.Path, "/v1/kv/data/"):
			if r.Header.Get("X-Vault-Token") != "openbao-token" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{"data": map[string]any{"password": appliancePasswd}},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// gwReq builds a request that looks like it came through the broker.
func gwReq(t *testing.T, method, url, body string) *http.Request {
	t.Helper()
	var r *http.Request
	if body == "" {
		r, _ = http.NewRequest(method, url, nil)
	} else {
		r, _ = http.NewRequest(method, url, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	r.Header.Set("X-Portal-Auth", "test-gateway-secret")
	return r
}

func newTestPortal(t *testing.T, applianceURL, baoURL string) *portal {
	t.Helper()
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte("fake-sa-jwt"), 0o600); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(applianceURL)
	cfg := &config{
		upstreamURL:      u,
		loginPath:        "/api/system/login",
		logoutPath:       "/api/system/logout",
		refreshPath:      "/api/token_refresh",
		tokenField:       "token",
		landingPath:      "/gui/system/dashboard",
		timeoutField:     "timeout",
		username:         "admin",
		openbaoAddr:      baoURL,
		openbaoAuthMount: "kubernetes",
		openbaoRole:      "switch-portal",
		openbaoPath:      "kv/data/example/appliance/admin",
		openbaoField:     "password",
		k8sTokenPath:     tokenPath,
		// Existing tests exercise the machine-identity fallback.
		requireUserToken: false,
		// This fixture exercises the gateway-secret / machine-identity mode, so
		// it must opt in explicitly. The default is OFF: fetching the appliance
		// credential without a user token makes per-user authorisation additive
		// rather than gating (P0-3).
		allowMachineCredential: true,
		syntheticTTL:           15 * time.Minute,
		gatewaySecret:          "test-gateway-secret",
		gatewaySecretHeader:    "X-Portal-Auth",
		userTokenHeader:        "X-Portal-User-Token",
		openbaoJWTMount:        "oidc",
		openbaoJWTRole:         "switch-portal",
	}
	bao, err := newOpenBao(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p := newPortal(cfg, newUpstreamSession(cfg, bao))
	// Production refuses to start in per-user mode without a verifier, so the
	// fixture always has one. Tests that exercise its absence construct that
	// state deliberately.
	jwks := fakeJWKS(t)
	t.Cleanup(jwks.Close)
	cfg.jwksURL, cfg.tokenIssuer, cfg.jwksCacheTTL = jwks.URL, testIssuer, time.Minute
	p.verif = newTokenVerifier(jwks.URL, testIssuer, "", &http.Client{Timeout: 5 * time.Second}, time.Minute)
	return p
}

// The headline guarantee: a browser logging in receives a token, and it is NOT
// the appliance's real one — nor is the password anywhere in the response.
func TestLoginReturnsSyntheticTokenNotTheRealOne(t *testing.T) {
	var hits []string
	app := fakeAppliance(t, &hits)
	defer app.Close()
	bao := fakeOpenBao(t)
	defer bao.Close()

	srv := httptest.NewServer(newTestPortal(t, app.URL, bao.URL))
	defer srv.Close()

	req := gwReq(t, http.MethodPatch, srv.URL+"/api/system/login", `{"user":"anything","password":"the-operator-types-junk"}`)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d, body %s", resp.StatusCode, raw)
	}
	if strings.Contains(string(raw), realToken) {
		t.Fatal("SECURITY FAILURE: the appliance's real token was returned to the browser")
	}
	if strings.Contains(string(raw), appliancePasswd) {
		t.Fatal("SECURITY FAILURE: the appliance password was returned to the browser")
	}

	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("login response was not JSON: %s", raw)
	}
	tok, _ := body["token"].(string)
	if tok == "" {
		t.Fatal("no token issued to the browser")
	}
	// The appliance's own response shape must survive the substitution, or the
	// SPA will not consider itself logged in.
	if body["timeout"] != float64(1800) {
		t.Errorf("timeout field not passed through: %v", body["timeout"])
	}
	if _, ok := body["forceChangePassword"]; !ok {
		t.Error("forceChangePassword field was dropped; the SPA expects it")
	}
}

// The synthetic token must actually work: swapped for the real one on the way out.
func TestSyntheticTokenIsSwappedForRealUpstream(t *testing.T) {
	var hits []string
	app := fakeAppliance(t, &hits)
	defer app.Close()
	bao := fakeOpenBao(t)
	defer bao.Close()

	srv := httptest.NewServer(newTestPortal(t, app.URL, bao.URL))
	defer srv.Close()

	// log in, capture the handle
	lr := gwReq(t, http.MethodPatch, srv.URL+"/api/system/login", `{}`)
	lresp, err := http.DefaultClient.Do(lr)
	if err != nil {
		t.Fatal(err)
	}
	var lbody map[string]any
	_ = json.NewDecoder(lresp.Body).Decode(&lbody)
	lresp.Body.Close()
	synthetic := lbody["token"].(string)

	// use it on a real endpoint
	req := gwReq(t, http.MethodGet, srv.URL+"/api/vlan", "")
	req.Header.Set("Authorization", "Bearer "+synthetic)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("proxied request failed: %d %s", resp.StatusCode, raw)
	}
	if len(hits) != 1 || hits[0] != "Bearer "+realToken {
		t.Fatalf("appliance did not receive the real token, saw %v", hits)
	}
}

// An unauthenticated caller must not be silently elevated by the portal.
func TestUnknownTokenIsNotElevated(t *testing.T) {
	var hits []string
	app := fakeAppliance(t, &hits)
	defer app.Close()
	bao := fakeOpenBao(t)
	defer bao.Close()

	srv := httptest.NewServer(newTestPortal(t, app.URL, bao.URL))
	defer srv.Close()

	for _, hdr := range []string{"", "Bearer not-a-real-handle"} {
		req := gwReq(t, http.MethodGet, srv.URL+"/api/vlan", "")
		if hdr != "" {
			req.Header.Set("Authorization", hdr)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Fatalf("caller with Authorization=%q was elevated to a valid session", hdr)
		}
	}
	for _, h := range hits {
		if h == "Bearer "+realToken {
			t.Fatal("SECURITY FAILURE: portal attached the real token for an unauthenticated caller")
		}
	}
}

// Logout must drop the browser's handle without tearing down the shared
// upstream session (which would disconnect every other operator).
func TestLogoutRevokesHandleButKeepsUpstream(t *testing.T) {
	var hits []string
	app := fakeAppliance(t, &hits)
	defer app.Close()
	bao := fakeOpenBao(t)
	defer bao.Close()

	p := newTestPortal(t, app.URL, bao.URL)
	srv := httptest.NewServer(p)
	defer srv.Close()

	lr := gwReq(t, http.MethodPatch, srv.URL+"/api/system/login", `{}`)
	lresp, _ := http.DefaultClient.Do(lr)
	var lbody map[string]any
	_ = json.NewDecoder(lresp.Body).Decode(&lbody)
	lresp.Body.Close()
	synthetic := lbody["token"].(string)

	out := gwReq(t, http.MethodPatch, srv.URL+"/api/system/logout", "")
	out.Header.Set("Authorization", "Bearer "+synthetic)
	oresp, _ := http.DefaultClient.Do(out)
	oresp.Body.Close()

	if p.tokens.validFor(synthetic, machineSubject) {
		t.Error("handle still valid after logout")
	}
	if p.sess.currentToken() != realToken {
		t.Error("upstream session was torn down by a single operator logging out")
	}
}

// The operator must never be shown the appliance's login form: the served
// document has to carry a bootstrap that populates sessionStorage first.
func TestHtmlDocumentGetsSessionBootstrap(t *testing.T) {
	var hits []string
	bao := fakeOpenBao(t)
	defer bao.Close()

	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch && r.URL.Path == "/api/system/login" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"restful_res": map[string]any{"token": realToken, "timeout": 300, "errCode": 0},
			})
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head><title>x</title></head><body><script src="/main.js"></script></body></html>`))
	}))
	defer app.Close()
	_ = hits

	srv := httptest.NewServer(newTestPortal(t, app.URL, bao.URL))
	defer srv.Close()

	resp, err := http.DefaultClient.Do(gwReq(t, http.MethodGet, srv.URL+"/", ""))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	html := string(raw)

	if !strings.Contains(html, `sessionStorage.setItem("auth"`) {
		t.Fatal("bootstrap script was not injected; the operator would see the login form")
	}
	if strings.Index(html, "sessionStorage") > strings.Index(html, `src="/main.js"`) {
		t.Error("bootstrap must precede the SPA bundle, or the SPA reads empty storage first")
	}
	if strings.Contains(html, realToken) {
		t.Fatal("SECURITY FAILURE: the real appliance token was embedded in the HTML")
	}
}

// Assets and JSON must pass through untouched.
func TestNonHtmlResponsesAreNotRewritten(t *testing.T) {
	bao := fakeOpenBao(t)
	defer bao.Close()
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte("console.log('untouched');"))
	}))
	defer app.Close()

	srv := httptest.NewServer(newTestPortal(t, app.URL, bao.URL))
	defer srv.Close()

	resp, err := http.DefaultClient.Do(gwReq(t, http.MethodGet, srv.URL+"/static/main.js", ""))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if string(raw) != "console.log('untouched');" {
		t.Fatalf("asset was rewritten: %q", string(raw))
	}
}

// --- per-user authorisation model -------------------------------------------

// fakeOpenBaoJWT additionally implements the JWT login endpoint, accepting only
// one specific token so we can assert that OpenBao is the decision maker.
func fakeOpenBaoJWT(t *testing.T, acceptToken string, jwtLogins *int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/auth/oidc/login"):
			*jwtLogins++
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["jwt"] != acceptToken {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"errors":["not authorized"]}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"auth": map[string]any{"client_token": "openbao-token", "policies": []string{"switch-read"}},
			})
		case strings.Contains(r.URL.Path, "/v1/kv/data/"):
			if r.Header.Get("X-Vault-Token") != "openbao-token" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{"data": map[string]any{"password": appliancePasswd}},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func newUserTokenPortal(t *testing.T, applianceURL, baoURL string) *portal {
	t.Helper()
	p := newTestPortal(t, applianceURL, baoURL)
	p.cfg.requireUserToken = true
	p.cfg.gatewaySecret = "" // the user's token IS the authorisation
	return p
}

// A request with no forwarded user identity must be refused outright.
func TestRequestWithoutUserTokenIsRefused(t *testing.T) {
	var hits []string
	app := fakeAppliance(t, &hits)
	defer app.Close()
	n := 0
	goodTok := jwtFor(t, "good@example.com", time.Now().Add(time.Hour))
	bao := fakeOpenBaoJWT(t, goodTok, &n)
	defer bao.Close()

	srv := httptest.NewServer(newUserTokenPortal(t, app.URL, bao.URL))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPatch, srv.URL+"/api/system/login", strings.NewReader(`{}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 without a user token, got %d", resp.StatusCode)
	}
	if n != 0 {
		t.Error("should not have contacted OpenBao at all")
	}
}

// OpenBao — not this service — decides who may have the credential.
func TestOpenBaoIsTheAuthorisationDecisionMaker(t *testing.T) {
	var hits []string
	app := fakeAppliance(t, &hits)
	defer app.Close()
	n := 0
	goodTok := jwtFor(t, "good@example.com", time.Now().Add(time.Hour))
	bao := fakeOpenBaoJWT(t, goodTok, &n)
	defer bao.Close()

	srv := httptest.NewServer(newUserTokenPortal(t, app.URL, bao.URL))
	defer srv.Close()

	// A user OpenBao rejects gets nothing, even though the token is well-formed.
	bad, _ := http.NewRequest(http.MethodPatch, srv.URL+"/api/system/login", strings.NewReader(`{}`))
	bad.Header.Set("X-Portal-User-Token", jwtFor(t, "mallory@example.com", time.Now().Add(time.Hour)))
	br, err := http.DefaultClient.Do(bad)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(br.Body)
	br.Body.Close()
	if br.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for a user OpenBao rejects, got %d", br.StatusCode)
	}
	if strings.Contains(string(raw), appliancePasswd) || strings.Contains(string(raw), realToken) {
		t.Fatal("SECURITY FAILURE: credential material leaked on the denied path")
	}

	// The authorised user succeeds and receives only a synthetic token.
	good, _ := http.NewRequest(http.MethodPatch, srv.URL+"/api/system/login", strings.NewReader(`{}`))
	good.Header.Set("X-Portal-User-Token", goodTok)
	gr, err := http.DefaultClient.Do(good)
	if err != nil {
		t.Fatal(err)
	}
	defer gr.Body.Close()
	graw, _ := io.ReadAll(gr.Body)
	if gr.StatusCode != http.StatusOK {
		t.Fatalf("authorised user was refused: %d %s", gr.StatusCode, graw)
	}
	if strings.Contains(string(graw), realToken) {
		t.Fatal("SECURITY FAILURE: real appliance token returned to the browser")
	}
	if n < 2 {
		t.Errorf("expected OpenBao to be consulted per login, saw %d calls", n)
	}
}

// Seeding storage alone is not enough: the SPA routes "/" to its login screen
// regardless, so the bootstrap must also rewrite the path.
func TestBootstrapNavigatesAwayFromLogin(t *testing.T) {
	bao := fakeOpenBao(t)
	defer bao.Close()
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch && r.URL.Path == "/api/system/login" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"restful_res": map[string]any{"token": realToken, "timeout": 300},
			})
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head></head><body><script src="/main.js"></script></body></html>`))
	}))
	defer app.Close()

	srv := httptest.NewServer(newTestPortal(t, app.URL, bao.URL))
	defer srv.Close()

	resp, err := http.DefaultClient.Do(gwReq(t, http.MethodGet, srv.URL+"/", ""))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	html := string(raw)

	if !strings.Contains(html, "history.replaceState") {
		t.Fatal("bootstrap does not navigate; the SPA will still render its login form")
	}
	if !strings.Contains(html, "/gui/system/dashboard") {
		t.Error("landing path missing from the bootstrap")
	}
}

// A stale or expired session must not suppress the bootstrap, or the SPA
// renders its login form with a dead token.
func TestBootstrapReseedsStaleSession(t *testing.T) {
	bao := fakeOpenBao(t)
	defer bao.Close()
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch && r.URL.Path == "/api/system/login" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"restful_res": map[string]any{"token": realToken, "timeout": 300},
			})
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head></head><body><script src="/m.js"></script></body></html>`))
	}))
	defer app.Close()

	srv := httptest.NewServer(newTestPortal(t, app.URL, bao.URL))
	defer srv.Close()

	resp, err := http.DefaultClient.Do(gwReq(t, http.MethodGet, srv.URL+"/", ""))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	html := string(raw)

	// It must validate expiry, not merely presence, and clear what it rejects.
	if !strings.Contains(html, "expiretime >") {
		t.Error("bootstrap does not check expiry; a stale session would suppress it")
	}
	if !strings.Contains(html, `removeItem("auth")`) {
		t.Error("bootstrap does not clear a rejected session")
	}
}

// ---------------------------------------------------------------- P0 regressions
//
// These three tests pin the fixes for the P0s found by adversarial review.
// Each FAILS against the pre-fix code.

// P0-1: the request gate accepted ANY non-empty user-token header, so a handle
// observed on the wire could be replayed with a bogus identity. Verified live
// against the deployed build: `X-Portal-User-Token: not-a-jwt-at-all` -> 200.
func TestGateRejectsMalformedUserToken(t *testing.T) {
	p := newTestPortal(t, "http://unused.invalid", "http://unused.invalid")
	for _, tc := range []struct{ name, tok string }{
		{"garbage", "not-a-jwt-at-all"},
		{"two parts", "aaa.bbb"},
		{"undecodable claims", "aaa.!!!!.ccc"},
		{"no subject", jwtFor(t, "", time.Now().Add(time.Hour))},
		{"expired", jwtFor(t, "someone@example.com", time.Now().Add(-time.Minute))},
		// Added after review: shape alone was never sufficient. A well-formed,
		// unexpired token carrying the right subject but NOT signed by the
		// trusted key is the artefact an observer of the boundary can build.
		{"forged signature", forgedJWT(t, "someone@example.com", time.Now().Add(time.Hour))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := p.verifyUserToken(tc.tok); err == nil {
				t.Fatalf("accepted an invalid user token (%s)", tc.name)
			}
		})
	}
	if _, err := p.verifyUserToken(jwtFor(t, "a@b.c", time.Now().Add(time.Hour))); err != nil {
		t.Fatalf("rejected a correctly signed token: %v", err)
	}
}

// P0-2: handles were valid on liveness alone, so a captured handle plus any
// user-token header rode the shared session for the handle's full lifetime.
func TestHandleIsBoundToItsSubject(t *testing.T) {
	ts := newTokenStore(time.Hour)
	tok, err := ts.mint("alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !ts.validFor(tok, "alice@example.com") {
		t.Fatal("handle rejected for the subject it was issued to")
	}
	if ts.validFor(tok, "mallory@example.com") {
		t.Fatal("handle accepted for a DIFFERENT subject -- replay is possible")
	}
	if ts.validFor(tok, "") {
		t.Fatal("handle accepted with no subject -- presence-only check regressed")
	}
}

// P0-3: startup fetched the credential with pod identity, so per-user
// authorisation was additive rather than gating.
func TestMachineCredentialRefusedByDefault(t *testing.T) {
	cfg := &config{}
	if cfg.allowMachineCredential {
		t.Fatal("machine-identity fallback must default to OFF")
	}
	s := &upstreamSession{cfg: cfg}
	if _, err := s.loginLocked(""); err == nil {
		t.Fatal("fetched appliance credential with no user token; authorisation is not gating")
	}
}

// jwtFor mints a genuinely SIGNED token. It used to produce an unsigned one,
// which was fine when the service only checked shape -- and stopped being fine
// the moment it started verifying signatures. Tests that want an unverifiable
// token call forgedJWT, so the distinction is explicit at the call site.
func jwtFor(t *testing.T, sub string, exp time.Time) string {
	t.Helper()
	return signedJWT(t, sub, exp)
}

// The appliance must never receive high-side credentials. Forwarding the
// operator's identity token and the broker session cookie into vendor firmware
// leaks them somewhere we neither control nor audit. Only the appliance's own
// credential belongs upstream.
func TestHighSideCredentialsAreNotForwardedUpstream(t *testing.T) {
	var got http.Header
	appliance := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer appliance.Close()

	bao := fakeOpenBao(t)
	defer bao.Close()
	p := newTestPortal(t, appliance.URL, bao.URL)
	srv := httptest.NewServer(p)
	defer srv.Close()

	req := gwReq(t, http.MethodGet, srv.URL+"/api/system/boardinfo", "")
	req.Header.Set("X-Portal-User-Token", jwtFor(t, "victim@example.com", time.Now().Add(time.Hour)))
	req.Header.Set("Cookie", "warpgate-session=super-secret-broker-cookie")
	req.Header.Set("X-Warpgate-Username", "victim")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	for _, leaked := range []string{"X-Portal-User-Token", "Cookie", "X-Portal-Auth", "X-Warpgate-Username"} {
		if v := got.Get(leaked); v != "" {
			t.Errorf("SECURITY FAILURE: %s forwarded to the appliance (%q)", leaked, v)
		}
	}
}

// ------------------------------------------------- adversarial-review regressions
// Findings from the triumvirate review of the fix itself. Each FAILS pre-fix.

// Found by ALL THREE lanes. A crafted {"sub":"\x00machine"} could assert the
// internal sentinel, letting a user-mode request satisfy a machine-mode handle.
func TestSubjectCannotAssertTheMachineSentinel(t *testing.T) {
	crafted := jwtFor(t, machineSubject, time.Now().Add(time.Hour))
	if got := subjectOf(crafted); got == machineSubject {
		t.Fatal("SECURITY FAILURE: a wire token asserted the machine sentinel")
	}
	p := newTestPortal(t, "http://unused.invalid", "http://unused.invalid")
	if _, err := p.verifyUserToken(crafted); err == nil {
		t.Fatal("gate accepted a token asserting the reserved sentinel")
	}
	nulTok := jwtFor(t, "a\x00b", time.Now().Add(time.Hour))
	if subjectOf(nulTok) != "" {
		t.Fatal("NUL-bearing subject was accepted")
	}
}

// Found by TWO lanes. Enabling both flags pre-warms the shared session with pod
// identity; ensure() then early-returns and fetchCredentialAsUser never runs, so
// per-user authorisation stops GATING the credential fetch.
func TestMutuallyExclusiveCredentialModesRejected(t *testing.T) {
	setMinimalConfigEnv(t)
	t.Setenv("REQUIRE_USER_TOKEN", "true")
	t.Setenv("ALLOW_MACHINE_CREDENTIAL", "true")
	_, err := loadConfig()
	if err == nil {
		t.Fatal("accepted REQUIRE_USER_TOKEN + ALLOW_MACHINE_CREDENTIAL; " +
			"this silently un-gates per-user authorisation")
	}
	// Assert the SPECIFIC error. Asserting "any error" made this pass even with
	// the guard removed, because unrelated config validation errored first.
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("rejected for the wrong reason: %v", err)
	}
}

// A config with neither credential path fails every login at runtime. Fail at
// startup instead of emitting 502s that look like an appliance outage.
func TestNoCredentialPathRejectedAtStartup(t *testing.T) {
	setMinimalConfigEnv(t)
	t.Setenv("REQUIRE_USER_TOKEN", "false")
	t.Setenv("ALLOW_MACHINE_CREDENTIAL", "false")
	t.Setenv("GATEWAY_SHARED_SECRET", "s")
	_, err := loadConfig()
	if err == nil {
		t.Fatal("accepted a config with no credential path enabled")
	}
	if !strings.Contains(err.Error(), "no credential path enabled") {
		t.Fatalf("rejected for the wrong reason: %v", err)
	}
}

// setMinimalConfigEnv supplies the unrelated required settings so a config test
// reaches the validation it actually targets, instead of tripping on the first
// missing field and passing for the wrong reason.
func setMinimalConfigEnv(t *testing.T) {
	t.Helper()
	t.Setenv("UPSTREAM_URL", "http://example.invalid")
	t.Setenv("OPENBAO_ADDR", "https://example.invalid")
	t.Setenv("OPENBAO_SECRET_PATH", "kv/data/x")
	t.Setenv("SWITCH_USERNAME", "admin")
}

// An observer on the wire who captured a handle could previously log the victim
// out with it -- availability loss for free. Revocation must be binding-checked.
func TestLogoutRequiresTheBoundSubject(t *testing.T) {
	bao := fakeOpenBao(t)
	defer bao.Close()
	appliance := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer appliance.Close()

	p := newTestPortal(t, appliance.URL, bao.URL)
	p.cfg.requireUserToken = true
	srv := httptest.NewServer(p)
	defer srv.Close()

	victim := jwtFor(t, "victim@example.com", time.Now().Add(time.Hour))
	handle, err := p.tokens.mint(subjectOf(victim))
	if err != nil {
		t.Fatal(err)
	}

	// Attacker: captured handle, but presents their OWN identity.
	att, _ := http.NewRequest(http.MethodPatch, srv.URL+"/api/system/logout", nil)
	att.Header.Set("Authorization", "Bearer "+handle)
	att.Header.Set("X-Portal-User-Token", jwtFor(t, "mallory@example.com", time.Now().Add(time.Hour)))
	resp, err := http.DefaultClient.Do(att)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if p.tokens.validFor(handle, "victim@example.com") == false {
		t.Fatal("SECURITY FAILURE: attacker revoked the victim's handle")
	}

	// The rightful owner can still log out.
	own, _ := http.NewRequest(http.MethodPatch, srv.URL+"/api/system/logout", nil)
	own.Header.Set("Authorization", "Bearer "+handle)
	own.Header.Set("X-Portal-User-Token", victim)
	r2, err := http.DefaultClient.Do(own)
	if err != nil {
		t.Fatal(err)
	}
	r2.Body.Close()
	if p.tokens.validFor(handle, "victim@example.com") {
		t.Fatal("rightful owner could not revoke their own handle")
	}
}

// authorize() must prove the user can READ the credential, not merely that they
// can authenticate at the OpenBao role. Those coincide only while bound_claims
// pins one subject; widening the role to a group separates them.
func TestAuthorizeProvesReadCapabilityNotJustAuthentication(t *testing.T) {
	var loginCalls, readCalls int
	bao := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/login"):
			loginCalls++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"auth":{"client_token":"t","policies":["p"]}}`))
		default:
			readCalls++
			// Authentication succeeded, but policy DENIES the read.
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer bao.Close()

	cfg := &config{openbaoAddr: bao.URL, openbaoPath: "kv/data/x", openbaoField: "password"}
	s := &upstreamSession{cfg: cfg, bao: &openbao{cfg: cfg, client: bao.Client()}}

	if err := s.authorize(jwtFor(t, "authn-ok-authz-denied@example.com", time.Now().Add(time.Hour))); err == nil {
		t.Fatal("SECURITY FAILURE: authorised a user who can authenticate but cannot read the credential")
	}
	if readCalls == 0 {
		t.Fatal("authorize() never attempted the read; it proves authentication only")
	}
}

// Attribution must come from the identity this service ESTABLISHED, never from
// the broker's X-Warpgate-Username header. That header is unsigned and
// unverifiable; authorising on the token but attributing to the header records
// an identity nobody authenticated -- and the audit log is exactly what is
// relied on after an incident.
func TestAuditLogAttributesTheTokenSubjectNotTheBrokerHeader(t *testing.T) {
	bao := fakeOpenBao(t)
	defer bao.Close()
	appliance := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"restful_res":{"token":"appliance-tok"}}`))
	}))
	defer appliance.Close()

	p := newTestPortal(t, appliance.URL, bao.URL)
	p.cfg.requireUserToken = true
	srv := httptest.NewServer(p)
	defer srv.Close()

	var logbuf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logbuf, nil)))
	defer slog.SetDefault(prev)

	req, _ := http.NewRequest(http.MethodPatch, srv.URL+p.cfg.loginPath, nil)
	req.Header.Set("X-Portal-User-Token", jwtFor(t, "real@example.com", time.Now().Add(time.Hour)))
	// The broker header asserts a DIFFERENT identity. It must not be believed.
	req.Header.Set("X-Warpgate-Username", "impostor@example.com")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	out := logbuf.String()
	if !strings.Contains(out, "real@example.com") {
		t.Fatalf("audit log does not attribute the token subject; got:\n%s", out)
	}
	if strings.Contains(out, "impostor@example.com") {
		t.Fatalf("SECURITY FAILURE: audit log attributed the unsigned broker header; got:\n%s", out)
	}
}

// Same rule on the REFUSAL path. Authorisation has failed there, so the subject
// is only claimed -- but it must still come from the token that was evaluated,
// not from a header the broker asserted and nobody verified.
func TestRefusalIsAttributedToTheTokenNotTheBrokerHeader(t *testing.T) {
	logins := 0
	// Accept only a token nobody will present, so authorize() always refuses.
	bao := fakeOpenBaoJWT(t, "a-token-that-is-never-presented", &logins)
	defer bao.Close()
	appliance := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer appliance.Close()

	p := newTestPortal(t, appliance.URL, bao.URL)
	p.cfg.requireUserToken = true
	srv := httptest.NewServer(p)
	defer srv.Close()

	var logbuf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logbuf, nil)))
	defer slog.SetDefault(prev)

	req, _ := http.NewRequest(http.MethodPatch, srv.URL+p.cfg.loginPath, nil)
	req.Header.Set("X-Portal-User-Token", jwtFor(t, "refused@example.com", time.Now().Add(time.Hour)))
	req.Header.Set("X-Warpgate-Username", "impostor@example.com")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	out := logbuf.String()
	if !strings.Contains(out, "refused@example.com") {
		t.Fatalf("refusal not attributed to the presented token subject; got:\n%s", out)
	}
	if strings.Contains(out, "impostor@example.com") {
		t.Fatalf("SECURITY FAILURE: refusal attributed to the unsigned broker header; got:\n%s", out)
	}
}

// The machine sentinel contains a NUL byte and must never reach a log verbatim.
func TestSubjectLabelNeverEmitsTheRawSentinel(t *testing.T) {
	if got := subjectLabel(machineSubject); got != "machine" {
		t.Fatalf("machine sentinel rendered as %q, want %q", got, "machine")
	}
	if strings.ContainsRune(subjectLabel(machineSubject), 0) {
		t.Fatal("rendered label still contains NUL")
	}
	if got := subjectLabel("ugo@example.invalid"); got != "ugo@example.invalid" {
		t.Fatalf("real subject was rewritten to %q", got)
	}
}

// A redirect must never be followed on a credential-carrying request.
//
// This is the regression test for a DEMONSTRATED defect, not a hypothetical
// one. Go's http.Client left at its default follows up to 10 redirects, and for
// 307/308 it REPLAYS the method and body. The appliance login sends the fetched
// password in its body, so a redirect from the login endpoint delivered that
// password verbatim to whatever host the redirect named.
//
// §11 of the paper prescribes "refuse redirects" as a rule that must hold. It
// was prescribed and not implemented; this test is what keeps it implemented.
//
// The assertion that matters is NOT that an error was returned -- an error is
// also reported after a leak. It is that the redirect target received NOTHING.
func TestRefuseRedirectsBlocksCredentialReplay(t *testing.T) {
	var mu sync.Mutex
	var secondHopBodies []string

	// Stands in for wherever a redirect might point.
	secondHop := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		secondHopBodies = append(secondHopBodies, string(b))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"restful_res":{"token":"attacker-issued"}}`))
	}))
	defer secondHop.Close()

	// The "appliance" answers the login with a 307 instead of a session.
	appliance := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, secondHop.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer appliance.Close()

	bao := fakeOpenBao(t)
	defer bao.Close()

	p := newTestPortal(t, appliance.URL, bao.URL)
	_, err := p.sess.loginLocked("")

	if err == nil {
		t.Fatal("SECURITY FAILURE: login followed a redirect and reported success")
	}
	if !errors.Is(err, errRedirectRefused) {
		t.Fatalf("login failed, but not by refusing the redirect: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(secondHopBodies) != 0 {
		t.Fatalf("SECURITY FAILURE: the redirect target received %d request(s); "+
			"first body was %q -- the appliance credential was replayed",
			len(secondHopBodies), secondHopBodies[0])
	}
}
