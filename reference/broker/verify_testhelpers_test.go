package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// One key for the whole test binary: generating RSA keys is slow and every test
// that mints a token needs the same one.
var (
	testKeyOnce sync.Once
	testKey     *rsa.PrivateKey
)

const testKid = "test-key-1"
const testIssuer = "https://idp.example.invalid/oauth2/token"

func signingKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	testKeyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		testKey = k
	})
	return testKey
}

// fakeJWKS serves the public half of the test key.
func fakeJWKS(t *testing.T) *httptest.Server {
	t.Helper()
	k := signingKey(t)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(k.PublicKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.PublicKey.E)).Bytes())
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{
				{"kty": "RSA", "kid": testKid, "alg": "RS256", "use": "sig", "n": n, "e": e},
			},
		})
	}))
}

// signedJWT mints a genuinely signed RS256 token.
func signedJWT(t *testing.T, sub string, exp time.Time) string {
	t.Helper()
	return signedJWTWithIssuer(t, sub, exp, testIssuer)
}

func signedJWTWithIssuer(t *testing.T, sub string, exp time.Time, iss string) string {
	t.Helper()
	k := signingKey(t)
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": testKid, "typ": "JWT"})
	claims := map[string]any{"exp": exp.Unix(), "iss": iss}
	if sub != "" {
		claims["sub"] = sub
	}
	cl, _ := json.Marshal(claims)
	signing := base64.RawURLEncoding.EncodeToString(hdr) + "." +
		base64.RawURLEncoding.EncodeToString(cl)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// forgedJWT mints a token that is well-formed and unexpired but NOT signed by
// the trusted key. This is the artefact an observer of the boundary can build
// after reading a victim's subject off the wire.
func forgedJWT(t *testing.T, sub string, exp time.Time) string {
	t.Helper()
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": testKid, "typ": "JWT"})
	claims := map[string]any{"exp": exp.Unix(), "iss": testIssuer, "sub": sub}
	cl, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString(hdr) + "." +
		base64.RawURLEncoding.EncodeToString(cl) + "." +
		base64.RawURLEncoding.EncodeToString([]byte("not-a-real-signature"))
}

// withVerifier points a test portal at a fake JWKS and turns on per-user mode.
func withVerifier(t *testing.T, p *portal) *httptest.Server {
	t.Helper()
	jwks := fakeJWKS(t)
	p.cfg.jwksURL = jwks.URL
	p.cfg.tokenIssuer = testIssuer
	p.cfg.jwksCacheTTL = time.Minute
	p.verif = newTokenVerifier(jwks.URL, testIssuer, "", &http.Client{Timeout: 5 * time.Second}, time.Minute)
	return jwks
}

// jwtWithAlg mints a token whose header claims an arbitrary algorithm. Used to
// prove the verifier pins RS256 rather than honouring the token's own claim.
func jwtWithAlg(t *testing.T, alg, sub string, exp time.Time) string {
	t.Helper()
	hdr, _ := json.Marshal(map[string]string{"alg": alg, "kid": testKid, "typ": "JWT"})
	claims := map[string]any{"exp": exp.Unix(), "iss": testIssuer, "sub": sub}
	cl, _ := json.Marshal(claims)
	signing := base64.RawURLEncoding.EncodeToString(hdr) + "." +
		base64.RawURLEncoding.EncodeToString(cl)
	if alg == "none" {
		return signing + "."
	}
	// A real signature over the signing input, but under a header that claims a
	// different algorithm — the shape an algorithm-confusion attempt takes.
	k := signingKey(t)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}
