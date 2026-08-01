package main

// Cryptographic verification of the forwarded user token.
//
// WHY THIS EXISTS
//
// The portal used to check the forwarded token only for shape, expiry and the
// presence of a subject, on the theory that OpenBao was the authority and
// verified the signature at login. That is true of the LOGIN path. It was not
// true of the steady-state path, which every proxied request takes.
//
// The consequence was a real, reachable defect. A capability is bound to a
// subject so that a captured capability cannot be used by anyone else. But the
// steady-state path compared that bound subject against a subject read out of an
// UNSIGNED assertion. An observer of the boundary sees both the capability (in
// the Authorization header) and the subject (the `sub` claim, in clear), so it
// could forge `header.{"sub":<victim>,"exp":<future>}.anything`, present it with
// the captured capability, and be accepted for the capability's remaining life.
//
// Binding to a subject means nothing unless the CLAIM of that subject is
// authenticated. Subject equality is not proof of subject possession.
//
// NO NEW DEPENDENCIES. This service deliberately has none, which is a property
// worth keeping in something that handles credentials. RS256 verification is
// about eighty lines of standard library, so that is what this is.

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// jwk is one key from the identity provider's JWKS document.
type jwk struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// rsaKey converts a JWK to an RSA public key. Only RSA is accepted: the IdP
// signs with RS256 and silently accepting another family would widen what a
// forged header can select.
func (k jwk) rsaKey() (*rsa.PublicKey, error) {
	if k.Kty != "RSA" {
		return nil, fmt.Errorf("unsupported key type %q", k.Kty)
	}
	nb, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("undecodable modulus: %w", err)
	}
	eb, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("undecodable exponent: %w", err)
	}
	e := 0
	for _, b := range eb {
		e = e<<8 | int(b)
	}
	if e == 0 {
		return nil, errors.New("zero exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}, nil
}

// tokenVerifier verifies forwarded user tokens against the identity provider's
// published keys.
//
// The key cache refreshes on expiry and on an unknown `kid`, which is what makes
// IdP key rotation survivable without a restart. A refresh triggered by an
// unknown kid is rate-limited so a stream of bogus kids cannot be turned into a
// request amplifier against the IdP.
type tokenVerifier struct {
	jwksURL  string
	issuer   string
	audience string
	client   *http.Client
	ttl      time.Duration

	mu          sync.RWMutex
	keys        map[string]*rsa.PublicKey
	fetchedAt   time.Time
	lastMissFet time.Time
}

func newTokenVerifier(jwksURL, issuer, audience string, client *http.Client, ttl time.Duration) *tokenVerifier {
	return &tokenVerifier{
		jwksURL: jwksURL, issuer: issuer, audience: audience,
		client: client, ttl: ttl, keys: map[string]*rsa.PublicKey{},
	}
}

// refresh replaces the cached key set. Callers hold no lock.
func (v *tokenVerifier) refresh() error {
	req, err := http.NewRequest(http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks endpoint returned %d", resp.StatusCode)
	}
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return fmt.Errorf("undecodable jwks: %w", err)
	}
	next := map[string]*rsa.PublicKey{}
	for _, k := range doc.Keys {
		if k.Kty != "RSA" {
			continue // not an error: the set may carry keys for other algorithms
		}
		pk, err := k.rsaKey()
		if err != nil {
			continue
		}
		next[k.Kid] = pk
	}
	if len(next) == 0 {
		return errors.New("jwks contained no usable RSA keys")
	}
	v.mu.Lock()
	v.keys, v.fetchedAt = next, time.Now()
	v.mu.Unlock()
	return nil
}

// keyFor returns the key for kid, refreshing once if the cache is stale or the
// kid is unknown.
func (v *tokenVerifier) keyFor(kid string) (*rsa.PublicKey, error) {
	v.mu.RLock()
	k, ok := v.keys[kid]
	stale := time.Since(v.fetchedAt) > v.ttl
	sinceMiss := time.Since(v.lastMissFet)
	v.mu.RUnlock()

	if ok && !stale {
		return k, nil
	}
	// Rate-limit refreshes provoked by an unknown kid; an attacker controls the
	// kid header and could otherwise use us to hammer the IdP.
	if !ok && sinceMiss < 30*time.Second {
		return nil, fmt.Errorf("unknown key id %q", kid)
	}
	if !ok {
		v.mu.Lock()
		v.lastMissFet = time.Now()
		v.mu.Unlock()
	}
	if err := v.refresh(); err != nil {
		// FAIL CLOSED. A stale key is not a fallback: if we cannot establish
		// the current key set we cannot establish identity, and proceeding on
		// an old key is exactly the "authorise on a weaker check" mistake this
		// file exists to remove.
		return nil, fmt.Errorf("cannot establish signing keys: %w", err)
	}
	v.mu.RLock()
	k, ok = v.keys[kid]
	v.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown key id %q", kid)
	}
	return k, nil
}

// verifiedClaims is what a caller may rely on AFTER verification succeeds.
type verifiedClaims struct {
	Subject string
	Issuer  string
	// ExpiresAt is when the assertion stops being valid. A capability minted on
	// its authority must not outlive it: authorisation the caller no longer
	// holds is not authorisation.
	ExpiresAt time.Time
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

type jwtClaims struct {
	Sub string          `json:"sub"`
	Iss string          `json:"iss"`
	Exp int64           `json:"exp"`
	Nbf int64           `json:"nbf"`
	Aud json.RawMessage `json:"aud"`
}

// audienceContains reports whether the `aud` claim includes want. The claim is
// either a string or an array of strings, and both shapes appear in the wild.
func audienceContains(raw json.RawMessage, want string) bool {
	if want == "" {
		return true // audience checking not configured
	}
	if len(raw) == 0 {
		return false
	}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == want
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		for _, a := range many {
			if a == want {
				return true
			}
		}
	}
	return false
}

// verify checks the token's signature and claims and returns what was proved.
//
// Order matters: nothing is trusted until the signature is verified, so the
// claims are only interpreted afterwards.
func (v *tokenVerifier) verify(tok string) (verifiedClaims, error) {
	var out verifiedClaims
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return out, errors.New("not a three-part JWT")
	}

	hraw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return out, fmt.Errorf("undecodable header: %w", err)
	}
	var hdr jwtHeader
	if err := json.Unmarshal(hraw, &hdr); err != nil {
		return out, fmt.Errorf("unparseable header: %w", err)
	}
	// Only RS256. Accepting the token's own `alg` would let a forged header
	// select "none" or downgrade to an algorithm we do not intend to allow --
	// the classic JWT algorithm-confusion defect.
	if hdr.Alg != "RS256" {
		return out, fmt.Errorf("unsupported algorithm %q", hdr.Alg)
	}
	if hdr.Kid == "" {
		return out, errors.New("no key id in header")
	}

	key, err := v.keyFor(hdr.Kid)
	if err != nil {
		return out, err
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return out, fmt.Errorf("undecodable signature: %w", err)
	}
	signed := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, signed[:], sig); err != nil {
		return out, errors.New("signature does not verify")
	}

	// Signature is good. Only now are the claims meaningful.
	craw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return out, fmt.Errorf("undecodable claims: %w", err)
	}
	var c jwtClaims
	if err := json.Unmarshal(craw, &c); err != nil {
		return out, fmt.Errorf("unparseable claims: %w", err)
	}
	if c.Sub == "" {
		return out, errors.New("no subject claim")
	}
	// The machine sentinel must never be assertable by a token from the wire.
	// NUL is rejected wholesale so a future sentinel cannot reopen this.
	if c.Sub == machineSubject || strings.ContainsRune(c.Sub, 0) {
		return out, errors.New("subject asserts a reserved internal value")
	}
	if v.issuer != "" && c.Iss != v.issuer {
		return out, fmt.Errorf("untrusted issuer %q", c.Iss)
	}
	if !audienceContains(c.Aud, v.audience) {
		return out, errors.New("token is not addressed to this service")
	}
	now := time.Now()
	if c.Exp == 0 {
		return out, errors.New("no expiry claim")
	}
	if now.After(time.Unix(c.Exp, 0)) {
		return out, errors.New("token expired")
	}
	if c.Nbf != 0 && now.Before(time.Unix(c.Nbf, 0)) {
		return out, errors.New("token not yet valid")
	}
	return verifiedClaims{Subject: c.Sub, Issuer: c.Iss, ExpiresAt: time.Unix(c.Exp, 0)}, nil
}
