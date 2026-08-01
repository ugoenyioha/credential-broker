// switch-portal is a credential-exchange reverse proxy for appliance web UIs
// whose admin interface is a client-side single-page application.
//
// # THE PROBLEM IT SOLVES
//
// A normal identity-aware proxy can inject request headers, but a SPA decides
// whether it is logged in by reading its OWN browser storage. That check happens
// inside the operator's browser before any request exists, so an injected header
// is invisible to it and the operator is shown a login form — forcing them to
// type the very credential we are trying to conceal.
//
// This proxy does not inject a header. It ANSWERS the login request:
//
//  1. It holds one authenticated upstream session, logging in itself with a
//     credential fetched from OpenBao at runtime.
//  2. When the SPA posts to the login endpoint, the proxy ignores whatever was
//     submitted, and replies with the upstream's own login response — but with
//     the token field replaced by an opaque SYNTHETIC token.
//  3. On every subsequent request it swaps that synthetic token back to the real
//     one before forwarding.
//
// Net effect: neither the appliance password nor its real session token ever
// reaches the browser. The browser holds a handle that is meaningless anywhere
// else and is revoked by restarting or logging out.
//
// # IT VERIFIES THE CALLER, BUT IT IS NOT THE ONLY GATE
//
// This service cryptographically verifies the forwarded user token on every
// request -- signature, issuer, audience, expiry -- and refuses to start in
// per-user mode without the key set and issuer configured. See verify.go for why
// checking shape alone was a reachable defect rather than a theoretical one.
//
// It still must only ever be reachable from the gateway in front of it, which
// performs the interactive login and session recording. Verification here is
// defence in depth, not a licence to expose this service directly.
// Enforce that with a NetworkPolicy.
package main

import (
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type config struct {
	listenAddr string

	upstreamURL      *url.URL
	upstreamInsecure bool

	loginPath   string
	logoutPath  string
	refreshPath string

	// Where the token lives in the upstream login response. The response is
	// passed through otherwise untouched, so we do not have to model the
	// appliance's envelope — only find the one field to substitute.
	tokenField   string
	timeoutField string

	// Where to send the browser once the session is seeded. The appliance SPA
	// routes "/" and "/login" to its login screen regardless of stored state.
	landingPath string

	username string

	openbaoAddr      string
	openbaoAuthMount string
	openbaoRole      string
	openbaoPath      string
	openbaoField     string
	openbaoCAFile    string
	k8sTokenPath     string

	// PREFERRED AUTHORISATION MODEL: the broker forwards the end user's OIDC
	// ID token, and this service exchanges THAT with OpenBao for the appliance
	// credential. Authorisation is then per-user and decided by OpenBao, whose
	// audit log names the actual human rather than a service account.
	//
	// userTokenHeader is where the caller's assertion arrives. The PAM gateway is
	// configured to inject a custom header carrying the SSO ACCESS token -- not the
	// ID token, which is audience-bound to the gateway and must not be forwarded to
	// a target (OWASP ASVS 5.0 V10).
	userTokenHeader string

	// Verification of the forwarded token on EVERY use. Empty jwksURL disables
	// it, which is only valid in machine mode -- enforced at startup.
	jwksURL          string
	oidcCAFile       string
	tokenIssuer      string
	tokenAudience    string
	jwksCacheTTL     time.Duration
	openbaoJWTMount  string
	openbaoJWTRole   string
	requireUserToken bool
	// allowMachineCredential permits fetching the appliance credential with the
	// pod's own identity when no user token is present. OFF by default: leaving
	// it on makes per-user authorisation additive rather than gating.
	allowMachineCredential bool
	// syntheticTTL bounds how long a browser handle stays usable. Was 8h, which
	// far exceeded the ID token it was derived from.
	syntheticTTL time.Duration

	// FALLBACK ONLY: authenticate to OpenBao with this pod's own Kubernetes
	// service account. Simpler, but authorisation becomes machine-level — any
	// caller that reaches this service gets a privileged appliance session,
	// so the shared secret below is then the only real access control.
	gatewaySecret       string
	gatewaySecretHeader string
	allowNoGatewayAuth  bool

	// Refresh the upstream session this long before it is due to expire.
	refreshMargin time.Duration
}

func loadConfig() (*config, error) {
	c := &config{
		listenAddr:       env("LISTEN_ADDR", ":8080"),
		loginPath:        env("LOGIN_PATH", "/api/system/login"),
		logoutPath:       env("LOGOUT_PATH", "/api/system/logout"),
		refreshPath:      env("REFRESH_PATH", "/api/token_refresh"),
		tokenField:       env("TOKEN_FIELD", "token"),
		landingPath:      env("LANDING_PATH", "/gui/system/dashboard"),
		timeoutField:     env("TIMEOUT_FIELD", "timeout"),
		username:         env("SWITCH_USERNAME", "admin"),
		openbaoAddr:      env("OPENBAO_ADDR", ""),
		openbaoAuthMount: env("OPENBAO_AUTH_MOUNT", "kubernetes"),
		openbaoRole:      env("OPENBAO_ROLE", "switch-portal"),
		openbaoPath:      env("OPENBAO_SECRET_PATH", "kv/data/example/appliance/admin"),
		openbaoField:     env("OPENBAO_SECRET_FIELD", "password"),
		openbaoCAFile:    env("OPENBAO_CA_FILE", ""),
		k8sTokenPath:     env("K8S_TOKEN_PATH", "/var/run/secrets/kubernetes.io/serviceaccount/token"),
		upstreamInsecure: env("UPSTREAM_INSECURE_TLS", "false") == "true",
		refreshMargin:    30 * time.Second,

		userTokenHeader:        env("USER_TOKEN_HEADER", "X-Portal-User-Token"),
		openbaoJWTMount:        env("OPENBAO_JWT_MOUNT", "oidc"),
		openbaoJWTRole:         env("OPENBAO_JWT_ROLE", "switch-portal"),
		requireUserToken:       env("REQUIRE_USER_TOKEN", "true") == "true",
		allowMachineCredential: env("ALLOW_MACHINE_CREDENTIAL", "false") == "true",
		syntheticTTL:           envDuration("SYNTHETIC_TOKEN_TTL", 15*time.Minute),

		// Verification of the forwarded token on EVERY use, not only at login.
		// Empty jwksURL is only valid in machine mode; loadConfig refuses to
		// start in per-user mode without it.
		jwksURL:       env("OIDC_JWKS_URL", ""),
		tokenIssuer:   env("OIDC_ISSUER", ""),
		tokenAudience: env("OIDC_AUDIENCE", ""),
		jwksCacheTTL:  envDuration("OIDC_JWKS_CACHE_TTL", 15*time.Minute),

		gatewaySecret:       os.Getenv("GATEWAY_SHARED_SECRET"),
		gatewaySecretHeader: env("GATEWAY_SECRET_HEADER", "X-Portal-Auth"),
		allowNoGatewayAuth:  env("ALLOW_NO_GATEWAY_AUTH", "false") == "true",
	}

	raw := env("UPSTREAM_URL", "")
	if raw == "" {
		return nil, errors.New("UPSTREAM_URL is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse UPSTREAM_URL: %w", err)
	}
	c.upstreamURL = u

	if c.openbaoAddr == "" {
		return nil, errors.New("OPENBAO_ADDR is required")
	}
	// Fail to start rather than run wide open by accident. With per-user token
	// exchange the user's own token IS the authorisation, so a shared secret
	// adds nothing; it is only required in the machine-identity fallback.
	if !c.requireUserToken && c.gatewaySecret == "" && !c.allowNoGatewayAuth {
		return nil, errors.New("REQUIRE_USER_TOKEN is false, so GATEWAY_SHARED_SECRET is required " +
			"(anything able to reach this service could otherwise obtain an appliance session); " +
			"set ALLOW_NO_GATEWAY_AUTH=true only if the network path is genuinely trusted")
	}
	// The machine-identity fallback and per-user authorisation are MUTUALLY
	// EXCLUSIVE. Enabling both re-creates the exact defect the fallback was
	// disabled to remove: startup pre-warms the shared session with pod
	// identity, ensure() then early-returns on the warm session, and
	// fetchCredentialAsUser never runs -- so per-user authorisation accompanies
	// the request but no longer GATES the credential fetch.
	if c.requireUserToken && c.allowMachineCredential {
		return nil, errors.New("REQUIRE_USER_TOKEN and ALLOW_MACHINE_CREDENTIAL are mutually exclusive: " +
			"enabling both pre-warms the shared appliance session with machine identity, " +
			"which stops per-user authorisation from gating the credential fetch")
	}
	// Neither mode enabled means every login fails at loginLocked. Fail loudly at
	// startup rather than serving 502s that look like an appliance outage.
	if !c.requireUserToken && !c.allowMachineCredential {
		return nil, errors.New("no credential path enabled: set REQUIRE_USER_TOKEN=true (per-user) " +
			"or ALLOW_MACHINE_CREDENTIAL=true (machine identity)")
	}
	// Per-user mode without signature verification is the defect this build
	// exists to remove: the steady-state path would compare a capability's bound
	// subject against an UNSIGNED assertion of that subject, which any observer
	// of the boundary can forge. Refuse to start rather than serve it.
	if c.requireUserToken && c.jwksURL == "" {
		return nil, errors.New("REQUIRE_USER_TOKEN=true needs OIDC_JWKS_URL: without it the " +
			"forwarded token's signature is never verified on proxied requests, and a captured " +
			"capability can be replayed with a forged assertion of the victim's subject")
	}
	if c.requireUserToken && c.tokenIssuer == "" {
		return nil, errors.New("REQUIRE_USER_TOKEN=true needs OIDC_ISSUER: a valid signature from " +
			"an unexpected issuer is not an authorisation")
	}
	return c, nil
}

// envDuration reads a duration from the environment, falling back to def when
// unset or unparseable.
func envDuration(key string, def time.Duration) time.Duration {
	raw := os.Getenv(key)
	if raw == "" {
		return def
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		slog.Warn("ignoring unparseable duration", "key", key, "value", raw, "using", def)
		return def
	}
	return d
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// ---------------------------------------------------------- redirect refusal

// errRedirectRefused is returned instead of following a redirect. §11 of the
// paper requires it, and the reason is specific rather than hygienic: the
// appliance login request carries the fetched credential in its BODY, and Go's
// http.Client, left at its default, follows up to 10 redirects — replaying the
// method and body each time for 307/308. A redirect from the login endpoint
// therefore hands the appliance password to whatever host the redirect names.
//
// Demonstrated, not theorised: a client configured as this one was, PATCHing a
// login body to a server answering 307, delivers the password to the second
// hop verbatim. See TestRefuseRedirectsBlocksCredentialReplay.
//
// A redirect on any of these paths is not a routine condition to be followed —
// it means the destination is not the one the grant authorised. Refuse, and let
// the caller see the error.
var errRedirectRefused = errors.New(
	"refusing to follow a redirect: the destination would not be the one the grant " +
		"authorised, and credential-carrying requests must not be replayed to it")

// refuseRedirects is the CheckRedirect for every client in this service that
// carries credential material — the caller's assertion to the secret store, the
// appliance password to the appliance, and the issuer's signing keys.
// Centralised so a client added later cannot silently omit the control.
//
// It returns a real error rather than http.ErrUseLastResponse. Both stop the
// replay, but ErrUseLastResponse hands the 3xx back with err == nil, so a
// caller that only checks err would treat a redirect as a normal response and
// fall through to its status check. Failing loudly is the point: a redirect
// here is a destination the grant did not authorise, not a routine hop.
func refuseRedirects(req *http.Request, via []*http.Request) error {
	return fmt.Errorf("%w: %s redirected to %s after %d hop(s)",
		errRedirectRefused, via[len(via)-1].URL.Host, req.URL.Host, len(via))
}

// ---------------------------------------------------------------- OpenBao

type openbao struct {
	cfg    *config
	client *http.Client
}

func newOpenBao(cfg *config) (*openbao, error) {
	tr := &http.Transport{}
	if cfg.openbaoCAFile != "" {
		pem, err := os.ReadFile(cfg.openbaoCAFile)
		if err != nil {
			return nil, fmt.Errorf("read OPENBAO_CA_FILE: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("OPENBAO_CA_FILE contained no usable certificates")
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &openbao{cfg: cfg, client: &http.Client{
		Timeout:       15 * time.Second,
		Transport:     tr,
		CheckRedirect: refuseRedirects, // carries the caller's assertion
	}}, nil
}

// login exchanges the pod's Kubernetes service account token for an OpenBao
// token. Nothing is cached: this runs only when the appliance session needs
// re-establishing, which is rare, and a short-lived token is preferable to a
// long-lived one held in memory.
func (o *openbao) login() (string, error) {
	jwt, err := os.ReadFile(o.cfg.k8sTokenPath)
	if err != nil {
		return "", fmt.Errorf("read service account token: %w", err)
	}
	body, _ := json.Marshal(map[string]string{
		"role": o.cfg.openbaoRole,
		"jwt":  strings.TrimSpace(string(jwt)),
	})
	endpoint := fmt.Sprintf("%s/v1/auth/%s/login", strings.TrimRight(o.cfg.openbaoAddr, "/"), o.cfg.openbaoAuthMount)
	resp, err := o.client.Post(endpoint, "application/json", strings.NewReader(string(body)))
	if err != nil {
		return "", fmt.Errorf("openbao login: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("openbao login: unexpected status %d", resp.StatusCode)
	}
	var out struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("decode openbao login: %w", err)
	}
	if out.Auth.ClientToken == "" {
		return "", errors.New("openbao login returned no client_token")
	}
	return out.Auth.ClientToken, nil
}

// fetchCredential authenticates with this pod's OWN identity and reads the
// secret. Fallback path only — see the config comments.
func (o *openbao) fetchCredential() (string, error) {
	token, err := o.login()
	if err != nil {
		return "", err
	}
	return o.readSecretWith(token)
}

// fetchCredentialAsUser authenticates as the END USER and reads the secret.
// This is the preferred path: OpenBao decides per-user and audits the human.
func (o *openbao) fetchCredentialAsUser(idToken string) (string, error) {
	token, err := o.loginWithUserToken(idToken)
	if err != nil {
		return "", err
	}
	return o.readSecretWith(token)
}

// loginWithUserToken exchanges the END USER's OIDC ID token for an OpenBao
// token, so the authorisation decision and the audit entry both belong to the
// human rather than to this pod.
func (o *openbao) loginWithUserToken(idToken string) (string, error) {
	body, _ := json.Marshal(map[string]string{"role": o.cfg.openbaoJWTRole, "jwt": idToken})
	endpoint := fmt.Sprintf("%s/v1/auth/%s/login",
		strings.TrimRight(o.cfg.openbaoAddr, "/"), o.cfg.openbaoJWTMount)
	resp, err := o.client.Post(endpoint, "application/json", strings.NewReader(string(body)))
	if err != nil {
		return "", fmt.Errorf("openbao jwt login: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Do not echo the response: it can quote the rejected token.
		return "", fmt.Errorf("openbao jwt login rejected the user token (status %d)", resp.StatusCode)
	}
	var out struct {
		Auth struct {
			ClientToken string   `json:"client_token"`
			Policies    []string `json:"policies"`
			Metadata    map[string]string
		} `json:"auth"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("decode openbao jwt login: %w", err)
	}
	if out.Auth.ClientToken == "" {
		return "", errors.New("openbao jwt login returned no client_token")
	}
	// Label this field for what it IS. It was previously emitted as "user",
	// which reads as the human and is not: Metadata["role"] is the OpenBao ROLE
	// the exchange bound to (e.g. "switch-portal"). A reviewer reading this line
	// reasonably concluded the vault was authorising the workload rather than
	// the operator -- it is not, the operator's own assertion is what was
	// exchanged above, but the log said otherwise.
	//
	// This is the §14 defect in miniature, in the component whose entire purpose
	// is attribution: authorisation used the strong channel, the local log
	// described it with the weak one. The authoritative per-human record is
	// OpenBao's own audit log, keyed to the assertion presented here.
	slog.Info("exchanged the caller's assertion for an OpenBao token",
		"openbao_policies", out.Auth.Policies,
		"openbao_role", out.Auth.Metadata["role"])
	return out.Auth.ClientToken, nil
}

// readSecretWith fetches the appliance password using an already-obtained
// OpenBao token. The value is returned to the caller and never logged, stored
// on disk, or written to a response.
func (o *openbao) readSecretWith(token string) (string, error) {
	endpoint := fmt.Sprintf("%s/v1/%s", strings.TrimRight(o.cfg.openbaoAddr, "/"), strings.TrimLeft(o.cfg.openbaoPath, "/"))
	req, _ := http.NewRequest(http.MethodGet, endpoint, nil)
	req.Header.Set("X-Vault-Token", token)
	resp, err := o.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("read secret: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("read secret: unexpected status %d", resp.StatusCode)
	}
	// KV v2 nests the payload under data.data.
	var out struct {
		Data struct {
			Data map[string]any `json:"data"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("decode secret: %w", err)
	}
	v, ok := out.Data.Data[o.cfg.openbaoField].(string)
	if !ok || v == "" {
		return "", fmt.Errorf("secret field %q missing or not a string", o.cfg.openbaoField)
	}
	return v, nil
}

// ---------------------------------------------------------------- upstream

// upstreamSession is the single authenticated session the portal holds against
// the appliance. All operators are multiplexed onto it, which avoids exhausting
// the appliance's concurrent-session limit.
type upstreamSession struct {
	cfg      *config
	bao      *openbao
	client   *http.Client
	mu       sync.Mutex
	token    string
	expires  time.Time
	loginRaw map[string]any // the appliance's own login response, for shape fidelity
}

func newUpstreamSession(cfg *config, bao *openbao) *upstreamSession {
	tr := &http.Transport{}
	if cfg.upstreamInsecure {
		// The appliance ships an expired, hostname-mismatched certificate.
		// Accepted deliberately: the target is a fixed IP on a directly
		// attached segment. Remove once the device serves a trusted cert.
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}
	return &upstreamSession{
		cfg: cfg,
		bao: bao,
		client: &http.Client{
			Timeout:       20 * time.Second,
			Transport:     tr,
			CheckRedirect: refuseRedirects, // carries the appliance password
		},
	}
}

// ensure guarantees a usable upstream appliance session.
//
// userToken is the end user's OIDC ID token. When present it is exchanged with
// OpenBao, so OPENBAO decides whether this particular human may read the
// appliance credential. That check happens on every login (i.e. every time a
// browser is issued a synthetic token), which is the point at which
// authorisation matters; the resulting appliance session is then shared, to
// avoid exhausting the appliance's concurrent-session limit.
func (s *upstreamSession) ensure(userToken string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token != "" && time.Now().Before(s.expires.Add(-s.cfg.refreshMargin)) {
		return s.token, nil
	}
	return s.loginLocked(userToken)
}

func (s *upstreamSession) loginLocked(userToken string) (string, error) {
	var password string
	var err error
	if userToken != "" {
		password, err = s.bao.fetchCredentialAsUser(userToken)
	} else if s.cfg.allowMachineCredential {
		// Fallback retained ONLY for deployments that deliberately opt out of
		// per-user authorisation. It is off by default because it makes the
		// per-user check additive rather than gating: the credential becomes
		// obtainable with pod identity alone, and OpenBao's audit record then
		// names the service account instead of the human.
		slog.Warn("fetching appliance credential with MACHINE identity; " +
			"per-user authorisation is NOT gating this fetch")
		password, err = s.bao.fetchCredential()
	} else {
		return "", errors.New("refusing to obtain appliance credential without a user token: " +
			"per-user authorisation is required (set ALLOW_MACHINE_CREDENTIAL=true to opt out)")
	}
	if err != nil {
		return "", fmt.Errorf("obtain appliance credential: %w", err)
	}

	body, _ := json.Marshal(map[string]string{"user": s.cfg.username, "password": password})
	endpoint := s.cfg.upstreamURL.JoinPath(s.cfg.loginPath).String()
	req, _ := http.NewRequest(http.MethodPatch, endpoint, strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("appliance login: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("appliance login: unexpected status %d", resp.StatusCode)
	}

	var parsed map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return "", fmt.Errorf("decode appliance login: %w", err)
	}

	token, ok := findString(parsed, s.cfg.tokenField)
	if !ok {
		// Log the SHAPE only — never values — so a mismatch is diagnosable
		// without leaking the session token.
		slog.Error("appliance login response did not contain the expected token field",
			"expected_field", s.cfg.tokenField, "response_keys", keysOf(parsed))
		return "", fmt.Errorf("token field %q not found in appliance login response", s.cfg.tokenField)
	}

	ttl := 15 * time.Minute // conservative default if the appliance omits one
	if secs, ok := findNumber(parsed, s.cfg.timeoutField); ok && secs > 0 {
		ttl = time.Duration(secs) * time.Second
	}

	s.token = token
	s.expires = time.Now().Add(ttl)
	s.loginRaw = parsed
	slog.Info("established appliance session", "ttl_seconds", int(ttl.Seconds()))
	return token, nil
}

// authorize proves the caller may have an appliance session, by exchanging
// their token with OpenBao. Called even when the shared appliance session is
// already warm, so a second user cannot ride the first user's authorisation.
func (s *upstreamSession) authorize(userToken string) error {
	if userToken == "" {
		return errors.New("no user token presented")
	}
	// Exercise the ACTUAL capability, not merely authentication.
	//
	// This used to call loginWithUserToken alone, which proves only that the
	// user can authenticate at the JWT role -- not that OpenBao's policy lets
	// them read the appliance credential. Those coincide only while bound_claims
	// pins a single subject. Widen the role to a group (the documented next
	// step) and a user who authenticates but fails the policy would still be
	// issued a handle and ride the already-warm shared session.
	//
	// The credential is fetched and immediately discarded; it is never logged,
	// returned, or stored. The cost is one extra read per login, which is rare.
	if _, err := s.bao.fetchCredentialAsUser(userToken); err != nil {
		return err
	}
	return nil
}

// loginResponseFor returns the appliance's own login response with the token
// substituted for a synthetic one. Passing the real body through means we never
// have to model the appliance's response envelope.
func (s *upstreamSession) loginResponseFor(synthetic, userToken string) ([]byte, error) {
	if _, err := s.ensure(userToken); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make(map[string]any, len(s.loginRaw))
	for k, v := range s.loginRaw {
		out[k] = v
	}
	if !setString(out, s.cfg.tokenField, synthetic) {
		return nil, fmt.Errorf("could not substitute token field %q", s.cfg.tokenField)
	}
	return json.Marshal(out)
}

func (s *upstreamSession) currentToken() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.token
}

// ---------------------------------------------------------------- synthetic tokens

// tokenStore tracks the opaque handles issued to browsers. Values are useless
// outside this process, so losing them on restart is harmless — operators simply
// log in again through the broker.
type issuedToken struct {
	expires time.Time
	// subject binds this handle to the identity that was authorised when it was
	// minted. A handle observed on the wire is useless without also presenting a
	// user token for the SAME subject, so a captured handle alone no longer
	// grants access.
	subject string
}

type tokenStore struct {
	mu     sync.RWMutex
	issued map[string]issuedToken
	ttl    time.Duration
}

func newTokenStore(ttl time.Duration) *tokenStore {
	return &tokenStore{issued: map[string]issuedToken{}, ttl: ttl}
}

// mintUntil issues a capability that expires at the earlier of the store's TTL
// and the supplied deadline. A capability must not outlive the assertion that
// authorised it: authorisation the caller no longer holds is not authorisation.
func (t *tokenStore) mintUntil(subject string, notAfter time.Time) (string, time.Time, error) {
	tok, err := t.mint(subject)
	if err != nil {
		return "", time.Time{}, err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	rec := t.issued[tok]
	if !notAfter.IsZero() && notAfter.Before(rec.expires) {
		rec.expires = notAfter
		t.issued[tok] = rec
	}
	return tok, rec.expires, nil
}

func (t *tokenStore) mint(subject string) (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	tok := base64.RawURLEncoding.EncodeToString(buf)
	t.mu.Lock()
	defer t.mu.Unlock()
	t.issued[tok] = issuedToken{expires: time.Now().Add(t.ttl), subject: subject}
	return tok, nil
}

// machineSubject marks a handle minted in gateway-secret / machine-identity
// mode, where there is no end-user identity to bind to and the gateway secret
// is the control instead. It is a distinct sentinel so a user-mode handle can
// never be satisfied by an absent subject.
const machineSubject = "\x00machine"

// validFor reports whether tok is live AND was issued to subject. Both
// conditions are required: liveness alone was the P0 that let a captured handle
// plus an arbitrary user-token header ride the shared session.
//
// An empty subject NEVER validates: that is exactly the replay case.
func (t *tokenStore) validFor(tok, subject string) bool {
	t.mu.RLock()
	rec, ok := t.issued[tok]
	t.mu.RUnlock()
	if !ok {
		return false
	}
	if time.Now().After(rec.expires) {
		t.revoke(tok)
		return false
	}
	if rec.subject == "" || subject == "" {
		return false
	}
	return rec.subject == subject
}

func (t *tokenStore) revoke(tok string) {
	t.mu.Lock()
	delete(t.issued, tok)
	t.mu.Unlock()
}

// ---------------------------------------------------------------- proxy

type portal struct {
	cfg    *config
	sess   *upstreamSession
	tokens *tokenStore
	proxy  *httputil.ReverseProxy
	verif  *tokenVerifier
}

// httpClientWithCA builds a client that trusts an internal CA when one is
// configured. The JWKS fetch needs this for the same reason the secret-store
// client does: the identity provider is signed by the internal CA, and without
// it verification fails -- which, because the verifier fails closed, would deny
// every request rather than degrade quietly.
func httpClientWithCA(caFile string, timeout time.Duration) (*http.Client, error) {
	tr := &http.Transport{}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", caFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s contained no usable certificates", caFile)
		}
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{
		Timeout:       timeout,
		Transport:     tr,
		CheckRedirect: refuseRedirects, // fetches the issuer's signing keys
	}, nil
}

func newPortal(cfg *config, sess *upstreamSession) *portal {
	p := &portal{cfg: cfg, sess: sess, tokens: newTokenStore(cfg.syntheticTTL)}
	if cfg.jwksURL != "" {
		jc, err := httpClientWithCA(cfg.oidcCAFile, 10*time.Second)
		if err != nil {
			// Fail loudly at construction: a verifier that cannot reach the
			// identity provider denies every request, which presents as an
			// outage rather than as the misconfiguration it is.
			slog.Error("cannot build the JWKS client", "error", err)
			os.Exit(1)
		}
		p.verif = newTokenVerifier(cfg.jwksURL, cfg.tokenIssuer, cfg.tokenAudience,
			jc, cfg.jwksCacheTTL)
	}

	transport := &http.Transport{}
	if cfg.upstreamInsecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}

	p.proxy = &httputil.ReverseProxy{
		Transport:      transport,
		ModifyResponse: p.injectBootstrap,
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(cfg.upstreamURL)
			r.Out.Host = cfg.upstreamURL.Host

			// THE SWAP. Whatever the browser presented, the appliance only
			// ever sees the real token. A browser that never authenticated
			// gets no Authorization header at all, so the appliance rejects
			// it rather than the portal silently elevating anonymous callers.
			r.Out.Header.Del("Authorization")

			// STRIP HIGH-SIDE CREDENTIALS. The appliance has no business seeing
			// the operator's identity token or the broker's session cookie, and
			// forwarding them leaks both into vendor firmware whose logs and
			// integrity we do not control. The broker cookie is the more
			// damaging of the two: whoever holds it can impersonate the operator
			// to the broker itself for the cookie's full lifetime.
			//
			// Only the appliance's OWN credential (set below) should go upstream.
			r.Out.Header.Del(cfg.userTokenHeader)
			r.Out.Header.Del("Cookie")
			r.Out.Header.Del(cfg.gatewaySecretHeader)
			r.Out.Header.Del("X-Warpgate-Username")
			// The handle must be live AND bound to the subject presenting it.
			// Checking only liveness was the P0: a handle observed on the wire
			// plus ANY non-empty user-token header rode the shared session.
			subj := machineSubject
			if cfg.requireUserToken {
				// VERIFIED subject, not a re-parse. The gate has already
				// verified this request, so a failure here is impossible in
				// practice -- but deriving a security binding from an
				// unverified read is the defect this build removes, and it
				// must not survive anywhere.
				vc, err := p.verifyUserToken(r.In.Header.Get(cfg.userTokenHeader))
				if err != nil {
					subj = "" // cannot match any bound handle
				} else {
					subj = vc.Subject
				}
			}
			if presented, ok := bearerOf(r.In.Header.Get("Authorization")); ok {
				if p.tokens.validFor(presented, subj) {
					if real := p.sess.currentToken(); real != "" {
						r.Out.Header.Set("Authorization", "Bearer "+real)
					}
				} else {
					// A live handle presented with the WRONG subject is the
					// signature of an attempted replay. Previously this fell
					// through silently and was proxied anonymously, discarding
					// the single highest-signal detection event.
					slog.Warn("handle rejected: not bound to the presenting subject",
						"path", r.In.URL.Path, "remote", r.In.RemoteAddr)
				}
			}
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			slog.Error("upstream proxy error", "error", err)
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
		},
	}
	return p
}

// bootstrapScript is injected into the appliance's index.html so the operator
// never sees the appliance's own login form.
//
// The SPA decides it is logged in by reading sessionStorage["auth"], so we
// populate that before its bundle runs. The values mirror exactly what the
// appliance's own login code writes:
//
//	sessionStorage auth      = {token, expiretime}
//	localStorage   userName  = <user>
//	localStorage   isFirstLogin = "0"
//
// The token stored here is the SYNTHETIC one — the real appliance token is
// still never sent to the browser.
const bootstrapScript = `<script>
(function () {
  try {
    // Re-seed unless there is a session that is still comfortably valid.
    // Checking only for presence would let a STALE entry (from an earlier
    // failed attempt, or one that expired while the tab was open) suppress
    // the bootstrap, leaving the SPA to render its login form.
    var cur = sessionStorage.getItem("auth");
    if (cur) {
      var parsed = JSON.parse(cur);
      if (parsed && parsed.token && parsed.expiretime > Date.now() + 30000) { return; }
      sessionStorage.removeItem("auth");
    }
  } catch (e) {
    try { sessionStorage.removeItem("auth"); } catch (e2) { return; }
  }
  var x = new XMLHttpRequest();
  // Synchronous on purpose: the SPA's bundle must not start before the session
  // exists, and a reload-based alternative makes the page visibly flicker.
  x.open("PATCH", "%s", false);
  x.setRequestHeader("Content-Type", "application/json");
  try {
    x.send(JSON.stringify({ user: "", password: "" }));
    if (x.status >= 200 && x.status < 300) {
      var d = JSON.parse(x.responseText);
      var r = d.restful_res || d;
      if (r && r.token) {
        var ttl = (r.timeout || 300) * 1000;
        sessionStorage.setItem("auth", JSON.stringify({ token: r.token, expiretime: Date.now() + ttl }));
        localStorage.setItem("userName", %q);
        localStorage.setItem("isFirstLogin", "0");
        // Seeding storage is not sufficient: the SPA's router sends "/" and
        // "/login" to the login screen regardless of stored session, because
        // its own login code NAVIGATES on success. Rewrite the path before the
        // bundle boots so the router initialises on the dashboard instead.
        var p = location.pathname;
        if (p === "/" || p === "" || p.indexOf("/login") === 0) {
          history.replaceState(null, "", %q + location.search + location.hash);
        }
      }
    }
  } catch (e) { /* fall through to the appliance's own login form */ }
})();
</script>`

// injectBootstrap rewrites the appliance's HTML document to pre-seed the
// session. Only the main document is touched; assets and API responses pass
// through untouched.
func (p *portal) injectBootstrap(resp *http.Response) error {
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(strings.ToLower(ct), "text/html") {
		return nil
	}
	// Content-Encoding would have to be decoded first; the appliance serves
	// this document uncompressed, so refuse rather than corrupt it.
	if enc := resp.Header.Get("Content-Encoding"); enc != "" && enc != "identity" {
		slog.Warn("not injecting bootstrap: response is encoded", "encoding", enc)
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()

	html := string(body)
	landing := p.cfg.landingPath
	if landing == "" {
		landing = "/"
	}
	script := fmt.Sprintf(bootstrapScript, p.cfg.loginPath, p.cfg.username, landing)

	// Insert before the first <script> so it runs ahead of the SPA bundle;
	// fall back to </head>, then give up and pass the document through.
	switch {
	case strings.Contains(html, "<script"):
		i := strings.Index(html, "<script")
		html = html[:i] + script + html[i:]
	case strings.Contains(html, "</head>"):
		html = strings.Replace(html, "</head>", script+"</head>", 1)
	default:
		slog.Warn("not injecting bootstrap: no <script> or </head> anchor found")
		resp.Body = io.NopCloser(strings.NewReader(html))
		return nil
	}

	resp.Body = io.NopCloser(strings.NewReader(html))
	resp.Header.Del("Content-Length")
	resp.ContentLength = int64(len(html))
	slog.Info("injected session bootstrap into appliance document")
	return nil
}

// verifyUserToken cryptographically verifies the forwarded token and returns
// what was proved. There is deliberately no unverified path: if no verifier is
// configured the service refuses to start in per-user mode (see loadConfig), so
// reaching here without one is a programming error, not a deployment choice.
func (p *portal) verifyUserToken(tok string) (verifiedClaims, error) {
	if tok == "" {
		return verifiedClaims{}, errors.New("no user token presented")
	}
	if p.verif == nil {
		return verifiedClaims{}, errors.New("no token verifier configured")
	}
	return p.verif.verify(tok)
}

// subjectOf extracts the `sub` claim from a JWT WITHOUT verifying the
// signature. That is sufficient here because the token's AUTHORITY is
// established separately -- OpenBao verifies it at login. This value is used
// only to bind a synthetic handle to the identity it was issued for, so a
// captured handle cannot be replayed alongside a different (or bogus) user
// token. An attacker who forges a `sub` gains nothing: the handle they hold was
// bound to the real subject at mint time, and minting requires OpenBao to have
// authorised that subject.
func subjectOf(tok string) string {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if json.Unmarshal(raw, &claims) != nil {
		return ""
	}
	// The sentinel marks machine mode and must never be assertable by a token
	// from the wire. Without this, a crafted {"sub":"\x00machine"} would let a
	// user-mode request satisfy a machine-mode handle. NUL is rejected wholesale
	// rather than just the exact sentinel, so a future sentinel cannot reopen it.
	if claims.Sub == machineSubject || strings.ContainsRune(claims.Sub, 0) {
		return ""
	}
	return claims.Sub
}

// subjectLabel renders a subject for logging. The machine sentinel contains a
// NUL byte, which must never reach a log line verbatim.
func subjectLabel(s string) string {
	if s == machineSubject {
		return "machine"
	}
	return s
}

// fromGateway reports whether a request carries the broker's shared secret.
// Compared in constant time so the header cannot be discovered by timing.
func (p *portal) fromGateway(r *http.Request) bool {
	if p.cfg.gatewaySecret == "" {
		return p.cfg.allowNoGatewayAuth
	}
	got := r.Header.Get(p.cfg.gatewaySecretHeader)
	return subtle.ConstantTimeCompare([]byte(got), []byte(p.cfg.gatewaySecret)) == 1
}

func (p *portal) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Health is unauthenticated so kubelet probes work.
	if r.URL.Path == "/healthz" {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
		return
	}

	// Primary gate: the broker must have forwarded the end user's token, which
	// is what OpenBao will authorise against. In the fallback (machine
	// identity) mode there is no user token, so the shared secret is the gate.
	if p.cfg.requireUserToken {
		userToken := r.Header.Get(p.cfg.userTokenHeader)
		if userToken == "" {
			slog.Warn("rejected request with no forwarded user token",
				"path", r.URL.Path, "remote", r.RemoteAddr, "header", p.cfg.userTokenHeader)
			http.Error(w, "forbidden: no user identity", http.StatusForbidden)
			return
		}
		// Presence is NOT sufficient. Checking only that the header was
		// non-empty meant any string ("not-a-jwt-at-all") was accepted as an
		// identity, so a synthetic handle captured on the wire could be replayed
		// with a bogus user token for the handle's full lifetime.
		//
		// The token must be well-formed, unexpired, and carry a subject. Its
		// AUTHORITY is still established by OpenBao at login; this gate exists
		// to stop unauthenticated replay of the handle.
		// Verify the SIGNATURE, issuer, audience and expiry on EVERY use --
		// not only at login. Without this the capability's subject binding is
		// meaningless: an observer of the boundary sees both the capability and
		// the subject, and could forge an unsigned assertion of that subject.
		if _, err := p.verifyUserToken(userToken); err != nil {
			slog.Warn("rejected request with an unverifiable user token",
				"path", r.URL.Path, "remote", r.RemoteAddr, "error", err)
			http.Error(w, "forbidden: invalid user identity", http.StatusForbidden)
			return
		}
	} else if !p.fromGateway(r) {
		slog.Warn("rejected request without the gateway shared secret",
			"path", r.URL.Path, "remote", r.RemoteAddr)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	switch {

	// The login request is answered here, never forwarded. Whatever
	// credentials the browser submitted are discarded unread.
	case r.Method == http.MethodPatch && r.URL.Path == p.cfg.loginPath:
		p.handleLogin(w, r)
		return

	// Refresh keeps the browser's handle alive. The upstream session is
	// refreshed independently by ensure(), so this only re-issues a handle.
	case r.Method == http.MethodPatch && r.URL.Path == p.cfg.refreshPath:
		p.handleLogin(w, r)
		return

	// Logout drops this browser's handle. It deliberately does NOT log out
	// upstream: the appliance session is shared by every operator, so tearing
	// it down would disconnect everyone else.
	case r.Method == http.MethodPatch && r.URL.Path == p.cfg.logoutPath:
		if presented, ok := bearerOf(r.Header.Get("Authorization")); ok {
			// Revoke ONLY a handle bound to the presenting subject. Revoking any
			// presented handle let an observer on the wire kill the victim's
			// session with a captured handle -- availability loss for free.
			revSubj := machineSubject
			if p.cfg.requireUserToken {
				vc, err := p.verifyUserToken(r.Header.Get(p.cfg.userTokenHeader))
				if err != nil {
					revSubj = "" // cannot match any bound handle
				} else {
					revSubj = vc.Subject
				}
			}
			if !p.tokens.validFor(presented, revSubj) {
				slog.Warn("refused logout for a handle not bound to the presenting subject",
					"remote", r.RemoteAddr)
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			p.tokens.revoke(presented)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
		return
	}

	p.proxy.ServeHTTP(w, r)
}

func (p *portal) handleLogin(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body) // never inspect submitted credentials
	_ = r.Body.Close()

	userToken := r.Header.Get(p.cfg.userTokenHeader)
	// Authorise THIS user against OpenBao even if the appliance session is
	// already warm, so nobody rides another user's authorisation.
	if p.cfg.requireUserToken {
		if err := p.sess.authorize(userToken); err != nil {
			// The subject is CLAIMED, not verified: authorisation just failed,
			// so nothing here has been established. It is still the better field
			// to log than X-Warpgate-Username -- that header is an unsigned,
			// unverifiable second identity channel, and attributing a refusal to
			// it records an identity nobody authenticated.
			slog.Warn("OpenBao refused this user", "error", err,
				"claimed_subject", subjectOf(userToken))
			http.Error(w, "forbidden: not authorised for this device", http.StatusForbidden)
			return
		}
	}

	mintSubject := machineSubject
	var assertionExpiry time.Time
	if p.cfg.requireUserToken {
		vc, err := p.verifyUserToken(userToken)
		if err != nil {
			slog.Warn("refusing to mint on an unverifiable token", "error", err)
			http.Error(w, "forbidden: invalid user identity", http.StatusForbidden)
			return
		}
		mintSubject = vc.Subject
		assertionExpiry = vc.ExpiresAt
		if mintSubject == "" {
			slog.Warn("authorised token carries no subject; refusing to mint an unbound handle")
			http.Error(w, "forbidden: no subject in user identity", http.StatusForbidden)
			return
		}
	}
	synthetic, capExpiry, err := p.tokens.mintUntil(mintSubject, assertionExpiry)
	if err != nil {
		slog.Error("mint synthetic token", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	body, err := p.sess.loginResponseFor(synthetic, userToken)
	if err != nil {
		p.tokens.revoke(synthetic)
		slog.Error("could not establish appliance session", "error", err)
		http.Error(w, "appliance session unavailable", http.StatusBadGateway)
		return
	}

	// mintSubject is the subject OpenBao authorised moments ago, so unlike the
	// broker's X-Warpgate-Username header it is an identity this service
	// actually established. Attribution and authorisation now agree.
	// Log both deadlines so the bound is verifiable in production rather than
	// only in tests: "bounded_by" says which limit actually applied.
	boundedBy := "capability_ttl"
	if !assertionExpiry.IsZero() && !capExpiry.After(assertionExpiry) &&
		capExpiry.Before(time.Now().Add(p.tokens.ttl).Add(-time.Second)) {
		boundedBy = "assertion_expiry"
	}
	slog.Info("issued synthetic session to browser",
		"path", r.URL.Path, "subject", subjectLabel(mintSubject),
		"capability_expires_in_s", int(time.Until(capExpiry).Seconds()),
		"bounded_by", boundedBy)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// ---------------------------------------------------------------- helpers

func bearerOf(h string) (string, bool) {
	const p = "Bearer "
	if len(h) > len(p) && strings.EqualFold(h[:len(p)], p) {
		return h[len(p):], true
	}
	return "", false
}

// findString locates a top-level or one-level-nested string field, so a simple
// envelope does not require configuration.
func findString(m map[string]any, field string) (string, bool) {
	if v, ok := m[field].(string); ok {
		return v, true
	}
	for _, v := range m {
		if inner, ok := v.(map[string]any); ok {
			if s, ok := inner[field].(string); ok {
				return s, true
			}
		}
	}
	return "", false
}

func findNumber(m map[string]any, field string) (float64, bool) {
	if v, ok := m[field].(float64); ok {
		return v, true
	}
	for _, v := range m {
		if inner, ok := v.(map[string]any); ok {
			if f, ok := inner[field].(float64); ok {
				return f, true
			}
		}
	}
	return 0, false
}

func setString(m map[string]any, field, val string) bool {
	if _, ok := m[field]; ok {
		m[field] = val
		return true
	}
	for _, v := range m {
		if inner, ok := v.(map[string]any); ok {
			if _, ok := inner[field]; ok {
				inner[field] = val
				return true
			}
		}
	}
	return false
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cfg, err := loadConfig()
	if err != nil {
		slog.Error("configuration", "error", err)
		os.Exit(1)
	}
	bao, err := newOpenBao(cfg)
	if err != nil {
		slog.Error("openbao client", "error", err)
		os.Exit(1)
	}

	sess := newUpstreamSession(cfg, bao)
	p := newPortal(cfg, sess)

	// The appliance session is established lazily, on the first AUTHORISED
	// login, and never at startup.
	//
	// It used to be pre-warmed here with sess.ensure(""), which fetched the
	// credential using the pod's identity before any human had authenticated.
	// That made per-user authorisation additive rather than gating, and made
	// OpenBao's audit record name the service account. Do not reinstate it.
	if cfg.allowMachineCredential && !cfg.requireUserToken {
		if _, err := sess.ensure(""); err != nil {
			slog.Warn("machine-identity session not established at startup", "error", err)
		}
	}

	srv := &http.Server{
		Addr:              cfg.listenAddr,
		Handler:           p,
		ReadHeaderTimeout: 10 * time.Second,
	}
	slog.Info("switch-portal listening", "addr", cfg.listenAddr, "upstream", cfg.upstreamURL.String())
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("server", "error", err)
		os.Exit(1)
	}
}
