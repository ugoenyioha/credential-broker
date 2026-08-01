package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The pattern claims a new target costs five parameters and no code. Four were
// always configuration; the fifth -- the login request shape -- used to be
// hardcoded. These are the tests that make the fifth one true too.

// TestCeremonyRendersRealVendorLoginShapes is the evidence behind the
// five-parameter claim. Each shape below is the documented login body of a real
// product, reached by configuration alone. If a target ever needs Go again,
// this test is where that should first become visible.
func TestCeremonyRendersRealVendorLoginShapes(t *testing.T) {
	cases := []struct {
		name   string
		method string
		body   string
		// where the credential must land in the parsed body, so the test
		// asserts placement rather than just "the password appears somewhere".
		check func(t *testing.T, parsed map[string]any)
	}{
		{
			// The reference appliance, and the shipped default.
			name:   "flat user/password (reference appliance)",
			method: http.MethodPatch,
			body:   defaultLoginBody,
			check: func(t *testing.T, parsed map[string]any) {
				if parsed["user"] != "operator" || parsed["password"] != "s3cr3t" {
					t.Fatalf("credential not placed: %v", parsed)
				}
			},
		},
		{
			// F5 BIG-IP iControl REST. Same flat shape, different key names,
			// plus a constant the ceremony carries verbatim.
			// https://clouddocs.f5.com/api/icontrol-soap/Authentication_with_the_F5_REST_API.html
			name:   "F5 BIG-IP iControl REST",
			method: http.MethodPost,
			body:   `{"username":"{{.User}}","password":"{{.Password}}","loginProviderName":"tmos"}`,
			check: func(t *testing.T, parsed map[string]any) {
				if parsed["username"] != "operator" || parsed["password"] != "s3cr3t" {
					t.Fatalf("credential not placed: %v", parsed)
				}
				if parsed["loginProviderName"] != "tmos" {
					t.Fatalf("ceremony constant not carried: %v", parsed)
				}
			},
		},
		{
			// FortiManager. The awkward case, and the reason this test exists:
			// the credential is nested inside a JSON-RPC envelope, under an
			// array, under a different pair of key names again. A hardcoded
			// flat body cannot express this at all.
			// https://community.fortinet.com/fortimanager-27/technical-tip-using-fortimanager-fortianalyzer-api-113174
			name:   "FortiManager JSON-RPC",
			method: http.MethodPost,
			body: `{"id":1,"method":"exec","params":[{"url":"/sys/login/user",` +
				`"data":{"user":"{{.User}}","passwd":"{{.Password}}"}}]}`,
			check: func(t *testing.T, parsed map[string]any) {
				params, ok := parsed["params"].([]any)
				if !ok || len(params) != 1 {
					t.Fatalf("params not an array of one: %v", parsed)
				}
				data := params[0].(map[string]any)["data"].(map[string]any)
				if data["user"] != "operator" || data["passwd"] != "s3cr3t" {
					t.Fatalf("credential not placed in nested envelope: %v", data)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Every shape must survive the startup guard, since in production
			// nothing reaches a login without passing it first.
			if err := validateLoginCeremony(tc.method, tc.body); err != nil {
				t.Fatalf("real vendor ceremony rejected at startup: %v", err)
			}
			rendered, err := renderLoginBody(tc.body, "operator", "s3cr3t")
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			var parsed map[string]any
			if err := json.Unmarshal([]byte(rendered), &parsed); err != nil {
				t.Fatalf("rendered body is not valid JSON: %v", err)
			}
			tc.check(t, parsed)
		})
	}
}

// TestCeremonyCannotBreakOutOfItsJSONString is the escaping property. A
// credential is attacker-influenced in the sense that nobody reviews what an
// operator sets in the vault, so a password full of quotes and braces must
// remain one JSON string value rather than becoming structure.
func TestCeremonyCannotBreakOutOfItsJSONString(t *testing.T) {
	hostile := `","admin":true,"x":"` + "\\" + `"`
	rendered, err := renderLoginBody(defaultLoginBody, "operator", hostile)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(rendered), &parsed); err != nil {
		t.Fatalf("hostile credential produced invalid JSON: %v", err)
	}
	// The injected key must NOT exist: the payload stayed data.
	if _, injected := parsed["admin"]; injected {
		t.Fatalf("credential escaped its string and injected a field: %v", parsed)
	}
	if parsed["password"] != hostile {
		t.Fatalf("credential did not round-trip intact: %q", parsed["password"])
	}
	if len(parsed) != 2 {
		t.Fatalf("expected exactly user and password, got %v", parsed)
	}
}

// TestCeremonyCannotRedirectTheCredential is the security property that
// separates a ceremony from an adapter, stated as a test.
//
// A hostile ceremony can copy the credential into extra fields -- that is
// conceded, and this test asserts it, because the point is that it does not
// matter. The body still goes only where the SERVICE sends it, and a ceremony
// has no way to express a destination. Note the deliberate absence of any
// assertion that the extra field is stripped: the defence is not sanitising the
// body, it is owning the address.
func TestCeremonyCannotRedirectTheCredential(t *testing.T) {
	hostile := `{"user":"{{.User}}","password":"{{.Password}}",` +
		`"exfil":"{{.Password}}"}`

	rendered, err := renderLoginBody(hostile, "operator", "s3cr3t")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(rendered), &parsed); err != nil {
		t.Fatal(err)
	}
	// Conceded: it duplicated the credential within the body.
	if parsed["exfil"] != "s3cr3t" {
		t.Fatalf("precondition failed; expected the copy to be present: %v", parsed)
	}

	// The property that actually matters: a ceremony is a body, and a body has
	// no address. The template language offers no field, function or syntax
	// that names a destination, so the only URL in play is the one the service
	// builds from upstreamURL and loginPath.
	for _, forbidden := range []string{"http://", "https://", "{{.URL}}", "{{.Destination}}"} {
		if strings.Contains(rendered, forbidden) {
			t.Fatalf("ceremony output contained a destination-like token %q", forbidden)
		}
	}

	// And a ceremony that TRIES to name one gets a literal, not a redirect:
	// text/template has no I/O, no exec and no network, so an unknown field is
	// an error and a string is just a string.
	attempt := `{"user":"{{.User}}","password":"{{.Password}}","url":"https://attacker.example/collect"}`
	out, err := renderLoginBody(attempt, "operator", "s3cr3t")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !json.Valid([]byte(out)) {
		t.Fatal("expected inert JSON")
	}
	// It rendered as an inert string in a body bound for the configured
	// upstream. Nothing dials it. That is the whole defence.
}

// TestCeremonyRejectsUnknownSubstitutions keeps the ceremony surface to exactly
// the two values a login needs. Without missingkey=error a typo such as
// {{.Passwrd}} renders as empty and the broker authenticates with a blank
// credential, which reaches the appliance as a confusing auth failure.
func TestCeremonyRejectsUnknownSubstitutions(t *testing.T) {
	_, err := renderLoginBody(`{"user":"{{.User}}","password":"{{.Passwrd}}"}`, "operator", "s3cr3t")
	if err == nil {
		t.Fatal("expected a typo'd substitution to be rejected, not rendered empty")
	}
}

// TestValidateLoginCeremonyRejectsBadCeremoniesAtStartup mirrors the destination
// guard: every one of these must fail at boot, while nothing is at stake,
// rather than at first login while the service holds the appliance password.
func TestValidateLoginCeremonyRejectsBadCeremoniesAtStartup(t *testing.T) {
	cases := []struct {
		name   string
		method string
		body   string
	}{
		{"GET cannot carry a login body", http.MethodGet, defaultLoginBody},
		{"unparseable template", http.MethodPost, `{"user":"{{.User"}`},
		// Deliberately carries the credential, so that this case can ONLY be
		// caught by the JSON validity check and not by the empty-handed check
		// below it. An earlier version of this case omitted the password and
		// was silently caught by the wrong guard.
		{"renders to malformed JSON", http.MethodPost,
			`{"user":"{{.User}}","password":"{{.Password}}",}`},
		{"unknown substitution", http.MethodPost, `{"p":"{{.Nope}}"}`},
		{"carries no credential at all", http.MethodPost, `{"user":"{{.User}}"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateLoginCeremony(tc.method, tc.body); err == nil {
				t.Fatal("expected startup rejection, got none")
			}
		})
	}
	// And the shipped default must pass the guard it is shipped with.
	if err := validateLoginCeremony(defaultLoginMethod, defaultLoginBody); err != nil {
		t.Fatalf("default ceremony rejected by its own guard: %v", err)
	}
}

// TestCeremonyErrorsNeverQuoteTheCredential. Ceremony failures are config
// errors, so they are exactly the errors an operator pastes into a ticket.
func TestCeremonyErrorsNeverQuoteTheCredential(t *testing.T) {
	const secret = "hunter2-do-not-log"
	for _, body := range []string{
		`{"user":"{{.User}}",}`,
		`{"p":"{{.Nope}}"}`,
		`{"user":"{{.User"}`,
	} {
		_, err := renderLoginBody(body, "operator", secret)
		if err == nil {
			t.Fatalf("expected failure for %q", body)
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("credential leaked into error: %v", err)
		}
	}
	// Same for the startup guard, whose probe is itself credential-shaped.
	err := validateLoginCeremony(http.MethodPost, `{"user":"{{.User}}"}`)
	if err == nil || strings.Contains(err.Error(), loginCeremonyProbe) {
		t.Fatalf("probe value leaked into startup error: %v", err)
	}
}

// TestDifferentlyShapedApplianceOnboardsWithoutCode is the claim under test:
// "onboarding is configuration, not an integration project."
//
// The appliance below is deliberately nothing like the reference one. It speaks
// FortiManager's JSON-RPC dialect: POST to /jsonrpc, the credential nested in an
// envelope under {user, passwd}, and the session token returned as "session"
// rather than "token". Under the old hardcoded body this target was unreachable
// without editing Go. Here it is reached by changing configuration only -- note
// that the test body contains no production code, just different strings.
func TestDifferentlyShapedApplianceOnboardsWithoutCode(t *testing.T) {
	const rpcToken = "FMG-SESSION-do-not-leak"

	var sawCredential bool
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/jsonrpc" {
			// Decode the vendor's real envelope. If the ceremony rendered the
			// wrong shape, this decode or the lookups below will not match.
			var env struct {
				Method string `json:"method"`
				Params []struct {
					URL  string `json:"url"`
					Data struct {
						User   string `json:"user"`
						Passwd string `json:"passwd"`
					} `json:"data"`
				} `json:"params"`
			}
			if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if env.Method != "exec" || len(env.Params) != 1 ||
				env.Params[0].URL != "/sys/login/user" ||
				env.Params[0].Data.Passwd != appliancePasswd {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			sawCredential = true
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"session":"` + rpcToken + `","timeout":900}`))
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+rpcToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer app.Close()

	bao := fakeOpenBao(t)
	defer bao.Close()

	p := newTestPortal(t, app.URL, bao.URL)
	// ---- the entire cost of onboarding this target: five strings ----
	p.cfg.loginPath = "/jsonrpc"
	p.cfg.loginMethod = http.MethodPost
	p.cfg.loginBody = `{"id":1,"method":"exec","params":[{"url":"/sys/login/user",` +
		`"data":{"user":"{{.User}}","passwd":"{{.Password}}"}}]}`
	p.cfg.tokenField = "session"
	p.cfg.timeoutField = "timeout"
	// -----------------------------------------------------------------

	srv := httptest.NewServer(p)
	defer srv.Close()

	lr := gwReq(t, http.MethodPost, srv.URL+"/jsonrpc", `{}`)
	resp, err := http.DefaultClient.Do(lr)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login against differently-shaped appliance failed: %d %s", resp.StatusCode, raw)
	}
	if !sawCredential {
		t.Fatal("appliance never received a correctly shaped login")
	}
	// The security properties must hold identically on a target we onboarded
	// purely by configuration -- that is the point of the exercise.
	if strings.Contains(string(raw), rpcToken) {
		t.Fatal("SECURITY FAILURE: real session token returned to the browser")
	}
	if strings.Contains(string(raw), appliancePasswd) {
		t.Fatal("SECURITY FAILURE: appliance password returned to the browser")
	}

	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("login response not JSON: %s", raw)
	}
	synthetic, _ := body["session"].(string)
	if synthetic == "" {
		t.Fatalf("no synthetic token issued in the vendor's own field: %s", raw)
	}

	// And the handle works: swapped back for the real token on the way out.
	req := gwReq(t, http.MethodGet, srv.URL+"/api/thing", "")
	req.Header.Set("Authorization", "Bearer "+synthetic)
	r2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Body.Close()
	if r2.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(r2.Body)
		t.Fatalf("synthetic token not honoured upstream: %d %s", r2.StatusCode, b)
	}
}
