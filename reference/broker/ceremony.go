package main

// THE LOGIN CEREMONY
//
// The pattern claims a new target costs five parameters. Four of them were
// always configuration -- the login path, the logout path, the token field, the
// timeout field. The fifth, the SHAPE of the login request, was hardcoded, so
// in practice a target that spelled its login body differently needed a code
// change. That was an implementation gap, not a property of the pattern, and
// this file closes it.
//
// A ceremony is DATA: an HTTP verb and a body template. Rendering it is the
// whole of the per-target adaptation.
//
//	{"user":"{{.User}}","password":"{{.Password}}"}
//	{"username":"{{.User}}","password":"{{.Password}}","loginProviderName":"tmos"}
//	{"id":1,"method":"exec","params":[{"url":"sys/login/user",
//	  "data":[{"user":"{{.User}}","passwd":"{{.Password}}"}]}]}
//
// # WHY THIS IS A CEREMONY AND NOT AN ADAPTER
//
// An earlier review rejected letting each target contribute an adapter, and
// that rejection stands -- for adapters that SEE the credential. Such an
// adapter runs in-process while the broker holds plaintext, so its own
// authorised outbound channel is an exfiltration path, and no sandbox helps:
// the adapter is supposed to talk to the appliance.
//
// A ceremony is credential-blind. It never receives the secret and never runs
// as code. It DESCRIBES a request; this service renders it, and this service
// alone decides where the result is sent. The template has no field for the
// destination, and text/template performs no I/O, no process execution and no
// network calls, so a hostile ceremony's ceiling is rearranging a body that was
// already bound for the one place it was always going to be sent.
//
// That is the distinction worth carrying: contributors supply the shape of the
// request, never the code that handles the credential.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"text/template"
	"text/template/parse"
)

// ceremonyValues carries the two substitutions a login body may reference.
//
// Both are pre-escaped for a JSON string context before the template runs, so a
// credential containing a quote or a backslash cannot terminate its own field
// and alter the structure of the body around it. Escaping at construction
// rather than at each use is deliberate: it cannot be forgotten by a ceremony
// author, because the ceremony author never gets the raw value.
type ceremonyValues struct {
	User     string
	Password string
}

// jsonStringEscape escapes a value for interpolation INSIDE JSON string quotes.
// json.Marshal supplies the escaping and the surrounding quotes; the quotes are
// stripped because the ceremony template already writes them.
func jsonStringEscape(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		// json.Marshal of a string fails only on invalid UTF-8, which Marshal
		// itself repairs with U+FFFD rather than erroring. Kept total anyway.
		return ""
	}
	return string(b[1 : len(b)-1])
}

// checkCeremonyShape restricts a ceremony to the smallest grammar that can
// still express a login body: literal text, and substitutions of exactly
// {{.User}} or {{.Password}}.
//
// Owning the destination already makes duplicating the credential pointless --
// a copy still goes only where we send it. This makes it IMPOSSIBLE, which is
// the stronger and more reviewable property: a human reading a ceremony does
// not have to reason about where else the credential might have got to.
//
// Everything with the power to repeat a value is rejected outright rather than
// analysed: {{if}}, {{range}}, {{with}}, {{template}}, {{define}}, {{block}},
// variable assignment, and pipelines (so `{{.Password | printf "%s%s"}}` cannot
// launder a second copy through a function). Whitelisting the two node types we
// need is safe against constructs added to text/template in future Go releases;
// blacklisting known-bad ones would not be.
func checkCeremonyShape(tree *parse.Tree) error {
	seenPassword := 0
	for _, n := range tree.Root.Nodes {
		switch node := n.(type) {
		case *parse.TextNode:
			// Literal bytes of the body. Inert.
		case *parse.ActionNode:
			if len(node.Pipe.Decl) != 0 {
				return fmt.Errorf("a ceremony may not declare variables")
			}
			if len(node.Pipe.Cmds) != 1 {
				return fmt.Errorf("a ceremony may not use pipelines")
			}
			args := node.Pipe.Cmds[0].Args
			if len(args) != 1 {
				return fmt.Errorf("a ceremony may not call functions")
			}
			field, ok := args[0].(*parse.FieldNode)
			if !ok || len(field.Ident) != 1 {
				return fmt.Errorf("a ceremony may substitute only .User and .Password")
			}
			switch field.Ident[0] {
			case "User":
			case "Password":
				seenPassword++
			default:
				return fmt.Errorf("unknown substitution .%s: a ceremony may substitute "+
					"only .User and .Password", field.Ident[0])
			}
		default:
			// {{if}}, {{range}}, {{with}}, {{template}}, {{block}}, comments...
			return fmt.Errorf("a ceremony may contain only literal text and " +
				"{{.User}} / {{.Password}} substitutions")
		}
	}
	// Exactly once, in both directions. Zero would authenticate as nobody;
	// more than one is the duplication this whole check exists to prevent.
	if seenPassword == 0 {
		return fmt.Errorf("a ceremony must reference {{.Password}} exactly once, found none: " +
			"the login request would carry no credential")
	}
	if seenPassword > 1 {
		return fmt.Errorf("a ceremony must reference {{.Password}} exactly once, found %d: "+
			"the credential may appear in the login body once and nowhere else", seenPassword)
	}
	return nil
}

// renderLoginBody turns a ceremony into the exact bytes of a login request body.
//
// It does NOT decide where those bytes go. The caller owns the destination.
func renderLoginBody(ceremony, user, password string) (string, error) {
	// No missingkey option: the data is a STRUCT, and text/template already
	// errors on an unknown struct field ("can't evaluate field ..."), so a
	// typo such as {{.Passwrd}} cannot silently render as empty. missingkey
	// governs map lookups only, and would be misleading reassurance here.
	tmpl, err := template.New("login").Parse(ceremony)
	if err != nil {
		return "", fmt.Errorf("parse ceremony: %w", err)
	}
	// Enforced on EVERY render, not only at startup: a config path that reached
	// rendering without passing the startup guard must not get a weaker rule.
	if err := checkCeremonyShape(tmpl.Tree); err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, ceremonyValues{
		User:     jsonStringEscape(user),
		Password: jsonStringEscape(password),
	}); err != nil {
		// Deliberately not wrapping buf: on a failed execute it may hold a
		// partially rendered body, and that body contains the credential.
		return "", fmt.Errorf("execute ceremony: %w", err)
	}
	// A ceremony that renders to malformed JSON is a bug we would otherwise
	// discover as an opaque appliance 400 while holding the password. Refuse
	// here instead. The error deliberately does not quote the body.
	if !json.Valid(buf.Bytes()) {
		return "", fmt.Errorf("ceremony rendered to invalid JSON")
	}
	return buf.String(), nil
}

// defaultLoginMethod and defaultLoginBody describe the reference appliance.
// They are the DEFAULT ceremony, not a privileged one -- a different target
// replaces them through LOGIN_METHOD and LOGIN_BODY without touching code.
// Kept here so production defaults and test fixtures cannot drift apart.
const (
	defaultLoginMethod = http.MethodPatch
	defaultLoginBody   = `{"user":"{{.User}}","password":"{{.Password}}"}`
)

// loginCeremonyProbe is the sentinel credential used to exercise a ceremony at
// startup. It contains a quote and a backslash so that a ceremony which somehow
// defeats escaping shows up as invalid JSON at boot rather than at first login.
const loginCeremonyProbe = `pr"obe\value`

// validateLoginCeremony is the startup half of the ceremony contract, and the
// exact analogue of validateUpstreamURL: establish that the login request is
// well formed while nothing is at stake, rather than discovering it later while
// holding the appliance password.
func validateLoginCeremony(method, ceremony string) error {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
	default:
		return fmt.Errorf("LOGIN_METHOD must be POST, PUT or PATCH, got %q", method)
	}
	// Rendering with the probe exercises the shape check, the escaping and the
	// JSON validity check in one go. The rendered body is discarded: it is only
	// evidence that a real login WOULD render, and it contains a credential
	// (albeit a fake one), so it is not something to hold or log.
	if _, err := renderLoginBody(ceremony, "probe-user", loginCeremonyProbe); err != nil {
		return fmt.Errorf("LOGIN_BODY: %w", err)
	}
	return nil
}
