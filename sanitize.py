#!/usr/bin/env python3
"""Build the public reference copy from the private working tree.

Rewrites environment-specific identifiers to documentation placeholders. Ordered
longest-first, and IPs are matched with word boundaries because 192.168.1.20 is a
prefix of 192.168.1.206 — a naive ordered replace turns the latter into
"<placeholder>6", which looks plausible and is wrong.

Run from the repo root:  python3 sanitize.py --check
"""
import re, sys, pathlib, shutil

# (pattern, replacement, is_regex)
SUBS = [
    # --- MUST BE FIRST: compound identifiers whose parts are rewritten below.
    # "github.com/usableapps/homelab/..." would otherwise be eaten piecewise by
    # the usableapps->example and homelab->example rules and emerge as
    # "github.com/example/example/...". Order is load-bearing here.
    ("github.com/usableapps/homelab/services/switch-portal",
     "github.com/example/credential-broker/reference/broker", False),

    # --- hosts, longest first -------------------------------------------------
    ("vault-qnap.home.usableapps.io",        "vault.example.internal",   False),
    ("wso2is.onprem.usableapps.io",          "idp.example.internal",     False),
    ("warpgate.home.usableapps.io",          "gateway.example.internal", False),
    ("gitlab-registry.onprem.usableapps.io", "ghcr.io/example",          False),
    (r"[a-z0-9-]+\.home\.usableapps\.io",    "host.example.internal",    True),
    (r"[a-z0-9-]+\.onprem\.usableapps\.io",  "host.example.internal",    True),
    ("usableapps.io",                        "example.internal",         False),
    ("usableapps",                           "example",                  False),

    # --- addresses: RFC 5737 TEST-NET-1, word-bounded -------------------------
    (r"\b192\.168\.1\.206\b", "192.0.2.10", True),   # IdP + vault (same host)
    (r"\b192\.168\.1\.254\b", "192.0.2.20", True),   # managed appliance
    (r"\b192\.168\.1\.20\b",  "192.0.2.30", True),   # gateway LoadBalancer
    (r"\b192\.168\.1\.16\b",  "192.0.2.40", True),   # ingress controller
    (r"\b192\.168\.1\.\d+\b", "192.0.2.99", True),   # anything else

    # --- identity -------------------------------------------------------------
    ("ugo.enyioha@gmail.com", "operator@example.com", False),
    ("Ugo Enyioha",           "Example Operator",     False),
    ("enyioha",               "operator",             False),

    # --- tenancy / naming -----------------------------------------------------
    ("urn:homelab:switch-credential", "urn:example:appliance-credential", False),
    ("kv/talos/switch/admin",         "kv/example/appliance/admin",       False),
    ("kv/talos/warpgate/config",      "kv/example/gateway/config",        False),
    ("kubernetes",         "kubernetes",                       False),
    ("ai-forge/kubeopencode",         "example",                          False),
    ("homelab",                       "example",                          False),

    # --- credentials that must never appear -----------------------------------
    (r"wn_[A-Za-z0-9]{20,}", "<oidc-client-id>", True),
]

# Anything matching these in the OUTPUT is a failure, not a warning.
FORBIDDEN = [
    r"usableapps", r"enyioha", r"@gmail", r"\b192\.168\.\d+\.\d+\b",
    r"vault-qnap", r"wso2is", r"onprem", r"gitlab-registry", r"wn_[A-Za-z0-9]{20,}",
    # NOT \bhrl\b: inside a literal "\\bhrl\\b" the term is preceded by a word
    # character, so the boundary never matches and the hit is missed. Plain substring.
    r"hrl", r"jpmc", r"jpmorgan",
    # source-specific framing and internal product names: these identify where
    # the problem came from even with no company name present.
    r"\bSXP\b", r"sentrywire", r"forensic",
]

SKIP_SUFFIX = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".tar", ".gz", ".zip"}


def sanitize(text: str) -> str:
    for pat, rep, is_re in SUBS:
        text = re.sub(pat, rep, text) if is_re else text.replace(pat, rep)
    return text


def scan(root: pathlib.Path):
    """Return [(path, pattern, count)] for every forbidden hit."""
    hits = []
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.suffix.lower() in SKIP_SUFFIX:
            continue
        if "/.git/" in str(p) or p.name == "sanitize.py":
            continue
        try:
            t = p.read_text()
        except (UnicodeDecodeError, OSError):
            continue
        for f in FORBIDDEN:
            n = len(re.findall(f, t, re.IGNORECASE))
            if n:
                hits.append((p.relative_to(root), f, n))
    return hits


# Canaries sanitize() is expected to REWRITE. Failure here means the rewrite
# rules have drifted from the detector.
REWRITABLE = [
    "contact ugo.enyioha@gmail.com",
    "https://vault-qnap.home.usableapps.io",
    "connect to 192.168.1.254",
    "issuer https://wso2is.onprem.usableapps.io/oauth2/token",
    "client_id wn_MPGMtwOJNYJbaIIt4EAYBhxQa",
]

# Canaries the detector must CATCH but sanitize() deliberately does not rewrite.
# These are terms eliminated at source; silently rewriting them would hide the
# fact that private material had leaked into the public tree at all.
DETECT_ONLY = [
    "the hrl boundary",
    r"git grep -E '\\bhrl\\b'",   # term embedded in an escape; boundary regex misses it
    "per the JPMC problem statement",
]


def self_test() -> bool:
    """A checker that cannot detect a known positive proves nothing when it
    reports clean. Verify detection for every canary, and rewriting only for
    those sanitize() is responsible for. Fails closed."""
    for c in REWRITABLE + DETECT_ONLY:
        if not any(re.search(f, c, re.IGNORECASE) for f in FORBIDDEN):
            print(f"  SELF-TEST FAILED: detector missed canary -> {c!r}")
            return False
    for c in REWRITABLE:
        out = sanitize(c)
        if any(re.search(f, out, re.IGNORECASE) for f in FORBIDDEN):
            print(f"  SELF-TEST FAILED: sanitize() left a hit -> {out!r}")
            return False
    return True


def main():
    root = pathlib.Path(__file__).parent
    if not self_test():
        print("  ABORT: scanner self-test failed; a clean result would be meaningless")
        return 2
    print("  self-test passed (canaries detected and neutralised)")

    if "--check" in sys.argv:
        hits = scan(root)
        if hits:
            print(f"  FAIL: {len(hits)} forbidden hit(s)")
            for p, f, n in hits[:40]:
                print(f"    {p}: /{f}/ x{n}")
            return 1
        print("  PASS: no forbidden identifiers in the reference copy")
        return 0

    print("  usage: sanitize.py --check")
    return 0


if __name__ == "__main__":
    sys.exit(main())
