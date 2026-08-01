#!/usr/bin/env python3
"""Build the public reference copy from the private working tree.

Rewrites environment-specific identifiers to documentation placeholders. Ordered
longest-first, and IPs are matched with word boundaries because 192.168.1.20 is a
prefix of 192.168.1.206 — a naive ordered replace turns the latter into
"<placeholder>6", which looks plausible and is wrong.

Run from the repo root:  python3 sanitize.py --check
"""
import re, sys, pathlib, shutil, hashlib

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
    # NOTE: the real path carries a /data/ segment (KV v2). An earlier rule matched
    # "kv/talos/..." and silently never fired. Match the shape, not a guess at it.
    (r"kv/data/talos/[a-z/]*admin",   "kv/data/example/appliance/admin",  True),
    (r"kv/talos/switch/admin",        "kv/example/appliance/admin",       True),
    (r"config/example/[A-Za-z0-9_./-]*", "config/example/",                 True),
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
    # deployment-platform and private-repo paths: no legitimate use in this repo
    r"talos",
]

SKIP_SUFFIX = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".tar", ".gz", ".zip"}

# Media that RENDERS TEXT A READER CAN SEE but that no text scan can read.
# The scanner reports PASS on these because it skipped them, not because it
# cleared them -- exactly the "watchlist proves presence, never absence" trap
# the paper documents, turned on this repo's own gate. A screen recording can
# carry an operator's name, an address, a hostname or a product identifier in
# pixels, and every rule in FORBIDDEN is blind to all of it.
#
# So they are REFUSED rather than skipped. Committing one is a deliberate act
# that requires frame-level review first, recorded here.
UNSCANNABLE_SUFFIX = {".mp4", ".mov", ".webm", ".gif", ".avi", ".mkv", ".m4v"}

# Media cleared by FRAME-LEVEL REVIEW, keyed by SHA-256 of the exact reviewed
# bytes. Keyed by content, not by path: a path exception would silently bless
# whatever file later appeared at that name, which is the failure this whole
# gate exists to prevent. Re-encoding changes the hash and forces re-review.
#
# docs/demo.mp4 -- 1280x800, 32.7s. Reviewed frame by frame at 1 frame/3s:
#   * operator display name blurred throughout
#   * appliance serial / MAC / IP panel blurred throughout
#   * no URL bar captured (viewport-only recording)
#   * gateway product name and appliance model ARE visible, and that
#     disclosure is intentional and approved.
REVIEWED_MEDIA = {
    "a5a1ce84f8fde50418dfdab44480fc1a0f6beec7e021e0e5b92138f74400cc9d":
        "docs/demo.mp4 (frame-reviewed; PII blurred, product names intentional)",
}


def sanitize(text: str) -> str:
    for pat, rep, is_re in SUBS:
        text = re.sub(pat, rep, text) if is_re else text.replace(pat, rep)
    return text


def scan(root: pathlib.Path):
    """Return [(path, pattern, count)] for every forbidden hit."""
    hits = []
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        if "/.git/" in str(p) or p.name == "sanitize.py":
            continue
        # Report unscannable media as a FAILURE unless its exact bytes have
        # been cleared by frame-level review. A text scan cannot clear a video,
        # so silently skipping one would let the gate pass a file it never read.
        if p.suffix.lower() in UNSCANNABLE_SUFFIX:
            digest = hashlib.sha256(p.read_bytes()).hexdigest()
            if digest not in REVIEWED_MEDIA:
                hits.append((p.relative_to(root), "UNSCANNABLE-MEDIA", 1))
            continue
        if p.suffix.lower() in SKIP_SUFFIX:
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

    # Plant a real video and confirm scan() REFUSES it. Asserting the suffix is
    # in a set would only test the set; this tests the code path that a
    # committed recording would actually take.
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        probe = pathlib.Path(td)
        (probe / "planted-demo.mp4").write_bytes(b"\x00\x00\x00\x18ftypmp42")
        if not any(f == "UNSCANNABLE-MEDIA" for _, f, _ in scan(probe)):
            print("  SELF-TEST FAILED: a video passed the gate unexamined")
            return False

    # ...and confirm the review allowance is bound to CONTENT, not to a name.
    # A file wearing an approved filename but carrying different bytes must
    # still be refused, or the allowance becomes a hole shaped like a path.
    with tempfile.TemporaryDirectory() as td:
        probe = pathlib.Path(td)
        (probe / "demo.mp4").write_bytes(b"different bytes, same familiar name")
        if not any(f == "UNSCANNABLE-MEDIA" for _, f, _ in scan(probe)):
            print("  SELF-TEST FAILED: approval keyed by name, not content")
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
