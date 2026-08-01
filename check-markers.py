#!/usr/bin/env python3
"""Marker index integrity: defined-vs-used, both directions.

The table is an index, so it goes stale the moment a new marker is used and
not declared -- or a declared one stops being used. Both are silent failures
in prose, so check them.

The CANONICAL table lives in the appendix. No other document repeats it -- a
second copy is a second thing to drift -- so every other page is checked for USE
only, and must link to the appendix so a reader can find the definitions.
"""
import re, pathlib, sys

DOCS = pathlib.Path("docs")
TABLE_ROW = re.compile(r"^\|\s*\*\*\[([A-Z])\]\*\*\s*\|")
# A marker in prose. Bold form **[M]** is the NORMAL way they are written, so
# it must count as a use; only the table ROW is excluded, by line, below.
USED = re.compile(r"\[([A-Z])\](?!\()")

def defined(p):
    return [m.group(1) for line in p.read_text().splitlines()
            if (m := TABLE_ROW.match(line))]

def used(p):
    out = set()
    for line in p.read_text().splitlines():
        if TABLE_ROW.match(line):
            continue
        out |= {m.group(1) for m in USED.finditer(line)}
    return out

appendix = DOCS / "appendix.md"

d_appendix = defined(appendix)
fail = False

if not d_appendix:
    print("  FAIL: the appendix carries no marker table; it is the canonical one")
    fail = True
else:
    print(f"  canonical table: {' '.join('[' + m + ']' for m in d_appendix)}")

# Exactly one table. A duplicate is a second thing to drift.
for other in sorted(DOCS.glob("*.md")):
    if other.name == "appendix.md":
        continue
    if defined(other):
        print(f"  FAIL: {other.name} repeats the marker table; the appendix is canonical")
        fail = True

# Any page that USES a marker must link to where they are defined.
for p_ in sorted(DOCS.glob("*.md")):
    if p_.name == "appendix.md" or not used(p_):
        continue
    if "appendix.html" not in p_.read_text():
        print(f"  FAIL: {p_.name} uses markers but never links to their definitions")
        fail = True

declared = set(d_appendix)
all_used = set()
for p in sorted(DOCS.glob("*.md")):
    u = used(p)
    all_used |= u
    if undeclared := u - declared:
        print(f"  FAIL: {p.name} uses undeclared {sorted(undeclared)}")
        fail = True

if unused := declared - all_used:
    print(f"  FAIL: declared but never used: {sorted(unused)}")
    fail = True

print("  FAIL" if fail else "  PASS: every marker used is declared, every marker declared is used")
sys.exit(1 if fail else 0)
