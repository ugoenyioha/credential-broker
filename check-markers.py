#!/usr/bin/env python3
"""Marker index integrity: defined-vs-used, both directions.

The table is an index, so it goes stale the moment a new marker is used and
not declared -- or a declared one stops being used. Both are silent failures
in prose, so check them.
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

paper = DOCS / "credential-broker-pattern.md"
evaluation = DOCS / "gateway-evaluation.md"

d_paper, d_eval = defined(paper), defined(evaluation)
fail = False

if d_paper != d_eval:
    print(f"  FAIL: tables disagree\n    paper: {d_paper}\n    eval:  {d_eval}")
    fail = True
else:
    print(f"  tables agree: {' '.join('[' + m + ']' for m in d_paper)}")

declared = set(d_paper)
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
