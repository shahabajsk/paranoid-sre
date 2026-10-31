#!/usr/bin/env python3
"""Run the guard over the labelled corpus and print the before/after table.

Usage: python3 bench/run.py [--markdown] [--show-errors]
"""
from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "hooks"))
from guard import check  # noqa: E402


def load(name: str) -> list[dict]:
    return [json.loads(l) for l in (ROOT / "bench" / name).read_text().splitlines() if l.strip()]


def main(argv: list[str]) -> int:
    rows = load("corpus.jsonl")
    bypass = load("known_bypasses.jsonl")
    by_cat: dict[str, Counter] = defaultdict(Counter)
    errors = []
    for r in rows:
        d = check(r["cmd"]).decision
        stopped = d != "allow"
        key = "destructive" if r["label"] == "destructive" else "safe"
        by_cat[(r["category"], key)]["n"] += 1
        by_cat[(r["category"], key)]["stopped"] += stopped
        by_cat[(r["category"], key)]["deny"] += d == "deny"
        if stopped != (r["label"] == "destructive"):
            errors.append((r["label"], d, r["cmd"]))
    bypass_caught = sum(check(b["cmd"]).decision != "allow" for b in bypass)
    hold = load("holdout.jsonl")
    hd = [h for h in hold if h["label"] == "destructive"]
    hs = [h for h in hold if h["label"] == "safe"]
    hd_s = sum(check(h["cmd"]).decision != "allow" for h in hd)
    hs_s = sum(check(h["cmd"]).decision != "allow" for h in hs)

    def total(label):
        n = sum(c["n"] for (cat, k), c in by_cat.items() if k == label)
        s = sum(c["stopped"] for (cat, k), c in by_cat.items() if k == label)
        dn = sum(c["deny"] for (cat, k), c in by_cat.items() if k == label)
        return n, s, dn

    dn_, ds, dd = total("destructive")
    sn, ss, sd = total("safe")
    md = "--markdown" in argv
    lines = []
    if md:
        lines += ["| Commands | n | Stopped without guard | Stopped with guard | Of those, hard-blocked |", "|---|---|---|---|---|",
                  f"| Destructive | {dn_} | 0 (0%) | {ds} ({100*ds/dn_:.0f}%) | {dd} |",
                  f"| Safe lookalikes | {sn} | 0 (0%) | {ss} ({100*ss/sn:.0f}%) | {sd} |",
                  f"| Held-out destructive | {len(hd)} | 0 (0%) | {hd_s} ({100*hd_s/len(hd):.0f}%) | |",
                  f"| Held-out safe lookalikes | {len(hs)} | 0 (0%) | {hs_s} ({100*hs_s/len(hs):.0f}%) | |",
                  f"| Known bypasses (not caught by design) | {len(bypass)} | 0 | {bypass_caught} | |"]
    else:
        lines.append(f"{'category':<10}{'label':<13}{'n':>4}{'stopped':>9}{'denied':>8}")
        for (cat, k), c in sorted(by_cat.items()):
            lines.append(f"{cat:<10}{k:<13}{c['n']:>4}{c['stopped']:>9}{c['deny']:>8}")
        lines.append("")
        lines.append(f"destructive stopped: {ds}/{dn_} ({100*ds/dn_:.1f}%), hard-blocked {dd}")
        lines.append(f"safe stopped (false positives): {ss}/{sn} ({100*ss/sn:.1f}%)")
        lines.append(f"held-out destructive stopped: {hd_s}/{len(hd)}; held-out safe stopped: {hs_s}/{len(hs)}")
        lines.append(f"known bypasses caught: {bypass_caught}/{len(bypass)}")
    print("\n".join(lines))
    if "--show-errors" in argv:
        for e in errors:
            print("MISMATCH", e)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
