"""Render docs/assets/hero.svg: an animated terminal replay of the guard's real verdicts.

Every verdict line comes from running `hooks/guard.py --check` on the command,
so the hero cannot drift from what the guard actually does.

Usage: python3 scripts/make_hero.py
"""
from __future__ import annotations

import subprocess
import textwrap
import sys
from html import escape
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "assets" / "hero.svg"
GUARD = ROOT / "hooks" / "guard.py"

COMMANDS = [
    "curl -X DELETE https://api.example-host.com/v1/volumes/vol-prod-db/backups",
    "terraform destroy -auto-approve",
    "git push --force origin main",
    'psql -c "DROP TABLE users"',
    "git stash clear",
    "rm -rf ./node_modules",
]
COL = {"DENY": "#ff6b6b", "ASK": "#ffd43b", "ALLOW": "#51cf66",
       "prompt": "#74c0fc", "text": "#e6edf3", "dim": "#8b949e"}
MAX = 96  # characters per line at 14px mono in an 860 wide frame (about 8.4 px each)


def verdict(cmd: str) -> tuple[str, str]:
    out = subprocess.run([sys.executable, str(GUARD), "--check", cmd], capture_output=True, text=True).stdout.strip()
    word, _, rest = out.partition(" ")
    reason = rest.strip()
    if "] " in reason:
        reason = reason.split("] ", 1)[1]
    return word, reason


def clip(s: str) -> str:
    return s if len(s) <= MAX else s[: MAX - 3] + "..."


def main() -> None:
    lines: list[tuple[str, str]] = []
    for cmd in COMMANDS:
        word, reason = verdict(cmd)
        lines.append((clip(f"$ {cmd}"), "prompt"))
        for j, chunk in enumerate(textwrap.wrap(reason, 76) or [""]):
            lines.append((f"  {word if j == 0 else '':<5} {chunk}".rstrip(), word))
        lines.append(("", "text"))
    lines.pop()

    lh, y0, left, width = 22, 52, 22, 860
    height = y0 + lh * len(lines) + 20
    step = 0.6
    total = step * len(lines) + 4.0
    parts = [
        f"<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 {width} {height}' width='{width}' height='{height}' "
        "role='img' aria-label='paranoid-sre guard blocks destructive commands against production and allows safe cleanup'>",
        "<style>text{font-family:'JetBrains Mono','SFMono-Regular',Menlo,Consolas,monospace;font-size:14px;white-space:pre}"
        f".l{{opacity:0;animation-duration:{total:.2f}s;animation-iteration-count:infinite}}"
        "@media (prefers-reduced-motion:reduce){.l{animation:none!important;opacity:1}}</style>",
        f"<rect width='{width}' height='{height}' rx='10' fill='#0d1117'/>",
        "<circle cx='22' cy='20' r='6' fill='#ff5f56'/><circle cx='42' cy='20' r='6' fill='#ffbd2e'/>"
        "<circle cx='62' cy='20' r='6' fill='#27c93f'/>",
        f"<text x='{width / 2}' y='25' text-anchor='middle' fill='{COL['dim']}' style='font-size:12px'>"
        "paranoid-sre: it's not paranoia if prod is real</text>",
    ]
    keyframes = []
    for i, (txt, kind) in enumerate(lines):
        if not txt:
            continue
        a = i * step / total * 100
        b = (i * step + 0.05) / total * 100
        keyframes.append(f"@keyframes s{i}{{0%,{a:.1f}%{{opacity:0}}{b:.1f}%,100%{{opacity:1}}}}.l{i}{{animation-name:s{i}}}")
        weight = " font-weight='700'" if kind in {"DENY", "ASK", "ALLOW"} else ""
        parts.append(f"<text class='l l{i}' x='{left}' y='{y0 + i * lh}' fill='{COL[kind]}'{weight}>{escape(txt)}</text>")
    parts.insert(2, "<style>" + "".join(keyframes) + "</style>")
    parts.append("</svg>")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(parts))
    print(f"wrote {OUT} ({OUT.stat().st_size} bytes, {len(lines)} lines, {total:.1f}s loop)")


if __name__ == "__main__":
    main()
