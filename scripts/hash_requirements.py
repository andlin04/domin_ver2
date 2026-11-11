"""Add PyPI's SHA-256 hashes to deploy/requirements.txt (pip install --require-hashes), for the pinned versions as
they are: every file PyPI publishes for that version (all wheels and the sdist), so any platform the installer
picks matches. Same result as `pip-compile --generate-hashes` for an already complete pin list.

    python scripts/hash_requirements.py            # rewrite deploy/requirements.txt in place
    python scripts/hash_requirements.py --check    # exit 1 when a pin has no hashes or they differ from PyPI's
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import httpx

REQ = Path(__file__).resolve().parent.parent / "deploy" / "requirements.txt"
PIN = re.compile(r"^([A-Za-z0-9._-]+)==([A-Za-z0-9.+!-]+)")


def hashes(client: httpx.Client, name: str, version: str) -> list[str]:
    r = client.get(f"https://pypi.org/pypi/{name}/{version}/json")
    r.raise_for_status()
    found = sorted({f["digests"]["sha256"] for f in r.json()["urls"] if not f.get("yanked")})
    if not found:
        raise SystemExit(f"{name}=={version}: PyPI lists no files")
    return found


def render(header: list[str], pins: list[tuple[str, str, list[str]]]) -> str:
    out = list(header)
    for name, version, hs in pins:
        out.append(f"{name}=={version} \\")
        out += [f"    --hash=sha256:{h}" + (" \\" if i < len(hs) - 1 else "") for i, h in enumerate(hs)]
    return "\n".join(out) + "\n"


def main() -> int:
    lines = REQ.read_text(encoding="utf-8").splitlines()
    header = [x for x in lines if x.startswith("#")]
    pins = [(m.group(1), m.group(2)) for x in lines if (m := PIN.match(x.strip()))]
    with httpx.Client(timeout=30, follow_redirects=True) as client:
        text = render(header, [(n, v, hashes(client, n, v)) for n, v in pins])
    if "--check" in sys.argv:
        same = text == REQ.read_text(encoding="utf-8")
        print("requirements hashes: " + ("up to date" if same else "missing or different"))
        return 0 if same else 1
    REQ.write_text(text, encoding="utf-8", newline="\n")
    print(f"{REQ.name}: {len(pins)} pins hashed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
