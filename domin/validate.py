"""Domain name checks: everything a user types passes through normalize_domain before use."""
from __future__ import annotations

import re

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_TLD = re.compile(r"^(xn--[a-z0-9-]{2,59}|[a-z]{2,63})$")


def normalize_domain(value: str) -> str | None:
    """Lower-case registrable-style name (example.se, sub.example.co.uk) or None when it isn't a valid host name.

    Accepts pasted URLs and e-mail addresses; IDNs are converted to punycode."""
    v = (value or "").strip().lower()
    v = re.sub(r"^[a-z][a-z0-9+.-]*://", "", v)       # scheme
    v = v.split("/", 1)[0].split("?", 1)[0]           # path, query
    v = v.rsplit("@", 1)[-1].split(":", 1)[0]         # user@, :port
    v = v.strip(".")
    if v.startswith("www."):
        v = v[4:]
    try:
        v = v.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if not v or len(v) > 253:
        return None
    labels = v.split(".")
    if len(labels) < 2 or not all(_LABEL.match(x) for x in labels) or not _TLD.match(labels[-1]):
        return None
    return v


def is_under(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)
