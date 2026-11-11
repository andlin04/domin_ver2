"""Time-based one-time passwords (RFC 6238) and one-time recovery codes, standard library only.

A secret is 20 random bytes kept as base32; the authenticator app and the server derive the same 6-digit code from
it and the current 30-second step. Verification accepts the step before and after to allow for clock drift, and the
caller records the last step a code was accepted for so one code can be used only once (replay guard)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import struct
import time

DIGITS = 6
STEP = 30          # seconds per code
WINDOW = 1         # also accept the neighbouring steps (± this many)
ISSUER = "domin"
RECOVERY_CODES = 10
RECOVERY_RE = re.compile(r"^[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}$")


def new_secret() -> str:
    """A fresh base32 secret (no padding) for a new enrolment."""
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _code(secret: str, counter: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10**DIGITS).zfill(DIGITS)


def valid_secret(secret: str) -> bool:
    try:
        base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
        return bool(secret)
    except (ValueError, TypeError):
        return False


def verify(secret: str, code: str, last_step: int = -1, now: float | None = None) -> int | None:
    """Return the step a correct code belongs to (to store as the new last_step), or None. A step at or below
    last_step is refused, so a code works only once."""
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit() or len(code) != DIGITS:
        return None
    step = int((time.time() if now is None else now) // STEP)
    for s in range(step - WINDOW, step + WINDOW + 1):
        if s > last_step and hmac.compare_digest(_code(secret, s), code):
            return s
    return None


def provisioning_uri(secret: str, account: str, issuer: str = ISSUER) -> str:
    """otpauth:// URI for an authenticator app (pasted or shown as a QR by the browser)."""
    from urllib.parse import quote, urlencode
    label = quote(f"{issuer}:{account}")
    query = urlencode({"secret": secret, "issuer": issuer, "algorithm": "SHA1", "digits": DIGITS, "period": STEP})
    return f"otpauth://totp/{label}?{query}"


def qr_svg(uri: str) -> str:
    """The URI as an inline SVG QR code (segno): black modules on a white quiet zone, so it scans in either theme.
    Attributes only, no style or script, so the page CSP holds."""
    import segno
    return segno.make(uri, error="m").svg_inline(scale=4, border=4, dark="#000", light="#fff", svgclass="qr-code",
                                                 lineclass=None)


def new_recovery_codes(n: int = RECOVERY_CODES) -> list[str]:
    """Human-friendly one-time codes (shown once at enrolment); only their hashes are stored."""
    return ["-".join(secrets.token_hex(2) for _ in range(3)) for _ in range(n)]


def normalize_recovery(code: str) -> str:
    """A recovery code as typed: case and spaces do not matter."""
    return code.strip().lower().replace(" ", "")


def looks_like_recovery(code: str) -> bool:
    """A recovery code (xxxx-xxxx-xxxx), not a 6-digit TOTP code: only these are tried against the slow hashes."""
    return bool(RECOVERY_RE.match(normalize_recovery(code)))


def hash_recovery(code: str) -> str:
    """The old storage format (unsalted SHA-256); still accepted once each, never written any more."""
    return hashlib.sha256(normalize_recovery(code).encode()).hexdigest()
