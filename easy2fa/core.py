"""
Easy2FA - a tiny, batteries-included 2FA helper for Python.

MVP features:
- RFC 4226/6238 HOTP/TOTP generation & verification (Google Authenticator compatible)
- otpauth:// provisioning URI builder
- Optional QR PNG generation (requires `qrcode` extra)
- Backup codes (hash-at-rest, one-time use)
- Simple rate limiting & lockout for brute-force protection
- Easy, single-object API (`Easy2FAAccount`) + pure functions for advanced use

No external deps required for core features. Optional extras:
    pip install qrcode[pil]

This file can be dropped into your project as `easy2fa.py` or packaged as a module.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import struct
import time
from collections import deque
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Deque, Iterable, Optional, Tuple

# ============================
# Utilities
# ============================

def _b32_no_padding(b: bytes) -> str:
    return base64.b32encode(b).decode("ascii").rstrip("=")


def generate_base32_secret(length: int = 20) -> str:
    """Generate a random Base32 secret (unpadded), suitable for TOTP.

    `length` is the number of *random bytes* pre-encoding. 20 bytes ≈ 160 bits.
    """
    if length < 10:
        # keep it reasonably strong
        length = 10
    return _b32_no_padding(secrets.token_bytes(length))


# ============================
# HOTP / TOTP core (RFC 4226 / 6238)
# ============================

_ALGOS = {
    "SHA1": hashlib.sha1,
    "SHA256": hashlib.sha256,
    "SHA512": hashlib.sha512,
}


def hotp(secret_b32: str, counter: int, digits: int = 6, algorithm: str = "SHA1") -> str:
    """Generate an HOTP code for a Base32 secret and counter.

    Args:
        secret_b32: Base32 (no padding) shared secret.
        counter: 8-byte counter value.
        digits: number of digits in the OTP (6–8 typical).
        algorithm: one of "SHA1", "SHA256", "SHA512".
    """
    algo = _ALGOS.get(algorithm.upper())
    if not algo:
        raise ValueError("Unsupported algorithm; use SHA1, SHA256, or SHA512")

    # Add padding back for decoding if needed
    pad = "=" * ((8 - (len(secret_b32) % 8)) % 8)
    key = base64.b32decode(secret_b32 + pad, casefold=True)

    msg = struct.pack(">Q", counter)
    hm = hmac.new(key, msg, algo).digest()

    # Dynamic truncation
    offset = hm[-1] & 0x0F
    code_int = ((hm[offset] & 0x7F) << 24) | (
        (hm[offset + 1] & 0xFF) << 16
    ) | ((hm[offset + 2] & 0xFF) << 8) | (hm[offset + 3] & 0xFF)

    code = code_int % (10 ** digits)
    return str(code).zfill(digits)


def totp(
    secret_b32: str,
    for_time: Optional[float] = None,
    step_seconds: int = 30,
    digits: int = 6,
    algorithm: str = "SHA1",
    t0: int = 0,
) -> str:
    """Generate a TOTP for a given time (defaults to now, UTC).

    Args mirror the RFC 6238 parameters. Compatible with Google Authenticator by default.
    """
    if for_time is None:
        for_time = time.time()
    counter = int((for_time - t0) // step_seconds)
    return hotp(secret_b32, counter, digits=digits, algorithm=algorithm)


def verify_totp(
    secret_b32: str,
    code: str,
    for_time: Optional[float] = None,
    step_seconds: int = 30,
    digits: int = 6,
    algorithm: str = "SHA1",
    t0: int = 0,
    window: int = 1,
) -> bool:
    """Verify a TOTP code, allowing ±`window` steps for clock skew.

    Returns True if any code in the allowed window matches (constant-time compare).
    """
    if for_time is None:
        for_time = time.time()

    # Normalize code (strip spaces)
    code = code.strip().replace(" ", "")
    if not code.isdigit():
        return False

    base_counter = int((for_time - t0) // step_seconds)
    for delta in range(-window, window + 1):
        candidate = hotp(secret_b32, base_counter + delta, digits=digits, algorithm=algorithm)
        if hmac.compare_digest(candidate, code):
            return True
    return False


# ============================
# Provisioning (otpauth://) & QR
# ============================

def provisioning_uri(
    secret_b32: str,
    label: str,
    issuer: Optional[str] = None,
    digits: int = 6,
    algorithm: str = "SHA1",
    step_seconds: int = 30,
) -> str:
    """Build an otpauth:// URI suitable for QR import by authenticator apps.

    Example label: "myapp:user@example.com"
    """
    from urllib.parse import quote

    params = [
        ("secret", secret_b32),
        ("digits", str(digits)),
        ("period", str(step_seconds)),
        ("algorithm", algorithm.upper()),
    ]
    if issuer:
        params.append(("issuer", issuer))

    q = "&".join(f"{k}={quote(v)}" for k, v in params)
    label_enc = quote(label)
    return f"otpauth://totp/{label_enc}?{q}"


def qr_png_bytes(otpauth_uri: str, box_size: int = 6, border: int = 2) -> bytes:
    """Return PNG bytes for a QR of the given otpauth:// URI.

    Requires optional dependency: `pip install qrcode[pil]`.
    """
    try:
        import qrcode  # type: ignore
    except Exception as e:
        raise RuntimeError(
            "QR generation requires the optional 'qrcode' package (pip install qrcode[pil])."
        ) from e

    img = qrcode.make(otpauth_uri, box_size=box_size, border=border)
    from io import BytesIO

    buf = BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


# ============================
# Backup codes (one-time use)
# ============================

@dataclass
class BackupCodes:
    salt: bytes
    hashes: set[str]

    @staticmethod
    def _hash(salt: bytes, code: str) -> str:
        return hashlib.sha256(salt + code.encode("utf-8")).hexdigest()

    @classmethod
    def new(cls, codes: Iterable[str]) -> "BackupCodes":
        salt = secrets.token_bytes(16)
        return cls(salt=salt, hashes={cls._hash(salt, c) for c in codes})

    def verify_and_consume(self, code: str) -> bool:
        h = self._hash(self.salt, code)
        if h in self.hashes:
            self.hashes.remove(h)
            return True
        return False

    def remaining(self) -> int:
        return len(self.hashes)


def generate_backup_codes(n: int = 10, length: int = 10) -> list[str]:
    """Generate user-facing backup codes (store only hashed)."""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no confusing chars
    return ["".join(secrets.choice(alphabet) for _ in range(length)) for _ in range(n)]


# ============================
# Rate limiting / Lockout
# ============================

class RateLimiter:
    def __init__(self, max_attempts: int = 5, window_seconds: int = 300, lockout_seconds: int = 300):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self.failures: Deque[float] = deque()
        self.locked_until: float = 0.0

    def _evict(self, now: float) -> None:
        cutoff = now - self.window_seconds
        while self.failures and self.failures[0] < cutoff:
            self.failures.popleft()

    def allowed(self, now: Optional[float] = None) -> Tuple[bool, float]:
        if now is None:
            now = time.time()
        if now < self.locked_until:
            return False, max(0.0, self.locked_until - now)
        self._evict(now)
        if len(self.failures) >= self.max_attempts:
            self.locked_until = now + self.lockout_seconds
            self.failures.clear()
            return False, self.lockout_seconds
        return True, 0.0

    def register_failure(self, now: Optional[float] = None) -> None:
        if now is None:
            now = time.time()
        self.failures.append(now)

    def reset(self) -> None:
        self.failures.clear()
        self.locked_until = 0.0


# ============================
# High-level account API
# ============================

@dataclass
class Easy2FAAccount:
    secret: str
    issuer: Optional[str] = None
    label: Optional[str] = None
    digits: int = 6
    algorithm: str = "SHA1"
    step_seconds: int = 30
    backup: Optional[BackupCodes] = None
    rate: RateLimiter = RateLimiter()

    @classmethod
    def create(
        cls,
        issuer: Optional[str] = None,
        label: Optional[str] = None,
        digits: int = 6,
        algorithm: str = "SHA1",
        step_seconds: int = 30,
    ) -> "Easy2FAAccount":
        return cls(
            secret=generate_base32_secret(),
            issuer=issuer,
            label=label,
            digits=digits,
            algorithm=algorithm,
            step_seconds=step_seconds,
        )

    # ---- TOTP ----
    def current_code(self, for_time: Optional[float] = None) -> str:
        return totp(
            self.secret,
            for_time=for_time,
            step_seconds=self.step_seconds,
            digits=self.digits,
            algorithm=self.algorithm,
        )

    def verify_code(self, code: str, for_time: Optional[float] = None, window: int = 1) -> Tuple[bool, str]:
        """Verify TOTP or backup code with rate limiting.

        Returns (ok, source) where source in {"totp", "backup", "locked", "invalid"}.
        """
        ok, wait = self.rate.allowed()
        if not ok:
            return False, "locked"

        # Try TOTP first
        if verify_totp(
            self.secret,
            code,
            for_time=for_time,
            step_seconds=self.step_seconds,
            digits=self.digits,
            algorithm=self.algorithm,
            window=window,
        ):
            self.rate.reset()
            return True, "totp"

        # Then fallback to backup codes if present
        if self.backup and self.backup.verify_and_consume(code.strip().upper()):
            self.rate.reset()
            return True, "backup"

        # Failure path
        self.rate.register_failure()
        return False, "invalid"

    # ---- Provisioning ----
    def otpauth_uri(self) -> str:
        lbl = self.label or "user"
        return provisioning_uri(
            self.secret,
            label=lbl,
            issuer=self.issuer,
            digits=self.digits,
            algorithm=self.algorithm,
            step_seconds=self.step_seconds,
        )

    def qr_png(self, box_size: int = 6, border: int = 2) -> bytes:
        return qr_png_bytes(self.otpauth_uri(), box_size=box_size, border=border)

    # ---- Backup codes ----
    def generate_backup_codes(self, n: int = 10, length: int = 10) -> list[str]:
        codes = generate_backup_codes(n=n, length=length)
        self.backup = BackupCodes.new(codes)
        return codes  # present these once to the user; store only hashed in `self.backup`

    def remaining_backup_codes(self) -> int:
        return self.backup.remaining() if self.backup else 0

    # ---- Persistence helpers ----
    def to_dict(self) -> dict:
        d = asdict(self)
        # Convert non-serializable pieces
        d["rate"] = {
            "max_attempts": self.rate.max_attempts,
            "window_seconds": self.rate.window_seconds,
            "lockout_seconds": self.rate.lockout_seconds,
            "locked_until": self.rate.locked_until,
            "failures": list(self.rate.failures),
        }
        if self.backup:
            d["backup"] = {
                "salt": base64.b64encode(self.backup.salt).decode("ascii"),
                "hashes": list(self.backup.hashes),
            }
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "Easy2FAAccount":
        # Rehydrate RateLimiter
        r = data.get("rate", {})
        rl = RateLimiter(
            max_attempts=r.get("max_attempts", 5),
            window_seconds=r.get("window_seconds", 300),
            lockout_seconds=r.get("lockout_seconds", 300),
        )
        rl.locked_until = r.get("locked_until", 0.0)
        rl.failures = deque(r.get("failures", []))

        # Rehydrate BackupCodes
        b = data.get("backup")
        backup = None
        if b:
            backup = BackupCodes(
                salt=base64.b64decode(b["salt"]),
                hashes=set(b.get("hashes", [])),
            )

        return cls(
            secret=data["secret"],
            issuer=data.get("issuer"),
            label=data.get("label"),
            digits=data.get("digits", 6),
            algorithm=data.get("algorithm", "SHA1"),
            step_seconds=data.get("step_seconds", 30),
            backup=backup,
            rate=rl,
        )


# ============================
# Demo & quick test (run this file)
# ============================
if __name__ == "__main__":
    print("\n--- Easy2FA quick demo ---")
    acct = Easy2FAAccount.create(issuer="MyApp", label="MyApp:user@example.com")
    print("Secret:", acct.secret)
    print("URI:", acct.otpauth_uri())

    try:
        png = acct.qr_png()
        with open("easy2fa_demo_qr.png", "wb") as f:
            f.write(png)
        print("Saved QR to easy2fa_demo_qr.png (scan with Google Authenticator)")
    except RuntimeError as e:
        print("QR not generated:", e)

    codes = acct.generate_backup_codes(n=5, length=10)
    print("Backup codes (store securely, show once):", codes)

    now = datetime.now(timezone.utc).timestamp()
    cur = acct.current_code(for_time=now)
    ok, src = acct.verify_code(cur, for_time=now)
    print(f"Verify current TOTP => {ok} (source={src})")

    # Wrong code, trigger rate limiter
    for i in range(6):
        ok, src = acct.verify_code("000000")
        print(f"Attempt {i+1} valid? {ok}, src={src}")
""
