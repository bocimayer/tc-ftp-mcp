"""Decode and encode passwords stored in Total Commander's wcx_ftp.ini.

Total Commander stores FTP passwords as a hex string of bytes scrambled with a
fixed-seed Delphi-style linear congruential generator. It is obfuscation, not
real encryption: no key is involved unless the user set a master password, in
which case the stored form differs and this module will not decode it.

The algorithm was reverse engineered by others (see the PELock write-up and the
total-commander-ftp-password-recovery package, Apache-2.0). This is an
independent implementation of the same published steps.
"""

from __future__ import annotations

_MASK = 0xFFFFFFFF


class _Prng:
    """Delphi `Random(n)` style generator used by Total Commander."""

    def __init__(self, seed: int) -> None:
        self.seed = seed & _MASK

    def below(self, n: int) -> int:
        self.seed = (self.seed * 0x8088405 + 1) & _MASK
        return (self.seed * n) >> 32


def _rol8(value: int, count: int) -> int:
    count &= 7
    return ((value << count) | (value >> (8 - count))) & 0xFF


def _ror8(value: int, count: int) -> int:
    return _rol8(value, 8 - (count & 7))


class PasswordDecodeError(ValueError):
    """Stored password cannot be decoded (bad hex, too short, master password)."""


def decode_password(stored: str) -> str:
    """Return the plain password for a hex string from wcx_ftp.ini."""
    stored = "".join(stored.split()).lower()
    try:
        data = list(bytes.fromhex(stored))
    except ValueError as exc:
        raise PasswordDecodeError("stored password is not valid hex") from exc
    if len(data) <= 4:
        raise PasswordDecodeError("stored password too short")
    n = len(data) - 4  # last 4 bytes are a checksum Total Commander verifies

    rng = _Prng(849521)
    for i in range(n):
        data[i] = _rol8(data[i], rng.below(8))

    rng = _Prng(12345)
    for _ in range(256):
        x = rng.below(n)
        y = rng.below(n)
        data[x], data[y] = data[y], data[x]

    rng = _Prng(42340)
    for i in range(n):
        data[i] ^= rng.below(256)

    rng = _Prng(54321)
    for i in range(n):
        data[i] = (data[i] - rng.below(256)) & 0xFF

    raw = bytes(data[:n])
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("cp1250", errors="replace")


def encode_password(plain: str) -> str:
    """Inverse of `decode_password` without the trailing checksum bytes.

    Used by the tests to prove the round trip; the four checksum bytes are
    zero-filled, which is enough for `decode_password` but not for Total
    Commander itself.
    """
    data = list(plain.encode("utf-8"))
    n = len(data)

    rng = _Prng(54321)
    for i in range(n):
        data[i] = (data[i] + rng.below(256)) & 0xFF

    rng = _Prng(42340)
    for i in range(n):
        data[i] ^= rng.below(256)

    rng = _Prng(12345)
    swaps = [(rng.below(n), rng.below(n)) for _ in range(256)]
    for x, y in reversed(swaps):
        data[x], data[y] = data[y], data[x]

    rng = _Prng(849521)
    for i in range(n):
        data[i] = _ror8(data[i], rng.below(8))

    return bytes(data + [0, 0, 0, 0]).hex().upper()
