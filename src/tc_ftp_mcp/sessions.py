"""Read FTP sessions from Total Commander's wcx_ftp.ini."""

from __future__ import annotations

import configparser
import os
from dataclasses import dataclass, field
from pathlib import Path

from .crypto import PasswordDecodeError, decode_password

# Sections that hold plugin settings, not connections.
_RESERVED = {"connections", "default", "oldconnections", "general", "certalias"}
_RESERVED_PREFIX = ("certsha",)


def default_ini_path() -> Path:
    appdata = os.environ.get("APPDATA")
    if not appdata:
        raise FileNotFoundError("APPDATA is not set; pass the wcx_ftp.ini path explicitly")
    return Path(appdata) / "GHISLER" / "wcx_ftp.ini"


class SessionError(Exception):
    pass


@dataclass(frozen=True)
class Session:
    name: str  # full section name, e.g. "egedi|egedi calendar"
    host: str
    port: int
    username: str
    directory: str
    passive: bool
    tls: bool
    pinned_sha256: str = ""  # fingerprint the user trusted in Total Commander
    cert_alias: str = ""  # name the server certificate is issued for, if not the host
    _stored_password: str = field(repr=False, default="")

    @property
    def folder(self) -> str:
        return self.name.split("|", 1)[0] if "|" in self.name else ""

    @property
    def label(self) -> str:
        return self.name.split("|", 1)[1] if "|" in self.name else self.name

    @property
    def has_password(self) -> bool:
        return bool(self._stored_password)

    def password(self) -> str:
        """Decode the password on demand. Never log or return this value."""
        if not self._stored_password:
            return ""
        return decode_password(self._stored_password)

    def public(self) -> dict:
        """Safe summary: no password."""
        return {
            "name": self.name,
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "directory": self.directory,
            "passive": self.passive,
            "tls": self.tls,
            "has_password": self.has_password,
        }


def _split_host(raw: str) -> tuple[str, int]:
    raw = raw.strip()
    for prefix in ("ftp://", "ftps://"):
        if raw.lower().startswith(prefix):
            raw = raw[len(prefix):]
    raw = raw.rstrip("/")
    if raw.startswith("["):  # [ipv6]:port
        host, _, rest = raw[1:].partition("]")
        port = int(rest[1:]) if rest.startswith(":") and rest[1:].isdigit() else 21
        return host, port
    if raw.count(":") == 1:
        host, _, port = raw.partition(":")
        if port.isdigit():
            return host, int(port)
    return raw, 21


def load_sessions(path: Path | str | None = None) -> dict[str, Session]:
    ini = Path(path) if path else default_ini_path()
    if not ini.is_file():
        raise FileNotFoundError(f"wcx_ftp.ini not found at {ini}")

    parser = configparser.RawConfigParser(strict=False, delimiters=("=",), interpolation=None)
    parser.optionxform = str.lower  # type: ignore[assignment]
    # Total Commander writes ANSI (Windows-1250 for Hungarian); latin-1 never fails
    # to decode, cp1250 keeps accented names intact.
    parser.read_string(ini.read_bytes().decode("cp1250", errors="replace"))

    aliases = dict(parser["CertAlias"]) if parser.has_section("CertAlias") else {}
    pins = dict(parser["CertSHA256hashes"]) if parser.has_section("CertSHA256hashes") else {}

    sessions: dict[str, Session] = {}
    for name in parser.sections():
        lowered = name.lower()
        if lowered in _RESERVED or lowered.startswith(_RESERVED_PREFIX):
            continue
        sec = parser[name]
        if "host" not in sec:
            continue
        host, port = _split_host(sec["host"])
        if not host:
            continue
        raw_host = sec["host"].lower()
        sessions[name] = Session(
            name=name,
            host=host,
            port=port,
            username=sec.get("username", "").strip(),
            directory=sec.get("directory", "").strip(),
            passive=sec.get("pasvmode", "1").strip() != "0",
            tls=raw_host.startswith("ftps://") or sec.get("ssl", "0").strip() == "1",
            pinned_sha256=pins.get(host.lower(), "").strip(),
            cert_alias=aliases.get(host.lower(), "").strip(),
            _stored_password=sec.get("password", "").strip(),
        )
    return sessions


def find_session(sessions: dict[str, Session], query: str) -> Session:
    """Exact name, then case-insensitive exact, then unique substring."""
    if query in sessions:
        return sessions[query]
    q = query.casefold()
    exact = [s for n, s in sessions.items() if n.casefold() == q or s.label.casefold() == q]
    if len(exact) == 1:
        return exact[0]
    pool = exact or [s for n, s in sessions.items() if q in n.casefold()]
    if len(pool) == 1:
        return pool[0]
    if not pool:
        raise SessionError(f"no session matches {query!r}")
    names = ", ".join(sorted(s.name for s in pool)[:15])
    raise SessionError(f"{len(pool)} sessions match {query!r}; be specific: {names}")


__all__ = ["Session", "SessionError", "PasswordDecodeError", "load_sessions", "find_session", "default_ini_path"]
