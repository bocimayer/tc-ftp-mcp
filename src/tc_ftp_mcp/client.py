"""Thin ftplib wrapper that connects with a Total Commander session."""

from __future__ import annotations

import ftplib
import hashlib
import posixpath
import ssl
from contextlib import contextmanager
from typing import Iterator

from . import trust
from .sessions import Session

TIMEOUT = 30

_TLS_HINTS = ("tls", "ssl", "cleartext", "encrypt", "secure", "auth")


class CertificateNotTrusted(ssl.SSLError):
    """Server certificate fails normal verification and is not pinned in Total Commander."""


class _ImplicitFTP_TLS(ftplib.FTP_TLS):
    """Implicit FTPS (TLS from the first byte, usually port 990)."""

    _sock = None

    @property
    def sock(self):
        return self._sock

    @sock.setter
    def sock(self, value):
        if value is not None and not isinstance(value, ssl.SSLSocket):
            value = self.context.wrap_socket(value, server_hostname=self.host)
        self._sock = value


def _fingerprint(der: bytes) -> str:
    h = hashlib.sha256(der).hexdigest().upper()
    return ":".join(h[i : i + 2] for i in range(0, len(h), 2))


def _make(session: Session, tls: bool, context: ssl.SSLContext | None) -> ftplib.FTP:
    if not tls:
        return ftplib.FTP(timeout=TIMEOUT)
    ctx = context or ssl.create_default_context()
    cls = _ImplicitFTP_TLS if session.port == 990 else ftplib.FTP_TLS
    return cls(context=ctx, timeout=TIMEOUT)


def _unverified_context() -> ssl.SSLContext:
    """Only used to read the peer certificate; trust comes from `_check_pin`."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _check_pin(ftp: ftplib.FTP, session: Session) -> None:
    sock = ftp.sock
    der = sock.getpeercert(binary_form=True) if isinstance(sock, ssl.SSLSocket) else None
    fp = _fingerprint(der) if der else ""
    known = trust.trusted(session.host)
    if session.pinned_sha256:
        known.add(session.pinned_sha256.upper())
    if not fp or fp not in known:
        raise CertificateNotTrusted(
            f"certificate for {session.host} fails normal verification and its SHA-256 "
            f"({fp or 'unavailable'}) is not trusted. If the user confirms this is the right "
            "server, call trust_certificate with that fingerprint."
        )


def _start(ftp: ftplib.FTP, session: Session, tls: bool) -> None:
    ftp.connect(session.host, session.port)
    if tls and not isinstance(ftp, _ImplicitFTP_TLS):
        if session.cert_alias:
            ftp.host = session.cert_alias  # name checked against the certificate
        ftp.auth()  # explicit FTPS: certificate is verified here


def _login(session: Session, tls: bool, password: str) -> ftplib.FTP:
    ftp = _make(session, tls, None)
    try:
        try:
            _start(ftp, session, tls)
        except ssl.SSLCertVerificationError:
            ftp.close()
            ftp = _make(session, tls, _unverified_context())
            _start(ftp, session, tls)
            _check_pin(ftp, session)
        ftp.login(session.username or "anonymous", password)
        if tls:
            ftp.prot_p()
        return ftp
    except BaseException:
        ftp.close()
        raise


def peer_fingerprint(session: Session) -> str:
    """SHA-256 of the certificate the server presents now (no login)."""
    tls = session.tls or session.port == 990
    ftp = _make(session, tls, _unverified_context())
    try:
        ftp.connect(session.host, session.port)
        if not isinstance(ftp, _ImplicitFTP_TLS):
            ftp.auth()
        der = ftp.sock.getpeercert(binary_form=True)
        return _fingerprint(der) if der else ""
    finally:
        ftp.close()


def _needs_tls(exc: Exception) -> bool:
    return isinstance(exc, ftplib.Error) and any(h in str(exc).lower() for h in _TLS_HINTS)


@contextmanager
def connect(session: Session, encoding: str | None = None) -> Iterator[ftplib.FTP]:
    """Open an authenticated connection. Plain sessions retry once over TLS when
    the server refuses cleartext."""
    password = session.password()
    try:
        ftp = _login(session, session.tls, password)
    except ftplib.Error as exc:
        if session.tls or not _needs_tls(exc):
            raise
        ftp = _login(session, True, password)
    try:
        ftp.set_pasv(session.passive)
        ftp.voidcmd("TYPE I")  # SIZE and binary transfers need image mode
        if encoding:
            ftp.encoding = encoding
        else:
            try:
                ftp.sendcmd("OPTS UTF8 ON")
                ftp.encoding = "utf-8"
            except ftplib.all_errors:
                ftp.encoding = "cp1250"
        if session.directory:
            try:
                ftp.cwd(session.directory)
            except ftplib.error_perm:
                pass  # start in the login directory if the saved one is gone
        yield ftp
    finally:
        try:
            ftp.quit()
        except (OSError, EOFError, ftplib.Error):
            ftp.close()


def remote_exists(ftp: ftplib.FTP, path: str) -> bool:
    """True if a file or directory exists. Errs on the side of True: a failed
    check must never let an upload silently replace a file."""
    try:
        ftp.size(path)
        return True
    except ftplib.error_perm:
        pass  # either missing, or a directory, or SIZE unsupported
    parent, name = posixpath.split(path.rstrip("/"))
    try:
        return any(e["name"] == name for e in list_dir(ftp, parent))
    except ftplib.Error:
        return True


def list_dir(ftp: ftplib.FTP, path: str = "") -> list[dict]:
    entries: list[dict] = []
    try:
        for name, facts in ftp.mlsd(path or "", facts=["type", "size", "modify"]):
            if name in (".", ".."):
                continue
            entries.append(
                {
                    "name": name,
                    "type": "dir" if facts.get("type") in ("dir", "cdir", "pdir") else "file",
                    "size": int(facts["size"]) if facts.get("size", "").isdigit() else None,
                    "modified": facts.get("modify"),
                }
            )
        return entries
    except ftplib.error_perm:
        pass  # server has no MLSD; fall back to NLST + type probe
    names = ftp.nlst(path) if path else ftp.nlst()
    here = ftp.pwd()
    for full in names:
        name = posixpath.basename(full.rstrip("/"))
        if name in (".", ".."):
            continue
        try:
            ftp.cwd(posixpath.join(path, name) if path else name)
            kind = "dir"
        except ftplib.error_perm:
            kind = "file"
        finally:
            ftp.cwd(here)
        entries.append({"name": name, "type": kind, "size": None, "modified": None})
    return entries


__all__ = ["connect", "list_dir", "remote_exists", "peer_fingerprint", "CertificateNotTrusted"]
