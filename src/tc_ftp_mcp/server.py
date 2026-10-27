"""MCP server exposing Total Commander FTP sessions."""

from __future__ import annotations

import argparse
import ftplib
import io
import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from . import client, trust
from .sessions import SessionError, find_session, load_sessions

MAX_READ_BYTES = 256 * 1024

mcp = FastMCP(
    "tc-ftp",
    instructions=(
        "Connect to FTP servers saved in Total Commander (wcx_ftp.ini). "
        "Call list_sessions first, then pass a session name to the other tools. "
        "Passwords are decoded in memory and never returned."
    ),
)

_ini_path: Path | None = None


def _session(query: str):
    return find_session(load_sessions(_ini_path), query)


def _fail(exc: Exception) -> str:
    return f"{type(exc).__name__}: {exc}"


_ERRORS = (SessionError, ValueError, OSError, ftplib.Error)


def _run(query: str, fn):
    """Connect to a session and call fn(ftp). Some old servers send Latin-2 names
    while claiming UTF-8, so a decode error retries once with cp1250."""
    session = _session(query)
    try:
        with client.connect(session) as ftp:
            return fn(ftp)
    except UnicodeError:
        with client.connect(session, encoding="cp1250") as ftp:
            return fn(ftp)


@mcp.tool()
def list_sessions(filter: str = "") -> list[dict]:
    """List saved Total Commander FTP sessions (no passwords).

    filter: optional case-insensitive substring of the session name or host.
    """
    q = filter.casefold()
    return [
        s.public()
        for s in load_sessions(_ini_path).values()
        if not q or q in s.name.casefold() or q in s.host.casefold()
    ]


@mcp.tool()
def list_dir(session: str, path: str = "") -> list[dict] | str:
    """List a remote directory. Empty path means the session's saved start directory."""
    try:
        return _run(session, lambda ftp: client.list_dir(ftp, path))
    except _ERRORS as exc:
        return _fail(exc)


@mcp.tool()
def read_text(session: str, path: str, max_bytes: int = MAX_READ_BYTES) -> str:
    """Read a remote text file (UTF-8, falls back to cp1250). Capped at max_bytes."""
    limit = min(max_bytes, MAX_READ_BYTES)
    def fetch(ftp: ftplib.FTP) -> tuple[bytes, bool]:
        # Stop reading at the cap instead of pulling a huge file over the wire.
        with ftp.transfercmd(f"RETR {path}") as conn:
            chunks, got = [], 0
            while got <= limit:
                chunk = conn.recv(min(65536, limit + 1 - got))
                if not chunk:
                    break
                chunks.append(chunk)
                got += len(chunk)
        data = b"".join(chunks)
        truncated = len(data) > limit
        if truncated:
            try:
                ftp.abort()
            except (OSError, EOFError, ftplib.Error):
                pass
        else:
            ftp.voidresp()
        return data[:limit], truncated

    try:
        data, truncated = _run(session, fetch)
    except _ERRORS as exc:
        return _fail(exc)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("cp1250", errors="replace")
    return text + ("\n[truncated]" if truncated else "")


@mcp.tool()
def download_file(session: str, remote_path: str, local_path: str) -> str:
    """Download a remote file to a local path. Refuses to overwrite an existing file."""
    dest = Path(local_path)
    if dest.exists():
        return f"refused: {dest} already exists"
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        def fetch(ftp: ftplib.FTP) -> None:
            with open(dest, "wb") as fh:
                ftp.retrbinary(f"RETR {remote_path}", fh.write)

        _run(session, fetch)
    except _ERRORS as exc:
        dest.unlink(missing_ok=True)
        return _fail(exc)
    return f"downloaded {remote_path} -> {dest} ({dest.stat().st_size} bytes)"


@mcp.tool()
def upload_file(session: str, local_path: str, remote_path: str, overwrite: bool = False) -> str:
    """Upload a local file. Refuses to replace an existing remote file unless overwrite is true."""
    src = Path(local_path)
    if not src.is_file():
        return f"refused: {src} is not a file"
    def put(ftp: ftplib.FTP) -> str | None:
        if not overwrite and client.remote_exists(ftp, remote_path):
            return f"refused: {remote_path} exists; pass overwrite=true to replace"
        with open(src, "rb") as fh:
            ftp.storbinary(f"STOR {remote_path}", fh)
        return None

    try:
        refused = _run(session, put)
    except _ERRORS as exc:
        return _fail(exc)
    if refused:
        return refused
    return f"uploaded {src} -> {remote_path} ({src.stat().st_size} bytes)"


@mcp.tool()
def trust_certificate(session: str, sha256: str) -> str:
    """Trust one TLS certificate fingerprint for a session's host.

    Only call this after the user has confirmed the fingerprint (it is shown in the
    CertificateNotTrusted error). The server must present exactly that fingerprint now.
    """
    try:
        s = _session(session)
        seen = client.peer_fingerprint(s)
    except _ERRORS as exc:
        return _fail(exc)
    if seen.upper() != sha256.strip().upper():
        return f"refused: server presents {seen or 'no certificate'}, not the fingerprint given"
    trust.add(s.host, seen)
    return f"trusted {seen} for {s.host}"


@mcp.tool()
def make_dir(session: str, path: str) -> str:
    """Create a remote directory."""
    try:
        return _run(session, lambda ftp: f"created {ftp.mkd(path)}")
    except _ERRORS as exc:
        return _fail(exc)


@mcp.tool()
def rename(session: str, from_path: str, to_path: str) -> str:
    """Rename or move a remote file or directory."""
    try:
        _run(session, lambda ftp: ftp.rename(from_path, to_path))
    except _ERRORS as exc:
        return _fail(exc)
    return f"renamed {from_path} -> {to_path}"


@mcp.tool()
def delete_file(session: str, path: str) -> str:
    """Delete one remote file (not directories)."""
    try:
        _run(session, lambda ftp: ftp.delete(path))
    except _ERRORS as exc:
        return _fail(exc)
    return f"deleted {path}"


def main() -> None:
    global _ini_path
    ap = argparse.ArgumentParser(prog="tc-ftp-mcp", description=__doc__)
    ap.add_argument("--ini", type=Path, help="path to wcx_ftp.ini (default: %%APPDATA%%\\GHISLER\\wcx_ftp.ini)")
    args = ap.parse_args()
    _ini_path = args.ini
    if _ini_path is None:
        # fail early with a clear message instead of on the first tool call
        load_sessions(None)
    mcp.run()


if __name__ == "__main__":
    main()
