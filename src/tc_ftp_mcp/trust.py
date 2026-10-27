"""Certificate fingerprints the user explicitly approved (public data, not secrets)."""

from __future__ import annotations

import json
import os
from pathlib import Path


def store_path() -> Path:
    base = os.environ.get("APPDATA")
    root = Path(base) if base else Path.home() / ".config"
    return root / "tc-ftp-mcp" / "trusted_certs.json"


def _read(path: Path) -> dict[str, list[str]]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def trusted(host: str, path: Path | None = None) -> set[str]:
    return {fp.upper() for fp in _read(path or store_path()).get(host.lower(), [])}


def add(host: str, sha256: str, path: Path | None = None) -> None:
    path = path or store_path()
    data = _read(path)
    fps = set(data.get(host.lower(), []))
    fps.add(sha256.upper())
    data[host.lower()] = sorted(fps)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
