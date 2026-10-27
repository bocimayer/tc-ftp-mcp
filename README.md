# tc-ftp-mcp

An [MCP](https://modelcontextprotocol.io) server that connects to FTP servers using the sessions you already saved in Total Commander. No second copy of your hosts and passwords: it reads `wcx_ftp.ini` directly.

## What it does

Tools exposed to the MCP client:

| Tool | Purpose |
|------|---------|
| `list_sessions` | Saved sessions (name, host, port, user, start directory, passive, TLS). Never the password. |
| `list_dir` | List a remote directory. |
| `read_text` | Read a remote text file (capped at 256 KiB). |
| `download_file` | Download to a local path; refuses to overwrite. |
| `upload_file` | Upload a local file; refuses to replace unless `overwrite=true`. |
| `make_dir`, `rename`, `delete_file` | Basic remote changes. |

Passwords are decoded in memory for the login and are never returned, logged or written to disk.

## Install

```bash
git clone https://github.com/bocimayer/tc-ftp-mcp
cd tc-ftp-mcp
pip install -e .
```

Register it with Claude Code:

```bash
claude mcp add tc-ftp -- python -m tc_ftp_mcp
```

Or point at a different ini file:

```bash
claude mcp add tc-ftp -- python -m tc_ftp_mcp --ini "D:\path\to\wcx_ftp.ini"
```

The default ini location is `%APPDATA%\GHISLER\wcx_ftp.ini`.

## Skill

`skills/tc-ftp/SKILL.md` teaches an agent the workflow: find candidate sessions, let you pick one, verify it read-only, and only then work, asking before any change. Install it by copying the folder to `~/.claude/skills/`.

## Limits

- Plain FTP and explicit FTPS (sessions with `ftps://` or `ssl=1`). SFTP sessions use a different Total Commander plugin and storage; not covered.
- If you set a Total Commander master password, the stored passwords use a different scheme and will not decode.
- Total Commander's stored form is obfuscation, not encryption (see CVE-2005-4066). Anyone who can read your `wcx_ftp.ini` can read your passwords. Treat the file, and this tool's access to it, accordingly.
- Windows-1250 is assumed for the ini and for servers that do not support UTF-8.

## Credits

The password scheme was reverse engineered by others; see PELock's write-up and the Apache-2.0 `total-commander-ftp-password-recovery` package. This repo contains an independent implementation of the same published steps.

## Development

```bash
pip install -e .[dev] pyftpdlib
pytest
```

MIT licensed.
