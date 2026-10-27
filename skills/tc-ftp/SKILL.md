---
name: tc-ftp
description: Use when a task needs FTP access to a website or server (read files, check a WordPress install, upload or fix a file) and the login may be saved in Total Commander. Finds the candidate Total Commander sessions through the tc-ftp MCP server, lets the user pick one, and verifies it read-only. Never asks for or copies FTP credentials.
---

# Connect to a site through Total Commander sessions

The `tc-ftp` MCP server reads the user's saved Total Commander FTP sessions (`wcx_ftp.ini`) and logs in itself. You never see or handle a password.

## Rules

- Do not ask the user for FTP credentials. Do not read `wcx_ftp.ini` yourself. Do not write any credential anywhere (files, memory, chat).
- Session names, hosts, usernames and directories are not secret; you may show them.
- Everything is read-only until the user approves a specific change in chat. `upload_file`, `make_dir`, `rename` and `delete_file` need explicit approval for that exact action, every time.
- Never pass `overwrite=true` without approval for that file.

## Steps

1. **Check the tools exist.** Look for the `tc-ftp` tools (`list_sessions`, `list_dir`, `read_text`, ...). If they are missing, the server is registered but this session started before it. Tell the user to start a new session. Do not look for credentials elsewhere.

2. **Find candidates.** Call `list_sessions` with a filter built from what you know: the domain, brand, project name or hostname. Try one or two short variants (`telekiter`, `teleki`). Total Commander folders appear as `folder|name`, so a folder prefix is a useful filter.

3. **Present the options and let the user choose.** Use AskUserQuestion with up to four candidates, each labelled with the session name and described with host, port and whether it is TLS. Add what you know about why it is a candidate. If there are more than four, show the best four and say how many others matched. If there is exactly one strong match, still name it and ask for a yes before connecting. If there are none, say so and ask the user for the session name; do not invent a place for the credentials.

4. **Verify read-only.** After the user picks, run `list_dir` on the start directory, then `list_dir` on `www` or `public_html` if present, and `read_text` on `www/robots.txt` (or `index.php`, `wp-config.php` for the `siteurl`). Confirm the site that folder actually serves matches the task. Sessions on a shared host (same hostname, different usernames) are separate hosting accounts; the wrong one serves a different site. Report what you found in two or three lines.

5. **Do the task.** Stay within the approved scope. Before any write, say exactly what will change and wait for a yes.

## Errors

- `error_perm: 530`: the saved password is stale in Total Commander. Tell the user; do not retry in a loop (accounts lock).
- `CertificateNotTrusted`: show the user the SHA-256 fingerprint from the error. Only if they confirm the server is right, call `trust_certificate` with that fingerprint.
- `SSLError ... HANDSHAKE_FAILURE`: the server offers only outdated TLS; the tool will not downgrade. Tell the user.
- `TimeoutError`: server or port is gone or blocked. Tell the user.
