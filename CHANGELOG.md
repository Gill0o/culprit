# Changelog

## 1.0.3 — 2026-11-13

### Compatibility
- **Supported: macOS 15 and later**, the last three releases. On macOS 13 or 14 Culprit starts with a warning and carries on: untested, a capture may be incomplete.
- Privacy (TCC) changes are reported from macOS 15.4, the release that introduced the event, not only from 26.

### Security
- **Python runs isolated (`-I`)**: a `json.py` or user site-packages near the caller no longer runs as root. Culprit starts as `zsh -f` and works from `/`.
- **Nothing pasted from a `#` line can run**, even in an interactive zsh: app, helper and path names in prose are neutralised; the script starts with `setopt interactivecomments`.
- The Team ID comes from one exact `TeamIdentifier=` line of 10 characters. Invalid bytes and invisible characters are escaped on the terminal and in NDJSON.

### Fix
- Under a UTF-8 locale (sudo, Jamf), a non-UTF-8 byte in an event no longer stops the parser.
- **A reused pid is no longer charged to the watched app**: a pid leaves the table when its process exits, and a full table drops its oldest entries instead of all of them.
- **Closing a terminal tab no longer prints `chown 0:0`/`chmod 0666` on `/dev/ttysNNN` as `⚠ destructive`**: login's pseudo-terminal reset is noise now (`-v` shows it).
- **bash's here-document temp file (`sh-thd-…`) is no longer reported as `⚠ destructive` `rm -rf`**: the shell deletes it itself (`-v` shows it).

### Output
- **`--help` is a reference now**: one or two lines per option, 67 lines instead of 174.

## 1.0.2 — 2026-11-12

First public release, after private development since version 0.1.0 (2026-07-25).

### What it does
- Attributes each command a third-party app runs — directly, through its privileged helper or a script interpreter — to that app, as a command line you can replay.
- Rebuilds file operations made through system calls as the command that reproduces them: deletions, moves, copies (APFS clones), links, permission changes, `xattr -d`.
- Marks what matters: `⚠ destructive`, `⚠ network`, `⚠ persistence`, `⚠ secret`, `⚠ system scope`.
- Reports privacy (TCC) grants and revokes (macOS 26+) and login items added or removed, as information.
- `--report`: a structured report on stop — marks, what survives a reboot, TCC changes, then the reproducible script in order. Reboot-safe.
- `--ndjson`: one JSON object per line for a SIEM or inventory, with `pid`/`pidver` to join network flows.
- `--mdm` writes fleet-portable paths; `--stable` sorts the report so two captures compare with `diff`.
- Jamf Pro: detected automatically, parameters `$4`–`$11`; `--detach` and `--duration` for unattended runs.

### Security
- Observation only: nothing is run, blocked or modified. Log and pidfile are 0600, written only in trusted directories, with no temp-dir fallback.
- The report quotes arguments as the live line did, so a replayed glob cannot match files planted since.
- Each release ships `culprit-vX.Y.Z.sh.sha256`; `SECURITY.md` says how to report a flaw.
