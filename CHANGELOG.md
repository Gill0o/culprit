# Changelog

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
