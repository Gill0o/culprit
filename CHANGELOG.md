# Changelog

## 1.0.5 — 2026-11-18

### Change
- **The report's command list is for review, not for pasting whole**: header `COMMANDS IN ORDER: review, keep only what to replay; never run it whole`, footer `end of commands`.
- **No built-in app labels**: `[app]` takes a bundle path or ID, an app in `/Applications` or a CLI tool, else `nothing matches "<name>"`. `--apps` takes several, comma-separated.
- **Renames that matter are shown**: a same-folder rename is hidden as a save, except onto a file the user cannot write or between two real names (`x` → `x.locked`).
- **Saves through a temp name (Firefox, Cocoa) stay hidden.**
- **`--destructive-only` keeps persistence acts and login items.**
- **Newly marked ⚠**: `: > f`, `perl`/`python` removals, `osascript` running an rm, `rsync --delete`, `LoginHook`, `crontab`, `tee` into a launch item, shell startup files, `/opt/homebrew/bin`.
- **Exit codes**: 2 when the capture stops by itself (eslogger killed or refused), 141 when stdout's reader leaves (`| head`).

### Fix
- **Ctrl-C no longer cuts a big `--report`**: the stop waits for the last report line (up to 120 s; a second Ctrl-C cuts it and keeps what was recorded).
- **`chown` with an unchanged uid or gid replays right**: `chgrp 80`, not `chown 4294967295:80`.
- **Deletions in a folder that is not emptied** print as one narrower glob (`rm -f <dir>/[0-9]*`) when it spares every file left, else as the exact list.
- **Replay fidelity**: a lone deleted file is `rm -f`, not `rm -rf`; `argv[0]` no longer hides the executable; repeats keep their order (`rm x`, `touch x`, `rm x`).
- **The `run from` note also covers a bare relative name** (`rm foo`).
- **Attribution**: a printed `rm` hides only its own deletions; an `sh -c` script with loops, `shift`, functions or zsh `$argv` prints the commands that really ran.
- **`--mdm` rewrites only the console user's `/var/folders`**; root's or another user's stays literal.
- **Stopping**: no orphan eslogger after `| head`; Ctrl-C during `--detach`'s start stops the child; a second signal keeps the exit code; a stuck eslogger is killed.
- **`--detach` and the pidfile**: inherited descriptors are closed, a reused pid counts as stale, and of two captures started together on one log only one runs.
- **Scale**: a 100k-file wipe folds in about 2 s (it was quadratic); huge argvs no longer grow the parser to gigabytes; a report line over 32 KiB is a `# NOTE`, and the report stops at 128 MiB.

### Security
- **Bidi and zero-width characters are escaped** (`\xHH`): a name holding U+202E no longer displays as another one.
- **The log is opened once without following a link**; the report's working file and `--report-file` are refused through a link or in a folder others can write (unless sticky).

## 1.0.4 — 2026-11-14

### Security
- **A shell payload prints bare only when it is plain words**, else quoted whole (`sh -c '…'`, or `$'…'` if it holds a quote): pasted, it cannot spill into the next line.
- **The report keeps an app's literal `$loggedInUser` or `~/` inert**; only what `--mdm` wrote expands. `rm -rf '/x/$loggedInUser'` no longer replays as `rm -rf /x/`.
- **No note trails a command, in any mode**: marks sit on their own `#` line above it. `--mdm` quotes `!`; its header and the TCC lines (`→`, not `->`) are inert prose.

### Fix
- A pipeline printed whole no longer carries a false "reads a pipe — will not replay" note: the pipe is in the line.
- **A copied LaunchDaemons tree is not persistence**: only `/Library/…`, `~/Library/…` and root's `Library` count. A package that `pkgutil` expanded under `/var/folders` was reported as persistence.

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
