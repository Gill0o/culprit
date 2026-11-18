# Culprit

Attributes what third-party software on macOS **runs, deletes, copies and reads**, and prints each
act as a command line you can replay. A privileged helper's `rm -rf` is still charged to its app,
and a Homebrew script to `brew`, not to the `bash` that runs it. Built on `eslogger`.

Built for one question: *what did this software actually do to my Mac?* Vetting a maintenance app
or an installer before it reaches a fleet, establishing what an app removed, documenting third-party
behaviour for an audit. It answers with evidence you can replay, not a verdict: no detection, no
baseline, no alerting.

It observes only: it never runs, blocks or modifies anything on the Mac it watches. It writes its
own log file, plus a copy of every emitted line to the unified log ([Security](#security)).

**Requires** root, macOS 15+, `python3`, and Full Disk Access for the terminal (or `jamf`).

## Install

Verify the release asset against its `.sha256`, then `chmod +x`:

```bash
shasum -a 256 -c culprit-vX.Y.Z.sh.sha256
```

## Quick start

```bash
sudo ./culprit.sh                                   # every third-party app and tool (default)
sudo ./culprit.sh /Applications/X.app --report      # one app, one structured report on stop
sudo ./culprit.sh com.vendor.app --mdm --detach     # bundle ID, fleet-portable paths, background
sudo ./culprit.sh brew                              # a CLI tool by name
sudo ./culprit.sh --destructive-only                # anything dangerous, any actor
```

`[app]` takes a bundle **path**, a bundle **ID** (path-independent, prefer it on a fleet), an **app
name** found in `/Applications` (`Zoom`), or a **CLI tool** by name or path (`brew`).
Omitted, the scope is every third-party app and tool (`--all`); Apple's own commands are left out.

## What the output looks like

A real `--report` run on OnyX (macOS 27, user renamed `alice`, lists cut at `…`):

```text
# ===== Culprit report — 64 distinct commands =====
# ⚠ destructive (3):
#   rm -rf /Users/alice/Library/Caches/com.titanium.OnyX/fsCachedData
#   …
#   rm -f /Users/alice/Library/Logs/OnyX.log

# ===== COMMANDS IN ORDER: review, keep only what to replay; never run it whole =====
…
sysctl -n hw.model
…
csrutil status
# run from /
sh -c $'dscl . -read /Users/alice GeneratedUID | awk \'{print $2}\''
…
# via diskutil
ls -la /Library/Filesystems
…
defaults read com.titanium.OnyX UpdateLocation
…
sleep 4.3
rm -rf /Users/alice/Library/Caches/com.titanium.OnyX/fsCachedData
ls -la /Users/alice/Library/Caches/com.titanium.OnyX/fsCachedData
sleep 1.9
diskutil apfs listSnapshots /System/Volumes/Data
…
sh -c 'fdesetup status || true'
…
mdutil -s /
…
rm -f /Users/alice/Library/Logs/OnyX.log
# ===== end of commands =====
```

Syscall-level deletions are written as the `rm` that reproduces them; a `# via` line names the
process that did the work; a `sleep` is a pause where nothing ran, kept so a replay is not too fast.
What was changed in this run, the screenshot file name, is not in it: OnyX set it through the
preferences API, not a command (see [Blind spots](#blind-spots)).

## Options

The ones that matter most; `./culprit.sh --help` lists all of them.

| Option | Does |
|---|---|
| `--apps <list>` | several targets, comma-separated, each written like `[app]` |
| `--exclude <list>` | more actors to drop under `--all` (name substrings or Team IDs) |
| `--report` | capture silently, one structured report on stop; reboot-safe |
| `--stable` | diffable report: one command per line, sorted, to compare two captures with `diff` |
| `--mdm` | rewrite host paths into fleet-portable form (`/Users/$loggedInUser/…`) |
| `--ndjson` | live stream as one JSON object per line, for a SIEM/inventory (CLI only) |
| `--destructive-only` | destructive and persistence acts only, any mode |
| `--marks-only` | report only what carries a `⚠` mark |
| `--detach` | run in the background, survive the terminal |
| `--duration <secs>` | stop by itself and render the report; needed unattended |
| `-l`, `--log <path>` | log file (default `/var/log/culprit-v<version>.log`), one capture per file |
| `-v`, `--verbose` | timestamped, noise filter off, not paste-ready (CLI only) |
| `--debug` | JSON shape of the first events of each kind, and what the noise filter drops (CLI only) |

**Jamf Pro**: Jamf mode is detected automatically; parameters `$4`–`$11` are listed in the script
header. Options marked *CLI only* have no Jamf parameter.

## Scope

Shell-outs (`exec`, always) plus native-syscall file operations (deletions, moves, copies (APFS
clones), links, permission changes and extended-attribute removals), each printed as the command
that reproduces it. Privacy (TCC) grants/revokes (macOS 15.4+) and login-item adds/removes
(Background Task Management) are reported as information, since no command can replay them.
Marks: `⚠ destructive`, `⚠ network`, `⚠ persistence`, `⚠ secret`, `⚠ system scope`. Treat
destructive output as a reviewed draft, not a blind replay.

## Blind spots

A clean capture does not mean an app is inert. It means the app did nothing Culprit can see.

- **In-process work**: `URLSession`, a preference set through the API (not `defaults write`), editing an already-open file: invisible. Pair with Little
  Snitch / LuLu for an app's own network traffic.
- **File writes**: `create`/`write`/`truncate` are not subscribed, and plain `cp` or `rsync` emit no
  file event: such a copy is visible only through the command that ran it.
- **An Apple binary acting for the user**: attribution needs a third-party actor, except for a
  file landing in a persistence location.
- **Extended attributes written** (removals are seen), **shell builtins**, and what the **noise filter** hides (`-v` shows it).

## Security

- Command lines may reveal user data. **Review a capture before sharing it.**
- **Pasting is contained**: every word from the app is quoted, notes sit on their own `#` line, and a
  shell payload that is not plain words prints as the whole quoted call (`sh -c '…'`, or `$'…'` when it
  holds a quote), so nothing breaks out of its line. It still replays what the app did: read the
  destructive lines first.
- **Every line also goes to the unified log** (`logger -t culprit`), system-wide and swept up by
  `sysdiagnose`. `--log` does not move that copy, and there is no flag to suppress it.
- **Commands typed in a third-party terminal** (iTerm2, Warp, VS Code) are captured, tokens and
  passwords included. Name a single app when that matters.
- **Put the log where the target does not sweep**: a cleaner app will delete it mid-run.

Report a vulnerability: [SECURITY.md](SECURITY.md).

## Contributing

Issues and pull requests are welcome. Pull requests are applied to the development tree and ship in
the next release, credited to their author. For a security issue, see [SECURITY.md](SECURITY.md).

## License

MIT, see [LICENSE](LICENSE). Release notes: [CHANGELOG](CHANGELOG.md).
