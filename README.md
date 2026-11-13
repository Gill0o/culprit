# Culprit

Attributes what third-party software on macOS **runs, deletes, copies and reads**, and prints each
act as a command line you can replay. A privileged helper's `rm -rf` is still charged to its app,
and a Homebrew script to `brew`, not to the `bash` that runs it. It is built on `eslogger`, Apple's
Endpoint Security client that ships with macOS.

Built for one question — *what did this software actually do to my Mac?* Vetting a maintenance app
or an installer before it reaches a fleet, establishing what an app removed, documenting third-party
behaviour for an audit. It answers with evidence you can replay, not a verdict: no detection, no
baseline, no alerting.

It observes only: it never runs, blocks or modifies anything on the Mac it watches. It writes its
own log file, plus a copy of every emitted line to the unified log ([Security](#security)).

**Requires** root, macOS 15+, `python3`, and Full Disk Access for the terminal that launches it
(System Settings → Privacy & Security → Full Disk Access).

## Install

Download `culprit-vX.Y.Z.sh` and `culprit-vX.Y.Z.sh.sha256` from the latest release, then:

```bash
shasum -a 256 -c culprit-vX.Y.Z.sh.sha256   # must print: culprit-vX.Y.Z.sh: OK
mv culprit-vX.Y.Z.sh culprit.sh
chmod +x culprit.sh
```

## Quick start

```bash
sudo ./culprit.sh                                   # every third-party app and tool (default)
sudo ./culprit.sh /Applications/X.app --report      # one app, one structured report on stop
sudo ./culprit.sh com.vendor.app --mdm --detach     # bundle ID, fleet-portable paths, background
sudo ./culprit.sh brew                              # a CLI tool by name
sudo ./culprit.sh --destructive-only                # anything dangerous, any actor
```

`[app]` takes a bundle **path**, a bundle **ID** (path-independent — prefer it on a fleet), a **CLI
tool** by name or path, or one of the built-in labels (`OnyX`, `Maintenance`, `Font Finagler`).
Omitted, the scope is every third-party app and tool (`--all`); Apple's own commands are left out.
Stop a capture with Ctrl-C.

## What the output looks like

A real `--report` run on Zoom, launched and quit (macOS 27, user renamed `alice`, lists cut at `…`):

```text
# ===== Culprit report — 186 distinct commands =====
# ⚠ destructive (125):
#   /bin/launchctl bootout gui/501/us.zoom.updater.gui.501.app.terminate.update
#   rm -rf '/Users/alice/Library/Group Containers/BJ4HAAB9B3.ZoomClient3rd/s.zoomclient'
#   …
# What survives a reboot (1):
#   LaunchAgent: /Users/alice/Library/LaunchAgents/us.zoom.updater.gui.501.app.terminate.update.plist — via mv

# ===== REPRODUCIBLE SCRIPT (in order) — copy from here to 'end of script' =====
…
/bin/launchctl list
rm -rf '/Users/alice/Library/Group Containers/BJ4HAAB9B3.ZoomClient3rd/s.zoomclient'
rm -rf /Users/alice/Library/Caches/us.zoom.xos/WebKit/ServiceWorkers   # via com.apple.WebKit.Networking
…
# ===== end of script =====
```

Each line is a command you can paste into a shell. Deletions the app made through system calls are
written as the `rm` that reproduces them, and `# via` names the process that did the work.

## Options

`./culprit.sh --help` is the full reference.

| Option | Does |
|---|---|
| `-l`, `--log <path>` | log file (default `/var/log/culprit-v<version>.log`); one capture per file; a named path never falls back |
| `-v`, `--verbose` | timestamped, and the noise filter is off (it hides shell plumbing such as `echo`, `sed`, `grep`) — not paste-ready (CLI only) |
| `-q`, `--only-cmds` | emitted commands alone (default) |
| `--apps <labels>` | several built-in labels, comma-separated (overrides `[app]`) |
| `--all` | every third-party app and tool (default); refused beside an app name or `--apps` |
| `--events <list>` | which optional event families to subscribe: `files`, `reads`, `opens`, `tcc`, `btm` (default all but `opens`; `+opens`, `-tcc` adjust it) |
| `--no-reads` | drop directory scans; deletions, moves and copies remain |
| `--no-files` | commands only, no file events |
| `--opens` | which files an app reads — high volume, for one target |
| `--mdm` | rewrite host paths into fleet-portable form (`/Users/$loggedInUser/…`) |
| `--report` | capture silently, one structured report on stop; reboot-safe |
| `--report-file <path>` | write the report to a file on stop instead of stdout (CLI only) |
| `--no-fold` | every deletion on its own line instead of one `rm -rf <dir>/*` |
| `--stable` | diffable report: one command per line, sorted — compare two captures with `diff` |
| `--marks-only` | report only what carries a `⚠` mark |
| `--no-queries` | drop the lines that only read (`defaults read`, `diskutil info`, `launchctl print`…) — for a replay script |
| `--ndjson` | live stream as one JSON object per line, for a SIEM/inventory; with `--report`, the report goes to a file on stop (CLI only) |
| `--cmd <list>` | only these commands, bypassing the noise filter |
| `--destructive-only` | destructive commands alone, any mode |
| `--exclude <list>` | more actors to drop under `--all` (name substrings or Team IDs) |
| `--detach` | run in the background, survive the terminal |
| `--duration <secs>` | stop by itself and render the report — needed unattended |
| `--debug` | show the JSON shape of the first events of each kind, and every command the noise filter drops (CLI only) |
| `-h`, `--help` | the option reference |

**Jamf Pro**: add `culprit.sh` as a script. Jamf mode is detected automatically, and parameters
`$4`–`$11` are described in the header of `culprit.sh`. Options marked *CLI only* have no Jamf
parameter.

## Scope

Shell-outs (`exec`, always) plus native-syscall file operations — deletions, moves, copies (APFS
clones), links, permission changes and extended-attribute removals — each printed as the command
that reproduces it. Privacy (TCC) grants/revokes (macOS 15.4+) and login-item adds/removes
(Background Task Management) are reported as information, since no command can replay them.
Marks: `⚠ destructive`, `⚠ network`, `⚠ persistence`, `⚠ secret`, `⚠ system scope`. Treat
destructive output as a reviewed draft, not a blind replay.

## Blind spots

A clean capture does not mean an app is inert. It means the app did nothing Culprit can see.

- **In-process work** — `URLSession`, editing an already-open file: invisible. Pair with Little
  Snitch / LuLu for an app's own network traffic.
- **File writes** — `create`/`write`/`truncate` are not subscribed, and plain `cp` or `rsync` emit no
  file event: such a copy is visible only through the command that ran it.
- **An Apple binary acting for the user** — attribution needs a third-party actor, except for a
  file landing in a persistence location.
- **Extended attributes written** (removals are seen), **shell builtins**, and what the **noise filter** hides (`-v` shows it).

## Security

- Command lines may reveal user data. **Review a capture before sharing it.**
- **Every line also goes to the unified log** (`logger -t culprit`), system-wide and swept up by
  `sysdiagnose`. `--log` does not move that copy, and there is no flag to suppress it.
- **Commands typed in a third-party terminal** (iTerm2, Warp, VS Code) are captured, tokens and
  passwords included. Name a single app when that matters.
- **Put the log where the target does not sweep** — a cleaner app will delete it mid-run.

Report a vulnerability: [SECURITY.md](SECURITY.md).

## Contributing

Issues and pull requests are welcome. Pull requests are applied to the development tree and ship in
the next release, credited to their author. For a security issue, see [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE). Release notes: [CHANGELOG](CHANGELOG.md).
