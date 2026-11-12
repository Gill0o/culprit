#!/bin/zsh
# ============================================================================
# Script: culprit.sh
# Version: 1.0.2
# Author: Gilles Bonpain
# Powered by Claude AI
# Description: Attribute what macOS apps and tools run, delete and read
# ============================================================================
# Attributes the commands an app runs, and the files it deletes, moves, copies or
# reads through system calls, to that app, as replayable command lines (an unlink
# becomes the `rm -rf` that reproduces it). It streams Apple's `eslogger` and
# resolves the actor from the code-signing Team ID, bundle path and process
# ancestry; a privileged helper is attributed to its app. Observation only:
# nothing on the host is run, blocked or modified. It writes its log file and
# sends a copy of every emitted line to the unified log through `logger`
# (no flag suppresses it).
#
# Usage:
#   sudo ./culprit.sh [app] [OPTIONS]
#   [app]: registry label, bundle path, bundle ID, or CLI tool name or path
#   (default: every third-party app and tool).
#   `./culprit.sh --help` is the full reference. Long options:
#     --log --verbose --only-cmds --debug --apps --all --events --no-reads
#     --no-files --opens --mdm --report --report-file --no-fold --stable
#     --marks-only --no-queries --ndjson --cmd --destructive-only --exclude
#     --detach --duration --help
#
# Jamf Pro mode (auto-detected): $1-$3 are reserved by Jamf, $4-$11 are used;
# every other option is CLI-only. A blank parameter takes its default. Booleans:
# "true", "yes", "y", "on", "1", "oui", "vrai" enable; anything else is false.
#   $4  App to watch: registry label | bundle path | bundle ID | CLI tool name
#       or path | ALL (blank = ALL)
#   $5  Report on stop: true | false (blank = false)
#   $6  MDM portable paths: true | false (blank = false)
#   $7  Report shape: comma-separated list, blank = everything. Terms:
#       destructive, actions (commands + file ops, no scans), marks (anything
#       flagged, secret too), stable (one sorted normalised command per line),
#       noqueries (drop read-only lines). marks and stable need $5=true.
#       "true" means destructive; an unknown term in a list is refused.
#   $8  No-fold, exact list: true | false (blank = false)
#   $9  Detach: true | false, or a number of seconds >= 2 (detach, stop after
#       that long and render the report). 0 and 1 are booleans; anything else
#       is refused.
#   $10 Exclude list, or key=value pairs. Without `=`: comma-separated
#       substrings/Team IDs. With `=`: pairs separated by `;` among exclude=,
#       events=, cmd=, apps= (narrows $4=ALL). Unknown or repeated key, or a
#       pair with no `=`, refuses the policy.
#   $11 Log path (blank = /var/log/culprit-v<version>.log; named: no fallback)
#
# Requirements: root + Full Disk Access on the terminal, macOS 13+, python3.
# ============================================================================

set -e
set -u
set -o pipefail

# One locale everywhere: `[[:space:]]`, `${x:l}` and the parser follow LC_CTYPE.
# Exported before parsing so the --detach re-exec and the parser inherit it.
export LC_ALL=en_US.UTF-8

# Self-diagnostic: record where a command returned non-zero (the log captures
# neither stderr nor an abort). ZERR fires on any non-zero status, whether or not
# `set -e` then aborts, so the message states the status, not a death.
TRAPZERR() {
  local _loc="${funcfiletrace[1]:-?}" _fn="${funcstack[2]:-main}"
  print -u2 "culprit: non-zero status at ${_loc} (in ${_fn})" 2>/dev/null || true
  # Logged only once the banner is down: earlier it would leave residue outside
  # CULPRIT_TMPDIR or become the log's first line, which `_is_culprit_log` refuses.
  if [ -z "${_IN_TRAPZERR:-}" ] && [ -n "${_LOG_READY:-}" ]; then
    # Recursion guard: a failing log_line re-enters this handler.
    _IN_TRAPZERR=1
    log_line "Cmd: # TRACE: non-zero status at ${_loc} (in ${_fn})" 2>/dev/null || true
    unset _IN_TRAPZERR
  fi
}

# ---------------------------------------
# CONFIGURATION — target app registry (declarative, extensible)
# ---------------------------------------
# Optional. An entry supplies a short label and the one relation the system does
# not expose: that a privileged helper belongs to the app that installed it.
#
# One line per app: "label|team_id|bundle_path_prefix|helper_paths(comma)".
#   - team_id           : code-signing Team ID; matches the app and everything
#                         else that developer signs, its SMJobBless helper included.
#   - bundle_path_prefix: evaluated before the Team ID (separates two apps from one
#                         vendor) and identifies the app's own image, so a relaunch
#                         is not logged as a command.
#   - helper_paths      : absolute paths to treat as the app; only needed where a
#                         helper is signed by another developer.
# Any field may be empty. A fifth field, `cli_paths`, is built at runtime by
# _target_from_path() and never written here: entries carry four fields, the
# parser reads five. A CLI tool is named on the command line, not listed here.
typeset -ga TARGET_APPS=(
  "OnyX|T49MRBL8UL|/Applications/OnyX.app|"
  "Maintenance|T49MRBL8UL|/Applications/Maintenance.app|"
  "Font Finagler|YP47SDZM4G|/Applications/Font Finagler.app|/Library/PrivilegedHelperTools/com.markdouma.finaglerd"
)

# Event types subscribed to. `exec` is unconditional and carries attribution on
# its own (each exec supplies ppid and responsible process, covering a helper
# subtree without a `fork` stream). The rest are appended below behind the option
# requiring them. create/write/truncate are excluded: they fire on every
# temporary file and bury the signal.
typeset -ga EVENT_TYPES=(exec)

# ALL mode: attribution widens from the registry to any third-party image (an
# executable inside a `.app`, or out-of-bundle non-Apple-platform code).
#
# Auto-updaters only: Docker, TeamViewer, Dropbox and the like are omitted on
# purpose, since root, file movement and remote access are what is audited. An
# exclusion drops an actor entirely, where a noise rule drops one command.
# `-v` disables it.
typeset -ga DEFAULT_EXCLUDES=(
  "MAU2.0"                          # Microsoft AutoUpdate (app + AU Daemon)
  "com.microsoft.autoupdate"        # …and its privileged helper
  "GoogleSoftwareUpdate"            # Google Keystone (legacy)
  "GoogleUpdater"                   # Google Updater (Chrome, replaces Keystone)
  "com.adobe.acc"                   # Adobe Creative Cloud updater
  "Adobe Desktop Common"
  "zoom.updater"                    # Zoom auto-updater (the Zoom app itself stays)
)

# Make a user- or Jamf-supplied value inert before printing: every control
# character as \xNN (the parser's raw_out rule), so a newline or ESC cannot forge
# a `# culprit: …` line or repaint the screen.
_inert() {
  local s="$1" o="" c i
  if [[ "$s" != *[[:cntrl:]]* ]]; then print -rn -- "$s"; return 0; fi
  for (( i = 1; i <= ${#s}; i++ )); do
    c="${s[i]}"
    if [[ "$c" == [[:cntrl:]] ]]; then o+="$(printf '\\x%02x' "'$c")"; else o+="$c"; fi
  done
  print -rn -- "$o"
}

show_help() {
  /bin/cat << 'EOF'
Usage: sudo ./culprit.sh [app] [OPTIONS]

Attributes each command an app shells out, and its API-level file operations, to
that app as a replayable command line. Observation only: nothing is run or
blocked.

Arguments:
  [app]                 Restrict to one app, by bundle path
                        (/Applications/Whatever.app), bundle ID (com.vendor.app,
                        Spotlight-resolved and path-independent, the form to use
                        on a fleet), or a registry label. A path or ID works for
                        any app, listed or not; its Team ID is read so its
                        privileged helper is attributed with it. A CLI tool is
                        targetable the same way, by name (`brew`, resolved on the
                        PATH and in the Homebrew, MacPorts and /usr/local
                        prefixes) or by path (/opt/homebrew/bin/…,
                        /Library/PrivilegedHelperTools/…): software shipping no
                        bundle is treated as an actor, its own command line
                        included with its arguments. Omitted, the scope is every
                        third-party app and tool; --apps <labels> for a set.

Options:
  Marked (CLI only) below have no Jamf Pro parameter — see the header comment
  for the eight Jamf gets ($4-$11); everything else keeps its default there.
  -l, --log <path>      Log file path (default /var/log/culprit-v<version>.log).
                        A named path is the only one used: if it cannot be
                        written safely the run stops, nothing falls back.
                        One capture per file: a watcher left running keeps
                        writing to the same report accumulator, so a second run
                        on that log is refused and names the pid to stop.
  -v, --verbose         (CLI only) Timestamped and unfiltered: the noise filter, the
                        toolchain rule and the exclude list are all disabled, and
                        Apple's applications become actors (Terminal, Script
                        Editor) while its daemons remain out. Not paste-ready.
  -q, --only-cmds       Emitted commands alone (default)
  --debug               (CLI only) Dump the JSON shape of the first events of each kind, to
                        confirm the eslogger schema of a given macOS release.
                        Adds '# FILTERED: <cmd> (reason)' for every command the
                        noise filter drops, and — in ALL mode — '# UNATTRIBUTED:
                        <cmd>' for every third-party exec resolving to no actor,
                        so an attribution gap is stated rather than silent.
                        Produces nothing under --report, which suppresses it —
                        except with --ndjson, whose stream stays live.
  --apps <labels>       Comma-separated labels to watch (overrides [app]). Also
                        settable via Jamf's `$10` (`apps=` key).
  --all                 Every third-party app and tool; the default. Apple's own
                        commands are dropped. Registry labels still apply;
                        anything else is named after its .app bundle.
  --events <list>       Which optional event families to subscribe: files, reads,
                        opens, tcc, btm (exec is always on). A bare list (files,opens)
                        sets exactly those — except reads/opens alone, which imply
                        files too: neither means anything without the file-operation
                        subscription they ride on. +term/-term (+opens, -reads,-opens)
                        adjust the default (files+reads+tcc+btm on, opens off)
                        instead of replacing it. An unknown term refuses the whole
                        list. --no-files, --no-reads and --opens below are
                        shorthands for the single-term case, through the same
                        code path, so every spelling and order agrees. Also
                        settable via Jamf's `$10` (`events=` key).
                        tcc: privacy (TCC) grants and revokes — Full Disk
                        Access, Camera, Automation, etc. — reported even though
                        no file changes and no command runs. On by default
                        (volume is tiny); `--events -tcc` drops it. Needs
                        macOS 26+ (ES_EVENT_TYPE_NOTIFY_TCC_MODIFY); older
                        releases drop it via the same preflight as any other
                        unsupported event type — no special case, no error.
                        btm: login items added or removed — a toggle in System
                        Settings > Login Items, or software registering itself
                        via SMAppService/ServiceManagement — reported even
                        though no command runs. On by default (volume is
                        tiny); `--events -btm` drops it.
  --no-reads            Omit the directories an app scans; deletions, moves and
                        copies remain. A SUBSCRIPTION cut — readdir stops firing,
                        so a scan never becomes an event — unlike --no-queries
                        below, which trims already-captured lines by what their
                        command does, not by event type.
  --no-files            Commands only — no file events. Both are reported by
                        default: an app operating through the system APIs runs no
                        command at all and would otherwise register as idle.
  --opens               Report which files an app reads (open events), emitted
                        as `cat <path>`. A directory scan gives the location an
                        app looked in; this gives the file it opened there, and
                        so its type. Opt-in and high volume, firing on every file
                        access: intended for a single target. Permitted in ALL
                        mode, with a warning.
  --mdm                 Render the emitted commands fleet-deployable: host user
                        paths become /Users/$loggedInUser/…, and the per-user
                        DARWIN folders (/var/folders/…/{0,C,T}, a per-machine
                        token) become $userDir/$userCache/$userTemp, resolved by
                        `getconf` as an app resolves them. A resolver header
                        defines each. The output runs on any Mac in the fleet.
  --report              Capture silently, then on stop emit one structured
                        report: the distinct commands, the destructive, network,
                        persistence, secret and privacy (TCC) sections, and a
                        paste-ready script in order.
                        Pairs with --detach. Reboot-safe: each command is fsync'd
                        to <log>.report as captured, so a Mac rebooted mid-run
                        loses nothing and the next --report launch renders it.
  --report-file <path>  (CLI only) Write the --report output to <path> on stop
                        instead of stdout — the same bytes --report prints. Must
                        not exist yet or be empty. Needs --report.
  --no-fold             Emit deletions individually. By default a syscall
                        tree-wipe is summarised as one `rm -rf <dir>/*`, and the
                        directory is examined afterwards to establish whether
                        that summary is exact or remains ⚠ approximate; --no-fold
                        emits every `unlink` as its own `rm -rf <file>`.
  --stable              Report as one normalised command per line, sorted and
                        de-duplicated, with no counts, no headers, no `sleep` and
                        no trailing caveats. Two captures of software that behaved
                        the same then produce identical files, so a `diff` between
                        them shows acts and not artefacts. Every line that does not
                        open with `#` is a command. Pair with --mdm to compare
                        across Macs. Needs --report; it shapes the report.
  --marks-only          Report only the lines carrying a mark — destructive,
                        network, persistence, secret. Unlike --destructive-only it
                        keeps a ⚠ secret line, which destroys nothing, and it
                        un-subscribes nothing: the capture is whole, the report is
                        narrower. Needs --report.
  --no-queries          Drop the lines that only read — `defaults read`,
                        `diskutil info`, `system_profiler`, `fdesetup status` and
                        the filters they pipe through. An app's launch checks are
                        worth reading in an audit and useless in a replay script.
                        A line that writes anywhere — a redirection to a file,
                        `defaults export`, `plutil -o <file>` — or carries a mark
                        is kept. Live output and report alike.
  --ndjson              (CLI only) The live stream as one JSON object per line
                        (ts/cmd/via/marks/kind/app/pid/pidver for a command,
                        type:"info" for everything else)
                        instead of text, for a SIEM or inventory to ingest. Same
                        objects go to the log file and the unified-log copy. With
                        --report the stream stays live and the text report is
                        written on stop to --report-file, by default
                        <log>.report.txt — never onto the stream.
  --cmd <list>          Restrict output to these commands, by name (ls,rm,
                        defaults), bypassing the noise filter for them. Also
                        settable via Jamf's `$10` (`cmd=` key).
  --destructive-only    Destructive commands alone (rm -rf, kill, erase, cache
                        flushes, launchctl bootout, …), in any mode. Directory
                        scans, file reads and TCC changes are un-subscribed with
                        them: none of them modifies anything, so none can
                        qualify. This also spares the event stream.
  --exclude <list>      Comma-separated substrings/Team IDs to drop in --all
                        mode, appended to the built-in updater excludes.
  --detach              Background the capture and return the prompt. Intended
                        for apps that quit every open application before working
                        (OnyX): the capture outlives its terminal, and SIGHUP is
                        ignored rather than trapped, so it keeps recording while
                        the app works. Reports how to follow the log and stop it.
  --duration <secs>     Stop by itself after that many seconds, render the report
                        and exit 0 — a planned stop is a success. An unattended run
                        needs this: the report is only written when a capture ends.
                        It is an UPPER BOUND, not a promise — a capture also ends
                        when eslogger's client is dropped, and a security agent may
                        take the slot. When that happens the log says so, with how
                        long the capture actually got, so a truncated report is
                        never mistaken for a complete one.
  -h, --help            Show this help

Requirements: root, Full Disk Access on the invoking terminal, macOS 13+ for
eslogger, python3.

Exit codes: 0 done · 1 refused before starting · 130 Ctrl+C · 143 SIGTERM ·
129 SIGHUP. A capture stopped by a signal still writes its report.

Examples:
  sudo ./culprit.sh                       # every third-party app and tool
  sudo ./culprit.sh /Applications/X.app   # one app by bundle path
  sudo ./culprit.sh com.vendor.app        # one app by bundle ID
  sudo ./culprit.sh brew                  # a CLI tool by name — brew, not bash
  sudo ./culprit.sh /Library/PrivilegedHelperTools/com.vendor.helper  # or by path
  sudo ./culprit.sh --apps OnyX,Maintenance   # a specific set
  sudo ./culprit.sh --destructive-only    # dangerous commands, any actor
  sudo ./culprit.sh --detach OnyX         # outlives OnyX quitting the terminal
  sudo ./culprit.sh --debug OnyX          # confirm the eslogger schema
EOF
  exit 0
}

parse_cli_args() {
  [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]] && show_help

  APP_FILTER=""
  LOG_FILE_PARAM=""
  ONLY_CMDS_RAW="true"
  DEBUG_RAW="false"
  DETACH_RAW="false"
  DURATION_RAW=""
  APPS_OVERRIDE=""
  ALL_RAW=""            # empty = scope not chosen yet; resolved after parsing
  CMD_FILTER=""
  FILES_RAW="true"
  READS_RAW="true"
  OPENS_RAW="false"
  TCC_RAW="true"
  BTM_RAW="true"
  MDM_RAW="false"
  REPORT_RAW="false"
  NOFOLD_RAW="false"
  STABLE_RAW="false"
  MARKS_RAW="false"
  NDJSON_RAW="false"
  REPORT_FILE_PARAM=""
  NOQUERIES_RAW="false"
  DESTR_RAW="false"
  EXCLUDE_EXTRA=""

  # First non-flag arg is the app filter (or ALL). An empty positional is refused,
  # not read as ALL.
  _ALL_FLAG="false"; _POS_SEEN="false"
  if [[ $# -gt 0 && "${1}" != -* ]]; then
    case "${1}" in
      "") echo "Error: empty app name" >&2; exit 1 ;;
      ALL|all|'*') ALL_RAW="true"; _ALL_FLAG="true" ;;
      *) APP_FILTER="${1}" ;;
    esac
    _POS_SEEN="true"
    shift
  fi

  while [[ $# -gt 0 ]]; do
    case "${1}" in
      -l|--log)     [[ -z "${2:-}" ]] && { echo "Error: --log requires a path" >&2; exit 1; }; LOG_FILE_PARAM="${2}"; shift 2 ;;
      -v|--verbose) ONLY_CMDS_RAW="false"; shift ;;
      -q|--only-cmds) ONLY_CMDS_RAW="true"; shift ;;
      --debug)      DEBUG_RAW="true"; shift ;;
      --apps)       [[ -z "${2:-}" ]] && { echo "Error: --apps requires a list" >&2; exit 1; }; APPS_OVERRIDE="${2}"; shift 2 ;;
      --all)        ALL_RAW="true"; _ALL_FLAG="true"; shift ;;
      --events)     [[ -z "${2:-}" ]] && { echo "Error: --events requires a list" >&2; exit 1; }; _events_apply_list "${2}" "--events"; shift 2 ;;
      # Aliases for single --events terms, through the same function so every
      # spelling and order lands on identical RAW values. (--no-files drops opens
      # too: that cascade runs once, below, off WATCH_FILES.)
      --no-files)   _events_apply_list "-files" "--no-files"; shift ;;
      --no-reads)   _events_apply_list "-reads" "--no-reads"; shift ;;
      --opens)      _events_apply_list "+opens" "--opens"; shift ;;
      --mdm)        MDM_RAW="true"; shift ;;
      --report)     REPORT_RAW="true"; shift ;;
      --no-fold)    NOFOLD_RAW="true"; shift ;;
      --stable)     STABLE_RAW="true"; shift ;;
      --marks-only) MARKS_RAW="true"; shift ;;
      --ndjson)     NDJSON_RAW="true"; shift ;;
      --report-file) [[ -z "${2:-}" ]] && { echo "Error: --report-file requires a path" >&2; exit 1; }; REPORT_FILE_PARAM="${2}"; shift 2 ;;
      --no-queries) NOQUERIES_RAW="true"; shift ;;
      --cmd)        [[ -z "${2:-}" ]] && { echo "Error: --cmd requires a list" >&2; exit 1; }; CMD_FILTER="${2}"; shift 2 ;;
      --destructive-only) DESTR_RAW="true"; shift ;;
      --exclude)    [[ -z "${2:-}" ]] && { echo "Error: --exclude requires a list" >&2; exit 1; }; EXCLUDE_EXTRA="${2}"; shift 2 ;;
      --detach)     DETACH_RAW="true"; shift ;;
      --duration)   [[ -z "${2:-}" ]] && { echo "Error: --duration requires whole seconds" >&2; exit 1; }; DURATION_RAW="${2}"; shift 2 ;;
      -h|--help)    show_help ;;
      *)
        # A bare word after a flag is still the [app] positional (`--debug OnyX`);
        # only a second positional is an error.
        if [[ "${1}" != -* ]] && [[ "$_POS_SEEN" != "true" ]]; then
          case "${1}" in
            "") echo "Error: empty app name" >&2; exit 1 ;;
            ALL|all|'*') ALL_RAW="true"; _ALL_FLAG="true" ;;
            *) APP_FILTER="${1}" ;;
          esac
          _POS_SEEN="true"
          shift
        else
          printf 'Error: Unknown option: %s\n' "$(_inert "${1}")" >&2; echo "Use --help for usage." >&2; exit 1
        fi ;;
    esac
  done

  # --all (or a positional ALL) contradicts naming an app, in either order.
  if [[ "$_ALL_FLAG" == "true" && ( -n "$APP_FILTER" || -n "$APPS_OVERRIDE" ) ]]; then
    echo "Error: --all cannot be combined with an app name or --apps" >&2; exit 1
  fi

  # Scope defaults to ALL; naming an app (or --apps) narrows it.
  if [[ -z "$ALL_RAW" ]]; then
    if [[ -n "$APP_FILTER" || -n "$APPS_OVERRIDE" ]]; then
      ALL_RAW="false"
    else
      ALL_RAW="true"
    fi
  fi
}

# Shared by --events and $10's "events=" key (and the --no-files/--no-reads/--opens
# aliases, as single-term deltas). Bare terms form an ABSOLUTE list replacing the
# whole set; every term signed +/- is a DELTA against the current *_RAW values.
# Mixing the two is refused; so is an unknown term.
_events_apply_list() {
  local _list="$1" _who="$2"
  local -a _toks=()
  local _tok
  for _tok in ${(s:,:)_list}; do
    while [[ "$_tok" == [[:space:]]* ]]; do _tok="${_tok#?}"; done
    while [[ "$_tok" == *[[:space:]] ]]; do _tok="${_tok%?}"; done
    [ -n "$_tok" ] && _toks+=("$_tok")
  done
  [ "${#_toks[@]}" -gt 0 ] || { printf '# culprit: %s requires a list\n' "$_who" >&2; exit 1; }
  local _mode="absolute" _t _abs="" _sgn=""
  for _t in "${_toks[@]}"; do
    case "$_t" in
      +*|-*) _mode="delta"; _sgn="${_sgn:-$_t}" ;;
      files|reads|opens|tcc|btm) _abs="${_abs:-$_t}" ;;
    esac
  done
  # A known bare term beside a signed one gets its own message, not "unknown".
  if [ -n "$_abs" ] && [ -n "$_sgn" ]; then
    printf '# culprit: %s: do not mix absolute terms (%s) with +/- terms (%s)\n' "$_who" "$(_inert "$_abs")" "$(_inert "$_sgn")" >&2; exit 1
  fi
  if [ "$_mode" = "absolute" ]; then
    FILES_RAW="false"; READS_RAW="false"; OPENS_RAW="false"; TCC_RAW="false"; BTM_RAW="false"
    for _t in "${_toks[@]}"; do
      case "$_t" in
        files) FILES_RAW="true" ;;
        reads) READS_RAW="true"; _EVENTS_WANT_READS="true" ;;
        opens) OPENS_RAW="true"; _EVENTS_WANT_OPENS="true" ;;
        tcc)   TCC_RAW="true" ;;
        btm)   BTM_RAW="true" ;;
        *) printf '# culprit: %s: unknown term "%s" — known: files, reads, opens, tcc, btm (or +files, -files, +reads, -reads, +opens, -opens, +tcc, -tcc, +btm, -btm)\n' "$_who" "$(_inert "$_t")" >&2; exit 1 ;;
      esac
    done
    # reads/opens ride on the file-operation subscription (WATCH_FILES=false
    # forces both off later), so a bare list naming either implies files. Delta
    # lists are untouched: an explicit -files always wins.
    if { [ "$READS_RAW" = "true" ] || [ "$OPENS_RAW" = "true" ]; } && [ "$FILES_RAW" != "true" ]; then
      FILES_RAW="true"
    fi
  else
    for _t in "${_toks[@]}"; do
      case "$_t" in
        +files) FILES_RAW="true" ;;
        -files) FILES_RAW="false" ;;
        +reads) READS_RAW="true"; _EVENTS_WANT_READS="true" ;;
        -reads) READS_RAW="false" ;;
        +opens) OPENS_RAW="true"; _EVENTS_WANT_OPENS="true" ;;
        -opens) OPENS_RAW="false" ;;
        +tcc)   TCC_RAW="true" ;;
        -tcc)   TCC_RAW="false" ;;
        +btm)   BTM_RAW="true" ;;
        -btm)   BTM_RAW="false" ;;
        *) printf '# culprit: %s: unknown term "%s" — known: files, reads, opens, tcc, btm (or +files, -files, +reads, -reads, +opens, -opens, +tcc, -tcc, +btm, -btm)\n' "$_who" "$(_inert "$_t")" >&2; exit 1 ;;
      esac
    done
  fi
}
# Set when a term explicitly asks for reads/opens (not by default); read by the
# --destructive-only warning, which drops both.
_EVENTS_WANT_READS=""
_EVENTS_WANT_OPENS=""

# Jamf detection: $1=mount_point $2=computer_name $3=username, params at $4+.
# The shape collides with a CLI call (`culprit.sh /Applications/X.app --opens
# --report`). Jamf never passes flags in those slots, and its mount point is a
# volume (`/`, `/Volumes/…`), never an app bundle.
JAMF_MODE="false"
# `$3` may be empty: Jamf passes no console user when nobody is logged in.
if [[ -n "${1:-}" && "${1}" == /* && "${1}" != *.app ]] \
   && [[ -n "${2:-}" && "${2}" != -* ]] && [[ "${3:-}" != -* ]]; then
  JAMF_MODE="true"
fi
if [ "$JAMF_MODE" = "true" ]; then
  # Jamf gives only $4-$11; the rest keep their defaults (CLI only). Empty $4 = ALL.
  APP_FILTER="${4:-}"
  case "$APP_FILTER" in
    ALL|all|'*'|"") ALL_RAW="true"; APP_FILTER="" ;;
    *) ALL_RAW="false" ;;
  esac
  REPORT_RAW="${5:-false}"
  MDM_RAW="${6:-false}"
  NOFOLD_RAW="${8:-false}"
  # $9 is a boolean OR a number of seconds: `true` detaches and runs until killed;
  # a number detaches and stops itself after that long (one policy, report
  # rendered at the end). Trimmed first, like $7's terms.
  _p9="${9:-false}"
  while [[ "$_p9" == [[:space:]]* ]]; do _p9="${_p9#?}"; done
  while [[ "$_p9" == *[[:space:]] ]]; do _p9="${_p9%?}"; done
  [ -n "$_p9" ] || _p9="false"
  case "${_p9:l}" in
    # `0` and `1` stay boolean (to_bool spellings), not durations; 2 and up is one.
    0|1|true|false|yes|no|non|y|n|on|off|oui|vrai) DETACH_RAW="$_p9" ;;
    *[!0-9]*)
      # Refused, not read as false: no detach and no limit would hang the policy
      # in a foreground capture that never reports.
      printf '# culprit: $9: "%s" is neither a boolean nor whole seconds\n' "$(_inert "$_p9")" >&2
      printf '#   detach: true/false — or a number of seconds to stop by itself: 300\n' >&2
      exit 1 ;;
    *) DETACH_RAW="true"; DURATION_RAW="$_p9" ;;
  esac
  LOG_FILE_PARAM="${11:-}"
  ONLY_CMDS_RAW="true"; DEBUG_RAW="false"; APPS_OVERRIDE=""; CMD_FILTER=""
  FILES_RAW="true"; READS_RAW="true"; OPENS_RAW="false"; TCC_RAW="true"; BTM_RAW="true"
  # $10: the exclude list, unless it contains "=": then key=value pairs separated
  # by ";" (values may hold commas) reach options with no Jamf slot. An unknown
  # key, a pair missing "=" or a repeated key refuses the policy. Read after the
  # defaults above so `events=` deltas adjust the real default.
  EXCLUDE_EXTRA=""
  _p10="${10:-}"
  if [[ "$_p10" == *=* ]]; then
    typeset -A _p10_seen=()
    for _p10_pair in ${(s:;:)_p10}; do
      while [[ "$_p10_pair" == [[:space:]]* ]]; do _p10_pair="${_p10_pair#?}"; done
      while [[ "$_p10_pair" == *[[:space:]] ]]; do _p10_pair="${_p10_pair%?}"; done
      [ -n "$_p10_pair" ] || continue
      if [[ "$_p10_pair" != *=* ]]; then
        printf '# culprit: $10: "%s" is not key=value\n' "$(_inert "$_p10_pair")" >&2
        exit 1
      fi
      _p10_key="${_p10_pair%%=*}"
      _p10_val="${_p10_pair#*=}"
      while [[ "$_p10_key" == [[:space:]]* ]]; do _p10_key="${_p10_key#?}"; done
      while [[ "$_p10_key" == *[[:space:]] ]]; do _p10_key="${_p10_key%?}"; done
      if [ -n "${_p10_seen[$_p10_key]:-}" ]; then
        printf '# culprit: $10: duplicate key "%s"\n' "$(_inert "$_p10_key")" >&2
        exit 1
      fi
      _p10_seen[$_p10_key]=1
      case "$_p10_key" in
        exclude) EXCLUDE_EXTRA="$_p10_val" ;;
        events)  _events_apply_list "$_p10_val" '$10: events' ;;
        cmd)     CMD_FILTER="$_p10_val" ;;
        # apps= narrows $4=ALL like naming an app in $4, else ALL_MODE would win.
        apps)    APPS_OVERRIDE="$_p10_val"; ALL_RAW="false" ;;
        *) printf '# culprit: $10: unknown key "%s" — known: exclude, events, cmd, apps\n' "$(_inert "$_p10_key")" >&2; exit 1 ;;
      esac
    done
    unset _p10_seen _p10_pair _p10_key _p10_val
  else
    EXCLUDE_EXTRA="$_p10"
  fi
  unset _p10
  # $7 shapes the report: a comma-separated list of named terms (`marks` narrows,
  # `stable` reformats; orthogonal). A single boolean spelling keeps its old
  # meaning (`true` = destructive).
  DESTR_RAW="false"
  _p7="${(L)7:-}"
  # Split, trimmed, empties dropped, THEN counted, so a trailing comma does not
  # turn `true,` into a list.
  _t7=()
  for _tok in ${(s:,:)_p7}; do
    while [[ "$_tok" == [[:space:]]* ]]; do _tok="${_tok#?}"; done
    while [[ "$_tok" == *[[:space:]] ]]; do _tok="${_tok%?}"; done
    [ -n "$_tok" ] && _t7+=("$_tok")
  done
  for _tok in "${_t7[@]}"; do
    case "$_tok" in
      actions)     READS_RAW="false" ;;     # commands + deletions, no scans
      destructive) DESTR_RAW="true" ;;
      marks)       MARKS_RAW="true" ;;      # everything carrying a mark
      noqueries)   NOQUERIES_RAW="true" ;;  # drop the lines that only read
      stable)      STABLE_RAW="true" ;;     # a report two runs can be diffed on
      *)
        # A single bare word may be a legacy boolean spelling (the same set $9
        # accepts). Inside a list, or if neither a $7 name nor a boolean, it is
        # refused: to_bool() would read a typo as false and silently drop the filter.
        if [ "${#_t7[@]}" -gt 1 ] \
           || [[ "$_tok" != (0|1|true|false|yes|no|non|y|n|on|off|oui|vrai) ]]; then
          printf '# culprit: $7: unknown value "%s" — known: destructive, actions, marks, stable, noqueries\n' "$(_inert "$_tok")" >&2
          exit 1
        fi
        # The trimmed token: `to_bool "true,"` is false.
        DESTR_RAW="$_tok" ;;
    esac
  done
else
  parse_cli_args "$@"
fi

to_bool() {
  # zsh's own ${(L)}, not `tr`: with `tr` unresolvable every option silently
  # turned off.
  case "${(L)1:-}" in
    1|true|yes|y|on|oui|vrai) echo "true";; *) echo "false";;
  esac
}
ONLY_CMDS=$(to_bool "$ONLY_CMDS_RAW")
DEBUG=$(to_bool "$DEBUG_RAW")
DETACH=$(to_bool "${DETACH_RAW:-false}")
# Whole seconds, more than none; a typo is refused, not read as "no limit".
DURATION="${DURATION_RAW:-}"
if [ -n "$DURATION" ]; then
  case "$DURATION" in
    *[!0-9]*) printf '# culprit: --duration takes whole seconds, e.g. --duration 300\n' >&2; exit 1 ;;
  esac
  [ "$DURATION" -gt 0 ] || { printf '# culprit: --duration must be greater than zero\n' >&2; exit 1; }
fi
ALL_MODE=$(to_bool "${ALL_RAW:-false}")
DESTRUCTIVE_ONLY=$(to_bool "${DESTR_RAW:-false}")
# Verbose lifts the noise filter too: one switch.
if [ "$ONLY_CMDS" = "true" ]; then SHOW_NOISE="false"; else SHOW_NOISE="true"; fi
WATCH_FILES=$(to_bool "${FILES_RAW:-false}")
WATCH_READS=$(to_bool "${READS_RAW:-false}")
WATCH_OPENS=$(to_bool "${OPENS_RAW:-false}")
WATCH_TCC=$(to_bool "${TCC_RAW:-true}")
WATCH_BTM=$(to_bool "${BTM_RAW:-true}")
# --destructive-only drops scans, reads, TCC and login-item events: none modifies
# anything. Cut at the source (the parser keeps its own guard).
if [ "$DESTRUCTIVE_ONLY" = "true" ]; then WATCH_READS="false"; WATCH_OPENS="false"; WATCH_TCC="false"; WATCH_BTM="false"; fi
# --no-files means no file events, whatever the flag order.
if [ "$WATCH_FILES" != "true" ]; then WATCH_READS="false"; WATCH_OPENS="false"; fi
# Options reach the parser by environment, so no argv position shifts.
# --mdm: fleet-portable paths ($loggedInUser / $userCache).
MDM=$(to_bool "${MDM_RAW:-false}")
[ "$MDM" = "true" ] && export CULPRIT_MDM=1 || export CULPRIT_MDM=0
# --events tcc: whether tcc_modify is subscribed.
[ "$WATCH_TCC" = "true" ] && export CULPRIT_TCC=1 || export CULPRIT_TCC=0
# --events btm: whether btm_launch_item_add/remove are subscribed.
[ "$WATCH_BTM" = "true" ] && export CULPRIT_BTM=1 || export CULPRIT_BTM=0
# --report: silent capture, one structured report + paste-ready script on stop.
REPORT=$(to_bool "${REPORT_RAW:-false}")
[ "$REPORT" = "true" ] && export CULPRIT_REPORT=1 || export CULPRIT_REPORT=0
# --no-fold: exact per-file deletions instead of the `rm -rf <dir>/*` summary.
NOFOLD=$(to_bool "${NOFOLD_RAW:-false}")
[ "$NOFOLD" = "true" ] && export CULPRIT_NOFOLD=1 || export CULPRIT_NOFOLD=0
# --stable (diffable report) and --marks-only (marked lines only) act at report
# render time; neither changes what is captured.
STABLE=$(to_bool "${STABLE_RAW:-false}")
MARKS_ONLY=$(to_bool "${MARKS_RAW:-false}")
# Refused without --report (they would silently do nothing). The message names
# the interface in use: under Jamf the switch is $5, not a flag.
if [ "$REPORT" != "true" ]; then
  if [ "$JAMF_MODE" = "true" ]; then _needs="set \$5=true"; else _needs="add --report"; fi
  [ "$STABLE" = "true" ] && { printf '# culprit: --stable shapes the report — %s\n' "$_needs" >&2; exit 1; }
  [ "$MARKS_ONLY" = "true" ] && { printf '# culprit: --marks-only shapes the report — %s\n' "$_needs" >&2; exit 1; }
  unset _needs
fi
[ "$STABLE" = "true" ] && export CULPRIT_STABLE=1 || export CULPRIT_STABLE=0
[ "$MARKS_ONLY" = "true" ] && export CULPRIT_MARKS=1 || export CULPRIT_MARKS=0
# --ndjson: the live stream as JSON Lines. With --report the text report goes to
# a file on stop, never onto the stream.
NDJSON=$(to_bool "${NDJSON_RAW:-false}")
[ "$NDJSON" = "true" ] && export CULPRIT_NDJSON=1 || export CULPRIT_NDJSON=0
# --report-file: checked before the run is spent, since a bad path would lose the
# report at the end. Absolute with `:a`, never `:A`: resolving symlinks would
# follow the very link the parser refuses. Refused if non-empty, like --log.
REPORT_OUT=""
if [ -n "${REPORT_FILE_PARAM:-}" ]; then
  if [ "$REPORT" != "true" ]; then
    printf '# culprit: --report-file is where the report goes — add --report\n' >&2; exit 1
  fi
  REPORT_OUT="${REPORT_FILE_PARAM:a}"
  if [ -h "$REPORT_OUT" ] || { [ -e "$REPORT_OUT" ] && [ ! -f "$REPORT_OUT" ]; }; then
    printf '# culprit: --report-file must be a plain file, not a link or a directory: %s\n' "$(_inert "$REPORT_OUT")" >&2; exit 1
  fi
  if [ -s "$REPORT_OUT" ]; then
    printf '# culprit: --report-file %s already holds something — remove it or pick a new path\n' "$(_inert "$REPORT_OUT")" >&2; exit 1
  fi
  if [ ! -d "${REPORT_OUT:h}" ] || [ ! -w "${REPORT_OUT:h}" ]; then
    printf '# culprit: --report-file %s: its directory does not exist or is not writable\n' "$(_inert "$REPORT_OUT")" >&2; exit 1
  fi
fi
# Run once the log is resolved: under --ndjson without --report-file the report
# goes to `<log>.report.txt` (stdout is the stream). Never one of the log's own
# files; `:A` makes /var/log and /private/var/log equal.
_report_out_resolve() {
  [ "$REPORT" = "true" ] || return 0
  [ -z "$REPORT_OUT" ] && [ "$NDJSON" = "true" ] && REPORT_OUT="${LOGFILE:a}.report.txt"
  [ -n "$REPORT_OUT" ] || return 0
  local _o="${REPORT_OUT:A}" _l="${LOGFILE:A}" _s
  for _s in "" .1 .pid .report; do
    if [ "$_o" = "${_l}${_s}" ]; then
      printf '# culprit: --report-file %s is one of the log'\''s own files — pick another path\n' "$(_inert "$REPORT_OUT")" >&2
      exit 1
    fi
  done
  return 0
}
# --no-queries: decided at emit time, so it shapes live output and report alike.
NO_QUERIES=$(to_bool "${NOQUERIES_RAW:-false}")
[ "$NO_QUERIES" = "true" ] && export CULPRIT_NOQUERIES=1 || export CULPRIT_NOQUERIES=0

unsetopt xtrace verbose 2>/dev/null || true

# ---------------------------------------
# Environment
# ---------------------------------------
get_console_user() { /usr/bin/stat -f %Su /dev/console 2>/dev/null || /usr/bin/id -un; }
# An inherited CONSOLE_USER is honoured only if it names a real account: it picks
# the home the parser treats as `~`, and root acts on it.
if [ -n "${CONSOLE_USER:-}" ] && { [[ "$CONSOLE_USER" != [A-Za-z0-9._-]## ]] \
     || ! /usr/bin/id -u -- "$CONSOLE_USER" >/dev/null 2>&1; }; then
  CONSOLE_USER=""
fi
CONSOLE_USER="${CONSOLE_USER:-$(get_console_user)}"
# The console user's home, exported for the parser to match `rm -rf ~/…/*` globs.
# `|| true`: dscl exits 56 when the record is absent (`dscl .` reads the local
# node only, so AD/Entra/Jamf Connect accounts lack it) and `set -e` + pipefail
# would abort before the fallback.
_UHOME=$(/usr/bin/dscl . -read "/Users/${CONSOLE_USER}" NFSHomeDirectory 2>/dev/null | /usr/bin/awk '{print $2}') || true
[ -n "$_UHOME" ] || _UHOME="/Users/${CONSOLE_USER}"
export CULPRIT_HOME="$_UHOME"
# The account's full name, for --mdm (the short name derives from the home
# directory, the full name does not). It can hold spaces, so it travels through
# the environment, taken as a whole line.
_UREAL=$(/usr/bin/dscl . -read "/Users/${CONSOLE_USER}" RealName 2>/dev/null | /usr/bin/tail -1 | /usr/bin/sed 's/^ *//') || true
[ "$_UREAL" = "RealName:" ] && _UREAL=""
export CULPRIT_REALNAME="${_UREAL#RealName: }"

# Python3 detection (the parser needs it). Check xcode-select first to avoid the
# /usr/bin/python3 CLT-install popup.
PYTHON3_BIN=""
_python3_validate() { "$1" -c 'import json,sys' >/dev/null 2>&1 && PYTHON3_BIN="$1" && return 0; return 1; }
_clt=false; /usr/bin/xcode-select -p >/dev/null 2>&1 && _clt=true
if [ "$_clt" = true ] && [ -x /usr/bin/python3 ] && _python3_validate /usr/bin/python3; then :
elif command -v python3 >/dev/null 2>&1; then
  _cand="$(command -v python3)"
  [ "$_cand" != /usr/bin/python3 ] && _python3_validate "$_cand" || true
fi
# sudo resets PATH to secure_path, so a Homebrew python3 is invisible above:
# look in the Homebrew and MacPorts prefixes too.
if [ -z "$PYTHON3_BIN" ]; then
  for _pd in /opt/homebrew/bin /usr/local/bin /opt/local/bin; do
    [ -x "$_pd/python3" ] && _python3_validate "$_pd/python3" && break
  done
  unset _pd
fi
# A group- or world-writable interpreter is noted, not refused: root executes it,
# but refusing would break every CLT-less Mac. Permissions are read from the
# resolved target (symlinks into a Cellar).
if [ -n "$PYTHON3_BIN" ] && [ "$PYTHON3_BIN" != /usr/bin/python3 ]; then
  _pr="${PYTHON3_BIN:A}"
  _pperm="$(/usr/bin/stat -f '%Sp' "$_pr" 2>/dev/null)" || _pperm=""
  _powner="$(/usr/bin/stat -f '%Su' "$_pr" 2>/dev/null)" || _powner=""
  case "$_pperm" in
    ?????w*|????????w*)
      printf '# culprit: note: running %s as root; it is %s and owned by %s,\n' \
             "$_pr" "$_pperm" "${_powner:-?}" >&2
      printf '#   so anyone who can write there chooses what root executes. Install the\n' >&2
      printf '#   Command Line Tools (xcode-select --install) to use /usr/bin/python3.\n' >&2 ;;
  esac
  unset _pr _pperm _powner
fi

# Temp dir + EXIT cleanup. No fallback name: a predictable `/tmp/culprit.<pid>`
# could be pre-created by anyone, and root writes the parser there and executes
# it. mktemp must succeed and hand back a directory we own, mode 700.
CULPRIT_TMPDIR=$(/usr/bin/mktemp -d "/tmp/culprit.${$}.XXXXXX") || {
  printf '# culprit: could not create a private temporary directory in /tmp — stopping\n' >&2; exit 1; }
if [ ! -d "$CULPRIT_TMPDIR" ] || [ -h "$CULPRIT_TMPDIR" ] || [ ! -O "$CULPRIT_TMPDIR" ] \
   || [ "$(/usr/bin/stat -f '%Lp' "$CULPRIT_TMPDIR" 2>/dev/null)" != "700" ]; then
  printf '# culprit: the temporary directory %s is not private to this run — stopping\n' "$CULPRIT_TMPDIR" >&2
  exit 1
fi
# Removes the tmpdir and the pidfile, but never while the watcher is alive: the
# tmpdir path in the parser's argv is the orphan sweep's only handle on it.
_exit_cleanup() {
  if [ -n "${WATCH_PID:-}" ] && /bin/kill -0 "$WATCH_PID" 2>/dev/null; then
    printf '# culprit: the watcher (pid %s) outlived this shell — stop it with: sudo kill %s\n' \
      "$WATCH_PID" "$WATCH_PID" >&2
    return 0
  fi
  /bin/rm -rf "$CULPRIT_TMPDIR" 2>/dev/null || true
  [ -n "${_PIDFILE:-}" ] && /bin/rm -f "$_PIDFILE" 2>/dev/null || true
}
trap '_exit_cleanup' EXIT

# Reclaim what a prior run left behind once its pid is gone: `kill -9` runs no
# trap, so its parser and root eslogger survive, the eslogger holding a scarce
# Endpoint Security client slot. An orphan is identified by the tmpdir path in its
# argv (dots escaped, `pgrep -f` takes a regex), never by a name like "eslogger",
# which would reach another tool's client. Every reclaim is announced.
for _stale in /tmp/culprit.[0-9]*(N/); do
  # The name must be exactly what `mktemp -d "/tmp/culprit.${$}.XXXXXX"` produces
  # and the directory ours. /tmp is world-writable, so a planted directory whose
  # NAME is a regex (`culprit.0|.*|`) would make `pgrep -f` match every process,
  # each then sent `kill -TERM` as root. Never act on what is not ours.
  [[ "${_stale:t}" =~ '^culprit\.[0-9]+\.[A-Za-z0-9]{6}$' ]] || continue
  [ -O "$_stale" ] || continue
  _sp="${${_stale:t}#culprit.}"; _sp="${_sp%%.*}"
  [ "$_sp" = "$$" ] && continue
  /bin/kill -0 "$_sp" 2>/dev/null && continue
  _pat="${_stale//./\\.}/parser\\.py"
  _orph=$(/usr/bin/pgrep -f "$_pat" 2>/dev/null) || _orph=""
  # The eslogger pids that run recorded. Both conditions are needed: the pid must
  # be one we recorded (a name match would reach another tool's ES client) and
  # still be eslogger now (the pid may have been reused).
  if [ -s "${_stale}/pids" ]; then
    while IFS= read -r _ep; do
      [ -n "$_ep" ] || continue
      # `comm=` (the executable), never `args=`, which matches any process that
      # merely mentions eslogger.
      case "$(/bin/ps -o comm= -p "$_ep" 2>/dev/null)" in
        *eslogger*) /bin/kill -TERM "$_ep" 2>/dev/null && _orph="${_orph} ${_ep}" ;;
      esac
    done < "${_stale}/pids"
  fi
  if [ -n "$_orph" ]; then
    for _op in ${=_orph}; do /bin/kill -TERM "$_op" 2>/dev/null || true; done
    /bin/sleep 0.2
    # Judged on every pid: the eslogger client's argv carries no tmpdir path.
    _left=""
    for _op in ${=_orph}; do
      /bin/kill -0 "$_op" 2>/dev/null && _left="${_left} ${_op}"
    done
    if [ -n "$_left" ]; then
      # Could not signal it (non-root vs a root orphan): keep the directory, the
      # only handle a later run has on that orphan.
      printf '# culprit: an orphaned watcher from a killed run is still running — stop it with: sudo kill %s\n' "${_left# }" >&2
      continue
    fi
    printf '# culprit: reclaimed an orphaned watcher left by a killed run (pid %s)\n' "${${_orph//$'\n'/ }# }" >&2
  fi
  /bin/rm -rf "$_stale" 2>/dev/null || true
done
unset _stale _sp _pat _orph _op _ep _left

zmodload zsh/datetime 2>/dev/null && HAVE_ZSH_STRFTIME=true || HAVE_ZSH_STRFTIME=false

SCRIPT_VERSION=$(/usr/bin/head -20 "$0" 2>/dev/null | /usr/bin/grep "^# Version:" | /usr/bin/sed -E 's/^# Version: //' | /usr/bin/head -1) || true
[ -z "$SCRIPT_VERSION" ] && SCRIPT_VERSION="unknown"

if [ -n "$LOG_FILE_PARAM" ]; then
  LOGFILE="$LOG_FILE_PARAM"
  _LOG_EXPLICIT=1     # named: no fallback
else
  LOGFILE="/var/log/culprit-v${SCRIPT_VERSION}.log"
fi
# Is this file one of our logs? Every log opens with its banner (`# Culprit v…`,
# timestamped under -v). An empty or absent file is fair game.
_is_culprit_log() {
  local p="$1" first
  # A symlink is refused first: `-e` follows it, so a dangling or empty-target
  # link would pass as fair game and root would write the capture at its target.
  # World-writable directories make planting one trivial.
  [ -h "$p" ] && return 1
  [ -e "$p" ] || return 0
  [ -s "$p" ] || return 0
  first=$(/usr/bin/head -1 "$p" 2>/dev/null) || return 1
  # Contains the banner (not starts with it): `-v` prefixes a timestamp.
  case "$first" in
    *'# Culprit v'*) return 0 ;;
  esac
  return 1
}

# A directory is a natural thing to type in `$11` or after `--log`: say so early.
if [ -d "$LOGFILE" ]; then
  printf '# culprit: the log path must be a FILE, not a directory: %s\n' "$(_inert "$LOGFILE")" >&2
  printf '#   try:  %s/culprit.log\n' "$(_inert "${LOGFILE%/}")" >&2
  exit 1
fi
# Never onto a file this tool did not write: rotation renames the log to `.1` and
# truncates, so `--log /var/log/install.log` would destroy it. Refused here, not
# left to a fallback; this is the only way Culprit could modify the Mac it watches.
if [ -e "$LOGFILE" ] && [ ! -h "$LOGFILE" ] && [ "$(/usr/bin/id -u)" != "0" ] && [ ! -r "$LOGFILE" ]; then
  # Root's log is 0600: unreadable by a non-root user is unknown, not foreign.
  # Fall through so the root check below gives the accurate message.
  :
elif [ -e "$LOGFILE" ] && ! _is_culprit_log "$LOGFILE"; then
  printf '# culprit: %s exists and was not written by Culprit — refusing to rotate it\n' "$(_inert "$LOGFILE")" >&2
  printf '#   a capture truncates its log and keeps one generation as .1\n' >&2
  printf '#   pick a path of your own:   --log /var/log/culprit-audit.log\n' >&2
  exit 1
fi

# ---------------------------------------
# Apply the [app] / --apps filter to the registry
# ---------------------------------------
# A registry line is `label|team|path|helpers|cli` with comma-split lists, read
# back the same way, so a `|` in a path would shift fields. Refuse before a line
# is built. `comma` adds `,` (for paths and tool names; --apps entries are
# checked without it since `,` is their separator).
_refuse_registry_chars() {
  local what="$1" v="$2" bad='|' desc='"|"'
  [[ "${3:-}" == comma ]] && { bad='|,'; desc='"|", ","'; }
  if [[ "$v" == *[$bad]* || "$v" == *$'\t'* || "$v" == *$'\n'* ]]; then
    printf '# culprit: %s "%s" contains a character the registry cannot carry (%s, TAB or newline)\n' \
      "$what" "$(_inert "$v")" "$desc" >&2
    exit 1
  fi
}
_filter_targets() {
  # Locals declared once: a repeated `local` on a set var prints `var=value`.
  local wanted="$1" line label w
  local -a keep=() want_list
  [ -z "$wanted" ] && return 0
  want_list=("${(@s:,:)wanted}")
  for line in "${TARGET_APPS[@]}"; do
    label="${line%%|*}"
    for w in "${want_list[@]}"; do
      # Trim ALL surrounding whitespace (`${w## }` strips only one space).
      while [[ "$w" == [[:space:]]* ]]; do w="${w#?}"; done
      while [[ "$w" == *[[:space:]] ]]; do w="${w%?}"; done
      if [[ "${label:l}" == "${w:l}" ]]; then keep+=("$line"); break; fi
    done
  done
  # A label that matched nothing is named even when others matched: a scope must
  # not shrink silently.
  local -a missed=()
  local hit l
  for w in "${want_list[@]}"; do
    while [[ "$w" == [[:space:]]* ]]; do w="${w#?}"; done
    while [[ "$w" == *[[:space:]] ]]; do w="${w%?}"; done
    [ -n "$w" ] || continue
    hit=0
    for l in "${keep[@]}"; do [[ "${${l%%|*}:l}" == "${w:l}" ]] && hit=1 && break; done
    (( hit )) || missed+=("$w")
  done
  if (( ${#missed[@]} > 0 && ${#keep[@]} > 0 )); then
    printf '# culprit: no registry app matches %s — watching the rest\n' \
      "$(_inert "${(j:, :)missed}")" >&2
  fi
  if (( ${#keep[@]} == 0 )); then
    printf '# culprit: no registry app matches "%s" — known: %s\n' "$(_inert "$wanted")" \
      "${(j:, :)${TARGET_APPS[@]%%|*}}" >&2
    printf '# culprit: for anything else, pass a bundle path, a bundle id, or the path of a CLI tool (%s)\n' \
      "/opt/homebrew/bin/…" >&2
    exit 1
  fi
  TARGET_APPS=("${keep[@]}")
}
# A privileged helper is typically mode 500/544 root:wheel: not executable by the
# invoking user but by root. Judge on the mode bits, not our own access.
_is_executable_file() {
  local m
  [[ -f "$1" ]] || return 1
  [[ -x "$1" ]] && return 0
  m=$(/usr/bin/stat -f %Lp "$1" 2>/dev/null) || return 1
  [[ "$m" == *[1357]* ]]
}
_registry_has() {
  local l
  for l in "${TARGET_APPS[@]}"; do [[ "${${l%%|*}:l}" == "${1:l}" ]] && return 0; done
  return 1
}
# A bare name that is not a registry label may be a CLI tool (`culprit.sh brew`).
_find_cli() {
  local n="$1" p d
  # `whence -p`, not `command -v`: the latter answers with the builtin name for
  # `log`, `kill`, `time`, `printf`…, though /usr/bin/log exists.
  p=$(whence -p -- "$n" 2>/dev/null) && [[ "$p" == /* && -x "$p" ]] && { print -r -- "$p"; return 0; }
  # sudo resets PATH, dropping the directories that hold third-party tools: look
  # where they install, system directories included.
  for d in /opt/homebrew/bin /usr/local/bin /opt/local/bin /opt/homebrew/sbin /usr/local/sbin \
           /usr/bin /bin /usr/sbin /sbin; do
    [[ -x "$d/$n" ]] && { print -r -- "$d/$n"; return 0; }
  done
  return 1
}
# Target an app by path. A registry entry for that bundle takes precedence;
# otherwise an entry is built on the spot, codesign supplying the Team ID so the
# privileged helper is attributed too. A plain executable (Homebrew/MacPorts tool,
# privileged helper, MDM script) is also accepted.
_target_from_path() {
  local path="${1%/}" label team line b h real cli
  # Absolute without resolving symlinks (`:a`, not `:A`): eslogger reports
  # absolute paths, and a symlinked CLI tool is registered with its target below.
  path="${path:a}"
  _refuse_registry_chars "path" "$path" comma
  if [ -d "$path" ]; then
    # A plain directory is not a bundle: as a path prefix it would match every app in it.
    if [[ "$path" != *.app ]] && [ ! -d "$path/Contents/MacOS" ]; then
      printf '# culprit: not an app bundle: %s (pass the .app itself, or an executable)\n' "$(_inert "$path")" >&2
      exit 1
    fi
    for line in "${TARGET_APPS[@]}"; do
      b="${${line#*|}#*|}"; b="${b%%|*}"
      if [[ -n "$b" && "$b" == "$path" ]]; then TARGET_APPS=("$line"); return 0; fi
    done
    label="${path:t:r}"
    team=$(/usr/bin/codesign -dv --verbose=2 "$path" 2>&1 | /usr/bin/awk -F= '/^TeamIdentifier/{print $2}') || team=""
    [[ "$team" == "not set" ]] && team=""
    TARGET_APPS=("${label}|${team}|${path}||")
    return 0
  fi
  if [ ! -e "$path" ]; then
    printf '# culprit: no such app bundle or executable: %s\n' "$(_inert "$path")" >&2; exit 1
  fi
  # eslogger reports the resolved executable (/opt/homebrew/Cellar/x/1.2/bin/x),
  # not the typed symlink: register both.
  real="${path:A}"
  _refuse_registry_chars "path" "$real" comma
  # A binary the registry knows as an app's helper stays that app. Checked before
  # the executable test: a helper is often mode 500 root:wheel.
  for line in "${TARGET_APPS[@]}"; do
    h="${line#*|}"; h="${h#*|}"; h="${h#*|}"; h="${h%%|*}"   # field 4 = helper paths
    for b in "${(@s:,:)h}"; do
      if [[ -n "$b" && ( "$b" == "$path" || "$b" == "$real" ) ]]; then
        TARGET_APPS=("$line"); return 0
      fi
    done
  done
  if ! _is_executable_file "$real" || [ -z "${path:t}" ]; then
    printf '# culprit: not an executable, and not an .app bundle: %s\n' "$(_inert "$path")" >&2; exit 1
  fi
  label="${path:t}"
  team=$(/usr/bin/codesign -dv --verbose=2 "$real" 2>&1 | /usr/bin/awk -F= '/^TeamIdentifier/{print $2}') || team=""
  [[ "$team" == "not set" ]] && team=""
  cli="$real"
  [[ "$real" != "$path" ]] && cli="${real},${path}"
  # 5th field = CLI paths: matched exactly; its own exec is shown as a command.
  TARGET_APPS=("${label}|${team}|||${cli}")
}

# A dotted argument shaped like a bundle id (`zoom.us`) can also be a literal app
# name (/Applications/zoom.us.app), as can any bare word that is not a label or CLI
# tool. Try the usual install locations; $CULPRIT_HOME, never $HOME (root's under sudo).
_try_app_name() {
  # CULPRIT_APPS_ROOT is honoured only when not root.
  local n="$1" p _root="/Applications"
  [ "$EUID" -ne 0 ] && _root="${CULPRIT_APPS_ROOT:-/Applications}"
  for p in "${_root}/${n}.app" "${_root}/Utilities/${n}.app" "${CULPRIT_HOME}/Applications/${n}.app"; do
    [ -e "$p" ] && { print -r -- "$p"; return 0; }
  done
  return 1
}

# Target an app by bundle ID (reverse-DNS): the path-independent handle a fleet
# keys on. Resolved to the bundle path (Spotlight, or lsappinfo for a running app
# when indexing is off), then handled as a path target.
_target_from_bundle_id() {
  local bid="$1" p asn
  local pat='^[A-Za-z0-9-]+(\.[A-Za-z0-9_-]+)+$'
  local -a matches
  if [[ ! "$bid" =~ $pat ]]; then
    printf '# culprit: not a valid bundle id: %s\n' "$(_inert "$bid")" >&2; exit 1
  fi
  # `|| true` on the lookups: a non-zero exit (mdfind with Spotlight off,
  # lsappinfo with no such app) would abort under `set -e` + pipefail.
  matches=("${(@f)$(/usr/bin/mdfind "kMDItemCFBundleIdentifier == '$bid'" 2>/dev/null)}") || true
  matches=(${matches:#})                       # drop empty lines
  # A clone/backup on a mounted volume must not shadow the real install.
  if (( ${#matches} > 1 )); then
    local -a onvol; onvol=(${matches:#/Volumes/*})
    (( ${#onvol} )) && matches=($onvol)
  fi
  if (( ${#matches} == 0 )); then
    # Spotlight off/unindexed: a RUNNING app still resolves via LaunchServices.
    asn=$(/usr/bin/lsappinfo find "bundleid=$bid" 2>/dev/null | /usr/bin/head -1) || true
    if [ -n "$asn" ]; then
      p=$(/usr/bin/lsappinfo info -only bundlepath "$asn" 2>/dev/null | /usr/bin/awk -F'"' '{print $4}') || true
      [ -n "$p" ] && matches=("$p")
    fi
  fi
  if (( ${#matches} == 0 )); then
    # Not a bundle id after all — try it as a literal app NAME before giving up.
    p=$(_try_app_name "$bid") && matches=("$p")
  fi
  if (( ${#matches} == 0 )); then
    printf '# culprit: no app with bundle id or name %s (Spotlight off? pass the .app path)\n' "$(_inert "$bid")" >&2
    exit 1
  fi
  if (( ${#matches} > 1 )); then
    printf '# culprit: bundle id %s is ambiguous — pass one path:\n' "$(_inert "$bid")" >&2
    local _m; for _m in "${matches[@]}"; do printf '#   %s\n' "$(_inert "$_m")" >&2; done
    exit 1
  fi
  _target_from_path "${matches[1]}"
}

# In ALL mode the registry is kept whole (labels only) and the filter is ignored.
if [ "$ALL_MODE" != "true" ]; then
  if [ -n "$APPS_OVERRIDE" ]; then
    _refuse_registry_chars "--apps entry" "$APPS_OVERRIDE"
    _filter_targets "$APPS_OVERRIDE"
  elif [ -n "$APP_FILTER" ]; then
    _refuse_registry_chars "app" "$APP_FILTER"
    # A bare word is a registry label, then a CLI tool on the PATH; a dotted one
    # is a bundle id, unless a tool by that name exists (`mytool.sh`).
    _cli_hit=""
    case "$APP_FILTER" in
      # A path carries a slash. `*.app` alone is ambiguous (`com.vendor.app` is a
      # bundle ID): a bundle if it exists on disk, otherwise an ID.
      /*|*/*)   _target_from_path "$APP_FILTER" ;;
      *.app)    if [ -e "$APP_FILTER" ]; then _target_from_path "$APP_FILTER"
                else _target_from_bundle_id "$APP_FILTER"; fi ;;
      *.*)      if _cli_hit=$(_find_cli "$APP_FILTER"); then _target_from_path "$_cli_hit"
                else _target_from_bundle_id "$APP_FILTER"; fi ;;   # reverse-DNS = bundle id
      *)        if ! _registry_has "$APP_FILTER" && _cli_hit=$(_find_cli "$APP_FILTER"); then
                  _target_from_path "$_cli_hit"
                # A bare word that is neither label nor tool may be a plain app
                # name: /Applications/<name>.app.
                elif ! _registry_has "$APP_FILTER" && _cli_hit=$(_try_app_name "$APP_FILTER"); then
                  _target_from_path "$_cli_hit"
                else _filter_targets "$APP_FILTER"; fi ;;
    esac
    unset _cli_hit
  fi
fi

# ---------------------------------------
# Exact bundle identifiers, for tcc_modify rule (a)
# ---------------------------------------
# TARGET_APPS is final here. A TCC identity of type bundle_id must match a
# target's real CFBundleIdentifier, never its app name ("com.evil.OnyX" must not
# attribute to OnyX). Read from each bundle's Info.plist; an unreadable id
# contributes nothing, and a CLI target has none. Each id carries its label so a
# multi-target run reports which app the grant belongs to.
typeset -a _bundle_ids
for _bt in "${TARGET_APPS[@]}"; do
  _blbl="${_bt%%|*}"
  _bpath="${${_bt#*|}#*|}"; _bpath="${_bpath%%|*}"
  [ -n "$_bpath" ] || continue
  _bid=$(/usr/bin/plutil -extract CFBundleIdentifier raw -o - "${_bpath}/Contents/Info.plist" 2>/dev/null) || continue
  # Defensive: a label or id carrying the delimiters would corrupt its neighbours.
  [[ -n "$_bid" && "$_blbl" != *$'\t'* && "$_blbl" != *$'\n'* && "$_bid" != *$'\t'* && "$_bid" != *$'\n'* ]] && \
    _bundle_ids+=("${_blbl}"$'\t'"${_bid}")
done
export CULPRIT_TARGET_BUNDLE_IDS="${(pj:\n:)_bundle_ids}"
unset _bundle_ids _bt _blbl _bpath _bid

# Each event type is appended behind the option that needs it; eslogger streams
# it whether or not a line is printed. clone and link ride with unlink/rename
# (where did this file come from; a persistence item can be copied into place).
# `copyfile` is absent: macOS 26 lists it but emits none. setmode/setowner/
# setflags/setacl and deleteextattr cover the API forms of `chmod u+s` and
# `xattr -d com.apple.quarantine`, which fire no exec. setextattr is not
# subscribed: the value is not in the event, so nothing could replay it.
[ "$WATCH_FILES" = "true" ] && EVENT_TYPES+=(unlink rename clone link setmode setowner setflags setacl deleteextattr)
# readdir shows how an app found its files; on by default, --no-reads drops it.
[ "$WATCH_READS" = "true" ] && EVENT_TYPES+=(readdir)
# open shows which files (hence type) were read. Opt-in: it fires on every file
# access, so it is meant for a single target.
[ "$WATCH_OPENS" = "true" ] && EVENT_TYPES+=(open)
# tcc_modify: a privacy grant or revoke (Settings UI, `tccutil`, MDM profile)
# touches no file and runs no command; tccd's event is the only record. Low
# volume, on by default. macOS 26+ only: the preflight below drops it elsewhere.
[ "$WATCH_TCC" = "true" ] && EVENT_TYPES+=(tcc_modify)
# btm_launch_item_add/remove: a login item added or removed (System Settings,
# `SMAppService`, MDM agent) touches no file and runs no command we catch;
# backgroundtaskmanagementd's event is the only record. Low volume, on by default;
# present since macOS 13.
[ "$WATCH_BTM" = "true" ] && EVENT_TYPES+=(btm_launch_item_add btm_launch_item_remove)
# exit separates a wait from a command still running, so `sleep` lines do not
# charge a slow command's run time to the pause after it. Never printed; only
# --report emits sleeps, so only --report subscribes.
[ "$REPORT" = "true" ] && EVENT_TYPES+=(exit)
# Preflight against what this macOS supports: eslogger refuses the whole
# subscription if one name is unknown. `--list-events` needs no root and creates
# no ES client. A dropped type is announced; a missing `exec` is fatal.
if _avail="$(/usr/bin/eslogger --list-events 2>/dev/null)" && [ -n "$_avail" ]; then
  typeset -a _keep=() _gone=()
  for _t in "${EVENT_TYPES[@]}"; do
    if print -r -- "$_avail" | /usr/bin/grep -qx -- "$_t"; then _keep+=("$_t"); else _gone+=("$_t"); fi
  done
  if [ "${#_gone[@]}" -gt 0 ]; then
    printf '# culprit: this macOS does not offer: %s\n' "${(j:, :)_gone}" >&2
    printf '#   eslogger refuses the whole subscription over one unknown name, so they are\n' >&2
    printf '#   dropped and the capture continues WITHOUT them. Coverage is reduced.\n' >&2
    # printf+exit inline, not _fatal: that helper is defined further down.
    if [ "${#_keep[@]}" -eq 0 ]; then
      printf '# culprit: no event type left to subscribe to.\n' >&2; exit 1
    fi
    case "${_keep[*]}" in
      *exec*) ;;
      *) printf '# culprit: exec is unavailable — there is nothing to attribute.\n' >&2; exit 1 ;;
    esac
    EVENT_TYPES=("${_keep[@]}")
  fi
fi

# Merge default + user excludes (ALL mode) into one comma-separated string.
_EXCLUDES_CSV="${(j:,:)DEFAULT_EXCLUDES}"
[ -n "${EXCLUDE_EXTRA:-}" ] && _EXCLUDES_CSV="${_EXCLUDES_CSV},${EXCLUDE_EXTRA}"

# ---------------------------------------
# Utilities & logging
# ---------------------------------------
get_timestamp() {
  if [ "$HAVE_ZSH_STRFTIME" = "true" ]; then local _t; strftime -s _t '%Y-%m-%d %H:%M:%S' "$EPOCHSECONDS"; printf '%s' "$_t"
  else /bin/date '+%Y-%m-%d %H:%M:%S'; fi
}

# --ndjson "ts" for lines log_line wraps itself: ISO 8601 UTC with milliseconds,
# like the parser's ts_iso. `date` has no %N, so ms come from EPOCHREALTIME
# (zsh/datetime), else .000.
get_timestamp_utc() {
  if [ "$HAVE_ZSH_STRFTIME" = "true" ] && [ -n "${EPOCHREALTIME:-}" ]; then
    local _t _ms="${EPOCHREALTIME#*.}"
    _t=$(/bin/date -u -r "${EPOCHREALTIME%.*}" '+%Y-%m-%dT%H:%M:%S')
    printf '%s.%sZ' "$_t" "${_ms[1,3]}"
  else
    /bin/date -u '+%Y-%m-%dT%H:%M:%S.000Z'
  fi
}

# Startup/shutdown prose: stderr under --ndjson (stdout is JSON Lines only).
_say() {
  if [ "${NDJSON:-false}" = "true" ]; then printf "$@" >&2; else printf "$@"; fi
}

# For the static strings log_line wraps into `"msg"` (untrusted paths go through
# the parser's json.dumps): escape backslash, quote and the whitespace controls.
_json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/\\r}"
  s="${s//$'\t'/\\t}"
  # Any other control byte is invalid raw in JSON; escape per character, only
  # when one is present.
  if [[ "$s" == *[[:cntrl:]]* ]]; then
    # zsh counts some characters above U+FFFF as control: `\u%04x` of those has
    # five digits. Only C0/C1/DEL need the escape.
    local out="" c i u
    for (( i = 1; i <= ${#s}; i++ )); do
      c="${s[i]}"
      if [[ "$c" == [[:cntrl:]] ]]; then
        u="$(printf '%04x' "'$c")"
        if (( ${#u} > 4 )); then out+="$c"; else out+="\\u$u"; fi
      else out+="$c"; fi
    done
    s="$out"
  fi
  printf '%s' "$s"
}

# Remove only the directories the probe created, deepest up to the topmost one
# that did not exist; `rmdir` refuses non-empty ones, so nothing pre-existing is
# reached.
_undo_probe_dirs() {
  local _d="$1" _top="$2" _c="$1"
  [ -n "$_top" ] || return 0
  while [ -n "$_c" ] && [ "$_c" != "/" ] && [ "$_c" != "." ]; do
    /bin/rmdir "$_c" 2>/dev/null || break
    [ "$_c" = "$_top" ] && break
    _c="$(/usr/bin/dirname "$_c")"
  done
  return 0
}
# What a root write into <p> must be able to trust, said when it cannot:
#  - an existing <p> is a plain file of ours with one link (else a pre-created
#    file would receive the root capture, `⚠ secret` lines included).
#  - <p>.1, the rotation target, is a plain file or absent (`mv -f` into a
#    directory or link would move the previous capture inside it).
#  - every directory up from the resolved parent belongs to root, this run or the
#    sudo user, and only a sticky one (/tmp, /Users/Shared) is writable by others
#    (else the log could be swapped for a link between two appends).
_log_path_safe() {
  local p="$1" d o m _why=""
  if [ -h "$p" ]; then _why="it is a symbolic link"
  elif [ -e "$p" ]; then
    if [ ! -f "$p" ]; then _why="it is not a plain file"
    elif [ ! -O "$p" ]; then _why="it belongs to another user"
    elif [ "$(/usr/bin/stat -f %l "$p" 2>/dev/null)" != 1 ]; then _why="it has another hard link"
    fi
  fi
  if [ -z "$_why" ] && { [ -h "${p}.1" ] || { [ -e "${p}.1" ] && [ ! -f "${p}.1" ]; }; }; then
    _why="${p:t}.1, where the previous capture is kept, is not a plain file"
  fi
  d="${p:h:A}"
  while [ -z "$_why" ]; do
    o="" m=""
    read -r o m <<< "$(/usr/bin/stat -f '%u %p' "$d" 2>/dev/null)"
    case "$o" in
      0|"$EUID"|"${SUDO_UID:-0}") ;;
      *) _why="$d belongs to another user"; break ;;
    esac
    if (( (8#${m:-0} & 8#022) && !(8#${m:-0} & 8#1000) )); then
      _why="$d is writable by others"; break
    fi
    [ "$d" = "/" ] && break
    d="${d:h}"
  done
  [ -z "$_why" ] && return 0
  printf '# culprit: not writing the log to %s — %s\n' "$(_inert "$p")" "$(_inert "$_why")" >&2
  return 1
}
_can_log_to() {
  local p="$1" _existed=1
  [ -e "$p" ] && [ ! -f "$p" ] && return 1
  _is_culprit_log "$p" || return 1
  # The probe creates the directory when it must and removes only what it created
  # (`rmdir -p` would also delete pre-existing empty parents).
  local _d="$(/usr/bin/dirname "$p")" _dtop="" _a
  if [ ! -d "$_d" ]; then
    _a="$_d"
    while [ -n "$_a" ] && [ "$_a" != "/" ] && [ "$_a" != "." ] && [ ! -d "$_a" ]; do
      _dtop="$_a"; _a="$(/usr/bin/dirname "$_a")"
    done
    /bin/mkdir -p "$_d" 2>/dev/null || _dtop=""
  fi
  _log_path_safe "$p" || { _undo_probe_dirs "$_d" "$_dtop"; return 1; }
  [ -e "$p" ] || _existed=0
  ( : >> "$p" ) 2>/dev/null || { _undo_probe_dirs "$_d" "$_dtop"; return 1; }
  # A probe leaves nothing behind.
  [ "$_existed" = 0 ] && /bin/rm -f "$p" 2>/dev/null
  _undo_probe_dirs "$_d" "$_dtop"
  return 0
}
# Candidate log paths, in order. A named path (--log, $11, or one a detaching
# parent resolved) is the only candidate; only the default falls back, /var/log
# before /tmp (macOS empties /tmp at boot). An array, so a newline in a path
# cannot split into two candidates.
_log_candidates() {
  reply=("$1")
  [ "${_LOG_EXPLICIT:-0}" = 1 ] || reply+=("/var/log/${1:t}" "/tmp/${1:t}")
}
# Where the log would land, without rotating or truncating: the --detach parent
# needs the answer before it forks.
_dry_logfile() {
  local want="$1" p
  local -a reply
  _log_candidates "$want"
  for p in "${reply[@]}"; do
    _can_log_to "$p" && { print -r -- "$p"; return 0; }
  done
  return 1
}
_try_logfile() {
  local p="$1"
  # The one place the tool could touch something not its own residue: refuse
  # anything that is not already a Culprit log, and anything but a regular file
  # (`-s` is true for a directory). One previous generation is kept as <log>.1.
  _is_culprit_log "$p" || return 1
  [ -e "$p" ] && [ ! -f "$p" ] && return 1
  _log_path_safe "$p" || return 1
  if [ -f "$p" ] && [ -s "$p" ]; then /bin/mv -f "$p" "${p}.1" 2>/dev/null || true; fi
  # umask, not chmod afterwards: a capture holds paths and command lines from the
  # whole Mac, and create-then-chmod leaves a world-readable window. The rotated
  # `.1` keeps the 0600 mode.
  ( umask 077; : > "$p" ) 2>/dev/null
}
prepare_logfile() {
  local want="$1" p
  local -a reply
  /bin/mkdir -p "$(/usr/bin/dirname "$want")" 2>/dev/null || true
  _log_candidates "$want"
  for p in "${reply[@]}"; do
    if _try_logfile "$p"; then echo "$p"; return 0; fi
  done
  # No candidate, no answer: the caller reports it and stops.
  return 1
}

# Core log. ONLY_CMDS keeps just the "Cmd: …" payload (Jamf/Console-friendly).
log_line() {
  # The timestamp is computed only where printed (ONLY_CMDS never uses it).
  local msg="$1" ts
  # --ndjson: every line must be one JSON object whatever -v/-q says. A payload
  # already a JSON object (built by the parser) passes through; any other line
  # (banner, warning, DEBUG notice) is wrapped here as an info object.
  if [ "${NDJSON:-false}" = "true" ]; then
    local nout
    case "$msg" in Cmd:\ *) nout="${msg#Cmd: }";; *) return 0;; esac
    [ -z "$nout" ] && return 0
    case "$nout" in
      \{*) ;;
      *) nout="{\"type\":\"info\",\"ts\":\"$(get_timestamp_utc)\",\"msg\":\"$(_json_escape "$nout")\"}" ;;
    esac
    printf "%s\n" "$nout" 2>/dev/null || true
    printf "%s\n" "$nout" >> "$LOGFILE" 2>/dev/null || true
    /usr/bin/logger -t "culprit" -- "$nout" 2>/dev/null || true
    return 0
  fi
  # A report spacer: a blank line in every mode, never stamped or sent to syslog.
  if [ "$msg" = "Cmd: " ]; then
    printf "\n" 2>/dev/null || true
    printf "\n" >> "$LOGFILE" 2>/dev/null || true
    return 0
  fi
  if [ "${ONLY_CMDS:-false}" = "true" ]; then
    local out
    case "$msg" in Cmd:\ *) out="${msg#Cmd: }";; *) return 0;; esac
    # stdout may vanish with the terminal; a dead tty must not take the watcher down.
    printf "%s\n" "$out" 2>/dev/null || true
    printf "%s\n" "$out" >> "$LOGFILE" 2>/dev/null || true
    # Guarded: a non-zero `logger` would kill the script under `set -e`.
    /usr/bin/logger -t "culprit" -- "$out" 2>/dev/null || true
    return 0
  fi
  ts="$(get_timestamp)"
  printf "[%s] %s\n" "$ts" "$msg" 2>/dev/null || true
  printf "[%s] %s\n" "$ts" "$msg" >> "$LOGFILE" 2>/dev/null || true
  /usr/bin/logger -t "culprit" -- "$msg" 2>/dev/null || true
}

# ---------------------------------------
# The Python parser (written to a temp file — stdin is the eslogger stream)
# ---------------------------------------
# Attribution: an exec is credited to a target app when the acting process, its
# parent (ppid) or its responsible process is already tracked, or when the new
# image itself matches a target (Team ID / bundle path), which also seeds tracking
# for that app and its privileged helper. Field extraction is defensive
# (audit_token as dict{pid} or a list with pid at index 5): eslogger's JSON shape
# varies by macOS.
PARSER="$CULPRIT_TMPDIR/parser.py"
/bin/cat > "$PARSER" <<'PY'
import sys, json, time, shlex, re, os, math, signal, stat, functools, tempfile
import urllib.parse

# One file, read top to bottom in processing order; each section below is framed.

# ============================================================================
# RUNTIME CONTEXT — what the shell handed over
# ============================================================================

# The console user's home (CULPRIT_HOME), so `rm -rf ~/Library/Biome/*` globs match absolute paths; empty if unknown.
HOME = os.environ.get("CULPRIT_HOME", "")

# Culprit's own pid: dir_state() reads must not make the parser appear as an actor in its own output.
SELF_PID = os.getpid()

# ============================================================================
# --mdm — REWRITING THIS MAC'S IDENTITY OUT OF THE OUTPUT
# ============================================================================

# --mdm: rewrite user-specific paths into fleet-portable ones. /Users/<me>/ and ~/ become
# /Users/$loggedInUser/; the per-user /var/folders/<a>/<b>/{0,C,T}/ roots become
# $userDir/$userCache/$userTemp (defined in the header via getconf).
MDM = os.environ.get("CULPRIT_MDM") == "1"
# The bare folder still counts: a boundary lookahead, not a required trailing slash.
_MDM_FOLDERS_RE = re.compile(r'(?:/private)?/var/folders/[^/]+/[^/]+/([0CT])(?=[/\s"\']|$)')
_MDM_VAR = {"0": "$userDir", "C": "$userCache", "T": "$userTemp"}
mdm_noted = False

# Only the variables --mdm introduces may force a single-quoted segment open (re-quoting any `$`
# would break captured awk programs like '{print $3}'). Every segment is matched and the callback
# decides, so the scan never pairs one path's closing quote with the next one's opening quote.
_SQ_SEG_RE = re.compile(r"'([^']*)'")
_MDM_VAR_RE = re.compile(r'\$(?:loggedInUser|userDir|userCache|userTemp)')
# Everything double quotes would still interpret is escaped on promotion, so a path holding
# backticks or `$` cannot become a command substitution in a root fleet script.
_MDM_DQ_ESC = re.compile(r'([\\"`$])')
def _mdm_dq(seg):
    # Escape the segment, then restore the --mdm variables untouched.
    out, last = [], 0
    for m in _MDM_VAR_RE.finditer(seg):
        out.append(_MDM_DQ_ESC.sub(r'\\\1', seg[last:m.start()]))
        out.append(m.group(0))
        last = m.end()
    out.append(_MDM_DQ_ESC.sub(r'\\\1', seg[last:]))
    return '"%s"' % "".join(out)

# An ANSI-C `$'…'` argument is matched whole, first; a --mdm variable is spliced out between two
# `$'…'` halves (raising it to double quotes would give a `$"…"` locale string, `\n` not decoded).
_SQ_OR_ANSI_RE = re.compile(r"\$'((?:[^'\\]|\\.)*)'|'([^']*)'")
def _mdm_ansi(body):
    out, last = [], 0
    for m in _MDM_VAR_RE.finditer(body):
        if m.start() > last: out.append("$'%s'" % body[last:m.start()])
        out.append('"%s"' % m.group(0))
        last = m.end()
    if last < len(body): out.append("$'%s'" % body[last:])
    return "".join(out)
def mdm_quotes(s):
    def _seg(m):
        if m.group(1) is not None:
            return _mdm_ansi(m.group(1)) if _MDM_VAR_RE.search(m.group(1)) else m.group(0)
        return _mdm_dq(m.group(2)) if _MDM_VAR_RE.search(m.group(2)) else m.group(0)
    return _SQ_OR_ANSI_RE.sub(_seg, s)

# This Mac's short user NAME, rewritten only where a command takes a user (`-u`/`-U <user>`, or the
# operand of a command in the list), never as a bare word: `admin` or `test` would corrupt arguments.
_MDM_USER = HOME.rsplit("/", 1)[-1] if HOME.startswith("/Users/") else ""
# The directory-service full name is rewritten too, longest first.
_MDM_REALNAME = os.environ.get("CULPRIT_REALNAME", "")
_MDM_NAMES = sorted((n for n in (_MDM_USER, _MDM_REALNAME) if n), key=len, reverse=True)
_MDM_USER_CMDS = ("id", "su", "groups", "chown", "chgrp", "logname")
_MDM_USER_RES = []
for _n in _MDM_NAMES:
    # Case-insensitive; the quotes are in the pattern because a name holding a space arrives quoted.
    _u = "['\"]?" + re.escape(_n) + "['\"]?"
    _MDM_USER_RES += [
        # `pkill -U ard`, `sudo -u ard`, `killall -u ard`
        re.compile(r'(?<![\w-])(-[uU]\s+)' + _u + r'(?![\w.-])', re.I),
        # the command's own operand, flags skipped, absolute binary path accepted
        re.compile(r'(?<![\w./-])((?:/\S+/)?(?:' + "|".join(_MDM_USER_CMDS) +
                   r')(?:\s+-\S+)*\s+)' + _u + r'(?![\w.-])', re.I),
    ]
_MDM_USER_RES = tuple(_MDM_USER_RES)

# A `$'…'` segment, walked like _SH_WALK_RE; the escapes shq writes for whitespace or `'`.
_MDM_ANSI_SEG_RE = re.compile(r"""'[^']*'|"(?:[^"\\]|\\.)*"|\$'(?:[^'\\]|\\.)*'""", re.S)
_MDM_ANSI_B = r'(?=[/\s"\']|\\[ntrvf]|\\x(?:0[9a-dA-D]|1[c-fC-F]|27)|$)'
_MDM_FOLDERS_ANSI_RE = re.compile(r'(?:/private)?/var/folders/[^/]+/[^/]+/([0CT])' + _MDM_ANSI_B)
def _mdm_ansi_paths(seg):
    if not seg.startswith("$'"): return seg
    if HOME: seg = re.sub(re.escape(HOME) + _MDM_ANSI_B, "/Users/$loggedInUser", seg)
    return _MDM_FOLDERS_ANSI_RE.sub(lambda m: _MDM_VAR[m.group(1)], seg)

def mdm_rewrite(s):
    if not MDM: return s
    # The bare home still counts (bounded, so /Users/ardvark is left alone). Inside `$'…'` the
    # boundary can also be an escape such as `\n`.
    s = _MDM_ANSI_SEG_RE.sub(lambda m: _mdm_ansi_paths(m.group(0)), s)
    if HOME: s = re.sub(re.escape(HOME) + r'(?=[/\s"\']|$)', "/Users/$loggedInUser", s)
    s = s.replace("~/", "/Users/$loggedInUser/")
    s = _MDM_FOLDERS_RE.sub(lambda m: _MDM_VAR[m.group(1)], s)
    # After the paths, so /Users/<me> is already a variable.
    for _rx in _MDM_USER_RES: s = _rx.sub(r'\1$loggedInUser', s)
    # A single-quoted path now holding a variable is switched to double quotes.
    s = mdm_quotes(s)
    return s

# The resolver lines --mdm output depends on, kept as data so --report emits the same block (_render_lines).
_MDM_HEADER = (
    "# NOTE: --mdm — define these once at the top of your script, then every command below deploys on any Mac:",
    "#   loggedInUser=$(/usr/bin/stat -f%Su /dev/console)",
    "#   userDir=$(/usr/bin/sudo -u \"$loggedInUser\" /usr/bin/getconf DARWIN_USER_DIR)",
    "#   userCache=$(/usr/bin/sudo -u \"$loggedInUser\" /usr/bin/getconf DARWIN_USER_CACHE_DIR)",
    "#   userTemp=$(/usr/bin/sudo -u \"$loggedInUser\" /usr/bin/getconf DARWIN_USER_TEMP_DIR)",
)

# The same resolvers as live code, for the report's script. With nobody at the console the script says so and exits 0.
def _mdm_script_header(cmds):
    _body = "\n".join(cmds)
    _vars = [v for v in ("userDir", "userCache", "userTemp") if "$" + v in _body]
    if not _vars and "$loggedInUser" not in _body: return []
    _hdr = ["# --mdm: resolved on the Mac that runs this script",
            _MDM_HEADER[1][4:],
            'case "$loggedInUser" in ""|root|loginwindow|_mbsetupuser) '
            'echo "no user logged in — nothing to do"; exit 0;; esac']
    for _l in _MDM_HEADER[2:]:
        if _l[4:].split("=", 1)[0] in _vars: _hdr.append(_l[4:])
    return _hdr

def mdm_header():
    global mdm_noted
    if not MDM or mdm_noted: return
    mdm_noted = True
    for _l in _MDM_HEADER: out("C\t" + _l)

# ============================================================================
# INVOCATION — the argv, the targets, and the shape of the output
# ============================================================================

# argv: debug all_mode destructive_only show_noise excludes_csv cmd_csv
#       files reads opens target...
argv = sys.argv[1:]
DEBUG = len(argv) > 0 and argv[0] == "1"
ALL_MODE = len(argv) > 1 and argv[1] == "1"
DESTRUCTIVE_ONLY = len(argv) > 2 and argv[2] == "1"
SHOW_NOISE = len(argv) > 3 and argv[3] == "1"
EXCLUDES = [e.strip().lower() for e in (argv[4].split(",") if len(argv) > 4 else []) if e.strip()]
# --cmd: name the command directly rather than rely on it surviving the filters.
ONLY_CMDS_SET = set(c.strip() for c in (argv[5].split(",") if len(argv) > 5 else []) if c.strip())
WATCH_FILES = len(argv) > 6 and argv[6] == "1"
WATCH_READS = len(argv) > 7 and argv[7] == "1"
WATCH_OPENS = len(argv) > 8 and argv[8] == "1"
# By environment, not argv: the argv positions above are fixed. Defaults to on; off for CULPRIT_TCC=0
# (--events -tcc, --destructive-only).
WATCH_TCC = os.environ.get("CULPRIT_TCC", "1") != "0"
# Same, for btm_launch_item_add/remove.
WATCH_BTM = os.environ.get("CULPRIT_BTM", "1") != "0"
# tcc_modify rule (a): exact CFBundleIdentifier per target, read from each bundle's Info.plist, one
# "label\tid" pair per line; never derived from the app name. Empty with no bundle target.
TARGET_BUNDLE_IDS = {}
for _bl in os.environ.get("CULPRIT_TARGET_BUNDLE_IDS", "").split("\n"):
    if "\t" not in _bl: continue
    _blbl, _bid = _bl.split("\t", 1)
    if _blbl and _bid: TARGET_BUNDLE_IDS[_bid] = _blbl
targets = []
for t in argv[9:]:
    p = t.split("\t")
    while len(p) < 5:
        p.append("")
    # "cli" = a single EXECUTABLE target, matched by exact path (resolved binary and symlink); its own
    # exec IS the command worth showing. Trailing `/` stripped so the boundary tests see the bundle.
    targets.append({"label": p[0], "team": p[1],
                    "bundle": p[2].rstrip("/") if len(p[2]) > 1 else p[2],
                    "helpers": set(h for h in p[3].split(",") if h),
                    "cli": set(c for c in p[4].split(",") if c)})

# SOLO: one target, not ALL mode. The `# <app> ran:` header is dropped, leaving a bare copy-pasteable
# command list; a destructive command keeps a `# ⚠` marker.
SOLO = (not ALL_MODE) and len(targets) == 1

# ============================================================================
# READING THE EVENT — eslogger's JSON, defensively
# ============================================================================
# The shape varies by macOS release, so every accessor answers "" or None rather than raising.
# Nothing here judges; it only reads.

# App executables live in <bundle>.app/Contents/MacOS/, but helpers nest their own bundle: credit the
# OUTERMOST .app (the one launched), not "Code Helper".
_APP_EXE_RE = re.compile(r'\.app/Contents/MacOS/')
_APP_RE = re.compile(r'/([^/]+)\.app/')
def app_bundle_name(path):
    # ANY executable inside a bundle belongs to that app (naming only; the app's own image stays strict).
    if not path: return ""
    m = _APP_RE.search(path)
    return m.group(1) if m else ""

def is_excluded(path, team):
    low = (path or "").lower()
    for e in EXCLUDES:
        if e and (e in low or e == (team or "").lower()):
            return True
    return False

def audit_pid(tok):
    if isinstance(tok, dict):
        for k in ("pid", "PID"):
            if k in tok:
                try: return int(tok[k])
                except Exception: pass
    if isinstance(tok, list) and len(tok) >= 6:   # audit_token_t: pid at index 5
        try: return int(tok[5])
        except Exception: pass
    return None

# The pid's generation: (pid, pidversion) names one process image. A dict key, or index 7 of the raw
# audit_token_t (pid 5, asid 6, pidversion 7); None when absent, never inferred.
def audit_pidver(tok):
    if isinstance(tok, dict):
        for k in ("pidversion", "pid_version"):
            if k in tok:
                try: return int(tok[k])
                except Exception: pass
    if isinstance(tok, list) and len(tok) >= 8:
        try: return int(tok[7])
        except Exception: pass
    return None

def proc_actor(proc):
    # (pid, pidversion) of a process node, for --ndjson's pid/pidver.
    if not isinstance(proc, dict): return (None, None)
    return (proc_pid(proc), audit_pidver(proc.get("audit_token")))

def proc_pid(proc):
    if not isinstance(proc, dict): return None
    p = audit_pid(proc.get("audit_token"))
    if p is not None: return p
    for k in ("pid", "PID"):
        if k in proc:
            try: return int(proc[k])
            except Exception: pass
    return None

def field(proc, *keys):
    if not isinstance(proc, dict): return ""
    for k in keys:
        v = proc.get(k)
        if isinstance(v, str) and v: return v
    return ""

def exe_path(proc):
    if not isinstance(proc, dict): return ""
    ex = proc.get("executable")
    if isinstance(ex, dict):
        # Return the value, not the container: a non-string `path` would raise downstream, and a parser crash
        # loses the whole in-memory report.
        _p = ex.get("path", "")
        return _p if isinstance(_p, str) else ""
    if isinstance(ex, str): return ex
    return ""

def exec_args(execu, tgt):
    # args live under event.exec.args or event.exec.target.args depending on macOS version. Every ELEMENT
    # must be a string; a malformed argv is not repaired (that would fabricate a command line), the exec
    # reports its executable alone.
    for a in (execu.get("args"), tgt.get("args") if isinstance(tgt, dict) else None):
        if isinstance(a, list) and a and all(isinstance(x, str) for x in a):
            return a
    return []

# ============================================================================
# ATTRIBUTION — which actor is behind this exec
# ============================================================================
# Which actor is behind this exec. A registry label wins; failing that, ALL mode names the third-party
# image. WHO (resolve_app) and whether the exec is that actor's own image (is_app_image) stay symmetric.

def match_target(team, path, sid=""):
    # Exact paths first (CLI, bundle prefix, helper), Team ID only after: two apps of one vendor share one.
    for t in targets:
        if path and path in t["cli"]: return t["label"]
        # The bundle itself or a path INSIDE it, never a bare prefix (OnyX.app.bak is not OnyX).
        if t["bundle"] and path and (path == t["bundle"] or path.startswith(t["bundle"] + "/")):
            return t["label"]
        if path and path in t["helpers"]: return t["label"]
    # Team ID only: an ad-hoc binary has no team_id, and its signing_id is an arbitrary string.
    cands = [t for t in targets if t["team"] and team and team == t["team"]]
    if len(cands) <= 1: return cands[0]["label"] if cands else None
    # Several targets share this Team ID: compare the signing_id with each target's real CFBundleIdentifier
    # (plus an optional ".suffix" for a helper); still ambiguous means no attribution.
    hits = []
    for t in cands:
        for bid, lbl in TARGET_BUNDLE_IDS.items():
            if lbl == t["label"] and sid and (sid == bid or sid.startswith(bid + ".")):
                hits.append(t["label"])
                break
    return hits[0] if len(hits) == 1 else None

def match_proc(proc, path):
    # match_target for a process; signing_id only separates targets sharing a Team ID.
    return match_target(field(proc, "team_id"), path, field(proc, "signing_id"))

def is_cli_target(path):
    return bool(path) and any(path in t["cli"] for t in targets)

def is_cli_launch(path, script=""):
    # The targeted CLI tool starting, emitted as the command it is. Its parent is the launcher (a terminal's
    # shell), never in the tool's subtree: tracking it would credit the tool with everything typed after.
    return is_cli_target(path) or (bool(script) and is_cli_target(script))

def is_platform(proc):
    if not isinstance(proc, dict): return False
    v = proc.get("is_platform_binary")
    if isinstance(v, bool): return v
    if isinstance(v, str): return v.strip().lower() in ("1", "true", "yes")
    # Fallback when the field is absent: Apple binaries live under these roots.
    p = exe_path(proc)
    # /Applications (also matches /System/Applications) holds Apple's bundled GUI apps, which stay
    # attributable actors rather than platform noise.
    if "/Applications/" in p: return False
    # Same Apple criterion as everywhere: is_apple_path(), which resolves the real path and strips
    # /System/Volumes/Data before judging (defined later, looked up at call time). /usr/local and /opt
    # stay third-party.
    return is_apple_path(p)

# Third-party code OUTSIDE any .app bundle. An SMJobBless helper is installed here and started by
# launchd, with no bundle name and no tracked ancestor; without this ALL mode misses every root helper
# command. Matched as a SUBSTRING: the same layout exists per user under ~/Library/Application Support.
_OUT_OF_BUNDLE_DIRS = ("/Library/PrivilegedHelperTools/", "/Library/Application Support/")
# Root lives HERE only: SMJobBless installs into this directory.
_PRIVILEGED_DIR = "/Library/PrivilegedHelperTools/"

# Developer toolchain: /usr/bin/python3 resolves into CommandLineTools' Python.app, so any script would
# surface as an app "Python". These may run commands under a real app's label but cannot become a
# label themselves. Restored by -v.
_TOOLCHAIN_DIRS = ("/Library/Developer/", "/Applications/Xcode.app/")

# A shebang script does not exec itself: the kernel execs its interpreter and the tool's own path
# appears only in argv (`/bin/bash /opt/homebrew/bin/brew install wget`). Judged on the interpreter
# alone, script tools and their subtrees would be dropped. Declarative: one entry per interpreter.
_INTERPRETERS = ("sh", "bash", "zsh", "dash", "ksh", "tcsh", "csh",
                 "python", "python2", "python3", "ruby", "perl", "node",
                 "deno", "bun", "php", "osascript", "tclsh", "wish",
                 "Rscript", "expect")
# Versioned names Homebrew and the system both ship: python3.13, ruby3.4, perl5.34.
_INTERP_RE = re.compile(r'^(python\d(\.\d+)?|ruby\d(\.\d+)?|perl5(\.\d+)*|node\d*)$')
def is_interpreter(path):
    b = path.rsplit("/", 1)[-1]
    return b in _INTERPRETERS or bool(_INTERP_RE.match(b))

# Apple's own script locations: a system script run by a system daemon is not a third-party actor.
# /usr/local is carved out in third_party_script(); /opt is absent, so MacPorts and /opt/homebrew
# count as third-party.
_APPLE_SCRIPT_DIRS = ("/System/", "/usr/", "/bin/", "/sbin/", "/etc/",
                      "/private/etc/", "/Library/Apple/")
def third_party_script(p):
    # A script is an ACTOR only when third-party. Resolved first: a /System/Volumes/Data/… spelling (the
    # Data volume's own route to /Applications, /Users) must not pass as Apple. Same normalisation as
    # is_apple_path.
    if not p or not p.startswith("/"): return ""
    try: r = os.path.realpath(p)
    except Exception: r = os.path.normpath(p)
    _dv = "/System/Volumes/Data"
    # The mount point itself is no third-party file.
    if r == _dv: return ""
    if r.startswith(_dv + "/"): r = r[len(_dv):] or "/"
    if r.startswith("/usr/local/"): return p
    return "" if r.startswith(_APPLE_SCRIPT_DIRS) else p

def script_image(path, args):
    # The script an interpreter was handed, read from ARGV: the fallback for a macOS that leaves
    # event.exec.script empty (preferred, see the main loop). Only an ABSOLUTE argv path is accepted: a
    # relative one cannot be judged without the working directory.
    if not args or not is_interpreter(path): return ""
    for a in args[1:]:
        if a == "-": return ""                  # the program comes from stdin
        if a.startswith("-"): continue          # interpreter flags (-p, -u, -E)
        if not a.startswith("/"): return ""     # `-c '…'`, a bare word: no script
        return third_party_script(a)
    return ""

def third_party_name(proc, script=""):
    # ALL mode: the third-party actor this image belongs to, or "" if Apple's or unattributable. GUI apps
    # are named by .app bundle, out-of-bundle helpers by executable name.
    path = exe_path(proc)
    # A script is judged and named on its own path, so a Homebrew tool is "brew", not "bash".
    sp = script
    if sp:
        path = sp
    elif is_platform(proc):
        # An Apple application (Terminal, Script Editor, Automator) is a legitimate actor under -v: it runs
        # what the user typed. Daemons and XPC services stay out; they are the volume.
        if not SHOW_NOISE or not _APP_EXE_RE.search(path): return ""
    if not SHOW_NOISE and path.startswith(_TOOLCHAIN_DIRS): return ""
    name = app_bundle_name(path)
    if not name:
        # PrivilegedHelperTools binaries are named by bundle id, informative on its own.
        if _PRIVILEGED_DIR in path:
            name = path.rsplit("/", 1)[-1]
        else:
            # Under Application Support the file name is often generic; the vendor folder below it identifies.
            for d in _OUT_OF_BUNDLE_DIRS:
                if d in path:
                    rest = path.split(d, 1)[1]
                    name = rest.split("/", 1)[0] if "/" in rest else rest
                    break
            else:
                # Last resort: third-party code outside bundles (Homebrew daemons, /usr/local agents, MDM scripts).
                # The file name is imprecise but better than not appearing.
                name = path.rsplit("/", 1)[-1] if path else ""
    return name

def resolve_app(proc, script=""):
    # Registry label wins in every mode. A script is also matched on its own path, so targeting a
    # script-based tool works though the exec names the interpreter.
    path = exe_path(proc)
    sp = script
    lbl = match_proc(proc, path)
    if lbl is None and sp: lbl = match_target("", sp)
    if lbl: return lbl
    if not ALL_MODE: return None
    name = third_party_name(proc, script)
    if not name: return None
    # -v lifts this too: an exclusion must not be a permanent blind spot on root software.
    if not SHOW_NOISE and is_excluded(sp or path, field(proc, "team_id", "signing_id")):
        return None
    return name

def is_app_image(proc, inherited=False, script=""):
    # True if this process IS an app/helper's own image (launch/relaunch), not a command it runs;
    # symmetric with resolve_app. `inherited` = an already-attributed process ran this, i.e. someone
    # chose to run it.
    path = exe_path(proc)
    sp = script
    judged_path = sp or path
    if (match_proc(proc, path) is not None
            or (sp and match_target("", sp) is not None)):
        # A CLI target IS the command.
        if is_cli_target(judged_path): return False
        # Only the bundle's MAIN executable is the app itself; a script in Contents/Resources is a command
        # the app runs.
        if _APP_EXE_RE.search(path): return True
        return any(path in t["helpers"] for t in targets)
    if not ALL_MODE or not third_party_name(proc, script): return False
    # Inside a bundle only the main executable is the app relaunching; anything else is a command.
    if _APP_RE.search(judged_path): return _APP_EXE_RE.search(judged_path) is not None
    # Outside any bundle it depends on who started it. Launched by another process (launchd forking a
    # daemon, an app spawning a tool): the acting pid differs from the new pid, nothing is inherited, the
    # binary is its own image, announced once. Exec'd in place (acting pid == new pid, a shell becoming
    # the tool): attribution is inherited and the line is a command.
    return not inherited

# ============================================================================
# PRIVACY (TCC) — who a grant/revoke belongs to
# ============================================================================
# tcc_modify's own `process` is always tccd, never the app concerned. The question is "whose permission
# is this", judged in order: (a) the identity IS a tracked app (a grant can happen while it is not
# running); (b) the instigator/responsible process is tracked; (c) ALL mode shows a third-party
# identity (not a com.apple. bundle id nor a path under Apple's roots, is_apple_path).

_TCC_RIGHT = {0: "denied", 1: "unknown", 2: "allowed", 3: "limited",
              4: "add_modify_added", 5: "session_pid", 6: "learn_more"}
_TCC_REASON = {0: "none", 1: "error", 2: "user_consent", 3: "user_set",
               4: "system_set", 5: "service_policy", 6: "mdm_policy",
               7: "service_override_policy", 8: "missing_usage_string",
               9: "prompt_timeout", 10: "preflight_unknown", 11: "entitled",
               12: "app_type_policy", 13: "prompt_cancel"}
_TCC_UPDATE = {0: "unknown", 1: "create", 2: "modify", 3: "delete"}
_TCC_IDTYPE = {0: "bundle_id", 1: "executable_path", 2: "policy_id",
               3: "file_provider_domain_id"}

def _tcc_enum(table, v):
    if v is None: return "?"
    return table.get(v, str(v))

def _identity_matches_target(identity, itype):
    # identity_type 1 = a path, matched like an exec's.
    if itype == 1:
        return match_target("", identity)
    # identity_type 0 = a bundle id, matched against each target's REAL CFBundleIdentifier
    # (TARGET_BUNDLE_IDS), never derived from the app name; exact and case-sensitive. No entry means no
    # match here; (b)/(c) still try.
    if itype == 0:
        return TARGET_BUNDLE_IDS.get(identity) if identity else None
    return None

def is_apple_path(p):
    # Rule (c) of TCC and BTM: is this item Apple's own, judged on a PATH alone (a TCC identity or login
    # item is a name; the event carries no platform flag for it). third_party_script() is that criterion.
    # Its realpath resolution means a symlink cannot hide it (/Applications/Safari.app links into
    # /System/Cryptexes/…), while a third party spelling its path /System/Volumes/Data/… is not Apple.
    if not p or not p.startswith("/"): return False
    return third_party_script(p) == ""

def _tcc_identity_is_apple(identity, itype):
    # identity_type 1 is an executable PATH (`/usr/libexec/sshd-keygen-wrapper` is Apple's despite no
    # com.apple. prefix). Other types are bundle-id-like names, where the prefix is the only criterion.
    if itype == 1: return is_apple_path(identity)
    return identity.startswith("com.apple.")

def _app_suffix(label):
    # Which watched app a TCC/BTM line belongs to. SOLO names one app, so nothing is added; with several
    # targets or in ALL mode the label is appended. Empty when no label applies (rule (c)).
    return " — app: %s" % label if label and not SOLO else ""

def _tcc_actor(tm):
    resp = tm.get("responsible")
    return resp if isinstance(resp, dict) else tm.get("instigator")

def _tcc_label_for(identity, itype, actor):
    # Returns (label, counted): the registry name (None for an unregistered third party in ALL mode) and
    # whether the event qualifies at all.
    lbl = _identity_matches_target(identity, itype)
    if lbl: return lbl, True
    if isinstance(actor, dict):
        apid = proc_pid(actor)
        if apid is not None and apid in tracked:
            return tracked[apid], True
        lbl = match_proc(actor, exe_path(actor))
        if lbl: return lbl, True
    if ALL_MODE and identity and not _tcc_identity_is_apple(identity, itype):
        return None, True
    return None, False

def _int_or_none(v):
    # An integer field. `1e400` parses as inf and int(inf) raises OverflowError, which would lose the
    # whole event.
    try: return int(v)
    except (TypeError, ValueError, OverflowError): return None
def _str_or_empty(v):
    # A string field in the NDJSON schema: a number is printed as text, null/absent as "".
    if v is None: return ""
    return v if isinstance(v, str) else str(v)

def handle_tcc_modify(tm, proc):
    if not WATCH_TCC or not isinstance(tm, dict): return
    service = _str_or_empty(tm.get("service"))
    identity = _str_or_empty(tm.get("identity"))
    itype = _int_or_none(tm.get("identity_type"))
    right = _int_or_none(tm.get("right"))
    reason = _int_or_none(tm.get("reason"))
    utype = _int_or_none(tm.get("update_type"))
    actor = _tcc_actor(tm)
    label, counted = _tcc_label_for(identity, itype, actor)
    if not counted: return
    # A buffered deletion happened BEFORE this change: print it first to keep event order.
    flush_deletes()
    actor_path = exe_path(actor) if isinstance(actor, dict) else ""
    right_s = _tcc_enum(_TCC_RIGHT, right)
    reason_s = _tcc_enum(_TCC_REASON, reason)
    utype_s = _tcc_enum(_TCC_UPDATE, utype)
    itype_s = _tcc_enum(_TCC_IDTYPE, itype)
    # Plain --report stays silent during the capture; with --ndjson the stream stays live.
    if not QUIET:
        if NDJSON:
            # pid/pidver: the actor's, else the token the event carries.
            _atok = actor.get("audit_token") if isinstance(actor, dict) else (
                tm.get("responsible_token") if tm.get("responsible_token") is not None
                else tm.get("instigator_token"))
            # --mdm rewrites a home in identity here too, as it does in cmd.
            obj = {"type": "tcc", "ts": ts_iso(), "service": service, "identity": mdm_rewrite(identity),
                   "identity_type": itype_s, "right": right_s, "reason": reason_s,
                   "update_type": utype_s, "instigator": actor_path or None,
                   "app": label or None, "pid": audit_pid(_atok), "pidver": audit_pidver(_atok)}
            # ensure_ascii=True: untrusted strings straight from the event.
            raw_out("C\t" + nd_dumps(obj))
        else:
            raw_out("C\t# TCC: %s %s for %s (%s, %s)%s"
                    % (service, right_s, mdm_rewrite(identity), reason_s, utype_s, _app_suffix(label)))
    record_tcc(service, identity, right_s, reason_s, utype_s, actor_path, label or "")

# ============================================================================
# LOGIN ITEMS (BTM) — persistence added or removed without a command
# ============================================================================
# btm_launch_item_add/remove report backgroundtaskmanagementd's registry of what launches at login
# (Settings toggle, SMAppService/SMLoginItemSetEnabled, MDM profile), none of which shells out or
# touches a file. Attribution, same order as TCC: (a) the ITEM's path is a tracked app's bundle or CLI
# target (it can be registered while the app is not running); (b) the instigator or app process is
# tracked; (c) ALL mode shows a third-party item that is not Apple's (is_apple_path()). Never by name.

_BTM_ITEM_TYPE = {0: "user item", 1: "app", 2: "login item", 3: "agent", 4: "daemon"}

def _btm_kind(v):
    if v is None: return "?"
    return _BTM_ITEM_TYPE.get(v, str(v))

def _btm_decode_url(u):
    # A file:// URL -> its local path, percent-decoded, trailing slash stripped. None for anything else;
    # the caller falls back.
    if not isinstance(u, str) or not u.startswith("file://"): return None
    try:
        p = urllib.parse.unquote(urllib.parse.urlparse(u).path)
    except Exception:
        return None
    if len(p) > 1 and p.endswith("/"): p = p.rstrip("/")
    return p or None

def _btm_item_path(item, exe_path_field):
    # Priority: item_url (file:// URL, decoded); executable_path (a string on the "add" shape only);
    # app_url decoded; else a raw url string taken literally, so an unknown shape still names something.
    iu = item.get("item_url") if isinstance(item, dict) else None
    p = _btm_decode_url(iu)
    if p: return p
    if isinstance(exe_path_field, str) and exe_path_field: return exe_path_field
    au = item.get("app_url") if isinstance(item, dict) else None
    p = _btm_decode_url(au)
    if p: return p
    if isinstance(iu, str) and iu: return iu
    if isinstance(au, str) and au: return au
    return ""

def _btm_path_matches_target(path):
    # Rule (a): the item is a tracked app's bundle or inside it (never a bare prefix), or a tracked CLI
    # target exactly.
    if not path: return None
    for t in targets:
        if t["bundle"] and (path == t["bundle"] or path.startswith(t["bundle"] + "/")):
            return t["label"]
        if path in t["cli"]:
            return t["label"]
    return None

def _btm_actor_label(proc_obj):
    # Rule (b): the instigator/app process is a tracked pid or matches a target as exec seeding does.
    if not isinstance(proc_obj, dict): return None
    apid = proc_pid(proc_obj)
    if apid is not None and apid in tracked: return tracked[apid]
    return match_proc(proc_obj, exe_path(proc_obj))

def _btm_label_for(path, instigator, app):
    lbl = _btm_path_matches_target(path)
    if lbl: return lbl, True
    lbl = _btm_actor_label(instigator)
    if lbl: return lbl, True
    lbl = _btm_actor_label(app)
    if lbl: return lbl, True
    # Same Apple criterion as TCC's path identities (is_apple_path()).
    if ALL_MODE and path and not is_apple_path(path):
        return None, True
    return None, False

def _btm_actor_short(instigator, app):
    p = exe_path(instigator) if isinstance(instigator, dict) else ""
    if not p and isinstance(app, dict): p = exe_path(app)
    return p.rsplit("/", 1)[-1] if p else "?"

def handle_btm_launch_item(bt, action, proc):
    if not WATCH_BTM or not isinstance(bt, dict): return
    item = bt.get("item")
    if not isinstance(item, dict): item = {}
    itype = _int_or_none(item.get("item_type"))
    instigator = bt.get("instigator")
    app = bt.get("app")
    path = _btm_item_path(item, bt.get("executable_path"))
    label, counted = _btm_label_for(path, instigator, app)
    if not counted: return
    flush_deletes()   # event order: see handle_tcc_modify
    kind_s = _btm_kind(itype)
    short = _btm_actor_short(instigator, app)
    managed = item.get("managed") is True
    legacy = item.get("legacy") is True
    actor_path = exe_path(instigator) if isinstance(instigator, dict) else ""
    # Plain --report stays silent during the capture; with --ndjson the stream stays live.
    if not QUIET:
        if NDJSON:
            iu = item.get("item_url")
            uid_i = _int_or_none(item.get("uid"))
            # pid/pidver: the instigator `instigator` names, else its bare token.
            _atok = (instigator.get("audit_token") if isinstance(instigator, dict)
                     else bt.get("instigator_token"))
            obj = {"type": "btm", "ts": ts_iso(), "action": action, "item_type": kind_s,
                   "path": mdm_rewrite(path), "url": mdm_rewrite(iu) if isinstance(iu, str) else None,
                   "legacy": legacy, "managed": managed, "uid": uid_i,
                   "instigator": actor_path or None,
                   "marks": ["persistence"] if action == "add" else [],
                   "app": label or None, "pid": audit_pid(_atok), "pidver": audit_pidver(_atok)}
            # ensure_ascii=True: untrusted strings straight from the event.
            raw_out("C\t" + nd_dumps(obj))
        else:
            _suffix = kind_s + (" (managed)" if managed else "") + (" (legacy)" if legacy else "")
            _app = _app_suffix(label)
            if action == "add":
                raw_out("C\t# LOGIN ITEM added (%s): %s — via %s%s   ⚠ persistence" % (_suffix, mdm_rewrite(path), short, _app))
            else:
                raw_out("C\t# LOGIN ITEM removed (%s): %s — via %s%s" % (_suffix, mdm_rewrite(path), short, _app))
    record_btm(action, path, kind_s, short, label or "")

# ============================================================================
# CLASSIFICATION — what a command DOES: the rule tables and their trigger syntax
# ============================================================================
# `DESTRUCTIVE` lives with `triggered()`, which every rule table (`_NETWORK`, `_SECRET`) is read
# through. Trigger forms: a literal, a prefix (`--set*`), a suffix (`*/.zcompdump`), a regex
# (`~^[2-7][0-7]{3}$`), or None for any arguments.

# Destructive command rules, one entry per binary. None = destructive whatever the arguments; a set =
# only when one of these arguments is present (read-only subcommands stay quiet).
DESTRUCTIVE = {
    # Removal / overwrite
    "rm": None, "rmdir": None, "srm": None, "unlink": None, "shred": None,
    "dd": None, "mkfs": None, "newfs": None,
    "find": {"-delete"},
    "chflags": {"nouchg", "noschg"},        # unlocks files so they CAN be deleted
    # Process control / power state
    "kill": None, "killall": None, "pkill": None,
    "shutdown": None, "reboot": None, "halt": None,
    # Verbs that stop a running job: `kill <sig>`, `stop <label>`, and `kickstart -k` (kills first; may
    # be a cluster like `-kp`, hence the regex). Plain `kickstart` stays unmarked.
    "launchctl": {"bootout", "unload", "remove", "disable", "kill", "stop",
                  "~^-[A-Za-z]*k[A-Za-z]*$"},
    # Caches & system databases — the bread and butter of maintenance apps
    "purge": None,
    "dscacheutil": {"-flushcache"},
    "atsutil": {"remove", "-remove"},       # font caches
    "mdutil": {"-E", "-X"},                 # erase / tear down the Spotlight index
    # `-delete` is how apps tear down the LaunchServices database; the store's unlink then arrives
    # attributed `via lsregister`.
    "lsregister": {"-kill", "-delete"},     # tear down the LaunchServices database
    # A shelled-out SQL statement: the rule is the STATEMENT, not the binary (sqlite3 is otherwise a
    # query tool). Regex triggers, case-insensitive, since SQL is free-form.
    "sqlite3": {r"~(?i)\bdelete\s+from\b", r"~(?i)\bdrop\s+(table|index|trigger|view)\b",
                r"~(?i)\bupdate\s+\S+\s+set\b", r"~(?i)\btruncate\b"},
    "qlmanage": {"-r"},                     # reset the QuickLook cache
    "kextcache": {"-i", "-u", "--invalidate", "--update-volume"},
    "defaults": {"delete"},
    # Disks & snapshots
    "diskutil": {"erase", "eraseDisk", "eraseVolume", "reformat",
                 "deleteVolume", "deleteContainer", "deleteSnapshot",
                 "repairVolume", "repairDisk", "resetUserPermissions"},
    "fsck": None,                           # a repair pass on a live volume
    "tmutil": {"delete", "deletelocalsnapshots", "disable"},
    # Read-only tools that can also write — the write form only
    "git":  {"--hard", "-D", "clean", "prune", "filter-branch",
             "--force", "--force-with-lease"},  # history/worktree destruction
    # Firewall changes: the whole --set* family at once, --add/--remove aside
    "socketfilterfw": {"--set*", "--add", "--remove"},
    "sysctl": {"-w"},                       # writes a kernel parameter
    "sed": {"-i"},                          # in-place edit
    "dscl": {"-delete"},                    # directory records
    "plutil": {"-remove"},
    # Permissions & security posture: setuid (`chmod u+s`) and world-writable matter most; each has an
    # octal and a symbolic spelling, hence the regex triggers.
    "chown": {"-R", "~^root(:|$)"},         # taking ownership for root
    "chmod": {"-R",
              "~[+=][rwx]*s",               # setuid/setgid: u+s, a+rws, u=rws
              "~^[2-7][0-7]{3}$",           # …and in octal: 4755, 2755, 6711
              "~^[0-7]{2,3}[2367]$",        # world-writable: 777, 666, 757
              "o+w", "a+w"},
    "csrutil": {"disable"},                 # System Integrity Protection off
    "nvram": {"-c", "-d"},                  # clear NVRAM
    "spctl": {"--master-disable", "--global-disable"},   # both spellings
    # Removal by tools that are not `rm` (`find -exec` is handled in is_destructive).
    "crontab": {"-r"},                      # wipes the user's crontab
    "security": {"delete-keychain", "delete-generic-password",
                 "delete-internet-password", "delete-certificate"},
    "profiles": {"remove", "-R", "-D"},     # removes a configuration profile
    "tccutil": {"reset"},                   # wipes privacy/security grants for an app
    "systemextensionsctl": {"uninstall", "reset"},
    "pkgutil": {"--forget"},                # drops the receipt for a package
    "hdiutil": {"erasekeys"},  # no `erase` verb
    "truncate": {"~^0$"},                   # `truncate -s 0` empties a file
    "log": {"erase"},                       # `log erase --all`: the unified log
}

_TRIG_RE = {}
def triggered(trig, args):
    # None = always. Otherwise any listed argument matches. A trigger ending in "*" matches by prefix,
    # one STARTING with "*" by suffix, one starting with "~" is a REGEX (a mode is written `u+s`, `4755`
    # or `6711`, all setuid).
    if trig is None: return True
    aset = set(args)
    for t in trig:
        if t.startswith("~"):                       # regex: "~^[2-7][0-7]{3}$"
            rx = _TRIG_RE.get(t)
            if rx is None:
                try: rx = _TRIG_RE[t] = re.compile(t[1:])
                except re.error: _TRIG_RE[t] = False; continue
            if rx is False: continue
            if any(rx.search(a) for a in args[1:]): return True
        elif t.startswith("*"):                     # suffix: "*/.zcompdump"
            if any(a.endswith(t[1:]) for a in args): return True
        elif t.endswith("*"):                       # prefix: "--set*"
            if any(a.startswith(t[:-1]) for a in args): return True
        elif t in aset:
            return True
    return False

def is_destructive(path, args):
    b = path.rsplit("/", 1)[-1]
    if b == "find":
        # `find <dir> -exec rm -rf {} ;`: the destructive act is the command `-exec` RUNS, and
        # destructive_stage cannot see it (it splits on `;` after the rm). Judged here.
        for i, a in enumerate(args):
            if a in ("-exec", "-execdir", "-ok", "-okdir") and i + 1 < len(args):
                inner = [x for x in args[i + 1:]
                         if x not in (";", "\\;", "+", "{}")]
                if inner and inner[0] != "find" and is_destructive(inner[0], inner):
                    return True
    if b not in DESTRUCTIVE: return False
    return triggered(DESTRUCTIVE[b], args)

# ============================================================================
# FILE EVENTS — reading a path, a destination, a mode
# ============================================================================
# unlink, rename, clone, link and the four permission events, each reduced to the command that
# reproduces it. `is_persistence` is here because where a file LANDS makes an install an install.

def any_path(node, depth=0):
    # File-event bodies nest their path differently per event type and macOS version, so walk the node
    # for the first "path" string (no per-type extraction code). Exact fields (a rename's DESTINATION, an
    # open's st_mode) are read directly. Depth 8 and lists walked too: a `target` that becomes a list of
    # one file must not be skipped.
    if depth > 8: return ""
    if isinstance(node, list):
        for v in node:
            r = any_path(v, depth + 1)
            if r: return r
        return ""
    if not isinstance(node, dict): return ""
    p = node.get("path")
    if isinstance(p, str) and p: return p
    for v in node.values():
        if isinstance(v, (dict, list)):
            r = any_path(v, depth + 1)
            if r: return r
    return ""

# Transient churn: lock files, editor swap files, per-process temp directories.
# Deleting those says nothing about what an app DOES; -v shows them anyway.
def atomic_write(src, dst):
    # `settings.json.SZgY1i -> settings.json`: write-to-temp then rename-into-place is plumbing, not the
    # app moving anything. A rename across directories is a real move.
    if not src or not dst: return False
    return src.rsplit("/", 1)[0] == dst.rsplit("/", 1)[0]

# Where software arranges to come back: a launch item, privileged helper, system extension, binary on
# the PATH, /etc. Installing one is the act an audit exists to catch, but the temp-then-rename install
# is read by atomic_write() as plumbing: right for a preferences file, wrong for a LaunchDaemon.
_PERSIST_ROOTS = ("/usr/local/bin/", "/usr/local/sbin/",
                  "/Library/StartupItems/", "/Library/Extensions/",
                  "/Library/SystemExtensions/")
# Matched anywhere in the path, not as a prefix: LaunchAgents exist per-user
# under ~/Library as well as system-wide.
_PERSIST_ANY = ("/Library/LaunchDaemons/", "/Library/LaunchAgents/",
                "/Library/PrivilegedHelperTools/")
# Only the /etc paths that re-run on their own (periodic scripts, login/rc shells, sudoers, pam.d,
# sshd, cron, paths.d, emond). A plain .conf or .plist an app owns stays plumbing: all of /etc would
# mark ordinary atomic rewrites as persistence and defeat the atomic-write noise rule.
_PERSIST_ETC_DIRS = ("/etc/periodic/", "/etc/pam.d/", "/etc/sudoers.d/",
                     "/etc/ssh/sshd_config.d/", "/etc/ssh/ssh_config.d/",
                     "/etc/paths.d/", "/etc/manpaths.d/", "/etc/emond.d/")
_PERSIST_ETC_FILES = ("/etc/rc.common", "/etc/launchd.conf", "/etc/crontab",
                      "/etc/sudoers", "/etc/ssh/sshd_config", "/etc/ssh/ssh_config",
                      "/etc/profile", "/etc/zshrc", "/etc/zprofile", "/etc/zshenv",
                      "/etc/zlogin", "/etc/zlogout", "/etc/bashrc",
                      "/etc/csh.cshrc", "/etc/csh.login")
def is_etc_persistence(path):
    p = _canon(path)
    if not p.startswith("/etc/"): return False
    if p in _PERSIST_ETC_FILES or p.startswith("/etc/rc."): return True
    return p.startswith(_PERSIST_ETC_DIRS)
def is_persistence(path):
    if not path: return False
    return (path.startswith(_PERSIST_ROOTS) or any(d in path for d in _PERSIST_ANY)
            or is_etc_persistence(path))

def rename_dest(body):
    # The destination is an existing file, or a directory plus the new name; stopping at the directory
    # would give `mv X /…/Logs` and defeat the atomic-write check.
    d = body.get("destination")
    if not isinstance(d, dict): return ""
    for k in ("existing_file", "new_path"):
        node = d.get(k)
        if isinstance(node, dict):
            fn = node.get("filename")
            base = any_path(node)
            if isinstance(fn, str) and fn and base:
                return base.rstrip("/") + "/" + fn if not base.endswith("/" + fn) else base
            if base: return base
    return any_path(d)

# The events that put a file somewhere. `_COPY_KINDS` carry a source and a destination, reproduced as
# `cp`/`ln`; `_WRITE_KINDS` is the set --no-files drops and --destructive-only keeps.
_COPY_KINDS = ("clone", "link")
# Permission and ownership changes made through the API: a direct chmod(2) fires no exec. setuid and
# `chown root` are the cases that matter most.
_PERM_KINDS = ("setmode", "setowner", "setflags", "setacl")
# deleteextattr stays OUT of _PERM_KINDS: covered_by_perm() absorbs any perm-kind event on a path a
# recent chmod/chown/chflags named, which would swallow a real xattr removal.
_WRITE_KINDS = ("unlink", "rename") + _COPY_KINDS + _PERM_KINDS + ("deleteextattr",)

_S_PERM = 0o7777

# File flags `chflags` accepts by NAME (sys/stat.h); decimal is the fallback for an unnamed bit.
# Hexadecimal is never emitted: `chflags` rejects it.
_FLAG_NAMES = ((0x00000001, "nodump"), (0x00000002, "uchg"), (0x00000004, "uappnd"),
               (0x00000008, "opaque"), (0x00008000, "hidden"),
               (0x00010000, "arch"), (0x00020000, "schg"), (0x00040000, "sappnd"),
               (0x00080000, "restricted"), (0x00100000, "sunlnk"))
def flags_arg(f):
    # The symbolic spelling, or None when the value cannot be written: `chflags` rejects a number with an
    # unknown bit, and a partial symbolic list would set something other than what happened.
    if f == 0: return "0"
    names, rest = [], f
    for bit, nm in _FLAG_NAMES:
        if f & bit: names.append(nm); rest &= ~bit
    return ",".join(names) if names and not rest else None
def perm_change(kind, body):
    # (command, destructive, path) reproducing the change, or None when the event carries nothing usable.
    # Fields follow es_event_setmode_t and friends, read defensively.
    if not isinstance(body, dict): return None
    path = any_path(body.get("target")) or any_path(body)
    if not path: return None
    q = shq(path)
    if kind == "setmode":
        m = body.get("mode")
        # A str is REFUSED, not converted: `int("4755")` is decimal and would give a wrong chmod, and the
        # base cannot be guessed. Counted via degrade() so the gap shows.
        if isinstance(m, bool) or not isinstance(m, int):
            degrade("setmode: the mode was not a number")
            return None
        m = int(m)
        m &= _S_PERM
        # setuid/setgid/sticky and world-writable, as the exec rules treat them.
        return ("chmod %04o %s" % (m, q), bool(m & 0o7000) or bool(m & 0o002), path)
    if kind == "setowner":
        u, g = body.get("uid"), body.get("gid")
        if isinstance(u, bool) or not isinstance(u, int):
            degrade("setowner: the uid was not a number")
            return None
        u = int(u)
        try: g = int(g)
        except Exception: g = None
        who = "%d:%d" % (u, g) if g is not None else "%d" % u
        # Ownership moving to root is how a file stops being the user's.
        return ("chown %s %s" % (who, q), u == 0, path)
    if kind == "setflags":
        f = body.get("flags")
        try: f = int(f)
        except Exception: return None
        # 0 clears the flags, which unlocks a file so it CAN be deleted (as `chflags nouchg`). Symbolic,
        # never hex: `chflags` rejects `0x2`.
        fa = flags_arg(f)
        if fa is None:
            # No spelling exists for these bits: recorded rather than reproduced, as an ACL is below.
            return ("# file flags set to %#x on %s" % (f, q), False, path)
        return ("chflags %s %s" % (fa, q), f == 0, path)
    # setacl carries an ACL structure and no short command reproduces it: recorded, not reproduced.
    return ("# ACL changed on %s" % q, False, path)

# deleteextattr's body: {"extattr": <name>, "target": {"path": …}}. setextattr is deliberately not
# subscribed: the value set is never in the event so nothing could replay it, and it fires constantly
# system-wide. Name and path go through shlex.quote; read defensively.
def xattr_change(body):
    if not isinstance(body, dict): return None
    name = body.get("extattr")
    if not isinstance(name, str) or not name:
        degrade("deleteextattr: the attribute name was not a string")
        return None
    path = any_path(body.get("target")) or any_path(body)
    if not path: return None
    return ("xattr -d %s %s" % (shq(name), shq(path)), path, name)

# Attribute names the OS rewrites as bookkeeping, not an act worth reproducing (`com.apple.lastuseddate#PS`
# is LaunchServices' last-opened stamp). `com.apple.quarantine` and `com.apple.provenance` stay OUT on
# purpose: removing them changes what Gatekeeper/AMFI do with the file, the class this feature catches.
_XATTR_NOISE = ("com.apple.lastuseddate#PS",)

def copy_dest(body):
    # Where a clone or a link puts the file. Finder's copy engine emits `clone` with `{"source": {"path": …},
    # "target_dir": {"path": …}, "target_name": …}`; es_event_link_t spells the name `target_filename`, and
    # an overwrite may name an existing `target_file`. Every spelling is tried.
    if not isinstance(body, dict): return ""
    tf = body.get("target_file")
    if isinstance(tf, dict):
        p = any_path(tf)
        if p: return p
    for dk in ("target_dir", "target_directory", "destination_dir"):
        node = body.get(dk)
        if not isinstance(node, dict): continue
        base = any_path(node)
        if not base: continue
        for nk in ("target_name", "target_filename", "filename", "name"):
            nm = body.get(nk)
            if isinstance(nm, str) and nm:
                return base if base.endswith("/" + nm) else base.rstrip("/") + "/" + nm
        # A directory with no name is not a destination (`ln src /usr/local/bin`, not the binary), and the
        # persistence roots are matched with a trailing slash.
        return ""
    return ""

def persistence_actor(ev, kind, proc):
    # Who to credit for a file landing where software installs itself, when normal attribution found
    # nobody. Attribution requires a THIRD-PARTY actor, wrong for this act: a launch agent that appears is a
    # fact whatever placed it (a Finder drag emits `clone` from DesktopServicesHelper, an Apple binary
    # outside any bundle). Narrow: persistence locations only, the actor NAMED from its executable.
    if kind != "rename" and kind not in _COPY_KINDS: return None
    body = ev.get(kind)
    d = rename_dest(body) if kind == "rename" else copy_dest(body)
    if not is_persistence(d): return None
    p = exe_path(proc)
    return app_bundle_name(p) or (p.rsplit("/", 1)[-1] if p else None)

_SELF_DB_DIRS = ("/Library/Sentinel/_sentinel/db/",)
_SCAN_CACHE_DIRS = ("/Library/Application Support/ESET/Security/cache/charon/",)
_SCAN_CACHE_FILE_RE = re.compile(r'^FND[0-9A-Fa-f]+\.NFI$')
_LEVELDB_DIR_RE = re.compile(r'\.leveldb/|/leveldb/')
_LEVELDB_FILE_RE = re.compile(r'^(\d+\.(ldb|log|sst)|MANIFEST-\d+|LOCK|CURRENT|LOG(\.old)?)$')
def transient(path):
    b = path.rsplit("/", 1)[-1]
    # `-journal`/`-wal`/`-shm`: SQLite companion files, recreated on every commit.
    if b.endswith((".lock", ".tmp", ".swp", "~", ".part", ".download", ".odl",
                   "-journal", "-wal", "-shm")): return True
    # todelete_<hex>_n: Chromium's doomed-cache files. NSFX.<rand>: NSFileManager scratch files. `.odl`
    # above is OneDrive's rotating diagnostic log.
    if b.startswith(("todelete_", "NSFX.")): return True
    if b in (".DS_Store", ".localized"): return True
    # LevelDB compaction: Electron apps keep IndexedDB and Local Storage in one and retire numbered
    # segments constantly. Narrow: numbered segments and bookkeeping files inside a leveldb directory
    # only; deleting the directory still shows.
    if _LEVELDB_DIR_RE.search(path) and _LEVELDB_FILE_RE.match(b): return True
    # …and one agent's own state database (SentinelOne's LevelDB under /Library/Sentinel/_sentinel/db/),
    # whose directory is not named for the engine. Named, not a relaxed rule, so no other app's numbered
    # files are hidden; only LevelDB-shaped names inside that directory.
    if any(d in path for d in _SELF_DB_DIRS) and _LEVELDB_FILE_RE.match(b): return True
    # …and an AV engine retiring entries from its own scanner cache (ESET's charon directory): one `rm` per
    # file for a single logical act. Directory AND file shape are named; deleting the cache DIRECTORY
    # still shows.
    if any(d in path for d in _SCAN_CACHE_DIRS) and _SCAN_CACHE_FILE_RE.match(b): return True
    return "/private/var/folders/" in path and "/T/" in path

# Startup/runtime reads every process makes (C runtime, ICU, timezone, eligibility, GPU shader cache,
# user database, crash reports): launch plumbing, so --opens drops them like loaded .dylibs.
# Substrings (so /var/db/timezone matches under /private too); /dev is a prefix.
_OPEN_NOISE = ("/usr/share/icu/", "/var/db/timezone/", "/var/db/eligibilityd/",
               "/System/Library/OpenDirectory/", "SystemVersion.plist",
               "/com.apple.metal/", "com.apple.IntlDataCache", "/CrashReporter/",
               "/etc/passwd", "/etc/group")

_S_IFMT = 0o170000
_S_IFDIR = 0o040000
_S_IFREG = 0o100000
def open_mode(body):
    # The file's st_mode from the open event (event.open.file.stat.st_mode), or None; defensive so a
    # missing field never hides a real read.
    f = body.get("file") if isinstance(body, dict) else None
    st = f.get("stat") if isinstance(f, dict) else None
    if isinstance(st, dict):
        for k in ("st_mode", "mode"):
            v = st.get(k)
            try:
                if v is not None: return int(v)
            except Exception: pass
    return None

def open_is_dir(body):
    # open() on a directory is not a file read: it duplicates the readdir already reported.
    m = open_mode(body)
    return m is not None and (m & _S_IFMT) == _S_IFDIR

def open_is_exec(body):
    # A regular file with an execute bit is a binary: `cat` on it dumps garbage. Data files (fonts,
    # plists, caches) are mode 644 and stay.
    m = open_mode(body)
    return m is not None and (m & _S_IFMT) == _S_IFREG and (m & 0o111) != 0

# ============================================================================
# ABSORPTION — a command and the syscalls it causes are ONE act
# ============================================================================
# Three times, one per kind of act: a shown command records what it is about to do and the events it
# produces are folded into it. An event no command covers is the only record of that act and always
# survives. Every entry is keyed by the ACTOR: absorbing across actors would be a false negative in
# an attribution tool.

# A shown removal (`rm -rf ~/Library/Biome/*`) is followed by hundreds of unlink events that are its
# own expansion: a deletion under a removal already printed is suppressed. One no command covers (an
# app unlinking through the API) still shows.
_REMOVERS = {"rm", "rmdir", "srm", "unlink", "shred"}
wipe_prefixes = []    # (label, path-prefix, time) of removals already shown

def _canon(p):
    # /var, /tmp, /etc are symlinks to /private/*; unlink reports the real path. Match on one form.
    if p.startswith(("/private/var", "/private/tmp", "/private/etc")):
        return p[len("/private"):]
    return p

def wipe_prefix_of(arg):
    # The directory/prefix a removal argument covers: `~/Library/Biome/*` -> /Users/<me>/Library/Biome/;
    # a plain path gets a trailing / so /a/dir does not swallow /a/dir2. "" for a relative or ~-without-home arg.
    a = arg
    if a.startswith("~/") and HOME: a = HOME + a[1:]
    elif a == "~" and HOME: a = HOME
    if not a.startswith("/"): return "", False
    globbed = False
    for i, ch in enumerate(a):
        if ch in "*?[":
            a = a[:i]; globbed = True; break
    a = _canon(a)
    if not globbed and not a.endswith("/"): a += "/"
    # Whether it was a glob travels with the prefix (see covered_by_wipe).
    return a, globbed

def covered_by_wipe(label, path, now):
    cp = _canon(path)
    for wl, wp, wg, wt in wipe_prefixes:
        if wl != label: continue
        if now - wt >= 120.0 or not wp: continue
        if wp == cp + "/":
            # The directory the command NAMED: `rm -rf /path/Keychains/` deletes it too, so print once. A GLOBBED
            # argument leaves the container standing, so its own unlink is not absorbed.
            if not wg: return True
            continue
        if not cp.startswith(wp): continue
        # A DIRECT child starting with a dot is not covered by a glob (no shell expands `*` onto a leading
        # dot), but only at a COMPONENT boundary (`wp` ending in `/`): cut mid-component
        # (`com.apple.wallpaper*`) the remainder may legitimately start with a dot.
        if wg and wp.endswith("/") and cp[len(wp):].split("/")[0].startswith("."):
            continue
        return True
    return False

# The same duplication for placements: a file-placing command an app shells out prints as the
# command, then its clone/link/rename arrives as a near-identical second line (`cp -c src dst` then
# `cp -R src dst`; `ditto` then the `mv` it renames into place). A placement no shown command covers
# still shows. `mv` belongs here too (cross-directory moves an app ran itself).
_COPIERS = {"cp", "ln", "mv", "ditto", "install", "rsync"}
copy_dests = []       # (label, destination, time) of placements already shown

def placed_dest(args):
    # Where a file-placing command puts its file: the last non-flag argument (`cp -R a b`,
    # `install -m 755 a b`, `mv a b`). Two operands required, so `rm -rf x` or a lone `ls` is not one.
    rest = [a for a in args[1:] if not a.startswith("-")]
    return rest[-1] if len(rest) >= 2 else ""

def places_persistence(args):
    # Does this command write where software installs itself? The mark belongs on the COMMAND, not only
    # its syscall: suppressing the duplicate rename (which carried `⚠ persistence`) would lose the signal.
    # The destination may be named as the file or as its directory.
    d = placed_dest(args)
    return bool(d) and (is_persistence(d) or is_persistence(d.rstrip("/") + "/"))

# The other half of an install: `cp x.plist /Library/LaunchDaemons/y.plist` places the job;
# `launchctl load`/`bootstrap` makes it RUN. Marked `⚠ persistence` (launchctl(1): `enable` "persists
# across boots"). Narrow:
#   load/bootstrap: only with an operand in a persistence location (a job loaded from /tmp stays unmarked);
#   enable: always (its target is a service, not a path);
#   kickstart/start/submit run a job now, not persistence; unload/bootout/disable/remove are in DESTRUCTIVE.
# `asuser <uid> launchctl …` is how a root script reaches a user's GUI domain.
def activates_launchd(args):
    ops = [a for a in args[1:] if not a.startswith("-")]
    if not ops: return False
    verb = ops[0]
    if verb == "asuser":
        # `asuser UID command…` takes no flag of its own: the inner argv
        # starts two tokens after the verb.
        _i = args.index("asuser", 1) + 2
        inner = args[_i:]
        return (bool(inner) and inner[0].rsplit("/", 1)[-1] == "launchctl"
                and activates_launchd(inner))
    if verb == "enable": return len(ops) > 1
    if verb in ("load", "bootstrap"):
        return any(is_persistence(a) or is_persistence(a.rstrip("/") + "/") for a in ops[1:])
    return False

def activation_stage(argv, path0=None):
    # Stage by stage, like _stage_hit: `launchctl bootout …; launchctl bootstrap …` is a reload. A copier
    # placing a file where software installs itself counts in any stage; a redirection is a copier too
    # (`cat > ~/Library/LaunchAgents/x.plist <<EOF`).
    for jp, ja, _r in _stages(argv, path0):
        if any(">" in op and tgt and is_persistence(tgt) for op, tgt in _r): return True
        b = jp.rsplit("/", 1)[-1]
        if b == "launchctl" and activates_launchd(ja): return True
        if b in _COPIERS and places_persistence(ja): return True
    return False

# Same absorption for permission changes: `chmod 4755 x` shelled out prints as the command, then its
# setmode would print again. Nothing is lost: the exec rules already mark a setuid `chmod` and
# `chflags nouchg`. A change through the API with no command in front of it still shows.
_PERM_CMDS = {"chmod", "chown", "chgrp", "chflags"}
perm_targets = []     # (label, path, time) of permission changes already shown

def covered_by_perm(label, path, now):
    if not path: return False
    cp = _canon(path)
    for pl, pp, pt in perm_targets:
        if pl != label: continue
        if now - pt >= 120.0 or not pp: continue
        # By PREFIX: `chmod -R 777 <tree>` names the tree while the setmode events name each file inside,
        # which would reprint one line per file.
        if cp == pp or cp.startswith(pp.rstrip("/") + "/"): return True
    return False

def covered_by_copy(label, dst, now):
    if not dst: return False
    cd = _canon(dst)
    for cl, cp_, ct in copy_dests:
        if cl != label: continue
        if now - ct >= 120.0 or not cp_: continue
        # The command may name the destination FILE or the directory it lands
        # in — `cp x /dest/` and `cp x /dest/x` are the same act.
        if cd == cp_ or cd.startswith(cp_.rstrip("/") + "/"): return True
    return False

# ============================================================================
# NOISE — what is dropped, and the reason --debug gives for it
# ============================================================================
# Four tables at three scopes: `NOISE` global; `APP_NOISE` and `APP_SCAN_NOISE` for one app's own
# polling; `_TOOL_SCAN_NOISE` for the walk a tool does for a command already announced. Every
# suppression is explainable (`noise_reason()` is the word `--debug` prints). `-v` lifts all of it.

# What gets filtered: not read-vs-write (`ls` is how a cleaner finds what it deletes) but whether a
# command is scriptable by itself. Filtered only when it is:
#   (a) a FRAGMENT no single exec captures whole: a pipeline stage (`awk`, `cut`),
#       a man-rendering cog (`mandoc`, `col`, `zcat`, `less`);
#   (b) SCAFFOLDING the app did not choose as an action: a login shell, an .xpc
#       launch (handled structurally), a wrapper's shell-init probe;
#   (c) shell GLUE with no effect and no inspection (`echo`, `sleep`, `test`);
#   (d) compinit CHURN (`mv */.zcompdump`);
#   (e) documentation display (`man`, `apropos`, `whatis`).
# Everything else is shown. Editor polling is handled by TARGETing the app, never by hiding a
# category. Same shape as DESTRUCTIVE: None = always, a set = only with one of those arguments. Each
# group carries the reason `--debug` reports.
NOISE = {
    # (a) Pipeline stages: one exec per stage; an isolated `awk '{print $2}'` cannot be replayed alone.
    "awk": None, "sed": None, "grep": None, "egrep": None, "fgrep": None,
    "cut": None, "head": None, "tail": None, "sort": None, "uniq": None,
    "tr": None, "wc": None, "cat": None, "rev": None, "expr": None,
    "printf": None, "seq": None, "column": None, "paste": None, "fold": None,
    "nl": None, "comm": None, "diff": None, "cmp": None, "base64": None,
    "xxd": None, "od": None, "strings": None, "md5": None, "shasum": None,
    # (a) Man-page rendering cogs: `man` fans out into these, none reusable alone.
    "mandoc": None, "col": None, "zcat": None, "groff": None, "nroff": None,
    "less": None, "more": None,
    # (e) Documentation display — reading a manual, not an action on the Mac.
    "man": None, "apropos": None, "whatis": None,
    # (b) Shell startup: every new terminal tab replays this (pty helper, PATH assembly).
    "path_helper": None, "spawn-helper": None,
    # (b) Wrapper shell-init: how a wrapper finds the shell, Homebrew's prefix or Xcode's path.
    "brew":           {"shellenv", "--prefix", "--cellar", "--repository",
                       "config", "--version"},
    "brew.sh":        {"shellenv"},
    "xcode-select":   {"-p", "--print-path", "--show-manpaths", "--version"},
    "sqlite3":        {"-version"},   # capability probe, not a query
    # system_profiler re-execs itself as `-nospawn -xml …` to do the work; the reusable command is the
    # one above it, already shown.
    "system_profiler": {"-nospawn"},
    # (c) Shell glue: control flow and string plumbing, no effect, no inspection.
    "echo": None, "true": None, "false": None, "test": None, "sleep": None,
    "basename": None, "dirname": None,
    # (d) compinit churn: zsh writes .zcompdump.<host>.<pid> then renames it into place. Only that
    # target is silenced.
    "mv": {"*/.zcompdump"},
}
# The reason each NOISE binary is filtered, reported by --debug as
# `# FILTERED: <cmd> (<reason>)`. A binary absent here defaults to "noise".
_NOISE_REASON = {}
for _b in ("awk", "sed", "grep", "egrep", "fgrep", "cut", "head", "tail", "sort",
           "uniq", "tr", "wc", "cat", "rev", "expr", "printf", "seq", "column",
           "paste", "fold", "nl", "comm", "diff", "cmp", "base64", "xxd", "od",
           "strings", "md5", "shasum", "mandoc", "col", "zcat", "groff", "nroff",
           "less", "more"):
    _NOISE_REASON[_b] = "pipeline-stage"
for _b in ("man", "apropos", "whatis"): _NOISE_REASON[_b] = "doc"
for _b in ("path_helper", "spawn-helper"): _NOISE_REASON[_b] = "shell-startup"
for _b in ("brew", "brew.sh", "xcode-select", "sqlite3", "system_profiler"): _NOISE_REASON[_b] = "wrapper-init"
for _b in ("echo", "true", "false", "test", "sleep", "basename", "dirname"): _NOISE_REASON[_b] = "shell-glue"
_NOISE_REASON["mv"] = "compinit"

# Per-app poll noise: real, scriptable commands that one app runs on a timer (an editor's `ps`/`git
# status`, a widget's `system_profiler`, an agent's `sw_vers`). Drops one command for one app, keyed
# by the label Culprit shows; the same command from any other app still shows. Hides a command, not
# the whole actor (unlike DEFAULT_EXCLUDES). -v lifts it, --debug says `app-poll`. Same shape as
# NOISE: None = the whole binary, a set = only those arguments.
_GIT_READS = {"status", "config", "for-each-ref", "check-ignore", "rev-parse",
              "log", "diff", "show", "ls-files", "symbolic-ref", "branch",
              "remote", "describe", "blame", "cat-file", "ls-remote", "shortlog",
              "name-rev", "merge-base", "var", "version", "--version"}
APP_NOISE = {
    "Visual Studio Code":   {"ps": None, "which": None, "git": _GIT_READS},
    "iStat Menus Menubar":  {"system_profiler": None},
    "ESET Management Agent": {"sw_vers": None, "fdesetup": {"status"}},
}
# Directory trees an app scans to inventory its own data. Matched as a SUBSTRING of the scanned
# path, per app; the counterpart of APP_NOISE for `ls -la` scans. -v lifts it.
APP_SCAN_NOISE = {
    "ESET Endpoint Security": ("/Application Support/ESET/",),
    "Qobuz":                  ("/Application Support/Qobuz/",),
    "Brave Browser":          ("/BraveSoftware/Brave-Browser/",),
}
# Tools whose directory WALK is their own implementation, already announced by the command that
# started them (`lsregister -delete -seed -r …` is followed by dozens of `ls -la`); same for the
# Finder restart an `osascript` triggers. Reads only: `lsregister` deleting the store is still the
# act it is. `-v` lifts it; `--debug` names it.
_TOOL_SCAN_NOISE = ("lsregister", "osascript")
# Standard tool/PATH directories any app pokes to locate a binary: never a reproducible step, so
# global. Not /System/Library at large: a cache dir there is the pre-delete scan we keep; only its
# SystemProfiler reporter dir is dropped.
_SCAN_NOISE_DIRS = ("/usr/bin", "/bin", "/sbin", "/usr/sbin", "/usr/libexec",
                    "/System/Library/SystemProfiler")
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}
# Commands whose only job is to prefix another: `xargs kill -9` IS a kill.
_ARG_WRAPPERS = {"xargs", "env", "nice", "nohup", "time", "sudo", "doas",
                 "caffeinate", "stdbuf", "script"}
# Which of each wrapper's flags take a VALUE, so the value is skipped with the flag. Per-wrapper:
# `sudo -i` takes none, `sudo -u` takes one.
_WRAPPER_VALUE_FLAGS = {
    "sudo":       {"-u", "-U", "-g", "-p", "-C", "-r", "-t", "--user", "--group"},
    "doas":       {"-u", "-C"},
    "xargs":      {"-I", "-L", "-n", "-P", "-s", "-a", "-E", "-d", "--replace"},
    "env":        {"-u", "-C", "-S", "--unset", "--chdir"},
    "nice":       {"-n"},
    "stdbuf":     {"-i", "-o", "-e"},
    "time":       {"-f", "-o"},
    "script":     {"-t"},
    "caffeinate": {"-t", "-w"},
}

# A shell's `-c` need not be a token of its own: `bash -lc '…'` is `bash -c '…'`. Only a cluster of
# the shell's single-letter options, and only BEFORE the first operand (`sh script.sh -clean`
# carries the SCRIPT's flag). Position does that work alone.
_SHELL_LONG_RE = re.compile(r'^--[A-Za-z][A-Za-z-]*$')
# No length cap: `-clean` and `-vxeuc` are both five letters. POSITION separates them, and the
# loop stops at the first operand.
_SHELL_OPT_RE = re.compile(r'^[-+][A-Za-z]+$')
# Long options that take a VALUE (`bash --rcfile X -c '…'`); other long options are plain switches.
_SHELL_LONG_VALUE = ("--rcfile", "--init-file", "--wordexp")
def shell_c_index(args):
    i, n = 1, len(args or ())
    while i < n:
        a = args[i]
        # Stop where a shell stops reading options: `--`, or the first non-option word. Long options
        # (`bash --login -c '…'`) are skipped.
        if a == "--" or a in ("-", "+") or not a.startswith(("-", "+")): break
        if _SHELL_LONG_RE.match(a):
            i += 2 if a in _SHELL_LONG_VALUE else 1
            continue
        if not _SHELL_OPT_RE.match(a): break
        # `c` first: in a cluster the LAST flag consumes the operand, so `-eo pipefail` skips a value while
        # `-c` claims the payload.
        if "c" in a[1:]: return i
        if "o" in a[1:]: i += 2; continue            # `-o pipefail` takes a value
        i += 1
    return -1

def noise_rule(binary, args):
    if binary not in NOISE: return False
    return triggered(NOISE[binary], args)

def payload_argv(path, args):
    # Commands that only wrap another one: `sh -c 'which ps'`, or a trampoline such as `disclaimer
    # /bin/ps …`. Reading the inner argv silences the pair with one rule. Returns the wrapped argv, or [].
    if path.rsplit("/", 1)[-1] in _SHELLS:
        i = shell_c_index(args)
        if i < 0:
            # `sh /usr/bin/man man`, `bash -pu /opt/homebrew/bin/brew shellenv` —
            # a shell invoked on a script FILE, possibly behind its own flags.
            rest = args[1:] if args else []
            while rest and rest[0].startswith("-"): rest.pop(0)
            if rest and rest[0].startswith("/"): return rest
            return []
        if i + 1 >= len(args): return []
        # With operators marked (shell_tokens), so _stages can walk a nested `sudo sh -c 'a;b'` stage by stage.
        try: toks = shell_tokens(args[i + 1])
        except ValueError: return []
        # Drop leading VAR=value assignments (`LANG= /usr/bin/fdesetup status`), but not one that runs a
        # command: `PW=$(security … -w)` IS the act.
        while (toks and not toks[0].startswith("/") and "=" in toks[0].split("/")[0]
               and not getattr(toks[0], "subs", None)):
            toks.pop(0)
        return toks
    # `env -i HOME=… /bin/bash …` buries the real command behind a wall of
    # assignments; `xargs kill -9` hides it behind flags. Unwrap either.
    _wb = path.rsplit("/", 1)[-1]
    if _wb in _ARG_WRAPPERS:
        rest = args[1:]
        _vals = _WRAPPER_VALUE_FLAGS.get(_wb, ())
        # Skip flags, their values and VAR=value assignments until the wrapped command appears. Which flags
        # take a value is per-wrapper (`sudo -i` takes none, `sudo -u` does): `sudo -u root /bin/rm -rf …`
        # must not halt the peel on `root`.
        while rest:
            if rest[0] in _vals:
                del rest[:2]; continue
            if (rest[0].startswith("-") or rest[0].isdigit() or
                    ("=" in rest[0].split("/")[0] and not rest[0].startswith("/"))):
                rest.pop(0); continue
            break
        return rest
    # A wrapper passes the real command as an absolute path in argv[1].
    if len(args) > 1 and args[1].startswith("/"): return args[1:]
    return []

_SHELL_STARTUP_FLAGS = {"-i", "-l", "-il", "-li", "-lis", "--login", "-s", "-pu", "-p"}

def is_shell_startup(path, args):
    # `/bin/zsh -il` is a terminal opening, not a command the app chose to run.
    # A shell with a script or -c has real work in it and is handled elsewhere.
    if path.rsplit("/", 1)[-1] not in _SHELLS: return False
    return all(a in _SHELL_STARTUP_FLAGS for a in args[1:]) if args else True

def noise_reason(path, args, label=""):
    # Why this command is filtered, or "" if it is not noise (--debug prints `# FILTERED: <cmd> (<reason>)`).
    # A destructive command is never noise, in ANY stage (`echo hi;rm -rf /Library/Foo`).
    if is_destructive(path, args) or destructive_stage(args): return ""
    # Per-app poll noise, arg-triggered: `git status` goes, `git commit` stays.
    _an = APP_NOISE.get(label) if label else None
    if _an:
        _jp, _ja = judged(path, args)
        _jb = _jp.rsplit("/", 1)[-1]
        if _jb in _an and triggered(_an[_jb], _ja): return "app-poll"
    if is_shell_startup(path, args): return "shell-startup"
    # An .xpc service or .appex extension is a bundle component the system launches for the app, not a
    # command it chose to run; the app-image test only recognises .app/Contents/MacOS.
    if ".xpc/Contents/MacOS/" in path: return "xpc"
    if ".appex/Contents/MacOS/" in path: return "app-extension"
    # The glue table judges a line by its FIRST command, so a marked later stage keeps the line
    # (`true&&curl …`), as does a write outside what the user can write: `echo '<plist/>' >
    # /Library/LaunchDaemons/x.plist` installs a daemon.
    if (network_stage(args) or secret_stage(args) or activation_stage(args)
            or writes_system_scope(path, args)): return ""
    b = path.rsplit("/", 1)[-1]
    if noise_rule(b, args): return _NOISE_REASON.get(b, "noise")
    # Wrappers nest (`env -i VAR=… /bin/bash -p …/brew.sh shellenv`): peel until the real command
    # appears, bounded.
    cur_path, cur_args = path, args
    for _ in range(4):
        inner = payload_argv(cur_path, cur_args)
        if not inner: return ""
        if is_destructive(inner[0], inner): return ""
        ib = inner[0].rsplit("/", 1)[-1]
        if noise_rule(ib, inner): return _NOISE_REASON.get(ib, "noise")
        cur_path, cur_args = inner[0], inner
    return ""

# ============================================================================
# RUNTIME STATE AND THE OUTPUT CHANNEL
# ============================================================================
# State that survives from one event to the next. Every dict is capped (TRACK_CAP): an ALL-mode
# capture runs for hours.

tracked = {}          # pid -> label
TRACK_CAP = 20000
last_seen = {}
DEDUP_S = 1.0

# --report: the run stays silent, distinct commands are collected with their ⚠ marks, and one report
# plus a paste-ready script is printed at stop. With --ndjson the stream stays live and the report
# goes to a file (see QUIET). Reboot-safe: each distinct command is also appended and fsync'd to an
# accumulator (CULPRIT_REPORT_FILE); the next --report launch prints the recovered report first, a
# clean stop removes it.
REPORT = os.environ.get("CULPRIT_REPORT") == "1"
REPORT_FILE = os.environ.get("CULPRIT_REPORT_FILE", "")
# --no-fold: never fold deletions — show every unlink as its own `rm -rf <file>`,
# so a destructive script gets the exact list, not the `rm -rf <dir>/*` summary.
NOFOLD = os.environ.get("CULPRIT_NOFOLD") == "1"
# --stable: one command per line, normalised, de-duplicated, sorted, nothing else, so two captures of
# identical behaviour are byte-identical and `diff` shows acts, not artefacts. Opt-in because it
# drops the caveats: it is for COMPARING runs.
STABLE = os.environ.get("CULPRIT_STABLE") == "1"
_stable_emitted = set()   # commands already printed in stable mode, across calls
_stable_hdr = False       # the --mdm header, emitted once
# --marks-only: keep only what carries a mark. Decided at render time, so no subscription changes: a
# dropped line is missing from the report, never from the capture.
MARKS_ONLY = os.environ.get("CULPRIT_MARKS") == "1"
# --no-queries: drop the lines that only read (READ_ONLY). Decided at emission, so
# live output and report agree; a run without it keeps them.
NO_QUERIES = os.environ.get("CULPRIT_NOQUERIES") == "1"
# --ndjson: the live stream as one JSON object per line. Decided at emission: a command line becomes
# a JSON object or prose, never both.
NDJSON = os.environ.get("CULPRIT_NDJSON") == "1"
# --ndjson with --report: the stream stays live and the report is accumulated by record() as usual.
# Only plain --report is silent.
QUIET = REPORT and not NDJSON
# --report-file (or --ndjson's default <log>.report.txt): where the report goes instead of stdout,
# which under --ndjson is the JSON stream.
REPORT_OUT = os.environ.get("CULPRIT_REPORT_OUT", "") if REPORT else ""
rep = []              # ordered [(cmd, destr, net, via, note, start, pid, synth, persist, secret)]
rep_seen = set()
rep_pids = set()      # pids a command was recorded under — see note_exit()
ended = {}            # pid -> when it exited
# TCC changes keyed by (service, identity): last event wins, so grant then revoke reports "denied".
rep_tcc = {}
# Login items keyed by path: FINAL state only; set on "add", deleted on "remove".
rep_btm = {}
_rep_fh = None
# Events seen but not fully readable, counted by reason: nothing observed may be missing from the
# report, so an unreadable field yields a visible count, not a wrong command or silence. eslogger is
# not an API (its man page: the structure "may change from release to release without warning").
_degraded = {}
# eslogger stamps each event with its schema_version and promises no stability across versions.
# Recorded from the first event and stated under the report.
_schema = None
def degrade(reason):
    _degraded[reason] = _degraded.get(reason, 0) + 1
    # Said once per reason as it happens (a live capture has no footer); a moved schema would otherwise
    # flood. `out` is a no-op under --report, where the footer runs.
    if _degraded[reason] == 1:
        # "C\t": the watcher keeps only C/D/R lines.
        out("C\t# NOTE: an event was observed but could not be fully read (%s). "
            "The capture is incomplete; run with --debug to see the shape." % reason)

# Set when an accumulator exists but is not trusted, so the refusal is reported.
_rep_refused = False

def _rep_open(path, flags):
    """Open the accumulator without ever following a symlink, and refuse a file
    this process does not own.

    The accumulator is replayed verbatim as a report whose entire purpose is to
    be pasted into a root shell — and the log location this very script
    recommends, /Users/Shared, is world-writable (drwxrwxrwt). Unguarded, three
    things followed: anyone could plant a `<log>.report` there and have the next
    root run render their commands as observed fact; a symlink turned the "start
    fresh" truncate into an arbitrary root truncation; and the append reached
    any file at all. O_NOFOLLOW closes the symlink, the uid check closes the
    planted file, and st_nlink closes the hard link that would sidestep both.
    """
    global _rep_refused
    try:
        fd = os.open(path, flags | os.O_NOFOLLOW, 0o600)
    except Exception:
        if os.path.lexists(path): _rep_refused = True
        return None
    try:
        st = os.fstat(fd)
        if stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and st.st_nlink == 1:
            return fd
    except Exception:
        pass
    _rep_refused = True
    try: os.close(fd)
    except Exception: pass
    return None

_NL_RE = re.compile(r'[\r\n]')
# Every OTHER C0/C1 control byte, rendered as \xNN: shlex.quote quotes a hostile filename but strips
# no byte, and a terminal obeys ESC and BS (a file name could repaint printed lines and hide a
# `⚠ destructive`). Neither contains *?[ , so cmd_quote never saw them.
_CTL_RE = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]')
def raw_out(s):
    # The transport is line-based (`read -r _k _v` in the watcher, then log_line, then syslog), so an
    # embedded newline would drop everything after it. Rendered as an escape rather than truncated:
    # complete, visibly not paste-ready; the `.report` accumulator keeps the real text. A COMMAND never
    # arrives with a control byte (shq writes `$'…'`); prose such as a path in a `#` record line or an
    # app name is guarded here.
    sys.stdout.write(_inert(s) + "\n")
    sys.stdout.flush()

def _inert(s):
    s = _NL_RE.sub(lambda m: "\\n" if m.group(0) == "\n" else "\\r", s)
    return _CTL_RE.sub(lambda m: "\\x%02x" % ord(m.group(0)), s)

def out(s):
    if QUIET: return
    raw_out(s)

# The report's sink: stdout, or with --report-file a file holding the very bytes the watcher would
# print (same escaping as raw_out, then the watcher's tab trim of the last field). Opened on the
# first report line. Root writes it, often in world-writable /Users/Shared, so the open follows no
# symlink and refuses a file it does not own or with a second hard link. Written WHOLE or not at
# all: lines go to a temporary file renamed over the path once the closing line is written
# (_rep_out_commit). An existing entry must be a plain file this run owns, with one link; the
# accumulator stays for the next launch.
_rep_out_fd = None
_rep_out_tmp = None
_rep_out_bad = False
_REPORT_END = "# ===== end of Culprit report ====="

def _rep_out_target_ok():
    try:
        st = os.lstat(REPORT_OUT)
    except FileNotFoundError:
        return True
    except Exception:
        return False
    return stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and st.st_nlink == 1

def _rep_out_refused():
    global _rep_out_bad
    _rep_out_bad = True
    sys.stderr.write("culprit: could not write the report to %s — a link, not owned by "
                     "this run, or unwritable. The accumulator is kept: the next --report "
                     "launch renders it.\n" % _inert(REPORT_OUT))

def _rep_out_get():
    global _rep_out_fd, _rep_out_tmp
    if _rep_out_fd is not None or _rep_out_bad: return _rep_out_fd
    fd = tmp = None
    try:
        if _rep_out_target_ok():
            # mkstemp: O_CREAT|O_EXCL (a planted name or link is never opened)
            # and 0600. Same directory, so the rename cannot cross a volume.
            _d, _b = os.path.split(REPORT_OUT)
            fd, tmp = tempfile.mkstemp(prefix="." + _b + ".", suffix=".part", dir=_d or ".")
            st = os.fstat(fd)
            if stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and st.st_nlink == 1:
                _rep_out_fd, _rep_out_tmp = fd, tmp
                return fd
    except Exception:
        pass
    if fd is not None:
        try: os.close(fd)
        except Exception: pass
    if tmp is not None:
        try: os.unlink(tmp)
        except Exception: pass
    _rep_out_refused()
    return None

def _rep_out_commit():
    # The file becomes the report only now; a render that never got here leaves the path as it was and
    # a `.part` beside it.
    global _rep_out_fd, _rep_out_tmp
    fd, tmp = _rep_out_fd, _rep_out_tmp
    if fd is None: return
    _rep_out_flush()
    _rep_out_fd = _rep_out_tmp = None
    ok = not _rep_out_bad
    try: os.fsync(fd)
    except Exception: ok = False
    try: os.close(fd)
    except Exception: pass
    if ok and _rep_out_target_ok():
        try:
            os.rename(tmp, REPORT_OUT)
        except Exception:
            ok = False
        else:
            try:
                _dfd = os.open(os.path.dirname(REPORT_OUT) or ".", os.O_RDONLY)
                try: os.fsync(_dfd)
                finally: os.close(_dfd)
            except Exception: pass
            return
    try: os.unlink(tmp)
    except Exception: pass
    if not _rep_out_bad: _rep_out_refused()

def rep_out(s):
    global _rep_out_bad
    if not REPORT_OUT:
        # Never onto the JSON stream; the shell always names a file under --ndjson, this guards a run without one.
        if not NDJSON: raw_out("C\t" + s)
        return
    if _rep_out_bad: return
    fd = _rep_out_get()
    if fd is None: return
    # Buffered: nobody reads the `.part`, and a syscall per line is costly on a large report.
    _rep_out_buf.append((_inert(s).strip("\t") + "\n").encode("utf-8", "surrogateescape"))
    if len(_rep_out_buf) >= 4096: _rep_out_flush()

_rep_out_buf = []
def _rep_out_flush():
    global _rep_out_bad
    if not _rep_out_buf: return
    data = b"".join(_rep_out_buf)
    del _rep_out_buf[:]
    if _rep_out_bad or _rep_out_fd is None: return
    try:
        while data:
            _n = os.write(_rep_out_fd, data)
            if _n <= 0: raise OSError("short write")
            data = data[_n:]
    except Exception:
        if not _rep_out_bad:
            sys.stderr.write("culprit: writing the report to %s failed — the accumulator "
                             "is kept: the next --report launch renders it.\n" % _inert(REPORT_OUT))
        _rep_out_bad = True

# --ndjson: the small, stable field set a command line becomes. Kept apart from raw_out/out, which
# carry prose `# …` lines that log_line on the zsh side wraps once as `{"type":"info", …}`. Only a
# reproducible command (emit_perm/emit_file/emit_wipe/emit) goes through json_out.
_MARK_TOKEN = {"⚠ destructive": "destructive", "⚠ network": "network",
               "⚠ persistence": "persistence", "⚠ secret": "secret",
               "⚠ system scope": "system_scope"}
# The eslogger event being handled, as ts_iso() prints it, set per event by the read loop (None
# without a usable `time`). `ts` is when the thing HAPPENED, not when it is printed.
_EV_T = None
def ev_time_iso(d):
    # eslogger's top-level `time`: ISO 8601 UTC with nanoseconds, truncated to milliseconds. Anything
    # else is None and the caller falls back to the print time.
    t = d.get("time") if isinstance(d, dict) else None
    if not isinstance(t, str): return None
    m = re.match(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?Z$", t)
    if not m: return None
    try: time.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S")
    except Exception: return None
    return m.group(1) + "." + (m.group(2) or "").ljust(3, "0")[:3] + "Z"
def ts_iso():
    # ISO 8601, UTC, millisecond precision.
    if _EV_T: return _EV_T
    t = time.time()
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + ".%03dZ" % int((t % 1) * 1000)
# Every NDJSON line goes through nd_dumps. A lone surrogate (an invalid UTF-8 byte read with
# surrogateescape, or a JSON `\ud800`) dumps as valid JSON but invalid Unicode, which a strict
# decoder refuses: U+FFFD instead. (shq already turns such bytes in a command into `$'\xff'`.)
_LONE_SURR_RE = re.compile(r'[\ud800-\udfff]')
def _nd_clean(v):
    if isinstance(v, str): return _LONE_SURR_RE.sub("\ufffd", v) if _LONE_SURR_RE.search(v) else v
    if isinstance(v, list): return [_nd_clean(x) for x in v]
    if isinstance(v, dict): return {_nd_clean(k): _nd_clean(x) for k, x in v.items()}
    return v
def nd_dumps(obj):
    return json.dumps(_nd_clean(obj), ensure_ascii=True)
def json_out(kind, label, cmd, via, marks, folded=None, actor=None, extra=None):
    if QUIET: return
    # `actor` is (pid, pidversion): the pair, not the pid, identifies a process across pid reuse and
    # is what a network flow is joined on.
    pid, pidver = actor if actor else (None, None)
    obj = {"type": "cmd", "ts": ts_iso(), "cmd": cmd, "via": via or None,
           "marks": [_MARK_TOKEN.get(m, m) for m in marks],
           "kind": kind, "app": label or None, "pid": pid, "pidver": pidver}
    if folded is not None: obj["folded"] = folded
    # Optional keys, present only when the text output prints the matching note:
    # via_helper, stdin_pipe, cwd (exec lines), verified (folded wipes).
    if extra: obj.update(extra)
    # ensure_ascii=True keeps this safe: every control byte and every codepoint above ASCII is
    # \u-escaped, so a hostile filename cannot put a raw control byte on the wire.
    raw_out("C\t" + nd_dumps(obj))

# ============================================================================
# THE REPORT — quoting, accumulation, recovery, rendering
# ============================================================================
# --report's deliverable: quoting (`cmd_quote`), collapsing two spellings of one command
# (`_report_form`), fsync'd accumulation (`record`/`_rep_write`), recovery of a killed run
# (`_read_report_file`/`recover_report`), layout (`_render_lines`). The `sleep` arithmetic is part of
# the delivered script, not of the observation.

_SHELL_OPS = "|&;<>`"
def _has_bare_operator(cmd):
    # Does this line carry a shell operator the shell would act on (pipe, separator, redirection,
    # substitution)? Those make re-quoting unsafe: shlex quotes `|` as a token of its own. The scan
    # respects quoting (`sqlite3 <db> 'delete from x;'` has no separator). Unbalanced quotes bail too.
    q = None
    i, n = 0, len(cmd)
    while i < n:
        c = cmd[i]
        if q == "'":
            if c == "'": q = None
        elif q == '"':
            if c == "\\": i += 1
            elif c == '"': q = None
        elif c in "'\"": q = c
        elif c == "\\": i += 1
        elif c in _SHELL_OPS: return True
        elif c == "$" and cmd[i + 1:i + 2] == "(": return True
        i += 1
    return q is not None

# An argument holding a control character (newline in a multi-line `sh -c`, tab, ESC) cannot go in
# single quotes without a raw byte, and raw_out would render it as a `\n` the shell does not read
# back. ANSI-C quoting (bash 3.2 and zsh) keeps the argv on one line. Only for those arguments;
# everything else keeps shlex.quote byte for byte. `'` is `\x27`, never `\'`, so scanners that see
# `$'…'` as `$` plus a single-quoted run (mdm_quotes, _has_bare_operator) still pair quotes. C1 goes
# out as UTF-8 bytes (`\u` is not in bash 3.2); so do U+2028/9, so the line stays one line everywhere.
_CTL_ANY_RE = re.compile(r'[\x00-\x1f\x7f-\x9f\u2028\u2029]')
# A non-UTF-8 argv/path byte arrives as U+DC80-U+DCFF (surrogateescape). Raw, it is a lone surrogate
# on the NDJSON wire; as `$'\xff'` it is the same argument in both and the shell reads it back.
_BADBYTE_RE = re.compile(r'[\udc80-\udcff]')
_SHQ_RE = re.compile(r'[\x00-\x1f\x7f-\x9f\u2028\u2029\ud800-\udfff]')
_LONE_RE = re.compile(r'[\ud800-\udfff]')
_ANSI_C_ESC = {"\n": "\\n", "\t": "\\t", "\r": "\\r", "\\": "\\\\", "'": "\\x27"}
def shq(s):
    if not _SHQ_RE.search(s): return shlex.quote(s)
    out = []
    for ch in s:
        if ch in _ANSI_C_ESC: out.append(_ANSI_C_ESC[ch])
        elif _BADBYTE_RE.match(ch): out.append("\\x%02x" % (ord(ch) - 0xdc00))
        elif _LONE_RE.match(ch): out.append("\\xef\\xbf\\xbd")   # any other lone surrogate: U+FFFD's bytes
        elif _CTL_ANY_RE.match(ch): out.append("".join("\\x%02x" % b for b in ch.encode("utf-8")))
        else: out.append(ch)
    return "$'" + "".join(out) + "'"

# The inverse: the body of a `$'…'` as the argument the shell hands over. ONE decoder for every
# reader: the report's re-reading (`_report_form`; shlex.split knows no `$'…'`) and the payload
# lexer. bash 3.2's set: \xHH and \NNN are BYTES, assembled then read as UTF-8 with surrogateescape
# (an invalid byte survives, never raises); an unknown escape keeps its backslash.
_ANSI_C_DEC = {"n": b"\n", "t": b"\t", "r": b"\r", "\\": b"\\", "'": b"'", '"': b'"',
               "?": b"?", "a": b"\a", "b": b"\b", "e": b"\x1b", "E": b"\x1b",
               "f": b"\f", "v": b"\v"}
_ANSI_C_TOK_RE = re.compile(r'\\x([0-9a-fA-F]{1,2})|\\([0-7]{1,3})|\\u([0-9a-fA-F]{1,4})'
                            r'|\\U([0-9a-fA-F]{1,8})|\\c([\x20-\x7e])|\\(.)|([^\\]+)|\\', re.S)
def _utf8b(s):
    # A str back to the bytes it was read from: surrogateescape undoes what
    # reading argv with it did; anything it cannot (a lone surrogate from a
    # JSON `\ud800`) is written as itself rather than raising.
    try: return s.encode("utf-8", "surrogateescape")
    except UnicodeEncodeError: return s.encode("utf-8", "surrogatepass")
def _ansi_c_decode(body):
    out = bytearray()
    for m in _ANSI_C_TOK_RE.finditer(body):
        x, o, u, U, c, e, lit = m.groups()
        if lit is not None: out += _utf8b(lit)
        elif x is not None: out.append(int(x, 16))
        elif o is not None: out.append(int(o, 8) & 0xff)
        elif u is not None or U is not None:
            cp = int(u or U, 16)
            if cp > 0x10ffff or 0xd800 <= cp <= 0xdfff: out += _utf8b(m.group(0))
            else: out += chr(cp).encode("utf-8")
        elif c is not None: out.append(0x7f if c == "?" else ord(c) & 0x1f)
        elif e is not None: out += _ANSI_C_DEC.get(e) or _utf8b("\\" + e)
        else: out += b"\\"                           # a lone trailing backslash
    return out.decode("utf-8", "surrogateescape")
# One shell word-piece per match, in the shell's own order, so a `$'` inside a
# single- or double-quoted run is never taken for an opener.
_SH_WALK_RE = re.compile(r"""'[^']*'|"(?:[^"\\]|\\.)*"|\$'((?:[^'\\]|\\.)*)'|\\.|.""", re.S)
# Without a quote or backslash, shlex.split only cuts on these four characters: same result, far
# cheaper on a large render.
_SH_WS_RE = re.compile(r'[ \t\r\n]+')
def shsplit(cmd):
    if "'" not in cmd and '"' not in cmd and "\\" not in cmd:
        return [t for t in _SH_WS_RE.split(cmd) if t]
    if "$'" not in cmd: return shlex.split(cmd)
    return shlex.split(_SH_WALK_RE.sub(
        lambda m: m.group(0) if m.group(1) is None else shlex.quote(_ansi_c_decode(m.group(1))), cmd))

_GLOB_META = "*?["
def cmd_quote(tok):
    # shlex.quote for a token from a COMMAND LINE, with glob metacharacters left outside the quotes so the
    # shell still expands them (quoted whole, `~/Library/Application Support/*/Cache` matches nothing).
    # A literal run carrying a `$` is quoted even where it needs none, so mdm_quotes can raise it to double
    # quotes. Only for command-line tokens: a path from a file EVENT is literal. And only in an ABSOLUTE
    # path: `rg --files -g '**/package.json'` is ripgrep's own pattern, which unquoted makes zsh say
    # `no matches found`.
    if not tok.startswith(("/", "~", "$")) or not any(c in tok for c in _GLOB_META):
        return _q_dollar(tok)
    out, buf = [], ""
    for ch in tok:
        if ch in _GLOB_META:
            if buf: out.append(_q_dollar(buf)); buf = ""
            out.append(ch)
        else:
            buf += ch
    if buf: out.append(_q_dollar(buf))
    return "".join(out)

def _q_dollar(s):
    # `shlex.quote` already quotes anything holding a `$`, supplying the single quotes `mdm_quotes`
    # later raises to double quotes.
    return shq(s)

def _code_operands(toks):
    # Indices of the words a shell runs as a SCRIPT: the operand of `-c` (or a
    # cluster ending in it, shell_c_index) of every shell named on the line —
    # `sh -c …`, `sudo sh -c …`, `env bash -lc …`, `launchctl asuser 501 zsh -c …`.
    out = set()
    for k, t in enumerate(toks):
        if t.rsplit("/", 1)[-1] in _SHELLS or t.rsplit("/", 1)[-1] in ("csh", "tcsh"):
            i = shell_c_index(toks[k:])
            if i > 0 and k + i + 1 < len(toks): out.add(k + i + 1)
    return out

def _report_form(cmd, literal=False):
    # Canonical form for the report: the same wipe written once as an `sh -c` payload with `~` and embedded
    # quotes and once as an expanded rm collapses to one line. Expand `~` and normalise quoting. Left
    # alone: a path with NO `~` (`~/Library` and `/Library` differ), pipelines and substitutions, and a
    # line opening with `#` (a RECORD, not a command).
    if cmd.startswith("#"): return cmd
    if _has_bare_operator(cmd): return cmd
    try: toks = shsplit(cmd)
    except Exception: return cmd
    if HOME: toks = [HOME + t[1:] if t.startswith("~/") else t for t in toks]
    # `shlex.quote` for a path from a file EVENT: it is literal, and a file named `report-2024*.log` must
    # keep its quotes, or the pasted line deletes every match as root. `cmd_quote` stays for command
    # lines, where the glob is the app's. Never for the operand of a shell's `-c` nor a word holding a
    # control character: that is a SCRIPT, its `*` is the inner shell's to expand, and a crafted file name
    # ending in a newline could become the script the report runs.
    _whole = _code_operands(toks)
    s = " ".join((shq if (literal or k in _whole or _CTL_ANY_RE.search(t))
                  else cmd_quote)(t) for k, t in enumerate(toks))
    # keep $loggedInUser / $userCache expandable
    return mdm_quotes(s)

# The accumulator is tab-separated and newline-terminated, so tabs and newlines inside a field are
# escaped (a multi-line `osascript -e` or a literal tab would otherwise split the record).
def _esc(s):
    # `\r` too: the accumulator is read in text mode, where a bare CR splits lines.
    return (s.replace("\\", "\\\\").replace("\t", "\\t")
             .replace("\n", "\\n").replace("\r", "\\r"))

def _unesc(s):
    out, i, n = [], 0, len(s)
    while i < n:
        c = s[i]
        if c == "\\" and i + 1 < n:
            nx = s[i + 1]
            out.append("\t" if nx == "t" else "\n" if nx == "n"
                       else "\r" if nx == "r" else nx)
            i += 2
        else:
            out.append(c); i += 1
    return "".join(out)

def _rep_write(s):
    global _rep_fh
    if not REPORT_FILE: return
    try:
        if _rep_fh is None:
            # FORMAT marker on a fresh file; a file without it is read verbatim (pre-escaping format). Version 3
            # marks a file that MAY hold a "T" record; _read_report_file treats 2 and 3 alike.
            fd = _rep_open(REPORT_FILE, os.O_WRONLY | os.O_CREAT | os.O_APPEND)
            if fd is None: return
            _new = True
            try: _new = os.fstat(fd).st_size == 0
            except Exception: pass
            # surrogateescape both ways (_read_report_file): a filename is bytes, and a strict encoder would raise.
            _rep_fh = os.fdopen(fd, "a", encoding="utf-8", errors="surrogateescape")
            if _new: _rep_fh.write("V\t3\n")
        _rep_fh.write(s)
        _rep_fh.flush()
        os.fsync(_rep_fh.fileno())
    except Exception: pass

def record(cmd, destr, net, via="", note="", pid=None, synth=False, persist=False,
           secret=False, literal=False):
    if not REPORT: return
    # `literal`: the line was SYNTHESISED from a file event, so `cmd_quote` must not run over it (it would
    # strip the quotes from a path containing `*` or `?`). The flag picks the quoting FUNCTION rather than
    # skipping normalisation, since `shlex.quote` protects `$loggedInUser` from word-splitting.
    cmd = _report_form(cmd, literal)
    if cmd in rep_seen: return
    # The time it was seen, so the script can reproduce the PAUSES. Appended fields keep older
    # accumulators parseable.
    _t = time.time()
    rep_seen.add(cmd)
    rep.append((cmd, destr, net, via, note, _t, pid, synth, persist, secret))
    if pid is not None: rep_pids.add(pid)
    # Five flag digits. `literal` must travel: _read_report_file re-runs _report_form on recovery. A
    # shorter record reads the missing digits as absent.
    _rep_write("%d%d%d%d%d\t%s\t%s\t%s\t%.3f\t%s\t%d\n"
               % (1 if destr else 0, 1 if net else 0, 1 if persist else 0,
                  1 if secret else 0, 1 if literal else 0,
                  _esc(cmd), _esc(via), _esc(note), _t,
                  "" if pid is None else pid, 1 if synth else 0))

def note_exit(pid):
    # When a command's process FINISHED, recorded only for pids a command was recorded under. Appended as
    # its own line: the accumulator is written once and fsync'd.
    if pid not in rep_pids or pid in ended: return
    ended[pid] = time.time()
    _rep_write("X\t%s\t%.3f\n" % (pid, ended[pid]))

def record_tcc(service, identity, right_s, reason_s, utype_s, actor_path, label=""):
    if not REPORT: return
    short = actor_path.rsplit("/", 1)[-1] if actor_path else ""
    _t = time.time()
    # Last event wins: a grant then a revoke reports "denied".
    rep_tcc[(service, identity)] = (right_s, reason_s, utype_s, short, _t, label)
    # The app label is a TRAILING field, so older "T" records still parse and older readers ignore the
    # extra column. "T" is a record type an unmodified reader would render as a bogus command; see the
    # version marker in _rep_write.
    _rep_write("T\t%s\t%s\t%s\t%s\t%s\t%s\t%.3f\t%s\n" %
               (_esc(service), _esc(identity), right_s, reason_s, utype_s, _esc(short), _t,
                _esc(label)))

def record_btm(action, path, kind_s, short, label=""):
    if not REPORT: return
    # FINAL state per path: an add later removed in the same run vanishes.
    if action == "add":
        rep_btm[path] = (kind_s, short, label)
    elif action == "remove":
        rep_btm.pop(path, None)
    # "B": a record type unknown to older readers; _read_report_file skips unknown record types. The app
    # label is a trailing fifth field (see record_tcc).
    _rep_write("B\t%s\t%s\t%s\t%s\t%s\n" % (action, _esc(path), kind_s, _esc(short), _esc(label)))

# A gap shorter than this is back-to-back process spawn, not a wait. Real pauses are 0.5-1.5 s, so
# the floor is 0.4 s and output is in tenths. Past the cap it is a human, and `sleep 600` has no place
# in a fleet script: capped, with the real figure stated.
_SLEEP_MIN = 0.4
_SLEEP_MAX = 60

def sleep_arg(gap):
    # Rounded UP, to the tenth: waiting too long is free, replaying too fast may
    # not be. A whole number of seconds prints without its ".0".
    if gap >= 10:
        n = min(math.ceil(round(gap, 6)), _SLEEP_MAX)
        return "%d" % n
    v = math.ceil(round(gap * 10, 6)) / 10.0
    return ("%d" % v) if v == int(v) else ("%.1f" % v)

def _gaps(entries, ends):
    # The wait BETWEEN two commands: from one's finish to the next's start, so a replay does not pay
    # execution time twice. Taken against the running maximum of every end so far, since what is still
    # executing is rarely the line above. A command with no seen exit falls back to its start time.
    gaps, prev_end = [], None
    for e in entries:
        st = e[5] if len(e) > 5 else None
        pid = e[6] if len(e) > 6 else None
        gaps.append(st - prev_end if (st is not None and prev_end is not None) else 0.0)
        if st is not None:
            _end = ends.get(pid) if pid is not None else None
            _end = max(_end, st) if _end is not None else st
            prev_end = _end if prev_end is None else max(prev_end, _end)
    return gaps

_WIPE_RE = re.compile(r'^(?:sudo )?rm -rf (.+)$')
def _wipe_root(cmd):
    # (path, removes_the_path_itself) for a reconstructed deletion, else None.
    # `rm -rf P` takes P with it; `rm -rf P/*` empties P and leaves it standing,
    # which is why the two are not interchangeable here.
    m = _WIPE_RE.match(cmd)
    if not m: return None
    rest = m.group(1)
    star = rest.endswith("/*")
    if star: rest = rest[:-2]
    try: toks = shsplit(rest)
    except ValueError: return None
    return (toks[0], not star) if len(toks) == 1 else None

def _covers(outer, inner):
    q, whole = outer
    p = inner[0]
    return (p == q or p.startswith(q + "/")) if whole else p.startswith(q + "/")

_FOLD_N_RE = re.compile(r'(\d+) syscall deletions folded')
def _drop_subsumed(entries):
    # One tree-wipe can be flushed as several summaries, each naming a path inside the next; streaming
    # cannot know that, the finished report can. Culprit's own reconstructions only: a `rm -rf` the app
    # ran stays whatever contains it.
    roots = [(_wipe_root(e[0]) if (len(e) > 7 and e[7]) else None) for e in entries]
    # Looked up by path, not pairwise (n²). What can cover p is p itself (a whole wipe) or a prefix of p
    # ending before a `/`: exactly _covers, read the other way.
    by_root = {}
    for j, b in enumerate(roots):
        if b is not None: by_root.setdefault(b[0], []).append((j, b[1]))
    inside = []
    for i, a in enumerate(roots):
        if a is None or not by_root:
            inside.append([]); continue
        p = a[0]
        hits = [j for j, whole in by_root.get(p, ()) if whole and j != i]
        k = p.find("/")
        while k != -1:
            hits.extend(j for j, _ in by_root.get(p[:k], ()) if j != i)
            k = p.find("/", k + 1)
        inside.append(sorted(set(hits)))
    drop = set(i for i, c in enumerate(inside) if c)
    # A dropped line's count goes to the line that SURVIVES to describe it, never to another dropped
    # one. If nothing survives to carry it, the line stays.
    keep, folded = [], {}
    for i in range(len(entries)):
        if i not in drop:
            keep.append(i); continue
        j = next((j for j in inside[i] if j not in drop), None)
        if j is None:
            drop.discard(i); keep.append(i); continue
        m = _FOLD_N_RE.search(entries[i][4] or "")
        folded[j] = folded.get(j, 0) + (int(m.group(1)) if m else 1)
    out = []
    for i in keep:
        e = entries[i]
        if i in folded:
            # The survivor swallowed those deletions too, so its count says so.
            m = _FOLD_N_RE.search(e[4] or "")
            if m:
                n = int(m.group(1)) + folded[i]
                e = e[:4] + (_FOLD_N_RE.sub("%d syscall deletions folded" % n, e[4]),) + e[5:]
        out.append(e)
    return out

# Per-run randomness, normalised so two captures of identical behaviour compare equal: mktemp's own
# suffix, which survives --mdm. ONE entry on purpose: normalising decides two things are the same,
# and too much of it hides a real difference. ANCHORED ON THE TEMP ROOT, not on a name shape: a path
# under the per-user temp root is per-run by construction; outside it nothing is touched
# (`~/Documents/tmp.backup2024` and `…2025` are different directories).
_SCRATCH_ROOT = (r'(?:(?:/private)?/var/folders/[^/\s"\']+/[^/\s"\']+/[0CT]'
                 r'|\$userTemp|\$userCache|\$userDir)')
_SCRATCH_PATH_RE = re.compile(_SCRATCH_ROOT + r'((?:/[^/\s"\']+)*)')
# `<name>.<random>` with an optional trailing suffix: `bac.A20DvY`, `tmp.ELw4ROZqmb.noindex`.
_MKTEMP_SEG_RE = re.compile(r'^([A-Za-z0-9_-]{1,32})\.([A-Za-z0-9]{6,})((?:\.[A-Za-z0-9]+)*)$')

def _looks_random(s):
    # A mktemp suffix is drawn from [A-Za-z0-9]; an English word is not, so all-lowercase letters are
    # refused (`cache/settings/vendor`). A missed suffix costs a line of diff noise, a false collapse
    # costs an observed act.
    return (not s.islower()) or any(c.isdigit() for c in s)

def _stable_form(cmd):
    def _seg(part):
        m = _MKTEMP_SEG_RE.match(part)
        if m and _looks_random(m.group(2)):
            return m.group(1) + ".XXXXXX" + m.group(3)
        return part
    # EVERY segment under the root, at any depth.
    return _SCRATCH_PATH_RE.sub(
        lambda m: m.group(0)[:len(m.group(0)) - len(m.group(1))]
                  + "".join("/" + _seg(x) for x in m.group(1).split("/")[1:]),
        cmd)

# Rolls the marked persistence entries up by WHERE they land (named from the same roots
# `is_persistence` matched), answering "what still comes back after a reboot?": `cp x y.plist` and
# the `chmod 644 y.plist` below it are one INSTALL.
_PERSIST_KIND = (("/Library/LaunchDaemons/", "LaunchDaemon"),
                 ("/Library/LaunchAgents/", "LaunchAgent"),
                 ("/Library/PrivilegedHelperTools/", "privileged helper"),
                 ("/Library/StartupItems/", "StartupItem"),
                 ("/Library/SystemExtensions/", "system extension"),
                 ("/Library/Extensions/", "kext"))
def _persist_kind(path):
    for _root, _kind in _PERSIST_KIND:
        if _root in path: return _kind
    if path.startswith(("/usr/local/bin/", "/usr/local/sbin/")): return "PATH binary"
    if is_etc_persistence(path): return "/etc re-exec"
    return "persistence"

def _persist_target(cmd):
    # The destination is the last operand that matches: cp/mv/ln/chmod/chown/ditto name their target last.
    try:
        _toks = shsplit(cmd)
    except ValueError:
        return ""
    _hit = ""
    for _t in _toks:
        if is_persistence(_t) or is_persistence(_t.rstrip("/") + "/"):
            _hit = _t
    return _hit

def _persist_path(t):
    return bool(t) and (is_persistence(t) or is_persistence(t.rstrip("/") + "/"))

def _persist_placements(cmd):
    # [(path, tool)]: where this command line puts something a reboot brings back, and which stage put it there.
    _out, _fallback = [], []
    for _jp, _ja, _redirs in _stages(shell_tokens(cmd)):
        _b = _jp.rsplit("/", 1)[-1]
        for _op, _tgt in _redirs:
            if ">" in _op and _persist_path(_tgt):
                _out.append((_tgt, _b or "shell redirection"))
        if _b in _COPIERS and places_persistence(_ja):
            _out.append((placed_dest(_ja), _b))
        elif _b and _b != "launchctl":
            _hit = ""
            for _t in _ja[1:]:
                if isinstance(_t, str) and _persist_path(_t): _hit = _t
            if _hit: _fallback.append((_hit, _b))
    return _out or _fallback[-1:]

def _persist_cmd_removed(cmd):
    # A path this run installed can also leave: the same final-state rule record_btm applies to a login item.
    try:
        _toks = _peel_asuser([t for t in shsplit(cmd) if t != "sudo"])
    except ValueError:
        return ""
    if not _toks or _toks[0].rsplit("/", 1)[-1] not in ("rm", "mv"):
        return ""
    return _persist_target(cmd)

def _persist_is_activation(cmd):
    # The leading verb decides, `sudo` aside. A line that also copies (`cp … && launchctl load …`) leads with
    # the copy and keeps its rollup item.
    try:
        _toks = _peel_asuser([t for t in shsplit(cmd) if t != "sudo"])
    except ValueError:
        return False
    return bool(_toks) and _toks[0].rsplit("/", 1)[-1] == "launchctl"

def _peel_asuser(toks):
    # `launchctl asuser 501 cp x y.plist` leads with launchctl but is a cp; judged() peels it the same way.
    for _ in range(8):
        if not toks or toks[0].rsplit("/", 1)[-1] != "launchctl": break
        inner = _asuser_inner(toks)
        if not inner: break
        toks = [t for t in inner if t != "sudo"]
    return toks

def _persist_actor(entry, tool=""):
    # The `via` the entry already carries, else the tool of the stage that placed it (the convention of
    # emit_file/emit_perm).
    _via = entry[3] if len(entry) > 3 else ""
    if _via: return _via
    if tool: return tool
    _toks = [t for t in entry[0].split() if t != "sudo" and not t.startswith("#")]
    return _toks[0].rsplit("/", 1)[-1] if _toks else "?"

def _persist_rollup_lines(entries, btm):
    # Final state, not "ever installed": a path placed and later removed (rm, unlink, rename away) is dropped.
    _persist_items = {}
    for e in entries:
        if len(e) > 8 and e[8]:
            # `launchctl load`/`bootstrap`/`enable` starts a job and installs nothing: the rollup is keyed on
            # what landed.
            if _persist_is_activation(e[0]): continue
            for _pp, _tool in _persist_placements(e[0]):
                if _pp and _pp not in _persist_items:
                    _persist_items[_pp] = (_persist_kind(_pp), _persist_actor(e, _tool))
            continue
        if not _persist_items: continue
        _rm = _persist_cmd_removed(e[0])
        if _rm and _rm in _persist_items:
            del _persist_items[_rm]
    _btm_items = sorted((btm or {}).items())   # [(path, (kind, short[, label])), …]
    _n_persist = len(_persist_items) + len(_btm_items)
    if not _n_persist: return []
    _lines = ["# What survives a reboot (%d):" % _n_persist]
    for _pp in sorted(_persist_items):
        _pk, _pa = _persist_items[_pp]
        _lines.append("#   %s: %s — via %s" % (_pk, _pp, _pa))
    for _pp, _bv in _btm_items:
        # (kind, short[, label]); the label is optional.
        _kind_s, _short = _bv[0], _bv[1]
        _blbl = _bv[2] if len(_bv) > 2 else ""
        _lines.append("#   Login item (%s): %s — via %s%s"
                       % (_kind_s, mdm_rewrite(_pp), _short or "?", _app_suffix(_blbl)))
    return _lines

def _tcc_lines_for(tcc):
    if not tcc: return []
    # Final state only: the last event per (service, identity), as rep_tcc/record_tcc apply live. A grant then a
    # revoke reports "denied".
    _lines = ["# Privacy (TCC) changes (%d):" % len(tcc)]
    for _svc, _id in sorted(tcc):
        _tv = tcc[(_svc, _id)]
        _right, _reason, _utype, _short = _tv[0], _tv[1], _tv[2], _tv[3]
        _tlbl = _tv[5] if len(_tv) > 5 else ""
        # A path identity (identity_type 1) can sit in a home: --mdm rewrites it at render time; the
        # accumulator keeps the raw one.
        _id = mdm_rewrite(_id)
        if STABLE:
            # reason and update_type say how a grant arrived, not what the current state is.
            _lines.append("#   %s: %s -> %s%s"
                           % (_svc, _id, _right, _app_suffix(_tlbl)))
        else:
            _via = " — via %s" % _short if _short else ""
            _lines.append("#   %s: %s -> %s (%s, %s)%s%s"
                           % (_svc, _id, _right, _reason, _utype, _via, _app_suffix(_tlbl)))
    return _lines

def _render_lines(entries, recovered, ends=None, tcc=None, btm=None):
    # `tcc`/`btm` default to the live globals; a recovery passes what _read_report_file rebuilt from the
    # accumulator.
    tcc = rep_tcc if tcc is None else tcc
    btm = rep_btm if btm is None else btm
    entries = _drop_subsumed(entries)
    # Marks are indexed on the entry: destructive, network, persistence, secret. Anything carrying one survives.
    if MARKS_ONLY:
        entries = [e for e in entries if (len(e) > 1 and e[1]) or (len(e) > 2 and e[2])
                   or (len(e) > 8 and e[8]) or (len(e) > 9 and e[9])]
    rout = rep_out
    # Computed once for STABLE and the full report: a privacy grant and what survives a reboot are state, not a
    # step whose wording drifts run to run.
    _persist_lines = _persist_rollup_lines(entries, btm)
    _tcc_lines = _tcc_lines_for(tcc)
    if STABLE:
        # A recovery is a truncated capture: the run was killed before it could render.
        global _stable_emitted, _stable_hdr
        if recovered:
            rout("# culprit: WARNING: recovered from an interrupted run — this capture is PARTIAL")
        if MDM and not _stable_hdr:
            _stable_hdr = True
            for _l in _MDM_HEADER: rout(_l)
        _fresh = sorted(set(_stable_form(e[0]) for e in entries) - _stable_emitted)
        _stable_emitted |= set(_fresh)
        for _c in _fresh: rout(_c)
        # Persistence and TCC sections are never stripped: a stable fleet audit diffs them for drift.
        for _l in _persist_lines: rout(_l)
        for _l in _tcc_lines: rout(_l)
        # A capture that saw nothing must not look like a dead parser; the line opens with `#`, so the contract
        # holds.
        if not _fresh and not _stable_emitted and not _persist_lines and not _tcc_lines:
            rout("# (nothing captured)")
        return
    _tag = " (recovered from an interrupted run — e.g. a reboot)" if recovered else ""
    rout("# ===== Culprit report%s — %d distinct command%s =====" %
         (_tag, len(entries), "" if len(entries) == 1 else "s"))
    for _title, _idx in (("⚠ destructive", 1), ("⚠ network", 2),
                         ("⚠ persistence", 8), ("⚠ secret", 9)):
        _hits = [e[0] for e in entries if len(e) > _idx and e[_idx]]
        if _hits:
            rout("# %s (%d):" % (_title, len(_hits)))
            for c in _hits: rout("#   %s" % c)
    for _l in _persist_lines: rout(_l)
    for _l in _tcc_lines: rout(_l)
    if entries:
        rout("")
        rout("# " + "=" * 76)
        rout("# ===== REPRODUCIBLE SCRIPT (in order) — copy from here to 'end of script' =====")
        rout("# " + "=" * 76)
        # --mdm rewrites user paths into variables; the script is runnable only if it defines them first.
        if MDM:
            for _l in _mdm_script_header([e[0] for e in entries]): rout(_l)
        # Trailing comments carry what the live stream prints under a line: the actor when it is a tool the app
        # ran (`via lsregister`), and the notes that decide whether the line can be replayed.
        _gp = _gaps(entries, ends or {})
        if any(g >= _SLEEP_MIN for g in _gp):
            rout("# NOTE: a `sleep` line is time nothing was RUNNING — measured from the end of the")
            rout("#   command above it to the start of the next, so a slow command's own execution")
            rout("#   is not counted twice. What is left is the app waiting for an effect, or you")
            rout("#   at the keyboard. Keep them: waiting too long is safe, replaying too fast is not.")
        for _e, _gap in zip(entries, _gp):
            c, v, nt = _e[0], _e[3], (_e[4] if len(_e) > 4 else "")
            if _gap >= _SLEEP_MIN:
                rout("sleep %s%s" % (sleep_arg(_gap),
                                     "   # observed %ds, capped" % int(_gap)
                                     if _gap > _SLEEP_MAX else ""))
            _bits = ([("via %s" % v)] if v else []) + ([nt] if nt else [])
            rout(c + ("   # " + " — ".join(_bits) if _bits else ""))
        rout("# ===== end of script =====")
        rout("")
    elif not tcc and not btm:
        # A filter (--marks-only) can be what emptied the report: say so instead of "nothing captured".
        rout("# (nothing carried a mark)" if MARKS_ONLY else "# (nothing captured)")
    if _schema is not None and not STABLE:
        rout("# eslogger schema_version: %s" % _schema)
    if _degraded and not STABLE:
        rout("")
        rout("# ⚠ %d event(s) were observed but could not be fully read:"
             % sum(_degraded.values()))
        for _r in sorted(_degraded):
            rout("#   %d x %s" % (_degraded[_r], _r))
        rout("#   The capture is incomplete by that much. If this is a new macOS,")
        rout("#   eslogger's event shape has moved — run with --debug to see it.")

def _read_report_file(path):
    entries, seen, ends, tcc, btm = [], set(), {}, {}, {}
    escaped = False
    try:
        _fd = _rep_open(path, os.O_RDONLY)
        if _fd is None: return entries, ends, tcc, btm
        with os.fdopen(_fd, encoding="utf-8", errors="surrogateescape") as f:
            for line in f:
                p = line.rstrip("\n").split("\t")
                if len(p) < 2: continue
                if p[0] == "V":                     # format marker, see _rep_write
                    # Versions 2 and 3 both escape (see _rep_write); 3 only adds the "T" record type.
                    escaped = len(p) > 1 and p[1] in ("2", "3")
                    continue
                if p[0] == "X":                     # a process finished
                    try: ends[int(p[1])] = float(p[2])
                    except (ValueError, IndexError): pass
                    continue
                if p[0] == "T":                     # a TCC change — see record_tcc()
                    if len(p) < 8: continue
                    _svc, _id, _short = p[1], p[2], p[6]
                    if escaped:
                        _svc, _id, _short = _unesc(_svc), _unesc(_id), _unesc(_short)
                    try: _tt = float(p[7]) if p[7] else None
                    except ValueError: _tt = None
                    # The last event per (service, identity) wins, as in the live rep_tcc; p[8] (app label) is
                    # optional.
                    _tlbl = p[8] if len(p) > 8 else ""
                    if escaped: _tlbl = _unesc(_tlbl)
                    tcc[(_svc, _id)] = (p[3], p[4], p[5], _short, _tt, _tlbl)
                    continue
                if p[0] == "B":                     # a login item add/remove — see record_btm()
                    if len(p) < 5: continue
                    _act, _bpath, _kind_s, _bshort = p[1], p[2], p[3], p[4]
                    _blbl = p[5] if len(p) > 5 else ""
                    if escaped:
                        _bpath, _bshort, _blbl = _unesc(_bpath), _unesc(_bshort), _unesc(_blbl)
                    if _act == "add":
                        btm[_bpath] = (_kind_s, _bshort, _blbl)
                    elif _act == "remove":
                        btm.pop(_bpath, None)
                    continue
                # A record type this reader does not recognise — never read as a command line.
                if len(p[0]) == 1 and p[0].isalpha() and p[0] not in ("V", "X", "T", "B"):
                    continue
                if escaped:
                    p[1] = _unesc(p[1])
                    if len(p) > 2: p[2] = _unesc(p[2])
                    if len(p) > 3: p[3] = _unesc(p[3])
                # As in record(): a line flagged as synthesised is taken verbatim; re-quoting it would strip the
                # quotes from a path that holds a glob character.
                _c = _report_form(p[1], p[0][4:5] == "1")
                if _c in seen: continue
                seen.add(_c); p[1] = _c
                try: _t = float(p[4]) if len(p) > 4 and p[4] else None
                except ValueError: _t = None
                try: _pid = int(p[5]) if len(p) > 5 and p[5] else None
                except ValueError: _pid = None
                entries.append((p[1], p[0][:1] == "1", p[0][1:2] == "1",
                                p[2] if len(p) > 2 else "", p[3] if len(p) > 3 else "",
                                _t, _pid, len(p) > 6 and p[6] == "1",
                                p[0][2:3] == "1", p[0][3:4] == "1"))
    except Exception: pass
    return entries, ends, tcc, btm

def recover_report():
    # At startup: a non-empty accumulator from a previous --report run means it was interrupted before it could
    # render. Print it, then clear it.
    if not (REPORT and REPORT_FILE): return
    # lexists, not exists: a dangling symlink is the shape being guarded against, and exists() reports it absent.
    try:
        if not os.path.lexists(REPORT_FILE): return
    except Exception: return
    ents, ends, tcc, btm = _read_report_file(REPORT_FILE)
    if _rep_refused:
        # Said out loud: silence would look like a clean previous stop.
        rep_out("# WARNING: an accumulator at %s was refused — a symlink, or not "
                "owned by this run. Nothing was recovered from it, and it was left "
                "untouched." % REPORT_FILE)
        return
    # `or tcc or btm`: a run that saw only TCC changes or login items still has something to recover.
    if ents or tcc or btm: _render_lines(ents, True, ends, tcc, btm)
    _fd = _rep_open(REPORT_FILE, os.O_WRONLY | os.O_TRUNC)   # start fresh
    if _fd is not None:
        try: os.close(_fd)
        except Exception: pass

def render_report():
    if not REPORT: return
    _render_lines(rep, False, ended, rep_tcc, rep_btm)
    # Here and not in _render_lines: a recovery renders twice into one report, and this line proves the whole
    # report was written.
    rep_out(_REPORT_END)
    _rep_out_commit()
    if REPORT_FILE and not _rep_out_bad:
        try: os.remove(REPORT_FILE)        # clean stop: nothing left to recover
        except Exception: pass

# ============================================================================
# JUDGING A COMMAND LINE — what it really is, under its wrappers
# ============================================================================
# A rule is evaluated against the real command, not its wrapper: `sh -c 'rm -rf …'` is an rm, `xargs kill -9`
# is a kill. `judged()` peels wrappers; `_stage_hit()` walks every pipeline stage. The destructive, network
# and secret tables read through it.

def judged(path, args):
    # The command a rule is evaluated against. Display keeps the wrapper; the destructive flag and the note come
    # from the command inside it.
    p, a = path, args
    for _ in range(4):
        b = p.rsplit("/", 1)[-1]
        # `launchctl asuser UID cmd…` runs cmd in that user's context. Peeled like sudo, so a cp into
        # ~/Library/LaunchAgents is judged as the cp.
        inner = _asuser_inner(a) if b == "launchctl" else None
        if inner is None:
            if b not in _SHELLS and b not in _ARG_WRAPPERS: break
            inner = payload_argv(p, a)
        if not inner: break
        p, a = inner[0], inner
    return p, a

def _asuser_inner(args):
    # The argv `launchctl asuser UID …` runs, [] when it names none, or None when this launchctl is not an asuser.
    ops = [x for x in args[1:] if not x.startswith("-")]
    if not ops or ops[0] != "asuser": return None
    return list(args[args.index("asuser", 1) + 2:])

_PY_SHIM_RE = re.compile(r'^python[\d.]*$')
def dedup_name(argv0):
    # /usr/bin/python3 is a shim that re-execs Xcode's Python: one invocation, two events, argv[0] changing name
    # and case.
    b = argv0.rsplit("/", 1)[-1]
    return "python" if _PY_SHIM_RE.match(b.lower()) else b

# ============================================================================
# SHELL STAGES — a command line cut where the shell cuts it
# ============================================================================
# Every mark is judged stage by stage. shlex.split cuts on whitespace only (`echo hi; rm -rf /x` would be one
# stage), so shell_tokens() reads a payload the way sh does: quotes, escapes, `$(…)` and backquotes kept whole,
# operators split out even when glued. _stages() is the one walk every stage-based rule goes through.

class _Op(str):
    # An operator the shell acts on: `;`, `&&`, `|`, `>`, `2>&`, a newline.
    __slots__ = ()

class _Word(str):
    # A word holding a command substitution: `.subs` are the bodies it runs.
    bare = None

def _bare_len(t):
    b = getattr(t, "bare", None)
    return len(t) if b is None else b

# Longest first, so `&&` is never read as two `&` and `2>&1` as a `>` and a `&`.
_OPS = ("<<<", "<<-", "&>>", ";;&", "&&", "||", ";;", ";&", "|&", "&>", ">>", ">&",
        ">|", "<<", "<&", "<>", ";", "&", "|", "(", ")", ">", "<")
_OP_CHARS = frozenset(";&|()<>")
_STAGE_SEPS = {"|", "|&", "||", "&&", ";", "&"}      # as plain argv tokens (find's `;`)
_CASE_ENDS = frozenset({";;", ";&", ";;&"})
_SEP_OPS = frozenset(_STAGE_SEPS | _CASE_ENDS | {"(", ")", "\n"})
_REDIRECTS = (">", ">>", ">|", "&>", "&>>", ">&", "<>")
# Reserved words that open a stage without being its command: judge what follows (`if …; then rm -rf /x; fi`).
_SH_KEYWORDS = frozenset({"if", "then", "else", "elif", "fi", "do", "done", "while",
                          "until", "!", "{", "}", "esac",
                          "exec", "command", "builtin", "coproc"})
_SH_KW_OPTS = {"exec": {"-a": 1, "-c": 0, "-l": 0}, "command": {"-p": 0}}

# The scanners below each take the index of an opening character and return the index just past its closing one,
# raising ValueError when there is none.
def _sq_end(s, i):                 # '…'
    k = s.find("'", i + 1)
    if k < 0: raise ValueError("No closing quotation")
    return k + 1

def _ansi_end(s, i):               # $'…', where \' does not close it
    j, n = i + 2, len(s)
    while j < n:
        if s[j] == "\\": j += 2; continue
        if s[j] == "'": return j + 1
        j += 1
    raise ValueError("No closing quotation")

def _bq_end(s, i):                 # `…`, where \` does not close it
    j, n = i + 1, len(s)
    while j < n:
        if s[j] == "\\": j += 2; continue
        if s[j] == "`": return j + 1
        j += 1
    raise ValueError("No closing backquote")

def _dq_end(s, i):                 # "…", with $(…), `…` and ${…} inside it
    j, n = i + 1, len(s)
    while j < n:
        d = s[j]
        if d == "\\": j += 2; continue
        if d == '"': return j + 1
        if d == "$" and s.startswith("$(", j): j = _subst_end(s, j + 1); continue
        if d == "$" and s.startswith("${", j): j = _brace_end(s, j); continue
        if d == "`": j = _bq_end(s, j); continue
        j += 1
    raise ValueError("No closing quotation")

def _brace_end(s, i):              # ${…}, quotes inside it respected
    j, n = i + 2, len(s)
    while j < n:
        d = s[j]
        if d == "\\": j += 2; continue
        if d == "}": return j + 1
        if d == "'": j = _sq_end(s, j); continue
        if d == '"': j = _dq_end(s, j); continue
        if d == "`": j = _bq_end(s, j); continue
        if d == "$" and s.startswith("$(", j): j = _subst_end(s, j + 1); continue
        if d == "$" and s.startswith("${", j): j = _brace_end(s, j); continue
        j += 1
    raise ValueError("No closing brace")

def _heredoc_skip(s, i, delim, dash):
    n = len(s)
    while i < n:
        j = s.find("\n", i); j = n if j < 0 else j
        line = s[i:j]; i = j + 1
        if (line.lstrip("\t") if dash else line) == delim: return min(i, n)
    return n

_HD_DELIM_RE = re.compile(r'<<(-?)[ \t]*((?:[^\s;&|()<>\\\'"]|\\.|\'[^\']*\'|"[^"]*")+)')
def _subst_end(s, i):
    # s[i] is the "(" of `$(`, `<(` or `>(`; the index just past its ")".
    depth, j, n = 0, i, len(s)
    heredocs = []
    while j < n:
        d = s[j]
        if d == "\\": j += 2; continue
        if d == "'": j = _sq_end(s, j); continue
        if d == '"': j = _dq_end(s, j); continue
        if d == "`": j = _bq_end(s, j); continue
        if d == "$" and s.startswith("$'", j): j = _ansi_end(s, j); continue
        if d == "$" and s.startswith("${", j): j = _brace_end(s, j); continue
        if d == "#" and (j == 0 or s[j - 1] in " \t\n;&|("):
            k = s.find("\n", j); j = n if k < 0 else k; continue
        # A here-string is one word, not a here-document: step over it whole, or its `<<` would start a body.
        if d == "<" and s.startswith("<<<", j): j += 3; continue
        if d == "<" and s.startswith("<<", j):
            m = _HD_DELIM_RE.match(s, j)
            if m:
                heredocs.append((re.sub(r'[\'"\\]', "", m.group(2)), m.group(1) == "-"))
                j = m.end(); continue
        if d == "\n" and heredocs:
            j += 1
            for delim, dash in heredocs: j = _heredoc_skip(s, j, delim, dash)
            heredocs = []; continue
        if d == "(": depth += 1
        elif d == ")":
            depth -= 1
            if depth == 0: return j + 1
        j += 1
    raise ValueError("No closing parenthesis")

def _bq_body(raw):
    # Inside backquotes `\$`, `` \` `` and `\\` lose their backslash.
    return re.sub(r'\\([$`\\])', r'\1', raw)

def _lex(s):
    toks, buf, subs = [], [], []
    have = False                   # a word is open, even an empty '' one
    heredocs = []                  # index in toks of a `<<` awaiting its body
    i, n = 0, len(s)
    # How the shell read the open word: `bare` characters unquoted before the first piece that was not (quote,
    # escape, `$'…'`, `${…}`, a substitution), and `still_bare` while no such piece has come.
    bare, still_bare = 0, True
    def flush():
        nonlocal have, bare, still_bare
        if have:
            w = "".join(buf)
            # A word that merely spells a separator (`-s ';'`, find's `\;`) is a _Word, so _stages never cuts on
            # it; only a plain str from an eslogger argv (find's own `;`) is a separator there.
            if subs or w in _STAGE_SEPS or not still_bare:
                w = _Word(w); w.subs = tuple(subs)
                if not still_bare: w.bare = bare
            toks.append(w)
        buf.clear(); subs.clear(); have = False
        bare, still_bare = 0, True
    def subst(j, k, body):         # copy `$(…)` whole into the word, keep its body
        nonlocal have, still_bare
        buf.append(s[j:k]); subs.append(body); have = True; still_bare = False
    while i < n:
        c = s[i]
        if c in " \t\r":
            flush(); i += 1; continue
        if c == "\n":
            flush(); toks.append(_Op("\n")); i += 1
            for h in heredocs:
                d = toks[h + 1] if h + 1 < len(toks) and not isinstance(toks[h + 1], _Op) else None
                if d is not None: i = _heredoc_skip(s, i, d, toks[h] == "<<-")
            heredocs.clear()
            continue
        if c == "#" and not have:
            j = s.find("\n", i); i = n if j < 0 else j; continue
        if c == "\\":
            if i + 1 >= n: raise ValueError("No escaped character")
            if s[i + 1] != "\n": buf.append(s[i + 1]); have = True
            still_bare = False; i += 2; continue
        if c == "'":
            k = _sq_end(s, i); buf.append(s[i + 1:k - 1]); have = True
            still_bare = False; i = k; continue
        if c == "$" and s.startswith("$'", i):             # ANSI-C quoting
            # The decoder the report uses too (_ansi_c_decode): `\x27` and `\101` are bytes.
            k = _ansi_end(s, i)
            buf.append(_ansi_c_decode(s[i + 2:k - 1]))
            have = True; still_bare = False; i = k; continue
        if c == "$" and s.startswith('$"', i):             # locale quoting: a "…"
            i += 1; continue
        if c == '"':
            i += 1; have = True; still_bare = False
            while True:
                if i >= n: raise ValueError("No closing quotation")
                d = s[i]
                if d == '"': i += 1; break
                if d == "\\" and i + 1 < n and s[i + 1] in '"\\$`\n':
                    if s[i + 1] != "\n": buf.append(s[i + 1])
                    i += 2; continue
                if d == "$" and s.startswith("$(", i):
                    k = _subst_end(s, i + 1); subst(i, k, s[i + 2:k - 1]); i = k; continue
                if d == "$" and s.startswith("${", i):
                    k = _brace_end(s, i); buf.append(s[i:k]); i = k; continue
                if d == "`":
                    k = _bq_end(s, i); subst(i, k, _bq_body(s[i + 1:k - 1])); i = k; continue
                buf.append(d); i += 1
            continue
        if c == "$" and s.startswith("$(", i):
            k = _subst_end(s, i + 1); subst(i, k, s[i + 2:k - 1]); i = k; continue
        if c == "$" and s.startswith("${", i):
            k = _brace_end(s, i); buf.append(s[i:k]); have = True
            still_bare = False; i = k; continue
        if c == "`":
            k = _bq_end(s, i); subst(i, k, _bq_body(s[i + 1:k - 1])); i = k; continue
        if c in "<>" and s.startswith("(", i + 1):          # process substitution
            k = _subst_end(s, i + 1); subst(i, k, s[i + 2:k - 1]); i = k; continue
        if c in _OP_CHARS:
            fd = ""
            if c in "<>" and have and not subs and buf and "".join(buf).isdigit():
                fd = "".join(buf); buf.clear(); have = False
            flush()
            op = next(o for o in _OPS if s.startswith(o, i))
            if op in ("<<", "<<-"): heredocs.append(len(toks))
            toks.append(_Op(fd + op)); i += len(op); continue
        buf.append(c); have = True; i += 1
        if still_bare: bare += 1
    flush()
    return tuple(toks)

def _split_ops(run):
    out, i = [], 0
    while i < len(run):
        if run[i] == "\n": out.append(_Op("\n")); i += 1; continue
        op = next(o for o in _OPS if run.startswith(o, i))
        out.append(_Op(op)); i += len(op)
    return out

_FALLBACK_RE = re.compile(r"\n|[;&|()<>]+|[^\s;&|()<>]+")
def _tokens(s):
    # RecursionError too: deeply nested `"$(` must not skip the event.
    try: return _lex(s)
    except (ValueError, RecursionError): pass
    toks = None
    if len(s) <= 65536:
        try:
            lx = shlex.shlex(s, posix=True, punctuation_chars=";&|()<>\n")
            lx.whitespace = " \t\r"; lx.whitespace_split = True; lx.commenters = ""
            toks = list(lx)
        except ValueError:
            toks = None
    if toks is None: toks = _FALLBACK_RE.findall(s)
    out = []
    for t in toks:
        if t and set(t) <= set(";&|()<>\n"): out.extend(_split_ops(t))
        else:
            # How the shell would read these words is unknown, so none is bare: no `{a,b}` or `~` is expanded.
            w = _Word(t); w.subs = (); w.bare = 0
            out.append(w)
    return tuple(out)

# Cached, because one event tokenises the same payload several times (every rule walks it).
_tokens_small = functools.lru_cache(maxsize=512)(_tokens)
_tokens_big = functools.lru_cache(maxsize=2)(_tokens)

def shell_tokens(s):
    # A shell payload as tokens, operators as _Op. Never raises: a line _lex cannot read falls back to a coarser
    # split (see _tokens).
    return list(_tokens_small(s) if len(s) <= 8192 else _tokens_big(s))

def _is_assign(t):
    return not t.startswith(("/", "-")) and "=" in t.split("/")[0]

def _stages(argv, path0=None, depth=0):
    # Every command a line runs, as (path, args, redirections): cut at the shell's list and pipeline operators,
    # leading reserved words and VAR=value assignments dropped, wrappers peeled by judged(), redirections lifted
    # out of args as (op, target).
    if depth > 8:
        # Nested past what is followed: a stage no rule knows, so it is never taken for a query and never marked.
        if argv: yield ("?", ["?"], [])
        return
    stage, redirs, first = [], [], True
    case_n, in_pat, in_test = 0, False, False
    toks = list(argv)
    i, n = 0, len(toks)
    while i <= n:
        t = toks[i] if i < n else None
        is_op = isinstance(t, _Op)
        if in_pat:
            # `case … in start|reboot)`: a pattern is matched, never run; skip its words up to `)`.
            if is_op and t == ")": in_pat = False
            elif t == "esac" and not is_op: in_pat = False; case_n -= 1
            i += 1; continue
        if in_test:
            # Inside `[[ … ]]` the shell's operators are the test's own syntax: `=~ ^(reboot|shutdown)$` is a
            # pattern, not a pipeline. Only a substitution in it runs.
            if t is None or (t == "]]" and not is_op):
                in_test = False
                if t is not None: stage.append(t); i += 1
                continue
            for body in getattr(t, "subs", ()) if not is_op else ():
                yield from _stages(shell_tokens(body), None, depth + 1)
            i += 1; continue
        if t == "[[" and not is_op:
            stage.append(t); in_test = True
            i += 1; continue
        if (t == "in" and not is_op and len(stage) >= 2 and stage[-2] == "case"
                and all(w in _SH_KEYWORDS for w in stage[:-2])):
            stage, in_pat, first = [], True, False; case_n += 1
            i += 1; continue
        # A separator is an _Op from shell_tokens, or a plain str from an eslogger argv (find's own `;`), never
        # a _Word that only spells one (`-s ';'`).
        if t is None or (t in _SEP_OPS if is_op else (type(t) is str and t in _STAGE_SEPS)):
            j = 0
            while j < len(stage) and (stage[j] in _SH_KEYWORDS or _is_assign(stage[j])
                                      or stage[j] == "function"):
                if stage[j] == "esac" and case_n: case_n -= 1
                if stage[j] == "function": j += 2; continue
                _kopts = _SH_KW_OPTS.get(stage[j])
                j += 1
                # `exec -a name rm`, `command -p rm`: the options they take. An unlisted option (`command -v rm`
                # only prints a path) stays, so the stage is judged as `-v …`, not as the rm.
                while _kopts and j < len(stage) and stage[j] in _kopts:
                    j += 1 + _kopts[stage[j]]
            words = stage[j:]
            if words and words[0] == "eval" and len(words) > 1:
                yield from _stages(shell_tokens(" ".join(words[1:])), None, depth + 1)
                if redirs: yield ("", [], redirs)
            elif words:
                p = path0 if (first and j == 0 and path0) else words[0]
                jp, ja = judged(p, words)
                _jb = jp.rsplit("/", 1)[-1]
                # Descend when judged() unwrapped something that is itself more than one command: a nested
                # payload's operators or substitutions, or a wrapper left by judged()'s depth limit.
                if ja is not words and (_jb in _SHELLS or _jb in _ARG_WRAPPERS or any(
                        isinstance(a, _Op) or getattr(a, "subs", None) for a in ja)):
                    yield from _stages(ja, jp, depth + 1)
                    if redirs: yield ("", [], redirs)
                else:
                    yield (jp, ja, redirs)
            elif redirs:
                yield ("", [], redirs)             # `> /Library/x` alone writes it
            stage, redirs, first = [], [], False
            if is_op and case_n and t in _CASE_ENDS: in_pat = True
            i += 1; continue
        if is_op:                                  # a redirection and its target
            tgt = toks[i + 1] if i + 1 < n and not isinstance(toks[i + 1], _Op) else ""
            redirs.append((str(t), tgt))
            for body in getattr(tgt, "subs", ()):
                yield from _stages(shell_tokens(body), None, depth + 1)
            i += 2 if tgt else 1; continue
        stage.append(t)
        for body in getattr(t, "subs", ()):
            yield from _stages(shell_tokens(body), None, depth + 1)
        i += 1

def destructive_stage(argv):
    for jp, ja, _r in _stages(argv):
        if jp and is_destructive(jp, ja): return (jp, ja)
    return None

# Network reach: "is it phoning home?". Only what an app shells out to is visible; an app fetching through its
# own code (URLSession) is not.
_NETWORK = {
    "curl": None, "wget": None, "nc": None, "ncat": None, "scp": None,
    "sftp": None, "ssh": None, "sshpass": None, "nscurl": None,
    # rsync has a local mode (`rsync -a src dst` reaches nothing): flagged only with a remote operand.
    "rsync": {"~^[^/]+:"},
    "ftp": None, "tftp": None, "telnet": None, "socket": None,
    "aria2c": None, "axel": None, "httpie": None,
    # Name resolution and reachability: a beacon can be a DNS lookup and nothing more.
    "dig": None, "nslookup": None, "host": None, "ping": None, "ping6": None,
    "traceroute": None, "traceroute6": None,
    # Package managers fetch: only the fetching subcommands, so a local build or status query stays unflagged.
    "git":  {"clone", "fetch", "pull", "push", "ls-remote"},
    "pip":  {"install", "download"}, "pip3": {"install", "download"},
    "npm":  {"install", "i", "ci", "publish"}, "yarn": {"add", "install"},
    "gem":  {"install", "fetch", "push"}, "cargo": {"install", "fetch"},
    "go":   {"get", "mod"},
    "softwareupdate": {"-i", "--install", "-d", "--download", "-l", "--list"},
    "mas": {"install", "upgrade", "lucky"},
    "installer": {"~^https?://"}, "open": {"~^https?://"},
}
# Credential reach — "does this line hand a secret to whoever runs it?".
_SECRET = {
    "security": {"-w", "dump-keychain", "export", "unlock-keychain"},
    "dscl": {"ShadowHashData", "AuthenticationAuthority"},
    "gh": {"token"},
}

_KNOWN_CMDS = ((set(DESTRUCTIVE) | set(NOISE) | set(_NETWORK) | set(_SECRET)
                | _COPIERS | _REMOVERS | _PERM_CMDS) - _SHELLS - _ARG_WRAPPERS)

def _stage_hit(argv, table):
    # Does any pipeline stage match this rule table? `pgrep x | xargs security … -w` reads a keychain even
    # though its leading command does not.
    for jp, ja, _r in _stages(argv):
        b = jp.rsplit("/", 1)[-1]
        if b in table and triggered(table[b], ja): return True
    return False

def network_stage(argv): return _stage_hit(argv, _NETWORK)
def secret_stage(argv):  return _stage_hit(argv, _SECRET)

# Queries — lines that only READ, dropped under --no-queries.
READ_ONLY = {
    "defaults": {"read", "read-type", "domains", "find"},   # never `export`: it writes
    "system_profiler": None, "sw_vers": None, "uname": None, "locale": None,
    "id": None, "whoami": None, "groups": None,
    "sysctl": {"-n", "-a", "~^[a-z_]+(\\.[A-Za-z0-9_]+)+$"},  # a name, never `k=v`
    "df": None, "du": None, "ls": None, "stat": None,
    "diskutil": {"info", "list", "listSnapshots", "listCryptoUsers", "listUsers"},
    "plutil": {"-p", "-lint", "-type", "-extract"},
    "fdesetup": {"status", "isactive", "list"},
    "csrutil": {"status"},
    "spctl": {"--status", "--assess"},
    "socketfilterfw": {"--get*", "--listapps"},
    "nvram": {"-p"},
    "mdutil": {"-s"},
    "dscl": {"-read", "-list", "-search"},
    # launchctl(1)'s inspection verbs, judged in _query_stage on the first operand only, since a service or
    # label can be named anything (`launchctl remove list`).
    "launchctl": {"print", "print-cache", "print-disabled", "list", "blame",
                  "dumpstate", "procinfo", "hostinfo", "resolveport", "plist",
                  "getenv", "error", "variant", "version", "managerpid",
                  "manageruid", "managername", "bslist", "help"},
    "awk": None, "grep": None, "egrep": None, "cut": None, "head": None,
    "tail": None, "sort": None, "uniq": None, "wc": None, "tr": None, "sed": None,
    "true": None, ":": None,
}
# An output file makes any of them a write: `plutil -extract … -o k.txt`, `sort -o`. `-o -` is stdout. An awk
# program can write too, through `>` or system().
_QUERY_AWK_WRITES = re.compile(r'system\s*\(|print[^|;}]*>|\|\s*"')

def _query_stage(stage):
    toks = list(stage)
    while toks and not toks[0].startswith(("/", "-")) and "=" in toks[0].split("/")[0]:
        toks.pop(0)                                 # `bootDisk=$(…)` — glue
    if not toks: return True
    jp, ja = toks[0], toks
    b = jp.rsplit("/", 1)[-1]
    # judged() peels `xargs <cmd>` to <cmd>, so an xargs still standing has no command: it runs echo.
    if b == "xargs": return True
    # Any other wrapper or shell still standing is one _stages could not see into: not a query.
    if b in _SHELLS or b in _ARG_WRAPPERS: return False
    if b not in READ_ONLY: return False
    for i, a in enumerate(ja):
        if a in ("-o", "--output") and (i + 1 >= len(ja) or ja[i + 1] != "-"): return False
    if b == "awk" and any(_QUERY_AWK_WRITES.search(a) for a in ja[1:]): return False
    if b == "plutil" and "-extract" in ja and "-o" not in ja: return False
    # `uniq in out`: no `-o`; the second operand is the output. `-f`/`-s` take a numeric value, not an operand.
    if b == "uniq":
        _ops, _skip = 0, False
        for a in ja[1:]:
            if _skip: _skip = False; continue
            if a in ("-f", "-s"): _skip = True; continue
            if not a.startswith("-"): _ops += 1
        if _ops > 1: return False
    trig = READ_ONLY[b]
    if trig is None: return True
    flags = {t for t in trig if t.startswith("-")}
    words = trig - flags
    ops = [a for a in ja[1:] if not a.startswith("-")][:2]
    if b == "launchctl": return bool(ops) and ops[0] in words
    return triggered(flags, ja) or triggered(words, [b] + ops)

def is_query(cmd, argv, is_payload):
    if is_payload:
        try: toks = shell_tokens(cmd)
        except ValueError: return False
    else:
        toks = list(argv)
    if not toks: return False
    # Walks _stages as every mark does: `defaults read x;rm -f y` is two stages, glued `;` or not.
    for jp, ja, redirs in _stages(toks):
        for op, tgt in redirs:
            if ">" not in op: continue                # <, <<, <&: input only
            # `2>&1` duplicates a descriptor; `>& file` writes one, in zsh as in csh.
            _dup = op.endswith("&") and (tgt.isdigit() or tgt == "-")
            if not (_dup or tgt == "/dev/null" or tgt.startswith("&")): return False
        if jp and not _query_stage(ja): return False
    return True

def effective(path, args):
    payload = shell_payload(path, args)
    if payload:
        # shell_tokens, not shlex.split: a glued `;` must reach the stage rules as an operator (see _stages).
        try: toks = shell_tokens(payload)
        except ValueError: toks = []
        # An assignment that runs a command (`ip=$(curl …)`) is kept, so its substitution's mark survives.
        while (toks and not toks[0].startswith("/") and "=" in toks[0].split("/")[0]
               and not getattr(toks[0], "subs", None)):
            toks.pop(0)
        if toks: return toks[0], toks, payload
    return path, args, payload

def shell_payload(path, args):
    # The command string inside `sh -c '…'`. A shell-out reaches us twice: once as the shell, once as what it
    # becomes.
    if path.rsplit("/", 1)[-1] not in _SHELLS: return ""
    i = shell_c_index(args)
    if i < 0: return ""
    return args[i + 1] if i + 1 < len(args) else ""

# ============================================================================
# PAIR FOLDING — one act that reaches us as two execs
# ============================================================================
# Distinct from ABSORPTION above, which folds an event into a command. Here both halves are execs: a
# wrapper and what it becomes, a pattern and its expansion, a command substitution and its body. The first
# form is kept (the portable one); the second becomes a note or nothing. Both windows are named five-second
# limits, so a pair cannot join two separate acts.

pending_glob = {}     # (label, binary) -> (prefixes, time, real_glob, n_globs, n_paths)

def payload_covers(payload, args, _depth=0):
    # Is this bare command already covered by the printed shell payload? Compared as tokens, never text:
    # the payload keeps the app's quoting while the exec carries the shell's unquoted argv.
    if not payload or not args: return False
    # shell_tokens, operators dropped: a glued `echo a|launchctl load X` must still cover the bare
    # `launchctl load X`.
    toks = [t for t in shell_tokens(payload) if not isinstance(t, _Op)]
    if _depth < 8:
        for t in toks:
            for body in getattr(t, "subs", ()):
                if payload_covers(body, args, _depth + 1): return True
    want = [args[0].rsplit("/", 1)[-1]] + list(args[1:])
    n = len(want)
    # The words as written, then as the shell expands braces: `rm -rf /tmp/{a,b}` execs `rm -rf /tmp/a /tmp/b`.
    # Both are tried — a quoted brace stays literal (_brace_words).
    _cands = [(toks, None)]
    _ex, _made = [], []
    for t in toks:
        _w = _brace_words(t)
        _ex.extend(_w); _made.extend([_w[0] is not t] * len(_w))
    if len(_ex) != len(toks): _cands.append((_ex, _made))
    for cand, made in _cands:
        if n > len(cand): continue
        for i in range(len(cand) - n + 1):
            if made and made[i]: continue
            if cand[i].rsplit("/", 1)[-1] == want[0] and all(
                    _tok_eq(p, a) for p, a in zip(cand[i + 1:i + n], want[1:])):
                return True
    return False

def _brace_split(w):
    # (prefix, [alternatives], suffix) of the first `{…}` in w that the shell would expand — a matching `}` and a
    # comma at its own depth — or None.
    i, n = w.find("{"), len(w)
    while i >= 0:
        depth, commas, j = 0, [], i
        while j < n:
            ch = w[j]
            if ch == "{": depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0: break
            elif ch == "," and depth == 1: commas.append(j)
            j += 1
        if j < n and commas:
            cuts = [i] + commas + [j]
            return (w[:i], [w[cuts[k] + 1:cuts[k + 1]] for k in range(len(cuts) - 1)],
                    w[j + 1:])
        i = w.find("{", i + 1)
    return None

_BRACE_MAX_LISTS = 8
def _brace_words(t, _cap=64):
    # A word with a `{a,b}` list as the shell would hand it to the command: one word per alternative, nested lists
    # in the shell's order (`{a,{b,c}}` is a b c), or [t] itself.
    if getattr(t, "bare", None) is not None or getattr(t, "subs", None): return [t]
    if "{" not in t or "," not in t or "$" in t: return [t]
    if t.count("{") > _BRACE_MAX_LISTS: return [t]
    try:
        out, work, steps = [], [str(t)], 0
        while work:
            w = work.pop()
            sp = _brace_split(w)
            if sp is None:
                out.append(w)
                if len(out) > _cap: return [t]
                continue
            steps += 1
            pre, alts, post = sp
            if steps > _cap or len(alts) > _cap: return [t]
            work.extend(pre + a + post for a in reversed(alts))
        return out if len(out) > 1 else [t]
    except Exception:
        return [t]

_SUBST_BODY_RE = re.compile(r'\$\(([^()]*)\)|`([^`]*)`')
def payload_substitutes(payload, args):
    # A command substitution runs as its own process and arrives as its own exec (`pkill -U $(whoami) …` then a
    # bare `whoami`): a fragment of the line already printed, like a pipeline stage.
    for m in _SUBST_BODY_RE.finditer(payload or ""):
        body = m.group(1) or m.group(2) or ""
        if body and payload_covers(body, args): return True
    return False

_SUBST_RE = re.compile(r'\$\(|`|\$\w|\$\{')
def _tok_eq(p, a):
    # A payload token holding a substitution or a variable cannot be compared to what the shell resolved it to:
    # `pkill -U $(whoami) nsurlstoraged` arrives as `pkill -U ard nsurlstoraged`.
    if _SUBST_RE.search(p): return True
    if p == a: return True
    return bool(HOME) and (p == "~" or p.startswith("~/")) \
        and _bare_len(p) >= min(len(p), 2) and HOME + p[1:] == a

# A shell line is printed whole, then every command inside it execs and arrives on its own — `diskutil info / |
# awk …` followed by a bare `diskutil info /`.
pending_shell = {}    # label -> [(payload, time)], most recent last
_PENDING_SHELL_S = 5.0
_PENDING_SHELL_MAX = 256
# The same bound for the glob pair: past a few seconds, two `rm` lines from one app are two acts.
_PENDING_GLOB_S = 5.0

def _remember_payload(label, text, now):
    # What this command is about to become, so the exec that arrives next folds into it instead of printing a
    # second time.
    _lst = [x for x in pending_shell.get(label, ()) if x[1] >= now - _PENDING_SHELL_S]
    _lst.append((text, now))
    del _lst[:-_PENDING_SHELL_MAX]
    pending_shell[label] = _lst
    if len(pending_shell) > 500: pending_shell.clear()

# Both take the judged argv: on `sh -c 'rm -rf ~/x/*'` the raw args are the shell's.
def has_glob(args):
    return any("*" in a or "?" in a or a.startswith("~") for a in args[1:])

def glob_count(args):
    return sum(1 for a in args[1:] if "*" in a or "?" in a or a.startswith("~"))

def glob_dirs(args):
    # The LITERAL prefix of each pattern — everything before its first glob character, tilde EXPANDED — which an
    # expanded path must therefore start with.
    out = []
    for a in args[1:]:
        if "*" in a or "?" in a or a.startswith("~"):
            i = min((a.index(c) for c in "*?[" if c in a), default=len(a))
            d = a[:i]
            # Expand the tilde, never strip it: stripping turns `~/Library/Caches` into the system path
            # /Library/Caches.
            if d.startswith("~"):
                if not HOME: continue
                d = HOME + d[1:]
            if d and d not in out: out.append(d)
    return out

# ============================================================================
# EMISSION — turning what happened into a line that can be pasted
# ============================================================================
# Four emitters, one per kind of act: `emit` for a command, `emit_file` for a file
# operation, `emit_perm` for a permission change, `emit_wipe` for a folded tree
# deletion. They share one contract — decide `sudo`, apply --mdm, mark, record for
# the report, print — and the marks are computed before `record`, so the report and
# the live stream can never disagree about a line. `flush_deletes` sits here too.

seen_apps = set()     # labels already announced as started
helper_noted = set()  # labels that already got the "runs as root" note
scope_noted = set()   # …and those told their commands write outside the user's reach

# System scope = the user cannot write there without root, so reproducing the act needs sudo.
# /private/var/folders is per-user; /opt/homebrew belongs to the installing user.
_USER_WRITABLE = ("/Users/", "/tmp/", "/private/tmp/", "/var/folders/",
                  "/private/var/folders/", "/Volumes/", "/opt/homebrew/")
_SYSTEM_ROOTS = ("/System/", "/Library/", "/usr/", "/bin/", "/sbin/",
                 "/Applications/", "/opt/", "/etc/", "/private/etc/",
                 "/var/", "/private/var/")
def system_scope(path):
    if not path: return False
    # Another account's home is not this user's to write: a root helper touching /Users/other/Library needs
    # `sudo`.
    if path.startswith("/Users/"):
        if not HOME.startswith("/Users/"): return False
        if path == HOME or path.startswith(HOME + "/"): return False
        return not path.startswith("/Users/Shared/")
    if path.startswith(_USER_WRITABLE): return False
    return path.startswith(_SYSTEM_ROOTS)

_COPY_READS_SRC = {"cp", "ln", "rsync", "ditto", "install"}
_SCOPE_WRITERS = _PERM_CMDS | _REMOVERS | {"mv", "touch", "mkdir", "tee", "dd"}
# launchctl writes launchd's state, not a file, so its operands are no path test. The system domain is a
# privileged execution context (launchctl(1)).
_LAUNCHCTL_DOMAIN_VERBS = {"bootstrap", "bootout", "enable", "disable", "kickstart", "kill"}
def launchctl_needs_root(args, _depth=0):
    ops, skip = [], False
    for a in args[1:]:
        if skip: skip = False; continue
        if a in ("-S", "-D"): skip = True; continue
        if not a.startswith("-"): ops.append(a)
    if not ops: return False
    verb = ops[0]
    if verb == "asuser":
        # `asuser UID command…`: the inner command is judged like any other. Bounded, so a long chain of
        # `asuser 1 launchctl asuser 1 …` cannot exhaust the stack.
        inner = args[args.index("asuser", 1) + 2:]
        return (bool(inner) and _depth < 8
                and writes_system_scope(inner[0], inner, _depth + 1))
    if verb in _LAUNCHCTL_DOMAIN_VERBS:
        return any(o == "system" or o.startswith("system/") for o in ops[1:])
    if verb in ("load", "unload"):
        return any(system_scope(o) and "/LaunchAgents/" not in o for o in ops[1:])
    return False

def writes_system_scope(path, args, _depth=0):
    # Stage by stage, like every mark (_stages): `echo hi ; rm -f /Library/Foo/x` writes in its second stage.
    for p, a, redirs in _stages(args, path):
        # A redirection lands wherever it points, whatever ran it, and names no writing command.
        if any(op.lstrip("0123456789") in _REDIRECTS and system_scope(t)
               for op, t in redirs):
            return True
        if not p: continue
        b = p.rsplit("/", 1)[-1]
        if b == "launchctl":
            if launchctl_needs_root(a, _depth): return True
            continue
        if b in _COPY_READS_SRC:
            if system_scope(placed_dest(a)): return True
            continue
        if b in _SCOPE_WRITERS or is_destructive(p, a):
            if any(x.startswith("/") and system_scope(x) for x in a[1:]): return True
    return False

dir_children = {}     # directory -> how many of its files we saw deleted
listed_dirs = {}      # directory -> when we reported listing it
# Bundle suffixes whose enumeration is machinery: frameworks loaded by dyld, plug-ins and reporters scanned at
# startup. .app is handled separately: its own directory stays visible, only what is inside it is dropped.
_CODE_BUNDLES = (".framework", ".bundle", ".plugin", ".spreporter", ".kext",
                 ".xpc", ".appex", ".qlgenerator", ".mdimporter", ".prefPane",
                 ".saver", ".component", ".audiounit", ".vst", ".vst3")
file_noted = set()    # labels already told these are reconstructed commands

perm_noted = set()    # labels already told these are reconstructed commands
def emit_perm(label, cmd, destr, path, kind, via="", actor=None):
    scoped = system_scope(path)
    if scoped and not cmd.startswith("#"): cmd = "sudo " + cmd
    cmd = mdm_rewrite(cmd)
    # Never say "via chmod" on a line that is a chmod; `sudo` comes off before the comparison.
    _tool = cmd.split()
    _tool = _tool[1] if _tool[:1] == ["sudo"] else (_tool[0] if _tool else "")
    via = via if via and via != _tool.lstrip("#") else ""
    key = label + "\x00" + cmd
    now = time.time()
    if key in last_seen and now - last_seen[key] < DEDUP_S: return
    if len(last_seen) > TRACK_CAP: last_seen.clear()
    last_seen[key] = now
    # A permission change on a launch-item or helper location must reach the report's `⚠ persistence` section.
    _persist = is_persistence(path)
    _marks = ((["⚠ destructive"] if destr else [])
              + (["⚠ system scope"] if scoped else [])
              + (["⚠ persistence"] if _persist else []))
    record(cmd, destr, False, via, persist=_persist, literal=True)
    mdm_header()
    if NDJSON:
        json_out(kind, label, cmd, via, _marks, actor=actor)
        return
    if SOLO:
        out("C\t%s%s" % (cmd, ("   # " + " ".join(_marks)) if _marks else ""))
    else:
        out("C\t# %s changed permissions:%s" % (label,
            ("  " + "  ".join(_marks)) if _marks else ""))
        out("C\t%s" % cmd)
    if via: out("C\t# via %s" % via)
    if label not in perm_noted:
        perm_noted.add(label)
        out("C\t# NOTE: changed through a system call, not by running this command — the line above reproduces it")

xattr_noted = set()   # labels already told these are reconstructed commands
def emit_xattr(label, cmd, path, name, via="", actor=None):
    scoped = system_scope(path)
    if scoped and not cmd.startswith("#"): cmd = "sudo " + cmd
    cmd = mdm_rewrite(cmd)
    _tool = cmd.split()
    _tool = _tool[1] if _tool[:1] == ["sudo"] else (_tool[0] if _tool else "")
    via = via if via and via != _tool.lstrip("#") else ""
    key = label + "\x00" + cmd
    now = time.time()
    if key in last_seen and now - last_seen[key] < DEDUP_S: return
    if len(last_seen) > TRACK_CAP: last_seen.clear()
    last_seen[key] = now
    _persist = is_persistence(path)
    _marks = ((["⚠ system scope"] if scoped else [])
              + (["⚠ persistence"] if _persist else []))
    record(cmd, False, False, via, persist=_persist, literal=True, synth=True)
    mdm_header()
    if NDJSON:
        json_out("deleteextattr", label, cmd, via, _marks, actor=actor)
        return
    if SOLO:
        out("C\t%s%s" % (cmd, ("   # " + " ".join(_marks)) if _marks else ""))
    else:
        out("C\t# %s removed an extended attribute:%s" % (label,
            ("  " + "  ".join(_marks)) if _marks else ""))
        out("C\t%s" % cmd)
    if via: out("C\t# via %s" % via)
    # com.apple.quarantine is the one attribute whose removal means something specific enough to say in words:
    # Gatekeeper no longer treats this file as downloaded from the internet.
    if name == "com.apple.quarantine":
        out("C\t# NOTE: this file's Gatekeeper quarantine was lifted — it will now open without the \"unidentified developer\" warning")
    if label not in xattr_noted:
        xattr_noted.add(label)
        out("C\t# NOTE: removed through a system call, not by running this command — the line above reproduces it")

_VERB_TOOL = {"moved": "mv", "listed": "ls", "opened": "cat", "deleted": "rm",
              "copied": "cp", "linked": "ln"}
# --ndjson's "kind" for emit_file: the eslogger event behind each verb (EVENT_TYPES). "copied" covers a clone
# and a plain copy; clone is the one subscribed.
_VERB_KIND = {"deleted": "unlink", "moved": "rename", "copied": "clone",
              "linked": "link", "listed": "readdir", "opened": "open"}
_WRITE_VERBS = ("deleted", "moved", "copied", "linked")
_DESTRUCTIVE_VERBS = ("deleted", "moved")
_VERB_SAID = {"deleted": "removed", "moved": "moved",
              "copied": "copied", "linked": "hard-linked"}
def emit_file(label, verb, path, dst="", via="", actor=None):
    if verb == "moved":
        cmd = "mv %s %s" % (shq(path), shq(dst))
    elif verb == "copied":
        # -R because the source may be a directory and a clone takes the tree with it; harmless on a single file.
        cmd = "cp -R %s %s" % (shq(path), shq(dst))
    elif verb == "linked":
        cmd = "ln %s %s" % (shq(path), shq(dst))
    elif verb == "listed":
        cmd = "ls -la %s" % shq(path)
    elif verb == "opened":
        cmd = "cat %s" % shq(path)
    else:
        cmd = "rm -rf %s" % shq(path)
    writing = verb in _WRITE_VERBS
    if verb == "moved":
        scoped = system_scope(path) or system_scope(dst)
    else:
        _target = dst if verb in ("copied", "linked") and dst else path
        scoped = writing and system_scope(_target)
    if scoped: cmd = "sudo " + cmd
    cmd = mdm_rewrite(cmd)
    # Name the actor only when it is not the app itself and not the tool we are already reconstructing (a
    # `/bin/rm` delete need not say "via rm").
    via = via if via and via != _VERB_TOOL.get(verb) else ""
    key = label + "\x00" + cmd
    now = time.time()
    if key in last_seen and now - last_seen[key] < DEDUP_S: return
    if len(last_seen) > TRACK_CAP: last_seen.clear()
    last_seen[key] = now
    _persist = verb in ("moved", "copied", "linked") and is_persistence(dst)
    _marks = []
    if scoped: _marks.append("⚠ system scope")
    if _persist: _marks.append("⚠ persistence")
    # --no-queries, as in emit(): a reconstruction that only reads (`ls` from a readdir, `cat` from an open) is
    # dropped; every write verb stays.
    if NO_QUERIES and not writing:
        debug_filtered("%s (query)" % cmd)
        return
    record(cmd, verb in _DESTRUCTIVE_VERBS, False, via,
           synth=(verb == "deleted"), persist=_persist, literal=True)
    mdm_header()
    if NDJSON:
        # record() is the truth on whether this verb destroys; _marks omits it (the header names the verb), but a
        # structured feed has no header, so it is added back.
        _jmarks = _marks + (["⚠ destructive"] if verb in _DESTRUCTIVE_VERBS else [])
        json_out(_VERB_KIND.get(verb, "unlink"), label, cmd, via, _jmarks, actor=actor)
        return
    if SOLO:
        out("C\t%s%s" % (cmd, ("   # " + " ".join(_marks)) if _marks else ""))
    else:
        out("C\t# %s %s:%s" % (label, verb,
                               ("  " + "  ".join(_marks)) if _marks else ""))
        out("C\t%s" % cmd)
    if via: out("C\t# via %s" % via)
    if _persist:
        # Said every time, not once per app: this is the line an audit is for. It records the act; the temp
        # source is gone.
        out("C\t# NOTE: software installing itself here — a launch item, a helper, a binary on the PATH. The temp source is gone, so this records the act rather than reproducing it")
    # Worded from the verb and remembered per verb, so a move and a delete each get their note.
    if writing and (label, verb) not in file_noted:
        file_noted.add((label, verb))
        out("C\t# NOTE: %s through a system call, not by running this command — the line above reproduces it"
            % _VERB_SAID.get(verb, "done"))
    if verb == "deleted":
        n = dir_children.pop(path, 0)
        if n: out("C\t# NOTE: %d file%s inside it %s removed just before" % (n, "" if n == 1 else "s", "was" if n == 1 else "were"))
        parent = path.rsplit("/", 1)[0]
        if parent:
            dir_children[parent] = dir_children.get(parent, 0) + 1
            if len(dir_children) > TRACK_CAP: dir_children.clear()

# An app that wipes a cache tree through the system API (no shell command) emits one unlink per file and per
# emptied directory — dozens for a single tree. They are one act.
del_buf = []          # [(label, path, via, time, actor)] — a run of uncovered deletions

# Directories holding unrelated content. Three deletions whose only common ancestor is one of these are three
# separate acts, and `rm -rf <it>/*` would describe something no app performed.
_NEVER_FOLD = ("", "/", "/Users", "/Library", "/System", "/Applications",
               "/usr", "/var", "/private", "/private/var", "/etc",
               "/private/etc", "/tmp", "/private/tmp", "/opt", "/bin", "/sbin")
# A home and its top-level folders hold unrelated things too.
_HOME_DIR_RE = re.compile(r'^/Users/[^/]+(/(Library|Documents|Desktop|Downloads'
                          r'|Movies|Music|Pictures|Public|Applications))?$')
def foldable(d):
    if not d or d in _NEVER_FOLD: return False
    if _HOME_DIR_RE.match(d): return False
    return d.count("/") >= 2

def dir_state(d, t0):
    try:
        with os.scandir(d) as it:
            for e in it:
                try: born = e.stat(follow_symlinks=False).st_birthtime
                except Exception: return "kept"
                if born < t0: return "kept"
        return "empty"
    except Exception:
        return "unknown"

def emit_wipe(label, root, n, via="", whole=False, verified=False, actor=None):
    # As in emit_file: never say "via rm" on a line that is an rm. Same table.
    via = via if via and via != _VERB_TOOL["deleted"] else ""
    # A summary of a syscall tree-wipe. `/*` (outside the quotes so the shell still globs it) empties the
    # directory without removing it.
    cmd = ("rm -rf %s" if whole else "rm -rf %s/*") % shq(root)
    scoped = system_scope(root)
    if scoped: cmd = "sudo " + cmd
    cmd = mdm_rewrite(cmd)
    now = time.time()
    key = label + "\x00" + cmd
    if key in last_seen and now - last_seen[key] < DEDUP_S: return
    last_seen[key] = now
    record(cmd, True, False, via,
           ("%d syscall deletions folded; %s verified empty afterwards" %
            (n, "removed" if whole else "left")) if verified else
           ("⚠ approximate: %d syscall deletions folded — --no-fold gives the exact list" % n),
           # Not literal: the trailing `/*` is an intended glob that shlex.quote would swallow. The root is
           # quoted before it gets here, and cmd_quote keeps that.
           synth=True)
    mdm_header()
    if NDJSON:
        json_out("unlink", label, cmd, via,
                 ["⚠ destructive"] + (["⚠ system scope"] if scoped else []),
                 folded=n, actor=actor, extra={"verified": bool(verified)})
        return
    if SOLO:
        out("C\t%s%s" % (cmd, "   # ⚠ system scope" if scoped else ""))
    else:
        out("C\t# %s deleted:%s" % (label, "  ⚠ system scope" if scoped else ""))
        out("C\t%s" % cmd)
    if via: out("C\t# via %s" % via)
    if verified:
        # Verified, not inferred: nothing predating the wipe survived, so the line is an exact reproduction.
        out("C\t# NOTE: %d entries erased %s by direct system calls (no shell command) — %s"
            % (n, "with it" if whole else "under it",
               "the directory is gone" if whole else "the directory was left empty"))
    else:
        out("C\t# NOTE: SUMMARY of %d entries erased %s by direct system calls (no shell command) — approximate, run with --no-fold for the exact per-file list"
            % (n, "with it" if whole else "under it"))

def flush_deletes():
    global del_buf, _EV_T
    if not del_buf: return
    buf, del_buf = del_buf, []
    seen, order, labels = set(), [], []
    acts = {}   # (label, path) -> (pid, pidversion) of the first deletion seen
    evts = {}   # (label, path) -> the first deletion's own event time (ts)
    for l, p, v, t, a, e in buf:
        if (l, p) in seen: continue
        seen.add((l, p)); order.append((l, p, v, t)); acts[(l, p)] = a; evts[(l, p)] = e
        if l not in labels: labels.append(l)
    for lbl in labels:
        items = [(p, v, t) for l, p, v, t in order if l == lbl]
        vias = dict((p, v) for p, v, _ in items)
        stamps = dict((p, t) for p, _, t in items)
        paths = [p for p, _, _ in items]
        rest, folds, blocked = list(paths), [], set()
        # A true fold (>=3 siblings gone) that is unsafe to glob: a survivor predating the run would be taken
        # by `rm -rf <dir>/*` too.
        near_miss, _nm_seen = [], set()
        members = {}
        # Pass 1, repeated: the DEEPEST directory covering three or more of what is left summarises them.
        while True:
            cand = {}
            for p in rest:
                d = p
                while "/" in d and d != "/":
                    d = d.rsplit("/", 1)[0]
                    if foldable(d): cand[d] = cand.get(d, 0) + 1
            best = ""
            for d, n in cand.items():
                if n < 3 or d in blocked: continue
                if not best or (d.count("/"), n) > (best.count("/"), cand[best]): best = d
            if not best: break
            covered = [p for p in rest if p == best or p.startswith(best + "/")]
            # A direct child whose name starts with a dot is not covered by `<dir>/*`.
            _whole = best in covered
            _dotted = [] if _whole else [
                p for p in covered
                if p != best
                and p[len(best):].lstrip("/").split("/")[0].startswith(".")]
            if _dotted:
                covered = [p for p in covered if p not in _dotted]
                if len(covered) < 3:
                    blocked.add(best); continue
            # Inspect before summarising: a directory still holding files the app did not touch is not reported
            # as emptied.
            state = dir_state(best, min(stamps[p] for p in covered))
            if state == "kept":
                blocked.add(best)
                _key = frozenset(covered)
                if _key not in _nm_seen:
                    _nm_seen.add(_key)
                    near_miss.append((best, covered))
                continue
            members[best] = set(covered)
            folds.append((best, len(covered), best in covered, state == "empty"))
            rest = [p for p in rest if p not in covered]
        # Pass 2: a deleted directory subsumes the paths beneath it.
        rest = [p for p in rest if not any(q != p and p.startswith(q + "/") for q in rest)]
        folds = [f for f in folds
                 if not any(f[0] == q or f[0].startswith(q + "/") for q in rest)]
        done = set()
        nm_dir, nm_n = {}, {}
        for d, covered in near_miss:
            nm_n[d] = len(covered)
            for p in covered:
                nm_dir.setdefault(p, d)
        nm_done = set()
        for p in paths:
            f = next((x for x in folds if p in members.get(x[0], ())), None)
            if f:
                if f[0] in done: continue
                done.add(f[0])
                _v = set(vias[q] for q in members[f[0]])
                # One process behind the whole fold names it; several do not, as `via` is only said when it is one.
                _a = set(acts[(lbl, q)] for q in members[f[0]])
                # ts = the FIRST event of the fold (ISO strings sort as times).
                _held = _EV_T
                _EV_T = min((evts[(lbl, q)] for q in members[f[0]] if evts[(lbl, q)]), default=None)
                try:
                    emit_wipe(lbl, f[0], f[1], _v.pop() if len(_v) == 1 else "", f[2], f[3],
                              actor=_a.pop() if len(_a) == 1 else None)
                finally: _EV_T = _held
            elif p in rest:
                d = nm_dir.get(p)
                if d and d not in nm_done and not NDJSON and not SOLO:
                    nm_done.add(d)
                    out("C\t# NOTE: %d syscall deletions listed individually under %s — "
                        "not folded, something there predates this run and a glob delete "
                        "would remove more than was observed"
                        % (nm_n[d], d))
                _held = _EV_T
                _EV_T = evts[(lbl, p)]
                try: emit_file(lbl, "deleted", p, via=vias[p], actor=acts[(lbl, p)])
                finally: _EV_T = _held

def handle_delete(label, path, via="", actor=None):
    # --no-fold: show every unlink exactly, with no glob-fold and no tree-summary.
    if NOFOLD:
        emit_file(label, "deleted", path, via=via, actor=actor); return
    # A deletion a removal command already accounts for (its glob) is folded into that command. Otherwise it joins
    # the syscall-deletion run.
    if not SHOW_NOISE and covered_by_wipe(label, path, time.time()): return
    del_buf.append((label, path, via, time.time(), actor, _EV_T))

def reads_stdin(binary, args):
    # `xargs kill -9` is valid shell and completely unusable on its own: the PIDs came down a pipe that no exec
    # event records. A bare "-" argument is the same admission (`plutil -extract … -o - -`).
    if binary in ("xargs", "tee"): return True
    return "-" in args[1:]

_URLISH_RE = re.compile(r'^[a-zA-Z][a-zA-Z0-9+.-]*://')
def has_relative_path(args):
    # An argument containing "/" but not starting with one is relative to the working directory; without that
    # directory the line cannot be replayed.
    for a in args[1:]:
        if a.startswith(("/", "-", "~")): continue
        if _URLISH_RE.match(a): continue
        if "/" in a: return True
    return False

def emit(label, path, args, via_helper=False, cwd="", pid=None, pidver=None):
    eff_path, eff_args, payload = effective(path, args)
    _jp, _ja = judged(eff_path, eff_args)
    # shlex.quote, not cmd_quote, for argv: these tokens reached execve after shell expansion, so a `*` is literal.
    _show_payload = payload and not _CTL_ANY_RE.search(payload)
    cmd = payload if _show_payload else (" ".join(shq(a) for a in args) if args else path)
    cmd = mdm_rewrite(cmd)
    # Dedup on a normalised form, so one logical command counts once: `sh -c 'tmutil stopbackup'` and the
    # `tmutil stopbackup` it becomes; /usr/bin/git (a shim) and the Xcode git it re-execs.
    if payload:
        key = label + "\x00" + payload
    elif args:
        key = label + "\x00" + dedup_name(args[0]) + " " + " ".join(args[1:])
    else:
        key = label + "\x00" + path
    now = time.time()
    _binary = _jp.rsplit("/", 1)[-1]
    _gkey = (label, _binary)
    # Record what a removal command covers, so the per-file unlink events it produces are folded into it.
    if _binary in _REMOVERS and not SHOW_NOISE:
        for _a in _ja[1:]:
            if _a.startswith("-"): continue
            _wp, _wg = wipe_prefix_of(_a)
            if _wp: wipe_prefixes.append((label, _wp, _wg, now))
        if len(wipe_prefixes) > 4000: del wipe_prefixes[:2000]
    # …and what a file-placing command covers, so the clone/link/rename it performs is not printed again.
    if _binary in _COPIERS and not SHOW_NOISE:
        _pd = placed_dest(_ja)
        if _pd: copy_dests.append((label, _canon(_pd), now))
        if len(copy_dests) > 4000: del copy_dests[:2000]
    # …and the files a permission command names, so its setmode/setowner/setflags is not printed again.
    if _binary in _PERM_CMDS and not SHOW_NOISE:
        for _a in _ja[1:]:
            if _a.startswith("/"): perm_targets.append((label, _canon(_a), now))
        if len(perm_targets) > 4000: del perm_targets[:2000]
    if not SHOW_NOISE:
        _prev = pending_glob.get(_gkey)
        if _prev and now - _prev[1] < _PENDING_GLOB_S:
            _paths = [a for a in _ja[1:] if a.startswith("/")]
            # An expansion resolves patterns: it carries FEWER of them than the command it came from, and no fewer
            # paths.
            if (_paths and _prev[0] and glob_count(_ja) < _prev[3]
                    and len(_paths) >= _prev[4]
                    # Under one of the heads, not merely containing it: `/Library/Caches/com.evil.payload` must
                    # not count as an expansion of a head that appears inside it.
                    and all(any(x.startswith(p) for p in _prev[0])
                            for x in _paths)):
                def _tail(x):
                    p = max((p for p in _prev[0] if x.startswith(p)),
                            key=len, default="")
                    if not p: return x.rstrip("/").rsplit("/", 1)[-1]
                    # From the last component boundary inside the prefix, so `CoreDuet*` expanding to
                    # `CoreDuetd` reads whole.
                    t = x[p.rfind("/") + 1:].lstrip("/")
                    return t or x.rstrip("/").rsplit("/", 1)[-1]
                _names = [_tail(x) for x in _paths]
                _shown = ", ".join(_names[:4])
                if len(_names) > 4: _shown += " +%d more" % (len(_names) - 4)
                # `~/Library/Safari` is not a pattern: the shell resolved a home, which must not read as a glob
                # that matched one file.
                if _prev[2]:
                    out("C\t# NOTE: the shell expanded that pattern to %d path%s: %s"
                        % (len(_paths), "" if len(_paths) == 1 else "s", _shown))
                else:
                    out("C\t# NOTE: the shell resolved that path to %s" % _paths[0])
                del pending_glob[_gkey]
                return
        if has_glob(_ja):
            pending_glob[_gkey] = (glob_dirs(_ja), now,
                                   any("*" in a or "?" in a for a in _ja[1:]),
                                   glob_count(_ja),
                                   len([a for a in _ja[1:] if a.startswith("/")]))
            if len(pending_glob) > 500: pending_glob.clear()
        if payload:
            _remember_payload(label, payload, now)
        elif args:
            for _p, _pt in reversed(pending_shell.get(label, ())):
                if now - _pt >= _PENDING_SHELL_S: continue
                if payload_covers(_p, args) or payload_substitutes(_p, args): return
            # A wrapper that is not a shell folds nowhere: `disclaimer /bin/ps -axwwo …` and the `/bin/ps …` it
            # execs are one act, so the inner line is remembered.
            _inner = payload_argv(path, args)
            if (len(_inner) > 1 and _inner[0].startswith("/") and _inner[0] != path
                    # The wrapper's own basename, not the judged one: `judged` peels to the script (`brew.sh`, a
                    # NOISE entry), which would block a legitimate wrapper.
                    and path.rsplit("/", 1)[-1] not in _KNOWN_CMDS):
                _remember_payload(label, " ".join(shlex.quote(a) for a in _inner), now)
    if key in last_seen and now - last_seen[key] < DEDUP_S: return
    # Bound the dedup cache like `tracked`: ALL mode sees a wide variety of command lines.
    if len(last_seen) > TRACK_CAP: last_seen.clear()
    last_seen[key] = now
    _destr = bool(destructive_stage(eff_args))
    _net = network_stage(eff_args)
    # A command that places a file where software installs itself is doing the act `⚠ persistence` exists to
    # catch, and the mark belongs on it.
    _persist = activation_stage(eff_args, eff_path)
    _secret = secret_stage(eff_args)
    _scoped = writes_system_scope(_jp, _ja) or writes_system_scope(eff_path, eff_args)
    _marks = []
    if _destr: _marks.append("⚠ destructive")
    if _net: _marks.append("⚠ network")
    if _persist: _marks.append("⚠ persistence")
    if _secret: _marks.append("⚠ secret")
    if _scoped: _marks.append("⚠ system scope")
    # --no-queries: after every fold above has registered this line (its payload must still absorb the bare
    # pipeline stages that follow), and never for a line carrying a mark.
    if NO_QUERIES and not _marks and is_query(payload or cmd, eff_args, bool(payload)):
        debug_filtered("%s (query)" % cmd)
        return
    _pipes = reads_stdin(eff_path.rsplit("/", 1)[-1], eff_args)
    _relative = bool(cwd) and has_relative_path(_ja)
    _notes = []
    if via_helper: _notes.append("⚠ run as root by a privileged helper — prefix with sudo")
    elif _scoped: _notes.append("⚠ writes outside what the user can write — prefix with sudo")
    if _pipes: _notes.append("⚠ reads a pipe — this line alone will not replay")
    if _relative: _notes.append("run from %s" % cwd)
    # literal unless the line is a shell payload: an argv's `*` is a character of a real filename (see the shq
    # note above), and _report_form's cmd_quote would lift it out of the quotes.
    record(cmd, _destr, _net, note="; ".join(_notes), pid=pid, persist=_persist,
           secret=_secret, literal=not _show_payload)
    mdm_header()
    if NDJSON:
        # "via" stays null: the actor here IS the exec'd image the "app" field already names. via is for
        # emit_file/emit_perm, where a DIFFERENT process acted on the tracked app's behalf through a system call.
        _x = {}
        if via_helper: _x["via_helper"] = True
        if _pipes: _x["stdin_pipe"] = True
        if _relative: _x["cwd"] = mdm_rewrite(cwd)
        json_out("exec", label, cmd, None, _marks, actor=(pid, pidver), extra=_x)
        return
    if SOLO:
        out("C\t%s%s" % (cmd, ("   # " + " ".join(_marks)) if _marks else ""))
    else:
        out("C\t# %s ran:%s" % (label, ("  " + "  ".join(_marks)) if _marks else ""))
        out("C\t%s" % cmd)
    # Reuse hint, once per helper: repeating it on every command would drown the output.
    if via_helper and label not in helper_noted:
        helper_noted.add(label)
        out("C\t# NOTE: run by a privileged helper, so as root — prefix with sudo to reuse")
    if _scoped and not via_helper and label not in scope_noted:
        # Once per app, like the helper hint: an actor that works in /Library does so on every line.
        scope_noted.add(label)
        # Worded on the path, which is a fact, never on the actor: whether the process ran as root is not in the
        # exec event.
        out("C\t# NOTE: writes where the user cannot — prefix with sudo to reuse")
    if _pipes:
        out("C\t# NOTE: reads its input from a pipe — that input is not captured, so this line alone will not replay")
    if _relative:
        out("C\t# NOTE: run from %s — the relative paths above resolve against it" % cwd)

# ============================================================================
# --debug — the diagnostic channel
# ============================================================================
# Answers the two questions a silent capture raises: why is my command missing (`# FILTERED:`, with the
# reason), and why did this exec reach no actor (`# UNATTRIBUTED:`). `debug_dump` prints the JSON shape of
# the first events of each kind. All three are bounded, so the diagnostic never buries the output it explains.

_filt_seen = {}
def debug_filtered(msg):
    if not DEBUG: return
    now = time.time()
    if msg in _filt_seen and now - _filt_seen[msg] < 30.0: return
    if len(_filt_seen) > TRACK_CAP: _filt_seen.clear()
    _filt_seen[msg] = now
    out("C\t# FILTERED: %s" % msg)

_dbg_unattr = 0
def debug_unattributed(tgt, args):
    # --debug: an exec resolving to no actor. Apple's own are the expected case and drop silently; third-party
    # code with no actor is a gap an audit states rather than passes over.
    global _dbg_unattr
    if not DEBUG or not ALL_MODE or _dbg_unattr >= 40: return
    path = exe_path(tgt)
    if not path: return
    if is_platform(tgt) and not is_interpreter(path): return
    _dbg_unattr += 1
    out("C\t# UNATTRIBUTED: %s (no tracked ancestor, and no third-party actor to name)"
        % (" ".join(shq(a) for a in args) if args else path))

# The dump exists to reveal a file event's SHAPE — which field holds the source, which holds the destination
# directory, which holds the new name.
_DBG_DROP = ("stat", "path_truncated")
def _shape_only(node, depth=0):
    if depth > 8 or not isinstance(node, dict): return node
    return dict((k, _shape_only(v, depth + 1))
                for k, v in node.items() if k not in _DBG_DROP)

_dbg = 0
_dbg_file = {}        # event kind -> how many of its bodies have been dumped
_dbg_script = 0
def _node(d, key):
    # A top-level node of the event, or {}; never raises.
    if not isinstance(d, dict): return {}
    v = d.get(key)
    return v if isinstance(v, dict) else {}

def debug_dump(d):
    # Separate budgets: exec events are far more frequent and would use up a shared quota before any file event
    # appeared.
    global _dbg, _dbg_file, _dbg_script
    if not DEBUG: return
    ev = _node(d, "event")
    if not isinstance(ev.get("exec"), dict):
        for _k in ("unlink", "rename", "clone", "link", "setmode", "setowner", "setflags", "setacl", "deleteextattr", "open", "tcc_modify", "btm_launch_item_add", "btm_launch_item_remove"):
            if isinstance(ev.get(_k), dict):
                if _dbg_file.get(_k, 0) >= 2: return
                _dbg_file[_k] = _dbg_file.get(_k, 0) + 1
                out("D\t" + json.dumps({"file_event": _k,
                                        "body": _shape_only(ev[_k]),
                                        "process_exe": exe_path(_node(d, "process"))},
                                       ensure_ascii=True)[:900])   # ASCII only: a lone surrogate cannot be written as UTF-8
                return
        return
    ex = ev.get("exec", {}) or {}
    # A script exec gets its own budget too: the first execs of any capture are boot plumbing.
    if any_path(ex.get("script")):
        if _dbg_script >= 3: return
        _dbg_script += 1
    elif _dbg >= 3:
        return
    else:
        _dbg += 1
    proc = _node(d, "process")
    tgt = ex.get("target", {}) or {}
    sample = {
        "top_keys": list(d.keys()),
        "process_keys": list(proc.keys()) if isinstance(proc, dict) else str(type(proc)),
        "process_pid": proc_pid(proc),
        "process_ppid": proc.get("ppid"),
        "process_team": field(proc, "team_id", "signing_id"),
        "process_exe": exe_path(proc),
        "process_is_platform": proc.get("is_platform_binary") if isinstance(proc, dict) else None,
        "has_responsible": "responsible_audit_token" in proc if isinstance(proc, dict) else False,
        "exec_keys": list(ex.keys()),
        "target_pid": proc_pid(tgt),
        "target_team": field(tgt, "team_id", "signing_id"),
        "target_exe": exe_path(tgt),
        "exec_script": any_path(ex.get("script")),
        "exec_cwd": any_path(ex.get("cwd")),
        "args_under_exec": (ex.get("args") or [])[:3] if isinstance(ex.get("args"), list) else [],
        "args_under_target": (tgt.get("args") or [])[:3] if isinstance(tgt, dict) and isinstance(tgt.get("args"), list) else [],
    }
    out("D\t" + json.dumps(sample, ensure_ascii=True))   # see above: never lose the event to the dump

# ============================================================================
# SHUTDOWN AND THE MAIN LOOP
# ============================================================================
# One handler and one loop. SIGTERM renders whatever is held rather than losing
# it; SIGINT and SIGHUP are deliberately NOT handled here — the watcher inherits
# them ignored, so the orderly shutdown always gets to run. The loop then reads
# one event per line and walks it through the sections above, file events first
# (they carry no new image) and execs second.

_stopping = False
def _on_term(signum, frame):
    global _stopping
    if _stopping: return
    _stopping = True
    try: flush_deletes()
    except Exception: pass
    render_report()
    os._exit(0)
try: signal.signal(signal.SIGTERM, _on_term)
except Exception: pass

recover_report()   # print any report left unrendered by a previous reboot
_live = False
_parser_errors = set()   # exception types already reported (capped at 64)
while True:
    line = sys.stdin.readline()
    if not line: flush_deletes(); break
    line = line.strip()
    if not line: continue
    if not _live:
        # The first event arrives: proof the ES client is connected and streaming (`# watcher started` is written
        # right after the fork, before eslogger has said anything).
        _live = True
        raw_out("R\t# Culprit: capture is LIVE — eslogger is streaming, you can start the app now")
    # One event is one unit of work: an exception anywhere below loses THIS event and nothing else.
    try:
        try:
            d = json.loads(line)
        except Exception:
            # Silent by design: eslogger's stream is not exclusively events, and non-JSON noise is skipped.
            continue
        _EV_T = ev_time_iso(d)
        # isinstance: valid JSON is not necessarily an object (a top-level list has no `.get`).
        if _schema is None and isinstance(d, dict):
            _sv = d.get("schema_version")
            if _sv is not None: _schema = _sv
        ev = _node(d, "event")
        # Culprit's own directory reads (confirming a wipe) are not the Mac's software: dropped before anything
        # else, debug included.
        if proc_pid(_node(d, "process")) == SELF_PID: continue
        debug_dump(d)
        ex = ev.get("exec")
        proc = _node(d, "process")

        if not isinstance(ex, dict):
            # File events carry no new image: the actor is the process itself, so attribution comes from the
            # tracking exec already built, or from the process being a known app on its own.
            if isinstance(ev.get("exit"), dict):
                _xp = proc_pid(proc)
                if _xp is not None: note_exit(_xp)
                continue
            # A privacy grant/revoke: tccd's own process, never the app it is about — attributed on
            # identity/instigator, not on `proc`.
            if isinstance(ev.get("tcc_modify"), dict):
                handle_tcc_modify(ev.get("tcc_modify"), proc)
                continue
            # A login item add/remove: backgroundtaskmanagementd's own process, never the app whose persistence
            # changed — attributed on the item's path or the instigator/app, not on `proc`.
            if isinstance(ev.get("btm_launch_item_add"), dict):
                handle_btm_launch_item(ev.get("btm_launch_item_add"), "add", proc)
                continue
            if isinstance(ev.get("btm_launch_item_remove"), dict):
                handle_btm_launch_item(ev.get("btm_launch_item_remove"), "remove", proc)
                continue
            if not (WATCH_FILES or WATCH_READS or WATCH_OPENS): continue
            kind = None
            for _k in ("unlink", "rename", "clone", "link", "setmode", "setowner", "setflags", "setacl", "deleteextattr", "readdir", "open"):
                if isinstance(ev.get(_k), dict): kind = _k; break
            if kind is None:
                degrade("an event type this version does not recognise: %s"
                        % ", ".join(sorted(k for k in ev if isinstance(ev.get(k), dict))[:3] or ["?"]))
                continue
            if DESTRUCTIVE_ONLY and kind in ("readdir", "open"): continue
            if kind == "readdir" and not WATCH_READS: continue
            if kind == "open" and not WATCH_OPENS: continue
            if kind in _WRITE_KINDS and not WATCH_FILES: continue
            _apid = proc_pid(proc)
            try: _ppid = int(proc.get("ppid")) if proc.get("ppid") is not None else None
            except Exception: _ppid = None
            _rtok = proc.get("responsible_audit_token")
            _rpid = audit_pid(_rtok) if _rtok is not None else None
            flabel = None
            for pp in (_apid, _ppid, _rpid):
                if pp is not None and pp in tracked: flabel = tracked[pp]; break
            if flabel is None: flabel = resolve_app(proc)
            if flabel is None:
                # No third-party actor, but an install is reported on what it is, not on who did it
                # (persistence_actor()).
                flabel = persistence_actor(ev, kind, proc)
            if flabel is None: continue
            # Who actually did it: the app's own bundle image (no annotation), or a tool/helper it ran —
            # lsregister deleting the LaunchServices store, a privileged helper, a shell.
            _fact = proc_actor(proc)
            _fvia = exe_path(proc)
            # An Apple XPC service reading on the app's behalf is the system's own UI at work (a file dialog
            # lists the sidebar, Downloads, iCloud…), not the app looking around.
            if (not SHOW_NOISE and kind in ("readdir", "open")
                    and is_platform(proc) and ".xpc/Contents/MacOS/" in _fvia):
                debug_filtered("ls -la %s (system-xpc)" % (any_path(ev[kind].get("target")) or "?"))
                continue
            _fvia = _fvia.rsplit("/", 1)[-1] if _fvia and ".app/Contents/MacOS/" not in _fvia else ""
            # When the actor is the tool the line would be written with, the command itself was already printed
            # and this would say it again.
            if (not SHOW_NOISE and
                    _fvia == _VERB_TOOL.get("listed" if kind == "readdir" else
                                            "opened" if kind == "open" else "")):
                continue
            body = ev[kind]
            _src_key = "source" if kind == "rename" or kind in _COPY_KINDS else "target"
            src = any_path(body.get(_src_key))
            if not src:
                for _k in ("target", "source", "file"):
                    if _k == _src_key: continue
                    src = any_path(body.get(_k))
                    if src: break
            if not src:
                degrade("%s: the path could not be read" % kind)
                continue
            if not SHOW_NOISE and kind in ("readdir", "open") and _fvia in _TOOL_SCAN_NOISE:
                debug_filtered("ls -la %s (tool-walk: %s)" % (src or "?", _fvia))
                continue
            if kind == "open":
                # Which files the app read: the half a readdir cannot give. The in-process filtering after a
                # readdir is invisible, and the file it then opens reveals the target.
                if not src: continue
                if not SHOW_NOISE:
                    # A directory open is the readdir we already show, not a file read; `.app` and other bundle
                    # dirs are the same, opened whole.
                    if open_is_dir(body): continue
                    if open_is_exec(body): continue
                    if src.endswith(".app") or ".app/" in src: continue
                    if transient(src): continue
                    if any(x in src for x in _CODE_BUNDLES): continue
                    if src.endswith((".dylib", ".so")) or "/usr/lib/" in src: continue
                    if src.startswith("/dev/") or any(p in src for p in _OPEN_NOISE): continue
                    _sp = APP_SCAN_NOISE.get(flabel)
                    if _sp and any(p in src for p in _sp): continue
                    if any(src == d or src.startswith(d + "/") for d in _SCAN_NOISE_DIRS): continue
                flush_deletes()
                emit_file(flabel, "opened", src, via=_fvia, actor=_fact)
                continue
            if kind == "readdir":
                if not src: continue
                if not SHOW_NOISE and transient(src): continue
                # Enumerating a code bundle is the loader or a plugin scan at work, not the app looking for
                # something: nothing to reproduce there.
                if not SHOW_NOISE and any(x in src for x in _CODE_BUNDLES): continue
                if not SHOW_NOISE and ".app/" in src: continue
                # An app inventorying its own data is housekeeping; a scan of a standard tool directory
                # (/usr/bin, /sbin…) is an app locating a binary.
                if not SHOW_NOISE:
                    _sp = APP_SCAN_NOISE.get(flabel)
                    if _sp and any(p in src for p in _sp):
                        debug_filtered("ls -la %s (app-scan)" % src)
                        continue
                    if any(src == d or src.startswith(d + "/") for d in _SCAN_NOISE_DIRS):
                        debug_filtered("ls -la %s (tool-dir)" % src)
                        continue
                if not SHOW_NOISE:
                    # Walking a tree lists every level (a bundle, its Contents, Resources): one act of looking,
                    # so only the top of the descent is reported.
                    _now = time.time()
                    if src in listed_dirs and _now - listed_dirs[src] < 300.0: continue
                    _anc, _under = src, False
                    while "/" in _anc and _anc != "/":
                        _anc = _anc.rsplit("/", 1)[0]
                        if _anc in listed_dirs and _now - listed_dirs[_anc] < 10.0:
                            _under = True; break
                    if _under:
                        listed_dirs[src] = _now
                        continue
                    listed_dirs[src] = _now
                    if len(listed_dirs) > TRACK_CAP: listed_dirs.clear()
                flush_deletes()
                emit_file(flabel, "listed", src, via=_fvia, actor=_fact)
                continue
            if kind in _PERM_KINDS:
                _pc = perm_change(kind, body)
                if not _pc: continue
                if not SHOW_NOISE and not (_pc[1] or system_scope(_pc[2])
                                           or is_persistence(_pc[2])):
                    debug_filtered("%s (self-permission)" % _pc[0])
                    continue
                if not SHOW_NOISE and transient(_pc[2]): continue
                if not SHOW_NOISE and covered_by_perm(flabel, _pc[2], time.time()): continue
                flush_deletes()
                emit_perm(flabel, _pc[0], _pc[1], _pc[2], kind, via=_fvia, actor=_fact)
                continue
            if kind == "deleteextattr":
                _xc = xattr_change(body)
                if not _xc: continue
                _xcmd, _xpath, _xname = _xc
                # System-maintained bookkeeping never worth reproducing. `-v` lifts this like every noise rule.
                if not SHOW_NOISE and _xname in _XATTR_NOISE:
                    debug_filtered("%s (bookkeeping attribute)" % _xcmd)
                    continue
                # `xattr -d`/`xattr -c` are not in DESTRUCTIVE (see its removal-tools comment), so an API
                # deleteextattr never meets --destructive-only's bar on its own.
                if DESTRUCTIVE_ONLY and not (system_scope(_xpath) or is_persistence(_xpath)):
                    continue
                if not SHOW_NOISE and transient(_xpath): continue
                flush_deletes()
                emit_xattr(flabel, _xcmd, _xpath, _xname, via=_fvia, actor=_fact)
                continue
            if not src: continue
            dst = (rename_dest(body) if kind == "rename"
                   else copy_dest(body) if kind in _COPY_KINDS else "")
            _installs = is_persistence(dst)
            if not SHOW_NOISE and transient(src) and not _installs: continue
            if kind in _COPY_KINDS:
                # A copy with no readable destination says nothing reproducible, and the destination decides
                # persistence: dropped.
                if not dst: continue
                if not SHOW_NOISE and covered_by_copy(flabel, dst, time.time()): continue
                # Same-directory copy churn (an app duplicating a file beside itself) is the copy form of
                # write-to-temp. An install is never that, so `_installs` overrides, as for rename.
                if not SHOW_NOISE and atomic_write(src, dst) and not _installs: continue
                flush_deletes()
                emit_file(flabel, "linked" if kind == "link" else "copied",
                          src, dst, via=_fvia, actor=_fact)
            elif kind == "rename":
                # Symmetric with the copy guard: with no readable destination the line would reproduce nothing and
                # drop the `⚠ persistence` mark.
                if not dst:
                    degrade("rename: the destination could not be read")
                    continue
                if not SHOW_NOISE and covered_by_copy(flabel, dst, time.time()): continue
                if not SHOW_NOISE and atomic_write(src, dst) and not _installs: continue
                flush_deletes()
                emit_file(flabel, "moved", src, dst, via=_fvia, actor=_fact)
            else:
                handle_delete(flabel, src, _fvia, _fact)
            continue

        # An exec ends any run of syscall deletions: flush it before the command, so the folded `rm -rf <tree>`
        # prints in its true place, right before this.
        flush_deletes()
        tgt = ex.get("target", {}) or {}

        apid = proc_pid(proc)
        try: ppid = int(proc.get("ppid")) if proc.get("ppid") is not None else None
        except Exception: ppid = None
        rtok = proc.get("responsible_audit_token")
        rpid = audit_pid(rtok) if rtok is not None else None
        tpid = proc_pid(tgt)

        tgt_path = exe_path(tgt)
        # Read the argv before attributing: a shebang script execs its interpreter, so the actor's own identity
        # (brew, mackup, an MDM script) is in there and nowhere else.
        args = exec_args(ex, tgt)
        # The script this exec is really running, when it runs one. macOS reports it (`brew list` arrives with
        # image /bin/bash and event.exec.script = /opt/homebrew/bin/brew): exact, and absolute even for a script
        # named relatively (`sh ./build.sh`).
        if "script" in ex:
            # macOS reports the field, so its answer is final — including when it is empty, which means there is
            # no script.
            tgt_script = third_party_script(any_path(ex.get("script")))
        else:
            tgt_script = script_image(tgt_path, args)

        seed = resolve_app(tgt, tgt_script)
        if seed is not None and tpid is not None and tpid not in tracked:
            tracked[tpid] = seed

        label = None
        inherited = False
        for pp in (apid, ppid, rpid):
            if pp is not None and pp in tracked:
                label = tracked[pp]; inherited = True; break
        # Not yet tracked, but the ACTING process identifies itself (an app's first command, a helper's): it is
        # the actor, and it CHOSE to run this — which is what separates a command from an actor starting.
        if label is None:
            _actor = resolve_app(proc)
            if _actor is not None:
                label = _actor; inherited = True
        if label is None: label = seed
        if label is None:
            debug_unattributed(tgt, args)
            continue

        # Skip the app/helper's own image (launch/relaunch) before propagating, or the launcher (launchd) of that
        # image would be tracked and pollute attribution. tpid is already seeded above.
        if not tgt_path: continue
        if is_app_image(tgt, inherited, tgt_script):
            # An app starting is not a command, but silence makes an app that never shells out indistinguishable
            # from one Culprit cannot see at all.
            _who = seed if seed is not None else label
            if not DESTRUCTIVE_ONLY and not ONLY_CMDS_SET and _who not in seen_apps:
                seen_apps.add(_who)
                out("C\t# %s started (pid %s)" % (_who, tpid if tpid is not None else "?"))
            continue

        for pp in ((tpid,) if is_cli_launch(tgt_path, tgt_script) else (tpid, apid)):
            if pp is not None: tracked[pp] = label
        if len(tracked) > TRACK_CAP: tracked.clear()

        _ep, _ea, _epl = effective(tgt_path, args)
        if ONLY_CMDS_SET:
            # An explicitly named command is shown even when the noise list would hide it.
            if judged(_ep, _ea)[0].rsplit("/", 1)[-1] not in ONLY_CMDS_SET: continue
        elif not SHOW_NOISE:
            _why = noise_reason(tgt_path, args, label)
            if _why:
                # Under --debug, say what was dropped and why. The command shown is the effective one (payload of
                # a shell-out).
                if DEBUG:
                    # Quoted like the real output: joined raw, `cut -d' ' -f1` would read `cut -d  -f1`.
                    _fcmd = _epl if _epl else (
                        " ".join(shq(a) for a in _ea) if _ea else tgt_path)
                    debug_filtered("%s (%s)" % (_fcmd, _why))
                continue
        if DESTRUCTIVE_ONLY and not destructive_stage(_ea): continue
        # Only a PrivilegedHelperTools binary is genuinely root; claiming it for anything under Application
        # Support would be a guess dressed as a fact.
        emit(label, tgt_path, args, _PRIVILEGED_DIR in exe_path(proc),
             any_path(ex.get("cwd")), tpid, proc_actor(tgt)[1])
    except Exception as _exc:
        # Narrow on purpose: Exception, not BaseException, so SIGTERM's own exit and a KeyboardInterrupt still
        # stop the parser.
        _pk = type(_exc).__name__
        if _pk not in _parser_errors and len(_parser_errors) < 64:
            _parser_errors.add(_pk)
            _pe = "%s: %s" % (_pk, str(_exc)[:160])
            if DEBUG: out("D\tparser error, event skipped — %s" % _pe)   # `# DEBUG: …`
            else: sys.stderr.write("culprit: parser error, event skipped — %s\n" % _pe)
        continue

# Stream drained (eslogger stopped at shutdown): print the report, if asked. _stopping first, since _shutdown
# sends SIGTERM a few seconds in and the handler would render the report a second time.
_stopping = True
render_report()
PY

# Build the parser argv, in this order: debug, all-mode, destructive-only, show-noise, excludes-csv, cmd-filter,
# watch-files, watch-reads, watch-opens — then one argument per registry target
# (label\tteam\tbundle\thelpers\tcli).
typeset -a _PARSER_ARGS
_PARSER_ARGS=(
  "$([ "$DEBUG" = true ] && echo 1 || echo 0)"
  "$([ "$ALL_MODE" = true ] && echo 1 || echo 0)"
  "$([ "$DESTRUCTIVE_ONLY" = true ] && echo 1 || echo 0)"
  "$([ "$SHOW_NOISE" = true ] && echo 1 || echo 0)"
  "${_EXCLUDES_CSV}"
  "${CMD_FILTER}"
  "$([ "$WATCH_FILES" = true ] && echo 1 || echo 0)"
  "$([ "$WATCH_READS" = true ] && echo 1 || echo 0)"
  "$([ "$WATCH_OPENS" = true ] && echo 1 || echo 0)"
)
for _t in "${TARGET_APPS[@]}"; do
  _lbl="${_t%%|*}"; _rest="${_t#*|}"
  _team="${_rest%%|*}"; _rest="${_rest#*|}"
  _bundle="${_rest%%|*}"; _rest="${_rest#*|}"
  # The 5th field (CLI paths) is optional: with four fields `${x#*|}` returns the remainder whole, which would
  # copy helpers into cli.
  if [[ "$_rest" == *"|"* ]]; then _helpers="${_rest%%|*}"; _cli="${_rest#*|}"
  else _helpers="$_rest"; _cli=""; fi
  _PARSER_ARGS+=("${_lbl}"$'\t'"${_team}"$'\t'"${_bundle}"$'\t'"${_helpers}"$'\t'"${_cli}")
done

# ---------------------------------------
# The watcher — stream eslogger → parser → log
# ---------------------------------------
cmd_watch() {
  trap '' INT HUP
  # Keep eslogger's stderr: an ES client can be refused for reasons that look identical from here (too many
  # clients, a revoked entitlement).
  local _errf="$CULPRIT_TMPDIR/eslogger.err"
  # eslogger line-buffers on a pipe; the parser reads with readline() (unbuffered via -u) so sparse events are
  # not stuck in a block buffer. --format json is pinned: eslogger documents it only as "default: json".
  PYTHONIOENCODING=utf-8:surrogateescape \
  /usr/bin/eslogger --format json "${EVENT_TYPES[@]}" 2>"$_errf" \
    | "$PYTHON3_BIN" -u "$PARSER" "${_PARSER_ARGS[@]}" \
    | while IFS=$'\t' read -r _k _v; do
        [ -n "$_k" ] || continue
        case "$_k" in
          C) log_line "Cmd: $_v" ;;
          D) log_line "Cmd: # DEBUG: $_v" ;;
          R) log_line "Cmd: $_v"      # lifecycle, not observation — see the parser
             : > "$CULPRIT_TMPDIR/live" 2>/dev/null || true
             # Tell a detaching parent the same thing — see the handshake there. Validated at startup
             # (_detach_ready_ok); `>>` all the same, so this line can never truncate anything.
             [ -n "${CULPRIT_DETACH_READY:-}" ] && \
               { : >> "$CULPRIT_DETACH_READY"; } 2>/dev/null || true ;;
        esac
      done || true
  if [ -s "$_errf" ]; then
    # Marker for the main shell: a refused ES client (revoked entitlement, no free slot) kills the watcher at once.
    : > "$CULPRIT_TMPDIR/eslogger.stderr" 2>/dev/null || true
    while IFS= read -r _e; do
      [ -n "$_e" ] && log_line "Cmd: # ERROR: eslogger: $_e"
    done < "$_errf"
  fi
}

# ============================================================================
# MAIN
# ============================================================================
if [ "$ALL_MODE" = "true" ]; then
  _apps_summary="ALL third-party apps and tools"
else
  # Join with zsh's (j) flag: `print` puts the array on one line, and labels with a space ("Font Finagler")
  # would blur into their neighbours.
  _apps_summary="${(j:, :)${TARGET_APPS[@]%%|*}}"
fi
[ "$DESTRUCTIVE_ONLY" = "true" ] && _apps_summary="${_apps_summary} (destructive commands only)"
_scope_summary="commands"
[ "$WATCH_FILES" = "true" ] && _scope_summary="commands + deletions, moves, copies and permission changes"
[ "$WATCH_READS" = "true" ] && _scope_summary="${_scope_summary} + directory scans"
[ "$WATCH_OPENS" = "true" ] && _scope_summary="${_scope_summary} + file reads"
[ "$MDM" = "true" ] && _scope_summary="${_scope_summary} (MDM: fleet-portable paths)"
[ "$REPORT" = "true" ] && _scope_summary="${_scope_summary} — report on stop"
[ -n "${DURATION:-}" ] && _scope_summary="${_scope_summary} — stopping itself after ${DURATION}s"
# Marks-only narrows the report, not the subscription: say so in the banner.
[ "$MARKS_ONLY" = "true" ] && _scope_summary="${_scope_summary} — report: marked lines only"
[ "$STABLE" = "true" ] && _scope_summary="${_scope_summary}, comparable form"
[ "$NO_QUERIES" = "true" ] && _scope_summary="${_scope_summary} — lines that only read dropped"
# --ndjson: this line and the advisories below print before the watcher exists, so under --ndjson they go to
# stderr and stdout carries JSON Lines from the first byte.
if [ "$NDJSON" = "true" ]; then
  printf "# Culprit: watching [%s] — %s\n" "$(_inert "$_apps_summary")" "$_scope_summary" >&2
else
  printf "# Culprit: watching [%s] — %s\n" "$(_inert "$_apps_summary")" "$_scope_summary"
fi
if [ "$WATCH_OPENS" = "true" ] && [ "$ALL_MODE" = "true" ]; then
  printf "# culprit: WARNING: --opens in ALL mode is very high volume — target one app (e.g. sudo ./culprit.sh \"Font Finagler\" --opens)\n" >&2
fi
# Plain --report is silent by construction: the report is the output, so the debug channel is suppressed with
# everything else.
if [ "$DEBUG" = "true" ] && [ "$REPORT" = "true" ] && [ "$NDJSON" != "true" ]; then
  printf "# culprit: WARNING: --debug prints nothing under --report — the report is the only output. Drop --report to see the JSON dumps and the FILTERED/UNATTRIBUTED lines\n" >&2
fi
# --exclude only reaches is_excluded() in the ALL_MODE branch of match_target(), and -v lifts it with the rest
# of the noise list: either combination leaves the list doing nothing.
if [ -n "${EXCLUDE_EXTRA:-}" ]; then
  if [ "$ALL_MODE" != "true" ]; then
    printf "# culprit: WARNING: --exclude has no effect outside --all — a single-app run has nothing to exclude by\n" >&2
  elif [ "$ONLY_CMDS" = "false" ]; then
    printf "# culprit: WARNING: --exclude has no effect under -v — verbose lifts the same noise list --exclude feeds\n" >&2
  fi
fi
# --destructive-only already forces reads and directory scans off; --no-reads asks for that twice, and
# --no-files also turns off the file events --destructive-only reports.
if [ "$DESTRUCTIVE_ONLY" = "true" ] && { [ "${READS_RAW:-}" = "false" ] || [ "${FILES_RAW:-}" = "false" ]; }; then
  if [ "${FILES_RAW:-}" = "false" ]; then
    printf "# culprit: WARNING: --no-files with --destructive-only also drops the deletions and moves it reports — --destructive-only already drops reads and directory scans on its own\n" >&2
  else
    printf "# culprit: WARNING: --no-reads with --destructive-only is redundant — --destructive-only already drops reads and directory scans on its own\n" >&2
  fi
fi
# The other way round: --events asking for reads or opens is pointless under --destructive-only, which drops both.
if [ "$DESTRUCTIVE_ONLY" = "true" ] && [ "${_EVENTS_WANT_READS:-}" = "true" ]; then
  printf "# culprit: WARNING: --events asks for reads but --destructive-only drops it — neither modifies anything, so neither can qualify\n" >&2
fi
if [ "$DESTRUCTIVE_ONLY" = "true" ] && [ "${_EVENTS_WANT_OPENS:-}" = "true" ]; then
  printf "# culprit: WARNING: --events asks for opens but --destructive-only drops it — neither modifies anything, so neither can qualify\n" >&2
fi
# --cmd skips the noise check entirely (see ONLY_CMDS_SET in the parser), so -v has nothing left to lift.
if [ -n "${CMD_FILTER:-}" ] && [ "$ONLY_CMDS" = "false" ]; then
  printf "# culprit: WARNING: -v with --cmd adds nothing — --cmd already shows the named commands regardless of the noise list -v would lift\n" >&2
fi

_fatal() { printf "# culprit: %s\n" "$(_inert "$1")" >&2; exit 1; }
[ "$(/usr/bin/id -u)" = "0" ] || _fatal "must run as root (sudo) — eslogger needs it."
[ -x /usr/bin/eslogger ] || _fatal "/usr/bin/eslogger not found — needs macOS 13+ (Ventura)."
[ -n "$PYTHON3_BIN" ] || _fatal "python3 unavailable — run 'xcode-select --install' (or install via Homebrew)."

# --detach: hand the prompt back and keep watching. Done HERE, after the prerequisites, so a missing sudo or
# python3 is still reported to the face of the person typing.
_detach_ready_ok() {
  local f="$1" d="${1:h}"
  [ -n "${CULPRIT_DETACHED:-}" ] || return 1
  [ "${f:t}" = "detach.ready" ] || return 1
  [[ "${d:t}" =~ '^culprit\.[0-9]+\.[A-Za-z0-9]{6}$' ]] || return 1
  [ "${d:h:A}" = "/private/tmp" ] || return 1
  [ -d "$d" ] && [ ! -h "$d" ] && [ -O "$d" ] || return 1
  [ "$(/usr/bin/stat -f '%Lp' "$d" 2>/dev/null)" = "700" ] || return 1
  [ ! -e "$f" ] && [ ! -h "$f" ]
}
if [ -n "${CULPRIT_DETACH_READY:-}" ] && ! _detach_ready_ok "$CULPRIT_DETACH_READY"; then
  unset CULPRIT_DETACH_READY
fi
[ -n "${CULPRIT_DETACHED:-}" ] || unset CULPRIT_LOGFILE_RESOLVED
if [ "$DETACH" = "true" ] && [ -z "${CULPRIT_DETACHED:-}" ]; then
  export CULPRIT_DETACHED=1
  # Resolve HERE, so the banner names the file that will actually be written and the child writes exactly that
  # one.
  LOGFILE="$(_dry_logfile "$LOGFILE")" || _fatal "nowhere to write a log — pick a path with --log"
  export CULPRIT_LOGFILE_RESOLVED="$LOGFILE"
  _report_out_resolve
  # Inside CULPRIT_TMPDIR, which the EXIT trap owns.
  _detach_err="$CULPRIT_TMPDIR/detach.err"
  export CULPRIT_DETACH_READY="$CULPRIT_TMPDIR/detach.ready"
  # Through `/bin/zsh -f`, not the file itself: exec'ing the script would need it executable, and its shebang
  # reads zsh's startup files (a `.zshenv` under $ZDOTDIR or $HOME, run as root). -f reads none of them.
  /usr/bin/nohup "$PYTHON3_BIN" -c \
    'import os,sys; os.setsid(); os.execv("/bin/zsh", ["/bin/zsh", "-f"] + sys.argv[1:])' \
    "${0:A}" "$@" >/dev/null 2>"$_detach_err" &
  _detached_pid=$!
  _dw=0
  while [ ! -f "$CULPRIT_DETACH_READY" ] && [ "$_dw" -lt 100 ]; do
    if ! /bin/kill -0 "$_detached_pid" 2>/dev/null; then
      printf "# culprit: the detached watcher stopped before its capture went live\n" >&2
      [ -s "$_detach_err" ] && /usr/bin/head -3 "$_detach_err" >&2
      /bin/rm -f "$_detach_err" 2>/dev/null || true
      exit 1
    fi
    /bin/sleep 0.1; _dw=$((_dw + 1))
  done
  [ -f "$CULPRIT_DETACH_READY" ] || \
    printf "# culprit: WARNING: detached, but no event yet after 10s — check the log for 'capture is LIVE'\n" >&2
  /bin/rm -f "$_detach_err" "$CULPRIT_DETACH_READY" 2>/dev/null || true
  unset _dw
  _say "# Culprit: detached (pid %s) — keeps running when this terminal closes\n" "$_detached_pid"
  _say "#   follow:  tail -f %s\n" "$(_inert "$LOGFILE")"
  [ -n "$REPORT_OUT" ] && _say "#   report:  %s — written when the capture stops\n" "$(_inert "$REPORT_OUT")"
  _say "#   watch:   open -a Console %s   — wait for the 'capture is LIVE' line before starting the app\n" "$(_inert "$LOGFILE")"
  _say "#   stop:    sudo kill %s\n" "$_detached_pid"
  exit 0
fi

_LOG_WANTED="$LOGFILE"
if [ -n "${CULPRIT_LOGFILE_RESOLVED:-}" ]; then
  LOGFILE="$CULPRIT_LOGFILE_RESOLVED"
  _LOG_EXPLICIT=1     # the parent already chose it; the child must not move it
elif ! LOGFILE="$(_dry_logfile "$LOGFILE")"; then
  if [ "${_LOG_EXPLICIT:-0}" = 1 ]; then
    printf '# culprit: cannot write the log at %s — a named log is never moved to\n' "$(_inert "$_LOG_WANTED")" >&2
    printf '#   /var/log or /tmp behind your back\n' >&2
  else
    printf '# culprit: nowhere to write a log — %s is not writable, and /var/log and /tmp\n' "$(_inert "$_LOG_WANTED")" >&2
    printf '#   already hold a file of that name that Culprit did not write\n' >&2
  fi
  printf '#   pick a path of your own:   --log /Users/Shared/culprit-audit.log\n' >&2
  exit 1
fi
# Before prepare_logfile rotates anything: a refused report path stops the run with the previous capture still
# where it was.
_report_out_resolve
_check_pid="${LOGFILE}.pid"
if [ -f "$_check_pid" ]; then
  _prev_pid=$(/bin/cat "$_check_pid" 2>/dev/null) || _prev_pid=""
  case "$(/bin/ps -o comm=,args= -p "${_prev_pid:-0}" 2>/dev/null)" in
    *zsh*culprit*.sh*) : ;;
    *) _prev_pid="" ;;
  esac
  if [ -n "$_prev_pid" ] && /bin/kill -0 "$_prev_pid" 2>/dev/null; then
    printf '# culprit: a capture is already writing to %s (pid %s)\n' "$(_inert "$LOGFILE")" "$_prev_pid" >&2
    printf '#   stop it first:   sudo kill %s\n' "$_prev_pid" >&2
    printf '#   or give this one its own file:   --log /var/log/culprit-2.log\n' >&2
    exit 1
  fi
fi
LOGFILE="$(prepare_logfile "$LOGFILE")" || _fatal "could not open a log file at $LOGFILE"
_PIDFILE="${LOGFILE}.pid"
# The log path is guarded; the pidfile sits beside it in the same world-writable directory, guarded the same way.
if [ -h "$_PIDFILE" ] || { [ -e "$_PIDFILE" ] && { [ ! -f "$_PIDFILE" ] || [ ! -O "$_PIDFILE" ]; }; }; then
  printf '# culprit: refusing to write a pidfile that is a link or not ours: %s\n' "$(_inert "$_PIDFILE")" >&2
  _PIDFILE=""
else
  /bin/rm -f "$_PIDFILE" 2>/dev/null || true
  ( umask 077; set -C; printf '%s' "$$" > "$_PIDFILE" ) 2>/dev/null || _PIDFILE=""
fi
_say "# Culprit: logging to %s\n" "$(_inert "$LOGFILE")"
[ -s "${LOGFILE}.1" ] && _say "# Culprit: previous capture kept as %s.1\n" "$(_inert "$LOGFILE")"
if [ "$LOGFILE" != "$_LOG_WANTED" ]; then
  printf "# culprit: WARNING: could not write %s — logging to %s instead\n" "$(_inert "$_LOG_WANTED")" "$(_inert "$LOGFILE")" >&2
fi
# --report accumulator, next to the resolved log so it survives a reboot in the same /var/log the log lives in.
# Only meaningful in --report mode.
[ "$REPORT" = "true" ] && export CULPRIT_REPORT_FILE="${LOGFILE}.report" || export CULPRIT_REPORT_FILE=""
# --report-file (or its --ndjson default): the parser writes the report there on stop instead of onto the stream.
export CULPRIT_REPORT_OUT="$REPORT_OUT"
if [ -n "$REPORT_OUT" ]; then
  if [ "$NDJSON" = "true" ]; then
    printf "# Culprit: report on stop written to %s\n" "$(_inert "$REPORT_OUT")" >&2
  else
    printf "# Culprit: report on stop written to %s\n" "$(_inert "$REPORT_OUT")"
  fi
fi
/usr/bin/logger -t "culprit" -- "Log file: $LOGFILE"
log_line "Cmd: # Culprit v${SCRIPT_VERSION} (pid $$) — watching: ${_apps_summary}"
_LOG_READY=1     # the banner is down; TRAPZERR may write into the log now
[ "$DEBUG" = true ] && log_line "Cmd: # DEBUG on — dumping the JSON shape of the first 3 events of each kind: plain exec, script exec, file (paste these back to refine field extraction)."

# The traps go up before the watcher is forked: a signal in between would have no handler, and on zsh INT and
# HUP still run the EXIT trap, which removes CULPRIT_TMPDIR.
_kill_tree() {
  local _root=$1 _kid _kids
  [ -n "$_root" ] || return 0
  # pgrep exits 1 when a process has no children (a leaf, not an error); inline in the `for` list it would trip
  # TRAPZERR.
  _kids=$(/usr/bin/pgrep -P "$_root" 2>/dev/null) || _kids=""
  for _kid in ${=_kids}; do _kill_tree "$_kid"; done
  kill -TERM "$_root" 2>/dev/null || true
}
_shutdown() {
  local _kid _kids _waited=0 _max="${1:-20}"
  _kids=$(/usr/bin/pgrep -P "${WATCH_PID:-0}" 2>/dev/null) || _kids=""
  for _kid in ${=_kids}; do
    case "$(/bin/ps -o comm= -p "$_kid" 2>/dev/null)" in
      *eslogger*) kill -TERM "$_kid" 2>/dev/null || true ;;
    esac
  done
  # Bounded by the caller's own budget: 2s on Ctrl+C, 5s on SIGTERM. A stuck parser must not hold the shutdown
  # open past it.
  while [ "$_waited" -lt "$_max" ] && [ -n "${WATCH_PID:-}" ] && kill -0 "$WATCH_PID" 2>/dev/null; do
    /bin/sleep 0.1 || true; _waited=$((_waited + 1))
  done
  _kill_tree "${_TIMER_PID:-}"
  _kill_tree "${WATCH_PID:-}"
  wait ${WATCH_PID:-} 2>/dev/null || true
  /bin/rm -f "${_PIDFILE:-}" 2>/dev/null || true
  /bin/rm -rf "$CULPRIT_TMPDIR" 2>/dev/null || true
}
trap '_shutdown 50; exit 143' TERM
trap '_shutdown 20; exit 130' INT
# A detached run must outlive the terminal (and the app that quits it), so it ignores SIGHUP; nohup already
# does.
if [ "$DETACH" = "true" ]; then
  trap '' HUP
else
  trap '_shutdown 20; exit 129' HUP
fi

_T0=$(/bin/date +%s)
cmd_watch &
WATCH_PID=$!
# A capture that stops itself. USR1 rather than TERM, because a planned stop is a SUCCESS: the handler exits 0,
# where TERM exits 143 and a Jamf policy would read its own duration limit as a failure.
if [ -n "${DURATION:-}" ]; then
  trap '_shutdown 50; exit 0' USR1
  ( _n=0
    while [ "$_n" -lt "$DURATION" ]; do
      /bin/sleep 1
      /bin/kill -0 $$ 2>/dev/null || exit 0
      _n=$(( _n + 1 ))
    done
    # The marker says the LIMIT is what ended this run. Written before the signal, since the handler exits and
    # never comes back here.
    : > "$CULPRIT_TMPDIR/duration_fired" 2>/dev/null || true
    # Re-checked here: a whole second separates the last loop check from the signal.
    /bin/kill -0 $$ 2>/dev/null || exit 0
    /bin/kill -USR1 $$ 2>/dev/null ) &
  _TIMER_PID=$!
fi
# Announced AFTER the fork: it describes a capture that is running. A detached run has no terminal to say it to.
[ "$DETACH" = "true" ] || \
  _say "# Culprit: watching — Ctrl+C to stop. Follow live: tail -f %s\n" "$(_inert "$LOGFILE")"
# Log the watcher too: when a capture stops short, the log must say how far startup got and which processes to
# look for afterwards.
log_line "Cmd: # watcher started (pid ${WATCH_PID})"

_es_wait=0
while [ "$_es_wait" -lt 10 ]; do
  _kids=$(/usr/bin/pgrep -P "$WATCH_PID" 2>/dev/null) || _kids=""
  for _k in ${=_kids}; do
    case "$(/bin/ps -o comm= -p "$_k" 2>/dev/null)" in
      *eslogger*) printf '%s\n' "$_k" >> "$CULPRIT_TMPDIR/pids" 2>/dev/null || true ;;
    esac
  done
  [ -s "$CULPRIT_TMPDIR/pids" ] && break
  /bin/sleep 0.1; _es_wait=$((_es_wait + 1))
done
unset _es_wait _kids _k


# Run until stopped. One behaviour, no window coupling: Ctrl+C / SIGTERM ends it (detach is stopped with `kill
# <pid>`, as its banner said).
wait "$WATCH_PID" 2>/dev/null || true
# Reaching here means the WATCHER ended, not the limit: the --duration handler exits from its own trap and never
# returns to this line.
if [ -n "${DURATION:-}" ] && [ ! -f "$CULPRIT_TMPDIR/duration_fired" ]; then
  _ran=$(( $(/bin/date +%s) - ${_T0:-0} ))
  log_line "Cmd: # culprit: WARNING: the capture ended by itself after ${_ran}s of the ${DURATION}s asked for — eslogger stopped; this report covers only that much"
fi
if [ -f "$CULPRIT_TMPDIR/eslogger.stderr" ] && [ ! -f "$CULPRIT_TMPDIR/live" ]; then
  printf '# culprit: eslogger produced no events and reported an error — see %s\n' "$(_inert "$LOGFILE")" >&2
  exit 1
fi
exit 0
