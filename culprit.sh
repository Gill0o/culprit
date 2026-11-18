#!/bin/zsh -f
# ============================================================================
# Script: culprit.sh
# Version: 1.0.5
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
#   [app]: bundle path, bundle ID, app name, or CLI tool name or path
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
#   $4  App to watch: bundle path | bundle ID | app name | CLI tool name or
#       path | ALL (blank = ALL)
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
#       events=, cmd=, apps= (several targets, comma-separated; needs $4 blank
#       or ALL). Unknown or repeated key, or a
#       pair with no `=`, refuses the policy.
#   $11 Log path (blank = /var/log/culprit-v<version>.log; named: no fallback)
#
# Requirements: root + Full Disk Access on the terminal, macOS 15+, python3.
# ============================================================================

set -e
set -u
set -o pipefail

# One locale everywhere; exported so the --detach re-exec and the parser inherit it.
export LC_ALL=en_US.UTF-8

# Log where a command returned non-zero (the log captures neither stderr nor an abort).
TRAPZERR() {
  local _loc="${funcfiletrace[1]:-?}" _fn="${funcstack[2]:-main}"
  print -u2 "culprit: non-zero status at ${_loc} (in ${_fn})" 2>/dev/null || true
  # Only once the banner is down: earlier it would leave residue outside CULPRIT_TMPDIR
  # or become the log's first line, which `_is_culprit_log` refuses.
  if [ -z "${_IN_TRAPZERR:-}" ] && [ -n "${_LOG_READY:-}" ]; then
    # Recursion guard: a failing log_line re-enters this handler.
    _IN_TRAPZERR=1
    log_line "Cmd: # TRACE: non-zero status at ${_loc} (in ${_fn})" 2>/dev/null || true
    unset _IN_TRAPZERR
  fi
}

# ---------------------------------------
# CONFIGURATION
# ---------------------------------------
# One line per target: "label|team_id|bundle_path|helper_paths(comma)|cli_paths(comma)".
# Any field may be empty; the team_id also matches the SMJobBless helper. Empty list means ALL mode.
typeset -ga TARGET_APPS=()

# `exec` carries attribution on its own (ppid + responsible process). create/write/truncate
# are excluded: they fire on every temporary file and bury the signal.
typeset -ga EVENT_TYPES=(exec)

# Auto-updaters only: Docker, TeamViewer, Dropbox and the like stay audited (root, file movement, remote access).
# An exclusion drops an actor entirely; a noise rule drops one command. `-v` disables it.
typeset -ga DEFAULT_EXCLUDES=(
  "MAU2.0"                          # Microsoft AutoUpdate (app + AU Daemon)
  "com.microsoft.autoupdate"        # …and its privileged helper
  "GoogleSoftwareUpdate"            # Google Keystone (legacy)
  "GoogleUpdater"                   # Google Updater (Chrome, replaces Keystone)
  "com.adobe.acc"                   # Adobe Creative Cloud updater
  "Adobe Desktop Common"
  "zoom.updater"                    # Zoom auto-updater (the Zoom app itself stays)
)

# Inert before printing: control characters as \xNN (the parser's raw_out rule),
# so a newline or ESC cannot forge a `# culprit: …` line.
_inert() {
  local s="$1" o="" c i
  # A non-UTF-8 byte too: raw, 0x9b is the terminal's CSI.
  if [[ "$s" != *[[:cntrl:][:INVALID:]]* ]]; then print -rn -- "$s"; return 0; fi
  for (( i = 1; i <= ${#s}; i++ )); do
    c="${s[i]}"
    if [[ "$c" == [[:cntrl:][:INVALID:]] ]]; then o+="$(printf '\\x%02x' "'$c")"; else o+="$c"; fi
  done
  print -rn -- "$o"
}
# The parser's inert_word, for a name an observed bundle chose, printed in a `#` line:
# pasted where `#` is not a comment, it must hold no shell syntax.
_inert_word() {
  local s="$1" o="" c i
  if [[ "$s" != *[^A-Za-z0-9\ ._/+:,@%=~-]* ]]; then print -rn -- "$s"; return 0; fi
  for (( i = 1; i <= ${#s}; i++ )); do
    c="${s[i]}"
    if [[ "$c" == [A-Za-z0-9\ ._/+:,@%=~-] ]]; then o+="$c"
    elif [[ "$c" == [[:cntrl:][:INVALID:]] ]]; then o+="$(printf '\\x%02x' "'$c")"
    elif [[ "$c" == [[:graph:]] && "$c" != [[:punct:]] ]]; then o+="$c"
    else o+="_"; fi
  done
  print -rn -- "$o"
}

show_help() {
  /bin/cat << 'EOF'
Usage: sudo ./culprit.sh [app] [OPTIONS]

Attributes each command an app runs, and the files it deletes, moves, copies or
reads, to that app as a replayable command line. Observes only: nothing is run
or blocked.

Arguments:
  [app]                 One app or tool: bundle path (/Applications/X.app),
                        bundle ID (com.vendor.app, best on a fleet), app name
                        in /Applications, CLI name (brew) or path. Its
                        privileged helper is attributed with it (same Team ID).
                        Omitted: every third-party app and tool.

Options — (CLI only): no Jamf Pro parameter. Jamf gets $4-$11 (see the header);
$10 takes key=value pairs: apps=, events=, cmd=, exclude=.
  -l, --log <path>      Log file (default /var/log/culprit-v<version>.log).
                        Refused if unsafe, no fallback; one capture per log.
  -v, --verbose         (CLI only) Timestamped and unfiltered; Apple's apps
                        become actors. Not paste-ready.
  -q, --only-cmds       Commands alone (default).
  --debug               (CLI only) Dump the first events' JSON shape; show what
                        the noise filter drops and what no actor claims.
  --apps <list>         Several targets, comma-separated, each like [app].
  --all                 Every third-party app and tool (default).
  --events <list>       Optional event families: files, reads, opens, tcc, btm.
                        Default: all but opens. A list replaces it, +x/-x
                        adjusts it (--events +opens,-tcc). tcc: macOS 15.4+.
  --no-reads            No directory scans (an event cut; --no-queries instead
                        trims read-only commands from the output).
  --no-files            Commands only, no file events.
  --opens               Also report files read, as `cat <path>`. High volume.
  --mdm                 Fleet-ready output: /Users/$loggedInUser/…, and
                        $userDir/$userCache/$userTemp for the user's
                        /var/folders (root's stays literal).
  --report              Capture silently; on stop, print the marked sections
                        and a paste-ready script. Survives a reboot.
  --report-file <path>  (CLI only) Write the report there instead of stdout.
  --no-fold             One `rm` per deleted file instead of `rm -rf <dir>/*`.
  --stable              Sorted, de-duplicated report, to diff two captures.
  --marks-only          Only the lines carrying a ⚠ mark, in the report.
  --no-queries          Drop read-only commands (defaults read, diskutil info…).
  --ndjson              (CLI only) One JSON object per line, for a SIEM
                        (ts/cmd/via/marks/kind/app/pid/pidver).
  --cmd <list>          Only these commands (ls,rm,defaults), unfiltered.
  --destructive-only    Destructive and persistence acts only, any actor.
  --exclude <list>      Substrings or Team IDs to drop in --all mode.
  --detach              Run in the background, past the terminal closing (an app
                        quitting it).
  --duration <secs>     Stop after that long, report, exit 0. Needed unattended.
  -h, --help            This help.
  --report-file, --stable and --marks-only need --report.

Requirements: root, Full Disk Access on the invoking terminal, macOS 15+ (13-14
start with a warning: untested), python3.

Exit codes: 0 done · 1 refused before starting · 2 capture stopped by itself ·
130 Ctrl+C · 143 SIGTERM · 129 SIGHUP · 141 stdout closed. A capture stopped
by a signal still writes its report.

Examples:
  sudo ./culprit.sh                       # every third-party app and tool
  sudo ./culprit.sh /Applications/X.app   # one app by bundle path
  sudo ./culprit.sh com.vendor.app        # one app by bundle ID
  sudo ./culprit.sh brew                  # a CLI tool by name — brew, not bash
  sudo ./culprit.sh /Library/PrivilegedHelperTools/com.vendor.helper  # by path
  sudo ./culprit.sh --apps /Applications/Zoom.app,brew   # a specific set
  sudo ./culprit.sh --destructive-only    # dangerous commands, any actor
  sudo ./culprit.sh --detach brew         # outlives the terminal closing
  sudo ./culprit.sh --debug brew          # confirm the eslogger schema
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
  ALL_RAW=""
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

  # First non-flag arg is the app filter; an empty one is refused, not read as ALL.
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
      # Aliases go through the same function so every spelling lands on identical RAW values.
      # (--no-files drops opens in the cascade below.)
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
        # A bare word after a flag is still the [app] positional (`--debug brew`).
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

  # --all contradicts naming an app, in either order.
  if [[ "$_ALL_FLAG" == "true" && ( -n "$APP_FILTER" || -n "$APPS_OVERRIDE" ) ]]; then
    echo "Error: --all cannot be combined with an app name or --apps" >&2; exit 1
  fi
  if [[ -n "$APP_FILTER" && -n "$APPS_OVERRIDE" ]]; then
    echo "Error: --apps cannot be combined with an app name; list every target in --apps" >&2; exit 1
  fi

  if [[ -z "$ALL_RAW" ]]; then
    if [[ -n "$APP_FILTER" || -n "$APPS_OVERRIDE" ]]; then
      ALL_RAW="false"
    else
      ALL_RAW="true"
    fi
  fi
}

# Shared by --events and $10's events=. Bare terms form an ABSOLUTE list; +/- terms are
# DELTAS on the current *_RAW values. Mixing is refused, so is an unknown term.
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
    # reads/opens ride on the file subscription, so a bare list naming either implies files;
    # delta lists are untouched.
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
# Set when a term explicitly asks for reads/opens; the --destructive-only warning reads it.
_EVENTS_WANT_READS=""
_EVENTS_WANT_OPENS=""

# Jamf detection: $1=mount_point $2=computer_name $3=username, params at $4+. Collides with a CLI call
# (`culprit.sh /Applications/X.app --opens`): Jamf passes no flags there and its mount point is a
# volume (`/`, `/Volumes/…`), never an app bundle.
JAMF_MODE="false"
# `$3` may be empty: no console user when nobody is logged in.
if [[ -n "${1:-}" && "${1}" == /* && "${1}" != *.app ]] \
   && [[ -n "${2:-}" && "${2}" != -* ]] && [[ "${3:-}" != -* ]]; then
  JAMF_MODE="true"
fi
if [ "$JAMF_MODE" = "true" ]; then
  # Jamf gives only $4-$11; the rest keep their defaults. Empty $4 = ALL.
  APP_FILTER="${4:-}"
  case "$APP_FILTER" in
    ALL|all|'*'|"") ALL_RAW="true"; APP_FILTER="" ;;
    *) ALL_RAW="false" ;;
  esac
  REPORT_RAW="${5:-false}"
  MDM_RAW="${6:-false}"
  NOFOLD_RAW="${8:-false}"
  # $9: a boolean, or seconds: `true` runs until killed, a number stops itself after that long.
  _p9="${9:-false}"
  while [[ "$_p9" == [[:space:]]* ]]; do _p9="${_p9#?}"; done
  while [[ "$_p9" == *[[:space:]] ]]; do _p9="${_p9%?}"; done
  [ -n "$_p9" ] || _p9="false"
  case "${_p9:l}" in
    # `0` and `1` stay boolean, not durations.
    0|1|true|false|yes|no|non|y|n|on|off|oui|vrai) DETACH_RAW="$_p9" ;;
    *[!0-9]*)
      # Refused, not read as false: no detach and no limit would hang the policy.
      printf '# culprit: $9: "%s" is neither a boolean nor whole seconds\n' "$(_inert "$_p9")" >&2
      printf '#   detach: true/false — or a number of seconds to stop by itself: 300\n' >&2
      exit 1 ;;
    *) DETACH_RAW="true"; DURATION_RAW="$_p9" ;;
  esac
  LOG_FILE_PARAM="${11:-}"
  ONLY_CMDS_RAW="true"; DEBUG_RAW="false"; APPS_OVERRIDE=""; CMD_FILTER=""
  FILES_RAW="true"; READS_RAW="true"; OPENS_RAW="false"; TCC_RAW="true"; BTM_RAW="true"
  # $10: the exclude list, unless it contains "=": then key=value pairs separated by ";"
  # (values may hold commas). An unknown, malformed or repeated key refuses the policy.
  # Read after the defaults so `events=` deltas adjust the real ones.
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
        apps)    APPS_OVERRIDE="$_p10_val"; [ -n "$_p10_val" ] && ALL_RAW="false" ;;
        *) printf '# culprit: $10: unknown key "%s" — known: exclude, events, cmd, apps\n' "$(_inert "$_p10_key")" >&2; exit 1 ;;
      esac
    done
    unset _p10_seen _p10_pair _p10_key _p10_val
    if [ -n "$APPS_OVERRIDE" ] && [ -n "$APP_FILTER" ]; then
      printf '# culprit: $10: apps= cannot be combined with an app named in $4; leave $4 blank or ALL\n' >&2
      exit 1
    fi
  else
    EXCLUDE_EXTRA="$_p10"
  fi
  unset _p10
  # $7: comma-separated named terms (`marks` narrows, `stable` reformats), or one boolean (`true` = destructive).
  DESTR_RAW="false"
  _p7="${(L)7:-}"
  # Counted after trimming and dropping empties, so `true,` is not a list.
  _t7=()
  for _tok in ${(s:,:)_p7}; do
    while [[ "$_tok" == [[:space:]]* ]]; do _tok="${_tok#?}"; done
    while [[ "$_tok" == *[[:space:]] ]]; do _tok="${_tok%?}"; done
    [ -n "$_tok" ] && _t7+=("$_tok")
  done
  for _tok in "${_t7[@]}"; do
    case "$_tok" in
      actions)     READS_RAW="false" ;;
      destructive) DESTR_RAW="true" ;;
      marks)       MARKS_RAW="true" ;;
      noqueries)   NOQUERIES_RAW="true" ;;
      stable)      STABLE_RAW="true" ;;
      *)
        # A single bare word may be a boolean spelling (as $9). Otherwise refused:
        # to_bool() would read a typo as false and silently drop the filter.
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
  # zsh's own ${(L)}, not `tr`: with `tr` unresolvable every option turned off.
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
if [ "$ONLY_CMDS" = "true" ]; then SHOW_NOISE="false"; else SHOW_NOISE="true"; fi
WATCH_FILES=$(to_bool "${FILES_RAW:-false}")
WATCH_READS=$(to_bool "${READS_RAW:-false}")
WATCH_OPENS=$(to_bool "${OPENS_RAW:-false}")
WATCH_TCC=$(to_bool "${TCC_RAW:-true}")
WATCH_BTM=$(to_bool "${BTM_RAW:-true}")
# --destructive-only drops scans, reads and TCC events (none lasts); login items stay, they are persistence. The parser keeps its own guard.
if [ "$DESTRUCTIVE_ONLY" = "true" ]; then WATCH_READS="false"; WATCH_OPENS="false"; WATCH_TCC="false"; fi
# --no-files means no file events, whatever the flag order.
if [ "$WATCH_FILES" != "true" ]; then WATCH_READS="false"; WATCH_OPENS="false"; fi
# Options reach the parser by environment, so no argv position shifts.
MDM=$(to_bool "${MDM_RAW:-false}")
[ "$MDM" = "true" ] && export CULPRIT_MDM=1 || export CULPRIT_MDM=0
[ "$WATCH_TCC" = "true" ] && export CULPRIT_TCC=1 || export CULPRIT_TCC=0
[ "$WATCH_BTM" = "true" ] && export CULPRIT_BTM=1 || export CULPRIT_BTM=0
REPORT=$(to_bool "${REPORT_RAW:-false}")
[ "$REPORT" = "true" ] && export CULPRIT_REPORT=1 || export CULPRIT_REPORT=0
NOFOLD=$(to_bool "${NOFOLD_RAW:-false}")
[ "$NOFOLD" = "true" ] && export CULPRIT_NOFOLD=1 || export CULPRIT_NOFOLD=0
STABLE=$(to_bool "${STABLE_RAW:-false}")
MARKS_ONLY=$(to_bool "${MARKS_RAW:-false}")
# Refused without --report (they would silently do nothing); the message names the interface (under Jamf the switch is $5).
if [ "$REPORT" != "true" ]; then
  if [ "$JAMF_MODE" = "true" ]; then _needs="set \$5=true"; else _needs="add --report"; fi
  [ "$STABLE" = "true" ] && { printf '# culprit: --stable shapes the report — %s\n' "$_needs" >&2; exit 1; }
  [ "$MARKS_ONLY" = "true" ] && { printf '# culprit: --marks-only shapes the report — %s\n' "$_needs" >&2; exit 1; }
  unset _needs
fi
[ "$STABLE" = "true" ] && export CULPRIT_STABLE=1 || export CULPRIT_STABLE=0
[ "$MARKS_ONLY" = "true" ] && export CULPRIT_MARKS=1 || export CULPRIT_MARKS=0
# --ndjson with --report: the text report goes to a file on stop, never onto the stream.
NDJSON=$(to_bool "${NDJSON_RAW:-false}")
[ "$NDJSON" = "true" ] && export CULPRIT_NDJSON=1 || export CULPRIT_NDJSON=0
# --report-file: checked before the run, since a bad path would lose the report. `:a`, never `:A`:
# resolving symlinks would follow the very link the parser refuses.
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
# Under --ndjson without --report-file the report goes to `<log>.report.txt` (stdout is the stream),
# never one of the log's own files; `:A` makes /var/log and /private/var/log equal.
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
NO_QUERIES=$(to_bool "${NOQUERIES_RAW:-false}")
[ "$NO_QUERIES" = "true" ] && export CULPRIT_NOQUERIES=1 || export CULPRIT_NOQUERIES=0

unsetopt xtrace verbose 2>/dev/null || true

# ---------------------------------------
# Environment
# ---------------------------------------
get_console_user() { /usr/bin/stat -f %Su /dev/console 2>/dev/null || /usr/bin/id -un; }
# An inherited CONSOLE_USER is honoured only if it names a real account: root acts on its home.
if [ -n "${CONSOLE_USER:-}" ] && { [[ "$CONSOLE_USER" != [A-Za-z0-9._-]## ]] \
     || ! /usr/bin/id -u -- "$CONSOLE_USER" >/dev/null 2>&1; }; then
  CONSOLE_USER=""
fi
CONSOLE_USER="${CONSOLE_USER:-$(get_console_user)}"
# `|| true`: dscl exits 56 when the record is absent (AD/Entra/Jamf Connect accounts),
# which `set -e` + pipefail would abort on.
_UHOME=$(/usr/bin/dscl . -read "/Users/${CONSOLE_USER}" NFSHomeDirectory 2>/dev/null | /usr/bin/awk '{print $2}') || true
[ -n "$_UHOME" ] || _UHOME="/Users/${CONSOLE_USER}"
export CULPRIT_HOME="$_UHOME"
# Full name for --mdm (can hold spaces, so it travels as a whole line in the environment).
_UREAL=$(/usr/bin/dscl . -read "/Users/${CONSOLE_USER}" RealName 2>/dev/null | /usr/bin/tail -1 | /usr/bin/sed 's/^ *//') || true
[ "$_UREAL" = "RealName:" ] && _UREAL=""
export CULPRIT_REALNAME="${_UREAL#RealName: }"
# --mdm: only this user's /var/folders prefix may become $userTemp & co; empty = leave them literal.
export CULPRIT_USERDIR=""
if [ "$MDM" = "true" ] && [ -n "$CONSOLE_USER" ]; then
  CULPRIT_USERDIR=$(/usr/bin/sudo -n -u "$CONSOLE_USER" /usr/bin/getconf DARWIN_USER_DIR 2>/dev/null) || CULPRIT_USERDIR=""
fi

# xcode-select first, to avoid the /usr/bin/python3 CLT-install popup.
PYTHON3_BIN=""
# Every python3 run takes -I: root imports nothing the caller planted.
_python3_validate() { "$1" -I -c 'import json,sys' >/dev/null 2>&1 && PYTHON3_BIN="$1" && return 0; return 1; }
_clt=false; /usr/bin/xcode-select -p >/dev/null 2>&1 && _clt=true
if [ "$_clt" = true ] && [ -x /usr/bin/python3 ] && _python3_validate /usr/bin/python3; then :
elif command -v python3 >/dev/null 2>&1; then
  _cand="$(command -v python3)"
  [ "$_cand" != /usr/bin/python3 ] && _python3_validate "$_cand" || true
fi
# sudo resets PATH to secure_path: look in the Homebrew and MacPorts prefixes too.
if [ -z "$PYTHON3_BIN" ]; then
  for _pd in /opt/homebrew/bin /usr/local/bin /opt/local/bin; do
    [ -x "$_pd/python3" ] && _python3_validate "$_pd/python3" && break
  done
  unset _pd
fi
# A group- or world-writable interpreter is noted, not refused (it would break every CLT-less Mac).
# Mode is read from the resolved target.
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

# No fallback name: a predictable /tmp/culprit.<pid> could be pre-created, and root writes the
# parser there and executes it. mktemp must give a directory we own, mode 700.
CULPRIT_TMPDIR=$(/usr/bin/mktemp -d "/tmp/culprit.${$}.XXXXXX") || {
  printf '# culprit: could not create a private temporary directory in /tmp — stopping\n' >&2; exit 1; }
if [ ! -d "$CULPRIT_TMPDIR" ] || [ -h "$CULPRIT_TMPDIR" ] || [ ! -O "$CULPRIT_TMPDIR" ] \
   || [ "$(/usr/bin/stat -f '%Lp' "$CULPRIT_TMPDIR" 2>/dev/null)" != "700" ]; then
  printf '# culprit: the temporary directory %s is not private to this run — stopping\n' "$CULPRIT_TMPDIR" >&2
  exit 1
fi
# Never removed while the watcher is alive: the tmpdir path in the parser's argv is the orphan sweep's only handle.
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
# _tty_lost before the capture's own traps: stop as SIGPIPE would.
trap 'exit 141' USR2

# Reclaim what a dead run left: `kill -9` runs no trap, so its parser and root eslogger survive
# (holding a scarce ES client slot). An orphan is found by the tmpdir path in its argv (dots escaped,
# `pgrep -f` takes a regex), never by name, which would reach another tool's client. Every reclaim is announced.
for _stale in /tmp/culprit.[0-9]*(N/); do
  # The name must be exactly what mktemp produces and the directory ours: /tmp is world-writable, and
  # a planted NAME like `culprit.0|.*|` would make `pgrep -f` match every process, each sent `kill -TERM` as root.
  [[ "${_stale:t}" =~ '^culprit\.[0-9]+\.[A-Za-z0-9]{6}$' ]] || continue
  [ -O "$_stale" ] || continue
  _sp="${${_stale:t}#culprit.}"; _sp="${_sp%%.*}"
  [ "$_sp" = "$$" ] && continue
  /bin/kill -0 "$_sp" 2>/dev/null && continue
  _pat="${_stale//./\\.}/parser\\.py"
  _orph=$(/usr/bin/pgrep -f "$_pat" 2>/dev/null) || _orph=""
  # The eslogger pids the run recorded: a name match would reach another tool's ES client,
  # and the pid may have been reused, so it must still be eslogger.
  if [ -s "${_stale}/pids" ]; then
    while IFS= read -r _ep; do
      [ -n "$_ep" ] || continue
      # `comm=`, never `args=`, which matches any process that merely mentions eslogger.
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
      # Could not signal it (non-root vs a root orphan): keep the directory, a later run's only handle.
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
# Is this file one of our logs? Every log opens with its banner (timestamped under -v). Empty or absent is fair game.
_is_culprit_log() {
  local p="$1" first
  # A symlink is refused first: `-e` follows it, so a dangling link would pass and root would write
  # the capture at its target.
  [ -h "$p" ] && return 1
  [ -e "$p" ] || return 0
  [ -s "$p" ] || return 0
  first=$(/usr/bin/head -1 "$p" 2>/dev/null) || return 1
  # Contains the banner, not starts with it: `-v` prefixes a timestamp.
  case "$first" in
    *'# Culprit v'*) return 0 ;;
  esac
  return 1
}

if [ -d "$LOGFILE" ]; then
  printf '# culprit: the log path must be a FILE, not a directory: %s\n' "$(_inert "$LOGFILE")" >&2
  printf '#   try:  %s/culprit.log\n' "$(_inert "${LOGFILE%/}")" >&2
  exit 1
fi
# Never onto a file this tool did not write: rotation truncates, so `--log /var/log/install.log` would
# destroy it. This is the only way Culprit could modify the Mac it watches.
if [ -e "$LOGFILE" ] && [ ! -h "$LOGFILE" ] && [ "$(/usr/bin/id -u)" != "0" ] && [ ! -r "$LOGFILE" ]; then
  # Root's log is 0600: unreadable by non-root is unknown, not foreign; fall through to the root check.
  :
elif [ -e "$LOGFILE" ] && ! _is_culprit_log "$LOGFILE"; then
  printf '# culprit: %s exists and was not written by Culprit — refusing to rotate it\n' "$(_inert "$LOGFILE")" >&2
  printf '#   a capture truncates its log and keeps one generation as .1\n' >&2
  printf '#   pick a path of your own:   --log /var/log/culprit-audit.log\n' >&2
  exit 1
fi

# ---------------------------------------
# Resolve the [app] / --apps targets into TARGET_APPS
# ---------------------------------------
# A `|` in a path would shift the registry fields: refuse before a line is built.
# `comma` adds `,` (not for --apps entries, where it is the separator).
_refuse_registry_chars() {
  local what="$1" v="$2" bad='|' desc='"|"'
  [[ "${3:-}" == comma ]] && { bad='|,'; desc='"|", ","'; }
  if [[ "$v" == *[$bad]* || "$v" == *$'\t'* || "$v" == *$'\n'* ]]; then
    printf '# culprit: %s "%s" contains a character the registry cannot carry (%s, TAB or newline)\n' \
      "$what" "$(_inert "$v")" "$desc" >&2
    exit 1
  fi
}
# A privileged helper is typically mode 500/544 root:wheel: judge on the mode bits, not our own access.
_is_executable_file() {
  local m
  [[ -f "$1" ]] || return 1
  [[ -x "$1" ]] && return 0
  m=$(/usr/bin/stat -f %Lp "$1" 2>/dev/null) || return 1
  [[ "$m" == *[1357]* ]]
}
_find_cli() {
  local n="$1" p d
  # `whence -p`, not `command -v`: the latter answers with the builtin for `log`, `kill`, `time`…
  p=$(whence -p -- "$n" 2>/dev/null) && [[ "$p" == /* && -x "$p" ]] && { print -r -- "$p"; return 0; }
  # sudo resets PATH: look where third-party tools install.
  for d in /opt/homebrew/bin /usr/local/bin /opt/local/bin /opt/homebrew/sbin /usr/local/sbin \
           /usr/bin /bin /usr/sbin /sbin; do
    [[ -x "$d/$n" ]] && { print -r -- "$d/$n"; return 0; }
  done
  return 1
}
# Team ID for <path>: only a line that IS `TeamIdentifier=<value>`, and only one (a newline in the
# name prints a second), ten [A-Z0-9] characters; "not set" or a registry separator is no Team ID.
_team_id_of() {
  local t
  t=$(/usr/bin/codesign -dv --verbose=2 "$1" 2>&1 \
      | /usr/bin/awk -F= '$1=="TeamIdentifier"{n++; t=(NF==2?$2:"")} END{if(n==1)print t}') || t=""
  [[ "$t" =~ '^[A-Z0-9]{10}$' ]] && print -r -- "$t"
  return 0
}
# By path: codesign supplies the Team ID so the privileged helper is attributed too.
# A plain executable (tool, privileged helper, MDM script) is also accepted.
_target_from_path() {
  local path="${1%/}" label team real cli
  # `:a`, not `:A`: eslogger reports absolute paths; a symlinked CLI tool is registered with its target below.
  path="${path:a}"
  _refuse_registry_chars "path" "$path" comma
  if [ -d "$path" ]; then
    # A plain directory is not a bundle: as a path prefix it would match every app in it.
    if [[ "$path" != *.app ]] && [ ! -d "$path/Contents/MacOS" ]; then
      printf '# culprit: not an app bundle: %s (pass the .app itself, or an executable)\n' "$(_inert "$path")" >&2
      exit 1
    fi
    label="${path:t:r}"
    team=$(_team_id_of "$path")
    TARGET_APPS=("${label}|${team}|${path}||")
    return 0
  fi
  if [ ! -e "$path" ]; then
    printf '# culprit: no such app bundle or executable: %s\n' "$(_inert "$path")" >&2; exit 1
  fi
  # eslogger reports the resolved executable, not the typed symlink: register both.
  real="${path:A}"
  _refuse_registry_chars "path" "$real" comma
  if ! _is_executable_file "$real" || [ -z "${path:t}" ]; then
    printf '# culprit: not an executable, and not an .app bundle: %s\n' "$(_inert "$path")" >&2; exit 1
  fi
  label="${path:t}"
  team=$(_team_id_of "$real")
  cli="$real"
  [[ "$real" != "$path" ]] && cli="${real},${path}"
  # 5th field = CLI paths: matched exactly; its own exec is shown as a command.
  TARGET_APPS=("${label}|${team}|||${cli}")
}

# A dotted argument shaped like a bundle id (`zoom.us`) can be a literal app name (/Applications/zoom.us.app),
# as can any bare word that is not a CLI tool. $CULPRIT_HOME, never $HOME (root's under sudo).
_try_app_name() {
  # CULPRIT_APPS_ROOT is honoured only when not root.
  local n="$1" p _root="/Applications"
  [ "$EUID" -ne 0 ] && _root="${CULPRIT_APPS_ROOT:-/Applications}"
  for p in "${_root}/${n}.app" "${_root}/Utilities/${n}.app" "${CULPRIT_HOME}/Applications/${n}.app"; do
    [ -e "$p" ] && { print -r -- "$p"; return 0; }
  done
  return 1
}

# By bundle ID: resolved to the bundle path (Spotlight, or lsappinfo for a running app), then handled as a path target.
_target_from_bundle_id() {
  local bid="$1" p asn
  local pat='^[A-Za-z0-9-]+(\.[A-Za-z0-9_-]+)+$'
  local -a matches
  if [[ ! "$bid" =~ $pat ]]; then
    printf '# culprit: not a valid bundle id: %s\n' "$(_inert "$bid")" >&2; exit 1
  fi
  # `|| true` on the lookups: a non-zero exit (mdfind with Spotlight off, lsappinfo with no such app)
  # would abort under `set -e` + pipefail.
  matches=("${(@f)$(/usr/bin/mdfind "kMDItemCFBundleIdentifier == '$bid'" 2>/dev/null)}") || true
  matches=(${matches:#})
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
    # Not a bundle id: try it as a literal app NAME.
    p=$(_try_app_name "$bid") && matches=("$p")
  fi
  if (( ${#matches} == 0 )); then
    printf '# culprit: no app with bundle id or name %s (Spotlight off? pass the .app path)\n' "$(_inert "$bid")" >&2
    exit 1
  fi
  if (( ${#matches} > 1 )); then
    printf '# culprit: bundle id %s is ambiguous — pass one path:\n' "$(_inert "$bid")" >&2
    local _m; for _m in "${matches[@]}"; do printf '#   %s\n' "$(_inert_word "$_m")" >&2; done
    exit 1
  fi
  _target_from_path "${matches[1]}"
}

_resolve_target() {
  local spec="$1" hit=""
  case "$spec" in
    # A path carries a slash. `*.app` alone is ambiguous: a bundle if it exists on disk, otherwise an ID.
    /*|*/*)   _target_from_path "$spec" ;;
    *.app)    if [ -e "$spec" ]; then _target_from_path "$spec"
              else _target_from_bundle_id "$spec"; fi ;;
    # Reverse-DNS is a bundle id, unless a tool by that name exists (`mytool.sh`).
    *.*)      if hit=$(_find_cli "$spec"); then _target_from_path "$hit"
              else _target_from_bundle_id "$spec"; fi ;;
    *)        if hit=$(_find_cli "$spec"); then _target_from_path "$hit"
              elif hit=$(_try_app_name "$spec"); then _target_from_path "$hit"
              else
                printf '# culprit: nothing matches "%s"\n' "$(_inert "$spec")" >&2
                printf '#   pass a bundle path (/Applications/Zoom.app), a bundle ID (us.zoom.xos),\n' >&2
                printf '#   an app name in /Applications (Zoom), or a CLI tool name or path (brew)\n' >&2
                exit 1
              fi ;;
  esac
}

# --apps: each element resolves like [app]; every element is checked before any is resolved.
_resolve_apps_list() {
  local el entry e2 dup
  local -a els=() acc=()
  for el in "${(@s:,:)1}"; do
    while [[ "$el" == [[:space:]]* ]]; do el="${el#?}"; done
    while [[ "$el" == *[[:space:]] ]]; do el="${el%?}"; done
    if [ -z "$el" ]; then
      printf '# culprit: --apps "%s" has an empty entry\n' "$(_inert "$1")" >&2
      exit 1
    fi
    _refuse_registry_chars "--apps entry" "$el"
    els+=("$el")
  done
  for el in "${els[@]}"; do
    TARGET_APPS=()
    _resolve_target "$el"
    for entry in "${TARGET_APPS[@]}"; do
      dup=0
      for e2 in "${acc[@]}"; do [[ "$e2" == "$entry" ]] && dup=1; done
      (( dup )) || acc+=("$entry")
    done
  done
  TARGET_APPS=("${acc[@]}")
}

if [ "$ALL_MODE" != "true" ]; then
  if [ -n "$APPS_OVERRIDE" ]; then
    _resolve_apps_list "$APPS_OVERRIDE"
  elif [ -n "$APP_FILTER" ]; then
    _refuse_registry_chars "app" "$APP_FILTER"
    _resolve_target "$APP_FILTER"
  fi
fi

# Root never works from the caller's directory: every path is absolute from here on.
# `$0` is read outside the function (inside it, it is the function's name).
_CULPRIT_SELF="${0:A}"
_leave_cwd() {
  _CULPRIT_CWD="$PWD"
  LOGFILE="${LOGFILE:a}"
  builtin cd / || exit 1
}
_leave_cwd

# ---------------------------------------
# Exact bundle identifiers, for tcc_modify rule (a)
# ---------------------------------------
# A TCC bundle_id identity must match a target's real CFBundleIdentifier, never its app name
# ("com.evil.Zoom" must not attribute to Zoom). An unreadable id contributes nothing; a CLI target has none.
# Each id carries its label so a multi-target run reports which app the grant belongs to.
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

# clone and link ride with unlink/rename (a persistence item can be copied into place).
# `copyfile` is absent: macOS 26 lists it but emits none. setmode/setowner/setflags/setacl and
# deleteextattr cover the API forms of `chmod u+s` and `xattr -d`, which fire no exec.
# setextattr is not subscribed: the value is not in the event, so nothing could replay it.
[ "$WATCH_FILES" = "true" ] && EVENT_TYPES+=(unlink rename clone link setmode setowner setflags setacl deleteextattr)
[ "$WATCH_READS" = "true" ] && EVENT_TYPES+=(readdir)
# open fires on every file access: opt-in, meant for a single target.
[ "$WATCH_OPENS" = "true" ] && EVENT_TYPES+=(open)
# tcc_modify: a privacy change touches no file and runs no command; tccd's event is the only record.
# macOS 15.4+ only: the preflight below drops it elsewhere.
[ "$WATCH_TCC" = "true" ] && EVENT_TYPES+=(tcc_modify)
# btm_launch_item_add/remove: backgroundtaskmanagementd's event is the only record of a login item change (macOS 13+).
[ "$WATCH_BTM" = "true" ] && EVENT_TYPES+=(btm_launch_item_add btm_launch_item_remove)
# exit separates a wait from a command still running and frees the pid in the attribution
# table (macOS reuses pids). Never printed; always subscribed.
EVENT_TYPES+=(exit)
# Preflight: eslogger refuses the whole subscription if one name is unknown.
# A dropped type is announced; a missing `exec` is fatal.
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

_EXCLUDES_CSV="${(j:,:)DEFAULT_EXCLUDES}"
[ -n "${EXCLUDE_EXTRA:-}" ] && _EXCLUDES_CSV="${_EXCLUDES_CSV},${EXCLUDE_EXTRA}"

# ---------------------------------------
# Utilities & logging
# ---------------------------------------
get_timestamp() {
  if [ "$HAVE_ZSH_STRFTIME" = "true" ]; then local _t; strftime -s _t '%Y-%m-%d %H:%M:%S' "$EPOCHSECONDS"; printf '%s' "$_t"
  else /bin/date '+%Y-%m-%d %H:%M:%S'; fi
}

# --ndjson "ts" for lines log_line wraps itself: ISO 8601 UTC with ms
# (`date` has no %N, so ms come from EPOCHREALTIME, else .000).
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
  # Reader gone (`| head -1`) with SIGPIPE ignored by the launcher: stop quietly, as SIGPIPE would.
  if [ "${NDJSON:-false}" = "true" ]; then printf "$@" >&2; else printf "$@" 2>/dev/null || { _stdout_gone; exit 141; }; fi
}
# Dropping stdout is what silences zsh's deferred "write error" (a 2>/dev/null does not).
_stdout_gone() { exec 1>/dev/null; }
# A failed terminal write in the watcher: stdout is dropped and the main shell stops as for SIGPIPE.
_tty_lost() { _stdout_gone; kill -USR2 $$ 2>/dev/null; return 0; }

# For static strings wrapped into `"msg"` (untrusted paths go through the parser's json.dumps).
_json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/\\r}"
  s="${s//$'\t'/\\t}"
  # Other control bytes are invalid raw in JSON; escape per character, only when present.
  if [[ "$s" == *[[:cntrl:][:INVALID:]]* ]]; then
    # zsh counts some characters above U+FFFF as control (`\u%04x` would give five digits): only
    # C0/C1/DEL need the escape. A non-UTF-8 byte is U+FFFD, as nd_dumps writes it.
    local out="" c i u
    for (( i = 1; i <= ${#s}; i++ )); do
      c="${s[i]}"
      if [[ "$c" == [[:INVALID:]] ]]; then out+="\\ufffd"
      elif [[ "$c" == [[:cntrl:]] ]]; then
        u="$(printf '%04x' "'$c")"
        if (( ${#u} > 4 )); then out+="$c"; else out+="\\u$u"; fi
      else out+="$c"; fi
    done
    s="$out"
  fi
  printf '%s' "$s"
}

# Remove only the directories the probe created (`rmdir` refuses non-empty ones, so nothing pre-existing is reached).
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
  # The probe creates the directory when needed and removes only what it created
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
  [ "$_existed" = 0 ] && /bin/rm -f "$p" 2>/dev/null
  _undo_probe_dirs "$_d" "$_dtop"
  return 0
}
# Candidate log paths, in order: a named path is the only candidate; the default falls back from
# /var/log to /tmp (emptied at boot). An array, so a newline in a path cannot split it.
_log_candidates() {
  reply=("$1")
  [ "${_LOG_EXPLICIT:-0}" = 1 ] || reply+=("/var/log/${1:t}" "/tmp/${1:t}")
}
# Where the log would land, without rotating or truncating: the --detach parent needs it before it forks.
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
  # The one place the tool could touch something not its own residue: refuse anything that is not
  # already a Culprit log or not a regular file (`-s` is true for a directory). One previous generation is kept as <log>.1.
  _is_culprit_log "$p" || return 1
  [ -e "$p" ] && [ ! -f "$p" ] && return 1
  _log_path_safe "$p" || return 1
  if [ -f "$p" ] && [ -s "$p" ]; then /bin/mv -f "$p" "${p}.1" 2>/dev/null || true; fi
  # umask, not chmod afterwards: create-then-chmod leaves a world-readable window on a capture of the
  # whole Mac. The rotated `.1` keeps the 0600 mode.
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
  return 1
}

# The log is opened once (_open_log_fd) and never by path again: a link swapped in between two lines is not followed.
# No fd yet: nothing is written to the file.
_log_fd_write() { if [ -n "${_LOG_FD:-}" ]; then printf "$@" >&$_LOG_FD 2>/dev/null || true; fi; return 0; }
_open_log_fd() {
  local -A _h
  zmodload zsh/system 2>/dev/null && zmodload -F zsh/stat b:zstat 2>/dev/null || return 1
  sysopen -a -w -o creat,nofollow -m 600 -u _LOG_FD -- "$LOGFILE" 2>/dev/null || return 1
  zstat -H _h -f $_LOG_FD 2>/dev/null && (( (_h[mode] & 8#170000) == 8#100000 && _h[nlink] == 1 && _h[uid] == EUID )) && return 0
  exec {_LOG_FD}>&-; unset _LOG_FD
  return 1
}

# The watcher feeds one long-lived logger (_SYSLOG_FD): a fork per line made a large --report take seconds to reach the log.
_syslog() {
  if [ -n "${_SYSLOG_FD:-}" ]; then print -r -- "$1" >&$_SYSLOG_FD 2>/dev/null || true
  else /usr/bin/logger -t "culprit" -- "$1" 2>/dev/null || true; fi
}
# Core log. ONLY_CMDS keeps just the "Cmd: …" payload.
log_line() {
  local msg="$1" ts
  # --ndjson: every line is one JSON object whatever -v/-q says: a JSON payload passes through,
  # any other line is wrapped as an info object.
  if [ "${NDJSON:-false}" = "true" ]; then
    local nout
    case "$msg" in Cmd:\ *) nout="${msg#Cmd: }";; *) return 0;; esac
    [ -z "$nout" ] && return 0
    case "$nout" in
      \{*) ;;
      *) nout="{\"type\":\"info\",\"ts\":\"$(get_timestamp_utc)\",\"msg\":\"$(_json_escape "$nout")\"}" ;;
    esac
    printf "%s\n" "$nout" 2>/dev/null || _tty_lost
    _log_fd_write "%s\n" "$nout"
    _syslog "$nout"
    return 0
  fi
  # A report spacer: blank in every mode, never stamped or sent to syslog.
  if [ "$msg" = "Cmd: " ]; then
    printf "\n" 2>/dev/null || _tty_lost
    _log_fd_write "\n"
    return 0
  fi
  if [ "${ONLY_CMDS:-false}" = "true" ]; then
    local out
    case "$msg" in Cmd:\ *) out="${msg#Cmd: }";; *) return 0;; esac
    # stdout may vanish with the terminal; a dead tty must not take the watcher down.
    printf "%s\n" "$out" 2>/dev/null || _tty_lost
    _log_fd_write "%s\n" "$out"
    _syslog "$out"
    return 0
  fi
  ts="$(get_timestamp)"
  printf "[%s] %s\n" "$ts" "$msg" 2>/dev/null || _tty_lost
  _log_fd_write "[%s] %s\n" "$ts" "$msg"
  _syslog "$msg"
}

# ---------------------------------------
# The Python parser
# ---------------------------------------
# Attribution: an exec is credited to a target when the acting process, its parent (ppid) or its
# responsible process is tracked, or the new image matches a target (Team ID / bundle path), which also
# seeds tracking. Field extraction is defensive: eslogger's JSON shape varies by macOS.
PARSER="$CULPRIT_TMPDIR/parser.py"
/bin/cat > "$PARSER" <<'PY'
import sys, json, time, shlex, re, os, math, signal, stat, functools, tempfile, collections, heapq
import urllib.parse, unicodedata, hashlib, threading

# UTF-8 whatever the locale (python runs with -I): a non-UTF-8 byte reads as U+DC80-U+DCFF and never raises.
for _stream in (sys.stdin, sys.stdout): _stream.reconfigure(encoding="utf-8", errors="surrogateescape")

# ============================================================================
# RUNTIME CONTEXT
# ============================================================================

# The console user's home, so `rm -rf ~/Library/Biome/*` globs match absolute paths.
HOME = os.environ.get("CULPRIT_HOME", "")

# Own pid: dir_state() reads must not make the parser an actor in its own output.
SELF_PID = os.getpid()

# ============================================================================
# --mdm
# ============================================================================

# --mdm: user-specific paths become fleet-portable: /Users/<me>/ and ~/ become /Users/$loggedInUser/;
# per-user /var/folders/<a>/<b>/{0,C,T}/ roots become $userDir/$userCache/$userTemp.
MDM = os.environ.get("CULPRIT_MDM") == "1"
# The bare folder still counts: a boundary lookahead, not a required trailing slash.
# Only the console user's own prefix (root's or another user's tree is not theirs); unknown = never matches.
_MDM_UD = re.fullmatch(r'(?:/private)?(/var/folders/[^/]+/[^/]+)/0/?', os.environ.get("CULPRIT_USERDIR", ""))
_MDM_FPFX = r'(?:/private)?' + re.escape(_MDM_UD.group(1)) if _MDM_UD else r'(?!)'
_MDM_FOLDERS_RE = re.compile(_MDM_FPFX + r'/([0CT])(?=[/\s"\']|$)')
_MDM_VAR = {"0": "$userDir", "C": "$userCache", "T": "$userTemp"}
mdm_noted = False

# Only the --mdm variables may force a single-quoted segment open (re-quoting any `$` would break
# captured awk programs like '{print $3}'). Every segment is matched and the callback decides, so one
# path's closing quote never pairs with the next one's opening quote.
_SQ_SEG_RE = re.compile(r"'([^']*)'")
_MDM_VAR_RE = re.compile(r'\$(?:loggedInUser|userDir|userCache|userTemp)')
# Everything double quotes would still interpret is escaped on promotion, so a path holding
# backticks or `$` cannot become a command substitution in a root fleet script.
_MDM_DQ_ESC = re.compile(r'([\\"`$])')
# `!`: a backslash before it is NOT removed inside bash double quotes, so it is closed out and
# single-quoted (`"a"'!'"b"`), which history expansion leaves alone in both shells.
def _mdm_esc(t): return _MDM_DQ_ESC.sub(r'\\\1', t).replace("!", "\"'!'\"")
def _mdm_dq(seg):
    out, last = [], 0
    for m in _MDM_VAR_RE.finditer(seg):
        out.append(_mdm_esc(seg[last:m.start()]))
        out.append(m.group(0))
        last = m.end()
    out.append(_mdm_esc(seg[last:]))
    return '"%s"' % "".join(out)

# An ANSI-C `$'…'` argument is matched whole, first; a --mdm variable is spliced out between two
# halves (double quotes would give a `$"…"` locale string, `\n` not decoded).
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

# The short user NAME is rewritten only where a command takes a user (`-u`/`-U <user>`, or the operand
# of a listed command), never as a bare word: `admin` or `test` would corrupt arguments.
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
        re.compile(r'(?<![\w-])(-[uU]\s+)' + _u + r'(?![\w.-])', re.I),
        re.compile(r'(?<![\w./-])((?:/\S+/)?(?:' + "|".join(_MDM_USER_CMDS) +
                   r')(?:\s+-\S+)*\s+)' + _u + r'(?![\w.-])', re.I),
    ]
_MDM_USER_RES = tuple(_MDM_USER_RES)

# A `$'…'` segment, walked like _SH_WALK_RE.
_MDM_ANSI_SEG_RE = re.compile(r"""'[^']*'|"(?:[^"\\]|\\.)*"|\$'(?:[^'\\]|\\.)*'""", re.S)
_MDM_ANSI_B = r'(?=[/\s"\']|\\[ntrvf]|\\x(?:0[9a-dA-D]|1[c-fC-F]|27)|$)'
_MDM_FOLDERS_ANSI_RE = re.compile(_MDM_FPFX + r'/([0CT])' + _MDM_ANSI_B)
def _mdm_ansi_paths(seg):
    if not seg.startswith("$'"): return seg
    if HOME: seg = re.sub(re.escape(HOME) + _MDM_ANSI_B, "/Users/$loggedInUser", seg)
    return _MDM_FOLDERS_ANSI_RE.sub(lambda m: _MDM_VAR[m.group(1)], seg)

# A `$loggedInUser`-like word in the input is the app's own bytes: parked behind private-use marks during
# the rewrite (mdm_quotes would lift it into double quotes, where it expands), then restored inert.
_MDM_LIT_RE = re.compile(r'\$(loggedInUser|userDir|userCache|userTemp)')
_MDM_LIT_BACK_RE = re.compile('\ue000(loggedInUser|userDir|userCache|userTemp)\ue001')
_MDM_LIT_WALK_RE = re.compile(r"""\$'(?:[^'\\]|\\.)*'|'[^']*'|"(?:[^"\\]|\\.)*\"""", re.S)
def _mdm_lit_back(s):
    s = _MDM_LIT_WALK_RE.sub(lambda m: _MDM_LIT_BACK_RE.sub(
        (r'\\$\1' if m.group(0)[0] == '"' else r'$\1'), m.group(0)), s)
    return _MDM_LIT_BACK_RE.sub(r'$\1', s)

def mdm_rewrite(s):
    if not MDM: return s
    s = _MDM_LIT_RE.sub('\ue000\\1\ue001', s)
    # The bare home still counts (bounded, so /Users/ardvark is left alone); inside `$'…'` the boundary
    # can also be an escape such as `\n`.
    s = _MDM_ANSI_SEG_RE.sub(lambda m: _mdm_ansi_paths(m.group(0)), s)
    if HOME: s = re.sub(re.escape(HOME) + r'(?=[/\s"\']|$)', "/Users/$loggedInUser", s)
    s = s.replace("~/", "/Users/$loggedInUser/")
    s = _MDM_FOLDERS_RE.sub(lambda m: _MDM_VAR[m.group(1)], s)
    # After the paths, so /Users/<me> is already a variable.
    for _rx in _MDM_USER_RES: s = _rx.sub(r'\1$loggedInUser', s)
    s = mdm_quotes(s)
    return _mdm_lit_back(s) if "\ue000" in s else s

# The resolver lines --mdm output depends on, as data so --report emits the same block (_render_lines).
_MDM_HEADER = (
    "# NOTE: --mdm — define these once at the top of your script, then every command below deploys on any Mac:",
    "#   loggedInUser = output of /usr/bin/stat -f%Su /dev/console",
    "#   userDir = output of /usr/bin/getconf DARWIN_USER_DIR, run as loggedInUser through /usr/bin/sudo -u",
    "#   userCache = output of /usr/bin/getconf DARWIN_USER_CACHE_DIR, run the same way",
    "#   userTemp = output of /usr/bin/getconf DARWIN_USER_TEMP_DIR, run the same way",
)
# The same four as live code (a `$(` in a `#` line would run if pasted into a zsh without interactivecomments).
_MDM_RESOLVERS = (
    "loggedInUser=$(/usr/bin/stat -f%Su /dev/console)",
    "userDir=$(/usr/bin/sudo -u \"$loggedInUser\" /usr/bin/getconf DARWIN_USER_DIR)",
    "userCache=$(/usr/bin/sudo -u \"$loggedInUser\" /usr/bin/getconf DARWIN_USER_CACHE_DIR)",
    "userTemp=$(/usr/bin/sudo -u \"$loggedInUser\" /usr/bin/getconf DARWIN_USER_TEMP_DIR)",
)

# The same resolvers as live code for the report's script; with nobody at the console it says so and exits 0.
def _mdm_script_header(cmds):
    _body = "\n".join(cmds)
    _vars = [v for v in ("userDir", "userCache", "userTemp") if "$" + v in _body]
    if not _vars and "$loggedInUser" not in _body: return []
    _hdr = ["# --mdm: resolved on the Mac that runs this script",
            _MDM_RESOLVERS[0],
            'case "$loggedInUser" in ""|root|loginwindow|_mbsetupuser) '
            'echo "no user logged in — nothing to do"; exit 0;; esac']
    for _l in _MDM_RESOLVERS[1:]:
        if _l.split("=", 1)[0] in _vars: _hdr.append(_l)
    return _hdr

def mdm_header():
    global mdm_noted
    if not MDM or mdm_noted: return
    mdm_noted = True
    for _l in _MDM_HEADER: out("C\t" + _l)

# ============================================================================
# INVOCATION
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
# By environment, not argv, whose positions are fixed. Defaults to on; off for CULPRIT_TCC=0 (--events -tcc, --destructive-only).
WATCH_TCC = os.environ.get("CULPRIT_TCC", "1") != "0"
WATCH_BTM = os.environ.get("CULPRIT_BTM", "1") != "0"
# tcc_modify rule (a): exact CFBundleIdentifier per target from each bundle's Info.plist, one
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
    # "cli" = a single EXECUTABLE target, matched by exact path; its own exec IS the command worth showing.
    # Trailing `/` stripped so the boundary tests see the bundle.
    targets.append({"label": p[0], "team": p[1],
                    "bundle": p[2].rstrip("/") if len(p[2]) > 1 else p[2],
                    "helpers": set(h for h in p[3].split(",") if h),
                    "cli": set(c for c in p[4].split(",") if c)})

# SOLO: one target. The `# <app> ran:` header is dropped, leaving a bare copy-pasteable command list;
# a destructive command keeps a `# ⚠` marker.
SOLO = (not ALL_MODE) and len(targets) == 1

# ============================================================================
# READING THE EVENT
# ============================================================================
# Shape varies by macOS release: every accessor answers "" or None rather than raising.

# Credit the OUTERMOST .app (helpers nest their own bundle), not "Code Helper".
_APP_EXE_RE = re.compile(r'\.app/Contents/MacOS/')
_APP_RE = re.compile(r'/([^/]+)\.app/')
def app_bundle_name(path):
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

# (pid, pidversion) names one process image: dict key, or index 7 of audit_token_t; None when absent.
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
        # Return the value, not the container: a non-string path would raise downstream and lose the report.
        _p = ex.get("path", "")
        return _p if isinstance(_p, str) else ""
    if isinstance(ex, str): return ex
    return ""

def exec_args(execu, tgt):
    # args sit under exec.args or exec.target.args by macOS version. A malformed argv is not repaired (would
    # fabricate a command line): the exec reports its executable alone.
    for a in (execu.get("args"), tgt.get("args") if isinstance(tgt, dict) else None):
        if isinstance(a, list) and a and all(isinstance(x, str) for x in a):
            return a
    return []

# ============================================================================
# ATTRIBUTION
# ============================================================================

def match_target(team, path, sid=""):
    # Exact paths first (CLI, bundle prefix, helper), Team ID only after: two apps of one vendor share one.
    for t in targets:
        if path and path in t["cli"]: return t["label"]
        # The bundle itself or a path INSIDE it, never a bare prefix (X.app.bak is not X).
        if t["bundle"] and path and (path == t["bundle"] or path.startswith(t["bundle"] + "/")):
            return t["label"]
        if path and path in t["helpers"]: return t["label"]
    # Team ID only: an ad-hoc binary has no team_id and an arbitrary signing_id.
    cands = [t for t in targets if t["team"] and team and team == t["team"]]
    if len(cands) <= 1: return cands[0]["label"] if cands else None
    # Targets sharing a Team ID: match signing_id to the real CFBundleIdentifier (+ optional ".suffix");
    # still ambiguous means no attribution.
    hits = []
    for t in cands:
        for bid, lbl in TARGET_BUNDLE_IDS.items():
            if lbl == t["label"] and sid and (sid == bid or sid.startswith(bid + ".")):
                hits.append(t["label"])
                break
    return hits[0] if len(hits) == 1 else None

def match_proc(proc, path):
    return match_target(field(proc, "team_id"), path, field(proc, "signing_id"))

def is_cli_target(path):
    return bool(path) and any(path in t["cli"] for t in targets)

def is_cli_launch(path, script=""):
    # Parent is the launcher (a terminal's shell), never in the tool's subtree: tracking it would credit the
    # tool with everything typed after.
    return is_cli_target(path) or (bool(script) and is_cli_target(script))

def is_platform(proc):
    if not isinstance(proc, dict): return False
    v = proc.get("is_platform_binary")
    if isinstance(v, bool): return v
    if isinstance(v, str): return v.strip().lower() in ("1", "true", "yes")
    p = exe_path(proc)
    # /Applications (and /System/Applications): Apple's GUI apps stay attributable, not platform noise.
    if "/Applications/" in p: return False
    # is_apple_path() resolves the real path and strips /System/Volumes/Data; /usr/local and /opt stay third-party.
    return is_apple_path(p)

# Third-party code outside any .app: an SMJobBless helper is started by launchd with no bundle and no tracked
# ancestor. SUBSTRING match: the same layout exists per user under ~/Library/Application Support.
_OUT_OF_BUNDLE_DIRS = ("/Library/PrivilegedHelperTools/", "/Library/Application Support/")
# Root lives HERE only (SMJobBless installs here).
_PRIVILEGED_DIR = "/Library/PrivilegedHelperTools/"

# python3 resolves into CommandLineTools' Python.app: toolchain code may run commands under a real app's
# label but never become a label. -v lifts this.
_TOOLCHAIN_DIRS = ("/Library/Developer/", "/Applications/Xcode.app/")

# A shebang script does not exec itself: its path appears only in argv (/bin/bash /opt/homebrew/bin/brew ...),
# so judging the interpreter alone drops script tools and their subtrees.
_INTERPRETERS = ("sh", "bash", "zsh", "dash", "ksh", "tcsh", "csh",
                 "python", "python2", "python3", "ruby", "perl", "node",
                 "deno", "bun", "php", "osascript", "tclsh", "wish",
                 "Rscript", "expect")
_INTERP_RE = re.compile(r'^(python\d(\.\d+)?|ruby\d(\.\d+)?|perl5(\.\d+)*|node\d*)$')
def is_interpreter(path):
    b = path.rsplit("/", 1)[-1]
    return b in _INTERPRETERS or bool(_INTERP_RE.match(b))

# Apple script locations: a system script run by a system daemon is not third-party. /usr/local is carved out
# in third_party_script(); /opt is absent on purpose (MacPorts, Homebrew).
_APPLE_SCRIPT_DIRS = ("/System/", "/usr/", "/bin/", "/sbin/", "/etc/",
                      "/private/etc/", "/Library/Apple/")
def third_party_script(p):
    # Resolved first: /System/Volumes/Data/... (the Data volume's route to /Applications, /Users) must not pass
    # as Apple. Same normalisation as is_apple_path.
    if not p or not p.startswith("/"): return ""
    try: r = os.path.realpath(p)
    except Exception: r = os.path.normpath(p)
    _dv = "/System/Volumes/Data"
    if r == _dv: return ""
    if r.startswith(_dv + "/"): r = r[len(_dv):] or "/"
    if r.startswith("/usr/local/"): return p
    return "" if r.startswith(_APPLE_SCRIPT_DIRS) else p

def script_image(path, args):
    # Fallback when event.exec.script is empty. Only an ABSOLUTE argv path: a relative one cannot be judged
    # without the working directory.
    if not args or not is_interpreter(path): return ""
    for a in args[1:]:
        if a == "-": return ""
        if a.startswith("-"): continue
        if not a.startswith("/"): return ""     # `-c '…'`, a bare word: no script
        return third_party_script(a)
    return ""

def third_party_name(proc, script=""):
    # ALL mode: the third-party actor this image belongs to, or "" if Apple's or unattributable.
    path = exe_path(proc)
    # Judged and named on the script's own path: a Homebrew tool is "brew", not "bash".
    sp = script
    if sp:
        path = sp
    elif is_platform(proc):
        # An Apple application (Terminal, Script Editor) is a legitimate actor under -v; daemons and XPC stay out.
        if not SHOW_NOISE or not _APP_EXE_RE.search(path): return ""
    if not SHOW_NOISE and path.startswith(_TOOLCHAIN_DIRS): return ""
    name = app_bundle_name(path)
    if not name:
        if _PRIVILEGED_DIR in path:
            name = path.rsplit("/", 1)[-1]
        else:
            # Under Application Support the file name is generic; the vendor folder identifies.
            for d in _OUT_OF_BUNDLE_DIRS:
                if d in path:
                    rest = path.split(d, 1)[1]
                    name = rest.split("/", 1)[0] if "/" in rest else rest
                    break
            else:
                # Last resort: third-party code outside bundles (Homebrew daemons, /usr/local agents, MDM scripts).
                name = path.rsplit("/", 1)[-1] if path else ""
    return name

def resolve_app(proc, script=""):
    # Target label wins in every mode; a script is matched on its own path (script-based tool, interpreter exec).
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
    # True if this process IS an app/helper's own image (launch/relaunch), not a command it runs.
    # `inherited` = an already-attributed process ran this.
    path = exe_path(proc)
    sp = script
    judged_path = sp or path
    if (match_proc(proc, path) is not None
            or (sp and match_target("", sp) is not None)):
        if is_cli_target(judged_path): return False
        # Only the bundle's MAIN executable is the app; a script in Contents/Resources is a command.
        if _APP_EXE_RE.search(path): return True
        return any(path in t["helpers"] for t in targets)
    if not ALL_MODE or not third_party_name(proc, script): return False
    # Inside a bundle only the main executable is the app relaunching; anything else is a command.
    if _APP_RE.search(judged_path): return _APP_EXE_RE.search(judged_path) is not None
    # Outside a bundle it depends on who started it. Launched by another process (acting pid != new pid): its own
    # image, announced once. Exec'd in place (acting pid == new pid): inherited, so a command.
    return not inherited

# ============================================================================
# PRIVACY (TCC)
# ============================================================================
# tcc_modify's process is always tccd, never the app concerned. Owner judged in order: (a) identity IS a tracked
# app (a grant can happen while it is not running); (b) instigator/responsible is tracked; (c) ALL mode,
# third-party identity.

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
    if itype == 1:
        return match_target("", identity)
    # identity_type 0 = bundle id, matched against the REAL CFBundleIdentifier (TARGET_BUNDLE_IDS), exact and
    # case-sensitive; no entry means no match here.
    if itype == 0:
        return TARGET_BUNDLE_IDS.get(identity) if identity else None
    return None

def is_apple_path(p):
    # Rule (c) of TCC and BTM, judged on a PATH alone (the event carries no platform flag). realpath resolution
    # means a symlink cannot hide it (/Applications/Safari.app links into /System/Cryptexes/), nor can a third
    # party spelling /System/Volumes/Data/... pass as Apple.
    if not p or not p.startswith("/"): return False
    return third_party_script(p) == ""

def _tcc_identity_is_apple(identity, itype):
    # identity_type 1 is a PATH (/usr/libexec/sshd-keygen-wrapper is Apple's despite no com.apple.); other types: prefix only.
    if itype == 1: return is_apple_path(identity)
    return identity.startswith("com.apple.")

def _app_suffix(label):
    # SOLO names one app, so nothing is added; with several targets or ALL mode the label is appended.
    return " — app: %s" % inert_word(label) if label and not SOLO else ""

def _tcc_actor(tm):
    resp = tm.get("responsible")
    return resp if isinstance(resp, dict) else tm.get("instigator")

def _tcc_label_for(identity, itype, actor):
    # Returns (label, counted): label is None for an untargeted third party in ALL mode.
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
    # `1e400` parses as inf and int(inf) raises OverflowError, which would lose the whole event.
    try: return int(v)
    except (TypeError, ValueError, OverflowError): return None
def _str_or_empty(v):
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
    # A buffered deletion predates this change: print it first (event order).
    flush_deletes()
    actor_path = exe_path(actor) if isinstance(actor, dict) else ""
    right_s = _tcc_enum(_TCC_RIGHT, right)
    reason_s = _tcc_enum(_TCC_REASON, reason)
    utype_s = _tcc_enum(_TCC_UPDATE, utype)
    itype_s = _tcc_enum(_TCC_IDTYPE, itype)
    # --report stays silent during capture; --ndjson stays live.
    if not QUIET:
        if NDJSON:
            # pid/pidver: the actor's, else the token the event carries.
            _atok = actor.get("audit_token") if isinstance(actor, dict) else (
                tm.get("responsible_token") if tm.get("responsible_token") is not None
                else tm.get("instigator_token"))
            # --mdm rewrites a home in identity here too.
            obj = {"type": "tcc", "ts": ts_iso(), "service": service, "identity": mdm_rewrite(identity),
                   "identity_type": itype_s, "right": right_s, "reason": reason_s,
                   "update_type": utype_s, "instigator": actor_path or None,
                   "app": label or None, "pid": audit_pid(_atok), "pidver": audit_pidver(_atok)}
            # ensure_ascii: untrusted strings from the event.
            raw_out("C\t" + nd_dumps(obj))
        else:
            raw_out("C\t# TCC: %s %s for %s (%s, %s)%s"
                    % (inert_word(service), inert_word(right_s), inert_word(mdm_rewrite(identity)),
                       inert_word(reason_s), inert_word(utype_s), _app_suffix(label)))
    record_tcc(service, identity, right_s, reason_s, utype_s, actor_path, label or "")

# ============================================================================
# LOGIN ITEMS (BTM)
# ============================================================================
# btm_launch_item_add/remove: backgroundtaskmanagementd's registry of what launches at login (Settings toggle,
# SMAppService, MDM profile), none of which shells out. Attribution as TCC: (a) the ITEM's path is a tracked
# app's bundle or CLI; (b) the instigator or app process is tracked; (c) ALL mode, third-party item. Never by name.

_BTM_ITEM_TYPE = {0: "user item", 1: "app", 2: "login item", 3: "agent", 4: "daemon"}

def _btm_kind(v):
    if v is None: return "?"
    return _BTM_ITEM_TYPE.get(v, str(v))

def _btm_decode_url(u):
    # file:// URL -> local path, percent-decoded, trailing slash stripped; None for anything else.
    if not isinstance(u, str) or not u.startswith("file://"): return None
    try:
        p = urllib.parse.unquote(urllib.parse.urlparse(u).path)
    except Exception:
        return None
    if len(p) > 1 and p.endswith("/"): p = p.rstrip("/")
    return p or None

def _btm_item_path(item, exe_path_field):
    # item_url, then executable_path ("add" shape only), then app_url; else a raw url taken literally.
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
    # Rule (a): a tracked app's bundle or inside it (never a bare prefix), or a tracked CLI target exactly.
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
    # --report stays silent during capture; --ndjson stays live.
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
            # ensure_ascii: untrusted strings from the event.
            raw_out("C\t" + nd_dumps(obj))
        else:
            _suffix = kind_s + (" (managed)" if managed else "") + (" (legacy)" if legacy else "")
            _app = _app_suffix(label)
            _bp, _bs = inert_word(mdm_rewrite(path)), inert_word(short)
            if action == "add":
                raw_out("C\t# LOGIN ITEM added (%s): %s — via %s%s   ⚠ persistence" % (_suffix, _bp, _bs, _app))
            else:
                raw_out("C\t# LOGIN ITEM removed (%s): %s — via %s%s" % (_suffix, _bp, _bs, _app))
    record_btm(action, path, kind_s, short, label or "")

# ============================================================================
# CLASSIFICATION
# ============================================================================
# Rule tables are read through triggered(). Trigger forms: a literal, a prefix (`--set*`), a suffix
# (`*/.zcompdump`), a regex (`~^[2-7][0-7]{3}$`), or None for any arguments.

# Destructive rules, one entry per binary. None = whatever the arguments; a set = only when one is present.
DESTRUCTIVE = {
    # Removal / overwrite
    "rm": None, "rmdir": None, "srm": None, "unlink": None, "shred": None,
    "dd": None, "mkfs": None, "newfs": None,
    "find": {"-delete"},
    "chflags": {"nouchg", "noschg"},        # unlocks files so they CAN be deleted
    # Process control / power state
    "kill": None, "killall": None, "pkill": None,
    "shutdown": None, "reboot": None, "halt": None,
    # `kill <sig>`, `stop <label>`, `kickstart -k` (may be a cluster like `-kp`, hence the regex); plain kickstart stays unmarked.
    "launchctl": {"bootout", "unload", "remove", "disable", "kill", "stop",
                  "~^-[A-Za-z]*k[A-Za-z]*$"},
    # Caches & system databases
    "purge": None,
    "dscacheutil": {"-flushcache"},
    "atsutil": {"remove", "-remove"},
    "mdutil": {"-E", "-X"},
    # `-delete` tears down the LaunchServices database; the store's unlink then arrives attributed `via lsregister`.
    "lsregister": {"-kill", "-delete"},
    # The rule is the STATEMENT, not the binary. Case-insensitive regex triggers: SQL is free-form.
    "sqlite3": {r"~(?i)\bdelete\s+from\b", r"~(?i)\bdrop\s+(table|index|trigger|view)\b",
                r"~(?i)\bupdate\s+\S+\s+set\b", r"~(?i)\btruncate\b"},
    "qlmanage": {"-r"},
    "kextcache": {"-i", "-u", "--invalidate", "--update-volume"},
    "defaults": {"delete"},
    # Disks & snapshots
    "diskutil": {"erase", "eraseDisk", "eraseVolume", "reformat",
                 "deleteVolume", "deleteContainer", "deleteSnapshot",
                 "repairVolume", "repairDisk", "resetUserPermissions"},
    "fsck": None,
    "tmutil": {"delete", "deletelocalsnapshots", "disable"},
    # Read-only tools that can also write: the write form only
    "git":  {"--hard", "-D", "clean", "prune", "filter-branch",
             "--force", "--force-with-lease"},
    # Firewall: the whole --set* family at once
    "socketfilterfw": {"--set*", "--add", "--remove"},
    "sysctl": {"-w"},
    "sed": {"-i"},
    "dscl": {"-delete"},
    "plutil": {"-remove"},
    # setuid and world-writable matter most; each has an octal and a symbolic spelling, hence the regexes.
    "chown": {"-R", "~^root(:|$)"},         # taking ownership for root
    "chmod": {"-R",
              "~[+=][rwx]*s",               # setuid/setgid: u+s, a+rws, u=rws
              "~^[2-7][0-7]{3}$",           # …and in octal: 4755, 2755, 6711
              "~^[0-7]{2,3}[2367]$",        # world-writable: 777, 666, 757
              "o+w", "a+w"},
    "csrutil": {"disable"},                 # System Integrity Protection off
    "nvram": {"-c", "-d"},                  # clear NVRAM
    "spctl": {"--master-disable", "--global-disable"},
    # Removal by tools that are not `rm` (`find -exec` is handled in is_destructive).
    "crontab": {"-r"},
    "security": {"delete-keychain", "delete-generic-password",
                 "delete-internet-password", "delete-certificate"},
    "profiles": {"remove", "-R", "-D"},
    "tccutil": {"reset"},                   # wipes privacy/security grants for an app
    "systemextensionsctl": {"uninstall", "reset"},
    "pkgutil": {"--forget"},
    "hdiutil": {"erasekeys"},
    "truncate": {"~^0$"},
    "log": {"erase"},
    # A removal written in an interpreter's own call: the call, not the binary, is the rule.
    "perl": {r"~\b(?:unlink|rmdir|rmtree|remove_tree)\b[\s(]"},
    "python": {r"~\b(?:rmtree|os\.(?:remove|unlink|rmdir|removedirs))\s*\(", r"~\.unlink\s*\("},
    "python3": {r"~\b(?:rmtree|os\.(?:remove|unlink|rmdir|removedirs))\s*\(", r"~\.unlink\s*\("},
    "rsync": {"--delete*", "--del", "--remove-source-files"},
}

_TRIG_RE = {}
def triggered(trig, args):
    # None = always. A trigger ending in "*" matches by prefix, starting with "*" by suffix, starting with "~" is a
    # REGEX (a mode is written `u+s`, `4755` or `6711`, all setuid).
    if trig is None: return True
    aset = set(args)
    for t in trig:
        if t.startswith("~"):
            rx = _TRIG_RE.get(t)
            if rx is None:
                try: rx = _TRIG_RE[t] = re.compile(t[1:])
                except re.error: _TRIG_RE[t] = False; continue
            if rx is False: continue
            if any(rx.search(a) for a in args[1:]): return True
        elif t.startswith("*"):
            if any(a.endswith(t[1:]) for a in args): return True
        elif t.endswith("*"):
            if any(a.startswith(t[:-1]) for a in args): return True
        elif t in aset:
            return True
    return False

_OSA_SHELL_RE = re.compile(r'do shell script\s+"((?:[^"\\]|\\.)*)"')
def is_destructive(path, args):
    b = path.rsplit("/", 1)[-1]
    if b == "find":
        # The destructive act is the command `-exec` RUNS; destructive_stage cannot see it (it splits on `;`).
        for i, a in enumerate(args):
            if a in ("-exec", "-execdir", "-ok", "-okdir") and i + 1 < len(args):
                inner = [x for x in args[i + 1:]
                         if x not in (";", "\\;", "+", "{}")]
                if inner and inner[0] != "find" and is_destructive(inner[0], inner):
                    return True
    if b == "osascript":
        # `do shell script "…"` runs a shell line: judged like one.
        for a in args[1:]:
            for m in _OSA_SHELL_RE.finditer(a):
                try: toks = shell_tokens(m.group(1).replace('\\"', '"').replace("\\\\", "\\"))
                except ValueError: continue
                if toks and destructive_stage(toks): return True
    if b not in DESTRUCTIVE: return False
    return triggered(DESTRUCTIVE[b], args)

# ============================================================================
# FILE EVENTS
# ============================================================================
# unlink, rename, clone, link and the permission events, each reduced to the command that reproduces it.

def any_path(node, depth=0):
    # Bodies nest the path differently per event type and macOS version: walk for the first "path" string.
    # Lists are walked too (a `target` may become a list of one file); depth capped at 8.
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

def atomic_write(src, dst):
    # write-to-temp then rename-into-place is plumbing; a rename across directories is a real move.
    if not src or not dst: return False
    return src.rsplit("/", 1)[0] == dst.rsplit("/", 1)[0]

# A save's scratch name (mkstemp, browser partial, Cocoa safe-save, the destination's own name plus filler).
# `x` -> `x.locked` is the reverse: the source is the real file, and the rename shows.
_TEMP_SUFFIXES = (".temp", ".crdownload")
_TEMP_WORDS = frozenset(("tmp", "temp", "swp", "swx", "part", "crdownload", "download"))
_SAFE_SAVE_RE = re.compile(r'^\.dat\.nosync[0-9A-Fa-f]+(\.[A-Za-z0-9]+)?$|\.sb-[0-9A-Fa-f]+-[A-Za-z0-9]+$')
_NAME_SEP_RE = re.compile(r'[.\-_~#]+')
def _filler(t, n, digits):
    # Generated, not chosen: `AbC123`, `1a2b3c` and a pid are; `Backup`, `locked` and `bak` are words.
    if len(t) < n or not t.isascii() or not t.isalnum(): return False
    if t.isdigit(): return digits
    if any(c.isdigit() for c in t): return any(c.isalpha() for c in t)
    return any(c.isupper() for c in t) and any(c.islower() for c in t) and not t.istitle()
# After the destination's own stem only: `prefs-1.js`, `cache-new.bin`, `dir-updating` -> the real name.
_STEM_WORDS = _TEMP_WORDS | {"new", "updating"}
def _temp_tok(t, digits, words=_TEMP_WORDS):
    tl = t.lower()
    if tl in words: return True
    for p in ("tmp", "temp"):
        if tl.startswith(p) and (len(t) == len(p) or _filler(t[len(p):], 1, True)): return True
    return _filler(t, 4 if digits else 6, digits)
def temp_name(src, dst):
    sb = src.rsplit("/", 1)[-1]
    db = dst.rsplit("/", 1)[-1]
    if transient(src) or sb.endswith(_TEMP_SUFFIXES) or _SAFE_SAVE_RE.search(sb): return True
    core = sb[1:] if sb.startswith(".") else sb
    if db and len(core) > len(db) and core.startswith(db) and core[len(db)] in ".-_~#":
        return all(_temp_tok(t, True, _STEM_WORDS) for t in _NAME_SEP_RE.split(core[len(db):]) if t)
    stem, dot, ext = db.rpartition(".")
    if stem and dot and core.endswith("." + ext) and core.startswith(stem) and len(core) > len(db):
        mid = core[len(stem):-len(ext) - 1]
        toks = [t for t in _NAME_SEP_RE.split(mid) if t]
        if mid[:1] in tuple(".-_~#") and toks:
            return all(t.isdigit() or _temp_tok(t, True, _STEM_WORDS) for t in toks)
    toks = [t for t in _NAME_SEP_RE.split(sb) if t]
    if not toks: return False
    if len(toks) == 1 and not sb.startswith("."):
        return toks[0].lower().startswith(("tmp", "temp")) and _temp_tok(toks[0], False)
    return _temp_tok(toks[-1], False)

# Where software arranges to come back (launch item, privileged helper, system extension, PATH binary, /etc). A
# temp-then-rename install reads as atomic_write() plumbing: wrong for a LaunchDaemon.
_PERSIST_ROOTS = ("/usr/local/bin/", "/usr/local/sbin/", "/opt/homebrew/bin/", "/opt/homebrew/sbin/",
                  "/Library/StartupItems/", "/Library/Extensions/",
                  "/Library/SystemExtensions/")
# Anchored at /Library (system or per-user): a package expanded under a temp dir (.../Payload/System/Library/...) is not an install.
_PERSIST_ANY_RE = re.compile(r"(?:/Users/[^/]+|/var/root|~)?/Library/(?:LaunchDaemons|LaunchAgents|PrivilegedHelperTools)/")
# Only the /etc paths that re-run on their own: all of /etc would mark ordinary atomic rewrites as persistence.
_PERSIST_ETC_DIRS = ("/etc/periodic/", "/etc/pam.d/", "/etc/sudoers.d/",
                     "/etc/ssh/sshd_config.d/", "/etc/ssh/ssh_config.d/",
                     "/etc/paths.d/", "/etc/manpaths.d/", "/etc/emond.d/")
_PERSIST_ETC_FILES = ("/etc/rc.common", "/etc/launchd.conf", "/etc/crontab",
                      "/etc/sudoers", "/etc/ssh/sshd_config", "/etc/ssh/ssh_config",
                      "/etc/profile", "/etc/zshrc", "/etc/zprofile", "/etc/zshenv",
                      "/etc/zlogin", "/etc/zlogout", "/etc/bashrc",
                      "/etc/csh.cshrc", "/etc/csh.login")
# A user's shell startup file runs at every login or new shell.
_PERSIST_RC_RE = re.compile(r"(?:/Users/[^/]+|/var/root|~)/\.(?:zshrc|zprofile|zshenv|zlogin|zlogout|bash_profile|bash_login|bashrc|profile)$")
def is_etc_persistence(path):
    p = _canon(path)
    if not p.startswith("/etc/"): return False
    if p in _PERSIST_ETC_FILES or p.startswith("/etc/rc."): return True
    return p.startswith(_PERSIST_ETC_DIRS)
def is_persistence(path):
    if not path: return False
    return (path.startswith(_PERSIST_ROOTS) or _PERSIST_ANY_RE.match(_canon(path)) is not None
            or _PERSIST_RC_RE.match(path) is not None or is_etc_persistence(path))

def rename_dest(body):
    # An existing file, or a directory plus the new name: stopping at the directory defeats the atomic-write check.
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

# `_COPY_KINDS` carry a source and a destination (cp/ln); `_WRITE_KINDS` is what --no-files drops and --destructive-only keeps.
_COPY_KINDS = ("clone", "link")
# Permission and ownership changes through the API: a direct chmod(2) fires no exec.
_PERM_KINDS = ("setmode", "setowner", "setflags", "setacl")
# deleteextattr stays OUT of _PERM_KINDS: covered_by_perm() would absorb it after a recent chmod and swallow
# a real xattr removal.
_WRITE_KINDS = ("unlink", "rename") + _COPY_KINDS + _PERM_KINDS + ("deleteextattr",)

_S_PERM = 0o7777

# Names `chflags` accepts (sys/stat.h); decimal for an unnamed bit; never hex (`chflags` rejects it).
_FLAG_NAMES = ((0x00000001, "nodump"), (0x00000002, "uchg"), (0x00000004, "uappnd"),
               (0x00000008, "opaque"), (0x00008000, "hidden"),
               (0x00010000, "arch"), (0x00020000, "schg"), (0x00040000, "sappnd"),
               (0x00080000, "restricted"), (0x00100000, "sunlnk"))
def flags_arg(f):
    # None when the value cannot be written: `chflags` rejects an unknown bit, and a partial list would set something else.
    if f == 0: return "0"
    names, rest = [], f
    for bit, nm in _FLAG_NAMES:
        if f & bit: names.append(nm); rest &= ~bit
    return ",".join(names) if names and not rest else None
def perm_change(kind, body):
    # (command, destructive, path) reproducing the change, or None when the event carries nothing usable.
    if not isinstance(body, dict): return None
    path = any_path(body.get("target")) or any_path(body)
    if not path: return None
    q = shq(path)
    if kind == "setmode":
        m = body.get("mode")
        # A str is REFUSED: int("4755") is decimal and would give a wrong chmod. Counted via degrade() so the gap shows.
        if isinstance(m, bool) or not isinstance(m, int):
            degrade("setmode: the mode was not a number")
            return None
        m = int(m)
        m &= _S_PERM
        return ("chmod %04o %s" % (m, q), bool(m & 0o7000) or bool(m & 0o002), path)
    if kind == "setowner":
        u, g = body.get("uid"), body.get("gid")
        if isinstance(u, bool) or not isinstance(u, int):
            degrade("setowner: the uid was not a number")
            return None
        u = int(u)
        try: g = int(g)
        except Exception: g = None
        # (uid_t)-1 / (gid_t)-1, unsigned or signed, means "leave unchanged": chown(1) would take it literally.
        _unset = (-1, 0xFFFFFFFF)
        if g in _unset: g = None
        if u in _unset:
            if g is None:
                debug_filtered("chown -1:-1 %s (nothing changed)" % q)
                return None
            return ("chgrp %d %s" % (g, q), False, path)
        who = "%d:%d" % (u, g) if g is not None else "%d" % u
        # Ownership moving to root is how a file stops being the user's.
        return ("chown %s %s" % (who, q), u == 0, path)
    if kind == "setflags":
        f = body.get("flags")
        try: f = int(f)
        except Exception: return None
        # 0 clears the flags, unlocking a file so it CAN be deleted. Symbolic, never hex.
        fa = flags_arg(f)
        if fa is None:
            # No spelling exists for these bits: recorded, not reproduced.
            return ("# file flags set to %#x on %s" % (f, q), False, path)
        return ("chflags %s %s" % (fa, q), f == 0, path)
    # setacl: no short command reproduces it; recorded, not reproduced.
    return ("# ACL changed on %s" % q, False, path)

# setextattr is deliberately not subscribed: the value is never in the event so nothing could replay it, and it
# fires constantly system-wide.
def xattr_change(body):
    if not isinstance(body, dict): return None
    name = body.get("extattr")
    if not isinstance(name, str) or not name:
        degrade("deleteextattr: the attribute name was not a string")
        return None
    path = any_path(body.get("target")) or any_path(body)
    if not path: return None
    return ("xattr -d %s %s" % (shq(name), shq(path)), path, name)

# Attributes the OS rewrites as bookkeeping (`com.apple.lastuseddate#PS`). quarantine and provenance stay OUT on
# purpose: removing them changes what Gatekeeper/AMFI do with the file.
_XATTR_NOISE = ("com.apple.lastuseddate#PS",)

def copy_dest(body):
    # Finder's copy engine emits `clone` with source, `target_dir` and `target_name`; es_event_link_t spells the name
    # `target_filename`, and an overwrite may name `target_file`. Every spelling is tried.
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
        # A directory with no name is not a destination (`ln src /usr/local/bin`), and persistence roots end in a slash.
        return ""
    return ""

def persistence_actor(ev, kind, proc):
    # Credit for a file landing where software installs itself when normal attribution found nobody: a launch agent
    # that appears is a fact whatever placed it (a Finder drag emits `clone` from DesktopServicesHelper, an Apple
    # binary outside any bundle). Persistence locations only; the actor is NAMED from its executable.
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
    # todelete_<hex>_n: Chromium doomed-cache files. NSFX.<rand>: NSFileManager scratch. `.odl`: OneDrive log.
    if b.startswith(("todelete_", "NSFX.")): return True
    if b in (".DS_Store", ".localized"): return True
    # LevelDB compaction (Electron IndexedDB/Local Storage) retires numbered segments constantly. Only numbered
    # segments and bookkeeping files inside a leveldb directory; deleting the directory still shows.
    if _LEVELDB_DIR_RE.search(path) and _LEVELDB_FILE_RE.match(b): return True
    # One agent's own state database (SentinelOne, /Library/Sentinel/_sentinel/db/), whose directory is not named for
    # the engine. Named, not a relaxed rule, so no other app's numbered files are hidden.
    if any(d in path for d in _SELF_DB_DIRS) and _LEVELDB_FILE_RE.match(b): return True
    # An AV engine retiring entries from its own scanner cache (ESET charon): one `rm` per file for one logical act.
    # Directory AND file shape are named; deleting the cache DIRECTORY still shows.
    if any(d in path for d in _SCAN_CACHE_DIRS) and _SCAN_CACHE_FILE_RE.match(b): return True
    return "/private/var/folders/" in path and "/T/" in path

# Startup reads every process makes (C runtime, ICU, timezone, GPU shader cache, user database, crash reports):
# launch plumbing, dropped by --opens like loaded .dylibs. Substrings (/var/db/timezone matches under /private too).
_OPEN_NOISE = ("/usr/share/icu/", "/var/db/timezone/", "/var/db/eligibilityd/",
               "/System/Library/OpenDirectory/", "SystemVersion.plist",
               "/com.apple.metal/", "com.apple.IntlDataCache", "/CrashReporter/",
               "/etc/passwd", "/etc/group")

_S_IFMT = 0o170000
_S_IFDIR = 0o040000
_S_IFREG = 0o100000
_S_IFLNK = 0o120000
def open_mode(body):
    # st_mode from event.open.file.stat.st_mode, or None; defensive so a missing field never hides a real read.
    f = body.get("file") if isinstance(body, dict) else None
    st = f.get("stat") if isinstance(f, dict) else None
    if isinstance(st, dict):
        for k in ("st_mode", "mode"):
            v = st.get(k)
            try:
                if v is not None: return int(v)
            except Exception: pass
    return None

def unlink_is_leaf(body):
    # True only for a regular file or symlink target (event.unlink.target.stat.st_mode): `rm -f` then replays no more
    # than happened. Directory, other type or missing stat stays False, so `rm -rf` is kept.
    t = body.get("target") if isinstance(body, dict) else None
    st = t.get("stat") if isinstance(t, dict) else None
    m = None
    if isinstance(st, dict):
        for k in ("st_mode", "mode"):
            try:
                if st.get(k) is not None: m = int(st[k]); break
            except Exception: pass
    return m is not None and (m & _S_IFMT) in (_S_IFREG, _S_IFLNK)

def open_is_dir(body):
    # open() on a directory is not a file read: it duplicates the readdir already reported.
    m = open_mode(body)
    return m is not None and (m & _S_IFMT) == _S_IFDIR

def open_is_exec(body):
    # A regular file with an execute bit is a binary (`cat` dumps garbage); data files are mode 644 and stay.
    m = open_mode(body)
    return m is not None and (m & _S_IFMT) == _S_IFREG and (m & 0o111) != 0

# ============================================================================
# ABSORPTION
# ============================================================================
# A shown command records what it is about to do and the events it produces fold into it. An event no command
# covers always survives. Keyed by ACTOR: absorbing across actors would be a false negative.

# A shown removal (`rm -rf ~/Library/Biome/*`) is followed by hundreds of unlinks that are its own expansion:
# suppressed. A deletion no command covers still shows.
_REMOVERS = {"rm", "rmdir", "srm", "unlink", "shred"}
# [label, path-prefix, globbed, time, pid, pidversion, exit time, exit pidversion] of removals already shown
wipe_prefixes = []
wipe_pids = set()

def _canon(p):
    # /var, /tmp, /etc are symlinks to /private/*; unlink reports the real path.
    if p.startswith(("/private/var", "/private/tmp", "/private/etc")):
        return p[len("/private"):]
    return p

def wipe_prefix_of(arg):
    # The prefix a removal argument covers: `~/Library/Biome/*` -> /Users/<me>/Library/Biome/; a plain path gets a
    # trailing / so /a/dir does not swallow /a/dir2. "" for a relative or ~-without-home arg.
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
    return a, globbed

def wipe_exit(pid, ver, now):
    if pid not in wipe_pids: return
    for w in wipe_prefixes:
        if w[4] == pid and w[6] is None and (ver is None or w[5] is None or w[5] <= ver):
            w[6], w[7] = now, ver

def _by_wiper(w, actor, ppid, now):
    # Only the removal's own process (an in-place exec raises its pidversion) or a child of it deletes as its expansion,
    # and only until shortly after it exits: another process of the same app deleting there is a separate act.
    wpid, wver, xt, xver = w[4], w[5], w[6], w[7]
    if wpid is None: return False
    if xt is not None and now - xt >= 1.0: return False
    apid, aver = actor if actor else (None, None)
    if ppid is not None and ppid == wpid: return True
    if apid != wpid: return False
    if aver is None or wver is None: return True
    return aver >= wver and (xver is None or aver <= xver)

def covered_by_wipe(label, path, now, actor=None, ppid=None):
    cp = _canon(path)
    for w in wipe_prefixes:
        wl, wp, wg, wt = w[0], w[1], w[2], w[3]
        if wl != label: continue
        if now - wt >= 120.0 or not wp: continue
        if not _by_wiper(w, actor, ppid, now): continue
        if wp == cp + "/":
            # The directory the command NAMED: its own unlink is printed once. A GLOBBED argument leaves the
            # container standing, so its unlink is not absorbed.
            if not wg: return True
            continue
        if not cp.startswith(wp): continue
        # A glob does not cover a DIRECT child starting with a dot (no shell expands `*` onto a leading dot), but
        # only at a COMPONENT boundary: cut mid-component (`com.apple.wallpaper*`) the remainder may start with a dot.
        if wg and wp.endswith("/") and cp[len(wp):].split("/")[0].startswith("."):
            continue
        return True
    return False

# Same for placements: a file-placing command an app shells out prints, then its clone/link/rename arrives as a
# near-identical second line (`cp -c src dst` then `cp -R src dst`; `ditto` then the `mv`). `mv` belongs here too.
_COPIERS = {"cp", "ln", "mv", "ditto", "install", "rsync"}
copy_dests = []       # (label, destination, time) of placements already shown

def placed_dest(args):
    # The last non-flag argument; two operands required, so `rm -rf x` or a lone `ls` is not one.
    rest = [a for a in args[1:] if not a.startswith("-")]
    return rest[-1] if len(rest) >= 2 else ""

def places_persistence(args):
    # The mark belongs on the COMMAND, not only its syscall: suppressing the duplicate rename (which carried
    # `⚠ persistence`) would lose the signal. The destination may be the file or its directory.
    d = placed_dest(args)
    return bool(d) and (is_persistence(d) or is_persistence(d.rstrip("/") + "/"))

# The other half of an install: `launchctl load`/`bootstrap` makes a placed job RUN. Marked `⚠ persistence`
# (launchctl(1): `enable` "persists across boots"). Narrow:
#   load/bootstrap: only with an operand in a persistence location (a job loaded from /tmp stays unmarked);
#   enable: always (its target is a service, not a path);
#   kickstart/start/submit run a job now, not persistence; unload/bootout/disable/remove are in DESTRUCTIVE.
# `asuser <uid> launchctl ...` is how a root script reaches a user's GUI domain.
def activates_launchd(args):
    ops = [a for a in args[1:] if not a.startswith("-")]
    if not ops: return False
    verb = ops[0]
    if verb == "asuser":
        # `asuser UID command...` takes no flag of its own: the inner argv starts two tokens after the verb.
        _i = args.index("asuser", 1) + 2
        inner = args[_i:]
        return (bool(inner) and inner[0].rsplit("/", 1)[-1] == "launchctl"
                and activates_launchd(inner))
    if verb == "enable": return len(ops) > 1
    if verb in ("load", "bootstrap"):
        return any(is_persistence(a) or is_persistence(a.rstrip("/") + "/") for a in ops[1:])
    return False

def activation_stage(argv, path0=None):
    # Stage by stage: `launchctl bootout ...; launchctl bootstrap ...` is a reload. A copier placing a file in a
    # persistence location counts in any stage, and so does a redirection (`cat > ~/Library/LaunchAgents/x.plist`).
    for jp, ja, _r in _stages(argv, path0):
        if any(">" in op and tgt and is_persistence(tgt) for op, tgt in _r): return True
        b = jp.rsplit("/", 1)[-1]
        if b == "launchctl" and activates_launchd(ja): return True
        if b in _COPIERS and places_persistence(ja): return True
        if b == "tee" and any(not a.startswith("-") and is_persistence(a) for a in ja[1:]): return True
        # A login/logout hook runs a script as root at every login; a crontab install or edit schedules one.
        if b == "defaults" and "write" in ja and ("LoginHook" in ja or "LogoutHook" in ja): return True
        if b == "crontab" and "-l" not in ja and "-r" not in ja: return True
    return False

# Same for permission changes: `chmod 4755 x` shelled out prints as the command, then its setmode would print
# again. The exec rules already mark a setuid `chmod` and `chflags nouchg`.
_PERM_CMDS = {"chmod", "chown", "chgrp", "chflags"}
perm_targets = []     # (label, path, time) of permission changes already shown

def covered_by_perm(label, path, now):
    if not path: return False
    cp = _canon(path)
    for pl, pp, pt in perm_targets:
        if pl != label: continue
        if now - pt >= 120.0 or not pp: continue
        # By PREFIX: `chmod -R 777 <tree>` names the tree while setmode events name each file inside.
        if cp == pp or cp.startswith(pp.rstrip("/") + "/"): return True
    return False

def covered_by_copy(label, dst, now):
    if not dst: return False
    cd = _canon(dst)
    for cl, cp_, ct in copy_dests:
        if cl != label: continue
        if now - ct >= 120.0 or not cp_: continue
        # The command may name the destination FILE or its directory (`cp x /dest/` and `cp x /dest/x` are one act).
        if cd == cp_ or cd.startswith(cp_.rstrip("/") + "/"): return True
    return False

# ============================================================================
# NOISE
# ============================================================================
# `NOISE` global; `APP_NOISE` and `APP_SCAN_NOISE` for one app's own polling; `_TOOL_SCAN_NOISE` for the walk a tool
# does for a command already announced. Every suppression is explainable (`noise_reason()`, printed by `--debug`). `-v` lifts all.

# Filtered: not read-vs-write (`ls` is how a cleaner finds what it deletes) but whether a command is scriptable by
# itself. Same shape as DESTRUCTIVE: None = always, a set = only with one of those arguments.
#   (a) FRAGMENT no single exec captures whole (pipeline stage, man-rendering cog); (b) SCAFFOLDING the app did not
#   choose (login shell, .xpc launch, shell-init probe); (c) shell GLUE with no effect; (d) compinit CHURN;
#   (e) documentation display. Everything else shows; editor polling is handled by TARGETing the app.
NOISE = {
    # (a) Pipeline stages: an isolated `awk '{print $2}'` cannot be replayed alone.
    "awk": None, "sed": None, "grep": None, "egrep": None, "fgrep": None,
    "cut": None, "head": None, "tail": None, "sort": None, "uniq": None,
    "tr": None, "wc": None, "cat": None, "rev": None, "expr": None,
    "printf": None, "seq": None, "column": None, "paste": None, "fold": None,
    "nl": None, "comm": None, "diff": None, "cmp": None, "base64": None,
    "xxd": None, "od": None, "strings": None, "md5": None, "shasum": None,
    # (a) Man-page rendering cogs (`man` fans out into these).
    "mandoc": None, "col": None, "zcat": None, "groff": None, "nroff": None,
    "less": None, "more": None,
    # (e) Documentation display
    "man": None, "apropos": None, "whatis": None,
    # (b) Shell startup: every new terminal tab replays this (pty helper, PATH assembly).
    "path_helper": None, "spawn-helper": None,
    # (b) Wrapper shell-init: how a wrapper finds the shell, Homebrew's prefix or Xcode's path.
    "brew":           {"shellenv", "--prefix", "--cellar", "--repository",
                       "config", "--version"},
    "brew.sh":        {"shellenv"},
    "xcode-select":   {"-p", "--print-path", "--show-manpaths", "--version"},
    "sqlite3":        {"-version"},   # capability probe, not a query
    # system_profiler re-execs itself as `-nospawn -xml ...`; the command above it is already shown.
    "system_profiler": {"-nospawn"},
    # (c) Shell glue: no effect, no inspection.
    "echo": None, "true": None, "false": None, "test": None, "sleep": None,
    "basename": None, "dirname": None,
    # (d) compinit: zsh writes .zcompdump.<host>.<pid> then renames it into place. Only that target is silenced.
    "mv": {"*/.zcompdump"},
}
# Reason per NOISE binary, reported by --debug as `# FILTERED: <cmd> (<reason>)`; absent means "noise".
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

# Per-app poll noise: real commands one app runs on a timer (an editor's `ps`/`git status`, a widget's
# `system_profiler`). Keyed by the label Culprit shows; the same command from another app still shows. Hides a
# command, not the actor (unlike DEFAULT_EXCLUDES). -v lifts it, --debug says `app-poll`. Same shape as NOISE.
_GIT_READS = {"status", "config", "for-each-ref", "check-ignore", "rev-parse",
              "log", "diff", "show", "ls-files", "symbolic-ref", "branch",
              "remote", "describe", "blame", "cat-file", "ls-remote", "shortlog",
              "name-rev", "merge-base", "var", "version", "--version"}
APP_NOISE = {
    "Visual Studio Code":   {"ps": None, "which": None, "git": _GIT_READS},
    "iStat Menus Menubar":  {"system_profiler": None},
    "ESET Management Agent": {"sw_vers": None, "fdesetup": {"status"}},
}
# Directory trees an app scans to inventory its own data, matched as a SUBSTRING of the scanned path, per app. -v lifts it.
APP_SCAN_NOISE = {
    "ESET Endpoint Security": ("/Application Support/ESET/",),
    "Qobuz":                  ("/Application Support/Qobuz/",),
    "Brave Browser":          ("/BraveSoftware/Brave-Browser/",),
}
# Tools whose directory WALK is their own implementation, already announced by the command that started them
# (`lsregister -delete -seed -r ...` is followed by dozens of `ls -la`; same for the Finder restart an `osascript`
# triggers). Reads only: `lsregister` deleting the store is still the act it is. `-v` lifts it.
_TOOL_SCAN_NOISE = ("lsregister", "osascript")
# Standard tool/PATH directories any app pokes to locate a binary: never a reproducible step. Not /System/Library at
# large: a cache dir there is the pre-delete scan we keep.
_SCAN_NOISE_DIRS = ("/usr/bin", "/bin", "/sbin", "/usr/sbin", "/usr/libexec",
                    "/System/Library/SystemProfiler")
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}
# Commands whose only job is to prefix another: `xargs kill -9` IS a kill.
_ARG_WRAPPERS = {"xargs", "env", "nice", "nohup", "time", "sudo", "doas",
                 "caffeinate", "stdbuf", "script"}
# Which of each wrapper's flags take a VALUE (skipped with the flag): `sudo -i` takes none, `sudo -u` one.
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

# A shell's `-c` may sit in a cluster (`bash -lc '...'`). Only a cluster of single-letter options, and only BEFORE the
# first operand (`sh script.sh -clean` carries the SCRIPT's flag): position does that work alone.
_SHELL_LONG_RE = re.compile(r'^--[A-Za-z][A-Za-z-]*$')
# No length cap: `-clean` and `-vxeuc` are both five letters; POSITION separates them.
_SHELL_OPT_RE = re.compile(r'^[-+][A-Za-z]+$')
# Long options that take a VALUE (`bash --rcfile X -c '…'`); other long options are plain switches.
_SHELL_LONG_VALUE = ("--rcfile", "--init-file", "--wordexp")
def shell_c_index(args):
    i, n = 1, len(args or ())
    while i < n:
        a = args[i]
        # Stop where a shell stops reading options: `--`, or the first non-option word.
        if a == "--" or a in ("-", "+") or not a.startswith(("-", "+")): break
        if _SHELL_LONG_RE.match(a):
            i += 2 if a in _SHELL_LONG_VALUE else 1
            continue
        if not _SHELL_OPT_RE.match(a): break
        # `c` first: in a cluster the LAST flag consumes the operand, so `-eo pipefail` skips a value while
        # `-c` claims the payload.
        if "c" in a[1:]: return i
        if "o" in a[1:]: i += 2; continue
        i += 1
    return -1

def noise_rule(binary, args):
    if binary not in NOISE: return False
    return triggered(NOISE[binary], args)

def payload_argv(path, args):
    # Commands that only wrap another (`sh -c 'which ps'`, a trampoline such as `disclaimer /bin/ps`): reading the inner
    # argv silences the pair with one rule. Returns the wrapped argv, or [].
    if path.rsplit("/", 1)[-1] in _SHELLS:
        i = shell_c_index(args)
        if i < 0:
            # A shell invoked on a script FILE (`sh /usr/bin/man man`), possibly behind its own flags.
            rest = args[1:] if args else []
            while rest and rest[0].startswith("-"): rest.pop(0)
            if rest and rest[0].startswith("/"): return rest
            return []
        if i + 1 >= len(args): return []
        # Operators marked (shell_tokens) so _stages can walk a nested `sudo sh -c 'a;b'`.
        try: toks = shell_tokens(args[i + 1])
        except ValueError: return []
        # Drop leading VAR=value assignments, but not one that runs a command: `PW=$(security ... -w)` IS the act.
        while (toks and not toks[0].startswith("/") and "=" in toks[0].split("/")[0]
               and not getattr(toks[0], "subs", None)):
            toks.pop(0)
        return toks
    # `env -i HOME=... /bin/bash` and `xargs kill -9` bury the real command: unwrap.
    _wb = path.rsplit("/", 1)[-1]
    if _wb in _ARG_WRAPPERS:
        rest = args[1:]
        _vals = _WRAPPER_VALUE_FLAGS.get(_wb, ())
        # Skip flags, their values and VAR=value until the wrapped command appears. Values are per-wrapper:
        # `sudo -u root /bin/rm -rf ...` must not halt the peel on `root`.
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
    # `/bin/zsh -il` is a terminal opening, not a command the app chose; a shell with a script or -c is handled elsewhere.
    if path.rsplit("/", 1)[-1] not in _SHELLS: return False
    return all(a in _SHELL_STARTUP_FLAGS for a in args[1:]) if args else True

def noise_reason(path, args, label=""):
    # Why filtered, or "" if not noise. A destructive command is never noise, in ANY stage (`echo hi;rm -rf /Library/Foo`).
    if is_destructive(path, args) or destructive_stage(args): return ""
    # Per-app poll noise, arg-triggered: `git status` goes, `git commit` stays.
    _an = APP_NOISE.get(label) if label else None
    if _an:
        _jp, _ja = judged(path, args)
        _jb = _jp.rsplit("/", 1)[-1]
        if _jb in _an and triggered(_an[_jb], _ja): return "app-poll"
    if is_shell_startup(path, args): return "shell-startup"
    # An .xpc/.appex is a bundle component the system launches for the app, not a command it chose.
    if ".xpc/Contents/MacOS/" in path: return "xpc"
    if ".appex/Contents/MacOS/" in path: return "app-extension"
    # Glue judges a line by its FIRST command, so a marked later stage keeps the line (`true&&curl ...`), as does a
    # write outside the user's scope: `echo '<plist/>' > /Library/LaunchDaemons/x.plist` installs a daemon.
    if (network_stage(args) or secret_stage(args) or activation_stage(args)
            or writes_system_scope(path, args)): return ""
    b = path.rsplit("/", 1)[-1]
    if noise_rule(b, args): return _NOISE_REASON.get(b, "noise")
    # Wrappers nest (`env -i VAR=... /bin/bash -p .../brew.sh shellenv`): peel until the real command, bounded.
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
# Every dict is capped (TRACK_CAP): an ALL-mode capture runs for hours.

tracked = {}          # pid -> label
tracked_ver = {}      # pid -> pidversion of the image that last named it
TRACK_CAP = 20000

def track(pid, label, ver=None):
    # Insertion order is age: pop first so a refreshed pid moves to the end. A full table drops the OLDEST tenth,
    # never everything (a flood of unrelated execs must not blind the app being watched).
    tracked.pop(pid, None)
    tracked[pid] = label
    if ver is None: tracked_ver.pop(pid, None)
    else: tracked_ver[pid] = ver
    if len(tracked) > TRACK_CAP:
        for _k in list(tracked)[:max(1, TRACK_CAP // 10)]:
            del tracked[_k]
            tracked_ver.pop(_k, None)

def untrack(pid, ver=None):
    # pid reuse: a LOWER pidversion than recorded is a stale exit of an earlier generation, leave the entry.
    # No version on either side: by pid.
    if pid not in tracked: return
    rv = tracked_ver.get(pid)
    if ver is not None and rv is not None and ver < rv: return
    del tracked[pid]
    tracked_ver.pop(pid, None)
last_seen = {}
DEDUP_S = 1.0

# The count caps do not bound BYTES: an argv can reach 1 MiB. A long dedup key is kept as its digest ("\0" cannot occur
# in an argv, so a digest never equals a real key).
def _dk(s):
    if len(s) <= 256: return s
    return "\0" + hashlib.sha256(s.encode("utf-8", "surrogateescape")).hexdigest()

# A repeat is printed again only when a DIFFERENT writing line touched one of its paths in between, so `rm x; touch x;
# rm x` replays with x gone. A read is never re-printed nor reorders anything: app polling stays folded.
_wpaths = {}
_wpaths_bytes = 0
_WPATHS_BYTES = 32 << 20
def _write_paths(cmd):
    global _wpaths_bytes
    k = _dk(cmd)
    r = _wpaths.get(k)
    if r is not None: return r
    r = ()
    if not cmd.startswith("#") and not is_query(cmd, None, True):
        try: toks = shlex.split(cmd)
        except ValueError: toks = []
        ps = []
        for t in toks[1:]:
            if t.startswith("-") or "/" not in t: continue
            if t.startswith("~/") and HOME: t = HOME + t[1:]
            g = next((i for i, ch in enumerate(t) if ch in "*?["), -1)
            if g >= 0: t = t[:t.rfind("/", 0, g) + 1]
            t = _canon(t).rstrip("/")
            if t: ps.append(t)
        r = tuple(ps)
    # A cached tuple is at most about the size of its line.
    _wpaths_bytes += len(cmd)
    if len(_wpaths) > TRACK_CAP or _wpaths_bytes > _WPATHS_BYTES: _wpaths.clear(); _wpaths_bytes = len(cmd)
    _wpaths[k] = r
    return r

def reordered(cmd, since):
    mine = _write_paths(cmd)
    if not mine: return False
    for c in since:
        if c == cmd: continue
        for p in _write_paths(c):
            for m in mine:
                if p == m or p.startswith(m + "/") or m.startswith(p + "/"): return True
    return False

_line_seq = 0
last_seq = {}         # dedup key -> sequence number of its last printing
recent_lines = collections.deque()   # (seq, time, cmd) printed within DEDUP_S

def repeated(key, cmd, now):
    # True: drop this line as a repeat. Otherwise it counts as printed.
    global _line_seq
    while recent_lines and now - recent_lines[0][1] >= DEDUP_S: recent_lines.popleft()
    key = _dk(key)
    if key in last_seen and now - last_seen[key] < DEDUP_S:
        s = last_seq.get(key, 0)
        if not reordered(cmd, (c for q, _t, c in recent_lines if q > s)): return True
    if len(last_seen) > TRACK_CAP:
        last_seen.clear(); last_seq.clear()
    _line_seq += 1
    last_seen[key] = now
    last_seq[key] = _line_seq
    recent_lines.append((_line_seq, now, cmd if len(cmd) <= REP_LINE_MAX else "#"))   # a giant line is not held for a second
    return False

# --report: silent run; distinct commands are collected and one report plus a paste-ready script is printed
# at stop. With --ndjson the stream stays live and the report goes to a file (see QUIET). Each command is also
# fsync'd to an accumulator (CULPRIT_REPORT_FILE): the next --report launch prints the recovered report first.
REPORT = os.environ.get("CULPRIT_REPORT") == "1"
REPORT_FILE = os.environ.get("CULPRIT_REPORT_FILE", "")
# --no-fold: every unlink as its own `rm` line, not the `rm -rf <dir>/*` summary.
NOFOLD = os.environ.get("CULPRIT_NOFOLD") == "1"
# --stable: one normalised, de-duplicated, sorted command per line, no caveats, so two captures of identical
# behaviour are byte-identical (for COMPARING runs).
STABLE = os.environ.get("CULPRIT_STABLE") == "1"
_stable_emitted = set()   # commands already printed in stable mode, across calls
_stable_hdr = False       # the --mdm header, emitted once
# --marks-only: decided at render time (a dropped line is missing from the report, never from the capture).
MARKS_ONLY = os.environ.get("CULPRIT_MARKS") == "1"
# --no-queries: decided at emission, so live output and report agree.
NO_QUERIES = os.environ.get("CULPRIT_NOQUERIES") == "1"
# --ndjson: decided at emission, a command line becomes a JSON object or prose, never both.
NDJSON = os.environ.get("CULPRIT_NDJSON") == "1"
QUIET = REPORT and not NDJSON
# --report-file (or --ndjson's default <log>.report.txt): where the report goes instead of stdout.
REPORT_OUT = os.environ.get("CULPRIT_REPORT_OUT", "") if REPORT else ""
rep = []              # ordered [(cmd, destr, net, via, note, start, pid, synth, persist, secret)]
rep_seen = {}         # cmd -> index of its last entry in rep
REP_LINE_MAX = 32768  # far above any real command; ARG_MAX is 1 MiB
REP_BYTES = 128 << 20 # the report's total, so thousands of huge argvs cannot take the machine's memory
_rep_bytes = 0
rep_pids = set()      # pids a command was recorded under — see note_exit()
ended = {}            # pid -> when it exited
# TCC changes keyed by (service, identity): last event wins, so grant then revoke reports "denied".
rep_tcc = {}
# Login items keyed by path: FINAL state only; set on "add", deleted on "remove".
rep_btm = {}
_rep_fh = None
# Events not fully readable, counted by reason so nothing observed goes missing silently. eslogger is not an
# API (its man page: the structure "may change from release to release without warning").
_degraded = {}
# schema_version is recorded from the first event and stated under the report (no stability promised).
_schema = None
def degrade(reason):
    _degraded[reason] = _degraded.get(reason, 0) + 1
    # Said once per reason (a live capture has no footer); `out` is a no-op under --report, where the footer runs.
    if _degraded[reason] == 1:
        # "C\t": the watcher keeps only C/D/R lines.
        out("C\t# NOTE: an event was observed but could not be fully read (%s). "
            "The capture is incomplete — run with --debug to see the shape." % inert_word(reason))

# Set when an accumulator exists but is not trusted, so the refusal is reported.
_rep_refused = False

def _safe_dir_fd(d):
    """fd of directory d, walked from / one component at a time without following a link; each must belong to
    root, this run or the sudo user and be writable by others only if sticky (the shell's _log_path_safe rule).
    The caller works through the fd, so a component swapped later changes nothing. None when refused."""
    ok = {0, os.geteuid()}
    _su = os.environ.get("SUDO_UID", "")
    if _su.isdigit(): ok.add(int(_su))
    fd = None
    try:
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        for part in [""] + [x for x in os.path.realpath(d).split("/") if x]:
            if part:
                nfd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd); fd = nfd
            st = os.fstat(fd)
            if st.st_uid not in ok or ((st.st_mode & 0o022) and not (st.st_mode & 0o1000)):
                raise OSError("untrusted directory")
        return fd
    except Exception:
        if fd is not None:
            try: os.close(fd)
            except Exception: pass
        return None

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
    dfd = _safe_dir_fd(os.path.dirname(path) or ".")
    if dfd is None:
        if os.path.lexists(path): _rep_refused = True
        return None
    try:
        fd = os.open(os.path.basename(path), flags | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
    except Exception:
        if os.path.lexists(path): _rep_refused = True
        return None
    finally:
        os.close(dfd)
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
# Every other C0/C1 control byte as \xNN: shlex.quote strips none, and a terminal obeys ESC and BS (a file
# name could repaint lines and hide a `⚠ destructive`).
_CTL_RE = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]')
# Bidi controls and zero-width characters too: U+202E makes `a<RLO>txt.sh` display as another name.
_INVIS = r'\u00ad\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff'
_INVIS_RE = re.compile('[' + _INVIS + r'\u2028\u2029]')
def raw_out(s):
    # The transport is line-based (`read -r` in the watcher, log_line, syslog): an embedded newline would drop the
    # rest, so it is escaped, not truncated (the `.report` accumulator keeps the real text). A COMMAND never carries
    # a control byte (shq writes `$'…'`); prose such as a path or an app name is guarded here.
    sys.stdout.write(_inert(s) + "\n")
    sys.stdout.flush()

def _inert(s):
    s = _NL_RE.sub(lambda m: "\\n" if m.group(0) == "\n" else "\\r", s)
    s = _CTL_RE.sub(lambda m: "\\x%02x" % ord(m.group(0)), s)
    s = _INVIS_RE.sub(lambda m: "".join("\\x%02x" % b for b in m.group(0).encode("utf-8")), s)
    # A lone surrogate would be written by surrogateescape as the raw C1 byte 0x9b (CSI): \xNN instead, or U+FFFD.
    return _SURR_RE.sub(_surr_esc, s) if _SURR_RE.search(s) else s

_SURR_RE = re.compile(r'[\ud800-\udfff]')
def _surr_esc(m):
    o = ord(m.group(0))
    return "\\x%02x" % (o - 0xdc00) if 0xdc80 <= o <= 0xdcff else "\ufffd"

# Text an observed process chose, shown in a `#` line. Pasted into zsh with INTERACTIVE_COMMENTS off (the macOS
# default), `#` is a command and the rest is parsed: so no shell syntax survives. Kept: letters, digits and marks
# of any script, ` ._-/+:,@%=~`, plus --mdm's own variables; control and non-UTF-8 bytes become \xNN; anything
# else (`;&|$`()<>'"\*?[]{}!#`, tab, bidi, zero-width) becomes `_`.
_WORD_OK = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ._-/+:,@%=~")
def _word_piece(s):
    if all(c in _WORD_OK for c in s): return s
    out = []
    for c in s:
        o = ord(c)
        if c in _WORD_OK: out.append(c)
        elif c == "\n": out.append("\\n")
        elif c == "\r": out.append("\\r")
        elif o < 0x20 or 0x7f <= o <= 0x9f: out.append("\\x%02x" % o)
        elif 0xdc80 <= o <= 0xdcff: out.append("\\x%02x" % (o - 0xdc00))
        elif o > 0x9f and not 0xd800 <= o <= 0xdfff and unicodedata.category(c)[0] in "LNM": out.append(c)
        else: out.append("_")
    return "".join(out)
def inert_word(s):
    if not s: return ""
    if not isinstance(s, str): s = str(s)
    if s == "?": return s                      # the parser's own "unknown"
    if "$" not in s: return _word_piece(s)
    _parts, _at = [], 0
    for m in _MDM_VAR_RE.finditer(s):
        _parts.append(_word_piece(s[_at:m.start()])); _parts.append(m.group(0)); _at = m.end()
    _parts.append(_word_piece(s[_at:]))
    return "".join(_parts)

# A command quoted inside a `#` line: kept as is when nothing in it can act once pasted (outside single quotes
# and `$'…'`, and inside double quotes where --mdm's variables alone may expand: no `;&|$`()<>!\` and no
# unbalanced quote). Otherwise (an unwrapped payload) inert_word renders it all. Globs and braces only expand.
_CMD_ACTS_RE = re.compile(r"[;&|$`()<>!\"'\\\x00-\x1f\x7f-\x9f\u2028\u2029\ud800-\udfff]")
_DQ_ACTS_RE = re.compile(r"[$`!\\\x00-\x1f\x7f-\x9f\u2028\u2029\ud800-\udfff]")
# One shell word-piece per match, in the shell's order; a bare run is taken whole (a report holds thousands).
_CMD_WALK_RE = re.compile(r"""'[^']*'|"(?:[^"\\]|\\.)*"|\$'(?:[^'\\]|\\.)*'|\\.|[^'"\\$]+|.""", re.S)
def comment_cmd(c):
    if not c: return ""
    if c.isascii():
        if not _CMD_ACTS_RE.search(c): return c
    elif any(unicodedata.category(ch) == "Cf" for ch in c): return inert_word(c)
    _bare = []
    for m in _CMD_WALK_RE.finditer(_MDM_VAR_RE.sub("", c)):
        t = m.group(0)
        if t[:1] == "'" and len(t) > 1 or t[:2] == "$'" and len(t) > 2: continue
        if t[:1] == '"' and len(t) > 1:
            if _DQ_ACTS_RE.search(t[1:-1]): return inert_word(c)
            continue
        _bare.append(t)
    return inert_word(c) if _CMD_ACTS_RE.search("".join(_bare)) else c

def out(s):
    if QUIET: return
    raw_out(s)

# The report's sink: stdout, or with --report-file a file holding the bytes the watcher would print. Root
# writes it, often in world-writable /Users/Shared, so the open follows no symlink and refuses a file it does
# not own or with a second hard link. Written WHOLE or not at all: lines go to a temporary file renamed over
# the path at the end (_rep_out_commit); the accumulator stays for the next launch.
_rep_out_fd = None
_rep_out_tmp = None
_rep_out_dfd = None
_rep_out_bad = False
_REPORT_END = "# ===== end of Culprit report ====="

def _rep_out_target_ok(dfd):
    try:
        st = os.lstat(os.path.basename(REPORT_OUT), dir_fd=dfd)
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
    global _rep_out_fd, _rep_out_tmp, _rep_out_dfd
    if _rep_out_fd is not None or _rep_out_bad: return _rep_out_fd
    fd = tmp = dfd = None
    try:
        dfd = _safe_dir_fd(os.path.dirname(REPORT_OUT) or ".")
        if dfd is not None and _rep_out_target_ok(dfd):
            # O_EXCL|O_NOFOLLOW at 0600, inside the checked directory fd (a planted name or link is never opened,
            # a swapped parent is never followed); the rename stays in that directory.
            tmp = "." + os.path.basename(REPORT_OUT) + "." + os.urandom(6).hex() + ".part"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
            st = os.fstat(fd)
            if stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and st.st_nlink == 1:
                _rep_out_fd, _rep_out_tmp, _rep_out_dfd = fd, tmp, dfd
                return fd
    except Exception:
        pass
    if fd is not None:
        try: os.close(fd)
        except Exception: pass
        try: os.unlink(tmp, dir_fd=dfd)
        except Exception: pass
    if dfd is not None:
        try: os.close(dfd)
        except Exception: pass
    _rep_out_refused()
    return None

def _rep_out_commit():
    # The file becomes the report only now; a failed render leaves the path as it was and a `.part` beside it.
    global _rep_out_fd, _rep_out_tmp, _rep_out_dfd
    fd, tmp, dfd = _rep_out_fd, _rep_out_tmp, _rep_out_dfd
    if fd is None: return
    _rep_out_flush()
    _rep_out_fd = _rep_out_tmp = _rep_out_dfd = None
    ok = not _rep_out_bad
    try: os.fsync(fd)
    except Exception: ok = False
    try: os.close(fd)
    except Exception: pass
    if ok and _rep_out_target_ok(dfd):
        try:
            os.rename(tmp, os.path.basename(REPORT_OUT), src_dir_fd=dfd, dst_dir_fd=dfd)
        except Exception:
            ok = False
        else:
            try: os.fsync(dfd)
            except Exception: pass
            try: os.close(dfd)
            except Exception: pass
            return
    try: os.unlink(tmp, dir_fd=dfd)
    except Exception: pass
    try: os.close(dfd)
    except Exception: pass
    if not _rep_out_bad: _rep_out_refused()

def rep_out(s):
    global _rep_out_bad
    if not REPORT_OUT:
        # Never onto the JSON stream; the shell names a file under --ndjson, this guards a run without one.
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

# --ndjson: the stable field set a command line becomes, kept apart from raw_out/out (prose `# …` lines, which
# log_line wraps as {"type":"info"}). Only a reproducible command goes through json_out.
_MARK_TOKEN = {"⚠ destructive": "destructive", "⚠ network": "network",
               "⚠ persistence": "persistence", "⚠ secret": "secret",
               "⚠ system scope": "system_scope"}
# The eslogger event being handled, as ts_iso() prints it (None without a usable `time`): when the thing
# HAPPENED, not when it is printed.
_EV_T = None
def ev_time_iso(d):
    # eslogger's top-level `time`: ISO 8601 UTC with nanoseconds, cut to milliseconds. Else None (print time).
    t = d.get("time") if isinstance(d, dict) else None
    if not isinstance(t, str): return None
    m = re.match(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?Z$", t)
    if not m: return None
    try: time.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S")
    except Exception: return None
    return m.group(1) + "." + (m.group(2) or "").ljust(3, "0")[:3] + "Z"
def ts_iso():
    if _EV_T: return _EV_T
    t = time.time()
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + ".%03dZ" % int((t % 1) * 1000)
# A lone surrogate (invalid UTF-8 byte via surrogateescape, or JSON `\ud800`) dumps as valid JSON but invalid
# Unicode, which a strict decoder refuses: U+FFFD instead.
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
    # `actor` is (pid, pidversion): the pair identifies a process across pid reuse and is what a network flow
    # joins on.
    pid, pidver = actor if actor else (None, None)
    obj = {"type": "cmd", "ts": ts_iso(), "cmd": cmd, "via": via or None,
           "marks": [_MARK_TOKEN.get(m, m) for m in marks],
           "kind": kind, "app": label or None, "pid": pid, "pidver": pidver}
    if folded is not None: obj["folded"] = folded
    # Optional keys, only when the text output prints the matching note: via_helper, stdin_pipe, cwd, verified.
    if extra: obj.update(extra)
    # ensure_ascii=True: every control byte and non-ASCII codepoint is \u-escaped, so a hostile filename cannot put
    # a raw control byte on the wire.
    raw_out("C\t" + nd_dumps(obj))

# ============================================================================
# THE REPORT
# ============================================================================
# The `sleep` arithmetic is part of the delivered script, not of the observation.

_SHELL_OPS = "|&;<>`"
def _has_bare_operator(cmd):
    # Does this line carry a shell operator the shell would act on (pipe, separator, redirection, substitution)?
    # Re-quoting would be unsafe: shlex quotes `|` as a token. The scan respects quoting; unbalanced quotes bail.
    q = None
    i, n = 0, len(cmd)
    while i < n:
        c = cmd[i]
        if q == "'":
            if c == "'": q = None
        elif q == '"':
            if c == "\\": i += 1
            elif c == '"': q = None
        elif c == "$" and cmd[i + 1:i + 2] == "'":      # ANSI-C: a backslash escapes the next character
            i += 2
            while i < n and cmd[i] != "'":
                i += 2 if cmd[i] == "\\" else 1
            if i >= n: return True
        elif c in "'\"": q = c
        elif c == "\\": i += 1
        elif c in _SHELL_OPS: return True
        elif c == "$" and cmd[i + 1:i + 2] == "(": return True
        i += 1
    return q is not None

# An argument holding a control character (newline in a multi-line `sh -c`, tab, ESC) cannot go in single
# quotes without a raw byte, and raw_out would render a `\n` the shell does not read back: ANSI-C quoting
# (bash 3.2 and zsh) keeps it on one line. Others keep shlex.quote byte for byte. `'` is `\x27`, never `\'`,
# so scanners that see `$'…'` as `$` plus a single-quoted run (mdm_quotes, _has_bare_operator) still pair
# quotes. C1 and U+2028/9 go out as UTF-8 bytes (`\u` is not in bash 3.2).
_CTL_ANY_RE = re.compile(r'[\x00-\x1f\x7f-\x9f\u2028\u2029' + _INVIS + ']')
# A non-UTF-8 byte arrives as U+DC80-U+DCFF (surrogateescape): a lone surrogate on the NDJSON wire raw;
# as `$'\xff'` it is the same argument in both.
_BADBYTE_RE = re.compile(r'[\udc80-\udcff]')
_SHQ_RE = re.compile(r'[\x00-\x1f\x7f-\x9f\u2028\u2029' + _INVIS + r'\ud800-\udfff]')
_LONE_RE = re.compile(r'[\ud800-\udfff]')
_ANSI_C_ESC = {"\n": "\\n", "\t": "\\t", "\r": "\\r", "\\": "\\\\", "'": "\\x27"}
def shq(s, readable=False):
    # Readable: a script word holding `'` (no control character) is written `$'…'` with `\'`, where shlex.quote
    # would splice `'"'"'` into every quote. Only the `sh -c` payload word.
    if readable and "'" in s and not _SHQ_RE.search(s):
        return "$'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"
    if not _SHQ_RE.search(s): return shlex.quote(s)
    out = []
    for ch in s:
        if ch in _ANSI_C_ESC: out.append(_ANSI_C_ESC[ch])
        elif _BADBYTE_RE.match(ch): out.append("\\x%02x" % (ord(ch) - 0xdc00))
        elif _LONE_RE.match(ch): out.append("\\xef\\xbf\\xbd")   # any other lone surrogate: U+FFFD's bytes
        elif _CTL_ANY_RE.match(ch): out.append("".join("\\x%02x" % b for b in ch.encode("utf-8")))
        else: out.append(ch)
    return "$'" + "".join(out) + "'"

# The inverse: the body of a `$'…'` as the argument the shell hands over. ONE decoder for the report's
# re-reading (shlex.split knows no `$'…'`) and the payload lexer. bash 3.2's set: \xHH and \NNN are BYTES,
# read as UTF-8 with surrogateescape (never raises); an unknown escape keeps its backslash.
_ANSI_C_DEC = {"n": b"\n", "t": b"\t", "r": b"\r", "\\": b"\\", "'": b"'", '"': b'"',
               "?": b"?", "a": b"\a", "b": b"\b", "e": b"\x1b", "E": b"\x1b",
               "f": b"\f", "v": b"\v"}
_ANSI_C_TOK_RE = re.compile(r'\\x([0-9a-fA-F]{1,2})|\\([0-7]{1,3})|\\u([0-9a-fA-F]{1,4})'
                            r'|\\U([0-9a-fA-F]{1,8})|\\c([\x20-\x7e])|\\(.)|([^\\]+)|\\', re.S)
def _utf8b(s):
    # A str back to its bytes: surrogateescape undoes the argv read; a lone surrogate (JSON `\ud800`) is written
    # as itself rather than raising.
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
# One shell word-piece per match, in the shell's own order, so a `$'` inside a quoted run is never an opener.
_SH_WALK_RE = re.compile(r"""'[^']*'|"(?:[^"\\]|\\.)*"|\$'((?:[^'\\]|\\.)*)'|\\.|.""", re.S)
# Without a quote or backslash, shlex.split only cuts on these four characters: same result, far cheaper.
_SH_WS_RE = re.compile(r'[ \t\r\n]+')
def shsplit(cmd):
    if "'" not in cmd and '"' not in cmd and "\\" not in cmd:
        return [t for t in _SH_WS_RE.split(cmd) if t]
    if "$'" not in cmd: return shlex.split(cmd)
    return shlex.split(_SH_WALK_RE.sub(
        lambda m: m.group(0) if m.group(1) is None else shlex.quote(_ansi_c_decode(m.group(1))), cmd))

_GLOB_META = "*?["
def cmd_quote(tok):
    # shlex.quote for a COMMAND-LINE token, glob metacharacters left outside the quotes so the shell still expands
    # them (quoted whole, `~/Library/Application Support/*/Cache` matches nothing). A literal run with a `$` is
    # quoted even where it needs none, so mdm_quotes can raise it to double quotes. Only in an ABSOLUTE path:
    # `rg --files -g '**/package.json'` is ripgrep's own pattern, which unquoted makes zsh say `no matches found`.
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
    # `shlex.quote` already quotes anything holding a `$`, supplying the single quotes `mdm_quotes` raises.
    return shq(s)

def _code_operands(toks):
    # Indices of the words a shell runs as a SCRIPT: the operand of `-c` (or a cluster ending in it, shell_c_index)
    # of every shell on the line (`sh -c`, `sudo sh -c`, `env bash -lc`, `launchctl asuser 501 zsh -c`).
    out = set()
    for k, t in enumerate(toks):
        if t.rsplit("/", 1)[-1] in _SHELLS or t.rsplit("/", 1)[-1] in ("csh", "tcsh"):
            i = shell_c_index(toks[k:])
            if i > 0 and k + i + 1 < len(toks): out.add(k + i + 1)
    return out

# What re-reading must tell apart: a bare `~/` (expanded, so `~/Library` and the absolute line collapse) from
# a quoted one (a directory called `~`), and a live --mdm variable from a `$name` the app wrote. The live ones
# are parked behind private-use marks across shlex, and _rf_live raises them back.
_RF_WALK_RE = re.compile(r"""('[^']*')|("(?:[^"\\]|\\.)*")|(\$'(?:[^'\\]|\\.)*')|(\\.)"""
                         r"""|\$(loggedInUser|userDir|userCache|userTemp)|(.)""", re.S)
_RF_DQ_RE = re.compile(r'(\\\\)|\\([$`])|\$(loggedInUser|userDir|userCache|userTemp)')
_RF_MARK_RE = re.compile('\ue000(loggedInUser|userDir|userCache|userTemp)\ue001')
def _rf_prep(cmd):
    out, prev = [], " "
    for m in _RF_WALK_RE.finditer(cmd):
        t = m.group(0)
        if m.group(2) is not None and MDM:
            t = '"' + _RF_DQ_RE.sub(lambda d: d.group(1) or d.group(2) or "\ue000" + d.group(3) + "\ue001",
                                    t[1:-1]) + '"'
        elif m.group(5) is not None and MDM:
            t = "\ue000" + m.group(5) + "\ue001"
        elif m.group(6) == "~" and HOME and prev in " \t\n" and cmd[m.end():m.end() + 1] == "/":
            t = shq(HOME)
        out.append(t); prev = t[-1:]
    return "".join(out)
def _rf_live(s):
    def _seg(m):
        if m.group(1) is not None:
            if "\ue000" not in m.group(1): return m.group(0)
            return "".join("\"$%s\"" % x if i % 2 else ("$'%s'" % x if x else "")
                           for i, x in enumerate(_RF_MARK_RE.split(m.group(1))))
        if "\ue000" not in m.group(2): return m.group(0)
        return '"' + "".join("$" + x if i % 2 else _MDM_DQ_ESC.sub(r'\\\1', x)
                              for i, x in enumerate(_RF_MARK_RE.split(m.group(2)))) + '"'
    return _RF_MARK_RE.sub(r'$\1', _SQ_OR_ANSI_RE.sub(_seg, s))

def _report_form(cmd, literal=False):
    # Canonical form: the same wipe as an `sh -c` payload with `~` and as an expanded rm collapses to one line.
    # Left alone: a path with NO `~` (`~/Library` and `/Library` differ), pipelines and substitutions, and a line
    # opening with `#` (a RECORD, not a command).
    if cmd.startswith("#"): return cmd
    if _has_bare_operator(cmd): return cmd
    try: toks = shsplit(_rf_prep(cmd))
    except Exception: return cmd
    # `shlex.quote` for a path from a file EVENT: it is literal, and `report-2024*.log` must keep its quotes, or the
    # pasted line deletes every match as root. Never for the operand of a shell's `-c` nor a word holding a control
    # character: that is a SCRIPT, and a file name ending in a newline could become the script the report runs.
    _whole = _code_operands(toks)
    s = " ".join((shq if (literal or k in _whole or _CTL_ANY_RE.search(t))
                  else cmd_quote)(t, *((True,) if k in _whole else ())) for k, t in enumerate(toks))
    # Only the variables --mdm itself wrote (parked by _rf_prep) become live again; a `$` from the app stays
    # inside single quotes.
    return _rf_live(s) if "\ue000" in s else s

# Tab-separated, newline-terminated: tabs and newlines in a field are escaped (a multi-line `osascript -e`
# would otherwise split the record).
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
            # FORMAT marker on a fresh file; a file without it is read verbatim. Version 3 marks a file that MAY hold a
            # "T" record; _read_report_file treats 2 and 3 alike.
            fd = _rep_open(REPORT_FILE, os.O_WRONLY | os.O_CREAT | os.O_APPEND)
            if fd is None: return
            _new = True
            try: _new = os.fstat(fd).st_size == 0
            except Exception: pass
            # surrogateescape both ways (_read_report_file): a filename is bytes, and a strict encoder would raise.
            _rep_fh = os.fdopen(fd, "a", encoding="utf-8", errors="surrogateescape")
            if _new: _rep_fh.write("V\t3\n")
        _rep_fh.write(s)
        # Every record reaches the kernel at once (a killed process loses nothing); fsync is grouped.
        _rep_fh.flush()
        _rep_dirty.set()
        if time.monotonic() - _rep_synced >= REP_SYNC_S: _rep_sync()
        _rep_start_syncer()
    except Exception: pass

# Group commit: a power cut or kernel panic loses at most the last REP_SYNC_S; a clean stop or SIGTERM syncs first.
REP_SYNC_S = 0.2
_rep_dirty = threading.Event()
_rep_synced = 0.0
_rep_lock = threading.RLock()   # re-entrant: SIGTERM can land while the main thread holds it
_rep_thread = None

def _rep_sync():
    global _rep_synced
    with _rep_lock:
        if not _rep_dirty.is_set() or _rep_fh is None: return
        _rep_dirty.clear()
        _rep_synced = time.monotonic()
        try: os.fsync(_rep_fh.fileno())
        except Exception: pass

def _rep_syncer():
    while True:
        time.sleep(REP_SYNC_S)
        _rep_sync()

def _rep_start_syncer():
    # Idle after a burst: the last records still reach the disk within the window.
    global _rep_thread
    if _rep_thread is None:
        _rep_thread = threading.Thread(target=_rep_syncer, daemon=True)
        _rep_thread.start()

def record(cmd, destr, net, via="", note="", pid=None, synth=False, persist=False,
           secret=False, literal=False):
    if not REPORT: return
    # `literal`: SYNTHESISED from a file event, so `cmd_quote` must not run over it (it would strip the quotes from
    # a path containing `*` or `?`). The flag picks the quoting FUNCTION: `shlex.quote` protects `$loggedInUser`.
    global _rep_bytes
    if len(cmd) > REP_LINE_MAX:
        # Never a cut command (pasted, it would run a different one): a comment naming the size and the digest.
        cmd = ("# NOTE: command truncated, %d bytes (over %d), sha256 %s, not kept in the report"
               % (len(cmd.encode("utf-8", "surrogateescape")), REP_LINE_MAX, _dk(cmd)[1:17]))
        literal = False
    else:
        cmd = _report_form(cmd, literal)
    _dc = _dk(cmd)
    if _dc in rep_seen and not reordered(cmd, (rep[k][0] for k in range(rep_seen[_dc] + 1, len(rep)))):
        return
    _rep_bytes += len(cmd)
    if _rep_bytes > REP_BYTES:
        degrade("report byte budget reached, command not recorded")
        return
    # The time it was seen, so the script can reproduce the PAUSES. Appended fields keep old accumulators parseable.
    _t = time.time()
    rep_seen[_dc] = len(rep)
    rep.append((cmd, destr, net, via, note, _t, pid, synth, persist, secret))
    if pid is not None: rep_pids.add(pid)
    # Five flag digits. `literal` must travel: recovery re-runs _report_form. A shorter record reads the missing
    # digits as absent.
    _rep_write("%d%d%d%d%d\t%s\t%s\t%s\t%.3f\t%s\t%d\n"
               % (1 if destr else 0, 1 if net else 0, 1 if persist else 0,
                  1 if secret else 0, 1 if literal else 0,
                  _esc(cmd), _esc(via), _esc(note), _t,
                  "" if pid is None else pid, 1 if synth else 0))

def note_exit(pid):
    # When a command's process FINISHED, only for pids a command was recorded under. Its own line: the
    # accumulator is written once and fsync'd.
    if pid not in rep_pids or pid in ended: return
    ended[pid] = time.time()
    _rep_write("X\t%s\t%.3f\n" % (pid, ended[pid]))

def record_tcc(service, identity, right_s, reason_s, utype_s, actor_path, label=""):
    if not REPORT: return
    short = actor_path.rsplit("/", 1)[-1] if actor_path else ""
    _t = time.time()
    # Last event wins: a grant then a revoke reports "denied".
    rep_tcc[(service, identity)] = (right_s, reason_s, utype_s, short, _t, label)
    # The app label is a TRAILING field, so older "T" records still parse. An unmodified reader would render "T" as
    # a bogus command; see the version marker in _rep_write.
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
    # "B": unknown to older readers, which skip unknown record types. The app label is a trailing fifth field.
    _rep_write("B\t%s\t%s\t%s\t%s\t%s\n" % (action, _esc(path), kind_s, _esc(short), _esc(label)))

# A gap under 0.4 s is back-to-back spawn, not a wait (real pauses are 0.5-1.5 s); output in tenths. Past the
# cap it is a human, and `sleep 600` has no place in a fleet script: capped, with the real figure stated.
_SLEEP_MIN = 0.4
_SLEEP_MAX = 60

def sleep_arg(gap):
    # Rounded UP, to the tenth: waiting too long is free, replaying too fast may not be.
    if gap >= 10:
        n = min(math.ceil(round(gap, 6)), _SLEEP_MAX)
        return "%d" % n
    v = math.ceil(round(gap * 10, 6)) / 10.0
    return ("%d" % v) if v == int(v) else ("%.1f" % v)

def _gaps(entries, ends):
    # The wait BETWEEN two commands: from one's finish to the next's start, so a replay does not pay execution time
    # twice. Taken against the running maximum of every end so far, since what is still executing is rarely the
    # line above. No seen exit: the start time.
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

_WIPE_RE = re.compile(r'^(?:sudo )?rm -(?:rf|f) (.+)$')
def _wipe_root(cmd):
    # (path, removes_the_path_itself) for a reconstructed deletion, else None: `rm -rf P` takes P with it,
    # `rm -rf P/*` empties P and leaves it standing.
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
    # One tree-wipe can be flushed as several summaries, each naming a path inside the next; only the finished
    # report can know. Culprit's own reconstructions only: a `rm -rf` the app ran stays.
    roots = [(_wipe_root(e[0]) if (len(e) > 7 and e[7]) else None) for e in entries]
    # Looked up by path, not pairwise (n²): p itself or a prefix of p ending before a `/` (_covers, read the other way).
    by_root = {}
    for j, b in enumerate(roots):
        if b is not None: by_root.setdefault(b[0], []).append((j, b[1]))
    inside = []
    for i, a in enumerate(roots):
        if a is None or not by_root:
            inside.append([]); continue
        p = a[0]
        # The same line twice was kept for order (reordered()): neither subsumes the other.
        hits = [j for j, whole in by_root.get(p, ()) if whole and j != i and entries[j][0] != entries[i][0]]
        k = p.find("/")
        while k != -1:
            hits.extend(j for j, _ in by_root.get(p[:k], ()) if j != i)
            k = p.find("/", k + 1)
        inside.append(sorted(set(hits)))
    drop = set(i for i, c in enumerate(inside) if c)
    # A dropped line's count goes to the line that SURVIVES, never to another dropped one. If none survives,
    # the line stays.
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
            m = _FOLD_N_RE.search(e[4] or "")
            if m:
                n = int(m.group(1)) + folded[i]
                e = e[:4] + (_FOLD_N_RE.sub("%d syscall deletions folded" % n, e[4]),) + e[5:]
        out.append(e)
    return out

# Per-run randomness, normalised so identical captures compare equal: mktemp's own suffix, which survives --mdm.
# ONE entry on purpose (too much normalising hides a real difference), ANCHORED ON THE TEMP ROOT, not on a name
# shape: outside it nothing is touched (`~/Documents/tmp.backup2024` and `…2025` are different directories).
_SCRATCH_ROOT = (r'(?:(?:/private)?/var/folders/[^/\s"\']+/[^/\s"\']+/[0CT]'
                 r'|\$userTemp|\$userCache|\$userDir)')
_SCRATCH_PATH_RE = re.compile(_SCRATCH_ROOT + r'((?:/[^/\s"\']+)*)')
_MKTEMP_SEG_RE = re.compile(r'^([A-Za-z0-9_-]{1,32})\.([A-Za-z0-9]{6,})((?:\.[A-Za-z0-9]+)*)$')

def _looks_random(s):
    # A mktemp suffix is drawn from [A-Za-z0-9]; an English word is not, so all-lowercase letters are refused
    # (`cache/settings/vendor`). A missed suffix costs diff noise, a false collapse costs an observed act.
    return (not s.islower()) or any(c.isdigit() for c in s)

def _stable_form(cmd):
    def _seg(part):
        m = _MKTEMP_SEG_RE.match(part)
        if m and _looks_random(m.group(2)):
            return m.group(1) + ".XXXXXX" + m.group(3)
        return part
    return _SCRATCH_PATH_RE.sub(
        lambda m: m.group(0)[:len(m.group(0)) - len(m.group(1))]
                  + "".join("/" + _seg(x) for x in m.group(1).split("/")[1:]),
        cmd)

# Rolls the marked persistence entries up by WHERE they land (the roots `is_persistence` matched): `cp x y.plist`
# and the `chmod 644 y.plist` below it are one INSTALL.
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

def _unwrap_sh_c(cmd):
    # A shell payload is printed as the quoted call; the verb that decides is the payload's.
    try: _t = [x for x in shsplit(cmd) if x != "sudo"]
    except ValueError: return cmd
    if len(_t) == 3 and _t[0].rsplit("/", 1)[-1] in ("sh", "bash", "zsh") and _t[1] == "-c": return _t[2]
    return cmd

def _persist_cmd_removed(cmd):
    # A path this run installed can also leave: same final-state rule as record_btm.
    cmd = _unwrap_sh_c(cmd)
    try:
        _toks = _peel_asuser([t for t in shsplit(cmd) if t != "sudo"])
    except ValueError:
        return ""
    if not _toks or _toks[0].rsplit("/", 1)[-1] not in ("rm", "mv"):
        return ""
    return _persist_target(cmd)

def _persist_is_activation(cmd):
    # The leading verb decides, `sudo` aside: a line that also copies (`cp … && launchctl load …`) leads with the
    # copy and keeps its rollup item.
    cmd = _unwrap_sh_c(cmd)
    try:
        _toks = _peel_asuser([t for t in shsplit(cmd) if t != "sudo"])
    except ValueError:
        return False
    return bool(_toks) and _toks[0].rsplit("/", 1)[-1] == "launchctl"

def _peel_asuser(toks):
    # `launchctl asuser 501 cp x y.plist` is a cp; judged() peels it the same way.
    for _ in range(8):
        if not toks or toks[0].rsplit("/", 1)[-1] != "launchctl": break
        inner = _asuser_inner(toks)
        if not inner: break
        toks = [t for t in inner if t != "sudo"]
    return toks

def _persist_actor(entry, tool=""):
    # The `via` the entry already carries, else the tool of the stage that placed it (as emit_file/emit_perm).
    _via = entry[3] if len(entry) > 3 else ""
    if _via: return _via
    if tool: return tool
    _toks = [t for t in entry[0].split() if t != "sudo" and not t.startswith("#")]
    return _toks[0].rsplit("/", 1)[-1] if _toks else "?"

def _persist_rollup_lines(entries, btm):
    # Final state, not "ever installed": a path placed and later removed is dropped.
    _persist_items = {}
    for e in entries:
        if len(e) > 8 and e[8]:
            # `launchctl load`/`bootstrap`/`enable` starts a job and installs nothing: the rollup is keyed on what landed.
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
        _lines.append("#   %s: %s — via %s" % (_pk, inert_word(_pp), inert_word(_pa)))
    for _pp, _bv in _btm_items:
        _kind_s, _short = _bv[0], _bv[1]
        _blbl = _bv[2] if len(_bv) > 2 else ""
        _lines.append("#   Login item (%s): %s — via %s%s"
                       % (inert_word(_kind_s), inert_word(mdm_rewrite(_pp)), inert_word(_short) or "?",
                          _app_suffix(_blbl)))
    return _lines

def _tcc_lines_for(tcc):
    if not tcc: return []
    # Final state only: the last event per (service, identity), as rep_tcc/record_tcc apply live.
    _lines = ["# Privacy (TCC) changes (%d):" % len(tcc)]
    for _svc, _id in sorted(tcc):
        _tv = tcc[(_svc, _id)]
        _right, _reason, _utype, _short = _tv[0], _tv[1], _tv[2], _tv[3]
        _tlbl = _tv[5] if len(_tv) > 5 else ""
        # A path identity (identity_type 1) can sit in a home: --mdm rewrites it at render time, the accumulator keeps
        # the raw one.
        _id = inert_word(mdm_rewrite(_id))
        _svc, _right, _reason, _utype = inert_word(_svc), inert_word(_right), inert_word(_reason), inert_word(_utype)
        _short = inert_word(_short)
        if STABLE:
            # reason and update_type say how a grant arrived, not what the current state is.
            _lines.append("#   %s: %s → %s%s"
                           % (_svc, _id, _right, _app_suffix(_tlbl)))
        else:
            _via = " — via %s" % _short if _short else ""
            _lines.append("#   %s: %s → %s (%s, %s)%s%s"
                           % (_svc, _id, _right, _reason, _utype, _via, _app_suffix(_tlbl)))
    return _lines

def _render_lines(entries, recovered, ends=None, tcc=None, btm=None):
    # `tcc`/`btm` default to the live globals; a recovery passes what _read_report_file rebuilt.
    tcc = rep_tcc if tcc is None else tcc
    btm = rep_btm if btm is None else btm
    entries = _drop_subsumed(entries)
    # Marks on the entry: destructive, network, persistence, secret. Anything carrying one survives.
    if MARKS_ONLY:
        entries = [e for e in entries if (len(e) > 1 and e[1]) or (len(e) > 2 and e[2])
                   or (len(e) > 8 and e[8]) or (len(e) > 9 and e[9])]
    rout = rep_out
    # Computed once for STABLE and the full report: a privacy grant and what survives a reboot are state, not a
    # step whose wording drifts.
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
        # A capture that saw nothing must not look like a dead parser; the line opens with `#`, so the contract holds.
        if not _fresh and not _stable_emitted and not _persist_lines and not _tcc_lines:
            rout("# (nothing captured)")
        return
    _tag = " (recovered from an interrupted run — e.g. a reboot)" if recovered else ""
    # A repeat kept for order is not another distinct command.
    _nd = len(set(e[0] for e in entries))
    rout("# ===== Culprit report%s — %d distinct command%s =====" %
         (_tag, _nd, "" if _nd == 1 else "s"))
    for _title, _idx in (("⚠ destructive", 1), ("⚠ network", 2),
                         ("⚠ persistence", 8), ("⚠ secret", 9)):
        _hits = list(dict.fromkeys(e[0] for e in entries if len(e) > _idx and e[_idx]))
        if _hits:
            rout("# %s (%d):" % (_title, len(_hits)))
            for c in _hits: rout("#   %s" % comment_cmd(c))
    for _l in _persist_lines: rout(_l)
    for _l in _tcc_lines: rout(_l)
    if entries:
        rout("")
        rout("# " + "=" * 76)
        rout("# ===== COMMANDS IN ORDER: review, keep only what to replay; never run it whole =====")
        rout("# " + "=" * 76)
        # In interactive zsh `#` starts a comment only with this option (off by default on macOS); bash and sh read
        # the line as a failing command, absorbed by `|| true`.
        rout("setopt interactivecomments 2>/dev/null || true")
        # --mdm rewrites user paths into variables; the script is runnable only if it defines them first.
        if MDM:
            for _l in _mdm_script_header([e[0] for e in entries]): rout(_l)
        # Comments ABOVE each command carry what the live stream prints under a line: the actor when it is a tool the
        # app ran (`via lsregister`), and the notes that decide whether the line can be replayed.
        _gp = _gaps(entries, ends or {})
        if any(g >= _SLEEP_MIN for g in _gp):
            rout("# NOTE: a `sleep` line is time nothing was RUNNING — measured from the end of the")
            rout("#   command above it to the start of the next, so a slow command's own execution")
            rout("#   is not counted twice. What is left is the app waiting for an effect, or you")
            rout("#   at the keyboard. Keep them: waiting too long is safe, replaying too fast is not.")
        for _e, _gap in zip(entries, _gp):
            c, v, nt = _e[0], _e[3], (_e[4] if len(_e) > 4 else "")
            if _gap >= _SLEEP_MIN:
                # Own line above, like the live stream: a `#` after a command shares its line with it.
                if _gap > _SLEEP_MAX: rout("# observed %ds, capped" % int(_gap))
                rout("sleep %s" % sleep_arg(_gap))
            _bits = ([("via %s" % inert_word(v))] if v else []) + ([nt] if nt else [])
            if _bits: rout("# " + " — ".join(_bits))
            rout(c)
        rout("# ===== end of commands =====")
        rout("")
    elif not tcc and not btm:
        # A filter (--marks-only) can be what emptied the report: say so instead of "nothing captured".
        rout("# (nothing carried a mark)" if MARKS_ONLY else "# (nothing captured)")
    if _schema is not None and not STABLE:
        rout("# eslogger schema_version: %s" % inert_word(_schema))
    if _degraded and not STABLE:
        rout("")
        rout("# ⚠ %d event(s) were observed but could not be fully read:"
             % sum(_degraded.values()))
        for _r in sorted(_degraded):
            rout("#   %d x %s" % (_degraded[_r], inert_word(_r)))
        rout("#   The capture is incomplete by that much. If this is a new macOS,")
        rout("#   eslogger's event shape has moved — run with --debug to see it.")

def _read_report_file(path):
    entries, seen, ends, tcc, btm = [], {}, {}, {}, {}
    escaped = False
    try:
        _fd = _rep_open(path, os.O_RDONLY)
        if _fd is None: return entries, ends, tcc, btm
        with os.fdopen(_fd, encoding="utf-8", errors="surrogateescape") as f:
            for line in f:
                # A torn tail (power cut mid-record) has no newline: half a command is never read as a command.
                if not line.endswith("\n"): break
                p = line.rstrip("\n").split("\t")
                if len(p) < 2: continue
                if p[0] == "V":                     # format marker, see _rep_write
                    escaped = len(p) > 1 and p[1] in ("2", "3")
                    continue
                if p[0] == "X":                     # a process finished
                    try: ends[int(p[1])] = float(p[2])
                    except (ValueError, IndexError): pass
                    continue
                if p[0] == "T":                     # a TCC change, see record_tcc()
                    if len(p) < 8: continue
                    _svc, _id, _short = p[1], p[2], p[6]
                    if escaped:
                        _svc, _id, _short = _unesc(_svc), _unesc(_id), _unesc(_short)
                    try: _tt = float(p[7]) if p[7] else None
                    except ValueError: _tt = None
                    # Last event per (service, identity) wins, as in rep_tcc; p[8] (app label) is optional.
                    _tlbl = p[8] if len(p) > 8 else ""
                    if escaped: _tlbl = _unesc(_tlbl)
                    tcc[(_svc, _id)] = (p[3], p[4], p[5], _short, _tt, _tlbl)
                    continue
                if p[0] == "B":                     # a login item add/remove, see record_btm()
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
                # A record type this reader does not recognise: never read as a command line.
                if len(p[0]) == 1 and p[0].isalpha() and p[0] not in ("V", "X", "T", "B"):
                    continue
                if escaped:
                    p[1] = _unesc(p[1])
                    if len(p) > 2: p[2] = _unesc(p[2])
                    if len(p) > 3: p[3] = _unesc(p[3])
                # As in record(): a synthesised line is taken verbatim; re-quoting would strip the quotes from a glob path.
                _c = _report_form(p[1], p[0][4:5] == "1")
                if _c in seen and not reordered(_c, (entries[k][0] for k in range(seen[_c] + 1, len(entries)))):
                    continue
                seen[_c] = len(entries); p[1] = _c
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
    # At startup: a non-empty accumulator means a previous --report run was interrupted before it could render.
    # Print it, then clear it.
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
                "untouched." % inert_word(REPORT_FILE))
        return
    # `or tcc or btm`: a run that saw only TCC changes or login items still has something to recover.
    if ents or tcc or btm: _render_lines(ents, True, ends, tcc, btm)
    _fd = _rep_open(REPORT_FILE, os.O_WRONLY | os.O_TRUNC)
    if _fd is not None:
        try: os.close(_fd)
        except Exception: pass

def render_report():
    if not REPORT: return
    _rep_sync()
    _render_lines(rep, False, ended, rep_tcc, rep_btm)
    # Here and not in _render_lines: a recovery renders twice into one report, and this line proves the whole
    # report was written.
    rep_out(_REPORT_END)
    _rep_out_commit()
    if REPORT_FILE and not _rep_out_bad:
        try: os.remove(REPORT_FILE)        # clean stop: nothing left to recover
        except Exception: pass

# ============================================================================
# JUDGING A COMMAND LINE
# ============================================================================
# A rule is evaluated against the real command, not its wrapper: `sh -c 'rm -rf …'` is an rm, `xargs kill -9` is
# a kill. `judged()` peels wrappers; `_stage_hit()` walks every pipeline stage.

def judged(path, args):
    # The command a rule is evaluated against. Display keeps the wrapper; the destructive flag and the note come
    # from the command inside it.
    p, a = path, args
    for _ in range(4):
        b = p.rsplit("/", 1)[-1]
        # `launchctl asuser UID cmd…` is peeled like sudo, so a cp into ~/Library/LaunchAgents is judged as the cp.
        inner = _asuser_inner(a) if b == "launchctl" else None
        if inner is None:
            if b not in _SHELLS and b not in _ARG_WRAPPERS: break
            inner = payload_argv(p, a)
        if not inner: break
        p, a = inner[0], inner
    return p, a

def _asuser_inner(args):
    # The argv `launchctl asuser UID …` runs, [] when it names none, None when this launchctl is not an asuser.
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
# SHELL STAGES
# ============================================================================
# shlex.split cuts on whitespace only (`echo hi; rm -rf /x` is one stage); shell_tokens() reads a payload as sh does.

class _Op(str):
    __slots__ = ()

class _Word(str):
    bare = None

def _bare_len(t):
    b = getattr(t, "bare", None)
    return len(t) if b is None else b

# Longest first, so `&&` is never read as two `&`.
_OPS = ("<<<", "<<-", "&>>", ";;&", "&&", "||", ";;", ";&", "|&", "&>", ">>", ">&",
        ">|", "<<", "<&", "<>", ";", "&", "|", "(", ")", ">", "<")
_OP_CHARS = frozenset(";&|()<>")
_STAGE_SEPS = {"|", "|&", "||", "&&", ";", "&"}      # as plain argv tokens (find's `;`)
_CASE_ENDS = frozenset({";;", ";&", ";;&"})
_SEP_OPS = frozenset(_STAGE_SEPS | _CASE_ENDS | {"(", ")", "\n"})
_REDIRECTS = (">", ">>", ">|", "&>", "&>>", ">&", "<>")
# Words that open a stage without being its command (`if …; then rm -rf /x; fi`).
_SH_KEYWORDS = frozenset({"if", "then", "else", "elif", "fi", "do", "done", "while",
                          "until", "!", "{", "}", "esac",
                          "exec", "command", "builtin", "coproc"})
_SH_KW_OPTS = {"exec": {"-a": 1, "-c": 0, "-l": 0}, "command": {"-p": 0}}

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
        # A here-string is one word, not a here-document: its `<<` must not start a body.
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
    # `bare`: unquoted characters before the first quoted piece; `still_bare` until one appears.
    bare, still_bare = 0, True
    def flush():
        nonlocal have, bare, still_bare
        if have:
            w = "".join(buf)
            # A word that merely spells a separator (`-s ';'`) is a _Word, so _stages never cuts on it.
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
            # Same decoder as the report (_ansi_c_decode): `\x27` and `\101` are bytes.
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
            # Unknown how the shell reads these words, so none is bare: no `{a,b}` or `~` expansion.
            w = _Word(t); w.subs = (); w.bare = 0
            out.append(w)
    return tuple(out)

# Cached: one event tokenises the same payload several times.
_tokens_small = functools.lru_cache(maxsize=512)(_tokens)
_tokens_big = functools.lru_cache(maxsize=2)(_tokens)

def shell_tokens(s):
    # Never raises: an unreadable line falls back to a coarser split (see _tokens).
    return list(_tokens_small(s) if len(s) <= 8192 else _tokens_big(s))

def _is_assign(t):
    return not t.startswith(("/", "-")) and "=" in t.split("/")[0]

def _stages(argv, path0=None, depth=0):
    # (path, args, redirections) per command, cut at list and pipeline operators; wrappers peeled by judged().
    if depth > 8:
        # Nested past what is followed: never taken for a query, never marked.
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
            # `case … in start|reboot)`: a pattern is matched, never run.
            if is_op and t == ")": in_pat = False
            elif t == "esac" and not is_op: in_pat = False; case_n -= 1
            i += 1; continue
        if in_test:
            # Inside `[[ … ]]` the operators are the test's syntax (`=~ ^(a|b)$`); only a substitution runs.
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
        # A separator is an _Op, or a plain str from an eslogger argv; never a _Word that only spells one.
        if t is None or (t in _SEP_OPS if is_op else (type(t) is str and t in _STAGE_SEPS)):
            j = 0
            while j < len(stage) and (stage[j] in _SH_KEYWORDS or _is_assign(stage[j])
                                      or stage[j] == "function"):
                if stage[j] == "esac" and case_n: case_n -= 1
                if stage[j] == "function": j += 2; continue
                _kopts = _SH_KW_OPTS.get(stage[j])
                j += 1
                # Options these take; an unlisted one (`command -v rm` only prints a path) stays, so it is not judged as rm.
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
                # Descend when judged() unwrapped something holding more than one command.
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

def _truncates(jp, ja, redirs):
    # A command that prints nothing, redirected with `>`, empties the file: `: > f`, `> f`, `cat /dev/null > f`.
    b = jp.rsplit("/", 1)[-1]
    if not (b in ("", ":", "true") or (b == "cat" and ja[1:] == ["/dev/null"])): return False
    return any(op in (">", ">|", "&>") and tgt and not tgt.startswith("/dev/") for op, tgt in redirs)

def destructive_stage(argv):
    for jp, ja, _r in _stages(argv):
        if (jp and is_destructive(jp, ja)) or _truncates(jp, ja, _r): return (jp, ja)
    return None

# Network reach: only what an app shells out to is visible, not its own URLSession.
_NETWORK = {
    "curl": None, "wget": None, "nc": None, "ncat": None, "scp": None,
    "sftp": None, "ssh": None, "sshpass": None, "nscurl": None,
    # rsync has a local mode: flagged only with a remote operand.
    "rsync": {"~^[^/]+:"},
    "ftp": None, "tftp": None, "telnet": None, "socket": None,
    "aria2c": None, "axel": None, "httpie": None,
    # A beacon can be a bare DNS lookup.
    "dig": None, "nslookup": None, "host": None, "ping": None, "ping6": None,
    "traceroute": None, "traceroute6": None,
    # Package managers: only the fetching subcommands.
    "git":  {"clone", "fetch", "pull", "push", "ls-remote"},
    "pip":  {"install", "download"}, "pip3": {"install", "download"},
    "npm":  {"install", "i", "ci", "publish"}, "yarn": {"add", "install"},
    "gem":  {"install", "fetch", "push"}, "cargo": {"install", "fetch"},
    "go":   {"get", "mod"},
    "softwareupdate": {"-i", "--install", "-d", "--download", "-l", "--list"},
    "mas": {"install", "upgrade", "lucky"},
    "installer": {"~^https?://"}, "open": {"~^https?://"},
}
# Credential reach: does this line hand a secret to whoever runs it?
_SECRET = {
    "security": {"-w", "dump-keychain", "export", "unlock-keychain"},
    "dscl": {"ShadowHashData", "AuthenticationAuthority"},
    "gh": {"token"},
}

_KNOWN_CMDS = ((set(DESTRUCTIVE) | set(NOISE) | set(_NETWORK) | set(_SECRET)
                | _COPIERS | _REMOVERS | _PERM_CMDS) - _SHELLS - _ARG_WRAPPERS)

def _stage_hit(argv, table):
    # Any pipeline stage may match: `pgrep x | xargs security … -w` reads a keychain though its first command does not.
    for jp, ja, _r in _stages(argv):
        b = jp.rsplit("/", 1)[-1]
        if b in table and triggered(table[b], ja): return True
    return False

def network_stage(argv): return _stage_hit(argv, _NETWORK)
def secret_stage(argv):  return _stage_hit(argv, _SECRET)

# Queries: lines that only READ, dropped under --no-queries.
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
    # launchctl inspection verbs, judged on the first operand only (a service can be named `list`).
    "launchctl": {"print", "print-cache", "print-disabled", "list", "blame",
                  "dumpstate", "procinfo", "hostinfo", "resolveport", "plist",
                  "getenv", "error", "variant", "version", "managerpid",
                  "manageruid", "managername", "bslist", "help"},
    "awk": None, "grep": None, "egrep": None, "cut": None, "head": None,
    "tail": None, "sort": None, "uniq": None, "wc": None, "tr": None, "sed": None,
    "true": None, ":": None,
}
# An output file makes any of these a write (`sort -o`; `-o -` is stdout); an awk program can write via `>` or system().
_QUERY_AWK_WRITES = re.compile(r'system\s*\(|print[^|;}]*>|\|\s*"')

def _query_stage(stage):
    toks = list(stage)
    while toks and not toks[0].startswith(("/", "-")) and "=" in toks[0].split("/")[0]:
        toks.pop(0)                                 # `bootDisk=$(…)`
    if not toks: return True
    jp, ja = toks[0], toks
    b = jp.rsplit("/", 1)[-1]
    # judged() peels `xargs <cmd>`; an xargs still standing has no command: it runs echo.
    if b == "xargs": return True
    # Any other wrapper or shell still standing is unseen by _stages: not a query.
    if b in _SHELLS or b in _ARG_WRAPPERS: return False
    if b not in READ_ONLY: return False
    for i, a in enumerate(ja):
        if a in ("-o", "--output") and (i + 1 >= len(ja) or ja[i + 1] != "-"): return False
    if b == "awk" and any(_QUERY_AWK_WRITES.search(a) for a in ja[1:]): return False
    if b == "plutil" and "-extract" in ja and "-o" not in ja: return False
    # `uniq in out`: the second operand is the output; `-f`/`-s` take a number, not an operand.
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
    # Walks _stages like every mark: `defaults read x;rm -f y` is two stages.
    for jp, ja, redirs in _stages(toks):
        for op, tgt in redirs:
            if ">" not in op: continue                # <, <<, <&: input only
            # `2>&1` duplicates a descriptor; `>& file` writes one.
            _dup = op.endswith("&") and (tgt.isdigit() or tgt == "-")
            if not (_dup or tgt == "/dev/null" or tgt.startswith("&")): return False
        if jp and not _query_stage(ja): return False
    return True

def effective(path, args):
    payload = shell_payload(path, args)
    if payload:
        # Judged on what a positional call resolves to: `rm -rf $1/Library` with `/System` is a system wipe.
        _src = (shell_positional(path, args, payload) and positional_text(path, args, payload)) or payload
        # shell_tokens, not shlex.split: a glued `;` must reach the stage rules as an operator.
        try: toks = shell_tokens(_src)
        except ValueError: toks = []
        # An assignment that runs a command (`ip=$(curl …)`) is kept, so its substitution's mark survives.
        while (toks and not toks[0].startswith("/") and "=" in toks[0].split("/")[0]
               and not getattr(toks[0], "subs", None)):
            toks.pop(0)
        if toks: return toks[0], toks, payload
    return path, args, payload

def shell_payload(path, args):
    # The command inside `sh -c '…'`; a shell-out arrives twice, as the shell and as what it becomes.
    if path.rsplit("/", 1)[-1] not in _SHELLS: return ""
    i = shell_c_index(args)
    if i < 0: return ""
    return args[i + 1] if i + 1 < len(args) else ""

# `sh -c 'rm -rf "$1"/Library' sh /Users/x`: words after the payload are $0, $1…. When the payload reads a positional
# parameter, the whole call is the command; the payload alone would replay differently.
# `for f; do` and `getopts` read them with no `$` in sight.
_POSITIONAL_RE = re.compile(r'\$(?:[0-9@*#]|argv\b|\{[#!]?(?:[0-9@*#]|argv\b))'
                            r'|\bfor\s+\w+\s*(?:;|\n|do\b)|\bgetopts\b')
def shell_positional(path, args, payload):
    if not payload or not _POSITIONAL_RE.search(payload): return False
    i = shell_c_index(args)
    return i >= 0 and i + 2 < len(args)

# The payload with its positional words put back: the exec it becomes folds into the call printed whole, and its marks
# are judged on the paths it touches. "" when the shell's resolution is uncertain (a loop variable, shift, a function,
# quoting not followed here): the real child then prints as observed.
_POS_SUB_RE = re.compile(r'(")?\$(?:\{(?:([@*])(?::(\d+))?|(\d+)|argv\[(\d+)\])\}'
                         r'|([@*])|(\d)|argv\[(\d+)\]|(argv)\b)(?(1)")')
_POS_FLOW_RE = re.compile(r'(?:^|[\s;&|(])(?:shift|set|getopts|function)(?=$|[\s;&|)])|\(\s*\)')
_DQ_SPECIAL = ('"', "$", "\\", "`")   # still live inside double quotes
def positional_text(path, args, payload):
    if any(c in payload for c in ("'", "\\", "`")) or _POS_FLOW_RE.search(payload): return ""
    zsh = path.rsplit("/", 1)[-1] == "zsh"
    pos = args[shell_c_index(args) + 2:]
    bad = []
    def _sub(m):
        g = m.groups()
        if (g[4] or g[7] or g[8]) and not zsh: bad.append(m); return ""
        quoted = g[0] is not None
        inside = payload.count('"', 0, m.start()) % 2 == 1
        # `"a"$1"b"`: those quotes close and reopen, they do not wrap the parameter.
        if quoted and inside: bad.append(m); return ""
        if g[1] or g[5] or g[8]:
            vals = pos[int(g[2]) if g[2] else 1:]
            if (g[1] or g[5]) == "*" and (quoted or inside): vals = [" ".join(vals)]
        else:
            n = int(next(x for x in (g[3], g[4], g[6], g[7]) if x is not None))
            if n == 0 and (g[4] or g[7]): bad.append(m); return ""
            vals = [pos[n] if n < len(pos) else ""]
        if quoted: return " ".join(shlex.quote(v) for v in vals)
        if inside:
            if any(c in v for v in vals for c in _DQ_SPECIAL): bad.append(m)
            return " ".join(vals)
        # Unquoted: sh splits and globs the value, zsh does neither.
        if zsh: return " ".join(shlex.quote(v) for v in vals if v)
        if any(v and shlex.quote(v) != v for v in vals): bad.append(m)
        return " ".join(v for v in vals if v)
    res = _POS_SUB_RE.sub(_sub, payload)
    return "" if bad or "$" in res else res

# ============================================================================
# PAIR FOLDING
# ============================================================================
# Both halves are execs (wrapper and what it becomes, pattern and expansion, substitution and body): the first form is kept,
# the second becomes a note or nothing. Five-second windows, so a pair cannot join two separate acts.

pending_glob = {}     # (label, binary) -> (prefixes, time, real_glob, n_globs, n_paths)

def payload_covers(payload, args, _depth=0):
    # Is this bare command already covered by the printed payload? Compared as tokens: the payload keeps the app's quoting,
    # the exec carries the shell's unquoted argv.
    if not payload or not args: return False
    # Operators dropped: `echo a|launchctl load X` still covers the bare `launchctl load X`.
    toks = [t for t in shell_tokens(payload) if not isinstance(t, _Op)]
    if _depth < 8:
        for t in toks:
            for body in getattr(t, "subs", ()):
                if payload_covers(body, args, _depth + 1): return True
    want = [args[0].rsplit("/", 1)[-1]] + list(args[1:])
    n = len(want)
    # Words as written, then brace-expanded (`rm -rf /tmp/{a,b}` execs two paths); a quoted brace stays literal (_brace_words).
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
    # (prefix, [alternatives], suffix) of the first expandable `{…}` (a comma at its own depth), or None.
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
    # A `{a,b}` word as the shell hands it over: one word per alternative, nested in the shell's order, or [t].
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
    # A command substitution arrives as its own exec (`pkill -U $(whoami) …` then a bare `whoami`): a fragment of the printed line.
    for m in _SUBST_BODY_RE.finditer(payload or ""):
        body = m.group(1) or m.group(2) or ""
        if body and payload_covers(body, args): return True
    return False

_SUBST_RE = re.compile(r'\$\(|`|\$\w|\$\{')
def _tok_eq(p, a):
    # A token holding a substitution or variable cannot be compared with what the shell resolved (`$(whoami)` vs `ard`).
    if _SUBST_RE.search(p): return True
    if p == a: return True
    return bool(HOME) and (p == "~" or p.startswith("~/")) \
        and _bare_len(p) >= min(len(p), 2) and HOME + p[1:] == a

# A shell line is printed whole, then each command inside it execs on its own (`diskutil info / | awk …`, then a bare `diskutil info /`).
pending_shell = {}    # label -> [(payload, time)], most recent last
_PENDING_SHELL_S = 5.0
_PENDING_SHELL_MAX = 256
# Same bound for the glob pair: past a few seconds, two `rm` lines are two acts.
_PENDING_GLOB_S = 5.0

def _remember_payload(label, text, now):
    # What this command is about to become, so the next exec folds into it.
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
    # LITERAL prefix of each pattern (before the first glob character, tilde EXPANDED): an expanded path must start with it.
    out = []
    for a in args[1:]:
        if "*" in a or "?" in a or a.startswith("~"):
            i = min((a.index(c) for c in "*?[" if c in a), default=len(a))
            d = a[:i]
            # Expand the tilde, never strip it: `~/Library/Caches` would become the system /Library/Caches.
            if d.startswith("~"):
                if not HOME: continue
                d = HOME + d[1:]
            if d and d not in out: out.append(d)
    return out

# ============================================================================
# EMISSION
# ============================================================================
# Four emitters (emit, emit_file, emit_perm, emit_wipe) share one contract: decide `sudo`, apply --mdm, mark, record, print.
# Marks are computed before `record`, so the report and the live stream never disagree.

seen_apps = set()     # labels already announced as started
helper_noted = set()  # labels that already got the "runs as root" note
scope_noted = set()   # …and those told their commands write outside the user's reach

# System scope: the user cannot write there without root, so reproducing needs sudo.
# /private/var/folders is per-user; /opt/homebrew belongs to the installing user.
_USER_WRITABLE = ("/Users/", "/tmp/", "/private/tmp/", "/var/folders/",
                  "/private/var/folders/", "/Volumes/", "/opt/homebrew/")
_SYSTEM_ROOTS = ("/System/", "/Library/", "/usr/", "/bin/", "/sbin/",
                 "/Applications/", "/opt/", "/etc/", "/private/etc/",
                 "/var/", "/private/var/")
def system_scope(path):
    if not path: return False
    # Another account's home needs `sudo`.
    if path.startswith("/Users/"):
        if not HOME.startswith("/Users/"): return False
        if path == HOME or path.startswith(HOME + "/"): return False
        return not path.startswith("/Users/Shared/")
    if path.startswith(_USER_WRITABLE): return False
    return path.startswith(_SYSTEM_ROOTS)

_COPY_READS_SRC = {"cp", "ln", "rsync", "ditto", "install"}
_SCOPE_WRITERS = _PERM_CMDS | _REMOVERS | {"mv", "touch", "mkdir", "tee", "dd"}
# launchctl writes launchd's state, not a file: no path test. The system domain is privileged (launchctl(1)).
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
        # `asuser UID command…`: the inner command is judged normally; bounded against a long `asuser 1 …` chain.
        inner = args[args.index("asuser", 1) + 2:]
        return (bool(inner) and _depth < 8
                and writes_system_scope(inner[0], inner, _depth + 1))
    if verb in _LAUNCHCTL_DOMAIN_VERBS:
        return any(o == "system" or o.startswith("system/") for o in ops[1:])
    if verb in ("load", "unload"):
        return any(system_scope(o) and "/LaunchAgents/" not in o for o in ops[1:])
    return False

def writes_system_scope(path, args, _depth=0):
    # Stage by stage like every mark: `echo hi ; rm -f /Library/Foo/x` writes in its second stage.
    for p, a, redirs in _stages(args, path):
        # A redirection lands where it points, whatever ran it.
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
# Bundle suffixes whose enumeration is machinery (dyld frameworks, plug-in scans). .app keeps its own directory, drops what is inside.
_CODE_BUNDLES = (".framework", ".bundle", ".plugin", ".spreporter", ".kext",
                 ".xpc", ".appex", ".qlgenerator", ".mdimporter", ".prefPane",
                 ".saver", ".component", ".audiounit", ".vst", ".vst3")
file_noted = set()    # labels already told these are reconstructed commands

perm_noted = set()    # labels already told these are reconstructed commands
def emit_perm(label, cmd, destr, path, kind, via="", actor=None):
    scoped = system_scope(path)
    if scoped and not cmd.startswith("#"): cmd = "sudo " + cmd
    cmd = mdm_rewrite(cmd)
    # Never say "via chmod" on a chmod line; `sudo` comes off before comparing.
    _tool = cmd.split()
    _tool = _tool[1] if _tool[:1] == ["sudo"] else (_tool[0] if _tool else "")
    via = via if via and via != _tool.lstrip("#") else ""
    key = label + "\x00" + cmd
    now = time.time()
    if repeated(key, cmd, now): return
    # A permission change on a launch-item or helper location must reach the `⚠ persistence` section.
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
        if _marks: out("C\t# " + " ".join(_marks))   # above the command, never after it
        out("C\t%s" % cmd)
    else:
        out("C\t# %s changed permissions:%s" % (inert_word(label),
            ("  " + "  ".join(_marks)) if _marks else ""))
        out("C\t%s" % cmd)
    if via: out("C\t# via %s" % inert_word(via))
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
    if repeated(key, cmd, now): return
    _persist = is_persistence(path)
    _marks = ((["⚠ system scope"] if scoped else [])
              + (["⚠ persistence"] if _persist else []))
    record(cmd, False, False, via, persist=_persist, literal=True, synth=True)
    mdm_header()
    if NDJSON:
        json_out("deleteextattr", label, cmd, via, _marks, actor=actor)
        return
    if SOLO:
        if _marks: out("C\t# " + " ".join(_marks))   # above the command, never after it
        out("C\t%s" % cmd)
    else:
        out("C\t# %s removed an extended attribute:%s" % (inert_word(label),
            ("  " + "  ".join(_marks)) if _marks else ""))
        out("C\t%s" % cmd)
    if via: out("C\t# via %s" % inert_word(via))
    # com.apple.quarantine: its removal means Gatekeeper no longer treats the file as downloaded.
    if name == "com.apple.quarantine":
        out("C\t# NOTE: the Gatekeeper quarantine on this file was lifted — it will now open without the \"unidentified developer\" warning")
    if label not in xattr_noted:
        xattr_noted.add(label)
        out("C\t# NOTE: removed through a system call, not by running this command — the line above reproduces it")

_VERB_TOOL = {"moved": "mv", "listed": "ls", "opened": "cat", "deleted": "rm",
              "copied": "cp", "linked": "ln"}
# --ndjson `kind` for emit_file: the eslogger event behind each verb; "copied" covers a clone and a plain copy.
_VERB_KIND = {"deleted": "unlink", "moved": "rename", "copied": "clone",
              "linked": "link", "listed": "readdir", "opened": "open"}
_WRITE_VERBS = ("deleted", "moved", "copied", "linked")
_DESTRUCTIVE_VERBS = ("deleted", "moved")
_VERB_SAID = {"deleted": "removed", "moved": "moved",
              "copied": "copied", "linked": "hard-linked"}
def emit_file(label, verb, path, dst="", via="", actor=None, leaf=False, note=""):
    if verb == "moved":
        cmd = "mv %s %s" % (shq(path), shq(dst))
    elif verb == "copied":
        # -R: the source may be a directory and a clone takes the tree.
        cmd = "cp -R %s %s" % (shq(path), shq(dst))
    elif verb == "linked":
        cmd = "ln %s %s" % (shq(path), shq(dst))
    elif verb == "listed":
        cmd = "ls -la %s" % shq(path)
    elif verb == "opened":
        cmd = "cat %s" % shq(path)
    else:
        cmd = ("rm -f %s" if leaf else "rm -rf %s") % shq(path)
    writing = verb in _WRITE_VERBS
    if verb == "moved":
        scoped = system_scope(path) or system_scope(dst)
    else:
        _target = dst if verb in ("copied", "linked") and dst else path
        scoped = writing and system_scope(_target)
    if scoped: cmd = "sudo " + cmd
    cmd = mdm_rewrite(cmd)
    # Name the actor only when it is not the app itself nor the tool being reconstructed.
    via = via if via and via != _VERB_TOOL.get(verb) else ""
    key = label + "\x00" + cmd
    now = time.time()
    if repeated(key, cmd, now): return
    _persist = verb in ("moved", "copied", "linked") and is_persistence(dst)
    _marks = []
    if scoped: _marks.append("⚠ system scope")
    if _persist: _marks.append("⚠ persistence")
    # --no-queries as in emit(): a read-only reconstruction (`ls`, `cat`) is dropped; write verbs stay.
    if NO_QUERIES and not writing:
        debug_filtered("%s (query)" % cmd)
        return
    record(cmd, verb in _DESTRUCTIVE_VERBS, False, via,
           synth=(verb == "deleted"), persist=_persist, literal=True)
    mdm_header()
    if NDJSON:
        # record() decides if the verb destroys; _marks omits it (the header names the verb), but a structured feed has no header.
        _jmarks = _marks + (["⚠ destructive"] if verb in _DESTRUCTIVE_VERBS else [])
        json_out(_VERB_KIND.get(verb, "unlink"), label, cmd, via, _jmarks, actor=actor)
        return
    if note: out("C\t# NOTE: " + note)   # caller passes it through inert_word
    if SOLO:
        if _marks: out("C\t# " + " ".join(_marks))   # above the command, never after it
        out("C\t%s" % cmd)
    else:
        out("C\t# %s %s:%s" % (inert_word(label), verb,
                               ("  " + "  ".join(_marks)) if _marks else ""))
        out("C\t%s" % cmd)
    if via: out("C\t# via %s" % inert_word(via))
    if _persist:
        # Said every time, not once per app: this is the line an audit is for. The temp source is gone.
        out("C\t# NOTE: software installing itself here — a launch item, a helper, a binary on the PATH. The temp source is gone, so this records the act rather than reproducing it")
    # Per verb, so a move and a delete each get their note.
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

# An app wiping a cache tree through the API emits one unlink per file and emptied directory: one act.
del_buf = []          # [(label, path, via, time, actor, ts, leaf)] — a run of uncovered deletions

# Directories holding unrelated content: three deletions sharing only one of these as ancestor are separate acts,
# and `rm -rf <it>/*` would describe something no app did.
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

# Literal glob parts: inert in sh and zsh unquoted, and ASCII, so the check below sees what the shell will match.
_GLOB_LIT_RE = re.compile(r'[A-Za-z0-9._,+-]*')
_DIGITS_RE = re.compile(r'[0-9]+$')
def _lit_head(names):
    return _GLOB_LIT_RE.match(os.path.commonprefix(names)).group(0)
def _lit_tail(names):
    return _lit_head([n[::-1] for n in names])[::-1]

def near_miss_glob(d, names):
    # One glob over d's direct children taking every deleted name and nothing still there; else None.
    if any(c in d for c in _GLOB_META): return None   # the report re-reads the line with globs unquoted
    try:
        with os.scandir(d) as it: left = [e.name for e in it]
    except Exception: return None
    cands = []   # (leading digit class, prefix, trailing digit class, suffix), simplest first
    pre, suf = _lit_head(names), _lit_tail(names)
    if len(pre) >= 2: cands.append((False, pre, False, ""))
    if len(suf) >= 2: cands.append((False, "", False, suf))
    if pre:
        s2 = _lit_tail([n[len(pre):] for n in names])
        if s2: cands.append((False, pre, False, s2))
    digits = all(_DIGITS_RE.match(n) for n in names)
    if digits: cands.append((True, "", False, ""))
    if all(_DIGITS_RE.match(n[:1]) for n in names):
        s2 = _lit_tail([n[1:] for n in names])
        if s2: cands.append((True, "", False, s2))
    if digits and all(len(n) >= 2 for n in names): cands.append((True, "", True, ""))
    for lead, p, trail, s in cands:
        rx = "%s%s.*%s%s" % ("[0-9]" if lead else "", re.escape(p), "[0-9]" if trail else "", re.escape(s))
        if not all(re.fullmatch(rx, n, re.S) for n in names): continue
        # Case-blind and dot-blind on what is left: nocaseglob or dotglob must not reach it either.
        if any(re.fullmatch(rx, n, re.S | re.I) for n in left): continue
        return "%s%s*%s%s" % ("[0-9]" if lead else "", p, "[0-9]" if trail else "", s), len(left)
    return None

def emit_glob(label, root, glob, n, left, via="", tree=False, actor=None):
    via = via if via and via != _VERB_TOOL["deleted"] else ""
    # Glob outside the quotes; -rf only when an entry may be a directory.
    cmd = "%s %s/%s" % ("rm -rf" if tree else "rm -f", shq(root), glob)
    scoped = system_scope(root)
    if scoped: cmd = "sudo " + cmd
    cmd = mdm_rewrite(cmd)
    if repeated(label + "\x00" + cmd, cmd, time.time()): return
    record(cmd, True, False, via,
           "%d syscall deletions folded; the glob matched nothing left there afterwards" % n, synth=True)
    mdm_header()
    if SOLO:
        if scoped: out("C\t# ⚠ system scope")
    else:
        out("C\t# %s deleted:%s" % (inert_word(label), "  ⚠ system scope" if scoped else ""))
    out("C\t%s" % cmd)
    if via: out("C\t# via %s" % inert_word(via))
    out("C\t# NOTE: %d entries erased under it by direct system calls (no shell command) — the glob was checked "
        "against what remained there at the end of the run: it takes every erased name and none of the %d left"
        % (n, left))

def emit_wipe(label, root, n, via="", whole=False, verified=False, actor=None):
    # As in emit_file: never "via rm" on an rm line.
    via = via if via and via != _VERB_TOOL["deleted"] else ""
    # Tree-wipe summary. `/*` (outside the quotes so the shell globs it) empties the directory without removing it.
    cmd = ("rm -rf %s" if whole else "rm -rf %s/*") % shq(root)
    scoped = system_scope(root)
    if scoped: cmd = "sudo " + cmd
    cmd = mdm_rewrite(cmd)
    now = time.time()
    key = label + "\x00" + cmd
    if repeated(key, cmd, now): return
    record(cmd, True, False, via,
           ("%d syscall deletions folded; %s verified empty afterwards" %
            (n, "removed" if whole else "left")) if verified else
           ("⚠ approximate: %d syscall deletions folded — --no-fold gives the exact list" % n),
           # Not literal: the trailing `/*` is a glob shlex.quote would swallow; the root is quoted before, and cmd_quote keeps that.
           synth=True)
    mdm_header()
    if NDJSON:
        json_out("unlink", label, cmd, via,
                 ["⚠ destructive"] + (["⚠ system scope"] if scoped else []),
                 folded=n, actor=actor, extra={"verified": bool(verified)})
        return
    if SOLO:
        if scoped: out("C\t# ⚠ system scope")
        out("C\t%s" % cmd)
    else:
        out("C\t# %s deleted:%s" % (inert_word(label), "  ⚠ system scope" if scoped else ""))
        out("C\t%s" % cmd)
    if via: out("C\t# via %s" % inert_word(via))
    if verified:
        # Verified: nothing predating the wipe survived, so the line is an exact reproduction.
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
    seen, by_label = set(), {}
    acts = {}   # (label, path) -> (pid, pidversion) of the first deletion seen
    evts = {}   # (label, path) -> the first deletion's own event time (ts)
    leaves = {}  # (label, path) -> target was a file or symlink
    for l, p, v, t, a, e, lf in buf:
        if (l, p) in seen: continue
        seen.add((l, p)); acts[(l, p)] = a; evts[(l, p)] = e; leaves[(l, p)] = lf
        by_label.setdefault(l, []).append((p, v, t))
    # Indexed, not rescanned: a 100k-file wipe must not stall the pipe until ES drops events.
    fold_ok = {}
    def beneath(p, pool):   # p lies under some path of pool
        k = p.find("/")
        while k >= 0:
            if p[:k] in pool: return True
            k = p.find("/", k + 1)
        return False
    for lbl, items in by_label.items():
        vias = dict((p, v) for p, v, _ in items)
        stamps = dict((p, t) for p, _, t in items)
        paths = [p for p, _, _ in items]
        idx = dict((p, i) for i, p in enumerate(paths))
        alive = [True] * len(paths)
        anc, desc = [], {}   # path index -> its foldable ancestors; foldable dir -> indexes beneath it, in order
        for i, p in enumerate(paths):
            ups, d = [], p
            while "/" in d and d != "/":
                d = d.rsplit("/", 1)[0]
                ok = fold_ok.get(d)
                if ok is None: ok = fold_ok[d] = foldable(d)
                if ok:
                    ups.append(d); desc.setdefault(d, []).append(i)
            anc.append(ups)
        count = dict((d, len(ix)) for d, ix in desc.items())
        head = dict.fromkeys(desc, 0)
        def first(d):
            ix, h = desc[d], head[d]
            while h < len(ix) and not alive[ix[h]]: h += 1
            head[d] = h
            return ix[h] if h < len(ix) else -1
        folds, blocked = [], set()
        # A true fold (>=3 siblings gone) unsafe to glob: a predating survivor would be taken by `rm -rf <dir>/*`.
        near_miss, _nm_seen = [], set()
        members = {}
        # Pass 1, repeated: the DEEPEST directory covering three or more of what is left summarises them;
        # on a tie, the most covered, then the one whose first remaining path came first.
        heap = [(-d.count("/"), -n, desc[d][0], d) for d, n in count.items() if n >= 3]
        heapq.heapify(heap)
        while heap:
            _, nn, fi, best = heapq.heappop(heap)
            if best in blocked or count[best] != -nn or first(best) != fi: continue   # stale entry
            covered = [paths[i] for i in desc[best] if alive[i]]
            _whole = best in idx and alive[idx[best]]
            if _whole: covered.append(best)
            # A dot-named direct child is not covered by `<dir>/*`.
            _dotted = set() if _whole else set(
                p for p in covered
                if p[len(best):].lstrip("/").split("/")[0].startswith("."))
            if _dotted:
                covered = [p for p in covered if p not in _dotted]
                if len(covered) < 3:
                    blocked.add(best); continue
            # Inspect first: a directory still holding files the app did not touch is not reported as emptied.
            state = dir_state(best, min(stamps[p] for p in covered))
            if state == "kept":
                blocked.add(best)
                _key = frozenset(covered)
                if _key not in _nm_seen:
                    _nm_seen.add(_key)
                    near_miss.append((best, covered))
                continue
            members[best] = set(covered)
            folds.append((best, len(covered), _whole, state == "empty"))
            touched = set()
            for p in covered:
                i = idx[p]; alive[i] = False
                for a in anc[i]:
                    count[a] -= 1; touched.add(a)
            for a in touched:
                if count[a] >= 3 and a not in blocked:
                    heapq.heappush(heap, (-a.count("/"), -count[a], first(a), a))
        # Pass 2: a deleted directory subsumes the paths beneath it.
        live = [p for i, p in enumerate(paths) if alive[i]]
        live_set = set(live)
        rest = [p for p in live if not beneath(p, live_set)]
        rest_set = set(rest)
        folds = [f for f in folds if f[0] not in rest_set and not beneath(f[0], rest_set)]
        fold_of = {}
        for f in folds:
            for q in members[f[0]]: fold_of[q] = f
        done = set()
        nm_dir, nm_n, nm_cov = {}, {}, {}
        for d, covered in near_miss:
            nm_n[d] = len(covered); nm_cov[d] = covered
            for p in covered:
                nm_dir.setdefault(p, d)
        nm_rest = {}
        for p in rest:
            if p in nm_dir: nm_rest.setdefault(nm_dir[p], []).append(p)
        nm_done, globbed = set(), set()
        for p in paths:
            if p in globbed: continue
            f = fold_of.get(p)
            if f:
                if f[0] in done: continue
                done.add(f[0])
                _v = set(vias[q] for q in members[f[0]])
                # One process behind the whole fold names it; several do not (`via` only when one).
                _a = set(acts[(lbl, q)] for q in members[f[0]])
                # ts = the FIRST event of the fold (ISO strings sort as times).
                _held = _EV_T
                _EV_T = min((evts[(lbl, q)] for q in members[f[0]] if evts[(lbl, q)]), default=None)
                try:
                    emit_wipe(lbl, f[0], f[1], _v.pop() if len(_v) == 1 else "", f[2], f[3],
                              actor=_a.pop() if len(_a) == 1 else None)
                finally: _EV_T = _held
            elif p in rest_set:
                d = nm_dir.get(p)
                if d and d not in nm_done:
                    nm_done.add(d)
                    g = None
                    if not NDJSON:
                        # Direct children only, never a dotfile (`*` skips it): a subfolder gets its own line.
                        mem = [q for q in nm_rest.get(d, ()) if q.rsplit("/", 1)[0] == d
                               and not q.rsplit("/", 1)[1].startswith(".")]
                        if len(mem) >= 3: g = near_miss_glob(d, [q.rsplit("/", 1)[1] for q in mem])
                    if g:
                        mset = set(mem); globbed.update(mset)
                        _v = set(vias[q] for q in mem)
                        _a = set(acts[(lbl, q)] for q in mem)
                        _held = _EV_T
                        _EV_T = min((evts[(lbl, q)] for q in mem if evts[(lbl, q)]), default=None)
                        try:
                            emit_glob(lbl, d, g[0], sum(1 for q in nm_cov[d] if q in mset or beneath(q, mset)),
                                      g[1], _v.pop() if len(_v) == 1 else "",
                                      not all(leaves[(lbl, q)] for q in mem),
                                      actor=_a.pop() if len(_a) == 1 else None)
                        finally: _EV_T = _held
                        _rest_n = len(nm_rest[d]) - len(mem)
                        if _rest_n and not SOLO:
                            out("C\t# NOTE: %d syscall deletions listed individually under %s — outside that glob"
                                % (_rest_n, inert_word(d)))
                    elif not NDJSON and not SOLO:
                        out("C\t# NOTE: %d syscall deletions listed individually under %s — "
                            "not folded, something there predates this run and a glob delete "
                            "would remove more than was observed"
                            % (nm_n[d], inert_word(d)))
                if p in globbed: continue
                _held = _EV_T
                _EV_T = evts[(lbl, p)]
                try: emit_file(lbl, "deleted", p, via=vias[p], actor=acts[(lbl, p)], leaf=leaves[(lbl, p)])
                finally: _EV_T = _held

def handle_delete(label, path, via="", actor=None, leaf=False, ppid=None):
    # --no-fold: every unlink exactly, no glob-fold, no tree-summary.
    if NOFOLD:
        emit_file(label, "deleted", path, via=via, actor=actor, leaf=leaf); return
    # A deletion a removal command already accounts for (its glob) folds into that command; otherwise it joins the syscall-deletion run.
    if not SHOW_NOISE and covered_by_wipe(label, path, time.time(), actor, ppid): return
    del_buf.append((label, path, via, time.time(), actor, _EV_T, leaf))

def payload_reads_stdin(toks):
    # A stage after `|` is fed by that pipe, which the line carries: only a pipeline's first stage reads outside input.
    first = True
    stage = []
    for t in list(toks) + [None]:
        if t is None or (isinstance(t, _Op) and t in _SEP_OPS):
            if stage and first and reads_stdin(stage[0].rsplit("/", 1)[-1], stage): return True
            stage = []
            first = not (isinstance(t, _Op) and t in ("|", "|&"))
        else: stage.append(t)
    return False

def reads_stdin(binary, args):
    # `xargs kill -9` is unusable alone: the PIDs came down a pipe no exec event records. A bare "-" argument is the same.
    if binary in ("xargs", "tee"): return True
    return "-" in args[1:]

_URLISH_RE = re.compile(r'^[a-zA-Z][a-zA-Z0-9+.-]*://')
_PATH_OPERAND_CMDS = _REMOVERS | _COPIERS | _PERM_CMDS | {"mkdir", "touch", "cat"}
def has_relative_path(args):
    # A relative path depends on the working directory; without it the line cannot replay. A bare word is a path only
    # where the command takes files (`rm build`), after `-o`, or as `.`/`..`: elsewhere it is a subcommand or a value.
    # A payload that `cd`s first resolves its own paths.
    if not args: return False
    cd = any(a in ("cd", "pushd") for a in args if not isinstance(a, _Op))
    b = args[0].rsplit("/", 1)[-1]
    skip = 1 if b in _PERM_CMDS else 0
    prev = ""
    for a in args[1:]:
        p, prev = prev, a
        if isinstance(a, _Op): continue
        if a.startswith(("/", "-", "~")): continue
        if _URLISH_RE.match(a): continue
        if "/" in a: return True
        if cd: continue
        if a in (".", "..") or p in ("-o", "--output"): return True
        if b in _PATH_OPERAND_CMDS:
            if skip and not p.startswith("-"):
                skip = 0; continue
            return True
    return False

# Plain word: shlex's safe set plus a leading `~` and glob characters; none can run anything, and a bare `~/`
# lets the report write the user's home, not the replaying shell's (root's under sudo).
_PLAIN_TOK_RE = re.compile(r'(?:~(?=/|\Z))?[\w@%+=:,./*?\[\]-]*\Z', re.ASCII)
def plain_payload(payload):
    try: toks = shlex.split(payload)
    except ValueError: return False
    return bool(toks) and all(t and _PLAIN_TOK_RE.match(t) for t in toks)

def argv0_differs(path, args):
    # argv[0] is whatever the caller chose; the executable is what ran. Silent for a login shell (`-zsh`), the python shim,
    # and a symlink whose target carries argv[0]'s name (`vi` -> `vim`).
    if not args or not path or not path.startswith("/"): return False
    a0 = args[0].rsplit("/", 1)[-1].lstrip("-")
    if not a0: return False
    a0 = dedup_name(a0).lower()
    if dedup_name(path).lower() == a0: return False
    # /bin/sh is a stub that re-execs the selected shell, argv[0] still `sh`.
    if a0 == "sh" and path.rsplit("/", 1)[-1] in ("bash", "zsh", "dash", "ksh"): return False
    try: return dedup_name(os.path.realpath(path)).lower() != a0
    except Exception: return True

def emit(label, path, args, via_helper=False, cwd="", pid=None, pidver=None):
    # Judged on both names: a `/bin/rm` run as `ls` is still a removal. Printed under the executable's.
    _orig = args
    _liar = argv0_differs(path, args)
    if _liar: args = [path] + list(args[1:])
    eff_path, eff_args, payload = effective(path, args)
    _jp, _ja = judged(eff_path, eff_args)
    # shlex.quote, not cmd_quote, for argv: execve tokens are post-expansion, so `*` is literal. A payload prints bare only as one
    # simple command of plain words that round-trips through the shell; anything else is printed as the quoted call.
    _show_payload = (payload and not _CTL_ANY_RE.search(payload)
                     and not shell_positional(path, args, payload)
                     and plain_payload(payload))
    _pw = shell_c_index(args) + 1 if payload else -1
    cmd = payload if _show_payload else (" ".join(shq(a, k == _pw) for k, a in enumerate(args)) if args else path)
    cmd = mdm_rewrite(cmd)
    # Dedup on a normalised form: `sh -c 'tmutil stopbackup'` and the `tmutil stopbackup` it becomes count once, as do a git shim
    # and the Xcode git it re-execs. A payload reading $1 is keyed on its whole call.
    if payload and shell_positional(path, args, payload):
        key = label + "\x00" + "\x00".join(args)
    elif payload:
        key = label + "\x00" + payload
    elif args:
        key = label + "\x00" + dedup_name(args[0]) + " " + " ".join(args[1:])
    else:
        key = label + "\x00" + path
    now = time.time()
    _binary = _jp.rsplit("/", 1)[-1]
    _gkey = (label, _binary)
    # What a removal covers, so its per-file unlink events fold into it.
    if _binary in _REMOVERS and not SHOW_NOISE:
        for _a in _ja[1:]:
            if _a.startswith("-"): continue
            _wp, _wg = wipe_prefix_of(_a)
            if _wp:
                wipe_prefixes.append([label, _wp, _wg, now, pid, pidver, None, None])
                wipe_pids.add(pid)
        if len(wipe_prefixes) > 4000:
            del wipe_prefixes[:2000]
            wipe_pids.clear()
            wipe_pids.update(w[4] for w in wipe_prefixes)
    # ...and what a file-placing command covers, so its clone/link/rename is not printed again.
    if _binary in _COPIERS and not SHOW_NOISE:
        _pd = placed_dest(_ja)
        if _pd: copy_dests.append((label, _canon(_pd), now))
        if len(copy_dests) > 4000: del copy_dests[:2000]
    # ...and the files a permission command names.
    if _binary in _PERM_CMDS and not SHOW_NOISE:
        for _a in _ja[1:]:
            if _a.startswith("/"): perm_targets.append((label, _canon(_a), now))
        if len(perm_targets) > 4000: del perm_targets[:2000]
    if not SHOW_NOISE:
        _prev = pending_glob.get(_gkey)
        if _prev and now - _prev[1] < _PENDING_GLOB_S:
            _paths = [a for a in _ja[1:] if a.startswith("/")]
            # An expansion carries FEWER patterns than its source, and no fewer paths.
            if (_paths and _prev[0] and glob_count(_ja) < _prev[3]
                    and len(_paths) >= _prev[4]
                    # Under one of the heads, not merely containing it (`/Library/Caches/com.evil.payload` is no expansion).
                    and all(any(x.startswith(p) for p in _prev[0])
                            for x in _paths)):
                def _tail(x):
                    p = max((p for p in _prev[0] if x.startswith(p)),
                            key=len, default="")
                    if not p: return x.rstrip("/").rsplit("/", 1)[-1]
                    # From the last component boundary in the prefix, so `CoreDuet*` expanding to `CoreDuetd` reads whole.
                    t = x[p.rfind("/") + 1:].lstrip("/")
                    return t or x.rstrip("/").rsplit("/", 1)[-1]
                _names = [inert_word(_tail(x)) for x in _paths]
                _shown = ", ".join(_names[:4])
                if len(_names) > 4: _shown += " +%d more" % (len(_names) - 4)
                # `~/Library/Safari` is not a pattern: a resolved home must not read as a glob that matched one file.
                if _prev[2]:
                    out("C\t# NOTE: the shell expanded that pattern to %d path%s: %s"
                        % (len(_paths), "" if len(_paths) == 1 else "s", _shown))
                else:
                    out("C\t# NOTE: the shell resolved that path to %s" % inert_word(_paths[0]))
                del pending_glob[_gkey]
                return
        if has_glob(_ja):
            pending_glob[_gkey] = (glob_dirs(_ja), now,
                                   any("*" in a or "?" in a for a in _ja[1:]),
                                   glob_count(_ja),
                                   len([a for a in _ja[1:] if a.startswith("/")]))
            if len(pending_glob) > 500: pending_glob.clear()
        if payload:
            # A positional template folds nothing (its `$` matches any word): only its resolved form does.
            if not shell_positional(path, args, payload):
                _remember_payload(label, payload, now)
            else:
                _rp = positional_text(path, args, payload)
                if _rp: _remember_payload(label, _rp, now)
        elif args:
            for _p, _pt in reversed(pending_shell.get(label, ())):
                if now - _pt >= _PENDING_SHELL_S: continue
                if payload_covers(_p, args) or payload_substitutes(_p, args): return
            # A non-shell wrapper folds nowhere (`disclaimer /bin/ps …` and the `/bin/ps …` it execs are one act): remember the inner line.
            _inner = payload_argv(path, args)
            if (len(_inner) > 1 and _inner[0].startswith("/") and _inner[0] != path
                    # The wrapper's own basename, not the judged one: `judged` peels to a NOISE script (`brew.sh`).
                    and path.rsplit("/", 1)[-1] not in _KNOWN_CMDS):
                _remember_payload(label, " ".join(shlex.quote(a) for a in _inner), now)
    if repeated(key, cmd, now): return
    _destr = bool(destructive_stage(eff_args))
    _net = network_stage(eff_args)
    # A command placing a file where software installs itself is what `⚠ persistence` catches: mark it.
    _persist = activation_stage(eff_args, eff_path)
    _secret = secret_stage(eff_args)
    _scoped = writes_system_scope(_jp, _ja) or writes_system_scope(eff_path, eff_args)
    if _liar:
        _op, _oa, _ = effective(path, _orig)
        _opj, _oaj = judged(_op, _oa)
        _destr = _destr or bool(destructive_stage(_oa))
        _net = _net or network_stage(_oa)
        _persist = _persist or activation_stage(_oa, _op)
        _secret = _secret or secret_stage(_oa)
        _scoped = _scoped or writes_system_scope(_opj, _oaj) or writes_system_scope(_op, _oa)
    _marks = []
    if _destr: _marks.append("⚠ destructive")
    if _net: _marks.append("⚠ network")
    if _persist: _marks.append("⚠ persistence")
    if _secret: _marks.append("⚠ secret")
    if _scoped: _marks.append("⚠ system scope")
    # --no-queries: after every fold registered this line (its payload still absorbs the pipeline stages that follow); never for a marked line.
    if NO_QUERIES and not _marks and is_query(payload or cmd, eff_args, bool(payload)):
        debug_filtered("%s (query)" % cmd)
        return
    _pipes = (payload_reads_stdin(eff_args) if payload else reads_stdin(eff_path.rsplit("/", 1)[-1], eff_args))
    _relative = bool(cwd) and has_relative_path(_ja)
    _notes = []
    if via_helper: _notes.append("⚠ run as root by a privileged helper — prefix with sudo")
    elif _scoped: _notes.append("⚠ writes outside what the user can write — prefix with sudo")
    if _pipes: _notes.append("⚠ reads a pipe — this line alone will not replay")
    if _relative: _notes.append("run from %s" % inert_word(cwd))
    _a0note = "argv[0] is %s, executable is %s" % (inert_word(_orig[0]), inert_word(path)) if _liar else ""
    if _a0note: _notes.append(_a0note)
    # Literal unless the line is a shell payload: an argv's `*` is a real filename character (see shq above),
    # and _report_form's cmd_quote would lift it out of the quotes.
    record(cmd, _destr, _net, note=" — ".join(_notes), pid=pid, persist=_persist,
           secret=_secret, literal=not _show_payload)
    mdm_header()
    if NDJSON:
        # via stays null: the actor IS the exec'd image the "app" field names; via is for emit_file/emit_perm.
        _x = {}
        if via_helper: _x["via_helper"] = True
        if _pipes: _x["stdin_pipe"] = True
        if _relative: _x["cwd"] = mdm_rewrite(cwd)
        json_out("exec", label, cmd, None, _marks, actor=(pid, pidver), extra=_x)
        return
    if SOLO:
        if _marks: out("C\t# " + " ".join(_marks))   # above the command, never after it
    else:
        out("C\t# %s ran:%s" % (inert_word(label), ("  " + "  ".join(_marks)) if _marks else ""))
    if _a0note: out("C\t# NOTE: " + _a0note)
    out("C\t%s" % cmd)
    # Reuse hint, once per helper.
    if via_helper and label not in helper_noted:
        helper_noted.add(label)
        out("C\t# NOTE: run by a privileged helper, so as root — prefix with sudo to reuse")
    if _scoped and not via_helper and label not in scope_noted:
        # Once per app.
        scope_noted.add(label)
        # Worded on the path, a fact, not on the actor: root is not in the exec event.
        out("C\t# NOTE: writes where the user cannot — prefix with sudo to reuse")
    if _pipes:
        out("C\t# NOTE: reads its input from a pipe — that input is not captured, so this line alone will not replay")
    if _relative:
        out("C\t# NOTE: run from %s — the relative paths above resolve against it" % inert_word(cwd))

# ============================================================================
# --debug
# ============================================================================
# Why is a command missing (`# FILTERED:`), why did an exec reach no actor (`# UNATTRIBUTED:`); `debug_dump` prints the JSON
# shape of the first events of each kind. All bounded, so the diagnostic never buries the output.

_filt_seen = {}
def debug_filtered(msg):
    if not DEBUG: return
    now = time.time()
    if msg in _filt_seen and now - _filt_seen[msg] < 30.0: return
    if len(_filt_seen) > TRACK_CAP: _filt_seen.clear()
    _filt_seen[msg] = now
    # `<command> (<reason>)`: the command through comment_cmd, the reason as a word.
    _head, _sep, _why = msg.rpartition(" (")
    if _sep and _why.endswith(")"):
        out("C\t# FILTERED: %s (%s)" % (comment_cmd(_head), inert_word(_why[:-1])))
    else:
        out("C\t# FILTERED: %s" % comment_cmd(msg))

_dbg_unattr = 0
def debug_unattributed(tgt, args):
    # --debug: an exec with no actor. Apple's own drop silently; third-party code with no actor is a gap an audit states.
    global _dbg_unattr
    if not DEBUG or not ALL_MODE or _dbg_unattr >= 40: return
    path = exe_path(tgt)
    if not path: return
    if is_platform(tgt) and not is_interpreter(path): return
    _dbg_unattr += 1
    out("C\t# UNATTRIBUTED: %s (no tracked ancestor, and no third-party actor to name)"
        % comment_cmd(" ".join(shq(a) for a in args) if args else path))

# The dump reveals a file event's SHAPE: which field holds the source, the destination directory, the new name.
_DBG_DROP = ("stat", "path_truncated")
def _shape_only(node, depth=0):
    if depth > 8 or not isinstance(node, dict): return node
    return dict((k, _shape_only(v, depth + 1))
                for k, v in node.items() if k not in _DBG_DROP)

# A dump is JSON on a `# DEBUG:` line. ASCII only (a lone surrogate cannot be UTF-8); `$`, backquote, `!` and `'` as \u escapes,
# so pasted double-quoted strings substitute nothing. A capped dump is cut outside a string, so quotes still pair.
_DBG_ESC = {ord("$"): "\\u0024", ord("`"): "\\u0060", ord("!"): "\\u0021", ord("'"): "\\u0027"}
def _dbg_json(obj, cap=0):
    s = json.dumps(obj, ensure_ascii=True).translate(_DBG_ESC)
    if not cap or len(s) <= cap: return s
    q = esc = False
    cut = 0
    for i, c in enumerate(s[:cap]):
        if esc: esc = False
        elif c == "\\": esc = True
        elif c == '"':
            q = not q
            if not q: cut = i + 1
        elif not q: cut = i + 1
    return s[:cut]

_dbg = 0
_dbg_file = {}        # event kind -> how many of its bodies have been dumped
_dbg_script = 0
def _node(d, key):
    # A top-level node of the event, or {}; never raises.
    if not isinstance(d, dict): return {}
    v = d.get(key)
    return v if isinstance(v, dict) else {}

def debug_dump(d):
    # Separate budgets: the far more frequent execs would use up a shared quota before any file event.
    global _dbg, _dbg_file, _dbg_script
    if not DEBUG: return
    ev = _node(d, "event")
    if not isinstance(ev.get("exec"), dict):
        for _k in ("unlink", "rename", "clone", "link", "setmode", "setowner", "setflags", "setacl", "deleteextattr", "open", "tcc_modify", "btm_launch_item_add", "btm_launch_item_remove"):
            if isinstance(ev.get(_k), dict):
                if _dbg_file.get(_k, 0) >= 2: return
                _dbg_file[_k] = _dbg_file.get(_k, 0) + 1
                out("D\t" + _dbg_json({"file_event": _k,
                                       "body": _shape_only(ev[_k]),
                                       "process_exe": exe_path(_node(d, "process"))}, 900))
                return
        return
    ex = ev.get("exec", {}) or {}
    # A script exec gets its own budget: a capture's first execs are boot plumbing.
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
    out("D\t" + _dbg_json(sample))   # see above: never lose the event to the dump

# ============================================================================
# SHUTDOWN AND THE MAIN LOOP
# ============================================================================
# SIGTERM renders what is held; SIGINT and SIGHUP are NOT handled here: the watcher inherits them ignored, so the orderly
# shutdown always runs. The loop walks file events first (no new image), execs second.

_stopping = False
def _on_term(signum, frame):
    global _stopping
    if _stopping: return
    _stopping = True
    try: flush_deletes()
    except Exception: pass
    # Reader gone mid-render: quiet, and the accumulator stays for the next --report.
    try: render_report()
    except BrokenPipeError: pass
    os._exit(0)
try: signal.signal(signal.SIGTERM, _on_term)
except Exception: pass

recover_report()   # print any report left unrendered by a previous reboot
_live = False
_parser_errors = set()   # exception types already reported (capped at 64)
while True:
    line = sys.stdin.readline()
    if not line: break
    line = line.strip()
    if not line: continue
    if not _live:
        # First event: proof the ES client is connected (`# watcher started` is written before eslogger speaks).
        _live = True
        raw_out("R\t# Culprit: capture is LIVE — eslogger is streaming, you can start the app now")
    # One event is one unit of work: an exception loses THIS event and nothing else.
    try:
        try:
            d = json.loads(line)
        except Exception:
            # Silent by design: eslogger's stream carries non-JSON noise.
            continue
        _EV_T = ev_time_iso(d)
        # isinstance: valid JSON need not be an object (a list has no `.get`).
        if _schema is None and isinstance(d, dict):
            _sv = d.get("schema_version")
            if _sv is not None: _schema = _sv
        ev = _node(d, "event")
        # Culprit's own directory reads (confirming a wipe) are dropped before anything else, debug included.
        if proc_pid(_node(d, "process")) == SELF_PID: continue
        debug_dump(d)
        ex = ev.get("exec")
        proc = _node(d, "process")

        if not isinstance(ex, dict):
            # File events carry no new image: attribute from the tracking exec already built, or the process being a known app.
            if isinstance(ev.get("exit"), dict):
                _xp = proc_pid(proc)
                if _xp is not None:
                    note_exit(_xp)
                    wipe_exit(_xp, proc_actor(proc)[1], time.time())
                    untrack(_xp, proc_actor(proc)[1])
                continue
            # A privacy grant/revoke is tccd's own process, not the app: attributed on identity/instigator, not `proc`.
            if isinstance(ev.get("tcc_modify"), dict):
                handle_tcc_modify(ev.get("tcc_modify"), proc)
                continue
            # A login item change is backgroundtaskmanagementd's own process, not the app: attributed on the item's path or instigator/app.
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
                # No third-party actor, but an install is reported on what it is (persistence_actor()).
                flabel = persistence_actor(ev, kind, proc)
            if flabel is None: continue
            # Who did it: the app's own image (no annotation), or a tool/helper it ran (lsregister, a privileged helper, a shell).
            _fact = proc_actor(proc)
            _fvia = exe_path(proc)
            # An Apple XPC service reading for the app is the system's UI (a file dialog listing), not the app looking around.
            if (not SHOW_NOISE and kind in ("readdir", "open")
                    and is_platform(proc) and ".xpc/Contents/MacOS/" in _fvia):
                debug_filtered("ls -la %s (system-xpc)" % (any_path(ev[kind].get("target")) or "?"))
                continue
            _fvia = _fvia.rsplit("/", 1)[-1] if _fvia and ".app/Contents/MacOS/" not in _fvia else ""
            # When the actor is the tool the line is written with, the command was already printed.
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
                # Which files the app read: what a readdir cannot give. The filtering after a readdir is invisible; the file then opened reveals the target.
                if not src: continue
                if not SHOW_NOISE:
                    # A directory open is the readdir already shown, not a file read; `.app` and other bundles are opened whole.
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
                # Enumerating a code bundle is the loader or a plugin scan: nothing to reproduce.
                if not SHOW_NOISE and any(x in src for x in _CODE_BUNDLES): continue
                if not SHOW_NOISE and ".app/" in src: continue
                # An app inventorying its own data is housekeeping; a scan of a tool directory (/usr/bin, /sbin…) is locating a binary.
                if not SHOW_NOISE:
                    _sp = APP_SCAN_NOISE.get(flabel)
                    if _sp and any(p in src for p in _sp):
                        debug_filtered("ls -la %s (app-scan)" % src)
                        continue
                    if any(src == d or src.startswith(d + "/") for d in _SCAN_NOISE_DIRS):
                        debug_filtered("ls -la %s (tool-dir)" % src)
                        continue
                if not SHOW_NOISE:
                    # A tree walk lists every level: one act, so only the top of the descent is reported.
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
                # A pty is session plumbing; its number never replays. Serial devices (/dev/tty.usbserial-…) are not matched.
                if not SHOW_NOISE and re.match(r"/dev/(ttys[0-9]+|[pt]ty[p-w][0-9a-f]|ptmx)$", _pc[2] or ""):
                    debug_filtered("%s (tty)" % _pc[0])
                    continue
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
                # System bookkeeping, never worth reproducing; `-v` lifts it like every noise rule.
                if not SHOW_NOISE and _xname in _XATTR_NOISE:
                    debug_filtered("%s (bookkeeping attribute)" % _xcmd)
                    continue
                # `xattr -d`/`-c` are not in DESTRUCTIVE (see its removal-tools comment), so an API deleteextattr never meets --destructive-only's bar alone.
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
            # A save is a temp renamed onto its name in one directory, or the old file moved aside to a temp first;
            # over a file the user cannot write (/etc/hosts) it is an act.
            _swap = atomic_write(src, dst) and (temp_name(src, dst) or temp_name(dst, src))
            _keep = _installs or (atomic_write(src, dst) and system_scope(dst))
            if not SHOW_NOISE and transient(src) and not _keep: continue
            if kind in _COPY_KINDS:
                # A copy with no readable destination reproduces nothing, and the destination decides persistence: dropped.
                if not dst: continue
                if not SHOW_NOISE and covered_by_copy(flabel, dst, time.time()): continue
                # Symmetric with rename: a same-directory copy from a temp name is churn.
                if not SHOW_NOISE and _swap and not _keep: continue
                flush_deletes()
                emit_file(flabel, "linked" if kind == "link" else "copied",
                          src, dst, via=_fvia, actor=_fact)
            elif kind == "rename":
                # Symmetric with the copy guard: no readable destination reproduces nothing and drops the `⚠ persistence` mark.
                if not dst:
                    degrade("rename: the destination could not be read")
                    continue
                if not SHOW_NOISE and covered_by_copy(flabel, dst, time.time()): continue
                if not SHOW_NOISE and _swap and not _keep: continue
                flush_deletes()
                # The temp is gone and its content was the app's: mv names the swap only. Persistence has its own note.
                _note = ("%s was replaced by a file the app wrote; mv replays the swap, not its content" % inert_word(dst)
                         if _swap and system_scope(dst) and not _installs else "")
                emit_file(flabel, "moved", src, dst, via=_fvia, actor=_fact, note=_note)
            else:
                # bash's here-document temp file (sh-thd-N), unlinked by the shell itself: not an act of the app.
                if (not SHOW_NOISE and re.match(r"(/private)?/(var/tmp|tmp|var/folders/[^/]+/[^/]+/T)/sh-thd[-.][A-Za-z0-9]+$", src)
                        and re.search(r"/(bash|sh|zsh|dash|ksh)$", exe_path(proc) or "")):
                    debug_filtered("rm %s (heredoc temp)" % src)
                    continue
                handle_delete(flabel, src, _fvia, _fact, unlink_is_leaf(body), _ppid)
            continue

        # An exec ends any run of syscall deletions: flush it first so the folded `rm -rf <tree>` prints right before this.
        flush_deletes()
        tgt = ex.get("target", {}) or {}

        apid = proc_pid(proc)
        try: ppid = int(proc.get("ppid")) if proc.get("ppid") is not None else None
        except Exception: ppid = None
        rtok = proc.get("responsible_audit_token")
        rpid = audit_pid(rtok) if rtok is not None else None
        tpid = proc_pid(tgt)

        tgt_path = exe_path(tgt)
        # Read argv before attributing: a shebang script execs its interpreter, so the actor's identity (brew, mackup, an MDM script) is only in there.
        args = exec_args(ex, tgt)
        # The script this exec really runs: macOS reports it (`brew list` is image /bin/bash with event.exec.script = /opt/homebrew/bin/brew),
        # absolute even for `sh ./build.sh`.
        if "script" in ex:
            # macOS reports the field, so its answer is final: empty means no script.
            tgt_script = third_party_script(any_path(ex.get("script")))
        else:
            tgt_script = script_image(tgt_path, args)

        seed = resolve_app(tgt, tgt_script)
        if seed is not None and tpid is not None and tpid not in tracked:
            track(tpid, seed, proc_actor(tgt)[1])

        label = None
        inherited = False
        for pp in (apid, ppid, rpid):
            if pp is not None and pp in tracked:
                label = tracked[pp]; inherited = True; break
        # Not yet tracked, but the ACTING process identifies itself (an app's or helper's first command): it is the actor and it CHOSE
        # this, which separates a command from an actor starting.
        if label is None:
            _actor = resolve_app(proc)
            if _actor is not None:
                label = _actor; inherited = True
        if label is None: label = seed
        if label is None:
            debug_unattributed(tgt, args)
            continue

        # Skip the app/helper's own image before propagating, or its launcher (launchd) would be tracked and pollute attribution.
        if not tgt_path: continue
        if is_app_image(tgt, inherited, tgt_script):
            # An app starting is not a command, but silence would hide an app that never shells out from one Culprit cannot see.
            _who = seed if seed is not None else label
            if not DESTRUCTIVE_ONLY and not ONLY_CMDS_SET and _who not in seen_apps:
                seen_apps.add(_who)
                out("C\t# %s started (pid %s)" % (inert_word(_who), tpid if tpid is not None else "?"))
            continue

        for pp in ((tpid,) if is_cli_launch(tgt_path, tgt_script) else (tpid, apid)):
            if pp is not None:
                track(pp, label, proc_actor(tgt if pp == tpid else proc)[1])

        _ep, _ea, _epl = effective(tgt_path, args)
        if ONLY_CMDS_SET:
            # An explicitly named command is shown even when the noise list would hide it.
            if judged(_ep, _ea)[0].rsplit("/", 1)[-1] not in ONLY_CMDS_SET: continue
        elif not SHOW_NOISE:
            _why = noise_reason(tgt_path, args, label)
            if _why:
                # --debug: say what was dropped and why; the command shown is the effective one (a shell-out's payload).
                if DEBUG:
                    # Quoted like the real output: joined raw, `cut -d' ' -f1` would read `cut -d  -f1`.
                    _fcmd = _epl if _epl else (
                        " ".join(shq(a) for a in _ea) if _ea else tgt_path)
                    debug_filtered("%s (%s)" % (_fcmd, _why))
                continue
        # An install that makes the machine come back (launch item, helper, /etc re-exec) changes it for good: kept like a removal.
        if DESTRUCTIVE_ONLY and not (destructive_stage(_ea) or activation_stage(_ea, _ep)): continue
        # Only a PrivilegedHelperTools binary is genuinely root; claiming it for Application Support would be a guess.
        emit(label, tgt_path, args, _PRIVILEGED_DIR in exe_path(proc),
             any_path(ex.get("cwd")), tpid, proc_actor(tgt)[1])
    except BrokenPipeError:
        # The watcher is gone (its stdout's reader left): nothing more can be shown.
        os._exit(0)
    except Exception as _exc:
        # Exception, not BaseException, so SIGTERM's own exit and a KeyboardInterrupt still stop the parser.
        _pk = type(_exc).__name__
        if _pk not in _parser_errors and len(_parser_errors) < 64:
            _parser_errors.add(_pk)
            _pe = "%s: %s" % (_pk, str(_exc)[:160])
            if DEBUG: out("D\tparser error, event skipped — %s" % inert_word(_pe))   # `# DEBUG: …`
            else: sys.stderr.write("culprit: parser error, event skipped — %s\n" % _pe)
        continue

# Stream drained: print the report if asked. _stopping first: _shutdown sends SIGTERM a few seconds in and the handler would render it twice.
_stopping = True
try:
    flush_deletes()
    render_report()
except BrokenPipeError:
    os._exit(0)   # as in _on_term
PY

# Parser argv, in order: debug, all-mode, destructive-only, show-noise, excludes-csv, cmd-filter, watch-files, watch-reads,
# watch-opens, then one argument per target (label\tteam\tbundle\thelpers\tcli).
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
  # 5th field (CLI paths) optional: with four fields `${x#*|}` returns the remainder whole, which would copy helpers into cli.
  if [[ "$_rest" == *"|"* ]]; then _helpers="${_rest%%|*}"; _cli="${_rest#*|}"
  else _helpers="$_rest"; _cli=""; fi
  _PARSER_ARGS+=("${_lbl}"$'\t'"${_team}"$'\t'"${_bundle}"$'\t'"${_helpers}"$'\t'"${_cli}")
done

# ---------------------------------------
# The watcher
# ---------------------------------------
cmd_watch() {
  trap '' INT HUP
  trap - PIPE
  # Keep eslogger's stderr: a refused ES client (too many clients, revoked entitlement) looks the same from here.
  local _errf="$CULPRIT_TMPDIR/eslogger.err"
  # `cat` keeps draining if logger dies: a dead reader would SIGPIPE the watcher.
  exec {_SYSLOG_FD}> >({ /usr/bin/logger -t "culprit" 2>/dev/null; /bin/cat > /dev/null; }) || unset _SYSLOG_FD
  # eslogger line-buffers on a pipe; the parser reads with readline() (-u) so sparse events are not stuck. --format json is pinned:
  # eslogger documents it only as "default: json".
  /usr/bin/eslogger --format json "${EVENT_TYPES[@]}" 2>"$_errf" \
    | "$PYTHON3_BIN" -I -u "$PARSER" "${_PARSER_ARGS[@]}" \
    | { while IFS=$'\t' read -r _k _v; do
        [ -n "$_k" ] || continue
        case "$_k" in
          C) log_line "Cmd: $_v" ;;
          D) log_line "Cmd: # DEBUG: $_v" ;;
          R) log_line "Cmd: $_v"
             : > "$CULPRIT_TMPDIR/live" 2>/dev/null || true
             # Tell a detaching parent the same (see the handshake there). Validated at startup (_detach_ready_ok); `>>` so it never truncates.
             [ -n "${CULPRIT_DETACH_READY:-}" ] && \
               { : >> "$CULPRIT_DETACH_READY"; } 2>/dev/null || true ;;
        esac
      done
      # The parser's last line is forwarded: _shutdown may now reap the pipeline.
      { : > "$CULPRIT_TMPDIR/drained"; } 2>/dev/null || true; } || true
  if [ -s "$_errf" ]; then
    # Marker for the main shell: a refused ES client kills the watcher at once.
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
  # Joined with ", ": labels with a space would blur. A label can be a bundle's name, so each goes through _inert_word.
  typeset -a _lbls=()
  for _t in "${TARGET_APPS[@]}"; do _lbls+=("$(_inert_word "${_t%%|*}")"); done
  _apps_summary="${(j:, :)_lbls}"
  unset _lbls
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
# --ndjson: this line and the advisories below print before the watcher exists, so they go to stderr and stdout carries JSON Lines from the first byte.
_say "# Culprit: watching [%s] — %s\n" "$(_inert "$_apps_summary")" "$_scope_summary"
if [ "$WATCH_OPENS" = "true" ] && [ "$ALL_MODE" = "true" ]; then
  printf "# culprit: WARNING: --opens in ALL mode is very high volume — target one app (e.g. sudo ./culprit.sh brew --opens)\n" >&2
fi
# Plain --report is silent: the report is the output, so the debug channel is suppressed with everything else.
if [ "$DEBUG" = "true" ] && [ "$REPORT" = "true" ] && [ "$NDJSON" != "true" ]; then
  printf "# culprit: WARNING: --debug prints nothing under --report — the report is the only output. Drop --report to see the JSON dumps and the FILTERED/UNATTRIBUTED lines\n" >&2
fi
# --exclude only reaches is_excluded() in ALL_MODE's match_target(), and -v lifts it with the noise list: either combination does nothing.
if [ -n "${EXCLUDE_EXTRA:-}" ]; then
  if [ "$ALL_MODE" != "true" ]; then
    printf "# culprit: WARNING: --exclude has no effect outside --all — a single-app run has nothing to exclude by\n" >&2
  elif [ "$ONLY_CMDS" = "false" ]; then
    printf "# culprit: WARNING: --exclude has no effect under -v — verbose lifts the same noise list --exclude feeds\n" >&2
  fi
fi
# --destructive-only already forces reads and directory scans off; --no-reads asks twice, and --no-files also turns off the file events it reports.
if [ "$DESTRUCTIVE_ONLY" = "true" ] && { [ "${READS_RAW:-}" = "false" ] || [ "${FILES_RAW:-}" = "false" ]; }; then
  if [ "${FILES_RAW:-}" = "false" ]; then
    printf "# culprit: WARNING: --no-files with --destructive-only also drops the deletions and moves it reports — --destructive-only already drops reads and directory scans on its own\n" >&2
  else
    printf "# culprit: WARNING: --no-reads with --destructive-only is redundant — --destructive-only already drops reads and directory scans on its own\n" >&2
  fi
fi
# --events asking for reads or opens is pointless under --destructive-only, which drops both.
if [ "$DESTRUCTIVE_ONLY" = "true" ] && [ "${_EVENTS_WANT_READS:-}" = "true" ]; then
  printf "# culprit: WARNING: --events asks for reads but --destructive-only drops it — neither modifies anything, so neither can qualify\n" >&2
fi
if [ "$DESTRUCTIVE_ONLY" = "true" ] && [ "${_EVENTS_WANT_OPENS:-}" = "true" ]; then
  printf "# culprit: WARNING: --events asks for opens but --destructive-only drops it — neither modifies anything, so neither can qualify\n" >&2
fi
# --cmd skips the noise check (see ONLY_CMDS_SET in the parser), so -v has nothing left to lift.
if [ -n "${CMD_FILTER:-}" ] && [ "$ONLY_CMDS" = "false" ]; then
  printf "# culprit: WARNING: -v with --cmd adds nothing — --cmd already shows the named commands regardless of the noise list -v would lift\n" >&2
fi

_fatal() { printf "# culprit: %s\n" "$(_inert "$1")" >&2; exit 1; }
[ "$(/usr/bin/id -u)" = "0" ] || _fatal "must run as root (sudo) — eslogger needs it."
[ -x /usr/bin/eslogger ] || _fatal "/usr/bin/eslogger not found — Culprit needs macOS 15 or later."
[ -n "$PYTHON3_BIN" ] || _fatal "python3 unavailable — run 'xcode-select --install' (or install via Homebrew)."
# Warns on macOS older than 15 (tested on 15 and later); never exits.
_os_support_note() {
  local v="$1" major="${1%%.*}"
  [[ "$major" == <-> ]] || return 0
  (( major < 15 )) || return 0
  printf "# culprit: WARNING: macOS %s is not supported — Culprit is tested on macOS 15 and later; a capture may be incomplete.\n" "$(_inert "$v")" >&2
  return 0
}
_os_support_note "$(/usr/bin/sw_vers -productVersion 2>/dev/null)"

# --detach: hand the prompt back and keep watching. Done HERE, after the prerequisites, so a missing sudo or python3 is reported to the person typing.
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
  # Resolve HERE, so the banner names the file that will be written and the child writes exactly that one.
  LOGFILE="$(_dry_logfile "$LOGFILE")" || _fatal "nowhere to write a log — pick a path with --log"
  export CULPRIT_LOGFILE_RESOLVED="$LOGFILE"
  _report_out_resolve
  # Inside CULPRIT_TMPDIR, which the EXIT trap owns.
  _detach_err="$CULPRIT_TMPDIR/detach.err"
  export CULPRIT_DETACH_READY="$CULPRIT_TMPDIR/detach.ready"
  # closerange: the child must not hold the caller's sockets or terminal fds for the whole run.
  # Through `/bin/zsh -f`, not the file itself: exec'ing it needs +x, and its shebang reads zsh's startup files (a `.zshenv` under
  # $ZDOTDIR or $HOME, run as root); -f reads none. The child re-reads the same argv from the caller's directory, so relative paths resolve.
  /usr/bin/nohup "$PYTHON3_BIN" -I -c \
    'import os,sys; os.chdir(sys.argv[1]); os.setsid(); os.closerange(3,256); os.execv("/bin/zsh", ["/bin/zsh", "-f"] + sys.argv[2:])' \
    "$_CULPRIT_CWD" "$_CULPRIT_SELF" "$@" >/dev/null 2>"$_detach_err" &
  _detached_pid=$!
  # Ctrl+C or TERM while waiting: the child would run on with nobody told its pid. HUP is left alone (a detached run outlives the terminal).
  trap '/bin/kill -TERM "$_detached_pid" 2>/dev/null; exit 130' INT
  trap '/bin/kill -TERM "$_detached_pid" 2>/dev/null; exit 143' TERM
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
  trap - INT TERM
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
# Before prepare_logfile rotates anything: a refused report path stops the run with the previous capture still where it was.
_report_out_resolve
_check_pid="${LOGFILE}.pid"
# The pid alone is not an identity (reboot, pid reuse): the process must also have started no later than the pidfile was written.
_live_capture() {
  local f="$1" p s m
  [ -f "$f" ] || return 1
  p=$(/bin/cat "$f" 2>/dev/null) || p=""
  [[ "$p" == <-> ]] || return 1
  case "$(/bin/ps -o comm=,args= -p "$p" 2>/dev/null)" in
    *zsh*culprit*.sh*) : ;;
    *) return 1 ;;
  esac
  /bin/kill -0 "$p" 2>/dev/null || return 1
  s=$(LC_ALL=C /bin/ps -o lstart= -p "$p" 2>/dev/null) || s=""
  s=$(LC_ALL=C /bin/date -j -f '%a %b %e %T %Y' "${s%%[[:space:]]#}" +%s 2>/dev/null) || s=""
  m=$(/usr/bin/stat -f %m "$f" 2>/dev/null) || m=""
  [[ "$s" == <-> && "$m" == <-> ]] || return 1
  [ "$s" -le $((m + 1)) ] || return 1
  print -r -- "$p"
}
_refuse_second() {
  printf '# culprit: a capture is already writing to %s (pid %s)\n' "$(_inert "$LOGFILE")" "$1" >&2
  printf '#   stop it first:   sudo kill %s\n' "$1" >&2
  printf '#   or give this one its own file:   --log /var/log/culprit-2.log\n' >&2
  exit 1
}
_prev_pid=""
if _prev_pid=$(_live_capture "$_check_pid"); then
  _refuse_second "$_prev_pid"
fi
_prev_pid="$(/bin/cat "$_check_pid" 2>/dev/null)" || _prev_pid=""
LOGFILE="$(prepare_logfile "$LOGFILE")" || _fatal "could not open a log file at $LOGFILE"
_open_log_fd || _fatal "could not open the log safely (link, not a plain file, or not ours): $LOGFILE"
_PIDFILE="${LOGFILE}.pid"
# The log path is guarded; the pidfile beside it in the same world-writable directory is guarded the same way.
if [ -h "$_PIDFILE" ] || { [ -e "$_PIDFILE" ] && { [ ! -f "$_PIDFILE" ] || [ ! -O "$_PIDFILE" ]; }; }; then
  printf '# culprit: refusing to write a pidfile that is a link or not ours: %s\n' "$(_inert "$_PIDFILE")" >&2
  _PIDFILE=""
else
  # Drop only the stale pidfile just read, never a rival's fresh one. Complete file by O_EXCL, then link(2) it in: exactly one starter wins, and a reader never sees it half written.
  [ -f "$_PIDFILE" ] && [ "$(/bin/cat "$_PIDFILE" 2>/dev/null)" = "$_prev_pid" ] && /bin/rm -f "$_PIDFILE" 2>/dev/null
  if ! ( umask 077; set -C; printf '%s' "$$" > "${_PIDFILE}.$$" && /bin/ln "${_PIDFILE}.$$" "$_PIDFILE"; _r=$?; /bin/rm -f "${_PIDFILE}.$$"; exit $_r ) 2>/dev/null; then
    # The loser must not remove the winner's pidfile on exit.
    _prev_pid=$(_live_capture "$_PIDFILE") && { _PIDFILE=""; _refuse_second "$_prev_pid"; }
    _PIDFILE=""
  fi
fi
_say "# Culprit: logging to %s\n" "$(_inert "$LOGFILE")"
[ -s "${LOGFILE}.1" ] && _say "# Culprit: previous capture kept as %s.1\n" "$(_inert "$LOGFILE")"
if [ "$LOGFILE" != "$_LOG_WANTED" ]; then
  printf "# culprit: WARNING: could not write %s — logging to %s instead\n" "$(_inert "$_LOG_WANTED")" "$(_inert "$LOGFILE")" >&2
fi
# --report accumulator, beside the resolved log so it survives a reboot in the same /var/log. Only meaningful in --report mode.
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

# Traps go up before the watcher is forked: a signal in between would have no handler, and on zsh INT and HUP still run the EXIT trap, which removes CULPRIT_TMPDIR.
_kill_tree() {
  local _root=$1 _sig="${2:-TERM}" _kid _kids
  [ -n "$_root" ] || return 0
  # pgrep exits 1 when a process has no children (a leaf, not an error); inline in the `for` list it would trip TRAPZERR.
  _kids=$(/usr/bin/pgrep -P "$_root" 2>/dev/null) || _kids=""
  for _kid in ${=_kids}; do _kill_tree "$_kid" "$_sig"; done
  kill -"$_sig" "$_root" 2>/dev/null || true
}
# The pipeline outlives a watcher killed by SIGPIPE; the tmpdir (pid file, parser path) must outlive it.
_reap_pipeline() {
  local _p _sig="${1:-TERM}" _pat="${CULPRIT_TMPDIR//./\\.}/parser\\.py"
  if [ -s "$CULPRIT_TMPDIR/pids" ]; then
    while IFS= read -r _p; do
      [ -n "$_p" ] || continue
      case "$(/bin/ps -o comm= -p "$_p" 2>/dev/null)" in *eslogger*) kill -"$_sig" "$_p" 2>/dev/null || true ;; esac
    done < "$CULPRIT_TMPDIR/pids"
  fi
  /usr/bin/pkill -"$_sig" -f "$_pat" 2>/dev/null || true
}
_pipeline_alive() {
  local _p
  [ -n "${WATCH_PID:-}" ] && kill -0 "$WATCH_PID" 2>/dev/null && return 0
  /usr/bin/pgrep -f "${CULPRIT_TMPDIR//./\\.}/parser\\.py" >/dev/null 2>&1 && return 0
  [ -s "$CULPRIT_TMPDIR/pids" ] || return 1
  while IFS= read -r _p; do
    [ -n "$_p" ] || continue
    case "$(/bin/ps -o comm= -p "$_p" 2>/dev/null)" in *eslogger*) return 0 ;; esac
  done < "$CULPRIT_TMPDIR/pids"
  return 1
}
# The first stop decides the exit code and the cleanup runs to the end: a second signal (a 2nd Ctrl+C, the --duration timer) returns at once.
_stop() {
  [ -z "${_STOP_RC:-}" ] || return 0
  _STOP_RC=$2
  _shutdown "$1"
  exit "$_STOP_RC"
}
_signal_eslogger() {
  local _kid _kids
  _kids=$(/usr/bin/pgrep -P "${WATCH_PID:-0}" 2>/dev/null) || _kids=""
  for _kid in ${=_kids}; do
    case "$(/bin/ps -o comm= -p "$_kid" 2>/dev/null)" in
      *eslogger*) kill -"$1" "$_kid" 2>/dev/null || true ;;
    esac
  done
}
_shutdown() {
  local _waited=0 _max="${1:-20}"
  # --report renders on EOF and a big one takes longer than a plain flush: as long as TERM's budget on every path.
  if [ "$REPORT" = "true" ] && [ "$_max" -lt 50 ]; then _max=50; fi
  _signal_eslogger TERM
  # Bounded by the caller's own budget (2s on Ctrl+C, 5s on SIGTERM): a stuck parser must not hold the shutdown open past it.
  while [ "$_waited" -lt "$_max" ] && [ -n "${WATCH_PID:-}" ] && kill -0 "$WATCH_PID" 2>/dev/null; do
    /bin/sleep 0.1 || true; _waited=$((_waited + 1))
  done
  # --report past the budget: the watcher is the report's only reader, so it stays until the last line is forwarded
  # (`drained`), up to 120 s. A parser still waiting for input renders on TERM; one already rendering ignores it.
  if [ "$REPORT" = "true" ] && [ -n "${WATCH_PID:-}" ] && kill -0 "$WATCH_PID" 2>/dev/null && [ ! -f "$CULPRIT_TMPDIR/drained" ]; then
    # Inside the INT trap a 2nd Ctrl+C reaches only a trap set anew.
    _REPORT_CUT=""; trap '_REPORT_CUT=1' INT
    printf '# culprit: writing the report… (Ctrl+C again cuts it short; its records are then kept for the next --report)\n' >&${_ERR_FD:-2}
    _signal_eslogger KILL
    /usr/bin/pkill -TERM -f "${CULPRIT_TMPDIR//./\\.}/parser\\.py" 2>/dev/null || true
    _waited=0
    while [ "$_waited" -lt 1200 ] && [ -z "$_REPORT_CUT" ] && kill -0 "$WATCH_PID" 2>/dev/null && [ ! -f "$CULPRIT_TMPDIR/drained" ]; do
      /bin/sleep 0.1 || true; _waited=$((_waited + 1))
    done
  fi
  _kill_tree "${_TIMER_PID:-}"
  _kill_tree "${WATCH_PID:-}"
  _reap_pipeline
  # A child that ignores TERM would hold `wait` forever: one second of grace, then KILL, on our own recorded pids and parser path only.
  _waited=0
  while [ "$_waited" -lt 10 ] && _pipeline_alive; do
    /bin/sleep 0.1 || true; _waited=$((_waited + 1))
  done
  if _pipeline_alive; then
    _kill_tree "${WATCH_PID:-}" KILL
    _reap_pipeline KILL
  fi
  wait ${WATCH_PID:-} 2>/dev/null || true
  # A finished render removes the accumulator; one still there is a report cut short.
  if [ "$REPORT" = "true" ] && [ -s "${CULPRIT_REPORT_FILE:-}" ]; then
    printf '# culprit: the report was cut short; its records stay in %s and the next --report run prints them\n' "$(_inert "$CULPRIT_REPORT_FILE")" >&${_ERR_FD:-2}
  fi
  /bin/rm -f "${_PIDFILE:-}" 2>/dev/null || true
  /bin/rm -rf "$CULPRIT_TMPDIR" 2>/dev/null || true
}
trap '_stop 50 143' TERM
trap '_stop 20 130' INT
# stdout's reader is gone (`| head`): stop cleanly instead of dying untrapped with the root eslogger still running.
trap '_stop 20 141' PIPE USR2
# A detached run must outlive the terminal (and the app that quits it), so it ignores SIGHUP; nohup already does.
if [ "$DETACH" = "true" ]; then
  trap '' HUP
else
  trap '_stop 20 129' HUP
fi

_T0=$(/bin/date +%s)
cmd_watch &
WATCH_PID=$!
# A stop trap runs inside `wait … 2>/dev/null`: its notes go to this copy of stderr. After the fork, so the pipeline has none.
exec {_ERR_FD}>&2
# A capture that stops itself. USR1 rather than TERM: a planned stop is a SUCCESS, the handler exits 0, where TERM exits 143 and a Jamf policy would read its own duration limit as a failure.
if [ -n "${DURATION:-}" ]; then
  trap '_stop 50 0' USR1
  ( _n=0
    while [ "$_n" -lt "$DURATION" ]; do
      /bin/sleep 1
      /bin/kill -0 $$ 2>/dev/null || exit 0
      _n=$(( _n + 1 ))
    done
    # The marker says the LIMIT ended this run. Written before the signal, since the handler exits and never comes back here.
    : > "$CULPRIT_TMPDIR/duration_fired" 2>/dev/null || true
    # Re-checked: a whole second separates the last loop check from the signal.
    /bin/kill -0 $$ 2>/dev/null || exit 0
    /bin/kill -USR1 $$ 2>/dev/null ) &
  _TIMER_PID=$!
fi
# Announced AFTER the fork: it describes a running capture. A detached run has no terminal.
[ "$DETACH" = "true" ] || \
  _say "# Culprit: watching — Ctrl+C to stop. Follow live: tail -f %s\n" "$(_inert "$LOGFILE")"
# Log the watcher too: when a capture stops short, the log must say how far startup got and which processes to look for.
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


# Run until stopped: Ctrl+C / SIGTERM ends it (detach is stopped with `kill <pid>`, as its banner said).
_wrc=0; wait "$WATCH_PID" 2>/dev/null || _wrc=$?
_reap_pipeline
# 141: the watcher died of SIGPIPE, stdout's reader is gone (`| head`), not eslogger.
[ "$_wrc" = 141 ] && { _stdout_gone; _stop 20 141; }
# Reaching here means the WATCHER ended, not the limit: the --duration handler exits from its own trap.
if [ -n "${DURATION:-}" ] && [ ! -f "$CULPRIT_TMPDIR/duration_fired" ]; then
  _ran=$(( $(/bin/date +%s) - ${_T0:-0} ))
  log_line "Cmd: # culprit: WARNING: the capture ended by itself after ${_ran}s of the ${DURATION}s asked for — eslogger stopped; this report covers only that much"
fi
if [ -f "$CULPRIT_TMPDIR/eslogger.stderr" ] && [ ! -f "$CULPRIT_TMPDIR/live" ]; then
  printf '# culprit: eslogger produced no events and reported an error — see %s\n' "$(_inert "$LOGFILE")" >&2
  exit 1
fi
# A requested stop exits from its trap; reaching here, the capture died alone.
printf '# culprit: the capture stopped by itself (eslogger exited) — see %s\n' "$(_inert "$LOGFILE")" >&2
exit 2
