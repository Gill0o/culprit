# Security Policy

Culprit runs as root and observes third-party software on macOS. It never runs, blocks or modifies
anything it watches; what it collects goes to its log file and to the unified log (see the README's
Security section).

## Supported versions

Only the **latest release** is supported. Fixes ship in the next release; there is no backport to an
older version.

| Version | Supported |
|---|---|
| 1.0.2 (latest) | yes |
| < 1.0.2 | no |

## Reporting a vulnerability

Report privately — not in a public issue:

- **Email**: <gbonpain@capside.fr>, or
- **GitHub**: private vulnerability reporting, from this repository's Security tab.

Include, where you can:

- The version (`# Version:` header of `culprit.sh`, or the release tag).
- macOS version and whether the issue needs root / Full Disk Access to trigger.
- Steps to reproduce, or the `eslogger` JSON that triggers it (`--debug` output). Review a capture
  before sharing it: a `⚠ secret` line is paste-ready and should not be included as-is.
- What you expected versus what happened.

Expect an acknowledgement within a few days. Culprit is a single-maintainer project without a
disclosure SLA, but every report gets a reply.

## Scope

In scope: `culprit.sh` itself, and the scripts it generates (the `--report` output, its embedded
reproducible script, and any file it writes — log, `.1` rotation, `.report`, pidfile).

Out of scope: the behaviour of software Culprit *observes* — Culprit reports what a third-party app
did, it does not vet it. A finding about what an observed app does is not a Culprit vulnerability.
