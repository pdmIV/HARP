# Changelog

## Unreleased

- Add the `harp-ai` installable Python distribution and terminal launcher, bundled dashboard/setup resources, persistent per-user installed data, and Kali dependency setup through `harp-ai deps`.
- Add Linux/Windows package validation and a GitHub release workflow for PyPI Trusted Publishing after repository/PyPI setup.

- Prioritize a bounded user-flag read after verified user-level access, before escalation or authorized pivots, without assuming both flags share a host. Supply live verified flag status to every proxy request.
- Scale model read timeouts with the effective reasoning effort: 4 minutes for low/default, 6 for medium, 10 for high, and 20 for max/xhigh, including adaptive oracle changes.
- Accept unused nullable oracle fields without format retries, while retaining type validation for executable commands.
- Stream Z.AI completions to accommodate long reasoning and automatically retry oracle read timeouts or interrupted connections twice within the same cycle. Reject incomplete streams and log unknown interrupted-request usage.
- Remove command and implementation character caps. Support complete multiline scripts through stdin transport in Kali WSL, native Kali and Docker, with complete syntax checks and exact root approvals.
- Require English model-authored prose in proxy and hosted-oracle prompts, including format retries, while preserving exact evidence and executable content.
- Restored live dashboard orbits and success-dismissal confetti when Windows animations are disabled. Added a shared On / Follow system setting / Off interface preference for live motion, replay and confetti, including settings backups.
- Recognize terminal control sequences and separately echoed flag reads in Evil-WinRM transcripts, including both flags from one session, and stop automatically on verified captures.
- Request Z.AI JSON output for oracle and proxy calls. Retry invalid oracle decisions twice with validation feedback and full usage accounting before stopping.
- Reject mixed proxy file/command actions before execution and allow bounded format correction.
- Include the exact Kali workspace and recent Whippet query history in model context. Allow correction of rejected capture paths while retaining fatal transport stops and explicit refresh requirements.
- Preserve structured Whippet reports behind shell setup commands and reuse identical successful managed queries against an unchanged capture snapshot.

## 0.5.0 - 2026-11-08

- Designated the current feature set as a research alpha milestone.
- Updated the shared release version used by the CLI, command center Overview, and new session records.
- Retained portable session archive format version 1.

## 0.1.0 — 2026-11-08

- Established a single release version for the CLI, command center, and new session records.
- Added portable ZIP export and import for completed sessions, including logs and captured evidence.
- Added the Overview Harp wordmark and version display.
