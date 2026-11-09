# Versioning

[Home](../README.md) · [Running sessions](running-sessions.md)

HARP uses `MAJOR.MINOR.PATCH` release numbers. `harp_version.py` is the single source for the installed release version. The command center reads that value through `/api/state`, the CLI prints it with `python harp.py --version`, and new session records include it as `harp_version`.

Increase PATCH for compatible fixes, MINOR for new compatible features, and MAJOR when a change requires migration or intentionally breaks an interface. For a release, update `harp_version.py` and `CHANGELOG.md` together. Older session records without `harp_version` remain readable.

Portable session ZIPs have a separate `format_version` in `harp-session.json`. This is currently `1`; a HARP software release does not require an archive format change. Change the archive format version only when the import contract changes incompatibly, and provide migration support before removing a supported format. The importer rejects unknown formats with an error instead of guessing.
