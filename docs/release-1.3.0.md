# Sentinel AV 1.3.0 — continuous scanning preview

## Shipped

- Persistent loopback ClamAV daemon with streaming scans, durable file-change queue, write settling, restart recovery and bounded concurrency.
- Downloads/Temp defaults and executable/script/archive filtering; CPU, memory, battery, idle, queue, file-size and pause controls.
- Hash-bound automatic quarantine for confirmed ClamAV threats, durable alerts and confirmed restore/recovery actions.
- Optional YARA-X community rules, Radare2 PE review and local osquery behavior snapshots. Heuristic/community matches remain review-only.
- Bundled pinned, SHA-256-verified engines and dependencies. Debug symbols, import libraries and the unused osquery daemon are excluded.
- Desktop-owned shutdown by default, an explicit continue-running option and an optional Windows service host.

Enable monitoring and optional detection layers in Settings after updating official ClamAV definitions. These are opt-in features; installing an upgrade alone does not turn them on.

## Validation

158 unit tests passed, plus the full Electron smoke suite with official definitions, real ClamAV exit-code checks, watcher/daemon integration, host-crash cleanup, automatic quarantine/restart/restore, actual YARA/Radare2/osquery checks and community-feed compilation/activation. Synthetic detection fixtures are harmless and do not measure malware coverage.

## Explicit limitations

This is an **unsigned preview**, not a certified antivirus replacement. It does not provide kernel execution prevention, active ETW collection or Windows Security Center registration. Experimental minifilter source is excluded from the installer and is not deployed. Production kernel work requires a native broker, complete identity/write/mapping safeguards, disposable-VM testing and Microsoft signing. No publisher signing certificate was available.

No “60%” baseline or improved detection percentage has been established. YARA works on file/container bytes; archive extraction remains ClamAV's responsibility. Behavior snapshots can miss short-lived activity. Clean-machine installation, actual SCM boot/logon and laptop power transitions still need deployment validation. Keep the primary antivirus enabled; no Defender exclusions or disabling are performed.

The release includes the rebuilt installer, SHA-256 checksums and unmodified corresponding source archives for bundled GPL/LGPL tools. See the repository README and `THIRD-PARTY-NOTICES.md` for component versions, licenses and setup instructions.
