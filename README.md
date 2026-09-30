# Sentinel AV · Clam Desktop

A Windows desktop companion for the open-source [ClamAV](https://www.clamav.net) antivirus engine. It sets up ClamAV for you, keeps its malware definitions up to date, runs daily and weekly scans on a schedule, and gives you a clear place to review and quarantine anything it finds.

![Sentinel AV dashboard](assets/dashboard.png)

## Download for Windows

**[Download Sentinel AV 1.3.0 for Windows (x64)](https://github.com/amosroger91/Clam-Desktop/releases/download/v1.3.0/Sentinel-AV-Setup-1.3.0.exe)** · [release notes and checksum](https://github.com/amosroger91/Clam-Desktop/releases/tag/v1.3.0) · [all releases](https://github.com/amosroger91/Clam-Desktop/releases)

- Windows 10 or 11, 64-bit. No administrator rights needed; it installs for your user account only.
- **This is an unsigned preview release.** Compare the installer's SHA-256 with the release checksum (`Get-FileHash .\Sentinel-AV-Setup-1.3.0.exe`). No certificate or SmartScreen reputation is implied.
- ClamAV, YARA-X, Radare2 and osquery are bundled from pinned, SHA-256-verified upstream releases. Open Settings and update definitions before scanning. Enable **Monitor file changes**, save, and optionally enable YARA, static analysis or local behavior snapshots. Downloads and user/system Temp are the default watched locations. Missing/inaccessible locations appear as issues.
- Upgrading from an earlier version keeps your settings, schedules, scan history, detections, and quarantined files.

## What it does

- **Continuous scanning (opt-in):** watches selected folders, queues new/changed files, and scans them through a persistent ClamAV engine. Includes CPU/memory policies, battery and idle controls, timed pauses, backlog/latency statistics, immediate detection alerts, and an optional Windows service. See [continuous scanning and resource management](docs/continuous-scanning.md).
- **Scheduled scans:** a daily **quick scan** (Desktop, Downloads, Documents, and your temporary folder, including folders Windows has redirected) and a weekly **full scan** of all local fixed drives. You can change the day, time, and frequency, or pause either one. A **custom scan** checks any folder you choose.
- **Definitions kept current:** checks for new ClamAV definitions hourly, verifies each database file's digital signature with ClamAV's `sigtool`, and warns when definitions are older than the threshold you choose (3 days by default).
- **An honest dashboard:** the Overview shows "All checks passed" only when a schedule is on, the definitions are current and verified, and your last scan completed. Otherwise it says what needs attention and offers the next useful action. The same status appears in the tray and in the window header.
- **Automatic quarantine:** when monitoring is enabled, confirmed ClamAV threats are moved into an isolated application vault by default. Disable this separately in Settings. PUA, heuristic, YARA and structural matches always require review. Files are identified by the SHA-256 of the bytes streamed to ClamAV before quarantine acts.
- **Additional detection layers (opt-in):** YARA-X scans with a curated, versioned Signature Base subset; Radare2 inspects PE sections/imports; osquery takes local process/connection snapshots once per minute and highlights Office-launched interpreters. These add evidence, not a demonstrated detection percentage. Packing or unusual imports alone do not prove malware.
- **Careful quarantine and restore:** quarantine confirms it is moving the same file that was detected, and restore never overwrites an existing file (you can restore to another location instead).
- **Runs in the background:** closing the window keeps Sentinel in the system tray so schedules keep running, and it can start at Windows sign-in.

Sentinel provides **scheduled, on-demand, and optional continuous file-change scanning**. It is not a production execution-blocking driver, a firewall, or a registered Windows Security provider. Keep your primary antivirus enabled. Monitoring stops on normal application quit unless **Continue after quitting Sentinel** or the optional Windows service is used. Desktop notifications are delivered while it is running or when it reconnects. Scheduled scans require the desktop scheduler. Nothing runs while the computer is off. File-size, archive and scan-time limits apply; skipped/error results are not clean verdicts.

## How it keeps your data safe

- **Scans are journaled.** Each detection is written to a durable journal the moment ClamAV reports it. If Sentinel, Windows, or the power fails mid-scan, the next start records the scan as interrupted and keeps every detection it had already found.
- **Scheduled scans are not silently skipped.** A due scan stays owed until it succeeds. Failures retry after 15 minutes, backing off to every 6 hours, and the Schedules page shows the next attempt. Cancelling a scan yourself does not trigger a surprise rescan. When both scans are due, the full scan runs first, and it counts for the quick scan only if its results show the quick-scan folders were actually checked.
- **Quarantine never deletes the only copy.** Files are hashed before and after being moved. If anything changes along the way, or Sentinel is interrupted, every copy is kept and the item appears under **Quarantine** for you to finish, undo, recheck, or mark reviewed.
- **Settings and history survive damage.** Data files are versioned and written atomically, with a verified backup of the previous version. A damaged file is set aside for diagnosis and reported in Settings instead of being silently reset, and a file from a newer version of Sentinel is left untouched.
- **Faults stop safely.** If Sentinel hits an internal error it stops making changes, saves diagnostics, and exits; the next start recovers and tells you what happened.

## Privacy

Scanned files and behavior observations stay on your computer. No file upload or remote analytics is performed. Network requests download official ClamAV definitions/engines and, when YARA is enabled, selected rules and revision metadata from GitHub's Signature Base repository. Build-time tooling downloads the pinned analysis binaries. Optional behavior snapshots omit command-line arguments, keep only bounded summaries in memory and do not claim to detect process injection or every short-lived process. Profile data lives in `%APPDATA%\sentinel-av`; background records and automatic quarantine live under `monitor`. Quarantine is isolated and renamed, not encrypted or resistant to an administrator modifying it. Bundled engines live alongside the app. The profile is excluded from scanning.

## Build from source

Requires Windows 10/11 and Node.js 22.12 or later.

```powershell
npm ci
npm start          # run the app
npm run dist       # build release\Sentinel-AV-Setup-<version>.exe
```

## Tests

```powershell
npm run format:check
npm test                  # unit tests
npm run test:smoke        # Electron smoke scenarios
npm run test:integration  # real ClamAV exit-code checks (needs prepared fixtures)
npm run test:monitor      # real daemon, watcher, restart, automatic quarantine/restore
node scripts/test-layers.cjs # actual YARA, Radare2, osquery and feed activation
```

- **`npm test`** covers the scheduler with a controllable clock, quarantine recovery with a simulated crash at every step and injected file mutations, persistence migration with a restart after every saved file, the scan journal and its idempotent replay, the operation conflict matrix, coverage evidence, the health/capability matrix, the scanner adapter with a fake process, and the fatal-fault policy.
- **`npm run test:smoke`** launches the real app several times:
  - a standard run covering screens, IPC validation, the unsaved-changes guard, and a verified healthy state;
  - a launch that exits abruptly after a detection is journaled, then a launch that must recover it;
  - an uncaught fault that must exit nonzero with diagnostics;
  - a deliberately failing run, which proves failures are reported.

  The real-engine parts run when `test-output\engine-path.txt` and a downloaded database (`test-output\database\main.cvd`) are present, and are skipped with a visible note otherwise. They use harmless synthetic signatures, never real malware.

The renderer is sandboxed with context isolation and a restrictive content security policy. Privileged work stays in the main process behind a sender-validated IPC bridge, processes are started with argument arrays rather than shell strings, and scan targets must be absolute paths.

## Project status

Version 1.3.0 adds persistent scanning, resource policies, automatic quarantine, optional multi-engine analysis and bundled tools. The previous engineering review remains at [CLAUDE_10X_QUALITY_REVIEW.md](CLAUDE_10X_QUALITY_REVIEW.md).

**Not complete:** production kernel interception and its native broker, Microsoft driver signing/HLK validation, publisher signing, Windows Security Center enrollment, ETW event collection, automatic application updates and clean-machine/SCM boot testing. An isolated [experimental execute-open minifilter source](driver/README.md) is excluded from the installer; it is not advertised as active protection. [Windows trust and signing](docs/windows-trust.md) explains the real prerequisites. The community “60%” claim has not been independently established; this release makes no coverage-rate claim.

Third-party tools and rules retain their own licenses; see [notices and corresponding source](THIRD-PARTY-NOTICES.md). Sentinel is not affiliated with their maintainers. Sentinel's original application code is MIT-licensed (see [LICENSE](LICENSE)).
