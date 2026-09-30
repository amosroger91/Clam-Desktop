# Sentinel AV · Clam Desktop

A Windows desktop companion for the open-source [ClamAV](https://www.clamav.net) antivirus engine. It sets up ClamAV for you, keeps its malware definitions up to date, runs daily and weekly scans on a schedule, and gives you a clear place to review and quarantine anything it finds.

![Sentinel AV dashboard](assets/dashboard.png)

## Download for Windows

**[Download Sentinel AV 1.2.0 for Windows (x64)](https://github.com/amosroger91/Clam-Desktop/releases/download/v1.2.0/Sentinel-AV-Setup-1.2.0.exe)** · [release notes and checksum](https://github.com/amosroger91/Clam-Desktop/releases/tag/v1.2.0) · [all releases](https://github.com/amosroger91/Clam-Desktop/releases)

- Windows 10 or 11, 64-bit. No administrator rights needed; it installs for your user account only.
- **This is a preview release and the installer is not code-signed.** Windows SmartScreen may say it "protected your PC"; choose **More info → Run anyway** only if you downloaded it from the link above. You can compare the file's SHA-256 with the checksum on the release page (`Get-FileHash .\Sentinel-AV-Setup-1.2.0.exe` in PowerShell).
- After installing, open **Settings → Install ClamAV & set up**. Sentinel downloads the official ClamAV engine for Windows from Cisco Talos, checks its SHA-256 digest, and downloads the signature database. The engine is about 225 MB; the definitions need additional space.
- Upgrading from an earlier version keeps your settings, schedules, scan history, detections, and quarantined files.

## What it does

- **Continuous scanning (opt-in):** watches selected folders, queues new/changed files, and scans them through a persistent ClamAV engine. Includes CPU/memory policies, battery and idle controls, timed pauses, backlog/latency statistics, immediate detection alerts, and an optional Windows service. See [continuous scanning and resource management](docs/continuous-scanning.md).
- **Scheduled scans:** a daily **quick scan** (Desktop, Downloads, Documents, and your temporary folder, including folders Windows has redirected) and a weekly **full scan** of all local fixed drives. You can change the day, time, and frequency, or pause either one. A **custom scan** checks any folder you choose.
- **Definitions kept current:** checks for new ClamAV definitions hourly, verifies each database file's digital signature with ClamAV's `sigtool`, and warns when definitions are older than the threshold you choose (3 days by default).
- **An honest dashboard:** the Overview shows "All checks passed" only when a schedule is on, the definitions are current and verified, and your last scan completed. Otherwise it says what needs attention and offers the next useful action. The same status appears in the tray and in the window header.
- **Review before anything changes:** detections wait in **Activity → Needs review** until you decide. Nothing is quarantined or deleted automatically.
- **Careful quarantine and restore:** quarantine confirms it is moving the same file that was detected, and restore never overwrites an existing file (you can restore to another location instead).
- **Runs in the background:** closing the window keeps Sentinel in the system tray so schedules keep running, and it can start at Windows sign-in.

Sentinel provides **scheduled, on-demand, and optional continuous file-change scanning**. It is not a real-time protection driver, a firewall, or a registered Windows Security provider, and it does not disable or replace Microsoft Defender. Continuous monitoring can continue after the desktop exits; desktop notifications are delivered when it is running or reconnects. Scheduled scans require the desktop scheduler; missed runs catch up when it restarts. Nothing runs while the computer is off. ClamAV's file-size and archive limits apply, and scan reports say which locations were fully checked and which had files that could not be read.

## How it keeps your data safe

- **Scans are journaled.** Each detection is written to a durable journal the moment ClamAV reports it. If Sentinel, Windows, or the power fails mid-scan, the next start records the scan as interrupted and keeps every detection it had already found.
- **Scheduled scans are not silently skipped.** A due scan stays owed until it succeeds. Failures retry after 15 minutes, backing off to every 6 hours, and the Schedules page shows the next attempt. Cancelling a scan yourself does not trigger a surprise rescan. When both scans are due, the full scan runs first, and it counts for the quick scan only if its results show the quick-scan folders were actually checked.
- **Quarantine never deletes the only copy.** Files are hashed before and after being moved. If anything changes along the way, or Sentinel is interrupted, every copy is kept and the item appears under **Quarantine** for you to finish, undo, recheck, or mark reviewed.
- **Settings and history survive damage.** Data files are versioned and written atomically, with a verified backup of the previous version. A damaged file is set aside for diagnosis and reported in Settings instead of being silently reset, and a file from a newer version of Sentinel is left untouched.
- **Faults stop safely.** If Sentinel hits an internal error it stops making changes, saves diagnostics, and exits; the next start recovers and tells you what happened.

## Privacy

Everything stays on your computer. Sentinel has no telemetry, uploads no files, and makes no network requests except downloading the ClamAV engine from Cisco Talos's GitHub releases and updating definitions from the official ClamAV service. Settings, the engine, definitions, detections, quarantined files, and up to 200 scan reports are stored in `%APPDATA%\sentinel-av`. Scan logs (in `logs\scans`) contain local file paths and are removed along with their reports. Sentinel's own data folder is always excluded from scans.

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

Version 1.2.0 addresses the release-blocking findings of the second engineering review ([CLAUDE_10X_QUALITY_REVIEW.md](CLAUDE_10X_QUALITY_REVIEW.md)); the wider backlog is in [CLAUDE_TODO.md](CLAUDE_TODO.md). Not yet done: code signing, automatic app updates, Windows Task Scheduler integration (so schedules run while Sentinel is fully closed), and clean-machine installation testing. Optional YARA, capa, and Loki analysis modules are planned but not included.

ClamAV is a separate project distributed under its own licenses; engine downloads keep the upstream license files. Sentinel is not affiliated with Cisco or the ClamAV team. Sentinel itself is MIT-licensed (see [LICENSE](LICENSE)).
