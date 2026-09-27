# Sentinel AV · Clam Desktop

A Windows Electron desktop companion for ClamAV. Includes a polished dashboard, first-run engine installation, hourly malware definition updates, configurable scan schedules, system tray controls, notifications, scan reports, exclusions, and manual quarantine/restore.

![Sentinel AV dashboard](assets/dashboard.png)

## Run locally

Requires Windows 10/11 and Node.js 22.12 or later.

```powershell
npm ci
npm start
```

Open **Settings → Install ClamAV & set up**. Sentinel downloads the latest official Cisco Talos Windows ZIP, verifies its published SHA-256 digest, installs it in your user profile, and runs FreshClam to download the database. The engine download is approximately 225 MB; definitions require additional space. No administrator access is required. You can also select an existing `clamscan.exe` installation.

## Build a Windows installer

```powershell
npm test
npm run dist
```

The installer is written to `release/`. It creates desktop and Start menu shortcuts. Installed copies start in the tray at Windows sign-in by default; this can be disabled in Settings. The app has a taskbar icon while open and a notification-area tray icon while running.

The build is unsigned. Public distribution should use a trusted Windows signing certificate. No certificate or signing key is included in this repository.

## Scanning and updates

- **Quick scan:** daily at 12:00 local time by default; recursively checks Desktop, Downloads, Documents, and the user's temporary folder.
- **Full scan:** Sunday at 18:00 by default; recursively checks all local fixed drives accessible to the current user.
- **Custom scan:** choose a folder with the native Windows picker.
- Change frequency, day, time, and enabled state independently for both schedules.
- A due run stays pending until a scan for it succeeds. Runs missed while the computer was off are caught up once when Sentinel is next running. Failed runs retry after 15 minutes, backing off to every 6 hours, and the Schedules page shows the next attempt. Cancelling a scan yourself does not trigger an immediate rescan. A scan interrupted by quitting, sign-out, or a crash is recorded as interrupted and retried shortly after Sentinel runs again.
- When both schedules are due, the full scan runs first; its success also covers the quick scan. Editing a schedule re-plans it from now. Concurrent scans are prevented. Closing the window keeps the app in the tray by default.
- FreshClam checks for new definitions hourly while the app is running. Failed checks back off from 15 minutes to 6 hours (at least 4 hours after a rate-limit response), and the delay is kept across restarts. Failures are classified (offline, DNS, rate limit, disk, integrity) and shown in Settings. The first database download is part of setup.
- Definition freshness is judged by the database's build time, not by when Sentinel last checked. Definitions older than the configured threshold (3 days by default) are reported as outdated. Database files are verified with ClamAV's `sigtool`, and a database ClamAV fails to load is reported as a problem.
- Database updates and scans do not run concurrently. Scans due during an update run after it finishes.
- Exit codes, errors, permission warnings, partial results, and cancellations are reported. The UI never shows a fabricated completion percentage.
- The Overview's health checks come from one model shared with the tray and notifications. It only reports everything as fine when a schedule is enabled, definitions are verified and current, and the last scan succeeded.

Sentinel is an **on-demand and scheduled scanner**, not a real-time file monitoring driver, firewall, or registered Windows Security antivirus provider. It does not disable Microsoft Defender. Scans cannot run while the computer is off or Sentinel is completely quit. ClamAV's default file-size and archive limits apply; “full scan” means all accessible local fixed drives, not guaranteed inspection of every byte.

## Quarantine and privacy

Detections are reported first and kept in their own store, so an unresolved detection stays in **Activity → Needs review** until you act on it, even after its scan report ages out. A file that disappears is shown as missing, not treated as clean.

Quarantine requires an explicit action and confirmation. Sentinel hashes the file first and refuses if it changed since detection. It then moves the file into the app's data directory under a non-executable extension, verifying copies made across drives before removing the original. Every step is journaled. If Sentinel stops mid-operation, recovery decides what happened from content hashes and never deletes a copy unless identical content is verified elsewhere. Uncertain cases keep every copy and appear under Quarantine for you to finish, undo, or mark reviewed. Restore asks for confirmation, never overwrites an existing file, and offers another location when the original path is taken. Quarantine is storage isolation, not an encrypted or access-controlled sandbox. There is no automatic destructive deletion.

Settings, the engine, signatures, quarantine, detections, schedule state, and up to 200 scan reports live in `%APPDATA%/sentinel-av` (the exact directory is displayed in exclusions). Data files are versioned and written atomically with a backup of the previous version. A damaged or invalid file is kept aside for diagnosis (for example `history.json.corrupt-<time>`) and reported in Settings instead of being silently reset. Plain-text scan logs are retained in its `logs` subfolder for reports that are still kept, and each log is capped at 64 MB. Logs contain local file paths. No telemetry or file uploads are implemented; network traffic is limited to official engine downloads and ClamAV definition services. The application data folder is automatically excluded from scans.

## Development and verification

`npm test` runs unit tests for the scheduler (with a controllable clock), quarantine recovery (with a simulated crash at every step), persistence migration and recovery, the scanner adapter (with a fake process), the health model, input validation, output parsing, exclusion handling, and trusted engine asset selection. `npm run pack` builds an unpacked app. For an Electron smoke test, run `npx electron . --smoke-test`; screenshots and renderer state are written to `test-output/`. When `test-output/engine-path.txt` and a downloaded database (`test-output/database/main.cvd`) are present, it also runs real ClamAV scans against a harmless synthetic signature and quits during a scan to check that it is saved as interrupted. Smoke tests use a temporary profile and do not register startup or run background scans.

The renderer is sandboxed with context isolation and a restrictive CSP. Privileged operations stay in the main process behind a sender-validated IPC bridge. Processes are spawned with argument arrays, not shell-interpolated file paths. The app never accepts an executable path directly from renderer text.

ClamAV is a separate project, distributed under its own licenses. Engine downloads preserve upstream license files. Sentinel is not affiliated with Cisco or the ClamAV team.

References: [ClamAV scanning](https://docs.clamav.net/manual/Usage/Scanning.html), [signature updates](https://docs.clamav.net/manual/Usage/SignatureManagement.html), [official engine releases](https://github.com/Cisco-Talos/clamav/releases), [Electron security](https://www.electronjs.org/docs/latest/tutorial/security).
