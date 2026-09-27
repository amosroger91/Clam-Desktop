# Sentinel AV / Clam Desktop — ambitious implementation handoff

Prepared: 2026-09-27

Repository: https://github.com/amosroger91/Clam-Desktop

Local repository: `C:\Users\roger\OneDrive\Desktop\Wellspring\website\sentinel-av`

Reviewed baseline: version **1.0.1**, commit **227c9d6** (`Fix scheduling, scan parsing and log growth; add live progress; format code`). Recheck HEAD and the working tree before acting; another developer may have made changes since this review.

## Mission and scope

Build a dependable, polished Windows Electron companion for ClamAV. The user's requested foundation is a desktop app, desktop/taskbar/tray presence, first-run ClamAV installation, ongoing definition updates, daily quick scans, weekly full scans, adjustable schedules, and a professional antivirus experience.

The app is functional today, but it is **not yet production-ready**. Prioritize correctness, recovery, truthful health reporting, and safe file handling before adding cosmetic features. Make the scheduled-scanning product excellent before attempting a real-time protection product.

This document is a backlog and execution guide, not a claim that the unchecked work exists. Advanced service, enterprise, and real-time features are later design gates. Do not silently introduce telemetry, cloud uploads, automatic deletion, elevated privileges, or Defender interference in order to check off a feature.

## Instructions for Claude

- [x] Read repository instructions, this file, current code, and the latest git history. Preserve other people's changes.
- [x] Work **inside this nested repository**, not the surrounding WellSpring website repository. Verify `git rev-parse --show-toplevel` before committing or pushing.
- [ ] Reproduce reported bugs against current HEAD before changing behavior. Add meaningful regression tests for failure and recovery paths.
- [ ] Implement in the milestone order below. Keep this file updated with completed checkboxes, dates, evidence, and remaining limitations.
- [x] Make reviewable commits grouped by behavior. Prefer working increments over a single broad rewrite. — Milestone 1 landed as a commit series; tests pass and the app loads at every commit.
- [x] Preserve existing settings, schedules, history, and quarantined files through migrations. Never destroy user data to simplify an upgrade. — v1.0.x files migrate in place and the first save keeps each legacy file as `.bak`. A dry run against a copy of real 1.0.1 data reported no issues.
- [ ] Keep the renderer unprivileged. Do not solve permission problems by running the entire Electron UI as administrator.
- [ ] Keep operational state truthful. Do not claim real-time protection, complete coverage, fresh signatures, or a clean device without evidence.
- [ ] Treat publication separately from local verification. The user previously authorized pushing this app to the named repository; inspect current instructions for release/tag/publication scope before performing those actions. Never force-push shared history.
- [ ] Use plain git and GitHub REST API on this machine. **GitHub CLI (`gh`) is not installed.** Do not print credential-helper output or tokens.
- [ ] Record any external prerequisites, such as a signing identity or Windows service deployment decision. Continue independent work while a prerequisite is unresolved.

## Existing implementation and verification

Current components:

- `src/main.cjs`: Electron lifecycle, IPC, scan processes, updates, scheduling, persistence, quarantine.
- `src/core.cjs`: settings defaults/validation, schedule calculation, arguments, output parsing, JSON writes.
- `src/installer.cjs`: official ClamAV ZIP download, SHA-256 verification, extraction, engine discovery.
- `src/preload.cjs`: renderer bridge.
- `src/smoke.cjs`: development-only Electron smoke and optional real-engine checks.
- `ui/`: vanilla JavaScript, HTML, CSS dashboard and settings.
- `test/core.test.cjs`: nine unit tests at the reviewed baseline.
- `scripts/integration.cjs`: real ClamAV tests using a harmless synthetic signature.
- `.github/workflows/build.yml`: Windows unit tests and installer build; uploads a CI artifact.

Checks passed during review: nine unit tests, real ClamAV clean/detection/error integration tests, Electron renderer and scan-lifecycle smoke checks, formatting, and `npm audit`. Those checks do **not** cover all recovery, scheduling, installer, or quarantine behaviors below. Dependency-audit success is not a security certification.

Useful commands:

```powershell
npm ci
npm test
npm run format:check
npm audit
npm run test:integration
npx electron . --smoke-test
npm run dist -- --publish never
```

The current integration test requires previously prepared engine/database fixtures under ignored `test-output/`. Make that setup reproducible instead of assuming these files exist on another machine. `ELECTRON_RUN_AS_NODE` may need to be removed from the environment when launching Electron.

---

## Milestone 1 — release-blocking correctness and safety

### 1. Preserve quarantine data during recovery — P1

Reference: `reconcileQuarantine()` in `src/main.cjs`, around line 410 at the reviewed baseline.

**Observed:** A pending record with both a stored file and an occupied original path causes the stored copy to be deleted. The original path could contain a different replacement file. This was reproduced with simulated filesystem state.

- [x] Stop deleting stored copies based only on path existence. — `recoverQuarantine()` in `src/quarantine.cjs` decides from SHA-256.
- [x] Define a durable quarantine operation state machine: prepared, copying/moving, verified, committed, failed, recovery-needed. — States: prepared → quarantined (atomic rename), or prepared → copying → quarantined (the copy is verified before the original is removed); restoring → restored; failed; recovery-needed; reviewed. Verification is a step inside `copying`, not a persisted state.
- [x] Preserve both copies when their identity or completeness is uncertain.
- [x] Record file identity and content hash where practical; record size and timestamps as supporting information, not proof of identity. — Each record stores SHA-256, size, and modification time; the hash is also recorded on detections.
- [x] Reconcile metadata and filesystem state without assuming the original path still refers to the scanned file.
- [x] Make recovery idempotent over repeated restarts.
- [x] Present ambiguous recovery cases with clear, non-destructive actions. — Quarantine page offers Finish or Undo (both re-verify hashes) and Mark reviewed (deletes nothing).
- [x] Test a replacement original file, missing original parent, partial copy, move completed before metadata commit, metadata write failure, and repeated recovery. — `test/quarantine.test.cjs`, with a simulated crash at each step.

**Acceptance:** No recovery path silently deletes the only copy of any content. An interrupted operation can be safely retried or reviewed.

### 2. Retry failed scheduled scans — P1

Reference: `tick()`, `scan()`, and scan completion handling in `src/main.cjs`, around lines 210–350.

**Observed:** The next run is advanced after process launch, before its exit result. A process that immediately fails still consumes the scheduled occurrence. This was reproduced by exercising the scheduler with a stubbed scan start.

- [x] Model scheduled occurrences as durable jobs, with distinct planned, queued, running, succeeded, failed, interrupted, and cancelled outcomes. — `src/scheduler.cjs` (next → pending → `jobs.current` → lastOutcome).
- [x] Separate `lastAttempt`, `lastSuccess`, `nextScheduledOccurrence`, and `retryAfter`. — Persisted in `schedule.json` and shown on the Schedules page.
- [x] Handle both failure to spawn and nonzero error exits after successful spawn.
- [x] Retry transient failures with bounded backoff and a visible next-attempt time. — 15 minutes, doubling to 6 hours.
- [x] Define explicit cancellation semantics: user cancellation should not cause an immediate surprise rescan.
- [x] Recover a running job after an app or machine crash without claiming completion. — `recoverInterruptedScan()` records the scan as interrupted, salvages detections from its log, and retries the occurrence.
- [x] Avoid duplicate jobs across resume events, repeated timer ticks, multiple launch attempts, and scheduler edits during a scan. — Reentrancy guard, a single journaled job, the single-instance lock, and occurrences settled by job start time.
- [x] Define catch-up policy when both quick and full jobs are overdue; do not silently skip one without an explicit policy. — The full scan runs first and its success covers a quick occurrence that was due; a failed full scan does not.
- [ ] Test all of these outcomes with a controllable clock and fake scanner process. — **Partial:** the scheduler rules are tested with a controllable clock (`test/scheduler.test.cjs`) and the scanner with a fake process (`test/scanner.test.cjs`), but their wiring in `main.cjs` is covered only by the Electron smoke test. This needs item 22's dependency injection.

**Acceptance:** A failed weekly scan does not quietly wait another week. Restarts do not lose or duplicate pending work.

### 3. Preserve unresolved detections independently — P1

Reference: history truncation in `src/main.cjs` around line 299 and `overview()` in `ui/app.js` around line 148.

**Observed:** Only 200 scan reports are retained. Outstanding detections are derived from those reports, so unresolved threats disappear when the associated report ages out.

- [x] Introduce a durable detection store independent of scan-report retention. — `src/detections.cjs`, stored in `detections.json`.
- [x] Migrate existing detections while preserving their status and quarantine association.
- [x] Keep unresolved detections visible until explicitly resolved; report missing files as missing, not automatically clean. — Activity → Needs review; a missing file can only be marked resolved explicitly.
- [ ] Deduplicate repeated detections thoughtfully using file identity/hash/signature and observation history. — **Partial:** deduplicated by path (case-insensitive) and signature while unresolved, with sightings and linked reports. The hash is recorded but not yet used for deduplication.
- [x] Keep a resolution audit trail with time and action.
- [x] Ensure report/log cleanup cannot delete unresolved detection records or quarantine metadata.
- [x] Test more than 200 scan results with an old unresolved detection.

**Acceptance:** Report retention cannot make an unresolved security issue disappear from the dashboard or review queue.

### 4. Make health reporting truthful — P1/P2

References: `detectEngine()` around line 130 and `overview()` in `ui/app.js`.

**Observed:** With both schedules disabled, the dashboard still says “Your next scan is covered” and “SCHEDULED SCANNING.” Database readiness checks only for a `.cvd` or `.cld` filename, not loadability or freshness.

- [ ] Create a central health model consumed by dashboard, tray, notifications, and diagnostics. — **Partial:** `src/health.cjs` drives the dashboard hero, the health checks, and the tray tooltip. Notifications are still event-driven (deduplicated per failure kind), and there is no diagnostics page yet (item 21).
- [x] Distinguish engine installed, engine runnable, database present, database loadable, database freshness, scheduler enabled, and latest successful scan.
- [x] Track database version/build date separately from last successful update check. “Checked just now” does not necessarily mean newly downloaded signatures.
- [x] Validate the database with ClamAV-supported tooling or a controlled engine load check. Do not validate solely through extensions or file timestamps. — `sigtool --info` signature verification, cached per database fingerprint; a scan that fails to load the database marks it failed.
- [x] Show clear paused, outdated, failed, incomplete-setup, scanning, and ready states.
- [x] Make stale-definition thresholds explicit and configurable where appropriate; explain reduced freshness without inventing a protection score. — Settings → Treat definitions as outdated after (default 3 days).
- [x] Show the actual next scheduled operation and the last successful scan, not only the most recent failed attempt.
- [x] Test disabled schedules, disabled updates, corrupt databases, an old database, partial initial setup, and repeated update failures. — `test/health.test.cjs`.

**Acceptance:** Reassuring dashboard language is supported by actual enabled features and verified operational state.

### 5. Fix shutdown and cancellation lifecycle — P2

Reference: completion handler calling `win.setProgressBar()`, window-close behavior, and `before-quit` in `src/main.cjs`.

**Code-review finding:** With close-to-tray disabled, the window can be destroyed while scanner shutdown is still pending. Completion then accesses the destroyed window without an `isDestroyed()` check.

- [x] Guard all window/tray access during asynchronous completion and shutdown.
- [x] Centralize lifecycle control with a single, idempotent quit path. — `shutdown()` in `main.cjs`.
- [x] Flush reports and close logs before exit, with a bounded shutdown timeout and visible recovery state if needed. — Bounded at 10 seconds; anything unfinished stays journaled and is recovered at the next start.
- [x] Support cancellation during drive discovery, database loading, active scanning, and engine download/extraction where safe.
- [x] Track and clean up owned child processes without terminating unrelated ClamAV processes. — Force kill only by the PID Sentinel started (`taskkill /PID /T /F`).
- [x] Confirm installer extraction subprocesses cannot remain abandoned after quitting. — Extraction runs under an AbortSignal that terminates PowerShell.
- [x] Prevent scheduled jobs from starting once shutdown begins.
- [x] Handle failed `kill()` calls and processes that do not exit promptly.
- [ ] Test window close with close-to-tray both on and off, tray quit, Windows sign-out, crash, sleep/resume, and quit during each operation phase. — **Partial:** automated coverage is a quit during a real scan (smoke test) plus the cancel, force-kill, and race paths in the scanner adapter. Close-to-tray variants, sign-out, crash recovery, sleep/resume, and quitting during an update or install still need manual or VM testing.

**Acceptance:** Closing or quitting never hangs, throws on a destroyed UI object, or loses a completed scan report.

### 6. Harden persistence and startup recovery — P2

References: `read()`, `saveJson()`, startup settings merge, and scan/update completion handlers.

- [x] Add versioned schemas and validation for settings, jobs, reports, detections, quarantine, and update state. — `src/schemas.cjs`, which also covers the schedule runtime.
- [x] Validate nested values and timestamps; merging defaults is not structural validation. — Validated per field or per entry; audit entries are not deeply validated.
- [x] Add explicit migrations with fixture tests for each supported schema version. — Schema 0 (v1.0.x) → 1, with fixtures in `test/store.test.cjs`.
- [x] Preserve invalid files for diagnosis and provide a user-visible recovery route instead of silently resetting everything. — `.corrupt-`, `.invalid-`, and `.newer-` copies plus a `.bak` fallback; Settings shows the issue with an Open data folder button.
- [x] Handle disk-full, read-only, permission-denied, antivirus interference, and interrupted-write conditions. — Actionable `StorageError` messages, retries for transient locks, and an fsync'd temporary file with rename.
- [x] Ensure cleanup occurs even when persistence fails; do not leave operation flags stuck or lose the original error.
- [x] Ensure async event-handler errors cannot leave outer promises unresolved. — The scanner's `done` never rejects, the update promise settles on every path, and the shutdown wait is bounded.
- [x] Use durable transactions or a journal for operations spanning metadata and filesystem changes. Evaluate SQLite for jobs/detections/history; select a maintained dependency only if it improves reliability enough to justify its packaging cost. — Quarantine and scans are journaled. SQLite was evaluated and deferred: `node:sqlite` needs no packaging but is still experimental, and atomic JSON with backups handles current volumes (at most 200 reports) well. Revisit with the headless runner (item 7), which needs cross-process locking.
- [x] Protect against concurrent writes and distinguish recoverable backup files from abandoned temporary writes. — The single-instance lock plus synchronous writes in one process; `.tmp` is discarded on load and `.bak` is used as a fallback.
- [x] Keep privacy-sensitive logs and paths out of generic crash messages. — Uncaught errors go to a local `logs/app-errors.log` and the notification text is generic.

**Acceptance:** Malformed state cannot prevent the app from opening its recovery UI. Storage failures produce actionable errors and preserve pending work.

---

## Milestone 2 — scheduling that survives normal Windows use

### 7. Separate the UI from job execution

- [ ] Design a headless scan/update runner shared with the UI's business logic.
- [ ] Integrate Windows Task Scheduler so closing the UI does not disable the user's routine.
- [ ] Use a documented missed-run policy, including `StartWhenAvailable` where appropriate.
- [ ] Provide an explicit optional wake-from-sleep setting; do not imply that a powered-off PC can scan.
- [ ] Keep per-user tasks as the initial privilege boundary. Evaluate a Windows service separately if logged-out or system-wide operation is required.
- [ ] Do not persist user passwords or require an administrator UI process.
- [ ] Use a single durable queue/lock so Task Scheduler and the open app cannot run conflicting jobs.
- [ ] Reconcile task registration with app settings and detect tasks disabled outside the app.
- [ ] Support installation path changes, upgrades, uninstall cleanup, and recovery from stale task registrations.
- [ ] Explain whether jobs run while logged out and under which account/access permissions.
- [ ] If a privileged service is introduced, authenticate IPC, restrict commands and paths, validate callers, and keep the exposed API narrowly scoped.

**Acceptance:** Documented scheduled behavior works with the UI open, hidden, closed, and after reboot. Privilege requirements are explicit and tested.

### 8. Make schedule behavior predictable

- [ ] Test daylight-saving transitions, nonexistent local times, repeated local times, timezone changes, manual clock changes, and long sleep periods.
- [ ] Decide whether local schedules follow the device timezone; recalculate persisted UTC instants when necessary.
- [ ] Add battery, AC-power, idle-only, and user-active deferral controls.
- [ ] Add a configurable maximum deferral so scans cannot postpone forever without warning.
- [ ] Show a human-readable schedule preview and next occurrence before saving.
- [ ] Support editable quick/full profiles first; later support multiple custom folder schedules.
- [ ] Define the precedence of manual scans, overdue scans, retries, and definition updates.
- [ ] Prefer refreshing stale definitions before a scheduled scan, but do not indefinitely block scanning during network outages.
- [ ] Add notification actions such as open results, retry, and defer, with clearly documented behavior.

### 9. Persist update retry policy

- [ ] Persist automatic update attempt times and backoff across restarts.
- [ ] Reset failure counters after any successful update, including a manually triggered one.
- [ ] Respect FreshClam cooldowns and avoid restart-driven retry storms.
- [ ] Distinguish offline, DNS, rate-limit, server, disk, and integrity failures.
- [ ] Show last check, next attempt, current database version, and a readable failure reason.
- [ ] Add bounded timeouts/watchdogs and cancellation for a stuck updater.
- [ ] Coordinate updates with scans without starving either indefinitely.

---

## Milestone 3 — safe installation and sustainable updates

### 10. Complete the first-run experience

- [ ] Build a focused setup flow: prerequisites → engine download → verification → installation → definitions → validated test scan → schedule summary.
- [ ] Check supported Windows version, architecture, free disk space, network availability, writable storage, and required runtime components.
- [ ] Present download size and expected storage use before starting.
- [ ] Detect existing managed and external ClamAV installations, including incomplete/broken installations.
- [ ] Let users choose managed installation or a verified existing engine without losing existing preferences.
- [ ] Support retry from the failed stage instead of restarting successful stages unnecessarily.
- [ ] Preserve useful diagnostics while translating common failures into plain language.
- [ ] Add download cancellation, bounded retry, and resumable downloads only with safe server validator/range handling.
- [ ] Clean up interrupted downloads and failed extraction directories safely; ensure all removal paths stay under the intended managed directory and do not follow reparse points unexpectedly.
- [ ] Reject unexpected download hosts, malformed metadata, unsupported architecture, unreasonable asset size, and invalid archive layouts.
- [ ] Keep SHA-256 verification. Evaluate upstream signature verification as an additional check; explain the trust boundary of a checksum delivered by the same release service.
- [ ] Test non-ASCII usernames, spaces, apostrophes, long paths, redirected folders, offline launch, and interrupted setup.

### 11. Add managed ClamAV engine upgrades

**Current gap:** `install` refuses when an engine already exists; automatic updates only update definitions.

- [ ] Check engine updates on a reasonable interval, separate from hourly definitions.
- [ ] Distinguish managed engines from external installations; never overwrite an external installation unexpectedly.
- [ ] Show installed/available engine versions and upstream release notes.
- [ ] Stage the new engine beside the active version.
- [ ] Verify the archive, executable presence, successful startup, and database compatibility before switching.
- [ ] Perform a small controlled scan before committing the upgrade.
- [ ] Switch atomically when no scan/update is running; retain a working previous version for rollback.
- [ ] Do not delete older managed engines before the replacement passes health checks.
- [ ] Detect unsupported/end-of-life engine versions and offer an upgrade path.
- [ ] Test upgrade success, failed download, failed validation, crash during switch, and rollback.

### 12. Add secure Sentinel application updates

- [ ] Select an updater compatible with the actual NSIS packaging and release strategy; do not assume a different installer format's updater works automatically.
- [ ] Use signed application releases, authenticated integrity verification, HTTPS, and a protected publishing workflow.
- [ ] Add update checks, release notes, download progress, defer/restart behavior, and a manual “Check for updates.”
- [ ] Avoid restarting during active scans or file operations.
- [ ] Test upgrading from each supported prior version with real user-state fixtures.
- [ ] Separate stable and prerelease channels if needed; do not silently move stable users to experimental builds.
- [ ] Define recovery/rollback for an app update that cannot launch.

### 13. Make distribution professional

- [ ] Obtain/configure a trusted Windows signing identity. Never commit private keys, certificates with private material, or credentials.
- [ ] Sign application binaries, installer, and uninstaller as appropriate; verify signatures in CI.
- [ ] Replace the current explicit `signExecutable: false` production configuration when signing is available.
- [ ] Publish versioned GitHub Releases with the installer, SHA-256 checksums, release notes, and supported-platform information.
- [ ] Keep source versions, executable metadata, installer names, UI versions, and release tags synchronized.
- [ ] Test desktop/Start menu shortcuts, taskbar/tray identity, notifications, launch at sign-in, and Windows Apps uninstall entries.
- [ ] Test x64 and ARM64 builds separately if both are offered; document unsupported combinations.
- [ ] Define uninstall behavior for jobs, services, startup entries, engine files, reports, and quarantine. Give a deliberate preserve/remove choice for user data; never silently delete quarantined files.
- [ ] Ship upstream license/attribution materials correctly and maintain an inventory of bundled components.

---

## Milestone 4 — safe and efficient scanning

### 14. Improve scan profiles and coverage reporting

- [ ] Make quick-scan locations explicit and editable; ensure redirected Desktop/Documents/Downloads are handled correctly.
- [ ] Avoid scanning the same physical location twice through overlapping targets or aliases.
- [ ] Document whether “quick” means common locations or shallow recursion. Provide configurable limits rather than implying it is inherently fast.
- [ ] Add individual-file selection, multiple targets, and optional drag-and-drop scanning.
- [ ] Add optional Explorer “Scan with Sentinel” integration with safe argument handling and uninstall cleanup.
- [ ] Let users select fixed/removable/network drives explicitly. Do not silently widen full-scan scope to network shares.
- [ ] Define handling of OneDrive placeholders and other cloud files; avoid unexpected bulk hydration/downloads.
- [ ] Handle inaccessible files, encrypted archives, files that change during scanning, offline volumes, and disconnected drives transparently.
- [ ] Report scanned, excluded, skipped, failed, and limit-reached categories separately where the engine can supply reliable evidence.
- [ ] Expose advanced size/archive limits with explanations and safe defaults. Do not imply that increasing every limit is universally safer.
- [ ] Test junctions, symlinks/reparse points, loops, case variants, Unicode, special characters, and deep paths.
- [ ] Validate exclusion matching against the real ClamAV regex/path behavior on Windows, not only JavaScript regular expressions.
- [ ] Ensure internal quarantine exclusion is invariant across aliases and equivalent paths, without excluding unrelated user files.

### 15. Strengthen scanner process handling

- [ ] Extract a scanner adapter with typed events and explicit start/load/scan/cancel/finish phases.
- [ ] Decode stdout/stderr incrementally so multi-byte characters split across chunks are preserved.
- [ ] Frame stderr lines as well as stdout; a chunk boundary is not a line boundary.
- [ ] Handle huge output, unusually long lines, and malformed output without unbounded memory growth.
- [ ] Respect log-stream backpressure rather than accumulating writes during a large scan.
- [ ] Bound log size as well as log count; show when a log is truncated or rotated.
- [ ] Avoid classifying informational output as warnings solely because it appears on stderr.
- [ ] Ensure completion runs exactly once for `error`, `close`, cancellation, watchdog timeout, and shutdown races.
- [ ] Keep arguments as arrays and use a strict command/option allowlist. Test paths that resemble switches.
- [ ] Record engine and database versions used by each scan, plus relevant profile settings.

### 16. Improve resource use without overpromising

- [ ] Measure time to load definitions, time to first file, steady-state throughput, peak memory, idle memory, and UI responsiveness.
- [ ] Add lower-priority/background scan operation and resource preferences supported safely on Windows.
- [ ] Display elapsed time, current phase, checked file count, warnings, and detections. Use indeterminate progress when total work is unknown.
- [ ] Add genuine pause/resume only if the chosen engine architecture supports it reliably; otherwise offer stop/restart honestly.
- [ ] Evaluate an optional managed `clamd` mode to avoid reloading definitions for each scan. Measure the resident-memory tradeoff and secure its local interface; do not expose an unauthenticated network listener.
- [ ] Evaluate incremental scan caching only with a clear invalidation model covering file identity/content changes, engine changes, database changes, and settings. Do not skip files based solely on modification time.

---

## Milestone 5 — a complete detection and quarantine workflow

### 17. Strengthen quarantine and restore

- [ ] Verify that the file selected for quarantine still matches the detection, or rescan/reconfirm if it changed.
- [ ] Avoid relying only on extension renaming as isolation. Evaluate restrictive ACLs and a non-executable container format; document the remaining threat boundary.
- [ ] If encryption is used, design recovery/key ownership carefully. Do not create a format that loses user files when an app preference resets.
- [ ] Hash and verify copied contents before deleting the original in a cross-volume operation.
- [ ] Move expensive file hashing/copying off the Electron UI's main event loop.
- [ ] Serialize conflicting file operations; prevent a restore from racing a scan/quarantine of the same file.
- [ ] Journal restore operations too, so crashes between copy, delete, and metadata update are recoverable.
- [ ] Restore without overwriting existing files; offer a native “restore to another location” flow.
- [ ] Preserve useful original metadata where safe and practical, and explicitly document metadata not retained.
- [ ] Rescan before restore on demand and show the detection that led to quarantine.
- [ ] Allow permanent deletion only through an explicit user action with clear consequences; keep it separate from routine cleanup.
- [ ] Add storage-use visibility, optional retention policy, and exportable quarantine metadata.

### 18. Improve detection review

- [ ] Add a dedicated unresolved-detections view with status, file path, signature, scan time, size/hash, and available actions.
- [ ] Support searching, filtering, sorting, and carefully scoped bulk actions.
- [ ] Distinguish malware detections from potentially unwanted applications where the engine provides reliable classification.
- [ ] Never invent severity, family attribution, or confidence scores from a signature name alone.
- [ ] Support “file already removed,” “review later,” “quarantined,” and “restored by user” as explicit states.
- [ ] Add narrowly scoped allowlisting with rationale and an audit trail. Prefer file-specific/hash-specific exceptions over excluding a broad parent folder.
- [ ] Offer guidance for false positives and optional upstream submission links. Any upload must be explicit and explain what leaves the device.

---

## Milestone 6 — professional product experience

### 19. Dashboard and navigation

- [ ] Keep the current restrained visual direction, but make operational status more prominent than decorative reassurance.
- [ ] Show next scan, latest successful scan, signature freshness, unresolved detections, and paused/failed jobs in one glance.
- [ ] Make status cards lead directly to the action that resolves the problem.
- [ ] Show a concise activity timeline for scans, updates, schedule edits, quarantine, restore, and recovery events.
- [ ] Add history search/filtering, pagination or virtualization, and useful readable report exports in addition to JSON.
- [ ] Include scan scope and limitations in reports so a clean result is not misinterpreted as universal coverage.
- [ ] Preserve scroll position, focus, selected controls, and expanded reports when state changes.
- [ ] Fix deferred-render behavior: an event skipped while an input is focused or a report is open must eventually reconcile after the interaction ends.
- [ ] Detect unsaved settings, provide clear Save/Discard behavior, and do not silently discard edits during navigation.
- [ ] Separate long-operation state from individual button states so unrelated settings remain usable safely.

### 20. Accessibility and Windows fit

- [ ] Increase tiny 8–11 px secondary text and verify contrast in actual rendered screens.
- [ ] Support 100%, 125%, 150%, and 200% display scaling, small laptop screens, and window resizing.
- [ ] Test high contrast/forced colors, keyboard-only navigation, screen readers, visible focus, and accessible names/states for switches and progress.
- [ ] Respect reduced-motion preferences for the indeterminate scan animation.
- [ ] Add system/light/dark theme preference without sacrificing status contrast.
- [ ] Use locale-aware dates and times, including the user's 12/24-hour preference.
- [ ] Persist sensible window size/position without reopening off-screen after monitor changes.
- [ ] Add useful notification click actions and rate limiting; avoid repeating the same failure every retry.
- [ ] Make the tray menu reflect busy/paused/error state and disable unavailable actions with a clear route to setup.
- [ ] Add an About/Help page with version, engine/database details, licenses, documentation, and privacy statement.

### 21. Diagnostics and support

- [ ] Add a health-check page that checks engine execution, database validity, scheduler registration, writable storage, free space, and update connectivity.
- [ ] Provide repair actions that preserve user data: retry update, repair managed engine, recreate scheduled tasks, and restore a settings backup.
- [ ] Create an exportable diagnostic bundle with a preview and path/user information redaction by default.
- [ ] Keep logs local by default. No automatic telemetry or crash upload without explicit opt-in and a clear privacy policy.
- [ ] Add persistent actionable error details; do not rely solely on a toast that disappears after a few seconds.
- [ ] Document expected limitations, common setup failures, how to recover quarantined files, and how to report a bug.

---

## Milestone 7 — architecture, security, and engineering discipline

### 22. Refactor along real component boundaries

- [ ] Split the large main-process module into app lifecycle, IPC, scanner, scheduler, updater, installer, persistence, quarantine, and notification components.
- [ ] Inject clock, filesystem, process runner, and notification dependencies where this enables real failure-path tests.
- [ ] Introduce shared types or schemas for IPC requests, operation states, settings, and reports. Consider TypeScript or checked JSDoc rather than a rewrite solely for fashion.
- [ ] Replace loosely related booleans with explicit operation state and a centralized coordinator.
- [ ] Keep core business logic reusable by the headless runner and UI without importing Electron everywhere.
- [ ] Keep UI changes incremental. Introduce a framework only if it materially improves state management, accessibility, or maintainability.

### 23. Tighten application security

- [ ] Retain sandboxing, context isolation, disabled Node integration, restrictive CSP, blocked navigation, and denied unsolicited permissions.
- [ ] Validate IPC action and payload schemas in the main process; expose narrow preload methods where practical instead of an unrestricted generic command surface.
- [ ] Verify sender/frame checks on every privileged path, including any future service/runner communication.
- [ ] Escape all untrusted paths, signature names, log text, and release metadata before rendering.
- [ ] Do not trust mutable persisted paths for deletion/restoration without confinement and record validation.
- [ ] Threat-model engine replacement, writable executable directories, reparse points, archive extraction, concurrent file replacement, and restore path manipulation.
- [ ] Use the least privilege needed and distinguish accidental-corruption protection from resistance to malware already running as the same user.
- [ ] Audit URI handling, Explorer arguments, native dialogs, export paths, and external-link allowlists.
- [ ] Add dependency/update monitoring, lockfile review, secret scanning, and source security checks to CI.
- [ ] Document the app's threat model and the limits of a per-user scheduled scanner.

### 24. Build a meaningful test suite and CI matrix

- [ ] Unit-test the scheduler state machine with a fake clock, DST/timezone cases, catch-up, retry, cancellation, and edits during execution.
- [ ] Test persistence migration and recovery against malformed/truncated/stale state fixtures.
- [ ] Test quarantine/restore with fault injection at every filesystem and metadata boundary.
- [ ] Test scanner framing with chunk-split Unicode, multiline stderr, partial lines, unexpected exit codes, and very large output.
- [ ] Automate harmless synthetic-signature integration tests with a pinned verified engine fixture or a documented trusted download stage.
- [ ] Make fresh-machine integration setup reproducible; skip with a clear reason only when an explicitly optional prerequisite is unavailable.
- [ ] Run renderer navigation and important interaction tests in CI, including unsaved settings, live state transitions, and recovery actions.
- [ ] Ensure every smoke/integration failure reliably exits nonzero; verify this by deliberately failing a test in a disposable test fixture.
- [ ] Add clean Windows VM tests for install, first-run engine setup, scan, reboot, scheduled catch-up, upgrade, uninstall, and preserved quarantine.
- [ ] Test non-administrator accounts and supported Windows/architecture combinations.
- [ ] Add performance budgets and regression checks for startup, idle memory, progress rendering, log growth, and large histories.
- [ ] Add formatting, linting/type checks, unit tests, integration checks, build, and artifact verification as distinct CI stages.
- [ ] Pin CI actions appropriately, minimize workflow permissions, protect release credentials, and ensure forked PRs cannot access signing secrets.
- [ ] Generate an SBOM/dependency inventory and publish provenance where supported by the release workflow.

---

## Milestone 8 — ambitious later features, each requiring a design gate

These are optional extensions, not release blockers for a dependable scheduled scanner.

### 25. Advanced local protection

- [ ] Research safe removable-drive scan prompts with opt-in behavior and no automatic destructive action.
- [ ] Explore folder-watch-triggered scans with event coalescing, debouncing, exclusion rules, and resource controls. Label this accurately: watching some folders is not comprehensive real-time interception.
- [ ] Evaluate managed `clamd` and a hardened local service if measured performance and logged-out scheduling justify the additional complexity.
- [ ] Investigate Windows Security Center integration only after confirming supported APIs, eligibility, behavior, and maintenance requirements. Do not disable or displace Defender as a shortcut.
- [ ] Treat kernel-level interception/minifilter development as a separate product/security project requiring specialized engineering, signing, and extensive compatibility testing—not an Electron feature toggle.

### 26. Optional team/managed deployments

- [ ] Design importable/exportable local policy presets with schema validation and clear precedence over personal preferences.
- [ ] Evaluate managed configuration, silent installation, and enterprise deployment documentation if requested.
- [ ] Keep any fleet console, remote commands, remote telemetry, or cloud service out of the default local-only product until explicitly scoped and threat-modeled.
- [ ] Require authentication, authorization, audit logging, and privacy controls for any future remote management feature.

### 27. Product polish beyond the first stable release

- [ ] Add localization-ready strings and validate layouts with longer translations.
- [ ] Add optional compact dashboard/tray-only mode.
- [ ] Provide a readable periodic local security report summarizing actual scans, failures, and unresolved detections; avoid unsupported security scores.
- [ ] Consider encrypted backup/export of settings and quarantine metadata with a documented recovery process.
- [ ] Add a release roadmap/changelog and a support policy defining which Windows and ClamAV versions are maintained.

---

## Recommended execution sequence

1. **Safety patch:** quarantine preservation, durable detections, scheduled-failure retries, destroyed-window guards, persistence error handling, and honest health states.
2. **Reliability release:** modular operation coordinator, durable jobs, Task Scheduler runner, timezone handling, resumable setup, stronger quarantine/restore transactions.
3. **Distribution release:** managed engine upgrades, signed installer/app updates, GitHub Releases, migration and upgrade/uninstall tests.
4. **Product release:** accessibility, richer reports, scan preferences, Explorer integration, support diagnostics, measured performance improvements.
5. **Advanced roadmap:** optional daemon/service, selected event-triggered scans, managed deployments, and separately evaluated real-time protection research.

## Definition of done for each milestone

- [ ] Required behavior is implemented, documented, and verified against explicit acceptance criteria.
- [ ] Regression tests cover the failure that motivated the change, not just the implementation's happy path.
- [ ] Existing user data survives upgrade and failure-path testing.
- [ ] No misleading protection claims or fake progress metrics are introduced.
- [ ] Windows build succeeds from a clean checkout and produces identifiable, versioned artifacts.
- [ ] Installation/update/recovery behavior is exercised on an appropriate clean Windows environment where relevant.
- [ ] This backlog and the changelog identify completed items and remaining limitations.
- [ ] The handoff summary names tests actually run, artifact locations, commit IDs, and any blocked external prerequisites.

## Reference material

- ClamAV scanning and `clamscan`/`clamd` tradeoffs: https://docs.clamav.net/manual/Usage/Scanning.html
- ClamAV definition management: https://docs.clamav.net/manual/Usage/SignatureManagement.html
- Official engine releases: https://github.com/Cisco-Talos/clamav/releases
- Windows Task Scheduler missed-run setting: https://learn.microsoft.com/en-us/windows/win32/taskschd/taskschedulerschema-startwhenavailable-settingstype-element
- Electron security: https://www.electronjs.org/docs/latest/tutorial/security
- Electron code signing: https://www.electronjs.org/docs/latest/tutorial/code-signing

Verify current documentation before implementing platform-specific behavior. Do not assume a README claim or a passing smoke test establishes production reliability.

## Claude's completion log

Append concise milestone records here with date, commit, completed task groups, validation, artifacts, and unresolved issues.

- **2026-09-27 — Milestone 1 (items 1–6).** Version 1.0.1, unreleased changes. Commits: `fddcb15` persistence and detection store, `5155b7c` scanner adapter, `fc015a8` durable scheduling, `93a52a0` journaled quarantine, `f192bc7` health model, `2a9da08` app wiring, then a follow-up commit adding quarantine timestamps and this log.
  - Validation: `npm test` (81 tests covering quarantine fault injection, the scheduler with a controllable clock, persistence and migration fixtures, scanner framing with a fake process, and the health model); `npm run format:check`; `npm run test:integration` (real ClamAV 1.5.4 with clean, detection, and missing-file exit codes); `npx electron . --smoke-test` with a complete real database (renderer, IPC validation, a real scan exercising the detection store and health checks, sigtool verification, and a quit during a real scan saved as `interrupted`). Each commit in the series was checked in a clean worktree: tests pass and `main.cjs` loads.
  - Migration dry run on a copy of the user's real 1.0.1 data: no issues. Schedules, update history, and one real detection (`Win.Malware.Aotera-10060486-0` in `Downloads\Mouse_Jiggler_V3.0.0.zip`) carried over. The detection is left for the user to review.
  - Remaining limitations: main-process orchestration is covered only by the smoke test (needs item 22's dependency injection); detection deduplication does not use hashes; shutdown, sign-out, and sleep variants need manual or VM testing; there is no cross-process lock yet, which item 7's Task Scheduler runner will need; integration fixtures in `test-output/` are still prepared by hand (item 24).
  - Not done this round: no build or install of this version, and no tag or release.
