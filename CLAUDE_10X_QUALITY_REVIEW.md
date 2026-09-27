# Sentinel AV — second deep review and 10× quality program

**Review date:** 2026-09-27  
**Reviewed baseline:** `b335ca9`, version `1.1.0`  
**Repository:** https://github.com/amosroger91/Clam-Desktop  
**Local root:** `C:\Users\roger\OneDrive\Desktop\Wellspring\website\sentinel-av`  
**Companion backlog:** [CLAUDE_TODO.md](CLAUDE_TODO.md)

## Read this first

This is a fresh review of the substantial 1.1.0 implementation, **not a repeat of the 1.0.1 review**. Independent detection storage, journaled file operations, scheduler retries, schema-aware persistence, health assessment, bounded scanner logs, stream decoding, and shutdown handling now exist. Preserve those gains. Do not rebuild completed work simply because the earlier backlog contains an unchecked box.

The remaining weaknesses are chiefly at the boundaries between these components. A component can pass its unit tests while the composed application loses evidence, overstates readiness, or gets stuck after a storage failure.

“10×” is an ambition for engineering quality and user trust, not a measured detection-rate or performance claim. This plan defines measurable outcomes instead of promising that ClamAV will detect ten times more malware.

**Assignment for Claude:** fix the verified defects, prove the cross-component invariants, and then build a quiet, understandable, recoverable Windows product. Deliver small vertical slices with evidence. Read current HEAD before acting; line references below are approximate pointers into the reviewed commit.

## Review evidence and limits

Completed during this review:

- Read main orchestration, scheduling, scanner adapter, schemas/store, file identity, quarantine/restore, detections, database inspection, health, installer, renderer, tests, smoke harness, build configuration, CI, and the previous handoff.
- Ran `npm test`: **81 passed**.
- Ran formatting verification and `npm audit`: both passed; the audit reported no known dependency vulnerabilities.
- Ran real ClamAV integration checks: clean exit 0, harmless synthetic detection exit 1, missing-file exit 2.
- Ran Electron smoke checks: renderer/navigation/IPC, real scan with detection and health persistence, shutdown during scanning recorded as interrupted.
- Inspected the current rendered detection dashboard.
- Ran **seven targeted probes** against current modules using mocks or disposable files under ignored `test-output/`. They exposed the behaviors listed as R01–R07 below.

No application source was modified for this review. No live user detections or quarantine files were manipulated. No signing, fresh-VM installation, reboot, sleep, long-duration soak, or privileged-service assessment was performed. Passing dependency checks do not establish the security of application logic.

### Reproduction results recorded during review

```text
R01 unverified database health: ok
R02 hash after new sighting: old-content-hash
R03 quick pending after partial full: null
R04 mutation between hash and move:
    status=quarantined, stored="version B", hashMatches=false
R05 stdout remains paused after log failure: true
R06 detection after log cap: inResult=1, inRecoveryLog=false
R07 backup contents after failed save of recovered state: broken
```

**Evidence labels:** Reproduced = exercised the actual module with controlled inputs; code-confirmed = visible from a specific execution path, but its complete Windows end-to-end scenario was not exercised; design gap = desired behavior not implemented; investigate = requires additional evidence. Priority P1 means address before broad distribution; P2 means important hardening; P3 means later improvement. Do not turn a code-review inference into a claim of a demonstrated exploit.

---

## Part I — new findings and implementation tickets

### R01 — Readiness and health still disagree about verification

**P1 · Reproduced / code-confirmed**  
Locations: `src/main.cjs:64`, `src/main.cjs:302`, `src/health.cjs:47`, `ui/app.js:196`, `ui/app.js:501`.

`ready()` permits a database whose verification is `null` and does not check `loadFailed`. `assess()` can return `ok` for a fresh but unverified database, while the renderer's `ok` description says definitions are verified. Settings uses yet another readiness definition. A valid-looking CVD header is not proof the database can be used.

- [x] **R01.1** Define one engine capability result: `canScan`, `canUpdate`, `verificationState`, and explicit blocking/advisory reasons. Use it in IPC, scheduler, UI, and tray. — `capability()` in `src/health.cjs`; used by the scheduler, IPC, tray tooltip, and renderer.
- [x] **R01.2** Treat verification pending/unavailable/failure as different states; choose and document whether an explicit manual scan is permitted while pending. Never label pending as verified. — Policy is documented on `capability()`: pending or unavailable verification allows scans (a scan is itself load evidence) but is never shown as verified.
- [x] **R01.3** Respect an observed database load failure in automatic scheduling. Provide a repair/recheck path instead of repeatedly launching a known-failing scan. — A load failure blocks scheduled scans; **Recheck database** re-verifies and runs a controlled load test.
- [x] **R01.4** Scope verification to database generation **and engine identity**. An old engine's cached result should not certify a different engine automatically. — The cache key is database fingerprint plus engine directory and version.
- [x] **R01.5** Test every combination of runnable engine, database presence, fresh/stale/unknown date, verification true/false/null, and previous load failure. — `test/health.test.cjs` runs a matrix of more than 100 combinations and asserts capability and health agree.

**Acceptance:** No surface says “all checks passed,” “verified,” or “ready” in a way that contradicts the execution policy. A scan's eligibility decision is reproducible from one immutable capability snapshot.

### R02 — Rescanning a changed detected file retains its obsolete hash

**P1 · Reproduced**  
Locations: `src/detections.cjs:23`, `src/main.cjs:617`, `src/quarantine.cjs:77`.

Observation merges by lowercased path and signature but keeps `sha256` from the previous sighting. Identity enrichment skips records that already have a hash. If the file changes and still matches the same signature, quarantine rejects it and says to scan again; another scan preserves the same old hash. An old `identifyError` can also prevent future identity retries.

- [x] **R02.1** Model observations separately from content revisions. Associate identity evidence with the observation that established it. — Each detection keeps a bounded `revisions` history of earlier identities with the report that established them. There is no separate observation table yet (Q2).
- [x] **R02.2** Refresh or invalidate content identity after a new sighting; do not silently overwrite historical evidence.
- [x] **R02.3** Make transient identity-read failures retryable on a new sighting or explicit user retry.
- [ ] **R02.4** Handle a missing file that reappears, a different file at the same path, and Windows directories with case-sensitive behavior. — **Partial:** a missing file that reappears and a different file at the same path are handled and tested. Paths are still compared case-insensitively, so two files differing only by case in a case-sensitive directory would merge.
- [x] **R02.5** Test detect A → replace with B matching same synthetic signature → rescan → review/quarantine B, preserving both observation histories. — `test/detections.test.cjs`.

**Acceptance:** “Scan again” can actually resolve the stale-identity condition without manually editing JSON or dismissing a real detection.

### R03 — A partial full scan incorrectly satisfies a quick scan

**P1 · Reproduced; coverage inference is code-confirmed**  
Location: `src/scheduler.cjs:70`.

A `partial` full-scan result clears a pending quick occurrence. No evidence establishes that the quick targets were inspected. Even a completed fixed-drive scan does not necessarily cover quick folders redirected to a network location. Finishing an attempt is different from meeting a coverage obligation.

- [x] **R03.1** Separate job completion from coverage satisfaction; do not retry forever for expected inaccessible Windows files. — File-level access gaps settle the job as partial; a scan in which every target failed is an error and retries.
- [x] **R03.2** Store the normalized target set and relevant exclusions/settings on each job. — Targets and exclusions are recorded in the scan journal and on the report.
- [x] **R03.3** Supersede another job only when scope and actual coverage justify it; otherwise leave the quick job pending. — `coversTargets()` in `src/coverage.cjs`.
- [x] **R03.4** Categorize warnings so harmless operational warnings and unscanned target failures are not equivalent. — `classifyWarning()`: access, limit, engine, and target failures.
- [x] **R03.5** Test partial full scans, excluded quick folders, redirected/network folders, and schedules changed during the scan. — `test/coverage.test.cjs`, plus scheduler tests for edits during a scan.

**Acceptance:** A full scan cannot claim to have covered a location it never scanned. The UI distinguishes “attempt completed with gaps” from coverage success.

### R04 — Hash checking and file mutation are separate operations

**P1 · Reproduced with an injected filesystem mutation**  
Locations: `src/files.cjs:15`, `src/quarantine.cjs:110`, `src/quarantine.cjs:150`, `src/quarantine.cjs:313`.

The probe changed a harmless file after `identify()` returned but immediately before rename. The operation reported `quarantined`, yet stored content did not match the recorded hash. Cross-volume removal and recovery resolution likewise have check-then-path-mutation windows. The probe establishes incorrect identity accounting, not a claim that every concurrent change causes data loss.

- [x] **R04.1** Design file operations around stable identity, open handles, before/after checks, and reparse-point policy. Document where Node APIs cannot provide the required Windows guarantee. — Documented in `src/quarantine.cjs`: rename-aside and post-move verification; Node cannot take a Windows deny-share lock.
- [x] **R04.2** Verify the moved/copied result before declaring it the detected content; preserve unexpected content in a recoverable state. — A mismatched move becomes `recovery-needed` with `storedSha256` recorded.
- [x] **R04.3** Never delete a path solely because a previously opened file at that path had the expected hash. — The original is renamed aside and re-verified before removal; unexpected content is put back.
- [x] **R04.4** Evaluate a narrowly scoped native helper only if stable Windows handle operations are necessary. Do not elevate the Electron renderer. — Evaluated: not needed for the current same-user design; revisit if a service is introduced.
- [ ] **R04.5** Inject mutation at each await boundary: replace, rename, hard-link, reparse-point substitution, truncate, and append. Test both same-volume and cross-volume flows. — **Partial:** content replacement is injected before the same-volume move and before cross-volume removal, and both are tested. Rename-into-place, hard-link, reparse-point substitution, truncate, and append at every await boundary are not yet covered (these need a Windows VM fixture).

**Acceptance:** Every committed record describes the bytes actually retained. Ambiguous concurrent changes preserve content and stop destructive continuation.

### R05 — Log failure can leave scanner stdout permanently paused

**P1 · Reproduced stream state**  
Location: `src/scanner.cjs:65`.

Backpressure pauses stdout and resumes it only on `drain`. When the log errors while stdout is paused, the error handler sets `logFailed` but never resumes stdout. A real child can then block on a full pipe. The controlled probe confirmed the stream stays paused after the log error; a long-running real-process reproduction remains to be added.

- [x] **R05.1** Centralize flow control for stdout and stderr; resume every paused stream on log failure/closure/cancellation. — The stream that caused backpressure is paused; all paused streams resume on drain, error, close, or cancel.
- [x] **R05.2** Ensure output parsing and detection processing continue when diagnostic logging becomes unavailable. — Parsing continues and `result.logError` records the lost log.
- [x] **R05.3** Bound stderr buffering too; the current write path pauses stdout even for stderr pressure. — stderr pressure pauses stderr, not stdout; line frames are capped.
- [x] **R05.4** Test backpressure → ENOSPC, backpressure → EIO, close before drain, simultaneous stderr bursts, and cancellation while paused. — `test/scanner.test.cjs` (ENOSPC, EIO, close before drain, stderr burst, cancel while paused).

**Acceptance:** A diagnostic sink failure cannot deadlock the scanner. The final report clearly records the lost log without losing parsed detections.

### R06 — Crash recovery depends on a capped diagnostic log

**P1 · Reproduced evidence gap; crash consequence follows recovery code**  
Locations: `src/scanner.cjs:65`, `src/main.cjs:137`, `src/main.cjs:535`, `src/main.cjs:576`.

During a scan, new detections stay in the scanner's in-memory result. They enter the independent detection store only at completion. Interrupted recovery reparses the human-readable log, but that log stops accepting output after its size cap. The probe produced a detection in memory after the cap with no corresponding recovery-log entry. A crash then loses that detection.

- [x] **R06.1** Persist structured detection events incrementally in a dedicated journal, independent of diagnostic-log retention. — `src/journal.cjs`, checksummed NDJSON with fsync per record.
- [x] **R06.2** Assign stable event IDs and sequence numbers; replay idempotently after restart. — Event ids, sequence numbers, and checksums; replay is idempotent.
- [x] **R06.3** Establish an acknowledgement boundary: do not describe a detection as durably recorded before persistence succeeds. — A detection counts only after its journal write succeeds.
- [x] **R06.4** Make journal-capacity failure an explicit degraded state; pause or stop safely if critical evidence cannot be retained. — A journal failure (including the size limit) stops the scan with an explicit error and a storage notice.
- [x] **R06.5** Test a detection after the log cap, a failed log writer, crash immediately after detection, and repeated replay without duplicate sightings. — `test/journal.test.cjs`, plus a two-launch smoke scenario that exits abruptly after a real journaled detection and then recovers it.

**Acceptance:** Every acknowledged detection survives restart even when verbose logs are disabled, truncated, or unavailable.

### R07 — Saving recovered state can destroy the only valid backup

**P1 · Reproduced with an injected rename failure**  
Locations: `src/store.cjs:81`, `src/store.cjs:144`, startup `loadAll()`.

Starting with a corrupt primary and a valid backup, load correctly restores the backup. Saving that recovered value copies the corrupt primary over the valid backup before promoting the new temporary file. If promotion fails, the temporary file is deleted and both normal recovery candidates are corrupt. The probe's previously valid backup ended up containing `broken`.

- [x] **R07.1** Track which generation was validated and recovered; never rotate an unvalidated primary over a known-good backup. — The primary is rotated into `.bak` only if the primary itself is valid.
- [x] **R07.2** Use generation files plus a committed manifest, or an equivalent tested recovery protocol. Retain a verified generation until replacement is durable. — Protocol: `.tmp` generation (fsync) → rotate a valid primary → promote; load picks the newest valid candidate. A manifest was not needed for this equivalent protocol.
- [x] **R07.3** Preserve a valid newly written temp/generation when promotion fails instead of automatically deleting the only fresh good copy.
- [x] **R07.4** Test recover-from-backup → primary-save failure at every step → repeated restart. — `test/store.test.cjs` fails each save step after a backup recovery and restarts twice.
- [x] **R07.5** Treat unsupported newer schemas as read-only/recovery mode. The current startup can save defaults over the active newer-schema file after preserving a side copy. — Newer-schema files are read-only; saves throw `EREADONLY` and the file is untouched.

**Acceptance:** Any failed save leaves at least one discoverable validated generation. Normal startup does not require a developer to locate preserved files manually.

### R08 — Quarantine activity is outside the global operation coordinator

**P1 · Code-confirmed; full shutdown race needs fault-injection test**  
Locations: `src/main.cjs:63`, quarantine IPC handlers, `shutdown()`; private queue in `src/quarantine.cjs`.

`busy()` and shutdown track scans, updates, and installation, but not quarantine/restore/recovery or identity hashing. The quarantine queue serializes its own operations only. A scan can start while a long file move/restore is active; quitting does not await that operation. Journaling helps after interruption but is not a substitute for coordinating normal execution.

- [x] **R08.1** Expose active operation handles and a drain/cancel contract from the quarantine manager. — File operations run through the coordinator (`src/operations.cjs`), which provides active handles and a bounded drain.
- [x] **R08.2** Define a conflict matrix across scan, verify, update, install, hash, quarantine, restore, migration, and shutdown. — Symmetric matrix over scan, update, install, verify, file, and identify, tested for every pair.
- [x] **R08.3** Acquire/revalidate permission to execute after confirmation dialogs, not only before opening them. — Permission is acquired after dialogs and state is revalidated.
- [x] **R08.4** Stop accepting mutations once shutdown starts; await tracked operations or leave an explicit durable interrupted state. — Shutdown closes the coordinator and drains it (bounded); unfinished work stays journaled.
- [ ] **R08.5** Test quit during copy/restore/hash and a scheduled scan becoming due while a quarantine confirmation is open. — **Partial:** the dialog-then-scan ordering and draining a running file operation after shutdown are tested at coordinator level. Quitting the real app during a copy, restore, or hash is not yet exercised end to end.

**Acceptance:** Every operation that changes files has an owner, a durable ID, a conflict policy, and an explicit shutdown outcome.

### R09 — Multiple JSON files do not form a single transaction

**P1 · Code-confirmed failure windows; reproduce each before fixing**  
Locations: `persistQuietly()`, `finishScan()`, `recoverInterruptedScan()`, `loadAll()`.

Report, detections, scheduler outcome, and running-job marker are saved sequentially. Recovery may see a completed report alongside an old running marker, then classify the job as interrupted and count sightings again. A failure while saving the detection file after the report is saved can leave the report and review store inconsistent. The one-time legacy migration similarly spans multiple files with no committed migration generation.

- [x] **R09.1** Define a transaction boundary covering scan completion, detection observations, scheduler settlement, and clearing the running marker. — Scan commit covers the report, detections, scheduler settlement, jobs, and journal removal.
- [x] **R09.2** Use a replayable transaction journal or a carefully evaluated transactional store; do not assume atomic rename of each file makes the group atomic. — The journal is the replayable transaction log; it is deleted only after the stores are saved.
- [x] **R09.3** Add operation IDs and deduplication keys so recovery cannot increment sightings or resettle jobs twice. — Report upsert by id, one sighting per scan, one settlement per job id, and stable event-derived detection ids.
- [x] **R09.4** Journal migrations with explicit source/target generations and a completion marker. Test a restart after each individual persisted file. — Save order plus deterministic derivation; `test/state.test.cjs` restarts after each of the 7 saves.
- [x] **R09.5** Verify every report-to-detection and detection-to-quarantine link on startup, repairing conservatively and surfacing ambiguity. — `verifyLinks()` runs at startup.

**Acceptance:** Every persisted mixture produced by interruption converges to the same result as uninterrupted completion, or a clearly identified recovery-needed state.

### R10 — Recovery-needed entries have no working refresh path

**P2 · Code-confirmed**  
Locations: `src/quarantine.cjs:215`, `src/quarantine.cjs:305`.

`resolve()` tells the user to restart when files change after review, but `recover()` skips records already in `recovery-needed`. Restart therefore does not perform the promised recheck. Restore errors and `saveError` also have inconsistent persistent UI treatment.

- [x] Add a non-destructive `recheck(id)` operation for every review state; regenerate valid actions from current evidence. — `quarantine.recheck()`; startup recovery also rechecks records waiting for review.
- [x] Expose the action in the UI and test stale finish/undo decisions followed by recheck. — Recheck button; `test/quarantine.test.cjs` (R10).
- [x] Present recoverable storage errors consistently after quarantine, restore, and recovery; a toast is not durable state. — `saveError` shown persistently on the item; failures also become storage notices.
- [x] Keep “dismiss” distinct from “resolved” and retain location/identity evidence after dismissal. — `reviewed` keeps paths and hashes and can be rechecked.

### R11 — Persisted paths and nested schemas need stronger validation

**P2 · Code-confirmed trust-boundary gap**  
Locations: `src/schemas.cjs`, stored-file operations in `src/quarantine.cjs`, report-log paths in `src/main.cjs`.

Several consequential values are validated only as strings or arrays: stored quarantine paths, report IDs, audit entries, hashes, options, cached database verification, and job target fields. A valid JSON envelope is not proof those values are safe. This is principally corruption/robustness hardening in the current same-user app; it becomes a much larger security boundary if a privileged service is added.

- [x] Derive internal vault/log paths from validated IDs rather than trusting stored absolute paths. — Vault paths derive from the record id; journal and log ids are UUID-validated.
- [x] Reject path traversal, unexpected drive/UNC forms, device paths, invalid UUIDs, malformed hashes, and external vault paths. — Schema `winPath`, `sha`, and `uuid` checks; restore targets are validated.
- [ ] Resolve and validate parent paths/reparse-point behavior before any deletion or restore operation. — **Partial:** not implemented. Restore recreates a missing parent folder, but reparse points on parent paths are not resolved or checked.
- [ ] Validate nested objects, counts, limits, timestamps, enum values, and audit entries; normalize only documented legacy shapes. — **Partial:** hashes, options, audit entries, the verification cache, and threat links are validated. Some nested report fields pass through unchecked.
- [ ] Test malformed-but-parseable files and guarantee the recovery UI itself does not throw. — **Partial:** store-level malformed fixtures are tested (`test/store.test.cjs`). The recovery UI is not tested against them.

### R12 — An uncaught exception logs and continues normal operation

**P1 · Code-confirmed**  
Location: `src/main.cjs:872`.

The handler records an error and notifies, but leaves the potentially inconsistent process alive. This is particularly risky while coordinating destructive file operations. Node's documentation explicitly warns against resuming normal operation after an uncaught exception.

- [x] Enter a fatal/degraded state that rejects new mutations, performs minimal bounded cleanup, preserves diagnostics, and exits nonzero. — `src/fatal.cjs`.
- [x] Avoid complex asynchronous recovery in a process whose invariants may already be broken; recover on a clean restart. — Recovery happens on the next start from journals.
- [x] Bound restart attempts and prevent crash loops. Distinguish expected operation failures from genuinely fatal faults. — Three quick startup crashes start the next launch in safe mode.
- [ ] Test thrown completion callbacks, rejected startup promises, renderer crashes, and disk failures during fatal logging. — **Partial:** the handler is unit-tested (including disk failure while logging) and a smoke scenario throws a real uncaught fault. Renderer-crash reload and rejected startup promises in the real app are not yet exercised.

### R13 — Recovery and update diagnostics still have unbounded memory paths

**P2 · Code-confirmed**  
Locations: interrupted scan `readFileSync(...).slice(...)`, FreshClam `output += ...`, state IPC, synchronous store writes.

Slicing after `readFileSync` does not bound the read. FreshClam's complete output accumulates even though the displayed tail is capped. Full state publications serialize potentially large histories, detection sets, and quarantine lists; frequent storage errors also accumulate without a bound. Synchronous JSON serialization/fsync/backoff can stall the main process.

- [x] Stream interrupted recovery with a true read bound; replace log reparsing with R06's structured journal. — The journal replaces log re-parsing; legacy recovery uses a bounded read.
- [x] Bound updater buffers and retain structured error facts plus a ring-buffer tail. — FreshClam output keeps a 64 KB tail.
- [ ] Page large collections over IPC, publish small typed events, and virtualize large UI lists. — **Partial:** not started. Full state is still published on changes, though progress uses small events.
- [ ] Deduplicate/bound storage issues and clear them only after a successful repair/retry, not merely a dismiss action. — **Partial:** issues are deduplicated and capped at 20. Dismiss still clears them rather than waiting for a successful repair.
- [ ] Move expensive serialization, hashing coordination, and blocking storage retries off the main event loop with a measured design. — **Partial:** not started. Hashing is streamed and async, but JSON saves are still synchronous on the main thread.

### R14 — Error diagnostics are pruned as though they were scan logs

**P2 · Code-confirmed**  
Location: `pruneLogs()` in `src/main.cjs:452`.

Any `.log` not linked to a retained report is removed. That includes `app-errors.log`, which the fatal-error handler writes for diagnosis. Startup cleanup can erase the very evidence needed to investigate the prior failure.

- [x] Separate scan, application, update, and audit log namespaces and retention rules. — `logs/scans` and `logs/app`; journals are separate.
- [x] Preserve a bounded crash diagnostic history and link it to recovery sessions. — Size-rotated `logs/app/errors.log` plus the crash marker.
- [x] Test that report cleanup removes only owned report logs and never crash diagnostics or active journals. — `test/logs.test.cjs`.

### R15 — Signature verification is not synchronized with database replacement

**P2 · Code-confirmed design gap; exercise with delayed verifier**  
Locations: `refreshDatabase()` and signature-update lifecycle.

Verification can inspect files while FreshClam changes them. The code notices fingerprint changes and discards results, but does not reliably schedule a new verification once the old promise clears. Readiness may remain unknown while scans are permitted. The fingerprint uses size and mtime, not content or a managed immutable database generation. Only known database filenames are included, although an engine can load additional supported database files from the directory.

- [ ] Coordinate verification and replacement using generation IDs; automatically verify the latest generation after a superseded check. — **Partial:** the coordinator prevents verification during an update, and a superseded check re-runs for the new files. The generation is still a size-and-mtime fingerprint, not a managed immutable generation.
- [ ] Record the full effective database set, including explicitly supported custom signatures, and explain its trust model. — **Partial:** not done. Only main, daily, and bytecode are inventoried.
- [ ] Test updater/verifier overlap, changed timestamps, missing sigtool, timeout, `.cvd`/`.cld` transitions, and compatibility with a new engine. — **Partial:** not yet tested with a delayed verifier.
- [x] Keep “cryptographically verified archive” separate from “engine successfully loaded this exact database set.” — `verified` (sigtool) and `loadFailed` (engine load) are separate states.

### R16 — Current UI and tests hide important product-level gaps

**P2 · Observed UI / code-confirmed / design gap**

- [x] Preserve unsaved settings across navigation or ask Save/Discard; current navigation replaces `draft` silently. — Save, Discard, or Stay banner; checked in the smoke test.
- [x] Make a health-state transition visible even while a report is expanded; do not replace the entire DOM or reset reading position to do it. — Header health badge.
- [x] Revalidate capability before acting on a stale button. Show why an action is unavailable rather than just rejecting after a click. — The main process revalidates every action; disabled buttons explain why.
- [ ] Increase secondary text sizes, improve high-DPI/minimum-window behavior, and validate screen reader/reduced-motion support. The rendered dashboard still uses very small supporting text. — **Partial:** text sizes raised and reduced motion supported. Screen-reader, high-DPI, and minimum-window validation are not yet done.
- [x] Update health when time crosses a freshness threshold even if no scan/update/state event occurs. — Republished every minute when the assessment changes.
- [ ] Test assembled flows, not just function outputs: first run → download failure → retry → verification → scan → detection → quarantine → restart → restore. — **Partial:** the smoke tests cover scan → detection → shutdown, crash → recovery, and the healthy state. The first-run download → retry → quarantine → restart → restore flow is not yet assembled.
- [ ] Add CI jobs for UI/real-engine checks and clean Windows installation; the current workflow still runs only unit tests and packaging before uploading an artifact. — **Partial:** CI now runs formatting, unit tests, and the smoke scenarios as separate stages. Real-engine fixtures and clean-Windows installation are not in CI.

---

## Part II — ten quality multipliers

These are engineering programs, not ten unrelated feature piles. Reuse the prior backlog for feature detail; use this document to choose architecture, prove invariants, and measure quality. Each program needs an owner, a design note, reproducible acceptance fixtures, and a release gate.

### Q1. An operation system instead of scattered busy flags

**Outcome:** Every user action and background action has a lifecycle the UI can explain and recovery can reconstruct.

- [ ] Define a common operation record: ID, type, initiator, resource claims, phase, generation, timestamps, cancellation policy, recovery policy, and outcome.
- [ ] Introduce a coordinator with explicit conflicts: database mutation vs scan, file restore vs scan of that file, shutdown vs every mutation, and migration vs all state access.
- [ ] Separate accepted, queued, starting, running, cancelling, finishing, succeeded, failed, and recovery-needed states.
- [ ] Provide cancellation semantics per phase; do not claim a request succeeded merely because a signal was sent.
- [ ] Treat a native dialog as a pause before authorization, not a lock on changing application state.
- [ ] Make the headless runner and Electron app use the same coordinator contract, including a cross-process lock/lease with stale-owner recovery.
- [ ] Expose a user-readable operations panel: what is happening, what is waiting, why, and what can be safely cancelled.

**Gate:** A conflict-matrix test suite demonstrates that incompatible operations never overlap, including after a crash or across processes.

### Q2. Evidence that survives crashes

**Outcome:** The app never forgets an acknowledged detection or silently rewrites history.

- [ ] Design an append-only critical-event journal with stable IDs, bounded records, versioning, checksums, and replay rules.
- [ ] Materialize reports, detection views, job summaries, and audit views from committed events or transactional state.
- [ ] Distinguish diagnostic logs from security evidence; retention for one must not dictate retention for the other.
- [ ] Make storage exhaustion visible before critical evidence cannot be committed; offer a safe read-only/recovery mode.
- [ ] Preserve observation time, engine/database generation, target/profile revision, user decision, and content identity when known.
- [ ] Write a migration/rollback protocol before choosing JSON generations versus SQLite. Benchmark both instead of adopting storage machinery for appearance.
- [ ] Export a human-readable report and a machine-readable evidence bundle with a declared schema and privacy controls.

**Gate:** Kill the process after every durable boundary; replay produces exactly one observation/decision per acknowledged event.

### Q3. Content-safe file handling

**Outcome:** Every quarantine and restore action preserves a verified recovery path through concurrency and failure.

- [ ] Write an invariant table for each operation: which copies exist, which hashes are known, which locations may have changed, and which deletion is permitted.
- [ ] Identify files by content revision and stable filesystem identity where available, not path alone.
- [ ] Make failed identity checks lead to review, not broad deletion or silent acceptance.
- [ ] Protect the managed vault with deliberate ACLs and a reviewed storage format; state its limits against same-user malware.
- [ ] Add a safe recovery browser for ambiguous copies, verified restore-to-new-location, and duplicate handling.
- [ ] Review hard-link publication and file metadata/ACL behavior on NTFS, exFAT, removable media, network locations, and redirected folders.
- [ ] Build a fault harness that can mutate files at every asynchronous boundary without using real malware.

**Gate:** No injected failure or mutation loses unique content in the controlled corpus; every ambiguous outcome is explicitly visible.

### Q4. Explainable scan coverage

**Outcome:** “Completed” tells the user what was inspected, what was skipped, and what remains uncertain.

- [ ] Represent a scan plan as an immutable target manifest, profile revision, exclusions, engine options, and database generation.
- [ ] Distinguish process outcome, threat outcome, and coverage outcome instead of packing all three into `completed`/`partial`.
- [ ] Track target-level accessibility and warning categories. Do not invent exact per-file coverage where ClamAV does not report it.
- [ ] Investigate ClamAV limit alerts and encrypted-file reporting. Classify limit alerts as coverage conditions rather than automatically treating every alert as malicious content.
- [ ] Explain overlapping scans and any supersession rule with a concrete coverage relation.
- [ ] Add actionable skipped-location review and an optional rescan of the accessible subset after permissions or connectivity change.
- [ ] Build regression fixtures for nested archives, encrypted containers, large files, invalid formats, offline placeholders, and redirected locations.

**Gate:** Reports never present unsupported certainty; a clean small custom scan cannot substitute for a full-device coverage statement.

### Q5. Windows-native reliability with a small privilege boundary

**Outcome:** The user's schedule remains dependable across normal Windows usage without turning Electron into a privileged service.

- [ ] Build the shared headless runner and Task Scheduler integration from the earlier backlog after Q1/Q2 are stable.
- [ ] Test missed triggers, battery policies, long sleep, DST, timezone travel, fast user switching, sign-out, and execution after an app update changes paths.
- [ ] Show registration drift: the app must detect when Windows tasks/startup entries were disabled externally.
- [ ] Decide explicitly which work is per-user and which would require a service; retain per-user operation unless the product requirement justifies more.
- [ ] If a service becomes necessary, define authenticated IPC and a tiny command surface; subject that boundary to separate review.
- [ ] Add safe Explorer scan actions, a taskbar/tray status model, useful notification actions, and tested uninstall cleanup.
- [ ] Never disable Microsoft Defender or imply Windows Security registration merely because the app has a shield icon.

**Gate:** A clean-VM matrix proves the advertised schedule behavior with the UI open, hidden, closed, restarted, and updated.

### Q6. Updates as recoverable transactions

**Outcome:** Definitions, the ClamAV engine, and Sentinel itself each have a safe independent update lifecycle.

- [ ] Stage, verify, health-check, commit, and retain rollback generations for managed engine/app updates.
- [ ] Preserve a known-good engine until the replacement successfully loads the effective database and passes a controlled scan.
- [ ] Model download trust, transport errors, integrity checks, compatibility, and runtime health as separate gates.
- [ ] Bound retry state and buffers; persist cooldowns; support cancellation without abandoned processes or artifacts.
- [ ] Provide clear version/build/channel information and a safe response when an update is blocked by an active operation.
- [ ] Sign production artifacts, protect release credentials, publish checksums/provenance, and verify installer upgrades in CI/VMs.
- [ ] Make rollback of application code compatible with persisted schema versions, or prevent unsafe downgrade and offer recovery.

**Gate:** For every supported upgrade, failure before or after commit leaves either the previous working installation or a clear recoverable maintenance state.

### Q7. A calm, accessible decision interface

**Outcome:** Users understand what needs attention without reading engine logs or being frightened by unsupported claims.

- [ ] Give the overview one primary decision: set up, repair, review detections, scan, or observe progress.
- [ ] Make every health item answer: what was checked, when, what the evidence says, and the next useful action.
- [ ] Add explicit dirty settings, Save/Discard behavior, inline validation, and a live schedule preview.
- [ ] Use a stable view model/component update strategy; preserve focus, scroll, expanded reports, and input composition.
- [ ] Separate benign operational issues, stale definitions, unresolved detections, and failures of the app itself.
- [ ] Test font size/contrast, keyboard navigation, high contrast, reduced motion, screen readers, 200% scale, and 1366×768-class layouts.
- [ ] Add redacted diagnostics export, persistent repair cards, contextual help, and a clear local-only privacy explanation.
- [ ] Introduce dark mode/localization only after the same states work correctly and accessibly in the default theme.

**Gate:** A fresh user can complete setup, understand a partial scan, and recover a quarantined file without manually locating logs or interpreting a raw exit code.

### Q8. Performance backed by workload measurements

**Outcome:** Sentinel stays responsive and quiet even when ClamAV is busy or the device contains a large history.

- [ ] Define reference hardware and benchmark fixtures before promising budgets.
- [ ] Measure cold/warm startup, UI event-loop lag, idle CPU/RAM, update peak RAM, database verification time, and scan wrapper overhead.
- [ ] Test 10,000 detection records, 200 large reports, a million-file output stream, and a 24-hour mock scan without unbounded growth.
- [ ] Page data over IPC and virtualize large lists; avoid serializing the entire store every progress tick.
- [ ] Bound every accumulator, queue, line frame, diagnostic tail, retry list, and retained record class.
- [ ] Explore optional `clamd` only through a measured comparison with explicit resident-memory and local-interface tradeoffs.
- [ ] Consider incremental scan caching only with correct invalidation on content, engine, signatures, and profile changes; never trade away coverage for an attractive benchmark.

**Proposed gates, to calibrate on reference hardware:** p95 ordinary UI action under 100 ms excluding deliberate disk/network operations; scan-progress paint within 500 ms; no monotonically growing idle heap over an eight-hour soak; no lost events during backpressure. These are targets, not measured current performance.

### Q9. Test the product, not the reassuring test names

**Outcome:** Tests make unsupported assumptions fail loudly before users encounter them.

- [ ] Review tests that encode questionable policy, particularly “partial results count as success” and “full scan covers quick.” Specify the policy first.
- [ ] Add property/model-based tests for schedules, state transitions, and recovery idempotence with deterministic seeds.
- [ ] Add fault injection at filesystem, stream, process, IPC, clock, and transaction boundaries.
- [ ] Run selected mutation testing to ensure removing verification, conflict checks, or persistence acknowledgement causes failures.
- [ ] Test main-process orchestration using injected adapters rather than relying exclusively on a happy-path smoke run.
- [ ] Make fixtures reproducible from a clean checkout, with verified engine sources and an explicit optional/required test policy.
- [ ] Exercise an intentionally failing smoke test in CI to verify it exits nonzero; do not infer failure propagation from `process.exitCode` alone.
- [ ] Add clean VM install/upgrade/uninstall, controlled crash/restart, and long-run suites as separate pipeline stages with retained evidence.

**Gate:** Every P1 regression has a targeted test plus an assembled-flow test; critical suites cannot silently skip and still satisfy the release gate.

### Q10. A trustworthy release and support system

**Outcome:** A downloadable version has a traceable source, known compatibility, recoverable upgrades, and honest support information.

- [ ] Maintain a release manifest connecting source commit, build environment, dependency inventory, artifact hashes, signing status, supported OS/architecture, and schema range.
- [ ] Separate source push, CI artifacts, prereleases, and user-ready releases in both workflow and wording.
- [ ] Publish release notes with changes, migration behavior, tests performed, remaining limitations, and rollback instructions.
- [ ] Keep crash diagnostics and user-support bundles local by default; offer an inspect/redact step before export.
- [ ] Define supported Windows/ClamAV versions and an end-of-support/update policy.
- [ ] Add a maintenance mode for corrupted/future-schema state, with backup selection and export before repair.
- [ ] Add a release-blocker ledger so an unresolved P1 cannot be hidden behind a version bump or large passing test count.

**Gate:** A release can be reproduced and its claims traced to verification evidence. No production signing keys or sensitive local data enter the repository.

---

## Part III — implementation architecture and sequencing

### Proposed boundaries

```text
Electron views + narrowly typed preload
                 |
          application commands
                 |
     operation coordinator / capabilities
        /          |           \
 scan adapter  update manager  file-operation manager
        \          |           /
       durable events + transaction boundary
                 |
 materialized reports / detections / jobs / health
                 |
      headless runner + Windows integration
```

This is a logical boundary map, not a mandate for separate OS processes everywhere. Keep the smallest architecture that establishes the invariants. The UI should never be the source of truth for whether an operation may run.

### Canonical records to specify before a storage rewrite

| Record                 | Identity and key facts                                                | Required invariants                                            |
| ---------------------- | --------------------------------------------------------------------- | -------------------------------------------------------------- |
| Operation              | immutable ID, type, initiator, phase, resource claims, outcome        | one owner; cancellation and terminal result are explicit       |
| Scan plan              | targets, exclusions, engine/options/profile revisions                 | recorded scope matches actual launched arguments               |
| Observation            | event ID, scan ID, signature, path, time, content revision when known | replay does not duplicate; acknowledged events survive crashes |
| File revision          | content hash, stable file identity where available, provenance        | path reuse does not mean same content                          |
| Detection case         | observations, current status, review decisions                        | unresolved evidence is not pruned with reports                 |
| Quarantine transaction | intent, verified copies, source identity, phase, decision             | deletion requires a verified retained copy and valid identity  |
| Database generation    | effective file set, validation, engine compatibility, version/build   | verification and scanning refer to the same defined generation |
| Scheduled obligation   | occurrence, attempt history, required scope, retry policy             | failed attempt and satisfied coverage are distinct             |
| Health snapshot        | timestamp, checks, evidence, limitations, available actions           | every green assertion is justified by current evidence         |

### Phase A — safety and consistency patch

1. R05 stream recovery and R07 backup preservation.
2. R01 capability/readiness unification and R02 observation identity refresh.
3. R06 durable detection events and R09 completion/migration transaction boundaries.
4. R04 file-operation identity guarantees and R08 coordinator ownership.
5. R03 coverage-aware supersession, R10 recovery recheck, R12 fatal-state policy.

Deliver regression tests and evidence with each patch. Do not wait for the complete architecture program before fixing local, well-understood defects.

### Phase B — durable background product

1. Finish coordinator and event/store contracts.
2. Add reproducible headless execution and Windows scheduling with cross-process ownership.
3. Add database generation management, transactional updates, and structured coverage reporting.
4. Add assembled recovery tests and clean Windows install/upgrade/reboot verification.

### Phase C — user-ready distribution and polish

1. Signed releases and updater compatibility, tested schema migrations, rollback/recovery UI.
2. Accessible decision-focused dashboard, detection case view, stable settings UX, and useful diagnostics.
3. Measured performance and soak tests; broaden supported platforms only when the matrix passes.

### Phase D — ambitious options with separate design approval

- Optional always-resident ClamAV daemon for measured latency benefits.
- Opt-in selected-folder event-triggered scans, honestly labeled as limited watching rather than comprehensive real-time interception.
- Optional enterprise policy import/deployment documentation.
- Any privileged service, fleet management, cloud analysis, Windows Security registration, or kernel interception requires a separate threat model and explicit product scope. Do not introduce these merely to satisfy an ambitious roadmap.

## Release scorecard — proposed criteria, not current claims

| Dimension            | Minimum release evidence                               | Strong quality target                                                               |
| -------------------- | ------------------------------------------------------ | ----------------------------------------------------------------------------------- |
| Content preservation | all R04/R07/R08 fault fixtures pass                    | thousands of deterministic mutation/failure sequences with zero unique-content loss |
| Detection durability | detection survives cap, log error, crash, replay       | no missing or duplicated acknowledged observations under crash fuzzing              |
| Schedule correctness | retries/cancellation/DST/resume covered                | model-based obligation tests plus VM task-registration/upgrade runs                 |
| Health honesty       | full capability matrix tested                          | UI, tray, notifications, and IPC decisions derive from one snapshot                 |
| Storage resilience   | schema, migration, backup and ENOSPC tests             | every partial commit state recovers deterministically                               |
| Responsiveness       | representative histories and output bursts             | calibrated latency/memory budgets enforced against regression                       |
| Accessibility        | keyboard, contrast, scale and reduced-motion checks    | manual screen-reader acceptance across primary flows                                |
| Install/update       | clean non-admin install and prior-version upgrade      | rollback/interruption matrix for app, engine, and definitions                       |
| Security posture     | renderer isolation, validated IPC, reviewed file paths | explicit threat model, dependency/release controls, independent boundary review     |
| Supportability       | persistent errors, local redacted export, changelog    | reproducible incident bundle and documented repair path for every recovery state    |

## Test campaign to add before calling this production-ready

- [ ] **Crash ladder:** terminate after each operation/journal/commit phase; restart twice; compare to invariant oracle.
- [ ] **Disk ladder:** fail each write/copy/fsync/rename/unlink independently, then fail a second step during recovery.
- [ ] **Identity ladder:** rename/replace/append/truncate at every await boundary; include hard links and reparse points in a disposable Windows VM.
- [ ] **Stream ladder:** split Unicode/newlines arbitrarily, flood stderr, remove log sink under backpressure, exceed log caps, truncate final output.
- [ ] **Time ladder:** DST, timezone switch, clock reversal, future timestamps, overdue full and quick, long scan crossing multiple occurrences.
- [ ] **Concurrency ladder:** dialogs + scheduler, update + verification, scan + restore, shutdown + hashing, two runner instances + app startup.
- [ ] **Migration ladder:** 1.0.x → 1.1.x → proposed version, interruption at every persisted store, future schema opened by old app, backup-only recovery.
- [ ] **Scale ladder:** empty state, many observations of one file, many unresolved files, huge audit history, full storage issue list, large but bounded logs.
- [ ] **Windows ladder:** non-admin, redirected folders, non-ASCII user, removable/exFAT media, offline share, missing engine runtime, externally disabled scheduled task.
- [ ] **Release ladder:** verify signatures/hashes, install/repair/upgrade/uninstall, retained quarantine choice, task cleanup, version metadata consistency.

## Instructions for the implementing agent

1. Recheck HEAD and reconcile this document with already-completed work. Reference ticket IDs in commits and completion notes.
2. Work only in the nested `sentinel-av` repository; verify git root before committing. Preserve unrelated changes and the original backlog.
3. Convert each reproduced probe into a regression test before fixing it. Avoid tests that simply restate the new code's branch conditions.
4. Never use live user quarantine data or real malware as test fixtures. Use disposable directories and harmless signatures; do not disable other antivirus software.
5. Keep completed/newly verified/inferred/blocked work distinct. Do not mark a fault path fixed solely because the original happy-path smoke test passes.
6. Avoid broad rewrites until the data and operation contracts are explicit. Add one architectural boundary with its callers and tests at a time.
7. Keep publication, signing prerequisites, and service privilege decisions visible. Do not embed credentials, force-push shared history, or claim a CI artifact is a published release.
8. The GitHub CLI is not installed on this machine; use git and the GitHub REST API when appropriate, without exposing tokens.
9. Keep this file as the second-review delta and quality program. Link overlapping tasks back to `CLAUDE_TODO.md` rather than duplicating conflicting instructions.
10. End each milestone with actual tests run, failures encountered, remaining limitations, commit IDs, artifact paths, and the release scorecard status.

## Primary references checked or provided for implementation

- [Node process error handling](https://nodejs.org/api/process.html): guidance on unrecoverable uncaught exceptions. The documentation states, “It is not safe to resume normal operation after 'uncaughtException'.”
- [Node filesystem APIs](https://nodejs.org/api/fs.html): review current handle, rename, stream, and race-condition behavior for the bundled Node version before implementation.
- [ClamAV scanning](https://docs.clamav.net/manual/Usage/Scanning.html): scanner behavior, options, limits, and daemon tradeoffs.
- [ClamAV scanner option definitions](https://github.com/Cisco-Talos/clamav/blob/main/clamscan/clamscan.c): inspect `--alert-exceeds-max` and classify limit alerts deliberately; do not equate all such alerts with malware.
- [Electron security](https://www.electronjs.org/docs/latest/tutorial/security): preserve sandboxing and narrow privilege boundaries.
- [Windows missed-task behavior](https://learn.microsoft.com/en-us/windows/win32/taskschd/taskschedulerschema-startwhenavailable-settingstype-element): verify scheduler integration against current Windows documentation.

These are references, not substitutes for tests against the actual shipped Electron/Node/ClamAV/Windows versions.

## Part IV — multi-engine detection and analysis implementation plans

**Added at the user's explicit request:** YARA, Loki, combined ClamAV + YARA scanning, capa, and the exclusion of proprietary Sigcheck from the open-source core. These are implementation plans; none of these integrations is claimed to exist in version 1.1.0.

### Product decisions and current upstream status

| Component     | Role in Sentinel                                         | Default product behavior                                     | Upstream decision to verify before shipping                                                                |
| ------------- | -------------------------------------------------------- | ------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------- |
| ClamAV        | Scheduled/on-demand antivirus scanning                   | Required base engine                                         | Preserve its definition updates and existing scan profiles                                                 |
| YARA          | Custom, curated, and threat-family content rules         | Recommended optional enhanced scanning module                | Classic YARA is in maintenance mode; evaluate YARA-X compatibility before choosing a long-term backend     |
| ClamAV + YARA | Complementary observations over a declared target scope  | Enhanced profile once the YARA pack is installed and enabled | Separate provider results, rule lineage, coverage, and failures                                            |
| Loki          | Focused IOC/threat-hunting workflows                     | Optional advanced, user-triggered hunts                      | Original Python Loki is deprecated; evaluate Loki-RS rather than silently building on obsolete assumptions |
| capa          | Static executable-capability enrichment                  | On-demand analysis of selected supported files               | Use supported standalone builds and versioned JSON output; preserve limitations                            |
| Sigcheck      | Publisher/signature context if ever separately requested | **Excluded from the open-source core and its installer**     | Proprietary Sysinternals licensing; no dependency or automatic download in the open-source edition         |

Upstream facts checked on 2026-09-27:

- Classic YARA's repository identifies its license as BSD-3-Clause and states it is in maintenance mode. The project points to YARA-X; this calls for a backend decision, not an untested claim that all rules and modules are interchangeable. [YARA repository](https://github.com/VirusTotal/yara), [YARA-X announcement](https://virustotal.github.io/yara-x/blog/yara-x-is-stable/).
- The original Python Loki repository declares deprecation and points to Loki-RS. Its GPL-3.0 licensing and its indicator/rule sources need explicit distribution review. Neither the old Python CLI nor its feature set should be assumed to describe the Rust successor. [Original Loki](https://github.com/Neo23x0/Loki), [Loki-RS](https://github.com/Neo23x0/Loki-RS).
- capa is an Apache-2.0 capability-analysis project with standalone binaries; JSON output is available via `-j`. Capability matches are analysis evidence, not a malware verdict. Packed/obfuscated files and some packaged applications can yield incomplete or misleading analysis. [Repository](https://github.com/mandiant/capa), [installation](https://github.com/mandiant/capa/blob/master/doc/installation.md), [usage](https://github.com/mandiant/capa/blob/master/doc/usage.md), [limitations](https://github.com/mandiant/capa/blob/master/doc/limitations.md).
- Sigcheck is distributed under the Sysinternals terms. It includes optional VirusTotal lookup/upload functions; Sentinel must not activate them as an incidental signature check. [Sigcheck documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sigcheck), [license terms](https://learn.microsoft.com/en-us/sysinternals/license-terms).

### E0 — shared provider architecture and distribution contract

**Dependency:** R01/R06/R08/R09 and the Q1/Q2 operation/evidence contracts. Do not multiply engines on top of unresolved evidence-loss or file-operation defects.

- [ ] **E0.1** Define a provider registry with IDs such as `clamav`, `yara-classic` or `yara-x`, `loki-python` or `loki-rs`, and `capa`. Keep product-facing feature names separate from backend IDs.
- [ ] **E0.2** Define a narrow adapter contract: discover/version, capabilities, validate configuration, compile/prepare rules if applicable, plan scope, run, cancel, normalize output, classify failure, and emit bounded diagnostics.
- [ ] **E0.3** Give every child process a tracked operation ID, bounded wall time/output/memory policy, deterministic working directory, restricted environment, and process-tree cleanup. Being a child process alone is not a security sandbox; evaluate Windows process isolation appropriate to parsing untrusted files.
- [ ] **E0.4** Keep native analyzers and their rule compilers outside the Electron renderer. Do not load arbitrary native plugins or execute user-authored scripts as a “rule” feature.
- [ ] **E0.5** Add a component manager showing installation source, version, architecture, hash, license/NOTICE, readiness, disk use, update channel, and supported ruleset versions.
- [ ] **E0.6** Pin approved runtime builds and verify artifacts. Never install arbitrary Python packages into the user's global Python environment. If a helper runtime is necessary, package and update it as an isolated, reviewed component.
- [ ] **E0.7** Create a per-component distribution record covering code, dependencies, rule packs, attribution, source availability, and redistribution obligations. Do not assume using a separate executable settles every licensing question or that a public GitHub rule is licensed for redistribution.
- [ ] **E0.8** Keep all analysis local by default. Record any provider feature that can use a network; forbid incidental telemetry, sample uploads, remote syslog, or external reputation queries in baseline profiles.
- [ ] **E0.9** Maintain independent runtime and rule-pack update generations. A running job must retain its pinned generation until it finishes.
- [ ] **E0.10** Add a compatibility matrix and conformance suite for each provider version. Unsupported backend/output/rule versions should fail clearly instead of being guessed at.

**Proposed result contract** — finalize as a versioned schema before implementation:

```text
ProviderObservation
  schemaVersion, observationId, parentJobId, providerRunId
  providerId, providerVersion, adapterVersion
  rulesetId, rulesetVersion, rulesetDigest, ruleOrigin
  targetId, targetKind, contentRevisionId, sha256 (when known)
  observedAt, completedAt
  category: signature_match | rule_match | ioc_match | capability | coverage_issue
  nativeRuleId, namespace, tags, nativeSeverityOrScore
  normalizedDisposition: informational | needs_review | detection
  evidence: structured, bounded, source-attributed fields
  limitations, warnings, coverageStatus, rawArtifactReference

ProviderRun
  requestedScope, effectiveScope, profileRevision
  outcome: succeeded | partial | failed | cancelled | unsupported | skipped
  matchCount, elapsedMs, limitsReached, errorCategory
```

Keep operational success separate from matching. Do **not** reuse ClamAV's exit-code interpretation for YARA, Loki, or capa. Establish each selected version's exit behavior with fixtures, including zero matches, matches, malformed input, timeout, and partial output.

**Acceptance:** All providers produce attributable events in the same durable pipeline while preserving their distinct meanings. Adding or disabling a provider cannot change unrelated engine settings or silently weaken an existing scan profile.

### E1 — YARA custom-rule and curated-rule scanning

#### E1A. Backend selection and delivery

- [ ] Compare classic YARA and YARA-X on the actual proposed rule corpus: syntax, modules, external variables, performance, output contracts, supported Windows builds, and known incompatibilities. Record the choice in an architecture decision.
- [ ] Support one production backend first. If classic compatibility mode is needed, expose it explicitly; do not silently route incompatible rules to a different engine.
- [ ] Prefer an isolated CLI/helper adapter for the first release. If the selected CLI lacks suitable structured output, implement a small reviewed helper that emits versioned JSON/NDJSON; do not rely on brittle whitespace splitting of paths and metadata.
- [ ] Install runtime/compiler artifacts through E0's component manager with integrity verification and rollback. A broken YARA update must not prevent ClamAV from running.
- [ ] Build a no-network runtime test and an installation cancellation/recovery test.

#### E1B. Rule-pack supply chain

- [ ] Define a manifest containing pack identity, publisher, source revision, content digests, license, engine compatibility, enabled modules, external-variable schema, and expected resource limits.
- [ ] Ship a small, reviewed initial pack with positive and negative fixtures. Do not begin by enabling every rule from an internet collection.
- [ ] Support user-imported `.yar`/`.yara` source through a native picker and a compile/validate preview.
- [ ] Resolve includes only inside the selected pack, with explicit confinement and size/depth limits. Reject traversal and unexpected external file dependencies.
- [ ] Compile in an isolated worker with resource limits. Show errors/warnings with source locations and preserve the previously working ruleset on failure.
- [ ] Accept compiled artifacts only when Sentinel generated them from the approved source and matching backend version; reject arbitrary downloaded compiled rules. YARA's documentation specifically warns about untrusted compiled rules. [CLI documentation](https://yara.readthedocs.io/en/stable/commandline.html)
- [ ] Namespace packs/rules to prevent collisions; distinguish upstream rules from local overrides.
- [ ] Support enable/disable, pack rollback, an intentional trusted-publisher policy, and a ruleset changelog/diff before activation.
- [ ] Cache compiled rules by source digest, compiler/runtime version, modules, and external-variable configuration, not just filename or mtime.

#### E1C. Execution and scope

- [ ] Enumerate targets through Sentinel's shared plan/exclusion policy so YARA does not accidentally follow a different set of junctions or scan the quarantine vault.
- [ ] Implement provider and job time budgets, maximum file size, controlled concurrency, rule/match limits, and explicit reporting of skipped or timed-out files.
- [ ] Separate file-content scanning from process-memory scanning; the initial integration is file-only and non-elevated.
- [ ] Avoid enabling a “fast scan” flag without confirming its semantic consequences for the chosen rule corpus.
- [ ] Do not assume YARA scans archive members because ClamAV does. Report outer-file versus member coverage separately. If archive expansion is added later, use confined extraction, traversal checks, expansion limits, depth limits, and verified cleanup.
- [ ] Bind matches to the actual content revision. If a file changes between providers, show distinct observations rather than presenting them as one file consensus.
- [ ] Use a bounded match-evidence policy; default to rule identity/metadata and offsets, with raw matched bytes optional and redacted on export.

#### E1D. Rules UI and acceptance tests

- [ ] Add a Rules page: installed packs, trusted source, version, enabled state, last update, validation status, and performance warnings.
- [ ] Add “Test rule” against a user-selected harmless fixture, with compile errors and a clear no-match/match/incomplete result.
- [ ] Display why a rule matched and where its classification came from. Rule names and metadata are untrusted content; escape them and do not convert an author's score into a malware probability.
- [ ] Add narrowly scoped suppressions by provider/rule/content revision, optionally expiring; never suppress the whole folder merely to quiet a single noisy rule.
- [ ] Test Unicode/spaces, duplicate rule IDs, include traversal, invalid source, untrusted compiled files, a slow pathological rule, unsupported modules, timeout with partial output, and cancellation.
- [ ] Maintain benign fixtures that deliberately match a training rule to prove that a rule match alone does not trigger automatic quarantine.

**Acceptance:** Users can install/import, validate, test, enable, update, and roll back rule packs. Every match has provider/ruleset provenance; malformed or slow rules cannot hang the desktop app or erase a working ruleset.

### E2 — ClamAV + YARA enhanced scanning

**Design intent:** Complementary inspection with shared evidence, not “two green badges mean safe.” YARA should inspect its declared target scope even when ClamAV has no detections; running it only after a ClamAV match would miss its main complementary value.

- [ ] Add an **Enhanced scan** profile with explicit provider requirements and per-provider target/size budgets. Preserve a clear ClamAV-only profile for users who do not install YARA.
- [ ] After module installation, offer daily quick/weekly full enhanced profiles rather than silently changing existing schedules or downloading extra engines without the user's choice.
- [ ] Build a parent job containing two provider runs and a shared immutable plan. Start sequentially by default; increase concurrency only after measuring I/O and memory contention.
- [ ] Run both engines against the same content revision when possible. If snapshots are used, confine/protect them and manage their lifecycle; if the source changes during sequential reads, label the comparison as non-identical.
- [ ] Keep independent provider completion, coverage, limits, and error status. “ClamAV completed; YARA timed out” is a partial enhanced scan, not a clean enhanced scan.
- [ ] Do not remove/quarantine a target before planned providers finish unless the user explicitly chooses a stop-and-quarantine action that records the remaining stages as cancelled/skipped.
- [ ] Group findings by content revision and location while retaining original signatures/rule IDs. Separate detections from heuristic/custom-rule matches and coverage alerts.
- [ ] Record rule lineage so the same YARA rule run standalone, through Loki, or through another supported engine path is not counted as independent corroboration.
- [ ] Use an explainable decision table, not summed arbitrary provider scores. A no-match from one engine does not negate a positive observation from another.
- [ ] Make optional-provider unavailability visible. Only allow fallback according to an explicit profile policy, and name the degraded scope in the report/notification.
- [ ] Reuse cached results only when content hash, provider/runtime, ruleset/database generation, and analysis settings all match.
- [ ] Make cancellation/shutdown propagate to all child stages; each durable observation remains reviewable even if the parent job is interrupted.

**Required result matrix:** ClamAV-only match; YARA-only match; both matching; neither matching; either provider failing; both failing; one cancelled; one unsupported; target changes between stages; same originating rule through two adapters. Add a restart during each combination's persistence boundary.

**Acceptance:** One coherent report explains what each engine checked and found, what remains unexamined, and why an item needs review. No result is upgraded to “confirmed malware” merely by counting correlated matches.

### E3 — Loki targeted threat hunting

#### E3A. Maintenance and packaging decision

- [ ] Evaluate original Python Loki and Loki-RS against a pinned test matrix: supported Windows architecture, maintenance/security history, IOC types, YARA backend, machine-readable output, configuration, privilege needs, and runtime dependencies.
- [ ] Prefer the maintained option if it meets requirements, but do not assume it is a drop-in replacement. If only legacy Loki meets a required capability, keep that adapter explicitly optional and document the maintenance tradeoff.
- [ ] Review the selected runtime's license and each IOC/rule source independently. Preserve attribution and distribution/source obligations; do not substitute THOR Lite merely because it is free to download.
- [ ] Make the adapter version-specific and test the exact binary's help/output. Do not copy legacy flags into the Rust backend.
- [ ] Install or attach a user-provided verified tool via the component manager. Keep its updates/rule preparation outside active hunts.

#### E3B. Hunt planning and execution

- [ ] Add an **Advanced → Threat hunt** workflow that selects a bounded scope and explains what the chosen backend can inspect.
- [ ] Start with file/IOC hunts over selected folders. Keep process-memory, broader host inspection, and elevated modes separate and explicitly initiated.
- [ ] Define a hunt manifest: tool/runtime version, IOC and rule revisions, targets, exclusions, enabled checks, privileges, budget, and reason for the hunt.
- [ ] Disable unsupported/out-of-scope checks using validated per-version options, or decline the profile if its scope cannot be enforced.
- [ ] Do not allow hidden self-updates, remote log destinations, network submissions, or an unbounded host-wide expansion during a run.
- [ ] Use structured output when the selected backend provides it; otherwise implement a fixture-tested parser retaining raw local evidence. Never infer “clean” solely from a console color or a successful exit code.
- [ ] Normalize evidence into filename IOC, content hash IOC, YARA rule, process/connection observation, and operational warning without conflating them.
- [ ] Preserve native scores as tool-specific metadata; show the contributing reasons and known false-positive context instead of treating a score as calibrated probability.
- [ ] Record permission gaps and skipped checks explicitly. Any later elevated helper should have a narrow authenticated interface, not an elevated Electron UI.

#### E3C. Hunt review

- [ ] Present a separate hunt report with evidence groups, timestamps, scope, missing access, and suggested local next actions.
- [ ] Revalidate a file observation against current content before offering quarantine. A historical PID/connection or a filename heuristic is not a file-removal authorization.
- [ ] Reuse YARA provenance/deduplication to avoid duplicate alerts when Loki loads a pack Sentinel already used.
- [ ] Do not let tool/rule installation failures disable the base ClamAV scheduler.
- [ ] Test offline hunts, missing IOC packs, malformed indicators, inaccessible directories, synthetic hash/name matches, benign matches, cancellation, and interrupted report recovery.

**Acceptance:** A user can run a targeted, attributable hunt, understand its coverage/limitations, and review findings without Sentinel overclaiming a host compromise or automatically modifying files.

### E4 — capa capability analysis and enrichment

#### E4A. Integration boundary

- [ ] Implement capa as a **static enrichment provider**, initially for selected supported Windows executable files. It is not a replacement for the default AV scan.
- [ ] Use a pinned standalone runtime where suitable, or a privately packaged helper environment. Manage tool/rule revisions and licenses through E0; inspect bundled dependencies separately.
- [ ] Use the selected version's JSON interface and validate its schema before importing results. Keep parser fixtures for supported old/new outputs; unknown schemas produce a readable compatibility error.
- [ ] Identify candidate file format by content, not extension alone. Unsupported data should be marked unsupported rather than clean.
- [ ] Never execute the suspicious sample to obtain richer results. Dynamic sandbox-report ingestion is a separate future feature and does not authorize running samples locally.
- [ ] Apply a strict analysis budget: per-file time, memory, output size, file size, and worker concurrency. Avoid automatic whole-drive capa processing.
- [ ] Analyze a stable content revision through a read-only/confined worker. If operating on quarantined content requires a staging copy, keep it protected and non-executable and track cleanup in the operation journal.

#### E4B. Evidence and UX

- [ ] Add **Analyze capabilities** on a selected supported file/detection, plus optional user-enabled enrichment of a bounded set of findings.
- [ ] Show capability categories with supporting rule IDs/locations and the exact capa/rules version, not a binary malicious/benign label.
- [ ] Explain benign dual-use capabilities: networking, encoding, service installation, process creation, and persistence-related APIs need context.
- [ ] Surface packer/obfuscation/installer limitations prominently. “No capabilities found,” analysis failure, and a complete result are distinct outcomes.
- [ ] Display ATT&CK or other taxonomy references only where the rule output actually supplies them; capability mappings are not proof that the technique was executed on this device.
- [ ] Retain an expandable evidence tree and export bounded JSON/readable summaries. Render locally; do not upload results to a public web explorer by default.
- [ ] Cache by content hash plus capa/rule/options generation, and invalidate when any component changes.
- [ ] Never auto-quarantine solely because capa found a capability. Route file actions through Sentinel's existing identity and confirmation safeguards.

#### E4C. Tests and acceptance

- [ ] Use self-built benign PE fixtures with known capabilities, a harmless managed executable, unsupported inputs, packed/limited fixtures where legally available, and corrupted/truncated files.
- [ ] Test JSON schema changes, enormous evidence trees, timeout, cancelled analysis, stale caches, source mutation, and analysis of a quarantined item without restoring it to its original location.
- [ ] Confirm benign capability matches remain informational and do not raise an infection count.

**Acceptance:** Users can understand what a binary appears capable of without being told that capabilities establish malicious intent. Analysis remains local, resource-bounded, attributable, and recoverable.

### E5 — Sigcheck exclusion and an open-source-compatible alternative

**Decision:** Do not bundle, download, require, or advertise Sigcheck as part of Sentinel's open-source engine collection. Its usefulness does not change the user's criterion. This section is an explicit exclusion plan, not a backdoor implementation requirement.

- [ ] Record Sigcheck as `excluded-proprietary` in the component/design inventory and keep core workflows functional without it.
- [ ] If publisher-signature context is desired, design an in-project open-source helper around Windows signature-verification facilities rather than redistributing Sigcheck. The Windows API is an operating-system dependency; this does not make Windows itself open source.
- [ ] Validate the distinction between embedded signatures, catalog signatures, trusted/untrusted chains, expired certificates, timestamped signatures, and unavailable revocation information.
- [ ] Separate signature validity from reputation and maliciousness: signed does not mean safe, unsigned does not mean malware.
- [ ] Make any potential revocation/network behavior explicit. An “offline” profile must not silently contact reputation services or certificate endpoints.
- [ ] Keep VirusTotal hash lookup and file upload out of this plan's default implementation. If requested later, treat hashes as data leaving the device and require a separate privacy/consent design for each operation.
- [ ] Only if the user later explicitly relaxes the open-source requirement, consider a separate bring-your-own Sigcheck adapter with visible licensing/EULA handling, verified path/version, no automatic acceptance of terms, and no cloud flags enabled by default.

**Acceptance:** Removing every proprietary optional utility leaves setup, scanning, enrichment, and reporting intact. The open-source edition accurately identifies all shipped components and rule-source licenses.

### E6 — multi-engine rollout order, test gates, and proposed code structure

**Order:** core evidence/coordinator fixes → provider contract/component manager → YARA and rule management → enhanced ClamAV + YARA jobs → capa enrichment → version-selected Loki hunting. Sigcheck remains excluded.

Proposed additions; adapt filenames to the actual architecture rather than creating empty scaffolding:

```text
src/providers/contracts.*       validated run/observation contracts
src/providers/registry.*        capabilities and component discovery
src/providers/clamav.*          existing scanner adapted without regressions
src/providers/yara.*            selected YARA backend adapter
src/providers/loki.*            selected, version-specific hunt adapter
src/providers/capa.*            static enrichment adapter
src/rules/manifest.*            provenance, licenses, digests, compatibility
src/rules/manager.*             staging, validation, activation, rollback
src/analysis/pipeline.*         parent jobs, scopes, budgets, provider stages
src/analysis/correlation.*      content revisions and rule-lineage grouping
test/providers/*               fixture-based adapter contract tests
test/rules/*                   import/compile/trust/rollback tests
test/pipelines/*               combined failure/cancellation/replay tests
```

- [ ] Create one vertical YARA slice first: install known backend → compile harmless local rule → scan fixture → durable event → review card → restart with result intact.
- [ ] Add negative/no-match fixtures and timing/resource budgets before importing broad rule collections.
- [ ] Gate combined scans on a tested parent/child operation model and explicit per-provider coverage reporting.
- [ ] Run the matrix with ClamAV detecting only, YARA detecting only, both detecting correlated/independent rules, neither matching, and every failure/timeout/cancellation combination.
- [ ] Test rule-pack update during a running job, incompatible pack rejection, rollback, offline operation, and removal of an optional engine without corrupting history.
- [ ] Verify all parsers preserve paths and rule metadata safely, including quotes, Unicode, HTML-like strings, control characters, and extremely large fields.
- [ ] Test evidence export redaction; matched bytes and capability metadata can contain private file contents or identifiers.
- [ ] Measure enhanced-profile overhead against the same corpus and hardware. Publish measured cost and coverage, not an unsupported “more engines means safer” score.
- [ ] Maintain a benign regression corpus for false-positive review, with recorded distribution rights. Do not fetch malware repositories onto the user's development machine.
- [ ] Add installer/component acceptance tests on clean Windows x64 and any separately supported ARM64 configuration.
- [ ] Complete source/license/NOTICE inventory and confirm the selected runtime and rule packages satisfy the open-source product requirement before distribution.
- [ ] Extend the release scorecard with provider compatibility, rule trust, correlated-evidence handling, resource isolation, and no-network-by-default evidence.

**Multi-engine definition of done:** A user can enable complementary tools without losing the simplicity of the base scanner; every result retains its meaning, origin, content revision, and limitations; one provider's failure cannot falsify another provider's outcome; no optional analysis feature silently executes samples, uploads data, or takes destructive action.

## Implementation log

No source fixes are included in this review document. Append implementation entries below with ticket IDs and evidence.

| Date       | Commit                     | Tickets                              | Verification                                                                                                                                                                       | Remaining risk                                                       |
| ---------- | -------------------------- | ------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| 2026-09-27 | `e979639`                  | R05                                  | Scanner stream tests (backpressure then ENOSPC/EIO, close before drain, stderr burst, cancel while paused)                                                                         | None known                                                           |
| 2026-09-27 | `059d98b`                  | R07                                  | Store tests: every save step failed after backup recovery, repeated restarts, newer-schema read-only                                                                               | No manifest; generation choice uses `savedAt`                        |
| 2026-09-27 | `982b629`                  | R01, R15 (part)                      | Capability/health matrix of more than 100 combinations; smoke                                                                                                                      | Generation is size and mtime; effective database set not inventoried |
| 2026-09-27 | `c64f78c`                  | R02                                  | Detect A → replace with B → rescan → quarantine B                                                                                                                                  | Case-sensitive directories                                           |
| 2026-09-27 | `82143a1`                  | R06, R09, R14, R13 (part), Q9 (part) | Journal, transaction, migration-ladder, and log-namespace tests; two-launch crash smoke; failing smoke must exit nonzero (**found and fixed: smoke failures previously exited 0**) | Main orchestration beyond smoke still lacks injected-adapter tests   |
| 2026-09-27 | `68c46af`                  | R04, R10, R11 (part)                 | Injected mutation before move and removal; recheck; untrusted stored path; malformed fixtures (**found and fixed: four test literals with collapsed backslashes**)                 | Hard-link and reparse fixtures; parent reparse checks                |
| 2026-09-27 | `620fefd`                  | R08, R13 (part)                      | Conflict matrix for every pair; dialog ordering; bounded drain                                                                                                                     | End-to-end quit during copy or restore                               |
| 2026-09-27 | `76e3234`                  | R03                                  | Coverage classification and supersession tests                                                                                                                                     | Per-file coverage is not available from ClamAV                       |
| 2026-09-27 | `f4b60d0`                  | R12                                  | Fatal handler unit tests; real uncaught-fault smoke (exit 1, diagnostics, marker)                                                                                                  | Renderer-crash reload not exercised                                  |
| 2026-09-27 | `5399b04` + release commit | R16 (part), CI                       | Unsaved-changes guard and header badge in smoke; verified-healthy screenshot                                                                                                       | Accessibility validation, clean-VM install, signing                  |

**Release scorecard (1.2.0, prerelease):** content preservation, minimum evidence met for the injected cases, not the full identity ladder. Detection durability: met (cap, log error, crash, replay). Schedule correctness: retries, cancellation, catch-up, and coverage met; DST and resume not yet. Health honesty: met (one capability snapshot). Storage resilience: met for schema, migration, backup, and ENOSPC. Responsiveness, accessibility, install/update, and supportability: **not yet met**. Security posture: renderer isolation and validated IPC in place; no threat model yet. Multi-engine work (Part IV) has not started, as planned, because it depends on this phase.
