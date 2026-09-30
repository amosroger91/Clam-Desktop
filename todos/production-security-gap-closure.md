# Sentinel AV — Production Security Gap Closure TODO

This checklist tracks the work required to move Sentinel AV from its current user-space antivirus implementation toward a production-grade Windows endpoint protection platform. Existing functionality must remain intact. An item may be checked only after its implementation, tests, documentation, and recovery behavior are verified.

## Operating rules

- [ ] Do not weaken existing security checks or remove tests to make work pass.
- [ ] Treat scanner errors, unavailable components, and timeouts as errors, never as clean results.
- [ ] Keep the renderer out of security decisions; keep kernel and privileged native code minimal.
- [ ] Keep malware parsing and expensive analysis out of kernel mode.
- [ ] Use strict schemas, bounded buffers, authentication, timeouts, and recoverable state transitions at every privileged boundary.
- [ ] Preserve local-only processing; never upload scanned files or behavioral telemetry.
- [ ] Never use real malware in source control; use legal test samples outside the repository and harmless synthetic fixtures in tests.
- [ ] Never fake driver signing, Windows Security Center registration, protection status, or detection-rate claims.
- [ ] Run the complete existing suite after every major milestone and record the result.

## Phase 0 — Baseline and architecture record

- [ ] Read and inventory the complete repository, including README, quality reviews, TODOs, driver, monitoring, trust/signing, build configuration, installer, and tests.
- [ ] Map Electron main, renderer, preload/IPC, Sentinel service host, clamd, watcher, queue, quarantine, YARA, Radare2, osquery, persistence, scheduler, installer, and experimental driver.
- [ ] Record security boundaries, trust boundaries, privileged components, recovery paths, and known limitations.
- [ ] Run and record the complete baseline test suite without changing tests.
- [ ] Create `docs/PRODUCTION_SECURITY_GAP.md` with architecture, capabilities, missing capabilities, boundaries, recovery paths, limitations, and baseline results.

## Phase 1 — Security architecture

- [ ] Document and review the target flow: filesystem/process activity → minifilter → secure IPC → native broker → Sentinel service → ClamAV/YARA-X/static/behavioral engines → policy engine → allow/block.
- [ ] Define the driver, broker, service, GUI, engine, updater, and storage trust boundaries.
- [ ] Specify which component owns each security decision and each durable state transition.
- [ ] Ensure the driver never executes JavaScript, invokes Electron, or depends on the renderer.
- [ ] Ensure the service and broker operate correctly without the GUI.
- [ ] Define unavailable, timeout, error, review, quarantine, allow, and block semantics before implementation.

## Phase 2 — Production filesystem minifilter

- [ ] Replace the experimental driver with a production-oriented minifilter design.
- [ ] Implement documented installation, startup, shutdown, filesystem attachment, and clean unload.
- [ ] Add only the required callbacks for file create/open, executable/image activity, rename/move, write/close, process identity, user/session correlation, exclusions, and safe bypasses.
- [ ] Keep expensive analysis out of kernel mode; never perform network access or complex untrusted-format parsing in the driver.
- [ ] Define deterministic behavior for broker/service unavailability and strict callback timeouts.
- [ ] Bound event queues and prevent filesystem deadlocks, recursion, and unbounded waits.
- [ ] Validate every user-mode message and document every callback and why it exists.
- [ ] Add Driver Verifier, unload, concurrency, malformed-message, queue-pressure, timeout, and broker-disconnect tests in disposable VMs.

## Phase 3 — Native security broker

- [ ] Create a small native broker between the minifilter and Sentinel service.
- [ ] Receive kernel events and validate version, lengths, path encoding, integers, handles, process/session identity, and request limits.
- [ ] Enforce authenticated IPC and ACLs so unauthorized clients cannot use the security channel.
- [ ] Correlate file/process context and return explicit allow/block decisions.
- [ ] Add bounded buffers, watchdog behavior, strict timeouts, health reporting, and deterministic service-failure handling.
- [ ] Keep the broker separate from the antivirus engine and minimize privileged code.
- [ ] Add extensive malformed-input, fuzz, impersonation, overflow, disconnect, restart, and unauthorized-client tests.

## Phase 4 — Real-time detection and policy engine

- [ ] Connect driver/broker events to the existing hash/cache, ClamAV, YARA-X, static-analysis, behavioral, quarantine, and persistence layers.
- [ ] Create one explicit policy engine with `ALLOW`, `BLOCK`, `QUARANTINE`, `REVIEW`, `ERROR`, and `TIMEOUT` states.
- [ ] Preserve the rule that skipped, unavailable, mutated, and error results are not clean.
- [ ] Make cache keys include content hash/file identity, modification generation, engine/database versions, YARA revision, and policy version.
- [ ] Prove cache invalidation after replacement, rename, write, database, rule, and policy changes.
- [ ] Journal every security-critical decision before enforcement and make replay idempotent.
- [ ] Add detection-to-decision latency, quarantine latency, and recovery metrics.

## Phase 5 — Process execution protection

- [ ] Cover executable/image launch, appropriate script/interpreter execution, suspicious child-process context, renamed files, temporary-directory execution, and downloaded executables.
- [ ] Do not rely on extensions; use content, hashes, file identity, process identity, and context.
- [ ] Bind the verdict to the object actually executed, including replacement and rename races.
- [ ] Address TOCTOU between check and execution with handle/file-generation/image-section correlation.
- [ ] Test launch, block, rename, copy-before-launch, replacement races, interpreter chains, and suspicious parent/child relationships.

## Phase 6 — ETW behavioral telemetry

- [ ] Implement bounded, local-only ETW collection in user mode.
- [ ] Collect only required security metadata: process lifecycle, parent/child relationships, executable identity, suspicious interpreters, persistence activity, network metadata, scripts, and Office-to-interpreter chains where supported.
- [ ] Avoid unnecessary command-line or sensitive data retention.
- [ ] Define retention limits, privacy behavior, sampling, backpressure, and failure handling.
- [ ] Integrate behavioral evidence into policy without treating a heuristic alone as proof of malware.
- [ ] Test provider failure, event loss, high event rates, service restart, and privacy boundaries.

## Phase 7 — Tamper protection

- [ ] Protect ordinary users from stopping the security service or modifying security-critical configuration.
- [ ] Protect engine databases, YARA rules, quarantine records, policy, driver configuration, and owned binaries with Windows ACLs and service controls.
- [ ] Separate user settings from privileged security configuration.
- [ ] Ensure the renderer cannot directly modify privileged state.
- [ ] Add authenticated administrator recovery procedures; do not lock administrators out permanently.
- [ ] Test unauthorized stop, file replacement, deletion, ACL changes, policy changes, and legitimate recovery.

## Phase 8 — Windows Security Center integration

- [ ] Define supported Windows versions and the applicable Microsoft provider/integration requirements.
- [ ] Implement only supported registration/reporting mechanisms; do not use it as a Defender exclusion or whitelist mechanism.
- [ ] Report antivirus availability, real-time protection, definitions, service, driver, broker, and overall health accurately.
- [ ] Make GUI health and Windows Security state agree.
- [ ] Test healthy, driver stopped, service stopped, stale/corrupt definitions, disabled protection, broker/scanner unavailable, and recovery states.

## Phase 9 — Service-first lifecycle

- [ ] Make the production stack start at Windows boot without Electron: driver → broker → Sentinel service → protection active.
- [ ] Implement service installation, automatic start, dependency ordering, clean shutdown, recovery actions, watchdog behavior, boot initialization, and health reporting.
- [ ] Keep the GUI as an administrative/visual client only.
- [ ] Test with GUI never launched, GUI crash, service/broker/clamd crash, driver communication failure, unexpected reboot, and power loss.
- [ ] Verify no duplicate agents, no orphaned children, and deterministic recovery after every failure.

## Phase 10 — Secure automatic updates

- [ ] Update the application, service, broker, driver, ClamAV databases, YARA rules, and supporting engines through authenticated channels.
- [ ] Verify signatures, hashes, versions, provenance, compatibility, and downgrade policy before installation.
- [ ] Stage atomically, validate, install, health-check, commit, and journal each update.
- [ ] Preserve the last known-good version and roll back on failed health checks.
- [ ] Test interrupted downloads, corruption, power loss, crash during replacement, downgrade attempts, and recovery.

## Phase 11 — Driver signing and production packaging

- [ ] Make driver builds reproducible and include version metadata, symbols policy, package manifests, and provenance.
- [ ] Define the exact external Microsoft Dev Portal, attestation/HLK, certificate, catalog, and hardware/software certification handoff.
- [ ] Sign the driver, broker, service, application, installer, and update packages with a real publisher identity when available.
- [ ] Verify signatures and package contents in CI and on a clean test machine.
- [ ] Validate driver install, upgrade, rollback, uninstall, and refusal of unsigned/invalid packages.
- [ ] Never mark this phase complete based only on a local unsigned compile.

## Phase 12 — Clean-machine installer

- [ ] Take a clean Windows 10/11 machine from nothing installed to fully operational protection.
- [ ] Install driver, broker, service, engines, definitions, configuration, Windows integration, and GUI in the correct order.
- [ ] Test fresh install, upgrade, supported downgrade, interrupted install, reboot during install, driver/service failure, corruption, uninstall, reinstall, and upgrades from prior Sentinel versions.
- [ ] Verify rollback leaves the previous working security installation intact.

## Phase 13 — Adversarial testing

- [ ] Test harmless files, synthetic signatures, renamed/no-extension threats, rapid creation, downloads, moves, post-detection modification, replacement races, locks, huge/malformed files, archives, and nested archives.
- [ ] Test executable launches, blocked launches, renamed/copy-before-launch races, interpreter chains, and process relationships.
- [ ] Kill and recover GUI, service, broker, clamd, watcher, scanner, and update processes.
- [ ] Test driver load/unload/restart, malformed messages, invalid paths, oversized messages, event floods, service/broker unavailability, and driver unavailability.
- [ ] Verify the driver never destabilizes Windows in disposable VMs.

## Phase 14 — Chaos and recovery

- [ ] Automate scan → kill → restart.
- [ ] Automate quarantine → kill → restart.
- [ ] Automate update → power loss and update → corrupted package.
- [ ] Automate scan/database update → crash and service restart during detection.
- [ ] Automate driver communication failure, broker restart, and Windows reboot during detection.
- [ ] Confirm every scenario converges to a recoverable state with no false clean result or lost detection.

## Phase 15 — Detection-quality evaluation

- [ ] Build a legally sourced external corpus plus safe synthetic fixtures; keep real malware out of source control.
- [ ] Measure signature, YARA, static, behavioral, false-positive, false-negative, latency, CPU, memory, and detection-to-quarantine results separately.
- [ ] Generate repeatable reports with corpus version, engine versions, rule revisions, policy version, and environment.
- [ ] Publish no detection-rate or “Norton equivalent” claim without reproducible evidence.

## Phase 16 — Performance

- [ ] Measure boot impact, application launch, file-copy throughput, compilation, CPU, RAM, scan/detection latency, battery, and idle behavior.
- [ ] Define acceptable thresholds and test on representative hardware.
- [ ] Preserve and validate CPU, memory, battery, idle, queue, concurrency, and pause policies.
- [ ] Verify protection remains active without making normal Windows use unusable.

## Phase 17 — Security review

- [ ] Review kernel IRQL, memory safety, synchronization, lifetime, pool allocation, callbacks, races, deadlocks, and TOCTOU.
- [ ] Review broker authentication, privilege boundaries, parsers, malformed input, impersonation, and escalation paths.
- [ ] Review service ACLs, IPC, configuration protection, updater security, and impersonation.
- [ ] Review Electron isolation, CSP, IPC validation, filesystem access, command execution, and renderer-compromise impact.
- [ ] Review installer/updater signatures, path traversal, DLL hijacking, downgrade, rollback, and partial-install behavior.
- [ ] Track findings to closure; do not declare readiness with an unresolved critical vulnerability.

## Phase 18 — Documentation

- [ ] Update README with separate Protection, Detection, Monitoring, Limitations, Privacy, Security Architecture, Recovery, and Trust/Signing sections.
- [ ] Include driver → broker → service → detection diagrams and component ownership.
- [ ] Explain behavior after GUI, service, broker, scanner, driver, database, and update failures.
- [ ] Document exactly what leaves the machine.
- [ ] Document external Microsoft signing/certification handoffs without pretending they are complete.
- [ ] Remove unsupported detection-rate and replacement-antivirus claims.

## Definition of Done

- [ ] Production minifilter exists, is signed, starts reliably, and is validated not to destabilize Windows.
- [ ] Native broker exists with hardened authenticated communication and bounded failure behavior.
- [ ] Real-time protection works without the GUI and can block malicious execution.
- [ ] Enforcement is race-resistant and bound to the object actually executed.
- [ ] Service and driver start automatically and recover after crashes/reboots.
- [ ] Driver/service/broker/scanner health is reported accurately in the GUI and Windows integration.
- [ ] Tamper protection, ETW telemetry, secure updates, rollback, and signed production packaging are complete.
- [ ] Clean install, upgrade, uninstall, adversarial, chaos, performance, and security tests pass.
- [ ] No known critical security vulnerabilities remain.
- [ ] Existing functionality remains intact.
- [ ] Documentation accurately describes demonstrated capabilities and limitations.

## Execution order

1. Baseline and architecture record
2. Production minifilter
3. Native broker
4. Driver/broker IPC
5. Real-time enforcement
6. Process execution protection
7. Service-first architecture
8. ETW telemetry
9. Tamper protection
10. Windows Security integration
11. Secure updater
12. Production driver/package process
13. Clean-machine installer
14. Adversarial testing
15. Chaos/recovery testing
16. Performance testing
17. Security review
18. Documentation and final release validation
