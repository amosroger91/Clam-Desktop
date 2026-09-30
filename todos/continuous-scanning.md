# Continuous scanning and resource management

Branch: `codex/continuous-scanning`

- [x] Persistent ClamAV daemon with bounded requests, recovery, and safe configuration.
- [x] Durable priority queue, filesystem monitoring, settling, retries, and reconciliation.
- [x] Background agent independent of the desktop, optional Windows service host.
- [x] Immediate durable detection alerts and responsive activity updates.
- [x] Resource budgets, battery/idle policies, pause/resume, queue and engine telemetry.
- [x] Integration with definitions, exclusions, quarantine and existing scan lifecycle.
- [x] Unit, real-engine, background restart, Electron smoke, and packaging checks.
- [x] Document behavior, resource tradeoffs, service setup, and remaining limitations.

This implements near-real-time detection, not a Windows interception driver. Existing scheduled and manual scans remain available. No automatic quarantine or deletion is introduced.

