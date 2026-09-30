# Continuous scanning

Enable **Settings → Continuous scanning & resources → Monitor file changes**, choose folders and save. If no folders are selected, Sentinel uses Downloads and user/system Temp. Monitoring is off by default. The high-risk filter defaults to executables, installers, scripts and archives; turn it off to inspect all extensions.

This is near-real-time detection after a file changes, not execution prevention. Confirmed ClamAV threats are automatically quarantined unless that option is disabled. PUA/heuristic and secondary-engine findings require review. It does not register as a Windows Security provider, install a kernel filter or replace Microsoft Defender.

## How it works

```text
Windows file notifications ─→ durable bounded queue ─→ persistent clamd
Periodic reconciliation ────→       ↑                         │
Manual / scheduled scans ───→ lower priority                  ↓
                                                   durable detection outbox
                                                            │
Electron settings / status / alerts ← authenticated local IPC┘
```

The agent runs outside Electron's UI process. It keeps one signature database loaded and serves both watched-file scans and, while monitoring is enabled, manual/scheduled scans. Changed files take the next available slot ahead of directory-scan work. An active individual file scan is bounded by scan/request deadlines, rather than interrupted each time a new file appears.

Notifications are coalesced by path, files get a settling delay, and a changed file is queued again if its identity changes during scanning. Windows can drop notifications, so Sentinel also walks the selected folders at startup and every five minutes. The walk yields between files and waits when the queue is full. It does not traverse symlinks/junctions. Unreadable or missing monitored roots appear in recent issues and are retried by reconciliation.

Queue state, cache metadata and an unacknowledged detection outbox live in the profile's `monitor` directory. Detections are flushed before the desktop can acknowledge them. Startup reconciliation repairs the short admission batching window after an abrupt stop. A clean-result cache is invalidated by definition or scan-policy changes. Oversized files are recorded as skipped, never described as clean.

The daemon listens only on an ephemeral loopback port. ClamAV's socket itself is unauthenticated; it must never be exposed to other machines. Desktop control uses a separate named pipe authenticated with a randomly generated key in the user's profile. The agent and optional service run as that same user, not LocalSystem. The packaged process host uses a Windows job object so stopping/crashing the host also terminates its agent and engine.

## Resource controls

| Control                | Default  | Behavior                                                                                                        |
| ---------------------- | -------- | --------------------------------------------------------------------------------------------------------------- |
| Concurrent scans       | 1        | Shared budget for monitored and directory-scan files; configurable up to 4.                                     |
| Low priority           | On       | Runs ClamAV below normal scheduling priority.                                                                   |
| CPU threshold          | 80%      | Pauses scanning under high **system** CPU load. This is a soft, sampled policy, not a hard per-process CPU cap. |
| Available-memory floor | 768 MB   | Pauses and unloads the engine below this system free-memory threshold. It is not a hard memory limit.           |
| Pause on battery       | On       | Queues changes while on battery or while power status is unknown.                                               |
| Idle only              | Off      | Requires a recent desktop idle-time sample; pauses if the desktop disconnects.                                  |
| File size              | 100 MB   | Larger files are shown as skipped. Archive expansion and scan-time limits also apply.                           |
| Queue capacity         | 5,000    | Keeps memory bounded; reconciliation repairs overflow.                                                          |
| Settling delay         | 1,500 ms | Waits after repeated writes before attempting a scan.                                                           |
| Timed pause            | None     | Pause for 15 or 60 minutes, or resume immediately. The deadline survives restart.                               |

The status panel shows queue length, oldest queued item, active scans, engine memory, available system memory, CPU load, counts, recent issues, and the 95th-percentile latency of the latest 100 completed watched-file scans. Resource sampling is approximately every 15 seconds; latency includes queueing/settling and is not a guaranteed response time. A persistent official ClamAV database can use substantial memory even when no file is being scanned.

Quarantine during a directory scan offers **Stop scan and quarantine**. The foreground scan is cancelled and saved, and an acknowledged maintenance lease drains the background scanner before the file operation. Definition updates use the same lease. Large file operations renew it while running; a disconnected desktop's lease expires.

## Background lifetime and definitions

On normal quit the desktop stops its agent and daemon unless **Continue after quitting Sentinel** is enabled. An installed Windows service runs independently. Desktop alerts are delivered while the desktop is running; detections found while it is closed are retained and presented when it reconnects. Scheduled quick/full scans still belong to the desktop scheduler. Enable launch at sign-in, or install the optional service, to restart monitoring after a reboot.

With automatic updates enabled, the agent checks definitions hourly when the desktop heartbeat is absent, with persisted failure backoff and signature verification. It stops its engine during updates. If the desktop requests a maintenance lease, the background updater is cancelled before the lease is granted. A failed update that changed the database blocks scanning until the definitions are successfully verified or replaced.

## Optional Windows service

The service is opt-in and requires an administrator to install. Sentinel's ordinary per-user installer does not register a service or store a service-account password. Build the host with `npm run build:service`; packaging includes it and the installation scripts under `resources/monitor`.

1. Install Sentinel to a local disk, enable monitoring, and save the folder/resource settings.
2. Close the desktop. Open an elevated PowerShell window as the **same Windows account**. That account needs the Windows **Log on as a service** right. A Windows Hello PIN is not a service logon password.
3. Run the shipped installation script using the actual installed paths:

   ```powershell
   $appDir = 'C:\Users\YOUR-NAME\AppData\Local\Programs\Sentinel AV'
   & "$appDir\resources\monitor\install-service.ps1" `
     -Runtime "$appDir\Sentinel AV.exe" `
     -Agent "$appDir\resources\monitor\src\monitor-agent.cjs" `
     -HostExecutable "$appDir\resources\monitor\SentinelMonitor.exe" `
     -Profile "$env:APPDATA\sentinel-av" `
     -Credential (Get-Credential)
   ```

The script stops the existing agent, registers `SentinelMonitor`, configures restart-on-failure, and starts it. Credentials go directly to Windows service registration; Sentinel does not save them. Do not substitute LocalSystem or another user's profile. Do not use mapped-drive installation paths; service sessions do not inherit desktop drive mappings.

Before upgrading or uninstalling Sentinel, stop and remove the optional service with the shipped `uninstall-service.ps1`, then reinstall the service against the new paths if needed. Removing the service preserves queued work and detections. Normal desktop launch reconnects to a running agent rather than starting a second scanner.

## Verification

```powershell
npm ci
npm test
node scripts/prepare-monitor-fixtures.cjs
npm run test:integration
npm run build:service
$env:SENTINEL_TEST_HOST = Join-Path $PWD 'service/SentinelMonitor.exe'
npm run test:monitor
npm run test:smoke
npm run pack
# Requires official database fixtures in test-output/database:
node scripts/test-packaged-monitor.cjs
```

The monitor integration test uses an actual ClamAV engine with a harmless custom signature. It checks a persistent engine, Windows file notifications, detection latency, restart/outbox recovery, maintenance pause/resume and background directory-scan requests. The console host exercises the same process-job code as the service. Actual SCM installation, service-account logon at boot, laptop battery transitions, and signed release distribution still require deployment validation on a suitable Windows test machine.
