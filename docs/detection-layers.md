# Detection pipeline

The persistent engine scans file bytes using `INSTREAM`, bounded chunks and a zero-length terminator. The queue checks file identity before and after scanning and never treats errors, limits or mutation as clean. SHA-256 is calculated over the streamed bytes, and automatic quarantine independently confirms that hash before moving anything. The daemon binds an ephemeral loopback port to avoid colliding with a separately installed ClamAV service. `config/clamd.conf` is the packaged reference template; the agent generates the actual profile-specific configuration.

When continuous monitoring is enabled, both watched files and foreground directory scans use the same bounded pipeline:

1. ClamAV with the official FreshClam databases. Strong signature detections are eligible for automatic quarantine in watched directories. PUA and heuristic signatures require review.
2. Optional YARA-X against a compiled curated Signature Base feed. Metadata and authors appear in the detection name. Every community-rule match requires review; a remote rule cannot make itself an automatic-removal rule. YARA errors fail the scan, rather than falling through to a clean result.
3. Optional Radare2 `rabin2` inspection of PE sections and imports for EXE/DLL/SCR/COM files. Packer sections, writable/executable sections and a combination of injection-related imports become review evidence. MSI is not assumed to be a PE file. These checks do not establish malicious behavior.

When monitoring is off, existing manual/scheduled scans use the standalone ClamAV adapter. Extra layers do not run in that mode. Archive unpacking belongs to ClamAV; YARA inspects the container bytes and is not an additional recursive archive extractor.

## Community feed

The updater retrieves an upstream commit and then downloads seven explicitly selected rule files from that immutable revision. It rejects file includes, compiles every selected rule without ignoring compile failures, scans a benign activation probe, hashes the compiled output and atomically switches the active pointer. Previous rules remain active if an update fails. Startup verifies the compiled-file digest. Downloaded source and licenses are retained for attribution and diagnosis. Updates run every six hours while YARA is enabled; the settings panel exposes revision, date and errors. This is not every Signature Base rule and does not imply complete malware coverage.

## Automatic quarantine

The background agent owns `monitor/quarantine` and its journal. The desktop's original manual vault remains separately owned. The UI combines both views, and authenticated IPC forwards automatic-vault restore/recheck/resolve operations under a maintenance lease. Restores require confirmation and never overwrite existing files. Automatic quarantine records survive a process restart even before the desktop receives the detection. Up to 500 automatic records are retained; further automatic moves report a capacity error and leave the detection for review. The vault uses non-executable filenames inside the user's application profile; it is not encrypted or protected against administrators.

## Local behavior snapshots

Optional osquery sampling runs at most once per minute, with a 15-second timeout, 2 MB response bound and 2,000-row limit. It observes process parent relationships and socket counts and flags Office applications launching command/script interpreters. It omits full command lines, disables extensions/logging, retains bounded summaries only in memory and uploads nothing. It can miss short-lived processes and does not observe registry writes, LSASS injection or file-encryption sequences. ETW/driver event collection remains separate unfinished work.

## Evidence and limits

Tests use harmless hash and YARA fixtures, benign executables, actual upstream binaries, queue mutation/failure fixtures, restart recovery and real Electron IPC. Those tests demonstrate the specified behavior; they do not establish a malware detection rate, eliminate false positives or validate a kernel driver. See [kernel work](../driver/README.md) and [Windows trust](windows-trust.md) for work excluded from this preview.
