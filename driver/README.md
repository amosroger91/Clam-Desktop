# Experimental kernel boundary — not part of the installer

`SentinelFilter.c` implements a bounded, versioned Filter Manager port and an experimental `IRP_MJ_CREATE` execute-open gate. It returns `STATUS_ACCESS_DENIED` only for an explicit, complete deny reply. Disconnection, timeout, missing names and invalid replies use a documented **fail-open development policy**. The default port ACL restricts connection to SYSTEM/administrators. Broker requests bypass interception to avoid recursive scan opens.

This source is not production protection and is not currently connected to the desktop scanner. There is no installer INF, assigned altitude, signing identity, or deployed kernel broker. Building it requires the Windows Driver Kit, not just the Windows SDK. Never install this unvalidated source on a working machine.

## Required completion and acceptance work

1. Obtain an allocated minifilter altitude and a Microsoft Hardware Developer account/signing identity. Produce an INF and signed catalog for supported Windows versions.
2. Implement and validate a privileged native broker using `FilterGetMessage` / `FilterReplyMessage`. The broker must hold a file handle with appropriate sharing restrictions while scanning, bind the verdict to volume/file identity and content generation, and use the desktop pipeline through an authenticated service boundary. A path-only verdict is insufficient.
3. Add stream contexts, write/rename invalidation and image-section synchronization. Execute-open interception alone misses existing handles, mapped images and script interpreters. Do not scan nonexistent content during an initial write-open or claim that it does.
4. Resolve the clean-verdict/open race and file-lock recursion with kernel tests. The two-second prototype deadline cannot accommodate a cold signature database; production policy must explicitly define unavailable/timeout behavior and a bounded verdict cache.
5. Test only in disposable VMs: Driver Verifier, concurrent writes/renames, hard links/reparse points, broker crash/disconnect, malicious reply lengths, low memory, mapped execution, boot/unload, AC/battery transitions, Defender coexistence and HLK requirements. Connect/disconnect/unload rundown needs stress testing.
6. Only then add the service/driver deployment option. The release installer deliberately excludes this directory.

References: [Microsoft scanner sample](https://github.com/microsoft/Windows-driver-samples/tree/main/filesys/miniFilter/scanner), [windows-drivers-rs](https://github.com/microsoft/windows-drivers-rs), [FltSendMessage](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltsendmessage), [driver signing policy](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-policy--windows-vista-and-later-).

The sample is original C source using the established WDK API; no GPL code from Amaru or other reference projects was copied. A Rust implementation would still require the same kernel validation and deployment work.
