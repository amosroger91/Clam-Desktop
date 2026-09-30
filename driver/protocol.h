#pragma once
// Experimental protocol, versioned independently from Electron IPC. No pointers cross the boundary.
#define SENTINEL_PROTOCOL_VERSION 1
#define SENTINEL_PATH_CHARS 2048
#define SENTINEL_PORT_NAME L"\\SentinelScanPort"
#define SENTINEL_VERDICT_UNKNOWN 0
#define SENTINEL_VERDICT_CLEAN 1
#define SENTINEL_VERDICT_DENY 2
typedef struct _SENTINEL_REQUEST {
    ULONG Version;
    ULONG ProcessId;
    ULONG PathBytes;
    WCHAR Path[SENTINEL_PATH_CHARS];
} SENTINEL_REQUEST;
typedef struct _SENTINEL_REPLY {
    ULONG Version;
    ULONG Verdict;
} SENTINEL_REPLY;
