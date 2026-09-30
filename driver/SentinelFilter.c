// EXPERIMENTAL EXECUTE-OPEN GATE. Not installed or shipped by Sentinel AV.
// This is not a complete anti-malware minifilter: see driver/README.md for mandatory acceptance work.
#include <fltKernel.h>
#include "protocol.h"

static PFLT_FILTER Filter;
static PFLT_PORT ServerPort, ClientPort;
static HANDLE BrokerPid;
static EX_RUNDOWN_REF ConnectionRundown;

static NTSTATUS Connect(PFLT_PORT port, PVOID cookie, PVOID context, ULONG size, PVOID *connection) {
    UNREFERENCED_PARAMETER(cookie); UNREFERENCED_PARAMETER(context);
    UNREFERENCED_PARAMETER(size); UNREFERENCED_PARAMETER(connection);
    // FltBuildDefaultSecurityDescriptor limits connections to SYSTEM/administrators; one connection.
    ExReInitializeRundownProtection(&ConnectionRundown);
    BrokerPid = PsGetCurrentProcessId(); ClientPort = port;
    return STATUS_SUCCESS;
}
static VOID Disconnect(PVOID cookie) {
    UNREFERENCED_PARAMETER(cookie);
    FltCloseClientPort(Filter, &ClientPort);
    ExWaitForRundownProtectionRelease(&ConnectionRundown);
    BrokerPid = NULL;
}
static FLT_PREOP_CALLBACK_STATUS PreCreate(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS objects, PVOID *completion) {
    PFLT_FILE_NAME_INFORMATION name = NULL;
    SENTINEL_REQUEST *request = NULL;
    SENTINEL_REPLY reply = { SENTINEL_PROTOCOL_VERSION, SENTINEL_VERDICT_UNKNOWN };
    ULONG replySize = sizeof(reply);
    LARGE_INTEGER deadline;
    NTSTATUS status;
    BOOLEAN deny = FALSE;
    UNREFERENCED_PARAMETER(objects); UNREFERENCED_PARAMETER(completion);
    if (KeGetCurrentIrql() != PASSIVE_LEVEL || data->RequestorMode == KernelMode ||
        !(data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & FILE_EXECUTE) ||
        (data->Iopb->Parameters.Create.Options & FILE_DIRECTORY_FILE) ||
        PsGetCurrentProcessId() == BrokerPid || !ClientPort)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (!ExAcquireRundownProtection(&ConnectionRundown)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    status = FltGetFileNameInformation(data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &name);
    if (!NT_SUCCESS(status) || name->Name.Length >= sizeof(request->Path)) goto done;
    request = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*request), 'ScnS');
    if (!request) goto done;
    RtlZeroMemory(request, sizeof(*request));
    request->Version = SENTINEL_PROTOCOL_VERSION;
    request->ProcessId = HandleToULong(PsGetCurrentProcessId());
    request->PathBytes = name->Name.Length;
    RtlCopyMemory(request->Path, name->Name.Buffer, name->Name.Length);
    deadline.QuadPart = -2 * 1000 * 1000 * 10LL; // Two seconds; never wait indefinitely on Electron.
    status = FltSendMessage(Filter, &ClientPort, request, sizeof(*request), &reply, &replySize, &deadline);
    // STATUS_TIMEOUT is NT_SUCCESS: require exact STATUS_SUCCESS and a complete versioned reply.
    deny = status == STATUS_SUCCESS && replySize == sizeof(reply) &&
        reply.Version == SENTINEL_PROTOCOL_VERSION && reply.Verdict == SENTINEL_VERDICT_DENY;
done:
    if (request) ExFreePoolWithTag(request, 'ScnS');
    if (name) FltReleaseFileNameInformation(name);
    ExReleaseRundownProtection(&ConnectionRundown);
    if (deny) {
        data->IoStatus.Status = STATUS_ACCESS_DENIED; data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK; // Explicit fail-open development policy.
}
static NTSTATUS Unload(FLT_FILTER_UNLOAD_FLAGS flags) {
    UNREFERENCED_PARAMETER(flags);
    FltCloseCommunicationPort(ServerPort);
    FltUnregisterFilter(Filter);
    return STATUS_SUCCESS;
}
static const FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE, 0, PreCreate, NULL }, { IRP_MJ_OPERATION_END }
};
static const FLT_REGISTRATION Registration = {
    sizeof(FLT_REGISTRATION), FLT_REGISTRATION_VERSION, 0, NULL, Callbacks, Unload
};
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registry) {
    NTSTATUS status;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    OBJECT_ATTRIBUTES attributes;
    UNICODE_STRING portName = RTL_CONSTANT_STRING(SENTINEL_PORT_NAME);
    UNREFERENCED_PARAMETER(registry);
    ExInitializeRundownProtection(&ConnectionRundown);
    status = FltRegisterFilter(driver, &Registration, &Filter);
    if (!NT_SUCCESS(status)) return status;
    status = FltBuildDefaultSecurityDescriptor(&descriptor, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) goto fail;
    InitializeObjectAttributes(&attributes, &portName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, descriptor);
    status = FltCreateCommunicationPort(Filter, &ServerPort, &attributes, NULL, Connect, Disconnect, NULL, 1);
    FltFreeSecurityDescriptor(descriptor);
    if (!NT_SUCCESS(status)) goto fail;
    status = FltStartFiltering(Filter);
    if (NT_SUCCESS(status)) return status;
    FltCloseCommunicationPort(ServerPort);
fail:
    FltUnregisterFilter(Filter);
    return status;
}
