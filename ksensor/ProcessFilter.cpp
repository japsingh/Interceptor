#include "ProcessFilter.h"
#include "comm.h"
#include "Utils.h"

VOID
CreateProcessNotifyRoutine(
	HANDLE ParentId,
	HANDLE ProcessId,
	BOOLEAN Create
);

NTSTATUS InitPF()
{
	NTSTATUS status = PsSetCreateProcessNotifyRoutine(
		CreateProcessNotifyRoutine,
		FALSE
	);

	return status;
}

VOID UninitPF()
{
	PsSetCreateProcessNotifyRoutine(
		CreateProcessNotifyRoutine,
		TRUE
	);
}

VOID
CreateProcessNotifyRoutine(
		HANDLE ParentId,
		HANDLE ProcessId,
		BOOLEAN Create
	)
{
	//NTSTATUS Status = STATUS_SUCCESS;
	EVENT evt;

	RtlZeroMemory(&evt, sizeof(evt));

	if (Create)
	{
		//DbgPrintEx(
		//	DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
		//	"ObCallbackTest: TdCreateProcessNotifyRoutine2: process %p (ID 0x%p) created, creator %Ix:%Ix\n"
		//	"    command line %wZ\n"
		//	"    file name %wZ (FileOpenNameAvailable: %d)\n",
		//	Process,
		//	(PVOID)ProcessId,
		//	(ULONG_PTR)CreateInfo->CreatingThreadId.UniqueProcess,
		//	(ULONG_PTR)CreateInfo->CreatingThreadId.UniqueThread,
		//	CreateInfo->CommandLine,
		//	CreateInfo->ImageFileName,
		//	CreateInfo->FileOpenNameAvailable
		//);
		evt.eventType = kProcessCreate;
		evt.pe.Pid = (ULONGLONG)ProcessId;
		//if (CreateInfo->ImageFileName->Length < sizeof(evt.pe.Name)) {
		//	RtlCopyMemory(evt.pe.Name, CreateInfo->ImageFileName->Buffer, CreateInfo->ImageFileName->Length);
		//}
		//if (CreateInfo->CommandLine->Length < sizeof(evt.pe.Commandline)) {
		//	RtlCopyMemory(evt.pe.Commandline, CreateInfo->CommandLine->Buffer, CreateInfo->CommandLine->Length);
		//}
		GetProcessImageName(evt.pe.InitiatorName, sizeof(evt.pe.InitiatorName));
		evt.pe.ParentPid = (ULONGLONG)ParentId;
	}
	else
	{
		//DbgPrintEx(
		//	DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "ObCallbackTest: TdCreateProcessNotifyRoutine2: process %p (ID 0x%p) destroyed\n",
		//	Process,
		//	(PVOID)ProcessId
		//);

		evt.eventType = kProcessTerminate;
		evt.pe.Pid = (ULONGLONG)ProcessId;
	}

	Publish(&evt);
}
