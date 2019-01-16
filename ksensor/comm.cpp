#include <fltKernel.h>
#include "comm.h"
#include "ksensorcommon.h"



NTSTATUS FLTAPI
CommConnect(
	_In_ PFLT_PORT ClientPort,
	_In_opt_ PVOID ServerPortCookie,
	_In_reads_bytes_(SizeOfContext) PVOID ConnectionContext,
	_In_ ULONG SizeOfContext,
	_Flt_ConnectionCookie_Outptr_ PVOID *ConnectionCookie
);

VOID FLTAPI
CommDisconnect(
	_In_opt_ PVOID ConnectionCookie
);

NTSTATUS FLTAPI
CommMessage(
	_In_ PVOID ConnectionCookie,
	_In_reads_bytes_opt_(InputBufferSize) PVOID InputBuffer,
	_In_ ULONG InputBufferSize,
	_Out_writes_bytes_to_opt_(OutputBufferSize, *ReturnOutputBufferLength) PVOID OutputBuffer,
	_In_ ULONG OutputBufferSize,
	_Out_ PULONG ReturnOutputBufferLength
);

NTSTATUS InitComm()
{
	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING uniString;
	PSECURITY_DESCRIPTOR secDesc = NULL;
	NTSTATUS status = STATUS_SUCCESS;

	RtlInitUnicodeString(&uniString, COMM_PORT_NAME);

	status = FltBuildDefaultSecurityDescriptor(&secDesc, FLT_PORT_ALL_ACCESS);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	InitializeObjectAttributes(&oa,
		&uniString,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
		NULL,
		secDesc);

	status = FltCreateCommunicationPort(KSensorData.Filter,
		&KSensorData.ServerPort,
		&oa,
		NULL,
		CommConnect,
		CommDisconnect,
		NULL,
		1);

	FltFreeSecurityDescriptor(secDesc);
	return status;
}

VOID UninitComm()
{
	if (KSensorData.ServerPort) {
		FltCloseCommunicationPort(KSensorData.ServerPort);
	}
}

NTSTATUS Publish(EVENT * evt)
{
	NTSTATUS status = STATUS_SUCCESS;
	LONGLONG _1ms = 10000;
	LARGE_INTEGER timeout = { 0 };

	if (KSensorData.ClientPort == NULL) {
		return STATUS_CONNECTION_INVALID;
	}

	timeout.QuadPart = -(1000 * _1ms);

	status = FltSendMessage(KSensorData.Filter,
		&KSensorData.ClientPort,
		evt,
		sizeof(EVENT),
		NULL,
		0,
		&timeout);

	return status;
}


// private functions

NTSTATUS FLTAPI
CommConnect(
	_In_ PFLT_PORT ClientPort,
	_In_opt_ PVOID ServerPortCookie,
	_In_reads_bytes_(SizeOfContext) PVOID ConnectionContext,
	_In_ ULONG SizeOfContext,
	_Flt_ConnectionCookie_Outptr_ PVOID *ConnectionCookie
)
/*++

Routine Description

	This is called when user-mode connects to the server
	port - to establish a connection

Arguments

	ClientPort - This is the pointer to the client port that
		will be used to send messages from the filter.
	ServerPortCookie - unused
	ConnectionContext - unused
	SizeofContext   - unused
	ConnectionCookie - unused

Return Value

	STATUS_SUCCESS - to accept the connection
--*/
{

	PAGED_CODE();

	UNREFERENCED_PARAMETER(ServerPortCookie);
	UNREFERENCED_PARAMETER(ConnectionContext);
	UNREFERENCED_PARAMETER(SizeOfContext);
	UNREFERENCED_PARAMETER(ConnectionCookie);

	FLT_ASSERT(KSensorData.ClientPort == NULL);
	KSensorData.ClientPort = ClientPort;
	return STATUS_SUCCESS;
}

VOID FLTAPI
CommDisconnect(
	_In_opt_ PVOID ConnectionCookie
)
/*++

Routine Description

	This is called when the connection is torn-down. We use it to close our handle to the connection

Arguments

	ConnectionCookie - unused

Return value

	None
--*/
{

	PAGED_CODE();

	UNREFERENCED_PARAMETER(ConnectionCookie);

	//
	//  Close our handle
	//

	FltCloseClientPort(KSensorData.Filter, &KSensorData.ClientPort);
}
