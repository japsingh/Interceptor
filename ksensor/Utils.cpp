#include "Utils.h"

BOOLEAN IsOperationsModifyingFile(PFLT_CALLBACK_DATA Data)
/*++

Routine Description:

	This identifies those operations we need to set the file to be modified.

Arguments:

	Data - Pointer to the filter callbackData that is passed to us.

Return Value:

	TRUE - If we want the file associated with the request to be modified.
	FALSE - If we don't

--*/
{
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

	PAGED_CODE();

	switch (iopb->MajorFunction) {

	case IRP_MJ_WRITE:
		return TRUE;

	//case IRP_MJ_FILE_SYSTEM_CONTROL:
	//	switch (iopb->Parameters.FileSystemControl.Common.FsControlCode) {
	//	case FSCTL_OFFLOAD_WRITE:
	//	case FSCTL_WRITE_RAW_ENCRYPTED:
	//	case FSCTL_SET_ZERO_DATA:
	//		return TRUE;
	//	default: break;
	//	}
	//	break;

	case IRP_MJ_SET_INFORMATION:
		switch (iopb->Parameters.SetFileInformation.FileInformationClass) {
		case FileEndOfFileInformation:
		case FileValidDataLengthInformation:
			return TRUE;
		default: break;
		}
		break;
	default:
		break;
	}
	return FALSE;
}

typedef NTSTATUS(*QUERY_INFO_PROCESS) (
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength,
	__out_opt PULONG ReturnLength
	);

QUERY_INFO_PROCESS ZwQueryInformationProcess;

NTSTATUS GetProcessImageName(WCHAR *ProcessImageName, ULONG ProcessImageNameSize)
{
	NTSTATUS status;
	ULONG returnedLength;
	ULONG bufferLength;
	PVOID buffer;
	PUNICODE_STRING imageName;

	PAGED_CODE(); // this eliminates the possibility of the IDLE Thread/Process

	if (NULL == ZwQueryInformationProcess) {

		UNICODE_STRING routineName;

		RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess");

		ZwQueryInformationProcess =
			(QUERY_INFO_PROCESS)MmGetSystemRoutineAddress(&routineName);

		if (NULL == ZwQueryInformationProcess) {
			DbgPrint("Cannot resolve ZwQueryInformationProcess\n");
		}
	}
	//
	// Step one - get the size we need
	//
	status = ZwQueryInformationProcess(NtCurrentProcess(),
		ProcessImageFileName,
		NULL, // buffer
		0, // buffer size
		&returnedLength);

	if (STATUS_INFO_LENGTH_MISMATCH != status) {

		return status;

	}

	//
	// Is the passed-in buffer going to be big enough for us?  
	// This function returns a single contguous buffer model...
	//
	bufferLength = returnedLength - sizeof(UNICODE_STRING);

	if (ProcessImageNameSize < bufferLength) {

		//ProcessImageName->Length = (USHORT)bufferLength;

		return STATUS_BUFFER_OVERFLOW;

	}

	//
	// If we get here, the buffer IS going to be big enough for us, so 
	// let's allocate some storage.
	//
	buffer = ExAllocatePoolWithTag(PagedPool, returnedLength, 'ipgD');

	if (NULL == buffer) {

		return STATUS_INSUFFICIENT_RESOURCES;

	}

	//
	// Now lets go get the data
	//
	status = ZwQueryInformationProcess(NtCurrentProcess(),
		ProcessImageFileName,
		buffer,
		returnedLength,
		&returnedLength);

	if (NT_SUCCESS(status)) {
		//
		// Ah, we got what we needed
		//
		imageName = (PUNICODE_STRING)buffer;

		RtlCopyMemory(ProcessImageName, imageName->Buffer, imageName->Length);
		//RtlCopyUnicodeString(ProcessImageName, imageName);

	}

	//
	// free our buffer
	//
	ExFreePool(buffer);

	//
	// And tell the caller what happened.
	//    
	return status;

}

