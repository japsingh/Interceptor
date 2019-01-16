#include "FileContext.h"

NTSTATUS CreateStreamHandleContext(PFLT_FILTER Filter, PFLT_INSTANCE Instance, PFILE_OBJECT FileObject, PUNICODE_STRING Name)
/*++

Routine Description:

	This routine creates a new streamhandle context

Arguments:

	StreamHandleContext - Returns the streamhandle context

Return Value:

	Status

--*/
{
	NTSTATUS status;
	PKSENSOR_STREAMHANDLE_CONTEXT streamHandleContext = NULL;
	PKSENSOR_STREAMHANDLE_CONTEXT oldStreamHandleContext = NULL;

	PAGED_CODE();

	//
	//  Allocate a streamhandle context
	//

	status = FltAllocateContext(Filter,
		FLT_STREAMHANDLE_CONTEXT,
		KSENSOR_STREAMHANDLE_CONTEXT_SIZE,
		PagedPool,
		(PFLT_CONTEXT*)&streamHandleContext);

	if (!NT_SUCCESS(status)) {

		//AV_DBG_PRINT(AVDBG_TRACE_ERROR,
		//	("[Av]: Failed to allocate stream handle context with status 0x%x \n",
		//		status));
		return status;
	}

	//
	//  Initialize the newly created context
	//

	RtlZeroMemory(streamHandleContext, KSENSOR_STREAMHANDLE_CONTEXT_SIZE);

	if (Name && (Name->Length > 0) && (Name->Length < sizeof(streamHandleContext->Name))) {
		RtlCopyMemory(streamHandleContext->Name, Name->Buffer, Name->Length);
	}

	status = FltSetStreamHandleContext(Instance,
		FileObject,
		FLT_SET_CONTEXT_KEEP_IF_EXISTS,
		streamHandleContext,
		(PFLT_CONTEXT *)&oldStreamHandleContext);

	FltReleaseContext(streamHandleContext);

	return STATUS_SUCCESS;
}

NTSTATUS SetFileModifiedInStreamHandleContext(PCFLT_RELATED_OBJECTS FltObjects)
{
	NTSTATUS status = STATUS_SUCCESS;
	PKSENSOR_STREAMHANDLE_CONTEXT streamHandleContext;

	status = FltGetStreamHandleContext(FltObjects->Instance,
		FltObjects->FileObject,
		(PFLT_CONTEXT*)&streamHandleContext);
	if (NT_SUCCESS(status)) {

		streamHandleContext->FileModified = TRUE;

		FltReleaseContext(streamHandleContext);
	}

	return status;
}

NTSTATUS GetStreamHandleContext(PCFLT_RELATED_OBJECTS FltObjects, PKSENSOR_STREAMHANDLE_CONTEXT *streamHandleContext)
{
	NTSTATUS status = FltGetStreamHandleContext(FltObjects->Instance,
		FltObjects->FileObject,
		(PFLT_CONTEXT *)streamHandleContext);
	//if (NT_SUCCESS(status)) {

	//	*pFileModified = streamHandleContext->FileModified;

	//	//FltReleaseContext(streamHandleContext);
	//}

	return status;
}
