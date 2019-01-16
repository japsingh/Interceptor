#pragma once
#include <fltKernel.h>
#include "ksensorcommon.h"

NTSTATUS
CreateStreamHandleContext(
	_In_ PFLT_FILTER Filter, PFLT_INSTANCE Instance, PFILE_OBJECT FileObject, PUNICODE_STRING Name
);


NTSTATUS
SetFileModifiedInStreamHandleContext(
	_In_ PCFLT_RELATED_OBJECTS FltObjects
);

NTSTATUS
GetStreamHandleContext(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Out_ PKSENSOR_STREAMHANDLE_CONTEXT *streamHandleContext
);


