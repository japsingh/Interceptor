#pragma once
#include <fltKernel.h>

BOOLEAN
IsOperationsModifyingFile(
	_In_ PFLT_CALLBACK_DATA Data
);

NTSTATUS GetProcessImageName(WCHAR *ProcessImageName, ULONG size);
