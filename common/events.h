#pragma once

#define COMM_PORT_NAME                   L"\\KSensorPort"

enum EVENT_T
{
	kFileWrite,
	kProcessCreate,
	kProcessTerminate
};

struct PROCESS_EVENT
{
	WCHAR Name[1024];
	WCHAR InitiatorName[1024];
	WCHAR Commandline[1024];
	ULONGLONG Pid;
	ULONGLONG ParentPid;
};


struct FILE_EVENT
{
	WCHAR Name[1024];
	WCHAR InitiatorName[1024];
};

struct EVENT
{
	EVENT_T eventType;
	union {
		FILE_EVENT fe;
		PROCESS_EVENT pe;
	};
};

