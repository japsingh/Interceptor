#pragma once
#include <fltKernel.h>

//---------------------------------------------------------------------------
//      Global variables
//---------------------------------------------------------------------------

struct KSENSOR_DATA {

	ULONG InitFlags;

	//
	//  The object that identifies this driver.
	//

	PDRIVER_OBJECT DriverObject;

	//
	//  The filter that results from a call to
	//  FltRegisterFilter.
	//

	PFLT_FILTER Filter;

	//
	//  Server port: user mode connects to this port
	//

	PFLT_PORT ServerPort;

	//
	//  Client connection port: only one connection is allowed at a time.,
	//

	PFLT_PORT ClientPort;

	////
	////  List of buffers with data to send to user mode.
	////

	//KSPIN_LOCK OutputBufferLock;
	//LIST_ENTRY OutputBufferList;

	////
	////  Lookaside list used for allocating buffers.
	////

	//NPAGED_LOOKASIDE_LIST FreeBufferList;

	////
	////  Variables used to throttle how many records buffer we can use
	////

	//LONG MaxRecordsToAllocate;
	//__volatile LONG RecordsAllocated;

	////
	////  static buffer used for sending an "out-of-memory" message
	////  to user mode.
	////

	//__volatile LONG StaticBufferInUse;

	////
	////  We need to make sure this buffer aligns on a PVOID boundary because
	////  minispy casts this buffer to a RECORD_LIST structure.
	////  That can cause alignment faults unless the structure starts on the
	////  proper PVOID boundary
	////

	//PVOID OutOfMemoryBuffer[RECORD_SIZE / sizeof(PVOID)];

	////
	////  Variable and lock for maintaining LogRecord sequence numbers.
	////

	//__volatile LONG LogSequenceNumber;

	////
	////  The name query method to use.  By default, it is set to
	////  FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, but it can be overridden
	////  by a setting in the registery.
	////

	//ULONG NameQueryMethod;

	////
	////  Global debug flags
	////

	//ULONG DebugFlags;

};

extern KSENSOR_DATA KSensorData;


struct KSENSOR_STREAMHANDLE_CONTEXT {

	BOOLEAN FileModified;
	WCHAR Name[1024];
};

typedef KSENSOR_STREAMHANDLE_CONTEXT * PKSENSOR_STREAMHANDLE_CONTEXT;

#define KSENSOR_STREAMHANDLE_CONTEXT_SIZE  sizeof( KSENSOR_STREAMHANDLE_CONTEXT )

#define KSENSOR_STREAMHANDLE_CONTEXT_TAG          'hSKs'
