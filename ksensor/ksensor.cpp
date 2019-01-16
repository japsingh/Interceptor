/*++

Module Name:

    ksensor.c

Abstract:

    This is the main module of the ksensor miniFilter driver.

Environment:

    Kernel mode

--*/

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include "ksensorcommon.h"
#include "Utils.h"
#include "FileContext.h"
#include "Comm.h"
#include "ProcessFilter.h"

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")


KSENSOR_DATA KSensorData;
ULONG_PTR OperationStatusCtx = 1;

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG gTraceFlags = 0;


#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))

/*************************************************************************
    Prototypes
*************************************************************************/

EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

VOID Uninit();

NTSTATUS
ksensorInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );

VOID
ksensorInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

VOID
ksensorInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

NTSTATUS
ksensorUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

NTSTATUS
ksensorInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
ksensorPreCreate(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_PREOP_CALLBACK_STATUS
ksensorPreCleanup(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_PREOP_CALLBACK_STATUS
ksensorPreDataWrite (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

VOID
ksensorOperationStatusCallback (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
    );

FLT_POSTOP_CALLBACK_STATUS
ksensorPostCreate (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
ksensorPreOperationNoPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

BOOLEAN
ksensorDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
    );

EXTERN_C_END

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, ksensorUnload)
#pragma alloc_text(PAGE, ksensorInstanceQueryTeardown)
#pragma alloc_text(PAGE, ksensorInstanceSetup)
#pragma alloc_text(PAGE, ksensorInstanceTeardownStart)
#pragma alloc_text(PAGE, ksensorInstanceTeardownComplete)
#endif

//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {

	{ IRP_MJ_CREATE,
	  0,
	  ksensorPreCreate,
	  ksensorPostCreate },

	{ IRP_MJ_WRITE,
	  0,
	  ksensorPreDataWrite,
	  NULL },

	{ IRP_MJ_SET_INFORMATION,
	  0,
	  ksensorPreDataWrite,
	  NULL},

	//{ IRP_MJ_FILE_SYSTEM_CONTROL,
	//  0,
	//  ksensorPreOperation,
	//  NULL},

	{ IRP_MJ_CLEANUP,
	  0,
	  ksensorPreCleanup,
	  NULL },

#if 0 // TODO - List all of the requests to filter.

    { IRP_MJ_CREATE_NAMED_PIPE,
      0,
      ksensorPreOperation,
      ksensorPostOperation },

    { IRP_MJ_CLOSE,
      0,
      ksensorPreOperation,
      ksensorPostOperation },

    { IRP_MJ_READ,
      0,
      ksensorPreOperation,
      ksensorPostOperation },


    { IRP_MJ_QUERY_INFORMATION,
      0,
      ksensorPreOperation,
      ksensorPostOperation },

    { IRP_MJ_QUERY_EA,
      0,
      ksensorPreOperation,
      ksensorPostOperation },

    { IRP_MJ_SET_EA,
      0,
      ksensorPreOperation,
      ksensorPostOperation },

    { IRP_MJ_FLUSH_BUFFERS,
      0,
      ksensorPreOperation,
      ksensorPostOperation },

    { IRP_MJ_QUERY_VOLUME_INFORMATION,
      0,
      ksensorPreOperation,
      ksensorPostOperation },

    { IRP_MJ_SET_VOLUME_INFORMATION,
      0,
      ksensorPreOperation,
      ksensorPostOperation },

    { IRP_MJ_DIRECTORY_CONTROL,
      0,
      ksensorPreOperation,
      ksensorPostOperation },

    { IRP_MJ_DEVICE_CONTROL,
      0,
      ksensorPreOperation,
      ksensorPostOperation },

    { IRP_MJ_INTERNAL_DEVICE_CONTROL,
      0,
      ksensorPreOperation,
      ksensorPostOperation },

    { IRP_MJ_SHUTDOWN,
      0,
      ksensorPreOperationNoPostOperation,
      NULL },                               //post operations not supported

    { IRP_MJ_LOCK_CONTROL,
      0,
      ksensorPreOperation,
      ksensorPostOperation },

    { IRP_MJ_CREATE_MAILSLOT,
      0,
      ksensorPreOperation,
      ksensorPostOperation },

    { IRP_MJ_QUERY_SECURITY,
      0,
      ksensorPreOperation,
      ksensorPostOperation },

    { IRP_MJ_SET_SECURITY,
      0,
      ksensorPreOperation,
      ksensorPostOperation },

    { IRP_MJ_QUERY_QUOTA,
      0,
      ksensorPreOperation,
      ksensorPostOperation },

    { IRP_MJ_SET_QUOTA,
      0,
      ksensorPreOperation,
      ksensorPostOperation },

    { IRP_MJ_PNP,
      0,
      ksensorPreOperation,
      ksensorPostOperation },

    { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
      0,
      ksensorPreOperation,
      ksensorPostOperation },

    { IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION,
      0,
      ksensorPreOperation,
      ksensorPostOperation },

    { IRP_MJ_ACQUIRE_FOR_MOD_WRITE,
      0,
      ksensorPreOperation,
      ksensorPostOperation },

    { IRP_MJ_RELEASE_FOR_MOD_WRITE,
      0,
      ksensorPreOperation,
      ksensorPostOperation },

    { IRP_MJ_ACQUIRE_FOR_CC_FLUSH,
      0,
      ksensorPreOperation,
      ksensorPostOperation },

    { IRP_MJ_RELEASE_FOR_CC_FLUSH,
      0,
      ksensorPreOperation,
      ksensorPostOperation },

    { IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE,
      0,
      ksensorPreOperation,
      ksensorPostOperation },

    { IRP_MJ_NETWORK_QUERY_OPEN,
      0,
      ksensorPreOperation,
      ksensorPostOperation },

    { IRP_MJ_MDL_READ,
      0,
      ksensorPreOperation,
      ksensorPostOperation },

    { IRP_MJ_MDL_READ_COMPLETE,
      0,
      ksensorPreOperation,
      ksensorPostOperation },

    { IRP_MJ_PREPARE_MDL_WRITE,
      0,
      ksensorPreOperation,
      ksensorPostOperation },

    { IRP_MJ_MDL_WRITE_COMPLETE,
      0,
      ksensorPreOperation,
      ksensorPostOperation },

    { IRP_MJ_VOLUME_MOUNT,
      0,
      ksensorPreOperation,
      ksensorPostOperation },

    { IRP_MJ_VOLUME_DISMOUNT,
      0,
      ksensorPreOperation,
      ksensorPostOperation },

#endif // TODO

    { IRP_MJ_OPERATION_END }
};

//
//  This defines what we want to filter with FltMgr
//

const FLT_CONTEXT_REGISTRATION ContextRegistration[] = {

	{ FLT_STREAMHANDLE_CONTEXT,
	  0,
	  NULL,
	  KSENSOR_STREAMHANDLE_CONTEXT_SIZE,
	  KSENSOR_STREAMHANDLE_CONTEXT_TAG },

	{ FLT_CONTEXT_END }
};

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags

	ContextRegistration,                               //  Context
    Callbacks,                          //  Operation callbacks

    ksensorUnload,                           //  MiniFilterUnload

    ksensorInstanceSetup,                    //  InstanceSetup
    ksensorInstanceQueryTeardown,            //  InstanceQueryTeardown
    ksensorInstanceTeardownStart,            //  InstanceTeardownStart
    ksensorInstanceTeardownComplete,         //  InstanceTeardownComplete

    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};



NTSTATUS
ksensorInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
/*++

Routine Description:

    This routine is called whenever a new instance is created on a volume. This
    gives us a chance to decide if we need to attach to this volume or not.

    If this routine is not defined in the registration structure, automatic
    instances are always created.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Flags describing the reason for this attach request.

Return Value:

    STATUS_SUCCESS - attach
    STATUS_FLT_DO_NOT_ATTACH - do not attach

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( VolumeDeviceType );
    UNREFERENCED_PARAMETER( VolumeFilesystemType );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("ksensor!ksensorInstanceSetup: Entered\n") );

    return STATUS_SUCCESS;
}


NTSTATUS
ksensorInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This is called when an instance is being manually deleted by a
    call to FltDetachVolume or FilterDetach thereby giving us a
    chance to fail that detach request.

    If this routine is not defined in the registration structure, explicit
    detach requests via FltDetachVolume or FilterDetach will always be
    failed.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Indicating where this detach request came from.

Return Value:

    Returns the status of this operation.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("ksensor!ksensorInstanceQueryTeardown: Entered\n") );

    return STATUS_SUCCESS;
}


VOID
ksensorInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the start of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("ksensor!ksensorInstanceTeardownStart: Entered\n") );
}


VOID
ksensorInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the end of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("ksensor!ksensorInstanceTeardownComplete: Entered\n") );
}


/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/

#define FILTER_REGISTERED	0x1
#define PF_INITED			0x2
#define COMM_INITED			0x4

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    This is the initialization routine for this miniFilter driver.  This
    registers with FltMgr and initializes all global data structures.

Arguments:

    DriverObject - Pointer to driver object created by the system to
        represent this driver.

    RegistryPath - Unicode string identifying where the parameters for this
        driver are located in the registry.

Return Value:

    Routine can return non success error codes.

--*/
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER( RegistryPath );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("ksensor!DriverEntry: Entered\n") );

	RtlZeroMemory(&KSensorData, sizeof(KSensorData));

    //
    //  Register with FltMgr to tell it our callback routines
    //

    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                &KSensorData.Filter );

    FLT_ASSERT( NT_SUCCESS( status ) );

    if (NT_SUCCESS( status )) {

		KSensorData.InitFlags |= FILTER_REGISTERED;

        //
        //  Start filtering i/o
        //

        status = FltStartFiltering(KSensorData.Filter);

        if (!NT_SUCCESS( status )) {

			goto Cleanup;
        }

		status = InitPF();

		if (!NT_SUCCESS(status)) {

			goto Cleanup;
		}
		KSensorData.InitFlags |= PF_INITED;

		status = InitComm();

		if (!NT_SUCCESS(status)) {

			goto Cleanup;
		}
		KSensorData.InitFlags |= COMM_INITED;
	}

Cleanup:

	if (!NT_SUCCESS(status)) {
		Uninit();
	}
    return status;
}

NTSTATUS
ksensorUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
/*++

Routine Description:

    This is the unload routine for this miniFilter driver. This is called
    when the minifilter is about to be unloaded. We can fail this unload
    request if this is not a mandatory unload indicated by the Flags
    parameter.

Arguments:

    Flags - Indicating if this is a mandatory unload.

Return Value:

    Returns STATUS_SUCCESS.

--*/
{
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("ksensor!ksensorUnload: Entered\n") );

	Uninit();

    return STATUS_SUCCESS;
}

VOID Uninit()
{
	if (FlagOn(KSensorData.InitFlags, COMM_INITED)) {
		UninitComm();
	}
	if (FlagOn(KSensorData.InitFlags, PF_INITED)) {
		UninitPF();
	}
	if (FlagOn(KSensorData.InitFlags, FILTER_REGISTERED)) {
		FltUnregisterFilter(KSensorData.Filter);
	}
}

/*************************************************************************
    MiniFilter callback routines.
*************************************************************************/

FLT_PREOP_CALLBACK_STATUS
ksensorPreCreate(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID * /*CompletionContext*/
)
/*++

Routine Description:

	This routine is the pre-create completion routine.


Arguments:

	Data - Pointer to the filter callbackData that is passed to us.

	FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
		opaque handles to this filter, instance, its associated volume and
		file object.

	CompletionContext - If this callback routine returns FLT_PREOP_SUCCESS_WITH_CALLBACK or
		FLT_PREOP_SYNCHRONIZE, this parameter is an optional context pointer to be passed to
		the corresponding post-operation callback routine. Otherwise, it must be NULL.

Return Value:

	FLT_PREOP_SYNCHRONIZE - PostCreate needs to be called back synchronizedly.
	FLT_PREOP_SUCCESS_NO_CALLBACK - PostCreate does not need to be called.

--*/
{
	ULONG_PTR stackLow;
	ULONG_PTR stackHigh;
	PFILE_OBJECT FileObject = Data->Iopb->TargetFileObject;
	//KSENSOR_STREAMHANDLE_CONTEXT streamHandleContext;


	PAGED_CODE();

	//AV_DBG_PRINT(AVDBG_TRACE_ROUTINES,
	//	("[AV] AvPreCreate: Entered\n"));

	//streamHandleContext.FileModified = FALSE;

	//
	//  Stack file objects are never scanned.
	//

	IoGetStackLimits(&stackLow, &stackHigh);

	if (((ULONG_PTR)FileObject > stackLow) &&
		((ULONG_PTR)FileObject < stackHigh)) {

		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	//
	//  Directory opens don't need to be scanned.
	//

	if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE)) {

		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	//
	//  Skip pre-rename operations which always open a directory.
	//

	if (FlagOn(Data->Iopb->OperationFlags, SL_OPEN_TARGET_DIRECTORY)) {

		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	//
	//  Skip paging files.
	//

	if (FlagOn(Data->Iopb->OperationFlags, SL_OPEN_PAGING_FILE)) {

		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	//
	//  Skip scanning DASD opens 
	//

	if (FlagOn(FltObjects->FileObject->Flags, FO_VOLUME_OPEN)) {

		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	////
	//// Skip scanning any files being opened by CSVFS for its downlevel
	//// processing. This includes filters on the hidden NTFS stack and
	//// for filters attached to MUP
	////
	//if (AvIsCsvDlEcpPresent(FltObjects->Filter, Data)) {

	//	return FLT_PREOP_SUCCESS_NO_CALLBACK;
	//}


	////
	////  Flag prefetch handles so they can be skipped. Performing IO
	////  using a prefetch fileobject could lead to a deadlock.
	////

	//if (AvIsPrefetchEcpPresent(FltObjects->Filter, Data)) {

	//	SetFlag(streamHandleContext.Flags, AV_FLAG_PREFETCH);
	//}

	//*CompletionContext = (PVOID)streamHandleContext.Flags;

	////
	//// Perform any CSVFS pre create processing
	////
	//AvPreCreateCsvfs(Data, FltObjects);

	//
	// return status can be safely ignored
	//

	//
	//  Return FLT_PREOP_SYNCHRONIZE at PreCreate to ensure PostCreate 
	//  is in the same thread at passive level. 
	//  EResource can't be acquired at DPC.
	//

	return FLT_PREOP_SYNCHRONIZE;

}

FLT_PREOP_CALLBACK_STATUS
ksensorPreCleanup(
	_Inout_ PFLT_CALLBACK_DATA /*Data*/,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
/*++

Routine Description:

	Pre-cleanup callback. Make the stream context persistent in the volatile cache.
	If the file is transacted, it will be synced at KTM notification callback
	if committed.

Arguments:

	Data - Pointer to the filter callbackData that is passed to us.

	FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
		opaque handles to this filter, instance, its associated volume and
		file object.

	CompletionContext - If this callback routine returns FLT_PREOP_SUCCESS_WITH_CALLBACK or
		FLT_PREOP_SYNCHRONIZE, this parameter is an optional context pointer to be passed to
		the corresponding post-operation callback routine. Otherwise, it must be NULL.

Return Value:

	The return value is the status of the operation.

--*/
{
	NTSTATUS status = STATUS_SUCCESS;
	//BOOLEAN encrypted = FALSE;
	//PKSENSOR_STREAMHANDLE_CONTEXT streamHandleContext = NULL;
	//ULONG_PTR stackLow;
	//ULONG_PTR stackHigh;
	//BOOLEAN FileModified = FALSE;

	UNREFERENCED_PARAMETER(CompletionContext);

	PAGED_CODE();

	////
	////  Skip scan on prefetcher handles to avoid deadlocks
	////

	//status = FltGetStreamHandleContext(FltObjects->Instance,
	//	FltObjects->FileObject,
	//	&streamHandleContext);
	//if (NT_SUCCESS(status)) {

	PKSENSOR_STREAMHANDLE_CONTEXT streamHandleContext = NULL;
	status = GetStreamHandleContext(FltObjects, &streamHandleContext);
	if (NT_SUCCESS(status)) {
		if (streamHandleContext->FileModified) {
			EVENT evt;
			RtlZeroMemory(&evt, sizeof(evt));
			RtlCopyMemory(evt.fe.Name, streamHandleContext->Name, sizeof(evt.fe.Name));

			GetProcessImageName(evt.fe.InitiatorName, sizeof(evt.fe.InitiatorName));
			/*NTSTATUS publishStatus = */Publish(&evt);
		}
		FltReleaseContext(streamHandleContext);

		goto Cleanup;
	}

	////
	////  Stack file objects are never scanned.
	////

	//IoGetStackLimits(&stackLow, &stackHigh);

	//if (((ULONG_PTR)FltObjects->FileObject > stackLow) &&
	//	((ULONG_PTR)FltObjects->FileObject < stackHigh)) {

	//	goto Cleanup;
	//}

Cleanup:

	//
	//  We only insert the entry when the file is clean or infected.
	//

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
ksensorPreDataWrite (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    This routine is a pre-operation dispatch routine for this miniFilter.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
    NTSTATUS status;
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("ksensor!ksensorPreOperation: Entered\n") );

    //
    //  See if this is an operation we would like the operation status
    //  for.  If so request it.
    //
    //  NOTE: most filters do NOT need to do this.  You only need to make
    //        this call if, for example, you need to know if the oplock was
    //        actually granted.
    //

    //if (ksensorDoRequestOperationStatus( Data )) {

    //    status = FltRequestOperationStatusCallback( Data,
    //                                                ksensorOperationStatusCallback,
    //                                                (PVOID)(++OperationStatusCtx) );
    //    if (!NT_SUCCESS(status)) {

    //        PT_DBG_PRINT( PTDBG_TRACE_OPERATION_STATUS,
    //                      ("ksensor!ksensorPreOperation: FltRequestOperationStatusCallback Failed, status=%08x\n",
    //                       status) );
    //    }
    //}

    // This template code does not do anything with the callbackData, but
    // rather returns FLT_PREOP_SUCCESS_WITH_CALLBACK.
    // This passes the request down to the next miniFilter in the chain.

	if (!IsOperationsModifyingFile(Data)) {

		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	status = SetFileModifiedInStreamHandleContext(FltObjects);
	if (NT_SUCCESS(status)) {
		// log
	}

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}



VOID
ksensorOperationStatusCallback (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
    )
/*++

Routine Description:

    This routine is called when the given operation returns from the call
    to IoCallDriver.  This is useful for operations where STATUS_PENDING
    means the operation was successfully queued.  This is useful for OpLocks
    and directory change notification operations.

    This callback is called in the context of the originating thread and will
    never be called at DPC level.  The file object has been correctly
    referenced so that you can access it.  It will be automatically
    dereferenced upon return.

    This is non-pageable because it could be called on the paging path

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    RequesterContext - The context for the completion routine for this
        operation.

    OperationStatus -

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("ksensor!ksensorOperationStatusCallback: Entered\n") );

    PT_DBG_PRINT( PTDBG_TRACE_OPERATION_STATUS,
                  ("ksensor!ksensorOperationStatusCallback: Status=%08x ctx=%p IrpMj=%02x.%02x \"%s\"\n",
                   OperationStatus,
                   RequesterContext,
                   ParameterSnapshot->MajorFunction,
                   ParameterSnapshot->MinorFunction,
                   FltGetIrpName(ParameterSnapshot->MajorFunction)) );
}

FLT_POSTOP_CALLBACK_STATUS
ksensorPostCreate(_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)
/*++

Routine Description:

	This routine is the post-create completion routine.
	In this routine, stream context and/or transaction context shall be
	created if not exits.

	Note that we only allocate and set the stream context to filter manager
	at post create.

Arguments:

	Data - Pointer to the filter callbackData that is passed to us.

	FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
		opaque handles to this filter, instance, its associated volume and
		file object.

	CompletionContext - The completion context set in the pre-create routine.

	Flags - Denotes whether the completion is successful or is being drained.

Return Value:

	The return value is the status of the operation.

--*/
{
	NTSTATUS status = Data->IoStatus.Status;
	BOOLEAN isDir = FALSE;

	//ACCESS_MASK desiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
	//BOOLEAN updateRevisionNumbers;
	//LONGLONG VolumeRevision, CacheRevision, FileRevision;

	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	if (!NT_SUCCESS(status) ||
		(status == STATUS_REPARSE)) {

		//
		//  File Creation may fail.
		//

		//AV_DBG_PRINT(AVDBG_TRACE_ROUTINES,
		//	("[AV] AvPostCreate: file creation failed\n"));

		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	//
	//  After creation, skip it if it is directory.
	//

	status = FltIsDirectory(FltObjects->FileObject,
		FltObjects->Instance,
		&isDir);

	//
	//  If FltIsDirectory failed, we do not know if it is a directoy,
	//  we let it go through because if it is a directory, it will fail
	//  at section creation anyway.
	//

	if (NT_SUCCESS(status) && isDir) {

		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	//
	//  We skip the encrypted file open without FILE_WRITE_DATA and FILE_READ_DATA
	//  This is because if application calls OpenEncryptedFileRaw(...) for backup, 
	//  it won't have to decrypt the file. In such case, if we scan it, we will hit 
	//  an assertion error in NTFS because it does not have the encryption context.
	//  Thus, we have to skip the encrypted file not open for read/write.
	//

	//if (!(FlagOn(desiredAccess, FILE_WRITE_DATA)) &&
	//	!(FlagOn(desiredAccess, FILE_READ_DATA))) {

	//	BOOLEAN encrypted = FALSE;
	//	status = AvGetFileEncrypted(FltObjects->Instance,
	//		FltObjects->FileObject,
	//		&encrypted);
	//	if (!NT_SUCCESS(status)) {

	//		AV_DBG_PRINT(AVDBG_TRACE_ROUTINES,
	//			("[AV] AvPostCreate: AvGetFileEncrypted FAILED!! \n0x%x\n", status));
	//	}
	//	if (encrypted) {

	//		return FLT_POSTOP_FINISHED_PROCESSING;
	//	}
	//}

	////
	////  In this sample, we skip the alternate data stream. However, you may decide 
	////  to scan it and modify accordingly.
	////

	//if (AvIsStreamAlternate(Data)) {

	//	return FLT_POSTOP_FINISHED_PROCESSING;
	//}

	////
	////  Skip a prefetch open and flag it so we skip subsequent
	////  IO operations on the handle.
	////

	//if (FlagOn((ULONG_PTR)CompletionContext, AV_FLAG_PREFETCH)) {

	//	if (!FltSupportsStreamHandleContexts(FltObjects->FileObject)) {

	//		return FLT_POSTOP_FINISHED_PROCESSING;
	//	}

	//	status = AvCreateStreamHandleContext(FltObjects->Filter,
	//		&streamHandleContext);

	//	if (!NT_SUCCESS(status)) {

	//		return FLT_POSTOP_FINISHED_PROCESSING;
	//	}

	//	SetFlag(streamHandleContext->Flags, AV_FLAG_PREFETCH);

	//	status = FltSetStreamHandleContext(FltObjects->Instance,
	//		FltObjects->FileObject,
	//		FLT_SET_CONTEXT_KEEP_IF_EXISTS,
	//		streamHandleContext,
	//		NULL);

	//	FltReleaseContext(streamHandleContext);

	//	if (!NT_SUCCESS(status)) {

	//		//
	//		// Shouldn't find the handle already set
	//		//

	//		ASSERT(status != STATUS_FLT_CONTEXT_ALREADY_DEFINED);
	//	}

	//	return FLT_POSTOP_FINISHED_PROCESSING;
	//}

	////
	////  Find or create a stream context
	////

	//status = FltGetStreamContext(FltObjects->Instance,
	//	FltObjects->FileObject,
	//	&streamContext);

	//if (status == STATUS_NOT_FOUND) {

	//	//
	//	//  Create a stream context
	//	//

	//	status = AvCreateStreamContext(FltObjects->Filter, &streamContext);

	//	if (!NT_SUCCESS(status)) {

	//		AV_DBG_PRINT(AVDBG_TRACE_ERROR,
	//			("[Av]: Failed to create stream context with status 0x%x. (FileObject = %p, Instance = %p)\n",
	//				status,
	//				FltObjects->FileObject,
	//				FltObjects->Instance));

	//		return FLT_POSTOP_FINISHED_PROCESSING;
	//	}

	//	//
	//	//  Attempt to get the stream infected state from our cache
	//	//            

	//	status = AvGetFileId(FltObjects->Instance, FltObjects->FileObject, &streamContext->FileId);

	//	if (!NT_SUCCESS(status)) {

	//		AV_DBG_PRINT(AVDBG_TRACE_ROUTINES,
	//			("[Av]: Failed to get file id with status 0x%x. (FileObject = %p, Instance = %p)\n",
	//				status,
	//				FltObjects->FileObject,
	//				FltObjects->Instance));

	//		//
	//		//  File id is optional and therefore should not affect the scan logic.
	//		//

	//		AV_SET_INVALID_FILE_REFERENCE(streamContext->FileId)

	//	}
	//	else {

	//		//
	//		//  This function will load the file infected state from the 
	//		//  cache if the fileID is valid. Even if this function fails,
	//		//  we still have to move on because the cache is optional.
	//		//

	//		AvLoadFileStateFromCache(FltObjects->Instance,
	//			&streamContext->FileId,
	//			&streamContext->State,
	//			&streamContext->VolumeRevision,
	//			&streamContext->CacheRevision,
	//			&streamContext->FileRevision);
	//	}

	//	//
	//	//  Set the new context we just allocated on the file object
	//	//

	//	status = FltSetStreamContext(FltObjects->Instance,
	//		FltObjects->FileObject,
	//		FLT_SET_CONTEXT_KEEP_IF_EXISTS,
	//		streamContext,
	//		&oldStreamContext);

	//	if (!NT_SUCCESS(status)) {

	//		if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED) {

	//			//
	//			//  Race condition. Someone has set a context after we queried it.
	//			//  Use the already set context instead
	//			//

	//			AV_DBG_PRINT(AVDBG_TRACE_ERROR,
	//				("[Av]: Race: Stream context already defined. Retaining old stream context %p (FileObject = %p, Instance = %p)\n",
	//					oldStreamContext,
	//					FltObjects->FileObject,
	//					FltObjects->Instance));

	//			FltReleaseContext(streamContext);

	//			streamContext = oldStreamContext;

	//		}
	//		else {

	//			AV_DBG_PRINT(AVDBG_TRACE_ERROR,
	//				("[Av]: Failed to set stream context with status 0x%x. (FileObject = %p, Instance = %p)\n",
	//					status,
	//					FltObjects->FileObject,
	//					FltObjects->Instance));
	//			goto Cleanup;
	//		}
	//	}

	//}
	//else if (!NT_SUCCESS(status)) {

	//	//
	//	//  We will get here if stream contexts are not supported
	//	//

	//	AV_DBG_PRINT(AVDBG_TRACE_ERROR,
	//		("[Av]: Failed to get stream context with status 0x%x. (FileObject = %p, Instance = %p)\n",
	//			status,
	//			FltObjects->FileObject,
	//			FltObjects->Instance));

	//	return FLT_POSTOP_FINISHED_PROCESSING;
	//}

	//
	//  If successfully opened a file with the desired access matching
	//  the "exclusive write" from a TxF point of view, we can guarantee that 
	//  if previous transaction context exists, it must have been comitted 
	//  or rollbacked.
	//

	//if (FlagOn(Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess,
	//	FILE_WRITE_DATA | FILE_APPEND_DATA |
	//	DELETE | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA |
	//	WRITE_DAC | WRITE_OWNER | ACCESS_SYSTEM_SECURITY)) {

		////
		////  Either this file is opened in a transaction context or not,
		////  we need to process the previous transaction if it exists.
		////  AvProcessPreviousTransaction(...) handles these cases.
		////

		//status = AvProcessPreviousTransaction(FltObjects,
		//	streamContext);
		//if (!NT_SUCCESS(status)) {

		//	AV_DBG_PRINT(AVDBG_TRACE_ERROR,
		//		("[AV] AvPostCreate: AvProcessTransaction FAILED!! \n"));

		//	goto Cleanup;
		//}

		//isTxWriter = (FltObjects->Transaction != NULL);
	//}

	////
	//// Perform any CSVFS specific processing
	////
	//AvPostCreateCsvfs(Data,
	//	FltObjects,
	//	streamContext,
	//	&updateRevisionNumbers,
	//	&VolumeRevision,
	//	&CacheRevision,
	//	&FileRevision);
	//
	// Ignore return status
	//



	//if (FlagOn(streamContext)) {

	//	status = AvScan(Data,
	//		FltObjects,
	//		AvUserMode,
	//		Data->Iopb->MajorFunction,
	//		isTxWriter,
	//		streamContext);
	//	if (!NT_SUCCESS(status) ||
	//		(STATUS_TIMEOUT == status)) {

	//		AV_DBG_PRINT(AVDBG_TRACE_ROUTINES,
	//			("[AV] AvPostCreate: AvScan FAILED!! \n"));

	//		goto Cleanup;
	//	}
	//}


	//
	// If needed, update the stream context with the latest revision
	// numbers that correspond to the verion just scanned
	//
	//if (updateRevisionNumbers) {
	//	streamContext->VolumeRevision = VolumeRevision;
	//	streamContext->CacheRevision = CacheRevision;
	//	streamContext->FileRevision = FileRevision;

	//	AV_DBG_PRINT(AVDBG_TRACE_DEBUG,
	//		("[Av]: AvPostCreate: RevisionNumbers updated to %I64x:%I64x:%I64x\n",
	//			VolumeRevision,
	//			CacheRevision,
	//			FileRevision)
	//	);
	//}

	//if (IS_FILE_INFECTED(streamContext)) {

	//	//
	//	//  If the file is infected, deny the access.
	//	//
	//	AvCancelFileOpen(Data, FltObjects, STATUS_VIRUS_INFECTED);

	//	//
	//	//  If the scan timed-out or scan was failed, we let the create succeed, 
	//	//  and it may cause security hole;
	//	//
	//	//  Alternatively, you can add a state called AvFileScanFailure or equivalent,
	//	//  add a condition here and fail the create.  This option will have better 
	//	//  protection from viruses, but the apps will see the failures due to a 
	//	//  lengthy scan or scan failure. It's a trade-off.
	//	//
	//	goto Cleanup;
	//}

	status = CreateStreamHandleContext(KSensorData.Filter, Data->Iopb->TargetInstance, FltObjects->FileObject, &FltObjects->FileObject->FileName);

//Cleanup:


	return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_POSTOP_CALLBACK_STATUS
ksensorPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
/*++

Routine Description:

    This routine is the post-operation completion routine for this
    miniFilter.

    This is non-pageable because it may be called at DPC level.

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The completion context set in the pre-operation routine.

    Flags - Denotes whether the completion is successful or is being drained.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );
    UNREFERENCED_PARAMETER( Flags );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("ksensor!ksensorPostOperation: Entered\n") );

    return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
ksensorPreOperationNoPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    This routine is a pre-operation dispatch routine for this miniFilter.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("ksensor!ksensorPreOperationNoPostOperation: Entered\n") );

    // This template code does not do anything with the callbackData, but
    // rather returns FLT_PREOP_SUCCESS_NO_CALLBACK.
    // This passes the request down to the next miniFilter in the chain.

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


BOOLEAN
ksensorDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
    )
/*++

Routine Description:

    This identifies those operations we want the operation status for.  These
    are typically operations that return STATUS_PENDING as a normal completion
    status.

Arguments:

Return Value:

    TRUE - If we want the operation status
    FALSE - If we don't

--*/
{
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

    //
    //  return boolean state based on which operations we are interested in
    //

    return (BOOLEAN)

            //
            //  Check for oplock operations
            //

             (((iopb->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) &&
               ((iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_FILTER_OPLOCK)  ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_BATCH_OPLOCK)   ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_1) ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_2)))

              ||

              //
              //    Check for directy change notification
              //

              ((iopb->MajorFunction == IRP_MJ_DIRECTORY_CONTROL) &&
               (iopb->MinorFunction == IRP_MN_NOTIFY_CHANGE_DIRECTORY))
             );
}
