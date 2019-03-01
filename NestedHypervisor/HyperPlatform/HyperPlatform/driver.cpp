// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements an entry point of the driver.

#ifndef POOL_NX_OPTIN
#define POOL_NX_OPTIN 1
#endif
#include "driver.h"
#include "common.h"
#include "log.h"
#include "util.h"
#include "vm.h"
#ifndef HYPERPLATFORM_PERFORMANCE_ENABLE_PERFCOUNTER
#define HYPERPLATFORM_PERFORMANCE_ENABLE_PERFCOUNTER 1
#endif  // HYPERPLATFORM_PERFORMANCE_ENABLE_PERFCOUNTER
#include "performance.h"
#include "../../DdiMon/ddi_mon.h"
struct Page1 {
	UCHAR* page;
	Page1();
	~Page1();
};
#define DDI_WIN32_DEVICE_NAME_A		"\\\\.\\DdiMon"
#define DDI_WIN32_DEVICE_NAME_W		L"\\\\.\\DdiMon"
#define DDI_DEVICE_NAME_A			"\\Device\\DdiMon"
#define DDI_DEVICE_NAME_W			L"\\Device\\DdiMon"
#define DDI_DOS_DEVICE_NAME_A		"\\DosDevices\\DdiMon"
#define DDI_DOS_DEVICE_NAME_W		L"\\DosDevices\\DdiMon"
typedef struct _DEVICE_EXTENSION
{
	ULONG  StateVariable;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;


extern "C" {
	////////////////////////////////////////////////////////////////////////////////
	//
	// macro utilities
	//

	////////////////////////////////////////////////////////////////////////////////
	//
	// constants and macros
	//

	////////////////////////////////////////////////////////////////////////////////
	//
	// types
	//

	////////////////////////////////////////////////////////////////////////////////
	//
	// prototypes
	//

	DRIVER_INITIALIZE DriverEntry;

	static DRIVER_UNLOAD DriverpDriverUnload;

	_IRQL_requires_max_(PASSIVE_LEVEL) bool DriverpIsSuppoetedOS();

#if defined(ALLOC_PRAGMA)
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DriverpDriverUnload)
#pragma alloc_text(INIT, DriverpIsSuppoetedOS)
#endif

	////////////////////////////////////////////////////////////////////////////////
	//
	// variables
	//
#define IOCTL_TRANSFER_TYPE( _iocontrol)   (_iocontrol & 0x3)

	////////////////////////////////////////////////////////////////////////////////
	//
	// implementations
	// 
	NTSTATUS DDI_devCtrlRoutine(
		IN PDEVICE_OBJECT		DeviceObject,
		IN PIRP					Irp
	)
	{
		PIO_STATUS_BLOCK	ioStatus;
		PIO_STACK_LOCATION	pIrpStack;
		PDEVICE_EXTENSION	deviceExtension;
		PVOID				inputBuffer, outputBuffer;
		ULONG				inputBufferLength, outputBufferLength;
		ULONG				ioControlCode;

		/*	dprintf("[$XTR]--->IrpMjXTRdevCtrlRoutine( 0x%08x, 0x%08x ).\n", DeviceObject, Irp);*/

		pIrpStack = IoGetCurrentIrpStackLocation(Irp);
		deviceExtension = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

		ioStatus = &Irp->IoStatus;
		ioStatus->Status = STATUS_SUCCESS;	// Assume success
		ioStatus->Information = 0;              // Assume nothing returned

												//
												// Get the pointer to the input/output buffer and it's length
		inputBuffer = Irp->AssociatedIrp.SystemBuffer;
		inputBufferLength = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
		outputBuffer = Irp->AssociatedIrp.SystemBuffer;
		outputBufferLength = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;
		ioControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;


		switch (pIrpStack->MajorFunction)
		{
		case IRP_MJ_CREATE:
			DbgPrint("[$ARK]<-IRP_MJ_CREATE.\n");
			break;

		case IRP_MJ_CLOSE:
			DbgPrint("[$ARK]->IRP_MJ_CLOSE.\n");
			break;

		case IRP_MJ_SHUTDOWN:
			DbgPrint("[$ARK] IRP_MJ_SHUTDOWN.\n");
			break;

		case IRP_MJ_DEVICE_CONTROL:
			if (IOCTL_TRANSFER_TYPE(ioControlCode) == METHOD_NEITHER)
			{
				DbgPrint("[$ARK] METHOD_NEITHER\n");
				outputBuffer = Irp->UserBuffer;
			}

			//
			DbgPrint("[$XTR] IRP_MJ_DEVICE_CONTROL->IrpMjXTRdevCtrlRoutine(DeviceObject=0x%08x, Irp=0x%08x)->ARKioControl().\n", DeviceObject, Irp);

			break;
		}

		//
		// TODO: if not pending, call IoCompleteRequest and Irp is freed.
		//

		Irp->IoStatus.Status = ioStatus->Status;
		Irp->IoStatus.Information = ioStatus->Information;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);

		return STATUS_SUCCESS;
	}
	// A driver entry point
	_Use_decl_annotations_ NTSTATUS DriverEntry(
		PDRIVER_OBJECT driver_object,	
		PUNICODE_STRING registry_path
	) 
	{

		UNREFERENCED_PARAMETER(registry_path);
		PAGED_CODE();
		HYPERPLATFORM_LOG_DEBUG_SAFE("start nested test \r\n");

		static const wchar_t kLogFilePath[] = L"\\SystemRoot\\DdiMon33.log";

		static const auto kLogLevel =
			(IsReleaseBuild()) ? kLogPutLevelInfo | kLogOptDisableFunctionName
			: kLogPutLevelDebug | kLogOptDisableFunctionName;

		auto status = STATUS_UNSUCCESSFUL;

		driver_object->DriverUnload = DriverpDriverUnload;


		//HYPERPLATFORM_COMMON_DBG_BREAK();

		// Request NX Non-Paged Pool when available
		ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

		// Initialize log functions
		bool need_reinitialization = false;
		status = LogInitialization(kLogLevel, kLogFilePath);
		if (status == STATUS_REINITIALIZATION_NEEDED) {
			need_reinitialization = true;
		}
		else if (!NT_SUCCESS(status)) {
			return status;
		}

		// Test if the system is supported
		if (!DriverpIsSuppoetedOS()) {
			LogTermination();
			return STATUS_CANCELLED;
		}

		// Initialize perf functions
		status = PerfInitialization();
		if (!NT_SUCCESS(status)) {
			LogTermination();
			return status;
		}
		// Initialize utility functions 

		status = UtilInitialization(driver_object);
		if (!NT_SUCCESS(status)) {
			//PerfTermination();
			// LogTermination();
			HYPERPLATFORM_LOG_DEBUG_SAFE("UtilInitialization FAILED\r\n");
			return status;
		}

		// Virtualize all processors

		HYPERPLATFORM_LOG_INFO("Start VM IRQL: %x \r\n", KeGetCurrentIrql());
		status = VmInitialization();

		if (!NT_SUCCESS(status))
		{
			UtilTermination();
			PerfTermination();
			LogTermination();
			return status;
		}


		HYPERPLATFORM_LOG_INFO("break IRQL: %x \r\n", KeGetCurrentIrql());

		HYPERPLATFORM_LOG_INFO("The VMM has been installed. IRQL: %x \r\n", KeGetCurrentIrql());
		return status;
	}

	// Unload handler
	_Use_decl_annotations_ static void DriverpDriverUnload(
		PDRIVER_OBJECT driver_object) {
		UNREFERENCED_PARAMETER(driver_object);
		PAGED_CODE();

		HYPERPLATFORM_COMMON_DBG_BREAK();

		VmTermination();
		UtilTermination();
		PerfTermination();
		LogTermination();
	}

	// Test if the system is one of supported OS versions
	_Use_decl_annotations_ bool DriverpIsSuppoetedOS() {
		PAGED_CODE();

		RTL_OSVERSIONINFOW os_version = {};
		auto status = RtlGetVersion(&os_version);
		if (!NT_SUCCESS(status)) {
			return false;
		}
		if (os_version.dwMajorVersion != 6 && os_version.dwMajorVersion != 10) {
			return false;
		}
		// 4-gigabyte tuning (4GT) should not be enabled
		if (!IsX64() &&
			reinterpret_cast<ULONG_PTR>(MmSystemRangeStart) != 0x80000000) {
			return false;
		}
		return true;
	}

}  // extern "C"

