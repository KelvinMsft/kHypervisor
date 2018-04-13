/*++

Copyright (c) 2016 KelvinChan. All rights reserved.
Use of this source code is governed by a MIT-style license that can be
found in the LICENSE file.

Module Name:

	vmcs.h

Abstract:

	VMCS utilies

Author:
	
	Kelvin Chan

Environment:

	Kernel VMM Mode

--*/
#include <fltKernel.h>
#include "..\HyperPlatform\asm.h"

extern "C"
{

////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//
#define PrintVMCS(){ VmcsPrintAllField(__func__);}
#define PrintVMCS12(vmcs12){ VmcsPrintAllFieldForVmcs12(__func__, vmcs12);}

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//
#define CHECK_BOUNDARY_FOR_IA32					 0xFFFFFFFF00000000
#define CHECK_PAGE_ALGINMENT					 0xFFF
#define VMX_HIGHEST_VMCS_ENCODING				 0x2C
#define VMCS_DATA_OFFSET                         0x0010
#define VMX_VMCS_AREA_SIZE						 0x1000 

#define VMCS_FIELD_WIDTH_16BIT					 0x0
#define VMCS_FIELD_WIDTH_64BIT					 0x1
#define VMCS_FIELD_WIDTH_32BIT					 0x2
#define VMCS_FIELD_WIDTH_NATURAL_WIDTH			 0x3


#define MY_SUPPORT_VMX							 2
	
////////////////////////////////////////////////////////////////////////////////
//
// types
//


////////////////////////////////////////////////////////////////////////////////
//
// prototype
//
VOID   
BuildGernericVMCSMap();

BOOLEAN 
RegularCheck();

BOOLEAN 
is_vmcs_field_supported(
	_In_ VmcsField encoding
);
 
VOID  
VmcsVmRead64(
	_In_ VmcsField Field,
	_In_ ULONG_PTR base,
	_In_ PULONG64 destination
);

VOID  
VmcsVmRead32(
	_In_ VmcsField Field,
	_In_ ULONG_PTR base,
	_In_ PULONG32 destination
);

VOID 
VmcsVmRead16(
	_In_ VmcsField Field,
	_In_ ULONG_PTR base,
	_In_ PUSHORT  destination
);

VOID  
VmcsVmWrite64(
	_In_ VmcsField Field,
	_In_ ULONG_PTR base,
	_In_ ULONG_PTR value
);

VOID  
VmcsVmWrite32(
	_In_ VmcsField Field,
	_In_ ULONG_PTR base,
	_In_ ULONG_PTR value
);

VOID  
VmcsVmWrite16(
	_In_ VmcsField Field,
	_In_ ULONG_PTR base,
	_In_ ULONG_PTR value
);

VmcsField 
VmcsDecodeVmwriteOrVmRead(
	_In_ GpRegisters* guest_context,
	_In_ ULONG_PTR* Offset,
	_In_ ULONG_PTR* Value,
	_In_ BOOLEAN* RorM,
	_In_ ULONG_PTR* RegIndex = NULL,
	_In_ ULONG_PTR* MemAddr = NULL
);


VOID 
VmcsPrepareHostAndControlField(
	_In_ ULONG_PTR vmcs12_va, 
	_In_ ULONG_PTR vmcs02_va,
	_In_ BOOLEAN isLaunch
);

VOID 
VmcsPrepareGuestStateField(
	_In_ ULONG_PTR guest_vmcs_va
);

VOID 
VmcsPrintControlField();

VOID 
VmcsPrintHostStateField();

VOID 
VmcsPrintGuestStateField();

VOID
VmcsPrintReadOnlyField();

VOID
VmcsPrintAllField(
	_In_ const char* func
); 

VOID 
VmcsPrintReadOnlyFieldForVmcs12(
	_In_ ULONG64 vmcs12_va
);

VOID 
VmcsPrintAllFieldForVmcs12(
	_In_ const char* func,
	_In_ ULONG64 vmcs12
);

}
#pragma once
