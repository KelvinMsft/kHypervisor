#pragma once

#include <fltKernel.h>
#include "../HyperPlatform/HyperPlatform/asm.h"


#define CHECK_BOUNDARY_FOR_IA32					 0xFFFFFFFF00000000
#define CHECK_PAGE_ALGINMENT					 0xFFF
#define VMX_HIGHEST_VMCS_ENCODING				 0x2C
#define VMCS_DATA_OFFSET                         0x0010
#define VMX_VMCS_AREA_SIZE						 0x1000 

#define VMCS_FIELD_WIDTH_16BIT					 0x0
#define VMCS_FIELD_WIDTH_64BIT					 0x1
#define VMCS_FIELD_WIDTH_32BIT					 0x2
#define VMCS_FIELD_WIDTH_NATURAL_WIDTH			 0x3


#define MY_SUPPORT_VMX							   2
extern "C" 
{
	VOID    BuildGernericVMCSMap();
	BOOLEAN RegularCheck();
	BOOLEAN is_vmcs_field_supported(VmcsField encoding);
	
	/*
		VMCS Phase 1
	*/
	VOID  VmRead64(VmcsField Field, ULONG_PTR base, PULONG64 destination);
	VOID  VmRead32(VmcsField Field, ULONG_PTR base, PULONG32 destination);
	VOID  VmRead16(VmcsField Field, ULONG_PTR base, PUSHORT  destination);

	VOID  VmWrite64(VmcsField Field, ULONG_PTR base, ULONG_PTR value);
	VOID  VmWrite32(VmcsField Field, ULONG_PTR base, ULONG_PTR value);
	VOID  VmWrite16(VmcsField Field, ULONG_PTR base, ULONG_PTR value);

	VmcsField DecodeVmwriteOrVmRead(
		GpRegisters* guest_context, 
		ULONG_PTR* Offset, 
		ULONG_PTR* Value, 
		BOOLEAN* RorM, 
		ULONG_PTR* RegIndex = NULL, 
		ULONG_PTR* MemAddr = NULL
	);

	VOID FillGuestFieldFromVMCS12(ULONG_PTR guest_vmcs_va, USHORT guest_interrupt_status, USHORT pml_index);
	VOID FillHostStateFieldByPhysicalCpu(ULONG_PTR host_rip, ULONG_PTR host_rsp);

	VOID PrintControlField();
	VOID PrintHostStateField();
	VOID PrintGuestStateField();
	VOID PrintVMCS();


}