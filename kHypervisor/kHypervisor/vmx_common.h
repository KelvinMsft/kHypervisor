/*++

Copyright (c) 2016 KelvinChan. All rights reserved.
Use of this source code is governed by a MIT-style license that can be
found in the LICENSE file.

Module Name:

	vmx_common.cpp

Abstract:

	VMX instruction emulation utilities

Author:
	
	Kelvin Chan

Environment:

	Kernel VMM Mode

--*/
#pragma once
#include <fltKernel.h>
#include <intrin.h>
#include "vmx_common.h"
#include "vmx.h"
#include "..\HyperPlatform\log.h"
#include "..\HyperPlatform\vmm.h"
#include "..\HyperPlatform\util.h"
#include "vmcs.h"
extern "C"
{

typedef enum
{
	Active = 0,
	HLT,
	ShutDown,
	WaitForSipi
}ActivityState;

// VMX Instruction Return 
VOID 
VMSucceed(
	_In_ FlagRegister *reg
);

VOID 
VMfailInvalid(
	_In_ FlagRegister *reg
);

VOID 
VMfailValid(
	_In_ FlagRegister *reg, 
	_In_ VmxInstructionError err
);

VOID 
VMfail(
	_In_ FlagRegister *reg, 
	_In_ VmxInstructionError err
);

//VMX Regular Check
BOOLEAN 
IsGuestinPagingMode();

BOOLEAN 
IsGuestSetNumericErrorBit();

BOOLEAN 
IsGuestInProtectedMode();

BOOLEAN 
IsGuestSupportVMX();

BOOLEAN
IsGuestInVirtual8086();

BOOLEAN 
IsGuestinCompatibliltyMode();

BOOLEAN 
IsGuestInIA32eMode();

BOOLEAN 
IsLockbitClear();

BOOLEAN 
IsGuestEnableVMXOnInstruction();

BOOLEAN
CheckPhysicalAddress(ULONG64 vmxon_region_pa);

//Normal Check
BOOLEAN 
CheckPageAlgined(_In_ ULONG64 address);

//Get Guest Information
USHORT	
GetGuestCPL(); 

ULONG	
GetVMCSRevisionIdentifier();

//Interrupt Injection
VOID	
FillEventInjection(
	_In_ ULONG32 interruption_type, 
	_In_ ULONG32 exception_vector, 
	_In_ BOOLEAN isDeliver_error_code, 
	_In_ BOOLEAN isValid
);

VOID	
ThrowInvalidCodeException();

VOID	
ThrowGerneralFaultInterrupt();

//Decode for VMCLEAR, VMPTRLD, VMPTRST, VMXON instruction
ULONG64
DecodeVmclearOrVmptrldOrVmptrstOrVmxon(
	_In_ GuestContext* guest_context
);


SegmentDescriptor* 
GetSegmentDesctiptor(
	_In_ SegmentSelector ss, 
	_In_ ULONG64 gdtBase
);
  
struct ProcessorData;

VOID	
SaveGuestKernelGsBase(
	_In_ ProcessorData* vcpu
);

VOID	
LoadGuestKernelGsBase(
	_In_ ProcessorData* vcpu
);

VOID	
SaveHostKernelGsBase(
	_In_ ProcessorData* vcpu
);

VOID	
LoadHostKernelGsBase(
	_In_ ProcessorData* vcpu
);


VOID
VmmSaveCurrentEpt02Pointer(
	_In_	GuestContext* guest_context, 
	_In_	EptData* Ept02
);

EptData*		
VmmGetCurrentEpt02Pointer(
	_In_	GuestContext* guest_context
);

EptData*
VmmGetCurrentEpt01Pointer(
	_In_	GuestContext* guest_context
);

VOID			
VmmSaveCurrentEpt12Pointer(
	_In_	GuestContext* guest_context, 
	_In_	EptData* Ept12
);

EptData*		
VmmGetCurrentEpt12Pointer(
	_In_ GuestContext* guest_context
);

ULONG			
VmpGetSegmentAccessRight(
	_In_ USHORT segment_selector
);

ULONG_PTR*		
VmmpSelectRegister(
	_In_ ULONG index, 
	_In_ GuestContext *guest_context
);

GpRegisters*	
VmmpGetGpReg(
	_In_ GuestContext* guest_context
);

FlagRegister*	
VmmpGetFlagReg(
	_In_ GuestContext* guest_context
);

KIRQL			
VmmpGetGuestIrql(
	_In_ GuestContext* guest_context
);

ULONG_PTR		
VmmpGetGuestCr8(
	_In_ GuestContext* guest_context
);

VCPUVMX*	 	
VmmpGetVcpuVmx(
	_In_ GuestContext* guest_context
);

VOID			
VmmpSetvCpuVmx(
	_In_ GuestContext* guest_context,
	_In_ VCPUVMX* VCPUVMX
);

VOID			
VmmpEnterVmxMode(
	_In_ GuestContext* guest_context
);
VOID			
VmmpLeaveVmxMode(
	_In_ GuestContext* guest_context
);

ULONG			
VmmpGetvCpuMode(
	_In_ GuestContext* guest_context
);

ProcessorData*	
VmmpGetProcessorData(
	_In_ GuestContext* guest_context
);


}