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

// VMX Instruction Return 
VOID VMSucceed(FlagRegister *reg);
VOID VMfailInvalid(FlagRegister *reg);
VOID VMfailValid(FlagRegister *reg, VmxInstructionError err);
VOID VMfail(FlagRegister *reg, VmxInstructionError err);

//VMX Regular Check
BOOLEAN IsGuestinPagingMode();
BOOLEAN IsGuestSetNumericErrorBit();
BOOLEAN IsGuestInProtectedMode();
BOOLEAN IsGuestSupportVMX();
BOOLEAN IsGuestInVirtual8086();
BOOLEAN IsGuestinCompatibliltyMode();
BOOLEAN IsGuestInIA32eMode();
BOOLEAN IsLockbitClear();
BOOLEAN IsGuestEnableVMXOnInstruction();
BOOLEAN CheckPhysicalAddress(ULONG64 vmxon_region_pa);

//Normal Check
BOOLEAN CheckPageAlgined(ULONG64 address);

//Get Guest Information
USHORT	GetGuestCPL(); 
ULONG	GetVMCSRevisionIdentifier();

//Interrupt Injection
VOID	FillEventInjection(ULONG32 interruption_type, ULONG32 exception_vector, BOOLEAN isDeliver_error_code, BOOLEAN isValid);
VOID	ThrowInvalidCodeException();
VOID	ThrowGerneralFaultInterrupt();

//Decode for VMCLEAR, VMPTRLD, VMPTRST, VMXON instruction
ULONG64 DecodeVmclearOrVmptrldOrVmptrstOrVmxon(GuestContext* guest_context);

VOID	init_vmx_extensions_bitmask(void);
BOOLEAN is_eptptr_valid(ULONG64 eptptr);

SegmentDescriptor* GetSegmentDesctiptor(SegmentSelector ss, ULONG64 gdtBase);
}