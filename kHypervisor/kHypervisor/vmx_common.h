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

VOID	InitVmxExtensionMask();
BOOLEAN IsEptptrValid(ULONG64 eptptr);

SegmentDescriptor* GetSegmentDesctiptor(SegmentSelector ss, ULONG64 gdtBase);
  
struct ProcessorData;
void	SaveGuestKernelGsBase(ProcessorData* vcpu); 
void	LoadGuestKernelGsBase(ProcessorData* vcpu);
void	SaveHostKernelGsBase(ProcessorData* vcpu);
void	LoadHostKernelGsBase(ProcessorData* vcpu);


}