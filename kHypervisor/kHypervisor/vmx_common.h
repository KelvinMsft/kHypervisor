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
VOID VMSucceed(FlagRegister *reg);
VOID VMfailInvalid(FlagRegister *reg);
VOID VMfailValid(FlagRegister *reg, VmxInstructionError err);
VOID VMfail(FlagRegister *reg, VmxInstructionError err);
BOOLEAN IsGuestinPagingMode();
BOOLEAN IsGuestSetNumericErrorBit();
BOOLEAN IsGuestInProtectedMode();
BOOLEAN IsGuestSupportVMX();
BOOLEAN IsGuestInVirtual8086();
SegmentDescriptor* GetSegmentDesctiptor(SegmentSelector ss, ULONG64 gdtBase);
BOOLEAN IsGuestinCompatibliltyMode();
USHORT GetGuestCPL();
BOOLEAN IsGuestInIA32eMode();
BOOLEAN IsLockbitClear();
BOOLEAN IsGuestEnableVMXOnInstruction();
BOOLEAN CheckPhysicalAddress(ULONG64 vmxon_region_pa);
ULONG GetVMCSRevisionIdentifier();
BOOLEAN CheckPageAlgined(ULONG64 address);
VOID FillEventInjection(ULONG32 interruption_type, ULONG32 exception_vector, BOOLEAN isDeliver_error_code, BOOLEAN isValid);
VOID ThrowInvalidCodeException();
VOID ThrowGerneralFaultInterrupt();

ULONG64 DecodeVmclearOrVmptrldOrVmptrstOrVmxon(GuestContext* guest_context);
VOID init_vmx_extensions_bitmask(void);
BOOLEAN is_eptptr_valid(ULONG64 eptptr);

}