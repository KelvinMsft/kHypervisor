// Copyright (c) 2016-2017, KelvinChan. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.#include <fltKernel.h>


#include <intrin.h>
#include "..\HyperPlatform\util.h"
#include "vmcs.h"
#include "vmx.h"
#include "..\HyperPlatform\vmm.h"
#include "..\HyperPlatform\log.h"
#include "..\HyperPlatform\common.h"
#include "vmx_common.h"
extern "C"
{
////////////////////////////////////////////////////////////////////////////////////////////////////
//// Prototype
////
extern ULONG_PTR*	 VmmpSelectRegister(_In_ ULONG index, _In_ GuestContext *guest_context);
extern GpRegisters*  GetGpReg(GuestContext* guest_context);
extern FlagRegister* GetFlagReg(GuestContext* guest_context);
extern KIRQL		 GetGuestIrql(GuestContext* guest_context);

NestedVmm* GetCurrentCPU(bool IsNested);

////////////////////////////////////////////////////////////////////////////////////////////////////
//// Marco
////

////////////////////////////////////////////////////////////////////////////////////////////////////
//// 
//// Variable
////
NestedVmm*	         g_vcpus[64] = {};
volatile LONG		 g_vpid = 1;
volatile LONG	     g_VM_Core_Count = 0;


////////////////////////////////////////////////////////////////////////////////////////////////////
//// 
//// Type
////
enum VMX_state
{
	VMCS_STATE_CLEAR = 0,
	VMCS_STATE_LAUNCHED
};

////////////////////////////////////////////////////////////////////////////////////////////////////
//// 
//// Implementation
////


VOID	LEAVE_GUEST_MODE(NestedVmm* vm) { vm->inRoot = TRUE; }
VOID	ENTER_GUEST_MODE(NestedVmm* vm) { vm->inRoot = FALSE; }
BOOLEAN IsRootMode(NestedVmm* vm) { return vm->inRoot; }

//---------------------------------------------------------------------------------------------------------------------//
NestedVmm* GetCurrentCPU(bool IsNested = true)
{
	ULONG64 vmcs12_va = 0;
	ULONG64 vmcs_pa;
	NestedVmm* ret = NULL;
	int i = 0;
	__vmx_vmptrst(&vmcs_pa);
	if (vmcs_pa)
	{
		for (i = 0; i < (int)KeQueryMaximumProcessorCount(); i++)
		{
			if (!g_vcpus[i])
			{
				break;
			}
			if (IsNested)
			{
				if (g_vcpus[i]->vmcs02_pa == vmcs_pa ||		//L2
					g_vcpus[i]->vmcs01_pa == vmcs_pa)		//L1
				{
					ret = g_vcpus[i];
					break;
				}
			}
			else
			{
				if (g_vcpus[i]->vmcs02_pa == vmcs_pa)		//L2
				{
					ret = g_vcpus[i];
					break;
				}
			}
		}
	}
	return ret;
}
//---------------------------------------------------------------------------------------------------------------------//
void DumpVcpu()
{
	ULONG64 vmcs12_va = 0;
	ULONG64 vmcs_pa;
	NestedVmm* ret = NULL;
	int i = 0;
	__vmx_vmptrst(&vmcs_pa);
	if (vmcs_pa)
	{
		for (i = 0; i < (int)KeQueryMaximumProcessorCount(); i++)
		{
			if (!g_vcpus[i])
			{
				break;
			}
			HYPERPLATFORM_LOG_DEBUG_SAFE("Current Vmcs: %I64X i:%d vmcs02: %I64X", vmcs_pa, i, g_vcpus[i]->vmcs02_pa);
		}
	}
}
//----------------------------------------------------------------------------------------------------------------------//
/*
Descritpion:

1. Call before emulate a VMExit, Read All VMExit related-Information
From VMCS0-2, And backup it into VMCS1-2, the purpose is for
emulate VMExit,

2. Actually the Emulation of VMExit is that we RESUME the L0 to L1,
so when L1 make any VMREAD/WRITE,  will trap by us, we return a
VMCS1-2 to its.

Parameters:

1. VMExit Reason
2. Physical Address for VMCS1-2

*/
VOID SaveExceptionInformationFromVmcs02(VmExitInformation exit_reason, ULONG64 vmcs12_va)
{

	const VmExitInterruptionInformationField exception = {
		static_cast<ULONG32>(UtilVmRead(VmcsField::kVmExitIntrInfo))
	};

	ULONG_PTR vmexit_qualification = UtilVmRead(VmcsField::kExitQualification);

	VmWrite32(VmcsField::kVmExitIntrInfo, vmcs12_va, exception.all);
	VmWrite32(VmcsField::kVmExitReason, vmcs12_va, exit_reason.all);
	VmWrite32(VmcsField::kExitQualification, vmcs12_va, vmexit_qualification);
	VmWrite32(VmcsField::kVmExitInstructionLen, vmcs12_va, UtilVmRead(VmcsField::kVmExitInstructionLen));
	VmWrite32(VmcsField::kVmInstructionError, vmcs12_va, UtilVmRead(VmcsField::kVmInstructionError));
	VmWrite32(VmcsField::kVmExitIntrErrorCode, vmcs12_va, UtilVmRead(VmcsField::kVmExitIntrErrorCode));
	VmWrite32(VmcsField::kIdtVectoringInfoField, vmcs12_va, UtilVmRead(VmcsField::kIdtVectoringInfoField));
	VmWrite32(VmcsField::kIdtVectoringErrorCode, vmcs12_va, UtilVmRead(VmcsField::kIdtVectoringErrorCode));
	VmWrite32(VmcsField::kVmxInstructionInfo, vmcs12_va, UtilVmRead(VmcsField::kVmxInstructionInfo));

}
//---------------------------------------------------------------------------------------------------------------------//

/*
Descritpion:
1.  Call before emulate a VMExit, Read All Guest Field From VMCS0-2,
And backup into VMCS1-2, the purpose is for emulated VMExit, but
actually we RESUME the VM to L1, when L1 make any VMREAD/WRITE,
we return a VMCS1-2 to its.

Parameters:
1.	Physical Address for VMCS1-2

*/
VOID SaveGuestFieldFromVmcs02(ULONG64 vmcs12_va)
{
	//all nested vm-exit should record 

	VmWrite64(VmcsField::kGuestRip, vmcs12_va, UtilVmRead(VmcsField::kGuestRip));
	VmWrite64(VmcsField::kGuestRsp, vmcs12_va, UtilVmRead(VmcsField::kGuestRsp));
	VmWrite64(VmcsField::kGuestCr3, vmcs12_va, UtilVmRead(VmcsField::kGuestCr3));
	VmWrite64(VmcsField::kGuestCr0, vmcs12_va, UtilVmRead(VmcsField::kGuestCr0));
	VmWrite64(VmcsField::kGuestCr4, vmcs12_va, UtilVmRead(VmcsField::kGuestCr4));
	VmWrite64(VmcsField::kGuestDr7, vmcs12_va, UtilVmRead(VmcsField::kGuestDr7));
	VmWrite64(VmcsField::kGuestRflags, vmcs12_va, UtilVmRead(VmcsField::kGuestRflags));


	VmWrite16(VmcsField::kGuestEsSelector, vmcs12_va, UtilVmRead(VmcsField::kGuestEsSelector));
	VmWrite16(VmcsField::kGuestCsSelector, vmcs12_va, UtilVmRead(VmcsField::kGuestCsSelector));
	VmWrite16(VmcsField::kGuestSsSelector, vmcs12_va, UtilVmRead(VmcsField::kGuestSsSelector));
	VmWrite16(VmcsField::kGuestDsSelector, vmcs12_va, UtilVmRead(VmcsField::kGuestDsSelector));
	VmWrite16(VmcsField::kGuestFsSelector, vmcs12_va, UtilVmRead(VmcsField::kGuestFsSelector));
	VmWrite16(VmcsField::kGuestGsSelector, vmcs12_va, UtilVmRead(VmcsField::kGuestGsSelector));
	VmWrite16(VmcsField::kGuestLdtrSelector, vmcs12_va, UtilVmRead(VmcsField::kGuestLdtrSelector));
	VmWrite16(VmcsField::kGuestTrSelector, vmcs12_va, UtilVmRead(VmcsField::kGuestTrSelector));

	VmWrite32(VmcsField::kGuestEsLimit, vmcs12_va, UtilVmRead(VmcsField::kGuestEsLimit));
	VmWrite32(VmcsField::kGuestCsLimit, vmcs12_va, UtilVmRead(VmcsField::kGuestCsLimit));
	VmWrite32(VmcsField::kGuestSsLimit, vmcs12_va, UtilVmRead(VmcsField::kGuestSsLimit));
	VmWrite32(VmcsField::kGuestDsLimit, vmcs12_va, UtilVmRead(VmcsField::kGuestDsLimit));
	VmWrite32(VmcsField::kGuestFsLimit, vmcs12_va, UtilVmRead(VmcsField::kGuestFsLimit));
	VmWrite32(VmcsField::kGuestGsLimit, vmcs12_va, UtilVmRead(VmcsField::kGuestGsLimit));
	VmWrite32(VmcsField::kGuestLdtrLimit, vmcs12_va, UtilVmRead(VmcsField::kGuestLdtrLimit));
	VmWrite32(VmcsField::kGuestTrLimit, vmcs12_va, UtilVmRead(VmcsField::kGuestTrLimit));
	VmWrite32(VmcsField::kGuestGdtrLimit, vmcs12_va, UtilVmRead(VmcsField::kGuestGdtrLimit));
	VmWrite32(VmcsField::kGuestIdtrLimit, vmcs12_va, UtilVmRead(VmcsField::kGuestIdtrLimit));

	VmWrite32(VmcsField::kGuestEsArBytes, vmcs12_va, UtilVmRead(VmcsField::kGuestEsArBytes));
	VmWrite32(VmcsField::kGuestCsArBytes, vmcs12_va, UtilVmRead(VmcsField::kGuestCsArBytes));
	VmWrite32(VmcsField::kGuestSsArBytes, vmcs12_va, UtilVmRead(VmcsField::kGuestSsArBytes));
	VmWrite32(VmcsField::kGuestDsArBytes, vmcs12_va, UtilVmRead(VmcsField::kGuestDsArBytes));
	VmWrite32(VmcsField::kGuestFsArBytes, vmcs12_va, UtilVmRead(VmcsField::kGuestFsArBytes));
	VmWrite32(VmcsField::kGuestGsArBytes, vmcs12_va, UtilVmRead(VmcsField::kGuestGsArBytes));
	VmWrite32(VmcsField::kGuestLdtrArBytes, vmcs12_va, UtilVmRead(VmcsField::kGuestLdtrArBytes));

	VmWrite32(VmcsField::kGuestTrArBytes, vmcs12_va, UtilVmRead(VmcsField::kGuestTrArBytes));

	VmWrite32(VmcsField::kGuestInterruptibilityInfo, vmcs12_va, UtilVmRead(VmcsField::kGuestInterruptibilityInfo));
	VmWrite32(VmcsField::kGuestActivityState, vmcs12_va, UtilVmRead(VmcsField::kGuestActivityState));
	VmWrite32(VmcsField::kGuestSysenterCs, vmcs12_va, UtilVmRead(VmcsField::kGuestSysenterCs));

	VmWrite64(VmcsField::kGuestSysenterEsp, vmcs12_va, UtilVmRead(VmcsField::kGuestSysenterEsp));
	VmWrite64(VmcsField::kGuestSysenterEip, vmcs12_va, UtilVmRead(VmcsField::kGuestSysenterEip));
	VmWrite64(VmcsField::kGuestPendingDbgExceptions, vmcs12_va, UtilVmRead(VmcsField::kGuestPendingDbgExceptions));
	VmWrite64(VmcsField::kGuestEsBase, vmcs12_va, UtilVmRead(VmcsField::kGuestEsBase));
	VmWrite64(VmcsField::kGuestCsBase, vmcs12_va, UtilVmRead(VmcsField::kGuestCsBase));
	VmWrite64(VmcsField::kGuestSsBase, vmcs12_va, UtilVmRead(VmcsField::kGuestSsBase));
	VmWrite64(VmcsField::kGuestDsBase, vmcs12_va, UtilVmRead(VmcsField::kGuestDsBase));
	VmWrite64(VmcsField::kGuestFsBase, vmcs12_va, UtilVmRead(VmcsField::kGuestFsBase));
	VmWrite64(VmcsField::kGuestGsBase, vmcs12_va, UtilVmRead(VmcsField::kGuestGsBase));
	VmWrite64(VmcsField::kGuestLdtrBase, vmcs12_va, UtilVmRead(VmcsField::kGuestLdtrBase));
	VmWrite64(VmcsField::kGuestTrBase, vmcs12_va, UtilVmRead(VmcsField::kGuestTrBase));
	VmWrite64(VmcsField::kGuestGdtrBase, vmcs12_va, UtilVmRead(VmcsField::kGuestGdtrBase));
	VmWrite64(VmcsField::kGuestIdtrBase, vmcs12_va, UtilVmRead(VmcsField::kGuestIdtrBase));

	/*
	VmWrite64(VmcsField::kGuestPdptr0, vmcs12_va, UtilVmRead(VmcsField::kGuestPdptr0));
	VmWrite64(VmcsField::kGuestPdptr1, vmcs12_va, UtilVmRead(VmcsField::kGuestPdptr1));
	VmWrite64(VmcsField::kGuestPdptr2, vmcs12_va, UtilVmRead(VmcsField::kGuestPdptr2));
	VmWrite64(VmcsField::kGuestPdptr3, vmcs12_va, UtilVmRead(VmcsField::kGuestPdptr3));
	*/
}
//---------------------------------------------------------------------------------------------------------------------//
/*
Descritpion:
1.  Emulate a VMExit, After Saving All Guest Field and Exception Information
From VMCS0-2, And backup into VMCS1-2, We need to modify VMCS0-1 and get
ready to back VMCS0-1.

The VMCS0-1's Guest RIP, RSP,CR0,CR3,CR4 should be modified to VMCS1-2's Host RIP
(Since L1 will fill the VMExit Handler when initialization stage)

Parameters:
1.	Physical Address for VMCS1-2

*/
VOID EmulateVmExit(ULONG64 vmcs01, ULONG64 vmcs12_va)
{

	VmxStatus status;

	ULONG64   VMCS_VMEXIT_HANDLER = 0;
	ULONG64   VMCS_VMEXIT_STACK = 0;
	ULONG64   VMCS_VMEXIT_RFLAGs = 0;
	ULONG64   VMCS_VMEXIT_CR4 = 0;
	ULONG64   VMCS_VMEXIT_CR3 = 0;
	ULONG64   VMCS_VMEXIT_CR0 = 0;


	ULONG64   VMCS_VMEXIT_CS = 0;
	ULONG64   VMCS_VMEXIT_SS = 0;
	ULONG64   VMCS_VMEXIT_DS = 0;
	ULONG64   VMCS_VMEXIT_ES = 0;
	ULONG64   VMCS_VMEXIT_FS = 0;
	ULONG64   VMCS_VMEXIT_GS = 0;
	ULONG64   VMCS_VMEXIT_TR = 0;

	ULONG32   VMCS_VMEXIT_SYSENTER_CS = 0;
	ULONG64   VMCS_VMEXIT_SYSENTER_RIP = 0;
	ULONG64   VMCS_VMEXIT_SYSENTER_RSP = 0;


	ULONG_PTR  VMCS_VMEXIT_HOST_FS = 0;
	ULONG_PTR  VMCS_VMEXIT_HOST_GS = 0;
	ULONG_PTR  VMCS_VMEXIT_HOST_TR = 0;

	//VMCS01 guest rip == VMCS12 host rip (should be)
	const VmExitInformation exit_reason = { static_cast<ULONG32>(UtilVmRead(VmcsField::kVmExitReason)) };

	const VmExitInterruptionInformationField exception = { static_cast<ULONG32>(UtilVmRead(VmcsField::kVmExitIntrInfo)) };

	PrintVMCS();
	/*
	1. Print about trapped reason
	*/
	HYPERPLATFORM_LOG_DEBUG_SAFE("[EmulateVmExit]VMCS id %x", UtilVmRead(VmcsField::kVirtualProcessorId));
	HYPERPLATFORM_LOG_DEBUG_SAFE("[EmulateVmExit]Trapped by %I64X ", UtilVmRead(VmcsField::kGuestRip));
	HYPERPLATFORM_LOG_DEBUG_SAFE("[EmulateVmExit]Trapped Reason: %I64X ", exit_reason.fields.reason);
	HYPERPLATFORM_LOG_DEBUG_SAFE("[EmulateVmExit]Trapped Intrreupt: %I64X ", exception.fields.interruption_type);
	HYPERPLATFORM_LOG_DEBUG_SAFE("[EmulateVmExit]Trapped Intrreupt vector: %I64X ", exception.fields.vector);
	HYPERPLATFORM_LOG_DEBUG_SAFE("[EmulateVmExit]Trapped kVmExitInstructionLen: %I64X ", UtilVmRead(VmcsField::kVmExitInstructionLen));

	if (VmxStatus::kOk != (status = static_cast<VmxStatus>(__vmx_vmptrld(&vmcs01))))
	{
		VmxInstructionError error = static_cast<VmxInstructionError>(UtilVmRead(VmcsField::kVmInstructionError));
		HYPERPLATFORM_LOG_DEBUG_SAFE("Error vmptrld error code :%x , %x", status, error);
	}

	//Read from vmcs12_va get it host vmexit handler
	VmRead64(VmcsField::kHostRip, vmcs12_va, &VMCS_VMEXIT_HANDLER);
	VmRead64(VmcsField::kHostRsp, vmcs12_va, &VMCS_VMEXIT_STACK);
	VmRead64(VmcsField::kHostCr0, vmcs12_va, &VMCS_VMEXIT_CR0);
	VmRead64(VmcsField::kHostCr3, vmcs12_va, &VMCS_VMEXIT_CR3);
	VmRead64(VmcsField::kHostCr4, vmcs12_va, &VMCS_VMEXIT_CR4);


	VmRead64(VmcsField::kHostCsSelector, vmcs12_va, &VMCS_VMEXIT_CS);
	VmRead64(VmcsField::kHostSsSelector, vmcs12_va, &VMCS_VMEXIT_SS);
	VmRead64(VmcsField::kHostDsSelector, vmcs12_va, &VMCS_VMEXIT_DS);
	VmRead64(VmcsField::kHostEsSelector, vmcs12_va, &VMCS_VMEXIT_ES);
	VmRead64(VmcsField::kHostFsSelector, vmcs12_va, &VMCS_VMEXIT_FS);
	VmRead64(VmcsField::kHostGsSelector, vmcs12_va, &VMCS_VMEXIT_GS);
	VmRead64(VmcsField::kHostTrSelector, vmcs12_va, &VMCS_VMEXIT_TR);


	VmRead32(VmcsField::kHostIa32SysenterCs, vmcs12_va, &VMCS_VMEXIT_SYSENTER_CS);
	VmRead64(VmcsField::kHostIa32SysenterEip, vmcs12_va, &VMCS_VMEXIT_SYSENTER_RSP);
	VmRead64(VmcsField::kHostIa32SysenterEsp, vmcs12_va, &VMCS_VMEXIT_SYSENTER_RIP);


	VmRead64(VmcsField::kHostFsBase, vmcs12_va, &VMCS_VMEXIT_HOST_FS);
	VmRead64(VmcsField::kHostGsBase, vmcs12_va, &VMCS_VMEXIT_HOST_GS);
	VmRead64(VmcsField::kHostTrBase, vmcs12_va, &VMCS_VMEXIT_HOST_TR);

	VmRead64(VmcsField::kGuestRflags, vmcs12_va, &VMCS_VMEXIT_RFLAGs);

	//Write VMCS01 for L1's VMExit handler
	UtilVmWrite(VmcsField::kGuestRflags, VMCS_VMEXIT_RFLAGs);
	UtilVmWrite(VmcsField::kGuestRip, VMCS_VMEXIT_HANDLER);
	UtilVmWrite(VmcsField::kGuestRsp, VMCS_VMEXIT_STACK);
	UtilVmWrite(VmcsField::kGuestCr0, VMCS_VMEXIT_CR0);
	UtilVmWrite(VmcsField::kGuestCr3, VMCS_VMEXIT_CR3);
	UtilVmWrite(VmcsField::kGuestCr4, VMCS_VMEXIT_CR4);
	UtilVmWrite(VmcsField::kGuestDr7, 0x400);

	UtilVmWrite(VmcsField::kGuestCsSelector, VMCS_VMEXIT_CS);
	UtilVmWrite(VmcsField::kGuestSsSelector, VMCS_VMEXIT_SS);
	UtilVmWrite(VmcsField::kGuestDsSelector, VMCS_VMEXIT_DS);
	UtilVmWrite(VmcsField::kGuestEsSelector, VMCS_VMEXIT_ES);
	UtilVmWrite(VmcsField::kGuestFsSelector, VMCS_VMEXIT_FS);
	UtilVmWrite(VmcsField::kGuestGsSelector, VMCS_VMEXIT_GS);
	UtilVmWrite(VmcsField::kGuestTrSelector, VMCS_VMEXIT_TR);

	UtilVmWrite(VmcsField::kGuestSysenterCs, VMCS_VMEXIT_SYSENTER_CS);
	UtilVmWrite(VmcsField::kGuestSysenterEsp, VMCS_VMEXIT_SYSENTER_RSP);
	UtilVmWrite(VmcsField::kGuestSysenterEip, VMCS_VMEXIT_SYSENTER_RIP);

	UtilVmWrite(VmcsField::kGuestFsBase, VMCS_VMEXIT_HOST_FS);
	UtilVmWrite(VmcsField::kGuestGsBase, VMCS_VMEXIT_HOST_GS);
	UtilVmWrite(VmcsField::kGuestTrBase, VMCS_VMEXIT_HOST_TR);

	VmWrite32(VmcsField::kVmEntryIntrInfoField, vmcs12_va, 0);
	VmWrite32(VmcsField::kVmEntryExceptionErrorCode, vmcs12_va, 0);

	UtilVmWrite(VmcsField::kVmEntryIntrInfoField, 0);
	UtilVmWrite(VmcsField::kVmEntryExceptionErrorCode, 0);

	PrintVMCS();
	PrintVMCS12(vmcs12_va);
}
//---------------------------------------------------------------------------------------------------------------------//
//Nested breakpoint dispatcher
VOID VmExitDispatcher(NestedVmm* vcpu, ULONG64 vmcs12_va)
{
	const VmExitInformation exit_reason = { static_cast<ULONG32>(UtilVmRead(VmcsField::kVmExitReason)) };
	if (!vcpu->vmcs01_pa)
	{
		HYPERPLATFORM_COMMON_DBG_BREAK();
	}

	if (vmcs12_va)
	{
		EmulateVmExit(vcpu->vmcs01_pa, vmcs12_va);
	}
}
//------------------------------------------------------------------------------------------------------------
BOOLEAN VMExitEmulationTest(VmExitInformation exit_reason)
{
	/*
	We need to emulate the exception if and only if the vCPU mode is Guest Mode ,
	and only the exception is somethings we want to redirect to L1 for handle it.
	IsRootMode:
	{
	Root Mode:
	- if the Guest's vCPU is root mode , that means he dun expected the action will be trap.
	so that action should not give its VMExit handler, otherwise.
	Guest Mode:
	- If the Guest's vCPU is in guest mode, that means he expected the action will be trapped
	And handle by its VMExit handler
	}

	We desginated the L1 wants to handle any breakpoint exception but the others.
	So that we only nested it for testing purpose.
	*/


	ULONG64 vmcs12_va = 0;
	NestedVmm* vm = NULL;
	BOOLEAN	ret;

	// Unit-Testing with nested INT 3 exception

	do
	{
		const VmExitInterruptionInformationField exception =
		{
			static_cast<ULONG32>(UtilVmRead(VmcsField::kVmExitIntrInfo))
		};

		vm = GetCurrentCPU(false);
		if (!vm)
		{
			ret = FALSE;
			break;
		}

		// Since VMXON, but VMPTRLD 
		if (!vm->vmcs02_pa || !vm->vmcs12_pa || vm->vmcs12_pa == ~0x0 || vm->vmcs02_pa == ~0x0)
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE("cannot find vmcs \r\n");
			ret = FALSE;
			break;
		}

		vmcs12_va = (ULONG64)UtilVaFromPa(vm->vmcs12_pa);
		// Test L0 exception
		if (static_cast<InterruptionVector>(exception.fields.vector) == InterruptionVector::kPageFaultException)
		{
			ret = FALSE;
			break;
		}
		// Test L1 exception
		if (!IsRootMode(vm) &&
			static_cast<InterruptionVector>(exception.fields.vector) == InterruptionVector::kBreakpointException)
		{
			if (vmcs12_va)
			{
				SaveGuestFieldFromVmcs02(vmcs12_va);
				SaveExceptionInformationFromVmcs02(exit_reason, vmcs12_va);
			}
			// Emulated VMExit 
			LEAVE_GUEST_MODE(vm);

			vmx_save_guest_msrs(vm);

			VmExitDispatcher(vm, vmcs12_va);

			ENTER_GUEST_MODE(vm);

			ret = TRUE;
			break;
		}
		else
		{
			ret = FALSE;
			break;
		}

	} while (0);

	return ret;
}
//---------------------------------------------------------------------------------------------------------------------//
void vmx_save_guest_msrs(NestedVmm* vcpu)
{
	/*
	* We cannot cache SHADOW_GS_BASE while the VCPU runs, as it can
	* be updated at any time via SWAPGS, which we cannot trap.
	*/
	vcpu->guest_gs_kernel_base = UtilReadMsr64(Msr::kIa32KernelGsBase);
	HYPERPLATFORM_LOG_DEBUG_SAFE("DEBUG###Save GS base: %I64X \r\n ", vcpu->guest_gs_kernel_base);
}
//---------------------------------------------------------------------------------------------------------------------//
void vmx_restore_guest_msrs(NestedVmm* vcpu)
{
	UtilWriteMsr64(Msr::kIa32KernelGsBase, vcpu->guest_gs_kernel_base);
	HYPERPLATFORM_LOG_DEBUG_SAFE("DEBUG###Restore GS base: %I64X \r\n ", vcpu->guest_gs_kernel_base);
}


//---------------------------------------------------------------------------------------------------------------------//
VOID VmxonEmulate(GuestContext* guest_context)
{
	do
	{
		ULONG64				InstructionPointer = { UtilVmRead64(VmcsField::kGuestRip) };
		ULONG64				StackPointer = { UtilVmRead64(VmcsField::kGuestRsp) };
		ULONG64				vmxon_region_pa = *(PULONG64)DecodeVmclearOrVmptrldOrVmptrstOrVmxon(guest_context);
		ULONG64				debug_vmxon_region_pa = DecodeVmclearOrVmptrldOrVmptrstOrVmxon(guest_context);
		VmControlStructure*   vmxon_region_struct = (VmControlStructure*)UtilVaFromPa(vmxon_region_pa);
		PROCESSOR_NUMBER      number;

		HYPERPLATFORM_LOG_DEBUG_SAFE("UtilVmRead: %I64X", &UtilVmRead);
		HYPERPLATFORM_LOG_DEBUG_SAFE("UtilVmRead64: %I64X", &UtilVmRead64);
		HYPERPLATFORM_LOG_DEBUG_SAFE("UtilVmWrite: %I64X", &UtilVmWrite);
		HYPERPLATFORM_LOG_DEBUG_SAFE("UtilVmWrite64: %I64X", &UtilVmWrite64);
		HYPERPLATFORM_LOG_DEBUG_SAFE("VmRead: %I64X", &VmRead16);
		HYPERPLATFORM_LOG_DEBUG_SAFE("VmRead32: %I64X", &VmRead32);
		HYPERPLATFORM_LOG_DEBUG_SAFE("VmRead64: %I64X", &VmRead64);
		HYPERPLATFORM_LOG_DEBUG_SAFE("VmWrite: %I64X", &VmWrite16);
		HYPERPLATFORM_LOG_DEBUG_SAFE("VmWrite32: %I64X", &VmWrite32);
		HYPERPLATFORM_LOG_DEBUG_SAFE("VmWrite64: %I64X", &VmWrite64);
		// VMXON_REGION IS NULL 
		if (!vmxon_region_pa)
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMXON: Parameter is NULL !"));
			//#UD
			ThrowInvalidCodeException();
			break;
		}

		// If already VCPU run in VMX operation
		if (g_vcpus[KeGetCurrentProcessorNumberEx(&number)])
		{
			///TODO: 
			///if( it is non root ) 
			///	VM Exit 
			HYPERPLATFORM_LOG_DEBUG_SAFE("VMX: Cpu is already in VMXON Mode, should be VM Exit here \r\n");
			break;
		}

		//CR0.PE = 0;
		if (!IsGuestInProtectedMode())
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMXON: Please running in Protected Mode !"));
			//#UD
			ThrowInvalidCodeException();
			break;
		}
		//If guest is not support VMX 
		//CR4.VMXE = 0;
		if (!IsGuestSupportVMX())
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMXON: Guest is not supported VMX !"));
			//#UD
			ThrowInvalidCodeException();
			break;
		}
		//If guest run in virtual-8086 mode
		//RFLAGS.VM = 1
		if (IsGuestInVirtual8086())
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMXON: Guest is running in virtual-8086 mode !"));
			//#UD
			ThrowInvalidCodeException();
			break;
		}
		//If guest run in IA32-e 
		//kGuestIa32Efer.LMA = 1
		if (IsGuestInIA32eMode())
		{
			//If CS.L == 0 , means compability mode (32bit addressing), CS.L == 1 is 64bit mode , default operand is 32bit
			if (!IsGuestinCompatibliltyMode())
			{
				HYPERPLATFORM_LOG_DEBUG_SAFE(("VMXON: Guest is IA-32e mode but not in 64bit mode !"));
				//#UD
				ThrowInvalidCodeException();
				break;
			}
		}
		//Get Guest CPL
		if (GetGuestCPL() > 0)
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMXON: Need run in Ring-0 !"));
			//#gp
			ThrowGerneralFaultInterrupt();
			break;
		}
		//If MSR Lockbit is not set
		//Ia32_Feature_Control.lock = 0
		if (!IsLockbitClear())
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMXON: IsLockbitClear !"));
			//#gp
			ThrowGerneralFaultInterrupt();
			break;
		}
		//If guest is not enable VMXON instruction
		//Run outside of SMX mode, and Ia32_Feature_Control.enable_vmxon = 1
		if (!IsGuestEnableVMXOnInstruction())
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMXON: Guest is not enable VMXON instruction !"));
			//#gp
			ThrowGerneralFaultInterrupt();
			break;
		}
		//If guest is not set Numberic Error Bit in CR0
		//CR0.NE = 0
		if (!IsGuestSetNumericErrorBit())
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMXON: has not set numberic error bit of CR0 register !"));
			//#gp
			ThrowGerneralFaultInterrupt();
			break;
		}
		//if is it not page aglined
		if (!CheckPageAlgined(vmxon_region_pa))
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMXON: not page aligned physical address %I64X !"), vmxon_region_pa);
			VMfailInvalid(GetFlagReg(guest_context));
			break;
		}
		//if IA32_VMX_BASIC[48] == 1 it is not support 64bit addressing, so address[32] to address[63] supposed = 0
		if (!CheckPhysicalAddress(vmxon_region_pa))
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMXON: invalid physical address %I64X !"), vmxon_region_pa);
			VMfailInvalid(GetFlagReg(guest_context));
			break;
		}

		//VMCS id is not supported
		if (vmxon_region_struct->revision_identifier != GetVMCSRevisionIdentifier())
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMXON: VMCS revision identifier is not supported,  CPU supports identifier is : %x !"), GetVMCSRevisionIdentifier());
			VMfailInvalid(GetFlagReg(guest_context));
			break;
		}

		///TODO: a20m and in SMX operation3 and bit 1 of IA32_FEATURE_CONTROL MSR is clear

		NestedVmm* vm = (NestedVmm*)ExAllocatePool(NonPagedPoolNx, sizeof(NestedVmm));
		vm->inVMX = TRUE;
		vm->inRoot = TRUE;
		vm->blockINITsignal = TRUE;
		vm->blockAndDisableA20M = TRUE;
		vm->vmcs02_pa = 0xFFFFFFFFFFFFFFFF;
		vm->vmcs12_pa = 0xFFFFFFFFFFFFFFFF;
		__vmx_vmptrst(&vm->vmcs01_pa);
		vm->vmxon_region = vmxon_region_pa;
		vm->CpuNumber = KeGetCurrentProcessorNumberEx(&number);
		g_vcpus[vm->CpuNumber] = vm;
		HYPERPLATFORM_LOG_DEBUG_SAFE("VMXON: Guest Instruction Pointer %I64X Guest Stack Pointer: %I64X  Guest VMXON_Region: %I64X stored at %I64x physical address\r\n",
			InstructionPointer, StackPointer, vmxon_region_pa, debug_vmxon_region_pa);

		HYPERPLATFORM_LOG_DEBUG_SAFE("VMXON: Run Successfully with VMXON_Region:  %I64X Total Vitrualized Core: %x  Current Cpu: %x in Cpu Group : %x  Number: %x \r\n",
			vmxon_region_pa, g_VM_Core_Count, vm->CpuNumber, number.Group, number.Number);

		HYPERPLATFORM_LOG_DEBUG_SAFE("VMXON: VCPU No.: %i Mode: %s Current VMCS : %I64X VMXON Region : %I64X  ",
			g_vcpus[vm->CpuNumber]->CpuNumber, (g_vcpus[vm->CpuNumber]->inVMX) ? "VMX" : "No VMX", g_vcpus[vm->CpuNumber]->vmcs02_pa, g_vcpus[vm->CpuNumber]->vmxon_region);

		//a group of CPU maximum is 64 core
		if (g_VM_Core_Count < 64)
		{
			_InterlockedIncrement(&g_VM_Core_Count);
		}

		BuildGernericVMCSMap();

		VMSucceed(GetFlagReg(guest_context));

	} while (FALSE);
}


//---------------------------------------------------------------------------------------------------------------------//
VOID VmclearEmulate(GuestContext* guest_context)
{
	do
	{
		ULONG64				InstructionPointer = { UtilVmRead64(VmcsField::kGuestRip) };
		ULONG64				StackPointer = { UtilVmRead64(VmcsField::kGuestRsp) };
		ULONG64				vmcs_region_pa = *(PULONG64)DecodeVmclearOrVmptrldOrVmptrstOrVmxon(guest_context);//*(PULONG64)(StackPointer + offset);				//May need to be fixed later
		ULONG64				debug_vmcs_region_pa = DecodeVmclearOrVmptrldOrVmptrstOrVmxon(guest_context);
		PROCESSOR_NUMBER	procnumber = {};
		VmControlStructure* vmcs_region_va = (VmControlStructure*)UtilVaFromPa(vmcs_region_pa);
		NestedVmm*				vm = GetCurrentCPU();

		if (!vm)
		{
			DumpVcpu();
			HYPERPLATFORM_COMMON_DBG_BREAK();
			break;
		}

		//If parameter is NULL
		if (!vmcs_region_pa)
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMXCLEAR: Parameter is NULL ! \r\n"));
			//#UD
			ThrowInvalidCodeException();
			break;
		}

		//If VCPU is not run in VMX mode
		if (!vm->inVMX)
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMXCLEAR: VMXON is required ! \r\n"));
			//#UD
			ThrowInvalidCodeException();
			break;
		}

		//CR0.PE = 0;
		if (!IsGuestInProtectedMode())
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMXCLEAR: Please running in Protected Mode ! \r\n"));
			//#UD
			ThrowInvalidCodeException();
			break;
		}

		//If guest run in virtual-8086 mode
		//RFLAGS.VM = 1
		if (IsGuestInVirtual8086())
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMXCLEAR: Guest is running in virtual-8086 mode ! \r\n"));
			//#UD
			ThrowInvalidCodeException();
			break;
		}

		//If guest run in IA32-e 
		//kGuestIa32Efer.LMA = 1
		if (IsGuestInIA32eMode())
		{
			//If CS.L == 0 , means compability mode (32bit addressing), CS.L == 1 is 64bit mode , default operand is 32bit
			if (!IsGuestinCompatibliltyMode())
			{
				HYPERPLATFORM_LOG_DEBUG_SAFE(("VMXCLEAR: Guest is IA-32e mode but not in 64bit mode ! \r\n"));
				//#UD
				ThrowInvalidCodeException();
				break;
			}
		}

		//Get Guest CPL
		if (GetGuestCPL() > 0)
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMXCLEAR: Need running in Ring - 0 ! \r\n")); 	  //#gp
			ThrowGerneralFaultInterrupt();
			break;
		}

		//if is it not page aglined
		if (!CheckPageAlgined(vmcs_region_pa))
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMXCLEAR: not page aligned physical address %I64X ! \r\n"),
				vmcs_region_pa);

			VMfailInvalid(GetFlagReg(guest_context));
			break;
		}

		//if IA32_VMX_BASIC[48] == 1 it is not support 64bit addressing, so address[32] to address[63] supposed = 0
		if (!CheckPhysicalAddress(vmcs_region_pa))
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMXCLEAR: invalid physical address %I64X ! \r\n"),
				vmcs_region_pa);

			VMfailInvalid(GetFlagReg(guest_context));
			break;
		}
		//if vmcs != vmregion 
		if (vm && (vmcs_region_pa == vm->vmxon_region))
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMXCLEAR: VMCS region %I64X same as VMXON region %I64X ! \r\n"),
				vmcs_region_pa, vm->vmxon_region);

			VMfailInvalid(GetFlagReg(guest_context));
			break;
		}

		*(PLONG)(&vmcs_region_va->data) = VMCS_STATE_CLEAR;
		if (vmcs_region_pa == vm->vmcs12_pa)
		{
			vm->vmcs12_pa = 0xFFFFFFFFFFFFFFFF;
		}

		__vmx_vmclear(&vm->vmcs02_pa);
		vm->vmcs02_pa = 0xFFFFFFFFFFFFFFFF;

		HYPERPLATFORM_LOG_DEBUG_SAFE("VMCLEAR: Guest Instruction Pointer %I64X Guest Stack Pointer: %I64X  Guest vmcs region: %I64X stored at %I64x on stack\r\n",
			InstructionPointer, StackPointer, vmcs_region_pa, debug_vmcs_region_pa);

		HYPERPLATFORM_LOG_DEBUG_SAFE("VMCLEAR: Run Successfully with VMCS_Region:  %I64X Total Vitrualized Core: %x  Current Cpu: %x in Cpu Group : %x  Number: %x \r\n",
			vmcs_region_pa, g_VM_Core_Count, vm->CpuNumber, procnumber.Group, procnumber.Number);

		HYPERPLATFORM_LOG_DEBUG_SAFE("VMCLEAR: VCPU No.: %i Mode: %s Current VMCS : %I64X VMXON Region : %I64X  ",
			vm->CpuNumber, (vm->inVMX) ? "VMX" : "No VMX", vm->vmcs02_pa, vm->vmxon_region);

		VMSucceed(GetFlagReg(guest_context));
	} while (FALSE);
}

//---------------------------------------------------------------------------------------------------------------------//
VOID VmptrldEmulate(GuestContext* guest_context)
{
	do
	{
		PROCESSOR_NUMBER	procnumber = {};
		ULONG64				InstructionPointer = { UtilVmRead64(VmcsField::kGuestRip) };
		ULONG64				StackPointer = { UtilVmRead64(VmcsField::kGuestRsp) };
		ULONG64				vmcs12_region_pa = *(PULONG64)DecodeVmclearOrVmptrldOrVmptrstOrVmxon(guest_context);
		VmControlStructure*   vmcs12_region_va = (VmControlStructure*)UtilVaFromPa(vmcs12_region_pa);
		NestedVmm*				vm = GetCurrentCPU();

		if (!vm)
		{
			DumpVcpu();
			HYPERPLATFORM_COMMON_DBG_BREAK();
			break;
		}

		// if vmcs region is NULL
		if (!vmcs12_region_va)
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("kVmptrld: Parameter is NULL ! \r\n"));
			//#UD
			ThrowInvalidCodeException();
			break;
		}
		// if VCPU not run in VMX mode 
		if (!vm->inVMX)
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("kVmptrld: VMXON is required ! \r\n"));
			//#UD
			ThrowInvalidCodeException();
			break;
		}
		//CR0.PE = 0;
		if (!IsGuestInProtectedMode())
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("kVmptrld: Please running in Protected Mode ! \r\n"));
			//#UD
			ThrowInvalidCodeException();
			break;
		}

		//If guest run in virtual-8086 mode
		//RFLAGS.VM = 1
		if (IsGuestInVirtual8086())
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("kVmptrld: Guest is running in virtual-8086 mode ! \r\n"));
			//#UD
			ThrowInvalidCodeException();
			break;
		}

		//If guest run in IA32-e 
		//kGuestIa32Efer.LMA = 1
		if (IsGuestInIA32eMode())
		{
			//If CS.L == 0 , means compability mode (32bit addressing), CS.L == 1 is 64bit mode , default operand is 32bit
			if (!IsGuestinCompatibliltyMode())
			{
				HYPERPLATFORM_LOG_DEBUG_SAFE(("kVmptrld: Guest is IA-32e mode but not in 64bit mode ! \r\n"));
				//#UD
				ThrowInvalidCodeException();
				break;
			}
		}

		///TODO: If in VMX non-root operation, should be VM Exit 
		//Get Guest CPL
		if (GetGuestCPL() > 0)
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("kVmptrld: Need running in Ring - 0 ! \r\n")); 	  //#gp
			ThrowGerneralFaultInterrupt();
			break;
		}
		//if is it not page aglined
		if (!CheckPageAlgined(vmcs12_region_pa))
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("kVmptrld: not page aligned physical address %I64X ! \r\n"),
				vmcs12_region_pa);

			VMfailInvalid(GetFlagReg(guest_context));
			break;
		}

		//if IA32_VMX_BASIC[48] == 1 it is not support 64bit addressing, so address[32] to address[63] supposed = 0
		if (!CheckPhysicalAddress(vmcs12_region_pa))
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("kVmptrld: invalid physical address %I64X ! \r\n"),
				vmcs12_region_pa);

			VMfailInvalid(GetFlagReg(guest_context));
			break;
		}

		if (vm && (vmcs12_region_pa == vm->vmxon_region))
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("kVmptrld: VMCS region %I64X same as VMXON region %I64X ! \r\n"),
				vmcs12_region_pa, vm->vmxon_region);

			VMfailInvalid(GetFlagReg(guest_context));
			break;
		}

		//VMCS id is not supported
		if (vmcs12_region_va->revision_identifier != GetVMCSRevisionIdentifier())
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMPTRLD: VMCS revision identifier is not supported,  CPU supports identifier is : %x !"), GetVMCSRevisionIdentifier());
			VMfailInvalid(GetFlagReg(guest_context));
			break;
		}

		PUCHAR			  vmcs02_region_va = (PUCHAR)ExAllocatePool(NonPagedPoolNx, PAGE_SIZE);
		ULONG64			  vmcs02_region_pa = UtilPaFromVa(vmcs02_region_va);

		RtlFillMemory(vmcs02_region_va, PAGE_SIZE, 0x0);

		vm->vmcs02_pa = vmcs02_region_pa;		    //vmcs02' physical address - DIRECT VMREAD/WRITE
		vm->vmcs12_pa = vmcs12_region_pa;		    //vmcs12' physical address - we will control its structure in Vmread/Vmwrite
		vm->kVirtualProcessorId = (USHORT)KeGetCurrentProcessorNumberEx(nullptr) + 1;

		HYPERPLATFORM_LOG_DEBUG_SAFE("[VMPTRLD] Run Successfully \r\n");
		HYPERPLATFORM_LOG_DEBUG_SAFE("[VMPTRLD] VMCS02 PA: %I64X VA: %I64X  \r\n", vmcs02_region_pa, vmcs02_region_va);
		HYPERPLATFORM_LOG_DEBUG_SAFE("[VMPTRLD] VMCS12 PA: %I64X VA: %I64X \r\n", vmcs12_region_pa, vmcs12_region_va);
		HYPERPLATFORM_LOG_DEBUG_SAFE("[VMPTRLD] VMCS01 PA: %I64X VA: %I64X \r\n", vm->vmcs01_pa);
		HYPERPLATFORM_LOG_DEBUG_SAFE("[VMPTRLD] Current Cpu: %x in Cpu Group : %x  Number: %x \r\n", vm->CpuNumber, procnumber.Group, procnumber.Number);

		VMSucceed(GetFlagReg(guest_context));

	} while (FALSE);
}

//---------------------------------------------------------------------------------------------------------------------//
VOID VmreadEmulate(GuestContext* guest_context)
{

	do
	{
		PROCESSOR_NUMBER  procnumber = { 0 };
		NestedVmm*				 vm = GetCurrentCPU();
		ULONG64			  vmcs12_pa = vm->vmcs12_pa;
		ULONG64			  vmcs12_va = (ULONG64)UtilVaFromPa(vmcs12_pa);
		if (!vm)
		{
			DumpVcpu();
			HYPERPLATFORM_COMMON_DBG_BREAK();
			break;
		}
		// if VCPU not run in VMX mode
		if (!vm->inVMX)
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMREAD: VMXON is required ! \r\n"));
			//#UD
			ThrowInvalidCodeException();
			break;
		}
		//CR0.PE = 0;
		if (!IsGuestInProtectedMode())
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMREAD: Please running in Protected Mode ! \r\n"));
			//#UD
			ThrowInvalidCodeException();
			break;
		}

		//If guest run in virtual-8086 mode
		//RFLAGS.VM = 1
		if (IsGuestInVirtual8086())
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMREAD: Guest is running in virtual-8086 mode ! \r\n"));
			//#UD
			ThrowInvalidCodeException();
			break;
		}

		//If guest run in IA32-e 
		//kGuestIa32Efer.LMA = 1
		if (IsGuestInIA32eMode())
		{
			//If CS.L == 0 , means compability mode (32bit addressing), CS.L == 1 is 64bit mode , default operand is 32bit
			if (!IsGuestinCompatibliltyMode())
			{
				HYPERPLATFORM_LOG_DEBUG_SAFE(("VMREAD: Guest is IA-32e mode but not in 64bit mode ! \r\n"));
				//#UD
				ThrowInvalidCodeException();
				break;
			}
		}

		///TODO: If in VMX non-root operation, should be VM Exit

		//Get Guest CPLvm
		if (GetGuestCPL() > 0)
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE("VMREAD: Need running in Ring - 0 ! , now is cs.cpi: %x \r\n", GetGuestCPL()); 	  //#gp
			ThrowGerneralFaultInterrupt();
			break;
		}

		VmcsField field;
		ULONG_PTR offset;
		ULONG_PTR value;
		BOOLEAN   RorM;
		ULONG_PTR regIndex;
		ULONG_PTR memAddress;

		field = DecodeVmwriteOrVmRead(GetGpReg(guest_context), &offset, &value, &RorM, &regIndex, &memAddress);

		if (!is_vmcs_field_supported(field))
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE("VMREAD: Virtual VT-x is not supported this feature [field: %I64X] \r\n", field); 	  //#gp
			VMfailInvalid(GetFlagReg(guest_context));
			break;
		}

		if ((ULONG64)vmcs12_va == 0xFFFFFFFFFFFFFFFF)
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMREAD: 0xFFFFFFFFFFFFFFFF		 ! \r\n")); 	  //#gp
			VMfailInvalid(GetFlagReg(guest_context));
			break;
		}


		/*  if (!g_vcpus[vcpu_index]->inRoot)
		{
		///TODO: Should INJECT vmexit to L1
		///	   And Handle it well
		break;
		}
		*/
		auto operand_size = VMCS_FIELD_WIDTH((int)field);


		if (RorM)
		{
			auto reg = VmmpSelectRegister((ULONG)regIndex, guest_context);
			if (operand_size == VMCS_FIELD_WIDTH_16BIT)
			{
				VmRead16(field, vmcs12_va, (PUSHORT)reg);
				HYPERPLATFORM_LOG_DEBUG_SAFE("VMREAD16: field: %I64X base: %I64X Offset: %I64X Value: %I64X\r\n", field, vmcs12_va, offset, *(PUSHORT)reg);

			}
			if (operand_size == VMCS_FIELD_WIDTH_32BIT)
			{
				VmRead32(field, vmcs12_va, (PULONG32)reg);
				HYPERPLATFORM_LOG_DEBUG_SAFE("VMREAD32: field: %I64X base: %I64X Offset: %I64X Value: %I64X\r\n", field, vmcs12_va, offset, *(PULONG32)reg);
			}
			if (operand_size == VMCS_FIELD_WIDTH_64BIT || operand_size == VMCS_FIELD_WIDTH_NATURAL_WIDTH)
			{
				VmRead64(field, vmcs12_va, (PULONG64)reg);
				HYPERPLATFORM_LOG_DEBUG_SAFE("VMREAD64: field: %I64X base: %I64X Offset: %I64X Value: %I64X\r\n", field, vmcs12_va, offset, *(PULONG64)reg);
			}

		}
		else
		{
			if (operand_size == VMCS_FIELD_WIDTH_16BIT)
			{
				VmRead16(field, vmcs12_va, (PUSHORT)memAddress);
				HYPERPLATFORM_LOG_DEBUG_SAFE("VMREAD16: field: %I64X base: %I64X Offset: %I64X Value: %I64X\r\n", field, vmcs12_va, offset, *(PUSHORT)memAddress);
			}
			if (operand_size == VMCS_FIELD_WIDTH_32BIT)
			{
				VmRead32(field, vmcs12_va, (PULONG32)memAddress);
				HYPERPLATFORM_LOG_DEBUG_SAFE("VMREAD32: field: %I64X base: %I64X Offset: %I64X Value: %I64X\r\n", field, vmcs12_va, offset, *(PULONG32)memAddress);
			}
			if (operand_size == VMCS_FIELD_WIDTH_64BIT || operand_size == VMCS_FIELD_WIDTH_NATURAL_WIDTH)
			{
				VmRead64(field, vmcs12_va, (PULONG64)memAddress);
				HYPERPLATFORM_LOG_DEBUG_SAFE("VMREAD64: field: %I64X base: %I64X Offset: %I64X Value: %I64X\r\n", field, vmcs12_va, offset, *(PULONG64)memAddress);
			}
		}
		VMSucceed(GetFlagReg(guest_context));
	} while (FALSE);
}

//---------------------------------------------------------------------------------------------------------------------//
VOID VmwriteEmulate(GuestContext* guest_context)
{

	do
	{
		PROCESSOR_NUMBER    procnumber = { 0 };
		NestedVmm*				 vm = GetCurrentCPU();
		ULONG64			  vmcs12_pa = (ULONG64)vm->vmcs12_pa;
		ULONG64			  vmcs12_va = (ULONG64)UtilVaFromPa(vmcs12_pa);
		if (!vm)
		{
			DumpVcpu();
			HYPERPLATFORM_COMMON_DBG_BREAK();
			break;
		}
		// if VCPU not run in VMX mode
		if (!vm->inVMX)
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMWRITE: VMXON is required ! \r\n"));
			//#UD
			ThrowInvalidCodeException();
			break;
		}
		//CR0.PE = 0;
		if (!IsGuestInProtectedMode())
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMWRITE: Please running in Protected Mode ! \r\n"));
			//#UD
			ThrowInvalidCodeException();
			break;
		}

		//If guest run in virtual-8086 mode
		//RFLAGS.VM = 1
		if (IsGuestInVirtual8086())
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMWRITE: Guest is running in virtual-8086 mode ! \r\n"));
			//#UD
			ThrowInvalidCodeException();
			break;
		}

		//If guest run in IA32-e 
		//kGuestIa32Efer.LMA = 1
		if (IsGuestInIA32eMode())
		{
			//If CS.L == 0 , means compability mode (32bit addressing), CS.L == 1 is 64bit mode , default operand is 32bit
			if (!IsGuestinCompatibliltyMode())
			{
				HYPERPLATFORM_LOG_DEBUG_SAFE(("VMWRITE: Guest is IA-32e mode but not in 64bit mode ! \r\n"));
				//#UD
				ThrowInvalidCodeException();
				break;
			}
		}

		///TODO: If in VMX non-root operation, should be VM Exit

		//Get Guest CPL
		if (GetGuestCPL() > 0)
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMWRITE: Need running in Ring - 0 ! \r\n")); 	  //#gp
			ThrowGerneralFaultInterrupt();
			break;
		}

		VmcsField field;
		ULONG_PTR offset;
		ULONG_PTR Value;
		BOOLEAN   RorM;

		field = DecodeVmwriteOrVmRead(GetGpReg(guest_context), &offset, &Value, &RorM);

		if (!is_vmcs_field_supported(field))
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE("VMWRITE: IS NOT SUPPORT %X ! \r\n", field); 	  //#gp
			VMfailInvalid(GetFlagReg(guest_context));
			break;
		}

		/*if (!g_vcpus[vcpu_index]->inRoot)
		{
		///TODO: Should INJECT vmexit to L1
		///	   And Handle it well
		break;
		}*/
		auto operand_size = VMCS_FIELD_WIDTH((int)field);
		if (operand_size == VMCS_FIELD_WIDTH_16BIT)
		{
			VmWrite16(field, vmcs12_va, Value);
			HYPERPLATFORM_LOG_DEBUG_SAFE("VMWRITE: field: %I64X base: %I64X Offset: %I64X Value: %I64X  \r\n", field, vmcs12_va, offset, (USHORT)Value);
		}

		if (operand_size == VMCS_FIELD_WIDTH_32BIT)
		{
			VmWrite32(field, vmcs12_va, Value);
			HYPERPLATFORM_LOG_DEBUG_SAFE("VMWRITE: field: %I64X base: %I64X Offset: %I64X Value: %I64X\r\n", field, vmcs12_va, offset, (ULONG32)Value);
		}
		if (operand_size == VMCS_FIELD_WIDTH_64BIT || operand_size == VMCS_FIELD_WIDTH_NATURAL_WIDTH)
		{
			VmWrite64(field, vmcs12_va, Value);
			HYPERPLATFORM_LOG_DEBUG_SAFE("VMWRITE: field: %I64X base: %I64X Offset: %I64X Value: %I64X\r\n", field, vmcs12_va, offset, (ULONG64)Value);
		}


		VMSucceed(GetFlagReg(guest_context));
	} while (FALSE);
}
/*
64 bit Control field is not used

// below not used
// kVmExitMsrStoreAddr = 0x00002006,
// kVmExitMsrStoreAddrHigh = 0x00002007,
// kVmExitMsrLoadAddr = 0x00002008,
// kVmExitMsrLoadAddrHigh = 0x00002009,
// kVmEntryMsrLoadAddr = 0x0000200a,
// kVmEntryMsrLoadAddrHigh = 0x0000200b,
// kExecutiveVmcsPointer = 0x0000200c,
// kExecutiveVmcsPointerHigh = 0x0000200d,


// below not used
kTscOffset = 0x00002010,
kTscOffsetHigh = 0x00002011,
kVirtualApicPageAddr = 0x00002012,
kVirtualApicPageAddrHigh = 0x00002013,
kApicAccessAddrHigh = 0x00002015,
kPostedInterruptDescAddr  =  0x00002016,
kPostedInterruptDescAddrHigh = 0x00002017,

// below not used
kVmreadBitmapAddress = 0x00002026,
kVmreadBitmapAddressHigh = 0x00002027,
kVmwriteBitmapAddress = 0x00002028,
kVmwriteBitmapAddressHigh = 0x00002029,
kVirtualizationExceptionInfoAddress = 0x0000202a,
kVirtualizationExceptionInfoAddressHigh = 0x0000202b,
kXssExitingBitmap = 0x0000202c,
kXssExitingBitmapHigh = 0x0000202d,
*/

/*----------------------------------------------------------------------------------------------------

VMCS02 Structure
--------------------------------------
16/32/64/Natrual Guest state field :  VMCS12
16/32/64/Natrual Host  state field :  VMCS01
16/32/64/Natrual Control field	   :  VMCS01+VMCS12

----------------------------------------------------------------------------------------------------*/


//---------------------------------------------------------------------------------------------------------------------//
VOID VmlaunchEmulate(GuestContext* guest_context)
{

	PROCESSOR_NUMBER  procnumber = { 0 };
	NestedVmm* vm = GetCurrentCPU();
	VmxStatus		  status;
	do { 
		HYPERPLATFORM_LOG_DEBUG_SAFE("-----start vmlaunch---- \r\n");
		if (!vm)
		{
			DumpVcpu();
			HYPERPLATFORM_COMMON_DBG_BREAK();
			break;
		}
		//not in vmx mode
		if (!vm->inVMX)
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMLAUNCH: VMXON is required ! \r\n"));
			//#UD
			ThrowInvalidCodeException();
			break;
		}

		//CR0.PE = 0;
		if (!IsGuestInProtectedMode())
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMLAUNCH: Please running in Protected Mode ! \r\n"));
			//#UD
			ThrowInvalidCodeException();
			break;
		}

		//If guest run in virtual-8086 mode
		//RFLAGS.VM = 1
		if (IsGuestInVirtual8086())
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMLAUNCH: Guest is running in virtual-8086 mode ! \r\n"));
			//#UD
			ThrowInvalidCodeException();
			break;
		}

		//If guest run in IA32-e
		//kGuestIa32Efer.LMA = 1
		if (IsGuestInIA32eMode())
		{
			//If CS.L == 0 , means compability mode (32bit addressing), CS.L == 1 is 64bit mode , default operand is 32bit
			if (!IsGuestinCompatibliltyMode())
			{
				HYPERPLATFORM_LOG_DEBUG_SAFE(("VMLAUNCH: Guest is IA-32e mode but not in 64bit mode ! \r\n"));
				//#UD
				ThrowInvalidCodeException();
				break;
			}
		}
		//Get Guest CPL
		if (GetGuestCPL() > 0)
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMLAUNCH: Need running in Ring - 0 ! \r\n")); 	  //#gp
			ThrowGerneralFaultInterrupt();
			break;
		}


		ENTER_GUEST_MODE(vm);

		/*
		if (!g_vcpus[vcpu_index]->inRoot)
		{
		///TODO: Should INJECT vmexit to L1
		///	   And Handle it well
		break;
		}
		*/
		//Get vmcs02 / vmcs12


		auto    vmcs02_pa = vm->vmcs02_pa;
		auto	vmcs12_pa = vm->vmcs12_pa;

		if (!vmcs02_pa || !vmcs12_pa)
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMLAUNCH: VMCS still not loaded ! \r\n"));
			VMfailInvalid(GetFlagReg(guest_context));
			break;
		}

		auto    vmcs02_va = (ULONG64)UtilVaFromPa(vmcs02_pa);
		auto    vmcs12_va = (ULONG64)UtilVaFromPa(vmcs12_pa);


		///1. Check Setting of VMX Controls and Host State area;
		///2. Attempt to load guest state and PDPTRs as appropriate
		///3. Attempt to load MSRs from VM-Entry MSR load area;
		///4. Set VMCS to "launched"
		///5. VM Entry success

		//Guest passed it to us, and read/write it  VMCS 1-2
		// Write a VMCS revision identifier
		const Ia32VmxBasicMsr vmx_basic_msr = { UtilReadMsr64(Msr::kIa32VmxBasic) };
		RtlFillMemory((PVOID)vmcs02_va, 0, PAGE_SIZE);
		VmControlStructure* ptr = (VmControlStructure*)vmcs02_va;
		ptr->revision_identifier = vmx_basic_msr.fields.revision_identifier;

		ULONG64 vmcs01_rsp = UtilVmRead64(VmcsField::kHostRsp);
		ULONG64 vmcs01_rip = UtilVmRead64(VmcsField::kHostRip);

		/*
		1. Mix vmcs control field
		*/
		PrepareHostAndControlField(vmcs12_va, vmcs02_pa, TRUE);

		/*
		2. Read VMCS12 Guest's field to VMCS02
		*/
		PrepareGuestStateField(vmcs12_va);


		if (GetGuestIrql(guest_context) < DISPATCH_LEVEL)
		{
			KeLowerIrql(GetGuestIrql(guest_context));
		}

		if (VmxStatus::kOk != (status = static_cast<VmxStatus>(__vmx_vmlaunch())))
		{
			VmxInstructionError error2 = static_cast<VmxInstructionError>(UtilVmRead(VmcsField::kVmInstructionError));
			HYPERPLATFORM_LOG_DEBUG_SAFE("Error VMLAUNCH error code :%x , %x ", status, error2);
			HYPERPLATFORM_COMMON_DBG_BREAK();
		}

		HYPERPLATFORM_LOG_DEBUG_SAFE("Error VMLAUNCH error code :%x , %x ", 0, 0);
		return;
	} while (FALSE);

}
//----------------------------------------------------------------------------------------------------------------//
VOID VmresumeEmulate(GuestContext* guest_context)
{
	do
	{
		PROCESSOR_NUMBER  procnumber = { 0 };
		NestedVmm* vm = GetCurrentCPU();
		HYPERPLATFORM_LOG_DEBUG_SAFE("----Start Emulate VMRESUME---");

		if (!vm)
		{
			DumpVcpu();
			HYPERPLATFORM_COMMON_DBG_BREAK();
			break;
		}
 		//not in vmx mode
		if (!vm->inVMX)
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMWRITE: VMXON is required ! \r\n"));
			//#UD
			ThrowInvalidCodeException();
			break;
		}

		//CR0.PE = 0;
		if (!IsGuestInProtectedMode())
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMWRITE: Please running in Protected Mode ! \r\n"));
			//#UD
			ThrowInvalidCodeException();
			break;
		}

		//If guest run in virtual-8086 mode
		//RFLAGS.VM = 1
		if (IsGuestInVirtual8086())
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMWRITE: Guest is running in virtual-8086 mode ! \r\n"));
			//#UD
			ThrowInvalidCodeException();
			break;
		}

		//If guest run in IA32-e
		//kGuestIa32Efer.LMA = 1
		if (IsGuestInIA32eMode())
		{
			//If CS.L == 0 , means compability mode (32bit addressing), CS.L == 1 is 64bit mode , default operand is 32bit
			if (!IsGuestinCompatibliltyMode())
			{
				HYPERPLATFORM_LOG_DEBUG_SAFE(("VMWRITE: Guest is IA-32e mode but not in 64bit mode ! \r\n"));
				//#UD
				ThrowInvalidCodeException();
				break;
			}
		}
		//Get Guest CPL
		if (GetGuestCPL() > 0)
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMLAUNCH: Need running in Ring - 0 ! \r\n")); 	  //#gp
			ThrowGerneralFaultInterrupt();
			break;
		}


		ENTER_GUEST_MODE(vm);

		auto      vmcs02_pa = vm->vmcs02_pa;
		auto	  vmcs12_pa = vm->vmcs12_pa;

		if (!vmcs02_pa || !vmcs12_pa)
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMLAUNCH: VMCS still not loaded ! \r\n"));
			VMfailInvalid(GetFlagReg(guest_context));
			break;
		}

		auto    vmcs02_va = (ULONG64)UtilVaFromPa(vmcs02_pa);
		auto    vmcs12_va = (ULONG64)UtilVaFromPa(vmcs12_pa);

		// Write a VMCS revision identifier
		const Ia32VmxBasicMsr vmx_basic_msr = { UtilReadMsr64(Msr::kIa32VmxBasic) };

		VmControlStructure* ptr = (VmControlStructure*)vmcs02_va;
		ptr->revision_identifier = vmx_basic_msr.fields.revision_identifier;

		//Restore some MSR we may need to ensure the consistency 
		vmx_restore_guest_msrs(vm);

		//Prepare VMCS01 Host / Control Field
		PrepareHostAndControlField(vmcs12_va, vmcs02_pa, FALSE);

		/*
		VM Guest state field Start
		*/
		PrepareGuestStateField(vmcs12_va);


		/*
		VM Guest state field End
		*/
		//--------------------------------------------------------------------------------------//

		/*
		*		After L1 handles any VM Exit and should be executes VMRESUME for back L2
		*		But this time trapped by VMCS01 and We can't get any VM-Exit information
		*       from it. So we need to read from VMCS12 and return from here immediately.
		*		We saved the vmcs02 GuestRip into VMCS12 our VMExit Handler because when
		*		L1 was executing VMRESUME(We injected VMExit to it), and it is running on
		*		VMCS01, we can't and shouldn't change it.
		*		See: VmmVmExitHandler
		*/

		//--------------------------------------------------------------------------------------//


		PrintVMCS(); 


		HYPERPLATFORM_COMMON_DBG_BREAK();
	} while (FALSE);
}

//----------------------------------------------------------------------------------------------------------------//
VOID VmptrstEmulate(GuestContext* guest_context)
{
	do
	{
		PROCESSOR_NUMBER	procnumber = {};
		ULONG64				InstructionPointer = { UtilVmRead64(VmcsField::kGuestRip) };
		ULONG64				StackPointer = { UtilVmRead64(VmcsField::kGuestRsp) };
		ULONG64				vmcs12_region_pa = *(PULONG64)DecodeVmclearOrVmptrldOrVmptrstOrVmxon(guest_context);
		ULONG64				vmcs12_region_va = (ULONG64)UtilVaFromPa(vmcs12_region_pa);
		ULONG				vcpu_index = KeGetCurrentProcessorNumberEx(&procnumber);

		__vmx_vmptrst(&vmcs12_region_va);
		VMSucceed(GetFlagReg(guest_context));
	} while (FALSE);
}
}