/*++

Copyright (c) 2016 KelvinChan. All rights reserved.
Use of this source code is governed by a MIT-style license that can be
found in the LICENSE file.

Module Name:

	vmx.cpp

Abstract:

	Intel VT-x , VMX Instruction and behavior Emulation

Author:
	
	Kelvin Chan

Environment:

	Kernel VMM Mode

--*/
#include <intrin.h>
#include "..\HyperPlatform\util.h"
#include "vmcs.h"
#include "vmx.h"
#include "..\HyperPlatform\vmm.h"
#include "..\HyperPlatform\log.h"
#include "..\HyperPlatform\common.h"
#include "vmx_common.h"
#include "..\HyperPlatform\ept.h"
extern "C"
{

////////////////////////////////////////////////////////////////////////////////////////////////////
//// Prototype
////

VOID			
SaveGuestCr8(
	VCPUVMX* vcpu, 
	ULONG_PTR cr8
);

VOID			
RestoreGuestCr8(
	VCPUVMX* vcpu
);

VOID			
VmxAssertPrint(
	ULONG Line, 
	bool IsVerified
);
////////////////////////////////////////////////////////////////////////////////////////////////////
//// Marco
////

#define HYPERPLATFORM_ASSERT(statement)   \
			VmxAssertPrint(__LINE__ , statement); 
	 
 
 
////////////////////////////////////////////////////////////////////////////////////////////////////
//// 
//// Variable
//// 

extern BOOLEAN		 IsEmulateVMExit;


////////////////////////////////////////////////////////////////////////////////////////////////////
//// 
//// Type
////

////////////////////////////////////////////////////////////////////////////////////////////////////
//// 
//// Implementation
//// 

//------------------------------------------------------------------------------------------------//
BOOLEAN 
VmxIsGuestPaePaging()
/*++

Desscription:
	
	Validating guest PAE mode.

Paremeters:

	Guest Context

Return Value:

	NO

--*/
{
	VmxVmEntryControls VmEntryCtrl = { UtilVmRead(VmcsField::kVmEntryControls) };
	FlagRegister rflags = { UtilVmRead(VmcsField::kGuestRflags) };
	Cr0 cr0 = { UtilVmRead(VmcsField::kGuestCr0) };
	Cr4 cr4 = { UtilVmRead(VmcsField::kGuestCr4) }; 
	if (cr0.fields.pg && cr4.fields.pae && !VmEntryCtrl.fields.ia32e_mode_guest)
	{
		return TRUE;
	}
	return FALSE;
}
//------------------------------------------------------------------------------------------------//
VOID 
VmxAssertPrint(
	_In_	ULONG Line, 
	_In_	bool IsVerified
)
/*++

Desscription:
	
	Test assert. debug use.

Paremeters:

	Guest Context

Return Value:

	NO

--*/
{
	if (!IsVerified)
	{
		PrintVMCS(); 
		///NT_ASSERT(IsVerified);
		HYPERPLATFORM_COMMON_DBG_BREAK(); 
		HYPERPLATFORM_LOG_DEBUG("Somethings wrong ~~~ Line: %x", Line);
	}
}
	
//------------------------------------------------------------------------------------------------//
VOID	
LEAVE_GUEST_MODE(
	_In_	VCPUVMX* vm
)
/*++

Desscription:
	
	Virtual process enter the Root Mode.

Paremeters:

	Guest Context

Return Value:

	NO

--*/
{
	vm->inRoot = RootMode; 
	HYPERPLATFORM_LOG_DEBUG_SAFE("VMM: %I64x RIP= %p Enter Root mode Reason: %d", vm, UtilVmRead(VmcsField::kGuestRip), UtilVmRead(VmcsField::kVmExitReason));
}


//------------------------------------------------------------------------------------------------//
VOID	
ENTER_GUEST_MODE(
	_In_	VCPUVMX* vm
)
/*++

Desscription:
	
	Virtual process enter the Guest Mode.

Paremeters:

	Guest Context

Return Value:

	NO

--*/
{
	vm->inRoot = GuestMode; 
	HYPERPLATFORM_LOG_DEBUG_SAFE("VMM: %I64x Enter Guest mode", vm);
} 


//------------------------------------------------------------------------------------------------//
VMX_MODE 
VmxGetVmxMode(
	_In_ VCPUVMX* vmx
)
/*++

Desscription:
	
	Get VMX Mode of the corresponding virtual processor

Paremeters:

	Guest Context

Return Value:

	Emulated-Root or Emulated-Guest Mode

--*/
{
	if (vmx) 
	{
		return vmx->inRoot;
	}
	else
	{
		return VMX_MODE::RootMode;
	}
}
//------------------------------------------------------------------------------------------------//
VOID 
SaveGuestCr8(
	_In_	VCPUVMX* vcpu, 
	_In_	ULONG_PTR cr8
)
/*++

Desscription:
	NO

Paremeters:

	Guest Context

Return Value:

	NO

--*/
{
	vcpu->guest_cr8 = cr8;
}


//------------------------------------------------------------------------------------------------//
VOID
RestoreGuestCr8(
	_In_	VCPUVMX* vcpu
)
/*++

Desscription:
	NO

Paremeters:

	Guest Context

Return Value:

	NO

--*/
{
	__writecr8(vcpu->guest_cr8);
}
 
//------------------------------------------------------------------------------------------------//
VOID 
DumpVcpu(
	_In_	GuestContext* guest_context
)
{
/*++

Desscription:

	Dumping the virtual process context.

Paremeters:

	Guest Context

Return Value:

	NO

--*/
	ULONG64 vmcs12_va = 0;
	ULONG64 vmcs_pa;
	VCPUVMX* vmx = NULL; 
	if (!guest_context)
	{
		HYPERPLATFORM_LOG_DEBUG_SAFE("GuestContex Empty");
		return;
	}

	vmx = VmmpGetVcpuVmx(guest_context);
	__vmx_vmptrst(&vmcs_pa);

	HYPERPLATFORM_LOG_DEBUG_SAFE("CurrentVmcs: %I64X vm: %I64x vmcs02: %I64X vmcs01: %I64x vmcs12: %I64x root mode: %I64x \r\n",
		vmcs_pa, vmx, vmx->vmcs02_pa, vmx->vmcs01_pa, vmx->vmcs12_pa, vmx->inRoot, VmmpGetvCpuMode(guest_context));
}
//------------------------------------------------------------------------------------------------//
VOID VmxVmEntryCheckGuestReg()
/*++

Desscription:

	Validating VMCS0-2's guest register state for vmentry to L2 during emulation of the VMEntry

Paremeters:

	Guest Context

Return Value:

	NO

--*/
{
	VmxVmEntryControls VmEntryCtrl = { UtilVmRead(VmcsField::kVmEntryControls) };
	FlagRegister rflags = { UtilVmRead(VmcsField::kGuestRflags) };
	Cr0 cr0 = { UtilVmRead(VmcsField::kGuestCr0) };
	Cr0 cr0_fixed0 = { UtilReadMsr(Msr::kIa32VmxCr0Fixed0) };
	Cr0 cr0_fixed1 = { UtilReadMsr(Msr::kIa32VmxCr0Fixed1) };
	Cr0 cr0_test = { 0 };
	cr0_test.all = cr0.all;
	cr0_test.all &= cr0_fixed1.all;
	cr0_test.all |= cr0_fixed0.all;

	HYPERPLATFORM_ASSERT(cr0_test.all == cr0.all);

	Cr4 cr4 = { UtilVmRead(VmcsField::kGuestCr4) };
	Cr4 cr4_fixed0 = { UtilReadMsr(Msr::kIa32VmxCr4Fixed0) };
	Cr4 cr4_fixed1 = { UtilReadMsr(Msr::kIa32VmxCr4Fixed1) };
	Cr4 cr4_test = { 0 };
	cr4_test.all = cr4.all;
	cr4_test.all &= cr4_fixed1.all;
	cr4_test.all |= cr4_fixed0.all;

	HYPERPLATFORM_ASSERT(cr4_test.all == cr4.all);


	if (VmEntryCtrl.fields.ia32e_mode_guest)
	{
		HYPERPLATFORM_ASSERT(cr0.fields.pg && cr4.fields.pae);
	}
	else
	{
		HYPERPLATFORM_ASSERT(!cr4.fields.pcide);
	}

	HYPERPLATFORM_ASSERT(cr0.fields.pg && cr0.fields.pe);

	if (VmEntryCtrl.fields.load_debug_controls)
	{
		MSR_IA32_DEBUGCTL DbgCtrl = { UtilVmRead64(VmcsField::kGuestIa32Debugctl)};
		HYPERPLATFORM_ASSERT(!DbgCtrl.fields.Reserved1 && !DbgCtrl.fields.Reserved2);
		HYPERPLATFORM_ASSERT(!(UtilVmRead64(VmcsField::kGuestDr7) >> 32));
	}
	 
	HYPERPLATFORM_ASSERT(UtilpIsCanonicalFormAddress((void*)UtilVmRead64(VmcsField::kGuestSysenterEip)) &&
		UtilpIsCanonicalFormAddress((void*)UtilVmRead64(VmcsField::kGuestSysenterEsp)));

	if (VmEntryCtrl.fields.load_ia32_perf_global_ctrl)
	{
		MSR_IA32_PERF_GLOBAL_CTRL PerfCtrl = { UtilVmRead(VmcsField::kGuestIa32PerfGlobalCtrl) };
		HYPERPLATFORM_ASSERT( !PerfCtrl.fields.Reserved && !PerfCtrl.fields.Reserved2);
	}
	
	if (VmEntryCtrl.fields.load_ia32_efer)
	{
		MSR_EFER efer = { UtilVmRead(VmcsField::kGuestIa32Efer) }; 
		if (cr0.fields.pg)
		{
			HYPERPLATFORM_ASSERT(efer.fields.LMA == VmEntryCtrl.fields.ia32e_mode_guest == efer.fields.LME);
		}
		else
		{
			HYPERPLATFORM_ASSERT(efer.fields.LMA == VmEntryCtrl.fields.ia32e_mode_guest);
		}
	}
	 
	if (VmEntryCtrl.fields.ia32e_mode_guest || !cr0.fields.pe)
	{
		HYPERPLATFORM_ASSERT(!rflags.fields.vm);
	}
}
//---------------------------------------------------------------------------------------------------------	------------//
VOID 
VmxVmEntryCheckGuestSegReg()
/*++

Desscription:

	Validating VMCS0-2's Segment Register for vmentry to L2 during emulation of the VMEntry

Paremeters:

	Guest Context

Return Value:

	NO

--*/
{
	FlagRegister		GuestRflags = { UtilVmRead64(VmcsField::kGuestRflags) };
	VmxVmEntryControls  VmEntryCtrl = { UtilVmRead64(VmcsField::kVmEntryControls) };
	VmxSecondaryProcessorBasedControls VmSecondProcCtrl = { UtilVmRead64(VmcsField::kSecondaryVmExecControl) };
	BOOLEAN IsGuestOnV8086 = FALSE;
	BOOLEAN IsGuestOnIa32e = FALSE;

	if (GuestRflags.fields.vm)
	{
		IsGuestOnV8086 = TRUE;
	}
	else if (VmEntryCtrl.fields.ia32e_mode_guest)
	{
		IsGuestOnIa32e = TRUE;
	}
  
	if (IsGuestOnV8086)
	{
		HYPERPLATFORM_ASSERT(UtilVmRead(VmcsField::kGuestCsBase) == UtilVmRead(VmcsField::kGuestCsSelector) << 4);
		HYPERPLATFORM_ASSERT(UtilVmRead(VmcsField::kGuestDsBase) == UtilVmRead(VmcsField::kGuestDsSelector) << 4);
		HYPERPLATFORM_ASSERT(UtilVmRead(VmcsField::kGuestSsBase) == UtilVmRead(VmcsField::kGuestSsSelector) << 4);
		HYPERPLATFORM_ASSERT(UtilVmRead(VmcsField::kGuestEsBase) == UtilVmRead(VmcsField::kGuestEsSelector) << 4);
		HYPERPLATFORM_ASSERT(UtilVmRead(VmcsField::kGuestFsBase) == UtilVmRead(VmcsField::kGuestFsSelector) << 4);
		HYPERPLATFORM_ASSERT(UtilVmRead(VmcsField::kGuestGsBase) == UtilVmRead(VmcsField::kGuestGsSelector) << 4);
 
		HYPERPLATFORM_ASSERT(UtilVmRead(VmcsField::kGuestCsLimit) == 0xFFFF);
		HYPERPLATFORM_ASSERT(UtilVmRead(VmcsField::kGuestDsLimit) == 0xFFFF);
		HYPERPLATFORM_ASSERT(UtilVmRead(VmcsField::kGuestSsLimit) == 0xFFFF);
		HYPERPLATFORM_ASSERT(UtilVmRead(VmcsField::kGuestEsLimit) == 0xFFFF);
		HYPERPLATFORM_ASSERT(UtilVmRead(VmcsField::kGuestFsLimit) == 0xFFFF);
		HYPERPLATFORM_ASSERT(UtilVmRead(VmcsField::kGuestGsLimit) == 0xFFFF);
 
		HYPERPLATFORM_ASSERT(UtilVmRead(VmcsField::kGuestCsArBytes) == 0xF3);
		HYPERPLATFORM_ASSERT(UtilVmRead(VmcsField::kGuestDsArBytes) == 0xF3);
		HYPERPLATFORM_ASSERT(UtilVmRead(VmcsField::kGuestSsArBytes) == 0xF3);
		HYPERPLATFORM_ASSERT(UtilVmRead(VmcsField::kGuestEsArBytes) == 0xF3);
		HYPERPLATFORM_ASSERT(UtilVmRead(VmcsField::kGuestFsArBytes) == 0xF3);
		HYPERPLATFORM_ASSERT(UtilVmRead(VmcsField::kGuestGsArBytes) == 0xF3);
	}
	else
	{
		Cr0 cr0 = { UtilVmRead(VmcsField::kGuestCr0) };
		ULONG CsBase =   UtilVmRead(VmcsField::kGuestCsBase)  ;
		ULONG DsBase =   UtilVmRead(VmcsField::kGuestDsBase)  ;
		ULONG SsBase =   UtilVmRead(VmcsField::kGuestSsBase)  ;
		ULONG EsBase =   UtilVmRead(VmcsField::kGuestEsBase)  ;
		ULONG FsBase =   UtilVmRead(VmcsField::kGuestFsBase)  ;
		ULONG GsBase =   UtilVmRead(VmcsField::kGuestGsBase)  ;
		ULONG TrBase =   UtilVmRead(VmcsField::kGuestTrBase)  ;
		ULONG LdtrBase =  UtilVmRead(VmcsField::kGuestLdtrBase);
		 
		VmxSegmentDescriptorAccessRight CsArBytes = { UtilVmRead(VmcsField::kGuestCsArBytes) };
		VmxSegmentDescriptorAccessRight DsArBytes = { UtilVmRead(VmcsField::kGuestDsArBytes) };
		VmxSegmentDescriptorAccessRight SsArBytes = { UtilVmRead(VmcsField::kGuestSsArBytes) };
		VmxSegmentDescriptorAccessRight EsArBytes = { UtilVmRead(VmcsField::kGuestEsArBytes) };
		VmxSegmentDescriptorAccessRight FsArBytes = { UtilVmRead(VmcsField::kGuestFsArBytes) };
		VmxSegmentDescriptorAccessRight GsArBytes = { UtilVmRead(VmcsField::kGuestGsArBytes) }; 
		VmxSegmentDescriptorAccessRight TrArBytes = { UtilVmRead(VmcsField::kGuestTrArBytes) };
		VmxSegmentDescriptorAccessRight	LdtrArBytes = { UtilVmRead(VmcsField::kGuestLdtrArBytes) };

		SegmentSelector SsSelector = { UtilVmRead(VmcsField::kGuestSsSelector) };
		SegmentSelector CsSelector = { UtilVmRead(VmcsField::kGuestCsSelector) };
		SegmentSelector EsSelector = { UtilVmRead(VmcsField::kGuestEsSelector) };
		SegmentSelector FsSelector = { UtilVmRead(VmcsField::kGuestFsSelector) };
		SegmentSelector GsSelector = { UtilVmRead(VmcsField::kGuestGsSelector) };
		SegmentSelector DsSelector = { UtilVmRead(VmcsField::kGuestDsSelector) };
		SegmentSelector TrSelector = { UtilVmRead(VmcsField::kGuestTrSelector) };
		SegmentSelector LdtrSelector = { UtilVmRead(VmcsField::kGuestLdtrSelector) };

		bool VerifiedCsSelectorAr = (CsArBytes.fields.type == 9 ||
								 	 CsArBytes.fields.type == 11 ||
									CsArBytes.fields.type == 13 ||
									CsArBytes.fields.type == 15);
	
		if (VmSecondProcCtrl.fields.unrestricted_guest)
		{
			//read/write accessed expand-up data segment
			HYPERPLATFORM_ASSERT(VerifiedCsSelectorAr || CsArBytes.fields.type == 3);		 
		}
		else
		{
			//accessed code segment
			HYPERPLATFORM_ASSERT(VerifiedCsSelectorAr); 
			HYPERPLATFORM_ASSERT(VerifiedCsSelectorAr || SsArBytes.fields.dpl == SsSelector.fields.rpl);
			if (!DsArBytes.fields.unusable)
			{
				HYPERPLATFORM_ASSERT((DsArBytes.fields.dpl >= DsSelector.fields.rpl) && (DsArBytes.fields.type <= 11));
			}
			if (!EsArBytes.fields.unusable) 
			{ 
				HYPERPLATFORM_ASSERT((EsArBytes.fields.dpl >= EsSelector.fields.rpl) && (EsArBytes.fields.type <= 11));
			}
			if (!FsArBytes.fields.unusable)
			{
				HYPERPLATFORM_ASSERT((FsArBytes.fields.dpl >= FsSelector.fields.rpl) && (FsArBytes.fields.type <= 11));
			}
			if (!GsArBytes.fields.unusable)
			{ 
				HYPERPLATFORM_ASSERT((GsArBytes.fields.dpl >= GsSelector.fields.rpl) && (GsArBytes.fields.type <= 11));
			}   
		}

		// Check valid Type 
		if (!SsArBytes.fields.unusable)
		{
			HYPERPLATFORM_ASSERT((SsArBytes.fields.type == 3 || SsArBytes.fields.type == 7));
		}
		if (!DsArBytes.fields.unusable)
		{
			HYPERPLATFORM_ASSERT(DsArBytes.fields.type >= 1);
		}
		if (!EsArBytes.fields.unusable)
		{
			HYPERPLATFORM_ASSERT(EsArBytes.fields.type >= 1);
		}
		if (!FsArBytes.fields.unusable)
		{
			HYPERPLATFORM_ASSERT(FsArBytes.fields.type >= 1);
		}
		if (!GsArBytes.fields.unusable)
		{
			HYPERPLATFORM_ASSERT(GsArBytes.fields.type >= 1);
		}

		if (!CsArBytes.fields.unusable)
		{
			//Check System bit
			HYPERPLATFORM_ASSERT(CsArBytes.fields.system);
		}

		//Check DPL , other selector is checked by unrestricted guest ....
		switch (CsArBytes.fields.type)
		{
			//read/write accessed expand-up data segment
		case 3:
			if (!CsArBytes.fields.unusable)
			{
				HYPERPLATFORM_ASSERT(!CsArBytes.fields.dpl && VmSecondProcCtrl.fields.unrestricted_guest);
			}
			HYPERPLATFORM_ASSERT(!SsArBytes.fields.dpl);
			break;

			//non-conforming code segment
		case 9 :
		case 11:
			if (!CsArBytes.fields.unusable)
			{
				HYPERPLATFORM_ASSERT((CsArBytes.fields.dpl == SsArBytes.fields.dpl));
			}
			break;
	
			//conforming code segment
		case 13:
		case 15:
			if (!CsArBytes.fields.unusable)
			{
				HYPERPLATFORM_ASSERT(CsArBytes.fields.dpl < SsArBytes.fields.dpl);
			}
			break; 
		}

		if (!cr0.fields.pe)
		{
			HYPERPLATFORM_ASSERT(!SsArBytes.fields.dpl);
		}
		
		//Check P bit
 
		if (!CsArBytes.fields.unusable)
		{
			HYPERPLATFORM_ASSERT(CsArBytes.fields.present);
			if (VmEntryCtrl.fields.ia32e_mode_guest && (CsArBytes.fields.l == 1))
			{
				HYPERPLATFORM_ASSERT(!CsArBytes.fields.db  );
			}

			HYPERPLATFORM_ASSERT(!(CsBase >> 32));
		}
		if (!DsArBytes.fields.unusable)
		{
			HYPERPLATFORM_ASSERT(DsArBytes.fields.present);	
			HYPERPLATFORM_ASSERT(!DsArBytes.fields.reserved1);  
			HYPERPLATFORM_ASSERT(!(DsBase >> 32));
		}
		if (!EsArBytes.fields.unusable)
		{
			HYPERPLATFORM_ASSERT(EsArBytes.fields.present); 
			HYPERPLATFORM_ASSERT(!EsArBytes.fields.reserved1);
			HYPERPLATFORM_ASSERT(!(EsBase >> 32));
		}

		if (!SsArBytes.fields.unusable)
		{
			HYPERPLATFORM_ASSERT(SsArBytes.fields.present); 
			HYPERPLATFORM_ASSERT(!SsArBytes.fields.reserved1);
			HYPERPLATFORM_ASSERT(!(SsBase >> 32));
		}

		if (!FsArBytes.fields.unusable)
		{
			HYPERPLATFORM_ASSERT(FsArBytes.fields.present);
			HYPERPLATFORM_ASSERT(!FsArBytes.fields.reserved1);
			HYPERPLATFORM_ASSERT(UtilpIsCanonicalFormAddress((void*)FsBase));
		}

		if (!GsArBytes.fields.unusable)
		{
			HYPERPLATFORM_ASSERT(GsArBytes.fields.present); 
			HYPERPLATFORM_ASSERT(!GsArBytes.fields.reserved1);
			HYPERPLATFORM_ASSERT(UtilpIsCanonicalFormAddress((void*)GsBase));
		} 

		if (!TrArBytes.fields.unusable)
		{
			HYPERPLATFORM_ASSERT(TrArBytes.fields.type == 3 || TrArBytes.fields.type == 11);
			HYPERPLATFORM_ASSERT(UtilpIsCanonicalFormAddress((void*)TrBase));
			HYPERPLATFORM_ASSERT(!TrArBytes.fields.system && TrArBytes.fields.present && !TrArBytes.fields.unusable && !TrArBytes.fields.reserved2);
		}
		 
	 	//NT_ASSERT(!LdtrArBytes.fields.unusable && (LdtrArBytes.fields.type == 2) && !LdtrArBytes.fields.system && LdtrArBytes.fields.present && !LdtrArBytes.fields.reserved1 && !LdtrArBytes.fields.reserved2);
  
	}

}

//------------------------------------------------------------------------------------------------//

VOID 
VmxVmEntryCheckGuestDescTableReg()
/*++

Desscription:

	Validating VMCS0-2 Descriptor Table register for vmentry to L2 during emulation of the VMEntry

Paremeters:

	Guest Context

Return Value:

	NO

--*/
{
	ULONG64 GdtrBase = { UtilVmRead64(VmcsField::kGuestGdtrBase) };
	ULONG64 IdtrBase = { UtilVmRead64(VmcsField::kGuestIdtrBase) };
	ULONG   GdtrLimit =  UtilVmRead(VmcsField::kGuestGdtrLimit);
	ULONG   IdtrLimit =  UtilVmRead(VmcsField::kGuestIdtrLimit);

	HYPERPLATFORM_ASSERT(UtilpIsCanonicalFormAddress((void*)GdtrBase)
						&& UtilpIsCanonicalFormAddress((void*)IdtrBase));
	HYPERPLATFORM_ASSERT(!((GdtrLimit >> 16) & 0xFFFF));
	HYPERPLATFORM_ASSERT(!((IdtrLimit >> 16) & 0xFFFF));
}

//------------------------------------------------------------------------------------------------//
VOID 
VmxVmEntryCheckGuestRipRflags()
/*++
Desscription:

	Validating VMCS0-2 rip and rflags register for vmentry to L2 during emulation of the VMEntry

Paremeters:

	Guest Context

Return Value:

	NO

--*/
{
	VmxVmEntryControls  VmEntryCtrl = { UtilVmRead64(VmcsField::kVmEntryControls) }; 
	VmxSegmentDescriptorAccessRight CsArBytes = { UtilVmRead(VmcsField::kGuestCsArBytes) }; 
	VmxSecondaryProcessorBasedControls VmSecondProcCtrl = { UtilVmRead64(VmcsField::kSecondaryVmExecControl) };
	VmEntryInterruptionInformationField VmInterruptField = { UtilVmRead64(VmcsField::kVmEntryIntrInfoField) };
	FlagRegister rflags = { UtilVmRead64(VmcsField::kGuestRflags) };
	Cr0 cr0 = { UtilVmRead(VmcsField::kGuestCr0) };
	
	//Check Rip 
	if (!VmEntryCtrl.fields.ia32e_mode_guest || !CsArBytes.fields.l)
	{
		HYPERPLATFORM_ASSERT(!(UtilVmRead64(VmcsField::kGuestRip) >> 32));
	}

	//Check Rflags	
	
	HYPERPLATFORM_ASSERT(rflags.fields.reserved1);
	HYPERPLATFORM_ASSERT(!rflags.fields.reserved3 && !rflags.fields.reserved2 && !rflags.fields.reserved4 && !rflags.fields.reserved5);

	if (VmEntryCtrl.fields.ia32e_mode_guest || !cr0.fields.pe)
	{
		HYPERPLATFORM_ASSERT(!rflags.fields.vm);
	}

	HYPERPLATFORM_ASSERT(!rflags.fields.reserved3 && !rflags.fields.reserved2 && !rflags.fields.reserved4 && !rflags.fields.reserved5);

	if (VmInterruptField.fields.valid && 
		(VmInterruptField.fields.interruption_type == static_cast<ULONG32>(InterruptionType::kExternalInterrupt)))
	{ 
		HYPERPLATFORM_ASSERT(rflags.fields.intf);
	}
}

//------------------------------------------------------------------------------------------------//
VOID 
VmxVmEntryCheckGuestNonRegstate()

/*++

Desscription:

	Validating VMCS0-2 non-register for vmentry to L2 during emulation of the VMEntry

Paremeters:

	Guest Context

Return Value:

	NO

--*/
{ 
	ActivityState  state = static_cast<ActivityState>(UtilVmRead64(VmcsField::kGuestActivityState));
	VmxSegmentDescriptorAccessRight SsArBytes = { UtilVmRead(VmcsField::kGuestSsArBytes) };
	VmEntryInterruptionInformationField IntrInfo = { UtilVmRead(VmcsField::kVmEntryIntrInfoField) };
	VmxVmEntryControls  VmEntryCtrl = { UtilVmRead64(VmcsField::kVmEntryControls) };
	HYPERPLATFORM_ASSERT(state >= 0 && state <=3);
	
	if (SsArBytes.fields.dpl)
	{
		HYPERPLATFORM_ASSERT(state != HLT);
	}

	if (IntrInfo.fields.valid)
	{
		// TODO : CHECK and disable / pending the interruption
		switch (state)
		{
		case HLT:
			break;
		case ShutDown:
			break;
		case WaitForSipi:
			break;
		case Active: 
		default:
			break; 
		}
	}

	if (VmEntryCtrl.fields.entry_to_smm)
	{
		HYPERPLATFORM_ASSERT(state != WaitForSipi);
	}
}
//------------------------------------------------------------------------------------------------//
VOID 
VmxVmEntryCheckGuestPdptes()
{
	if(VmxIsGuestPaePaging())
	{
	}
}
//------------------------------------------------------------------------------------------------//
VOID VmEntryCheck()
{

	VmxVmEntryCheckGuestReg();
	VmxVmEntryCheckGuestSegReg();
	VmxVmEntryCheckGuestDescTableReg();
	VmxVmEntryCheckGuestRipRflags();
	VmxVmEntryCheckGuestNonRegstate();
}

//------------------------------------------------------------------------------------------------//
NTSTATUS SaveExceptionInformationFromVmcs02(VCPUVMX* vcpu)
/*++

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

--*/
{
	ULONG_PTR vmcs12_va = 0;
	//all nested vm-exit should record 
	if (!vcpu)
	{
		return STATUS_UNSUCCESSFUL;
	}

	if (!vcpu->vmcs12_pa)
	{
		return STATUS_UNSUCCESSFUL;
	}

	vmcs12_va = (ULONG_PTR)UtilVaFromPa(vcpu->vmcs12_pa);

	if (!vmcs12_va)
	{
		return STATUS_UNSUCCESSFUL;
	}
	const VmExitInformation exit_reason = {UtilVmRead(VmcsField::kVmExitReason)};
	
	const VmExitInterruptionInformationField exception = {
		static_cast<ULONG32>(UtilVmRead(VmcsField::kVmExitIntrInfo))
	};

	ULONG_PTR vmexit_qualification = UtilVmRead(VmcsField::kExitQualification);

	VmcsVmWrite32(VmcsField::kVmExitIntrInfo, vmcs12_va, exception.all);
	VmcsVmWrite32(VmcsField::kVmExitReason, vmcs12_va, exit_reason.all);
	VmcsVmWrite32(VmcsField::kExitQualification, vmcs12_va, vmexit_qualification);
	VmcsVmWrite32(VmcsField::kVmExitInstructionLen, vmcs12_va, UtilVmRead(VmcsField::kVmExitInstructionLen));
	VmcsVmWrite32(VmcsField::kVmInstructionError, vmcs12_va, UtilVmRead(VmcsField::kVmInstructionError));
	VmcsVmWrite32(VmcsField::kVmExitIntrErrorCode, vmcs12_va, UtilVmRead(VmcsField::kVmExitIntrErrorCode));
	VmcsVmWrite32(VmcsField::kIdtVectoringInfoField, vmcs12_va, UtilVmRead(VmcsField::kIdtVectoringInfoField));
	VmcsVmWrite32(VmcsField::kIdtVectoringErrorCode, vmcs12_va, UtilVmRead(VmcsField::kIdtVectoringErrorCode));
	VmcsVmWrite32(VmcsField::kVmxInstructionInfo, vmcs12_va, UtilVmRead(VmcsField::kVmxInstructionInfo));

	VmcsVmWrite64(VmcsField::kGuestLinearAddress, vmcs12_va, UtilVmRead(VmcsField::kGuestLinearAddress));
	VmcsVmWrite64(VmcsField::kGuestPhysicalAddress, vmcs12_va, UtilVmRead(VmcsField::kGuestPhysicalAddress));

}
//------------------------------------------------------------------------------------------------//
NTSTATUS SaveGuestFieldFromVmcs02(VCPUVMX* vcpu)	
/*++

Descritpion:

	Call before emulate a VMExit, Read All Guest Field From VMCS0-2,
	And backup into VMCS1-2, the purpose is for emulated VMExit, but
	actually we RESUME the VM to L1, when L1 make any VMREAD/WRITE,
	we return a VMCS1-2 to its.

Parameters:

	Physical Address for VMCS1-2

--*/
{
	ULONG_PTR vmcs12_va = 0;
	//all nested vm-exit should record 
	if(!vcpu)
	{ 
		return STATUS_UNSUCCESSFUL;
	}

	if (!vcpu->vmcs12_pa)
	{
		return STATUS_UNSUCCESSFUL;
	}

	vmcs12_va = (ULONG_PTR)UtilVaFromPa(vcpu->vmcs12_pa);

	if (!vmcs12_va)
	{
		return STATUS_UNSUCCESSFUL;
	}

	VmcsVmWrite64(VmcsField::kGuestRip, vmcs12_va, UtilVmRead(VmcsField::kGuestRip));
	VmcsVmWrite64(VmcsField::kGuestRsp, vmcs12_va, UtilVmRead(VmcsField::kGuestRsp));
	VmcsVmWrite64(VmcsField::kGuestCr3, vmcs12_va, UtilVmRead(VmcsField::kGuestCr3));
	VmcsVmWrite64(VmcsField::kGuestCr0, vmcs12_va, UtilVmRead(VmcsField::kGuestCr0));
	VmcsVmWrite64(VmcsField::kGuestCr4, vmcs12_va, UtilVmRead(VmcsField::kGuestCr4));
	VmcsVmWrite64(VmcsField::kGuestDr7, vmcs12_va, UtilVmRead(VmcsField::kGuestDr7));
	VmcsVmWrite64(VmcsField::kGuestRflags, vmcs12_va, UtilVmRead(VmcsField::kGuestRflags));

	VmcsVmWrite16(VmcsField::kGuestEsSelector, vmcs12_va, UtilVmRead(VmcsField::kGuestEsSelector));
	VmcsVmWrite16(VmcsField::kGuestCsSelector, vmcs12_va, UtilVmRead(VmcsField::kGuestCsSelector));
	VmcsVmWrite16(VmcsField::kGuestSsSelector, vmcs12_va, UtilVmRead(VmcsField::kGuestSsSelector));
	VmcsVmWrite16(VmcsField::kGuestDsSelector, vmcs12_va, UtilVmRead(VmcsField::kGuestDsSelector));
	VmcsVmWrite16(VmcsField::kGuestFsSelector, vmcs12_va, UtilVmRead(VmcsField::kGuestFsSelector));
	VmcsVmWrite16(VmcsField::kGuestGsSelector, vmcs12_va, UtilVmRead(VmcsField::kGuestGsSelector));
	VmcsVmWrite16(VmcsField::kGuestLdtrSelector, vmcs12_va, UtilVmRead(VmcsField::kGuestLdtrSelector));
	VmcsVmWrite16(VmcsField::kGuestTrSelector, vmcs12_va, UtilVmRead(VmcsField::kGuestTrSelector));

	VmcsVmWrite32(VmcsField::kGuestEsLimit, vmcs12_va, UtilVmRead(VmcsField::kGuestEsLimit));
	VmcsVmWrite32(VmcsField::kGuestCsLimit, vmcs12_va, UtilVmRead(VmcsField::kGuestCsLimit));
	VmcsVmWrite32(VmcsField::kGuestSsLimit, vmcs12_va, UtilVmRead(VmcsField::kGuestSsLimit));
	VmcsVmWrite32(VmcsField::kGuestDsLimit, vmcs12_va, UtilVmRead(VmcsField::kGuestDsLimit));
	VmcsVmWrite32(VmcsField::kGuestFsLimit, vmcs12_va, UtilVmRead(VmcsField::kGuestFsLimit));
	VmcsVmWrite32(VmcsField::kGuestGsLimit, vmcs12_va, UtilVmRead(VmcsField::kGuestGsLimit));
	VmcsVmWrite32(VmcsField::kGuestLdtrLimit, vmcs12_va, UtilVmRead(VmcsField::kGuestLdtrLimit));
	VmcsVmWrite32(VmcsField::kGuestTrLimit, vmcs12_va, UtilVmRead(VmcsField::kGuestTrLimit));
	VmcsVmWrite32(VmcsField::kGuestGdtrLimit, vmcs12_va, UtilVmRead(VmcsField::kGuestGdtrLimit));
	VmcsVmWrite32(VmcsField::kGuestIdtrLimit, vmcs12_va, UtilVmRead(VmcsField::kGuestIdtrLimit));

	VmcsVmWrite32(VmcsField::kGuestEsArBytes, vmcs12_va, UtilVmRead(VmcsField::kGuestEsArBytes));
	VmcsVmWrite32(VmcsField::kGuestCsArBytes, vmcs12_va, UtilVmRead(VmcsField::kGuestCsArBytes));
	VmcsVmWrite32(VmcsField::kGuestSsArBytes, vmcs12_va, UtilVmRead(VmcsField::kGuestSsArBytes));
	VmcsVmWrite32(VmcsField::kGuestDsArBytes, vmcs12_va, UtilVmRead(VmcsField::kGuestDsArBytes));
	VmcsVmWrite32(VmcsField::kGuestFsArBytes, vmcs12_va, UtilVmRead(VmcsField::kGuestFsArBytes));
	VmcsVmWrite32(VmcsField::kGuestGsArBytes, vmcs12_va, UtilVmRead(VmcsField::kGuestGsArBytes));
	VmcsVmWrite32(VmcsField::kGuestLdtrArBytes, vmcs12_va, UtilVmRead(VmcsField::kGuestLdtrArBytes));

	VmcsVmWrite32(VmcsField::kGuestTrArBytes, vmcs12_va, UtilVmRead(VmcsField::kGuestTrArBytes));

	VmcsVmWrite32(VmcsField::kGuestInterruptibilityInfo, vmcs12_va, UtilVmRead(VmcsField::kGuestInterruptibilityInfo));
	VmcsVmWrite32(VmcsField::kGuestActivityState, vmcs12_va, UtilVmRead(VmcsField::kGuestActivityState));
	VmcsVmWrite32(VmcsField::kGuestSysenterCs, vmcs12_va, UtilVmRead(VmcsField::kGuestSysenterCs));

	VmcsVmWrite64(VmcsField::kGuestSysenterEsp, vmcs12_va, UtilVmRead(VmcsField::kGuestSysenterEsp));
	VmcsVmWrite64(VmcsField::kGuestSysenterEip, vmcs12_va, UtilVmRead(VmcsField::kGuestSysenterEip));
	VmcsVmWrite64(VmcsField::kGuestPendingDbgExceptions, vmcs12_va, UtilVmRead(VmcsField::kGuestPendingDbgExceptions));
	VmcsVmWrite64(VmcsField::kGuestEsBase, vmcs12_va, UtilVmRead(VmcsField::kGuestEsBase));
	VmcsVmWrite64(VmcsField::kGuestCsBase, vmcs12_va, UtilVmRead(VmcsField::kGuestCsBase));
	VmcsVmWrite64(VmcsField::kGuestSsBase, vmcs12_va, UtilVmRead(VmcsField::kGuestSsBase));
	VmcsVmWrite64(VmcsField::kGuestDsBase, vmcs12_va, UtilVmRead(VmcsField::kGuestDsBase));
	VmcsVmWrite64(VmcsField::kGuestFsBase, vmcs12_va, UtilVmRead(VmcsField::kGuestFsBase));
	VmcsVmWrite64(VmcsField::kGuestGsBase, vmcs12_va, UtilVmRead(VmcsField::kGuestGsBase));
	VmcsVmWrite64(VmcsField::kGuestLdtrBase, vmcs12_va, UtilVmRead(VmcsField::kGuestLdtrBase));
	VmcsVmWrite64(VmcsField::kGuestTrBase, vmcs12_va, UtilVmRead(VmcsField::kGuestTrBase));
	VmcsVmWrite64(VmcsField::kGuestGdtrBase, vmcs12_va, UtilVmRead(VmcsField::kGuestGdtrBase));
	VmcsVmWrite64(VmcsField::kGuestIdtrBase, vmcs12_va, UtilVmRead(VmcsField::kGuestIdtrBase));
	
	VmcsVmWrite64(VmcsField::kGuestIa32Efer, vmcs12_va, UtilVmRead(VmcsField::kGuestIa32Efer));

	/*
	VmcsVmWrite64(VmcsField::kGuestPdptr0, vmcs12_va, UtilVmRead(VmcsField::kGuestPdptr0));
	VmcsVmWrite64(VmcsField::kGuestPdptr1, vmcs12_va, UtilVmRead(VmcsField::kGuestPdptr1));
	VmcsVmWrite64(VmcsField::kGuestPdptr2, vmcs12_va, UtilVmRead(VmcsField::kGuestPdptr2));
	VmcsVmWrite64(VmcsField::kGuestPdptr3, vmcs12_va, UtilVmRead(VmcsField::kGuestPdptr3));
	*/
}

//------------------------------------------------------------------------------------------------//
NTSTATUS LoadHostStateForLevel1(
	_In_ VCPUVMX* vcpu
)
/*++

Descritpion:

	Load VMCS1-2 into VMCS0-1

Parameters:

	VCPUVMX

--*/
{ 
	ULONG_PTR Vmcs01_pa = 0;
	ULONG_PTR Vmcs12_va = 0;

	if (!vcpu || !vcpu->vmcs01_pa || !vcpu->vmcs12_pa)
	{
		HYPERPLATFORM_COMMON_DBG_BREAK();
		return STATUS_UNSUCCESSFUL;
	}

	Vmcs01_pa = vcpu->vmcs01_pa;
	Vmcs12_va = (ULONG_PTR)UtilVaFromPa(vcpu->vmcs12_pa);

	if (!Vmcs01_pa || !Vmcs12_va)
	{
		HYPERPLATFORM_COMMON_DBG_BREAK();
		return STATUS_UNSUCCESSFUL;
	}


	VmxStatus status;

	// Host Data Field  
	ULONG64   VMCS12_HOST_RIP = 0;
	ULONG64   VMCS12_HOST_STACK = 0;
	ULONG_PTR VMCS12_HOST_RFLAGs = 0;
	ULONG64   VMCS12_HOST_CR4 = 0;
	ULONG64   VMCS12_HOST_CR3 = 0;
	ULONG64   VMCS12_HOST_CR0 = 0;
	
	ULONG64   VMCS12_HOST_CS = 0;
	ULONG64   VMCS12_HOST_SS = 0;
	ULONG64   VMCS12_HOST_DS = 0;
	ULONG64   VMCS12_HOST_ES = 0;
	ULONG64   VMCS12_HOST_FS = 0;
	ULONG64   VMCS12_HOST_GS = 0;
	ULONG64   VMCS12_HOST_TR = 0;

	ULONG32   VMCS12_HOST_SYSENTER_CS = 0;
	ULONG64   VMCS12_HOST_SYSENTER_RIP = 0;
	ULONG64   VMCS12_HOST_SYSENTER_RSP = 0;

	ULONG64   VMCS12_HOST_FS_BASE = 0;
	ULONG64   VMCS12_HOST_GS_BASE = 0;
	ULONG64   VMCS12_HOST_TR_BASE = 0;

	if (VmxStatus::kOk != (status = static_cast<VmxStatus>(__vmx_vmptrld(&Vmcs01_pa))))
	{
		VmxInstructionError error = static_cast<VmxInstructionError>(UtilVmRead(VmcsField::kVmInstructionError));
		HYPERPLATFORM_LOG_DEBUG_SAFE("Error vmptrld error code :%x , %x", status, error);
	}
 
	VmcsVmRead64(VmcsField::kHostRip, Vmcs12_va, &VMCS12_HOST_RIP);
	VmcsVmRead64(VmcsField::kHostRsp, Vmcs12_va, &VMCS12_HOST_STACK);
	VmcsVmRead64(VmcsField::kHostCr0, Vmcs12_va, &VMCS12_HOST_CR0);
	VmcsVmRead64(VmcsField::kHostCr3, Vmcs12_va, &VMCS12_HOST_CR3);
	VmcsVmRead64(VmcsField::kHostCr4, Vmcs12_va, &VMCS12_HOST_CR4);
	 
	VmcsVmRead64(VmcsField::kHostCsSelector, Vmcs12_va, &VMCS12_HOST_CS);
	VmcsVmRead64(VmcsField::kHostSsSelector, Vmcs12_va, &VMCS12_HOST_SS);
	VmcsVmRead64(VmcsField::kHostDsSelector, Vmcs12_va, &VMCS12_HOST_DS);
	VmcsVmRead64(VmcsField::kHostEsSelector, Vmcs12_va, &VMCS12_HOST_ES);
	VmcsVmRead64(VmcsField::kHostFsSelector, Vmcs12_va, &VMCS12_HOST_FS);
	VmcsVmRead64(VmcsField::kHostGsSelector, Vmcs12_va, &VMCS12_HOST_GS);
	VmcsVmRead64(VmcsField::kHostTrSelector, Vmcs12_va, &VMCS12_HOST_TR);
	 
	VmcsVmRead32(VmcsField::kHostIa32SysenterCs, Vmcs12_va, &VMCS12_HOST_SYSENTER_CS);
	VmcsVmRead64(VmcsField::kHostIa32SysenterEip, Vmcs12_va, &VMCS12_HOST_SYSENTER_RSP);
	VmcsVmRead64(VmcsField::kHostIa32SysenterEsp, Vmcs12_va, &VMCS12_HOST_SYSENTER_RIP);


	VmcsVmRead64(VmcsField::kHostFsBase, Vmcs12_va, &VMCS12_HOST_FS_BASE);
	VmcsVmRead64(VmcsField::kHostGsBase, Vmcs12_va, &VMCS12_HOST_GS_BASE);
	VmcsVmRead64(VmcsField::kHostTrBase, Vmcs12_va, &VMCS12_HOST_TR_BASE);

	//Disable Interrupt Flags
	FlagRegister rflags = { VMCS12_HOST_RFLAGs };
	rflags.fields.reserved1 = 1;
	UtilVmWrite(VmcsField::kGuestRflags, rflags.all);

	UtilVmWrite(VmcsField::kGuestRip, VMCS12_HOST_RIP);
	UtilVmWrite(VmcsField::kGuestRsp, VMCS12_HOST_STACK);
	UtilVmWrite(VmcsField::kGuestCr0, VMCS12_HOST_CR0);
	UtilVmWrite(VmcsField::kGuestCr3, VMCS12_HOST_CR3);
	UtilVmWrite(VmcsField::kGuestCr4, VMCS12_HOST_CR4);
	UtilVmWrite(VmcsField::kGuestDr7, 0x400);

	UtilVmWrite(VmcsField::kGuestCsSelector, VMCS12_HOST_CS);
	UtilVmWrite(VmcsField::kGuestSsSelector, VMCS12_HOST_SS);
	UtilVmWrite(VmcsField::kGuestDsSelector, VMCS12_HOST_DS);
	UtilVmWrite(VmcsField::kGuestEsSelector, VMCS12_HOST_ES);
	UtilVmWrite(VmcsField::kGuestFsSelector, VMCS12_HOST_FS);
	UtilVmWrite(VmcsField::kGuestGsSelector, VMCS12_HOST_GS);
	UtilVmWrite(VmcsField::kGuestTrSelector, VMCS12_HOST_TR);

	UtilVmWrite(VmcsField::kGuestSysenterCs,  VMCS12_HOST_SYSENTER_CS);
	UtilVmWrite(VmcsField::kGuestSysenterEsp, VMCS12_HOST_SYSENTER_RSP);
	UtilVmWrite(VmcsField::kGuestSysenterEip, VMCS12_HOST_SYSENTER_RIP);

	// Sync L1's Host segment base with L0 VMM Host Host segment base
	UtilVmWrite(VmcsField::kGuestCsBase, 0);
	UtilVmWrite(VmcsField::kGuestSsBase, 0);
	UtilVmWrite(VmcsField::kGuestDsBase, 0);
	UtilVmWrite(VmcsField::kGuestEsBase, 0);
	UtilVmWrite(VmcsField::kGuestFsBase, VMCS12_HOST_FS_BASE);
	UtilVmWrite(VmcsField::kGuestGsBase, VMCS12_HOST_GS_BASE);
	UtilVmWrite(VmcsField::kGuestTrBase, VMCS12_HOST_TR_BASE);
	  
	// Sync L1's Host Host segment Limit with L0 Host Host segment Limit
	UtilVmWrite(VmcsField::kGuestEsLimit, GetSegmentLimit(AsmReadES()));
	UtilVmWrite(VmcsField::kGuestCsLimit, GetSegmentLimit(AsmReadCS()));
	UtilVmWrite(VmcsField::kGuestSsLimit, GetSegmentLimit(AsmReadSS()));
	UtilVmWrite(VmcsField::kGuestDsLimit, GetSegmentLimit(AsmReadDS()));
	UtilVmWrite(VmcsField::kGuestFsLimit, GetSegmentLimit(AsmReadFS()));
	UtilVmWrite(VmcsField::kGuestGsLimit, GetSegmentLimit(AsmReadGS()));
	UtilVmWrite(VmcsField::kGuestLdtrLimit, GetSegmentLimit(AsmReadLDTR()));
	UtilVmWrite(VmcsField::kGuestTrLimit, GetSegmentLimit(AsmReadTR())); 

	// Sync L1's Host segment ArBytes with L0  Host segment ArBytes 
	UtilVmWrite(VmcsField::kGuestEsArBytes,	  VmpGetSegmentAccessRight(AsmReadES()));
	UtilVmWrite(VmcsField::kGuestCsArBytes,	  VmpGetSegmentAccessRight(AsmReadCS()));
	UtilVmWrite(VmcsField::kGuestSsArBytes,	  VmpGetSegmentAccessRight(AsmReadSS()));
	UtilVmWrite(VmcsField::kGuestDsArBytes,	  VmpGetSegmentAccessRight(AsmReadDS()));
	UtilVmWrite(VmcsField::kGuestFsArBytes,	  VmpGetSegmentAccessRight(AsmReadFS()));
	UtilVmWrite(VmcsField::kGuestGsArBytes,	  VmpGetSegmentAccessRight(AsmReadGS()));
	UtilVmWrite(VmcsField::kGuestLdtrArBytes, VmpGetSegmentAccessRight(AsmReadLDTR()));
	UtilVmWrite(VmcsField::kGuestTrArBytes,	  VmpGetSegmentAccessRight(AsmReadTR()) | LONG_MODE_BUSY_TSS);

	UtilVmWrite(VmcsField::kGuestIa32Debugctl, 0);
	  
	//Clean VMCS1-2 Injecting event since it shouldn't be injected 
	VmcsVmWrite32(VmcsField::kVmEntryIntrInfoField, Vmcs12_va, 0);
	VmcsVmWrite32(VmcsField::kVmEntryExceptionErrorCode, Vmcs12_va, 0); 
	UtilVmWrite(VmcsField::kVmEntryIntrInfoField, 0);
	UtilVmWrite(VmcsField::kVmEntryExceptionErrorCode, 0);

	return STATUS_SUCCESS;
}


 
//------------------------------------------------------------------------------------------------//
NTSTATUS 
VmxVMExitEmulate(
	_In_ VCPUVMX* vCPU,
	_In_ GuestContext* guest_context
)
/*++

Description:

		Emulating the VMExit behavior from L2 to L1

		We need to emulate the exception if and only if the vCPU mode is Guest Mode ,
		and only the exception is somethings we want to redirect to L1 VMM to handle it.
	
		VCPU Mode as follow:
		
		Root Mode:
			- if the Guest's vCPU is root mode , that means he dun expected the action will be trap.
			so that action should not give its VMExit handler, otherwise.
		
		Guest Mode:
			- If the Guest's vCPU is in guest mode, that means he expected the action will be trapped
			And handle by its VMExit handler
		
		After this function, VCPU mode should be changed to ROOT Mode , since every other step should be 
		worded as root mode , and We turn it back to Guest whenever L1's VMM want to do this through 
		VMlaunch or VMResume instruction.
	
		We desginated the L1 wants to handle any breakpoint exception but the others.
		So that we only nested it for testing purpose.


Parameters:
		
		vCPU - corresponding structure to current Virtual processor

		guest_context - guest context

Return Value:
		
		If the vmexit's context passed, return STATUS_SUCEESS. Otherwise, return STATUS_UNSUCCESSFUL
--*/
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	do
	{
		if (!vCPU)
		{
			break;
		}

		// Since VMXON, but VMPTRLD 
		if (!vCPU->vmcs02_pa || !vCPU->vmcs12_pa || vCPU->vmcs12_pa == ~0x0 || vCPU->vmcs02_pa == ~0x0)
		{
			//HYPERPLATFORM_LOG_DEBUG_SAFE("cannot find vmcs \r\n");
			break;
		}

		LEAVE_GUEST_MODE(vCPU);
		SaveGuestKernelGsBase(VmmpGetProcessorData(guest_context));
		LoadHostKernelGsBase(VmmpGetProcessorData(guest_context));

		SaveGuestFieldFromVmcs02(vCPU);
		SaveExceptionInformationFromVmcs02(vCPU);
		SaveGuestCr8(vCPU, VmmpGetGuestCr8(guest_context));
		LoadHostStateForLevel1(vCPU);

		status = STATUS_SUCCESS;
	} while (FALSE);
	return status;
} 
//--------------------------------------------------------------------------------------//
NTSTATUS 
VMEntryEmulate(
	_In_ VCPUVMX* vCPU, 
	_In_ GuestContext* guest_context , 
	_In_ BOOLEAN IsVmLaunch
)
/*++

Description:
		
		Emulating VMEntry behavior from L1 to L2.

		After L1 handles any VM Exit and should be executes VMRESUME for back L2
		But this time trapped by VMCS01 and We can't get any VM-Exit information
        from it. So we need to read from VMCS12 and return from here immediately.
		We saved the vmcs02 GuestRip into VMCS12 our VMExit Handler because when
		L1 was executing VMRESUME(We injected VMExit to it), and it is running on
		VMCS01, we can't and shouldn't change it.

		See: VmmVmExitHandler

		N.B. if the VMEntry is not passed, the control transfer to debugger or BSOD. 

Parameters:
		
		vCPU - corresponding structure to current Virtual processor

		guest_context - guest context

		IsVmLaunch - Indicate the Virtual-VMentry either come from VMLAUNCH or VMRESUME 

Return Value:
		
		If the vmentry's context passed, return STATUS_SUCEESS. Otherwise, return STATUS_UNSUCCESSFUL

--*/
{
	ULONG_PTR    vmcs02_va = 0;
	ULONG_PTR    vmcs12_va = 0;
	Ia32VmxBasicMsr vmx_basic_msr = { 0 };
	VmControlStructure* vmcs02_ptr = NULL;

	if (!vCPU)
	{
		return STATUS_UNSUCCESSFUL;
	}

	// Since VMXON, but VMPTRLD 
	if (!vCPU->vmcs02_pa || !vCPU->vmcs12_pa || vCPU->vmcs12_pa == ~0x0 || vCPU->vmcs02_pa == ~0x0)
	{
		//HYPERPLATFORM_LOG_DEBUG_SAFE("cannot find vmcs \r\n");
		return STATUS_UNSUCCESSFUL;
	}
	 
	vmcs02_va = (ULONG_PTR)UtilVaFromPa(vCPU->vmcs02_pa);
	vmcs12_va = (ULONG_PTR)UtilVaFromPa(vCPU->vmcs12_pa);

	if (!vmcs02_va || !vmcs12_va)
	{
		return STATUS_UNSUCCESSFUL;
	}

	ENTER_GUEST_MODE(vCPU);

	// Write a VMCS revision identifier
	vmx_basic_msr = { UtilReadMsr64(Msr::kIa32VmxBasic) };
	vmcs02_ptr = (VmControlStructure*)vmcs02_va;
	vmcs02_ptr->revision_identifier = vmx_basic_msr.fields.revision_identifier;
	 
	//Prepare VMCS01 Host / Control Field
	VmcsPrepareHostAndControlField(vmcs12_va,  vCPU->vmcs02_pa, IsVmLaunch);

	VmcsPrepareGuestStateField(vmcs12_va); 
	 
	SaveHostKernelGsBase(VmmpGetProcessorData(guest_context));

	VmEntryCheck();

	if (IsVmLaunch)
	{
		VmxStatus status;
#ifdef __NEST_EPT_ENBLE 
		VmxSecondaryProcessorBasedControls ProcCtrl = { UtilVmRead64(VmcsField::kSecondaryVmExecControl) };
	 	if (ProcCtrl.fields.enable_ept)
		{
			EptData*	Ept02Data=nullptr;
			EptData*	Ept12Data=nullptr;	//1. Determine if Nested EPT Enabled.
			EptData*	Ept01Data=nullptr;	//2. Build-EPT0-2  

			ULONG64 _Ept12Ptr = NULL;
			VmcsVmRead64(VmcsField::kEptPointer, vmcs12_va, &_Ept12Ptr); 
			Ept02Data = EptBuildEptDataByEptp(); 
			Ept12Data = EptBuildEptDataByEptp();
			Ept01Data = VmmGetCurrentEpt01Pointer(guest_context);
			if (Ept02Data && Ept12Data && Ept01Data)
			{
				EptpBuildNestedEpt(_Ept12Ptr, Ept12Data, Ept02Data);
				
				VmmSaveCurrentEpt02Pointer(guest_context, Ept02Data);
				VmmSaveCurrentEpt12Pointer(guest_context, Ept12Data);

				EptpInvalidateEpt(Ept12Data, Ept01Data);

				UtilVmWrite64(VmcsField::kEptPointer, Ept02Data->ept_pointer->all);
				UtilInveptGlobal();
			}
		}
#endif
		// We must be careful of this, since we jmp back to the Guest soon. 
		// It is a exceptional case  
		if (VmmpGetGuestIrql(guest_context) < DISPATCH_LEVEL)
		{
			KeLowerIrql(VmmpGetGuestIrql(guest_context));
		}

		if (VmxStatus::kOk != (status = static_cast<VmxStatus>(__vmx_vmlaunch())))
		{
			VmxInstructionError error2 = static_cast<VmxInstructionError>(UtilVmRead(VmcsField::kVmInstructionError));
			HYPERPLATFORM_LOG_DEBUG_SAFE("Error VMLAUNCH error code :%x , %x ", status, error2);
			HYPERPLATFORM_COMMON_DBG_BREAK();
		}
	}
	else
	{
#ifdef __NEST_EPT_ENBLE
		VmxSecondaryProcessorBasedControls ProcCtrl = { UtilVmRead64(VmcsField::kSecondaryVmExecControl) };
		if (ProcCtrl.fields.enable_ept)
		{
			EptData* ept_data02 = VmmGetCurrentEpt02Pointer(guest_context);
			if (ept_data02)
			{
				UtilVmWrite64(VmcsField::kEptPointer, ept_data02->ept_pointer->all);
			}
		}
#endif
		RestoreGuestCr8(vCPU);
		LoadGuestKernelGsBase(VmmpGetProcessorData(guest_context));
	}

	return STATUS_SUCCESS;
}

 
//------------------------------------------------------------------------------------------------//
VOID VmxVmxonEmulate(
	_In_ GuestContext* guest_context
)
/*++
Desscription:

	Emulating Vmxon instruction, Allocating the data structure of Virtual Processors, 
	and initial the virtual prcoessors as VMX-root mode.

Paremeters:

	Guest Context

Return Value:

	NO

--*/
{
	do
	{
		VCPUVMX*					  nested_vmx    = NULL;
		ULONG64				  InstructionPointer	= 0;	 
		ULONG64				  StackPointer			= 0;	 
		ULONG64				  vmxon_region_pa		= 0;	 
		ULONG64				  guest_address			= NULL;
		VmControlStructure*   vmxon_region_struct	= NULL;  
		PROCESSOR_NUMBER      number = { 0 };

		InstructionPointer  =  { UtilVmRead64(VmcsField::kGuestRip) };
		StackPointer		=  { UtilVmRead64(VmcsField::kGuestRsp) };   
		guest_address		= DecodeVmclearOrVmptrldOrVmptrstOrVmxon(guest_context);
		  
		if (VmmpGetvCpuMode(guest_context) == VmxMode)
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("Current vCPU already in VMX mode !"));
			VMfailInvalid(VmmpGetFlagReg(guest_context));
			break;
		} 

		if (!guest_address || !UtilpIsCanonicalFormAddress((void*)guest_address))
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMXON: guest_address Parameter is NULL !"));
			//#UD
			ThrowInvalidCodeException();
			break;
		}
 
		vmxon_region_pa = *(PULONG64)guest_address;
		// VMXON_REGION IS NULL 
		if (!vmxon_region_pa)
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMXON: vmxon_region_pa Parameter is NULL !"));
			//#UD
			ThrowInvalidCodeException();
			break;
		}

		//if is it not page aglined
		if (!CheckPageAlgined(vmxon_region_pa))
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMXON: not page aligned physical address %I64X !"), vmxon_region_pa);
			VMfailInvalid(VmmpGetFlagReg(guest_context));
			break;
		}
		//if IA32_VMX_BASIC[48] == 1 it is not support 64bit addressing, so address[32] to address[63] supposed = 0
		if (!CheckPhysicalAddress(vmxon_region_pa))
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMXON: invalid physical address %I64X !"), vmxon_region_pa);
			VMfailInvalid(VmmpGetFlagReg(guest_context));
			break;
		}
		 
		// todo: check vcpu context ...'

		nested_vmx = (VCPUVMX*)ExAllocatePool(NonPagedPoolNx, sizeof(VCPUVMX));

		nested_vmx->inRoot = RootMode;
		nested_vmx->blockINITsignal = TRUE;
		nested_vmx->blockAndDisableA20M = TRUE;
		nested_vmx->vmcs02_pa = 0xFFFFFFFFFFFFFFFF;
		nested_vmx->vmcs12_pa = 0xFFFFFFFFFFFFFFFF;
		__vmx_vmptrst(&nested_vmx->vmcs01_pa);
		nested_vmx->vmxon_region = vmxon_region_pa;
		nested_vmx->InitialCpuNumber = KeGetCurrentProcessorNumberEx(&number);

		// vcpu etner vmx-root mode now
		VmmpEnterVmxMode(guest_context);  
		VmmpSetvCpuVmx(guest_context, nested_vmx);

		HYPERPLATFORM_LOG_DEBUG("VMXON: Guest Instruction Pointer %I64X Guest Stack Pointer: %I64X  Guest VMXON_Region: %I64X stored at %I64x physical address\r\n",
			InstructionPointer, StackPointer, vmxon_region_pa, guest_address);

		HYPERPLATFORM_LOG_DEBUG("VMXON: Run Successfully with VMXON_Region:  %I64X Total Vitrualized Core: %x  Current Cpu: %x in Cpu Group : %x  Number: %x \r\n",
			vmxon_region_pa, nested_vmx->InitialCpuNumber, number.Group, number.Number);
		  
		BuildGernericVMCSMap();

		VMSucceed(VmmpGetFlagReg(guest_context));

	} while (FALSE);


}
//------------------------------------------------------------------------------------------------//
VOID 
VmxVmxoffEmulate(
	_In_ GuestContext* guest_context
)
/*++
Desscription:

	Emulating Vmxoff instruction , releasing the data structure of Virtual Processors, 
	and initial the virtual prcoessors as VMX-root mode.

Paremeters:

	Guest Context

Return Value:

	NO

--*/
{
	do
	{
		VCPUVMX* vcpu_vmx = NULL; 

		HYPERPLATFORM_COMMON_DBG_BREAK();
		if (VmmpGetvCpuMode(guest_context) != VmxMode)
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("Current vCPU already in VMX mode ! \r\n"));
			VMfailInvalid(VmmpGetFlagReg(guest_context));
			break;
		}

		vcpu_vmx = VmmpGetVcpuVmx(guest_context);
		if (!vcpu_vmx)
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("Don't have Nested vCPU ! \r\n"));
			VMfailInvalid(VmmpGetFlagReg(guest_context));
			HYPERPLATFORM_COMMON_DBG_BREAK();
			break;
		}

		// if VCPU not run in VMX mode 
		if (VmxGetVmxMode(VmmpGetVcpuVmx(guest_context)) != RootMode)
		{
			// Inject ...'
			HYPERPLATFORM_LOG_DEBUG_SAFE(("Vmxoff: Unimplemented third level virualization \r\n"));
			VMfailInvalid(VmmpGetFlagReg(guest_context));
			break;
		}
		
		ULONG GuestRip = UtilVmRead(VmcsField::kGuestRip);
		ULONG InstLen  = UtilVmRead(VmcsField::kVmExitInstructionLen);
		//load back vmcs01
		__vmx_vmptrld(&vcpu_vmx->vmcs01_pa); 
	 
		EptData* ept_data01 = VmmGetCurrentEpt01Pointer(guest_context);
		EptData* ept_data12 = VmmGetCurrentEpt12Pointer(guest_context);  

		if (ept_data01 && ept_data12)
		{
			EptpValidateEpt(ept_data12, ept_data01);
			ExFreePool(ept_data12); 
			ept_data12 = nullptr;
		} 

		VmmSaveCurrentEpt02Pointer(guest_context, nullptr);
		VmmSaveCurrentEpt12Pointer(guest_context, nullptr);

		UtilVmWrite(VmcsField::kGuestRip, GuestRip + InstLen);
	
		VmmpSetvCpuVmx(guest_context, NULL);

		VmmpLeaveVmxMode(guest_context);

		ExFreePool(vcpu_vmx);
		vcpu_vmx = NULL;  

		HYPERPLATFORM_LOG_DEBUG("VMXOFF Stopped Nested Virtualization, and Back to Normal Guest OS ");
		VMSucceed(VmmpGetFlagReg(guest_context));
	} while (0);
}
//------------------------------------------------------------------------------------------------//
VOID 
VmxVmclearEmulate(
	_In_ GuestContext* guest_context
)
/*++
Desscription:

	Emulating VMClear instruction, We basically clear the VMCS0-2 which is transparent
	to the L1's VMM, because we need to load this VMCS into the real processors. So we 
	need to make an effect on them.

Paremeters:

	Guest Context

Return Value:

	NO

--*/
{
	do
	{ 
		//*(PULONG64)(StackPointer + offset);				
		//May need to be fixed later 
		VCPUVMX*				nested_vmx = NULL;
		ULONG64			InstructionPointer = 0;
		ULONG64				  StackPointer = 0;
		ULONG64				vmcs_region_pa = 0;
		ULONG64				 guest_address = NULL;  
		PROCESSOR_NUMBER		procnumber = { 0 };

		InstructionPointer = { UtilVmRead64(VmcsField::kGuestRip) };
		StackPointer = { UtilVmRead64(VmcsField::kGuestRsp) };
		guest_address = DecodeVmclearOrVmptrldOrVmptrstOrVmxon(guest_context);
		if (!guest_address || !UtilpIsCanonicalFormAddress((void*)guest_address))
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMCLEAR: guest_address NULL ! \r\n"));
			VMfailInvalid(VmmpGetFlagReg(guest_context));
			break;
		}
		 
		vmcs_region_pa = *(PULONG64)guest_address; 	 
		if (!vmcs_region_pa)
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMCLEAR: vmcs_region_pa NULL ! \r\n"));
			ThrowInvalidCodeException();
			break;
		} 
		 
		if (VmmpGetvCpuMode(guest_context) != VmxMode)
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMCLEAR: Current vCPU already in VMX mode ! \r\n"));
			VMfailInvalid(VmmpGetFlagReg(guest_context));
			break;
		}
		 
		if (VmxGetVmxMode(VmmpGetVcpuVmx(guest_context)) != RootMode)
		{
			// Inject ...'
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMCLEAR : Unimplemented third level virualization \r\n"));
			VMfailInvalid(VmmpGetFlagReg(guest_context));
			break;
		}

		nested_vmx = VmmpGetVcpuVmx(guest_context);
		if (!nested_vmx)
		{
			DumpVcpu(guest_context);
			HYPERPLATFORM_COMMON_DBG_BREAK();
			break;
		}
 
		//if is it not page aglined
		if (!CheckPageAlgined(vmcs_region_pa))
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMXCLEAR: not page aligned physical address %I64X ! \r\n"),
				vmcs_region_pa);

			VMfailInvalid(VmmpGetFlagReg(guest_context));
			break;
		}

		//if IA32_VMX_BASIC[48] == 1 it is not support 64bit addressing, so address[32] to address[63] supposed = 0
		if (!CheckPhysicalAddress(vmcs_region_pa))
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMXCLEAR: invalid physical address %I64X ! \r\n"),
				vmcs_region_pa);

			VMfailInvalid(VmmpGetFlagReg(guest_context));
			break;
		}
		//if vmcs != vmregion 
		if (nested_vmx && (vmcs_region_pa == nested_vmx->vmxon_region))
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMXCLEAR: VMCS region %I64X same as VMXON region %I64X ! \r\n"),
				vmcs_region_pa, nested_vmx->vmxon_region);

			VMfailInvalid(VmmpGetFlagReg(guest_context));
			break;
		}
	
		if (vmcs_region_pa == nested_vmx->vmcs12_pa)
		{
			nested_vmx->vmcs12_pa = 0xFFFFFFFFFFFFFFFF;
		}

		__vmx_vmclear(&nested_vmx->vmcs02_pa);
		nested_vmx->vmcs02_pa = 0xFFFFFFFFFFFFFFFF;

		HYPERPLATFORM_LOG_DEBUG_SAFE("VMCLEAR: Guest Instruction Pointer %I64X Guest Stack Pointer: %I64X  Guest vmcs region: %I64X stored at %I64x on stack\r\n",
			InstructionPointer, StackPointer, vmcs_region_pa, guest_address);

		HYPERPLATFORM_LOG_DEBUG_SAFE("VMCLEAR: Run Successfully Current Cpu: %x in Cpu Group : %x  Number: %x \r\n",
			nested_vmx->InitialCpuNumber, procnumber.Group, procnumber.Number);

		HYPERPLATFORM_LOG_DEBUG_SAFE("VMCLEAR: VCPU No.: %i Current VMCS : %I64X VMXON Region : %I64X  ",
			nested_vmx->InitialCpuNumber, nested_vmx->vmcs02_pa, nested_vmx->vmxon_region);

		VMSucceed(VmmpGetFlagReg(guest_context));

	} while (FALSE);
}

//------------------------------------------------------------------------------------------------//
VOID
VmxVmptrldEmulate(
	_In_	GuestContext* guest_context
)
/*++
Desscription:

	Emulating VMPTRLD instruction , We basically initial the corresponding EPT 
	to the virtual processor with VMCS1-2 

Paremeters:

	Guest Context

Return Value:

	NO

--*/
{
	do
	{
		VCPUVMX*				nested_vmx = NULL;
		ULONG64			InstructionPointer = 0;
		ULONG64				  StackPointer = 0;
		PUCHAR			   vmcs02_region_va = NULL;
		ULONG64			   vmcs02_region_pa = NULL; 
		ULONG64				vmcs12_region_pa = 0;
		ULONG64				 guest_address = NULL;
		PROCESSOR_NUMBER		procnumber = { 0 };

		InstructionPointer = { UtilVmRead64(VmcsField::kGuestRip) };
		StackPointer = { UtilVmRead64(VmcsField::kGuestRsp) };

		guest_address = DecodeVmclearOrVmptrldOrVmptrstOrVmxon(guest_context);
		if (!guest_address || !UtilpIsCanonicalFormAddress((void*)guest_address))
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMCLEAR: guest_address NULL ! \r\n"));
			VMfailInvalid(VmmpGetFlagReg(guest_context));
			break;
		}

		vmcs12_region_pa = *(PULONG64)guest_address;
		if (!vmcs12_region_pa)
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMCLEAR: vmcs_region_pa NULL ! \r\n"));
			VMfailInvalid(VmmpGetFlagReg(guest_context));
			break;
		}

		if (VmmpGetvCpuMode(guest_context) != VmxMode)
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("Current vCPU already in VMX mode ! \r\n"));
			VMfailInvalid(VmmpGetFlagReg(guest_context));
			break;
		}
 
		// if VCPU not run in VMX mode 
		if (VmxGetVmxMode(VmmpGetVcpuVmx(guest_context)) != RootMode)
		{
			// Inject ...'
			HYPERPLATFORM_LOG_DEBUG_SAFE("VMPTRLD Unimplemented third level virualization %I64x \r\n", VmmpGetVcpuVmx(guest_context));
			VMfailInvalid(VmmpGetFlagReg(guest_context)); 
			break;
		}
		
		//if is it not page aglined
		if (!CheckPageAlgined(vmcs12_region_pa))
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMPTRLD: not page aligned physical address %I64X ! \r\n"),
				vmcs12_region_pa);

			VMfailInvalid(VmmpGetFlagReg(guest_context));
			break;
		}

		//if IA32_VMX_BASIC[48] == 1 it is not support 64bit addressing, so address[32] to address[63] supposed = 0
		if (!CheckPhysicalAddress(vmcs12_region_pa))
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMPTRLD: invalid physical address %I64X ! \r\n"),
				vmcs12_region_pa);

			VMfailInvalid(VmmpGetFlagReg(guest_context));
			break;
		}

		nested_vmx = VmmpGetVcpuVmx(guest_context);
		if (nested_vmx && (vmcs12_region_pa == nested_vmx->vmxon_region))
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMPTRLD: VMCS region %I64X same as VMXON region %I64X ! \r\n"),
				vmcs12_region_pa, nested_vmx->vmxon_region);

			VMfailInvalid(VmmpGetFlagReg(guest_context));
			break;
		}
 
		vmcs02_region_va = (PUCHAR)ExAllocatePool(NonPagedPoolNx, PAGE_SIZE); 
		if (!vmcs02_region_va)
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMPTRLD: vmcs02_region_va NULL ! \r\n"),
				vmcs12_region_pa, nested_vmx->vmxon_region);

			VMfailInvalid(VmmpGetFlagReg(guest_context));
			break;
		}

		RtlZeroMemory(vmcs02_region_va, PAGE_SIZE); 

		vmcs02_region_pa = UtilPaFromVa(vmcs02_region_va); 
		nested_vmx->vmcs02_pa = vmcs02_region_pa;		    //vmcs02' physical address - DIRECT VMREAD/WRITE
		nested_vmx->vmcs12_pa = vmcs12_region_pa;		    //vmcs12' physical address - we will control its structure in Vmread/Vmwrite
		nested_vmx->kVirtualProcessorId = (USHORT)KeGetCurrentProcessorNumberEx(nullptr) + 1;

		HYPERPLATFORM_LOG_DEBUG_SAFE("[VMPTRLD] Run Successfully \r\n");
		HYPERPLATFORM_LOG_DEBUG_SAFE("[VMPTRLD] VMCS02 PA: %I64X VA: %I64X  \r\n", vmcs02_region_pa, vmcs02_region_va);
		HYPERPLATFORM_LOG_DEBUG_SAFE("[VMPTRLD] VMCS12 PA: %I64X \r\n", vmcs12_region_pa);
		HYPERPLATFORM_LOG_DEBUG_SAFE("[VMPTRLD] VMCS01 PA: %I64X VA: %I64X \r\n", nested_vmx->vmcs01_pa, UtilVaFromPa(nested_vmx->vmcs01_pa));
		HYPERPLATFORM_LOG_DEBUG_SAFE("[VMPTRLD] Current Cpu: %x in Cpu Group : %x  Number: %x \r\n", nested_vmx->InitialCpuNumber, procnumber.Group, procnumber.Number);

		VMSucceed(VmmpGetFlagReg(guest_context));

	} while (FALSE);
}

//------------------------------------------------------------------------------------------------//
VOID 
VmxVmreadEmulate(
	_In_	GuestContext* guest_context
)
/*++
Desscription:

	Emulating VMRead instruction , we are passing through the contents of paremeter, to the 
	VMCS1-2, L1's VMM doesn't realize the effect is not making on the VMCS0-2, however, that is 
	not really loaded into physical processor. But it is used to be a material for producing the VMCS0-2

Paremeters:

	Guest Context

Return Value:

	NO

--*/
{
	do
	{

		VmcsField		  field;
		ULONG_PTR		  offset;
		ULONG_PTR		  value;
		BOOLEAN			  RorM;
		ULONG_PTR		  regIndex;
		ULONG_PTR		  memAddress;
		PROCESSOR_NUMBER  procnumber = { 0 };
		VCPUVMX*		  NestedvCPU = VmmpGetVcpuVmx(guest_context);
		ULONG64			  vmcs12_pa = NestedvCPU->vmcs12_pa;
		ULONG64			  vmcs12_va = (ULONG64)UtilVaFromPa(vmcs12_pa);
		
		if (VmmpGetvCpuMode(guest_context) != VmxMode)
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("Current vCPU already in VMX mode ! \r\n"));
			VMfailInvalid(VmmpGetFlagReg(guest_context));
			break;
		}

		if (!NestedvCPU)
		{
			DumpVcpu(guest_context);
			HYPERPLATFORM_COMMON_DBG_BREAK();
			break;
		}

		// if VCPU not run in VMX mode 
		if (VmxGetVmxMode(VmmpGetVcpuVmx(guest_context)) != RootMode)
		{
			// Inject ...'
			HYPERPLATFORM_LOG_DEBUG(" Vmread: Unimplemented third level virualization VMX: %I64x  VMCS12: %I64x \r\n", VmmpGetVcpuVmx(guest_context), vmcs12_pa);
			VMfailInvalid(VmmpGetFlagReg(guest_context));
			break;
		}

		field = VmcsDecodeVmwriteOrVmRead(VmmpGetGpReg(guest_context), &offset, &value, &RorM, &regIndex, &memAddress);

		if (!is_vmcs_field_supported(field))
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE("VMREAD: Virtual VT-x is not supported this feature [field: %I64X] \r\n", field); 	  //#gp
			VMfailInvalid(VmmpGetFlagReg(guest_context));
			break;
		}

		if ((ULONG64)vmcs12_va == 0xFFFFFFFFFFFFFFFF)
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("VMREAD: 0xFFFFFFFFFFFFFFFF		 ! \r\n")); 	  //#gp
			VMfailInvalid(VmmpGetFlagReg(guest_context));
			break;
		}

		auto operand_size = VMCS_FIELD_WIDTH((int)field);

		if (RorM)
		{
			auto reg = VmmpSelectRegister((ULONG)regIndex, guest_context);
			if (operand_size == VMCS_FIELD_WIDTH_16BIT)
			{
				VmcsVmRead16(field, vmcs12_va, (PUSHORT)reg);
				HYPERPLATFORM_LOG_DEBUG_SAFE("VMREAD16: field: %I64X base: %I64X Offset: %I64X Value: %I64X\r\n", field, vmcs12_va, offset, *(PUSHORT)reg);

			}
			if (operand_size == VMCS_FIELD_WIDTH_32BIT)
			{
				VmcsVmRead32(field, vmcs12_va, (PULONG32)reg);
				HYPERPLATFORM_LOG_DEBUG_SAFE("VMREAD32: field: %I64X base: %I64X Offset: %I64X Value: %I64X\r\n", field, vmcs12_va, offset, *(PULONG32)reg);
			}
			if (operand_size == VMCS_FIELD_WIDTH_64BIT || operand_size == VMCS_FIELD_WIDTH_NATURAL_WIDTH)
			{
				VmcsVmRead64(field, vmcs12_va, (PULONG64)reg);
				HYPERPLATFORM_LOG_DEBUG_SAFE("VMREAD64: field: %I64X base: %I64X Offset: %I64X Value: %I64X\r\n", field, vmcs12_va, offset, *(PULONG64)reg);
			}

		}
		else
		{
			if (operand_size == VMCS_FIELD_WIDTH_16BIT)
			{
				VmcsVmRead16(field, vmcs12_va, (PUSHORT)memAddress);
				//HYPERPLATFORM_LOG_DEBUG_SAFE("VMREAD16: field: %I64X base: %I64X Offset: %I64X Value: %I64X\r\n", field, vmcs12_va, offset, *(PUSHORT)memAddress);
			}
			if (operand_size == VMCS_FIELD_WIDTH_32BIT)
			{
				VmcsVmRead32(field, vmcs12_va, (PULONG32)memAddress);
				//HYPERPLATFORM_LOG_DEBUG_SAFE("VMREAD32: field: %I64X base: %I64X Offset: %I64X Value: %I64X\r\n", field, vmcs12_va, offset, *(PULONG32)memAddress);
			}
			if (operand_size == VMCS_FIELD_WIDTH_64BIT || operand_size == VMCS_FIELD_WIDTH_NATURAL_WIDTH)
			{
				VmcsVmRead64(field, vmcs12_va, (PULONG64)memAddress);
				//HYPERPLATFORM_LOG_DEBUG_SAFE("VMREAD64: field: %I64X base: %I64X Offset: %I64X Value: %I64X\r\n", field, vmcs12_va, offset, *(PULONG64)memAddress);
			}
		}

		VMSucceed(VmmpGetFlagReg(guest_context));

	} while (FALSE);
}

//------------------------------------------------------------------------------------------------//
VOID VmxVmwriteEmulate(
	_In_	GuestContext* guest_context
)
/*++
Desscription:

	Emulating VMWrite instruction , we are passing through the contents of paremeter, to the 
	VMCS1-2, L1's VMM doesn't realize the effect is not making on the VMCS0-2, however, that is 
	not really loaded into physical processor. But it is used to be a material for producing
	the VMCS0-2.

Paremeters:

	Guest Context

Return Value:

	NO

--*/
{
	do
	{
		VmcsField			field;
		ULONG_PTR			offset;
		ULONG_PTR			Value;
		BOOLEAN				RorM;
		PROCESSOR_NUMBER    procnumber = { 0 };
		VCPUVMX*			NestedvCPU = VmmpGetVcpuVmx(guest_context);
		ULONG64				vmcs12_pa = (ULONG64)NestedvCPU->vmcs12_pa;
		ULONG64				vmcs12_va = (ULONG64)UtilVaFromPa(vmcs12_pa);

		if (VmmpGetvCpuMode(guest_context) != VmxMode)
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE((" Vmwrite: Current vCPU already in VMX mode ! \r\n"));
			VMfailInvalid(VmmpGetFlagReg(guest_context));
			break;
		}
		// if VCPU not run in VMX mode 
		if (VmxGetVmxMode(VmmpGetVcpuVmx(guest_context)) != RootMode)
		{
			// Inject ...'
			HYPERPLATFORM_LOG_DEBUG(" Vmwrite: Unimplemented third level virualization VMX: %I64x  VMCS12: %I64x \r\n", VmmpGetVcpuVmx(guest_context), vmcs12_pa);
			VMfailInvalid(VmmpGetFlagReg(guest_context));
			break;
		}
		
		if (!NestedvCPU)
		{
			DumpVcpu(guest_context);
			HYPERPLATFORM_COMMON_DBG_BREAK();
			break;
		}
		 
	
		///TODO: If in VMX non-root operation, should be VM Exit

		field = VmcsDecodeVmwriteOrVmRead(VmmpGetGpReg(guest_context), &offset, &Value, &RorM);

		if (!is_vmcs_field_supported(field))
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE("VMWRITE: IS NOT SUPPORT %X ! \r\n", field); 	  //#gp
			VMfailInvalid(VmmpGetFlagReg(guest_context));
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
			VmcsVmWrite16(field, vmcs12_va, Value);
			//HYPERPLATFORM_LOG_DEBUG_SAFE("VMWRITE: field: %I64X base: %I64X Offset: %I64X Value: %I64X  \r\n", field, vmcs12_va, offset, (USHORT)Value);
		}

		if (operand_size == VMCS_FIELD_WIDTH_32BIT)
		{
			VmcsVmWrite32(field, vmcs12_va, Value);
			//HYPERPLATFORM_LOG_DEBUG_SAFE("VMWRITE: field: %I64X base: %I64X Offset: %I64X Value: %I64X\r\n", field, vmcs12_va, offset, (ULONG32)Value);
		}
		if (operand_size == VMCS_FIELD_WIDTH_64BIT || operand_size == VMCS_FIELD_WIDTH_NATURAL_WIDTH)
		{
			VmcsVmWrite64(field, vmcs12_va, Value);
			//HYPERPLATFORM_LOG_DEBUG_SAFE("VMWRITE: field: %I64X base: %I64X Offset: %I64X Value: %I64X\r\n", field, vmcs12_va, offset, (ULONG64)Value);
		}


		VMSucceed(VmmpGetFlagReg(guest_context));
	} while (FALSE);
}


//------------------------------------------------------------------------------------------------//
VOID 
VmxVmlaunchEmulate(
	_In_	GuestContext* guest_context
)
/*++
Desscription:

	Emulating VMLaunch instruction , start the emulation of the VMEntry

Paremeters:

	Guest Context

Return Value:

	NO

--*/
{

	PROCESSOR_NUMBER  procnumber = { 0 };
	VCPUVMX*		  NestedvCPU = VmmpGetVcpuVmx(guest_context);
	VmxStatus		  status;
	do { 
		HYPERPLATFORM_COMMON_DBG_BREAK();
		HYPERPLATFORM_LOG_DEBUG_SAFE("-----start vmlaunch---- \r\n");

		if (VmmpGetvCpuMode(guest_context) != VmxMode)
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("Current vCPU already in VMX mode ! \r\n"));
			VMfailInvalid(VmmpGetFlagReg(guest_context));
			break;
		}

		if (!NestedvCPU)
		{
			DumpVcpu(guest_context);
			HYPERPLATFORM_COMMON_DBG_BREAK();
			break;
		}

		// if VCPU not run in VMX mode 
		if (VmxGetVmxMode(VmmpGetVcpuVmx(guest_context)) != RootMode)
		{
			// Inject ...'
			HYPERPLATFORM_LOG_DEBUG(" Vmlaunch: Unimplemented third level virualization VMX: %I64x  VMCS12: %I64x \r\n", VmmpGetVcpuVmx(guest_context), NestedvCPU->vmcs12_pa);
			VMfailInvalid(VmmpGetFlagReg(guest_context));
			break;
		}
		  
		VMEntryEmulate(NestedvCPU, guest_context, TRUE);

		HYPERPLATFORM_LOG_DEBUG_SAFE("Error VMLAUNCH error code :%x , %x ", 0, 0);
		return;
	} while (FALSE);

}
//------------------------------------------------------------------------------------------------//
VOID 
VmxVmresumeEmulate(
	_In_	GuestContext* guest_context
)
/*++
Desscription:

	Emulating VMLaunch instruction , start the emulation of the VMEntry

Paremeters:

	Guest Context

Return Value:

	NO

--*/
{
	do
	{
		VmxStatus			  status;
		PROCESSOR_NUMBER  procnumber = { 0 };
		VCPUVMX*		  NestedvCPU	 = VmmpGetVcpuVmx(guest_context);
		//	HYPERPLATFORM_LOG_DEBUG_SAFE("----Start Emulate VMRESUME---");

		if (VmmpGetvCpuMode(guest_context) != VmxMode)
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("Current vCPU already in VMX mode ! \r\n"));
			VMfailInvalid(VmmpGetFlagReg(guest_context));
			break;
		}

		if (!NestedvCPU)
		{
			DumpVcpu(guest_context);
			HYPERPLATFORM_COMMON_DBG_BREAK();
			break;
		}

		// if VCPU not run in VMX mode 
		if (VmxGetVmxMode(VmmpGetVcpuVmx(guest_context)) != RootMode)
		{
			// Inject ...'
			HYPERPLATFORM_LOG_DEBUG(" Vmresume: Unimplemented third level virualization VMX: %I64x  VMCS12: %I64x \r\n",
				VmmpGetVcpuVmx(guest_context), NestedvCPU->vmcs12_pa);

			VMfailInvalid(VmmpGetFlagReg(guest_context));
			break;
		}

		VMEntryEmulate(NestedvCPU, guest_context, FALSE); 


		//HYPERPLATFORM_COMMON_DBG_BREAK();

		VMSucceed(VmmpGetFlagReg(guest_context));
	} while (FALSE);
}

//------------------------------------------------------------------------------------------------//
VOID 
VmxVmptrstEmulate(
	GuestContext* guest_context
)
/*++
Desscription:

	Emulating VMPtrst instruction , simple emulation , may not be consistent with Intel's behavior

Paremeters:

	Guest Context

Return Value:

	NO

--*/
{
	do
	{
		PROCESSOR_NUMBER	procnumber = {};
		ULONG64				InstructionPointer = { UtilVmRead64(VmcsField::kGuestRip) };
		ULONG64				StackPointer = { UtilVmRead64(VmcsField::kGuestRsp) };
		ULONG64				vmcs12_region_pa = *(PULONG64)DecodeVmclearOrVmptrldOrVmptrstOrVmxon(guest_context); 
		ULONG				vcpu_index = KeGetCurrentProcessorNumberEx(&procnumber);

		if (!vmcs12_region_pa)
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("vmcs12_region_pa null ! \r\n"));
			VMfailInvalid(VmmpGetFlagReg(guest_context));
			break;
		}

		ULONG64	vmcs12_region_va = (ULONG64)UtilVaFromPa(vmcs12_region_pa);  
		if (VmmpGetvCpuMode(guest_context) != VmxMode)
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("Current vCPU already in VMX mode ! \r\n"));
			VMfailInvalid(VmmpGetFlagReg(guest_context));
			break;
		}

		// if VCPU not run in VMX mode 
		if (VmxGetVmxMode(VmmpGetVcpuVmx(guest_context)) != RootMode)
		{
			// Inject ...'
			HYPERPLATFORM_LOG_DEBUG_SAFE("Vmptrst: Unimplemented third level virualization  %I64x \r\n", VmmpGetVcpuVmx(guest_context));
			VMfailInvalid(VmmpGetFlagReg(guest_context));
			break;
		}

		*(PULONG64)vmcs12_region_va = VmmpGetVcpuVmx(guest_context)->vmcs12_pa; 

		VMSucceed(VmmpGetFlagReg(guest_context));
	} while (FALSE);
}
//------------------------------------------------------------------------------------------------//VOID 
void VmxInveptEmulate(
	_In_	GuestContext* guest_context
) {
	do{
		
		/*EptpRefreshEpt02(
			VmmGetCurrentEpt02Pointer(guest_context), 
			VmmGetCurrentEpt12Pointer(guest_context), 
			VmmGetCurrentEpt01Pointer(guest_context)
		);*/
		VMSucceed(VmmpGetFlagReg(guest_context));
	} while (FALSE);
}

}
 