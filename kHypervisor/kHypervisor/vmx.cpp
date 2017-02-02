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

extern "C"
{
////////////////////////////////////////////////////////////////////////////////////////////////////
//// Prototype
////
extern ULONG_PTR*	 VmmpSelectRegister(_In_ ULONG index, _In_ GuestContext *guest_context);
extern GpRegisters*  GetGpReg(GuestContext* guest_context);
extern FlagRegister* GetFlagReg(GuestContext* guest_context);
extern KIRQL		 GetGuestIrql(GuestContext* guest_context);


////////////////////////////////////////////////////////////////////////////////////////////////////
//// Marco
////
#define MY_VMX_TPR_SHADOW            (1 <<  0)              /* TPR shadow */
#define MY_VMX_VIRTUAL_NMI           (1 <<  1)              /* Virtual NMI */
#define MY_VMX_APIC_VIRTUALIZATION   (1 <<  2)              /* APIC Access Virtualization */
#define MY_VMX_WBINVD_VMEXIT         (1 <<  3)              /* WBINVD VMEXIT */
#define MY_VMX_PERF_GLOBAL_CTRL      (1 <<  4)              /* Save/Restore MSR_PERF_GLOBAL_CTRL */
#define MY_VMX_MONITOR_TRAP_FLAG     (1 <<  5)              /* Monitor trap Flag (MTF) */
#define MY_VMX_X2APIC_VIRTUALIZATION (1 <<  6)              /* Virtualize X2APIC */
#define MY_VMX_EPT                   (1 <<  7)              /* Extended Page Tables (EPT) */
#define MY_VMX_VPID                  (1 <<  8)              /* VPID */
#define MY_VMX_UNRESTRICTED_GUEST    (1 <<  9)              /* Unrestricted Guest */
#define MY_VMX_PREEMPTION_TIMER      (1 << 10)              /* VMX preemption timer */
#define MY_VMX_SAVE_DEBUGCTL_DISABLE (1 << 11)              /* Disable Save/Restore of MSR_DEBUGCTL */
#define MY_VMX_PAT                   (1 << 12)              /* Save/Restore MSR_PAT */
#define MY_VMX_EFER                  (1 << 13)              /* Save/Restore MSR_EFER */
#define MY_VMX_DESCRIPTOR_TABLE_EXIT (1 << 14)              /* Descriptor Table VMEXIT */
#define MY_VMX_PAUSE_LOOP_EXITING    (1 << 15)              /* Pause Loop Exiting */
#define MY_VMX_EPTP_SWITCHING        (1 << 16)              /* EPTP switching (VM Function 0) */
#define MY_VMX_EPT_ACCESS_DIRTY      (1 << 17)              /* Extended Page Tables (EPT) A/D Bits */
#define MY_VMX_VINTR_DELIVERY        (1 << 18)              /* Virtual Interrupt Delivery */
#define MY_VMX_POSTED_INSTERRUPTS    (1 << 19)              /* Posted Interrupts support - not implemented yet */
#define MY_VMX_VMCS_SHADOWING        (1 << 20)              /* VMCS Shadowing */
#define MY_VMX_EPT_EXCEPTION         (1 << 21)              /* EPT Violation (#VE) exception */
#define MY_VMX_PML                   (1 << 22)              /* Page Modification Logging - not implemented yet */
#define MY_VMX_TSC_SCALING           (1 << 23)              /* TSC Scaling */
 

////////////////////////////////////////////////////////////////////////////////////////////////////
//// 
//// Variable
////
ULONG32				 g_vmx_extensions_bitmask;
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
//---------------------------------------------------------------------------------------------------------------------//
/*
VMsucceed:
CF ¡û 0;
PF ¡û 0;
AF ¡û 0;
ZF ¡û 0;
SF ¡û 0;
OF ¡û 0;
*/
VOID VMSucceed(FlagRegister *reg)
{
	reg->fields.cf = false;  // Error without status
	reg->fields.pf = false;
	reg->fields.af = false;
	reg->fields.zf = false;  // Error without status
	reg->fields.sf = false;
	reg->fields.of = false;
}
//-----------------------------------------------------------------------------------------------------------------------------------------------------//
/*
VMfailInvalid:
CF ¡û 1;
PF ¡û 0;
AF ¡û 0;
ZF ¡û 0;
SF ¡û 0;
OF ¡û 0;
*/
VOID VMfailInvalid(FlagRegister *reg)
{
	reg->fields.cf = true;  // Error without status
	reg->fields.pf = false;
	reg->fields.af = false;
	reg->fields.zf = false;  // Error without status
	reg->fields.sf = false;
	reg->fields.of = false;
}


//-----------------------------------------------------------------------------------------------------------------------------------------------------//
/*
VMfailValid(ErrorNumber):// executed only if there is a current VMCS
CF ¡û 0;
PF ¡û 0;
AF ¡û 0;
ZF ¡û 1;
SF ¡û 0;
OF ¡û 0;
Set the VM-instruction error field to ErrorNumber;
*/
VOID VMfailValid(FlagRegister *reg, VmxInstructionError err)
{
	UNREFERENCED_PARAMETER(err);
	reg->fields.cf = false;  // Error without status
	reg->fields.pf = false;
	reg->fields.af = false;
	reg->fields.zf = true;  // Error without status
	reg->fields.sf = false;
	reg->fields.of = false;
	//	Set the VM-instruction error field to ErrorNumber;
}

//-------------------------------------------------------------------------------------------------------------------------------------------------------//

VOID VMfail(FlagRegister *reg, VmxInstructionError err)
{
	UNREFERENCED_PARAMETER(err);
	//if and only if VMCS is current
	//VMfailValid(reg, err);
	//else
	VMfailInvalid(reg);
}

//----------------------------------------------------------------------------------------------------------------//
BOOLEAN IsGuestinPagingMode()
{
	Cr0 cr0 = { UtilVmRead64(VmcsField::kGuestCr0) };
	return (cr0.fields.pg) ? TRUE : FALSE;
}

//----------------------------------------------------------------------------------------------------------------//
BOOLEAN IsGuestSetNumericErrorBit()
{
	Cr0 cr0 = { UtilVmRead64(VmcsField::kGuestCr0) };
	return (cr0.fields.ne) ? TRUE : FALSE;
}

//----------------------------------------------------------------------------------------------------------------//
BOOLEAN IsGuestInProtectedMode()
{
	Cr0 cr0 = { UtilVmRead64(VmcsField::kGuestCr0) };
	return (cr0.fields.pe) ? TRUE : FALSE;
}

//----------------------------------------------------------------------------------------------------------------//
BOOLEAN IsGuestSupportVMX()
{
	Cr4 cr4 = { UtilVmRead64(VmcsField::kGuestCr4) };
	return (cr4.fields.vmxe) ? TRUE : FALSE;
}

//----------------------------------------------------------------------------------------------------------------//
BOOLEAN IsGuestInVirtual8086()
{
	FlagRegister flags = { UtilVmRead64(VmcsField::kGuestRflags) };
	return (flags.fields.vm) ? TRUE : FALSE;
}

//----------------------------------------------------------------------------------------------------------------//
SegmentDescriptor* GetSegmentDesctiptor(SegmentSelector ss, ULONG64 gdtBase)
{
	return	reinterpret_cast<SegmentDescriptor *>(gdtBase + ss.fields.index * sizeof(SegmentDescriptor));
}


//----------------------------------------------------------------------------------------------------------------//
BOOLEAN IsGuestinCompatibliltyMode()
{
	SegmentSelector ss = { UtilVmRead64(VmcsField::kGuestCsSelector) };
	ULONG64 gdtBase = UtilVmRead64(VmcsField::kGuestGdtrBase);
	SegmentDescriptor* ds = GetSegmentDesctiptor(ss, gdtBase);
	return (ds->fields.l) ? TRUE : FALSE;
}


//----------------------------------------------------------------------------------------------------------------//
USHORT GetGuestCPL()
{
	const SegmentSelector ss = { UtilVmRead64(VmcsField::kGuestCsSelector) };
	USHORT ret = ss.fields.rpl;
	return ret;
}

//----------------------------------------------------------------------------------------------------------------//
BOOLEAN IsGuestInIA32eMode()
{
	MSR_EFER efer = { UtilVmRead64(VmcsField::kGuestIa32Efer) };
	return (efer.fields.LMA) ? TRUE : FALSE;
}

//----------------------------------------------------------------------------------------------------------------//
///See: Layout of IA32_FEATURE_CONTROL
BOOLEAN IsLockbitClear()
{
	Ia32FeatureControlMsr vmx_feature_control = { UtilReadMsr64(Msr::kIa32FeatureControl) };
	if (vmx_feature_control.fields.lock) {
		return TRUE;
	}
	return FALSE;
}
//----------------------------------------------------------------------------------------------------------------//
///See:  Layout of IA32_FEATURE_CONTROL
BOOLEAN IsGuestEnableVMXOnInstruction()
{
	Ia32FeatureControlMsr vmx_feature_control = { UtilReadMsr64(Msr::kIa32FeatureControl) };
	if (vmx_feature_control.fields.enable_vmxon) {
		return TRUE;
	}
	return FALSE;
}
//----------------------------------------------------------------------------------------------------------------//
BOOLEAN CheckPhysicalAddress(ULONG64 vmxon_region_pa)
{
	Ia32VmxBasicMsr vmx_basic = { UtilReadMsr64(Msr::kIa32VmxBasic) };
	if (vmx_basic.fields.supported_ia64)
	{
		//0xFFFFFFFF00001234 & 0xFFFFFFFF00000000 != 0
		if ((CHECK_BOUNDARY_FOR_IA32 & vmxon_region_pa) != 0)
		{
			return FALSE;
		}
	}
	return TRUE;
}

//----------------------------------------------------------------------------------------------------------------//
ULONG GetVMCSRevisionIdentifier()
{
	Ia32VmxBasicMsr vmx_basic = { UtilReadMsr64(Msr::kIa32VmxBasic) };
	return vmx_basic.fields.revision_identifier;
}




//----------------------------------------------------------------------------------------------------------------//
BOOLEAN CheckPageAlgined(ULONG64 address)
{
	//i.e. 0x22341000 & 0xFFF = 0 , it is page aligned ,
	//	   0x22342355 &	0xFFF = 0x355 , it is not aglined
	return ((address & CHECK_PAGE_ALGINMENT) == 0);
}


//----------------------------------------------------------------------------------------------------------------//
VOID FillEventInjection(ULONG32 interruption_type, ULONG32 exception_vector, BOOLEAN isDeliver_error_code, BOOLEAN isValid)
{
	VmEntryInterruptionInformationField inject = {};
	inject.fields.interruption_type = interruption_type;
	inject.fields.vector = exception_vector;
	inject.fields.deliver_error_code = isDeliver_error_code;
	inject.fields.valid = isValid;
	UtilVmWrite(VmcsField::kVmEntryIntrInfoField, inject.all);
}

//----------------------------------------------------------------------------------------------------------------//
VOID ThrowInvalidCodeException()
{
	FillEventInjection((ULONG32)InterruptionType::kHardwareException, (ULONG32)InterruptionVector::kInvalidOpcodeException, FALSE, TRUE);
}


//----------------------------------------------------------------------------------------------------------------//
VOID ThrowGerneralFaultInterrupt()
{
	FillEventInjection((ULONG32)InterruptionType::kHardwareException, (ULONG32)InterruptionVector::kGeneralProtectionException, FALSE, TRUE);
}


ULONG64 DecodeVmclearOrVmptrldOrVmptrstOrVmxon(GuestContext* guest_context)
{
	const VMInstructionQualificationForClearOrPtrldOrPtrstOrVmxon exit_qualification =
	{
		static_cast<ULONG32>(UtilVmRead(VmcsField::kVmxInstructionInfo))
	};

	// Calculate an address to be used for the instruction
	const auto displacement = UtilVmRead(VmcsField::kExitQualification);
	// Base
	ULONG_PTR base_value = 0;
	if (!exit_qualification.fields.BaseRegInvalid)
	{
		const auto register_used = VmmpSelectRegister(exit_qualification.fields.BaseReg, guest_context);
		base_value = *register_used;
	}

	// Index
	ULONG_PTR index_value = 0;

	if (!exit_qualification.fields.IndexRegInvalid)
	{
		const auto register_used = VmmpSelectRegister(exit_qualification.fields.IndxeReg, guest_context);

		index_value = *register_used;
		switch (static_cast<VMXScaling>(exit_qualification.fields.scalling))
		{
		case VMXScaling::kNoScaling:
			index_value = index_value;
			break;
		case VMXScaling::kScaleBy2:
			index_value = index_value * 2;
			break;
		case VMXScaling::kScaleBy4:
			index_value = index_value * 4;
			break;
		case VMXScaling::kScaleBy8:
			index_value = index_value * 8;
			break;
		default:
			break;
		}
	}

	auto operation_address = base_value + index_value + displacement;

	if (static_cast<VMXAaddressSize>(exit_qualification.fields.address_size) == VMXAaddressSize::k32bit)
	{
		operation_address &= MAXULONG;
	}
	const auto guest_cr3 = UtilVmRead(VmcsField::kGuestCr3);
	const auto vmm_cr3 = __readcr3();
	HYPERPLATFORM_LOG_DEBUG_SAFE("operation_address= %I64x + %I64x + %I64x = %I64x \r\n", base_value, index_value, displacement, operation_address);
 	return operation_address;

}


//----------------------------------------------------------------------------------------------------------------//
//What functions we support for nested
void init_vmx_extensions_bitmask(void)
{
	g_vmx_extensions_bitmask |=
		MY_VMX_VIRTUAL_NMI |
		MY_VMX_TPR_SHADOW |
		MY_VMX_APIC_VIRTUALIZATION |
		MY_VMX_WBINVD_VMEXIT |
		MY_VMX_PREEMPTION_TIMER |
		MY_VMX_PAT |
		MY_VMX_EFER |
		MY_VMX_EPT |
		MY_VMX_VPID |
		MY_VMX_UNRESTRICTED_GUEST |
		MY_VMX_DESCRIPTOR_TABLE_EXIT |
		MY_VMX_X2APIC_VIRTUALIZATION |
		MY_VMX_PAUSE_LOOP_EXITING |
		MY_VMX_EPT_ACCESS_DIRTY |
		MY_VMX_VINTR_DELIVERY |
		MY_VMX_VMCS_SHADOWING |
		MY_VMX_EPTP_SWITCHING |
		MY_VMX_EPT_EXCEPTION |
		MY_VMX_SAVE_DEBUGCTL_DISABLE |
		MY_VMX_PERF_GLOBAL_CTRL;

}

//----------------------------------------------------------------------------------------------------------------//
//Is ept-pointer validate
BOOLEAN is_eptptr_valid(ULONG64 eptptr)
{
	// [2:0] EPT paging-structure memory type
	//       0 = Uncacheable (UC)
	//       6 = Write-back (WB)
	ULONG32 memtype = eptptr & 7;
	if (memtype != (ULONG32)memory_type::kUncacheable && memtype != (ULONG32)memory_type::kWriteBack)
		return FALSE;

	// [5:3] This value is 1 less than the EPT page-walk length
	ULONG32 walk_length = (eptptr >> 3) & 7;
	if (walk_length != 3)
		return FALSE;

	// [6]   EPT A/D Enable
	if (!(g_vmx_extensions_bitmask & MY_VMX_EPT_ACCESS_DIRTY))
	{
		if (eptptr & 0x40)
		{
			HYPERPLATFORM_LOG_DEBUG_SAFE(("is_eptptr_valid: EPTPTR A/D enabled when not supported by CPU"));
			return FALSE;
		}
	}

#define BX_EPTPTR_RESERVED_BITS 0xf80 /* bits 11:7 are reserved */
	if (eptptr & BX_EPTPTR_RESERVED_BITS) {
		HYPERPLATFORM_LOG_DEBUG_SAFE(("is_eptptr_valid: EPTPTR reserved bits set"));
		return FALSE;
	}

	if (!CheckPhysicalAddress(eptptr))
		return FALSE;
	return TRUE;
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
			HYPERPLATFORM_LOG_DEBUG_SAFE("Error vmclear error code :%x , %x ", status, error2);
			HYPERPLATFORM_COMMON_DBG_BREAK();
		}

		HYPERPLATFORM_LOG_DEBUG_SAFE("Error vmclear error code :%x , %x ", 0, 0);
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