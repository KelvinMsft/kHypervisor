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


extern ULONG_PTR*	 VmmpSelectRegister(_In_ ULONG index, _In_ GuestContext *guest_context);

ULONG32				 g_vmx_extensions_bitmask;
 
//---------------------------------------------------------------------------------------------------------------------//
void SaveGuestKernelGsBase(ProcessorData* vcpu)
{
	vcpu->GuestKernelGsBase.QuadPart = UtilReadMsr64(Msr::kIa32KernelGsBase);
}

//---------------------------------------------------------------------------------------------------------------------//
void LoadGuestKernelGsBase(ProcessorData* vcpu)
{
	UtilWriteMsr64(Msr::kIa32KernelGsBase, vcpu->GuestKernelGsBase.QuadPart);
}

//---------------------------------------------------------------------------------------------------------------------//
void SaveHostKernelGsBase(ProcessorData* vcpu)
{
	vcpu->HostKernelGsBase.QuadPart = UtilReadMsr64(Msr::kIa32KernelGsBase);
}

//---------------------------------------------------------------------------------------------------------------------//
void LoadHostKernelGsBase(ProcessorData* vcpu)
{
	UtilWriteMsr64(Msr::kIa32KernelGsBase, vcpu->HostKernelGsBase.QuadPart);
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


//----------------------------------------------------------------------------------------------------------------//
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
void InitVmxExtensionMask(void)
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
BOOLEAN IsEptptrValid(ULONG64 eptptr)
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
}