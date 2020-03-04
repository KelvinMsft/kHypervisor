// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Copyright (c) 2016-2017, KelvinChan. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements VMM functions.

#include "vmm.h"
#include <intrin.h>
#include "asm.h"
#include "common.h"
#include "ept.h"
#include "log.h"
#include "util.h"
#include "performance.h"
#include "vmcs.h"
#include "vmx.h"
#pragma warning(disable: 4505)
extern "C" {
	////////////////////////////////////////////////////////////////////////////////
	//
	// macro utilities
	//

	////////////////////////////////////////////////////////////////////////////////
	//
	// constants and macros
	//
	// Whether VM-exit recording is enabled
	static const long kVmmpEnableRecordVmExit = false;

	// How many events should be recorded per a processor
	static const long kVmmpNumberOfRecords = 100;

	// How many processors are supported for recording
	static const long kVmmpNumberOfProcessors = 4;

	////////////////////////////////////////////////////////////////////////////////
	//
	// types
	//
	// Represents raw structure of stack of VMM when VmmVmExitHandler() is called
	struct VmmInitialStack {
		GpRegisters gp_regs;
		ULONG_PTR reserved;
		ProcessorData *processor_data;


	};

#pragma pack(8)
	struct GuestContext {
		union {
			VmmInitialStack *stack;
			GpRegisters *gp_regs;
		};
		FlagRegister flag_reg;
		ULONG_PTR ip;
		ULONG_PTR cr8;
		KIRQL irql;
		bool vm_continue;
	};
#pragma pack()

#if defined(_AMD64_)
	static_assert(sizeof(GuestContext) == 40, "Size check");
#else
	static_assert(sizeof(GuestContext) == 20, "Size check");
#endif



	// Context at the moment of vmexit
	struct VmExitHistory {
		GpRegisters gp_regs;
		ULONG_PTR ip;
		VmExitInformation exit_reason;
		ULONG_PTR exit_qualification;
		ULONG_PTR instruction_info;
		VmExitInterruptionInformationField exception_infomation_field;
	};

	////////////////////////////////////////////////////////////////////////////////
	//
	// prototypes
	//

	bool __stdcall VmmVmExitHandler(_Inout_ VmmInitialStack *stack);

	DECLSPEC_NORETURN void __stdcall VmmVmxFailureHandler(
		_Inout_ AllRegisters *all_regs);

	static void VmmpHandleVmExit(_Inout_ GuestContext *guest_context);

	DECLSPEC_NORETURN static void VmmpHandleTripleFault(
		_Inout_ GuestContext *guest_context);

	DECLSPEC_NORETURN static void VmmpHandleUnexpectedExit(
		_Inout_ GuestContext *guest_context);

	static void VmmpHandleHlt(GuestContext* guest_context);
 
	static void VmmpHandleMonitorTrap(_Inout_ GuestContext *guest_context);

	static void VmmpHandleException(_Inout_ GuestContext *guest_context);

	static void VmmpHandleCpuid(_Inout_ GuestContext *guest_context);

	static void VmmpHandleRdtsc(_Inout_ GuestContext *guest_context);

	static void VmmpHandleRdtscp(_Inout_ GuestContext *guest_context);

	static void VmmpHandleXsetbv(_Inout_ GuestContext *guest_context);

	static void VmmpHandleMsrReadAccess(_Inout_ GuestContext *guest_context);

	static void VmmpHandleMsrWriteAccess(_Inout_ GuestContext *guest_context);

	static void VmmpHandleMsrAccess(_Inout_ GuestContext *guest_context,
		_In_ bool read_access);

	static void VmmpHandleGdtrOrIdtrAccess(_Inout_ GuestContext *guest_context);

	static void VmmpHandleLdtrOrTrAccess(_Inout_ GuestContext *guest_context);

	static void VmmpHandleDrAccess(_Inout_ GuestContext *guest_context);

	static void VmmpHandleIoPort(_Inout_ GuestContext *guest_context);

	static void VmmpHandleCrAccess(_Inout_ GuestContext *guest_context);

	static void VmmpHandleVmx(_Inout_ GuestContext *guest_context);

	static void VmmpHandleVmCall(_Inout_ GuestContext *guest_context);

	static void VmmpHandleInvalidateInternalCaches(
		_Inout_ GuestContext *guest_context);

	static void VmmpHandleInvalidateTlbEntry(_Inout_ GuestContext *guest_context);

	static void VmmpHandleEptViolation(_Inout_ GuestContext *guest_context);

	static void VmmpHandleEptMisconfig(_Inout_ GuestContext *guest_context);

	ULONG_PTR *VmmpSelectRegister(_In_ ULONG index,
		_In_ GuestContext *guest_context);

	static void VmmpDumpGuestSelectors();

	static void VmmpAdjustGuestInstructionPointer(_In_ GuestContext *guest_context);

	static void VmmpIoWrapper(_In_ bool to_memory, _In_ bool is_string,
		_In_ SIZE_T size_of_access, _In_ unsigned short port,
		_Inout_ void *address, _In_ unsigned long count);

	static void VmmpSaveExtendedProcessorState(_Inout_ GuestContext *guest_context);

	static void VmmpRestoreExtendedProcessorState(_In_ GuestContext *guest_context);

	static void VmmpIndicateSuccessfulVmcall(_In_ GuestContext *guest_context);

	static void VmmpIndicateUnsuccessfulVmcall(_In_ GuestContext *guest_context);

	static void VmmpHandleVmCallTermination(_In_ GuestContext *guest_context,
		_Inout_ void *context);

	static UCHAR VmmpGetGuestCpl();

	static void VmmpInjectInterruption(_In_ InterruptionType interruption_type,
		_In_ InterruptionVector vector,
		_In_ bool deliver_error_code,
		_In_ ULONG32 error_code);

	////////////////////////////////////////////////////////////////////////////////
	//
	// variables
	// 
	// Those variables are all for diagnostic purpose
	static ULONG g_vmmp_next_history_index[kVmmpNumberOfProcessors];
	static VmExitHistory g_vmmp_vm_exit_history[kVmmpNumberOfProcessors]
		[kVmmpNumberOfRecords];
	extern VOID VMSucceed(FlagRegister* reg);
	////////////////////////////////////////////////////////////////////////////////
	//
	// implementations


	//----------------------------------------------------------------------------------------------------------------//
	_Use_decl_annotations_ GpRegisters* VmmpGetGpReg(GuestContext* guest_context)
	{
		return	guest_context->gp_regs;
	}

	//----------------------------------------------------------------------------------------------------------------//
	_Use_decl_annotations_ FlagRegister* VmmpGetFlagReg(GuestContext* guest_context)
	{
		return &guest_context->flag_reg;
	}

	//----------------------------------------------------------------------------------------------------------------//
	_Use_decl_annotations_ KIRQL VmmpGetGuestIrql(GuestContext* guest_context)
	{
		return guest_context->irql;
	}
	//----------------------------------------------------------------------------------------------------------------//
	_Use_decl_annotations_ ProcessorData* VmmpGetProcessorData(GuestContext* guest_context)
	{
		return guest_context->stack->processor_data;
	} 
	//----------------------------------------------------------------------------------------------------------------//
	_Use_decl_annotations_ ULONG_PTR VmmpGetGuestCr8(GuestContext* guest_context)
	{
		return guest_context->cr8;
	}

	//----------------------------------------------------------------------------------------------------------------//
	_Use_decl_annotations_ ULONG VmmpGetvCpuMode(GuestContext* guest_context)
	{
		return guest_context->stack->processor_data->CpuMode;
	}

	//----------------------------------------------------------------------------------------------------------------//
	_Use_decl_annotations_ VOID SetvCpuMode(GuestContext* guest_context, CPU_MODE CpuMode)
	{
		guest_context->stack->processor_data->CpuMode = CpuMode;
	}

	//----------------------------------------------------------------------------------------------------------------//
	_Use_decl_annotations_ VOID VmmpEnterVmxMode(GuestContext* guest_context)
	{
		SetvCpuMode(guest_context, VmxMode);
	}

	//----------------------------------------------------------------------------------------------------------------//
	_Use_decl_annotations_ VOID VmmpLeaveVmxMode(GuestContext* guest_context)
	{
		SetvCpuMode(guest_context, ProtectedMode);
	}

	//----------------------------------------------------------------------------------------------------------------//
	_Use_decl_annotations_ VCPUVMX* VmmpGetVcpuVmx(GuestContext* guest_context)
	{
		return guest_context->stack->processor_data->vcpu_vmx;
	}

	//----------------------------------------------------------------------------------------------------------------//
	_Use_decl_annotations_ VOID VmmpSetvCpuVmx(GuestContext* guest_context, VCPUVMX* VCPUVMX)
	{
		guest_context->stack->processor_data->vcpu_vmx = VCPUVMX;
	}

	//----------------------------------------------------------------------------------------------------------------//
	_Use_decl_annotations_ EptData* VmmGetCurrentEpt02Pointer(GuestContext* guest_context)
	{
		return guest_context->stack->processor_data->EptDat02;
	}
	//----------------------------------------------------------------------------------------------------------------//
	_Use_decl_annotations_ VOID VmmSaveCurrentEpt02Pointer(GuestContext* guest_context, EptData* Ept02)
	{
		guest_context->stack->processor_data->EptDat02 = Ept02;
	}

	//----------------------------------------------------------------------------------------------------------------//
	_Use_decl_annotations_ EptData* VmmGetCurrentEpt12Pointer(GuestContext* guest_context)
	{
		return guest_context->stack->processor_data->EptDat12;
	}
	//----------------------------------------------------------------------------------------------------------------//
	_Use_decl_annotations_ VOID VmmSaveCurrentEpt12Pointer(GuestContext* guest_context, EptData* Ept12)
	{
		guest_context->stack->processor_data->EptDat12 = Ept12;
	}
	//----------------------------------------------------------------------------------------------------------------//
	_Use_decl_annotations_ EptData* VmmGetCurrentEpt01Pointer(GuestContext* guest_context)
	{
		return guest_context->stack->processor_data->ept_data;
	}
	//----------------------------------------------------------------------------------------------------------------//

	// A high level VMX handler called from AsmVmExitHandler().
	// Return true for vmresume, or return false for vmxoff.
#pragma warning(push)
#pragma warning(disable : 28167)
	_Use_decl_annotations_ bool __stdcall VmmVmExitHandler(VmmInitialStack *stack)
	{

		// Save guest's context and raise IRQL as quick as possible
		const auto guest_irql = KeGetCurrentIrql();
		const auto guest_cr8 = IsX64() ? __readcr8() : 0;
		if (guest_irql < DISPATCH_LEVEL) {
			KeRaiseIrqlToDpcLevel();
		}
		NT_ASSERT(stack->reserved == MAXULONG_PTR);

		// Capture the current guest state
		GuestContext guest_context = { stack,
			UtilVmRead(VmcsField::kGuestRflags),
			UtilVmRead(VmcsField::kGuestRip),
			guest_cr8,
			guest_irql,
			true };

		guest_context.gp_regs->sp = UtilVmRead(VmcsField::kGuestRsp);

		VmmpSaveExtendedProcessorState(&guest_context);

		// Dispatch the current VM-exit event
		VmmpHandleVmExit(&guest_context);

		VmmpRestoreExtendedProcessorState(&guest_context);

		// See: Guidelines for Use of the INVVPID Instruction, and Guidelines for Use
		// of the INVEPT Instruction
		if (!guest_context.vm_continue)
		{
			UtilInveptGlobal();
			UtilInvvpidAllContext();
		}

		// Restore guest's context
		if (guest_context.irql < DISPATCH_LEVEL)
		{
			KeLowerIrql(guest_context.irql);
		}

		// Apply possibly updated CR8 by the handler
		if (IsX64())
		{
			__writecr8(guest_context.cr8);
		}
		return guest_context.vm_continue;
	}
	//-----------------------------------------------------------------------------------------------------------------------//
#pragma warning(pop)
	_Use_decl_annotations_ static void VmmpHandleVmExitForL1(GuestContext *guest_context)
	{
		const VmExitInformation exit_reason = { static_cast<ULONG32>(UtilVmRead(VmcsField::kVmExitReason)) };

		switch (exit_reason.fields.reason)
		{
		case VmxExitReason::kHlt:
			VmmpHandleHlt(guest_context);
			break;
		case VmxExitReason::kExceptionOrNmi:
			VmmpHandleException(guest_context);
			break;
		case VmxExitReason::kExternalInterrupt:
			VmmpHandleException(guest_context);
			break;
		case VmxExitReason::kTripleFault:
			VmmpHandleTripleFault(guest_context);
			break;
		case VmxExitReason::kCpuid:
			VmmpHandleCpuid(guest_context);
			break;
		case VmxExitReason::kInvd:
			VmmpHandleInvalidateInternalCaches(guest_context);
			break;
		case VmxExitReason::kInvlpg:
			VmmpHandleInvalidateTlbEntry(guest_context);
			break;
		case VmxExitReason::kRdtsc:
			VmmpHandleRdtsc(guest_context);
			break;
		case VmxExitReason::kCrAccess:
			VmmpHandleCrAccess(guest_context);
			break;
		case VmxExitReason::kDrAccess:
			VmmpHandleDrAccess(guest_context);
			break;
		case VmxExitReason::kIoInstruction:
			VmmpHandleIoPort(guest_context);
			break;
		case VmxExitReason::kMsrRead:
			VmmpHandleMsrReadAccess(guest_context);
			break;
		case VmxExitReason::kMsrWrite:
			VmmpHandleMsrWriteAccess(guest_context);
			break;
		case VmxExitReason::kMonitorTrapFlag:
			VmmpHandleMonitorTrap(guest_context);
			break;
		case VmxExitReason::kGdtrOrIdtrAccess:
			VmmpHandleGdtrOrIdtrAccess(guest_context);
			break;
		case VmxExitReason::kLdtrOrTrAccess:
			VmmpHandleLdtrOrTrAccess(guest_context);
			break;
		case VmxExitReason::kEptViolation:
			VmmpHandleEptViolation(guest_context);
			break;
		case VmxExitReason::kEptMisconfig:
			VmmpHandleEptMisconfig(guest_context);
			break;
		case VmxExitReason::kVmcall:
			VmmpHandleVmCall(guest_context);
			break;
		case VmxExitReason::kVmclear:
		case VmxExitReason::kVmlaunch:
		case VmxExitReason::kVmptrld:
		case VmxExitReason::kVmptrst:
		case VmxExitReason::kVmread:
		case VmxExitReason::kVmresume:
		case VmxExitReason::kVmwrite:
		case VmxExitReason::kVmoff:
		case VmxExitReason::kVmon:
		case VmxExitReason::kInvept:
			VmmpHandleVmx(guest_context);
			break;
		case VmxExitReason::kRdtscp:
			VmmpHandleRdtscp(guest_context);
			break;
		case VmxExitReason::kXsetbv:
			VmmpHandleXsetbv(guest_context);
			break;
		case VmxExitReason::kInvvpid:
			VmmpAdjustGuestInstructionPointer(guest_context);
			break;
		default:
			VmmpHandleUnexpectedExit(guest_context);
			break;
		}
	}
	//-----------------------------------------------------------------------------------------------------------------------//
	_Use_decl_annotations_ static ULONG_PTR GetCurrentVmcs12(
		_In_ GuestContext *guest_context
	)
	{
		if (!guest_context)
		{
			return 0;
		}

		VCPUVMX* vcpu_vmx = VmmpGetVcpuVmx(guest_context);
		if (!vcpu_vmx || !vcpu_vmx->vmcs12_pa)
		{
			return 0;
		}

		ULONG_PTR vmcs12_va = (ULONG_PTR)UtilVaFromPa(vcpu_vmx->vmcs12_pa);
		if (!vmcs12_va)
		{
			return  0;
		}

		return vmcs12_va;
	}
	//-----------------------------------------------------------------------------------------------------------------------//
	_Use_decl_annotations_ VmxSecondaryProcessorBasedControls GetSecondaryCpuBasedVmexitCtrlForLevel1(
		_In_	GuestContext* guest_context
	)
	{
		ULONG_PTR				  vmcs12_va = 0;
		ULONG32					  CpuBasedVmExitCtrl = 0;
		VmxProcessorBasedControls ctrl = { 0 };
		VmxSecondaryProcessorBasedControls SecondaryCtrl = { 0 };
		if (!guest_context)
		{
			return SecondaryCtrl;
		}
 
		vmcs12_va = GetCurrentVmcs12(guest_context);
		if (!vmcs12_va)
		{
			return  SecondaryCtrl;
		}
		VmcsVmRead32(VmcsField::kSecondaryVmExecControl, vmcs12_va, &CpuBasedVmExitCtrl);
		SecondaryCtrl = { CpuBasedVmExitCtrl };
		return SecondaryCtrl;
	}
	//-----------------------------------------------------------------------------------------------------------------------//
	_Use_decl_annotations_ PUCHAR GetMsrBitmap(
		_In_	GuestContext* guest_context
	)
	{
		ULONG_PTR vmcs12_va = 0;
		ULONG64 msr_bitmap = 0;
		
		if (!guest_context)
		{
			return NULL;
		}
		vmcs12_va = GetCurrentVmcs12(guest_context);
		if (!vmcs12_va)
		{
			return NULL;
		}
		VmcsVmRead64(VmcsField::kMsrBitmap, vmcs12_va, &msr_bitmap);
		return (PUCHAR)msr_bitmap;
	}
	//-----------------------------------------------------------------------------------------------------------------------//
	_Use_decl_annotations_ VmxProcessorBasedControls GetCpuBasedVmexitCtrlForLevel1(
		_In_	GuestContext* guest_context
	)
	{
		ULONG_PTR				  vmcs12_va = 0;
		ULONG32					  CpuBasedVmExitCtrl = 0;
		VmxProcessorBasedControls ctrl = { 0 };

		if (!guest_context)
		{
			return ctrl;
		}
		vmcs12_va = GetCurrentVmcs12(guest_context);
		if (!vmcs12_va)
		{
			return  ctrl;
		}
		VmcsVmRead32(VmcsField::kCpuBasedVmExecControl, vmcs12_va, &CpuBasedVmExitCtrl);
		ctrl = { CpuBasedVmExitCtrl };
		return ctrl;
	}
	//-----------------------------------------------------------------------------------------------------------------------//
	_Use_decl_annotations_ static NTSTATUS VmmpHandleExceptionForL2(
		_In_ GuestContext *guest_context
	)
	{
		NTSTATUS status = STATUS_UNSUCCESSFUL;
		VmExitInterruptionInformationField 	exception = { static_cast<ULONG32>(UtilVmRead(VmcsField::kVmExitIntrInfo)) }; 
		ULONG32    ExceptionBitmap = 0; 
		ULONG_PTR  vmcs12_va = GetCurrentVmcs12(guest_context);

		VmcsVmRead32(VmcsField::kExceptionBitmap, vmcs12_va, &ExceptionBitmap); 
		if (ExceptionBitmap & (1 << exception.fields.vector))
		{
			//HYPERPLATFORM_COMMON_DBG_BREAK(); 
			HYPERPLATFORM_LOG_DEBUG("Exception vector: %x Rip: %p ", exception.fields.vector, UtilVmRead64(VmcsField::kGuestRip));
			status =  VmxVMExitEmulate(VmmpGetVcpuVmx(guest_context), guest_context);
		}
		return status;
	}
	//-----------------------------------------------------------------------------------------------------------------------//
	_Use_decl_annotations_ static NTSTATUS VmmpHandleVmcallForL2(
		_In_ VmExitInformation exit_reason,
		_In_ GuestContext *guest_context
	)
	{
		UNREFERENCED_PARAMETER(exit_reason);
		return VmxVMExitEmulate(VmmpGetVcpuVmx(guest_context), guest_context); 
	}
	//-----------------------------------------------------------------------------------------------------------------------//
	_Use_decl_annotations_ static NTSTATUS VmmpHandleRdmsrForL2(
		_In_ GuestContext *guest_context
	)
	{
		VmxProcessorBasedControls ctrl = GetCpuBasedVmexitCtrlForLevel1(guest_context);
		PUCHAR msr_bitmap = (PUCHAR)UtilVaFromPa((ULONG64)GetMsrBitmap(guest_context));
		ULONG Index = guest_context->gp_regs->cx;

		if (!ctrl.fields.use_msr_bitmaps)
		{
			return STATUS_UNSUCCESSFUL;
		}
		
		if (Index >= 0xC0000000 && Index <= 0xC0001FFF)
		{
			msr_bitmap += 1024;
			Index = Index & 0x1FFF;
		}
		
		ULONG TestIndex	   = Index / 8;
		ULONG TestIndexBit = Index % 8;
		if (!(msr_bitmap[TestIndex] & (1 << TestIndexBit)))
		{
			return STATUS_UNSUCCESSFUL;
		}

		return VmxVMExitEmulate(VmmpGetVcpuVmx(guest_context), guest_context);
	}
	//-----------------------------------------------------------------------------------------------------------------------//
	_Use_decl_annotations_ static NTSTATUS VmmpHandleWrmsrForL2(
		_In_ GuestContext *guest_context
	)
	{
		VmxProcessorBasedControls ctrl = GetCpuBasedVmexitCtrlForLevel1(guest_context);
		PUCHAR				msr_bitmap = (PUCHAR)UtilVaFromPa((ULONG64)GetMsrBitmap(guest_context));
		ULONG					 Index = guest_context->gp_regs->cx;

		if (!ctrl.fields.use_msr_bitmaps)
		{
			return STATUS_UNSUCCESSFUL;
		}
		
		msr_bitmap += 2048;

		if (Index >= 0xC0000000 && Index <= 0xC0001FFF)
		{
			msr_bitmap += 3072;
			Index = Index & 0x1FFF;
		}

		ULONG TestIndex = Index / 8;
		ULONG TestIndexBit = Index % 8;
		if (!(msr_bitmap[TestIndex] & (1 << TestIndexBit)))
		{
			return STATUS_UNSUCCESSFUL;
		}

		return VmxVMExitEmulate(VmmpGetVcpuVmx(guest_context), guest_context);
	}
	//-----------------------------------------------------------------------------------------------------------------------//
	_Use_decl_annotations_ static NTSTATUS VmmpHandleCpuidForL2(
		_In_ GuestContext *guest_context
	)
	{  
		return VmxVMExitEmulate(VmmpGetVcpuVmx(guest_context), guest_context);
	}
	//-----------------------------------------------------------------------------------------------------------------------//
	_Use_decl_annotations_ static NTSTATUS VmmpHandlerRdtscForL2(
		_In_ GuestContext *guest_context
	)
	{ 
		VmxProcessorBasedControls ctrl = GetCpuBasedVmexitCtrlForLevel1(guest_context);
		if (!ctrl.fields.rdtsc_exiting)
		{
			return STATUS_UNSUCCESSFUL;
		}

		HYPERPLATFORM_LOG_DEBUG_SAFE("Rdtsc VMExit to L1");
		return VmxVMExitEmulate(VmmpGetVcpuVmx(guest_context), guest_context);
	} 
	//-----------------------------------------------------------------------------------------------------------------------//
	_Use_decl_annotations_ static NTSTATUS VmmpHandlerCrAccessForL2(
		_In_ GuestContext *guest_context
	)
	{ 
		BOOLEAN ExitOrNot = FALSE;
		const MovCrQualification exit_qualification = {	UtilVmRead(VmcsField::kExitQualification) };
		VmxProcessorBasedControls ctrl = GetCpuBasedVmexitCtrlForLevel1(guest_context);

		switch (static_cast<MovCrAccessType>(exit_qualification.fields.access_type))
		{

			case MovCrAccessType::kMoveToCr:
				switch (exit_qualification.fields.control_register) 
				{
					// CR0 <- Reg
					case 0: {
						ExitOrNot = FALSE;
						break;
					}

					// CR3 <- Reg
					case 3: {
						ExitOrNot = ctrl.fields.cr3_load_exiting;
						break;
					}

					// CR4 <- Reg
					case 4: { 
						ExitOrNot = FALSE; 
						break;
					}

					// CR8 <- Reg
					case 8: { 
						ExitOrNot = ctrl.fields.cr8_load_exiting;
						break;
					}

					default: 
						break;
				}
			break; 
			case MovCrAccessType::kMoveFromCr:
				switch (exit_qualification.fields.control_register) 
				{
					// Reg <- CR3
					case 3: 
					{  
						ExitOrNot = ctrl.fields.cr3_store_exiting; 
						break;
					}

					// Reg <- CR8
					case 8: 
					{
						ExitOrNot = ctrl.fields.cr8_store_exiting;
						break;
					}

					default:
						HYPERPLATFORM_COMMON_BUG_CHECK(HyperPlatformBugCheck::kUnspecified, 0,
							0, 0);
						break;
				}
			break;
			// Unimplemented
			case MovCrAccessType::kClts:
			case MovCrAccessType::kLmsw:
			default:
				ExitOrNot = FALSE; 
				HYPERPLATFORM_COMMON_DBG_BREAK();
				break;
		}

		if (!ExitOrNot)
		{
			return STATUS_UNSUCCESSFUL;
		}

		return VmxVMExitEmulate(VmmpGetVcpuVmx(guest_context), guest_context);
	}

	//-----------------------------------------------------------------------------------------------------------------------//
	_Use_decl_annotations_ static NTSTATUS VmmpHandlerDrAccessForL2(
		_In_ GuestContext *guest_context
	)
	{ 
		VmxProcessorBasedControls ctrl = GetCpuBasedVmexitCtrlForLevel1(guest_context);
		if (!ctrl.fields.mov_dr_exiting)
		{
			return STATUS_UNSUCCESSFUL;
		} 
		HYPERPLATFORM_LOG_DEBUG_SAFE("DrAccess VMExit to L1");
		return VmxVMExitEmulate(VmmpGetVcpuVmx(guest_context), guest_context);
	}

	//-----------------------------------------------------------------------------------------------------------------------//
	_Use_decl_annotations_ static NTSTATUS VmmpHandlerMontiorTrapFlagForL2(
		_In_ GuestContext *guest_context
	)
	{ 
		VmxProcessorBasedControls ctrl = GetCpuBasedVmexitCtrlForLevel1(guest_context);
		if (!ctrl.fields.monitor_trap_flag)
		{
			return STATUS_UNSUCCESSFUL;
		}
		return VmxVMExitEmulate(VmmpGetVcpuVmx(guest_context), guest_context);
		//return STATUS_UNSUCCESSFUL;;
	}
	 
	//-----------------------------------------------------------------------------------------------------------------------//
	_Use_decl_annotations_ static NTSTATUS VmmpHandleDescriptorTableAccessForL2(
		_In_ GuestContext *guest_context
	)
	{
		VmxSecondaryProcessorBasedControls ctrl = GetSecondaryCpuBasedVmexitCtrlForLevel1(guest_context);
		if (!ctrl.fields.descriptor_table_exiting)
		{
			return STATUS_UNSUCCESSFUL;
		}
		HYPERPLATFORM_LOG_DEBUG_SAFE("DescriptorTableAccess VMExit to L1"); 
		return VmxVMExitEmulate(VmmpGetVcpuVmx(guest_context), guest_context);
	}
	//-----------------------------------------------------------------------------------------------------------------------//
	_Use_decl_annotations_ static NTSTATUS VmmpHandleEptViolationForL2(
		_In_ GuestContext *guest_context
	)
	{  
		/*
		  		-------------------
		   	  |
		   L2 |   nGVa			
		  		-------------------
		  	  | 
		  	  |   nGPa			   -----										-----
		  		-------------------		|											|
		      |							|	EPT1-2 PML4 -> PDPTR -> PDE -> PTE	    |								|
		   L1 |   GPA			<-------											|
		  		-------------------		|											|  EPT0-2 PML4 -> PDPTR -> PDE ->PTE 
		  	  |							|	EPT0-1 PML4 -> PDPTR -> PDE -> PTE		|
		   L0 |	  HPA			<-------	<---------------------------------------										
		  		-------------------	
		*/
		NTSTATUS status = STATUS_UNSUCCESSFUL;

		do {
			const EptViolationQualification exit_qualification = {
				UtilVmRead(VmcsField::kExitQualification) };

			if (!guest_context->stack->processor_data->EptDat12 || 
				!guest_context->stack->processor_data->EptDat02)
			{
				break;
			}
			//Translate L2 nGPA to L1 GPA
			EptCommonEntry *Ept12Pte = EptGetEptPtEntry(guest_context->stack->processor_data->EptDat12, UtilVmRead64(VmcsField::kGuestPhysicalAddress));
			if (!Ept12Pte || !Ept12Pte->all)
			{
				HYPERPLATFORM_LOG_DEBUG_SAFE("Nested Guest Translate GPA: %p to by EPTPTE Error (pte: %p)", UtilVmRead64(VmcsField::kGuestPhysicalAddress), Ept12Pte);
				HYPERPLATFORM_COMMON_DBG_BREAK();
				status = VmxVMExitEmulate(VmmpGetVcpuVmx(guest_context), guest_context);
				break;
			}

			HYPERPLATFORM_LOG_DEBUG("Translating L2  GuestRip: %p Qualification: %I64x nGVA: %p nGPA: %p to GPA: %p", UtilVmRead64(VmcsField::kGuestRip), exit_qualification.all, UtilVmRead64(VmcsField::kGuestLinearAddress), UtilVmRead64(VmcsField::kGuestPhysicalAddress), Ept12Pte->fields.physial_address);

			//Translate L1 GPA to HPA 
			EptCommonEntry *Ept01Entry = EptGetEptPtEntry(guest_context->stack->processor_data->ept_data, UtilPaFromPfn(Ept12Pte->fields.physial_address));
			if (!Ept01Entry || !Ept01Entry->all)
			{
				EptHandleEptViolation(guest_context->stack->processor_data->ept_data, nullptr, false);
				HYPERPLATFORM_LOG_DEBUG_SAFE("case 4 l1 GPA: %p to entry2: %p", UtilVmRead64(VmcsField::kGuestPhysicalAddress), Ept01Entry);
				HYPERPLATFORM_COMMON_DBG_BREAK();
			}

			Ept01Entry = EptGetEptPtEntry(guest_context->stack->processor_data->ept_data, UtilPaFromPfn(Ept12Pte->fields.physial_address));
			if (!Ept01Entry || !Ept01Entry->all)
			{
				status = STATUS_UNSUCCESSFUL;
				break;
			}

			HYPERPLATFORM_LOG_DEBUG("Translting L1 GPA: %p to HPA: %p", UtilVmRead64(VmcsField::kGuestPhysicalAddress), Ept01Entry->fields.physial_address);

			EptCommonEntry* Ept02Pte = EptGetEptPtEntry(guest_context->stack->processor_data->EptDat02, UtilVmRead64(VmcsField::kGuestPhysicalAddress));
			if (!exit_qualification.fields.ept_readable &&
				!exit_qualification.fields.ept_writeable &&
				!exit_qualification.fields.ept_executable)
			{
				if (!Ept02Pte || !Ept02Pte->all)
				{
					//Constructing by nGPA to HPA , EPT0-2 we used it for normal run.
					Ept02Pte = EptpConstructTablesEx(
									guest_context->stack->processor_data->EptDat02->ept_pml4,
									4,
									UtilVmRead64(VmcsField::kGuestPhysicalAddress),
									nullptr,
									guest_context->stack->processor_data->ept_data->ept_pml4
							   );
					 
					UtilVmWrite64(VmcsField::kEptPointer, guest_context->stack->processor_data->EptDat02->ept_pointer->all);

					//TODO: switch guest cr3. 
					UtilInveptGlobal();
					HYPERPLATFORM_LOG_DEBUG("We are using EPT0-2 Currently !!!");
				}
				status = STATUS_SUCCESS;
				break;
			}
 
			status =  VmxVMExitEmulate(VmmpGetVcpuVmx(guest_context), guest_context);
		} while (0);
		return status;
	}
	//-----------------------------------------------------------------------------------------------------------------------//
	_Use_decl_annotations_ static NTSTATUS VmmpHandleEptMisconfigForL2(
		_In_ GuestContext *guest_context
	)
	{
		HYPERPLATFORM_COMMON_DBG_BREAK();
		HYPERPLATFORM_COMMON_BUG_CHECK(HyperPlatformBugCheck::kUnspecified, 2, 3, 5);
		return VmxVMExitEmulate(VmmpGetVcpuVmx(guest_context), guest_context);
	}
	//-----------------------------------------------------------------------------------------------------------------------//
	_Use_decl_annotations_ static NTSTATUS VmmpHandleVmExitForL2(
		_In_ GuestContext *guest_context
	)
	{
		const VmExitInformation exit_reason = { UtilVmRead(VmcsField::kVmExitReason) };
		NTSTATUS IsHandled = STATUS_UNSUCCESSFUL;
		switch (exit_reason.fields.reason)
		{
		case VmxExitReason::kCpuid:
			IsHandled = VmmpHandleCpuidForL2(guest_context);
			break;
		case VmxExitReason::kExceptionOrNmi:
			IsHandled = VmmpHandleExceptionForL2(guest_context);
			break;
		case VmxExitReason::kTripleFault:
			break;
		case VmxExitReason::kInvd:
			break;
		case VmxExitReason::kInvlpg:
			break;
		case VmxExitReason::kRdtsc:
			IsHandled = VmmpHandlerRdtscForL2(guest_context);
			break;
		case VmxExitReason::kCrAccess:
			//IsHandled = VmmpHandlerCrAccessForL2(guest_context); 
			break;
		case VmxExitReason::kDrAccess:		
			//IsHandled = VmmpHandlerDrAccessForL2(guest_context);
			break;
		case VmxExitReason::kIoInstruction:
			break;
		case VmxExitReason::kMsrRead:
			IsHandled = VmmpHandleRdmsrForL2(guest_context);
			break;
		case VmxExitReason::kMsrWrite:
			IsHandled = VmmpHandleWrmsrForL2(guest_context);
				break;
		case VmxExitReason::kMonitorTrapFlag:
			IsHandled = VmmpHandlerMontiorTrapFlagForL2(guest_context);
			break;
		case VmxExitReason::kGdtrOrIdtrAccess: 
		case VmxExitReason::kLdtrOrTrAccess:
			//IsHandled = VmmpHandleDescriptorTableAccessForL2(guest_context);
			break; 
		case VmxExitReason::kEptViolation:
#ifdef __NEST_EPT_ENBLE
			IsHandled = VmmpHandleEptViolationForL2(guest_context);
			break;
		case VmxExitReason::kEptMisconfig:
			IsHandled = VmmpHandleEptMisconfigForL2(guest_context);
			break;
#endif
			break;
		case VmxExitReason::kVmcall:
		{	
			IsHandled = VmmpHandleVmcallForL2(exit_reason, guest_context);
			HYPERPLATFORM_LOG_DEBUG("Vmcall Exit to L1");
		}
			break;
		case VmxExitReason::kVmclear:
		case VmxExitReason::kVmlaunch:
		case VmxExitReason::kVmptrld:
		case VmxExitReason::kVmptrst:
		case VmxExitReason::kVmread:
		case VmxExitReason::kVmresume:
		case VmxExitReason::kVmwrite:
		case VmxExitReason::kVmoff:
		case VmxExitReason::kVmon:
			break;
		case VmxExitReason::kRdtscp:
			break;
		case VmxExitReason::kXsetbv:
			break;
		default:
			break;
		}
		return IsHandled;
	}

	//---------------------------------------------------------------------------------------------------------------------//
	// Dispatches VM-exit to a corresponding handler
	_Use_decl_annotations_ static void VmmpHandleVmExit(GuestContext *guest_context)
	{
		HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();

		if (kVmmpEnableRecordVmExit)
		{
			const VmExitInformation exit_reason = { static_cast<ULONG32>(UtilVmRead(VmcsField::kVmExitReason)) };

			// Save them for ease of trouble shooting
			const auto processor = KeGetCurrentProcessorNumberEx(nullptr);
			auto &index = g_vmmp_next_history_index[processor];
			auto &history = g_vmmp_vm_exit_history[processor][index];

			history.ip = guest_context->ip;
			history.exit_reason = exit_reason;
			history.exit_qualification = UtilVmRead(VmcsField::kExitQualification);
			history.instruction_info = UtilVmRead(VmcsField::kVmxInstructionInfo);
			history.exception_infomation_field = { (ULONG32)UtilVmRead(VmcsField::kVmExitIntrInfo) };
			if (++index == kVmmpNumberOfRecords)
			{
				index = 0;
			}
		}

		do
		{
			//after vmxon emulation
			if (VmmpGetvCpuMode(guest_context) != VmxMode)
			{
				//...
				VmmpHandleVmExitForL1(guest_context);
				break;
			}

			//after vmptrld emulation
			//after vmlaunch / vmresume emulation		
			ULONG64 vmcs_pa = 0;
			VCPUVMX* vCPU = VmmpGetVcpuVmx(guest_context);

			__vmx_vmptrst(&vmcs_pa);

			if (VmxGetVmxMode(vCPU) != GuestMode)	 //L2 - OS
			{
				//HYPERPLATFORM_LOG_DEBUG("#1 Almost impossible come here Mode: %x vmcs02_pa: %I64x vmcs_pa: %I64x ", VmxGetVmxMode(vCPU), vCPU->vmcs02_pa, vmcs_pa);
				VmmpHandleVmExitForL1(guest_context);
				break;
			}

			if (vCPU->vmcs02_pa != vmcs_pa)
			{
				HYPERPLATFORM_LOG_DEBUG("Is there possible?? ");
				VmmpHandleVmExitForL1(guest_context);
				break;
			}

			if (!NT_SUCCESS(VmmpHandleVmExitForL2(guest_context)))
			{
				VmmpHandleVmExitForL1(guest_context);
			}

		} while (FALSE);
	}
	//---------------------------------------------------------------------------------------------------------------------//

	// Triple fault VM-exit. Fatal error.
	_Use_decl_annotations_ static void VmmpHandleTripleFault(
		GuestContext *guest_context) {
		VmmpDumpGuestSelectors();
		HYPERPLATFORM_COMMON_BUG_CHECK(HyperPlatformBugCheck::kTripleFaultVmExit,
			reinterpret_cast<ULONG_PTR>(guest_context),
			guest_context->ip, 0);
	}

	// Unexpected VM-exit. Fatal error.
	_Use_decl_annotations_ static void VmmpHandleUnexpectedExit(
		GuestContext *guest_context) {
		VmmpDumpGuestSelectors();
		HYPERPLATFORM_COMMON_BUG_CHECK(HyperPlatformBugCheck::kUnexpectedVmExit,
			reinterpret_cast<ULONG_PTR>(guest_context), UtilVmRead(VmcsField::kVmExitReason),
			UtilVmRead(VmcsField::kVmInstructionError));
	}

	_Use_decl_annotations_  void ShpSetMonitorTrapFlag(bool enable);
	// MTF VM-exit
	_Use_decl_annotations_ static void VmmpHandleMonitorTrap(GuestContext *guest_context)
	{ 
		do {
			if (!guest_context->stack->processor_data->LastEptFaultAddr)
			{
				break;
			}
		
			//before MTF , L1 change its EPT (EPT1-2) , we need to know the content now, find it by fault GPA
			EptCommonEntry* entry12 = (EptCommonEntry*)UtilVaFromPa(guest_context->stack->processor_data->LastEptFaultAddr);
			if (!entry12 || !entry12->fields.physial_address)
			{
				break;
			}
			
			//we need to know the corresponding HPA to the latest modified value  
			EptCommonEntry* entry01 = EptGetEptPtEntry(guest_context->stack->processor_data->ept_data, guest_context->stack->processor_data->LastEptFaultAddr);
			if (!entry01 || !entry01->fields.physial_address)
			{
				break;
			}

			//TODO: we need to get back the EPTPTE source operand AND get the PTE of EPT02, and update it access right and pages.

			HYPERPLATFORM_LOG_DEBUG_SAFE("L1 Acccess PTE_va= %p pa= %p,	modified page= %p	R= %x	W= %x	E= %x", 
				entry12, guest_context->stack->processor_data->LastEptFaultAddr, entry12->fields.physial_address,
				entry12->fields.read_access, entry12->fields.write_access, entry12->fields.execute_access);

			//Turn back the address to be non-writable 
			entry01->fields.write_access = false; 
			guest_context->stack->processor_data->LastEptFaultAddr = 0;

			UtilInveptGlobal(); 
		} while (FALSE);
		ShpSetMonitorTrapFlag(false);
	}

	_Use_decl_annotations_ static void VmmpHandleHlt(GuestContext* guest_context)
	{
		//DbgPrintEx(0,0,"halt: %p Rsp: %p \r\n", guest_context->ip, UtilVmRead64(VmcsField::kGuestRsp));
		VmmpAdjustGuestInstructionPointer(guest_context);
	}
	// Interrupt
	_Use_decl_annotations_ static void VmmpHandleException(
		GuestContext *guest_context) {
		HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
		const VmExitInterruptionInformationField exception = {
			static_cast<ULONG32>(UtilVmRead(VmcsField::kVmExitIntrInfo)) };

		const auto interruption_type =
			static_cast<InterruptionType>(exception.fields.interruption_type);

		const auto vector = static_cast<InterruptionVector>(exception.fields.vector);
		if (interruption_type == InterruptionType::kExternalInterrupt) {
			HYPERPLATFORM_COMMON_DBG_BREAK();
			PrintVMCS();
			
			FlagRegister reg = { UtilVmRead(VmcsField::kGuestRflags) };
			reg.fields.intf = true;
			UtilVmWrite64(VmcsField::kGuestRflags, reg.all);

			HYPERPLATFORM_LOG_DEBUG("GuestRip: %p flags: %x vector: %x", UtilVmRead(VmcsField::kGuestRip), reg , vector);
			VmmpInjectInterruption(interruption_type, vector, exception.fields.error_code_valid, 0);

		}
		else if (interruption_type == InterruptionType::kHardwareException) {
			if (vector == InterruptionVector::kDebugException) 
			{
				HYPERPLATFORM_LOG_DEBUG("#Tf: %x %I64X %I64X %I64X %I64x", interruption_type, UtilVmRead(VmcsField::kGuestRip), UtilVmRead(VmcsField::kGuestRflags), UtilVmRead(VmcsField::kGuestCr0), UtilVmRead(VmcsField::kGuestCr4));
				VmmpAdjustGuestInstructionPointer(guest_context);
			}
			// Hardware exception
			if (vector == InterruptionVector::kPageFaultException) {

				// #PF
				const PageFaultErrorCode fault_code = {
					static_cast<ULONG32>(UtilVmRead(VmcsField::kVmExitIntrErrorCode)) };
				const auto fault_address = UtilVmRead(VmcsField::kExitQualification);

				VmmpInjectInterruption(interruption_type, vector, exception.fields.error_code_valid, fault_code.all);

				AsmWriteCR2(fault_address);

			}
			else if (vector == InterruptionVector::kGeneralProtectionException) {
				// # GP
				const auto error_code =
					static_cast<ULONG32>(UtilVmRead(VmcsField::kVmExitIntrErrorCode));

				VmmpInjectInterruption(interruption_type, vector, true, error_code);
			}

			else {

				HYPERPLATFORM_COMMON_BUG_CHECK(HyperPlatformBugCheck::kUnspecified, 0, 0,
					0);
			}

		}
		else if (interruption_type == InterruptionType::kSoftwareException) {
			// Software exception
			if (vector == InterruptionVector::kBreakpointException) {
				// #BP
				VmmpInjectInterruption(interruption_type, vector, false, 0);
				HYPERPLATFORM_LOG_INFO_SAFE("L0 GuestIp= %p, #BP ", guest_context->ip);
				UtilVmWrite(VmcsField::kVmEntryInstructionLen, 1);

			}
			else {
				HYPERPLATFORM_COMMON_BUG_CHECK(HyperPlatformBugCheck::kUnspecified, 0, 0,
					0);
			}
		}
		else {
			HYPERPLATFORM_COMMON_BUG_CHECK(HyperPlatformBugCheck::kUnspecified, 0, 0,
				0);
		}
	}
	//  L2 -> L0	cpuid 
	//  L0 -> L1	inject cpuid
	//  L1 -> L0	vmresume
	//  L0 -> L2	resume l2 

	// CPUID
	_Use_decl_annotations_ static void VmmpHandleCpuid(
		_In_ GuestContext *guest_context
	)
	{
		HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
		unsigned int cpu_info[4] = {};
		const auto function_id = static_cast<int>(guest_context->gp_regs->ax);
		const auto sub_function_id = static_cast<int>(guest_context->gp_regs->cx);

		__cpuidex(reinterpret_cast<int *>(cpu_info), function_id, sub_function_id);

		if (function_id == 1)
		{
			// Present existence of a hypervisor using the HypervisorPresent bit
			CpuFeaturesEcx cpu_features = { static_cast<ULONG_PTR>(cpu_info[2]) };
			cpu_features.fields.not_used = false;
			cpu_info[2] = static_cast<int>(cpu_features.all);
		}
		else if (function_id == kHyperVCpuidInterface)
		{
			// Leave signature of HyperPlatform onto EAX
			cpu_info[0] = 'PpyH';
		}

		guest_context->gp_regs->ax = cpu_info[0];
		guest_context->gp_regs->bx = cpu_info[1];
		guest_context->gp_regs->cx = cpu_info[2];
		guest_context->gp_regs->dx = cpu_info[3];

		HYPERPLATFORM_LOG_DEBUG("Root CPUID Called with id : %x sid: %x !!!!!!!!!!!!!!! \r\n", function_id, sub_function_id);
		VmmpAdjustGuestInstructionPointer(guest_context);
	}

	// RDTSC
	_Use_decl_annotations_ static void VmmpHandleRdtsc(
		GuestContext *guest_context) {
		HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
		ULARGE_INTEGER tsc = {};
		tsc.QuadPart = __rdtsc();
		guest_context->gp_regs->dx = tsc.HighPart;
		guest_context->gp_regs->ax = tsc.LowPart;

		VmmpAdjustGuestInstructionPointer(guest_context);
	}

	// RDTSCP
	_Use_decl_annotations_ static void VmmpHandleRdtscp(
		GuestContext *guest_context) {
		HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
		unsigned int tsc_aux = 0;
		ULARGE_INTEGER tsc = {};
		tsc.QuadPart = __rdtscp(&tsc_aux);
		guest_context->gp_regs->dx = tsc.HighPart;
		guest_context->gp_regs->ax = tsc.LowPart;
		guest_context->gp_regs->cx = tsc_aux;

		VmmpAdjustGuestInstructionPointer(guest_context);
	}

	// XSETBV. It is executed at the time of system resuming
	_Use_decl_annotations_ static void VmmpHandleXsetbv(
		GuestContext *guest_context) {
		HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
		ULARGE_INTEGER value = {};
		value.LowPart = static_cast<ULONG>(guest_context->gp_regs->ax);
		value.HighPart = static_cast<ULONG>(guest_context->gp_regs->dx);
		_xsetbv(static_cast<ULONG>(guest_context->gp_regs->cx), value.QuadPart);

		VmmpAdjustGuestInstructionPointer(guest_context);
	}

	// RDMSR
	_Use_decl_annotations_ static void VmmpHandleMsrReadAccess(
		GuestContext *guest_context) {
		HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
		VmmpHandleMsrAccess(guest_context, true);
	}

	// WRMSR
	_Use_decl_annotations_ static void VmmpHandleMsrWriteAccess(
		GuestContext *guest_context) {
		HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
		VmmpHandleMsrAccess(guest_context, false);
	}

	// RDMSR and WRMSR
	_Use_decl_annotations_ static void VmmpHandleMsrAccess(
		GuestContext *guest_context, bool read_access) {
		// Apply it for VMCS instead of a real MSR if a specified MSR is either of
		// them.
		const auto msr = static_cast<Msr>(guest_context->gp_regs->cx);

		bool transfer_to_vmcs = false;
		VmcsField vmcs_field = {};
		switch (msr) {
		case Msr::kIa32SysenterCs:
			vmcs_field = VmcsField::kGuestSysenterCs;
			transfer_to_vmcs = true;
			break;
		case Msr::kIa32SysenterEsp:
			vmcs_field = VmcsField::kGuestSysenterEsp;
			transfer_to_vmcs = true;
			break;
		case Msr::kIa32SysenterEip:
			vmcs_field = VmcsField::kGuestSysenterEip;
			transfer_to_vmcs = true;
			break;
		case Msr::kIa32Debugctl:
			vmcs_field = VmcsField::kGuestIa32Debugctl;
			transfer_to_vmcs = true;
			break;
		case Msr::kIa32GsBase: 
			vmcs_field = VmcsField::kGuestGsBase;
			transfer_to_vmcs = true;
			break;   
		case Msr::kIa32FsBase:
			vmcs_field = VmcsField::kGuestFsBase;
			transfer_to_vmcs = true;
			break;
		default:
			break;
		}

		const auto is_64bit_vmcs =
			UtilIsInBounds(vmcs_field, VmcsField::kIoBitmapA,
				VmcsField::kHostIa32PerfGlobalCtrlHigh);

		LARGE_INTEGER msr_value = {};
		if (read_access)
		{
			if (transfer_to_vmcs)
			{
				if (is_64bit_vmcs)
				{
					msr_value.QuadPart = UtilVmRead64(vmcs_field);
				}
				else
				{
					msr_value.QuadPart = UtilVmRead(vmcs_field);
				}
			}
			else
			{
				switch (msr)
				{
					case Msr::kIa32VmxEptVpidCap:
					{
						msr_value.LowPart = guest_context->stack->processor_data->VmxEptMsr.LowPart;
						msr_value.HighPart = guest_context->stack->processor_data->VmxEptMsr.HighPart;
					}
					break;
					case Msr::kIa32FeatureControl:
					{
						msr_value.LowPart = guest_context->stack->processor_data->Ia32FeatureMsr.LowPart;
						msr_value.HighPart = guest_context->stack->processor_data->Ia32FeatureMsr.HighPart;
					}
					break;
					case Msr::kIa32VmxBasic:
					{
						msr_value.LowPart = guest_context->stack->processor_data->VmxBasicMsr.LowPart;
						msr_value.HighPart = guest_context->stack->processor_data->VmxBasicMsr.HighPart;
					}
					break;
					case Msr::kIa32KernelGsBase:
						 msr_value.QuadPart = guest_context->stack->processor_data->GuestKernelGsBase.QuadPart;
					break;
					default:
					{
						msr_value.QuadPart = UtilReadMsr64(msr);
					}
					break;
				}
			}
			guest_context->gp_regs->ax = msr_value.LowPart;
			guest_context->gp_regs->dx = msr_value.HighPart;
		}
		else
		{
			msr_value.LowPart = static_cast<ULONG>(guest_context->gp_regs->ax);
			msr_value.HighPart = static_cast<ULONG>(guest_context->gp_regs->dx);
			if (transfer_to_vmcs)
			{
				if (is_64bit_vmcs)
				{
					UtilVmWrite64(vmcs_field, static_cast<ULONG_PTR>(msr_value.QuadPart));
				}
				else
				{
					UtilVmWrite(vmcs_field, static_cast<ULONG_PTR>(msr_value.QuadPart));
				}
			}
			else
			{
				switch (msr)
				{
					case Msr::kIa32VmxEptVpidCap:
						guest_context->stack->processor_data->VmxEptMsr.QuadPart = msr_value.QuadPart;
					break;
					case Msr::kIa32FeatureControl:
						guest_context->stack->processor_data->Ia32FeatureMsr.QuadPart = msr_value.QuadPart;
					break;
					case  Msr::kIa32VmxBasic:
						guest_context->stack->processor_data->VmxBasicMsr.QuadPart = msr_value.QuadPart;
					break;
					case Msr::kIa32KernelGsBase:
						guest_context->stack->processor_data->GuestKernelGsBase.QuadPart = msr_value.QuadPart;
					break;
					default:
						UtilWriteMsr64(msr, msr_value.QuadPart); 
					break;
				}
			}
		}

		VmmpAdjustGuestInstructionPointer(guest_context);
	}

	// LIDT, SIDT, LGDT and SGDT
	_Use_decl_annotations_ static void VmmpHandleGdtrOrIdtrAccess(
		GuestContext *guest_context) {
		HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
		const GdtrOrIdtrInstInformation exit_qualification = {
			static_cast<ULONG32>(UtilVmRead(VmcsField::kVmxInstructionInfo)) };

		// Calculate an address to be used for the instruction
		const auto displacement = UtilVmRead(VmcsField::kExitQualification);

		// Base
		ULONG_PTR base_value = 0;
		if (!exit_qualification.fields.base_register_invalid) {
			const auto register_used = VmmpSelectRegister(
				exit_qualification.fields.base_register, guest_context);
			base_value = *register_used;
		}

		// Index
		ULONG_PTR index_value = 0;
		if (!exit_qualification.fields.index_register_invalid) {
			const auto register_used = VmmpSelectRegister(
				exit_qualification.fields.index_register, guest_context);
			index_value = *register_used;
			switch (static_cast<Scaling>(exit_qualification.fields.scalling)) {
			case Scaling::kNoScaling:
				index_value = index_value;
				break;
			case Scaling::kScaleBy2:
				index_value = index_value * 2;
				break;
			case Scaling::kScaleBy4:
				index_value = index_value * 4;
				break;
			case Scaling::kScaleBy8:
				index_value = index_value * 8;
				break;
			default:
				break;
			}
		}

		auto operation_address = base_value + index_value + displacement;
		if (static_cast<AddressSize>(exit_qualification.fields.address_size) ==
			AddressSize::k32bit) {
			operation_address &= MAXULONG;
		}

		// Update CR3 with that of the guest since below code is going to access
		// memory.
		const auto guest_cr3 = UtilVmRead(VmcsField::kGuestCr3);
		const auto vmm_cr3 = __readcr3();
		__writecr3(guest_cr3);

		// Emulate the instruction
		auto descriptor_table_reg = reinterpret_cast<Idtr *>(operation_address);
		switch (static_cast<GdtrOrIdtrInstructionIdentity>(
			exit_qualification.fields.instruction_identity)) {
		case GdtrOrIdtrInstructionIdentity::kSgdt:
			descriptor_table_reg->base = UtilVmRead(VmcsField::kGuestGdtrBase);
			descriptor_table_reg->limit =
				static_cast<unsigned short>(UtilVmRead(VmcsField::kGuestGdtrLimit));
			break;
		case GdtrOrIdtrInstructionIdentity::kSidt:
			descriptor_table_reg->base = UtilVmRead(VmcsField::kGuestIdtrBase);
			descriptor_table_reg->limit =
				static_cast<unsigned short>(UtilVmRead(VmcsField::kGuestIdtrLimit));
			break;
		case GdtrOrIdtrInstructionIdentity::kLgdt:
			UtilVmWrite(VmcsField::kGuestGdtrBase, descriptor_table_reg->base);
			UtilVmWrite(VmcsField::kGuestGdtrLimit, descriptor_table_reg->limit);
			break;
		case GdtrOrIdtrInstructionIdentity::kLidt:
			UtilVmWrite(VmcsField::kGuestIdtrBase, descriptor_table_reg->base);
			UtilVmWrite(VmcsField::kGuestIdtrLimit, descriptor_table_reg->limit);
			break;
		}

		__writecr3(vmm_cr3);
		VmmpAdjustGuestInstructionPointer(guest_context);
	}

	// LLDT, LTR, SLDT, and STR
	_Use_decl_annotations_ static void VmmpHandleLdtrOrTrAccess(
		GuestContext *guest_context) {
		HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
		const LdtrOrTrInstInformation exit_qualification = {
			static_cast<ULONG32>(UtilVmRead(VmcsField::kVmxInstructionInfo)) };

		// Calculate an address or a register to be used for the instruction
		const auto displacement = UtilVmRead(VmcsField::kExitQualification);

		ULONG_PTR operation_address = 0;
		if (exit_qualification.fields.register_access) {
			// Register
			const auto register_used =
				VmmpSelectRegister(exit_qualification.fields.register1, guest_context);
			operation_address = reinterpret_cast<ULONG_PTR>(register_used);
		}
		else {
			// Base
			ULONG_PTR base_value = 0;
			if (!exit_qualification.fields.base_register_invalid) {
				const auto register_used = VmmpSelectRegister(
					exit_qualification.fields.base_register, guest_context);
				base_value = *register_used;
			}

			// Index
			ULONG_PTR index_value = 0;
			if (!exit_qualification.fields.index_register_invalid) {
				const auto register_used = VmmpSelectRegister(
					exit_qualification.fields.index_register, guest_context);
				index_value = *register_used;
				switch (static_cast<Scaling>(exit_qualification.fields.scalling)) {
				case Scaling::kNoScaling:
					index_value = index_value;
					break;
				case Scaling::kScaleBy2:
					index_value = index_value * 2;
					break;
				case Scaling::kScaleBy4:
					index_value = index_value * 4;
					break;
				case Scaling::kScaleBy8:
					index_value = index_value * 8;
					break;
				default:
					break;
				}
			}

			operation_address = base_value + index_value + displacement;
			if (static_cast<AddressSize>(exit_qualification.fields.address_size) ==
				AddressSize::k32bit) {
				operation_address &= MAXULONG;
			}
		}

		// Update CR3 with that of the guest since below code is going to access
		// memory.
		const auto guest_cr3 = UtilVmRead(VmcsField::kGuestCr3);
		const auto vmm_cr3 = __readcr3();
		__writecr3(guest_cr3);

		// Emulate the instruction
		auto selector = reinterpret_cast<USHORT *>(operation_address);
		switch (static_cast<LdtrOrTrInstructionIdentity>(
			exit_qualification.fields.instruction_identity)) {
		case LdtrOrTrInstructionIdentity::kSldt:
			*selector = static_cast<USHORT>(UtilVmRead(VmcsField::kGuestLdtrSelector));
			break;
		case LdtrOrTrInstructionIdentity::kStr:
			*selector = static_cast<USHORT>(UtilVmRead(VmcsField::kGuestTrSelector));
			break;
		case LdtrOrTrInstructionIdentity::kLldt:
			UtilVmWrite(VmcsField::kGuestLdtrSelector, *selector);
			break;
		case LdtrOrTrInstructionIdentity::kLtr:
			UtilVmWrite(VmcsField::kGuestTrSelector, *selector);
			break;
		default:
			break;
		}

		__writecr3(vmm_cr3);
		VmmpAdjustGuestInstructionPointer(guest_context);
	}

	// MOV to / from DRx
	_Use_decl_annotations_ static void VmmpHandleDrAccess(
		GuestContext *guest_context) {
		HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
		const MovDrQualification exit_qualification = {
			UtilVmRead(VmcsField::kExitQualification) };
		const auto register_used =
			VmmpSelectRegister(exit_qualification.fields.gp_register, guest_context);

		// Emulate the instruction
		switch (static_cast<MovDrDirection>(exit_qualification.fields.direction)) {
		case MovDrDirection::kMoveToDr:
			// clang-format off
			switch (exit_qualification.fields.debugl_register) {
			case 0: __writedr(0, *register_used); break;
			case 1: __writedr(1, *register_used); break;
			case 2: __writedr(2, *register_used); break;
			case 3: __writedr(3, *register_used); break;
			case 4: __writedr(4, *register_used); break;
			case 5: __writedr(5, *register_used); break;
			case 6: __writedr(6, *register_used); break;
			case 7: UtilVmWrite(VmcsField::kGuestDr7, *register_used); break;
			default: break;
			}
			// clang-format on
			break;
		case MovDrDirection::kMoveFromDr:
			// clang-format off
			switch (exit_qualification.fields.debugl_register) {
			case 0: *register_used = __readdr(0); break;
			case 1: *register_used = __readdr(1); break;
			case 2: *register_used = __readdr(2); break;
			case 3: *register_used = __readdr(3); break;
			case 4: *register_used = __readdr(4); break;
			case 5: *register_used = __readdr(5); break;
			case 6: *register_used = __readdr(6); break;
			case 7: *register_used = UtilVmRead(VmcsField::kGuestDr7); break;
			default: break;
			}
			// clang-format on
			break;
		default:
			HYPERPLATFORM_COMMON_BUG_CHECK(HyperPlatformBugCheck::kUnspecified, 0, 0,
				0);
			break;
		}

		VmmpAdjustGuestInstructionPointer(guest_context);
	}

	// IN, INS, OUT, OUTS
	_Use_decl_annotations_ static void VmmpHandleIoPort(
		GuestContext *guest_context) {
		const IoInstQualification exit_qualification = {
			UtilVmRead(VmcsField::kExitQualification) };

		const auto is_in = exit_qualification.fields.direction == 1;  // to memory?
		const auto is_string = exit_qualification.fields.string_instruction == 1;
		const auto is_rep = exit_qualification.fields.rep_prefixed == 1;
		const auto port = static_cast<USHORT>(exit_qualification.fields.port_number);
		const auto string_address = reinterpret_cast<void *>(
			(is_in) ? guest_context->gp_regs->di : guest_context->gp_regs->si);
		const auto count =
			static_cast<unsigned long>((is_rep) ? guest_context->gp_regs->cx : 1);
		const auto address =
			(is_string) ? string_address : &guest_context->gp_regs->ax;

		SIZE_T size_of_access = 0;
		const char *suffix = "";
		switch (static_cast<IoInstSizeOfAccess>(
			exit_qualification.fields.size_of_access)) {
		case IoInstSizeOfAccess::k1Byte:
			size_of_access = 1;
			suffix = "B";
			break;
		case IoInstSizeOfAccess::k2Byte:
			size_of_access = 2;
			suffix = "W";
			break;
		case IoInstSizeOfAccess::k4Byte:
			size_of_access = 4;
			suffix = "D";
			break;
		}

		HYPERPLATFORM_LOG_DEBUG_SAFE("GuestIp= %p, Port= %04x, %s%s%s",
			guest_context->ip, port, (is_in ? "IN" : "OUT"),
			(is_string ? "S" : ""),
			(is_string ? suffix : ""));

		VmmpIoWrapper(is_in, is_string, size_of_access, port, address, count);

		// Update RCX, RDI and RSI accordingly. Note that this code can handle only
		// the REP prefix.
		if (is_string) {
			const auto update_count = (is_rep) ? guest_context->gp_regs->cx : 1;
			const auto update_size = update_count * size_of_access;
			const auto update_register =
				(is_in) ? &guest_context->gp_regs->di : &guest_context->gp_regs->si;

			if (guest_context->flag_reg.fields.df) {
				*update_register = *update_register - update_size;
			}
			else {
				*update_register = *update_register + update_size;
			}

			if (is_rep) {
				guest_context->gp_regs->cx = 0;
			}
		}

		VmmpAdjustGuestInstructionPointer(guest_context);
	}

	// Perform IO instruction according with parameters
	_Use_decl_annotations_ static void VmmpIoWrapper(bool to_memory, bool is_string,
		SIZE_T size_of_access,
		unsigned short port,
		void *address,
		unsigned long count) {
		NT_ASSERT(size_of_access == 1 || size_of_access == 2 || size_of_access == 4);

		// Update CR3 with that of the guest since below code is going to access
		// memory.
		const auto guest_cr3 = UtilVmRead(VmcsField::kGuestCr3);
		const auto vmm_cr3 = __readcr3();
		__writecr3(guest_cr3);

		// clang-format off
		if (to_memory) {
			if (is_string) {
				// INS
				switch (size_of_access) {
				case 1: __inbytestring(port, reinterpret_cast<UCHAR*>(address), count); break;
				case 2: __inwordstring(port, reinterpret_cast<USHORT*>(address), count); break;
				case 4: __indwordstring(port, reinterpret_cast<ULONG*>(address), count); break;
				}
			}
			else {
				// IN
				switch (size_of_access) {
				case 1: *reinterpret_cast<UCHAR*>(address) = __inbyte(port); break;
				case 2: *reinterpret_cast<USHORT*>(address) = __inword(port); break;
				case 4: *reinterpret_cast<ULONG*>(address) = __indword(port); break;
				}
			}
		}
		else {
			if (is_string) {
				// OUTS
				switch (size_of_access) {
				case 1: __outbytestring(port, reinterpret_cast<UCHAR*>(address), count); break;
				case 2: __outwordstring(port, reinterpret_cast<USHORT*>(address), count); break;
				case 4: __outdwordstring(port, reinterpret_cast<ULONG*>(address), count); break;
				}
			}
			else {
				// OUT
				switch (size_of_access) {
				case 1: __outbyte(port, *reinterpret_cast<UCHAR*>(address)); break;
				case 2: __outword(port, *reinterpret_cast<USHORT*>(address)); break;
				case 4: __outdword(port, *reinterpret_cast<ULONG*>(address)); break;
				}
			}
		}
		// clang-format on

		__writecr3(vmm_cr3);
	}

	// MOV to / from CRx
	_Use_decl_annotations_ static void VmmpHandleCrAccess(
		GuestContext *guest_context) {
		HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
		const MovCrQualification exit_qualification = {
			UtilVmRead(VmcsField::kExitQualification) };

		const auto register_used =
			VmmpSelectRegister(exit_qualification.fields.gp_register, guest_context);

		switch (static_cast<MovCrAccessType>(exit_qualification.fields.access_type)) {
		case MovCrAccessType::kMoveToCr:
			switch (exit_qualification.fields.control_register) {
				// CR0 <- Reg
			case 0: {
				HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
				if (UtilIsX86Pae()) {
					UtilLoadPdptes(UtilVmRead(VmcsField::kGuestCr3));
				}
				const Cr0 cr0_fixed0 = { UtilReadMsr(Msr::kIa32VmxCr0Fixed0) };
				const Cr0 cr0_fixed1 = { UtilReadMsr(Msr::kIa32VmxCr0Fixed1) };
				Cr0 cr0 = { *register_used };
				cr0.all &= cr0_fixed1.all;
				cr0.all |= cr0_fixed0.all;
				UtilVmWrite(VmcsField::kGuestCr0, cr0.all);
				UtilVmWrite(VmcsField::kCr0ReadShadow, cr0.all);
				break;
			}

					// CR3 <- Reg
			case 3: {
				HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
				if (UtilIsX86Pae()) {
					UtilLoadPdptes(*register_used);
				}
				UtilInvvpidSingleContextExceptGlobal(
					static_cast<USHORT>(KeGetCurrentProcessorNumberEx(nullptr) + 1));

				UtilVmWrite(VmcsField::kGuestCr3, *register_used);
				break;
			}

					// CR4 <- Reg
			case 4: {
				HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
				if (UtilIsX86Pae()) {
					UtilLoadPdptes(UtilVmRead(VmcsField::kGuestCr3));
				}
				UtilInvvpidAllContext();
				const Cr4 cr4_fixed0 = { UtilReadMsr(Msr::kIa32VmxCr4Fixed0) };
				const Cr4 cr4_fixed1 = { UtilReadMsr(Msr::kIa32VmxCr4Fixed1) };
				Cr4 cr4 = { *register_used };
				cr4.all &= cr4_fixed1.all;
				cr4.all |= cr4_fixed0.all;
				UtilVmWrite(VmcsField::kGuestCr4, cr4.all);
				UtilVmWrite(VmcsField::kCr4ReadShadow, cr4.all);
				break;
			}

					// CR8 <- Reg
			case 8: {
				HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
				guest_context->cr8 = *register_used;
				break;
			}

			default:
				HYPERPLATFORM_COMMON_BUG_CHECK(HyperPlatformBugCheck::kUnspecified, 0,
					0, 0);
				break;
			}
			break;

		case MovCrAccessType::kMoveFromCr:
			switch (exit_qualification.fields.control_register) {
				// Reg <- CR3
			case 3: {
				HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
				*register_used = UtilVmRead(VmcsField::kGuestCr3);
				break;
			}

					// Reg <- CR8
			case 8: {
				HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
				*register_used = guest_context->cr8;
				break;
			}

			default:
				HYPERPLATFORM_COMMON_BUG_CHECK(HyperPlatformBugCheck::kUnspecified, 0,
					0, 0);
				break;
			}
			break;

			// Unimplemented
		case MovCrAccessType::kClts:
		case MovCrAccessType::kLmsw:
		default:
			HYPERPLATFORM_COMMON_DBG_BREAK();
			break;
		}

		VmmpAdjustGuestInstructionPointer(guest_context);
	}

	// VMCALL
	_Use_decl_annotations_ static void VmmpHandleVmCall(
		GuestContext *guest_context) {
		// VMCALL convention for HyperPlatform:
		//  ecx: hyper-call number (always 32bit)
		//  edx: arbitrary context parameter (pointer size)
		// Any unsuccessful VMCALL will inject #UD into a guest
		const auto hypercall_number =
			static_cast<HypercallNumber>(guest_context->gp_regs->cx);
		const auto context = reinterpret_cast<void *>(guest_context->gp_regs->dx);

		switch (hypercall_number) {
		case HypercallNumber::kTerminateVmm:
			// Unloading requested. This VMCALL is allowed to execute only from CPL=0
			if (VmmpGetGuestCpl() == 0) {
				VmmpHandleVmCallTermination(guest_context, context);
			}
			else {
				VmmpIndicateUnsuccessfulVmcall(guest_context);
			}
			break;
		case HypercallNumber::kPingVmm:
			// Sample VMCALL handler
			HYPERPLATFORM_LOG_INFO_SAFE("Pong by VMM! (context = %p)", context);
			VmmpIndicateSuccessfulVmcall(guest_context);
			break;
		case HypercallNumber::kGetSharedProcessorData:
			*reinterpret_cast<void **>(context) =
				guest_context->stack->processor_data->shared_data;
			VmmpIndicateSuccessfulVmcall(guest_context);
			break;
		default:
			// Unsupported hypercall
			VmmpIndicateUnsuccessfulVmcall(guest_context);
		}
	}

	// INVD
	_Use_decl_annotations_ static void VmmpHandleInvalidateInternalCaches(
		GuestContext *guest_context) {
		HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
		AsmInvalidateInternalCaches();
		VmmpAdjustGuestInstructionPointer(guest_context);
	}

	// INVLPG
	_Use_decl_annotations_ static void VmmpHandleInvalidateTlbEntry(
		GuestContext *guest_context) {
		HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
		const auto invalidate_address =
			reinterpret_cast<void *>(UtilVmRead(VmcsField::kExitQualification));
		__invlpg(invalidate_address);
		UtilInvvpidIndividualAddress(
			static_cast<USHORT>(KeGetCurrentProcessorNumberEx(nullptr) + 1),
			invalidate_address);
		VmmpAdjustGuestInstructionPointer(guest_context);
	}

	// EXIT_REASON_EPT_VIOLATION
	_Use_decl_annotations_ static void VmmpHandleEptViolation(
		GuestContext *guest_context) {
		HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE(); 
		auto processor_data = guest_context->stack->processor_data;

#ifdef __NEST_EPT_ENBLE	
		bool is_ranges_of_ept12 = false;

		if (guest_context->stack->processor_data->EptDat12 && (ULONG64)guest_context->stack->processor_data->EptDat12!= 0xFFFFFFFFFFFFFFFF)
		{
 			is_ranges_of_ept12 = EptpIsInRangesOfEpt(UtilVmRead64(VmcsField::kGuestPhysicalAddress),
				guest_context->stack->processor_data->ept_data,
				guest_context->stack->processor_data->EptDat12->ept_pml4);
		}
		EptHandleEptViolation(processor_data->ept_data, processor_data->EptDat02, is_ranges_of_ept12);
#else
		EptHandleEptViolation(processor_data->ept_data, processor_data->EptDat02, false);
#endif

#ifdef __NEST_EPT_ENBLE
		if (is_ranges_of_ept12)
		{
			ShpSetMonitorTrapFlag(true);
			guest_context->stack->processor_data->LastEptFaultAddr = UtilVmRead64(VmcsField::kGuestPhysicalAddress);
		}
#endif
	}

	// EXIT_REASON_EPT_MISCONFIG
	_Use_decl_annotations_ static void VmmpHandleEptMisconfig(
		GuestContext *guest_context) {
		UNREFERENCED_PARAMETER(guest_context);

		const auto fault_address = UtilVmRead(VmcsField::kGuestPhysicalAddress);
		const auto ept_pt_entry = EptGetEptPtEntry(
			guest_context->stack->processor_data->ept_data, fault_address);
		HYPERPLATFORM_COMMON_BUG_CHECK(HyperPlatformBugCheck::kEptMisconfigVmExit,
			fault_address,
			reinterpret_cast<ULONG_PTR>(ept_pt_entry), 0);
	}

	// Selects a register to be used based on the index
	_Use_decl_annotations_ ULONG_PTR *VmmpSelectRegister(
		ULONG index, GuestContext *guest_context) {
		ULONG_PTR *register_used = nullptr;
		// clang-format off
		switch (index) {
		case 0: register_used = &guest_context->gp_regs->ax; break;
		case 1: register_used = &guest_context->gp_regs->cx; break;
		case 2: register_used = &guest_context->gp_regs->dx; break;
		case 3: register_used = &guest_context->gp_regs->bx; break;
		case 4: register_used = &guest_context->gp_regs->sp; break;
		case 5: register_used = &guest_context->gp_regs->bp; break;
		case 6: register_used = &guest_context->gp_regs->si; break;
		case 7: register_used = &guest_context->gp_regs->di; break;
#if defined(_AMD64_)
		case 8: register_used = &guest_context->gp_regs->r8; break;
		case 9: register_used = &guest_context->gp_regs->r9; break;
		case 10: register_used = &guest_context->gp_regs->r10; break;
		case 11: register_used = &guest_context->gp_regs->r11; break;
		case 12: register_used = &guest_context->gp_regs->r12; break;
		case 13: register_used = &guest_context->gp_regs->r13; break;
		case 14: register_used = &guest_context->gp_regs->r14; break;
		case 15: register_used = &guest_context->gp_regs->r15; break;
#endif
		default: HYPERPLATFORM_COMMON_DBG_BREAK(); break;
		}
		// clang-format on
		return register_used;
	}

	// Dumps guest's selectors
	/*_Use_decl_annotations_*/ static void VmmpDumpGuestSelectors() {
		HYPERPLATFORM_LOG_DEBUG_SAFE(
			"es %04x %p %08x %08x", UtilVmRead(VmcsField::kGuestEsSelector),
			UtilVmRead(VmcsField::kGuestEsBase), UtilVmRead(VmcsField::kGuestEsLimit),
			UtilVmRead(VmcsField::kGuestEsArBytes));
		HYPERPLATFORM_LOG_DEBUG_SAFE(
			"cs %04x %p %08x %08x", UtilVmRead(VmcsField::kGuestCsSelector),
			UtilVmRead(VmcsField::kGuestCsBase), UtilVmRead(VmcsField::kGuestCsLimit),
			UtilVmRead(VmcsField::kGuestCsArBytes));
		HYPERPLATFORM_LOG_DEBUG_SAFE(
			"ss %04x %p %08x %08x", UtilVmRead(VmcsField::kGuestSsSelector),
			UtilVmRead(VmcsField::kGuestSsBase), UtilVmRead(VmcsField::kGuestSsLimit),
			UtilVmRead(VmcsField::kGuestSsArBytes));
		HYPERPLATFORM_LOG_DEBUG_SAFE(
			"ds %04x %p %08x %08x", UtilVmRead(VmcsField::kGuestDsSelector),
			UtilVmRead(VmcsField::kGuestDsBase), UtilVmRead(VmcsField::kGuestDsLimit),
			UtilVmRead(VmcsField::kGuestDsArBytes));
		HYPERPLATFORM_LOG_DEBUG_SAFE(
			"fs %04x %p %08x %08x", UtilVmRead(VmcsField::kGuestFsSelector),
			UtilVmRead(VmcsField::kGuestFsBase), UtilVmRead(VmcsField::kGuestFsLimit),
			UtilVmRead(VmcsField::kGuestFsArBytes));
		HYPERPLATFORM_LOG_DEBUG_SAFE(
			"gs %04x %p %08x %08x", UtilVmRead(VmcsField::kGuestGsSelector),
			UtilVmRead(VmcsField::kGuestGsBase), UtilVmRead(VmcsField::kGuestGsLimit),
			UtilVmRead(VmcsField::kGuestGsArBytes));
		HYPERPLATFORM_LOG_DEBUG_SAFE("ld %04x %p %08x %08x",
			UtilVmRead(VmcsField::kGuestLdtrSelector),
			UtilVmRead(VmcsField::kGuestLdtrBase),
			UtilVmRead(VmcsField::kGuestLdtrLimit),
			UtilVmRead(VmcsField::kGuestLdtrArBytes));
		HYPERPLATFORM_LOG_DEBUG_SAFE(
			"tr %04x %p %08x %08x", UtilVmRead(VmcsField::kGuestTrSelector),
			UtilVmRead(VmcsField::kGuestTrBase), UtilVmRead(VmcsField::kGuestTrLimit),
			UtilVmRead(VmcsField::kGuestTrArBytes));
	}

	// Advances guest's IP to the next instruction
	_Use_decl_annotations_ static void VmmpAdjustGuestInstructionPointer(
		GuestContext *guest_context) {
		const auto exit_inst_length = UtilVmRead(VmcsField::kVmExitInstructionLen);
		UtilVmWrite(VmcsField::kGuestRip, guest_context->ip + exit_inst_length);

		// Inject #DB if TF is set
		if (guest_context->flag_reg.fields.tf) {
			VmmpInjectInterruption(InterruptionType::kHardwareException,
				InterruptionVector::kDebugException, false, 0);
			UtilVmWrite(VmcsField::kVmEntryInstructionLen, exit_inst_length);
		}
	}

	// Handle VMRESUME or VMXOFF failure. Fatal error.
	_Use_decl_annotations_ void __stdcall VmmVmxFailureHandler(
		AllRegisters *all_regs) {
		const auto guest_ip = UtilVmRead(VmcsField::kGuestRip);
		// See: VM-Instruction Error Numbers
		const auto vmx_error = (all_regs->flags.fields.zf)
			? UtilVmRead(VmcsField::kVmInstructionError)
			: 0;
		HYPERPLATFORM_COMMON_BUG_CHECK(
			HyperPlatformBugCheck::kCriticalVmxInstructionFailure, vmx_error, 0, 0);
	}

	// Saves all supported user state components (x87, SSE, AVX states)
	_Use_decl_annotations_ static void VmmpSaveExtendedProcessorState(
		GuestContext *guest_context) {
		// Clear the TS flag temporarily since XSAVE/XRSTOR raise #NM
		Cr0 cr0 = { __readcr0() };
		const auto old_cr0 = cr0;
		cr0.fields.ts = false;
		__writecr0(cr0.all);
		if (guest_context->stack->processor_data->xsave_inst_mask) {
			_xsave(guest_context->stack->processor_data->xsave_area,
				guest_context->stack->processor_data->xsave_inst_mask);
		}
		else {
			// Advances an address up to 15 bytes to be 16-byte aligned
			auto alignment = reinterpret_cast<ULONG_PTR>(
				guest_context->stack->processor_data->fxsave_area) %
				16;
			alignment = (alignment) ? 16 - alignment : 0;
			_fxsave(guest_context->stack->processor_data->fxsave_area + alignment);
		}
		__writecr0(old_cr0.all);


	}

	// Restores all supported user state components (x87, SSE, AVX states)
	_Use_decl_annotations_ static void VmmpRestoreExtendedProcessorState(
		GuestContext *guest_context) {
		// Clear the TS flag temporarily since XSAVE/XRSTOR raise #NM
		Cr0 cr0 = { __readcr0() };
		const auto old_cr0 = cr0;
		cr0.fields.ts = false;
		__writecr0(cr0.all);
		if (guest_context->stack->processor_data->xsave_inst_mask) {
			_xrstor(guest_context->stack->processor_data->xsave_area,
				guest_context->stack->processor_data->xsave_inst_mask);
		}
		else {
			// Advances an address up to 15 bytes to be 16-byte aligned
			auto alignment = reinterpret_cast<ULONG_PTR>(
				guest_context->stack->processor_data->fxsave_area) %
				16;
			alignment = (alignment) ? 16 - alignment : 0;
			_fxsave(guest_context->stack->processor_data->fxsave_area + alignment);
		}
		__writecr0(old_cr0.all);
	}

	// Indicates successful VMCALL
	_Use_decl_annotations_ static void VmmpIndicateSuccessfulVmcall(
		GuestContext *guest_context) {
		// See "CONVENTIONS"
		guest_context->flag_reg.fields.cf = false;
		guest_context->flag_reg.fields.pf = false;
		guest_context->flag_reg.fields.af = false;
		guest_context->flag_reg.fields.zf = false;
		guest_context->flag_reg.fields.sf = false;
		guest_context->flag_reg.fields.of = false;
		guest_context->flag_reg.fields.cf = false;
		guest_context->flag_reg.fields.zf = false;
		UtilVmWrite(VmcsField::kGuestRflags, guest_context->flag_reg.all);
		VmmpAdjustGuestInstructionPointer(guest_context);
	}

	// Indicates unsuccessful VMCALL
	_Use_decl_annotations_ static void VmmpIndicateUnsuccessfulVmcall(
		GuestContext *guest_context) {
		UNREFERENCED_PARAMETER(guest_context);

		VmmpInjectInterruption(InterruptionType::kHardwareException,
			InterruptionVector::kInvalidOpcodeException, false, 0);
		UtilVmWrite(VmcsField::kVmEntryInstructionLen, 3);  // VMCALL is 3 bytes
	}

	// Handles an unloading request
	_Use_decl_annotations_ static void VmmpHandleVmCallTermination(
		GuestContext *guest_context, void *context) {
		// The processor sets ffff to limits of IDT and GDT when VM-exit occurred.
		// It is not correct value but fine to ignore since vmresume loads correct
		// values from VMCS. But here, we are going to skip vmresume and simply
		// return to where VMCALL is executed. It results in keeping those broken
		// values and ends up with bug check 109, so we should fix them manually.
		const auto gdt_limit = UtilVmRead(VmcsField::kGuestGdtrLimit);
		const auto gdt_base = UtilVmRead(VmcsField::kGuestGdtrBase);
		const auto idt_limit = UtilVmRead(VmcsField::kGuestIdtrLimit);
		const auto idt_base = UtilVmRead(VmcsField::kGuestIdtrBase);
		Gdtr gdtr = { static_cast<USHORT>(gdt_limit), gdt_base };
		Idtr idtr = { static_cast<USHORT>(idt_limit), idt_base };
		__lgdt(&gdtr);
		__lidt(&idtr);

		// Store an address of the management structure to the context parameter
		const auto result_ptr = reinterpret_cast<ProcessorData **>(context);
		*result_ptr = guest_context->stack->processor_data;
		HYPERPLATFORM_LOG_DEBUG_SAFE("Context at %p %p", context,
			guest_context->stack->processor_data);

		// Set rip to the next instruction of VMCALL
		const auto exit_instruction_length =
			UtilVmRead(VmcsField::kVmExitInstructionLen);
		const auto return_address = guest_context->ip + exit_instruction_length;

		// Since the flag register is overwritten after VMXOFF, we should manually
		// indicates that VMCALL was successful by clearing those flags.
		// See "CONVENTIONS"
		guest_context->flag_reg.fields.cf = false;
		guest_context->flag_reg.fields.pf = false;
		guest_context->flag_reg.fields.af = false;
		guest_context->flag_reg.fields.zf = false;
		guest_context->flag_reg.fields.sf = false;
		guest_context->flag_reg.fields.of = false;
		guest_context->flag_reg.fields.cf = false;
		guest_context->flag_reg.fields.zf = false;

		// Set registers used after VMXOFF to recover the context. Volatile
		// registers must be used because those changes are reflected to the
		// guest's context after VMXOFF.
		guest_context->gp_regs->cx = return_address;
		guest_context->gp_regs->dx = guest_context->gp_regs->sp;
		guest_context->gp_regs->ax = guest_context->flag_reg.all;
		guest_context->vm_continue = false;
	}

	// Returns guest's CPL
	/*_Use_decl_annotations_*/ static UCHAR VmmpGetGuestCpl() {
		VmxSegmentDescriptorAccessRight ar = {
			static_cast<unsigned int>(UtilVmRead(VmcsField::kGuestSsArBytes)) };
		return ar.fields.dpl;
	}
	static bool IsBenignException(InterruptionVector vector)
	{
		switch (vector)
		{
		case InterruptionVector::kDebugException:
		case InterruptionVector::kNmiInterrupt:
		case InterruptionVector::kBreakpointException:
		case InterruptionVector::kOverflowException:
		case InterruptionVector::kBoundRangeExceededException:
		case InterruptionVector::kInvalidOpcodeException:
		case InterruptionVector::kDeviceNotAvailableException:
		case InterruptionVector::kCoprocessorSegmentOverrun:
		case InterruptionVector::kx87FpuFloatingPointError:
		case InterruptionVector::kAlignmentCheckException:
		case InterruptionVector::kMachineCheckException:
		case InterruptionVector::kSimdFloatingPointException:
			return true;
		default:
			return false;
		}
	}
	static bool IsContributoryException(InterruptionVector vector)
	{
		switch (vector)
		{
		case InterruptionVector::kDivideErrorException:
		case InterruptionVector::kInvalidTssException:
		case InterruptionVector::kSegmentNotPresent:
		case InterruptionVector::kStackFaultException:
			return true;
		default:
			return false;
		}
	}
	// Injects interruption to a guest
	_Use_decl_annotations_ static void VmmpInjectInterruption(
		InterruptionType interruption_type, InterruptionVector vector,
		bool deliver_error_code, ULONG32 error_code)
	{
		IdtVectoringInformationField idt_vectoring = { UtilVmRead(VmcsField::kIdtVectoringInfoField) };
		if (idt_vectoring.fields.valid)
		{
			if (InterruptionType::kHardwareException != static_cast<InterruptionType>(idt_vectoring.fields.interruption_type)
				|| IsBenignException(static_cast<InterruptionVector>(idt_vectoring.fields.vector))
				|| IsBenignException(vector)
				|| (IsContributoryException(static_cast<InterruptionVector>(idt_vectoring.fields.vector)) && InterruptionVector::kPageFaultException == vector)
				)
			{
				VmEntryInterruptionInformationField inject = {};
				inject.fields.valid = true;
				inject.fields.interruption_type = static_cast<ULONG32>(interruption_type);
				inject.fields.vector = static_cast<ULONG32>(vector);
				inject.fields.deliver_error_code = deliver_error_code;
				UtilVmWrite(VmcsField::kVmEntryIntrInfoField, inject.all);

				if (deliver_error_code) {
					UtilVmWrite(VmcsField::kVmEntryExceptionErrorCode, error_code);
				}

			}
			else if (InterruptionType::kHardwareException == static_cast<InterruptionType>(idt_vectoring.fields.interruption_type))
			{
				if ((IsContributoryException(vector) && IsContributoryException(static_cast<InterruptionVector>(idt_vectoring.fields.vector)))
					|| ((IsContributoryException(vector) || InterruptionVector::kPageFaultException == vector) &&
						static_cast<InterruptionVector>(idt_vectoring.fields.vector) == InterruptionVector::kPageFaultException
						)
					)
				{
					//double fault
					VmEntryInterruptionInformationField inject = {};
					inject.fields.valid = true;
					inject.fields.interruption_type = static_cast<ULONG32>(InterruptionType::kHardwareException);
					inject.fields.vector = static_cast<ULONG32>(InterruptionVector::kDoubleFaultException);
					inject.fields.deliver_error_code = 1;
					UtilVmWrite(VmcsField::kVmEntryIntrInfoField, inject.all);
					UtilVmWrite(VmcsField::kVmEntryExceptionErrorCode, 0);
				}
			}
			const PageFaultErrorCode fault_code = {
				static_cast<ULONG32>(UtilVmRead(VmcsField::kVmExitIntrErrorCode)) };

			const auto fault_address = UtilVmRead(VmcsField::kExitQualification);

			PrintVMCS();

			HYPERPLATFORM_COMMON_DBG_BREAK();
		}
		else
		{
			VmEntryInterruptionInformationField inject = {};
			inject.fields.valid = true;
			inject.fields.interruption_type = static_cast<ULONG32>(interruption_type);
			inject.fields.vector = static_cast<ULONG32>(vector);
			inject.fields.deliver_error_code = deliver_error_code;
			UtilVmWrite(VmcsField::kVmEntryIntrInfoField, inject.all);

			if (deliver_error_code) {
				UtilVmWrite(VmcsField::kVmEntryExceptionErrorCode, error_code);
			}
		}
	}

	//----------------------------------------------------------------------------------------------------------------//
	_Use_decl_annotations_ static void VmmpHandleVmx(GuestContext *guest_context)
	{
		HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();


		//	Assumption:  If and only If trapped by L1 only,
		//    TODO	  :  Trapped by L2 handler

		const VmExitInformation exit_reason = {
			static_cast<ULONG32>(UtilVmRead(VmcsField::kVmExitReason)) };
		switch (exit_reason.fields.reason)
		{
		case VmxExitReason::kVmon:
		{
			VmxVmxonEmulate(guest_context);
		}
		break;

		/*
		Simpily clear VMCS02 and VMCS12
		*/
		case VmxExitReason::kVmclear:
		{
			VmxVmclearEmulate(guest_context);
		}
		break;

		/*
		Load VMCS02 into physical cpu , And perform some check on VMCS12
		*/
		case VmxExitReason::kVmptrld:
		{
			VmxVmptrldEmulate(guest_context);
		}
		break;

		case VmxExitReason::kVmptrst:
		{
			VmxVmptrstEmulate(guest_context);
		}
		break;
		/// TODO:
		case VmxExitReason::kVmoff:
		{ 
			VmxVmxoffEmulate(guest_context);
		}
		break;
		/*
		ReadWrite on VMCS12
		*/
		case VmxExitReason::kVmwrite:
		{
			VmxVmwriteEmulate(guest_context);
		}
		break;
		/*
		ReadWrite on VMCS12
		*/
		case VmxExitReason::kVmread:
		{
			VmxVmreadEmulate(guest_context);
		}
		break;

		case VmxExitReason::kVmlaunch:
		{
			VmxVmlaunchEmulate(guest_context);
		}
		break;

		case VmxExitReason::kVmresume:
		{
			//In VmxVmresumeEmulate will modify Guest Rip so no need to execute anymore after it returns.
			//And should not execute anymore.

			//Vmresume Emulation :
			//- Fill Guest, Host, Control field state in VMCS02
			//- Read GuestRIP from VMCS02 as it is trapped by L2 if Vmresume is trapped by L1
			//- So we need to help L1 to resume to L2
			//- We saved the vmcs02 GuestRip into VMCS12 our VMExit Handler, 
			//- because when L1 is executing VMRESUME, it is running on VMCS01
			VmxVmresumeEmulate(guest_context);
			return;
		}
		break;

		case VmxExitReason::kVmxPreemptionTime:
		{
			VMSucceed(&guest_context->flag_reg);
			HYPERPLATFORM_LOG_DEBUG_SAFE("nested kVmwrite \r\n");
		}
		break;

		case VmxExitReason::kInvept:
		default:
		{
			UtilInveptGlobal();
			VMSucceed(&guest_context->flag_reg); 
		}
		break;
		}

		/***************changed 2017.6.5 by wwq vmresume don't need invoke VmmpAdjustGuestInstructionPointer***********/
		if (exit_reason.fields.reason != VmxExitReason::kVmresume|| exit_reason.fields.reason != VmxExitReason::kVmoff)
		{
			VmmpAdjustGuestInstructionPointer(guest_context);
		}
		UtilVmWrite(VmcsField::kGuestRflags, guest_context->flag_reg.all);
	}
}  // extern "C"
