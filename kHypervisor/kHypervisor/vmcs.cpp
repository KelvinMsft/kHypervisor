/*++

Copyright (c) 2016 KelvinChan. All rights reserved.
Use of this source code is governed by a MIT-style license that can be
found in the LICENSE file.

Module Name:

	vmcs.cpp

Abstract:

	VMCS utilies

Author:
	
	Kelvin Chan

Environment:

	Kernel VMM Mode

--*/
#include <fltKernel.h>
#include <intrin.h>
#include "vmcs.h"
#include "..\HyperPlatform\util.h" 
#include "..\HyperPlatform\common.h"
#include "..\HyperPlatform\asm.h"
#include "..\HyperPlatform\log.h"   
#include "..\HyperPlatform\ept.h"
 

extern "C" 
{
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////
//// Variable
////
unsigned	g_vmcs_map[16][1 + VMX_HIGHEST_VMCS_ENCODING];

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////
//// Prototype
////
extern 	BOOLEAN VmxIsGuestPaePaging();

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////
//// Marco
////

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////
//// Implementation
////
//----------------------------------------------------------------------------------------------------------------//
VOID 
VmcsPrintAllFieldForVmcs12(
	_In_ const char* func,
	_In_ ULONG64 vmcs12
)
{
	HYPERPLATFORM_LOG_DEBUG("------------------------- Start Print VMCS12 by %s -----------------------------", func);
	VmcsPrintReadOnlyFieldForVmcs12(vmcs12);
	HYPERPLATFORM_LOG_DEBUG_SAFE("------------------------- End Printed VMCS12 by %s -----------------------------", func);

}
//----------------------------------------------------------------------------------------------------------------//
VOID
VmcsPrintAllField(
	_In_ const char* func
)
{
	HYPERPLATFORM_LOG_DEBUG_SAFE("------------------------- Start Printe Current VMCS by %s -----------------------------", func);
	VmcsPrintControlField();
	VmcsPrintHostStateField();
	VmcsPrintGuestStateField();
	VmcsPrintReadOnlyField();
	HYPERPLATFORM_LOG_DEBUG_SAFE("kIa32GsBase: %I64X kIa32KernelGsBase: %I64X \r\n", UtilReadMsr(Msr::kIa32GsBase), UtilReadMsr(Msr::kIa32KernelGsBase));
	HYPERPLATFORM_LOG_DEBUG_SAFE("------------------------- End Printed Current VMCS by %s -----------------------------", func);
}
//----------------------------------------------------------------------------------------------------------------// 
VOID	 
VmcsPrintReadOnlyFieldForVmcs12(
	_In_ ULONG64 vmcs12_va
)
{
	ULONG64 kVmInstructionError = 0;
	ULONG64 kVmExitReason = 0; 
	ULONG64 kVmExitIntrInfo = 0; 
	ULONG64	kVmExitIntrErrorCode = 0;
	ULONG64	kIdtVectoringInfoField = 0;
	ULONG64	kIdtVectoringErrorCode = 0;
	ULONG64	kVmExitInstructionLen = 0;
	ULONG64	kVmxInstructionInfo = 0;
	VmcsVmRead64(VmcsField::kVmInstructionError, vmcs12_va, &kVmInstructionError);
	VmcsVmRead64(VmcsField::kVmExitReason     , vmcs12_va, &kVmExitReason);
	VmcsVmRead64(VmcsField::kVmExitIntrInfo   , vmcs12_va, &kVmExitIntrInfo);
	VmcsVmRead64(VmcsField::kVmExitIntrErrorCode, vmcs12_va, &kVmExitIntrErrorCode);
	VmcsVmRead64(VmcsField::kIdtVectoringInfoField, vmcs12_va, &kIdtVectoringInfoField);
	VmcsVmRead64(VmcsField::kIdtVectoringErrorCode, vmcs12_va, &kIdtVectoringErrorCode);
	VmcsVmRead64(VmcsField::kVmExitInstructionLen, vmcs12_va, &kVmExitInstructionLen);
	VmcsVmRead64(VmcsField::kVmxInstructionInfo, vmcs12_va, &kVmxInstructionInfo);

	HYPERPLATFORM_LOG_DEBUG_SAFE("kVmInstructionError	:%I64X  ", kVmInstructionError);
	HYPERPLATFORM_LOG_DEBUG_SAFE("kVmExitReason			:%I64X  ", kVmExitReason);
	HYPERPLATFORM_LOG_DEBUG_SAFE("kVmExitIntrInfo		:%I64X  ", kVmExitIntrInfo);
	HYPERPLATFORM_LOG_DEBUG_SAFE("kVmExitIntrErrorCode	:%I64X  ", kVmExitIntrErrorCode);
	HYPERPLATFORM_LOG_DEBUG_SAFE("kIdtVectoringInfoField	:%I64X  ", kIdtVectoringInfoField);
	HYPERPLATFORM_LOG_DEBUG_SAFE("kIdtVectoringErrorCode	:%I64X  ", kIdtVectoringErrorCode);
	HYPERPLATFORM_LOG_DEBUG_SAFE("kVmExitInstructionLen	:%I64X  ", kVmExitInstructionLen);
	HYPERPLATFORM_LOG_DEBUG_SAFE("kVmxInstructionInfo	:%I64X  ", kVmxInstructionInfo);
}

//---------------------------------------------------------------------------------------------------------------------------//
VOID 
VmcsPrintHostStateField()
{

	HYPERPLATFORM_LOG_DEBUG("###################### 16bit Host State #############################");
	HYPERPLATFORM_LOG_DEBUG("kHostCsSelector : %X", UtilVmRead(VmcsField::kHostCsSelector));
	HYPERPLATFORM_LOG_DEBUG("kHostDsSelector : %X", UtilVmRead(VmcsField::kHostDsSelector));
	HYPERPLATFORM_LOG_DEBUG("kHostEsSelector : %X", UtilVmRead(VmcsField::kHostEsSelector));
	HYPERPLATFORM_LOG_DEBUG("kHostSsSelector : %X", UtilVmRead(VmcsField::kHostSsSelector));
	HYPERPLATFORM_LOG_DEBUG("kHostFsSelector : %X", UtilVmRead(VmcsField::kHostFsSelector));
	HYPERPLATFORM_LOG_DEBUG("kHostGsSelector : %X", UtilVmRead(VmcsField::kHostGsSelector));
	HYPERPLATFORM_LOG_DEBUG("kHostTrSelector : %X", UtilVmRead(VmcsField::kHostTrSelector));

	/*
	Host 32 bit state field
	*/
	HYPERPLATFORM_LOG_DEBUG("###################### 32bit Host State #############################");

	HYPERPLATFORM_LOG_DEBUG(" %.8X", UtilVmRead(VmcsField::kHostIa32SysenterCs));


	HYPERPLATFORM_LOG_DEBUG("###################### 64bit Host State #############################");

	HYPERPLATFORM_LOG_DEBUG("kHostCr0 %I64X", UtilVmRead64(VmcsField::kHostCr0));
	HYPERPLATFORM_LOG_DEBUG("kHostCr3 %I64X", UtilVmRead64(VmcsField::kHostCr3));
	HYPERPLATFORM_LOG_DEBUG("kHostCr4 %I64X", UtilVmRead64(VmcsField::kHostCr4));
	HYPERPLATFORM_LOG_DEBUG("kHostFsBase %I64X", UtilVmRead64(VmcsField::kHostFsBase));
	HYPERPLATFORM_LOG_DEBUG("kHostGsBase %I64X", UtilVmRead64(VmcsField::kHostGsBase));
	HYPERPLATFORM_LOG_DEBUG("kHostTrBase %I64X", UtilVmRead64(VmcsField::kHostTrBase));
	HYPERPLATFORM_LOG_DEBUG("kHostGdtrBase %I64X", UtilVmRead64(VmcsField::kHostGdtrBase));
	HYPERPLATFORM_LOG_DEBUG("kHostIdtrBase %I64X", UtilVmRead64(VmcsField::kHostIdtrBase));
	HYPERPLATFORM_LOG_DEBUG("kHostIa32SysenterEsp %I64X", UtilVmRead64(VmcsField::kHostIa32SysenterEsp));
	HYPERPLATFORM_LOG_DEBUG("kHostIa32SysenterEip %I64X", UtilVmRead64(VmcsField::kHostIa32SysenterEip));
	HYPERPLATFORM_LOG_DEBUG("kHostRsp %I64X", UtilVmRead64(VmcsField::kHostRsp));
	HYPERPLATFORM_LOG_DEBUG("kHostRip %I64X", UtilVmRead64(VmcsField::kHostRip));

}

//---------------------------------------------------------------------------------------------------------------------------//
VOID
VmcsPrintControlField()
{

	HYPERPLATFORM_LOG_DEBUG("###################### 16bit Control State #############################");


	HYPERPLATFORM_LOG_DEBUG("kHostIa32Pat: %x", UtilVmRead(VmcsField::kHostIa32Pat));
	HYPERPLATFORM_LOG_DEBUG("kHostIa32PatHigh: %x", UtilVmRead(VmcsField::kHostIa32PatHigh));
	HYPERPLATFORM_LOG_DEBUG("kHostIa32Efer: %x", UtilVmRead(VmcsField::kHostIa32Efer));
	HYPERPLATFORM_LOG_DEBUG("kHostIa32EferHigh: %x", UtilVmRead(VmcsField::kHostIa32EferHigh));
	HYPERPLATFORM_LOG_DEBUG("kHostIa32PerfGlobalCtrl: %x", UtilVmRead(VmcsField::kHostIa32PerfGlobalCtrl));
	HYPERPLATFORM_LOG_DEBUG("kHostIa32PerfGlobalCtrlHigh: %x", UtilVmRead(VmcsField::kHostIa32PerfGlobalCtrlHigh));

	HYPERPLATFORM_LOG_DEBUG("###################### 32bit Control State #############################");


	HYPERPLATFORM_LOG_DEBUG("kPinBasedVmExecControl: %x", UtilVmRead(VmcsField::kPinBasedVmExecControl));
	HYPERPLATFORM_LOG_DEBUG("kCpuBasedVmExecControl: %x", UtilVmRead(VmcsField::kCpuBasedVmExecControl));
	HYPERPLATFORM_LOG_DEBUG("kExceptionBitmap: %x", UtilVmRead(VmcsField::kExceptionBitmap));
	HYPERPLATFORM_LOG_DEBUG("kPageFaultErrorCodeMask: %x", UtilVmRead(VmcsField::kPageFaultErrorCodeMask));
	HYPERPLATFORM_LOG_DEBUG("kPageFaultErrorCodeMatch: %x", UtilVmRead(VmcsField::kPageFaultErrorCodeMatch));
	HYPERPLATFORM_LOG_DEBUG("kCr3TargetCount: %x", UtilVmRead(VmcsField::kCr3TargetCount));
	HYPERPLATFORM_LOG_DEBUG("kVmExitControls: %x", UtilVmRead(VmcsField::kVmExitControls));
	HYPERPLATFORM_LOG_DEBUG("kVmExitMsrStoreCount: %x", UtilVmRead(VmcsField::kVmExitMsrStoreCount));
	HYPERPLATFORM_LOG_DEBUG("kVmExitMsrLoadCount: %x", UtilVmRead(VmcsField::kVmExitMsrLoadCount));
	HYPERPLATFORM_LOG_DEBUG("kVmEntryControls: %x", UtilVmRead(VmcsField::kVmEntryControls));
	HYPERPLATFORM_LOG_DEBUG("kVmEntryMsrLoadCount: %x", UtilVmRead(VmcsField::kVmEntryMsrLoadCount));
	HYPERPLATFORM_LOG_DEBUG("kVmEntryIntrInfoField: %x", UtilVmRead(VmcsField::kVmEntryIntrInfoField));
	HYPERPLATFORM_LOG_DEBUG("kVmEntryExceptionErrorCode: %x", UtilVmRead(VmcsField::kVmEntryExceptionErrorCode));
	HYPERPLATFORM_LOG_DEBUG("kVmEntryInstructionLen: %x", UtilVmRead(VmcsField::kVmEntryInstructionLen));
	HYPERPLATFORM_LOG_DEBUG("kTprThreshold: %x", UtilVmRead(VmcsField::kTprThreshold));
	HYPERPLATFORM_LOG_DEBUG("kPleGap: %x", UtilVmRead(VmcsField::kPleGap));
	HYPERPLATFORM_LOG_DEBUG("kPleWindow: %x", UtilVmRead(VmcsField::kPleWindow));
	HYPERPLATFORM_LOG_DEBUG("kSecondaryVmExecControl: %x", UtilVmRead(VmcsField::kSecondaryVmExecControl));


	HYPERPLATFORM_LOG_DEBUG("###################### 64bit Control State #############################");

	HYPERPLATFORM_LOG_DEBUG("kIoBitmapA: %I64X", UtilVmRead64(VmcsField::kIoBitmapA));
	HYPERPLATFORM_LOG_DEBUG("kIoBitmapB: %I64X", UtilVmRead64(VmcsField::kIoBitmapB));
	HYPERPLATFORM_LOG_DEBUG("kMsrBitmap: %I64X", UtilVmRead64(VmcsField::kMsrBitmap));
	HYPERPLATFORM_LOG_DEBUG("kPmlAddress: %I64X", UtilVmRead64(VmcsField::kPmlAddress));
	HYPERPLATFORM_LOG_DEBUG("kApicAccessAddr: %I64X", UtilVmRead64(VmcsField::kApicAccessAddr));
	HYPERPLATFORM_LOG_DEBUG("kVmFuncCtls: %I64X", UtilVmRead64(VmcsField::kVmFuncCtls));
	HYPERPLATFORM_LOG_DEBUG("kEptPointer: %I64X", UtilVmRead64(VmcsField::kEptPointer));
	HYPERPLATFORM_LOG_DEBUG("kEoiExitBitmap0: %I64X", UtilVmRead64(VmcsField::kEoiExitBitmap0));
	HYPERPLATFORM_LOG_DEBUG("kEoiExitBitmap0High: %I64X", UtilVmRead64(VmcsField::kEoiExitBitmap0High));
	HYPERPLATFORM_LOG_DEBUG("kEoiExitBitmap1: %I64X", UtilVmRead64(VmcsField::kEoiExitBitmap1));
	HYPERPLATFORM_LOG_DEBUG("kEoiExitBitmap1High: %I64X", UtilVmRead64(VmcsField::kEoiExitBitmap1High));
	HYPERPLATFORM_LOG_DEBUG("kEoiExitBitmap2: %I64X", UtilVmRead64(VmcsField::kEoiExitBitmap2));
	HYPERPLATFORM_LOG_DEBUG("kEoiExitBitmap2High: %I64X", UtilVmRead64(VmcsField::kEoiExitBitmap2High));
	HYPERPLATFORM_LOG_DEBUG("kEoiExitBitmap3: %I64X", UtilVmRead64(VmcsField::kEoiExitBitmap3));
	HYPERPLATFORM_LOG_DEBUG("kEoiExitBitmap3High: %I64X", UtilVmRead64(VmcsField::kEoiExitBitmap3High));
	HYPERPLATFORM_LOG_DEBUG("kEptpListAddress: %I64X", UtilVmRead64(VmcsField::kEptpListAddress));


	HYPERPLATFORM_LOG_DEBUG("###################### Natural Control State #############################");

	/*
	Natural-width field
	*/
	HYPERPLATFORM_LOG_DEBUG("kCr0GuestHostMask: %I64X", UtilVmRead64(VmcsField::kCr0GuestHostMask));
	HYPERPLATFORM_LOG_DEBUG("kCr4GuestHostMask: %I64X", UtilVmRead64(VmcsField::kCr4GuestHostMask));
	HYPERPLATFORM_LOG_DEBUG("kCr0ReadShadow: %I64X", UtilVmRead64(VmcsField::kCr0ReadShadow));
	HYPERPLATFORM_LOG_DEBUG("kCr4ReadShadow: %I64X", UtilVmRead64(VmcsField::kCr4ReadShadow));
	HYPERPLATFORM_LOG_DEBUG("kCr3TargetValue0: %I64X", UtilVmRead64(VmcsField::kCr3TargetValue0));
	HYPERPLATFORM_LOG_DEBUG("kCr3TargetValue1: %I64X", UtilVmRead64(VmcsField::kCr3TargetValue1));
	HYPERPLATFORM_LOG_DEBUG("kCr3TargetValue2: %I64X", UtilVmRead64(VmcsField::kCr3TargetValue2));
	HYPERPLATFORM_LOG_DEBUG("kCr3TargetValue3: %I64X", UtilVmRead64(VmcsField::kCr3TargetValue3));
}


//---------------------------------------------------------------------------------------------------------------------------//
VOID 
VmcsPrintGuestStateField()
{

	HYPERPLATFORM_LOG_DEBUG("###################### 16bit Guest State #############################");
	//16bit guest state field 
	HYPERPLATFORM_LOG_DEBUG("kGuestEsSelector: %x  ", UtilVmRead(VmcsField::kGuestEsSelector));
	HYPERPLATFORM_LOG_DEBUG("kGuestCsSelector: %x  ", UtilVmRead(VmcsField::kGuestCsSelector));
	HYPERPLATFORM_LOG_DEBUG("kGuestSsSelector: %x  ", UtilVmRead(VmcsField::kGuestSsSelector));
	HYPERPLATFORM_LOG_DEBUG("kGuestDsSelector: %x  ", UtilVmRead(VmcsField::kGuestDsSelector));
	HYPERPLATFORM_LOG_DEBUG("kGuestFsSelector: %x  ", UtilVmRead(VmcsField::kGuestFsSelector));
	HYPERPLATFORM_LOG_DEBUG("kGuestGsSelector: %x  ", UtilVmRead(VmcsField::kGuestGsSelector));
	HYPERPLATFORM_LOG_DEBUG("kGuestLdtrSelector: %x  ", UtilVmRead(VmcsField::kGuestLdtrSelector));
	HYPERPLATFORM_LOG_DEBUG("kGuestTrSelector: %x  ", UtilVmRead(VmcsField::kGuestTrSelector));

	HYPERPLATFORM_LOG_DEBUG("###################### 32bit Guest State #############################");
	//32bit guest state field
	HYPERPLATFORM_LOG_DEBUG ("kGuestEsLimit: %.8x  ", UtilVmRead(VmcsField::kGuestEsLimit));
	HYPERPLATFORM_LOG_DEBUG ("kGuestCsLimit: %.8x  ", UtilVmRead(VmcsField::kGuestCsLimit));
	HYPERPLATFORM_LOG_DEBUG ("kGuestSsLimit: %.8x  ", UtilVmRead(VmcsField::kGuestSsLimit));
	HYPERPLATFORM_LOG_DEBUG ("kGuestDsLimit: %.8x  ", UtilVmRead(VmcsField::kGuestDsLimit));
	HYPERPLATFORM_LOG_DEBUG ("kGuestFsLimit: %.8x  ", UtilVmRead(VmcsField::kGuestFsLimit));
	HYPERPLATFORM_LOG_DEBUG ("kGuestGsLimit: %.8x  ", UtilVmRead(VmcsField::kGuestGsLimit));
	HYPERPLATFORM_LOG_DEBUG ("kGuestLdtrLimit: %.8x  ", UtilVmRead(VmcsField::kGuestLdtrLimit));
	HYPERPLATFORM_LOG_DEBUG ("kGuestTrLimit: %.8x  ", UtilVmRead(VmcsField::kGuestTrLimit));
	HYPERPLATFORM_LOG_DEBUG ("kGuestGdtrLimit: %.8x  ", UtilVmRead(VmcsField::kGuestGdtrLimit));
	HYPERPLATFORM_LOG_DEBUG ("kGuestIdtrLimit: %.8x  ", UtilVmRead(VmcsField::kGuestIdtrLimit));
	HYPERPLATFORM_LOG_DEBUG ("kGuestEsArBytes: %.8x  ", UtilVmRead(VmcsField::kGuestEsArBytes));
	HYPERPLATFORM_LOG_DEBUG ("kGuestCsArBytes: %.8x  ", UtilVmRead(VmcsField::kGuestCsArBytes));
	HYPERPLATFORM_LOG_DEBUG ("kGuestSsArBytes: %.8x  ", UtilVmRead(VmcsField::kGuestSsArBytes));
	HYPERPLATFORM_LOG_DEBUG ("kGuestDsArBytes: %.8x  ", UtilVmRead(VmcsField::kGuestDsArBytes));
	HYPERPLATFORM_LOG_DEBUG ("kGuestFsArBytes: %.8x  ", UtilVmRead(VmcsField::kGuestFsArBytes));
	HYPERPLATFORM_LOG_DEBUG ("kGuestGsArBytes: %.8x  ", UtilVmRead(VmcsField::kGuestGsArBytes));
	HYPERPLATFORM_LOG_DEBUG ("kGuestLdtrArBytes: %.8x  ", UtilVmRead(VmcsField::kGuestLdtrArBytes));
	HYPERPLATFORM_LOG_DEBUG ("kGuestTrArBytes: %.8x  ", UtilVmRead(VmcsField::kGuestTrArBytes));
	HYPERPLATFORM_LOG_DEBUG ("kGuestInterruptibilityInfo: %.8x  ", UtilVmRead(VmcsField::kGuestInterruptibilityInfo));
	HYPERPLATFORM_LOG_DEBUG ("kGuestActivityState: %.8x  ", UtilVmRead(VmcsField::kGuestActivityState));
	HYPERPLATFORM_LOG_DEBUG ("kGuestSysenterCs: %.8x  ", UtilVmRead(VmcsField::kGuestSysenterCs));

	HYPERPLATFORM_LOG_DEBUG("###################### 64bit Guest State #############################");
	//64bit guest state field 
	HYPERPLATFORM_LOG_DEBUG("kVmcsLinkPointer: %I64X  ", UtilVmRead64(VmcsField::kVmcsLinkPointer));
	HYPERPLATFORM_LOG_DEBUG("kGuestIa32Debugctl: %I64X  ", UtilVmRead64(VmcsField::kGuestIa32Debugctl));


	HYPERPLATFORM_LOG_DEBUG("###################### Natural Guest State #############################");
	//natural			   
	HYPERPLATFORM_LOG_DEBUG("kGuestCr0: %I64X  ", UtilVmRead(VmcsField::kGuestCr0));
	HYPERPLATFORM_LOG_DEBUG("kGuestCr3: %I64X  ", UtilVmRead(VmcsField::kGuestCr3));
	HYPERPLATFORM_LOG_DEBUG("kGuestCr4: %I64X  ", UtilVmRead(VmcsField::kGuestCr4));
						   
	HYPERPLATFORM_LOG_DEBUG("kGuestEsBase: %I64X  ", UtilVmRead(VmcsField::kGuestEsBase));
	HYPERPLATFORM_LOG_DEBUG("kGuestCsBase: %I64X  ", UtilVmRead(VmcsField::kGuestCsBase));
	HYPERPLATFORM_LOG_DEBUG("kGuestSsBase: %I64X  ", UtilVmRead(VmcsField::kGuestSsBase));
	HYPERPLATFORM_LOG_DEBUG("kGuestDsBase: %I64X  ", UtilVmRead(VmcsField::kGuestDsBase));
	HYPERPLATFORM_LOG_DEBUG("kGuestFsBase: %I64X  ", UtilVmRead(VmcsField::kGuestFsBase));
	HYPERPLATFORM_LOG_DEBUG("kGuestGsBase: %I64X  ", UtilVmRead(VmcsField::kGuestGsBase));
	HYPERPLATFORM_LOG_DEBUG("kGuestLdtrBase: %I64X  ", UtilVmRead(VmcsField::kGuestLdtrBase));
	HYPERPLATFORM_LOG_DEBUG("kGuestTrBase: %I64X  ", UtilVmRead(VmcsField::kGuestTrBase));
	HYPERPLATFORM_LOG_DEBUG("kGuestGdtrBase: %I64X  ", UtilVmRead(VmcsField::kGuestGdtrBase));
	HYPERPLATFORM_LOG_DEBUG("kGuestIdtrBase: %I64X  ", UtilVmRead(VmcsField::kGuestIdtrBase));
	HYPERPLATFORM_LOG_DEBUG("kGuestDr7: %I64X  ", UtilVmRead(VmcsField::kGuestDr7));
	HYPERPLATFORM_LOG_DEBUG("kGuestRflags: %I64X  ", UtilVmRead(VmcsField::kGuestRflags));
	HYPERPLATFORM_LOG_DEBUG("kGuestSysenterEsp: %I64X  ", UtilVmRead(VmcsField::kGuestSysenterEsp));
	HYPERPLATFORM_LOG_DEBUG("kGuestSysenterEip: %I64X  ", UtilVmRead(VmcsField::kGuestSysenterEip));
	HYPERPLATFORM_LOG_DEBUG("kGuestRip: %I64X  ", UtilVmRead(VmcsField::kGuestRip));
	HYPERPLATFORM_LOG_DEBUG("kGuestRsp: %I64X  ", UtilVmRead(VmcsField::kGuestRsp));

}

//---------------------------------------------------------------------------------------------------------------------------//
VOID 
VmcsPrintReadOnlyField()
{

	HYPERPLATFORM_LOG_DEBUG_SAFE("###################### Natural Read-only data field #############################");
	HYPERPLATFORM_LOG_DEBUG_SAFE("kGuestPhysicalAddress: %I64X  ", UtilVmRead(VmcsField::kGuestPhysicalAddress));
	HYPERPLATFORM_LOG_DEBUG_SAFE("###################### 64bit Read-only data field #############################");
	HYPERPLATFORM_LOG_DEBUG_SAFE("kVmInstructionError	:%I64X  ", UtilVmRead(VmcsField::kVmInstructionError));
	HYPERPLATFORM_LOG_DEBUG_SAFE("kVmExitReason			:%I64X  ", UtilVmRead(VmcsField::kVmExitReason));
	HYPERPLATFORM_LOG_DEBUG_SAFE("kVmExitIntrInfo		:%I64X  ", UtilVmRead(VmcsField::kVmExitIntrInfo));
	HYPERPLATFORM_LOG_DEBUG_SAFE("kVmExitIntrErrorCode	:%I64X  ", UtilVmRead(VmcsField::kVmExitIntrErrorCode));
	HYPERPLATFORM_LOG_DEBUG_SAFE("kIdtVectoringInfoField	:%I64X  ", UtilVmRead(VmcsField::kIdtVectoringInfoField));
	HYPERPLATFORM_LOG_DEBUG_SAFE("kIdtVectoringErrorCode	:%I64X  ", UtilVmRead(VmcsField::kIdtVectoringErrorCode));
	HYPERPLATFORM_LOG_DEBUG_SAFE("kVmExitInstructionLen	:%I64X  ", UtilVmRead(VmcsField::kVmExitInstructionLen));
	HYPERPLATFORM_LOG_DEBUG_SAFE("kVmxInstructionInfo	:%I64X  ", UtilVmRead(VmcsField::kVmxInstructionInfo));

}
//---------------------------------------------------------------------------------------------------------------------------//
ULONG_PTR* SelectRegister(ULONG index, GpRegisters *gp_regs)
{
	ULONG_PTR *register_used = nullptr;
	// clang-format off
	switch (index) {
	case 0: register_used = &gp_regs->ax; break;
	case 1: register_used = &gp_regs->cx; break;
	case 2: register_used = &gp_regs->dx; break;
	case 3: register_used = &gp_regs->bx; break;
	case 4: register_used = &gp_regs->sp; break;
	case 5: register_used = &gp_regs->bp; break;
	case 6: register_used = &gp_regs->si; break;
	case 7: register_used = &gp_regs->di; break;
#if defined(_AMD64_)
	case 8: register_used = &gp_regs->r8; break;
	case 9: register_used = &gp_regs->r9; break;
	case 10: register_used = &gp_regs->r10; break;
	case 11: register_used = &gp_regs->r11; break;
	case 12: register_used = &gp_regs->r12; break;
	case 13: register_used = &gp_regs->r13; break;
	case 14: register_used = &gp_regs->r14; break;
	case 15: register_used = &gp_regs->r15; break;
#endif
	default:
		break;
	}
	// clang-format on
	return register_used;
}

//-------------------------------------------------------------------------------------------------------------------------------------//
ULONG 
GetVMCSOffset(
	_In_ ULONG_PTR encoded
)
{
	if (encoded)
	{
		unsigned int type;
		unsigned int index;
		// try to build generic VMCS map
		for (type = 0; type < 16; type++)
		{
			for (index = 0; index <= VMX_HIGHEST_VMCS_ENCODING; index++)
			{
				unsigned encoding = ((type & 0xc) << 11) + ((type & 3) << 10) + index;
				if ((ULONG_PTR)encoded == encoding)
				{
					//HYPERPLATFORM_LOG_DEBUG_SAFE("field: %I64X offset: %I64X ", encoding , g_vmcs_map[type][index]);
					return g_vmcs_map[type][index];
				}
			}
		}
	}
	return 0;
}
//-------------------------------------------------------------------------------------------------------------------------------------//
VmcsField 
VmcsDecodeVmwriteOrVmRead(
	_In_ GpRegisters* guest_context, 
	_In_ ULONG_PTR* Offset, 
	_In_ ULONG_PTR* Value,
	_In_ BOOLEAN* RorM, 
	_In_ ULONG_PTR* RegIndex, 
	_In_ ULONG_PTR* MemAddr
)
{
	const VMInstructionQualificationForVmreadOrVmwrite exit_qualification = {
		static_cast<ULONG32>(UtilVmRead(VmcsField::kVmxInstructionInfo))
	};

	ULONG VmcsFieldRegIndex = exit_qualification.fields.Reg2;
	auto  Field = SelectRegister(VmcsFieldRegIndex, guest_context);
	ULONG FieldOffset = GetVMCSOffset(*Field);
	// if passed by register -> no need to calculate the operand address 
	// VMREAD  : return to reg/ mem
	// VMWRITE : value come from reg / mem
	if (exit_qualification.fields.MemOrReg)
	{
		ULONG ValueRegIndex = exit_qualification.fields.Reg1;
		auto ParamValue = SelectRegister(ValueRegIndex, guest_context);

		if (RegIndex)
			*RegIndex = ValueRegIndex;

		if (MemAddr)
			*MemAddr = 0;

		*Value = *ParamValue;

		//Register , return Reg index
		*RorM = TRUE;
	}
	//if operand is address, we need to calculate it 
	else
	{
		//offset
		const auto displacement = UtilVmRead(VmcsField::kExitQualification);

		//base
		ULONG_PTR base_value = 0;
		if (!exit_qualification.fields.BaseRegInvalid)
		{
			//get register in stack. when VM-exit it is pushed on the stack
			const auto register_used = SelectRegister(exit_qualification.fields.BaseReg, guest_context);
			base_value = *register_used;
		}

		//scaling
		ULONG_PTR index_value = 0;
		if (!exit_qualification.fields.Reg1)
		{
			//get register in stack. when VM-exit it is pushed on the stack
			const auto register_used = SelectRegister(exit_qualification.fields.IndexReg, guest_context);

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
		//result
		auto operation_address = base_value + index_value + displacement;

		if (static_cast<VMXAaddressSize>(exit_qualification.fields.address_size) == VMXAaddressSize::k32bit)
		{
			//32bit->64bit
			operation_address &= MAXULONG;
		}
		if (RegIndex)
			*RegIndex = 0;

		if (MemAddr)
			*MemAddr = operation_address;

		if (Value)
			*Value = *(PULONG64)operation_address;

		//Mem , return Memory Address
		*RorM = FALSE;
	}

	*Offset = FieldOffset;
	return static_cast<VmcsField>(*Field);
}

//-------------------------------------------------------------------------------------------------------------------------------------//

VOID 
VmcsVmRead64(
	_In_ VmcsField Field, 
	_In_ ULONG_PTR base, 
	_In_ PULONG64 destination
)
{
	ULONG_PTR offset = GetVMCSOffset((ULONG64)Field);
	*destination = *(PULONG64)(base + offset);
}

//-------------------------------------------------------------------------------------------------------------------------------------//
VOID 
VmcsVmRead32(
	_In_ VmcsField Field, 
	_In_ ULONG_PTR base, 
	_In_ PULONG32 destination
)
{
	ULONG_PTR offset = GetVMCSOffset((ULONG64)Field);
	*destination = *(PULONG32)(base + offset);
}
//-------------------------------------------------------------------------------------------------------------------------------------//
VOID 
VmcsVmRead16(
	_In_ VmcsField Field, 
	_In_ ULONG_PTR base, 
	_In_ PUSHORT destination
)
{
	ULONG_PTR offset = GetVMCSOffset((ULONG64)Field);
	*destination = *(PUSHORT)(base + offset);
}
//-------------------------------------------------------------------------------------------------------------------------------------//

VOID 
VmcsVmWrite64(
	_In_ VmcsField Field, 
	_In_ ULONG_PTR base, 
	_In_ ULONG_PTR value
)
{
	ULONG_PTR offset = GetVMCSOffset((ULONG64)Field);
	*(PULONG64)(base + offset) = (ULONG64)value;
}
//-------------------------------------------------------------------------------------------------------------------------------------//

VOID
VmcsVmWrite32(
	_In_ VmcsField Field,
	_In_ ULONG_PTR base, 
	_In_ ULONG_PTR value
)
{
	ULONG_PTR offset = GetVMCSOffset((ULONG64)Field);
	*(PULONG32)(base + offset) = (ULONG32)value;
}
//-------------------------------------------------------------------------------------------------------------------------------------//

VOID 
VmcsVmWrite16(
	_In_ VmcsField Field, 
	_In_ ULONG_PTR base, 
	_In_ ULONG_PTR value
)
{
	ULONG_PTR offset = GetVMCSOffset((ULONG64)Field);
	*(PUSHORT)(base + offset) = (USHORT)value;
}
//-------------------------------------------------------------------------------------------------------------------------------------//

BOOLEAN
is_vmcs_field_supported(
	VmcsField encoding
)
{
	switch (encoding)
	{

#if MY_SUPPORT_VMX >= 2
		/* VMCS 16-bit control fields */
		/* binary 0000_00xx_xxxx_xxx0 */
	case VmcsField::kVirtualProcessorId:
	case VmcsField::kGuestInterruptStatus:
		return 1;
#endif

		/* VMCS 16-bit host-state fields */
		/* binary 0000_11xx_xxxx_xxx0 */
	case VmcsField::kHostEsSelector:
	case VmcsField::kHostCsSelector:
	case VmcsField::kHostSsSelector:
	case VmcsField::kHostDsSelector:
	case VmcsField::kHostFsSelector:
	case VmcsField::kHostGsSelector:
	case VmcsField::kHostTrSelector:

		return 1;
		/* VMCS 16-bit guest-state fields */
		/* binary 0000_10xx_xxxx_xxx0 */
	case VmcsField::kGuestEsSelector:
	case VmcsField::kGuestCsSelector:
	case VmcsField::kGuestSsSelector:
	case VmcsField::kGuestDsSelector:
	case VmcsField::kGuestFsSelector:
	case VmcsField::kGuestGsSelector:
	case VmcsField::kGuestTrSelector:
	case VmcsField::kGuestLdtrSelector:
	case VmcsField::kGuestPmlIndex:
		return 1;

		/* VMCS 32_bit control fields */
		/* binary 0100_00xx_xxxx_xxx0 */
	case VmcsField::kPinBasedVmExecControl:
	case VmcsField::kCpuBasedVmExecControl:
	case VmcsField::kExceptionBitmap:
	case VmcsField::kPageFaultErrorCodeMask:
	case VmcsField::kPageFaultErrorCodeMatch:
	case VmcsField::kCr3TargetCount:
	case VmcsField::kVmExitControls:
	case VmcsField::kVmExitMsrStoreCount:
	case VmcsField::kVmExitMsrLoadCount:
	case VmcsField::kVmEntryControls:
	case VmcsField::kVmEntryMsrLoadCount:
	case VmcsField::kVmEntryIntrInfoField:
	case VmcsField::kVmEntryExceptionErrorCode:
	case VmcsField::kVmEntryInstructionLen:
	case VmcsField::kPleGap:
	case VmcsField::kPleWindow:
	case VmcsField::kTprThreshold:
#if MY_SUPPORT_X86_64
	case VmcsField:kTprThreshold:
#endif
#if MY_SUPPORT_VMX >= 2
	case VmcsField::kSecondaryVmExecControl:
#endif
		return 1;

			/* VMCS 32-bit read only data fields */
			/* binary 0100_01xx_xxxx_xxx0 */
	case VmcsField::kVmInstructionError:
	case VmcsField::kVmExitReason:
	case VmcsField::kVmExitIntrInfo:
	case VmcsField::kVmExitIntrErrorCode:
	case VmcsField::kIdtVectoringInfoField:
	case VmcsField::kIdtVectoringErrorCode:
	case VmcsField::kVmExitInstructionLen:
	case VmcsField::kVmxInstructionInfo:
		return 1;

		/* VMCS 32-bit guest-state fields */
		/* binary 0100_10xx_xxxx_xxx0 */
	case VmcsField::kGuestEsLimit:
	case VmcsField::kGuestCsLimit:
	case VmcsField::kGuestSsLimit:
	case VmcsField::kGuestDsLimit:
	case VmcsField::kGuestFsLimit:
	case VmcsField::kGuestGsLimit:
	case VmcsField::kGuestLdtrLimit:
	case VmcsField::kGuestTrLimit:
	case VmcsField::kGuestGdtrLimit:
	case VmcsField::kGuestIdtrLimit:
	case VmcsField::kGuestEsArBytes:
	case VmcsField::kGuestCsArBytes:
	case VmcsField::kGuestSsArBytes:
	case VmcsField::kGuestDsArBytes:
	case VmcsField::kGuestFsArBytes:
	case VmcsField::kGuestGsArBytes:
	case VmcsField::kGuestLdtrArBytes:
	case VmcsField::kGuestTrArBytes:
	case VmcsField::kGuestInterruptibilityInfo:
	case VmcsField::kGuestActivityState:
	case VmcsField::kGuestSmbase:
	case VmcsField::kGuestSysenterCs:
	case VmcsField::kVmxPreemptionTimerValue:
		return 1;

		/* VMCS 32-bit host-state fields */
		/* binary 0100_11xx_xxxx_xxx0 */
	case  VmcsField::kHostIa32SysenterCs:
		return 1;
		/* VMCS 64-bit control fields */
		/* binary 0010_00xx_xxxx_xxx0 */
	case VmcsField::kIoBitmapA:
	case VmcsField::kIoBitmapAHigh:
	case VmcsField::kIoBitmapB:
	case VmcsField::kIoBitmapBHigh:
	case VmcsField::kMsrBitmap:
	case VmcsField::kMsrBitmapHigh:
	case VmcsField::kVmExitMsrStoreAddr:
	case VmcsField::kVmExitMsrStoreAddrHigh:
	case VmcsField::kVmExitMsrLoadAddr:
	case VmcsField::kVmExitMsrLoadAddrHigh:
	case VmcsField::kVmEntryMsrLoadAddr:
	case VmcsField::kVmEntryMsrLoadAddrHigh:
	case VmcsField::kExecutiveVmcsPointer:
	case VmcsField::kExecutiveVmcsPointerHigh:
	case VmcsField::kTscOffset:
	case VmcsField::kTscOffsetHigh:
	case VmcsField::kEptpListAddress:
	case VmcsField::kEptpListAddressHigh:
	case VmcsField::kPmlAddress:
#if MY_SUPPORT_X86_64
	case VmcsField::kVirtualApicPageAddr:
	case VmcsField::kVirtualApicPageAddrHigh:
#endif
#if MY_SUPPORT_VMX >= 2
	case VmcsField::kApicAccessAddr:
	case VmcsField::kApicAccessAddrHigh:
	case VmcsField::kEptPointer:
	case VmcsField::kEptPointerHigh:
#endif
		return 1;

#if MY_SUPPORT_VMX >= 2
			/* VMCS 64-bit read only data fields */
			/* binary 0010_01xx_xxxx_xxx0 */
	case VmcsField::kGuestPhysicalAddress:
	case VmcsField::kGuestPhysicalAddressHigh:
		return 1;
#endif

	/* VMCS 64-bit guest state fields */
	/* binary 0010_10xx_xxxx_xxx0 */
	case VmcsField::kVmcsLinkPointer:
	case VmcsField::kVmcsLinkPointerHigh:
	case VmcsField::kGuestIa32Debugctl:
	case VmcsField::kGuestIa32DebugctlHigh:
#if MY_SUPPORT_VMX >= 2
	case VmcsField::kGuestIa32Pat:
	case VmcsField::kGuestIa32PatHigh:
	case VmcsField::kGuestIa32Efer:
	case VmcsField::kGuestIa32EferHigh:
	case VmcsField::kGuestPdptr0:
	case VmcsField::kGuestPdptr0High:
	case VmcsField::kGuestPdptr1:
	case VmcsField::kGuestPdptr1High:
	case VmcsField::kGuestPdptr2:
	case VmcsField::kGuestPdptr2High:
	case VmcsField::kGuestPdptr3:
	case VmcsField::kGuestPdptr3High:
#endif
		return 1;

#if MY_SUPPORT_VMX >= 3
		/* VMCS 64-bit host state fields */
		/* binary 0010_11xx_xxxx_xxx0 */
	case VmcsField::kGuestIa32Pat:
	case VmcsField::kGuestIa32PatHigh:
	case VmcsField::kGuestIa32Efer:
	case VmcsField::kGuestIa32EferHigh:
		return 1;
#endif
		/*
		/* VMCS natural width control fields
		*/
		/* binary 0110_00xx_xxxx_xxx0 */
	case VmcsField::kCr0GuestHostMask:
	case VmcsField::kCr4GuestHostMask:
	case VmcsField::kCr0ReadShadow:
	case VmcsField::kCr4ReadShadow:
	case VmcsField::kCr3TargetValue0:
	case VmcsField::kCr3TargetValue1:
	case VmcsField::kCr3TargetValue2:
	case VmcsField::kCr3TargetValue3:
		return 1;

		/* VMCS natural width read only data fields */
		/* binary 0110_01xx_xxxx_xxx0 */
	case VmcsField::kExitQualification:
	case VmcsField::kIoRcx:
	case VmcsField::kIoRsi:
	case VmcsField::kIoRdi:
	case VmcsField::kIoRip:
	case VmcsField::kGuestLinearAddress:
		return 1;

		/* VMCS natural width guest state fields */
		/* binary 0110_10xx_xxxx_xxx0 */
	case VmcsField::kGuestCr0:
	case VmcsField::kGuestCr3:
	case VmcsField::kGuestCr4:
	case VmcsField::kGuestEsBase:
	case VmcsField::kGuestCsBase:
	case VmcsField::kGuestSsBase:
	case VmcsField::kGuestDsBase:
	case VmcsField::kGuestFsBase:
	case VmcsField::kGuestGsBase:
	case VmcsField::kGuestLdtrBase:
	case VmcsField::kGuestTrBase:
	case VmcsField::kGuestGdtrBase:
	case VmcsField::kGuestIdtrBase:
	case VmcsField::kGuestDr7:
	case VmcsField::kGuestRsp:
	case VmcsField::kGuestRip:
	case VmcsField::kGuestRflags:
	case VmcsField::kGuestPendingDbgExceptions:
	case VmcsField::kGuestSysenterEsp:
	case VmcsField::kGuestSysenterEip:
		return 1;

		/* VMCS natural width host state fields */
		/* binary 0110_11xx_xxxx_xxx0 */
	case VmcsField::kHostCr0:
	case VmcsField::kHostCr3:
	case VmcsField::kHostCr4:
	case VmcsField::kHostFsBase:
	case VmcsField::kHostGsBase:
	case VmcsField::kHostTrBase:
	case VmcsField::kHostGdtrBase:
	case VmcsField::kHostIdtrBase:
	case VmcsField::kHostIa32SysenterEsp:
	case VmcsField::kHostIa32SysenterEip:
	case VmcsField::kHostRsp:
	case VmcsField::kHostRip:
		return 1;


	default:
		return 0;
	}
}
//-------------------------------------------------------------------------------------------------------------------------------------//

VOID 
BuildGernericVMCSMap()
{
	static bool vmcs_map_ready = 0;
	unsigned type, index;

	if (vmcs_map_ready)
		return;

	vmcs_map_ready = 1;

	for (type = 0; type < 16; type++)
	{
		for (index = 0; index <= VMX_HIGHEST_VMCS_ENCODING; index++)
		{
			//initialize each type for each index corresponding to the VMCS structure
			g_vmcs_map[type][index] = 0xffffffff;
		}
	}

	// try to build generic VMCS map
	for (type = 0; type < 16; type++)
	{
		for (index = 0; index <= VMX_HIGHEST_VMCS_ENCODING; index++)
		{
			unsigned encoding = ((type & 0xc) << 11) + ((type & 3) << 10) + index;
			//  type = 1:
			//  ((type & 3) << 10)  = what is that field indicated:
			//  ((type & 0xc) << 11) = how many bits 
			//  + index
			if (g_vmcs_map[type][index] != 0xffffffff)
			{
				HYPERPLATFORM_LOG_DEBUG_SAFE("VMCS type %d field %d (encoding = 0x%08x) is already initialized", type, index, encoding);
			}
		//	if (is_vmcs_field_supported(VmcsField(encoding)))
			{
				// allocate 64 fields (4 byte each) per type
				g_vmcs_map[type][index] = VMCS_DATA_OFFSET + (type * 64 + index) * 4;
				if (g_vmcs_map[type][index] >= VMX_VMCS_AREA_SIZE)
				{
					HYPERPLATFORM_LOG_DEBUG_SAFE("VMCS type %d field %d (encoding = 0x%08x) is out of VMCS boundaries", type, index, encoding);
				}
			}
		}
	}

	for (type = 0; type < 16; type++)
	{
		for (index = 0; index <= VMX_HIGHEST_VMCS_ENCODING; index++)
		{
			if (g_vmcs_map[type][index] != 0xFFFFFFFF)
				HYPERPLATFORM_LOG_DEBUG_SAFE("Type: %d Field: %d = value: %x \r\n", type, index, g_vmcs_map[type][index]);
		}
	}
}
//-------------------------------------------------------------------------------------------------------------------------------------//

// Returns a base address of segment_descriptor
_Use_decl_annotations_ 
static 
ULONG_PTR 
GetSegmentBaseByDescriptor(
	_In_ const SegmentDescriptor *segment_descriptor
)
{
	// Caluculate a 32bit base address
	const auto base_high = segment_descriptor->fields.base_high << (6 * 4);
	const auto base_middle = segment_descriptor->fields.base_mid << (4 * 4);
	const auto base_low = segment_descriptor->fields.base_low;
	ULONG_PTR base = (base_high | base_middle | base_low) & MAXULONG;
	// Get upper 32bit of the base address if needed
	if (IsX64() && !segment_descriptor->fields.system) {
		auto desc64 =
			reinterpret_cast<const SegmentDesctiptorX64 *>(segment_descriptor);
		ULONG64 base_upper32 = desc64->base_upper32;
		base |= (base_upper32 << 32);
	}
	return base;
}
//-------------------------------------------------------------------------------------------------------------------------------------//

// Returns the segment descriptor corresponds to the SegmentSelector
_Use_decl_annotations_ 
static 
SegmentDescriptor*
GetSegmentDescriptor(
	_In_ ULONG_PTR descriptor_table_base,
	_In_ USHORT segment_selector
)
{
	const SegmentSelector ss = { segment_selector };
	return reinterpret_cast<SegmentDescriptor *>(descriptor_table_base + ss.fields.index * sizeof(SegmentDescriptor));
}
//-------------------------------------------------------------------------------------------------------------------------------------//

// Returns a base address of the segment specified by SegmentSelector
_Use_decl_annotations_
static 
ULONG_PTR 
GetSegmentBase(
	_In_ ULONG_PTR gdt_base, 
	_In_ USHORT segment_selector
) 
{
	const SegmentSelector ss = { segment_selector };
	if (!ss.all) {
		return 0;
	}

	if (ss.fields.ti) {
		const auto local_segment_descriptor =
			GetSegmentDescriptor(gdt_base, AsmReadLDTR());
		const auto ldt_base =
			GetSegmentBaseByDescriptor(local_segment_descriptor);
		const auto segment_descriptor =
			GetSegmentDescriptor(ldt_base, segment_selector);
		return GetSegmentBaseByDescriptor(segment_descriptor);
	}
	else {
		const auto segment_descriptor =
			GetSegmentDescriptor(gdt_base, segment_selector);
		return	GetSegmentBaseByDescriptor(segment_descriptor);
	}
}
//-------------------------------------------------------------------------------------------------------------------------------------//

//IF (register operand) or (CR0.PE = 0) or (CR4.VMXE = 0) or (RFLAGS.VM = 1) or (IA32_EFER.LMA = 1 and CS.L = 0) 
//if and only if compatibility mode is on 
/*
//https://en.wikipedia.org/wiki/Control_register about MSR.EFER structure
*/

/*
See: Code Segment Descriptor in 64-bit Mode

if IA32_EFER.LMA = 1	(IA-32e mode is active)
if CS.D = 1
32bit mode or compatibility mode
if CS.D = 0
64bit mode
*/
ULONG64
GetControlValue(
	_In_ Msr msr, 
	_In_ ULONG32* highpart,
	_In_ ULONG32* lowpart
)
{
	LARGE_INTEGER msr_value = {};

	msr_value.QuadPart = UtilReadMsr64(msr);
	// bit == 0 in high word ==> must be zero  
	*highpart = msr_value.HighPart;
	// bit == 1 in low word  ==> must be one
	*lowpart = msr_value.LowPart;
	return msr_value.QuadPart;
}

//---------------------------------------------------------------------------------------------------------------------// 
VOID 
VmcsPrepareHostAndControlField(
	_In_ ULONG_PTR vmcs12_va,
	_In_ ULONG_PTR vmcs02_pa,
	_In_ BOOLEAN isLaunch
)
{

	VmxStatus status;

	USHORT my_guest_vpid;

	//vmcs0-1 32bit control field
	ULONG32 exit_control = (ULONG32)UtilVmRead(VmcsField::kVmExitControls);
	ULONG32 guest_primary_processor_base_ctls = (ULONG32)UtilVmRead(VmcsField::kCpuBasedVmExecControl);
	ULONG32 guest_secondary_processor_base_ctls = (ULONG32)UtilVmRead(VmcsField::kSecondaryVmExecControl);

	ULONG32 vmexit_ctrls = (ULONG32)UtilVmRead(VmcsField::kVmExitControls);
	ULONG32 vmexit_msr_store_cnt = (ULONG32)UtilVmRead(VmcsField::kVmExitMsrStoreCount);
	ULONG32 vmexit_msr_load_cnt = (ULONG32)UtilVmRead(VmcsField::kVmExitMsrLoadCount);

	ULONG32 vmentry_interr_info = (ULONG32)UtilVmRead(VmcsField::kVmEntryIntrInfoField);
	ULONG32 vmentry_except_Err_code = (ULONG32)UtilVmRead(VmcsField::kVmEntryExceptionErrorCode);
	ULONG32 vmentry_instr_length = (ULONG32)UtilVmRead(VmcsField::kVmEntryInstructionLen);
	ULONG32 vmentry_ctrls = (ULONG32)UtilVmRead(VmcsField::kVmEntryControls);
	ULONG32 vmentry_msr_load_cnt = (ULONG32)UtilVmRead(VmcsField::kVmEntryMsrLoadCount);

	ULONG32 guest_exception_bitmap = (ULONG32)UtilVmRead(VmcsField::kExceptionBitmap);

	//vmcs0-1 natural-width control field
	ULONG_PTR guest_cr0_mask = UtilVmRead64(VmcsField::kCr0GuestHostMask);
	ULONG_PTR guest_cr4_mask = UtilVmRead64(VmcsField::kCr4GuestHostMask);
	ULONG_PTR guest_cr0_read_shadow = UtilVmRead64(VmcsField::kCr0ReadShadow);
	ULONG_PTR guest_cr4_read_shadow = UtilVmRead64(VmcsField::kCr4ReadShadow);
	ULONG_PTR guest_cr3_target_value[4] = { 0 };
	guest_cr3_target_value[0] = UtilVmRead64(VmcsField::kCr3TargetValue0);
	guest_cr3_target_value[1] = UtilVmRead64(VmcsField::kCr3TargetValue1);
	guest_cr3_target_value[2] = UtilVmRead64(VmcsField::kCr3TargetValue2);
	guest_cr3_target_value[3] = UtilVmRead64(VmcsField::kCr3TargetValue3);


	// vmcs0-1 64bit Control Field
	ULONG64 guest_io_bitmap[2] = { 0 };
	guest_io_bitmap[0] = UtilVmRead64(VmcsField::kIoBitmapA);
	guest_io_bitmap[1] = UtilVmRead64(VmcsField::kIoBitmapB);
	ULONG64 guest_msr_bitmap = UtilVmRead64(VmcsField::kMsrBitmap);
//	ULONG64 guest_vmreadBitmapAddress = UtilVmRead64(VmcsField::kVmreadBitmapAddress);
//	ULONG64 guest_vmwriteBitMapAddress = UtilVmRead64(VmcsField::kVmwriteBitmapAddress);
//	ULONG64 guest_vmexceptionAddress = UtilVmRead64(VmcsField::kVirtualizationExceptionInfoAddress);
//	ULONG64 guest_virtual_apicpage = UtilVmRead64(VmcsField::kVirtualApicPageAddr);
	ULONG64 guest_eoi_exit_bitmap[8] = { 0 };
    guest_eoi_exit_bitmap[0] = UtilVmRead64(VmcsField::kEoiExitBitmap0);
    guest_eoi_exit_bitmap[1] = UtilVmRead64(VmcsField::kEoiExitBitmap0High);
    guest_eoi_exit_bitmap[2] = UtilVmRead64(VmcsField::kEoiExitBitmap1);
    guest_eoi_exit_bitmap[3] = UtilVmRead64(VmcsField::kEoiExitBitmap1High);
    guest_eoi_exit_bitmap[4] = UtilVmRead64(VmcsField::kEoiExitBitmap2);
    guest_eoi_exit_bitmap[5] = UtilVmRead64(VmcsField::kEoiExitBitmap2High);
    guest_eoi_exit_bitmap[6] = UtilVmRead64(VmcsField::kEoiExitBitmap3);
    guest_eoi_exit_bitmap[7] = UtilVmRead64(VmcsField::kEoiExitBitmap3High);

//	ULONG64 guest_tpr_threshold = (ULONG32)UtilVmRead(VmcsField::kTprThreshold);
	ULONG64 guest_apic_access_address = UtilVmRead64(VmcsField::kApicAccessAddr);
	ULONG64 guest_ept_pointer = UtilVmRead64(VmcsField::kEptPointer);
	ULONG64 vmfunc_ctrls = UtilVmRead64(VmcsField::kVmFuncCtls);
	ULONG64 eptp_list_address = UtilVmRead64(VmcsField::kEptpListAddress);
	ULONG64 pml_address = UtilVmRead64(VmcsField::kPmlAddress);
	ULONG64 pause_loop_exiting_gap = (ULONG32)UtilVmRead(VmcsField::kPleGap);
	ULONG64 pause_loop_exiting_window = (ULONG32)UtilVmRead(VmcsField::kPleWindow);
	ULONG64 guest_vpid = (USHORT)UtilVmRead(VmcsField::kVirtualProcessorId);

	//vmcs0-1 16bit Host state Field 
	ULONG_PTR	kHostCsSelector = UtilVmRead(VmcsField::kHostCsSelector);
	ULONG_PTR	kHostDsSelector = UtilVmRead(VmcsField::kHostDsSelector);
	ULONG_PTR	kHostEsSelector = UtilVmRead(VmcsField::kHostEsSelector);
	ULONG_PTR	kHostSsSelector = UtilVmRead(VmcsField::kHostSsSelector);
	ULONG_PTR	kHostFsSelector = UtilVmRead(VmcsField::kHostFsSelector);
	ULONG_PTR	kHostGsSelector = UtilVmRead(VmcsField::kHostGsSelector);
	ULONG_PTR	kHostTrSelector = UtilVmRead(VmcsField::kHostTrSelector);

	//vmcs0-1 Natural-Width Host-State Field
	ULONG_PTR kHostCr0 = UtilVmRead(VmcsField::kHostCr0);
	ULONG_PTR kHostCr3 = UtilVmRead(VmcsField::kHostCr3);
	ULONG_PTR kHostCr4 = UtilVmRead(VmcsField::kHostCr4);
	ULONG_PTR kHostFsBase = UtilVmRead(VmcsField::kHostFsBase);
	ULONG_PTR kHostGsBase = UtilVmRead(VmcsField::kHostGsBase);
	ULONG_PTR kHostTrBase = UtilVmRead(VmcsField::kHostTrBase);
	ULONG_PTR kHostGdtrBase = UtilVmRead(VmcsField::kHostGdtrBase);
	ULONG_PTR kHostIdtrBase = UtilVmRead(VmcsField::kHostIdtrBase);
	ULONG_PTR kHostIa32SysenterEsp= UtilVmRead(VmcsField::kHostIa32SysenterEsp);
	ULONG_PTR kHostIa32SysenterEip= UtilVmRead(VmcsField::kHostIa32SysenterEip);
	ULONG_PTR kHostRsp = UtilVmRead( VmcsField::kHostRsp );
	ULONG_PTR kHostRip = UtilVmRead( VmcsField::kHostRip ); 

	//vmcs0-1 32-Bit Host-State Field
	ULONG_PTR kHostIa32SysenterCs = UtilVmRead(VmcsField::kHostIa32SysenterCs);
	 
	ULONG32 highpart, lowpart = 0;

	const auto use_true_msrs = Ia32VmxBasicMsr{ UtilReadMsr64(Msr::kIa32VmxBasic) }.fields.vmx_capability_hint;

	GetControlValue((use_true_msrs) ? Msr::kIa32VmxTruePinbasedCtls : Msr::kIa32VmxPinbasedCtls, &highpart, &lowpart);

	if (isLaunch)
	{
		if (VmxStatus::kOk != (status = static_cast<VmxStatus>(__vmx_vmclear(&vmcs02_pa))))
		{
			VmxInstructionError error = static_cast<VmxInstructionError>(UtilVmRead(VmcsField::kVmInstructionError));
			HYPERPLATFORM_LOG_DEBUG_SAFE("Error vmclear2 error code :%x , %x ", status, error);
			HYPERPLATFORM_COMMON_DBG_BREAK();
		}
	}

	//Load VMCS02 into CPU
	if (VmxStatus::kOk != (status = static_cast<VmxStatus>(__vmx_vmptrld(&vmcs02_pa))))
	{
		VmxInstructionError error = static_cast<VmxInstructionError>(UtilVmRead(VmcsField::kVmInstructionError));
		HYPERPLATFORM_LOG_DEBUG_SAFE("Error vmptrld error code :%x , %x", status, error);
		HYPERPLATFORM_COMMON_DBG_BREAK();
	}

	/*
	Host 16 bit State field
	*/
	UtilVmWrite(VmcsField::kHostCsSelector, kHostCsSelector);
	UtilVmWrite(VmcsField::kHostDsSelector, kHostDsSelector);
	UtilVmWrite(VmcsField::kHostEsSelector, kHostEsSelector);
	UtilVmWrite(VmcsField::kHostSsSelector, kHostSsSelector);
	UtilVmWrite(VmcsField::kHostFsSelector, kHostFsSelector);
	UtilVmWrite(VmcsField::kHostGsSelector, kHostGsSelector);
	UtilVmWrite(VmcsField::kHostTrSelector, kHostTrSelector);

	/*
	Host 32 bit state field
	*/
	UtilVmWrite(VmcsField::kHostIa32SysenterCs, kHostIa32SysenterCs);

	/*
	Host Natural width state field
	*/
	UtilVmWrite64(VmcsField::kHostCr0, kHostCr0);
	UtilVmWrite64(VmcsField::kHostCr3, kHostCr3);
	UtilVmWrite64(VmcsField::kHostCr4, kHostCr4);

	UtilVmWrite64(VmcsField::kHostFsBase, kHostFsBase);
	UtilVmWrite64(VmcsField::kHostGsBase, kHostGsBase);
	UtilVmWrite64(VmcsField::kHostTrBase, kHostTrBase);
	UtilVmWrite64(VmcsField::kHostGdtrBase, kHostGdtrBase);
	UtilVmWrite64(VmcsField::kHostIdtrBase, kHostIdtrBase);
	UtilVmWrite64(VmcsField::kHostIa32SysenterEsp, kHostIa32SysenterEsp);
	UtilVmWrite64(VmcsField::kHostIa32SysenterEip, kHostIa32SysenterEip);

	UtilVmWrite64(VmcsField::kHostRsp, kHostRsp);
	UtilVmWrite64(VmcsField::kHostRip, kHostRip);

	 	
	//  Start Mixing Control field with VMCS01 and VMCS12 into VMCS02
	/*
	16 bit Control Field
	*/ 

	UtilVmWrite(VmcsField::kVirtualProcessorId, guest_vpid);

	/*
	32 bit Control Field
	*/
	ULONG32 my_pin_base_ctls;
	ULONG32 my_primary_processor_base_ctls;
	ULONG32 my_exception_bitmap;
	ULONG32 my_guest_page_fault_mask;
	ULONG32 my_page_fault_error_code_match;
	ULONG32 my_cr3_target_count;
	ULONG32 my_exit_control;
	ULONG32 my_vmexit_msr_store_cnt;
	ULONG32 my_vmexit_msr_load_cnt;
	ULONG32 my_vmentry_ctrls;
	ULONG32 my_vmentry_msr_load_cnt;
	ULONG32 my_vmentry_interr_info;
	ULONG32 my_vmentry_except_Err_code;
	ULONG32 my_vmentry_instr_length;
	ULONG32 my_guest_tpr_threshold;
	ULONG32 my_pause_loop_exiting_gap;
	ULONG32 my_pause_loop_exiting_window;
	ULONG32 my_guest_secondary_processor_base_ctls;

	VmcsVmRead32(VmcsField::kPinBasedVmExecControl, vmcs12_va, &my_pin_base_ctls);
	VmcsVmRead32(VmcsField::kCpuBasedVmExecControl, vmcs12_va, &my_primary_processor_base_ctls);
	VmcsVmRead32(VmcsField::kExceptionBitmap, vmcs12_va, &my_exception_bitmap);
	VmcsVmRead32(VmcsField::kPageFaultErrorCodeMask, vmcs12_va, &my_guest_page_fault_mask);
	VmcsVmRead32(VmcsField::kPageFaultErrorCodeMatch, vmcs12_va, &my_page_fault_error_code_match);
	VmcsVmRead32(VmcsField::kCr3TargetCount, vmcs12_va, &my_cr3_target_count);
	VmcsVmRead32(VmcsField::kVmExitControls, vmcs12_va, &my_exit_control);
	VmcsVmRead32(VmcsField::kVmExitMsrStoreCount, vmcs12_va, &my_vmexit_msr_store_cnt);
	VmcsVmRead32(VmcsField::kVmExitMsrLoadCount, vmcs12_va, &my_vmexit_msr_load_cnt);
	VmcsVmRead32(VmcsField::kVmEntryControls, vmcs12_va, &my_vmentry_ctrls);
	VmcsVmRead32(VmcsField::kVmEntryMsrLoadCount, vmcs12_va, &my_vmentry_msr_load_cnt);
	VmcsVmRead32(VmcsField::kVmEntryIntrInfoField, vmcs12_va, &my_vmentry_interr_info);
	VmcsVmRead32(VmcsField::kVmEntryExceptionErrorCode, vmcs12_va, &my_vmentry_except_Err_code);
	VmcsVmRead32(VmcsField::kVmEntryInstructionLen, vmcs12_va, &my_vmentry_instr_length);
	VmcsVmRead32(VmcsField::kTprThreshold, vmcs12_va, &my_guest_tpr_threshold);
	VmcsVmRead32(VmcsField::kPleGap, vmcs12_va, &my_pause_loop_exiting_gap);
	VmcsVmRead32(VmcsField::kPleWindow, vmcs12_va, &my_pause_loop_exiting_window);
	VmcsVmRead32(VmcsField::kSecondaryVmExecControl, vmcs12_va, &my_guest_secondary_processor_base_ctls);

	UtilVmWrite(VmcsField::kPageFaultErrorCodeMask, my_guest_page_fault_mask);
	UtilVmWrite(VmcsField::kPageFaultErrorCodeMatch, my_page_fault_error_code_match);
	UtilVmWrite(VmcsField::kCr3TargetCount, my_cr3_target_count);

	UtilVmWrite(VmcsField::kPinBasedVmExecControl, my_pin_base_ctls );
	UtilVmWrite(VmcsField::kVmExitControls, exit_control);
	UtilVmWrite(VmcsField::kSecondaryVmExecControl, guest_secondary_processor_base_ctls | my_guest_secondary_processor_base_ctls);
	UtilVmWrite(VmcsField::kCpuBasedVmExecControl, guest_primary_processor_base_ctls | my_primary_processor_base_ctls);
	UtilVmWrite(VmcsField::kExceptionBitmap, guest_exception_bitmap | my_exception_bitmap);

	UtilVmWrite(VmcsField::kVmExitMsrStoreCount, my_vmexit_msr_store_cnt);
	UtilVmWrite(VmcsField::kVmExitMsrLoadCount, my_vmexit_msr_load_cnt);
	UtilVmWrite(VmcsField::kVmEntryControls, my_vmentry_ctrls);
	UtilVmWrite(VmcsField::kVmEntryMsrLoadCount, my_vmentry_msr_load_cnt);
	UtilVmWrite(VmcsField::kVmEntryIntrInfoField, my_vmentry_interr_info);
	UtilVmWrite(VmcsField::kVmEntryExceptionErrorCode, my_vmentry_except_Err_code);
	UtilVmWrite(VmcsField::kVmEntryInstructionLen, my_vmentry_instr_length);
	UtilVmWrite(VmcsField::kTprThreshold, my_guest_tpr_threshold);
	UtilVmWrite(VmcsField::kPleGap, 0);
	UtilVmWrite(VmcsField::kPleWindow, 0);


	/*
	64bit control field
	*/
	UtilVmWrite64(VmcsField::kIoBitmapA, guest_io_bitmap[0]);
	UtilVmWrite64(VmcsField::kIoBitmapB, guest_io_bitmap[1]);
	UtilVmWrite64(VmcsField::kMsrBitmap, guest_msr_bitmap);
	UtilVmWrite64(VmcsField::kPmlAddress, pml_address);
	UtilVmWrite64(VmcsField::kApicAccessAddr, guest_apic_access_address);
	UtilVmWrite64(VmcsField::kVmFuncCtls, vmfunc_ctrls);
	UtilVmWrite64(VmcsField::kEptPointer, guest_ept_pointer);
	UtilVmWrite64(VmcsField::kEoiExitBitmap0, guest_eoi_exit_bitmap[0]);
	UtilVmWrite64(VmcsField::kEoiExitBitmap0High, guest_eoi_exit_bitmap[1]);
	UtilVmWrite64(VmcsField::kEoiExitBitmap1, guest_eoi_exit_bitmap[2]);
	UtilVmWrite64(VmcsField::kEoiExitBitmap1High, guest_eoi_exit_bitmap[3]);
	UtilVmWrite64(VmcsField::kEoiExitBitmap2, guest_eoi_exit_bitmap[4]);
	UtilVmWrite64(VmcsField::kEoiExitBitmap2High, guest_eoi_exit_bitmap[5]);
	UtilVmWrite64(VmcsField::kEoiExitBitmap3, guest_eoi_exit_bitmap[6]);
	UtilVmWrite64(VmcsField::kEoiExitBitmap3High, guest_eoi_exit_bitmap[7]);
	UtilVmWrite64(VmcsField::kEptpListAddress, eptp_list_address);

	/*
	Natural-width field
	*/
	UtilVmWrite64(VmcsField::kCr0GuestHostMask, guest_cr0_mask);
	UtilVmWrite64(VmcsField::kCr4GuestHostMask, guest_cr4_mask);
	UtilVmWrite64(VmcsField::kCr0ReadShadow, guest_cr0_read_shadow);
	UtilVmWrite64(VmcsField::kCr4ReadShadow, guest_cr4_read_shadow);
	UtilVmWrite64(VmcsField::kCr3TargetValue0, guest_cr3_target_value[0]);
	UtilVmWrite64(VmcsField::kCr3TargetValue1, guest_cr3_target_value[1]);
	UtilVmWrite64(VmcsField::kCr3TargetValue2, guest_cr3_target_value[2]);
	UtilVmWrite64(VmcsField::kCr3TargetValue3, guest_cr3_target_value[3]);
	/*
	VM control field End
	--------------------------------------------------------------------------------------*/
}
//-------------------------------------------------------------------------------------------------------------------------------------//

VOID 
VmcsPrepareGuestStateField(
	_In_ ULONG_PTR guest_vmcs_va
)
{
	// Guest state field
	USHORT vmcs12_es_selector;
	USHORT vmcs12_cs_selector;
	USHORT vmcs12_ss_selector;
	USHORT vmcs12_ds_selector;
	USHORT vmcs12_fs_selector;
	USHORT vmcs12_gs_selector;
	USHORT vmcs12_ldtr_selector;
	USHORT vmcs12_tr_selector; 

	/*
	Guest 16bit state field
	*/

	// Read Guest 16 bit state field from VMCS12
	VmcsVmRead16(VmcsField::kGuestEsSelector, guest_vmcs_va, &vmcs12_es_selector);
	VmcsVmRead16(VmcsField::kGuestCsSelector, guest_vmcs_va, &vmcs12_cs_selector);
	VmcsVmRead16(VmcsField::kGuestSsSelector, guest_vmcs_va, &vmcs12_ss_selector);
	VmcsVmRead16(VmcsField::kGuestDsSelector, guest_vmcs_va, &vmcs12_ds_selector);
	VmcsVmRead16(VmcsField::kGuestFsSelector, guest_vmcs_va, &vmcs12_fs_selector);
	VmcsVmRead16(VmcsField::kGuestGsSelector, guest_vmcs_va, &vmcs12_gs_selector);
	VmcsVmRead16(VmcsField::kGuestLdtrSelector, guest_vmcs_va, &vmcs12_ldtr_selector);
	VmcsVmRead16(VmcsField::kGuestTrSelector, guest_vmcs_va, &vmcs12_tr_selector);
	 

	UtilVmWrite(VmcsField::kGuestEsSelector, vmcs12_es_selector);
	UtilVmWrite(VmcsField::kGuestCsSelector, vmcs12_cs_selector);
	UtilVmWrite(VmcsField::kGuestSsSelector, vmcs12_ss_selector);
	UtilVmWrite(VmcsField::kGuestDsSelector, vmcs12_ds_selector);
	UtilVmWrite(VmcsField::kGuestFsSelector, vmcs12_fs_selector);
	UtilVmWrite(VmcsField::kGuestGsSelector, vmcs12_gs_selector);
	UtilVmWrite(VmcsField::kGuestLdtrSelector, vmcs12_ldtr_selector);
	UtilVmWrite(VmcsField::kGuestTrSelector, vmcs12_tr_selector); 

	/*
	Guest 32bit state field
	*/
	ULONG32 vmcs12_kGuestEsLimit;
	ULONG32 vmcs12_kGuestCsLimit;
	ULONG32 vmcs12_kGuestSsLimit;
	ULONG32 vmcs12_kGuestDsLimit;
	ULONG32 vmcs12_kGuestFsLimit;
	ULONG32 vmcs12_kGuestGsLimit;
	ULONG32 vmcs12_kGuestLdtrLimit;
	ULONG32 vmcs12_kGuestTrLimit;
	ULONG32 vmcs12_kGuestGdtrLimit;
	ULONG32 vmcs12_kGuestIdtrLimit;
	ULONG32 vmcs12_kGuestEsArBytes;
	ULONG32 vmcs12_kGuestCsArBytes;
	ULONG32 vmcs12_kGuestSsArBytes;
	ULONG32 vmcs12_kGuestDsArBytes;
	ULONG32 vmcs12_kGuestFsArBytes;
	ULONG32 vmcs12_kGuestGsArBytes;
	ULONG32 vmcs12_kGuestLdtrArBytes;
	ULONG32 vmcs12_kGuestTrArBytes;
	ULONG32 vmcs12_kGuestInterruptibilityInfo;
	ULONG32 vmcs12_kGuestActivityState;
	ULONG32 vmcs12_kGuestSysenterCs;

	// Read Guest 32 bit state field from VMCS12
	VmcsVmRead32(VmcsField::kGuestEsLimit, guest_vmcs_va, &vmcs12_kGuestEsLimit);
	VmcsVmRead32(VmcsField::kGuestCsLimit, guest_vmcs_va, &vmcs12_kGuestCsLimit);
	VmcsVmRead32(VmcsField::kGuestSsLimit, guest_vmcs_va, &vmcs12_kGuestSsLimit);
	VmcsVmRead32(VmcsField::kGuestDsLimit, guest_vmcs_va, &vmcs12_kGuestDsLimit);
	VmcsVmRead32(VmcsField::kGuestFsLimit, guest_vmcs_va, &vmcs12_kGuestFsLimit);
	VmcsVmRead32(VmcsField::kGuestGsLimit, guest_vmcs_va, &vmcs12_kGuestGsLimit);
	VmcsVmRead32(VmcsField::kGuestLdtrLimit, guest_vmcs_va, &vmcs12_kGuestLdtrLimit);
	VmcsVmRead32(VmcsField::kGuestTrLimit, guest_vmcs_va, &vmcs12_kGuestTrLimit);
	VmcsVmRead32(VmcsField::kGuestGdtrLimit, guest_vmcs_va, &vmcs12_kGuestGdtrLimit);
	VmcsVmRead32(VmcsField::kGuestIdtrLimit, guest_vmcs_va, &vmcs12_kGuestIdtrLimit);
	VmcsVmRead32(VmcsField::kGuestEsArBytes, guest_vmcs_va, &vmcs12_kGuestEsArBytes);
	VmcsVmRead32(VmcsField::kGuestCsArBytes, guest_vmcs_va, &vmcs12_kGuestCsArBytes);
	VmcsVmRead32(VmcsField::kGuestSsArBytes, guest_vmcs_va, &vmcs12_kGuestSsArBytes);
	VmcsVmRead32(VmcsField::kGuestDsArBytes, guest_vmcs_va, &vmcs12_kGuestDsArBytes);
	VmcsVmRead32(VmcsField::kGuestFsArBytes, guest_vmcs_va, &vmcs12_kGuestFsArBytes);
	VmcsVmRead32(VmcsField::kGuestGsArBytes, guest_vmcs_va, &vmcs12_kGuestGsArBytes);
	VmcsVmRead32(VmcsField::kGuestLdtrArBytes, guest_vmcs_va, &vmcs12_kGuestLdtrArBytes);
	VmcsVmRead32(VmcsField::kGuestTrArBytes, guest_vmcs_va, &vmcs12_kGuestTrArBytes);

	VmcsVmRead32(VmcsField::kGuestInterruptibilityInfo, guest_vmcs_va, &vmcs12_kGuestInterruptibilityInfo);
	VmcsVmRead32(VmcsField::kGuestActivityState, guest_vmcs_va, &vmcs12_kGuestActivityState);
	VmcsVmRead32(VmcsField::kGuestSysenterCs, guest_vmcs_va, &vmcs12_kGuestSysenterCs);

	UtilVmWrite(VmcsField::kGuestEsLimit, vmcs12_kGuestEsLimit);
	UtilVmWrite(VmcsField::kGuestCsLimit, vmcs12_kGuestCsLimit);
	UtilVmWrite(VmcsField::kGuestSsLimit, vmcs12_kGuestSsLimit);
	UtilVmWrite(VmcsField::kGuestDsLimit, vmcs12_kGuestDsLimit);
	UtilVmWrite(VmcsField::kGuestFsLimit, vmcs12_kGuestFsLimit);
	UtilVmWrite(VmcsField::kGuestGsLimit, vmcs12_kGuestGsLimit);
	UtilVmWrite(VmcsField::kGuestLdtrLimit, vmcs12_kGuestLdtrLimit);
	UtilVmWrite(VmcsField::kGuestTrLimit, vmcs12_kGuestTrLimit);
	UtilVmWrite(VmcsField::kGuestGdtrLimit, vmcs12_kGuestGdtrLimit);
	UtilVmWrite(VmcsField::kGuestIdtrLimit, vmcs12_kGuestIdtrLimit);

	UtilVmWrite(VmcsField::kGuestEsArBytes, vmcs12_kGuestEsArBytes);
	UtilVmWrite(VmcsField::kGuestCsArBytes, vmcs12_kGuestCsArBytes);
	UtilVmWrite(VmcsField::kGuestSsArBytes, vmcs12_kGuestSsArBytes);
	UtilVmWrite(VmcsField::kGuestDsArBytes, vmcs12_kGuestDsArBytes);
	UtilVmWrite(VmcsField::kGuestFsArBytes, vmcs12_kGuestFsArBytes);
	UtilVmWrite(VmcsField::kGuestGsArBytes, vmcs12_kGuestGsArBytes);
	UtilVmWrite(VmcsField::kGuestLdtrArBytes, vmcs12_kGuestLdtrArBytes);

	//Intel needs BUSY TSS for VMRESUME / VMLAUNCH
	UtilVmWrite(VmcsField::kGuestTrArBytes, vmcs12_kGuestTrArBytes | LONG_MODE_BUSY_TSS);

	UtilVmWrite(VmcsField::kGuestInterruptibilityInfo, vmcs12_kGuestInterruptibilityInfo);
	UtilVmWrite(VmcsField::kGuestActivityState, vmcs12_kGuestActivityState);
	UtilVmWrite(VmcsField::kGuestSysenterCs, vmcs12_kGuestSysenterCs);

	/*
	Guest 64 bit state field
	*/
	ULONG64 vmcs12_kIa32Debugctl;
	VmcsVmRead64(VmcsField::kGuestIa32Debugctl, guest_vmcs_va, &vmcs12_kIa32Debugctl);
	UtilVmWrite64(VmcsField::kVmcsLinkPointer, MAXULONG64);//不使用影子VMCS
	UtilVmWrite64(VmcsField::kGuestIa32Debugctl, vmcs12_kIa32Debugctl);

	/*
	Guest Natural width state field
	*/
	ULONG64 vmcs12_guest_Pending_dbg_exception;
	ULONG64 vmcs12_kGuestSysenterEsp;
	ULONG64 vmcs12_kGuestSysenterEip;
	ULONG64 vmcs12_kGuestEsBase;
	ULONG64	vmcs12_kGuestCsBase;
	ULONG64	vmcs12_kGuestSsBase;
	ULONG64	vmcs12_kGuestDsBase;
	ULONG64	vmcs12_kGuestFsBase;
	ULONG64	vmcs12_kGuestGsBase;
	ULONG64	vmcs12_kGuestLdtrBase;
	ULONG64	vmcs12_kGuestTrBase;
	ULONG64	vmcs12_kGuestGdtrBase;
	ULONG64	vmcs12_kGuestIdtrBase;
	ULONG64	vmcs12_kGuestDr7;
	ULONG64	vmcs12_kGuestRflags;
	ULONG64	vmcs12_kGuestCr0;
	ULONG64	vmcs12_kGuestCr3;
	ULONG64	vmcs12_kGuestCr4;
	ULONG64	vmcs12_kGuestRip;
	ULONG64	vmcs12_kGuestRsp;
	ULONG64	vmcs12_kGuestRlags;

	VmcsVmRead64(VmcsField::kGuestSysenterEsp, guest_vmcs_va, &vmcs12_kGuestSysenterEsp);
	VmcsVmRead64(VmcsField::kGuestSysenterEip, guest_vmcs_va, &vmcs12_kGuestSysenterEip);
	VmcsVmRead64(VmcsField::kGuestPendingDbgExceptions, guest_vmcs_va, &vmcs12_guest_Pending_dbg_exception);
	VmcsVmRead64(VmcsField::kGuestEsBase, guest_vmcs_va, &vmcs12_kGuestEsBase);
	VmcsVmRead64(VmcsField::kGuestCsBase, guest_vmcs_va, &vmcs12_kGuestCsBase);
	VmcsVmRead64(VmcsField::kGuestSsBase, guest_vmcs_va, &vmcs12_kGuestSsBase);
	VmcsVmRead64(VmcsField::kGuestDsBase, guest_vmcs_va, &vmcs12_kGuestDsBase);
	VmcsVmRead64(VmcsField::kGuestFsBase, guest_vmcs_va, &vmcs12_kGuestFsBase);
	VmcsVmRead64(VmcsField::kGuestGsBase, guest_vmcs_va, &vmcs12_kGuestGsBase);
	VmcsVmRead64(VmcsField::kGuestLdtrBase, guest_vmcs_va, &vmcs12_kGuestLdtrBase);
	VmcsVmRead64(VmcsField::kGuestTrBase, guest_vmcs_va, &vmcs12_kGuestTrBase);
	VmcsVmRead64(VmcsField::kGuestGdtrBase, guest_vmcs_va, &vmcs12_kGuestGdtrBase);
	VmcsVmRead64(VmcsField::kGuestIdtrBase, guest_vmcs_va, &vmcs12_kGuestIdtrBase);
	VmcsVmRead64(VmcsField::kGuestDr7, guest_vmcs_va, &vmcs12_kGuestDr7);
	VmcsVmRead64(VmcsField::kGuestRflags, guest_vmcs_va, &vmcs12_kGuestRflags);

	VmcsVmRead64(VmcsField::kGuestCr0, guest_vmcs_va, &vmcs12_kGuestCr0);
	VmcsVmRead64(VmcsField::kGuestCr4, guest_vmcs_va, &vmcs12_kGuestCr4);

	VmcsVmRead64(VmcsField::kGuestCr3, guest_vmcs_va, &vmcs12_kGuestCr3); 

	VmcsVmRead64(VmcsField::kGuestRip, guest_vmcs_va, &vmcs12_kGuestRip);
	VmcsVmRead64(VmcsField::kGuestRsp, guest_vmcs_va, &vmcs12_kGuestRsp);
	VmcsVmRead64(VmcsField::kGuestRflags, guest_vmcs_va, &vmcs12_kGuestRlags); 

	UtilVmWrite(VmcsField::kGuestSysenterEsp, vmcs12_kGuestSysenterEsp);
	UtilVmWrite(VmcsField::kGuestSysenterEip, vmcs12_kGuestSysenterEip);
	UtilVmWrite(VmcsField::kGuestPendingDbgExceptions, vmcs12_guest_Pending_dbg_exception);
	UtilVmWrite(VmcsField::kGuestEsBase, vmcs12_kGuestEsBase);
	UtilVmWrite(VmcsField::kGuestCsBase, vmcs12_kGuestCsBase);
	UtilVmWrite(VmcsField::kGuestSsBase, vmcs12_kGuestSsBase);
	UtilVmWrite(VmcsField::kGuestDsBase, vmcs12_kGuestDsBase);
	UtilVmWrite(VmcsField::kGuestFsBase, vmcs12_kGuestFsBase);
	UtilVmWrite(VmcsField::kGuestGsBase, vmcs12_kGuestGsBase);
	UtilVmWrite(VmcsField::kGuestLdtrBase, vmcs12_kGuestLdtrBase);
	UtilVmWrite(VmcsField::kGuestTrBase, vmcs12_kGuestTrBase);
	UtilVmWrite(VmcsField::kGuestGdtrBase, vmcs12_kGuestGdtrBase);
	UtilVmWrite(VmcsField::kGuestIdtrBase, vmcs12_kGuestIdtrBase);
	UtilVmWrite(VmcsField::kGuestDr7, vmcs12_kGuestDr7);
	UtilVmWrite(VmcsField::kGuestRflags, vmcs12_kGuestRflags);

	const Cr0 cr0_fixed0 = { UtilReadMsr(Msr::kIa32VmxCr0Fixed0) };
	const Cr0 cr0_fixed1 = { UtilReadMsr(Msr::kIa32VmxCr0Fixed1) };
	Cr0 cr0 = { vmcs12_kGuestCr0 };
	cr0.all &= cr0_fixed1.all;
	cr0.all |= cr0_fixed0.all;
	UtilVmWrite(VmcsField::kGuestCr0, cr0.all);
	UtilVmWrite(VmcsField::kCr0ReadShadow, cr0.all);

	const Cr4 cr4_fixed0 = { UtilReadMsr(Msr::kIa32VmxCr4Fixed0) };
	const Cr4 cr4_fixed1 = { UtilReadMsr(Msr::kIa32VmxCr4Fixed1) };
	Cr4 cr4 = { vmcs12_kGuestCr4 };
	cr4.all &= cr4_fixed1.all;
	cr4.all |= cr4_fixed0.all;
	UtilVmWrite(VmcsField::kGuestCr4, cr4.all);
	UtilVmWrite(VmcsField::kCr4ReadShadow, cr4.all);
	 
	UtilVmWrite(VmcsField::kGuestCr3, vmcs12_kGuestCr3); 
	UtilVmWrite(VmcsField::kGuestRip, vmcs12_kGuestRip);
	UtilVmWrite(VmcsField::kGuestRsp, vmcs12_kGuestRsp);
	UtilVmWrite(VmcsField::kGuestRflags, vmcs12_kGuestRlags);
	
	//HYPERPLATFORM_COMMON_DBG_BREAK();
	if (VmxIsGuestPaePaging())
	{
		VmxSecondaryProcessorBasedControls vm_second_ctrl = { UtilVmRead(VmcsField::kSecondaryVmExecControl) };
		if (vm_second_ctrl.fields.enable_ept)
		{
		//	UtilLoadPdptes(UtilVmRead(VmcsField::kGuestCr3));
		}
	}

	// Guest stated field END
}
//-------------------------------------------------------------------------------------------------------------------------------------//

}

