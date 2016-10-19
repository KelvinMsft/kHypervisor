#include "vmcs.h"
#include "..\HyperPlatform\HyperPlatform\log.h"

unsigned		 g_vmcs_map[16][1 + VMX_HIGHEST_VMCS_ENCODING];

BOOLEAN RegularCheck()
{
	return FALSE;
}

BOOLEAN is_vmcs_field_supported(VmcsField encoding)
{
	switch (encoding)
	{
#if BX_SUPPORT_VMX >= 2
		/* VMCS 16-bit control fields */
		/* binary 0000_00xx_xxxx_xxx0 */
	case VMCS_16BIT_CONTROL_VPID:
		return 1;
#endif

		/* VMCS 16-bit guest-state fields */
		/* binary 0000_10xx_xxxx_xxx0 */
	case VmcsField::kHostEsSelector:
	case VmcsField::kHostCsSelector:
	case VmcsField::kHostSsSelector:
	case VmcsField::kHostDsSelector:
	case VmcsField::kHostFsSelector:
	case VmcsField::kHostGsSelector:
	case VmcsField::kHostTrSelector:
		return 1;

		/* VMCS 16-bit host-state fields */
		/* binary 0000_11xx_xxxx_xxx0 */
	case VmcsField::kGuestEsSelector:
	case VmcsField::kGuestCsSelector:
	case VmcsField::kGuestSsSelector:
	case VmcsField::kGuestDsSelector:
	case VmcsField::kGuestFsSelector:
	case VmcsField::kGuestGsSelector:
	case VmcsField::kGuestTrSelector:
	case VmcsField::kGuestLdtrSelector:
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
#if BX_SUPPORT_X86_64
	case VmcsField:kTprThreshold:
#endif
#if BX_SUPPORT_VMX >= 2
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
#if BX_SUPPORT_X86_64
	case VmcsField::kVirtualApicPageAddr:
	case VmcsField::kVirtualApicPageAddrHigh:
#endif
#if BX_SUPPORT_VMX >= 2
	case VmcsField::kApicAccessAddr:
	case VmcsField::kApicAccessAddrHigh:
	case VmcsField::kEptPointer:
	case VmcsField::kEptPointerHigh:
#endif
		return 1;

#if BX_SUPPORT_VMX >= 2
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
#if BX_SUPPORT_VMX >= 2
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

#if BX_SUPPORT_VMX >= 2
		/* VMCS 64-bit host state fields */
		/* binary 0010_11xx_xxxx_xxx0 */
	case VmcsField::kGuestIa32Pat:
	case VmcsField::kGuestIa32PatHigh:
	case VmcsField::kGuestIa32Efer:
	case VmcsField::kGuestIa32EferHigh:
		return 1;
#endif
		/*
		/* VMCS natural width control fields */
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


VOID BuildGernericVMCSMap()
{
	static bool vmcs_map_ready = 0;
	unsigned type, index;

	if (vmcs_map_ready)
		return;

	vmcs_map_ready = 1;

	for (type = 0; type<16; type++)
	{
		for (index = 0; index <= VMX_HIGHEST_VMCS_ENCODING; index++)
		{
			//初始化每一種類的每一個field
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
				HYPERPLATFORM_LOG_DEBUG("VMCS type %d field %d (encoding = 0x%08x) is already initialized", type, index, encoding);
			}
			if (is_vmcs_field_supported(VmcsField(encoding)))
			{
				// allocate 64 fields (4 byte each) per type
				g_vmcs_map[type][index] = VMCS_DATA_OFFSET + (type * 64 + index) * 4;
				if (g_vmcs_map[type][index] >= VMX_VMCS_AREA_SIZE)
				{
					HYPERPLATFORM_LOG_DEBUG("VMCS type %d field %d (encoding = 0x%08x) is out of VMCS boundaries", type, index, encoding);
				}
			}
		}
	}

	for (type = 0; type < 16; type++)
	{
		for (index = 0; index <= VMX_HIGHEST_VMCS_ENCODING; index++)
		{
			HYPERPLATFORM_LOG_DEBUG("Type: %d Field: %d = value: %x \r\n", type, index, g_vmcs_map[type][index]);
		}
	}
}