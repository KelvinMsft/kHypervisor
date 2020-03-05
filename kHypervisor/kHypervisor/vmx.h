/*++

Copyright (c) 2016 KelvinChan. All rights reserved.
Use of this source code is governed by a MIT-style license that can be
found in the LICENSE file.

Module Name:

	vmx.h

Abstract:

	VMX Instruction Emulation

Author:
	
	Kelvin Chan

Environment:

	Kernel VMM Mode

--*/
#pragma once
#ifndef NESTED_HYPERPLATFORM_VMX_H_
#define NESTED_HYPERPLATFORM_VMX_H_
#include <fltKernel.h>
#include "..\HyperPlatform\vmm.h"
#include "..\HyperPlatform\util.h"

struct GuestContext;

enum VMX_state
{
	VMCS_STATE_CLEAR = 0,
	VMCS_STATE_LAUNCHED
};

extern "C"
{

VOID 
VmxVmxonEmulate(
	_In_ GuestContext* guest_context
);

VOID 
VmxVmxoffEmulate(
	_In_ GuestContext* guest_context
);

VOID 
VmxVmclearEmulate(
	_In_ GuestContext* guest_context
);

VOID 
VmxVmptrldEmulate(
	_In_ GuestContext* guest_context
);

VOID 
VmxVmreadEmulate(
	_In_ GuestContext* guest_context
);

VOID 
VmxVmwriteEmulate(
	_In_ GuestContext* guest_context
);

VOID 
VmxVmlaunchEmulate(
	_In_ GuestContext* guest_context
);

VOID 
VmxVmresumeEmulate(
	_In_ GuestContext* guest_context
);

VOID 
VmxVmptrstEmulate(
	_In_ GuestContext* guest_context
);

VOID VmxInveptEmulate(
	_In_ GuestContext* guest_context
);
VOID 
LEAVE_GUEST_MODE(
	_In_ VCPUVMX* vcpu
);
VOID 
ENTER_GUEST_MODE(
	_In_ VCPUVMX* vcpu
);
VMX_MODE
VmxGetVmxMode(
	_In_ VCPUVMX* vcpu
);  

NTSTATUS 
VmxVMExitEmulate(
	_In_ VCPUVMX* vCPU,
	_In_ GuestContext* guest_context
);

}

#endif