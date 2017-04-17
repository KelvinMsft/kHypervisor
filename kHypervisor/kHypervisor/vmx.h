// Copyright (c) 2016-2017, KelvinChan. All rights reserved.
// Copyright (c) 2016-2017, KelvinChan. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

#ifndef NESTED_HYPERPLATFORM_VMX_H_
#define NESTED_HYPERPLATFORM_VMX_H_
#include <fltKernel.h>
#include "..\HyperPlatform\vmm.h"
#include "..\HyperPlatform\util.h"
extern struct GuestContext;
extern "C"
{

VOID VmxonEmulate(
	GuestContext* guest_context
);

VOID VmxoffEmulate(
	GuestContext* guest_context
);

VOID VmclearEmulate(
	GuestContext* guest_context
);

VOID VmptrldEmulate(
	GuestContext* guest_context
);

VOID VmreadEmulate(
	GuestContext* guest_context
);

VOID VmwriteEmulate(
	GuestContext* guest_context
);

VOID VmlaunchEmulate(
	GuestContext* guest_context
);

VOID VmresumeEmulate(
	GuestContext* guest_context
);

VOID VmptrstEmulate(
	GuestContext* guest_context
);

VOID LEAVE_GUEST_MODE(
	NestedVmm* vcpu
);
VOID ENTER_GUEST_MODE(
	NestedVmm* vcpu
);
BOOLEAN IsRootMode(
	NestedVmm* vcpu
);  

BOOLEAN VMExitEmulationTest(
	NestedVmm* vCPU,
	VmExitInformation exit_reason,
	GuestContext* guest_context
);

}

#endif