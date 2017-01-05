# kHypervisor
kHypervisor is an Open Source light-weighted Nested-Virtual Machine Monitor in Windows x64 platform. Temporarily not supported multi-core yet, and which is using a VT framework from Hyper-platform :-)

#Environment
- Visual Studio 2015 update 3 
- Windows SDK 10
- Windowr Driver Kit 10
- Single Core CPU (Temporarily)
- VMware 12 with EPT environment.
- Windbg

#Description
The kHypervisor is not yet completed, and it will be rapidly update on progress, please using a windbg+vmware 12 for debugging kHypervisor. Otherwise, it will be bugcheck by driver verifier(0xC4)

#Progress
2016-10-19 :  First commit, Supporting nested itself only, and nested software breakpoint exception from Level 2. And the nested-Vmm is able to dispatch this exception to L1 and help L1 to resume to L2.


2016-10-21 : Fixed Ring-3 vm-exit emulation error. 

2017-01-03 : Reconstruct project, and Finding VMCS12 through VMCS02 by executing vmptrst 

#Installation

 - kHypervisor extended HyperPlatform which is created by Tandasat, it is a Nested-Virtual Machine Monitor, and DdiMon is one of Tandasat's product of HyperPlatform for test demo in kHypervisor.

 1. Compiled kHypervisor.sys and DdiMon.sys by kHypervisor and NestedHypervisor respectively

 2. We only support Signle core temporarily. (We can set a multi-core by msconfig.exe)

 3. Install DdiMon.sys and kHypervisor.sys by following command:

  -  sc create hostvmm type= kernel binPath= C:\kHypervisor.sys 
  
  -  sc create nestedvmm type= kernel binPath= C:\Ddimon.sys

 4. start a service as following screen capture with its expected output : 

 <img src="https://cloud.githubusercontent.com/assets/22551808/21606548/47069716-d1eb-11e6-9620-4c7262aad172.png" width="50%" height="50%"> </img>

#Expected Output
 kHypervisor can be tested by kernel/user mode with Single-Core Processor Configuration 
 
#Kenrel mode Test: 
 
 1. During the installion we could able to see a result, since we set a breakpoint as soon as the DdiMon's virtualization. </br>
 <img src="https://cloud.githubusercontent.com/assets/22551808/21608786/796ca796-d1f9-11e6-98c7-853933c7447b.png" width="70%" height="70%"> </img>
 2. We can see the windbg as following result, after the DdiMon execute a breakpoint, kHypervisor will first capture the breakpoint : </br>
  <img src="https://cloud.githubusercontent.com/assets/22551808/21608841/ce0d11aa-d1f9-11e6-8014-db882836c751.png" width="70%" height="70%"> </img>
 3. After printed VMCS, the emulation of vmexit is done, and kHypervisor will find out which is the original handler as following, the control flow is transfer to DdiMon now. (the kHypervisor is not supposed exists by Ddimon, but it does.)
  <img src="https://cloud.githubusercontent.com/assets/22551808/21608895/50274d54-d1fa-11e6-84a2-fddd41b5d2b5.png" width="70%" height="70%"> </img>
 4. After the DdiMon catch up the control flow, it will normally execute a <b>VMRESUME</b>, since he didn't know anythings, and feel it is normal trap only :) </br>

 #User Mode Test:  
  
  Any everybreakpoint in the system will be work as follow:

 1: We start any program with x64dbg, and the debugger will break the process, and L0 should catch the exception.  </br>
  <img src="https://cloud.githubusercontent.com/assets/22551808/21672418/6d6e8760-d35d-11e6-9679-b74eeabf9742.png" width="70%" height="70%"/>
 </img>
 </br>
 2:  we handled it, and we will emulate the VMExit to L1 by execute VMRESUME with L1's host VMM Handler address (guest rip == L1's host rip, the mode of VCPU will be rooted, but actually it is non-rooted, so that after the L1's VMM handled it, it called VMRESUME will trapped by L0 again. )</br>
 <img src="https://cloud.githubusercontent.com/assets/22551808/21672419/6d74a1cc-d35d-11e6-9c96-3a7b3547bd4f.png" width="70%" height="70%"/>
 </img>
 3:  Once again trapped by VMRESUME , we emulated the VMRESUME with trapped address. Help L1 resume to L2</br>
 <img src="https://cloud.githubusercontent.com/assets/22551808/21672420/6d7935e8-d35d-11e6-989c-4afb97f65047.png" width="70%" height="70%"/>
</img></br>
 
#TODO
 - Fully Support CPU Feature from vCPU aspect.
 - EPT virtualization
 - APIC virtualization
 - Multi-core Support
 
