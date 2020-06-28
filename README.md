# kHypervisor

# Introduction
kHypervisor is an Open Source light-weighted Hypervisor that's capable for nested virtualization in Windows x64 platform, as an extended work of HyperPlatform

# Environment
  * Visual Studio 2015 update 3 
  * Windows SDK 10
  * Windowr Driver Kit 10 
  * VMware 12 with EPT environment. 
  * Supports Multi-core processor environment
  * Test environment with Windows 7 x64 sp1 to Windows 10 x64 build 16299 RS3
  * It onlys support restricted guest (protected - paging mode) for the present

# Description
The kHypervisor is completed in lab machines, please test kHypervisor in your VMWare or newly installed machine for best experience. 

# Supported Event
* Virtualized VMX environment
* Virtualized Guest EPT 
* VMCS Emulation
* VMExit  Emulation
* VMEntry Emulation, including VMEntry parameter check same as hardware spec.
* VMCALL  Redirection
* Processor Exception / Interrupt Injection
 
# Advantages
kHypervisor provide an light-weighted virtulized environment for nesting Guest Hypervisor
- VM Entry Emulation with VMCS state check which is a good solution for debugging VMEntry fail, and locate the actual failure location.
- VM Exit  Emulation 
- Nested VM Exit Event
- The code is simple and minimize as a nested vmm.

# Progress
`2016-10-19`  First commit, Supporting nested itself only, and nested software breakpoint exception from Level 2. And the nested-Vmm is able to dispatch this exception to L1 and help L1 to resume to L2.

`2016-10-21`  Fixed Ring-3 vm-exit emulation error. 

`2017-01-03`  Refactor project, and Finding VMCS12 through VMCS02 by executing vmptrst 

`2017-01-22`  GS Kernel base MSR bug fixed when Emulation VMRESUME/VMLAUNCH 

`2017-02-05`  VPID shared between VMCS0-1 and VMCS0-2, support multi-processor.

`2017-02-08 ` Emulate VMExit behaviour has been slightly Changed. in case of L2 is trapped by L0, and L0 emulate VMExit to L1, this time of VMRESUME will not be restore a Guest CR8 and Guest IRQL, it is until VMRESUME by L1. (L0 helps L1 resume to L2) 

`2017-05-28`  Fixed Nested-CPUID problem, and add Nested-VMCALL.

`2017-06-07`  Fixed a VMExit buggy , clear the guest eflags, and reserved bit[1] == 1 

`2017-06-08`  Adding a support for Monitor Trap Flags from L2 and perform Nested VMExit

`2017-11-21`  Added VM-Entry Check Emulation , Bug Fixed

`2018-01-19`  Added Nest-Msr Access support , plus, a better coding style changes. Add Test in Windows x64 build 16299 RS3.Release  

`2018-02-05`  Added Nested EPT which is running in Windows 7 x64 build 7601 system. (still not test by Windows 10)

`2018-03-28`  Use lateste version repo of Ddimon as a being nested-target, deleted nested-vmm

`2018-03-29`  Added Nested EPT monitoring , when the PTE entry OF guest EPT is modified, L0 knows.

`2020-03-07`  Refactored and testing on DdiMon

`2020-06-27`  Fixed MSR out of index for reserved MSR (0x40000000 ~ 0x400000FF)
# Installation

 * kHypervisor extended HyperPlatform which is created by Satoshi Tanda, it is a Nested-Virtual Machine Monitor, and DdiMon is one of instance of HyperPlatform for test demo in kHypervisor.

   *  Compiled kHypervisor.sys and DdiMon.sys by kHypervisor and NestedHypervisor respectively

   *  We supports a multi-core environment 

   *  Enable Testsigning on x64:
   
         `bcdedit /set testsigning on` 
   
   *  Install DdiMon.sys and kHypervisor.sys by following command:
   
         `sc create hostvmm type= kernel binPath= C:\kHypervisor.sys`
         
         `sc create nestedvmm type= kernel binPath= C:\Ddimon.sys`
         
   * start a service as following screen capture with its expected output
   
 
# Live Demo with kernel rootkit
  [![Alt text](https://img.youtube.com/vi/wRCDeucwfiM/0.jpg)](https://www.youtube.com/watch?v=wRCDeucwfiM)
   
# Nesting VT-x EPT for EPT Based Rootkit - DdiMon 

   <img src="https://user-images.githubusercontent.com/22551808/76154782-49a37a00-6097-11ea-8f54-e0b537cefb4f.png" width="70%" height="70%"> </img> 
  
 # Windows 10 x64 build 16299 RS3 Test Demo (with Nested EPT) :

   <img src="https://user-images.githubusercontent.com/22551808/35140833-a7896dec-fd33-11e7-9c96-179e7cbd73fd.png" width="70%" height="70%"> </img>

   <img src="https://user-images.githubusercontent.com/22551808/35140835-a7b8d186-fd33-11e7-8c3d-583eba6bd9a0.png" width="70%" height="70%"> </img>   
        
# Kenrel mode Test (Nested breakpoint INT3 exception)
 
 #### 1. During the installion we could be able to see a result, since we set a breakpoint as soon as the DdiMon's virtualization. </br>
 <img src="https://cloud.githubusercontent.com/assets/22551808/21608786/796ca796-d1f9-11e6-98c7-853933c7447b.png" width="50%" height="50%"> </img>
 #### 2. We can see the windbg as following result, after the DdiMon execute a breakpoint, kHypervisor will first capture the breakpoint : </br>
  <img src="https://cloud.githubusercontent.com/assets/22551808/21608841/ce0d11aa-d1f9-11e6-8014-db882836c751.png" width="50%" height="50%"> </img>
 #### 3. After printed VMCS, the emulation of vmexit is done, and kHypervisor will find out which is the original handler as following, the control flow is transfer to DdiMon now. (the kHypervisor is not supposed exists by Ddimon, but it does.)
  <img src="https://cloud.githubusercontent.com/assets/22551808/21608895/50274d54-d1fa-11e6-84a2-fddd41b5d2b5.png" width="50%" height="50%"> </img>
 #### 4. After the DdiMon catch up the control flow, it will normally execute a <b>VMRESUME</b>, since he didn't know anythings, and feel it is normal trap only :) </br>

# User Mode Test  (Nested breakpoint INT3 Exception)
  
 #### A INT 3 breakpoint in the system will be work as follow:

 #### 1. We start any program with x64dbg, and the debugger will break the process, and L0 should catch the exception.  </br>
  <img src="https://cloud.githubusercontent.com/assets/22551808/21672418/6d6e8760-d35d-11e6-9679-b74eeabf9742.png" width="50%" height="50%"/>
 </img>
 
 #### 2. we handled it, and we will emulate the VMExit to L1 by execute VMRESUME with L1's host VMM Handler address (guest rip == L1's host rip, the mode of VCPU will be rooted, but actually it is non-rooted, so that after the L1's VMM handled it, it called VMRESUME will trapped by L0 again. )</br>
 <img src="https://cloud.githubusercontent.com/assets/22551808/21672419/6d74a1cc-d35d-11e6-9c96-3a7b3547bd4f.png" width="50%" height="50%"/>
 </img> 
 
 #### 3. Once again trapped by VMRESUME , we emulated the VMRESUME with trapped address. Help L1 resume to L2</br>
 <img src="https://cloud.githubusercontent.com/assets/22551808/21672420/6d7935e8-d35d-11e6-989c-4afb97f65047.png" width="50%" height="50%"/>
</img></br>
 
 # Nested VMCALL Emulation (Turning off L1 VMM By VMCALL)
  <img src="https://user-images.githubusercontent.com/22551808/33070774-1c3ffde0-cef4-11e7-93cc-2316ef1f9aff.jpg" width="50%" height="50%"> </img>
  
 # Nested EPT Modification monitoring 
   <img src="https://user-images.githubusercontent.com/22551808/38097002-d4d521fc-33a6-11e8-95ad-67b22f92c558.png" width="70%" height="70%"/>
</img></br>

  # P.S.
  With a highest stablility, better close nested-EPT or running nested-EPT in a unicore enivronment first. 
 
# TODO
 - Fully Support CPU Feature from vCPU aspect.
 - ~~EPT virtualization~~
 - APIC virtualization
 - Unrestricted guest support (vbox) , such as virtual 8086 mode.
 
# Related Project(s)
 https://github.com/tandasat/HyperPlatform </br>
 https://github.com/tandasat/ddimon</br>
 
# License
This software is released under the MIT License, see LICENSE.
 
