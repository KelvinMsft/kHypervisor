#ifndef HYPERPLATFORM_VARHIDE_H_
#define HYPERPLATFORM_VARHIDE_H_
#include "../HyperPlatform/HyperPlatform/kernel_stl.h"
#include "ntifs.h"
#include <fltKernel.h>
#include <string>
#include <shadow_hook.h>
#define NTSTRSAFE_NO_CB_FUNCTIONS
#include <ntstrsafe.h>
#include "../HyperPlatform/HyperPlatform/common.h"
#include "../HyperPlatform/HyperPlatform/log.h"
#include "../HyperPlatform/HyperPlatform/util.h"
#include "../HyperPlatform/HyperPlatform/ept.h"
#include <vector>
#include <memory>
#include <algorithm>
#include <array>
#include "cs_driver_mm.h"
using namespace std;
struct HookInformation;
struct HideInformation;
extern SharedShadowHookData shared_sh_data;

HideInformation* FindPatchInfoByAddress(SharedShadowHookData* data, void* address);


struct MyPage {
	UCHAR* page;
	MyPage();
	~MyPage(); 
};

struct ShadowHookData;
struct HideInformation {
	void* patch_address;  // An address where a hook is installed
	void* handler;        // An address of the handler routine

						  // A copy of a pages where patch_address belongs to. shadow_page_base_for_rw
						  // is exposed to a guest for read and write operation against the page of
						  // patch_address, and shadow_page_base_for_exec is exposed for execution.
	std::shared_ptr<MyPage> shadow_page_base_for_rw;	//VA for rw hooking page of created / retrieved page of Original page
	std::shared_ptr<MyPage> shadow_page_base_for_exec;  //VA for exec hooking page of created / retrieved page of Original page

													  // Phyisical address of the above two copied pages
	ULONG64 pa_base_for_rw;							//PA of above
	ULONG64 pa_base_for_exec;							//PA of above

														// A name of breakpont (a DDI name)
	string name;

	PEPROCESS proc;									//no use
	ULONG64 P_patchaddress;							//no use
	bool isRing3;							

};

class VariableHiding
{
public:
	struct {
		void *address;
		ULONG_PTR set_value;
		string hookName;
		ULONG bytes;
		bool bcopy;
	};
	
	//unique_ptr cannot use with extern type !!!
	std::unique_ptr<HideInformation> CreateHidingInformation(
		PVOID address, 
		ULONG byte, 
		ULONG_PTR setValue, 
		string name,
		bool copy);
	
	VOID set_global_array(SharedShadowHookData* data) {
		this->data = data;
	}
	_Use_decl_annotations_ static HookInformation* FindPatchInfoByAddress(
		const SharedShadowHookData* shared_sh_data,
		void* address);
private:
	SharedShadowHookData* data;	
public:
	VariableHiding();
	~VariableHiding();
};
#endif