#include "VarHide.h"
// .h ---> shaodo.cpp
std::unique_ptr<HideInformation> VariableHiding::CreateHidingInformation(
	PVOID address,
	ULONG byte,
	ULONG_PTR setValue, 
	string name,
	bool copy)
{
	auto page_base = PAGE_ALIGN(address);
	auto info = std::make_unique<HideInformation>();
	info->shadow_page_base_for_rw = std::make_shared<MyPage>();
	info->shadow_page_base_for_exec = std::make_shared<MyPage>();
	
	 if (page_base == NULL) {
		 HYPERPLATFORM_LOG_INFO("base is null..");
		return NULL;
	}
	RtlCopyMemory(info->shadow_page_base_for_exec->page, page_base, PAGE_SIZE);
	RtlCopyMemory(info->shadow_page_base_for_rw->page, page_base, PAGE_SIZE);
	if (!info->shadow_page_base_for_exec || !info->shadow_page_base_for_rw) {
		HYPERPLATFORM_LOG_INFO("copy error");
		return NULL;
	}
	info->name = name;
	info->patch_address = address;
	info->pa_base_for_rw = UtilPaFromVa(info->shadow_page_base_for_rw->page);
	info->pa_base_for_exec = UtilPaFromVa(info->shadow_page_base_for_exec->page);
	
	HYPERPLATFORM_LOG_INFO("\r\n hiding address : 0x%I64X  \r\n name : %s \r\n PA(RW) : 0x%I64X PA(Exec) : 0x%I64X \r\n VA(RW) : 0x%I64X VA(Exec) : 0x%I64X  \r\n  ",
		info->patch_address,
		info->name,
		info->pa_base_for_rw,
		info->pa_base_for_exec,
		info->shadow_page_base_for_rw,
		info->shadow_page_base_for_exec
		);
	
	return info;
}

VariableHiding::VariableHiding()
{
}

VariableHiding::~VariableHiding()
{
}
MyPage::MyPage()
	: page(reinterpret_cast<UCHAR*>(ExAllocatePoolWithTag(
		NonPagedPool, PAGE_SIZE, kHyperPlatformCommonPoolTag))) {
	if (!page) {
		HYPERPLATFORM_COMMON_BUG_CHECK(
			HyperPlatformBugCheck::kCritialPoolAllocationFailure, 0, 0, 0);
	}
}

// De-allocates the allocated page
MyPage::~MyPage() { ExFreePoolWithTag(page, kHyperPlatformCommonPoolTag); }
