// Copyright (c) 2015-2016, tandasat. All rights reserved.
// Copyright (c) 2016-2017, KelvinChan. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Implements EPT functions.

#include "ept.h"
#include "asm.h"
#include "common.h"
#include "log.h"
#include "util.h"
#include "performance.h"

extern "C" {
////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// types
//




#include <pshpack1.h>
struct MtrrData {
	bool enabled;        //<! Whether this entry is valid
	bool fixedMtrr;      //<! Whether this entry manages a fixed range MTRR
	UCHAR type;          //<! Memory Type (such as WB, UC)
	bool reserverd1;     //<! Padding
	ULONG reserverd2;    //<! Padding
	ULONG64 range_base;  //<! A base address of a range managed by this entry
	ULONG64 range_end;   //<! An end address of a range managed by this entry
};
#include <poppack.h>

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

// Followings are how 64bits of a physical address is used to locate EPT
// entries:
//
// EPT Page map level 4 selector           9 bits
// EPT Page directory pointer selector     9 bits
// EPT Page directory selector             9 bits
// EPT Page table selector                 9 bits
// EPT Byte within page                   12 bits

// Get the highest 25 bits
static const auto kEptpPxiShift = 39ull;

// Get the highest 34 bits
static const auto kEptpPpiShift = 30ull;

// Get the highest 43 bits
static const auto kEptpPdiShift = 21ull;

// Get the highest 52 bits
static const auto kEptpPtiShift = 12ull;

// Use 9 bits; 0b0000_0000_0000_0000_0000_0000_0001_1111_1111
static const auto kEptpPtxMask = 0x1ffull;

// Architecture defined number of variable range MTRRs
static const auto kEptpNumOfMaxVariableRangeMtrrs = 255;

// Architecture defined number of fixed range MTRRs (1 for 64k, 2 for 16k, 8
// for 4k)
static const auto kEptpNumOfFixedRangeMtrrs = 1 + 2 + 8;

// A size of array to store all possible MTRRs
static const auto kEptpMtrrEntriesSize =
kEptpNumOfMaxVariableRangeMtrrs + kEptpNumOfFixedRangeMtrrs;


// How many EPT entries are preallocated. When the number exceeds it, the
// hypervisor issues a bugcheck.
static const auto kEptpNumberOfPreallocatedEntries = 50;

static MtrrData g_eptp_mtrr_entries[kEptpMtrrEntriesSize];

static UCHAR g_eptp_mtrr_default_type;
static_assert(sizeof(MtrrData) == 24, "Size check");
////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

struct GuestContext;

typedef void(*pEptWalkerCallback)(EptCommonEntry* entry, void* Context);

//----------------------------------------------------------------------------------------------------------------//
NTSTATUS VmmpSetLastFaultAddr(
	_In_ GuestContext *guest_context,
	_In_ ULONG_PTR	LastFaultAddr
);


_When_(ept_data == nullptr,
	_IRQL_requires_max_(DISPATCH_LEVEL)) static EptCommonEntry
	*EptpConstructTables(_In_ EptCommonEntry *table, _In_ ULONG table_level,
		_In_ ULONG64 physical_address,
		_In_opt_ EptData *ept_data);

static void EptpDestructTables(_In_ EptCommonEntry *table,
	_In_ ULONG table_level);

_Must_inspect_result_ __drv_allocatesMem(Mem)
_When_(ept_data == nullptr,
	_IRQL_requires_max_(DISPATCH_LEVEL)) static EptCommonEntry
	*EptpAllocateEptEntry(_In_opt_ EptData *ept_data);

static EptCommonEntry *EptpAllocateEptEntryFromPreAllocated(
	_In_ EptData *ept_data);

_Must_inspect_result_ __drv_allocatesMem(Mem) _IRQL_requires_max_(
	DISPATCH_LEVEL) static EptCommonEntry *EptpAllocateEptEntryFromPool();

static void EptpInitTableEntry(_In_ EptCommonEntry *Entry,
	_In_ ULONG table_level,
	_In_ ULONG64 physical_address);

static ULONG64 EptpAddressToPxeIndex(_In_ ULONG64 physical_address);

static ULONG64 EptpAddressToPpeIndex(_In_ ULONG64 physical_address);

static ULONG64 EptpAddressToPdeIndex(_In_ ULONG64 physical_address);

static ULONG64 EptpAddressToPteIndex(_In_ ULONG64 physical_address);

static bool EptpIsDeviceMemory(_In_ ULONG64 physical_address);

static EptCommonEntry *EptpGetEptPtEntry(_In_ EptCommonEntry *table,
	_In_ ULONG table_level,
	_In_ ULONG64 physical_address);

static void EptpFreeUnusedPreAllocatedEntries(
	_Pre_notnull_ __drv_freesMem(Mem) EptCommonEntry **preallocated_entries,
	_In_ long used_count);

_Use_decl_annotations_ void EptHandleEptViolationEx(
	_In_ EptData *ept_data,
	_In_ ULONG64 PhysAddr,
	_In_ bool is_range_of_ept12);


#if defined(ALLOC_PRAGMA)
#pragma alloc_text(PAGE, EptIsEptAvailable)
#pragma alloc_text(PAGE, EptInitialization)
#pragma alloc_text(PAGE, EptInitializeMtrrEntries) 
#endif

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

_Use_decl_annotations_ static bool EptpWalker(
	EptCommonEntry *table,
	ULONG table_level,
	pEptWalkerCallback callback,
	void* context)
{
	bool ret = false;
	for (auto i = 0ul; i < 512; ++i)
	{
		const auto entry = table[i];
		if (callback) {
			callback(&table[i], context);
		} 

		if (table_level == 1) {
			continue;
		}

		if (entry.fields.physial_address)
		{
			const auto sub_table = reinterpret_cast<EptCommonEntry *>(
				UtilVaFromPfn(entry.fields.physial_address));

			switch (table_level) {
			case 4:  // table == PML4, sub_table == PDPT
			case 3:  // table == PDPT, sub_table == PDT
			case 2:  // table == PDT, sub_table == PT 	
				ret = EptpWalker(sub_table, table_level - 1, callback, context);
				break;
			case 1:
				break;
			default:
				HYPERPLATFORM_COMMON_DBG_BREAK();
				break;
			}
		}
	}
	return ret;
}
// Reads and stores all MTRRs to set a correct memory type for EPT
_Use_decl_annotations_ void EptInitializeMtrrEntries() {
	PAGED_CODE();

	int index = 0;
	MtrrData *mtrr_entries = g_eptp_mtrr_entries;

	// Get and store the default memory type
	Ia32MtrrDefaultTypeMsr default_type = { UtilReadMsr64(Msr::kIa32MtrrDefType) };
	g_eptp_mtrr_default_type = default_type.fields.default_mtemory_type;

	// Read MTRR capability
	Ia32MtrrCapabilitiesMsr mtrr_capabilities = {
		UtilReadMsr64(Msr::kIa32MtrrCap) };
	HYPERPLATFORM_LOG_DEBUG(
		"MTRR Default=%lld, VariableCount=%lld, FixedSupported=%lld, FixedEnabled=%lld",
		default_type.fields.default_mtemory_type,
		mtrr_capabilities.fields.variable_range_count,
		mtrr_capabilities.fields.fixed_range_supported,
		default_type.fields.fixed_mtrrs_enabled);

	// Read fixed range MTRRs if supported
	if (mtrr_capabilities.fields.fixed_range_supported &&
		default_type.fields.fixed_mtrrs_enabled) {
		static const auto k64kBase = 0x0;
		static const auto k64kManagedSize = 0x10000;
		static const auto k16kBase = 0x80000;
		static const auto k16kManagedSize = 0x4000;
		static const auto k4kBase = 0xC0000;
		static const auto k4kManagedSize = 0x1000;

		// The kIa32MtrrFix64k00000 manages 8 ranges of memory. The first range
		// starts at 0x0, and each range manages a 64k (0x10000) range. For example,
		//  entry[0]:     0x0 : 0x10000 - 1
		//  entry[1]: 0x10000 : 0x20000 - 1
		//  ...
		//  entry[7]: 0x70000 : 0x80000 - 1
		ULONG64 offset = 0;
		Ia32MtrrFixedRangeMsr fixed_range = {
			UtilReadMsr64(Msr::kIa32MtrrFix64k00000) };
		for (auto memory_type : fixed_range.fields.types) {
			// Each entry manages 64k (0x10000) length.
			ULONG64 base = k64kBase + offset;
			offset += k64kManagedSize;

			// Saves the MTRR
			mtrr_entries[index].enabled = true;
			mtrr_entries[index].fixedMtrr = true;
			mtrr_entries[index].type = memory_type;
			mtrr_entries[index].range_base = base;
			mtrr_entries[index].range_end = base + k64kManagedSize - 1;
			index++;
		}
		NT_ASSERT(k64kBase + offset == k16kBase);

		// kIa32MtrrFix16k80000 manages 8 ranges of memory. The first range starts
		// at 0x80000, and each range manages a 16k (0x4000) range. For example,
		//  entry[0]: 0x80000 : 0x84000 - 1
		//  entry[1]: 0x88000 : 0x8C000 - 1
		//  ...
		//  entry[7]: 0x9C000 : 0xA0000 - 1
		// Also, subsequent memory ranges are managed by other MSR,
		// kIa32MtrrFix16kA0000, which manages 8 ranges of memory starting at
		// 0xA0000 in the same fashion. For example,
		//  entry[0]: 0xA0000 : 0xA4000 - 1
		//  entry[1]: 0xA8000 : 0xAC000 - 1
		//  ...
		//  entry[7]: 0xBC000 : 0xC0000 - 1
		offset = 0;
		for (auto msr = static_cast<ULONG>(Msr::kIa32MtrrFix16k80000);
			msr <= static_cast<ULONG>(Msr::kIa32MtrrFix16kA0000); msr++) {
			fixed_range.all = UtilReadMsr64(static_cast<Msr>(msr));
			for (auto memory_type : fixed_range.fields.types) {
				// Each entry manages 16k (0x4000) length.
				ULONG64 base = k16kBase + offset;
				offset += k16kManagedSize;

				// Saves the MTRR
				mtrr_entries[index].enabled = true;
				mtrr_entries[index].fixedMtrr = true;
				mtrr_entries[index].type = memory_type;
				mtrr_entries[index].range_base = base;
				mtrr_entries[index].range_end = base + k16kManagedSize - 1;
				index++;
			}
		}
		NT_ASSERT(k16kBase + offset == k4kBase);

		// kIa32MtrrFix4kC0000 manages 8 ranges of memory. The first range starts
		// at 0xC0000, and each range manages a 4k (0x1000) range. For example,
		//  entry[0]: 0xC0000 : 0xC1000 - 1
		//  entry[1]: 0xC1000 : 0xC2000 - 1
		//  ...
		//  entry[7]: 0xC7000 : 0xC8000 - 1
		// Also, subsequent memory ranges are managed by other MSRs such as
		// kIa32MtrrFix4kC8000, kIa32MtrrFix4kD0000, and kIa32MtrrFix4kF8000. Each
		// MSR manages 8 ranges of memory in the same fashion up to 0x100000.
		offset = 0;
		for (auto msr = static_cast<ULONG>(Msr::kIa32MtrrFix4kC0000);
			msr <= static_cast<ULONG>(Msr::kIa32MtrrFix4kF8000); msr++) {
			fixed_range.all = UtilReadMsr64(static_cast<Msr>(msr));
			for (auto memory_type : fixed_range.fields.types) {
				// Each entry manages 4k (0x1000) length.
				ULONG64 base = k4kBase + offset;
				offset += k4kManagedSize;

				// Saves the MTRR
				mtrr_entries[index].enabled = true;
				mtrr_entries[index].fixedMtrr = true;
				mtrr_entries[index].type = memory_type;
				mtrr_entries[index].range_base = base;
				mtrr_entries[index].range_end = base + k4kManagedSize - 1;
				index++;
			}
		}
		NT_ASSERT(k4kBase + offset == 0x100000);
	}

	// Read all variable range MTRRs
	for (auto i = 0; i < mtrr_capabilities.fields.variable_range_count; i++) {
		// Read MTRR mask and check if it is in use
		const auto phy_mask = static_cast<ULONG>(Msr::kIa32MtrrPhysMaskN) + i * 2;
		Ia32MtrrPhysMaskMsr mtrr_mask = { UtilReadMsr64(static_cast<Msr>(phy_mask)) };
		if (!mtrr_mask.fields.valid) {
			continue;
		}

		// Get a length this MTRR manages
		ULONG length;
		BitScanForward64(&length, mtrr_mask.fields.phys_mask * PAGE_SIZE);

		// Read MTRR base and calculate a range this MTRR manages
		const auto phy_base = static_cast<ULONG>(Msr::kIa32MtrrPhysBaseN) + i * 2;
		Ia32MtrrPhysBaseMsr mtrr_base = { UtilReadMsr64(static_cast<Msr>(phy_base)) };
		ULONG64 base = mtrr_base.fields.phys_base * PAGE_SIZE;
		ULONG64 end = base + (1ull << length) - 1;

		// Save it
		mtrr_entries[index].enabled = true;
		mtrr_entries[index].fixedMtrr = false;
		mtrr_entries[index].type = mtrr_base.fields.type;
		mtrr_entries[index].range_base = base;
		mtrr_entries[index].range_end = end;
		index++;
	}
}

// Returns a memory type based on MTRRs
_Use_decl_annotations_ static memory_type EptpGetMemoryType(
	ULONG64 physical_address) {
	// Indicate that MTRR is not defined (as a default)
	UCHAR result_type = MAXUCHAR;

	// Looks for MTRR that includes the specified physical_address
	for (const auto mtrr_entry : g_eptp_mtrr_entries) {
		if (!mtrr_entry.enabled) {
			// Reached out the end of stored MTRRs
			break;
		}

		if (!UtilIsInBounds(physical_address, mtrr_entry.range_base,
			mtrr_entry.range_end)) {
			// This MTRR does not describe a memory type of the physical_address
			continue;
		}

		// See: MTRR Precedences
		if (mtrr_entry.fixedMtrr) {
			// If a fixed MTRR describes a memory type, it is priority
			result_type = mtrr_entry.type;
			break;
		}

		if (mtrr_entry.type == static_cast<UCHAR>(memory_type::kUncacheable)) {
			// If a memory type is UC, it is priority. Do not continue to search as
			// UC has the highest priority
			result_type = mtrr_entry.type;
			break;
		}

		if (result_type == static_cast<UCHAR>(memory_type::kWriteThrough) ||
			mtrr_entry.type == static_cast<UCHAR>(memory_type::kWriteThrough)) {
			if (result_type == static_cast<UCHAR>(memory_type::kWriteBack)) {
				// If two or more MTRRs describes an over-wrapped memory region, and
				// one is WT and the other one is WB, use WT. However, look for other
				// MTRRs, as the other MTRR specifies the memory address as UC, which is
				// priority.
				result_type = static_cast<UCHAR>(memory_type::kWriteThrough);
				continue;
			}
		}

		// Otherwise, processor behavior is undefined. We just use the last MTRR
		// describes the memory address.
		result_type = mtrr_entry.type;
	}

	// Use the default MTRR if no MTRR entry is found
	if (result_type == MAXUCHAR) {
		result_type = g_eptp_mtrr_default_type;
	}

	return static_cast<memory_type>(result_type);
}

// Checks if the system supports EPT technology sufficient enough
_Use_decl_annotations_ bool EptIsEptAvailable() {
  PAGED_CODE();

  // Check the followings:
  // - page walk length is 4 steps
  // - extended page tables can be laid out in write-back memory
  // - INVEPT instruction with all possible types is supported
  // - INVVPID instruction with all possible types is supported
  Ia32VmxEptVpidCapMsr capability = {UtilReadMsr64(Msr::kIa32VmxEptVpidCap)};
  if (!capability.fields.support_page_walk_length4 ||
      !capability.fields.support_write_back_memory_type ||
      !capability.fields.support_invept ||
      !capability.fields.support_single_context_invept ||
      !capability.fields.support_all_context_invept ||
      !capability.fields.support_invvpid ||
      !capability.fields.support_individual_address_invvpid ||
      !capability.fields.support_single_context_invvpid ||
      !capability.fields.support_all_context_invvpid ||
      !capability.fields.support_single_context_retaining_globals_invvpid) {
    return false;
  }
  return true;
}

// Returns an EPT pointer from ept_data
_Use_decl_annotations_ ULONG64 EptGetEptPointer(EptData *ept_data) {
  return ept_data->ept_pointer->all;
}

// Builds EPT, allocates pre-allocated enties, initializes and returns EptData
_Use_decl_annotations_ EptData *EptInitialization() {
  PAGED_CODE();

  static const auto kEptPageWalkLevel = 4ul;

  // Allocate ept_data
  const auto ept_data = reinterpret_cast<EptData *>(ExAllocatePoolWithTag(
      NonPagedPool, sizeof(EptData), kHyperPlatformCommonPoolTag));
  if (!ept_data) {
    return nullptr;
  }
  RtlZeroMemory(ept_data, sizeof(EptData));

  // Allocate EptPointer
  const auto ept_poiner = reinterpret_cast<EptPointer *>(ExAllocatePoolWithTag(
      NonPagedPool, PAGE_SIZE, kHyperPlatformCommonPoolTag));
  if (!ept_poiner) {
    ExFreePoolWithTag(ept_data, kHyperPlatformCommonPoolTag);
    return nullptr;
  }
  RtlZeroMemory(ept_poiner, PAGE_SIZE);

  // Allocate EPT_PML4 and initialize EptPointer
  const auto ept_pml4 =
      reinterpret_cast<EptCommonEntry *>(ExAllocatePoolWithTag(
          NonPagedPool, PAGE_SIZE, kHyperPlatformCommonPoolTag));
  if (!ept_pml4) {
    ExFreePoolWithTag(ept_poiner, kHyperPlatformCommonPoolTag);
    ExFreePoolWithTag(ept_data, kHyperPlatformCommonPoolTag);
    return nullptr;
  }
  RtlZeroMemory(ept_pml4, PAGE_SIZE);
  ept_poiner->fields.memory_type = static_cast<ULONG64>(EptpGetMemoryType(UtilPaFromVa(ept_pml4))); 
  ept_poiner->fields.page_walk_length = kEptPageWalkLevel - 1;
  ept_poiner->fields.pml4_address = UtilPfnFromPa(UtilPaFromVa(ept_pml4));

  // Initialize all EPT entries for all physical memory pages
  const auto pm_ranges = UtilGetPhysicalMemoryRanges();
  for (auto run_index = 0ul; run_index < pm_ranges->number_of_runs;
       ++run_index) {
    const auto run = &pm_ranges->run[run_index];
    const auto base_addr = run->base_page * PAGE_SIZE;
    for (auto page_index = 0ull; page_index < run->page_count; ++page_index) {
      const auto indexed_addr = base_addr + page_index * PAGE_SIZE;
      const auto ept_pt_entry =
          EptpConstructTables(ept_pml4, 4, indexed_addr, nullptr);
      if (!ept_pt_entry) {
        EptpDestructTables(ept_pml4, 4);
        ExFreePoolWithTag(ept_poiner, kHyperPlatformCommonPoolTag);
        ExFreePoolWithTag(ept_data, kHyperPlatformCommonPoolTag);
        return nullptr;
      }
    }
  }

  // Initialize an EPT entry for APIC_BASE. It is required to allocated it now
  // for some reasons, or else, system hangs.
  const Ia32ApicBaseMsr apic_msr = {UtilReadMsr64(Msr::kIa32ApicBase)};
  if (!EptpConstructTables(ept_pml4, 4, apic_msr.fields.apic_base * PAGE_SIZE,
                           nullptr)) {
    EptpDestructTables(ept_pml4, 4);
    ExFreePoolWithTag(ept_poiner, kHyperPlatformCommonPoolTag);
    ExFreePoolWithTag(ept_data, kHyperPlatformCommonPoolTag);
    return nullptr;
  }

  // Allocate preallocated_entries
  const auto preallocated_entries_size =
      sizeof(EptCommonEntry *) * kEptpNumberOfPreallocatedEntries;
  const auto preallocated_entries = reinterpret_cast<EptCommonEntry **>(
      ExAllocatePoolWithTag(NonPagedPool, preallocated_entries_size,
                            kHyperPlatformCommonPoolTag));
  if (!preallocated_entries) {
    EptpDestructTables(ept_pml4, 4);
    ExFreePoolWithTag(ept_poiner, kHyperPlatformCommonPoolTag);
    ExFreePoolWithTag(ept_data, kHyperPlatformCommonPoolTag);
    return nullptr;
  }
  RtlZeroMemory(preallocated_entries, preallocated_entries_size);

  // And fill preallocated_entries with newly created entries
  for (auto i = 0ul; i < kEptpNumberOfPreallocatedEntries; ++i) {
    const auto ept_entry = EptpAllocateEptEntry(nullptr);
    if (!ept_entry) {
      EptpFreeUnusedPreAllocatedEntries(preallocated_entries, 0);
      EptpDestructTables(ept_pml4, 4);
      ExFreePoolWithTag(ept_poiner, kHyperPlatformCommonPoolTag);
      ExFreePoolWithTag(ept_data, kHyperPlatformCommonPoolTag);
      return nullptr;
    }
    preallocated_entries[i] = ept_entry;
  }

  // Initialization completed
  ept_data->ept_pointer = ept_poiner;
  ept_data->ept_pml4 = ept_pml4;
  ept_data->preallocated_entries = preallocated_entries;
  ept_data->preallocated_entries_count = 0;
  return ept_data;
}


// Allocate and initialize all EPT entries associated with the physical_address
_Use_decl_annotations_ static EptCommonEntry *EptpConstructTables(
	EptCommonEntry *table, ULONG table_level, ULONG64 physical_address, EptData* ept_data)
{
	return EptpConstructTablesEx(table, table_level, physical_address, nullptr  ,nullptr);
}
// Allocate and initialize all EPT entries associated with the physical_address
_Use_decl_annotations_  EptCommonEntry *EptpConstructTablesEx(
    EptCommonEntry *table, ULONG table_level, ULONG64 physical_address,
    EptData *ept_data, EptCommonEntry* reserved) {
  switch (table_level) {
    case 4: {
      // table == PML4 (512 GB)
      const auto pxe_index = EptpAddressToPxeIndex(physical_address);
      const auto ept_pml4_entry = &table[pxe_index];
      if (!ept_pml4_entry->all) { 
		if (!reserved)
		{ 
			const auto ept_pdpt = EptpAllocateEptEntry(ept_data);
			if (!ept_pdpt) {
			  return nullptr;
			}
			EptpInitTableEntry(ept_pml4_entry, table_level, UtilPaFromVa(ept_pdpt));
		}
		else
		{
			const auto ept01_pml4_entry = &reserved[pxe_index];
			ept_pml4_entry->all = ept01_pml4_entry->all;
			reserved = reinterpret_cast<EptCommonEntry *>(UtilVaFromPfn(ept01_pml4_entry->fields.physial_address));
		}
      }
	  
      return EptpConstructTablesEx(
          reinterpret_cast<EptCommonEntry *>(
              UtilVaFromPfn(ept_pml4_entry->fields.physial_address)),
          table_level - 1, physical_address, ept_data, reserved);
    }
    case 3: {
      // table == PDPT (1 GB)
      const auto ppe_index = EptpAddressToPpeIndex(physical_address);
      const auto ept_pdpt_entry = &table[ppe_index];
	  if (!ept_pdpt_entry->all) { 
		  if (!reserved)
		  { 
			  const auto ept_pdt = EptpAllocateEptEntry(ept_data);
			  if (!ept_pdt) {
				  return nullptr;
			  }
			  EptpInitTableEntry(ept_pdpt_entry, table_level, UtilPaFromVa(ept_pdt));
		  }
		  else
		  {
			  const auto ept01_pdpt_entry = &reserved[ppe_index];
			  ept_pdpt_entry->all = ept01_pdpt_entry->all;
			  reserved = reinterpret_cast<EptCommonEntry *>(UtilVaFromPfn(ept01_pdpt_entry->fields.physial_address));
		  } 
	  } 
      return EptpConstructTablesEx(
          reinterpret_cast<EptCommonEntry *>(
              UtilVaFromPfn(ept_pdpt_entry->fields.physial_address)),
          table_level - 1, physical_address, ept_data, reserved);
    }
    case 2: {
      // table == PDT (2 MB)
      const auto pde_index = EptpAddressToPdeIndex(physical_address);
      const auto ept_pdt_entry = &table[pde_index];		
	  if (!ept_pdt_entry->all)
	  {
		 if (!reserved)
		 { 
			  const auto ept_pt = EptpAllocateEptEntry(ept_data);
			  if (!ept_pt) {
				  return nullptr;
			  }
			  EptpInitTableEntry(ept_pdt_entry, table_level, UtilPaFromVa(ept_pt));
		  }
		  else
		  {
			  const auto ept01_pdt_entry = &reserved[pde_index];
			  ept_pdt_entry->all = ept01_pdt_entry->all;
			  reserved = reinterpret_cast<EptCommonEntry *>(UtilVaFromPfn(ept01_pdt_entry->fields.physial_address));
		  }
	  }
      return EptpConstructTablesEx(
          reinterpret_cast<EptCommonEntry *>(
              UtilVaFromPfn(ept_pdt_entry->fields.physial_address)),
          table_level - 1, physical_address, ept_data, reserved);
    }
    case 1: {
      // table == PT (4 KB)
      const auto pte_index = EptpAddressToPteIndex(physical_address);
      const auto ept_pt_entry = &table[pte_index];
     // NT_ASSERT(!ept_pt_entry->all); 
	  if (!ept_pt_entry->all)
	  {
		  if (!reserved)
		  {
			  EptpInitTableEntry(ept_pt_entry, table_level, physical_address);
		  }
		  else
		  {
			  const auto ept01_pt_entry = &reserved[pte_index];
			  ept_pt_entry->all = ept01_pt_entry->all;
		  }
	  }		
	  return ept_pt_entry;
    }
    default:
      HYPERPLATFORM_COMMON_DBG_BREAK();
      return nullptr;
  }
}

// Return a new EPT entry either by creating new one or from pre-allocated ones
_Use_decl_annotations_ static EptCommonEntry *EptpAllocateEptEntry(
	EptData *ept_data) {	
	if (ept_data) {
	  return EptpAllocateEptEntryFromPreAllocated(ept_data);
	} else {
	 
	return EptpAllocateEptEntryFromPool();
	}
}

// Return a new EPT entry from pre-allocated ones.
_Use_decl_annotations_ static EptCommonEntry *
EptpAllocateEptEntryFromPreAllocated(EptData *ept_data) {
  const auto count =
      InterlockedIncrement(&ept_data->preallocated_entries_count);
  if (count > kEptpNumberOfPreallocatedEntries) {
    HYPERPLATFORM_COMMON_BUG_CHECK(
        HyperPlatformBugCheck::kExhaustedPreallocatedEntries, count,
        reinterpret_cast<ULONG_PTR>(ept_data), 0);
  }
  return ept_data->preallocated_entries[count - 1];
}

// Return a new EPT entry either by creating new one
_Use_decl_annotations_ static EptCommonEntry *EptpAllocateEptEntryFromPool() {
  static const auto kAllocSize = 512 * sizeof(EptCommonEntry);
  static_assert(kAllocSize == PAGE_SIZE, "Size check");

  const auto entry = reinterpret_cast<EptCommonEntry *>(ExAllocatePoolWithTag(
      NonPagedPool, kAllocSize, kHyperPlatformCommonPoolTag));
  if (!entry) {
    return nullptr;
  }
  RtlZeroMemory(entry, kAllocSize);
  return entry;
}

// Initialize an EPT entry with a "pass through" attribute
_Use_decl_annotations_ static void EptpInitTableEntry(
    EptCommonEntry *entry, ULONG table_level, ULONG64 physical_address) {
  entry->fields.read_access = true;
  entry->fields.write_access = true;
  entry->fields.execute_access = true;
  entry->fields.physial_address = UtilPfnFromPa(physical_address);
  if (table_level == 1) {
    entry->fields.memory_type = static_cast<ULONG64>(memory_type::kWriteBack);
  }
}

// Return an address of PXE
_Use_decl_annotations_ static ULONG64 EptpAddressToPxeIndex(
    ULONG64 physical_address) {
  const auto index = (physical_address >> kEptpPxiShift) & kEptpPtxMask;
  return index;
}

// Return an address of PPE
_Use_decl_annotations_ static ULONG64 EptpAddressToPpeIndex(
    ULONG64 physical_address) {
  const auto index = (physical_address >> kEptpPpiShift) & kEptpPtxMask;
  return index;
}

// Return an address of PDE
_Use_decl_annotations_ static ULONG64 EptpAddressToPdeIndex(
    ULONG64 physical_address) {
  const auto index = (physical_address >> kEptpPdiShift) & kEptpPtxMask;
  return index;
}

// Set MTF on the current processor
_Use_decl_annotations_  void ShpSetMonitorTrapFlag(bool enable) {
	VmxProcessorBasedControls vm_procctl = {
		static_cast<unsigned int>(UtilVmRead(VmcsField::kCpuBasedVmExecControl)) };
	vm_procctl.fields.monitor_trap_flag = enable;
	UtilVmWrite(VmcsField::kCpuBasedVmExecControl, vm_procctl.all);
}


// Return an address of PTE
_Use_decl_annotations_ static ULONG64 EptpAddressToPteIndex(
    ULONG64 physical_address) {
  const auto index = (physical_address >> kEptpPtiShift) & kEptpPtxMask;
  return index;
}


// Deal with L2 EPT violation VM-exit.
_Use_decl_annotations_ void EptHandleEptViolationEx(EptData *ept_data, ULONG64 PhysAddr, bool is_range_of_ept12) {

	const EptViolationQualification exit_qualification = {
		UtilVmRead(VmcsField::kExitQualification) };
	ULONG_PTR fault_pa = 0;

	if (PhysAddr) {
		fault_pa = PhysAddr;
	}
	else {
		fault_pa = UtilVmRead64(VmcsField::kGuestPhysicalAddress);
	}
	 
	if (!exit_qualification.fields.ept_readable && 
		!exit_qualification.fields.ept_writeable && 
		!exit_qualification.fields.ept_executable) 
	{
		const auto ept_entry = EptGetEptPtEntry(ept_data, fault_pa);
		if (!ept_entry || !ept_entry->all) 
		{ 
			EptpConstructTables(ept_data->ept_pml4, 4, fault_pa, ept_data); 
			UtilInveptGlobal();
			return;
		}
		else {
			ept_entry->fields.read_access = true;
			ept_entry->fields.execute_access = true;
			ept_entry->fields.write_access = true;		
			UtilInveptGlobal();
 			return;
		}
	}
	else if (exit_qualification.fields.caused_by_translation)
	{
		if ((!exit_qualification.fields.ept_writeable  && exit_qualification.fields.write_access) ||
			(!exit_qualification.fields.ept_readable   && exit_qualification.fields.read_access) ||
			(!exit_qualification.fields.ept_executable && exit_qualification.fields.execute_access) )
		{
			const auto Ept01Pte = EptGetEptPtEntry(ept_data, fault_pa);
			if (!Ept01Pte) 
			{
				HYPERPLATFORM_COMMON_BUG_CHECK(HyperPlatformBugCheck::kUnexpectedVmEptExit3,
					UtilVmRead(VmcsField::kGuestRip), exit_qualification.all, fault_pa);
			}

			Ept01Pte->fields.read_access = true;
			Ept01Pte->fields.execute_access = true;
			Ept01Pte->fields.write_access = true;
			return;
		}
		else
		{
			HYPERPLATFORM_COMMON_BUG_CHECK(HyperPlatformBugCheck::kUnexpectedVmEptExit2,
				UtilVmRead(VmcsField::kGuestRip), exit_qualification.all, fault_pa);
		}
	}
	else {
		HYPERPLATFORM_COMMON_BUG_CHECK(HyperPlatformBugCheck::kUnexpectedVmEptExit, 
			UtilVmRead(VmcsField::kGuestRip), exit_qualification.all, fault_pa);
	}
}
// Deal with EPT violation VM-exit.
_Use_decl_annotations_ void EptHandleEptViolation(EptData* ept_data, ULONG64 PhysAddr, bool is_range_of_ept12) {
	EptHandleEptViolationEx(ept_data, PhysAddr, is_range_of_ept12);
}

// Returns if the physical_address is device memory (which could not have a
// corresponding PFN entry)
_Use_decl_annotations_ static bool EptpIsDeviceMemory(
    ULONG64 physical_address) {
  const auto pm_ranges = UtilGetPhysicalMemoryRanges();
  for (auto i = 0ul; i < pm_ranges->number_of_runs; ++i) {
    const auto current_run = &pm_ranges->run[i];
    const auto base_addr =
        static_cast<ULONG64>(current_run->base_page) * PAGE_SIZE;
    const auto endAddr = base_addr + current_run->page_count * PAGE_SIZE - 1;
    if (UtilIsInBounds(physical_address, base_addr, endAddr)) {
      return false;
    }
  }
  return true;
}

// Returns an EPT entry corresponds to the physical_address
_Use_decl_annotations_ EptCommonEntry *EptGetEptPtEntry(
    EptData *ept_data, ULONG64 physical_address) {
  return EptpGetEptPtEntry(ept_data->ept_pml4, 4, physical_address);
}

// Returns an EPT entry corresponds to the physical_address
_Use_decl_annotations_ static EptCommonEntry *EptpGetEptPtEntry(
    EptCommonEntry *table, ULONG table_level, ULONG64 physical_address) {
  if (!table) {
    return nullptr;
  }
  switch (table_level) {
    case 4: {
      // table == PML4
      const auto pxe_index = EptpAddressToPxeIndex(physical_address);
      const auto ept_pml4_entry = &table[pxe_index];
      if (!ept_pml4_entry->all) {
        return nullptr;
      }
	 
	  return EptpGetEptPtEntry(reinterpret_cast<EptCommonEntry *>(UtilVaFromPfn(
                                   ept_pml4_entry->fields.physial_address)),
                               table_level - 1, physical_address);
    }
    case 3: {
      // table == PDPT
      const auto ppe_index = EptpAddressToPpeIndex(physical_address);
      const auto ept_pdpt_entry = &table[ppe_index];
      if (!ept_pdpt_entry->all) {
        return nullptr;
      }
      return EptpGetEptPtEntry(reinterpret_cast<EptCommonEntry *>(UtilVaFromPfn(
                                   ept_pdpt_entry->fields.physial_address)),
                               table_level - 1, physical_address);
    }
    case 2: {
      // table == PDT
      const auto pde_index = EptpAddressToPdeIndex(physical_address);
      const auto ept_pdt_entry = &table[pde_index];
      if (!ept_pdt_entry->all) {
        return nullptr;
      }
      return EptpGetEptPtEntry(reinterpret_cast<EptCommonEntry *>(UtilVaFromPfn(
                                   ept_pdt_entry->fields.physial_address)),
                               table_level - 1, physical_address);
    }
    case 1: {
      // table == PT
      const auto pte_index = EptpAddressToPteIndex(physical_address);
      const auto ept_pt_entry = &table[pte_index];
      return ept_pt_entry;
    }
    default:
      HYPERPLATFORM_COMMON_DBG_BREAK();
      return nullptr;
  }
}

// Frees all EPT stuff
_Use_decl_annotations_ void EptTermination(EptData *ept_data) {
  HYPERPLATFORM_LOG_DEBUG("Used pre-allocated entries  = %2d / %2d",
                          ept_data->preallocated_entries_count,
                          kEptpNumberOfPreallocatedEntries);

  EptpFreeUnusedPreAllocatedEntries(ept_data->preallocated_entries,
                                    ept_data->preallocated_entries_count);
  EptpDestructTables(ept_data->ept_pml4, 4);
  ExFreePoolWithTag(ept_data->ept_pointer, kHyperPlatformCommonPoolTag);
  ExFreePoolWithTag(ept_data, kHyperPlatformCommonPoolTag);
}

// Frees all unused pre-allocated EPT entries. Other used entries should be
// freed with EptpDestructTables().
_Use_decl_annotations_ static void EptpFreeUnusedPreAllocatedEntries(
    EptCommonEntry **preallocated_entries, long used_count) {
  for (auto i = used_count; i < kEptpNumberOfPreallocatedEntries; ++i) {
    if (!preallocated_entries[i]) {
      break;
    }
#pragma warning(push)
#pragma warning(disable : 6001)
    ExFreePoolWithTag(preallocated_entries[i], kHyperPlatformCommonPoolTag);
#pragma warning(pop)
  }
  ExFreePoolWithTag(preallocated_entries, kHyperPlatformCommonPoolTag);
}

_Use_decl_annotations_ EptCommonEntry*  EptpGetNextLevelTableBase(EptCommonEntry *table)
{
	const auto entry = table;
	if (entry && entry->fields.physial_address)
	{
		const auto sub_table = reinterpret_cast<EptCommonEntry *>(UtilVaFromPfn(entry->fields.physial_address));
		return sub_table;
	}
	return nullptr;
} 


_Use_decl_annotations_ ULONG64  EptpGetNextLevelTablePhysicalBase(EptCommonEntry *table)
{
	const auto entry = table;
	if (entry && entry->fields.physial_address)
	{
		const auto sub_table = UtilPaFromPfn(entry->fields.physial_address);
		return sub_table;
	}
	return 0;
}
_Use_decl_annotations_ void EptpRefreshEpt02(EptData* EptData02, EptData* EptData12, EptData* EptData01, void* LookupEntryPa)
{
	if (!EptData01 || !EptData02 || !EptData12) {
		return;
	}
	EptCommonEntry* pml4_table = EptData02->ept_pml4;
	EptCommonEntry* pml4_table2 = EptData12->ept_pml4;
	EptCommonEntry* pdptr_table = NULL;
	EptCommonEntry* pdptr_table2 = NULL;
	EptCommonEntry* pdt_table = NULL;
	EptCommonEntry* pdt_table2 = NULL;
	EptCommonEntry* pt_table = NULL;
	EptCommonEntry* pt_table2 = NULL;
	for (int i = 0; i < 512 && pml4_table && pml4_table2; i++, pml4_table++, pml4_table2++)			//PML4
	{
		pml4_table->all = pml4_table2->all; 
		ULONG_PTR pdptr_entry_pa02 = EptpGetNextLevelTablePhysicalBase(pml4_table);
		ULONG_PTR pdptr_entry_pa12 = EptpGetNextLevelTablePhysicalBase(pml4_table2);
		if (!pdptr_entry_pa02 || !pdptr_entry_pa12) {
			continue; 
		}
		pdptr_table = (EptCommonEntry*)UtilVaFromPa(pdptr_entry_pa02);
		pdptr_table2 = (EptCommonEntry*)UtilVaFromPa(pdptr_entry_pa12);

		for (int j = 0; j < 512 && pdptr_table && pdptr_table2; j++, pdptr_table++, pdptr_table2++)	//PDPTR
		{
			pdptr_table->all = pdptr_table2->all;
			ULONG_PTR pdt_entry_pa02 = EptpGetNextLevelTablePhysicalBase(pdptr_table);
			ULONG_PTR pdt_entry_pa12 = EptpGetNextLevelTablePhysicalBase(pdptr_table2);
			if (!pdt_entry_pa02 || !pdt_entry_pa12) {
				continue;
			}
			pdt_table = (EptCommonEntry*)UtilVaFromPa(pdt_entry_pa02);
			pdt_table2 = (EptCommonEntry*)UtilVaFromPa(pdt_entry_pa12);
			for (int k = 0; k < 512 && pdt_table && pdt_table2; k++, pdt_table++, pdt_table2++)		// PDT
			{
				pdt_table->all = pdt_table2->all;
				ULONG_PTR pt_table_pa02 = EptpGetNextLevelTablePhysicalBase(pdt_table);
				ULONG_PTR pt_table_pa12 = EptpGetNextLevelTablePhysicalBase(pdt_table2);
				if (!pt_table_pa02 || !pt_table_pa12) {
					continue;
				}
				pt_table = (EptCommonEntry*)UtilVaFromPa(pt_table_pa02);
				pt_table2 = (EptCommonEntry*)UtilVaFromPa(pt_table_pa12);
				for (int p = 0; p < 512 && pt_table && pt_table2; p++, pt_table++, pt_table2++)		// PT
				{
					pt_table->all = pt_table2->all;
					if (LookupEntryPa == (void*)UtilPaFromVa(pt_table2) && LookupEntryPa != nullptr)
					{
						return;
					}
				}
			}
		}
	}
}

_Use_decl_annotations_ bool EptpIsInRangesOfEpt(ULONG_PTR PhysicalAddres, EptCommonEntry *pml4_table)
{
	
	EptCommonEntry* pdptr_table = NULL;
	EptCommonEntry* pdt_table = NULL;
	EptCommonEntry* pt_table = NULL;
	bool IsMatch = false;
	
	for (int i = 0; i < 512 && pml4_table; i++, pml4_table++)			//PML4
	{
		if ((void*)PhysicalAddres == (void*)UtilPaFromVa(pml4_table))
		{
			IsMatch = true;
			return IsMatch;
		}

		ULONG_PTR pdptr_entry_pa = EptpGetNextLevelTablePhysicalBase(pml4_table);
		pdptr_table = (EptCommonEntry*)UtilVaFromPa(pdptr_entry_pa);
		for (int j = 0; j < 512 && pdptr_table; j++, pdptr_table++)		//PDPTR
		{
			if ((void*)PhysicalAddres == (void*)(pdptr_entry_pa + j * sizeof(EptCommonEntry)))
			{
				IsMatch = true;
				return IsMatch;
			}

			ULONG_PTR pdt_entry_pa = EptpGetNextLevelTablePhysicalBase(pdptr_table); 
			pdt_table = (EptCommonEntry*)UtilVaFromPa(pdt_entry_pa);
			for (int k = 0; k < 512 && pdt_table; k++, pdt_table++)		// PDT
			{
				if ((void*)PhysicalAddres == (void*)(pdt_entry_pa + k * sizeof(EptCommonEntry)))
				{
					IsMatch = true;
					return IsMatch;
				}
				ULONG_PTR pt_table_pa = EptpGetNextLevelTablePhysicalBase(pdt_table);
				//Last Level, we dun need get each of them.
				if (PAGE_ALIGN(PhysicalAddres) == (void*)pt_table_pa)
				{
					IsMatch = true;
					return IsMatch;
				}
			}
		}
	}
	return IsMatch;
	
} 

_Use_decl_annotations_ void  EptpSetEntryAccess(
	EptData* ept_data, ULONG_PTR physical_address, bool readable, bool writable, bool executable)
{
	EptCommonEntry* entry  = EptGetEptPtEntry(ept_data, physical_address);
	if (!entry  || !entry ->fields.physial_address)
	{
		return;
	} 
	entry->fields.read_access    = readable;
	entry->fields.execute_access = executable;
	entry->fields.write_access	 = writable;
}

_Use_decl_annotations_ void  EptpValidateEptCallback(EptCommonEntry* EptEntry, void* Context)
{
	EptData* ept_data01 = (EptData*)Context;
	EptpSetEntryAccess(ept_data01, (ULONG64)UtilPaFromVa(EptEntry), true, true, true);
}

_Use_decl_annotations_ void  EptpValidateEpt(EptData* EptData12, EptData* EptData01)
{	 
	EptpWalker(EptData12->ept_pml4, 4, EptpValidateEptCallback, EptData01);
}

_Use_decl_annotations_ void  EptpInvalidateEptCallback(EptCommonEntry* EptEntry, void* Context)
{
	EptData* ept_data01 = (EptData*)Context;
	EptpSetEntryAccess(ept_data01, (ULONG64)UtilPaFromVa(EptEntry), true, false , true);
}

_Use_decl_annotations_ void  EptpInvalidateEpt(EptData* EptData12, EptData* EptData01)
{
	EptpWalker(EptData12->ept_pml4, 4, EptpInvalidateEptCallback, EptData01);
}

// Frees all used EPT entries by walking through whole EPT
_Use_decl_annotations_ static void EptpDestructTables(EptCommonEntry *table,
                                                      ULONG table_level) {
  for (auto i = 0ul; i < 512; ++i) {
    const auto entry = table[i];
    if (entry.fields.physial_address) {
      const auto sub_table = reinterpret_cast<EptCommonEntry *>(
          UtilVaFromPfn(entry.fields.physial_address));

      switch (table_level) {
        case 4:  // table == PML4, sub_table == PDPT
        case 3:  // table == PDPT, sub_table == PDT
          EptpDestructTables(sub_table, table_level - 1);
          break;
        case 2:  // table == PDT, sub_table == PT
          ExFreePoolWithTag(sub_table, kHyperPlatformCommonPoolTag);
          break;
        default:
          HYPERPLATFORM_COMMON_DBG_BREAK();
          break;
      }
    }
  }
  ExFreePoolWithTag(table, kHyperPlatformCommonPoolTag);
}



NTSTATUS  EptpBuildNestedEpt( 
	ULONG_PTR vmcs12_va,
	EptData* ept_data12,
	EptData* ept_data02)
{
	do { 
		EptCommonEntry* Pml4Entry = NULL;
		EptPointer*		 Ept02Ptr = NULL;
		EptPointer*		 Ept12Ptr = NULL;
		ULONG64			_Ept12Ptr = vmcs12_va;
		if (!vmcs12_va || !ept_data12 || !ept_data02)
		{
			break;
		}

		Ept12Ptr = (EptPointer*)ExAllocatePoolWithTag(NonPagedPoolMustSucceed, PAGE_SIZE, 'eptp');
		if (!Ept12Ptr)
		{
			break;
		} 
		RtlZeroMemory(Ept12Ptr, PAGE_SIZE); 
		  
		Ept02Ptr = (EptPointer*)ExAllocatePoolWithTag(NonPagedPoolMustSucceed, PAGE_SIZE, 'eptp');
		if (!Ept02Ptr)
		{
			ExFreePool(Ept12Ptr);
			break;
		}
		RtlZeroMemory(Ept02Ptr, PAGE_SIZE);

		Pml4Entry = (EptCommonEntry*)ExAllocatePoolWithTag(NonPagedPoolMustSucceed, PAGE_SIZE, 'pml4');
		if (!Pml4Entry)
		{
			ExFreePool(Ept12Ptr);
			ExFreePool(Ept02Ptr);
			break;
		}  
		RtlZeroMemory(Pml4Entry, PAGE_SIZE);
		  
		Ept12Ptr->all = _Ept12Ptr;

		Pml4Entry->fields.read_access = false;
		Pml4Entry->fields.execute_access = false;
		Pml4Entry->fields.memory_type = 0;
		Pml4Entry->fields.write_access = false;

		Ept02Ptr->fields.memory_type = static_cast<ULONG>(memory_type::kWriteBack);
		Ept02Ptr->fields.pml4_address = UtilPfnFromPa(UtilPaFromVa(Pml4Entry));
		Ept02Ptr->fields.page_walk_length = 4 - 1;
		Ept02Ptr->fields.enable_accessed_and_dirty_flags = false;
		 
	 	const auto pm_ranges = UtilGetPhysicalMemoryRanges();
		for (auto run_index = 0ul; run_index < pm_ranges->number_of_runs;
			++run_index) {
			const auto run = &pm_ranges->run[run_index];
			const auto base_addr = run->base_page * PAGE_SIZE;
			for (auto page_index = 0ull; page_index < run->page_count; ++page_index) {
				const auto indexed_addr = base_addr + page_index * PAGE_SIZE;
				EptpConstructTables(Pml4Entry, 4, indexed_addr, nullptr); 
				EptpConstructTablesEx(Pml4Entry, 4, indexed_addr, nullptr, ept_data12->ept_pml4);
			}
		} 

		ept_data02->ept_pointer = Ept02Ptr;
		ept_data02->ept_pml4 = Pml4Entry;
	 
		ept_data12->ept_pointer = Ept12Ptr;
		ept_data12->ept_pml4 = (EptCommonEntry*)UtilVaFromPfn(Ept12Ptr->fields.pml4_address);	  	 
	} while (FALSE);
	return STATUS_SUCCESS;
}

EptData* EptBuildEptDataByEptp()
{	
	EptData*	EptDataPtr = (EptData*)ExAllocatePoolWithTag(NonPagedPoolMustSucceed, PAGE_SIZE, 'eptd');
	NT_ASSERT(EptDataPtr);
	RtlZeroMemory(EptDataPtr, sizeof(EptData));
	return EptDataPtr;
} 
}  // extern "C"
