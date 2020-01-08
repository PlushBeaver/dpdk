#include <io.h>

#include <rte_common.h>
#include <rte_errno.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_os.h>

#include "eal_internal_cfg.h"
#include "eal_memalloc.h"
#include "eal_memcfg.h"
#include "eal_options.h"
#include "eal_private.h"
#include "eal_windows.h"

/* Cross headers may lack VirtualAlloc2() in some distributions.
 * Provide a copy of definitions and code to load it dynamically.
 * Note: definitions are copied verbatim and don't follow code style.
 */ 
#if (_WIN32_WINNT >= _WIN32_WINNT_WIN10) && \
	!defined(MEM_PRESERVE_PLACEHOLDER)

/* https://docs.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-mem_extended_parameter_type */
typedef enum MEM_EXTENDED_PARAMETER_TYPE {
	MemExtendedParameterInvalidType,
	MemExtendedParameterAddressRequirements,
	MemExtendedParameterNumaNode,
	MemExtendedParameterPartitionHandle,
	MemExtendedParameterMax,
	MemExtendedParameterUserPhysicalHandle,
	MemExtendedParameterAttributeFlags
} *PMEM_EXTENDED_PARAMETER_TYPE;

#define MEM_EXTENDED_PARAMETER_TYPE_BITS 4

/* https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-mem_extended_parameter */
typedef struct MEM_EXTENDED_PARAMETER {
	struct {
		DWORD64 Type : MEM_EXTENDED_PARAMETER_TYPE_BITS;
		DWORD64 Reserved : 64 - MEM_EXTENDED_PARAMETER_TYPE_BITS;
	} DUMMYSTRUCTNAME;
	union {
		DWORD64 ULong64;
		PVOID   Pointer;
		SIZE_T  Size;
		HANDLE  Handle;
		DWORD   ULong;
	} DUMMYUNIONNAME;
} MEM_EXTENDED_PARAMETER, *PMEM_EXTENDED_PARAMETER;

/* https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc2 */
typedef PVOID (*VirtualAlloc2_type)(
	HANDLE                 Process,
	PVOID                  BaseAddress,
	SIZE_T                 Size,
	ULONG                  AllocationType,
	ULONG                  PageProtection,
	MEM_EXTENDED_PARAMETER *ExtendedParameters,
	ULONG                  ParameterCount
);

/* VirtualAlloc2() flags. */
#define MEM_COALESCE_PLACEHOLDERS 0x00000001
#define MEM_PRESERVE_PLACEHOLDER  0x00000002
#define MEM_REPLACE_PLACEHOLDER   0x00004000
#define MEM_RESERVE_PLACEHOLDER   0x00040000

/* Named exactly as the function, so that user code does not depend
 * on it being found at compile time or dynamically.
 */
static VirtualAlloc2_type VirtualAlloc2;

static int
mem_access_advanced_features(void)
{
	const char library_name[] = "kernelbase.dll";
	const char function[] = "VirtualAlloc2";

	OSVERSIONINFO info;
	HMODULE library = NULL;
	int ret = 0;

	/* Already done. */
	if (VirtualAlloc2 != NULL)
		return 0;

	/* IsWindows10OrGreater() may also be unavailable. */
	memset(&info, 0, sizeof(info));
	info.dwOSVersionInfoSize = sizeof(info);
	GetVersionEx(&info);

	/* Checking for Windows 10+ will also detect Windows Server 2016+.
	 * Do not abort, because Windows may report false version depending
	 * on executable manifest, compatibility mode, etc.
	 */
	if (info.dwMajorVersion < 10)
		RTE_LOG(DEBUG, EAL, "Windows 10+ or Windows Server 2016+ "
			"is required for advanced memory features\n");

	library = LoadLibraryA(library_name);
	if (library == NULL) {
		RTE_LOG_SYSTEM_ERROR("LoadLibraryA(\"%s\")", library_name);
		return -1;
	}

	VirtualAlloc2 = (VirtualAlloc2_type)(
		(void*)GetProcAddress(library, function));
	if (VirtualAlloc2 == NULL) {
		RTE_LOG_SYSTEM_ERROR("GetProcAddress(\"%s\", \"%s\")\n",
			library_name, function);
		ret = -1;
	}

	FreeLibrary(library);

	return ret;
}

#else

/* Stub in case VirtualAlloc2() is provided by the compiler. */
static int
mem_access_advanced_features(void)
{
	return 0;
}

#endif /* no VirtualAlloc2() */

/* Approximate error mapping from VirtualAlloc2() to POSIX mmap(3). */
static int
win32_alloc_error_to_errno(DWORD code)
{
	switch (code) {
	case ERROR_SUCCESS:
		return 0;

	case ERROR_INVALID_ADDRESS:
		/* A valid requested address is not available. */
	case ERROR_COMMITMENT_LIMIT:
		/* May occcur when commiting regular memory. */
	case ERROR_NO_SYSTEM_RESOURCES:
		/* Occurs when the system runs out of hugepages. */
		return ENOMEM;

	case ERROR_INVALID_PARAMETER:
	default:
		return EINVAL;
	}
}

void*
eal_mem_alloc(size_t size, int socket_id)
{
	DWORD flags = MEM_RESERVE | MEM_COMMIT;
	void *addr;

	flags = MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES;
	addr = VirtualAllocExNuma(
		GetCurrentProcess(), NULL, size, flags, PAGE_READWRITE,
		eal_socket_numa_node(socket_id));
	if (addr == NULL)
		rte_errno = ENOMEM;
	return addr;
}

void*
eal_mem_commit(void *requested_addr, size_t size, int socket_id)
{
	MEM_EXTENDED_PARAMETER param;
	DWORD param_count = 0;
	DWORD flags;
	void *addr;

	if (mem_access_advanced_features() < 0) {
		RTE_LOG(ERR, EAL, "Cannot access advanced memory features\n");
		return NULL;
	}

	if (requested_addr != NULL) {
		MEMORY_BASIC_INFORMATION info;
		if (VirtualQuery(requested_addr, &info, sizeof(info)) == 0) {
			RTE_LOG_SYSTEM_ERROR("VirtualQuery()");
			return NULL;
		}

		/* Split reserved region if only a part is committed. */
		flags = MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER;
		if ((info.RegionSize > size) &&
			!VirtualFree(requested_addr, size, flags)) {
			RTE_LOG_SYSTEM_ERROR("VirtualFree(%p, %" RTE_PRIzu ", "
				"<split placeholder>)", requested_addr, size);
			return NULL;	
		}
	}

	if (socket_id != SOCKET_ID_ANY) {
		param_count = 1;
		memset(&param, 0, sizeof(param));
		param.Type = MemExtendedParameterNumaNode;
		param.ULong = eal_socket_numa_node(socket_id);
	}

	flags = MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES;
	if (requested_addr != NULL) {
		flags |= MEM_REPLACE_PLACEHOLDER;
	}
	addr = VirtualAlloc2(GetCurrentProcess(), requested_addr, size,
		flags, PAGE_READWRITE, &param, param_count);
	if (addr == NULL) {
		RTE_LOG_SYSTEM_ERROR("VirtualAlloc2(%p, %" RTE_PRIzu ", "
			"<replace placeholder>)", addr, size);
		rte_errno = win32_alloc_error_to_errno(GetLastError());
		return NULL;
	}

	return addr;
}

int
eal_mem_decommit(void *addr, size_t size)
{
	if (mem_access_advanced_features() < 0) {
		RTE_LOG(ERR, EAL, "Cannot access advanced memory features\n");
		return -1;
	}

	if (!VirtualFree(addr, size, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER)) {
		RTE_LOG_SYSTEM_ERROR("VirtualFree(%p, %" RTE_PRIzu ", ...)",
			addr, size);
		return -1;
	}

	return 0;
}

int
eal_mem_free(void *addr, size_t size, bool reserved)
{
	MEMORY_BASIC_INFORMATION info;
	if (VirtualQuery(addr, &info, sizeof(info)) == 0) {
		RTE_LOG_SYSTEM_ERROR("VirtualQuery()");
		return -1;
	}

	if (reserved && (info.State != MEM_RESERVE)) {
		return 1;
	}
	
	/* Free complete region. */
	if ((addr == info.AllocationBase) && (size == info.RegionSize)) {
		if (!VirtualFree(addr, 0, MEM_RELEASE)) {
			RTE_LOG_SYSTEM_ERROR("VirtualFree(%p, 0, MEM_RELEASE)", addr);
		}
		return 0;
	}

	if (mem_access_advanced_features() < 0) {
		RTE_LOG(ERR, EAL, "Cannot access advanced memory features\n");
		return -1;
	}

	/* Split the part to be freed and the remaining reservation. */
	if (!VirtualFree(addr, size, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER)) {
		RTE_LOG_SYSTEM_ERROR("VirtualFree(%p, %" RTE_PRIzu ", "
			"MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER)", addr, size);
		return -1;
	}

	/* Actually free reservation part. */
	if (!VirtualFree(addr, 0, MEM_RELEASE)) {
		RTE_LOG_SYSTEM_ERROR("VirtualFree(%p, 0, MEM_RELEASE)", addr);
		return -1;
	}

	return 0;
}

void*
rte_mem_reserve(void *requested_addr, size_t size,
	enum rte_mem_reserve_flags flags)
{
	void *virt;

	if (mem_access_advanced_features() < 0) {
		RTE_LOG(ERR, EAL, "Cannot access advanced memory features\n");
		rte_errno = ENOTSUP;
		return NULL;
	}

	/* Windows requires hugepages to be committed. */
	if (flags & RTE_RESERVE_HUGEPAGES) {
		RTE_LOG(ERR, EAL, "Windows: hugepage reservation is not supported\n");
		rte_errno = ENOTSUP;
		return NULL;
	}

	virt = VirtualAlloc2(GetCurrentProcess(), requested_addr, size,
		MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS,
		NULL, 0);
	if (virt == NULL) {
		RTE_LOG_SYSTEM_ERROR("VirtualAlloc2()");
		rte_errno = win32_alloc_error_to_errno(GetLastError());
	}

	if ((flags & RTE_RESERVE_EXACT_ADDRESS) && (virt != requested_addr)) {
		if (!VirtualFree(virt, 0, MEM_RELEASE)) {
			RTE_LOG_SYSTEM_ERROR("VirtualFree()");
		}
		rte_errno = ENOMEM;
		return NULL;
	}

    return virt;
}

void*
rte_mem_alloc(size_t size, enum rte_page_sizes hugepage_size)
{
	DWORD flags = MEM_RESERVE | MEM_COMMIT;
	void *base;
	size_t page_size, offset;

	/* No control over page size on Windows. */
	if (hugepage_size != 0)
		flags |= MEM_LARGE_PAGES;

	base = VirtualAlloc(NULL, size, flags, PAGE_READWRITE);
	if (base == NULL) {
		rte_errno = ENOMEM;
		return NULL;
	}

	/* Trigger physical page allocation. */
	page_size = hugepage_size ? hugepage_size :
		(size_t)rte_get_page_size();
	for (offset = 0; offset < size; offset += page_size) {
		void *addr = (uint8_t *)base + offset;
		*(volatile int *)addr = *(volatile int *)addr;
	}

	return base;
}

void
rte_mem_free(void *virt, size_t size)
{
	eal_mem_free(virt, size, false);
}

int
rte_mem_lock(const void* virt, size_t size)
{
    /* VirtualLock() takes `void*`, workaround compiler warning. */
    void *addr = (void *)((uintptr_t)virt);

    if (!VirtualLock(addr, size)) {
        RTE_LOG_SYSTEM_ERROR("VirtualLock()");
        return -1;
    }

    return 0;
}

int
rte_mem_lockall(enum rte_mem_lockall_flags flags)
{
	RTE_SET_USED(flags);

	/* Indicate lack of platform support per mlockall() specification. */
	rte_errno = ENOTSUP;
	return -1;
}

int
rte_mem_protect(void *addr, size_t size, enum rte_mem_prot prot)
{
	DWORD sys_prot = 0, old_sys_prot;

	if (prot & RTE_PROT_EXECUTE) {
		if (prot & RTE_PROT_READ)
			sys_prot = PAGE_EXECUTE_READ;
		if (prot & RTE_PROT_WRITE)
			sys_prot = PAGE_EXECUTE_READWRITE;
	} else {
		if (prot & RTE_PROT_READ)
			sys_prot = PAGE_READONLY;
		if (prot & RTE_PROT_WRITE)
			sys_prot = PAGE_READWRITE;
	}
	
	if (!VirtualProtect(addr, size, sys_prot, &old_sys_prot)) {
		RTE_LOG_SYSTEM_ERROR("VirtualProtect()");
		rte_errno = EINVAL;
		return -1;
	}
	return 0;
}

void*
rte_mem_map(void* requested_addr, size_t size, enum rte_mem_prot prot,
		enum rte_map_flags flags, int fd, size_t offset)
{
	HANDLE file_handle = INVALID_HANDLE_VALUE;
	HANDLE mapping_handle = INVALID_HANDLE_VALUE;
	DWORD sys_prot = 0;
	DWORD sys_access = 0;
	DWORD size_high = (DWORD)(size >> 32);
	DWORD size_low = (DWORD)size;
	DWORD offset_high = (DWORD)(offset >> 32);
	DWORD offset_low = (DWORD)offset;
	LPVOID virt = NULL;

	if (prot & RTE_PROT_EXECUTE) {
		if (prot & RTE_PROT_READ) {
			sys_prot = PAGE_EXECUTE_READ;
			sys_access = FILE_MAP_READ | FILE_MAP_EXECUTE;
		}
		if (prot & RTE_PROT_WRITE) {
			sys_prot = PAGE_EXECUTE_READWRITE;
			sys_access = FILE_MAP_WRITE | FILE_MAP_EXECUTE;
		}
	} else {
		if (prot & RTE_PROT_READ) {
			sys_prot = PAGE_READONLY;
			sys_access = FILE_MAP_READ;
		}
		if (prot & RTE_PROT_WRITE) {
			sys_prot = PAGE_READWRITE;
			sys_access = FILE_MAP_WRITE;
		}
	}

	if (flags & RTE_MAP_PRIVATE)
		sys_access |= FILE_MAP_COPY;

	if ((flags & RTE_MAP_ANONYMOUS) == 0)
		file_handle = (HANDLE)_get_osfhandle(fd);

	mapping_handle = CreateFileMapping(
		file_handle, NULL, sys_prot, size_high, size_low, NULL);
	if (mapping_handle == INVALID_HANDLE_VALUE) {
		RTE_LOG_SYSTEM_ERROR("CreateFileMapping()");
		return NULL;
	}

	if (requested_addr != NULL) {
		int ret = eal_mem_free(requested_addr, size, true);
		if (ret) {
			if (ret > 0) {
				RTE_LOG(ERR, EAL, "Cannot map memory "
					"to a region not reserved\n");
				rte_errno = EADDRNOTAVAIL;
			}
			return NULL;
		}
	}

	virt = MapViewOfFileEx(mapping_handle, sys_access,
		offset_high, offset_low, size, requested_addr);
	if (!virt) {
		RTE_LOG_SYSTEM_ERROR("MapViewOfFileEx()");
		return NULL;
	}

	if ((flags & RTE_MAP_FIXED) && (virt != requested_addr)) {
		BOOL ret = UnmapViewOfFile(virt);
		virt = NULL;
		if (!ret) {
			RTE_LOG_SYSTEM_ERROR("UnmapViewOfFile()");
		}
	}

	if (!CloseHandle(mapping_handle)) {
		RTE_LOG_SYSTEM_ERROR("CloseHandle()");
	}

	return virt;
}

int
rte_mem_unmap(void *virt, size_t size)
{
	RTE_SET_USED(size);

	if (!UnmapViewOfFile(virt)) {
		rte_errno = GetLastError();
		RTE_LOG_SYSTEM_ERROR("UnmapViewOfFile()");
		return -1;
	}
	return 0;
}

/* Always using physical addresses under Windows. */
int
rte_eal_using_phys_addrs(void)
{
	return 1;
}

/* Windows kernel uses top half of address space. */
uint64_t
eal_get_baseaddr(void)
{
	return 0;
}

int
rte_get_page_size(void)
{
    SYSTEM_INFO info;
    GetSystemInfo(&info);
    return (int)info.dwPageSize;
}

#define MEMSEG_LIST_FMT "memseg-%" PRIu64 "k-%i-%i"

static int
memseg_alloc_list(struct rte_memseg_list *msl, uint64_t page_sz,
		int n_segs, int socket_id, int type_msl_idx)
{
	char name[RTE_FBARRAY_NAME_LEN];

	snprintf(name, sizeof(name), MEMSEG_LIST_FMT, page_sz >> 10, socket_id,
		 type_msl_idx);
	if (rte_fbarray_init(&msl->memseg_arr, name, n_segs,
			sizeof(struct rte_memseg))) {
		RTE_LOG(ERR, EAL, "Cannot allocate memseg list: %s\n",
			rte_strerror(rte_errno));
		return -1;
	}

	msl->page_sz = page_sz;
	msl->socket_id = socket_id;
	msl->base_va = NULL;
	msl->heap = 1; /* mark it as a heap segment */

	RTE_LOG(DEBUG, EAL, "Memseg list allocated: 0x%"RTE_PRIzx"kB at socket %i\n",
			(size_t)page_sz >> 10, socket_id);

	return 0;
}

static int
memseg_alloc_va_space(struct rte_memseg_list *msl)
{
	uint64_t page_sz;
	size_t mem_sz;
	void *addr;

	page_sz = msl->page_sz;
	mem_sz = page_sz * msl->memseg_arr.len;

	addr = eal_get_virtual_area(msl->base_va, &mem_sz, page_sz, 0, 0);
	if (addr == NULL) {
		if (rte_errno == EADDRNOTAVAIL)
			RTE_LOG(ERR, EAL, "Could not mmap %" RTE_PRIzu
				" bytes at [%p] - use '--" OPT_BASE_VIRTADDR "'"
				" option\n", mem_sz, msl->base_va);
		else
			RTE_LOG(ERR, EAL, "Cannot reserve memory\n");
		return -1;
	}
	msl->base_va = addr;
	msl->len = mem_sz;

	return 0;
}

static int __rte_unused
memseg_primary_init_32(void)
{
	EAL_NOT_IMPLEMENTED();
	return -1;
}

static int __rte_unused
memseg_primary_init(void)
{
	struct rte_mem_config *mcfg = rte_eal_get_configuration()->mem_config;
	struct memtype {
		uint64_t page_sz;
		int socket_id;
	} *memtypes = NULL;
	int i, hpi_idx, msl_idx, ret = -1; /* fail unless told to succeed */
	struct rte_memseg_list *msl;
	uint64_t max_mem, max_mem_per_type;
	unsigned int max_seglists_per_type;
	unsigned int n_memtypes, cur_type;

	/* no-huge does not need this at all */
	if (internal_config.no_hugetlbfs)
		return 0;

	/*
	 * figuring out amount of memory we're going to have is a long and very
	 * involved process. the basic element we're operating with is a memory
	 * type, defined as a combination of NUMA node ID and page size (so that
	 * e.g. 2 sockets with 2 page sizes yield 4 memory types in total).
	 *
	 * deciding amount of memory going towards each memory type is a
	 * balancing act between maximum segments per type, maximum memory per
	 * type, and number of detected NUMA nodes. the goal is to make sure
	 * each memory type gets at least one memseg list.
	 *
	 * the total amount of memory is limited by RTE_MAX_MEM_MB value.
	 *
	 * the total amount of memory per type is limited by either
	 * RTE_MAX_MEM_MB_PER_TYPE, or by RTE_MAX_MEM_MB divided by the number
	 * of detected NUMA nodes. additionally, maximum number of segments per
	 * type is also limited by RTE_MAX_MEMSEG_PER_TYPE. this is because for
	 * smaller page sizes, it can take hundreds of thousands of segments to
	 * reach the above specified per-type memory limits.
	 *
	 * additionally, each type may have multiple memseg lists associated
	 * with it, each limited by either RTE_MAX_MEM_MB_PER_LIST for bigger
	 * page sizes, or RTE_MAX_MEMSEG_PER_LIST segments for smaller ones.
	 *
	 * the number of memseg lists per type is decided based on the above
	 * limits, and also taking number of detected NUMA nodes, to make sure
	 * that we don't run out of memseg lists before we populate all NUMA
	 * nodes with memory.
	 *
	 * we do this in three stages. first, we collect the number of types.
	 * then, we figure out memory constraints and populate the list of
	 * would-be memseg lists. then, we go ahead and allocate the memseg
	 * lists.
	 */

	/* create space for mem types */
	n_memtypes = internal_config.num_hugepage_sizes * rte_socket_count();
	memtypes = calloc(n_memtypes, sizeof(*memtypes));
	if (memtypes == NULL) {
		RTE_LOG(ERR, EAL, "Cannot allocate space for memory types\n");
		return -1;
	}

	/* populate mem types */
	cur_type = 0;
	for (hpi_idx = 0; hpi_idx < (int) internal_config.num_hugepage_sizes;
			hpi_idx++) {
		struct hugepage_info *hpi;
		uint64_t hugepage_sz;

		hpi = &internal_config.hugepage_info[hpi_idx];
		hugepage_sz = hpi->hugepage_sz;

		for (i = 0; i < (int) rte_socket_count(); i++, cur_type++) {
			int socket_id = rte_socket_id_by_idx(i);

#ifndef RTE_EAL_NUMA_AWARE_HUGEPAGES
			/* we can still sort pages by socket in legacy mode */
			if (!internal_config.legacy_mem && socket_id > 0)
				break;
#endif
			memtypes[cur_type].page_sz = hugepage_sz;
			memtypes[cur_type].socket_id = socket_id;

			RTE_LOG(DEBUG, EAL, "Detected memory type: "
				"socket_id:%u hugepage_sz:%" PRIu64 "\n",
				socket_id, hugepage_sz);
		}
	}
	/* number of memtypes could have been lower due to no NUMA support */
	n_memtypes = cur_type;

	/* set up limits for types */
	max_mem = (uint64_t)RTE_MAX_MEM_MB << 20;
	max_mem_per_type = RTE_MIN((uint64_t)RTE_MAX_MEM_MB_PER_TYPE << 20,
			max_mem / n_memtypes);

	/*
	 * limit maximum number of segment lists per type to ensure there's
	 * space for memseg lists for all NUMA nodes with all page sizes
	 */
	max_seglists_per_type = RTE_MAX_MEMSEG_LISTS / n_memtypes;

	if (max_seglists_per_type == 0) {
		RTE_LOG(ERR, EAL, "Cannot accommodate all memory types, please increase %s\n",
			RTE_STR(CONFIG_RTE_MAX_MEMSEG_LISTS));
		goto out;
	}

	/* go through all mem types and create segment lists */
	msl_idx = 0;
	for (cur_type = 0; cur_type < n_memtypes; cur_type++) {
		unsigned int cur_seglist, n_seglists, n_segs;
		unsigned int max_segs_per_type, max_segs_per_list;
		struct memtype *type = &memtypes[cur_type];
		uint64_t max_mem_per_list, pagesz;
		int socket_id;

		pagesz = type->page_sz;
		socket_id = type->socket_id;

		/*
		 * we need to create segment lists for this type. we must take
		 * into account the following things:
		 *
		 * 1. total amount of memory we can use for this memory type
		 * 2. total amount of memory per memseg list allowed
		 * 3. number of segments needed to fit the amount of memory
		 * 4. number of segments allowed per type
		 * 5. number of segments allowed per memseg list
		 * 6. number of memseg lists we are allowed to take up
		 */

		/* calculate how much segments we will need in total */
		max_segs_per_type = max_mem_per_type / pagesz;
		/* limit number of segments to maximum allowed per type */
		max_segs_per_type = RTE_MIN(max_segs_per_type,
				(unsigned int)RTE_MAX_MEMSEG_PER_TYPE);
		/* limit number of segments to maximum allowed per list */
		max_segs_per_list = RTE_MIN(max_segs_per_type,
				(unsigned int)RTE_MAX_MEMSEG_PER_LIST);

		/* calculate how much memory we can have per segment list */
		max_mem_per_list = RTE_MIN(max_segs_per_list * pagesz,
				(uint64_t)RTE_MAX_MEM_MB_PER_LIST << 20);

		/* calculate how many segments each segment list will have */
		n_segs = RTE_MIN(max_segs_per_list, max_mem_per_list / pagesz);

		/* calculate how many segment lists we can have */
		n_seglists = RTE_MIN(max_segs_per_type / n_segs,
				max_mem_per_type / max_mem_per_list);

		/* limit number of segment lists according to our maximum */
		n_seglists = RTE_MIN(n_seglists, max_seglists_per_type);

		RTE_LOG(DEBUG, EAL, "Creating %i segment lists: "
				"n_segs:%i socket_id:%i hugepage_sz:%" PRIu64 "\n",
			n_seglists, n_segs, socket_id, pagesz);

		/* create all segment lists */
		for (cur_seglist = 0; cur_seglist < n_seglists; cur_seglist++) {
			if (msl_idx >= RTE_MAX_MEMSEG_LISTS) {
				RTE_LOG(ERR, EAL,
					"No more space in memseg lists, please increase %s\n",
					RTE_STR(CONFIG_RTE_MAX_MEMSEG_LISTS));
				goto out;
			}
			msl = &mcfg->memsegs[msl_idx++];

			if (memseg_alloc_list(msl, pagesz, n_segs,
					socket_id, cur_seglist))
				goto out;

			if (memseg_alloc_va_space(msl)) {
				RTE_LOG(ERR, EAL, "Cannot allocate VA space for memseg list\n");
				goto out;
			}
		}
	}
	/* we're successful */
	ret = 0;
out:
	free(memtypes);
	return ret;
}

static int
memseg_secondary_init(void)
{
	struct rte_mem_config *mcfg = rte_eal_get_configuration()->mem_config;
	int msl_idx = 0;
	struct rte_memseg_list *msl;

	for (msl_idx = 0; msl_idx < RTE_MAX_MEMSEG_LISTS; msl_idx++) {

		msl = &mcfg->memsegs[msl_idx];

		/* skip empty memseg lists */
		if (msl->memseg_arr.len == 0)
			continue;

		if (rte_fbarray_attach(&msl->memseg_arr)) {
			RTE_LOG(ERR, EAL, "Cannot attach to primary process memseg lists\n");
			return -1;
		}

		/* preallocate VA space */
		if (memseg_alloc_va_space(msl)) {
			RTE_LOG(ERR, EAL, "Cannot preallocate VA space for hugepage memory\n");
			return -1;
		}
	}

	return 0;
}

int
rte_eal_memseg_init(void)
{
#ifndef RTE_EAL_NUMA_AWARE_HUGEPAGES
	if (!internal_config.legacy_mem && rte_socket_count() > 1) {
		RTE_LOG(WARNING, EAL, "DPDK is running on a NUMA system, but is compiled without NUMA support.\n");
		RTE_LOG(WARNING, EAL, "This will have adverse consequences for performance and usability.\n");
		RTE_LOG(WARNING, EAL, "Please use --"OPT_LEGACY_MEM" option, or recompile with NUMA support.\n");
	}
#endif

	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
#ifndef RTE_ARCH_64
			return memseg_primary_init_32();
#else
			return memseg_primary_init();
#endif
    }
	return memseg_secondary_init();
}

__rte_unused /* function is unused on 32-bit builds */
static inline uint64_t
get_socket_mem_size(int socket)
{
	uint64_t size = 0;
	unsigned i;

	for (i = 0; i < internal_config.num_hugepage_sizes; i++){
		struct hugepage_info *hpi = &internal_config.hugepage_info[i];
		size += hpi->hugepage_sz * hpi->num_pages[socket];
	}

	return size;
}

static int
calc_num_pages_per_socket(uint64_t * memory,
		struct hugepage_info *hp_info,
		struct hugepage_info *hp_used,
		unsigned num_hp_info)
{
	unsigned socket, j, i = 0;
	unsigned requested, available;
	int total_num_pages = 0;
	uint64_t remaining_mem, cur_mem;
	uint64_t total_mem = internal_config.memory;

	if (num_hp_info == 0)
		return -1;

	/* if specific memory amounts per socket weren't requested */
	if (internal_config.force_sockets == 0) {
		size_t total_size;
#ifdef RTE_ARCH_64
		int cpu_per_socket[RTE_MAX_NUMA_NODES];
		size_t default_size;
		unsigned lcore_id;

		/* Compute number of cores per socket */
		memset(cpu_per_socket, 0, sizeof(cpu_per_socket));
		RTE_LCORE_FOREACH(lcore_id) {
			cpu_per_socket[rte_lcore_to_socket_id(lcore_id)]++;
		}

		/*
		 * Automatically spread requested memory amongst detected sockets according
		 * to number of cores from cpu mask present on each socket
		 */
		total_size = internal_config.memory;
		for (socket = 0; socket < RTE_MAX_NUMA_NODES && total_size != 0; socket++) {

			/* Set memory amount per socket */
			default_size = (internal_config.memory * cpu_per_socket[socket])
					/ rte_lcore_count();

			/* Limit to maximum available memory on socket */
			default_size = RTE_MIN(default_size, get_socket_mem_size(socket));

			/* Update sizes */
			memory[socket] = default_size;
			total_size -= default_size;
		}

		/*
		 * If some memory is remaining, try to allocate it by getting all
		 * available memory from sockets, one after the other
		 */
		for (socket = 0; socket < RTE_MAX_NUMA_NODES && total_size != 0; socket++) {
			/* take whatever is available */
			default_size = RTE_MIN(get_socket_mem_size(socket) - memory[socket],
					       total_size);

			/* Update sizes */
			memory[socket] += default_size;
			total_size -= default_size;
		}
#else
		/* in 32-bit mode, allocate all of the memory only on master
		 * lcore socket
		 */
		total_size = internal_config.memory;
		for (socket = 0; socket < RTE_MAX_NUMA_NODES && total_size != 0;
				socket++) {
			struct rte_config *cfg = rte_eal_get_configuration();
			unsigned int master_lcore_socket;

			master_lcore_socket =
				rte_lcore_to_socket_id(cfg->master_lcore);

			if (master_lcore_socket != socket)
				continue;

			/* Update sizes */
			memory[socket] = total_size;
			break;
		}
#endif
	}

	for (socket = 0; socket < RTE_MAX_NUMA_NODES && total_mem != 0; socket++) {
		/* skips if the memory on specific socket wasn't requested */
		for (i = 0; i < num_hp_info && memory[socket] != 0; i++){
			strncpy(hp_used[i].hugedir, hp_info[i].hugedir,
				sizeof(hp_used[i].hugedir));
			hp_used[i].num_pages[socket] = RTE_MIN(
					memory[socket] / hp_info[i].hugepage_sz,
					hp_info[i].num_pages[socket]);

			cur_mem = hp_used[i].num_pages[socket] *
					hp_used[i].hugepage_sz;

			memory[socket] -= cur_mem;
			total_mem -= cur_mem;

			total_num_pages += hp_used[i].num_pages[socket];

			/* check if we have met all memory requests */
			if (memory[socket] == 0)
				break;

			/* check if we have any more pages left at this size, if so
			 * move on to next size */
			if (hp_used[i].num_pages[socket] == hp_info[i].num_pages[socket])
				continue;
			/* At this point we know that there are more pages available that are
			 * bigger than the memory we want, so lets see if we can get enough
			 * from other page sizes.
			 */
			remaining_mem = 0;
			for (j = i+1; j < num_hp_info; j++)
				remaining_mem += hp_info[j].hugepage_sz *
				hp_info[j].num_pages[socket];

			/* is there enough other memory, if not allocate another page and quit */
			if (remaining_mem < memory[socket]){
				cur_mem = RTE_MIN(memory[socket],
						hp_info[i].hugepage_sz);
				memory[socket] -= cur_mem;
				total_mem -= cur_mem;
				hp_used[i].num_pages[socket]++;
				total_num_pages++;
				break; /* we are done with this socket*/
			}
		}
		/* if we didn't satisfy all memory requirements per socket */
		if (memory[socket] > 0 &&
				internal_config.socket_mem[socket] != 0) {
			/* to prevent icc errors */
			requested = (unsigned) (internal_config.socket_mem[socket] /
					0x100000);
			available = requested -
					((unsigned) (memory[socket] / 0x100000));
			RTE_LOG(ERR, EAL, "Not enough memory available on socket %u! "
					"Requested: %uMB, available: %uMB\n", socket,
					requested, available);
			return -1;
		}
	}

	/* if we didn't satisfy total memory requirements */
	if (total_mem > 0) {
		requested = (unsigned) (internal_config.memory / 0x100000);
		available = requested - (unsigned) (total_mem / 0x100000);
		RTE_LOG(ERR, EAL, "Not enough memory available! Requested: %uMB,"
				" available: %uMB\n", requested, available);
		return -1;
	}
	return total_num_pages;
}

static int __rte_unused
hugepage_count_walk(const struct rte_memseg_list *msl, void *arg)
{
	struct hugepage_info *hpi = arg;

	if (msl->page_sz != hpi->hugepage_sz)
		return 0;

	hpi->num_pages[msl->socket_id] += msl->memseg_arr.len;
	return 0;
}

static int
limits_callback(int socket_id, size_t cur_limit, size_t new_len)
{
	RTE_SET_USED(socket_id);
	RTE_SET_USED(cur_limit);
	RTE_SET_USED(new_len);
	return -1;
}

static int
eal_hugepage_init(void)
{
	struct hugepage_info used_hp[MAX_HUGEPAGE_SIZES];
	uint64_t memory[RTE_MAX_NUMA_NODES];
	int hp_sz_idx, socket_id;

	memset(used_hp, 0, sizeof(used_hp));

	for (hp_sz_idx = 0;
			hp_sz_idx < (int) internal_config.num_hugepage_sizes;
			hp_sz_idx++) {
#ifndef RTE_ARCH_64
		struct hugepage_info dummy;
		unsigned int i;
#endif
		/* also initialize used_hp hugepage sizes in used_hp */
		struct hugepage_info *hpi;
		hpi = &internal_config.hugepage_info[hp_sz_idx];
		used_hp[hp_sz_idx].hugepage_sz = hpi->hugepage_sz;

#ifndef RTE_ARCH_64
		/* for 32-bit, limit number of pages on socket to whatever we've
		 * preallocated, as we cannot allocate more.
		 */
		memset(&dummy, 0, sizeof(dummy));
		dummy.hugepage_sz = hpi->hugepage_sz;
		if (rte_memseg_list_walk(hugepage_count_walk, &dummy) < 0)
			return -1;

		for (i = 0; i < RTE_DIM(dummy.num_pages); i++) {
			hpi->num_pages[i] = RTE_MIN(hpi->num_pages[i],
					dummy.num_pages[i]);
		}
#endif
	}

	/* make a copy of socket_mem, needed for balanced allocation. */
	for (hp_sz_idx = 0; hp_sz_idx < RTE_MAX_NUMA_NODES; hp_sz_idx++)
		memory[hp_sz_idx] = internal_config.socket_mem[hp_sz_idx];

	/* calculate final number of pages */
	if (calc_num_pages_per_socket(memory,
			internal_config.hugepage_info, used_hp,
			internal_config.num_hugepage_sizes) < 0)
		return -1;

	for (hp_sz_idx = 0;
			hp_sz_idx < (int)internal_config.num_hugepage_sizes;
			hp_sz_idx++) {
		for (socket_id = 0; socket_id < RTE_MAX_NUMA_NODES;
				socket_id++) {
			struct rte_memseg **pages;
			struct hugepage_info *hpi = &used_hp[hp_sz_idx];
			unsigned int num_pages = hpi->num_pages[socket_id];
			unsigned int num_pages_alloc;

			if (num_pages == 0)
				continue;

			RTE_LOG(DEBUG, EAL,
					"Allocating %u pages of size %" PRIu64 "M on socket %i\n",
					num_pages, hpi->hugepage_sz >> 20, socket_id);

			/* we may not be able to allocate all pages in one go,
			 * because we break up our memory map into multiple
			 * memseg lists. therefore, try allocating multiple
			 * times and see if we can get the desired number of
			 * pages from multiple allocations.
			 */

			num_pages_alloc = 0;
			do {
				int i, cur_pages, needed;

				needed = num_pages - num_pages_alloc;

				pages = malloc(sizeof(*pages) * needed);

				/* do not request exact number of pages */
				cur_pages = eal_memalloc_alloc_seg_bulk(pages,
						needed, hpi->hugepage_sz,
						socket_id, false);
				if (cur_pages <= 0) {
					free(pages);
					return -1;
				}

				/* mark preallocated pages as unfreeable */
				for (i = 0; i < cur_pages; i++) {
					struct rte_memseg *ms = pages[i];
					ms->flags |= RTE_MEMSEG_FLAG_DO_NOT_FREE;
				}
				free(pages);

				num_pages_alloc += cur_pages;
			} while (num_pages_alloc != num_pages);
		}
	}
	/* if socket limits were specified, set them */
	if (internal_config.force_socket_limits) {
		unsigned int i;
		for (i = 0; i < RTE_MAX_NUMA_NODES; i++) {
			uint64_t limit = internal_config.socket_limit[i];
			if (limit == 0)
				continue;
			if (rte_mem_alloc_validator_register("socket-limit",
					limits_callback, i, limit))
				RTE_LOG(ERR, EAL, "Failed to register socket limits validator callback\n");
		}
	}
	return 0;
}

static int
eal_nohuge_init(void)
{
	struct rte_mem_config *mcfg;
	struct rte_memseg_list *msl;
	int n_segs, cur_seg;
	uint64_t page_sz;
	void *addr;
	struct rte_fbarray *arr;
	struct rte_memseg *ms;

	mcfg = rte_eal_get_configuration()->mem_config;

	/* nohuge mode is legacy mode */
	internal_config.legacy_mem = 1;

	/* nohuge mode is single-file segments mode */
	internal_config.single_file_segments = 1;

	/* create a memseg list */
	msl = &mcfg->memsegs[0];

	page_sz = RTE_PGSIZE_4K;
	n_segs = internal_config.memory / page_sz;

	if (rte_fbarray_init(&msl->memseg_arr, "nohugemem", n_segs,
			sizeof(struct rte_memseg))) {
		RTE_LOG(ERR, EAL, "Cannot allocate memseg list\n");
		return -1;
	}

	addr = rte_mem_alloc(internal_config.memory, 0);
	if (addr == NULL) {
		RTE_LOG(ERR, EAL, "Cannot allocate %" RTE_PRIzu " bytes",
			internal_config.memory);
		return -1;
	}

	msl->base_va = addr;
	msl->page_sz = page_sz;
	msl->socket_id = 0;
	msl->len = internal_config.memory;
	msl->heap = 1;

	/* populate memsegs. each memseg is one page long */
	for (cur_seg = 0; cur_seg < n_segs; cur_seg++) {
		arr = &msl->memseg_arr;

		ms = rte_fbarray_get(arr, cur_seg);
		if (rte_eal_iova_mode() == RTE_IOVA_VA)
			ms->iova = (uintptr_t)addr;
		else
			ms->iova = RTE_BAD_IOVA;
		ms->addr = addr;
		ms->hugepage_sz = page_sz;
		ms->socket_id = 0;
		ms->len = page_sz;

		rte_fbarray_set_used(arr, cur_seg);

		addr = RTE_PTR_ADD(addr, (size_t)page_sz);
	}

	if (mcfg->dma_maskbits &&
		rte_mem_check_dma_mask_thread_unsafe(mcfg->dma_maskbits)) {
		RTE_LOG(ERR, EAL,
			"%s(): couldn't allocate memory due to IOVA "
			"exceeding limits of current DMA mask.\n",
			__func__);
		if (rte_eal_iova_mode() == RTE_IOVA_VA &&
			rte_eal_using_phys_addrs())
			RTE_LOG(ERR, EAL,
				"%s(): Please try initializing EAL with "
				"--iova-mode=pa parameter.\n",
				__func__);
		return -1;
	}

	return 0;
}

int
rte_eal_hugepage_init(void)
{
	return internal_config.no_hugetlbfs ?
		eal_nohuge_init() : eal_hugepage_init();
}

int
rte_eal_hugepage_attach(void)
{
	EAL_NOT_IMPLEMENTED();
	return -1;
}
