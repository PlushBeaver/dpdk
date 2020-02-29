#include <io.h>

#include <rte_errno.h>
#include <rte_memory.h>

#include "eal_private.h"
#include "eal_windows.h"

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

void *
eal_mem_reserve(void *requested_addr, size_t size,
	enum rte_mem_reserve_flags flags)
{
	void *virt;

	/* Windows requires hugepages to be committed. */
	if (flags & RTE_RESERVE_HUGEPAGES) {
		RTE_LOG(ERR, EAL, "Hugepage reservation is not supported\n");
		rte_errno = ENOTSUP;
		return NULL;
	}

	virt = VirtualAlloc2(GetCurrentProcess(), requested_addr, size,
		MEM_RESERVE | MEM_RESERVE_PLACEHOLDER, PAGE_NOACCESS,
		NULL, 0);
	if (virt == NULL) {
		RTE_LOG_WIN32_ERR("VirtualAlloc2()");
		rte_errno = win32_alloc_error_to_errno(GetLastError());
	}

	if ((flags & RTE_RESERVE_EXACT_ADDRESS) && (virt != requested_addr)) {
		if (!VirtualFree(virt, 0, MEM_RELEASE)) {
			RTE_LOG_WIN32_ERR("VirtualFree()");
		}
		rte_errno = ENOMEM;
		return NULL;
	}

    return virt;
}

void *
eal_mem_alloc(size_t size, int socket_id)
{
	DWORD flags = MEM_RESERVE | MEM_COMMIT;
	void *addr;

	flags = MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES;
	addr = VirtualAllocExNuma(GetCurrentProcess(), NULL, size, flags,
		PAGE_READWRITE, eal_socket_numa_node(socket_id));
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

	if (requested_addr != NULL) {
		MEMORY_BASIC_INFORMATION info;
		if (VirtualQuery(requested_addr, &info, sizeof(info)) == 0) {
			RTE_LOG_WIN32_ERR("VirtualQuery()");
			return NULL;
		}

		/* Split reserved region if only a part is committed. */
		flags = MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER;
		if ((info.RegionSize > size) &&
			!VirtualFree(requested_addr, size, flags)) {
			RTE_LOG_WIN32_ERR("VirtualFree(%p, %zu, "
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
		int err = GetLastError();
		RTE_LOG_WIN32_ERR("VirtualAlloc2(%p, %zu, "
			"<replace placeholder>)", addr, size);
		rte_errno = win32_alloc_error_to_errno(err);
		return NULL;
	}

	return addr;
}

int
eal_mem_decommit(void *addr, size_t size)
{
	if (!VirtualFree(addr, size, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER)) {
		RTE_LOG_WIN32_ERR("VirtualFree(%p, %zu, ...)", addr, size);
		return -1;
	}
	return 0;
}

/**
 * Free a reserved memory region in full or in part.
 *
 * @param addr
 *  Starting address of the area to free.
 * @param size
 *  Number of bytes to free. Must be a multiple of page size.
 * @param reserved
 *  Fail if the region is not in reserved state.
 * @return
 *  * 0 on successful deallocation;
 *  * 1 if region mut be in reserved state but it is not;
 *  * (-1) on system API failures.
 */
static int
mem_free(void *addr, size_t size, bool reserved)
{
	MEMORY_BASIC_INFORMATION info;
	if (VirtualQuery(addr, &info, sizeof(info)) == 0) {
		RTE_LOG_WIN32_ERR("VirtualQuery()");
		return -1;
	}

	if (reserved && (info.State != MEM_RESERVE)) {
		return 1;
	}
	
	/* Free complete region. */
	if ((addr == info.AllocationBase) && (size == info.RegionSize)) {
		if (!VirtualFree(addr, 0, MEM_RELEASE)) {
			RTE_LOG_WIN32_ERR("VirtualFree(%p, 0, MEM_RELEASE)",
				addr);
		}
		return 0;
	}

	/* Split the part to be freed and the remaining reservation. */
	if (!VirtualFree(addr, size, MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER)) {
		RTE_LOG_WIN32_ERR("VirtualFree(%p, %zu, "
			"MEM_RELEASE | MEM_PRESERVE_PLACEHOLDER)", addr, size);
		return -1;
	}

	/* Actually free reservation part. */
	if (!VirtualFree(addr, 0, MEM_RELEASE)) {
		RTE_LOG_WIN32_ERR("VirtualFree(%p, 0, MEM_RELEASE)", addr);
		return -1;
	}

	return 0;
}

void
eal_mem_free(void *virt, size_t size)
{
	mem_free(virt, size, false);
}

void *
rte_mem_map(void *requested_addr, size_t size, enum rte_mem_prot prot,
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
		RTE_LOG_WIN32_ERR("CreateFileMapping()");
		return NULL;
	}

	/* TODO: there is a race for the requested_addr between mem_free()
	 * and MapViewOfFileEx(). MapViewOfFile3() that can replace a reserved
	 * region with a mapping in a single operation, but it does not support
	 * private mappings.
	 */
	if (requested_addr != NULL) {
		int ret = mem_free(requested_addr, size, true);
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
		RTE_LOG_WIN32_ERR("MapViewOfFileEx()");
		return NULL;
	}

	if ((flags & RTE_MAP_FIXED) && (virt != requested_addr)) {
		BOOL ret = UnmapViewOfFile(virt);
		virt = NULL;
		if (!ret) {
			RTE_LOG_WIN32_ERR("UnmapViewOfFile()");
		}
	}

	if (!CloseHandle(mapping_handle)) {
		RTE_LOG_WIN32_ERR("CloseHandle()");
	}

	return virt;
}

int
rte_mem_unmap(void *virt, size_t size)
{
	RTE_SET_USED(size);

	if (!UnmapViewOfFile(virt)) {
		rte_errno = GetLastError();
		RTE_LOG_WIN32_ERR("UnmapViewOfFile()");
		return -1;
	}
	return 0;
}

int
rte_get_page_size(void)
{
    SYSTEM_INFO info;
    GetSystemInfo(&info);
    return info.dwPageSize;
}

int
rte_mem_lock(const void *virt, size_t size)
{
    /* VirtualLock() takes `void*`, work around compiler warning. */
    void *addr = (void *)((uintptr_t)virt);

    if (!VirtualLock(addr, size)) {
        RTE_LOG_WIN32_ERR("VirtualLock()");
        return -1;
    }

    return 0;
}
