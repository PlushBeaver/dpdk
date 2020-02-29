#include <io.h>

#include <rte_errno.h>
#include <rte_memory.h>

#include "eal_windows.h"

/**
 * Free a reserved memory region in full or in part.
 *
 * @param addr
 *  Starting address of the area to free.
 * @param size
 *  Number of bytes to free. Must be a multiple of page size.
 * @return
 *  * 0 on successful deallocation;
 *  * 1 if region is not in reserved state;
 *  * (-1) on system API failures.
 */
static int
mem_free(void *addr, size_t size)
{
	MEMORY_BASIC_INFORMATION info;
	if (VirtualQuery(addr, &info, sizeof(info)) == 0) {
		RTE_LOG_WIN32_ERR("VirtualQuery()");
		return -1;
	}

	if (info.State != MEM_RESERVE) {
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
		int ret = mem_free(requested_addr, size);
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
