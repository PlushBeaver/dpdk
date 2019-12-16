#include <fcntl.h>
#include <io.h>

#include <rte_errno.h>
#include <rte_filesystem.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_os.h>
#include <rte_windows.h>

/* must come after <windows.h> */
#include <psapi.h>

#include "eal_filesystem.h"
#include "eal_hugepages.h"
#include "eal_internal_cfg.h"
#include "eal_windows.h"

static void *
map_shared_memory(const char *filename, const size_t mem_size, int flags)
{
	void *addr;
    int fd;
	
    fd = _open(filename, flags, 0600);
	if (fd < 0) {
		return NULL;
    }

	if (rte_ftruncate(fd, mem_size) < 0) {
		_close(fd);
		return NULL;
	}

	addr = rte_mem_map(NULL, mem_size, RTE_PROT_READ | RTE_PROT_WRITE,
			RTE_MAP_SHARED, fd, 0);
	_close(fd);
	return addr;
}

static void *
open_shared_memory(const char *filename, const size_t mem_size)
{
	return map_shared_memory(filename, mem_size, _O_RDWR);
}

static void *
create_shared_memory(const char *filename, const size_t mem_size)
{
	return map_shared_memory(filename, mem_size, _O_RDWR | _O_CREAT);
}

static int
hugepage_claim_privilege(void) {
    const wchar_t privilege[] = L"SeLockMemoryPrivilege";

    HANDLE token;
    LUID luid;
    TOKEN_PRIVILEGES tp;
    int ret = -1;

    if (!OpenProcessToken(
            GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token)) {
        RTE_LOG_SYSTEM_ERROR("OpenProcessToken()");
        return -1;
    }

    if (!LookupPrivilegeValueW(NULL, privilege, &luid)) {
        RTE_LOG_SYSTEM_ERROR("LookupPrivilegeValue(\"%S\")", privilege);
        goto exit;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(
           token,
           FALSE,
           &tp,
           sizeof(TOKEN_PRIVILEGES),
           NULL,
           NULL)) {
        RTE_LOG_SYSTEM_ERROR("AdjustTokenPrivileges()");
        goto exit;
    }

    ret = 0;

exit:
    CloseHandle(token);

    return ret;
}

static int
hugepage_estimate_count(size_t hugepage_sz, ULONGLONG available_bytes,
        struct hugepage_info *hpi)
{
    void *addr = NULL;
    PSAPI_WORKING_SET_EX_INFORMATION *infos;
    DWORD infos_size;
    int i;
    int max_page_count, test_page_count, page_count;
    int ret = 0;

    /* Binary search for total available hugepages in the system. */
    page_count = 1;
    max_page_count = available_bytes / hugepage_sz;
    test_page_count = max_page_count;
    while (page_count + 1 < max_page_count) {
        addr = VirtualAlloc(
                NULL,
                test_page_count * hugepage_sz,
                MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES,
                PAGE_READWRITE);
        if (addr != NULL) {
            VirtualFree(addr, 0, MEM_RELEASE);
            page_count = test_page_count;
        } else {
            max_page_count = test_page_count;
        }
        test_page_count = (page_count + max_page_count) / 2;
    }

    /* Allocate all possible hugepages on all nodes. */
    addr = VirtualAlloc(
                NULL,
                page_count * hugepage_sz,
                MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES,
                PAGE_READWRITE);
    if (addr == NULL) {
        RTE_LOG_SYSTEM_ERROR("VirtualAlloc()");
        return -1;
    }

    /* Query information about actual allocations performed. */
    infos_size = sizeof(infos[0]) * page_count;
    infos = malloc(infos_size);
    if (infos == NULL) {
        ret = -1;
        goto exit;
    }

    for (i = 0; i < page_count; i++) {
        uint8_t *virt = (uint8_t *)addr + i * hugepage_sz;

        /* Force OS to allocate a physical page and choose a node for it. */
        *virt = 0;

        infos[i].VirtualAddress = virt;
    }

    if (!QueryWorkingSetEx(GetCurrentProcess(), infos, infos_size)) {
        RTE_LOG_SYSTEM_ERROR("QueryWorkingSetEx()");
        ret = -1;
        goto exit;
    }

    /* Count pages allocated on each node. */
    for (i = 0; i < page_count; i++) {
        unsigned int socket_id;

        if (!infos[i].VirtualAttributes.Valid) {
            continue;
        }

        if (!infos[i].VirtualAttributes.LargePage) {
            continue;
        }

        socket_id = eal_numa_node_socket_id(infos[i].VirtualAttributes.Node);
        hpi->num_pages[socket_id]++;
    }

    hpi->hugepage_sz = hugepage_sz;

exit:
    /* Free hugepages and intermediate data. */
    if (infos) {
        free(infos);
    }
    if (addr) {
        VirtualFree(addr, 0, MEM_RELEASE);
    }
    return ret;
}

static int
hugepage_info_init(void)
{
    size_t hugepage_sz;
    struct hugepage_info *hpi;
    MEMORYSTATUSEX memstat;
    unsigned int socket_id;
    int ret = 0;

    hugepage_sz = GetLargePageMinimum();
    if (hugepage_sz == 0) {
        return -ENOTSUP;
    }

    memstat.dwLength = sizeof(memstat);
    if (!GlobalMemoryStatusEx(&memstat)) {
        RTE_LOG_SYSTEM_ERROR("GlobalMemoryStatusEx()");
        return -1;
    }

    /* Only one hugepage size available in Windows. */
    internal_config.num_hugepage_sizes = 1;
    hpi = &internal_config.hugepage_info[0];

    ret = hugepage_estimate_count(hugepage_sz, memstat.ullAvailPhys, hpi);
    if (ret) {
        return ret;
    }

    for (socket_id = 0; socket_id < rte_socket_count(); socket_id++) {
        RTE_LOG(DEBUG, EAL,
                "Found %u hugepages of %" RTE_PRIzu " bytes on socket %u\n",
                hpi->num_pages[socket_id], hpi->hugepage_sz, socket_id);
    }

    hpi->lock_descriptor = CreateMutex(NULL, FALSE, EAL_HUGEPAGE_LOCK);
    if (EAL_LOCK_INVALID(hpi->lock_descriptor)) {
        RTE_LOG_SYSTEM_ERROR("CreateMutex()");
        return -1;
    }
    
    /* No hugepage filesystem in Windows. */
    memset(hpi->hugedir, 0, sizeof(hpi->hugedir));

    return ret;
}

int
eal_hugepage_info_init(void)
{
    struct hugepage_info *hpi, *shared;

    if (hugepage_claim_privilege() < 0) {
        RTE_LOG(ERR, EAL, "Failed to claim hugepage privilege!\n");
        return -1;
    }

	if (hugepage_info_init() < 0) {
        RTE_LOG(ERR, EAL, "Failed to get hugepage information!\n");
		return -1;
    }

	if (internal_config.no_shconf) {
		return 0;
    }

	hpi = &internal_config.hugepage_info[0];

	shared = create_shared_memory(
            eal_hugepage_info_path(),
			sizeof(*shared));
	if (shared == NULL) {
		RTE_LOG(ERR, EAL, "Failed to create shared memory!\n");
		return -1;
	}

	memcpy(shared, hpi, sizeof(*shared));

	if (rte_mem_unmap(shared, sizeof(*shared)) < 0) {
		RTE_LOG(ERR, EAL, "Failed to unmap shared memory!\n");
		return -1;
	}

	return 0;
}

int
eal_hugepage_info_read(void)
{
    struct hugepage_info *hpi, *shared;

    hpi = &internal_config.hugepage_info[0];

	shared = open_shared_memory(
            eal_hugepage_info_path(),
			sizeof(*shared));
	if (shared == NULL) {
		RTE_LOG(ERR, EAL, "Failed to open shared memory!\n");
		return -1;
	}

	memcpy(hpi, shared, sizeof(*hpi));

	if (rte_mem_unmap(shared, sizeof(*shared)) < 0) {
		RTE_LOG(ERR, EAL, "Failed to unmap shared memory!\n");
		return -1;
	}
	return 0;
}