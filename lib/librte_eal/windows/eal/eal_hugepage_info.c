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
	    token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
		RTE_LOG_SYSTEM_ERROR("AdjustTokenPrivileges()");
		goto exit;
	}

	ret = 0;

exit:
	CloseHandle(token);

	return ret;
}

static int
hugepage_info_init(void)
{
	struct hugepage_info *hpi;
	unsigned int socket_id;
	int ret = 0;

	/* Only one hugepage size available in Windows. */
	internal_config.num_hugepage_sizes = 1;
	hpi = &internal_config.hugepage_info[0];

	hpi->hugepage_sz = GetLargePageMinimum();
	if (hpi->hugepage_sz == 0) {
		return -ENOTSUP;
	}

	/* Assume all memory on each NUMA node available for hugepages,
	 * because Windows does not impose any additional limits.
	 */
	for (socket_id = 0; socket_id < rte_socket_count(); socket_id++) {
		ULONGLONG bytes;
		unsigned int numa_node;

		numa_node = eal_socket_numa_node(socket_id);
		if (!GetNumaAvailableMemoryNodeEx(numa_node, &bytes)) {
			RTE_LOG_SYSTEM_ERROR(
				"GetNumaAvailableMemoryNodeEx(%u)", numa_node);
			continue;
		}

		hpi->num_pages[socket_id] = bytes / hpi->hugepage_sz;
		RTE_LOG(DEBUG, EAL,
			"Found %u hugepages of %zu bytes on socket %u\n",
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
		RTE_LOG(ERR, EAL, "Cannot claim hugepage privilege\n");
		return -1;
	}

	if (hugepage_info_init() < 0) {
		RTE_LOG(ERR, EAL, "Cannot get hugepage information\n");
		return -1;
	}

	if (internal_config.no_shconf) {
		return 0;
	}

	hpi = &internal_config.hugepage_info[0];

	shared = create_shared_memory(eal_hugepage_info_path(), sizeof(*shared));
	if (shared == NULL) {
		RTE_LOG(ERR, EAL, "Cannot create hugepage info shared memory\n");
		return -1;
	}

	memcpy(shared, hpi, sizeof(*shared));

	if (rte_mem_unmap(shared, sizeof(*shared)) < 0) {
		RTE_LOG(ERR, EAL, "Cannot unmap hugepage info shared memory\n");
		return -1;
	}

	return 0;
}

int
eal_hugepage_info_read(void)
{
	struct hugepage_info *hpi, *shared;

	hpi = &internal_config.hugepage_info[0];

	shared = open_shared_memory(eal_hugepage_info_path(), sizeof(*shared));
	if (shared == NULL) {
		RTE_LOG(ERR, EAL, "Cannot open hugepage info shared memory\n");
		return -1;
	}

	memcpy(hpi, shared, sizeof(*hpi));

	if (rte_mem_unmap(shared, sizeof(*shared)) < 0) {
		RTE_LOG(ERR, EAL, "Cannot unmap hugepage info shared memory\n");
		return -1;
	}
	return 0;
}
