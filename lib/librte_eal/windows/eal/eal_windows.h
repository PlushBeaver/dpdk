#ifndef EAL_WINDOWS_H
#define EAL_WINDOWS_H

/**
 * @file Facilities private to Windows EAL
 */

#include <stdbool.h>
#include <stdint.h>

#include <rte_errno.h>
#include <rte_log.h>
#include <rte_windows.h>

/** Number of processors in a processor group (32 or 64). */
#define EAL_PROCESSOR_GROUP_SIZE (sizeof(KAFFINITY) * CHAR_BIT)

/**
 * Name of the mutex to synchronize hugepage allocation.
 */
#define EAL_HUGEPAGE_LOCK TEXT("rte_hugepage_lock")

/**
 * Check if mutex handle is (in)valid.
 */
#define EAL_LOCK_VALID(handle)   (handle != EAL_INVALID_LOCK)
#define EAL_LOCK_INVALID(handle) (!EAL_LOCK_VALID(handle))

/**
 * Report current function as unimplemented in Windows.
 */
#define EAL_NOT_IMPLEMENTED() \
    do { \
        RTE_LOG(ERR, EAL, "Windows: %s() is not implemented\n", __func__); \
        rte_errno = ENOTSUP; \
    } while (0)

/**
 * Report current function implemented as a stub in Windows.
 */
#define EAL_STUB() \
    RTE_LOG(WARNING, EAL, "Windows: %s() stub called\n", __func__)

/**
 * Create a map of processors and cores on the system.
 */
void eal_create_cpu_map(void);

/**
 * Get system NUMA node number for a socket ID.
 * 
 * @param socket_id
 *  Valid EAL socket ID.
 * @return
 *  NUMA node number to use with Win32 API.
 */
unsigned int eal_socket_numa_node(unsigned int socket_id);

/**
 * Get socket ID associated with system NUMA node ID.
 * 
 * @param node_id
 *  NUMA node ID obtained from Win32 API.
 * @return
 *  EAL socket ID or 0 if @code node_id @endcode is not valid.
 */
unsigned int eal_numa_node_socket_id(unsigned int node_id);

/**
 * Free a reserved memory region in full or in part.
 *
 * This function is similar to @ref rte_mem_free(), except that it can check
 * if memory is not in reserved state.
 *
 * @param addr
 *  Starting address of the area to free.
 * @param size
 *  Number of bytes to free. Must be a multiple of page size.
 * @param reserved
 *  Fail if memory is not in reserved state.
 * @return
 *  * 0 on successful deallocation;
 * 	* 1 if region must be in reserved state and it is not;
 *  * (-1) on system API failures.
 */
int eal_mem_free(void *addr, size_t size, bool reserved);

/**
 * Allocate new memory in hugepages on the specified NUMa node.
 */
void *eal_mem_alloc(size_t size, int socket_id);

/**
 * Commit memory previously reserved with @ref rte_mem_reserve()
 * or freed with @ref eal_mem_decommit() from hugepages.
 * 
 * @param requested_addr
 *  Address within a reserved region. Must not be NULL.
 * @param size
 *  Number of bytes to commit. Must be a multiple of page size.
 * @param socket_id
 *  Socket ID to allocate on. Can be SOCKET_ID_ANY.
 * @return
 *  On success, address of the committed memory, that is, requested_addr.
 *  On failure, NULL and @code rte_errno @endcode is set.
 */
void *eal_mem_commit(void *requested_addr, size_t size, int socket_id);

/**
 * Put allocated or committed memory back into reserved state.
 * 
 * @param addr
 *  Address of the region to decommit.
 * @param size
 *  Number of bytes to decommit.
 * 
 * The @code addr @endcode and @code param @endcode must match
 * location and size of previously allocated or commited region.
 * 
 * @return
 *  0 on success, (-1) on failure.
 */
int eal_mem_decommit(void *addr, size_t size);

#endif