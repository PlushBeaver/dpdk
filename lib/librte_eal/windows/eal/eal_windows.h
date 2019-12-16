#ifndef EAL_WINDOWS_H
#define EAL_WINDOWS_H

/**
 * @file Facilities private to Windows EAL
 */

#include <stdint.h>

#include <rte_windows.h>

/** Number of processors in a processor group (32 or 64). */
#define EAL_PROCESSOR_GROUP_SIZE (sizeof(KAFFINITY) * CHAR_BIT)

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
 * This function is similar to @ref rte_mem_free_virtual(),
 * except that it fails if memory is not in reserved state.
 *
 * @param addr
 *  Starting address of the area to free.
 * 
 * @param size
 *  Number of bytes to free. Must be a multiple of page size.
 * 
 * @return
 *  * 0 on successful deallocation;
 * 	* 1 if region is not in reserved state;
 *  * (-1) on system API failures.
 */
int eal_mem_free_virtual(void *addr, size_t size);

/**
 * Name of the mutex to synchronize hugepage allocation.
 */
#define EAL_HUGEPAGE_LOCK TEXT("rte_hugepage_lock")

/**
 * Check if mutex handle is (in)valid.
 */
#define EAL_LOCK_VALID(handle)   (handle != EAL_INVALID_LOCK)
#define EAL_LOCK_INVALID(handle) (!EAL_LOCK_VALID(handle))

#endif