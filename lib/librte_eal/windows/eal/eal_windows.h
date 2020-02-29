/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020 Dmitry Kozlyuk
 */

#ifndef _EAL_WINDOWS_H_
#define _EAL_WINDOWS_H_

/**
 * @file Facilities private to Windows EAL
 */

#include <rte_errno.h>
#include <rte_windows.h>

/**
 * Log current function as not implemented and set rte_errno.
 */
#define EAL_LOG_NOT_IMPLEMENTED() \
	do { \
		RTE_LOG(DEBUG, EAL, "%s() is not implemented\n", __func__); \
		rte_errno = ENOTSUP; \
	} while (0)

/**
 * Create a map of processors and cores on the system.
 */
void eal_create_cpu_map(void);

/**
 * Create a thread.
 *
 * @param thread
 *   The location to store the thread id if successful.
 * @return
 *   0 for success, -1 if the thread is not created.
 */
int eal_thread_create(pthread_t *thread);

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
 * Open virt2phys driver interface device.
 *
 * @return 0 on success, (-1) on failure.
 */
int eal_mem_virt2iova_init(void);

/**
 * Allocate new memory in hugepages on the specified NUMa node.
 */
void * eal_mem_alloc(size_t size, int socket_id);

/**
 * Commit memory previously reserved with @ref eal_mem_reserve()
 * or decommitted from hugepages by @ref eal_mem_decommit().
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
void * eal_mem_commit(void *requested_addr, size_t size, int socket_id);

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

#endif /* _EAL_WINDOWS_H_ */
