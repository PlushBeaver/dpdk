/* SPDX-License-Identifier: BSD-3-Clause */

/**
 * @file OS-independent filesystem API.
 */

#ifndef _RTE_FILESYSTEM_H_
#define _RTE_FILESYSTEM_H_

#include <stdint.h>

/** File locking operation. */
enum rte_flock_op {
	RTE_FLOCK_SHARED,    /**< Acquire a shared lock. */
	RTE_FLOCK_EXCLUSIVE, /**< Acquire an exclusive lock. */
	RTE_FLOCK_UNLOCK     /**< Release a previously taken lock. */
};

/** Behavior on file locking conflict. */
enum rte_flock_mode {
	RTE_FLOCK_WAIT,  /**< Wait until the file gets unlocked to lock it. */
	RTE_FLOCK_RETURN /**< Return immediately if the file is locked. */
};

/**
 * Lock or unlock the file.
 * 
 * On failure @code rte_errno @endcode is set to the error code
 * specified by POSIX flock(3) description.
 * 
 * @param fd
 * 	Opened file descriptor.
 * @param op
 * 	Operation to perform.
 * @param mode
 * 	Behavior on conflict.
 * @return
 * 	0 on success, (-1) on failure.
 */
int rte_flock(int fd, enum rte_flock_op op, enum rte_flock_mode mode);

/**
 * Truncate or extend the file to the specified size.
 *
 * On failure @code rte_errno @endcode is set to the error code
 * specified by POSIX ftruncate(3) description.
 * 
 * @param fd
 * 	Opened file descriptor.
 * @param size
 * 	Desired file size.
 * @return
 * 	0 on success, (-1) on failure.
 */
int rte_ftruncate(int fd, ssize_t size);

#endif
