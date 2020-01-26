/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2019 Intel Corporation
 */

#ifndef _RTE_OS_H_
#define _RTE_OS_H_

/**
 * This is header should contain any function/macro definition
 * which are not supported natively or named differently in the
 * linux OS. Functions will be added in future releases.
 */

#include <linux/limits.h>
#include <sched.h>

typedef cpu_set_t rte_cpuset_t;
#define RTE_CPU_AND(dst, src1, src2) CPU_AND(dst, src1, src2)
#define RTE_CPU_OR(dst, src1, src2) CPU_OR(dst, src1, src2)
#define RTE_CPU_FILL(set) do \
{ \
	unsigned int i; \
	CPU_ZERO(set); \
	for (i = 0; i < CPU_SETSIZE; i++) \
		CPU_SET(i, set); \
} while (0)
#define RTE_CPU_NOT(dst, src) do \
{ \
	cpu_set_t tmp; \
	RTE_CPU_FILL(&tmp); \
	CPU_XOR(dst, &tmp, src); \
} while (0)

/**
 * Dynamically loded module descriptor.
 */
typedef void* rte_module;

/**
 * Invalid @code rte_module @endcode value.
 */
#define RTE_INVALID_MODULE NULL

/**
 * Opened device descriptor.
 * 
 * This type must be used to abstract platform-specific descriptors.
 * For operations involving only standard C API, int is sufficient.
 */
typedef int rte_fd;

/**
 * Invalid @code rte_fd @endcode value.
 */
#define RTE_INVALID_FD (-1)

/**
 * Check whether an @code rte_fd @endcode is invalid.
 */
#define RTE_FD_INVALID(fd) ((fd) < 0)

/**
 * Formatting specifier for @code rte_fd @endcode.
 */
#define RTE_PRI_FD "d"

/**
 * Invalid value for lock descriptor.
 * This constant is private to EAL.
 */
#define EAL_INVALID_LOCK RTE_INVALID_FD

#endif /* _RTE_OS_H_ */
