/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2019 Intel Corporation
 */

#ifndef _RTE_OS_H_
#define _RTE_OS_H_

#include <inttypes.h>
#include <pthread.h>
#include <sched.h>

/**
 * @file
 * This is header should contain any function/macro definition
 * which are not supported natively or named differently in the
 * Windows OS. Functions will be added in future releases.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * POSIX compatibility section
 */

/* strdup is deprecated in Microsoft libc and _strdup is preferred */
#define strdup(str) _strdup(str)

#define strerror_r(a, b, c) strerror_s(b, c, a)

#define strtok_r(str, delim, saveptr) strtok_s(str, delim, saveptr)

long int random(void);

unsigned int sleep(unsigned long sec);

int usleep(useconds_t usec);

int vdprintf(int fd, const char* format, va_list op);

int pthread_setaffinity_np(
		pthread_t thread, size_t cpuset_size, const rte_cpuset_t *cpuset);


/**
 * Maximum path length supported by target platform.
 * 
 * In Windows, this is equal to @code MAX_PATH @endcode.
 */
#define RTE_PATH_MAX 260

/**
 * The most precise floating-point type supported by target platform.
 *
 * MSVCRT does not distinguish between "double" and "long double",
 * but GCC issues a warning if "%lf" is used with "double".
 * 
 * @see RTE_PRILf
 */
typedef double rte_long_double;

/**
 * Formatting specifier for @code rte_long_double @endcode.
 * 
 * MSVCRT does not support "%Lf".
 */
#define RTE_PRILf "lf"

/**
 * Formatting specifiers for (s)size_t.
 *
 * MSVCRT does not support "%z" modifier.
 */
#define RTE_PRIzd PRId64
#define RTE_PRIzu PRIu64
#define RTE_PRIzx PRIx64

/**
 * Dynamically loaded module descriptor.
 * 
 * In Windows, this is @code HMODULE @endcode.
 */
typedef void *rte_module;

/**
 * Invalid @code rte_module @endcode value.
 */
#define RTE_INVALID_MODULE NULL

/**
 * Opened device descriptor.
 * 
 * This type must be used to abstract platform-specific descriptors.
 * For operations involving only standard C API, int is sufficient.
 * 
 * In Windows, this is @code HANDLE @endcode.
 */
typedef void *rte_fd;

/**
 * Invalid @code rte_fd @endcode value.
 * 
 * In Windows, this is @code INVALID_HANDLE_VALUE @endcode.
 */
#define RTE_INVALID_FD ((rte_fd)(-1))

/**
 * Check whether an @code rte_fd @endcode is invalid.
 */
#define RTE_FD_INVALID(fd) ((fd) == RTE_INVALID_FD)

/**
 * Formatting specifier for @code rte_fd @endcode.
 */
#define RTE_PRI_FD "p"

/*
 * CPU set operations
 */

#define RTE_CPU_AND CPU_AND

#define RTE_CPU_OR CPU_OR

#define RTE_CPU_FILL(set) do \
{ \
	unsigned int i; \
	CPU_ZERO(set); \
	for (i = 0; i < CPU_SET_SIZE; i++) \
		CPU_SET(i, set); \
} while (0)

#define RTE_CPU_NOT(dst, src) do \
{ \
	rte_cpuset_t tmp; \
	RTE_CPU_FILL(&tmp); \
	CPU_XOR(dst, &tmp, src); \
} while (0)

/**
 * Create a thread.
 * This function is private to EAL.
 *
 * @param thread
 *   The location to store the thread id if successful.
 * @return
 *   0 for success, -1 if the thread is not created.
 */
int eal_thread_create(pthread_t *thread);

/*
 * Check if a cpu is present.
 * This function is private to EAL.
 */
int eal_cpu_detected(unsigned int lcore_id);

/*
 * Get CPU socket id for a logical core.
 * This function is private to EAL.
 */
unsigned eal_cpu_socket_id(unsigned int lcore_id);

/*
 * Get CPU socket id (NUMA node) for a logical core.
 * This function is private to EAL.
 */
unsigned eal_cpu_core_id(unsigned int lcore_id);

/**
 * Invalid value for lock descriptor.
 * This constant is private to EAL.
 */
#define EAL_INVALID_LOCK NULL

#ifdef __cplusplus
}
#endif

#endif /* _RTE_OS_H_ */
