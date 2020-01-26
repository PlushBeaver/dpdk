/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2019 Intel Corporation
 */

#ifndef _RTE_OS_H_
#define _RTE_OS_H_

#include <inttypes.h>
#include <limits.h>

#include <sched.h>
#include <pthread.h>

/**
 * @file
 * This header should contain any function/macro definitions
 * which are not supported natively or named differently in the Windows OS.
 * Note that <windows.h> is intentionally not included
 * because its definitions may break otherwise portable code.
 * Use <rte_windows.h> to access basic Windows facilities.
 */

#ifdef __cplusplus
extern "C" {
#endif

/* These defines from Microsoft libc often conflict with portable code. */
#ifdef max
#undef max
#endif
#ifdef min
#undef min
#endif

/*
 * POSIX compatibility section
 */

/* strdup is deprecated in Microsoft libc and _strdup is preferred */
#define strdup(str) _strdup(str)
#define strerror_r(a, b, c) strerror_s(b, c, a)
#define strtok_r(str, delim, saveptr) strtok_s(str, delim, saveptr)

/* No special versions of <setjmp.h> functions due to lack of signals. */
#define sigjmp_buf jmp_buf
#define sigsetjmp(env, savesigs) setjmp(env)
#define siglongjmp(env, val) longjmp(env, val)

#define ffs __builtin_ffs

/* as defined in <windows.h> */
#ifndef PATH_MAX
#define PATH_MAX 260
#endif

/* as defined in Linux */
#define LINE_MAX 2048

/* as defined in <windows.h> */
#ifdef RTE_ARCH_64
typedef long long int ssize_t;
#else
typedef long int ssize_t;
#endif

long int random(void);

long int lrand48(void);

long int mrand48(void);

unsigned int sleep(unsigned long sec);

int usleep(unsigned int usec);

int vdprintf(int fd, const char* format, va_list op);

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

#ifndef CPU_SET_SIZE
#define CPU_SET_SIZE 128
#endif

/* GNU extension used across EAL. */
#ifndef CPU_SETSIZE
#define CPU_SETSIZE CPU_SET_SIZE
#endif

#define _BITS_PER_SET (sizeof(long long) * 8)
#define _BIT_SET_MASK (_BITS_PER_SET - 1)

#define _NUM_SETS(b) (((b) + _BIT_SET_MASK) / _BITS_PER_SET)
#define _WHICH_SET(b) ((b) / _BITS_PER_SET)
#define _WHICH_BIT(b) ((b) & (_BITS_PER_SET - 1))

typedef struct _rte_cpuset_s {
	long long _bits[_NUM_SETS(CPU_SET_SIZE)];
} rte_cpuset_t;

#define CPU_SET(b, s) \
	((s)->_bits[_WHICH_SET(b)] |= (1LL << _WHICH_BIT(b)))

#define CPU_ZERO(s) \
	do { \
		unsigned int _i; \
		for (_i = 0; _i < _NUM_SETS(CPU_SET_SIZE); _i++) \
			(s)->_bits[_i] = 0LL; \
	} while (0)

#define CPU_ISSET(b, s) \
	((s)->_bits[_WHICH_SET(b)] & (1LL << _WHICH_BIT(b)))

#define DEFINE_CPUSET_OP(name, op) \
	static inline rte_cpuset_t* \
	name(rte_cpuset_t* dest, const rte_cpuset_t* lhs, \
		const rte_cpuset_t* rhs) \
        { \
		size_t i; \
		for (i = 0; i < _NUM_SETS(CPU_SET_SIZE); i++) \
			dest->_bits[i] = lhs->_bits[i] op rhs->_bits[i]; \
		return dest; \
        }

DEFINE_CPUSET_OP(RTE_CPU_AND, &)
DEFINE_CPUSET_OP(RTE_CPU_OR, |)

DEFINE_CPUSET_OP(CPU_XOR, ^)

#undef DEFINE_CPUSET_OP

static inline int
CPU_COUNT(rte_cpuset_t *cpuset)
{
	size_t i, j;
	int count = 0;

	for (i = 0; i < _NUM_SETS(CPU_SET_SIZE); i++) {
		for (j = 0; j < CHAR_BIT; j++) {
			if (cpuset->_bits[i] & (1LL << j))
				count++;
		}
	}

	return count;
}

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
