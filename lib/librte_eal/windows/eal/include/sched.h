/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Intel Corporation
 */

#ifndef _SCHED_H_
#define _SCHED_H_

#include <limits.h>

/**
 * This file is added to support the common code in eal_common_thread.c
 * as Microsoft libc does not contain sched.h. This may be removed
 * in future releases.
 */
#ifdef __cplusplus
extern "C" {
#endif

#ifndef CPU_SETSIZE
#define CPU_SETSIZE RTE_MAX_LCORE
#endif

#define _BITS_PER_SET (sizeof(long long) * 8)
#define _BIT_SET_MASK (_BITS_PER_SET - 1)

#define _NUM_SETS(b) (((b) + _BIT_SET_MASK) / _BITS_PER_SET)
#define _WHICH_SET(b) ((b) / _BITS_PER_SET)
#define _WHICH_BIT(b) ((b) & (_BITS_PER_SET - 1))

typedef struct _rte_cpuset_s {
	long long _bits[_NUM_SETS(CPU_SETSIZE)];
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
		name(rte_cpuset_t* dest, const rte_cpuset_t* lhs, const rte_cpuset_t* rhs) \
        { \
            size_t i; \
            for (i = 0; i < _NUM_SETS(CPU_SET_SIZE); i++) \
                dest->_bits[i] = lhs->_bits[i] op rhs->_bits[i]; \
            return dest; \
        }

DEFINE_CPUSET_OP(CPU_AND, &)
DEFINE_CPUSET_OP(CPU_OR, |)
DEFINE_CPUSET_OP(CPU_XOR, ^)

#define CPU_ZERO(s)							\
	do {								\
		unsigned int _i;					\
									\
		for (_i = 0; _i < _NUM_SETS(CPU_SETSIZE); _i++)		\
			(s)->_bits[_i] = 0LL;				\
	} while (0)

#ifdef __cplusplus
}
#endif

#endif /* _SCHED_H_ */
