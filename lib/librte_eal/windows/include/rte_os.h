/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2019 Intel Corporation
 */

#ifndef _RTE_OS_H_
#define _RTE_OS_H_

/**
 * This is header should contain any function/macro definition
 * which are not supported natively or named differently in the
 * Windows OS. It must not include Windows-specific headers.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* cpu_set macros implementation */
#define RTE_CPU_AND(dst, src1, src2) CPU_AND(dst, src1, src2)
#define RTE_CPU_OR(dst, src1, src2) CPU_OR(dst, src1, src2)
#define RTE_CPU_FILL(set) CPU_FILL(set)
#define RTE_CPU_NOT(dst, src) CPU_NOT(dst, src)

/* Allow DPDK to call common functions by POSIX names. */
#ifdef RTE_BUILD_INTERNAL

#ifndef PATH_MAX
#define PATH_MAX _MAX_PATH
#endif

#define strdup(str) _strdup(str)
#define strtok_r(str, delim, saveptr) strtok_s(str, delim, saveptr)
#define strncasecmp(s1, s2, count) _strnicmp(s1, s2, count)

#define open(path, flags, ...) _open(path, flags, ##__VA_ARGS__)
#define read(fd, buf, n) _read(fd, buf, n)
#define write(fd, buf, n) _write(fd, buf, n)
#define close(fd) _close(fd)
#define unlink(path) _unlink(path)

#endif /* RTE_BUILD_INTERNAL */

/* This is an exception without "rte_" prefix, because Windows does have
 * ssize_t, but it's defined in <windows.h> which we avoid to expose.
 * If ssize_t is defined in user code, it necessarily has the same type.
 */
typedef long long ssize_t;

#ifdef __cplusplus
}
#endif

#endif /* _RTE_OS_H_ */
