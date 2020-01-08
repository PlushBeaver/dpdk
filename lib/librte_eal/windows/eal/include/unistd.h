/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Intel Corporation
 */

#ifndef _UNISTD_H_
#define _UNISTD_H_

/**
 * This file is added to support common code in eal_common_lcore.c
 * as Microsoft libc does not contain unistd.h. This may be removed
 * in future releases.
 */

#ifdef _WIN32 /* Compiling target binaries, emulate POSIX. */

#include <stddef.h>

#include <io.h>

/* Defined in ws2_32.dll, `namelen` is `int` in Windows. */
__attribute__((stdcall, dllimport))
int gethostname(char *name, int namelen);

#else /* Compiling a build tool, chain-include native header. */

#ifdef __has_include_next
#include_next <unistd.h>
#endif

#endif /* _WIN32 */
#endif /* _UNISTD_H_ */
