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

#include <stddef.h>

/* Defined in ws2_32.dll, `namelen` is `int` in Windows. */
__attribute__((stdcall, dllimport))
int gethostname(char *name, int namelen);

#endif /* _UNISTD_H_ */
