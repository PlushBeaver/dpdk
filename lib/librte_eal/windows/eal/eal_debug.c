/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Intel Corporation
 */

#include <stdarg.h>

#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_log.h>

#include "eal_windows.h"

 /* call abort(), it will generate a coredump if enabled */
void
__rte_panic(const char *funcname, const char *format, ...)
{
	va_list ap;

	rte_log(RTE_LOG_CRIT, RTE_LOGTYPE_EAL, "PANIC in %s():\n", funcname);
	va_start(ap, format);
	rte_vlog(RTE_LOG_CRIT, RTE_LOGTYPE_EAL, format, ap);
	va_end(ap);
	abort();
}

void
rte_dump_stack(void)
{
	EAL_NOT_IMPLEMENTED();
}

void
rte_dump_registers(void)
{
	EAL_NOT_IMPLEMENTED();
}

/*
 * Like rte_panic this terminates the application. However, no traceback is
 * provided and no core-dump is generated.
 */
void
rte_exit(int exit_code, const char *format, ...)
{
	va_list ap;

	if (exit_code != 0)
		RTE_LOG(CRIT, EAL, "Error - exiting with code: %d\n"
				"  Cause: ", exit_code);

	va_start(ap, format);
	rte_vlog(RTE_LOG_CRIT, RTE_LOGTYPE_EAL, format, ap);
	va_end(ap);

#ifndef RTE_EAL_ALWAYS_PANIC_ON_ERROR
	if (rte_eal_cleanup() != 0)
		RTE_LOG(CRIT, EAL,
			"EAL could not release all resources\n");
	exit(exit_code);
#else
	abort();
#endif
}
