/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020 Dmitry Kozlyuk
 */

#ifndef _RTE_WINDOWS_H_
#define _RTE_WINDOWS_H_

/**
 * @file Windows-specific facilities
 *
 * This file should be included by DPDK libraries and applications
 * that need access to Windows API. It includes platform SDK headers
 * in compatible order with proper options and defines error-handling macros.
 */

/* Disable excessive libraries. */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

/* Must come first. */
#include <windows.h>

#include <basetsd.h>
#include <psapi.h>
#include <setupapi.h>
#include <winioctl.h>

/* Have GUIDs defined. */
#ifndef INITGUID
#define INITGUID
#endif
#include <initguid.h>

/**
 * Log GetLastError() with context, usually a Win32 API function and arguments.
 */
#define RTE_LOG_WIN32_ERR(format, ...) \
	do { \
		RTE_LOG(DEBUG, EAL, "GetLastError()=%lu: " format "\n", \
			GetLastError(), ##__VA_ARGS__); \
	} while (0)

#endif /* _RTE_WINDOWS_H_ */
