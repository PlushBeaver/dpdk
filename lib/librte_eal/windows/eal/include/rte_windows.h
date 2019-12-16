#ifndef _RTE_WINDOWS_H_
#define _RTE_WINDOWS_H_

/* Cancel MinGW definition in standard library. */
#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#endif

/* Memory management requires VirtualAlloc2(). */
#define _WIN32_WINNT _WIN32_WINNT_WIN10

#define WIN32_LEAN_AND_MEAN /* Disable excessive libraries. */
#define INITGUID            /* Have GUIDs defined. */

#include <windows.h>

#include <rte_log.h>

/**
 * @file Windows-specific facilities
 * 
 * In Windows, system API errors are unrelated to CRT errors.
 * Different types of API have their own sets of error codes
 * and specific functions to get error messages.
 * This file provides error handling facilities for all
 * Windows-specific code, EAL and PCI in the first place.
 */

/**
 * Log an error caused by API with caller function and system error code.
 *
 * @param fmt
 *  Details format string, typically an OS function name with some context.
 */ 
#define RTE_LOG_SYSTEM_ERROR(fmt, ...) do { \
			RTE_LOG(ERR, EAL, "%s(): error %lu from " fmt "\n", \
					__func__, GetLastError(), ##__VA_ARGS__); \
		} while (0)

#endif
