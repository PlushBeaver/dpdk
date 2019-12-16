/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef _ARPA_INET_H_
#define _ARPA_INET_H_

/**
 * @file Compatibility header
 *
 * This file is added to support common code dealing with networking
 * as Microsoft libc does not contain <arpa/inet.h>. Windows Sockets
 * include must come before <windows.h>, so include entire <rte_os.h>.
 */

#include <sys/socket.h>

#endif /* _ARPA_INET_H_ */
