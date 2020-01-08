/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef _NETINET_IN_H_
#define _NETINET_IN_H_

/**
 * @file Compatibility header
 *
 * This file is added to support common code dealing with networking
 * as Microsoft libc does not contain <netinet/in.h>. Windows Sockets
 * includes must come before <windows.h>, so include entire <rte_os.h>.
 */

#include <sys/socket.h>

#endif /* _NETINET_IN_H_ */
