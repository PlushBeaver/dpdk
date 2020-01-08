/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef _SYS_SOCKET_H_
#define _SYS_SOCKET_H_

/**
 * @file Compatibility header
 *
 * This file is added to support common code dealing with networking
 * as Microsoft libc does not contain <sys/socket.h>. Windows Sockets
 * includes must come before <windows.h>, so include entire <rte_os.h>.
 */

#include <inttypes.h>

#include <rte_common.h>

#define AF_INET  2
#define AF_INET6 23

#define IPPROTO_IP 0
#define IPPROTO_HOPOPTS 0
#define IPPROTO_ICMP 1
#define IPPROTO_IGMP 2
#define IPPROTO_GGP 3
#define IPPROTO_IPV4 4
#define IPPROTO_ST 5
#define IPPROTO_TCP 6
#define IPPROTO_CBT 7
#define IPPROTO_EGP 8
#define IPPROTO_IGP 9
#define IPPROTO_PUP 12
#define IPPROTO_UDP 17
#define IPPROTO_IDP 22
#define IPPROTO_RDP 27
#define IPPROTO_IPV6 41
#define IPPROTO_ROUTING 43
#define IPPROTO_FRAGMENT 44
#define IPPROTO_ESP 50
#define IPPROTO_AH 51
#define IPPROTO_ICMPV6 58
#define IPPROTO_NONE 59
#define IPPROTO_DSTOPTS 60
#define IPPROTO_ND 77
#define IPPROTO_ICLFXBM 78
#define IPPROTO_PIM 103
#define IPPROTO_PGM 113
#define IPPROTO_L2TP 115
#define IPPROTO_SCTP 132

#define IPPROTO_RAW 255
#define IPPROTO_MAX 256

#define IPDEFTTL 64

#define IPVERSION 4

#define INET6_ADDRSTRLEN 40

#ifdef __cplusplus
extern "C" {
#endif

struct in_addr {
    uint32_t s_addr;
};

struct in6_addr {
    union {
        unsigned char _u6_addr8[16];
        unsigned short _u6_addr16[8];
    } _u6;
};

#define s6_addr _u6._u6_addr8
#define s6_addr16 _u6._u6_addr16

typedef size_t socklen_t;

int inet_aton(const char *cp, struct in_addr *inp);

/* defined in ws2_32.dll */
__attribute__((stdcall))
int inet_pton(int af, const char *src, void *dst);

/* defined in ws2_32.dll */
__attribute__((stdcall))
const char *inet_ntop(int af, const void *src, char *dst, socklen_t size);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* _SYS_SOCKET_H_ */
