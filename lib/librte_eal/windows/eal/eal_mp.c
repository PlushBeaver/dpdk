/* SPDX-License-Identifier: BSD-3-Clause */

/**
 * @file Multiprocess support stubs
 * 
 * Stubs must log an error until implemented. If success is required
 * for non-multiprocess operation, stub must log a warning and a comment
 * must document what requires success emulation.
 */

#include <rte_eal.h>
#include <rte_errno.h>

#include "eal_private.h"
#include "eal_windows.h"
#include "malloc_mp.h"

void
rte_mp_channel_cleanup(void)
{
    EAL_NOT_IMPLEMENTED();
}

int
rte_mp_action_register(const char *name, rte_mp_t action)
{
    RTE_SET_USED(name);
    RTE_SET_USED(action);
    EAL_NOT_IMPLEMENTED();
    return -1;
}

void
rte_mp_action_unregister(const char *name)
{
    RTE_SET_USED(name);
    EAL_NOT_IMPLEMENTED();
}

int
rte_mp_sendmsg(struct rte_mp_msg *msg)
{
    RTE_SET_USED(msg);
    EAL_NOT_IMPLEMENTED();
    return -1;
}

int
rte_mp_request_sync(struct rte_mp_msg *req, struct rte_mp_reply *reply,
        const struct timespec *ts)
{
    RTE_SET_USED(req);
    RTE_SET_USED(reply);
    RTE_SET_USED(ts);
    EAL_NOT_IMPLEMENTED();
    return -1;
}

int
rte_mp_request_async(struct rte_mp_msg *req, const struct timespec *ts,
		rte_mp_async_reply_t clb)
{
    RTE_SET_USED(req);
    RTE_SET_USED(ts);
    RTE_SET_USED(clb);
    EAL_NOT_IMPLEMENTED();
    return -1;
}

int
rte_mp_reply(struct rte_mp_msg *msg, const char *peer)
{
    RTE_SET_USED(msg);
    RTE_SET_USED(peer);
    EAL_NOT_IMPLEMENTED();
    return -1;
}
