/* SPDX-License-Identifier: BSD-3-Clause */

/**
 * @file Multiprocess support stubs
 * 
 * Stubs must log an error until implemented. If success is required
 * for non-multiprocess operation, stub must log a warning and a comment
 * must document what requires success emulation.
 */

#include <rte_eal.h>

#include "eal_private.h"
#include "malloc_mp.h"

void
rte_mp_channel_cleanup(void)
{
    RTE_LOG(ERR, EAL, "Windows: %s() not implemented\n", __func__);
}

int
rte_mp_action_register(const char *name, rte_mp_t action)
{
    /* Success required for vdev bus scan. */
    RTE_SET_USED(name);
    RTE_SET_USED(action);
    RTE_LOG(WARNING, EAL, "Windows: %s() stub called\n", __func__);
    return 0;
}

void
rte_mp_action_unregister(const char *name)
{
    RTE_SET_USED(name);
    RTE_LOG(ERR, EAL, "Windows: %s() not implemented\n", __func__);
}

int
rte_mp_sendmsg(struct rte_mp_msg *msg)
{
    RTE_SET_USED(msg);
    RTE_LOG(ERR, EAL, "Windows: %s() not implemented\n", __func__);
    return -ENOTSUP;
}

int
rte_mp_request_sync(struct rte_mp_msg *req, struct rte_mp_reply *reply,
        const struct timespec *ts)
{
    RTE_SET_USED(req);
    RTE_SET_USED(reply);
    RTE_SET_USED(ts);
    RTE_LOG(ERR, EAL, "Windows: %s() not implemented\n", __func__);
    return -ENOTSUP;
}

int
rte_mp_request_async(struct rte_mp_msg *req, const struct timespec *ts,
		rte_mp_async_reply_t clb)
{
    RTE_SET_USED(req);
    RTE_SET_USED(ts);
    RTE_SET_USED(clb);
    RTE_LOG(ERR, EAL, "Windows: %s() not implemented\n", __func__);
    return -ENOTSUP;
}

int
rte_mp_reply(struct rte_mp_msg *msg, const char *peer)
{
    RTE_SET_USED(msg);
    RTE_SET_USED(peer);
    RTE_LOG(ERR, EAL, "Windows: %s() not implemented\n", __func__);
    return -ENOTSUP;
}

int
register_mp_requests(void)
{
    /* Success required for memory manager initialization. */
    RTE_LOG(WARNING, EAL, "Windows: %s() stub called\n", __func__);
    return 0;
}

int
request_to_primary(struct malloc_mp_req *req)
{
    RTE_SET_USED(req);
    RTE_LOG(ERR, EAL, "Windows: %s() not implemented\n", __func__);
    return -ENOTSUP;
}

int
request_sync(void)
{
    /* Success required for memory manager operation. */
    RTE_LOG(WARNING, EAL, "Windows: %s() stub called\n", __func__);
    return 0;
}
