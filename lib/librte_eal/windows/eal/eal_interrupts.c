#include <io.h>

#include <rte_interrupts.h>
#include <rte_log.h>

#include "eal_private.h"
#include "eal_windows.h"

int
rte_intr_callback_register(const struct rte_intr_handle *intr_handle,
			rte_intr_callback_fn cb, void *cb_arg)
{
	/* Success required for PMD initialization. */
	RTE_SET_USED(intr_handle);
	RTE_SET_USED(cb);
	RTE_SET_USED(cb_arg);
	EAL_STUB();
	return 0;
}

int
rte_intr_callback_unregister(const struct rte_intr_handle *intr_handle,
			rte_intr_callback_fn cb, void *cb_arg)
{
	RTE_SET_USED(intr_handle);
	RTE_SET_USED(cb);
	RTE_SET_USED(cb_arg);
	EAL_NOT_IMPLEMENTED();
	return -1;
}

int
rte_intr_enable(const struct rte_intr_handle *intr_handle __rte_unused)
{
	/* Success required for PMD initialization. */
	RTE_SET_USED(intr_handle);
	EAL_STUB();
	return 0;
}

int
rte_intr_disable(const struct rte_intr_handle *intr_handle __rte_unused)
{
	/* Success required for PMD initialization. */
	RTE_SET_USED(intr_handle);
	EAL_STUB();
	return 0;
}

int
rte_intr_rx_ctl(struct rte_intr_handle *intr_handle, rte_fd epfd, int op,
		unsigned int vec, void *data)
{
	/* Success required for PMD initialization. */
	RTE_SET_USED(intr_handle);
	RTE_SET_USED(epfd);
	RTE_SET_USED(op);
	RTE_SET_USED(vec);
	RTE_SET_USED(data);
	EAL_NOT_IMPLEMENTED();
	return 0;
}

int
rte_intr_ack(const struct rte_intr_handle *intr_handle)
{
	RTE_SET_USED(intr_handle);
	EAL_NOT_IMPLEMENTED();
	return -1;
}

int
rte_intr_efd_enable(struct rte_intr_handle *intr_handle, uint32_t nb_efd)
{
	/* Success required for PMD initialization. */
	RTE_SET_USED(intr_handle);
	RTE_SET_USED(nb_efd);
	EAL_STUB();
	return 0;
}

void
rte_intr_efd_disable(struct rte_intr_handle *intr_handle)
{
	RTE_SET_USED(intr_handle);
	EAL_NOT_IMPLEMENTED();
}

int
rte_intr_dp_is_en(struct rte_intr_handle *intr_handle)
{
	RTE_SET_USED(intr_handle);
	EAL_NOT_IMPLEMENTED();
	return -1;
}

int
rte_intr_allow_others(struct rte_intr_handle *intr_handle)
{
	RTE_SET_USED(intr_handle);
	EAL_NOT_IMPLEMENTED();
	return -1;
}

int
rte_intr_cap_multiple(struct rte_intr_handle *intr_handle)
{
	/* Success required for PMD initialization, advertize no support. */
	RTE_SET_USED(intr_handle);
	EAL_STUB();
	return 0;
}

int
rte_eal_intr_init(void)
{
	/* Success required for EAL initialization. */
	EAL_STUB();
	return 0;
}
