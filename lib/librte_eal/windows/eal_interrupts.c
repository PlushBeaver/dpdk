/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Mellanox Technologies, Ltd
 */

#include <rte_interrupts.h>
#include <rte_spinlock.h>
#include <rte_tailq.h>

#include <rte_eal_trace.h>

#include "eal_private.h"
#include "eal_windows.h"

TAILQ_HEAD(rte_intr_cb_list, rte_intr_callback);
TAILQ_HEAD(rte_intr_source_list, rte_intr_source);

struct rte_intr_callback {
	TAILQ_ENTRY(rte_intr_callback) next;
	rte_intr_callback_fn cb_fn;
	void *cb_arg;
	rte_intr_unregister_callback_fn ucb_fn;
	int pending_delete;
};

struct rte_intr_source {
	TAILQ_ENTRY(rte_intr_source) next;
	struct rte_intr_handle intr_handle;
	struct rte_intr_cb_list callbacks;

	/* A handle can be added to IOCP only once. If we use device handle
	 * directly, remove the source, and then add it again, associating
	 * the handle with IOCP will fail. So we use a duplicated handle,
	 * which is closed when interrupt source is removed.
	 */
	HANDLE handle;
	OVERLAPPED overlapped;
	volatile int active;
};

static struct rte_intr_source_list intr_sources;

static rte_spinlock_t intr_lock = RTE_SPINLOCK_INITIALIZER;

static pthread_t intr_thread;

static HANDLE intr_iocp;

static bool
intr_handle_valid(const struct rte_intr_handle *ih)
{
	return (ih != NULL) &&
		(ih->handle != 0 && ih->handle != INVALID_HANDLE_VALUE);
}

static bool
intr_source_matches(const struct rte_intr_source *src,
		const struct rte_intr_handle *ih)
{
	return src->intr_handle.handle == ih->handle;
}

static int
intr_source_init(struct rte_intr_source *src, const struct rte_intr_handle *ih)
{
	HANDLE handle, process;

	process = GetCurrentProcess();
	if (!DuplicateHandle(process, ih->handle, process, &handle,
			0, FALSE, DUPLICATE_SAME_ACCESS)) {
		RTE_LOG_WIN32_ERR("DuplicateHandle(%p)", ih->handle);
		return -EINVAL;
	}

	src->intr_handle = *ih;
	src->handle = handle;
	TAILQ_INIT(&src->callbacks);
	return 0;
}

static int
intr_source_cancel(struct rte_intr_source *src)
{
	DWORD bytes_transferred;

	if (!CancelIoEx(src->handle, &src->overlapped)) {
		RTE_LOG_WIN32_ERR("CancelIoEx(handle=%p)", src->handle);
		return -1;
	}
		
	if (!GetOverlappedResult(src->handle, &src->overlapped,
			&bytes_transferred, TRUE)) {
		RTE_LOG_WIN32_ERR("GetOverlappedResult(handle=%p)",
			src->handle);
		return -1;
	}

	return 0;
}

static int
intr_source_close(struct rte_intr_source *src)
{
	if (!CloseHandle(src->handle)) {
		RTE_LOG_WIN32_ERR("CloseHandle(%p)", src->handle);
		return -1;
	}
	return 0;
}

static void
intr_source_free(struct rte_intr_source *src)
{
	if (src->handle != NULL) {
		if (intr_source_cancel(src) < 0)
			RTE_LOG(ERR, EAL, "Cannot cancel interrupt request\n");

		if (intr_source_close(src) < 0)
			RTE_LOG(ERR, EAL, "Cannot close interrupt source handle\n");
	}

	free(src);
}

static bool
intr_callback_matches(const struct rte_intr_callback *cb,
		rte_intr_callback_fn cb_fn, void *cb_arg)
{
	bool any_arg = cb_arg == (void *)(-1);
	return (cb->cb_fn == cb_fn) && (any_arg || cb->cb_arg == cb_arg);
}

int
rte_intr_callback_register(const struct rte_intr_handle *ih,
	rte_intr_callback_fn cb_fn, void *cb_arg)
{
	struct rte_intr_source *src;
	bool new_src = false;
	struct rte_intr_callback *cb;
	int ret;

	if (!intr_handle_valid(ih) || cb_fn == NULL)
		return -EINVAL;

	rte_spinlock_lock(&intr_lock);

	TAILQ_FOREACH(src, &intr_sources, next)
		if (intr_source_matches(src, ih))
			break;

	cb = calloc(1, sizeof(*cb));
	if (cb == NULL) {
		RTE_LOG(ERR, EAL, "Cannot allocate interrupt callback\n");
		ret = -ENOMEM;
		goto fail;
	}

	if (src == NULL) {
		new_src = true;

		src = calloc(1, sizeof(*src));
		if (src == NULL) {
			RTE_LOG(ERR, EAL, "Cannot allocate interrupt source\n");
			ret = -ENOMEM;
			goto fail;
		}

		ret = intr_source_init(src, ih);
		if (ret < 0) {
			RTE_LOG(ERR, EAL, "Cannot initialize interrupt source\n");
			goto fail;
		}

		TAILQ_INSERT_TAIL(&intr_sources, src, next);
	}

	cb->cb_fn = cb_fn;
	cb->cb_arg = cb_arg;
	TAILQ_INSERT_TAIL(&src->callbacks, cb, next);

	ret = 0;
	goto exit;

fail:
	if (new_src && src != NULL)
		/* Never blocks, because only happens when handle duplication
		 * has failed, so the only resource to free is memory.
		 */
		intr_source_free(src);
	if (cb != NULL)
		free(cb);

exit:
	rte_spinlock_unlock(&intr_lock);
	rte_eal_trace_intr_callback_register(ih, cb_fn, cb_arg, ret);
	return ret;
}

int
rte_intr_callback_unregister(const struct rte_intr_handle *ih,
	rte_intr_callback_fn cb_fn, void *cb_arg)
{
	struct rte_intr_source *src;
	struct rte_intr_callback *cb;
	bool free_src = false;
	int ret;

	if (!intr_handle_valid(ih))
		return -EINVAL;

	rte_spinlock_lock(&intr_lock);

	TAILQ_FOREACH(src, &intr_sources, next)
		if (intr_source_matches(src, ih))
			break;

	if (src == NULL) {
		ret = -ENOENT;
		goto exit;
	}

	if (src->active != 0) {
		ret = -EAGAIN;
		goto exit;
	}

	ret = 0;
	TAILQ_FOREACH(cb, &src->callbacks, next)
		if (intr_callback_matches(cb, cb_fn, cb_arg)) {
			TAILQ_REMOVE(&src->callbacks, cb, next);
			free(cb);
			ret++;
		}

	if (TAILQ_EMPTY(&src->callbacks)) {
		TAILQ_REMOVE(&intr_sources, src, next);

		/* Resource release may block and at least does syscalls,
		 * postpone it until after the spinlock is released.
		 */
		free_src = true;
	}

exit:
	rte_spinlock_unlock(&intr_lock);

	if (free_src)
		intr_source_free(src);

	rte_eal_trace_intr_callback_unregister(ih, cb_fn, cb_arg, ret);
	return ret;
}

int
rte_intr_callback_unregister_pending(const struct rte_intr_handle *ih,
	rte_intr_callback_fn cb_fn, void *cb_arg,
	rte_intr_unregister_callback_fn ucb_fn)
{
	struct rte_intr_source *src;
	struct rte_intr_callback *cb;
	int ret;

	if (!intr_handle_valid(ih))
		return -EINVAL;

	rte_spinlock_lock(&intr_lock);

	TAILQ_FOREACH(src, &intr_sources, next)
		if (intr_source_matches(src, ih))
			break;

	if (src == NULL) {
		ret = -ENOENT;
		goto exit;
	}

	if (src->active == 0) {
		ret = -EAGAIN;
		goto exit;
	}

	ret = 0;
	TAILQ_FOREACH(cb, &src->callbacks, next)
		if (intr_callback_matches(cb, cb_fn, cb_arg)) {
			cb->pending_delete = 1;
			cb->ucb_fn = ucb_fn;
			ret++;
		}

exit:
	rte_spinlock_unlock(&intr_lock);
	return ret;
}

static int
eal_intr_source_control(const struct rte_intr_handle *ih __rte_unused,
	DWORD state __rte_unused)
{
	return -ENOTSUP;
}

int
rte_intr_enable(const struct rte_intr_handle *ih)
{
	int ret = eal_intr_source_control(ih, 1);
	rte_eal_trace_intr_enable(ih, ret);
	return ret;
}

int
rte_intr_disable(const struct rte_intr_handle *ih)
{
	int ret = eal_intr_source_control(ih, 0);
	rte_eal_trace_intr_disable(ih, ret);
	return ret;
}

int
rte_intr_ack(const struct rte_intr_handle *ih __rte_unused)
{
	return -ENOTSUP;
}

static void
eal_intr_process(const OVERLAPPED_ENTRY *entry)
{
	struct rte_intr_source *src;
	struct rte_intr_callback *cb;
	struct rte_intr_callback active_cb;
	bool free_src = false;

	/* It's not thread-safe to obtain "src" using container_of(),
	 * because intr_source_free() is done without holding the lock.
	 */
	rte_spinlock_lock(&intr_lock);
	TAILQ_FOREACH(src, &intr_sources, next)
		if (&src->overlapped == entry->lpOverlapped)
			break;
	if (src == NULL) {
		rte_spinlock_unlock(&intr_lock);
		return;
	}

	src->active = 1;

	TAILQ_FOREACH(cb, &src->callbacks, next) {
		/* Copy handler to call it without holding the lock. */
		active_cb = *cb;
		rte_spinlock_unlock(&intr_lock);

		active_cb.cb_fn(active_cb.cb_arg);

		rte_spinlock_lock(&intr_lock);
	}

	src->active = 0;

	TAILQ_FOREACH(cb, &src->callbacks, next) {
		if (!cb->pending_delete)
			continue;

		TAILQ_REMOVE(&src->callbacks, cb, next);
		if (cb->ucb_fn != NULL)
			cb->ucb_fn(&src->intr_handle, cb->cb_arg);
		free(cb);
	}

	if (TAILQ_EMPTY(&src->callbacks)) {
		TAILQ_REMOVE(&intr_sources, src, next);

		/* Avoid syscalls while holding the lock. */
		free_src = true;
	}

	rte_spinlock_unlock(&intr_lock);

	if (free_src)
		intr_source_free(src);
}

static void *
eal_intr_thread_main(LPVOID arg __rte_unused)
{
	while (1) {
		OVERLAPPED_ENTRY entries[16];
		ULONG entry_count, i;
		BOOL result;

		result = GetQueuedCompletionStatusEx(
			intr_iocp, entries, RTE_DIM(entries), &entry_count,
			INFINITE, /* no timeout */
			TRUE);    /* alertable wait for alarm APCs */

		if (!result) {
			DWORD error = GetLastError();
			if (error != WAIT_IO_COMPLETION) {
				RTE_LOG_WIN32_ERR("GetQueuedCompletionStatusEx()");
				RTE_LOG(ERR, EAL, "Failed waiting for interrupts\n");
				break;
			}

			/* No I/O events, all work is done in completed APCs. */
			continue;
		}

		for (i = 0; i < entry_count; i++)
			eal_intr_process(&entries[i]);
	}

	CloseHandle(intr_iocp);
	intr_iocp = NULL;
	return NULL;
}

int
rte_eal_intr_init(void)
{
	int ret = 0;

	TAILQ_INIT(&intr_sources);

	intr_iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1);
	if (intr_iocp == NULL) {
		RTE_LOG_WIN32_ERR("CreateIoCompletionPort()");
		RTE_LOG(ERR, EAL, "Cannot create interrupt IOCP\n");
		return -1;
	}

	ret = rte_ctrl_thread_create(&intr_thread, "eal-intr-thread", NULL,
			eal_intr_thread_main, NULL);
	if (ret != 0) {
		rte_errno = -ret;
		RTE_LOG(ERR, EAL, "Cannot create interrupt thread\n");
	}

	return ret;
}

int
rte_thread_is_intr(void)
{
	return pthread_equal(intr_thread, pthread_self());
}

int
rte_intr_rx_ctl(__rte_unused struct rte_intr_handle *intr_handle,
		__rte_unused int epfd, __rte_unused int op,
		__rte_unused unsigned int vec, __rte_unused void *data)
{
	return -ENOTSUP;
}

int
eal_intr_thread_schedule(void (*func)(void *arg), void *arg)
{
	HANDLE handle;

	handle = OpenThread(THREAD_ALL_ACCESS, FALSE, intr_thread);
	if (handle == NULL) {
		RTE_LOG_WIN32_ERR("OpenThread(%llu)", intr_thread);
		return -ENOENT;
	}

	if (!QueueUserAPC((PAPCFUNC)(ULONG_PTR)func, handle, (ULONG_PTR)arg)) {
		RTE_LOG_WIN32_ERR("QueueUserAPC()");
		return -EINVAL;
	}

	return 0;
}
