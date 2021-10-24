/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Mellanox Technologies, Ltd
 */

#include <rte_interrupts.h>
#include <rte_spinlock.h>
#include <rte_tailq.h>

#include <rte_eal_trace.h>

#include "eal_private.h"
#include "eal_windows.h"

#include <winioctl.h>

#define IOCP_KEY_SHUTDOWN UINT32_MAX

struct rte_intr_callback {
	TAILQ_ENTRY(rte_intr_callback) next;
	rte_intr_callback_fn cb_fn;
	void *cb_arg;
	rte_intr_unregister_callback_fn ucb_fn;
	int pending_delete;
};

TAILQ_HEAD(rte_intr_cb_list, rte_intr_callback);

struct intr_source {
	TAILQ_ENTRY(intr_source) next;
	struct rte_intr_handle *intr_handle;
	struct rte_intr_cb_list callbacks;
	uint32_t active;

	/*
	 * A handle can be added to IOCP only once. If we use device handle
	 * directly, remove the source, and then add it again, associating
	 * the handle with IOCP will fail. So we use a duplicated handle,
	 * which is closed when interrupt source is removed.
	 */
	HANDLE handle;
	OVERLAPPED overlapped;
	/*
	 * Whether at least one request to deliver interrupts was issued.
	 */
	bool queried;
};

TAILQ_HEAD(rte_intr_source_list, intr_source);

static struct rte_intr_source_list intr_sources;

static rte_spinlock_t intr_lock = RTE_SPINLOCK_INITIALIZER;

static pthread_t intr_thread;

static HANDLE intr_iocp;
static HANDLE intr_thread_handle;
static RTE_DEFINE_PER_LCORE(HANDLE, local_iocp);

static bool
intr_callback_matches(const struct rte_intr_callback *cb,
		rte_intr_callback_fn cb_fn, void *cb_arg)
{
	bool any_arg = cb_arg == (void *)(-1);
	return cb->cb_fn == cb_fn && (any_arg || cb->cb_arg == cb_arg);
}

static bool
intr_handle_valid(const struct rte_intr_handle *intr_handle)
{
	return intr_handle != NULL &&
			intr_handle->handle != NULL &&
			intr_handle->handle != INVALID_HANDLE_VALUE;
}

/* Copy the device handle with overlapped mode added. */
static int
eal_intr_dup_handle(const struct rte_intr_handle *intr_handle, HANDLE *handle)
{
	*handle = ReOpenFile(intr_handle->handle, GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			FILE_FLAG_OVERLAPPED);
	if (*handle == INVALID_HANDLE_VALUE) {
		RTE_LOG_WIN32_ERR("ReOpenFile(handle=%p, flags|=OVERLAPPED)",
				intr_handle->handle);
		rte_errno = EINVAL;
		return -1;
	}
	return 0;
}

static int
intr_source_init(struct intr_source *src,
		const struct rte_intr_handle *intr_handle)
{
	HANDLE handle;
	int ret;

	ret = eal_intr_dup_handle(intr_handle, &handle);
	if (ret < 0)
		return ret;
	/* Attach the new handle to the common IOCP. */
	if (CreateIoCompletionPort(handle, intr_iocp, 0, 0) ==
			INVALID_HANDLE_VALUE) {
		RTE_LOG_WIN32_ERR("CreateIoCompletionPort(add %p)", handle);
		CloseHandle(handle);
		rte_errno = EINVAL;
		return -1;
	}

	/* TODO: the cast will not be needed after rebase. */
	src->intr_handle = (struct rte_intr_handle *)(uintptr_t)intr_handle;
	src->handle = handle;
	TAILQ_INIT(&src->callbacks);
	return 0;
}

static int
eal_intr_cancel(HANDLE handle, OVERLAPPED *overlapped)
{
	DWORD bytes_transferred;
	BOOL ret;

	ret = CancelIoEx(handle, overlapped);
	if (!ret && GetLastError() != ERROR_NOT_FOUND) {
		RTE_LOG_WIN32_ERR("CancelIoEx(handle=%p)", handle);
		return -1;
	}
	ret = GetOverlappedResult(handle, overlapped,
			&bytes_transferred, TRUE);
	if (!ret && GetLastError() != ERROR_OPERATION_ABORTED) {
		RTE_LOG_WIN32_ERR("GetOverlappedResult(handle=%p)", handle);
		return -1;
	}
	return 0;
}

static int
intr_source_cancel(struct intr_source *src)
{
	return eal_intr_cancel(src->handle, &src->overlapped);
}

static int
intr_source_close(struct intr_source *src)
{
	if (!CloseHandle(src->handle)) {
		RTE_LOG_WIN32_ERR("CloseHandle(%p)", src->handle);
		return -1;
	}
	return 0;
}

static void
intr_source_free(struct intr_source *src)
{
	if (src->handle != NULL) {
		if (intr_source_cancel(src) < 0)
			RTE_LOG(ERR, EAL, "Cannot cancel interrupt request\n");

		if (intr_source_close(src) < 0)
			RTE_LOG(ERR, EAL, "Cannot close interrupt source handle\n");
	}
	free(src);
}

static struct intr_source *
intr_source_lookup(const struct rte_intr_handle *intr_handle)
{
	struct intr_source *src;

	TAILQ_FOREACH(src, &intr_sources, next)
		if (src->intr_handle->handle == intr_handle->handle)
			break;
	return src;
}

int
rte_intr_callback_register(const struct rte_intr_handle *intr_handle,
	rte_intr_callback_fn cb_fn, void *cb_arg)
{
	struct intr_source *src;
	bool new_src = false;
	struct rte_intr_callback *cb = NULL;
	int ret;

	if (!intr_handle_valid(intr_handle) || cb_fn == NULL) {
		ret = -EINVAL;
		goto exit;
	}

	cb = calloc(1, sizeof(*cb));
	if (cb == NULL) {
		RTE_LOG(ERR, EAL, "Cannot allocate interrupt callback\n");
		ret = -ENOMEM;
		goto exit;
	}

	rte_spinlock_lock(&intr_lock);
	src = intr_source_lookup(intr_handle);
	if (src == NULL) {
		new_src = true;
		src = calloc(1, sizeof(*src));
		if (src == NULL) {
			RTE_LOG(ERR, EAL, "Cannot allocate interrupt source\n");
			ret = -ENOMEM;
			goto exit;
		}

		ret = intr_source_init(src, intr_handle);
		if (ret < 0) {
			RTE_LOG(ERR, EAL, "Cannot initialize interrupt source\n");
			goto exit;
		}
		TAILQ_INSERT_TAIL(&intr_sources, src, next);
	}

	cb->cb_fn = cb_fn;
	cb->cb_arg = cb_arg;
	TAILQ_INSERT_TAIL(&src->callbacks, cb, next);
	ret = 0;

exit:
	rte_spinlock_unlock(&intr_lock);
	if (ret < 0) {
		if (new_src && src != NULL)
			intr_source_free(src);
		if (cb != NULL)
			free(cb);
	}
	rte_eal_trace_intr_callback_register(intr_handle, cb_fn, cb_arg, ret);
	return ret;
}

int
rte_intr_callback_unregister(const struct rte_intr_handle *intr_handle,
		rte_intr_callback_fn cb_fn, void *cb_arg)
{
	struct intr_source *src;
	struct rte_intr_callback *cb, *tmp;
	struct rte_intr_cb_list cbs;
	bool free_src = false;
	int ret = 0;

	TAILQ_INIT(&cbs);
	if (!intr_handle_valid(intr_handle)) {
		ret = -EINVAL;
		goto exit;
	}

	rte_spinlock_lock(&intr_lock);
	src = intr_source_lookup(intr_handle);
	if (src == NULL) {
		ret = -ENOENT;
		goto unlock;
	}
	if (src->active == 1) {
		ret = -EAGAIN;
		goto unlock;
	}
	TAILQ_FOREACH(cb, &src->callbacks, next)
		if (intr_callback_matches(cb, cb_fn, cb_arg)) {
			TAILQ_REMOVE(&src->callbacks, cb, next);
			TAILQ_INSERT_HEAD(&cbs, cb, next);
			ret++;
		}
	if (TAILQ_EMPTY(&src->callbacks)) {
		TAILQ_REMOVE(&intr_sources, src, next);
		free_src = true;
	}

unlock:
	rte_spinlock_unlock(&intr_lock);
	RTE_TAILQ_FOREACH_SAFE(cb, &cbs, next, tmp)
		free(cb);
	if (free_src)
		intr_source_free(src);
exit:
	rte_eal_trace_intr_callback_unregister(intr_handle, cb_fn, cb_arg, ret);
	return ret;
}

int
rte_intr_callback_unregister_pending(const struct rte_intr_handle *intr_handle,
		rte_intr_callback_fn cb_fn, void *cb_arg,
		rte_intr_unregister_callback_fn ucb_fn)
{
	struct intr_source *src;
	struct rte_intr_callback *cb;
	int ret = 0;

	if (!intr_handle_valid(intr_handle))
		return -EINVAL;
	rte_spinlock_lock(&intr_lock);
	src = intr_source_lookup(intr_handle);
	if (src == NULL) {
		ret = -ENOENT;
		goto exit;
	}
	if (src->active == 0) {
		ret = -EAGAIN;
		goto exit;
	}
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

/** Enable or disable delivery of device interrupts. */
#define IOCTL_NETUIO_INTR_CONTROL CTL_CODE(FILE_DEVICE_NETWORK, 53, \
					   METHOD_BUFFERED, FILE_ANY_ACCESS)

struct netuio_intr_control {
	uint32_t enable;
};

static int
eal_intr_netuio_control(HANDLE handle, bool state)
{
	struct netuio_intr_control in = { .enable = state ? 1 : 0 };
	BOOL ret;

	ret = DeviceIoControl(handle, IOCTL_NETUIO_INTR_CONTROL,
			&in, sizeof(in), NULL, 0, NULL, NULL);
	if (!ret) {
		RTE_LOG_WIN32_ERR("DeviceIoControl(handle=%p, code=IOCTL_NETUIO_INTR_CONTROL, enable=%u)",
				handle, in.enable);
		return -1;
	}
	return 0;
}

/** Request delivery of an interrupt event. */
#define IOCTL_NETUIO_INTR_QUERY CTL_CODE(FILE_DEVICE_NETWORK, 54, \
					 METHOD_BUFFERED, FILE_ANY_ACCESS)

struct netuio_intr_query {
	uint32_t vector;
};

static int
eal_intr_netuio_query(HANDLE handle, uint32_t vector, OVERLAPPED *overlapped)
{
	struct netuio_intr_query in = { .vector = vector };
	BOOL ret;

	ret = DeviceIoControl(handle, IOCTL_NETUIO_INTR_QUERY,
			&in, sizeof(in), NULL, 0, NULL, overlapped);
	if (!ret && GetLastError() != ERROR_IO_PENDING) {
		RTE_LOG_WIN32_ERR("DeviceIoControl(handle=%p, code=IOCTL_NETUIO_INTR_QUERY, vector=%u)",
				handle, in.vector);
		return -1;
	}
	return 0;
}

int
rte_intr_enable(const struct rte_intr_handle *intr_handle)
{
	struct intr_source *src;
	int ret;

	rte_spinlock_lock(&intr_lock);
	src = intr_source_lookup(intr_handle);
	if (src == NULL) {
		ret = -ENOENT;
		goto exit;
	}
	ret = eal_intr_netuio_control(src->handle, true);
	if (ret == 0 && !src->queried) {
		ret = eal_intr_netuio_query(src->handle, 0, &src->overlapped);
		if (ret == 0)
			src->queried = true;
	}
exit:
	rte_spinlock_unlock(&intr_lock);
	rte_eal_trace_intr_enable(intr_handle, ret);
	return ret;
}

int
rte_intr_disable(const struct rte_intr_handle *intr_handle)
{
	struct intr_source *src;
	int ret;

	rte_spinlock_lock(&intr_lock);
	src = intr_source_lookup(intr_handle);
	if (src == NULL) {
		ret = -ENOENT;
		goto exit;
	}
	ret = eal_intr_netuio_control(src->handle, false);
exit:
	rte_spinlock_unlock(&intr_lock);
	rte_eal_trace_intr_disable(intr_handle, ret);
	return ret;
}

int
rte_intr_ack(const struct rte_intr_handle *intr_handle)
{
	struct intr_source *src;
	int ret = -ENOENT;

	/*
	 * TODO: making a syscall under a lock is bad. It is probably worth
	 * storing the handle duplicate in the interrupt handle.
	 */
	rte_spinlock_lock(&intr_lock);
	src = intr_source_lookup(intr_handle);
	if (src != NULL)
		ret = eal_intr_netuio_query(src->handle, 0, &src->overlapped);
	rte_spinlock_unlock(&intr_lock);
	return ret;
}

static void
eal_intr_process(const OVERLAPPED_ENTRY *entry)
{
	struct intr_source *src;
	struct rte_intr_callback *cb, *tmp;
	struct rte_intr_callback active_cb;
	struct rte_intr_cb_list cbs;
	bool free_src = false;

	/*
	 * It's not thread-safe to obtain "src" using container_of(),
	 * because intr_source_free() is called without holding the lock.
	 */
	rte_spinlock_lock(&intr_lock);
	TAILQ_INIT(&cbs);
	TAILQ_FOREACH(src, &intr_sources, next)
		if (&src->overlapped == entry->lpOverlapped)
			break;
	if (src == NULL) {
		rte_spinlock_unlock(&intr_lock);
		return;
	}

	src->active = 1;
	TAILQ_FOREACH(cb, &src->callbacks, next) {
		active_cb = *cb;
		rte_spinlock_unlock(&intr_lock);

		active_cb.cb_fn(active_cb.cb_arg);

		rte_spinlock_lock(&intr_lock);
	}
	src->active = 0;

	TAILQ_FOREACH(cb, &src->callbacks, next)
		if (cb->pending_delete) {
			TAILQ_REMOVE(&src->callbacks, cb, next);
			TAILQ_INSERT_HEAD(&cbs, cb, next);
			if (cb->ucb_fn != NULL)
				cb->ucb_fn(src->intr_handle, cb->cb_arg);
		}
	if (TAILQ_EMPTY(&src->callbacks)) {
		TAILQ_REMOVE(&intr_sources, src, next);
		free_src = true;
	}
	rte_spinlock_unlock(&intr_lock);

	RTE_TAILQ_FOREACH_SAFE(cb, &cbs, next, tmp)
		free(cb);
	if (free_src)
		intr_source_free(src);
}

static int
eal_intr_thread_handle_init(void)
{
	DWORD thread_id = GetCurrentThreadId();

	intr_thread_handle = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_id);
	if (intr_thread_handle == NULL) {
		RTE_LOG_WIN32_ERR("OpenThread(%lu)", thread_id);
		return -1;
	}
	return 0;
}

static void *
eal_intr_thread_main(LPVOID arg __rte_unused)
{
	bool finished = false;

	if (eal_intr_thread_handle_init() < 0) {
		RTE_LOG(ERR, EAL, "Cannot open interrupt thread handle\n");
		goto cleanup;
	}

	while (!finished) {
		OVERLAPPED_ENTRY events[16];
		ULONG event_count, i;
		BOOL result;

		result = GetQueuedCompletionStatusEx(
			intr_iocp, events, RTE_DIM(events), &event_count,
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

		for (i = 0; i < event_count; i++) {
			if (events[i].lpCompletionKey == IOCP_KEY_SHUTDOWN) {
				finished = true;
				break;
			}
			eal_intr_process(&events[i]);
		}
	}

	CloseHandle(intr_thread_handle);
	intr_thread_handle = NULL;

cleanup:
	intr_thread = 0;

	CloseHandle(intr_iocp);
	intr_iocp = NULL;

	return NULL;
}

typedef DWORD NTSTATUS;

#define STATUS_SUCCESS   0x00000000
#define STATUS_CANCELLED 0xC0000120

typedef enum {
	FileCompletionInformation = 30,
} FILE_INFORMATION_CLASS;

typedef struct _FILE_COMPLETION_INFORMATION {
	HANDLE Port;
	PVOID  Key;
} FILE_COMPLETION_INFORMATION;

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

__kernel_entry NTSYSCALLAPI
NTSTATUS
NtSetInformationFile(
	HANDLE handle,
	IO_STATUS_BLOCK *io_status_block,
	void *info,
	ULONG info_size,
	FILE_INFORMATION_CLASS info_class
);

static typeof(NtSetInformationFile) *NtSetInformationFile_ptr;

/* TODO: extract to common EAL code, reuse here and for memory manager */
static const void *
eal_find_system_function(const char *lib_name, const char *func_name)
{
	HMODULE lib;
	const void *func;

	lib = GetModuleHandle(lib_name);
	if (lib == NULL) {
		RTE_LOG_WIN32_ERR("GetModuleHandle(\"%s\")", lib_name);
		return NULL;
	}
	func = GetProcAddress(lib, func_name);
	if (func == NULL) {
		RTE_LOG_WIN32_ERR("GetProcAddress(\"%s\", \"%s\")",
				lib_name, func_name);
	}
	return func;
}

int
rte_eal_intr_init(void)
{
	int ret = 0;

	TAILQ_INIT(&intr_sources);

	NtSetInformationFile_ptr = eal_find_system_function("ntdll.dll",
			"NtSetInformationFile");
	if (NtSetInformationFile_ptr == NULL) {
		RTE_LOG(ERR, EAL, "Cannot locate API\n");
		return -1;
	}

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

static HANDLE
eal_intr_tls_iocp(void)
{
	HANDLE iocp, old, *target;

	target = &RTE_PER_LCORE(local_iocp);
	iocp = *target;
	if (iocp == NULL) {
		iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL,
			0 /* (unused) completion key */,
			1 /* number of threads for this IOCP */);
		if (iocp == NULL) {
			RTE_LOG_WIN32_ERR("CreateIoCompletionPort()");
			return NULL;
		}
		old = (HANDLE)InterlockedCompareExchange64(
				(LONG64 *)target, (LONG64)iocp, 0);
		if (old != NULL) {
			CloseHandle(iocp);
			iocp = old;
		}
	}
	return iocp;
}

static int
eal_intr_handle_change_iocp(HANDLE handle, HANDLE iocp, void *data)
{
	IO_STATUS_BLOCK iosb;
	FILE_COMPLETION_INFORMATION info;
	NTSTATUS status;

	info.Key = data;
	info.Port = iocp;
	status = NtSetInformationFile_ptr(handle, &iosb, &info, sizeof(info),
			FileCompletionInformation);
	if (status != 0) {
		RTE_LOG(DEBUG, EAL, "NtSetInformationFile(handle=%p, type=FileCompletionInformation, {Key=%p, Port=%p}) -> %#08lx\n",
				handle, data, iocp, status);
		return -1;
	}
	return 0;
}

int
rte_intr_rx_ctl(struct rte_intr_handle *intr_handle, int epfd, int op,
		unsigned int vec, void *data)
{
	HANDLE iocp, handle;
	OVERLAPPED *overlapped;
	struct rte_epoll_event *event;
	size_t index;
	int ret;

	if (intr_handle == NULL)
		return -EINVAL;
	if (vec >= intr_handle->max_intr)
		return -EINVAL;
	if (epfd != RTE_EPOLL_PER_THREAD)
		return -ENOTSUP;

	iocp = eal_intr_tls_iocp();
	if (iocp == NULL) {
		RTE_LOG(ERR, EAL, "Cannot create per-thread epoll instance\n");
		return -EINVAL;
	}

	index = (vec >= RTE_INTR_VEC_RXTX_OFFSET) ?
			(vec - RTE_INTR_VEC_RXTX_OFFSET) : vec;
	handle = intr_handle->vector_handles[index];
	switch (op) {
	case RTE_INTR_EVENT_ADD:
		ret = eal_intr_handle_change_iocp(handle, iocp, intr_handle);
		if (ret < 0) {
			RTE_LOG(ERR, EAL, "Cannot add interrupt to per-thread epoll\n");
			return -EINVAL;
		}
		event = &intr_handle->elist[index];
		event->epdata.data = data;
		overlapped = (OVERLAPPED *)intr_handle->vector_overlapped + index;
		ret = eal_intr_netuio_query(handle, vec, overlapped);
		if (ret < 0) {
			RTE_LOG(ERR, EAL, "Cannot query interrupt events\n");
			return ret;
		}
		break;
	case RTE_INTR_EVENT_DEL:
		ret = eal_intr_handle_change_iocp(handle, NULL, NULL);
		if (ret < 0) {
			RTE_LOG(ERR, EAL, "Cannot remove interrupt from per-thread epoll\n");
			return -EINVAL;
		}
		break;
	default:
		RTE_LOG(DEBUG, EAL, "Invalid interrupt RX control operation\n");
		ret = -EINVAL;
	}
	return ret;
}

int
eal_intr_thread_schedule(void (*func)(void *arg), void *arg)
{
	if (!QueueUserAPC((PAPCFUNC)(ULONG_PTR)func,
			intr_thread_handle, (ULONG_PTR)arg)) {
		RTE_LOG_WIN32_ERR("QueueUserAPC()");
		return -EINVAL;
	}

	return 0;
}

void
eal_intr_thread_cancel(void)
{
	if (!PostQueuedCompletionStatus(
			intr_iocp, 0, IOCP_KEY_SHUTDOWN, NULL)) {
		RTE_LOG_WIN32_ERR("PostQueuedCompletionStatus()");
		RTE_LOG(ERR, EAL, "Cannot cancel interrupt thread\n");
		return;
	}

	WaitForSingleObject(intr_thread_handle, INFINITE);
}

int
rte_intr_callback_unregister_sync(
	__rte_unused const struct rte_intr_handle *intr_handle,
	__rte_unused rte_intr_callback_fn cb_fn, __rte_unused void *cb_arg)
{
	/* TODO: implement */
	return 0;
}

static int
eal_netuio_efd_enable(struct rte_intr_handle *intr_handle, uint32_t n)
{
	OVERLAPPED *overlapped;
	uint32_t i, j;
	int ret;

	/* TODO: add safety */
	overlapped = calloc(n, sizeof(overlapped[0]));
	if (overlapped == NULL)
		return -ENOMEM;
	for (i = 0; i < n; i++) {
		ret = eal_intr_dup_handle(intr_handle,
				&intr_handle->vector_handles[i]);
		if (ret < 0)
			break;
	}
	if (i != n) {
		for (j = 0; j < i; j++)
			CloseHandle(intr_handle->vector_handles[i]);
		return ret;
	}
	intr_handle->vector_overlapped = overlapped;
	intr_handle->nb_efd = n;
	intr_handle->max_intr = 1 + n;
	return 0;
}

int
rte_intr_efd_enable(struct rte_intr_handle *intr_handle, uint32_t nb_efd)
{
	uint32_t n = RTE_MIN(nb_efd, (uint32_t)RTE_MAX_RXTX_INTR_VEC_ID);

	if (intr_handle->nb_efd != 0)
		return -EEXIST;
	switch (intr_handle->type) {
	case RTE_INTR_HANDLE_NETUIO:
		return eal_netuio_efd_enable(intr_handle, n);
	default:
		return 0;
	}
}

void
rte_intr_efd_disable(struct rte_intr_handle *intr_handle)
{
	uint32_t i;

	if (intr_handle->max_intr > intr_handle->nb_efd) {
		for (i = 0; i < intr_handle->nb_efd; i++)
			CloseHandle(intr_handle->vector_handles[i]);
	}
	free(intr_handle->vector_overlapped);
	intr_handle->vector_overlapped = NULL;
	intr_handle->nb_efd = 0;
	intr_handle->max_intr = 0;
}

int
rte_intr_dp_is_en(struct rte_intr_handle *intr_handle)
{
	return !(!intr_handle->nb_efd);
}

int
rte_intr_allow_others(struct rte_intr_handle *intr_handle)
{
	if (!rte_intr_dp_is_en(intr_handle))
		return 1;
	else
		return !!(intr_handle->max_intr - intr_handle->nb_efd);
}

int
rte_intr_cap_multiple(struct rte_intr_handle *intr_handle)
{
	return intr_handle->type == RTE_INTR_HANDLE_NETUIO ? 1 : 0;
}

static int
eal_epoll_wait(int epfd, struct rte_epoll_event *events,
		int maxevents, int timeout)
{
	OVERLAPPED_ENTRY entries[maxevents];
	HANDLE iocp;
	DWORD timeout_ms;
	ULONG event_count, i;
	BOOL result;

	if (epfd != RTE_EPOLL_PER_THREAD)
		return -ENOTSUP;

	iocp = eal_intr_tls_iocp();
	if (iocp == NULL) {
		RTE_LOG(ERR, EAL, "Cannot get per-thread IOCP\n");
		return -EINVAL;
	}

	timeout_ms = timeout >= 0 ? timeout * MS_PER_S : INFINITE;
	result = GetQueuedCompletionStatusEx(iocp,
			entries, maxevents, &event_count,
			timeout_ms, FALSE);
	if (!result) {
		if (GetLastError() == WAIT_TIMEOUT)
			return 0;
		RTE_LOG_WIN32_ERR("GetQueuedCompletionStatusEx()");
		RTE_LOG(ERR, EAL, "Polling for interrupts failed\n");
		return -EINVAL;
	}

	/*
	 * OVERLAPPED pointer to an array member inside rte_intr_handle.
	 * Use it to determine the vector.
	 */
	for (i = 0; i < event_count; i++) {
		HANDLE handle;
		OVERLAPPED *overlapped;
		NTSTATUS status;
		struct rte_intr_handle *intr_handle;
		size_t index;
		unsigned int vec;
		const struct rte_epoll_event *event;

		overlapped = entries[i].lpOverlapped;
		status = overlapped->Internal;
		intr_handle = (struct rte_intr_handle *)
						entries[i].lpCompletionKey;
		index = overlapped -
				(OVERLAPPED *)intr_handle->vector_overlapped;
		vec = index + RTE_INTR_VEC_RXTX_OFFSET;

		if (status != STATUS_SUCCESS) {
			if (status != STATUS_CANCELLED)
				RTE_LOG(ERR, EAL, "Interrupt request for vector %u failed with status %#lx\n",
					vec, status);
			continue;
		}

		event = &intr_handle->elist[index];
		events[i].status = RTE_EPOLL_VALID;
		events[i].epdata.data = event->epdata.data;

		switch (intr_handle->type) {
		case RTE_INTR_HANDLE_NETUIO:
			handle = intr_handle->vector_handles[index];
			if (eal_intr_netuio_query(handle, vec, overlapped) < 0)
				RTE_LOG(ERR, EAL, "Cannot request new interrupt events for vector %u\n",
					vec);
			break;
		default:
			RTE_LOG(DEBUG, EAL, "Not rearming interrupt vector %u\n",
				vec);
		}
	}
	return event_count;
}

int
rte_epoll_wait(int epfd, struct rte_epoll_event *events,
		int maxevents, int timeout)
{
	return eal_epoll_wait(epfd, events, maxevents, timeout);
}

int
rte_epoll_wait_interruptible(int epfd, struct rte_epoll_event *events,
			     int maxevents, int timeout)
{
	/* There are no interrupts, so there's nothing special to be done. */
	return eal_epoll_wait(epfd, events, maxevents, timeout);
}

int
rte_epoll_ctl(int epfd, int op, int fd, struct rte_epoll_event *event)
{
	RTE_SET_USED(epfd);
	RTE_SET_USED(op);
	RTE_SET_USED(fd);
	RTE_SET_USED(event);

	return -ENOTSUP;
}

int
rte_intr_tls_epfd(void)
{
	/*
	 * There are per-thread IOCP, but this function is meant to return
	 * an epoll descriptor that can be used with epoll_*() API,
	 * which is missing on Windows, so there's nothing to provide.
	 */
	return -ENOTSUP;
}

void
rte_intr_free_epoll_fd(struct rte_intr_handle *intr_handle)
{
	size_t i;

	if (intr_handle == NULL)
		return;
	for (i = 0; i < intr_handle->nb_efd; i++) {
		HANDLE handle = intr_handle->vector_handles[i];
		OVERLAPPED *overlapped = &((OVERLAPPED *)intr_handle->vector_overlapped)[i];

		if (handle == NULL)
			continue;
		/* Ignore possible errors: maybe no IOCP is connected. */
		eal_intr_handle_change_iocp(handle, NULL, NULL);
		if (eal_intr_cancel(handle, overlapped) < 0)
			RTE_LOG(ERR, EAL, "Cannot cancel request for interrupt vector %zu\n", i);
	}
}
