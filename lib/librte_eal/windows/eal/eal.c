/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Intel Corporation
 */

#include <sys/stat.h>
#include <io.h>
#include <fcntl.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <eal_memcfg.h>
#include <rte_errno.h>
#include <rte_lcore.h>
#include <eal_thread.h>
#include <eal_internal_cfg.h>
#include <eal_filesystem.h>
#include <eal_options.h>
#include <eal_private.h>

#include "eal_hugepages.h"
#include "eal_windows.h"

#define MEMSIZE_IF_NO_HUGE_PAGE (64ULL * 1024ULL * 1024ULL)

 /* Allow the application to print its usage message too if set */
static rte_usage_hook_t	rte_application_usage_hook;

/* define fd variable here, because file needs to be kept open for the
 * duration of the program, as we hold a write lock on it in the primary proc
 */
static int mem_cfg_fd = -1;

/* early configuration structure, when memory config is not mmapped */
static struct rte_mem_config early_mem_config;

/* Address of global and public configuration */
static struct rte_config rte_config = {
		.mem_config = &early_mem_config,
};

/* internal configuration (per-core) */
struct lcore_config lcore_config[RTE_MAX_LCORE];

/* internal configuration */
struct internal_config internal_config;

/* platform-specific runtime dir */
static char runtime_dir[PATH_MAX];

const char *
rte_eal_get_runtime_dir(void)
{
	return runtime_dir;
}

/* Return a pointer to the configuration structure */
struct rte_config *
rte_eal_get_configuration(void)
{
	return &rte_config;
}

/* Detect if we are a primary or a secondary process */
enum rte_proc_type_t
eal_proc_type_detect(void)
{
	enum rte_proc_type_t ptype = RTE_PROC_PRIMARY;
	const char *pathname = eal_runtime_config_path();

	/* if we can open the file but not get a write-lock we are a secondary
	 * process. NOTE: if we get a file handle back, we keep that open
	 * and don't close it to prevent a race condition between multiple opens
	 */
	errno_t err = _sopen_s(&mem_cfg_fd, pathname,
		_O_RDWR, _SH_DENYNO, _S_IREAD | _S_IWRITE);
	if (err == 0) {
		OVERLAPPED soverlapped = { 0 };
		soverlapped.Offset = sizeof(*rte_config.mem_config);
		soverlapped.OffsetHigh = 0;

		HANDLE hwinfilehandle = (HANDLE)_get_osfhandle(mem_cfg_fd);

		if (!LockFileEx(hwinfilehandle,
			LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0,
			sizeof(*rte_config.mem_config), 0, &soverlapped))
			ptype = RTE_PROC_SECONDARY;
	}

	RTE_LOG(INFO, EAL, "Auto-detected process type: %s\n",
		ptype == RTE_PROC_PRIMARY ? "PRIMARY" : "SECONDARY");

	return ptype;
}

enum rte_proc_type_t
rte_eal_process_type(void)
{
	return rte_config.process_type;
}

int
rte_eal_has_hugepages(void)
{
	return !internal_config.no_hugetlbfs;
}

enum rte_iova_mode
rte_eal_iova_mode(void)
{
	return rte_config.iova_mode;
}

/* display usage */
static void
eal_usage(const char *prgname)
{
	printf("\nUsage: %s ", prgname);
	eal_common_usage();
	/* Allow the application to print its usage message too
	 * if hook is set
	 */
	if (rte_application_usage_hook) {
		printf("===== Application Usage =====\n\n");
		rte_application_usage_hook(prgname);
	}
}

/* Parse the arguments for --log-level only */
static void
eal_log_level_parse(int argc, char **argv)
{
	int opt;
	char **argvopt;
	int option_index;

	argvopt = argv;

	eal_reset_internal_config(&internal_config);

	while ((opt = getopt_long(argc, argvopt, eal_short_options,
		eal_long_options, &option_index)) != EOF) {

		int ret;

		/* getopt is not happy, stop right now */
		if (opt == '?')
			break;

		ret = (opt == OPT_LOG_LEVEL_NUM) ?
			eal_parse_common_option(opt, optarg,
				&internal_config) : 0;

		/* common parser is not happy */
		if (ret < 0)
			break;
	}

	optind = 0; /* reset getopt lib */
}

/* Parse the argument given in the command line of the application */
__attribute__((optnone)) static int
eal_parse_args(int argc, char **argv)
{
	int opt, ret;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, eal_short_options,
		eal_long_options, &option_index)) != EOF) {

		int ret;

		/* getopt is not happy, stop right now */
		if (opt == '?') {
			eal_usage(prgname);
			return -1;
		}

		ret = eal_parse_common_option(opt, optarg, &internal_config);
		/* common parser is not happy */
		if (ret < 0) {
			eal_usage(prgname);
			return -1;
		}
		/* common parser handled this option */
		if (ret == 0)
			continue;

		switch (opt) {
		case 'h':
			eal_usage(prgname);
			exit(EXIT_SUCCESS);
		default:
			if (opt < OPT_LONG_MIN_NUM && isprint(opt)) {
				RTE_LOG(ERR, EAL, "Option %c is not supported "
					"on Windows\n", opt);
			} else if (opt >= OPT_LONG_MIN_NUM &&
				opt < OPT_LONG_MAX_NUM) {
				RTE_LOG(ERR, EAL, "Option %s is not supported "
					"on Windows\n",
					eal_long_options[option_index].name);
			} else {
				RTE_LOG(ERR, EAL, "Option %d is not supported "
					"on Windows\n", opt);
			}
			eal_usage(prgname);
			return -1;
		}
	}

	if (eal_adjust_config(&internal_config) != 0)
		return -1;

	/* sanity checks */
	if (eal_check_common_options(&internal_config) != 0) {
		eal_usage(prgname);
		return -1;
	}

	if (optind >= 0)
		argv[optind - 1] = prgname;
	ret = optind - 1;
	optind = 0; /* reset getopt lib */
	return ret;
}

static int
sync_func(void *arg __rte_unused)
{
	return 0;
}

static void
rte_eal_init_alert(const char *msg)
{
	fprintf(stderr, "EAL: FATAL: %s\n", msg);
	RTE_LOG(ERR, EAL, "%s\n", msg);
}

int
eal_file_truncate(int fd, ssize_t size)
{
	HANDLE handle;
	DWORD ret;
	LONG low = (LONG)((size_t)size);
	LONG high = (LONG)((size_t)size >> 32);

	handle = (HANDLE)_get_osfhandle(fd);
	if (handle == INVALID_HANDLE_VALUE) {
		rte_errno = EBADF;
		return -1;
	}

	ret = SetFilePointer(handle, low, &high, FILE_BEGIN);
	if (ret == INVALID_SET_FILE_POINTER) {
		RTE_LOG_WIN32_ERR("SetFilePointer()");
		rte_errno = EINVAL;
		return -1;
	}

	return 0;
}

static int
lock_file(HANDLE handle, enum rte_flock_op op, enum rte_flock_mode mode)
{
	DWORD sys_flags = 0;
	OVERLAPPED overlapped;

	if (op == RTE_FLOCK_EXCLUSIVE)
		sys_flags |= LOCKFILE_EXCLUSIVE_LOCK;
	if (mode == RTE_FLOCK_RETURN)
		sys_flags |= LOCKFILE_FAIL_IMMEDIATELY;

	memset(&overlapped, 0, sizeof(overlapped));
	if (!LockFileEx(handle, sys_flags, 0, 0, 0, &overlapped)) {
		if ((sys_flags & LOCKFILE_FAIL_IMMEDIATELY) &&
			(GetLastError() == ERROR_IO_PENDING)) {
			rte_errno = EWOULDBLOCK;
		} else {
			RTE_LOG_WIN32_ERR("LockFileEx()");
			rte_errno = EINVAL;
		}
		return -1;
	}

	return 0;
}

static int
unlock_file(HANDLE handle)
{
	if (!UnlockFileEx(handle, 0, 0, 0, NULL)) {
		RTE_LOG_WIN32_ERR("UnlockFileEx()");
		rte_errno = EINVAL;
		return -1;
	}
	return 0;
}

int
eal_file_lock(int fd, enum rte_flock_op op, enum rte_flock_mode mode)
{
	HANDLE handle = (HANDLE)_get_osfhandle(fd);

	if (handle == INVALID_HANDLE_VALUE) {
		rte_errno = EBADF;
		return -1;
	}

	switch (op) {
	case RTE_FLOCK_EXCLUSIVE:
	case RTE_FLOCK_SHARED:
		return lock_file(handle, op, mode);
	case RTE_FLOCK_UNLOCK:
		return unlock_file(handle);
	default:
		rte_errno = EINVAL;
		return -1;
	}
}

 /* Launch threads, called at application init(). */
int
rte_eal_init(int argc, char **argv)
{
	int i, fctret;

	eal_log_level_parse(argc, argv);

	/* create a map of all processors in the system */
	eal_create_cpu_map();

	if (rte_eal_cpu_init() < 0) {
		rte_eal_init_alert("Cannot detect lcores.");
		rte_errno = ENOTSUP;
		return -1;
	}

	fctret = eal_parse_args(argc, argv);
	if (fctret < 0)
		exit(1);

	if (!internal_config.no_hugetlbfs && (eal_hugepage_info_init() < 0)) {
		rte_eal_init_alert("Cannot get hugepage information.");
		rte_errno = EACCES;
		return -1;
	}

	if (internal_config.memory == 0 && !internal_config.force_sockets) {
		if (internal_config.no_hugetlbfs)
			internal_config.memory = MEMSIZE_IF_NO_HUGE_PAGE;
	}

	if (rte_eal_memzone_init() < 0) {
		rte_eal_init_alert("Cannot init memzone");
		rte_errno = ENODEV;
		return -1;
	}

	if (rte_eal_memory_init() < 0) {
		rte_eal_init_alert("Cannot init memory");
		rte_errno = ENOMEM;
		return -1;
	}

	if (rte_eal_malloc_heap_init() < 0) {
		rte_eal_init_alert("Cannot init malloc heap");
		rte_errno = ENODEV;
		return -1;
	}

	if (rte_eal_tailqs_init() < 0) {
		rte_eal_init_alert("Cannot init tail queues for objects");
		rte_errno = EFAULT;
		return -1;
	}

	eal_thread_init_master(rte_config.master_lcore);

	RTE_LCORE_FOREACH_SLAVE(i) {

		/*
		 * create communication pipes between master thread
		 * and children
		 */
		if (_pipe(lcore_config[i].pipe_master2slave,
			sizeof(char), _O_BINARY) < 0)
			rte_panic("Cannot create pipe\n");
		if (_pipe(lcore_config[i].pipe_slave2master,
			sizeof(char), _O_BINARY) < 0)
			rte_panic("Cannot create pipe\n");

		lcore_config[i].state = WAIT;

		/* create a thread for each lcore */
		if (eal_thread_create(&lcore_config[i].thread_id) != 0)
			rte_panic("Cannot create thread\n");
	}

	/*
	 * Launch a dummy function on all slave lcores, so that master lcore
	 * knows they are all ready when this function returns.
	 */
	rte_eal_mp_remote_launch(sync_func, NULL, SKIP_MASTER);
	rte_eal_mp_wait_lcore();
	return fctret;
}
