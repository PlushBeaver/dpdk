/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Intel Corporation
 */

#define _WIN32_WINNT _WIN32_WINNT_WIN10
#include <ws2tcpip.h>

#include <io.h>
#include <fcntl.h>
#include <termios.h>
#include <ntsecapi.h>

#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_filesystem.h>
#include <rte_lcore.h>
#include <rte_os.h>
#include <rte_service_component.h>

#include "eal_filesystem.h"
#include "eal_hugepages.h"
#include "eal_internal_cfg.h"
#include "eal_memcfg.h"
#include "eal_options.h"
#include "eal_private.h"
#include "eal_thread.h"
#include "eal_windows.h"

/* early configuration structure, when memory config is not mmapped */
static struct rte_mem_config early_mem_config;

/* define fd variable here, because file needs to be kept open for the
 * duration of the program, as we hold a write lock on it in the primary proc */
static int mem_cfg_fd = -1;

/* Address of global and public configuration */
static struct rte_config rte_config = {
	.mem_config = &early_mem_config,
};

/* internal configuration */
struct internal_config internal_config = {0};

/* internal configuration (per-core) */
struct lcore_config lcore_config[RTE_MAX_LCORE] = {0};

/* Allow the application to print its usage message too if set */
static rte_usage_hook_t	rte_application_usage_hook = NULL;

/* used by rte_rdtsc() */
int rte_cycles_vmware_tsc_map;

/* Return a pointer to the configuration structure */
struct rte_config *
rte_eal_get_configuration(void)
{
	return &rte_config;
}

/* Return user provided mbuf pool ops name */
const char *
rte_eal_mbuf_user_pool_ops(void)
{
	return internal_config.user_mbuf_pool_ops_name;
}

const char *
rte_eal_get_runtime_dir(void)
{
	/* TODO */
	return "%TEMP%";
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

/* create memory configuration in shared/mmap memory. Take out
 * a write lock on the memsegs, so we can auto-detect primary/secondary.
 * This means we never close the file while running (auto-close on exit).
 * We also don't lock the whole file, so that in future we can use read-locks
 * on other parts, e.g. memzones, to detect if there are running secondary
 * processes. */
static int
rte_eal_config_create(void)
{
	size_t page_sz = rte_get_page_size();
	size_t cfg_len = sizeof(*rte_config.mem_config);
	size_t cfg_len_aligned = RTE_ALIGN(cfg_len, page_sz);
	void *rte_mem_cfg_addr, *mapped_mem_cfg_addr;
	int retval;

	const char *pathname = eal_runtime_config_path();

	if (internal_config.no_shconf)
		return 0;

	/* map the config before hugepage address so that we don't waste a page */
	if (internal_config.base_virtaddr != 0)
		rte_mem_cfg_addr = (void *)
			RTE_ALIGN_FLOOR(internal_config.base_virtaddr -
			sizeof(struct rte_mem_config), page_sz);
	else
		rte_mem_cfg_addr = NULL;

	if (mem_cfg_fd < 0){
		mem_cfg_fd = open(pathname, O_RDWR | O_CREAT, 0600);
		if (mem_cfg_fd < 0) {
			RTE_LOG(ERR, EAL, "Cannot open '%s' for rte_mem_config\n",
				pathname);
			return -1;
		}
	}

	retval = rte_ftruncate(mem_cfg_fd, cfg_len);
	if (retval < 0){
		close(mem_cfg_fd);
		mem_cfg_fd = -1;
		RTE_LOG(ERR, EAL, "Cannot resize '%s' for rte_mem_config\n",
			pathname);
		return -1;
	}
/*
	TODO: restore!

	retval = fcntl(mem_cfg_fd, F_SETLK, &wr_lock);
	if (retval < 0){
		close(mem_cfg_fd);
		mem_cfg_fd = -1;
		RTE_LOG(ERR, EAL, "Cannot create lock on '%s'. Is another primary "
			"process running?\n", pathname);
		return -1;
	}
*/
	/* reserve space for config */
	rte_mem_cfg_addr = eal_get_virtual_area(rte_mem_cfg_addr,
			&cfg_len_aligned, page_sz, 0, 0);
	if (rte_mem_cfg_addr == NULL) {
		RTE_LOG(ERR, EAL, "Cannot mmap memory for rte_config\n");
		close(mem_cfg_fd);
		mem_cfg_fd = -1;
		return -1;
	}

	/* remap the actual file into the space we've just reserved */
	mapped_mem_cfg_addr = rte_mem_map(rte_mem_cfg_addr,
			cfg_len_aligned, RTE_PROT_READ | RTE_PROT_WRITE,
			RTE_MAP_SHARED | RTE_MAP_FIXED, mem_cfg_fd, 0);
	if (mapped_mem_cfg_addr == NULL) {
		rte_mem_unmap(rte_mem_cfg_addr, cfg_len);
		close(mem_cfg_fd);
		mem_cfg_fd = -1;
		RTE_LOG(ERR, EAL, "Cannot remap memory for rte_config\n");
		return -1;
	}

	memcpy(rte_mem_cfg_addr, &early_mem_config, sizeof(early_mem_config));
	rte_config.mem_config = rte_mem_cfg_addr;
	
	/* store address of the config in the config itself so that secondary
	 * processes could later map the config into this exact location */
	rte_config.mem_config->mem_cfg_addr = (uintptr_t) rte_mem_cfg_addr;

	rte_config.mem_config->dma_maskbits = 0;

	return 0;
}

/* Sets up rte_config structure with the pointer to shared memory config.*/
static int
rte_config_init(void)
{
	rte_config.process_type = internal_config.process_type;
	if (rte_eal_config_create() < 0) {
		return -1;
	}
	eal_mcfg_update_from_internal();

	return 0;
}

/* Parse the arguments for --log-level only */
static void
eal_log_level_parse(int argc, char **argv)
{
	int opt;
	char **argvopt;
	int option_index;
	const int old_optind = optind;
	const int old_optopt = optopt;
	char * const old_optarg = optarg;

	argvopt = argv;
	optind = 1;

	while ((opt = getopt_long(argc, argvopt, eal_short_options,
				  eal_long_options, &option_index)) != EOF) {

		int ret;

		/* getopt is not happy, stop right now */
		if (opt == '?')
			break;

		ret = (opt == OPT_LOG_LEVEL_NUM) ?
			eal_parse_common_option(opt, optarg, &internal_config) : 0;

		/* common parser is not happy */
		if (ret < 0)
			break;
	}

	/* restore getopt lib */
	optind = old_optind;
	optopt = old_optopt;
	optarg = old_optarg;
}

/* display usage */
static void
eal_usage(const char *prgname)
{
	printf("\nUsage: %s ", prgname);
	eal_common_usage();

	/* Allow the application to print its usage message too if hook is set */
	if (rte_application_usage_hook) {
		printf("===== Application Usage =====\n\n");
		rte_application_usage_hook(prgname);
	}
}

static int
eal_check_options(struct internal_config *cfg)
{
	if (cfg->iova_mode == RTE_IOVA_VA) {
		rte_eal_init_alert("unsupported IOVA mode 'VA'");
		return -ENOTSUP;
	}

	return 0;
}

/* Parse the argument given in the command line of the application */
static int
eal_parse_args(int argc, char **argv)
{
	int opt, ret;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];
	const int old_optind = optind;
	const int old_optopt = optopt;
	char * const old_optarg = optarg;

	argvopt = argv;
	optind = 1;
	opterr = 0;

	while ((opt = getopt_long(argc, argvopt, eal_short_options,
				  eal_long_options, &option_index)) != EOF) {

		/*
		 * getopt didn't recognise the option, lets parse the
		 * registered options to see if the flag is valid
		 */
		if (opt == '?') {
			ret = rte_option_parse(argv[optind-1]);
			if (ret == 0)
				continue;

			eal_usage(prgname);
			ret = -1;
			goto out;
		}

		ret = eal_parse_common_option(opt, optarg, &internal_config);
		/* common parser is not happy */
		if (ret < 0) {
			eal_usage(prgname);
			ret = -1;
			goto out;
		}
		/* common parser handled this option */
		if (ret == 0)
			continue;
	}

	if (eal_adjust_config(&internal_config) != 0) {
		ret = -1;
		goto out;
	}

	/* sanity checks */
	if (eal_check_common_options(&internal_config) != 0) {
		eal_usage(prgname);
		ret = -1;
		goto out;
	}

	/* platform-specific checks */
	if (eal_check_options(&internal_config)) {
		ret = -1;
		goto out;
	}

	if (optind >= 0)
		argv[optind-1] = prgname;
	ret = optind - 1;

out:
	/* restore getopt lib */
	optind = old_optind;
	optopt = old_optopt;
	optarg = old_optarg;

	return ret;
}

/* Set a per-application usage message */
rte_usage_hook_t
rte_set_application_usage_hook( rte_usage_hook_t usage_func )
{
	rte_usage_hook_t	old_func;

	/* Will be NULL on the first call to denote the last usage routine. */
	old_func					= rte_application_usage_hook;
	rte_application_usage_hook	= usage_func;

	return old_func;
}

/* Multi-process is not yet supported, any process is primary. */
enum rte_proc_type_t
eal_proc_type_detect(void)
{
	return RTE_PROC_PRIMARY;
}

enum rte_proc_type_t
rte_eal_process_type(void)
{
	return rte_config.process_type;
}

int
rte_eal_primary_proc_alive(const char *config_file_path)
{
	RTE_SET_USED(config_file_path);
	RTE_LOG(WARNING, EAL, "Windows: %s() stub called\n", __func__);
	return 1;
}

int rte_eal_has_hugepages(void)
{
	return !internal_config.no_hugetlbfs;
}

int rte_eal_has_pci(void)
{
	return !internal_config.no_pci;
}

enum rte_iova_mode
rte_eal_iova_mode(void)
{
	return rte_config.iova_mode;
}

/* There is no documented way of controlling IOPL under Windows.
 * The only access to IO ports is via bus API.
 */
int
rte_eal_iopl_init(void)
{
	return 0;
}

 /* Launch threads, called at application init(). */
int
rte_eal_init(int argc __rte_unused, char **argv __rte_unused)
{
	static rte_atomic32_t run_once = RTE_ATOMIC32_INIT(0);

	char cpuset[RTE_CPU_AFFINITY_STR_LEN] = {0};
	pthread_t thread_id;
	int i, ret, args_parsed;

	/* checks if the machine is adequate */
	if (!rte_cpu_is_supported()) {
		rte_eal_init_alert("unsupported cpu type.");
		rte_errno = ENOTSUP;
		return -1;
	}

	if (!rte_atomic32_test_and_set(&run_once)) {
		rte_eal_init_alert("already called initialization.");
		rte_errno = EALREADY;
		return -1;
	}

	thread_id = pthread_self();

	eal_reset_internal_config(&internal_config);

	/* set log level as early as possible */
	eal_log_level_parse(argc, argv);

	/* create a map of all processors in the system */
	eal_create_cpu_map();

	if (rte_eal_cpu_init() < 0) {
		rte_eal_init_alert("Cannot detect lcores.");
		rte_errno = ENOTSUP;
		return -1;
	}

	ret = eal_parse_args(argc, argv);
	if (ret < 0) {
		rte_eal_init_alert("Invalid 'command line' arguments.");
		rte_errno = EINVAL;
		rte_atomic32_clear(&run_once);
		return -1;
	}
	args_parsed = ret;

	if (eal_plugins_init() < 0) {
		rte_eal_init_alert("Cannot init plugins");
		rte_errno = EINVAL;
		rte_atomic32_clear(&run_once);
		return -1;
	}

	if (eal_option_device_parse()) {
		rte_eal_init_alert("Cannot parse device arguments");
		rte_errno = ENODEV;
		rte_atomic32_clear(&run_once);
		return -1;
	}

	if (rte_config_init() < 0) {
		rte_eal_init_alert("Cannot init config");
		return -1;
	}

	if (rte_eal_intr_init() < 0) {
		rte_eal_init_alert("Cannot init interrupt-handling thread");
		return -1;
	}

	if (rte_eal_alarm_init() < 0) {
		rte_eal_init_alert("Cannot init alarm");
		/* rte_eal_alarm_init sets rte_errno on failure. */
		return -1;
	}

	if (rte_bus_scan()) {
		rte_eal_init_alert("Cannot scan the buses for devices");
		rte_errno = ENODEV;
		rte_atomic32_clear(&run_once);
		return -1;
	}

	/* default IOVA mode is PA, VA is not supported */
	if (internal_config.iova_mode == RTE_IOVA_DC) {
		rte_eal_get_configuration()->iova_mode = RTE_IOVA_PA;
	}

	if (internal_config.no_hugetlbfs == 0) {
		/* rte_config isn't initialized yet */
		ret = internal_config.process_type == RTE_PROC_PRIMARY ?
				eal_hugepage_info_init() :
				eal_hugepage_info_read();
		if (ret < 0) {
			rte_eal_init_alert("Cannot get hugepage information.");
			rte_errno = EACCES;
			rte_atomic32_clear(&run_once);
			return -1;
		}
	}

	if (internal_config.vmware_tsc_map == 1) {
#ifdef RTE_LIBRTE_EAL_VMWARE_TSC_MAP_SUPPORT
		rte_cycles_vmware_tsc_map = 1;
		RTE_LOG (DEBUG, EAL, "Using VMWARE TSC MAP, you must have "
				"monitor_control.pseudo_perfctr = true in VM properties\n");
#else
		RTE_LOG (WARNING, EAL, "Ignoring --vmware-tsc-map because "
				"RTE_LIBRTE_EAL_VMWARE_TSC_MAP_SUPPORT is not set\n");
#endif
	}

	if (rte_eal_log_init(NULL, 0)) {
		rte_eal_init_alert("Cannot init logging");
		rte_errno = EINVAL;
		rte_atomic32_clear(&run_once);
		return -1;
	}

	/* in secondary processes, memory init may allocate additional fbarrays
	 * not present in primary processes, so to avoid any potential issues,
	 * initialize memzones first.
	 */
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

	ret = eal_thread_dump_affinity(cpuset, sizeof(cpuset));

	RTE_LOG(DEBUG, EAL, "Master lcore %u is ready "
			"(tid=%#" RTE_PRIzx ";cpuset=[%s%s])\n",
		rte_config.master_lcore, (uintptr_t)thread_id, cpuset,
		ret == 0 ? "" : "...");

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

	/* initialize services so vdevs register service during bus_probe. */
	ret = rte_service_init();
	if (ret) {
		puts("2.1");
		rte_eal_init_alert("rte_service_init() failed");
		rte_errno = ENOEXEC;
		return -1;
	}

	/* Probe all the buses and devices/drivers on them */
	if (rte_bus_probe()) {
		rte_eal_init_alert("Cannot probe devices");
		rte_errno = ENOTSUP;
		return -1;
	}

	return args_parsed;
}

static int
mark_freeable(const struct rte_memseg_list *msl, const struct rte_memseg *ms,
		void *arg __rte_unused)
{
	/* ms is const, so find this memseg */
	struct rte_memseg *found;

	if (msl->external)
		return 0;

	found = rte_mem_virt2memseg(ms->addr, msl);

	found->flags &= ~RTE_MEMSEG_FLAG_DO_NOT_FREE;

	return 0;
}

int
rte_eal_cleanup(void)
{
	/* if we're in a primary process, we need to mark hugepages as freeable
	 * so that finalization can release them back to the system.
	 */
	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		rte_memseg_walk(mark_freeable, NULL);
	}
	rte_service_finalize();
	rte_mp_channel_cleanup();
	eal_cleanup_config(&internal_config);
	return 0;
}

/* Redeclaration: cannot include <sys/socket.h> alongside Windows headers. */
int inet_aton(const char *cp, struct in_addr *inp);

int
inet_aton(const char *cp, struct in_addr *inp)
{
    return inet_pton(AF_INET, cp, inp);
}

long int
random(void)
{
	/* FIXME: return value range differs from random(3) specification. */
	/* TODO: implement thread-safe RNG to get rid of advapi32.dll. */
	unsigned int value;
	RtlGenRandom(&value, sizeof(value));
	return value;
}

unsigned int
sleep(unsigned long int seconds)
{
	Sleep(1000 * seconds);
	return 0;
}

int
usleep(useconds_t usec) 
{ 
    HANDLE timer;
    LARGE_INTEGER ft;

	/* Convert to 100 nanosecond interval,
	 * negative value indicates relative time.
	 */
    ft.QuadPart = -(10 * usec);

    timer = CreateWaitableTimer(NULL, TRUE, NULL);
    SetWaitableTimer(timer, &ft, 0, NULL, NULL, 0);
    WaitForSingleObject(timer, INFINITE);
    CloseHandle(timer);

	return 0;
}

int
vdprintf(int fd, const char* format, va_list op)
{
	int copy = dup(fd);
	FILE* file = _fdopen(copy, "a");
	int ret = vfprintf(file, format, op);
	fclose(file);
	return ret;
}

int
pthread_setaffinity_np(
		pthread_t thread,
		size_t cpuset_size __rte_unused,
		const rte_cpuset_t *cpuset)
{
	HANDLE sys_thread;
	KAFFINITY mask;
	int i;

	if (cpuset == NULL) {
		return EFAULT;
	}

	sys_thread = pthread_gethandle(thread);
	if (sys_thread == INVALID_HANDLE_VALUE) {
		return ESRCH;
	}

	mask = 0;
	for (i = 0; i < CPU_SET_SIZE; i++) {
		if (CPU_ISSET(i, cpuset)) {
			mask |= (KAFFINITY)1 << i;
		}

		if ((((i + 1) % EAL_PROCESSOR_GROUP_SIZE == 0) ||
				(i + 1 == CPU_SET_SIZE)) && (mask != 0)) {
			/* End of CPU set or a processor group, configure the group. */
			GROUP_AFFINITY affinity;
			memset(&affinity, 0, sizeof(affinity));
			affinity.Group = i / EAL_PROCESSOR_GROUP_SIZE;
			affinity.Mask = mask;
			if (!SetThreadGroupAffinity(sys_thread, &affinity, NULL)) {
				RTE_LOG_SYSTEM_ERROR(
						"SetThreadGroupAffinity(group=%u, mask=%#" PRIx64 ")",
						affinity.Group, affinity.Mask);
				return EINVAL;
			}

			/* Reset mask for next processor group. */
			mask = 0;
		}
	}

	return 0;
}

int
tcgetattr(int fd, struct termios *termios)
{
	HANDLE handle;

	if (fd != STDIN_FILENO) {
		errno = ENOTSUP;
		return -1;
	}

	handle = (HANDLE)_get_osfhandle(fd);
	if (!GetConsoleMode(handle, &termios->c_lflag)) {
		errno = EINVAL;
		return -1;
	}

	return 0;
}

int
tcsetattr(int fd, int actions, const struct termios *termios)
{
	HANDLE handle;

	if ((fd != STDIN_FILENO) || (actions != TCSANOW)) {
		errno = ENOTSUP;
		return -1;
	}

	handle = (HANDLE)_get_osfhandle(fd);
	if (!SetConsoleMode(handle, termios->c_lflag)) {
		errno = EINVAL;
		return -1;
	}

	return 0;
}