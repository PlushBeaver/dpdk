# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2019 Intel Corporation

eal_inc += include_directories('include')

env_objs = []
env_headers = files(
	'include/rte_os.h',
	'include/rte_windows.h',
	'include/rte_virt2phys.h',
)
common_sources = files(
	'../../common/eal_common_bus.c',
	'../../common/eal_common_class.c',
	'../../common/eal_common_devargs.c',
	'../../common/eal_common_errno.c',
	'../../common/eal_common_fbarray.c',
	'../../common/eal_common_launch.c',
	'../../common/eal_common_lcore.c',
	'../../common/eal_common_log.c',
	'../../common/eal_common_mcfg.c',
	'../../common/eal_common_memalloc.c',
	'../../common/eal_common_memory.c',
	'../../common/eal_common_memzone.c',
	'../../common/eal_common_options.c',
	'../../common/eal_common_tailqs.c',
	'../../common/eal_common_thread.c',
	'../../common/malloc_elem.c',
	'../../common/malloc_heap.c',
	'../../common/rte_malloc.c',
	'../../common/rte_option.c',
)
env_sources = files('eal.c',
	'eal_debug.c',
	'eal_hugepages.c',
	'eal_lcore.c',
	'eal_memalloc.c',
	'eal_memory.c',
	'eal_mp.c',
	'eal_thread.c',
	'getopt.c',
)
