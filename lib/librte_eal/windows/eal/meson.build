# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2019 Intel Corporation

eal_inc += include_directories('include')

env_objs = []
env_headers = files(
	'include/arpa/inet.h',
	'include/netinet/in.h',
	'include/netinet/ip.h',
	'include/netinet/ip6.h',
	'include/sys/queue.h',
	'include/sys/socket.h',
	'include/rte_os.h',
	'include/rte_windows.h',
)
if is_ms_linker
	env_headers += [
		'include/sched.h',
		'include/unistd.h',
	]
endif
env_sources = files(
	'eal.c',
	'eal_alarm.c',
	'eal_debug.c',
	'eal_dev.c',
	'eal_hugepage_info.c',
	'eal_interrupts.c',
	'eal_lcore.c',
	'eal_log.c',
	'eal_memalloc.c',
	'eal_memory.c',
	'eal_memory_xlate.c',
	'eal_module.c',
	'eal_mp.c',
	'eal_thread.c',
	'eal_timer.c',
	'rte_filesystem.c',
)

excluded_common_sources = [
	'eal_common_proc.c'
]
win_common_sources = []
foreach src:common_sources
	parts = '@0@'.format(src).split('/')
	file = parts.get(parts.length() - 1, parts.get(0))
	if not excluded_common_sources.contains(file)
		win_common_sources += src
	endif
endforeach
common_sources = win_common_sources

install_headers('include/sys/queue.h', subdir: 'sys')

deps += ['kvargs']
