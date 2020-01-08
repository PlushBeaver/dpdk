# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018 Luca Boccassi <bluca@debian.org>

if is_windows
	build = false
	reason = 'not supported on Windows'
	subdir_done()
endif

allow_experimental_apis = true

subdir('base')
objs = [base_objs]

sources = files(
	'qede_ethdev.c',
	'qede_filter.c',
	'qede_main.c',
	'qede_rxtx.c',
)
