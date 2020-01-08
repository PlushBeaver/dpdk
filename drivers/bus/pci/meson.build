# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation

deps += ['eal', 'kvargs', 'pci']
install_headers('rte_bus_pci.h')
sources = files(
	'pci_common.c',
	'pci_params.c')
if is_linux
	sources += files(
			'pci_common_uio.c',
			'linux/pci.c',
			'linux/pci_uio.c',
			'linux/pci_vfio.c')
	includes += include_directories('linux')
elif is_freebsd
	sources += files(
		'pci_common_uio.c',
		'bsd/pci.c')
	includes += include_directories('bsd')
elif is_windows
	sources += files(
		'windows/pci.c',
		'windows/pci_windio.c'
	)
	includes += include_directories('windows')
endif

# memseg walk is not part of stable API yet
allow_experimental_apis = true
