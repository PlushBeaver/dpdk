# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation

pmdinfogen_inc = [global_inc]
pmdinfogen_inc += include_directories(
	'../../lib/librte_eal/common/include',
	'../../lib/librte_pci',
)
pmdinfogen_src = [
	'pmdinfogen.c',
	'mmap.c',
]
if is_windows
	pmdinfogen_src += 'coff.c'
else
	pmdinfogen_src += 'elf.c'
endif
pmdinfogen = executable('pmdinfogen',
	pmdinfogen_src,
	include_directories: pmdinfogen_inc,
	native: true)
