# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2016 Neil Horman <nhorman@tuxdriver.com>
# All rights reserved.

include $(RTE_SDK)/mk/rte.vars.mk

# application name
HOSTAPP = dpdk-pmdinfogen

# target-specific object file image parsing library
IMAGELIB-linux    := elf.c
IMAGELIB-linuxapp := $(IMAGELIB-linux)
IMAGELIB-freebsd := elf.c
IMAGELIB-bsdapp  := $(IMAGELIB-freebsd)
IMAGELIB-windows    := coff.c
IMAGELIB-windowsapp := $(IMAGELIB-windows)

SRCS-y += pmdinfogen.c
SRCS-y += mmap.c
SRCS-y += $(IMAGELIB-$(RTE_EXEC_ENV))

HOST_CFLAGS += $(HOST_WERROR_FLAGS) -g
HOST_CFLAGS += -I$(RTE_OUTPUT)/include

include $(RTE_SDK)/mk/rte.hostapp.mk
