# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation

include $(RTE_SDK)/mk/rte.vars.mk

DIRS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += eal
DEPDIRS-kni := eal

CFLAGS += -DALLOW_EXPERIMENTAL_API
CFLAGS += -D__USE_MINGW_ANSI_STDIO=1	# printf("%Lf") for long double
CFLAGS += -Wno-pedantic-ms-format

include $(RTE_SDK)/mk/rte.subdir.mk
