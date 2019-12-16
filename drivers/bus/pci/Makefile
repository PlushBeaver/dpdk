# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 6WIND S.A.

include $(RTE_SDK)/mk/rte.vars.mk

LIB = librte_bus_pci.a
EXPORT_MAP := rte_bus_pci_version.map

CFLAGS := -I$(SRCDIR) $(CFLAGS)
CFLAGS += -O3 $(WERROR_FLAGS)
CFLAGS += -DALLOW_EXPERIMENTAL_API

CFLAGS += -I$(RTE_SDK)/drivers/bus/pci/$(RTE_EXEC_ENV)
CFLAGS += -I$(RTE_SDK)/lib/librte_eal/common

# memseg walk is not part of stable API yet
CFLAGS += -DALLOW_EXPERIMENTAL_API

LDLIBS += -lrte_eal -lrte_mbuf -lrte_mempool -lrte_ring
LDLIBS += -lrte_pci -lrte_kvargs

include $(RTE_SDK)/drivers/bus/pci/$(RTE_EXEC_ENV)/Makefile
SRCS-$(CONFIG_RTE_LIBRTE_PCI_BUS) := $(addprefix $(RTE_EXEC_ENV)/,$(SRCS))
SRCS-$(CONFIG_RTE_LIBRTE_PCI_BUS) += pci_params.c
SRCS-$(CONFIG_RTE_LIBRTE_PCI_BUS) += pci_common.c

SYMLINK-$(CONFIG_RTE_LIBRTE_PCI_BUS)-include += rte_bus_pci.h

include $(RTE_SDK)/mk/rte.lib.mk
