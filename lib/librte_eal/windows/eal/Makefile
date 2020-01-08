# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2020 Dmitry Kozlyuk

include $(RTE_SDK)/mk/rte.vars.mk

LIB = librte_eal.a

ARCH_DIR ?= $(RTE_ARCH)

EXPORT_MAP := ../../rte_eal_version.map
VPATH += $(RTE_SDK)/lib/librte_eal/common/arch/$(ARCH_DIR)

VPATH += $(RTE_SDK)/lib/librte_eal/common

CFLAGS += -DALLOW_EXPERIMENTAL_API
CFLAGS += -I$(SRCDIR)/include
CFLAGS += -I$(RTE_SDK)/lib/librte_eal/common
CFLAGS += -I$(RTE_SDK)/lib/librte_eal/common/include
CFLAGS += $(WERROR_FLAGS) -O3

ifeq ($(RTE_TOOLCHAIN),gcc)
CFLAGS += -D__USE_MINGW_ANSI_STDIO
endif

LDLIBS += -lpthread
ifeq ($(RTE_TOOLCHAIN),gcc)
LDLIBS += -lgcc_s
endif
LDLIBS += -lrte_kvargs

# specific to windows exec-env
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) := eal.c
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += eal_hugepage_info.c
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += eal_memory.c
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += eal_memory_xlate.c
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += eal_thread.c
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += eal_log.c
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += eal_memalloc.c
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += eal_debug.c
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += eal_lcore.c
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += eal_module.c
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += eal_timer.c
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += eal_interrupts.c
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += eal_alarm.c
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += eal_dev.c
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += rte_filesystem.c
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += eal_mp.c

# from common dir
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += eal_common_lcore.c
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += eal_common_timer.c
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += eal_common_memzone.c
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += eal_common_log.c
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += eal_common_launch.c
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += eal_common_mcfg.c
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += eal_common_memalloc.c
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += eal_common_memory.c
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += eal_common_tailqs.c
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += eal_common_errno.c
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += eal_common_cpuflags.c
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += eal_common_hypervisor.c
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += eal_common_string_fns.c
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += eal_common_hexdump.c
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += eal_common_devargs.c
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += eal_common_class.c
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += eal_common_bus.c
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += eal_common_dev.c
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += eal_common_options.c
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += eal_common_thread.c
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += eal_common_fbarray.c
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += eal_common_uuid.c
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += rte_malloc.c
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += hotplug_mp.c
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += malloc_elem.c
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += malloc_heap.c
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += malloc_mp.c
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += rte_keepalive.c
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += rte_option.c
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += rte_service.c
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += rte_random.c
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += rte_reciprocal.c

# from arch dir
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += rte_cpuflags.c
SRCS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += rte_hypervisor.c
SRCS-$(CONFIG_RTE_ARCH_X86) += rte_spinlock.c
SRCS-y += rte_cycles.c

CFLAGS_eal_common_cpuflags.o := $(CPUFLAGS_LIST)
CFLAGS_eal_memory_xlate.o := -I$(RTE_SDK)/kernel/windows/virt2phys

# workaround for a gcc bug with noreturn attribute
# http://gcc.gnu.org/bugzilla/show_bug.cgi?id=12603
ifeq ($(CONFIG_RTE_TOOLCHAIN_GCC),y)
CFLAGS_eal_thread.o += -Wno-return-type
endif

INC += rte_os.h
INC += rte_windows.h

SYMLINK-$(CONFIG_RTE_EXEC_ENV_WINDOWS)-include := $(addprefix include/,$(INC))

# POSIX compatibility includes
SYMLINK-DIRS-$(CONFIG_RTE_EXEC_ENV_WINDOWS) += \
	$(addprefix include/,arpa netinet sys)
SYMLINK-$(CONFIG_RTE_EXEC_ENV_WINDOWS)-include/arpa := \
	$(addprefix include/arpa/,inet.h)
SYMLINK-$(CONFIG_RTE_EXEC_ENV_WINDOWS)-include/netinet := \
	$(addprefix include/netinet/,in.h ip.h ip6.h)
SYMLINK-$(CONFIG_RTE_EXEC_ENV_WINDOWS)-include/sys := \
	$(addprefix include/sys/,queue.h socket.h)

# MinGW includes files related to pthread, but other toolchains do not.
ifneq ($(CONFIG_RTE_TOOLCHAIN_GCC),y)
SYMLINK-$(CONFIG_RTE_EXEC_ENV_WINDOWS)-include += \
	$(addprefix include/,sched.h unistd.h)
endif

include $(RTE_SDK)/mk/rte.lib.mk
