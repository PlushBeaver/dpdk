/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef USERPCI_REQUEST_H
#define USERPCI_REQUEST_H

#include <wdf.h>

VOID request_config_read(struct device* device, WDFREQUEST request);
VOID request_config_write(struct device* device, WDFREQUEST request);
VOID request_memory_map(struct device* device, WDFREQUEST request);
VOID request_memory_unmap(struct device* device, WDFREQUEST request);
VOID request_ioport_map(struct device* device, WDFREQUEST request);
VOID request_ioport_unmap(struct device* device, WDFREQUEST request);
VOID request_ioport_read(struct device* device, WDFREQUEST request);
VOID request_ioport_write(struct device* device, WDFREQUEST request);

#endif
