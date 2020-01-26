/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef USERPCI_DEVICE_H
#define USERPCI_DEVICE_H

#include <wdf.h>

#include "userpci_internal.h"

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DeviceContext, device_context_get)

EVT_WDF_DEVICE_PREPARE_HARDWARE userpci_device_EvtDevicePrepareHardware;
EVT_WDF_DEVICE_RELEASE_HARDWARE userpci_device_EvtDeviceReleaseHardware;
EVT_WDF_IO_IN_CALLER_CONTEXT userpci_device_EvtIoInCallerContext;
EVT_WDF_FILE_CLEANUP userpci_device_EvtFileCleanup;

#endif
