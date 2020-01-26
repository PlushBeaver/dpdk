/* SPDX-License-Identifier: BSD-3-Clause */

/**
 * @file Driver interface implementation
 *
 * - Initialize and clean up driver-wide resources.
 * - Create framework objects and register their callbacks.
 */

#include <ntifs.h>
#include <ntddk.h>
#include <wdf.h>
#include <initguid.h>

#include "userpci.h"
#include "userpci_device.h"
#include "userpci_request.h"
#include "userpci_trace.h"

#include "userpci_driver.tmh"

DRIVER_INITIALIZE DriverEntry;

EVT_WDF_DRIVER_DEVICE_ADD userpci_driver_EvtDeviceAdd;
EVT_WDF_OBJECT_CONTEXT_CLEANUP userpci_driver_EvtDriverContextCleanup;

static NTSTATUS
driver_create_device(PWDFDEVICE_INIT init, WDFDEVICE *device)
{
	WDF_PNPPOWER_EVENT_CALLBACKS pnp;
	WDF_FILEOBJECT_CONFIG foc;
	WDF_OBJECT_ATTRIBUTES attributes;
	NTSTATUS status;

	WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnp);
	pnp.EvtDevicePrepareHardware = userpci_device_EvtDevicePrepareHardware;
	pnp.EvtDeviceReleaseHardware = userpci_device_EvtDeviceReleaseHardware;
	WdfDeviceInitSetPnpPowerEventCallbacks(init, &pnp);

	/* Whan a process has finished using a device (including process
	 * termination case), its memory mappings need to be cleaned up.
	 * This must be done in the context of that process.
	 */
	WDF_FILEOBJECT_CONFIG_INIT(&foc, WDF_NO_EVENT_CALLBACK,
		WDF_NO_EVENT_CALLBACK, userpci_device_EvtFileCleanup);
	WdfDeviceInitSetFileObjectConfig(init, &foc, WDF_NO_OBJECT_ATTRIBUTES);

	/* Memory (un)mapping must be performed in the context of a process. */
	WdfDeviceInitSetIoInCallerContextCallback(
		init, userpci_device_EvtIoInCallerContext);

	WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, DeviceContext);

	status = WdfDeviceCreate(&init, &attributes, device);
	if (!NT_SUCCESS(status)) {
		TraceEvents(TRACE_LEVEL_ERROR, TRACE_GENERAL,
			"WdfDeviceCreate() -> %!STATUS!", status);
		return status;
	}

	status = WdfDeviceCreateDeviceInterface(
		*device, &GUID_DEVINTERFACE_USERPCI, NULL);
	if (!NT_SUCCESS(status)) {
		TraceEvents(TRACE_LEVEL_ERROR, TRACE_GENERAL,
			"WdfDeviceCreateDeviceInterface() -> %!STATUS!",
			status);
		return status;
	}

	return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path)
{
	WDF_OBJECT_ATTRIBUTES attributes;
	WDF_DRIVER_CONFIG config;
	NTSTATUS status;

	WPP_INIT_TRACING(driver_object, registry_path);

	WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
	attributes.EvtCleanupCallback = userpci_driver_EvtDriverContextCleanup;

	WDF_DRIVER_CONFIG_INIT(&config, userpci_driver_EvtDeviceAdd);

	status = WdfDriverCreate(
		driver_object, registry_path,
		&attributes, &config,
		WDF_NO_HANDLE);
	if (!NT_SUCCESS(status)) {
		TraceEvents(TRACE_LEVEL_ERROR, TRACE_GENERAL,
			"WdfDriverCreate() -> %!STATUS!", status);
		WPP_CLEANUP(driver_object);
	}

	return status;
}

_Use_decl_annotations_
NTSTATUS
userpci_driver_EvtDeviceAdd(WDFDRIVER driver, PWDFDEVICE_INIT init)
{
	WDFDEVICE device;
	NTSTATUS status;

	UNREFERENCED_PARAMETER(driver);
	PAGED_CODE();

	status = driver_create_device(init, &device);
	if (!NT_SUCCESS(status))
		return status;

	return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
userpci_driver_EvtDriverContextCleanup(WDFOBJECT driver_object)
{
        PAGED_CODE();

        WPP_CLEANUP(WdfDriverWdmGetDriverObject((WDFDRIVER)driver_object));
}
