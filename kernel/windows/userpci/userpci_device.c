/* SPDX-License-Identifier: BSD-3-Clause */

#include <initguid.h>
#include <ntifs.h>
#include <ntddk.h>
#include <wdf.h>
#include <wdmguid.h>

#include "userpci.h"
#include "userpci_device.h"
#include "userpci_request.h"
#include "userpci_trace.h"

#include "userpci_device.tmh"

/**
 * @file Device interface implementation
 *
 * - Enumerate hardware resources on device appearance.
 * - Dispatch I/O control requests.
 * - Cleanup resources on device removal.
 */

static NTSTATUS
device_get_address(WDFDEVICE device, struct pci_addr* addr)
{
	UINT32 bus, address;
	ULONG value_size;
	NTSTATUS status;

	status = WdfDeviceQueryProperty(
		device, DevicePropertyBusNumber,
		sizeof(bus), &bus, &value_size);
	if (!NT_SUCCESS(status)) {
		TraceEvents(TRACE_LEVEL_ERROR, TRACE_GENERAL,
			"WdfDeviceQueryProperty(BusNumber) -> %!STATUS!",
			status);
		return status;
	}

	status = WdfDeviceQueryProperty(
		device, DevicePropertyAddress,
		sizeof(address), &address, &value_size);
	if (!NT_SUCCESS(status)) {
		TraceEvents(TRACE_LEVEL_ERROR, TRACE_GENERAL,
			"WdfDeviceQueryProperty(Address) -> %!STATUS!",
			status);
		return status;
	}

	addr->bus = bus & 0xffff;
	addr->device = (address >> 16) & 0xff;
	addr->function = address & 0xff;

	return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
userpci_device_EvtDevicePrepareHardware(
	WDFDEVICE device,
	WDFCMRESLIST resources_raw, WDFCMRESLIST resources)
{
	DeviceContext* context;
	NTSTATUS status = STATUS_SUCCESS;
	size_t i;
	
	UNREFERENCED_PARAMETER(resources_raw);
	PAGED_CODE();

	context = device_context_get(device);

	/* Save device PCI address for logging. */
	status = device_get_address(device, &context->address);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	/* Save parent PCI bus interface. */
	status = WdfFdoQueryForInterface(
		device, &GUID_BUS_INTERFACE_STANDARD,
		(PINTERFACE)&context->bus, sizeof(context->bus), 1, NULL);
	if (!NT_SUCCESS(status)) {
		TraceEvents(TRACE_LEVEL_ERROR, TRACE_GENERAL,
			"[%04u:%02u.%u] WdfFdoQueryForInterface() -> %!STATUS!",
			context->address.bus, context->address.device, context->address.function,
			status);
		return status;
	}

	/* Do not perform zero-size allocation. */
	context->resource_count = WdfCmResourceListGetCount(resources);
	if (context->resource_count == 0)
		return STATUS_SUCCESS;

	/* Allocate resources array. */
	status = device_alloc(context, context->resource_count);
	if (!NT_SUCCESS(status)) {
		TraceEvents(TRACE_LEVEL_ERROR, TRACE_GENERAL,
			"cannot allocate device resources array");
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	
	/* Fill resource descriptions. */
	for (i = 0; i < context->resource_count; i++) {
		CM_PARTIAL_RESOURCE_DESCRIPTOR* descriptor =
			WdfCmResourceListGetDescriptor(resources, (ULONG)i);

		struct resource* resource = &context->resources[i];
		resource_init(resource);

		switch (descriptor->Type) {
		case CmResourceTypePort:
			resource->physical_address = descriptor->u.Port.Start;
			resource->length = descriptor->u.Port.Length;
			if (descriptor->Flags & CM_RESOURCE_PORT_MEMORY) {
				/* I/O port region of physical memory. */
				resource->type = RESOURCE_MEMORY;
			}
			else if (descriptor->Flags & CM_RESOURCE_PORT_IO) {
				/* I/O port separate from physical memory. */
				resource->type = RESOURCE_PORT;
				resource->kernel_address = ULongToPtr(
					resource->physical_address.LowPart);
			}
			break;
		case CmResourceTypeMemory:
			/* A register file in physical memory. */
			resource->type = RESOURCE_MEMORY;
			resource->physical_address = descriptor->u.Memory.Start;
			resource->length = descriptor->u.Memory.Length;
			break;
		default:
			/* TODO: interrupts */
			continue;
		}

		TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_GENERAL,
			"resource %llu type %d phys 0x%llx virt %p size %llu",
			i, (int)resource->type, resource->physical_address.QuadPart,
			resource->kernel_address, resource->length);
	}

	return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
userpci_device_EvtDeviceReleaseHardware(
	WDFDEVICE device, WDFCMRESLIST resources)
{
	DeviceContext* context;

	UNREFERENCED_PARAMETER(resources);
	PAGED_CODE();

	context = device_context_get(device);
	device_unmap(context);
	ExFreePoolWithTag(context->resources, USERPCI_POOL_TAG);

	return STATUS_SUCCESS;
}

/* Called in the context of a process which has just closed
 * its last handle to a driver interface device.
 */
_Use_decl_annotations_
VOID
userpci_device_EvtFileCleanup(WDFFILEOBJECT object)
{
	HANDLE process_id;
	WDFDEVICE device;
	DeviceContext* context;

	PAGED_CODE();

	process_id = PsGetCurrentProcessId();
	device = WdfFileObjectGetDevice(object);
	context = device_context_get(device);
	device_unmap_process(context, process_id);
}

_Use_decl_annotations_
VOID
userpci_device_EvtIoInCallerContext(WDFDEVICE device, WDFREQUEST request)
{
	WDF_REQUEST_PARAMETERS params;
	struct device* context;
	ULONG code;

	UNREFERENCED_PARAMETER(device);
	PAGED_CODE();

	if (WdfRequestGetRequestorMode(request) != UserMode) {
		TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_GENERAL,
			"requests from kernel-mode not supported");
		WdfRequestComplete(request, STATUS_UNSUCCESSFUL);
		return;
	}

	WDF_REQUEST_PARAMETERS_INIT(&params);
	WdfRequestGetParameters(request, &params);

	if (params.Type != WdfRequestTypeDeviceControl) {
		TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_GENERAL,
			"non-I/O control requests not supported");
		WdfRequestComplete(request, STATUS_UNSUCCESSFUL);
		return;
	}

	context = device_context_get(device);
	code = params.Parameters.DeviceIoControl.IoControlCode;
	switch (code) {
	case IOCTL_USERPCI_CONFIG_READ:
		request_config_read(context, request);
		return;
	case IOCTL_USERPCI_CONFIG_WRITE:
		request_config_write(context, request);
		return;
	case IOCTL_USERPCI_IOPORT_MAP:
		request_ioport_map(context, request);
		return;
	case IOCTL_USERPCI_IOPORT_UNMAP:
		request_ioport_unmap(context, request);
		return;
	case IOCTL_USERPCI_IOPORT_READ:
		request_ioport_read(context, request);
		return;
	case IOCTL_USERPCI_IOPORT_WRITE:
		request_ioport_write(context, request);
		return;
	case IOCTL_USERPCI_MEMORY_MAP:
		request_memory_map(context, request);
		return;
	case IOCTL_USERPCI_MEMORY_UNMAP:
		request_memory_unmap(context, request);
		return;
	}

	TraceEvents(TRACE_LEVEL_ERROR, TRACE_GENERAL,
		"I/O control code %#08x not recognized", code);
	WdfRequestComplete(request, STATUS_INVALID_DEVICE_REQUEST);
}
