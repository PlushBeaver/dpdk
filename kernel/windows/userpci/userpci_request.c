/* SPDX-License-Identifier: BSD-3-Clause */

/**
 * @file I/O request handlers
 * Functions in this file parse I/O requests, validate parameters
 * and call internal routines to do the real work.
 *
 * Every function either always completes requests or never does so.
 * Functions that complete requests may only tail-call each other.
 * Helper functions that return a value never complete requests.
 */

#include <ntifs.h>
#include <ntddk.h>
#include <wdf.h>
#include <initguid.h>

#include "userpci.h"
#include "userpci_device.h"
#include "userpci_internal.h"
#include "userpci_request.h"
#include "userpci_trace.h"

#include "userpci_request.tmh"

VOID
request_config_read(struct device* device, WDFREQUEST request) {
	struct userpci_config_data *in = NULL;
	void* out = NULL;
	ULONG bytes_read;
	NTSTATUS status = STATUS_SUCCESS;

	status = WdfRequestRetrieveInputBuffer(request, sizeof(*in), &in, NULL);
	if (!NT_SUCCESS(status)) {
		WdfRequestComplete(request, STATUS_INVALID_PARAMETER);
		return;
	}

	status = WdfRequestRetrieveOutputBuffer(request, in->size, &out, NULL);
	if (!NT_SUCCESS(status)) {
		WdfRequestComplete(request, STATUS_INVALID_PARAMETER);
		return;
	}

	status = config_read(
		&device->bus, in->offset, in->size, out, &bytes_read);

	WdfRequestCompleteWithInformation(request, status, bytes_read);
}

VOID
request_config_write(struct device* device, WDFREQUEST request) {
	struct userpci_config_data* in = NULL;
	void* data = NULL;
	size_t length = 0;
	ULONG bytes_written;
	NTSTATUS status = STATUS_SUCCESS;

	status = WdfRequestRetrieveInputBuffer(request, sizeof(*in), &in, &length);
	if (!NT_SUCCESS(status)) {
		WdfRequestComplete(request, STATUS_INVALID_PARAMETER);
		return;
	}

	length -= sizeof(*in);
	if (length < in->size) {
		WdfRequestComplete(request, STATUS_INVALID_PARAMETER);
		return;
	}

	data = (PUCHAR)in + sizeof(*in);
	status = config_write(
		&device->bus, in->offset, in->size, data, &bytes_written);

	WdfRequestCompleteWithInformation(request, status, bytes_written);
}

static NTSTATUS
request_check_resource(struct device* device, int index,
	const char* func, struct resource** resource)
{
	if ((index < 0) && (device->resource_count <= index)) {
		TraceEventsRaw(TRACE_LEVEL_ERROR, TRACE_MAPPING,
			"%s: resource (%d) out of range (0, %llu)",
			func, index, device->resource_count);
		return STATUS_INVALID_PARAMETER;
	}

	*resource = &device->resources[index];

	if ((*resource)->type == RESOURCE_INVALID) {
		TraceEventsRaw(TRACE_LEVEL_ERROR, TRACE_MAPPING,
			"%s: resource (%d) is not valid", func, index);
		return STATUS_INVALID_PARAMETER;
	}

	return STATUS_SUCCESS;
}

VOID
request_memory_map(struct device* device, WDFREQUEST request) {
	struct userpci_memory_map_in* in = NULL;
	struct userpci_memory_map_out* out = NULL;
	size_t length = 0;
	struct resource* resource = NULL;
	struct mapping_request mreq;
	NTSTATUS status = STATUS_SUCCESS;

	status = WdfRequestRetrieveInputBuffer(
		request, sizeof(*in), &in, &length);
	if (!NT_SUCCESS(status)) {
		WdfRequestComplete(request, STATUS_INVALID_PARAMETER);
		return;
	}

	status = WdfRequestRetrieveOutputBuffer(
		request, sizeof(*out), &out, &length);
	if (!NT_SUCCESS(status)) {
		WdfRequestComplete(request, STATUS_INVALID_PARAMETER);
		return;
	}

	TraceEventsRaw(TRACE_LEVEL_INFORMATION, TRACE_MAPPING,
		"%!FUNC!(resource=%d, address=%#p, length=%llu, protection=%#x)",
		in->resource, in->address, in->length, in->protection);

	status = request_check_resource(
		device, in->resource, __func__, &resource);
	if (!NT_SUCCESS(status)) {
		WdfRequestComplete(request, status);
		return;
	}
	
	if (resource->type != RESOURCE_MEMORY) {
		TraceEvents(TRACE_LEVEL_ERROR, TRACE_MAPPING,
			"resource (%d) is not a MMIO",
			in->resource);
		WdfRequestComplete(request, STATUS_UNSUCCESSFUL);
		return;
	}

	if (!in->length || (in->length > resource->length)) {
		TraceEvents(TRACE_LEVEL_ERROR, TRACE_MAPPING,
			"length (%llu) out of range (0, %llu)",
			in->length, resource->length);
		WdfRequestComplete(request, STATUS_INVALID_PARAMETER);
		return;
	}

	mreq.process_id = PsGetCurrentProcessId();
	mreq.address = in->address;
	mreq.length = in->length;
	mreq.protection = in->protection;
	status = mapping_create(resource, &mreq, &out->address);
	if (!NT_SUCCESS(status)) {
		WdfRequestComplete(request, status);
		return;
	}

	WdfRequestCompleteWithInformation(request, STATUS_SUCCESS, sizeof(*out));

	TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_MAPPING,
		"mapped to %p in process %!HANDLE!",
		out->address, mreq.process_id);
}

VOID
request_memory_unmap(struct device* device, WDFREQUEST request) {
	struct userpci_memory_unmap_in* in = NULL;
	struct mapping* mapping;
	struct mapping_locator locator;
	NTSTATUS status = STATUS_SUCCESS;

	status = WdfRequestRetrieveInputBuffer(
		request, sizeof(*in), &in, NULL);
	if (!NT_SUCCESS(status)) {
		TraceEvents(TRACE_LEVEL_ERROR, TRACE_MAPPING,
			"WdfRequestRetrieveInputBuffer() -> %!STATUS!",
			status);
		WdfRequestComplete(request, STATUS_INVALID_PARAMETER);
		return;
	}

	TraceEventsRaw(TRACE_LEVEL_INFORMATION, TRACE_MAPPING,
			"%!FUNC!(address=%#p, length=%llu)",
			in->address, in->length);

	locator.process_id = (HANDLE)WdfRequestGetRequestorProcessId(request);
	locator.address = in->address;
	mapping = device_find_mapping(device, &locator);
	if (mapping == NULL) {
		TraceEvents(TRACE_LEVEL_ERROR, TRACE_MAPPING,
			"no mapping at %p in process %!HANDLE!",
			locator.address, locator.process_id);
		WdfRequestComplete(request, STATUS_MEMORY_NOT_ALLOCATED);
		return;
	}

	if (in->length != mapping->length) {
		TraceEvents(TRACE_LEVEL_ERROR, TRACE_MAPPING,
			"unmapped length (%llu) must match mapped length (%llu)",
			in->length, mapping->length);
		WdfRequestComplete(request, STATUS_INVALID_PARAMETER);
		return;
	}

	mapping_destroy(mapping);

	WdfRequestComplete(request, STATUS_SUCCESS);
}

static NTSTATUS
request_check_ioport_item_size(BYTE item_size, const char* func)
{
	switch (item_size) {
	case sizeof(UCHAR) :
	case sizeof(USHORT) :
	case sizeof(ULONG) :
		return STATUS_SUCCESS;
	}

	TraceEventsRaw(TRACE_LEVEL_ERROR, TRACE_MAPPING,
		"%s: item size (%d) must be 1, 2, or 4",
		func, item_size);
	return STATUS_INVALID_PARAMETER;
}

static NTSTATUS
request_check_ioport_access(struct resource* resource,
	struct userpci_ioport_data* in, const char* func)
{
	if (resource->type != RESOURCE_PORT) {
		TraceEventsRaw(TRACE_LEVEL_ERROR, TRACE_MAPPING,
			"%s: resource (%d) is not an I/O port",
			func, in->resource);
		return STATUS_NOT_SUPPORTED;
	}

	if (resource->kernel_address == NULL) {
		TraceEventsRaw(TRACE_LEVEL_ERROR, TRACE_MAPPING,
			"%s: resource (%d) is not mapped",
			func, in->resource);
		return STATUS_UNSUCCESSFUL;
	}

	if (in->offset >= resource->length) {
		TraceEventsRaw(TRACE_LEVEL_ERROR, TRACE_MAPPING,
			"%s: offset (%u) out of range (0, %llu)",
			func, in->offset, resource->length);
		return STATUS_INVALID_PARAMETER;
	}

	return STATUS_SUCCESS;
}

VOID
request_ioport_map(struct device* device, WDFREQUEST request)
{
	struct userpci_ioport_map_in* in = NULL;
	struct resource* resource;
	NTSTATUS status = STATUS_SUCCESS;

	status = WdfRequestRetrieveInputBuffer(request, sizeof(*in), &in, NULL);
	if (!NT_SUCCESS(status)) {
		WdfRequestComplete(request, status);
		return;
	}

	status = request_check_resource(
		device, in->resource, __func__, &resource);
	if (!NT_SUCCESS(status)) {
		WdfRequestComplete(request, status);
		return;
	}

	if (resource->type != RESOURCE_PORT) {
		WdfRequestComplete(request, STATUS_UNSUCCESSFUL);
		return;
	}

	/* No real mapping needs to be done. */
	WdfRequestComplete(request, STATUS_SUCCESS);
}

VOID
request_ioport_unmap(struct device* device, WDFREQUEST request)
{
	/* Device parameter is for module consistency. */
	UNREFERENCED_PARAMETER(device);

	/* No real unmapping needs to be done. */
	WdfRequestComplete(request, STATUS_SUCCESS);
}

VOID
request_ioport_read(struct device* device, WDFREQUEST request)
{
	struct userpci_ioport_data* in = NULL;
	void* out = NULL;
	size_t length = 0;
	struct resource* resource;
	PVOID address;
	NTSTATUS status = STATUS_SUCCESS;

	status = WdfRequestRetrieveInputBuffer(request, sizeof(*in), &in, NULL);
	if (!NT_SUCCESS(status)) {
		WdfRequestComplete(request, status);
		return;
	}

	status = request_check_ioport_item_size(in->item_size, __func__);
	if (!NT_SUCCESS(status)) {
		WdfRequestComplete(request, status);
		return;
	}

	length = (size_t)in->item_count * in->item_size;
	if (length >= MAXUINT16) {
		TraceEvents(TRACE_LEVEL_ERROR, TRACE_MAPPING,
			"item count (%d) too large, would require %llu bytes",
			in->item_count, length);
		WdfRequestComplete(request, STATUS_INVALID_PARAMETER);
		return;
	}

	status = WdfRequestRetrieveOutputBuffer(request, length, &out, &length);
	if (!NT_SUCCESS(status)) {
		WdfRequestComplete(request, status);
		return;
	}

	status = request_check_resource(
		device, in->resource, __func__, &resource);
	if (!NT_SUCCESS(status)) {
		TraceEvents(TRACE_LEVEL_ERROR, TRACE_MAPPING,
			"resource check failed, status %!STATUS!",
			status);
		WdfRequestComplete(request, status);
		return;
	}

	status = request_check_ioport_access(resource, in, __func__);
	if (!NT_SUCCESS(status)) {
		TraceEvents(TRACE_LEVEL_ERROR, TRACE_MAPPING,
			"access check failed, status %!STATUS!",
			status);
		WdfRequestComplete(request, status);
		return;
	}

	address = (PUCHAR)resource->kernel_address + in->offset;
	ioport_read(address, in->item_size, in->item_count, out);

	WdfRequestCompleteWithInformation(request, STATUS_SUCCESS, length);
}

VOID
request_ioport_write(struct device* device, WDFREQUEST request)
{
	struct userpci_ioport_data* in = NULL;
	void* data = NULL;
	size_t length = 0;
	struct resource* resource;
	PVOID address;
	NTSTATUS status = STATUS_SUCCESS;

	status = WdfRequestRetrieveInputBuffer(request, sizeof(*in), &in, &length);
	if (!NT_SUCCESS(status)) {
		WdfRequestComplete(request, status);
		return;
	}

	status = request_check_ioport_item_size(in->item_size, __func__);
	if (!NT_SUCCESS(status)) {
		WdfRequestComplete(request, status);
		return;
	}

	length -= sizeof(*in);
	if (((size_t)in->item_count * (size_t)in->item_size) != length) {
		TraceEvents(TRACE_LEVEL_ERROR, TRACE_MAPPING,
			"item count (%d) * item size (%d) must match length (%llu)",
			in->item_count, in->item_size, length);
		WdfRequestComplete(request, STATUS_INVALID_PARAMETER);
		return;
	}

	status = request_check_resource(
		device, in->resource, __func__, &resource);
	if (!NT_SUCCESS(status)) {
		TraceEvents(TRACE_LEVEL_ERROR, TRACE_MAPPING,
			"resource check failed, status %!STATUS!",
			status);
		WdfRequestComplete(request, status);
		return;
	}

	status = request_check_ioport_access(resource, in, __func__);
	if (!NT_SUCCESS(status)) {
		TraceEvents(TRACE_LEVEL_ERROR, TRACE_MAPPING,
			"access check failed, status %!STATUS!",
			status);
		WdfRequestComplete(request, status);
		return;
	}

	data = (PUCHAR)in + sizeof(*in);
	address = (PUCHAR)resource->kernel_address + in->offset;
	ioport_write(address, in->item_size, in->item_count, data);

	WdfRequestCompleteWithInformation(request, STATUS_SUCCESS, (ULONG)length);
}
