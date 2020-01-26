/* SPDX-License-Identifier: BSD-3-Clause */

#include <ntifs.h>
#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>
#include <initguid.h>

#include "userpci_internal.h"
#include "userpci_trace.h"

#include "userpci_internal.tmh"

/* Iterate a doubly-linked list. */
#define FOR_EACH(list, entry) \
	for (entry = (list).Flink; entry != &(list); entry = entry->Flink)

NTSTATUS
config_read(
	const BUS_INTERFACE_STANDARD *bus, USHORT offset, USHORT size,
	void* out, ULONG* bytes_read)
{
	*bytes_read = bus->GetBusData(
		bus->Context, PCI_WHICHSPACE_CONFIG, out, offset, size);
	return (*bytes_read == size) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

NTSTATUS
config_write(
	const BUS_INTERFACE_STANDARD *bus, USHORT offset, USHORT size,
	void* in, ULONG* bytes_written)
{
	*bytes_written = bus->SetBusData(
		bus->Context, PCI_WHICHSPACE_CONFIG, in, offset, size);
	return (*bytes_written == size) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

VOID
ioport_read(void* port, BYTE item_size, USHORT item_count, void* out)
{
	switch (item_size) {
	case sizeof(UCHAR) :
		READ_PORT_BUFFER_UCHAR((PUCHAR)port, (PUCHAR)out, item_count);
		break;
	case sizeof(USHORT) :
		READ_PORT_BUFFER_USHORT((PUSHORT)port, (PUSHORT)out, item_count);
		break;
	case sizeof(ULONG) :
		READ_PORT_BUFFER_ULONG((PULONG)port, (PULONG)out, item_count);
		break;
	}
}

VOID
ioport_write(void* port, BYTE item_size, USHORT item_count, void* in)
{
	switch (item_size) {
	case sizeof(UCHAR) :
		WRITE_PORT_BUFFER_UCHAR((PUCHAR)port, (PUCHAR)in, item_count);
		break;
	case sizeof(USHORT) :
		WRITE_PORT_BUFFER_USHORT((PUSHORT)port, (PUSHORT)in, item_count);
		break;
	case sizeof(ULONG) :
		WRITE_PORT_BUFFER_ULONG((PULONG)port, (PULONG)in, item_count);
		break;
	}
}

VOID
resource_init(struct resource* resource)
{
	RtlZeroMemory(resource, sizeof(*resource));
	InitializeListHead(&resource->mappings);
}

static NTSTATUS
resource_alloc(struct resource* resource, size_t length, ULONG protection)
{
	PVOID kernel_address = NULL;
	PMDL mdl = NULL;

	kernel_address = MmMapIoSpaceEx(
		resource->physical_address, length, protection);
	if (kernel_address == NULL) {
		TraceEvents(TRACE_LEVEL_ERROR, TRACE_MAPPING,
			"MmMapIoSpace(%#llx, %llu) failed",
			resource->physical_address.QuadPart, length);
		goto cleanup;
	}

	mdl = IoAllocateMdl(kernel_address, (ULONG)length, FALSE, FALSE, NULL);
	if (!mdl) {
		TraceEvents(TRACE_LEVEL_ERROR, TRACE_MAPPING,
			"IoAllocateMdl(%#p, %llu) failed",
			kernel_address, length);
		goto cleanup;
	}

	MmBuildMdlForNonPagedPool(mdl);

	resource->kernel_address = kernel_address;
	resource->mdl = mdl;
	return STATUS_SUCCESS;

cleanup:
	if (mdl != NULL)
		IoFreeMdl(mdl);
	if (kernel_address != NULL)
		MmUnmapIoSpace(kernel_address, length);
	return STATUS_UNSUCCESSFUL;
}

static VOID
resource_free(struct resource* resource)
{
	IoFreeMdl(resource->mdl);
	MmUnmapIoSpace(resource->kernel_address, resource->length);
	resource->mdl = NULL;
	resource->kernel_address = NULL;
}

static struct mapping*
resource_find_mapping(const struct resource* resource,
	const struct mapping_locator* locator)
{
	PLIST_ENTRY entry;

	FOR_EACH(resource->mappings, entry) {
		struct mapping* candidate = CONTAINING_RECORD(
			entry, struct mapping, resource_mappings);

		if (candidate->process_id != locator->process_id)
			continue;
		if (candidate->address != locator->address)
			continue;
		return candidate;
	}
	return NULL;
}

NTSTATUS
mapping_create(struct resource* resource, struct mapping_request* request,
	PVOID *usermode_address)
{
	NTSTATUS status;
	PVOID address = NULL;
	BOOLEAN allocated_resource = FALSE;
	struct mapping* mapping = NULL;

	if (IsListEmpty(&resource->mappings)) {
		status = resource_alloc(
			resource, request->length, request->protection);
		if (!NT_SUCCESS(status)) {
			return status;
		}
		allocated_resource = TRUE;
	}

	/* MmMapLockedPagesSpecifyCache(UserMode) may raise a SEH exception. */
	__try {
		address = MmMapLockedPagesSpecifyCache(
			resource->mdl, UserMode, MmNonCached,
			request->address, FALSE, NormalPagePriority);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		address = NULL;
	}
	if (address == NULL) {
		TraceEvents(TRACE_LEVEL_ERROR, TRACE_MAPPING,
			"MmMapLockedPagesSpecifyCache(mdl=%#p, address=%#p) raised an exception",
			resource->mdl, request->address);
		status = STATUS_UNSUCCESSFUL;
		goto error;
	}

	mapping = ExAllocatePoolWithTag(
		PagedPool, sizeof(*mapping), USERPCI_POOL_TAG);
	if (mapping == NULL) {
		TraceEvents(TRACE_LEVEL_ERROR, TRACE_MAPPING,
			"ExAllocatePoolWithTag(%llu) failed",
			sizeof(*mapping));
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto error;
	}

	mapping->address = address;
	mapping->length = request->length;
	mapping->process_id = request->process_id;
	mapping->resource = resource;
	InsertTailList(&resource->mappings, &mapping->resource_mappings);

	*usermode_address = address;
	return STATUS_SUCCESS;

error:
	if (allocated_resource)
		resource_free(resource);
	return status;
}

/**
 * Invoke MmUnmapLockedPages() in the context of a given process.
 */
static VOID
unmap_locked_pages_in_process(
	HANDLE process_id, PVOID mapped_address, PMDL mdl) {
	KAPC_STATE apc;
	PEPROCESS process;
	NTSTATUS status;

	if (process_id == PsGetCurrentProcessId()) {
		/* Current process address space is the needed one. */
		MmUnmapLockedPages(mapped_address, mdl);
		return;
	}

	status = PsLookupProcessByProcessId(process_id, &process);
	if (!NT_SUCCESS(status)) {
		TraceEvents(TRACE_LEVEL_ERROR, TRACE_MAPPING,
			"PsLookupProcessByProcessId(%!HANDLE!) -> %!STATUS!",
			process_id, status);
		/* Should not happen unless process removal was missed. */
		return;
	}

	/* Temporarily switch to remote process address space for unmapping. */
	KeStackAttachProcess(process, &apc);
	MmUnmapLockedPages(mapped_address, mdl);
	KeUnstackDetachProcess(&apc);
}

VOID
mapping_destroy(struct mapping* mapping)
{
	struct resource* resource = mapping->resource;

	/* Remove the mapping. */
	unmap_locked_pages_in_process(mapping->process_id,
		mapping->address, mapping->resource->mdl);
	RemoveEntryList(&mapping->resource_mappings);
	ExFreePoolWithTag(mapping, USERPCI_POOL_TAG);

	/* Free non-paged pool used for the resource. */
	if (IsListEmpty(&resource->mappings))
		resource_free(resource);
}

NTSTATUS
device_alloc(struct device* device, size_t resource_count)
{
	size_t size = sizeof(*device->resources) * resource_count;

	device->resources = (struct resource*)ExAllocatePoolWithTag(
		PagedPool, size, USERPCI_POOL_TAG);
	if (device->resources == NULL) {
		TraceEvents(TRACE_LEVEL_ERROR, TRACE_MAPPING,
			"ExAllocatePoolWithTag(%llu) failed", size);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	device->resource_count = resource_count;
	RtlZeroMemory(device->resources, size);

	return STATUS_SUCCESS;
}

VOID
device_free(struct device* device)
{
	if (device->resources != NULL)
		ExFreePoolWithTag(device->resources, USERPCI_POOL_TAG);
}

struct mapping*
device_find_mapping(const struct device* device,
	const struct mapping_locator* locator)
{
	size_t i;

	for (i = 0; i < device->resource_count; i++) {
		struct resource* resource = &device->resources[i];
		if (resource->type == RESOURCE_INVALID)
			continue;

		struct mapping* mapping = resource_find_mapping(
			resource, locator);
		if (mapping != NULL)
			return mapping;
	}
	return NULL;
}

VOID
device_unmap_process(struct device *device, HANDLE process_id)
{
	size_t i;
	PLIST_ENTRY entry;

	for (i = 0; i < device->resource_count; i++) {
		struct resource* resource = &device->resources[i];
		if (resource->type != RESOURCE_MEMORY)
			continue;

		FOR_EACH(resource->mappings, entry) {
			struct mapping* mapping = CONTAINING_RECORD(
				entry, struct mapping, resource_mappings);
			if (mapping->process_id == process_id) {
				mapping_destroy(mapping);
			}
		}
	}
}

VOID
device_unmap(struct device* device)
{
	size_t i;
	PLIST_ENTRY entry;

	for (i = 0; i < device->resource_count; i++) {
		struct resource* resource = &device->resources[i];
		if (resource->type != RESOURCE_MEMORY)
			continue;

		FOR_EACH(resource->mappings, entry) {
			struct mapping* mapping = CONTAINING_RECORD(
				entry, struct mapping, resource_mappings);
			mapping_destroy(mapping);
		}
	}
}
