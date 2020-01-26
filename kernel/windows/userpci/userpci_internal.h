/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef USERPCI_INTERNAL_H
#define USERPCI_INTERNAL_H

#include "userpci.h"

/** Driver memory pool tag. */
#define USERPCI_POOL_TAG 'icpu'

/**
 * Resource type.
 */
enum resource_type {
	RESOURCE_INVALID, /**< Resource cannot be used. */
	RESOURCE_MEMORY,  /**< Resource is a memory to be mapped. */
	RESOURCE_PORT     /**< Resource is a non-mapped I/O port. */
};

/**
 * Parameters of a new user-mode mapping to create.
 */
struct mapping_request {
        /** Process in the address pace of which to map memory. */
	HANDLE process_id;
        /** Optional desired user-space address of the mapping. */
	PVOID address;
        /** Size of the region to map. Must not exceed resource length. */
	size_t length;
        /** Mapped memory protection flags. Cannot contain execute bit. */
	ULONG protection;
};

/**
 * Description of an existing user-mode mapping to locate.
 */
struct mapping_locator {
	HANDLE process_id;
	PVOID address;
};

/**
 * User-mode memory mapping.
 */
struct mapping {
	PVOID address;                /**< User-mode virtual address. */
	size_t length;                /**< Mapped region length. */
	HANDLE process_id;            /**< Owning process of user-mode memory. */
	struct resource* resource;    /**< Parent resource. */
	LIST_ENTRY resource_mappings; /**< Entry in the parent list. */
};

/**
 * Map hardware resource into user-space.
 *
 * A new mapping is allocated and added to the resource mapping list.
 * If the resource is not yet mapped to kernel-space, this function maps it
 * before creating a mapping from kernel-space to user-space. 
 *
 * Note: this function must be called from the context of a process
 * to address space of which the mapping must be performed.
 *
 * @param resource
 *  Hardware resoruce to map.
 * @param request
 *  Parameters of the mapping to create.
 * @param usermode_address
 *  Receives a user-mode address of the mapped memory.
 * @return
 *  Status of the operation.
 */
NTSTATUS mapping_create(struct resource* resource,
	struct mapping_request* request, PVOID *usermode_address);

/**
 * Remove a user-space mapping.
 *
 * The mapping is removed from the resource mapping list and deallocated.
 * If the last mapping of a resource is removed, the resource is unmapped
 * from kernel-space to conserve non-paged pool.
 *
 * Note: this function can be called from the context of an arbitrary process.
 *
 * @param mapping
 *  Mapping to be removed.
 */
VOID mapping_destroy(struct mapping* mapping);

/**
 * Device memory or port resource.
 */
struct resource {
	/** Resource type. */
	enum resource_type type;
	/** Translated physical address (logical address). */
	PHYSICAL_ADDRESS physical_address;
	/** Kernel-mode mapping address. */
	PVOID kernel_address;              
	/** Length of both physical resource and kernel-mode mapping. */
	ULONG length;
	/** Memory Descriptor List of kernel-mode mapping. */
	PMDL mdl;
	/** Head of user-mode mappings list. */
	LIST_ENTRY mappings;               
};

/**
 * Initialize a new allocated resource.
 */
VOID resource_init(struct resource* resource);

/**
 * PCI address.
 */
struct pci_addr {
	UINT16 bus;
	UINT8 device;
	UINT8 function;
};

/**
 * Device-private data ("context" in WDF, "extension" in WDM).
 * Framework requires a typedef for various macros to work.
 */
typedef struct device {
	struct pci_addr address;    /**< PCI address. */
	BUS_INTERFACE_STANDARD bus; /**< PCI bus interface operations. */
	struct resource* resources; /**< Resources array. */
	size_t resource_count;      /**< Number of resources. */
} DeviceContext;

/** Allocate device context resources, exceppt the context itself. */
NTSTATUS device_alloc(struct device* device, size_t resource_count);

/** Free device context resources, except the context itself. */
VOID device_free(struct device* device);

/** Remove mappings of all device resources in a process. */
VOID device_unmap_process(struct device* device, HANDLE process_id);

/** Unmap all device resources in all processes. */
VOID device_unmap(struct device* device);

/**
 * Find a specified user-mode mapping of a device resource.
 *
 * @param device
 *  Device with a required resource.
 * @param locator
 *  Mapping identification.
 * @return
 *  Pointer to the mapping or NULL if mapping not found.
 */
struct mapping* device_find_mapping(const struct device* device,
	const struct mapping_locator* locator);

VOID ioport_read(void* port, BYTE item_size, USHORT item_count, void* out);
VOID ioport_write(void* port, BYTE item_size, USHORT item_count, void* in);

NTSTATUS config_read(
	const BUS_INTERFACE_STANDARD *bus, USHORT offset, USHORT size,
	void* out, ULONG *bytes_read);
NTSTATUS config_write(
	const BUS_INTERFACE_STANDARD *bus, USHORT offset, USHORT size,
	void* in, ULONG *bytes_written);

#endif
