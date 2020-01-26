/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef USERPCI_H
#define USERPCI_H

/**
 * Driver device interface GUID {024385ce-dc9c-4a32-9d9c-064b1c9e454a}.
 */
DEFINE_GUID(GUID_DEVINTERFACE_USERPCI,
	0x024385ce, 0xdc9c, 0x4a32, 0x9d,0x9c, 0x06,0x4b,0x1c,0x9e,0x45,0x4a);

/**
 * Device type for I/O control codes.
 */
#define USERPCI_DEVTYPE 0x8001

/**
 * Read device PCI configuration space data.
 *
 * Input: @ref userpci_config_data.
 * Output: buffer for the data to read.
 */
#define IOCTL_USERPCI_CONFIG_READ  CTL_CODE(USERPCI_DEVTYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

 /**
  * Write device PCI configuration space data.
  *
  * Input: @ref userpci_config_data followed by the data to write.
  * Output: unused.
  */
#define IOCTL_USERPCI_CONFIG_WRITE CTL_CODE(USERPCI_DEVTYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

/**
 * Read I/O port data.
 *
 * Input: @ref userpci_ioport_data.
 * Output: buffer for the data to read.
 */
#define IOCTL_USERPCI_IOPORT_READ  CTL_CODE(USERPCI_DEVTYPE, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS) /* TODO: direct */

 /**
  * Write I/O port data.
  *
  * Input: @ref userpci_ioport_data followed by the data to write.
  * Output: unused.
  */
#define IOCTL_USERPCI_IOPORT_WRITE CTL_CODE(USERPCI_DEVTYPE, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS) /* TODO: direct */

/**
 * Map an I/O port resource.
 *
 * Input: @ref userpci_ioport_map_in.
 * Output: unused.
 *
 * Since user-mode processes in Windows can never access I/O ports
 * because of insufficient I/O privilege level (IOPL), this request
 * only checks if a resource can be used as an I/O port.
 */
#define IOCTL_USERPCI_IOPORT_MAP   CTL_CODE(USERPCI_DEVTYPE, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS)

/**
 * Unmap I/O port resource.
 *
 * Input: unused. Output: unused.
 *
 * Since I/O port mapping is a no-op, this request does nothing.
 */
#define IOCTL_USERPCI_IOPORT_UNMAP CTL_CODE(USERPCI_DEVTYPE, 0x813, METHOD_BUFFERED, FILE_ANY_ACCESS)

/**
 * Map a memory resource into user-space.
 *
 * Input: @ref userpci_memory_map_in.
 * Output: @ref userpci_memory_map_out.
 */
#define IOCTL_USERPCI_MEMORY_MAP   CTL_CODE(USERPCI_DEVTYPE, 0x820, METHOD_BUFFERED, FILE_ANY_ACCESS)

/**
 * Remove a user-space mapping of a memory resource.
 *
 * Inout: @ref userpci_memory_unmap_in.
 * Ouput: unused.
 *
 * This request must be preformed by the same process that created a mapping.
 */
#define IOCTL_USERPCI_MEMORY_UNMAP CTL_CODE(USERPCI_DEVTYPE, 0x821, METHOD_BUFFERED, FILE_ANY_ACCESS)

/**
 * Location in the PCI configuration space to be read or written.
 * For write requests, the structure is followed by input data.
 */
struct userpci_config_data {
        /** Byte offset in the PCI configuration space. */
	USHORT offset;
        /** Number of bytes to read or write. */
	USHORT size;
};

/**
 * Location in the PCI I/O port space and I/O format specification.
 * For write requests, the structure is followed by input data.
 */
struct userpci_ioport_data {
        /** PCI device resource index. */
	int resource;
        /** Byte offset from the start of I/O port area. */
	USHORT offset;
        /** Data item size: 1, 4, or 8. */
	BYTE item_size;
        /** Data item count. */
	USHORT item_count;
};

/**
 * I/O port resource mapping request.
 */
struct userpci_ioport_map_in {
        /** PCI device resource index. */
        int resource;
};

/**
 * Memory resource mapping request.
 */
struct userpci_memory_map_in {
        /** PCI device resource index. */
	int resource;
        /** Optional desired user-space address to place the mapping. */
	void* address;
        /** Size of the region to map, must not exceed hardware resource size. */
	size_t length;
        /** Mapped region pages protection. Cannot include execute bits. */
	int protection;
};

/**
 * Result of mapping a memory resource.
 */
struct userpci_memory_map_out {
	void* address; /**< User-space address of the created mapping. */
};

/**
 * Memory resource unmapping request.
 */
struct userpci_memory_unmap_in {
	void* address; /**< User-space address of an existing mapping. */
	size_t length; /**< Length of the mapped region. */
};

#endif
