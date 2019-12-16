#ifndef WINDIO_H
#define WINDIO_H

#include <windows.h>
#include <winioctl.h>

#ifdef __cplusplus
extern "C" {
#endif

/* {024385ce-dc9c-4a32-9d9c-064b1c9e454a} */
DEFINE_GUID(GUID_DEVINTERFACE_WINDIO, 0x024385ce, 0xdc9c, 0x4a32, 0x9d, 0x9c, 0x06, 0x4b, 0x1c, 0x9e, 0x45, 0x4a);

#define WINDIO_DEVPATH L"\\Device\\WINDIO"

#define WINDIO_DEVTYPE 0x8000

#define IOCTL_WINDIO_CONFIG_READ  CTL_CODE(WINDIO_DEVTYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINDIO_CONFIG_WRITE CTL_CODE(WINDIO_DEVTYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINDIO_IOPORT_READ  CTL_CODE(WINDIO_DEVTYPE, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINDIO_IOPORT_WRITE CTL_CODE(WINDIO_DEVTYPE, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINDIO_IOPORT_MAP   CTL_CODE(WINDIO_DEVTYPE, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINDIO_IOPORT_UNMAP CTL_CODE(WINDIO_DEVTYPE, 0x813, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINDIO_MEMORY_MAP   CTL_CODE(WINDIO_DEVTYPE, 0x820, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINDIO_MEMORY_UNMAP CTL_CODE(WINDIO_DEVTYPE, 0x821, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINDIO_VIRT2PHYS    CTL_CODE(WINDIO_DEVTYPE, 0x830, METHOD_BUFFERED, FILE_ANY_ACCESS)

struct WINDIO_CONFIG_DATA {
	USHORT offset;
	USHORT size;
	/* here comes (size) bytes of data for write requests */
};

struct WINDIO_IOPORT_MAP_IN {
	int resource;
};

struct WINDIO_IOPORT_DATA {
	int resource;
	USHORT offset;
	BYTE item_size;
	USHORT item_count;
	/* here comes (item_size*item_count) bytes of data for write requests */
};

struct WINDIO_MEMORY_MAP_IN {
	int resource;
	void* address;
	size_t length;
	int protection;
};

struct WINDIO_MEMORY_MAP_OUT {
	void* address;
};

struct WINDIO_MEMORY_UNMAP_IN {
	void* address;
	size_t length;
};

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* WINDIO_H */