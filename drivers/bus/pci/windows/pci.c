/* Use Unicode for everything as Setup API has no ANSI version. */
#define UNICODE

#include <rte_bus_pci.h>
#include <rte_eal.h>
#include <rte_log.h>
#include <rte_os.h>
#include <rte_windows.h>

#include "pci_windows.h"
#include "pci_windio.h"
#include "private.h"
#include "windio.h"

#include <cfgmgr32.h>
#include <setupapi.h>

DEFINE_DEVPROPKEY(DEVPKEY_Device_BusNumber,   0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0, 23);
DEFINE_DEVPROPKEY(DEVPKEY_Device_Address,     0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0, 30);
DEFINE_DEVPROPKEY(DEVPKEY_Device_HardwareIds, 0xa45c254e, 0xdf1c, 0x4efd, 0x80, 0x20, 0x67, 0xd1, 0x46, 0xa8, 0x50, 0xe0, 3);
DEFINE_DEVPROPKEY(DEVPKEY_Device_InstanceId,  0x78c34fc8, 0x104a, 0x4aca, 0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57, 256);
DEFINE_DEVPROPKEY(DEVPKEY_Device_Numa_Node,   0x540b947e, 0x8b40, 0x45bc, 0xa8, 0xa2, 0x6a, 0x0b, 0x89, 0x4c, 0xbd, 0xa2, 3);

#define PCI_LOG_CFGMGR_ERROR(fmt, ret, ...) do { \
			RTE_LOG(ERR, EAL, "%s(): cfgmgr32 error 0x%lx from " fmt "\n", \
					__func__, ret, ##__VA_ARGS__); \
		} while (0)

int
rte_pci_map_device(struct rte_pci_device *dev)
{
	switch (dev->kdrv) {
	case RTE_KDRV_WINDIO:
		return pci_windio_map_device(dev);
	default:
		RTE_LOG(DEBUG, EAL,
			"  Not managed by a supported kernel driver, skipped\n");
		return 1;
	}
}

void
rte_pci_unmap_device(struct rte_pci_device *dev __rte_unused)
{
	switch (dev->kdrv) {
	case RTE_KDRV_WINDIO:
		pci_windio_unmap_device(dev);
		break;
	default:
		RTE_LOG(DEBUG, EAL,
			"  Not managed by a supported kernel driver, skipped\n");
		break;
	}
}

int
rte_pci_read_config(const struct rte_pci_device *device,
		void *buf, size_t len, off_t offset)
{
	char devname[RTE_DEV_NAME_MAX_LEN] = "";
	const struct rte_intr_handle *intr_handle = &device->intr_handle;

	switch (device->kdrv) {
	case RTE_KDRV_WINDIO:
		return pci_windio_read_config(intr_handle, buf, len, offset);
	default:
		rte_pci_device_name(&device->addr, devname, RTE_DEV_NAME_MAX_LEN);
		RTE_LOG(ERR, EAL, "Unknown driver type for %s\n", devname);
		return -ENOTSUP;
	}
}

int
rte_pci_write_config(const struct rte_pci_device *device,
		const void *buf, size_t len, off_t offset)
{
	char devname[RTE_DEV_NAME_MAX_LEN] = "";
	const struct rte_intr_handle *intr_handle = &device->intr_handle;

	switch (device->kdrv) {
	case RTE_KDRV_WINDIO:
		return pci_windio_write_config(intr_handle, buf, len, offset);
	default:
		rte_pci_device_name(&device->addr, devname, RTE_DEV_NAME_MAX_LEN);
		RTE_LOG(ERR, EAL, "Unknown driver type for %s\n", devname);
		return -ENOTSUP;
	}
}

int
rte_pci_ioport_map(struct rte_pci_device *dev, int bar,
		struct rte_pci_ioport *p)
{
	int ret = -ENOTSUP;

	switch (dev->kdrv) {
	case RTE_KDRV_WINDIO:
		ret = pci_windio_ioport_map(dev, bar, p);
		break;
	default:
		break;
	}

	if (!ret) {
		p->dev = dev;
		p->bar = bar;
	}

	return ret;
}

int
rte_pci_ioport_unmap(struct rte_pci_ioport *p)
{
	switch (p->dev->kdrv) {
	case RTE_KDRV_WINDIO:
		return pci_windio_ioport_unmap(p);
	default:
		return -ENOTSUP;
	}
}

void
rte_pci_ioport_read(struct rte_pci_ioport *p,
		void *data, size_t len, off_t offset)
{
	switch (p->dev->kdrv) {
	case RTE_KDRV_WINDIO:
		pci_windio_ioport_read(p, data, len, offset);
		break;
	default:
		break;
	}
}

void
rte_pci_ioport_write(struct rte_pci_ioport *p,
		const void *data, size_t len, off_t offset)
{
	switch (p->dev->kdrv) {
	case RTE_KDRV_WINDIO:
		pci_windio_ioport_write(p, data, len, offset);
		break;
	default:
		break;
	}
}

/* No IOMMU control on Windows, advertise no support. */
bool
pci_device_iommu_support_va(__rte_unused const struct rte_pci_device *dev)
{
	return false;
}

/* No IOMMU control on Windows, thus only PA is available. */
enum rte_iova_mode
pci_device_iova_mode(
		__rte_unused const struct rte_pci_driver *pdrv,
		__rte_unused const struct rte_pci_device *pdev)
{
	return RTE_IOVA_PA;
}

/* Get a variable-length textual property, (re)allocating buffer for it.
 * If buffer is not yet allocated, it must be NULL.
 */
static int
pci_get_device_property_string(HDEVINFO list, SP_DEVINFO_DATA *devinfo,
		DEVPROPKEY key, wchar_t **buffer)
{
	DWORD size = 0;
	DEVPROPTYPE type;

	/* probe the amount of required space */
    if (!SetupDiGetDevicePropertyW(
            list, devinfo, &key, &type, NULL, 0, &size, 0)) {
		switch (GetLastError()) {
		case ERROR_INSUFFICIENT_BUFFER:
			break;
		case ERROR_NOT_FOUND:
			return -ENOENT;
		default:
			RTE_LOG_SYSTEM_ERROR("SetupDiGetDeviceProperty(probe)");
			return -EINVAL;
		}
    }

    *buffer = (wchar_t *)realloc(*buffer, size);
	if (*buffer == NULL) {
		RTE_LOG(DEBUG, EAL, "Cannot allocate %lu bytes\n", size);
		return -ENOMEM;
	}

	/* actually read property value */
    if (!SetupDiGetDevicePropertyW(
            list, devinfo, &key, &type, (PBYTE)*buffer, size, &size, 0)) {
        RTE_LOG_SYSTEM_ERROR("SetupDiGetDeviceProperty(read)");
        return -EINVAL;
    }

    return 0;
}

static int
pci_get_device_property(HDEVINFO list, SP_DEVINFO_DATA *devinfo,
		DEVPROPKEY key, void *buffer, size_t buffer_size)
{
	DWORD size = 0;
	DEVPROPTYPE type;

	/* probe the amount of required space */
    if (!SetupDiGetDevicePropertyW(
            list, devinfo, &key, &type, NULL, 0, &size, 0)) {
		switch (GetLastError()) {
		case ERROR_INSUFFICIENT_BUFFER:
			break;
		case ERROR_NOT_FOUND:
			return -ENOENT;
		default:
			RTE_LOG_SYSTEM_ERROR("SetupDiGetDeviceProperty(probe)");
			return -EINVAL;
		}
    }

	/* cancel reading if supplied buffer is too small */
	if (size > buffer_size) {
		return -EMSGSIZE;
	}

	/* actually read property value */
    if (!SetupDiGetDevicePropertyW(
            list, devinfo, &key, &type, buffer, size, &size, 0)) {
        RTE_LOG_SYSTEM_ERROR("SetupDiGetDeviceProperty(read)");
        return -EINVAL;
    }

    return 0;
}

static int
pci_get_device_address(
		HDEVINFO list, SP_DEVINFO_DATA *devinfo, struct rte_pci_addr *addr)
{
	uint32_t bus, address;
	int ret;

	ret = pci_get_device_property(
		list, devinfo, DEVPKEY_Device_BusNumber, &bus, sizeof(bus));
	if (ret) {
		RTE_LOG(DEBUG, EAL, "cannot get device PCI bus number\n");
		return -1;
	}

	ret = pci_get_device_property(
		list, devinfo, DEVPKEY_Device_Address, &address, sizeof(address));
	if (ret) {
		RTE_LOG(DEBUG, EAL, "cannot get device PCI bus address\n");
		return -1;
	}

	/* Windows allows 16-bit BDF values, but API takes 8 bits only */
	addr->domain = 0;
	addr->bus = bus & 0xff;
	addr->devid = (address >> 16) & 0xFF;
	addr->function = address & 0xFF;
	return 0;
}

static int
pci_scan_memory_resource(
		RES_DES resource_desc, MEM_RESOURCE **resource,
		struct rte_pci_device* dev, size_t index)
{
	ULONG size = 0;
	DWORD count;
	CONFIGRET ret;

	ret = CM_Get_Res_Des_Data_Size(&size, resource_desc, 0);
	if (ret != CR_SUCCESS) {
		PCI_LOG_CFGMGR_ERROR("CM_Get_Res_Des_Data_Size()", ret);
		return -1;
	}

	*resource = (MEM_RESOURCE *)realloc(*resource, size);
	if (!*resource)  {
		RTE_LOG(DEBUG, EAL, "Cannot allocate %lu bytes "
				"for resource data\n", size);
		return -1;
	}

	ret = CM_Get_Res_Des_Data(resource_desc, *resource, size, 0);
	if (ret != CR_SUCCESS) {
		PCI_LOG_CFGMGR_ERROR("CM_Get_Res_Des_Data()", ret);
		return -1;
	}

	count = (*resource)->MEM_Header.MD_Count;
	if (count == 0) {
		phys_addr_t base = (*resource)->MEM_Header.MD_Alloc_Base;
		size_t length = (*resource)->MEM_Header.MD_Alloc_End - base + 1;
		dev->mem_resource[index].phys_addr = base;
		dev->mem_resource[index].len = length;
		dev->mem_resource[index].addr = NULL;
	}
	else {
		/* TODO: support requirements list? */
		RTE_LOG(WARNING, EAL, "Requirements lists not supported\n");
		return -ENOTSUP;
	}

	return 0;
}

static int
pci_scan_resources(wchar_t *instance_id, struct rte_pci_device* dev)
{
	DEVINST devinst;
	LOG_CONF logical_conf;
	RES_DES resource_desc;
	RESOURCEID type;
	MEM_RESOURCE *resource = NULL;
	CONFIGRET ret;
	int logical_conf_allocated = 0;
	int resource_desc_allocated = 0;
	int i;

	ret = CM_Locate_DevNode(&devinst, instance_id, CM_LOCATE_DEVNODE_NORMAL);
	if (ret != CR_SUCCESS) {
		PCI_LOG_CFGMGR_ERROR("CM_Locate_DevNode()", ret);
		goto cleanup;
	}

	ret = CM_Get_First_Log_Conf(&logical_conf, devinst, ALLOC_LOG_CONF);
	if (ret != CR_SUCCESS) {
		ret = CM_Get_First_Log_Conf(&logical_conf, devinst, BOOT_LOG_CONF);
		if (ret != CR_SUCCESS) {
            if (ret == CR_NO_MORE_LOG_CONF) {
                /* no configuration */
                return 0;
            }

			PCI_LOG_CFGMGR_ERROR("CM_Get_First_Log_Conf()", ret);
			goto cleanup;
		}
	}
	logical_conf_allocated = 1;

	ret = CM_Get_Next_Res_Des(
			&resource_desc, logical_conf, ResType_All, &type, 0);
	if (ret != CR_SUCCESS) {
		PCI_LOG_CFGMGR_ERROR("CM_Get_Next_Res_Des()", ret);
		goto cleanup;
	}
	resource_desc_allocated = 1;

	for (i = 0; i < PCI_MAX_RESOURCE; i++) {
		if ((type == ResType_Mem) &&
				pci_scan_memory_resource(resource_desc, &resource, dev, i)) {
			RTE_LOG(ERR, EAL, "Cannot scan memory BAR %d\n", i);
			goto cleanup;
		}

		ret = CM_Get_Next_Res_Des(
                &resource_desc, resource_desc, ResType_All, &type, 0);
        if (ret != CR_SUCCESS){
            if (ret == CR_NO_MORE_RES_DES) {
                break;
            }

            PCI_LOG_CFGMGR_ERROR("CM_Get_Next_Res_Des()", ret);
            goto cleanup;
        }
	}

cleanup:
	if (resource) {
		free(resource);
	}
	if (resource_desc_allocated) {
		CM_Free_Res_Des_Handle(resource_desc);
	}
	if (logical_conf_allocated) {
		CM_Free_Res_Des_Handle(logical_conf);	
	}

	switch (ret) {
	case CR_SUCCESS:
		/* Maximum number of resources scanned. */
	case CR_NO_MORE_RES_DES:
		/* All available resources scanned. */
		return 0;
	default:
		return -1;
	}
}

static int
pci_get_device_driver_path(
		HDEVINFO list,
		SP_DEVICE_INTERFACE_DATA *ifdata,
		struct windows_pci_device *dev)
{
	SP_DEVICE_INTERFACE_DETAIL_DATA *detail = NULL;
	DWORD detail_size;

	if (!SetupDiGetDeviceInterfaceDetail(
			list, ifdata, NULL, 0, &detail_size, NULL)) {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            RTE_LOG_SYSTEM_ERROR("SetupDiGetDeviceInterfaceDetail(probe)");
            return -EINVAL;
        }
    }

	if (detail_size > sizeof(dev->path)) {
		return -EMSGSIZE;
	}

    detail = malloc(detail_size);
    if (detail == NULL) {
        return -ENOMEM;
    }

    detail->cbSize = sizeof(*detail);
    if (!SetupDiGetDeviceInterfaceDetail(
            list, ifdata, detail, detail_size, NULL, NULL)) {
        RTE_LOG_SYSTEM_ERROR("SetupDiGetDeviceInterfaceDetail(read)");
		free(detail);
        return -EINVAL;
    }

	wcscpy(dev->path, detail->DevicePath);
	free(detail);
	return 0;
}

/**
 * Determine kernel driver and locate device driver interface if possible.
 * 
 * Per documentation, we should call SetupDiGetClassDevs()
 * with DIGCF_DEVICEINTERFACE set and then enumerate supported interfaces
 * for each device. However, SetupDiGetClassDevs() fails with such flags.
 * Instead, for a given device instance ID, we are enumerating all known
 * driver GUIDs and check if device supports the driver interface.
 * 
 * @param instance_id
 * 	Device instance ID.
 * 
 * @param dev
 * 	Device structure to be filled. At least @code dev->device.kdrv @endcode
 * 	is set, and for supported drivers @code dev->path @endcode is filled.
 * 
 * @return
 * 	- non-negative value if driver is identified and interface is located;
 * 	- negative error code on failure.
 */
static int
pci_get_device_driver(
		const wchar_t* instance_id,
		struct windows_pci_device *dev)
{
	/* GUID is not a compile-time constant, but its address is. */
	struct pci_driver_guid {
		const GUID *guid;
		enum rte_kernel_driver driver;
	};

	static struct pci_driver_guid table[] = {
		{
			.guid = &GUID_DEVINTERFACE_WINDIO,
			.driver = RTE_KDRV_WINDIO
		}
	};

	HDEVINFO list = INVALID_HANDLE_VALUE;
	int ret = 1;
	DWORD i;    

	dev->device.kdrv = RTE_KDRV_UNKNOWN;
    for (i = 0; (i < RTE_DIM(table)) && (ret > 0); i++) {
        list = SetupDiGetClassDevs(
                table[i].guid,
		instance_id,
		NULL,
		DIGCF_DEVICEINTERFACE | DIGCF_PRESENT);
        if (list == INVALID_HANDLE_VALUE) {
            RTE_LOG_SYSTEM_ERROR("SetupDiGetClassDevs()");
            return -EINVAL;
        }

        SP_DEVICE_INTERFACE_DATA ifdata;
        ifdata.cbSize = sizeof(ifdata);
        if (!SetupDiEnumDeviceInterfaces(
				list, NULL, table[i].guid, 0, &ifdata)) {
        	if (GetLastError() != ERROR_NO_MORE_ITEMS) {
            	RTE_LOG_SYSTEM_ERROR("SetupDiEnumDeviceInterfaces()");
        	}
			goto destroy_list;
		}

		ret = pci_get_device_driver_path(list, &ifdata, dev);
		if (ret) {
			goto destroy_list;
		}

		dev->device.kdrv = table[i].driver;

destroy_list:
        if (!SetupDiDestroyDeviceInfoList(list)) {
            RTE_LOG_SYSTEM_ERROR("SetupDiDestroyDeviceInfoList()");
			return -EINVAL;
        }
    }

	return ret;
}

static int
pci_scan_one(HDEVINFO list, SP_DEVINFO_DATA *devinfo)
{
    wchar_t *hw_ids = NULL;
	wchar_t *hw_id = NULL;
	wchar_t *instance_id = NULL;
	uint32_t numa_node;
	struct windows_pci_device *windev = NULL;
	struct rte_pci_device *dev = NULL;
    struct rte_pci_id* id = NULL;
	int ret;

	windev = malloc(sizeof(*windev));
	if (windev == NULL) {
		RTE_LOG(ERR, EAL, "Cannot allocate %" RTE_PRIzu " bytes for device\n",
				sizeof(*windev));
		return -1;
	}
	dev = &windev->device;
	id = &dev->id;

	memset(dev, 0, sizeof(*windev));
	dev->device.bus = &rte_pci_bus.bus;

	ret = pci_get_device_address(list, devinfo, &dev->addr);
	if (ret) {
		RTE_LOG(ERR, EAL, "Cannot get device address (%d)\n", ret);
		goto error;
	}

	ret = pci_get_device_property_string(
			list, devinfo, DEVPKEY_Device_HardwareIds, &hw_ids);
	if (ret) {
		RTE_LOG(ERR, EAL, "Cannot get hardware IDs (%d)\n", ret);
		goto error;
	}

	/* path = "<ID>\0<ID>\0...\0\0" */
	id->class_id = RTE_CLASS_ANY_ID;
	id->vendor_id = PCI_ANY_ID;
	id->device_id = PCI_ANY_ID;
	id->subsystem_vendor_id = PCI_ANY_ID;
	id->subsystem_device_id = PCI_ANY_ID;
    for (hw_id = hw_ids; *hw_id; hw_id += wcslen(hw_id) + 1) {
		/* try to parse various formats in order of increased generality */
        swscanf(hw_id, L"PCI\\VEN_%04hx&DEV_%04hx&SUBSYS_%04hx%04hx",
                &id->vendor_id, &id->device_id,
				&id->subsystem_device_id, &id->subsystem_vendor_id);
		swscanf(hw_id, L"PCI\\VEN_%04hx&DEV_%04hx",
                &id->vendor_id, &id->device_id);
		swscanf(hw_id, L"PCI\\VEN_%04hx&DEV_%04hx&CC_%x",
				&id->vendor_id, &id->device_id, &id->class_id);
    }
	id->class_id &= RTE_CLASS_ANY_ID;

	/* NUMA node may be undefined */
	ret = pci_get_device_property(list, devinfo, DEVPKEY_Device_Numa_Node,
			&numa_node, sizeof(numa_node));
	if (!ret) {
        dev->device.numa_node = (int)numa_node;
	}

	pci_name_set(dev);

	/* instance ID is used both to find resources and to select a driver */
	ret = pci_get_device_property_string(
			list, devinfo, DEVPKEY_Device_InstanceId, &instance_id);
	if (ret) {
		RTE_LOG(ERR, EAL, "Cannot get instance ID\n");
		goto error;
	}

	ret = pci_scan_resources(instance_id, dev);
	if (ret) {
		RTE_LOG(ERR, EAL, "Cannot enumerate resources\n");
		goto error;
	}

	/* select driver, positive value is not an error */
	ret = pci_get_device_driver(instance_id, windev);
	if (ret < 0) {
		RTE_LOG(ERR, EAL, "Cannot get device driver\n");
		goto error;
	}

	/* device is valid, add in list (sorted) */
	if (TAILQ_EMPTY(&rte_pci_bus.device_list)) {
		rte_pci_add_device(dev);
	}
	else {
		struct rte_pci_device *dev2 = NULL;
		int ret;

		TAILQ_FOREACH(dev2, &rte_pci_bus.device_list, next) {
			ret = rte_pci_addr_cmp(&dev->addr, &dev2->addr);
			if (ret > 0)
				continue;
			else if (ret < 0) {
				rte_pci_insert_device(dev2, dev);
			} else { /* already registered */
				dev2->kdrv = dev->kdrv;
				dev2->max_vfs = dev->max_vfs;
				pci_name_set(dev2);
				memmove(dev2->mem_resource,
						dev->mem_resource,
						sizeof(dev->mem_resource));
				free(dev);
			}
			goto exit;
		}
		rte_pci_add_device(dev);
	}

exit:
	free(hw_ids);
	free(instance_id);
	return 0;

error:
	if (windev)
		free(windev);
	if (hw_ids)
		free(hw_ids);
	if (instance_id)
		free(instance_id);
	return ret;
}

int
rte_pci_scan(void) 
{
    HDEVINFO list;
    DWORD i;

	/* for debug purposes, PCI can be disabled */
	if (!rte_eal_has_pci()) {
		return 0;
	}

    list = SetupDiGetClassDevs(
            NULL, L"PCI", NULL, DIGCF_ALLCLASSES | DIGCF_PRESENT);
    if (list == INVALID_HANDLE_VALUE) {
        RTE_LOG_SYSTEM_ERROR("SetupDiGetClassDevs()");
		return -1;
    }

    
    for (i = 0;; i++) {
		SP_DEVINFO_DATA devinfo;
		devinfo.cbSize = sizeof(devinfo);

        if (!SetupDiEnumDeviceInfo(list, i, &devinfo)) {
            if (GetLastError() != ERROR_NO_MORE_ITEMS) {
                RTE_LOG_SYSTEM_ERROR("SetupDiEnumDeviceInfo()");
            }
            break;
        }

        if (pci_scan_one(list, &devinfo)) {
			break;
		}
    }

    if (!SetupDiDestroyDeviceInfoList(list)) {
		RTE_LOG_SYSTEM_ERROR("SetupDiDestroyDeviceInfoList()");
    }

    return 0;
}
