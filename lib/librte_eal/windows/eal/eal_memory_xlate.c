#include <rte_memory.h>
#include <rte_os.h>
#include <rte_windows.h>

/* must come after <windows.h> */
#include <setupapi.h>
#include <winioctl.h>

/* from driver folder */
#include <virt2phys.h>

static HANDLE s_device = INVALID_HANDLE_VALUE;

static int
mem_open_device(void)
{
    HDEVINFO list = INVALID_HANDLE_VALUE;
    SP_DEVICE_INTERFACE_DATA ifdata;
    SP_DEVICE_INTERFACE_DETAIL_DATA *detail = NULL;
	DWORD detail_size;
    int ret = -1;
  
    list = SetupDiGetClassDevs(
            &GUID_DEVINTERFACE_VIRT2PHYS, NULL, NULL,
            DIGCF_DEVICEINTERFACE | DIGCF_PRESENT);
    if (list == INVALID_HANDLE_VALUE) {
        RTE_LOG_SYSTEM_ERROR("SetupDiGetClassDevs()");
        goto exit;
    }

    ifdata.cbSize = sizeof(ifdata);
    if (!SetupDiEnumDeviceInterfaces(
            list, NULL, &GUID_DEVINTERFACE_VIRT2PHYS, 0, &ifdata)) {
        RTE_LOG_SYSTEM_ERROR("SetupDiEnumDeviceInterfaces()");
        goto exit;
    }

    if (!SetupDiGetDeviceInterfaceDetail(
			list, &ifdata, NULL, 0, &detail_size, NULL)) {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            RTE_LOG_SYSTEM_ERROR("SetupDiGetDeviceInterfaceDetail(probe)");
            goto exit;
        }
    }

    detail = malloc(detail_size);
    if (detail == NULL) {
        RTE_LOG(ERR, EAL,
                "Cannot allocate virt2phys device interface detail data\n");
        goto exit;
    }

    detail->cbSize = sizeof(*detail);
    if (!SetupDiGetDeviceInterfaceDetail(
            list, &ifdata, detail, detail_size, NULL, NULL)) {
        RTE_LOG_SYSTEM_ERROR("SetupDiGetDeviceInterfaceDetail(read)");
        goto exit;
    }

    RTE_LOG(DEBUG, EAL, "Found virt2phys device: %s\n", detail->DevicePath);

    s_device = CreateFile(
            detail->DevicePath, 0, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (s_device == INVALID_HANDLE_VALUE) {
        RTE_LOG_SYSTEM_ERROR("CreateFile()");
        goto exit;
    }

    /* Indicate success. */
    ret = 0;

exit:
    if (detail != NULL) {
        free(detail);
    }
    if (list != INVALID_HANDLE_VALUE) {
        SetupDiDestroyDeviceInfoList(list);
    }

    return ret;
}

phys_addr_t
rte_mem_virt2phy(const void *virt)
{
    LARGE_INTEGER phys;
    DWORD bytes_returned;

    /* Open device on demand so that application would not require a driver
     * if it needs no physical addresses (e.g. vdev without hugepages).
     * 
     * TODO: thread safety?
     */
    if ((s_device == INVALID_HANDLE_VALUE) && mem_open_device()) {
        RTE_LOG(ERR, EAL, "Cannot open virt2phys device\n");
        return RTE_BAD_IOVA;
    }

    if (!DeviceIoControl(
            s_device, IOCTL_VIRT2PHYS_TRANSLATE,
            &virt, sizeof(virt), &phys, sizeof(phys),
            &bytes_returned, NULL)) {
        RTE_LOG_SYSTEM_ERROR("DeviceIoControl()");
        return RTE_BAD_PHYS_ADDR;
    }

    return phys.QuadPart;
}

rte_iova_t
rte_mem_virt2iova(const void *virt)
{
    phys_addr_t phys = rte_mem_virt2phy(virt);
    if (phys == RTE_BAD_PHYS_ADDR) {
        return RTE_BAD_IOVA;
    }
    return (rte_iova_t)phys;
}
