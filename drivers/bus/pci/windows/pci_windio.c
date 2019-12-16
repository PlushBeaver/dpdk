#include <wchar.h>

#include <rte_bus_pci.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_tailq.h>
#include <rte_windows.h>

#include "pci_windows.h"
#include "pci_windio.h"
#include "windio.h"

/* Offset to command register in PCI config space. */
#define PCI_COMMAND 0x04

/* Bus mastering bit in PCI command register. */
#define PCI_COMMAND_MASTER 0x0004

static struct rte_tailq_elem rte_windio_tailq = {
	.name = "WINDIO_RESOURCE_LIST",
};
EAL_REGISTER_TAILQ(rte_windio_tailq)

static const char*
pci_system_strerror(DWORD last_error_code) {
    static char *last_error_text = NULL;

    if (last_error_text) {
        LocalFree(last_error_text);
    }

    FormatMessage(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER,
            NULL,
            last_error_code,
            0 /* default language */,
            (char*)&last_error_text,
            0 /* no minimum allocation */,
            NULL);

    return last_error_text;
}

static void*
winuio_mmap(rte_fd fd, int bar, void *address, size_t length)
{
    struct WINDIO_MEMORY_MAP_IN in;
    struct WINDIO_MEMORY_MAP_OUT out;
    DWORD bytes_returned = 0;

    in.resource = bar;
    in.address = address;
    in.length = length;
    in.protection = PAGE_READWRITE;
    if (!DeviceIoControl(
            fd, IOCTL_WINDIO_MEMORY_MAP,
            &in, sizeof(in), &out, sizeof(out),
            &bytes_returned, NULL)) {
        RTE_LOG_SYSTEM_ERROR("DeviceIoControl()");
        return NULL;
    }

    return out.address;
}

static int
winuio_munmap(rte_fd fd, void* address, size_t length)
{
    struct WINDIO_MEMORY_UNMAP_IN in;
    DWORD bytes_returned = 0;

    in.address = address;
    in.length = length;
    if (!DeviceIoControl(
            fd, IOCTL_WINDIO_MEMORY_UNMAP,
            &in, sizeof(in), NULL, 0,
            &bytes_returned, NULL)) {
        RTE_LOG_SYSTEM_ERROR("DeviceIoControl()");
        return -EIO;
    }

    return 0;
}

static int
pci_windio_set_bus_master(struct rte_intr_handle *intr)
{
    uint16_t reg;
	int ret;

	ret = pci_windio_read_config(intr, &reg, sizeof(reg), PCI_COMMAND);
	if (ret != sizeof(reg)) {
		RTE_LOG(ERR, EAL,
			"Cannot read command register from PCI config space!\n");
		return -1;
	}

	if (reg & PCI_COMMAND_MASTER) {
		return 0;
    }

	reg |= PCI_COMMAND_MASTER;

	ret = pci_windio_write_config(intr, &reg, sizeof(reg), PCI_COMMAND);
	if (ret != sizeof(reg)) {
		RTE_LOG(ERR, EAL,
			"Cannot write command register to PCI config space!\n");
		return -1;
	}

	return 0;
}

static void
pci_windio_free_resource(
        struct rte_pci_device *dev, struct mapped_pci_resource *res)
{
    if (res) {
	    rte_free(res);
    }

	if (!RTE_FD_INVALID(dev->intr_handle.fd)) {
		CloseHandle(dev->intr_handle.fd);
		dev->intr_handle.fd = RTE_INVALID_FD;
		dev->intr_handle.type = RTE_INTR_HANDLE_UNKNOWN;
	}
}

/**
 * Open driver interface device.
 *
 * @param dev
 *  winio PCI device.
 * 
 * @param fd
 *  Receives devie interface descriptor on success.
 * 
 * @return
 *  * 0 if opened the device;
 *  * 1 if device already opened;
 *  * negative error code on error.
 */
static int
windio_open_device(struct rte_pci_device *dev, rte_fd *fd)
{
    struct windows_pci_device *windev;

    if (!RTE_FD_INVALID(dev->intr_handle.fd)) {
        *fd = dev->intr_handle.fd;
        return 1;
    }

    if (dev->kdrv != RTE_KDRV_WINDIO) {
        return -ENOTSUP;
    }
    windev = (struct windows_pci_device *)dev;

	*fd = CreateFileW(windev->path, 0, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (RTE_FD_INVALID(*fd)) {
		RTE_LOG(ERR, EAL, "cannot open %S: %s\n",
                windev->path, pci_system_strerror(GetLastError()));
        return -EIO;
	}

    return 0;
}

static int
pci_windio_alloc_resource(
        struct rte_pci_device *dev, struct mapped_pci_resource **res)
{
    struct windows_pci_device *windev = (struct windows_pci_device *)dev;
    int ret = 0;

    /* sanity check */
    if (dev->kdrv != RTE_KDRV_WINDIO) {
        return -ENOTSUP;
    }

	/* save fd if in primary process */
	ret = windio_open_device(dev, &dev->intr_handle.fd);
	if (ret < 0) {
        return ret;
    }

    /* TODO: interrupt support */
	dev->intr_handle.type = RTE_INTR_HANDLE_UNKNOWN;

    ret = pci_windio_set_bus_master(&dev->intr_handle);
    if (ret) {
        RTE_LOG(ERR, EAL, "cannot set up bus mastering\n");
        goto error;
    }

	/* allocate the mapping details for secondary processes*/
	*res = rte_zmalloc("WINUIO_RES", sizeof(**res), 0);
	if (*res == NULL) {
		RTE_LOG(ERR, EAL,
                "cannot allocate %" RTE_PRIzu " bytes for resource record",
                sizeof(**res));
        ret = -ENOMEM;
		goto error;
	}

    /* translate UTF-16 path to UTF-8 for storage */
    if (WideCharToMultiByte(
            CP_UTF8, WC_ERR_INVALID_CHARS,
            windev->path, wcslen(windev->path),
            (*res)->path, sizeof((*res)->path),
            NULL, NULL) == 0) {
        RTE_LOG_SYSTEM_ERROR("WideCharToMultiByte()");
        ret = -EINVAL;
        goto error;
    }
	memcpy(&(*res)->pci_addr, &dev->addr, sizeof((*res)->pci_addr));

	return 0;

error:
	pci_windio_free_resource(dev, *res);
	return ret;
}

static int
pci_windio_map_resource(
        struct rte_pci_device *dev, int resource_idx,
        struct mapped_pci_resource *res, int map_idx)
{
    struct rte_mem_resource *resource = &dev->mem_resource[resource_idx];
    struct pci_map *map = &res->maps[map_idx];
    size_t path_size = strlen(res->path);

    map->path = rte_malloc(NULL, path_size, 0);
    if (map->path == NULL) {
        RTE_LOG(ERR, EAL,
                "cannot allocate %" RTE_PRIzu " bytes for resource path\n",
                path_size);
        return -ENOMEM;
    }

    resource->addr = winuio_mmap(
            dev->intr_handle.fd, resource_idx, resource->addr, resource->len);
    if (resource->addr == NULL) {
        RTE_LOG(ERR, EAL, "cannot map resource %d\n", resource_idx);
        return -EIO;
    }

    map->addr = resource->addr;
    map->offset = 0;
    map->phaddr = resource->phys_addr;
    map->size = resource->len;
    strcpy(map->path, res->path);

    return 0;
}

int
pci_windio_map_device(struct rte_pci_device *dev)
{
    int i, map_idx = 0, ret;
	struct mapped_pci_resource *res = NULL;
	struct mapped_pci_res_list *res_list =
		    RTE_TAILQ_CAST(rte_windio_tailq.head, mapped_pci_res_list);

	dev->intr_handle.fd = RTE_INVALID_FD;

	/* TODO: support mapping from multiple processes. */
	if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
		return -ENOTSUP;
    }

	/* allocate uio resource */
	ret = pci_windio_alloc_resource(dev, &res);
	if (ret) {
		return ret;
    }

	for (i = 0; i != PCI_MAX_RESOURCE; i++) {
		uint64_t phys = dev->mem_resource[i].phys_addr;
		if (phys == 0)
			continue;

		ret = pci_windio_map_resource(dev, i, res, map_idx);
		if (ret) {
			goto error;
        }

		map_idx++;
	}

	res->nb_maps = map_idx;

	TAILQ_INSERT_TAIL(res_list, res, next);

	return 0;

error:
	for (i = 0; i < map_idx; i++) {
        struct pci_map *map = &res->maps[i];
		winuio_munmap(dev->intr_handle.fd, map->addr, (size_t)map->size);
		rte_free(map->path);
	}
	pci_windio_free_resource(dev, res);
	return -1;
}

static void
pci_windio_unmap_resource(
        struct rte_pci_device *dev, struct mapped_pci_resource *res)
{
    int i;

    for (i = 0; i < res->nb_maps; i++) {
        struct pci_map *map = &res->maps[i];
		winuio_munmap(dev->intr_handle.fd, map->addr, (size_t)map->size);
		rte_free(map->path);
	}
}

static struct mapped_pci_resource *
pci_windio_find_resource(struct rte_pci_device *dev)
{
	struct mapped_pci_resource *res;
	struct mapped_pci_res_list *res_list =
			RTE_TAILQ_CAST(rte_windio_tailq.head, mapped_pci_res_list);

	if (dev == NULL) {
		return NULL;
    }

	TAILQ_FOREACH(res, res_list, next) {
		if (!rte_pci_addr_cmp(&res->pci_addr, &dev->addr)) {
			return res;
        }
	}
	return NULL;
}

void
pci_windio_unmap_device(struct rte_pci_device *dev)
{
    struct mapped_pci_resource *res;
	struct mapped_pci_res_list *res_list =
			RTE_TAILQ_CAST(rte_windio_tailq.head, mapped_pci_res_list);

	if (dev == NULL) {
		return;
    }

	/* find an entry for the device */
	res = pci_windio_find_resource(dev);
	if (res == NULL)
		return;

	/* TODO: support mapping from multiple processes. */
	if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
		return;
    }

	TAILQ_REMOVE(res_list, res, next);
	pci_windio_unmap_resource(dev, res);
    pci_windio_free_resource(dev, res);
}

int
pci_windio_read_config(const struct rte_intr_handle *intr_handle,
		    void *buf, size_t len, off_t offset)
{
    struct WINDIO_CONFIG_DATA in;
    DWORD bytes_read = 0;

    in.offset = offset;
    in.size = len;
    if (!DeviceIoControl(
            intr_handle->fd,
            IOCTL_WINDIO_CONFIG_READ,
            &in, sizeof(in), buf, len,
            &bytes_read, NULL)) {
        RTE_LOG_SYSTEM_ERROR("DeviceIoControl()");
        return -EIO;
    }
    return bytes_read;
}

int
pci_windio_write_config(const struct rte_intr_handle *intr_handle,
		     const void *buf, size_t len, off_t offset)
{
	struct WINDIO_CONFIG_DATA *in = NULL;
    DWORD bytes_written = 0;
    BOOL ret;

    in = malloc(sizeof(*in) + len);
    if (in == NULL) {
        return -ENOMEM;
    }

    in->offset = offset;
    in->size = len;
    memcpy(in + 1, buf, len);
    ret = DeviceIoControl(
            intr_handle->fd,
            IOCTL_WINDIO_CONFIG_WRITE,
            in, sizeof(*in) + len, NULL, 0,
            &bytes_written, NULL);

    free(in);

    if (!ret) {
        RTE_LOG_SYSTEM_ERROR("DeviceIoControl()");
        return -EIO;
    }
    return bytes_written;
}

int
pci_windio_ioport_map(
        struct rte_pci_device *dev, int bar, struct rte_pci_ioport *p)
{
    rte_fd device;
    int open_ret, ret = 0;
    struct WINDIO_IOPORT_MAP_IN in;

    RTE_SET_USED(p);

    open_ret = windio_open_device(dev, &device);
    if (open_ret < 0) {
        return open_ret;
    }

    in.resource = bar;
    if (!DeviceIoControl(
            dev->intr_handle.fd,
            IOCTL_WINDIO_IOPORT_MAP,
            &in, sizeof(in), NULL, 0,
            NULL, NULL)) {
        RTE_LOG_SYSTEM_ERROR("DeviceIoControl()");
        ret = -EIO;
    }

    if (open_ret == 0) {
        CloseHandle(device);
    }
    return ret;
}

int
pci_windio_ioport_unmap(struct rte_pci_ioport *p)
{
    RTE_SET_USED(p);
    return 0;
}

static int
winuio_ioport_read(rte_fd fd, int bar, off_t offset,
        uint8_t item_size, uint16_t item_count, void* data)
{
    struct WINDIO_IOPORT_DATA in;
    DWORD bytes_read = 0;

    in.resource = bar;
    in.offset = offset;
    in.item_size = item_size;
    in.item_count = item_count;
    if (!DeviceIoControl(
            fd, IOCTL_WINDIO_IOPORT_READ,
            &in, sizeof(in), data, item_size * item_count,
            &bytes_read, NULL)) {
        RTE_LOG_SYSTEM_ERROR("DeviceIoControl()");
        return -EIO;
    }
    return bytes_read;
}

void
pci_windio_ioport_read(struct rte_pci_ioport *p,
		void *data, size_t len, off_t offset)
{
    rte_fd fd = p->dev->intr_handle.fd;
    uint8_t *out = (uint8_t *)data;
    uint16_t count;

    count = len / 4;
    if (count) {
        int size = count * sizeof(uint32_t);
        if (winuio_ioport_read(
                fd, p->bar, offset, sizeof(uint32_t), count, out) != size) {
            return;
        }
        offset += size;
        out += size;
        len -= size;
    }

    if (len >= 2) {
        int size = sizeof(uint16_t);
        if (winuio_ioport_read(
                fd, p->bar, offset, sizeof(uint16_t), 1, out) != size) {
            return;
        }
        offset += size;
        out += size;
        len -= size;
    }

    if (len >= 1) {
        winuio_ioport_read(fd, p->bar, offset, sizeof(uint8_t), 1, out);
    }
}

static int
winuio_ioport_write(rte_fd fd, int bar, off_t offset,
        uint8_t item_size, uint16_t item_count, const void* data)
{
    struct WINDIO_IOPORT_DATA *in = NULL;
    size_t data_size = item_size * item_count;
    size_t total_size = sizeof(*in) + data_size;
    DWORD bytes_written = 0;
    BOOL ret;

    in = malloc(total_size);
    if (in == NULL) {
        return -ENOMEM;
    }

    in->resource = bar;
    in->offset = offset;
    in->item_size = item_size;
    in->item_count = item_count;
    memcpy(in + 1, data, data_size);
    ret = DeviceIoControl(
            fd, IOCTL_WINDIO_IOPORT_WRITE,
            in, total_size, NULL, 0,
            &bytes_written, NULL);

    free(in);

    if (!ret) {
        RTE_LOG_SYSTEM_ERROR("DeviceIoControl()");
        return -EIO;
    }
    return bytes_written;
}

void
pci_windio_ioport_write(struct rte_pci_ioport *p,
		const void *data, size_t len, off_t offset)
{
    rte_fd fd = p->dev->intr_handle.fd;
    const uint8_t *in = (const uint8_t *)data;
    uint16_t count;

    count = len / 4;
    if (count) {
        int size = count * sizeof(uint32_t);
        if (winuio_ioport_write(
                fd, p->bar, offset, sizeof(uint32_t), count, in) != size) {
            return;
        }
        offset += size;
        in += size;
        len -= size;
    }

    if (len >= 2) {
        int size = sizeof(uint16_t);
        if (winuio_ioport_write(
                fd, p->bar, offset, sizeof(uint16_t), 1, in) != size) {
            return;
        }
        offset += size;
        in += size;
        len -= size;
    }

    if (len >= 1) {
        winuio_ioport_write(fd, p->bar, offset, sizeof(uint8_t), 1, in);
    }
}
