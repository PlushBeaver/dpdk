#ifndef PCI_WINDIO_H
#define PCI_WINDIO_H

#include <rte_bus_pci.h>

int pci_userpci_map_device(struct rte_pci_device *dev);
void pci_userpci_unmap_device(struct rte_pci_device *dev);

int pci_userpci_read_config(const struct rte_intr_handle *intr_handle,
		void *buf, size_t len, off_t offset);
int pci_userpci_write_config(const struct rte_intr_handle *intr_handle,
		const void *buf, size_t len, off_t offset);

int pci_userpci_ioport_map(
        struct rte_pci_device *dev, int bar, struct rte_pci_ioport *p);
int pci_userpci_ioport_unmap(
        struct rte_pci_ioport *p);
void pci_userpci_ioport_read(
        struct rte_pci_ioport *p, void *data, size_t len, off_t offset);
void pci_userpci_ioport_write(
        struct rte_pci_ioport *p, const void *data, size_t len, off_t offset);

#endif