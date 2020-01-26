#ifndef PCI_WINDOWS_H
#define PCI_WINDOWS_H

#include <rte_bus_pci.h>
#include <rte_os.h>

/* Under Windows, PCI address is not sufficient to locate device interface
 * for communication with the driver, direct path must be stored.
 */
struct windows_pci_device {
	struct rte_pci_device device; /* inherit public structure */
	wchar_t path[PATH_MAX];       /* path to device object to open */
};

#endif