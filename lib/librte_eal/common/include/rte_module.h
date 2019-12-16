#ifndef _RTE_MODULE_H_
#define _RTE_MODULE_H_

/**
 * @file OS-independent facilities for managing dynamic modules (shared objects).
 */

#include <rte_os.h>

enum rte_module_binding {
    RTE_MODULE_BIND_LAZY,
    RTE_MODULE_BIND_NOW
};

rte_module rte_module_load(const char* path, enum rte_module_binding binding);

const char* rte_module_error(void);


#endif
