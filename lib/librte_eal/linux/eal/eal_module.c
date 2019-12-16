
#include <dlfcn.h>
#include <errno.h>

#include <rte_errno.h>
#include <rte_module.h>

rte_module
rte_module_load(const char* path, enum rte_module_binding binding)
{
    int sys_flags = 0;

    switch (binding) {
    case RTE_MODULE_BIND_LAZY:
        sys_flags = RTLD_LAZY;
        break;
    case RTE_MODULE_BIND_NOW:
        sys_flags = RTLD_NOW;
        break;
    default:
        rte_errno = EINVAL;
        return RTE_INVALID_MODULE;
    }

    return dlopen(path, sys_flags);
}

const char*
rte_module_error(void)
{
    return dlerror();
}