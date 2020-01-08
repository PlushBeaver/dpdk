#include <stdlib.h>
#include <stdio.h>

#include <rte_common.h>
#include <rte_errno.h>
#include <rte_module.h>
#include <rte_windows.h>

static DWORD last_error_code = 0;
static char* last_error_text = NULL;
static char fallback_buffer[32];

static void
module_set_last_error(void)
{
    last_error_code = GetLastError();
    if (last_error_text && (last_error_text != fallback_buffer)) {
        LocalFree(last_error_text);
    }
    last_error_text = NULL;
}

rte_module
rte_module_load(const char* path, enum rte_module_binding binding) {
    wchar_t sys_path[PATH_MAX];
    HANDLE module;

    RTE_SET_USED(binding);

    if (!MultiByteToWideChar(
            CP_UTF8, MB_ERR_INVALID_CHARS,
            path, strlen(path),
            sys_path, sizeof(sys_path))) {
        module_set_last_error();
        return NULL;
    }

    module = LoadLibraryW(sys_path);
    if (!module) {
        module_set_last_error();
    }
    return module;
}

void*
rte_module_symbol(rte_module module, const char* name)
{
    void *symbol = GetProcAddress(module, name);
    if (symbol == NULL) {
        module_set_last_error();
    }
    return symbol;
}

const char*
rte_module_error(void) {
    if (last_error_text) {
        return last_error_text;
    }

    if (FormatMessageA(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER,
            NULL,
            last_error_code,
            0 /* default language */,
            (char*)&last_error_text,
            0 /* no minimum allocation */,
            NULL)) {
        RTE_LOG_SYSTEM_ERROR("FormatMessage(code=%lu)", last_error_code);
        sprintf(fallback_buffer, "<code=%lu>", last_error_code);
        last_error_text = fallback_buffer;
    }

    return last_error_text;
}