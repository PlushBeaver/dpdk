#include "pmdinfogen.h"

#if defined(__linux) || defined(__FREEBSD) /* POSIX */

#include <sys/mman.h>

void*
file_map(int fd, size_t size)
{
    return mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
}

void
file_unmap(void* virt, size_t size)
{
    munmap(virt, size);
}

#else /* Windows */

#include <io.h>

#include <windows.h>

void*
file_map(int fd, size_t size)
{
    HANDLE file_handle = INVALID_HANDLE_VALUE;
    HANDLE mapping_handle = INVALID_HANDLE_VALUE;
    LPVOID virt = NULL;

    file_handle = (HANDLE)_get_osfhandle(fd);

    mapping_handle = CreateFileMapping(
            file_handle, NULL, PAGE_READWRITE, 0, 0, NULL);
    if (mapping_handle == INVALID_HANDLE_VALUE) {
        LOG(ERROR, "CreateFileMapping() failed, GetLastError() is %d",
                GetLastError());
        return NULL;
    }

    virt = MapViewOfFileEx(mapping_handle, FILE_MAP_COPY, 0, 0, size, NULL);
    if (!virt) {
        LOG(ERROR, "MapViewOfFileEx() failed, GetLastError() is %d",
                GetLastError());
        return NULL;
    }

    if (!CloseHandle(mapping_handle)) {
        LOG(ERROR, "CloseHandle() failed, GetLastError() is %d",
                GetLastError());
    }

    return virt;
}

void
file_unmap(void* virt, __attribute__((unused)) size_t size)
{
    UnmapViewOfFile(virt);
}

#endif