#include <io.h>

#include <rte_errno.h>
#include <rte_filesystem.h>
#include <rte_log.h>
#include <rte_windows.h>

int
rte_ftruncate(int fd, ssize_t size)
{
    HANDLE handle;
    DWORD ret;
    LONG low = (LONG)((size_t)size);
    LONG high = (LONG)((size_t)size >> 32);

    handle = (HANDLE)_get_osfhandle(fd);
    if (handle == INVALID_HANDLE_VALUE) {
        rte_errno = EBADF;
        return -1;
    }

    ret = SetFilePointer(handle, low, &high, FILE_BEGIN);
    if (ret == INVALID_SET_FILE_POINTER) {
        RTE_LOG_SYSTEM_ERROR("SetFilePointer()");
        rte_errno = EINVAL;
        return -1;
    }

    return 0;
}

static int
lock_file(HANDLE handle, enum rte_flock_op op, enum rte_flock_mode mode)
{
    DWORD sys_flags = 0;

    if (op == RTE_FLOCK_EXCLUSIVE)
        sys_flags |= LOCKFILE_EXCLUSIVE_LOCK;
    if (mode == RTE_FLOCK_RETURN)
        sys_flags |= LOCKFILE_FAIL_IMMEDIATELY;

    if (!LockFileEx(handle, sys_flags, 0, 0, 0, NULL)) {
        if ((sys_flags & LOCKFILE_FAIL_IMMEDIATELY) &&
                (GetLastError() == ERROR_IO_PENDING)) {
            rte_errno = EWOULDBLOCK;
        } else {
            RTE_LOG_SYSTEM_ERROR("LockFileEx()");
            rte_errno = EINVAL;
        }
        return -1;
    }

    return 0;
}

static int
unlock_file(HANDLE handle)
{
    if (!UnlockFileEx(handle, 0, 0, 0, NULL)) {
        RTE_LOG_SYSTEM_ERROR("UnlockFileEx()");
        rte_errno = EINVAL;
        return -1;
    }
    return 0;
}

int
rte_flock(int fd, enum rte_flock_op op, enum rte_flock_mode mode)
{
    HANDLE handle = (HANDLE)_get_osfhandle(fd);

    if (handle == INVALID_HANDLE_VALUE) {
        rte_errno = EBADF;
        return -1;
    }

    switch (op) {
    case RTE_FLOCK_EXCLUSIVE:
    case RTE_FLOCK_SHARED:
        return lock_file(handle, op, mode);
    case RTE_FLOCK_UNLOCK:
        return unlock_file(handle);
    default:
        rte_errno = EINVAL;
        return -1;
    }
}
