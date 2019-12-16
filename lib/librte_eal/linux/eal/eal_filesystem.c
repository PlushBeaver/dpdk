#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>

#include <rte_errno.h>
#include <rte_filesystem.h>

int
rte_ftruncate(int fd, ssize_t size)
{
    int ret;

    ret = ftruncate(fd, size);
    if (ret) {
        rte_errno = errno;
    }

    return ret;
}

int
rte_flock(int fd, enum rte_flock_op op, enum rte_flock_mode mode)
{
    int sys_flags = 0;
    int ret;

    if (mode == RTE_FLOCK_RETURN)
        sys_flags |= LOCK_NB;

    switch (op) {
    case RTE_FLOCK_EXCLUSIVE:
        sys_flags |= LOCK_EX;
        break;
    case RTE_FLOCK_SHARED:
        sys_flags |= LOCK_SH;
        break;
    case RTE_FLOCK_UNLOCK:
        sys_flags |= LOCK_UN;
        break;
    }

    ret = flock(fd, sys_flags);
    if (ret) {
        rte_errno = errno;
    }

    return ret;
}
