#include "h_linux.h"

#include <compat/linux/linux_syscall.h>
#include <compat/linux/common/linux_inotify.h>

void
_start(void)
{
	int fd;

	RS(fd = syscall(LINUX_SYS_inotify_init));

	RS(fd = syscall(LINUX_SYS_inotify_init1, LINUX_IN_NONBLOCK));
	// TODO check if NONBLOCK is set

	RS(fd = syscall(LINUX_SYS_inotify_init1, LINUX_IN_CLOEXEC));
	// TODO check if CLOEXEC is set

	exit(0);
}
