#include "h_linux.h"

#include <compat/linux/linux_syscall.h>
#include <compat/linux/common/linux_inotify.h>

void
_start(void)
{
	int fd;

	RS(fd = syscall(LINUX_SYS_inotify_init));
	// TODO

	exit(0);
}
