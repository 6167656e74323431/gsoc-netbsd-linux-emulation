#include "h_linux.h"

#include <compat/linux/linux_syscall.h>
#include <compat/linux/common/linux_errno.h>
#include <compat/linux/common/linux_fcntl.h>
#include <compat/linux/common/linux_inotify.h>

void
_start(void)
{
	int fd;

	/* Check that none of CLOEXEC or NONBLOCK are set. */
	RS(fd = syscall(LINUX_SYS_inotify_init));
	if (fcntl(fd, LINUX_F_GETFD) != 0)
		exit(LINUX_EBADFD);
	if ((fcntl(fd, LINUX_F_GETFL) & LINUX_O_NONBLOCK) != 0)
		exit(LINUX_EBADFD);
	RS(close(fd));

	/* Check that only NONBLOCK is set. */
	RS(fd = syscall(LINUX_SYS_inotify_init1, LINUX_IN_NONBLOCK));
	if (fcntl(fd, LINUX_F_GETFD) != 0)
		exit(LINUX_EBADFD);
	if ((fcntl(fd, LINUX_F_GETFL) & LINUX_O_NONBLOCK) == 0)
		exit(LINUX_EBADFD);
	RS(close(fd));

	/* Check that only CLOEXEC is set. */
	RS(fd = syscall(LINUX_SYS_inotify_init1, LINUX_IN_CLOEXEC));
	if (fcntl(fd, LINUX_F_GETFD) == 0)
		exit(LINUX_EBADFD);
	if ((fcntl(fd, LINUX_F_GETFL) & LINUX_O_NONBLOCK) != 0)
		exit(LINUX_EBADFD);
	RS(close(fd));

	exit(0);
}
