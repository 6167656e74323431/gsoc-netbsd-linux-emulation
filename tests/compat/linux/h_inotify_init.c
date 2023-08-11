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
	REQUIRE(fcntl(fd, LINUX_F_GETFD) == 0);
	REQUIRE((fcntl(fd, LINUX_F_GETFL) & LINUX_O_NONBLOCK) == 0);
	RS(close(fd));

	/* Check that only NONBLOCK is set. */
	RS(fd = syscall(LINUX_SYS_inotify_init1, LINUX_IN_NONBLOCK));
	REQUIRE(fcntl(fd, LINUX_F_GETFD) == 0);
	REQUIRE((fcntl(fd, LINUX_F_GETFL) & LINUX_O_NONBLOCK) != 0);
	RS(close(fd));

	/* Check that only CLOEXEC is set. */
	RS(fd = syscall(LINUX_SYS_inotify_init1, LINUX_IN_CLOEXEC));
	REQUIRE(fcntl(fd, LINUX_F_GETFD) != 0);
	REQUIRE((fcntl(fd, LINUX_F_GETFL) & LINUX_O_NONBLOCK) == 0);
	RS(close(fd));

	exit(0);
}
