#include "h_linux.h"

#include <compat/linux/linux_syscall.h>

int errno = 0;

void
exit(int status)
{
	syscall(LINUX_SYS_exit, status);
}
