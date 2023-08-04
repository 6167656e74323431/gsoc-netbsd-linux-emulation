#ifndef	SRC_TESTS_COMPAT_LINUX_H_LINUX_H_
#define	SRC_TESTS_COMPAT_LINUX_H_LINUX_H_

#include <compat/linux/linux_syscall.h>

long	syscall(long number, ...);

#define	RS(x)	if ((x) == -1) exit(errno);

extern int errno;

static inline void
exit(int status)
{
	syscall(LINUX_SYS_exit, status);
}

#endif /* !SRC_TESTS_COMPAT_LINUX_H_LINUX_H_ */
