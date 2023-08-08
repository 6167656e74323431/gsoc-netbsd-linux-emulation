#include "h_linux.h"

#include <compat/linux/linux_syscall.h>

long
syscall6(long number, register_t arg1, register_t arg2, register_t arg3,
    register_t arg4, register_t arg5, register_t arg6, ...)
{
	long retval;
	register register_t r10 __asm__ ("r10") = arg4;
	register register_t r8 __asm__ ("r8") = arg5;
	register register_t r9 __asm__ ("r9") = arg6;

	__asm__ __volatile__ ("syscall"
	    : "=a"(retval)
	    : "a"(number), "D"(arg1), "S"(arg2), "d"(arg3), "r"(r10), "r"(r8), "r"(r9)
	    : "rcx", "r11", "memory");

	if (retval < 0) {
		errno = -retval;
		return -1;
	}

	return retval;
}
