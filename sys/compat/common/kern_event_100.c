#if defined(_KERNEL_OPT)
#include "opt_compat_netbsd.h"
#endif

#include <sys/param.h>
#include <sys/event.h>
#include <sys/syscall.h>
#include <sys/syscallvar.h>
#include <sys/syscallargs.h>

#include <compat/common/compat_mod.h>
#include <compat/sys/event.h>

static const struct syscall_package kern_event_100_syscalls[] = {
	{ SYS_compat_100___kevent50, 0, (sy_call_t *)compat_100_sys___kevent50 },
	{ 0, 0, NULL },
};

int
compat_100_sys___kevent50(struct lwp *l, const struct compat_100_sys___kevent50_args *uap,
    register_t *retval)
{
	/* {
		syscallarg(int) fd;
		syscallarg(const struct kevent100 *) changelist;
		syscallarg(size_t) nchanges;
		syscallarg(struct kevent100 *) eventlist;
		syscallarg(size_t) nevents;
		syscallarg(const struct timespec *) timeout;
	} */
	static const struct kevent_ops compat_100_kevent_ops = {
		.keo_private = NULL,
		.keo_fetch_timeout = copyin,
		.keo_fetch_changes = compat_100___kevent50_fetch_changes,
		.keo_put_events = compat_100___kevent50_put_events,
	};

	return kevent1(retval, SCARG(uap, fd),
	    (const struct kevent *)SCARG(uap, changelist), SCARG(uap, nchanges),
	    (struct kevent *)SCARG(uap, eventlist), SCARG(uap, nevents),
	    SCARG(uap, timeout), &compat_100_kevent_ops);
}

int
kern_event_100_init(void)
{

	return syscall_establish(NULL, kern_event_100_syscalls);
}

int
kern_event_100_fini(void)
{

	return syscall_disestablish(NULL, kern_event_100_syscalls);
}
