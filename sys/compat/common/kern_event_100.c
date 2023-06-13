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
kevent100_fetch_changes(void *ctx, const struct kevent *changelist,
    struct kevent *changes, size_t index, int n)
{
	int error, i;
	struct kevent100 *buf;
	const size_t buf_size = sizeof(*buf) * n;
	const struct kevent100 *changelist100 = (const struct kevent100 *)changelist;

	KASSERT(n >= 0);

	buf = kmem_alloc(buf_size, KM_SLEEP);

	error = copyin(changelist100 + index, buf, buf_size);
	if (error != 0)
		goto leave;

	for (i = 0; i < n; i++)
		kevent100_to_kevent(buf + i, changes + i);

leave:
	kmem_free(buf, buf_size);
	return error;
}

int
kevent100_put_events(void *ctx, struct kevent *events,
    struct kevent *eventlist, size_t index, int n)
{
	int error, i;
        struct kevent100 *buf;
	const size_t buf_size = sizeof(*buf) * n;
	struct kevent100 *eventlist100 = (struct kevent100 *)eventlist;

	KASSERT(n >= 0);

	buf = kmem_alloc(buf_size, KM_SLEEP);

	for (i = 0; i < n; i++)
	        kevent_to_kevent100(events + i, buf + i);

	error = copyout(buf, eventlist100 + index, buf_size);

	kmem_free(buf, buf_size);
	return error;
}

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
		.keo_fetch_changes = kevent100_fetch_changes,
		.keo_put_events = kevent100_put_events,
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
