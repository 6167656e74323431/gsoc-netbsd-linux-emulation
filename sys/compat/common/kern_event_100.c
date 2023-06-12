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

static int compat_100_kevent_fetch_changes(void *ctx,
    const struct kevent *changelist, struct kevent *changes, size_t index, int n);
static int compat_100_kevent_put_events(void *ctx, struct kevent *events,
    struct kevent *eventlist, size_t index, int n);

struct compat_100_kevent_ops_args {
	const struct kevent100 *changelist;
	struct kevent100 *eventlist;
};

static int
compat_100_kevent_fetch_changes(void *ctx, const struct kevent *changelist,
    struct kevent *changes, size_t index, int n)
{
	struct compat_100_kevent_ops_args *args;
	int error, i;

	/* Zero out ext fields. */
	memset(changes, 0, n * sizeof(*changes));

	args = (struct compat_100_kevent_ops_args *)ctx;

	for (i = 0; i < n; i++) {
		error = copyin(args->changelist + i, changes + i,
		    sizeof(*(args->changelist)));
		if (error != 0)
			return error;
	}

	args->changelist += n;
	return error;
}

static int
compat_100_kevent_put_events(void *ctx, struct kevent *events,
    struct kevent *eventlist, size_t index, int n)
{
	struct compat_100_kevent_ops_args *args;
	int error, i;

	args = (struct compat_100_kevent_ops_args *)ctx;

	for (i = 0; i < n; i++) {
		error = copyout(events + i, args->eventlist + index + i,
		    sizeof(*(args->eventlist)));
		if (error != 0)
			return error;
	}

	args->eventlist += n;
	return error;
}

int
compat_100_kevent1(register_t *retval, int fd, const struct kevent100 *changelist,
    size_t nchanges, struct kevent100 *eventlist, size_t nevents,
    const struct timespec *timeout, copyin_t fetch_timeout)
{
        struct compat_100_kevent_ops_args args = {
		.changelist = changelist,
		.eventlist = eventlist,
	};
	const struct kevent_ops k_ops = {
		.keo_private = &args,
		.keo_fetch_timeout = fetch_timeout,
		.keo_fetch_changes = compat_100_kevent_fetch_changes,
		.keo_put_events = compat_100_kevent_put_events,
	};
	
	return kevent1(retval, fd, NULL, nchanges, NULL, nevents, timeout,
	    &k_ops);
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
	struct compat_100_kevent_ops_args args = {
		.changelist = SCARG(uap, changelist),
		.eventlist = SCARG(uap, eventlist),
	};
	const struct kevent_ops k_ops = {
		.keo_private = &args,
		.keo_fetch_timeout = copyin,
		.keo_fetch_changes = compat_100_kevent_fetch_changes,
		.keo_put_events = compat_100_kevent_put_events,
	};

	return kevent1(retval, SCARG(uap, fd),
	    NULL, SCARG(uap, nchanges), NULL, SCARG(uap, nevents),
	    SCARG(uap, timeout), &k_ops);
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
