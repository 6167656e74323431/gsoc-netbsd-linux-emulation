/* $NetBSD: osf1_misc.c,v 1.29 1999/04/28 02:02:50 cgd Exp $ */

/*
 * Copyright (c) 1999 Christopher G. Demetriou.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Christopher G. Demetriou
 *	for the NetBSD Project.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Copyright (c) 1994, 1995 Carnegie-Mellon University.
 * All rights reserved.
 *
 * Author: Chris G. Demetriou
 * 
 * Permission to use, copy, modify and distribute this software and
 * its documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 * 
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS" 
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND 
 * FOR ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 * 
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie the
 * rights to redistribute these changes.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/signal.h>
#include <sys/signalvar.h>
#include <sys/reboot.h>
#include <sys/syscallargs.h>
#include <sys/exec.h>
#include <sys/vnode.h>
#include <sys/socketvar.h>
#include <vm/vm.h>				/* XXX UVM headers are Cool */
#include <uvm/uvm.h>				/* XXX see mmap emulation */

#include <compat/osf1/osf1.h>
#include <compat/osf1/osf1_syscall.h>
#include <compat/osf1/osf1_syscallargs.h>
#include <compat/osf1/osf1_util.h>

#include <vm/vm.h>

void cvtstat2osf1 __P((struct stat *, struct osf1_stat *));
void cvtrusage2osf1 __P((struct rusage *, struct osf1_rusage *));

#ifdef SYSCALL_DEBUG
extern int scdebug;
#endif

const char osf1_emul_path[] = "/emul/osf1";

const struct emul_flags_xtab osf1_open_flags_xtab[] = {
    {	OSF1_O_ACCMODE,		OSF1_O_RDONLY,		O_RDONLY	},
    {	OSF1_O_ACCMODE,		OSF1_O_WRONLY,		O_WRONLY	},
    {	OSF1_O_ACCMODE,		OSF1_O_RDWR,		O_RDWR		},
    {	OSF1_O_NONBLOCK,	OSF1_O_NONBLOCK,	O_NONBLOCK	},
    {	OSF1_O_APPEND,		OSF1_O_APPEND,		O_APPEND	},
#if 0 /* no equivalent +++ */
    {	OSF1_O_DEFER,		OSF1_O_DEFER,		???		},
#endif
    {	OSF1_O_CREAT,		OSF1_O_CREAT,		O_CREAT		},
    {	OSF1_O_TRUNC,		OSF1_O_TRUNC,		O_TRUNC		},
    {	OSF1_O_EXCL,		OSF1_O_EXCL,		O_EXCL		},
    {	OSF1_O_NOCTTY,		OSF1_O_NOCTTY,		O_NOCTTY	},
    {	OSF1_O_SYNC,		OSF1_O_SYNC,		O_SYNC		},
    {	OSF1_O_NDELAY,		OSF1_O_NDELAY,		O_NDELAY	},
#if 0 /* no equivalent, also same value as O_NDELAY! */
    {	OSF1_O_DRD,		OSF1_O_DRD,		???		},
#endif
    {	OSF1_O_DSYNC,		OSF1_O_DSYNC,		O_DSYNC		},
    {	OSF1_O_RSYNC,		OSF1_O_RSYNC,		O_RSYNC		},
    {	0								}
};

int
osf1_sys_open(p, v, retval)
	struct proc *p;
	void *v;
	register_t *retval;
{
	struct osf1_sys_open_args *uap = v;
	struct sys_open_args a;
	const char *path;
	caddr_t sg;
	unsigned long leftovers;
#ifdef SYSCALL_DEBUG
	char pnbuf[1024];

	if (scdebug &&
	    copyinstr(SCARG(uap, path), pnbuf, sizeof pnbuf, NULL) == 0)
		printf("osf1_open: open: %s\n", pnbuf);
#endif

	sg = stackgap_init(p->p_emul);

	/* translate flags */
	SCARG(&a, flags) = emul_flags_translate(osf1_open_flags_xtab,
	    SCARG(uap, flags), &leftovers);
	if (leftovers != 0)
		return (EINVAL);

	/* copy mode, no translation necessary */
	SCARG(&a, mode) = SCARG(uap, mode);

	/* pick appropriate path */
	path = SCARG(uap, path);
	if (SCARG(&a, flags) & O_CREAT)
		OSF1_CHECK_ALT_CREAT(p, &sg, path);
	else
		OSF1_CHECK_ALT_EXIST(p, &sg, path);
	SCARG(&a, path) = path;

	return sys_open(p, &a, retval);
}

int
osf1_sys_setsysinfo(p, v, retval)
	struct proc *p;
	void *v;
	register_t *retval;
{

	/* XXX */
	return (0);
}

int
osf1_sys_getrlimit(p, v, retval)
	struct proc *p;
	void *v;
	register_t *retval;
{
	struct osf1_sys_getrlimit_args *uap = v;
	struct sys_getrlimit_args a;

	switch (SCARG(uap, which)) {
	case OSF1_RLIMIT_CPU:
		SCARG(&a, which) = RLIMIT_CPU;
		break;
	case OSF1_RLIMIT_FSIZE:
		SCARG(&a, which) = RLIMIT_FSIZE;
		break;
	case OSF1_RLIMIT_DATA:
		SCARG(&a, which) = RLIMIT_DATA;
		break;
	case OSF1_RLIMIT_STACK:
		SCARG(&a, which) = RLIMIT_STACK;
		break;
	case OSF1_RLIMIT_CORE:
		SCARG(&a, which) = RLIMIT_CORE;
		break;
	case OSF1_RLIMIT_RSS:
		SCARG(&a, which) = RLIMIT_RSS;
		break;
	case OSF1_RLIMIT_NOFILE:
		SCARG(&a, which) = RLIMIT_NOFILE;
		break;
	case OSF1_RLIMIT_AS:		/* unhandled */
	default:
		return (EINVAL);
	}

	/* XXX should translate */
	SCARG(&a, rlp) = SCARG(uap, rlp);

	return sys_getrlimit(p, &a, retval);
}

int
osf1_sys_setrlimit(p, v, retval)
	struct proc *p;
	void *v;
	register_t *retval;
{
	struct osf1_sys_setrlimit_args *uap = v;
	struct sys_setrlimit_args a;

	switch (SCARG(uap, which)) {
	case OSF1_RLIMIT_CPU:
		SCARG(&a, which) = RLIMIT_CPU;
		break;
	case OSF1_RLIMIT_FSIZE:
		SCARG(&a, which) = RLIMIT_FSIZE;
		break;
	case OSF1_RLIMIT_DATA:
		SCARG(&a, which) = RLIMIT_DATA;
		break;
	case OSF1_RLIMIT_STACK:
		SCARG(&a, which) = RLIMIT_STACK;
		break;
	case OSF1_RLIMIT_CORE:
		SCARG(&a, which) = RLIMIT_CORE;
		break;
	case OSF1_RLIMIT_RSS:
		SCARG(&a, which) = RLIMIT_RSS;
		break;
	case OSF1_RLIMIT_NOFILE:
		SCARG(&a, which) = RLIMIT_NOFILE;
		break;
	case OSF1_RLIMIT_AS:		/* unhandled */
	default:
		return (EINVAL);
	}

	/* XXX should translate */
	SCARG(&a, rlp) = SCARG(uap, rlp);

	return sys_setrlimit(p, &a, retval);
}

const struct emul_flags_xtab osf1_mmap_prot_xtab[] = {
#if 0 /* pseudo-flag */
    {	OSF1_PROT_NONE,		OSF1_PROT_NONE,		PROT_NONE	},
#endif
    {	OSF1_PROT_READ,		OSF1_PROT_READ,		PROT_READ	},
    {	OSF1_PROT_WRITE,	OSF1_PROT_WRITE,	PROT_WRITE	},
    {	OSF1_PROT_EXEC,		OSF1_PROT_EXEC,		PROT_EXEC	},
    {	0								}
};

const struct emul_flags_xtab osf1_mmap_flags_xtab[] = {
    {	OSF1_MAP_SHARED,	OSF1_MAP_SHARED,	MAP_SHARED	},
    {	OSF1_MAP_PRIVATE,	OSF1_MAP_PRIVATE,	MAP_PRIVATE	},
    {	OSF1_MAP_TYPE,		OSF1_MAP_FILE,		MAP_FILE	},
    {	OSF1_MAP_TYPE,		OSF1_MAP_ANON,		MAP_ANON	},
    {	OSF1_MAP_FIXED,		OSF1_MAP_FIXED,		MAP_FIXED	},
#if 0 /* pseudo-flag, and the default */
    {	OSF1_MAP_VARIABLE,	OSF1_MAP_VARIABLE,	0		},
#endif
    {	OSF1_MAP_HASSEMAPHORE,	OSF1_MAP_HASSEMAPHORE,	MAP_HASSEMAPHORE },
    {	OSF1_MAP_INHERIT,	OSF1_MAP_INHERIT,	MAP_INHERIT	},
#if 0 /* no equivalent +++ */
    {	OSF1_MAP_UNALIGNED,	OSF1_MAP_UNALIGNED,	???		},
#endif
    {	0								}
};

int
osf1_sys_mmap(p, v, retval)
	struct proc *p;
	void *v;
	register_t *retval;
{
	struct osf1_sys_mmap_args *uap = v;
	struct sys_mmap_args a;
	unsigned long leftovers;

	SCARG(&a, addr) = SCARG(uap, addr);
	SCARG(&a, len) = SCARG(uap, len);
	SCARG(&a, fd) = SCARG(uap, fd);
	SCARG(&a, pad) = 0;
	SCARG(&a, pos) = SCARG(uap, pos);

	/* translate prot */
	SCARG(&a, prot) = emul_flags_translate(osf1_mmap_prot_xtab,
	    SCARG(uap, prot), &leftovers);
	if (leftovers != 0)
		return (EINVAL);

	/* translate flags */
	SCARG(&a, flags) = emul_flags_translate(osf1_mmap_flags_xtab,
	    SCARG(uap, flags), &leftovers);
	if (leftovers != 0)
		return (EINVAL);

	/*
	 * XXX The following code is evil.
	 *
	 * The OSF/1 mmap() function attempts to map non-fixed entries
	 * near the address that the user specified.  Therefore, for
	 * non-fixed entires we try to find space in the address space
	 * starting at that address.  If the user specified zero, we
	 * start looking at at least NBPG, so that programs can't
	 * accidentally live through deferencing NULL.
	 *
	 * The need for this kludgery is increased by the fact that
	 * the loader data segment is mapped at
	 * (end of user address space) - 1G, MAXDSIZ is 1G, and
	 * the VM system tries allocate non-fixed mappings _AFTER_
	 * (start of data) + MAXDSIZ.  With the loader, of course,
	 * that means that it'll start trying at
	 * (end of user address space), and will never succeed!
	 *
	 * Notes:
	 *
	 * * Though we find space here, if something else (e.g. a second
	 *   thread) were mucking with the address space the mapping
	 *   we found might be used by another mmap(), and this call
	 *   would clobber that region.
	 *
	 * * In general, tricks like this only work for MAP_ANON mappings,
	 *   because of sharing/cache issues.  That's not a problem on
	 *   the Alpha, and though it's not good style to abuse that fact,
	 *   there's little choice.
	 *
	 * * In order for this to be done right, the VM system should
	 *   really try to use the requested 'addr' passed in to mmap()
	 *   as a hint, even if non-fixed.  If it's passed as zero,
	 *   _maybe_ then try (start of data) + MAXDSIZ, or maybe
	 *   provide a better way to avoid the data region altogether.
	 */
	if ((SCARG(&a, flags) & MAP_FIXED) == 0) {
		vaddr_t addr = round_page(SCARG(&a, addr));
		vsize_t size = round_page(SCARG(&a, len));
		int fixed = 0;

		vm_map_lock(&p->p_vmspace->vm_map);

		/* if non-NULL address given, start looking there */
		if (addr != 0 && uvm_map_findspace(&p->p_vmspace->vm_map,
		    addr, size, &addr, NULL, 0, 0) != NULL) {
			fixed = 1;
			goto done;
		}

		/* didn't find anything.  take it again from the top. */
		if (uvm_map_findspace(&p->p_vmspace->vm_map, NBPG, size, &addr,
		    NULL, 0, 0) != NULL) {
			fixed = 1;
			goto done;
		}

done:
		vm_map_unlock(&p->p_vmspace->vm_map);
		if (fixed) {
			SCARG(&a, flags) |= MAP_FIXED;
			SCARG(&a, addr) = (void *)addr;
		}
	}

	return sys_mmap(p, &a, retval);
}

int
osf1_sys_usleep_thread(p, v, retval)
	struct proc *p;
	void *v;
	register_t *retval;
{
	struct osf1_sys_usleep_thread_args *uap = v;
	struct timeval tv, endtv;
	u_long ticks;
	int error, s;

	if ((error = copyin(SCARG(uap, sleep), &tv, sizeof tv)))
		return (error);

	ticks = ((u_long)tv.tv_sec * 1000000 + tv.tv_usec) / tick;
	s = splclock();
	tv = time;
	splx(s);

	tsleep(p, PUSER|PCATCH, "OSF/1", ticks);	/* XXX */

	if (SCARG(uap, slept) != NULL) {
		s = splclock();
		timersub(&time, &tv, &endtv);
		splx(s);
		if (tv.tv_sec < 0 || tv.tv_usec < 0)
			tv.tv_sec = tv.tv_usec = 0;

		error = copyout(&endtv, SCARG(uap, slept), sizeof endtv);
	}
	return (error);
}

/*
 * Get file status; this version follows links.
 */
/* ARGSUSED */
int
osf1_sys_stat(p, v, retval)
	struct proc *p;
	void *v;
	register_t *retval;
{
	struct osf1_sys_stat_args *uap = v;
	struct stat sb;
	struct osf1_stat osb;
	int error;
	struct nameidata nd;
	caddr_t sg;

	sg = stackgap_init(p->p_emul);
	OSF1_CHECK_ALT_EXIST(p, &sg, SCARG(uap, path));

	NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF, UIO_USERSPACE,
	    SCARG(uap, path), p);
	if ((error = namei(&nd)))
		return (error);
	error = vn_stat(nd.ni_vp, &sb, p);
	vput(nd.ni_vp);
	if (error)
		return (error);
	cvtstat2osf1(&sb, &osb);
	error = copyout((caddr_t)&osb, (caddr_t)SCARG(uap, ub), sizeof (osb));
	return (error);
}

/*
 * Get file status; this version does not follow links.
 */
/* ARGSUSED */
int
osf1_sys_lstat(p, v, retval)
	struct proc *p;
	void *v;
	register_t *retval;
{
	struct osf1_sys_lstat_args *uap = v;
	struct stat sb;
	struct osf1_stat osb;
	int error;
	struct nameidata nd;
	caddr_t sg;

	sg = stackgap_init(p->p_emul);
	OSF1_CHECK_ALT_EXIST(p, &sg, SCARG(uap, path));

	NDINIT(&nd, LOOKUP, NOFOLLOW | LOCKLEAF, UIO_USERSPACE,
	    SCARG(uap, path), p);
	if ((error = namei(&nd)))
		return (error);
	error = vn_stat(nd.ni_vp, &sb, p);
	vput(nd.ni_vp);
	if (error)
		return (error);
	cvtstat2osf1(&sb, &osb);
	error = copyout((caddr_t)&osb, (caddr_t)SCARG(uap, ub), sizeof (osb));
	return (error);
}

/*
 * Return status information about a file descriptor.
 */
int
osf1_sys_fstat(p, v, retval)
	struct proc *p;
	void *v;
	register_t *retval;
{
	struct osf1_sys_fstat_args *uap = v;
	struct filedesc *fdp = p->p_fd;
	struct file *fp;
	struct stat ub;
	struct osf1_stat oub;
	int error;

	if ((unsigned)SCARG(uap, fd) >= fdp->fd_nfiles ||
	    (fp = fdp->fd_ofiles[SCARG(uap, fd)]) == NULL)
		return (EBADF);
	switch (fp->f_type) {

	case DTYPE_VNODE:
		error = vn_stat((struct vnode *)fp->f_data, &ub, p);
		break;

	case DTYPE_SOCKET:
		error = soo_stat((struct socket *)fp->f_data, &ub);
		break;

	default:
		panic("ofstat");
		/*NOTREACHED*/
	}
	cvtstat2osf1(&ub, &oub);
	if (error == 0)
		error = copyout((caddr_t)&oub, (caddr_t)SCARG(uap, sb),
		    sizeof (oub));
	return (error);
}

#define	bsd2osf_dev(dev)	osf1_makedev(major(dev), minor(dev))
#define	osf2bsd_dev(dev)	makedev(osf1_major(dev), osf1_minor(dev))

/*
 * Convert from a stat structure to an osf1 stat structure.
 */
void
cvtstat2osf1(st, ost)
	struct stat *st;
	struct osf1_stat *ost;
{

	ost->st_dev = bsd2osf_dev(st->st_dev);
	ost->st_ino = st->st_ino;
	ost->st_mode = st->st_mode;
	ost->st_nlink = st->st_nlink;
	ost->st_uid = st->st_uid == -2 ? (u_int16_t) -2 : st->st_uid;
	ost->st_gid = st->st_gid == -2 ? (u_int16_t) -2 : st->st_gid;
	ost->st_rdev = bsd2osf_dev(st->st_rdev);
	ost->st_size = st->st_size;
	ost->st_atime_sec = st->st_atime;
	ost->st_spare1 = 0;
	ost->st_mtime_sec = st->st_mtime;
	ost->st_spare2 = 0;
	ost->st_ctime_sec = st->st_ctime;
	ost->st_spare3 = 0;
	ost->st_blksize = st->st_blksize;
	ost->st_blocks = st->st_blocks;
	ost->st_flags = st->st_flags;
	ost->st_gen = st->st_gen;
}

int
osf1_sys_mknod(p, v, retval)
	struct proc *p;
	void *v;
	register_t *retval;
{
	struct osf1_sys_mknod_args *uap = v;
	struct sys_mknod_args a;
	caddr_t sg;

	sg = stackgap_init(p->p_emul);
	OSF1_CHECK_ALT_EXIST(p, &sg, SCARG(uap, path));

	SCARG(&a, path) = SCARG(uap, path);
	SCARG(&a, mode) = SCARG(uap, mode);
	SCARG(&a, dev) = osf2bsd_dev(SCARG(uap, dev));

	return sys_mknod(p, &a, retval);
}

const struct emul_flags_xtab osf1_fcntl_getsetfd_flags_xtab[] = {
    {	OSF1_FD_CLOEXEC,	OSF1_FD_CLOEXEC,	FD_CLOEXEC	},
    {	0								}
};

const struct emul_flags_xtab osf1_fcntl_getsetfd_flags_rxtab[] = {
    {	FD_CLOEXEC,		FD_CLOEXEC,		OSF1_FD_CLOEXEC	},
    {	0								}
};

const struct emul_flags_xtab osf1_fcntl_getsetfl_flags_xtab[] = {
    {	OSF1_FNONBLOCK,		OSF1_FNONBLOCK,		FNONBLOCK	},
    {	OSF1_FAPPEND,		OSF1_FAPPEND,		FAPPEND		},
    {	OSF1_FASYNC,		OSF1_FASYNC,		FASYNC		},
    {	OSF1_FSYNC,		OSF1_FSYNC,		FFSYNC		},
    {	OSF1_FNDELAY,		OSF1_FNDELAY,		FNDELAY		},
    {	OSF1_FDSYNC,		OSF1_FDSYNC,		FDSYNC		},
    {	OSF1_FRSYNC,		OSF1_FRSYNC,		FRSYNC		},
    {	0								}
};

const struct emul_flags_xtab osf1_fcntl_getsetfl_flags_rxtab[] = {
    {	FNONBLOCK,		FNONBLOCK,		OSF1_FNONBLOCK	},
    {	FAPPEND,		FAPPEND,		OSF1_FAPPEND	},
    {	FASYNC,			FASYNC,			OSF1_FASYNC	},
    {	FFSYNC,			FFSYNC,			OSF1_FSYNC	},
    {	FNDELAY,		FNDELAY,		OSF1_FNDELAY	},
    {	FDSYNC,			FDSYNC,			OSF1_FDSYNC	},
    {	FRSYNC,			FRSYNC,			OSF1_FRSYNC	},
    {	0								}
};

int
osf1_sys_fcntl(p, v, retval)
	struct proc *p;
	void *v;
	register_t *retval;
{
	struct osf1_sys_fcntl_args *uap = v;
	struct sys_fcntl_args a;
	unsigned long leftovers;
	int error;

	SCARG(&a, fd) = SCARG(uap, fd);

	leftovers = 0;
	switch (SCARG(uap, cmd)) {
	case OSF1_F_DUPFD:
		SCARG(&a, cmd) = F_DUPFD;
		SCARG(&a, arg) = SCARG(uap, arg);
		break;

	case OSF1_F_GETFD:
		SCARG(&a, cmd) = F_GETFD;
		SCARG(&a, arg) = 0;		/* ignored */
		break;

	case OSF1_F_SETFD:
		SCARG(&a, cmd) = F_SETFD;
		SCARG(&a, arg) = (void *)emul_flags_translate(
		    osf1_fcntl_getsetfd_flags_xtab,
		    (unsigned long)SCARG(uap, arg), &leftovers);
		break;

	case OSF1_F_GETFL:
		SCARG(&a, cmd) = F_GETFL;
		SCARG(&a, arg) = 0;		/* ignored */
		break;

	case OSF1_F_SETFL:
		SCARG(&a, cmd) = F_SETFL;
		SCARG(&a, arg) = (void *)emul_flags_translate(
		    osf1_fcntl_getsetfl_flags_xtab,
		    (unsigned long)SCARG(uap, arg), &leftovers);
		break;

	case OSF1_F_GETOWN:		/* XXX not yet supported */
	case OSF1_F_SETOWN:		/* XXX not yet supported */
	case OSF1_F_GETLK:		/* XXX not yet supported */
	case OSF1_F_SETLK:		/* XXX not yet supported */
	case OSF1_F_SETLKW:		/* XXX not yet supported */
		/* XXX translate. */
		return (EINVAL);
		
	case OSF1_F_RGETLK:		/* [lock mgr op] XXX not supported */
	case OSF1_F_RSETLK:		/* [lock mgr op] XXX not supported */
	case OSF1_F_CNVT:		/* [lock mgr op] XXX not supported */
	case OSF1_F_RSETLKW:		/* [lock mgr op] XXX not supported */
	case OSF1_F_PURGEFS:		/* [lock mgr op] XXX not supported */
	case OSF1_F_PURGENFS:		/* [DECsafe op] XXX not supported */
	default:
		/* XXX syslog? */
		return (EINVAL);
	}
	if (leftovers != 0)
		return (EINVAL);

	error = sys_fcntl(p, &a, retval);

	if (error)
		return error;

	switch (SCARG(uap, cmd)) {
	case OSF1_F_GETFD:
		retval[0] = emul_flags_translate(
		    osf1_fcntl_getsetfd_flags_rxtab, retval[0], NULL);
		break;

	case OSF1_F_GETFL:
		retval[0] = emul_flags_translate(
		    osf1_fcntl_getsetfl_flags_rxtab, retval[0], NULL);
		break;
	}

	return error;
}

int
osf1_sys_socket(p, v, retval)
	struct proc *p;
	void *v;
	register_t *retval;
{
	struct osf1_sys_socket_args *uap = v;
	struct sys_socket_args a;

	/* XXX TRANSLATE */

	if (SCARG(uap, type) > AF_LINK)
		return (EINVAL);	/* XXX After AF_LINK, divergence. */

	SCARG(&a, domain) = SCARG(uap, domain);
	SCARG(&a, type) = SCARG(uap, type);
	SCARG(&a, protocol) = SCARG(uap, protocol);

	return sys_socket(p, &a, retval);
}

const struct emul_flags_xtab osf1_sendrecv_msg_flags_xtab[] = {
    {	OSF1_MSG_OOB,		OSF1_MSG_OOB,		MSG_OOB		},
    {	OSF1_MSG_PEEK,		OSF1_MSG_PEEK,		MSG_PEEK	},
    {	OSF1_MSG_DONTROUTE,	OSF1_MSG_DONTROUTE,	MSG_DONTROUTE	},
    {	OSF1_MSG_EOR,		OSF1_MSG_EOR,		MSG_EOR		},
    {	OSF1_MSG_TRUNC,		OSF1_MSG_TRUNC,		MSG_TRUNC	},
    {	OSF1_MSG_CTRUNC,	OSF1_MSG_CTRUNC,	MSG_CTRUNC	},
    {	OSF1_MSG_WAITALL,	OSF1_MSG_WAITALL,	MSG_WAITALL	},
    {	0								}
};

int
osf1_sys_sendto(p, v, retval)
	struct proc *p;
	void *v;
	register_t *retval;
{
	struct osf1_sys_sendto_args *uap = v;
	struct sys_sendto_args a;
	unsigned long leftovers;

	SCARG(&a, s) = SCARG(uap, s);
	SCARG(&a, buf) = SCARG(uap, buf);
	SCARG(&a, len) = SCARG(uap, len);
	SCARG(&a, to) = SCARG(uap, to);
	SCARG(&a, tolen) = SCARG(uap, tolen);

	/* translate flags */
	SCARG(&a, flags) = emul_flags_translate(osf1_sendrecv_msg_flags_xtab,
	    SCARG(uap, flags), &leftovers);
	if (leftovers != 0)
		return (EINVAL);

	return sys_sendto(p, &a, retval);
}

const struct emul_flags_xtab osf1_reboot_opt_xtab[] = {
#if 0 /* pseudo-flag */
    {	OSF1_RB_AUTOBOOT,	OSF1_RB_AUTOBOOT,	RB_AUTOBOOT	},
#endif
    {	OSF1_RB_ASKNAME,	OSF1_RB_ASKNAME,	RB_ASKNAME	},
    {	OSF1_RB_SINGLE,		OSF1_RB_SINGLE,		RB_SINGLE	},
    {	OSF1_RB_NOSYNC,		OSF1_RB_NOSYNC,		RB_NOSYNC	},
#if 0 /* same value as O_NDELAY, only used at boot time? */
    {	OSF1_RB_KDB,		OSF1_RB_KDB,		RB_KDB		},
#endif
    {	OSF1_RB_HALT,		OSF1_RB_HALT,		RB_HALT		},
    {	OSF1_RB_INITNAME,	OSF1_RB_INITNAME,	RB_INITNAME	},
    {	OSF1_RB_DFLTROOT,	OSF1_RB_DFLTROOT,	RB_DFLTROOT	},
#if 0 /* no equivalents +++ */
    {	OSF1_RB_ALTBOOT,	OSF1_RB_ALTBOOT,	???		},
    {	OSF1_RB_UNIPROC,	OSF1_RB_UNIPROC,	???		},
    {	OSF1_RB_PARAM,		OSF1_RB_PARAM,		???		},
#endif
    {	OSF1_RB_DUMP,		OSF1_RB_DUMP,		RB_DUMP		},
    {	0								}
};

int
osf1_sys_reboot(p, v, retval)
	struct proc *p;
	void *v;
	register_t *retval;
{
	struct osf1_sys_reboot_args *uap = v;
	struct sys_reboot_args a;
	unsigned long leftovers;

	/* translate opt */
	SCARG(&a, opt) = emul_flags_translate(osf1_reboot_opt_xtab,
	    SCARG(uap, opt), &leftovers);
	if (leftovers != 0)
		return (EINVAL);

	SCARG(&a, bootstr) = NULL;

	return sys_reboot(p, &a, retval);
}

int
osf1_sys_lseek(p, v, retval)
	struct proc *p;
	void *v;
	register_t *retval;
{
	struct osf1_sys_lseek_args *uap = v;
	struct sys_lseek_args a;

	SCARG(&a, fd) = SCARG(uap, fd);
	SCARG(&a, pad) = 0;
	SCARG(&a, offset) = SCARG(uap, offset);
	SCARG(&a, whence) = SCARG(uap, whence);

	return sys_lseek(p, &a, retval);
}

/*
 * OSF/1 defines _POSIX_SAVED_IDS, which means that our normal
 * setuid() won't work.
 *
 * Instead, by P1003.1b-1993, setuid() is supposed to work like:
 *	If the process has appropriate [super-user] priviledges, the
 *	    setuid() function sets the real user ID, effective user
 *	    ID, and the saved set-user-ID to uid.
 *	If the process does not have appropriate priviledges, but uid
 *	    is equal to the real user ID or the saved set-user-ID, the
 *	    setuid() function sets the effective user ID to uid; the
 *	    real user ID and saved set-user-ID remain unchanged by
 *	    this function call.
 */
int
osf1_sys_setuid(p, v, retval)
	struct proc *p;
	void *v;
	register_t *retval;
{
	struct osf1_sys_setuid_args *uap = v;
	struct pcred *pc = p->p_cred;
	uid_t uid = SCARG(uap, uid);
	int error;

	if ((error = suser(pc->pc_ucred, &p->p_acflag)) != 0 &&
	    uid != pc->p_ruid && uid != pc->p_svuid)
		return (error);

	pc->pc_ucred = crcopy(pc->pc_ucred);
	pc->pc_ucred->cr_uid = uid;
	if (error == 0) {
	        (void)chgproccnt(pc->p_ruid, -1);
	        (void)chgproccnt(uid, 1);
		pc->p_ruid = uid;
		pc->p_svuid = uid;
	}
	p->p_flag |= P_SUGID;
	return (0);
}

/*
 * OSF/1 defines _POSIX_SAVED_IDS, which means that our normal
 * setgid() won't work.
 *
 * If you change "uid" to "gid" in the discussion, above, about
 * setuid(), you'll get a correct description of setgid().
 */
int
osf1_sys_setgid(p, v, retval)
	struct proc *p;
	void *v;
	register_t *retval;
{
	struct osf1_sys_setgid_args *uap = v;
	struct pcred *pc = p->p_cred;
	gid_t gid = SCARG(uap, gid);
	int error;

	if ((error = suser(pc->pc_ucred, &p->p_acflag)) != 0 &&
	    gid != pc->p_rgid && gid != pc->p_svgid)
		return (error);

	pc->pc_ucred = crcopy(pc->pc_ucred);
	pc->pc_ucred->cr_gid = gid;
	if (error == 0) {
		pc->p_rgid = gid;
		pc->p_svgid = gid;
	}
	p->p_flag |= P_SUGID;
	return (0);
}

/*
 * The structures end up being the same... but we can't be sure that
 * the other word of our iov_len is zero!
 */
int
osf1_sys_readv(p, v, retval)
	struct proc *p;
	void *v;
	register_t *retval;
{
	struct osf1_sys_readv_args *uap = v;
	struct sys_readv_args a;
	struct osf1_iovec *oio;
	struct iovec *nio;
	caddr_t sg = stackgap_init(p->p_emul);
	int error, osize, nsize, i;

	if (SCARG(uap, iovcnt) > (STACKGAPLEN / sizeof (struct iovec)))
		return (EINVAL);

	osize = SCARG(uap, iovcnt) * sizeof (struct osf1_iovec);
	nsize = SCARG(uap, iovcnt) * sizeof (struct iovec);

	oio = malloc(osize, M_TEMP, M_WAITOK);
	nio = malloc(nsize, M_TEMP, M_WAITOK);

	error = 0;
	if ((error = copyin(SCARG(uap, iovp), oio, osize)))
		goto punt;
	for (i = 0; i < SCARG(uap, iovcnt); i++) {
		nio[i].iov_base = oio[i].iov_base;
		nio[i].iov_len = oio[i].iov_len;
	}

	SCARG(&a, fd) = SCARG(uap, fd);
	SCARG(&a, iovp) = stackgap_alloc(&sg, nsize);
	SCARG(&a, iovcnt) = SCARG(uap, iovcnt);

	if ((error = copyout(nio, (caddr_t)SCARG(&a, iovp), nsize)))
		goto punt;
	error = sys_readv(p, &a, retval);

punt:
	free(oio, M_TEMP);
	free(nio, M_TEMP);
	return (error);
}

int
osf1_sys_writev(p, v, retval)
	struct proc *p;
	void *v;
	register_t *retval;
{
	struct osf1_sys_writev_args *uap = v;
	struct sys_writev_args a;
	struct osf1_iovec *oio;
	struct iovec *nio;
	caddr_t sg = stackgap_init(p->p_emul);
	int error, osize, nsize, i;

	if (SCARG(uap, iovcnt) > (STACKGAPLEN / sizeof (struct iovec)))
		return (EINVAL);

	osize = SCARG(uap, iovcnt) * sizeof (struct osf1_iovec);
	nsize = SCARG(uap, iovcnt) * sizeof (struct iovec);

	oio = malloc(osize, M_TEMP, M_WAITOK);
	nio = malloc(nsize, M_TEMP, M_WAITOK);

	error = 0;
	if ((error = copyin(SCARG(uap, iovp), oio, osize)))
		goto punt;
	for (i = 0; i < SCARG(uap, iovcnt); i++) {
		nio[i].iov_base = oio[i].iov_base;
		nio[i].iov_len = oio[i].iov_len;
	}

	SCARG(&a, fd) = SCARG(uap, fd);
	SCARG(&a, iovp) = stackgap_alloc(&sg, nsize);
	SCARG(&a, iovcnt) = SCARG(uap, iovcnt);

	if ((error = copyout(nio, (caddr_t)SCARG(&a, iovp), nsize)))
		goto punt;
	error = sys_writev(p, &a, retval);

punt:
	free(oio, M_TEMP);
	free(nio, M_TEMP);
	return (error);
}

/* More of the stupid off_t padding! */
int
osf1_sys_truncate(p, v, retval)
	struct proc *p;
	void *v;
	register_t *retval;
{
	struct osf1_sys_truncate_args *uap = v;
	struct sys_truncate_args a;
	caddr_t sg;

	sg = stackgap_init(p->p_emul);
	OSF1_CHECK_ALT_EXIST(p, &sg, SCARG(uap, path));

	SCARG(&a, path) = SCARG(uap, path);
	SCARG(&a, pad) = 0;
	SCARG(&a, length) = SCARG(uap, length);

	return sys_truncate(p, &a, retval);
}

int
osf1_sys_ftruncate(p, v, retval)
	struct proc *p;
	void *v;
	register_t *retval;
{
	struct osf1_sys_ftruncate_args *uap = v;
	struct sys_ftruncate_args a;

	SCARG(&a, fd) = SCARG(uap, fd);
	SCARG(&a, pad) = 0;
	SCARG(&a, length) = SCARG(uap, length);

	return sys_ftruncate(p, &a, retval);
}

int
osf1_sys_getrusage(p, v, retval)
	struct proc *p;
	void *v;
	register_t *retval;
{
	struct osf1_sys_getrusage_args *uap = v;
	struct sys_getrusage_args a;
	struct osf1_rusage osf1_rusage;
	struct rusage netbsd_rusage;
	caddr_t sg;
	int error;

	switch (SCARG(uap, who)) {
	case OSF1_RUSAGE_SELF:
		SCARG(&a, who) = RUSAGE_SELF;
		break;

	case OSF1_RUSAGE_CHILDREN:
		SCARG(&a, who) = RUSAGE_CHILDREN;
		break;

	case OSF1_RUSAGE_THREAD:		/* XXX not supported */
	default:
		return (EINVAL);
	}

	sg = stackgap_init(p->p_emul);
	SCARG(&a, rusage) = stackgap_alloc(&sg, sizeof netbsd_rusage);

	error = sys_getrusage(p, &a, retval);
	if (error == 0)
                error = copyin((caddr_t)SCARG(&a, rusage),
		    (caddr_t)&netbsd_rusage, sizeof netbsd_rusage);
	if (error == 0) {
		cvtrusage2osf1(&netbsd_rusage, &osf1_rusage);
                error = copyout((caddr_t)&osf1_rusage,
		    (caddr_t)SCARG(uap, rusage), sizeof osf1_rusage);
	}

	return (error);
}

/*
 * Convert from as rusage structure to an osf1 rusage structure.
 */
void
cvtrusage2osf1(ru, oru)
	struct rusage *ru;
	struct osf1_rusage *oru;
{

	oru->ru_utime.tv_sec = ru->ru_utime.tv_sec;
	oru->ru_utime.tv_usec = ru->ru_utime.tv_usec;

	oru->ru_stime.tv_sec = ru->ru_stime.tv_sec;
	oru->ru_stime.tv_usec = ru->ru_stime.tv_usec;

	oru->ru_maxrss = ru->ru_maxrss;
	oru->ru_ixrss = ru->ru_ixrss;
	oru->ru_idrss = ru->ru_idrss;
	oru->ru_isrss = ru->ru_isrss;
	oru->ru_minflt = ru->ru_minflt;
	oru->ru_majflt = ru->ru_majflt;
	oru->ru_nswap = ru->ru_nswap;
	oru->ru_inblock = ru->ru_inblock;
	oru->ru_oublock = ru->ru_oublock;
	oru->ru_msgsnd = ru->ru_msgsnd;
	oru->ru_msgrcv = ru->ru_msgrcv;
	oru->ru_nsignals = ru->ru_nsignals;
	oru->ru_nvcsw = ru->ru_nvcsw;
	oru->ru_nivcsw = ru->ru_nivcsw;
}

int
osf1_sys_madvise(p, v, retval)
	struct proc *p;
	void *v;
	register_t *retval;
{
	struct osf1_sys_madvise_args *uap = v;
	struct sys_madvise_args a;
	int error;

	SCARG(&a, addr) = SCARG(uap, addr);
	SCARG(&a, len) = SCARG(uap, len);

	error = 0;
	switch (SCARG(uap, behav)) {
	case OSF1_MADV_NORMAL:
		SCARG(&a, behav) = MADV_NORMAL;
		break;

	case OSF1_MADV_RANDOM:
		SCARG(&a, behav) = MADV_RANDOM;
		break;

	case OSF1_MADV_SEQUENTIAL:
		SCARG(&a, behav) = MADV_SEQUENTIAL;
		break;

	case OSF1_MADV_WILLNEED:
		SCARG(&a, behav) = MADV_WILLNEED;
		break;

	case OSF1_MADV_DONTNEED_COMPAT:
		SCARG(&a, behav) = MADV_DONTNEED;
		break;

	case OSF1_MADV_SPACEAVAIL:
		SCARG(&a, behav) = MADV_SPACEAVAIL;
		break;

	case OSF1_MADV_DONTNEED:
		/*
		 * XXX not supported.  In Digital UNIX, this flushes all
		 * XXX data in the region and replaces it with ZFOD pages.
		 */
		error = EINVAL;
		break;

	default:
		error = EINVAL;
		break;
	}

	if (error == 0) {
		error = sys_madvise(p, &a, retval);

		/*
		 * NetBSD madvise() currently always returns ENOSYS.
		 * Digital UNIX says that non-operational requests (i.e.
		 * valid, but unimplemented 'behav') will return success.
		 */
		if (error == ENOSYS)
			error = 0;
	}
	return (error);
}

int
osf1_sys_execve(p, v, retval)
	struct proc *p;
	void *v;
	register_t *retval;
{
	struct osf1_sys_execve_args *uap = v;
	struct sys_execve_args ap;
	caddr_t sg;

	sg = stackgap_init(p->p_emul);
	OSF1_CHECK_ALT_EXIST(p, &sg, SCARG(uap, path));

	SCARG(&ap, path) = SCARG(uap, path);
	SCARG(&ap, argp) = SCARG(uap, argp);
	SCARG(&ap, envp) = SCARG(uap, envp);

	return sys_execve(p, &ap, retval);
}

int
osf1_sys_uname(p, v, retval)
	struct proc *p;
	void *v;
	register_t *retval;
{
	struct osf1_sys_uname_args *uap = v;
        struct osf1_utsname u;
        char *cp, *dp, *ep;
        extern char ostype[], osrelease[];

	/* XXX would use stackgap, but our struct utsname is too big! */

        strncpy(u.sysname, ostype, sizeof(u.sysname));
        strncpy(u.nodename, hostname, sizeof(u.nodename));
        strncpy(u.release, osrelease, sizeof(u.release));
        dp = u.version;
        ep = &u.version[sizeof(u.version) - 1];
        for (cp = version; *cp && *cp != '('; cp++)
                ;
        for (cp++; *cp && *cp != ')' && dp < ep; cp++)
                *dp++ = *cp;
        for (; *cp && *cp != '#'; cp++)
                ;
        for (; *cp && *cp != ':' && dp < ep; cp++)
                *dp++ = *cp;
        *dp = '\0';
        strncpy(u.machine, MACHINE, sizeof(u.machine));
        return (copyout((caddr_t)&u, (caddr_t)SCARG(uap, name), sizeof u));
}

int
osf1_sys_gettimeofday(p, v, retval)
	struct proc *p;
	void *v;
	register_t *retval;
{
	struct osf1_sys_gettimeofday_args *uap = v;
	struct sys_gettimeofday_args a;
	struct osf1_timeval otv;
	struct osf1_timezone otz;
	struct timeval tv;
	struct timezone tz;
	int error;
	caddr_t sg;

	sg = stackgap_init(p->p_emul);
	if (SCARG(uap, tp) == NULL)
		SCARG(&a, tp) = NULL;
	else
		SCARG(&a, tp) = stackgap_alloc(&sg, sizeof tv);
	if (SCARG(uap, tzp) == NULL)
		SCARG(&a, tzp) = NULL;
	else
		SCARG(&a, tzp) = stackgap_alloc(&sg, sizeof tz);

	error = sys_gettimeofday(p, &a, retval);

	if (error == 0 && SCARG(uap, tp) != NULL) {
		error = copyin((caddr_t)SCARG(&a, tp),
		    (caddr_t)&tv, sizeof tv);
		if (error == 0) {
			memset(&otv, 0, sizeof otv);
			otv.tv_sec = tv.tv_sec;
			otv.tv_usec = tv.tv_usec;

			error = copyout((caddr_t)&otv,
			    (caddr_t)SCARG(uap, tp), sizeof otv);
		}
	}
	if (error == 0 && SCARG(uap, tzp) != NULL) {
		error = copyin((caddr_t)SCARG(&a, tzp),
		    (caddr_t)&tz, sizeof tz);
		if (error == 0) {
			memset(&otz, 0, sizeof otz);
			otz.tz_minuteswest = tz.tz_minuteswest;
			otz.tz_dsttime = tz.tz_dsttime;

			error = copyout((caddr_t)&otv,
			    (caddr_t)SCARG(uap, tzp), sizeof otv);
		}
	}
	return (error);
}
