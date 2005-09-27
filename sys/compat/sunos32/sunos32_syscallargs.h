/* $NetBSD: sunos32_syscallargs.h,v 1.15 2005/09/27 15:07:54 chs Exp $ */

/*
 * System call argument lists.
 *
 * DO NOT EDIT-- this file is automatically generated.
 * created from;	NetBSD: syscalls.master,v 1.11 2005/09/27 15:07:40 chs Exp
 */

#ifndef _SUNOS32_SYS__SYSCALLARGS_H_
#define	_SUNOS32_SYS__SYSCALLARGS_H_

#ifdef	syscallarg
#undef	syscallarg
#endif

#define	syscallarg(x)							\
	union {								\
		register32_t pad;						\
		struct { x datum; } le;					\
		struct { /* LINTED zero array dimension */		\
			int8_t pad[  /* CONSTCOND */			\
				(sizeof (register32_t) < sizeof (x))	\
				? 0					\
				: sizeof (register32_t) - sizeof (x)];	\
			x datum;					\
		} be;							\
	}

struct sunos32_sys_open_args {
	syscallarg(const netbsd32_charp) path;
	syscallarg(int) flags;
	syscallarg(int) mode;
};

struct sunos32_sys_wait4_args {
	syscallarg(int) pid;
	syscallarg(netbsd32_intp) status;
	syscallarg(int) options;
	syscallarg(netbsd32_rusagep_t) rusage;
};

struct sunos32_sys_creat_args {
	syscallarg(const netbsd32_charp) path;
	syscallarg(int) mode;
};

struct sunos32_sys_execv_args {
	syscallarg(const netbsd32_charp) path;
	syscallarg(netbsd32_charpp) argp;
};

struct sunos32_sys_mknod_args {
	syscallarg(const netbsd32_charp) path;
	syscallarg(int) mode;
	syscallarg(int) dev;
};

struct sunos32_sys_stime_args {
	syscallarg(sunos32_time_tp) tp;
};

struct sunos32_sys_ptrace_args {
	syscallarg(int) req;
	syscallarg(pid_t) pid;
	syscallarg(netbsd32_caddr_t) addr;
	syscallarg(int) data;
	syscallarg(netbsd32_charp) addr2;
};

struct sunos32_sys_access_args {
	syscallarg(const netbsd32_charp) path;
	syscallarg(int) flags;
};

struct sunos32_sys_stat_args {
	syscallarg(const netbsd32_charp) path;
	syscallarg(netbsd32_stat43p_t) ub;
};

struct sunos32_sys_lstat_args {
	syscallarg(const netbsd32_charp) path;
	syscallarg(netbsd32_stat43p_t) ub;
};

struct sunos32_sys_mctl_args {
	syscallarg(netbsd32_voidp) addr;
	syscallarg(int) len;
	syscallarg(int) func;
	syscallarg(netbsd32_voidp) arg;
};

struct sunos32_sys_ioctl_args {
	syscallarg(int) fd;
	syscallarg(netbsd32_u_long) com;
	syscallarg(netbsd32_caddr_t) data;
};

struct sunos32_sys_reboot_args {
	syscallarg(int) howto;
	syscallarg(netbsd32_charp) bootstr;
};

struct sunos32_sys_execve_args {
	syscallarg(const netbsd32_charp) path;
	syscallarg(netbsd32_charpp) argp;
	syscallarg(netbsd32_charpp) envp;
};

struct sunos32_sys_omsync_args {
	syscallarg(netbsd32_caddr_t) addr;
	syscallarg(netbsd32_size_t) len;
	syscallarg(int) flags;
};

struct sunos32_sys_mmap_args {
	syscallarg(netbsd32_voidp) addr;
	syscallarg(netbsd32_size_t) len;
	syscallarg(int) prot;
	syscallarg(int) flags;
	syscallarg(int) fd;
	syscallarg(netbsd32_long) pos;
};

struct sunos32_sys_setpgrp_args {
	syscallarg(int) pid;
	syscallarg(int) pgid;
};

struct sunos32_sys_fcntl_args {
	syscallarg(int) fd;
	syscallarg(int) cmd;
	syscallarg(netbsd32_voidp) arg;
};

struct sunos32_sys_socket_args {
	syscallarg(int) domain;
	syscallarg(int) type;
	syscallarg(int) protocol;
};

struct sunos32_sys_setsockopt_args {
	syscallarg(int) s;
	syscallarg(int) level;
	syscallarg(int) name;
	syscallarg(netbsd32_caddr_t) val;
	syscallarg(int) valsize;
};

struct sunos32_sys_sigvec_args {
	syscallarg(int) signum;
	syscallarg(netbsd32_sigvecp_t) nsv;
	syscallarg(netbsd32_sigvecp_t) osv;
};

struct sunos32_sys_sigsuspend_args {
	syscallarg(int) mask;
};

struct sunos32_sys_socketpair_args {
	syscallarg(int) domain;
	syscallarg(int) type;
	syscallarg(int) protocol;
	syscallarg(netbsd32_intp) rsv;
};

struct sunos32_sys_sigreturn_args {
	syscallarg(netbsd32_sigcontextp_t) sigcntxp;
};

struct sunos32_sys_getrlimit_args {
	syscallarg(u_int) which;
	syscallarg(netbsd32_orlimitp_t) rlp;
};

struct sunos32_sys_setrlimit_args {
	syscallarg(u_int) which;
	syscallarg(netbsd32_orlimitp_t) rlp;
};
#ifdef NFSSERVER

struct sunos32_sys_nfssvc_args {
	syscallarg(int) fd;
};
#else
#endif

struct sunos32_sys_statfs_args {
	syscallarg(const netbsd32_charp) path;
	syscallarg(sunos32_statfsp_t) buf;
};

struct sunos32_sys_fstatfs_args {
	syscallarg(int) fd;
	syscallarg(sunos32_statfsp_t) buf;
};

struct sunos32_sys_unmount_args {
	syscallarg(netbsd32_charp) path;
};
#ifdef NFS
#else
#endif

struct sunos32_sys_quotactl_args {
	syscallarg(int) cmd;
	syscallarg(netbsd32_charp) special;
	syscallarg(int) uid;
	syscallarg(netbsd32_caddr_t) addr;
};

struct sunos32_sys_exportfs_args {
	syscallarg(netbsd32_charp) path;
	syscallarg(netbsd32_charp) ex;
};

struct sunos32_sys_mount_args {
	syscallarg(netbsd32_charp) type;
	syscallarg(netbsd32_charp) path;
	syscallarg(int) flags;
	syscallarg(netbsd32_caddr_t) data;
};

struct sunos32_sys_ustat_args {
	syscallarg(int) dev;
	syscallarg(sunos32_ustatp_t) buf;
};
#ifdef SYSVSEM
#else
#endif
#ifdef SYSVMSG
#else
#endif
#ifdef SYSVSHM
#else
#endif

struct sunos32_sys_auditsys_args {
	syscallarg(netbsd32_charp) record;
};

struct sunos32_sys_getdents_args {
	syscallarg(int) fd;
	syscallarg(netbsd32_charp) buf;
	syscallarg(int) nbytes;
};

struct sunos32_sys_sigpending_args {
	syscallarg(netbsd32_intp) mask;
};

struct sunos32_sys_sysconf_args {
	syscallarg(int) name;
};

struct sunos32_sys_uname_args {
	syscallarg(sunos32_utsnamep_t) name;
};

/*
 * System call prototypes.
 */

int	sys_nosys(struct lwp *, void *, register_t *);

int	netbsd32_exit(struct lwp *, void *, register_t *);

int	sys_fork(struct lwp *, void *, register_t *);

int	netbsd32_read(struct lwp *, void *, register_t *);

int	netbsd32_write(struct lwp *, void *, register_t *);

int	sunos32_sys_open(struct lwp *, void *, register_t *);

int	netbsd32_close(struct lwp *, void *, register_t *);

int	sunos32_sys_wait4(struct lwp *, void *, register_t *);

int	sunos32_sys_creat(struct lwp *, void *, register_t *);

int	netbsd32_link(struct lwp *, void *, register_t *);

int	netbsd32_unlink(struct lwp *, void *, register_t *);

int	sunos32_sys_execv(struct lwp *, void *, register_t *);

int	netbsd32_chdir(struct lwp *, void *, register_t *);

int	sunos32_sys_mknod(struct lwp *, void *, register_t *);

int	netbsd32_chmod(struct lwp *, void *, register_t *);

int	netbsd32_chown(struct lwp *, void *, register_t *);

int	netbsd32_break(struct lwp *, void *, register_t *);

int	compat_43_netbsd32_olseek(struct lwp *, void *, register_t *);

int	sys_getpid_with_ppid(struct lwp *, void *, register_t *);

int	netbsd32_setuid(struct lwp *, void *, register_t *);

int	sys_getuid_with_euid(struct lwp *, void *, register_t *);

int	sunos32_sys_stime(struct lwp *, void *, register_t *);

int	sunos32_sys_ptrace(struct lwp *, void *, register_t *);

int	sunos32_sys_access(struct lwp *, void *, register_t *);

int	sys_sync(struct lwp *, void *, register_t *);

int	netbsd32_kill(struct lwp *, void *, register_t *);

int	sunos32_sys_stat(struct lwp *, void *, register_t *);

int	sunos32_sys_lstat(struct lwp *, void *, register_t *);

int	netbsd32_dup(struct lwp *, void *, register_t *);

int	sys_pipe(struct lwp *, void *, register_t *);

int	netbsd32_profil(struct lwp *, void *, register_t *);

int	netbsd32_setgid(struct lwp *, void *, register_t *);

int	sys_getgid_with_egid(struct lwp *, void *, register_t *);

int	netbsd32_acct(struct lwp *, void *, register_t *);

int	sunos32_sys_mctl(struct lwp *, void *, register_t *);

int	sunos32_sys_ioctl(struct lwp *, void *, register_t *);

int	sunos32_sys_reboot(struct lwp *, void *, register_t *);

int	netbsd32_symlink(struct lwp *, void *, register_t *);

int	netbsd32_readlink(struct lwp *, void *, register_t *);

int	sunos32_sys_execve(struct lwp *, void *, register_t *);

int	netbsd32_umask(struct lwp *, void *, register_t *);

int	netbsd32_chroot(struct lwp *, void *, register_t *);

int	compat_43_netbsd32_fstat43(struct lwp *, void *, register_t *);

int	compat_43_sys_getpagesize(struct lwp *, void *, register_t *);

int	sunos32_sys_omsync(struct lwp *, void *, register_t *);

int	sys_vfork(struct lwp *, void *, register_t *);

int	netbsd32_sbrk(struct lwp *, void *, register_t *);

int	netbsd32_sstk(struct lwp *, void *, register_t *);

int	sunos32_sys_mmap(struct lwp *, void *, register_t *);

int	netbsd32_ovadvise(struct lwp *, void *, register_t *);

int	netbsd32_munmap(struct lwp *, void *, register_t *);

int	netbsd32_mprotect(struct lwp *, void *, register_t *);

int	netbsd32_madvise(struct lwp *, void *, register_t *);

int	sunos32_sys_vhangup(struct lwp *, void *, register_t *);

int	netbsd32_mincore(struct lwp *, void *, register_t *);

int	netbsd32_getgroups(struct lwp *, void *, register_t *);

int	netbsd32_setgroups(struct lwp *, void *, register_t *);

int	sys_getpgrp(struct lwp *, void *, register_t *);

int	sunos32_sys_setpgrp(struct lwp *, void *, register_t *);

int	netbsd32_setitimer(struct lwp *, void *, register_t *);

int	compat_12_netbsd32_oswapon(struct lwp *, void *, register_t *);

int	netbsd32_getitimer(struct lwp *, void *, register_t *);

int	compat_43_netbsd32_ogethostname(struct lwp *, void *, register_t *);

int	compat_43_netbsd32_osethostname(struct lwp *, void *, register_t *);

int	compat_43_sys_getdtablesize(struct lwp *, void *, register_t *);

int	netbsd32_dup2(struct lwp *, void *, register_t *);

int	sunos32_sys_fcntl(struct lwp *, void *, register_t *);

int	netbsd32_select(struct lwp *, void *, register_t *);

int	netbsd32_fsync(struct lwp *, void *, register_t *);

int	netbsd32_setpriority(struct lwp *, void *, register_t *);

int	sunos32_sys_socket(struct lwp *, void *, register_t *);

int	netbsd32_connect(struct lwp *, void *, register_t *);

int	compat_43_netbsd32_oaccept(struct lwp *, void *, register_t *);

int	netbsd32_getpriority(struct lwp *, void *, register_t *);

int	compat_43_netbsd32_osend(struct lwp *, void *, register_t *);

int	compat_43_netbsd32_orecv(struct lwp *, void *, register_t *);

int	netbsd32_bind(struct lwp *, void *, register_t *);

int	sunos32_sys_setsockopt(struct lwp *, void *, register_t *);

int	netbsd32_listen(struct lwp *, void *, register_t *);

int	sunos32_sys_sigvec(struct lwp *, void *, register_t *);

int	compat_43_netbsd32_sigblock(struct lwp *, void *, register_t *);

int	compat_43_netbsd32_sigsetmask(struct lwp *, void *, register_t *);

int	sunos32_sys_sigsuspend(struct lwp *, void *, register_t *);

int	compat_43_netbsd32_osigstack(struct lwp *, void *, register_t *);

int	compat_43_netbsd32_orecvmsg(struct lwp *, void *, register_t *);

int	compat_43_netbsd32_osendmsg(struct lwp *, void *, register_t *);

int	netbsd32_gettimeofday(struct lwp *, void *, register_t *);

int	netbsd32_getrusage(struct lwp *, void *, register_t *);

int	netbsd32_getsockopt(struct lwp *, void *, register_t *);

int	netbsd32_readv(struct lwp *, void *, register_t *);

int	netbsd32_writev(struct lwp *, void *, register_t *);

int	netbsd32_settimeofday(struct lwp *, void *, register_t *);

int	netbsd32_fchown(struct lwp *, void *, register_t *);

int	netbsd32_fchmod(struct lwp *, void *, register_t *);

int	compat_43_netbsd32_orecvfrom(struct lwp *, void *, register_t *);

int	netbsd32_setreuid(struct lwp *, void *, register_t *);

int	netbsd32_setregid(struct lwp *, void *, register_t *);

int	netbsd32_rename(struct lwp *, void *, register_t *);

int	compat_43_netbsd32_otruncate(struct lwp *, void *, register_t *);

int	compat_43_netbsd32_oftruncate(struct lwp *, void *, register_t *);

int	netbsd32_flock(struct lwp *, void *, register_t *);

int	netbsd32_sendto(struct lwp *, void *, register_t *);

int	netbsd32_shutdown(struct lwp *, void *, register_t *);

int	sunos32_sys_socketpair(struct lwp *, void *, register_t *);

int	netbsd32_mkdir(struct lwp *, void *, register_t *);

int	netbsd32_rmdir(struct lwp *, void *, register_t *);

int	netbsd32_utimes(struct lwp *, void *, register_t *);

int	sunos32_sys_sigreturn(struct lwp *, void *, register_t *);

int	netbsd32_adjtime(struct lwp *, void *, register_t *);

int	compat_43_netbsd32_ogetpeername(struct lwp *, void *, register_t *);

int	compat_43_sys_gethostid(struct lwp *, void *, register_t *);

int	sunos32_sys_getrlimit(struct lwp *, void *, register_t *);

int	sunos32_sys_setrlimit(struct lwp *, void *, register_t *);

int	compat_43_netbsd32_killpg(struct lwp *, void *, register_t *);

int	compat_43_netbsd32_ogetsockname(struct lwp *, void *, register_t *);

int	netbsd32_poll(struct lwp *, void *, register_t *);

#ifdef NFSSERVER
int	sunos32_sys_nfssvc(struct lwp *, void *, register_t *);

#else
#endif
int	compat_43_netbsd32_ogetdirentries(struct lwp *, void *, register_t *);

int	sunos32_sys_statfs(struct lwp *, void *, register_t *);

int	sunos32_sys_fstatfs(struct lwp *, void *, register_t *);

int	sunos32_sys_unmount(struct lwp *, void *, register_t *);

#ifdef NFS
int	async_daemon(struct lwp *, void *, register_t *);

int	sys_getfh(struct lwp *, void *, register_t *);

#else
#endif
int	compat_09_netbsd32_ogetdomainname(struct lwp *, void *, register_t *);

int	compat_09_netbsd32_osetdomainname(struct lwp *, void *, register_t *);

int	sunos32_sys_quotactl(struct lwp *, void *, register_t *);

int	sunos32_sys_exportfs(struct lwp *, void *, register_t *);

int	sunos32_sys_mount(struct lwp *, void *, register_t *);

int	sunos32_sys_ustat(struct lwp *, void *, register_t *);

#ifdef SYSVSEM
int	compat_10_netbsd32_sys_semsys(struct lwp *, void *, register_t *);

#else
#endif
#ifdef SYSVMSG
int	compat_10_netbsd32_sys_msgsys(struct lwp *, void *, register_t *);

#else
#endif
#ifdef SYSVSHM
int	compat_10_netbsd32_sys_shmsys(struct lwp *, void *, register_t *);

#else
#endif
int	sunos32_sys_auditsys(struct lwp *, void *, register_t *);

int	sunos32_sys_getdents(struct lwp *, void *, register_t *);

int	sys_setsid(struct lwp *, void *, register_t *);

int	netbsd32_fchdir(struct lwp *, void *, register_t *);

int	netbsd32_fchroot(struct lwp *, void *, register_t *);

int	sunos32_sys_sigpending(struct lwp *, void *, register_t *);

int	netbsd32_setpgid(struct lwp *, void *, register_t *);

int	netbsd32_pathconf(struct lwp *, void *, register_t *);

int	netbsd32_fpathconf(struct lwp *, void *, register_t *);

int	sunos32_sys_sysconf(struct lwp *, void *, register_t *);

int	sunos32_sys_uname(struct lwp *, void *, register_t *);

#endif /* _SUNOS32_SYS__SYSCALLARGS_H_ */
