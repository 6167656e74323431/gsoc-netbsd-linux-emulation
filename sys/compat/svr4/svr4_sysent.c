/*
 * System call switch table.
 *
 * DO NOT EDIT-- this file is automatically generated.
 * created from	NetBSD: syscalls.master,v 1.2 1994/06/29 06:30:37 cgd Exp 
 */

#include <sys/param.h>
#include <compat/svr4/svr4_types.h>
#include <sys/systm.h>
#include <sys/signal.h>
#include <sys/mount.h>
#include <sys/syscallargs.h>
#include <compat/svr4/svr4_syscallargs.h>
int	nosys();
int	exit();
int	fork();
int	read();
int	write();
int	svr4_open();
int	close();
int	svr4_wait();
int	svr4_creat();
int	link();
int	unlink();
int	svr4_execv();
int	chdir();
int	svr4_time();
int	svr4_mknod();
int	chmod();
int	chown();
int	svr4_break();
int	svr4_stat();
int	lseek();
int	getpid();
int	setuid();
int	getuid();
int	svr4_fstat();
int	svr4_access();
int	sync();
int	kill();
int	dup();
int	pipe();
int	svr4_times();
int	getgid();
int	svr4_signal();
#ifdef SYSVMSG
#else
#endif
int	svr4_syssun();
#ifdef SYSVSHM
#else
#endif
#ifdef SYSVSEM
#else
#endif
int	svr4_ioctl();
int	svr4_utssys();
int	fsync();
int	svr4_execve();
int	umask();
int	chroot();
int	svr4_fcntl();
int	mkdir();
int	rmdir();
int	svr4_getdents();
int	svr4_lstat();
int	symlink();
int	readlink();
int	getgroups();
int	setgroups();
int	fchmod();
int	fchown();
int	sigprocmask();
int	sigaltstack();
int	sigsuspend();
int	sigaction();
int	svr4_sigpending();
#ifdef NFSSERVER
#else
#endif
int	svr4_mmap();
int	mprotect();
int	munmap();
int	fpathconf();
int	vfork();
int	fchdir();
int	readv();
int	writev();
int	svr4_xstat();
int	svr4_lxstat();
int	svr4_fxstat();
int	svr4_setrlimit();
int	svr4_getrlimit();
int	rename();
int	svr4_uname();
int	setegid();
int	svr4_sysconfig();
int	adjtime();
int	seteuid();
int	svr4_fchroot();
int	svr4_vhangup();
int	gettimeofday();
int	getitimer();
int	setitimer();

#ifdef COMPAT_43
#define compat_43(func) __CONCAT(compat_43_,func)

#ifdef SYSVMSG
#else
#endif
#ifdef SYSVSHM
#else
#endif
#ifdef SYSVSEM
#else
#endif
#ifdef NFSSERVER
#else
#endif

#else /* COMPAT_43 */
#define compat_43(func) nosys
#endif /* COMPAT_43 */


#ifdef COMPAT_09
#define compat_09(func) __CONCAT(compat_09_,func)

#ifdef SYSVMSG
#else
#endif
#ifdef SYSVSHM
#else
#endif
#ifdef SYSVSEM
#else
#endif
#ifdef NFSSERVER
#else
#endif

#else /* COMPAT_09 */
#define compat_09(func) nosys
#endif /* COMPAT_09 */


#ifdef COMPAT_10
#define compat_10(func) __CONCAT(compat_10_,func)

#ifdef SYSVMSG
#else
#endif
#ifdef SYSVSHM
#else
#endif
#ifdef SYSVSEM
#else
#endif
#ifdef NFSSERVER
#else
#endif

#else /* COMPAT_10 */
#define compat_10(func) nosys
#endif /* COMPAT_10 */

#define	s(type)	sizeof(type)

struct sysent svr4_sysent[] = {
	{ 0, 0,
	    nosys },				/* 0 = syscall */
	{ 1, s(struct exit_args),
	    exit },				/* 1 = exit */
	{ 0, 0,
	    fork },				/* 2 = fork */
	{ 3, s(struct read_args),
	    read },				/* 3 = read */
	{ 3, s(struct write_args),
	    write },				/* 4 = write */
	{ 3, s(struct svr4_open_args),
	    svr4_open },			/* 5 = svr4_open */
	{ 1, s(struct close_args),
	    close },				/* 6 = close */
	{ 1, s(struct svr4_wait_args),
	    svr4_wait },			/* 7 = svr4_wait */
	{ 2, s(struct svr4_creat_args),
	    svr4_creat },			/* 8 = svr4_creat */
	{ 2, s(struct link_args),
	    link },				/* 9 = link */
	{ 1, s(struct unlink_args),
	    unlink },				/* 10 = unlink */
	{ 2, s(struct svr4_execv_args),
	    svr4_execv },			/* 11 = svr4_execv */
	{ 1, s(struct chdir_args),
	    chdir },				/* 12 = chdir */
	{ 1, s(struct svr4_time_args),
	    svr4_time },			/* 13 = svr4_time */
	{ 3, s(struct svr4_mknod_args),
	    svr4_mknod },			/* 14 = svr4_mknod */
	{ 2, s(struct chmod_args),
	    chmod },				/* 15 = chmod */
	{ 3, s(struct chown_args),
	    chown },				/* 16 = chown */
	{ 1, s(struct svr4_break_args),
	    svr4_break },			/* 17 = svr4_break */
	{ 2, s(struct svr4_stat_args),
	    svr4_stat },			/* 18 = svr4_stat */
	{ 3, s(struct lseek_args),
	    lseek },				/* 19 = lseek */
	{ 0, 0,
	    getpid },				/* 20 = getpid */
	{ 0, 0,
	    nosys },				/* 21 = unimplemented svr4_old_mount */
	{ 0, 0,
	    nosys },				/* 22 = unimplemented System V umount */
	{ 1, s(struct setuid_args),
	    setuid },				/* 23 = setuid */
	{ 0, 0,
	    getuid },				/* 24 = getuid */
	{ 0, 0,
	    nosys },				/* 25 = unimplemented svr4_stime */
	{ 0, 0,
	    nosys },				/* 26 = unimplemented svr4_ptrace */
	{ 0, 0,
	    nosys },				/* 27 = unimplemented svr4_alarm */
	{ 2, s(struct svr4_fstat_args),
	    svr4_fstat },			/* 28 = svr4_fstat */
	{ 0, 0,
	    nosys },				/* 29 = unimplemented svr4_pause */
	{ 0, 0,
	    nosys },				/* 30 = unimplemented svr4_utime */
	{ 0, 0,
	    nosys },				/* 31 = unimplemented was stty */
	{ 0, 0,
	    nosys },				/* 32 = unimplemented was gtty */
	{ 2, s(struct svr4_access_args),
	    svr4_access },			/* 33 = svr4_access */
	{ 0, 0,
	    nosys },				/* 34 = unimplemented svr4_nice */
	{ 0, 0,
	    nosys },				/* 35 = unimplemented svr4_statfs */
	{ 0, 0,
	    sync },				/* 36 = sync */
	{ 2, s(struct kill_args),
	    kill },				/* 37 = kill */
	{ 0, 0,
	    nosys },				/* 38 = unimplemented svr4_fstatfs */
	{ 0, 0,
	    nosys },				/* 39 = unimplemented svr4_pgrpsys */
	{ 0, 0,
	    nosys },				/* 40 = unimplemented svr4_xenix */
	{ 1, s(struct dup_args),
	    dup },				/* 41 = dup */
	{ 0, 0,
	    pipe },				/* 42 = pipe */
	{ 1, s(struct svr4_times_args),
	    svr4_times },			/* 43 = svr4_times */
	{ 0, 0,
	    nosys },				/* 44 = unimplemented svr4_profil */
	{ 0, 0,
	    nosys },				/* 45 = unimplemented svr4_plock */
	{ 0, 0,
	    nosys },				/* 46 = unimplemented svr4_setgid */
	{ 0, 0,
	    getgid },				/* 47 = getgid */
	{ 2, s(struct svr4_signal_args),
	    svr4_signal },			/* 48 = svr4_signal */
#ifdef SYSVMSG
	{ 0, 0,
	    nosys },				/* 49 = unimplemented { int msgsys ( int which , int a2 , int a3 , int a4 , int a5 , int a6 ) ; } */
#else
	{ 0, 0,
	    nosys },				/* 49 = unimplemented nosys */
#endif
	{ 1, s(struct svr4_syssun_args),
	    svr4_syssun },			/* 50 = svr4_syssun */
	{ 0, 0,
	    nosys },				/* 51 = unimplemented svr4_acct */
#ifdef SYSVSHM
	{ 0, 0,
	    nosys },				/* 52 = unimplemented { int shmsys ( int which , int a2 , int a3 , int a4 ) ; } */
#else
	{ 0, 0,
	    nosys },				/* 52 = unimplemented nosys */
#endif
#ifdef SYSVSEM
	{ 0, 0,
	    nosys },				/* 53 = unimplemented { int semsys ( int which , int a2 , int a3 , int a4 , int a5 ) ; } */
#else
	{ 0, 0,
	    nosys },				/* 53 = unimplemented nosys */
#endif
	{ 3, s(struct svr4_ioctl_args),
	    svr4_ioctl },			/* 54 = svr4_ioctl */
	{ 0, 0,
	    nosys },				/* 55 = unimplemented svr4_uadmin */
	{ 0, 0,
	    nosys },				/* 56 = unimplemented svr4_exch */
	{ 1, s(struct svr4_utssys_args),
	    svr4_utssys },			/* 57 = svr4_utssys */
	{ 1, s(struct fsync_args),
	    fsync },				/* 58 = fsync */
	{ 3, s(struct svr4_execve_args),
	    svr4_execve },			/* 59 = svr4_execve */
	{ 1, s(struct umask_args),
	    umask },				/* 60 = umask */
	{ 1, s(struct chroot_args),
	    chroot },				/* 61 = chroot */
	{ 3, s(struct svr4_fcntl_args),
	    svr4_fcntl },			/* 62 = svr4_fcntl */
	{ 0, 0,
	    nosys },				/* 63 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 64 = unimplemented reserved for unix/pc */
	{ 0, 0,
	    nosys },				/* 65 = unimplemented reserved for unix/pc */
	{ 0, 0,
	    nosys },				/* 66 = unimplemented reserved for unix/pc */
	{ 0, 0,
	    nosys },				/* 67 = unimplemented reserved for unix/pc */
	{ 0, 0,
	    nosys },				/* 68 = unimplemented reserved for unix/pc */
	{ 0, 0,
	    nosys },				/* 69 = unimplemented reserved for unix/pc */
	{ 0, 0,
	    nosys },				/* 70 = obsolete svr4_advfs */
	{ 0, 0,
	    nosys },				/* 71 = obsolete svr4_unadvfs */
	{ 0, 0,
	    nosys },				/* 72 = obsolete svr4_rmount */
	{ 0, 0,
	    nosys },				/* 73 = obsolete svr4_rumount */
	{ 0, 0,
	    nosys },				/* 74 = obsolete svr4_rfstart */
	{ 0, 0,
	    nosys },				/* 75 = obsolete svr4_sigret */
	{ 0, 0,
	    nosys },				/* 76 = obsolete svr4_rdebug */
	{ 0, 0,
	    nosys },				/* 77 = obsolete svr4_rfstop */
	{ 0, 0,
	    nosys },				/* 78 = unimplemented svr4_rfsys */
	{ 2, s(struct mkdir_args),
	    mkdir },				/* 79 = mkdir */
	{ 1, s(struct rmdir_args),
	    rmdir },				/* 80 = rmdir */
	{ 3, s(struct svr4_getdents_args),
	    svr4_getdents },			/* 81 = svr4_getdents */
	{ 0, 0,
	    nosys },				/* 82 = obsolete svr4_libattach */
	{ 0, 0,
	    nosys },				/* 83 = obsolete svr4_libdetach */
	{ 0, 0,
	    nosys },				/* 84 = unimplemented svr4_sysfs */
	{ 0, 0,
	    nosys },				/* 85 = unimplemented svr4_getmsg */
	{ 0, 0,
	    nosys },				/* 86 = unimplemented svr4_putmsg */
	{ 0, 0,
	    nosys },				/* 87 = unimplemented svr4_poll */
	{ 2, s(struct svr4_lstat_args),
	    svr4_lstat },			/* 88 = svr4_lstat */
	{ 2, s(struct symlink_args),
	    symlink },				/* 89 = symlink */
	{ 3, s(struct readlink_args),
	    readlink },				/* 90 = readlink */
	{ 2, s(struct getgroups_args),
	    getgroups },			/* 91 = getgroups */
	{ 2, s(struct setgroups_args),
	    setgroups },			/* 92 = setgroups */
	{ 2, s(struct fchmod_args),
	    fchmod },				/* 93 = fchmod */
	{ 3, s(struct fchown_args),
	    fchown },				/* 94 = fchown */
	{ 2, s(struct sigprocmask_args),
	    sigprocmask },			/* 95 = sigprocmask */
	{ 2, s(struct sigaltstack_args),
	    sigaltstack },			/* 96 = sigaltstack */
	{ 1, s(struct sigsuspend_args),
	    sigsuspend },			/* 97 = sigsuspend */
	{ 3, s(struct sigaction_args),
	    sigaction },			/* 98 = sigaction */
	{ 1, s(struct svr4_sigpending_args),
	    svr4_sigpending },			/* 99 = svr4_sigpending */
	{ 0, 0,
	    nosys },				/* 100 = unimplemented svr4_context */
	{ 0, 0,
	    nosys },				/* 101 = unimplemented svr4_evsys */
	{ 0, 0,
	    nosys },				/* 102 = unimplemented svr4_evtrapret */
	{ 0, 0,
	    nosys },				/* 103 = unimplemented svr4_statvfs */
	{ 0, 0,
	    nosys },				/* 104 = unimplemented svr4_fstatvfs */
	{ 0, 0,
	    nosys },				/* 105 = unimplemented svr4 reserved */
#ifdef NFSSERVER
	{ 0, 0,
	    nosys },				/* 106 = unimplemented svr4_nfssvc */
#else
	{ 0, 0,
	    nosys },				/* 106 = unimplemented nosys */
#endif
	{ 0, 0,
	    nosys },				/* 107 = unimplemented svr4_waitsys */
	{ 0, 0,
	    nosys },				/* 108 = unimplemented svr4_sigsendsys */
	{ 0, 0,
	    nosys },				/* 109 = unimplemented svr4_hrtsys */
	{ 0, 0,
	    nosys },				/* 110 = unimplemented svr4_acancel */
	{ 0, 0,
	    nosys },				/* 111 = unimplemented svr4_async */
	{ 0, 0,
	    nosys },				/* 112 = unimplemented svr4_priocntlsys */
	{ 0, 0,
	    nosys },				/* 113 = unimplemented svr4_pathconf */
	{ 0, 0,
	    nosys },				/* 114 = unimplemented svr4_mincore */
	{ 6, s(struct svr4_mmap_args),
	    svr4_mmap },			/* 115 = svr4_mmap */
	{ 3, s(struct mprotect_args),
	    mprotect },				/* 116 = mprotect */
	{ 2, s(struct munmap_args),
	    munmap },				/* 117 = munmap */
	{ 2, s(struct fpathconf_args),
	    fpathconf },			/* 118 = fpathconf */
	{ 0, 0,
	    vfork },				/* 119 = vfork */
	{ 1, s(struct fchdir_args),
	    fchdir },				/* 120 = fchdir */
	{ 3, s(struct readv_args),
	    readv },				/* 121 = readv */
	{ 3, s(struct writev_args),
	    writev },				/* 122 = writev */
	{ 3, s(struct svr4_xstat_args),
	    svr4_xstat },			/* 123 = svr4_xstat */
	{ 3, s(struct svr4_lxstat_args),
	    svr4_lxstat },			/* 124 = svr4_lxstat */
	{ 3, s(struct svr4_fxstat_args),
	    svr4_fxstat },			/* 125 = svr4_fxstat */
	{ 0, 0,
	    nosys },				/* 126 = unimplemented svr4_xmknod */
	{ 0, 0,
	    nosys },				/* 127 = unimplemented svr4_clocal */
	{ 2, s(struct svr4_setrlimit_args),
	    svr4_setrlimit },			/* 128 = svr4_setrlimit */
	{ 2, s(struct svr4_getrlimit_args),
	    svr4_getrlimit },			/* 129 = svr4_getrlimit */
	{ 0, 0,
	    nosys },				/* 130 = unimplemented svr4_lchown */
	{ 0, 0,
	    nosys },				/* 131 = unimplemented svr4_memcntl */
	{ 0, 0,
	    nosys },				/* 132 = unimplemented svr4_getpmsg */
	{ 0, 0,
	    nosys },				/* 133 = unimplemented svr4_putpmsg */
	{ 2, s(struct rename_args),
	    rename },				/* 134 = rename */
	{ 2, s(struct svr4_uname_args),
	    svr4_uname },			/* 135 = svr4_uname */
	{ 1, s(struct setegid_args),
	    setegid },				/* 136 = setegid */
	{ 1, s(struct svr4_sysconfig_args),
	    svr4_sysconfig },			/* 137 = svr4_sysconfig */
	{ 2, s(struct adjtime_args),
	    adjtime },				/* 138 = adjtime */
	{ 0, 0,
	    nosys },				/* 139 = unimplemented svr4_systeminfo */
	{ 0, 0,
	    nosys },				/* 140 = unimplemented reserved */
	{ 1, s(struct seteuid_args),
	    seteuid },				/* 141 = seteuid */
	{ 0, 0,
	    nosys },				/* 142 = unimplemented vtrace */
	{ 0, 0,
	    nosys },				/* 143 = unimplemented svr4_fork1 */
	{ 0, 0,
	    nosys },				/* 144 = unimplemented svr4_sigwait */
	{ 0, 0,
	    nosys },				/* 145 = unimplemented svr4_lwp_info */
	{ 0, 0,
	    nosys },				/* 146 = unimplemented svr4_yield */
	{ 0, 0,
	    nosys },				/* 147 = unimplemented svr4_lwp_sema_p */
	{ 0, 0,
	    nosys },				/* 148 = unimplemented svr4_lwp_sema_v */
	{ 0, 0,
	    nosys },				/* 149 = unimplemented reserved */
	{ 0, 0,
	    nosys },				/* 150 = unimplemented reserved */
	{ 0, 0,
	    nosys },				/* 151 = unimplemented reserved */
	{ 0, 0,
	    nosys },				/* 152 = unimplemented svr4_modctl */
	{ 1, s(struct svr4_fchroot_args),
	    svr4_fchroot },			/* 153 = svr4_fchroot */
	{ 0, 0,
	    nosys },				/* 154 = unimplemented svr4_utimes */
	{ 0, 0,
	    svr4_vhangup },			/* 155 = svr4_vhangup */
	{ 2, s(struct gettimeofday_args),
	    gettimeofday },			/* 156 = gettimeofday */
	{ 2, s(struct getitimer_args),
	    getitimer },			/* 157 = getitimer */
	{ 3, s(struct setitimer_args),
	    setitimer },			/* 158 = setitimer */
	{ 0, 0,
	    nosys },				/* 159 = unimplemented svr4_lwp_create */
	{ 0, 0,
	    nosys },				/* 160 = unimplemented svr4_lwp_exit */
	{ 0, 0,
	    nosys },				/* 161 = unimplemented svr4_lwp_suspend */
	{ 0, 0,
	    nosys },				/* 162 = unimplemented svr4_lwp_continue */
	{ 0, 0,
	    nosys },				/* 163 = unimplemented svr4_lwp_kill */
	{ 0, 0,
	    nosys },				/* 164 = unimplemented svr4_lwp_self */
	{ 0, 0,
	    nosys },				/* 165 = unimplemented svr4_lwp_getprivate */
	{ 0, 0,
	    nosys },				/* 166 = unimplemented svr4_lwp_setprivate */
	{ 0, 0,
	    nosys },				/* 167 = unimplemented svr4_lwp_wait */
	{ 0, 0,
	    nosys },				/* 168 = unimplemented svr4_lwp_mutex_unlock */
	{ 0, 0,
	    nosys },				/* 169 = unimplemented svr4_lwp_mutex_lock */
	{ 0, 0,
	    nosys },				/* 170 = unimplemented svr4_lwp_cond_wait */
	{ 0, 0,
	    nosys },				/* 171 = unimplemented svr4_lwp_cond_signal */
	{ 0, 0,
	    nosys },				/* 172 = unimplemented svr4_lwp_cond_broadcast */
	{ 0, 0,
	    nosys },				/* 173 = unimplemented svr4_pread */
	{ 0, 0,
	    nosys },				/* 174 = unimplemented svr4_pwrite */
	{ 0, 0,
	    nosys },				/* 175 = unimplemented svr4_llseek */
	{ 0, 0,
	    nosys },				/* 176 = unimplemented svr4_inst_sync */
	{ 0, 0,
	    nosys },				/* 177 = unimplemented reserved */
	{ 0, 0,
	    nosys },				/* 178 = unimplemented reserved */
	{ 0, 0,
	    nosys },				/* 179 = unimplemented reserved */
	{ 0, 0,
	    nosys },				/* 180 = unimplemented reserved */
	{ 0, 0,
	    nosys },				/* 181 = unimplemented reserved */
	{ 0, 0,
	    nosys },				/* 182 = unimplemented reserved */
	{ 0, 0,
	    nosys },				/* 183 = unimplemented reserved */
	{ 0, 0,
	    nosys },				/* 184 = unimplemented reserved */
	{ 0, 0,
	    nosys },				/* 185 = unimplemented reserved */
	{ 0, 0,
	    nosys },				/* 186 = unimplemented svr4_auditsys */
};

int	nsvr4_sysent= sizeof(svr4_sysent) / sizeof(svr4_sysent[0]);
