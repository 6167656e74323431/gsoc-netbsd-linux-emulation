/*
 * System call argument lists.
 *
 * DO NOT EDIT-- this file is automatically generated.
 * created from	NetBSD: syscalls.master,v 1.33 1996/06/23 11:06:54 mycroft Exp 
 */

#define	syscallarg(x)	union { x datum; register_t pad; }

struct sys_exit_args {
	syscallarg(int) rval;
};

struct sys_read_args {
	syscallarg(int) fd;
	syscallarg(char *) buf;
	syscallarg(u_int) nbyte;
};

struct sys_write_args {
	syscallarg(int) fd;
	syscallarg(char *) buf;
	syscallarg(u_int) nbyte;
};

struct sys_open_args {
	syscallarg(char *) path;
	syscallarg(int) flags;
	syscallarg(int) mode;
};

struct sys_close_args {
	syscallarg(int) fd;
};

struct sys_wait4_args {
	syscallarg(int) pid;
	syscallarg(int *) status;
	syscallarg(int) options;
	syscallarg(struct rusage *) rusage;
};

struct compat_43_sys_creat_args {
	syscallarg(char *) path;
	syscallarg(int) mode;
};

struct sys_link_args {
	syscallarg(char *) path;
	syscallarg(char *) link;
};

struct sys_unlink_args {
	syscallarg(char *) path;
};

struct sys_chdir_args {
	syscallarg(char *) path;
};

struct sys_fchdir_args {
	syscallarg(int) fd;
};

struct sys_mknod_args {
	syscallarg(char *) path;
	syscallarg(int) mode;
	syscallarg(int) dev;
};

struct sys_chmod_args {
	syscallarg(char *) path;
	syscallarg(int) mode;
};

struct sys_chown_args {
	syscallarg(char *) path;
	syscallarg(int) uid;
	syscallarg(int) gid;
};

struct sys_obreak_args {
	syscallarg(char *) nsize;
};

struct sys_getfsstat_args {
	syscallarg(struct statfs *) buf;
	syscallarg(long) bufsize;
	syscallarg(int) flags;
};

struct compat_43_sys_lseek_args {
	syscallarg(int) fd;
	syscallarg(long) offset;
	syscallarg(int) whence;
};

struct sys_mount_args {
	syscallarg(char *) type;
	syscallarg(char *) path;
	syscallarg(int) flags;
	syscallarg(caddr_t) data;
};

struct sys_unmount_args {
	syscallarg(char *) path;
	syscallarg(int) flags;
};

struct sys_setuid_args {
	syscallarg(uid_t) uid;
};

struct sys_ptrace_args {
	syscallarg(int) req;
	syscallarg(pid_t) pid;
	syscallarg(caddr_t) addr;
	syscallarg(int) data;
};

struct sys_recvmsg_args {
	syscallarg(int) s;
	syscallarg(struct msghdr *) msg;
	syscallarg(int) flags;
};

struct sys_sendmsg_args {
	syscallarg(int) s;
	syscallarg(caddr_t) msg;
	syscallarg(int) flags;
};

struct sys_recvfrom_args {
	syscallarg(int) s;
	syscallarg(caddr_t) buf;
	syscallarg(size_t) len;
	syscallarg(int) flags;
	syscallarg(caddr_t) from;
	syscallarg(int *) fromlenaddr;
};

struct sys_accept_args {
	syscallarg(int) s;
	syscallarg(caddr_t) name;
	syscallarg(int *) anamelen;
};

struct sys_getpeername_args {
	syscallarg(int) fdes;
	syscallarg(caddr_t) asa;
	syscallarg(int *) alen;
};

struct sys_getsockname_args {
	syscallarg(int) fdes;
	syscallarg(caddr_t) asa;
	syscallarg(int *) alen;
};

struct sys_access_args {
	syscallarg(char *) path;
	syscallarg(int) flags;
};

struct sys_chflags_args {
	syscallarg(char *) path;
	syscallarg(int) flags;
};

struct sys_fchflags_args {
	syscallarg(int) fd;
	syscallarg(int) flags;
};

struct sys_kill_args {
	syscallarg(int) pid;
	syscallarg(int) signum;
};

struct compat_43_sys_stat_args {
	syscallarg(char *) path;
	syscallarg(struct ostat *) ub;
};

struct compat_43_sys_lstat_args {
	syscallarg(char *) path;
	syscallarg(struct ostat *) ub;
};

struct sys_dup_args {
	syscallarg(u_int) fd;
};

struct sys_profil_args {
	syscallarg(caddr_t) samples;
	syscallarg(size_t) size;
	syscallarg(u_long) offset;
	syscallarg(u_int) scale;
};

struct sys_ktrace_args {
	syscallarg(char *) fname;
	syscallarg(int) ops;
	syscallarg(int) facs;
	syscallarg(int) pid;
};

struct sys_sigaction_args {
	syscallarg(int) signum;
	syscallarg(struct sigaction *) nsa;
	syscallarg(struct sigaction *) osa;
};

struct sys_sigprocmask_args {
	syscallarg(int) how;
	syscallarg(sigset_t) mask;
};

struct sys_getlogin_args {
	syscallarg(char *) namebuf;
	syscallarg(u_int) namelen;
};

struct sys_setlogin_args {
	syscallarg(char *) namebuf;
};

struct sys_acct_args {
	syscallarg(char *) path;
};

struct sys_sigaltstack_args {
	syscallarg(struct sigaltstack *) nss;
	syscallarg(struct sigaltstack *) oss;
};

struct sys_ioctl_args {
	syscallarg(int) fd;
	syscallarg(u_long) com;
	syscallarg(caddr_t) data;
};

struct compat_12_sys_reboot_args {
	syscallarg(int) opt;
};

struct sys_revoke_args {
	syscallarg(char *) path;
};

struct sys_symlink_args {
	syscallarg(char *) path;
	syscallarg(char *) link;
};

struct sys_readlink_args {
	syscallarg(char *) path;
	syscallarg(char *) buf;
	syscallarg(int) count;
};

struct sys_execve_args {
	syscallarg(char *) path;
	syscallarg(char **) argp;
	syscallarg(char **) envp;
};

struct sys_umask_args {
	syscallarg(int) newmask;
};

struct sys_chroot_args {
	syscallarg(char *) path;
};

struct compat_43_sys_fstat_args {
	syscallarg(int) fd;
	syscallarg(struct ostat *) sb;
};

struct compat_43_sys_getkerninfo_args {
	syscallarg(int) op;
	syscallarg(char *) where;
	syscallarg(int *) size;
	syscallarg(int) arg;
};

struct sys_msync_args {
	syscallarg(caddr_t) addr;
	syscallarg(size_t) len;
};

struct sys_sbrk_args {
	syscallarg(int) incr;
};

struct sys_sstk_args {
	syscallarg(int) incr;
};

struct compat_43_sys_mmap_args {
	syscallarg(caddr_t) addr;
	syscallarg(size_t) len;
	syscallarg(int) prot;
	syscallarg(int) flags;
	syscallarg(int) fd;
	syscallarg(long) pos;
};

struct sys_ovadvise_args {
	syscallarg(int) anom;
};

struct sys_munmap_args {
	syscallarg(caddr_t) addr;
	syscallarg(size_t) len;
};

struct sys_mprotect_args {
	syscallarg(caddr_t) addr;
	syscallarg(size_t) len;
	syscallarg(int) prot;
};

struct sys_madvise_args {
	syscallarg(caddr_t) addr;
	syscallarg(size_t) len;
	syscallarg(int) behav;
};

struct sys_mincore_args {
	syscallarg(caddr_t) addr;
	syscallarg(size_t) len;
	syscallarg(char *) vec;
};

struct sys_getgroups_args {
	syscallarg(u_int) gidsetsize;
	syscallarg(gid_t *) gidset;
};

struct sys_setgroups_args {
	syscallarg(u_int) gidsetsize;
	syscallarg(gid_t *) gidset;
};

struct sys_setpgid_args {
	syscallarg(int) pid;
	syscallarg(int) pgid;
};

struct sys_setitimer_args {
	syscallarg(u_int) which;
	syscallarg(struct itimerval *) itv;
	syscallarg(struct itimerval *) oitv;
};

struct sys_swapon_args {
	syscallarg(char *) name;
};

struct sys_getitimer_args {
	syscallarg(u_int) which;
	syscallarg(struct itimerval *) itv;
};

struct compat_43_sys_gethostname_args {
	syscallarg(char *) hostname;
	syscallarg(u_int) len;
};

struct compat_43_sys_sethostname_args {
	syscallarg(char *) hostname;
	syscallarg(u_int) len;
};

struct sys_dup2_args {
	syscallarg(u_int) from;
	syscallarg(u_int) to;
};

struct sys_fcntl_args {
	syscallarg(int) fd;
	syscallarg(int) cmd;
	syscallarg(void *) arg;
};

struct sys_select_args {
	syscallarg(u_int) nd;
	syscallarg(fd_set *) in;
	syscallarg(fd_set *) ou;
	syscallarg(fd_set *) ex;
	syscallarg(struct timeval *) tv;
};

struct sys_fsync_args {
	syscallarg(int) fd;
};

struct sys_setpriority_args {
	syscallarg(int) which;
	syscallarg(int) who;
	syscallarg(int) prio;
};

struct sys_socket_args {
	syscallarg(int) domain;
	syscallarg(int) type;
	syscallarg(int) protocol;
};

struct sys_connect_args {
	syscallarg(int) s;
	syscallarg(caddr_t) name;
	syscallarg(int) namelen;
};

struct compat_43_sys_accept_args {
	syscallarg(int) s;
	syscallarg(caddr_t) name;
	syscallarg(int *) anamelen;
};

struct sys_getpriority_args {
	syscallarg(int) which;
	syscallarg(int) who;
};

struct compat_43_sys_send_args {
	syscallarg(int) s;
	syscallarg(caddr_t) buf;
	syscallarg(int) len;
	syscallarg(int) flags;
};

struct compat_43_sys_recv_args {
	syscallarg(int) s;
	syscallarg(caddr_t) buf;
	syscallarg(int) len;
	syscallarg(int) flags;
};

struct sys_sigreturn_args {
	syscallarg(struct sigcontext *) sigcntxp;
};

struct sys_bind_args {
	syscallarg(int) s;
	syscallarg(caddr_t) name;
	syscallarg(int) namelen;
};

struct sys_setsockopt_args {
	syscallarg(int) s;
	syscallarg(int) level;
	syscallarg(int) name;
	syscallarg(caddr_t) val;
	syscallarg(int) valsize;
};

struct sys_listen_args {
	syscallarg(int) s;
	syscallarg(int) backlog;
};

struct compat_43_sys_sigvec_args {
	syscallarg(int) signum;
	syscallarg(struct sigvec *) nsv;
	syscallarg(struct sigvec *) osv;
};

struct compat_43_sys_sigblock_args {
	syscallarg(int) mask;
};

struct compat_43_sys_sigsetmask_args {
	syscallarg(int) mask;
};

struct sys_sigsuspend_args {
	syscallarg(int) mask;
};

struct compat_43_sys_sigstack_args {
	syscallarg(struct sigstack *) nss;
	syscallarg(struct sigstack *) oss;
};

struct compat_43_sys_recvmsg_args {
	syscallarg(int) s;
	syscallarg(struct omsghdr *) msg;
	syscallarg(int) flags;
};

struct compat_43_sys_sendmsg_args {
	syscallarg(int) s;
	syscallarg(caddr_t) msg;
	syscallarg(int) flags;
};

struct sys_vtrace_args {
	syscallarg(int) request;
	syscallarg(int) value;
};

struct sys_gettimeofday_args {
	syscallarg(struct timeval *) tp;
	syscallarg(struct timezone *) tzp;
};

struct sys_getrusage_args {
	syscallarg(int) who;
	syscallarg(struct rusage *) rusage;
};

struct sys_getsockopt_args {
	syscallarg(int) s;
	syscallarg(int) level;
	syscallarg(int) name;
	syscallarg(caddr_t) val;
	syscallarg(int *) avalsize;
};

struct sys_readv_args {
	syscallarg(int) fd;
	syscallarg(struct iovec *) iovp;
	syscallarg(u_int) iovcnt;
};

struct sys_writev_args {
	syscallarg(int) fd;
	syscallarg(struct iovec *) iovp;
	syscallarg(u_int) iovcnt;
};

struct sys_settimeofday_args {
	syscallarg(struct timeval *) tv;
	syscallarg(struct timezone *) tzp;
};

struct sys_fchown_args {
	syscallarg(int) fd;
	syscallarg(int) uid;
	syscallarg(int) gid;
};

struct sys_fchmod_args {
	syscallarg(int) fd;
	syscallarg(int) mode;
};

struct compat_43_sys_recvfrom_args {
	syscallarg(int) s;
	syscallarg(caddr_t) buf;
	syscallarg(size_t) len;
	syscallarg(int) flags;
	syscallarg(caddr_t) from;
	syscallarg(int *) fromlenaddr;
};

struct sys_setreuid_args {
	syscallarg(int) ruid;
	syscallarg(int) euid;
};

struct sys_setregid_args {
	syscallarg(int) rgid;
	syscallarg(int) egid;
};

struct sys_rename_args {
	syscallarg(char *) from;
	syscallarg(char *) to;
};

struct compat_43_sys_truncate_args {
	syscallarg(char *) path;
	syscallarg(long) length;
};

struct compat_43_sys_ftruncate_args {
	syscallarg(int) fd;
	syscallarg(long) length;
};

struct sys_flock_args {
	syscallarg(int) fd;
	syscallarg(int) how;
};

struct sys_mkfifo_args {
	syscallarg(char *) path;
	syscallarg(int) mode;
};

struct sys_sendto_args {
	syscallarg(int) s;
	syscallarg(caddr_t) buf;
	syscallarg(size_t) len;
	syscallarg(int) flags;
	syscallarg(caddr_t) to;
	syscallarg(int) tolen;
};

struct sys_shutdown_args {
	syscallarg(int) s;
	syscallarg(int) how;
};

struct sys_socketpair_args {
	syscallarg(int) domain;
	syscallarg(int) type;
	syscallarg(int) protocol;
	syscallarg(int *) rsv;
};

struct sys_mkdir_args {
	syscallarg(char *) path;
	syscallarg(int) mode;
};

struct sys_rmdir_args {
	syscallarg(char *) path;
};

struct sys_utimes_args {
	syscallarg(char *) path;
	syscallarg(struct timeval *) tptr;
};

struct sys_adjtime_args {
	syscallarg(struct timeval *) delta;
	syscallarg(struct timeval *) olddelta;
};

struct compat_43_sys_getpeername_args {
	syscallarg(int) fdes;
	syscallarg(caddr_t) asa;
	syscallarg(int *) alen;
};

struct compat_43_sys_sethostid_args {
	syscallarg(int32_t) hostid;
};

struct compat_43_sys_getrlimit_args {
	syscallarg(u_int) which;
	syscallarg(struct ogetrlimit *) rlp;
};

struct compat_43_sys_setrlimit_args {
	syscallarg(u_int) which;
	syscallarg(struct ogetrlimit *) rlp;
};

struct compat_43_sys_killpg_args {
	syscallarg(int) pgid;
	syscallarg(int) signum;
};

struct sys_quotactl_args {
	syscallarg(char *) path;
	syscallarg(int) cmd;
	syscallarg(int) uid;
	syscallarg(caddr_t) arg;
};

struct compat_43_sys_getsockname_args {
	syscallarg(int) fdec;
	syscallarg(caddr_t) asa;
	syscallarg(int *) alen;
};

struct sys_nfssvc_args {
	syscallarg(int) flag;
	syscallarg(caddr_t) argp;
};

struct compat_43_sys_getdirentries_args {
	syscallarg(int) fd;
	syscallarg(char *) buf;
	syscallarg(u_int) count;
	syscallarg(long *) basep;
};

struct sys_statfs_args {
	syscallarg(char *) path;
	syscallarg(struct statfs *) buf;
};

struct sys_fstatfs_args {
	syscallarg(int) fd;
	syscallarg(struct statfs *) buf;
};

struct sys_getfh_args {
	syscallarg(char *) fname;
	syscallarg(fhandle_t *) fhp;
};

struct compat_09_sys_getdomainname_args {
	syscallarg(char *) domainname;
	syscallarg(int) len;
};

struct compat_09_sys_setdomainname_args {
	syscallarg(char *) domainname;
	syscallarg(int) len;
};

struct compat_09_sys_uname_args {
	syscallarg(struct outsname *) name;
};

struct sys_sysarch_args {
	syscallarg(int) op;
	syscallarg(char *) parms;
};

struct compat_10_sys_semsys_args {
	syscallarg(int) which;
	syscallarg(int) a2;
	syscallarg(int) a3;
	syscallarg(int) a4;
	syscallarg(int) a5;
};

struct compat_10_sys_msgsys_args {
	syscallarg(int) which;
	syscallarg(int) a2;
	syscallarg(int) a3;
	syscallarg(int) a4;
	syscallarg(int) a5;
	syscallarg(int) a6;
};

struct compat_10_sys_shmsys_args {
	syscallarg(int) which;
	syscallarg(int) a2;
	syscallarg(int) a3;
	syscallarg(int) a4;
};

struct ntp_gettime_args {
	syscallarg(struct timex *) tp;
};

struct ntp_adjtime_args {
	syscallarg(struct timex *) tp;
};

struct sys_setgid_args {
	syscallarg(gid_t) gid;
};

struct sys_setegid_args {
	syscallarg(gid_t) egid;
};

struct sys_seteuid_args {
	syscallarg(uid_t) euid;
};

struct lfs_bmapv_args {
	syscallarg(fsid_t *) fsidp;
	syscallarg(struct block_info *) blkiov;
	syscallarg(int) blkcnt;
};

struct lfs_markv_args {
	syscallarg(fsid_t *) fsidp;
	syscallarg(struct block_info *) blkiov;
	syscallarg(int) blkcnt;
};

struct lfs_segclean_args {
	syscallarg(fsid_t *) fsidp;
	syscallarg(u_long) segment;
};

struct lfs_segwait_args {
	syscallarg(fsid_t *) fsidp;
	syscallarg(struct timeval *) tv;
};

struct sys_stat_args {
	syscallarg(char *) path;
	syscallarg(struct stat *) ub;
};

struct sys_fstat_args {
	syscallarg(int) fd;
	syscallarg(struct stat *) sb;
};

struct sys_lstat_args {
	syscallarg(char *) path;
	syscallarg(struct stat *) ub;
};

struct sys_pathconf_args {
	syscallarg(char *) path;
	syscallarg(int) name;
};

struct sys_fpathconf_args {
	syscallarg(int) fd;
	syscallarg(int) name;
};

struct sys_getrlimit_args {
	syscallarg(u_int) which;
	syscallarg(struct rlimit *) rlp;
};

struct sys_setrlimit_args {
	syscallarg(u_int) which;
	syscallarg(struct rlimit *) rlp;
};

struct sys_getdirentries_args {
	syscallarg(int) fd;
	syscallarg(char *) buf;
	syscallarg(u_int) count;
	syscallarg(long *) basep;
};

struct sys_mmap_args {
	syscallarg(caddr_t) addr;
	syscallarg(size_t) len;
	syscallarg(int) prot;
	syscallarg(int) flags;
	syscallarg(int) fd;
	syscallarg(long) pad;
	syscallarg(off_t) pos;
};

struct sys_lseek_args {
	syscallarg(int) fd;
	syscallarg(int) pad;
	syscallarg(off_t) offset;
	syscallarg(int) whence;
};

struct sys_truncate_args {
	syscallarg(char *) path;
	syscallarg(int) pad;
	syscallarg(off_t) length;
};

struct sys_ftruncate_args {
	syscallarg(int) fd;
	syscallarg(int) pad;
	syscallarg(off_t) length;
};

struct sys___sysctl_args {
	syscallarg(int *) name;
	syscallarg(u_int) namelen;
	syscallarg(void *) old;
	syscallarg(size_t *) oldlenp;
	syscallarg(void *) new;
	syscallarg(size_t) newlen;
};

struct sys_mlock_args {
	syscallarg(caddr_t) addr;
	syscallarg(size_t) len;
};

struct sys_munlock_args {
	syscallarg(caddr_t) addr;
	syscallarg(size_t) len;
};

struct sys_undelete_args {
	syscallarg(char *) path;
};

struct sys_futimes_args {
	syscallarg(int) fd;
	syscallarg(struct timeval *) tptr;
};

struct sys_getpgid_args {
	syscallarg(pid_t) pid;
};

struct sys_reboot_args {
	syscallarg(int) opt;
	syscallarg(char *) bootstr;
};

struct sys___semctl_args {
	syscallarg(int) semid;
	syscallarg(int) semnum;
	syscallarg(int) cmd;
	syscallarg(union semun *) arg;
};

struct sys_semget_args {
	syscallarg(key_t) key;
	syscallarg(int) nsems;
	syscallarg(int) semflg;
};

struct sys_semop_args {
	syscallarg(int) semid;
	syscallarg(struct sembuf *) sops;
	syscallarg(u_int) nsops;
};

struct sys_semconfig_args {
	syscallarg(int) flag;
};

struct sys_msgctl_args {
	syscallarg(int) msqid;
	syscallarg(int) cmd;
	syscallarg(struct msqid_ds *) buf;
};

struct sys_msgget_args {
	syscallarg(key_t) key;
	syscallarg(int) msgflg;
};

struct sys_msgsnd_args {
	syscallarg(int) msqid;
	syscallarg(void *) msgp;
	syscallarg(size_t) msgsz;
	syscallarg(int) msgflg;
};

struct sys_msgrcv_args {
	syscallarg(int) msqid;
	syscallarg(void *) msgp;
	syscallarg(size_t) msgsz;
	syscallarg(long) msgtyp;
	syscallarg(int) msgflg;
};

struct sys_shmat_args {
	syscallarg(int) shmid;
	syscallarg(void *) shmaddr;
	syscallarg(int) shmflg;
};

struct sys_shmctl_args {
	syscallarg(int) shmid;
	syscallarg(int) cmd;
	syscallarg(struct shmid_ds *) buf;
};

struct sys_shmdt_args {
	syscallarg(void *) shmaddr;
};

struct sys_shmget_args {
	syscallarg(key_t) key;
	syscallarg(int) size;
	syscallarg(int) shmflg;
};

/*
 * System call prototypes.
 */

int	sys_nosys	__P((struct proc *, void *, register_t *));
int	sys_exit	__P((struct proc *, void *, register_t *));
int	sys_fork	__P((struct proc *, void *, register_t *));
int	sys_read	__P((struct proc *, void *, register_t *));
int	sys_write	__P((struct proc *, void *, register_t *));
int	sys_open	__P((struct proc *, void *, register_t *));
int	sys_close	__P((struct proc *, void *, register_t *));
int	sys_wait4	__P((struct proc *, void *, register_t *));
int	compat_43_sys_creat	__P((struct proc *, void *, register_t *));
int	sys_link	__P((struct proc *, void *, register_t *));
int	sys_unlink	__P((struct proc *, void *, register_t *));
int	sys_chdir	__P((struct proc *, void *, register_t *));
int	sys_fchdir	__P((struct proc *, void *, register_t *));
int	sys_mknod	__P((struct proc *, void *, register_t *));
int	sys_chmod	__P((struct proc *, void *, register_t *));
int	sys_chown	__P((struct proc *, void *, register_t *));
int	sys_obreak	__P((struct proc *, void *, register_t *));
int	sys_getfsstat	__P((struct proc *, void *, register_t *));
int	compat_43_sys_lseek	__P((struct proc *, void *, register_t *));
int	sys_getpid	__P((struct proc *, void *, register_t *));
int	sys_mount	__P((struct proc *, void *, register_t *));
int	sys_unmount	__P((struct proc *, void *, register_t *));
int	sys_setuid	__P((struct proc *, void *, register_t *));
int	sys_getuid	__P((struct proc *, void *, register_t *));
int	sys_geteuid	__P((struct proc *, void *, register_t *));
int	sys_ptrace	__P((struct proc *, void *, register_t *));
int	sys_recvmsg	__P((struct proc *, void *, register_t *));
int	sys_sendmsg	__P((struct proc *, void *, register_t *));
int	sys_recvfrom	__P((struct proc *, void *, register_t *));
int	sys_accept	__P((struct proc *, void *, register_t *));
int	sys_getpeername	__P((struct proc *, void *, register_t *));
int	sys_getsockname	__P((struct proc *, void *, register_t *));
int	sys_access	__P((struct proc *, void *, register_t *));
int	sys_chflags	__P((struct proc *, void *, register_t *));
int	sys_fchflags	__P((struct proc *, void *, register_t *));
int	sys_sync	__P((struct proc *, void *, register_t *));
int	sys_kill	__P((struct proc *, void *, register_t *));
int	compat_43_sys_stat	__P((struct proc *, void *, register_t *));
int	sys_getppid	__P((struct proc *, void *, register_t *));
int	compat_43_sys_lstat	__P((struct proc *, void *, register_t *));
int	sys_dup	__P((struct proc *, void *, register_t *));
int	sys_pipe	__P((struct proc *, void *, register_t *));
int	sys_getegid	__P((struct proc *, void *, register_t *));
int	sys_profil	__P((struct proc *, void *, register_t *));
#ifdef KTRACE
int	sys_ktrace	__P((struct proc *, void *, register_t *));
#else
#endif
int	sys_sigaction	__P((struct proc *, void *, register_t *));
int	sys_getgid	__P((struct proc *, void *, register_t *));
int	sys_sigprocmask	__P((struct proc *, void *, register_t *));
int	sys_getlogin	__P((struct proc *, void *, register_t *));
int	sys_setlogin	__P((struct proc *, void *, register_t *));
int	sys_acct	__P((struct proc *, void *, register_t *));
int	sys_sigpending	__P((struct proc *, void *, register_t *));
int	sys_sigaltstack	__P((struct proc *, void *, register_t *));
int	sys_ioctl	__P((struct proc *, void *, register_t *));
int	compat_12_sys_reboot	__P((struct proc *, void *, register_t *));
int	sys_revoke	__P((struct proc *, void *, register_t *));
int	sys_symlink	__P((struct proc *, void *, register_t *));
int	sys_readlink	__P((struct proc *, void *, register_t *));
int	sys_execve	__P((struct proc *, void *, register_t *));
int	sys_umask	__P((struct proc *, void *, register_t *));
int	sys_chroot	__P((struct proc *, void *, register_t *));
int	compat_43_sys_fstat	__P((struct proc *, void *, register_t *));
int	compat_43_sys_getkerninfo	__P((struct proc *, void *, register_t *));
int	compat_43_sys_getpagesize	__P((struct proc *, void *, register_t *));
int	sys_msync	__P((struct proc *, void *, register_t *));
int	sys_vfork	__P((struct proc *, void *, register_t *));
int	sys_sbrk	__P((struct proc *, void *, register_t *));
int	sys_sstk	__P((struct proc *, void *, register_t *));
int	compat_43_sys_mmap	__P((struct proc *, void *, register_t *));
int	sys_ovadvise	__P((struct proc *, void *, register_t *));
int	sys_munmap	__P((struct proc *, void *, register_t *));
int	sys_mprotect	__P((struct proc *, void *, register_t *));
int	sys_madvise	__P((struct proc *, void *, register_t *));
int	sys_mincore	__P((struct proc *, void *, register_t *));
int	sys_getgroups	__P((struct proc *, void *, register_t *));
int	sys_setgroups	__P((struct proc *, void *, register_t *));
int	sys_getpgrp	__P((struct proc *, void *, register_t *));
int	sys_setpgid	__P((struct proc *, void *, register_t *));
int	sys_setitimer	__P((struct proc *, void *, register_t *));
int	compat_43_sys_wait	__P((struct proc *, void *, register_t *));
int	sys_swapon	__P((struct proc *, void *, register_t *));
int	sys_getitimer	__P((struct proc *, void *, register_t *));
int	compat_43_sys_gethostname	__P((struct proc *, void *, register_t *));
int	compat_43_sys_sethostname	__P((struct proc *, void *, register_t *));
int	compat_43_sys_getdtablesize	__P((struct proc *, void *, register_t *));
int	sys_dup2	__P((struct proc *, void *, register_t *));
int	sys_fcntl	__P((struct proc *, void *, register_t *));
int	sys_select	__P((struct proc *, void *, register_t *));
int	sys_fsync	__P((struct proc *, void *, register_t *));
int	sys_setpriority	__P((struct proc *, void *, register_t *));
int	sys_socket	__P((struct proc *, void *, register_t *));
int	sys_connect	__P((struct proc *, void *, register_t *));
int	compat_43_sys_accept	__P((struct proc *, void *, register_t *));
int	sys_getpriority	__P((struct proc *, void *, register_t *));
int	compat_43_sys_send	__P((struct proc *, void *, register_t *));
int	compat_43_sys_recv	__P((struct proc *, void *, register_t *));
int	sys_sigreturn	__P((struct proc *, void *, register_t *));
int	sys_bind	__P((struct proc *, void *, register_t *));
int	sys_setsockopt	__P((struct proc *, void *, register_t *));
int	sys_listen	__P((struct proc *, void *, register_t *));
int	compat_43_sys_sigvec	__P((struct proc *, void *, register_t *));
int	compat_43_sys_sigblock	__P((struct proc *, void *, register_t *));
int	compat_43_sys_sigsetmask	__P((struct proc *, void *, register_t *));
int	sys_sigsuspend	__P((struct proc *, void *, register_t *));
int	compat_43_sys_sigstack	__P((struct proc *, void *, register_t *));
int	compat_43_sys_recvmsg	__P((struct proc *, void *, register_t *));
int	compat_43_sys_sendmsg	__P((struct proc *, void *, register_t *));
#ifdef TRACE
int	sys_vtrace	__P((struct proc *, void *, register_t *));
#else
#endif
int	sys_gettimeofday	__P((struct proc *, void *, register_t *));
int	sys_getrusage	__P((struct proc *, void *, register_t *));
int	sys_getsockopt	__P((struct proc *, void *, register_t *));
int	sys_readv	__P((struct proc *, void *, register_t *));
int	sys_writev	__P((struct proc *, void *, register_t *));
int	sys_settimeofday	__P((struct proc *, void *, register_t *));
int	sys_fchown	__P((struct proc *, void *, register_t *));
int	sys_fchmod	__P((struct proc *, void *, register_t *));
int	compat_43_sys_recvfrom	__P((struct proc *, void *, register_t *));
int	sys_setreuid	__P((struct proc *, void *, register_t *));
int	sys_setregid	__P((struct proc *, void *, register_t *));
int	sys_rename	__P((struct proc *, void *, register_t *));
int	compat_43_sys_truncate	__P((struct proc *, void *, register_t *));
int	compat_43_sys_ftruncate	__P((struct proc *, void *, register_t *));
int	sys_flock	__P((struct proc *, void *, register_t *));
int	sys_mkfifo	__P((struct proc *, void *, register_t *));
int	sys_sendto	__P((struct proc *, void *, register_t *));
int	sys_shutdown	__P((struct proc *, void *, register_t *));
int	sys_socketpair	__P((struct proc *, void *, register_t *));
int	sys_mkdir	__P((struct proc *, void *, register_t *));
int	sys_rmdir	__P((struct proc *, void *, register_t *));
int	sys_utimes	__P((struct proc *, void *, register_t *));
int	sys_adjtime	__P((struct proc *, void *, register_t *));
int	compat_43_sys_getpeername	__P((struct proc *, void *, register_t *));
int	compat_43_sys_gethostid	__P((struct proc *, void *, register_t *));
int	compat_43_sys_sethostid	__P((struct proc *, void *, register_t *));
int	compat_43_sys_getrlimit	__P((struct proc *, void *, register_t *));
int	compat_43_sys_setrlimit	__P((struct proc *, void *, register_t *));
int	compat_43_sys_killpg	__P((struct proc *, void *, register_t *));
int	sys_setsid	__P((struct proc *, void *, register_t *));
int	sys_quotactl	__P((struct proc *, void *, register_t *));
int	compat_43_sys_quota	__P((struct proc *, void *, register_t *));
int	compat_43_sys_getsockname	__P((struct proc *, void *, register_t *));
#if defined(NFSCLIENT) || defined(NFSSERVER)
int	sys_nfssvc	__P((struct proc *, void *, register_t *));
#else
#endif
int	compat_43_sys_getdirentries	__P((struct proc *, void *, register_t *));
int	sys_statfs	__P((struct proc *, void *, register_t *));
int	sys_fstatfs	__P((struct proc *, void *, register_t *));
#ifdef NFSCLIENT
int	sys_getfh	__P((struct proc *, void *, register_t *));
#else
#endif
int	compat_09_sys_getdomainname	__P((struct proc *, void *, register_t *));
int	compat_09_sys_setdomainname	__P((struct proc *, void *, register_t *));
int	compat_09_sys_uname	__P((struct proc *, void *, register_t *));
int	sys_sysarch	__P((struct proc *, void *, register_t *));
#if defined(SYSVSEM) && !defined(alpha)
int	compat_10_sys_semsys	__P((struct proc *, void *, register_t *));
#else
#endif
#if defined(SYSVMSG) && !defined(alpha)
int	compat_10_sys_msgsys	__P((struct proc *, void *, register_t *));
#else
#endif
#if defined(SYSVSHM) && !defined(alpha)
int	compat_10_sys_shmsys	__P((struct proc *, void *, register_t *));
#else
#endif
int	ntp_gettime	__P((struct proc *, void *, register_t *));
int	ntp_adjtime	__P((struct proc *, void *, register_t *));
int	sys_setgid	__P((struct proc *, void *, register_t *));
int	sys_setegid	__P((struct proc *, void *, register_t *));
int	sys_seteuid	__P((struct proc *, void *, register_t *));
#ifdef LFS
int	lfs_bmapv	__P((struct proc *, void *, register_t *));
int	lfs_markv	__P((struct proc *, void *, register_t *));
int	lfs_segclean	__P((struct proc *, void *, register_t *));
int	lfs_segwait	__P((struct proc *, void *, register_t *));
#else
#endif
int	sys_stat	__P((struct proc *, void *, register_t *));
int	sys_fstat	__P((struct proc *, void *, register_t *));
int	sys_lstat	__P((struct proc *, void *, register_t *));
int	sys_pathconf	__P((struct proc *, void *, register_t *));
int	sys_fpathconf	__P((struct proc *, void *, register_t *));
int	sys_getrlimit	__P((struct proc *, void *, register_t *));
int	sys_setrlimit	__P((struct proc *, void *, register_t *));
int	sys_getdirentries	__P((struct proc *, void *, register_t *));
int	sys_mmap	__P((struct proc *, void *, register_t *));
int	sys_nosys	__P((struct proc *, void *, register_t *));
int	sys_lseek	__P((struct proc *, void *, register_t *));
int	sys_truncate	__P((struct proc *, void *, register_t *));
int	sys_ftruncate	__P((struct proc *, void *, register_t *));
int	sys___sysctl	__P((struct proc *, void *, register_t *));
int	sys_mlock	__P((struct proc *, void *, register_t *));
int	sys_munlock	__P((struct proc *, void *, register_t *));
int	sys_undelete	__P((struct proc *, void *, register_t *));
int	sys_futimes	__P((struct proc *, void *, register_t *));
int	sys_getpgid	__P((struct proc *, void *, register_t *));
int	sys_reboot	__P((struct proc *, void *, register_t *));
#ifdef LKM
int	sys_lkmnosys	__P((struct proc *, void *, register_t *));
int	sys_lkmnosys	__P((struct proc *, void *, register_t *));
int	sys_lkmnosys	__P((struct proc *, void *, register_t *));
int	sys_lkmnosys	__P((struct proc *, void *, register_t *));
int	sys_lkmnosys	__P((struct proc *, void *, register_t *));
int	sys_lkmnosys	__P((struct proc *, void *, register_t *));
int	sys_lkmnosys	__P((struct proc *, void *, register_t *));
int	sys_lkmnosys	__P((struct proc *, void *, register_t *));
int	sys_lkmnosys	__P((struct proc *, void *, register_t *));
int	sys_lkmnosys	__P((struct proc *, void *, register_t *));
#else	/* !LKM */
#endif	/* !LKM */
#ifdef SYSVSEM
int	sys___semctl	__P((struct proc *, void *, register_t *));
int	sys_semget	__P((struct proc *, void *, register_t *));
int	sys_semop	__P((struct proc *, void *, register_t *));
int	sys_semconfig	__P((struct proc *, void *, register_t *));
#else
#endif
#ifdef SYSVMSG
int	sys_msgctl	__P((struct proc *, void *, register_t *));
int	sys_msgget	__P((struct proc *, void *, register_t *));
int	sys_msgsnd	__P((struct proc *, void *, register_t *));
int	sys_msgrcv	__P((struct proc *, void *, register_t *));
#else
#endif
#ifdef SYSVSHM
int	sys_shmat	__P((struct proc *, void *, register_t *));
int	sys_shmctl	__P((struct proc *, void *, register_t *));
int	sys_shmdt	__P((struct proc *, void *, register_t *));
int	sys_shmget	__P((struct proc *, void *, register_t *));
#else
#endif
