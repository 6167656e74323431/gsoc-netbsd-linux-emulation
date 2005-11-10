/* $NetBSD: pecoff_syscall.h,v 1.15 2005/11/10 18:47:31 christos Exp $ */

/*
 * System call numbers.
 *
 * DO NOT EDIT-- this file is automatically generated.
 * created from	NetBSD: syscalls.master,v 1.14 2005/11/10 18:47:16 christos Exp
 */

/* syscall: "syscall" ret: "int" args: "int" "..." */
#define	PECOFF_SYS_syscall	0

/* syscall: "exit" ret: "void" args: "int" */
#define	PECOFF_SYS_exit	1

/* syscall: "fork" ret: "int" args: */
#define	PECOFF_SYS_fork	2

/* syscall: "read" ret: "ssize_t" args: "int" "void *" "size_t" */
#define	PECOFF_SYS_read	3

/* syscall: "write" ret: "ssize_t" args: "int" "const void *" "size_t" */
#define	PECOFF_SYS_write	4

/* syscall: "open" ret: "int" args: "const char *" "int" "..." */
#define	PECOFF_SYS_open	5

/* syscall: "close" ret: "int" args: "int" */
#define	PECOFF_SYS_close	6

/* syscall: "wait4" ret: "int" args: "int" "int *" "int" "struct rusage *" */
#define	PECOFF_SYS_wait4	7

				/* 8 is excluded { int sys_creat ( const char * path , mode_t mode ) ; } ocreat */
/* syscall: "link" ret: "int" args: "const char *" "const char *" */
#define	PECOFF_SYS_link	9

/* syscall: "unlink" ret: "int" args: "const char *" */
#define	PECOFF_SYS_unlink	10

				/* 11 is obsolete execv */
/* syscall: "chdir" ret: "int" args: "const char *" */
#define	PECOFF_SYS_chdir	12

/* syscall: "fchdir" ret: "int" args: "int" */
#define	PECOFF_SYS_fchdir	13

/* syscall: "mknod" ret: "int" args: "const char *" "mode_t" "dev_t" */
#define	PECOFF_SYS_mknod	14

/* syscall: "chmod" ret: "int" args: "const char *" "mode_t" */
#define	PECOFF_SYS_chmod	15

/* syscall: "chown" ret: "int" args: "const char *" "uid_t" "gid_t" */
#define	PECOFF_SYS_chown	16

/* syscall: "break" ret: "int" args: "char *" */
#define	PECOFF_SYS_break	17

#ifdef COMPAT_20
/* syscall: "getfsstat" ret: "int" args: "struct statfs12 *" "long" "int" */
#define	PECOFF_SYS_getfsstat	18

#else
				/* 18 is excluded compat_20_sys_getfsstat */
#endif
				/* 19 is excluded { long sys_lseek ( int fd , long offset , int whence ) ; } olseek */
#ifdef COMPAT_43
/* syscall: "getpid" ret: "pid_t" args: */
#define	PECOFF_SYS_getpid	20

#else
/* syscall: "getpid" ret: "pid_t" args: */
#define	PECOFF_SYS_getpid	20

#endif
/* syscall: "mount" ret: "int" args: "const char *" "const char *" "int" "void *" */
#define	PECOFF_SYS_mount	21

/* syscall: "unmount" ret: "int" args: "const char *" "int" */
#define	PECOFF_SYS_unmount	22

/* syscall: "setuid" ret: "int" args: "uid_t" */
#define	PECOFF_SYS_setuid	23

#ifdef COMPAT_43
/* syscall: "getuid" ret: "uid_t" args: */
#define	PECOFF_SYS_getuid	24

#else
/* syscall: "getuid" ret: "uid_t" args: */
#define	PECOFF_SYS_getuid	24

#endif
/* syscall: "geteuid" ret: "uid_t" args: */
#define	PECOFF_SYS_geteuid	25

/* syscall: "ptrace" ret: "int" args: "int" "pid_t" "caddr_t" "int" */
#define	PECOFF_SYS_ptrace	26

/* syscall: "recvmsg" ret: "ssize_t" args: "int" "struct msghdr *" "int" */
#define	PECOFF_SYS_recvmsg	27

/* syscall: "sendmsg" ret: "ssize_t" args: "int" "const struct msghdr *" "int" */
#define	PECOFF_SYS_sendmsg	28

/* syscall: "recvfrom" ret: "ssize_t" args: "int" "void *" "size_t" "int" "struct sockaddr *" "unsigned int *" */
#define	PECOFF_SYS_recvfrom	29

/* syscall: "accept" ret: "int" args: "int" "struct sockaddr *" "unsigned int *" */
#define	PECOFF_SYS_accept	30

/* syscall: "getpeername" ret: "int" args: "int" "struct sockaddr *" "unsigned int *" */
#define	PECOFF_SYS_getpeername	31

/* syscall: "getsockname" ret: "int" args: "int" "struct sockaddr *" "unsigned int *" */
#define	PECOFF_SYS_getsockname	32

/* syscall: "access" ret: "int" args: "const char *" "int" */
#define	PECOFF_SYS_access	33

/* syscall: "chflags" ret: "int" args: "const char *" "u_long" */
#define	PECOFF_SYS_chflags	34

/* syscall: "fchflags" ret: "int" args: "int" "u_long" */
#define	PECOFF_SYS_fchflags	35

/* syscall: "sync" ret: "void" args: */
#define	PECOFF_SYS_sync	36

/* syscall: "kill" ret: "int" args: "int" "int" */
#define	PECOFF_SYS_kill	37

				/* 38 is excluded { int pecoff_compat_43_sys_stat ( const char * path , struct stat43 * ub ) ; } stat43 */
/* syscall: "getppid" ret: "pid_t" args: */
#define	PECOFF_SYS_getppid	39

				/* 40 is excluded { int pecoff_compat_43_sys_lstat ( const char * path , struct stat43 * ub ) ; } lstat43 */
/* syscall: "dup" ret: "int" args: "int" */
#define	PECOFF_SYS_dup	41

/* syscall: "pipe" ret: "int" args: */
#define	PECOFF_SYS_pipe	42

/* syscall: "getegid" ret: "gid_t" args: */
#define	PECOFF_SYS_getegid	43

/* syscall: "profil" ret: "int" args: "caddr_t" "size_t" "u_long" "u_int" */
#define	PECOFF_SYS_profil	44

#if defined(KTRACE) || !defined(_KERNEL)
/* syscall: "ktrace" ret: "int" args: "const char *" "int" "int" "int" */
#define	PECOFF_SYS_ktrace	45

#else
				/* 45 is excluded ktrace */
#endif
				/* 46 is excluded { int sys_sigaction ( int signum , const struct sigaction13 * nsa , struct sigaction13 * osa ) ; } sigaction13 */
#ifdef COMPAT_43
/* syscall: "getgid" ret: "gid_t" args: */
#define	PECOFF_SYS_getgid	47

#else
/* syscall: "getgid" ret: "gid_t" args: */
#define	PECOFF_SYS_getgid	47

#endif
				/* 48 is excluded { int sys_sigprocmask ( int how , int mask ) ; } sigprocmask13 */
/* syscall: "__getlogin" ret: "int" args: "char *" "size_t" */
#define	PECOFF_SYS___getlogin	49

/* syscall: "__setlogin" ret: "int" args: "const char *" */
#define	PECOFF_SYS___setlogin	50

/* syscall: "acct" ret: "int" args: "const char *" */
#define	PECOFF_SYS_acct	51

				/* 52 is excluded { int sys_sigpending ( void ) ; } sigpending13 */
				/* 53 is excluded { int sys_sigaltstack ( const struct sigaltstack13 * nss , struct sigaltstack13 * oss ) ; } sigaltstack13 */
/* syscall: "ioctl" ret: "int" args: "int" "u_long" "..." */
#define	PECOFF_SYS_ioctl	54

				/* 55 is excluded { int sys_reboot ( int opt ) ; } oreboot */
/* syscall: "revoke" ret: "int" args: "const char *" */
#define	PECOFF_SYS_revoke	56

/* syscall: "symlink" ret: "int" args: "const char *" "const char *" */
#define	PECOFF_SYS_symlink	57

/* syscall: "readlink" ret: "int" args: "const char *" "char *" "size_t" */
#define	PECOFF_SYS_readlink	58

/* syscall: "execve" ret: "int" args: "const char *" "char *const *" "char *const *" */
#define	PECOFF_SYS_execve	59

/* syscall: "umask" ret: "mode_t" args: "mode_t" */
#define	PECOFF_SYS_umask	60

/* syscall: "chroot" ret: "int" args: "const char *" */
#define	PECOFF_SYS_chroot	61

				/* 62 is excluded { int sys_fstat ( int fd , struct stat43 * sb ) ; } fstat43 */
				/* 63 is excluded { int sys_getkerninfo ( int op , char * where , int * size , int arg ) ; } ogetkerninfo */
				/* 64 is excluded { int sys_getpagesize ( void ) ; } ogetpagesize */
				/* 65 is excluded { int sys_msync ( caddr_t addr , size_t len ) ; } */
/* syscall: "vfork" ret: "int" args: */
#define	PECOFF_SYS_vfork	66

				/* 67 is obsolete vread */
				/* 68 is obsolete vwrite */
/* syscall: "sbrk" ret: "int" args: "intptr_t" */
#define	PECOFF_SYS_sbrk	69

/* syscall: "sstk" ret: "int" args: "int" */
#define	PECOFF_SYS_sstk	70

				/* 71 is excluded { int sys_mmap ( caddr_t addr , size_t len , int prot , int flags , int fd , long pos ) ; } ommap */
/* syscall: "vadvise" ret: "int" args: "int" */
#define	PECOFF_SYS_vadvise	72

/* syscall: "munmap" ret: "int" args: "void *" "size_t" */
#define	PECOFF_SYS_munmap	73

/* syscall: "mprotect" ret: "int" args: "void *" "size_t" "int" */
#define	PECOFF_SYS_mprotect	74

/* syscall: "madvise" ret: "int" args: "void *" "size_t" "int" */
#define	PECOFF_SYS_madvise	75

				/* 76 is obsolete vhangup */
				/* 77 is obsolete vlimit */
/* syscall: "mincore" ret: "int" args: "void *" "size_t" "char *" */
#define	PECOFF_SYS_mincore	78

/* syscall: "getgroups" ret: "int" args: "int" "gid_t *" */
#define	PECOFF_SYS_getgroups	79

/* syscall: "setgroups" ret: "int" args: "int" "const gid_t *" */
#define	PECOFF_SYS_setgroups	80

/* syscall: "getpgrp" ret: "int" args: */
#define	PECOFF_SYS_getpgrp	81

/* syscall: "setpgid" ret: "int" args: "int" "int" */
#define	PECOFF_SYS_setpgid	82

/* syscall: "setitimer" ret: "int" args: "int" "const struct itimerval *" "struct itimerval *" */
#define	PECOFF_SYS_setitimer	83

				/* 84 is excluded { int sys_wait ( void ) ; } owait */
				/* 85 is excluded { int sys_swapon ( const char * name ) ; } oswapon */
/* syscall: "getitimer" ret: "int" args: "int" "struct itimerval *" */
#define	PECOFF_SYS_getitimer	86

				/* 87 is excluded { int sys_gethostname ( char * hostname , u_int len ) ; } ogethostname */
				/* 88 is excluded { int sys_sethostname ( char * hostname , u_int len ) ; } osethostname */
				/* 89 is excluded { int sys_getdtablesize ( void ) ; } ogetdtablesize */
/* syscall: "dup2" ret: "int" args: "int" "int" */
#define	PECOFF_SYS_dup2	90

/* syscall: "fcntl" ret: "int" args: "int" "int" "..." */
#define	PECOFF_SYS_fcntl	92

/* syscall: "select" ret: "int" args: "int" "fd_set *" "fd_set *" "fd_set *" "struct timeval *" */
#define	PECOFF_SYS_select	93

/* syscall: "fsync" ret: "int" args: "int" */
#define	PECOFF_SYS_fsync	95

/* syscall: "setpriority" ret: "int" args: "int" "int" "int" */
#define	PECOFF_SYS_setpriority	96

/* syscall: "socket" ret: "int" args: "int" "int" "int" */
#define	PECOFF_SYS_socket	97

/* syscall: "connect" ret: "int" args: "int" "const struct sockaddr *" "unsigned int" */
#define	PECOFF_SYS_connect	98

				/* 99 is excluded { int sys_accept ( int s , caddr_t name , int * anamelen ) ; } oaccept */
/* syscall: "getpriority" ret: "int" args: "int" "int" */
#define	PECOFF_SYS_getpriority	100

				/* 101 is excluded { int sys_send ( int s , caddr_t buf , int len , int flags ) ; } osend */
				/* 102 is excluded { int sys_recv ( int s , caddr_t buf , int len , int flags ) ; } orecv */
				/* 103 is excluded { int sys_sigreturn ( struct sigcontext13 * sigcntxp ) ; } sigreturn13 */
/* syscall: "bind" ret: "int" args: "int" "const struct sockaddr *" "unsigned int" */
#define	PECOFF_SYS_bind	104

/* syscall: "setsockopt" ret: "int" args: "int" "int" "int" "const void *" "unsigned int" */
#define	PECOFF_SYS_setsockopt	105

/* syscall: "listen" ret: "int" args: "int" "int" */
#define	PECOFF_SYS_listen	106

				/* 107 is obsolete vtimes */
				/* 108 is excluded { int sys_sigvec ( int signum , struct sigvec * nsv , struct sigvec * osv ) ; } osigvec */
				/* 109 is excluded { int sys_sigblock ( int mask ) ; } osigblock */
				/* 110 is excluded { int sys_sigsetmask ( int mask ) ; } osigsetmask */
				/* 111 is excluded { int sys_sigsuspend ( int mask ) ; } sigsuspend13 */
				/* 112 is excluded { int sys_sigstack ( struct sigstack * nss , struct sigstack * oss ) ; } osigstack */
				/* 113 is excluded { int sys_recvmsg ( int s , struct omsghdr * msg , int flags ) ; } orecvmsg */
				/* 114 is excluded { int sys_sendmsg ( int s , caddr_t msg , int flags ) ; } osendmsg */
				/* 115 is obsolete vtrace */
/* syscall: "gettimeofday" ret: "int" args: "struct timeval *" "struct timezone *" */
#define	PECOFF_SYS_gettimeofday	116

/* syscall: "getrusage" ret: "int" args: "int" "struct rusage *" */
#define	PECOFF_SYS_getrusage	117

/* syscall: "getsockopt" ret: "int" args: "int" "int" "int" "void *" "unsigned int *" */
#define	PECOFF_SYS_getsockopt	118

				/* 119 is obsolete resuba */
/* syscall: "readv" ret: "ssize_t" args: "int" "const struct iovec *" "int" */
#define	PECOFF_SYS_readv	120

/* syscall: "writev" ret: "ssize_t" args: "int" "const struct iovec *" "int" */
#define	PECOFF_SYS_writev	121

/* syscall: "settimeofday" ret: "int" args: "const struct timeval *" "const struct timezone *" */
#define	PECOFF_SYS_settimeofday	122

/* syscall: "fchown" ret: "int" args: "int" "uid_t" "gid_t" */
#define	PECOFF_SYS_fchown	123

/* syscall: "fchmod" ret: "int" args: "int" "mode_t" */
#define	PECOFF_SYS_fchmod	124

				/* 125 is excluded { int sys_recvfrom ( int s , caddr_t buf , size_t len , int flags , caddr_t from , int * fromlenaddr ) ; } orecvfrom */
/* syscall: "setreuid" ret: "int" args: "uid_t" "uid_t" */
#define	PECOFF_SYS_setreuid	126

/* syscall: "setregid" ret: "int" args: "gid_t" "gid_t" */
#define	PECOFF_SYS_setregid	127

/* syscall: "rename" ret: "int" args: "const char *" "const char *" */
#define	PECOFF_SYS_rename	128

				/* 129 is excluded { int pecoff_compat_43_sys_truncate ( const char * path , long length ) ; } otruncate */
				/* 130 is excluded { int sys_ftruncate ( int fd , long length ) ; } oftruncate */
/* syscall: "flock" ret: "int" args: "int" "int" */
#define	PECOFF_SYS_flock	131

/* syscall: "mkfifo" ret: "int" args: "const char *" "mode_t" */
#define	PECOFF_SYS_mkfifo	132

/* syscall: "sendto" ret: "ssize_t" args: "int" "const void *" "size_t" "int" "const struct sockaddr *" "unsigned int" */
#define	PECOFF_SYS_sendto	133

/* syscall: "shutdown" ret: "int" args: "int" "int" */
#define	PECOFF_SYS_shutdown	134

/* syscall: "socketpair" ret: "int" args: "int" "int" "int" "int *" */
#define	PECOFF_SYS_socketpair	135

/* syscall: "mkdir" ret: "int" args: "const char *" "mode_t" */
#define	PECOFF_SYS_mkdir	136

/* syscall: "rmdir" ret: "int" args: "const char *" */
#define	PECOFF_SYS_rmdir	137

/* syscall: "utimes" ret: "int" args: "const char *" "const struct timeval *" */
#define	PECOFF_SYS_utimes	138

				/* 139 is obsolete 4.2 sigreturn */
/* syscall: "adjtime" ret: "int" args: "const struct timeval *" "struct timeval *" */
#define	PECOFF_SYS_adjtime	140

				/* 141 is excluded { int sys_getpeername ( int fdes , caddr_t asa , int * alen ) ; } ogetpeername */
				/* 142 is excluded { int32_t sys_gethostid ( void ) ; } ogethostid */
				/* 143 is excluded { int sys_sethostid ( int32_t hostid ) ; } osethostid */
				/* 144 is excluded { int sys_getrlimit ( int which , struct orlimit * rlp ) ; } ogetrlimit */
				/* 145 is excluded { int sys_setrlimit ( int which , const struct orlimit * rlp ) ; } osetrlimit */
				/* 146 is excluded { int sys_killpg ( int pgid , int signum ) ; } okillpg */
/* syscall: "setsid" ret: "int" args: */
#define	PECOFF_SYS_setsid	147

/* syscall: "quotactl" ret: "int" args: "const char *" "int" "int" "caddr_t" */
#define	PECOFF_SYS_quotactl	148

				/* 149 is excluded { int sys_quota ( void ) ; } oquota */
				/* 150 is excluded { int sys_getsockname ( int fdec , caddr_t asa , int * alen ) ; } ogetsockname */
#if defined(NFS) || defined(NFSSERVER) || !defined(_KERNEL)
/* syscall: "nfssvc" ret: "int" args: "int" "void *" */
#define	PECOFF_SYS_nfssvc	155

#else
				/* 155 is excluded nfssvc */
#endif
				/* 156 is excluded { int sys_getdirentries ( int fd , char * buf , u_int count , long * basep ) ; } ogetdirentries */
/* syscall: "statfs" ret: "int" args: "const char *" "struct statvfs12 *" */
#define	PECOFF_SYS_statfs	157

#ifdef COMPAT_20
/* syscall: "fstatfs" ret: "int" args: "int" "struct statfs12 *" */
#define	PECOFF_SYS_fstatfs	158

#else
				/* 158 is excluded compat_20_sys_fstatfs */
#endif
/* syscall: "getfh" ret: "int" args: "const char *" "fhandle_t *" */
#define	PECOFF_SYS_getfh	161

				/* 162 is excluded { int sys_getdomainname ( char * domainname , int len ) ; } ogetdomainname */
				/* 163 is excluded { int sys_setdomainname ( char * domainname , int len ) ; } osetdomainname */
				/* 164 is excluded { int sys_uname ( struct outsname * name ) ; } ouname */
/* syscall: "sysarch" ret: "int" args: "int" "void *" */
#define	PECOFF_SYS_sysarch	165

#if (defined(SYSVSEM) || !defined(_KERNEL)) && !defined(_LP64)
				/* 169 is excluded { int sys_semsys ( int which , int a2 , int a3 , int a4 , int a5 ) ; } osemsys */
#else
				/* 169 is excluded 1.0 semsys */
#endif
#if (defined(SYSVMSG) || !defined(_KERNEL)) && !defined(_LP64)
				/* 170 is excluded { int sys_msgsys ( int which , int a2 , int a3 , int a4 , int a5 , int a6 ) ; } omsgsys */
#else
				/* 170 is excluded 1.0 msgsys */
#endif
#if (defined(SYSVSHM) || !defined(_KERNEL)) && !defined(_LP64)
				/* 171 is excluded { int sys_shmsys ( int which , int a2 , int a3 , int a4 ) ; } oshmsys */
#else
				/* 171 is excluded 1.0 shmsys */
#endif
/* syscall: "pread" ret: "ssize_t" args: "int" "void *" "size_t" "int" "off_t" */
#define	PECOFF_SYS_pread	173

/* syscall: "pwrite" ret: "ssize_t" args: "int" "const void *" "size_t" "int" "off_t" */
#define	PECOFF_SYS_pwrite	174

/* syscall: "ntp_gettime" ret: "int" args: "struct ntptimeval *" */
#define	PECOFF_SYS_ntp_gettime	175

#if defined(NTP) || !defined(_KERNEL)
/* syscall: "ntp_adjtime" ret: "int" args: "struct timex *" */
#define	PECOFF_SYS_ntp_adjtime	176

#else
				/* 176 is excluded ntp_adjtime */
#endif
/* syscall: "setgid" ret: "int" args: "gid_t" */
#define	PECOFF_SYS_setgid	181

/* syscall: "setegid" ret: "int" args: "gid_t" */
#define	PECOFF_SYS_setegid	182

/* syscall: "seteuid" ret: "int" args: "uid_t" */
#define	PECOFF_SYS_seteuid	183

#if defined(LFS) || !defined(_KERNEL)
/* syscall: "lfs_bmapv" ret: "int" args: "fsid_t *" "struct block_info *" "int" */
#define	PECOFF_SYS_lfs_bmapv	184

/* syscall: "lfs_markv" ret: "int" args: "fsid_t *" "struct block_info *" "int" */
#define	PECOFF_SYS_lfs_markv	185

/* syscall: "lfs_segclean" ret: "int" args: "fsid_t *" "u_long" */
#define	PECOFF_SYS_lfs_segclean	186

/* syscall: "lfs_segwait" ret: "int" args: "fsid_t *" "struct timeval *" */
#define	PECOFF_SYS_lfs_segwait	187

#else
				/* 184 is excluded lfs_bmapv */
				/* 185 is excluded lfs_markv */
				/* 186 is excluded lfs_segclean */
				/* 187 is excluded lfs_segwait */
#endif
				/* 188 is excluded { int pecoff_compat_12_sys_stat ( const char * path , struct stat12 * ub ) ; } stat12 */
				/* 189 is excluded { int sys_fstat ( int fd , struct stat12 * sb ) ; } fstat12 */
				/* 190 is excluded { int pecoff_compat_12_sys_lstat ( const char * path , struct stat12 * ub ) ; } lstat12 */
/* syscall: "pathconf" ret: "long" args: "const char *" "int" */
#define	PECOFF_SYS_pathconf	191

/* syscall: "fpathconf" ret: "long" args: "int" "int" */
#define	PECOFF_SYS_fpathconf	192

/* syscall: "getrlimit" ret: "int" args: "int" "struct rlimit *" */
#define	PECOFF_SYS_getrlimit	194

/* syscall: "setrlimit" ret: "int" args: "int" "const struct rlimit *" */
#define	PECOFF_SYS_setrlimit	195

				/* 196 is excluded { int sys_getdirentries ( int fd , char * buf , u_int count , long * basep ) ; } */
/* syscall: "mmap" ret: "void *" args: "void *" "size_t" "int" "int" "int" "long" "off_t" */
#define	PECOFF_SYS_mmap	197

/* syscall: "__syscall" ret: "quad_t" args: "quad_t" "..." */
#define	PECOFF_SYS___syscall	198

/* syscall: "lseek" ret: "off_t" args: "int" "int" "off_t" "int" */
#define	PECOFF_SYS_lseek	199

/* syscall: "truncate" ret: "int" args: "const char *" "int" "off_t" */
#define	PECOFF_SYS_truncate	200

/* syscall: "ftruncate" ret: "int" args: "int" "int" "off_t" */
#define	PECOFF_SYS_ftruncate	201

/* syscall: "__sysctl" ret: "int" args: "int *" "u_int" "void *" "size_t *" "void *" "size_t" */
#define	PECOFF_SYS___sysctl	202

/* syscall: "mlock" ret: "int" args: "const void *" "size_t" */
#define	PECOFF_SYS_mlock	203

/* syscall: "munlock" ret: "int" args: "const void *" "size_t" */
#define	PECOFF_SYS_munlock	204

/* syscall: "undelete" ret: "int" args: "const char *" */
#define	PECOFF_SYS_undelete	205

/* syscall: "futimes" ret: "int" args: "int" "const struct timeval *" */
#define	PECOFF_SYS_futimes	206

/* syscall: "getpgid" ret: "pid_t" args: "pid_t" */
#define	PECOFF_SYS_getpgid	207

/* syscall: "reboot" ret: "int" args: "int" "char *" */
#define	PECOFF_SYS_reboot	208

/* syscall: "poll" ret: "int" args: "struct pollfd *" "u_int" "int" */
#define	PECOFF_SYS_poll	209

#if defined(LKM) || !defined(_KERNEL)
#else	/* !LKM */
				/* 210 is excluded lkmnosys */
				/* 211 is excluded lkmnosys */
				/* 212 is excluded lkmnosys */
				/* 213 is excluded lkmnosys */
				/* 214 is excluded lkmnosys */
				/* 215 is excluded lkmnosys */
				/* 216 is excluded lkmnosys */
				/* 217 is excluded lkmnosys */
				/* 218 is excluded lkmnosys */
				/* 219 is excluded lkmnosys */
#endif	/* !LKM */
#if defined(SYSVSEM) || !defined(_KERNEL)
				/* 220 is excluded { int sys___semctl ( int semid , int semnum , int cmd , union __semun * arg ) ; } */
/* syscall: "semget" ret: "int" args: "key_t" "int" "int" */
#define	PECOFF_SYS_semget	221

/* syscall: "semop" ret: "int" args: "int" "struct sembuf *" "size_t" */
#define	PECOFF_SYS_semop	222

/* syscall: "semconfig" ret: "int" args: "int" */
#define	PECOFF_SYS_semconfig	223

#else
				/* 220 is excluded compat_14_semctl */
				/* 221 is excluded semget */
				/* 222 is excluded semop */
				/* 223 is excluded semconfig */
#endif
#if defined(SYSVMSG) || !defined(_KERNEL)
				/* 224 is excluded { int sys_msgctl ( int msqid , int cmd , struct msqid_ds14 * buf ) ; } */
/* syscall: "msgget" ret: "int" args: "key_t" "int" */
#define	PECOFF_SYS_msgget	225

/* syscall: "msgsnd" ret: "int" args: "int" "const void *" "size_t" "int" */
#define	PECOFF_SYS_msgsnd	226

/* syscall: "msgrcv" ret: "ssize_t" args: "int" "void *" "size_t" "long" "int" */
#define	PECOFF_SYS_msgrcv	227

#else
				/* 224 is excluded compat_14_msgctl */
				/* 225 is excluded msgget */
				/* 226 is excluded msgsnd */
				/* 227 is excluded msgrcv */
#endif
#if defined(SYSVSHM) || !defined(_KERNEL)
/* syscall: "shmat" ret: "void *" args: "int" "const void *" "int" */
#define	PECOFF_SYS_shmat	228

				/* 229 is excluded { int sys_shmctl ( int shmid , int cmd , struct shmid_ds14 * buf ) ; } */
/* syscall: "shmdt" ret: "int" args: "const void *" */
#define	PECOFF_SYS_shmdt	230

/* syscall: "shmget" ret: "int" args: "key_t" "size_t" "int" */
#define	PECOFF_SYS_shmget	231

#else
				/* 228 is excluded shmat */
				/* 229 is excluded compat_14_shmctl */
				/* 230 is excluded shmdt */
				/* 231 is excluded shmget */
#endif
/* syscall: "clock_gettime" ret: "int" args: "clockid_t" "struct timespec *" */
#define	PECOFF_SYS_clock_gettime	232

/* syscall: "clock_settime" ret: "int" args: "clockid_t" "const struct timespec *" */
#define	PECOFF_SYS_clock_settime	233

/* syscall: "clock_getres" ret: "int" args: "clockid_t" "struct timespec *" */
#define	PECOFF_SYS_clock_getres	234

/* syscall: "timer_create" ret: "int" args: "clockid_t" "struct sigevent *" "timer_t *" */
#define	PECOFF_SYS_timer_create	235

/* syscall: "timer_delete" ret: "int" args: "timer_t" */
#define	PECOFF_SYS_timer_delete	236

/* syscall: "timer_settime" ret: "int" args: "timer_t" "int" "const struct itimerspec *" "struct itimerspec *" */
#define	PECOFF_SYS_timer_settime	237

/* syscall: "timer_gettime" ret: "int" args: "timer_t" "struct itimerspec *" */
#define	PECOFF_SYS_timer_gettime	238

/* syscall: "timer_getoverrun" ret: "int" args: "timer_t" */
#define	PECOFF_SYS_timer_getoverrun	239

/* syscall: "nanosleep" ret: "int" args: "const struct timespec *" "struct timespec *" */
#define	PECOFF_SYS_nanosleep	240

/* syscall: "fdatasync" ret: "int" args: "int" */
#define	PECOFF_SYS_fdatasync	241

/* syscall: "mlockall" ret: "int" args: "int" */
#define	PECOFF_SYS_mlockall	242

/* syscall: "munlockall" ret: "int" args: */
#define	PECOFF_SYS_munlockall	243

/* syscall: "__sigtimedwait" ret: "int" args: "const sigset_t *" "siginfo_t *" "struct timespec *" */
#define	PECOFF_SYS___sigtimedwait	244

#if defined(P1003_1B_SEMAPHORE) || !defined(_KERNEL)
/* syscall: "_ksem_init" ret: "int" args: "unsigned int" "semid_t *" */
#define	PECOFF_SYS__ksem_init	247

/* syscall: "_ksem_open" ret: "int" args: "const char *" "int" "mode_t" "unsigned int" "semid_t *" */
#define	PECOFF_SYS__ksem_open	248

/* syscall: "_ksem_unlink" ret: "int" args: "const char *" */
#define	PECOFF_SYS__ksem_unlink	249

/* syscall: "_ksem_close" ret: "int" args: "semid_t" */
#define	PECOFF_SYS__ksem_close	250

/* syscall: "_ksem_post" ret: "int" args: "semid_t" */
#define	PECOFF_SYS__ksem_post	251

/* syscall: "_ksem_wait" ret: "int" args: "semid_t" */
#define	PECOFF_SYS__ksem_wait	252

/* syscall: "_ksem_trywait" ret: "int" args: "semid_t" */
#define	PECOFF_SYS__ksem_trywait	253

/* syscall: "_ksem_getvalue" ret: "int" args: "semid_t" "unsigned int *" */
#define	PECOFF_SYS__ksem_getvalue	254

/* syscall: "_ksem_destroy" ret: "int" args: "semid_t" */
#define	PECOFF_SYS__ksem_destroy	255

#else
				/* 247 is excluded sys__ksem_init */
				/* 248 is excluded sys__ksem_open */
				/* 249 is excluded sys__ksem_unlink */
				/* 250 is excluded sys__ksem_close */
				/* 251 is excluded sys__ksem_post */
				/* 252 is excluded sys__ksem_wait */
				/* 253 is excluded sys__ksem_trywait */
				/* 254 is excluded sys__ksem_getvalue */
				/* 255 is excluded sys__ksem_destroy */
#endif
/* syscall: "__posix_rename" ret: "int" args: "const char *" "const char *" */
#define	PECOFF_SYS___posix_rename	270

/* syscall: "swapctl" ret: "int" args: "int" "const void *" "int" */
#define	PECOFF_SYS_swapctl	271

/* syscall: "__getdents30" ret: "int" args: "int" "char *" "size_t" */
#define	PECOFF_SYS___getdents30	272

/* syscall: "minherit" ret: "int" args: "void *" "size_t" "int" */
#define	PECOFF_SYS_minherit	273

/* syscall: "lchmod" ret: "int" args: "const char *" "mode_t" */
#define	PECOFF_SYS_lchmod	274

/* syscall: "lchown" ret: "int" args: "const char *" "uid_t" "gid_t" */
#define	PECOFF_SYS_lchown	275

/* syscall: "lutimes" ret: "int" args: "const char *" "const struct timeval *" */
#define	PECOFF_SYS_lutimes	276

/* syscall: "__msync13" ret: "int" args: "void *" "size_t" "int" */
#define	PECOFF_SYS___msync13	277

/* syscall: "__stat30" ret: "int" args: "const char *" "struct stat *" */
#define	PECOFF_SYS___stat30	278

/* syscall: "__fstat30" ret: "int" args: "int" "struct stat *" */
#define	PECOFF_SYS___fstat30	279

/* syscall: "__lstat30" ret: "int" args: "const char *" "struct stat *" */
#define	PECOFF_SYS___lstat30	280

/* syscall: "__sigaltstack14" ret: "int" args: "const struct sigaltstack *" "struct sigaltstack *" */
#define	PECOFF_SYS___sigaltstack14	281

/* syscall: "__vfork14" ret: "int" args: */
#define	PECOFF_SYS___vfork14	282

/* syscall: "__posix_chown" ret: "int" args: "const char *" "uid_t" "gid_t" */
#define	PECOFF_SYS___posix_chown	283

/* syscall: "__posix_fchown" ret: "int" args: "int" "uid_t" "gid_t" */
#define	PECOFF_SYS___posix_fchown	284

/* syscall: "__posix_lchown" ret: "int" args: "const char *" "uid_t" "gid_t" */
#define	PECOFF_SYS___posix_lchown	285

/* syscall: "getsid" ret: "pid_t" args: "pid_t" */
#define	PECOFF_SYS_getsid	286

/* syscall: "__clone" ret: "pid_t" args: "int" "void *" */
#define	PECOFF_SYS___clone	287

#if defined(KTRACE) || !defined(_KERNEL)
/* syscall: "fktrace" ret: "int" args: "const int" "int" "int" "int" */
#define	PECOFF_SYS_fktrace	288

#else
				/* 288 is excluded ktrace */
#endif
/* syscall: "preadv" ret: "ssize_t" args: "int" "const struct iovec *" "int" "int" "off_t" */
#define	PECOFF_SYS_preadv	289

/* syscall: "pwritev" ret: "ssize_t" args: "int" "const struct iovec *" "int" "int" "off_t" */
#define	PECOFF_SYS_pwritev	290

#ifdef COMPAT_16
/* syscall: "__sigaction14" ret: "int" args: "int" "const struct sigaction *" "struct sigaction *" */
#define	PECOFF_SYS___sigaction14	291

#else
				/* 291 is excluded compat_16_sys___sigaction14 */
#endif
/* syscall: "__sigpending14" ret: "int" args: "sigset_t *" */
#define	PECOFF_SYS___sigpending14	292

/* syscall: "__sigprocmask14" ret: "int" args: "int" "const sigset_t *" "sigset_t *" */
#define	PECOFF_SYS___sigprocmask14	293

/* syscall: "__sigsuspend14" ret: "int" args: "const sigset_t *" */
#define	PECOFF_SYS___sigsuspend14	294

#ifdef COMPAT_16
/* syscall: "__sigreturn14" ret: "int" args: "struct sigcontext *" */
#define	PECOFF_SYS___sigreturn14	295

#else
				/* 295 is excluded compat_16_sys___sigreturn14 */
#endif
/* syscall: "__getcwd" ret: "int" args: "char *" "size_t" */
#define	PECOFF_SYS___getcwd	296

/* syscall: "fchroot" ret: "int" args: "int" */
#define	PECOFF_SYS_fchroot	297

/* syscall: "fhopen" ret: "int" args: "const fhandle_t *" "int" */
#define	PECOFF_SYS_fhopen	298

/* syscall: "fhstat" ret: "int" args: "const fhandle_t *" "struct stat *" */
#define	PECOFF_SYS_fhstat	299

#ifdef COMPAT_20
/* syscall: "fhstatfs" ret: "int" args: "const fhandle_t *" "struct statfs12 *" */
#define	PECOFF_SYS_fhstatfs	300

#else
				/* 300 is excluded compat_20_sys_fhstatfs */
#endif
#if defined(SYSVSEM) || !defined(_KERNEL)
/* syscall: "____semctl13" ret: "int" args: "int" "int" "int" "..." */
#define	PECOFF_SYS_____semctl13	301

#else
				/* 301 is excluded ____semctl13 */
#endif
#if defined(SYSVMSG) || !defined(_KERNEL)
/* syscall: "__msgctl13" ret: "int" args: "int" "int" "struct msqid_ds *" */
#define	PECOFF_SYS___msgctl13	302

#else
				/* 302 is excluded __msgctl13 */
#endif
#if defined(SYSVSHM) || !defined(_KERNEL)
/* syscall: "__shmctl13" ret: "int" args: "int" "int" "struct shmid_ds *" */
#define	PECOFF_SYS___shmctl13	303

#else
				/* 303 is excluded __shmctl13 */
#endif
/* syscall: "lchflags" ret: "int" args: "const char *" "u_long" */
#define	PECOFF_SYS_lchflags	304

/* syscall: "issetugid" ret: "int" args: */
#define	PECOFF_SYS_issetugid	305

/* syscall: "utrace" ret: "int" args: "const char *" "void *" "size_t" */
#define	PECOFF_SYS_utrace	306

/* syscall: "getcontext" ret: "int" args: "struct __ucontext *" */
#define	PECOFF_SYS_getcontext	307

/* syscall: "setcontext" ret: "int" args: "const struct __ucontext *" */
#define	PECOFF_SYS_setcontext	308

/* syscall: "_lwp_create" ret: "int" args: "const struct __ucontext *" "u_long" "lwpid_t *" */
#define	PECOFF_SYS__lwp_create	309

/* syscall: "_lwp_exit" ret: "int" args: */
#define	PECOFF_SYS__lwp_exit	310

/* syscall: "_lwp_self" ret: "lwpid_t" args: */
#define	PECOFF_SYS__lwp_self	311

/* syscall: "_lwp_wait" ret: "int" args: "lwpid_t" "lwpid_t *" */
#define	PECOFF_SYS__lwp_wait	312

/* syscall: "_lwp_suspend" ret: "int" args: "lwpid_t" */
#define	PECOFF_SYS__lwp_suspend	313

/* syscall: "_lwp_continue" ret: "int" args: "lwpid_t" */
#define	PECOFF_SYS__lwp_continue	314

/* syscall: "_lwp_wakeup" ret: "int" args: "lwpid_t" */
#define	PECOFF_SYS__lwp_wakeup	315

/* syscall: "_lwp_getprivate" ret: "void *" args: */
#define	PECOFF_SYS__lwp_getprivate	316

/* syscall: "_lwp_setprivate" ret: "void" args: "void *" */
#define	PECOFF_SYS__lwp_setprivate	317

/* syscall: "sa_register" ret: "int" args: "sa_upcall_t" "sa_upcall_t *" "int" */
#define	PECOFF_SYS_sa_register	330

/* syscall: "sa_stacks" ret: "int" args: "int" "stack_t *" */
#define	PECOFF_SYS_sa_stacks	331

/* syscall: "sa_enable" ret: "int" args: */
#define	PECOFF_SYS_sa_enable	332

/* syscall: "sa_setconcurrency" ret: "int" args: "int" */
#define	PECOFF_SYS_sa_setconcurrency	333

/* syscall: "sa_yield" ret: "int" args: */
#define	PECOFF_SYS_sa_yield	334

/* syscall: "sa_preempt" ret: "int" args: "int" */
#define	PECOFF_SYS_sa_preempt	335

/* syscall: "__sigaction_sigtramp" ret: "int" args: "int" "const struct sigaction *" "struct sigaction *" "void *" "int" */
#define	PECOFF_SYS___sigaction_sigtramp	340

/* syscall: "pmc_get_info" ret: "int" args: "int" "int" "void *" */
#define	PECOFF_SYS_pmc_get_info	341

/* syscall: "pmc_control" ret: "int" args: "int" "int" "void *" */
#define	PECOFF_SYS_pmc_control	342

/* syscall: "rasctl" ret: "int" args: "caddr_t" "size_t" "int" */
#define	PECOFF_SYS_rasctl	343

/* syscall: "kqueue" ret: "int" args: */
#define	PECOFF_SYS_kqueue	344

/* syscall: "kevent" ret: "int" args: "int" "const struct kevent *" "size_t" "struct kevent *" "size_t" "const struct timespec *" */
#define	PECOFF_SYS_kevent	345

/* syscall: "fsync_range" ret: "int" args: "int" "int" "off_t" "off_t" */
#define	PECOFF_SYS_fsync_range	354

/* syscall: "uuidgen" ret: "int" args: "struct uuid *" "int" */
#define	PECOFF_SYS_uuidgen	355

/* syscall: "getvfsstat" ret: "int" args: "struct statvfs *" "size_t" "int" */
#define	PECOFF_SYS_getvfsstat	356

/* syscall: "statvfs1" ret: "int" args: "const char *" "struct statvfs *" "int" */
#define	PECOFF_SYS_statvfs1	357

/* syscall: "fstatvfs1" ret: "int" args: "int" "struct statvfs *" "int" */
#define	PECOFF_SYS_fstatvfs1	358

/* syscall: "fhstatvfs1" ret: "int" args: "const fhandle_t *" "struct statvfs *" "int" */
#define	PECOFF_SYS_fhstatvfs1	359

#define	PECOFF_SYS_MAXSYSCALL	360
#define	PECOFF_SYS_NSYSENT	512
