/*
 * System call names.
 *
 * DO NOT EDIT-- this file is automatically generated.
 * created from	NetBSD: syscalls.master,v 1.11 1995/08/27 20:51:53 fvdl Exp 
 */

char *linux_syscallnames[] = {
	"syscall",			/* 0 = syscall */
	"exit",			/* 1 = exit */
	"linux_fork",			/* 2 = linux_fork */
	"read",			/* 3 = read */
	"write",			/* 4 = write */
	"linux_open",			/* 5 = linux_open */
	"close",			/* 6 = close */
	"linux_waitpid",			/* 7 = linux_waitpid */
	"linux_creat",			/* 8 = linux_creat */
	"link",			/* 9 = link */
	"linux_unlink",			/* 10 = linux_unlink */
	"linux_execve",			/* 11 = linux_execve */
	"linux_chdir",			/* 12 = linux_chdir */
	"linux_time",			/* 13 = linux_time */
	"linux_mknod",			/* 14 = linux_mknod */
	"linux_chmod",			/* 15 = linux_chmod */
	"linux_chown",			/* 16 = linux_chown */
	"linux_break",			/* 17 = linux_break */
	"#18 (obsolete linux_ostat)",		/* 18 = obsolete linux_ostat */
	"compat_43_lseek",			/* 19 = compat_43_lseek */
	"getpid",			/* 20 = getpid */
	"#21 (unimplemented linux_mount)",		/* 21 = unimplemented linux_mount */
	"#22 (unimplemented linux_umount)",		/* 22 = unimplemented linux_umount */
	"setuid",			/* 23 = setuid */
	"getuid",			/* 24 = getuid */
	"#25 (unimplemented linux_stime)",		/* 25 = unimplemented linux_stime */
	"#26 (unimplemented linux_ptrace)",		/* 26 = unimplemented linux_ptrace */
	"linux_alarm",			/* 27 = linux_alarm */
	"#28 (obsolete linux_ofstat)",		/* 28 = obsolete linux_ofstat */
	"linux_pause",			/* 29 = linux_pause */
	"linux_utime",			/* 30 = linux_utime */
	"#31 (unimplemented linux_stty)",		/* 31 = unimplemented linux_stty */
	"#32 (unimplemented linux_gtty)",		/* 32 = unimplemented linux_gtty */
	"linux_access",			/* 33 = linux_access */
	"#34 (unimplemented linux_nice)",		/* 34 = unimplemented linux_nice */
	"#35 (unimplemented linux_ftime)",		/* 35 = unimplemented linux_ftime */
	"sync",			/* 36 = sync */
	"linux_kill",			/* 37 = linux_kill */
	"linux_rename",			/* 38 = linux_rename */
	"linux_mkdir",			/* 39 = linux_mkdir */
	"linux_rmdir",			/* 40 = linux_rmdir */
	"dup",			/* 41 = dup */
	"linux_pipe",			/* 42 = linux_pipe */
	"linux_times",			/* 43 = linux_times */
	"#44 (unimplemented linux_prof)",		/* 44 = unimplemented linux_prof */
	"linux_brk",			/* 45 = linux_brk */
	"setgid",			/* 46 = setgid */
	"getgid",			/* 47 = getgid */
	"linux_signal",			/* 48 = linux_signal */
	"geteuid",			/* 49 = geteuid */
	"getegid",			/* 50 = getegid */
	"acct",			/* 51 = acct */
	"#52 (unimplemented linux_phys)",		/* 52 = unimplemented linux_phys */
	"#53 (unimplemented linux_lock)",		/* 53 = unimplemented linux_lock */
	"linux_ioctl",			/* 54 = linux_ioctl */
	"linux_fcntl",			/* 55 = linux_fcntl */
	"#56 (unimplemented linux_mpx)",		/* 56 = unimplemented linux_mpx */
	"setpgid",			/* 57 = setpgid */
	"#58 (unimplemented linux_ulimit)",		/* 58 = unimplemented linux_ulimit */
	"linux_oldolduname",			/* 59 = linux_oldolduname */
	"umask",			/* 60 = umask */
	"chroot",			/* 61 = chroot */
	"#62 (unimplemented linux_ustat)",		/* 62 = unimplemented linux_ustat */
	"dup2",			/* 63 = dup2 */
	"getppid",			/* 64 = getppid */
	"getpgrp",			/* 65 = getpgrp */
	"setsid",			/* 66 = setsid */
	"linux_sigaction",			/* 67 = linux_sigaction */
	"linux_siggetmask",			/* 68 = linux_siggetmask */
	"linux_sigsetmask",			/* 69 = linux_sigsetmask */
	"compat_43_setreuid",			/* 70 = compat_43_setreuid */
	"compat_43_setregid",			/* 71 = compat_43_setregid */
	"linux_sigsuspend",			/* 72 = linux_sigsuspend */
	"linux_sigpending",			/* 73 = linux_sigpending */
	"compat_43_sethostname",			/* 74 = compat_43_sethostname */
	"compat_43_setrlimit",			/* 75 = compat_43_setrlimit */
	"compat_43_getrlimit",			/* 76 = compat_43_getrlimit */
	"getrusage",			/* 77 = getrusage */
	"gettimeofday",			/* 78 = gettimeofday */
	"settimeofday",			/* 79 = settimeofday */
	"getgroups",			/* 80 = getgroups */
	"setgroups",			/* 81 = setgroups */
	"linux_oldselect",			/* 82 = linux_oldselect */
	"linux_symlink",			/* 83 = linux_symlink */
	"compat_43_lstat",			/* 84 = compat_43_lstat */
	"linux_readlink",			/* 85 = linux_readlink */
	"linux_uselib",			/* 86 = linux_uselib */
	"swapon",			/* 87 = swapon */
	"reboot",			/* 88 = reboot */
	"linux_readdir",			/* 89 = linux_readdir */
	"linux_mmap",			/* 90 = linux_mmap */
	"munmap",			/* 91 = munmap */
	"linux_truncate",			/* 92 = linux_truncate */
	"compat_43_ftruncate",			/* 93 = compat_43_ftruncate */
	"fchmod",			/* 94 = fchmod */
	"fchown",			/* 95 = fchown */
	"getpriority",			/* 96 = getpriority */
	"setpriority",			/* 97 = setpriority */
	"profil",			/* 98 = profil */
	"linux_statfs",			/* 99 = linux_statfs */
	"linux_fstatfs",			/* 100 = linux_fstatfs */
#ifdef __i386__
	"linux_ioperm",			/* 101 = linux_ioperm */
#else
	"#101 (unimplemented linux_ioperm)",		/* 101 = unimplemented linux_ioperm */
#endif
	"linux_socketcall",			/* 102 = linux_socketcall */
	"#103 (unimplemented linux_klog)",		/* 103 = unimplemented linux_klog */
	"setitimer",			/* 104 = setitimer */
	"getitimer",			/* 105 = getitimer */
	"linux_stat",			/* 106 = linux_stat */
	"linux_lstat",			/* 107 = linux_lstat */
	"linux_fstat",			/* 108 = linux_fstat */
	"linux_olduname",			/* 109 = linux_olduname */
#ifdef __i386__
	"linux_iopl",			/* 110 = linux_iopl */
#else
	"#110 (unimplemented linux_iopl)",		/* 110 = unimplemented linux_iopl */
#endif
	"#111 (unimplemented linux_vhangup)",		/* 111 = unimplemented linux_vhangup */
	"#112 (unimplemented linux_idle)",		/* 112 = unimplemented linux_idle */
	"#113 (unimplemented linux_vm86)",		/* 113 = unimplemented linux_vm86 */
	"linux_wait4",			/* 114 = linux_wait4 */
	"#115 (unimplemented linux_swapoff)",		/* 115 = unimplemented linux_swapoff */
	"#116 (unimplemented linux_sysinfo)",		/* 116 = unimplemented linux_sysinfo */
	"linux_ipc",			/* 117 = linux_ipc */
	"fsync",			/* 118 = fsync */
	"linux_sigreturn",			/* 119 = linux_sigreturn */
	"#120 (unimplemented linux_clone)",		/* 120 = unimplemented linux_clone */
	"compat_09_setdomainname",			/* 121 = compat_09_setdomainname */
	"linux_uname",			/* 122 = linux_uname */
#ifdef __i386__
	"linux_modify_ldt",			/* 123 = linux_modify_ldt */
#else
	"#123 (unimplemented linux_modify_ldt)",		/* 123 = unimplemented linux_modify_ldt */
#endif
	"#124 (unimplemented linux_adjtimex)",		/* 124 = unimplemented linux_adjtimex */
	"mprotect",			/* 125 = mprotect */
	"linux_sigprocmask",			/* 126 = linux_sigprocmask */
	"#127 (unimplemented linux_create_module)",		/* 127 = unimplemented linux_create_module */
	"#128 (unimplemented linux_init_module)",		/* 128 = unimplemented linux_init_module */
	"#129 (unimplemented linux_delete_module)",		/* 129 = unimplemented linux_delete_module */
	"#130 (unimplemented linux_get_kernel_syms)",		/* 130 = unimplemented linux_get_kernel_syms */
	"#131 (unimplemented linux_quotactl)",		/* 131 = unimplemented linux_quotactl */
	"linux_getpgid",			/* 132 = linux_getpgid */
	"fchdir",			/* 133 = fchdir */
	"#134 (unimplemented linux_bdflush)",		/* 134 = unimplemented linux_bdflush */
	"#135 (unimplemented linux_sysfs)",		/* 135 = unimplemented linux_sysfs */
	"linux_personality",			/* 136 = linux_personality */
	"#137 (unimplemented linux_afs_syscall)",		/* 137 = unimplemented linux_afs_syscall */
	"#138 (unimplemented linux_setfsuid)",		/* 138 = unimplemented linux_setfsuid */
	"#139 (unimplemented linux_getfsuid)",		/* 139 = unimplemented linux_getfsuid */
	"linux_llseek",			/* 140 = linux_llseek */
	"linux_getdents",			/* 141 = linux_getdents */
	"linux_select",			/* 142 = linux_select */
	"flock",			/* 143 = flock */
};
