/*
 * System call switch table.
 *
 * DO NOT EDIT-- this file is automatically generated.
 * created from	NetBSD: syscalls.master,v 1.7 1995/05/10 16:45:47 christos Exp 
 */

#include <sys/param.h>
#include <compat/hpux/hpux.h>
#include <sys/systm.h>
#include <sys/signal.h>
#include <sys/mount.h>
#include <sys/syscallargs.h>
#include <compat/hpux/hpux_syscallargs.h>
#define	s(type)	sizeof(type)

struct sysent hpux_sysent[] = {
	{ 0, 0,
	    nosys },				/* 0 = syscall */
	{ 1, s(struct exit_args),
	    exit },				/* 1 = exit */
	{ 0, 0,
	    hpux_fork },			/* 2 = hpux_fork */
	{ 3, s(struct hpux_read_args),
	    hpux_read },			/* 3 = hpux_read */
	{ 3, s(struct hpux_write_args),
	    hpux_write },			/* 4 = hpux_write */
	{ 3, s(struct hpux_open_args),
	    hpux_open },			/* 5 = hpux_open */
	{ 1, s(struct close_args),
	    close },				/* 6 = close */
	{ 1, s(struct hpux_wait_args),
	    hpux_wait },			/* 7 = hpux_wait */
	{ 2, s(struct hpux_creat_args),
	    hpux_creat },			/* 8 = hpux_creat */
	{ 2, s(struct link_args),
	    link },				/* 9 = link */
	{ 1, s(struct unlink_args),
	    unlink },				/* 10 = unlink */
	{ 2, s(struct hpux_execv_args),
	    hpux_execv },			/* 11 = hpux_execv */
	{ 1, s(struct chdir_args),
	    chdir },				/* 12 = chdir */
	{ 1, s(struct compat_hpux_6x_time_args),
	    compat_hpux_6x(time) },		/* 13 = compat_hpux_6x time */
	{ 3, s(struct mknod_args),
	    mknod },				/* 14 = mknod */
	{ 2, s(struct chmod_args),
	    chmod },				/* 15 = chmod */
	{ 3, s(struct chown_args),
	    chown },				/* 16 = chown */
	{ 1, s(struct obreak_args),
	    obreak },				/* 17 = obreak */
	{ 2, s(struct compat_hpux_6x_stat_args),
	    compat_hpux_6x(stat) },		/* 18 = compat_hpux_6x stat */
	{ 3, s(struct compat_43_lseek_args),
	    compat_43_lseek },			/* 19 = compat_43_lseek */
	{ 0, 0,
	    getpid },				/* 20 = getpid */
	{ 0, 0,
	    nosys },				/* 21 = unimplemented hpux_mount */
	{ 0, 0,
	    nosys },				/* 22 = unimplemented hpux_umount */
	{ 1, s(struct setuid_args),
	    setuid },				/* 23 = setuid */
	{ 0, 0,
	    getuid },				/* 24 = getuid */
	{ 1, s(struct compat_hpux_6x_stime_args),
	    compat_hpux_6x(stime) },		/* 25 = compat_hpux_6x stime */
	{ 4, s(struct hpux_ptrace_args),
	    hpux_ptrace },			/* 26 = hpux_ptrace */
	{ 1, s(struct compat_hpux_6x_alarm_args),
	    compat_hpux_6x(alarm) },		/* 27 = compat_hpux_6x alarm */
	{ 2, s(struct compat_hpux_6x_fstat_args),
	    compat_hpux_6x(fstat) },		/* 28 = compat_hpux_6x fstat */
	{ 0, 0,
	    compat_hpux_6x(pause) },		/* 29 = compat_hpux_6x pause */
	{ 2, s(struct compat_hpux_6x_utime_args),
	    compat_hpux_6x(utime) },		/* 30 = compat_hpux_6x utime */
	{ 2, s(struct compat_hpux_6x_stty_args),
	    compat_hpux_6x(stty) },		/* 31 = compat_hpux_6x stty */
	{ 2, s(struct compat_hpux_6x_gtty_args),
	    compat_hpux_6x(gtty) },		/* 32 = compat_hpux_6x gtty */
	{ 2, s(struct access_args),
	    access },				/* 33 = access */
	{ 1, s(struct compat_hpux_6x_nice_args),
	    compat_hpux_6x(nice) },		/* 34 = compat_hpux_6x nice */
	{ 1, s(struct compat_hpux_6x_ftime_args),
	    compat_hpux_6x(ftime) },		/* 35 = compat_hpux_6x ftime */
	{ 0, 0,
	    sync },				/* 36 = sync */
	{ 2, s(struct hpux_kill_args),
	    hpux_kill },			/* 37 = hpux_kill */
	{ 2, s(struct hpux_stat_args),
	    hpux_stat },			/* 38 = hpux_stat */
	{ 0, 0,
	    compat_hpux_6x(setpgrp) },		/* 39 = compat_hpux_6x setpgrp */
	{ 2, s(struct hpux_lstat_args),
	    hpux_lstat },			/* 40 = hpux_lstat */
	{ 1, s(struct hpux_dup_args),
	    hpux_dup },				/* 41 = hpux_dup */
	{ 0, 0,
	    pipe },				/* 42 = pipe */
	{ 1, s(struct compat_hpux_6x_times_args),
	    compat_hpux_6x(times) },		/* 43 = compat_hpux_6x times */
	{ 4, s(struct profil_args),
	    profil },				/* 44 = profil */
	{ 0, 0,
	    nosys },				/* 45 = unimplemented hpux_ki_syscall */
	{ 1, s(struct setgid_args),
	    setgid },				/* 46 = setgid */
	{ 0, 0,
	    getgid },				/* 47 = getgid */
	{ 2, s(struct compat_hpux_6x_ssig_args),
	    compat_hpux_6x(ssig) },		/* 48 = compat_hpux_6x ssig */
	{ 0, 0,
	    nosys },				/* 49 = unimplemented reserved for USG */
	{ 0, 0,
	    nosys },				/* 50 = unimplemented reserved for USG */
	{ 0, 0,
	    nosys },				/* 51 = unimplemented hpux_acct */
	{ 0, 0,
	    nosys },				/* 52 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 53 = unimplemented nosys */
	{ 3, s(struct hpux_ioctl_args),
	    hpux_ioctl },			/* 54 = hpux_ioctl */
	{ 0, 0,
	    nosys },				/* 55 = unimplemented hpux_reboot */
	{ 2, s(struct symlink_args),
	    symlink },				/* 56 = symlink */
	{ 3, s(struct hpux_utssys_args),
	    hpux_utssys },			/* 57 = hpux_utssys */
	{ 3, s(struct readlink_args),
	    readlink },				/* 58 = readlink */
	{ 3, s(struct execve_args),
	    execve },				/* 59 = execve */
	{ 1, s(struct umask_args),
	    umask },				/* 60 = umask */
	{ 1, s(struct chroot_args),
	    chroot },				/* 61 = chroot */
	{ 3, s(struct hpux_fcntl_args),
	    hpux_fcntl },			/* 62 = hpux_fcntl */
	{ 2, s(struct hpux_ulimit_args),
	    hpux_ulimit },			/* 63 = hpux_ulimit */
	{ 0, 0,
	    nosys },				/* 64 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 65 = unimplemented nosys */
	{ 0, 0,
	    hpux_vfork },			/* 66 = hpux_vfork */
	{ 3, s(struct hpux_read_args),
	    hpux_read },			/* 67 = vread */
	{ 3, s(struct hpux_write_args),
	    hpux_write },			/* 68 = vwrite */
	{ 0, 0,
	    nosys },				/* 69 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 70 = unimplemented nosys */
	{ 6, s(struct hpux_mmap_args),
	    hpux_mmap },			/* 71 = hpux_mmap */
	{ 0, 0,
	    nosys },				/* 72 = unimplemented nosys */
	{ 2, s(struct munmap_args),
	    munmap },				/* 73 = munmap */
	{ 3, s(struct mprotect_args),
	    mprotect },				/* 74 = mprotect */
	{ 0, 0,
	    nosys },				/* 75 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 76 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 77 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 78 = unimplemented nosys */
	{ 2, s(struct getgroups_args),
	    getgroups },			/* 79 = getgroups */
	{ 2, s(struct setgroups_args),
	    setgroups },			/* 80 = setgroups */
	{ 1, s(struct hpux_getpgrp2_args),
	    hpux_getpgrp2 },			/* 81 = hpux_getpgrp2 */
	{ 2, s(struct hpux_setpgrp2_args),
	    hpux_setpgrp2 },			/* 82 = hpux_setpgrp2 */
	{ 3, s(struct setitimer_args),
	    setitimer },			/* 83 = setitimer */
	{ 3, s(struct hpux_wait3_args),
	    hpux_wait3 },			/* 84 = hpux_wait3 */
	{ 0, 0,
	    nosys },				/* 85 = unimplemented swapon */
	{ 2, s(struct getitimer_args),
	    getitimer },			/* 86 = getitimer */
	{ 0, 0,
	    nosys },				/* 87 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 88 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 89 = unimplemented nosys */
	{ 2, s(struct dup2_args),
	    dup2 },				/* 90 = dup2 */
	{ 0, 0,
	    nosys },				/* 91 = unimplemented nosys */
	{ 2, s(struct hpux_fstat_args),
	    hpux_fstat },			/* 92 = hpux_fstat */
	{ 5, s(struct select_args),
	    select },				/* 93 = select */
	{ 0, 0,
	    nosys },				/* 94 = unimplemented nosys */
	{ 1, s(struct fsync_args),
	    fsync },				/* 95 = fsync */
	{ 0, 0,
	    nosys },				/* 96 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 97 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 98 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 99 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 100 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 101 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 102 = unimplemented nosys */
	{ 1, s(struct sigreturn_args),
	    sigreturn },			/* 103 = sigreturn */
	{ 0, 0,
	    nosys },				/* 104 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 105 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 106 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 107 = unimplemented nosys */
	{ 3, s(struct hpux_sigvec_args),
	    hpux_sigvec },			/* 108 = hpux_sigvec */
	{ 1, s(struct hpux_sigblock_args),
	    hpux_sigblock },			/* 109 = hpux_sigblock */
	{ 1, s(struct hpux_sigsetmask_args),
	    hpux_sigsetmask },			/* 110 = hpux_sigsetmask */
	{ 1, s(struct hpux_sigpause_args),
	    hpux_sigpause },			/* 111 = hpux_sigpause */
	{ 2, s(struct compat_43_sigstack_args),
	    compat_43_sigstack },		/* 112 = compat_43_sigstack */
	{ 0, 0,
	    nosys },				/* 113 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 114 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 115 = unimplemented nosys */
	{ 1, s(struct gettimeofday_args),
	    gettimeofday },			/* 116 = gettimeofday */
	{ 0, 0,
	    nosys },				/* 117 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 118 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 119 = unimplemented hpib_io_stub */
	{ 3, s(struct hpux_readv_args),
	    hpux_readv },			/* 120 = hpux_readv */
	{ 3, s(struct hpux_writev_args),
	    hpux_writev },			/* 121 = hpux_writev */
	{ 2, s(struct settimeofday_args),
	    settimeofday },			/* 122 = settimeofday */
	{ 3, s(struct fchown_args),
	    fchown },				/* 123 = fchown */
	{ 2, s(struct fchmod_args),
	    fchmod },				/* 124 = fchmod */
	{ 0, 0,
	    nosys },				/* 125 = unimplemented nosys */
	{ 3, s(struct hpux_setresuid_args),
	    hpux_setresuid },			/* 126 = hpux_setresuid */
	{ 3, s(struct hpux_setresgid_args),
	    hpux_setresgid },			/* 127 = hpux_setresgid */
	{ 2, s(struct rename_args),
	    rename },				/* 128 = rename */
	{ 2, s(struct compat_43_truncate_args),
	    compat_43_truncate },		/* 129 = compat_43_truncate */
	{ 2, s(struct compat_43_ftruncate_args),
	    compat_43_ftruncate },		/* 130 = compat_43_ftruncate */
	{ 0, 0,
	    nosys },				/* 131 = unimplemented nosys */
	{ 1, s(struct hpux_sysconf_args),
	    hpux_sysconf },			/* 132 = hpux_sysconf */
	{ 0, 0,
	    nosys },				/* 133 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 134 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 135 = unimplemented nosys */
	{ 2, s(struct mkdir_args),
	    mkdir },				/* 136 = mkdir */
	{ 1, s(struct rmdir_args),
	    rmdir },				/* 137 = rmdir */
	{ 0, 0,
	    nosys },				/* 138 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 139 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 140 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 141 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 142 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 143 = unimplemented nosys */
	{ 2, s(struct hpux_getrlimit_args),
	    hpux_getrlimit },			/* 144 = hpux_getrlimit */
	{ 2, s(struct hpux_setrlimit_args),
	    hpux_setrlimit },			/* 145 = hpux_setrlimit */
	{ 0, 0,
	    nosys },				/* 146 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 147 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 148 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 149 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 150 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 151 = unimplemented hpux_privgrp */
	{ 2, s(struct hpux_rtprio_args),
	    hpux_rtprio },			/* 152 = hpux_rtprio */
	{ 0, 0,
	    nosys },				/* 153 = unimplemented hpux_plock */
	{ 2, s(struct hpux_netioctl_args),
	    hpux_netioctl },			/* 154 = hpux_netioctl */
	{ 3, s(struct hpux_lockf_args),
	    hpux_lockf },			/* 155 = hpux_lockf */
#ifdef SYSVSEM
	{ 3, s(struct semget_args),
	    semget },				/* 156 = semget */
	{ 4, s(struct __semctl_args),
	    __semctl },				/* 157 = __semctl */
	{ 3, s(struct semop_args),
	    semop },				/* 158 = semop */
#else
	{ 0, 0,
	    nosys },				/* 156 = unimplemented semget */
	{ 0, 0,
	    nosys },				/* 157 = unimplemented semctl */
	{ 0, 0,
	    nosys },				/* 158 = unimplemented semop */
#endif
#ifdef SYSVMSG
	{ 2, s(struct msgget_args),
	    msgget },				/* 159 = msgget */
	{ 3, s(struct msgctl_args),
	    msgctl },				/* 160 = msgctl */
	{ 4, s(struct msgsnd_args),
	    msgsnd },				/* 161 = msgsnd */
	{ 5, s(struct msgrcv_args),
	    msgrcv },				/* 162 = msgrcv */
#else
	{ 0, 0,
	    nosys },				/* 159 = unimplemented msgget */
	{ 0, 0,
	    nosys },				/* 160 = unimplemented msgctl */
	{ 0, 0,
	    nosys },				/* 161 = unimplemented msgsnd */
	{ 0, 0,
	    nosys },				/* 162 = unimplemented msgrcv */
#endif
#ifdef SYSVSHM
	{ 3, s(struct shmget_args),
	    shmget },				/* 163 = shmget */
	{ 3, s(struct hpux_shmctl_args),
	    hpux_shmctl },			/* 164 = hpux_shmctl */
	{ 3, s(struct shmat_args),
	    shmat },				/* 165 = shmat */
	{ 1, s(struct shmdt_args),
	    shmdt },				/* 166 = shmdt */
#else
	{ 0, 0,
	    nosys },				/* 163 = unimplemented shmget */
	{ 0, 0,
	    nosys },				/* 164 = unimplemented shmctl */
	{ 0, 0,
	    nosys },				/* 165 = unimplemented shmat */
	{ 0, 0,
	    nosys },				/* 166 = unimplemented shmdt */
#endif
	{ 1, s(struct hpux_advise_args),
	    hpux_advise },			/* 167 = hpux_advise */
	{ 0, 0,
	    nosys },				/* 168 = unimplemented nsp_init */
	{ 0, 0,
	    nosys },				/* 169 = unimplemented cluster */
	{ 0, 0,
	    nosys },				/* 170 = unimplemented mkrnod */
	{ 0, 0,
	    nosys },				/* 171 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 172 = unimplemented unsp_open */
	{ 0, 0,
	    nosys },				/* 173 = unimplemented nosys */
	{ 2, s(struct hpux_getcontext_args),
	    hpux_getcontext },			/* 174 = hpux_getcontext */
	{ 0, 0,
	    nosys },				/* 175 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 176 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 177 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 178 = unimplemented lsync */
	{ 0, 0,
	    nosys },				/* 179 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 180 = unimplemented mysite */
	{ 0, 0,
	    nosys },				/* 181 = unimplemented sitels */
	{ 0, 0,
	    nosys },				/* 182 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 183 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 184 = unimplemented dskless_stats */
	{ 0, 0,
	    nosys },				/* 185 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 186 = unimplemented setacl */
	{ 0, 0,
	    nosys },				/* 187 = unimplemented fsetacl */
	{ 0, 0,
	    nosys },				/* 188 = unimplemented getacl */
	{ 0, 0,
	    nosys },				/* 189 = unimplemented fgetacl */
	{ 6, s(struct hpux_getaccess_args),
	    hpux_getaccess },			/* 190 = hpux_getaccess */
	{ 0, 0,
	    nosys },				/* 191 = unimplemented getaudid */
	{ 0, 0,
	    nosys },				/* 192 = unimplemented setaudid */
	{ 0, 0,
	    nosys },				/* 193 = unimplemented getaudproc */
	{ 0, 0,
	    nosys },				/* 194 = unimplemented setaudproc */
	{ 0, 0,
	    nosys },				/* 195 = unimplemented getevent */
	{ 0, 0,
	    nosys },				/* 196 = unimplemented setevent */
	{ 0, 0,
	    nosys },				/* 197 = unimplemented audwrite */
	{ 0, 0,
	    nosys },				/* 198 = unimplemented audswitch */
	{ 0, 0,
	    nosys },				/* 199 = unimplemented audctl */
	{ 4, s(struct hpux_waitpid_args),
	    hpux_waitpid },			/* 200 = hpux_waitpid */
	{ 0, 0,
	    nosys },				/* 201 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 202 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 203 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 204 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 205 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 206 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 207 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 208 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 209 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 210 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 211 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 212 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 213 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 214 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 215 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 216 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 217 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 218 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 219 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 220 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 221 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 222 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 223 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 224 = unimplemented nosys */
	{ 2, s(struct pathconf_args),
	    pathconf },				/* 225 = pathconf */
	{ 2, s(struct fpathconf_args),
	    fpathconf },			/* 226 = fpathconf */
	{ 0, 0,
	    nosys },				/* 227 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 228 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 229 = unimplemented hpux_async_daemon */
	{ 0, 0,
	    nosys },				/* 230 = unimplemented hpux_nfs_fcntl */
	{ 4, s(struct compat_43_getdirentries_args),
	    compat_43_getdirentries },		/* 231 = compat_43_getdirentries */
	{ 2, s(struct compat_09_getdomainname_args),
	    compat_09_getdomainname },		/* 232 = compat_09_getdomainname */
	{ 0, 0,
	    nosys },				/* 233 = unimplemented hpux_nfs_getfh */
	{ 0, 0,
	    nosys },				/* 234 = unimplemented hpux_vfsmount */
	{ 0, 0,
	    nosys },				/* 235 = unimplemented hpux_nfs_svc */
	{ 2, s(struct compat_09_setdomainname_args),
	    compat_09_setdomainname },		/* 236 = compat_09_setdomainname */
	{ 0, 0,
	    nosys },				/* 237 = unimplemented hpux_statfs */
	{ 0, 0,
	    nosys },				/* 238 = unimplemented hpux_fstatfs */
	{ 3, s(struct hpux_sigaction_args),
	    hpux_sigaction },			/* 239 = hpux_sigaction */
	{ 3, s(struct hpux_sigprocmask_args),
	    hpux_sigprocmask },			/* 240 = hpux_sigprocmask */
	{ 1, s(struct hpux_sigpending_args),
	    hpux_sigpending },			/* 241 = hpux_sigpending */
	{ 1, s(struct hpux_sigsuspend_args),
	    hpux_sigsuspend },			/* 242 = hpux_sigsuspend */
	{ 0, 0,
	    nosys },				/* 243 = unimplemented hpux_fsctl */
	{ 0, 0,
	    nosys },				/* 244 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 245 = unimplemented hpux_pstat */
	{ 0, 0,
	    nosys },				/* 246 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 247 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 248 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 249 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 250 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 251 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 252 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 253 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 254 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 255 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 256 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 257 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 258 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 259 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 260 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 261 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 262 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 263 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 264 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 265 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 266 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 267 = unimplemented nosys */
	{ 0, 0,
	    compat_43_getdtablesize },		/* 268 = compat_43_getdtablesize */
	{ 0, 0,
	    nosys },				/* 269 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 270 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 271 = unimplemented nosys */
	{ 1, s(struct fchdir_args),
	    fchdir },				/* 272 = fchdir */
	{ 0, 0,
	    nosys },				/* 273 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 274 = unimplemented nosys */
	{ 3, s(struct compat_43_accept_args),
	    compat_43_accept },			/* 275 = compat_43_accept */
	{ 3, s(struct bind_args),
	    bind },				/* 276 = bind */
	{ 3, s(struct connect_args),
	    connect },				/* 277 = connect */
	{ 3, s(struct compat_43_getpeername_args),
	    compat_43_getpeername },		/* 278 = compat_43_getpeername */
	{ 3, s(struct compat_43_getsockname_args),
	    compat_43_getsockname },		/* 279 = compat_43_getsockname */
	{ 5, s(struct getsockopt_args),
	    getsockopt },			/* 280 = getsockopt */
	{ 2, s(struct listen_args),
	    listen },				/* 281 = listen */
	{ 4, s(struct compat_43_recv_args),
	    compat_43_recv },			/* 282 = compat_43_recv */
	{ 6, s(struct compat_43_recvfrom_args),
	    compat_43_recvfrom },		/* 283 = compat_43_recvfrom */
	{ 3, s(struct compat_43_recvmsg_args),
	    compat_43_recvmsg },		/* 284 = compat_43_recvmsg */
	{ 4, s(struct compat_43_send_args),
	    compat_43_send },			/* 285 = compat_43_send */
	{ 3, s(struct compat_43_sendmsg_args),
	    compat_43_sendmsg },		/* 286 = compat_43_sendmsg */
	{ 6, s(struct sendto_args),
	    sendto },				/* 287 = sendto */
	{ 5, s(struct hpux_setsockopt2_args),
	    hpux_setsockopt2 },			/* 288 = hpux_setsockopt2 */
	{ 2, s(struct shutdown_args),
	    shutdown },				/* 289 = shutdown */
	{ 3, s(struct socket_args),
	    socket },				/* 290 = socket */
	{ 4, s(struct socketpair_args),
	    socketpair },			/* 291 = socketpair */
	{ 0, 0,
	    nosys },				/* 292 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 293 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 294 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 295 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 296 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 297 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 298 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 299 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 300 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 301 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 302 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 303 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 304 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 305 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 306 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 307 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 308 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 309 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 310 = unimplemented nosys */
	{ 0, 0,
	    nosys },				/* 311 = unimplemented nosys */
#ifdef SYSVSEM
	{ 4, s(struct __semctl_args),
	    __semctl },				/* 312 = nsemctl */
#else
	{ 0, 0,
	    nosys },				/* 312 = unimplemented semctl */
#endif
#ifdef SYSVMSG
	{ 3, s(struct msgctl_args),
	    msgctl },				/* 313 = nmsgctl */
#else
	{ 0, 0,
	    nosys },				/* 313 = unimplemented msgctl */
#endif
#ifdef SYSVSHM
	{ 3, s(struct hpux_nshmctl_args),
	    hpux_nshmctl },			/* 314 = hpux_nshmctl */
#else
	{ 0, 0,
	    nosys },				/* 314 = unimplemented shmctl */
#endif
};

