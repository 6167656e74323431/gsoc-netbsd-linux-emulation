/*	$NetBSD: linux_syscalls.c,v 1.18 2000/03/20 00:50:45 erh Exp $	*/

/*
 * System call names.
 *
 * DO NOT EDIT-- this file is automatically generated.
 * created from	NetBSD: syscalls.master,v 1.18 2000/03/18 23:53:24 erh Exp 
 */

#if defined(_KERNEL) && !defined(_LKM)
#include "opt_sysv.h"
#include "opt_compat_43.h"
#include <sys/param.h>
#include <sys/poll.h>
#include <sys/systm.h>
#include <sys/signal.h>
#include <sys/mount.h>
#include <sys/syscallargs.h>
#include <compat/linux/common/linux_types.h>
#include <compat/linux/common/linux_signal.h>
#include <compat/linux/common/linux_siginfo.h>
#include <compat/linux/common/linux_ipc.h>
#include <compat/linux/common/linux_msg.h>
#include <compat/linux/common/linux_sem.h>
#include <compat/linux/common/linux_shm.h>
#include <compat/linux/common/linux_mmap.h>
#include <compat/linux/linux_syscallargs.h>
#endif /* _KERNEL && ! _LKM */

char *linux_syscallnames[] = {
	"syscall",			/* 0 = syscall */
	"exit",			/* 1 = exit */
	"fork",			/* 2 = fork */
	"read",			/* 3 = read */
	"write",			/* 4 = write */
	"#5 (unimplemented)",		/* 5 = unimplemented */
	"close",			/* 6 = close */
	"#7 (unimplemented osf_wait4)",		/* 7 = unimplemented osf_wait4 */
	"creat",			/* 8 = creat */
	"link",			/* 9 = link */
	"unlink",			/* 10 = unlink */
	"#11 (unimplemented)",		/* 11 = unimplemented */
	"chdir",			/* 12 = chdir */
	"fchdir",			/* 13 = fchdir */
	"mknod",			/* 14 = mknod */
	"chmod",			/* 15 = chmod */
	"chown",			/* 16 = chown */
	"brk",			/* 17 = brk */
	"#18 (unimplemented)",		/* 18 = unimplemented */
	"lseek",			/* 19 = lseek */
	"getpid",			/* 20 = getpid */
	"#21 (unimplemented osf_mount)",		/* 21 = unimplemented osf_mount */
	"#22 (unimplemented osf_umount)",		/* 22 = unimplemented osf_umount */
	"setuid",			/* 23 = setuid */
	"getuid",			/* 24 = getuid */
	"#25 (unimplemented)",		/* 25 = unimplemented */
	"ptrace",			/* 26 = ptrace */
	"#27 (unimplemented)",		/* 27 = unimplemented */
	"#28 (unimplemented)",		/* 28 = unimplemented */
	"#29 (unimplemented)",		/* 29 = unimplemented */
	"#30 (unimplemented)",		/* 30 = unimplemented */
	"#31 (unimplemented)",		/* 31 = unimplemented */
	"#32 (unimplemented)",		/* 32 = unimplemented */
	"access",			/* 33 = access */
	"#34 (unimplemented)",		/* 34 = unimplemented */
	"#35 (unimplemented)",		/* 35 = unimplemented */
	"sync",			/* 36 = sync */
	"kill",			/* 37 = kill */
	"#38 (unimplemented)",		/* 38 = unimplemented */
	"setpgid",			/* 39 = setpgid */
	"#40 (unimplemented)",		/* 40 = unimplemented */
	"dup",			/* 41 = dup */
	"pipe",			/* 42 = pipe */
	"#43 (unimplemented osf_set_program_attributes)",		/* 43 = unimplemented osf_set_program_attributes */
	"#44 (unimplemented)",		/* 44 = unimplemented */
	"open",			/* 45 = open */
	"#46 (unimplemented)",		/* 46 = unimplemented */
	"getgid",			/* 47 = getgid */
	"#48 (unimplemented osf_sigprocmask)",		/* 48 = unimplemented osf_sigprocmask */
	"#49 (unimplemented)",		/* 49 = unimplemented */
	"#50 (unimplemented)",		/* 50 = unimplemented */
	"acct",			/* 51 = acct */
	"sigpending",			/* 52 = sigpending */
	"#53 (unimplemented)",		/* 53 = unimplemented */
	"ioctl",			/* 54 = ioctl */
	"#55 (unimplemented)",		/* 55 = unimplemented */
	"#56 (unimplemented)",		/* 56 = unimplemented */
	"symlink",			/* 57 = symlink */
	"readlink",			/* 58 = readlink */
	"execve",			/* 59 = execve */
	"umask",			/* 60 = umask */
	"chroot",			/* 61 = chroot */
	"#62 (unimplemented)",		/* 62 = unimplemented */
	"getpgrp",			/* 63 = getpgrp */
	"getpagesize",			/* 64 = getpagesize */
	"#65 (unimplemented)",		/* 65 = unimplemented */
	"__vfork14",			/* 66 = __vfork14 */
	"stat",			/* 67 = stat */
	"lstat",			/* 68 = lstat */
	"#69 (unimplemented)",		/* 69 = unimplemented */
	"#70 (unimplemented)",		/* 70 = unimplemented */
	"mmap",			/* 71 = mmap */
	"#72 (unimplemented)",		/* 72 = unimplemented */
	"munmap",			/* 73 = munmap */
	"mprotect",			/* 74 = mprotect */
	"#75 (unimplemented madvise)",		/* 75 = unimplemented madvise */
	"#76 (unimplemented vhangup)",		/* 76 = unimplemented vhangup */
	"#77 (unimplemented)",		/* 77 = unimplemented */
	"#78 (unimplemented)",		/* 78 = unimplemented */
	"getgroups",			/* 79 = getgroups */
	"setgroups",			/* 80 = setgroups */
	"#81 (unimplemented)",		/* 81 = unimplemented */
	"#82 (unimplemented setpgrp)",		/* 82 = unimplemented setpgrp */
	"#83 (unimplemented osf_setitimer)",		/* 83 = unimplemented osf_setitimer */
	"#84 (unimplemented)",		/* 84 = unimplemented */
	"#85 (unimplemented)",		/* 85 = unimplemented */
	"#86 (unimplemented osf_getitimer)",		/* 86 = unimplemented osf_getitimer */
	"gethostname",			/* 87 = gethostname */
	"sethostname",			/* 88 = sethostname */
	"#89 (unimplemented getdtablesize)",		/* 89 = unimplemented getdtablesize */
	"dup2",			/* 90 = dup2 */
	"fstat",			/* 91 = fstat */
	"fcntl",			/* 92 = fcntl */
	"#93 (unimplemented osf_select)",		/* 93 = unimplemented osf_select */
	"poll",			/* 94 = poll */
	"fsync",			/* 95 = fsync */
	"setpriority",			/* 96 = setpriority */
	"socket",			/* 97 = socket */
	"connect",			/* 98 = connect */
	"accept",			/* 99 = accept */
	"getpriority",			/* 100 = getpriority */
	"send",			/* 101 = send */
	"recv",			/* 102 = recv */
	"sigreturn",			/* 103 = sigreturn */
	"bind",			/* 104 = bind */
	"setsockopt",			/* 105 = setsockopt */
	"listen",			/* 106 = listen */
	"#107 (unimplemented)",		/* 107 = unimplemented */
	"#108 (unimplemented)",		/* 108 = unimplemented */
	"#109 (unimplemented)",		/* 109 = unimplemented */
	"#110 (unimplemented)",		/* 110 = unimplemented */
	"sigsuspend",			/* 111 = sigsuspend */
	"#112 (unimplemented)",		/* 112 = unimplemented */
	"recvmsg",			/* 113 = recvmsg */
	"sendmsg",			/* 114 = sendmsg */
	"#115 (unimplemented)",		/* 115 = unimplemented */
	"#116 (unimplemented osf_gettimeofday)",		/* 116 = unimplemented osf_gettimeofday */
	"#117 (unimplemented osf_getrusage)",		/* 117 = unimplemented osf_getrusage */
	"getsockopt",			/* 118 = getsockopt */
	"#119 (unimplemented)",		/* 119 = unimplemented */
	"readv",			/* 120 = readv */
	"writev",			/* 121 = writev */
	"#122 (unimplemented osf_settimeofday)",		/* 122 = unimplemented osf_settimeofday */
	"fchown",			/* 123 = fchown */
	"fchmod",			/* 124 = fchmod */
	"recvfrom",			/* 125 = recvfrom */
	"setreuid",			/* 126 = setreuid */
	"setregid",			/* 127 = setregid */
	"rename",			/* 128 = rename */
	"truncate",			/* 129 = truncate */
	"ftruncate",			/* 130 = ftruncate */
	"flock",			/* 131 = flock */
	"setgid",			/* 132 = setgid */
	"sendto",			/* 133 = sendto */
	"shutdown",			/* 134 = shutdown */
	"socketpair",			/* 135 = socketpair */
	"mkdir",			/* 136 = mkdir */
	"rmdir",			/* 137 = rmdir */
	"#138 (unimplemented osf_utimes)",		/* 138 = unimplemented osf_utimes */
	"#139 (unimplemented)",		/* 139 = unimplemented */
	"#140 (unimplemented)",		/* 140 = unimplemented */
	"getpeername",			/* 141 = getpeername */
	"#142 (unimplemented)",		/* 142 = unimplemented */
	"#143 (unimplemented)",		/* 143 = unimplemented */
	"getrlimit",			/* 144 = getrlimit */
	"setrlimit",			/* 145 = setrlimit */
	"#146 (unimplemented)",		/* 146 = unimplemented */
	"setsid",			/* 147 = setsid */
	"#148 (unimplemented quotactl)",		/* 148 = unimplemented quotactl */
	"#149 (unimplemented)",		/* 149 = unimplemented */
	"getsockname",			/* 150 = getsockname */
	"#151 (unimplemented)",		/* 151 = unimplemented */
	"#152 (unimplemented)",		/* 152 = unimplemented */
	"#153 (unimplemented)",		/* 153 = unimplemented */
	"#154 (unimplemented)",		/* 154 = unimplemented */
	"#155 (unimplemented)",		/* 155 = unimplemented */
	"sigaction",			/* 156 = sigaction */
	"#157 (unimplemented)",		/* 157 = unimplemented */
	"#158 (unimplemented)",		/* 158 = unimplemented */
	"#159 (unimplemented osf_getdirentries)",		/* 159 = unimplemented osf_getdirentries */
	"#160 (unimplemented osf_statfs)",		/* 160 = unimplemented osf_statfs */
	"#161 (unimplemented osf_fstatfs)",		/* 161 = unimplemented osf_fstatfs */
	"#162 (unimplemented)",		/* 162 = unimplemented */
	"#163 (unimplemented)",		/* 163 = unimplemented */
	"#164 (unimplemented)",		/* 164 = unimplemented */
	"#165 (unimplemented osf_getdomainname)",		/* 165 = unimplemented osf_getdomainname */
	"#166 (unimplemented setdomainname)",		/* 166 = unimplemented setdomainname */
	"#167 (unimplemented)",		/* 167 = unimplemented */
	"#168 (unimplemented)",		/* 168 = unimplemented */
	"#169 (unimplemented)",		/* 169 = unimplemented */
	"#170 (unimplemented)",		/* 170 = unimplemented */
	"#171 (unimplemented)",		/* 171 = unimplemented */
	"#172 (unimplemented)",		/* 172 = unimplemented */
	"#173 (unimplemented)",		/* 173 = unimplemented */
	"#174 (unimplemented)",		/* 174 = unimplemented */
	"#175 (unimplemented)",		/* 175 = unimplemented */
	"#176 (unimplemented)",		/* 176 = unimplemented */
	"#177 (unimplemented)",		/* 177 = unimplemented */
	"#178 (unimplemented)",		/* 178 = unimplemented */
	"#179 (unimplemented)",		/* 179 = unimplemented */
	"#180 (unimplemented)",		/* 180 = unimplemented */
	"#181 (unimplemented)",		/* 181 = unimplemented */
	"#182 (unimplemented)",		/* 182 = unimplemented */
	"#183 (unimplemented)",		/* 183 = unimplemented */
	"#184 (unimplemented)",		/* 184 = unimplemented */
	"#185 (unimplemented)",		/* 185 = unimplemented */
	"#186 (unimplemented)",		/* 186 = unimplemented */
	"#187 (unimplemented)",		/* 187 = unimplemented */
	"#188 (unimplemented)",		/* 188 = unimplemented */
	"#189 (unimplemented)",		/* 189 = unimplemented */
	"#190 (unimplemented)",		/* 190 = unimplemented */
	"#191 (unimplemented)",		/* 191 = unimplemented */
	"#192 (unimplemented)",		/* 192 = unimplemented */
	"#193 (unimplemented)",		/* 193 = unimplemented */
	"#194 (unimplemented)",		/* 194 = unimplemented */
	"#195 (unimplemented)",		/* 195 = unimplemented */
	"#196 (unimplemented)",		/* 196 = unimplemented */
	"#197 (unimplemented)",		/* 197 = unimplemented */
	"#198 (unimplemented)",		/* 198 = unimplemented */
	"#199 (unimplemented osf_swapon)",		/* 199 = unimplemented osf_swapon */
#ifdef SYSVMSG
	"msgctl",			/* 200 = msgctl */
	"msgget",			/* 201 = msgget */
	"msgrcv",			/* 202 = msgrcv */
	"msgsnd",			/* 203 = msgsnd */
#else
	"#200 (unimplemented msgctl)",		/* 200 = unimplemented msgctl */
	"#201 (unimplemented msgget)",		/* 201 = unimplemented msgget */
	"#202 (unimplemented msgrcv)",		/* 202 = unimplemented msgrcv */
	"#203 (unimplemented msgsnd)",		/* 203 = unimplemented msgsnd */
#endif
#ifdef SYSVSEM
	"semctl",			/* 204 = semctl */
	"semget",			/* 205 = semget */
	"semop",			/* 206 = semop */
#else
	"#204 (unimplemented semctl)",		/* 204 = unimplemented semctl */
	"#205 (unimplemented semget)",		/* 205 = unimplemented semget */
	"#206 (unimplemented semop)",		/* 206 = unimplemented semop */
#endif
	"olduname",			/* 207 = olduname */
	"lchown",			/* 208 = lchown */
#ifdef SYSVSHM
	"shmat",			/* 209 = shmat */
	"shmctl",			/* 210 = shmctl */
	"shmdt",			/* 211 = shmdt */
	"shmget",			/* 212 = shmget */
#else
	"#209 (unimplemented shmat)",		/* 209 = unimplemented shmat */
	"#210 (unimplemented shmctl)",		/* 210 = unimplemented shmctl */
	"#211 (unimplemented shmdt)",		/* 211 = unimplemented shmdt */
	"#212 (unimplemented shmget)",		/* 212 = unimplemented shmget */
#endif
	"#213 (unimplemented)",		/* 213 = unimplemented */
	"#214 (unimplemented)",		/* 214 = unimplemented */
	"#215 (unimplemented)",		/* 215 = unimplemented */
	"#216 (unimplemented)",		/* 216 = unimplemented */
	"msync",			/* 217 = msync */
	"#218 (unimplemented osf_signal)",		/* 218 = unimplemented osf_signal */
	"#219 (unimplemented)",		/* 219 = unimplemented */
	"#220 (unimplemented)",		/* 220 = unimplemented */
	"#221 (unimplemented)",		/* 221 = unimplemented */
	"#222 (unimplemented)",		/* 222 = unimplemented */
	"#223 (unimplemented)",		/* 223 = unimplemented */
	"#224 (unimplemented)",		/* 224 = unimplemented */
	"#225 (unimplemented)",		/* 225 = unimplemented */
	"#226 (unimplemented)",		/* 226 = unimplemented */
	"#227 (unimplemented)",		/* 227 = unimplemented */
	"#228 (unimplemented)",		/* 228 = unimplemented */
	"#229 (unimplemented)",		/* 229 = unimplemented */
	"#230 (unimplemented)",		/* 230 = unimplemented */
	"#231 (unimplemented)",		/* 231 = unimplemented */
	"#232 (unimplemented)",		/* 232 = unimplemented */
	"getpgid",			/* 233 = getpgid */
	"getsid",			/* 234 = getsid */
	"#235 (unimplemented)",		/* 235 = unimplemented */
	"#236 (unimplemented)",		/* 236 = unimplemented */
	"#237 (unimplemented)",		/* 237 = unimplemented */
	"#238 (unimplemented)",		/* 238 = unimplemented */
	"#239 (unimplemented)",		/* 239 = unimplemented */
	"#240 (unimplemented)",		/* 240 = unimplemented */
	"#241 (unimplemented osf_sysinfo)",		/* 241 = unimplemented osf_sysinfo */
	"#242 (unimplemented)",		/* 242 = unimplemented */
	"#243 (unimplemented)",		/* 243 = unimplemented */
	"#244 (unimplemented osf_proplist_syscall)",		/* 244 = unimplemented osf_proplist_syscall */
	"#245 (unimplemented)",		/* 245 = unimplemented */
	"#246 (unimplemented)",		/* 246 = unimplemented */
	"#247 (unimplemented)",		/* 247 = unimplemented */
	"#248 (unimplemented)",		/* 248 = unimplemented */
	"#249 (unimplemented)",		/* 249 = unimplemented */
	"#250 (unimplemented)",		/* 250 = unimplemented */
	"#251 (unimplemented osf_usleep_thread)",		/* 251 = unimplemented osf_usleep_thread */
	"#252 (unimplemented)",		/* 252 = unimplemented */
	"#253 (unimplemented)",		/* 253 = unimplemented */
	"#254 (unimplemented sysfs)",		/* 254 = unimplemented sysfs */
	"#255 (unimplemented)",		/* 255 = unimplemented */
	"#256 (unimplemented osf_getsysinfo)",		/* 256 = unimplemented osf_getsysinfo */
	"#257 (unimplemented osf_setsysinfo)",		/* 257 = unimplemented osf_setsysinfo */
	"#258 (unimplemented)",		/* 258 = unimplemented */
	"#259 (unimplemented)",		/* 259 = unimplemented */
	"#260 (unimplemented)",		/* 260 = unimplemented */
	"fdatasync",			/* 261 = fdatasync */
	"#262 (unimplemented)",		/* 262 = unimplemented */
	"#263 (unimplemented)",		/* 263 = unimplemented */
	"#264 (unimplemented)",		/* 264 = unimplemented */
	"#265 (unimplemented)",		/* 265 = unimplemented */
	"#266 (unimplemented)",		/* 266 = unimplemented */
	"#267 (unimplemented)",		/* 267 = unimplemented */
	"#268 (unimplemented)",		/* 268 = unimplemented */
	"#269 (unimplemented)",		/* 269 = unimplemented */
	"#270 (unimplemented)",		/* 270 = unimplemented */
	"#271 (unimplemented)",		/* 271 = unimplemented */
	"#272 (unimplemented)",		/* 272 = unimplemented */
	"#273 (unimplemented)",		/* 273 = unimplemented */
	"#274 (unimplemented)",		/* 274 = unimplemented */
	"#275 (unimplemented)",		/* 275 = unimplemented */
	"#276 (unimplemented)",		/* 276 = unimplemented */
	"#277 (unimplemented)",		/* 277 = unimplemented */
	"#278 (unimplemented)",		/* 278 = unimplemented */
	"#279 (unimplemented)",		/* 279 = unimplemented */
	"#280 (unimplemented)",		/* 280 = unimplemented */
	"#281 (unimplemented)",		/* 281 = unimplemented */
	"#282 (unimplemented)",		/* 282 = unimplemented */
	"#283 (unimplemented)",		/* 283 = unimplemented */
	"#284 (unimplemented)",		/* 284 = unimplemented */
	"#285 (unimplemented)",		/* 285 = unimplemented */
	"#286 (unimplemented)",		/* 286 = unimplemented */
	"#287 (unimplemented)",		/* 287 = unimplemented */
	"#288 (unimplemented)",		/* 288 = unimplemented */
	"#289 (unimplemented)",		/* 289 = unimplemented */
	"#290 (unimplemented)",		/* 290 = unimplemented */
	"#291 (unimplemented)",		/* 291 = unimplemented */
	"#292 (unimplemented)",		/* 292 = unimplemented */
	"#293 (unimplemented)",		/* 293 = unimplemented */
	"#294 (unimplemented)",		/* 294 = unimplemented */
	"#295 (unimplemented)",		/* 295 = unimplemented */
	"#296 (unimplemented)",		/* 296 = unimplemented */
	"#297 (unimplemented)",		/* 297 = unimplemented */
	"#298 (unimplemented)",		/* 298 = unimplemented */
	"#299 (unimplemented)",		/* 299 = unimplemented */
	"#300 (unimplemented bdflush)",		/* 300 = unimplemented bdflush */
	"#301 (unimplemented sethae)",		/* 301 = unimplemented sethae */
	"#302 (unimplemented mount)",		/* 302 = unimplemented mount */
	"#303 (unimplemented old_adjtimex)",		/* 303 = unimplemented old_adjtimex */
	"#304 (unimplemented swapoff)",		/* 304 = unimplemented swapoff */
	"getdents",			/* 305 = getdents */
	"#306 (unimplemented create_module)",		/* 306 = unimplemented create_module */
	"#307 (unimplemented init_module)",		/* 307 = unimplemented init_module */
	"#308 (unimplemented delete_module)",		/* 308 = unimplemented delete_module */
	"#309 (unimplemented get_kernel_syms)",		/* 309 = unimplemented get_kernel_syms */
	"#310 (unimplemented syslog)",		/* 310 = unimplemented syslog */
	"reboot",			/* 311 = reboot */
	"clone",			/* 312 = clone */
#ifdef EXEC_AOUT
	"uselib",			/* 313 = uselib */
#else
	"#313 (unimplemented sys_uselib)",		/* 313 = unimplemented sys_uselib */
#endif
	"mlock",			/* 314 = mlock */
	"munlock",			/* 315 = munlock */
	"#316 (unimplemented mlockall)",		/* 316 = unimplemented mlockall */
	"#317 (unimplemented munlockall)",		/* 317 = unimplemented munlockall */
	"#318 (unimplemented sysinfo)",		/* 318 = unimplemented sysinfo */
	"__sysctl",			/* 319 = __sysctl */
	"#320 (unimplemented idle)",		/* 320 = unimplemented idle */
	"#321 (unimplemented umount)",		/* 321 = unimplemented umount */
	"swapon",			/* 322 = swapon */
	"times",			/* 323 = times */
	"personality",			/* 324 = personality */
	"setfsuid",			/* 325 = setfsuid */
	"#326 (unimplemented setfsgid)",		/* 326 = unimplemented setfsgid */
	"#327 (unimplemented ustat)",		/* 327 = unimplemented ustat */
	"statfs",			/* 328 = statfs */
	"fstatfs",			/* 329 = fstatfs */
	"sched_setparam",			/* 330 = sched_setparam */
	"sched_getparam",			/* 331 = sched_getparam */
	"sched_setscheduler",			/* 332 = sched_setscheduler */
	"sched_getscheduler",			/* 333 = sched_getscheduler */
	"sched_yield",			/* 334 = sched_yield */
	"sched_get_priority_max",			/* 335 = sched_get_priority_max */
	"sched_get_priority_min",			/* 336 = sched_get_priority_min */
	"#337 (unimplemented sched_rr_get_interval)",		/* 337 = unimplemented sched_rr_get_interval */
	"#338 (unimplemented afs_syscall)",		/* 338 = unimplemented afs_syscall */
	"uname",			/* 339 = uname */
	"nanosleep",			/* 340 = nanosleep */
	"mremap",			/* 341 = mremap */
	"#342 (unimplemented nfsservctl)",		/* 342 = unimplemented nfsservctl */
	"setresuid",			/* 343 = setresuid */
	"getresuid",			/* 344 = getresuid */
	"#345 (unimplemented pciconfig_read)",		/* 345 = unimplemented pciconfig_read */
	"#346 (unimplemented pciconfig_write)",		/* 346 = unimplemented pciconfig_write */
	"#347 (unimplemented query_module)",		/* 347 = unimplemented query_module */
	"#348 (unimplemented prctl)",		/* 348 = unimplemented prctl */
	"pread",			/* 349 = pread */
	"pwrite",			/* 350 = pwrite */
	"rt_sigreturn",			/* 351 = rt_sigreturn */
	"rt_sigaction",			/* 352 = rt_sigaction */
	"rt_sigprocmask",			/* 353 = rt_sigprocmask */
	"rt_sigpending",			/* 354 = rt_sigpending */
	"#355 (unimplemented rt_sigtimedwait)",		/* 355 = unimplemented rt_sigtimedwait */
	"rt_queueinfo",			/* 356 = rt_queueinfo */
	"rt_sigsuspend",			/* 357 = rt_sigsuspend */
	"select",			/* 358 = select */
	"gettimeofday",			/* 359 = gettimeofday */
	"settimeofday",			/* 360 = settimeofday */
	"getitimer",			/* 361 = getitimer */
	"setitimer",			/* 362 = setitimer */
	"utimes",			/* 363 = utimes */
	"getrusage",			/* 364 = getrusage */
	"wait4",			/* 365 = wait4 */
	"#366 (unimplemented adjtimex)",		/* 366 = unimplemented adjtimex */
	"__getcwd",			/* 367 = __getcwd */
	"#368 (unimplemented capget)",		/* 368 = unimplemented capget */
	"#369 (unimplemented capset)",		/* 369 = unimplemented capset */
	"#370 (unimplemented sendfile)",		/* 370 = unimplemented sendfile */
};
