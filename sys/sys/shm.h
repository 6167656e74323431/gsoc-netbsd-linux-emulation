/*
 * Copyright (c) 1994 Adam Glass
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. The name of the Author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY Adam Glass ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL Adam Glass BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * As defined+described in "X/Open System Interfaces and Headers"
 *                         Issue 4, p. XXX
 */

#ifndef _SYS_SHM_H_
#define _SYS_SHM_H_

#include <sys/ipc.h>

#define SHM_RDONLY  010000  /* Attach read-only (else read-write) (origin ?)*/
#define SHM_RND     020000  /* Round attach address to SHMLBA (origin XXX) */
#define SHMLBA      CLBYTES /* Segment low boundry address multiple (origin, machdep XXX*/

typedef u_short shmatt_t;

struct shmid_ds {
	struct ipc_perm shm_perm;	/* operation permission structure */
	int             shm_segsz;	/* size of segment in bytes */
	pid_t           shm_lpid;   /* process ID of last shared memory op */
	pid_t           shm_cpid;	/* process ID of creator */
	shmatt_t        shm_nattch;	/* number of current attaches */
	time_t          shm_atime;	/* time of last shmat() */
	time_t          shm_dtime;	/* time of last shmdt() */
	time_t          shm_ctime;	/* time of last change by shmctl() */
	void           *shm_internal;   /* sysv stupidity */
};

#ifdef KERNEL

/*
 * System 5 style catch-all structure for shared memory constants that
 * might be of interest to user programs.  Do we really want/need this?
 */
struct shminfo {
	int	shmmax,		/* max shared memory segment size (bytes) */
		shmmin,		/* min shared memory segment size (bytes) */
		shmmni,		/* max number of shared memory identifiers */
		shmseg,		/* max shared memory segments per process */
		shmall;		/* max amount of shared memory (pages) */
};
struct shminfo	shminfo;
struct shmid_ds	*shmsegs;

#else /* !KERNEL */

#include <sys/cdefs.h>

__BEGIN_DECLS
void *shmat __P((int, const void *, int));
void  shmctl __P((int, int, struct shmid_ds *));
void  shmdt __P((const void *));
void  shmget __P((key_t, size_t, int));
__END_DECLS

#endif /* !KERNEL */

#endif /* !_SYS_SHM_H_ */
