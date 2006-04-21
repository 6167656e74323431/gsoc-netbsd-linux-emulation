/*	$NetBSD: iostat.h,v 1.3 2006/04/21 13:48:57 yamt Exp $	*/

/*-
 * Copyright (c) 1996, 1997, 2004 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Jason R. Thorpe of the Numerical Aerospace Simulation Facility,
 * NASA Ames Research Center.
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
 *	This product includes software developed by the NetBSD
 *	Foundation, Inc. and its contributors.
 * 4. Neither the name of The NetBSD Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _SYS_IOSTAT_H_
#define _SYS_IOSTAT_H_

/*
 * Disk device structures.
 */

#include <sys/time.h>
#include <sys/queue.h>
#include <sys/lock.h>

#define	IOSTATNAMELEN	16

/* types of drives we can have */
#define IOSTAT_DISK	0
#define IOSTAT_TAPE	1
#define IOSTAT_NFS	2

/* The following structure is 64-bit alignment safe */
struct io_sysctl {
	char		name[IOSTATNAMELEN];
	int32_t		busy;
	int32_t		type;
	u_int64_t	xfer;
	u_int64_t	seek;
	u_int64_t	bytes;
	u_int32_t	attachtime_sec;
	u_int32_t	attachtime_usec;
	u_int32_t	timestamp_sec;
	u_int32_t	timestamp_usec;
	u_int32_t	time_sec;
	u_int32_t	time_usec;
	/* New separate read/write stats */
	u_int64_t	rxfer;
	u_int64_t	rbytes;
	u_int64_t	wxfer;
	u_int64_t	wbytes;
};

/*
 * Structure for keeping the in-kernel drive stats - these are linked
 * together in drivelist.
 */

struct io_stats
{
	char		*io_name;  /* device name */
	void		*io_parent; /* pointer to what we are attached to */
	int		io_type;   /* type of device the state belong to */
	int		io_busy;	/* busy counter */
	u_int64_t	io_rxfer;	/* total number of read transfers */
	u_int64_t	io_wxfer;	/* total number of write transfers */
	u_int64_t	io_seek;	/* total independent seek operations */
	u_int64_t	io_rbytes;	/* total bytes read */
	u_int64_t	io_wbytes;	/* total bytes written */
	struct timeval	io_attachtime;	/* time disk was attached */
	struct timeval	io_timestamp;	/* timestamp of last unbusy */
	struct timeval	io_time;	/* total time spent busy */
	TAILQ_ENTRY(io_stats) io_link;
};

/*
 * drivelist_head is defined here so that user-land has access to it.
 */
TAILQ_HEAD(iostatlist_head, io_stats);	/* the iostatlist is a TAILQ */

#ifdef _KERNEL
void	iostat_busy(struct io_stats *);
void	iostat_unbusy(struct io_stats *, long, int);
struct io_stats *iostat_find(char *);
struct io_stats *iostat_alloc(int32_t);
void	iostat_free(struct io_stats *);
void	iostat_seek(struct io_stats *);
#endif

#endif /* _SYS_IOSTAT_H_ */
