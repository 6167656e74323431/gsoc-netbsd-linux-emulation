/*	$NetBSD: sparc.c,v 1.5 2002/05/15 09:44:55 lukem Exp $ */

/*-
 * Copyright (c) 1998, 2002 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Paul Kranenburg and Luke Mewburn.
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

#include <sys/cdefs.h>
#if defined(__RCSID) && !defined(__lint)
__RCSID("$NetBSD: sparc.c,v 1.5 2002/05/15 09:44:55 lukem Exp $");
#endif	/* !__lint */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/param.h>

#include <assert.h>
#include <err.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "installboot.h"

static struct bbinfo_params bbparams = {
	SPARC_BBINFO_MAGIC,
	SPARC_BOOT_BLOCK_OFFSET,
	SPARC_BOOT_BLOCK_BLOCKSIZE,
	SPARC_BOOT_BLOCK_MAX_SIZE,
	32,			/* leave room for a.out header */
	0,
};

int
sparc_clearboot(ib_params *params)
{

	assert(params != NULL);

	if (params->flags & IB_STAGE1START) {
		warnx("`-b bno' is not supported for %s",
		    params->machine->name);
		return (0);
	}
	return (shared_bbinfo_clearboot(params, &bbparams));
}

static int
sparc_frobheader(ib_params *params, struct bbinfo_params *bb_params, char *bb)
{

	assert(params != NULL);
	assert(bb_params != NULL);
	assert(bb != NULL);

	/*
	 * sun4c/sun4m PROMs require an a.out(5) format header.
	 * Old-style sun4 PROMs do not expect a header at all.
	 * To deal with this, we construct a header that is also executable
	 * code containing a forward branch that gets us past the 32-byte
	 * header where the actual code begins. In assembly:
	 * 	.word	MAGIC		! a NOP
	 * 	ba,a	start		!
	 * 	.skip	24		! pad
	 * start:
	 */
#define SUN_MAGIC	0x01030107
#define SUN4_BASTART	0x30800007	/* i.e.: ba,a `start' */
	*((uint32_t *)bb) = htobe32(SUN_MAGIC);
	*((uint32_t *)bb + 1) = htobe32(SUN4_BASTART);

	return (1);
}

int
sparc_setboot(ib_params *params)
{
	assert(params != NULL);

	if (params->flags & IB_STAGE1START) {
		warnx("`-b bno' is not supported for %s",
		    params->machine->name);
		return (0);
	}
	return (shared_bbinfo_setboot(params, &bbparams, sparc_frobheader));
}
