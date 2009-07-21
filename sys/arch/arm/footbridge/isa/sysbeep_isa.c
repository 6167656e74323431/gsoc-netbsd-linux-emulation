/*	$NetBSD: sysbeep_isa.c,v 1.10 2009/07/21 07:35:55 skrll Exp $	*/

/*-
 * Copyright (c) 1998 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Mark Brinicombe of Causality Limited.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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
__KERNEL_RCSID(0, "$NetBSD: sysbeep_isa.c,v 1.10 2009/07/21 07:35:55 skrll Exp $");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/device.h>
#include <dev/isa/isavar.h>

#include <dev/isa/pcppivar.h>

/* Prototypes */
int sysbeep_isa_match(device_t parent, cfdata_t cf, void *aux);
void sysbeep_isa_attach(device_t parent, device_t self, void *aux);
void sysbeep_isa(int pitch, int period);

/* device attach structure */
CFATTACH_DECL_NEW(sysbeep_isa, sizeof(struct device),
    sysbeep_isa_match, sysbeep_isa_attach, NULL, NULL);

static int ppi_attached;
static pcppi_tag_t ppicookie;

int
sysbeep_isa_match(device_t parent, cfdata_t match, void *aux)
{
	return (!ppi_attached);
}

void
sysbeep_isa_attach(device_t parent, device_t self, void *aux)
{
	aprint_normal("\n");

	ppicookie = ((struct pcppi_attach_args *)aux)->pa_cookie;
	ppi_attached = 1;
}

void
sysbeep(int pitch, int period)
{
	if (ppi_attached)
		pcppi_bell(ppicookie, pitch, period, 0);
}
