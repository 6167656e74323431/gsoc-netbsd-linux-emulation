/*	$NetBSD: autoconf.c,v 1.1 1995/02/13 00:41:05 ragge Exp $ */
/*
 * Copyright (c) 1994 Ludd, University of Lule}, Sweden.
 * All rights reserved.
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
 *     This product includes software developed at Ludd, University of Lule}.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

 /* All bugs are subject to removal without further notice */
		


#include "sys/param.h"
#include "../include/mtpr.h"
#include "../include/sid.h"
#include "vaxstand.h"

int	nmba=0, nuba=0, nbi=0,nsbi=0;
int	*mbaaddr, *ubaaddr;

static int mba750[]={0xf28000,0xf2a000,0xf2c000};
static int uba750[]={0xf30000,0xf32000};
/*
 * Autoconf routine is really stupid; but it actually don't
 * need any intelligence. We just assume that all possible
 * devices exists on each cpu. Fast & easy.
 */

autoconf()
{
	int i=MACHID(mfpr(PR_SID));

	switch(i){

	default:
		printf("CPU type %d not supported by boot\n",i);
		asm("halt");

	case VAX_750:
		nmba=3;
		nuba=2;
		mbaaddr=mba750;
		ubaaddr=uba750;
		break;
	}
}

