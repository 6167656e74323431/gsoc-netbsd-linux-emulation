/*	$NetBSD: pmreg.h,v 1.4 2023/02/11 18:30:45 tsutsui Exp $	*/

/*
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Ralph Campbell.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)pmreg.h	8.1 (Berkeley) 6/10/93
 */

#ifndef _PMREG_H_
#define	_PMREG_H_

/*
 * Magic offset for cursor X & Y locations.
 */
#define PCC_X_OFFSET	212
#define PCC_Y_OFFSET	34

/*
 * Defines for the BrookTree bt478 VDAC.
 */
typedef volatile struct VDACRegs {
	u_char	mapWA;		/* address register (color map write) */
	char	pad1[3];
	u_char	map;		/* color map */
	char	pad2[3];
	u_char	mask;		/* pixel read mask */
	char	pad3[3];
	u_char	mapRA;		/* address register (color map read) */
	char	pad4[3];
	u_char	overWA;		/* address register (overlay map write) */
	char	pad5[3];
	u_char	over;		/* overlay map */
	char	pad6[7];
	u_char	overRA;		/* address register (overlay map read) */
} VDACRegs;

#endif	/* !_PMREG_H_ */
