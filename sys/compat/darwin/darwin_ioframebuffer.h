/*	$NetBSD: darwin_ioframebuffer.h,v 1.6 2003/05/14 18:28:05 manu Exp $ */

/*-
 * Copyright (c) 2003 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Emmanuel Dreyfus
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
 *        This product includes software developed by the NetBSD
 *        Foundation, Inc. and its contributors.
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

#ifndef	_DARWIN_IOFRAMEBUFFER_H_
#define	_DARWIN_IOFRAMEBUFFER_H_

extern struct mach_iokit_devclass darwin_ioframebuffer_devclass;

#define DARWIN_IOFRAMEBUFFER_CURSOR_MEMORY	100
#define DARWIN_IOFRAMEBUFFER_VRAM_MEMORY	110
#define DARWIN_IOFRAMEBUFFER_SYSTEM_APERTURE	0

struct darwin_ioframebuffer_shmem {
	darwin_ev_lock_data_t dis_sem;
	char dis_cursshow;
	char dis_sursobscured;
	char dis_shieldflag;
	char dis_dhielded;
	darwin_iogbounds dis_saverect;
	darwin_iogbounds dis_shieldrect;
	darwin_iogpoint dis_location;
	darwin_iogbounds dis_cursrect;
	darwin_iogbounds dis_oldcursrect;
	darwin_iogbounds dis_screen;
	int version;
	darwin_absolutetime dis_vbltime;
	darwin_absolutetime dis_vbldelta;
	unsigned int dis_reserved1[30];
	unsigned char dis_hwcurscapable;
	unsigned char dis_hwcursactive;
	unsigned char dis_hwcursshields;
	unsigned char dis_reserved2;
	darwin_iogsize dis_cursorsize[4];
	darwin_iogpoint dis_hotspot[4];
	unsigned char dis_curs[0];
};

int 
darwin_ioframebuffer_connect_method_scalari_scalaro(struct mach_trap_args *);
int 
darwin_ioframebuffer_connect_method_scalari_structo(struct mach_trap_args *);
int
darwin_ioframebuffer_connect_method_structi_structo(struct mach_trap_args *);
int darwin_ioframebuffer_connect_map_memory(struct mach_trap_args *);

#endif /* _DARWIN_IOFRAMEBUFFER_H_ */
