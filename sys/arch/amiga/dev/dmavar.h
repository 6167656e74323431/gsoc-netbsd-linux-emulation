/*
 * Copyright (c) 1982, 1990 The Regents of the University of California.
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
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
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
 *	from: @(#)dmavar.h	7.2 (Berkeley) 11/4/90
 *	$Id: dmavar.h,v 1.3 1993/09/02 18:07:55 mw Exp $
 */

/* dmago flags */
#define	DMAGO_READ	0x08	/* transfer is a read */
#define	DMAGO_NOINT	0x80	/* don't interrupt on completion */

#ifdef KERNEL
typedef int  (*dmareq_t)  (struct devqueue *);
typedef void (*dmafree_t) (struct devqueue *dq);
typedef int  (*dmago_t)   (int, char *, int, int);
typedef int  (*dmanext_t) (int);
typedef void (*dmastop_t) (int);

extern void dma3000init (struct amiga_ctlr *, dmareq_t *, dmafree_t *, dmago_t *, 
			 dmanext_t *, dmastop_t *);

extern void dma2091init (struct amiga_ctlr *, dmareq_t *, dmafree_t *, dmago_t *, 
			 dmanext_t *, dmastop_t *);

extern void dmagvp11init (struct amiga_ctlr *, dmareq_t *, dmafree_t *, dmago_t *, 
			  dmanext_t *, dmastop_t *);
#endif
