/*	$NetBSD: pio.h,v 1.9 1994/11/18 22:18:35 mycroft Exp $	*/

/*
 * Copyright (c) 1993 Charles Hannum.
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
 *      This product includes software developed by Charles Hannum.
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

/*
 * Functions to provide access to i386 programmed I/O instructions.
 */

static __inline u_char
inb(int port)
{
	u_char	data;
	__asm __volatile("inb %%dx,%0" : "=a" (data) : "d" (port));
	return data;
}

static __inline void
insb(int port, void *addr, int cnt)
{
	__asm __volatile("cld\n\trepne\n\tinsb" :
			 : "d" (port), "D" (addr), "c" (cnt) : "%edi", "%ecx", "memory");
}

static __inline u_short
inw(int port)
{
	u_short	data;
	__asm __volatile("inw %%dx,%0" : "=a" (data) : "d" (port));
	return data;
}

static __inline void
insw(int port, void *addr, int cnt)
{
	__asm __volatile("cld\n\trepne\n\tinsw" :
			 : "d" (port), "D" (addr), "c" (cnt) : "%edi", "%ecx", "memory");
}

static __inline u_int
inl(int port)
{
	u_int	data;
	__asm __volatile("inl %%dx,%0" : "=a" (data) : "d" (port));
	return data;
}

static __inline void
insl(int port, void *addr, int cnt)
{
	__asm __volatile("cld\n\trepne\n\tinsl" :
			 : "d" (port), "D" (addr), "c" (cnt) : "%edi", "%ecx", "memory");
}

static __inline void
outb(int port, u_char data)
{
	__asm __volatile("outb %0,%%dx" : : "a" (data), "d" (port));
}

static __inline void
outsb(int port, void *addr, int cnt)
{
	__asm __volatile("cld\n\trepne\n\toutsb" :
			 : "d" (port), "S" (addr), "c" (cnt) : "%esi", "%ecx");
}

static __inline void
outw(int port, u_short data)
{
	__asm __volatile("outw %0,%%dx" : : "a" (data), "d" (port));
}

static __inline void
outsw(int port, void *addr, int cnt)
{
	__asm __volatile("cld\n\trepne\n\toutsw" :
			 : "d" (port), "S" (addr), "c" (cnt) : "%esi", "%ecx");
}

static __inline void
outl(int port, u_int data)
{
	__asm __volatile("outl %0,%%dx" : : "a" (data), "d" (port));
}

static __inline void
outsl(int port, void *addr, int cnt)
{
	__asm __volatile("cld\n\trepne\n\toutsl" :
			 : "d" (port), "S" (addr), "c" (cnt) : "%esi", "%ecx");
}
