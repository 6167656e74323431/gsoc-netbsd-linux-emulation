/* $NetBSD: lkminit_exec.c,v 1.1 2000/12/08 23:05:38 jdolecek Exp $ */

/*-
 * Copyright (c) 1996 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Michael Graff <explorer@flame.org>.
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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/exec.h>
#include <sys/proc.h>
#include <sys/lkm.h>

#include <machine/elf_machdep.h>
#define ELFSIZE	32
#include <sys/exec_elf.h>

#include <compat/ibcs2/ibcs2_exec.h>

int exec_ibcs2_elf_lkmentry __P((struct lkm_table *, int, int));

static struct execsw exec_ibcs2_elf =
	{ sizeof (Elf32_Ehdr), exec_elf32_makecmds,
	  { elf_probe_func: ELFNAME2(ibcs2,probe) },
	  &emul_ibcs2, EXECSW_PRIO_ANY,
	  IBCS2_ELF_AUX_ARGSIZ, elf32_copyargs, setregs };
				/* SCO 32bit ELF bins (not 64bit safe) */

/*
 * declare the exec
 */
MOD_EXEC("exec_ibcs2_elf", -1, &exec_ibcs2_elf, "ibcs2");

/*
 * entry point
 */
int
exec_ibcs2_elf_lkmentry(lkmtp, cmd, ver)
	struct lkm_table *lkmtp;	
	int cmd;
	int ver;
{
	DISPATCH(lkmtp, cmd, ver,
		 lkm_nofunc,
		 lkm_nofunc,
		 lkm_nofunc);
}
