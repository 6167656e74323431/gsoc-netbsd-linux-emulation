/* $NetBSD: gtmr_var.h,v 1.16 2022/11/19 12:12:25 skrll Exp $ */
/*-
 * Copyright (c) 2013 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Matt Thomas of 3am Software Foundry.
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

#ifndef _ARM_CORTEX_GTMR_VAR_
#define _ARM_CORTEX_GTMR_VAR_

#include <sys/percpu.h>

struct gtmr_softc {
	device_t sc_dev;
	struct evcnt sc_ev_missing_ticks;
	uint32_t sc_freq;
	uint32_t sc_flags;
#define	GTMR_FLAG_SUN50I_A64_UNSTABLE_TIMER		__BIT(0)
#define	GTMR_FLAG_CPU_REGISTERS_NOT_FW_CONFIGURED	__BIT(1)
	u_long sc_autoinc;
	bool sc_physical;
	void *sc_global_ih;
#ifdef DIAGNOSTIC
	percpu_t *sc_percpu;
#endif
};

#ifdef _KERNEL
#include "opt_arm_timer.h"
struct cpu_info;
int	gtmr_intr(void *);
void	gtmr_init_cpu_clock(struct cpu_info *);
void	gtmr_delay(unsigned int n);
#ifdef __HAVE_GENERIC_CPU_INITCLOCKS
void	gtmr_cpu_initclocks(void);
#else
#define gtmr_cpu_initclocks	cpu_initclocks
#endif
#endif

#endif /* _ARM_CORTEX_GTMR_VAR_ */
