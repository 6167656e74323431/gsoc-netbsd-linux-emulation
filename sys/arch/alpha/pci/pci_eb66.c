/* $NetBSD: pci_eb66.c,v 1.6 2000/06/04 19:14:24 cgd Exp $ */

/*-
 * Copyright (c) 1998 The NetBSD Foundation, Inc.
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

/*
 * Copyright (c) 1995, 1996 Carnegie-Mellon University.
 * All rights reserved.
 *
 * Author: Chris G. Demetriou
 * 
 * Permission to use, copy, modify and distribute this software and
 * its documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 * 
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS" 
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND 
 * FOR ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 * 
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie the
 * rights to redistribute these changes.
 */

#include <sys/cdefs.h>			/* RCS ID & Copyright macro defns */

__KERNEL_RCSID(0, "$NetBSD: pci_eb66.c,v 1.6 2000/06/04 19:14:24 cgd Exp $");

#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/device.h>
#include <sys/syslog.h>

#include <vm/vm.h>

#include <machine/autoconf.h>

#include <dev/pci/pcireg.h>
#include <dev/pci/pcivar.h>

#include <alpha/pci/lcareg.h>
#include <alpha/pci/lcavar.h>

#include <alpha/pci/pci_eb66.h>

#include <machine/intrcnt.h>

#include "sio.h"
#if NSIO
#include <alpha/pci/siovar.h>
#endif

int	dec_eb66_intr_map __P((void *, pcitag_t, int, int,
	    pci_intr_handle_t *));
const char *dec_eb66_intr_string __P((void *, pci_intr_handle_t));
const struct evcnt *dec_eb66_intr_evcnt __P((void *, pci_intr_handle_t));
void	*dec_eb66_intr_establish __P((void *, pci_intr_handle_t,
	    int, int (*func)(void *), void *));
void	dec_eb66_intr_disestablish __P((void *, void *));

#define	EB66_MAX_IRQ		32
#define	PCI_STRAY_MAX		5

struct alpha_shared_intr *eb66_pci_intr;

bus_space_tag_t eb66_intrgate_iot;
bus_space_handle_t eb66_intrgate_ioh;

void	eb66_iointr __P((void *framep, unsigned long vec));
extern void	eb66_intr_enable __P((int irq));  /* pci_eb66_intr.S */
extern void	eb66_intr_disable __P((int irq)); /* pci_eb66_intr.S */

void
pci_eb66_pickintr(lcp)
	struct lca_config *lcp;
{
	bus_space_tag_t iot = &lcp->lc_iot;
	pci_chipset_tag_t pc = &lcp->lc_pc;
	int i;

        pc->pc_intr_v = lcp;
        pc->pc_intr_map = dec_eb66_intr_map;
        pc->pc_intr_string = dec_eb66_intr_string;
	pc->pc_intr_evcnt = dec_eb66_intr_evcnt;
        pc->pc_intr_establish = dec_eb66_intr_establish;
        pc->pc_intr_disestablish = dec_eb66_intr_disestablish;

	/* Not supported on the EB66. */
	pc->pc_pciide_compat_intr_establish = NULL;

	eb66_intrgate_iot = iot;
	if (bus_space_map(eb66_intrgate_iot, 0x804, 3, 0,
	    &eb66_intrgate_ioh) != 0)
		panic("pci_eb66_pickintr: couldn't map interrupt PLD");
	for (i = 0; i < EB66_MAX_IRQ; i++)
		eb66_intr_disable(i);	

	eb66_pci_intr = alpha_shared_intr_alloc(EB66_MAX_IRQ);
	for (i = 0; i < EB66_MAX_IRQ; i++)
		alpha_shared_intr_set_maxstrays(eb66_pci_intr, i,
			PCI_STRAY_MAX);

#if NSIO
	sio_intr_setup(pc, iot);
#endif

	set_iointr(eb66_iointr);
}

int     
dec_eb66_intr_map(lcv, bustag, buspin, line, ihp)
        void *lcv;
        pcitag_t bustag; 
        int buspin, line;
        pci_intr_handle_t *ihp;
{
	struct lca_config *lcp = lcv;
	pci_chipset_tag_t pc = &lcp->lc_pc;
	int bus, device, function;

	if (buspin == 0) {
		/* No IRQ used. */
		return 1;
	}
	if (buspin > 4) {
		printf("dec_eb66_intr_map: bad interrupt pin %d\n", buspin);
		return 1;
	}

	alpha_pci_decompose_tag(pc, bustag, &bus, &device, &function);

	/*
	 * The console places the interrupt mapping in the "line" value.
	 * A value of (char)-1 indicates there is no mapping.
	 */
	if (line == 0xff) {
		printf("dec_eb66_intr_map: no mapping for %d/%d/%d\n",
		    bus, device, function);
		return (1);
	}

	if (line >= EB66_MAX_IRQ)
		panic("dec_eb66_intr_map: eb66 irq too large (%d)\n",
		    line);

	*ihp = line;
	return (0);
}

const char *
dec_eb66_intr_string(lcv, ih)
	void *lcv;
	pci_intr_handle_t ih;
{
        static char irqstr[15];          /* 11 + 2 + NULL + sanity */

	if (ih >= EB66_MAX_IRQ)
		panic("dec_eb66_intr_string: bogus eb66 IRQ 0x%lx\n", ih);
	sprintf(irqstr, "eb66 irq %ld", ih);
	return (irqstr);
}

const struct evcnt *
dec_eb66_intr_evcnt(lcv, ih)
	void *lcv;
	pci_intr_handle_t ih;
{

	/* XXX for now, no evcnt parent reported */
	return (NULL);
}

void *
dec_eb66_intr_establish(lcv, ih, level, func, arg)
        void *lcv, *arg;
        pci_intr_handle_t ih;
        int level;
        int (*func) __P((void *));
{
	void *cookie;

	if (ih >= EB66_MAX_IRQ)
		panic("dec_eb66_intr_establish: bogus eb66 IRQ 0x%lx\n", ih);

	cookie = alpha_shared_intr_establish(eb66_pci_intr, ih, IST_LEVEL,
	    level, func, arg, "eb66 irq");

	if (cookie != NULL && alpha_shared_intr_isactive(eb66_pci_intr, ih))
		eb66_intr_enable(ih);
	return (cookie);
}

void
dec_eb66_intr_disestablish(lcv, cookie)
        void *lcv, *cookie;
{
	struct alpha_shared_intrhand *ih = cookie;
	unsigned int irq = ih->ih_num;
	int s;
 
	s = splhigh();

	alpha_shared_intr_disestablish(eb66_pci_intr, cookie,
	    "eb66 irq");
	if (alpha_shared_intr_isactive(eb66_pci_intr, irq) == 0) {
		eb66_intr_disable(irq);
		alpha_shared_intr_set_dfltsharetype(eb66_pci_intr, irq,
		    IST_NONE);
	}
 
	splx(s);
}

void
eb66_iointr(framep, vec)
	void *framep;
	unsigned long vec;
{
	int irq; 

	if (vec >= 0x900) {
		if (vec >= 0x900 + (EB66_MAX_IRQ << 4))
			panic("eb66_iointr: vec 0x%lx out of range\n", vec);
		irq = (vec - 0x900) >> 4;

		if (EB66_MAX_IRQ != INTRCNT_EB66_IRQ_LEN)
			panic("eb66 interrupt counter sizes inconsistent");
		intrcnt[INTRCNT_EB66_IRQ + irq]++;

		if (!alpha_shared_intr_dispatch(eb66_pci_intr, irq)) {
			alpha_shared_intr_stray(eb66_pci_intr, irq,
			    "eb66 irq");
			if (ALPHA_SHARED_INTR_DISABLE(eb66_pci_intr, irq))
				eb66_intr_disable(irq);
		}
		return;
	}
#if NSIO
	if (vec >= 0x800) {
		sio_iointr(framep, vec);
		return;
	}
#endif
	panic("eb66_iointr: weird vec 0x%lx\n", vec);
}

#if 0		/* THIS DOES NOT WORK!  see pci_eb66_intr.S. */
u_int8_t eb66_intr_mask[3] = { 0xff, 0xff, 0xff };

void
eb66_intr_enable(irq)
	int irq;
{
	int byte = (irq / 8), bit = (irq % 8);

#if 1
	printf("eb66_intr_enable: enabling %d (%d:%d)\n", irq, byte, bit);
#endif
	eb66_intr_mask[byte] &= ~(1 << bit);

	bus_space_write_1(eb66_intrgate_iot, eb66_intrgate_ioh, byte,
	    eb66_intr_mask[byte]);
}

void
eb66_intr_disable(irq)
	int irq;
{
	int byte = (irq / 8), bit = (irq % 8);

#if 1
	printf("eb66_intr_disable: disabling %d (%d:%d)\n", irq, byte, bit);
#endif
	eb66_intr_mask[byte] |= (1 << bit);

	bus_space_write_1(eb66_intrgate_iot, eb66_intrgate_ioh, byte,
	    eb66_intr_mask[byte]);
}
#endif
