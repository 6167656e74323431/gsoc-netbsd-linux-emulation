/*	$NetBSD: if_rl_cardbus.c,v 1.4 2000/04/24 15:25:00 tsutsui Exp $	*/
/*
 * Copyright (c) 2000 Masanori Kanaoka
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
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL Bill Paul OR THE VOICES IN HIS HEAD
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/*
 * if_rl_cardbus.c:
 *	Cardbus specific routines for RealTek 8139 ethernet adapter.
 *	Tested for 
 *		- elecom-Laneed	LD-10/100CBA (Accton MPX5030)
 *		- MELCO		LPC3-TX-CB   (RealTek 8138)
 */

#include "opt_inet.h"
#include "opt_ns.h"
#include "bpfilter.h"
#include "rnd.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/callout.h>
#include <sys/device.h>
#include <sys/sockio.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_ether.h>
#include <net/if_dl.h>
#include <net/if_media.h>
#ifdef INET
#include <netinet/in.h>
#include <netinet/if_inarp.h>
#endif
#ifdef NS
#include <netns/ns.h>
#include <netns/ns_if.h>
#endif

#if NBPFILTER > 0
#include <net/bpf.h>
#endif
#if NRND > 0
#include <sys/rnd.h>
#endif

#include <machine/bus.h>

#include <dev/pci/pcireg.h>
#include <dev/pci/pcivar.h>
#include <dev/pci/pcidevs.h>

#include <dev/cardbus/cardbusvar.h>
#include <dev/cardbus/cardbusdevs.h>

#include <dev/mii/mii.h>
#include <dev/mii/miivar.h>

/*
 * Default to using PIO access for this driver. On SMP systems,
 * there appear to be problems with memory mapped mode: it looks like
 * doing too many memory mapped access back to back in rapid succession
 * can hang the bus. I'm inclined to blame this on crummy design/construction
 * on the part of RealTek. Memory mapped mode does appear to work on
 * uniprocessor systems though.
 */
#define RL_USEIOSPACE 

#include <dev/ic/rtl81x9reg.h>

/*
 * Various supported device vendors/types and their names.
 */
static struct rl_type rl_cardbus_devs[] = {
	{ CARDBUS_VENDOR_ACCTON, CARDBUS_PRODUCT_ACCTON_MPX5030,
		"Accton MPX 5030/5038 10/100BaseTX" },
	{ CARDBUS_VENDOR_REALTEK, CARDBUS_PRODUCT_REALTEK_RT8138,
		"RealTek 8138 10/100BaseTX" },
	{ 0, 0, NULL }
};

const struct rl_type *rl_cardbus_lookup
	__P((const struct cardbus_attach_args *));
static int rl_cardbus_match __P((struct device *, struct cfdata *, void *));
static void rl_cardbus_attach __P((struct device *, struct device *, void *));

struct rl_cardbus_softc {
	struct rl_softc sc_rl;		/* real rl softc */ 

	/* CardBus-specific goo. */
	void *sc_ih;
	cardbus_devfunc_t sc_ct;
	cardbustag_t sc_tag;
	int sc_csr;
	int sc_cben;
	int sc_bar_reg;
	pcireg_t sc_bar_val;
	bus_size_t sc_mapsize;
	int sc_intrline;
};

struct cfattach rtk_cardbus_ca = {
	sizeof(struct rl_cardbus_softc), rl_cardbus_match, rl_cardbus_attach,
};

const struct rl_type *
rl_cardbus_lookup(ca)
	const struct cardbus_attach_args *ca;
{
	struct rl_type		*t;

	for (t = rl_cardbus_devs; t->rl_name != NULL; t++){ 	
		if (PCI_VENDOR(ca->ca_id) == t->rl_vid &&
		    PCI_PRODUCT(ca->ca_id)  == t->rl_did) {
			return (t);
		}
	}
	return (NULL);
}

int
rl_cardbus_match(parent, match, aux)
	struct device *parent;
	struct cfdata *match;
	void *aux;
{
	struct cardbus_attach_args *ca = aux;

	if (rl_cardbus_lookup(ca) != NULL)
		return (1);
	return (0);
}


void
rl_cardbus_attach(parent, self, aux)
	struct device *parent, *self;
	void *aux;
{
	int			s, pmreg;
	u_char			eaddr[ETHER_ADDR_LEN];
	pcireg_t		command;
	struct rl_cardbus_softc *csc = (struct rl_cardbus_softc *)self;
	struct rl_softc *sc = &csc->sc_rl;
	struct cardbus_attach_args *ca = aux;
	cardbus_devfunc_t ct = ca->ca_ct;
	cardbus_chipset_tag_t cc = ct->ct_cc;
	cardbus_function_tag_t cf = ct->ct_cf;
	const struct rl_type *t;
	bus_addr_t adr;
	pcireg_t reg;

	sc->sc_dmat = ca->ca_dmat;
	csc->sc_ct = ct;
	csc->sc_tag = ca->ca_tag;
	csc->sc_intrline = ca->ca_intrline;

	t = rl_cardbus_lookup(ca); 
	if (t == NULL) { 
		printf("\n"); 
		panic("rl_cardbus_attach: impossible");
	 } 
	printf(": %s\n", t->rl_name); 

	s = splimp();
	/*
	 * Handle power management nonsense.
	 */
	if (cardbus_get_capability(cc, cf, csc->sc_tag, PCI_CAP_PWRMGMT, &pmreg, 0)) {
		command = cardbus_conf_read(cc, cf, csc->sc_tag, pmreg + 4);
		if (command & RL_PSTATE_MASK) {
			pcireg_t		iobase, membase, irq;

			/* Save important PCI config data. */
			iobase = cardbus_conf_read(cc, cf, csc->sc_tag, RL_PCI_LOIO);
			membase = cardbus_conf_read(cc, cf,csc->sc_tag, RL_PCI_LOMEM);
			irq = cardbus_conf_read(cc, cf,csc->sc_tag, PCI_PRODUCT_DELTA_8139);

			/* Reset the power state. */
			printf("%s: chip is is in D%d power mode "
			"-- setting to D0\n", sc->sc_dev.dv_xname,
			       command & RL_PSTATE_MASK);
			command &= 0xFFFFFFFC;
			cardbus_conf_write(cc, cf, csc->sc_tag, pmreg + 4, command);

			/* Restore PCI config data. */
			cardbus_conf_write(cc, cf, csc->sc_tag, RL_PCI_LOIO, iobase);
			cardbus_conf_write(cc, cf, csc->sc_tag, RL_PCI_LOMEM, membase);
			cardbus_conf_write(cc, cf, csc->sc_tag, PCI_PRODUCT_DELTA_8139, irq);
		}
	}
	/*
	 * Map control/status registers.
	 */
#ifdef RL_USEIOSPACE
	if (Cardbus_mapreg_map(ct, RL_PCI_LOIO, PCI_MAPREG_TYPE_IO, 0,
	    &sc->rl_btag, &sc->rl_bhandle, &adr, &csc->sc_mapsize) == 0) {
#if rbus
#else
		(*ct->ct_cf->carbus_io_open)(cc,0,adr, adr+csc->sc_mapsize);
#endif
		csc->sc_cben = CARDBUS_IO_ENABLE;
		csc->sc_csr |= (PCI_COMMAND_IO_ENABLE | PCI_COMMAND_MASTER_ENABLE);
		csc->sc_bar_reg = RL_PCI_LOIO;
		csc->sc_bar_val = adr | PCI_MAPREG_TYPE_IO;
	}
#else
	if (Cardbus_mapreg_map(ct, RL_PCI_LOMEM, PCI_MAPREG_TYPE_MEM, 0,
	    &sc->rl_btag, &sc->rl_bhandle, &adr, &csc->sc_mapsize) == 0) {
#if rbus
#else
		(*ct->ct_cf->carbus_mem_open)(cc,0,adr, adr+csc->sc_mapsize);
#endif
		csc->sc_cben = CARDBUS_MEM_ENABLE;
		csc->sc_csr |= (PCI_COMMAND_MEM_ENABLE|PCI_COMMAND_MASTER_ENABLE);
		csc->sc_bar_reg = RL_PCI_LOMEM;
		csc->sc_bar_val = adr | PCI_MAPREG_TYPE_MEM;
	}
#endif
	else {
		printf(": can't map i/o space\n");
		goto fail;
	}
	/* Make sure the right access type is on the CardBus bridge. */
	(*ct->ct_cf->cardbus_ctrl)(cc,csc->sc_cben);
	(*ct->ct_cf->cardbus_ctrl)(cc,CARDBUS_BM_ENABLE);

	/* Program the BAR */
	cardbus_conf_write(cc, cf, csc->sc_tag,
		csc->sc_bar_reg, csc->sc_bar_val);

	/* Enable the appropriate bits in the PCI CSR. */
	reg = cardbus_conf_read(cc, cf, csc->sc_tag, PCI_COMMAND_STATUS_REG);
	reg &= ~(PCI_COMMAND_IO_ENABLE|PCI_COMMAND_MEM_ENABLE);
	reg |= csc->sc_csr;
	cardbus_conf_write(cc, cf, csc->sc_tag, PCI_COMMAND_STATUS_REG,reg);

	/*
	 * Make sure the latency timer is set to some reasonable
	 * value.
	 */
	reg = cardbus_conf_read(cc, cf, csc->sc_tag, PCI_BHLC_REG);
	if (PCI_LATTIMER(reg) < 0x20) {
		reg &= ~(PCI_LATTIMER_MASK << PCI_LATTIMER_SHIFT);
		reg |= (0x20 << PCI_LATTIMER_SHIFT);
		cardbus_conf_write(cc, cf, csc->sc_tag, PCI_BHLC_REG, reg);
	}

	/* Reset the adapter. */
	rl_reset(sc);

	/*
	 * Now read the exact device type from the EEPROM to find
	 * out if it's an 8129 or 8139.
	 */

	if (t->rl_did == CARDBUS_PRODUCT_ACCTON_MPX5030 ||
		t->rl_did == CARDBUS_PRODUCT_REALTEK_RT8138){
		sc->rl_type = RL_8139;

		/*
		 * LD-10/100CBA (ACCTON_MPX5030):
		 * LPC3-TX-CB   (REALTEK_RT8138):
		 *     rl_read_eeprom() can't get MAC address 
		 *     from EEPROM(serial access). Lift MAC address
		 *     from RL-IDR0 -Rl_IDR5 register.
		 *
		 *  RTL8139B(L) datasheet rev 2.4.
		 *                                 
		 *    o REGSTER RL_IDR0 - RL_IDR5 address
		 *                                 
		 *    o "After the vaild duration of the RSTB pin or
		 *     autoload command in 9346CR,RTL8139B(L) performs
		 *     a series of EEPROM read operation from 93C46(93C56)
		 *     address 00H to 31H."  from 6. EEPROM Contents
		 */
		eaddr[0] = CSR_READ_1(sc, RL_IDR0);
		eaddr[1] = CSR_READ_1(sc, RL_IDR1);
		eaddr[2] = CSR_READ_1(sc, RL_IDR2);
		eaddr[3] = CSR_READ_1(sc, RL_IDR3);
		eaddr[4] = CSR_READ_1(sc, RL_IDR4);
		eaddr[5] = CSR_READ_1(sc, RL_IDR5);
	} else {
		printf(": unknown device ID: 0x%x\n", t->rl_did);
		goto fail;
	}
	printf("%s: Ethernet address: %s\n", sc->sc_dev.dv_xname,
	       ether_sprintf(eaddr));

	/* Allocate interrupt */
	printf("%s: interrupting at %d\n", sc->sc_dev.dv_xname, csc->sc_intrline);
	csc->sc_ih = cardbus_intr_establish(cc, cf, csc->sc_intrline, IPL_NET, 
		rl_intr, sc);
	if (csc->sc_ih == NULL) {
		printf("%s: unable to establish interrupt at %d\n",
		    sc->sc_dev.dv_xname,csc->sc_intrline);
		printf("\n");
		goto fail;
	}

	rl_attach(sc, eaddr);

fail:
	splx(s);
	return;
}

