/*	$NetBSD: ess_isa.c,v 1.3 1999/03/18 20:55:50 mycroft Exp $	*/

/*-
 * Copyright (c) 1999 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Nathan J. Williams.
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
#include <sys/device.h>

#include <machine/cpu.h>
#include <machine/bus.h>

#include <dev/isa/isavar.h>

#include <dev/isa/essreg.h>
#include <dev/isa/essvar.h>

#ifdef ESS_ISA_DEBUG
#define DPRINTF(x)	printf x
#else
#define DPRINTF(x)
#endif

int ess_isa_probe __P((struct device *, struct cfdata *, void *));
void ess_isa_attach __P((struct device *, struct device *, void *));

struct cfattach ess_isa_ca = {
	sizeof(struct ess_softc), ess_isa_probe, ess_isa_attach
};

int
ess_isa_probe(parent, match, aux)
	struct device *parent;
	struct cfdata *match;
	void *aux;
{
  	int ret;   
	struct isa_attach_args *ia = aux;
	struct ess_softc probesc, *sc= &probesc;
	
	memset(sc, 0, sizeof *sc);

	sc->sc_ic = ia->ia_ic;
	sc->sc_iot = ia->ia_iot;
	sc->sc_iobase = ia->ia_iobase;
	if (bus_space_map(sc->sc_iot, sc->sc_iobase, ESS_NPORT, 0, &sc->sc_ioh)) {
	  DPRINTF(("ess_isa_probe: Couldn't map I/O region at %x, size %x\n",
			   sc->sc_iobase, ESS_NPORT));
	  return 0;
	}

	sc->sc_audio1.irq = ia->ia_irq;
	sc->sc_audio1.ist = IST_EDGE;
	sc->sc_audio1.drq = ia->ia_drq;
	sc->sc_audio2.irq = -1;
	sc->sc_audio2.drq = ia->ia_drq2;

	ret = essmatch(sc);
		
	bus_space_unmap(sc->sc_iot, sc->sc_ioh, ESS_NPORT);

	if (ret)
		DPRINTF(("ess_isa_probe succeeded (score %d)\n", ret));
	else
		DPRINTF(("ess_isa_probe failed]n"));
		
	return ret;
}

void ess_isa_attach(parent, self, aux)
	 struct device *parent, *self;
	 void *aux;
{
	struct ess_softc *sc = (void *)self;
	struct isa_attach_args *ia = aux;

	printf("\n");

	sc->sc_ic = ia->ia_ic;
	sc->sc_iot = ia->ia_iot;
	sc->sc_iobase = ia->ia_iobase;
	if (bus_space_map(sc->sc_iot, sc->sc_iobase, ESS_NPORT, 0, &sc->sc_ioh)) {
	  DPRINTF(("ess_isa_attach: Couldn't map I/O region at %x, size %x\n",
			   sc->sc_iobase, ESS_NPORT));
	  return;
	}

	sc->sc_audio1.irq = ia->ia_irq;
	sc->sc_audio1.ist = IST_EDGE;
	sc->sc_audio1.drq = ia->ia_drq;
	sc->sc_audio2.irq = -1;
	sc->sc_audio2.drq = ia->ia_drq2;

	printf("%s", sc->sc_dev.dv_xname);

	essattach(sc);
}
