/*	$NetBSD: pas.c,v 1.47 2000/04/28 08:51:42 jdolecek Exp $	*/

/*
 * Copyright (c) 1991-1993 Regents of the University of California.
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
 *	This product includes software developed by the Computer Systems
 *	Engineering Group at Lawrence Berkeley Laboratory.
 * 4. Neither the name of the University nor of the Laboratory may be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
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
 */
/*
 * jfw 7/13/97 - The soundblaster code requires the generic bus-space 
 * structures to be set up properly.  Rather than go to the effort of making
 * code for a dead line fully generic, properly set up the SB structures and
 * leave the rest x86/ISA/default-configuration specific.  If you have a
 * REAL computer, go buy a REAL sound card.
 */
/*
 * Todo:
 * 	- look at other PAS drivers (for PAS native suport)
 * 	- use common sb.c once emulation is setup
 */
/*
 * jfw 6/21/98 - WARNING:  the PAS native IO ports are scattered all around
 * IO port space (0x0388, 0x738B, 0xBF88, 0x2789, ...) which will make proper
 * reservation a real pain, so I'm not going to do it (while fixing the
 * current reservation code to "work").  As a sanity check, I reserve the
 * 0x0388 base address, but you probably shouldn't even think of trying this
 * driver unless you're certain you have the hardware installed and it doesn't
 * conflict with other hardware...
 */


#include <sys/param.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/syslog.h>
#include <sys/device.h>
#include <sys/proc.h>

#include <machine/cpu.h>
#include <machine/intr.h>
#include <machine/bus.h>
#include <machine/pio.h>

#include <sys/audioio.h>
#include <dev/audio_if.h>
#include <dev/midi_if.h>

#include <dev/isa/isavar.h>
#include <dev/isa/isadmavar.h>

#include <dev/isa/sbdspvar.h>
#include <dev/isa/sbreg.h>

#define DEFINE_TRANSLATIONS
#include <dev/isa/pasreg.h>

#ifdef AUDIO_DEBUG
#define DPRINTF(x)	if (pasdebug) printf x
int	pasdebug = 0;
#else
#define DPRINTF(x)
#endif

/*
 * Software state, per SoundBlaster card.
 * The soundblaster has multiple functionality, which we must demultiplex.
 * One approach is to have one major device number for the soundblaster card,
 * and use different minor numbers to indicate which hardware function
 * we want.  This would make for one large driver.  Instead our approach
 * is to partition the design into a set of drivers that share an underlying
 * piece of hardware.  Most things are hard to share, for example, the audio
 * and midi ports.  For audio, we might want to mix two processes' signals,
 * and for midi we might want to merge streams (this is hard due to
 * running status).  Moreover, we should be able to re-use the high-level
 * modules with other kinds of hardware.  In this module, we only handle the
 * most basic communications with the sb card.
 */
struct pas_softc {
	struct sbdsp_softc sc_sbdsp;	/* base device, &c. */
        bus_space_handle_t pas_port_handle;    /* the pas-specific port */

	int model;
	int rev;
};

int	pas_getdev __P((void *, struct audio_device *));
void	pasconf __P((int, int, int, int));


/*
 * Define our interface to the higher level audio driver.
 */

struct audio_hw_if pas_hw_if = {
	sbdsp_open,
	sbdsp_close,
	0,
	sbdsp_query_encoding,
	sbdsp_set_params,
	sbdsp_round_blocksize,
	0,
	0,
	0,
	0,
	0,
	sbdsp_halt_output,
	sbdsp_halt_input,
	sbdsp_speaker_ctl,
	pas_getdev,
	0,
	sbdsp_mixer_set_port,
	sbdsp_mixer_get_port,
	sbdsp_mixer_query_devinfo,
	sb_malloc,
	sb_free,
	sb_round_buffersize,
        sb_mappage,
	sbdsp_get_props,
	sbdsp_trigger_output,
	sbdsp_trigger_input,
};

/* The Address Translation code is used to convert I/O register addresses to
   be relative to the given base -register */

static char *pasnames[] = {
	"",
	"Plus",
	"CDPC",
	"16",
	"16Basic"
};

static struct audio_device pas_device = {
	"PAS,??",
	"",
	"pas"
};

/*XXX assume default I/O base address */
#define pasread(p) inb(p)
#define paswrite(d, p) outb(p, d)

void
pasconf(model, sbbase, sbirq, sbdrq)
	int model;
	int sbbase;
	int sbirq;
	int sbdrq;
{
	paswrite(0x00, INTERRUPT_MASK);
	/* Local timer control register */
	paswrite(0x36, SAMPLE_COUNTER_CONTROL);
	/* Sample rate timer (16 bit) */
	paswrite(0x36, SAMPLE_RATE_TIMER);
	paswrite(0, SAMPLE_RATE_TIMER);
	/* Local timer control register */
	paswrite(0x74, SAMPLE_COUNTER_CONTROL);
	/* Sample count register (16 bit) */
	paswrite(0x74, SAMPLE_BUFFER_COUNTER);
	paswrite(0, SAMPLE_BUFFER_COUNTER);

	paswrite(P_C_PCM_MONO | P_C_PCM_DAC_MODE |
		  P_C_MIXER_CROSS_L_TO_L | P_C_MIXER_CROSS_R_TO_R,
		  PCM_CONTROL);
	paswrite(S_M_PCM_RESET | S_M_FM_RESET |
		  S_M_SB_RESET | S_M_MIXER_RESET, SERIAL_MIXER);

/*XXX*/
	paswrite(I_C_1_BOOT_RESET_ENABLE|1, IO_CONFIGURATION_1);

	paswrite(I_C_2_PCM_DMA_DISABLED, IO_CONFIGURATION_2);
	paswrite(I_C_3_PCM_IRQ_DISABLED, IO_CONFIGURATION_3);
	
#ifdef BROKEN_BUS_CLOCK 
	paswrite(S_C_1_PCS_ENABLE | S_C_1_PCS_STEREO | S_C_1_PCS_REALSOUND |
		  S_C_1_FM_EMULATE_CLOCK, SYSTEM_CONFIGURATION_1);
#else
	paswrite(S_C_1_PCS_ENABLE | S_C_1_PCS_STEREO | S_C_1_PCS_REALSOUND,
		  SYSTEM_CONFIGURATION_1);     
#endif

	/*XXX*/
	paswrite(0, SYSTEM_CONFIGURATION_2);
	paswrite(0, SYSTEM_CONFIGURATION_3);

	/* Sets mute off and selects filter rate of 17.897 kHz */
	paswrite(F_F_MIXER_UNMUTE | 0x01, FILTER_FREQUENCY);

	if (model == PAS_16 || model == PAS_16BASIC)
		paswrite(8, PRESCALE_DIVIDER);
	else
		paswrite(0, PRESCALE_DIVIDER);

	paswrite(P_M_MV508_ADDRESS | P_M_MV508_PCM, PARALLEL_MIXER);
	paswrite(5, PARALLEL_MIXER);
		
	/*
	 * Setup SoundBlaster emulation.
	 */
	paswrite((sbbase >> 4) & 0xf, EMULATION_ADDRESS);
	paswrite(E_C_SB_IRQ_translate[sbirq] | E_C_SB_DMA_translate[sbdrq],
		 EMULATION_CONFIGURATION);
	paswrite(C_E_SB_ENABLE, COMPATIBILITY_ENABLE);

	/*
	 * Set mid-range levels.
	 */
	paswrite(P_M_MV508_ADDRESS | P_M_MV508_MODE, PARALLEL_MIXER);
	paswrite(P_M_MV508_LOUDNESS | P_M_MV508_ENHANCE_NONE, PARALLEL_MIXER);	

	paswrite(P_M_MV508_ADDRESS | P_M_MV508_MASTER_A, PARALLEL_MIXER);
	paswrite(50, PARALLEL_MIXER);
	paswrite(P_M_MV508_ADDRESS | P_M_MV508_MASTER_B, PARALLEL_MIXER);
	paswrite(50, PARALLEL_MIXER);

	paswrite(P_M_MV508_ADDRESS | P_M_MV508_MIXER | P_M_MV508_SB, PARALLEL_MIXER);
	paswrite(P_M_MV508_OUTPUTMIX | 30, PARALLEL_MIXER);

	paswrite(P_M_MV508_ADDRESS | P_M_MV508_MIXER | P_M_MV508_MIC, PARALLEL_MIXER);
	paswrite(P_M_MV508_INPUTMIX | 30, PARALLEL_MIXER);
}

int	pasprobe __P((struct device *, struct cfdata *, void *));
void	pasattach __P((struct device *, struct device *, void *));
static	int pasfind __P((struct device *, struct pas_softc *, 
			struct isa_attach_args *, int));
/* argument to pasfind */
#define PASPROBE  1
#define PASATTACH 0

struct cfattach pas_ca = {
	sizeof(struct pas_softc), pasprobe, pasattach
};

/*
 * Probe / attach routines.
 */

int
pasprobe(parent, match, aux)
	struct device *parent;
	struct cfdata *match;
	void *aux;
{
	struct pas_softc probesc, *sc = &probesc;

	bzero(sc, sizeof *sc);
	sc->sc_sbdsp.sc_dev.dv_cfdata = match;
	strcpy(sc->sc_sbdsp.sc_dev.dv_xname, "pas");
	return pasfind(parent, sc, aux, PASPROBE);
}

/*
 * Probe for the soundblaster hardware.
 */
static int
pasfind(parent, sc, ia, probing)
	struct device *parent;
	struct pas_softc *sc;
	struct isa_attach_args *ia;
	int probing;
{
	int iobase;
	u_char id, t;
	int rc = 0;  /* failure */

        /* ensure we can set this up as a sound blaster */
       	if (!SB_BASE_VALID(ia->ia_iobase)) {
		printf("pas: configured SB iobase 0x%x invalid\n", ia->ia_iobase);
		return 0;
	}

	if (bus_space_map(sc->sc_sbdsp.sc_iot, PAS_DEFAULT_BASE, 1, 0,
                          &sc->pas_port_handle)) {
		printf("pas: can't map base register %x in probe\n",
		       PAS_DEFAULT_BASE);
		return 0;
	}

	/*
	 * WARNING: Setting an option like W:1 or so that disables
	 * warm boot reset of the card will screw up this detect code
	 * something fierce.  Adding code to handle this means possibly
	 * interfering with other cards on the bus if you have something
	 * on base port 0x388.  SO be forewarned. 
	 */
	/* Talk to first board */
	outb(MASTER_DECODE, 0xbc);
	/* Set base address */

#if 0
	/* XXX Need to setup pseudo device */
	/* XXX What are good io addrs ? */
	if (iobase != PAS_DEFAULT_BASE) {
		printf("pas: configured iobase %d invalid\n", iobase);
		return 0;
	}
#else
	/* Start out talking to native PAS */
	iobase = PAS_DEFAULT_BASE;
#endif

	outb(MASTER_DECODE, iobase >> 2);
	/* One wait-state */
	paswrite(1, WAIT_STATE);

	id = pasread(INTERRUPT_MASK);
	if (id == 0xff || id == 0xfe) {
		/* sanity */
		DPRINTF(("pas: bogus card id\n"));
		goto unmap1;
	}
	/*
	 * We probably have a PAS-series board, now check for a
	 * PAS2-series board by trying to change the board revision
	 * bits.  PAS2-series hardware won't let you do this because
	 * the bits are read-only.
	 */
	t = id ^ 0xe0;
	paswrite(t, INTERRUPT_MASK);
	t = inb(INTERRUPT_MASK);
	paswrite(id, INTERRUPT_MASK);

	if (t != id) {
		/* Not a PAS2 */
		printf("pas: detected card but PAS2 test failed\n");
		goto unmap1;
	}
	/*XXX*/
	t = pasread(OPERATION_MODE_1) & 0xf;
	sc->model = O_M_1_to_card[t];
	if (sc->model != 0) {
		sc->rev = pasread(BOARD_REV_ID);
	}
	else {
		DPRINTF(("pas: bogus model id\n"));
		goto unmap1;
	}

        if (sc->model >= 0) {
                if (ia->ia_irq == IRQUNK) {
                        printf("pas: sb emulation requires known irq\n");
			goto unmap1;
                } 
                pasconf(sc->model, ia->ia_iobase, ia->ia_irq, 1);
        } else {
                DPRINTF(("pas: could not probe pas\n"));
		goto unmap1;
        }

	/* Now a SoundBlaster, so set up proper bus-space hooks
         * appropriately
         */

	sc->sc_sbdsp.sc_iobase = ia->ia_iobase;
	sc->sc_sbdsp.sc_iot = ia->ia_iot;

	/* Map i/o space [we map 24 ports which is the max of the sb and pro */
	if (bus_space_map(sc->sc_sbdsp.sc_iot, ia->ia_iobase, SBP_NPORT, 0,
	    &sc->sc_sbdsp.sc_ioh)) {
		printf("pas: can't map i/o space 0x%x/%d in probe\n",
		    ia->ia_iobase, SBP_NPORT);
		goto unmap1;
	}

	if (sbdsp_reset(&sc->sc_sbdsp) < 0) {
		DPRINTF(("pas: couldn't reset card\n"));
		goto unmap;
	}

	/*
	 * Cannot auto-discover DMA channel.
	 */
	if (!SB_DRQ_VALID(ia->ia_drq)) {
		printf("pas: configured dma chan %d invalid\n", ia->ia_drq);
		goto unmap;
	}
#ifdef NEWCONFIG
	/*
	 * If the IRQ wasn't compiled in, auto-detect it.
	 */
	if (ia->ia_irq == IRQUNK) {
		ia->ia_irq = isa_discoverintr(pasforceintr, aux);
		sbdsp_reset(&sc->sc_sbdsp);
		if (!SB_IRQ_VALID(ia->ia_irq)) {
			printf("pas: couldn't auto-detect interrupt");
			goto unmap;
		}
	} else
#endif
	if (!SB_IRQ_VALID(ia->ia_irq)) {
		printf("pas: configured irq chan %d invalid\n", ia->ia_irq);
		goto unmap;
	}

	sc->sc_sbdsp.sc_irq = ia->ia_irq;
	sc->sc_sbdsp.sc_drq8 = ia->ia_drq;
	sc->sc_sbdsp.sc_drq16 = -1; /* XXX */
	
	if (sbdsp_probe(&sc->sc_sbdsp) == 0) {
		DPRINTF(("pas: sbdsp probe failed\n"));
		goto unmap;
	}

	rc = 1;
	ia->ia_iosize = SB_NPORT;

 unmap:
	if (rc == 0 || probing)
	        bus_space_unmap(sc->sc_sbdsp.sc_iot, sc->sc_sbdsp.sc_ioh, SBP_NPORT);
 unmap1:
	if (rc == 0 || probing)
	        bus_space_unmap(sc->sc_sbdsp.sc_iot, PAS_DEFAULT_BASE, 1);
	return rc;
}

#ifdef NEWCONFIG
void
pasforceintr(aux)
	void *aux;
{
	static char dmabuf;
	struct isa_attach_args *ia = aux;
	int iobase = ia->ia_iobase;

	/*
	 * Set up a DMA read of one byte.
	 * XXX Note that at this point we haven't called 
	 * at_setup_dmachan().  This is okay because it just
	 * allocates a buffer in case it needs to make a copy,
	 * and it won't need to make a copy for a 1 byte buffer.
	 * (I think that calling at_setup_dmachan() should be optional;
	 * if you don't call it, it will be called the first time
	 * it is needed (and you pay the latency).  Also, you might
	 * never need the buffer anyway.)
	 */
	at_dma(DMAMODE_READ, &dmabuf, 1, ia->ia_drq);
	if (pas_wdsp(iobase, SB_DSP_RDMA) == 0) {
		(void)pas_wdsp(iobase, 0);
		(void)pas_wdsp(iobase, 0);
	}
}
#endif

/*
 * Attach hardware to driver, attach hardware driver to audio
 * pseudo-device driver .
 */
void
pasattach(parent, self, aux)
	struct device *parent, *self;
	void *aux;
{
	struct pas_softc *sc = (struct pas_softc *)self;
	struct isa_attach_args *ia = (struct isa_attach_args *)aux;
	int iobase = ia->ia_iobase;
	
	if (!pasfind(parent, sc, ia, PASATTACH)) {
		printf("%s: pasfind failed\n", sc->sc_sbdsp.sc_dev.dv_xname);
		return;
	}

	sc->sc_sbdsp.sc_ic = ia->ia_ic;
	sc->sc_sbdsp.sc_iobase = iobase;
	sc->sc_sbdsp.sc_ih = isa_intr_establish(ia->ia_ic, ia->ia_irq,
	    IST_EDGE, IPL_AUDIO, sbdsp_intr, &sc->sc_sbdsp);

	printf(" ProAudio Spectrum %s [rev %d] ", pasnames[sc->model],
	    sc->rev);
	
	sbdsp_attach(&sc->sc_sbdsp);

	sprintf(pas_device.name, "pas,%s", pasnames[sc->model]);
	sprintf(pas_device.version, "%d", sc->rev);

	audio_attach_mi(&pas_hw_if, &sc->sc_sbdsp, &sc->sc_sbdsp.sc_dev);
}

int
pas_getdev(addr, retp)
	void *addr;
	struct audio_device *retp;
{
	*retp = pas_device;
	return 0;
}
