/*	$NetBSD: sscom_s3c2800.c,v 1.11 2022/09/27 06:36:43 skrll Exp $ */

/*
 * Copyright (c) 2002, 2003 Fujitsu Component Limited
 * Copyright (c) 2002, 2003 Genetec Corporation
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
 * 3. Neither the name of The Fujitsu Component Limited nor the name of
 *    Genetec corporation may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY FUJITSU COMPONENT LIMITED AND GENETEC
 * CORPORATION ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL FUJITSU COMPONENT LIMITED OR GENETEC
 * CORPORATION BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: sscom_s3c2800.c,v 1.11 2022/09/27 06:36:43 skrll Exp $");

#include "opt_sscom.h"
#include "opt_ddb.h"
#include "opt_kgdb.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/tty.h>
#include <sys/proc.h>
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/uio.h>
#include <sys/kernel.h>
#include <sys/syslog.h>
#include <sys/types.h>
#include <sys/device.h>
#include <sys/timepps.h>
#include <sys/vnode.h>

#include <machine/intr.h>
#include <sys/bus.h>

#include <arm/s3c2xx0/s3c2800reg.h>
#include <arm/s3c2xx0/s3c2800var.h>
#include <arm/s3c2xx0/sscom_var.h>
#include <sys/termios.h>

static int sscom_match(device_t, cfdata_t, void *);
static void sscom_attach(device_t, device_t, void *);

CFATTACH_DECL_NEW(sscom, sizeof(struct sscom_softc), sscom_match,
    sscom_attach, NULL, NULL);

const struct sscom_uart_info s3c2800_uart_config[] = {
	/* UART 0 */
	{
		0,
		S3C2800_INT_TXD0,
		S3C2800_INT_RXD0,
		S3C2800_INT_UERR0,
		S3C2800_UART0_BASE,
	},
	/* UART 1 */
	{
		1,
		S3C2800_INT_TXD1,
		S3C2800_INT_RXD1,
		S3C2800_INT_UERR1,
		S3C2800_UART1_BASE,
	},
};

static int
sscom_match(device_t parent, cfdata_t cf, void *aux)
{
	struct s3c2xx0_attach_args *sa = aux;
	int unit = sa->sa_index;

	return unit == 0 || unit == 1;
}

static void
s3c2800_change_txrx_interrupts(struct sscom_softc *sc, bool unmask_p,
    u_int flags)
{
	int intbits = 0;
	if (flags & SSCOM_HW_RXINT)
		intbits |= 1 << sc->sc_rx_irqno;
	if (flags & SSCOM_HW_TXINT)
		intbits |= 1 << sc->sc_tx_irqno;
	if (unmask_p) {
		s3c2xx0_unmask_interrupts(intbits);
	} else {
		s3c2xx0_mask_interrupts(intbits);
	}
}

static void
sscom_attach(device_t parent, device_t self, void *aux)
{
	struct sscom_softc *sc = device_private(self);
	struct s3c2xx0_attach_args *sa = aux;
	int unit = sa->sa_index;
	bus_addr_t iobase = s3c2800_uart_config[unit].iobase;

	printf( ": UART%d addr=%lx", sa->sa_index, iobase );

	sc->sc_dev = self;
	sc->sc_iot = s3c2xx0_softc->sc_iot;
	sc->sc_unit = unit;
	sc->sc_frequency = s3c2xx0_softc->sc_pclk;

	sc->sc_change_txrx_interrupts = s3c2800_change_txrx_interrupts;

	sc->sc_rx_irqno = S3C2800_INT_RXD0 + sa->sa_index;
	sc->sc_tx_irqno = S3C2800_INT_TXD0 + sa->sa_index;

	if (bus_space_map(sc->sc_iot, iobase, SSCOM_SIZE, 0, &sc->sc_ioh)) {
		printf( ": failed to map registers\n" );
		return;
	}

	printf("\n");

	s3c2800_intr_establish(s3c2800_uart_config[unit].tx_int,
	    IPL_SERIAL, IST_LEVEL, sscomtxintr, sc);
	s3c2800_intr_establish(s3c2800_uart_config[unit].rx_int,
	    IPL_SERIAL, IST_LEVEL, sscomrxintr, sc);
	s3c2800_intr_establish(s3c2800_uart_config[unit].err_int,
	    IPL_SERIAL, IST_LEVEL, sscomrxintr, sc);
	sscom_disable_txrxint(sc);

	sscom_attach_subr(sc);
}



int
s3c2800_sscom_cnattach(bus_space_tag_t iot, int unit, int rate,
    int frequency, tcflag_t cflag)
{
	return sscom_cnattach(iot, s3c2800_uart_config + unit,
	    rate, frequency, cflag);
}

#ifdef KGDB
int
s3c2800_sscom_kgdb_attach(bus_space_tag_t iot, int unit, int rate,
    int frequency, tcflag_t cflag)
{
	return sscom_kgdb_attach(iot, s3c2800_uart_config + unit,
	    rate, frequency, cflag);
}
#endif /* KGDB */
