/* $NetBSD: hpet.c,v 1.18 2022/08/20 06:47:28 mlelstv Exp $ */

/*
 * Copyright (c) 2006 Nicolas Joly
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
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS
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
 * High Precision Event Timer.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: hpet.c,v 1.18 2022/08/20 06:47:28 mlelstv Exp $");

#include <sys/systm.h>
#include <sys/device.h>
#include <sys/module.h>

#include <sys/time.h>
#include <sys/timetc.h>

#include <sys/bus.h>
#include <sys/lock.h>

#include <machine/cpu_counter.h>

#include <dev/ic/hpetreg.h>
#include <dev/ic/hpetvar.h>

static u_int	hpet_get_timecount(struct timecounter *);
static bool	hpet_resume(device_t, const pmf_qual_t *);

static struct hpet_softc *hpet0 __read_mostly;

int
hpet_detach(device_t dv, int flags)
{
#if 0 /* XXX DELAY() is based off this, detaching is not a good idea. */
	struct hpet_softc *sc = device_private(dv);
	int rc;

	if ((rc = tc_detach(&sc->sc_tc)) != 0)
		return rc;

	pmf_device_deregister(dv);

	bus_space_write_4(sc->sc_memt, sc->sc_memh, HPET_CONFIG, sc->sc_config);

	return 0;
#else
	return EBUSY;
#endif
}

void
hpet_attach_subr(device_t dv)
{
	struct hpet_softc *sc = device_private(dv);
	struct timecounter *tc;
	uint64_t tmp;
	uint32_t val, sval, eval;
	int i;

	tc = &sc->sc_tc;

	tc->tc_name = device_xname(dv);
	tc->tc_get_timecount = hpet_get_timecount;
	tc->tc_quality = 2000;

	tc->tc_counter_mask = 0xffffffff;

	/* Get frequency */
	sc->sc_period = bus_space_read_4(sc->sc_memt, sc->sc_memh, HPET_PERIOD);
	if (sc->sc_period == 0 || sc->sc_period > HPET_PERIOD_MAX) {
		aprint_error_dev(dv, "invalid timer period\n");
		return;
	}

	/*
	 * The following loop is a workaround for AMD SB700 based systems.
	 * http://kerneltrap.org/mailarchive/git-commits-head/2008/8/17/2964724
	 * http://git.kernel.org/git/?p=linux/kernel/git/torvalds/linux-2.6.git;a=commit;h=a6825f1c1fa83b1e92b6715ee5771a4d6524d3b9
	 */
	for (i = 0; bus_space_read_4(sc->sc_memt, sc->sc_memh, HPET_CONFIG)
	    == 0xffffffff; i++) {
		if (i >= 1000) {
			aprint_error_dev(dv,
			    "HPET_CONFIG value = 0xffffffff\n");
			return;
		}
	}

	tmp = (1000000000000000ULL * 2) / sc->sc_period;
	tc->tc_frequency = (tmp / 2) + (tmp & 1);

	/* Enable timer */
	val = bus_space_read_4(sc->sc_memt, sc->sc_memh, HPET_CONFIG);
	sc->sc_config = val;
	if ((val & HPET_CONFIG_ENABLE) == 0) {
		val |= HPET_CONFIG_ENABLE;
		bus_space_write_4(sc->sc_memt, sc->sc_memh, HPET_CONFIG, val);
	}

	tc->tc_priv = sc;
	tc_init(tc);

	if (!pmf_device_register(dv, NULL, hpet_resume))
		aprint_error_dev(dv, "couldn't establish power handler\n");

	if (device_unit(dv) == 0)
		hpet0 = sc;

	/*
	 * Determine approximately how long it takes to read the counter
	 * register once, and compute an ajustment for hpet_delay() based on
	 * that.
	 */
	(void)bus_space_read_4(sc->sc_memt, sc->sc_memh, HPET_MCOUNT_LO);
	sval = bus_space_read_4(sc->sc_memt, sc->sc_memh, HPET_MCOUNT_LO);
	for (i = 0; i < 998; i++)
		(void)bus_space_read_4(sc->sc_memt, sc->sc_memh, HPET_MCOUNT_LO);
	eval = bus_space_read_4(sc->sc_memt, sc->sc_memh, HPET_MCOUNT_LO);
	val = eval - sval;
	sc->sc_adj = (int64_t)val * sc->sc_period / 1000;
}

static u_int
hpet_get_timecount(struct timecounter *tc)
{
	struct hpet_softc *sc = tc->tc_priv;

	return bus_space_read_4(sc->sc_memt, sc->sc_memh, HPET_MCOUNT_LO);
}

static bool
hpet_resume(device_t dv, const pmf_qual_t *qual)
{
	struct hpet_softc *sc = device_private(dv);
	uint32_t val;

	val = bus_space_read_4(sc->sc_memt, sc->sc_memh, HPET_CONFIG);
	val |= HPET_CONFIG_ENABLE;
	bus_space_write_4(sc->sc_memt, sc->sc_memh, HPET_CONFIG, val);

	return true;
}

bool
hpet_delay_p(void)
{

	return hpet0 != NULL;
}

void
hpet_delay(unsigned int us)
{
	struct hpet_softc *sc;
	uint32_t ntick, otick;
	int64_t delta;

	/*
	 * Read timer before slow division.  Convert microseconds to
	 * femtoseconds, subtract the cost of 1 counter register access,
	 * and convert to HPET units.
	 */
	sc = hpet0;
	otick = bus_space_read_4(sc->sc_memt, sc->sc_memh, HPET_MCOUNT_LO);
	delta = (((int64_t)us * 1000000000) - sc->sc_adj) / sc->sc_period;

	while (delta > 0) {
		SPINLOCK_BACKOFF_HOOK;
		ntick = bus_space_read_4(sc->sc_memt, sc->sc_memh,
		    HPET_MCOUNT_LO);
		delta -= (uint32_t)(ntick - otick);
		otick = ntick;
	}
}

uint64_t
hpet_tsc_freq(void)
{
	struct hpet_softc *sc;
	uint64_t td0, td, val, freq;
	uint32_t hd0, hd;
	int s;

	if (hpet0 == NULL || !cpu_hascounter())
		return 0;

	sc = hpet0;

	s = splhigh();
	(void)cpu_counter();
	(void)bus_space_read_4(sc->sc_memt, sc->sc_memh, HPET_MCOUNT_LO);
	hd0 = bus_space_read_4(sc->sc_memt, sc->sc_memh, HPET_MCOUNT_LO);
	td0 = cpu_counter();
	splx(s);

	/*
	 * Wait 1000000 HPET ticks (typically 50..100ms).
	 *
	 * This interval can produce an error of 1ppm (a few kHz
	 * in estimated TSC frequency), however the HPET timer is
	 * allowed to drift +/- 500ppm in that interval.
	 *
	 */
	hpet_delay(sc->sc_period / 1000);

	/*
	 * Determine TSC freq by comparing how far the TSC and HPET have
	 * advanced and round result to the nearest 1000.
	 */
	s = splhigh();
	(void)cpu_counter();
	(void)bus_space_read_4(sc->sc_memt, sc->sc_memh, HPET_MCOUNT_LO);
	hd = bus_space_read_4(sc->sc_memt, sc->sc_memh, HPET_MCOUNT_LO);
	td = cpu_counter();
	splx(s);

	val = (uint64_t)(hd - hd0) * sc->sc_period / 100000000;
	freq = (td - td0) * 10000000 / val;
	return rounddown(freq + 500, 1000);
}

MODULE(MODULE_CLASS_DRIVER, hpet, NULL);

#ifdef _MODULE
#include "ioconf.c"
#endif

static int
hpet_modcmd(modcmd_t cmd, void *aux)
{
	int rv = 0;

	switch (cmd) {

	case MODULE_CMD_INIT:

#ifdef _MODULE
		rv = config_init_component(cfdriver_ioconf_hpet,
		    cfattach_ioconf_hpet, cfdata_ioconf_hpet);
#endif
		break;

	case MODULE_CMD_FINI:

#ifdef _MODULE
		rv = config_fini_component(cfdriver_ioconf_hpet,
		    cfattach_ioconf_hpet, cfdata_ioconf_hpet);
#endif
		break;

	default:
		rv = ENOTTY;
	}

	return rv;
}
