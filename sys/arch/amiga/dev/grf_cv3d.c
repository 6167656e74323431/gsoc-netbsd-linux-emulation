/*	$NetBSD: grf_cv3d.c,v 1.13 2002/10/02 04:55:50 thorpej Exp $ */

/*
 * Copyright (c) 1995 Michael Teske
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
 *      This product includes software developed by Ezra Story, by Kari
 *      Mettinen, and Michael Teske.
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
#include "opt_amigacons.h"

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: grf_cv3d.c,v 1.13 2002/10/02 04:55:50 thorpej Exp $");

#include "grfcv3d.h"
#if NGRFCV3D > 0

/*
 * Graphics routines for the CyberVision 64/3D board, using the S3 ViRGE.
 *
 * Modified for CV64/3D from Michael Teske's CV driver by Tobias Abt 10/97.
 * Bugfixes by Bernd Ernesti 10/97.
 * Many thanks to Richard Hartmann who gave us his board so we could make
 * driver.
 *
 * TODO:
 *	- ZorroII support
 *	- Blitter support
 *	- Memcheck for 2MB boards (if they exists)
 */

/* Thanks to Frank Mariak for these infos
BOARDBASE
        +0x4000000      Memorybase start
        +0x4ffffff      Memorybase end
        +0x5000000      Img TransPort start
        +0x5007fff      Img TransPort end
        +0x5008000      MMIO Regbase start
        +0x500ffff      MMIO Regbase end
        +0x5800000      Img TransPort (rot) start
        +0x5807fff      Img TransPort (rot) end
        +0x7000000      Img TransPort (rot) start
        +0x7007fff      Img TransPort (rot) end
        +0x8000000      VCodeSwitch start
        +0x8000fff      VCodeSwitch end
        +0xc000000      IO Regbase start
        +0xc00ffff      IO Regbase end
        +0xc0e0000      PCI Cfg Base start
        +0xc0e0fff      PCI Cfg Base end

Note: IO Regbase is needed fo wakeup of the board otherwise use
      MMIO Regbase
*/

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/device.h>
#include <sys/malloc.h>
#include <sys/systm.h>
#include <machine/cpu.h>
#include <dev/cons.h>
#include <amiga/dev/itevar.h>
#include <amiga/amiga/device.h>
#include <amiga/dev/grfioctl.h>
#include <amiga/dev/grfvar.h>
#include <amiga/dev/grf_cv3dreg.h>
#include <amiga/dev/zbusvar.h>

int	grfcv3dmatch(struct device *, struct cfdata *, void *);
void	grfcv3dattach(struct device *, struct device *, void *);
int	grfcv3dprint(void *, const char *);

static int cv3d_has_4mb(volatile caddr_t);
static unsigned short cv3d_compute_clock(unsigned long);
void	cv3d_boardinit(struct grf_softc *);
int	cv3d_getvmode(struct grf_softc *, struct grfvideo_mode *);
int	cv3d_setvmode(struct grf_softc *, unsigned int);
int	cv3d_blank(struct grf_softc *, int *);
int	cv3d_mode(register struct grf_softc *, u_long, void *, u_long, int);
int	cv3d_ioctl(register struct grf_softc *gp, u_long cmd, void *data);
int	cv3d_setmonitor(struct grf_softc *, struct grfvideo_mode *);
int	cv3d_getcmap(struct grf_softc *, struct grf_colormap *);
int	cv3d_putcmap(struct grf_softc *, struct grf_colormap *);
int	cv3d_toggle(struct grf_softc *);
int	cv3d_mondefok(struct grfvideo_mode *);
int	cv3d_load_mon(struct grf_softc *, struct grfcv3dtext_mode *);
void	cv3d_inittextmode(struct grf_softc *);
static	__inline void cv3dscreen(int, volatile caddr_t);
static	__inline void cv3d_gfx_on_off(int, volatile caddr_t);

#ifdef CV3D_HARDWARE_CURSOR
int	cv3d_getspritepos(struct grf_softc *, struct grf_position *);
int	cv3d_setspritepos(struct grf_softc *, struct grf_position *);
int	cv3d_getspriteinfo(struct grf_softc *,struct grf_spriteinfo *);
void	cv3d_setup_hwc(struct grf_softc *);
int	cv3d_setspriteinfo(struct grf_softc *,struct grf_spriteinfo *);
int	cv3d_getspritemax(struct grf_softc *,struct grf_position *);
#endif	/* CV3D_HARDWARE_CURSOR */

/* Graphics display definitions.
 * These are filled by 'grfconfig' using GRFIOCSETMON.
 */
#define monitor_def_max 24
static struct grfvideo_mode monitor_def[24] = {
	{0}, {0}, {0}, {0}, {0}, {0}, {0}, {0},
	{0}, {0}, {0}, {0}, {0}, {0}, {0}, {0},
	{0}, {0}, {0}, {0}, {0}, {0}, {0}, {0}
};
static struct grfvideo_mode *monitor_current = &monitor_def[0];
#define MAXPIXELCLOCK 135000000 /* safety */

int	cv3d_zorroIII = 0;	/* CV64/3D in ZorroII or ZorroIII mode */
unsigned char cv3d_pass_toggle;	/* passthru status tracker */

/* Console display definition.
 *   Default hardcoded text mode.  This grf_cv3d is set up to
 *   use one text mode only, and this is it.  You may use
 *   grfconfig to change the mode after boot.
 */

/* Console font */
#ifdef KFONT_8X11
#define S3FONT kernel_font_8x11
#define S3FONTY 11
#else
#define S3FONT kernel_font_8x8
#define S3FONTY 8
#endif
extern unsigned char S3FONT[];

/*
 * Define default console mode
 * (Internally, we still have to use hvalues/8!)
 */
struct grfcv3dtext_mode cv3dconsole_mode = {
	{255, "", 25000000, 640, 480, 4, 640/8, 680/8, 768/8, 800/8,
	 481, 491, 493, 525, 0},
	8, S3FONTY, 80, 480 / S3FONTY, S3FONT, 32, 255
};

/* Console colors */
unsigned char cv3dconscolors[16][3] = {	/* background, foreground, hilite */
	/*  R     G     B  */
	{0x30, 0x30, 0x30},
	{0x00, 0x00, 0x00},
	{0x80, 0x00, 0x00},
	{0x00, 0x80, 0x00},
	{0x00, 0x00, 0x80},
	{0x80, 0x80, 0x00},
	{0x00, 0x80, 0x80},
	{0x80, 0x00, 0x80},
	{0xff, 0xff, 0xff},
	{0x40, 0x40, 0x40},
	{0xff, 0x00, 0x00},
	{0x00, 0xff, 0x00},
	{0x00, 0x00, 0xff},
	{0xff, 0xff, 0x00},
	{0x00, 0xff, 0xff},
	{0x00, 0x00, 0xff}
};

static unsigned char clocks[]={
0x13, 0x61, 0x6b, 0x6d, 0x51, 0x69, 0x54, 0x69,
0x4f, 0x68, 0x6b, 0x6b, 0x18, 0x61, 0x7b, 0x6c,
0x51, 0x67, 0x24, 0x62, 0x56, 0x67, 0x77, 0x6a,
0x1d, 0x61, 0x53, 0x66, 0x6b, 0x68, 0x79, 0x69,
0x7c, 0x69, 0x7f, 0x69, 0x22, 0x61, 0x54, 0x65,
0x56, 0x65, 0x58, 0x65, 0x67, 0x66, 0x41, 0x63,
0x27, 0x61, 0x13, 0x41, 0x37, 0x62, 0x6b, 0x4d,
0x23, 0x43, 0x51, 0x49, 0x79, 0x66, 0x54, 0x49,
0x7d, 0x66, 0x34, 0x56, 0x4f, 0x63, 0x1f, 0x42,
0x6b, 0x4b, 0x7e, 0x4d, 0x18, 0x41, 0x2a, 0x43,
0x7b, 0x4c, 0x74, 0x4b, 0x51, 0x47, 0x65, 0x49,
0x24, 0x42, 0x68, 0x49, 0x56, 0x47, 0x75, 0x4a,
0x77, 0x4a, 0x31, 0x43, 0x1d, 0x41, 0x71, 0x49,
0x53, 0x46, 0x29, 0x42, 0x6b, 0x48, 0x1f, 0x41,
0x79, 0x49, 0x6f, 0x48, 0x7c, 0x49, 0x38, 0x43,
0x7f, 0x49, 0x5d, 0x46, 0x22, 0x41, 0x53, 0x45,
0x54, 0x45, 0x55, 0x45, 0x56, 0x45, 0x57, 0x45,
0x58, 0x45, 0x25, 0x41, 0x67, 0x46, 0x5b, 0x45,
0x41, 0x43, 0x78, 0x47, 0x27, 0x41, 0x51, 0x44,
0x13, 0x21, 0x7d, 0x47, 0x37, 0x42, 0x71, 0x46,
0x6b, 0x2d, 0x14, 0x21, 0x23, 0x23, 0x7d, 0x2f,
0x51, 0x29, 0x61, 0x2b, 0x79, 0x46, 0x1d, 0x22,
0x54, 0x29, 0x45, 0x27, 0x7d, 0x46, 0x7f, 0x46,
0x4f, 0x43, 0x2f, 0x41, 0x1f, 0x22, 0x6a, 0x2b,
0x6b, 0x2b, 0x5b, 0x29, 0x7e, 0x2d, 0x65, 0x44,
0x18, 0x21, 0x5e, 0x29, 0x2a, 0x23, 0x45, 0x26,
0x7b, 0x2c, 0x19, 0x21, 0x74, 0x2b, 0x75, 0x2b,
0x51, 0x27, 0x3f, 0x25, 0x65, 0x29, 0x40, 0x25,
0x24, 0x22, 0x41, 0x25, 0x68, 0x29, 0x42, 0x25,
0x56, 0x27, 0x7e, 0x2b, 0x75, 0x2a, 0x1c, 0x21,
0x77, 0x2a, 0x4f, 0x26, 0x31, 0x23, 0x6f, 0x29,
0x1d, 0x21, 0x32, 0x23, 0x71, 0x29, 0x72, 0x29,
0x53, 0x26, 0x69, 0x28, 0x29, 0x22, 0x75, 0x29,
0x6b, 0x28, 0x1f, 0x21, 0x1f, 0x21, 0x6d, 0x28,
0x79, 0x29, 0x2b, 0x22, 0x6f, 0x28, 0x59, 0x26,
0x7c, 0x29, 0x7d, 0x29, 0x38, 0x23, 0x21, 0x21,
0x7f, 0x29, 0x39, 0x23, 0x5d, 0x26, 0x75, 0x28,
0x22, 0x21, 0x77, 0x28, 0x53, 0x25, 0x6c, 0x27,
0x54, 0x25, 0x61, 0x26, 0x55, 0x25, 0x30, 0x22,
0x56, 0x25, 0x63, 0x26, 0x57, 0x25, 0x71, 0x27,
0x58, 0x25, 0x7f, 0x28, 0x25, 0x21, 0x74, 0x27,
0x67, 0x26, 0x40, 0x23, 0x5b, 0x25, 0x26, 0x21,
0x41, 0x23, 0x34, 0x22, 0x78, 0x27, 0x6b, 0x26,
0x27, 0x21, 0x35, 0x22, 0x51, 0x24, 0x7b, 0x27,
0x13, 0x1,  0x13, 0x1,  0x7d, 0x27, 0x4c, 0x9,
0x37, 0x22, 0x5b, 0xb,  0x71, 0x26, 0x5c, 0xb,
0x6b, 0xd,  0x47, 0x23, 0x14, 0x1,  0x4f, 0x9,
0x23, 0x3,  0x75, 0x26, 0x7d, 0xf,  0x1c, 0x2,
0x51, 0x9,  0x59, 0x24, 0x61, 0xb,  0x69, 0x25,
0x79, 0x26, 0x34, 0x5,  0x1d, 0x2,  0x6b, 0x25,
0x54, 0x9,  0x35, 0x5,  0x45, 0x7,  0x6d, 0x25,
0x7d, 0x26, 0x16, 0x1,  0x7f, 0x26, 0x77, 0xd,
0x4f, 0x23, 0x78, 0xd,  0x2f, 0x21, 0x27, 0x3,
0x1f, 0x2,  0x59, 0x9,  0x6a, 0xb,  0x73, 0x25,
0x6b, 0xb,  0x63, 0x24, 0x5b, 0x9,  0x20, 0x2,
0x7e, 0xd,  0x4b, 0x7,  0x65, 0x24, 0x43, 0x22,
0x18, 0x1,  0x6f, 0xb,  0x5e, 0x9,  0x70, 0xb,
0x2a, 0x3,  0x33, 0x4,  0x45, 0x6,  0x60, 0x9,
0x7b, 0xc,  0x19, 0x1,  0x19, 0x1,  0x7d, 0xc,
0x74, 0xb,  0x50, 0x7,  0x75, 0xb,  0x63, 0x9,
0x51, 0x7,  0x23, 0x2,  0x3f, 0x5,  0x1a, 0x1,
0x65, 0x9,  0x2d, 0x3,  0x40, 0x5,  0x0,  0x0,
};


/* Board Address of CV64/3D */
static volatile caddr_t cv3d_boardaddr;
static int cv3d_fbsize;

static volatile caddr_t cv3d_memory_io_base;
static volatile caddr_t cv3d_register_base;
static volatile caddr_t cv3d_vcode_switch_base;
static volatile caddr_t cv3d_special_register_base;

/*
 * Memory clock (binpatchable).
 */
long cv3d_memclk = 55000000;

/* standard driver stuff */
CFATTACH_DECL(grfcv3d, sizeof(struct grf_softc),
    grfcv3dmatch, grfcv3dattach, NULL, NULL);

static struct cfdata *cfdata;

#define CV3D_ULCURSOR	1	/* Underlined Cursor in textmode */

/*
 * Get frambuffer memory size.
 * phase5 didn't provide the bit in CR36,
 * so we have to do it this way.
 * Return 0 for 2MB, 1 for 4MB
 */
static int
cv3d_has_4mb(volatile caddr_t fb)
{
#if 0	/* XXX */
	volatile unsigned long *testfbw, *testfbr;

	/* write patterns in memory and test if they can be read */
	testfbw = (volatile unsigned long *)fb;
	testfbr = (volatile unsigned long *)(fb + 0x02000000);
	*testfbw = 0x87654321;
	if (*testfbr != 0x87654321)
		return (0);

	/* upper memory region */
	testfbw = (volatile unsigned long *)(fb + 0x00200000);
	testfbr = (volatile unsigned long *)(fb + 0x02200000);
	*testfbw = 0x87654321;
	if (*testfbr != 0x87654321)
		return (0);
	*testfbw = 0xAAAAAAAA;
	if (*testfbr != 0xAAAAAAAA)
		return (0);
	*testfbw = 0x55555555;
	if (*testfbr != 0x55555555)
		return (0);
#endif
	return (1);
}

int
grfcv3dmatch(struct device *pdp, struct cfdata *cfp, void *auxp)
{
#ifdef CV3DCONSOLE
	static int cv3dcons_unit = -1;
#endif
	struct zbus_args *zap;

	zap = auxp;

	if (amiga_realconfig == 0)
#ifdef CV3DCONSOLE
		if (cv3dcons_unit != -1)
#endif
			 return (0);

	/*
	 * Distinct between ZorroII or ZorroIII mode.
	 * Note that iszthreepa(x) is true for the Z2 bus on the DraCo;
	 * therefore we check for the size instead.
	 */
	cv3d_zorroIII = zap->size > 4*1024*1024;

	/* Lets be Paranoid: Test man and prod id */
	if (zap->manid != 8512 || zap->prodid != 67)
		return (0);

#ifndef CV3DONZORRO2
	if (!cv3d_zorroIII) {
		return (0);
	}
#endif

	cv3d_boardaddr = zap->va;

#ifdef CV3DCONSOLE
	if (amiga_realconfig == 0) {
		cv3dcons_unit = cfp->cf_unit;
		cfdata = cfp;
	}
#endif

	return (1);
}

void
grfcv3dattach(struct device *pdp, struct device *dp, void *auxp)
{
	static struct grf_softc congrf;
	struct zbus_args *zap;
	struct grf_softc *gp;
	static char attachflag = 0;

	zap = auxp;

	printf("\n");

	/*
	 * This function is called twice, once on console init (dp == NULL)
	 * and once on "normal" grf7 init.
	 */

	if (dp == NULL) /* console init */
		gp = &congrf;
	else
		gp = (struct grf_softc *)dp;

	if (dp != NULL && congrf.g_regkva != 0) {
		/*
		 * inited earlier, just copy (not device struct)
		 */

		bcopy(&congrf.g_display, &gp->g_display,
			(char *) &gp[1] - (char *) &gp->g_display);
	} else {
		if (cv3d_zorroIII) {
			gp->g_fbkva =
			    (volatile caddr_t)cv3d_boardaddr + 0x04800000;
			cv3d_memory_io_base =
			    (volatile caddr_t)cv3d_boardaddr + 0x05000000;
			cv3d_register_base =
			    (volatile caddr_t)cv3d_boardaddr + 0x05008000;
			cv3d_vcode_switch_base =
			    (volatile caddr_t)cv3d_boardaddr + 0x08000000;
			cv3d_special_register_base =
			    (volatile caddr_t)cv3d_boardaddr + 0x0C000000;
		} else {
			gp->g_fbkva =
			    (volatile caddr_t)cv3d_boardaddr + 0x00000000;
			cv3d_memory_io_base =
			    (volatile caddr_t)cv3d_boardaddr + 0x003E0000;
			cv3d_register_base =
			    (volatile caddr_t)cv3d_boardaddr + 0x003C8000;
			cv3d_vcode_switch_base =
			    (volatile caddr_t)cv3d_boardaddr + 0x003A0000;
			cv3d_special_register_base =
			    (volatile caddr_t)cv3d_boardaddr + 0x003C0000;
		}

		gp->g_regkva = (volatile caddr_t)cv3d_register_base;

		gp->g_unit = GRF_CV3D_UNIT;
		gp->g_mode = cv3d_mode;
		gp->g_conpri = grfcv3d_cnprobe();
		gp->g_flags = GF_ALIVE;

		/* wakeup the board */
		cv3d_boardinit(gp);

#ifdef CV3DCONSOLE
		grfcv3d_iteinit(gp);
		(void)cv3d_load_mon(gp, &cv3dconsole_mode);
#endif
	}

	/*
	 * attach grf
	 */
	if (amiga_config_found(cfdata, &gp->g_device, gp, grfcv3dprint)) {
		if (dp != NULL)
			printf("%s: CyberVision64/3D with %dMB being used\n",
			    dp->dv_xname, cv3d_fbsize / 0x100000);
		attachflag = 1;
	} else {
		if (!attachflag)
			/*printf("grfcv3d unattached!!\n")*/;
	}
}

int
grfcv3dprint(void *auxp, const char *pnp)
{
	if (pnp)
		printf("ite at %s: ", pnp);
	return (UNCONF);
}


/*
 * Computes M, N, and R values from
 * given input frequency. It uses a table of
 * precomputed values, to keep CPU time low.
 *
 * The return value consist of:
 * lower byte:  Bits 4-0: N Divider Value
 *	        Bits 5-6: R Value          for e.g. SR10 or SR12
 * higher byte: Bits 0-6: M divider value  for e.g. SR11 or SR13
 */

static unsigned short
cv3d_compute_clock(unsigned long freq)
{
	static unsigned char *mnr, *save;	/* M, N + R vals */
	unsigned long work_freq, r;
	unsigned short erg;
	long diff, d2;

	if (freq < 12500000 || freq > MAXPIXELCLOCK) {
		printf("grfcv3d: Illegal clock frequency: %ldMHz\n", freq/1000000);
		printf("grfcv3d: Using default frequency: 25MHz\n");
		printf("grfcv3d: See the manpage of grfconfig for more informations.\n");
		freq = 25000000;
	}

	mnr = clocks;	/* there the vals are stored */
	d2 = 0x7fffffff;

	while (*mnr) {	/* mnr vals are 0-terminated */
		work_freq = (0x37EE * (mnr[0] + 2)) / ((mnr[1] & 0x1F) + 2);

		r = (mnr[1] >> 5) & 0x03;
		if (r != 0)
			work_freq=work_freq >> r;	/* r is the freq divider */

		work_freq *= 0x3E8;	/* 2nd part of OSC */

		diff = abs(freq - work_freq);

		if (d2 >= diff) {
			d2 = diff;
			/* In save are the vals for minimal diff */
			save = mnr;
		}
		mnr += 2;
	}
	erg = *((unsigned short *)save);

	return (erg);
}


void
cv3d_boardinit(struct grf_softc *gp)
{
	volatile caddr_t ba, special;
	unsigned char test;
	unsigned int clockpar;
	int i;
	struct grfinfo *gi;

	ba = gp->g_regkva;

	/* PCI config */
	if (cv3d_zorroIII) {
		special = (cv3d_special_register_base + 0x000E0000);
	} else {
		special = (cv3d_special_register_base);
	}
	*((short *)(special + 0x10)) = 0;
	*((long *)(special + 0x4)) = 0x02000003;

	/* Wakeup Chip */
	vgawio(cv3d_boardaddr, SREG_VIDEO_SUBS_ENABLE, 1);

	vgaw(ba, SREG_VIDEO_SUBS_ENABLE, 0x01);

	vgaw(ba, GREG_MISC_OUTPUT_W, 0x03);

	WCrt(ba, CRT_ID_REGISTER_LOCK_1, 0x48);	/* unlock S3 VGA regs */
	WCrt(ba, CRT_ID_REGISTER_LOCK_2, 0xA5);	/* unlock syscontrol */

	WCrt(ba, CRT_ID_EXT_MISC_CNTL_1, 0x02);
	WCrt(ba, CRT_ID_EXT_MISC_CNTL_1, 0x00);

	WSeq(ba, SEQ_ID_UNLOCK_EXT, 0x06);	/* Unlock extensions */

	/*
	 * bit 0=1: enable enhanced mode functions
	 * bit 4=1: enable linear adressing
	 */
	vgaw32(cv3d_memory_io_base, MR_ADVANCED_FUNCTION_CONTROL, 0x00000011);

	/* -hsync and -vsync */
	vgaw(ba, GREG_MISC_OUTPUT_W, 0xC3);

	/* Reset. This does nothing, but everyone does it:) */
	WSeq(ba, SEQ_ID_RESET, 0x03);

	WSeq(ba, SEQ_ID_CLOCKING_MODE, 0x01);	/* 8 Dot Clock */
	WSeq(ba, SEQ_ID_MAP_MASK, 0x0F);	/* Enable write planes */
	WSeq(ba, SEQ_ID_CHAR_MAP_SELECT, 0x00);	/* Character Font */

	WSeq(ba, SEQ_ID_MEMORY_MODE, 0x02);	/* Complete mem access */
	WSeq(ba, SEQ_ID_MMIO_SELECT, 0x00);

	test = RSeq(ba, SEQ_ID_BUS_REQ_CNTL);	/* Bus Request */

	/* enable 4MB fast Page Mode */
	test = test | 0xC0;
	WSeq(ba, SEQ_ID_BUS_REQ_CNTL, test);

#if 0	/* XXX */
	/* faster LUT write */
	WSeq(ba, SEQ_ID_RAMDAC_CNTL, 0xC0);
#else
	WSeq(ba, SEQ_ID_UNKNOWN6, 0x00);
	WSeq(ba, SEQ_ID_SIGNAL_SELECT, 0x02);
#endif

	test = RSeq(ba, SEQ_ID_CLKSYN_CNTL_2);	/* Clksyn2 read */

	/* immediately Clkload bit clear */
	test = test & 0xDF;

	/* 2 MCLK Memory Write.... */
	if (cv3d_memclk >= 55000000)
		test |= 0x80;

	WSeq(ba, SEQ_ID_CLKSYN_CNTL_2, test);

	/* Memory CLK */
	clockpar = cv3d_compute_clock(cv3d_memclk);
	test = (clockpar & 0xFF00) >> 8;
	WSeq(ba, SEQ_ID_MCLK_HI, test);		/* PLL N-Divider Value */

	test = clockpar & 0xFF;
	WSeq(ba, SEQ_ID_MCLK_LO, test);		/* PLL M-Divider Value */

	/* We now load an 25 MHz, 31 kHz, 640x480 standard VGA Mode. */
	/* DCLK */
	WSeq(ba, SEQ_ID_DCLK_HI, 0x13);
	WSeq(ba, SEQ_ID_DCLK_LO, 0x41);

	test = RSeq (ba, SEQ_ID_CLKSYN_CNTL_2);
	test = test | 0x22;

	/* DCLK + MCLK Clock immediate load! */
	WSeq(ba,SEQ_ID_CLKSYN_CNTL_2, test);

	/* DCLK load */
	test = vgar(ba, 0x3cc);
	test = test | 0x0c;
	vgaw(ba, 0x3c2, test);

	/* Clear bit 5 again, prevent further loading. */
	WSeq(ba, SEQ_ID_CLKSYN_CNTL_2, 0x02);

	WCrt(ba, CRT_ID_HOR_TOTAL, 0x5F);
	WCrt(ba, CRT_ID_HOR_DISP_ENA_END, 0x4F);
	WCrt(ba, CRT_ID_START_HOR_BLANK, 0x50);
	WCrt(ba, CRT_ID_END_HOR_BLANK, 0x82);
	WCrt(ba, CRT_ID_START_HOR_RETR, 0x54);
	WCrt(ba, CRT_ID_END_HOR_RETR, 0x80);
	WCrt(ba, CRT_ID_VER_TOTAL, 0xBF);

	WCrt(ba, CRT_ID_OVERFLOW, 0x1F);	/* overflow reg */

	WCrt(ba, CRT_ID_PRESET_ROW_SCAN, 0x00);	/* no panning */

	WCrt(ba, CRT_ID_MAX_SCAN_LINE, 0x40);	/* vscan */

	WCrt(ba, CRT_ID_CURSOR_START, 0x00);
	WCrt(ba, CRT_ID_CURSOR_END, 0x00);

	/* Display start adress */
	WCrt(ba, CRT_ID_START_ADDR_HIGH, 0x00);
	WCrt(ba, CRT_ID_START_ADDR_LOW, 0x00);

	/* Cursor location */
	WCrt(ba, CRT_ID_CURSOR_LOC_HIGH, 0x00);
	WCrt(ba, CRT_ID_CURSOR_LOC_LOW, 0x00);

	/* Vertical retrace */
	WCrt(ba, CRT_ID_START_VER_RETR, 0x9C);
	WCrt(ba, CRT_ID_END_VER_RETR, 0x0E);

	WCrt(ba, CRT_ID_VER_DISP_ENA_END, 0x8F);
	WCrt(ba, CRT_ID_SCREEN_OFFSET, 0x50);

	WCrt(ba, CRT_ID_UNDERLINE_LOC, 0x00);

	WCrt(ba, CRT_ID_START_VER_BLANK, 0x96);
	WCrt(ba, CRT_ID_END_VER_BLANK, 0xB9);

	WCrt(ba, CRT_ID_MODE_CONTROL, 0xE3);

	WCrt(ba, CRT_ID_LINE_COMPARE, 0xFF);

	WCrt(ba, CRT_ID_SYSTEM_CONFIG, 0x21);
	WCrt(ba, CRT_ID_MEMORY_CONF, 0x04);
	WCrt(ba, CRT_ID_BACKWAD_COMP_1, 0x00);
	WCrt(ba, CRT_ID_BACKWAD_COMP_2, 0x02);
	WCrt(ba, CRT_ID_BACKWAD_COMP_3, 0x10);	/* FIFO enabled */

	/* Refresh count 1, High speed text font, enhanced color mode */
	WCrt(ba, CRT_ID_MISC_1, 0x35);

	/* start fifo position */
	WCrt(ba, CRT_ID_DISPLAY_FIFO, 0x5A);

	WCrt(ba, CRT_ID_EXT_MEM_CNTL_2, 0x02);

	WCrt(ba, CRT_ID_LAW_POS_LO, 0x40);

	WCrt(ba, CRT_ID_EXT_MISC_CNTL_1, 0x81);
	WCrt(ba, CRT_ID_MISC_1, 0xB5);
	WCrt(ba, CRT_ID_CONFIG_1, 0x0E);

	WGfx(ba, GCT_ID_SET_RESET, 0x00);
	WGfx(ba, GCT_ID_ENABLE_SET_RESET, 0x00);
	WGfx(ba, GCT_ID_COLOR_COMPARE, 0x00);
	WGfx(ba, GCT_ID_DATA_ROTATE, 0x00);
	WGfx(ba, GCT_ID_READ_MAP_SELECT, 0x00);
	WGfx(ba, GCT_ID_GRAPHICS_MODE, 0x40);
	WGfx(ba, GCT_ID_MISC, 0x01);
	WGfx(ba, GCT_ID_COLOR_XCARE, 0x0F);
	WGfx(ba, GCT_ID_BITMASK, 0xFF);

	/* colors for text mode */
	for (i = 0; i <= 0xf; i++)
		WAttr (ba, i, i);

	WAttr(ba, ACT_ID_ATTR_MODE_CNTL, 0x41);
	WAttr(ba, ACT_ID_OVERSCAN_COLOR, 0x01);
	WAttr(ba, ACT_ID_COLOR_PLANE_ENA, 0x0F);
	WAttr(ba, ACT_ID_HOR_PEL_PANNING, 0x00);
	WAttr(ba, ACT_ID_COLOR_SELECT, 0x00);

	vgawio(cv3d_boardaddr, VDAC_MASK, 0xFF);	/* DAC Mask */

	/* colors initially set to greyscale */

	vgawio(cv3d_boardaddr, VDAC_ADDRESS_W, 0);

	for (i = 255; i >= 0 ; i--) {
		vgawio(cv3d_boardaddr, VDAC_DATA, i);
		vgawio(cv3d_boardaddr, VDAC_DATA, i);
		vgawio(cv3d_boardaddr, VDAC_DATA, i);
	}

	/* GFx hardware cursor off */
	WCrt(ba, CRT_ID_HWGC_MODE, 0x00);

	/* Set first to 4 MB, so test will work */
	WCrt(ba, CRT_ID_LAW_CNTL, 0x13);

	/* find *correct* fbsize of z3 board */
	if (cv3d_has_4mb(gp->g_fbkva)) {
		cv3d_fbsize = 1024 * 1024 * 4;
		WCrt(ba, CRT_ID_LAW_CNTL, 0x13); /* 4 MB */
	} else {
		cv3d_fbsize = 1024 * 1024 * 2;
		WCrt(ba, CRT_ID_LAW_CNTL, 0x12); /* 2 MB */
	}

	/* Initialize graphics engine */
	GfxBusyWait(cv3d_memory_io_base);
	vgaw32(cv3d_memory_io_base, BLT_COMMAND_SET, CMD_NOP);
	vgaw32(cv3d_memory_io_base, BLT_CLIP_LEFT_RIGHT, 0x000007ff);
	vgaw32(cv3d_memory_io_base, BLT_CLIP_TOP_BOTTOM, 0x000007ff);
	vgaw32(cv3d_memory_io_base, L2D_COMMAND_SET, CMD_NOP);
	vgaw32(cv3d_memory_io_base, L2D_CLIP_LEFT_RIGHT, 0x000007ff);
	vgaw32(cv3d_memory_io_base, L2D_CLIP_TOP_BOTTOM, 0x000007ff);
	vgaw32(cv3d_memory_io_base, P2D_COMMAND_SET, CMD_NOP);
	vgaw32(cv3d_memory_io_base, P2D_CLIP_LEFT_RIGHT, 0x000007ff);
	vgaw32(cv3d_memory_io_base, P2D_CLIP_TOP_BOTTOM, 0x000007ff);

	/* Enable Video Display (Set Bit 5) */
	WAttr(ba, 0x33, 0);


	gi = &gp->g_display;
	gi->gd_regaddr	= (caddr_t) kvtop (ba);
	gi->gd_regsize	= 64 * 1024;
	gi->gd_fbaddr	= (caddr_t) kvtop (gp->g_fbkva);
	gi->gd_fbsize	= cv3d_fbsize;
}


int
cv3d_getvmode(struct grf_softc *gp, struct grfvideo_mode *vm)
{
	struct grfvideo_mode *gv;

#ifdef CV3DCONSOLE
	/* Handle grabbing console mode */
	if (vm->mode_num == 255) {
		bcopy(&cv3dconsole_mode, vm, sizeof(struct grfvideo_mode));
		/* XXX so grfconfig can tell us the correct text dimensions. */
		vm->depth = cv3dconsole_mode.fy;
	} else
#endif
	{
		if (vm->mode_num == 0)
			vm->mode_num = (monitor_current - monitor_def) + 1;
		if (vm->mode_num < 1 || vm->mode_num > monitor_def_max)
			return (EINVAL);
		gv = monitor_def + (vm->mode_num - 1);
		if (gv->mode_num == 0)
			return (EINVAL);

		bcopy(gv, vm, sizeof(struct grfvideo_mode));
	}

	/* adjust internal values to pixel values */

	vm->hblank_start *= 8;
	vm->hsync_start *= 8;
	vm->hsync_stop *= 8;
	vm->htotal *= 8;

	return (0);
}


int
cv3d_setvmode(struct grf_softc *gp, unsigned mode)
{

	if (!mode || (mode > monitor_def_max) ||
	    monitor_def[mode - 1].mode_num == 0)
		return (EINVAL);

	monitor_current = monitor_def + (mode - 1);

	return (0);
}


int
cv3d_blank(struct grf_softc *gp, int *on)
{
	volatile caddr_t ba;

	ba = gp->g_regkva;
	cv3d_gfx_on_off(*on > 0 ? 0 : 1, ba);
	return (0);
}


/*
 * Change the mode of the display.
 * Return a UNIX error number or 0 for success.
 */
int
cv3d_mode(register struct grf_softc *gp, u_long cmd, void *arg, u_long a2,
          int a3)
{
	int error;

	switch (cmd) {
	    case GM_GRFON:
		error = cv3d_load_mon (gp,
		    (struct grfcv3dtext_mode *) monitor_current) ? 0 : EINVAL;
		return (error);

	    case GM_GRFOFF:
#ifndef CV3DCONSOLE
		cv3dscreen(1, cv3d_vcode_switch_base);
#else
		cv3d_load_mon(gp, &cv3dconsole_mode);
		ite_reinit(gp->g_itedev);
#endif
		return (0);

	    case GM_GRFCONFIG:
		return (0);

	    case GM_GRFGETVMODE:
		return (cv3d_getvmode (gp, (struct grfvideo_mode *) arg));

	    case GM_GRFSETVMODE:
		error = cv3d_setvmode (gp, *(unsigned *) arg);
		if (!error && (gp->g_flags & GF_GRFON))
			cv3d_load_mon(gp,
			    (struct grfcv3dtext_mode *) monitor_current);
		return (error);

	    case GM_GRFGETNUMVM:
		*(int *)arg = monitor_def_max;
		return (0);

	    case GM_GRFIOCTL:
		return (cv3d_ioctl (gp, a2, arg));

	    default:
		break;
	}

	return (EPASSTHROUGH);
}


int
cv3d_ioctl(register struct grf_softc *gp, u_long cmd, void *data)
{
	switch (cmd) {
#ifdef CV3D_HARDWARE_CURSOR
	    case GRFIOCGSPRITEPOS:
		return(cv3d_getspritepos (gp, (struct grf_position *) data));

	    case GRFIOCSSPRITEPOS:
		return(cv3d_setspritepos (gp, (struct grf_position *) data));

	    case GRFIOCSSPRITEINF:
		return(cv3d_setspriteinfo (gp, (struct grf_spriteinfo *) data));

	    case GRFIOCGSPRITEINF:
		return(cv3d_getspriteinfo (gp, (struct grf_spriteinfo *) data));

	    case GRFIOCGSPRITEMAX:
		return(cv3d_getspritemax (gp, (struct grf_position *) data));
#else	/* CV3D_HARDWARE_CURSOR */
	    case GRFIOCGSPRITEPOS:
	    case GRFIOCSSPRITEPOS:
	    case GRFIOCSSPRITEINF:
	    case GRFIOCGSPRITEINF:
	    case GRFIOCGSPRITEMAX:
		break;
#endif	/* CV3D_HARDWARE_CURSOR */

	    case GRFIOCGETCMAP:
		return (cv3d_getcmap (gp, (struct grf_colormap *) data));

	    case GRFIOCPUTCMAP:
		return (cv3d_putcmap (gp, (struct grf_colormap *) data));

	    case GRFIOCBITBLT:
		break;

	    case GRFTOGGLE:
		return (cv3d_toggle (gp));

	    case GRFIOCSETMON:
		return (cv3d_setmonitor (gp, (struct grfvideo_mode *)data));

	    case GRFIOCBLANK:
		return (cv3d_blank (gp, (int *)data));
	}
	return (EPASSTHROUGH);
}


int
cv3d_setmonitor(struct grf_softc *gp, struct grfvideo_mode *gv)
{
	struct grfvideo_mode *md;

	if (!cv3d_mondefok(gv))
		return (EINVAL);

#ifdef CV3DCONSOLE
	/* handle interactive setting of console mode */
	if (gv->mode_num == 255) {
		bcopy(gv, &cv3dconsole_mode.gv, sizeof(struct grfvideo_mode));
		cv3dconsole_mode.gv.hblank_start /= 8;
		cv3dconsole_mode.gv.hsync_start /= 8;
		cv3dconsole_mode.gv.hsync_stop /= 8;
		cv3dconsole_mode.gv.htotal /= 8;
		cv3dconsole_mode.rows = gv->disp_height / cv3dconsole_mode.fy;
		cv3dconsole_mode.cols = gv->disp_width / cv3dconsole_mode.fx;
		if (!(gp->g_flags & GF_GRFON))
			cv3d_load_mon(gp, &cv3dconsole_mode);
		ite_reinit(gp->g_itedev);
		return (0);
	}
#endif

	md = monitor_def + (gv->mode_num - 1);

	/*
	 * Prevent user from crashing the system by using
	 * grfconfig while in X
	 */
	if (gp->g_flags & GF_GRFON)
		if (md == monitor_current) {
			printf("grfcv3d: Changing the used mode not allowed!\n");
			return (EINVAL);
		}

	bcopy(gv, md, sizeof(struct grfvideo_mode));

	/* adjust pixel oriented values to internal rep. */

	md->hblank_start /= 8;
	md->hsync_start /= 8;
	md->hsync_stop /= 8;
	md->htotal /= 8;

	return (0);
}


int
cv3d_getcmap(struct grf_softc *gfp, struct grf_colormap *cmap)
{
	volatile caddr_t ba;
	u_char red[256], green[256], blue[256], *rp, *gp, *bp;
	short x;
	int error;

	ba = gfp->g_regkva;
	if (cmap->count == 0 || cmap->index >= 256)
		return (0);

	if (cmap->count > 256 - cmap->index)
		cmap->count = 256 - cmap->index;

	/* first read colors out of the chip, then copyout to userspace */
	vgawio(cv3d_boardaddr, VDAC_ADDRESS_W, cmap->index);
	x = cmap->count - 1;

	rp = red + cmap->index;
	gp = green + cmap->index;
	bp = blue + cmap->index;

	do {
		*rp++ = vgario(cv3d_special_register_base, VDAC_DATA) << 2;
		*gp++ = vgario(cv3d_special_register_base, VDAC_DATA) << 2;
		*bp++ = vgario(cv3d_special_register_base, VDAC_DATA) << 2;
	} while (x-- > 0);

	if (!(error = copyout (red + cmap->index, cmap->red, cmap->count))
	    && !(error = copyout (green + cmap->index, cmap->green, cmap->count))
	    && !(error = copyout (blue + cmap->index, cmap->blue, cmap->count)))
		return (0);

	return (error);
}


int
cv3d_putcmap(struct grf_softc *gfp, struct grf_colormap *cmap)
{
	volatile caddr_t ba;
	u_char red[256], green[256], blue[256], *rp, *gp, *bp;
	short x;
	int error;

	ba = gfp->g_regkva;
	if (cmap->count == 0 || cmap->index >= 256)
		return (0);

	if (cmap->index + cmap->count > 256)
		cmap->count = 256 - cmap->index;

	/* first copy the colors into kernelspace */
	if (!(error = copyin (cmap->red, red + cmap->index, cmap->count))
	    && !(error = copyin (cmap->green, green + cmap->index, cmap->count))
	    && !(error = copyin (cmap->blue, blue + cmap->index, cmap->count))) {
		vgawio(cv3d_boardaddr, VDAC_ADDRESS_W, cmap->index);
		x = cmap->count - 1;

		rp = red + cmap->index;
		gp = green + cmap->index;
		bp = blue + cmap->index;

		do {
			vgawio(cv3d_boardaddr, VDAC_DATA, *rp++ >> 2);
			vgawio(cv3d_boardaddr, VDAC_DATA, *gp++ >> 2);
			vgawio(cv3d_boardaddr, VDAC_DATA, *bp++ >> 2);
		} while (x-- > 0);
		return (0);
	} else
		return (error);
}


int
cv3d_toggle(struct grf_softc *gp)
{
	volatile caddr_t ba;

	ba = gp->g_regkva;
#ifndef CV3DCONSOLE
	cv3d_pass_toggle = 1;
#endif /* !CV3DCONSOLE */

	if (cv3d_pass_toggle) {
		cv3dscreen(0, cv3d_vcode_switch_base);
		cv3d_pass_toggle = 0;
	} else {
		cv3dscreen(1, cv3d_vcode_switch_base);
		cv3d_pass_toggle = 1;
	}

	return (0);
}


int
cv3d_mondefok(struct grfvideo_mode *gv)
{
	unsigned long maxpix;

	if (gv->mode_num < 1 || gv->mode_num > monitor_def_max) {
		if (gv->mode_num != 255 || gv->depth != 4)
			return (0);
	}

	switch(gv->depth) {
	   case 4:
		maxpix = MAXPIXELCLOCK - 55000000;
		break;
	   case 8:
		maxpix = MAXPIXELCLOCK;
		break;
	   case 15:
	   case 16:
#ifdef	CV3D_AGGRESSIVE_TIMING
		maxpix = MAXPIXELCLOCK - 35000000;
#else
		maxpix = MAXPIXELCLOCK - 55000000;
#endif
		break;
	   case 24:
	   case 32:
#ifdef	CV3D_AGGRESSIVE_TIMING
		maxpix = MAXPIXELCLOCK - 75000000;
#else
		maxpix = MAXPIXELCLOCK - 85000000;
#endif
		break;
	   default:
		printf("grfcv3d: Illegal depth in mode %d\n",
			(int) gv->mode_num);
		return (0);
	}

	if (gv->pixel_clock > maxpix) {
		printf("grfcv3d: Pixelclock too high in mode %d\n",
			(int) gv->mode_num);
		return (0);
	}

	if (gv->mode_num == 255) { /* console mode */
		if ((gv->disp_width / 8) > MAXCOLS) {
			printf ("grfcv3d: Too many columns for console\n");
			return (0);
		} else if ((gv->disp_height / S3FONTY) > MAXROWS) {
			printf ("grfcv3d: Too many rows for console\n");
			return (0);
		}
	}

	if (gv->disp_flags & GRF_FLAGS_SYNC_ON_GREEN) {
		printf("grfcv3d: sync-on-green is not supported\n");
		return (0);
	}

	return (1);
}


int
cv3d_load_mon(struct grf_softc *gp, struct grfcv3dtext_mode *md)
{
	struct grfvideo_mode *gv;
	struct grfinfo *gi;
	volatile caddr_t ba, fb;
	unsigned short mnr;
	unsigned short HT, HDE, HBS, HBE, HSS, HSE, VDE, VBS, VBE, VSS,
		VSE, VT;
	int cr50, cr66, sr15, sr18, clock_mode, test;
	int hmul;	/* Multiplier for hor. Values */
	int fb_flag = 2;	/* default value for 8bit memory access */
	unsigned char hvsync_pulse;
	char TEXT, CONSOLE;

	/* identity */
	gv = &md->gv;

	TEXT = (gv->depth == 4);
	CONSOLE = (gv->mode_num == 255);

	if (!cv3d_mondefok(gv)) {
		printf("grfcv3d: Monitor definition not ok\n");
		return (0);
	}

	ba = gp->g_regkva;
	fb = gp->g_fbkva;

	/* turn gfx off, don't mess up the display */
	cv3d_gfx_on_off(1, ba);

	/* provide all needed information in grf device-independant locations */
	gp->g_data		= (caddr_t) gv;
	gi = &gp->g_display;
	gi->gd_colors		= 1 << gv->depth;
	gi->gd_planes		= gv->depth;
	gi->gd_fbwidth		= gv->disp_width;
	gi->gd_fbheight		= gv->disp_height;
	gi->gd_fbx		= 0;
	gi->gd_fby		= 0;
	if (CONSOLE) {
		gi->gd_dwidth	= md->fx * md->cols;
		gi->gd_dheight	= md->fy * md->rows;
	} else {
		gi->gd_dwidth	= gv->disp_width;
		gi->gd_dheight	= gv->disp_height;
	}
	gi->gd_dx		= 0;
	gi->gd_dy		= 0;

	/* get display mode parameters */
	switch (gv->depth) {
	    case 15:
	    case 16:
		hmul = 2;
		break;
	    default:
		hmul = 1;
		break;
	}

	HBS = gv->hblank_start * hmul;
	HSS = gv->hsync_start * hmul;
	HSE = gv->hsync_stop * hmul;
	HBE = gv->htotal * hmul - 6;
	HT  = gv->htotal * hmul - 5;
	VBS = gv->vblank_start - 1;
	VSS = gv->vsync_start;
	VSE = gv->vsync_stop;
	VBE = gv->vtotal - 3;
	VT  = gv->vtotal - 2;

	/*
	 * Disable enhanced Mode for text display
	 *
	 * XXX You need to set this bit in CRT_ID_EXT_MISC_CNTL_1
	 * _and_ MR_ADVANCED_FUNCTION_CONTROL, because the same
	 * function exists in both registers.
	 */
	cr66 = RCrt(ba, CRT_ID_EXT_MISC_CNTL_1);
	if (TEXT) {
		cr66 &= ~0x01;
		vgaw32(cv3d_memory_io_base, MR_ADVANCED_FUNCTION_CONTROL,
			0x00000010);
	} else {
		cr66 |= 0x01;
		vgaw32(cv3d_memory_io_base, MR_ADVANCED_FUNCTION_CONTROL,
			0x00000011);
	}
	WCrt(ba, CRT_ID_EXT_MISC_CNTL_1, cr66);

	if (TEXT)
		HDE = ((gv->disp_width + md->fx - 1) / md->fx) - 1;
	else
		HDE = (gv->disp_width + 3) * hmul / 8 - 1; /*HBS;*/
	VDE = gv->disp_height - 1;

	/* adjustments */

	if (gv->disp_flags & GRF_FLAGS_LACE) {
		VDE = VDE / 2;
		VBS = VBS / 2;
		VSS = VSS / 2;
		VSE = VSE / 2;
		VBE = VBE / 2;
		VT  = VT / 2;
	}

	/* Horizontal/Vertical Sync Pulse */
	/*
	 * GREG_MISC_OUTPUT_W Register:
	 * bit	description (0/1)
	 *  0	Monochrome/Color emulation
	 *  1	Disable/Enable access of the display memory from the CPU
	 *  5	Select the low/high 64K page of memory
	 *  6	Select a positive/negative horizontal retrace sync pulse
	 *  7	Select a positive/negative vertical retrace sync pulse
	 */
	hvsync_pulse = vgar(ba, GREG_MISC_OUTPUT_R);
	if (gv->disp_flags & GRF_FLAGS_PHSYNC)
		hvsync_pulse &= ~0x40;
	else
		hvsync_pulse |= 0x40;
	if (gv->disp_flags & GRF_FLAGS_PVSYNC)
		hvsync_pulse &= ~0x80;
	else
		hvsync_pulse |= 0x80;
	vgaw(ba, GREG_MISC_OUTPUT_W, hvsync_pulse);

	/* GFX hardware cursor off */
	WCrt(ba, CRT_ID_HWGC_MODE, 0x00);
	WCrt(ba, CRT_ID_EXT_DAC_CNTL, 0x00);

	WSeq(ba, SEQ_ID_MEMORY_MODE, (TEXT || (gv->depth == 1)) ? 0x06 : 0x0e);
	WGfx(ba, GCT_ID_READ_MAP_SELECT, 0x00);
	WSeq(ba, SEQ_ID_MAP_MASK, (gv->depth == 1) ? 0x01 : 0xff);
	WSeq(ba, SEQ_ID_CHAR_MAP_SELECT, 0x00);

	/* Set clock */

	mnr = cv3d_compute_clock(gv->pixel_clock);
	WSeq(ba, SEQ_ID_DCLK_HI, ((mnr & 0xFF00) >> 8));
	WSeq(ba, SEQ_ID_DCLK_LO, (mnr & 0xFF));

	/* load display parameters into board */

	WCrt(ba, CRT_ID_EXT_HOR_OVF,
	   ((HT & 0x100) ? 0x01 : 0x00) |
	   ((HDE & 0x100) ? 0x02 : 0x00) |
	   ((HBS & 0x100) ? 0x04 : 0x00) |
	/* ((HBE & 0x40) ? 0x08 : 0x00) | */  /* Later... */
	   ((HSS & 0x100) ? 0x10 : 0x00) |
	/* ((HSE & 0x20) ? 0x20 : 0x00) | */
	   (((HT-5) & 0x100) ? 0x40 : 0x00) );

	WCrt(ba, CRT_ID_EXT_VER_OVF,
	    0x40 |	/* Line compare */
	    ((VT  & 0x400) ? 0x01 : 0x00) |
	    ((VDE & 0x400) ? 0x02 : 0x00) |
	    ((VBS & 0x400) ? 0x04 : 0x00) |
	    ((VSS & 0x400) ? 0x10 : 0x00) );

	WCrt(ba, CRT_ID_HOR_TOTAL, HT);
	WCrt(ba, CRT_ID_DISPLAY_FIFO, HT - 5);

	WCrt(ba, CRT_ID_HOR_DISP_ENA_END, ((HDE >= HBS) ? (HBS - 1) : HDE));
	WCrt(ba, CRT_ID_START_HOR_BLANK, HBS);
	WCrt(ba, CRT_ID_END_HOR_BLANK, ((HBE & 0x1f) | 0x80));
	WCrt(ba, CRT_ID_START_HOR_RETR, HSS);
	WCrt(ba, CRT_ID_END_HOR_RETR,
	    (HSE & 0x1f) |
	    ((HBE & 0x20) ? 0x80 : 0x00) );
	WCrt(ba, CRT_ID_VER_TOTAL, VT);
	WCrt(ba, CRT_ID_OVERFLOW,
	    0x10 |
	    ((VT  & 0x100) ? 0x01 : 0x00) |
	    ((VDE & 0x100) ? 0x02 : 0x00) |
	    ((VSS & 0x100) ? 0x04 : 0x00) |
	    ((VBS & 0x100) ? 0x08 : 0x00) |
	    ((VT  & 0x200) ? 0x20 : 0x00) |
	    ((VDE & 0x200) ? 0x40 : 0x00) |
	    ((VSS & 0x200) ? 0x80 : 0x00) );

	WCrt(ba, CRT_ID_MAX_SCAN_LINE,
	    0x40 |  /* TEXT ? 0x00 ??? */
	    ((gv->disp_flags & GRF_FLAGS_DBLSCAN) ? 0x80 : 0x00) |
	    ((VBS & 0x200) ? 0x20 : 0x00) |
	    (TEXT ? ((md->fy - 1) & 0x1f) : 0x00));

	WCrt(ba, CRT_ID_MODE_CONTROL, 0xE3);

	/* text cursor */

	if (TEXT) {
#if CV3D_ULCURSOR
		WCrt(ba, CRT_ID_CURSOR_START, (md->fy & 0x1f) - 2);
		WCrt(ba, CRT_ID_CURSOR_END, (md->fy & 0x1f) - 1);
#else
		WCrt(ba, CRT_ID_CURSOR_START, 0x00);
		WCrt(ba, CRT_ID_CURSOR_END, md->fy & 0x1f);
#endif
		WCrt(ba, CRT_ID_UNDERLINE_LOC, (md->fy - 1) & 0x1f);

		WCrt(ba, CRT_ID_CURSOR_LOC_HIGH, 0x00);
		WCrt(ba, CRT_ID_CURSOR_LOC_LOW, 0x00);
	}

	WCrt(ba, CRT_ID_START_ADDR_HIGH, 0x00);
	WCrt(ba, CRT_ID_START_ADDR_LOW, 0x00);

	WCrt(ba, CRT_ID_START_VER_RETR, VSS);
	WCrt(ba, CRT_ID_END_VER_RETR, (VSE & 0x0f));
	WCrt(ba, CRT_ID_VER_DISP_ENA_END, VDE);
	WCrt(ba, CRT_ID_START_VER_BLANK, VBS);
	WCrt(ba, CRT_ID_END_VER_BLANK, VBE);

	WCrt(ba, CRT_ID_LINE_COMPARE, 0xff);
	WCrt(ba, CRT_ID_LACE_RETR_START, HT / 2);
	WCrt(ba, CRT_ID_LACE_CONTROL,
	    ((gv->disp_flags & GRF_FLAGS_LACE) ? 0x20 : 0x00));

	WGfx(ba, GCT_ID_GRAPHICS_MODE,
	    ((TEXT || (gv->depth == 1)) ? 0x00 : 0x40));
	WGfx(ba, GCT_ID_MISC, (TEXT ? 0x04 : 0x01));

	WSeq (ba, SEQ_ID_MEMORY_MODE,
	    ((TEXT || (gv->depth == 1)) ? 0x06 : 0x02));

	vgawio(cv3d_boardaddr, VDAC_MASK, 0xff);

	/* Blank border */
	test = RCrt(ba, CRT_ID_BACKWAD_COMP_2);
	WCrt(ba, CRT_ID_BACKWAD_COMP_2, (test | 0x20));

	sr15 = RSeq(ba, SEQ_ID_CLKSYN_CNTL_2);
	sr15 &= ~0x10;
	sr18 = RSeq(ba, SEQ_ID_RAMDAC_CNTL);
	sr18 &= ~0x80;
	clock_mode = 0x00;
	cr50 = 0x00;

	test = RCrt(ba, CRT_ID_EXT_MISC_CNTL_2);
	test &= 0xd;

	switch (gv->depth) {
	   case 1:
	   case 4: /* text */
		fb_flag = 2;
		HDE = gv->disp_width / 16;
		break;
	   case 8:
		fb_flag = 2;
		if (gv->pixel_clock > 80000000) {
			/*
			 * CR67 bit 1 is undocumented but needed to prevent
			 * a white line on the left side of the screen.
			 */
			clock_mode = 0x10 | 0x02;
			sr15 |= 0x10;
			sr18 |= 0x80;
		}
		HDE = gv->disp_width / 8;
		cr50 |= 0x00;
		break;
	   case 15:
		fb_flag = 1;
		clock_mode = 0x30;
		HDE = gv->disp_width / 4;
		cr50 |= 0x10;
		break;
	   case 16:
		fb_flag = 1;
		clock_mode = 0x50;
		HDE = gv->disp_width / 4;
		cr50 |= 0x10;
		break;
	   case 24: /* this is really 32 Bit on CV64/3D */
	   case 32:
		fb_flag = 0;
		clock_mode = 0xd0;
		HDE = (gv->disp_width / 2);
		cr50 |= 0x30;
		break;
	}

	if (cv3d_zorroIII) {
		gp->g_fbkva = (volatile caddr_t)cv3d_boardaddr + 0x04000000 +
				(0x00400000 * fb_flag);
	} else {
		/* XXX This is totaly untested */
		Select_Zorro2_FrameBuffer(fb_flag);
	}

	WCrt(ba, CRT_ID_EXT_MISC_CNTL_2, clock_mode | test);
	WSeq(ba, SEQ_ID_CLKSYN_CNTL_2, sr15);
	WSeq(ba, SEQ_ID_RAMDAC_CNTL, sr18);
	WCrt(ba, CRT_ID_SCREEN_OFFSET, HDE);

	WCrt(ba, CRT_ID_MISC_1, (TEXT ? 0x05 : 0x35));

	test = RCrt(ba, CRT_ID_EXT_SYS_CNTL_2);
	test &= ~0x30;
	/* HDE Overflow in bits 4-5 */
	test |= (HDE >> 4) & 0x30;
	WCrt(ba, CRT_ID_EXT_SYS_CNTL_2, test);

#if 0	/* XXX */
	/* Set up graphics engine */
	switch (gv->disp_width) {
	   case 1024:
		cr50 |= 0x00;
		break;
	   case 640:
		cr50 |= 0x40;
		break;
	   case 800:
		cr50 |= 0x80;
		break;
	   case 1280:
		cr50 |= 0xc0;
		break;
	   case 1152:
		cr50 |= 0x01;
		break;
	   case 1600:
		cr50 |= 0x81;
		break;
	   default: /* XXX The Xserver has to handle this */
		break;
	}

	WCrt(ba, CRT_ID_EXT_SYS_CNTL_1, cr50);
#endif

	delay(100000);
	WAttr(ba, ACT_ID_ATTR_MODE_CNTL, (TEXT ? 0x08 : 0x41));
	delay(100000);
	WAttr(ba, ACT_ID_COLOR_PLANE_ENA,
	    (gv->depth == 1) ? 0x01 : 0x0f);
	delay(100000);

	/* text initialization */

	if (TEXT) {
		cv3d_inittextmode(gp);
	}

	if (CONSOLE) {
		int i;
		vgawio(cv3d_boardaddr, VDAC_ADDRESS_W, 0);
		for (i = 0; i < 16; i++) {
			vgawio(cv3d_boardaddr, VDAC_DATA, cv3dconscolors[i][0]);
			vgawio(cv3d_boardaddr, VDAC_DATA, cv3dconscolors[i][1]);
			vgawio(cv3d_boardaddr, VDAC_DATA, cv3dconscolors[i][2]);
		}
	}

	/* Set display enable flag */
	WAttr(ba, 0x33, 0);

	/* turn gfx on again */
	cv3d_gfx_on_off(0, ba);

	/* Pass-through */
	cv3dscreen(0, cv3d_vcode_switch_base);

	return (1);
}


void
cv3d_inittextmode(struct grf_softc *gp)
{
	struct grfcv3dtext_mode *tm = (struct grfcv3dtext_mode *)gp->g_data;
	volatile caddr_t ba, fb;
	unsigned char *c, *f, y;
	unsigned short z;

	ba = gp->g_regkva;
	fb = gp->g_fbkva;

	/* load text font into beginning of display memory.
	 * Each character cell is 32 bytes long (enough for 4 planes)
	 * In linear adressing text mode, the memory is organized
	 * so, that the Bytes of all 4 planes are interleaved.
	 * 1st byte plane 0, 1st byte plane 1, 1st byte plane 2,
	 * 1st byte plane 3, 2nd byte plane 0, 2nd byte plane 1,...
	 * The font is loaded in plane 2.
	 */

	c = (unsigned char *) fb;

	/* clear screen */
	for (z = 0; z < tm->cols * tm->rows * 3; z++) {
		*c++ = 0x20;
		*c++ = 0x07;
		*c++ = 0;
		*c++ = 0;
	}

	c = (unsigned char *) (fb) + (32 * tm->fdstart * 4 + 2);
	f = tm->fdata;
	for (z = tm->fdstart; z <= tm->fdend; z++, c += (32 - tm->fy) * 4)
		for (y = 0; y < tm->fy; y++) {
			*c = *f++;
			c += 4;
		}

	/* print out a little init msg */
	c = (unsigned char *)(fb) + (tm->cols - 9) * 4;
	*c++ = 'C';
	*c++ = 0x0c;
	c +=2;
	*c++ = 'V';
	*c++ = 0x0c;
	c +=2;
	*c++ = '6';
	*c++ = 0x0b;
	c +=2;
	*c++ = '4';
	*c++ = 0x0f;
	c +=2;
	*c++ = '/';
	*c++ = 0x0e;
	c +=2;
	*c++ = '3';
	*c++ = 0x0a;
	c +=2;
	*c++ = 'D';
	*c++ = 0x0a;
}

/*
 *  Monitor Switch
 *  0 = CyberVision Signal
 *  1 = Amiga Signal,
 * ba = boardaddr
 */
static __inline void
cv3dscreen(int toggle, volatile caddr_t ba)
{
	*((short *)(ba)) = (toggle & 1);
}


/* 0 = on, 1= off */
/* ba= registerbase */
static __inline void
cv3d_gfx_on_off(int toggle, volatile caddr_t ba)
{
	int r;

	toggle &= 0x1;
	toggle = toggle << 5;

	r = RSeq(ba, SEQ_ID_CLOCKING_MODE);
	r &= ~0x20;	/* set Bit 5 to 0 */

	WSeq(ba, SEQ_ID_CLOCKING_MODE, r | toggle);
}


#ifdef CV3D_HARDWARE_CURSOR

static unsigned char cv3d_hotx = 0, cv3d_hoty = 0;
static char cv_cursor_on = 0;

#define HWC_OFF (cv3d_fbsize - 1024*2)
#define HWC_SIZE 1024

/* Hardware Cursor handling routines */

int
cv3d_getspritepos(struct grf_softc *gp, struct grf_position *pos)
{
	int hi,lo;
	volatile caddr_t ba = gp->g_regkva;

	hi = RCrt(ba, CRT_ID_HWGC_ORIGIN_Y_HI);
	lo = RCrt(ba, CRT_ID_HWGC_ORIGIN_Y_LO);

	pos->y = (hi << 8) + lo;
	hi = RCrt(ba, CRT_ID_HWGC_ORIGIN_X_HI);
	lo = RCrt(ba, CRT_ID_HWGC_ORIGIN_X_LO);
	pos->x = (hi << 8) + lo;
	return (0);
}


int
cv3d_setspritepos(struct grf_softc *gp, struct grf_position *pos)
{
	volatile caddr_t ba = gp->g_regkva;
	short x, y;
	static short savex, savey;
	short xoff, yoff;

	if (pos) {
		x = pos->x;
		y = pos->y;
		savex = x;
		savey= y;
	} else { /* restore cursor */
		x = savex;
		y = savey;
	}
	x -= cv3d_hotx;
	y -= cv3d_hoty;
	if (x < 0) {
		xoff = ((-x) & 0xFE);
		x = 0;
	} else {
		xoff = 0;
	}

	if (y < 0) {
		yoff = ((-y) & 0xFE);
		y = 0;
	} else {
		yoff = 0;
	}

	WCrt(ba, CRT_ID_HWGC_ORIGIN_X_HI, (x >> 8));
	WCrt(ba, CRT_ID_HWGC_ORIGIN_X_LO, (x & 0xff));

	WCrt(ba, CRT_ID_HWGC_ORIGIN_Y_LO, (y & 0xff));
	WCrt(ba, CRT_ID_HWGC_DSTART_X, xoff);
	WCrt(ba, CRT_ID_HWGC_DSTART_Y, yoff);
	WCrt(ba, CRT_ID_HWGC_ORIGIN_Y_HI, (y >> 8));

	return(0);
}

static __inline short
M2I(short val)
{
	return ( ((val & 0xff00) >> 8) | ((val & 0xff) << 8));
}

int
cv3d_getspriteinfo(struct grf_softc *gp, struct grf_spriteinfo *info)
{
	volatile caddr_t ba, fb;

	ba = gp->g_regkva;
	fb = gp->g_fbkva;

	if (info->set & GRFSPRSET_ENABLE)
		info->enable = RCrt(ba, CRT_ID_HWGC_MODE) & 0x01;

	if (info->set & GRFSPRSET_POS)
		cv3d_getspritepos (gp, &info->pos);

#if 0	/* XXX */
	if (info->set & GRFSPRSET_SHAPE) {
		u_char image[512], mask[512];
		volatile u_long *hwp;
		u_char *imp, *mp;
		short row;
		info->size.x = 64;
		info->size.y = 64;
		for (row = 0, hwp = (u_long *)(fb + HWC_OFF),
		    mp = mask, imp = image;
		    row < 64;
		    row++) {
			u_long bp10, bp20, bp11, bp21;
			bp10 = *hwp++;
			bp20 = *hwp++;
			bp11 = *hwp++;
			bp21 = *hwp++;
			M2I (bp10);
			M2I (bp20);
			M2I (bp11);
			M2I (bp21);
			*imp++ = (~bp10) & bp11;
			*imp++ = (~bp20) & bp21;
			*mp++  = (~bp10) | (bp10 & ~bp11);
			*mp++  = (~bp20) & (bp20 & ~bp21);
		}
		copyout (image, info->image, sizeof (image));
		copyout (mask, info->mask, sizeof (mask));
	}
#endif
	return(0);
}


void
cv3d_setup_hwc(struct grf_softc *gp)
{
	volatile caddr_t ba = gp->g_regkva;
	volatile caddr_t hwc;
	int test;

	if (gp->g_display.gd_planes <= 4)
		cv3d_cursor_on = 0;	/* don't enable hwc in text modes */
	if (cv3d_cursor_on == 0)
		return;

	/* reset colour stack */
#if 0
	test = RCrt(ba, CRT_ID_HWGC_MODE);
	asm volatile("nop");
#else
	/* do it in assembler, the above does't seem to work */
	asm volatile ("moveb #0x45, %1@(0x3d4); \
		moveb %1@(0x3d5),%0" : "=r" (test) : "a" (ba));
#endif

	WCrt (ba, CRT_ID_HWGC_FG_STACK, 0);

	hwc = ba + CRT_ADDRESS_W;
	*hwc = 0;
	*hwc = 0;

#if 0
	test = RCrt(ba, CRT_ID_HWGC_MODE);
	asm volatile("nop");
#else
	/* do it in assembler, the above does't seem to work */
	asm volatile ("moveb #0x45, %1@(0x3d4); \
		moveb %1@(0x3d5),%0" : "=r" (test) : "a" (ba));
#endif
	switch (gp->g_display.gd_planes) {
	    case 8:
		WCrt (ba, CRT_ID_HWGC_BG_STACK, 0x1);
		*hwc = 1;
		break;
	    default:
		WCrt (ba, CRT_ID_HWGC_BG_STACK, 0xff);
		*hwc = 0xff;
		*hwc = 0xff;
	}

	test = HWC_OFF / HWC_SIZE;
	WCrt (ba, CRT_ID_HWGC_START_AD_HI, (test >> 8));
	WCrt (ba, CRT_ID_HWGC_START_AD_LO, (test & 0xff));

	WCrt (ba, CRT_ID_HWGC_DSTART_X , 0);
	WCrt (ba, CRT_ID_HWGC_DSTART_Y , 0);

	WCrt (ba, CRT_ID_EXT_DAC_CNTL, 0x10);	/* Cursor X11 Mode */
	/*
	 * Put it into Windoze Mode or you'll see sometimes a white stripe
	 * on the right side (in double clocking modes with a screen bigger
	 * > 1023 pixels).
	 */
	WCrt (ba, CRT_ID_EXT_DAC_CNTL, 0x00);	/* Cursor Windoze Mode */

	WCrt (ba, CRT_ID_HWGC_MODE, 0x01);
}


/*
 * This was the reason why you shouldn't use the HWC in the Kernel:(
 * Obsoleted now by use of interrupts :-)
 */

#define VerticalRetraceWait(ba) \
{ \
	while (vgar(ba, GREG_INPUT_STATUS1_R) == 0x00) ; \
	while ((vgar(ba, GREG_INPUT_STATUS1_R) & 0x08) == 0x08) ; \
	while ((vgar(ba, GREG_INPUT_STATUS1_R) & 0x08) == 0x00) ; \
}


int
cv3d_setspriteinfo(struct grf_softc *gp, struct grf_spriteinfo *info)
{
	volatile caddr_t ba, fb;
	int depth = gp->g_display.gd_planes;

	ba = gp->g_regkva;
	fb = gp->g_fbkva;

	if (info->set & GRFSPRSET_SHAPE) {
		/*
		 * For an explanation of these weird actions here, see above
		 * when reading the shape.  We set the shape directly into
		 * the video memory, there's no reason to keep 1k on the
		 * kernel stack just as template
		 */
		u_char *image, *mask;
		volatile u_short *hwp;
		u_char *imp, *mp;
		unsigned short row;

		/* Cursor off */
		WCrt (ba, CRT_ID_HWGC_MODE, 0x00);

		/*
		 * The Trio64 crashes if the cursor data is written
		 * while the cursor is displayed.
		 * Sadly, turning the cursor off is not enough.
		 * What we have to do is:
		 * 1. Wait for vertical retrace, to make sure no-one
		 * has moved the cursor in this sync period (because
		 * another write then would have no effect, argh!).
		 * 2. Move the cursor off-screen
		 * 3. Another wait for v. retrace to make sure the cursor
		 * is really off.
		 * 4. Write the data, finally.
		 * (thanks to Harald Koenig for this tip!)
		 */

		/*
		 * Remark 06/06/96: Update in interrupt obsoletes this,
		 * but the warning should stay there!
		 */

		VerticalRetraceWait(ba);

		WCrt (ba, CRT_ID_HWGC_ORIGIN_X_HI, 0x7);
		WCrt (ba, CRT_ID_HWGC_ORIGIN_X_LO,  0xff);
		WCrt (ba, CRT_ID_HWGC_ORIGIN_Y_LO, 0xff);
		WCrt (ba, CRT_ID_HWGC_DSTART_X, 0x3f);
		WCrt (ba, CRT_ID_HWGC_DSTART_Y, 0x3f);
		WCrt (ba, CRT_ID_HWGC_ORIGIN_Y_HI, 0x7);

		if (info->size.y > 64)
			info->size.y = 64;
		if (info->size.x > 64)
			info->size.x = 64;
		if (info->size.x < 32)
			info->size.x = 32;

		image = malloc(HWC_SIZE, M_TEMP, M_WAITOK);
		mask  = image + HWC_SIZE/2;

		copyin(info->image, image, info->size.y * info->size.x / 8);
		copyin(info->mask, mask, info->size.y * info->size.x / 8);

		hwp = (u_short *)(fb  +HWC_OFF);

		/* This is necessary in order not to crash the board */
		VerticalRetraceWait(ba);

		/*
		 * setting it is slightly more difficult, because we can't
		 * force the application to not pass a *smaller* than
		 * supported bitmap
		 */

		for (row = 0, mp = mask, imp = image;
		    row < info->size.y; row++) {
			u_short im1, im2, im3, im4, m1, m2, m3, m4;

			m1  = ~(*(unsigned short *)mp);
			im1 = *(unsigned short *)imp & *(unsigned short *)mp;
			mp  += 2;
			imp += 2;

			m2  = ~(*(unsigned short *)mp);
			im2 = *(unsigned short *)imp & *(unsigned short *)mp;
			mp  += 2;
			imp += 2;

			if (info->size.x > 32) {
				m3  = ~(*(unsigned short *)mp);
				im3 = *(unsigned short *)imp & *(unsigned short *)mp;
				mp  += 2;
				imp += 2;
				m4  = ~(*(unsigned short *)mp);
				im4 = *(unsigned short *)imp & *(unsigned short *)mp;
				mp  += 2;
				imp += 2;
			} else {
				m3  = 0xffff;
				im3 = 0;
				m4  = 0xffff;
				im4 = 0;
			}

			switch (depth) {
			    case 8:
				*hwp++ = m1;
				*hwp++ = im1;
				*hwp++ = m2;
				*hwp++ = im2;
				*hwp++ = m3;
				*hwp++ = im3;
				*hwp++ = m4;
				*hwp++ = im4;
				break;
			    case 15:
			    case 16:
				*hwp++ = M2I(m1);
				*hwp++ = M2I(im1);
				*hwp++ = M2I(m2);
				*hwp++ = M2I(im2);
				*hwp++ = M2I(m3);
				*hwp++ = M2I(im3);
				*hwp++ = M2I(m4);
				*hwp++ = M2I(im4);
				break;
			    case 24:
			    case 32:
				*hwp++ = M2I(im1);
				*hwp++ = M2I(m1);
				*hwp++ = M2I(im2);
				*hwp++ = M2I(m2);
				*hwp++ = M2I(im3);
				*hwp++ = M2I(m3);
				*hwp++ = M2I(im4);
				*hwp++ = M2I(m4);
				break;
			}
		}

		if (depth < 24) {
			for (; row < 64; row++) {
				*hwp++ = 0xffff;
				*hwp++ = 0x0000;
				*hwp++ = 0xffff;
				*hwp++ = 0x0000;
				*hwp++ = 0xffff;
				*hwp++ = 0x0000;
				*hwp++ = 0xffff;
				*hwp++ = 0x0000;
			}
		} else {
			for (; row < 64; row++) {
				*hwp++ = 0x0000;
				*hwp++ = 0xffff;
				*hwp++ = 0x0000;
				*hwp++ = 0xffff;
				*hwp++ = 0x0000;
				*hwp++ = 0xffff;
				*hwp++ = 0x0000;
				*hwp++ = 0xffff;
			}
		}

		free(image, M_TEMP);
		/* cv3d_setup_hwc(gp); */
		cv3d_hotx = info->hot.x;
		cv3d_hoty = info->hot.y;

		/* One must not write twice per vertical blank :-( */
		VerticalRetraceWait(ba);
		cv3d_setspritepos(gp, &info->pos);
	}
	if (info->set & GRFSPRSET_CMAP) {
		volatile caddr_t hwc;
		int test;

		/* reset colour stack */
		test = RCrt(ba, CRT_ID_HWGC_MODE);
		asm volatile("nop");
		switch (depth) {
		    case 8:
		    case 15:
		    case 16:
			WCrt (ba, CRT_ID_HWGC_FG_STACK, 0);
			hwc = ba + CRT_ADDRESS_W;
			*hwc = 0;
			break;
		    case 32:
		    case 24:
			WCrt (ba, CRT_ID_HWGC_FG_STACK, 0);
			hwc = ba + CRT_ADDRESS_W;
			*hwc = 0;
			*hwc = 0;
			break;
		}

		test = RCrt(ba, CRT_ID_HWGC_MODE);
		asm volatile("nop");
		switch (depth) {
		    case 8:
			WCrt (ba, CRT_ID_HWGC_BG_STACK, 1);
			hwc = ba + CRT_ADDRESS_W;
			*hwc = 1;
			break;
		    case 15:
		    case 16:
			WCrt (ba, CRT_ID_HWGC_BG_STACK, 0xff);
			hwc = ba + CRT_ADDRESS_W;
			*hwc = 0xff;
			break;
		    case 32:
		    case 24:
			WCrt (ba, CRT_ID_HWGC_BG_STACK, 0xff);
			hwc = ba + CRT_ADDRESS_W;
			*hwc = 0xff;
			*hwc = 0xff;
			break;
		}
	}

	if (info->set & GRFSPRSET_ENABLE) {
		if (info->enable) {
			cv3d_cursor_on = 1;
			cv3d_setup_hwc(gp);
			/* WCrt(ba, CRT_ID_HWGC_MODE, 0x01); */
		} else
			WCrt(ba, CRT_ID_HWGC_MODE, 0x00);
	}
	if (info->set & GRFSPRSET_POS)
		cv3d_setspritepos(gp, &info->pos);
	if (info->set & GRFSPRSET_HOT) {

		cv3d_hotx = info->hot.x;
		cv3d_hoty = info->hot.y;
		cv3d_setspritepos (gp, &info->pos);
	}
	return(0);
}


int
cv3d_getspritemax(struct grf_softc *gp, struct grf_position *pos)
{

	pos->x = 64;
	pos->y = 64;
	return(0);
}

#endif /* CV3D_HARDWARE_CURSOR */

#endif  /* NGRFCV3D */
