/*	$NetBSD: sa11x0_gpioreg.h,v 1.4 2001/03/11 06:00:42 ichiro Exp $	*/

/*-
 * Copyright (c) 2001 The NetBSD Foundation, Inc.  All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Ichiro FUKUHARA.
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
 * SA-11x0 GPIO Register 
 */

#define SAGPIO_NPORTS	8

/* GPIO pin-level register */
#define SAGPIO_PLR	0x00

/* GPIO pin direction register */
#define SAGPIO_PDR	0x04

/* GPIO pin output set register */
#define SAGPIO_PSR	0x08

/* GPIO pin output clear register */
#define SAGPIO_PCR	0x0C

/* GPIO rising-edge detect register */
#define SAGPIO_RER	0x10

/* GPIO falling-edge detect register */
#define SAGPIO_FER	0x14

/* GPIO edge-detect status register */
#define SAGPIO_EDR	0x18

/* GPIO alternate function register */
#define SAGPIO_AFR	0x1C

/* XXX */
#define GPIO(x)		(0x00000001 << (x))

/*
 * iPAQ H3600 specific parameter
 */
/*
port	I/O(Active)	desc
0	I(L)	button detect: power-on
1	I(L)	cpu-interrupt
2...9	O	LCD DATA(8-15)
10	I(L)	PCMCIA Socket1 inserted detection
11	I(L)	PCMCIA slot1 IRQ
12	O	clock select 0 for audio codec
13	O	clock select 1 for audio codec
14	I/O	UDA1341 L3DATA
15	O	UDA1341 L3MODE
16	O	UDA1341 L3SCLK
17	I(L)	PCMCIA Socket0 inserted detection
18	I(L)	button detect: center button
19	I	Stereo audio codev external clock
20	I(H)	Battery fault
21	I(L)	PCMCIA slot0 IRQ	
22	I(L)	expansion pack lock/unlock signal
23	I(H)	RS-232 DCD
24	I(H)	expansion pach shared IRQ
25	I(H)	RS-232 CTS
26	O(H)	RS-232 RTS
27	O(L)	Indicates presence of expansion pack inserted
 */

#define GPIO_H3600_POWER_BUTTON	GPIO (0)
#define GPIO_H3600_PCMCIA_CD0	GPIO (17)
#define GPIO_H3600_PCMCIA_CD1	GPIO (10)
#define GPIO_H3600_PCMCIA_IRQ0	GPIO (21)
#define GPIO_H3600_PCMCIA_IRQ1	GPIO (11)
#define GPIO_H3600_OPT_LOCK	GPIO (22)
#define GPIO_H3600_OPT_IRQ	GPIO (24)
#define GPIO_H3600_OPT_DETECT	GPIO (27)

#define IRQ_H3600_POWER_BUTTON	IRQ_GPIO0
#define IRQ_H3600_PCMCIA_CD0	IRQ_GPIO17
#define IRQ_H3600_PCMCIA_CD1	IRQ_GPIO10
#define IRQ_H3600_PCMCIA_IRQ0	IRQ_GPIO21
#define IRQ_H3600_PCMCIA_IRQ1	IRQ_GPIO11
#define IRQ_H3600_OPT_IRQ	IRQ_GPIO24
#define IRQ_H3600_OPT_DETECT	IRQ_GPIO27

/*
 * JORNADA720 specific parameter
 */

#define JORNADA720_KBD_IRQ	GPIO (0)
#define JORNADA720_MOUSE_IRQ	GPIO (9)

/* 
 * IRQ Number of GPIO(x)
 * GPIO(0..10)  -> IRQ(0..10)
 * GPIO(11..27) -> IRQ(32..48)
 */
#define IRQ_GPIO1(x)		(0 + x)
#define IRQ_GPIO2(x)		(32 * (x) - 11)

#define IRQ_GPIO0	IRQ_GPIO1(0)
#define IRQ_GPIO1	IRQ_GPIO1(1)
#define IRQ_GPIO2	IRQ_GPIO1(2)
#define IRQ_GPIO3	IRQ_GPIO1(3)
#define IRQ_GPIO4	IRQ_GPIO1(4)
#define IRQ_GPIO5	IRQ_GPIO1(5)
#define IRQ_GPIO6	IRQ_GPIO1(6)
#define IRQ_GPIO7	IRQ_GPIO1(7)
#define IRQ_GPIO8	IRQ_GPIO1(8)
#define IRQ_GPIO9	IRQ_GPIO1(9)
#define IRQ_GPIO10	IRQ_GPIO1(10)
#define IRQ_GPIO11	IRQ_GPIO2(11)
#define IRQ_GPIO12	IRQ_GPIO2(12)
#define IRQ_GPIO13	IRQ_GPIO2(13)
#define IRQ_GPIO14	IRQ_GPIO2(14)
#define IRQ_GPIO15	IRQ_GPIO2(15)
#define IRQ_GPIO16	IRQ_GPIO2(16)
#define IRQ_GPIO17	IRQ_GPIO2(17)
#define IRQ_GPIO18	IRQ_GPIO2(18)
#define IRQ_GPIO19	IRQ_GPIO2(19)
#define IRQ_GPIO20	IRQ_GPIO2(20)
#define IRQ_GPIO21	IRQ_GPIO2(21)
#define IRQ_GPIO22	IRQ_GPIO2(22)
#define IRQ_GPIO23	IRQ_GPIO2(23)
#define IRQ_GPIO24	IRQ_GPIO2(24)
#define IRQ_GPIO25	IRQ_GPIO2(25)
#define IRQ_GPIO26	IRQ_GPIO2(26)
#define IRQ_GPIO27	IRQ_GPIO2(27)

