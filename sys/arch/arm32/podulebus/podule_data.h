/*
 * THIS FILE AUTOMATICALLY GENERATED.  DO NOT EDIT.
 *
 * generated from:
 *	NetBSD: podules,v 1.2 1996/11/23 03:23:49 mark Exp 
 */

/*
 * Copyright (c) 1996 Mark Brinicombe
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
 *      This product includes software developed by Mark Brinicombe
 *	for the NetBSD Project.
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

static struct podule_description podules_acorn[] = {
	{ PODULE_ACORN_SCSI,	"SCSI 1 interface" },
	{ PODULE_ACORN_ETHER1,	"ether 1 interface" },
	{ PODULE_ACORN_RAMROM,	"RAM/ROM podule" },
	{ PODULE_ACORN_BBCIO,	"BBC IO interface" },
	{ PODULE_ACORN_MIDI,	"MIDI interface" },
	{ PODULE_ACORN_ETHER2,	"ether 2 interface" },
	{ 0x0000, NULL }
};

static struct podule_description podules_olivetti[] = {
	{ 0x0000, NULL }
};

static struct podule_description podules_watford[] = {
	{ 0x0000, NULL }
};

static struct podule_description podules_cconcepts[] = {
	{ PODULE_CCONCEPTS_LASERDIRECT,	"laser direct (Canon LBP-4)" },
	{ 0x0000, NULL }
};

static struct podule_description podules_armadillo[] = {
	{ PODULE_ARMADILLO_A448,	"A447 sound sampler" },
	{ 0x0000, NULL }
};

static struct podule_description podules_wildvision[] = {
	{ PODULE_WILDVISION_HAWKV9,	"hawk v9 mark2" },
	{ PODULE_WILDVISION_SCANLIGHTV256,	"scanlight video 256" },
	{ PODULE_WILDVISION_EAGLEM2,	"eagle M2" },
	{ PODULE_WILDVISION_LARKA16,	"lark A16" },
	{ PODULE_WILDVISION_MIDIMAX,	"MIDI max" },
	{ 0x0000, NULL }
};

static struct podule_description podules_atomwide[] = {
	{ PODULE_ATOMWIDE_ETHER3,	"ether 3/5 interface" },
	{ 0x0000, NULL }
};

static struct podule_description podules_lingenuity[] = {
	{ PODULE_LINGENUITY_SCSI,	"16 bit SCSI interface" },
	{ 0x0000, NULL }
};

static struct podule_description podules_irlam[] = {
	{ PODULE_IRLAM_24I16,	"24i16 digitiser" },
	{ 0x0000, NULL }
};

static struct podule_description podules_oak[] = {
	{ PODULE_OAK_SCSI,	"16 bit SCSI interface" },
	{ 0x0000, NULL }
};

static struct podule_description podules_morley[] = {
	{ PODULE_MORLEY_SCSI,	"SCSI interface" },
	{ 0x0000, NULL }
};

static struct podule_description podules_cumana[] = {
	{ PODULE_CUMANA_SCSI2,	"SCSI II interface" },
	{ PODULE_CUMANA_SCSI1,	"SCSI I interface" },
	{ PODULE_CUMANA_SLCD,	"CDFS & SLCD expansion card" },
	{ 0x0000, NULL }
};

static struct podule_description podules_ics[] = {
	{ PODULE_ICS_IDE,	"IDE Interface" },
	{ 0x0000, NULL }
};

static struct podule_description podules_arxe[] = {
	{ PODULE_ARXE_SCSI,	"16 bit SCSI interface" },
	{ 0x0000, NULL }
};

static struct podule_description podules_aleph1[] = {
	{ PODULE_ALEPH1_PCCARD,	"PC card" },
	{ 0x0000, NULL }
};

static struct podule_description podules_icubed[] = {
	{ PODULE_ICUBED_ETHERH,	"etherlan 600 network slot interface" },
	{ PODULE_ICUBED_ETHERHFLASH,	"etherlan 600 network slot interface" },
	{ 0x0000, NULL }
};

static struct podule_description podules_brini[] = {
	{ PODULE_BRINI_PORT,	"BriniPort intelligent I/O interface" },
	{ PODULE_BRINI_LINK,	"BriniLink transputer link adapter" },
	{ 0x0000, NULL }
};

static struct podule_description podules_ant[] = {
	{ PODULE_ANT_ETHER3,	"ether 3/5 interface" },
	{ PODULE_ANT_ETHERB,	"ether B network slot interface" },
	{ 0x0000, NULL }
};

static struct podule_description podules_alsystems[] = {
	{ PODULE_ALSYSTEMS_SCSI,	"SCSI II host adapter" },
	{ 0x0000, NULL }
};

static struct podule_description podules_mcs[] = {
	{ PODULE_MCS_SCSI,	"Connect32 SCSI II interface" },
	{ 0x0000, NULL }
};


struct podule_list known_podules[] = {
	{ MANUFACTURER_ACORN, 		"Acorn Computers", 	podules_acorn },
	{ MANUFACTURER_OLIVETTI, 	"Olivetti", 	podules_olivetti },
	{ MANUFACTURER_WATFORD, 	"Watford", 	podules_watford },
	{ MANUFACTURER_CCONCEPTS, 	"Computer Concepts", 	podules_cconcepts },
	{ MANUFACTURER_ARMADILLO, 	"Armadillo Systems", 	podules_armadillo },
	{ MANUFACTURER_WILDVISION, 	"Wild Vision", 	podules_wildvision },
	{ MANUFACTURER_ATOMWIDE, 	"Atomwide", 	podules_atomwide },
	{ MANUFACTURER_LINGENUITY, 	"Lingenuity", 	podules_lingenuity },
	{ MANUFACTURER_IRLAM, 		"Irlam Instruments", 	podules_irlam },
	{ MANUFACTURER_OAK, 		"Oak Solutions", 	podules_oak },
	{ MANUFACTURER_MORLEY, 		"Morley", 	podules_morley },
	{ MANUFACTURER_CUMANA, 		"Cumana", 	podules_cumana },
	{ MANUFACTURER_ICS, 		"ICS", 	podules_ics },
	{ MANUFACTURER_ARXE, 		"ARXE", 	podules_arxe },
	{ MANUFACTURER_ALEPH1, 		"Aleph 1", 	podules_aleph1 },
	{ MANUFACTURER_ICUBED, 		"I-Cubed", 	podules_icubed },
	{ MANUFACTURER_BRINI, 		"Brini", 	podules_brini },
	{ MANUFACTURER_ANT, 		"ANT", 	podules_ant },
	{ MANUFACTURER_ALSYSTEMS, 	"Alsystems", 	podules_alsystems },
	{ MANUFACTURER_MCS, 		"MCS", 	podules_mcs },
	{ 0, NULL, NULL }
};
