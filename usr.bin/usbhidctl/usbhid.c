/*	$NetBSD: usbhid.c,v 1.3 1998/07/13 20:56:28 augustss Exp $	*/

/*
 * Copyright (c) 1998 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * Author: Lennart Augustsson
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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <err.h>
#include <dev/usb/usb.h>
#include <dev/usb/usbhid.h>

#include "hidsubr.h"

#define HIDTABLE "/usr/share/misc/usb_hid_usages"

#define USBDEV "/dev/uhid0"

int verbose = 0;
int all = 0;
int noname = 0;

char **names;
int nnames;

void prbits(int bits, char **strs, int n);
void usage(void);
void dumpitems(u_char *buf, int len);
void rev(struct hid_item **p);
u_long getdata(u_char *buf, int hpos, int hsize, int sign);
void prdata(u_char *buf, struct hid_item *h);
void dumpdata(int f, u_char *buf, int len, int loop);
int gotname(char *n);

int
gotname(char *n)
{
	int i;

	for (i = 0; i < nnames; i++)
		if (strcmp(names[i], n) == 0)
			return 1;
	return 0;
}

void
prbits(int bits, char **strs, int n)
{
	int i;

	for(i = 0; i < n; i++, bits >>= 1)
		if (strs[i*2])
			printf("%s%s", i == 0 ? "" : ", ", strs[i*2 + (bits&1)]);
}

void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "Usage: %s [-a] -f device [-l] [-n] [-r] [-t tablefile] [-v] [name ...]\n", __progname);
	exit(1);
}

void
dumpitems(u_char *buf, int len)
{
	struct hid_data *d;
	struct hid_item h;

	for (d = hid_start_parse(buf, len, ~0); hid_get_item(d, &h); ) {
		switch (h.kind) {
		case hid_collection:
			printf("Collection page=%s usage=%s\n",
			       usage_page(HID_PAGE(h.usage)), 
			       usage_in_page(h.usage));
			break;
		case hid_endcollection:
			printf("End collection\n");
			break;
		case hid_input:
			printf("Input   size=%d count=%d page=%s usage=%s%s\n", 
			       h.report_size, h.report_count, 
			       usage_page(HID_PAGE(h.usage)), 
			       usage_in_page(h.usage),
			       h.flags & HIO_CONST ? " Const" : "");
			break;
		case hid_output:
			printf("Output  size=%d count=%d page=%s usage=%s%s\n", 
			       h.report_size, h.report_count,
			       usage_page(HID_PAGE(h.usage)), 
			       usage_in_page(h.usage),
			       h.flags & HIO_CONST ? " Const" : "");
			break;
		case hid_feature:
			printf("Feature size=%d count=%d page=%s usage=%s%s\n",
			       h.report_size, h.report_count,
			       usage_page(HID_PAGE(h.usage)),
			       usage_in_page(h.usage),
			       h.flags & HIO_CONST ? " Const" : "");
			break;
		}
	}
	hid_end_parse(d);
	printf("Total   input size %d bytes\n", 
	       hid_report_size(buf, len, hid_input));
	printf("Total  output size %d bytes\n", 
	       hid_report_size(buf, len, hid_output));
	printf("Total feature size %d bytes\n", 
	       hid_report_size(buf, len, hid_feature));
}

void
rev(struct hid_item **p)
{
	struct hid_item *cur, *prev, *next;

	prev = 0;
	cur = *p;
	while(cur != 0) {
		next = cur->next;
		cur->next = prev;
		prev = cur;
		cur = next;
	}
	*p = prev;
}

u_long
getdata(u_char *buf, int hpos, int hsize, int sign)
{
	u_long data;
	int i, size, s;

	data = 0;
	s = hpos/8; 
	for (i = hpos; i < hpos+hsize; i += 8)
		data |= buf[i / 8] << ((i/8-s) * 8);
	data >>= (hpos % 8);
	data &= (1 << hsize) - 1;
	size = 32 - hsize;
	if (sign)
		/* Need to sign extend */
		data = ((long)data << size) >> size;
	return data;
}

void
prdata(u_char *buf, struct hid_item *h)
{
	u_long data;
	int i, pos;

	pos = h->pos;
	for (i = 0; i < h->report_count; i++) {
		data = getdata(buf, pos, h->report_size, 
			       h->logical_minimum < 0);
		if (h->logical_minimum < 0)
			printf("%ld", (long)data);
		else
			printf("%lu", data);
		pos += h->report_size;
	}
}

void
dumpdata(int f, u_char *buf, int len, int loop)
{
	struct hid_data *d;
	struct hid_item h, *hids, *n;
	int r, dlen;
	u_char *dbuf;
	static int one = 1;
	u_int32_t colls[100];
	int sp = 0;
	char namebuf[10000], *namep;

	hids = 0;
	for (d = hid_start_parse(buf, len, 1<<hid_input); 
	     hid_get_item(d, &h); ) {
		if (h.kind == hid_collection)
			colls[++sp] = h.usage;
		else if (h.kind == hid_endcollection)
			--sp;
		if (h.kind != hid_input || (h.flags & HIO_CONST))
			continue;
		h.next = hids;
		h.collection = colls[sp];
		hids = malloc(sizeof *hids);
		*hids = h;
	}
	hid_end_parse(d);
	rev(&hids);
	dlen = hid_report_size(buf, len, hid_input);
	dbuf = malloc(dlen);
	if (!loop)
		if (ioctl(f, USB_SET_IMMED, &one) < 0)
			err(1, "USB_SET_IMMED");
	do {
		r = read(f, dbuf, dlen);
		if (r != dlen) {
			err(1, "bad read %d != %d", r, dlen);
		}
		for (n = hids; n; n = n->next) {
			namep = namebuf;
			namep += sprintf(namep, "%s:%s.",
					 usage_page(HID_PAGE(n->collection)),
					 usage_in_page(n->collection));
			namep += sprintf(namep, "%s:%s",
					 usage_page(HID_PAGE(n->usage)),
					 usage_in_page(n->usage));
			if (all || gotname(namebuf)) {
				if (!noname)
					printf("%s=", namebuf);
				prdata(dbuf, n);
				if (verbose)
					printf(" [%d - %d]", 
					       n->logical_minimum, 
					       n->logical_maximum);
				printf("\n");
			}
		}
		if (loop)
			printf("\n");
	} while (loop);
	free(dbuf);
}

int
main(int argc, char **argv)
{
	int f, r;
	char *dev = 0;
	int ch;
	extern char *optarg;
	extern int optind;
	struct usb_ctl_report_desc rep;
	int repdump = 0;
	int loop = 0;
	char *table = HIDTABLE;

	while ((ch = getopt(argc, argv, "af:lnrt:v")) != -1) {
		switch(ch) {
		case 'a':
			all++;
			break;
		case 'f':
			dev = optarg;
			break;
		case 'l':
			loop ^= 1;
			break;
		case 'n':
			noname++;
			break;
		case 'r':
			repdump++;
			break;
		case 't':
			table = optarg;
			break;
		case 'v':
			verbose++;
			break;
		case '?':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (dev == 0)
		usage();
	names = argv;
	nnames = argc;

	init_hid(table);

	f = open(dev, O_RDWR);
	if (f < 0)
		err(1, "%s", dev);

	rep.size = 0;
	r = ioctl(f, USB_GET_REPORT_DESC, &rep);
	if (r) 
		errx(1, "USB_GET_REPORT_DESC");
	       
	if (repdump) {
		printf("Report descriptor\n");
		dumpitems(rep.data, rep.size);
	}
	dumpdata(f, rep.data, rep.size, loop);

	exit(0);
}
