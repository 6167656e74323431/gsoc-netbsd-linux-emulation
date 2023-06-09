/*	$NetBSD: dmesg.c,v 1.51 2022/08/06 10:22:22 rin Exp $	*/
/*-
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
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
 */

#include <sys/cdefs.h>
#ifndef lint
__COPYRIGHT("@(#) Copyright (c) 1991, 1993\
 The Regents of the University of California.  All rights reserved.");
#endif /* not lint */

#ifndef lint
#if 0
static char sccsid[] = "@(#)dmesg.c	8.1 (Berkeley) 6/5/93";
#else
__RCSID("$NetBSD: dmesg.c,v 1.51 2022/08/06 10:22:22 rin Exp $");
#endif
#endif /* not lint */

#include <sys/param.h>
#include <sys/msgbuf.h>
#include <sys/sysctl.h>

#include <err.h>
#include <ctype.h>
#include <fcntl.h>
#include <time.h>
#include <kvm.h>
#include <nlist.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <vis.h>

#ifndef SMALL
#include <langinfo.h>
#include <locale.h>

static struct nlist nl[] = {
#define	X_MSGBUF	0
	{ .n_name = "_msgbufp" },
	{ .n_name = NULL },
};

static const char *radix;

__dead static void	usage(void);

#define	KREAD(addr, var) \
	kvm_read(kd, addr, &var, sizeof(var)) != sizeof(var)

static const char *
fmtydhmsf(char *b, size_t l, intmax_t t, long nsec, int ht)
{
	intmax_t s, m, h;
	int z;
	int prec;
	size_t o;

	s = t % 60;
	t /= 60;

	m = t % 60;
	t /= 60;

	h = t;

	z = 0;
	o = 0;

#define APPENDFMT(fmt, ...)  \
    do { \
	    z = snprintf(b + o, l - o, fmt, __VA_ARGS__); \
	    if (z == -1) \
		    return b; \
	    o += (size_t)z; \
	    if (o >= l) \
		    return b; \
    } while (/*CONSTCOND*/0)

#define APPEND(a) \
    do if (a) \
	APPENDFMT("%jd%c", a, toupper((unsigned char)__STRING(a)[0])); \
    while (/*CONSTCOND*/0)
#define APPENDS(a, pr, ms) \
    APPENDFMT("%jd%s%.*ld%c", a, radix, pr, ms, \
	toupper((unsigned char)__STRING(a)[0]))

	APPENDFMT("%s", "P");
	APPENDFMT("%s", "T");
	APPEND(h);
	APPEND(m);
	if (nsec)
		nsec = (nsec + 500000) / 1000000;	/* now milliseconds */
	prec = 3;
	if (nsec && ht == 2) {
		while (prec > 0 && (nsec % 10) == 0)
			--prec, nsec /= 10;
	}
	if (nsec || ht > 2)
		APPENDS(s, prec, nsec);
	else
		APPEND(s);
	return b;
}

static void
pnsec(long nsec, long fsec, int scale)
{
	if (scale > 6)
		printf("%6.6ld", (nsec + 499) / 1000);
	else
		printf("%*.*ld%.*s", scale, scale, fsec, 6 - scale, "000000");
}
#endif

int
main(int argc, char *argv[])
{
	struct kern_msgbuf cur;
	int ch, newl, log, i;
	size_t size;
	char *p, *bufdata;
	char buf[5];
#ifndef SMALL
	size_t tstamp;
	char tbuf[64];
	char *memf, *nlistf;
	struct timespec boottime;
	struct timespec lasttime;
	intmax_t sec;
	long nsec, fsec;
	int scale;
	int deltas, quiet, humantime;
	bool frac, postts;

	static const int bmib[] = { CTL_KERN, KERN_BOOTTIME };
	size = sizeof(boottime);

	(void)setlocale(LC_ALL, "");
	radix = nl_langinfo(RADIXCHAR);
	if (radix == NULL)
		radix = ".";	/* could also select "," */

	boottime.tv_sec = 0;
	boottime.tv_nsec = 0;
	lasttime.tv_sec = 0;
	lasttime.tv_nsec = 0;
	deltas = quiet = humantime = 0;

	(void)sysctl(bmib, 2, &boottime, &size, NULL, 0);

	memf = nlistf = NULL;
	while ((ch = getopt(argc, argv, "dM:N:tT")) != -1)
		switch(ch) {
		case 'd':
			deltas = 1;
			break;
		case 'M':
			memf = optarg;
			break;
		case 'N':
			nlistf = optarg;
			break;
		case 't':
			quiet = 1;
			break;
		case 'T':
			humantime++;
			break;
		case '?':
		default:
			usage();
		}
	argc -= optind;
	argv += optind;
	if (quiet && humantime)
		err(EXIT_FAILURE, "-t cannot be used with -T");

	if (memf == NULL) {
#endif
		static const int mmib[2] = { CTL_KERN, KERN_MSGBUF };

		if (sysctl(mmib, 2, NULL, &size, NULL, 0) == -1 ||
		    (bufdata = malloc(size)) == NULL ||
		    sysctl(mmib, 2, bufdata, &size, NULL, 0) == -1)
			err(1, "can't get msgbuf");

		/* make a dummy struct msgbuf for the display logic */
		cur.msg_bufx = 0;
		cur.msg_bufs = size;
#ifndef SMALL
	} else {
		kvm_t *kd;
		struct kern_msgbuf *bufp;

		/*
		 * Read in message buffer header and data, and do sanity
		 * checks.
		 */
		kd = kvm_open(nlistf, memf, NULL, O_RDONLY, "dmesg");
		if (kd == NULL)
			exit (1);
		if (kvm_nlist(kd, nl) == -1)
			errx(1, "kvm_nlist: %s", kvm_geterr(kd));
		if (nl[X_MSGBUF].n_type == 0)
			errx(1, "%s: msgbufp not found", nlistf ? nlistf :
			    "namelist");
		if (KREAD(nl[X_MSGBUF].n_value, bufp))
			errx(1, "kvm_read: %s (0x%lx)", kvm_geterr(kd),
			    nl[X_MSGBUF].n_value);
		if (kvm_read(kd, (long)bufp, &cur,
		    offsetof(struct kern_msgbuf, msg_bufc)) !=
		    offsetof(struct kern_msgbuf, msg_bufc))
			errx(1, "kvm_read: %s (0x%lx)", kvm_geterr(kd),
			    (unsigned long)bufp);
		if (cur.msg_magic != MSG_MAGIC)
			errx(1, "magic number incorrect");
		bufdata = malloc(cur.msg_bufs);
		if (bufdata == NULL)
			errx(1, "couldn't allocate space for buffer data");
		if (kvm_read(kd, (long)&bufp->msg_bufc, bufdata,
		    cur.msg_bufs) != cur.msg_bufs)
			errx(1, "kvm_read: %s", kvm_geterr(kd));
		kvm_close(kd);
		if (cur.msg_bufx >= cur.msg_bufs)
			cur.msg_bufx = 0;
	}
#endif

	/*
	 * The message buffer is circular; start at the write pointer
	 * (which points the oldest character), and go to the write
	 * pointer - 1 (which points the newest character).  I.e, loop
	 * over cur.msg_bufs times.  Unused area is skipped since it
	 * contains nul.
	 */
#ifndef SMALL
	frac = false;
	postts = false;
	tstamp = 0;
	scale = 0;
#endif
	for (newl = 1, log = i = 0, p = bufdata + cur.msg_bufx;
	    i < cur.msg_bufs; i++, p++) {

#ifndef SMALL
		if (p == bufdata + cur.msg_bufs)
			p = bufdata;
#define ADDC(c)								\
    do {								\
	if (tstamp < sizeof(tbuf) - 1)					\
		tbuf[tstamp++] = (c);					\
	else {								\
		/* Cannot be a timestamp. */				\
		tstamp = 0;						\
		tbuf[sizeof(tbuf) - 1] = '\0';				\
		goto not_tstamp;					\
	}								\
	if (frac)							\
		scale++;						\
    } while (0)
#define	PRTBUF()							\
    for (char *_p = tbuf; *_p != '\0'; _p++) {				\
	(void)vis(buf, *_p, VIS_NOSLASH, 0);				\
	if (buf[1] == 0)						\
		(void)putchar(buf[0]);					\
	else								\
		(void)printf("%s", buf);				\
    }
#endif
		ch = *p;
		if (ch == '\0')
			continue;
		/* Skip "\n<.*>" syslog sequences. */
		/* Gather timestamp sequences */
		if (newl) {
#ifndef SMALL
			int j;
#endif

			switch (ch) {
#ifndef SMALL
			case '[':
				frac = false;
				scale = 0;
				ADDC(ch);
				continue;
#endif
			case '<':
				log = 1;
				continue;
			case '>':
				log = 0;
				continue;
#ifndef SMALL
			case ']':
				if (tstamp == 0)
					goto prchar;
				frac = false;
				ADDC(ch);
				ADDC('\0');
				tstamp = 0;
				sec = fsec = 0;
				switch (sscanf(tbuf, "[%jd.%ld]", &sec, &fsec)){
				case 0:
 not_tstamp:				/* not a timestamp */
					PRTBUF();
					continue;
				case 1:
					fsec = 0; /* XXX PRTBUF()? */
					break;
				case 2:
					break;
				case EOF:
				default:
					/* Help */
					continue;
				}
				postts = true;

				for (nsec = fsec, j = 9 - scale; --j >= 0; )
					nsec *= 10;
				if (!quiet || deltas)
					printf("[");
				if (humantime == 1) {
					time_t t;
					struct tm tm;

					t = boottime.tv_sec + sec;
					if (nsec + boottime.tv_nsec >=
					    ( 1L		/* 1 second */
						 * 1000L	/* ms */
						 * 1000L	/* us */
						 * 1000L	/* ns */ ))
							t++;

					if (localtime_r(&t, &tm) != NULL) {
						strftime(tbuf, sizeof(tbuf),
						    "%a %b %e %H:%M:%S %Z %Y",
						    &tm);
						printf("%s", tbuf);
					}
				} else if (humantime > 1) {
					const char *fp = fmtydhmsf(tbuf,
					    sizeof(tbuf), sec, fsec, humantime);
					if (fp) {
						printf("%s", fp);
					}
				} else if (!quiet) {
					printf(" %5jd%s", sec, radix);
					pnsec(nsec, fsec, scale);
				}
				if (deltas) {
					struct timespec nt = { sec, nsec };
					struct timespec dt;

					timespecsub(&nt, &lasttime, &dt);
					if (humantime || !quiet)
						printf(" ");
					printf("<% 4jd%s%6.6ld>",
					    (intmax_t)dt.tv_sec, radix,
					    (dt.tv_nsec+499) / 1000);
					lasttime = nt;
				}
				if (!quiet || deltas)
					printf("] ");
				continue;
#endif
			case ' ':
#ifndef SMALL
				if (!tstamp && postts) {
					postts = false;
					continue;
				}
#endif
				/*FALLTHROUGH*/
			default:
#ifndef SMALL
				if (tstamp) {
					ADDC(ch);
					if (ch == '.')
						frac = true;
					continue;
				}
 prchar:
#endif
				if (log)
					continue;
				break;
			}
		}
		newl = ch == '\n';
		(void)vis(buf, ch, VIS_NOSLASH, 0);
#ifndef SMALL
		if (buf[1] == 0)
			(void)putchar(buf[0]);
		else
#endif
			(void)printf("%s", buf);
	}
#ifndef SMALL
	/* non-terminated [.*] */
	if (tstamp) {
		ADDC('\0');
		PRTBUF();
	}
#endif
	if (!newl)
		(void)putchar('\n');
	return EXIT_SUCCESS;
}

#ifndef SMALL
static void
usage(void)
{

	(void)fprintf(stderr, "Usage: %s [-dTt] [-M core] [-N system]\n",
		getprogname());
	exit(EXIT_FAILURE);
}
#endif
