/*	$NetBSD: logger.c,v 1.7 2000/09/21 10:17:24 ad Exp $	*/

/*
 * Copyright (c) 1983, 1993
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
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
__COPYRIGHT("@(#) Copyright (c) 1983, 1993\n\
	The Regents of the University of California.  All rights reserved.\n");
#endif /* not lint */

#ifndef lint
#if 0
static char sccsid[] = "@(#)logger.c	8.1 (Berkeley) 6/6/93";
#endif
__RCSID("$NetBSD: logger.c,v 1.7 2000/09/21 10:17:24 ad Exp $");
#endif /* not lint */

#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <err.h>

#define	SYSLOG_NAMES
#include <syslog.h>

int	decode(const char *, const CODE *);
int	pencode(char *);
int	main(int, char **);
void	usage(void);

/*
 * logger -- read and log utility
 *
 *	Reads from an input and arranges to write the result on the system
 *	log.
 */
int
main(int argc, char *argv[])
{
	int ch, logflags, pri;
	const char *tag;
	char buf[1024];

	tag = NULL;
	pri = LOG_NOTICE;
	logflags = 0;
	while ((ch = getopt(argc, argv, "f:ip:st:")) != -1)
		switch((char)ch) {
		case 'f':		/* file to log */
			if (freopen(optarg, "r", stdin) == NULL)
				err(EXIT_FAILURE, "%s", optarg);
			break;
		case 'i':		/* log process id also */
			logflags |= LOG_PID;
			break;
		case 'p':		/* priority */
			pri = pencode(optarg);
			break;
		case 's':		/* log to standard error */
			logflags |= LOG_PERROR;
			break;
		case 't':		/* tag */
			tag = optarg;
			break;
		case '?':
		default:
			usage();
		}
	argc -= optind;
	argv += optind;

	/* setup for logging */
	openlog(tag != NULL ? tag : getlogin(), logflags, 0);
	(void)fclose(stdout);

	/* log input line if appropriate */
	if (argc > 0) {
		char *p, *endp;
		int len;

		for (p = buf, endp = buf + sizeof(buf) - 2; *argv != NULL;) {
			len = strlen(*argv);
			if (p + len > endp && p > buf) {
				syslog(pri, "%s", buf);
				p = buf;
			}
			if (len > sizeof(buf) - 1)
				syslog(pri, "%s", *argv++);
			else {
				if (p != buf)
					*p++ = ' ';
				memmove(p, *argv++, len);
				*(p += len) = '\0';
			}
		}
		if (p != buf)
			syslog(pri, "%s", buf);
	} else
		while (fgets(buf, sizeof(buf), stdin) != NULL)
			syslog(pri, "%s", buf);

	exit(EXIT_SUCCESS);
	/* NOTREACHED */
}

/*
 *  Decode a symbolic name to a numeric value
 */
int
pencode(char *s)
{
	char *save;
	int fac, lev;

	for (save = s; *s != '\0' && *s != '.'; ++s)
		;
	if (*s != '\0') {
		*s = '\0';
		fac = decode(save, facilitynames);
		if (fac < 0)
			errx(EXIT_FAILURE, "unknown facility name: %s", save);
		*s++ = '.';
	} else {
		fac = 0;
		s = save;
	}
	lev = decode(s, prioritynames);
	if (lev < 0)
		errx(EXIT_FAILURE, "unknown priority name: %s", s);
	return ((lev & LOG_PRIMASK) | (fac & LOG_FACMASK));
}

int
decode(const char *name, const CODE *codetab)
{
	const CODE *c;

	if (isdigit((unsigned char)*name))
		return (atoi(name));

	for (c = codetab; c->c_name != NULL; c++)
		if (strcasecmp(name, c->c_name) == 0)
			return (c->c_val);

	return (-1);
}

void
usage(void)
{
	extern const char *__progname;

	(void)fprintf(stderr,
	    "%s: [-is] [-f file] [-p pri] [-t tag] [ message ... ]\n",
	    __progname);
	exit(EXIT_FAILURE);
}
