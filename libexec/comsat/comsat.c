/*	$NetBSD: comsat.c,v 1.26 2003/09/19 05:33:15 itojun Exp $	*/

/*
 * Copyright (c) 1980, 1993
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
__COPYRIGHT("@(#) Copyright (c) 1980, 1993\n\
	The Regents of the University of California.  All rights reserved.\n");
#if 0
static char sccsid[] = "from: @(#)comsat.c	8.1 (Berkeley) 6/4/93";
#else
__RCSID("$NetBSD: comsat.c,v 1.26 2003/09/19 05:33:15 itojun Exp $");
#endif
#endif /* not lint */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/wait.h>

#include <netinet/in.h>

#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <paths.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <termios.h>
#include <time.h>
#include <vis.h>
#include <unistd.h>
#include <utmp.h>

int	logging;
int	debug = 0;
#define	dsyslog	if (debug) syslog

#define MAXIDLE	120

char	hostname[MAXHOSTNAMELEN+1];
struct	utmp *utmp = NULL;
time_t	lastmsgtime;
int	nutmp, uf;

void jkfprintf (FILE *, char[], off_t);
void mailfor (char *);
void notify (struct utmp *, off_t);
void onalrm (int);
void reapchildren (int);

int
main(int argc, char *argv[])
{
	struct sockaddr_storage from;
	int cc, ch;
	int fromlen;
	char msgbuf[100];
	sigset_t nsigset;

	/* verify proper invocation */
	fromlen = sizeof(from);
	if (getsockname(0, (struct sockaddr *)&from, &fromlen) < 0) {
		(void)fprintf(stderr,
		    "comsat: getsockname: %s.\n", strerror(errno));
		exit(1);
	}

	openlog("comsat", LOG_PID, LOG_DAEMON);
	while ((ch = getopt(argc, argv, "l")) != -1)
		switch (ch) {
		case 'l':
			logging = 1;
			break;
		default:
			syslog(LOG_ERR, "Usage: %s [-l]", getprogname());
			exit(1);
		}
	if (chdir(_PATH_MAILDIR)) {
		syslog(LOG_ERR, "chdir: %s: %m", _PATH_MAILDIR);
		(void)recv(0, msgbuf, sizeof(msgbuf) - 1, 0);
		exit(1);
	}
	if ((uf = open(_PATH_UTMP, O_RDONLY, 0)) < 0) {
		syslog(LOG_ERR, "open: %s: %m", _PATH_UTMP);
		(void)recv(0, msgbuf, sizeof(msgbuf) - 1, 0);
		exit(1);
	}
	(void)time(&lastmsgtime);
	(void)gethostname(hostname, sizeof(hostname));
	hostname[sizeof(hostname) - 1] = '\0';
	onalrm(0);
	(void)signal(SIGALRM, onalrm);
	(void)signal(SIGTTOU, SIG_IGN);
	(void)signal(SIGCHLD, reapchildren);
	for (;;) {
		cc = recv(0, msgbuf, sizeof(msgbuf) - 1, 0);
		if (cc <= 0) {
			if (errno != EINTR)
				sleep(1);
			errno = 0;
			continue;
		}
		if (!nutmp)		/* no one has logged in yet */
			continue;
		sigemptyset(&nsigset);
		sigaddset(&nsigset, SIGALRM);
		sigprocmask(SIG_SETMASK, &nsigset, NULL);
		msgbuf[cc] = '\0';
		(void)time(&lastmsgtime);
		mailfor(msgbuf);
		sigemptyset(&nsigset);
		sigprocmask(SIG_SETMASK, &nsigset, NULL);
	}
}

void
reapchildren(int signo)
{

	while (wait3(NULL, WNOHANG, NULL) > 0);
}

void
onalrm(int signo)
{
	static u_int utmpsize;		/* last malloced size for utmp */
	static u_int utmpmtime;		/* last modification time for utmp */
	struct stat statbf;
	struct utmp *u;

	if (time(NULL) - lastmsgtime >= MAXIDLE)
		exit(0);
	(void)alarm((u_int)15);
	(void)fstat(uf, &statbf);
	if (statbf.st_mtime > utmpmtime) {
		utmpmtime = statbf.st_mtime;
		if (statbf.st_size > utmpsize) {
			if ((u = realloc(utmp,
			    statbf.st_size + 10 * sizeof(struct utmp))) == NULL) {
				syslog(LOG_ERR, "%s", strerror(errno));
				exit(1);
			}
			utmp = u;
			utmpsize = statbf.st_size + 10 * sizeof(struct utmp);
		}
		(void)lseek(uf, (off_t)0, SEEK_SET);
		nutmp = read(uf, utmp, (int)statbf.st_size)/sizeof(struct utmp);
	}
}

void
mailfor(char *name)
{
	struct utmp *utp = &utmp[nutmp];
	char *cp, *fn;
	off_t offset;

	if (!(cp = strchr(name, '@')))
		return;
	*cp = '\0';
	errno = 0;
	offset = strtol(cp + 1, &fn, 10);
	if (errno == ERANGE)
		return;
	if (fn && *fn && *fn != '\n') {
		/*
		 * Procmail sends messages to comsat with a trailing colon
		 * and a pathname to the folder where the new message was
		 * deposited.  Since we can't reliably open only regular
		 * files, we need to ignore these.  With one exception:
		 * if it mentions the user's system mailbox.
		 */
		char maildir[128];
		int l = snprintf(maildir, sizeof(maildir), ":%s/%s",
				 _PATH_MAILDIR, name);
		if (l > sizeof(maildir) || strcmp(maildir, fn) != 0)
			return;
	}
	while (--utp >= utmp)
		if (!strncmp(utp->ut_name, name, sizeof(utmp[0].ut_name)))
			notify(utp, offset);
}

static char *cr;

void
notify(struct utmp *utp, off_t offset)
{
	FILE *tp;
	struct passwd *p;
	struct stat stb;
	struct termios ttybuf;
	char tty[20], name[sizeof(utmp[0].ut_name) + 1];

	(void)snprintf(tty, sizeof(tty), "%s%.*s",
	    _PATH_DEV, (int)sizeof(utp->ut_line), utp->ut_line);
	if (strchr(tty + sizeof(_PATH_DEV) - 1, '/')) {
		/* A slash is an attempt to break security... */
		/*
		 * XXX but what about something like "/dev/pts/5"
		 * that we may one day "support". ?
		 */
		syslog(LOG_AUTH | LOG_NOTICE, "'/' in \"%s\"", tty);
		return;
	}
	if (stat(tty, &stb) || !(stb.st_mode & S_IEXEC)) {
		dsyslog(LOG_DEBUG, "%s: wrong mode on %s", utp->ut_name, tty);
		return;
	}
	dsyslog(LOG_DEBUG, "notify %s on %s", utp->ut_name, tty);
	if (fork())
		return;
	(void)signal(SIGALRM, SIG_DFL);
	(void)alarm((u_int)30);
	if ((tp = fopen(tty, "w")) == NULL) {
		dsyslog(LOG_ERR, "%s: %s", tty, strerror(errno));
		_exit(1);
	}
	(void)tcgetattr(fileno(tp), &ttybuf);
	cr = (ttybuf.c_oflag & ONLCR) && (ttybuf.c_oflag & OPOST) ?
	    "\n" : "\n\r";
	(void)strlcpy(name, utp->ut_name, sizeof(name));

	/* Set uid/gid/groups to users in case mail drop is on nfs */
	if ((p = getpwnam(name)) == NULL ||
	    initgroups(p->pw_name, p->pw_gid) < 0 ||
	    setgid(p->pw_gid) < 0 ||
	    setuid(p->pw_uid) < 0)
		_exit(1);

	if (logging)
		syslog(LOG_INFO, "biff message for %s", name);

	(void)fprintf(tp, "%s\007New mail for %s@%.*s\007 has arrived:%s----%s",
	    cr, name, (int)sizeof(hostname), hostname, cr, cr);
	jkfprintf(tp, name, offset);
	(void)fclose(tp);
	_exit(0);
}

void
jkfprintf(FILE *tp, char name[], off_t offset)
{
	FILE *fi;
	int linecnt, charcnt, inheader;
	char line[BUFSIZ], visline[BUFSIZ*4], *nl;

	if ((fi = fopen(name, "r")) == NULL)
		return;

	(void)fseek(fi, offset, SEEK_SET);
	/*
	 * Print the first 7 lines or 560 characters of the new mail
	 * (whichever comes first).  Skip header crap other than
	 * From, Subject, To, and Date.
	 */
	linecnt = 7;
	charcnt = 560;
	inheader = 1;
	while (fgets(line, sizeof(line), fi) != NULL) {
		line[sizeof(line) - 1] = '\0';
		if (inheader) {
			if (line[0] == '\n') {
				inheader = 0;
				continue;
			}
			if (line[0] == ' ' || line[0] == '\t' ||
			    (strncasecmp(line, "From:", 5) &&
			    strncasecmp(line, "Subject:", 8)))
				continue;
		}
		if (strncmp(line, "From ", 5) == 0) {
			(void)fprintf(tp, "----%s", cr);
			(void)fclose(fi);
			return;
		}
		if (linecnt <= 0 || charcnt <= 0) {
			(void)fprintf(tp, "...more...%s", cr);
			(void)fclose(fi);
			return;
		}
		if ((nl = strchr(line, '\n')) != NULL)
			*nl = '\0';
		/* strip weird stuff so can't trojan horse stupid terminals */
		(void)strvis(visline, line, VIS_CSTYLE);
		(void)fputs(visline, tp);
		(void)fputs(cr, tp);
		--linecnt;
	}
	(void)fprintf(tp, "----%s\n", cr);
	(void)fclose(fi);
}
