/*	$NetBSD: extern.h,v 1.11 2009/08/12 04:28:27 dholland Exp $	*/

/*
 * Copyright (c) 1997 Christos Zoulas.  All rights reserved.
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
 *	This product includes software developed by Christos Zoulas.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
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

#include <string.h>

/* crc.c */
void crc_start(void);
unsigned long crc(const char *, int);

/* done.c */
int score(void);
void done(int) __attribute__((__noreturn__));
void die(int);

/* init.c */
void init(void);
char   *decr(int, int, int, int, int);
void trapdel(int);
void startup(void);

/* io.c */
void getin(char **, char **);
int yes(int, int, int);
int yesm(int, int, int);
void rdata(void);
#ifdef DEBUG
void twrite(int);
#endif
void rspeak(int);
void mspeak(int);
struct text;
void speak(const struct text *);
void pspeak(int, int);

/* save.c */
int save(const char *);
int restore(const char *);

/* subr.c */
int toting(int);
int here(int);
int at(int);
int liq(void);
int liqloc(int);
int forced(int);
int dark(void);
int pct(int);
int fdwarf(void);
int march(void);
void bug(int) __attribute__((__noreturn__));
void checkhints(void);
int trsay(void);
int trtake(void);
int trdrop(void);
int tropen(void);
int trkill(void);
int trtoss(void);
int trfeed(void);
int trfill(void);
void closing(void);
void caveclose(void);

/* vocab.c */
void dstroy(int);
void juggle(int);
void move(int, int);
int put(int, int, int);
void carry(int, int);
void drop(int, int);
int vocab(const char *, int, int);

/* These three used to be functions in vocab.c */
#define copystr(src, dest)	strcpy((dest), (src))
#define weq(str1, str2)		(!strncmp((str1), (str2), 5))
#define length(str)		(strlen((str)) + 1)

/* wizard.c */
void datime(int *, int *);
void poof(void);
int Start(void);
void ciao(void);
int ran(int);
