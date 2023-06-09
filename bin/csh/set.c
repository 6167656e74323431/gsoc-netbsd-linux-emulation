/* $NetBSD: set.c,v 1.40 2022/09/15 11:35:06 martin Exp $ */

/*-
 * Copyright (c) 1980, 1991, 1993
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
#if 0
static char sccsid[] = "@(#)set.c	8.1 (Berkeley) 5/31/93";
#else
__RCSID("$NetBSD: set.c,v 1.40 2022/09/15 11:35:06 martin Exp $");
#endif
#endif /* not lint */

#include <sys/types.h>

#include <stdarg.h>
#include <stdlib.h>

#include <string.h>

#include "csh.h"
#include "extern.h"

static Char *getinx(Char *, int *);
static void asx(Char *, int, Char *);
static struct varent *getvx(Char *, int);
static Char *xset(Char *, Char ***);
static Char *operate(int, Char *, Char *);
static void putn1(int);
static struct varent *madrof(Char *, struct varent *);
static void unsetv1(struct varent *);
static void exportpath(Char **);
static void balance(struct varent *, int, int);

#ifdef EDIT
static int wantediting;

static const char *
alias_text(void *dummy __unused, const char *name)
{
	static char *buf;
	struct varent *vp;
	Char **av;
	char *p;
	size_t len;

	vp = adrof1(str2short(name), &aliases);
	if (vp == NULL)
	    return NULL;

	len = 0;
	for (av = vp->vec; *av; av++) {
	    len += strlen(vis_str(*av));
	    if (av[1])
		len++;
	}
	len++;
	free(buf);
	p = buf = xmalloc(len);
	for (av = vp->vec; *av; av++) {
	    const char *s = vis_str(*av);
	    while ((*p++ = *s++) != '\0')
		continue;
	    if (av[1])
		*p++ = ' ';
	}
	*p = '\0';
	return buf;
}
#endif

/*
 * C Shell
 */

static void
update_vars(Char *vp)
{
    if (eq(vp, STRpath)) {
	struct varent *pt = adrof(STRpath); 
	if (pt == NULL)
	    stderror(ERR_NAME | ERR_UNDVAR);
	else {
	    exportpath(pt->vec);
	    dohash(NULL, NULL);
	}
    }
    else if (eq(vp, STRhistchars)) {
	Char *pn = value(STRhistchars);

	HIST = *pn++;
	HISTSUB = *pn;
    }
    else if (eq(vp, STRuser)) {
	Setenv(STRUSER, value(vp));
	Setenv(STRLOGNAME, value(vp));
    }
    else if (eq(vp, STRwordchars)) {
	word_chars = value(vp);
    }
    else if (eq(vp, STRterm))
	Setenv(STRTERM, value(vp));
    else if (eq(vp, STRhome)) {
	Char *cp;

	cp = Strsave(value(vp));	/* get the old value back */

	/*
	 * convert to canonical pathname (possibly resolving symlinks)
	 */
	cp = dcanon(cp, cp);

	set(vp, Strsave(cp));	/* have to save the new val */

	/* and now mirror home with HOME */
	Setenv(STRHOME, cp);
	/* fix directory stack for new tilde home */
	dtilde();
	free(cp);
    }
#ifdef FILEC
    else if (eq(vp, STRfilec))
	filec = 1;
#endif
#ifdef EDIT
    else if (eq(vp, STRedit))
	wantediting = 1;
#endif
}

void
/*ARGSUSED*/
doset(Char **v, struct command *t)
{
    Char op, *p, **vecp, *vp;
    int subscr = 0;	/* XXX: GCC */
    int hadsub;

    v++;
    p = *v++;
    if (p == 0) {
	prvars();
	return;
    }
    do {
	hadsub = 0;
	vp = p;
	if (letter(*p))
	    for (; alnum(*p); p++)
		continue;
	if (vp == p || !letter(*vp))
	    stderror(ERR_NAME | ERR_VARBEGIN);
	if ((p - vp) > MAXVARLEN)
	    stderror(ERR_NAME | ERR_VARTOOLONG);
	if (*p == '[') {
	    hadsub++;
	    p = getinx(p, &subscr);
	}
	if ((op = *p) != '\0') {
	    *p++ = 0;
	    if (*p == 0 && *v && **v == '(')
		p = *v++;
	}
	else if (*v && eq(*v, STRequal)) {
	    op = '=', v++;
	    if (*v)
		p = *v++;
	}
	if (op && op != '=')
	    stderror(ERR_NAME | ERR_SYNTAX);
	if (eq(p, STRLparen)) {
	    Char **e = v;

	    if (hadsub)
		stderror(ERR_NAME | ERR_SYNTAX);
	    for (;;) {
		if (!*e)
		    stderror(ERR_NAME | ERR_MISSING, ')');
		if (**e == ')')
		    break;
		e++;
	    }
	    p = *e;
	    *e = 0;
	    vecp = saveblk(v);
	    set1(vp, vecp, &shvhed);
	    *e = p;
	    v = e + 1;
	}
	else if (hadsub)
	    asx(vp, subscr, Strsave(p));
	else
	    set(vp, Strsave(p));
	update_vars(vp);
    } while ((p = *v++) != NULL);
}

static Char *
getinx(Char *cp, int *ip)
{
    *ip = 0;
    *cp++ = 0;
    while (*cp && Isdigit(*cp))
	*ip = *ip * 10 + *cp++ - '0';
    if (*cp++ != ']')
	stderror(ERR_NAME | ERR_SUBSCRIPT);
    return (cp);
}

static void
asx(Char *vp, int subscr, Char *p)
{
    struct varent *v;

    v = getvx(vp, subscr);
    free(v->vec[subscr - 1]);
    v->vec[subscr - 1] = globone(p, G_APPEND);
}

static struct varent *
getvx(Char *vp, int subscr)
{
    struct varent *v;

    v = adrof(vp);
    if (v == 0)
	udvar(vp);
    if (subscr < 1 || subscr > blklen(v->vec))
	stderror(ERR_NAME | ERR_RANGE);
    return (v);
}

void
/*ARGSUSED*/
dolet(Char **v, struct command *t)
{
    Char c, op, *p, *vp;
    int subscr = 0;	/* XXX: GCC */
    int hadsub;

    v++;
    p = *v++;
    if (p == 0) {
	prvars();
	return;
    }
    do {
	hadsub = 0;
	vp = p;
	if (letter(*p))
	    for (; alnum(*p); p++)
		continue;
	if (vp == p || !letter(*vp))
	    stderror(ERR_NAME | ERR_VARBEGIN);
	if ((p - vp) > MAXVARLEN)
	    stderror(ERR_NAME | ERR_VARTOOLONG);
	if (*p == '[') {
	    hadsub++;
	    p = getinx(p, &subscr);
	}
	if (*p == 0 && *v)
	    p = *v++;
	if ((op = *p) != '\0')
	    *p++ = 0;
	else
	    stderror(ERR_NAME | ERR_ASSIGN);

	if (*p == '\0' && *v == NULL)
	    stderror(ERR_NAME | ERR_ASSIGN);

	vp = Strsave(vp);
	if (op == '=') {
	    c = '=';
	    p = xset(p, &v);
	}
	else {
	    c = *p++;
	    if (any("+-", c)) {
		if (c != op || *p)
		    stderror(ERR_NAME | ERR_UNKNOWNOP);
		p = Strsave(STR1);
	    }
	    else {
		if (any("<>", op)) {
		    if (c != op)
			stderror(ERR_NAME | ERR_UNKNOWNOP);
		    c = *p++;
		    stderror(ERR_NAME | ERR_SYNTAX);
		}
		if (c != '=')
		    stderror(ERR_NAME | ERR_UNKNOWNOP);
		p = xset(p, &v);
	    }
	}
	if (op == '=') {
	    if (hadsub)
		asx(vp, subscr, p);
	    else
		set(vp, p);
	} else if (hadsub) {
	    struct varent *gv = getvx(vp, subscr);

	    asx(vp, subscr, operate(op, gv->vec[subscr - 1], p));
	}
	else
	    set(vp, operate(op, value(vp), p));
	if (eq(vp, STRpath)) {
	    struct varent *pt = adrof(STRpath); 
	    if (pt == NULL)
		stderror(ERR_NAME | ERR_UNDVAR);
	    else {
		exportpath(pt->vec);
		dohash(NULL, NULL);
	    }
	}
	free(vp);
	if (c != '=')
	    free(p);
    } while ((p = *v++) != NULL);
}

static Char *
xset(Char *cp, Char ***vp)
{
    Char *dp;

    if (*cp) {
	dp = Strsave(cp);
	--(*vp);
	free(** vp);
	**vp = dp;
    }
    return (putn(expr(vp)));
}

static Char *
operate(int op, Char *vp, Char *p)
{
    Char opr[2], **v, *vec[5], **vecp;
    int i;

    v = vec;
    vecp = v;
    if (op != '=') {
	if (*vp)
	    *v++ = vp;
	opr[0] = (Char)op;
	opr[1] = 0;
	*v++ = opr;
	if (op == '<' || op == '>')
	    *v++ = opr;
    }
    *v++ = p;
    *v++ = 0;
    i = expr(&vecp);
    if (*vecp)
	stderror(ERR_NAME | ERR_EXPRESSION);
    return (putn(i));
}

static Char *putp;

Char *
putn(int n)
{
    static Char numbers[15];

    putp = numbers;
    if (n < 0) {
	n = -n;
	*putp++ = '-';
    }
    if ((unsigned int)n == 0x80000000U) {
	*putp++ = '2';
	n = 147483648;
    }
    putn1(n);
    *putp = 0;
    return (Strsave(numbers));
}

static void
putn1(int n)
{
    if (n > 9)
	putn1(n / 10);
    *putp++ = (Char)(n % 10 + '0');
}

int
getn(Char *cp)
{
    int n, sign;

    sign = 0;
    if (cp[0] == '+' && cp[1])
	cp++;
    if (*cp == '-') {
	sign++;
	cp++;
	if (!Isdigit(*cp))
	    stderror(ERR_NAME | ERR_BADNUM);
    }
    n = 0;
    while (Isdigit(*cp))
	n = n * 10 + *cp++ - '0';
    if (*cp)
	stderror(ERR_NAME | ERR_BADNUM);
    return (sign ? -n : n);
}

Char *
value1(Char *var, struct varent *head)
{
    struct varent *vp;

    vp = adrof1(var, head);
    return (vp == 0 || vp->vec[0] == 0 ? STRNULL : vp->vec[0]);
}

static struct varent *
madrof(Char *pat, struct varent *vp)
{
    struct varent *vp1;

    for (; vp; vp = vp->v_right) {
	if (vp->v_left && (vp1 = madrof(pat, vp->v_left)))
	    return vp1;
	if (Gmatch(vp->v_name, pat))
	    return vp;
    }
    return vp;
}

struct varent *
adrof1(Char *name, struct varent *v)
{
    int cmp;

    v = v->v_left;
    while (v && ((cmp = *name - *v->v_name) ||
		 (cmp = Strcmp(name, v->v_name))))
	if (cmp < 0)
	    v = v->v_left;
	else
	    v = v->v_right;
    return v;
}

/*
 * The caller is responsible for putting value in a safe place
 */
void
set(Char *var, Char *val)
{
    Char **vec;

    vec = xmalloc(2 * sizeof(*vec));
    vec[0] = val;
    vec[1] = 0;
    set1(var, vec, &shvhed);
}

void
set1(Char *var, Char **vec, struct varent *head)
{
    Char **oldv;

    oldv = vec;
    gflag = 0;
    tglob(oldv);
    if (gflag) {
	vec = globall(oldv);
	if (vec == 0) {
	    blkfree(oldv);
	    stderror(ERR_NAME | ERR_NOMATCH);
	}
	blkfree(oldv);
	gargv = 0;
    }
    setq(var, vec, head);
}

void
setq(Char *name, Char **vec, struct varent *p)
{
    struct varent *c;
    int f;

    f = 0;			/* tree hangs off the header's left link */
    while ((c = p->v_link[f]) != NULL) {
	if ((f = *name - *c->v_name) == 0 &&
	    (f = Strcmp(name, c->v_name)) == 0) {
	    blkfree(c->vec);
	    goto found;
	}
	p = c;
	f = f > 0;
    }
    p->v_link[f] = c = xmalloc(sizeof(*c));
    c->v_name = Strsave(name);
    c->v_bal = 0;
    c->v_left = c->v_right = 0;
    c->v_parent = p;
    balance(p, f, 0);
found:
    trim(c->vec = vec);
}

void
/*ARGSUSED*/
unset(Char **v, struct command *t)
{
    unset1(v, &shvhed);
    if (adrof(STRhistchars) == 0) {
	HIST = '!';
	HISTSUB = '^';
    }
    if (adrof(STRwordchars) == 0)
	word_chars = STR_WORD_CHARS;
#ifdef FILEC
    if (adrof(STRfilec) == 0)
	filec = 0;
#endif
#ifdef EDIT
    if (adrof(STRedit) == 0)
	wantediting = 0;
#endif
}

#ifdef EDIT
extern int insource;
void
updateediting(void)
{
    if (insource || wantediting == editing)
	return;

    if (wantediting) {
	HistEvent ev;
	Char *vn = value(STRhistchars);

	el = el_init_fd(getprogname(), cshin, cshout, csherr,
	    SHIN, SHOUT, SHERR);
	el_set(el, EL_EDITOR, *vn ? short2str(vn) : "emacs");
	el_set(el, EL_PROMPT, printpromptstr);
	el_set(el, EL_ALIAS_TEXT, alias_text, NULL);
	el_set(el, EL_SAFEREAD, 1);
	el_set(el, EL_ADDFN, "rl-complete",
	    "ReadLine compatible completion function", _el_fn_complete);
	el_set(el, EL_BIND, "^I", adrof(STRfilec) ? "rl-complete" : "ed-insert",
	    NULL);
	hi = history_init();
	history(hi, &ev, H_SETSIZE, getn(value(STRhistory)));
	loadhist(Histlist.Hnext);
	el_set(el, EL_HIST, history, hi);
    } else {
	if (el)
	    el_end(el);
	if (hi)
	    history_end(hi);
	el = NULL;
	hi = NULL;
    }
    editing = wantediting;
}
#endif

void
unset1(Char *v[], struct varent *head)
{
    struct varent *vp;
    int cnt;

    while (*++v) {
	cnt = 0;
	while ((vp = madrof(*v, head->v_left)) != NULL)
	    unsetv1(vp), cnt++;
	if (cnt == 0)
	    setname(vis_str(*v));
    }
}

void
unsetv(Char *var)
{
    struct varent *vp;

    if ((vp = adrof1(var, &shvhed)) == 0)
	udvar(var);
    unsetv1(vp);
}

static void
unsetv1(struct varent *p)
{
    struct varent *c, *pp;
    int f;

    /*
     * Free associated memory first to avoid complications.
     */
    blkfree(p->vec);
    free(p->v_name);
    /*
     * If p is missing one child, then we can move the other into where p is.
     * Otherwise, we find the predecessor of p, which is guaranteed to have no
     * right child, copy it into p, and move its left child into it.
     */
    if (p->v_right == 0)
	c = p->v_left;
    else if (p->v_left == 0)
	c = p->v_right;
    else {
	for (c = p->v_left; c->v_right; c = c->v_right)
	    continue;
	p->v_name = c->v_name;
	p->vec = c->vec;
	p = c;
	c = p->v_left;
    }
    /*
     * Move c into where p is.
     */
    pp = p->v_parent;
    f = pp->v_right == p;
    if ((pp->v_link[f] = c) != NULL)
	c->v_parent = pp;
    /*
     * Free the deleted node, and rebalance.
     */
    free(p);
    balance(pp, f, 1);
}

void
setNS(Char *cp)
{
    set(cp, Strsave(STRNULL));
}

void
/*ARGSUSED*/
shift(Char **v, struct command *t)
{
    struct varent *argv;
    Char *name;

    v++;
    name = *v;
    if (name == 0)
	name = STRargv;
    else
	(void) strip(name);
    argv = adrof(name);
    if (argv == 0)
	udvar(name);
    if (argv->vec[0] == 0)
	stderror(ERR_NAME | ERR_NOMORE);
    lshift(argv->vec, 1);
    update_vars(name);
}

static void
exportpath(Char **val)
{
    Char exppath[BUFSIZE];

    exppath[0] = 0;
    if (val)
	while (*val) {
	    if (Strlen(*val) + Strlen(exppath) + 2 > BUFSIZE) {
		(void)fprintf(csherr,
			       "Warning: ridiculously long PATH truncated\n");
		break;
	    }
	    (void)Strcat(exppath, *val++);
	    if (*val == 0 || eq(*val, STRRparen))
		break;
	    (void)Strcat(exppath, STRcolon);
	}
    Setenv(STRPATH, exppath);
}

#ifndef lint
 /*
  * Lint thinks these have null effect
  */
 /* macros to do single rotations on node p */
#define rright(p) (\
	t = (p)->v_left,\
	(t)->v_parent = (p)->v_parent,\
	((p)->v_left = t->v_right) ? (t->v_right->v_parent = (p)) : 0,\
	(t->v_right = (p))->v_parent = t,\
	(p) = t)
#define rleft(p) (\
	t = (p)->v_right,\
	(t)->v_parent = (p)->v_parent,\
	((p)->v_right = t->v_left) ? (t->v_left->v_parent = (p)) : 0,\
	(t->v_left = (p))->v_parent = t,\
	(p) = t)
#else
struct varent *
rleft(struct varent *p)
{
    return (p);
}
struct varent *
rright(struct varent *p)
{
    return (p);
}
#endif				/* ! lint */


/*
 * Rebalance a tree, starting at p and up.
 * F == 0 means we've come from p's left child.
 * D == 1 means we've just done a delete, otherwise an insert.
 */
static void
balance(struct varent *p, int f, int d)
{
    struct varent *pp;

#ifndef lint
    struct varent *t;	/* used by the rotate macros */

#endif
    int ff;

    /*
     * Ok, from here on, p is the node we're operating on; pp is its parent; f
     * is the branch of p from which we have come; ff is the branch of pp which
     * is p.
     */
    for (; (pp = p->v_parent) != NULL; p = pp, f = ff) {
	ff = pp->v_right == p;
	if (f ^ d) {		/* right heavy */
	    switch (p->v_bal) {
	    case -1:		/* was left heavy */
		p->v_bal = 0;
		break;
	    case 0:		/* was balanced */
		p->v_bal = 1;
		break;
	    case 1:		/* was already right heavy */
		switch (p->v_right->v_bal) {
		case 1:	/* single rotate */
		    pp->v_link[ff] = rleft(p);
		    p->v_left->v_bal = 0;
		    p->v_bal = 0;
		    break;
		case 0:	/* single rotate */
		    pp->v_link[ff] = rleft(p);
		    p->v_left->v_bal = 1;
		    p->v_bal = -1;
		    break;
		case -1:	/* double rotate */
		    (void) rright(p->v_right);
		    pp->v_link[ff] = rleft(p);
		    p->v_left->v_bal =
			p->v_bal < 1 ? 0 : -1;
		    p->v_right->v_bal =
			p->v_bal > -1 ? 0 : 1;
		    p->v_bal = 0;
		    break;
		}
		break;
	    }
	}
	else {			/* left heavy */
	    switch (p->v_bal) {
	    case 1:		/* was right heavy */
		p->v_bal = 0;
		break;
	    case 0:		/* was balanced */
		p->v_bal = -1;
		break;
	    case -1:		/* was already left heavy */
		switch (p->v_left->v_bal) {
		case -1:	/* single rotate */
		    pp->v_link[ff] = rright(p);
		    p->v_right->v_bal = 0;
		    p->v_bal = 0;
		    break;
		case 0:	/* single rotate */
		    pp->v_link[ff] = rright(p);
		    p->v_right->v_bal = -1;
		    p->v_bal = 1;
		    break;
		case 1:	/* double rotate */
		    (void) rleft(p->v_left);
		    pp->v_link[ff] = rright(p);
		    p->v_left->v_bal =
			p->v_bal < 1 ? 0 : -1;
		    p->v_right->v_bal =
			p->v_bal > -1 ? 0 : 1;
		    p->v_bal = 0;
		    break;
		}
		break;
	    }
	}
	/*
	 * If from insert, then we terminate when p is balanced. If from
	 * delete, then we terminate when p is unbalanced.
	 */
	if ((p->v_bal == 0) ^ d)
	    break;
    }
}

void
plist(struct varent *p)
{
    struct varent *c;
    sigset_t nsigset;
    int len;

    if (setintr) {
	sigemptyset(&nsigset);
	(void)sigaddset(&nsigset, SIGINT);
	(void)sigprocmask(SIG_UNBLOCK, &nsigset, NULL);
    }

    for (;;) {
	while (p->v_left)
	    p = p->v_left;
x:
	if (p->v_parent == 0)	/* is it the header? */
	    return;
	len = blklen(p->vec);
	(void)fprintf(cshout, "%s\t", short2str(p->v_name));
	if (len != 1)
	    (void)fputc('(', cshout);
	blkpr(cshout, p->vec);
	if (len != 1)
	    (void)fputc(')', cshout);
	(void)fputc('\n', cshout);
	if (p->v_right) {
	    p = p->v_right;
	    continue;
	}
	do {
	    c = p;
	    p = p->v_parent;
	} while (p->v_right == c);
	goto x;
    }
}
