/*	$NetBSD: hack.h,v 1.4 1997/10/19 16:58:02 christos Exp $	*/

/*
 * Copyright (c) Stichting Mathematisch Centrum, Amsterdam, 1985.
 */
#ifndef _HACK_H_
#define _HACK_H_

#include "config.h"
#include <string.h>

#ifndef BSD
#define	index	strchr
#define	rindex	strrchr
#endif /* BSD */

#define	Null(type)	((struct type *) 0)

#include	"def.objclass.h"

typedef struct {
	xchar x,y;
} coord;

#include	"def.monst.h"	/* uses coord */
#include	"def.gold.h"
#include	"def.trap.h"
#include	"def.obj.h"
#include	"def.flag.h"

#define	plur(x)	(((x) == 1) ? "" : "s")

#define	BUFSZ	256	/* for getlin buffers */
#define	PL_NSIZ	32	/* name of player, ghost, shopkeeper */

#include	"def.rm.h"
#include	"def.permonst.h"

#define	newstring(x)	(char *) alloc((unsigned)(x))
#include "hack.onames.h"

#define ON 1
#define OFF 0

struct prop {
#define	TIMEOUT		007777	/* mask */
#define	LEFT_RING	W_RINGL	/* 010000L */
#define	RIGHT_RING	W_RINGR	/* 020000L */
#define	INTRINSIC	040000L
#define	LEFT_SIDE	LEFT_RING
#define	RIGHT_SIDE	RIGHT_RING
#define	BOTH_SIDES	(LEFT_SIDE | RIGHT_SIDE)
	long p_flgs;
	void (*p_tofn) __P((void));	/* called after timeout */
};

struct you {
	xchar ux, uy;
	schar dx, dy, dz;	/* direction of move (or zap or ... ) */
#ifdef QUEST
	schar di;		/* direction of FF */
	xchar ux0, uy0;		/* initial position FF */
#endif QUEST
	xchar udisx, udisy;	/* last display pos */
	char usym;		/* usually '@' */
	schar uluck;
#define	LUCKMAX		10	/* on moonlit nights 11 */
#define	LUCKMIN		(-10)
	int last_str_turn:3;	/* 0: none, 1: half turn, 2: full turn */
				/* +: turn right, -: turn left */
	unsigned udispl:1;	/* @ on display */
	unsigned ulevel:4;	/* 1 - 14 */
#ifdef QUEST
	unsigned uhorizon:7;
#endif QUEST
	unsigned utrap:3;	/* trap timeout */
	unsigned utraptype:1;	/* defined if utrap nonzero */
#define	TT_BEARTRAP	0
#define	TT_PIT		1
	unsigned uinshop:6;	/* used only in shk.c - (roomno+1) of shop */


/* perhaps these #define's should also be generated by makedefs */
#define	TELEPAT		LAST_RING		/* not a ring */
#define	Telepat		u.uprops[TELEPAT].p_flgs
#define	FAST		(LAST_RING+1)		/* not a ring */
#define	Fast		u.uprops[FAST].p_flgs
#define	CONFUSION	(LAST_RING+2)		/* not a ring */
#define	Confusion	u.uprops[CONFUSION].p_flgs
#define	INVIS		(LAST_RING+3)		/* not a ring */
#define	Invis		u.uprops[INVIS].p_flgs
#define Invisible	(Invis && !See_invisible)
#define	GLIB		(LAST_RING+4)		/* not a ring */
#define	Glib		u.uprops[GLIB].p_flgs
#define	PUNISHED	(LAST_RING+5)		/* not a ring */
#define	Punished	u.uprops[PUNISHED].p_flgs
#define	SICK		(LAST_RING+6)		/* not a ring */
#define	Sick		u.uprops[SICK].p_flgs
#define	BLIND		(LAST_RING+7)		/* not a ring */
#define	Blind		u.uprops[BLIND].p_flgs
#define	WOUNDED_LEGS	(LAST_RING+8)		/* not a ring */
#define Wounded_legs	u.uprops[WOUNDED_LEGS].p_flgs
#define STONED		(LAST_RING+9)		/* not a ring */
#define Stoned		u.uprops[STONED].p_flgs
#define PROP(x) (x-RIN_ADORNMENT)       /* convert ring to index in uprops */
	unsigned umconf:1;
	char *usick_cause;
	struct prop uprops[LAST_RING+10];

	unsigned uswallow:1;		/* set if swallowed by a monster */
	unsigned uswldtim:4;		/* time you have been swallowed */
	unsigned uhs:3;			/* hunger state - see hack.eat.c */
	schar ustr,ustrmax;
	schar udaminc;
	schar uac;
	int uhp,uhpmax;
	long int ugold,ugold0,uexp,urexp;
	int uhunger;			/* refd only in eat.c and shk.c */
	int uinvault;
	struct monst *ustuck;
	int nr_killed[CMNUM+2];		/* used for experience bookkeeping */
};

#define DIST(x1,y1,x2,y2)       (((x1)-(x2))*((x1)-(x2)) + ((y1)-(y2))*((y1)-(y2)))

#define	PL_CSIZ		20	/* sizeof pl_character */
#define	MAX_CARR_CAP	120	/* so that boulders can be heavier */
#define	MAXLEVEL	40
#define	FAR	(COLNO+2)	/* position outside screen */

extern boolean in_mklev;
extern boolean level_exists[];
extern boolean restoring;
extern char *CD;
extern char *catmore;
extern char *hname;
extern char *hu_stat[]; /* in eat.c */
extern char *nomovemsg;
extern char *occtxt;
extern char *save_cm,*killer;
extern char *traps[];
extern char SAVEF[];
extern char fut_geno[60]; /* idem */
extern char genocided[60]; /* defined in Decl.c */
extern char lock[];
extern char mlarge[];
extern char morc;
extern char nul[];
extern char pl_character[];
extern char plname[PL_NSIZ], pl_character[PL_CSIZ];
extern char quitchars[];
extern char sdir[]; /* defined in hack.c */
extern char shtypes[]; /* = "=/)%?!["; 8 types: 7 specialized, 1 mixed */
extern char vowels[];
extern coord bhitpos;	/* place where thrown weapon falls to the ground */
extern int (*afternmv) __P((void));
extern int (*occupation) __P((void));
extern int CO, LI; /* usually COLNO and ROWNO+2 */
extern int bases[];
extern int doorindex;
extern int hackpid;
extern int multi;
extern int nroom;
extern long moves;
extern long wailmsg;
extern schar xdir[], ydir[]; /* idem */
extern struct gold *fgold;
extern struct monst *mydogs;
extern struct monst youmonst;
extern struct obj *billobjs;
extern struct obj *invent, *uwep, *uarm, *uarm2, *uarmh, *uarms, *uarmg;
extern struct obj *uleft, *uright, *fcobj;
extern struct obj *uball;	/* defined if PUNISHED */
extern struct obj *uchain;	/* defined iff PUNISHED */
extern struct obj zeroobj;
extern struct permonst li_dog, dog, la_dog;
extern struct permonst mons[CMNUM + 2];
extern struct permonst pm_eel;
extern struct permonst pm_ghost;
extern struct permonst pm_mail_daemon;
extern struct permonst pm_wizard;
#ifndef NOWORM
extern long wgrowtime[32];
extern struct wseg *m_atseg;
extern struct wseg *wsegs[32], *wheads[32];
#endif
extern struct you u;
extern xchar curx, cury;	/* cursor location on screen */
extern xchar dlevel, maxdlevel; /* dungeon level */
extern xchar seehx,seelx,seehy,seely; /* where to see*/
extern xchar xdnstair, ydnstair, xupstair, yupstair; /* stairs up and down. */
#endif /* _HACK_H_ */
