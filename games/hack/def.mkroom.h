/*	$NetBSD: def.mkroom.h,v 1.4 1997/10/19 16:57:05 christos Exp $ */

/*
 * Copyright (c) Stichting Mathematisch Centrum, Amsterdam, 1985.
 */
#ifndef _DEF_MKROOM_H_
#define _DEF_MKROOM_H_
struct mkroom {
	schar lx,hx,ly,hy;	/* usually xchar, but hx may be -1 */
	schar rtype,rlit,doorct,fdoor;
};

#define	MAXNROFROOMS	15
extern struct mkroom rooms[MAXNROFROOMS+1];

#define	DOORMAX	100
extern coord doors[DOORMAX];

/* various values of rtype */
/* 0: ordinary room; 8-15: various shops */
/* Note: some code assumes that >= 8 means shop, so be careful when adding
   new roomtypes */
#define	SWAMP	3
#define	VAULT	4
#define	BEEHIVE	5
#define	MORGUE	6
#define	ZOO	7
#define	SHOPBASE	8
#define	WANDSHOP	9
#define	GENERAL	15
#endif /* _DEF_MKROOM_H_ */
