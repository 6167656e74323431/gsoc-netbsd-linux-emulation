/*	$NetBSD: v6ionames.c,v 1.2 2004/12/30 08:29:09 darrenr Exp $	*/

/*
 * Copyright (C) 1993-2001 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * Id: v6ionames.c,v 1.1 2003/04/26 04:55:58 darrenr Exp
 */
#include "ipf.h"


#ifdef	USE_INET6

struct	ipopt_names	v6ionames[] ={
	{ IPPROTO_HOPOPTS,	0x000001,	0,	"hopopts" },
	{ IPPROTO_IPV6,		0x000002,	0,	"ipv6" },
	{ IPPROTO_ROUTING,	0x000004,	0,	"routing" },
	{ IPPROTO_FRAGMENT,	0x000008,	0,	"frag" },	
	{ IPPROTO_ESP,		0x000010,	0,	"esp" },
	{ IPPROTO_AH,		0x000020,	0,	"ah" },
	{ IPPROTO_NONE,		0x000040,	0,	"none" },	
	{ IPPROTO_DSTOPTS,	0x000080,	0,	"dstopts" },
	{ 0, 			0,		0,	(char *)NULL }
};

#endif
