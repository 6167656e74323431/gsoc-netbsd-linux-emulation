/*	$NetBSD: getproto.c,v 1.1.1.1 2004/03/28 08:56:18 martti Exp $	*/

#include "ipf.h"

int getproto(name)
char *name;
{
	struct protoent *p;
	char *s;

	for (s = name; *s != '\0'; s++)
		if (!isdigit(*s))
			break;
	if (*s == '\0')
		return atoi(name);

	p = getprotobyname(name);
	if (p != NULL)
		return p->p_proto;
	return -1;
}
