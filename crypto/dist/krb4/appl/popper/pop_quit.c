/*
 * Copyright (c) 1989 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#include <popper.h>
__RCSID("$KTH-KRB: pop_quit.c,v 1.7 1996/11/19 22:48:30 assar Exp $"
      "$NetBSD: pop_quit.c,v 1.1.1.3 2002/09/12 12:22:06 joda Exp $");

/* 
 *  quit:   Terminate a POP session
 */

int
pop_quit (POP *p)
{
    /*  Release the message information list */
    if (p->mlp) free (p->mlp);

    return(POP_SUCCESS);
}
