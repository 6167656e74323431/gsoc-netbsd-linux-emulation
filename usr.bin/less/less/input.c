/*	$NetBSD: input.c,v 1.1.1.5 2001/07/26 12:00:31 mrg Exp $	*/

/*
 * Copyright (C) 1984-2000  Mark Nudelman
 *
 * You may distribute under the terms of either the GNU General Public
 * License or the Less License, as specified in the README file.
 *
 * For more information about less, or for information on how to 
 * contact the author, see the README file.
 */


/*
 * High level routines dealing with getting lines of input 
 * from the file being viewed.
 *
 * When we speak of "lines" here, we mean PRINTABLE lines;
 * lines processed with respect to the screen width.
 * We use the term "raw line" to refer to lines simply
 * delimited by newlines; not processed with respect to screen width.
 */

#include "less.h"

extern int squeeze;
extern int chopline;
extern int hshift;
extern int quit_if_one_screen;
extern int sigs;
extern int ignore_eoi;
extern POSITION start_attnpos;
extern POSITION end_attnpos;
#if HILITE_SEARCH
extern int hilite_search;
extern int size_linebuf;
#endif

/*
 * Get the next line.
 * A "current" position is passed and a "new" position is returned.
 * The current position is the position of the first character of
 * a line.  The new position is the position of the first character
 * of the NEXT line.  The line obtained is the line starting at curr_pos.
 */
	public POSITION
forw_line(curr_pos)
	POSITION curr_pos;
{
	POSITION new_pos;
	register int c;
	int blankline;
	int endline;

	if (curr_pos == NULL_POSITION)
	{
		null_line();
		return (NULL_POSITION);
	}
#if HILITE_SEARCH
	if (hilite_search == OPT_ONPLUS)
		/*
		 * If we are ignoring EOI (command F), only prepare
		 * one line ahead, to avoid getting stuck waiting for
		 * slow data without displaying the data we already have.
		 * If we're not ignoring EOI, we *could* do the same, but
		 * for efficiency we prepare several lines ahead at once.
		 */
		prep_hilite(curr_pos, curr_pos + 3*size_linebuf, 
				ignore_eoi ? 1 : -1);
#endif
	if (ch_seek(curr_pos))
	{
		null_line();
		return (NULL_POSITION);
	}

	prewind();
	plinenum(curr_pos);
	(void) ch_seek(curr_pos);

	c = ch_forw_get();
	if (c == EOI)
	{
		null_line();
		return (NULL_POSITION);
	}
	blankline = (c == '\n' || c == '\r');

	for (;;)
	{
		if (ABORT_SIGS())
		{
			null_line();
			return (NULL_POSITION);
		}
		if (c == '\n' || c == EOI)
		{
			/*
			 * End of the line.
			 */
			new_pos = ch_tell();
			endline = TRUE;
			break;
		}

		/*
		 * Append the char to the line and get the next char.
		 */
		if (pappend(c, ch_tell()-1))
		{
			/*
			 * The char won't fit in the line; the line
			 * is too long to print in the screen width.
			 * End the line here.
			 */
			if (chopline || hshift > 0)
			{
				do
				{
					c = ch_forw_get();
				} while (c != '\n' && c != EOI);
				new_pos = ch_tell();
				endline = TRUE;
				quit_if_one_screen = FALSE;
			} else
			{
				new_pos = ch_tell() - 1;
				endline = FALSE;
			}
			break;
		}
		c = ch_forw_get();
	}
	pdone(endline);

	if (squeeze && blankline)
	{
		/*
		 * This line is blank.
		 * Skip down to the last contiguous blank line
		 * and pretend it is the one which we are returning.
		 */
		while ((c = ch_forw_get()) == '\n' || c == '\r')
			if (ABORT_SIGS())
			{
				null_line();
				return (NULL_POSITION);
			}
		if (c != EOI)
			(void) ch_back_get();
		new_pos = ch_tell();
	}

	return (new_pos);
}

/*
 * Get the previous line.
 * A "current" position is passed and a "new" position is returned.
 * The current position is the position of the first character of
 * a line.  The new position is the position of the first character
 * of the PREVIOUS line.  The line obtained is the one starting at new_pos.
 */
	public POSITION
back_line(curr_pos)
	POSITION curr_pos;
{
	POSITION new_pos, begin_new_pos;
	int c;
	int endline;

	if (curr_pos == NULL_POSITION || curr_pos <= ch_zero())
	{
		null_line();
		return (NULL_POSITION);
	}
#if HILITE_SEARCH
	if (hilite_search == OPT_ONPLUS)
		prep_hilite((curr_pos < 3*size_linebuf) ? 
				0 : curr_pos - 3*size_linebuf, curr_pos, -1);
#endif
	if (ch_seek(curr_pos-1))
	{
		null_line();
		return (NULL_POSITION);
	}

	if (squeeze)
	{
		/*
		 * Find out if the "current" line was blank.
		 */
		(void) ch_forw_get();	/* Skip the newline */
		c = ch_forw_get();	/* First char of "current" line */
		(void) ch_back_get();	/* Restore our position */
		(void) ch_back_get();

		if (c == '\n' || c == '\r')
		{
			/*
			 * The "current" line was blank.
			 * Skip over any preceding blank lines,
			 * since we skipped them in forw_line().
			 */
			while ((c = ch_back_get()) == '\n' || c == '\r')
				if (ABORT_SIGS())
				{
					null_line();
					return (NULL_POSITION);
				}
			if (c == EOI)
			{
				null_line();
				return (NULL_POSITION);
			}
			(void) ch_forw_get();
		}
	}

	/*
	 * Scan backwards until we hit the beginning of the line.
	 */
	for (;;)
	{
		if (ABORT_SIGS())
		{
			null_line();
			return (NULL_POSITION);
		}
		c = ch_back_get();
		if (c == '\n')
		{
			/*
			 * This is the newline ending the previous line.
			 * We have hit the beginning of the line.
			 */
			new_pos = ch_tell() + 1;
			break;
		}
		if (c == EOI)
		{
			/*
			 * We have hit the beginning of the file.
			 * This must be the first line in the file.
			 * This must, of course, be the beginning of the line.
			 */
			new_pos = ch_tell();
			break;
		}
	}

	/*
	 * Now scan forwards from the beginning of this line.
	 * We keep discarding "printable lines" (based on screen width)
	 * until we reach the curr_pos.
	 *
	 * {{ This algorithm is pretty inefficient if the lines
	 *    are much longer than the screen width, 
	 *    but I don't know of any better way. }}
	 */
	if (ch_seek(new_pos))
	{
		null_line();
		return (NULL_POSITION);
	}
	endline = FALSE;
    loop:
	begin_new_pos = new_pos;
	prewind();
	plinenum(new_pos);
	(void) ch_seek(new_pos);

	do
	{
		c = ch_forw_get();
		if (c == EOI || ABORT_SIGS())
		{
			null_line();
			return (NULL_POSITION);
		}
		new_pos++;
		if (c == '\n')
		{
			endline = TRUE;
			break;
		}
		if (pappend(c, ch_tell()-1))
		{
			/*
			 * Got a full printable line, but we haven't
			 * reached our curr_pos yet.  Discard the line
			 * and start a new one.
			 */
			if (chopline || hshift > 0)
			{
				endline = TRUE;
				quit_if_one_screen = FALSE;
				break;
			}
			pdone(0);
			(void) ch_back_get();
			new_pos--;
			goto loop;
		}
	} while (new_pos < curr_pos);

	pdone(endline);

	return (begin_new_pos);
}

/*
 * Set attnpos.
 */
	public void
set_attnpos(pos)
	POSITION pos;
{
	int c;

	if (pos != NULL_POSITION)
	{
		if (ch_seek(pos))
			return;
		for (;;)
		{
			c = ch_forw_get();
			if (c == EOI)
				return;
			if (c != '\n' && c != '\r')
				break;
			pos++;
		}
	}
	start_attnpos = pos;
	for (;;)
	{
		c = ch_forw_get();
		pos++;
		if (c == EOI || c == '\n' || c == '\r')
			break;
	}
	end_attnpos = pos;
}
