/*	$NetBSD: env.c,v 1.10 1998/10/12 22:15:47 aidan Exp $	*/

/* Copyright 1988,1990,1993,1994 by Paul Vixie
 * All rights reserved
 *
 * Distribute freely, except: don't remove my name from the source or
 * documentation (don't take credit for my work), mark your changes (don't
 * get me blamed for your possible bugs), don't alter or remove this
 * notice.  May be sold if buildable source is provided to buyer.  No
 * warrantee of any kind, express or implied, is included with this
 * software; use at your own risk, responsibility for damages (if any) to
 * anyone resulting from the use of this software rests entirely with the
 * user.
 *
 * Send bug reports, bug fixes, enhancements, requests, flames, etc., and
 * I'll try to keep a version up to date.  I can be reached as follows:
 * Paul Vixie          <paul@vix.com>          uunet!decwrl!vixie!paul
 */

#include <sys/cdefs.h>
#if !defined(lint) && !defined(LINT)
#if 0
static char rcsid[] = "Id: env.c,v 2.7 1994/01/26 02:25:50 vixie Exp";
#else
__RCSID("$NetBSD: env.c,v 1.10 1998/10/12 22:15:47 aidan Exp $");
#endif
#endif


#include "cron.h"
#include <string.h>

char **
env_init()
{
	char	**p = (char **) malloc(sizeof(char **));

	p[0] = NULL;
	return (p);
}


void
env_free(envp)
	char	**envp;
{
	char	**p;

	for (p = envp;  *p;  p++)
		free(*p);
	free(envp);
}


char **
env_copy(envp)
	char	**envp;
{
	int	count, i;
	char	**p;

	for (count = 0;  envp[count] != NULL;  count++)
		;
	p = (char **) malloc((count+1) * sizeof(char *));  /* 1 for the NULL */
	for (i = 0;  i < count;  i++)
		p[i] = strdup(envp[i]);
	p[count] = NULL;
	return (p);
}


char **
env_set(envp, envstr)
	char	**envp;
	char	*envstr;
{
	int	count, found;
	char	**p;

	/*
	 * count the number of elements, including the null pointer;
	 * also set 'found' to -1 or index of entry if already in here.
	 */
	found = -1;
	for (count = 0;  envp[count] != NULL;  count++) {
		if (!strcmp_until(envp[count], envstr, '='))
			found = count;
	}
	count++;	/* for the NULL */

	if (found != -1) {
		/*
		 * it exists already, so just free the existing setting,
		 * save our new one there, and return the existing array.
		 */
		free(envp[found]);
		envp[found] = strdup(envstr);
		return (envp);
	}

	/*
	 * it doesn't exist yet, so resize the array, move null pointer over
	 * one, save our string over the old null pointer, and return resized
	 * array.
	 */
	p = (char **) realloc((void *) envp,
			      (unsigned) ((count+1) * sizeof(char **)));
	p[count] = p[count-1];
	p[count-1] = strdup(envstr);
	return (p);
}


/* return	ERR = end of file
 *		FALSE = not an env setting (file was repositioned)
 *		TRUE = was an env setting
 */
int
load_env(envstr, f)
	char	*envstr;
	FILE	*f;
{
	long	filepos;
	int	fileline, len;
	char	*name, *val, *s;
	char	*space = NULL;

	filepos = ftell(f);
	fileline = LineNumber;
	skip_comments(f);
	if (EOF == get_string(envstr, MAX_ENVSTR, f, "\n"))
		return (ERR);

	Debug(DPARS, ("load_env, read <%s>\n", envstr))

	s = strchr(envstr, '=');
	if (s && (*envstr != '"' || *envstr == '\'')) {
		/*
		 * decide if this is an environment variable or not by
		 * checking for spaces in the middle of the variable name.
		 * (it could also be a crontab line of the form
		 * <min> <hour> <day> <month> <weekday> command flag=value)
		 */
		/* space before var name */
		for (space = envstr; space < s && isspace(*space); space++)
			;
		/* var name */
		for ( ; space < s && !isspace(*space); space++)
			;
		/* space after var name */
		for ( ; space < s && isspace(*space); space++)
			;
		/*
		 * space should equal s..  otherwise, this is not an
		 * environment set command.
		 */
	} else if (s && (*envstr == '"' || *envstr == '\'')) {
		/*
		 * allow quoting the environment variable name to contain
		 * spaces.  The close quote will have to exist before the
		 * '=' character.
		 */
		space = strchr(envstr+1, *envstr);
		if (!space || space > s) {
			Debug(DPARS, ("load_env, didn't get valid string"));
			fseek(f, filepos, 0);
			Set_LineNum(fileline);
			return (FALSE);
		}
		space++;
		while (space < s && isspace(*space))
			space++;
	}
	if (s != NULL && s != envstr && *space == '=') {
		/* XXX:
		 * The manpage says spaces around the '=' are ignored, but
		 * there's no code here to ignore them.
		 */
		*s++ = '\0';
		val = s;
		if (*envstr == '"' || *envstr == '\'') {
			space = strchr(envstr+1, *envstr);
			*space = 0;
			name = strdup(envstr+1);
		} else
			name = strdup(envstr);
	} else {
		Debug(DPARS, ("load_env, didn't get valid string"));
		fseek(f, filepos, 0);
		Set_LineNum(fileline);
		return (FALSE);
	}

	/*
	 * process value string
	 */
	if (*val) {
		len = strdtb(val);
		if (len >= 2 && (val[0] == '\'' || val[0] == '"') &&
		    val[len-1] == val[0]) {
			val[len-1] = '\0';
			val++;
		}
	}

	(void) snprintf(envstr, MAX_ENVSTR, "%s=%s", name, val);
	Debug(DPARS, ("load_env, <%s> <%s> -> <%s>\n", name, val, envstr))
	free(name);
	return (TRUE);
}


char *
env_get(name, envp)
	char	*name;
	char	**envp;
{
	int	len = strlen(name);
	char	*p, *q;

	while ((p = *envp++) != NULL) {
		if (!(q = strchr(p, '=')))
			continue;
		if ((q - p) == len && !strncmp(p, name, len))
			return (q+1);
	}
	return (NULL);
}
