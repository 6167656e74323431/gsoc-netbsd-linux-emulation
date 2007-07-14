/*	$NetBSD: compat_mount.c,v 1.1 2007/07/14 15:53:04 dsl Exp $	*/


#include <sys/cdefs.h>
#if defined(LIBC_SCCS) && !defined(lint)
__RCSID("$NetBSD: compat_mount.c,v 1.1 2007/07/14 15:53:04 dsl Exp $");
#endif /* LIBC_SCCS and not lint */

#define __LIBC12_SOURCE__

#include <sys/types.h>
#include <sys/mount.h>

__warn_references(mount,
    "warning: reference to compatibility mount(); include <sys/mount.h> to generate correct reference")

int	mount(const char *, const char *, int, void *);
int	__mount50(const char *, const char *, int, void *, size_t);

/*
 * Convert old mount() call to new calling convention
 * The kernel will treat length 0 as 'default for the fs'.
 */
int
mount(const char *type, const char *dir, int flags, void *data)
{
	return __mount50(type, dir, flags, data, 0);
}
