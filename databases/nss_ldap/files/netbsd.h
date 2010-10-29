/* $NetBSD: netbsd.h,v 1.2 2010/10/29 13:47:11 adam Exp $ */

#undef HAVE_NSSWITCH_H
#define HAVE_NSS_H

#ifndef _NSS_LDAP_NETBSD_H
#define _NSS_LDAP_NETBSD_H
enum nss_status {
	NSS_STATUS_SUCCESS,
	NSS_STATUS_NOTFOUND,
	NSS_STATUS_UNAVAIL,
	NSS_STATUS_TRYAGAIN,
	NSS_STATUS_RETURN
};
#endif /* _NSS_LDAP_NETBSD_H */
