# $NetBSD: buildlink3.mk,v 1.2 2011/08/31 19:57:50 abs Exp $

BUILDLINK_TREE+=	libmicrohttpd

.if !defined(LIBMICROHTTPD_BUILDLINK3_MK)
LIBMICROHTTPD_BUILDLINK3_MK:=

BUILDLINK_API_DEPENDS.libmicrohttpd+=	libmicrohttpd>=0.9.9
BUILDLINK_PKGSRCDIR.libmicrohttpd?=	../../www/libmicrohttpd

.include "../../security/gnutls/buildlink3.mk"
.include "../../security/libgcrypt/buildlink3.mk"
.endif # LIBMICROHTTPD_BUILDLINK3_MK

BUILDLINK_TREE+=	-libmicrohttpd
