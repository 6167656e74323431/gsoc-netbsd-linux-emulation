# $NetBSD: buildlink3.mk,v 1.4 2015/11/22 23:56:52 wiz Exp $

BUILDLINK_TREE+=	notmuch

.if !defined(NOTMUCH_BUILDLINK3_MK)
NOTMUCH_BUILDLINK3_MK:=

BUILDLINK_API_DEPENDS.notmuch+=	notmuch>=0.16
BUILDLINK_ABI_DEPENDS.notmuch+=	notmuch>=0.21
BUILDLINK_PKGSRCDIR.notmuch?=	../../mail/notmuch

.include "../../mail/gmime/buildlink3.mk"
.include "../../textproc/xapian/buildlink3.mk"
.endif	# NOTMUCH_BUILDLINK3_MK

BUILDLINK_TREE+=	-notmuch
