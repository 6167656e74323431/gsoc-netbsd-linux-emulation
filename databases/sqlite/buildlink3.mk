# $NetBSD: buildlink3.mk,v 1.2 2004/10/03 00:13:23 tv Exp $

BUILDLINK_DEPTH:=	${BUILDLINK_DEPTH}+
SQLITE_BUILDLINK3_MK:=	${SQLITE_BUILDLINK3_MK}+

.if !empty(BUILDLINK_DEPTH:M+)
BUILDLINK_DEPENDS+=	sqlite
.endif

BUILDLINK_PACKAGES:=	${BUILDLINK_PACKAGES:Nsqlite}
BUILDLINK_PACKAGES+=	sqlite

.if !empty(SQLITE_BUILDLINK3_MK:M+)
BUILDLINK_DEPENDS.sqlite+=	sqlite>=2.8.0
BUILDLINK_RECOMMENDED.sqlite+=	sqlite>=2.8.15nb2
BUILDLINK_PKGSRCDIR.sqlite?=	../../databases/sqlite
.endif	# SQLITE_BUILDLINK3_MK

BUILDLINK_DEPTH:=     ${BUILDLINK_DEPTH:S/+$//}
