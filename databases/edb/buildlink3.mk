# $NetBSD: buildlink3.mk,v 1.2 2004/10/03 00:13:18 tv Exp $

BUILDLINK_DEPTH:=	${BUILDLINK_DEPTH}+
EDB_BUILDLINK3_MK:=	${EDB_BUILDLINK3_MK}+

.if !empty(BUILDLINK_DEPTH:M+)
BUILDLINK_DEPENDS+=	edb
.endif

BUILDLINK_PACKAGES:=	${BUILDLINK_PACKAGES:Nedb}
BUILDLINK_PACKAGES+=	edb

.if !empty(EDB_BUILDLINK3_MK:M+)
BUILDLINK_DEPENDS.edb+=	edb>=1.0.3nb3
BUILDLINK_RECOMMENDED.edb+=	edb>=1.0.3nb4
BUILDLINK_PKGSRCDIR.edb?=	../../databases/edb
.endif	# EDB_BUILDLINK3_MK

BUILDLINK_DEPTH:=     ${BUILDLINK_DEPTH:S/+$//}
