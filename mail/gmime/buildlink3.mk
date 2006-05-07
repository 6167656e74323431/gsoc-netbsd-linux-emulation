# $NetBSD: buildlink3.mk,v 1.9 2006/05/07 18:22:41 recht Exp $

BUILDLINK_DEPTH:=	${BUILDLINK_DEPTH}+
GMIME_BUILDLINK3_MK:=	${GMIME_BUILDLINK3_MK}+

.if !empty(BUILDLINK_DEPTH:M+)
BUILDLINK_DEPENDS+=	gmime
.endif

BUILDLINK_PACKAGES:=	${BUILDLINK_PACKAGES:Ngmime}
BUILDLINK_PACKAGES+=	gmime

.if !empty(GMIME_BUILDLINK3_MK:M+)
BUILDLINK_API_DEPENDS.gmime+=	gmime>=2.1.7
BUILDLINK_PKGSRCDIR.gmime?=	../../mail/gmime
.endif	# GMIME_BUILDLINK3_MK

.include "../../devel/glib2/buildlink3.mk"

BUILDLINK_DEPTH:=     ${BUILDLINK_DEPTH:S/+$//}
