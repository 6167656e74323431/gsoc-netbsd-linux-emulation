# $NetBSD: buildlink3.mk,v 1.3 2004/10/03 00:14:51 tv Exp $

BUILDLINK_DEPTH:=	${BUILDLINK_DEPTH}+
GLITZ_BUILDLINK3_MK:=	${GLITZ_BUILDLINK3_MK}+

.if !empty(BUILDLINK_DEPTH:M+)
BUILDLINK_DEPENDS+=	glitz
.endif

BUILDLINK_PACKAGES:=	${BUILDLINK_PACKAGES:Nglitz}
BUILDLINK_PACKAGES+=	glitz

.if !empty(GLITZ_BUILDLINK3_MK:M+)
BUILDLINK_DEPENDS.glitz+=	glitz>=0.1.2
BUILDLINK_RECOMMENDED.glitz+=	glitz>=0.1.2nb1
BUILDLINK_PKGSRCDIR.glitz?=	../../graphics/glitz
.endif	# GLITZ_BUILDLINK3_MK

.include "../../graphics/MesaLib/buildlink3.mk"

BUILDLINK_DEPTH:=     ${BUILDLINK_DEPTH:S/+$//}
