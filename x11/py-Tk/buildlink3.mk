# $NetBSD: buildlink3.mk,v 1.7 2007/07/13 10:42:44 drochner Exp $

BUILDLINK_DEPTH:=	${BUILDLINK_DEPTH}+
PYTK_BUILDLINK3_MK:=	${PYTK_BUILDLINK3_MK}+

.include "../../lang/python/pyversion.mk"

.if !empty(BUILDLINK_DEPTH:M+)
BUILDLINK_DEPENDS+=	pytk
.endif

BUILDLINK_PACKAGES:=	${BUILDLINK_PACKAGES:Npytk}
BUILDLINK_PACKAGES+=	pytk
BUILDLINK_ORDER:=	${BUILDLINK_ORDER} ${BUILDLINK_DEPTH}pytk

.if !empty(PYTK_BUILDLINK3_MK:M+)
BUILDLINK_API_DEPENDS.pytk+=	${PYPKGPREFIX}-Tk-[0-9]*
BUILDLINK_ABI_DEPENDS.pytk?=	${PYPKGPREFIX}-Tk>=0nb4
BUILDLINK_PKGSRCDIR.pytk?=	../../x11/py-Tk
.endif	# PYTK_BUILDLINK3_MK

.include "../../x11/tk/buildlink3.mk"

BUILDLINK_DEPTH:=	${BUILDLINK_DEPTH:S/+$//}
