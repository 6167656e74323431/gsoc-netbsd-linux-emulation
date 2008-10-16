# $NetBSD: buildlink3.mk,v 1.1.1.1 2008/10/16 20:06:11 drochner Exp $

BUILDLINK_DEPTH:=		${BUILDLINK_DEPTH}+
PY_GDATA_BUILDLINK3_MK:=	${PY_GDATA_BUILDLINK3_MK}+

.include "../../lang/python/pyversion.mk"

.if ${BUILDLINK_DEPTH} == "+"
BUILDLINK_DEPENDS+=	py-gdata
.endif

BUILDLINK_PACKAGES:=	${BUILDLINK_PACKAGES:Npy-gdata}
BUILDLINK_PACKAGES+=	py-gdata
BUILDLINK_ORDER:=	${BUILDLINK_ORDER} ${BUILDLINK_DEPTH}py-gdata

.if ${PY_GDATA_BUILDLINK3_MK} == "+"
BUILDLINK_API_DEPENDS.py-gdata+=	${PYPKGPREFIX}-gdata>=1.2.1
BUILDLINK_PKGSRCDIR.py-gdata?=	../../www/py-gdata
.endif	# PY_GDATA_BUILDLINK3_MK

BUILDLINK_DEPTH:=		${BUILDLINK_DEPTH:S/+$//}
