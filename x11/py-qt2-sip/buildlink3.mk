# $NetBSD: buildlink3.mk,v 1.2 2004/10/03 00:18:37 tv Exp $

BUILDLINK_DEPTH:=		${BUILDLINK_DEPTH}+
PY_QT2_SIP_BUILDLINK3_MK:=	${PY_QT2_SIP_BUILDLINK3_MK}+

.include "../../lang/python/pyversion.mk"

.if !empty(BUILDLINK_DEPTH:M+)
BUILDLINK_DEPENDS+=	pyqt2sip
.endif

BUILDLINK_PACKAGES:=	${BUILDLINK_PACKAGES:Npyqt2sip}
BUILDLINK_PACKAGES+=	pyqt2sip

.if !empty(PY_QT2_SIP_BUILDLINK3_MK:M+)
BUILDLINK_DEPENDS.pyqt2sip+=	${PYPKGPREFIX}-qt2-sip-[0-9]*
BUILDLINK_RECOMMENDED.pyqt2sip+=	${PYPKGPREFIX}-qt2-sip>=3.1nb1
BUILDLINK_PKGSRCDIR.pyqt2sip?=	../../x11/py-qt2-sip
.endif	# PY_QT2_SIP_BUILDLINK3_MK

BUILDLINK_DEPTH:=     ${BUILDLINK_DEPTH:S/+$//}
