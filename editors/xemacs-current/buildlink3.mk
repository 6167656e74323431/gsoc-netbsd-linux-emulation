# $NetBSD: buildlink3.mk,v 1.1 2007/10/29 12:40:03 uebayasi Exp $
#

BUILDLINK_DEPTH:=	${BUILDLINK_DEPTH}+
XEMACS_BUILDLINK3_MK:=	${XEMACS_BUILDLINK3_MK}+

.if ${BUILDLINK_DEPTH} == "+"
BUILDLINK_DEPENDS+=	xemacs
.endif

BUILDLINK_PACKAGES:=	${BUILDLINK_PACKAGES:Nxemacs}
BUILDLINK_PACKAGES+=	xemacs
BUILDLINK_ORDER:=	${BUILDLINK_ORDER} ${BUILDLINK_DEPTH}xemacs

.if ${XEMACS_BUILDLINK3_MK} == "+"
.include "../../mk/emacs.mk"
BUILDLINK_API_DEPENDS.xemacs+=	${_EMACS_REQD.xemacs215}
BUILDLINK_PKGSRCDIR.xemacs?=	${_EMACS_DEP.xemacs215}
.endif	# XEMACS_BUILDLINK3_MK

BUILDLINK_CONTENTS_FILTER.xemacs=	${EGREP} '.*\.el$$|.*\.elc$$'

BUILDLINK_DEPTH:=	${BUILDLINK_DEPTH:S/+$//}
