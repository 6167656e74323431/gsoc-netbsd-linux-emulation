# $NetBSD: buildlink3.mk,v 1.1 2007/10/29 12:41:17 uebayasi Exp $
#

BUILDLINK_DEPTH:=	${BUILDLINK_DEPTH}+
SEMANTIC_BUILDLINK3_MK:=	${SEMANTIC_BUILDLINK3_MK}+

.if ${BUILDLINK_DEPTH} == "+"
BUILDLINK_DEPENDS+=	semantic
.endif

BUILDLINK_PACKAGES:=	${BUILDLINK_PACKAGES:Nsemantic}
BUILDLINK_PACKAGES+=	semantic
BUILDLINK_ORDER:=	${BUILDLINK_ORDER} ${BUILDLINK_DEPTH}semantic

.if ${SEMANTIC_BUILDLINK3_MK} == "+"
BUILDLINK_API_DEPENDS.semantic+=	${EMACS_PKGNAME_PREFIX}semantic>=10
BUILDLINK_PKGSRCDIR.semantic?=	../../devel/semantic
.endif	# SEMANTIC_BUILDLINK3_MK

BUILDLINK_CONTENTS_FILTER.semantic=	${EGREP} '.*\.el$$|.*\.elc$$'

BUILDLINK_DEPTH:=	${BUILDLINK_DEPTH:S/+$//}
