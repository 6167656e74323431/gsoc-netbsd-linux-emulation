# $NetBSD: buildlink3.mk,v 1.6 2004/03/05 19:25:37 jlam Exp $

BUILDLINK_DEPTH:=		${BUILDLINK_DEPTH}+
PYTHON23_BUILDLINK3_MK:=	${PYTHON23_BUILDLINK3_MK}+

.if !empty(BUILDLINK_DEPTH:M+)
BUILDLINK_DEPENDS+=	python23
.endif

BUILDLINK_PACKAGES:=	${BUILDLINK_PACKAGES:Npython23}
BUILDLINK_PACKAGES+=	python23

.if !empty(PYTHON23_BUILDLINK3_MK:M+)
BUILDLINK_DEPENDS.python23+=	python23>=2.3
BUILDLINK_PKGSRCDIR.python23?=	../../lang/python23

.if defined(BUILDLINK_DEPMETHOD.python)
BUILDLINK_DEPMETHOD.python23?=	${BUILDLINK_DEPMETHOD.python}
.endif

BUILDLINK_INCDIRS.python23+=	include/python2.3
BUILDLINK_LIBDIRS.python23+=	lib/python2.3/config
BUILDLINK_TRANSFORM+=		l:python:python2.3

.endif	# PYTHON23_BUILDLINK3_MK

BUILDLINK_DEPTH:=     ${BUILDLINK_DEPTH:S/+$//}
