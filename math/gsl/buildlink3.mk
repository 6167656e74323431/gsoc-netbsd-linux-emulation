# $NetBSD: buildlink3.mk,v 1.3 2004/10/03 00:12:56 tv Exp $

BUILDLINK_DEPTH:=	${BUILDLINK_DEPTH}+
GSL_BUILDLINK3_MK:=	${GSL_BUILDLINK3_MK}+

.if !empty(BUILDLINK_DEPTH:M+)
BUILDLINK_DEPENDS+=	gsl
.endif

BUILDLINK_PACKAGES:=	${BUILDLINK_PACKAGES:Ngsl}
BUILDLINK_PACKAGES+=	gsl

.if !empty(GSL_BUILDLINK3_MK:M+)
BUILDLINK_DEPENDS.gsl+=		gsl>=1.4
BUILDLINK_RECOMMENDED.gsl+=	gsl>=1.5nb1
BUILDLINK_PKGSRCDIR.gsl?=	../../math/gsl
.endif	# GSL_BUILDLINK3_MK

BUILDLINK_DEPTH:=     ${BUILDLINK_DEPTH:S/+$//}
