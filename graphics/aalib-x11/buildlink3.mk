# $NetBSD: buildlink3.mk,v 1.5 2004/03/05 19:25:12 jlam Exp $

BUILDLINK_DEPTH:=		${BUILDLINK_DEPTH}+
AALIB_X11_BUILDLINK3_MK:=	${AALIB_X11_BUILDLINK3_MK}+

.if !empty(BUILDLINK_DEPTH:M+)
BUILDLINK_DEPENDS+=		aalib-x11
.endif

BUILDLINK_PACKAGES:=	${BUILDLINK_PACKAGES:Naalib-x11}
BUILDLINK_PACKAGES+=	aalib-x11

.if !empty(AALIB_X11_BUILDLINK3_MK:M+)
BUILDLINK_DEPENDS.aalib-x11+=	aalib-x11>=1.4.0.4nb1
BUILDLINK_PKGSRCDIR.aalib-x11?=	../../graphics/aalib-x11

BUILDLINK_FILES.aalib-x11=	include/aalib-x11.h
BUILDLINK_TRANSFORM.aalib-x11+=	-e "s|/aalib-x11.h|/aalib.h|g"
BUILDLINK_TRANSFORM+=		l:aa:aa-x11

AALIB_CONFIG=		${BUILDLINK_PREFIX.aalib-x11}/bin/aalib-x11-config
CONFIGURE_ENV+=		AALIB_CONFIG="${AALIB_CONFIG}"
MAKE_ENV+=		AALIB_CONFIG="${AALIB_CONFIG}"

.endif	# AALIB_X11_BUILDLINK3_MK

BUILDLINK_DEPTH:=	${BUILDLINK_DEPTH:S/+$//}
