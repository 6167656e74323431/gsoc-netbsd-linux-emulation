# $NetBSD: buildlink3.mk,v 1.6 2004/03/26 02:27:52 wiz Exp $

BUILDLINK_DEPTH:=		${BUILDLINK_DEPTH}+
CYRUS_SASL_BUILDLINK3_MK:=	${CYRUS_SASL_BUILDLINK3_MK}+

.if !empty(BUILDLINK_DEPTH:M+)
BUILDLINK_DEPENDS+=	cyrus-sasl
.endif

BUILDLINK_PACKAGES:=	${BUILDLINK_PACKAGES:Ncyrus-sasl}
BUILDLINK_PACKAGES+=	cyrus-sasl

.if !empty(CYRUS_SASL_BUILDLINK3_MK:M+)
BUILDLINK_DEPENDS.cyrus-sasl+=		cyrus-sasl>=2.1.12
BUILDLINK_RECOMMENDED.cyrus-sasl?=	cyrus-sasl>=2.1.17nb2
BUILDLINK_PKGSRCDIR.cyrus-sasl?=	../../security/cyrus-sasl2
.endif	# CYRUS_SASL_BUILDLINK3_MK

BUILDLINK_DEPTH:=	${BUILDLINK_DEPTH:S/+$//}
