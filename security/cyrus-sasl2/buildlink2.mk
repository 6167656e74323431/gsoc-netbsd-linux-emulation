# $NetBSD: buildlink2.mk,v 1.7 2004/03/26 02:27:52 wiz Exp $

.if !defined(CYRUS_SASL_BUILDLINK2_MK)
CYRUS_SASL_BUILDLINK2_MK=	# defined

BUILDLINK_PACKAGES+=			cyrus-sasl
BUILDLINK_DEPENDS.cyrus-sasl?=		cyrus-sasl>=2.1.12
BUILDLINK_RECOMMENDED.cyrus-sasl?=	cyrus-sasl>=2.1.17nb2
BUILDLINK_PKGSRCDIR.cyrus-sasl?=	../../security/cyrus-sasl2

EVAL_PREFIX+=	BUILDLINK_PREFIX.cyrus-sasl=cyrus-sasl
BUILDLINK_PREFIX.cyrus-sasl_DEFAULT=	${LOCALBASE}
BUILDLINK_FILES.cyrus-sasl=	include/sasl/*
BUILDLINK_FILES.cyrus-sasl+=	lib/libsasl2.*

BUILDLINK_TARGETS+=	cyrus-sasl-buildlink

cyrus-sasl-buildlink: _BUILDLINK_USE

.endif	# CYRUS_SASL_BUILDLINK2_MK
