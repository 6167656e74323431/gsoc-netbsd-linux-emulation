#	$NetBSD: Makefile,v 1.9 2022/10/28 09:43:58 wiz Exp $

.include <bsd.own.mk>

PROG=	xauth
SRCS=	xauth.c gethost.c process.c parsedpy.c

CPPFLAGS+=		-DRETSIGTYPE=void -DPACKAGE_VERSION=\"1.0.8\"
CPPFLAGS+= 		-DHAVE_STRLCPY
CPPFLAGS+= 		-DHAVE_REALLOCARRAY
CPPFLAGS.gethost.c=	${X11FLAGS.CONNECTION}
CPPFLAGS.parsedpy.c=	${X11FLAGS.CONNECTION}

.if (${USE_INET6} != "no")
CPPFLAGS+=      	-DIPv6
.endif

CWARNFLAGS.clang=	-Wno-empty-body
COPTS.parsedpy.c+=	${GCC_NO_STRINGOP_OVERFLOW}

LDADD+=	-lXau -lXmuu -lXt -lSM -lICE -lXext -lX11
DPADD+=	${LIBXAU} ${LIBXMUU} ${LIBXT} ${LIBSM} ${LIBICE} ${LIBXEXT} ${LIBX11}

.PATH:	${X11SRCDIR.${PROG}} ${X11SRCDIR.${PROG}}/man

.include <bsd.own.mk>

USE_SSP:=	no

.include <bsd.x11.mk>
.include <bsd.prog.mk>
