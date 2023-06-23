# $NetBSD$

GITHUB_RELEASE=	20230516
PKGNAME=	suse_ltp-${GITHUB_RELEASE}
DISTNAME=	ltp-full-${GITHUB_RELEASE}
CATEGORIES=	emulators
MASTER_SITES=	${MASTER_SITE_GITHUB:=linux-test-project/}
GITHUB_PROJECT=	ltp
EXTRACT_SUFX=	.tar.xz
LICENSE=	gnu-gpl-v2

MAINTAINER=	pkgsrc-users@NetBSD.org
COMMENT=	The Linux Test Project

LINUX_MAKE=	${EMULDIR}/usr/bin/make
LINUX_GCC=	${EMULDIR}/usr/bin/gcc

USE_TOOLS+=	perl
MAKE_PROGRAM=	${LINUX_MAKE}

# Despite the fact this package uses a GNU autoconf script, we don't
# want most of what GNU_CONFIGURE_DOES.
HAS_CONFIGURE=	yes
CONFIG_SHELL=	${EMULDIR}/bin/bash
CONFIGURE_ARGS+=	--prefix=${EMULDIR}/opt/ltp
CONFIGURE_ARGS+=	--build=x86_64-suse-linux-gnu
CONFIGURE_ARGS+=	--host=x86_64-suse-linux-gnu
CONFIGURE_ARGS+=	MAKE=${LINUX_MAKE}
CONFIGURE_ARGS+=	CC=${LINUX_GCC}
CONFIGURE_ARGS+=	CFLAGS=-I${EMULDIR}/usr/include

GENERATE_PLIST+=	cd ${DESTDIR}${PREFIX} && \
			${FIND} ${EMULSUBDIR}/opt/ltp -type f -print | ${SORT} ;

# LTP expects /dev/kmsg to be writeable... but no such node exists.
# Maybe this should be a change to MAKEDEV(?)
post-install:
	${MKDIR} ${DESTDIR}${EMULDIR}/dev
	${TOUCH} ${DESTDIR}${EMULDIR}/dev/kmsg

EMUL_PLATFORMS+=	linux-x86_64
EMUL_REQD=		suse>=15.5
EMUL_MODULES.linux=	devel

.include "../../mk/bsd.pkg.mk"
