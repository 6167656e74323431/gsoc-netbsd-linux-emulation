# $NetBSD$

PKGNAME=	suse_devel-${SUSE_VERSION}
CATEGORIES=	emulators
RPMPKGS+=	cpp7-7.5.0+r278197-4.30.1.${SUSE_ARCH}
RPMPKGS+=	libasan4-7.5.0+r278197-4.30.1.${SUSE_ARCH}
RPMPKGS+=	libatomic1-12.2.1+git416-150000.1.7.1.${SUSE_ARCH}
RPMPKGS+=	libcilkrts5-7.5.0+r278197-4.30.1.${SUSE_ARCH}
RPMPKGS+=	libgomp1-12.2.1+git416-150000.1.7.1.${SUSE_ARCH}
RPMPKGS+=	libisl15-0.18-1.443.${SUSE_ARCH}
RPMPKGS+=	libitm1-12.2.1+git416-150000.1.7.1.${SUSE_ARCH}
RPMPKGS+=	liblsan0-12.2.1+git416-150000.1.7.1.${SUSE_ARCH}
RPMPKGS+=	libmpc3-1.1.0-1.47.${SUSE_ARCH}
RPMPKGS+=	libmpfr6-4.0.2-3.3.1.${SUSE_ARCH}
RPMPKGS+=	libmpx2-8.2.1+r264010-150000.1.6.4.${SUSE_ARCH}
RPMPKGS+=	libmpxwrappers2-8.2.1+r264010-150000.1.6.4.${SUSE_ARCH}
RPMPKGS+=	libtsan0-11.3.0+git1637-150000.1.11.2.${SUSE_ARCH}
RPMPKGS+=	libubsan0-7.5.0+r278197-4.30.1.${SUSE_ARCH}
RPMPKGS+=	zlib-devel-1.2.13-150500.2.3.${SUSE_ARCH}
RPMPKGS+=	glibc-devel-2.31-150300.46.1.${SUSE_ARCH}
RPMPKGS+=	linux-glibc-devel-5.14-150500.10.15.${SUSE_ARCH}
RPMPKGS+=	gcc7-7.5.0+r278197-4.30.1.${SUSE_ARCH}
RPMPKGS+=	make-4.2.1-7.3.2.${SUSE_ARCH}

MAINTAINER=	pkgsrc-users@NetBSD.org
COMMENT=	Linux compatibility package for gcc

EMUL_MODULES.linux=	binutils

post-install:
	${LN} -sf ${EMULDIR}/usr/bin/gcc-7 ${DESTDIR}${EMULDIR}/usr/bin/gcc

.include "../../emulators/suse15_linux/Makefile.common"
.include "../../mk/bsd.pkg.mk"
