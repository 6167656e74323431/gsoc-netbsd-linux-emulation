#	$NetBSD: Makefile,v 1.2 2022/08/30 13:40:37 riastradh Exp $

.include <bsd.own.mk>

DIST=	${NETBSDSRCDIR}/external/ibm-public/postfix/dist/conf
.PATH:	${DIST}

FILESDIR=	${PFIX_ETCDIR}

# These two .cf files are the only ones absolutely needed. It is not
# clear if we should be installing things like the transport and
# virtual file, etc. I contend we shouldn't, since they contain no
# real information at all, just the man page sources, and are not
# needed by default.
#
CONFIGFILES=	main.cf master.cf README
FILESMODE=	644
FILESMODE_README=444

.include <bsd.prog.mk>
