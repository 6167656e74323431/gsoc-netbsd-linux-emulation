#	$NetBSD: bsd.kmod.mk,v 1.1 1996/08/22 20:33:02 explorer Exp $

#
# This shouldn't be hard coded...  [XXX MLG]
#
KERN=	/sys/kern

.if exists(${.CURDIR}/../Makefile.inc)
.include "${.CURDIR}/../Makefile.inc"
.endif

.SUFFIXES: .out .o .c .cc .cxx .C .y .l .s .S

.include <bsd.own.mk>

KMODOWN?=	bin
KMODGRP?=	bin
KMODMODE?=	444
KMODDIR?=	/usr/lkm

CFLAGS+=	${COPTS} -D_KERNEL -D_LKM -I. -I/sys

DPSRCS+= ${SRCS:M*.h}
OBJS+=	${SRCS:N*.h:R:S/$/.o/g}

.if !defined(PROG)
PROG=	${KMOD}.o
.endif

${PROG}: ${DPSRCS} ${OBJS} ${DPADD}
	${LD} -r ${LDFLAGS} -o tmp.o ${OBJS}
	mv tmp.o ${.TARGET}

.if	!defined(MAN)
MAN=	${KMOD}.4
.endif

.MAIN: all
all: ${PROG} _SUBDIRUSE

.if !target(clean)
clean: _SUBDIRUSE
	rm -f a.out [Ee]rrs mklog core *.core \
		${PROG} ${OBJS} ${LOBJS} ${CLEANFILES}
.endif

cleandir: _SUBDIRUSE clean

#
# if no beforedepend target is defined, generate an empty target here
#
.if !target(beforedepend)
beforedepend:
.endif

#
# define various install targets
#
.if !target(install)
.if !target(beforeinstall)
beforeinstall:
.endif
.if !target(afterinstall)
afterinstall:
.endif

.if !target(realinstall)
realinstall:
	install ${COPY} -o ${KMODOWN} -g ${KMODGRP} -m ${KMODMODE} \
		${PROG} ${DESTDIR}${KMODDIR}
.endif

install: maninstall _SUBDIRUSE
.if defined(LINKS) && !empty(LINKS)
	@set ${LINKS}; \
	while test $$# -ge 2; do \
		l=${DESTDIR}$$1; \
		shift; \
		t=${DESTDIR}$$1; \
		shift; \
		${ECHO} $$t -\> $$l; \
		rm -f $$t; \
		ln $$l $$t; \
	done; true
.endif

maninstall: afterinstall
afterinstall: realinstall
realinstall: beforeinstall
.endif

.if !target(lint)
lint: ${LOBJS}
.if defined(LOBJS) && !empty(LOBJS)
	@${LINT} ${LINTFLAGS} ${LDFLAGS:M-L*} ${LOBJS} ${LDADD}
.endif
.endif

.if !target(load)
load:	${PROG}
	/sbin/modload -o ${KMOD} -e${KMOD}_lkmentry ${PROG}
.endif

.if !target(unload)
unload: ${PROG}
	/sbin/modunload -n ${KMOD}
.endif

.include <bsd.dep.mk>

.if !defined(NOMAN)
.include <bsd.man.mk>
.endif

.include <bsd.obj.mk>
.include <bsd.dep.mk>
.include <bsd.subdir.mk>
.include <bsd.sys.mk>
