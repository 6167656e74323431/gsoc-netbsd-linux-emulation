.include <bsd.own.mk>

TESTSDIR=	${TESTSBASE}/compat/linux
TESTS_SH=	t_inotify

TC_PROGS=	h_inotify_init
TC_PROGS+=	h_inotify_directory
TC_PROGS+=	h_inotify_single_file
TC_PROGS+=	h_inotify_watch_change

.PATH: ${.CURDIR}/arch/${MACHINE}

LDFLAGS+=	-nostartfiles -static
CFLAGS+=	-I${.CURDIR}/../../../sys
CFLAGS+=	-I${.CURDIR}
CFLAGS+=	-D_STANDALONE

FILESDIR=	${TESTSDIR}

.for _P in ${TESTS_SH}
.if ${MACHINE} == "amd64"
TESTS_SH_SRC_${_P}=	h_common.sh
.else
TESTS_SH_SRC_${_P}=	h_not_supported.sh
.endif
TESTS_SH_SRC_${_P}+=	${_P}.sh
.endfor

.for _P in ${TC_PROGS}
CLEANFILES+=		${_P}
FILES+=			${_P}

.if ${MACHINE} == "amd64"
PROGS+=			${_P}.tmp
SRCS.${_P}.tmp=		${_P}.c
SRCS.${_P}.tmp+=	h_linux.c
SRCS.${_P}.tmp+=	h_syscall.c
MAN.${_P}.tmp=		# empty
FILESMODE_${_P}=	${BINMODE}

proginstall-${_P}.tmp:
	# Do not install

${_P}: ${_P}.tmp
	${ELFEDIT} --output-osabi Linux ${.TARGET}.tmp
	${MV} ${.TARGET}.tmp ${.TARGET}
.else
${_P}:
	echo '' > ${.TARGET}
.endif

realall: ${_P}
.endfor

CLEANFILES+=	${TESTS_SH}
CLEANFILES+=	Atffile

.include <bsd.test.mk>
