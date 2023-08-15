.include <bsd.own.mk>

TESTSDIR=	${TESTSBASE}/compat/linux
TESTS_SH=	t_inotify

.PATH: ${.CURDIR}/arch/${MACHINE}

TC_PROGS=	h_inotify_init
TC_PROGS+=	h_inotify_directory
TC_PROGS+=	h_inotify_single_file
TC_PROGS+=	h_inotify_watch_change

LDFLAGS+=	-nostartfiles -static
CFLAGS+=	-I${.CURDIR}/../../../sys
CFLAGS+=	-I${.CURDIR}
CFLAGS+=	-D_STANDALONE

FILESDIR=	${TESTSDIR}

.for _P in ${TESTS_SH}
TESTS_SH_SRC_${_P}=	h_common.sh
TESTS_SH_SRC_${_P}+=	${_P}.sh
.endfor

.for _P in ${TC_PROGS}
PROGS+=			${_P}.out
SRCS.${_P}.out=		${_P}.c
SRCS.${_P}.out+=	h_linux.c
SRCS.${_P}.out+=	h_syscall.c
MAN.${_P}.out=		# empty
CLEANFILES+=		${_P}
FILES+=			${_P}
FILESMODE_${_P}=	${BINMODE}

proginstall-${_P}.out:
	# Do not install

${_P}: ${_P}.out
	cp ${_P}.out ${_P}
	${ELFEDIT} --output-osabi Linux ${_P}

realall: ${_P}
.endfor

CLEANFILES+=	${TESTS_SH}
CLEANFILES+=	Atffile

.include <bsd.test.mk>
