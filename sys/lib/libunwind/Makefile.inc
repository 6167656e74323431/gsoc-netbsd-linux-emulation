#	$NetBSD: Makefile.inc,v 1.14 2021/11/22 16:41:32 thorpej Exp $

.PATH:	${NETBSDSRCDIR}/sys/lib/libunwind

SRCS+=	libunwind.cxx \
	unwind_registers.S

INCS+=	unwind.h

COPTS.libunwind.cxx+=	${${ACTIVE_CXX} == "gcc":? -std=c++0x : -std=c++11 }
COPTS.libunwind.cxx+=	-funwind-tables -fno-rtti
COPTS.libunwind.cxx+=	-fno-exceptions -fvisibility=hidden
COPTS.libunwind.cxx+=	-Wno-old-style-cast
CPPFLAGS.libunwind.cxx+=-I${NETBSDSRCDIR}/sys/lib/libunwind

.if ${LIBC_MACHINE_CPU} == "arm"
COPTS.libunwind.cxx+=	${${ACTIVE_CC} == "gcc":? -mfpu=vfp3 :}
AFLAGS.unwind_registers.S+=	${${ACTIVE_CC} == "clang":? -mfpu=vfp3 :}
.endif
