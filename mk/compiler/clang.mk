# $NetBSD: clang.mk,v 1.17 2017/05/18 08:14:08 jperkin Exp $
#
# This is the compiler definition for the clang compiler.
#
# User-settable variables:
#
# CLANGBASE
#	The base directory where the compiler is installed.
#

.if !defined(COMPILER_CLANG_MK)
COMPILER_CLANG_MK=	defined

# Add the dependency on clang
# TODO: may be installed already, check for this
#TOOL_DEPENDS+= clang-[0-9]*:../../lang/clang

.include "../../mk/bsd.prefs.mk"

CLANGBASE?=		${LOCALBASE}
LANGUAGES.clang=	# empty

.if exists(${CLANGBASE}/bin/clang)
LANGUAGES.clang+=	c objc
_COMPILER_STRIP_VARS+=	CC
CCPATH=			${CLANGBASE}/bin/clang
PKG_CC:=		${CCPATH}
.endif

.if exists(${CLANGBASE}/bin/clang++)
LANGUAGES.clang+=	c++
_COMPILER_STRIP_VARS+=	CXX
CXXPATH=		${CLANGBASE}/bin/clang++
PKG_CXX:=		${CXXPATH}
.endif

.if exists(${CLANGBASE}/bin/clang-cpp)
CPPPATH=		${CLANGBASE}/bin/clang-cpp
PKG_CPP:=		${CPPPATH}
.endif

.if exists(${CCPATH})
CC_VERSION_STRING!=	${CCPATH} -v 2>&1
CC_VERSION!=		${CCPATH} --version 2>&1 | ${SED} -n "s/^.* version /clang-/p" 
.else
CC_VERSION_STRING?=	${CC_VERSION}
CC_VERSION?=		clang
.endif

_COMPILER_ABI_FLAG.32=	-m32
_COMPILER_ABI_FLAG.64=	-m64
_COMPILER_LD_FLAG=	-Wl,
_LINKER_RPATH_FLAG=	-R
_COMPILER_RPATH_FLAG=	${_COMPILER_LD_FLAG}${_LINKER_RPATH_FLAG}

# The user can choose the level of stack smashing protection.
.if ${PKGSRC_USE_SSP} == "all"
_SSP_CFLAGS=		-fstack-protector-all
.else
_SSP_CFLAGS=		-fstack-protector
.endif

# _LANGUAGES.<compiler> is ${LANGUAGES.<compiler>} restricted to the
# ones requested by the package in USE_LANGUAGES.
#
_LANGUAGES.clang=	# empty
.for _lang_ in ${USE_LANGUAGES}
_LANGUAGES.clang+=	${LANGUAGES.clang:M${_lang_}}
.endfor

PKGSRC_FORTRAN?=g95

.if !empty(PKGSRC_FORTRAN) && (!empty(USE_LANGUAGES:Mfortran) || !empty(USE_LANGUAGES:Mfortran77))
.  include "../../mk/compiler/${PKGSRC_FORTRAN}.mk"
.endif

_WRAP_EXTRA_ARGS.CC+=	-Qunused-arguments
CWRAPPERS_APPEND.cc+=	-Qunused-arguments
_WRAP_EXTRA_ARGS.CXX+=	-Qunused-arguments
CWRAPPERS_APPEND.cxx+=	-Qunused-arguments

CLANG_NO_VALUE_PROPAGATION_PASS=	-O0

.endif	# COMPILER_CLANG_MK
