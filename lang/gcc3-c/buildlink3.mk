# $NetBSD: buildlink3.mk,v 1.5 2004/03/05 19:25:36 jlam Exp $

BUILDLINK_DEPTH:=	${BUILDLINK_DEPTH}+
GCC3C_BUILDLINK3_MK:=	${GCC3C_BUILDLINK3_MK}+

.include "../../mk/bsd.prefs.mk"

.if !empty(BUILDLINK_DEPTH:M+)
BUILDLINK_DEPENDS+=	gcc3c
.endif

BUILDLINK_PACKAGES:=	${BUILDLINK_PACKAGES:Ngcc3c}
BUILDLINK_PACKAGES+=	gcc3c

.if !empty(GCC3C_BUILDLINK3_MK:M+)
.  if defined(GCC3_INSTALLTO_SUBPREFIX)
#
# "gcc3" is the directory named in pkgsrc/lang/gcc3-c/Makefile.common"
# as GCC3_DEFAULT_SUBPREFIX.
#
.    if ${GCC3_INSTALLTO_SUBPREFIX} != "gcc3"
GCC3_PKGMODIF=	_${GCC3_INSTALLTO_SUBPREFIX}
.    endif
.  endif
BUILDLINK_DEPENDS.gcc3c+=	gcc3${GCC3_PKGMODIF}-c>=${_GCC_REQD}
BUILDLINK_PKGSRCDIR.gcc3c?=	../../lang/gcc3-c
BUILDLINK_LIBDIRS.gcc3c?=	\
	lib ${_GCC_ARCHDIR:S/^${BUILDLINK_PREFIX.gcc3c}\///}

# Packages that link against shared libraries need a full dependency.
.if defined(USE_GCC_SHLIB)
BUILDLINK_DEPMETHOD.gcc3c+=	full
.else
BUILDLINK_DEPMETHOD.gcc3c?=	build
.endif

.endif	# GCC3C_BUILDLINK3_MK

BUILDLINK_DEPTH:=	${BUILDLINK_DEPTH:S/+$//}
