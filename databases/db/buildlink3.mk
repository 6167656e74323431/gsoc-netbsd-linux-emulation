# $NetBSD: buildlink3.mk,v 1.9 2004/02/05 07:17:14 jlam Exp $

BUILDLINK_DEPTH:=	${BUILDLINK_DEPTH}+
DB2_BUILDLINK3_MK:=	${DB2_BUILDLINK3_MK}+

.include "../../mk/bsd.prefs.mk"

.if !empty(DB2_BUILDLINK3_MK:M+)
BUILDLINK_PACKAGES+=		db
BUILDLINK_DEPENDS.db+=		db>=2.7.3
BUILDLINK_PKGSRCDIR.db?=	../../databases/db
.endif	# DB2_BUILDLINK3_MK

.if !empty(PREFER_PKGSRC:M[yY][eE][sS]) || \
    !empty(PREFER_PKGSRC:Mdb)
BUILDLINK_USE_BUILTIN.db=	NO
.endif

.if !defined(BUILDLINK_USE_BUILTIN.db)
BUILDLINK_USE_BUILTIN.db=	NO
.  if defined(USE_DB185)
.    if exists(/usr/include/db.h)
# NetBSD, Darwin
BUILDLINK_USE_BUILTIN.db=	YES
.    elif exists(/usr/include/db1/db.h)
# Linux
BUILDLINK_USE_BUILTIN.db=	YES
BUILDLINK_INCDIRS.db?=		include/db1
BUILDLINK_TRANSFORM+=		l:db:db1
.    endif
.  endif
MAKEFLAGS+=	BUILDLINK_USE_BUILTIN.db="${BUILDLINK_USE_BUILTIN.db}"
.endif

.if !empty(BUILDLINK_USE_BUILTIN.db:M[nN][oO])
.  if !empty(BUILDLINK_DEPTH:M+)
BUILDLINK_DEPENDS+=	db
.  endif
.endif

.if !empty(DB2_BUILDLINK3_MK:M+)
.  if !empty(BUILDLINK_USE_BUILTIN.db:M[nN][oO])
BUILDLINK_INCDIRS.db=	include/db2
BUILDLINK_TRANSFORM+=	l:db:db2
.  endif
.endif	# DB2_BUILDLINK3_MK

BUILDLINK_DEPTH:=	${BUILDLINK_DEPTH:S/+$//}
