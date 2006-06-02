# $NetBSD: apachever.mk,v 1.1 2006/06/02 18:27:57 joerg Exp $
#
# This Makefile fragment handles Apache dependencies and make variables,
# and is meant to be included by packages that require Apache either at
# build-time or at run-time.  apache.mk will:
#
#	* set PKG_APACHE to the name of the apache web server used
#
#	* add a full dependency on the apache server
#
#	* optionally add a full dependency on apr
#
# The available user variables are:
#
# PKG_APACHE_DEFAULT is a user-settable variable whose value is the default
#	apache server to use.  Possible values are apache13 and apache2.
#   If there is already a version of apache installed this will have no
#   effect.
#
# The available makefile variables are:
#
# PKG_APACHE_ACCEPTED is a package-settable list of servers that may be used as
#	possible dependencies for the package.  Possible values are the same as
#   for PKG_APACHE_DEFAULT.
#
# USE_APR is used to note that the package requires the Apache Portable
#   runtime to build and execute.  This is only takes effect if apache2
#   is chosen (by this file) as the web server to use.  This adds a full
#   dependency on apr.
#

.if !defined(APACHEVER_MK)
APACHEVER_MK=	# defined

.include "../../mk/bsd.prefs.mk"

PKG_APACHE_DEFAULT?=	# empty

_PKG_APACHES?=	apache13 apache2

.if defined(PKG_APACHE_ACCEPTED)
.  for _ap_ in ${PKG_APACHE_ACCEPTED}
.    if !empty(_PKG_APACHES:M${_ap_})
_PKG_APACHE_ACCEPTED+=	${PKG_APACHE_ACCEPTED:M${_ap_}}
.    endif
.  endfor
.endif

_PKG_APACHE_ACCEPTED?=	${_PKG_APACHES}

# Set the default apache for this platform.
#
.if !empty(PKG_APACHE_DEFAULT)
_PKG_APACHE_DEFAULT=	${PKG_APACHE_DEFAULT}
.endif
.if !defined(_PKG_APACHE_DEFAULT)
_PKG_APACHE_DEFAULT?=	apache2
.endif

_APACHE_PKGBASE.apache13=	apache-1\*
_APACHE_PKGBASE.apache2=	apache-2\*

# Mark the acceptable apaches and check which apache packages are installed.
.for _ap_ in ${_PKG_APACHE_ACCEPTED}
_PKG_APACHE_OK.${_ap_}=	yes
_PKG_APACHE_INSTALLED.${_ap_}!= \
	if ${PKG_INFO} -qe ${_APACHE_PKGBASE.${_ap_}}; then		\
		${ECHO} yes;						\
	else								\
		${ECHO} no;						\
	fi
.endfor

# Use one of the installed apaches,...
#
.if !defined(_PKG_APACHE)
.  for _ap_ in ${_PKG_APACHE_ACCEPTED}
.    if !empty(_PKG_APACHE_INSTALLED.${_ap_}:M[yY][eE][sS])
_PKG_APACHE?=			${_ap_}
.    else
_PKG_APACHE_FIRSTACCEPTED?=	${_ap_}
.    endif
.  endfor
.endif
#
# ...otherwise, prefer the default one if it's accepted,...
#
.if !defined(_PKG_APACHE)
.  if defined(_PKG_APACHE_OK.${_PKG_APACHE_DEFAULT}) && \
      !empty(_PKG_APACHE_OK.${_PKG_APACHE_DEFAULT}:M[yY][eE][sS])
_PKG_APACHE=	${_PKG_APACHE_DEFAULT}
.  endif
.endif
#
# ...otherwise, just use the first accepted apache.
#
.if !defined(_PKG_APACHE)
.  if defined(_PKG_APACHE_FIRSTACCEPTED)
_PKG_APACHE=	${_PKG_APACHE_FIRSTACCEPTED}
.  endif
.endif
#
# If there are no acceptable apaches, then generate an error.
#
.if !defined(_PKG_APACHE)
# force an error
PKG_FAIL_REASON=	"no acceptable apache found"
_PKG_APACHE=		"none"
.endif

.if ${_PKG_APACHE} == "apache13"
_APACHE_PKGSRCDIR=	../../www/apache
_APACHE_PKG_PREFIX=	ap13
.elif ${_PKG_APACHE} == "apache2"
_APACHE_PKGSRCDIR=	../../www/apache2
_APACHE_BL_SRCDIR=	${_APACHE_PKGSRCDIR}
_APACHE_PKG_PREFIX=	ap2
.endif

_APACHE_BL_SRCDIR?=	../../www/apache

# PKG_APACHE is a publicly readable variable containing the name of the server
#	we will be using.
#
PKG_APACHE:=		${_PKG_APACHE}
APACHE_PKG_PREFIX:=	${_APACHE_PKG_PREFIX}
BUILD_DEFS+=		PKG_APACHE

.endif	# APACHEVER_MK
