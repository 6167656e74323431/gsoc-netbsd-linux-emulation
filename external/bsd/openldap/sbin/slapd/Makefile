# $NetBSD: Makefile,v 1.2 2021/12/29 18:13:43 christos Exp $

.include <bsd.init.mk>

SLAPD= ${LDAP_DISTDIR}/servers/slapd
.PATH:${SLAPD} ${SLAPD}/back-ldif ${SLAPD}/back-monitor \
    ${SLAPD}/overlays

CPPFLAGS+=-I${SLAPD} -I${SLAPD}/back-monitor

MAN=slapd.8 slapd.conf.5
PROG = slapd
TOOLS=slapadd slapcat slapdn slapindex slapmodify slappasswd slaptest \
    slapauth slapacl slapschema
.for tool in ${TOOLS}
LINKS+= ${BINDIR}/slapd ${BINDIR}/${tool}
MAN+=${tool}.8
.endfor

SRCS += \
	main.c globals.c bconfig.c config.c daemon.c \
	connection.c search.c filter.c add.c cr.c \
	attr.c entry.c backend.c result.c operation.c \
	dn.c compare.c modify.c delete.c modrdn.c ch_malloc.c \
	value.c ava.c bind.c unbind.c abandon.c filterentry.c \
	phonetic.c acl.c str2filter.c aclparse.c init.c user.c \
	lock.c controls.c extended.c passwd.c proxyp.c \
	schema.c schema_check.c schema_init.c schema_prep.c \
	schemaparse.c ad.c at.c mr.c syntax.c oc.c saslauthz.c \
	oidm.c starttls.c index.c sets.c referral.c root_dse.c \
	sasl.c module.c mra.c mods.c sl_malloc.c zn_malloc.c limits.c \
	operational.c matchedValues.c cancel.c syncrepl.c \
	backglue.c backover.c ctxcsn.c ldapsync.c frontend.c \
	slapadd.c slapcat.c slapcommon.c slapdn.c slapindex.c \
	slappasswd.c slaptest.c slapauth.c slapacl.c component.c \
	aci.c txn.c slapschema.c slapmodify.c

SRCS+=	backends.c

PROGDPLIBS+= \
	back_ldif ${.CURDIR}/../../lib/slapd/back-ldif \
	back_mdb ${.CURDIR}/../../lib/slapd/back-mdb \
	back_monitor ${.CURDIR}/../../lib/slapd/back-monitor \
	back_relay ${.CURDIR}/../../lib/slapd/back-relay \
	overlays ${.CURDIR}/../../lib/slapd/overlays \
	lunicode ${.CURDIR}/../../lib/liblunicode \
	rewrite ${.CURDIR}/../../lib/librewrite 

__makeman: .USE
	${_MKTARGET_CREATE}
	${TOOL_SED} \
	    -e s@LOCALSTATEDIR@/var@g \
	    -e s@SYSCONFDIR@/etc/openldap@g \
	    -e s@DATADIR@/usr/share@g \
	    -e s@SBINDIR@/usr/sbin@g \
	    -e s@BINDIR@/usr/bin@g \
	    -e s@LIBDIR@/usr/lib@g \
	    -e s@LIBEXECDIR@/usr/sbin@g \
	    -e s@MODULEDIR@/usr/lib/openldap@g \
	    -e s@ETCDIR@/etc/openldap@g ${.ALLSRC} > ${.TARGET}

.for man in ${MAN}
${man}: ${LDAP_DISTDIR}/doc/man/man${man:E}/${man} __makeman
.endfor

.include <bsd.prog.mk>
