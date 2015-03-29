# $NetBSD: options.mk,v 1.3 2015/03/29 18:00:31 rodent Exp $

PKG_OPTIONS_VAR=	PKG_OPTIONS.redmine

PKG_OPTIONS_REQUIRED_GROUPS=	db
PKG_OPTIONS_GROUP.db=		mysql pgsql sqlite3
PKG_SUPPORTED_OPTIONS+=		unicorn

PKG_SUGGESTED_OPTIONS=	mysql unicorn

.include "../../mk/bsd.options.mk"

PLIST_VARS+=	mysql pgsql sqlite3

###
### Use mysql, pgsql, or sqlite3 backend
###
MYSQL_DISTFILE=		mysql2-0.3.18.gem
PGSQL_DISTFILE=		pg-0.18.1.gem
SQLITE3_DISTFILE=	sqlite3-1.3.10.gem

.if make (distinfo) || make (mdi) # for checksum generation only
DISTFILES+=	${MYSQL_DISTFILE}
DISTFILES+=	${PGSQL_DISTFILE}
DISTFILES+=	${SQLITE3_DISTFILE}
.elif !empty(PKG_OPTIONS:Mmysql)
DISTFILES+=	${MYSQL_DISTFILE}
.include "../../mk/mysql.buildlink3.mk"
PLIST_SRC=	${PLIST_SRC_DFLT} PLIST.mysql
.elif !empty(PKG_OPTIONS:Mpgsql)
DISTFILES+=	${PGSQL_DISTFILE}
.include "../../mk/pgsql.buildlink3.mk"
CHECK_INTERPRETER_SKIP+=	${RM_DIR}/gems/gems/pg-*/spec/*
CHECK_INTERPRETER_SKIP+=	${RM_DIR}/gems/gems/pg-*/spec/pg/*
PLIST_SRC=	${PLIST_SRC_DFLT} PLIST.pgsql
.elif !empty(PKG_OPTIONS:Msqlite3)
DISTFILES+=	${SQLITE3_DISTFILE}
.include "../../databases/sqlite3/buildlink3.mk"
PLIST_SRC=	${PLIST_SRC_DFLT} PLIST.sqlite3
.endif

###
### Use Unicorn web server
###
.if !empty(PKG_OPTIONS:Municorn) || make (distinfo) || make (mdi)
PLIST_SRC+=	PLIST.unicorn
DISTFILES+=	kgio-2.9.3.gem \
		raindrops-0.13.0.gem \
		unicorn-4.8.3.gem

SUBST_CLASSES+=			prefix
SUBST_STAGE.prefix=		pre-configure
SUBST_MESSAGE.prefix=		Setting PREFIX.
SUBST_FILES.prefix=		${WRKDIR}/unicorn.rb
SUBST_VARS.prefix+=		PREFIX

RCD_SCRIPTS+=	redmine_unicorn

CONF_FILES+=	${EGDIR}/unicorn.rb.example \
		${PREFIX}/${RM_DIR}/app/config/unicorn.rb

post-extract:
	${CP} ${FILESDIR}/unicorn.rb ${WRKDIR}/unicorn.rb

.PHONY: unicorn-post-install
unicorn-post-install:
	${CP} ${WRKDIR}/unicorn.rb \
		${DESTDIR}${PREFIX}/share/examples/redmine/unicorn.rb.example
	${CP} ${FILESDIR}/Gemfile.local \
		${DESTDIR}${PREFIX}/share/redmine/app
.endif
.PHONY: unicorn-post-install
unicorn-post-install:
# nothing
