#	Id: NEWS-OS.4.x,v 8.9 2002/03/21 23:59:25 gshapiro Exp

dnl	DO NOT EDIT THIS FILE.
dnl	Place personal settings in devtools/Site/site.config.m4

define(`confBEFORE', `limits.h')
define(`confMAPDEF', `-DNDBM')
define(`confLIBS', `-lmld')
define(`confMBINDIR', `/usr/lib')
define(`confSBINDIR', `/usr/etc')
define(`confUBINDIR', `/usr/ucb')
define(`confEBINDIR', `/usr/lib')
PUSHDIVERT(3)
limits.h:
	touch limits.h
POPDIVERT
