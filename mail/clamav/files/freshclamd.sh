#!@RCD_SCRIPTS_SHELL@
#
# $NetBSD: freshclamd.sh,v 1.1 2004/10/30 10:23:02 grant Exp $
#
# PROVIDE: freshclamd
# REQUIRE: DAEMON LOGIN clamd


name="freshclamd"
command="@PREFIX@/bin/freshclam"
required_files="@PKG_SYSCONFDIR@/freshclam.conf"
pidfile="@VARBASE@/run/${name}.pid"
sig_stop="KILL"
freshclamd_user="@CLAMAV_USER@"
command_args="-d -c 2"

. /etc/rc.subr

load_rc_config $name
run_rc_command "$1"

if [ "$1" != "stop" ]; then
	echo $(check_process $command) > $pidfile
fi
