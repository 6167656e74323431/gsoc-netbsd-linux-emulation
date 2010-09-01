#!/bin/sh
#
#	$NetBSD: makerumpif.sh,v 1.5 2010/09/01 19:32:11 pooka Exp $
#
# Copyright (c) 2009 Antti Kantee.  All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

#
# This reads a rump component interface description and creates:
#  1: rump private prototypes for internal calls
#  2: public prototypes for calls outside of rump
#  3: public interface implementations which run the rump scheduler
#     and call the private interface
#

usage ()
{

	echo "usage: $0 spec"
	exit 1
}

boom ()
{

	echo $*
	exit 1
}

[ $# != 1 ] && usage

MYDIR=`pwd`
while [ ! -f Makefile.rump  ]; do
	[ `pwd` = '/' ] && boom Could not find rump topdir.
	cd ..
done
RUMPTOP="`pwd`"
cd ${MYDIR}

sed -e '
:again
	/\\$/{
		N
		s/[ 	]*\\\n[ 	]*/ /
		b again
	}
' ${1} | awk -F\| -v rumptop=${RUMPTOP} '
function fileheaders(file, srcstr)
{
	printf("/*\t$NetBSD: makerumpif.sh,v 1.5 2010/09/01 19:32:11 pooka Exp $\t*/\n\n") > file
	printf("/*\n * Automatically generated.  DO NOT EDIT.\n") > file
	genstr = "$NetBSD: makerumpif.sh,v 1.5 2010/09/01 19:32:11 pooka Exp $"
	gsub("\\$", "", genstr)
	printf(" * from: %s\n", srcstr) > file
	printf(" * by:   %s\n", genstr) > file
	printf(" */\n") > file
}

function die(str)
{

	print str
	exit(1)
}

NR == 1 {
	sub(";[^\\$]*\\$", "")
	sub("\\$", "")
	fromstr = $0
	next
}

$1 == "NAME"{myname = $2;next}
$1 == "PUBHDR"{pubhdr = rumptop "/" $2;print pubhdr;next}
$1 == "PRIVHDR"{privhdr = rumptop "/" $2;print privhdr;next}
$1 == "WRAPPERS"{gencalls = rumptop "/" $2;print gencalls;next}

/^;/{next}
/\\$/{sub("\\\n", "");getline nextline;$0 = $0 nextline}
/^[ \t]*$/{next}
{
	if (NF != 3 && NF != 4) {
		die("error: unexpected number of fields\n")
	}
	if (NF == 4) {
		if ($4 == "WEAK")
			isweak = 1
		else
			die("error: unexpected fourth field");
	} else {
		isweak = 0
	}
	if (!myname)
		die("name not specified");
	if (!pubhdr)
		die("public header not specified");
	if (!privhdr)
		die("private header not specified");
	if (!gencalls)
		die("wrapper file not specified");

	if (!once) {
		fileheaders(pubhdr, fromstr)
		fileheaders(privhdr, fromstr)
		fileheaders(gencalls, fromstr)
		once = 1

		pubfile = pubhdr
		sub(".*/", "", pubfile)

		privfile = privhdr
		sub(".*/", "", privfile)

		printf("\n") > pubhdr
		printf("\n") > privhdr

		printf("\n#include <sys/cdefs.h>\n") > gencalls
		printf("#include <sys/systm.h>\n") > gencalls
		printf("\n#include <rump/rump.h>\n") > gencalls
		printf("#include <rump/%s>\n\n", pubfile) > gencalls
		printf("#include \"rump_private.h\"\n", privfile) > gencalls
		printf("#include \"%s\"\n\n", privfile) > gencalls
		printf("void __dead rump_%s_unavailable(void);\n",	\
		    myname) > gencalls
		printf("void __dead\nrump_%s_unavailable(void)\n{\n",	\
		    myname) > gencalls
		printf("\n\tpanic(\"%s interface unavailable\");\n}\n",	\
		    myname) > gencalls
	}

	funtype = $1
	sub("[ \t]*$", "", funtype)
	funname = $2
	sub("[ \t]*$", "", funname)
	funargs = $3
	sub("[ \t]*$", "", funargs)

	printf("%s rump_pub_%s(%s);\n", funtype, funname, funargs) > pubhdr
	printf("%s rump_%s(%s);\n", funtype, funname, funargs) > privhdr

	if (funtype == "void")
		voidret = 1
	else
		voidret = 0
	if (funargs == "void")
		voidarg = 1
	else
		voidarg = 0

	printf("\n%s\nrump_pub_%s(", funtype, funname) > gencalls
	if (!voidarg) {
		narg = split(funargs, argv, ",")
		for (i = 1; i <= narg; i++) {
			sub(" *", "", argv[i])
			if (match(argv[i], "\\*$") != 0)
				printf("%sarg%d", argv[i], i) > gencalls
			else
				printf("%s arg%d", argv[i], i) > gencalls
			if (i != narg)
				printf(", ") > gencalls
		}
	} else {
		narg = 0
		printf("void") > gencalls
	}
	printf(")\n{\n") > gencalls

	if (!voidret) {
		printf("\t%s rv;\n", funtype) > gencalls
	}
	printf("\n\trump_schedule();\n\t") > gencalls
	if (!voidret)
		printf("rv = ") > gencalls
	printf("rump_%s(", funname) > gencalls
	for (i = 1; i <= narg; i++) {
		printf("arg%i", i) > gencalls
		if (i < narg)
			printf(", ") > gencalls
	}
	printf(");\n\trump_unschedule();\n") > gencalls
	if (!voidret)
		printf("\n\treturn rv;\n") > gencalls
	printf("}\n") > gencalls
	if (isweak)
		printf("__weak_alias(rump_%s,rump_%s_unavailable);\n", \
		    funname, myname) > gencalls
}'
