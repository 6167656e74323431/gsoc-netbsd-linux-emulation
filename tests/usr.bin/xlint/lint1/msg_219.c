/*	$NetBSD: msg_219.c,v 1.6 2023/03/28 14:44:35 rillig Exp $	*/
# 3 "msg_219.c"


/* Test for message: concatenated strings are illegal in traditional C [219] */

/* lint1-flags: -t -w -X 351 */

char concat1[] = "one";
/* expect+1: warning: concatenated strings are illegal in traditional C [219] */
char concat2[] = "one" "two";
/* expect+2: warning: concatenated strings are illegal in traditional C [219] */
/* expect+1: warning: concatenated strings are illegal in traditional C [219] */
char concat3[] = "one" "two" "three";
/* expect+3: warning: concatenated strings are illegal in traditional C [219] */
/* expect+2: warning: concatenated strings are illegal in traditional C [219] */
/* expect+1: warning: concatenated strings are illegal in traditional C [219] */
char concat4[] = "one" "two" "three" "four";

char concat4lines[] =
	"one"
	/* expect+1: warning: concatenated strings are illegal in traditional C [219] */
	"two"
	/* expect+1: warning: concatenated strings are illegal in traditional C [219] */
	"three"
	/* expect+1: warning: concatenated strings are illegal in traditional C [219] */
	"four";
