/*	$NetBSD: opt_pipe.h,v 1.1 2008/10/15 13:00:40 pooka Exp $	*/

#undef PIPE_SOCKETPAIR /* would need uipc_usrreq.c */
#define PIPE_NODIRECT
