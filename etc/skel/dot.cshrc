#	$NetBSD: dot.cshrc,v 1.2 2002/09/29 14:52:57 grant Exp $
#csh .cshrc file

alias h		history 25
alias j		jobs -l
alias la	ls -a
alias lf	ls -FA
alias ll	ls -lA
alias su	su -m

setenv	EDITOR	vi
setenv	VISUAL	${EDITOR}
setenv	EXINIT	'set autoindent'
setenv	PAGER	more

set path = (~/bin /bin /sbin /usr/{bin,sbin,X11R6/bin,pkg/{,s}bin,games} \
	    /usr/local/{,s}bin)

if ($?prompt) then
	# An interactive shell -- set some stuff up
	set filec
	set history = 1000
	set ignoreeof
	set mail = (/var/mail/$USER)
	set mch = `hostname -s`
	set prompt = "${mch:q}: {\!} "
endif
