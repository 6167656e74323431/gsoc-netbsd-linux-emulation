!	$NetBSD: upsboo.cmd,v 1.2 1998/01/05 20:52:13 perry Exp $
!
! BOOTSTRAP ON UP, LEAVING SINGLE USER
!
SET DEF HEX
SET DEF LONG
SET REL:0
HALT
UNJAM
INIT
LOAD BOOT
D R10 2		! DEVICE CHOICE 2=UP
D R11 2		! 2= RB_SINGLE
START 2
