!	$NetBSD: hksboo.com,v 1.2 1998/01/05 20:51:59 perry Exp $
!
! Load 'boot.' and boot 4.3BSD.
!
! rk07 drive type boot to single user mode
!
!
SET SNAP ON		! Enable ERROR_HALT snapshots
SET FBOX OFF		! System will turn on Fbox
INIT			! SRM processor init
UNJAM 			! UNJAM SBIA's and enable master sbia interrupts
INIT/PAMM		! INIT physical address memory map
DEPOSIT CSWP 8		! Turn off the cache - System will enable cache

DEPOSIT R10 3		! rk07 drive type - uba0 - drive 0
DEPOSIT R11 2		! Software boot flags (single user mode)

LOAD/START:0 BOOT.	! Load 'boot.' at memory location 0
START 2			! Start 'boot.' at the address 2
