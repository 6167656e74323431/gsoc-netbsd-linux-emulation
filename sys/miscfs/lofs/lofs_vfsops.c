/*
 * Copyright (c) 1992 The Regents of the University of California
 * Copyright (c) 1990, 1992 Jan-Simon Pendry
 * All rights reserved.
 *
 * This code is derived from software donated to Berkeley by
 * Jan-Simon Pendry.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * From:
 *	Id: lofs_vfsops.c,v 4.1 1993/12/17 10:47:45 jsp Rel
 *
 *	$Id: lofs_vfsops.c,v 1.2 1994/01/05 15:11:51 cgd Exp $
 */

/*
 * Loopback Filesystem
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/malloc.h>
#include <miscfs/lofs/lofs.h>

#if 0
/*
 * Allocate a new unique fsid
 */
getnewfsid(mp, mtype)
	struct mount *mp;
	int mtype;
{
static u_short xxxfs_mntid;

	fsid_t tfsid;

	mp->mnt_stat.f_fsid.val[0] = makedev(nblkdev + 11, 0);	/* XXX */
	mp->mnt_stat.f_fsid.val[1] = MOUNT_LOFS;
	if (xxxfs_mntid == 0)
		++xxxfs_mntid;
	tfsid.val[0] = makedev(nblkdev, xxxfs_mntid);
	tfsid.val[1] = mtype;
	while (getvfs(&tfsid)) {
#ifdef DIAGNOSTIC
		printf("mntid %d in use\n", xxxfs_mntid);
#endif
		tfsid.val[0]++;
		xxxfs_mntid++;
	}
	mp->mnt_stat.f_fsid.val[0] = tfsid.val[0];
}
#endif

/*
 * Mount loopback copy of existing name space
 */
lofs_mount(mp, path, data, ndp, p)
	struct mount *mp;
	char *path;
	caddr_t data;
	struct nameidata *ndp;
	struct proc *p;
{
	int error = 0;
	struct lofs_args args;
	struct vnode *vp;
	struct vnode *rootvp;
	struct lofsmount *amp;
	u_int size;

#ifdef LOFS_DIAGNOSTIC
	printf("lofs_mount(mp = %x)\n", mp);
#endif

	/*
	 * Update is a no-op
	 */
	if (mp->mnt_flag & MNT_UPDATE) {
		return (EOPNOTSUPP);
		/* return VFS_MOUNT(VFSTOLOFS(mp)->looped_vfs, path, data, ndp, p);*/
	}

	/*
	 * Get argument
	 */
	if (error = copyin(data, (caddr_t)&args, sizeof(struct lofs_args)))
		return (error);

	/*
	 * Find target node
	 */
	ndp->ni_nameiop = LOOKUP | FOLLOW | WANTPARENT | LOCKLEAF;
	ndp->ni_segflg = UIO_USERSPACE;
	ndp->ni_dirp = args.target;
	if (error = namei(ndp, p))
		return (error);

	/*
	 * Sanity check on target vnode
	 */
	vp = ndp->ni_vp;
#ifdef LOFS_DIAGNOSTIC
	printf("vp = %x, check for VDIR...\n", vp);
#endif
	vrele(ndp->ni_dvp);
	ndp->ni_dvp = 0;

	if (vp->v_type != VDIR) {
		vput(vp);
		return (EINVAL);
	}

#ifdef LOFS_DIAGNOSTIC
	printf("mp = %x\n", mp);
#endif

	amp = (struct lofsmount *) malloc(sizeof(struct lofsmount),
				M_UFSMNT, M_WAITOK);	/* XXX */

	/*
	 * Save reference to underlying target FS
	 */
	amp->looped_vfs = vp->v_mount;

	/*
	 * Save reference.  Each mount also holds
	 * a reference on the root vnode.
	 */
	error = make_lofs(mp, ndp);
	/*
	 * Unlock the node (either the target or the alias)
	 */
	VOP_UNLOCK(ndp->ni_vp);
	/*
	 * Make sure the node alias worked
	 */
	if (error) {
		vrele(ndp->ni_vp);
		free(amp, M_UFSMNT);	/* XXX */
		return (error);
	}

	/*
	 * Keep a held reference to the root vnode.
	 * It is vrele'd in lofs_unmount.
	 */
	rootvp = ndp->ni_vp;
	rootvp->v_flag |= VROOT;
	amp->rootvp = rootvp;
	if (LOFSVP(rootvp)->v_mount->mnt_flag & MNT_LOCAL)
		mp->mnt_flag |= MNT_LOCAL;
	mp->mnt_data = (qaddr_t) amp;
	getnewfsid(mp, MOUNT_LOFS);

	(void) copyinstr(path, mp->mnt_stat.f_mntonname, MNAMELEN - 1, &size);
	bzero(mp->mnt_stat.f_mntonname + size, MNAMELEN - size);
	(void) copyinstr(args.target, mp->mnt_stat.f_mntfromname, MNAMELEN - 1, 
	    &size);
	bzero(mp->mnt_stat.f_mntfromname + size, MNAMELEN - size);
#ifdef LOFS_DIAGNOSTIC
	printf("lofs_mount: target %s, alias at %s\n",
		mp->mnt_stat.f_mntfromname, mp->mnt_stat.f_mntonname);
#endif
	return (0);
}

/*
 * VFS start.  Nothing needed here - the start routine
 * on the underlying filesystem will have been called
 * when that filesystem was mounted.
 */
lofs_start(mp, flags, p)
	struct mount *mp;
	int flags;
	struct proc *p;
{
	return (0);
	/* return VFS_START(VFSTOLOFS(mp)->looped_vfs, flags, p); */
}

/*
 * Free reference to looped FS
 */
lofs_unmount(mp, mntflags, p)
	struct mount *mp;
	int mntflags;
	struct proc *p;
{
	struct vnode *rootvp = VFSTOLOFS(mp)->rootvp;
	int error;
	int flags = 0;
	extern int doforce;

#ifdef LOFS_DIAGNOSTIC
	printf("lofs_unmount(mp = %x)\n", mp);
#endif

	if (mntflags & MNT_FORCE) {
		/* lofs can never be rootfs so don't check for it */
		if (!doforce)
			return (EINVAL);
		flags |= FORCECLOSE;
	}

	/*
	 * Clear out buffer cache.  I don't think we
	 * ever get anything cached at this level at the
	 * moment, but who knows...
	 */
	mntflushbuf(mp, 0); 
	if (mntinvalbuf(mp, 1))
		return (EBUSY);
	if (rootvp->v_usecount > 1)
		return (EBUSY);
	if (error = vflush(mp, rootvp, flags))
		return (error);

#ifdef LOFS_DIAGNOSTIC
	/*
	 * Flush any remaining vnode references
	 */
	lofs_flushmp(mp);
#endif

#ifdef LOFS_DIAGNOSTIC
	vprint("alias root of target", rootvp);
#endif	 
	/*
	 * Release reference on underlying root vnode
	 */
	vrele(rootvp);
	/*
	 * And blow it away for future re-use
	 */
	vgone(rootvp);
	/*
	 * Finally, throw away the lofsmount structure
	 */
	free(mp->mnt_data, M_UFSMNT);	/* XXX */
	mp->mnt_data = 0;
	return 0;
}

lofs_root(mp, vpp)
	struct mount *mp;
	struct vnode **vpp;
{
	struct vnode *vp;

#ifdef LOFS_DIAGNOSTIC
	printf("lofs_root(mp = %x, vp = %x->%x)\n", mp,
			VFSTOLOFS(mp)->rootvp,
			LOFSVP(VFSTOLOFS(mp)->rootvp)
			);
#endif

	/*
	 * Return locked reference to root.
	 */
	vp = VFSTOLOFS(mp)->rootvp;
	VREF(vp);
	VOP_LOCK(vp);
	*vpp = vp;
	return 0;
}

lofs_quotactl(mp, cmd, uid, arg, p)
	struct mount *mp;
	int cmd;
	uid_t uid;
	caddr_t arg;
	struct proc *p;
{
	return VFS_QUOTACTL(VFSTOLOFS(mp)->looped_vfs, cmd, uid, arg, p);
}

lofs_statfs(mp, sbp, p)
	struct mount *mp;
	struct statfs *sbp;
	struct proc *p;
{
	int error;
	struct statfs mstat;

#ifdef LOFS_DIAGNOSTIC
	printf("lofs_statfs(mp = %x, vp = %x->%x)\n", mp,
			VFSTOLOFS(mp)->rootvp,
			LOFSVP(VFSTOLOFS(mp)->rootvp)
			);
#endif

	bzero(&mstat, sizeof(mstat));

	error = VFS_STATFS(VFSTOLOFS(mp)->looped_vfs, &mstat, p);
	if (error)
		return (error);

	/* now copy across the "interesting" information and fake the rest */
	sbp->f_type = mstat.f_type;
	sbp->f_flags = mstat.f_flags;
	sbp->f_fsize = mstat.f_fsize;
	sbp->f_bsize = mstat.f_bsize;
	sbp->f_blocks = mstat.f_blocks;
	sbp->f_bfree = mstat.f_bfree;
	sbp->f_bavail = mstat.f_bavail;
	sbp->f_files = mstat.f_files;
	sbp->f_ffree = mstat.f_ffree;
	if (sbp != &mp->mnt_stat) {
		bcopy(&mp->mnt_stat.f_fsid, &sbp->f_fsid, sizeof(sbp->f_fsid));
		bcopy(mp->mnt_stat.f_mntonname, sbp->f_mntonname, MNAMELEN);
		bcopy(mp->mnt_stat.f_mntfromname, sbp->f_mntfromname, MNAMELEN);
	}
	return (0);
}

lofs_sync(mp, waitfor)
struct mount *mp;
int waitfor;
{
	return (0);
}

lofs_fhtovp(mp, fhp, vpp)
	struct mount *mp;
	struct fid *fhp;
	struct vnode **vpp;
{
	return VFS_FHTOVP(VFSTOLOFS(mp)->looped_vfs, fhp, vpp);
}

lofs_vptofh(vp, fhp)
	struct vnode *vp;
	struct fid *fhp;
{
	return VFS_VPTOFH(LOFSVP(vp), fhp);
}

int lofs_init __P((void));

struct vfsops lofs_vfsops = {
	lofs_mount,
	lofs_start,
	lofs_unmount,
	lofs_root,
	lofs_quotactl,
	lofs_statfs,
	lofs_sync,
	lofs_fhtovp,
	lofs_vptofh,
	lofs_init,
};
