/*	$NetBSD: tmpfs_subr.c,v 1.4 2005/09/13 14:29:18 yamt Exp $	*/

/*
 * Copyright (c) 2005 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Julio M. Merino Vidal.
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
 *        This product includes software developed by the NetBSD
 *        Foundation, Inc. and its contributors.
 * 4. Neither the name of The NetBSD Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Efficient memory file system supporting functions.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: tmpfs_subr.c,v 1.4 2005/09/13 14:29:18 yamt Exp $");

#include <sys/param.h>
#include <sys/dirent.h>
#include <sys/event.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/systm.h>
#include <sys/swap.h>
#include <sys/vnode.h>

#include <uvm/uvm.h>

#include <miscfs/specfs/specdev.h>
#include <fs/tmpfs/tmpfs.h>
#include <fs/tmpfs/tmpfs_fifoops.h>
#include <fs/tmpfs/tmpfs_specops.h>
#include <fs/tmpfs/tmpfs_vnops.h>

/* --------------------------------------------------------------------- */

int
tmpfs_alloc_node(struct tmpfs_mount *tmp, enum vtype type,
    uid_t uid, gid_t gid, mode_t mode, struct tmpfs_node *parent,
    char *target, dev_t rdev, struct proc *p, struct tmpfs_node **node)
{
	struct tmpfs_node *nnode;

	/* If the root directory of the 'tmp' file system is not yet
	 * allocated, this must be the request to do it. */
	KASSERT(IMPLIES(tmp->tm_root == NULL, parent == NULL && type == VDIR));

	KASSERT(IFF(type == VLNK, target != NULL));
	KASSERT(IFF(type == VBLK || type == VCHR, rdev != VNOVAL));

	KASSERT(uid != VNOVAL && gid != VNOVAL && mode != VNOVAL);

	nnode = NULL;
	if (LIST_EMPTY(&tmp->tm_nodes_avail)) {
		KASSERT(tmp->tm_nodes_last <= tmp->tm_nodes_max);
		if (tmp->tm_nodes_last == tmp->tm_nodes_max)
			return ENOSPC;

		nnode =
		    (struct tmpfs_node *)TMPFS_POOL_GET(&tmp->tm_node_pool, 0);
		if (nnode == NULL)
			return ENOSPC;
		nnode->tn_id = tmp->tm_nodes_last++;
		nnode->tn_gen = 0;
	} else {
		nnode = LIST_FIRST(&tmp->tm_nodes_avail);
		LIST_REMOVE(nnode, tn_entries);
		nnode->tn_gen++;
	}
	KASSERT(nnode != NULL);
	LIST_INSERT_HEAD(&tmp->tm_nodes_used, nnode, tn_entries);

	/* Generic initialization. */
	nnode->tn_type = type;
	nnode->tn_size = 0;
	nnode->tn_status = 0;
	nnode->tn_flags = 0;
	nnode->tn_links = 0;
	(void)nanotime(&nnode->tn_atime);
	nnode->tn_birthtime = nnode->tn_ctime = nnode->tn_mtime =
	    nnode->tn_atime;
	nnode->tn_uid = uid;
	nnode->tn_gid = gid;
	nnode->tn_mode = mode;
	nnode->tn_vnode = NULL;

	/* Type-specific initialization. */
	switch (nnode->tn_type) {
	case VBLK:
	case VCHR:
		nnode->tn_rdev = rdev;
		break;

	case VDIR:
		TAILQ_INIT(&nnode->tn_dir);
		nnode->tn_parent = (parent == NULL) ? nnode : parent;
		nnode->tn_readdir_lastn = 0;
		nnode->tn_readdir_lastp = NULL;
		nnode->tn_links++;
		nnode->tn_parent->tn_links++;
		break;

	case VFIFO:
		/* FALLTHROUGH */
	case VSOCK:
		break;

	case VLNK:
		KASSERT(strlen(target) < MAXPATHLEN);
		nnode->tn_link = tmpfs_str_pool_get(&tmp->tm_str_pool,
		    strlen(target), 0);
		if (nnode->tn_link == NULL) {
			nnode->tn_type = VNON;
			tmpfs_free_node(tmp, nnode);
			return ENOSPC;
		}
		strcpy(nnode->tn_link, target);
		nnode->tn_size = strlen(target);
		break;

	case VREG:
		nnode->tn_aobj = uao_create(INT32_MAX - PAGE_SIZE, 0);
		nnode->tn_aobj_pages = 0;
		break;

	default:
		KASSERT(0);
	}

	*node = nnode;
	return 0;
}

/* --------------------------------------------------------------------- */

void
tmpfs_free_node(struct tmpfs_mount *tmp, struct tmpfs_node *node)
{
	ino_t id;
	unsigned long gen;
	size_t pages;

	switch (node->tn_type) {
	case VNON:
		/* Do not do anything.  VNON is provided to let the
		 * allocation routine clean itself easily by avoiding
		 * duplicating code in it. */
		/* FALLTHROUGH */
	case VBLK:
		/* FALLTHROUGH */
	case VCHR:
		/* FALLTHROUGH */
	case VDIR:
		/* FALLTHROUGH */
	case VFIFO:
		/* FALLTHROUGH */
	case VSOCK:
		pages = 0;
		break;

	case VLNK:
		tmpfs_str_pool_put(&tmp->tm_str_pool, node->tn_link,
		    strlen(node->tn_link));
		pages = 0;
		break;

	case VREG:
		if (node->tn_aobj != NULL)
			uao_detach(node->tn_aobj);
		pages = node->tn_aobj_pages;
		break;

	default:
		KASSERT(0);
		pages = 0; /* Shut up gcc when !DIAGNOSTIC. */
		break;
	}

	tmp->tm_pages_used -= pages;

	LIST_REMOVE(node, tn_entries);
	id = node->tn_id;
	gen = node->tn_gen;
	memset(node, 0, sizeof(struct tmpfs_node));
	node->tn_id = id;
	node->tn_type = VNON;
	node->tn_gen = gen;
	LIST_INSERT_HEAD(&tmp->tm_nodes_avail, node, tn_entries);
}

/* --------------------------------------------------------------------- */

int
tmpfs_alloc_dirent(struct tmpfs_mount *tmp, struct tmpfs_node *node,
    const char *name, uint16_t len, struct tmpfs_dirent **de)
{
	struct tmpfs_dirent *nde;

	nde = (struct tmpfs_dirent *)TMPFS_POOL_GET(&tmp->tm_dirent_pool, 0);
	if (nde == NULL)
		return ENOSPC;

	nde->td_name = tmpfs_str_pool_get(&tmp->tm_str_pool, len, 0);
	if (nde->td_name == NULL) {
		TMPFS_POOL_PUT(&tmp->tm_dirent_pool, nde);
		return ENOSPC;
	}
	nde->td_namelen = len;
	memcpy(nde->td_name, name, len);
	nde->td_node = node;

	node->tn_links++;
	*de = nde;

	return 0;
}

/* --------------------------------------------------------------------- */

void
tmpfs_free_dirent(struct tmpfs_mount *tmp, struct tmpfs_dirent *de,
    boolean_t node_exists)
{
	if (node_exists) {
		struct tmpfs_node *node;

		node = de->td_node;

		KASSERT(node->tn_links > 0);
		node->tn_links--;
	}

	tmpfs_str_pool_put(&tmp->tm_str_pool, de->td_name, de->td_namelen);
	TMPFS_POOL_PUT(&tmp->tm_dirent_pool, de);
}

/* --------------------------------------------------------------------- */

int
tmpfs_alloc_vp(struct mount *mp, struct tmpfs_node *node, struct vnode **vpp)
{
	int error;
	struct vnode *nvp;
	struct vnode *vp;

	vp = NULL;

	if (node->tn_vnode != NULL) {
		vp = node->tn_vnode;
		vget(vp, LK_EXCLUSIVE | LK_RETRY);
		error = 0;
		goto out;
	}

	/* Get a new vnode and associate it with our node. */
	error = getnewvnode(VT_TMPFS, mp, tmpfs_vnodeop_p, &vp);
	if (error != 0)
		goto out;
	KASSERT(vp != NULL);

	error = vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
	if (error != 0) {
		vp->v_data = NULL;
		ungetnewvnode(vp);
		vp = NULL;
		goto out;
	}

	vp->v_data = node;
	vp->v_type = node->tn_type;

	/* Type-specific initialization. */
	switch (node->tn_type) {
	case VBLK:
		/* FALLTHROUGH */
	case VCHR:
		vp->v_op = tmpfs_specop_p;
		nvp = checkalias(vp, node->tn_rdev, mp);
		if (nvp != NULL) {
			/* Discard unneeded vnode, but save its inode. */
			nvp->v_data = vp->v_data;
			vp->v_data = NULL;

			/* XXX spec_vnodeops has no locking, so we have to
			 * do it explicitly. */
			VOP_UNLOCK(vp, 0);
			vp->v_op = spec_vnodeop_p;
			vp->v_flag &= ~VLOCKSWORK;
			vrele(vp);
			vgone(vp);

			/* Reinitialize aliased node. */
			vp = nvp;
			error = vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
			if (error != 0) {
				vp->v_data = NULL;
				vp = NULL;
				goto out;
			}
		}
		break;

	case VDIR:
		vp->v_flag = node->tn_parent == node ? VROOT : 0;
		break;

	case VFIFO:
		vp->v_op = tmpfs_fifoop_p;
		break;

	case VLNK:
		/* FALLTHROUGH */
	case VREG:
		/* FALLTHROUGH */
	case VSOCK:
		break;

	default:
		KASSERT(0);
	}

	uvm_vnp_setsize(vp, node->tn_size);

	error = 0;

out:
	*vpp = node->tn_vnode = vp;

	KASSERT(IFF(error == 0, *vpp != NULL && VOP_ISLOCKED(*vpp)));
	KASSERT(*vpp == node->tn_vnode);

	return error;
}

/* --------------------------------------------------------------------- */

void
tmpfs_free_vp(struct vnode *vp)
{
	struct tmpfs_node *node;

	node = VP_TO_TMPFS_NODE(vp);

	node->tn_vnode = NULL;
	vp->v_data = NULL;
}

/* --------------------------------------------------------------------- */

/* Allocates a new file of type 'type' and adds it to the parent directory
 * 'dvp'; this addition is done using the component name given in 'cnp'.
 * The ownership of the new file is automatically assigned based on the
 * credentials of the caller (through 'cnp'), the group is set based on
 * the parent directory and the mode is determined from the 'vap' argument.
 * If successful, *vpp holds a vnode to the newly created file and zero
 * is returned.  Otherwise *vpp is NULL and the function returns an
 * appropriate error code .*/
int
tmpfs_alloc_file(struct vnode *dvp, struct vnode **vpp, struct vattr *vap,
    struct componentname *cnp, char *target)
{
	int error;
	struct tmpfs_dirent *de;
	struct tmpfs_mount *tmp;
	struct tmpfs_node *dnode;
	struct tmpfs_node *node;
	struct tmpfs_node *parent;

	KASSERT(VOP_ISLOCKED(dvp));
	KASSERT(cnp->cn_flags & HASBUF);

	tmp = VFS_TO_TMPFS(dvp->v_mount);
	dnode = VP_TO_TMPFS_DIR(dvp);
	*vpp = NULL;

	/* If the entry we are creating is a directory, we cannot overflow
	 * the number of links of its parent, because it will get a new
	 * link. */
	if (vap->va_type == VDIR) {
		/* Ensure that we do not overflow the maximum number of links
		 * imposed by the system. */
		KASSERT(dnode->tn_links <= LINK_MAX);
		if (dnode->tn_links == LINK_MAX) {
			error = EMLINK;
			goto out;
		}

		parent = dnode;
	} else
		parent = NULL;

	/* Allocate a node that represents the new file. */
	error = tmpfs_alloc_node(tmp, vap->va_type, cnp->cn_cred->cr_uid,
	    dnode->tn_gid, vap->va_mode, parent, target, vap->va_rdev,
	    cnp->cn_proc, &node);
	if (error != 0)
		goto out;

	/* Allocate a directory entry that points to the new file. */
	error = tmpfs_alloc_dirent(tmp, node, cnp->cn_nameptr, cnp->cn_namelen,
	    &de);
	if (error != 0) {
		tmpfs_free_node(tmp, node);
		goto out;
	}

	/* Allocate a vnode for the new file. */
	error = tmpfs_alloc_vp(dvp->v_mount, node, vpp);
	if (error != 0) {
		tmpfs_free_dirent(tmp, de, TRUE);
		tmpfs_free_node(tmp, node);
		goto out;
	}

	/* Now that all required items are allocated, we can proceed to
	 * insert the new node into the directory, an operation that
	 * cannot fail. */
	tmpfs_dir_attach(dvp, de);
	VN_KNOTE(dvp, NOTE_WRITE);

out:
	if (error != 0 || !(cnp->cn_flags & SAVESTART))
		PNBUF_PUT(cnp->cn_pnbuf);
	vput(dvp);

	KASSERT(!VOP_ISLOCKED(dvp));
	KASSERT(IFF(error == 0, *vpp != NULL));

	return error;
}

/* --------------------------------------------------------------------- */

void
tmpfs_dir_attach(struct vnode *vp, struct tmpfs_dirent *de)
{
	struct tmpfs_node *dnode;

	dnode = VP_TO_TMPFS_DIR(vp);

	TAILQ_INSERT_TAIL(&dnode->tn_dir, de, td_entries);
	dnode->tn_size += sizeof(struct tmpfs_dirent);
	dnode->tn_status |= TMPFS_NODE_ACCESSED | TMPFS_NODE_CHANGED | \
	    TMPFS_NODE_MODIFIED;
	uvm_vnp_setsize(vp, dnode->tn_size);
}

/* --------------------------------------------------------------------- */

void
tmpfs_dir_detach(struct vnode *vp, struct tmpfs_dirent *de)
{
	struct tmpfs_node *dnode;

	dnode = VP_TO_TMPFS_DIR(vp);

	TAILQ_REMOVE(&dnode->tn_dir, de, td_entries);
	dnode->tn_size -= sizeof(struct tmpfs_dirent);
	dnode->tn_status |= TMPFS_NODE_ACCESSED | TMPFS_NODE_CHANGED | \
	    TMPFS_NODE_MODIFIED;
	uvm_vnp_setsize(vp, dnode->tn_size);
}

/* --------------------------------------------------------------------- */

struct tmpfs_dirent *
tmpfs_dir_lookup(struct tmpfs_node *node, struct componentname *cnp)
{
	boolean_t found;
	struct tmpfs_dirent *de;

	KASSERT(IMPLIES(cnp->cn_namelen == 1, cnp->cn_nameptr[0] != '.'));
	KASSERT(IMPLIES(cnp->cn_namelen == 2, !(cnp->cn_nameptr[0] == '.' &&
	    cnp->cn_nameptr[1] == '.')));
	TMPFS_VALIDATE_DIR(node);

	node->tn_status |= TMPFS_NODE_ACCESSED;

	found = 0;
	TAILQ_FOREACH(de, &node->tn_dir, td_entries) {
		KASSERT(cnp->cn_namelen < 0xffff);
		if (de->td_namelen == (uint16_t)cnp->cn_namelen &&
		    memcmp(de->td_name, cnp->cn_nameptr, de->td_namelen) == 0) {
			found = 1;
			break;
		}
	}

	return found ? de : NULL;
}

/* --------------------------------------------------------------------- */

/* Helper function for tmpfs_readdir.  Creates a '.' entry for the given
 * directory and returns it in the uio space.  The function returns 0
 * on success, -1 if there was not enough space in the uio structure to
 * hold the directory entry or an appropriate error code if another
 * error happens. */
int
tmpfs_dir_getdotdent(struct tmpfs_node *node, struct uio *uio)
{
	int error;
	struct dirent dent;

	TMPFS_VALIDATE_DIR(node);
	KASSERT(uio->uio_offset == 0);

	dent.d_fileno = node->tn_id;
	dent.d_type = DT_DIR;
	dent.d_namlen = 1;
	dent.d_name[0] = '.';
	dent.d_name[1] = '\0';
	dent.d_reclen = _DIRENT_SIZE(&dent);

	if (dent.d_reclen > uio->uio_resid)
		error = -1;
	else {
		error = uiomove(&dent, dent.d_reclen, uio);
		if (error == 0)
			uio->uio_offset += sizeof(struct tmpfs_dirent) - \
			    dent.d_reclen;
	}

	node->tn_status |= TMPFS_NODE_ACCESSED;

	return error;
}

/* --------------------------------------------------------------------- */

/* Helper function for tmpfs_readdir.  Creates a '..' entry for the given
 * directory and returns it in the uio space.  The function returns 0
 * on success, -1 if there was not enough space in the uio structure to
 * hold the directory entry or an appropriate error code if another
 * error happens. */
int
tmpfs_dir_getdotdotdent(struct tmpfs_node *node, struct uio *uio)
{
	int error;
	struct dirent dent;

	TMPFS_VALIDATE_DIR(node);
	KASSERT(uio->uio_offset == sizeof(struct tmpfs_dirent));

	dent.d_fileno = node->tn_id;
	dent.d_type = DT_DIR;
	dent.d_namlen = 2;
	dent.d_name[0] = '.';
	dent.d_name[1] = '.';
	dent.d_name[2] = '\0';
	dent.d_reclen = _DIRENT_SIZE(&dent);

	if (dent.d_reclen > uio->uio_resid)
		error = -1;
	else {
		error = uiomove(&dent, dent.d_reclen, uio);
		if (error == 0)
			uio->uio_offset += sizeof(struct tmpfs_dirent) - \
			    dent.d_reclen;
	}

	node->tn_status |= TMPFS_NODE_ACCESSED;

	return error;
}

/* --------------------------------------------------------------------- */

/* Helper function for tmpfs_readdir.  Returns as much directory entries
 * as can fit in the uio space.  The read starts at uio->uio_offset.
 * The function returns 0 on success, -1 if there was not enough space
 * in the uio structure to hold the directory entry or an appropriate
 * error code if another error happens. */
int
tmpfs_dir_getdents(struct tmpfs_node *node, struct uio *uio)
{
	int error;
	long cnt, startcnt;
	struct tmpfs_dirent *de;

	TMPFS_VALIDATE_DIR(node);
	KASSERT(uio->uio_offset % sizeof(struct tmpfs_dirent) == 0);
	KASSERT(uio->uio_offset >= sizeof(struct tmpfs_dirent) * 2);
	KASSERT(uio->uio_offset < node->tn_size +
	    sizeof(struct tmpfs_dirent) * 2);

	/* Locate the first directory entry we have to return.  We have cached
	 * the last readdir in the node, so use those values if appropriate.
	 * Otherwise do a linear scan to find the requested entry. */
	de = NULL;
	startcnt = uio->uio_offset / sizeof(struct tmpfs_dirent) - 2;
	if (startcnt == node->tn_readdir_lastn && \
	    node->tn_readdir_lastp != NULL) {
		cnt = node->tn_readdir_lastn;
		de = node->tn_readdir_lastp;
	} else {
		cnt = 0;
		de = TAILQ_FIRST(&node->tn_dir);
		while (cnt < startcnt) {
			cnt++;
			de = TAILQ_NEXT(de, td_entries);

			/* Ensure that if we have not found the desired item,
			 * there are more entries in the directory to continue
			 * the search. */
			KASSERT(IMPLIES(de == TAILQ_LAST(&node->tn_dir,
			    tmpfs_dir), cnt == startcnt));
		}
	}
	KASSERT(cnt == startcnt);
	KASSERT(de != NULL);

	/* Read as much entries as possible; i.e., until we reach the end of
	 * the directory or we exhaust uio space. */
	do {
		struct dirent d;

		/* Create a dirent structure representing the current
		 * tmpfs_node and fill it. */
		d.d_fileno = de->td_node->tn_id;
		switch (de->td_node->tn_type) {
		case VBLK:
			d.d_type = DT_BLK;
			break;

		case VCHR:
			d.d_type = DT_CHR;
			break;

		case VDIR:
			d.d_type = DT_DIR;
			break;

		case VFIFO:
			d.d_type = DT_FIFO;
			break;

		case VLNK:
			d.d_type = DT_LNK;
			break;

		case VREG:
			d.d_type = DT_REG;
			break;

		case VSOCK:
			d.d_type = DT_SOCK;
			break;

		default:
			KASSERT(0);
		}
		d.d_namlen = de->td_namelen;
		KASSERT(de->td_namelen < sizeof(d.d_name));
		(void)memcpy(d.d_name, de->td_name, de->td_namelen);
		d.d_name[de->td_namelen] = '\0';
		d.d_reclen = _DIRENT_SIZE(&d);

		/* Stop reading if the directory entry we are treating is
		 * bigger than the amount of data that can be returned. */
		if (d.d_reclen > uio->uio_resid) {
			error = -1;
			break;
		}

		/* Copy the new dirent structure into the output buffer and
		 * advance pointers. */
		error = uiomove(&d, d.d_reclen, uio);

		cnt++;
		de = TAILQ_NEXT(de, td_entries);
	} while (error == 0 && uio->uio_resid > 0 && de != NULL);

	/* Update the offset in the uio structure to be correctly aligned
	 * with tmpfs_dirent structures.  Otherwise, the offset is the
	 * size of the returned dirent structures, which is useless for us. */
	uio->uio_offset = (cnt + 2) * sizeof(struct tmpfs_dirent);

	/* Cache the current status. */
	if (de == NULL) {
		KASSERT(cnt == node->tn_size / sizeof(struct tmpfs_dirent));
		node->tn_readdir_lastn = 0;
		node->tn_readdir_lastp = NULL;
	} else {
		node->tn_readdir_lastn = cnt;
		node->tn_readdir_lastp = de;
	}

	node->tn_status |= TMPFS_NODE_ACCESSED;

	return error;
}

/* --------------------------------------------------------------------- */

int
tmpfs_reg_resize(struct vnode *vp, off_t newsize)
{
	int error;
	size_t newpages, oldpages;
	struct tmpfs_mount *tmp;
	struct tmpfs_node *node;

	KASSERT(vp->v_type == VREG);
	KASSERT(newsize >= 0);

	node = VP_TO_TMPFS_NODE(vp);
	tmp = VFS_TO_TMPFS(vp->v_mount);

	/* Convert the old and new sizes to the number of pages needed to
	 * store them.  It may happen that we do not need to do anything
	 * because the last allocated page can accommodate the change on
	 * its own. */
	oldpages = round_page(node->tn_size) / PAGE_SIZE;
	KASSERT(oldpages == node->tn_aobj_pages);
	newpages = round_page(newsize) / PAGE_SIZE;

	if (newpages > oldpages &&
	    newpages - oldpages > TMPFS_PAGES_AVAIL(tmp)) {
		error = ENOSPC;
		goto out;
	}

	node->tn_aobj_pages = newpages;

	tmp->tm_pages_used += (newpages - oldpages);
	node->tn_size = newsize;
	uvm_vnp_setsize(vp, newsize);

	error = 0;

out:
	return error;
}

/* --------------------------------------------------------------------- */

/* Returns information about the number of available memory pages,
 * including physical and virtual ones.
 *
 * If 'total' is TRUE, the value returned is the total amount of memory 
 * pages configured for the system (either in use or free).
 * If it is FALSE, the value returned is the amount of free memory pages.
 *
 * Remember to remove TMPFS_PAGES_RESERVED from the returned value to avoid
 * excessive memory usage.
 *
 * XXX: This function is used every time TMPFS_PAGES_MAX is called to gather
 * the amount of free memory, something that happens during _each_
 * object allocation.  The time it takes to run this function so many
 * times is not negligible, so this value should be stored as an
 * aggregate somewhere, possibly within UVM (we cannot do it ourselves
 * because we can't get notifications on memory usage changes). */
size_t
tmpfs_mem_info(boolean_t total)
{
	int i, sec;
	register_t retval;
	size_t size;
	struct swapent *sep;

	sec = uvmexp.nswapdev;
	sep = (struct swapent *)malloc(sizeof(struct swapent) * sec, M_TEMP,
	    M_WAITOK);
	KASSERT(sep != NULL);
	uvm_swap_stats(SWAP_STATS, sep, sec, &retval);
	KASSERT(retval == sec);

	size = 0;
	if (total) {
		for (i = 0; i < sec; i++)
			size += dbtob(sep[i].se_nblks) / PAGE_SIZE;
	} else {
		for (i = 0; i < sec; i++)
			size += dbtob(sep[i].se_nblks - sep[i].se_inuse) /
			    PAGE_SIZE;
	}
	size += uvmexp.free;

	free(sep, M_TEMP);

	return size;
}

/* --------------------------------------------------------------------- */

/* Change flags of the given vnode.
 * Caller should execute VOP_UPDATE on vp after a successful execution.
 * The vnode must be locked on entry and remain locked on exit. */
int
tmpfs_chflags(struct vnode *vp, int flags, struct ucred *cred, struct proc *p)
{
	int error;
	struct tmpfs_node *node;

	KASSERT(VOP_ISLOCKED(vp));

	node = VP_TO_TMPFS_NODE(vp);

	/* Disallow this operation if the file system is mounted read-only. */
	if (vp->v_mount->mnt_flag & MNT_RDONLY)
		return EROFS;

	/* XXX: The following comes from UFS code, and can be found in
	 * several other file systems.  Shouldn't this be centralized
	 * somewhere? */
	if (cred->cr_uid != node->tn_uid &&
	    (error = suser(cred, &p->p_acflag)))
		return error;
	if (cred->cr_uid == 0) {
		/* The super-user is only allowed to change flags if the file
		 * wasn't protected before and the securelevel is zero. */
		if ((node->tn_flags & (SF_IMMUTABLE | SF_APPEND)) &&
		    securelevel > 0)
			return EPERM;
		node->tn_flags = flags;
	} else {
		/* Regular users can change flags provided they only want to
		 * change user-specific ones, not those reserved for the
		 * super-user. */
		if ((node->tn_flags & (SF_IMMUTABLE | SF_APPEND)) ||
		    (flags & UF_SETTABLE) != flags)
			return EPERM;
		if ((node->tn_flags & SF_SETTABLE) != (flags & SF_SETTABLE))
			return EPERM;
		node->tn_flags &= SF_SETTABLE;
		node->tn_flags |= (flags & UF_SETTABLE);
	}

	node->tn_status |= TMPFS_NODE_CHANGED;
	VN_KNOTE(vp, NOTE_ATTRIB);

	KASSERT(VOP_ISLOCKED(vp));

	return 0;
}

/* --------------------------------------------------------------------- */

/* Change access mode on the given vnode.
 * Caller should execute VOP_UPDATE on vp after a successful execution.
 * The vnode must be locked on entry and remain locked on exit. */
int
tmpfs_chmod(struct vnode *vp, mode_t mode, struct ucred *cred, struct proc *p)
{
	int error;
	struct tmpfs_node *node;

	KASSERT(VOP_ISLOCKED(vp));

	node = VP_TO_TMPFS_NODE(vp);

	/* Disallow this operation if the file system is mounted read-only. */
	if (vp->v_mount->mnt_flag & MNT_RDONLY)
		return EROFS;

	/* Immutable or append-only files cannot be modified, either. */
	if (node->tn_flags & (IMMUTABLE | APPEND))
		return EPERM;

	/* XXX: The following comes from UFS code, and can be found in
	 * several other file systems.  Shouldn't this be centralized
	 * somewhere? */
	if (cred->cr_uid != node->tn_uid &&
	    (error = suser(cred, &p->p_acflag)))
		return error;
	if (cred->cr_uid != 0) {
		if (vp->v_type != VDIR && (mode & S_ISTXT))
			return EFTYPE;

		if (!groupmember(node->tn_gid, cred) && (mode & S_ISGID))
			return EPERM;
	}

	node->tn_mode = (mode & ALLPERMS);

	node->tn_status |= TMPFS_NODE_CHANGED;
	VN_KNOTE(vp, NOTE_ATTRIB);

	KASSERT(VOP_ISLOCKED(vp));

	return 0;
}

/* --------------------------------------------------------------------- */

/* Change ownership of the given vnode.  At least one of uid or gid must
 * be different than VNOVAL.  If one is set to that value, the attribute
 * is unchanged.
 * Caller should execute VOP_UPDATE on vp after a successful execution.
 * The vnode must be locked on entry and remain locked on exit. */
int
tmpfs_chown(struct vnode *vp, uid_t uid, gid_t gid, struct ucred *cred,
    struct proc *p)
{
	int error;
	struct tmpfs_node *node;

	KASSERT(VOP_ISLOCKED(vp));

	node = VP_TO_TMPFS_NODE(vp);

	/* Assign default values if they are unknown. */
	KASSERT(uid != VNOVAL || gid != VNOVAL);
	if (uid == VNOVAL)
		uid = node->tn_uid;
	if (gid == VNOVAL)
		gid = node->tn_gid;
	KASSERT(uid != VNOVAL && gid != VNOVAL);

	/* Disallow this operation if the file system is mounted read-only. */
	if (vp->v_mount->mnt_flag & MNT_RDONLY)
		return EROFS;

	/* Immutable or append-only files cannot be modified, either. */
	if (node->tn_flags & (IMMUTABLE | APPEND))
		return EPERM;

	/* XXX: The following comes from UFS code, and can be found in
	 * several other file systems.  Shouldn't this be centralized
	 * somewhere? */
	if ((cred->cr_uid != node->tn_uid || uid != node->tn_uid ||
	    (gid != node->tn_gid && !(cred->cr_gid == node->tn_gid ||
	     groupmember(gid, cred)))) &&
	    ((error = suser(cred, &p->p_acflag)) != 0))
		return error;

	node->tn_uid = uid;
	node->tn_gid = gid;

	node->tn_status |= TMPFS_NODE_CHANGED;
	VN_KNOTE(vp, NOTE_ATTRIB);

	KASSERT(VOP_ISLOCKED(vp));

	return 0;
}

/* --------------------------------------------------------------------- */

/* Change size of the given vnode.
 * Caller should execute VOP_UPDATE on vp after a successful execution.
 * The vnode must be locked on entry and remain locked on exit. */
int
tmpfs_chsize(struct vnode *vp, u_quad_t size, struct ucred *cred,
    struct proc *p)
{
	int error;
	struct tmpfs_node *node;

	KASSERT(VOP_ISLOCKED(vp));

	node = VP_TO_TMPFS_NODE(vp);

	/* Decide whether this is a valid operation based on the file type. */
	error = 0;
	switch (vp->v_type) {
	case VDIR:
		return EISDIR;

	case VLNK:
		/* FALLTHROUGH */
	case VREG:
		if (vp->v_mount->mnt_flag & MNT_RDONLY)
			return EROFS;
		break;

	case VBLK:
		/* FALLTHROUGH */
	case VCHR:
		/* FALLTHROUGH */
	case VSOCK:
		/* FALLTHROUGH */
	case VFIFO:
		/* Allow modifications of special files even if in the file
		 * system is mounted read-only (we are not modifying the
		 * files themselves, but the objects they represent). */
		break;

	default:
		/* Anything else is unsupported. */
		return EINVAL;
	}

	/* Immutable or append-only files cannot be modified, either. */
	if (node->tn_flags & (IMMUTABLE | APPEND))
		return EPERM;

	error = VOP_TRUNCATE(vp, size, 0, cred, p);
	/* tmpfs_truncate will raise the NOTE_EXTEND and NOTE_ATTRIB kevents
	 * for us, as will update tn_status; no need to do that here. */

	KASSERT(VOP_ISLOCKED(vp));

	return error;
}

/* --------------------------------------------------------------------- */

/* Change access and modification times of the given vnode.
 * Caller should execute VOP_UPDATE on vp after a successful execution.
 * The vnode must be locked on entry and remain locked on exit. */
int
tmpfs_chtimes(struct vnode *vp, struct timespec *atime, struct timespec *mtime,
    int vaflags, struct ucred *cred, struct proc *p)
{
	int error;
	struct tmpfs_node *node;

	KASSERT(VOP_ISLOCKED(vp));

	node = VP_TO_TMPFS_NODE(vp);

	/* Disallow this operation if the file system is mounted read-only. */
	if (vp->v_mount->mnt_flag & MNT_RDONLY)
		return EROFS;

	/* Immutable or append-only files cannot be modified, either. */
	if (node->tn_flags & (IMMUTABLE | APPEND))
		return EPERM;

	/* XXX: The following comes from UFS code, and can be found in
	 * several other file systems.  Shouldn't this be centralized
	 * somewhere? */
	if (cred->cr_uid != node->tn_uid &&
	    (error = suser(cred, &p->p_acflag)) &&
	    ((vaflags & VA_UTIMES_NULL) == 0 ||
	    (error = VOP_ACCESS(vp, VWRITE, cred, p))))
		return error;

	if (atime->tv_sec != VNOVAL && atime->tv_nsec != VNOVAL)
		node->tn_status |= TMPFS_NODE_ACCESSED;

	if (mtime->tv_sec != VNOVAL && mtime->tv_nsec != VNOVAL)
		node->tn_status |= TMPFS_NODE_MODIFIED;

	error = VOP_UPDATE(vp, atime, mtime, 0);

	KASSERT(VOP_ISLOCKED(vp));

	return error;
}
