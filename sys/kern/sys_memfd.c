#include <sys/param.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/mman.h>
#include <sys/syscallargs.h>
#include <uvm/uvm_extern.h>

struct memfd {
	char			mfd_name[256];
//	uint64_t		mfd_refcnt;
//	kmutex_t 		mfd_lock; GTODO for close
	struct uvm_object	*mfd_uobj;
	size_t			mfd_size;
	int		        mfd_seals;
};

static int memfd_read(file_t *fp, off_t *offp, struct uio *uio,
    kauth_cred_t cred, int flags);
static int memfd_write(file_t *fp, off_t *offp, struct uio *uio,
    kauth_cred_t cred, int flags);
static int memfd_fcntl(file_t *fp, u_int cmd, void *data);
static int memfd_close(file_t *fp);
static int memfd_mmap(struct file *fp, off_t *offp, size_t size, int prot,
    int *flagsp, int *advicep, struct uvm_object **uobjp, int *maxprotp);
static int memfd_seek(struct file *fp, off_t delta, int whence,
    off_t *newoffp, int flags);

static int do_memfd_truncate(struct memfd *mfd, off_t newsize);

static const struct fileops memfd_fileops = {
	.fo_name = "memfd",
	.fo_read = memfd_read,
	.fo_write = memfd_write,
	.fo_ioctl = (void *)eopnotsupp, // GTODO
	.fo_fcntl = memfd_fcntl,
	.fo_poll = fnullop_poll,
	.fo_stat = (void *)eopnotsupp, // GTODO
	.fo_close = memfd_close,
	.fo_kqfilter = fnullop_kqfilter,
	.fo_restart = fnullop_restart,
	.fo_mmap = memfd_mmap,
	.fo_seek = memfd_seek,
	.fo_advlock = (void *)eopnotsupp, // GTODO
	.fo_fpathconf = (void *)eopnotsupp, // GTODO
	.fo_posix_fadvise = (void *)eopnotsupp, // GTODO
	// GTODO .fo_truncate
};

int
sys_memfd_create(struct lwp *l, const struct sys_memfd_create_args *uap,
    register_t *retval)
{
	/* {
		syscallarg(const char *) name;
		syscallarg(unsigned int) flags;
	} */
	int error, fd;
	file_t *fp;
	size_t done;
	struct memfd *mfd;
	struct proc *p = l->l_proc;
	const unsigned int flags = SCARG(uap, flags);

	mfd = kmem_zalloc(sizeof(*mfd), KM_SLEEP);
	mfd->mfd_size = 0;
	mfd->mfd_uobj = uao_create(INT64_MAX - PAGE_SIZE, 0); /* same as tmpfs */

	strcpy(mfd->mfd_name, "memfd:");
	error = copyinstr(SCARG(uap, name), &mfd->mfd_name[6], 250, &done);
	if (error != 0)
		goto leave;
	if (done > 249) {
		error = EINVAL;
		goto leave;
	}

	if ((flags & MFD_ALLOW_SEALING) == 0)
		mfd->mfd_seals |= F_SEAL_SEAL;

	error = fd_allocfile(&fp, &fd);
	if (error != 0)
		goto leave;

	fp->f_flag = FREAD|FWRITE;
	fp->f_type = DTYPE_MEMFD;
	fp->f_ops = &memfd_fileops;
	fp->f_memfd = mfd;
	fd_set_exclose(l, fd, (flags & MFD_CLOEXEC) != 0);
	fd_affix(p, fp, fd);

	*retval = fd;
	return 0;

leave:
	uao_detach(mfd->mfd_uobj);
	kmem_free(mfd, sizeof(*mfd));
	return error;
}

static int
memfd_read(file_t *fp, off_t *offp, struct uio *uio, kauth_cred_t cred,
    int flags)
{
	int error;
	vsize_t todo;
	struct memfd *mfd = fp->f_memfd;

	if (offp == &fp->f_offset)
		mutex_enter(&fp->f_lock);

	if (*offp < 0) {
		error = EINVAL;
		goto leave;
	}

	/* Trying to read past the end does nothing. */
	if (*offp >= mfd->mfd_size) {
		error = 0;
		goto leave;
	}

	uio->uio_offset = *offp;
	todo = MIN(uio->uio_resid, mfd->mfd_size - *offp);
	error = ubc_uiomove(mfd->mfd_uobj, uio, todo, UVM_ADV_SEQUENTIAL,
	    UBC_READ|UBC_PARTIALOK);

leave:
	if (offp == &fp->f_offset)
		mutex_exit(&fp->f_lock);
	
	return error;
}

static int
memfd_write(file_t *fp, off_t *offp, struct uio *uio, kauth_cred_t cred,
    int flags)
{
        int error;
	vsize_t todo;
	struct memfd *mfd = fp->f_memfd;

	if (mfd->mfd_seals & (F_SEAL_WRITE|F_SEAL_FUTURE_WRITE))
		return EPERM;

	if (offp == &fp->f_offset)
		mutex_enter(&fp->f_lock);

	if (*offp < 0) {
		error = EINVAL;
		goto leave;
	}

	/* Grow to accommodate the write request. */
	if (*offp + uio->uio_resid >= mfd->mfd_size) {
		error = do_memfd_truncate(mfd, *offp + uio->uio_resid);
		if (error != 0)
			goto leave;
	}

	uio->uio_offset = *offp;
	todo = uio->uio_resid; // GTODO seals...
	error = ubc_uiomove(mfd->mfd_uobj, uio, todo, UVM_ADV_SEQUENTIAL,
	    UBC_WRITE|UBC_PARTIALOK);

leave:
	if (offp == &fp->f_offset)
		mutex_exit(&fp->f_lock);
	
	return error;
}

static int
memfd_fcntl(file_t *fp, u_int cmd, void *data)
{
	struct memfd *mfd = fp->f_memfd;

	switch (cmd) {
	case F_ADD_SEALS:
		if (mfd->mfd_seals & F_SEAL_SEAL)
			return EPERM;

	        mfd->mfd_seals |= *(int *)data;
		return 0;

	case F_GET_SEALS:
		*(int *)data = mfd->mfd_seals;
		return 0;

	default:
		return EOPNOTSUPP;
	}
}

static int
memfd_close(file_t *fp)	// GTODO
{
	return 0;
}

static int
memfd_mmap(struct file *fp, off_t *offp, size_t size, int prot, int *flagsp,
    int *advicep, struct uvm_object **uobjp, int *maxprotp)
{
	*uobjp = fp->f_memfd->mfd_uobj;
	uao_reference(fp->f_memfd->mfd_uobj);
	return 0;
}

static int
memfd_seek(struct file *fp, off_t delta, int whence, off_t *newoffp,
    int flags)
{
	off_t newoff;
	int error;

	switch (whence) {
	case SEEK_CUR:
		// GTODO
		newoff = delta;
		break;

	case SEEK_END:
		// GTODO
		newoff = delta;
		break;

	case SEEK_SET:
		newoff = delta;
		break;

	default:
		error = EINVAL;
		return error;
	}

	if (newoffp)
		*newoffp = newoff;
	if (flags & FOF_UPDATE_OFFSET)
		fp->f_offset = newoff;

	return 0;
}

static int
do_memfd_truncate(struct memfd *mfd, off_t newsize)
{
	if ((mfd->mfd_seals & F_SEAL_SHRINK) && newsize < mfd->mfd_size)
		return EPERM;
	if ((mfd->mfd_seals & F_SEAL_GROW) && newsize > mfd->mfd_size)
		return EPERM;

	if (newsize < 0)
		return EINVAL;

	if (newsize > mfd->mfd_size) {
		ubc_zerorange(mfd->mfd_uobj, mfd->mfd_size,
		    newsize - mfd->mfd_size, 0);
	}

	mfd->mfd_size = newsize;
	return 0;
}
