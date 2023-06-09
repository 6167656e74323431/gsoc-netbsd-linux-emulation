/*	$OpenBSD: pci_machdep.h,v 1.1 2003/09/29 19:23:02 mickey Exp $	*/

/*
 * Copyright (c) 2003 Michael Shalayeff
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR OR HIS RELATIVES BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF MIND, USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef	_MACHINE_PCI_MACHDEP_H_
#define	_MACHINE_PCI_MACHDEP_H_

/*
 * Types provided to machine-independent PCI code
 */
typedef struct hppa_pci_chipset_tag *pci_chipset_tag_t;
typedef u_long pcitag_t;
typedef u_long pci_intr_handle_t;

struct pci_attach_args;

struct hppa_pci_chipset_tag {
	void		*_cookie;
	void		(*pc_attach_hook)(device_t,
			    device_t, struct pcibus_attach_args *);
	int		(*pc_bus_maxdevs)(void *, int);
	pcitag_t	(*pc_make_tag)(void *, int, int, int);
	void		(*pc_decompose_tag)(void *, pcitag_t, int *,
			    int *, int *);
	pcireg_t	(*pc_conf_read)(void *, pcitag_t, int);
	void		(*pc_conf_write)(void *, pcitag_t, int, pcireg_t);

	int		(*pc_intr_map)(const struct pci_attach_args *,
			    pci_intr_handle_t *);
	const char	*(*pc_intr_string)(void *, pci_intr_handle_t,
			    char *, size_t);
	int		(*pc_intr_setattr)(void *, pci_intr_handle_t *,
			    int, uint64_t);
	void		*(*pc_intr_establish)(void *, pci_intr_handle_t,
			    int, int (*)(void *), void *);
	void		(*pc_intr_disestablish)(void *, void *);

	void		*(*pc_alloc_parent)(device_t,
			    struct pci_attach_args *, int);
};

/*
 * Functions provided to machine-independent PCI code.
 */
#define	pci_attach_hook(p, s, pba)					\
    (*(pba)->pba_pc->pc_attach_hook)((p), (s), (pba))
#define	pci_bus_maxdevs(c, b)						\
    (*(c)->pc_bus_maxdevs)((c)->_cookie, (b))
#define	pci_make_tag(c, b, d, f)					\
    (*(c)->pc_make_tag)((c)->_cookie, (b), (d), (f))
#define	pci_decompose_tag(c, t, bp, dp, fp)				\
    (*(c)->pc_decompose_tag)((c)->_cookie, (t), (bp), (dp), (fp))
#define	pci_conf_read(c, t, r)						\
    (*(c)->pc_conf_read)((c)->_cookie, (t), (r))
#define	pci_conf_write(c, t, r, v)					\
    (*(c)->pc_conf_write)((c)->_cookie, (t), (r), (v))
#define	pci_intr_map(p, ihp)						\
    (*(p)->pa_pc->pc_intr_map)((p), (ihp))
#define	pci_intr_line(ih)	(ih)
#define	pci_intr_string(c, ih, buf, len)				\
    (*(c)->pc_intr_string)((c)->_cookie, (ih), (buf), (len))
#define	pci_intr_establish(c, ih, l, h, a)				\
    (*(c)->pc_intr_establish)((c)->_cookie, (ih), (l), (h), (a))
#define	pci_intr_disestablish(c, iv)					\
    (*(c)->pc_intr_disestablish)((c)->_cookie, (iv))

static inline int
pci_intr_setattr(pci_chipset_tag_t pc, pci_intr_handle_t *ihp,
    int attr, uint64_t data)
{
	if (!pc->pc_intr_setattr)
		return ENODEV;
	return pc->pc_intr_setattr(pc, ihp, attr, data);
}

#define	pciide_machdep_compat_intr_establish(a, b, c, d, e)	(NULL)
#define	pciide_machdep_compat_intr_disestablish(a, b)	((void)(a), (void)(b))

#define	pci_intr_evcnt(a, b) (NULL)

#endif /* _MACHINE_PCI_MACHDEP_H_ */
