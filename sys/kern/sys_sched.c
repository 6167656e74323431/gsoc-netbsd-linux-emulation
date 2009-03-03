/*	$NetBSD: sys_sched.c,v 1.33 2009/03/03 21:55:06 rmind Exp $	*/

/*
 * Copyright (c) 2008, Mindaugas Rasiukevicius <rmind at NetBSD org>
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * System calls relating to the scheduler.
 *
 * Lock order:
 *
 *	cpu_lock ->
 *	    proc_lock ->
 *		proc_t::p_lock ->
 *		    lwp_t::lwp_lock
 *
 * TODO:
 *  - Handle pthread_setschedprio() as defined by POSIX;
 *  - Handle sched_yield() case for SCHED_FIFO as defined by POSIX;
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: sys_sched.c,v 1.33 2009/03/03 21:55:06 rmind Exp $");

#include <sys/param.h>

#include <sys/cpu.h>
#include <sys/kauth.h>
#include <sys/kmem.h>
#include <sys/lwp.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/pset.h>
#include <sys/sa.h>
#include <sys/savar.h>
#include <sys/sched.h>
#include <sys/syscallargs.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/unistd.h>

#include "opt_sa.h"

/*
 * Convert user priority or the in-kernel priority or convert the current
 * priority to the appropriate range according to the policy change.
 */
static pri_t
convert_pri(lwp_t *l, int policy, pri_t pri)
{

	/* Convert user priority to the in-kernel */
	if (pri != PRI_NONE) {
		/* Only for real-time threads */
		KASSERT(pri >= SCHED_PRI_MIN && pri <= SCHED_PRI_MAX);
		KASSERT(policy != SCHED_OTHER);
		return PRI_USER_RT + pri;
	}

	/* Neither policy, nor priority change */
	if (l->l_class == policy)
		return l->l_priority;

	/* Time-sharing -> real-time */
	if (l->l_class == SCHED_OTHER) {
		KASSERT(policy == SCHED_FIFO || policy == SCHED_RR);
		return PRI_USER_RT;
	}

	/* Real-time -> time-sharing */
	if (policy == SCHED_OTHER) {
		KASSERT(l->l_class == SCHED_FIFO || l->l_class == SCHED_RR);
		return l->l_priority - PRI_USER_RT;
	}

	/* Real-time -> real-time */
	return l->l_priority;
}

int
do_sched_setparam(pid_t pid, lwpid_t lid, int policy,
    const struct sched_param *params)
{
	struct proc *p;
	struct lwp *t;
	pri_t pri;
	u_int lcnt;
	int error;

	error = 0;

	pri = params->sched_priority;

	/* If no parameters specified, just return (this should not happen) */
	if (pri == PRI_NONE && policy == SCHED_NONE)
		return 0;

	/* Validate scheduling class */
	if (policy != SCHED_NONE && (policy < SCHED_OTHER || policy > SCHED_RR))
		return EINVAL;

	/* Validate priority */
	if (pri != PRI_NONE && (pri < SCHED_PRI_MIN || pri > SCHED_PRI_MAX))
		return EINVAL;

	if (pid != 0) {
		/* Find the process */
		mutex_enter(proc_lock);
		p = p_find(pid, PFIND_LOCKED);
		if (p == NULL) {
			mutex_exit(proc_lock);
			return ESRCH;
		}
		mutex_enter(p->p_lock);
		mutex_exit(proc_lock);
		/* Disallow modification of system processes */
		if ((p->p_flag & PK_SYSTEM) != 0) {
			mutex_exit(p->p_lock);
			return EPERM;
		}
	} else {
		/* Use the calling process */
		p = curlwp->l_proc;
		mutex_enter(p->p_lock);
	}

	/* Find the LWP(s) */
	lcnt = 0;
	LIST_FOREACH(t, &p->p_lwps, l_sibling) {
		pri_t kpri;
		int lpolicy;

		if (lid && lid != t->l_lid)
			continue;

		lcnt++;
		lwp_lock(t);
		lpolicy = (policy == SCHED_NONE) ? t->l_class : policy;

		/* Disallow setting of priority for SCHED_OTHER threads */
		if (lpolicy == SCHED_OTHER && pri != PRI_NONE) {
			lwp_unlock(t);
			error = EINVAL;
			break;
		}

		/* Convert priority, if needed */
		kpri = convert_pri(t, lpolicy, pri);

		/* Check the permission */
		error = kauth_authorize_process(kauth_cred_get(),
		    KAUTH_PROCESS_SCHEDULER_SETPARAM, p, t, KAUTH_ARG(lpolicy),
		    KAUTH_ARG(kpri));
		if (error) {
			lwp_unlock(t);
			break;
		}

		/* Set the scheduling class, change the priority */
		t->l_class = lpolicy;
		lwp_changepri(t, kpri);
		lwp_unlock(t);
	}
	mutex_exit(p->p_lock);
	return (lcnt == 0) ? ESRCH : error;
}

/*
 * Set scheduling parameters.
 */
int
sys__sched_setparam(struct lwp *l, const struct sys__sched_setparam_args *uap,
    register_t *retval)
{
	/* {
		syscallarg(pid_t) pid;
		syscallarg(lwpid_t) lid;
		syscallarg(int) policy;
		syscallarg(const struct sched_param *) params;
	} */
	struct sched_param params;
	int error;

	/* Get the parameters from the user-space */
	error = copyin(SCARG(uap, params), &params, sizeof(params));
	if (error)
		goto out;

	error = do_sched_setparam(SCARG(uap, pid), SCARG(uap, lid),
	    SCARG(uap, policy), &params);
out:
	return error;
}

int
do_sched_getparam(pid_t pid, lwpid_t lid, int *policy,
    struct sched_param *params)
{
	struct sched_param lparams;
	struct lwp *t;
	int error, lpolicy;

	/* Locks the LWP */
	t = lwp_find2(pid, lid);
	if (t == NULL)
		return ESRCH;

	/* Check the permission */
	error = kauth_authorize_process(kauth_cred_get(),
	    KAUTH_PROCESS_SCHEDULER_GETPARAM, t->l_proc, NULL, NULL, NULL);
	if (error != 0) {
		mutex_exit(t->l_proc->p_lock);
		return error;
	}

	lwp_lock(t);
	lparams.sched_priority = t->l_priority;
	lpolicy = t->l_class;

	switch (lpolicy) {
	case SCHED_OTHER:
		lparams.sched_priority -= PRI_USER;
		break;
	case SCHED_RR:
	case SCHED_FIFO:
		lparams.sched_priority -= PRI_USER_RT;
		break;
	}

	if (policy != NULL)
		*policy = lpolicy;

	if (params != NULL)
		*params = lparams;

	lwp_unlock(t);
	mutex_exit(t->l_proc->p_lock);
	return error;
}

/*
 * Get scheduling parameters.
 */
int
sys__sched_getparam(struct lwp *l, const struct sys__sched_getparam_args *uap,
    register_t *retval)
{
	/* {
		syscallarg(pid_t) pid;
		syscallarg(lwpid_t) lid;
		syscallarg(int *) policy;
		syscallarg(struct sched_param *) params;
	} */
	struct sched_param params;
	int error, policy;

	error = do_sched_getparam(SCARG(uap, pid), SCARG(uap, lid), &policy,
	    &params);
	if (error)
		goto out;

	error = copyout(&params, SCARG(uap, params), sizeof(params));
	if (error == 0 && SCARG(uap, policy) != NULL)
		error = copyout(&policy, SCARG(uap, policy), sizeof(int));
out:
	return error;
}

/*
 * Allocate the CPU set, and get it from userspace.
 */
static int
genkcpuset(kcpuset_t **dset, const cpuset_t *sset, size_t size)
{
	int error;

	*dset = kcpuset_create();
	error = kcpuset_copyin(sset, *dset, size);
	if (error != 0)
		kcpuset_unuse(*dset, NULL);
	return error;
}

/*
 * Set affinity.
 */
int
sys__sched_setaffinity(struct lwp *l,
    const struct sys__sched_setaffinity_args *uap, register_t *retval)
{
	/* {
		syscallarg(pid_t) pid;
		syscallarg(lwpid_t) lid;
		syscallarg(size_t) size;
		syscallarg(const cpuset_t *) cpuset;
	} */
	kcpuset_t *cpuset, *cpulst = NULL;
	struct cpu_info *ici, *ci;
	struct proc *p;
	struct lwp *t;
	CPU_INFO_ITERATOR cii;
	bool alloff;
	lwpid_t lid;
	u_int lcnt;
	int error;

	error = genkcpuset(&cpuset, SCARG(uap, cpuset), SCARG(uap, size));
	if (error)
		return error;

	/*
	 * Traverse _each_ CPU to:
	 *  - Check that CPUs in the mask have no assigned processor set.
	 *  - Check that at least one CPU from the mask is online.
	 *  - Find the first target CPU to migrate.
	 *
	 * To avoid the race with CPU online/offline calls and processor sets,
	 * cpu_lock will be locked for the entire operation.
	 */
	ci = NULL;
	alloff = false;
	mutex_enter(&cpu_lock);
	for (CPU_INFO_FOREACH(cii, ici)) {
		struct schedstate_percpu *ispc;

		if (kcpuset_isset(cpu_index(ici), cpuset) == 0)
			continue;

		ispc = &ici->ci_schedstate;
		/* Check that CPU is not in the processor-set */
		if (ispc->spc_psid != PS_NONE) {
			error = EPERM;
			goto out;
		}
		/* Skip offline CPUs */
		if (ispc->spc_flags & SPCF_OFFLINE) {
			alloff = true;
			continue;
		}
		/* Target CPU to migrate */
		if (ci == NULL) {
			ci = ici;
		}
	}
	if (ci == NULL) {
		if (alloff) {
			/* All CPUs in the set are offline */
			error = EPERM;
			goto out;
		}
		/* Empty set */
		kcpuset_unuse(cpuset, &cpulst);
		cpuset = NULL; 
	}

	if (SCARG(uap, pid) != 0) {
		/* Find the process */
		mutex_enter(proc_lock);
		p = p_find(SCARG(uap, pid), PFIND_LOCKED);
		if (p == NULL) {
			mutex_exit(proc_lock);
			error = ESRCH;
			goto out;
		}
		mutex_enter(p->p_lock);
		mutex_exit(proc_lock);
		/* Disallow modification of system processes. */
		if ((p->p_flag & PK_SYSTEM) != 0) {
			mutex_exit(p->p_lock);
			error = EPERM;
			goto out;
		}
	} else {
		/* Use the calling process */
		p = l->l_proc;
		mutex_enter(p->p_lock);
	}

	/*
	 * Check the permission.
	 */
	error = kauth_authorize_process(l->l_cred,
	    KAUTH_PROCESS_SCHEDULER_SETAFFINITY, p, NULL, NULL, NULL);
	if (error != 0) {
		mutex_exit(p->p_lock);
		goto out;
	}

#ifdef KERN_SA
	/* Changing the affinity of a SA process is not supported */
	if ((p->p_sflag & (PS_SA | PS_WEXIT)) != 0 || p->p_sa != NULL) {
		mutex_exit(p->p_lock);
		error = EINVAL;
		goto out;
	}
#endif

	/* Find the LWP(s) */
	lcnt = 0;
	lid = SCARG(uap, lid);
	LIST_FOREACH(t, &p->p_lwps, l_sibling) {
		if (lid && lid != t->l_lid)
			continue;
		lwp_lock(t);
		/* It is not allowed to set the affinity for zombie LWPs */
		if (t->l_stat == LSZOMB) {
			lwp_unlock(t);
			continue;
		}
		if (cpuset) {
			/* Set the affinity flag and new CPU set */
			t->l_flag |= LW_AFFINITY;
			kcpuset_use(cpuset);
			if (t->l_affinity != NULL)
				kcpuset_unuse(t->l_affinity, &cpulst);
			t->l_affinity = cpuset;
			/* Migrate to another CPU, unlocks LWP */
			lwp_migrate(t, ci);
		} else {
			/* Unset the affinity flag */
			t->l_flag &= ~LW_AFFINITY;
			if (t->l_affinity != NULL)
				kcpuset_unuse(t->l_affinity, &cpulst);
			t->l_affinity = NULL;
			lwp_unlock(t);
		}
		lcnt++;
	}
	mutex_exit(p->p_lock);
	if (lcnt == 0)
		error = ESRCH;
out:
	mutex_exit(&cpu_lock);
	if (cpuset != NULL)
		kcpuset_unuse(cpuset, &cpulst);
	kcpuset_destroy(cpulst);
	return error;
}

/*
 * Get affinity.
 */
int
sys__sched_getaffinity(struct lwp *l,
    const struct sys__sched_getaffinity_args *uap, register_t *retval)
{
	/* {
		syscallarg(pid_t) pid;
		syscallarg(lwpid_t) lid;
		syscallarg(size_t) size;
		syscallarg(cpuset_t *) cpuset;
	} */
	struct lwp *t;
	kcpuset_t *cpuset;
	int error;

	error = genkcpuset(&cpuset, SCARG(uap, cpuset), SCARG(uap, size));
	if (error)
		return error;

	/* Locks the LWP */
	t = lwp_find2(SCARG(uap, pid), SCARG(uap, lid));
	if (t == NULL) {
		error = ESRCH;
		goto out;
	}
	/* Check the permission */
	if (kauth_authorize_process(l->l_cred,
	    KAUTH_PROCESS_SCHEDULER_GETAFFINITY, t->l_proc, NULL, NULL, NULL)) {
		mutex_exit(t->l_proc->p_lock);
		error = EPERM;
		goto out;
	}
	lwp_lock(t);
	if (t->l_flag & LW_AFFINITY) {
		KASSERT(t->l_affinity != NULL);
		kcpuset_copy(cpuset, t->l_affinity);
	} else
		kcpuset_zero(cpuset);
	lwp_unlock(t);
	mutex_exit(t->l_proc->p_lock);

	error = kcpuset_copyout(cpuset, SCARG(uap, cpuset), SCARG(uap, size));
out:
	kcpuset_unuse(cpuset, NULL);
	return error;
}

/*
 * Yield.
 */
int
sys_sched_yield(struct lwp *l, const void *v, register_t *retval)
{

	yield();
#ifdef KERN_SA
	if (l->l_flag & LW_SA) {
		sa_preempt(l);
	}
#endif
	return 0;
}

/*
 * Sysctl nodes and initialization.
 */
SYSCTL_SETUP(sysctl_sched_setup, "sysctl sched setup")
{
	const struct sysctlnode *node = NULL;

	sysctl_createv(clog, 0, NULL, NULL,
		CTLFLAG_PERMANENT,
		CTLTYPE_NODE, "kern", NULL,
		NULL, 0, NULL, 0,
		CTL_KERN, CTL_EOL);
	sysctl_createv(clog, 0, NULL, NULL,
		CTLFLAG_PERMANENT|CTLFLAG_IMMEDIATE,
		CTLTYPE_INT, "posix_sched",
		SYSCTL_DESCR("Version of IEEE Std 1003.1 and its "
			     "Process Scheduling option to which the "
			     "system attempts to conform"),
		NULL, _POSIX_PRIORITY_SCHEDULING, NULL, 0,
		CTL_KERN, CTL_CREATE, CTL_EOL);
	sysctl_createv(clog, 0, NULL, &node,
		CTLFLAG_PERMANENT,
		CTLTYPE_NODE, "sched",
		SYSCTL_DESCR("Scheduler options"),
		NULL, 0, NULL, 0,
		CTL_KERN, CTL_CREATE, CTL_EOL);

	if (node == NULL)
		return;

	sysctl_createv(clog, 0, &node, NULL,
		CTLFLAG_PERMANENT | CTLFLAG_IMMEDIATE,
		CTLTYPE_INT, "pri_min",
		SYSCTL_DESCR("Minimal POSIX real-time priority"),
		NULL, SCHED_PRI_MIN, NULL, 0,
		CTL_CREATE, CTL_EOL);
	sysctl_createv(clog, 0, &node, NULL,
		CTLFLAG_PERMANENT | CTLFLAG_IMMEDIATE,
		CTLTYPE_INT, "pri_max",
		SYSCTL_DESCR("Maximal POSIX real-time priority"),
		NULL, SCHED_PRI_MAX, NULL, 0,
		CTL_CREATE, CTL_EOL);
}
