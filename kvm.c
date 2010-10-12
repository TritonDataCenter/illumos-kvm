
/* Solaris kvm (kernel virtual machine) driver */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/uio.h>
#include <sys/buf.h>
#include <sys/modctl.h>
#include <sys/open.h>
#include <sys/kmem.h>
#include <sys/poll.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/atomic.h>
#include <sys/spl.h>
#include <sys/cpuvar.h>

#include "kvm.h"

extern struct kvm *kvm_arch_create_vm(void);
extern void kvm_arch_destroy_vm(struct kvm *kvmp);
extern int kvm_arch_hardware_enable(void *garbage);
extern void kvm_arch_hardware_disable(void *garbage);

static cpuset_t cpus_hardware_enabled;
static volatile uint32_t hardware_enable_failed;
static int kvm_usage_count;
static list_t vm_list;
kmutex_t kvm_lock;
kmem_cache_t *kvm_cache;

/*
 * The entire state of the kvm device.
 */
typedef struct {
	dev_info_t	*dip;		/* my devinfo handle */
} kvm_devstate_t;

/*
 * An opaque handle where the kvm device state lives
 */
static void *kvm_state;

static int kvm_open(dev_t *devp, int flag, int otyp, cred_t *cred);
static int kvm_close(dev_t dev, int flag, int otyp, cred_t *cred);
static int kvm_read(dev_t dev, struct uio *uiop, cred_t *credp);
static int kvm_write(dev_t dev, struct uio *uiop, cred_t *credp);
static int kvm_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
		     cred_t *cred_p, int *rval_p);
static int kvm_devmap(dev_t dev, devmap_cookie_t dhp, offset_t off,
		      size_t len, size_t *maplen, uint_t model);

static struct cb_ops kvm_cb_ops = {
	kvm_open,
	kvm_close,	/* close */
	nodev,
	nodev,
	nodev,		/* dump */
	nodev,		/* read */
	nodev,		/* write */
	kvm_ioctl,
	kvm_devmap,
	nodev,		/* mmap */
	nodev,		/* segmap */
	nochpoll,	/* poll */
	ddi_prop_op,
	NULL,
	D_NEW | D_MP
};

static int kvm_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
    void **result);
static int kvm_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int kvm_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);

static struct dev_ops kvm_ops = {
	DEVO_REV,
	0,
	kvm_getinfo,
	nulldev,	/* identify */
	nulldev,	/* probe */
	kvm_attach,
	kvm_detach,
	nodev,		/* reset */
	&kvm_cb_ops,
	(struct bus_ops *)0
};


extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,
	"kvm driver v0.1",
	&kvm_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	0
};

int
_init(void)
{
	int e;

	if ((e = ddi_soft_state_init(&kvm_state,
	    sizeof (kvm_devstate_t), 1)) != 0) {
		return (e);
	}

	if ((e = mod_install(&modlinkage)) != 0)  {
		ddi_soft_state_fini(&kvm_state);
	}

	mutex_init(&kvm_lock, NULL, MUTEX_DRIVER, 0);  /* XXX */
	return (e);
}

int
_fini(void)
{
	int e;

	if ((e = mod_remove(&modlinkage)) != 0)  {
		return (e);
	}
	ddi_soft_state_fini(&kvm_state);
	return (e);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
kvm_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int instance;
	kvm_devstate_t *rsp;

	switch (cmd) {

	case DDI_ATTACH:

		instance = ddi_get_instance(dip);

		if (ddi_soft_state_zalloc(kvm_state, instance) != DDI_SUCCESS) {
			cmn_err(CE_CONT, "%s%d: can't allocate state\n",
			    ddi_get_name(dip), instance);
			return (DDI_FAILURE);
		} else
			rsp = ddi_get_soft_state(kvm_state, instance);

		kvm_cache = kmem_cache_create("kvm_cache", KVM_VM_DATA_SIZE,
					      ptob(1),  NULL, NULL, NULL, NULL, NULL, 0);
		if (ddi_create_minor_node(dip, "kvm", S_IFCHR,
		    instance, DDI_PSEUDO, 0) == DDI_FAILURE) {
			ddi_remove_minor_node(dip, NULL);
			goto attach_failed;
		}

		rsp->dip = dip;
		ddi_report_dev(dip);

		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

attach_failed:
	if (kvm_cache)
		kmem_cache_destroy(kvm_cache);
	(void) kvm_detach(dip, DDI_DETACH);
	return (DDI_FAILURE);
}

static int
kvm_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int instance;
	register kvm_devstate_t *rsp;

	switch (cmd) {

	case DDI_DETACH:
		ddi_prop_remove_all(dip);
		instance = ddi_get_instance(dip);
		rsp = ddi_get_soft_state(kvm_state, instance);
		ddi_remove_minor_node(dip, NULL);
		ddi_soft_state_free(kvm_state, instance);
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

/*ARGSUSED*/
static int
kvm_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	kvm_devstate_t *rsp;
	int error = DDI_FAILURE;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if ((rsp = ddi_get_soft_state(kvm_state,
		    getminor((dev_t)arg))) != NULL) {
			*result = rsp->dip;
			error = DDI_SUCCESS;
		} else
			*result = NULL;
		break;

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)getminor((dev_t)arg);
		error = DDI_SUCCESS;
		break;

	default:
		break;
	}

	return (error);
}


/*ARGSUSED*/
static int
kvm_open(dev_t *devp, int flag, int otyp, cred_t *cred)
{
	if (otyp != OTYP_BLK && otyp != OTYP_CHR)
		return (EINVAL);

	if (ddi_get_soft_state(kvm_state, getminor(*devp)) == NULL)
		return (ENXIO);

	return (0);
}

/*ARGSUSED*/
static int
kvm_close(dev_t dev, int flag, int otyp, cred_t *cred)
{
	return (0);
}


static void hardware_enable(void *junk)
{
	int cpu;
	int r;

	cpu = curthread->t_cpu->cpu_id;

	if (CPU_IN_SET(cpus_hardware_enabled, cpu))
		return;

	CPUSET_ADD(cpus_hardware_enabled, cpu);

	r = kvm_arch_hardware_enable(NULL);

	if (r) {
		CPUSET_DEL(cpus_hardware_enabled, cpu);
		atomic_inc_32(&hardware_enable_failed);
		cmn_err(CE_WARN, "kvm: enabling virtualization CPU%d failed\n",
			cpu);
	}
}

static void hardware_disable(void *junk)
{
	int cpu = curthread->t_cpu->cpu_id;

	if (!CPU_IN_SET(cpus_hardware_enabled,cpu))
		return;
	CPUSET_DEL(cpus_hardware_enabled, cpu);
	kvm_arch_hardware_disable(NULL);
}

extern unsigned int ddi_enter_critical(void);
extern void ddi_exit_critical(unsigned int d);

#define on_each_cpu(func, info, wait) \
	({                            \
	unsigned int d;               \
	d = ddi_enter_critical();     \
	func(info);                   \
	ddi_exit_critical(d);         \
	0;			      \
	})

static void hardware_disable_all_nolock(void)
{
	kvm_usage_count--;
	if (!kvm_usage_count)
		on_each_cpu(hardware_disable, NULL, 1);
}

static void hardware_disable_all(void)
{
	mutex_enter(&kvm_lock);
	hardware_disable_all_nolock();
	mutex_exit(&kvm_lock);
}

static int hardware_enable_all(void)
{
	int r = 0;

	mutex_enter(&kvm_lock);

	kvm_usage_count++;
	if (kvm_usage_count == 1) {
		hardware_enable_failed = 0;
		on_each_cpu(hardware_enable, NULL, 1);

		if (hardware_enable_failed) {
			hardware_disable_all_nolock();
			r = EBUSY;
		}
	}

	mutex_exit(&kvm_lock);

	return r;
}

#if defined(CONFIG_MMU_NOTIFIER) && defined(KVM_ARCH_WANT_MMU_NOTIFIER)
static inline struct kvm *mmu_notifier_to_kvm(struct mmu_notifier *mn)
{
	return container_of(mn, struct kvm, mmu_notifier);
}

static void kvm_mmu_notifier_invalidate_page(struct mmu_notifier *mn,
					     struct mm_struct *mm,
					     unsigned long address)
{
	struct kvm *kvm = mmu_notifier_to_kvm(mn);
	int need_tlb_flush, idx;

	/*
	 * When ->invalidate_page runs, the linux pte has been zapped
	 * already but the page is still allocated until
	 * ->invalidate_page returns. So if we increase the sequence
	 * here the kvm page fault will notice if the spte can't be
	 * established because the page is going to be freed. If
	 * instead the kvm page fault establishes the spte before
	 * ->invalidate_page runs, kvm_unmap_hva will release it
	 * before returning.
	 *
	 * The sequence increase only need to be seen at spin_unlock
	 * time, and not at spin_lock time.
	 *
	 * Increasing the sequence after the spin_unlock would be
	 * unsafe because the kvm page fault could then establish the
	 * pte after kvm_unmap_hva returned, without noticing the page
	 * is going to be freed.
	 */
	idx = srcu_read_lock(&kvm->srcu);
	spin_lock(&kvm->mmu_lock);
	kvm->mmu_notifier_seq++;
	need_tlb_flush = kvm_unmap_hva(kvm, address);
	spin_unlock(&kvm->mmu_lock);
	srcu_read_unlock(&kvm->srcu, idx);

	/* we've to flush the tlb before the pages can be freed */
	if (need_tlb_flush)
		kvm_flush_remote_tlbs(kvm);

}

static void kvm_mmu_notifier_change_pte(struct mmu_notifier *mn,
					struct mm_struct *mm,
					unsigned long address,
					pte_t pte)
{
	struct kvm *kvm = mmu_notifier_to_kvm(mn);
	int idx;

	idx = srcu_read_lock(&kvm->srcu);
	spin_lock(&kvm->mmu_lock);
	kvm->mmu_notifier_seq++;
	kvm_set_spte_hva(kvm, address, pte);
	spin_unlock(&kvm->mmu_lock);
	srcu_read_unlock(&kvm->srcu, idx);
}

static void kvm_mmu_notifier_invalidate_range_start(struct mmu_notifier *mn,
						    struct mm_struct *mm,
						    unsigned long start,
						    unsigned long end)
{
	struct kvm *kvm = mmu_notifier_to_kvm(mn);
	int need_tlb_flush = 0, idx;

	idx = srcu_read_lock(&kvm->srcu);
	spin_lock(&kvm->mmu_lock);
	/*
	 * The count increase must become visible at unlock time as no
	 * spte can be established without taking the mmu_lock and
	 * count is also read inside the mmu_lock critical section.
	 */
	kvm->mmu_notifier_count++;
	for (; start < end; start += PAGE_SIZE)
		need_tlb_flush |= kvm_unmap_hva(kvm, start);
	spin_unlock(&kvm->mmu_lock);
	srcu_read_unlock(&kvm->srcu, idx);

	/* we've to flush the tlb before the pages can be freed */
	if (need_tlb_flush)
		kvm_flush_remote_tlbs(kvm);
}

static void kvm_mmu_notifier_invalidate_range_end(struct mmu_notifier *mn,
						  struct mm_struct *mm,
						  unsigned long start,
						  unsigned long end)
{
	struct kvm *kvm = mmu_notifier_to_kvm(mn);

	spin_lock(&kvm->mmu_lock);
	/*
	 * This sequence increase will notify the kvm page fault that
	 * the page that is going to be mapped in the spte could have
	 * been freed.
	 */
	kvm->mmu_notifier_seq++;
	/*
	 * The above sequence increase must be visible before the
	 * below count decrease but both values are read by the kvm
	 * page fault under mmu_lock spinlock so we don't need to add
	 * a smb_wmb() here in between the two.
	 */
	kvm->mmu_notifier_count--;
	spin_unlock(&kvm->mmu_lock);

	BUG_ON(kvm->mmu_notifier_count < 0);
}

static int kvm_mmu_notifier_clear_flush_young(struct mmu_notifier *mn,
					      struct mm_struct *mm,
					      unsigned long address)
{
	struct kvm *kvm = mmu_notifier_to_kvm(mn);
	int young, idx;

	idx = srcu_read_lock(&kvm->srcu);
	spin_lock(&kvm->mmu_lock);
	young = kvm_age_hva(kvm, address);
	spin_unlock(&kvm->mmu_lock);
	srcu_read_unlock(&kvm->srcu, idx);

	if (young)
		kvm_flush_remote_tlbs(kvm);

	return young;
}

static void kvm_mmu_notifier_release(struct mmu_notifier *mn,
				     struct mm_struct *mm)
{
	struct kvm *kvm = mmu_notifier_to_kvm(mn);
	int idx;

	idx = srcu_read_lock(&kvm->srcu);
	kvm_arch_flush_shadow(kvm);
	srcu_read_unlock(&kvm->srcu, idx);
}

static const struct mmu_notifier_ops kvm_mmu_notifier_ops = {
	.invalidate_page	= kvm_mmu_notifier_invalidate_page,
	.invalidate_range_start	= kvm_mmu_notifier_invalidate_range_start,
	.invalidate_range_end	= kvm_mmu_notifier_invalidate_range_end,
	.clear_flush_young	= kvm_mmu_notifier_clear_flush_young,
	.change_pte		= kvm_mmu_notifier_change_pte,
	.release		= kvm_mmu_notifier_release,
};

static int kvm_init_mmu_notifier(struct kvm *kvm)
{
	kvm->mmu_notifier.ops = &kvm_mmu_notifier_ops;
	return mmu_notifier_register(&kvm->mmu_notifier, current->mm);
}

#else  /* !(CONFIG_MMU_NOTIFIER && KVM_ARCH_WANT_MMU_NOTIFIER) */

static int kvm_init_mmu_notifier(struct kvm *kvm)
{
	return 0;
}

#endif /* CONFIG_MMU_NOTIFIER && KVM_ARCH_WANT_MMU_NOTIFIER */


static
struct kvm *
kvm_create_vm(void)
{
	int rval = 0;
	int i;
	struct kvm *kvmp = kvm_arch_create_vm();
	proc_t *p;

	if (kvmp == NULL)
		return (NULL);

	rval = hardware_enable_all();

	if (rval != 0) {
		kvm_arch_destroy_vm(kvmp);
		return (NULL);
	}

	kvmp->memslots = kmem_zalloc(sizeof(struct kvm_memslots), KM_NOSLEEP);
	if (!kvmp->memslots) {
		kvm_arch_destroy_vm(kvmp);
		return (NULL);
	}

	rw_init(&kvmp->kvm_rwlock, NULL, RW_DRIVER, NULL);

	rval = kvm_init_mmu_notifier(kvmp);
	
	if (rval != DDI_SUCCESS) {
		rw_destroy(&kvmp->kvm_rwlock);
		kvm_arch_destroy_vm(kvmp);
		return (NULL);
	}

	if (drv_getparm(UPROCP, &p) != 0)
		cmn_err(CE_PANIC, "Cannot get proc_t for current process\n");

	kvmp->mm = p->p_as;  /* XXX note that the as struct does not contain */
	                    /* a refcnt, may have to go lower */
	mutex_init(&kvmp->mmu_lock, NULL, MUTEX_SPIN,
		   (void *)ipltospl(DISP_LEVEL));  /* could be adaptive ?? */
	mutex_init(&kvmp->requests_lock, NULL, MUTEX_SPIN,
		   (void *)ipltospl(DISP_LEVEL));
#ifdef XXX
	kvm_eventfd_init(kvmp);
#endif
	mutex_init(&kvmp->lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&kvmp->irq_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&kvmp->slots_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_enter(&kvm_lock);
	kvmp->users_count = 1;
	list_insert_tail(&vm_list, &kvmp->vm_list);
	mutex_exit(&kvm_lock);

	return (kvmp);
}
	
static int
kvm_dev_ioctl_create_vm(void)
{
	struct kvm *kvmp;

	kvmp = kvm_create_vm();
	if (kvmp == NULL) {
		cmn_err(CE_WARN, "Could not create new vm\n");
		return (-1);
	}

	return (DDI_SUCCESS);
}

static long 
kvm_dev_ioctl_check_extension_generic(long arg)
{
	return (EINVAL);
}

static int
kvm_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *cred_p, int *rval_p)
{
	int rval = EINVAL;

	switch(cmd) {
	case KVM_GET_API_VERSION:
		if (arg != NULL)
			return (rval);
		*rval_p = KVM_API_VERSION;
		break;
	case KVM_CREATE_VM:
		if (arg != NULL)
			return (rval);
		*rval_p = kvm_dev_ioctl_create_vm();
		break;
	case KVM_CHECK_EXTENSION:
		*rval_p = kvm_dev_ioctl_check_extension_generic(arg);
		break;
	case KVM_GET_VCPU_MMAP_SIZE:
		if (arg != NULL)
			return (rval);
		*rval_p = ptob(1);
		break;
	default:
		return (rval);  /* x64, others may do other things... */
	}
	if (*rval_p == -1)
		return (EINVAL);
	return (DDI_SUCCESS);
}

static int
kvm_devmap(dev_t dev, devmap_cookie_t dhp, offset_t off,
		      size_t len, size_t *maplen, uint_t model)
{
	return (ENOTSUP);
}

