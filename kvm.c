
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
#include <sys/segments.h>
#include <sys/cred.h>
#include <sys/devops.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/vm.h>
#include <sys/proc.h>
#include <vm/seg_kpm.h>
#include <sys/avl.h>
#include <sys/condvar_impl.h>
#include <sys/file.h>
#include <sys/vnode.h>
#include <sys/strsubr.h>
#include <sys/stream.h>

#include "bitops.h"
#include "vmx.h"
#include "msr-index.h"
#include "msr.h"
#include "irqflags.h"
#include "kvm_host.h"
#include "kvm_lapic.h"
#include "processor-flags.h"
#include "kvm_cpuid.h"
#include "hyperv.h"
#include "apicdef.h"
#include "kvm_iodev.h"
#include "kvm.h"
#include "irq.h"
#include "tss.h"
#include "kvm_ioapic.h"
#include "kvm_coalesced_mmio.h"
#include "kvm_i8254.h"
#include "kvm_mmu.h"
#include "kvm_cache_regs.h"

#undef DEBUG

/*
 * The entire state of the kvm device.
 */
typedef struct {
	struct kvm *kds_kvmp;			/* pointer to underlying VM */
	struct kvm_vcpu *kds_vcpu;		/* pointer to VCPU */
} kvm_devstate_t;

/*
 * Tunables
 */
static int kvm_hiwat = 0x1000000;

/*
 * Internal driver-wide values
 */
static void *kvm_state;		/* DDI state */
static vmem_t *kvm_minor;	/* minor number arena */
static dev_info_t *kvm_dip;	/* global devinfo hanlde */
static minor_t kvm_base_minor;	/* The only minor device that can be opened */

int kvmid;  /* monotonically increasing, unique per vm */

int largepages_enabled = 1;
static cpuset_t cpus_hardware_enabled;
static volatile uint32_t hardware_enable_failed;
static int kvm_usage_count;
static list_t vm_list;
kmutex_t kvm_lock;

/*
 * Driver forward declarations
 */
static int kvm_open(dev_t *devp, int flag, int otyp, cred_t *cred);
static int kvm_close(dev_t dev, int flag, int otyp, cred_t *cred);
static int kvm_read(dev_t dev, struct uio *uiop, cred_t *credp);
static int kvm_write(dev_t dev, struct uio *uiop, cred_t *credp);
static int kvm_ioctl(dev_t dev, int cmd, intptr_t arg, int md,
    cred_t *cred_p, int *rv);
static int kvm_devmap(dev_t dev, devmap_cookie_t dhp, offset_t off,
    size_t len, size_t *maplen, uint_t model);
static int kvm_segmap(dev_t, off_t, struct as *, caddr_t *, off_t,
    unsigned int, unsigned int, unsigned int, cred_t *);
static int kvm_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
    void **result);
static int kvm_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int kvm_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);

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
	kvm_segmap,	/* segmap */
	nochpoll,	/* poll */
	ddi_prop_op,
	NULL,
	D_NEW | D_MP | D_DEVMAP
};
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
	{ &modldrv, NULL }
};

extern struct kvm *kvm_arch_create_vm(void);
extern void kvm_arch_destroy_vm(struct kvm *kvmp);
extern int kvm_arch_hardware_enable(void *garbage);
extern void kvm_arch_hardware_disable(void *garbage);
extern long kvm_vm_ioctl(struct kvm *kvmp, unsigned int ioctl,
    unsigned long arg, int md);
static void hardware_enable(void *junk);
static void hardware_disable(void *junk);
extern struct kvm_vcpu *vmx_create_vcpu(struct kvm *kvm,
    unsigned int id);
extern void vmx_destroy_vcpu(struct kvm_vcpu *);
extern int vmx_vcpu_reset(struct kvm_vcpu *vcpu);
void vmx_vcpu_load(struct kvm_vcpu *vcpu, int cpu);
void vmx_vcpu_put(struct kvm_vcpu *vcpu);
extern void vmx_set_cr0(struct kvm_vcpu *vcpu, unsigned long cr0);
extern void vmx_set_cr4(struct kvm_vcpu *vcpu, unsigned long cr4);
extern int vmx_set_tss_addr(struct kvm *kvmp, caddr_t addr);
static int vmx_hardware_setup(void);
extern unsigned long vmx_get_rflags(struct kvm_vcpu *vcpu);
void vmcs_writel(unsigned long field, unsigned long value);
unsigned long vmcs_readl(unsigned long field);
extern void vmx_set_rflags(struct kvm_vcpu *vcpu, unsigned long rflags);
void vmx_get_segment(struct kvm_vcpu *vcpu,
    struct kvm_segment *var, int seg);
static void vmx_set_segment(struct kvm_vcpu *vcpu,
			    struct kvm_segment *var, int seg);
static void vmx_update_cr8_intercept(struct kvm_vcpu *vcpu, int tpr, int irr);
static int vmx_get_msr(struct kvm_vcpu *vcpu, uint32_t msr_index,
    uint64_t *pdata);
static int vmx_set_msr(struct kvm_vcpu *vcpu, uint32_t msr_index,
    uint64_t data);
static void vmx_vcpu_run(struct kvm_vcpu *vcpu);
static void vmx_save_host_state(struct kvm_vcpu *vcpu);


static int vmx_handle_exit(struct kvm_vcpu *vcpu);
int vmx_interrupt_allowed(struct kvm_vcpu *vcpu);
static int vmx_get_lpage_level(void);
static int vmx_rdtscp_supported(void);
void vmx_set_efer(struct kvm_vcpu *vcpu, uint64_t efer);
static uint64_t vmx_get_segment_base(struct kvm_vcpu *vcpu, int seg);
static void vmx_get_idt(struct kvm_vcpu *vcpu, struct descriptor_table *dt);
static void vmx_set_idt(struct kvm_vcpu *vcpu, struct descriptor_table *dt);
static void vmx_get_gdt(struct kvm_vcpu *vcpu, struct descriptor_table *dt);
static void vmx_set_gdt(struct kvm_vcpu *vcpu, struct descriptor_table *dt);
static int vmx_get_cpl(struct kvm_vcpu *vcpu);
static uint32_t vmx_get_interrupt_shadow(struct kvm_vcpu *vcpu, int mask);
static void vmx_set_interrupt_shadow(struct kvm_vcpu *vcpu, int mask);
static void skip_emulated_instruction(struct kvm_vcpu *vcpu);
static void vmx_inject_irq(struct kvm_vcpu *vcpu);
static void vmx_inject_nmi(struct kvm_vcpu *vcpu);
static void vmx_queue_exception(struct kvm_vcpu *vcpu, unsigned nr,
				int has_error_code, uint32_t error_code);
static int vmx_nmi_allowed(struct kvm_vcpu *vcpu);
static int vmx_get_nmi_mask(struct kvm_vcpu *vcpu);
static void vmx_set_nmi_mask(struct kvm_vcpu *vcpu, int masked);
static void enable_nmi_window(struct kvm_vcpu *vcpu);
static void enable_irq_window(struct kvm_vcpu *vcpu);
static void vmx_cpuid_update(struct kvm_vcpu *vcpu);
static void vmx_fpu_deactivate(struct kvm_vcpu *vcpu);
static void vmx_decache_cr0_guest_bits(struct kvm_vcpu *vcpu);
static void vmx_decache_cr4_guest_bits(struct kvm_vcpu *vcpu);
void vmx_fpu_activate(struct kvm_vcpu *vcpu);
void kvm_set_pfn_dirty(pfn_t);
extern void kvm_set_cr8(struct kvm_vcpu *vcpu, unsigned long cr8);
extern void kvm_release_pfn_dirty(pfn_t pfn);
extern void kvm_release_pfn_clean(pfn_t pfn);
extern void kvm_mmu_free_some_pages(struct kvm_vcpu *vcpu);
extern int mmu_topup_memory_caches(struct kvm_vcpu *vcpu);
static int hardware_enable_all(void);
static void hardware_disable_all(void);
extern int sigprocmask(int, const sigset_t *, sigset_t *);
extern void cli(void);
extern void sti(void);
static void kvm_destroy_vm(struct kvm *);
static int kvm_avlmmucmp(const void *, const void *);

int get_ept_level(void);
static void vmx_cache_reg(struct kvm_vcpu *vcpu, enum kvm_reg reg);

/*
 * XXX
 */
extern int enable_vpid;
extern struct kvm_x86_ops vmx_x86_ops;
extern int vmx_init(void);
extern uint32_t bit(int);
extern struct kvm_shared_msrs **shared_msrs;
extern int make_all_cpus_request(struct kvm *, unsigned int);
extern int is_long_mode(struct kvm_vcpu *);
extern int tdp_enabled;
extern void kvm_mmu_pte_write(struct kvm_vcpu *, gpa_t, const uint8_t *,
    int, int);
extern int kvm_mmu_unprotect_page_virt(struct kvm_vcpu *, gva_t);
extern void kvm_mmu_sync_roots(struct kvm_vcpu *);
extern void kvm_mmu_flush_tlb(struct kvm_vcpu *);
extern void kvm_mmu_unload(struct kvm_vcpu *vcpu);
extern int kvm_pic_set_irq(void *, int, int);

/*
 * Find the first cleared bit in a memory region.
 */
unsigned long
find_first_zero_bit(const unsigned long *addr, unsigned long size)
{
	const unsigned long *p = addr;
	unsigned long result = 0;
	unsigned long tmp;

	while (size & ~(64-1)) {
		if (~(tmp = *(p++)))
			goto found;
		result += 64;
		size -= 64;
	}
	if (!size)
		return (result);

	tmp = (*p) | (~0UL << size);
	if (tmp == ~0UL)	/* Are any bits zero? */
		return (result + size);	/* Nope. */
found:
	return (result + ffz(tmp));
}


static void vmx_get_cs_db_l_bits(struct kvm_vcpu *vcpu, int *db, int *l);
extern void update_exception_bitmap(struct kvm_vcpu *vcpu);

extern struct vmcs_config vmcs_config;

static int setup_vmcs_config(struct vmcs_config *vmcs_conf);


struct kvm_x86_ops *kvm_x86_ops;







inline int
kvm_exception_is_soft(unsigned int nr)
{
	return (nr == BP_VECTOR) || (nr == OF_VECTOR);
}

/*
 * EFER defaults:
 * - enable syscall per default because its emulated by KVM
 * - enable LME and LMA per default on 64 bit KVM
 */
#ifdef CONFIG_X86_64
static uint64_t efer_reserved_bits = 0xfffffffffffffafeULL;
#else
static uint64_t efer_reserved_bits = 0xfffffffffffffffeULL;
#endif

void
kvm_enable_efer_bits(uint64_t mask)
{
	efer_reserved_bits &= ~mask;
}

void
kvm_disable_largepages(void)
{
	largepages_enabled = 0;
}

int
kvm_arch_hardware_setup(void)
{
	return (kvm_x86_ops->hardware_setup());
}

static void *
mmu_memory_cache_alloc(struct kvm_mmu_memory_cache *mc, size_t size)
{
	return (mc->objects[--mc->nobjs]);
}

void
bitmap_zero(unsigned long *dst, int nbits)
{
	int len = BITS_TO_LONGS(nbits) * sizeof (unsigned long);
	memset(dst, 0, len);
}

extern page_t *pfn_to_page(pfn_t pfn);

struct kvm_mmu_page *
page_private(kvm_t *kvmp, page_t *page)
{
	kvm_mmu_page_t mp, *res;
	mp.kmp_avlspt = (uintptr_t)page;
	mutex_enter(&kvmp->kvm_avllock);
	res = avl_find(&kvmp->kvm_avlmp, &mp, NULL);
	mutex_exit(&kvmp->kvm_avllock);
	ASSERT(res != NULL);
	return (res);
}

inline struct kvm_mmu_page *
page_header(kvm_t *kvmp, hpa_t shadow_page)
{
	return (page_private(kvmp, pfn_to_page(shadow_page >> PAGESHIFT)));
}







struct kvm_memory_slot *
gfn_to_memslot_unaliased(struct kvm *kvm, gfn_t gfn)
{
	int i;
#ifdef XXX_KVM_DECLARATION
	struct kvm_memslots *slots = rcu_dereference(kvm->memslots);
#else
	struct kvm_memslots *slots = kvm->memslots;
#endif

	for (i = 0; i < slots->nmemslots; ++i) {
		struct kvm_memory_slot *memslot = &slots->memslots[i];

		if (gfn >= memslot->base_gfn &&
		    gfn < memslot->base_gfn + memslot->npages)
			return (memslot);
	}
	return (NULL);
}

void
kvm_reload_remote_mmus(struct kvm *kvm)
{
	make_all_cpus_request(kvm, KVM_REQ_MMU_RELOAD);
}

gfn_t
unalias_gfn_instantiation(struct kvm *kvm, gfn_t gfn)
{
	int i;
	struct kvm_mem_alias *alias;
	struct kvm_mem_aliases *aliases;
#ifdef XXX
	aliases = rcu_dereference(kvm->arch.aliases);
#else
	XXX_KVM_SYNC_PROBE;
	aliases = kvm->arch.aliases;
#endif

	for (i = 0; i < aliases->naliases; i++) {
		alias = &aliases->aliases[i];
		if (alias->flags & KVM_ALIAS_INVALID)
			continue;
		if (gfn >= alias->base_gfn &&
		    gfn < alias->base_gfn + alias->npages)
			return (alias->target_gfn + gfn - alias->base_gfn);
	}

	return (gfn);
}

int
kvm_is_visible_gfn(struct kvm *kvm, gfn_t gfn)
{
	int i;
#ifdef XXX_KVM_DECLARATION
	struct kvm_memslots *slots = rcu_dereference(kvm->memslots);
#else
	struct kvm_memslots *slots = kvm->memslots;
#endif

	gfn = unalias_gfn_instantiation(kvm, gfn);

	for (i = 0; i < KVM_MEMORY_SLOTS; ++i) {
		struct kvm_memory_slot *memslot = &slots->memslots[i];

		if (memslot->flags & KVM_MEMSLOT_INVALID)
			continue;

		if (gfn >= memslot->base_gfn &&
		    gfn < memslot->base_gfn + memslot->npages) {
			return (1);
		}
	}

	return (0);
}



int
zero_constructor(void *buf, void *arg, int tags)
{
	bzero(buf, (size_t)arg);
	return (0);
}


/*
 * List of msr numbers which we expose to userspace through KVM_GET_MSRS
 * and KVM_SET_MSRS, and KVM_GET_MSR_INDEX_LIST.
 *
 * This list is modified at module load time to reflect the
 * capabilities of the host cpu. This capabilities test skips MSRs that are
 * kvm-specific. Those are put in the beginning of the list.
 */

#define	MSR_KVM_WALL_CLOCK  0x11
#define	MSR_KVM_SYSTEM_TIME 0x12

#define	KVM_SAVE_MSRS_BEGIN	5
static uint32_t msrs_to_save[] = {
	MSR_KVM_SYSTEM_TIME, MSR_KVM_WALL_CLOCK,
	HV_X64_MSR_GUEST_OS_ID, HV_X64_MSR_HYPERCALL,
	HV_X64_MSR_APIC_ASSIST_PAGE,
	MSR_IA32_SYSENTER_CS, MSR_IA32_SYSENTER_ESP, MSR_IA32_SYSENTER_EIP,
	MSR_K6_STAR,
#ifdef CONFIG_X86_64
	MSR_CSTAR, MSR_KERNEL_GS_BASE, MSR_SYSCALL_MASK, MSR_LSTAR,
#endif
	MSR_IA32_TSC, MSR_IA32_PERF_STATUS, MSR_IA32_CR_PAT, MSR_VM_HSAVE_PA
};

static unsigned num_msrs_to_save;

static uint32_t emulated_msrs[] = {
	MSR_IA32_MISC_ENABLE,
};

uint64_t
native_read_msr_safe(unsigned int msr, int *err)
{
	DECLARE_ARGS(val, low, high);
	uint64_t ret = 0;
	on_trap_data_t otd;

	if (on_trap(&otd, OT_DATA_ACCESS) == 0) {
		ret = native_read_msr(msr);
		*err = 0;
	} else {
		*err = EINVAL; /* XXX probably not right... */
	}
	no_trap();

	return (ret);
}

/* Can be uninlined because referenced by paravirt */
int
native_write_msr_safe(unsigned int msr, unsigned low, unsigned high)
{
	int err = 0;
	on_trap_data_t otd;

	if (on_trap(&otd, OT_DATA_ACCESS) == 0) {
		native_write_msr(msr, low, high);
	} else {
		err = EINVAL;  /* XXX probably not right... */
	}
	no_trap();

	return (err);
}

static void
kvm_init_msr_list(void)
{
	uint32_t dummy[2];
	unsigned i, j;

	/* skip the first msrs in the list. KVM-specific */
	for (i = j = KVM_SAVE_MSRS_BEGIN; i < ARRAY_SIZE(msrs_to_save); i++) {
		if (rdmsr_safe(msrs_to_save[i], &dummy[0], &dummy[1]) < 0)
			continue;
		if (j < i)
			msrs_to_save[j] = msrs_to_save[i];
		j++;
	}
	num_msrs_to_save = j;
}

uint64_t cpu_tsc_khz;
extern uint64_t cpu_freq_hz;

static void
kvm_timer_init(void)
{
	int cpu;

	/*
	 * XXX We assume that any machine running solaris kvm
	 * has constant time stamp counter increment rate.
	 * This will be true for all but older machines.
	 */
	/* assume pi_clock in mhz */
	cpu_tsc_khz = (cpu_freq_hz / 1000);
}

int
kvm_arch_init(void *opaque)
{
	int r;
	struct kvm_x86_ops *ops = (struct kvm_x86_ops *)opaque;

	if (ops->cpu_has_kvm_support()) {
		cmn_err(CE_WARN, "kvm: no hardware support\n");
		r = ENOTSUP;
		goto out;
	}
	if (ops->disabled_by_bios()) {
		cmn_err(CE_WARN, "kvm: disabled by bios\n");
		r = ENOTSUP;
		goto out;
	}

	r = kvm_mmu_module_init();
	if (r)
		goto out;

	kvm_init_msr_list();

	kvm_x86_ops = ops;
	kvm_mmu_set_nonpresent_ptes(0ull, 0ull);
	kvm_mmu_set_base_ptes(PT_PRESENT_MASK);
	kvm_mmu_set_mask_ptes(PT_USER_MASK, PT_ACCESSED_MASK,
	    PT_DIRTY_MASK, PT64_NX_MASK, 0);

	kvm_timer_init();

	return (0);

out:
	return (r);
}

page_t *
alloc_page(size_t size, int flag)
{
	caddr_t page_addr;
	pfn_t pfn;
	page_t *pp;

	if ((page_addr = kmem_zalloc(size, flag)) == NULL)
		return ((page_t *)NULL);

	pp = page_numtopp_nolock(hat_getpfnum(kas.a_hat, page_addr));
	return (pp);
}

page_t *bad_page;
pfn_t bad_pfn;
kmem_cache_t *kvm_vcpu_cache;

void
kvm_arch_check_processor_compat(void *rtn)
{
	kvm_x86_ops->check_processor_compatibility(rtn);
}

extern void kvm_xcall(processorid_t cpu, kvm_xcall_t func, void *arg);

int
kvm_init(void *opaque, unsigned int vcpu_size)
{
	int r;
	int cpu;

	r = kvm_arch_init(opaque);

	if (r != DDI_SUCCESS)
		return (r);

	bad_page = alloc_page(PAGESIZE, KM_SLEEP);
	bad_pfn = bad_page->p_pagenum;

#ifdef XXX
	if (!zalloc_cpumask_var(&cpus_hardware_enabled, GFP_KERNEL)) {
		r = -ENOMEM;
		goto out_free_0;
	}
#else
	XXX_KVM_PROBE;
#endif
	r = kvm_arch_hardware_setup();

	if (r != DDI_SUCCESS)
		goto out_free_0a;

#ifdef XXX
	for_each_online_cpu(cpu) {
		smp_call_function_single(cpu,
				kvm_arch_check_processor_compat,
				&r, 1);
		if (r < 0)
			goto out_free_1;
	}
#else
	r = 0;
	kvm_xcall(KVM_CPUALL, kvm_arch_check_processor_compat, &r);
	if (r < 0)
		goto out_free_1;
	XXX_KVM_PROBE;
#endif


#ifdef XXX
	r = register_cpu_notifier(&kvm_cpu_notifier);
	if (r)
		goto out_free_2;
	register_reboot_notifier(&kvm_reboot_notifier);

	r = sysdev_class_register(&kvm_sysdev_class);
	if (r)
		goto out_free_3;

	r = sysdev_register(&kvm_sysdev);
	if (r)
		goto out_free_4;
#else
	XXX_KVM_PROBE;
#endif
	/* A kmem cache lets us meet the alignment requirements of fx_save. */
	kvm_vcpu_cache = kmem_cache_create("kvm_vcpu", (size_t)vcpu_size,
#ifdef XXX_KVM_DECLARATION
	    (size_t)__alignof__(struct kvm_vcpu),
#else
	    (size_t)PAGESIZE,
#endif
	    zero_constructor, NULL, NULL, (void *)((uint64_t)vcpu_size),
	    NULL, 0);

	if (!kvm_vcpu_cache) {
		r = ENOMEM;
		goto out_free_5;
	}

#ifdef XXX
	kvm_chardev_ops.owner = module;
	kvm_vm_fops.owner = module;
	kvm_vcpu_fops.owner = module;

	r = misc_register(&kvm_dev);
	if (r) {
		cmn_err(CE_WARN, "kvm: misc device register failed\n");
		goto out_free;
	}

	/*
	 * XXX - if kernel preemption occurs, we probably need
	 * to implement these, and add hooks to the preemption code.
	 * For right now, we'll make the totally unreasonable
	 * assumption that we won't be preempted while in the
	 * kernel, i.e., no realtime threads are running
	 */
	kvm_preempt_ops.sched_in = kvm_sched_in;
	kvm_preempt_ops.sched_out = kvm_sched_out;

	kvm_init_debug();
#else
	XXX_KVM_PROBE;
#endif

	return (0);

out_free:
	kmem_cache_destroy(kvm_vcpu_cache);
out_free_5:
#ifdef XXX
	sysdev_unregister(&kvm_sysdev);
out_free_4:
	sysdev_class_unregister(&kvm_sysdev_class);
out_free_3:
	unregister_reboot_notifier(&kvm_reboot_notifier);
	unregister_cpu_notifier(&kvm_cpu_notifier);
#else
	XXX_KVM_PROBE;
#endif
out_free_2:
out_free_1:
#ifdef XXX
	kvm_arch_hardware_unsetup();
#else
	XXX_KVM_PROBE;
#endif
out_free_0a:
#ifdef XXX
	free_cpumask_var(cpus_hardware_enabled);
#else
	XXX_KVM_PROBE;
#endif
out_free_0:
#ifdef XXX
	free_page(bad_page, PAGESIZE);
#else
	XXX_KVM_PROBE;
#endif
out:
#ifdef XXX
	kvm_arch_exit();
#else
	XXX_KVM_PROBE;
#endif
out_fail:
	return (r);
}



static struct kvm_shared_msrs_global shared_msrs_global;

void
kvm_define_shared_msr(unsigned slot, uint32_t msr)
{
	if (slot >= shared_msrs_global.nr)
		shared_msrs_global.nr = slot + 1;
	shared_msrs_global.msrs[slot] = msr;
#ifdef XXX
	/* we need ensured the shared_msr_global have been updated */
	smp_wmb();
#else
	XXX_KVM_SYNC_PROBE;
#endif
}

#define	VMX_NR_VPIDS				(1 << 16)
ulong_t *vmx_vpid_bitmap;
size_t vpid_bitmap_words;
kmutex_t vmx_vpid_lock;


int
_init(void)
{

	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
kvm_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	minor_t instance;

	if (kpm_enable == 0) {
		cmn_err(CE_WARN, "kvm: kpm_enable must be true\n");
		return (DDI_FAILURE);
	}


	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	if (kvm_dip != NULL)
		return (DDI_FAILURE);

	if (ddi_soft_state_init(&kvm_state, sizeof (kvm_devstate_t), 1) != 0)
		return (DDI_FAILURE);

	instance = ddi_get_instance(dip);
	if (ddi_create_minor_node(dip, "kvm",
	    S_IFCHR, instance, DDI_PSEUDO, 0) == DDI_FAILURE) {
		ddi_soft_state_fini(&kvm_state);
		return (DDI_FAILURE);
	}

	if (enable_vpid) {
		vpid_bitmap_words = howmany(VMX_NR_VPIDS, 64);
		vmx_vpid_bitmap = kmem_zalloc(sizeof (ulong_t) *
		    vpid_bitmap_words, KM_SLEEP);
		mutex_init(&vmx_vpid_lock, NULL, MUTEX_DRIVER, NULL);
	}

	mutex_init(&kvm_lock, NULL, MUTEX_DRIVER, 0);
	kvm_x86_ops = &vmx_x86_ops;
	if (vmx_init() != DDI_SUCCESS) {
		ddi_soft_state_fini(&kvm_state);
		ddi_remove_minor_node(dip, NULL);
		mutex_destroy(&kvm_lock);
		if (enable_vpid && vmx_vpid_bitmap != NULL) {
			kmem_free(vmx_vpid_bitmap,
			    sizeof (ulong_t) * vpid_bitmap_words);
			mutex_destroy(&vmx_vpid_lock);
		}

		return (DDI_FAILURE);
	}

	if (hardware_enable_all() != 0) {
		/* XXX Missing vmx_fini */
		ddi_soft_state_fini(&kvm_state);
		ddi_remove_minor_node(dip, NULL);
		mutex_destroy(&kvm_lock);
		if (enable_vpid && vmx_vpid_bitmap != NULL) {
			kmem_free(vmx_vpid_bitmap,
			    sizeof (ulong_t) * vpid_bitmap_words);
			mutex_destroy(&vmx_vpid_lock);
		}

		return (DDI_FAILURE);

	}

	kvm_dip = dip;
	kvm_base_minor = instance;

	list_create(&vm_list, sizeof (struct kvm),
	    offsetof(struct kvm, vm_list));
	kvm_minor = vmem_create("kvm_minor", (void *)1, UINT32_MAX - 1, 1,
	    NULL, NULL, NULL, 0, VM_SLEEP | VMC_IDENTIFIER);

	ddi_report_dev(dip);

	return (DDI_SUCCESS);
}

static int
kvm_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int instance;

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	VERIFY(kvm_dip != NULL && kvm_dip == dip);
	instance = ddi_get_instance(dip);
	VERIFY(instance == kvm_base_minor);
	ddi_prop_remove_all(dip);
	ddi_remove_minor_node(dip, NULL);
	list_destroy(&vm_list);
	vmem_destroy(kvm_minor);
	kvm_dip = NULL;

	hardware_disable_all();
	if (enable_vpid && vmx_vpid_bitmap != NULL) {
		kmem_free(vmx_vpid_bitmap,
		    sizeof (ulong_t) * vpid_bitmap_words);
		mutex_destroy(&vmx_vpid_lock);
	}
	mutex_destroy(&kvm_lock);
	ddi_soft_state_fini(&kvm_state);

	/* XXX Mising vmx_fini */

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
kvm_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	kvm_devstate_t *rsp;
	int error = DDI_FAILURE;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = kvm_dip;
		break;

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)((uint64_t)getminor((dev_t)arg));
		error = DDI_SUCCESS;
		break;

	default:
		break;
	}

	return (error);
}

/*ARGSUSED*/
static int
kvm_open(dev_t *devp, int flag, int otype, cred_t *credp)
{
	minor_t minor;
	kvm_devstate_t *ksp;

	if (flag & FEXCL || flag & FNDELAY)
		return (EINVAL);

	if (otype != OTYP_CHR)
		return (EINVAL);

	/*
	 * XXX This should be its own privilage
	 */
	if (drv_priv(credp) != 0)
		return (EPERM);

	if (!(flag & FREAD && flag & FWRITE))
		return (EINVAL);

	if (getminor(*devp) != kvm_base_minor)
		return (ENXIO);

	minor = (minor_t)(uintptr_t)vmem_alloc(kvm_minor,
	    1, VM_BESTFIT | VM_SLEEP);

	if (ddi_soft_state_zalloc(kvm_state, minor) != 0) {
		vmem_free(kvm_minor, (void *)(uintptr_t)minor, 1);
		return (ENXIO);
	}

	*devp = makedevice(getmajor(*devp), minor);
	ksp = ddi_get_soft_state(kvm_state, minor);
	VERIFY(ksp != NULL);

	return (0);
}

/*ARGSUSED*/
static int
kvm_close(dev_t dev, int flag, int otyp, cred_t *cred)
{
	kvm_devstate_t *ksp;
	minor_t minor = getminor(dev);
	kvm_t *kvmp;

	VERIFY(getminor(dev) != kvm_base_minor);
	ksp = ddi_get_soft_state(kvm_state, minor);

	if ((kvmp = ksp->kds_kvmp) != NULL) {
		mutex_enter(&kvm_lock);

		if (kvmp->kvm_clones > 0) {
			kvmp->kvm_clones--;
			mutex_exit(&kvm_lock);
		} else {
			mutex_exit(&kvm_lock);
			kvm_destroy_vm(kvmp);
		}
	}

	ddi_soft_state_free(kvm_state, minor);
	vmem_free(kvm_minor, (void *)(uintptr_t)minor, 1);

	return (0);
}

static void
hardware_enable(void *junk)
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

static void
hardware_disable(void *junk)
{
	int cpu = curthread->t_cpu->cpu_id;

	if (!CPU_IN_SET(cpus_hardware_enabled, cpu))
		return;

	CPUSET_DEL(cpus_hardware_enabled, cpu);
	kvm_arch_hardware_disable(NULL);
}

extern unsigned int ddi_enter_critical(void);
extern void ddi_exit_critical(unsigned int d);

/*
 * The following needs to run on each cpu.  Currently,
 * wait is always 1, so we use the kvm_xcall() routine which
 * calls xc_sync.  Later, if needed, the implementation can be
 * changed to use xc_call or xc_call_nowait.
 */
#define	on_each_cpu(func, info, wait)	\
	/*CSTYLED*/			\
	({				\
		kvm_xcall(KVM_CPUALL, func, info);	\
	0;				\
	})

static void
hardware_disable_all_nolock(void)
{
	kvm_usage_count--;
	if (!kvm_usage_count)
		on_each_cpu(hardware_disable, NULL, 1);
}

static void
hardware_disable_all(void)
{
	mutex_enter(&kvm_lock);
	hardware_disable_all_nolock();
	mutex_exit(&kvm_lock);
}

static int
hardware_enable_all(void)
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

	return (r);
}

#if defined(CONFIG_MMU_NOTIFIER) && defined(KVM_ARCH_WANT_MMU_NOTIFIER)
static inline struct kvm *
mmu_notifier_to_kvm(struct mmu_notifier *mn)
{
	return (container_of(mn, struct kvm, mmu_notifier));
}

extern pfn_t hat_getpfnum(struct hat *hat, caddr_t);

static void
kvm_mmu_notifier_invalidate_page(struct mmu_notifier *mn,
    struct mm_struct *mm, unsigned long address)
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
	 * The sequence increase only need to be seen at mutex_exit
	 * time, and not at mutex_enter time.
	 *
	 * Increasing the sequence after the mutex_exit would be
	 * unsafe because the kvm page fault could then establish the
	 * pte after kvm_unmap_hva returned, without noticing the page
	 * is going to be freed.
	 */
	idx = srcu_read_lock(&kvm->srcu);
	mutex_enter(&kvm->mmu_lock);
	kvm->mmu_notifier_seq++;
	need_tlb_flush = kvm_unmap_hva(kvm, address);
	mutex_exit(&kvm->mmu_lock);
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
	mutex_enter(&kvm->mmu_lock);
	kvm->mmu_notifier_seq++;
	kvm_set_spte_hva(kvm, address, pte);
	mutex_exit(&kvm->mmu_lock);
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
	mutex_enter(&kvm->mmu_lock);
	/*
	 * The count increase must become visible at unlock time as no
	 * spte can be established without taking the mmu_lock and
	 * count is also read inside the mmu_lock critical section.
	 */
	kvm->mmu_notifier_count++;
	for (; start < end; start += PAGESIZE)
		need_tlb_flush |= kvm_unmap_hva(kvm, start);
	mutex_exit(&kvm->mmu_lock);
	srcu_read_unlock(&kvm->srcu, idx);

	/* we've to flush the tlb before the pages can be freed */
	if (need_tlb_flush)
		kvm_flush_remote_tlbs(kvm);
}

static void
kvm_mmu_notifier_invalidate_range_end(struct mmu_notifier *mn,
    struct mm_struct *mm, unsigned long start, unsigned long end)
{
	struct kvm *kvm = mmu_notifier_to_kvm(mn);

	mutex_enter(&kvm->mmu_lock);
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
	mutex_exit(&kvm->mmu_lock);

	assert(kvm->mmu_notifier_count >= 0);
}

static int
kvm_mmu_notifier_clear_flush_young(struct mmu_notifier *mn,
    struct mm_struct *mm, unsigned long address)
{
	struct kvm *kvm = mmu_notifier_to_kvm(mn);
	int young, idx;

	idx = srcu_read_lock(&kvm->srcu);
	mutex_enter(&kvm->mmu_lock);
	young = kvm_age_hva(kvm, address);
	mutex_exit(&kvm->mmu_lock);
	srcu_read_unlock(&kvm->srcu, idx);

	if (young)
		kvm_flush_remote_tlbs(kvm);

	return (young);
}

static void
kvm_mmu_notifier_release(struct mmu_notifier *mn, struct mm_struct *mm)
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

static int
kvm_init_mmu_notifier(struct kvm *kvm)
{
	kvm->mmu_notifier.ops = &kvm_mmu_notifier_ops;
	return (mmu_notifier_register(&kvm->mmu_notifier, current->mm));
}
#else  /* !(CONFIG_MMU_NOTIFIER && KVM_ARCH_WANT_MMU_NOTIFIER) */

static int kvm_init_mmu_notifier(struct kvm *kvm)
{
	return (0);
}

static void
kvm_fini_mmu_notifier(struct kvm *kvm)
{
}

#endif /* CONFIG_MMU_NOTIFIER && KVM_ARCH_WANT_MMU_NOTIFIER */


void
kvm_arch_flush_shadow(struct kvm *kvm)
{
	kvm_mmu_zap_all(kvm);
#ifdef XXX
	kvm_reload_remote_mmus(kvm);
#else
	XXX_KVM_PROBE;
#endif
}

static struct kvm *
kvm_create_vm(void)
{
	int rval = 0;
	int i;
	struct kvm *kvmp = kvm_arch_create_vm();

	if (kvmp == NULL)
		return (NULL);

#ifdef CONFIG_HAVE_KVM_IRQCHIP
	list_create(&kvmp->mask_notifier_list,
		    sizeof (struct kvm_irq_mask_notifier),
		    offsetof(struct kvm_irq_mask_notifier, link));
	list_create(&kvmp->irq_ack_notifier_list,
		    sizeof (struct kvm_irq_ack_notifier),
		    offsetof(struct kvm_irq_ack_notifier, link));
#endif

	kvmp->memslots = kmem_zalloc(sizeof (struct kvm_memslots), KM_SLEEP);

	rw_init(&kvmp->kvm_rwlock, NULL, RW_DRIVER, NULL);

	for (i = 0; i < KVM_NR_BUSES; i++) {
		kvmp->buses[i] =
		    kmem_zalloc(sizeof (struct kvm_io_bus), KM_SLEEP);
	}

	rval = kvm_init_mmu_notifier(kvmp);

	if (rval != DDI_SUCCESS) {
		rw_destroy(&kvmp->kvm_rwlock);
		kvm_arch_destroy_vm(kvmp);
		return (NULL);
	}

	/*
	 * XXX note that the as struct does not contain  a refcnt, may
	 * have to go lower
	 */
	kvmp->mm = curproc->p_as;
	mutex_init(&kvmp->mmu_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&kvmp->requests_lock, NULL, MUTEX_DRIVER, NULL);
#ifdef XXX
	kvm_eventfd_init(kvmp);
#else
	XXX_KVM_PROBE;
#endif

	mutex_init(&kvmp->lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&kvmp->irq_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&kvmp->slots_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&kvmp->kvm_avllock, NULL, MUTEX_DRIVER, NULL);
	avl_create(&kvmp->kvm_avlmp, kvm_avlmmucmp, sizeof (kvm_mmu_page_t),
	    offsetof(kvm_mmu_page_t, kmp_avlnode));

	mutex_enter(&kvm_lock);
	kvmp->kvmid = kvmid++;
	kvmp->users_count = 1;
	list_insert_tail(&vm_list, kvmp);
	mutex_exit(&kvm_lock);

	if ((kvmp->kvm_kstat = kstat_create("kvm", kvmp->kvmid, "vm",
	    "misc", KSTAT_TYPE_NAMED, sizeof (kvm_stats_t) /
	    sizeof (kstat_named_t), KSTAT_FLAG_VIRTUAL)) == NULL) {
		kvm_destroy_vm(kvmp);
		return (NULL);
	}

	kvmp->kvm_kstat->ks_data = &kvmp->kvm_stats;

	KVM_KSTAT_INIT(kvmp, kvmks_pid, "pid");
	kvmp->kvm_stats.kvmks_pid.value.ui64 = kvmp->kvm_pid = curproc->p_pid;

	KVM_KSTAT_INIT(kvmp, kvmks_mmu_pte_write, "mmu-pte-write");
	KVM_KSTAT_INIT(kvmp, kvmks_mmu_pte_updated, "mmu-pte-updated");
	KVM_KSTAT_INIT(kvmp, kvmks_mmu_pte_zapped, "mmu-pte-zapped");
	KVM_KSTAT_INIT(kvmp, kvmks_mmu_flooded, "mmu-flooded");
	KVM_KSTAT_INIT(kvmp, kvmks_mmu_cache_miss, "mmu-cache-miss");
	KVM_KSTAT_INIT(kvmp, kvmks_mmu_recycled, "mmu-recycled");
	KVM_KSTAT_INIT(kvmp, kvmks_remote_tlb_flush, "remote-tlb-flush");
	KVM_KSTAT_INIT(kvmp, kvmks_lpages, "lpages");

	kstat_install(kvmp->kvm_kstat);

#ifdef KVM_COALESCED_MMIO_PAGE_OFFSET
	kvm_coalesced_mmio_init(kvmp);
#endif

	return (kvmp);
}

static void
kvm_destroy_vm(struct kvm *kvmp)
{
	int ii;
	void *cookie;

	if (kvmp == NULL)
		return;

	if (kvmp->kvm_kstat != NULL)
		kstat_delete(kvmp->kvm_kstat);

	kvm_arch_destroy_vm_comps(kvmp);

#ifdef KVM_COALESCED_MMIO_PAGE_OFFSET
	kvm_coalesced_mmio_free(kvmp);
#endif

	list_remove(&vm_list, kvmp);
	/*
	 * XXX: The fact that we're cleaning these up here means that we aren't
	 * properly cleaning them up somewhere else.
	 */
	cookie = NULL;
	while (avl_destroy_nodes(&kvmp->kvm_avlmp, &cookie) != NULL)
		continue;
	avl_destroy(&kvmp->kvm_avlmp);
	mutex_destroy(&kvmp->kvm_avllock);
	mutex_destroy(&kvmp->slots_lock);
	mutex_destroy(&kvmp->irq_lock);
	mutex_destroy(&kvmp->lock);
	mutex_destroy(&kvmp->requests_lock);
	mutex_destroy(&kvmp->mmu_lock);
	kvmp->mm = NULL;
	kvm_fini_mmu_notifier(kvmp);

	for (ii = 0; ii < KVM_NR_BUSES; ii++)
		kmem_free(kvmp->buses[ii], sizeof (struct kvm_io_bus));

	rw_destroy(&kvmp->kvm_rwlock);
#ifdef CONFIG_HAVE_KVM_IRQCHIP
	/*
	 * These lists are contained by the pic. However, the pic isn't
	 */
	list_destroy(&kvmp->irq_ack_notifier_list);
	list_destroy(&kvmp->mask_notifier_list);
#endif
	kvm_arch_destroy_vm(kvmp);
}

static int
kvm_dev_ioctl_create_vm(kvm_devstate_t *ksp, intptr_t arg, int *rv)
{
	if (ksp->kds_kvmp != NULL)
		return (EINVAL);

	ksp->kds_kvmp = kvm_create_vm();

	if (ksp->kds_kvmp == NULL) {
		cmn_err(CE_WARN, "Could not create new vm\n");
		return (EIO);
	}
	*rv = ksp->kds_kvmp->kvmid;
	return (DDI_SUCCESS);
}

extern int kvm_dev_ioctl_check_extension(long ext, int *rv);

static long
kvm_dev_ioctl_check_extension_generic(long arg, int *rv)
{
	switch (arg) {
	case KVM_CAP_USER_MEMORY:
	case KVM_CAP_DESTROY_MEMORY_REGION_WORKS:
	case KVM_CAP_JOIN_MEMORY_REGIONS_WORKS:
#ifdef CONFIG_KVM_APIC_ARCHITECTURE
	case KVM_CAP_SET_BOOT_CPU_ID:
#endif
	case KVM_CAP_INTERNAL_ERROR_DATA:
		*rv = 1;
		return (DDI_SUCCESS);
#ifdef CONFIG_HAVE_KVM_IRQCHIP
	case KVM_CAP_IRQ_ROUTING:
		*rv = KVM_MAX_IRQ_ROUTES;
		return (DDI_SUCCESS);
#endif
	default:
		break;
	}
	return (kvm_dev_ioctl_check_extension(arg, rv));
}


void
kvm_arch_commit_memory_region(struct kvm *kvm,
    struct kvm_userspace_memory_region *mem, struct kvm_memory_slot old,
    int user_alloc)
{

	int npages = mem->memory_size >> PAGESHIFT;

	if (!user_alloc && !old.user_alloc && old.rmap && !npages) {
		int ret = 0;

#ifdef XXX
		down_write(&current->mm->mmap_sem);
		ret = munmap(old.userspace_addr,
				old.npages * PAGESIZE);
		up_write(&current->mm->mmap_sem);
#else
		XXX_KVM_PROBE;
		/* see comment in kvm_arch_prepare_memory_region */
		/*
		 * XXX this needs to be here, but I'm getting kernel heap
		 * corruption panics with someone writing to a buffer after it
		 * is freed
		 */
		kmem_free((caddr_t)old.userspace_addr, old.npages * PAGESIZE);
#endif
		if (ret < 0) {
			cmn_err(CE_WARN, "kvm_vm_ioctl_set_memory_region: "
			    "failed to munmap memory\n");
		}
	}

	mutex_enter(&kvm->mmu_lock);
	if (!kvm->arch.n_requested_mmu_pages) {
		unsigned int nr_mmu_pages = kvm_mmu_calculate_mmu_pages(kvm);
		kvm_mmu_change_mmu_pages(kvm, nr_mmu_pages);
	}

	kvm_mmu_slot_remove_write_access(kvm, mem->slot);
	mutex_exit(&kvm->mmu_lock);
}

/*
 * Free any memory in @free but not in @dont.
 */
void
kvm_free_physmem_slot(struct kvm_memory_slot *free,
    struct kvm_memory_slot *dont)
{
	int i;
#ifdef XXX  /* currently, this routine does nothing (memory leak, at best) */

	if (!dont || free->rmap != dont->rmap)
		vfree(free->rmap);

	if (!dont || free->dirty_bitmap != dont->dirty_bitmap)
		vfree(free->dirty_bitmap);


	for (i = 0; i < KVM_NR_PAGE_SIZES - 1; ++i) {
		if (!dont || free->lpage_info[i] != dont->lpage_info[i]) {
			vfree(free->lpage_info[i]);
			free->lpage_info[i] = NULL;
		}
	}

	free->npages = 0;
	free->dirty_bitmap = NULL;
	free->rmap = NULL;
#else
	XXX_KVM_PROBE;
#endif
}

extern int
kvm_arch_prepare_memory_region(struct kvm *kvm,
    struct kvm_memory_slot *memslot, struct kvm_memory_slot old,
    struct kvm_userspace_memory_region *mem, int user_alloc);

/*
 * Allocate some memory and give it an address in the guest physical address
 * space.
 *
 * Discontiguous memory is allowed, mostly for framebuffers.
 *
 * Must be called holding mmap_sem for write.
 */
int
__kvm_set_memory_region(struct kvm *kvmp,
    struct kvm_userspace_memory_region *mem, int user_alloc)
{
	int r, flush_shadow = 0;
	gfn_t base_gfn;
	unsigned long npages;
	unsigned long i;
	struct kvm_memory_slot *memslot;
	struct kvm_memory_slot old, new;
	struct kvm_memslots *slots, *old_memslots;

	r = EINVAL;
	/* General sanity checks */
	if (mem->memory_size & (PAGESIZE - 1))
		goto out;
	if (mem->guest_phys_addr & (PAGESIZE - 1))
		goto out;
	if (user_alloc && (mem->userspace_addr & (PAGESIZE - 1)))
		goto out;
	if (mem->slot >= KVM_MEMORY_SLOTS + KVM_PRIVATE_MEM_SLOTS)
		goto out;
	if (mem->guest_phys_addr + mem->memory_size < mem->guest_phys_addr)
		goto out;

	memslot = &kvmp->memslots->memslots[mem->slot];
	base_gfn = mem->guest_phys_addr >> PAGESHIFT;
	npages = mem->memory_size >> PAGESHIFT;

	if (!npages)
		mem->flags &= ~KVM_MEM_LOG_DIRTY_PAGES;

	new = old = *memslot;

	new.base_gfn = base_gfn;
	new.npages = npages;
	new.flags = mem->flags;

	/* Disallow changing a memory slot's size. */
	r = EINVAL;
	if (npages && old.npages && npages != old.npages)
		goto out_free;

	/* Check for overlaps */
	r = EEXIST;
	for (i = 0; i < KVM_MEMORY_SLOTS; ++i) {
		struct kvm_memory_slot *s = &kvmp->memslots->memslots[i];

		if (s == memslot || !s->npages)
			continue;
		if (!((base_gfn + npages <= s->base_gfn) ||
		    (base_gfn >= s->base_gfn + s->npages)))
			goto out_free;
	}

	/* Free page dirty bitmap if unneeded */
	if (!(new.flags & KVM_MEM_LOG_DIRTY_PAGES))
		new.dirty_bitmap = NULL;

	r = ENOMEM;

	/* Allocate if a slot is being created */
	if (npages && !new.rmap) {
		new.rmap =
		    kmem_zalloc(npages * sizeof (struct page *), KM_SLEEP);

		new.user_alloc = user_alloc;
		new.userspace_addr = mem->userspace_addr;
	}

	if (!npages)
		goto skip_lpage;

	for (i = 0; i < KVM_NR_PAGE_SIZES - 1; ++i) {
		unsigned long ugfn;
		unsigned long j;
		int lpages;
		int level = i + 2;

		/* Avoid unused variable warning if no large pages */
		(void) level;

		if (new.lpage_info[i])
			continue;

		lpages = 1 + (base_gfn + npages - 1) /
		    KVM_PAGES_PER_HPAGE(level);
		lpages -= base_gfn / KVM_PAGES_PER_HPAGE(level);

		new.lpage_info[i] =
		    kmem_zalloc(lpages * sizeof (*new.lpage_info[i]), KM_SLEEP);

		if (base_gfn % KVM_PAGES_PER_HPAGE(level))
			new.lpage_info[i][0].write_count = 1;
		if ((base_gfn+npages) % KVM_PAGES_PER_HPAGE(level))
			new.lpage_info[i][lpages - 1].write_count = 1;
		ugfn = new.userspace_addr >> PAGESHIFT;
		/*
		 * If the gfn and userspace address are not aligned wrt each
		 * other, or if explicitly asked to, disable large page
		 * support for this slot
		 */
		if ((base_gfn ^ ugfn) & (KVM_PAGES_PER_HPAGE(level) - 1) ||
		    !largepages_enabled)
			for (j = 0; j < lpages; ++j)
				new.lpage_info[i][j].write_count = 1;
	}

skip_lpage:

	/* Allocate page dirty bitmap if needed */
	if ((new.flags & KVM_MEM_LOG_DIRTY_PAGES) && !new.dirty_bitmap) {
		unsigned long dirty_bytes = kvm_dirty_bitmap_bytes(&new);

		new.dirty_bitmap = kmem_zalloc(dirty_bytes, KM_SLEEP);

		/* destroy any largepage mappings for dirty tracking */
		if (old.npages)
			flush_shadow = 1;
	}

	if (!npages) {
		r = ENOMEM;
		slots = kmem_zalloc(sizeof (kvm_memslots_t), KM_SLEEP);
		memcpy(slots, kvmp->memslots, sizeof (kvm_memslots_t));
		if (mem->slot >= slots->nmemslots)
			slots->nmemslots = mem->slot + 1;
		slots->memslots[mem->slot].flags |= KVM_MEMSLOT_INVALID;

		old_memslots = kvmp->memslots;
#ifdef XXX
		rcu_assign_pointer(kvmp->memslots, slots);
		synchronize_srcu_expedited(&kvm->srcu);
#else
		XXX_KVM_SYNC_PROBE;
		kvmp->memslots = slots;
#endif
		/*
		 * From this point no new shadow pages pointing to a deleted
		 * memslot will be created.
		 *
		 * validation of sp->gfn happens in:
		 * 	- gfn_to_hva (kvm_read_guest, gfn_to_pfn)
		 * 	- kvm_is_visible_gfn (mmu_check_roots)
		 */
		kvm_arch_flush_shadow(kvmp);

		/* XXX: how many bytes to free??? */
		kmem_free(old_memslots, sizeof (struct kvm_memslots));
	}

	r = kvm_arch_prepare_memory_region(kvmp, &new, old, mem, user_alloc);
	if (r)
		goto out_free;

#ifdef CONFIG_DMAR
	/* map the pages in iommu page table */
	if (npages) {
		r = kvm_iommu_map_pages(kvmp, &new);
		if (r)
			goto out_free;
	}
#endif

	r = ENOMEM;
	slots = kmem_zalloc(sizeof (kvm_memslots_t), KM_SLEEP);
	memcpy(slots, kvmp->memslots, sizeof (kvm_memslots_t));

	if (mem->slot >= slots->nmemslots)
		slots->nmemslots = mem->slot + 1;

	/* actual memory is freed via old in kvm_free_physmem_slot below */
	if (!npages) {
		new.rmap = NULL;
		new.dirty_bitmap = NULL;
		for (i = 0; i < KVM_NR_PAGE_SIZES - 1; ++i)
			new.lpage_info[i] = NULL;
	}

	slots->memslots[mem->slot] = new;
	old_memslots = kvmp->memslots;
#ifdef XXX
	rcu_assign_pointer(kvmp->memslots, slots);
	synchronize_srcu_expedited(&kvmp->srcu);
#else
	XXX_KVM_SYNC_PROBE;
	kvmp->memslots = slots;
#endif

	kvm_arch_commit_memory_region(kvmp, mem, old, user_alloc);

	kvm_free_physmem_slot(&old, &new);
	kmem_free(old_memslots, sizeof (struct kvm_memslots));

	if (flush_shadow)
		kvm_arch_flush_shadow(kvmp);

	return (DDI_SUCCESS);

out_free:
	kvm_free_physmem_slot(&new, &old);
out:
	return (r);
}

int
kvm_set_memory_region(kvm_t *kvm,
    kvm_userspace_memory_region_t *mem, int user_alloc)
{
	int r;

	mutex_enter(&kvm->slots_lock);
	r = __kvm_set_memory_region(kvm, mem, user_alloc);
	mutex_exit(&kvm->slots_lock);

	return (r);
}


static int
kvm_vm_ioctl_set_tss_addr(struct kvm *kvmp, caddr_t addr)
{
	/*
	 * XXX later, if adding other arch beside x86, need to do something
	 * else here
	 */
	return (kvm_x86_ops->set_tss_addr(kvmp, addr));
}

extern int kvm_vm_ioctl_create_vcpu(struct kvm *kvm, uint32_t id, int *rv);

static inline void native_cpuid(unsigned int *eax, unsigned int *ebx,
				unsigned int *ecx, unsigned int *edx)
{
	/* ecx is often an input as well as an output. */
	__asm__ volatile("cpuid"
	    : "=a" (*eax),
	    "=b" (*ebx),
	    "=c" (*ecx),
	    "=d" (*edx)
	    : "0" (*eax), "2" (*ecx));
}

#define	__cpuid			native_cpuid

/* Some CPUID calls want 'count' to be placed in ecx */
static inline void
cpuid_count(unsigned int op, int count, unsigned int *eax, unsigned int *ebx,
    unsigned int *ecx, unsigned int *edx)
{
	*eax = op;
	*ecx = count;
	__cpuid(eax, ebx, ecx, edx);
}

static void
do_cpuid_1_ent(kvm_cpuid_entry2_t *entry, uint32_t function, uint32_t index)
{
	entry->function = function;
	entry->index = index;
	cpuid_count(entry->function, entry->index,
		    &entry->eax, &entry->ebx, &entry->ecx, &entry->edx);
	entry->flags = 0;
}


static int
is_efer_nx(void)
{
	unsigned long long efer = 0;

	rdmsrl_safe(MSR_EFER, &efer);
	return (efer & EFER_NX);
}


#define	F(x) bit(X86_FEATURE_##x)

static void
do_cpuid_ent(struct kvm_cpuid_entry2 *entry, uint32_t function,
    uint32_t index, int *nent, int maxnent)
{
	unsigned int ddic;
	unsigned f_nx = is_efer_nx() ? F(NX) : 0;
#ifdef CONFIG_X86_64
	unsigned f_gbpages = (kvm_x86_ops->get_lpage_level() == PT_PDPE_LEVEL)
				? F(GBPAGES) : 0;
	unsigned f_lm = F(LM);
#else
	unsigned f_gbpages = 0;
	unsigned f_lm = 0;
#endif
	unsigned f_rdtscp = kvm_x86_ops->rdtscp_supported() ? F(RDTSCP) : 0;

	/* cpuid 1.edx */
	const uint32_t kvm_supported_word0_x86_features =
		F(FPU) | F(VME) | F(DE) | F(PSE) |
		F(TSC) | F(MSR) | F(PAE) | F(MCE) |
		F(CX8) | F(APIC) | 0 /* Reserved */ | F(SEP) |
		F(MTRR) | F(PGE) | F(MCA) | F(CMOV) |
		F(PAT) | F(PSE36) | 0 /* PSN */ | F(CLFLSH) |
		0 /* Reserved, DS, ACPI */ | F(MMX) |
		F(FXSR) | F(XMM) | F(XMM2) | F(SELFSNOOP) |
		0 /* HTT, TM, Reserved, PBE */;
	/* cpuid 0x80000001.edx */
	const uint32_t kvm_supported_word1_x86_features =
		F(FPU) | F(VME) | F(DE) | F(PSE) |
		F(TSC) | F(MSR) | F(PAE) | F(MCE) |
		F(CX8) | F(APIC) | 0 /* Reserved */ | F(SYSCALL) |
		F(MTRR) | F(PGE) | F(MCA) | F(CMOV) |
		F(PAT) | F(PSE36) | 0 /* Reserved */ |
		f_nx | 0 /* Reserved */ | F(MMXEXT) | F(MMX) |
		F(FXSR) | F(FXSR_OPT) | f_gbpages | f_rdtscp |
		0 /* Reserved */ | f_lm | F(3DNOWEXT) | F(3DNOW);
	/* cpuid 1.ecx */
	const uint32_t kvm_supported_word4_x86_features =
		F(XMM3) | 0 /* Reserved, DTES64, MONITOR */ |
		0 /* DS-CPL, VMX, SMX, EST */ |
		0 /* TM2 */ | F(SSSE3) | 0 /* CNXT-ID */ | 0 /* Reserved */ |
		0 /* Reserved */ | F(CX16) | 0 /* xTPR Update, PDCM */ |
		0 /* Reserved, DCA */ | F(XMM4_1) |
		F(XMM4_2) | F(X2APIC) | F(MOVBE) | F(POPCNT) |
		0 /* Reserved, XSAVE, OSXSAVE */;
	/* cpuid 0x80000001.ecx */
	const uint32_t kvm_supported_word6_x86_features =
		F(LAHF_LM) | F(CMP_LEGACY) | F(SVM) | 0 /* ExtApicSpace */ |
		F(CR8_LEGACY) | F(ABM) | F(SSE4A) | F(MISALIGNSSE) |
		F(3DNOWPREFETCH) | 0 /* OSVW */ | 0 /* IBS */ | F(SSE5) |
		0 /* SKINIT */ | 0 /* WDT */;

	/* all calls to cpuid_count() should be made on the same cpu */
	/* XXX - right now, system panics at ddi_exit_critical() */
	/* XXX - to run everything on same cpu, bind qemu at startup */

	kpreempt_disable();

	do_cpuid_1_ent(entry, function, index);
	++*nent;

	switch (function) {
	case 0:
		entry->eax = min(entry->eax, (uint32_t)0xb);
		break;
	case 1:
		entry->edx &= kvm_supported_word0_x86_features;
		entry->ecx &= kvm_supported_word4_x86_features;
		/*
		 * we support x2apic emulation even if host does not support
		 * it since we emulate x2apic in software
		 */
		entry->ecx |= F(X2APIC);
		break;
	/*
	 * function 2 entries are STATEFUL. That is, repeated cpuid commands
	 * may return different values. This forces us to get_cpu() before
	 * issuing the first command, and also to emulate this annoying behavior
	 * in kvm_emulate_cpuid() using KVM_CPUID_FLAG_STATE_READ_NEXT
	 */
	case 2: {
		int t, times = entry->eax & 0xff;

		entry->flags |= KVM_CPUID_FLAG_STATEFUL_FUNC;
		entry->flags |= KVM_CPUID_FLAG_STATE_READ_NEXT;
		for (t = 1; t < times && *nent < maxnent; ++t) {
			do_cpuid_1_ent(&entry[t], function, 0);
			entry[t].flags |= KVM_CPUID_FLAG_STATEFUL_FUNC;
			++*nent;
		}
		break;
	}
	/* function 4 and 0xb have additional index. */
	case 4: {
		int i, cache_type;

		entry->flags |= KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
		/* read more entries until cache_type is zero */
		for (i = 1; *nent < maxnent; ++i) {
			cache_type = entry[i - 1].eax & 0x1f;
			if (!cache_type)
				break;
			do_cpuid_1_ent(&entry[i], function, i);
			entry[i].flags |= KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
			++*nent;
		}
		break;
	}
	case 0xb: {
		int i, level_type;

		entry->flags |= KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
		/* read more entries until level_type is zero */
		for (i = 1; *nent < maxnent; ++i) {
			level_type = entry[i - 1].ecx & 0xff00;
			if (!level_type)
				break;
			do_cpuid_1_ent(&entry[i], function, i);
			entry[i].flags |= KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
			++*nent;
		}
		break;
	}
	case 0x80000000:
		entry->eax = min(entry->eax, 0x8000001a);
		break;
	case 0x80000001:
		entry->edx &= kvm_supported_word1_x86_features;
		entry->ecx &= kvm_supported_word6_x86_features;
		break;
	}
	/*
	 * XXX - see comment above for ddi_enter_critical()
	 *
	 * ddi_exit_critical(ddic);
	 */
	kpreempt_enable();
}

#undef F

static int
kvm_dev_ioctl_get_supported_cpuid(struct kvm_cpuid2 *cpuid,
    struct kvm_cpuid_entry2  *entries)
{
	struct kvm_cpuid_entry2 *cpuid_entries;
	int limit, nent = 0, r = E2BIG;
	uint32_t func;
	int allocsize = 0;

	if (cpuid->nent < 1)
		goto out;
	if (cpuid->nent > KVM_MAX_CPUID_ENTRIES)
		cpuid->nent = KVM_MAX_CPUID_ENTRIES;
	r = ENOMEM;
	allocsize = sizeof (struct kvm_cpuid_entry2) * cpuid->nent;
	cpuid_entries = kmem_zalloc(allocsize, KM_SLEEP);

	do_cpuid_ent(&cpuid_entries[0], 0, 0, &nent, cpuid->nent);
	limit = cpuid_entries[0].eax;
	for (func = 1; func <= limit && nent < cpuid->nent; ++func)
		do_cpuid_ent(&cpuid_entries[nent], func, 0, &nent, cpuid->nent);

	r = E2BIG;
	if (nent >= cpuid->nent)
		goto out_free;

	do_cpuid_ent(&cpuid_entries[nent], 0x80000000, 0, &nent, cpuid->nent);
	limit = cpuid_entries[nent - 1].eax;
	for (func = 0x80000001; func <= limit && nent < cpuid->nent; ++func)
		do_cpuid_ent(&cpuid_entries[nent], func, 0, &nent, cpuid->nent);
	r = E2BIG;
	if (nent >= cpuid->nent)
		goto out_free;

	r = EFAULT;
	if (copyout(cpuid_entries, entries,
	    nent * sizeof (kvm_cpuid_entry2_t)))
		goto out_free;

	cpuid->nent = nent;
	r = 0;

out_free:
	kmem_free(cpuid_entries, allocsize);
out:
	return (r);
}

static inline void
__vmwrite(unsigned long field, unsigned long value)
{
	uint8_t err = 0;

	/*CSTYLED*/
	__asm__ volatile ( ASM_VMX_VMWRITE_RAX_RDX "\n\t" "setna %0"
	    /* XXX: CF==1 or ZF==1 --> crash (ud2) */
	    /* "ja 1f ; ud2 ; 1:\n" */
	    : "=q"(err) : "a" (value), "d" (field)
	    : "cc", "memory");

	/* XXX the following should be ifdef debug... */
	if (err) {
#ifdef XXX
		vmcs_read32(VM_INSTRUCTION_ERROR);
		cmn_err(CE_WARN, "_vmwrite: error writing %lx to %lx: "
		    "error number = %d\n", value, field, err & 0xff);
#else
		XXX_KVM_PROBE;
#endif
	}
}

/*
 * Volatile isn't enough to prevent the compiler from reordering the
 * read/write functions for the control registers and messing everything up.
 * A memory clobber would solve the problem, but would prevent reordering of
 * all loads stores around it, which can hurt performance. Solution is to
 * use a variable and mimic reads and writes to it to enforce serialization
 */
static unsigned long __force_order;

unsigned long
native_read_cr0(void)
{
	unsigned long val;
	__asm__ volatile("mov %%cr0,%0\n\t" : "=r" (val), "=m" (__force_order));
	return (val);
}

#define	read_cr0()	(native_read_cr0())

unsigned long
native_read_cr4(void)
{
	unsigned long val;
	__asm__ volatile("mov %%cr4,%0\n\t" : "=r" (val), "=m" (__force_order));
	return (val);
}

#define	read_cr4()	(native_read_cr4())

unsigned long
native_read_cr3(void)
{
	unsigned long val;
	__asm__ volatile("mov %%cr3,%0\n\t" : "=r" (val), "=m" (__force_order));
	return (val);
}

#define	read_cr3()	(native_read_cr3())

inline ulong kvm_read_cr4(struct kvm_vcpu *vcpu);

void
kvm_migrate_timers(struct kvm_vcpu *vcpu)
{
	set_bit(KVM_REQ_MIGRATE_TIMER, &vcpu->requests);
}



static int
kvm_request_guest_time_update(struct kvm_vcpu *v)
{
	struct kvm_vcpu_arch *vcpu = &v->arch;

	if (!vcpu->time_page)
		return (0);

	set_bit(KVM_REQ_KVMCLOCK_UPDATE, &v->requests);

	return (1);
}

void
kvm_arch_vcpu_load(struct kvm_vcpu *vcpu, int cpu)
{
	kvm_x86_ops->vcpu_load(vcpu, cpu);
#ifdef XXX
	if (unlikely(per_cpu(cpu_tsc_khz, cpu) == 0)) {
		unsigned long khz = cpufreq_quick_get(cpu);
		if (!khz)
			khz = tsc_khz;
		per_cpu(cpu_tsc_khz, cpu) = khz;
	}
#else
	XXX_KVM_PROBE;
#endif
	kvm_request_guest_time_update(vcpu);
}

void
kvm_put_guest_fpu(struct kvm_vcpu *vcpu)
{
	if (!vcpu->guest_fpu_loaded)
		return;

	vcpu->guest_fpu_loaded = 0;
	kvm_fx_save(&vcpu->arch.guest_fx_image);
	kvm_fx_restore(&vcpu->arch.host_fx_image);
	KVM_VCPU_KSTAT_INC(vcpu, kvmvs_fpu_reload);
	set_bit(KVM_REQ_DEACTIVATE_FPU, &vcpu->requests);
	KVM_TRACE1(fpu, int, 0);
}

/* straight from xen code... */
void
ldt_load(void)
{
	*((system_desc_t *)&CPU->cpu_gdt[GDT_LDT]) = curproc->p_ldt_desc;
	wr_ldtr(ULDT_SEL);
}


inline int
is_pae(struct kvm_vcpu *vcpu)
{
	return (kvm_read_cr4_bits(vcpu, X86_CR4_PAE));
}



void
kvm_arch_vcpu_put(struct kvm_vcpu *vcpu)
{
	kvm_put_guest_fpu(vcpu);

	kvm_x86_ops->vcpu_put(vcpu);
}

void
kvm_user_return_notifier_register(struct kvm_vcpu *vcpu,
    struct kvm_user_return_notifier *urn)
{
	vcpu->urn = urn;
}

void
kvm_user_return_notifier_unregister(struct kvm_vcpu *vcpu,
    struct kvm_user_return_notifier *urn)
{
	vcpu->urn = NULL;
}

void
kvm_fire_urn(struct kvm_vcpu *vcpu)
{
	if (vcpu->urn)
		vcpu->urn->on_user_return(vcpu, vcpu->urn);
}

/*
 * Called when we've been asked to save our context. i.e. we're being swapped
 * out.
 */
void
kvm_ctx_save(void *arg)
{
	struct kvm_vcpu *vcpu = arg;
	kvm_arch_vcpu_put(vcpu);
	kvm_fire_urn(vcpu);
}

/*
 * Called when we're being asked to restore our context. i.e. we're returning
 * from being swapped out.
 */
void
kvm_ctx_restore(void *arg)
{
	int cpu;

	cpu = CPU->cpu_seqid;
	struct kvm_vcpu *vcpu = arg;
	kvm_arch_vcpu_load(vcpu, cpu);
}

/*
 * Switches to specified vcpu, until a matching vcpu_put()
 */
void
vcpu_load(struct kvm_vcpu *vcpu)
{
	int cpu;

	mutex_enter(&vcpu->mutex);
	kpreempt_disable();
	cpu = CPU->cpu_seqid;
	installctx(curthread, vcpu, kvm_ctx_save, kvm_ctx_restore, NULL,
	    NULL, NULL, NULL);
	kvm_arch_vcpu_load(vcpu, cpu);
	kpreempt_enable();
}

void
vcpu_put(struct kvm_vcpu *vcpu)
{
	kpreempt_disable();
	kvm_arch_vcpu_put(vcpu);
	kvm_fire_urn(vcpu);
	removectx(curthread, vcpu, kvm_ctx_save, kvm_ctx_restore, NULL,
	    NULL, NULL, NULL);
	kpreempt_enable();
	mutex_exit(&vcpu->mutex);
}

/*
 * find an entry with matching function, matching index (if needed), and that
 * should be read next (if it's stateful)
 */
static int
is_matching_cpuid_entry(struct kvm_cpuid_entry2 *e,
    uint32_t function, uint32_t index)
{
	if (e->function != function)
		return (0);
	if ((e->flags & KVM_CPUID_FLAG_SIGNIFCANT_INDEX) && e->index != index)
		return (0);
	if ((e->flags & KVM_CPUID_FLAG_STATEFUL_FUNC) &&
	    !(e->flags & KVM_CPUID_FLAG_STATE_READ_NEXT))
		return (0);
	return (1);
}

struct kvm_pic *pic_irqchip(struct kvm *kvm);
extern int irqchip_in_kernel(struct kvm *kvm);

static int
move_to_next_stateful_cpuid_entry(struct kvm_vcpu *vcpu, int i)
{
	struct kvm_cpuid_entry2 *e = &vcpu->arch.cpuid_entries[i];
	int j, nent = vcpu->arch.cpuid_nent;

	e->flags &= ~KVM_CPUID_FLAG_STATE_READ_NEXT;
	/* when no next entry is found, the current entry[i] is reselected */
	for (j = i + 1; ; j = (j + 1) % nent) {
		struct kvm_cpuid_entry2 *ej = &vcpu->arch.cpuid_entries[j];
		if (ej->function == e->function) {
			ej->flags |= KVM_CPUID_FLAG_STATE_READ_NEXT;
			return (j);
		}
	}

	return (0); /* silence gcc, even though control never reaches here */
}

struct kvm_cpuid_entry2 *
kvm_find_cpuid_entry(struct kvm_vcpu *vcpu, uint32_t function, uint32_t index)
{
	int i;
	struct kvm_cpuid_entry2 *best = NULL;

	for (i = 0; i < vcpu->arch.cpuid_nent; ++i) {
		struct kvm_cpuid_entry2 *e;

		e = &vcpu->arch.cpuid_entries[i];
		if (is_matching_cpuid_entry(e, function, index)) {
			if (e->flags & KVM_CPUID_FLAG_STATEFUL_FUNC)
				move_to_next_stateful_cpuid_entry(vcpu, i);
			best = e;
			break;
		}
		/*
		 * Both basic or both extended?
		 */
		if (((e->function ^ function) & 0x80000000) == 0)
			if (!best || e->function > best->function)
				best = e;
	}

	return (best);
}

#define	APIC_LVT_NUM			6
/* 14 is the version for Xeon and Pentium 8.4.8 */
#define	APIC_VERSION			(0x14UL | ((APIC_LVT_NUM - 1) << 16))

static int
kvm_vcpu_ioctl_set_cpuid2(struct kvm_vcpu *vcpu, struct kvm_cpuid2 *cpuid)
{
	if (cpuid->nent > KVM_MAX_CPUID_ENTRIES)
		return (E2BIG);

	bcopy(cpuid->entries, vcpu->arch.cpuid_entries,
	    cpuid->nent * sizeof (struct kvm_cpuid_entry2));

	vcpu_load(vcpu);
	vcpu->arch.cpuid_nent = cpuid->nent;
	kvm_apic_set_version(vcpu);
	kvm_x86_ops->cpuid_update(vcpu);
	vcpu_put(vcpu);

	return (0);
}

static int
kvm_vcpu_ioctl_get_cpuid2(struct kvm_vcpu *vcpu, struct kvm_cpuid2 *cpuid)
{
	int r;
	struct kvm_cpuid_entry2 *entries = cpuid->entries;

	cpuid->nent = vcpu->arch.cpuid_nent;

	if (cpuid->nent < vcpu->arch.cpuid_nent)
		return (E2BIG);

	bcopy(&vcpu->arch.cpuid_entries, cpuid->entries,
	    vcpu->arch.cpuid_nent * sizeof (struct kvm_cpuid_entry2));

	return (0);
}



unsigned long
kvm_get_rflags(struct kvm_vcpu *vcpu)
{
	unsigned long rflags;

	rflags = kvm_x86_ops->get_rflags(vcpu);

	if (vcpu->guest_debug & KVM_GUESTDBG_SINGLESTEP)
		rflags &= ~(unsigned long)(X86_EFLAGS_TF | X86_EFLAGS_RF);

	return (rflags);
}

int
kvm_arch_vcpu_ioctl_get_regs(struct kvm_vcpu *vcpu, struct kvm_regs *regs)
{
	vcpu_load(vcpu);

	regs->rax = kvm_register_read(vcpu, VCPU_REGS_RAX);
	regs->rbx = kvm_register_read(vcpu, VCPU_REGS_RBX);
	regs->rcx = kvm_register_read(vcpu, VCPU_REGS_RCX);
	regs->rdx = kvm_register_read(vcpu, VCPU_REGS_RDX);
	regs->rsi = kvm_register_read(vcpu, VCPU_REGS_RSI);
	regs->rdi = kvm_register_read(vcpu, VCPU_REGS_RDI);
	regs->rsp = kvm_register_read(vcpu, VCPU_REGS_RSP);
	regs->rbp = kvm_register_read(vcpu, VCPU_REGS_RBP);
#ifdef CONFIG_X86_64
	regs->r8 = kvm_register_read(vcpu, VCPU_REGS_R8);
	regs->r9 = kvm_register_read(vcpu, VCPU_REGS_R9);
	regs->r10 = kvm_register_read(vcpu, VCPU_REGS_R10);
	regs->r11 = kvm_register_read(vcpu, VCPU_REGS_R11);
	regs->r12 = kvm_register_read(vcpu, VCPU_REGS_R12);
	regs->r13 = kvm_register_read(vcpu, VCPU_REGS_R13);
	regs->r14 = kvm_register_read(vcpu, VCPU_REGS_R14);
	regs->r15 = kvm_register_read(vcpu, VCPU_REGS_R15);
#endif

	regs->rip = kvm_rip_read(vcpu);
	regs->rflags = kvm_get_rflags(vcpu);

	vcpu_put(vcpu);

	return (0);
}





void
kvm_get_segment(struct kvm_vcpu *vcpu, struct kvm_segment *var, int seg)
{
	kvm_x86_ops->get_segment(vcpu, var, seg);
}

static uint16_t
get_segment_selector(struct kvm_vcpu *vcpu, int seg)
{
	struct kvm_segment kvm_seg;

	kvm_get_segment(vcpu, &kvm_seg, seg);

	return (kvm_seg.selector);
}

void
kvm_set_rflags(struct kvm_vcpu *vcpu, unsigned long rflags)
{
	if (vcpu->guest_debug & KVM_GUESTDBG_SINGLESTEP &&
	    vcpu->arch.singlestep_cs == get_segment_selector(vcpu,
	    VCPU_SREG_CS) && vcpu->arch.singlestep_rip == kvm_rip_read(vcpu)) {
		rflags |= X86_EFLAGS_TF | X86_EFLAGS_RF;
	}

	kvm_x86_ops->set_rflags(vcpu, rflags);
}

int
kvm_arch_vcpu_ioctl_set_regs(struct kvm_vcpu *vcpu, struct kvm_regs *regs)
{
	vcpu_load(vcpu);

	kvm_register_write(vcpu, VCPU_REGS_RAX, regs->rax);
	kvm_register_write(vcpu, VCPU_REGS_RBX, regs->rbx);
	kvm_register_write(vcpu, VCPU_REGS_RCX, regs->rcx);
	kvm_register_write(vcpu, VCPU_REGS_RDX, regs->rdx);
	kvm_register_write(vcpu, VCPU_REGS_RSI, regs->rsi);
	kvm_register_write(vcpu, VCPU_REGS_RDI, regs->rdi);
	kvm_register_write(vcpu, VCPU_REGS_RSP, regs->rsp);
	kvm_register_write(vcpu, VCPU_REGS_RBP, regs->rbp);
#ifdef CONFIG_X86_64
	kvm_register_write(vcpu, VCPU_REGS_R8, regs->r8);
	kvm_register_write(vcpu, VCPU_REGS_R9, regs->r9);
	kvm_register_write(vcpu, VCPU_REGS_R10, regs->r10);
	kvm_register_write(vcpu, VCPU_REGS_R11, regs->r11);
	kvm_register_write(vcpu, VCPU_REGS_R12, regs->r12);
	kvm_register_write(vcpu, VCPU_REGS_R13, regs->r13);
	kvm_register_write(vcpu, VCPU_REGS_R14, regs->r14);
	kvm_register_write(vcpu, VCPU_REGS_R15, regs->r15);
#endif

	kvm_rip_write(vcpu, regs->rip);
	kvm_set_rflags(vcpu, regs->rflags);

	vcpu->arch.exception.pending = 0;

	vcpu_put(vcpu);

	return (0);
}

int
kvm_arch_vcpu_ioctl_get_fpu(struct kvm_vcpu *vcpu, struct kvm_fpu *fpu)
{
	struct fxsave *fxsave = (struct fxsave *)&vcpu->arch.guest_fx_image;

	vcpu_load(vcpu);

	memcpy(fpu->fpr, fxsave->st_space, 128);
	fpu->fcw = fxsave->cwd;
	fpu->fsw = fxsave->swd;
	fpu->ftwx = fxsave->twd;
	fpu->last_opcode = fxsave->fop;
	fpu->last_ip = fxsave->rip;
	fpu->last_dp = fxsave->rdp;
	memcpy(fpu->xmm, fxsave->xmm_space, sizeof (fxsave->xmm_space));

	vcpu_put(vcpu);

	return (0);
}

int
kvm_arch_vcpu_ioctl_set_fpu(struct kvm_vcpu *vcpu, struct kvm_fpu *fpu)
{
	struct fxsave *fxsave = (struct fxsave *)&vcpu->arch.guest_fx_image;

	vcpu_load(vcpu);

	memcpy(fxsave->st_space, fpu->fpr, 128);
	fxsave->cwd = fpu->fcw;
	fxsave->swd = fpu->fsw;
	fxsave->twd = fpu->ftwx;
	fxsave->fop = fpu->last_opcode;
	fxsave->rip = fpu->last_ip;
	fxsave->rdp = fpu->last_dp;
	memcpy(fxsave->xmm_space, fpu->xmm, sizeof (fxsave->xmm_space));

	vcpu_put(vcpu);

	return (0);
}

unsigned long
kvm_get_cr8(struct kvm_vcpu *vcpu)
{
	if (irqchip_in_kernel(vcpu->kvm)) {
		return (kvm_lapic_get_cr8(vcpu));
	} else {
		return (vcpu->arch.cr8);
	}
}

int
kvm_arch_vcpu_ioctl_get_sregs(struct kvm_vcpu *vcpu, struct kvm_sregs *sregs)
{
	struct descriptor_table dt;

	vcpu_load(vcpu);

	kvm_get_segment(vcpu, &sregs->cs, VCPU_SREG_CS);
	kvm_get_segment(vcpu, &sregs->ds, VCPU_SREG_DS);
	kvm_get_segment(vcpu, &sregs->es, VCPU_SREG_ES);
	kvm_get_segment(vcpu, &sregs->fs, VCPU_SREG_FS);
	kvm_get_segment(vcpu, &sregs->gs, VCPU_SREG_GS);
	kvm_get_segment(vcpu, &sregs->ss, VCPU_SREG_SS);

	kvm_get_segment(vcpu, &sregs->tr, VCPU_SREG_TR);
	kvm_get_segment(vcpu, &sregs->ldt, VCPU_SREG_LDTR);

	kvm_x86_ops->get_idt(vcpu, &dt);
	sregs->idt.limit = dt.limit;
	sregs->idt.base = dt.base;
	kvm_x86_ops->get_gdt(vcpu, &dt);
	sregs->gdt.limit = dt.limit;
	sregs->gdt.base = dt.base;

	sregs->cr0 = kvm_read_cr0(vcpu);
	sregs->cr2 = vcpu->arch.cr2;
	sregs->cr3 = vcpu->arch.cr3;
	sregs->cr4 = kvm_read_cr4(vcpu);
	sregs->cr8 = kvm_get_cr8(vcpu);
	sregs->efer = vcpu->arch.efer;
	sregs->apic_base = kvm_get_apic_base(vcpu);

	memset(sregs->interrupt_bitmap, 0, sizeof (sregs->interrupt_bitmap));

	if (vcpu->arch.interrupt.pending && !vcpu->arch.interrupt.soft) {
		set_bit(vcpu->arch.interrupt.nr,
			(unsigned long *)sregs->interrupt_bitmap);
	}

	vcpu_put(vcpu);

	return (0);
}

static void kvm_set_segment(struct kvm_vcpu *vcpu,
			struct kvm_segment *var, int seg)
{
	kvm_x86_ops->set_segment(vcpu, var, seg);
}


inline void
kvm_queue_interrupt(struct kvm_vcpu *vcpu, uint8_t vector, int soft)
{
	vcpu->arch.interrupt.pending = 1;
	vcpu->arch.interrupt.soft = soft;
	vcpu->arch.interrupt.nr = vector;
}

inline unsigned long
bad_hva(void)
{
	return (PAGEOFFSET);
}

unsigned long
gfn_to_hva(struct kvm *kvm, gfn_t gfn)
{
	struct kvm_memory_slot *slot;

	gfn = unalias_gfn_instantiation(kvm, gfn);
	slot = gfn_to_memslot_unaliased(kvm, gfn);
	if (!slot || slot->flags & KVM_MEMSLOT_INVALID)
		return (bad_hva());

	return (slot->userspace_addr + (gfn - slot->base_gfn) * PAGESIZE);
}


int
kvm_is_error_hva(unsigned long addr)
{
	return (addr == bad_hva());
}

/* kernelbase is used by kvm_read_guest_page/kvm_write_guest_page */
extern uintptr_t kernelbase;

int
kvm_read_guest_page(struct kvm *kvm, gfn_t gfn, void *data, int offset, int len)
{
	int r = 0;
	unsigned long addr;

	addr = gfn_to_hva(kvm, gfn);

	if (kvm_is_error_hva(addr))
		return (-EFAULT);

	if (addr >= kernelbase) {
		bcopy((caddr_t)(addr + offset), data, len);
	} else {
		r = copyin((caddr_t)(addr + offset), data, len);
	}

	if (r)
		return (-EFAULT);

	return (0);
}

/*
 * Load the pae pdptrs.  Return true is they are all valid.
 */
int
load_pdptrs(struct kvm_vcpu *vcpu, unsigned long cr3)
{
	gfn_t pdpt_gfn = cr3 >> PAGESHIFT;
	unsigned offset = ((cr3 & (PAGESIZE-1)) >> 5) << 2;
	int i;
	int ret;
	uint64_t pdpte[ARRAY_SIZE(vcpu->arch.pdptrs)];

	ret = kvm_read_guest_page(vcpu->kvm, pdpt_gfn,
	    pdpte, offset * sizeof (uint64_t), sizeof (pdpte));

	if (ret < 0) {
		ret = 0;
		goto out;
	}

	for (i = 0; i < ARRAY_SIZE(pdpte); i++) {
		if (is_present_gpte(pdpte[i]) &&
		    (pdpte[i] & vcpu->arch.mmu.rsvd_bits_mask[0][2])) {
			ret = 0;
			goto out;
		}
	}
	ret = 1;

	memcpy(vcpu->arch.pdptrs, pdpte, sizeof (vcpu->arch.pdptrs));
	__set_bit(VCPU_EXREG_PDPTR, (unsigned long *)&vcpu->arch.regs_avail);
	__set_bit(VCPU_EXREG_PDPTR, (unsigned long *)&vcpu->arch.regs_dirty);
out:
	return (ret);
}

static void
update_cr8_intercept(struct kvm_vcpu *vcpu)
{
	int max_irr, tpr;

	if (!kvm_x86_ops->update_cr8_intercept)
		return;

	if (!vcpu->arch.apic)
		return;
	if (!vcpu->arch.apic->vapic_addr)
		max_irr = kvm_lapic_find_highest_irr(vcpu);
	else
		max_irr = -1;

	if (max_irr != -1)
		max_irr >>= 4;
	tpr = kvm_lapic_get_cr8(vcpu);

	kvm_x86_ops->update_cr8_intercept(vcpu, tpr, max_irr);
}




inline int
is_protmode(struct kvm_vcpu *vcpu)
{
	return (kvm_read_cr0_bits(vcpu, X86_CR0_PE));
}

int
kvm_vcpu_is_bsp(struct kvm_vcpu *vcpu)
{
	return (vcpu->kvm->bsp_vcpu_id == vcpu->vcpu_id);
}


unsigned long
find_next_bit(const unsigned long *addr,
    unsigned long size, unsigned long offset)
{
	const unsigned long *p = addr + (offset/64);
	unsigned long result = offset & ~(64-1);
	unsigned long tmp;

	if (offset >= size)
		return (size);

	size -= result;
	offset %= 64;

	if (offset) {
		tmp = *(p++);
		tmp &= (~0UL << offset);
		if (size < 64)
			goto found_first;
		if (tmp)
			goto found_middle;
		size -= 64;
		result += 64;
	}
	while (size & ~(64-1)) {
		if ((tmp = *(p++)))
			goto found_middle;
		result += 64;
		size -= 64;
	}

	if (!size)
		return (result);
	tmp = *p;

found_first:
	tmp &= (~0UL >> (64 - size));
	if (tmp == 0UL)		/* Are any bits set? */
		return (result + size);	/* Nope. */
found_middle:
	return (result + __ffs(tmp));
}

int
kvm_arch_vcpu_ioctl_set_sregs(struct kvm_vcpu *vcpu, struct kvm_sregs *sregs)
{
	int mmu_reset_needed = 0;
	int pending_vec, max_bits;
	struct descriptor_table dt;

	vcpu_load(vcpu);

	dt.limit = sregs->idt.limit;
	dt.base = sregs->idt.base;
	kvm_x86_ops->set_idt(vcpu, &dt);
	dt.limit = sregs->gdt.limit;
	dt.base = sregs->gdt.base;
	kvm_x86_ops->set_gdt(vcpu, &dt);

	vcpu->arch.cr2 = sregs->cr2;
	mmu_reset_needed |= vcpu->arch.cr3 != sregs->cr3;
	vcpu->arch.cr3 = sregs->cr3;

	kvm_set_cr8(vcpu, sregs->cr8);

	mmu_reset_needed |= vcpu->arch.efer != sregs->efer;
	kvm_x86_ops->set_efer(vcpu, sregs->efer);
	kvm_set_apic_base(vcpu, sregs->apic_base);

	mmu_reset_needed |= kvm_read_cr0(vcpu) != sregs->cr0;
	kvm_x86_ops->set_cr0(vcpu, sregs->cr0);
	vcpu->arch.cr0 = sregs->cr0;

	mmu_reset_needed |= kvm_read_cr4(vcpu) != sregs->cr4;
	kvm_x86_ops->set_cr4(vcpu, sregs->cr4);

	if (!is_long_mode(vcpu) && is_pae(vcpu)) {
		load_pdptrs(vcpu, vcpu->arch.cr3);
		mmu_reset_needed = 1;
	}

	if (mmu_reset_needed)
		kvm_mmu_reset_context(vcpu);

	max_bits = (sizeof (sregs->interrupt_bitmap)) << 3;
	pending_vec =
	    find_next_bit((const unsigned long *)sregs->interrupt_bitmap,
	    max_bits, 0);

	if (pending_vec < max_bits) {
		kvm_queue_interrupt(vcpu, pending_vec, 0);
		if (irqchip_in_kernel(vcpu->kvm))
			kvm_pic_clear_isr_ack(vcpu->kvm);
	}

	kvm_set_segment(vcpu, &sregs->cs, VCPU_SREG_CS);
	kvm_set_segment(vcpu, &sregs->ds, VCPU_SREG_DS);
	kvm_set_segment(vcpu, &sregs->es, VCPU_SREG_ES);
	kvm_set_segment(vcpu, &sregs->fs, VCPU_SREG_FS);
	kvm_set_segment(vcpu, &sregs->gs, VCPU_SREG_GS);
	kvm_set_segment(vcpu, &sregs->ss, VCPU_SREG_SS);

	kvm_set_segment(vcpu, &sregs->tr, VCPU_SREG_TR);
	kvm_set_segment(vcpu, &sregs->ldt, VCPU_SREG_LDTR);

	update_cr8_intercept(vcpu);

#ifdef CONFIG_KVM_APIC_ARCHITECTURE
	/* Older userspace won't unhalt the vcpu on reset. */
	if (kvm_vcpu_is_bsp(vcpu) && kvm_rip_read(vcpu) == 0xfff0 &&
	    sregs->cs.selector == 0xf000 && sregs->cs.base == 0xffff0000 &&
	    !is_protmode(vcpu))
		vcpu->arch.mp_state = KVM_MP_STATE_RUNNABLE;
#endif /* CONFIG_KVM_APIC_ARCHITECTURE */

	vcpu_put(vcpu);

	return (0);
}

static void
kvm_write_wall_clock(struct kvm *kvm, gpa_t wall_clock)
{
	static int version;
	struct pvclock_wall_clock wc;
	struct timespec boot;

	if (!wall_clock)
		return;

	version++;

	kvm_write_guest(kvm, wall_clock, &version, sizeof (version));

	/*
	 * The guest calculates current wall clock time by adding
	 * system time (updated by kvm_write_guest_time below) to the
	 * wall clock specified here.  guest system time equals host
	 * system time for us, thus we must fill in host boot time here.
	 */
#ifdef XXX
	getboottime(&boot);

	wc.sec = boot.tv_sec;
	wc.nsec = boot.tv_nsec;
	wc.version = version;

	kvm_write_guest(kvm, wall_clock, &wc, sizeof (wc));

	version++;
	kvm_write_guest(kvm, wall_clock, &version, sizeof (version));
#else
	XXX_KVM_PROBE;
#endif
}

static int
next_segment(unsigned long len, int offset)
{
	if (len > PAGESIZE - offset)
		return (PAGESIZE - offset);
	else
		return (len);
}

void
mark_page_dirty(struct kvm *kvm, gfn_t gfn)
{
	struct kvm_memory_slot *memslot;

	gfn = unalias_gfn(kvm, gfn);
	memslot = gfn_to_memslot_unaliased(kvm, gfn);

	if (memslot && memslot->dirty_bitmap) {
		unsigned long rel_gfn = gfn - memslot->base_gfn;
		unsigned long *p = memslot->dirty_bitmap + rel_gfn / 64;
		int offset = rel_gfn % 64;

		/* avoid RMW */
		if (!test_bit(offset, p))
			__set_bit(offset, p);
	}
}

int
kvm_write_guest_page(struct kvm *kvm,
    gfn_t gfn, const void *data, int offset, int len)
{
	int r = 0;
	unsigned long addr;

	addr = gfn_to_hva(kvm, gfn);

	if (kvm_is_error_hva(addr))
		return (-EFAULT);

	/* XXX - addr could be user or kernel */
	if (addr >= kernelbase) {
		bcopy(data, (caddr_t)(addr + offset), len);
	} else {
		r = copyout(data, (caddr_t)(addr + offset), len);
	}

	if (r)
		return (-EFAULT);

	mark_page_dirty(kvm, gfn);
	return (0);
}

int
kvm_write_guest(struct kvm *kvm, gpa_t gpa, const void *data, unsigned long len)
{
	gfn_t gfn = gpa >> PAGESHIFT;
	int seg;
	int offset = offset_in_page(gpa);
	int ret;
	uintptr_t dp = (uintptr_t)data;

	while ((seg = next_segment(len, offset)) != 0) {
		ret = kvm_write_guest_page(kvm, gfn, (void *)dp, offset, seg);
		if (ret < 0)
			return (ret);
		offset = 0;
		len -= seg;
		dp += seg;
		++gfn;
	}

	return (0);
}

static int
xen_hvm_config(struct kvm_vcpu *vcpu, uint64_t data)
{
	struct kvm *kvm = vcpu->kvm;
	int lm = is_long_mode(vcpu);
	uint8_t *blob_addr = lm ?
	    (uint8_t *)(long)kvm->arch.xen_hvm_config.blob_addr_64 :
	    (uint8_t *)(long)kvm->arch.xen_hvm_config.blob_addr_32;
	uint8_t blob_size = lm ?
	    kvm->arch.xen_hvm_config.blob_size_64 :
	    kvm->arch.xen_hvm_config.blob_size_32;
	uint32_t page_num = data & ~PAGEMASK;
	uint64_t page_addr = data & PAGEMASK;
	uint8_t *page;
	int r;

	r = E2BIG;
	if (page_num >= blob_size)
		goto out;
	r = ENOMEM;
	page = kmem_alloc(PAGESIZE, KM_SLEEP);
	r = EFAULT;
	if (copyin(blob_addr + (page_num * PAGESIZE), page, PAGESIZE))
		goto out_free;
	if (kvm_write_guest(kvm, page_addr, page, PAGESIZE))
		goto out_free;
	r = 0;
out_free:
	kmem_free(page, PAGESIZE);
out:
	return (r);
}

int ignore_msrs = 0;
extern int is_paging(struct kvm_vcpu *vcpu);

static void
set_efer(struct kvm_vcpu *vcpu, uint64_t efer)
{
	if (efer & efer_reserved_bits) {
		kvm_inject_gp(vcpu, 0);
		return;
	}

	if (is_paging(vcpu) &&
	    (vcpu->arch.efer & EFER_LME) != (efer & EFER_LME)) {
		kvm_inject_gp(vcpu, 0);
		return;
	}

	if (efer & EFER_FFXSR) {
		struct kvm_cpuid_entry2 *feat;

		feat = kvm_find_cpuid_entry(vcpu, 0x80000001, 0);
		if (!feat || !(feat->edx & bit(X86_FEATURE_FXSR_OPT))) {
			kvm_inject_gp(vcpu, 0);
			return;
		}
	}

	if (efer & EFER_SVME) {
		struct kvm_cpuid_entry2 *feat;

		feat = kvm_find_cpuid_entry(vcpu, 0x80000001, 0);
		if (!feat || !(feat->ecx & bit(X86_FEATURE_SVM))) {
			kvm_inject_gp(vcpu, 0);
			return;
		}
	}

	kvm_x86_ops->set_efer(vcpu, efer);

	efer &= ~EFER_LMA;
	efer |= vcpu->arch.efer & EFER_LMA;

	vcpu->arch.efer = efer;

	vcpu->arch.mmu.base_role.nxe = (efer & EFER_NX) && !tdp_enabled;
	kvm_mmu_reset_context(vcpu);
}

static int
msr_mtrr_valid(unsigned msr)
{
	switch (msr) {
	case 0x200 ... 0x200 + 2 * KVM_NR_VAR_MTRR - 1:
	case MSR_MTRRfix64K_00000:
	case MSR_MTRRfix16K_80000:
	case MSR_MTRRfix16K_A0000:
	case MSR_MTRRfix4K_C0000:
	case MSR_MTRRfix4K_C8000:
	case MSR_MTRRfix4K_D0000:
	case MSR_MTRRfix4K_D8000:
	case MSR_MTRRfix4K_E0000:
	case MSR_MTRRfix4K_E8000:
	case MSR_MTRRfix4K_F0000:
	case MSR_MTRRfix4K_F8000:
	case MSR_MTRRdefType:
	case MSR_IA32_CR_PAT:
		return (1);
	case 0x2f8:
		return (1);
	}

	return (0);
}


static int
valid_pat_type(unsigned t)
{
	return (t < 8 && (1 << t) & 0xf3); /* 0, 1, 4, 5, 6, 7 */
}

static int
valid_mtrr_type(unsigned t)
{
	return (t < 8 && (1 << t) & 0x73); /* 0, 1, 4, 5, 6 */
}

static int
mtrr_valid(struct kvm_vcpu *vcpu, uint32_t msr, uint64_t data)
{
	int i;

	if (!msr_mtrr_valid(msr))
		return (0);

	if (msr == MSR_IA32_CR_PAT) {
		for (i = 0; i < 8; i++)
			if (!valid_pat_type((data >> (i * 8)) & 0xff))
				return (0);
		return (1);
	} else if (msr == MSR_MTRRdefType) {
		if (data & ~0xcff)
			return (0);
		return (valid_mtrr_type(data & 0xff));
	} else if (msr >= MSR_MTRRfix64K_00000 && msr <= MSR_MTRRfix4K_F8000) {
		for (i = 0; i < 8; i++)
			if (!valid_mtrr_type((data >> (i * 8)) & 0xff))
				return (0);
		return (1);
	}

	/* variable MTRRs */
	return (valid_mtrr_type(data & 0xff));
}

static int
set_msr_mtrr(struct kvm_vcpu *vcpu, uint32_t msr, uint64_t data)
{
	struct mtrr_state_type *state = &vcpu->arch.mtrr_state;

	uint64_t *p = (uint64_t *)&state->fixed_ranges;

	if (!mtrr_valid(vcpu, msr, data))
		return (1);

	if (msr == MSR_MTRRdefType) {
		state->def_type = data;
		state->enabled = (data & 0xc00) >> 10;
	} else if (msr == MSR_MTRRfix64K_00000)
		p[0] = data;
	else if (msr == MSR_MTRRfix16K_80000 || msr == MSR_MTRRfix16K_A0000)
		p[1 + msr - MSR_MTRRfix16K_80000] = data;
	else if (msr >= MSR_MTRRfix4K_C0000 && msr <= MSR_MTRRfix4K_F8000)
		p[3 + msr - MSR_MTRRfix4K_C0000] = data;
	else if (msr == MSR_IA32_CR_PAT)
		vcpu->arch.pat = data;
	else {	/* Variable MTRRs */
		int idx, is_mtrr_mask;
		uint64_t *pt;

		idx = (msr - 0x200) / 2;
		is_mtrr_mask = msr - 0x200 - 2 * idx;

		if (!is_mtrr_mask) {
			pt = (uint64_t *)&state->var_ranges[idx].base_lo;
		} else {
			pt = (uint64_t *)&state->var_ranges[idx].mask_lo;
		}

		*pt = data;
	}

	kvm_mmu_reset_context(vcpu);

	return (0);
}

int
clear_user(void *addr, unsigned long size)
{
	caddr_t ka;
	int rval = 0;

	ka = kmem_zalloc(size, KM_SLEEP);
	rval = copyout(ka, addr, size);
	kmem_free(ka, size);

	return (rval);
}

static int
set_msr_hyperv(struct kvm_vcpu *vcpu, uint32_t msr, uint64_t data)
{
	switch (msr) {
	case HV_X64_MSR_APIC_ASSIST_PAGE: {
		unsigned long addr;

		if (!(data & HV_X64_MSR_APIC_ASSIST_PAGE_ENABLE)) {
			vcpu->arch.hv_vapic = data;
			break;
		}

		addr = gfn_to_hva(vcpu->kvm,
		    data >> HV_X64_MSR_APIC_ASSIST_PAGE_ADDRESS_SHIFT);

		if (kvm_is_error_hva(addr))
			return (1);

		if (clear_user((void *)addr, PAGESIZE))
			return (1);

		vcpu->arch.hv_vapic = data;
		break;
	}

	case HV_X64_MSR_EOI:
		return (kvm_hv_vapic_msr_write(vcpu, APIC_EOI, data));
	case HV_X64_MSR_ICR:
		return (kvm_hv_vapic_msr_write(vcpu, APIC_ICR, data));
	case HV_X64_MSR_TPR:
		return (kvm_hv_vapic_msr_write(vcpu, APIC_TASKPRI, data));

	default:
		cmn_err(CE_WARN, "HYPER-V unimplemented wrmsr: 0x%x "
		    "data 0x%lx\n", msr, data);
		return (1);
	}

	return (0);
}

static int
set_msr_hyperv_pw(struct kvm_vcpu *vcpu, uint32_t msr, uint64_t data)
{
	struct kvm *kvm = vcpu->kvm;

	switch (msr) {
	case HV_X64_MSR_GUEST_OS_ID:
		kvm->arch.hv_guest_os_id = data;
		/* setting guest os id to zero disables hypercall page */
		if (!kvm->arch.hv_guest_os_id)
			kvm->arch.hv_hypercall &= ~HV_X64_MSR_HYPERCALL_ENABLE;
		break;
	case HV_X64_MSR_HYPERCALL: {
		uint64_t gfn;
		unsigned long addr;
		uint8_t instructions[4];

		/* if guest os id is not set hypercall should remain disabled */
		if (!kvm->arch.hv_guest_os_id)
			break;
		if (!(data & HV_X64_MSR_HYPERCALL_ENABLE)) {
			kvm->arch.hv_hypercall = data;
			break;
		}
		gfn = data >> HV_X64_MSR_HYPERCALL_PAGE_ADDRESS_SHIFT;
		addr = gfn_to_hva(kvm, gfn);
		if (kvm_is_error_hva(addr))
			return (1);
		kvm_x86_ops->patch_hypercall(vcpu, instructions);
		((unsigned char *)instructions)[3] = 0xc3; /* ret */
		if (copyout(instructions, (caddr_t)addr, 4))
			return (1);
		kvm->arch.hv_hypercall = data;
		break;
	}
	default:
		cmn_err(CE_WARN, "HYPER-V unimplemented wrmsr: 0x%x "
		    "data 0x%lx\n", msr, data);
		return (1);
	}

	return (0);
}

static int
set_msr_mce(struct kvm_vcpu *vcpu, uint32_t msr, uint64_t data)
{
	uint64_t mcg_cap = vcpu->arch.mcg_cap;
	unsigned bank_num = mcg_cap & 0xff;

	switch (msr) {
	case MSR_IA32_MCG_STATUS:
		vcpu->arch.mcg_status = data;
		break;
	case MSR_IA32_MCG_CTL:
		if (!(mcg_cap & MCG_CTL_P))
			return (1);
		if (data != 0 && data != ~(uint64_t)0)
			return (-1);
		vcpu->arch.mcg_ctl = data;
		break;
	default:
		if (msr >= MSR_IA32_MC0_CTL &&
		    msr < MSR_IA32_MC0_CTL + 4 * bank_num) {
			uint32_t offset = msr - MSR_IA32_MC0_CTL;
			/*
			 * only 0 or all 1s can be written to IA32_MCi_CTL
			 * some Linux kernels though clear bit 10 in bank 4 to
			 * workaround a BIOS/GART TBL issue on AMD K8s, ignore
			 * this to avoid an uncatched #GP in the guest
			 */
			if ((offset & 0x3) == 0 &&
			    data != 0 && (data | (1 << 10)) != ~(uint64_t)0)
				return (-1);
			vcpu->arch.mce_banks[offset] = data;
			break;
		}
		return (1);
	}
	return (0);
}

static int
kvm_hv_msr_partition_wide(uint32_t msr)
{
	int r = 0;
	switch (msr) {
	case HV_X64_MSR_GUEST_OS_ID:
	case HV_X64_MSR_HYPERCALL:
		r = 1;
		break;
	}

	return (r);
}

inline page_t *
compound_head(page_t *page)
{
	/* XXX - linux links page_t together. */
	return (page);
}

inline void
get_page(page_t *page)
{
	page = compound_head(page);
}

extern pfn_t physmax;

#ifdef XXX_KVM_DECLARATION
#define	pfn_valid(pfn) ((pfn < physmax) && (pfn != PFN_INVALID))
#else
#define	pfn_valid(pfn) (pfn != PFN_INVALID)
#endif

inline int
kvm_is_mmio_pfn(pfn_t pfn)
{
	if (pfn_valid(pfn)) {
#ifdef XXX
		struct page *page = compound_head(pfn_to_page(pfn));
		return (PageReserved(page));
#else
		XXX_KVM_PROBE;
#endif
		return (0);
	} else
		return (1);
}

page_t *
gfn_to_page(struct kvm *kvm, gfn_t gfn)
{
	pfn_t pfn = gfn_to_pfn(kvm, gfn);

	if (!kvm_is_mmio_pfn(pfn))
		return (pfn_to_page(pfn));

	get_page(bad_page);
	return (bad_page);
}

void
kvm_release_page_dirty(page_t *page)
{
	kvm_release_pfn_dirty(page_to_pfn(page));
}

int
kvm_set_msr_common(struct kvm_vcpu *vcpu, uint32_t msr, uint64_t data)
{
	switch (msr) {
	case MSR_EFER:
		set_efer(vcpu, data);
		break;
	case MSR_K7_HWCR:
		data &= ~(uint64_t)0x40; /* ignore flush filter disable */
		if (data != 0) {
			cmn_err(CE_NOTE,
			    "unimplemented HWCR wrmsr: 0x%lx\n", data);
			return (1);
		}
		break;
	case MSR_FAM10H_MMIO_CONF_BASE:
		if (data != 0) {
			cmn_err(CE_NOTE, "unimplemented MMIO_CONF_BASE wrmsr: "
				"0x%lx\n", data);
			return (1);
		}
		break;
	case MSR_AMD64_NB_CFG:
		break;
	case MSR_IA32_DEBUGCTLMSR:
		if (!data) {
			/* We support the non-activated case already */
			break;
		} else if (data & ~(DEBUGCTLMSR_LBR | DEBUGCTLMSR_BTF)) {
			/*
			 * Values other than LBR and BTF are vendor-specific,
			 * thus reserved and should throw a #GP
			 */
			return (1);
		}
		cmn_err(CE_NOTE, "%s: MSR_IA32_DEBUGCTLMSR 0x%lx, nop\n",
			__func__, data);
		break;
	case MSR_IA32_UCODE_REV:
	case MSR_IA32_UCODE_WRITE:
	case MSR_VM_HSAVE_PA:
	case MSR_AMD64_PATCH_LOADER:
		break;
	case 0x200 ... 0x2ff:
		return (set_msr_mtrr(vcpu, msr, data));
	case MSR_IA32_APICBASE:
		kvm_set_apic_base(vcpu, data);
		break;
	case APIC_BASE_MSR ... APIC_BASE_MSR + 0x3ff:
		return (kvm_x2apic_msr_write(vcpu, msr, data));
	case MSR_IA32_MISC_ENABLE:
		vcpu->arch.ia32_misc_enable_msr = data;
		break;
	case MSR_KVM_WALL_CLOCK:
		vcpu->kvm->arch.wall_clock = data;
		kvm_write_wall_clock(vcpu->kvm, data);
		break;
	case MSR_KVM_SYSTEM_TIME: {
#ifdef XXX
		if (vcpu->arch.time_page) {
			kvm_release_page_dirty(vcpu->arch.time_page);
			vcpu->arch.time_page = NULL;
		}
#else
		XXX_KVM_PROBE;
#endif

		vcpu->arch.time = data;

		/* we verify if the enable bit is set... */
		if (!(data & 1))
			break;

		/* ...but clean it before doing the actual write */
		vcpu->arch.time_offset = data & ~(PAGEOFFSET | 1);
#ifdef XXX
		vcpu->arch.time_page =
				gfn_to_page(vcpu->kvm, data >> PAGESHIFT);

		if (is_error_page(vcpu->arch.time_page)) {
			kvm_release_page_clean(vcpu->arch.time_page);
			vcpu->arch.time_page = NULL;
		}

		kvm_request_guest_time_update(vcpu);
#else
		XXX_KVM_PROBE;
#endif
		break;
	}
	case MSR_IA32_MCG_CTL:
	case MSR_IA32_MCG_STATUS:
	case MSR_IA32_MC0_CTL ... MSR_IA32_MC0_CTL + 4 * KVM_MAX_MCE_BANKS - 1:
		return (set_msr_mce(vcpu, msr, data));

	/*
	 * Performance counters are not protected by a CPUID bit, so we should
	 * check all of them in the generic path for the sake of cross vendor
	 * migration. Writing a zero into the event select MSRs disables them,
	 * which we perfectly emulate ;-). Any other value should be at least
	 * reported, some guests depend on them.
	 */
	case MSR_P6_EVNTSEL0:
	case MSR_P6_EVNTSEL1:
	case MSR_K7_EVNTSEL0:
	case MSR_K7_EVNTSEL1:
	case MSR_K7_EVNTSEL2:
	case MSR_K7_EVNTSEL3:
		if (data != 0)
			cmn_err(CE_NOTE, "unimplemented perfctr wrmsr: "
				"0x%x data 0x%lx\n", msr, data);
		break;
	/*
	 * at least RHEL 4 unconditionally writes to the perfctr registers,
	 * so we ignore writes to make it happy.
	 */
	case MSR_P6_PERFCTR0:
	case MSR_P6_PERFCTR1:
	case MSR_K7_PERFCTR0:
	case MSR_K7_PERFCTR1:
	case MSR_K7_PERFCTR2:
	case MSR_K7_PERFCTR3:
		cmn_err(CE_NOTE, "unimplemented perfctr wrmsr: "
			"0x%x data 0x%lx\n", msr, data);
		break;
	case HV_X64_MSR_GUEST_OS_ID ... HV_X64_MSR_SINT15:
		if (kvm_hv_msr_partition_wide(msr)) {
			int r;
			mutex_enter(&vcpu->kvm->lock);
			r = set_msr_hyperv_pw(vcpu, msr, data);
			mutex_exit(&vcpu->kvm->lock);
			return (r);
		} else
			return (set_msr_hyperv(vcpu, msr, data));
		break;
	default:
		if (msr && (msr == vcpu->kvm->arch.xen_hvm_config.msr))
			return (xen_hvm_config(vcpu, data));
		if (!ignore_msrs) {
			cmn_err(CE_NOTE, "unhandled wrmsr: 0x%x data %lx\n",
				msr, data);
			return (1);
		} else {
			cmn_err(CE_NOTE, "ignored wrmsr: 0x%x data %lx\n",
				msr, data);
			break;
		}
	}

	return (0);
}



static int
get_msr_mtrr(struct kvm_vcpu *vcpu, uint32_t msr, uint64_t *pdata)
{
	struct mtrr_state_type *state = &vcpu->arch.mtrr_state;
	uint64_t *p = (uint64_t *)&state->fixed_ranges;

	if (!msr_mtrr_valid(msr))
		return (1);

	if (msr == MSR_MTRRdefType)
		*pdata = vcpu->arch.mtrr_state.def_type +
		    (vcpu->arch.mtrr_state.enabled << 10);
	else if (msr == MSR_MTRRfix64K_00000)
		*pdata = p[0];
	else if (msr == MSR_MTRRfix16K_80000 || msr == MSR_MTRRfix16K_A0000)
		*pdata = p[1 + msr - MSR_MTRRfix16K_80000];
	else if (msr >= MSR_MTRRfix4K_C0000 && msr <= MSR_MTRRfix4K_F8000)
		*pdata = p[3 + msr - MSR_MTRRfix4K_C0000];
	else if (msr == MSR_IA32_CR_PAT)
		*pdata = vcpu->arch.pat;
	else {	/* Variable MTRRs */
		int idx, is_mtrr_mask;
		uint64_t *pt;

		idx = (msr - 0x200) / 2;
		is_mtrr_mask = msr - 0x200 - 2 * idx;
		if (!is_mtrr_mask) {
			pt = (uint64_t *)&state->var_ranges[idx].base_lo;
		} else {
			pt = (uint64_t *)&state->var_ranges[idx].mask_lo;
		}

		*pdata = *pt;
	}

	return (0);
}


static int
get_msr_hyperv(struct kvm_vcpu *vcpu, uint32_t msr, uint64_t *pdata)
{
	uint64_t data = 0;

	switch (msr) {
	case HV_X64_MSR_VP_INDEX: {
		int r;
		struct kvm_vcpu *v;
		kvm_for_each_vcpu(r, v, vcpu->kvm)
			if (v == vcpu)
				data = r;
		break;
	}
	case HV_X64_MSR_EOI:
		return (kvm_hv_vapic_msr_read(vcpu, APIC_EOI, pdata));
	case HV_X64_MSR_ICR:
		return (kvm_hv_vapic_msr_read(vcpu, APIC_ICR, pdata));
	case HV_X64_MSR_TPR:
		return (kvm_hv_vapic_msr_read(vcpu, APIC_TASKPRI, pdata));
	default:
		cmn_err(CE_WARN, "Hyper-V unhandled rdmsr: 0x%x\n", msr);
		return (1);
	}

	*pdata = data;
	return (0);
}

static int
get_msr_hyperv_pw(struct kvm_vcpu *vcpu, uint32_t msr, uint64_t *pdata)
{
	uint64_t data = 0;
	struct kvm *kvm = vcpu->kvm;

	switch (msr) {
	case HV_X64_MSR_GUEST_OS_ID:
		data = kvm->arch.hv_guest_os_id;
		break;
	case HV_X64_MSR_HYPERCALL:
		data = kvm->arch.hv_hypercall;
		break;
	default:
		cmn_err(CE_WARN, "Hyper-V unhandled rdmsr: 0x%x\n", msr);
		return (1);
	}

	*pdata = data;

	return (0);
}

static int get_msr_mce(struct kvm_vcpu *vcpu, uint32_t msr, uint64_t *pdata)
{
	uint64_t data;
	uint64_t mcg_cap = vcpu->arch.mcg_cap;
	unsigned bank_num = mcg_cap & 0xff;

	switch (msr) {
	case MSR_IA32_P5_MC_ADDR:
	case MSR_IA32_P5_MC_TYPE:
		data = 0;
		break;
	case MSR_IA32_MCG_CAP:
		data = vcpu->arch.mcg_cap;
		break;
	case MSR_IA32_MCG_CTL:
		if (!(mcg_cap & MCG_CTL_P))
			return (1);
		data = vcpu->arch.mcg_ctl;
		break;
	case MSR_IA32_MCG_STATUS:
		data = vcpu->arch.mcg_status;
		break;
	default:
		if (msr >= MSR_IA32_MC0_CTL &&
		    msr < MSR_IA32_MC0_CTL + 4 * bank_num) {
			uint32_t offset = msr - MSR_IA32_MC0_CTL;
			data = vcpu->arch.mce_banks[offset];
			break;
		}
		return (1);
	}
	*pdata = data;
	return (0);
}

int
kvm_get_msr_common(struct kvm_vcpu *vcpu, uint32_t msr, uint64_t *pdata)
{
	uint64_t data;

	switch (msr) {
	case MSR_IA32_PLATFORM_ID:
	case MSR_IA32_UCODE_REV:
	case MSR_IA32_EBL_CR_POWERON:
	case MSR_IA32_DEBUGCTLMSR:
	case MSR_IA32_LASTBRANCHFROMIP:
	case MSR_IA32_LASTBRANCHTOIP:
	case MSR_IA32_LASTINTFROMIP:
	case MSR_IA32_LASTINTTOIP:
	case MSR_K8_SYSCFG:
	case MSR_K7_HWCR:
	case MSR_VM_HSAVE_PA:
	case MSR_P6_PERFCTR0:
	case MSR_P6_PERFCTR1:
	case MSR_P6_EVNTSEL0:
	case MSR_P6_EVNTSEL1:
	case MSR_K7_EVNTSEL0:
	case MSR_K7_PERFCTR0:
	case MSR_K8_INT_PENDING_MSG:
	case MSR_AMD64_NB_CFG:
	case MSR_FAM10H_MMIO_CONF_BASE:
		data = 0;
		break;
	case MSR_MTRRcap:
		data = 0x500 | KVM_NR_VAR_MTRR;
		break;
	case 0x200 ... 0x2ff:
		return (get_msr_mtrr(vcpu, msr, pdata));
	case 0xcd: /* fsb frequency */
		data = 3;
		break;
	case MSR_IA32_APICBASE:
		data = kvm_get_apic_base(vcpu);
		break;
	case APIC_BASE_MSR ... APIC_BASE_MSR + 0x3ff:
		return (kvm_x2apic_msr_read(vcpu, msr, pdata));
		break;
	case MSR_IA32_MISC_ENABLE:
		data = vcpu->arch.ia32_misc_enable_msr;
		break;
	case MSR_IA32_PERF_STATUS:
		/* TSC increment by tick */
		data = 1000ULL;
		/* CPU multiplier */
		data |= (((uint64_t)4ULL) << 40);
		break;
	case MSR_EFER:
		data = vcpu->arch.efer;
		break;
	case MSR_KVM_WALL_CLOCK:
		data = vcpu->kvm->arch.wall_clock;
		break;
	case MSR_KVM_SYSTEM_TIME:
		data = vcpu->arch.time;
		break;
	case MSR_IA32_P5_MC_ADDR:
	case MSR_IA32_P5_MC_TYPE:
	case MSR_IA32_MCG_CAP:
	case MSR_IA32_MCG_CTL:
	case MSR_IA32_MCG_STATUS:
	case MSR_IA32_MC0_CTL ... MSR_IA32_MC0_CTL + 4 * KVM_MAX_MCE_BANKS - 1:
		return (get_msr_mce(vcpu, msr, pdata));
	case HV_X64_MSR_GUEST_OS_ID ... HV_X64_MSR_SINT15:
		if (kvm_hv_msr_partition_wide(msr)) {
			int r;
			mutex_enter(&vcpu->kvm->lock);
			r = get_msr_hyperv_pw(vcpu, msr, pdata);
			mutex_exit(&vcpu->kvm->lock);
			return (r);
		} else
			return (get_msr_hyperv(vcpu, msr, pdata));
		break;
	default:
		if (!ignore_msrs) {
			cmn_err(CE_NOTE, "unhandled rdmsr: 0x%x\n", msr);
			return (1);
		} else {
			cmn_err(CE_NOTE, "ignored rdmsr: 0x%x\n", msr);
			data = 0;
		}
		break;
	}
	*pdata = data;

	return (0);
}

/*
 * Read or write a bunch of msrs. All parameters are kernel addresses.
 *
 * @return number of msrs set successfully.
 */
static int __msr_io(struct kvm_vcpu *vcpu, struct kvm_msrs *msrs,
    struct kvm_msr_entry *entries, int (*do_msr)(struct kvm_vcpu *vcpu,
    unsigned index, uint64_t *data))
{
	int i, idx;

	vcpu_load(vcpu);

#ifdef XXX
	idx = srcu_read_lock(&vcpu->kvm->srcu);
#else
	XXX_KVM_SYNC_PROBE;
#endif
	for (i = 0; i < msrs->nmsrs; i++) {
		if (do_msr(vcpu, entries[i].index, &entries[i].data))
			break;
	}

#ifdef XXX
	srcu_read_unlock(&vcpu->kvm->srcu, idx);
#else
	XXX_KVM_SYNC_PROBE;
#endif
	vcpu_put(vcpu);

	return (i);
}


/*
 * Reads an msr value (of 'msr_index') into 'pdata'.
 * Returns 0 on success, non-0 otherwise.
 * Assumes vcpu_load() was already called.
 */
int
kvm_get_msr(struct kvm_vcpu *vcpu, uint32_t msr_index, uint64_t *pdata)
{
	return (kvm_x86_ops->get_msr(vcpu, msr_index, pdata));
}



/*
 * Writes msr value into into the appropriate "register".
 * Returns 0 on success, non-0 otherwise.
 * Assumes vcpu_load() was already called.
 */
int
kvm_set_msr(struct kvm_vcpu *vcpu, uint32_t msr_index, uint64_t data)
{
	return (kvm_x86_ops->set_msr(vcpu, msr_index, data));
}

/*
 * Adapt set_msr() to msr_io()'s calling convention
 */
static int
do_set_msr(struct kvm_vcpu *vcpu, unsigned index, uint64_t *data)
{
	return (kvm_set_msr(vcpu, index, *data));
}


#define	EXCPT_BENIGN		0
#define	EXCPT_CONTRIBUTORY	1
#define	EXCPT_PF		2

static int
exception_class(int vector)
{
	switch (vector) {
	case PF_VECTOR:
		return (EXCPT_PF);
	case DE_VECTOR:
	case TS_VECTOR:
	case NP_VECTOR:
	case SS_VECTOR:
	case GP_VECTOR:
		return (EXCPT_CONTRIBUTORY);
	default:
		break;
	}

	return (EXCPT_BENIGN);
}

static void
kvm_multiple_exception(struct kvm_vcpu *vcpu,
    unsigned nr, int has_error, uint32_t error_code)
{
	uint32_t prev_nr;
	int class1, class2;

	if (!vcpu->arch.exception.pending) {
queue:
		vcpu->arch.exception.pending = 1;
		vcpu->arch.exception.has_error_code = has_error;
		vcpu->arch.exception.nr = nr;
		vcpu->arch.exception.error_code = error_code;
		return;
	}

	/* to check exception */
	prev_nr = vcpu->arch.exception.nr;
	if (prev_nr == DF_VECTOR) {
		/* triple fault -> shutdown */
		set_bit(KVM_REQ_TRIPLE_FAULT, &vcpu->requests);
		return;
	}
	class1 = exception_class(prev_nr);
	class2 = exception_class(nr);
	if ((class1 == EXCPT_CONTRIBUTORY && class2 == EXCPT_CONTRIBUTORY) ||
	    (class1 == EXCPT_PF && class2 != EXCPT_BENIGN)) {
		/* generate double fault per SDM Table 5-5 */
		vcpu->arch.exception.pending = 1;
		vcpu->arch.exception.has_error_code = 1;
		vcpu->arch.exception.nr = DF_VECTOR;
		vcpu->arch.exception.error_code = 0;
	} else {
		/*
		 * replace previous exception with a new one in a hope
		 * that instruction re-execution will regenerate lost
		 * exception
		 */
		goto queue;
	}
}

void
kvm_queue_exception(struct kvm_vcpu *vcpu, unsigned nr)
{
	kvm_multiple_exception(vcpu, nr, 0, 0);
}

void
kvm_queue_exception_e(struct kvm_vcpu *vcpu, unsigned nr, uint32_t error_code)
{
	kvm_multiple_exception(vcpu, nr, 1, error_code);
}

inline void
kvm_clear_exception_queue(struct kvm_vcpu *vcpu)
{
	vcpu->arch.exception.pending = 0;
}

inline void
kvm_clear_interrupt_queue(struct kvm_vcpu *vcpu)
{
	vcpu->arch.interrupt.pending = 0;
}


static void kvm_on_user_return(struct kvm_vcpu *,
    struct kvm_user_return_notifier *);

static void
shared_msr_update(unsigned slot, uint32_t msr)
{
	struct kvm_shared_msrs *smsr;
	uint64_t value;
	smsr = shared_msrs[CPU->cpu_id];

	/*
	 * only read, and nobody should modify it at this time,
	 * so don't need lock
	 */
	if (slot >= shared_msrs_global.nr) {
		cmn_err(CE_WARN, "kvm: invalid MSR slot!");
		return;
	}

	rdmsrl_safe(msr, (unsigned long long *)&value);
	smsr->values[slot].host = value;
	smsr->values[slot].curr = value;
}

void
kvm_shared_msr_cpu_online(void)
{
	unsigned i;

	for (i = 0; i < shared_msrs_global.nr; i++)
		shared_msr_update(i, shared_msrs_global.msrs[i]);
}

void
kvm_set_shared_msr(struct kvm_vcpu *vcpu, unsigned slot, uint64_t value,
    uint64_t mask)
{
	struct kvm_shared_msrs *smsr = shared_msrs[CPU->cpu_id];

	if (((value ^ smsr->values[slot].curr) & mask) == 0)
		return;

	smsr->values[slot].curr = value;
	wrmsrl(shared_msrs_global.msrs[slot], value);

	if (!smsr->registered) {
		smsr->urn.on_user_return = kvm_on_user_return;
		kvm_user_return_notifier_register(vcpu, &smsr->urn);
		smsr->registered = 1;
	}
}


int
kvm_arch_interrupt_allowed(struct kvm_vcpu *vcpu)
{
	return (kvm_x86_ops->interrupt_allowed(vcpu));
}



static int
kvm_read_guest_virt_helper(gva_t addr, void *val, unsigned int bytes,
    struct kvm_vcpu *vcpu, uint32_t access, uint32_t *error)
{
	uintptr_t data = (uintptr_t)val;
	int r = 0; /* X86EMUL_CONTINUE */

	while (bytes) {
		gpa_t gpa = vcpu->arch.mmu.gva_to_gpa(vcpu, addr,
		    access, error);
		unsigned offset = addr & (PAGESIZE-1);
		unsigned toread = min(bytes, (unsigned)PAGESIZE - offset);
		int ret;

		if (gpa == UNMAPPED_GVA) {
			r = 1; /* X86EMUL_PROPAGATE_FAULT */
			goto out;
		}
		ret = kvm_read_guest(vcpu->kvm, gpa, (void *)data, toread);
		if (ret < 0) {
			r = 1; /* X86EMUL_UNHANDLEABLE */
			goto out;
		}

		bytes -= toread;
		data += toread;
		addr += toread;
	}
out:
	return (r);
}

void
kvm_inject_page_fault(struct kvm_vcpu *vcpu, unsigned long addr,
    uint32_t error_code)
{
	KVM_VCPU_KSTAT_INC(vcpu, kvmvs_pf_guest);
	vcpu->arch.cr2 = addr;
	kvm_queue_exception_e(vcpu, PF_VECTOR, error_code);
}

static int
kvm_read_guest_virt_system(gva_t addr, void *val, unsigned int bytes,
    struct kvm_vcpu *vcpu, uint32_t *error)
{
	return (kvm_read_guest_virt_helper(addr, val, bytes, vcpu, 0, error));
}

/* used for instruction fetching */
static int
kvm_fetch_guest_virt(gva_t addr, void *val, unsigned int bytes,
    struct kvm_vcpu *vcpu, uint32_t *error)
{
	uint32_t access = (kvm_x86_ops->get_cpl(vcpu) == 3) ?
	    PFERR_USER_MASK : 0;

	return (kvm_read_guest_virt_helper(addr, val, bytes, vcpu,
	    access | PFERR_FETCH_MASK, error));
}

/* kvm_io_bus_write - called under kvm->slots_lock */
int
kvm_io_bus_write(struct kvm *kvm, enum kvm_bus bus_idx, gpa_t addr,
    int len, const void *val)
{
	int i;
#ifdef XXX_KVM_DECLARATION
	struct kvm_io_bus *bus = rcu_dereference(kvm->buses[bus_idx]);
#else
	struct kvm_io_bus *bus = kvm->buses[bus_idx];
#endif

	for (i = 0; i < bus->dev_count; i++) {
		if (!kvm_iodevice_write(bus->devs[i], addr, len, val))
			return (0);
	}

	return (-EOPNOTSUPP);
}

/* kvm_io_bus_read - called under kvm->slots_lock */
int
kvm_io_bus_read(struct kvm *kvm, enum kvm_bus bus_idx, gpa_t addr,
    int len, void *val)
{
	int i;
#ifdef XXX_KVM_DECLARATION
	struct kvm_io_bus *bus = rcu_dereference(kvm->buses[bus_idx]);
#else
	struct kvm_io_bus *bus = kvm->buses[bus_idx];
#endif

	for (i = 0; i < bus->dev_count; i++) {
		if (!kvm_iodevice_read(bus->devs[i], addr, len, val))
			return (0);
	}

	return (-EOPNOTSUPP);
}

static int
vcpu_mmio_write(struct kvm_vcpu *vcpu, gpa_t addr, int len, const void *v)
{
	if (vcpu->arch.apic &&
	    !kvm_iodevice_write(&vcpu->arch.apic->dev, addr, len, v))
		return (0);

	return (kvm_io_bus_write(vcpu->kvm, KVM_MMIO_BUS, addr, len, v));
}

static int
vcpu_mmio_read(struct kvm_vcpu *vcpu, gpa_t addr, int len, void *v)
{
	if (vcpu->arch.apic &&
	    !kvm_iodevice_read(&vcpu->arch.apic->dev, addr, len, v))
		return (0);

	return (kvm_io_bus_read(vcpu->kvm, KVM_MMIO_BUS, addr, len, v));
}

gpa_t
kvm_mmu_gva_to_gpa_read(struct kvm_vcpu *vcpu, gva_t gva, uint32_t *error)
{
	uint32_t access = (kvm_x86_ops->get_cpl(vcpu) == 3) ?
	    PFERR_USER_MASK : 0;

	return (vcpu->arch.mmu.gva_to_gpa(vcpu, gva, access, error));
}

static int
kvm_read_guest_virt(gva_t addr, void *val, unsigned int bytes,
    struct kvm_vcpu *vcpu, uint32_t *error)
{
	uint32_t access = (kvm_x86_ops->get_cpl(vcpu) == 3) ?
	    PFERR_USER_MASK : 0;

	return (kvm_read_guest_virt_helper(addr, val,
	    bytes, vcpu, access, error));
}

static int
emulator_read_emulated(unsigned long addr, void *val,
    unsigned int bytes, struct kvm_vcpu *vcpu)
{
	gpa_t gpa;
	uint32_t error_code;

	if (vcpu->mmio_read_completed) {
		memcpy(val, vcpu->mmio_data, bytes);
		KVM_TRACE3(mmio__read, unsigned int, bytes, uintptr_t,
		    vcpu->mmio_phys_addr, uint64_t, *(uint64_t *)val);

		vcpu->mmio_read_completed = 0;
		return (X86EMUL_CONTINUE);
	}

	gpa = kvm_mmu_gva_to_gpa_read(vcpu, addr, &error_code);

	if (gpa == UNMAPPED_GVA) {
		kvm_inject_page_fault(vcpu, addr, error_code);
		return (X86EMUL_PROPAGATE_FAULT);
	}

	/* For APIC access vmexit */
	if ((gpa & PAGEMASK) == APIC_DEFAULT_PHYS_BASE)
		goto mmio;

	if (kvm_read_guest_virt(addr, val,
	    bytes, vcpu, NULL) == X86EMUL_CONTINUE)
		return (X86EMUL_CONTINUE);

mmio:
	/*
	 * Is this MMIO handled locally?
	 */
	if (!vcpu_mmio_read(vcpu, gpa, bytes, val)) {
		KVM_TRACE3(mmio__read, unsigned int, bytes, uintptr_t, gpa,
		    uint64_t, *(uint64_t *)val);
		return (X86EMUL_CONTINUE);
	}

	KVM_TRACE2(mmio__read__unsatisfied, unsigned int, bytes,
	    uintptr_t, gpa);

	vcpu->mmio_needed = 1;
	vcpu->mmio_phys_addr = gpa;
	vcpu->mmio_size = bytes;
	vcpu->mmio_is_write = 0;

	return (X86EMUL_UNHANDLEABLE);
}


int
emulator_write_phys(struct kvm_vcpu *vcpu, gpa_t gpa,
    const void *val, int bytes)
{
	int ret;

	ret = kvm_write_guest(vcpu->kvm, gpa, val, bytes);

	if (ret < 0)
		return (0);

	kvm_mmu_pte_write(vcpu, gpa, val, bytes, 1);

	return (1);
}

gpa_t
kvm_mmu_gva_to_gpa_write(struct kvm_vcpu *vcpu, gva_t gva, uint32_t *error)
{
	uint32_t access = (kvm_x86_ops->get_cpl(vcpu) == 3) ?
	    PFERR_USER_MASK : 0;

	access |= PFERR_WRITE_MASK;

	return (vcpu->arch.mmu.gva_to_gpa(vcpu, gva, access, error));
}

static int
emulator_write_emulated_onepage(unsigned long addr, const void *val,
    unsigned int bytes, struct kvm_vcpu *vcpu)
{
	gpa_t gpa;
	uint32_t error_code;

	gpa = kvm_mmu_gva_to_gpa_write(vcpu, addr, &error_code);

	if (gpa == UNMAPPED_GVA) {
		kvm_inject_page_fault(vcpu, addr, error_code);
		return (X86EMUL_PROPAGATE_FAULT);
	}

	/* For APIC access vmexit */
	if ((gpa & PAGEMASK) == APIC_DEFAULT_PHYS_BASE)
		goto mmio;

	if (emulator_write_phys(vcpu, gpa, val, bytes))
		return (X86EMUL_CONTINUE);

mmio:
	KVM_TRACE3(mmio__write, unsigned int, bytes, uintptr_t, gpa,
	    uint64_t, *(uint64_t *)val);

	/*
	 * Is this MMIO handled locally?
	 */
	if (!vcpu_mmio_write(vcpu, gpa, bytes, val))
		return (X86EMUL_CONTINUE);

	vcpu->mmio_needed = 1;
	vcpu->mmio_phys_addr = gpa;
	vcpu->mmio_size = bytes;
	vcpu->mmio_is_write = 1;
	memcpy(vcpu->mmio_data, val, bytes);

	return (X86EMUL_CONTINUE);
}

int
emulator_write_emulated(unsigned long addr, const void *val,
    unsigned int bytes, struct kvm_vcpu *vcpu)
{
	uintptr_t data = (uintptr_t)val;

	/* Crossing a page boundary? */
	if (((addr + bytes - 1) ^ addr) & PAGEMASK) {
		int rc, now;

		now = -addr & ~PAGEMASK;
		rc = emulator_write_emulated_onepage(addr,
		    (void *)data, now, vcpu);

		if (rc != X86EMUL_CONTINUE)
			return (rc);

		addr += now;
		data += now;
		bytes -= now;
	}

	return (emulator_write_emulated_onepage(addr, val, bytes, vcpu));
}

static int
emulator_cmpxchg_emulated(unsigned long addr, const void *old,
    const void *new, unsigned int bytes, struct kvm_vcpu *vcpu)
{
	cmn_err(CE_WARN, "kvm: emulating exchange as write\n");
#ifndef CONFIG_X86_64
	/* guests cmpxchg8b have to be emulated atomically */
	if (bytes == 8) {
		gpa_t gpa;
		page_t page;
		char *kaddr;
		uint64_t val;

		gpa = kvm_mmu_gva_to_gpa_write(vcpu, addr, NULL);

		if (gpa == UNMAPPED_GVA ||
		    (gpa & PAGEMASK) == APIC_DEFAULT_PHYS_BASE)
			goto emul_write;

		if (((gpa + bytes - 1) & PAGEMASK) != (gpa & PAGEMASK))
			goto emul_write;

		val = *(uint64_t *)new;

		page = gfn_to_page(vcpu->kvm, gpa >> PAGESHIFT);
		kaddr = kmap_atomic(page, KM_USER0);

		set_64bit((uint64_t *)(kaddr + offset_in_page(gpa)), val);
		kunmap_atomic(kaddr, KM_USER0);
		kvm_release_page_dirty(page);
	}
emul_write:
#endif

	return (emulator_write_emulated(addr, new, bytes, vcpu));
}

static struct x86_emulate_ops emulate_ops = {
	.read_std		= kvm_read_guest_virt_system,
	.fetch			= kvm_fetch_guest_virt,
	.read_emulated		= emulator_read_emulated,
	.write_emulated		= emulator_write_emulated,
	.cmpxchg_emulated	= emulator_cmpxchg_emulated,
};

static void
cache_all_regs(struct kvm_vcpu *vcpu)
{
	kvm_register_read(vcpu, VCPU_REGS_RAX);
	kvm_register_read(vcpu, VCPU_REGS_RSP);
	kvm_register_read(vcpu, VCPU_REGS_RIP);
	vcpu->arch.regs_dirty = ~0;
}

static unsigned long
get_segment_base(struct kvm_vcpu *vcpu, int seg)
{
	return (kvm_x86_ops->get_segment_base(vcpu, seg));
}

void
kvm_report_emulation_failure(struct kvm_vcpu *vcpu, const char *context)
{
	uint8_t opcodes[4];
	unsigned long rip = kvm_rip_read(vcpu);
	unsigned long rip_linear;

#ifdef XXX
	if (!printk_ratelimit())
		return;
#else
	XXX_KVM_PROBE;
#endif

	rip_linear = rip + get_segment_base(vcpu, VCPU_SREG_CS);

	kvm_read_guest_virt(rip_linear, (void *)opcodes, 4, vcpu, NULL);

	cmn_err(CE_WARN, "emulation failed (%s) rip %lx %02x %02x %02x %02x\n",
	    context, rip, opcodes[0], opcodes[1], opcodes[2], opcodes[3]);
}

int
emulate_instruction(struct kvm_vcpu *vcpu, unsigned long cr2,
    uint16_t error_code, int emulation_type)
{
	int r, shadow_mask;
	struct decode_cache *c;
	struct kvm_run *run = vcpu->run;

	kvm_clear_exception_queue(vcpu);
	vcpu->arch.mmio_fault_cr2 = cr2;

	/*
	 * TODO: fix emulate.c to use guest_read/write_register
	 * instead of direct ->regs accesses, can save hundred cycles
	 * on Intel for instructions that don't read/change RSP, for
	 * for example.
	 */
	cache_all_regs(vcpu);

	vcpu->mmio_is_write = 0;
	vcpu->arch.pio.string = 0;

	if (!(emulation_type & EMULTYPE_NO_DECODE)) {
		int cs_db, cs_l;
		kvm_x86_ops->get_cs_db_l_bits(vcpu, &cs_db, &cs_l);

		vcpu->arch.emulate_ctxt.vcpu = vcpu;
		vcpu->arch.emulate_ctxt.eflags = kvm_get_rflags(vcpu);
		vcpu->arch.emulate_ctxt.mode = (!is_protmode(vcpu)) ?
		    X86EMUL_MODE_REAL :
		    (vcpu->arch.emulate_ctxt.eflags & X86_EFLAGS_VM) ?
		    X86EMUL_MODE_VM86 : cs_l ? X86EMUL_MODE_PROT64 :
		    cs_db ? X86EMUL_MODE_PROT32 : X86EMUL_MODE_PROT16;

		r = x86_decode_insn(&vcpu->arch.emulate_ctxt, &emulate_ops);

		/*
		 * Only allow emulation of specific instructions on #UD
		 * (namely VMMCALL, sysenter, sysexit, syscall)
		 */
		c = &vcpu->arch.emulate_ctxt.decode;
		if (emulation_type & EMULTYPE_TRAP_UD) {
			if (!c->twobyte)
				return (EMULATE_FAIL);
			switch (c->b) {
			case 0x01: /* VMMCALL */
				if (c->modrm_mod != 3 || c->modrm_rm != 1)
					return (EMULATE_FAIL);
				break;
			case 0x34: /* sysenter */
			case 0x35: /* sysexit */
				if (c->modrm_mod != 0 || c->modrm_rm != 0)
					return (EMULATE_FAIL);
				break;
			case 0x05: /* syscall */
				if (c->modrm_mod != 0 || c->modrm_rm != 0)
					return (EMULATE_FAIL);
				break;
			default:
				return (EMULATE_FAIL);
			}

			if (!(c->modrm_reg == 0 || c->modrm_reg == 3))
				return (EMULATE_FAIL);
		}

		KVM_VCPU_KSTAT_INC(vcpu, kvmvs_insn_emulation);

		if (r)  {
			KVM_VCPU_KSTAT_INC(vcpu, kvmvs_insn_emulation_fail);

			if (kvm_mmu_unprotect_page_virt(vcpu, cr2))
				return (EMULATE_DONE);
			return (EMULATE_FAIL);
		}
	}

	if (emulation_type & EMULTYPE_SKIP) {
		kvm_rip_write(vcpu, vcpu->arch.emulate_ctxt.decode.eip);
		return (EMULATE_DONE);
	}

	r = x86_emulate_insn(&vcpu->arch.emulate_ctxt, &emulate_ops);
	shadow_mask = vcpu->arch.emulate_ctxt.interruptibility;

	if (r == 0)
		kvm_x86_ops->set_interrupt_shadow(vcpu, shadow_mask);

	if (vcpu->arch.pio.string)
		return (EMULATE_DO_MMIO);

	if ((r || vcpu->mmio_is_write) && run) {
		run->exit_reason = KVM_EXIT_MMIO;
		run->mmio.phys_addr = vcpu->mmio_phys_addr;
		memcpy(run->mmio.data, vcpu->mmio_data, 8);
		run->mmio.len = vcpu->mmio_size;
		run->mmio.is_write = vcpu->mmio_is_write;
	}

	if (r) {
		if (kvm_mmu_unprotect_page_virt(vcpu, cr2))
			return (EMULATE_DONE);
		if (!vcpu->mmio_needed) {
			kvm_report_emulation_failure(vcpu, "mmio");
			return (EMULATE_FAIL);
		}

		return (EMULATE_DO_MMIO);
	}

	kvm_set_rflags(vcpu, vcpu->arch.emulate_ctxt.eflags);

	if (vcpu->mmio_is_write) {
		vcpu->mmio_needed = 0;
		return (EMULATE_DO_MMIO);
	}

	return (EMULATE_DONE);
}

int
kvm_event_needs_reinjection(struct kvm_vcpu *vcpu)
{
	return (vcpu->arch.exception.pending || vcpu->arch.interrupt.pending ||
	    vcpu->arch.nmi_injected);
}

int
kvm_emulate_halt(struct kvm_vcpu *vcpu)
{
	KVM_VCPU_KSTAT_INC(vcpu, kvmvs_halt_exits);

	if (irqchip_in_kernel(vcpu->kvm)) {
		vcpu->arch.mp_state = KVM_MP_STATE_HALTED;
		return (1);
	} else {
		vcpu->run->exit_reason = KVM_EXIT_HLT;
		return (0);
	}
}




static int
kvm_write_guest_virt(gva_t addr, void *val, unsigned int bytes,
    struct kvm_vcpu *vcpu, uint32_t *error)
{
	uintptr_t data = (uintptr_t)val;

	while (bytes) {
		gpa_t gpa = kvm_mmu_gva_to_gpa_write(vcpu, addr, error);
		unsigned offset = addr & (PAGESIZE-1);
		unsigned towrite = min(bytes, (unsigned)PAGESIZE - offset);
		int ret;

		if (gpa == UNMAPPED_GVA)
			return (X86EMUL_PROPAGATE_FAULT);

		if (kvm_write_guest(vcpu->kvm, gpa, (void *)data, towrite) < 0)
			return (X86EMUL_UNHANDLEABLE);

		bytes -= towrite;
		data += towrite;
		addr += towrite;
	}

	return (0);
}

static int
pio_copy_data(struct kvm_vcpu *vcpu)
{
	void *p = vcpu->arch.pio_data;
	gva_t q = vcpu->arch.pio.guest_gva;
	unsigned bytes;
	int ret;
	uint32_t error_code;

	bytes = vcpu->arch.pio.size * vcpu->arch.pio.cur_count;

	if (vcpu->arch.pio.in)
		ret = kvm_write_guest_virt(q, p, bytes, vcpu, &error_code);
	else
		ret = kvm_read_guest_virt(q, p, bytes, vcpu, &error_code);

	if (ret == X86EMUL_PROPAGATE_FAULT)
		kvm_inject_page_fault(vcpu, q, error_code);

	return (ret);
}

int
complete_pio(struct kvm_vcpu *vcpu)
{
	struct kvm_pio_request *io = &vcpu->arch.pio;
	long delta;
	int r;
	unsigned long val;

	if (!io->string) {
		if (io->in) {
			val = kvm_register_read(vcpu, VCPU_REGS_RAX);
			memcpy(&val, vcpu->arch.pio_data, io->size);
			kvm_register_write(vcpu, VCPU_REGS_RAX, val);
		}
	} else {
		if (io->in) {
			r = pio_copy_data(vcpu);
			if (r)
				goto out;
		}

		delta = 1;
		if (io->rep) {
			delta *= io->cur_count;
			/*
			 * The size of the register should really depend on
			 * current address size.
			 */
			val = kvm_register_read(vcpu, VCPU_REGS_RCX);
			val -= delta;
			kvm_register_write(vcpu, VCPU_REGS_RCX, val);
		}
		if (io->down)
			delta = -delta;
		delta *= io->size;
		if (io->in) {
			val = kvm_register_read(vcpu, VCPU_REGS_RDI);
			val += delta;
			kvm_register_write(vcpu, VCPU_REGS_RDI, val);
		} else {
			val = kvm_register_read(vcpu, VCPU_REGS_RSI);
			val += delta;
			kvm_register_write(vcpu, VCPU_REGS_RSI, val);
		}
	}
out:
	io->count -= io->cur_count;
	io->cur_count = 0;

	return (0);
}

static int
kernel_pio(struct kvm_vcpu *vcpu, void *pd)
{
	/* TODO: String I/O for in kernel device */
	int r;

	if (vcpu->arch.pio.in) {
		r = kvm_io_bus_read(vcpu->kvm, KVM_PIO_BUS, vcpu->arch.pio.port,
		    vcpu->arch.pio.size, pd);
	} else {
		r = kvm_io_bus_write(vcpu->kvm, KVM_PIO_BUS,
		    vcpu->arch.pio.port, vcpu->arch.pio.size, pd);
	}

	return (r);
}

int
kvm_emulate_pio(struct kvm_vcpu *vcpu, int in, int size, unsigned port)
{
	unsigned long val;

	DTRACE_PROBE4(kvm__pio, int, !in, unsigned, port, int, size,
	    unsigned long, 1)

	vcpu->run->exit_reason = KVM_EXIT_IO;
	vcpu->run->io.direction = in ? KVM_EXIT_IO_IN : KVM_EXIT_IO_OUT;
	vcpu->run->io.size = vcpu->arch.pio.size = size;
	vcpu->run->io.data_offset = KVM_PIO_PAGE_OFFSET * PAGESIZE;
	vcpu->run->io.count = vcpu->arch.pio.count =
	    vcpu->arch.pio.cur_count = 1;
	vcpu->run->io.port = vcpu->arch.pio.port = port;
	vcpu->arch.pio.in = in;
	vcpu->arch.pio.string = 0;
	vcpu->arch.pio.down = 0;
	vcpu->arch.pio.rep = 0;

	if (!vcpu->arch.pio.in) {
		val = kvm_register_read(vcpu, VCPU_REGS_RAX);
		memcpy(vcpu->arch.pio_data, &val, 4);
	}

	if (!kernel_pio(vcpu, vcpu->arch.pio_data)) {
		complete_pio(vcpu);
		return (1);
	}

	return (0);
}


void
kvm_set_cr0(struct kvm_vcpu *vcpu, unsigned long cr0)
{
	cr0 |= X86_CR0_ET;

#ifdef CONFIG_X86_64
	if (cr0 & 0xffffffff00000000UL) {
		kvm_inject_gp(vcpu, 0);
		return;
	}
#endif

	cr0 &= ~CR0_RESERVED_BITS;

	if ((cr0 & X86_CR0_NW) && !(cr0 & X86_CR0_CD)) {
		kvm_inject_gp(vcpu, 0);
		return;
	}

	if ((cr0 & X86_CR0_PG) && !(cr0 & X86_CR0_PE)) {
		kvm_inject_gp(vcpu, 0);
		return;
	}

	if (!is_paging(vcpu) && (cr0 & X86_CR0_PG)) {
#ifdef CONFIG_X86_64
		if ((vcpu->arch.efer & EFER_LME)) {
			int cs_db, cs_l;

			if (!is_pae(vcpu)) {
				kvm_inject_gp(vcpu, 0);
				return;
			}

			kvm_x86_ops->get_cs_db_l_bits(vcpu, &cs_db, &cs_l);
			if (cs_l) {
				kvm_inject_gp(vcpu, 0);
				return;

			}
		} else
#endif
		if (is_pae(vcpu) && !load_pdptrs(vcpu, vcpu->arch.cr3)) {
			kvm_inject_gp(vcpu, 0);
			return;
		}

	}

	kvm_x86_ops->set_cr0(vcpu, cr0);
	vcpu->arch.cr0 = cr0;
	kvm_mmu_reset_context(vcpu);
}

static int
pdptrs_changed(struct kvm_vcpu *vcpu)
{
	uint64_t pdpte[ARRAY_SIZE(vcpu->arch.pdptrs)];

	if (is_long_mode(vcpu) || !is_pae(vcpu))
		return (0);

	if (!test_bit(VCPU_EXREG_PDPTR,
	    (unsigned long *)&vcpu->arch.regs_avail)) {
		return (1);
	}

	if (kvm_read_guest(vcpu->kvm, vcpu->arch.cr3 & ~31u,
	    pdpte, sizeof (pdpte)) < 0)
		return (1);

	return (memcmp(pdpte, vcpu->arch.pdptrs, sizeof (pdpte)) != 0);
}

void
kvm_set_cr3(struct kvm_vcpu *vcpu, unsigned long cr3)
{
	if (cr3 == vcpu->arch.cr3 && !pdptrs_changed(vcpu)) {
		kvm_mmu_sync_roots(vcpu);
		kvm_mmu_flush_tlb(vcpu);
		return;
	}

	if (is_long_mode(vcpu)) {
		if (cr3 & CR3_L_MODE_RESERVED_BITS) {
			kvm_inject_gp(vcpu, 0);
			return;
		}
	} else {
		if (is_pae(vcpu)) {
			if (cr3 & CR3_PAE_RESERVED_BITS) {
				kvm_inject_gp(vcpu, 0);
				return;
			}
			if (is_paging(vcpu) && !load_pdptrs(vcpu, cr3)) {
				kvm_inject_gp(vcpu, 0);
				return;
			}
		}
		/*
		 * We don't check reserved bits in nonpae mode, because
		 * this isn't enforced, and VMware depends on this.
		 */
	}

	/*
	 * Does the new cr3 value map to physical memory? (Note, we
	 * catch an invalid cr3 even in real-mode, because it would
	 * cause trouble later on when we turn on paging anyway.)
	 *
	 * A real CPU would silently accept an invalid cr3 and would
	 * attempt to use it - with largely undefined (and often hard
	 * to debug) behavior on the guest side.
	 */
	if ((!gfn_to_memslot(vcpu->kvm, cr3 >> PAGESHIFT)))
		kvm_inject_gp(vcpu, 0);
	else {
		vcpu->arch.cr3 = cr3;
		vcpu->arch.mmu.new_cr3(vcpu);
	}
}

void
kvm_set_cr4(struct kvm_vcpu *vcpu, unsigned long cr4)
{
	unsigned long old_cr4 = kvm_read_cr4(vcpu);
	unsigned long pdptr_bits = X86_CR4_PGE | X86_CR4_PSE | X86_CR4_PAE;

	if (cr4 & CR4_RESERVED_BITS) {
		kvm_inject_gp(vcpu, 0);
		return;
	}

	if (is_long_mode(vcpu)) {
		if (!(cr4 & X86_CR4_PAE)) {
			kvm_inject_gp(vcpu, 0);
			return;
		}
	} else if (is_paging(vcpu) && (cr4 & X86_CR4_PAE) &&
	    ((cr4 ^ old_cr4) & pdptr_bits) &&
	    !load_pdptrs(vcpu, vcpu->arch.cr3)) {
		kvm_inject_gp(vcpu, 0);
		return;
	}

	if (cr4 & X86_CR4_VMXE) {
		kvm_inject_gp(vcpu, 0);
		return;
	}

	kvm_x86_ops->set_cr4(vcpu, cr4);
	vcpu->arch.cr4 = cr4;
	vcpu->arch.mmu.base_role.cr4_pge = (cr4 & X86_CR4_PGE) && !tdp_enabled;
	kvm_mmu_reset_context(vcpu);
}

void
kvm_lmsw(struct kvm_vcpu *vcpu, unsigned long msw)
{
	kvm_set_cr0(vcpu, kvm_read_cr0_bits(vcpu, ~0x0ful) | (msw & 0x0f));
}



/*
 * Checks if cpl <= required_cpl; if true, return true.  Otherwise queue
 * a #GP and return false.
 */
int
kvm_require_cpl(struct kvm_vcpu *vcpu, int required_cpl)
{
	if (kvm_x86_ops->get_cpl(vcpu) <= required_cpl)
		return (1);
	kvm_queue_exception_e(vcpu, GP_VECTOR, 0);
	return (0);
}


void
kvm_emulate_cpuid(struct kvm_vcpu *vcpu)
{
	uint32_t function, index;
	struct kvm_cpuid_entry2 *best;

	function = kvm_register_read(vcpu, VCPU_REGS_RAX);
	index = kvm_register_read(vcpu, VCPU_REGS_RCX);
	kvm_register_write(vcpu, VCPU_REGS_RAX, 0);
	kvm_register_write(vcpu, VCPU_REGS_RBX, 0);
	kvm_register_write(vcpu, VCPU_REGS_RCX, 0);
	kvm_register_write(vcpu, VCPU_REGS_RDX, 0);
	best = kvm_find_cpuid_entry(vcpu, function, index);
	if (best) {
		kvm_register_write(vcpu, VCPU_REGS_RAX, best->eax);
		kvm_register_write(vcpu, VCPU_REGS_RBX, best->ebx);
		kvm_register_write(vcpu, VCPU_REGS_RCX, best->ecx);
		kvm_register_write(vcpu, VCPU_REGS_RDX, best->edx);
	}
	kvm_x86_ops->skip_emulated_instruction(vcpu);

	KVM_TRACE5(cpuid, uint32_t, function,
	    uint32_t, kvm_register_read(vcpu, VCPU_REGS_RAX),
	    uint32_t, kvm_register_read(vcpu, VCPU_REGS_RBX),
	    uint32_t, kvm_register_read(vcpu, VCPU_REGS_RCX),
	    uint32_t, kvm_register_read(vcpu, VCPU_REGS_RDX));
}

static int
kvm_hv_hypercall_enabled(struct kvm *kvm)
{
	return (kvm->arch.hv_hypercall & HV_X64_MSR_HYPERCALL_ENABLE);
}

int
kvm_hv_hypercall(struct kvm_vcpu *vcpu)
{
	uint64_t param, ingpa, outgpa, ret;
	uint16_t code, rep_idx, rep_cnt, res = HV_STATUS_SUCCESS, rep_done = 0;
	int fast, longmode;
	int cs_db, cs_l;

	/*
	 * hypercall generates UD from non zero cpl and real mode
	 * per HYPER-V spec
	 */
	if (kvm_x86_ops->get_cpl(vcpu) != 0 || !is_protmode(vcpu)) {
		kvm_queue_exception(vcpu, UD_VECTOR);
		return (0);
	}

	kvm_x86_ops->get_cs_db_l_bits(vcpu, &cs_db, &cs_l);
	longmode = is_long_mode(vcpu) && cs_l == 1;

	if (!longmode) {
		param = ((uint64_t)kvm_register_read(vcpu,
		    VCPU_REGS_RDX) << 32) | (kvm_register_read(vcpu,
		    VCPU_REGS_RAX) & 0xffffffff);

		ingpa = ((uint64_t)kvm_register_read(vcpu,
		    VCPU_REGS_RBX) << 32) | (kvm_register_read(vcpu,
		    VCPU_REGS_RCX) & 0xffffffff);

		outgpa = ((uint64_t)kvm_register_read(vcpu,
		    VCPU_REGS_RDI) << 32) | (kvm_register_read(vcpu,
		    VCPU_REGS_RSI) & 0xffffffff);
	}
#ifdef CONFIG_X86_64
	else {
		param = kvm_register_read(vcpu, VCPU_REGS_RCX);
		ingpa = kvm_register_read(vcpu, VCPU_REGS_RDX);
		outgpa = kvm_register_read(vcpu, VCPU_REGS_R8);
	}
#endif

	code = param & 0xffff;
	fast = (param >> 16) & 0x1;
	rep_cnt = (param >> 32) & 0xfff;
	rep_idx = (param >> 48) & 0xfff;

	KVM_TRACE6(hv__hypercall, uintptr_t, code, uintptr_t, fast,
	    uintptr_t, rep_cnt, uintptr_t, rep_idx, uintptr_t, ingpa,
	    uintptr_t, outgpa);

	switch (code) {
	case HV_X64_HV_NOTIFY_LONG_SPIN_WAIT:
#ifdef XXX
		kvm_vcpu_on_spin(vcpu);
#else
		XXX_KVM_PROBE;
#endif
		break;
	default:
		res = HV_STATUS_INVALID_HYPERCALL_CODE;
		break;
	}

	ret = res | (((uint64_t)rep_done & 0xfff) << 32);

	if (longmode) {
		kvm_register_write(vcpu, VCPU_REGS_RAX, ret);
	} else {
		kvm_register_write(vcpu, VCPU_REGS_RDX, ret >> 32);
		kvm_register_write(vcpu, VCPU_REGS_RAX, ret & 0xffffffff);
	}

	return (1);
}

/* Return values for hypercalls */
#define	KVM_ENOSYS		1000
#define	KVM_EFAULT		EFAULT
#define	KVM_E2BIG		E2BIG
#define	KVM_EPERM		EPERM

#define	KVM_HC_VAPIC_POLL_IRQ		1
#define	KVM_HC_MMU_OP			2

/*
 * hypercalls use architecture specific
 */

#ifdef _KERNEL
#ifdef CONFIG_KVM_GUEST
void __init kvm_guest_init(void);
#else
#define	kvm_guest_init() do { } while (0)
#endif

static unsigned int
kvm_arch_para_features(void)
{
#ifdef XXX
	return (cpuid_eax(KVM_CPUID_FEATURES));
#else
	XXX_KVM_PROBE;
	return (0);
#endif
}

static inline int
kvm_para_has_feature(unsigned int feature)
{
	if (kvm_arch_para_features() & (1UL << feature))
		return (1);
	return (0);
}
#endif /* _KERNEL */

int
kvm_emulate_hypercall(struct kvm_vcpu *vcpu)
{
	unsigned long nr, a0, a1, a2, a3, ret;
	int r = 1;

	if (kvm_hv_hypercall_enabled(vcpu->kvm))
		return (kvm_hv_hypercall(vcpu));

	nr = kvm_register_read(vcpu, VCPU_REGS_RAX);
	a0 = kvm_register_read(vcpu, VCPU_REGS_RBX);
	a1 = kvm_register_read(vcpu, VCPU_REGS_RCX);
	a2 = kvm_register_read(vcpu, VCPU_REGS_RDX);
	a3 = kvm_register_read(vcpu, VCPU_REGS_RSI);

	KVM_TRACE5(hypercall, uintptr_t, nr, uintptr_t, a0, uintptr_t, a1,
	    uintptr_t, a2, uintptr_t, a3);

	if (!is_long_mode(vcpu)) {
		nr &= 0xFFFFFFFF;
		a0 &= 0xFFFFFFFF;
		a1 &= 0xFFFFFFFF;
		a2 &= 0xFFFFFFFF;
		a3 &= 0xFFFFFFFF;
	}

	if (kvm_x86_ops->get_cpl(vcpu) != 0) {
		ret = -EPERM;
		goto out;
	}

	switch (nr) {
	case KVM_HC_VAPIC_POLL_IRQ:
		ret = 0;
		break;
	case KVM_HC_MMU_OP:
#ifdef XXX
		r = kvm_pv_mmu_op(vcpu, a0, hc_gpa(vcpu, a1, a2), &ret);
#else
		XXX_KVM_PROBE;
		ret = -ENOSYS;
#endif
		break;
	default:
		ret = -ENOSYS;
		break;
	}
out:
	kvm_register_write(vcpu, VCPU_REGS_RAX, ret);

	KVM_VCPU_KSTAT_INC(vcpu, kvmvs_hypercalls);

	return (r);
}





static int
is_vm86_segment(struct kvm_vcpu *vcpu, int seg)
{
	return (seg != VCPU_SREG_LDTR) && (seg != VCPU_SREG_TR) &&
	    (kvm_get_rflags(vcpu) & X86_EFLAGS_VM);
}

static inline unsigned long
get_desc_limit(const struct desc_struct *desc)
{
	return (desc->c.b.limit0 | (desc->c.b.limit << 16));
}

unsigned long
get_desc_base(const struct desc_struct *desc)
{
	return (unsigned)(desc->c.b.base0 | ((desc->c.b.base1) << 16) |
	    ((desc->c.b.base2) << 24));
}


static void
seg_desct_to_kvm_desct(struct desc_struct *seg_desc, uint16_t selector,
    struct kvm_segment *kvm_desct)
{
	kvm_desct->base = get_desc_base(seg_desc);
	kvm_desct->limit = get_desc_limit(seg_desc);
	if (seg_desc->c.b.g) {
		kvm_desct->limit <<= 12;
		kvm_desct->limit |= 0xfff;
	}
	kvm_desct->selector = selector;
	kvm_desct->type = seg_desc->c.b.type;
	kvm_desct->present = seg_desc->c.b.p;
	kvm_desct->dpl = seg_desc->c.b.dpl;
	kvm_desct->db = seg_desc->c.b.d;
	kvm_desct->s = seg_desc->c.b.s;
	kvm_desct->l = seg_desc->c.b.l;
	kvm_desct->g = seg_desc->c.b.g;
	kvm_desct->avl = seg_desc->c.b.avl;
	if (!selector)
		kvm_desct->unusable = 1;
	else
		kvm_desct->unusable = 0;
	kvm_desct->padding = 0;
}

static int
kvm_load_realmode_segment(struct kvm_vcpu *vcpu, uint16_t selector, int seg)
{
	struct kvm_segment segvar = {
		.base = selector << 4,
		.limit = 0xffff,
		.selector = selector,
		.type = 3,
		.present = 1,
		.dpl = 3,
		.db = 0,
		.s = 1,
		.l = 0,
		.g = 0,
		.avl = 0,
		.unusable = 0,
	};
	kvm_x86_ops->set_segment(vcpu, &segvar, seg);
	return (0);
}

static void
get_segment_descriptor_dtable(struct kvm_vcpu *vcpu, uint16_t selector,
    struct descriptor_table *dtable)
{
	if (selector & 1 << 2) {
		struct kvm_segment kvm_seg;

		kvm_get_segment(vcpu, &kvm_seg, VCPU_SREG_LDTR);

		if (kvm_seg.unusable)
			dtable->limit = 0;
		else
			dtable->limit = kvm_seg.limit;
		dtable->base = kvm_seg.base;
	} else
		kvm_x86_ops->get_gdt(vcpu, dtable);
}

/* allowed just for 8 bytes segments */
static int
load_guest_segment_descriptor(struct kvm_vcpu *vcpu, uint16_t selector,
    struct desc_struct *seg_desc)
{
	struct descriptor_table dtable;
	uint16_t index = selector >> 3;
	int ret;
	uint32_t err;
	gva_t addr;

	get_segment_descriptor_dtable(vcpu, selector, &dtable);

	if (dtable.limit < index * 8 + 7) {
		kvm_queue_exception_e(vcpu, GP_VECTOR, selector & 0xfffc);
		return (1);
	}

	addr = dtable.base + index * 8;
	ret = kvm_read_guest_virt_system(addr, seg_desc, sizeof (*seg_desc),
	    vcpu,  &err);

	if (ret == 1)
		kvm_inject_page_fault(vcpu, addr, err);

	return (ret);
}

/* allowed just for 8 bytes segments */
static int
save_guest_segment_descriptor(struct kvm_vcpu *vcpu, uint16_t selector,
    struct desc_struct *seg_desc)
{
	struct descriptor_table dtable;
	uint16_t index = selector >> 3;

	get_segment_descriptor_dtable(vcpu, selector, &dtable);

	if (dtable.limit < index * 8 + 7)
		return (1);

	return kvm_write_guest_virt(dtable.base + index * 8, seg_desc,
	    sizeof (*seg_desc), vcpu, NULL);
}

int
kvm_load_segment_descriptor(struct kvm_vcpu *vcpu, uint16_t selector, int seg)
{
	struct kvm_segment kvm_seg;
	struct desc_struct seg_desc;
	uint8_t dpl, rpl, cpl;
	unsigned err_vec = GP_VECTOR;
	uint32_t err_code = 0;
	int null_selector = !(selector & ~0x3); /* 0000-0003 are null */
	int ret;

	if (is_vm86_segment(vcpu, seg) || !is_protmode(vcpu))
		return (kvm_load_realmode_segment(vcpu, selector, seg));

	/* NULL selector is not valid for TR, CS and SS */
	if ((seg == VCPU_SREG_CS || seg == VCPU_SREG_SS ||
	    seg == VCPU_SREG_TR) && null_selector)
		goto exception;

	/* TR should be in GDT only */
	if (seg == VCPU_SREG_TR && (selector & (1 << 2)))
		goto exception;

	ret = load_guest_segment_descriptor(vcpu, selector, &seg_desc);

	if (ret)
		return (ret);

	seg_desct_to_kvm_desct(&seg_desc, selector, &kvm_seg);

	if (null_selector) { /* for NULL selector skip all following checks */
		kvm_seg.unusable = 1;
		goto load;
	}

	err_code = selector & 0xfffc;
	err_vec = GP_VECTOR;

	/* can't load system descriptor into segment selecor */
	if (seg <= VCPU_SREG_GS && !kvm_seg.s)
		goto exception;

	if (!kvm_seg.present) {
		err_vec = (seg == VCPU_SREG_SS) ? SS_VECTOR : NP_VECTOR;
		goto exception;
	}

	rpl = selector & 3;
	dpl = kvm_seg.dpl;
	cpl = kvm_x86_ops->get_cpl(vcpu);

	switch (seg) {
	case VCPU_SREG_SS:
		/*
		 * segment is not a writable data segment or segment
		 * selector's RPL != CPL or segment selector's RPL != CPL
		 */
		if (rpl != cpl || (kvm_seg.type & 0xa) != 0x2 || dpl != cpl)
			goto exception;
		break;
	case VCPU_SREG_CS:
		if (!(kvm_seg.type & 8))
			goto exception;

		if (kvm_seg.type & 4) {
			/* conforming */
			if (dpl > cpl)
				goto exception;
		} else {
			/* nonconforming */
			if (rpl > cpl || dpl != cpl)
				goto exception;
		}
		/* CS(RPL) <- CPL */
		selector = (selector & 0xfffc) | cpl;
		break;
	case VCPU_SREG_TR:
		if (kvm_seg.s || (kvm_seg.type != 1 && kvm_seg.type != 9))
			goto exception;
		break;
	case VCPU_SREG_LDTR:
		if (kvm_seg.s || kvm_seg.type != 2)
			goto exception;
		break;
	default: /*  DS, ES, FS, or GS */
		/*
		 * segment is not a data or readable code segment or
		 * ((segment is a data or nonconforming code segment)
		 * and (both RPL and CPL > DPL))
		 */
		if ((kvm_seg.type & 0xa) == 0x8 ||
		    (((kvm_seg.type & 0xc) != 0xc) && (rpl > dpl && cpl > dpl)))
			goto exception;
		break;
	}

	if (!kvm_seg.unusable && kvm_seg.s) {
		/* mark segment as accessed */
		kvm_seg.type |= 1;
		seg_desc.c.b.type |= 1;
		save_guest_segment_descriptor(vcpu, selector, &seg_desc);
	}
load:
	kvm_set_segment(vcpu, &kvm_seg, seg);
	return (0);
exception:
	kvm_queue_exception_e(vcpu, err_vec, err_code);
	return (1);

}

static void
save_state_to_tss32(struct kvm_vcpu *vcpu, struct tss_segment_32 *tss)
{
	tss->cr3 = vcpu->arch.cr3;
	tss->eip = kvm_rip_read(vcpu);
	tss->eflags = kvm_get_rflags(vcpu);
	tss->eax = kvm_register_read(vcpu, VCPU_REGS_RAX);
	tss->ecx = kvm_register_read(vcpu, VCPU_REGS_RCX);
	tss->edx = kvm_register_read(vcpu, VCPU_REGS_RDX);
	tss->ebx = kvm_register_read(vcpu, VCPU_REGS_RBX);
	tss->esp = kvm_register_read(vcpu, VCPU_REGS_RSP);
	tss->ebp = kvm_register_read(vcpu, VCPU_REGS_RBP);
	tss->esi = kvm_register_read(vcpu, VCPU_REGS_RSI);
	tss->edi = kvm_register_read(vcpu, VCPU_REGS_RDI);
	tss->es = get_segment_selector(vcpu, VCPU_SREG_ES);
	tss->cs = get_segment_selector(vcpu, VCPU_SREG_CS);
	tss->ss = get_segment_selector(vcpu, VCPU_SREG_SS);
	tss->ds = get_segment_selector(vcpu, VCPU_SREG_DS);
	tss->fs = get_segment_selector(vcpu, VCPU_SREG_FS);
	tss->gs = get_segment_selector(vcpu, VCPU_SREG_GS);
	tss->ldt_selector = get_segment_selector(vcpu, VCPU_SREG_LDTR);
}

static void
kvm_load_segment_selector(struct kvm_vcpu *vcpu, uint16_t sel, int seg)
{
	struct kvm_segment kvm_seg;
	kvm_get_segment(vcpu, &kvm_seg, seg);
	kvm_seg.selector = sel;
	kvm_set_segment(vcpu, &kvm_seg, seg);
}

static int
load_state_from_tss32(struct kvm_vcpu *vcpu, struct tss_segment_32 *tss)
{
	kvm_set_cr3(vcpu, tss->cr3);

	kvm_rip_write(vcpu, tss->eip);
	kvm_set_rflags(vcpu, tss->eflags | 2);

	kvm_register_write(vcpu, VCPU_REGS_RAX, tss->eax);
	kvm_register_write(vcpu, VCPU_REGS_RCX, tss->ecx);
	kvm_register_write(vcpu, VCPU_REGS_RDX, tss->edx);
	kvm_register_write(vcpu, VCPU_REGS_RBX, tss->ebx);
	kvm_register_write(vcpu, VCPU_REGS_RSP, tss->esp);
	kvm_register_write(vcpu, VCPU_REGS_RBP, tss->ebp);
	kvm_register_write(vcpu, VCPU_REGS_RSI, tss->esi);
	kvm_register_write(vcpu, VCPU_REGS_RDI, tss->edi);

	/*
	 * SDM says that segment selectors are loaded before segment
	 * descriptors
	 */
	kvm_load_segment_selector(vcpu, tss->ldt_selector, VCPU_SREG_LDTR);
	kvm_load_segment_selector(vcpu, tss->es, VCPU_SREG_ES);
	kvm_load_segment_selector(vcpu, tss->cs, VCPU_SREG_CS);
	kvm_load_segment_selector(vcpu, tss->ss, VCPU_SREG_SS);
	kvm_load_segment_selector(vcpu, tss->ds, VCPU_SREG_DS);
	kvm_load_segment_selector(vcpu, tss->fs, VCPU_SREG_FS);
	kvm_load_segment_selector(vcpu, tss->gs, VCPU_SREG_GS);

	/*
	 * Now load segment descriptors. If fault happenes at this stage
	 * it is handled in a context of new task
	 */
	if (kvm_load_segment_descriptor(vcpu,
	    tss->ldt_selector, VCPU_SREG_LDTR))
		return (1);

	if (kvm_load_segment_descriptor(vcpu, tss->es, VCPU_SREG_ES))
		return (1);

	if (kvm_load_segment_descriptor(vcpu, tss->cs, VCPU_SREG_CS))
		return (1);

	if (kvm_load_segment_descriptor(vcpu, tss->ss, VCPU_SREG_SS))
		return (1);

	if (kvm_load_segment_descriptor(vcpu, tss->ds, VCPU_SREG_DS))
		return (1);

	if (kvm_load_segment_descriptor(vcpu, tss->fs, VCPU_SREG_FS))
		return (1);

	if (kvm_load_segment_descriptor(vcpu, tss->gs, VCPU_SREG_GS))
		return (1);

	return (0);
}

static void
save_state_to_tss16(struct kvm_vcpu *vcpu, struct tss_segment_16 *tss)
{
	tss->ip = kvm_rip_read(vcpu);
	tss->flag = kvm_get_rflags(vcpu);
	tss->ax = kvm_register_read(vcpu, VCPU_REGS_RAX);
	tss->cx = kvm_register_read(vcpu, VCPU_REGS_RCX);
	tss->dx = kvm_register_read(vcpu, VCPU_REGS_RDX);
	tss->bx = kvm_register_read(vcpu, VCPU_REGS_RBX);
	tss->sp = kvm_register_read(vcpu, VCPU_REGS_RSP);
	tss->bp = kvm_register_read(vcpu, VCPU_REGS_RBP);
	tss->si = kvm_register_read(vcpu, VCPU_REGS_RSI);
	tss->di = kvm_register_read(vcpu, VCPU_REGS_RDI);

	tss->es = get_segment_selector(vcpu, VCPU_SREG_ES);
	tss->cs = get_segment_selector(vcpu, VCPU_SREG_CS);
	tss->ss = get_segment_selector(vcpu, VCPU_SREG_SS);
	tss->ds = get_segment_selector(vcpu, VCPU_SREG_DS);
	tss->ldt = get_segment_selector(vcpu, VCPU_SREG_LDTR);
}

static int
load_state_from_tss16(struct kvm_vcpu *vcpu, struct tss_segment_16 *tss)
{
	kvm_rip_write(vcpu, tss->ip);
	kvm_set_rflags(vcpu, tss->flag | 2);
	kvm_register_write(vcpu, VCPU_REGS_RAX, tss->ax);
	kvm_register_write(vcpu, VCPU_REGS_RCX, tss->cx);
	kvm_register_write(vcpu, VCPU_REGS_RDX, tss->dx);
	kvm_register_write(vcpu, VCPU_REGS_RBX, tss->bx);
	kvm_register_write(vcpu, VCPU_REGS_RSP, tss->sp);
	kvm_register_write(vcpu, VCPU_REGS_RBP, tss->bp);
	kvm_register_write(vcpu, VCPU_REGS_RSI, tss->si);
	kvm_register_write(vcpu, VCPU_REGS_RDI, tss->di);

	/*
	 * SDM says that segment selectors are loaded before segment
	 * descriptors
	 */
	kvm_load_segment_selector(vcpu, tss->ldt, VCPU_SREG_LDTR);
	kvm_load_segment_selector(vcpu, tss->es, VCPU_SREG_ES);
	kvm_load_segment_selector(vcpu, tss->cs, VCPU_SREG_CS);
	kvm_load_segment_selector(vcpu, tss->ss, VCPU_SREG_SS);
	kvm_load_segment_selector(vcpu, tss->ds, VCPU_SREG_DS);

	/*
	 * Now load segment descriptors. If fault happenes at this stage
	 * it is handled in a context of new task
	 */
	if (kvm_load_segment_descriptor(vcpu, tss->ldt, VCPU_SREG_LDTR))
		return (1);

	if (kvm_load_segment_descriptor(vcpu, tss->es, VCPU_SREG_ES))
		return (1);

	if (kvm_load_segment_descriptor(vcpu, tss->cs, VCPU_SREG_CS))
		return (1);

	if (kvm_load_segment_descriptor(vcpu, tss->ss, VCPU_SREG_SS))
		return (1);

	if (kvm_load_segment_descriptor(vcpu, tss->ds, VCPU_SREG_DS))
		return (1);

	return (0);
}

int
kvm_read_guest(struct kvm *kvm, gpa_t gpa, void *data, unsigned long len)
{
	gfn_t gfn = gpa >> PAGESHIFT;
	int seg;
	int offset = offset_in_page(gpa);
	int ret;
	uintptr_t dp = (uintptr_t)data;

	while ((seg = next_segment(len, offset)) != 0) {
		ret = kvm_read_guest_page(kvm, gfn, (void *)dp, offset, seg);
		if (ret < 0)
			return (ret);
		offset = 0;
		len -= seg;
		dp += seg;
		++gfn;
	}
	return (0);
}

static gpa_t
get_tss_base_addr_write(struct kvm_vcpu *vcpu, struct desc_struct *seg_desc)
{
	uint32_t base_addr = get_desc_base(seg_desc);

	return (kvm_mmu_gva_to_gpa_write(vcpu, base_addr, NULL));
}

static gpa_t
get_tss_base_addr_read(struct kvm_vcpu *vcpu, struct desc_struct *seg_desc)
{
	uint32_t base_addr = get_desc_base(seg_desc);

	return (kvm_mmu_gva_to_gpa_read(vcpu, base_addr, NULL));
}

static int
kvm_task_switch_16(struct kvm_vcpu *vcpu, uint16_t tss_selector,
    uint16_t old_tss_sel, uint32_t old_tss_base, struct desc_struct *nseg_desc)
{
	struct tss_segment_16 tss_segment_16;
	int ret = 0;

	if (kvm_read_guest(vcpu->kvm, old_tss_base,
	    &tss_segment_16, sizeof (tss_segment_16)))
		goto out;

	save_state_to_tss16(vcpu, &tss_segment_16);

	if (kvm_write_guest(vcpu->kvm, old_tss_base,
	    &tss_segment_16, sizeof (tss_segment_16)))
		goto out;

	if (kvm_read_guest(vcpu->kvm, get_tss_base_addr_read(vcpu, nseg_desc),
	    &tss_segment_16, sizeof (tss_segment_16)))
		goto out;

	if (old_tss_sel != 0xffff) {
		tss_segment_16.prev_task_link = old_tss_sel;

		if (kvm_write_guest(vcpu->kvm, get_tss_base_addr_write(vcpu,
		    nseg_desc), &tss_segment_16.prev_task_link,
		    sizeof (tss_segment_16.prev_task_link)))
			goto out;
	}

	if (load_state_from_tss16(vcpu, &tss_segment_16))
		goto out;

	ret = 1;
out:
	return (ret);
}

static int
kvm_task_switch_32(struct kvm_vcpu *vcpu, uint16_t tss_selector,
    uint16_t old_tss_sel, uint32_t old_tss_base, struct desc_struct *nseg_desc)
{
	struct tss_segment_32 tss_segment_32;
	int ret = 0;

	if (kvm_read_guest(vcpu->kvm, old_tss_base,
	    &tss_segment_32, sizeof (tss_segment_32)))
		goto out;

	save_state_to_tss32(vcpu, &tss_segment_32);

	if (kvm_write_guest(vcpu->kvm, old_tss_base,
	    &tss_segment_32, sizeof (tss_segment_32)))
		goto out;

	if (kvm_read_guest(vcpu->kvm, get_tss_base_addr_read(vcpu, nseg_desc),
	    &tss_segment_32, sizeof (tss_segment_32)))
		goto out;

	if (old_tss_sel != 0xffff) {
		tss_segment_32.prev_task_link = old_tss_sel;

		if (kvm_write_guest(vcpu->kvm, get_tss_base_addr_write(vcpu,
		    nseg_desc), &tss_segment_32.prev_task_link,
		    sizeof (tss_segment_32.prev_task_link)))
			goto out;
	}

	if (load_state_from_tss32(vcpu, &tss_segment_32))
		goto out;

	ret = 1;
out:
	return (ret);
}

int
kvm_task_switch(struct kvm_vcpu *vcpu, uint16_t tss_selector, int reason)
{
	struct kvm_segment tr_seg;
	struct desc_struct cseg_desc;
	struct desc_struct nseg_desc;
	int ret = 0;
	uint32_t old_tss_base = get_segment_base(vcpu, VCPU_SREG_TR);
	uint16_t old_tss_sel = get_segment_selector(vcpu, VCPU_SREG_TR);
	uint32_t desc_limit;

	old_tss_base = kvm_mmu_gva_to_gpa_write(vcpu, old_tss_base, NULL);

	/*
	 * FIXME: Handle errors. Failure to read either TSS or their
	 * descriptors should generate a pagefault.
	 */
	if (load_guest_segment_descriptor(vcpu, tss_selector, &nseg_desc))
		goto out;

	if (load_guest_segment_descriptor(vcpu, old_tss_sel, &cseg_desc))
		goto out;

	if (reason != TASK_SWITCH_IRET) {
		int cpl;

		cpl = kvm_x86_ops->get_cpl(vcpu);
		if ((tss_selector & 3) > nseg_desc.c.b.dpl ||
		    cpl > nseg_desc.c.b.dpl) {
			kvm_queue_exception_e(vcpu, GP_VECTOR, 0);
			return (1);
		}
	}

	desc_limit = get_desc_limit(&nseg_desc);

	if (!nseg_desc.c.b.p || ((desc_limit < 0x67 &&
	    (nseg_desc.c.b.type & 8)) || desc_limit < 0x2b)) {
		kvm_queue_exception_e(vcpu, TS_VECTOR, tss_selector & 0xfffc);
		return (1);
	}

	if (reason == TASK_SWITCH_IRET || reason == TASK_SWITCH_JMP) {
		cseg_desc.c.b.type &= ~(1 << 1); // clear the B flag
		save_guest_segment_descriptor(vcpu, old_tss_sel, &cseg_desc);
	}

	if (reason == TASK_SWITCH_IRET) {
		uint32_t eflags = kvm_get_rflags(vcpu);
		kvm_set_rflags(vcpu, eflags & ~X86_EFLAGS_NT);
	}

	/*
	 * set back link to prev task only if NT bit is set in eflags
	 * note that old_tss_sel is not used afetr this point
	 */
	if (reason != TASK_SWITCH_CALL && reason != TASK_SWITCH_GATE)
		old_tss_sel = 0xffff;

	if (nseg_desc.c.b.type & 8) {
		ret = kvm_task_switch_32(vcpu, tss_selector, old_tss_sel,
		    old_tss_base, &nseg_desc);
	} else {
		ret = kvm_task_switch_16(vcpu, tss_selector, old_tss_sel,
		    old_tss_base, &nseg_desc);
	}

	if (reason == TASK_SWITCH_CALL || reason == TASK_SWITCH_GATE) {
		uint32_t eflags = kvm_get_rflags(vcpu);
		kvm_set_rflags(vcpu, eflags | X86_EFLAGS_NT);
	}

	if (reason != TASK_SWITCH_IRET) {
		nseg_desc.c.b.type |= (1 << 1);
		save_guest_segment_descriptor(vcpu, tss_selector, &nseg_desc);
	}

	kvm_x86_ops->set_cr0(vcpu, kvm_read_cr0(vcpu) | X86_CR0_TS);
	seg_desct_to_kvm_desct(&nseg_desc, tss_selector, &tr_seg);
	tr_seg.type = 11;
	kvm_set_segment(vcpu, &tr_seg, VCPU_SREG_TR);
out:
	return (ret);
}




void
kvm_guest_exit(void)
{
#ifdef XXX
	account_system_vtime(current);
	current->flags &= ~PF_VCPU;
#else
	XXX_KVM_PROBE;
#endif
}

void
kvm_guest_enter(void)
{
#ifdef XXX
	account_system_vtime(current);
	current->flags |= PF_VCPU;
#else
	XXX_KVM_PROBE;
#endif
}


/*
 * Often times we have pages that correspond to addresses that are in a users
 * virtual address space. Rather than trying to constantly map them in and out
 * of our address space we instead go through and use the kpm segment to
 * facilitate this for us. This always returns an address that is always in the
 * kernel's virtual address space.
 */
caddr_t
page_address(page_t *page)
{
	return (hat_kpm_mapin_pfn(page->p_pagenum));
}



static void
inject_pending_event(struct kvm_vcpu *vcpu)
{
	/* try to reinject previous events if any */
	if (vcpu->arch.exception.pending) {
		kvm_x86_ops->queue_exception(vcpu, vcpu->arch.exception.nr,
		    vcpu->arch.exception.has_error_code,
		    vcpu->arch.exception.error_code);
		return;
	}

	if (vcpu->arch.nmi_injected) {
		kvm_x86_ops->set_nmi(vcpu);
		return;
	}

	if (vcpu->arch.interrupt.pending) {
		kvm_x86_ops->set_irq(vcpu);
		return;
	}

	/* try to inject new event if pending */
	if (vcpu->arch.nmi_pending) {
		if (kvm_x86_ops->nmi_allowed(vcpu)) {
			vcpu->arch.nmi_pending = 0;
			vcpu->arch.nmi_injected = 1;
			kvm_x86_ops->set_nmi(vcpu);
		}
	} else if (kvm_cpu_has_interrupt(vcpu)) {
		if (kvm_x86_ops->interrupt_allowed(vcpu)) {
			kvm_queue_interrupt(vcpu, kvm_cpu_get_interrupt(vcpu),
					    0);
			kvm_x86_ops->set_irq(vcpu);
		}
	}
}

void
kvm_load_guest_fpu(struct kvm_vcpu *vcpu)
{
	if (vcpu->guest_fpu_loaded)
		return;

	vcpu->guest_fpu_loaded = 1;
	kvm_fx_save(&vcpu->arch.host_fx_image);
	kvm_fx_restore(&vcpu->arch.guest_fx_image);
	KVM_TRACE1(fpu, int, 1);
}

static inline unsigned long
native_get_debugreg(int regno)
{
	unsigned long val = 0;	/* Damn you, gcc! */

	switch (regno) {
	case 0:
		__asm__("mov %%db0, %0" :"=r" (val));
		break;
	case 1:
		__asm__("mov %%db1, %0" :"=r" (val));
		break;
	case 2:
		__asm__("mov %%db2, %0" :"=r" (val));
		break;
	case 3:
		__asm__("mov %%db3, %0" :"=r" (val));
		break;
	case 6:
		__asm__("mov %%db6, %0" :"=r" (val));
		break;
	case 7:
		__asm__("mov %%db7, %0" :"=r" (val));
		break;
	default:
		cmn_err(CE_WARN, "kvm: invalid debug register retrieval, "
		    "regno =  %d\n", regno);
	}

	return (val);
}

static inline void
native_set_debugreg(int regno, unsigned long value)
{
	switch (regno) {
	case 0:
		__asm__("mov %0, %%db0"	::"r" (value));
		break;
	case 1:
		__asm__("mov %0, %%db1"	::"r" (value));
		break;
	case 2:
		__asm__("mov %0, %%db2"	::"r" (value));
		break;
	case 3:
		__asm__("mov %0, %%db3"	::"r" (value));
		break;
	case 6:
		__asm__("mov %0, %%db6"	::"r" (value));
		break;
	case 7:
		__asm__("mov %0, %%db7"	::"r" (value));
		break;
	default:
		cmn_err(CE_WARN, "kvm: invalid debug register set, "
		    "regno =  %d\n", regno);
	}
}

static uint32_t
div_frac(uint32_t dividend, uint32_t divisor)
{
	uint32_t quotient, remainder;

	/*
	 * Don't try to replace with do_div(), this one calculates
	 * "(dividend << 32) / divisor"
	 */
	__asm__("divl %4"
		: "=a" (quotient), "=d" (remainder)
		: "0" (0), "1" (dividend), "r" (divisor));

	return (quotient);
}

static void
kvm_set_time_scale(uint32_t tsc_khz, struct pvclock_vcpu_time_info *hv_clock)
{
	uint64_t nsecs = 1000000000LL;
	int32_t  shift = 0;
	uint64_t tps64;
	uint32_t tps32;

	tps64 = tsc_khz * 1000LL;
	while (tps64 > nsecs*2) {
		tps64 >>= 1;
		shift--;
	}

	tps32 = (uint32_t)tps64;
	while (tps32 <= (uint32_t)nsecs) {
		tps32 <<= 1;
		shift++;
	}

	hv_clock->tsc_shift = shift;
	hv_clock->tsc_to_system_mul = div_frac(nsecs, tps32);
}

static void
kvm_write_guest_time(struct kvm_vcpu *v)
{
	struct timespec ts;
	unsigned long flags;
	struct kvm_vcpu_arch *vcpu = &v->arch;
	void *shared_kaddr;
	unsigned long this_tsc_khz;

	if ((!vcpu->time_page))
		return;

	this_tsc_khz = cpu_tsc_khz;
	if (vcpu->hv_clock_tsc_khz != this_tsc_khz) {
		kvm_set_time_scale(this_tsc_khz, &vcpu->hv_clock);
		vcpu->hv_clock_tsc_khz = this_tsc_khz;
	}

#ifdef XXX
	put_cpu_var(cpu_tsc_khz);
#else
	XXX_KVM_PROBE;
#endif

#ifdef XXX
	/* Keep irq disabled to prevent changes to the clock */
	local_irq_save(flags);
#else
	/*
	 * may need to mask interrupts for local_irq_save, and unmask
	 * for local_irq_restore.  cli()/sti() might be done...
	 */
	XXX_KVM_PROBE;
#endif
	kvm_get_msr(v, MSR_IA32_TSC, &vcpu->hv_clock.tsc_timestamp);
	gethrestime(&ts);
#ifdef XXX
	monotonic_to_bootbased(&ts);
	local_irq_restore(flags);
#else
	XXX_KVM_PROBE;
#endif

	/* With all the info we got, fill in the values */

	vcpu->hv_clock.system_time = ts.tv_nsec + (NSEC_PER_SEC *
	    (uint64_t)ts.tv_sec) + v->kvm->arch.kvmclock_offset;

	/*
	 * The interface expects us to write an even number signaling that the
	 * update is finished. Since the guest won't see the intermediate
	 * state, we just increase by 2 at the end.
	 */
	vcpu->hv_clock.version += 2;

	shared_kaddr = page_address(vcpu->time_page);

	memcpy((void *)((uintptr_t)shared_kaddr + vcpu->time_offset),
	    &vcpu->hv_clock, sizeof (vcpu->hv_clock));

	mark_page_dirty(v->kvm, vcpu->time >> PAGESHIFT);
}

/*
 * These special macros can be used to get or set a debugging register
 */
#define	get_debugreg(var, register)				\
	(var) = native_get_debugreg(register)
#define	set_debugreg(value, register)				\
	native_set_debugreg(register, value)

static int
vcpu_enter_guest(struct kvm_vcpu *vcpu)
{
	int r;

	int req_int_win = !irqchip_in_kernel(vcpu->kvm) &&
	    vcpu->run->request_interrupt_window;

	if (vcpu->requests) {
		if (test_and_clear_bit(KVM_REQ_MMU_RELOAD, &vcpu->requests))
			kvm_mmu_unload(vcpu);
	}

	r = kvm_mmu_reload(vcpu);

	if (r)
		goto out;

	if (vcpu->requests) {
		if (test_and_clear_bit(KVM_REQ_MIGRATE_TIMER,
		    &vcpu->requests)) {
			__kvm_migrate_timers(vcpu);
		}
		if (test_and_clear_bit(KVM_REQ_KVMCLOCK_UPDATE,
		    &vcpu->requests)) {
			kvm_write_guest_time(vcpu);
		}

		if (test_and_clear_bit(KVM_REQ_MMU_SYNC, &vcpu->requests))
			kvm_mmu_sync_roots(vcpu);

		if (test_and_clear_bit(KVM_REQ_TLB_FLUSH, &vcpu->requests))
			kvm_x86_ops->tlb_flush(vcpu);

		if (test_and_clear_bit(KVM_REQ_REPORT_TPR_ACCESS,
		    &vcpu->requests)) {
			vcpu->run->exit_reason = KVM_EXIT_TPR_ACCESS;
			r = 0;
			goto out;
		}

		if (test_and_clear_bit(KVM_REQ_TRIPLE_FAULT, &vcpu->requests)) {
			vcpu->run->exit_reason = KVM_EXIT_SHUTDOWN;
			r = 0;
			goto out;
		}

		if (test_and_clear_bit(KVM_REQ_DEACTIVATE_FPU,
		    &vcpu->requests)) {
			vcpu->fpu_active = 0;
			kvm_x86_ops->fpu_deactivate(vcpu);
		}
	}

	kpreempt_disable();

	kvm_x86_ops->prepare_guest_switch(vcpu);
	if (vcpu->fpu_active)
		kvm_load_guest_fpu(vcpu);

	cli();

	clear_bit(KVM_REQ_KICK, &vcpu->requests);
#ifdef XXX
	smp_mb__after_clear_bit();
#else
	XXX_KVM_PROBE;
#endif

	if (vcpu->requests || issig(JUSTLOOKING)) {
		set_bit(KVM_REQ_KICK, &vcpu->requests);
		sti();
		kpreempt_enable();
		r = 1;
		goto out;
	}

	inject_pending_event(vcpu);

	/* enable NMI/IRQ window open exits if needed */
	if (vcpu->arch.nmi_pending)
		kvm_x86_ops->enable_nmi_window(vcpu);
	else if (kvm_cpu_has_interrupt(vcpu) || req_int_win)
		kvm_x86_ops->enable_irq_window(vcpu);

	if (kvm_lapic_enabled(vcpu)) {
		update_cr8_intercept(vcpu);
		kvm_lapic_sync_to_vapic(vcpu);
	}
#ifdef XXX
	srcu_read_unlock(&vcpu->kvm->srcu, vcpu->srcu_idx);
#else
	XXX_KVM_PROBE;
#endif
	kvm_guest_enter();

	if (vcpu->arch.switch_db_regs) {
		set_debugreg(0, 7);
		set_debugreg(vcpu->arch.eff_db[0], 0);
		set_debugreg(vcpu->arch.eff_db[1], 1);
		set_debugreg(vcpu->arch.eff_db[2], 2);
		set_debugreg(vcpu->arch.eff_db[3], 3);
	}

	KVM_TRACE1(vm__entry, int, vcpu->vcpu_id);

	kvm_x86_ops->run(vcpu);
#ifdef XXX
	/*
	 * If the guest has used debug registers, at least dr7
	 * will be disabled while returning to the host.
	 * If we don't have active breakpoints in the host, we don't
	 * care about the messed up debug address registers. But if
	 * we have some of them active, restore the old state.
	 */
	if (hw_breakpoint_active())
		hw_breakpoint_restore();
#else
	XXX_KVM_PROBE;
#endif
	set_bit(KVM_REQ_KICK, &vcpu->requests);

	sti();

#ifdef XXX
	local_irq_enable();  /* XXX - should be ok with kpreempt_enable below */

	barrier();
#else
	XXX_KVM_PROBE;
#endif
	KVM_VCPU_KSTAT_INC(vcpu, kvmvs_exits);
	kvm_guest_exit();

	kpreempt_enable();
#ifdef XXX
	vcpu->srcu_idx = srcu_read_lock(&vcpu->kvm->srcu);

	/*
	 * Profile KVM exit RIPs:
	 */
	if (unlikely(prof_on == KVM_PROFILING)) {
		unsigned long rip = kvm_rip_read(vcpu);
		profile_hit(KVM_PROFILING, (void *)rip);
	}
#else
	XXX_KVM_PROBE;
#endif
	kvm_lapic_sync_from_vapic(vcpu);
	r = kvm_x86_ops->handle_exit(vcpu);

out:
	return (r);
}


static void
post_kvm_run_save(struct kvm_vcpu *vcpu)
{
	struct kvm_run *kvm_run = vcpu->run;

	kvm_run->if_flag = (kvm_get_rflags(vcpu) & X86_EFLAGS_IF) != 0;
	kvm_run->cr8 = kvm_get_cr8(vcpu);
	kvm_run->apic_base = kvm_get_apic_base(vcpu);
	if (irqchip_in_kernel(vcpu->kvm))
		kvm_run->ready_for_interrupt_injection = 1;
	else
		kvm_run->ready_for_interrupt_injection =
			kvm_arch_interrupt_allowed(vcpu) &&
			!kvm_cpu_has_interrupt(vcpu) &&
			!kvm_event_needs_reinjection(vcpu);
}

/*
 * The vCPU has executed a HLT instruction with in-kernel mode enabled.
 */
void
kvm_vcpu_block(struct kvm_vcpu *vcpu)
{
	for (;;) {
		if (kvm_arch_vcpu_runnable(vcpu)) {
			set_bit(KVM_REQ_UNHALT, &vcpu->requests);
			break;
		}

		if (issig(JUSTLOOKING))
			break;

		mutex_enter(&vcpu->kvcpu_kick_lock);

		if (kvm_cpu_has_pending_timer(vcpu)) {
			mutex_exit(&vcpu->kvcpu_kick_lock);
			break;
		}

		(void) cv_wait_sig_swap(&vcpu->kvcpu_kick_cv,
		    &vcpu->kvcpu_kick_lock);

		mutex_exit(&vcpu->kvcpu_kick_lock);
	}
}

void
kvm_vcpu_kick(struct kvm_vcpu *vcpu)
{
	processorid_t cpu = vcpu->cpu;

	mutex_enter(&vcpu->kvcpu_kick_lock);

	if (CV_HAS_WAITERS(&vcpu->kvcpu_kick_cv))
		KVM_VCPU_KSTAT_INC(vcpu, kvmvs_halt_wakeup);

	cv_broadcast(&vcpu->kvcpu_kick_cv);
	mutex_exit(&vcpu->kvcpu_kick_lock);

	if (cpu != CPU->cpu_id && cpu != -1) {
		if (!test_and_set_bit(KVM_REQ_KICK, &vcpu->requests)) {
			/*
			 * If we haven't already kicked this VCPU, we'll poke
			 * the the CPU on which it's running.  (This will serve
			 * to induce a VM exit.)
			 */
			poke_cpu(cpu);
		}
	}
}

static void
vapic_enter(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;
	page_t *page;

	if (!apic || !apic->vapic_addr)
		return;

	page = gfn_to_page(vcpu->kvm, apic->vapic_addr >> PAGESHIFT);

	vcpu->arch.apic->vapic_page = page;
}

static void
vapic_exit(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;
	int idx;

	if (!apic || !apic->vapic_addr)
		return;
#ifdef XXX
	idx = srcu_read_lock(&vcpu->kvm->srcu);
#else
	XXX_KVM_SYNC_PROBE;
#endif
	kvm_release_page_dirty(apic->vapic_page);
	mark_page_dirty(vcpu->kvm, apic->vapic_addr >> PAGESHIFT);
#ifdef XXX
	srcu_read_unlock(&vcpu->kvm->srcu, idx);
#else
	XXX_KVM_SYNC_PROBE;
#endif
}

static int
dm_request_for_irq_injection(struct kvm_vcpu *vcpu)
{
	return (!irqchip_in_kernel(vcpu->kvm) &&
	    !kvm_cpu_has_interrupt(vcpu) &&
	    vcpu->run->request_interrupt_window &&
	    kvm_arch_interrupt_allowed(vcpu));
}

static int
__vcpu_run(struct kvm_vcpu *vcpu)
{
	int r;
	struct kvm *kvm = vcpu->kvm;

	if (vcpu->arch.mp_state == KVM_MP_STATE_SIPI_RECEIVED) {
		cmn_err(CE_NOTE, "vcpu %d received sipi with vector # %x\n",
		    vcpu->vcpu_id, vcpu->arch.sipi_vector);
		kvm_lapic_reset(vcpu);
		r = kvm_arch_vcpu_reset(vcpu);
		if (r)
			return (r);
		vcpu->arch.mp_state = KVM_MP_STATE_RUNNABLE;
	}

#ifdef XXX
	vcpu->srcu_idx = srcu_read_lock(&kvm->srcu);
#else
	XXX_KVM_SYNC_PROBE;
#endif
	vapic_enter(vcpu);

	r = 1;
	while (r > 0) {
		if (vcpu->arch.mp_state == KVM_MP_STATE_RUNNABLE)
			r = vcpu_enter_guest(vcpu);
		else {
#ifdef XXX
			srcu_read_unlock(&kvm->srcu, vcpu->srcu_idx);
#else
			XXX_KVM_SYNC_PROBE;
#endif
			kvm_vcpu_block(vcpu);
#ifdef XXX
			vcpu->srcu_idx = srcu_read_lock(&kvm->srcu);
#else
			XXX_KVM_SYNC_PROBE;
#endif
			if (test_and_clear_bit(KVM_REQ_UNHALT,
			    &vcpu->requests)) {
				switch (vcpu->arch.mp_state) {
				case KVM_MP_STATE_HALTED:
					vcpu->arch.mp_state =
					    KVM_MP_STATE_RUNNABLE;
				case KVM_MP_STATE_RUNNABLE:
					break;
				case KVM_MP_STATE_SIPI_RECEIVED:
				default:
					r = -EINTR;
					break;
				}
			}
		}

		if (r <= 0)
			break;

		clear_bit(KVM_REQ_PENDING_TIMER, &vcpu->requests);
		if (kvm_cpu_has_pending_timer(vcpu))
			kvm_inject_pending_timer_irqs(vcpu);

		if (dm_request_for_irq_injection(vcpu)) {
			r = -EINTR;
			vcpu->run->exit_reason = KVM_EXIT_INTR;
			KVM_VCPU_KSTAT_INC(vcpu, kvmvs_irq_exits);
		}

		if (issig(JUSTLOOKING)) {
			r = -EINTR;
			vcpu->run->exit_reason = KVM_EXIT_INTR;
			KVM_VCPU_KSTAT_INC(vcpu, kvmvs_signal_exits);
		}
	}
#ifdef XXX
	srcu_read_unlock(&kvm->srcu, vcpu->srcu_idx);
#else
	XXX_KVM_SYNC_PROBE;
#endif
	post_kvm_run_save(vcpu);
	vapic_exit(vcpu);

	return (r);
}

int
kvm_arch_vcpu_ioctl_run(struct kvm_vcpu *vcpu)
{
	int r;
	sigset_t sigsaved;
	struct kvm_run *kvm_run = vcpu->run;

	vcpu_load(vcpu);

	if (vcpu->sigset_active)
		kvm_sigprocmask(SIG_SETMASK, &vcpu->sigset, &sigsaved);

	if (vcpu->arch.mp_state == KVM_MP_STATE_UNINITIALIZED) {
		kvm_vcpu_block(vcpu);
		clear_bit(KVM_REQ_UNHALT, &vcpu->requests);
		r = -EAGAIN;
		goto out;
	}

	/* re-sync apic's tpr */
	if (!irqchip_in_kernel(vcpu->kvm))
		kvm_set_cr8(vcpu, kvm_run->cr8);

	if (vcpu->arch.pio.cur_count) {
#ifdef XXX
		vcpu->srcu_idx = srcu_read_lock(&vcpu->kvm->srcu);
#else
		XXX_KVM_SYNC_PROBE;
#endif
		r = complete_pio(vcpu);
#ifdef XXX
		srcu_read_unlock(&vcpu->kvm->srcu, vcpu->srcu_idx);
#else
		XXX_KVM_SYNC_PROBE;
#endif
		if (r)
			goto out;
	}
	if (vcpu->mmio_needed) {
		memcpy(vcpu->mmio_data, kvm_run->mmio.data, 8);
		vcpu->mmio_read_completed = 1;
		vcpu->mmio_needed = 0;
#ifdef XXX
		vcpu->srcu_idx = srcu_read_lock(&vcpu->kvm->srcu);
#else
		XXX_KVM_SYNC_PROBE;
#endif
		r = emulate_instruction(vcpu, vcpu->arch.mmio_fault_cr2, 0,
					EMULTYPE_NO_DECODE);
#ifdef XXX
		srcu_read_unlock(&vcpu->kvm->srcu, vcpu->srcu_idx);
#else
		XXX_KVM_SYNC_PROBE;
#endif
		if (r == EMULATE_DO_MMIO) {
			/*
			 * Read-modify-write.  Back to userspace.
			 */
			r = 0;
			goto out;
		}
	}

	if (kvm_run->exit_reason == KVM_EXIT_HYPERCALL)
		kvm_register_write(vcpu, VCPU_REGS_RAX, kvm_run->hypercall.ret);

	r = __vcpu_run(vcpu);

out:
	if (vcpu->sigset_active)
		kvm_sigprocmask(SIG_SETMASK, &sigsaved, NULL);

	vcpu_put(vcpu);
	return (r);
}

int
kvm_arch_vcpu_ioctl_get_mpstate(struct kvm_vcpu *vcpu,
    struct kvm_mp_state *mp_state)
{
	vcpu_load(vcpu);
	mp_state->mp_state = vcpu->arch.mp_state;
	vcpu_put(vcpu);
	return (0);
}

int
kvm_arch_vcpu_ioctl_set_mpstate(struct kvm_vcpu *vcpu,
    struct kvm_mp_state *mp_state)
{
	vcpu_load(vcpu);
	vcpu->arch.mp_state = mp_state->mp_state;
	vcpu_put(vcpu);
	return (0);
}

static int
kvm_vcpu_ioctl_x86_get_vcpu_events(struct kvm_vcpu *vcpu,
    struct kvm_vcpu_events *events)
{
	vcpu_load(vcpu);

	events->exception.injected = vcpu->arch.exception.pending;
	events->exception.nr = vcpu->arch.exception.nr;
	events->exception.has_error_code = vcpu->arch.exception.has_error_code;
	events->exception.error_code = vcpu->arch.exception.error_code;

	events->interrupt.injected = vcpu->arch.interrupt.pending;
	events->interrupt.nr = vcpu->arch.interrupt.nr;
	events->interrupt.soft = vcpu->arch.interrupt.soft;

	events->nmi.injected = vcpu->arch.nmi_injected;
	events->nmi.pending = vcpu->arch.nmi_pending;
	events->nmi.masked = kvm_x86_ops->get_nmi_mask(vcpu);

	events->sipi_vector = vcpu->arch.sipi_vector;

	events->flags = (KVM_VCPUEVENT_VALID_NMI_PENDING |
	    KVM_VCPUEVENT_VALID_SIPI_VECTOR);

	vcpu_put(vcpu);

	return (0);
}

static int
kvm_vcpu_ioctl_x86_set_vcpu_events(struct kvm_vcpu *vcpu,
    struct kvm_vcpu_events *events)
{
	if (events->flags & ~(KVM_VCPUEVENT_VALID_NMI_PENDING |
	    KVM_VCPUEVENT_VALID_SIPI_VECTOR))
		return (-EINVAL);

	vcpu_load(vcpu);

	vcpu->arch.exception.pending = events->exception.injected;
	vcpu->arch.exception.nr = events->exception.nr;
	vcpu->arch.exception.has_error_code = events->exception.has_error_code;
	vcpu->arch.exception.error_code = events->exception.error_code;

	vcpu->arch.interrupt.pending = events->interrupt.injected;
	vcpu->arch.interrupt.nr = events->interrupt.nr;
	vcpu->arch.interrupt.soft = events->interrupt.soft;

	if (vcpu->arch.interrupt.pending && irqchip_in_kernel(vcpu->kvm))
		kvm_pic_clear_isr_ack(vcpu->kvm);

	vcpu->arch.nmi_injected = events->nmi.injected;

	if (events->flags & KVM_VCPUEVENT_VALID_NMI_PENDING)
		vcpu->arch.nmi_pending = events->nmi.pending;

	kvm_x86_ops->set_nmi_mask(vcpu, events->nmi.masked);

	if (events->flags & KVM_VCPUEVENT_VALID_SIPI_VECTOR)
		vcpu->arch.sipi_vector = events->sipi_vector;

	vcpu_put(vcpu);

	return (0);
}

extern void kvm_vcpu_kick(struct kvm_vcpu *vcpu);

static int
kvm_vm_ioctl_set_identity_map_addr(struct kvm *kvm, uint64_t ident_addr)
{
	kvm->arch.ept_identity_map_addr = ident_addr;
	return (0);
}

void
kvm_timer_fire(void *arg)
{
	struct kvm_timer *timer = (struct kvm_timer *)arg;
	struct kvm_vcpu *vcpu = timer->vcpu;

	if (vcpu == NULL)
		return;

	mutex_enter(&vcpu->kvcpu_kick_lock);

	if (timer->reinject || !timer->pending) {
		atomic_add_32(&timer->pending, 1);
		set_bit(KVM_REQ_PENDING_TIMER, &vcpu->requests);
	}

	timer->intervals++;

	cv_broadcast(&vcpu->kvcpu_kick_cv);
	mutex_exit(&vcpu->kvcpu_kick_lock);
}



static int
kvm_vcpu_ioctl_get_lapic(struct kvm_vcpu *vcpu, struct kvm_lapic_state *s)
{
	vcpu_load(vcpu);
	bcopy(vcpu->arch.apic->regs, s->regs, sizeof (*s));
	vcpu_put(vcpu);

	return (0);
}

static int
kvm_vcpu_ioctl_set_lapic(struct kvm_vcpu *vcpu, struct kvm_lapic_state *s)
{
	vcpu_load(vcpu);
	bcopy(s->regs, vcpu->arch.apic->regs, sizeof (*s));
	kvm_apic_post_state_restore(vcpu);
	update_cr8_intercept(vcpu);
	vcpu_put(vcpu);

	return (0);
}

static int
kvm_vm_ioctl_get_irqchip(struct kvm *kvm, struct kvm_irqchip *chip)
{
	int r;

	r = 0;
	switch (chip->chip_id) {
	case KVM_IRQCHIP_PIC_MASTER:
		memcpy(&chip->chip.pic, &pic_irqchip(kvm)->pics[0],
		    sizeof (struct kvm_pic_state));
		break;
	case KVM_IRQCHIP_PIC_SLAVE:
		memcpy(&chip->chip.pic, &pic_irqchip(kvm)->pics[1],
		    sizeof (struct kvm_pic_state));
		break;
	case KVM_IRQCHIP_IOAPIC:
		r = kvm_get_ioapic(kvm, &chip->chip.ioapic);
		break;
	default:
		r = EINVAL;
		break;
	}

	return (r);
}

static int
kvm_vm_ioctl_set_irqchip(struct kvm *kvm, struct kvm_irqchip *chip)
{
	int r;

	r = 0;

	switch (chip->chip_id) {
	case KVM_IRQCHIP_PIC_MASTER:
		mutex_enter(&pic_irqchip(kvm)->lock);
		memcpy(&pic_irqchip(kvm)->pics[0], &chip->chip.pic,
		    sizeof (struct kvm_pic_state));
		mutex_exit(&pic_irqchip(kvm)->lock);
		break;
	case KVM_IRQCHIP_PIC_SLAVE:
		mutex_enter(&pic_irqchip(kvm)->lock);
		memcpy(&pic_irqchip(kvm)->pics[1], &chip->chip.pic,
		    sizeof (struct kvm_pic_state));
		mutex_exit(&pic_irqchip(kvm)->lock);
		break;
	case KVM_IRQCHIP_IOAPIC:
		r = kvm_set_ioapic(kvm, &chip->chip.ioapic);
		break;
	default:
		r = EINVAL;
		break;
	}

	kvm_pic_update_irq(pic_irqchip(kvm));

	return (r);
}


static int
kvm_vcpu_ioctl_interrupt(struct kvm_vcpu *vcpu, struct kvm_interrupt *irq)
{
	if (irq->irq < 0 || irq->irq >= 256)
		return (-EINVAL);

	if (irqchip_in_kernel(vcpu->kvm))
		return (-ENXIO);

	vcpu_load(vcpu);

	kvm_queue_interrupt(vcpu, irq->irq, 0);

	vcpu_put(vcpu);

	return (0);
}

static int
kvm_vcpu_ioctl_x86_setup_mce(struct kvm_vcpu *vcpu, uint64_t *mcg_capp)
{
	int rval;
	uint64_t mcg_cap = *mcg_capp;
	unsigned bank_num = mcg_cap & 0xff, bank;

	rval = -EINVAL;
	if (!bank_num || bank_num >= KVM_MAX_MCE_BANKS)
		goto out;
	if (mcg_cap & ~(KVM_MCE_CAP_SUPPORTED | 0xff | 0xff0000))
		goto out;
	rval = 0;
	vcpu->arch.mcg_cap = mcg_cap;
	/* Init IA32_MCG_CTL to all 1s */
	if (mcg_cap & MCG_CTL_P)
		vcpu->arch.mcg_ctl = ~(uint64_t)0;
	/* Init IA32_MCi_CTL to all 1s */
	for (bank = 0; bank < bank_num; bank++)
		vcpu->arch.mce_banks[bank*4] = ~(uint64_t)0;
out:
	return (rval);
}

static int
kvm_vcpu_ioctl_set_sigmask(struct kvm_vcpu *vcpu, sigset_t *sigset)
{
	if (sigset) {
		vcpu->sigset_active = 1;
		vcpu->sigset = *sigset;
	} else
		vcpu->sigset_active = 0;

	return (0);
}

static int
kvm_vcpu_ioctl_get_msrs(struct kvm_vcpu *vcpu, struct kvm_msrs *msrs, int *rv)
{
	int r;

	if (msrs->nmsrs >= MAX_IO_MSRS)
		return (-E2BIG);

	if ((r = __msr_io(vcpu, msrs, msrs->entries, kvm_get_msr)) < 0)
		return (r);

	*rv = r;

	return (0);
}

static int
kvm_vcpu_ioctl_set_msrs(struct kvm_vcpu *vcpu, struct kvm_msrs *msrs, int *rv)
{
	int r;

	if (msrs->nmsrs >= MAX_IO_MSRS)
		return (-E2BIG);

	if ((r = __msr_io(vcpu, msrs, msrs->entries, do_set_msr)) < 0)
		return (-EINVAL);

	*rv = r;

	return (0);
}

/*
 * Get (and clear) the dirty memory log for a memory slot.
 */
int
kvm_vm_ioctl_get_dirty_log(struct kvm *kvm, struct kvm_dirty_log *log)
{
	int r, i;
	struct kvm_memory_slot *memslot;
	unsigned long n;
	unsigned long is_dirty = 0;
	unsigned long *dirty_bitmap = NULL;

	mutex_enter(&kvm->slots_lock);

	r = EINVAL;
	if (log->slot >= KVM_MEMORY_SLOTS)
		goto out;

	memslot = &kvm->memslots->memslots[log->slot];
	r = ENOENT;
	if (!memslot->dirty_bitmap)
		goto out;

	n = kvm_dirty_bitmap_bytes(memslot);

	dirty_bitmap = kmem_alloc(n, KM_SLEEP);
	memset(dirty_bitmap, 0, n);

	for (i = 0; !is_dirty && i < n / sizeof (long); i++)
		is_dirty = memslot->dirty_bitmap[i];

	/* If nothing is dirty, don't bother messing with page tables. */
	if (is_dirty) {
		struct kvm_memslots *slots, *old_slots;

		mutex_enter(&kvm->mmu_lock);
		kvm_mmu_slot_remove_write_access(kvm, log->slot);
		mutex_exit(&kvm->mmu_lock);

		slots = kmem_zalloc(sizeof (struct kvm_memslots), KM_SLEEP);
		if (!slots)
			goto out_free;

		memcpy(slots, kvm->memslots, sizeof (struct kvm_memslots));
		slots->memslots[log->slot].dirty_bitmap = dirty_bitmap;

		old_slots = kvm->memslots;
#ifdef XXX
		rcu_assign_pointer(kvm->memslots, slots);
		kvm_synchronize_srcu_expedited(&kvm->srcu);
#else
		kvm->memslots = slots;
		XXX_KVM_SYNC_PROBE;
#endif
		dirty_bitmap = old_slots->memslots[log->slot].dirty_bitmap;
		kmem_free(old_slots, sizeof (struct kvm_memslots));
	}

	r = 0;
	if (copyout(dirty_bitmap, log->v.dirty_bitmap, n) != 0)
		r = EFAULT;
out_free:
	kmem_free(dirty_bitmap, n);
out:
	mutex_exit(&kvm->slots_lock);
	return (r);
}

static int
kvm_vm_ioctl_get_pit2(struct kvm *kvm, struct kvm_pit_state2 *ps)
{
	struct kvm_pit *vpit = kvm->arch.vpit;

	mutex_enter(&vpit->pit_state.lock);
	memcpy(ps->channels, &vpit->pit_state.channels, sizeof (ps->channels));
	ps->flags = vpit->pit_state.flags;
	mutex_exit(&vpit->pit_state.lock);

	return (0);
}

static int
kvm_vm_ioctl_set_pit2(struct kvm *kvm, struct kvm_pit_state2 *ps)
{
	boolean_t prev_legacy, cur_legacy, start = B_FALSE;
	struct kvm_pit *vpit = kvm->arch.vpit;

	mutex_enter(&vpit->pit_state.lock);
	prev_legacy = vpit->pit_state.flags & KVM_PIT_FLAGS_HPET_LEGACY;
	cur_legacy = ps->flags & KVM_PIT_FLAGS_HPET_LEGACY;

	if (!prev_legacy && cur_legacy)
		start = B_TRUE;

	memcpy(&vpit->pit_state.channels, &ps->channels,
	    sizeof (vpit->pit_state.channels));

	vpit->pit_state.flags = ps->flags;
	kvm_pit_load_count(kvm, 0, vpit->pit_state.channels[0].count, start);

	mutex_exit(&vpit->pit_state.lock);

	return (0);
}

static int
kvm_ioctl(dev_t dev, int cmd, intptr_t arg, int md, cred_t *cr, int *rv)
{
	int rval = DDI_SUCCESS;
	minor_t minor;
	kvm_devstate_t *ksp;
	void *argp = (void *)arg;

	minor = getminor(dev);
	ksp = ddi_get_soft_state(kvm_state, minor);
	if (ksp == NULL)
		return (ENXIO);

	union {
		struct kvm_pit_state ps;
		struct kvm_pit_state2 ps2;
#ifdef XXX_KVM_DECLARATION
		struct kvm_memory_alias alias;
#endif
		struct kvm_pit_config pit_config;
	} u;

	struct {
		int cmd;		/* command */
		void *func;		/* function to call */
		size_t size;		/* size of user-level structure */
		boolean_t copyout;	/* boolean: copy out after func */
		boolean_t vmwide;	/* boolean: ioctl is not per-VCPU */
	} *ioctl, ioctltab[] = {
		{ KVM_RUN, kvm_arch_vcpu_ioctl_run },
		{ KVM_X86_SETUP_MCE, kvm_vcpu_ioctl_x86_setup_mce,
		    sizeof (uint64_t) },
		{ KVM_GET_MSRS, kvm_vcpu_ioctl_get_msrs,
		    sizeof (struct kvm_msrs), B_TRUE },
		{ KVM_SET_MSRS, kvm_vcpu_ioctl_set_msrs,
		    sizeof (struct kvm_msrs) },
		{ KVM_GET_MP_STATE, kvm_arch_vcpu_ioctl_get_mpstate,
		    sizeof (struct kvm_mp_state), B_TRUE },
		{ KVM_SET_MP_STATE, kvm_arch_vcpu_ioctl_set_mpstate,
		    sizeof (struct kvm_mp_state) },
		{ KVM_GET_REGS, kvm_arch_vcpu_ioctl_get_regs,
		    sizeof (struct kvm_regs), B_TRUE },
		{ KVM_SET_REGS, kvm_arch_vcpu_ioctl_set_regs,
		    sizeof (struct kvm_regs) },
		{ KVM_GET_SREGS, kvm_arch_vcpu_ioctl_get_sregs,
		    sizeof (struct kvm_sregs), B_TRUE },
		{ KVM_SET_SREGS, kvm_arch_vcpu_ioctl_set_sregs,
		    sizeof (struct kvm_sregs) },
		{ KVM_GET_FPU, kvm_arch_vcpu_ioctl_get_fpu,
		    sizeof (struct kvm_fpu), B_TRUE },
		{ KVM_SET_FPU, kvm_arch_vcpu_ioctl_set_fpu,
		    sizeof (struct kvm_fpu) },
		{ KVM_GET_CPUID2, kvm_vcpu_ioctl_get_cpuid2,
		    sizeof (struct kvm_cpuid2), B_TRUE },
		{ KVM_SET_CPUID2, kvm_vcpu_ioctl_set_cpuid2,
		    sizeof (struct kvm_cpuid2) },
		{ KVM_GET_LAPIC, kvm_vcpu_ioctl_get_lapic,
		    sizeof (struct kvm_lapic_state), B_TRUE },
		{ KVM_SET_LAPIC, kvm_vcpu_ioctl_set_lapic,
		    sizeof (struct kvm_lapic_state) },
		{ KVM_GET_VCPU_EVENTS, kvm_vcpu_ioctl_x86_get_vcpu_events,
		    sizeof (struct kvm_vcpu_events), B_TRUE },
		{ KVM_SET_VCPU_EVENTS, kvm_vcpu_ioctl_x86_set_vcpu_events,
		    sizeof (struct kvm_vcpu_events) },
		{ KVM_INTERRUPT, kvm_vcpu_ioctl_interrupt,
		    sizeof (struct kvm_interrupt) },
		{ KVM_SET_VAPIC_ADDR, kvm_lapic_set_vapic_addr,
		    sizeof (struct kvm_vapic_addr) },
		{ KVM_GET_PIT2, kvm_vm_ioctl_get_pit2,
		    sizeof (struct kvm_pit_state2), B_TRUE, B_TRUE },
		{ KVM_SET_PIT2, kvm_vm_ioctl_set_pit2,
		    sizeof (struct kvm_pit_state2), B_FALSE, B_TRUE },
		{ 0, NULL }
	};

	for (ioctl = &ioctltab[0]; ioctl->func != NULL; ioctl++) {
		caddr_t buf = NULL;

		if (ioctl->cmd != cmd)
			continue;

		if (ioctl->size != 0) {
			buf = kmem_alloc(ioctl->size, KM_SLEEP);

			if (copyin(argp, buf, ioctl->size) != 0) {
				kmem_free(buf, ioctl->size);
				return (EFAULT);
			}
		}

		if (ioctl->vmwide) {
			kvm_t *kvmp;
			int (*func)(kvm_t *, void *, int *);

			if ((kvmp = ksp->kds_kvmp) == NULL) {
				kmem_free(buf, ioctl->size);
				return (EINVAL);
			}

			func = (int(*)(kvm_t *, void *, int *))ioctl->func;
			rval = func(kvmp, buf, rv);
		} else {
			kvm_vcpu_t *vcpu;
			int (*func)(kvm_vcpu_t *, void *, int *);

			if ((vcpu = ksp->kds_vcpu) == NULL) {
				kmem_free(buf, ioctl->size);
				return (EINVAL);
			}

			func = (int(*)(kvm_vcpu_t *, void *, int *))ioctl->func;
			rval = func(vcpu, buf, rv);
		}

		if (rval == 0 && ioctl->size != 0 && ioctl->copyout) {
			if (copyout(buf, argp, ioctl->size) != 0) {
				kmem_free(buf, ioctl->size);
				return (EFAULT);
			}
		}

		kmem_free(buf, ioctl->size);

		return (rval < 0 ? -rval : rval);
	}

	switch (cmd) {
	case KVM_GET_API_VERSION:
		if (arg != NULL) {
			rval = EINVAL;
			break;
		}
		*rv = KVM_API_VERSION;
		break;

	case KVM_CREATE_VM:
		if (arg != NULL) {
			rval = EINVAL;
			break;
		}

		rval = kvm_dev_ioctl_create_vm(ksp, arg, rv);
		break;

	case KVM_CLONE: {
		dev_t parent = arg;
		kvm_devstate_t *clone;
		struct kvm *kvmp;

		/*
		 * We are not allowed to clone another open if we have created
		 * a virtual machine or virtual CPU with this open.
		 */
		if (ksp->kds_kvmp != NULL || ksp->kds_vcpu != NULL) {
			rval = EBUSY;
			break;
		}

		if (getmajor(parent) != getmajor(dev)) {
			rval = ENODEV;
			break;
		}

		minor = getminor(parent);

		mutex_enter(&kvm_lock);

		if ((clone = ddi_get_soft_state(kvm_state, minor)) == NULL) {
			mutex_exit(&kvm_lock);
			rval = EINVAL;
			break;
		}

		if ((kvmp = clone->kds_kvmp) == NULL) {
			mutex_exit(&kvm_lock);
			rval = ESRCH;
			break;
		}

		kvmp->kvm_clones++;
		ksp->kds_kvmp = kvmp;

		mutex_exit(&kvm_lock);
		break;
	}

	case KVM_CHECK_EXTENSION:
		rval = kvm_dev_ioctl_check_extension_generic(arg, rv);
		break;

	case KVM_GET_VCPU_MMAP_SIZE:
		if (arg != NULL) {
			rval = EINVAL;
			break;
		}
		*rv = ptob(KVM_VCPU_MMAP_LENGTH);
		break;

	case KVM_CREATE_PIT2:
		if (copyin(argp, &u.pit_config,
		    sizeof (struct kvm_pit_config)) != 0) {
			rval = EFAULT;
			break;
		}
		/*FALLTHROUGH*/

	case KVM_CREATE_PIT: {
		struct kvm *kvmp;

		if ((kvmp = ksp->kds_kvmp) == NULL) {
			rval = EINVAL;
			break;
		}

		if (cmd == KVM_CREATE_PIT) {
			u.pit_config.flags = KVM_PIT_SPEAKER_DUMMY;
		} else {
			ASSERT(cmd == KVM_CREATE_PIT2);
		}

		mutex_enter(&kvmp->slots_lock);

		if (kvmp->arch.vpit != NULL) {
			rval = EEXIST;
		} else if ((kvmp->arch.vpit = kvm_create_pit(kvmp,
		    u.pit_config.flags)) == NULL) {
			rval = ENOMEM;
		}

		mutex_exit(&kvmp->slots_lock);
		break;
	}

	case KVM_CREATE_IRQCHIP: {
		struct kvm_pic *vpic;
		struct kvm *kvmp;

		if ((kvmp = ksp->kds_kvmp) == NULL) {
			rval = EINVAL;
			break;
		}

		mutex_enter(&kvmp->lock);
		rval = EEXIST;
		if (kvmp->arch.vpic)
			goto create_irqchip_unlock;
		rval = ENOMEM;
		vpic = kvm_create_pic(kvmp);
		if (vpic) {
			rval = kvm_ioapic_init(kvmp);
			if (rval) {
				kvm_io_bus_unregister_dev(kvmp,
				    KVM_PIO_BUS, &vpic->dev);
				goto create_irqchip_unlock;
			}
		} else
			goto create_irqchip_unlock;
#ifdef XXX
		smp_wmb();
#else
		XXX_KVM_SYNC_PROBE;
#endif
		kvmp->arch.vpic = vpic;
#ifdef XXX
		smp_wmb();
#else
		XXX_KVM_SYNC_PROBE;
#endif
		rval = kvm_setup_default_irq_routing(kvmp);
		if (rval) {
			mutex_enter(&kvmp->irq_lock);
			kvm_ioapic_destroy(kvmp);
			kvm_destroy_pic(kvmp);
			mutex_exit(&kvmp->irq_lock);
		}
	create_irqchip_unlock:
		mutex_exit(&kvmp->lock);
		break;
	}

	case KVM_X86_GET_MCE_CAP_SUPPORTED: {
		uint64_t mce_cap = KVM_MCE_CAP_SUPPORTED;

		if (copyout(&mce_cap, argp, sizeof (mce_cap)))
			rval = EFAULT;

		break;
	}

	case KVM_SET_IDENTITY_MAP_ADDR: {
		kvm_id_map_addr_ioc_t *kvm_id_map_addr_ioc;
		size_t sz = sizeof (kvm_id_map_addr_ioc_t);
		struct kvm *kvmp;

		kvm_id_map_addr_ioc = kmem_zalloc(sz, KM_SLEEP);

		if (copyin(argp, kvm_id_map_addr_ioc, sz) != 0) {
			kmem_free(kvm_id_map_addr_ioc, sz);
			rval = EFAULT;
			break;
		}

		if ((kvmp = ksp->kds_kvmp) == NULL) {
			kmem_free(kvm_id_map_addr_ioc, sz);
			rval = EINVAL;
			break;
		}

		rval = kvm_vm_ioctl_set_identity_map_addr(kvmp,
		    kvm_id_map_addr_ioc->ident_addr);

		kmem_free(kvm_id_map_addr_ioc, sz);
		*rv = 0;
		break;
	}

	case KVM_CREATE_VCPU: {
		uint32_t id = (uintptr_t)arg;
		struct kvm *kvmp;
		struct kvm_vcpu *vcpu;

		if ((kvmp = ksp->kds_kvmp) == NULL) {
			rval = EINVAL;
			break;
		}

		if (ksp->kds_vcpu != NULL) {
			rval = EEXIST;
			break;
		}

		rval = kvm_vm_ioctl_create_vcpu(ksp->kds_kvmp, id, rv);

		if (rval == 0) {
			ksp->kds_vcpu = kvmp->vcpus[id];
			ASSERT(ksp->kds_vcpu != NULL);
		}

		break;
	}

	case KVM_SET_USER_MEMORY_REGION: {
		struct kvm_userspace_memory_region map;
		struct kvm *kvmp;

		if (copyin(argp, &map, sizeof (map)) != 0) {
			rval = EFAULT;
			break;
		}

		if ((kvmp = ksp->kds_kvmp) == NULL) {
			rval = EINVAL;
			break;
		}

		rval = kvm_vm_ioctl_set_memory_region(kvmp, &map, 1);
		break;
	}

	case KVM_GET_SUPPORTED_CPUID: {
		struct kvm_cpuid2 *cpuid_arg = (struct kvm_cpuid2 *)arg;
		struct kvm_cpuid2 *cpuid;

		cpuid = kmem_zalloc(sizeof (struct kvm_cpuid2), KM_SLEEP);

		if (copyin(argp, cpuid, sizeof (struct kvm_cpuid2)) != 0) {
			kmem_free(cpuid, sizeof (struct kvm_cpuid2));
			rval = EFAULT;
			break;
		}

		if ((rval = kvm_dev_ioctl_get_supported_cpuid(cpuid,
		    cpuid_arg->entries)) != 0) {
			kmem_free(cpuid, sizeof (struct kvm_cpuid2));
			break;
		}

		if (copyout(&cpuid->nent, cpuid_arg, sizeof (int)))
			rval = EFAULT;

		kmem_free(cpuid, sizeof (struct kvm_cpuid2));
		break;
	}

	case KVM_GET_MSR_INDEX_LIST: {
		struct kvm_msr_list *user_msr_list = (struct kvm_msr_list *)arg;
		struct kvm_msr_list *msr_list;
		size_t sz = sizeof (struct kvm_msr_list);
		unsigned n;

		msr_list = kmem_zalloc(sz, KM_SLEEP);

		if (copyin(user_msr_list, msr_list, sz) != 0) {
			kmem_free(msr_list, sz);
			rval = EFAULT;
			break;
		}

		n = msr_list->nmsrs;
		msr_list->nmsrs = num_msrs_to_save + ARRAY_SIZE(emulated_msrs);

		if (copyout(msr_list, user_msr_list, sz) != 0) {
			kmem_free(msr_list, sz);
			rval = EFAULT;
			break;
		}

		if (n < msr_list->nmsrs) {
			kmem_free(msr_list, sz);
			rval = E2BIG;
			break;
		}

		if (copyout(&msrs_to_save, user_msr_list->indices,
		    num_msrs_to_save * sizeof (uint32_t))) {
			kmem_free(msr_list, sz);
			rval = EFAULT;
			break;
		}

		if (copyout(&emulated_msrs, user_msr_list->indices +
		    num_msrs_to_save, ARRAY_SIZE(emulated_msrs) *
		    sizeof (uint32_t)) != 0) {
			kmem_free(msr_list, sz);
			rval = EFAULT;
			break;
		}

		kmem_free(msr_list, sz);

		rval = 0;
		*rv = 0;
		break;
	}

	case KVM_SET_SIGNAL_MASK: {
		struct kvm_signal_mask *sigmask = argp;
		struct kvm_signal_mask kvm_sigmask;
		sigset_t sigset;
		struct kvm_vcpu *vcpu;

		if ((vcpu = ksp->kds_vcpu) == NULL) {
			rval = EINVAL;
			break;
		}

		if (argp == NULL) {
			rval = kvm_vcpu_ioctl_set_sigmask(vcpu, NULL);
			break;
		}

		if (copyin(argp, &kvm_sigmask, sizeof (kvm_sigmask)) != 0) {
			rval = EFAULT;
			break;
		}

		if (kvm_sigmask.len != sizeof (sigset)) {
			rval = EINVAL;
			break;
		}

		if (copyin(sigmask->sigset, &sigset, sizeof (sigset)) != 0) {
			rval = EINVAL;
			break;
		}

		rval = kvm_vcpu_ioctl_set_sigmask(vcpu, &sigset);
		break;
	}

	case KVM_SET_TSS_ADDR: {
		struct kvm_tss kvm_tss;
		struct kvm *kvmp;

		if (copyin(argp, &kvm_tss, sizeof (kvm_tss)) != 0) {
			rval = EFAULT;
			break;
		}

		if ((kvmp = ksp->kds_kvmp) == NULL) {
			rval = EINVAL;
			break;
		}

		rval = kvm_vm_ioctl_set_tss_addr(kvmp, (caddr_t)kvm_tss.addr);
		break;
	}

#ifdef CONFIG_KVM_APIC_ARCHITECTURE
	case KVM_SET_BOOT_CPU_ID: {
		struct kvm_set_boot_cpu_id_ioc boot_cpu_id_ioc;
		struct kvm *kvmp;

		if (copyin(argp, &boot_cpu_id_ioc,
		    sizeof (boot_cpu_id_ioc)) != 0) {
			rval = EFAULT;
			break;
		}

		if ((kvmp = ksp->kds_kvmp) == NULL) {
			rval = EINVAL;
			break;
		}

		mutex_enter(&kvmp->lock);
#ifdef XXX
		if (atomic_read(&kvmp->online_vcpus) != 0)
			rval = -EBUSY;
		else {
#else
		{
			XXX_KVM_PROBE;
#endif
			kvmp->bsp_vcpu_id = boot_cpu_id_ioc.id;
		}

		*rv = kvmp->bsp_vcpu_id;
		mutex_exit(&kvmp->lock);
		break;
	}
#endif
#ifdef KVM_COALESCED_MMIO_PAGE_OFFSET
	case KVM_REGISTER_COALESCED_MMIO: {
		struct kvm *kvmp;
		struct kvm_coalesced_mmio_zone_ioc *zone_ioc;
		size_t sz = sizeof (struct kvm_coalesced_mmio_zone_ioc);

		zone_ioc = kmem_zalloc(sz, KM_SLEEP);

		if (copyin(argp, zone_ioc, sz) != 0) {
			kmem_free(zone_ioc, sz);
			rval = EFAULT;
			break;
		}

		if ((kvmp = ksp->kds_kvmp) == NULL) {
			rval = EINVAL;
			kmem_free(zone_ioc, sz);
			break;
		}

		rval = kvm_vm_ioctl_register_coalesced_mmio(kvmp,
		    &zone_ioc->zone);

		kmem_free(zone_ioc, sz);
		break;
	}

	case KVM_UNREGISTER_COALESCED_MMIO: {
		struct kvm_coalesced_mmio_zone_ioc *zone_ioc;
		struct kvm *kvmp;
		size_t sz = sizeof (struct kvm_coalesced_mmio_zone_ioc);

		zone_ioc = kmem_zalloc(sz, KM_SLEEP);

		if (copyin(argp, zone_ioc, sz) != 0) {
			kmem_free(zone_ioc, sz);
			break;
		}

		if ((kvmp = ksp->kds_kvmp) == NULL) {
			kmem_free(zone_ioc, sz);
			rval = EINVAL;
			break;
		}

		rval = kvm_vm_ioctl_unregister_coalesced_mmio(kvmp,
		    &zone_ioc->zone);

		kmem_free(zone_ioc, sz);
		break;
	}
#endif
#ifdef KVM_CAP_IRQ_ROUTING
	case KVM_SET_GSI_ROUTING: {
		struct kvm_irq_routing *route;
		struct kvm *kvmp;
		struct kvm_irq_routing_entry *entries;
		uint32_t nroutes;

		/*
		 * Note the route must be allocated on the heap. The sizeof
		 * (kvm_kirq_routing) is approximately 0xc038 currently.
		 */
		route = kmem_zalloc(sizeof (kvm_irq_routing_t), KM_SLEEP);

		/*
		 * copyin the number of routes, then copyin the routes
		 * themselves.
		 */
		if (copyin(argp, &nroutes, sizeof (nroutes)) != 0) {
			kmem_free(route, sizeof (kvm_irq_routing_t));
			rval = EFAULT;
			break;
		}

		if (nroutes <= 0) {
			kmem_free(route, sizeof (kvm_irq_routing_t));
			rval = EINVAL;
			break;
		}

		if (copyin(argp, route,
		    sizeof (struct kvm_irq_routing) + (nroutes - 1) *
		    sizeof (struct kvm_irq_routing_entry)) != 0) {
			kmem_free(route, sizeof (kvm_irq_routing_t));
			rval = EFAULT;
			break;
		}

		if ((kvmp = ksp->kds_kvmp) == NULL) {
			kmem_free(route, sizeof (kvm_irq_routing_t));
			rval = EINVAL;
			break;
		}

		if (route->nr >= KVM_MAX_IRQ_ROUTES || route->flags) {
			kmem_free(route, sizeof (kvm_irq_routing_t));
			rval = EINVAL;
			break;
		}

		rval = kvm_set_irq_routing(kvmp, route->entries,
		    route->nr, route->flags);
		kmem_free(route, sizeof (kvm_irq_routing_t));
		*rv = 0;
		break;
	}
#endif /* KVM_CAP_IRQ_ROUTING */
	case KVM_IRQ_LINE_STATUS:
	case KVM_IRQ_LINE: {
		struct kvm_irq_level level;
		struct kvm *kvmp;
		size_t sz = sizeof (struct kvm_irq_level);
		int32_t status;

		if (copyin(argp, &level, sz) != 0) {
			rval = EFAULT;
			break;
		}

		if ((kvmp = ksp->kds_kvmp) == NULL) {
			rval = EINVAL;
			break;
		}

		if (!irqchip_in_kernel(kvmp)) {
			rval = ENXIO;
			break;
		}

		status = kvm_set_irq(kvmp, KVM_USERSPACE_IRQ_SOURCE_ID,
		    level.irq, level.level);

		if (cmd == KVM_IRQ_LINE_STATUS) {
			level.status = status;

			if (copyout(&level, argp, sz) != 0) {
				rval = EFAULT;
				break;
			}
		}

		break;
	}

	case KVM_GET_IRQCHIP: {
		struct kvm *kvmp;
		struct kvm_irqchip chip;
		size_t sz = sizeof (struct kvm_irqchip);
		/* 0: PIC master, 1: PIC slave, 2: IOAPIC */

		if ((kvmp = ksp->kds_kvmp) == NULL) {
			rval = EINVAL;
			break;
		}

		if (!irqchip_in_kernel(kvmp)) {
			rval = ENXIO;
			break;
		}

		rval = kvm_vm_ioctl_get_irqchip(kvmp, &chip);

		if (rval == 0 && copyout(&chip, argp, sz) != 0) {
			rval = EFAULT;
			break;
		}

		break;
	}

	case KVM_SET_IRQCHIP: {
		struct kvm *kvmp;
		struct kvm_irqchip chip;
		size_t sz = sizeof (struct kvm_irqchip);
		/* 0: PIC master, 1: PIC slave, 2: IOAPIC */

		if ((kvmp = ksp->kds_kvmp) == NULL) {
			rval = EINVAL;
			break;
		}

		if (copyin(argp, &chip, sizeof (struct kvm_irqchip)) != 0) {
			rval = EFAULT;
			break;
		}

		if (!irqchip_in_kernel(kvmp)) {
			rval = ENXIO;
			break;
		}

		rval = kvm_vm_ioctl_set_irqchip(kvmp, &chip);
		break;
	}
	case KVM_GET_DIRTY_LOG: {
		struct kvm_dirty_log log;
		struct kvm *kvmp;

		if ((kvmp = ksp->kds_kvmp) == NULL) {
			rval = EINVAL;
			break;
		}

		if (copyin(argp, &log, sizeof (struct kvm_dirty_log)) != 0) {
			rval = EFAULT;
			break;
		}

		rval = kvm_vm_ioctl_get_dirty_log(kvmp, &log);
		break;
	}
	case KVM_NET_QUEUE: {
		struct vnode *vn;
		file_t *fp;
		struct stroptions *stropt;
		mblk_t *mp;
		queue_t *q;

		fp = getf(arg);
		if (fp == NULL) {
			rval = EINVAL;
			break;
		}
		ASSERT(fp->f_vnode);

		if (fp->f_vnode->v_stream == NULL) {
			releasef(arg);
			rval = EINVAL;
			break;
		}

		mp = allocb(sizeof (struct stroptions), BPRI_LO);
		if (mp == NULL) {
			releasef(arg);
			rval = ENOMEM;
		}

		/*
		 * XXX This really just shouldn't need to exist, etc. and we
		 * should really get the hiwat value more intelligently at least
		 * a #define or a tunable god forbid. Oh well, as bmc said
		 * earlier:
		 * "I am in blood steeped in so far that I wade no more.
		 * Returning were as tedious as go o'er.
		 *
		 * We'd love to just putmsg on RD(fp->f_vnode->v_stream->sd_wq)
		 * however that would be the stream head. Instead, we need to
		 * get the write version and then go to the next one and then
		 * the opposite end. The doctor may hemorrhage before the
		 * patient.
		 *
		 * Banquo's ghost is waiting to pop up
		 */
		mp->b_datap->db_type = M_SETOPTS;
		stropt = (struct stroptions *)mp->b_rptr;
		stropt->so_flags = SO_HIWAT;
		stropt->so_hiwat = 0x100042;
		q = WR(fp->f_vnode->v_stream->sd_wrq);
		q = RD(q->q_next);
		putnext(q, mp);

		releasef(arg);

		rval = 0;
		*rv = 0;
	}
	default:
#ifndef XXX
		XXX_KVM_PROBE;
		DTRACE_PROBE1(kvm__xxx__ioctl, int, cmd);
#endif
		rval = EINVAL;  /* x64, others may do other things... */
	}

	if (*rv == -1)
		return (EINVAL);

	return (rval < 0 ? -rval : rval);
}

/* BEGIN CSTYLED */

/*
 * mmap(2), segmap(9E), and devmap(9E)
 *
 * Users call mmap(2). For each call to mmap(2) there is a corresponding call to
 * segmap(9E). segmap(9E) is responsible for making sure that the various
 * requests in the mmap call make sense from the question of protection,
 * offsets, lengths, etc. It then ends by calling the ddi_devmap_segmap() which
 * is what is responsible for making all of the actual mappings.
 *
 * The devmap entry point is called a variable number of times. It is called a
 * number of times until all the maplen values equal the original length of the
 * requested mapping. This allows us to make several different mappings by not
 * honoring the full requested mapping the first time. Each subsequent time it
 * is called with an updated offset and length.
 */


/*
 * We can only create one mapping per dhp. We know whether this is the first
 * time or the second time in based on the requested offset / length. If we only
 * have one page worth, then it's always looking for the shared mmio page. If it
 * is asking for KVM_VCPU_MMAP_LENGTH pages, then it's asking for the shared
 * vcpu pages.
 */
static int
kvm_devmap(dev_t dev, devmap_cookie_t dhp, offset_t off, size_t len,
    size_t *maplen, uint_t model)
{
	int res, vpi;
	minor_t instance;
	kvm_devstate_t *ksp;
	kvm_vcpu_t *vcpu;

	instance = getminor(dev);
	ksp = ddi_get_soft_state(kvm_state, instance);
	if (ksp == NULL)
		return (ENXIO);

	/*
	 * Enforce that only 64-bit guests are allowed.
	 */
	if (ddi_model_convert_from(model) == DDI_MODEL_ILP32)
		return (EINVAL);

	if (ksp->kds_kvmp == NULL)
		return (EINVAL);

	if (len == PAGESIZE) {
		res = devmap_umem_setup(dhp, kvm_dip, NULL,
		    ksp->kds_kvmp->mmio_cookie, 0, len, PROT_READ | PROT_WRITE |
		    PROT_USER, DEVMAP_DEFAULTS, NULL);
		*maplen = len;
		return (res);
	}

	vpi = btop(off) / 3;
	VERIFY(vpi < ksp->kds_kvmp->online_vcpus);
	vcpu = ksp->kds_kvmp->vcpus[vpi];
	VERIFY(vcpu != NULL);

	res = devmap_umem_setup(dhp, kvm_dip, NULL, vcpu->cookie, 0,
	    PAGESIZE*2, PROT_READ | PROT_WRITE | PROT_USER, DEVMAP_DEFAULTS,
	    NULL);

	*maplen = PAGESIZE*2;

	return (res);
}

/*
 * We determine which vcpu we're trying to mmap in based upon the requested
 * offset. For a given vcpu n the offset to specify it is
 * n*KVM_VCPU_MMAP_LENGTH. Thus the first vcpu is at offset 0. 
 */
static int
kvm_segmap(dev_t dev, off_t off, struct as *asp, caddr_t *addrp, off_t len,
    unsigned int prot, unsigned int maxprot, unsigned int flags,
    cred_t *credp)
{
	kvm_devstate_t *ksp;
	off_t poff;

	if ((ksp = ddi_get_soft_state(kvm_state, getminor(dev))) == NULL)
		return (ENXIO);

	if (prot & PROT_EXEC)
		return (EINVAL);

	if (!(prot & PROT_USER))
	    return (EINVAL);

	if (len != ptob(KVM_VCPU_MMAP_LENGTH))
		return (EINVAL);

	poff = btop(off);
	if (poff % 3 != 0)
		return (EINVAL);

	/*
	 * Currently vcpus can only be turned on, they cannot be offlined. As a
	 * result we can safely check that we have a request for a valid cpu
	 * because it is within this range.
	 */
	if (poff / 3 + 1 > ksp->kds_kvmp->online_vcpus)
		return (EINVAL);

	return (ddi_devmap_segmap(dev, off, asp, addrp, len, prot, maxprot,
	    flags, credp));
}


static void
kvm_on_user_return(struct kvm_vcpu *vcpu, struct kvm_user_return_notifier *urn)
{
	unsigned slot;
	struct kvm_shared_msrs *locals =
	    (struct kvm_shared_msrs *)(((caddr_t)urn) -
		offsetof(struct kvm_shared_msrs, urn));
	struct kvm_shared_msr_values *values;

	for (slot = 0; slot < shared_msrs_global.nr; ++slot) {
		values = &locals->values[slot];
		if (values->host != values->curr) {
			wrmsrl(shared_msrs_global.msrs[slot], values->host);
			values->curr = values->host;
		}
	}
	locals->registered = 0;
	kvm_user_return_notifier_unregister(vcpu, urn);
}

void
kvm_vcpu_uninit(struct kvm_vcpu *vcpu)
{
	kvm_arch_vcpu_uninit(vcpu);
	ddi_umem_free(vcpu->cookie);
}

static int
kvm_avlmmucmp(const void *arg1, const void *arg2)
{
	const kvm_mmu_page_t *mp1 = arg1;
	const kvm_mmu_page_t *mp2 = arg2;
	if (mp1->kmp_avlspt > mp2->kmp_avlspt)
		return (1);
	if (mp1->kmp_avlspt < mp2->kmp_avlspt)
		return (-1);
	ASSERT(mp1->kmp_avlspt == mp2->kmp_avlspt);
	return (0);
}
/* END CSTYLED */
