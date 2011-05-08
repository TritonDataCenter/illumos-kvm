
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

#include "vmx.h"
#include "msr-index.h"
#include "msr.h"
#include "irqflags.h"
#include "kvm_host.h"
#include "kvm_x86host.h"
#include "processor-flags.h"
#include "hyperv.h"
#include "apicdef.h"
#include "iodev.h"
#include "kvm.h"
#include "irq.h"
#include "tss.h"
#include "ioapic.h"
#include "coalesced_mmio.h"

#undef DEBUG

/*
 * The entire state of the kvm device.
 */
typedef struct {
	struct kvm	*kds_kvmp;
} kvm_devstate_t;

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
kmem_cache_t *kvm_cache;
struct vmx_capability  vmx_capability;


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
static int vmx_set_tss_addr(struct kvm *kvmp, caddr_t addr);
static int vmx_hardware_setup(void);
extern int vmx_hardware_enable(void *garbage);
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
extern int irqchip_in_kernel(struct kvm *kvm);
extern void kvm_set_cr8(struct kvm_vcpu *vcpu, unsigned long cr8);
extern void kvm_set_apic_base(struct kvm_vcpu *vcpu, uint64_t data);
extern void kvm_release_pfn_dirty(pfn_t pfn);
extern void kvm_release_pfn_clean(pfn_t pfn);
extern void kvm_mmu_free_some_pages(struct kvm_vcpu *vcpu);
extern int mmu_topup_memory_caches(struct kvm_vcpu *vcpu);
extern int kvm_irq_delivery_to_apic(struct kvm *kvm, struct kvm_lapic *src,
				    struct kvm_lapic_irq *irq);
static int hardware_enable_all(void);
static void hardware_disable_all(void);
extern int sigprocmask(int, const sigset_t *, sigset_t *);
extern void start_apic_timer(struct kvm_lapic *);
extern void update_divide_count(struct kvm_lapic *);
extern void cli(void);
extern void sti(void);
static void kvm_destroy_vm(struct kvm *);


int get_ept_level(void);
static void vmx_cache_reg(struct kvm_vcpu *vcpu, enum kvm_reg reg);

struct vcpu_vmx *
to_vmx(struct kvm_vcpu *vcpu)
{
#ifdef XXX_KVM_DOESNTCOMPILE
	return (container_of(vcpu, struct vcpu_vmx, vcpu));
#else
	/* assumes vcpu is first field in vcpu_vmx */
	/* because gcc with kernel flags complains about container_of */
	return ((struct vcpu_vmx *)vcpu);
#endif
}

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

static inline void
__invvpid(int ext, uint16_t vpid, gva_t gva)
{
	struct {
		uint64_t vpid:16;
		uint64_t rsvd:48;
		uint64_t gva;
	} operand = { vpid, 0, gva };

	/* BEGIN CSTYLED */
#ifdef XXX_KVM_DOESNTCOMPILE
	__asm__ volatile (__ex(ASM_VMX_INVVPID)
#else
	__asm__ volatile (ASM_VMX_INVVPID
#endif /*XXX*/
		  /* CF==1 or ZF==1 --> rc = -1 */
		  "; ja 1f ; ud2 ; 1:"
		  : : "a"(&operand), "c"(ext) : "cc", "memory");
	/* END CSTYLED */
}

inline void
vpid_sync_vcpu_all(struct vcpu_vmx *vmx)
{
	if (vmx->vpid == 0)
		return;

	__invvpid(VMX_VPID_EXTENT_SINGLE_CONTEXT, vmx->vpid, 0);
}

static inline void
__invept(int ext, uint64_t eptp, gpa_t gpa)
{
	struct {
		uint64_t eptp, gpa;
	} operand = {eptp, gpa};

	/* BEGIN CSTYLED */
	__asm__ volatile (ASM_VMX_INVEPT
			/* CF==1 or ZF==1 --> rc = -1 */
			"; ja 1f ; ud2 ; 1:\n"
			: : "a" (&operand), "c" (ext) : "cc", "memory");
	/* END CSTYLED */
}

static inline int
cpu_has_vmx_invept_context(void)
{
	return (!!(vmx_capability.ept & VMX_EPT_EXTENT_CONTEXT_BIT));
}

static inline int
cpu_has_vmx_invept_global(void)
{
	return (!!(vmx_capability.ept & VMX_EPT_EXTENT_GLOBAL_BIT));
}

inline void
ept_sync_global(void)
{
	if (cpu_has_vmx_invept_global())
		__invept(VMX_EPT_EXTENT_GLOBAL, 0, 0);
}

int enable_ept = 1;   /* XXX */

static inline void
ept_sync_context(uint64_t eptp)
{
	if (enable_ept) {
		if (cpu_has_vmx_invept_context())
			__invept(VMX_EPT_EXTENT_CONTEXT, eptp, 0);
		else
			ept_sync_global();
	}
}

static uint64_t
construct_eptp(unsigned long root_hpa)
{
	uint64_t eptp;

	/* TODO write the value reading from MSR */
	eptp = VMX_EPT_DEFAULT_MT |
		VMX_EPT_DEFAULT_GAW << VMX_EPT_GAW_EPTP_SHIFT;
	eptp |= (root_hpa & PAGEMASK);

	return (eptp);
}


static void vmx_flush_tlb(struct kvm_vcpu *vcpu)
{
	vpid_sync_vcpu_all(to_vmx(vcpu));
	if (enable_ept)
		ept_sync_context(construct_eptp(vcpu->arch.mmu.root_hpa));
}

void
vmcs_write64(unsigned long field, uint64_t value)
{
	vmcs_writel(field, value);
#ifndef CONFIG_X86_64
	/*CSTYLED*/
	__asm__ volatile ("");
	vmcs_writel(field + 1, value >> 32);
#endif
}

inline int is_pae(struct kvm_vcpu *vcpu);
extern int is_paging(struct kvm_vcpu *);
extern int is_long_mode(struct kvm_vcpu *);

static void
ept_load_pdptrs(struct kvm_vcpu *vcpu)
{
	if (!test_bit(VCPU_EXREG_PDPTR,
	    (unsigned long *)&vcpu->arch.regs_dirty))
		return;

	if (is_paging(vcpu) && is_pae(vcpu) && !is_long_mode(vcpu)) {
		vmcs_write64(GUEST_PDPTR0, vcpu->arch.pdptrs[0]);
		vmcs_write64(GUEST_PDPTR1, vcpu->arch.pdptrs[1]);
		vmcs_write64(GUEST_PDPTR2, vcpu->arch.pdptrs[2]);
		vmcs_write64(GUEST_PDPTR3, vcpu->arch.pdptrs[3]);
	}
}

static void
vmx_set_cr3(struct kvm_vcpu *vcpu, unsigned long cr3)
{
	unsigned long guest_cr3;
	uint64_t eptp;

	guest_cr3 = cr3;

	if (enable_ept) {
		eptp = construct_eptp(cr3);
		vmcs_write64(EPT_POINTER, eptp);
		guest_cr3 = is_paging(vcpu) ?
		    vcpu->arch.cr3 : vcpu->kvm->arch.ept_identity_map_addr;
		ept_load_pdptrs(vcpu);
	}

	vmx_flush_tlb(vcpu);
	vmcs_writel(GUEST_CR3, guest_cr3);
}

#define	_ER(x) { EXIT_REASON_##x, #x }

struct trace_print_flags {
	unsigned long		mask;
	const char		*name;
};

static const struct trace_print_flags vmx_exit_reasons_str[] = {
	_ER(EXCEPTION_NMI),
	_ER(EXTERNAL_INTERRUPT),
	_ER(TRIPLE_FAULT),
	_ER(PENDING_INTERRUPT),
	_ER(NMI_WINDOW),
	_ER(TASK_SWITCH),
	_ER(CPUID),
	_ER(HLT),
	_ER(INVLPG),
	_ER(RDPMC),
	_ER(RDTSC),
	_ER(VMCALL),
	_ER(VMCLEAR),
	_ER(VMLAUNCH),
	_ER(VMPTRLD),
	_ER(VMPTRST),
	_ER(VMREAD),
	_ER(VMRESUME),
	_ER(VMWRITE),
	_ER(VMOFF),
	_ER(VMON),
	_ER(CR_ACCESS),
	_ER(DR_ACCESS),
	_ER(IO_INSTRUCTION),
	_ER(MSR_READ),
	_ER(MSR_WRITE),
	_ER(MWAIT_INSTRUCTION),
	_ER(MONITOR_INSTRUCTION),
	_ER(PAUSE_INSTRUCTION),
	_ER(MCE_DURING_VMENTRY),
	_ER(TPR_BELOW_THRESHOLD),
	_ER(APIC_ACCESS),
	_ER(EPT_VIOLATION),
	_ER(EPT_MISCONFIG),
	_ER(WBINVD),
	{ -1, NULL }
};

#undef _ER

static int flexpriority_enabled = 1;

static inline int
report_flexpriority(void)
{
	return (flexpriority_enabled);
}

/*
 * The function is based on mtrr_type_lookup() in
 * arch/x86/kernel/cpu/mtrr/generic.c
 */

/*  These are the region types  */
#define	MTRR_TYPE_UNCACHABLE	0
#define	MTRR_TYPE_WRCOMB	1
#define	MTRR_TYPE_WRTHROUGH	4
#define	MTRR_TYPE_WRPROT	5
#define	MTRR_TYPE_WRBACK	6
#define	MTRR_NUM_TYPES		7

static int
get_mtrr_type(struct mtrr_state_type *mtrr_state, uint64_t start, uint64_t end)
{
	int i;
	uint64_t base, mask;
	uint8_t prev_match, curr_match;
	int num_var_ranges = KVM_NR_VAR_MTRR;

	if (!mtrr_state->enabled)
		return (0xFF);

	/* Make end inclusive end, instead of exclusive */
	end--;

	/* Look in fixed ranges. Just return the type as per start */
	if (mtrr_state->have_fixed && (start < 0x100000)) {
		int idx;

		if (start < 0x80000) {
			idx = 0;
			idx += (start >> 16);
			return (mtrr_state->fixed_ranges[idx]);
		} else if (start < 0xC0000) {
			idx = 1 * 8;
			idx += ((start - 0x80000) >> 14);
			return (mtrr_state->fixed_ranges[idx]);
		} else if (start < 0x1000000) {
			idx = 3 * 8;
			idx += ((start - 0xC0000) >> 12);
			return (mtrr_state->fixed_ranges[idx]);
		}
	}

	/*
	 * Look in variable ranges
	 * Look of multiple ranges matching this address and pick type
	 * as per MTRR precedence
	 */
	if (!(mtrr_state->enabled & 2))
		return (mtrr_state->def_type);

	prev_match = 0xFF;
	for (i = 0; i < num_var_ranges; ++i) {
		unsigned short start_state, end_state;

		if (!(mtrr_state->var_ranges[i].mask_lo & (1 << 11)))
			continue;

		base = (((uint64_t)mtrr_state->var_ranges[i].base_hi) << 32) +
		    (mtrr_state->var_ranges[i].base_lo & PAGEMASK);
		mask = (((uint64_t)mtrr_state->var_ranges[i].mask_hi) << 32) +
		    (mtrr_state->var_ranges[i].mask_lo & PAGEMASK);

		start_state = ((start & mask) == (base & mask));
		end_state = ((end & mask) == (base & mask));
		if (start_state != end_state)
			return (0xFE);

		if ((start & mask) != (base & mask))
			continue;

		curr_match = mtrr_state->var_ranges[i].base_lo & 0xff;
		if (prev_match == 0xFF) {
			prev_match = curr_match;
			continue;
		}

		if (prev_match == MTRR_TYPE_UNCACHABLE ||
		    curr_match == MTRR_TYPE_UNCACHABLE)
			return (MTRR_TYPE_UNCACHABLE);

		if ((prev_match == MTRR_TYPE_WRBACK &&
		    curr_match == MTRR_TYPE_WRTHROUGH) ||
		    (prev_match == MTRR_TYPE_WRTHROUGH &&
		    curr_match == MTRR_TYPE_WRBACK)) {
			prev_match = MTRR_TYPE_WRTHROUGH;
			curr_match = MTRR_TYPE_WRTHROUGH;
		}

		if (prev_match != curr_match)
			return (MTRR_TYPE_UNCACHABLE);
	}

	if (prev_match != 0xFF)
		return (prev_match);

	return (mtrr_state->def_type);
}

uint8_t
kvm_get_guest_memory_type(struct kvm_vcpu *vcpu, gfn_t gfn)
{
	uint8_t mtrr;

	mtrr = get_mtrr_type(&vcpu->arch.mtrr_state,
	    gfn << PAGESHIFT, (gfn << PAGESHIFT) + PAGESIZE);
	if (mtrr == 0xfe || mtrr == 0xff)
		mtrr = MTRR_TYPE_WRBACK;
	return (mtrr);
}

static uint64_t
vmx_get_mt_mask(struct kvm_vcpu *vcpu, gfn_t gfn, int is_mmio)
{
	/*
	 * For VT-d and EPT combination
	 * 1. MMIO: always map as UC
	 * 2. EPT with VT-d:
	 *   a. VT-d without snooping control feature: can't guarantee the
	 *	result, try to trust guest.
	 *   b. VT-d with snooping control feature: snooping control feature of
	 *	VT-d engine can guarantee the cache correctness. Just set it
	 *	to WB to keep consistent with host. So the same as item 3.
	 * 3. EPT without VT-d: always map as WB and set IPAT=1 to keep
	 *    consistent with host MTRR
	 */
	if (is_mmio)
		return (MTRR_TYPE_UNCACHABLE << VMX_EPT_MT_EPTE_SHIFT);

	if (vcpu->kvm->arch.iommu_domain &&
	    !(vcpu->kvm->arch.iommu_flags & KVM_IOMMU_CACHE_COHERENCY)) {
		return (kvm_get_guest_memory_type(vcpu, gfn) <<
		    VMX_EPT_MT_EPTE_SHIFT);
	}

	return ((MTRR_TYPE_WRBACK << VMX_EPT_MT_EPTE_SHIFT) | VMX_EPT_IPAT_BIT);
}

static void
vmx_patch_hypercall(struct kvm_vcpu *vcpu, unsigned char *hypercall)
{
	/*
	 * Patch in the VMCALL instruction:
	 */
	hypercall[0] = 0x0f;
	hypercall[1] = 0x01;
	hypercall[2] = 0xc1;
}

static void vmx_get_cs_db_l_bits(struct kvm_vcpu *vcpu, int *db, int *l);
extern void update_exception_bitmap(struct kvm_vcpu *vcpu);

static void
set_guest_debug(struct kvm_vcpu *vcpu, struct kvm_guest_debug *dbg)
{
	if (vcpu->guest_debug & KVM_GUESTDBG_USE_HW_BP)
		vmcs_writel(GUEST_DR7, dbg->arch.debugreg[7]);
	else
		vmcs_writel(GUEST_DR7, vcpu->arch.dr7);

	update_exception_bitmap(vcpu);
}

static struct kvm_x86_ops vmx_x86_ops = {
	.cpu_has_kvm_support = nulldev, /* XXX: cpu_has_kvm_support? */
	.disabled_by_bios = nulldev, /* XXX: vmx_disabled_by_bios? */

	.hardware_enable = vmx_hardware_enable,
	.hardware_disable = hardware_disable,

	.check_processor_compatibility = (void(*)(void *))nulldev, /* XXX */

	.hardware_setup = vmx_hardware_setup,

	.hardware_unsetup = (void(*)(void))nulldev, /* XXX: hardware_unsetup? */

	.cpu_has_accelerated_tpr = report_flexpriority,
	.vcpu_create = vmx_create_vcpu,
	.vcpu_free = vmx_destroy_vcpu, /* XXX */
	.vcpu_reset = vmx_vcpu_reset,

	.prepare_guest_switch = vmx_save_host_state,
	.vcpu_load = vmx_vcpu_load,
	.vcpu_put = vmx_vcpu_put,

	.set_guest_debug = set_guest_debug,
	.get_msr = vmx_get_msr,
	.set_msr = vmx_set_msr,
	.get_segment_base = vmx_get_segment_base,
	.get_segment = vmx_get_segment,
	.set_segment = vmx_set_segment,
	.get_cpl = vmx_get_cpl,
	.get_cs_db_l_bits = vmx_get_cs_db_l_bits,
	.decache_cr0_guest_bits = vmx_decache_cr0_guest_bits,
	.decache_cr4_guest_bits = vmx_decache_cr4_guest_bits,
	.set_cr0 = vmx_set_cr0,
	.set_cr3 = vmx_set_cr3,
	.set_cr4 = vmx_set_cr4,
	.set_efer = vmx_set_efer,
	.get_idt = vmx_get_idt,
	.set_idt = vmx_set_idt,
	.get_gdt = vmx_get_gdt,
	.set_gdt = vmx_set_gdt,
	.cache_reg = vmx_cache_reg,
	.get_rflags = vmx_get_rflags,
	.set_rflags = vmx_set_rflags,
	.fpu_activate = vmx_fpu_activate,
	.fpu_deactivate = vmx_fpu_deactivate,

	.tlb_flush = vmx_flush_tlb,

	.run = vmx_vcpu_run,
	.handle_exit = vmx_handle_exit,
	.skip_emulated_instruction = skip_emulated_instruction,
	.set_interrupt_shadow = vmx_set_interrupt_shadow,
	.get_interrupt_shadow = vmx_get_interrupt_shadow,
	.patch_hypercall = vmx_patch_hypercall,
	.set_irq = vmx_inject_irq,
	.set_nmi = vmx_inject_nmi,
	.queue_exception = vmx_queue_exception,
	.interrupt_allowed = vmx_interrupt_allowed,
	.nmi_allowed = vmx_nmi_allowed,
	.get_nmi_mask = vmx_get_nmi_mask,
	.set_nmi_mask = vmx_set_nmi_mask,
	.enable_nmi_window = enable_nmi_window,
	.enable_irq_window = enable_irq_window,
	.update_cr8_intercept = vmx_update_cr8_intercept,

	.set_tss_addr = vmx_set_tss_addr,
	.get_tdp_level = get_ept_level,
	.get_mt_mask = vmx_get_mt_mask,

	.exit_reasons_str = vmx_exit_reasons_str,

	.get_lpage_level = vmx_get_lpage_level,

	.cpuid_update = vmx_cpuid_update,

	.rdtscp_supported = vmx_rdtscp_supported
};

struct kvm_x86_ops *kvm_x86_ops;

uint32_t
vmcs_read32(unsigned long field)
{
	return (vmcs_readl(field));
}

static void
vmx_get_cs_db_l_bits(struct kvm_vcpu *vcpu, int *db, int *l)
{
	uint32_t ar = vmcs_read32(GUEST_CS_AR_BYTES);

	*db = (ar >> 14) & 1;
	*l = (ar >> 13) & 1;
}

void
vmcs_write32(unsigned long field, uint32_t value)
{
	vmcs_writel(field, value);
}

static void
vmx_decache_cr0_guest_bits(struct kvm_vcpu *vcpu)
{
	ulong cr0_guest_owned_bits = vcpu->arch.cr0_guest_owned_bits;

	vcpu->arch.cr0 &= ~cr0_guest_owned_bits;
	vcpu->arch.cr0 |= vmcs_readl(GUEST_CR0) & cr0_guest_owned_bits;
}

static void
vmx_decache_cr4_guest_bits(struct kvm_vcpu *vcpu)
{
	ulong cr4_guest_owned_bits = vcpu->arch.cr4_guest_owned_bits;

	vcpu->arch.cr4 &= ~cr4_guest_owned_bits;
	vcpu->arch.cr4 |= vmcs_readl(GUEST_CR4) & cr4_guest_owned_bits;
}

inline ulong
kvm_read_cr0_bits(struct kvm_vcpu *vcpu, ulong mask)
{
	ulong tmask = mask & KVM_POSSIBLE_CR0_GUEST_BITS;

	if (tmask & vcpu->arch.cr0_guest_owned_bits)
		kvm_x86_ops->decache_cr0_guest_bits(vcpu);

	return (vcpu->arch.cr0 & mask);
}

static void
vmcs_clear_bits(unsigned long field, uint32_t mask)
{
	vmcs_writel(field, vmcs_readl(field) & ~mask);
}

static void
vmcs_set_bits(unsigned long field, uint32_t mask)
{
	vmcs_writel(field, vmcs_readl(field) | mask);
}

void
vmx_fpu_activate(struct kvm_vcpu *vcpu)
{
	ulong cr0;

	if (vcpu->fpu_active)
		return;

	vcpu->fpu_active = 1;
	cr0 = vmcs_readl(GUEST_CR0);
	cr0 &= ~(X86_CR0_TS | X86_CR0_MP);
	cr0 |= kvm_read_cr0_bits(vcpu, X86_CR0_TS | X86_CR0_MP);
	vmcs_writel(GUEST_CR0, cr0);
	update_exception_bitmap(vcpu);
	vcpu->arch.cr0_guest_owned_bits = X86_CR0_TS;
	vmcs_writel(CR0_GUEST_HOST_MASK, ~vcpu->arch.cr0_guest_owned_bits);
}

static void
vmx_fpu_deactivate(struct kvm_vcpu *vcpu)
{
	vmx_decache_cr0_guest_bits(vcpu);
	vmcs_set_bits(GUEST_CR0, X86_CR0_TS | X86_CR0_MP);
	update_exception_bitmap(vcpu);
	vcpu->arch.cr0_guest_owned_bits = 0;
	vmcs_writel(CR0_GUEST_HOST_MASK, ~vcpu->arch.cr0_guest_owned_bits);
	vmcs_writel(CR0_READ_SHADOW, vcpu->arch.cr0);
}

#define	MSR_EFER		0xc0000080 /* extended feature register */

/* Intel-defined CPU features, CPUID level 0x00000001 (edx), word 0 */
#define	X86_FEATURE_FPU		(0 * 32 + 0)	/* Onboard FPU */
#define	X86_FEATURE_VME		(0 * 32 + 1)	/* Virtual Mode Extensions */
#define	X86_FEATURE_DE		(0 * 32 + 2)	/* Debugging Extensions */
#define	X86_FEATURE_PSE		(0 * 32 + 3)	/* Page Size Extensions */
#define	X86_FEATURE_TSC		(0 * 32 + 4)	/* Time Stamp Counter */
#define	X86_FEATURE_MSR		(0 * 32 + 5)	/* Model-Specific Registers */
#define	X86_FEATURE_PAE		(0 * 32 + 6)	/* Phys. Address Extensions */
#define	X86_FEATURE_MCE		(0 * 32 + 7)	/* Machine Check Exception */
#define	X86_FEATURE_CX8		(0 * 32 + 8)	/* CMPXCHG8 instruction */
#define	X86_FEATURE_APIC	(0 * 32 + 9)	/* Onboard APIC */
#define	X86_FEATURE_SEP		(0 * 32 + 11)	/* SYSENTER/SYSEXIT */
#define	X86_FEATURE_MTRR	(0 * 32 + 12)	/* Memory Type Range Regs. */
#define	X86_FEATURE_PGE		(0 * 32 + 13)	/* Page Global Enable */
#define	X86_FEATURE_MCA		(0 * 32 + 14)	/* Machine Check Architecture */
#define	X86_FEATURE_CMOV	(0 * 32 + 15)	/* CMOV instructions */
						/*  (+ FCMOVcc, FCOMI w/ FPU) */
#define	X86_FEATURE_PAT		(0 * 32 + 16)	/* Page Attribute Table */
#define	X86_FEATURE_PSE36	(0 * 32 + 17)	/* 36-bit PSEs */
#define	X86_FEATURE_PN		(0 * 32 + 18)	/* Processor serial number */
#define	X86_FEATURE_CLFLSH	(0 * 32 + 19)	/* "clflush" instruction */
#define	X86_FEATURE_DS		(0 * 32 + 21)	/* "dts" Debug Store */
#define	X86_FEATURE_ACPI	(0 * 32 + 22)	/* ACPI via MSR */
#define	X86_FEATURE_MMX		(0 * 32 + 23)	/* Multimedia Extensions */
#define	X86_FEATURE_FXSR	(0 * 32 + 24)	/* FXSAVE/FXRSTOR, CR4.OSFXSR */
#define	X86_FEATURE_XMM		(0 * 32 + 25)	/* "sse" */
#define	X86_FEATURE_XMM2	(0 * 32 + 26)	/* "sse2" */
#define	X86_FEATURE_SELFSNOOP	(0 * 32 + 27)	/* "ss" CPU self snoop */
#define	X86_FEATURE_HT		(0 * 32 + 28)	/* Hyper-Threading */
#define	X86_FEATURE_ACC		(0 * 32 + 29)	/* "tm" Auto. clock control */
#define	X86_FEATURE_IA64	(0 * 32 + 30)	/* IA-64 processor */
#define	X86_FEATURE_PBE		(0 * 32 + 31)	/* Pending Break Enable */

/* AMD-defined CPU features, CPUID level 0x80000001, word 1 */
/* Don't duplicate feature flags which are redundant with Intel! */
#define	X86_FEATURE_SYSCALL	(1 * 32 + 11)	/* SYSCALL/SYSRET */
#define	X86_FEATURE_MP		(1 * 32 + 19)	/* MP Capable. */
#define	X86_FEATURE_NX		(1 * 32 + 20)	/* Execute Disable */
#define	X86_FEATURE_MMXEXT	(1 * 32 + 22)	/* AMD MMX extensions */
#define	X86_FEATURE_FXSR_OPT	(1 * 32 + 25)	/* FXSAVE/FXRSTOR optimiztns */
#define	X86_FEATURE_GBPAGES	(1 * 32 + 26)	/* "pdpe1gb" GB pages */
#define	X86_FEATURE_RDTSCP	(1 * 32 + 27)	/* RDTSCP */
#define	X86_FEATURE_LM		(1 * 32 + 29)	/* Long Mode (x86-64) */
#define	X86_FEATURE_3DNOWEXT	(1 * 32 + 30)	/* AMD 3DNow! extensions */
#define	X86_FEATURE_3DNOW	(1 * 32 + 31)	/* 3DNow! */

/* cpu types for specific tunings: */
#define	X86_FEATURE_K8		(3 * 32 + 4)	/* "" Opteron, Athlon64 */
#define	X86_FEATURE_K7		(3 * 32 + 5)	/* "" Athlon */
#define	X86_FEATURE_P3		(3 * 32 + 6)	/* "" P3 */
#define	X86_FEATURE_P4		(3 * 32 + 7)	/* "" P4 */
#define	X86_FEATURE_CONSTANT_TSC (3 * 32 + 8)	/* TSC ticks at constant rate */
#define	X86_FEATURE_UP		(3 * 32 + 9)	/* smp kernel running on up */
#define	X86_FEATURE_FXSAVE_LEAK (3 * 32 + 10)	/* FXSAVE leaks FOP/FIP/FOP */
#define	X86_FEATURE_ARCH_PERFMON (3 * 32 + 11)	/* Intel Arch. PerfMon */
#define	X86_FEATURE_PEBS	(3 * 32 + 12)	/* Precise-Event Based Smplng */
#define	X86_FEATURE_BTS		(3 * 32 + 13)	/* Branch Trace Store */
#define	X86_FEATURE_SYSCALL32	(3 * 32 + 14)	/* syscall in ia32 userspace */
#define	X86_FEATURE_SYSENTER32	(3 * 32 + 15)	/* sysenter in ia32 userspace */
#define	X86_FEATURE_REP_GOOD	(3 * 32 + 16)	/* rep microcode works well */
#define	X86_FEATURE_MFENCE_RDTSC (3 * 32 + 17)	/* Mfence synchronizes RDTSC */
#define	X86_FEATURE_LFENCE_RDTSC (3 * 32 + 18)	/* Lfence synchronizes RDTSC */
#define	X86_FEATURE_11AP	(3 * 32 + 19)	/* Bad local APIC aka 11AP */
#define	X86_FEATURE_NOPL	(3 * 32 + 20)	/* NOPL (0F 1F) instructions */
#define	X86_FEATURE_AMDC1E	(3 * 32 + 21)	/* AMD C1E detected */
#define	X86_FEATURE_XTOPOLOGY	(3 * 32 + 22)	/* topology enum extensions */
#define	X86_FEATURE_TSC_RELIABLE (3 * 32 + 23)	/* TSC is reliable */
#define	X86_FEATURE_NONSTOP_TSC	(3 * 32 + 24) 	/* TSC continues in C states */
#define	X86_FEATURE_CLFLUSH_MONITOR (3 * 32 + 25) /* clflush reqd w/ monitor */
#define	X86_FEATURE_EXTD_APICID	(3 * 32 + 26)	/* extended APICID (8 bits) */
#define	X86_FEATURE_AMD_DCM	(3 * 32 + 27)	/* multi-node processor */
#define	X86_FEATURE_APERFMPERF	(3 * 32 + 28)	/* APERFMPERF */

/* Intel-defined CPU features, CPUID level 0x00000001 (ecx), word 4 */
#define	X86_FEATURE_XMM3	(4 * 32 + 0)	/* "pni" SSE-3 */
#define	X86_FEATURE_PCLMULQDQ	(4 * 32 + 1)	/* PCLMULQDQ instruction */
#define	X86_FEATURE_DTES64	(4 * 32 + 2)	/* 64-bit Debug Store */
#define	X86_FEATURE_MWAIT	(4 * 32 + 3)	/* "monitor" Monitor/Mwait */
#define	X86_FEATURE_DSCPL	(4 * 32 + 4)	/* ds_cpl CPL Qual Debug Str */
#define	X86_FEATURE_VMX		(4 * 32 + 5)	/* Hardware virtualization */
#define	X86_FEATURE_SMX		(4 * 32 + 6)	/* Safer mode */
#define	X86_FEATURE_EST		(4 * 32 + 7)	/* Enhanced SpeedStep */
#define	X86_FEATURE_TM2		(4 * 32 + 8)	/* Thermal Monitor 2 */
#define	X86_FEATURE_SSSE3	(4 * 32 + 9)	/* Supplemental SSE-3 */
#define	X86_FEATURE_CID		(4 * 32 + 10)	/* Context ID */
#define	X86_FEATURE_FMA		(4 * 32 + 12)	/* Fused multiply-add */
#define	X86_FEATURE_CX16	(4 * 32 + 13)	/* CMPXCHG16B */
#define	X86_FEATURE_XTPR	(4 * 32 + 14)	/* Send Task Priority Msgs */
#define	X86_FEATURE_PDCM	(4 * 32 + 15)	/* Performance Capabilities */
#define	X86_FEATURE_DCA		(4 * 32 + 18)	/* Direct Cache Access */
#define	X86_FEATURE_XMM4_1	(4 * 32 + 19)	/* "sse4_1" SSE-4.1 */
#define	X86_FEATURE_XMM4_2	(4 * 32 + 20)	/* "sse4_2" SSE-4.2 */
#define	X86_FEATURE_X2APIC	(4 * 32 + 21)	/* x2APIC */
#define	X86_FEATURE_MOVBE	(4 * 32 + 22)	/* MOVBE instruction */
#define	X86_FEATURE_POPCNT	(4 * 32 + 23)	/* POPCNT instruction */
#define	X86_FEATURE_AES		(4 * 32 + 25)	/* AES instructions */
#define	X86_FEATURE_XSAVE	(4 * 32 + 26)	/* XSAVE/XRSTOR/XSETBV/XGETBV */
#define	X86_FEATURE_OSXSAVE	(4 * 32 + 27)	/* "" XSAVE enabled in the OS */
#define	X86_FEATURE_AVX		(4 * 32 + 28)	/* Advanced Vector Extensions */
#define	X86_FEATURE_HYPERVISOR	(4 * 32 + 31)	/* Running on a hypervisor */

/* More extended AMD flags: CPUID level 0x80000001, ecx, word 6 */
#define	X86_FEATURE_LAHF_LM	(6 * 32 + 0)	/* LAHF/SAHF in long mode */
#define	X86_FEATURE_CMP_LEGACY	(6 * 32 + 1)	/* HyperThreading invalid */
#define	X86_FEATURE_SVM		(6 * 32 + 2)	/* Secure virtual machine */
#define	X86_FEATURE_EXTAPIC	(6 * 32 + 3)	/* Extended APIC space */
#define	X86_FEATURE_CR8_LEGACY	(6 * 32 + 4)	/* CR8 in 32-bit mode */
#define	X86_FEATURE_ABM		(6 * 32 + 5)	/* Advanced bit manipulation */
#define	X86_FEATURE_SSE4A	(6 * 32 + 6)	/* SSE-4A */
#define	X86_FEATURE_MISALIGNSSE (6 * 32 + 7)	/* Misaligned SSE mode */
#define	X86_FEATURE_3DNOWPREFETCH (6 * 32 + 8)	/* 3DNow prefetch */
#define	X86_FEATURE_OSVW	(6 * 32 + 9)	/* OS Visible Workaround */
#define	X86_FEATURE_IBS		(6 * 32 + 10)	/* Instruction Based Sampling */
#define	X86_FEATURE_SSE5	(6 * 32 + 11)	/* SSE-5 */
#define	X86_FEATURE_SKINIT	(6 * 32 + 12)	/* SKINIT/STGI instructions */
#define	X86_FEATURE_WDT		(6 * 32 + 13)	/* Watchdog timer */
#define	X86_FEATURE_NODEID_MSR	(6 * 32 + 19)	/* NodeId MSR */

/* Transmeta-defined CPU features, CPUID level 0x80860001, word 2 */
#define	X86_FEATURE_RECOVERY	(2 * 32 + 0)	/* CPU in recovery mode */
#define	X86_FEATURE_LONGRUN	(2 * 32 + 1)	/* Longrun power control */
#define	X86_FEATURE_LRTI	(2 * 32 + 3)	/* LongRun table interface */


struct kvm_cpuid_entry2 *kvm_find_cpuid_entry(struct kvm_vcpu *vcpu,
    uint32_t function, uint32_t index);

static inline uint32_t
bit(int bitno)
{
	return (1 << (bitno & 31));
}

static void
vmx_cpuid_update(struct kvm_vcpu *vcpu)
{
	struct kvm_cpuid_entry2 *best;
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	uint32_t exec_control;

	vmx->rdtscp_enabled = 0;

	if (vmx_rdtscp_supported()) {
		exec_control = vmcs_read32(SECONDARY_VM_EXEC_CONTROL);
		if (exec_control & SECONDARY_EXEC_RDTSCP) {
			best = kvm_find_cpuid_entry(vcpu, 0x80000001, 0);
			if (best && (best->edx & bit(X86_FEATURE_RDTSCP)))
				vmx->rdtscp_enabled = 1;
			else {
				exec_control &= ~SECONDARY_EXEC_RDTSCP;
				vmcs_write32(SECONDARY_VM_EXEC_CONTROL,
						exec_control);
			}
		}
	}
}

static void
enable_irq_window(struct kvm_vcpu *vcpu)
{
	uint32_t cpu_based_vm_exec_control;

	cpu_based_vm_exec_control = vmcs_read32(CPU_BASED_VM_EXEC_CONTROL);
	cpu_based_vm_exec_control |= CPU_BASED_VIRTUAL_INTR_PENDING;
	vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, cpu_based_vm_exec_control);
}

extern struct vmcs_config vmcs_config;

static inline int
cpu_has_virtual_nmis(void)
{
	return (vmcs_config.pin_based_exec_ctrl & PIN_BASED_VIRTUAL_NMIS);
}

static void
enable_nmi_window(struct kvm_vcpu *vcpu)
{
	uint32_t cpu_based_vm_exec_control;

	if (!cpu_has_virtual_nmis()) {
		enable_irq_window(vcpu);
		return;
	}

	cpu_based_vm_exec_control = vmcs_read32(CPU_BASED_VM_EXEC_CONTROL);
	cpu_based_vm_exec_control |= CPU_BASED_VIRTUAL_NMI_PENDING;
	vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, cpu_based_vm_exec_control);
}

static void
vmx_set_nmi_mask(struct kvm_vcpu *vcpu, int masked)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	if (!cpu_has_virtual_nmis()) {
		if (vmx->soft_vnmi_blocked != masked) {
			vmx->soft_vnmi_blocked = masked;
			vmx->vnmi_blocked_time = 0;
		}

		return;
	} else {
		if (masked) {
			vmcs_set_bits(GUEST_INTERRUPTIBILITY_INFO,
			    GUEST_INTR_STATE_NMI);
		} else {
			vmcs_clear_bits(GUEST_INTERRUPTIBILITY_INFO,
			    GUEST_INTR_STATE_NMI);
		}
	}
}

static int
vmx_get_nmi_mask(struct kvm_vcpu *vcpu)
{
	if (!cpu_has_virtual_nmis())
		return (to_vmx(vcpu)->soft_vnmi_blocked);
	else
		return (!!(vmcs_read32(GUEST_INTERRUPTIBILITY_INFO) &
		    GUEST_INTR_STATE_NMI));
}

static int
vmx_nmi_allowed(struct kvm_vcpu *vcpu)
{
	if (!cpu_has_virtual_nmis() && to_vmx(vcpu)->soft_vnmi_blocked)
		return (0);

	return (!(vmcs_read32(GUEST_INTERRUPTIBILITY_INFO) &
	    (GUEST_INTR_STATE_MOV_SS | GUEST_INTR_STATE_NMI)));
}

static inline unsigned long
kvm_register_read(struct kvm_vcpu *vcpu, enum kvm_reg reg)
{
	if (!test_bit(reg, (unsigned long *)&vcpu->arch.regs_avail))
		kvm_x86_ops->cache_reg(vcpu, reg);

	return (vcpu->arch.regs[reg]);
}

inline void
kvm_register_write(struct kvm_vcpu *vcpu, enum kvm_reg reg, unsigned long val)
{
	vcpu->arch.regs[reg] = val;
	__set_bit(reg, (unsigned long *)&vcpu->arch.regs_dirty);
	__set_bit(reg, (unsigned long *)&vcpu->arch.regs_avail);
}

inline unsigned long
kvm_rip_read(struct kvm_vcpu *vcpu)
{
	return (kvm_register_read(vcpu, VCPU_REGS_RIP));
}

inline void
kvm_rip_write(struct kvm_vcpu *vcpu, unsigned long val)
{
	kvm_register_write(vcpu, VCPU_REGS_RIP, val);
}

static inline int
kvm_exception_is_soft(unsigned int nr)
{
	return (nr == BP_VECTOR) || (nr == OF_VECTOR);
}

static void
vmx_queue_exception(struct kvm_vcpu *vcpu, unsigned nr,
    int has_error_code, uint32_t error_code)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	uint32_t intr_info = nr | INTR_INFO_VALID_MASK;

	if (has_error_code) {
		vmcs_write32(VM_ENTRY_EXCEPTION_ERROR_CODE, error_code);
		intr_info |= INTR_INFO_DELIVER_CODE_MASK;
	}

	if (vmx->rmode.vm86_active) {
		vmx->rmode.irq.pending = 1;
		vmx->rmode.irq.vector = nr;
		vmx->rmode.irq.rip = kvm_rip_read(vcpu);
		if (kvm_exception_is_soft(nr))
			vmx->rmode.irq.rip +=
				vmx->vcpu.arch.event_exit_inst_len;
		intr_info |= INTR_TYPE_SOFT_INTR;
		vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, intr_info);
		vmcs_write32(VM_ENTRY_INSTRUCTION_LEN, 1);
		kvm_rip_write(vcpu, vmx->rmode.irq.rip - 1);
		return;
	}

	if (kvm_exception_is_soft(nr)) {
		vmcs_write32(VM_ENTRY_INSTRUCTION_LEN,
		    vmx->vcpu.arch.event_exit_inst_len);
		intr_info |= INTR_TYPE_SOFT_EXCEPTION;
	} else
		intr_info |= INTR_TYPE_HARD_EXCEPTION;

	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, intr_info);
}

static void
vmx_inject_nmi(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	if (!cpu_has_virtual_nmis()) {
		/*
		 * Tracking the NMI-blocked state in software is built upon
		 * finding the next open IRQ window. This, in turn, depends on
		 * well-behaving guests: They have to keep IRQs disabled at
		 * least as long as the NMI handler runs. Otherwise we may
		 * cause NMI nesting, maybe breaking the guest. But as this is
		 * highly unlikely, we can live with the residual risk.
		 */
		vmx->soft_vnmi_blocked = 1;
		vmx->vnmi_blocked_time = 0;
	}

#ifdef XXX_KVM_STAT
	++vcpu->stat.nmi_injections;
#endif
	if (vmx->rmode.vm86_active) {
		vmx->rmode.irq.pending = 1;
		vmx->rmode.irq.vector = NMI_VECTOR;
		vmx->rmode.irq.rip = kvm_rip_read(vcpu);
		vmcs_write32(VM_ENTRY_INTR_INFO_FIELD,
		    NMI_VECTOR | INTR_TYPE_SOFT_INTR |
		    INTR_INFO_VALID_MASK);
		vmcs_write32(VM_ENTRY_INSTRUCTION_LEN, 1);
		kvm_rip_write(vcpu, vmx->rmode.irq.rip - 1);
		return;
	}
	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD,
	    INTR_TYPE_NMI_INTR | INTR_INFO_VALID_MASK | NMI_VECTOR);
}

static void
vmx_inject_irq(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	uint32_t intr;
	int irq = vcpu->arch.interrupt.nr;

#ifdef XXX_KVM_TRACE
	trace_kvm_inj_virq(irq);
#endif
#ifdef XXX_KVM_STAT
	++vcpu->stat.irq_injections;
#endif
	if (vmx->rmode.vm86_active) {
		vmx->rmode.irq.pending = 1;
		vmx->rmode.irq.vector = irq;
		vmx->rmode.irq.rip = kvm_rip_read(vcpu);
		if (vcpu->arch.interrupt.soft)
			vmx->rmode.irq.rip +=
				vmx->vcpu.arch.event_exit_inst_len;
		vmcs_write32(VM_ENTRY_INTR_INFO_FIELD,
		    irq | INTR_TYPE_SOFT_INTR | INTR_INFO_VALID_MASK);
		vmcs_write32(VM_ENTRY_INSTRUCTION_LEN, 1);
		kvm_rip_write(vcpu, vmx->rmode.irq.rip - 1);
		return;
	}
	intr = irq | INTR_INFO_VALID_MASK;
	if (vcpu->arch.interrupt.soft) {
		intr |= INTR_TYPE_SOFT_INTR;
		vmcs_write32(VM_ENTRY_INSTRUCTION_LEN,
		    vmx->vcpu.arch.event_exit_inst_len);
	} else
		intr |= INTR_TYPE_EXT_INTR;

	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, intr);
}


static void
vmx_get_idt(struct kvm_vcpu *vcpu, struct descriptor_table *dt)
{
	dt->limit = vmcs_read32(GUEST_IDTR_LIMIT);
	dt->base = vmcs_readl(GUEST_IDTR_BASE);
}

static void
vmx_set_idt(struct kvm_vcpu *vcpu, struct descriptor_table *dt)
{
	vmcs_write32(GUEST_IDTR_LIMIT, dt->limit);
	vmcs_writel(GUEST_IDTR_BASE, dt->base);
}

static void
vmx_get_gdt(struct kvm_vcpu *vcpu, struct descriptor_table *dt)
{
	dt->limit = vmcs_read32(GUEST_GDTR_LIMIT);
	dt->base = vmcs_readl(GUEST_GDTR_BASE);
}

static void
vmx_set_gdt(struct kvm_vcpu *vcpu, struct descriptor_table *dt)
{
	vmcs_write32(GUEST_GDTR_LIMIT, dt->limit);
	vmcs_writel(GUEST_GDTR_BASE, dt->base);
}

static uint32_t
vmx_get_interrupt_shadow(struct kvm_vcpu *vcpu, int mask)
{
	uint32_t interruptibility = vmcs_read32(GUEST_INTERRUPTIBILITY_INFO);
	int ret = 0;

	if (interruptibility & GUEST_INTR_STATE_STI)
		ret |= X86_SHADOW_INT_STI;
	if (interruptibility & GUEST_INTR_STATE_MOV_SS)
		ret |= X86_SHADOW_INT_MOV_SS;

	return (ret & mask);
}

static void
vmx_set_interrupt_shadow(struct kvm_vcpu *vcpu, int mask)
{
	uint32_t old = vmcs_read32(GUEST_INTERRUPTIBILITY_INFO);
	uint32_t interruptibility = old;

	interruptibility &= ~(GUEST_INTR_STATE_STI | GUEST_INTR_STATE_MOV_SS);

	if (mask & X86_SHADOW_INT_MOV_SS)
		interruptibility |= GUEST_INTR_STATE_MOV_SS;
	if (mask & X86_SHADOW_INT_STI)
		interruptibility |= GUEST_INTR_STATE_STI;

	if ((interruptibility != old))
		vmcs_write32(GUEST_INTERRUPTIBILITY_INFO, interruptibility);
}

static void
skip_emulated_instruction(struct kvm_vcpu *vcpu)
{
	unsigned long rip;

	rip = kvm_rip_read(vcpu);
	rip += vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
	kvm_rip_write(vcpu, rip);

	/* skipping an emulated instruction also counts */
	vmx_set_interrupt_shadow(vcpu, 0);
}

/*
 * In linux, there is a separate vmx kernel module from the kvm driver.
 * That may be a good idea, but we're going to do everything in
 * the kvm driver, for now.
 * The call to vmx_init() in _init() is done when the vmx module
 * is loaded on linux.
 */

struct vmcs **vmxarea;  /* 1 per cpu */

static int
alloc_kvm_area(void)
{
	int i, j;

	/*
	 * linux seems to do the allocations in a numa-aware
	 * fashion.  We'll just allocate...
	 */
	vmxarea = kmem_alloc(ncpus * sizeof (struct vmcs *), KM_SLEEP);

	for (i = 0; i < ncpus; i++) {
		struct vmcs *vmcs;

		/* XXX the following assumes PAGESIZE allocations */
		/* are PAGESIZE aligned.  We could enforce this */
		/* via kmem_cache_create, but I'm lazy */
		vmcs = kmem_zalloc(PAGESIZE, KM_SLEEP);
		vmxarea[i] = vmcs;
	}

	return (0);
}

static int
adjust_vmx_controls(uint32_t ctl_min, uint32_t ctl_opt,
    uint32_t msr, uint32_t *result)
{
	uint32_t vmx_msr_low, vmx_msr_high;
	uint32_t ctl = ctl_min | ctl_opt;

	rdmsr(msr, vmx_msr_low, vmx_msr_high);

	ctl &= vmx_msr_high; /* bit == 0 in high word ==> must be zero */
	ctl |= vmx_msr_low;  /* bit == 1 in low word  ==> must be one  */

	/* Ensure minimum (required) set of control bits are supported. */
	if (ctl_min & ~ctl)
		return (EIO);

	*result = ctl;
	return (DDI_SUCCESS);
}

/* Pure 2^n version of get_order */
static inline int
get_order(unsigned long size)
{
	int order;

	size = (size - 1) >> (PAGESHIFT - 1);
	order = -1;
	do {
		size >>= 1;
		order++;
	} while (size);

	return (order);
}

static int
setup_vmcs_config(struct vmcs_config *vmcs_conf)
{
	uint32_t vmx_msr_low, vmx_msr_high;
	uint32_t min, opt, min2, opt2;
	uint32_t _pin_based_exec_control = 0;
	uint32_t _cpu_based_exec_control = 0;
	uint32_t _cpu_based_2nd_exec_control = 0;
	uint32_t _vmexit_control = 0;
	uint32_t _vmentry_control = 0;
	uint32_t ept, vpid;

	min = PIN_BASED_EXT_INTR_MASK | PIN_BASED_NMI_EXITING;
	opt = PIN_BASED_VIRTUAL_NMIS;
	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_PINBASED_CTLS,
	    &_pin_based_exec_control) != DDI_SUCCESS)
		return (EIO);

	min = CPU_BASED_HLT_EXITING |
#ifdef CONFIG_X86_64
	    CPU_BASED_CR8_LOAD_EXITING |
	    CPU_BASED_CR8_STORE_EXITING |
#endif
	    CPU_BASED_CR3_LOAD_EXITING |
	    CPU_BASED_CR3_STORE_EXITING |
	    CPU_BASED_USE_IO_BITMAPS |
	    CPU_BASED_MOV_DR_EXITING |
	    CPU_BASED_USE_TSC_OFFSETING |
	    CPU_BASED_MWAIT_EXITING |
	    CPU_BASED_MONITOR_EXITING |
	    CPU_BASED_INVLPG_EXITING;

	opt = CPU_BASED_TPR_SHADOW |
	    CPU_BASED_USE_MSR_BITMAPS |
	    CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;

	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_PROCBASED_CTLS,
	    &_cpu_based_exec_control) != DDI_SUCCESS)
		return (EIO);

#ifdef CONFIG_X86_64
	if ((_cpu_based_exec_control & CPU_BASED_TPR_SHADOW))
		_cpu_based_exec_control &= ~CPU_BASED_CR8_LOAD_EXITING &
		    ~CPU_BASED_CR8_STORE_EXITING;
#endif
	if (_cpu_based_exec_control & CPU_BASED_ACTIVATE_SECONDARY_CONTROLS) {
		min2 = 0;
		opt2 = SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES |
		    SECONDARY_EXEC_WBINVD_EXITING |
		    SECONDARY_EXEC_ENABLE_VPID |
		    SECONDARY_EXEC_ENABLE_EPT |
		    SECONDARY_EXEC_UNRESTRICTED_GUEST |
		    SECONDARY_EXEC_PAUSE_LOOP_EXITING |
		    SECONDARY_EXEC_RDTSCP;

		if (adjust_vmx_controls(min2, opt2,
		    MSR_IA32_VMX_PROCBASED_CTLS2,
		    &_cpu_based_2nd_exec_control) != DDI_SUCCESS)
			return (EIO);
	}
#ifndef CONFIG_X86_64
	if (!(_cpu_based_2nd_exec_control &
				SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES))
		_cpu_based_exec_control &= ~CPU_BASED_TPR_SHADOW;
#endif
	if (_cpu_based_2nd_exec_control & SECONDARY_EXEC_ENABLE_EPT) {
		/*
		 * CR3 accesses and invlpg don't need to cause VM Exits when EPT
		 * enabled
		 */
		_cpu_based_exec_control &= ~(CPU_BASED_CR3_LOAD_EXITING |
		    CPU_BASED_CR3_STORE_EXITING | CPU_BASED_INVLPG_EXITING);
		rdmsr(MSR_IA32_VMX_EPT_VPID_CAP, vmx_capability.ept,
		    vmx_capability.vpid);
	}

	min = 0;
#ifdef CONFIG_X86_64
	min |= VM_EXIT_HOST_ADDR_SPACE_SIZE;
#endif
	opt = VM_EXIT_SAVE_IA32_PAT | VM_EXIT_LOAD_IA32_PAT;
	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_EXIT_CTLS,
	    &_vmexit_control) != DDI_SUCCESS)
		return (EIO);

	min = 0;
	opt = VM_ENTRY_LOAD_IA32_PAT;
	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_ENTRY_CTLS,
	    &_vmentry_control) != DDI_SUCCESS)
		return (EIO);

	rdmsr(MSR_IA32_VMX_BASIC, vmx_msr_low, vmx_msr_high);

	/* IA-32 SDM Vol 3B: VMCS size is never greater than 4kB. */
	if ((vmx_msr_high & 0x1fff) > PAGESIZE)
		return (EIO);

#ifdef CONFIG_X86_64
	/* IA-32 SDM Vol 3B: 64-bit CPUs always have VMX_BASIC_MSR[48]==0. */
	if (vmx_msr_high & (1u<<16))
		return (EIO);
#endif

	/* Require Write-Back (WB) memory type for VMCS accesses. */
	if (((vmx_msr_high >> 18) & 15) != 6)
		return (EIO);

	vmcs_conf->size = vmx_msr_high & 0x1fff;
	vmcs_conf->order = get_order(vmcs_config.size);
	vmcs_conf->revision_id = vmx_msr_low;

	vmcs_conf->pin_based_exec_ctrl = _pin_based_exec_control;
	vmcs_conf->cpu_based_exec_ctrl = _cpu_based_exec_control;
	vmcs_conf->cpu_based_2nd_exec_ctrl = _cpu_based_2nd_exec_control;
	vmcs_conf->vmexit_ctrl = _vmexit_control;
	vmcs_conf->vmentry_ctrl = _vmentry_control;

	return (0);
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

static int bypass_guest_pf = 1;
int enable_vpid = 1;
int enable_unrestricted_guest = 1;
int emulate_invalid_guest_state = 0;

void
kvm_enable_efer_bits(uint64_t mask)
{
	efer_reserved_bits &= ~mask;
}

static inline int
cpu_has_vmx_vpid(void)
{
	return (vmcs_config.cpu_based_2nd_exec_ctrl &
	    SECONDARY_EXEC_ENABLE_VPID);
}

static inline int
cpu_has_vmx_ept(void)
{
	return (vmcs_config.cpu_based_2nd_exec_ctrl &
	    SECONDARY_EXEC_ENABLE_EPT);
}

static inline int
cpu_has_vmx_unrestricted_guest(void)
{
	return (vmcs_config.cpu_based_2nd_exec_ctrl &
	    SECONDARY_EXEC_UNRESTRICTED_GUEST);
}

inline int
cpu_has_vmx_tpr_shadow(void)
{
	return (vmcs_config.cpu_based_exec_ctrl & CPU_BASED_TPR_SHADOW);
}

static inline int
cpu_has_vmx_virtualize_apic_accesses(void)
{
	return (vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES);
}

static inline int
cpu_has_vmx_flexpriority(void)
{
	return (cpu_has_vmx_tpr_shadow() &&
		cpu_has_vmx_virtualize_apic_accesses());
}

static inline int
cpu_has_vmx_ept_2m_page(void)
{
	return (!!(vmx_capability.ept & VMX_EPT_2MB_PAGE_BIT));
}

void
kvm_disable_largepages(void)
{
	largepages_enabled = 0;
}

static inline int
cpu_has_vmx_ple(void)
{
	return (vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_PAUSE_LOOP_EXITING);
}

/*
 * These 2 parameters are used to config the controls for Pause-Loop Exiting:
 * ple_gap:    upper bound on the amount of time between two successive
 *             executions of PAUSE in a loop. Also indicate if ple enabled.
 *             According to test, this time is usually small than 41 cycles.
 * ple_window: upper bound on the amount of time a guest is allowed to execute
 *             in a PAUSE loop. Tests indicate that most spinlocks are held for
 *             less than 2^12 cycles
 * Time is measured based on a counter that runs at the same rate as the TSC,
 * refer SDM volume 3b section 21.6.13 & 22.1.3.
 */
#define	KVM_VMX_EFAULT_PLE_GAP    41
#define	KVM_VMX_DEFAULT_PLE_WINDOW 4096
static int ple_gap = KVM_VMX_DEFAULT_PLE_GAP;
static int ple_window = KVM_VMX_DEFAULT_PLE_WINDOW;

static int
vmx_hardware_setup(void)
{
	if (setup_vmcs_config(&vmcs_config) != DDI_SUCCESS)
		return (EIO);
#ifdef XXX
	if (boot_cpu_has(X86_FEATURE_NX))
#else
	XXX_KVM_PROBE;
#endif
		kvm_enable_efer_bits(EFER_NX);

	if (!cpu_has_vmx_vpid())
		enable_vpid = 0;

	if (!cpu_has_vmx_ept()) {
		enable_ept = 0;
		enable_unrestricted_guest = 0;
	}

	if (!cpu_has_vmx_unrestricted_guest())
		enable_unrestricted_guest = 0;
	if (!cpu_has_vmx_flexpriority())
		flexpriority_enabled = 0;

	if (!cpu_has_vmx_tpr_shadow())
		kvm_x86_ops->update_cr8_intercept = NULL;

	if (enable_ept && !cpu_has_vmx_ept_2m_page())
		kvm_disable_largepages();

	if (!cpu_has_vmx_ple())
		ple_gap = 0;


	return (alloc_kvm_area());
}

int
kvm_arch_hardware_setup(void)
{
	return (kvm_x86_ops->hardware_setup());
}

struct kmem_cache *pte_chain_cache;
struct kmem_cache *rmap_desc_cache;
struct kmem_cache *mmu_page_header_cache;

int tdp_enabled = 0;

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

#define	virt_to_page(addr) pfn_to_page(hat_getpfnum(kas.a_hat, addr))

static struct kvm_mmu_page *
kvm_mmu_alloc_page(struct kvm_vcpu *vcpu, uint64_t *parent_pte)
{
	struct kvm_mmu_page *sp;

	sp = mmu_memory_cache_alloc(&vcpu->arch.mmu_page_header_cache,
	    sizeof (*sp));
	sp->spt = mmu_memory_cache_alloc(&vcpu->arch.mmu_page_cache, PAGESIZE);
	sp->gfns = mmu_memory_cache_alloc(&vcpu->arch.mmu_page_cache, PAGESIZE);
#ifndef XXX
	set_page_private(virt_to_page((caddr_t)sp->spt), (void *)sp);
#else
	XXX_KVM_PROBE;
	sp->hpa = (hat_getpfnum(kas.a_hat, (caddr_t)sp->spt)<< PAGESHIFT);
#endif
	list_insert_head(&vcpu->kvm->arch.active_mmu_pages, sp);
#ifdef XXX
	/* XXX don't see this used anywhere */
	INIT_LIST_HEAD(&sp->oos_link);
#else
	XXX_KVM_PROBE;
#endif
	bitmap_zero(sp->slot_bitmap, KVM_MEMORY_SLOTS + KVM_PRIVATE_MEM_SLOTS);
	sp->multimapped = 0;
	sp->parent_pte = parent_pte;
	--vcpu->kvm->arch.n_free_mmu_pages;
	return (sp);
}

typedef int (*mmu_parent_walk_fn) (struct kvm_vcpu *, struct kvm_mmu_page *);

extern uint64_t kvm_va2pa(caddr_t va);

struct kvm_mmu_page *
page_private(page_t *page)
{
	return ((struct kvm_mmu_page *)page->p_private);
}

inline struct kvm_mmu_page *
page_header(hpa_t shadow_page)
{
	return (page_private(pfn_to_page(shadow_page >> PAGESHIFT)));
}

static void
mmu_parent_walk(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp,
    mmu_parent_walk_fn fn)
{
	struct kvm_pte_chain *pte_chain;
	struct hlist_node *node;
	struct kvm_mmu_page *parent_sp;
	int i;

	if (!sp->multimapped && sp->parent_pte) {
		parent_sp = page_header(kvm_va2pa((caddr_t)sp->parent_pte));

		fn(vcpu, parent_sp);
		mmu_parent_walk(vcpu, parent_sp, fn);
		return;
	}

	for (pte_chain = list_head(&sp->parent_ptes); pte_chain != NULL;
	    pte_chain = list_next(&sp->parent_ptes, pte_chain)) {
		for (i = 0; i < NR_PTE_CHAIN_ENTRIES; ++i) {
			if (!pte_chain->parent_ptes[i])
				break;

			parent_sp = page_header(kvm_va2pa(
			    (caddr_t)pte_chain->parent_ptes[i]));
			fn(vcpu, parent_sp);
			mmu_parent_walk(vcpu, parent_sp, fn);
		}
	}
}

static void
kvm_mmu_update_unsync_bitmap(uint64_t *spte, struct kvm *kvm)
{
	unsigned int index;
	struct kvm_mmu_page *sp = page_header(kvm_va2pa((caddr_t)spte));

	index = spte - sp->spt;
	if (!__test_and_set_bit(index, sp->unsync_child_bitmap))
		sp->unsync_children++;
}

static void
kvm_mmu_update_parents_unsync(struct kvm_mmu_page *sp, struct kvm *kvm)
{
	struct kvm_pte_chain *pte_chain;
	int i;

	if (!sp->parent_pte)
		return;

	if (!sp->multimapped) {
		kvm_mmu_update_unsync_bitmap(sp->parent_pte, kvm);
		return;
	}

	for (pte_chain = list_head(&sp->parent_ptes); pte_chain != NULL;
	    pte_chain = list_next(&sp->parent_ptes, pte_chain)) {
		for (i = 0; i < NR_PTE_CHAIN_ENTRIES; ++i) {
			if (!pte_chain->parent_ptes[i])
				break;
			kvm_mmu_update_unsync_bitmap(pte_chain->parent_ptes[i],
			    kvm);
		}
	}
}

static int
unsync_walk_fn(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp)
{
	kvm_mmu_update_parents_unsync(sp, vcpu->kvm);
	return (1);
}

void
kvm_mmu_mark_parents_unsync(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp)
{
	mmu_parent_walk(vcpu, sp, unsync_walk_fn);
	kvm_mmu_update_parents_unsync(sp, vcpu->kvm);
}

unsigned
kvm_page_table_hashfn(gfn_t gfn)
{
	return (gfn & ((1 << KVM_MMU_HASH_SHIFT) - 1));
}

static struct kvm_pte_chain *
mmu_alloc_pte_chain(struct kvm_vcpu *vcpu)
{
	return (mmu_memory_cache_alloc(&vcpu->arch.mmu_pte_chain_cache,
	    sizeof (struct kvm_pte_chain)));
}

static void
mmu_page_add_parent_pte(struct kvm_vcpu *vcpu,
    struct kvm_mmu_page *sp, uint64_t *parent_pte)
{
	struct kvm_pte_chain *pte_chain;
	struct hlist_node *node;
	int i;

	if (!parent_pte)
		return;
	if (!sp->multimapped) {
		uint64_t *old = sp->parent_pte;

		if (!old) {
			sp->parent_pte = parent_pte;
			return;
		}
		sp->multimapped = 1;
		pte_chain = mmu_alloc_pte_chain(vcpu);
		list_create(&sp->parent_ptes, sizeof (struct kvm_pte_chain),
			    offsetof(struct kvm_pte_chain, link));
		list_insert_head(&sp->parent_ptes, pte_chain);
		pte_chain->parent_ptes[0] = old;
	}

	for (pte_chain = list_head(&sp->parent_ptes); pte_chain != NULL;
	    pte_chain = list_next(&sp->parent_ptes, pte_chain)) {
		if (pte_chain->parent_ptes[NR_PTE_CHAIN_ENTRIES-1])
			continue;
		for (i = 0; i < NR_PTE_CHAIN_ENTRIES; ++i) {
			if (!pte_chain->parent_ptes[i]) {
				pte_chain->parent_ptes[i] = parent_pte;
				return;
			}
		}
	}

	pte_chain = mmu_alloc_pte_chain(vcpu);
	list_insert_head(&sp->parent_ptes, pte_chain);
	pte_chain->parent_ptes[0] = parent_pte;
}

uint64_t shadow_trap_nonpresent_pte;
uint64_t shadow_notrap_nonpresent_pte;
uint64_t shadow_base_present_pte;
uint64_t shadow_nx_mask;
uint64_t shadow_x_mask;	/* mutual exclusive with nx_mask */
uint64_t shadow_user_mask;
uint64_t shadow_accessed_mask;
uint64_t shadow_dirty_mask;

static void kvm_unlink_unsync_page(struct kvm *kvm, struct kvm_mmu_page *sp)
{
	sp->unsync = 0;
}

static void
kvm_mmu_pages_init(struct kvm_mmu_page *parent, struct mmu_page_path *parents,
    struct kvm_mmu_pages *pvec)
{
	parents->parent[parent->role.level-1] = NULL;
	pvec->nr = 0;
}

static void
mmu_pages_clear_parents(struct mmu_page_path *parents)
{
	struct kvm_mmu_page *sp;
	unsigned int level = 0;

	do {
		unsigned int idx = parents->idx[level];

		sp = parents->parent[level];
		if (!sp)
			return;

		--sp->unsync_children;
#ifdef XXX
		WARN_ON((int)sp->unsync_children < 0);
#else
		XXX_KVM_PROBE;
#endif
		__clear_bit(idx, sp->unsync_child_bitmap);
		level++;
	} while (level < PT64_ROOT_LEVEL-1 && !sp->unsync_children);
}

static void
kvm_mmu_free_page(struct kvm *kvm, struct kvm_mmu_page *sp)
{
#ifdef XXX
	ASSERT(is_empty_shadow_page(sp->spt));
	list_del(&sp->link);
	__free_page(virt_to_page(sp->spt));
	__free_page(virt_to_page(sp->gfns));
#else
	XXX_KVM_PROBE;
#endif

	list_remove(&kvm->arch.active_mmu_pages, sp);
	if (sp)
		kmem_cache_free(mmu_page_header_cache, sp);
	++kvm->arch.n_free_mmu_pages;
}

static int
mmu_pages_add(struct kvm_mmu_pages *pvec, struct kvm_mmu_page *sp, int idx)
{
	int i;

	if (sp->unsync) {
		for (i = 0; i < pvec->nr; i++) {
			if (pvec->page[i].sp == sp)
				return (0);
		}
	}

	pvec->page[pvec->nr].sp = sp;
	pvec->page[pvec->nr].idx = idx;
	pvec->nr++;

	return (pvec->nr == KVM_PAGE_ARRAY_NR);
}

int
is_large_pte(uint64_t pte)
{
	return (pte & PT_PAGE_SIZE_MASK);
}

extern int is_shadow_present_pte(uint64_t pte);

static int
__mmu_unsync_walk(struct kvm_mmu_page *sp, struct kvm_mmu_pages *pvec,
    struct kvm *kvm)
{
	int i, ret, nr_unsync_leaf = 0;

	for_each_unsync_children(sp->unsync_child_bitmap, i) {
		uint64_t ent = sp->spt[i];

		if (is_shadow_present_pte(ent) && !is_large_pte(ent)) {
			struct kvm_mmu_page *child;
			child = page_header(ent & PT64_BASE_ADDR_MASK);

			if (child->unsync_children) {
				if (mmu_pages_add(pvec, child, i))
					return (-ENOSPC);
				ret = __mmu_unsync_walk(child, pvec, kvm);
				if (!ret) {
					__clear_bit(i, sp->unsync_child_bitmap);
				} else if (ret > 0)
					nr_unsync_leaf += ret;
				else
					return (ret);
			}

			if (child->unsync) {
				nr_unsync_leaf++;
				if (mmu_pages_add(pvec, child, i))
					return (-ENOSPC);
			}
		}
	}

	if (bt_getlowbit(sp->unsync_child_bitmap, 0, 512) == 512)
		sp->unsync_children = 0;

	return (nr_unsync_leaf);
}

static int
mmu_unsync_walk(struct kvm_mmu_page *sp,
    struct kvm_mmu_pages *pvec, struct kvm *kvm)
{
	if (!sp->unsync_children)
		return (0);

	mmu_pages_add(pvec, sp, 0);
	return (__mmu_unsync_walk(sp, pvec, kvm));
}

static int mmu_pages_next(struct kvm_mmu_pages *pvec,
    struct mmu_page_path *parents, int i);

#define	for_each_sp(pvec, sp, parents, i)				\
		for (i = mmu_pages_next(&pvec, &parents, -1),		\
			sp = pvec.page[i].sp;				\
			/*CSTYLED*/					\
			i < pvec.nr && ({ sp = pvec.page[i].sp; 1; });	\
			i = mmu_pages_next(&pvec, &parents, i))

int kvm_mmu_zap_page(struct kvm *kvm, struct kvm_mmu_page *sp);

static int
mmu_zap_unsync_children(struct kvm *kvm, struct kvm_mmu_page *parent)
{
	int i, zapped = 0;
	struct mmu_page_path parents;
	struct kvm_mmu_pages pages;

	if (parent->role.level == PT_PAGE_TABLE_LEVEL)
		return (0);

	kvm_mmu_pages_init(parent, &parents, &pages);
	while (mmu_unsync_walk(parent, &pages, kvm)) {
		struct kvm_mmu_page *sp;

		for_each_sp(pages, sp, parents, i) {
			kvm_mmu_zap_page(kvm, sp);
			mmu_pages_clear_parents(&parents);
			zapped++;
		}
		kvm_mmu_pages_init(parent, &parents, &pages);
	}

	return (zapped);
}

static void
mmu_free_pte_chain(struct kvm_pte_chain *pc)
{
	if (pc)
		kmem_cache_free(pte_chain_cache, pc);
}

void
mmu_page_remove_parent_pte(struct kvm_mmu_page *sp, uint64_t *parent_pte)
{
	struct kvm_pte_chain *pte_chain;
	struct list_t *node;
	int i;

	if (!sp->multimapped) {
		sp->parent_pte = NULL;
		return;
	}

	for (pte_chain = list_head(&sp->parent_ptes); pte_chain != NULL;
	    pte_chain = list_next(&sp->parent_ptes, pte_chain)) {
		for (i = 0; i < NR_PTE_CHAIN_ENTRIES; ++i) {
			if (!pte_chain->parent_ptes[i])
				break;
			if (pte_chain->parent_ptes[i] != parent_pte)
				continue;
			while (i + 1 < NR_PTE_CHAIN_ENTRIES &&
			    pte_chain->parent_ptes[i + 1]) {
				pte_chain->parent_ptes[i] =
				    pte_chain->parent_ptes[i + 1];
				i++;
			}
			pte_chain->parent_ptes[i] = NULL;
			if (i == 0) {
				list_remove(&sp->parent_ptes, pte_chain);
				mmu_free_pte_chain(pte_chain);
				if (list_is_empty(&sp->parent_ptes)) {
					sp->multimapped = 0;
					sp->parent_pte = NULL;
				}
			}
			return;
		}
	}
}

void
kvm_mmu_put_page(struct kvm_mmu_page *sp, uint64_t *parent_pte)
{
	mmu_page_remove_parent_pte(sp, parent_pte);
}

extern void __set_spte(uint64_t *sptep, uint64_t spte);

static void
kvm_mmu_unlink_parents(struct kvm *kvm, struct kvm_mmu_page *sp)
{
	uint64_t *parent_pte;

#ifndef XXX
	while (sp->multimapped || sp->parent_pte) {
		if (!sp->multimapped)
			parent_pte = sp->parent_pte;
		else {
			struct kvm_pte_chain *chain;

			chain = list_head(&sp->parent_ptes);

			parent_pte = chain->parent_ptes[0];
		}

		kvm_mmu_put_page(sp, parent_pte);
		__set_spte(parent_pte, shadow_trap_nonpresent_pte);
	}
#else
	XXX_KVM_PROBE;

	while (sp->multimapped || sp->parent_pte) {
		if (!sp->multimapped) {
			parent_pte = sp->parent_pte;
			kvm_mmu_put_page(sp, parent_pte);
			__set_spte(parent_pte, shadow_trap_nonpresent_pte);
		} else {
			struct kvm_pte_chain *chain;
			int i;
			for (chain = list_head(&sp->parent_ptes); chain != NULL;
			    chain = list_next(&sp->parent_ptes, chain)) {
				for (i = 0; i < NR_PTE_CHAIN_ENTRIES; i++) {
					if (chain->parent_ptes[i] == 0)
						continue;

					parent_pte = chain->parent_ptes[i];
					kvm_mmu_put_page(sp, parent_pte);
					__set_spte(parent_pte,
					    shadow_trap_nonpresent_pte);
				}
			}
		}
	}
#endif
}

static void
kvm_mmu_reset_last_pte_updated(struct kvm *kvm)
{
	int i;
	struct kvm_vcpu *vcpu;

#ifdef XXX
	kvm_for_each_vcpu(i, vcpu, kvm)
		vcpu->arch.last_pte_updated = NULL;
#else
	XXX_KVM_PROBE;
#endif
}

extern void rmap_remove(struct kvm *kvm, uint64_t *spte);

static int
is_last_spte(uint64_t pte, int level)
{
	if (level == PT_PAGE_TABLE_LEVEL)
		return (1);
	if (is_large_pte(pte))
		return (1);
	return (0);
}

static void
kvm_mmu_page_unlink_children(struct kvm *kvm, struct kvm_mmu_page *sp)
{
	unsigned i;
	uint64_t *pt;
	uint64_t ent;

	pt = sp->spt;

	for (i = 0; i < PT64_ENT_PER_PAGE; ++i) {
		ent = pt[i];

		if (is_shadow_present_pte(ent)) {
			if (!is_last_spte(ent, sp->role.level)) {
				ent &= PT64_BASE_ADDR_MASK;
				mmu_page_remove_parent_pte(page_header(ent),
				    &pt[i]);
			} else {
				rmap_remove(kvm, &pt[i]);
			}
		}
		pt[i] = shadow_trap_nonpresent_pte;
	}
}

int
kvm_mmu_zap_page(struct kvm *kvm, struct kvm_mmu_page *sp)
{
	int ret;

	ret = mmu_zap_unsync_children(kvm, sp);
	kvm_mmu_page_unlink_children(kvm, sp);
	kvm_mmu_unlink_parents(kvm, sp);
	kvm_flush_remote_tlbs(kvm);
#ifdef XXX
	if (!sp->role.invalid && !sp->role.direct)
		unaccount_shadowed(kvm, sp->gfn);
#else
	XXX_KVM_PROBE;
#endif
	if (sp->unsync)
		kvm_unlink_unsync_page(kvm, sp);

	if (!sp->root_count) {
		sp->hash_link.list_prev->list_next = sp->hash_link.list_next;
		sp->hash_link.list_next->list_prev = sp->hash_link.list_prev;
		sp->hash_link.list_prev = 0;
		sp->hash_link.list_next = 0;
		kvm_mmu_free_page(kvm, sp);
	} else {
		sp->role.invalid = 1;
		if (!list_link_active(&sp->link))
			list_insert_head(&kvm->arch.active_mmu_pages, sp);
#ifdef XXX
		kvm_reload_remote_mmus(kvm);
#else
		XXX_KVM_PROBE;
#endif
	}
	kvm_mmu_reset_last_pte_updated(kvm);

	return (ret);
}

extern int make_all_cpus_request(struct kvm *kvm, unsigned int req);

void
kvm_reload_remote_mmus(struct kvm *kvm)
{
	make_all_cpus_request(kvm, KVM_REQ_MMU_RELOAD);
}

void
kvm_mmu_flush_tlb(struct kvm_vcpu *vcpu)
{
	kvm_x86_ops->tlb_flush(vcpu);
}

int
is_writable_pte(unsigned long pte)
{
	return (pte & PT_WRITABLE_MASK);
}

extern pfn_t spte_to_pfn(uint64_t pte);
extern unsigned long *gfn_to_rmap(struct kvm *kvm, gfn_t gfn, int level);

static uint64_t *
rmap_next(struct kvm *kvm, unsigned long *rmapp, uint64_t *spte)
{
	struct kvm_rmap_desc *desc;
	struct kvm_rmap_desc *prev_desc;
	uint64_t *prev_spte;
	int i;

	if (!*rmapp)
		return (NULL);
	else if (!(*rmapp & 1)) {
		if (!spte)
			return ((uint64_t *)*rmapp);
		return (NULL);
	}

	desc = (struct kvm_rmap_desc *)(*rmapp & ~1ul);
	prev_desc = NULL;
	prev_spte = NULL;
	while (desc) {
		for (i = 0; i < RMAP_EXT && desc->sptes[i]; ++i) {
			if (prev_spte == spte)
				return (desc->sptes[i]);
			prev_spte = desc->sptes[i];
		}
		desc = desc->more;
	}

	return (NULL);
}

static int
rmap_write_protect(struct kvm *kvm, uint64_t gfn)
{
	unsigned long *rmapp;
	uint64_t *spte;
	int i, write_protected = 0;

	gfn = unalias_gfn(kvm, gfn);
	rmapp = gfn_to_rmap(kvm, gfn, PT_PAGE_TABLE_LEVEL);

	spte = rmap_next(kvm, rmapp, NULL);
	while (spte) {
		ASSERT(!spte);
		ASSERT(!(*spte & PT_PRESENT_MASK));
		if (is_writable_pte(*spte)) {
			__set_spte(spte, *spte & ~PT_WRITABLE_MASK);
			write_protected = 1;
		}
		spte = rmap_next(kvm, rmapp, spte);
	}
	if (write_protected) {
		pfn_t pfn;

		spte = rmap_next(kvm, rmapp, NULL);
		pfn = spte_to_pfn(*spte);
		kvm_set_pfn_dirty(pfn);
	}

	/* check for huge page mappings */
	for (i = PT_DIRECTORY_LEVEL;
	    i < PT_PAGE_TABLE_LEVEL + KVM_NR_PAGE_SIZES; i++) {
		rmapp = gfn_to_rmap(kvm, gfn, i);
		spte = rmap_next(kvm, rmapp, NULL);
		while (spte) {
			ASSERT(!spte);
			ASSERT(!(*spte & PT_PRESENT_MASK));
			ASSERT((*spte & (PT_PAGE_SIZE_MASK|PT_PRESENT_MASK)) !=
			    (PT_PAGE_SIZE_MASK|PT_PRESENT_MASK));

			if (is_writable_pte(*spte)) {
				rmap_remove(kvm, spte);
#ifdef XXX_KVM_STAT
				--kvm->stat.lpages;
#endif
				__set_spte(spte, shadow_trap_nonpresent_pte);
				spte = NULL;
				write_protected = 1;
			}
			spte = rmap_next(kvm, rmapp, spte);
		}
	}

	return (write_protected);
}

static int
kvm_sync_page(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp)
{
	if (sp->role.glevels != vcpu->arch.mmu.root_level) {
		kvm_mmu_zap_page(vcpu->kvm, sp);
		return (1);
	}

#ifdef XXX_KVM_TRACE
	trace_kvm_mmu_sync_page(sp);
#endif
	if (rmap_write_protect(vcpu->kvm, sp->gfn))
		kvm_flush_remote_tlbs(vcpu->kvm);
	kvm_unlink_unsync_page(vcpu->kvm, sp);
	if (vcpu->arch.mmu.sync_page(vcpu, sp)) {
		kvm_mmu_zap_page(vcpu->kvm, sp);
		return (1);
	}

	kvm_mmu_flush_tlb(vcpu);
	return (0);
}

static void
nonpaging_prefetch_page(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp)
{
	int i;

	for (i = 0; i < PT64_ENT_PER_PAGE; ++i)
		sp->spt[i] = shadow_trap_nonpresent_pte;
}

struct kvm_mmu_page *
kvm_mmu_get_page(struct kvm_vcpu *vcpu, gfn_t gfn, gva_t gaddr, unsigned level,
    int direct, unsigned access, uint64_t *parent_pte)
{
	union kvm_mmu_page_role role;
	unsigned index;
	unsigned quadrant;
	list_t *bucket;
	struct kvm_mmu_page *sp;
	struct hlist_node *node, *tmp;

	role = vcpu->arch.mmu.base_role;
	role.level = level;
	role.direct = direct;
	role.access = access;

	if (vcpu->arch.mmu.root_level <= PT32_ROOT_LEVEL) {
		quadrant = gaddr >> (PAGESHIFT + (PT64_PT_BITS * level));
		quadrant &= (1 << ((PT32_PT_BITS - PT64_PT_BITS) * level)) - 1;
		role.quadrant = quadrant;
	}

	index = kvm_page_table_hashfn(gfn);
	bucket = &vcpu->kvm->arch.mmu_page_hash[index];

	for (sp = list_head(bucket); sp != NULL;
	    sp = list_next(bucket, sp)) {
		if (sp->gfn == gfn) {
			if (sp->unsync)
				if (kvm_sync_page(vcpu, sp))
					continue;

			if (sp->role.word != role.word)
				continue;

			mmu_page_add_parent_pte(vcpu, sp, parent_pte);
			if (sp->unsync_children) {
				set_bit(KVM_REQ_MMU_SYNC, &vcpu->requests);
				kvm_mmu_mark_parents_unsync(vcpu, sp);
			}
			return (sp);
		}
	}
#ifdef XXX_KVM_STAT
	++vcpu->kvm->stat.mmu_cache_miss;
#endif
	sp = kvm_mmu_alloc_page(vcpu, parent_pte);

	if (!sp)
		return (sp);

	sp->gfn = gfn;
	sp->role = role;
	list_insert_head(bucket, sp);
	if (!direct) {
		if (rmap_write_protect(vcpu->kvm, gfn))
			kvm_flush_remote_tlbs(vcpu->kvm);
#ifdef XXX
		account_shadowed(vcpu->kvm, gfn);
#else
		XXX_KVM_PROBE;
#endif
	}

	if (shadow_trap_nonpresent_pte != shadow_notrap_nonpresent_pte)
		vcpu->arch.mmu.prefetch_page(vcpu, sp);
	else
		nonpaging_prefetch_page(vcpu, sp);
#ifdef XXX_KVM_TRACE
	trace_kvm_mmu_get_page(sp, true);
#endif
	return (sp);
}

inline int
is_present_gpte(unsigned long pte)
{
	return (pte & PT_PRESENT_MASK);
}

extern inline uint64_t kvm_pdptr_read(struct kvm_vcpu *vcpu, int index);

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

static int
mmu_check_root(struct kvm_vcpu *vcpu, gfn_t root_gfn)
{
	int ret = 0;

	if (!kvm_is_visible_gfn(vcpu->kvm, root_gfn)) {
		set_bit(KVM_REQ_TRIPLE_FAULT, &vcpu->requests);
		ret = 1;
	}

	return (ret);
}

static int
mmu_alloc_roots(struct kvm_vcpu *vcpu)
{
	int i;
	gfn_t root_gfn;
	struct kvm_mmu_page *sp;
	int direct = 0;
	uint64_t pdptr;

	root_gfn = vcpu->arch.cr3 >> PAGESHIFT;

	if (vcpu->arch.mmu.shadow_root_level == PT64_ROOT_LEVEL) {
		hpa_t root = vcpu->arch.mmu.root_hpa;

		ASSERT(!VALID_PAGE(root));
		if (tdp_enabled)
			direct = 1;
		if (mmu_check_root(vcpu, root_gfn))
			return (1);

		sp = kvm_mmu_get_page(vcpu, root_gfn, 0, PT64_ROOT_LEVEL,
		    direct, ACC_ALL, NULL);
		root = kvm_va2pa((caddr_t)sp->spt);

		++sp->root_count;
		vcpu->arch.mmu.root_hpa = root;
		return (0);
	}
	direct = !is_paging(vcpu);
	if (tdp_enabled)
		direct = 1;
	for (i = 0; i < 4; ++i) {
		hpa_t root = vcpu->arch.mmu.pae_root[i];

		ASSERT(!VALID_PAGE(root));
		if (vcpu->arch.mmu.root_level == PT32E_ROOT_LEVEL) {
			pdptr = kvm_pdptr_read(vcpu, i);

			if (!is_present_gpte(pdptr)) {
				vcpu->arch.mmu.pae_root[i] = 0;
				continue;
			}
			root_gfn = pdptr >> PAGESHIFT;
		} else if (vcpu->arch.mmu.root_level == 0)
			root_gfn = 0;
		if (mmu_check_root(vcpu, root_gfn))
			return (1);
			sp = kvm_mmu_get_page(vcpu, root_gfn, i << 30,
			    PT32_ROOT_LEVEL, direct, ACC_ALL, NULL);
#ifdef XXX
		root = __pa(sp->spt);
#else
		XXX_KVM_PROBE;
		root = kvm_va2pa((caddr_t)sp->spt);
#endif
		++sp->root_count;
		vcpu->arch.mmu.pae_root[i] = root | PT_PRESENT_MASK;
	}
	vcpu->arch.mmu.root_hpa = kvm_va2pa((caddr_t)vcpu->arch.mmu.pae_root);

	return (0);
}

static int
mmu_pages_next(struct kvm_mmu_pages *pvec, struct mmu_page_path *parents, int i)
{
	int n;

	for (n = i + 1; n < pvec->nr; n++) {
		struct kvm_mmu_page *sp = pvec->page[n].sp;

		if (sp->role.level == PT_PAGE_TABLE_LEVEL) {
			parents->idx[0] = pvec->page[n].idx;
			return (n);
		}

		parents->parent[sp->role.level-2] = sp;
		parents->idx[sp->role.level-1] = pvec->page[n].idx;
	}

	return (n);
}

static void
mmu_sync_children(struct kvm_vcpu *vcpu, struct kvm_mmu_page *parent)
{
	int i;
	struct kvm_mmu_page *sp;
	struct mmu_page_path parents;
	struct kvm_mmu_pages pages;

	kvm_mmu_pages_init(parent, &parents, &pages);
	while (mmu_unsync_walk(parent, &pages, vcpu->kvm)) {
		int protected = 0;

		for_each_sp(pages, sp, parents, i)
			protected |= rmap_write_protect(vcpu->kvm, sp->gfn);

		if (protected)
			kvm_flush_remote_tlbs(vcpu->kvm);

		for_each_sp(pages, sp, parents, i) {
			kvm_sync_page(vcpu, sp);
			mmu_pages_clear_parents(&parents);
		}
#ifdef XXX
		cond_resched_lock(&vcpu->mutex);
#else
		XXX_KVM_SYNC_PROBE;
		mutex_enter(&vcpu->kvm->mmu_lock);
#endif
		kvm_mmu_pages_init(parent, &parents, &pages);
#ifndef XXX
		mutex_exit(&vcpu->kvm->mmu_lock);
#endif
	}
}

static void
mmu_sync_roots(struct kvm_vcpu *vcpu)
{
	int i;
	struct kvm_mmu_page *sp;

	if (!VALID_PAGE(vcpu->arch.mmu.root_hpa))
		return;

	if (vcpu->arch.mmu.shadow_root_level == PT64_ROOT_LEVEL) {
		hpa_t root = vcpu->arch.mmu.root_hpa;
		sp = page_header(root);
		mmu_sync_children(vcpu, sp);
		return;
	}

	for (i = 0; i < 4; i++) {
		hpa_t root = vcpu->arch.mmu.pae_root[i];

		if (root && VALID_PAGE(root)) {
			root &= PT64_BASE_ADDR_MASK;
			sp = page_header(root);
			mmu_sync_children(vcpu, sp);
		}
	}
}

void
kvm_mmu_sync_roots(struct kvm_vcpu *vcpu)
{
	mutex_enter(&vcpu->kvm->mmu_lock);
	mmu_sync_roots(vcpu);
	mutex_exit(&vcpu->kvm->mmu_lock);
}

static void
mmu_destroy_caches(void)
{
	if (pte_chain_cache)
		kmem_cache_destroy(pte_chain_cache);
	if (rmap_desc_cache)
		kmem_cache_destroy(rmap_desc_cache);
	if (mmu_page_header_cache)
		kmem_cache_destroy(mmu_page_header_cache);
}

int
zero_constructor(void *buf, void *arg, int tags)
{
	bzero(buf, (size_t)arg);
	return (0);
}

int
kvm_mmu_module_init(void)
{
	if ((pte_chain_cache = kmem_cache_create("kvm_pte_chain",
	    sizeof (struct kvm_pte_chain), 0, zero_constructor, NULL, NULL,
	    (void *)sizeof (struct kvm_pte_chain), NULL, 0)) == NULL)
		goto nomem;

	if ((rmap_desc_cache = kmem_cache_create("kvm_rmap_desc",
	    sizeof (struct kvm_rmap_desc), 0, zero_constructor, NULL, NULL,
	    (void *)sizeof (struct kvm_rmap_desc), NULL, 0)) == NULL)
		goto nomem;

	if ((mmu_page_header_cache = kmem_cache_create("kvm_mmu_page_header",
	    sizeof (struct kvm_mmu_page), 0, zero_constructor, NULL, NULL,
	    (void *)sizeof (struct kvm_mmu_page), NULL, 0)) == NULL)
		goto nomem;

#ifdef XXX
	/*
	 * this looks like a garbage collector/reaper.  Implement later if
	 * needed
	 */
	register_shrinker(&mmu_shrinker);
#else
	XXX_KVM_PROBE;
#endif

	return (0);

nomem:
	mmu_destroy_caches();
	return (ENOMEM);
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


void
kvm_mmu_set_nonpresent_ptes(uint64_t trap_pte, uint64_t notrap_pte)
{
	shadow_trap_nonpresent_pte = trap_pte;
	shadow_notrap_nonpresent_pte = notrap_pte;
}

void
kvm_mmu_set_base_ptes(uint64_t base_pte)
{
	shadow_base_present_pte = base_pte;
}

void
kvm_mmu_set_mask_ptes(uint64_t user_mask, uint64_t accessed_mask,
    uint64_t dirty_mask, uint64_t nx_mask, uint64_t x_mask)
{
	shadow_user_mask = user_mask;
	shadow_accessed_mask = accessed_mask;
	shadow_dirty_mask = dirty_mask;
	shadow_nx_mask = nx_mask;
	shadow_x_mask = x_mask;
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

extern unsigned long vmx_io_bitmap_a[];
extern unsigned long vmx_io_bitmap_b[];
extern unsigned long vmx_msr_bitmap_legacy[];
extern unsigned long vmx_msr_bitmap_longmode[];

static inline int
cpu_has_vmx_msr_bitmap(void)
{
	return (vmcs_config.cpu_based_exec_ctrl & CPU_BASED_USE_MSR_BITMAPS);
}

static void
__vmx_disable_intercept_for_msr(unsigned long *msr_bitmap, uint32_t msr)
{
	int f = sizeof (unsigned long);

	if (!cpu_has_vmx_msr_bitmap())
		return;

	/*
	 * See Intel PRM Vol. 3, 20.6.9 (MSR-Bitmap Address). Early manuals
	 * have the write-low and read-high bitmap offsets the wrong way round.
	 * We can control MSRs 0x00000000-0x00001fff and 0xc0000000-0xc0001fff.
	 */
	if (msr <= 0x1fff) {
		__clear_bit(msr, msr_bitmap + 0x000 / f); /* read-low */
		__clear_bit(msr, msr_bitmap + 0x800 / f); /* write-low */
	} else if ((msr >= 0xc0000000) && (msr <= 0xc0001fff)) {
		msr &= 0x1fff;
		__clear_bit(msr, msr_bitmap + 0x400 / f); /* read-high */
		__clear_bit(msr, msr_bitmap + 0xc00 / f); /* write-high */
	}
}

static void
vmx_disable_intercept_for_msr(uint32_t msr, int longmode_only)
{
	if (!longmode_only)
		__vmx_disable_intercept_for_msr(vmx_msr_bitmap_legacy, msr);
	__vmx_disable_intercept_for_msr(vmx_msr_bitmap_longmode, msr);
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

static uint64_t host_efer;

/*
 * Keep MSR_K6_STAR at the end, as setup_msrs() will try to optimize it
 * away by decrementing the array size.
 */
static const uint32_t vmx_msr_index[] = {
#ifdef CONFIG_X86_64
	MSR_SYSCALL_MASK, MSR_LSTAR, MSR_CSTAR,
#endif
	MSR_EFER, MSR_TSC_AUX, MSR_K6_STAR,
};
#define	NR_VMX_MSR ARRAY_SIZE(vmx_msr_index)
#define	VMX_NR_VPIDS				(1 << 16)
ulong_t *vmx_vpid_bitmap;
size_t vpid_bitmap_words;
kmutex_t vmx_vpid_lock;

void
kvm_disable_tdp(void)
{
	tdp_enabled = 0;
}

void
kvm_enable_tdp(void)
{
	tdp_enabled = 1;
}

static int
vmx_init(void)
{
	int r, i;

	rdmsrl_safe(MSR_EFER, (unsigned long long *)&host_efer);

	for (i = 0; i < NR_VMX_MSR; ++i)
		kvm_define_shared_msr(i, vmx_msr_index[i]);

#ifdef XXX
	vmx_io_bitmap_a = kmem_zalloc(PAGESIZE, KM_SLEEP);
	vmx_io_bitmap_b = kmem_zalloc(PAGESIZE, KM_SLEEP);
	vmx_msr_bitmap_legacy = kmem_zalloc(PAGESIZE, KM_SLEEP);
	vmx_msr_bitmap_longmode = kmem_zalloc(PAGESIZE, KM_SLEEP);
#else
	XXX_KVM_PROBE;
#endif

	/*
	 * Allow direct access to the PC debug port (it is often used for I/O
	 * delays, but the vmexits simply slow things down).
	 */
	memset(vmx_io_bitmap_a, 0xff, PAGESIZE);
	clear_bit(0x80, vmx_io_bitmap_a);

	memset(vmx_io_bitmap_b, 0xff, PAGESIZE);

	memset(vmx_msr_bitmap_legacy, 0xff, PAGESIZE);
	memset(vmx_msr_bitmap_longmode, 0xff, PAGESIZE);

	set_bit(0, vmx_vpid_bitmap); /* 0 is reserved for host */

	r = kvm_init(&vmx_x86_ops, sizeof (struct vcpu_vmx));

	if (r)
		goto out3;

	vmx_disable_intercept_for_msr(MSR_FS_BASE, 0);
	vmx_disable_intercept_for_msr(MSR_GS_BASE, 0);
	vmx_disable_intercept_for_msr(MSR_KERNEL_GS_BASE, 1);
	vmx_disable_intercept_for_msr(MSR_IA32_SYSENTER_CS, 0);
	vmx_disable_intercept_for_msr(MSR_IA32_SYSENTER_ESP, 0);
	vmx_disable_intercept_for_msr(MSR_IA32_SYSENTER_EIP, 0);

	if (enable_ept) {
		bypass_guest_pf = 0;
		kvm_mmu_set_base_ptes(VMX_EPT_READABLE_MASK |
			VMX_EPT_WRITABLE_MASK);
		kvm_mmu_set_mask_ptes(0ull, 0ull, 0ull, 0ull,
				VMX_EPT_EXECUTABLE_MASK);
		kvm_enable_tdp();
	} else
		kvm_disable_tdp();

	if (bypass_guest_pf)
		kvm_mmu_set_nonpresent_ptes(~0xffeull, 0ull);

	return (0);

out3:
	kmem_free(vmx_msr_bitmap_longmode, PAGESIZE);
out2:
	kmem_free(vmx_msr_bitmap_legacy, PAGESIZE);
out1:
	kmem_free(vmx_io_bitmap_b, PAGESIZE);
out:
	kmem_free(vmx_io_bitmap_a, PAGESIZE);

	return (r);
}

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

	kvm_cache = kmem_cache_create("kvm_cache", KVM_VM_DATA_SIZE,
	    ptob(1),  NULL, NULL, NULL, NULL, NULL, 0);
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
	kmem_cache_destroy(kvm_cache);
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

	VERIFY(getminor(dev) != kvm_base_minor);
	ksp = ddi_get_soft_state(kvm_state, minor);
	/*
	 * XXX We need to clean up the vcpus / kvm structs we allocated.
	 */
	kvm_destroy_vm(ksp->kds_kvmp);
	ddi_soft_state_free(kvm_state, minor);
	vmem_free(kvm_minor, (void *)(uintptr_t)minor, 1);

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

	if (!CPU_IN_SET(cpus_hardware_enabled, cpu))
		return;

	CPUSET_DEL(cpus_hardware_enabled, cpu);
	kvm_arch_hardware_disable(NULL);
}

extern unsigned int ddi_enter_critical(void);
extern void ddi_exit_critical(unsigned int d);

/*
 * XXX the following needs to run on
 * every cpu.  Right now, only run on the current
 * cpu.
 */
#define	on_each_cpu(func, info, wait)	\
	/*CSTYLED*/			\
	({				\
	unsigned int d;			\
	d = ddi_enter_critical();	\
	func(info);			\
	ddi_exit_critical(d);		\
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

void
kvm_mmu_zap_all(struct kvm *kvm)
{
	struct kvm_mmu_page *sp, *node;

	/*
	 * In the following loop, sp may be freed and deleted
	 * from the list indirectly from kvm_mmu_zap_page.
	 * So we hold onto the next element before zapping.
	 */
	mutex_enter(&kvm->mmu_lock);
	sp = list_head(&kvm->arch.active_mmu_pages);
	if (sp)
		nsp = list_next(&kvm->arch.active_mmu_pages, sp);

	while (sp) {
		(void) kvm_mmu_zap_page(kvm, sp);
		sp = nsp;
		if (sp)
			nsp = list_next(&kvm->arch.active_mmu_pages, sp);
	}

	mutex_exit(&kvm->mmu_lock);
	kvm_flush_remote_tlbs(kvm);
}

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
kvm_mmu_zap_all(struct kvm *kvm)
{
	struct kvm_mmu_page *sp, *nsp;

	/*
	 * In the following loop, sp may be freed and deleted
	 * from the list indirectly from kvm_mmu_zap_page.
	 * So we hold onto the next element before zapping.
	 */
	mutex_enter(&kvm->mmu_lock);
	sp = list_head(&kvm->arch.active_mmu_pages);
	if (sp)
		nsp = list_next(&kvm->arch.active_mmu_pages, sp);

	while (sp) {
		(void) kvm_mmu_zap_page(kvm, sp);
		sp = nsp;
		if (sp == list_head(&kvm->arch.active_mmu_pages))
			break;
		if (sp)
			nsp = list_next(&kvm->arch.active_mmu_pages, sp);
	}

	mutex_exit(&kvm->mmu_lock);
	kvm_flush_remote_tlbs(kvm);
}

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
	proc_t *p;

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

	kvmp->memslots = kmem_zalloc(sizeof (struct kvm_memslots), KM_NOSLEEP);

	if (kvmp->memslots == NULL) {
		kvm_arch_destroy_vm(kvmp);
		return (NULL);
	}

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

	if (drv_getparm(UPROCP, &p) != 0)
		cmn_err(CE_PANIC, "Cannot get proc_t for current process\n");

	/*
	 * XXX note that the as struct does not contain  a refcnt, may
	 * have to go lower
	 */
	kvmp->mm = p->p_as;
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
	kvmp->kvmid = kvmid++;
	mutex_enter(&kvm_lock);
	kvmp->users_count = 1;
	list_insert_tail(&vm_list, kvmp);
	mutex_exit(&kvm_lock);
#ifdef KVM_COALESCED_MMIO_PAGE_OFFSET
	kvm_coalesced_mmio_init(kvmp);
#endif

	return (kvmp);
}

static void
kvm_destroy_vm(struct kvm *kvmp)
{
	int ii;

	if (kvmp == NULL)
		return;

	kvm_arch_destroy_vm_comps(kvmp);

#ifdef KVM_COALESCED_MMIO_PAGE_OFFSET
	kvm_coalesced_mmio_free(kvmp);
#endif

	list_remove(&vm_list, kvmp);
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


/*
 * Caculate mmu pages needed for kvm.
 */
unsigned int
kvm_mmu_calculate_mmu_pages(struct kvm *kvm)
{
	int i;
	unsigned int nr_mmu_pages;
	unsigned int  nr_pages = 0;
	struct kvm_memslots *slots;

	slots = kvm->memslots;
	for (i = 0; i < slots->nmemslots; i++)
		nr_pages += slots->memslots[i].npages;

	nr_mmu_pages = nr_pages * KVM_PERMILLE_MMU_PAGES / 1000;
	nr_mmu_pages = max(nr_mmu_pages, (unsigned int)KVM_MIN_ALLOC_MMU_PAGES);

	return (nr_mmu_pages);
}

/*
 * Changing the number of mmu pages allocated to the vm
 * Note: if kvm_nr_mmu_pages is too small, you will get dead lock
 */
void
kvm_mmu_change_mmu_pages(struct kvm *kvm, unsigned int kvm_nr_mmu_pages)
{
	int used_pages;

	used_pages = kvm->arch.n_alloc_mmu_pages - kvm->arch.n_free_mmu_pages;
	used_pages = max(0, used_pages);

	/* for the time being, assume that address space will only grow */
	/* larger.  The following code will be added later. */

	/*
	 * If we set the number of mmu pages to be smaller be than the
	 * number of actived pages , we must to free some mmu pages before we
	 * change the value
	 */

	if (used_pages > kvm_nr_mmu_pages) {
		while (used_pages > kvm_nr_mmu_pages &&
			!list_is_empty(&kvm->arch.active_mmu_pages)) {
			struct kvm_mmu_page *page;

#ifdef XXX_KVM_DOESNTCOMPILE
			page = container_of(kvm->arch.active_mmu_pages.prev,
					    struct kvm_mmu_page, link);
#else
			page = (struct kvm_mmu_page *)
			    list_head(&kvm->arch.active_mmu_pages);
#endif
			/* page removed by kvm_mmu_zap_page */
			used_pages -= kvm_mmu_zap_page(kvm, page);
			used_pages--;
		}
		kvm_nr_mmu_pages = used_pages;
		kvm->arch.n_free_mmu_pages = 0;
	} else {
		kvm->arch.n_free_mmu_pages +=
		    kvm_nr_mmu_pages - kvm->arch.n_alloc_mmu_pages;
	}

	kvm->arch.n_alloc_mmu_pages = kvm_nr_mmu_pages;
}

void
kvm_mmu_slot_remove_write_access(struct kvm *kvm, int slot)
{
	struct kvm_mmu_page *sp;

	for (sp = list_head(&kvm->arch.active_mmu_pages);
	    sp != NULL; sp = list_next(&kvm->arch.active_mmu_pages, sp)) {
		int i;
		uint64_t *pt;

		if (!test_bit(slot, sp->slot_bitmap))
			continue;

		pt = sp->spt;
		for (i = 0; i < PT64_ENT_PER_PAGE; i++) {
			/* avoid RMW */
			if (pt[i] & PT_WRITABLE_MASK)
				pt[i] &= ~PT_WRITABLE_MASK;
		}
	}
	kvm_flush_remote_tlbs(kvm);
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
vmx_set_tss_addr(struct kvm *kvmp, caddr_t addr)
{
	int ret;

	struct kvm_userspace_memory_region tss_mem = {
		.slot = TSS_PRIVATE_MEMSLOT,
		.guest_phys_addr = (uint64_t)addr,
		.memory_size = PAGESIZE * 3,
		.flags = 0,
	};

	ret = kvm_set_memory_region(kvmp, &tss_mem, 0);

	if (ret)
		return (ret);

	kvmp->arch.tss_addr = (uint64_t)addr;

	return (DDI_SUCCESS);
}

static int
kvm_vm_ioctl_set_tss_addr(struct kvm *kvmp, caddr_t addr)
{
	/*
	 * XXX later, if adding other arch beside x86, need to do something
	 * else here
	 */
	return (vmx_set_tss_addr(kvmp, addr));
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

static inline int
cpu_has_vmx_ept_1g_page(void)
{
	return (!!(vmx_capability.ept & VMX_EPT_1GB_PAGE_BIT));
}

static int
vmx_get_lpage_level(void)
{
	if (enable_ept && !cpu_has_vmx_ept_1g_page())
		return (PT_DIRECTORY_LEVEL);
	else
		/* For shadow and EPT supported 1GB page */
		return (PT_PDPE_LEVEL);
}

static inline int
cpu_has_vmx_rdtscp(void)
{
	return (vmcs_config.cpu_based_2nd_exec_ctrl & SECONDARY_EXEC_RDTSCP);
}

static int
vmx_rdtscp_supported(void)
{
	return (cpu_has_vmx_rdtscp());
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

#define	__ex(x) __kvm_handle_fault_on_reboot(x)

void
vmcs_clear(struct vmcs *vmcs)
{
	unsigned char error;
	uint64_t phys_addr = (hat_getpfnum(kas.a_hat, (caddr_t)vmcs) <<
	    PAGESHIFT) | ((uint64_t)vmcs & PAGEOFFSET);

	/*CSTYLED*/
	__asm__ volatile (__ex(ASM_VMX_VMCLEAR_RAX) "\n\tsetna %0\n"
	    : "=g"(error) : "a"(&phys_addr), "m"(phys_addr)
	    : "cc", "memory");

	if (error)
		cmn_err(CE_PANIC, "kvm: vmclear fail: %p/%lx\n",
			vmcs, phys_addr);
}

void
__vcpu_clear(void *arg)
{
	struct vcpu_vmx *vmx = arg;
	int cpu = CPU->cpu_id;

	vmx->vmcs->revision_id = vmcs_config.revision_id;

	if (vmx->vcpu.cpu == cpu)
		vmcs_clear(vmx->vmcs);
#ifdef XXX
	if (per_cpu(current_vmcs, cpu) == vmx->vmcs)
		per_cpu(current_vmcs, cpu) = NULL;
	rdtscll(vmx->vcpu.arch.host_tsc);
	list_del(&vmx->local_vcpus_link);
#else
	XXX_KVM_PROBE;
	rdtscll(vmx->vcpu.arch.host_tsc);
#endif
	vmx->vcpu.cpu = -1;
	vmx->launched = 0;
}

static void vcpu_clear(struct vcpu_vmx *vmx)
{
	if (vmx->vcpu.cpu == -1)
		return;

	/*
	 * XXX: commented out below?
	 *
	 * smp_call_function_single(vmx->vcpu.cpu, __vcpu_clear, vmx, 1);
	 */
	__vcpu_clear(vmx);
}


uint16_t
vmcs_read16(unsigned long field)
{
	return (vmcs_readl(field));
}

static void
vmwrite_error(unsigned long field, unsigned long value)
{
	cmn_err(CE_WARN, "vmwrite error: reg %lx value %lx (err %x)\n",
	    field, value, vmcs_read32(VM_INSTRUCTION_ERROR));
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

void
vmcs_writel(unsigned long field, unsigned long value)
{
	unsigned char error = 0;
#ifndef XXX
	/*CSTYLED*/
	__asm__ volatile (ASM_VMX_VMWRITE_RAX_RDX "\n\tsetna %0"
	    : "=q"(error) : "a"(value), "d"(field) : "cc");

	if ((error))
		vmwrite_error(field, value);
#else
	XXX_KVM_PROBE;
	__vmwrite(field, value);
#endif
}

unsigned long
vmcs_readl(unsigned long field)
{
	unsigned long value;

	/*CSTYLED*/
	__asm__ volatile (ASM_VMX_VMREAD_RDX_RAX
	    : "=a"(value) : "d"(field) : "cc");

	return (value);
}

uint64_t
vmcs_read64(unsigned long field)
{
#ifdef CONFIG_X86_64
	return (vmcs_readl(field));
#else
	return (vmcs_readl(field) | ((uint64_t)vmcs_readl(field + 1) << 32));
#endif
}

void
vmcs_write16(unsigned long field, uint16_t value)
{
	vmcs_writel(field, value);
}

/*
 * writes 'guest_tsc' into guest's timestamp counter "register"
 * guest_tsc = host_tsc + tsc_offset ==> tsc_offset = guest_tsc - host_tsc
 */
static void
guest_write_tsc(uint64_t guest_tsc, uint64_t host_tsc)
{
	vmcs_write64(TSC_OFFSET, guest_tsc - host_tsc);
}

static inline int
cpu_has_secondary_exec_ctrls(void)
{
	return (vmcs_config.cpu_based_exec_ctrl &
	    CPU_BASED_ACTIVATE_SECONDARY_CONTROLS);
}

int
vm_need_virtualize_apic_accesses(struct kvm *kvm)
{
	return (flexpriority_enabled && irqchip_in_kernel(kvm));
}

inline int
vm_need_tpr_shadow(struct kvm *kvm)
{
	return ((cpu_has_vmx_tpr_shadow()) && (irqchip_in_kernel(kvm)));
}

/*
 * Volatile isn't enough to prevent the compiler from reordering the
 * read/write functions for the control registers and messing everything up.
 * A memory clobber would solve the problem, but would prevent reordering of
 * all loads stores around it, which can hurt performance. Solution is to
 * use a variable and mimic reads and writes to it to enforce serialization
 */
static unsigned long __force_order;

static inline unsigned long
native_read_cr0(void)
{
	unsigned long val;
	__asm__ volatile("mov %%cr0,%0\n\t" : "=r" (val), "=m" (__force_order));
	return (val);
}

#define	read_cr0()	(native_read_cr0())

static inline unsigned long
native_read_cr4(void)
{
	unsigned long val;
	__asm__ volatile("mov %%cr4,%0\n\t" : "=r" (val), "=m" (__force_order));
	return (val);
}

#define	read_cr4()	(native_read_cr4())

static inline unsigned long
native_read_cr3(void)
{
	unsigned long val;
	__asm__ volatile("mov %%cr3,%0\n\t" : "=r" (val), "=m" (__force_order));
	return (val);
}

#define	read_cr3()	(native_read_cr3())

inline ulong kvm_read_cr4(struct kvm_vcpu *vcpu);

/*
 * Sets up the vmcs for emulated real mode.
 */
int
vmx_vcpu_setup(struct vcpu_vmx *vmx)
{
	uint32_t host_sysenter_cs, msr_low, msr_high;
	uint32_t junk;
	uint64_t host_pat, tsc_this, tsc_base;
	volatile uint64_t a;
	struct descriptor_table dt;
	int i;
	unsigned long kvm_vmx_return;
	uint32_t exec_control;

	/* I/O */
	vmcs_write64(IO_BITMAP_A, kvm_va2pa((caddr_t)vmx_io_bitmap_a));
	vmcs_write64(IO_BITMAP_B, kvm_va2pa((caddr_t)vmx_io_bitmap_b));

	if (cpu_has_vmx_msr_bitmap()) {
		vmcs_write64(MSR_BITMAP,
		    kvm_va2pa((caddr_t)vmx_msr_bitmap_legacy));
	}

	vmcs_write64(VMCS_LINK_POINTER, -1ull); /* 22.3.1.5 */

	/* Control */
	vmcs_write32(PIN_BASED_VM_EXEC_CONTROL,
		vmcs_config.pin_based_exec_ctrl);

	exec_control = vmcs_config.cpu_based_exec_ctrl;
	if (!vm_need_tpr_shadow(vmx->vcpu.kvm)) {
		exec_control &= ~CPU_BASED_TPR_SHADOW;
#ifdef CONFIG_X86_64
		exec_control |= CPU_BASED_CR8_STORE_EXITING |
				CPU_BASED_CR8_LOAD_EXITING;
#endif
	}

	if (!enable_ept)
		exec_control |= CPU_BASED_CR3_STORE_EXITING |
				CPU_BASED_CR3_LOAD_EXITING  |
				CPU_BASED_INVLPG_EXITING;
	vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, exec_control);

	if (cpu_has_secondary_exec_ctrls()) {
		exec_control = vmcs_config.cpu_based_2nd_exec_ctrl;
		if (!vm_need_virtualize_apic_accesses(vmx->vcpu.kvm))
			exec_control &=
				~SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES;
		if (vmx->vpid == 0)
			exec_control &= ~SECONDARY_EXEC_ENABLE_VPID;
		if (!enable_ept) {
			exec_control &= ~SECONDARY_EXEC_ENABLE_EPT;
			enable_unrestricted_guest = 0;
		}
		if (!enable_unrestricted_guest)
			exec_control &= ~SECONDARY_EXEC_UNRESTRICTED_GUEST;

		if (!ple_gap)
			exec_control &= ~SECONDARY_EXEC_PAUSE_LOOP_EXITING;
		vmcs_write32(SECONDARY_VM_EXEC_CONTROL, exec_control);
	}

	if (ple_gap) {
		vmcs_write32(PLE_GAP, ple_gap);
		vmcs_write32(PLE_WINDOW, ple_window);
	}

	vmcs_write32(PAGE_FAULT_ERROR_CODE_MASK, !!bypass_guest_pf);
	vmcs_write32(PAGE_FAULT_ERROR_CODE_MATCH, !!bypass_guest_pf);
	vmcs_write32(CR3_TARGET_COUNT, 0);	/* 22.2.1 */

	vmcs_writel(HOST_CR0, read_cr0());  /* 22.2.3 */
	vmcs_writel(HOST_CR4, read_cr4());  /* 22.2.3, 22.2.5 */
	vmcs_writel(HOST_CR3, read_cr3());  /* 22.2.3  FIXME: shadow tables */

	vmcs_write16(HOST_CS_SELECTOR, KCS_SEL);  /* 22.2.4 */
#ifndef XXX
	vmcs_write16(HOST_DS_SELECTOR, KDS_SEL);  /* 22.2.4 */
	vmcs_write16(HOST_ES_SELECTOR, KDS_SEL);  /* 22.2.4 */
	vmcs_write16(HOST_FS_SELECTOR, kvm_read_fs());    /* 22.2.4 */
	vmcs_write16(HOST_GS_SELECTOR, kvm_read_gs());    /* 22.2.4 */

#else
	XXX_KVM_PROBE;
	vmcs_write16(HOST_DS_SELECTOR, 0x4b);  /* 22.2.4 */
	vmcs_write16(HOST_ES_SELECTOR, 0x4b);  /* 22.2.4 */
	vmcs_write16(HOST_FS_SELECTOR, 0);    /* 22.2.4 */
	vmcs_write16(HOST_GS_SELECTOR, 0);    /* 22.2.4 */
#endif
	vmcs_write16(HOST_SS_SELECTOR, KDS_SEL);  /* 22.2.4 */
#ifdef CONFIG_X86_64
	rdmsrl(MSR_FS_BASE, a);
	vmcs_writel(HOST_FS_BASE, a); /* 22.2.4 */
	rdmsrl(MSR_GS_BASE, a);
	vmcs_writel(HOST_GS_BASE, a); /* 22.2.4 */
#else
	vmcs_writel(HOST_FS_BASE, 0); /* 22.2.4 */
	vmcs_writel(HOST_GS_BASE, 0); /* 22.2.4 */
#endif

	vmcs_write16(HOST_TR_SELECTOR, KTSS_SEL);  /* 22.2.4 */

	kvm_get_idt(&dt);
	vmcs_writel(HOST_IDTR_BASE, dt.base);   /* 22.2.4 */

	__asm__("mov $.Lkvm_vmx_return, %0" : "=r"(kvm_vmx_return));
	vmcs_writel(HOST_RIP, kvm_vmx_return); /* 22.2.5 */
	vmcs_write32(VM_EXIT_MSR_STORE_COUNT, 0);
	vmcs_write32(VM_EXIT_MSR_LOAD_COUNT, 0);
	vmcs_write32(VM_ENTRY_MSR_LOAD_COUNT, 0);

	rdmsr(MSR_IA32_SYSENTER_CS, host_sysenter_cs, junk);
	vmcs_write32(HOST_IA32_SYSENTER_CS, host_sysenter_cs);
	rdmsrl(MSR_IA32_SYSENTER_ESP, a);
	vmcs_writel(HOST_IA32_SYSENTER_ESP, a);   /* 22.2.3 */
	rdmsrl(MSR_IA32_SYSENTER_EIP, a);
	vmcs_writel(HOST_IA32_SYSENTER_EIP, a);   /* 22.2.3 */

	if (vmcs_config.vmexit_ctrl & VM_EXIT_LOAD_IA32_PAT) {
		rdmsr(MSR_IA32_CR_PAT, msr_low, msr_high);
		host_pat = msr_low | ((uint64_t) msr_high << 32);
		vmcs_write64(HOST_IA32_PAT, host_pat);
	}
	if (vmcs_config.vmentry_ctrl & VM_ENTRY_LOAD_IA32_PAT) {
		rdmsr(MSR_IA32_CR_PAT, msr_low, msr_high);
		host_pat = msr_low | ((uint64_t) msr_high << 32);
		/* Write the default value follow host pat */
		vmcs_write64(GUEST_IA32_PAT, host_pat);
		/* Keep arch.pat sync with GUEST_IA32_PAT */
		vmx->vcpu.arch.pat = host_pat;
	}

	for (i = 0; i < NR_VMX_MSR; ++i) {
		uint32_t index = vmx_msr_index[i];
		uint32_t data_low, data_high;
		int j = vmx->nmsrs;

		if (rdmsr_safe(index, &data_low, &data_high) < 0)
			continue;
		if (wrmsr_safe(index, data_low, data_high) < 0)
			continue;
		vmx->guest_msrs[j].index = i;
		vmx->guest_msrs[j].data = 0;
		vmx->guest_msrs[j].mask = -1ull;
		++vmx->nmsrs;
	}

	vmcs_write32(VM_EXIT_CONTROLS, vmcs_config.vmexit_ctrl);

	/* 22.2.1, 20.8.1 */
	vmcs_write32(VM_ENTRY_CONTROLS, vmcs_config.vmentry_ctrl);

	vmcs_writel(CR0_GUEST_HOST_MASK, ~0UL);
	vmx->vcpu.arch.cr4_guest_owned_bits = KVM_CR4_GUEST_OWNED_BITS;
	if (enable_ept)
		vmx->vcpu.arch.cr4_guest_owned_bits |= X86_CR4_PGE;
	vmcs_writel(CR4_GUEST_HOST_MASK, ~vmx->vcpu.arch.cr4_guest_owned_bits);

	tsc_base = vmx->vcpu.kvm->arch.vm_init_tsc;
	rdtscll(tsc_this);
	if (tsc_this < vmx->vcpu.kvm->arch.vm_init_tsc)
		tsc_base = tsc_this;

	guest_write_tsc(0, tsc_base);

	return (0);
}

/*
 * Switches to specified vcpu, until a matching vcpu_put(), but assumes
 * vcpu mutex is already taken.
 */
void
vmx_vcpu_load(struct kvm_vcpu *vcpu, int cpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	uint64_t phys_addr = (hat_getpfnum(kas.a_hat, (char *)vmx->vmcs) <<
	    PAGESHIFT) | ((uint64_t)(vmx->vmcs) & 0xfff);
	uint64_t tsc_this, delta, new_offset;

	if (vcpu->cpu != cpu) {
		vcpu_clear(vmx);
#ifdef XXX
		kvm_migrate_timers(vcpu);
#else
		XXX_KVM_PROBE;
#endif
		set_bit(KVM_REQ_TLB_FLUSH, &vcpu->requests);
#ifdef XXX
		kpreempt_disable();
		list_add(&vmx->local_vcpus_link, &per_cpu(vcpus_on_cpu, cpu));
		kpreempt_enable();
#else
		XXX_KVM_PROBE;
#endif
	}

#ifdef XXX
	if (per_cpu(current_vmcs, cpu) != vmx->vmcs) {
		uint8_t error;

		per_cpu(current_vmcs, cpu) = vmx->vmcs;

		/*CSTYLED*/
		__asm__ volatile (__ex(ASM_VMX_VMPTRLD_RAX) "; setna %0"
		    : "=g"(error) : "a"(&phys_addr), "m"(phys_addr)
		    : "cc");
#else
	{
		uint8_t error;

		/*CSTYLED*/
		__asm__ volatile (ASM_VMX_VMPTRLD_RAX ";\n\t setna %0"
		    : "=g"(error) : "a"(&phys_addr), "m"(phys_addr)
		    : "cc");

		XXX_KVM_PROBE;

		if (error)
			cmn_err(CE_PANIC, "kvm: vmptrld %p/%lx fail\n",
			    vmx->vmcs, phys_addr);
#endif
	}

	if (vcpu->cpu != cpu) {
		struct descriptor_table dt;
		unsigned long sysenter_esp;

		vcpu->cpu = cpu;
		/*
		 * Linux uses per-cpu TSS and GDT, so set these when switching
		 * processors.
		 */
		vmcs_writel(HOST_TR_BASE, kvm_read_tr_base()); /* 22.2.4 */
		kvm_get_gdt(&dt);
		vmcs_writel(HOST_GDTR_BASE, dt.base);   /* 22.2.4 */

		rdmsrl(MSR_IA32_SYSENTER_ESP, sysenter_esp);
		vmcs_writel(HOST_IA32_SYSENTER_ESP, sysenter_esp); /* 22.2.3 */

		/*
		 * Make sure the time stamp counter is monotonous.
		 */
		rdtscll(tsc_this);
		if (tsc_this < vcpu->arch.host_tsc) {
			delta = vcpu->arch.host_tsc - tsc_this;
			new_offset = vmcs_read64(TSC_OFFSET) + delta;
			vmcs_write64(TSC_OFFSET, new_offset);
		}
	}
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
#ifdef XXX_KVM_STAT
	++vcpu->stat.fpu_reload;
#endif
#ifdef XXX_KVM_DOESNTCOMPILE
	BT_SET(&vcpu->requests, KVM_REQ_DEACTIVATE_FPU);
#else
	set_bit(KVM_REQ_DEACTIVATE_FPU, &vcpu->requests);
#endif
#ifdef XXX_KVM_TRACE
	trace_kvm_fpu(0);
#endif
}

/* straight from xen code... */
void
ldt_load(void)
{
	*((system_desc_t *)&CPU->cpu_gdt[GDT_LDT]) = curproc->p_ldt_desc;
	wr_ldtr(ULDT_SEL);
}


static void reload_tss(void)
{
	/*
	 * VT restores TR but not its size.  Useless.
	 */
	struct descriptor_table gdt;
	struct desc_struct *descs;

	kvm_get_gdt(&gdt);
	descs = (void *)gdt.base;
	descs[GDT_KTSS].c.b.type = 9; /* available TSS */
	load_TR_desc();
}

int
is_long_mode(struct kvm_vcpu *vcpu)
{
#ifdef CONFIG_X86_64
	return (vcpu->arch.efer & EFER_LMA);
#else
	return (0);
#endif
}

inline ulong
kvm_read_cr4_bits(struct kvm_vcpu *vcpu, ulong mask)
{
	uint64_t tmask = mask & KVM_POSSIBLE_CR4_GUEST_BITS;

	if (tmask & vcpu->arch.cr4_guest_owned_bits)
		kvm_x86_ops->decache_cr4_guest_bits(vcpu);

	return (vcpu->arch.cr4 & mask);
}

inline int
is_pae(struct kvm_vcpu *vcpu)
{
	return (kvm_read_cr4_bits(vcpu, X86_CR4_PAE));
}

static void
__vmx_load_host_state(struct vcpu_vmx *vmx)
{
	unsigned long flags;

	if (!vmx->host_state.loaded)
		return;

#ifdef XXX_KVM_STAT
	++vmx->vcpu.stat.host_state_reload;
#endif
	vmx->host_state.loaded = 0;
	if (vmx->host_state.fs_reload_needed)
		kvm_load_fs(vmx->host_state.fs_sel);
	if (vmx->host_state.gs_ldt_reload_needed) {
		kvm_load_ldt(vmx->host_state.ldt_sel);
		/*
		 * If we have to reload gs, we must take care to
		 * preserve our gs base.
		 */
		cli();
		kvm_load_gs(vmx->host_state.gs_sel);
#ifdef CONFIG_X86_64
		wrmsrl(MSR_GS_BASE, vmcs_readl(HOST_GS_BASE));
#endif
		sti();
	}
	reload_tss();

#ifdef CONFIG_X86_64
	if (is_long_mode(&vmx->vcpu)) {
		rdmsrl(MSR_KERNEL_GS_BASE, vmx->msr_guest_kernel_gs_base);
		wrmsrl(MSR_KERNEL_GS_BASE, vmx->msr_host_kernel_gs_base);
	}
#endif
}

static void
vmx_load_host_state(struct vcpu_vmx *vmx)
{
	kpreempt_disable();
	__vmx_load_host_state(vmx);
	kpreempt_enable();
}

void
vmx_vcpu_put(struct kvm_vcpu *vcpu)
{
	__vmx_load_host_state(to_vmx(vcpu));
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

extern void apic_set_reg(struct kvm_lapic *apic, int reg_off, uint32_t val);

void
kvm_apic_set_version(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;
	struct kvm_cpuid_entry2 *feat;
	uint32_t v = APIC_VERSION;

	if (!irqchip_in_kernel(vcpu->kvm))
		return;

	feat = kvm_find_cpuid_entry(apic->vcpu, 0x1, 0);
	if (feat && (feat->ecx & (1 << (X86_FEATURE_X2APIC & 31))))
		v |= APIC_LVR_DIRECTED_EOI;
	apic_set_reg(apic, APIC_LVR, v);
}


static int
kvm_vcpu_ioctl_set_cpuid2(struct kvm_vcpu *vcpu, struct kvm_cpuid2 *cpuid,
    struct kvm_cpuid_entry2 *entries)
{
	int r;

	r = E2BIG;
	if (cpuid->nent > KVM_MAX_CPUID_ENTRIES)
		goto out;
	bcopy(entries, vcpu->arch.cpuid_entries,
	    cpuid->nent * sizeof (struct kvm_cpuid_entry2));
	vcpu_load(vcpu);
	vcpu->arch.cpuid_nent = cpuid->nent;
	kvm_apic_set_version(vcpu);
	kvm_x86_ops->cpuid_update(vcpu);
	vcpu_put(vcpu);
	return (0);

out:
	return (r);
}

static int
kvm_vcpu_ioctl_get_cpuid2(struct kvm_vcpu *vcpu, struct kvm_cpuid2 *cpuid,
    struct kvm_cpuid_entry2 *entries)
{
	int r;

	r = E2BIG;
	if (cpuid->nent < vcpu->arch.cpuid_nent)
		goto out;

	return (0);
out:
	cpuid->nent = vcpu->arch.cpuid_nent;
	return (r);
}

static void
ept_save_pdptrs(struct kvm_vcpu *vcpu)
{
	if (is_paging(vcpu) && is_pae(vcpu) && !is_long_mode(vcpu)) {
		vcpu->arch.pdptrs[0] = vmcs_read64(GUEST_PDPTR0);
		vcpu->arch.pdptrs[1] = vmcs_read64(GUEST_PDPTR1);
		vcpu->arch.pdptrs[2] = vmcs_read64(GUEST_PDPTR2);
		vcpu->arch.pdptrs[3] = vmcs_read64(GUEST_PDPTR3);
	}

	__set_bit(VCPU_EXREG_PDPTR, (unsigned long *)&vcpu->arch.regs_avail);
	__set_bit(VCPU_EXREG_PDPTR, (unsigned long *)&vcpu->arch.regs_dirty);
}

static void
vmx_cache_reg(struct kvm_vcpu *vcpu, enum kvm_reg reg)
{
	__set_bit(reg, (unsigned long *)&vcpu->arch.regs_avail);

	switch (reg) {
	case VCPU_REGS_RSP:
		vcpu->arch.regs[VCPU_REGS_RSP] = vmcs_readl(GUEST_RSP);
		break;
	case VCPU_REGS_RIP:
		vcpu->arch.regs[VCPU_REGS_RIP] = vmcs_readl(GUEST_RIP);
		break;
	case VCPU_EXREG_PDPTR:
		if (enable_ept)
			ept_save_pdptrs(vcpu);
		break;
	default:
		break;
	}
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

#define	VMX_SEGMENT_FIELD(seg)					\
	[VCPU_SREG_##seg] = {                                   \
		.selector = GUEST_##seg##_SELECTOR,		\
		.base = GUEST_##seg##_BASE,		   	\
		.limit = GUEST_##seg##_LIMIT,		   	\
		.ar_bytes = GUEST_##seg##_AR_BYTES,	   	\
	}

struct kvm_vmx_segment_field kvm_vmx_segment_fields[] = {
	VMX_SEGMENT_FIELD(CS),
	VMX_SEGMENT_FIELD(DS),
	VMX_SEGMENT_FIELD(ES),
	VMX_SEGMENT_FIELD(FS),
	VMX_SEGMENT_FIELD(GS),
	VMX_SEGMENT_FIELD(SS),
	VMX_SEGMENT_FIELD(TR),
	VMX_SEGMENT_FIELD(LDTR),
};

void vmx_get_segment(struct kvm_vcpu *vcpu,
			    struct kvm_segment *var, int seg)
{
	struct kvm_vmx_segment_field *sf = &kvm_vmx_segment_fields[seg];
	uint32_t ar;

	var->base = vmcs_readl(sf->base);
	var->limit = vmcs_read32(sf->limit);
	var->selector = vmcs_read16(sf->selector);
	ar = vmcs_read32(sf->ar_bytes);

	if ((ar & AR_UNUSABLE_MASK) && !emulate_invalid_guest_state)
		ar = 0;
	var->type = ar & 15;
	var->s = (ar >> 4) & 1;
	var->dpl = (ar >> 5) & 3;
	var->present = (ar >> 7) & 1;
	var->avl = (ar >> 12) & 1;
	var->l = (ar >> 13) & 1;
	var->db = (ar >> 14) & 1;
	var->g = (ar >> 15) & 1;
	var->unusable = (ar >> 16) & 1;
}

static uint32_t vmx_segment_access_rights(struct kvm_segment *var)
{
	uint32_t ar;

	if (var->unusable)
		ar = 1 << 16;
	else {
		ar = var->type & 15;
		ar |= (var->s & 1) << 4;
		ar |= (var->dpl & 3) << 5;
		ar |= (var->present & 1) << 7;
		ar |= (var->avl & 1) << 12;
		ar |= (var->l & 1) << 13;
		ar |= (var->db & 1) << 14;
		ar |= (var->g & 1) << 15;
	}
	if (ar == 0) /* a 0 value means unusable */
		ar = AR_UNUSABLE_MASK;

	return (ar);
}

static void
vmx_set_segment(struct kvm_vcpu *vcpu, struct kvm_segment *var, int seg)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct kvm_vmx_segment_field *sf = &kvm_vmx_segment_fields[seg];
	uint32_t ar;

	if (vmx->rmode.vm86_active && seg == VCPU_SREG_TR) {
		vmx->rmode.tr.selector = var->selector;
		vmx->rmode.tr.base = var->base;
		vmx->rmode.tr.limit = var->limit;
		vmx->rmode.tr.ar = vmx_segment_access_rights(var);
		return;
	}
	vmcs_writel(sf->base, var->base);
	vmcs_write32(sf->limit, var->limit);
	vmcs_write16(sf->selector, var->selector);
	if (vmx->rmode.vm86_active && var->s) {
		/*
		 * Hack real-mode segments into vm86 compatibility.
		 */
		if (var->base == 0xffff0000 && var->selector == 0xf000)
			vmcs_writel(sf->base, 0xf0000);
		ar = 0xf3;
	} else
		ar = vmx_segment_access_rights(var);


	/*
	 *   Fix the "Accessed" bit in AR field of segment registers for older
	 * qemu binaries.
	 *   IA32 arch specifies that at the time of processor reset the
	 * "Accessed" bit in the AR field of segment registers is 1. And qemu
	 * is setting it to 0 in the usedland code. This causes invalid guest
	 * state vmexit when "unrestricted guest" mode is turned on.
	 *    Fix for this setup issue in cpu_reset is being pushed in the qemu
	 * tree. Newer qemu binaries with that qemu fix would not need this
	 * kvm hack.
	 */
	if (enable_unrestricted_guest && (seg != VCPU_SREG_LDTR))
		ar |= 0x1; /* Accessed */

	vmcs_write32(sf->ar_bytes, ar);
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


inline ulong
kvm_read_cr4(struct kvm_vcpu *vcpu)
{
	return (kvm_read_cr4_bits(vcpu, ~0UL));
}

inline ulong
kvm_read_cr0(struct kvm_vcpu *vcpu)
{
	return (kvm_read_cr0_bits(vcpu, ~0UL));
}

extern inline uint32_t apic_get_reg(struct kvm_lapic *apic, int reg_off);

uint64_t
kvm_lapic_get_cr8(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;
	uint64_t tpr;

	if (apic == NULL)
		return (0);

	tpr = (uint64_t)apic_get_reg(apic, APIC_TASKPRI);

	return ((tpr & 0xf0) >> 4);
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

extern uint64_t kvm_get_apic_base(struct kvm_vcpu *vcpu);

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

static void destroy_kvm_mmu(struct kvm_vcpu *vcpu)
{
	ASSERT(vcpu);
	if (VALID_PAGE(vcpu->arch.mmu.root_hpa)) {
		vcpu->arch.mmu.free(vcpu);
		vcpu->arch.mmu.root_hpa = INVALID_PAGE;
	}
}

extern int init_kvm_mmu(struct kvm_vcpu *vcpu);

int
kvm_mmu_reset_context(struct kvm_vcpu *vcpu)
{
	destroy_kvm_mmu(vcpu);
	return (init_kvm_mmu(vcpu));
}

static inline void
kvm_queue_interrupt(struct kvm_vcpu *vcpu, uint8_t vector, int soft)
{
	vcpu->arch.interrupt.pending = 1;
	vcpu->arch.interrupt.soft = soft;
	vcpu->arch.interrupt.nr = vector;
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
		bcopy((caddr_t)(addr+offset), data, len);
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
vmx_update_cr8_intercept(struct kvm_vcpu *vcpu, int tpr, int irr)
{
	if (irr == -1 || tpr < irr) {
		vmcs_write32(TPR_THRESHOLD, 0);
		return;
	}

	vmcs_write32(TPR_THRESHOLD, irr);
}

static int
fls(int x)
{
	int r = 32;

	if (!x)
		return (0);

	if (!(x & 0xffff0000u)) {
		x <<= 16;
		r -= 16;
	}
	if (!(x & 0xff000000u)) {
		x <<= 8;
		r -= 8;
	}
	if (!(x & 0xf0000000u)) {
		x <<= 4;
		r -= 4;
	}
	if (!(x & 0xc0000000u)) {
		x <<= 2;
		r -= 2;
	}
	if (!(x & 0x80000000u)) {
		x <<= 1;
		r -= 1;
	}

	return (r);
}

static int
find_highest_vector(void *bitmap)
{
	uint32_t *word = bitmap;
	int word_offset = MAX_APIC_VECTOR >> 5;

	while ((word_offset != 0) && (word[(--word_offset) << 2] == 0))
		continue;

	if (!word_offset && !word[0])
		return (-1);
	else
		return (fls(word[word_offset << 2]) - 1 + (word_offset << 5));
}

static inline int
apic_search_irr(struct kvm_lapic *apic)
{
	return (find_highest_vector((void *)((uintptr_t)apic->regs +
	    APIC_IRR)));
}

static inline int
apic_find_highest_irr(struct kvm_lapic *apic)
{
	int result;

	if (!apic->irr_pending)
		return (-1);

	result = apic_search_irr(apic);
	ASSERT(result == -1 || result >= 16);

	return (result);
}

int
kvm_lapic_find_highest_irr(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;
	int highest_irr;

	/*
	 * This may race with setting of irr in __apic_accept_irq() and
	 * value returned may be wrong, but kvm_vcpu_kick() in __apic_accept_irq
	 * will cause vmexit immediately and the value will be recalculated
	 * on the next vmentry.
	 */
	if (!apic)
		return (0);

	highest_irr = apic_find_highest_irr(apic);

	return (highest_irr);
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

static int
__find_msr_index(struct vcpu_vmx *vmx, uint32_t msr)
{
	int i;

	for (i = 0; i < vmx->nmsrs; i++) {
		if (vmx_msr_index[vmx->guest_msrs[i].index] == msr)
			return (i);
	}

	return (-1);
}

static struct shared_msr_entry *
find_msr_entry(struct vcpu_vmx *vmx, uint32_t msr)
{
	int i;

	i = __find_msr_index(vmx, msr);
	if (i >= 0)
		return (&vmx->guest_msrs[i]);

	return (NULL);
}

/*
 * Swap MSR entry in host/guest MSR entry array.
 */
static void
move_msr_up(struct vcpu_vmx *vmx, int from, int to)
{
	struct shared_msr_entry tmp;

	tmp = vmx->guest_msrs[to];
	vmx->guest_msrs[to] = vmx->guest_msrs[from];
	vmx->guest_msrs[from] = tmp;
}

static int
update_transition_efer(struct vcpu_vmx *vmx, int efer_offset)
{
	uint64_t guest_efer;
	uint64_t ignore_bits;

	guest_efer = vmx->vcpu.arch.efer;

	/*
	 * NX is emulated; LMA and LME handled by hardware; SCE meaninless
	 * outside long mode
	 */
	ignore_bits = EFER_NX | EFER_SCE;
#ifdef CONFIG_X86_64
	ignore_bits |= EFER_LMA | EFER_LME;
	/* SCE is meaningful only in long mode on Intel */
	if (guest_efer & EFER_LMA)
		ignore_bits &= ~(uint64_t)EFER_SCE;
#endif
	guest_efer &= ~ignore_bits;
	guest_efer |= host_efer & ignore_bits;
	vmx->guest_msrs[efer_offset].data = guest_efer;
	vmx->guest_msrs[efer_offset].mask = ~ignore_bits;

	return (1);
}

/*
 * Set up the vmcs to automatically save and restore system
 * msrs.  Don't touch the 64-bit msrs if the guest is in legacy
 * mode, as fiddling with msrs is very expensive.
 */
void
setup_msrs(struct vcpu_vmx *vmx)
{
	int save_nmsrs, index;
	unsigned long *msr_bitmap;

	vmx_load_host_state(vmx);
	save_nmsrs = 0;
#ifdef CONFIG_X86_64
	if (is_long_mode(&vmx->vcpu)) {
		index = __find_msr_index(vmx, MSR_SYSCALL_MASK);
		if (index >= 0)
			move_msr_up(vmx, index, save_nmsrs++);
		index = __find_msr_index(vmx, MSR_LSTAR);
		if (index >= 0)
			move_msr_up(vmx, index, save_nmsrs++);
		index = __find_msr_index(vmx, MSR_CSTAR);
		if (index >= 0)
			move_msr_up(vmx, index, save_nmsrs++);
		index = __find_msr_index(vmx, MSR_TSC_AUX);
		if (index >= 0 && vmx->rdtscp_enabled)
			move_msr_up(vmx, index, save_nmsrs++);
		/*
		 * MSR_K6_STAR is only needed on long mode guests, and only
		 * if efer.sce is enabled.
		 */
		index = __find_msr_index(vmx, MSR_K6_STAR);
		if ((index >= 0) && (vmx->vcpu.arch.efer & EFER_SCE))
			move_msr_up(vmx, index, save_nmsrs++);
	}
#endif
	index = __find_msr_index(vmx, MSR_EFER);
	if (index >= 0 && update_transition_efer(vmx, index))
		move_msr_up(vmx, index, save_nmsrs++);

	vmx->save_nmsrs = save_nmsrs;

	if (cpu_has_vmx_msr_bitmap()) {
		if (is_long_mode(&vmx->vcpu))
			msr_bitmap = vmx_msr_bitmap_longmode;
		else
			msr_bitmap = vmx_msr_bitmap_legacy;

		vmcs_write64(MSR_BITMAP, kvm_va2pa((caddr_t)msr_bitmap));
	}
}

void
vmx_set_efer(struct kvm_vcpu *vcpu, uint64_t efer)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct shared_msr_entry *msr = find_msr_entry(vmx, MSR_EFER);

	if (!msr)
		return;

	/*
	 * Force kernel_gs_base reloading before EFER changes, as control
	 * of this msr depends on is_long_mode().
	 */
	vmx_load_host_state(to_vmx(vcpu));
	vcpu->arch.efer = efer;
	if (efer & EFER_LMA) {
		vmcs_write32(VM_ENTRY_CONTROLS,
		    vmcs_read32(VM_ENTRY_CONTROLS) | VM_ENTRY_IA32E_MODE);
		msr->data = efer;
	} else {
		vmcs_write32(VM_ENTRY_CONTROLS,
		    vmcs_read32(VM_ENTRY_CONTROLS) & ~VM_ENTRY_IA32E_MODE);

		msr->data = efer & ~EFER_LME;
	}

	setup_msrs(vmx);
}

static inline int
is_protmode(struct kvm_vcpu *vcpu)
{
	return (kvm_read_cr0_bits(vcpu, X86_CR0_PE));
}


int
kvm_vcpu_is_bsp(struct kvm_vcpu *vcpu)
{
	return (vcpu->kvm->bsp_vcpu_id == vcpu->vcpu_id);
}

void
kvm_pic_clear_isr_ack(struct kvm *kvm)
{
	struct kvm_pic *s = pic_irqchip(kvm);

	mutex_enter(&s->lock);
	s->pics[0].isr_ack = 0xff;
	s->pics[1].isr_ack = 0xff;
	mutex_exit(&s->lock);
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
		bcopy(data, (caddr_t)(addr+offset), len);
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

static inline int
apic_x2apic_mode(struct kvm_lapic *apic)
{
	return (apic->vcpu->arch.apic_base & X2APIC_ENABLE);
}

extern int apic_reg_write(struct kvm_lapic *apic, uint32_t reg, uint32_t val);

int
kvm_x2apic_msr_write(struct kvm_vcpu *vcpu, uint32_t msr, uint64_t data)
{
	struct kvm_lapic *apic = vcpu->arch.apic;
	uint32_t reg = (msr - APIC_BASE_MSR) << 4;

	if (!irqchip_in_kernel(vcpu->kvm) || !apic_x2apic_mode(apic))
		return (1);

	/* if this is ICR write vector before command */
	if (msr == 0x830)
		apic_reg_write(apic, APIC_ICR2, (uint32_t)(data >> 32));

	return (apic_reg_write(apic, reg, (uint32_t)data));
}

extern int apic_reg_read(struct kvm_lapic *apic,
    uint32_t offset, int len, void *data);

int
kvm_x2apic_msr_read(struct kvm_vcpu *vcpu, uint32_t msr, uint64_t *data)
{
	struct kvm_lapic *apic = vcpu->arch.apic;
	uint32_t reg = (msr - APIC_BASE_MSR) << 4, low, high = 0;

	if (!irqchip_in_kernel(vcpu->kvm) || !apic_x2apic_mode(apic))
		return (1);

	if (apic_reg_read(apic, reg, 4, &low))
		return (1);

	if (msr == 0x830)
		apic_reg_read(apic, APIC_ICR2, 4, &high);

	*data = (((uint64_t)high) << 32) | low;

	return (0);
}

int
kvm_hv_vapic_msr_write(struct kvm_vcpu *vcpu, uint32_t reg, uint64_t data)
{
	struct kvm_lapic *apic = vcpu->arch.apic;

	if (!irqchip_in_kernel(vcpu->kvm))
		return (1);

	/* if this is ICR write vector before command */
	if (reg == APIC_ICR)
		apic_reg_write(apic, APIC_ICR2, (uint32_t)(data >> 32));

	return (apic_reg_write(apic, reg, (uint32_t)data));
}

int
kvm_hv_vapic_msr_read(struct kvm_vcpu *vcpu, uint32_t reg, uint64_t *data)
{
	struct kvm_lapic *apic = vcpu->arch.apic;
	uint32_t low, high = 0;

	if (!irqchip_in_kernel(vcpu->kvm))
		return (1);

	if (apic_reg_read(apic, reg, 4, &low))
		return (1);

	if (reg == APIC_ICR)
		apic_reg_read(apic, APIC_ICR2, 4, &high);

	*data = (((uint64_t)high) << 32) | low;

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
 * reads and returns guest's timestamp counter "register"
 * guest_tsc = host_tsc + tsc_offset    -- 21.3
 */
static uint64_t
guest_read_tsc(void)
{
	uint64_t host_tsc, tsc_offset;

	rdtscll(host_tsc);
	tsc_offset = vmcs_read64(TSC_OFFSET);
	return (host_tsc + tsc_offset);
}

/*
 * Reads an msr value (of 'msr_index') into 'pdata'.
 * Returns 0 on success, non-0 otherwise.
 * Assumes vcpu_load() was already called.
 */
static int
vmx_get_msr(struct kvm_vcpu *vcpu, uint32_t msr_index, uint64_t *pdata)
{
	uint64_t data;
	struct shared_msr_entry *msr;

	if (!pdata) {
		cmn_err(CE_WARN, "BUG: get_msr called with NULL pdata\n");
		return (EINVAL);
	}

	switch (msr_index) {
#ifdef CONFIG_X86_64
	case MSR_FS_BASE:
		data = vmcs_readl(GUEST_FS_BASE);
		break;
	case MSR_GS_BASE:
		data = vmcs_readl(GUEST_GS_BASE);
		break;
	case MSR_KERNEL_GS_BASE:
		vmx_load_host_state(to_vmx(vcpu));
		data = to_vmx(vcpu)->msr_guest_kernel_gs_base;
		break;
#endif
	case MSR_EFER:
		return (kvm_get_msr_common(vcpu, msr_index, pdata));
	case MSR_IA32_TSC:
		data = guest_read_tsc();
		break;
	case MSR_IA32_SYSENTER_CS:
		data = vmcs_read32(GUEST_SYSENTER_CS);
		break;
	case MSR_IA32_SYSENTER_EIP:
		data = vmcs_readl(GUEST_SYSENTER_EIP);
		break;
	case MSR_IA32_SYSENTER_ESP:
		data = vmcs_readl(GUEST_SYSENTER_ESP);
		break;
	case MSR_TSC_AUX:
		if (!to_vmx(vcpu)->rdtscp_enabled)
			return (1);
		/* Otherwise falls through */
	default:
		vmx_load_host_state(to_vmx(vcpu));
		msr = find_msr_entry(to_vmx(vcpu), msr_index);
		if (msr) {
			vmx_load_host_state(to_vmx(vcpu));
			data = msr->data;
			break;
		}
		return (kvm_get_msr_common(vcpu, msr_index, pdata));
	}

	*pdata = data;

	return (0);
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
static int
vmx_set_msr(struct kvm_vcpu *vcpu, uint32_t msr_index, uint64_t data)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct shared_msr_entry *msr;
	uint64_t host_tsc;
	int ret = 0;

	switch (msr_index) {
	case MSR_EFER:
		vmx_load_host_state(vmx);
		ret = kvm_set_msr_common(vcpu, msr_index, data);
		break;
#ifdef CONFIG_X86_64
	case MSR_FS_BASE:
		vmcs_writel(GUEST_FS_BASE, data);
		break;
	case MSR_GS_BASE:
		vmcs_writel(GUEST_GS_BASE, data);
		break;
	case MSR_KERNEL_GS_BASE:
		vmx_load_host_state(vmx);
		vmx->msr_guest_kernel_gs_base = data;
		break;
#endif
	case MSR_IA32_SYSENTER_CS:
		vmcs_write32(GUEST_SYSENTER_CS, data);
		break;
	case MSR_IA32_SYSENTER_EIP:
		vmcs_writel(GUEST_SYSENTER_EIP, data);
		break;
	case MSR_IA32_SYSENTER_ESP:
		vmcs_writel(GUEST_SYSENTER_ESP, data);
		break;
	case MSR_IA32_TSC:
		rdtscll(host_tsc);
		guest_write_tsc(data, host_tsc);
		break;
	case MSR_IA32_CR_PAT:
		if (vmcs_config.vmentry_ctrl & VM_ENTRY_LOAD_IA32_PAT) {
			vmcs_write64(GUEST_IA32_PAT, data);
			vcpu->arch.pat = data;
			break;
		}
		ret = kvm_set_msr_common(vcpu, msr_index, data);
		break;
	case MSR_TSC_AUX:
		if (!vmx->rdtscp_enabled)
			return (1);
		/* Check reserved bit, higher 32 bits should be zero */
		if ((data >> 32) != 0)
			return (1);
		/* Otherwise falls through */
	default:
		msr = find_msr_entry(vmx, msr_index);
		if (msr) {
			vmx_load_host_state(vmx);
			msr->data = data;
			break;
		}
		ret = kvm_set_msr_common(vcpu, msr_index, data);
	}

	return (ret);
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

static inline int
is_machine_check(uint32_t intr_info)
{
	return (intr_info & (INTR_INFO_INTR_TYPE_MASK | INTR_INFO_VECTOR_MASK |
	    INTR_INFO_VALID_MASK)) == (INTR_TYPE_HARD_EXCEPTION |
	    MC_VECTOR | INTR_INFO_VALID_MASK);
}

/*
 * Trigger machine check on the host. We assume all the MSRs are already set up
 * by the CPU and that we still run on the same CPU as the MCE occurred on.
 * We pass a fake environment to the machine check handler because we want
 * the guest to be always treated like user space, no matter what context
 * it used internally.
 */
static void kvm_machine_check(void)
{
#if defined(CONFIG_X86_MCE) && defined(CONFIG_X86_64)
	struct pt_regs regs = {
		.cs = 3, /* Fake ring 3 no matter what the guest ran on */
		.flags = X86_EFLAGS_IF,
	};

	do_machine_check(&regs, 0);
#endif
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

static inline void
kvm_clear_exception_queue(struct kvm_vcpu *vcpu)
{
	vcpu->arch.exception.pending = 0;
}

static inline void
kvm_clear_interrupt_queue(struct kvm_vcpu *vcpu)
{
	vcpu->arch.interrupt.pending = 0;
}

static void
vmx_complete_interrupts(struct vcpu_vmx *vmx)
{
	uint32_t exit_intr_info;
	uint32_t idt_vectoring_info = vmx->idt_vectoring_info;
	int unblock_nmi;
	uint8_t vector;
	int type;
	int idtv_info_valid;

	exit_intr_info = vmcs_read32(VM_EXIT_INTR_INFO);

	vmx->exit_reason = vmcs_read32(VM_EXIT_REASON);

	/* Handle machine checks before interrupts are enabled */
	if ((vmx->exit_reason == EXIT_REASON_MCE_DURING_VMENTRY) ||
	    (vmx->exit_reason == EXIT_REASON_EXCEPTION_NMI &&
	    is_machine_check(exit_intr_info)))
		kvm_machine_check();

	/* We need to handle NMIs before interrupts are enabled */
	if ((exit_intr_info & INTR_INFO_INTR_TYPE_MASK) == INTR_TYPE_NMI_INTR &&
	    (exit_intr_info & INTR_INFO_VALID_MASK))
		__asm__("int $2");

	idtv_info_valid = idt_vectoring_info & VECTORING_INFO_VALID_MASK;

	if (cpu_has_virtual_nmis()) {
		unblock_nmi = (exit_intr_info & INTR_INFO_UNBLOCK_NMI) != 0;
		vector = exit_intr_info & INTR_INFO_VECTOR_MASK;
		/*
		 * SDM 3: 27.7.1.2 (September 2008)
		 * Re-set bit "block by NMI" before VM entry if vmexit caused by
		 * a guest IRET fault.
		 * SDM 3: 23.2.2 (September 2008)
		 * Bit 12 is undefined in any of the following cases:
		 *  If the VM exit sets the valid bit in the IDT-vectoring
		 *   information field.
		 *  If the VM exit is due to a double fault.
		 */
		if ((exit_intr_info & INTR_INFO_VALID_MASK) && unblock_nmi &&
		    vector != DF_VECTOR && !idtv_info_valid)
			vmcs_set_bits(GUEST_INTERRUPTIBILITY_INFO,
			    GUEST_INTR_STATE_NMI);
	} else if (vmx->soft_vnmi_blocked) {
#ifdef XXX
		vmx->vnmi_blocked_time +=
			ktime_to_ns(ktime_sub(ktime_get(), vmx->entry_time));
#else
		vmx->vnmi_blocked_time +=
			gethrtime() - vmx->entry_time;
		XXX_KVM_PROBE;
#endif
	}

	vmx->vcpu.arch.nmi_injected = 0;
	kvm_clear_exception_queue(&vmx->vcpu);
	kvm_clear_interrupt_queue(&vmx->vcpu);

	if (!idtv_info_valid)
		return;

	vector = idt_vectoring_info & VECTORING_INFO_VECTOR_MASK;
	type = idt_vectoring_info & VECTORING_INFO_TYPE_MASK;

	switch (type) {
	case INTR_TYPE_NMI_INTR:
		vmx->vcpu.arch.nmi_injected = 1;
		/*
		 * SDM 3: 27.7.1.2 (September 2008)
		 * Clear bit "block by NMI" before VM entry if a NMI
		 * delivery faulted.
		 */
		vmcs_clear_bits(GUEST_INTERRUPTIBILITY_INFO,
				GUEST_INTR_STATE_NMI);
		break;
	case INTR_TYPE_SOFT_EXCEPTION:
		vmx->vcpu.arch.event_exit_inst_len =
			vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
		/* fall through */
	case INTR_TYPE_HARD_EXCEPTION:
		if (idt_vectoring_info & VECTORING_INFO_DELIVER_CODE_MASK) {
			uint32_t err = vmcs_read32(IDT_VECTORING_ERROR_CODE);
			kvm_queue_exception_e(&vmx->vcpu, vector, err);
		} else
			kvm_queue_exception(&vmx->vcpu, vector);
		break;
	case INTR_TYPE_SOFT_INTR:
		vmx->vcpu.arch.event_exit_inst_len =
			vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
		/* fall through */
	case INTR_TYPE_EXT_INTR:
		kvm_queue_interrupt(&vmx->vcpu, vector,
			type == INTR_TYPE_SOFT_INTR);
		break;
	default:
		break;
	}
}

#ifdef CONFIG_X86_64
#define	R "r"
#define	Q "q"
#else
#define	R "e"
#define	Q "l"
#endif

/*
 * Failure to inject an interrupt should give us the information
 * in IDT_VECTORING_INFO_FIELD.  However, if the failure occurs
 * when fetching the interrupt redirection bitmap in the real-mode
 * tss, this doesn't happen.  So we do it ourselves.
 */
static void
fixup_rmode_irq(struct vcpu_vmx *vmx)
{
	vmx->rmode.irq.pending = 0;
	if (kvm_rip_read(&vmx->vcpu) + 1 != vmx->rmode.irq.rip)
		return;

	kvm_rip_write(&vmx->vcpu, vmx->rmode.irq.rip);
	if (vmx->idt_vectoring_info & VECTORING_INFO_VALID_MASK) {
		vmx->idt_vectoring_info &= ~VECTORING_INFO_TYPE_MASK;
		vmx->idt_vectoring_info |= INTR_TYPE_EXT_INTR;
		return;
	}

	vmx->idt_vectoring_info = VECTORING_INFO_VALID_MASK |
	    INTR_TYPE_EXT_INTR | vmx->rmode.irq.vector;
}

static void
vmx_vcpu_run(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	/* Record the guest's net vcpu time for enforced NMI injections. */
	if (!cpu_has_virtual_nmis() && vmx->soft_vnmi_blocked) {
#ifdef XXX
		vmx->entry_time = ktime_get();
#else
		vmx->entry_time = gethrtime();
		XXX_KVM_PROBE;
#endif
	}

	/*
	 * Don't enter VMX if guest state is invalid, let the exit handler
	 * start emulation until we arrive back to a valid state
	 */
	if (vmx->emulation_required && emulate_invalid_guest_state)
		return;

	if (test_bit(VCPU_REGS_RSP, (unsigned long *)&vcpu->arch.regs_dirty))
		vmcs_writel(GUEST_RSP, vcpu->arch.regs[VCPU_REGS_RSP]);
	if (test_bit(VCPU_REGS_RIP, (unsigned long *)&vcpu->arch.regs_dirty))
		vmcs_writel(GUEST_RIP, vcpu->arch.regs[VCPU_REGS_RIP]);

	DTRACE_PROBE1(kvm__vrun, unsigned long, vcpu->arch.regs[VCPU_REGS_RIP]);

	/*
	 * When single-stepping over STI and MOV SS, we must clear the
	 * corresponding interruptibility bits in the guest state. Otherwise
	 * vmentry fails as it then expects bit 14 (BS) in pending debug
	 * exceptions being set, but that's not correct for the guest debugging
	 * case.
	 */
	if (vcpu->guest_debug & KVM_GUESTDBG_SINGLESTEP)
		vmx_set_interrupt_shadow(vcpu, 0);

	/*
	 * Loading guest fpu may have cleared host cr0.ts
	 */
	vmcs_writel(HOST_CR0, read_cr0());

	__asm__(
	    /* Store host registers */
	    "push %%"R"dx; push %%"R"bp;"
	    "push %%"R"cx \n\t"
	    "cmp %%"R"sp, %c[host_rsp](%0) \n\t"
	    "je 1f \n\t"
	    "mov %%"R"sp, %c[host_rsp](%0) \n\t"
	    __ex(ASM_VMX_VMWRITE_RSP_RDX) "\n\t"
	    "1: \n\t"
	    /* Reload cr2 if changed */
	    "mov %c[cr2](%0), %%"R"ax \n\t"
	    "mov %%cr2, %%"R"dx \n\t"
	    "cmp %%"R"ax, %%"R"dx \n\t"
	    "je 2f \n\t"
	    "mov %%"R"ax, %%cr2 \n\t"
	    "2: \n\t"
	    /* Check if vmlaunch of vmresume is needed */
	    "cmpl $0, %c[launched](%0) \n\t"
	    /* Load guest registers.  Don't clobber flags. */
	    "mov %c[rax](%0), %%"R"ax \n\t"
	    "mov %c[rbx](%0), %%"R"bx \n\t"
	    "mov %c[rdx](%0), %%"R"dx \n\t"
	    "mov %c[rsi](%0), %%"R"si \n\t"
	    "mov %c[rdi](%0), %%"R"di \n\t"
	    "mov %c[rbp](%0), %%"R"bp \n\t"
#ifdef CONFIG_X86_64
	    "mov %c[r8](%0),  %%r8  \n\t"
	    "mov %c[r9](%0),  %%r9  \n\t"
	    "mov %c[r10](%0), %%r10 \n\t"
	    "mov %c[r11](%0), %%r11 \n\t"
	    "mov %c[r12](%0), %%r12 \n\t"
	    "mov %c[r13](%0), %%r13 \n\t"
	    "mov %c[r14](%0), %%r14 \n\t"
	    "mov %c[r15](%0), %%r15 \n\t"
#endif
	    "mov %c[rcx](%0), %%"R"cx \n\t" /* kills %0 (ecx) */

	    /* Enter guest mode */
	    "jne .Llaunched \n\t"
	    __ex(ASM_VMX_VMLAUNCH) "\n\t"
	    "jmp .Lkvm_vmx_return \n\t"
	    ".Llaunched: " __ex(ASM_VMX_VMRESUME) "\n\t"
	    ".Lkvm_vmx_return: "
	    /* Save guest registers, load host registers, keep flags */
	    "xchg %0,     (%%"R"sp) \n\t"
	    "mov %%"R"ax, %c[rax](%0) \n\t"
	    "mov %%"R"bx, %c[rbx](%0) \n\t"
	    "push"Q" (%%"R"sp); pop"Q" %c[rcx](%0) \n\t"
	    "mov %%"R"dx, %c[rdx](%0) \n\t"
	    "mov %%"R"si, %c[rsi](%0) \n\t"
	    "mov %%"R"di, %c[rdi](%0) \n\t"
	    "mov %%"R"bp, %c[rbp](%0) \n\t"
#ifdef CONFIG_X86_64
	    "mov %%r8,  %c[r8](%0) \n\t"
	    "mov %%r9,  %c[r9](%0) \n\t"
	    "mov %%r10, %c[r10](%0) \n\t"
	    "mov %%r11, %c[r11](%0) \n\t"
	    "mov %%r12, %c[r12](%0) \n\t"
	    "mov %%r13, %c[r13](%0) \n\t"
	    "mov %%r14, %c[r14](%0) \n\t"
	    "mov %%r15, %c[r15](%0) \n\t"
#endif
	    "mov %%cr2, %%"R"ax   \n\t"
	    "mov %%"R"ax, %c[cr2](%0) \n\t"

	    "pop  %%"R"bp; pop  %%"R"bp; pop  %%"R"dx \n\t"
	    "setbe %c[fail](%0) \n\t"
	    : : "c"(vmx), "d"((unsigned long)HOST_RSP),
	    [launched]"i"(offsetof(struct vcpu_vmx, launched)),
	    [fail]"i"(offsetof(struct vcpu_vmx, fail)),
	    [host_rsp]"i"(offsetof(struct vcpu_vmx, host_rsp)),
	    [rax]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RAX])),
	    [rbx]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RBX])),
	    [rcx]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RCX])),
	    [rdx]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RDX])),
	    [rsi]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RSI])),
	    [rdi]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RDI])),
	    [rbp]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RBP])),
#ifdef CONFIG_X86_64
	    [r8]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R8])),
	    [r9]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R9])),
	    [r10]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R10])),
	    [r11]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R11])),
	    [r12]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R12])),
	    [r13]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R13])),
	    [r14]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R14])),
	    [r15]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R15])),
#endif
	    [cr2]"i"(offsetof(struct vcpu_vmx, vcpu.arch.cr2))
	    : "cc", "memory"
	    /*CSTYLED*/
	    , R"bx", R"di", R"si"
#ifdef CONFIG_X86_64
	    /*CSTYLED*/
	    , "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
#endif
	/*CSTYLED*/
	);

	vcpu->arch.regs_avail = ~((1 << VCPU_REGS_RIP) |
	    (1 << VCPU_REGS_RSP) | (1 << VCPU_EXREG_PDPTR));
	vcpu->arch.regs_dirty = 0;

	vmx->idt_vectoring_info = vmcs_read32(IDT_VECTORING_INFO_FIELD);

	if (vmx->rmode.irq.pending)
		fixup_rmode_irq(vmx);

#ifdef XXX
	__asm__("mov %0, %%ds; mov %0, %%es" :
	    : "r"SEL_GDT(GDT_UDATA, SEL_UPL));
#else
	XXX_KVM_PROBE;
	__asm__("mov %0, %%ds; mov %0, %%es" : : "r"KDS_SEL);
#endif
	vmx->launched = 1;

	vmx_complete_interrupts(vmx);
}

#undef R
#undef Q

/* XXX - need to dynamic alloc based on cpus, not vcpus */
static struct kvm_shared_msrs shared_msrs[KVM_MAX_VCPUS];

static void kvm_on_user_return(struct kvm_vcpu *,
    struct kvm_user_return_notifier *);

static void
shared_msr_update(unsigned slot, uint32_t msr)
{
	struct kvm_shared_msrs *smsr;
	uint64_t value;
#ifdef XXX
	smsr = &__get_cpu_var(shared_msrs);
#else
	smsr = &shared_msrs[0];
	XXX_KVM_PROBE;
#endif
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
#ifdef XXX_KVM_DECLARATION
	struct kvm_shared_msrs *smsr = &__get_cpu_var(shared_msrs);
#else
	struct kvm_shared_msrs *smsr = &shared_msrs[0];
#endif

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

static void
vmx_save_host_state(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	int i;

	if (vmx->host_state.loaded)
		return;

	vmx->host_state.loaded = 1;
	/*
	 * Set host fs and gs selectors.  Unfortunately, 22.2.3 does not
	 * allow segment selectors with cpl > 0 or ti == 1.
	 */
	vmx->host_state.ldt_sel = kvm_read_ldt();
	vmx->host_state.gs_ldt_reload_needed = vmx->host_state.ldt_sel;
	vmx->host_state.fs_sel = kvm_read_fs();
	if (!(vmx->host_state.fs_sel & 7)) {
		vmcs_write16(HOST_FS_SELECTOR, vmx->host_state.fs_sel);
		vmx->host_state.fs_reload_needed = 0;
	} else {
		vmcs_write16(HOST_FS_SELECTOR, 0);
		vmx->host_state.fs_reload_needed = 1;
	}
	vmx->host_state.gs_sel = kvm_read_gs();
	if (!(vmx->host_state.gs_sel & 7))
		vmcs_write16(HOST_GS_SELECTOR, vmx->host_state.gs_sel);
	else {
		vmcs_write16(HOST_GS_SELECTOR, 0);
		vmx->host_state.gs_ldt_reload_needed = 1;
	}

#ifdef CONFIG_X86_64
	vmcs_writel(HOST_FS_BASE, read_msr(MSR_FS_BASE));
	vmcs_writel(HOST_GS_BASE, read_msr(MSR_GS_BASE));
#else
	vmcs_writel(HOST_FS_BASE, segment_base(vmx->host_state.fs_sel));
	vmcs_writel(HOST_GS_BASE, segment_base(vmx->host_state.gs_sel));
#endif

#ifdef CONFIG_X86_64
	if (is_long_mode(&vmx->vcpu)) {
		rdmsrl(MSR_KERNEL_GS_BASE, vmx->msr_host_kernel_gs_base);
		wrmsrl(MSR_KERNEL_GS_BASE, vmx->msr_guest_kernel_gs_base);
	}
#endif
	for (i = 0; i < vmx->save_nmsrs; i++) {
		kvm_set_shared_msr(vcpu, vmx->guest_msrs[i].index,
		    vmx->guest_msrs[i].data, vmx->guest_msrs[i].mask);
	}
}

int
vmx_interrupt_allowed(struct kvm_vcpu *vcpu)
{
	return ((vmcs_readl(GUEST_RFLAGS) & X86_EFLAGS_IF) &&
	    !(vmcs_read32(GUEST_INTERRUPTIBILITY_INFO) &
	    (GUEST_INTR_STATE_STI | GUEST_INTR_STATE_MOV_SS)));
}

int
kvm_arch_interrupt_allowed(struct kvm_vcpu *vcpu)
{
	return (kvm_x86_ops->interrupt_allowed(vcpu));
}

static int
handle_machine_check(struct kvm_vcpu *vcpu)
{
	/* already handled by vcpu_run */
	return (1);
}

static inline int
is_page_fault(uint32_t intr_info)
{
	return ((intr_info & (INTR_INFO_INTR_TYPE_MASK | INTR_INFO_VECTOR_MASK |
	    INTR_INFO_VALID_MASK)) == (INTR_TYPE_HARD_EXCEPTION |
	    PF_VECTOR | INTR_INFO_VALID_MASK));
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
#ifdef XXX_KVM_STAT
	++vcpu->stat.pf_guest;
#endif
	vcpu->arch.cr2 = addr;
	kvm_queue_exception_e(vcpu, PF_VECTOR, error_code);
}

static int
kvm_read_guest_virt_system(gva_t addr, void *val, unsigned int bytes,
    struct kvm_vcpu *vcpu, uint32_t *error)
{
	return (kvm_read_guest_virt_helper(addr, val, bytes, vcpu, 0, error));
}

static int vmx_get_cpl(struct kvm_vcpu *vcpu)
{
	if (!is_protmode(vcpu))
		return (0);

	if (vmx_get_rflags(vcpu) & X86_EFLAGS_VM) /* if virtual 8086 */
		return (3);

	return (vmcs_read16(GUEST_CS_SELECTOR) & 3);
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
#ifdef XXX_KVM_TRACE
		trace_kvm_mmio(KVM_TRACE_MMIO_READ, bytes,
		    vcpu->mmio_phys_addr, *(uint64_t *)val);
#endif
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
#ifdef XXX_KVM_TRACE
		trace_kvm_mmio(KVM_TRACE_MMIO_READ, bytes, gpa,
		    *(uint64_t *)val);
#endif
		return (X86EMUL_CONTINUE);
	}

#ifdef XXX_KVM_TRACE
	trace_kvm_mmio(KVM_TRACE_MMIO_READ_UNSATISFIED, bytes, gpa, 0);
#endif

	vcpu->mmio_needed = 1;
	vcpu->mmio_phys_addr = gpa;
	vcpu->mmio_size = bytes;
	vcpu->mmio_is_write = 0;

	return (X86EMUL_UNHANDLEABLE);
}

static void
mmu_guess_page_from_pte_write(struct kvm_vcpu *vcpu, gpa_t gpa,
    const uint8_t *new, int bytes)
{
	gfn_t gfn;
	int r;
	uint64_t gpte = 0;
	pfn_t pfn;

	if (bytes != 4 && bytes != 8)
		return;

	/*
	 * Assume that the pte write on a page table of the same type
	 * as the current vcpu paging mode.  This is nearly always true
	 * (might be false while changing modes).  Note it is verified later
	 * by update_pte().
	 */
	if (is_pae(vcpu)) {
		/* Handle a 32-bit guest writing two halves of a 64-bit gpte */
		if ((bytes == 4) && (gpa % 4 == 0)) {
			r = kvm_read_guest(vcpu->kvm,
			    gpa & ~(uint64_t)7, &gpte, 8);

			if (r)
				return;
			memcpy((void *)((uintptr_t)&gpte + (gpa % 8)), new, 4);
		} else if ((bytes == 8) && (gpa % 8 == 0)) {
			memcpy((void *)&gpte, new, 8);
		}
	} else {
		if ((bytes == 4) && (gpa % 4 == 0))
			memcpy((void *)&gpte, new, 4);
	}
	if (!is_present_gpte(gpte))
		return;

	gfn = (gpte & PT64_BASE_ADDR_MASK) >> PAGESHIFT;

#ifdef XXX
	vcpu->arch.update_pte.mmu_seq = vcpu->kvm->mmu_notifier_seq;
	smp_rmb();
#else
	XXX_KVM_PROBE;
#endif
	pfn = gfn_to_pfn(vcpu->kvm, gfn);

	if (is_error_pfn(pfn)) {
		kvm_release_pfn_clean(pfn);
		return;
	}
	vcpu->arch.update_pte.gfn = gfn;
	vcpu->arch.update_pte.pfn = pfn;
}

extern void
mmu_pte_write_new_pte(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp,
    uint64_t *spte, const void *new);

static void
kvm_mmu_access_page(struct kvm_vcpu *vcpu, gfn_t gfn)
{
	uint64_t *spte = vcpu->arch.last_pte_updated;

	if (spte && vcpu->arch.last_pte_gfn == gfn && shadow_accessed_mask &&
	    !(*spte & shadow_accessed_mask) && is_shadow_present_pte(*spte))
		set_bit(PT_ACCESSED_SHIFT, (unsigned long *)spte);
}

static void
mmu_pte_write_zap_pte(struct kvm_vcpu *vcpu,
    struct kvm_mmu_page *sp, uint64_t *spte)
{
	uint64_t pte;
	struct kvm_mmu_page *child;

	pte = *spte;

	if (is_shadow_present_pte(pte)) {
		if (is_last_spte(pte, sp->role.level)) {
			rmap_remove(vcpu->kvm, spte);
		} else {
			child = page_header(pte & PT64_BASE_ADDR_MASK);
			mmu_page_remove_parent_pte(child, spte);
		}
	}
	__set_spte(spte, shadow_trap_nonpresent_pte);
#ifdef XXX_KVM_STAT
	if (is_large_pte(pte))
		--vcpu->kvm->stat.lpages;
#endif
}

static int
last_updated_pte_accessed(struct kvm_vcpu *vcpu)
{
	uint64_t *spte = vcpu->arch.last_pte_updated;

	return (!!(spte && (*spte & shadow_accessed_mask)));
}

static void
mmu_pte_write_flush_tlb(struct kvm_vcpu *vcpu, uint64_t old, uint64_t new)
{
#ifdef XXX
	if (need_remote_flush(old, new))
		kvm_flush_remote_tlbs(vcpu->kvm);
	else {
#else
	{
		XXX_KVM_PROBE;
#endif
		kvm_mmu_flush_tlb(vcpu);
	}
}

void
kvm_mmu_pte_write(struct kvm_vcpu *vcpu, gpa_t gpa,
    const uint8_t *new, int bytes, int guest_initiated)
{
	gfn_t gfn = gpa >> PAGESHIFT;
	struct kvm_mmu_page *sp;
	list_t *bucket;
	unsigned index;
	uint64_t entry, gentry;
	uint64_t *spte;
	unsigned offset = offset_in_page(gpa);
	unsigned pte_size;
	unsigned page_offset;
	unsigned misaligned;
	unsigned quadrant;
	int level;
	int flooded = 0;
	int npte;
	int r;

	mmu_guess_page_from_pte_write(vcpu, gpa, new, bytes);
	mutex_enter(&vcpu->kvm->mmu_lock);
	kvm_mmu_access_page(vcpu, gfn);
	kvm_mmu_free_some_pages(vcpu);
#ifdef XXX_KVM_STAT
	++vcpu->kvm->stat.mmu_pte_write;
	kvm_mmu_audit(vcpu, "pre pte write");
#endif
	if (guest_initiated) {
		if (gfn == vcpu->arch.last_pt_write_gfn &&
		    !last_updated_pte_accessed(vcpu)) {
#ifdef XXX
			++vcpu->arch.last_pt_write_count;
			if (vcpu->arch.last_pt_write_count >= 3)
				flooded = 1;
#else
			XXX_KVM_PROBE;
#endif
		} else {
			vcpu->arch.last_pt_write_gfn = gfn;
#ifdef XXX
			vcpu->arch.last_pt_write_count = 1;
#else
			XXX_KVM_PROBE;
#endif
			vcpu->arch.last_pte_updated = NULL;
		}
	}
	index = kvm_page_table_hashfn(gfn);
	bucket = &vcpu->kvm->arch.mmu_page_hash[index];

	/* XXX - need protection ?  I think not since mmu_lock held above... */
	for (sp = list_head(bucket); sp; sp = list_next(bucket, sp)) {
		if (sp->gfn != gfn || sp->role.direct || sp->role.invalid)
			continue;

		pte_size = sp->role.glevels == PT32_ROOT_LEVEL ? 4 : 8;
		misaligned = (offset ^ (offset + bytes - 1)) & ~(pte_size - 1);
		misaligned |= bytes < 4;
		if (misaligned || flooded) {
			/*
			 * Misaligned accesses are too much trouble to fix
			 * up; also, they usually indicate a page is not used
			 * as a page table.
			 *
			 * If we're seeing too many writes to a page,
			 * it may no longer be a page table, or we may be
			 * forking, in which case it is better to unmap the
			 * page.
			 */
#ifdef XXX
			if (kvm_mmu_zap_page(vcpu->kvm, sp))
				n = bucket->first;
#else
			XXX_KVM_PROBE;
			kvm_mmu_zap_page(vcpu->kvm, sp);
#endif
#ifdef XXX_KVM_STAT
			++vcpu->kvm->stat.mmu_flooded;
#endif
			continue;
		}
		page_offset = offset;
		level = sp->role.level;
		npte = 1;
		if (sp->role.glevels == PT32_ROOT_LEVEL) {
			page_offset <<= 1;	/* 32->64 */
			/*
			 * A 32-bit pde maps 4MB while the shadow pdes map
			 * only 2MB.  So we need to double the offset again
			 * and zap two pdes instead of one.
			 */
			if (level == PT32_ROOT_LEVEL) {
				page_offset &= ~7; /* kill rounding error */
				page_offset <<= 1;
				npte = 2;
			}
			quadrant = page_offset >> PAGESHIFT;
			page_offset &= ~PAGEMASK;
			if (quadrant != sp->role.quadrant)
				continue;
		}

		spte = &sp->spt[page_offset / sizeof (*spte)];

		if ((gpa & (pte_size - 1)) || (bytes < pte_size)) {
			gentry = 0;
			r = kvm_read_guest_atomic(vcpu->kvm,
			    gpa & ~(uint64_t)(pte_size - 1), &gentry, pte_size);
			new = (const void *)&gentry;
			if (r < 0)
				new = NULL;
		}

		while (npte--) {
			entry = *spte;
			mmu_pte_write_zap_pte(vcpu, sp, spte);
			if (new)
				mmu_pte_write_new_pte(vcpu, sp, spte, new);
			mmu_pte_write_flush_tlb(vcpu, entry, *spte);
			++spte;
		}
	}
#ifdef XXX_KVM_TRACE
	kvm_mmu_audit(vcpu, "post pte write");
#endif
	mutex_exit(&vcpu->kvm->mmu_lock);

	if (!is_error_pfn(vcpu->arch.update_pte.pfn)) {
		kvm_release_pfn_clean(vcpu->arch.update_pte.pfn);
		vcpu->arch.update_pte.pfn = bad_pfn;
	}
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
#ifdef XXX_KVM_TRACE
	trace_kvm_mmio(KVM_TRACE_MMIO_WRITE, bytes, gpa, *(uint64_t *)val);
#endif
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

static int
kvm_mmu_unprotect_page(struct kvm *kvm, gfn_t gfn)
{
	unsigned index;
	list_t *bucket;
	struct kvm_mmu_page *sp;
	int r;

	r = 0;
	index = kvm_page_table_hashfn(gfn);
	bucket = &kvm->arch.mmu_page_hash[index];

	/* XXX - need lock? */
	for (sp = list_head(bucket); sp; sp = list_next(bucket, sp)) {
		if (sp->gfn == gfn && !sp->role.direct) {
			r = 1;
#ifdef XXX
			if (kvm_mmu_zap_page(kvm, sp))
				n = bucket->first;
#else
			XXX_KVM_PROBE;
			kvm_mmu_zap_page(kvm, sp);
#endif
		}
	}
	return (r);
}

int
kvm_mmu_unprotect_page_virt(struct kvm_vcpu *vcpu, gva_t gva)
{
	gpa_t gpa;
	int r;

	if (tdp_enabled)
		return (0);

	gpa = kvm_mmu_gva_to_gpa_read(vcpu, gva, NULL);

	mutex_enter(&vcpu->kvm->mmu_lock);
	r = kvm_mmu_unprotect_page(vcpu->kvm, gpa >> PAGESHIFT);
	mutex_exit(&vcpu->kvm->mmu_lock);

	return (r);
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

#ifdef XXX_KVM_STAT
		++vcpu->stat.insn_emulation;
#endif
		if (r)  {
#ifdef XXX_KVM_STAT
			++vcpu->stat.insn_emulation_fail;
#endif
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
kvm_mmu_page_fault(struct kvm_vcpu *vcpu, gva_t cr2, uint32_t error_code)
{
	int r;
	enum emulation_result er;

	if ((r = vcpu->arch.mmu.page_fault(vcpu, cr2, error_code)) < 0)
		return (r);

	if (r == 0)
		return (1);

	if ((r = mmu_topup_memory_caches(vcpu)) != 0)
		return (r);

	er = emulate_instruction(vcpu, cr2, error_code, 0);

	switch (er) {
	case EMULATE_DONE:
		return (1);

	case EMULATE_DO_MMIO:
#ifdef XXX_KVM_STAT
		++vcpu->stat.mmio_exits;
#endif
		return (0);

	case EMULATE_FAIL:
		vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
		vcpu->run->internal.suberror = KVM_INTERNAL_ERROR_EMULATION;
		vcpu->run->internal.ndata = 0;
		return (0);
	default:
		cmn_err(CE_PANIC, "kvm_mmu_page_fault: unknown return "
		    "from emulate_instruction: %x\n", er);
	}

	return (0);
}

static inline int
is_no_device(uint32_t intr_info)
{
	return ((intr_info & (INTR_INFO_INTR_TYPE_MASK | INTR_INFO_VECTOR_MASK |
	    INTR_INFO_VALID_MASK)) == (INTR_TYPE_HARD_EXCEPTION | NM_VECTOR |
	    INTR_INFO_VALID_MASK));
}

static inline int
is_invalid_opcode(uint32_t intr_info)
{
	return ((intr_info & (INTR_INFO_INTR_TYPE_MASK | INTR_INFO_VECTOR_MASK |
	    INTR_INFO_VALID_MASK)) == (INTR_TYPE_HARD_EXCEPTION | UD_VECTOR |
	    INTR_INFO_VALID_MASK));
}

static inline int
is_external_interrupt(uint32_t intr_info)
{
	return ((intr_info & (INTR_INFO_INTR_TYPE_MASK |
	    INTR_INFO_VALID_MASK)) == (INTR_TYPE_EXT_INTR |
	    INTR_INFO_VALID_MASK));
}

static inline int
kvm_event_needs_reinjection(struct kvm_vcpu *vcpu)
{
	return (vcpu->arch.exception.pending || vcpu->arch.interrupt.pending ||
	    vcpu->arch.nmi_injected);
}

static int
handle_rmode_exception(struct kvm_vcpu *vcpu, int vec, uint32_t err_code)
{
	/*
	 * Instruction with address size override prefix opcode 0x67
	 * Cause the #SS fault with 0 error code in VM86 mode.
	 */
	if (((vec == GP_VECTOR) || (vec == SS_VECTOR)) && err_code == 0) {
		if (emulate_instruction(vcpu, 0, 0, 0) == EMULATE_DONE)
			return (1);
	}

	/*
	 * Forward all other exceptions that are valid in real mode.
	 * FIXME: Breaks guest debugging in real mode, needs to be fixed with
	 * the required debugging infrastructure rework.
	 */
	switch (vec) {
	case DB_VECTOR:
		if (vcpu->guest_debug &
		    (KVM_GUESTDBG_SINGLESTEP | KVM_GUESTDBG_USE_HW_BP)) {
			return (0);
		}

		kvm_queue_exception(vcpu, vec);
		return (1);

	case BP_VECTOR:
		/*
		 * Update instruction length as we may reinject the exception
		 * from user space while in guest debugging mode.
		 */
		to_vmx(vcpu)->vcpu.arch.event_exit_inst_len =
		    vmcs_read32(VM_EXIT_INSTRUCTION_LEN);

		if (vcpu->guest_debug & KVM_GUESTDBG_USE_SW_BP)
			return (0);
		/* fall through */

	case DE_VECTOR:
	case OF_VECTOR:
	case BR_VECTOR:
	case UD_VECTOR:
	case DF_VECTOR:
	case SS_VECTOR:
	case GP_VECTOR:
	case MF_VECTOR:
		kvm_queue_exception(vcpu, vec);
		return (1);
	}

	return (0);
}

int
kvm_emulate_halt(struct kvm_vcpu *vcpu)
{
#ifdef XXX_KVM_STAT
	++vcpu->stat.halt_exits;
#endif
	if (irqchip_in_kernel(vcpu->kvm)) {
		vcpu->arch.mp_state = KVM_MP_STATE_HALTED;
		return (1);
	} else {
		vcpu->run->exit_reason = KVM_EXIT_HLT;
		return (0);
	}
}

/*
 * The guest has exited.  See if we can fix it or if we need userspace
 * assistance.
 */
static int
handle_exception(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct kvm_run *kvm_run = vcpu->run;
	uint32_t intr_info, ex_no, error_code;
	unsigned long cr2, rip, dr6;
	uint32_t vect_info;
	enum emulation_result er;

	vect_info = vmx->idt_vectoring_info;
	intr_info = vmcs_read32(VM_EXIT_INTR_INFO);

	if (is_machine_check(intr_info))
		return (handle_machine_check(vcpu));

	if ((vect_info & VECTORING_INFO_VALID_MASK) &&
	    !is_page_fault(intr_info)) {
		vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
		vcpu->run->internal.suberror = KVM_INTERNAL_ERROR_SIMUL_EX;
		vcpu->run->internal.ndata = 2;
		vcpu->run->internal.data[0] = vect_info;
		vcpu->run->internal.data[1] = intr_info;
		return (0);
	}

	if ((intr_info & INTR_INFO_INTR_TYPE_MASK) == INTR_TYPE_NMI_INTR)
		return (1);  /* already handled by vmx_vcpu_run() */

	if (is_no_device(intr_info)) {
		vmx_fpu_activate(vcpu);
		return (1);
	}

	if (is_invalid_opcode(intr_info)) {
		er = emulate_instruction(vcpu, 0, 0, EMULTYPE_TRAP_UD);
		if (er != EMULATE_DONE)
			kvm_queue_exception(vcpu, UD_VECTOR);
		return (1);
	}

	error_code = 0;
	rip = kvm_rip_read(vcpu);

	if (intr_info & INTR_INFO_DELIVER_CODE_MASK)
		error_code = vmcs_read32(VM_EXIT_INTR_ERROR_CODE);

	if (is_page_fault(intr_info)) {
		/* EPT won't cause page fault directly */
		if (enable_ept)
			cmn_err(CE_PANIC, "page fault with ept enabled\n");
		cr2 = vmcs_readl(EXIT_QUALIFICATION);
#ifdef XXX_KVM_TRACE
		trace_kvm_page_fault(cr2, error_code);
#endif
		if (kvm_event_needs_reinjection(vcpu))
			kvm_mmu_unprotect_page_virt(vcpu, cr2);
		return (kvm_mmu_page_fault(vcpu, cr2, error_code));
	}

	if (vmx->rmode.vm86_active && handle_rmode_exception(vcpu,
	    intr_info & INTR_INFO_VECTOR_MASK, error_code)) {
		if (vcpu->arch.halt_request) {
			vcpu->arch.halt_request = 0;
			return (kvm_emulate_halt(vcpu));
		}
		return (1);
	}

	ex_no = intr_info & INTR_INFO_VECTOR_MASK;
	switch (ex_no) {
	case DB_VECTOR:
		dr6 = vmcs_readl(EXIT_QUALIFICATION);
		if (!(vcpu->guest_debug &
		    (KVM_GUESTDBG_SINGLESTEP | KVM_GUESTDBG_USE_HW_BP))) {
			vcpu->arch.dr6 = dr6 | DR6_FIXED_1;
			kvm_queue_exception(vcpu, DB_VECTOR);
			return (1);
		}

		kvm_run->debug.arch.dr6 = dr6 | DR6_FIXED_1;
		kvm_run->debug.arch.dr7 = vmcs_readl(GUEST_DR7);
		/* fall through */
	case BP_VECTOR:
		/*
		 * Update instruction length as we may reinject #BP from
		 * user space while in guest debugging mode. Reading it for
		 * #DB as well causes no harm, it is not used in that case.
		 */
		vmx->vcpu.arch.event_exit_inst_len =
			vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
		kvm_run->exit_reason = KVM_EXIT_DEBUG;
		kvm_run->debug.arch.pc = vmcs_readl(GUEST_CS_BASE) + rip;
		kvm_run->debug.arch.exception = ex_no;
		break;
	default:
		kvm_run->exit_reason = KVM_EXIT_EXCEPTION;
		kvm_run->ex.exception = ex_no;
		kvm_run->ex.error_code = error_code;
		break;
	}

	return (0);
}

static int
handle_external_interrupt(struct kvm_vcpu *vcpu)
{
#ifdef XXX_KVM_STAT
	++vcpu->stat.irq_exits;
#endif
	return (1);
}

static int
handle_triple_fault(struct kvm_vcpu *vcpu)
{
	vcpu->run->exit_reason = KVM_EXIT_SHUTDOWN;
	return (0);
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

static int
handle_io(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qualification;
	int size, in, string;
	unsigned port;

#ifdef XXX_KVM_STAT
	++vcpu->stat.io_exits;
#endif
	exit_qualification = vmcs_readl(EXIT_QUALIFICATION);
	string = (exit_qualification & 16) != 0;

	if (string) {
		if (emulate_instruction(vcpu, 0, 0, 0) == EMULATE_DO_MMIO)
			return (0);
		return (1);
	}

	size = (exit_qualification & 7) + 1;
	in = (exit_qualification & 8) != 0;
	port = exit_qualification >> 16;
	skip_emulated_instruction(vcpu);

	return (kvm_emulate_pio(vcpu, in, size, port));
}

static int
handle_nmi_window(struct kvm_vcpu *vcpu)
{
	uint32_t cpu_based_vm_exec_control;

	/* clear pending NMI */
	cpu_based_vm_exec_control = vmcs_read32(CPU_BASED_VM_EXEC_CONTROL);
	cpu_based_vm_exec_control &= ~CPU_BASED_VIRTUAL_NMI_PENDING;
	vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, cpu_based_vm_exec_control);

#ifdef XXX_KVM_STAT
	++vcpu->stat.nmi_window_exits;
#endif

	return (1);
}

static int
code_segment_valid(struct kvm_vcpu *vcpu)
{
	struct kvm_segment cs;
	unsigned int cs_rpl;

	vmx_get_segment(vcpu, &cs, VCPU_SREG_CS);
	cs_rpl = cs.selector & SELECTOR_RPL_MASK;

	if (cs.unusable)
		return (0);
	if (~cs.type & (AR_TYPE_CODE_MASK|AR_TYPE_ACCESSES_MASK))
		return (0);
	if (!cs.s)
		return (0);

	if (cs.type & AR_TYPE_WRITEABLE_MASK) {
		if (cs.dpl > cs_rpl)
			return (0);
	} else {
		if (cs.dpl != cs_rpl)
			return (0);
	}

	if (!cs.present)
		return (0);

	/*
	 * TODO: Add Reserved field check, this'll require a new member in the
	 * kvm_segment_field structure
	 */
	return (1);
}

static int
data_segment_valid(struct kvm_vcpu *vcpu, int seg)
{
	struct kvm_segment var;
	unsigned int rpl;

	vmx_get_segment(vcpu, &var, seg);
	rpl = var.selector & SELECTOR_RPL_MASK;

	if (var.unusable)
		return (1);

	if (!var.s)
		return (0);

	if (!var.present)
		return (0);

	if (~var.type & (AR_TYPE_CODE_MASK|AR_TYPE_WRITEABLE_MASK)) {
		if (var.dpl < rpl) /* DPL < RPL */
			return (0);
	}

	/*
	 * TODO: Add other members to kvm_segment_field to allow checking for
	 * other access rights flags
	 */
	return (1);
}

static int
ldtr_valid(struct kvm_vcpu *vcpu)
{
	struct kvm_segment ldtr;

	vmx_get_segment(vcpu, &ldtr, VCPU_SREG_LDTR);

	if (ldtr.unusable)
		return (1);
	if (ldtr.selector & SELECTOR_TI_MASK)	/* TI = 1 */
		return (0);
	if (ldtr.type != 2)
		return (0);
	if (!ldtr.present)
		return (0);

	return (1);
}

static int
tr_valid(struct kvm_vcpu *vcpu)
{
	struct kvm_segment tr;

	vmx_get_segment(vcpu, &tr, VCPU_SREG_TR);

	if (tr.unusable)
		return (0);
	if (tr.selector & SELECTOR_TI_MASK)	/* TI = 1 */
		return (0);
	if (tr.type != 3 && tr.type != 11)
		return (0);	/* TODO: Check if guest is in IA32e mode */
	if (!tr.present)
		return (0);

	return (1);
}

static int
cs_ss_rpl_check(struct kvm_vcpu *vcpu)
{
	struct kvm_segment cs, ss;

	vmx_get_segment(vcpu, &cs, VCPU_SREG_CS);
	vmx_get_segment(vcpu, &ss, VCPU_SREG_SS);

	return ((cs.selector & SELECTOR_RPL_MASK) ==
	    (ss.selector & SELECTOR_RPL_MASK));
}

static int
rmode_segment_valid(struct kvm_vcpu *vcpu, int seg)
{
	struct kvm_segment var;
	uint32_t ar;

	vmx_get_segment(vcpu, &var, seg);
	ar = vmx_segment_access_rights(&var);

	if (var.base != (var.selector << 4))
		return (0);
	if (var.limit != 0xffff)
		return (0);
	if (ar != 0xf3)
		return (0);

	return (1);
}

static int
stack_segment_valid(struct kvm_vcpu *vcpu)
{
	struct kvm_segment ss;
	unsigned int ss_rpl;

	vmx_get_segment(vcpu, &ss, VCPU_SREG_SS);
	ss_rpl = ss.selector & SELECTOR_RPL_MASK;

	if (ss.unusable)
		return (1);
	if (ss.type != 3 && ss.type != 7)
		return (0);
	if (!ss.s)
		return (0);
	if (ss.dpl != ss_rpl) /* DPL != RPL */
		return (0);
	if (!ss.present)
		return (0);

	return (1);
}

/*
 * Check if guest state is valid. Returns true if valid, false if
 * not.
 * We assume that registers are always usable
 */
static int
guest_state_valid(struct kvm_vcpu *vcpu)
{
	if (!is_protmode(vcpu)) {
		/* real mode guest state checks */
		if (!rmode_segment_valid(vcpu, VCPU_SREG_CS))
			return (0);
		if (!rmode_segment_valid(vcpu, VCPU_SREG_SS))
			return (0);
		if (!rmode_segment_valid(vcpu, VCPU_SREG_DS))
			return (0);
		if (!rmode_segment_valid(vcpu, VCPU_SREG_ES))
			return (0);
		if (!rmode_segment_valid(vcpu, VCPU_SREG_FS))
			return (0);
		if (!rmode_segment_valid(vcpu, VCPU_SREG_GS))
			return (0);
	} else {
		/* protected mode guest state checks */
		if (!cs_ss_rpl_check(vcpu))
			return (0);
		if (!code_segment_valid(vcpu))
			return (0);
		if (!stack_segment_valid(vcpu))
			return (0);
		if (!data_segment_valid(vcpu, VCPU_SREG_DS))
			return (0);
		if (!data_segment_valid(vcpu, VCPU_SREG_ES))
			return (0);
		if (!data_segment_valid(vcpu, VCPU_SREG_FS))
			return (0);
		if (!data_segment_valid(vcpu, VCPU_SREG_GS))
			return (0);
		if (!tr_valid(vcpu))
			return (0);
		if (!ldtr_valid(vcpu))
			return (0);
	}

	/*
	 * TODO:
	 * - Add checks on RIP
	 * - Add checks on RFLAGS
	 */

	return (1);
}

static int handle_invalid_guest_state(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	enum emulation_result err = EMULATE_DONE;
	int ret = 1;

	while (!guest_state_valid(vcpu)) {
		err = emulate_instruction(vcpu, 0, 0, 0);

		if (err == EMULATE_DO_MMIO) {
			ret = 0;
			goto out;
		}

		if (err != EMULATE_DONE) {
			vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
			vcpu->run->internal.suberror =
			    KVM_INTERNAL_ERROR_EMULATION;
			vcpu->run->internal.ndata = 0;
			ret = 0;
			goto out;
		}

#ifdef XXX
		if ((current))
			goto out;
#else
		XXX_KVM_PROBE;
#endif
	}

	vmx->emulation_required = 0;
out:
	return (ret);
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

static int
handle_cr(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qualification, val;
	int cr;
	int reg;

	exit_qualification = vmcs_readl(EXIT_QUALIFICATION);
	cr = exit_qualification & 15;
	reg = (exit_qualification >> 8) & 15;
	DTRACE_PROBE3(kvm__cr, int, cr, int, reg, int,
	    (exit_qualification >> 4) & 3);
	switch ((exit_qualification >> 4) & 3) {
	case 0: /* mov to cr */
		val = kvm_register_read(vcpu, reg);
#ifdef XXX_KVM_TRACE
		trace_kvm_cr_write(cr, val);
#endif
		switch (cr) {
		case 0:
			kvm_set_cr0(vcpu, val);
			skip_emulated_instruction(vcpu);
			return (1);
		case 3:
			kvm_set_cr3(vcpu, val);
			skip_emulated_instruction(vcpu);
			return (1);
		case 4:
			kvm_set_cr4(vcpu, val);
			skip_emulated_instruction(vcpu);
			return (1);
		case 8: {
			uint8_t cr8_prev = kvm_get_cr8(vcpu);
			uint8_t cr8 = kvm_register_read(vcpu, reg);
			kvm_set_cr8(vcpu, cr8);
			skip_emulated_instruction(vcpu);

			if (irqchip_in_kernel(vcpu->kvm))
				return (1);

			if (cr8_prev <= cr8)
				return (1);

			vcpu->run->exit_reason = KVM_EXIT_SET_TPR;
			return (0);
		}
		};

		break;

	case 2: /* clts */
		vmx_set_cr0(vcpu, kvm_read_cr0_bits(vcpu, ~X86_CR0_TS));
#ifdef XXX_KVM_TRACE
		trace_kvm_cr_write(0, kvm_read_cr0(vcpu));
#endif
		skip_emulated_instruction(vcpu);
		vmx_fpu_activate(vcpu);
		return (1);
	case 1: /* mov from cr */
		switch (cr) {
		case 3:
			kvm_register_write(vcpu, reg, vcpu->arch.cr3);
#ifdef XXX_KVM_TRACE
			trace_kvm_cr_read(cr, vcpu->arch.cr3);
#endif
			skip_emulated_instruction(vcpu);
			return (1);
		case 8:
			val = kvm_get_cr8(vcpu);
			kvm_register_write(vcpu, reg, val);
#ifdef XXX_KVM_TRACE
			trace_kvm_cr_read(cr, val);
#endif
			skip_emulated_instruction(vcpu);
			return (1);
		}
		break;
	case 3: /* lmsw */
		val = (exit_qualification >> LMSW_SOURCE_DATA_SHIFT) & 0x0f;
#ifdef XXX_KVM_TRACE
		trace_kvm_cr_write(0, (kvm_read_cr0(vcpu) & ~0xful) | val);
#endif
		kvm_lmsw(vcpu, val);

		skip_emulated_instruction(vcpu);
		return (1);
	default:
		break;
	}
	vcpu->run->exit_reason = 0;
	cmn_err(CE_WARN, "unhandled control register: op %d cr %d\n",
	    (int)(exit_qualification >> 4) & 3, cr);

	return (0);
}

static int
check_dr_alias(struct kvm_vcpu *vcpu)
{
	if (kvm_read_cr4_bits(vcpu, X86_CR4_DE)) {
		kvm_queue_exception(vcpu, UD_VECTOR);
		return (-1);
	}

	return (0);
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

static int handle_dr(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qualification;
	unsigned long val;
	int dr, reg;

	/* Do not handle if the CPL > 0, will trigger GP on re-entry */
	if (!kvm_require_cpl(vcpu, 0))
		return (1);

	dr = vmcs_readl(GUEST_DR7);

	if (dr & DR7_GD) {
		/*
		 * As the vm-exit takes precedence over the debug trap, we
		 * need to emulate the latter, either for the host or the
		 * guest debugging itself.
		 */
		if (vcpu->guest_debug & KVM_GUESTDBG_USE_HW_BP) {
			vcpu->run->debug.arch.dr6 = vcpu->arch.dr6;
			vcpu->run->debug.arch.dr7 = dr;
			vcpu->run->debug.arch.pc =
				vmcs_readl(GUEST_CS_BASE) +
				vmcs_readl(GUEST_RIP);
			vcpu->run->debug.arch.exception = DB_VECTOR;
			vcpu->run->exit_reason = KVM_EXIT_DEBUG;
			return (0);
		} else {
			vcpu->arch.dr7 &= ~DR7_GD;
			vcpu->arch.dr6 |= DR6_BD;
			vmcs_writel(GUEST_DR7, vcpu->arch.dr7);
			kvm_queue_exception(vcpu, DB_VECTOR);
			return (1);
		}
	}

	exit_qualification = vmcs_readl(EXIT_QUALIFICATION);
	dr = exit_qualification & DEBUG_REG_ACCESS_NUM;
	reg = DEBUG_REG_ACCESS_REG(exit_qualification);
	if (exit_qualification & TYPE_MOV_FROM_DR) {
		switch (dr) {
		case 0 ... 3:
			val = vcpu->arch.db[dr];
			break;
		case 4:
			if (check_dr_alias(vcpu) < 0)
				return (1);
			/* fall through */
		case 6:
			val = vcpu->arch.dr6;
			break;
		case 5:
			if (check_dr_alias(vcpu) < 0)
				return (1);
			/* fall through */
		default: /* 7 */
			val = vcpu->arch.dr7;
			break;
		}
		kvm_register_write(vcpu, reg, val);
	} else {
		val = vcpu->arch.regs[reg];
		switch (dr) {
		case 0 ... 3:
			vcpu->arch.db[dr] = val;
			if (!(vcpu->guest_debug & KVM_GUESTDBG_USE_HW_BP))
				vcpu->arch.eff_db[dr] = val;
			break;
		case 4:
			if (check_dr_alias(vcpu) < 0)
				return (1);
			/* fall through */
		case 6:
			if (val & 0xffffffff00000000ULL) {
				kvm_inject_gp(vcpu, 0);
				return (1);
			}
			vcpu->arch.dr6 = (val & DR6_VOLATILE) | DR6_FIXED_1;
			break;
		case 5:
			if (check_dr_alias(vcpu) < 0)
				return (1);
			/* fall through */
		default: /* 7 */
			if (val & 0xffffffff00000000ULL) {
				kvm_inject_gp(vcpu, 0);
				return (1);
			}
			vcpu->arch.dr7 = (val & DR7_VOLATILE) | DR7_FIXED_1;

			if (!(vcpu->guest_debug & KVM_GUESTDBG_USE_HW_BP)) {
				vmcs_writel(GUEST_DR7, vcpu->arch.dr7);
				vcpu->arch.switch_db_regs =
					(val & DR7_BP_EN_MASK);

			}
			break;
		}
	}
	skip_emulated_instruction(vcpu);
	return (1);
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
#ifdef XXX_KVM_TRACE
	trace_kvm_cpuid(function,
			kvm_register_read(vcpu, VCPU_REGS_RAX),
			kvm_register_read(vcpu, VCPU_REGS_RBX),
			kvm_register_read(vcpu, VCPU_REGS_RCX),
			kvm_register_read(vcpu, VCPU_REGS_RDX));
#endif
}

static int
handle_cpuid(struct kvm_vcpu *vcpu)
{
	kvm_emulate_cpuid(vcpu);
	return (1);
}

static int
handle_rdmsr(struct kvm_vcpu *vcpu)
{
	uint32_t ecx = vcpu->arch.regs[VCPU_REGS_RCX];
	uint64_t data;

	if (vmx_get_msr(vcpu, ecx, &data)) {
#ifdef XXX_KVM_TRACE
		trace_kvm_msr_read_ex(ecx);
#endif
		kvm_inject_gp(vcpu, 0);
		return (1);
	}

#ifdef XXX_KVM_TRACE
	trace_kvm_msr_read(ecx, data);
#endif

	/* FIXME: handling of bits 32:63 of rax, rdx */
	vcpu->arch.regs[VCPU_REGS_RAX] = data & -1u;
	vcpu->arch.regs[VCPU_REGS_RDX] = (data >> 32) & -1u;
	skip_emulated_instruction(vcpu);
	return (1);
}

static int
handle_wrmsr(struct kvm_vcpu *vcpu)
{
	uint32_t ecx = vcpu->arch.regs[VCPU_REGS_RCX];
	uint64_t data = (vcpu->arch.regs[VCPU_REGS_RAX] & -1u)
		| ((uint64_t)(vcpu->arch.regs[VCPU_REGS_RDX] & -1u) << 32);

	if (vmx_set_msr(vcpu, ecx, data) != 0) {
#ifdef XXX_KVM_TRACE
		trace_kvm_msr_write_ex(ecx, data);
#endif
		kvm_inject_gp(vcpu, 0);
		return (1);
	}

#ifdef XXX_KVM_TRACE
	trace_kvm_msr_write(ecx, data);
#endif
	skip_emulated_instruction(vcpu);
	return (1);
}

static int
handle_tpr_below_threshold(struct kvm_vcpu *vcpu)
{
	return (1);
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

#ifdef XXX_KVM_TRACE
	trace_kvm_hv_hypercall(code, fast, rep_cnt, rep_idx, ingpa, outgpa);
#endif

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

#ifdef XXX_KVM_TRACE
	trace_kvm_hypercall(nr, a0, a1, a2, a3);
#endif

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

#ifdef XXX_KVM_STAT
	++vcpu->stat.hypercalls;
#endif
	return (r);
}

static int
handle_halt(struct kvm_vcpu *vcpu)
{
	skip_emulated_instruction(vcpu);
	return (kvm_emulate_halt(vcpu));
}

static int
handle_vmcall(struct kvm_vcpu *vcpu)
{
	skip_emulated_instruction(vcpu);
	kvm_emulate_hypercall(vcpu);
	return (1);
}

static int
handle_vmx_insn(struct kvm_vcpu *vcpu)
{
	kvm_queue_exception(vcpu, UD_VECTOR);
	return (1);
}

void
kvm_mmu_invlpg(struct kvm_vcpu *vcpu, gva_t gva)
{
	vcpu->arch.mmu.invlpg(vcpu, gva);
	kvm_mmu_flush_tlb(vcpu);
#ifdef XXX_KVM_STAT
	++vcpu->stat.invlpg;
#endif
}

static int
handle_invlpg(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qualification = vmcs_readl(EXIT_QUALIFICATION);

	kvm_mmu_invlpg(vcpu, exit_qualification);
	skip_emulated_instruction(vcpu);
	return (1);
}

static int
handle_wbinvd(struct kvm_vcpu *vcpu)
{
	skip_emulated_instruction(vcpu);
	/* TODO: Add support for VT-d/pass-through device */
	return (1);
}

static int
handle_apic_access(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qualification;
	enum emulation_result er;
	unsigned long offset;

	exit_qualification = vmcs_readl(EXIT_QUALIFICATION);
	offset = exit_qualification & 0xffful;

	er = emulate_instruction(vcpu, 0, 0, 0);

	if (er !=  EMULATE_DONE) {
		cmn_err(CE_PANIC, "Fail to handle apic access vmexit! "
		    "Offset is 0x%lx\n", offset);
	}

	return (1);
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

static uint64_t
vmx_get_segment_base(struct kvm_vcpu *vcpu, int seg)
{
	struct kvm_vmx_segment_field *sf = &kvm_vmx_segment_fields[seg];

	return (vmcs_readl(sf->base));
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

static int
handle_task_switch(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	unsigned long exit_qualification;
	uint16_t tss_selector;
	int reason, type, idt_v;

	idt_v = (vmx->idt_vectoring_info & VECTORING_INFO_VALID_MASK);
	type = (vmx->idt_vectoring_info & VECTORING_INFO_TYPE_MASK);
	exit_qualification = vmcs_readl(EXIT_QUALIFICATION);

	reason = (uint32_t)exit_qualification >> 30;
	if (reason == TASK_SWITCH_GATE && idt_v) {
		switch (type) {
		case INTR_TYPE_NMI_INTR:
			vcpu->arch.nmi_injected = 0;
			if (cpu_has_virtual_nmis()) {
				vmcs_set_bits(GUEST_INTERRUPTIBILITY_INFO,
				    GUEST_INTR_STATE_NMI);
			}
			break;
		case INTR_TYPE_EXT_INTR:
		case INTR_TYPE_SOFT_INTR:
			kvm_clear_interrupt_queue(vcpu);
			break;
		case INTR_TYPE_HARD_EXCEPTION:
		case INTR_TYPE_SOFT_EXCEPTION:
			kvm_clear_exception_queue(vcpu);
			break;
		default:
			break;
		}
	}
	tss_selector = exit_qualification;

	if (!idt_v || (type != INTR_TYPE_HARD_EXCEPTION &&
	    type != INTR_TYPE_EXT_INTR && type != INTR_TYPE_NMI_INTR))
		skip_emulated_instruction(vcpu);

	if (!kvm_task_switch(vcpu, tss_selector, reason))
		return (0);

	/* clear all local breakpoint enable flags */
	vmcs_writel(GUEST_DR7, vmcs_readl(GUEST_DR7) & ~55);

	/*
	 * TODO: What about debug traps on tss switch?
	 * Are we supposed to inject them and update dr6?
	 */

	return (1);
}

static int
handle_ept_violation(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qualification;
	gpa_t gpa;
	int gla_validity;

	exit_qualification = vmcs_readl(EXIT_QUALIFICATION);

	if (exit_qualification & (1 << 6)) {
		cmn_err(CE_PANIC, "EPT: GPA exceeds GAW!\n");
	}

	gla_validity = (exit_qualification >> 7) & 0x3;
	if (gla_validity != 0x3 && gla_validity != 0x1 && gla_validity != 0) {
		cmn_err(CE_WARN, "EPT: Handling EPT violation failed!\n");
		cmn_err(CE_CONT, "EPT: GPA: 0x%lx, GVA: 0x%lx\n",
			(long unsigned int)vmcs_read64(GUEST_PHYSICAL_ADDRESS),
			vmcs_readl(GUEST_LINEAR_ADDRESS));
		cmn_err(CE_PANIC, "EPT: Exit qualification is 0x%lx\n",
			(long unsigned int)exit_qualification);
		vcpu->run->exit_reason = KVM_EXIT_UNKNOWN;
		vcpu->run->hw.hardware_exit_reason = EXIT_REASON_EPT_VIOLATION;
		return (0);
	}

	gpa = vmcs_read64(GUEST_PHYSICAL_ADDRESS);
#ifdef XXX_KVM_TRACE
	trace_kvm_page_fault(gpa, exit_qualification);
#endif
	return (kvm_mmu_page_fault(vcpu, gpa & PAGEMASK, 0));
}

int
kvm_mmu_get_spte_hierarchy(struct kvm_vcpu *vcpu,
    uint64_t addr, uint64_t sptes[4])
{
	struct kvm_shadow_walk_iterator iterator;
	int nr_sptes = 0;

	mutex_enter(&vcpu->kvm->mmu_lock);
	for_each_shadow_entry(vcpu, addr, iterator) {
		sptes[iterator.level - 1] = *iterator.sptep;
		nr_sptes++;
		if (!is_shadow_present_pte(*iterator.sptep))
			break;
	}
	mutex_exit(&vcpu->kvm->mmu_lock);

	return (nr_sptes);
}

/* XXX - The following assumes we're running on the maximum sized box... */

#define	MAX_PHYSMEM_BITS 46
static uint64_t ept_rsvd_mask(uint64_t spte, int level)
{
	int i;
	uint64_t mask = 0;

#ifdef XXX
	for (i = 51; i > boot_cpu_data.x86_phys_bits; i--)
		mask |= (1ULL << i);
#else
	XXX_KVM_PROBE;
	for (i = 51; i > MAX_PHYSMEM_BITS; i--)
		mask |= (1ULL << i);
#endif

	if (level > 2)
		/* bits 7:3 reserved */
		mask |= 0xf8;
	else if (level == 2) {
		if (spte & (1ULL << 7))
			/* 2MB ref, bits 20:12 reserved */
			mask |= 0x1ff000;
		else
			/* bits 6:3 reserved */
			mask |= 0x78;
	}

	return (mask);
}

static inline int
cpu_has_vmx_ept_execute_only(void)
{
	return (!!(vmx_capability.ept & VMX_EPT_EXECUTE_ONLY_BIT));
}

static void
ept_misconfig_inspect_spte(struct kvm_vcpu *vcpu, uint64_t spte, int level)
{
	cmn_err(CE_WARN, "%s: spte 0x%lx level %d\n", __func__, spte, level);

	/* 010b (write-only) */
	if ((spte & 0x7) == 0x2)
		cmn_err(CE_CONT, "%s: spte is write-only\n", __func__);

	/* 110b (write/execute) */
	if ((spte & 0x7) == 0x6)
		cmn_err(CE_CONT, "%s: spte is write-execute\n", __func__);

	/* 100b (execute-only) and value not supported by logical processor */
	if (!cpu_has_vmx_ept_execute_only()) {
		if ((spte & 0x7) == 0x4)
			cmn_err(CE_CONT,
			    "%s: spte is execute-only\n", __func__);
	}

	/* not 000b */
	if ((spte & 0x7)) {
		uint64_t rsvd_bits = spte & ept_rsvd_mask(spte, level);

		if (rsvd_bits != 0) {
			cmn_err(CE_CONT, "%s: rsvd_bits = 0x%lx\n",
			    __func__, rsvd_bits);
		}

		if (level == 1 || (level == 2 && (spte & (1ULL << 7)))) {
			uint64_t ept_mem_type = (spte & 0x38) >> 3;

			if (ept_mem_type == 2 || ept_mem_type == 3 ||
			    ept_mem_type == 7) {
				cmn_err(CE_CONT, "%s: ept_mem_type=0x%lx\n",
						__func__, ept_mem_type);
			}
		}
	}
}

static int
handle_ept_misconfig(struct kvm_vcpu *vcpu)
{
	uint64_t sptes[4];
	int nr_sptes, i;
	gpa_t gpa;

	gpa = vmcs_read64(GUEST_PHYSICAL_ADDRESS);

	cmn_err(CE_WARN, "EPT: Misconfiguration.\n");
	cmn_err(CE_CONT, "EPT: GPA: 0x%lx\n", gpa);
	nr_sptes = kvm_mmu_get_spte_hierarchy(vcpu, gpa, sptes);

	for (i = PT64_ROOT_LEVEL; i > PT64_ROOT_LEVEL - nr_sptes; --i)
		ept_misconfig_inspect_spte(vcpu, sptes[i-1], i);

	vcpu->run->exit_reason = KVM_EXIT_UNKNOWN;
	vcpu->run->hw.hardware_exit_reason = EXIT_REASON_EPT_MISCONFIG;

	return (0);
}

/*
 * Indicate a busy-waiting vcpu in spinlock. We do not enable the PAUSE
 * exiting, so only get here on cpu with PAUSE-Loop-Exiting.
 */
static int
handle_pause(struct kvm_vcpu *vcpu)
{
	skip_emulated_instruction(vcpu);
#ifdef XXX
	kvm_vcpu_on_spin(vcpu);
#else
	XXX_KVM_PROBE;
#endif
	return (1);
}

static int
handle_invalid_op(struct kvm_vcpu *vcpu)
{
	kvm_queue_exception(vcpu, UD_VECTOR);
	return (1);
}

inline int
apic_find_highest_isr(struct kvm_lapic *apic)
{
	int ret;

	ret = find_highest_vector((void *)((uintptr_t)apic->regs + APIC_ISR));
	ASSERT(ret == -1 || ret >= 16);

	return (ret);
}

void
apic_update_ppr(struct kvm_lapic *apic)
{
	uint32_t tpr, isrv, ppr;
	int isr;

	tpr = apic_get_reg(apic, APIC_TASKPRI);
	isr = apic_find_highest_isr(apic);
	isrv = (isr != -1) ? isr : 0;

	if ((tpr & 0xf0) >= (isrv & 0xf0))
		ppr = tpr & 0xff;
	else
		ppr = isrv & 0xf0;

	apic_set_reg(apic, APIC_PROCPRI, ppr);
}

extern inline int apic_enabled(struct kvm_lapic *apic);

int
kvm_apic_has_interrupt(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;
	int highest_irr;

	if (!apic || !apic_enabled(apic))
		return (-1);

	apic_update_ppr(apic);
	highest_irr = apic_find_highest_irr(apic);
	if ((highest_irr == -1) ||
	    ((highest_irr & 0xF0) <= apic_get_reg(apic, APIC_PROCPRI)))
		return (-1);

	return (highest_irr);
}

extern inline int apic_hw_enabled(struct kvm_lapic *apic);

int
kvm_apic_accept_pic_intr(struct kvm_vcpu *vcpu)
{
	uint32_t lvt0 = apic_get_reg(vcpu->arch.apic, APIC_LVT0);
	int r = 0;

	if (kvm_vcpu_is_bsp(vcpu)) {
		if (!apic_hw_enabled(vcpu->arch.apic))
			r = 1;
		if ((lvt0 & APIC_LVT_MASKED) == 0 &&
		    GET_APIC_DELIVERY_MODE(lvt0) == APIC_MODE_EXTINT)
			r = 1;
	}

	return (r);
}

/*
 * check if there is pending interrupt without intack.
 */
int
kvm_cpu_has_interrupt(struct kvm_vcpu *v)
{
	struct kvm_pic *s;

	if (!irqchip_in_kernel(v->kvm))
		return (v->arch.interrupt.pending);

	if (kvm_apic_has_interrupt(v) == -1) {	/* LAPIC */
		if (kvm_apic_accept_pic_intr(v)) {
			s = pic_irqchip(v->kvm);	/* PIC */
			return (s->output);
		} else
			return (0);
	}
	return (1);
}

extern inline void apic_set_vector(int vec, caddr_t bitmap);
extern inline void apic_clear_vector(int vec, caddr_t bitmap);

static inline void
apic_clear_irr(int vec, struct kvm_lapic *apic)
{
	apic->irr_pending = 0;
	apic_clear_vector(vec, (void *)((uintptr_t)apic->regs + APIC_IRR));
	if (apic_search_irr(apic) != -1)
		apic->irr_pending = 1;
}

int
kvm_get_apic_interrupt(struct kvm_vcpu *vcpu)
{
	int vector = kvm_apic_has_interrupt(vcpu);
	struct kvm_lapic *apic = vcpu->arch.apic;

	if (vector == -1)
		return (-1);

	apic_set_vector(vector, (void *)((uintptr_t)apic->regs + APIC_ISR));
	apic_update_ppr(apic);
	apic_clear_irr(vector, apic);

	return (vector);
}

static int
handle_interrupt_window(struct kvm_vcpu *vcpu)
{
	uint32_t cpu_based_vm_exec_control;

	/* clear pending irq */
	cpu_based_vm_exec_control = vmcs_read32(CPU_BASED_VM_EXEC_CONTROL);
	cpu_based_vm_exec_control &= ~CPU_BASED_VIRTUAL_INTR_PENDING;
	vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, cpu_based_vm_exec_control);

#ifdef XXX_KVM_STAT
	++vcpu->stat.irq_window_exits;
#endif
	/*
	 * If the user space waits to inject interrupts, exit as soon as
	 * possible
	 */
	if (!irqchip_in_kernel(vcpu->kvm) &&
	    vcpu->run->request_interrupt_window &&
	    !kvm_cpu_has_interrupt(vcpu)) {
		vcpu->run->exit_reason = KVM_EXIT_IRQ_WINDOW_OPEN;
		return (0);
	}
	return (1);
}

/*
 * The exit handlers return 1 if the exit was handled fully and guest execution
 * may resume.  Otherwise they set the kvm_run parameter to indicate what needs
 * to be done to userspace and return 0.
 */
static int (*kvm_vmx_exit_handlers[])(struct kvm_vcpu *vcpu) = {
	[EXIT_REASON_EXCEPTION_NMI]		= handle_exception,
	[EXIT_REASON_EXTERNAL_INTERRUPT]	= handle_external_interrupt,
	[EXIT_REASON_TRIPLE_FAULT]		= handle_triple_fault,
	[EXIT_REASON_NMI_WINDOW]		= handle_nmi_window,
	[EXIT_REASON_IO_INSTRUCTION]		= handle_io,
	[EXIT_REASON_CR_ACCESS]			= handle_cr,
	[EXIT_REASON_DR_ACCESS]			= handle_dr,
	[EXIT_REASON_CPUID]			= handle_cpuid,
	[EXIT_REASON_MSR_READ]			= handle_rdmsr,
	[EXIT_REASON_MSR_WRITE]			= handle_wrmsr,
	[EXIT_REASON_PENDING_INTERRUPT]		= handle_interrupt_window,
	[EXIT_REASON_HLT]			= handle_halt,
	[EXIT_REASON_INVLPG]			= handle_invlpg,
	[EXIT_REASON_VMCALL]			= handle_vmcall,
	[EXIT_REASON_VMCLEAR]			= handle_vmx_insn,
	[EXIT_REASON_VMLAUNCH]			= handle_vmx_insn,
	[EXIT_REASON_VMPTRLD]			= handle_vmx_insn,
	[EXIT_REASON_VMPTRST]			= handle_vmx_insn,
	[EXIT_REASON_VMREAD]			= handle_vmx_insn,
	[EXIT_REASON_VMRESUME]			= handle_vmx_insn,
	[EXIT_REASON_VMWRITE]			= handle_vmx_insn,
	[EXIT_REASON_VMOFF]			= handle_vmx_insn,
	[EXIT_REASON_VMON]			= handle_vmx_insn,
	[EXIT_REASON_TPR_BELOW_THRESHOLD]	= handle_tpr_below_threshold,
	[EXIT_REASON_APIC_ACCESS]		= handle_apic_access,
	[EXIT_REASON_WBINVD]			= handle_wbinvd,
	[EXIT_REASON_TASK_SWITCH]		= handle_task_switch,
	[EXIT_REASON_MCE_DURING_VMENTRY]	= handle_machine_check,
	[EXIT_REASON_EPT_VIOLATION]		= handle_ept_violation,
	[EXIT_REASON_EPT_MISCONFIG]		= handle_ept_misconfig,
	[EXIT_REASON_PAUSE_INSTRUCTION]		= handle_pause,
	[EXIT_REASON_MWAIT_INSTRUCTION]		= handle_invalid_op,
	[EXIT_REASON_MONITOR_INSTRUCTION]	= handle_invalid_op,
};

/* BEGIN CSTYLED */

static const int kvm_vmx_max_exit_handlers =
	ARRAY_SIZE(kvm_vmx_exit_handlers);

/*
 * The guest has exited.  See if we can fix it or if we need userspace
 * assistance.
 */

static int vmx_handle_exit(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	uint32_t exit_reason = vmx->exit_reason;
	uint32_t vectoring_info = vmx->idt_vectoring_info;
	int rval;
	unsigned long rip;

	/* Always read the guest rip when exiting */
	rip = vmcs_readl(GUEST_RIP);
	DTRACE_PROBE2(kvm__vexit, unsigned long, rip, uint32_t, exit_reason);

#ifdef DEBUG
	cmn_err(CE_NOTE, "vmx_handle_exit: exit_reason = %d, vectoring_info = %x\n", exit_reason, vectoring_info);
#endif /*DEBUG*/
	/* If guest state is invalid, start emulating */
	if (vmx->emulation_required && emulate_invalid_guest_state)
		return handle_invalid_guest_state(vcpu);

	/* Access CR3 don't cause VMExit in paging mode, so we need
	 * to sync with guest real CR3. */
	if (enable_ept && is_paging(vcpu))
		vcpu->arch.cr3 = vmcs_readl(GUEST_CR3);

	if (vmx->fail) {
		vcpu->run->exit_reason = KVM_EXIT_FAIL_ENTRY;
		vcpu->run->fail_entry.hardware_entry_failure_reason
			= vmcs_read32(VM_INSTRUCTION_ERROR);
#ifdef DEBUG
		cmn_err(CE_NOTE, "vmx_handle_exit: fail = %x, failure reason = %x\n",
			vmx->fail, (unsigned int)vcpu->run->fail_entry.hardware_entry_failure_reason&0xff);
#endif /*DEBUG*/

		return (0);
	}

	if ((vectoring_info & VECTORING_INFO_VALID_MASK) &&
			(exit_reason != EXIT_REASON_EXCEPTION_NMI &&
			exit_reason != EXIT_REASON_EPT_VIOLATION &&
			exit_reason != EXIT_REASON_TASK_SWITCH))
		cmn_err(CE_WARN, "%s: unexpected, valid vectoring info "
		       "(0x%x) and exit reason is 0x%x\n",
		       __func__, vectoring_info, exit_reason);

	if (!cpu_has_virtual_nmis() && vmx->soft_vnmi_blocked) {
		if (vmx_interrupt_allowed(vcpu)) {
			vmx->soft_vnmi_blocked = 0;
		} else if (vmx->vnmi_blocked_time > 1000000000LL &&
			   vcpu->arch.nmi_pending) {
			/*
			 * This CPU don't support us in finding the end of an
			 * NMI-blocked window if the guest runs with IRQs
			 * disabled. So we pull the trigger after 1 s of
			 * futile waiting, but inform the user about this.
			 */
			cmn_err(CE_WARN, "%s: Breaking out of NMI-blocked "
			       "state on VCPU %d after 1 s timeout\n",
			       __func__, vcpu->vcpu_id);
			vmx->soft_vnmi_blocked = 0;
		}
	}

	if (exit_reason < kvm_vmx_max_exit_handlers
	    && kvm_vmx_exit_handlers[exit_reason]) {
		rval = kvm_vmx_exit_handlers[exit_reason](vcpu);
#ifdef DEBUG
		cmn_err(CE_NOTE, "vmx_handle_exit: returning %d from kvm_vmx_exit_handlers[%d]\n",
			rval, exit_reason);
#endif /*DEBUG*/
		return rval;
	} else {
		vcpu->run->exit_reason = KVM_EXIT_UNKNOWN;
		vcpu->run->hw.hardware_exit_reason = exit_reason;
	}
	return (0);
}

static inline void kvm_guest_exit(void)
{
#ifdef XXX
	account_system_vtime(current);
	current->flags &= ~PF_VCPU;
#else
	XXX_KVM_PROBE;
#endif /*XXX*/
}

static inline void kvm_guest_enter(void)
{
#ifdef XXX
	account_system_vtime(current);
	current->flags |= PF_VCPU;
#else
	XXX_KVM_PROBE;
#endif /*XXX*/
}

int kvm_mmu_load(struct kvm_vcpu *vcpu)
{
	int r;

	r = mmu_topup_memory_caches(vcpu);
	if (r)
		goto out;
	mutex_enter(&vcpu->kvm->mmu_lock);
	kvm_mmu_free_some_pages(vcpu);
	r = mmu_alloc_roots(vcpu);

	mmu_sync_roots(vcpu);
	mutex_exit(&vcpu->kvm->mmu_lock);
	if (r)
		goto out;
	/* set_cr3() should ensure TLB has been flushed */
	kvm_x86_ops->set_cr3(vcpu, vcpu->arch.mmu.root_hpa);
out:
	return r;
}

static int kvm_mmu_reload(struct kvm_vcpu *vcpu)
{
	if (vcpu->arch.mmu.root_hpa != INVALID_PAGE)
		return (0);

	return kvm_mmu_load(vcpu);
}

extern void mmu_free_roots(struct kvm_vcpu *vcpu);

void kvm_mmu_unload(struct kvm_vcpu *vcpu)
{
	mmu_free_roots(vcpu);
}

extern void apic_set_tpr(struct kvm_lapic *apic, uint32_t tpr);

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


void kvm_lapic_sync_from_vapic(struct kvm_vcpu *vcpu)
{
	uint32_t data;
	void *vapic;

	if (!irqchip_in_kernel(vcpu->kvm) || !vcpu->arch.apic->vapic_addr)
		return;

	vapic = page_address(vcpu->arch.apic->vapic_page);

	data = *(uint32_t *)((uintptr_t)vapic + offset_in_page(vcpu->arch.apic->vapic_addr));
#ifdef XXX
	kunmap_atomic(vapic, KM_USER0);
#else
	XXX_KVM_PROBE;
#endif /*XXX*/

	apic_set_tpr(vcpu->arch.apic, data & 0xff);
}

void kvm_lapic_sync_to_vapic(struct kvm_vcpu *vcpu)
{
	uint32_t data, tpr;
	int max_irr, max_isr;
	struct kvm_lapic *apic;
	void *vapic;

	if (!irqchip_in_kernel(vcpu->kvm) || !vcpu->arch.apic->vapic_addr)
		return;

	apic = vcpu->arch.apic;
	tpr = apic_get_reg(apic, APIC_TASKPRI) & 0xff;
	max_irr = apic_find_highest_irr(apic);
	if (max_irr < 0)
		max_irr = 0;
	max_isr = apic_find_highest_isr(apic);
	if (max_isr < 0)
		max_isr = 0;
	data = (tpr & 0xff) | ((max_isr & 0xf0) << 8) | (max_irr << 24);

	vapic = page_address(vcpu->arch.apic->vapic_page);

	*(uint32_t *)((uintptr_t)vapic + offset_in_page(vcpu->arch.apic->vapic_addr)) = data;
#ifdef XXX
	kunmap_atomic(vapic, KM_USER0);
#else
	XXX_KVM_PROBE;
#endif /*XXX*/
}

extern inline int  apic_sw_enabled(struct kvm_lapic *apic);

int kvm_apic_present(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.apic && apic_hw_enabled(vcpu->arch.apic);
}


int kvm_lapic_enabled(struct kvm_vcpu *vcpu)
{
	return kvm_apic_present(vcpu) && apic_sw_enabled(vcpu->arch.apic);
}

void kvm_notify_acked_irq(struct kvm *kvm, unsigned irqchip, unsigned pin)
{
	struct kvm_irq_ack_notifier *kian;
	struct hlist_node *n;
	int gsi;

#ifdef DEBUG
	cmn_err(CE_NOTE, "%s: irqchip = %x, pin = %x\n", __func__, irqchip, pin);
#endif /*DEBUG*/
#ifdef XXX_KVM_TRACE
	trace_kvm_ack_irq(irqchip, pin);
#endif /*XXX*/

#ifdef XXX
	rcu_read_lock();

	gsi = rcu_dereference(kvm->irq_routing)->chip[irqchip][pin];
#else
	XXX_KVM_SYNC_PROBE;
#endif /*XXX*/
	gsi = (kvm->irq_routing)->chip[irqchip][pin];

	if (gsi != -1) {
		for (kian = list_head(&kvm->irq_ack_notifier_list);
		     kian;
		     kian = list_next(&kvm->irq_ack_notifier_list, kian)) {
			if (kian->gsi == gsi)
				kian->irq_acked(kian);
		}
	}
#ifdef XXX
	rcu_read_unlock();
#else
	XXX_KVM_SYNC_PROBE;
#endif /*XXX*/

}

static void pic_clear_isr(struct kvm_kpic_state *s, int irq)
{
	s->isr &= ~(1 << irq);
	s->isr_ack |= (1 << irq);
	if (s != &s->pics_state->pics[0])
		irq += 8;
	/*
	 * We are dropping lock while calling ack notifiers since ack
	 * notifier callbacks for assigned devices call into PIC recursively.
	 * Other interrupt may be delivered to PIC while lock is dropped but
	 * it should be safe since PIC state is already updated at this stage.
	 */
	mutex_exit(&s->pics_state->lock);
	kvm_notify_acked_irq(s->pics_state->kvm, SELECT_PIC(irq), irq);
	mutex_enter(&s->pics_state->lock);
}

/*
 * acknowledge interrupt 'irq'
 */
static inline void pic_intack(struct kvm_kpic_state *s, int irq)
{
	s->isr |= 1 << irq;
	/*
	 * We don't clear a level sensitive interrupt here
	 */
	if (!(s->elcr & (1 << irq)))
		s->irr &= ~(1 << irq);

	if (s->auto_eoi) {
		if (s->rotate_on_auto_eoi)
			s->priority_add = (irq + 1) & 7;
		pic_clear_isr(s, irq);
	}

}

/*
 * return the highest priority found in mask (highest = smallest
 * number). Return 8 if no irq
 */
static inline int get_priority(struct kvm_kpic_state *s, int mask)
{
	int priority;
	if (mask == 0)
		return 8;
	priority = 0;
	while ((mask & (1 << ((priority + s->priority_add) & 7))) == 0)
		priority++;
	return priority;
}

/*
 * return the pic wanted interrupt. return -1 if none
 */
static int pic_get_irq(struct kvm_kpic_state *s)
{
	int mask, cur_priority, priority;

	mask = s->irr & ~s->imr;
	priority = get_priority(s, mask);
	if (priority == 8)
		return -1;
	/*
	 * compute current priority. If special fully nested mode on the
	 * master, the IRQ coming from the slave is not taken into account
	 * for the priority computation.
	 */
	mask = s->isr;
	if (s->special_fully_nested_mode && s == &s->pics_state->pics[0])
		mask &= ~(1 << 2);
	cur_priority = get_priority(s, mask);
	if (priority < cur_priority)
		/*
		 * higher priority found: an irq should be generated
		 */
		return (priority + s->priority_add) & 7;
	else
		return -1;
}

/*
 * set irq level. If an edge is detected, then the IRR is set to 1
 */
static inline int pic_set_irq1(struct kvm_kpic_state *s, int irq, int level)
{
	int mask, ret = 1;
	mask = 1 << irq;
	if (s->elcr & mask)	/* level triggered */
		if (level) {
			ret = !(s->irr & mask);
			s->irr |= mask;
			s->last_irr |= mask;
		} else {
			s->irr &= ~mask;
			s->last_irr &= ~mask;
		}
	else	/* edge triggered */
		if (level) {
			if ((s->last_irr & mask) == 0) {
				ret = !(s->irr & mask);
				s->irr |= mask;
			}
			s->last_irr |= mask;
		} else
			s->last_irr &= ~mask;

	return (s->imr & mask) ? -1 : ret;
}


/*
 * raise irq to CPU if necessary. must be called every time the active
 * irq may change
 */
static void pic_update_irq(struct kvm_pic *s)
{
	int irq2, irq;

	irq2 = pic_get_irq(&s->pics[1]);
	if (irq2 >= 0) {
		/*
		 * if irq request by slave pic, signal master PIC
		 */
		pic_set_irq1(&s->pics[0], 2, 1);
		pic_set_irq1(&s->pics[0], 2, 0);
	}
	irq = pic_get_irq(&s->pics[0]);
	if (irq >= 0)
		s->irq_request(s->irq_request_opaque, 1);
	else
		s->irq_request(s->irq_request_opaque, 0);
}

int kvm_pic_read_irq(struct kvm *kvm)
{
	int irq, irq2, intno;
	struct kvm_pic *s = pic_irqchip(kvm);

	mutex_enter(&s->lock);
	irq = pic_get_irq(&s->pics[0]);
	if (irq >= 0) {
		pic_intack(&s->pics[0], irq);
		if (irq == 2) {
			irq2 = pic_get_irq(&s->pics[1]);
			if (irq2 >= 0)
				pic_intack(&s->pics[1], irq2);
			else
				/*
				 * spurious IRQ on slave controller
				 */
				irq2 = 7;
			intno = s->pics[1].irq_base + irq2;
			irq = irq2 + 8;
		} else
			intno = s->pics[0].irq_base + irq;
	} else {
		/*
		 * spurious IRQ on host controller
		 */
		irq = 7;
		intno = s->pics[0].irq_base + irq;
	}
	pic_update_irq(s);
	mutex_exit(&s->lock);

	return intno;
}


/*
 * Read pending interrupt vector and intack.
 */
int kvm_cpu_get_interrupt(struct kvm_vcpu *v)
{
	struct kvm_pic *s;
	int vector;

	if (!irqchip_in_kernel(v->kvm))
		return v->arch.interrupt.nr;

	vector = kvm_get_apic_interrupt(v);	/* APIC */
	if (vector == -1) {
		if (kvm_apic_accept_pic_intr(v)) {
			s = pic_irqchip(v->kvm);
			s->output = 0;		/* PIC */
			vector = kvm_pic_read_irq(v->kvm);
		}
	}
	return vector;
}

static void inject_pending_event(struct kvm_vcpu *vcpu)
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

void kvm_load_guest_fpu(struct kvm_vcpu *vcpu)
{
	if (vcpu->guest_fpu_loaded)
		return;

	vcpu->guest_fpu_loaded = 1;
	kvm_fx_save(&vcpu->arch.host_fx_image);
	kvm_fx_restore(&vcpu->arch.guest_fx_image);
#ifdef XXX_KVM_TRACE
	trace_kvm_fpu(1);
#endif /*XXX*/
}

static inline unsigned long native_get_debugreg(int regno)
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
		cmn_err(CE_WARN, "kvm: invalid debug register retrieval, regno =  %d\n", regno);
	}
	return val;
}

static inline void native_set_debugreg(int regno, unsigned long value)
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
		cmn_err(CE_WARN, "kvm: invalid debug register set, regno =  %d\n", regno);
	}
}

static uint32_t div_frac(uint32_t dividend, uint32_t divisor)
{
	uint32_t quotient, remainder;

	/* Don't try to replace with do_div(), this one calculates
	 * "(dividend << 32) / divisor" */
	__asm__ ( "divl %4"
		  : "=a" (quotient), "=d" (remainder)
		  : "0" (0), "1" (dividend), "r" (divisor) );
	return quotient;
}

static void kvm_set_time_scale(uint32_t tsc_khz, struct pvclock_vcpu_time_info *hv_clock)
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

#ifdef KVM_DEBUG
	pr_debug("%s: tsc_khz %u, tsc_shift %d, tsc_mul %u\n",
		 __func__, tsc_khz, hv_clock->tsc_shift,
		 hv_clock->tsc_to_system_mul);
#endif /*KVM_DEBUG*/
}

static void kvm_write_guest_time(struct kvm_vcpu *v)
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
#endif /*XXX*/

#ifdef XXX
	/* Keep irq disabled to prevent changes to the clock */
	local_irq_save(flags);
#else
	/*
	 * may need to mask interrupts for local_irq_save, and unmask
	 * for local_irq_restore.  cli()/sti() might be done...
	 */
	XXX_KVM_PROBE;
#endif /*XXX*/
	kvm_get_msr(v, MSR_IA32_TSC, &vcpu->hv_clock.tsc_timestamp);
	gethrestime(&ts);
#ifdef XXX
	monotonic_to_bootbased(&ts);
	local_irq_restore(flags);
#else
	XXX_KVM_PROBE;
#endif /*XXX*/

	/* With all the info we got, fill in the values */

	vcpu->hv_clock.system_time = ts.tv_nsec +
				     (NSEC_PER_SEC * (uint64_t)ts.tv_sec) + v->kvm->arch.kvmclock_offset;

	/*
	 * The interface expects us to write an even number signaling that the
	 * update is finished. Since the guest won't see the intermediate
	 * state, we just increase by 2 at the end.
	 */
	vcpu->hv_clock.version += 2;

	shared_kaddr = page_address(vcpu->time_page);

	memcpy((void *)((uintptr_t)shared_kaddr + vcpu->time_offset), &vcpu->hv_clock,
	       sizeof(vcpu->hv_clock));


	mark_page_dirty(v->kvm, vcpu->time >> PAGESHIFT);
}

/*
 * These special macros can be used to get or set a debugging register
 */
#define	get_debugreg(var, register)				\
	(var) = native_get_debugreg(register)
#define	set_debugreg(value, register)				\
	native_set_debugreg(register, value)

static int vcpu_enter_guest(struct kvm_vcpu *vcpu)
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
		if (test_and_clear_bit(KVM_REQ_MIGRATE_TIMER, &vcpu->requests)) {
#ifdef XXX
			__kvm_migrate_timers(vcpu);
#else
			XXX_KVM_PROBE;
#endif /*XXX*/
		}
		if (test_and_clear_bit(KVM_REQ_KVMCLOCK_UPDATE, &vcpu->requests)) {
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

		if (test_and_clear_bit(KVM_REQ_DEACTIVATE_FPU, &vcpu->requests)) {
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
#endif /*XXX*/

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
#endif /*XXX*/
	kvm_guest_enter();

	if (vcpu->arch.switch_db_regs) {
		set_debugreg(0, 7);
		set_debugreg(vcpu->arch.eff_db[0], 0);
		set_debugreg(vcpu->arch.eff_db[1], 1);
		set_debugreg(vcpu->arch.eff_db[2], 2);
		set_debugreg(vcpu->arch.eff_db[3], 3);
	}

#ifdef XXX_KVM_TRACE
	trace_kvm_entry(vcpu->vcpu_id);
#endif /*XXX*/
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
#endif /*XXX*/
	set_bit(KVM_REQ_KICK, &vcpu->requests);

	sti();

#ifdef XXX
	local_irq_enable();  /* XXX - should be ok with kpreempt_enable below */

	++vcpu->stat.exits;
	barrier();
#else
	XXX_KVM_PROBE;
#endif /*XXX*/
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
#endif /*XXX*/
	kvm_lapic_sync_from_vapic(vcpu);
	r = kvm_x86_ops->handle_exit(vcpu);
#ifdef DEBUG
	cmn_err(CE_NOTE, "vcpu_enter_guest: returning %d\n", r);
#endif /*DEBUG*/
out:
	return r;
}


static void post_kvm_run_save(struct kvm_vcpu *vcpu)
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
void kvm_vcpu_block(struct kvm_vcpu *vcpu)
{
	for (;;) {
		if (kvm_arch_vcpu_runnable(vcpu)) {
			set_bit(KVM_REQ_UNHALT, &vcpu->requests);
			break;
		}

		if (issig(JUSTLOOKING))
			break;

		mutex_enter(&vcpu->kvcpu_timer_lock);
		
		if (kvm_cpu_has_pending_timer(vcpu)) {
			mutex_exit(&vcpu->kvcpu_timer_lock);
			break;
		}

		(void) cv_wait_sig_swap(&vcpu->kvcpu_timer_cv,
		    &vcpu->kvcpu_timer_lock);

		mutex_exit(&vcpu->kvcpu_timer_lock);
	}
}

static void vapic_enter(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;
	page_t *page;

	if (!apic || !apic->vapic_addr)
		return;

	page = gfn_to_page(vcpu->kvm, apic->vapic_addr >> PAGESHIFT);

	vcpu->arch.apic->vapic_page = page;
}

extern int kvm_apic_id(struct kvm_lapic *apic);

static void vapic_exit(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;
	int idx;

	if (!apic || !apic->vapic_addr)
		return;
#ifdef XXX
	idx = srcu_read_lock(&vcpu->kvm->srcu);
#else
	XXX_KVM_SYNC_PROBE;
#endif /*XXX*/
	kvm_release_page_dirty(apic->vapic_page);
	mark_page_dirty(vcpu->kvm, apic->vapic_addr >> PAGESHIFT);
#ifdef XXX
	srcu_read_unlock(&vcpu->kvm->srcu, idx);
#else
	XXX_KVM_SYNC_PROBE;
#endif /*XXX*/
}

void kvm_lapic_reset(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic;
	int i;

	ASSERT(vcpu);
	apic = vcpu->arch.apic;
	ASSERT(apic != NULL);

#ifdef XXX
	/* Stop the timer in case it's a reset to an active apic */
	hrtimer_cancel(&apic->lapic_timer.timer);
#else
	mutex_enter(&cpu_lock);
	if (apic->lapic_timer.active) {
		cyclic_remove(apic->lapic_timer.kvm_cyclic_id);
		apic->lapic_timer.active = 0;
	}
	mutex_exit(&cpu_lock);
	XXX_KVM_PROBE;
#endif /*XXX*/

	apic_set_reg(apic, APIC_ID, vcpu->vcpu_id << 24);
	kvm_apic_set_version(apic->vcpu);

	for (i = 0; i < APIC_LVT_NUM; i++)
		apic_set_reg(apic, APIC_LVTT + 0x10 * i, APIC_LVT_MASKED);
	apic_set_reg(apic, APIC_LVT0,
		     SET_APIC_DELIVERY_MODE(0, APIC_MODE_EXTINT));

	apic_set_reg(apic, APIC_DFR, 0xffffffffU);
	apic_set_reg(apic, APIC_SPIV, 0xff);
	apic_set_reg(apic, APIC_TASKPRI, 0);
	apic_set_reg(apic, APIC_LDR, 0);
	apic_set_reg(apic, APIC_ESR, 0);
	apic_set_reg(apic, APIC_ICR, 0);
	apic_set_reg(apic, APIC_ICR2, 0);
	apic_set_reg(apic, APIC_TDCR, 0);
	apic_set_reg(apic, APIC_TMICT, 0);
	for (i = 0; i < 8; i++) {
		apic_set_reg(apic, APIC_IRR + 0x10 * i, 0);
		apic_set_reg(apic, APIC_ISR + 0x10 * i, 0);
		apic_set_reg(apic, APIC_TMR + 0x10 * i, 0);
	}
	apic->irr_pending = 0;
	update_divide_count(apic);
#ifdef XXX
	atomic_set(&apic->lapic_timer.pending, 0);
#else
	apic->lapic_timer.pending = 0;
	XXX_KVM_PROBE;
#endif /*XXX*/
	if (kvm_vcpu_is_bsp(vcpu))
		vcpu->arch.apic_base |= MSR_IA32_APICBASE_BSP;
	apic_update_ppr(apic);

	vcpu->arch.apic_arb_prio = 0;

	cmn_err(CE_NOTE, "%s: vcpu=%p, id=%d, base_msr= %lx PRIx64 base_address=%lx\n",
		__func__, vcpu, kvm_apic_id(apic), vcpu->arch.apic_base, apic->base_address);
}

static int dm_request_for_irq_injection(struct kvm_vcpu *vcpu)
{
	return (!irqchip_in_kernel(vcpu->kvm) && !kvm_cpu_has_interrupt(vcpu) &&
		vcpu->run->request_interrupt_window &&
		kvm_arch_interrupt_allowed(vcpu));
}

static int __vcpu_run(struct kvm_vcpu *vcpu)
{
	int r;
	struct kvm *kvm = vcpu->kvm;

	if (vcpu->arch.mp_state == KVM_MP_STATE_SIPI_RECEIVED) {
		cmn_err(CE_NOTE, "vcpu %d received sipi with vector # %x\n",
			 vcpu->vcpu_id, vcpu->arch.sipi_vector);
		kvm_lapic_reset(vcpu);
		r = kvm_arch_vcpu_reset(vcpu);
		if (r)
			return r;
		vcpu->arch.mp_state = KVM_MP_STATE_RUNNABLE;
	}

#ifdef XXX
	vcpu->srcu_idx = srcu_read_lock(&kvm->srcu);
#else
	XXX_KVM_SYNC_PROBE;
#endif /*XXX*/
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
#endif /*XXX*/
			kvm_vcpu_block(vcpu);
#ifdef XXX
			vcpu->srcu_idx = srcu_read_lock(&kvm->srcu);
#else
			XXX_KVM_SYNC_PROBE;
#endif /*XXX*/
			if (test_and_clear_bit(KVM_REQ_UNHALT, &vcpu->requests))
			{
				switch(vcpu->arch.mp_state) {
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

		if (r <= 0) {
#ifdef DEBUG
			cmn_err(CE_NOTE, "__vcpu_run: r = %d\n", r);
#endif /*DEBUG*/
			break;
		}

		clear_bit(KVM_REQ_PENDING_TIMER, &vcpu->requests);
		if (kvm_cpu_has_pending_timer(vcpu))
			kvm_inject_pending_timer_irqs(vcpu);

		if (dm_request_for_irq_injection(vcpu)) {
			r = -EINTR;
			vcpu->run->exit_reason = KVM_EXIT_INTR;
#ifdef XXX_KVM_STAT
			++vcpu->stat.request_irq_exits;
#endif /*XXX*/
		}

		if (issig(JUSTLOOKING)) {
			r = -EINTR;
			vcpu->run->exit_reason = KVM_EXIT_INTR;
#ifdef XXX_KVM_STAT
			++vcpu->stat.signal_exits;
#endif /*XXX*/
		}

		if (CPU->cpu_runrun || CPU->cpu_kprunrun)
			preempt();
	}
#ifdef XXX
	srcu_read_unlock(&kvm->srcu, vcpu->srcu_idx);
#else
	XXX_KVM_SYNC_PROBE;
#endif /*XXX*/
	post_kvm_run_save(vcpu);
	vapic_exit(vcpu);
#ifdef DEBUG
	cmn_err(CE_NOTE, "__vcpu_run: returning %d\n", r);
#endif /*DEBUG*/
	return r;
}

int kvm_arch_vcpu_ioctl_run(struct kvm_vcpu *vcpu, struct kvm_run *kvm_run)
{
	int r;
	sigset_t sigsaved;

	vcpu_load(vcpu);

	if (vcpu->sigset_active)
		sigprocmask(SIG_SETMASK, &vcpu->sigset, &sigsaved);

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
#endif /*XXX*/
		r = complete_pio(vcpu);
#ifdef XXX
		srcu_read_unlock(&vcpu->kvm->srcu, vcpu->srcu_idx);
#else
		XXX_KVM_SYNC_PROBE;
#endif /*XXX*/
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
#endif /*XXX*/
		r = emulate_instruction(vcpu, vcpu->arch.mmio_fault_cr2, 0,
					EMULTYPE_NO_DECODE);
#ifdef XXX
		srcu_read_unlock(&vcpu->kvm->srcu, vcpu->srcu_idx);
#else
		XXX_KVM_SYNC_PROBE;
#endif /*XXX*/
		if (r == EMULATE_DO_MMIO) {
			/*
			 * Read-modify-write.  Back to userspace.
			 */
			r = 0;
			goto out;
		}
	}
	if (kvm_run->exit_reason == KVM_EXIT_HYPERCALL)
		kvm_register_write(vcpu, VCPU_REGS_RAX,
				     kvm_run->hypercall.ret);

	r = __vcpu_run(vcpu);

out:
	if (vcpu->sigset_active)
		sigprocmask(SIG_SETMASK, &sigsaved, NULL);

	vcpu_put(vcpu);
	return r;
}

int kvm_arch_vcpu_ioctl_get_mpstate(struct kvm_vcpu *vcpu,
				    struct kvm_mp_state *mp_state)
{
	vcpu_load(vcpu);
	mp_state->mp_state = vcpu->arch.mp_state;
	vcpu_put(vcpu);
	return (0);
}

int kvm_arch_vcpu_ioctl_set_mpstate(struct kvm_vcpu *vcpu,
				    struct kvm_mp_state *mp_state)
{
	vcpu_load(vcpu);
	vcpu->arch.mp_state = mp_state->mp_state;
	vcpu_put(vcpu);
	return (0);
}

static void kvm_vcpu_ioctl_x86_get_vcpu_events(struct kvm_vcpu *vcpu,
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

	events->flags = (KVM_VCPUEVENT_VALID_NMI_PENDING
			 | KVM_VCPUEVENT_VALID_SIPI_VECTOR);

	vcpu_put(vcpu);
}

static int kvm_vcpu_ioctl_x86_set_vcpu_events(struct kvm_vcpu *vcpu,
					      struct kvm_vcpu_events *events)
{
	if (events->flags & ~(KVM_VCPUEVENT_VALID_NMI_PENDING
			      | KVM_VCPUEVENT_VALID_SIPI_VECTOR))
		return -EINVAL;

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

static int picdev_in_range(gpa_t addr)
{
	switch (addr) {
	case 0x20:
	case 0x21:
	case 0xa0:
	case 0xa1:
	case 0x4d0:
	case 0x4d1:
		return (1);
	default:
		return (0);
	}
}

static inline struct kvm_pic *to_pic(struct kvm_io_device *dev)
{
#ifdef XXX_KVM_DOESNTCOMPILE
	return container_of(dev, struct kvm_pic, dev);
#else
	return (struct kvm_pic *) ((caddr_t)dev-offsetof(struct kvm_pic, dev));
#endif /*XXX*/
}

void kvm_pic_reset(struct kvm_kpic_state *s)
{
	int irq;
	struct kvm *kvm = s->pics_state->irq_request_opaque;
	struct kvm_vcpu *vcpu0 = kvm->bsp_vcpu;
	uint8_t irr = s->irr, isr = s->imr;

	s->last_irr = 0;
	s->irr = 0;
	s->imr = 0;
	s->isr = 0;
	s->isr_ack = 0xff;
	s->priority_add = 0;
	s->irq_base = 0;
	s->read_reg_select = 0;
	s->poll = 0;
	s->special_mask = 0;
	s->init_state = 0;
	s->auto_eoi = 0;
	s->rotate_on_auto_eoi = 0;
	s->special_fully_nested_mode = 0;
	s->init4 = 0;

	for (irq = 0; irq < PIC_NUM_PINS/2; irq++) {
		if (vcpu0 && kvm_apic_accept_pic_intr(vcpu0))
			if (irr & (1 << irq) || isr & (1 << irq)) {
				pic_clear_isr(s, irq);
			}
	}
}


static void pic_ioport_write(void *opaque, uint32_t addr, uint32_t val)
{
	struct kvm_kpic_state *s = opaque;
	int priority, cmd, irq;

	addr &= 1;
	if (addr == 0) {
		if (val & 0x10) {
			kvm_pic_reset(s);	/* init */
			/*
			 * deassert a pending interrupt
			 */
			s->pics_state->irq_request(s->pics_state->
						   irq_request_opaque, 0);
			s->init_state = 1;
			s->init4 = val & 1;
			if (val & 0x02)
				cmn_err(CE_WARN, "single mode not supported");
			if (val & 0x08)
				cmn_err(CE_WARN, "level sensitive irq not supported");
		} else if (val & 0x08) {
			if (val & 0x04)
				s->poll = 1;
			if (val & 0x02)
				s->read_reg_select = val & 1;
			if (val & 0x40)
				s->special_mask = (val >> 5) & 1;
		} else {
			cmd = val >> 5;
			switch (cmd) {
			case 0:
			case 4:
				s->rotate_on_auto_eoi = cmd >> 2;
				break;
			case 1:	/* end of interrupt */
			case 5:
				priority = get_priority(s, s->isr);
				if (priority != 8) {
					irq = (priority + s->priority_add) & 7;
					if (cmd == 5)
						s->priority_add = (irq + 1) & 7;
					pic_clear_isr(s, irq);
					pic_update_irq(s->pics_state);
				}
				break;
			case 3:
				irq = val & 7;
				pic_clear_isr(s, irq);
				pic_update_irq(s->pics_state);
				break;
			case 6:
				s->priority_add = (val + 1) & 7;
				pic_update_irq(s->pics_state);
				break;
			case 7:
				irq = val & 7;
				s->priority_add = (irq + 1) & 7;
				pic_clear_isr(s, irq);
				pic_update_irq(s->pics_state);
				break;
			default:
				break;	/* no operation */
			}
		}
	} else
		switch (s->init_state) {
		case 0:		/* normal mode */
			s->imr = val;
			pic_update_irq(s->pics_state);
			break;
		case 1:
			s->irq_base = val & 0xf8;
			s->init_state = 2;
			break;
		case 2:
			if (s->init4)
				s->init_state = 3;
			else
				s->init_state = 0;
			break;
		case 3:
			s->special_fully_nested_mode = (val >> 4) & 1;
			s->auto_eoi = (val >> 1) & 1;
			s->init_state = 0;
			break;
		}
}

static uint32_t pic_poll_read(struct kvm_kpic_state *s, uint32_t addr1)
{
	int ret;

	ret = pic_get_irq(s);
	if (ret >= 0) {
		if (addr1 >> 7) {
			s->pics_state->pics[0].isr &= ~(1 << 2);
			s->pics_state->pics[0].irr &= ~(1 << 2);
		}
		s->irr &= ~(1 << ret);
		pic_clear_isr(s, ret);
		if (addr1 >> 7 || ret != 2)
			pic_update_irq(s->pics_state);
	} else {
		ret = 0x07;
		pic_update_irq(s->pics_state);
	}

	return ret;
}

static uint32_t pic_ioport_read(void *opaque, uint32_t addr1)
{
	struct kvm_kpic_state *s = opaque;
	unsigned int addr;
	int ret;

	addr = addr1;
	addr &= 1;
	if (s->poll) {
		ret = pic_poll_read(s, addr1);
		s->poll = 0;
	} else
		if (addr == 0)
			if (s->read_reg_select)
				ret = s->isr;
			else
				ret = s->irr;
		else
			ret = s->imr;
	return ret;
}

static void elcr_ioport_write(void *opaque, uint32_t addr, uint32_t val)
{
	struct kvm_kpic_state *s = opaque;
	s->elcr = val & s->elcr_mask;
}

static uint32_t elcr_ioport_read(void *opaque, uint32_t addr1)
{
	struct kvm_kpic_state *s = opaque;
	return s->elcr;
}


static int picdev_write(struct kvm_io_device *this,
			 gpa_t addr, int len, const void *val)
{
	struct kvm_pic *s = to_pic(this);
	unsigned char data = *(unsigned char *)val;
	if (!picdev_in_range(addr))
		return -EOPNOTSUPP;

	if (len != 1) {
		return (0);
	}
	mutex_enter(&s->lock);
	switch (addr) {
	case 0x20:
	case 0x21:
	case 0xa0:
	case 0xa1:
		pic_ioport_write(&s->pics[addr >> 7], addr, data);
		break;
	case 0x4d0:
	case 0x4d1:
		elcr_ioport_write(&s->pics[addr & 1], addr, data);
		break;
	}
	mutex_exit(&s->lock);
	return (0);
}

static int picdev_read(struct kvm_io_device *this,
		       gpa_t addr, int len, void *val)
{
	struct kvm_pic *s = to_pic(this);
	unsigned char data = 0;
	if (!picdev_in_range(addr))
		return -EOPNOTSUPP;

	if (len != 1) {
		return (0);
	}
	mutex_enter(&s->lock);
	switch (addr) {
	case 0x20:
	case 0x21:
	case 0xa0:
	case 0xa1:
		data = pic_ioport_read(&s->pics[addr >> 7], addr);
		break;
	case 0x4d0:
	case 0x4d1:
		data = elcr_ioport_read(&s->pics[addr & 1], addr);
		break;
	}
	*(unsigned char *)val = data;
	mutex_exit(&s->lock);
	return (0);
}

/*
 * callback when PIC0 irq status changed
 */
static void pic_irq_request(void *opaque, int level)
{
	struct kvm *kvm = opaque;
	struct kvm_vcpu *vcpu = kvm->bsp_vcpu;
	struct kvm_pic *s = pic_irqchip(kvm);
	int irq = pic_get_irq(&s->pics[0]);

	s->output = level;
	if (vcpu && level && (s->pics[0].isr_ack & (1 << irq))) {
		s->pics[0].isr_ack &= ~(1 << irq);
		kvm_vcpu_kick(vcpu);
	}
}

static const struct kvm_io_device_ops picdev_ops = {
	.read     = picdev_read,
	.write    = picdev_write,
};

struct kvm_pic *kvm_create_pic(struct kvm *kvm)
{
	struct kvm_pic *s;
	int ret;

	s = kmem_zalloc(sizeof(struct kvm_pic), KM_SLEEP);
	mutex_init(&s->lock, NULL, MUTEX_DRIVER, 0);
	s->kvm = kvm;
	s->pics[0].elcr_mask = 0xf8;
	s->pics[1].elcr_mask = 0xde;
	s->irq_request = pic_irq_request;
	s->irq_request_opaque = kvm;
	s->pics[0].pics_state = s;
	s->pics[1].pics_state = s;

	/*
	 * Initialize PIO device
	 */
	kvm_iodevice_init(&s->dev, &picdev_ops);
	mutex_enter(&kvm->slots_lock);
	ret = kvm_io_bus_register_dev(kvm, KVM_PIO_BUS, &s->dev);
	mutex_exit(&kvm->slots_lock);
	if (ret < 0) {
		kmem_free(s, sizeof(struct kvm_pic));
		return NULL;
	}

	return s;
}

void kvm_destroy_pic(struct kvm *kvm)
{
	struct kvm_pic *vpic = kvm->arch.vpic;

	if (vpic) {
		kvm_io_bus_unregister_dev(kvm, KVM_PIO_BUS, &vpic->dev);
		kvm->arch.vpic = NULL;
		kmem_free(vpic, sizeof(struct kvm_pic));
	}
}

static unsigned long ioapic_read_indirect(struct kvm_ioapic *ioapic,
					  unsigned long addr,
					  unsigned long length)
{
	unsigned long result = 0;

	switch (ioapic->ioregsel) {
	case IOAPIC_REG_VERSION:
		result = ((((IOAPIC_NUM_PINS - 1) & 0xff) << 16)
			  | (IOAPIC_VERSION_ID & 0xff));
		break;

	case IOAPIC_REG_APIC_ID:
	case IOAPIC_REG_ARB_ID:
		result = ((ioapic->id & 0xf) << 24);
		break;

	default:
		{
			uint32_t redir_index = (ioapic->ioregsel - 0x10) >> 1;
			uint64_t redir_content;

			ASSERT(redir_index < IOAPIC_NUM_PINS);

			redir_content = ioapic->redirtbl[redir_index].bits;
			result = (ioapic->ioregsel & 0x1) ?
			    (redir_content >> 32) & 0xffffffff :
			    redir_content & 0xffffffff;
			break;
		}
	}

	return result;
}

static int ioapic_deliver(struct kvm_ioapic *ioapic, int irq)
{
	union kvm_ioapic_redirect_entry *entry = &ioapic->redirtbl[irq];
	struct kvm_lapic_irq irqe;

	irqe.dest_id = entry->fields.dest_id;
	irqe.vector = entry->fields.vector;
	irqe.dest_mode = entry->fields.dest_mode;
	irqe.trig_mode = entry->fields.trig_mode;
	irqe.delivery_mode = entry->fields.delivery_mode << 8;
	irqe.level = 1;
	irqe.shorthand = 0;

#ifdef CONFIG_X86
	/* Always delivery PIT interrupt to vcpu 0 */
	if (irq == 0) {
		irqe.dest_mode = 0; /* Physical mode. */
		/* need to read apic_id from apic regiest since
		 * it can be rewritten */
		irqe.dest_id = ioapic->kvm->bsp_vcpu->vcpu_id;
	}
#endif
	return kvm_irq_delivery_to_apic(ioapic->kvm, NULL, &irqe);
}

extern int kvm_apic_set_irq(struct kvm_vcpu *vcpu, struct kvm_lapic_irq *irq);

static int ioapic_service(struct kvm_ioapic *ioapic, unsigned int idx)
{
	union kvm_ioapic_redirect_entry *pent;
	int injected = -1;

	pent = &ioapic->redirtbl[idx];

	if (!pent->fields.mask) {
		injected = ioapic_deliver(ioapic, idx);
		if (injected && pent->fields.trig_mode == IOAPIC_LEVEL_TRIG)
			pent->fields.remote_irr = 1;
	}

	return injected;
}

static void update_handled_vectors(struct kvm_ioapic *ioapic)
{
#ifdef XXX_KVM_DECLARATION
	BITMAP_VECTORS(handled_vectors, 256);
#else
	unsigned long handled_vectors[4];
#endif
	int i;

	memset(handled_vectors, 0, sizeof(handled_vectors));
	for (i = 0; i < IOAPIC_NUM_PINS; ++i)
		__set_bit(ioapic->redirtbl[i].fields.vector, handled_vectors);
	memcpy(ioapic->handled_vectors, handled_vectors,
	       sizeof(handled_vectors));
#ifdef XXX
	smp_wmb();
#else
	XXX_KVM_SYNC_PROBE;
#endif /*XXX*/
}

void kvm_fire_mask_notifiers(struct kvm *kvm, int irq, int mask)
{
	struct kvm_irq_mask_notifier *kimn;

#ifdef XXX
	rcu_read_lock();
#else
	XXX_KVM_SYNC_PROBE;
#endif

	for (kimn = list_head(&kvm->mask_notifier_list); kimn;
	     kimn = list_next(&kvm->mask_notifier_list, kimn))
		if (kimn->irq == irq)
			kimn->func(kimn, mask);
#ifdef XXX
	rcu_read_unlock();
#else
	XXX_KVM_SYNC_PROBE;
#endif /*XXX*/
}


static void ioapic_write_indirect(struct kvm_ioapic *ioapic, uint32_t val)
{
	unsigned index;
	int mask_before, mask_after;
	union kvm_ioapic_redirect_entry *e;

	switch (ioapic->ioregsel) {
	case IOAPIC_REG_VERSION:
		/* Writes are ignored. */
		break;

	case IOAPIC_REG_APIC_ID:
		ioapic->id = (val >> 24) & 0xf;
		break;

	case IOAPIC_REG_ARB_ID:
		break;

	default:
		index = (ioapic->ioregsel - 0x10) >> 1;

		if (index >= IOAPIC_NUM_PINS)
			return;
		e = &ioapic->redirtbl[index];
		mask_before = e->fields.mask;
		if (ioapic->ioregsel & 1) {
			e->bits &= 0xffffffff;
			e->bits |= (uint64_t) val << 32;
		} else {
			e->bits &= ~0xffffffffULL;
			e->bits |= (uint32_t) val;
			e->fields.remote_irr = 0;
		}
		update_handled_vectors(ioapic);
		mask_after = e->fields.mask;
		if (mask_before != mask_after)
			kvm_fire_mask_notifiers(ioapic->kvm, index, mask_after);
		if (e->fields.trig_mode == IOAPIC_LEVEL_TRIG
		    && ioapic->irr & (1 << index))
			ioapic_service(ioapic, index);
		break;
	}
}

int kvm_ioapic_set_irq(struct kvm_ioapic *ioapic, int irq, int level)
{
	uint32_t old_irr = ioapic->irr;
	uint32_t mask = 1 << irq;
	union kvm_ioapic_redirect_entry entry;
	int ret = 1;

	mutex_enter(&ioapic->lock);
	if (irq >= 0 && irq < IOAPIC_NUM_PINS) {
		entry = ioapic->redirtbl[irq];
		level ^= entry.fields.polarity;
		if (!level)
			ioapic->irr &= ~mask;
		else {
			int edge = (entry.fields.trig_mode == IOAPIC_EDGE_TRIG);
			ioapic->irr |= mask;
			if ((edge && old_irr != ioapic->irr) ||
			    (!edge && !entry.fields.remote_irr))
				ret = ioapic_service(ioapic, irq);
			else
				ret = 0; /* report coalesced interrupt */
		}
#ifdef XXX_KVM_TRACE
		trace_kvm_ioapic_set_irq(entry.bits, irq, ret == 0);
#endif /*XXX*/
	}
	mutex_exit(&ioapic->lock);

	return ret;
}

static void __kvm_ioapic_update_eoi(struct kvm_ioapic *ioapic, int vector,
				     int trigger_mode)
{
	int i;

	for (i = 0; i < IOAPIC_NUM_PINS; i++) {
		union kvm_ioapic_redirect_entry *ent = &ioapic->redirtbl[i];

		if (ent->fields.vector != vector)
			continue;

		/*
		 * We are dropping lock while calling ack notifiers because ack
		 * notifier callbacks for assigned devices call into IOAPIC
		 * recursively. Since remote_irr is cleared only after call
		 * to notifiers if the same vector will be delivered while lock
		 * is dropped it will be put into irr and will be delivered
		 * after ack notifier returns.
		 */
		mutex_exit(&ioapic->lock);
		kvm_notify_acked_irq(ioapic->kvm, KVM_IRQCHIP_IOAPIC, i);
		mutex_enter(&ioapic->lock);

		if (trigger_mode != IOAPIC_LEVEL_TRIG)
			continue;

		ASSERT(ent->fields.trig_mode == IOAPIC_LEVEL_TRIG);
		ent->fields.remote_irr = 0;
		if (!ent->fields.mask && (ioapic->irr & (1 << i)))
			ioapic_service(ioapic, i);
	}
}

void kvm_ioapic_update_eoi(struct kvm *kvm, int vector, int trigger_mode)
{
	struct kvm_ioapic *ioapic = kvm->arch.vioapic;

#ifdef XXX
	smp_rmb();
#else
	XXX_KVM_SYNC_PROBE;
#endif /*XXX*/
	if (!test_bit(vector, ioapic->handled_vectors))
		return;
	mutex_enter(&ioapic->lock);
	__kvm_ioapic_update_eoi(ioapic, vector, trigger_mode);
	mutex_exit(&ioapic->lock);
}

static inline struct kvm_ioapic *
to_ioapic(struct kvm_io_device *dev)
{
#ifdef XXX_KVM_DOESNTCOMPILE
	return container_of(dev, struct kvm_ioapic, dev);
#else
	return (struct kvm_ioapic *)(((caddr_t)dev) -
	    offsetof(struct kvm_ioapic, dev));
#endif /*XXX*/
}

static inline int ioapic_in_range(struct kvm_ioapic *ioapic, gpa_t addr)
{
	return ((addr >= ioapic->base_address &&
		 (addr < ioapic->base_address + IOAPIC_MEM_LENGTH)));
}

static int ioapic_mmio_read(struct kvm_io_device *this, gpa_t addr, int len,
			    void *val)
{
	struct kvm_ioapic *ioapic = to_ioapic(this);
	uint32_t result;
	if (!ioapic_in_range(ioapic, addr))
		return -EOPNOTSUPP;

	ASSERT(!(addr & 0xf));	/* check alignment */

	addr &= 0xff;
	mutex_enter(&ioapic->lock);
	switch (addr) {
	case IOAPIC_REG_SELECT:
		result = ioapic->ioregsel;
		break;

	case IOAPIC_REG_WINDOW:
		result = ioapic_read_indirect(ioapic, addr, len);
		break;

	default:
		result = 0;
		break;
	}
	mutex_exit(&ioapic->lock);

	switch (len) {
	case 8:
		*(uint64_t *) val = result;
		break;
	case 1:
	case 2:
	case 4:
		memcpy(val, (char *)&result, len);
		break;
	default:
		cmn_err(CE_WARN, "ioapic: wrong length %d\n", len);
	}
	return (0);
}

static int ioapic_mmio_write(struct kvm_io_device *this, gpa_t addr, int len,
			     const void *val)
{
	struct kvm_ioapic *ioapic = to_ioapic(this);
	uint32_t data;
	if (!ioapic_in_range(ioapic, addr))
		return -EOPNOTSUPP;

	ASSERT(!(addr & 0xf));	/* check alignment */

	if (len == 4 || len == 8)
		data = *(uint32_t *) val;
	else {
		return (0);
	}

	addr &= 0xff;
	mutex_enter(&ioapic->lock);
	switch (addr) {
	case IOAPIC_REG_SELECT:
		ioapic->ioregsel = data;
		break;

	case IOAPIC_REG_WINDOW:
		ioapic_write_indirect(ioapic, data);
		break;
#ifdef	CONFIG_IA64
	case IOAPIC_REG_EOI:
		__kvm_ioapic_update_eoi(ioapic, data, IOAPIC_LEVEL_TRIG);
		break;
#endif

	default:
		break;
	}
	mutex_exit(&ioapic->lock);
	return (0);
}

void kvm_ioapic_reset(struct kvm_ioapic *ioapic)
{
	int i;

	for (i = 0; i < IOAPIC_NUM_PINS; i++)
		ioapic->redirtbl[i].fields.mask = 1;
	ioapic->base_address = IOAPIC_DEFAULT_BASE_ADDRESS;
	ioapic->ioregsel = 0;
	ioapic->irr = 0;
	ioapic->id = 0;
	update_handled_vectors(ioapic);
}

static const struct kvm_io_device_ops ioapic_mmio_ops = {
	.read     = ioapic_mmio_read,
	.write    = ioapic_mmio_write,
};

int kvm_ioapic_init(struct kvm *kvm)
{
	struct kvm_ioapic *ioapic;
	int ret;

	ioapic = kmem_zalloc(sizeof(struct kvm_ioapic), KM_SLEEP);
	mutex_init(&ioapic->lock, NULL, MUTEX_DRIVER, 0);
	kvm->arch.vioapic = ioapic;
	kvm_ioapic_reset(ioapic);
	kvm_iodevice_init(&ioapic->dev, &ioapic_mmio_ops);
	ioapic->kvm = kvm;
	mutex_enter(&kvm->slots_lock);
	ret = kvm_io_bus_register_dev(kvm, KVM_MMIO_BUS, &ioapic->dev);
	mutex_exit(&kvm->slots_lock);
	if (ret < 0) {
		kvm->arch.vioapic = NULL;
		kmem_free(ioapic, sizeof(struct kvm_ioapic));
	}

	return ret;
}

void kvm_ioapic_destroy(struct kvm *kvm)
{
	struct kvm_ioapic *ioapic = kvm->arch.vioapic;

	if (ioapic) {
		kvm_io_bus_unregister_dev(kvm, KVM_MMIO_BUS, &ioapic->dev);
		kvm->arch.vioapic = NULL;
		kmem_free(ioapic, sizeof(struct kvm_ioapic));
	}
}

static inline int kvm_irq_line_state(unsigned long *irq_state,
				     int irq_source_id, int level)
{
	/* Logical OR for level trig interrupt */
	if (level)
		set_bit(irq_source_id, irq_state);
	else
		clear_bit(irq_source_id, irq_state);

	return !!(*irq_state);
}

void kvm_pic_update_irq(struct kvm_pic *s)
{
	mutex_enter(&s->lock);
	pic_update_irq(s);
	mutex_exit(&s->lock);
}

int kvm_pic_set_irq(void *opaque, int irq, int level)
{
	struct kvm_pic *s = opaque;
	int ret = -1;

	mutex_enter(&s->lock);
	if (irq >= 0 && irq < PIC_NUM_PINS) {
		ret = pic_set_irq1(&s->pics[irq >> 3], irq & 7, level);
		pic_update_irq(s);
#ifdef XXX_KVM_TRACE
		trace_kvm_pic_set_irq(irq >> 3, irq & 7, s->pics[irq >> 3].elcr,
				      s->pics[irq >> 3].imr, ret == 0);
#endif /*XXX*/
	}
	mutex_exit(&s->lock);

	return ret;
}


static int kvm_set_pic_irq(struct kvm_kernel_irq_routing_entry *e,
			   struct kvm *kvm, int irq_source_id, int level)
{
#ifdef CONFIG_X86
	struct kvm_pic *pic = pic_irqchip(kvm);
	level = kvm_irq_line_state(&pic->irq_states[e->irqchip.pin],
				   irq_source_id, level);
	return kvm_pic_set_irq(pic, e->irqchip.pin, level);
#else
	return -1;
#endif
}

static int kvm_set_ioapic_irq(struct kvm_kernel_irq_routing_entry *e,
			      struct kvm *kvm, int irq_source_id, int level)
{
	struct kvm_ioapic *ioapic = kvm->arch.vioapic;
	level = kvm_irq_line_state(&ioapic->irq_states[e->irqchip.pin],
				   irq_source_id, level);

	return kvm_ioapic_set_irq(ioapic, e->irqchip.pin, level);
}

static int kvm_set_msi(struct kvm_kernel_irq_routing_entry *e,
		       struct kvm *kvm, int irq_source_id, int level)
{
	struct kvm_lapic_irq irq;

	if (!level)
		return -1;

#ifdef XXX_KVM_TRACE
	trace_kvm_msi_set_irq(e->msi.address_lo, e->msi.data);
#endif /*XXX*/

	irq.dest_id = (e->msi.address_lo &
			MSI_ADDR_DEST_ID_MASK) >> MSI_ADDR_DEST_ID_SHIFT;
	irq.vector = (e->msi.data &
			MSI_DATA_VECTOR_MASK) >> MSI_DATA_VECTOR_SHIFT;
	irq.dest_mode = (1 << MSI_ADDR_DEST_MODE_SHIFT) & e->msi.address_lo;
	irq.trig_mode = (1 << MSI_DATA_TRIGGER_SHIFT) & e->msi.data;
	irq.delivery_mode = e->msi.data & 0x700;
	irq.level = 1;
	irq.shorthand = 0;

	/* TODO Deal with RH bit of MSI message address */
	return kvm_irq_delivery_to_apic(kvm, NULL, &irq);
}

static int setup_routing_entry(struct kvm_irq_routing_table *rt,
			       struct kvm_kernel_irq_routing_entry *e,
			       const struct kvm_irq_routing_entry *ue)
{
	int r = -EINVAL;
	int delta;
	unsigned max_pin;
	struct kvm_kernel_irq_routing_entry *ei;

	/*
	 * Do not allow GSI to be mapped to the same irqchip more than once.
	 * Allow only one to one mapping between GSI and MSI.
	 */
	for (ei = list_head(&rt->map[ue->gsi]); ei; ei = list_next(&rt->map[ue->gsi], ei)) {
		if (ei->type == KVM_IRQ_ROUTING_MSI ||
		    ue->u.irqchip.irqchip == ei->irqchip.irqchip)
			return r;
	}

	e->gsi = ue->gsi;
	e->type = ue->type;
	switch (ue->type) {
	case KVM_IRQ_ROUTING_IRQCHIP:
		delta = 0;
		switch (ue->u.irqchip.irqchip) {
		case KVM_IRQCHIP_PIC_MASTER:
			e->set = kvm_set_pic_irq;
			max_pin = 16;
			break;
		case KVM_IRQCHIP_PIC_SLAVE:
			e->set = kvm_set_pic_irq;
			max_pin = 16;
			delta = 8;
			break;
		case KVM_IRQCHIP_IOAPIC:
			max_pin = KVM_IOAPIC_NUM_PINS;
			e->set = kvm_set_ioapic_irq;
			break;
		default:
			goto out;
		}
		e->irqchip.irqchip = ue->u.irqchip.irqchip;
		e->irqchip.pin = ue->u.irqchip.pin + delta;
		if (e->irqchip.pin >= max_pin)
			goto out;
		rt->chip[ue->u.irqchip.irqchip][e->irqchip.pin] = ue->gsi;
		break;
	case KVM_IRQ_ROUTING_MSI:
		e->set = kvm_set_msi;
		e->msi.address_lo = ue->u.msi.address_lo;
		e->msi.address_hi = ue->u.msi.address_hi;
		e->msi.data = ue->u.msi.data;
		break;
	default:
		goto out;
	}

	list_insert_head(&rt->map[e->gsi], e);
	r = 0;
out:
	return r;
}


int kvm_set_irq_routing(struct kvm *kvm,
			const struct kvm_irq_routing_entry *ue,
			unsigned nr,
			unsigned flags)
{
	struct kvm_irq_routing_table *new, *old;
	uint32_t i, j, nr_rt_entries = 0;
	int r;

	for (i = 0; i < nr; ++i) {
		if (ue[i].gsi >= KVM_MAX_IRQ_ROUTES)
			return -EINVAL;
		nr_rt_entries = max(nr_rt_entries, ue[i].gsi);
	}

	nr_rt_entries += 1;

#ifdef XXX
	new = kmem_zalloc(sizeof(*new) + (nr_rt_entries * sizeof(list_t))
		      + (nr * sizeof(struct kvm_kernel_irq_routing_entry)),
		      KM_SLEEP);

	new->rt_entries = (void *)&new->map[nr_rt_entries];
#else
	XXX_KVM_PROBE;
	new = kmem_zalloc(sizeof(*new), KM_SLEEP);

	for (i = 0; i < KVM_MAX_IRQ_ROUTES; i++) {
		list_create(&new->map[i], sizeof(struct kvm_kernel_irq_routing_entry),
			    offsetof(struct kvm_kernel_irq_routing_entry, link));
	}
	new->rt_entries = kmem_zalloc(sizeof(struct kvm_kernel_irq_routing_entry)*nr, KM_SLEEP);

#endif /*XXX*/

	new->nr_rt_entries = nr_rt_entries;
	for (i = 0; i < 3; i++)
		for (j = 0; j < KVM_IOAPIC_NUM_PINS; j++)
			new->chip[i][j] = -1;

	for (i = 0; i < nr; ++i) {
		r = -EINVAL;
		if (ue->flags)
			goto out;
		r = setup_routing_entry(new, (struct kvm_kernel_irq_routing_entry *)((caddr_t) new->rt_entries+(i*sizeof(struct kvm_kernel_irq_routing_entry))), ue);
		if (r)
			goto out;
		++ue;
	}

	mutex_enter(&kvm->irq_lock);
	old = kvm->irq_routing;
#ifdef XXX
	rcu_assign_pointer(kvm->irq_routing, new);
#else
	XXX_KVM_SYNC_PROBE;
	kvm->irq_routing = new;
#endif /*XXX*/
	mutex_exit(&kvm->irq_lock);
#ifdef XXX
	synchronize_rcu();
#else
	XXX_KVM_SYNC_PROBE;
#endif /*XXX*/

	new = old;
	r = 0;

out:
	if (new) {
		if (new->rt_entries)
			kmem_free(new->rt_entries, sizeof(struct kvm_kernel_irq_routing_entry)*nr);
		kmem_free(new, sizeof(*new));
	}
	return r;
}

#define	IOAPIC_ROUTING_ENTRY(irq) \
	{ .gsi = irq, .type = KVM_IRQ_ROUTING_IRQCHIP,	\
	  .u.irqchip.irqchip = KVM_IRQCHIP_IOAPIC, .u.irqchip.pin = (irq) }
#define	ROUTING_ENTRY1(irq) IOAPIC_ROUTING_ENTRY(irq)

#ifdef CONFIG_X86
#  define PIC_ROUTING_ENTRY(irq) \
	{ .gsi = irq, .type = KVM_IRQ_ROUTING_IRQCHIP,	\
	  .u.irqchip.irqchip = SELECT_PIC(irq), .u.irqchip.pin = (irq) % 8 }
#  define ROUTING_ENTRY2(irq) \
	IOAPIC_ROUTING_ENTRY(irq), PIC_ROUTING_ENTRY(irq)
#else
#  define ROUTING_ENTRY2(irq) \
	IOAPIC_ROUTING_ENTRY(irq)
#endif

static const struct kvm_irq_routing_entry default_routing[] = {
	ROUTING_ENTRY2(0), ROUTING_ENTRY2(1),
	ROUTING_ENTRY2(2), ROUTING_ENTRY2(3),
	ROUTING_ENTRY2(4), ROUTING_ENTRY2(5),
	ROUTING_ENTRY2(6), ROUTING_ENTRY2(7),
	ROUTING_ENTRY2(8), ROUTING_ENTRY2(9),
	ROUTING_ENTRY2(10), ROUTING_ENTRY2(11),
	ROUTING_ENTRY2(12), ROUTING_ENTRY2(13),
	ROUTING_ENTRY2(14), ROUTING_ENTRY2(15),
	ROUTING_ENTRY1(16), ROUTING_ENTRY1(17),
	ROUTING_ENTRY1(18), ROUTING_ENTRY1(19),
	ROUTING_ENTRY1(20), ROUTING_ENTRY1(21),
	ROUTING_ENTRY1(22), ROUTING_ENTRY1(23),
#ifdef CONFIG_IA64
	ROUTING_ENTRY1(24), ROUTING_ENTRY1(25),
	ROUTING_ENTRY1(26), ROUTING_ENTRY1(27),
	ROUTING_ENTRY1(28), ROUTING_ENTRY1(29),
	ROUTING_ENTRY1(30), ROUTING_ENTRY1(31),
	ROUTING_ENTRY1(32), ROUTING_ENTRY1(33),
	ROUTING_ENTRY1(34), ROUTING_ENTRY1(35),
	ROUTING_ENTRY1(36), ROUTING_ENTRY1(37),
	ROUTING_ENTRY1(38), ROUTING_ENTRY1(39),
	ROUTING_ENTRY1(40), ROUTING_ENTRY1(41),
	ROUTING_ENTRY1(42), ROUTING_ENTRY1(43),
	ROUTING_ENTRY1(44), ROUTING_ENTRY1(45),
	ROUTING_ENTRY1(46), ROUTING_ENTRY1(47),
#endif
};

int kvm_setup_default_irq_routing(struct kvm *kvm)
{
	return kvm_set_irq_routing(kvm, default_routing,
				   ARRAY_SIZE(default_routing), 0);
}

static int kvm_vm_ioctl_set_identity_map_addr(struct kvm *kvm,
					      uint64_t ident_addr)
{
	kvm->arch.ept_identity_map_addr = ident_addr;
	return (0);
}

int kvm_request_irq_source_id(struct kvm *kvm)
{
	unsigned long *bitmap = &kvm->arch.irq_sources_bitmap;
	int irq_source_id;

	mutex_enter(&kvm->irq_lock);
	irq_source_id = find_first_zero_bit(bitmap, 64);

	if (irq_source_id >= 64) {
		irq_source_id = -EFAULT;
		goto unlock;
	}

	ASSERT(irq_source_id != KVM_USERSPACE_IRQ_SOURCE_ID);
	set_bit(irq_source_id, bitmap);
unlock:
	mutex_exit(&kvm->irq_lock);

	return irq_source_id;
}

void
kvm_timer_fire(void *arg)
{
	struct kvm_timer *timer = (struct kvm_timer *)arg;
	struct kvm_vcpu *vcpu = timer->vcpu;

	if (vcpu == NULL)
		return;

	mutex_enter(&vcpu->kvcpu_timer_lock);

	if (timer->reinject || !timer->pending) {
		atomic_add_32(&timer->pending, 1);
		set_bit(KVM_REQ_PENDING_TIMER, &vcpu->requests);
	}

	timer->intervals++;

	cv_broadcast(&vcpu->kvcpu_timer_cv);

	mutex_exit(&vcpu->kvcpu_timer_lock);
}

static void kvm_pit_ack_irq(struct kvm_irq_ack_notifier *kian)
{
	struct kvm_kpit_state *ps = (struct kvm_kpit_state *)(((caddr_t)kian) -
				     offsetof(struct kvm_kpit_state,
					      irq_ack_notifier));
	mutex_enter(&ps->inject_lock);
	if (--ps->pit_timer.pending < 0)
		ps->pit_timer.pending++;
	ps->irq_ack = 1;
	mutex_exit(&ps->inject_lock);
}

static int64_t
__kpit_elapsed(struct kvm *kvm)
{
	int64_t elapsed;
	hrtime_t remaining, now;
	struct kvm_kpit_state *ps = &kvm->arch.vpit->pit_state;

	if (!ps->pit_timer.period)
		return (0);

	/*
	 * The Counter does not stop when it reaches zero. In
	 * Modes 0, 1, 4, and 5 the Counter ``wraps around'' to
	 * the highest count, either FFFF hex for binary counting
	 * or 9999 for BCD counting, and continues counting.
	 * Modes 2 and 3 are periodic; the Counter reloads
	 * itself with the initial count and continues counting
	 * from there.
	 */
	now = gethrtime();
	elapsed = now - ps->pit_timer.start -
	    ps->pit_timer.period * ps->pit_timer.intervals;
	remaining = ps->pit_timer.period - elapsed;
	elapsed = mod_64(elapsed, ps->pit_timer.period);

	return (elapsed);
}

static int64_t kpit_elapsed(struct kvm *kvm, struct kvm_kpit_channel_state *c,
			int channel)
{
	if (channel == 0)
		return __kpit_elapsed(kvm);

	return gethrtime() - c->count_load_time;
}

static uint64_t muldiv64(uint64_t a, uint32_t b, uint32_t c)
{
	union {
		uint64_t ll;
		struct {
			uint32_t low, high;
		} l;
	} u, res;
	uint64_t rl, rh;

	u.ll = a;
	rl = (uint64_t)u.l.low * (uint64_t)b;
	rh = (uint64_t)u.l.high * (uint64_t)b;
	rh += (rl >> 32);
	res.l.high = rh/c;
	res.l.low = ((mod_64(rh, c) << 32) + (rl & 0xffffffff))/ c;
	return res.ll;
}

static int pit_get_count(struct kvm *kvm, int channel)
{
	struct kvm_kpit_channel_state *c =
		&kvm->arch.vpit->pit_state.channels[channel];
	int64_t d, t;
	int counter;

	ASSERT(mutex_owned(&kvm->arch.vpit->pit_state.lock));

	t = kpit_elapsed(kvm, c, channel);
	d = muldiv64(t, KVM_PIT_FREQ, NSEC_PER_SEC);

	switch (c->mode) {
	case 0:
	case 1:
	case 4:
	case 5:
		counter = (c->count - d) & 0xffff;
		break;
	case 3:
		/* XXX: may be incorrect for odd counts */
		counter = c->count - (mod_64((2 * d), c->count));
		break;
	default:
		counter = c->count - mod_64(d, c->count);
		break;
	}
	return counter;
}

static int pit_get_out(struct kvm *kvm, int channel)
{
	struct kvm_kpit_channel_state *c =
		&kvm->arch.vpit->pit_state.channels[channel];
	int64_t d, t;
	int out;

	ASSERT(mutex_owned(&kvm->arch.vpit->pit_state.lock));

	t = kpit_elapsed(kvm, c, channel);
	d = muldiv64(t, KVM_PIT_FREQ, NSEC_PER_SEC);

	switch (c->mode) {
	default:
	case 0:
		out = (d >= c->count);
		break;
	case 1:
		out = (d < c->count);
		break;
	case 2:
		out = ((mod_64(d, c->count) == 0) && (d != 0));
		break;
	case 3:
		out = (mod_64(d, c->count) < ((c->count + 1) >> 1));
		break;
	case 4:
	case 5:
		out = (d == c->count);
		break;
	}

	return out;
}

static void pit_latch_count(struct kvm *kvm, int channel)
{
	struct kvm_kpit_channel_state *c =
		&kvm->arch.vpit->pit_state.channels[channel];

	ASSERT(mutex_owned(&kvm->arch.vpit->pit_state.lock));

	if (!c->count_latched) {
		c->latched_count = pit_get_count(kvm, channel);
		c->count_latched = c->rw_mode;
	}
}

static void pit_latch_status(struct kvm *kvm, int channel)
{
	struct kvm_kpit_channel_state *c =
		&kvm->arch.vpit->pit_state.channels[channel];

	ASSERT(mutex_owned(&kvm->arch.vpit->pit_state.lock));

	if (!c->status_latched) {
		/* TODO: Return NULL COUNT (bit 6). */
		c->status = ((pit_get_out(kvm, channel) << 7) |
				(c->rw_mode << 4) |
				(c->mode << 1) |
				c->bcd);
		c->status_latched = 1;
	}
}

static struct kvm_pit *dev_to_pit(struct kvm_io_device *dev)
{
#ifdef XXX_KVM_DOESNTCOMPILE
	return container_of(dev, struct kvm_pit, dev);
#else
	return (struct kvm_pit *)(((caddr_t)dev) -
	    offsetof(struct kvm_pit, dev));
#endif /*XXX_KVM_DOESNTCOMPILE*/
}

static int pit_in_range(gpa_t addr)
{
	return ((addr >= KVM_PIT_BASE_ADDRESS) &&
		(addr < KVM_PIT_BASE_ADDRESS + KVM_PIT_MEM_LENGTH));
}

static int pit_ioport_read(struct kvm_io_device *this,
			   gpa_t addr, int len, void *data)
{
	struct kvm_pit *pit = dev_to_pit(this);
	struct kvm_kpit_state *pit_state = &pit->pit_state;
	struct kvm *kvm = pit->kvm;
	int ret, count;
	struct kvm_kpit_channel_state *s;
	if (!pit_in_range(addr))
		return -EOPNOTSUPP;

	addr &= KVM_PIT_CHANNEL_MASK;
	if (addr == 3)
		return (0);

	s = &pit_state->channels[addr];

	mutex_enter(&pit_state->lock);

	if (s->status_latched) {
		s->status_latched = 0;
		ret = s->status;
	} else if (s->count_latched) {
		switch (s->count_latched) {
		default:
		case RW_STATE_LSB:
			ret = s->latched_count & 0xff;
			s->count_latched = 0;
			break;
		case RW_STATE_MSB:
			ret = s->latched_count >> 8;
			s->count_latched = 0;
			break;
		case RW_STATE_WORD0:
			ret = s->latched_count & 0xff;
			s->count_latched = RW_STATE_MSB;
			break;
		}
	} else {
		switch (s->read_state) {
		default:
		case RW_STATE_LSB:
			count = pit_get_count(kvm, addr);
			ret = count & 0xff;
			break;
		case RW_STATE_MSB:
			count = pit_get_count(kvm, addr);
			ret = (count >> 8) & 0xff;
			break;
		case RW_STATE_WORD0:
			count = pit_get_count(kvm, addr);
			ret = count & 0xff;
			s->read_state = RW_STATE_WORD1;
			break;
		case RW_STATE_WORD1:
			count = pit_get_count(kvm, addr);
			ret = (count >> 8) & 0xff;
			s->read_state = RW_STATE_WORD0;
			break;
		}
	}

	if (len > sizeof(ret))
		len = sizeof(ret);
	memcpy(data, (char *)&ret, len);

	mutex_exit(&pit_state->lock);
	return (0);
}

static void destroy_pit_timer(struct kvm_timer *pt)
{
#ifdef XXX
	pr_debug("pit: " "execute del timer!\n");
	hrtimer_cancel_p(&pt->timer);
#else
	XXX_KVM_PROBE;
#endif /*XXX*/
}

static int kpit_is_periodic(struct kvm_timer *ktimer)
{
	struct kvm_kpit_state *ps = (struct kvm_kpit_state *)(((caddr_t)ktimer)
							 - offsetof(struct kvm_kpit_state,
								    pit_timer));
	return ps->is_periodic;
}

static struct kvm_timer_ops kpit_ops = {
	.is_periodic = kpit_is_periodic,
};

static void
create_pit_timer(struct kvm_kpit_state *ps, uint32_t val, int is_period)
{
	struct kvm_timer *pt = &ps->pit_timer;
	int64_t interval;

	interval = muldiv64(val, NSEC_PER_SEC, KVM_PIT_FREQ);

	mutex_enter(&cpu_lock);
	/* TODO The new value only affected after the retriggered */
	if (pt->active) {
		cyclic_remove(pt->kvm_cyclic_id);
		pt->active = 0;
	}
	pt->period = interval;
	ps->is_periodic = is_period;

	pt->kvm_cyc_handler.cyh_func = kvm_timer_fire;
	pt->kvm_cyc_handler.cyh_level = CY_LOW_LEVEL;
	pt->kvm_cyc_handler.cyh_arg = pt;
	pt->t_ops = &kpit_ops;
	pt->kvm = ps->pit->kvm;
	pt->vcpu = pt->kvm->bsp_vcpu;

	pt->pending = 0;  /*XXX need protection?*/
	ps->irq_ack = 1;
	pt->start = gethrtime();

	if (is_period) {
		pt->kvm_cyc_when.cyt_when = pt->start + pt->period;
		pt->kvm_cyc_when.cyt_interval = pt->period;
	} else {
		pt->kvm_cyc_when.cyt_when = pt->start + pt->period;
		pt->kvm_cyc_when.cyt_when = CY_INFINITY;
	}
	pt->kvm_cyclic_id = cyclic_add(&pt->kvm_cyc_handler, &pt->kvm_cyc_when);
	pt->intervals = 0;
	pt->active = 1;
	mutex_exit(&cpu_lock);
}

static void pit_load_count(struct kvm *kvm, int channel, uint32_t val)
{
	struct kvm_kpit_state *ps = &kvm->arch.vpit->pit_state;

	ASSERT(mutex_owned(&ps->lock));

#ifdef KVM_DEBUG
	cmn_err(CE_NOTE, "pit: load_count val is %d, channel is %d\n", val, channel);
#endif

	/*
	 * The largest possible initial count is 0; this is equivalent
	 * to 216 for binary counting and 104 for BCD counting.
	 */
	if (val == 0)
		val = 0x10000;

	ps->channels[channel].count = val;

	if (channel != 0) {
		ps->channels[channel].count_load_time = gethrtime();
		return;
	}

	/* Two types of timer
	 * mode 1 is one shot, mode 2 is period, otherwise del timer */
	switch (ps->channels[0].mode) {
	case 0:
	case 1:
        /* FIXME: enhance mode 4 precision */
	case 4:
		if (!(ps->flags & KVM_PIT_FLAGS_HPET_LEGACY)) {
			create_pit_timer(ps, val, 0);
		}
		break;
	case 2:
	case 3:
		if (!(ps->flags & KVM_PIT_FLAGS_HPET_LEGACY)){
			create_pit_timer(ps, val, 1);
		}
		break;
	default:
		destroy_pit_timer(&ps->pit_timer);
	}
}

static int pit_ioport_write(struct kvm_io_device *this,
			    gpa_t addr, int len, const void *data)
{
	struct kvm_pit *pit = dev_to_pit(this);
	struct kvm_kpit_state *pit_state = &pit->pit_state;
	struct kvm *kvm = pit->kvm;
	int channel, access;
	struct kvm_kpit_channel_state *s;
	uint32_t val = *(uint32_t *) data;
	if (!pit_in_range(addr))
		return -EOPNOTSUPP;

	val  &= 0xff;
	addr &= KVM_PIT_CHANNEL_MASK;

	mutex_enter(&pit_state->lock);

#ifdef KVM_DEBUG
	if (val != 0)
		pr_debug("pit: " "write addr is 0x%x, len is %d, val is 0x%x\n",
			 (unsigned int)addr, len, val);
#endif

	if (addr == 3) {
		channel = val >> 6;
		if (channel == 3) {
			/* Read-Back Command. */
			for (channel = 0; channel < 3; channel++) {
				s = &pit_state->channels[channel];
				if (val & (2 << channel)) {
					if (!(val & 0x20))
						pit_latch_count(kvm, channel);
					if (!(val & 0x10))
						pit_latch_status(kvm, channel);
				}
			}
		} else {
			/* Select Counter <channel>. */
			s = &pit_state->channels[channel];
			access = (val >> 4) & KVM_PIT_CHANNEL_MASK;
			if (access == 0) {
				pit_latch_count(kvm, channel);
			} else {
				s->rw_mode = access;
				s->read_state = access;
				s->write_state = access;
				s->mode = (val >> 1) & 7;
				if (s->mode > 5)
					s->mode -= 4;
				s->bcd = val & 1;
			}
		}
	} else {
		/* Write Count. */
		s = &pit_state->channels[addr];
		switch (s->write_state) {
		default:
		case RW_STATE_LSB:
			pit_load_count(kvm, addr, val);
			break;
		case RW_STATE_MSB:
			pit_load_count(kvm, addr, val << 8);
			break;
		case RW_STATE_WORD0:
			s->write_latch = val;
			s->write_state = RW_STATE_WORD1;
			break;
		case RW_STATE_WORD1:
			pit_load_count(kvm, addr, s->write_latch | (val << 8));
			s->write_state = RW_STATE_WORD0;
			break;
		}
	}

	mutex_exit(&pit_state->lock);
	return (0);
}

static const struct kvm_io_device_ops pit_dev_ops = {
	.read     = pit_ioport_read,
	.write    = pit_ioport_write,
};

void kvm_pit_reset(struct kvm_pit *pit)
{
	int i;
	struct kvm_kpit_channel_state *c;

	mutex_enter(&pit->pit_state.lock);
	pit->pit_state.flags = 0;
	for (i = 0; i < 3; i++) {
		c = &pit->pit_state.channels[i];
		c->mode = 0xff;
		c->gate = (i != 2);
		pit_load_count(pit->kvm, i, 0);
	}
	mutex_exit(&pit->pit_state.lock);

	pit->pit_state.pit_timer.pending =  0; /*XXX need protection?*/
	pit->pit_state.irq_ack = 1;
}


void kvm_register_irq_ack_notifier(struct kvm *kvm,
				   struct kvm_irq_ack_notifier *kian)
{
	mutex_enter(&kvm->irq_lock);
	list_insert_head(&kvm->irq_ack_notifier_list, kian);
	mutex_exit(&kvm->irq_lock);
}

void
kvm_unregister_irq_ack_notifier(struct kvm *kvm,
   struct kvm_irq_ack_notifier *kian)
{
	mutex_enter(&kvm->irq_lock);
	list_remove(&kvm->irq_ack_notifier_list, kian);
	mutex_exit(&kvm->irq_lock);
}

static void pit_mask_notifer(struct kvm_irq_mask_notifier *kimn, int mask)
{
	struct kvm_pit *pit = (struct kvm_pit *)(((caddr_t)kimn)
					  - offsetof(struct kvm_pit,
						     mask_notifier));
	if (!mask) {
#ifdef XXX
		atomic_set(&pit->pit_state.pit_timer.pending, 0);
#else
		pit->pit_state.pit_timer.pending = 0;
		XXX_KVM_PROBE;
#endif /*XXX*/
		pit->pit_state.irq_ack = 1;
	}
}

void kvm_register_irq_mask_notifier(struct kvm *kvm, int irq,
				    struct kvm_irq_mask_notifier *kimn)
{
	mutex_enter(&kvm->irq_lock);
	kimn->irq = irq;
	list_insert_head(&kvm->mask_notifier_list, kimn);
	mutex_exit(&kvm->irq_lock);
}

void
kvm_unregister_irq_mask_notifier(struct kvm *kvm, int irq,
    struct kvm_irq_mask_notifier *kimn)
{
	mutex_enter(&kvm->irq_lock);
	list_remove(&kvm->mask_notifier_list, kimn);
	mutex_exit(&kvm->irq_lock);
}

static struct kvm_pit *speaker_to_pit(struct kvm_io_device *dev)
{
	struct kvm_pit *pit = (struct kvm_pit *)(((caddr_t)dev)
						 - offsetof(struct kvm_pit,
							    speaker_dev));
	return pit;
}

static int pit_get_gate(struct kvm *kvm, int channel)
{
	ASSERT(mutex_owned(&kvm->arch.vpit->pit_state.lock));

	return kvm->arch.vpit->pit_state.channels[channel].gate;
}

static int speaker_ioport_read(struct kvm_io_device *this,
			       gpa_t addr, int len, void *data)
{
	struct kvm_pit *pit = speaker_to_pit(this);
	struct kvm_kpit_state *pit_state = &pit->pit_state;
	struct kvm *kvm = pit->kvm;
	unsigned int refresh_clock;
	int ret;
	if (addr != KVM_SPEAKER_BASE_ADDRESS)
		return -EOPNOTSUPP;

	/* Refresh clock toggles at about 15us. We approximate as 2^14ns. */
#ifdef XXX
	refresh_clock = ((unsigned int)ktime_to_ns(ktime_get()) >> 14) & 1;
#else
	refresh_clock = ((unsigned int)gethrtime() >> 14) &1;
	XXX_KVM_PROBE;
#endif /* XXX */

	mutex_enter(&pit_state->lock);
	ret = ((pit_state->speaker_data_on << 1) | pit_get_gate(kvm, 2) |
		(pit_get_out(kvm, 2) << 5) | (refresh_clock << 4));
	if (len > sizeof(ret))
		len = sizeof(ret);
	memcpy(data, (char *)&ret, len);
	mutex_exit(&pit_state->lock);
	return (0);
}

static void pit_set_gate(struct kvm *kvm, int channel, uint32_t val)
{
	struct kvm_kpit_channel_state *c =
		&kvm->arch.vpit->pit_state.channels[channel];

	ASSERT(mutex_owned(&kvm->arch.vpit->pit_state.lock));

	switch (c->mode) {
	default:
	case 0:
	case 4:
		/* XXX: just disable/enable counting */
		break;
	case 1:
	case 2:
	case 3:
	case 5:
		/* Restart counting on rising edge. */
#ifdef XXX
		if (c->gate < val)
			c->count_load_time = ktime_get();
#else
		if (c->gate < val)
			c->count_load_time = gethrtime();
		XXX_KVM_PROBE;
#endif /* XXX */
		break;
	}

	c->gate = val;
}

static int speaker_ioport_write(struct kvm_io_device *this,
				gpa_t addr, int len, const void *data)
{
	struct kvm_pit *pit = speaker_to_pit(this);
	struct kvm_kpit_state *pit_state = &pit->pit_state;
	struct kvm *kvm = pit->kvm;
	uint32_t val = *(uint32_t *) data;
	if (addr != KVM_SPEAKER_BASE_ADDRESS)
		return -EOPNOTSUPP;

	mutex_enter(&pit_state->lock);
	pit_state->speaker_data_on = (val >> 1) & 1;
	pit_set_gate(kvm, 2, val & 1);
	mutex_exit(&pit_state->lock);
	return (0);
}

static const struct kvm_io_device_ops speaker_dev_ops = {
	.read     = speaker_ioport_read,
	.write    = speaker_ioport_write,
};

/* Caller must hold slots_lock */
struct kvm_pit *kvm_create_pit(struct kvm *kvm, uint32_t flags)
{
	struct kvm_pit *pit;
	struct kvm_kpit_state *pit_state;
	int ret;

	pit = kmem_zalloc(sizeof(struct kvm_pit), KM_SLEEP);

	pit->irq_source_id = kvm_request_irq_source_id(kvm);
	if (pit->irq_source_id < 0) {
		kmem_free(pit, sizeof(struct kvm_pit));
		return NULL;
	}

	mutex_init(&pit->pit_state.lock, NULL, MUTEX_DRIVER, 0);
	mutex_enter(&pit->pit_state.lock);
#ifdef XXX
	raw_spin_lock_init(&pit->pit_state.inject_lock);
#else
	XXX_KVM_SYNC_PROBE;
	mutex_init(&pit->pit_state.inject_lock, NULL, MUTEX_DRIVER, 0);
#endif /*XXX*/
	kvm->arch.vpit = pit;
	pit->kvm = kvm;

	pit_state = &pit->pit_state;
	pit_state->pit = pit;
#ifdef XXX
	hrtimer_init(&pit_state->pit_timer.timer,
		     CLOCK_MONOTONIC, HRTIMER_MODE_ABS);
#else
	XXX_KVM_PROBE;
#endif /*XXX*/
	pit_state->irq_ack_notifier.gsi = 0;
	pit_state->irq_ack_notifier.irq_acked = kvm_pit_ack_irq;

	kvm_register_irq_ack_notifier(kvm, &pit_state->irq_ack_notifier);

	pit_state->pit_timer.reinject = 1;
	pit_state->pit_timer.active = 0;

	mutex_exit(&pit->pit_state.lock);

	kvm_pit_reset(pit);

	pit->mask_notifier.func = pit_mask_notifer;
	kvm_register_irq_mask_notifier(kvm, 0, &pit->mask_notifier);

	kvm_iodevice_init(&pit->dev, &pit_dev_ops);
	ret = kvm_io_bus_register_dev(kvm, KVM_PIO_BUS, &pit->dev);
	if (ret < 0)
		goto fail;

	if (flags & KVM_PIT_SPEAKER_DUMMY) {
		kvm_iodevice_init(&pit->speaker_dev, &speaker_dev_ops);
		ret = kvm_io_bus_register_dev(kvm, KVM_PIO_BUS,
						&pit->speaker_dev);
		if (ret < 0)
			goto fail_unregister;
	}
	return pit;

fail_unregister:
#ifdef XXX
	kvm_io_bus_unregister_dev(kvm, KVM_PIO_BUS, &pit->dev);
#else
	XXX_KVM_PROBE;
#endif /*XXX*/
fail:
#ifdef XXX
	kvm_unregister_irq_mask_notifier(kvm, 0, &pit->mask_notifier);
	kvm_unregister_irq_ack_notifier(kvm, &pit_state->irq_ack_notifier);
	kvm_free_irq_source_id(kvm, pit->irq_source_id);
	kmem_free(pit, sizeof(struct kvm_pit));
#else
	XXX_KVM_PROBE;
#endif /*XXX*/
	return NULL;
}

void
kvm_apic_post_state_restore(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;

	apic->base_address = vcpu->arch.apic_base &
	    MSR_IA32_APICBASE_BASE;
	kvm_apic_set_version(vcpu);

	apic_update_ppr(apic);
	mutex_enter(&cpu_lock);
	if (apic->lapic_timer.active)
		cyclic_remove(apic->lapic_timer.kvm_cyclic_id);
	apic->lapic_timer.active = 0;
	mutex_exit(&cpu_lock);
	update_divide_count(apic);
	start_apic_timer(apic);
	apic->irr_pending = 1;
}

static int kvm_vcpu_ioctl_get_lapic(struct kvm_vcpu *vcpu,
				    struct kvm_lapic_state *s)
{
	vcpu_load(vcpu);
	bcopy(vcpu->arch.apic->regs, s->regs, sizeof *s);
	vcpu_put(vcpu);

	return (0);
}

static int kvm_vcpu_ioctl_set_lapic(struct kvm_vcpu *vcpu,
				    struct kvm_lapic_state *s)
{
	vcpu_load(vcpu);
	bcopy(s->regs, vcpu->arch.apic->regs, sizeof *s);
	kvm_apic_post_state_restore(vcpu);
	update_cr8_intercept(vcpu);
	vcpu_put(vcpu);

	return (0);
}

int kvm_get_ioapic(struct kvm *kvm, struct kvm_ioapic_state *state)
{
	struct kvm_ioapic *ioapic = ioapic_irqchip(kvm);
	if (!ioapic)
		return EINVAL;

	mutex_enter(&ioapic->lock);
	memcpy(state, ioapic, sizeof(struct kvm_ioapic_state));
	mutex_exit(&ioapic->lock);
	return (0);
}

int kvm_set_ioapic(struct kvm *kvm, struct kvm_ioapic_state *state)
{
	struct kvm_ioapic *ioapic = ioapic_irqchip(kvm);
	if (!ioapic)
		return EINVAL;

	mutex_enter(&ioapic->lock);
	memcpy(ioapic, state, sizeof(struct kvm_ioapic_state));
	update_handled_vectors(ioapic);
	mutex_exit(&ioapic->lock);
	return (0);
}

static int kvm_vm_ioctl_get_irqchip(struct kvm *kvm, struct kvm_irqchip *chip)
{
	int r;

	r = 0;
	switch (chip->chip_id) {
	case KVM_IRQCHIP_PIC_MASTER:
		memcpy(&chip->chip.pic,
			&pic_irqchip(kvm)->pics[0],
			sizeof(struct kvm_pic_state));
		break;
	case KVM_IRQCHIP_PIC_SLAVE:
		memcpy(&chip->chip.pic,
			&pic_irqchip(kvm)->pics[1],
			sizeof(struct kvm_pic_state));
		break;
	case KVM_IRQCHIP_IOAPIC:
		r = kvm_get_ioapic(kvm, &chip->chip.ioapic);
		break;
	default:
		r = EINVAL;
		break;
	}
	return r;
}

static int kvm_vm_ioctl_set_irqchip(struct kvm *kvm, struct kvm_irqchip *chip)
{
	int r;

	r = 0;
	switch (chip->chip_id) {
	case KVM_IRQCHIP_PIC_MASTER:
		mutex_enter(&pic_irqchip(kvm)->lock);
		memcpy(&pic_irqchip(kvm)->pics[0],
			&chip->chip.pic,
			sizeof(struct kvm_pic_state));
		mutex_exit(&pic_irqchip(kvm)->lock);
		break;
	case KVM_IRQCHIP_PIC_SLAVE:
		mutex_enter(&pic_irqchip(kvm)->lock);
		memcpy(&pic_irqchip(kvm)->pics[1],
			&chip->chip.pic,
			sizeof(struct kvm_pic_state));
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
	return r;
}

/*
 * Return value:
 *  < 0   Interrupt was ignored (masked or not delivered for other reasons)
 *  = 0   Interrupt was coalesced (previous irq is still pending)
 *  > 0   Number of CPUs interrupt was delivered to
 */
int kvm_set_irq(struct kvm *kvm, int irq_source_id, uint32_t irq, int level)
{
	struct kvm_kernel_irq_routing_entry *e, irq_set[KVM_NR_IRQCHIPS];
	int ret = -1, i = 0;
	struct kvm_irq_routing_table *irq_rt;

	/* Not possible to detect if the guest uses the PIC or the
	 * IOAPIC.  So set the bit in both. The guest will ignore
	 * writes to the unused one.
	 */
#ifdef XXX
	rcu_read_lock();
	irq_rt = rcu_dereference(kvm->irq_routing);
#else
	XXX_KVM_SYNC_PROBE;
	irq_rt = kvm->irq_routing;
#endif /*XXX*/
	if (irq < irq_rt->nr_rt_entries) {
		for (e = list_head(&irq_rt->map[irq]); e; e = list_next(&irq_rt->map[irq], e))
			irq_set[i++] = *e;
	}
#ifdef XXX
	rcu_read_unlock();
#else
	XXX_KVM_SYNC_PROBE;
#endif /*XXX*/

	while(i--) {
		int r;
		r = irq_set[i].set(&irq_set[i], kvm, irq_source_id, level);
		if (r < 0)
			continue;

		ret = r + ((ret < 0) ? 0 : ret);
	}

	return ret;
}

static int kvm_vcpu_ioctl_interrupt(struct kvm_vcpu *vcpu,
				    struct kvm_interrupt *irq)
{
	if (irq->irq < 0 || irq->irq >= 256)
		return -EINVAL;
	if (irqchip_in_kernel(vcpu->kvm))
		return -ENXIO;
	vcpu_load(vcpu);

	kvm_queue_interrupt(vcpu, irq->irq, 0);

	vcpu_put(vcpu);

	return (0);
}

void kvm_lapic_set_vapic_addr(struct kvm_vcpu *vcpu, gpa_t vapic_addr)
{
	if (!irqchip_in_kernel(vcpu->kvm))
		return;

	vcpu->arch.apic->vapic_addr = vapic_addr;
}

static int kvm_vcpu_ioctl_x86_setup_mce(struct kvm_vcpu *vcpu,
					uint64_t mcg_cap)
{
	int rval;
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
	return rval;
}
/* END CSTYLED */

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

	case KVM_CREATE_PIT: {
		struct kvm *kvmp;

		kvmp = ksp->kds_kvmp;
		if (kvmp == NULL) {
			rval = EINVAL;
			break;
		}

		u.pit_config.flags = KVM_PIT_SPEAKER_DUMMY;
		mutex_enter(&kvmp->slots_lock);
		rval = EEXIST;
		if (kvmp->arch.vpit)
			goto create_pit_unlock;
		rval = ENOMEM;
		kvmp->arch.vpit = kvm_create_pit(kvmp, u.pit_config.flags);
		if (kvmp->arch.vpit)
			rval = 0;
	create_pit_unlock:
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
	case KVM_RUN: {
		struct kvm *kvmp;
		struct kvm_vcpu *vcpu;
		int cpu = (int)arg;

		kvmp = ksp->kds_kvmp;
		if (kvmp == NULL) {
			rval = EINVAL;
			break;
		}
		if (!kvmp || cpu >= kvmp->online_vcpus) {
			rval = EINVAL;
			break;
		}
		vcpu = kvmp->vcpus[cpu];

		rval = kvm_arch_vcpu_ioctl_run(vcpu, vcpu->run);
		break;
	}

	case KVM_X86_GET_MCE_CAP_SUPPORTED: {
		uint64_t mce_cap = KVM_MCE_CAP_SUPPORTED;

		if (copyout(&mce_cap, argp, sizeof (mce_cap)))
			rval = EFAULT;

		break;
	}

	case KVM_X86_SETUP_MCE: {
		struct mcg_cap_ioc mcg_cap_ioc;
		struct kvm *kvmp;
		struct kvm_vcpu *vcpu;

		if (copyin(argp, &mcg_cap_ioc, sizeof (mcg_cap_ioc))) {
			rval = EFAULT;
			break;
		}

		if ((kvmp = ksp->kds_kvmp) == NULL) {
			rval = EINVAL;
			break;
		}

		if (mcg_cap_ioc.kvm_cpu_index >= kvmp->online_vcpus) {
			rval = EINVAL;
			break;
		}

		vcpu = kvmp->vcpus[mcg_cap_ioc.kvm_cpu_index];
		rval = kvm_vcpu_ioctl_x86_setup_mce(vcpu, mcg_cap_ioc.mcg_cap);
		break;
	}

	case KVM_GET_MSRS: {
		struct kvm_msrs_ioc *kvm_msrs_ioc;
		struct kvm *kvmp;
		struct kvm_vcpu *vcpu;
		size_t sz = sizeof (struct kvm_msrs_ioc);

		kvm_msrs_ioc = kmem_alloc(sz, KM_SLEEP);

		if (copyin(argp, kvm_msrs_ioc, sz) != 0) {
			rval = EFAULT;
			break;
		}

		if ((kvmp = ksp->kds_kvmp) == NULL) {
			rval = EINVAL;
			break;
		}

		if (kvm_msrs_ioc->kvm_cpu_index >= kvmp->online_vcpus) {
			kmem_free(kvm_msrs_ioc, sz);
			rval = EINVAL;
			break;
		}

		vcpu = kvmp->vcpus[kvm_msrs_ioc->kvm_cpu_index];

		if (kvm_msrs_ioc->kvm_msrs.nmsrs >= MAX_IO_MSRS) {
			kmem_free(kvm_msrs_ioc, sz);
			rval = E2BIG;
			break;
		}

		if (__msr_io(vcpu, &kvm_msrs_ioc->kvm_msrs,
		    kvm_msrs_ioc->kvm_msrs.entries, kvm_get_msr) < 0) {
			kmem_free(kvm_msrs_ioc, sz);
			rval = EINVAL;
			break;
		}

		if (copyout(kvm_msrs_ioc, argp, sizeof (kvm_msrs_ioc_t) != 0)) {
			kmem_free(kvm_msrs_ioc, sz);
			rval = EFAULT;
			break;
		}

		*rv = kvm_msrs_ioc->kvm_msrs.nmsrs;
		kmem_free(kvm_msrs_ioc, sz);
		break;
	}

	case KVM_SET_MSRS: {
		struct kvm_msrs_ioc *kvm_msrs_ioc;
		struct kvm *kvmp;
		struct kvm_vcpu *vcpu;
		size_t sz = sizeof (struct kvm_msrs_ioc);
		int n;

		kvm_msrs_ioc = kmem_alloc(sz, KM_SLEEP);

		if (copyin(argp, kvm_msrs_ioc, sz) != 0) {
			rval = EFAULT;
			break;
		}

		if ((kvmp = ksp->kds_kvmp) == NULL) {
			rval = EINVAL;
			break;
		}

		if (kvm_msrs_ioc->kvm_cpu_index >= kvmp->online_vcpus) {
			kmem_free(kvm_msrs_ioc, sz);
			rval = EINVAL;
			break;
		}

		vcpu = kvmp->vcpus[kvm_msrs_ioc->kvm_cpu_index];

		if (kvm_msrs_ioc->kvm_msrs.nmsrs >= MAX_IO_MSRS) {
			kmem_free(kvm_msrs_ioc, sz);
			rval = E2BIG;
			break;
		}

		n = __msr_io(vcpu, &kvm_msrs_ioc->kvm_msrs,
		    kvm_msrs_ioc->kvm_msrs.entries, do_set_msr);

		kmem_free(kvm_msrs_ioc, sz);

		if (n < 0) {
			rval = EINVAL;
			break;
		}

		*rv = n;
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
			rval = EINVAL;
			break;
		}

		rval = kvm_vm_ioctl_set_identity_map_addr(kvmp,
		    kvm_id_map_addr_ioc->ident_addr);

		*rv = 0;
		break;
	}

	case KVM_GET_MP_STATE: {
		struct kvm_mp_state mp_state;
		struct kvm_mp_state_ioc kvm_mp_state_ioc;
		struct kvm *kvmp;
		struct kvm_vcpu *vcpu;

		if (copyin(argp, &kvm_mp_state_ioc,
		    sizeof (kvm_mp_state_ioc)) != 0) {
			rval = EFAULT;
			break;
		}

		if ((kvmp = ksp->kds_kvmp) == NULL) {
			rval = EINVAL;
			break;
		}

		if (kvm_mp_state_ioc.kvm_cpu_index >= kvmp->online_vcpus) {
			rval = EINVAL;
			break;
		}

		vcpu = kvmp->vcpus[kvm_mp_state_ioc.kvm_cpu_index];

		rval = kvm_arch_vcpu_ioctl_get_mpstate(vcpu, &mp_state);

		if (rval != 0)
			break;

		if (copyout(&mp_state, &kvm_mp_state_ioc.mp_state,
		    sizeof (struct kvm_mp_state)) != 0) {
			rval = EFAULT;
			break;
		}

		*rv = 0;
		break;
	}

	case KVM_SET_MP_STATE: {
		struct kvm_mp_state_ioc kvm_mp_state_ioc;
		struct kvm *kvmp;
		struct kvm_vcpu *vcpu;

		if (copyin(argp, &kvm_mp_state_ioc,
		    sizeof (kvm_mp_state_ioc)) != 0) {
			rval = EFAULT;
			break;
		}

		if ((kvmp = ksp->kds_kvmp) == NULL) {
			rval = EINVAL;
			break;
		}

		if (kvm_mp_state_ioc.kvm_cpu_index >= kvmp->online_vcpus) {
			rval = EINVAL;
			break;
		}

		vcpu = kvmp->vcpus[kvm_mp_state_ioc.kvm_cpu_index];

		if ((rval = kvm_arch_vcpu_ioctl_set_mpstate(vcpu,
		    &kvm_mp_state_ioc.mp_state)) != 0)
			break;

		*rv = 0;
		break;
	}

	case KVM_CREATE_VCPU: {
		uint32_t id = (uintptr_t)arg;

		rval = kvm_vm_ioctl_create_vcpu(ksp->kds_kvmp, id, rv);
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

	case KVM_GET_REGS: {
		struct kvm_regs_ioc *kvm_regs_ioc;
		struct kvm *kvmp;
		struct kvm_vcpu *vcpu;
		size_t sz = sizeof (struct kvm_regs_ioc);

		kvm_regs_ioc = kmem_zalloc(sz, KM_SLEEP);

		if (copyin(argp, kvm_regs_ioc, sz) != 0) {
			kmem_free(kvm_regs_ioc, sz);
			rval = EFAULT;
			break;
		}

		if ((kvmp = ksp->kds_kvmp) == NULL ||
		    kvm_regs_ioc->kvm_cpu_index >= kvmp->online_vcpus) {
			kmem_free(kvm_regs_ioc, sz);
			rval = EINVAL;
			break;
		}

		vcpu = kvmp->vcpus[kvm_regs_ioc->kvm_cpu_index];

		if ((rval = kvm_arch_vcpu_ioctl_get_regs(vcpu,
		    &kvm_regs_ioc->kvm_regs)) != 0) {
			kmem_free(kvm_regs_ioc, sz);
			break;
		}

		if (copyout(kvm_regs_ioc, argp, sz) != 0)
			rval = EFAULT;

		*rv = 0;
		kmem_free(kvm_regs_ioc, sz);
		break;
	}

	case KVM_SET_REGS: {
		struct kvm_regs_ioc *kvm_regs_ioc;
		struct kvm *kvmp;
		struct kvm_vcpu *vcpu;
		size_t sz = sizeof (struct kvm_regs_ioc);

		kvm_regs_ioc = kmem_zalloc(sz, KM_SLEEP);

		if (copyin(argp, kvm_regs_ioc, sz) != 0) {
			kmem_free(kvm_regs_ioc, sz);
			rval = EFAULT;
			break;
		}

		if ((kvmp = ksp->kds_kvmp) == NULL ||
		    kvm_regs_ioc->kvm_cpu_index >= kvmp->online_vcpus) {
			kmem_free(kvm_regs_ioc, sz);
			rval = EINVAL;
			break;
		}

		vcpu = kvmp->vcpus[kvm_regs_ioc->kvm_cpu_index];

		if ((rval = kvm_arch_vcpu_ioctl_set_regs(vcpu,
		    &kvm_regs_ioc->kvm_regs)) != 0) {
			kmem_free(kvm_regs_ioc, sz);
			break;
		}

		*rv = 0;
		kmem_free(kvm_regs_ioc, sz);
		break;
	}

	case KVM_SET_SIGNAL_MASK: {
		struct kvm_signal_mask *sigmask_arg = argp;
		struct kvm_signal_mask kvm_sigmask;
		sigset_t sigset;
		struct kvm *kvmp;
		struct kvm_vcpu *vcpu;

		/*
		 * XXX: we currently assume only one VCPU.
		 */
		if ((kvmp = ksp->kds_kvmp) == NULL || kvmp->online_vcpus != 1) {
			rval = EINVAL;
			break;
		}

		vcpu = kvmp->vcpus[0];

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

		if (copyin(sigmask_arg->sigset,
		    &sigset, sizeof (sigset)) != 0) {
			rval = EINVAL;
			break;
		}

		rval = kvm_vcpu_ioctl_set_sigmask(vcpu, &sigset);
		break;
	}

	case KVM_GET_FPU: {
		struct kvm_fpu_ioc *kvm_fpu_ioc;
		struct kvm *kvmp;
		struct kvm_vcpu *vcpu;
		size_t sz = sizeof (struct kvm_fpu_ioc);

		kvm_fpu_ioc = kmem_zalloc(sz, KM_SLEEP);

		if (copyin(argp, kvm_fpu_ioc, sz) != 0) {
			kmem_free(kvm_fpu_ioc, sz);
			rval = EFAULT;
			break;
		}

		if ((kvmp = ksp->kds_kvmp) == NULL ||
		    kvm_fpu_ioc->kvm_cpu_index >= kvmp->online_vcpus) {
			kmem_free(kvm_fpu_ioc, sz);
			rval = EINVAL;
			break;
		}

		vcpu = kvmp->vcpus[kvm_fpu_ioc->kvm_cpu_index];

		rval = kvm_arch_vcpu_ioctl_get_fpu(vcpu, &kvm_fpu_ioc->fpu);

		if (rval == 0 && copyout(kvm_fpu_ioc, argp, sz) != 0)
			rval = EFAULT;

		kmem_free(kvm_fpu_ioc, sz);
		*rv = 0;
		break;
	}

	case KVM_SET_FPU: {
		struct kvm_fpu_ioc *kvm_fpu_ioc;
		struct kvm *kvmp;
		struct kvm_vcpu *vcpu;
		size_t sz = sizeof (struct kvm_fpu_ioc);

		kvm_fpu_ioc = kmem_zalloc(sz, KM_SLEEP);

		if (copyin(argp, kvm_fpu_ioc, sz) != 0) {
			kmem_free(kvm_fpu_ioc, sz);
			rval = EFAULT;
			break;
		}

		if ((kvmp = ksp->kds_kvmp) == NULL ||
		    kvm_fpu_ioc->kvm_cpu_index >= kvmp->online_vcpus) {
			kmem_free(kvm_fpu_ioc, sz);
			rval = EINVAL;
			break;
		}

		vcpu = kvmp->vcpus[kvm_fpu_ioc->kvm_cpu_index];

		rval = kvm_arch_vcpu_ioctl_set_fpu(vcpu, &kvm_fpu_ioc->fpu);
		kmem_free(kvm_fpu_ioc, sz);
		*rv = 0;
		break;
	}

	case KVM_GET_SREGS: {
		struct kvm_sregs_ioc *kvm_sregs_ioc;
		struct kvm *kvmp;
		struct kvm_vcpu *vcpu;
		size_t sz = sizeof (struct kvm_sregs_ioc);

		kvm_sregs_ioc = kmem_zalloc(sz, KM_SLEEP);

		if (copyin(argp, kvm_sregs_ioc, sz) != 0) {
			kmem_free(kvm_sregs_ioc, sz);
			rval = EFAULT;
			break;
		}

		if ((kvmp = ksp->kds_kvmp) == NULL ||
		    kvm_sregs_ioc->kvm_cpu_index >= kvmp->online_vcpus) {
			kmem_free(kvm_sregs_ioc, sz);
			rval = EINVAL;
			break;
		}

		vcpu = kvmp->vcpus[kvm_sregs_ioc->kvm_cpu_index];

		if ((rval = kvm_arch_vcpu_ioctl_get_sregs(vcpu,
		    &kvm_sregs_ioc->sregs)) != 0) {
			kmem_free(kvm_sregs_ioc, sz);
			break;
		}

		if (copyout(kvm_sregs_ioc, argp, sz) != 0)
			rval = EFAULT;

		kmem_free(kvm_sregs_ioc, sz);
		*rv = 0;
		break;
	}

	case KVM_SET_SREGS: {
		struct kvm_sregs_ioc *kvm_sregs_ioc;
		struct kvm *kvmp;
		struct kvm_vcpu *vcpu;
		size_t sz = sizeof (struct kvm_sregs_ioc);

		kvm_sregs_ioc = kmem_zalloc(sz, KM_SLEEP);

		if (copyin(argp, kvm_sregs_ioc, sz) != 0) {
			kmem_free(kvm_sregs_ioc, sz);
			rval = EFAULT;
			break;
		}

		if ((kvmp = ksp->kds_kvmp) == NULL ||
		    kvm_sregs_ioc->kvm_cpu_index >= kvmp->online_vcpus) {
			kmem_free(kvm_sregs_ioc, sz);
			rval = EINVAL;
			break;
		}

		vcpu = kvmp->vcpus[kvm_sregs_ioc->kvm_cpu_index];
		rval = kvm_arch_vcpu_ioctl_set_sregs(vcpu,
		    &kvm_sregs_ioc->sregs);

		kmem_free(kvm_sregs_ioc, sizeof (struct kvm_sregs_ioc));
		*rv = 0;
		break;
	}

	case KVM_SET_CPUID2: {
		struct kvm_cpuid2_ioc *cpuid2_ioc;
		struct kvm_cpuid2 *cpuid2_data;
		struct kvm *kvmp;
		struct kvm_vcpu *vcpu;
		size_t sz = sizeof (struct kvm_cpuid2_ioc);

		cpuid2_ioc = kmem_alloc(sz, KM_SLEEP);

		if (copyin(argp, cpuid2_ioc, sz) != 0) {
			kmem_free(cpuid2_ioc, sz);
			rval = EFAULT;
			break;
		}

		if ((kvmp = ksp->kds_kvmp) == NULL ||
		    cpuid2_ioc->cpu_index >= kvmp->online_vcpus) {
			kmem_free(cpuid2_ioc, sz);
			rval = EINVAL;
			break;
		}

		vcpu = kvmp->vcpus[cpuid2_ioc->cpu_index];

		cpuid2_data = kmem_alloc(sizeof (struct kvm_cpuid2), KM_SLEEP);
		bcopy(&cpuid2_ioc->cpuid_data, cpuid2_data,
		    sizeof (struct kvm_cpuid2));

		rval = kvm_vcpu_ioctl_set_cpuid2(vcpu, cpuid2_data,
		    cpuid2_data->entries);

		kmem_free(cpuid2_data, sizeof (struct kvm_cpuid2));
		kmem_free(cpuid2_ioc, sz);

		break;
	}

	case KVM_GET_CPUID2: {
		struct kvm_cpuid2_ioc *cpuid2_ioc;
		struct kvm_cpuid2 *cpuid2_data;
		struct kvm *kvmp;
		struct kvm_vcpu *vcpu;
		size_t sz = sizeof (struct kvm_cpuid2_ioc);

		cpuid2_ioc = kmem_alloc(sz, KM_SLEEP);

		if (copyin(argp, cpuid2_ioc, sz) != 0) {
			kmem_free(cpuid2_ioc, sz);
			rval = EFAULT;
			break;
		}

		if ((kvmp = ksp->kds_kvmp) == NULL ||
		    cpuid2_ioc->cpu_index >= kvmp->online_vcpus) {
			kmem_free(cpuid2_ioc, sz);
			rval = EINVAL;
			break;
		}

		vcpu = kvmp->vcpus[cpuid2_ioc->cpu_index];

		cpuid2_data = kmem_alloc(sizeof (struct kvm_cpuid2), KM_SLEEP);
		bcopy(&cpuid2_ioc->cpuid_data, cpuid2_data,
		    sizeof (struct kvm_cpuid2));

		rval = kvm_vcpu_ioctl_get_cpuid2(vcpu, cpuid2_data,
		    cpuid2_data->entries);

		if (rval) {
			kmem_free(cpuid2_ioc, sz);
			kmem_free(cpuid2_data, sizeof (struct kvm_cpuid2));
			break;
		}

		if (copyout(cpuid2_ioc, argp, sz) != 0)
			rval = EFAULT;

		kmem_free(cpuid2_data, sizeof (struct kvm_cpuid2));
		kmem_free(cpuid2_ioc, sz);
		break;
	}

	case KVM_GET_LAPIC: {
		struct kvm_lapic_ioc *lapic_ioc;
		struct kvm *kvmp;
		struct kvm_vcpu *vcpu;
		size_t sz = sizeof (struct kvm_lapic_ioc);

		lapic_ioc = kmem_zalloc(sz, KM_SLEEP);

		if (copyin(argp, lapic_ioc, sz) != 0) {
			kmem_free(lapic_ioc, sz);
			rval = EFAULT;
			break;
		}

		if ((kvmp = ksp->kds_kvmp) == NULL ||
		    lapic_ioc->kvm_cpu_index >= kvmp->online_vcpus) {
			kmem_free(lapic_ioc, sz);
			rval = EINVAL;
			break;
		}

		vcpu = kvmp->vcpus[lapic_ioc->kvm_cpu_index];

		if (vcpu->arch.apic == NULL) {
			kmem_free(lapic_ioc, sz);
			rval = EINVAL;
			break;
		}

		rval = kvm_vcpu_ioctl_get_lapic(vcpu, &lapic_ioc->s);

		if (rval == 0 && copyout(lapic_ioc, argp, sz) != 0)
			rval = EFAULT;

		kmem_free(lapic_ioc, sz);
		break;
	}

	case KVM_SET_LAPIC: {
		struct kvm_lapic_ioc *lapic_ioc;
		struct kvm *kvmp;
		struct kvm_vcpu *vcpu;
		size_t sz = sizeof (struct kvm_lapic_ioc);

		lapic_ioc = kmem_zalloc(sz, KM_SLEEP);

		if (copyin(argp, lapic_ioc, sz) != 0) {
			kmem_free(lapic_ioc, sz);
			rval = EFAULT;
			break;
		}

		if ((kvmp = ksp->kds_kvmp) == NULL ||
		    lapic_ioc->kvm_cpu_index >= kvmp->online_vcpus) {
			kmem_free(lapic_ioc, sz);
			rval = EINVAL;
			break;
		}

		vcpu = kvmp->vcpus[lapic_ioc->kvm_cpu_index];

		if (vcpu->arch.apic == NULL) {
			kmem_free(lapic_ioc, sz);
			rval = EINVAL;
			break;
		}

		rval = kvm_vcpu_ioctl_set_lapic(vcpu, &lapic_ioc->s);
		kmem_free(lapic_ioc, sz);
		break;
	}

	case KVM_GET_VCPU_EVENTS: {
		struct kvm_vcpu_events_ioc *events_ioc;
		struct kvm *kvmp;
		struct kvm_vcpu *vcpu;
		size_t sz = sizeof (struct kvm_vcpu_events_ioc);

		events_ioc = kmem_zalloc(sz, KM_SLEEP);

		if (copyin(argp, events_ioc, sz) != 0) {
			kmem_free(events_ioc, sz);
			rval = EFAULT;
			break;
		}

		if ((kvmp = ksp->kds_kvmp) == NULL ||
		    events_ioc->kvm_cpu_index >= kvmp->online_vcpus) {
			kmem_free(events_ioc, sz);
			rval = EINVAL;
			break;
		}

		vcpu = kvmp->vcpus[events_ioc->kvm_cpu_index];

		kvm_vcpu_ioctl_x86_get_vcpu_events(vcpu, &events_ioc->events);

		if (copyout(events_ioc, argp, sz) != 0)
			rval = EFAULT;

		kmem_free(events_ioc, sz);
		*rv = 0;
		break;
	}

	case KVM_SET_VCPU_EVENTS: {
		struct kvm_vcpu_events_ioc *events_ioc;
		struct kvm *kvmp;
		struct kvm_vcpu *vcpu;
		size_t sz = sizeof (struct kvm_vcpu_events_ioc);

		events_ioc = kmem_zalloc(sz, KM_SLEEP);

		if (copyin(argp, events_ioc, sz) != 0) {
			kmem_free(events_ioc, sz);
			rval = EFAULT;
			break;
		}

		if ((kvmp = ksp->kds_kvmp) == NULL ||
		    events_ioc->kvm_cpu_index >= kvmp->online_vcpus) {
			kmem_free(events_ioc, sz);
			rval = EINVAL;
			break;
		}

		vcpu = kvmp->vcpus[events_ioc->kvm_cpu_index];

		rval = kvm_vcpu_ioctl_x86_set_vcpu_events(vcpu,
		    &events_ioc->events);

		kmem_free(events_ioc, sz);
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

	case KVM_INTERRUPT: {
		struct kvm_interrupt_ioc irq_ioc;
		struct kvm *kvmp;
		struct kvm_vcpu *vcpu;

		if (copyin(argp, &irq_ioc, sizeof (irq_ioc)) != 0) {
			rval = EFAULT;
			break;
		}

		if ((kvmp = ksp->kds_kvmp) == NULL ||
		    irq_ioc.kvm_cpu_index >= kvmp->online_vcpus) {
			rval = EINVAL;
			break;
		}

		vcpu = kvmp->vcpus[irq_ioc.kvm_cpu_index];
		rval = kvm_vcpu_ioctl_interrupt(vcpu, &irq_ioc.intr);
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
		struct kvm_kirq_routing *route;
		struct kvm *kvmp;
		struct kvm_irq_routing_entry *entries;
		uint32_t nroutes;

		/*
		 * Note the route must be allocated on the heap. The sizeof
		 * (kvm_kirq_routing) is approximately 0xc038 currently.
		 */
		route = kmem_zalloc(sizeof (kvm_kirq_routing_t), KM_SLEEP);

		/*
		 * copyin the number of routes, then copyin the routes
		 * themselves.
		 */
		if (copyin(argp, &nroutes, sizeof (nroutes)) != 0) {
			kmem_free(route, sizeof (kvm_kirq_routing_t));
			rval = EFAULT;
			break;
		}

		if (nroutes <= 0) {
			kmem_free(route, sizeof (kvm_kirq_routing_t));
			rval = EINVAL;
			break;
		}

		if (copyin(argp, route,
		    sizeof (struct kvm_irq_routing) + (nroutes - 1) *
		    sizeof (struct kvm_irq_routing_entry)) != 0) {
			kmem_free(route, sizeof (kvm_kirq_routing_t));
			rval = EFAULT;
			break;
		}

		if ((kvmp = ksp->kds_kvmp) == NULL) {
			kmem_free(route, sizeof (kvm_kirq_routing_t));
			rval = EINVAL;
			break;
		}

		if (route->nr >= KVM_MAX_IRQ_ROUTES || route->flags) {
			kmem_free(route, sizeof (kvm_kirq_routing_t));
			rval = EINVAL;
			break;
		}

		rval = kvm_set_irq_routing(kvmp, route->entries,
		    route->nr, route->flags);
		kmem_free(route, sizeof (kvm_kirq_routing_t));
		*rv = 0;
		break;
	}
#endif /* KVM_CAP_IRQ_ROUTING */
	case KVM_IRQ_LINE_STATUS:
	case KVM_IRQ_LINE: {
		struct kvm_irq_level_ioc *irq_event_ioc;
		struct kvm *kvmp;
		size_t sz = sizeof (struct kvm_irq_level_ioc);
		int32_t status;

		irq_event_ioc = kmem_zalloc(sz, KM_SLEEP);

		if (copyin(argp, irq_event_ioc, sz) != 0) {
			kmem_free(irq_event_ioc, sz);
			rval = EFAULT;
			break;
		}

		if ((kvmp = ksp->kds_kvmp) == NULL) {
			kmem_free(irq_event_ioc, sz);
			rval = EINVAL;
			break;
		}

		if (!irqchip_in_kernel(kvmp)) {
			kmem_free(irq_event_ioc, sz);
			rval = ENXIO;
			break;
		}

		status = kvm_set_irq(kvmp, KVM_USERSPACE_IRQ_SOURCE_ID,
		    irq_event_ioc->event.irq, irq_event_ioc->event.level);

		if (cmd == KVM_IRQ_LINE_STATUS) {
			irq_event_ioc->event.status = status;

			if (copyout(irq_event_ioc, argp, sz) != 0) {
				kmem_free(irq_event_ioc, sz);
				rval = EFAULT;
				break;
			}
		}

		kmem_free(irq_event_ioc, sz);
		break;
	}

	case KVM_SET_VAPIC_ADDR: {
		struct kvm_vapic_ioc kvm_vapic_ioc;
		struct kvm *kvmp = ksp->kds_kvmp;
		struct kvm_vcpu *vcpu;

		if (kvmp == NULL) {
			rval = EINVAL;
			break;
		}

		if (!irqchip_in_kernel(kvmp)) {
			rval = EINVAL;
			break;
		}

		if (copyin(argp, &kvm_vapic_ioc,
		    sizeof (struct kvm_vapic_ioc)) != 0) {
			rval = EFAULT;
			break;
		}

		if (kvm_vapic_ioc.kvm_cpu_index >= kvmp->online_vcpus) {
			rval = EINVAL;
			break;
		}

		vcpu = kvmp->vcpus[kvm_vapic_ioc.kvm_cpu_index];

		kvm_lapic_set_vapic_addr(vcpu, kvm_vapic_ioc.va.vapic_addr);
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
/* END CSTYLED */
