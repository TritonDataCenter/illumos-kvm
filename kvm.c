
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

#include "vmx.h"
#include "msr-index.h"
#include "msr.h"
#include "irqflags.h"
#include "kvm_host.h"
#include "kvm_x86host.h"
#include "processor-flags.h"
#include "hyperv.h"
#include "apicdef.h"
#include "segment.h"
#include "iodev.h"
#include "kvm.h"
#include "irq.h"
#include "tss.h"

int kvmid;  /* monotonically increasing, unique per vm */
int largepages_enabled = 1;

extern struct kvm *kvm_arch_create_vm(void);
extern void kvm_arch_destroy_vm(struct kvm *kvmp);
extern int kvm_arch_hardware_enable(void *garbage);
extern void kvm_arch_hardware_disable(void *garbage);
extern long kvm_vm_ioctl(struct kvm *kvmp, unsigned int ioctl, unsigned long arg, int mode);

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

static void hardware_enable(void *junk);
static void hardware_disable(void *junk);
extern struct kvm_vcpu *vmx_create_vcpu(struct kvm *kvm, struct kvm_vcpu_ioc *arg,
				 unsigned int id);
extern int vmx_vcpu_reset(struct kvm_vcpu *vcpu);
void vmx_vcpu_load(struct kvm_vcpu *vcpu, int cpu);
void vmx_vcpu_put(struct kvm_vcpu *vcpu);
extern void vmx_set_cr0(struct kvm_vcpu *vcpu, unsigned long cr0);
extern void vmx_set_cr4(struct kvm_vcpu *vcpu, unsigned long cr4);
static int vmx_set_tss_addr(struct kvm *kvmp, uintptr_t addr);
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
static int vmx_get_msr(struct kvm_vcpu *vcpu, uint32_t msr_index, uint64_t *pdata);
static int vmx_set_msr(struct kvm_vcpu *vcpu, uint32_t msr_index, uint64_t data);
static void vmx_vcpu_run(struct kvm_vcpu *vcpu);
static void vmx_save_host_state(struct kvm_vcpu *vcpu);

struct vcpu_vmx *to_vmx(struct kvm_vcpu *vcpu)
{
	return container_of(vcpu, struct vcpu_vmx, vcpu);
}

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
int get_ept_level(void);

static void vmx_flush_tlb(struct kvm_vcpu *vcpu)
{
#ifdef XXX
	vpid_sync_vcpu_all(to_vmx(vcpu));
	if (enable_ept)
		ept_sync_context(construct_eptp(vcpu->arch.mmu.root_hpa));
#endif
}

static void vmx_set_cr3(struct kvm_vcpu *vcpu, unsigned long cr3)
{
	unsigned long guest_cr3;
	uint64_t eptp;

	guest_cr3 = cr3;
#ifdef XXX
	if (enable_ept) {
		/*
		 * ept not implemented right now...
		 */
		eptp = construct_eptp(cr3);
		vmcs_write64(EPT_POINTER, eptp);
		guest_cr3 = is_paging(vcpu) ? vcpu->arch.cr3 :
			vcpu->kvm->arch.ept_identity_map_addr;
		ept_load_pdptrs(vcpu);
	}
#endif /*XXX*/

	vmx_flush_tlb(vcpu);
	vmcs_writel(GUEST_CR3, guest_cr3);
}

static struct kvm_x86_ops vmx_x86_ops = {
	.cpu_has_kvm_support = nulldev/*cpu_has_kvm_support*/,
	.disabled_by_bios = nulldev /*vmx_disabled_by_bios*/,
	.hardware_setup = vmx_hardware_setup /*hardware_setup*/,
	.hardware_unsetup = nulldev /*hardware_unsetup*/,
	.check_processor_compatibility = nulldev /*vmx_check_processor_compat*/,
	.hardware_enable = vmx_hardware_enable,
	.hardware_disable = hardware_disable,
	.cpu_has_accelerated_tpr = nulldev /*report_flexpriority*/,

	.vcpu_create = vmx_create_vcpu,
	.vcpu_free = nulldev /*vmx_free_vcpu*/,
	.vcpu_reset = vmx_vcpu_reset,

	.prepare_guest_switch = vmx_save_host_state /*vmx_save_host_state*/,
	.vcpu_load = vmx_vcpu_load,
	.vcpu_put = vmx_vcpu_put,

	.set_guest_debug = nulldev /*set_guest_debug*/,
	.get_msr = vmx_get_msr /*vmx_get_msr*/,
	.set_msr = vmx_set_msr /*vmx_set_msr*/,
	.get_segment_base = vmx_get_segment_base /*vmx_get_segment_base*/,
	.get_segment = vmx_get_segment /*vmx_get_segment*/,
	.set_segment = vmx_set_segment /*vmx_set_segment*/,
	.get_cpl = vmx_get_cpl /*vmx_get_cpl*/,
	.get_cs_db_l_bits = nulldev /*vmx_get_cs_db_l_bits*/,
	.decache_cr0_guest_bits = nulldev /*vmx_decache_cr0_guest_bits*/,
	.decache_cr4_guest_bits = nulldev /*vmx_decache_cr4_guest_bits*/,
	.set_cr0 = vmx_set_cr0,
	.set_cr3 = vmx_set_cr3 /*vmx_set_cr3*/,
	.set_cr4 = vmx_set_cr4,
	.set_efer = vmx_set_efer /*vmx_set_efer*/,
	.get_idt = vmx_get_idt /*vmx_get_idt*/,
	.set_idt = vmx_set_idt /*vmx_set_idt*/,
	.get_gdt = vmx_get_gdt /*vmx_get_gdt*/,
	.set_gdt = vmx_set_gdt /*vmx_set_gdt*/,
	.cache_reg = nulldev /*vmx_cache_reg*/,
	.get_rflags = vmx_get_rflags /*vmx_get_rflags*/,
	.set_rflags = vmx_set_rflags /*vmx_set_rflags*/,
	.fpu_activate = nulldev /*vmx_fpu_activate*/,
	.fpu_deactivate = nulldev /*vmx_fpu_deactivate*/,

	.tlb_flush = nulldev /*vmx_flush_tlb*/,

	.run = vmx_vcpu_run /*vmx_vcpu_run*/,
	.handle_exit = vmx_handle_exit /*vmx_handle_exit*/,
	.skip_emulated_instruction = nulldev /*skip_emulated_instruction*/,
	.set_interrupt_shadow = nulldev /*vmx_set_interrupt_shadow*/,
	.get_interrupt_shadow = nulldev /*vmx_get_interrupt_shadow*/,
	.patch_hypercall = nulldev /*vmx_patch_hypercall*/,
	.set_irq = nulldev /*vmx_inject_irq*/,
	.set_nmi = nulldev /*vmx_inject_nmi*/,
	.queue_exception = nulldev /*vmx_queue_exception*/,
	.interrupt_allowed = vmx_interrupt_allowed /*vmx_interrupt_allowed*/,
	.nmi_allowed = nulldev /*vmx_nmi_allowed*/,
	.get_nmi_mask = nulldev /*vmx_get_nmi_mask*/,
	.set_nmi_mask = nulldev /*vmx_set_nmi_mask*/,
	.enable_nmi_window = nulldev /*enable_nmi_window*/,
	.enable_irq_window = nulldev /*enable_irq_window*/,
	.update_cr8_intercept = vmx_update_cr8_intercept /*update_cr8_intercept*/,

	.set_tss_addr = vmx_set_tss_addr,
	.get_tdp_level = get_ept_level /*get_ept_level*/,
	.get_mt_mask = nulldev /*vmx_get_mt_mask*/,

	.exit_reasons_str = nulldev /*vmx_exit_reasons_str*/,
	.get_lpage_level = vmx_get_lpage_level /*vmx_get_lpage_level*/,

	.cpuid_update = nulldev /*vmx_cpuid_update*/,

	.rdtscp_supported = vmx_rdtscp_supported /*vmx_rdtscp_supported*/,
};

struct kvm_x86_ops *kvm_x86_ops;

uint32_t vmcs_read32(unsigned long field)
{
	return vmcs_readl(field);
}

void vmcs_write32(unsigned long field, uint32_t value)
{
	vmcs_writel(field, value);
}

static void vmx_get_idt(struct kvm_vcpu *vcpu, struct descriptor_table *dt)
{
	dt->limit = vmcs_read32(GUEST_IDTR_LIMIT);
	dt->base = vmcs_readl(GUEST_IDTR_BASE);
}

static void vmx_set_idt(struct kvm_vcpu *vcpu, struct descriptor_table *dt)
{
	vmcs_write32(GUEST_IDTR_LIMIT, dt->limit);
	vmcs_writel(GUEST_IDTR_BASE, dt->base);
}

static void vmx_get_gdt(struct kvm_vcpu *vcpu, struct descriptor_table *dt)
{
	dt->limit = vmcs_read32(GUEST_GDTR_LIMIT);
	dt->base = vmcs_readl(GUEST_GDTR_BASE);
}

static void vmx_set_gdt(struct kvm_vcpu *vcpu, struct descriptor_table *dt)
{
	vmcs_write32(GUEST_GDTR_LIMIT, dt->limit);
	vmcs_writel(GUEST_GDTR_BASE, dt->base);
}

/*
 * In linux, there is a separate vmx kernel module from the kvm driver.
 * That may be a good idea, but we're going to do everything in
 * the kvm driver, for now.
 * The call to vmx_init() in _init() is done when the vmx module
 * is loaded on linux.
 */

struct vmcs **vmxarea;  /* 1 per cpu */

static int alloc_kvm_area(void){

	int i, j;

	/*
	 * linux seems to do the allocations in a numa-aware
	 * fashion.  We'll just allocate...
	 */
	vmxarea = kmem_alloc(ncpus * sizeof(struct vmcs *), KM_SLEEP);
	if (vmxarea == NULL)
		return (ENOMEM);

	for (i = 0; i < ncpus; i++) {
		struct vmcs *vmcs;

		/* XXX the following assumes PAGESIZE allocations */
		/* are PAGESIZE aligned.  We could enforce this */
		/* via kmem_cache_create, but I'm lazy */
		vmcs = kmem_zalloc(PAGESIZE, KM_SLEEP);
		if (!vmcs) {
			for (j = 0; j < i; j++)
				kmem_free(vmxarea[j], PAGESIZE);
			return ENOMEM;
		}

		vmxarea[i] = vmcs;
	}
	return 0;
}

extern struct vmcs_config vmcs_config;

static int adjust_vmx_controls(uint32_t ctl_min, uint32_t ctl_opt,
				      uint32_t msr, uint32_t *result)
{
	uint32_t vmx_msr_low, vmx_msr_high;
	uint32_t ctl = ctl_min | ctl_opt;

	rdmsr(msr, vmx_msr_low, vmx_msr_high);

	ctl &= vmx_msr_high; /* bit == 0 in high word ==> must be zero */
	ctl |= vmx_msr_low;  /* bit == 1 in low word  ==> must be one  */

	/* Ensure minimum (required) set of control bits are supported. */
	if (ctl_min & ~ctl)
		return EIO;

	*result = ctl;
	return DDI_SUCCESS;
}

/* Pure 2^n version of get_order */
static inline int get_order(unsigned long size)
{
	int order;

	size = (size - 1) >> (PAGESHIFT - 1);
	order = -1;
	do {
		size >>= 1;
		order++;
	} while (size);
	return order;
}

static int setup_vmcs_config(struct vmcs_config *vmcs_conf)
{
	uint32_t vmx_msr_low, vmx_msr_high;
	uint32_t min, opt, min2, opt2;
	uint32_t _pin_based_exec_control = 0;
	uint32_t _cpu_based_exec_control = 0;
	uint32_t _cpu_based_2nd_exec_control = 0;
	uint32_t _vmexit_control = 0;
	uint32_t _vmentry_control = 0;

	min = PIN_BASED_EXT_INTR_MASK | PIN_BASED_NMI_EXITING;
	opt = PIN_BASED_VIRTUAL_NMIS;
	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_PINBASED_CTLS,
				&_pin_based_exec_control) != DDI_SUCCESS)
		return EIO;

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
		return EIO;
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
			return EIO;
	}
#ifndef CONFIG_X86_64
	if (!(_cpu_based_2nd_exec_control &
				SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES))
		_cpu_based_exec_control &= ~CPU_BASED_TPR_SHADOW;
#endif
	if (_cpu_based_2nd_exec_control & SECONDARY_EXEC_ENABLE_EPT) {
		/* CR3 accesses and invlpg don't need to cause VM Exits when EPT
		   enabled */
		_cpu_based_exec_control &= ~(CPU_BASED_CR3_LOAD_EXITING |
					     CPU_BASED_CR3_STORE_EXITING |
					     CPU_BASED_INVLPG_EXITING);
		rdmsr(MSR_IA32_VMX_EPT_VPID_CAP,
		      vmx_capability.ept, vmx_capability.vpid);
	}

	min = 0;
#ifdef CONFIG_X86_64
	min |= VM_EXIT_HOST_ADDR_SPACE_SIZE;
#endif
	opt = VM_EXIT_SAVE_IA32_PAT | VM_EXIT_LOAD_IA32_PAT;
	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_EXIT_CTLS,
				&_vmexit_control) != DDI_SUCCESS)
		return EIO;

	min = 0;
	opt = VM_ENTRY_LOAD_IA32_PAT;
	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_ENTRY_CTLS,
				&_vmentry_control) != DDI_SUCCESS)
		return EIO;

	rdmsr(MSR_IA32_VMX_BASIC, vmx_msr_low, vmx_msr_high);

	/* IA-32 SDM Vol 3B: VMCS size is never greater than 4kB. */
	if ((vmx_msr_high & 0x1fff) > PAGESIZE)
		return EIO;

#ifdef CONFIG_X86_64
	/* IA-32 SDM Vol 3B: 64-bit CPUs always have VMX_BASIC_MSR[48]==0. */
	if (vmx_msr_high & (1u<<16))
		return EIO;
#endif

	/* Require Write-Back (WB) memory type for VMCS accesses. */
	if (((vmx_msr_high >> 18) & 15) != 6)
		return EIO;

	vmcs_conf->size = vmx_msr_high & 0x1fff;
	vmcs_conf->order = get_order(vmcs_config.size);
	vmcs_conf->revision_id = vmx_msr_low;

	vmcs_conf->pin_based_exec_ctrl = _pin_based_exec_control;
	vmcs_conf->cpu_based_exec_ctrl = _cpu_based_exec_control;
	vmcs_conf->cpu_based_2nd_exec_ctrl = _cpu_based_2nd_exec_control;
	vmcs_conf->vmexit_ctrl         = _vmexit_control;
	vmcs_conf->vmentry_ctrl        = _vmentry_control;

	return 0;
}

/* EFER defaults:
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
static int flexpriority_enabled = 1;
int enable_ept = 0;  
int enable_unrestricted_guest = 1;
int emulate_invalid_guest_state = 0;

void kvm_enable_efer_bits(uint64_t mask)
{
       efer_reserved_bits &= ~mask;
}

static inline int cpu_has_vmx_vpid(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_ENABLE_VPID;
}

static inline int cpu_has_vmx_ept(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_ENABLE_EPT;
}
static inline int cpu_has_vmx_unrestricted_guest(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_UNRESTRICTED_GUEST;
}

static inline int cpu_has_vmx_tpr_shadow(void)
{
	return vmcs_config.cpu_based_exec_ctrl & CPU_BASED_TPR_SHADOW;
}

static inline int cpu_has_vmx_virtualize_apic_accesses(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES;
}

static inline int cpu_has_vmx_flexpriority(void)
{
	return cpu_has_vmx_tpr_shadow() &&
		cpu_has_vmx_virtualize_apic_accesses();
}

static inline int cpu_has_vmx_ept_2m_page(void)
{
	return !!(vmx_capability.ept & VMX_EPT_2MB_PAGE_BIT);
}

void kvm_disable_largepages(void)
{
	largepages_enabled = 0;
}

static inline int cpu_has_vmx_ple(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_PAUSE_LOOP_EXITING;
}

static int vmx_hardware_setup(void)
{

	if (setup_vmcs_config(&vmcs_config) != DDI_SUCCESS)
		return EIO;
#ifdef XXX
	if (boot_cpu_has(X86_FEATURE_NX))
		kvm_enable_efer_bits(EFER_NX);
#endif /*XXX*/


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
#ifdef XXX
	if (!cpu_has_vmx_ple())
		ple_gap = 0;
#endif

	return alloc_kvm_area();
}

int kvm_arch_hardware_setup(void)
{
	return kvm_x86_ops->hardware_setup();
}

struct kmem_cache *pte_chain_cache;
struct kmem_cache *rmap_desc_cache;
struct kmem_cache *mmu_page_header_cache;

int tdp_enabled = 0;

#define PT_WRITABLE_SHIFT 1
#define PT_PRESENT_MASK (1ULL << 0)
#define PT64_BASE_ADDR_MASK (((1ULL << 52) - 1) & ~(uint64_t)(PAGESIZE-1))
#define PT_WRITABLE_MASK (1ULL << PT_WRITABLE_SHIFT)
#define PT_USER_MASK (1ULL << 2)
#define ACC_EXEC_MASK    1
#define ACC_WRITE_MASK   PT_WRITABLE_MASK
#define ACC_USER_MASK    PT_USER_MASK
#define ACC_ALL          (ACC_EXEC_MASK | ACC_WRITE_MASK | ACC_USER_MASK)

static void *mmu_memory_cache_alloc(struct kvm_mmu_memory_cache *mc,
				    size_t size)
{
	void *p;

	p = mc->objects[--mc->nobjs];
	return p;
}

static struct kvm_mmu_page *kvm_mmu_alloc_page(struct kvm_vcpu *vcpu,
					       uint64_t *parent_pte)
{
	struct kvm_mmu_page *sp;

	sp = mmu_memory_cache_alloc(&vcpu->arch.mmu_page_header_cache, sizeof *sp);
	sp->spt = mmu_memory_cache_alloc(&vcpu->arch.mmu_page_cache, PAGESIZE);
	sp->gfns = mmu_memory_cache_alloc(&vcpu->arch.mmu_page_cache, PAGESIZE);
	set_page_private(virt_to_page(sp->spt), (unsigned long)sp);
	list_insert_head(&vcpu->kvm->arch.active_mmu_pages, sp);
#ifdef XXX
	/* XXX don't see this used anywhere */
	INIT_LIST_HEAD(&sp->oos_link);
#endif /*XXX*/
	bitmap_zero(sp->slot_bitmap, KVM_MEMORY_SLOTS + KVM_PRIVATE_MEM_SLOTS);
	sp->multimapped = 0;
	sp->parent_pte = parent_pte;
	--vcpu->kvm->arch.n_free_mmu_pages;
	return sp;
}

typedef int (*mmu_parent_walk_fn) (struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp);

struct kvm_mmu_page *
shadow_hpa_to_kvmpage(hpa_t shadow_page)
{
	/*
	 * XXX - We'll probably need a faster way to do this...
	 * For right now, search all kvm_mmu_page for matching hpa
	 */

}	

struct kvm_mmu_page *
page_header(hpa_t shadow_page)
{
	return (struct kvm_mmu_page *)shadow_hpa_to_kvmpage(shadow_page);
}

static void mmu_parent_walk(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp,
			    mmu_parent_walk_fn fn)
{
	struct kvm_pte_chain *pte_chain;
	struct hlist_node *node;
	struct kvm_mmu_page *parent_sp;
	int i;

	if (!sp->multimapped && sp->parent_pte) {
		parent_sp = page_header(__pa(sp->parent_pte));
		fn(vcpu, parent_sp);
		mmu_parent_walk(vcpu, parent_sp, fn);
		return;
	}
	for(pte_chain = list_head(sp->parent_ptes); pte_chain;
	    pte_chain = list_next(sp->parent_ptes, pte_chain)) {
		for (i = 0; i < NR_PTE_CHAIN_ENTRIES; ++i) {
			if (!pte_chain->parent_ptes[i])
				break;
			parent_sp = page_header(__pa(pte_chain->parent_ptes[i]));
			fn(vcpu, parent_sp);
			mmu_parent_walk(vcpu, parent_sp, fn);
		}
	}
}

static void kvm_mmu_mark_parents_unsync(struct kvm_vcpu *vcpu,
					struct kvm_mmu_page *sp)
{
	mmu_parent_walk(vcpu, sp, unsync_walk_fn);
	kvm_mmu_update_parents_unsync(sp);
}

static unsigned kvm_page_table_hashfn(gfn_t gfn)
{
	return gfn & ((1 << KVM_MMU_HASH_SHIFT) - 1);
}

static struct kvm_mmu_page *kvm_mmu_get_page(struct kvm_vcpu *vcpu,
					     gfn_t gfn,
					     gva_t gaddr,
					     unsigned level,
					     int direct,
					     unsigned access,
					     uint64_t *parent_pte)
{
	union kvm_mmu_page_role role;
	unsigned index;
	unsigned quadrant;
	struct hlist_head *bucket;
	struct kvm_mmu_page *sp;
	struct hlist_node *node, *tmp;

	role = vcpu->arch.mmu.base_role;
	role.level = level;
	role.direct = direct;
	role.access = access;
	if (vcpu->arch.mmu.root_level <= PT32_ROOT_LEVEL) {
		quadrant = gaddr >> (PAGE_SHIFT + (PT64_PT_BITS * level));
		quadrant &= (1 << ((PT32_PT_BITS - PT64_PT_BITS) * level)) - 1;
		role.quadrant = quadrant;
	}
	index = kvm_page_table_hashfn(gfn);
	bucket = &vcpu->kvm->arch.mmu_page_hash[index];
	for (sp = list_head(&vcpu->kvm->arch.mmu_page_hash[index]); sp;
	     sp = list_next(&vcpu->kvm->arch.mmu_page_hash[index], sp)) {
		if (sp->gfn == gfn) {
			if (sp->unsync)
				if (kvm_sync_page(vcpu, sp))
					continue;

			if (sp->role.word != role.word)
				continue;

			mmu_page_add_parent_pte(vcpu, sp, parent_pte);
			if (sp->unsync_children) {
				BT_SET(&vcpu->requests, KVM_REQ_MMU_SYNC);
				kvm_mmu_mark_parents_unsync(vcpu, sp);
			}
			return sp;
		}
	}
#ifdef XXX
	++vcpu->kvm->stat.mmu_cache_miss;
#endif
	sp = kvm_mmu_alloc_page(vcpu, parent_pte);
	if (!sp)
		return sp;
	sp->gfn = gfn;
	sp->role = role;
	list_insert_head(bucket, &sp);
	if (!direct) {
		if (rmap_write_protect(vcpu->kvm, gfn))
			kvm_flush_remote_tlbs(vcpu->kvm);
#ifdef XXX
		account_shadowed(vcpu->kvm, gfn);
#endif /*XXX*/
	}
	if (shadow_trap_nonpresent_pte != shadow_notrap_nonpresent_pte)
		vcpu->arch.mmu.prefetch_page(vcpu, sp);
	else
		nonpaging_prefetch_page(vcpu, sp);
#ifdef XXX
	trace_kvm_mmu_get_page(sp, true);
#endif /*XXX*/
	return sp;
}

static int mmu_alloc_roots(struct kvm_vcpu *vcpu)
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
			return 1;
		sp = kvm_mmu_get_page(vcpu, root_gfn, 0,
				      PT64_ROOT_LEVEL, direct,
				      ACC_ALL, NULL);
		root = kvm_va2pa(sp->spt);
		++sp->root_count;
		vcpu->arch.mmu.root_hpa = root;
		return 0;
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
			return 1;
		sp = kvm_mmu_get_page(vcpu, root_gfn, i << 30,
				      PT32_ROOT_LEVEL, direct,
				      ACC_ALL, NULL);
		root = __pa(sp->spt);
		++sp->root_count;
		vcpu->arch.mmu.pae_root[i] = root | PT_PRESENT_MASK;
	}
	vcpu->arch.mmu.root_hpa = __pa(vcpu->arch.mmu.pae_root);
	return 0;
}

static void mmu_sync_roots(struct kvm_vcpu *vcpu)
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
	for (i = 0; i < 4; ++i) {
		hpa_t root = vcpu->arch.mmu.pae_root[i];

		if (root && VALID_PAGE(root)) {
			root &= PT64_BASE_ADDR_MASK;
			sp = page_header(root);
			mmu_sync_children(vcpu, sp);
		}
	}
}

void kvm_mmu_sync_roots(struct kvm_vcpu *vcpu)
{
	spin_lock(&vcpu->kvm->mmu_lock);
	mmu_sync_roots(vcpu);
	spin_unlock(&vcpu->kvm->mmu_lock);
}

static void mmu_destroy_caches(void)
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
}

int kvm_mmu_module_init(void)
{
	pte_chain_cache = kmem_cache_create("kvm_pte_chain",
					    sizeof(struct kvm_pte_chain), 0,
					    zero_constructor, NULL, NULL,
					    sizeof(struct kvm_pte_chain), NULL, 0);
	if (!pte_chain_cache)
		goto nomem;
	rmap_desc_cache = kmem_cache_create("kvm_rmap_desc",
					    sizeof(struct kvm_rmap_desc), 0,
					    zero_constructor, NULL, NULL, 
					    sizeof(struct kvm_rmap_desc), NULL, 0);
	if (!rmap_desc_cache)
		goto nomem;

	mmu_page_header_cache = kmem_cache_create("kvm_mmu_page_header",
						  sizeof(struct kvm_mmu_page), 0,
						  zero_constructor, NULL, NULL, 
						  sizeof(struct kvm_mmu_page), NULL, 0);
	if (!mmu_page_header_cache)
		goto nomem;

#ifdef XXX
	/* this looks like a garbage collector/reaper.  Implement later if needed */
	register_shrinker(&mmu_shrinker);
#endif /*XXX*/

	return 0;

nomem:
	mmu_destroy_caches();
	return ENOMEM;
}

/*
 * List of msr numbers which we expose to userspace through KVM_GET_MSRS
 * and KVM_SET_MSRS, and KVM_GET_MSR_INDEX_LIST.
 *
 * This list is modified at module load time to reflect the
 * capabilities of the host cpu. This capabilities test skips MSRs that are
 * kvm-specific. Those are put in the beginning of the list.
 */

#define MSR_KVM_WALL_CLOCK  0x11
#define MSR_KVM_SYSTEM_TIME 0x12

#define KVM_SAVE_MSRS_BEGIN	5
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

#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))

uint64_t native_read_msr_safe(unsigned int msr,
				     int *err)
{
	DECLARE_ARGS(val, low, high);

#ifdef CONFIG_SOLARIS
	{
		on_trap_data_t otd;

		if (on_trap(&otd, OT_DATA_ACCESS) == 0) {
			native_read_msr(msr);
		} else {
			*err = EINVAL; /* XXX probably not right... */
		}
		no_trap();
	}
#else
	asm volatile("2: rdmsr ; xor %[err],%[err]\n"
		     "1:\n\t"
		     ".section .fixup,\"ax\"\n\t"
		     "3:  mov %[fault],%[err] ; jmp 1b\n\t"
		     ".previous\n\t"
		     _ASM_EXTABLE(2b, 3b)
		     : [err] "=r" (*err), EAX_EDX_RET(val, low, high)
		     : "c" (msr), [fault] "i" (-EIO));
#endif /*CONFIG_SOLARIS*/
	return EAX_EDX_VAL(val, low, high);
}

/* Can be uninlined because referenced by paravirt */
int native_write_msr_safe(unsigned int msr,
				 unsigned low, unsigned high)
{
	int err;
#ifdef CONFIG_SOLARIS
	{
		on_trap_data_t otd;

		if (on_trap(&otd, OT_DATA_ACCESS) == 0) {
			native_write_msr(msr, low, high);
		} else {
			err = EINVAL;  /* XXX probably not right... */
		}
		no_trap();
	}
#else
	asm volatile("2: wrmsr ; xor %[err],%[err]\n"
		     "1:\n\t"
		     ".section .fixup,\"ax\"\n\t"
		     "3:  mov %[fault],%[err] ; jmp 1b\n\t"
		     ".previous\n\t"
		     _ASM_EXTABLE(2b, 3b)
		     : [err] "=a" (err)
		     : "c" (msr), "0" (low), "d" (high),
		       [fault] "i" (-EIO)
		     : "memory");
#endif /*CONFIG_SOLARIS*/
	return err;
}

static void kvm_init_msr_list(void)
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

static uint64_t shadow_trap_nonpresent_pte;
static uint64_t shadow_notrap_nonpresent_pte;
static uint64_t shadow_base_present_pte;
static uint64_t shadow_nx_mask;
static uint64_t shadow_x_mask;	/* mutual exclusive with nx_mask */
static uint64_t shadow_user_mask;
static uint64_t shadow_accessed_mask;
static uint64_t shadow_dirty_mask;

void kvm_mmu_set_nonpresent_ptes(uint64_t trap_pte, uint64_t notrap_pte)
{
	shadow_trap_nonpresent_pte = trap_pte;
	shadow_notrap_nonpresent_pte = notrap_pte;
}

void kvm_mmu_set_base_ptes(uint64_t base_pte)
{
	shadow_base_present_pte = base_pte;
}

void kvm_mmu_set_mask_ptes(uint64_t user_mask, uint64_t accessed_mask,
		uint64_t dirty_mask, uint64_t nx_mask, uint64_t x_mask)
{
	shadow_user_mask = user_mask;
	shadow_accessed_mask = accessed_mask;
	shadow_dirty_mask = dirty_mask;
	shadow_nx_mask = nx_mask;
	shadow_x_mask = x_mask;
}

#define PT64_PT_BITS 9
#define PT64_ENT_PER_PAGE (1 << PT64_PT_BITS)
#define PT32_PT_BITS 10
#define PT32_ENT_PER_PAGE (1 << PT32_PT_BITS)

#define PT_WRITABLE_SHIFT 1

#define PT_PRESENT_MASK (1ULL << 0)
#define PT_WRITABLE_MASK (1ULL << PT_WRITABLE_SHIFT)
#define PT_USER_MASK (1ULL << 2)
#define PT_PWT_MASK (1ULL << 3)
#define PT_PCD_MASK (1ULL << 4)
#define PT_ACCESSED_SHIFT 5
#define PT_ACCESSED_MASK (1ULL << PT_ACCESSED_SHIFT)
#define PT_DIRTY_MASK (1ULL << 6)
#define PT_PAGE_SIZE_MASK (1ULL << 7)
#define PT_PAT_MASK (1ULL << 7)
#define PT_GLOBAL_MASK (1ULL << 8)
#define PT64_NX_SHIFT 63
#define PT64_NX_MASK (1ULL << PT64_NX_SHIFT)

#define PT_PAT_SHIFT 7
#define PT_DIR_PAT_SHIFT 12
#define PT_DIR_PAT_MASK (1ULL << PT_DIR_PAT_SHIFT)

#define PT32_DIR_PSE36_SIZE 4
#define PT32_DIR_PSE36_SHIFT 13
#define PT32_DIR_PSE36_MASK \
	(((1ULL << PT32_DIR_PSE36_SIZE) - 1) << PT32_DIR_PSE36_SHIFT)

#define PT64_ROOT_LEVEL 4
#define PT32_ROOT_LEVEL 2
#define PT32E_ROOT_LEVEL 3

#define PT_PDPE_LEVEL 3
#define PT_DIRECTORY_LEVEL 2
#define PT_PAGE_TABLE_LEVEL 1

#define PFERR_PRESENT_MASK (1U << 0)
#define PFERR_WRITE_MASK (1U << 1)
#define PFERR_USER_MASK (1U << 2)
#define PFERR_RSVD_MASK (1U << 3)
#define PFERR_FETCH_MASK (1U << 4)

static void kvm_timer_init(void)
{
	int cpu;

	/*
	 * XXX We assume that any machine running solaris kvm
	 * has constant time stamp counter increment rate.
	 * This will be true for all but older machines.
	 */
#ifndef CONFIG_SOLARIS
	for_each_possible_cpu(cpu)
		per_cpu(cpu_tsc_khz, cpu) = tsc_khz;
#else
	/* assume pi_clock in mhz */
	/* cpu_tsc_khz = (CPU)->cpu_type_info.pi_clock * 1000;*/
#endif /*CONFIG_SOLARIS*/
}

int kvm_arch_init(void *opaque)
{
	int r;
	struct kvm_x86_ops *ops = (struct kvm_x86_ops *)opaque;
	volatile int x;  /* XXX - dtrace return probe missing */

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

	x = 10; /*XXX*/
	return 0;

out:
	x = 20; /*XXX*/
	return r;
}

caddr_t bad_page;  /* XXX page_t on linux... */
pfn_t bad_pfn;
kmem_cache_t *kvm_vcpu_cache;

int kvm_init(void *opaque, unsigned int vcpu_size)
{
	int r;
	int cpu;

	r = kvm_arch_init(opaque);

	if (r != DDI_SUCCESS)
		return (r);

	bad_page = kmem_zalloc(PAGESIZE, KM_SLEEP);

	if (bad_page == NULL) {
		r = ENOMEM;
		goto out;
	}

	bad_pfn = hat_getpfnum(kas.a_hat, bad_page);

#ifdef XXX
	if (!zalloc_cpumask_var(&cpus_hardware_enabled, GFP_KERNEL)) {
		r = -ENOMEM;
		goto out_free_0;
	}
#endif /*XXX*/
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
#endif /*XXX*/


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
#endif /*XXX*/
	/* A kmem cache lets us meet the alignment requirements of fx_save. */
	kvm_vcpu_cache = kmem_cache_create("kvm_vcpu", vcpu_size,
					   __alignof__(struct kvm_vcpu),
					   NULL, NULL, NULL, NULL, NULL, 0);
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
#endif /*XXX*/

	return 0;

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
#endif /*XXX*/
out_free_2:
out_free_1:
#ifdef XXX
	kvm_arch_hardware_unsetup();
#endif /*XXX*/
out_free_0a:
#ifdef XXX
	free_cpumask_var(cpus_hardware_enabled);
#endif /*XXX*/
out_free_0:
	kmem_free(bad_page, PAGESIZE);
out:
#ifdef XXX
	kvm_arch_exit();
#endif
out_fail:
	return r;
}

extern unsigned long vmx_io_bitmap_a[];
extern unsigned long vmx_io_bitmap_b[];
extern unsigned long vmx_msr_bitmap_legacy[];
extern unsigned long vmx_msr_bitmap_longmode[];

static inline int cpu_has_vmx_msr_bitmap(void)
{
	return vmcs_config.cpu_based_exec_ctrl & CPU_BASED_USE_MSR_BITMAPS;
}

static void __vmx_disable_intercept_for_msr(unsigned long *msr_bitmap, uint32_t msr)
{
	int f = sizeof(unsigned long);

	if (!cpu_has_vmx_msr_bitmap())
		return;

	/*
	 * See Intel PRM Vol. 3, 20.6.9 (MSR-Bitmap Address). Early manuals
	 * have the write-low and read-high bitmap offsets the wrong way round.
	 * We can control MSRs 0x00000000-0x00001fff and 0xc0000000-0xc0001fff.
	 */
	if (msr <= 0x1fff) {
		BT_CLEAR(msr_bitmap + 0x000 / f, msr); /* read-low */
		BT_CLEAR(msr_bitmap + 0x800 / f, msr); /* write-low */
	} else if ((msr >= 0xc0000000) && (msr <= 0xc0001fff)) {
		msr &= 0x1fff;
		BT_CLEAR(msr_bitmap + 0x400 / f, msr); /* read-high */
		BT_CLEAR(msr_bitmap + 0xc00 / f, msr); /* write-high */
	}
}

static void vmx_disable_intercept_for_msr(uint32_t msr, int longmode_only)
{
	if (!longmode_only)
		__vmx_disable_intercept_for_msr(vmx_msr_bitmap_legacy, msr);
	__vmx_disable_intercept_for_msr(vmx_msr_bitmap_longmode, msr);
}

static struct kvm_shared_msrs_global shared_msrs_global;

void kvm_define_shared_msr(unsigned slot, uint32_t msr)
{
	if (slot >= shared_msrs_global.nr)
		shared_msrs_global.nr = slot + 1;
	shared_msrs_global.msrs[slot] = msr;
#ifdef XXX
	/* we need ensured the shared_msr_global have been updated */
	smp_wmb();
#endif /*XXX*/
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
#define NR_VMX_MSR ARRAY_SIZE(vmx_msr_index)
#define VMX_NR_VPIDS				(1 << 16)
ulong_t *vmx_vpid_bitmap;
size_t vpid_bitmap_words;
kmutex_t vmx_vpid_lock;

void kvm_disable_tdp(void)
{
	tdp_enabled = 0;
}

static int vmx_init(void)
{
	int r, i;

	rdmsrl_safe(MSR_EFER, &host_efer);

	for (i = 0; i < NR_VMX_MSR; ++i)
		kvm_define_shared_msr(i, vmx_msr_index[i]);

#ifdef XXX
	vmx_io_bitmap_a = (unsigned long *)kmem_zalloc(PAGESIZE, KM_SLEEP);
	if (!vmx_io_bitmap_a)
		return ENOMEM;

	vmx_io_bitmap_b = (unsigned long *)kmem_zalloc(PAGESIZE, KM_SLEEP);
	if (!vmx_io_bitmap_b) {
		r = ENOMEM;
		goto out;
	}

	vmx_msr_bitmap_legacy = (unsigned long *)kmem_zalloc(PAGESIZE, KM_SLEEP);
	if (!vmx_msr_bitmap_legacy) {
		r = ENOMEM;
		goto out1;
	}

	vmx_msr_bitmap_longmode = (unsigned long *)kmem_zalloc(PAGESIZE, KM_SLEEP);
	if (!vmx_msr_bitmap_longmode) {
		r = ENOMEM;		goto out2;
	}
#endif
	/*
	 * Allow direct access to the PC debug port (it is often used for I/O
	 * delays, but the vmexits simply slow things down).
	 */
	memset(vmx_io_bitmap_a, 0xff, PAGESIZE);
	BT_CLEAR(vmx_io_bitmap_a, 0x80);

	memset(vmx_io_bitmap_b, 0xff, PAGESIZE);

	memset(vmx_msr_bitmap_legacy, 0xff, PAGESIZE);
	memset(vmx_msr_bitmap_longmode, 0xff, PAGESIZE);

	BT_SET(vmx_vpid_bitmap, 0); /* 0 is reserved for host */

	r = kvm_init(&vmx_x86_ops, sizeof(struct vcpu_vmx));

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

#ifdef XXX
	if (bypass_guest_pf)
		kvm_mmu_set_nonpresent_ptes(~0xffeull, 0ull);
#endif /*XXX*/
	return 0;

out3:
	kmem_free(vmx_msr_bitmap_longmode, PAGESIZE);
out2:
	kmem_free(vmx_msr_bitmap_legacy, PAGESIZE);
out1:
	kmem_free(vmx_io_bitmap_b, PAGESIZE);
out:
	kmem_free(vmx_io_bitmap_a, PAGESIZE);
	return r;
}


int
_init(void)
{
	int e, r;

	if ((e = ddi_soft_state_init(&kvm_state,
	    sizeof (kvm_devstate_t), 1)) != 0) {
		return (e);
	}

	if ((e = mod_install(&modlinkage)) != 0)  {
		ddi_soft_state_fini(&kvm_state);
	}

	if (enable_vpid) {
		vpid_bitmap_words = howmany(VMX_NR_VPIDS, BT_NBIPUL);
		vmx_vpid_bitmap = kmem_zalloc(sizeof(ulong_t)*vpid_bitmap_words, KM_SLEEP);
		mutex_init(&vmx_vpid_lock, NULL, MUTEX_DRIVER, NULL);
	}
		
	mutex_init(&kvm_lock, NULL, MUTEX_DRIVER, 0);  /* XXX */
	kvm_x86_ops = &vmx_x86_ops;
	if ((r = vmx_init()) != DDI_SUCCESS) {
		mutex_destroy(&kvm_lock);
		if (vmx_vpid_bitmap) {
			kmem_free(vmx_vpid_bitmap, sizeof(ulong_t)*vpid_bitmap_words);
			mutex_destroy(&vmx_vpid_lock);
		}
		mod_remove(&modlinkage);
		ddi_soft_state_fini(&kvm_state);
		return (r);
	}
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
		list_create(&vm_list, sizeof(struct kvm), offsetof(struct kvm, vm_list));
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

/*
 * XXX the following needs to run on
 * every cpu.  Right now, only run on the current
 * cpu.
 */
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

static void 
kvm_mmu_pages_init(struct kvm_mmu_page *parent,
			       struct mmu_page_path *parents,
			       struct kvm_mmu_pages *pvec)
{
	parents->parent[parent->role.w.level-1] = NULL;
	pvec->nr = 0;
}

static int 
mmu_pages_add(struct kvm_mmu_pages *pvec, struct kvm_mmu_page *sp,
	      int idx)
{
	int i;

	if (sp->unsync)
		for (i=0; i < pvec->nr; i++)
			if (pvec->page[i].sp == sp)
				return 0;

	pvec->page[pvec->nr].sp = sp;
	pvec->page[pvec->nr].idx = idx;
	pvec->nr++;
	return (pvec->nr == KVM_PAGE_ARRAY_NR);
}

extern pfn_t hat_getpfnum(struct hat *hat, caddr_t);

static int 
is_large_pte(uint64_t pte)
{
	return pte & PT_PAGE_SIZE_MASK;
}

static int 
is_shadow_present_pte(uint64_t pte)
{
	return pte != shadow_trap_nonpresent_pte
		&& pte != shadow_notrap_nonpresent_pte;
}


static int __mmu_unsync_walk(struct kvm_mmu_page *sp,
			   struct kvm_mmu_pages *pvec)
{
	int i, ret, nr_unsync_leaf = 0;

	for_each_unsync_children(sp->unsync_child_bitmap, i) {
		uint64_t ent = sp->spt[i];

		if (is_shadow_present_pte(ent) && !is_large_pte(ent)) {
			struct kvm_mmu_page *child;
			child = page_header(ent & PT64_BASE_ADDR_MASK);

			if (child->unsync_children) {
				if (mmu_pages_add(pvec, child, i))
					return -ENOSPC;

				ret = __mmu_unsync_walk(child, pvec);
				if (!ret)
					__clear_bit(i, sp->unsync_child_bitmap);
				else if (ret > 0)
					nr_unsync_leaf += ret;
				else
					return ret;
			}

			if (child->unsync) {
				nr_unsync_leaf++;
				if (mmu_pages_add(pvec, child, i))
					return -ENOSPC;
			}
		}
	}

	if (bt_getlowbit(sp->unsync_child_bitmap, 0, 512) == 512)
		sp->unsync_children = 0;

	return nr_unsync_leaf;
}

static int 
mmu_unsync_walk(struct kvm_mmu_page *sp, struct kvm_mmu_pages *pvec)
{
	if (!sp->unsync_children)
		return 0;

	mmu_pages_add(pvec, sp, 0);
	return __mmu_unsync_walk(sp, pvec);
}

static int 
mmu_zap_unsync_children(struct kvm *kvm, struct kvm_mmu_page *parent)
{
	int i, zapped = 0;
	struct mmu_page_path parents;
	struct kvm_mmu_pages pages;

	if (parent->role.level == PT_PAGE_TABLE_LEVEL)
		return 0;

	kvm_mmu_pages_init(parent, &parents, &pages);
	while (mmu_unsync_walk(parent, &pages)) {
		struct kvm_mmu_page *sp;

		for_each_sp(pages, sp, parents, i) {
			kvm_mmu_zap_page(kvm, sp);
			mmu_pages_clear_parents(&parents);
			zapped++;
		}
		kvm_mmu_pages_init(parent, &parents, &pages);
	}

	return zapped;
}

static int 
kvm_mmu_zap_page(struct kvm *kvm, struct kvm_mmu_page *sp)
{
	int ret;

	ret = mmu_zap_unsync_children(kvm, sp);
	kvm_mmu_page_unlink_children(kvm, sp);
	kvm_mmu_unlink_parents(kvm, sp);
	kvm_flush_remote_tlbs(kvm);
	if (!sp->role.invalid && !sp->role.direct)
		unaccount_shadowed(kvm, sp->gfn);
	if (sp->unsync)
		kvm_unlink_unsync_page(kvm, sp);
	if (!sp->root_count) {
		hlist_del(&sp->hash_link);
		kvm_mmu_free_page(kvm, sp);
	} else {
		sp->role.invalid = 1;
		list_move(&sp->link, &kvm->arch.active_mmu_pages);
		kvm_reload_remote_mmus(kvm);
	}
	kvm_mmu_reset_last_pte_updated(kvm);
	return ret;
}

void kvm_mmu_zap_all(struct kvm *kvm)
{
	struct kvm_mmu_page *sp, *node;

	mutex_enter(&kvm->mmu_lock);
	for (sp = list_head(&kvm->arch.active_mmu_pages); sp;
	     sp = list_next(&kvm->arch.active_mmu_pages, sp->link)
		if (kvm_mmu_zap_page(kvm, sp))
			/* XXX ?*/
			node = container_of(kvm->arch.active_mmu_pages.next,
					    struct kvm_mmu_page, link);
	mutex_exit(&kvm->mmu_lock);

	kvm_flush_remote_tlbs(kvm);
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
	for (; start < end; start += PAGESIZE)
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

	assert(kvm->mmu_notifier_count >= 0);
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

void
kvm_arch_flush_shadow(struct kvm *kvm)
{
	kvm_mmu_zap_all(kvm);
	kvm_reload_remote_mmus(kvm);
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

	list_create(&kvmp->arch.active_mmu_pages, sizeof (struct kvm_mmu_page),
		    offsetof(struct kvm_mmu_page, link));
 
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
#endif /*XXX*/

	mutex_init(&kvmp->lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&kvmp->irq_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&kvmp->slots_lock, NULL, MUTEX_DRIVER, NULL);
	kvmp->kvmid = kvmid++;
	mutex_enter(&kvm_lock);
	kvmp->users_count = 1;
	list_insert_tail(&vm_list, kvmp);
	mutex_exit(&kvm_lock);

	return (kvmp);
}
	
static int
kvm_dev_ioctl_create_vm(intptr_t arg, int mode)
{
	struct kvm *kvmp;

	kvmp = kvm_create_vm();
	if (kvmp == NULL) {
		cmn_err(CE_WARN, "Could not create new vm\n");
		return (EIO);
	}
	
	if (ddi_copyout(&kvmp->kvmid, (void *)arg, sizeof(kvmp->kvmid), mode)
	    != 0) {
		/* XXX kvm_destroy_vm(kvmp);*/
		return (EFAULT);
	}
	return (DDI_SUCCESS);
}

extern int kvm_dev_ioctl_check_extension(long ext, int *rval_p);

static long
kvm_dev_ioctl_check_extension_generic(long arg, int *rval_p)
{
	switch (arg) {
	case KVM_CAP_USER_MEMORY:
	case KVM_CAP_DESTROY_MEMORY_REGION_WORKS:
	case KVM_CAP_JOIN_MEMORY_REGIONS_WORKS:
#ifdef CONFIG_KVM_APIC_ARCHITECTURE
	case KVM_CAP_SET_BOOT_CPU_ID:
#endif
	case KVM_CAP_INTERNAL_ERROR_DATA:
		*rval_p = 1;
		return DDI_SUCCESS;
#ifdef CONFIG_HAVE_KVM_IRQCHIP
	case KVM_CAP_IRQ_ROUTING:
		*rval_p = KVM_MAX_IRQ_ROUTES;
		return DDI_SUCCESS;
#endif
	default:
		break;
	}
	return kvm_dev_ioctl_check_extension(arg, rval_p);
}


/*
 * Caculate mmu pages needed for kvm.
 */
unsigned int kvm_mmu_calculate_mmu_pages(struct kvm *kvm)
{
	int i;
	unsigned int nr_mmu_pages;
	unsigned int  nr_pages = 0;
	struct kvm_memslots *slots;

	slots = kvm->memslots;
	for (i = 0; i < slots->nmemslots; i++)
		nr_pages += slots->memslots[i].npages;

	nr_mmu_pages = nr_pages * KVM_PERMILLE_MMU_PAGES / 1000;
	nr_mmu_pages = max(nr_mmu_pages,
			(unsigned int) KVM_MIN_ALLOC_MMU_PAGES);

	return nr_mmu_pages;
}

/*
 * Changing the number of mmu pages allocated to the vm
 * Note: if kvm_nr_mmu_pages is too small, you will get dead lock
 */
void kvm_mmu_change_mmu_pages(struct kvm *kvm, unsigned int kvm_nr_mmu_pages)
{
	int used_pages;

	used_pages = kvm->arch.n_alloc_mmu_pages - kvm->arch.n_free_mmu_pages;
	used_pages = max(0, used_pages);

	/* for the time being, assume that address space will only grow */
	/* larger.  The following code will be added later. */
#ifdef XXX
	/*
	 * If we set the number of mmu pages to be smaller be than the
	 * number of actived pages , we must to free some mmu pages before we
	 * change the value
	 */

	if (used_pages > kvm_nr_mmu_pages) {
		while (used_pages > kvm_nr_mmu_pages &&
			!list_is_empty(&kvm->arch.active_mmu_pages)) {
			struct kvm_mmu_page *page;

			page = container_of(kvm->arch.active_mmu_pages.prev,
					    struct kvm_mmu_page, link);
			used_pages -= kvm_mmu_zap_page(kvm, page);
			used_pages--;
		}
		kvm_nr_mmu_pages = used_pages;
		kvm->arch.n_free_mmu_pages = 0;
	}
	else
#endif /*XXX*/
		kvm->arch.n_free_mmu_pages += kvm_nr_mmu_pages
					 - kvm->arch.n_alloc_mmu_pages;

	kvm->arch.n_alloc_mmu_pages = kvm_nr_mmu_pages;
}

void kvm_arch_commit_memory_region(struct kvm *kvm,
				struct kvm_userspace_memory_region *mem,
				struct kvm_memory_slot old,
				int user_alloc)
{

	int npages = mem->memory_size >> PAGESHIFT;
#ifdef XXX
	if (!user_alloc && !old.user_alloc && old.rmap && !npages) {
		int ret;

		down_write(&current->mm->mmap_sem);
		ret = do_munmap(current->mm, old.userspace_addr,
				old.npages * PAGESIZE);
		up_write(&current->mm->mmap_sem);
		if (ret < 0)
			cmn_err(CE_WARN,
			       "kvm_vm_ioctl_set_memory_region: "
			       "failed to munmap memory\n");
	}
#endif
	mutex_enter(&kvm->mmu_lock);
	if (!kvm->arch.n_requested_mmu_pages) {
		unsigned int nr_mmu_pages = kvm_mmu_calculate_mmu_pages(kvm);
		kvm_mmu_change_mmu_pages(kvm, nr_mmu_pages);
	}

#ifdef XXX
	kvm_mmu_slot_remove_write_access(kvm, mem->slot);
#endif /*XXX*/
	mutex_exit(&kvm->mmu_lock);
}

/*
 * Free any memory in @free but not in @dont.
 */
static void kvm_free_physmem_slot(struct kvm_memory_slot *free,
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
#endif /*XXX*/
}

extern int kvm_arch_prepare_memory_region(struct kvm *kvm,
				struct kvm_memory_slot *memslot,
				struct kvm_memory_slot old,
				struct kvm_userspace_memory_region *mem,
					  int user_alloc);

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
			    struct kvm_userspace_memory_region *mem,
			    int user_alloc)
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
#ifndef CONFIG_S390
	if (npages && !new.rmap) {
		new.rmap = kmem_alloc(npages * sizeof(struct page *), KM_SLEEP);

		if (!new.rmap)
			goto out_free;

		memset(new.rmap, 0, npages * sizeof(*new.rmap));

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
		(void)level;

		if (new.lpage_info[i])
			continue;

		lpages = 1 + (base_gfn + npages - 1) /
			     KVM_PAGES_PER_HPAGE(level);
		lpages -= base_gfn / KVM_PAGES_PER_HPAGE(level);

		new.lpage_info[i] = kmem_alloc(lpages * sizeof(*new.lpage_info[i]), KM_SLEEP);

		if (!new.lpage_info[i])
			goto out_free;

		memset(new.lpage_info[i], 0,
		       lpages * sizeof(*new.lpage_info[i]));

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

		new.dirty_bitmap = kmem_alloc(dirty_bytes, KM_SLEEP);
		if (!new.dirty_bitmap)
			goto out_free;
		memset(new.dirty_bitmap, 0, dirty_bytes);
		/* destroy any largepage mappings for dirty tracking */
		if (old.npages)
			flush_shadow = 1;
	}
#else  /* not defined CONFIG_S390 */
	new.user_alloc = user_alloc;
	if (user_alloc)
		new.userspace_addr = mem->userspace_addr;
#endif /* not defined CONFIG_S390 */

	if (!npages) {
		r = ENOMEM;
		slots = kmem_zalloc(sizeof(struct kvm_memslots), KM_SLEEP);
		if (!slots)
			goto out_free;
		memcpy(slots, kvmp->memslots, sizeof(struct kvm_memslots));
		if (mem->slot >= slots->nmemslots)
			slots->nmemslots = mem->slot + 1;
		slots->memslots[mem->slot].flags |= KVM_MEMSLOT_INVALID;

		old_memslots = kvmp->memslots;
#ifdef XXX
		rcu_assign_pointer(kvmp->memslots, slots);
		synchronize_srcu_expedited(&kvm->srcu);
		/* From this point no new shadow pages pointing to a deleted
		 * memslot will be created.
		 *
		 * validation of sp->gfn happens in:
		 * 	- gfn_to_hva (kvm_read_guest, gfn_to_pfn)
		 * 	- kvm_is_visible_gfn (mmu_check_roots)
		 */
		kvm_arch_flush_shadow(kvmp);
		kmem_free(old_memslots); /* how many bytes to free??? */
#endif /*XXX*/
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
	slots = kmem_zalloc(sizeof(struct kvm_memslots), KM_SLEEP);
	if (!slots)
		goto out_free;
	memcpy(slots, kvmp->memslots, sizeof(struct kvm_memslots));
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
#endif /*XXX*/

	kvm_arch_commit_memory_region(kvmp, mem, old, user_alloc);

	kvm_free_physmem_slot(&old, &new);
#ifdef XXX
	kmem_free(old_memslots);
	if (flush_shadow)
		kvm_arch_flush_shadow(kvmp);
#endif /*XXX*/

	return DDI_SUCCESS;

out_free:
	kvm_free_physmem_slot(&new, &old);
out:
	return r;

}

int
kvm_set_memory_region(struct kvm *kvm,
			  struct kvm_userspace_memory_region *mem,
			  int user_alloc)
{
	int r;

	mutex_enter(&kvm->slots_lock);
	r = __kvm_set_memory_region(kvm, mem, user_alloc);
	mutex_exit(&kvm->slots_lock);
	return r;
}

static int
vmx_set_tss_addr(struct kvm *kvmp, uintptr_t addr)
{
	int ret;
	struct kvm_userspace_memory_region tss_mem = {
		.slot = TSS_PRIVATE_MEMSLOT,
		.guest_phys_addr = addr,
		.memory_size = PAGESIZE * 3,
		.flags = 0,
	};

	ret = kvm_set_memory_region(kvmp, &tss_mem, 0);
	if (ret)
		return ret;
	kvmp->arch.tss_addr = addr;
	return DDI_SUCCESS;
}

static int
kvm_vm_ioctl_set_tss_addr(struct kvm *kvmp, uintptr_t addr)
{
	/* XXX later, if adding other arch beside x86, need to do something else here */
	return vmx_set_tss_addr(kvmp, addr);
}

struct kvm *
find_kvm_id(int id)
{
	struct kvm *kvmp;

	mutex_enter(&kvm_lock);
	kvmp = list_head(&vm_list);
	while(kvmp) {
		if (kvmp->kvmid == id)
			break;
		kvmp = list_next(&vm_list, kvmp);
	}
	mutex_exit(&kvm_lock);
	return (kvmp);
}

extern int kvm_vm_ioctl_create_vcpu(struct kvm *kvm, uint32_t id,
				    struct kvm_vcpu_ioc *kvm_vcpu, int *rval_p);

static inline void native_cpuid(unsigned int *eax, unsigned int *ebx,
				unsigned int *ecx, unsigned int *edx)
{
	/* ecx is often an input as well as an output. */
	asm volatile("cpuid"
	    : "=a" (*eax),
	      "=b" (*ebx),
	      "=c" (*ecx),
	      "=d" (*edx)
	    : "0" (*eax), "2" (*ecx));
}

#define __cpuid			native_cpuid

/* Some CPUID calls want 'count' to be placed in ecx */
static inline void cpuid_count(unsigned int op, int count,
			       unsigned int *eax, unsigned int *ebx,
			       unsigned int *ecx, unsigned int *edx)
{
	*eax = op;
	*ecx = count;
	__cpuid(eax, ebx, ecx, edx);
}

static void do_cpuid_1_ent(struct kvm_cpuid_entry2 *entry, uint32_t function,
			   uint32_t index)
{
	entry->function = function;
	entry->index = index;
	cpuid_count(entry->function, entry->index,
		    &entry->eax, &entry->ebx, &entry->ecx, &entry->edx);
	entry->flags = 0;
}

#define MSR_EFER		0xc0000080 /* extended feature register */
/* EFER bits: */
#define _EFER_SCE		0  /* SYSCALL/SYSRET */
#define _EFER_LME		8  /* Long mode enable */
#define _EFER_LMA		10 /* Long mode active (read-only) */
#define _EFER_NX		11 /* No execute enable */
#define _EFER_SVME		12 /* Enable virtualization */
#define _EFER_FFXSR		14 /* Enable Fast FXSAVE/FXRSTOR */

#define EFER_SCE		(1<<_EFER_SCE)
#define EFER_LME		(1<<_EFER_LME)
#define EFER_LMA		(1<<_EFER_LMA)
#define EFER_NX			(1<<_EFER_NX)
#define EFER_SVME		(1<<_EFER_SVME)
#define EFER_FFXSR		(1<<_EFER_FFXSR)
/* Intel-defined CPU features, CPUID level 0x00000001 (edx), word 0 */
#define X86_FEATURE_FPU		(0*32+ 0) /* Onboard FPU */
#define X86_FEATURE_VME		(0*32+ 1) /* Virtual Mode Extensions */
#define X86_FEATURE_DE		(0*32+ 2) /* Debugging Extensions */
#define X86_FEATURE_PSE		(0*32+ 3) /* Page Size Extensions */
#define X86_FEATURE_TSC		(0*32+ 4) /* Time Stamp Counter */
#define X86_FEATURE_MSR		(0*32+ 5) /* Model-Specific Registers */
#define X86_FEATURE_PAE		(0*32+ 6) /* Physical Address Extensions */
#define X86_FEATURE_MCE		(0*32+ 7) /* Machine Check Exception */
#define X86_FEATURE_CX8		(0*32+ 8) /* CMPXCHG8 instruction */
#define X86_FEATURE_APIC	(0*32+ 9) /* Onboard APIC */
#define X86_FEATURE_SEP		(0*32+11) /* SYSENTER/SYSEXIT */
#define X86_FEATURE_MTRR	(0*32+12) /* Memory Type Range Registers */
#define X86_FEATURE_PGE		(0*32+13) /* Page Global Enable */
#define X86_FEATURE_MCA		(0*32+14) /* Machine Check Architecture */
#define X86_FEATURE_CMOV	(0*32+15) /* CMOV instructions */
					  /* (plus FCMOVcc, FCOMI with FPU) */
#define X86_FEATURE_PAT		(0*32+16) /* Page Attribute Table */
#define X86_FEATURE_PSE36	(0*32+17) /* 36-bit PSEs */
#define X86_FEATURE_PN		(0*32+18) /* Processor serial number */
#define X86_FEATURE_CLFLSH	(0*32+19) /* "clflush" CLFLUSH instruction */
#define X86_FEATURE_DS		(0*32+21) /* "dts" Debug Store */
#define X86_FEATURE_ACPI	(0*32+22) /* ACPI via MSR */
#define X86_FEATURE_MMX		(0*32+23) /* Multimedia Extensions */
#define X86_FEATURE_FXSR	(0*32+24) /* FXSAVE/FXRSTOR, CR4.OSFXSR */
#define X86_FEATURE_XMM		(0*32+25) /* "sse" */
#define X86_FEATURE_XMM2	(0*32+26) /* "sse2" */
#define X86_FEATURE_SELFSNOOP	(0*32+27) /* "ss" CPU self snoop */
#define X86_FEATURE_HT		(0*32+28) /* Hyper-Threading */
#define X86_FEATURE_ACC		(0*32+29) /* "tm" Automatic clock control */
#define X86_FEATURE_IA64	(0*32+30) /* IA-64 processor */
#define X86_FEATURE_PBE		(0*32+31) /* Pending Break Enable */

/* AMD-defined CPU features, CPUID level 0x80000001, word 1 */
/* Don't duplicate feature flags which are redundant with Intel! */
#define X86_FEATURE_SYSCALL	(1*32+11) /* SYSCALL/SYSRET */
#define X86_FEATURE_MP		(1*32+19) /* MP Capable. */
#define X86_FEATURE_NX		(1*32+20) /* Execute Disable */
#define X86_FEATURE_MMXEXT	(1*32+22) /* AMD MMX extensions */
#define X86_FEATURE_FXSR_OPT	(1*32+25) /* FXSAVE/FXRSTOR optimizations */
#define X86_FEATURE_GBPAGES	(1*32+26) /* "pdpe1gb" GB pages */
#define X86_FEATURE_RDTSCP	(1*32+27) /* RDTSCP */
#define X86_FEATURE_LM		(1*32+29) /* Long Mode (x86-64) */
#define X86_FEATURE_3DNOWEXT	(1*32+30) /* AMD 3DNow! extensions */
#define X86_FEATURE_3DNOW	(1*32+31) /* 3DNow! */

/* cpu types for specific tunings: */
#define X86_FEATURE_K8		(3*32+ 4) /* "" Opteron, Athlon64 */
#define X86_FEATURE_K7		(3*32+ 5) /* "" Athlon */
#define X86_FEATURE_P3		(3*32+ 6) /* "" P3 */
#define X86_FEATURE_P4		(3*32+ 7) /* "" P4 */
#define X86_FEATURE_CONSTANT_TSC (3*32+ 8) /* TSC ticks at a constant rate */
#define X86_FEATURE_UP		(3*32+ 9) /* smp kernel running on up */
#define X86_FEATURE_FXSAVE_LEAK (3*32+10) /* "" FXSAVE leaks FOP/FIP/FOP */
#define X86_FEATURE_ARCH_PERFMON (3*32+11) /* Intel Architectural PerfMon */
#define X86_FEATURE_PEBS	(3*32+12) /* Precise-Event Based Sampling */
#define X86_FEATURE_BTS		(3*32+13) /* Branch Trace Store */
#define X86_FEATURE_SYSCALL32	(3*32+14) /* "" syscall in ia32 userspace */
#define X86_FEATURE_SYSENTER32	(3*32+15) /* "" sysenter in ia32 userspace */
#define X86_FEATURE_REP_GOOD	(3*32+16) /* rep microcode works well */
#define X86_FEATURE_MFENCE_RDTSC (3*32+17) /* "" Mfence synchronizes RDTSC */
#define X86_FEATURE_LFENCE_RDTSC (3*32+18) /* "" Lfence synchronizes RDTSC */
#define X86_FEATURE_11AP	(3*32+19) /* "" Bad local APIC aka 11AP */
#define X86_FEATURE_NOPL	(3*32+20) /* The NOPL (0F 1F) instructions */
#define X86_FEATURE_AMDC1E	(3*32+21) /* AMD C1E detected */
#define X86_FEATURE_XTOPOLOGY	(3*32+22) /* cpu topology enum extensions */
#define X86_FEATURE_TSC_RELIABLE (3*32+23) /* TSC is known to be reliable */
#define X86_FEATURE_NONSTOP_TSC	(3*32+24) /* TSC does not stop in C states */
#define X86_FEATURE_CLFLUSH_MONITOR (3*32+25) /* "" clflush reqd with monitor */
#define X86_FEATURE_EXTD_APICID	(3*32+26) /* has extended APICID (8 bits) */
#define X86_FEATURE_AMD_DCM     (3*32+27) /* multi-node processor */
#define X86_FEATURE_APERFMPERF	(3*32+28) /* APERFMPERF */

/* Intel-defined CPU features, CPUID level 0x00000001 (ecx), word 4 */
#define X86_FEATURE_XMM3	(4*32+ 0) /* "pni" SSE-3 */
#define X86_FEATURE_PCLMULQDQ	(4*32+ 1) /* PCLMULQDQ instruction */
#define X86_FEATURE_DTES64	(4*32+ 2) /* 64-bit Debug Store */
#define X86_FEATURE_MWAIT	(4*32+ 3) /* "monitor" Monitor/Mwait support */
#define X86_FEATURE_DSCPL	(4*32+ 4) /* "ds_cpl" CPL Qual. Debug Store */
#define X86_FEATURE_VMX		(4*32+ 5) /* Hardware virtualization */
#define X86_FEATURE_SMX		(4*32+ 6) /* Safer mode */
#define X86_FEATURE_EST		(4*32+ 7) /* Enhanced SpeedStep */
#define X86_FEATURE_TM2		(4*32+ 8) /* Thermal Monitor 2 */
#define X86_FEATURE_SSSE3	(4*32+ 9) /* Supplemental SSE-3 */
#define X86_FEATURE_CID		(4*32+10) /* Context ID */
#define X86_FEATURE_FMA		(4*32+12) /* Fused multiply-add */
#define X86_FEATURE_CX16	(4*32+13) /* CMPXCHG16B */
#define X86_FEATURE_XTPR	(4*32+14) /* Send Task Priority Messages */
#define X86_FEATURE_PDCM	(4*32+15) /* Performance Capabilities */
#define X86_FEATURE_DCA		(4*32+18) /* Direct Cache Access */
#define X86_FEATURE_XMM4_1	(4*32+19) /* "sse4_1" SSE-4.1 */
#define X86_FEATURE_XMM4_2	(4*32+20) /* "sse4_2" SSE-4.2 */
#define X86_FEATURE_X2APIC	(4*32+21) /* x2APIC */
#define X86_FEATURE_MOVBE	(4*32+22) /* MOVBE instruction */
#define X86_FEATURE_POPCNT      (4*32+23) /* POPCNT instruction */
#define X86_FEATURE_AES		(4*32+25) /* AES instructions */
#define X86_FEATURE_XSAVE	(4*32+26) /* XSAVE/XRSTOR/XSETBV/XGETBV */
#define X86_FEATURE_OSXSAVE	(4*32+27) /* "" XSAVE enabled in the OS */
#define X86_FEATURE_AVX		(4*32+28) /* Advanced Vector Extensions */
#define X86_FEATURE_HYPERVISOR	(4*32+31) /* Running on a hypervisor */

/* More extended AMD flags: CPUID level 0x80000001, ecx, word 6 */
#define X86_FEATURE_LAHF_LM	(6*32+ 0) /* LAHF/SAHF in long mode */
#define X86_FEATURE_CMP_LEGACY	(6*32+ 1) /* If yes HyperThreading not valid */
#define X86_FEATURE_SVM		(6*32+ 2) /* Secure virtual machine */
#define X86_FEATURE_EXTAPIC	(6*32+ 3) /* Extended APIC space */
#define X86_FEATURE_CR8_LEGACY	(6*32+ 4) /* CR8 in 32-bit mode */
#define X86_FEATURE_ABM		(6*32+ 5) /* Advanced bit manipulation */
#define X86_FEATURE_SSE4A	(6*32+ 6) /* SSE-4A */
#define X86_FEATURE_MISALIGNSSE (6*32+ 7) /* Misaligned SSE mode */
#define X86_FEATURE_3DNOWPREFETCH (6*32+ 8) /* 3DNow prefetch instructions */
#define X86_FEATURE_OSVW	(6*32+ 9) /* OS Visible Workaround */
#define X86_FEATURE_IBS		(6*32+10) /* Instruction Based Sampling */
#define X86_FEATURE_SSE5	(6*32+11) /* SSE-5 */
#define X86_FEATURE_SKINIT	(6*32+12) /* SKINIT/STGI instructions */
#define X86_FEATURE_WDT		(6*32+13) /* Watchdog timer */
#define X86_FEATURE_NODEID_MSR	(6*32+19) /* NodeId MSR */

/* Transmeta-defined CPU features, CPUID level 0x80860001, word 2 */
#define X86_FEATURE_RECOVERY	(2*32+ 0) /* CPU in recovery mode */
#define X86_FEATURE_LONGRUN	(2*32+ 1) /* Longrun power control */
#define X86_FEATURE_LRTI	(2*32+ 3) /* LongRun table interface */


static int is_efer_nx(void)
{
	unsigned long long efer = 0;

	rdmsrl_safe(MSR_EFER, &efer);
	return efer & EFER_NX;
}

static inline uint32_t bit(int bitno)
{
	return 1 << (bitno & 31);
}

static inline int cpu_has_vmx_ept_1g_page(void)
{
	return !!(vmx_capability.ept & VMX_EPT_1GB_PAGE_BIT);
}

static int vmx_get_lpage_level(void)
{
	if (enable_ept && !cpu_has_vmx_ept_1g_page())
		return PT_DIRECTORY_LEVEL;
	else
		/* For shadow and EPT supported 1GB page */
		return PT_PDPE_LEVEL;
}

static inline int cpu_has_vmx_rdtscp(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_RDTSCP;
}

static int vmx_rdtscp_supported(void)
{
	return cpu_has_vmx_rdtscp();
}


#define F(x) bit(X86_FEATURE_##x)

static void do_cpuid_ent(struct kvm_cpuid_entry2 *entry, uint32_t function,
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

	volatile int x;  /* XXX - dtrace return probe missing */

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
		/* we support x2apic emulation even if host does not support
		 * it since we emulate x2apic in software */
		entry->ecx |= F(X2APIC);
		break;
	/* function 2 entries are STATEFUL. That is, repeated cpuid commands
	 * may return different values. This forces us to get_cpu() before
	 * issuing the first command, and also to emulate this annoying behavior
	 * in kvm_emulate_cpuid() using KVM_CPUID_FLAG_STATE_READ_NEXT */
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
			entry[i].flags |=
			       KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
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
			entry[i].flags |=
			       KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
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
	/*XXX - see comment above for ddi_enter_critical() */
	/*ddi_exit_critical(ddic);*/
	kpreempt_enable();
	x = 10; /*XXX*/
}

#undef F

static int kvm_dev_ioctl_get_supported_cpuid(struct kvm_cpuid2 *cpuid,
					     struct kvm_cpuid_entry2  *entries,
					     int mode)
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
	allocsize = sizeof(struct kvm_cpuid_entry2)*cpuid->nent;
	cpuid_entries = kmem_alloc(allocsize, KM_SLEEP);
	if (!cpuid_entries)
		goto out;

	do_cpuid_ent(&cpuid_entries[0], 0, 0, &nent, cpuid->nent);
	limit = cpuid_entries[0].eax;
	for (func = 1; func <= limit && nent < cpuid->nent; ++func)
		do_cpuid_ent(&cpuid_entries[nent], func, 0,
			     &nent, cpuid->nent);
	r = E2BIG;
	if (nent >= cpuid->nent)
		goto out_free;

	do_cpuid_ent(&cpuid_entries[nent], 0x80000000, 0, &nent, cpuid->nent);
	limit = cpuid_entries[nent - 1].eax;
	for (func = 0x80000001; func <= limit && nent < cpuid->nent; ++func)
		do_cpuid_ent(&cpuid_entries[nent], func, 0,
			     &nent, cpuid->nent);
	r = E2BIG;
	if (nent >= cpuid->nent)
		goto out_free;

	r = EFAULT;
	if (ddi_copyout(cpuid_entries, entries,
			nent * sizeof(struct kvm_cpuid_entry2), mode))
		goto out_free;
	cpuid->nent = nent;
	r = 0;

out_free:
	kmem_free(cpuid_entries, allocsize);
out:
	return r;
}

#define __ex(x) __kvm_handle_fault_on_reboot(x)


void vmcs_clear(struct vmcs *vmcs)
{
	unsigned char error;
	uint64_t phys_addr = (hat_getpfnum(kas.a_hat, (char *)vmcs)<<PAGESHIFT)|((uint64_t)vmcs&PAGEOFFSET);
	volatile int x;  /*XXX - dtrace return probe missing */

	asm volatile (__ex(ASM_VMX_VMCLEAR_RAX) "\n\tsetna %0\n"
		      : "=g"(error) : "a"(&phys_addr), "m"(phys_addr)
		      : "cc", "memory");
	if (error)
		cmn_err(CE_PANIC, "kvm: vmclear fail: %p/%llx\n",
		       vmcs, phys_addr);
	x = 10; /*XXX*/
}

static void __vcpu_clear(void *arg)
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
#endif
	vmx->vcpu.cpu = -1;
	vmx->launched = 0;
}

static void vcpu_clear(struct vcpu_vmx *vmx)
{
	if (vmx->vcpu.cpu == -1)
		return;
/*	smp_call_function_single(vmx->vcpu.cpu, __vcpu_clear, vmx, 1);*/
	__vcpu_clear(vmx);
}



static void vmwrite_error(unsigned long field, unsigned long value)
{
	cmn_err(CE_WARN, "vmwrite error: reg %lx value %lx (err %d)\n",
	       field, value, vmcs_read32(VM_INSTRUCTION_ERROR));
}

void vmcs_writel(unsigned long field, unsigned long value)
{
	unsigned char error;

	asm volatile (ASM_VMX_VMWRITE_RAX_RDX "\n\tsetna %0"
		       : "=q"(error) : "a"(value), "d"(field) : "cc");
	if ((error))
		vmwrite_error(field, value);
}

unsigned long vmcs_readl(unsigned long field)
{
	unsigned long value;

	asm volatile (__ex(ASM_VMX_VMREAD_RDX_RAX)
		      : "=a"(value) : "d"(field) : "cc");
	return value;
}

uint64_t vmcs_read64(unsigned long field)
{
#ifdef CONFIG_X86_64
	return vmcs_readl(field);
#else
	return vmcs_readl(field) | ((uint64_t)vmcs_readl(field+1) << 32);
#endif
}

uint16_t vmcs_read16(unsigned long field)
{
	return vmcs_readl(field);
}

void vmcs_write64(unsigned long field, uint64_t value)
{
	vmcs_writel(field, value);
#ifndef CONFIG_X86_64
	asm volatile ("");
	vmcs_writel(field+1, value >> 32);
#endif
}


void vmcs_write16(unsigned long field, uint16_t value)
{
	vmcs_writel(field, value);
}

/*
 * writes 'guest_tsc' into guest's timestamp counter "register"
 * guest_tsc = host_tsc + tsc_offset ==> tsc_offset = guest_tsc - host_tsc
 */
static void guest_write_tsc(uint64_t guest_tsc, uint64_t host_tsc)
{
	vmcs_write64(TSC_OFFSET, guest_tsc - host_tsc);
}

static inline int cpu_has_secondary_exec_ctrls(void)
{
	return vmcs_config.cpu_based_exec_ctrl &
		CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
}

int vm_need_virtualize_apic_accesses(struct kvm *kvm)
{
	return flexpriority_enabled && irqchip_in_kernel(kvm);
}

extern uint64_t kvm_va2pa(caddr_t va);
/*
 * Sets up the vmcs for emulated real mode.
 */
int vmx_vcpu_setup(struct vcpu_vmx *vmx)
{
	uint32_t host_sysenter_cs, msr_low, msr_high;
	uint32_t junk;
	uint64_t host_pat, tsc_this, tsc_base;
	unsigned long a;
	struct descriptor_table dt;
	int i;
	unsigned long kvm_vmx_return;
	uint32_t exec_control;

	/* I/O */
	vmcs_write64(IO_BITMAP_A, kvm_va2pa((caddr_t)vmx_io_bitmap_a));
	vmcs_write64(IO_BITMAP_B, kvm_va2pa((caddr_t)vmx_io_bitmap_b));

	if (cpu_has_vmx_msr_bitmap())
		vmcs_write64(MSR_BITMAP, kvm_va2pa((caddr_t)vmx_msr_bitmap_legacy));

	vmcs_write64(VMCS_LINK_POINTER, -1ull); /* 22.3.1.5 */

	/* Control */
	vmcs_write32(PIN_BASED_VM_EXEC_CONTROL,
		vmcs_config.pin_based_exec_ctrl);

	exec_control = vmcs_config.cpu_based_exec_ctrl;
#ifdef XXX
	if (!vm_need_tpr_shadow(vmx->vcpu.kvm)) {
		exec_control &= ~CPU_BASED_TPR_SHADOW;
#ifdef CONFIG_X86_64
		exec_control |= CPU_BASED_CR8_STORE_EXITING |
				CPU_BASED_CR8_LOAD_EXITING;
#endif
	}
#endif /*XXX*/

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
#ifdef XXX
		if (!ple_gap)
#endif /*XXX*/
			exec_control &= ~SECONDARY_EXEC_PAUSE_LOOP_EXITING;
		vmcs_write32(SECONDARY_VM_EXEC_CONTROL, exec_control);
	}

#ifdef XXX
	if (ple_gap) {
		vmcs_write32(PLE_GAP, ple_gap);
		vmcs_write32(PLE_WINDOW, ple_window);
	}
#endif /*XXX*/

	vmcs_write32(PAGE_FAULT_ERROR_CODE_MASK, !!bypass_guest_pf);
	vmcs_write32(PAGE_FAULT_ERROR_CODE_MATCH, !!bypass_guest_pf);
	vmcs_write32(CR3_TARGET_COUNT, 0);           /* 22.2.1 */

	vmcs_writel(HOST_CR0, getcr0());  /* 22.2.3 */
	vmcs_writel(HOST_CR4, getcr4());  /* 22.2.3, 22.2.5 */
	vmcs_writel(HOST_CR3, getcr3());  /* 22.2.3  FIXME: shadow tables */

	vmcs_write16(HOST_CS_SELECTOR, GDT_KCODE);  /* 22.2.4 */
	vmcs_write16(HOST_DS_SELECTOR, GDT_KDATA);  /* 22.2.4 */
	vmcs_write16(HOST_ES_SELECTOR, GDT_KDATA);  /* 22.2.4 */
	vmcs_write16(HOST_FS_SELECTOR, kvm_read_fs());    /* 22.2.4 */
	vmcs_write16(HOST_GS_SELECTOR, kvm_read_gs());    /* 22.2.4 */
	vmcs_write16(HOST_SS_SELECTOR, GDT_KDATA);  /* 22.2.4 */
#ifdef CONFIG_X86_64
	rdmsrl(MSR_FS_BASE, a);
	vmcs_writel(HOST_FS_BASE, a); /* 22.2.4 */
	rdmsrl(MSR_GS_BASE, a);
	vmcs_writel(HOST_GS_BASE, a); /* 22.2.4 */
#else
	vmcs_writel(HOST_FS_BASE, 0); /* 22.2.4 */
	vmcs_writel(HOST_GS_BASE, 0); /* 22.2.4 */
#endif

	vmcs_write16(HOST_TR_SELECTOR, GDT_ENTRY_TSS*8);  /* 22.2.4 */

	kvm_get_idt(&dt);
	vmcs_writel(HOST_IDTR_BASE, dt.base);   /* 22.2.4 */

	asm("mov $.Lkvm_vmx_return, %0" : "=r"(kvm_vmx_return));
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
	return 0;
}

/*
 * Switches to specified vcpu, until a matching vcpu_put(), but assumes
 * vcpu mutex is already taken.
 */
void vmx_vcpu_load(struct kvm_vcpu *vcpu, int cpu)
{
	/* XXX - the following assignment assumes vmx contains vcpu */
	/* at the beginning of the structure */

	struct vcpu_vmx *vmx = (struct vcpu_vmx *)vcpu; 
	uint64_t phys_addr = (hat_getpfnum(kas.a_hat, (char *)vmx->vmcs)<<PAGESHIFT)|((uint64_t)(vmx->vmcs)&0xfff);
	uint64_t tsc_this, delta, new_offset;
	volatile int x;  /* XXX - dtrace return probe missing */

	if (vcpu->cpu != cpu) {
		vcpu_clear(vmx);
#ifdef XXX
		kvm_migrate_timers(vcpu);
#endif /*XXX*/
		BT_SET(&vcpu->requests, KVM_REQ_TLB_FLUSH);
#ifdef XXX
		kpreempt_disable();
		list_add(&vmx->local_vcpus_link,
			 &per_cpu(vcpus_on_cpu, cpu));
		kpreempt_enable();
#endif /*XXX*/
	}

#ifdef XXX
	if (per_cpu(current_vmcs, cpu) != vmx->vmcs) {
		uint8_t error;

		per_cpu(current_vmcs, cpu) = vmx->vmcs;

		asm volatile (__ex(ASM_VMX_VMPTRLD_RAX) "; setna %0"
			      : "=g"(error) : "a"(&phys_addr), "m"(phys_addr)
			      : "cc");
#else
		{
		uint8_t error;
		asm volatile (ASM_VMX_VMPTRLD_RAX ";\n\t setna %0"
			      : "=g"(error) : "a"(&phys_addr), "m"(phys_addr)
			      : "cc");

		if (error)
			cmn_err(CE_PANIC, "kvm: vmptrld %p/%llx fail\n",
			       vmx->vmcs, phys_addr);
		}
#endif /*XXX*/
#ifdef XXX
	}
#endif

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
	x = 10;
	return;
}

void kvm_arch_vcpu_load(struct kvm_vcpu *vcpu, int cpu)
{
	kvm_x86_ops->vcpu_load(vcpu, cpu);
#ifdef XXX
	if (unlikely(per_cpu(cpu_tsc_khz, cpu) == 0)) {
		unsigned long khz = cpufreq_quick_get(cpu);
		if (!khz)
			khz = tsc_khz;
		per_cpu(cpu_tsc_khz, cpu) = khz;
	}
	kvm_request_guest_time_update(vcpu);
#endif /*XXX*/
}

void kvm_put_guest_fpu(struct kvm_vcpu *vcpu)
{
	if (!vcpu->guest_fpu_loaded)
		return;

#ifdef XXX
	vcpu->guest_fpu_loaded = 0;
	kvm_fx_save(&vcpu->arch.guest_fx_image);
	kvm_fx_restore(&vcpu->arch.host_fx_image);
	++vcpu->stat.fpu_reload;
	BT_BIT(&vcpu->requests, KVM_REQ_DEACTIVATE_FPU);
	trace_kvm_fpu(0);
#endif /*XXX*/
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
	descs[GDT_ENTRY_TSS].c.b.type = 9; /* available TSS */
	load_TR_desc();
}

int is_long_mode(struct kvm_vcpu *vcpu)
{
#ifdef CONFIG_X86_64
	return vcpu->arch.efer & EFER_LMA;
#else
	return 0;
#endif
}

#define KVM_POSSIBLE_CR0_GUEST_BITS X86_CR0_TS
#define KVM_POSSIBLE_CR4_GUEST_BITS				  \
	(X86_CR4_PVI | X86_CR4_DE | X86_CR4_PCE | X86_CR4_OSFXSR  \
	 | X86_CR4_OSXMMEXCPT | X86_CR4_PGE)

ulong kvm_read_cr4_bits(struct kvm_vcpu *vcpu, ulong mask)
{
	uint64_t tmask = mask & KVM_POSSIBLE_CR4_GUEST_BITS;
#ifdef XXX
	if (tmask & vcpu->arch.cr4_guest_owned_bits)
		kvm_x86_ops->decache_cr4_guest_bits(vcpu);
#endif /*XXX*/
	return vcpu->arch.cr4 & mask;
}

static inline int is_pae(struct kvm_vcpu *vcpu)
{
	return kvm_read_cr4_bits(vcpu, X86_CR4_PAE);
}


static void
__vmx_load_host_state(struct vcpu_vmx *vmx)
{
	unsigned long flags;

	if (!vmx->host_state.loaded)
		return;

#ifdef XXX  /* kstat stuff */
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
		kpreempt_disable();
		kvm_load_gs(vmx->host_state.gs_sel);
#ifdef CONFIG_X86_64
		wrmsrl(MSR_GS_BASE, vmcs_readl(HOST_GS_BASE));
#endif
		kpreempt_enable();
	}
	reload_tss();

#ifdef CONFIG_X86_64
	if (is_long_mode(&vmx->vcpu)) {
		rdmsrl(MSR_KERNEL_GS_BASE, vmx->msr_guest_kernel_gs_base);
		wrmsrl(MSR_KERNEL_GS_BASE, vmx->msr_host_kernel_gs_base);
	}
#endif
}

static void vmx_load_host_state(struct vcpu_vmx *vmx)
{
	kpreempt_disable();
	__vmx_load_host_state(vmx);
	kpreempt_enable();
}

void vmx_vcpu_put(struct kvm_vcpu *vcpu)
{
	__vmx_load_host_state((struct vcpu_vmx *)vcpu);
}

void kvm_arch_vcpu_put(struct kvm_vcpu *vcpu)
{
#ifdef XXX	
	kvm_put_guest_fpu(vcpu);
#endif

/*	kvm_x86_ops->vcpu_put(vcpu);*/
	vmx_vcpu_put(vcpu);
}

/*
 * Switches to specified vcpu, until a matching vcpu_put()
 */
void vcpu_load(struct kvm_vcpu *vcpu)
{
	int cpu;

	mutex_enter(&vcpu->mutex);
	kpreempt_disable();
	cpu = CPU->cpu_seqid;
#ifdef XXX
	preempt_notifier_register(&vcpu->preempt_notifier);
#endif /*XXX*/
	kvm_arch_vcpu_load(vcpu, cpu);
	kpreempt_enable();
}

void vcpu_put(struct kvm_vcpu *vcpu)
{
	kpreempt_disable();
	kvm_arch_vcpu_put(vcpu);
#ifdef XXX
	preempt_notifier_unregister(&vcpu->preempt_notifier);
#endif /*XXX*/
	kpreempt_enable();
	mutex_exit(&vcpu->mutex);
}

/* find an entry with matching function, matching index (if needed), and that
 * should be read next (if it's stateful) */
static int is_matching_cpuid_entry(struct kvm_cpuid_entry2 *e,
	uint32_t function, uint32_t index)
{
	if (e->function != function)
		return 0;
	if ((e->flags & KVM_CPUID_FLAG_SIGNIFCANT_INDEX) && e->index != index)
		return 0;
	if ((e->flags & KVM_CPUID_FLAG_STATEFUL_FUNC) &&
	    !(e->flags & KVM_CPUID_FLAG_STATE_READ_NEXT))
		return 0;
	return 1;
}

struct kvm_pic *pic_irqchip(struct kvm *kvm);
extern int irqchip_in_kernel(struct kvm *kvm);

static int move_to_next_stateful_cpuid_entry(struct kvm_vcpu *vcpu, int i)
{
	struct kvm_cpuid_entry2 *e = &vcpu->arch.cpuid_entries[i];
	int j, nent = vcpu->arch.cpuid_nent;

	e->flags &= ~KVM_CPUID_FLAG_STATE_READ_NEXT;
	/* when no next entry is found, the current entry[i] is reselected */
	for (j = i + 1; ; j = (j + 1) % nent) {
		struct kvm_cpuid_entry2 *ej = &vcpu->arch.cpuid_entries[j];
		if (ej->function == e->function) {
			ej->flags |= KVM_CPUID_FLAG_STATE_READ_NEXT;
			return j;
		}
	}
	return 0; /* silence gcc, even though control never reaches here */
}

struct kvm_cpuid_entry2 *kvm_find_cpuid_entry(struct kvm_vcpu *vcpu,
					      uint32_t function, uint32_t index)
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
	return best;
}

#define APIC_LVT_NUM			6
/* 14 is the version for Xeon and Pentium 8.4.8*/
#define APIC_VERSION			(0x14UL | ((APIC_LVT_NUM - 1) << 16))

extern void apic_set_reg(struct kvm_lapic *apic, int reg_off, uint32_t val);

void kvm_apic_set_version(struct kvm_vcpu *vcpu)
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


static int kvm_vcpu_ioctl_set_cpuid2(struct kvm_vcpu *vcpu,
				     struct kvm_cpuid2 *cpuid,
				     struct kvm_cpuid_entry2 *entries,
				     int mode)
{
	int r;

	r = E2BIG;
	if (cpuid->nent > KVM_MAX_CPUID_ENTRIES)
		goto out;
	r = EFAULT;
	if (ddi_copyin(entries, &vcpu->arch.cpuid_entries, 
		       cpuid->nent * sizeof(struct kvm_cpuid_entry2), mode))
		goto out;
	vcpu_load(vcpu);
	vcpu->arch.cpuid_nent = cpuid->nent;
	kvm_apic_set_version(vcpu);
	kvm_x86_ops->cpuid_update(vcpu);
	vcpu_put(vcpu);
	return 0;

out:
	return r;
}

static int kvm_vcpu_ioctl_get_cpuid2(struct kvm_vcpu *vcpu,
				     struct kvm_cpuid2 *cpuid,
				     struct kvm_cpuid_entry2 *entries,
				     int mode)
{
	int r;

	r = E2BIG;
	if (cpuid->nent < vcpu->arch.cpuid_nent)
		goto out;
	r = EFAULT;
	if (ddi_copyin(&vcpu->arch.cpuid_entries, entries, 
		       vcpu->arch.cpuid_nent * sizeof(struct kvm_cpuid_entry2), mode))
		goto out;
	return 0;

out:
	cpuid->nent = vcpu->arch.cpuid_nent;
	return r;
}

static inline unsigned long kvm_register_read(struct kvm_vcpu *vcpu,
					      enum kvm_reg reg)
{
#ifdef XXX
	if (!test_bit(reg, (unsigned long *)&vcpu->arch.regs_avail))
		kvm_x86_ops->cache_reg(vcpu, reg);
#endif /*XXX*/

	return vcpu->arch.regs[reg];
}

void kvm_register_write(struct kvm_vcpu *vcpu,
				      enum kvm_reg reg,
				      unsigned long val)
{
	vcpu->arch.regs[reg] = val;
#ifdef XXX
	__set_bit(reg, (unsigned long *)&vcpu->arch.regs_dirty);
	__set_bit(reg, (unsigned long *)&vcpu->arch.regs_avail);
#endif
}

unsigned long kvm_rip_read(struct kvm_vcpu *vcpu)
{
	return kvm_register_read(vcpu, VCPU_REGS_RIP);
}

void kvm_rip_write(struct kvm_vcpu *vcpu, unsigned long val)
{
	kvm_register_write(vcpu, VCPU_REGS_RIP, val);
}

unsigned long kvm_get_rflags(struct kvm_vcpu *vcpu)
{
	unsigned long rflags;

	rflags = kvm_x86_ops->get_rflags(vcpu);
#ifdef XXX
	if (vcpu->guest_debug & KVM_GUESTDBG_SINGLESTEP)
		rflags &= ~(unsigned long)(X86_EFLAGS_TF | X86_EFLAGS_RF);
#endif /*XXX*/
	return rflags;
}

int kvm_arch_vcpu_ioctl_get_regs(struct kvm_vcpu *vcpu, struct kvm_regs *regs)
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

	return 0;
}

#define VMX_SEGMENT_FIELD(seg)					\
	[VCPU_SREG_##seg] = {                                   \
		.selector = GUEST_##seg##_SELECTOR,		\
		.base = GUEST_##seg##_BASE,		   	\
		.limit = GUEST_##seg##_LIMIT,		   	\
		.ar_bytes = GUEST_##seg##_AR_BYTES,	   	\
	}

static struct kvm_vmx_segment_field {
	unsigned selector;
	unsigned base;
	unsigned limit;
	unsigned ar_bytes;
} kvm_vmx_segment_fields[] = {
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
#ifdef XXX
	if ((ar & AR_UNUSABLE_MASK) && !emulate_invalid_guest_state)
		ar = 0;
#endif /*XXX*/
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

	return ar;
}

static void vmx_set_segment(struct kvm_vcpu *vcpu,
			    struct kvm_segment *var, int seg)
{
	struct vcpu_vmx *vmx = (struct vcpu_vmx *)vcpu;
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
#ifdef XXX
	if (enable_unrestricted_guest && (seg != VCPU_SREG_LDTR))
		ar |= 0x1; /* Accessed */
#endif /*XXX*/

	vmcs_write32(sf->ar_bytes, ar);
}

void kvm_get_segment(struct kvm_vcpu *vcpu,
		     struct kvm_segment *var, int seg)
{
	kvm_x86_ops->get_segment(vcpu, var, seg);
}

static uint16_t get_segment_selector(struct kvm_vcpu *vcpu, int seg)
{
	struct kvm_segment kvm_seg;

	kvm_get_segment(vcpu, &kvm_seg, seg);
	return kvm_seg.selector;
}

void kvm_set_rflags(struct kvm_vcpu *vcpu, unsigned long rflags)
{
#ifdef XXX
	if (vcpu->guest_debug & KVM_GUESTDBG_SINGLESTEP &&
	    vcpu->arch.singlestep_cs ==
			get_segment_selector(vcpu, VCPU_SREG_CS) &&
	    vcpu->arch.singlestep_rip == kvm_rip_read(vcpu))
		rflags |= X86_EFLAGS_TF | X86_EFLAGS_RF;
#endif /*XXX*/
	kvm_x86_ops->set_rflags(vcpu, rflags);
}

int kvm_arch_vcpu_ioctl_set_regs(struct kvm_vcpu *vcpu, struct kvm_regs *regs)
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

	return 0;
}

int kvm_arch_vcpu_ioctl_get_fpu(struct kvm_vcpu *vcpu, struct kvm_fpu *fpu)
{
#ifdef XXX
	struct fxsave *fxsave = (struct fxsave *)&vcpu->arch.guest_fx_image;
#endif /*XXX*/

	vcpu_load(vcpu);
#ifdef XXX
	memcpy(fpu->fpr, fxsave->st_space, 128);
	fpu->fcw = fxsave->cwd;
	fpu->fsw = fxsave->swd;
	fpu->ftwx = fxsave->twd;
	fpu->last_opcode = fxsave->fop;
	fpu->last_ip = fxsave->rip;
	fpu->last_dp = fxsave->rdp;
	memcpy(fpu->xmm, fxsave->xmm_space, sizeof fxsave->xmm_space);
#endif /*XXX*/
	vcpu_put(vcpu);

	return 0;
}

int kvm_arch_vcpu_ioctl_set_fpu(struct kvm_vcpu *vcpu, struct kvm_fpu *fpu)
{
#ifdef XXX
	struct fxsave *fxsave = (struct fxsave *)&vcpu->arch.guest_fx_image;
#endif

	vcpu_load(vcpu);
#ifdef XXX
	memcpy(fxsave->st_space, fpu->fpr, 128);
	fxsave->cwd = fpu->fcw;
	fxsave->swd = fpu->fsw;
	fxsave->twd = fpu->ftwx;
	fxsave->fop = fpu->last_opcode;
	fxsave->rip = fpu->last_ip;
	fxsave->rdp = fpu->last_dp;
	memcpy(fxsave->xmm_space, fpu->xmm, sizeof fxsave->xmm_space);
#endif /*XXX*/
	vcpu_put(vcpu);

	return 0;
}


ulong kvm_read_cr4(struct kvm_vcpu *vcpu)
{
	return kvm_read_cr4_bits(vcpu, ~0UL);
}

static inline ulong kvm_read_cr0_bits(struct kvm_vcpu *vcpu, ulong mask)
{
	ulong tmask = mask & KVM_POSSIBLE_CR0_GUEST_BITS;
#ifdef XXX
	if (tmask & vcpu->arch.cr0_guest_owned_bits)
		kvm_x86_ops->decache_cr0_guest_bits(vcpu);
#endif /*XXX*/
	return vcpu->arch.cr0 & mask;
}


ulong kvm_read_cr0(struct kvm_vcpu *vcpu)
{
	return kvm_read_cr0_bits(vcpu, ~0UL);
}

unsigned long kvm_get_cr8(struct kvm_vcpu *vcpu)
{
#ifdef XXX
	if (irqchip_in_kernel(vcpu->kvm))
		return kvm_lapic_get_cr8(vcpu);
	else
#endif /*XXX*/
		return vcpu->arch.cr8;
}

extern uint64_t kvm_get_apic_base(struct kvm_vcpu *vcpu);

int kvm_arch_vcpu_ioctl_get_sregs(struct kvm_vcpu *vcpu,
				  struct kvm_sregs *sregs)
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

	memset(sregs->interrupt_bitmap, 0, sizeof sregs->interrupt_bitmap);

	if (vcpu->arch.interrupt.pending && !vcpu->arch.interrupt.soft)
		BT_SET((unsigned long *)sregs->interrupt_bitmap,
		       vcpu->arch.interrupt.nr);

	vcpu_put(vcpu);

	return 0;
}

static void kvm_set_segment(struct kvm_vcpu *vcpu,
			struct kvm_segment *var, int seg)
{
	kvm_x86_ops->set_segment(vcpu, var, seg);
}

#define VALID_PAGE(x) ((x) != INVALID_PAGE)

static void destroy_kvm_mmu(struct kvm_vcpu *vcpu)
{
	ASSERT(vcpu);
	if (VALID_PAGE(vcpu->arch.mmu.root_hpa)) {
		vcpu->arch.mmu.free(vcpu);
		vcpu->arch.mmu.root_hpa = INVALID_PAGE;
	}
}

extern int init_kvm_mmu(struct kvm_vcpu *vcpu);

int kvm_mmu_reset_context(struct kvm_vcpu *vcpu)
{
	destroy_kvm_mmu(vcpu);
	return init_kvm_mmu(vcpu);
}

static inline void kvm_queue_interrupt(struct kvm_vcpu *vcpu, uint8_t vector,
	int soft)
{
	vcpu->arch.interrupt.pending = 1;
	vcpu->arch.interrupt.soft = soft;
	vcpu->arch.interrupt.nr = vector;
}


static inline int is_present_gpte(unsigned long pte)
{
	return pte & PT_PRESENT_MASK;
}

gfn_t unalias_gfn_instantiation(struct kvm *kvm, gfn_t gfn)
{
	int i;
	struct kvm_mem_alias *alias;
	struct kvm_mem_aliases *aliases;
#ifdef XXX
	aliases = rcu_dereference(kvm->arch.aliases);

	for (i = 0; i < aliases->naliases; ++i) {
		alias = &aliases->aliases[i];
		if (alias->flags & KVM_ALIAS_INVALID)
			continue;
		if (gfn >= alias->base_gfn
		    && gfn < alias->base_gfn + alias->npages)
			return alias->target_gfn + gfn - alias->base_gfn;
	}
#endif /*XXX*/
	return gfn;
}

struct kvm_memory_slot *gfn_to_memslot_unaliased(struct kvm *kvm, gfn_t gfn)
{
	int i;
#ifdef XXX
	struct kvm_memslots *slots = rcu_dereference(kvm->memslots);
#else
	struct kvm_memslots *slots = kvm->memslots;
#endif /*XXX*/

	for (i = 0; i < slots->nmemslots; ++i) {
		struct kvm_memory_slot *memslot = &slots->memslots[i];

		if (gfn >= memslot->base_gfn
		    && gfn < memslot->base_gfn + memslot->npages)
			return memslot;
	}
	return NULL;
}

static inline unsigned long bad_hva(void)
{
	return PAGEOFFSET;
}

unsigned long gfn_to_hva(struct kvm *kvm, gfn_t gfn)
{
	struct kvm_memory_slot *slot;

	gfn = unalias_gfn_instantiation(kvm, gfn);
	slot = gfn_to_memslot_unaliased(kvm, gfn);
	if (!slot || slot->flags & KVM_MEMSLOT_INVALID)
		return bad_hva();
	return (slot->userspace_addr + (gfn - slot->base_gfn) * PAGESIZE);
}


int kvm_is_error_hva(unsigned long addr)
{
	return addr == bad_hva();
}

int kvm_read_guest_page(struct kvm *kvm, gfn_t gfn, void *data, int offset,
			int len)
{
	int r;
	unsigned long addr;

	addr = gfn_to_hva(kvm, gfn);
	if (kvm_is_error_hva(addr))
		return EFAULT;
	r = copyin((caddr_t)(addr + offset), data, len);
	if (r)
		return EFAULT;
	return 0;
}


/*
 * Load the pae pdptrs.  Return true is they are all valid.
 */
int load_pdptrs(struct kvm_vcpu *vcpu, unsigned long cr3)
{
	gfn_t pdpt_gfn = cr3 >> PAGESHIFT;
	unsigned offset = ((cr3 & (PAGESIZE-1)) >> 5) << 2;
	int i;
	int ret;
	uint64_t pdpte[ARRAY_SIZE(vcpu->arch.pdptrs)];

	ret = kvm_read_guest_page(vcpu->kvm, pdpt_gfn, pdpte,
				  offset * sizeof(uint64_t), sizeof(pdpte));
	if (ret < 0) {
		ret = 0;
		goto out;
	}
	for (i = 0; i < ARRAY_SIZE(pdpte); ++i) {
		if (is_present_gpte(pdpte[i]) &&
		    (pdpte[i] & vcpu->arch.mmu.rsvd_bits_mask[0][2])) {
			ret = 0;
			goto out;
		}
	}
	ret = 1;

	memcpy(vcpu->arch.pdptrs, pdpte, sizeof(vcpu->arch.pdptrs));
	BT_SET((unsigned long *)&vcpu->arch.regs_avail,
	       VCPU_EXREG_PDPTR);
	BT_SET((unsigned long *)&vcpu->arch.regs_dirty,
	       VCPU_EXREG_PDPTR);
out:

	return ret;
}

static void vmx_update_cr8_intercept(struct kvm_vcpu *vcpu, int tpr, int irr)
{
	if (irr == -1 || tpr < irr) {
		vmcs_write32(TPR_THRESHOLD, 0);
		return;
	}

	vmcs_write32(TPR_THRESHOLD, irr);
}

static void update_cr8_intercept(struct kvm_vcpu *vcpu)
{
	int max_irr, tpr;

	if (!kvm_x86_ops->update_cr8_intercept)
		return;

	if (!vcpu->arch.apic)
		return;
#ifdef XXX
	if (!vcpu->arch.apic->vapic_addr)
		max_irr = kvm_lapic_find_highest_irr(vcpu);
	else
#endif /*XXX*/
		max_irr = -1;

	if (max_irr != -1)
		max_irr >>= 4;
#ifdef XXX
	tpr = kvm_lapic_get_cr8(vcpu);

	kvm_x86_ops->update_cr8_intercept(vcpu, tpr, max_irr);
#endif /*XXX*/
}

static int __find_msr_index(struct vcpu_vmx *vmx, uint32_t msr)
{
	int i;

	for (i = 0; i < vmx->nmsrs; ++i)
		if (vmx_msr_index[vmx->guest_msrs[i].index] == msr)
			return i;
	return -1;
}

static struct shared_msr_entry *find_msr_entry(struct vcpu_vmx *vmx, uint32_t msr)
{
	int i;

	i = __find_msr_index(vmx, msr);
	if (i >= 0)
		return &vmx->guest_msrs[i];
	return NULL;
}

/*
 * Swap MSR entry in host/guest MSR entry array.
 */
static void move_msr_up(struct vcpu_vmx *vmx, int from, int to)
{
	struct shared_msr_entry tmp;

	tmp = vmx->guest_msrs[to];
	vmx->guest_msrs[to] = vmx->guest_msrs[from];
	vmx->guest_msrs[from] = tmp;
}

static int update_transition_efer(struct vcpu_vmx *vmx, int efer_offset)
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
	return 1;
}

/*
 * Set up the vmcs to automatically save and restore system
 * msrs.  Don't touch the 64-bit msrs if the guest is in legacy
 * mode, as fiddling with msrs is very expensive.
 */
void setup_msrs(struct vcpu_vmx *vmx)
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

void vmx_set_efer(struct kvm_vcpu *vcpu, uint64_t efer)
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
			     vmcs_read32(VM_ENTRY_CONTROLS) |
			     VM_ENTRY_IA32E_MODE);
		msr->data = efer;
	} else {
		vmcs_write32(VM_ENTRY_CONTROLS,
			     vmcs_read32(VM_ENTRY_CONTROLS) &
			     ~VM_ENTRY_IA32E_MODE);

		msr->data = efer & ~EFER_LME;
	}
	setup_msrs(vmx);
}

static inline int is_protmode(struct kvm_vcpu *vcpu)
{
	return kvm_read_cr0_bits(vcpu, X86_CR0_PE);
}


#ifdef CONFIG_KVM_APIC_ARCHITECTURE
int kvm_vcpu_is_bsp(struct kvm_vcpu *vcpu)
{
	return vcpu->kvm->bsp_vcpu_id == vcpu->vcpu_id;
}
#endif

void kvm_pic_clear_isr_ack(struct kvm *kvm)
{
	struct kvm_pic *s = pic_irqchip(kvm);

	mutex_enter(&s->lock);
	s->pics[0].isr_ack = 0xff;
	s->pics[1].isr_ack = 0xff;
	mutex_exit(&s->lock);
}

int kvm_arch_vcpu_ioctl_set_sregs(struct kvm_vcpu *vcpu,
				  struct kvm_sregs *sregs)
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

	max_bits = (sizeof sregs->interrupt_bitmap) << 3;
	pending_vec = bt_getlowbit(
		(const unsigned long *)sregs->interrupt_bitmap, 0, max_bits);
	if (pending_vec < max_bits) {
		kvm_queue_interrupt(vcpu, pending_vec, 0);
		cmn_err(CE_NOTE, "Set back pending irq %d\n", pending_vec);
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
#endif /*CONFIG_KVM_APIC_ARCHITECTURE*/

	vcpu_put(vcpu);

	return 0;
}

static void kvm_write_wall_clock(struct kvm *kvm, gpa_t wall_clock)
{
	static int version;
	struct pvclock_wall_clock wc;
	struct timespec boot;

#ifdef XXX
	if (!wall_clock)
		return;

	version++;

	kvm_write_guest(kvm, wall_clock, &version, sizeof(version));

	/*
	 * The guest calculates current wall clock time by adding
	 * system time (updated by kvm_write_guest_time below) to the
	 * wall clock specified here.  guest system time equals host
	 * system time for us, thus we must fill in host boot time here.
	 */
	getboottime(&boot);

	wc.sec = boot.tv_sec;
	wc.nsec = boot.tv_nsec;
	wc.version = version;

	kvm_write_guest(kvm, wall_clock, &wc, sizeof(wc));

	version++;
	kvm_write_guest(kvm, wall_clock, &version, sizeof(version));
#endif /*XXX*/
}

static int next_segment(unsigned long len, int offset)
{
	if (len > PAGESIZE - offset)
		return PAGESIZE - offset;
	else
		return len;
}


void mark_page_dirty(struct kvm *kvm, gfn_t gfn)
{
	struct kvm_memory_slot *memslot;

#ifdef XXX
	gfn = unalias_gfn(kvm, gfn);
	memslot = gfn_to_memslot_unaliased(kvm, gfn);
	if (memslot && memslot->dirty_bitmap) {
		unsigned long rel_gfn = gfn - memslot->base_gfn;
		unsigned long *p = memslot->dirty_bitmap +
			rel_gfn / BT_NBIPUL;
		int offset = rel_gfn % BT_NBIPUL;

		/* avoid RMW */
		if (!generic_test_le_bit(offset, p))
			generic___set_le_bit(offset, p);
	}
#endif /*XXX*/
}

int kvm_write_guest_page(struct kvm *kvm, gfn_t gfn, const void *data,
			 int offset, int len)
{
	int r;
	unsigned long addr;

	addr = gfn_to_hva(kvm, gfn);
	if (kvm_is_error_hva(addr))
		return -EFAULT;
	r = copyout(data, (caddr_t)((uint64_t)addr + offset), len);
	if (r)
		return -EFAULT;
	mark_page_dirty(kvm, gfn);
	return 0;
}

int kvm_write_guest(struct kvm *kvm, gpa_t gpa, const void *data,
		    unsigned long len)
{
	gfn_t gfn = gpa >> PAGESHIFT;
	int seg;
	int offset = offset_in_page(gpa);
	int ret;

	while ((seg = next_segment(len, offset)) != 0) {
		ret = kvm_write_guest_page(kvm, gfn, data, offset, seg);
		if (ret < 0)
			return ret;
		offset = 0;
		len -= seg;
		data += seg;
		++gfn;
	}
	return 0;
}

static int xen_hvm_config(struct kvm_vcpu *vcpu, uint64_t data)
{
	struct kvm *kvm = vcpu->kvm;
	int lm = is_long_mode(vcpu);
	uint8_t *blob_addr = lm ? (uint8_t *)(long)kvm->arch.xen_hvm_config.blob_addr_64
		: (uint8_t *)(long)kvm->arch.xen_hvm_config.blob_addr_32;
	uint8_t blob_size = lm ? kvm->arch.xen_hvm_config.blob_size_64
		: kvm->arch.xen_hvm_config.blob_size_32;
	uint32_t page_num = data & ~PAGEMASK;
	uint64_t page_addr = data & PAGEMASK;
	uint8_t *page;
	int r;

	r = E2BIG;
	if (page_num >= blob_size)
		goto out;
	r = ENOMEM;
	page = kmem_alloc(PAGESIZE, KM_SLEEP);
	if (!page)
		goto out;
	r = EFAULT;
	if (copyin(blob_addr + (page_num * PAGESIZE), page, PAGESIZE))
		goto out_free;
	if (kvm_write_guest(kvm, page_addr, page, PAGESIZE))
		goto out_free;
	r = 0;
out_free:
	kmem_free(page, PAGESIZE);
out:
	return r;
}

int ignore_msrs = 0;
extern int is_paging(struct kvm_vcpu *vcpu);

static void set_efer(struct kvm_vcpu *vcpu, uint64_t efer)
{
	if (efer & efer_reserved_bits) {
		kvm_inject_gp(vcpu, 0);
		return;
	}

	if (is_paging(vcpu)
	    && (vcpu->arch.efer & EFER_LME) != (efer & EFER_LME)) {
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

static int msr_mtrr_valid(unsigned msr)
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
		return 1;
	case 0x2f8:
		return 1;
	}
	return 0;
}


static int valid_pat_type(unsigned t)
{
	return t < 8 && (1 << t) & 0xf3; /* 0, 1, 4, 5, 6, 7 */
}

static int valid_mtrr_type(unsigned t)
{
	return t < 8 && (1 << t) & 0x73; /* 0, 1, 4, 5, 6 */
}

static int mtrr_valid(struct kvm_vcpu *vcpu, uint32_t msr, uint64_t data)
{
	int i;

	if (!msr_mtrr_valid(msr))
		return 0;

	if (msr == MSR_IA32_CR_PAT) {
		for (i = 0; i < 8; i++)
			if (!valid_pat_type((data >> (i * 8)) & 0xff))
				return 0;
		return 1;
	} else if (msr == MSR_MTRRdefType) {
		if (data & ~0xcff)
			return 0;
		return valid_mtrr_type(data & 0xff);
	} else if (msr >= MSR_MTRRfix64K_00000 && msr <= MSR_MTRRfix4K_F8000) {
		for (i = 0; i < 8 ; i++)
			if (!valid_mtrr_type((data >> (i * 8)) & 0xff))
				return 0;
		return 1;
	}

	/* variable MTRRs */
	return valid_mtrr_type(data & 0xff);
}


static int set_msr_mtrr(struct kvm_vcpu *vcpu, uint32_t msr, uint64_t data)
{
	uint64_t *p = (uint64_t *)&vcpu->arch.mtrr_state.fixed_ranges;

	if (!mtrr_valid(vcpu, msr, data))
		return 1;

	if (msr == MSR_MTRRdefType) {
		vcpu->arch.mtrr_state.def_type = data;
		vcpu->arch.mtrr_state.enabled = (data & 0xc00) >> 10;
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
		if (!is_mtrr_mask)
			pt =
			  (uint64_t *)&vcpu->arch.mtrr_state.var_ranges[idx].base_lo;
		else
			pt =
			  (uint64_t *)&vcpu->arch.mtrr_state.var_ranges[idx].mask_lo;
		*pt = data;
	}

#ifdef XXX
	kvm_mmu_reset_context(vcpu);
#endif /*XXX*/
	return 0;
}

static int set_msr_hyperv(struct kvm_vcpu *vcpu, uint32_t msr, uint64_t data)
{
	switch (msr) {
#ifdef XXX
	case HV_X64_MSR_APIC_ASSIST_PAGE: {
		unsigned long addr;

		if (!(data & HV_X64_MSR_APIC_ASSIST_PAGE_ENABLE)) {
			vcpu->arch.hv_vapic = data;
			break;
		}
		addr = gfn_to_hva(vcpu->kvm, data >>
				  HV_X64_MSR_APIC_ASSIST_PAGE_ADDRESS_SHIFT);
		if (kvm_is_error_hva(addr))
			return 1;
		if (clear_user((void __user *)addr, PAGESIZE))
			return 1;
		vcpu->arch.hv_vapic = data;
		break;
	}
	case HV_X64_MSR_EOI:
		return kvm_hv_vapic_msr_write(vcpu, APIC_EOI, data);
	case HV_X64_MSR_ICR:
		return kvm_hv_vapic_msr_write(vcpu, APIC_ICR, data);
	case HV_X64_MSR_TPR:
		return kvm_hv_vapic_msr_write(vcpu, APIC_TASKPRI, data);
#endif /*XXX*/
	default:
		cmn_err(CE_WARN, "HYPER-V unimplemented wrmsr: 0x%x "
			  "data 0x%llx\n", msr, data);
		return 1;
	}

	return 0;
}

static int set_msr_hyperv_pw(struct kvm_vcpu *vcpu, uint32_t msr, uint64_t data)
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
			return 1;
		kvm_x86_ops->patch_hypercall(vcpu, instructions);
		((unsigned char *)instructions)[3] = 0xc3; /* ret */
		if (copyout(instructions, (caddr_t)addr, 4))
			return 1;
		kvm->arch.hv_hypercall = data;
		break;
	}
	default:
		cmn_err(CE_WARN, "HYPER-V unimplemented wrmsr: 0x%x "
			  "data 0x%llx\n", msr, data);
		return 1;
	}
	return 0;
}

static int set_msr_mce(struct kvm_vcpu *vcpu, uint32_t msr, uint64_t data)
{
	uint64_t mcg_cap = vcpu->arch.mcg_cap;
	unsigned bank_num = mcg_cap & 0xff;

	switch (msr) {
	case MSR_IA32_MCG_STATUS:
		vcpu->arch.mcg_status = data;
		break;
	case MSR_IA32_MCG_CTL:
		if (!(mcg_cap & MCG_CTL_P))
			return 1;
		if (data != 0 && data != ~(uint64_t)0)
			return -1;
		vcpu->arch.mcg_ctl = data;
		break;
	default:
		if (msr >= MSR_IA32_MC0_CTL &&
		    msr < MSR_IA32_MC0_CTL + 4 * bank_num) {
			uint32_t offset = msr - MSR_IA32_MC0_CTL;
			/* only 0 or all 1s can be written to IA32_MCi_CTL
			 * some Linux kernels though clear bit 10 in bank 4 to
			 * workaround a BIOS/GART TBL issue on AMD K8s, ignore
			 * this to avoid an uncatched #GP in the guest
			 */
			if ((offset & 0x3) == 0 &&
			    data != 0 && (data | (1 << 10)) != ~(uint64_t)0)
				return -1;
			vcpu->arch.mce_banks[offset] = data;
			break;
		}
		return 1;
	}
	return 0;
}

static int kvm_hv_msr_partition_wide(uint32_t msr)
{
	int r = 0;
	switch (msr) {
	case HV_X64_MSR_GUEST_OS_ID:
	case HV_X64_MSR_HYPERCALL:
		r = 1;
		break;
	}

	return r;
}


static inline void get_page(caddr_t page)
{
}

struct page *gfn_to_page(struct kvm *kvm, gfn_t gfn)
{
	pfn_t pfn;

	pfn = gfn_to_pfn(kvm, gfn);
#ifdef XXX
	if (!kvm_is_mmio_pfn(pfn))
		return pfn_to_page(pfn);
#endif /*XXX*/

	get_page(bad_page);
	return (struct page *)bad_page;
}


int kvm_set_msr_common(struct kvm_vcpu *vcpu, uint32_t msr, uint64_t data)
{
	volatile int x;

	switch (msr) {
	case MSR_EFER:
		set_efer(vcpu, data);
		break;
	case MSR_K7_HWCR:
		data &= ~(uint64_t)0x40;	/* ignore flush filter disable */
		if (data != 0) {
			cmn_err(CE_NOTE, "unimplemented HWCR wrmsr: 0x%llx\n",
				data);
			return 1;
		}
		break;
	case MSR_FAM10H_MMIO_CONF_BASE:
		if (data != 0) {
			cmn_err(CE_NOTE, "unimplemented MMIO_CONF_BASE wrmsr: "
				"0x%llx\n", data);
			return 1;
		}
		break;
	case MSR_AMD64_NB_CFG:
		break;
	case MSR_IA32_DEBUGCTLMSR:
		if (!data) {
			/* We support the non-activated case already */
			break;
		} else if (data & ~(DEBUGCTLMSR_LBR | DEBUGCTLMSR_BTF)) {
			/* Values other than LBR and BTF are vendor-specific,
			   thus reserved and should throw a #GP */
			return 1;
		}
		cmn_err(CE_NOTE, "%s: MSR_IA32_DEBUGCTLMSR 0x%llx, nop\n",
			__func__, data);
		break;
	case MSR_IA32_UCODE_REV:
	case MSR_IA32_UCODE_WRITE:
	case MSR_VM_HSAVE_PA:
	case MSR_AMD64_PATCH_LOADER:
		break;
	case 0x200 ... 0x2ff:
		return set_msr_mtrr(vcpu, msr, data);
	case MSR_IA32_APICBASE:
		kvm_set_apic_base(vcpu, data);
		break;
#ifdef XXX
	case APIC_BASE_MSR ... APIC_BASE_MSR + 0x3ff:
		return kvm_x2apic_msr_write(vcpu, msr, data);
#endif /*XXX*/
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
#endif /*XXX*/

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
#endif /*XXX*/
		break;
	}
	case MSR_IA32_MCG_CTL:
	case MSR_IA32_MCG_STATUS:
	case MSR_IA32_MC0_CTL ... MSR_IA32_MC0_CTL + 4 * KVM_MAX_MCE_BANKS - 1:
		return set_msr_mce(vcpu, msr, data);

	/* Performance counters are not protected by a CPUID bit,
	 * so we should check all of them in the generic path for the sake of
	 * cross vendor migration.
	 * Writing a zero into the event select MSRs disables them,
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
				"0x%x data 0x%llx\n", msr, data);
		break;
	/* at least RHEL 4 unconditionally writes to the perfctr registers,
	 * so we ignore writes to make it happy.
	 */
	case MSR_P6_PERFCTR0:
	case MSR_P6_PERFCTR1:
	case MSR_K7_PERFCTR0:
	case MSR_K7_PERFCTR1:
	case MSR_K7_PERFCTR2:
	case MSR_K7_PERFCTR3:
		cmn_err(CE_NOTE, "unimplemented perfctr wrmsr: "
			"0x%x data 0x%llx\n", msr, data);
		break;
	case HV_X64_MSR_GUEST_OS_ID ... HV_X64_MSR_SINT15:
		if (kvm_hv_msr_partition_wide(msr)) {
			int r;
			mutex_enter(&vcpu->kvm->lock);
			r = set_msr_hyperv_pw(vcpu, msr, data);
			mutex_exit(&vcpu->kvm->lock);
			return r;
		} else
			return set_msr_hyperv(vcpu, msr, data);
		break;
	default:
		if (msr && (msr == vcpu->kvm->arch.xen_hvm_config.msr))
			return xen_hvm_config(vcpu, data);
		if (!ignore_msrs) {
			cmn_err(CE_NOTE, "unhandled wrmsr: 0x%x data %llx\n",
				msr, data);
			return 1;
		} else {
			cmn_err(CE_NOTE, "ignored wrmsr: 0x%x data %llx\n",
				msr, data);
			break;
		}
	}
	x = 10; /*XXX*/
	return 0;
}



static int get_msr_mtrr(struct kvm_vcpu *vcpu, uint32_t msr, uint64_t *pdata)
{
	uint64_t *p = (uint64_t *)&vcpu->arch.mtrr_state.fixed_ranges;

	if (!msr_mtrr_valid(msr))
		return 1;

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
		if (!is_mtrr_mask)
			pt =
			  (uint64_t *)&vcpu->arch.mtrr_state.var_ranges[idx].base_lo;
		else
			pt =
			  (uint64_t *)&vcpu->arch.mtrr_state.var_ranges[idx].mask_lo;
		*pdata = *pt;
	}

	return 0;
}



static int get_msr_hyperv(struct kvm_vcpu *vcpu, uint32_t msr, uint64_t *pdata)
{
	uint64_t data = 0;

	switch (msr) {
#ifdef XXX
	case HV_X64_MSR_VP_INDEX: {
		int r;
		struct kvm_vcpu *v;
		kvm_for_each_vcpu(r, v, vcpu->kvm)
			if (v == vcpu)
				data = r;
		break;
	}
	case HV_X64_MSR_EOI:
		return kvm_hv_vapic_msr_read(vcpu, APIC_EOI, pdata);
	case HV_X64_MSR_ICR:
		return kvm_hv_vapic_msr_read(vcpu, APIC_ICR, pdata);
	case HV_X64_MSR_TPR:
		return kvm_hv_vapic_msr_read(vcpu, APIC_TASKPRI, pdata);
#endif /*XXX*/
	default:
		cmn_err(CE_WARN, "Hyper-V unhandled rdmsr: 0x%x\n", msr);
		return 1;
	}
	*pdata = data;
	return 0;
}

static int get_msr_hyperv_pw(struct kvm_vcpu *vcpu, uint32_t msr, uint64_t *pdata)
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
		return 1;
	}

	*pdata = data;
	return 0;
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
			return 1;
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
		return 1;
	}
	*pdata = data;
	return 0;
}


int kvm_get_msr_common(struct kvm_vcpu *vcpu, uint32_t msr, uint64_t *pdata)
{
	uint64_t data;
	volatile int x;  /*XXX - dtrace return probe is not there... */

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
		return get_msr_mtrr(vcpu, msr, pdata);
	case 0xcd: /* fsb frequency */
		data = 3;
		break;
	case MSR_IA32_APICBASE:
		data = kvm_get_apic_base(vcpu);
		break;
#ifdef XXX
	case APIC_BASE_MSR ... APIC_BASE_MSR + 0x3ff:
		return kvm_x2apic_msr_read(vcpu, msr, pdata);
		break;
#endif /*XXX*/
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
		return get_msr_mce(vcpu, msr, pdata);
	case HV_X64_MSR_GUEST_OS_ID ... HV_X64_MSR_SINT15:
		if (kvm_hv_msr_partition_wide(msr)) {
			int r;
			mutex_enter(&vcpu->kvm->lock);
			r = get_msr_hyperv_pw(vcpu, msr, pdata);
			mutex_exit(&vcpu->kvm->lock);
			return r;
		} else
			return get_msr_hyperv(vcpu, msr, pdata);
		break;
	default:
		if (!ignore_msrs) {
			cmn_err(CE_NOTE, "unhandled rdmsr: 0x%x\n", msr);
			return 1;
		} else {
			cmn_err(CE_NOTE, "ignored rdmsr: 0x%x\n", msr);
			data = 0;
		}
		break;
	}
	*pdata = data;
	x = 10;  /*XXX*/
	return 0;
}

/*
 * Read or write a bunch of msrs. All parameters are kernel addresses.
 *
 * @return number of msrs set successfully.
 */
static int __msr_io(struct kvm_vcpu *vcpu, struct kvm_msrs *msrs,
		    struct kvm_msr_entry *entries,
		    int (*do_msr)(struct kvm_vcpu *vcpu,
				  unsigned index, uint64_t *data))
{
	int i, idx;

	vcpu_load(vcpu);

#ifdef XXX
	idx = srcu_read_lock(&vcpu->kvm->srcu);
#endif
	for (i = 0; i < msrs->nmsrs; ++i)
		if (do_msr(vcpu, entries[i].index, &entries[i].data))
			break;
#ifdef XXX
	srcu_read_unlock(&vcpu->kvm->srcu, idx);
#endif
	vcpu_put(vcpu);

	return i;
}

/*
 * reads and returns guest's timestamp counter "register"
 * guest_tsc = host_tsc + tsc_offset    -- 21.3
 */
static uint64_t guest_read_tsc(void)
{
	uint64_t host_tsc, tsc_offset;

	rdtscll(host_tsc);
	tsc_offset = vmcs_read64(TSC_OFFSET);
	return host_tsc + tsc_offset;
}


/*
 * Reads an msr value (of 'msr_index') into 'pdata'.
 * Returns 0 on success, non-0 otherwise.
 * Assumes vcpu_load() was already called.
 */
static int vmx_get_msr(struct kvm_vcpu *vcpu, uint32_t msr_index, uint64_t *pdata)
{
	uint64_t data;
	struct shared_msr_entry *msr;

	if (!pdata) {
		cmn_err(CE_WARN, "BUG: get_msr called with NULL pdata\n");
		return EINVAL;
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
		vmx_load_host_state((struct vcpu_vmx *)vcpu);
		data = ((struct vcpu_vmx *)(vcpu))->msr_guest_kernel_gs_base;
		break;
#endif
	case MSR_EFER:
		return kvm_get_msr_common(vcpu, msr_index, pdata);
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
		if (!((struct vcpu_vmx *)(vcpu))->rdtscp_enabled)
			return 1;
		/* Otherwise falls through */
	default:
		vmx_load_host_state((struct vcpu_vmx *)vcpu);
		msr = find_msr_entry((struct vcpu_vmx *)vcpu, msr_index);
		if (msr) {
			vmx_load_host_state((struct vcpu_vmx *)vcpu);
			data = msr->data;
			break;
		}
		return kvm_get_msr_common(vcpu, msr_index, pdata);
	}

	*pdata = data;
	return 0;
}

/*
 * Reads an msr value (of 'msr_index') into 'pdata'.
 * Returns 0 on success, non-0 otherwise.
 * Assumes vcpu_load() was already called.
 */
int kvm_get_msr(struct kvm_vcpu *vcpu, uint32_t msr_index, uint64_t *pdata)
{
	return kvm_x86_ops->get_msr(vcpu, msr_index, pdata);
}


/*
 * Writes msr value into into the appropriate "register".
 * Returns 0 on success, non-0 otherwise.
 * Assumes vcpu_load() was already called.
 */
static int vmx_set_msr(struct kvm_vcpu *vcpu, uint32_t msr_index, uint64_t data)
{
	struct vcpu_vmx *vmx = (struct vcpu_vmx *)vcpu;
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
			return 1;
		/* Check reserved bit, higher 32 bits should be zero */
		if ((data >> 32) != 0)
			return 1;
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

	return ret;
}

/*
 * Writes msr value into into the appropriate "register".
 * Returns 0 on success, non-0 otherwise.
 * Assumes vcpu_load() was already called.
 */
int kvm_set_msr(struct kvm_vcpu *vcpu, uint32_t msr_index, uint64_t data)
{
	return kvm_x86_ops->set_msr(vcpu, msr_index, data);
}

/*
 * Adapt set_msr() to msr_io()'s calling convention
 */
static int do_set_msr(struct kvm_vcpu *vcpu, unsigned index, uint64_t *data)
{
	return kvm_set_msr(vcpu, index, *data);
}

static inline int is_machine_check(uint32_t intr_info)
{
	return (intr_info & (INTR_INFO_INTR_TYPE_MASK | INTR_INFO_VECTOR_MASK |
			     INTR_INFO_VALID_MASK)) ==
		(INTR_TYPE_HARD_EXCEPTION | MC_VECTOR | INTR_INFO_VALID_MASK);
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
#ifdef XXX
#if defined(CONFIG_X86_MCE) && defined(CONFIG_X86_64)
	struct pt_regs regs = {
		.cs = 3, /* Fake ring 3 no matter what the guest ran on */
		.flags = X86_EFLAGS_IF,
	};

	do_machine_check(&regs, 0);
#endif
#endif /*XXX*/
}

static void vmcs_clear_bits(unsigned long field, uint32_t mask)
{
	vmcs_writel(field, vmcs_readl(field) & ~mask);
}

static void vmcs_set_bits(unsigned long field, uint32_t mask)
{
	vmcs_writel(field, vmcs_readl(field) | mask);
}

#define EXCPT_BENIGN		0
#define EXCPT_CONTRIBUTORY	1
#define EXCPT_PF		2

static int exception_class(int vector)
{
	switch (vector) {
	case PF_VECTOR:
		return EXCPT_PF;
	case DE_VECTOR:
	case TS_VECTOR:
	case NP_VECTOR:
	case SS_VECTOR:
	case GP_VECTOR:
		return EXCPT_CONTRIBUTORY;
	default:
		break;
	}
	return EXCPT_BENIGN;
}

static void kvm_multiple_exception(struct kvm_vcpu *vcpu,
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
		BT_SET(&vcpu->requests, KVM_REQ_TRIPLE_FAULT);
		return;
	}
	class1 = exception_class(prev_nr);
	class2 = exception_class(nr);
	if ((class1 == EXCPT_CONTRIBUTORY && class2 == EXCPT_CONTRIBUTORY)
		|| (class1 == EXCPT_PF && class2 != EXCPT_BENIGN)) {
		/* generate double fault per SDM Table 5-5 */
		vcpu->arch.exception.pending = 1;
		vcpu->arch.exception.has_error_code = 1;
		vcpu->arch.exception.nr = DF_VECTOR;
		vcpu->arch.exception.error_code = 0;
	} else
		/* replace previous exception with a new one in a hope
		   that instruction re-execution will regenerate lost
		   exception */
		goto queue;
}

void kvm_queue_exception(struct kvm_vcpu *vcpu, unsigned nr)
{
	kvm_multiple_exception(vcpu, nr, 0, 0);
}

void kvm_queue_exception_e(struct kvm_vcpu *vcpu, unsigned nr, uint32_t error_code)
{
	kvm_multiple_exception(vcpu, nr, 1, error_code);
}


static void vmx_complete_interrupts(struct vcpu_vmx *vmx)
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
	if ((vmx->exit_reason == EXIT_REASON_MCE_DURING_VMENTRY)
	    || (vmx->exit_reason == EXIT_REASON_EXCEPTION_NMI
		&& is_machine_check(exit_intr_info)))
		kvm_machine_check();

	/* We need to handle NMIs before interrupts are enabled */
	if ((exit_intr_info & INTR_INFO_INTR_TYPE_MASK) == INTR_TYPE_NMI_INTR &&
	    (exit_intr_info & INTR_INFO_VALID_MASK))
		asm("int $2");

	idtv_info_valid = idt_vectoring_info & VECTORING_INFO_VALID_MASK;

#ifdef XXX
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
	} else if (unlikely(vmx->soft_vnmi_blocked))
		vmx->vnmi_blocked_time +=
			ktime_to_ns(ktime_sub(ktime_get(), vmx->entry_time));
#endif /*XXX*/
	vmx->vcpu.arch.nmi_injected = 0;
#ifdef XXX
	kvm_clear_exception_queue(&vmx->vcpu);
	kvm_clear_interrupt_queue(&vmx->vcpu);

	if (!idtv_info_valid)
		return;
#endif /*XXX*/
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
#ifdef XXX
		if (idt_vectoring_info & VECTORING_INFO_DELIVER_CODE_MASK) {
			uint32_t err = vmcs_read32(IDT_VECTORING_ERROR_CODE);
			kvm_queue_exception_e(&vmx->vcpu, vector, err);
		} else
			kvm_queue_exception(&vmx->vcpu, vector);
#endif /*XXX*/
		break;
	case INTR_TYPE_SOFT_INTR:
		vmx->vcpu.arch.event_exit_inst_len =
			vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
		/* fall through */
	case INTR_TYPE_EXT_INTR:
#ifdef XXX
		kvm_queue_interrupt(&vmx->vcpu, vector,
			type == INTR_TYPE_SOFT_INTR);
#endif /*XXX*/
		break;
	default:
		break;
	}
}

#ifdef CONFIG_X86_64
#define R "r"
#define Q "q"
#else
#define R "e"
#define Q "l"
#endif

/*
 * Volatile isn't enough to prevent the compiler from reordering the
 * read/write functions for the control registers and messing everything up.
 * A memory clobber would solve the problem, but would prevent reordering of
 * all loads stores around it, which can hurt performance. Solution is to
 * use a variable and mimic reads and writes to it to enforce serialization
 */
static unsigned long __force_order;

static inline unsigned long native_read_cr0(void)
{
	unsigned long val;
	asm volatile("mov %%cr0,%0\n\t" : "=r" (val), "=m" (__force_order));
	return val;
}

#define read_cr0()	(native_read_cr0())

static void vmx_vcpu_run(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = (struct vcpu_vmx *)vcpu;

	/* Record the guest's net vcpu time for enforced NMI injections. */
#ifdef XXX
	if (!cpu_has_virtual_nmis() && vmx->soft_vnmi_blocked)
		vmx->entry_time = ktime_get();

	/* Don't enter VMX if guest state is invalid, let the exit handler
	   start emulation until we arrive back to a valid state */
	if (vmx->emulation_required && emulate_invalid_guest_state)
		return;

	if (test_bit(VCPU_REGS_RSP, (unsigned long *)&vcpu->arch.regs_dirty))
		vmcs_writel(GUEST_RSP, vcpu->arch.regs[VCPU_REGS_RSP]);
	if (test_bit(VCPU_REGS_RIP, (unsigned long *)&vcpu->arch.regs_dirty))
		vmcs_writel(GUEST_RIP, vcpu->arch.regs[VCPU_REGS_RIP]);

	/* When single-stepping over STI and MOV SS, we must clear the
	 * corresponding interruptibility bits in the guest state. Otherwise
	 * vmentry fails as it then expects bit 14 (BS) in pending debug
	 * exceptions being set, but that's not correct for the guest debugging
	 * case. */
	if (vcpu->guest_debug & KVM_GUESTDBG_SINGLESTEP)
		vmx_set_interrupt_shadow(vcpu, 0);
#endif /*XXX*/

	/*
	 * Loading guest fpu may have cleared host cr0.ts
	 */
	vmcs_writel(HOST_CR0, read_cr0());

	asm(
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
		, R"bx", R"di", R"si"
#ifdef CONFIG_X86_64
		, "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
#endif
	      );

	vcpu->arch.regs_avail = ~((1 << VCPU_REGS_RIP) | (1 << VCPU_REGS_RSP)
				  | (1 << VCPU_EXREG_PDPTR));
	vcpu->arch.regs_dirty = 0;

	vmx->idt_vectoring_info = vmcs_read32(IDT_VECTORING_INFO_FIELD);

#ifdef XXX
	if (vmx->rmode.irq.pending)
		fixup_rmode_irq(vmx);
#endif /*XXX*/

	asm("mov %0, %%ds; mov %0, %%es" : : "r"(__USER_DS));
	vmx->launched = 1;

	vmx_complete_interrupts(vmx);
}

#undef R
#undef Q

void kvm_set_shared_msr(unsigned slot, uint64_t value, uint64_t mask)
{
#ifdef XXX
	struct kvm_shared_msrs *smsr = &__get_cpu_var(shared_msrs);

	if (((value ^ smsr->values[slot].curr) & mask) == 0)
		return;
	smsr->values[slot].curr = value;
	wrmsrl(shared_msrs_global.msrs[slot], value);
	if (!smsr->registered) {
		smsr->urn.on_user_return = kvm_on_user_return;
		user_return_notifier_register(&smsr->urn);
		smsr->registered = 1;
	}
#endif /*XXX*/
}
static void vmx_save_host_state(struct kvm_vcpu *vcpu)
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
	for (i = 0; i < vmx->save_nmsrs; ++i)
		kvm_set_shared_msr(vmx->guest_msrs[i].index,
				   vmx->guest_msrs[i].data,
				   vmx->guest_msrs[i].mask);
}

int vmx_interrupt_allowed(struct kvm_vcpu *vcpu)
{
	return (vmcs_readl(GUEST_RFLAGS) & X86_EFLAGS_IF) &&
		!(vmcs_read32(GUEST_INTERRUPTIBILITY_INFO) &
			(GUEST_INTR_STATE_STI | GUEST_INTR_STATE_MOV_SS));
}

int kvm_arch_interrupt_allowed(struct kvm_vcpu *vcpu)
{
	return kvm_x86_ops->interrupt_allowed(vcpu);
}

static int handle_machine_check(struct kvm_vcpu *vcpu)
{
	/* already handled by vcpu_run */
	return 1;
}


static inline int is_page_fault(uint32_t intr_info)
{
	return (intr_info & (INTR_INFO_INTR_TYPE_MASK | INTR_INFO_VECTOR_MASK |
			     INTR_INFO_VALID_MASK)) ==
		(INTR_TYPE_HARD_EXCEPTION | PF_VECTOR | INTR_INFO_VALID_MASK);
}


static int kvm_read_guest_virt_helper(gva_t addr, void *val, unsigned int bytes,
				      struct kvm_vcpu *vcpu, uint32_t access,
				      uint32_t *error)
{
	void *data = val;
	int r = /*X86EMUL_CONTINUE*/ 0;

	while (bytes) {
		gpa_t gpa = vcpu->arch.mmu.gva_to_gpa(vcpu, addr, access, error);
		unsigned offset = addr & (PAGESIZE-1);
		unsigned toread = min(bytes, (unsigned)PAGESIZE - offset);
		int ret;

		if (gpa == UNMAPPED_GVA) {
			r = /*X86EMUL_PROPAGATE_FAULT*/1;
			goto out;
		}
		ret = kvm_read_guest(vcpu->kvm, gpa, data, toread);
		if (ret < 0) {
			r = /*X86EMUL_UNHANDLEABLE*/ 1;
			goto out;
		}

		bytes -= toread;
		data += toread;
		addr += toread;
	}
out:
	return r;
}

void kvm_inject_page_fault(struct kvm_vcpu *vcpu, unsigned long addr,
			   uint32_t error_code)
{
#ifdef XXX
	++vcpu->stat.pf_guest;
#endif /*XXX*/
	vcpu->arch.cr2 = addr;
	kvm_queue_exception_e(vcpu, PF_VECTOR, error_code);
}

static int kvm_read_guest_virt_system(gva_t addr, void *val, unsigned int bytes,
			       struct kvm_vcpu *vcpu, uint32_t *error)
{
	return kvm_read_guest_virt_helper(addr, val, bytes, vcpu, 0, error);
}

static int vmx_get_cpl(struct kvm_vcpu *vcpu)
{
	if (!is_protmode(vcpu))
		return 0;

	if (vmx_get_rflags(vcpu) & X86_EFLAGS_VM) /* if virtual 8086 */
		return 3;

	return vmcs_read16(GUEST_CS_SELECTOR) & 3;
}


/* used for instruction fetching */
static int kvm_fetch_guest_virt(gva_t addr, void *val, unsigned int bytes,
				struct kvm_vcpu *vcpu, uint32_t *error)
{
	uint32_t access = (kvm_x86_ops->get_cpl(vcpu) == 3) ? PFERR_USER_MASK : 0;
	return kvm_read_guest_virt_helper(addr, val, bytes, vcpu,
					  access | PFERR_FETCH_MASK, error);
}

static int vcpu_mmio_write(struct kvm_vcpu *vcpu, gpa_t addr, int len,
			   const void *v)
{
#ifdef XXX
	if (vcpu->arch.apic &&
	    !kvm_iodevice_write(&vcpu->arch.apic->dev, addr, len, v))
		return 0;

	return kvm_io_bus_write(vcpu->kvm, KVM_MMIO_BUS, addr, len, v);
#else
	return 0;
#endif /*XXX*/
}

static int vcpu_mmio_read(struct kvm_vcpu *vcpu, gpa_t addr, int len, void *v)
{
#ifdef XXX
	if (vcpu->arch.apic &&
	    !kvm_iodevice_read(&vcpu->arch.apic->dev, addr, len, v))
		return 0;

	return kvm_io_bus_read(vcpu->kvm, KVM_MMIO_BUS, addr, len, v);
#else
	return 0;
#endif /*XXX*/
}

gpa_t kvm_mmu_gva_to_gpa_read(struct kvm_vcpu *vcpu, gva_t gva, uint32_t *error)
{
#ifdef XXX
	uint32_t access = (kvm_x86_ops->get_cpl(vcpu) == 3) ? PFERR_USER_MASK : 0;
	return vcpu->arch.mmu.gva_to_gpa(vcpu, gva, access, error);
#else
	return UNMAPPED_GVA;
#endif
}

static int kvm_read_guest_virt(gva_t addr, void *val, unsigned int bytes,
			       struct kvm_vcpu *vcpu, uint32_t *error)
{
	uint32_t access = (kvm_x86_ops->get_cpl(vcpu) == 3) ? PFERR_USER_MASK : 0;
	return kvm_read_guest_virt_helper(addr, val, bytes, vcpu, access,
					  error);
}

static int emulator_read_emulated(unsigned long addr,
				  void *val,
				  unsigned int bytes,
				  struct kvm_vcpu *vcpu)
{
	gpa_t                 gpa;
	uint32_t error_code;

	if (vcpu->mmio_read_completed) {
		memcpy(val, vcpu->mmio_data, bytes);
#ifdef XXX
		trace_kvm_mmio(KVM_TRACE_MMIO_READ, bytes,
			       vcpu->mmio_phys_addr, *(uint64_t *)val);
#endif /*XXX*/
		vcpu->mmio_read_completed = 0;
		return X86EMUL_CONTINUE;
	}

	gpa = kvm_mmu_gva_to_gpa_read(vcpu, addr, &error_code);

	if (gpa == UNMAPPED_GVA) {
		kvm_inject_page_fault(vcpu, addr, error_code);
		return X86EMUL_PROPAGATE_FAULT;
	}

	/* For APIC access vmexit */
	if ((gpa & PAGEMASK) == APIC_DEFAULT_PHYS_BASE)
		goto mmio;

	if (kvm_read_guest_virt(addr, val, bytes, vcpu, NULL)
				== X86EMUL_CONTINUE)
		return X86EMUL_CONTINUE;

mmio:
	/*
	 * Is this MMIO handled locally?
	 */
	if (!vcpu_mmio_read(vcpu, gpa, bytes, val)) {
#ifdef XXX
		trace_kvm_mmio(KVM_TRACE_MMIO_READ, bytes, gpa, *(uint64_t *)val);
#endif /*XXX*/
		return X86EMUL_CONTINUE;
	}

#ifdef XXX
	trace_kvm_mmio(KVM_TRACE_MMIO_READ_UNSATISFIED, bytes, gpa, 0);
#endif /*XXX*/

	vcpu->mmio_needed = 1;
	vcpu->mmio_phys_addr = gpa;
	vcpu->mmio_size = bytes;
	vcpu->mmio_is_write = 0;

	return X86EMUL_UNHANDLEABLE;
}

int emulator_write_phys(struct kvm_vcpu *vcpu, gpa_t gpa,
			  const void *val, int bytes)
{
	int ret;

	ret = kvm_write_guest(vcpu->kvm, gpa, val, bytes);
	if (ret < 0)
		return 0;
#ifdef XXX
	kvm_mmu_pte_write(vcpu, gpa, val, bytes, 1);
#endif /*XXX*/
	return 1;
}

gpa_t kvm_mmu_gva_to_gpa_write(struct kvm_vcpu *vcpu, gva_t gva, uint32_t *error)
{
#ifdef XXX
	uint32_t access = (kvm_x86_ops->get_cpl(vcpu) == 3) ? PFERR_USER_MASK : 0;
	access |= PFERR_WRITE_MASK;
	return vcpu->arch.mmu.gva_to_gpa(vcpu, gva, access, error);
#else
	return UNMAPPED_GVA;
#endif
}

static int emulator_write_emulated_onepage(unsigned long addr,
					   const void *val,
					   unsigned int bytes,
					   struct kvm_vcpu *vcpu)
{
	gpa_t                 gpa;
	uint32_t error_code;

	gpa = kvm_mmu_gva_to_gpa_write(vcpu, addr, &error_code);

	if (gpa == UNMAPPED_GVA) {
		kvm_inject_page_fault(vcpu, addr, error_code);
		return X86EMUL_PROPAGATE_FAULT;
	}

	/* For APIC access vmexit */
	if ((gpa & PAGEMASK) == APIC_DEFAULT_PHYS_BASE)
		goto mmio;

	if (emulator_write_phys(vcpu, gpa, val, bytes))
		return X86EMUL_CONTINUE;

mmio:
#ifdef XXX
	trace_kvm_mmio(KVM_TRACE_MMIO_WRITE, bytes, gpa, *(uint64_t *)val);
#endif /*XXX*/
	/*
	 * Is this MMIO handled locally?
	 */
	if (!vcpu_mmio_write(vcpu, gpa, bytes, val))
		return X86EMUL_CONTINUE;

	vcpu->mmio_needed = 1;
	vcpu->mmio_phys_addr = gpa;
	vcpu->mmio_size = bytes;
	vcpu->mmio_is_write = 1;
	memcpy(vcpu->mmio_data, val, bytes);

	return X86EMUL_CONTINUE;
}

int emulator_write_emulated(unsigned long addr,
				   const void *val,
				   unsigned int bytes,
				   struct kvm_vcpu *vcpu)
{
	/* Crossing a page boundary? */
	if (((addr + bytes - 1) ^ addr) & PAGEMASK) {
		int rc, now;

		now = -addr & ~PAGEMASK;
		rc = emulator_write_emulated_onepage(addr, val, now, vcpu);
		if (rc != X86EMUL_CONTINUE)
			return rc;
		addr += now;
		val += now;
		bytes -= now;
	}
	return emulator_write_emulated_onepage(addr, val, bytes, vcpu);
}

static int emulator_cmpxchg_emulated(unsigned long addr,
				     const void *old,
				     const void *new,
				     unsigned int bytes,
				     struct kvm_vcpu *vcpu)
{
	cmn_err(CE_WARN, "kvm: emulating exchange as write\n");
#ifndef CONFIG_X86_64
	/* guests cmpxchg8b have to be emulated atomically */
	if (bytes == 8) {
		gpa_t gpa;
		struct page *page;
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

	return emulator_write_emulated(addr, new, bytes, vcpu);
}

static struct x86_emulate_ops emulate_ops = {
	.read_std            = kvm_read_guest_virt_system,
	.fetch               = kvm_fetch_guest_virt,
	.read_emulated       = emulator_read_emulated,
	.write_emulated      = emulator_write_emulated,
	.cmpxchg_emulated    = emulator_cmpxchg_emulated,
};

static void cache_all_regs(struct kvm_vcpu *vcpu)
{
	kvm_register_read(vcpu, VCPU_REGS_RAX);
	kvm_register_read(vcpu, VCPU_REGS_RSP);
	kvm_register_read(vcpu, VCPU_REGS_RIP);
	vcpu->arch.regs_dirty = ~0;
}

int kvm_mmu_unprotect_page_virt(struct kvm_vcpu *vcpu, gva_t gva)
{
	gpa_t gpa;
	int r;
#ifdef XXX
	if (tdp_enabled)
		return 0;

	gpa = kvm_mmu_gva_to_gpa_read(vcpu, gva, NULL);

	mutex_enter(&vcpu->kvm->mmu_lock);
	r = kvm_mmu_unprotect_page(vcpu->kvm, gpa >> PAGESHIFT);
	mutex_exit(&vcpu->kvm->mmu_lock);
	return r;
#else
	return 0;
#endif /*XXX*/
}

int emulate_instruction(struct kvm_vcpu *vcpu,
			unsigned long cr2,
			uint16_t error_code,
			int emulation_type)
{
	int r, shadow_mask;
	struct decode_cache *c;
	struct kvm_run *run = vcpu->run;

#ifdef XXX
	kvm_clear_exception_queue(vcpu);
#endif /*XXX*/
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
		vcpu->arch.emulate_ctxt.mode =
			(!is_protmode(vcpu)) ? X86EMUL_MODE_REAL :
			(vcpu->arch.emulate_ctxt.eflags & X86_EFLAGS_VM)
			? X86EMUL_MODE_VM86 : cs_l
			? X86EMUL_MODE_PROT64 :	cs_db
			? X86EMUL_MODE_PROT32 : X86EMUL_MODE_PROT16;

		r = x86_decode_insn(&vcpu->arch.emulate_ctxt, &emulate_ops);

		/* Only allow emulation of specific instructions on #UD
		 * (namely VMMCALL, sysenter, sysexit, syscall)*/
		c = &vcpu->arch.emulate_ctxt.decode;
		if (emulation_type & EMULTYPE_TRAP_UD) {
			if (!c->twobyte)
				return EMULATE_FAIL;
			switch (c->b) {
			case 0x01: /* VMMCALL */
				if (c->modrm_mod != 3 || c->modrm_rm != 1)
					return EMULATE_FAIL;
				break;
			case 0x34: /* sysenter */
			case 0x35: /* sysexit */
				if (c->modrm_mod != 0 || c->modrm_rm != 0)
					return EMULATE_FAIL;
				break;
			case 0x05: /* syscall */
				if (c->modrm_mod != 0 || c->modrm_rm != 0)
					return EMULATE_FAIL;
				break;
			default:
				return EMULATE_FAIL;
			}

			if (!(c->modrm_reg == 0 || c->modrm_reg == 3))
				return EMULATE_FAIL;
		}

#ifdef XXX
		++vcpu->stat.insn_emulation;
#endif /*XXX*/
		if (r)  {
#ifdef XXX
			++vcpu->stat.insn_emulation_fail;
#endif /*XXX*/
			if (kvm_mmu_unprotect_page_virt(vcpu, cr2))
				return EMULATE_DONE;
			return EMULATE_FAIL;
		}
	}

	if (emulation_type & EMULTYPE_SKIP) {
		kvm_rip_write(vcpu, vcpu->arch.emulate_ctxt.decode.eip);
		return EMULATE_DONE;
	}

	r = x86_emulate_insn(&vcpu->arch.emulate_ctxt, &emulate_ops);
	shadow_mask = vcpu->arch.emulate_ctxt.interruptibility;

	if (r == 0)
		kvm_x86_ops->set_interrupt_shadow(vcpu, shadow_mask);

	if (vcpu->arch.pio.string)
		return EMULATE_DO_MMIO;

	if ((r || vcpu->mmio_is_write) && run) {
		run->exit_reason = KVM_EXIT_MMIO;
		run->mmio.phys_addr = vcpu->mmio_phys_addr;
		memcpy(run->mmio.data, vcpu->mmio_data, 8);
		run->mmio.len = vcpu->mmio_size;
		run->mmio.is_write = vcpu->mmio_is_write;
	}

	if (r) {
		if (kvm_mmu_unprotect_page_virt(vcpu, cr2))
			return EMULATE_DONE;
		if (!vcpu->mmio_needed) {
#ifdef XXX
			kvm_report_emulation_failure(vcpu, "mmio");
#endif /*XXX*/
			return EMULATE_FAIL;
		}
		return EMULATE_DO_MMIO;
	}

	kvm_set_rflags(vcpu, vcpu->arch.emulate_ctxt.eflags);

	if (vcpu->mmio_is_write) {
		vcpu->mmio_needed = 0;
		return EMULATE_DO_MMIO;
	}

	return EMULATE_DONE;
}

/*
 * The guest has exited.  See if we can fix it or if we need userspace
 * assistance.
 */
static int handle_exception(struct kvm_vcpu *vcpu)
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
		return handle_machine_check(vcpu);

	if ((vect_info & VECTORING_INFO_VALID_MASK) &&
	    !is_page_fault(intr_info)) {
		vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
		vcpu->run->internal.suberror = KVM_INTERNAL_ERROR_SIMUL_EX;
		vcpu->run->internal.ndata = 2;
		vcpu->run->internal.data[0] = vect_info;
		vcpu->run->internal.data[1] = intr_info;
		return 0;
	}

	if ((intr_info & INTR_INFO_INTR_TYPE_MASK) == INTR_TYPE_NMI_INTR)
		return 1;  /* already handled by vmx_vcpu_run() */

#ifdef XXX
	if (is_no_device(intr_info)) {
		vmx_fpu_activate(vcpu);
		return 1;
	}

	if (is_invalid_opcode(intr_info)) {
		er = emulate_instruction(vcpu, 0, 0, EMULTYPE_TRAP_UD);
		if (er != EMULATE_DONE)
			kvm_queue_exception(vcpu, UD_VECTOR);
		return 1;
	}
#endif /*XXX*/

	error_code = 0;
	rip = kvm_rip_read(vcpu);
	if (intr_info & INTR_INFO_DELIVER_CODE_MASK)
		error_code = vmcs_read32(VM_EXIT_INTR_ERROR_CODE);
	if (is_page_fault(intr_info)) {
		/* EPT won't cause page fault directly */
		if (enable_ept)
			cmn_err(CE_PANIC, "page fault with ept enabled\n");
		cr2 = vmcs_readl(EXIT_QUALIFICATION);
#ifdef XXX
		trace_kvm_page_fault(cr2, error_code);

		if (kvm_event_needs_reinjection(vcpu))
			kvm_mmu_unprotect_page_virt(vcpu, cr2);
		return kvm_mmu_page_fault(vcpu, cr2, error_code);
#else
		return -1;
#endif /*XXX*/
	}

#ifdef XXX
	if (vmx->rmode.vm86_active &&
	    handle_rmode_exception(vcpu, intr_info & INTR_INFO_VECTOR_MASK,
								error_code)) {
		if (vcpu->arch.halt_request) {
			vcpu->arch.halt_request = 0;
			return kvm_emulate_halt(vcpu);
		}
		return 1;
	}
#endif /*XXX*/

	ex_no = intr_info & INTR_INFO_VECTOR_MASK;
	switch (ex_no) {
	case DB_VECTOR:
#ifdef XXX
		dr6 = vmcs_readl(EXIT_QUALIFICATION);
		if (!(vcpu->guest_debug &
		      (KVM_GUESTDBG_SINGLESTEP | KVM_GUESTDBG_USE_HW_BP))) {
			vcpu->arch.dr6 = dr6 | DR6_FIXED_1;
			kvm_queue_exception(vcpu, DB_VECTOR);
			return 1;
		}
		kvm_run->debug.arch.dr6 = dr6 | DR6_FIXED_1;
		kvm_run->debug.arch.dr7 = vmcs_readl(GUEST_DR7);
		/* fall through */
#endif /*XXX*/
	case BP_VECTOR:
#ifdef XXX
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
#endif /*XXX*/
		break;
	default:
		kvm_run->exit_reason = KVM_EXIT_EXCEPTION;
		kvm_run->ex.exception = ex_no;
		kvm_run->ex.error_code = error_code;
		break;
	}
	return 0;
}

static int handle_external_interrupt(struct kvm_vcpu *vcpu)
{
#ifdef XXX
	++vcpu->stat.irq_exits;
#endif /*XXX*/
	return 1;
}

static int handle_triple_fault(struct kvm_vcpu *vcpu)
{
	vcpu->run->exit_reason = KVM_EXIT_SHUTDOWN;
	return 0;
}

static int handle_io(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qualification;
	int size, in, string;
	unsigned port;

#ifdef XXX
	++vcpu->stat.io_exits;
#endif /*XXX*/
	exit_qualification = vmcs_readl(EXIT_QUALIFICATION);
	string = (exit_qualification & 16) != 0;

	if (string) {
		if (emulate_instruction(vcpu, 0, 0, 0) == EMULATE_DO_MMIO)
			return 0;
		return 1;
	}

	size = (exit_qualification & 7) + 1;
	in = (exit_qualification & 8) != 0;
	port = exit_qualification >> 16;
#ifdef XXX
	skip_emulated_instruction(vcpu);
	return kvm_emulate_pio(vcpu, in, size, port);
#endif /*XXX*/
}

static int handle_nmi_window(struct kvm_vcpu *vcpu)
{
	uint32_t cpu_based_vm_exec_control;

	/* clear pending NMI */
	cpu_based_vm_exec_control = vmcs_read32(CPU_BASED_VM_EXEC_CONTROL);
	cpu_based_vm_exec_control &= ~CPU_BASED_VIRTUAL_NMI_PENDING;
	vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, cpu_based_vm_exec_control);
#ifdef XXX
	++vcpu->stat.nmi_window_exits;
#endif /*XXX*/

	return 1;
}

static int handle_invalid_guest_state(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	enum emulation_result err = EMULATE_DONE;
	int ret = 1;

#ifdef XXX
	while (!guest_state_valid(vcpu)) {
		err = emulate_instruction(vcpu, 0, 0, 0);

		if (err == EMULATE_DO_MMIO) {
			ret = 0;
			goto out;
		}

		if (err != EMULATE_DONE) {
			vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
			vcpu->run->internal.suberror = KVM_INTERNAL_ERROR_EMULATION;
			vcpu->run->internal.ndata = 0;
			ret = 0;
			goto out;
		}
		if (signal_pending(current))
			goto out;
		if (need_resched())
			schedule();
	}
#endif /*XXX*/

	vmx->emulation_required = 0;
out:
	return ret;
}

void kvm_set_cr0(struct kvm_vcpu *vcpu, unsigned long cr0)
{
	cr0 |= X86_CR0_ET;

#ifdef CONFIG_X86_64
	if (cr0 & 0xffffffff00000000UL) {
#ifdef XXX
		kvm_inject_gp(vcpu, 0);
#endif
		return;
	}
#endif

	cr0 &= ~CR0_RESERVED_BITS;

	if ((cr0 & X86_CR0_NW) && !(cr0 & X86_CR0_CD)) {
#ifdef XXX
		kvm_inject_gp(vcpu, 0);
#endif
		return;
	}

	if ((cr0 & X86_CR0_PG) && !(cr0 & X86_CR0_PE)) {
#ifdef XXX
		kvm_inject_gp(vcpu, 0);
#endif
		return;
	}

	if (!is_paging(vcpu) && (cr0 & X86_CR0_PG)) {
#ifdef CONFIG_X86_64
#ifdef XXX
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
#endif /*XXX*/
#endif
#ifdef XXX
		if (is_pae(vcpu) && !load_pdptrs(vcpu, vcpu->arch.cr3)) {
			kvm_inject_gp(vcpu, 0);
			return;
		}
#endif /*XXX*/

	}

	kvm_x86_ops->set_cr0(vcpu, cr0);
	vcpu->arch.cr0 = cr0;
#ifdef XXX
	kvm_mmu_reset_context(vcpu);
#endif /*XXX*/
	return;
}

static inline int constant_test_bit(int nr, const void *addr)
{
	const uint32_t *p = (const uint32_t *)addr;
	return ((1UL << (nr & 31)) & (p[nr >> 5])) != 0;
}
static inline int variable_test_bit(int nr, const void *addr)
{
	uint8_t v;
	const uint32_t *p = (const uint32_t *)addr;

	asm("btl %2,%1; setc %0" : "=qm" (v) : "m" (*p), "Ir" (nr));
	return v;
}

#define test_bit(nr,addr) \
(__builtin_constant_p(nr) ? \
 constant_test_bit((nr),(addr)) : \
 variable_test_bit((nr),(addr)))

static int pdptrs_changed(struct kvm_vcpu *vcpu)
{
	uint64_t pdpte[ARRAY_SIZE(vcpu->arch.pdptrs)];
	int changed = 1;
	int r;

	if (is_long_mode(vcpu) || !is_pae(vcpu))
		return 0;

	if (!test_bit(VCPU_EXREG_PDPTR,
		      (unsigned long *)&vcpu->arch.regs_avail))
		return 1;

	r = kvm_read_guest(vcpu->kvm, vcpu->arch.cr3 & ~31u, pdpte, sizeof(pdpte));
	if (r < 0)
		goto out;
	changed = memcmp(pdpte, vcpu->arch.pdptrs, sizeof(pdpte)) != 0;
out:

	return changed;
}

void kvm_set_cr3(struct kvm_vcpu *vcpu, unsigned long cr3)
{
	if (cr3 == vcpu->arch.cr3 && !pdptrs_changed(vcpu)) {
#ifdef XXX
		kvm_mmu_sync_roots(vcpu);
		kvm_mmu_flush_tlb(vcpu);
#endif /*XXX*/
		return;
	}

	if (is_long_mode(vcpu)) {
		if (cr3 & CR3_L_MODE_RESERVED_BITS) {
#ifdef XXX
			kvm_inject_gp(vcpu, 0);
#endif /*XXX*/
			return;
		}
	} else {
#ifdef XXX
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
#endif /*XXX*/
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
#ifdef XXX
	if (unlikely(!gfn_to_memslot(vcpu->kvm, cr3 >> PAGESHIFT)))
		kvm_inject_gp(vcpu, 0);
	else {
#endif /*XXX*/
		vcpu->arch.cr3 = cr3;
#ifdef XXX
		vcpu->arch.mmu.new_cr3(vcpu);
	}
#endif /*XXX*/
}

void kvm_set_cr4(struct kvm_vcpu *vcpu, unsigned long cr4)
{
	unsigned long old_cr4 = kvm_read_cr4(vcpu);
	unsigned long pdptr_bits = X86_CR4_PGE | X86_CR4_PSE | X86_CR4_PAE;

	if (cr4 & CR4_RESERVED_BITS) {
#ifdef XXX
		kvm_inject_gp(vcpu, 0);
#endif /*XXX*/
		return;
	}

	if (is_long_mode(vcpu)) {
		if (!(cr4 & X86_CR4_PAE)) {
#ifdef XXX
			kvm_inject_gp(vcpu, 0);
#endif /*XXX*/
			return;
		}
#ifdef XXX
	} else if (is_paging(vcpu) && (cr4 & X86_CR4_PAE)
		   && ((cr4 ^ old_cr4) & pdptr_bits)
		   && !load_pdptrs(vcpu, vcpu->arch.cr3)) {
		kvm_inject_gp(vcpu, 0);
		return;
#endif /*XXX*/
	}

	if (cr4 & X86_CR4_VMXE) {
#ifdef XXX
		kvm_inject_gp(vcpu, 0);
#endif /*XXX*/
		return;
	}
	kvm_x86_ops->set_cr4(vcpu, cr4);
	vcpu->arch.cr4 = cr4;
	vcpu->arch.mmu.base_role.cr4_pge = (cr4 & X86_CR4_PGE) && !tdp_enabled;
	kvm_mmu_reset_context(vcpu);
}

static int handle_cr(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qualification, val;
	int cr;
	int reg;

	exit_qualification = vmcs_readl(EXIT_QUALIFICATION);
	cr = exit_qualification & 15;
	reg = (exit_qualification >> 8) & 15;
	switch ((exit_qualification >> 4) & 3) {
	case 0: /* mov to cr */
		val = kvm_register_read(vcpu, reg);
#ifdef XXX
		trace_kvm_cr_write(cr, val);
#endif /*XXX*/
		switch (cr) {
		case 0:
			kvm_set_cr0(vcpu, val);
#ifdef XXX
			skip_emulated_instruction(vcpu);
#endif /*XXX*/
			return 1;
		case 3:
			kvm_set_cr3(vcpu, val);
#ifdef XXX			
			skip_emulated_instruction(vcpu);
#endif /*XXX*/
			return 1;
		case 4:
			kvm_set_cr4(vcpu, val);
#ifdef XXX
			skip_emulated_instruction(vcpu);
#endif /*XXX*/
			return 1;
		case 8: {
				uint8_t cr8_prev = kvm_get_cr8(vcpu);
				uint8_t cr8 = kvm_register_read(vcpu, reg);
				kvm_set_cr8(vcpu, cr8);
#ifdef XXX
				skip_emulated_instruction(vcpu);
#endif /*XXX*/
				if (irqchip_in_kernel(vcpu->kvm))
					return 1;
				if (cr8_prev <= cr8)
					return 1;
				vcpu->run->exit_reason = KVM_EXIT_SET_TPR;
				return 0;
			}
		};
		break;
	case 2: /* clts */
		vmx_set_cr0(vcpu, kvm_read_cr0_bits(vcpu, ~X86_CR0_TS));
#ifdef XXX
		trace_kvm_cr_write(0, kvm_read_cr0(vcpu));
		skip_emulated_instruction(vcpu);
		vmx_fpu_activate(vcpu);
#endif /*XXX*/
		return 1;
	case 1: /*mov from cr*/
		switch (cr) {
		case 3:
			kvm_register_write(vcpu, reg, vcpu->arch.cr3);
#ifdef XXX
			trace_kvm_cr_read(cr, vcpu->arch.cr3);
			skip_emulated_instruction(vcpu);
#endif /*XXX*/
			return 1;
		case 8:
			val = kvm_get_cr8(vcpu);
			kvm_register_write(vcpu, reg, val);
#ifdef XXX
			trace_kvm_cr_read(cr, val);
			skip_emulated_instruction(vcpu);
#endif /*XXX*/
			return 1;
		}
		break;
	case 3: /* lmsw */
		val = (exit_qualification >> LMSW_SOURCE_DATA_SHIFT) & 0x0f;
#ifdef XXX
		trace_kvm_cr_write(0, (kvm_read_cr0(vcpu) & ~0xful) | val);
		kvm_lmsw(vcpu, val);

		skip_emulated_instruction(vcpu);
#endif /*XXX*/
		return 1;
	default:
		break;
	}
	vcpu->run->exit_reason = 0;
	cmn_err(CE_WARN, "unhandled control register: op %d cr %d\n",
	       (int)(exit_qualification >> 4) & 3, cr);
	return 0;
}

static int handle_dr(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qualification;
	unsigned long val;
	int dr, reg;

#ifdef XXX
	/* Do not handle if the CPL > 0, will trigger GP on re-entry */
	if (!kvm_require_cpl(vcpu, 0))
		return 1;
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
			return 0;
		} else {
			vcpu->arch.dr7 &= ~DR7_GD;
			vcpu->arch.dr6 |= DR6_BD;
			vmcs_writel(GUEST_DR7, vcpu->arch.dr7);
			kvm_queue_exception(vcpu, DB_VECTOR);
			return 1;
		}
	}
#endif /*XXX*/
	exit_qualification = vmcs_readl(EXIT_QUALIFICATION);
	dr = exit_qualification & DEBUG_REG_ACCESS_NUM;
	reg = DEBUG_REG_ACCESS_REG(exit_qualification);
	if (exit_qualification & TYPE_MOV_FROM_DR) {
		switch (dr) {
		case 0 ... 3:
			val = vcpu->arch.db[dr];
			break;
		case 4:
#ifdef XXX
			if (check_dr_alias(vcpu) < 0)
#endif /*XXX*/
				return 1;
			/* fall through */
		case 6:
			val = vcpu->arch.dr6;
			break;
		case 5:
#ifdef XXX
			if (check_dr_alias(vcpu) < 0)
#endif /*XXX*/
				return 1;
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
#ifdef XXX
			if (!(vcpu->guest_debug & KVM_GUESTDBG_USE_HW_BP))
#endif
				vcpu->arch.eff_db[dr] = val;
			break;
		case 4:
#ifdef XXX
			if (check_dr_alias(vcpu) < 0)
#endif /*XXX*/
				return 1;
			/* fall through */
		case 6:
			if (val & 0xffffffff00000000ULL) {
				kvm_inject_gp(vcpu, 0);
				return 1;
			}
			vcpu->arch.dr6 = (val & DR6_VOLATILE) | DR6_FIXED_1;
			break;
		case 5:
#ifdef XXX
			if (check_dr_alias(vcpu) < 0)
#endif /*XXX*/
				return 1;
			/* fall through */
		default: /* 7 */
			if (val & 0xffffffff00000000ULL) {
				kvm_inject_gp(vcpu, 0);
				return 1;
			}
			vcpu->arch.dr7 = (val & DR7_VOLATILE) | DR7_FIXED_1;
#ifdef XXX
			if (!(vcpu->guest_debug & KVM_GUESTDBG_USE_HW_BP)) {
#endif /*XXX*/
				vmcs_writel(GUEST_DR7, vcpu->arch.dr7);
				vcpu->arch.switch_db_regs =
					(val & DR7_BP_EN_MASK);
#ifdef XXX
			}
#endif /*XXX*/
			break;
		}
	}
#ifdef XXX
	skip_emulated_instruction(vcpu);
#endif /*XXX*/
	return 1;
}

static int handle_cpuid(struct kvm_vcpu *vcpu)
{
#ifdef XXX
	kvm_emulate_cpuid(vcpu);
#endif /*XXX*/
	return 1;
}

static int handle_rdmsr(struct kvm_vcpu *vcpu)
{
	uint32_t ecx = vcpu->arch.regs[VCPU_REGS_RCX];
	uint64_t data;

	if (vmx_get_msr(vcpu, ecx, &data)) {
#ifdef XXX
		trace_kvm_msr_read_ex(ecx);
#endif /*XXX*/
		kvm_inject_gp(vcpu, 0);
		return 1;
	}

#ifdef XXX
	trace_kvm_msr_read(ecx, data);
#endif /*XXX*/

	/* FIXME: handling of bits 32:63 of rax, rdx */
	vcpu->arch.regs[VCPU_REGS_RAX] = data & -1u;
	vcpu->arch.regs[VCPU_REGS_RDX] = (data >> 32) & -1u;
#ifdef XXX
	skip_emulated_instruction(vcpu);
#endif /*XXX*/
	return 1;
}

static int handle_wrmsr(struct kvm_vcpu *vcpu)
{
	uint32_t ecx = vcpu->arch.regs[VCPU_REGS_RCX];
	uint64_t data = (vcpu->arch.regs[VCPU_REGS_RAX] & -1u)
		| ((uint64_t)(vcpu->arch.regs[VCPU_REGS_RDX] & -1u) << 32);

	if (vmx_set_msr(vcpu, ecx, data) != 0) {
#ifdef XXX
		trace_kvm_msr_write_ex(ecx, data);
#endif /*XXX*/	       
		kvm_inject_gp(vcpu, 0);
		return 1;
	}

#ifdef XXX
	trace_kvm_msr_write(ecx, data);
	skip_emulated_instruction(vcpu);
#endif /*XXX*/
	return 1;
}

static int handle_tpr_below_threshold(struct kvm_vcpu *vcpu)
{
	return 1;
}

static int kvm_hv_hypercall_enabled(struct kvm *kvm)
{
	return kvm->arch.hv_hypercall & HV_X64_MSR_HYPERCALL_ENABLE;
}

int kvm_hv_hypercall(struct kvm_vcpu *vcpu)
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
		return 0;
	}

	kvm_x86_ops->get_cs_db_l_bits(vcpu, &cs_db, &cs_l);
	longmode = is_long_mode(vcpu) && cs_l == 1;

	if (!longmode) {
		param = ((uint64_t)kvm_register_read(vcpu, VCPU_REGS_RDX) << 32) |
			(kvm_register_read(vcpu, VCPU_REGS_RAX) & 0xffffffff);
		ingpa = ((uint64_t)kvm_register_read(vcpu, VCPU_REGS_RBX) << 32) |
			(kvm_register_read(vcpu, VCPU_REGS_RCX) & 0xffffffff);
		outgpa = ((uint64_t)kvm_register_read(vcpu, VCPU_REGS_RDI) << 32) |
			(kvm_register_read(vcpu, VCPU_REGS_RSI) & 0xffffffff);
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

#ifdef XXX
	trace_kvm_hv_hypercall(code, fast, rep_cnt, rep_idx, ingpa, outgpa);
#endif /*XXX*/

	switch (code) {
	case HV_X64_HV_NOTIFY_LONG_SPIN_WAIT:
#ifdef XXX
		kvm_vcpu_on_spin(vcpu);
#endif /*XXX*/
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

	return 1;
}


/* Return values for hypercalls */
#define KVM_ENOSYS		1000
#define KVM_EFAULT		EFAULT
#define KVM_E2BIG		E2BIG
#define KVM_EPERM		EPERM

#define KVM_HC_VAPIC_POLL_IRQ		1
#define KVM_HC_MMU_OP			2

/*
 * hypercalls use architecture specific
 */

#ifdef _KERNEL
#ifdef CONFIG_KVM_GUEST
void __init kvm_guest_init(void);
#else
#define kvm_guest_init() do { } while (0)
#endif

static inline int kvm_para_has_feature(unsigned int feature)
{
	if (kvm_arch_para_features() & (1UL << feature))
		return 1;
	return 0;
}
#endif /* _KERNEL */

int kvm_emulate_hypercall(struct kvm_vcpu *vcpu)
{
	unsigned long nr, a0, a1, a2, a3, ret;
	int r = 1;

	if (kvm_hv_hypercall_enabled(vcpu->kvm))
		return kvm_hv_hypercall(vcpu);

	nr = kvm_register_read(vcpu, VCPU_REGS_RAX);
	a0 = kvm_register_read(vcpu, VCPU_REGS_RBX);
	a1 = kvm_register_read(vcpu, VCPU_REGS_RCX);
	a2 = kvm_register_read(vcpu, VCPU_REGS_RDX);
	a3 = kvm_register_read(vcpu, VCPU_REGS_RSI);

#ifdef XXX
	trace_kvm_hypercall(nr, a0, a1, a2, a3);
#endif /*XXX*/

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
#endif /*XXX*/
		break;
	default:
		ret = -ENOSYS;
		break;
	}
out:
	kvm_register_write(vcpu, VCPU_REGS_RAX, ret);
#ifdef XXX
	++vcpu->stat.hypercalls;
#endif /*XXX*/
	return r;
}

static int handle_halt(struct kvm_vcpu *vcpu)
{
#ifdef XXX
	skip_emulated_instruction(vcpu);
	return kvm_emulate_halt(vcpu);
#else
	return 0;
#endif /*XXX*/
}

static int handle_vmcall(struct kvm_vcpu *vcpu)
{
#ifdef XXX
	skip_emulated_instruction(vcpu);
#endif /*XXX*/
	kvm_emulate_hypercall(vcpu);
	return 1;
}

static int handle_vmx_insn(struct kvm_vcpu *vcpu)
{
#ifdef XXX
	kvm_queue_exception(vcpu, UD_VECTOR);
#endif /*XXX*/
	return 1;
}

static int handle_invlpg(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qualification = vmcs_readl(EXIT_QUALIFICATION);

#ifdef XXX
	kvm_mmu_invlpg(vcpu, exit_qualification);
	skip_emulated_instruction(vcpu);
#endif /*XXX*/
	return 1;
}

static int handle_wbinvd(struct kvm_vcpu *vcpu)
{
#ifdef XXX
	skip_emulated_instruction(vcpu);
#endif /*XXX*/
	/* TODO: Add support for VT-d/pass-through device */
	return 1;
}

static int handle_apic_access(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qualification;
	enum emulation_result er;
	unsigned long offset;

	exit_qualification = vmcs_readl(EXIT_QUALIFICATION);
	offset = exit_qualification & 0xffful;

	er = emulate_instruction(vcpu, 0, 0, 0);

	if (er !=  EMULATE_DONE) {
		cmn_err(CE_PANIC,
		       "Fail to handle apic access vmexit! Offset is 0x%lx\n",
		       offset);
	}
	return 1;
}

static int is_vm86_segment(struct kvm_vcpu *vcpu, int seg)
{
	return (seg != VCPU_SREG_LDTR) &&
		(seg != VCPU_SREG_TR) &&
		(kvm_get_rflags(vcpu) & X86_EFLAGS_VM);
}

static inline unsigned long get_desc_limit(const struct desc_struct *desc)
{
	return desc->c.b.limit0 | (desc->c.b.limit << 16);
}

static void seg_desct_to_kvm_desct(struct desc_struct *seg_desc, uint16_t selector,
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

static int kvm_load_realmode_segment(struct kvm_vcpu *vcpu, uint16_t selector, int seg)
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
	return 0;
}

static void get_segment_descriptor_dtable(struct kvm_vcpu *vcpu,
					  uint16_t selector,
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
	}
	else
		kvm_x86_ops->get_gdt(vcpu, dtable);
}

/* allowed just for 8 bytes segments */
static int load_guest_segment_descriptor(struct kvm_vcpu *vcpu, uint16_t selector,
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
		return 1;
	}
	addr = dtable.base + index * 8;
	ret = kvm_read_guest_virt_system(addr, seg_desc, sizeof(*seg_desc),
					 vcpu,  &err);
	if (ret == 1)
		kvm_inject_page_fault(vcpu, addr, err);

       return ret;
}

static int kvm_write_guest_virt(gva_t addr, void *val, unsigned int bytes,
				struct kvm_vcpu *vcpu, uint32_t *error)
{
	void *data = val;
	int r = 0;

#ifdef XXX
	while (bytes) {
		gpa_t gpa = kvm_mmu_gva_to_gpa_write(vcpu, addr, error);
		unsigned offset = addr & (PAGESIZE-1);
		unsigned towrite = min(bytes, (unsigned)PAGESIZE - offset);
		int ret;

		if (gpa == UNMAPPED_GVA) {
			r = X86EMUL_PROPAGATE_FAULT;
			goto out;
		}
		ret = kvm_write_guest(vcpu->kvm, gpa, data, towrite);
		if (ret < 0) {
			r = X86EMUL_UNHANDLEABLE;
			goto out;
		}

		bytes -= towrite;
		data += towrite;
		addr += towrite;
	}
out:
#endif /*XXX*/
	return r;
}

/* allowed just for 8 bytes segments */
static int save_guest_segment_descriptor(struct kvm_vcpu *vcpu, uint16_t selector,
					 struct desc_struct *seg_desc)
{
	struct descriptor_table dtable;
	uint16_t index = selector >> 3;

	get_segment_descriptor_dtable(vcpu, selector, &dtable);

	if (dtable.limit < index * 8 + 7)
		return 1;
	return kvm_write_guest_virt(dtable.base + index*8, seg_desc, sizeof(*seg_desc), vcpu, NULL);
}

int kvm_load_segment_descriptor(struct kvm_vcpu *vcpu, uint16_t selector, int seg)
{
	struct kvm_segment kvm_seg;
	struct desc_struct seg_desc;
	uint8_t dpl, rpl, cpl;
	unsigned err_vec = GP_VECTOR;
	uint32_t err_code = 0;
	int null_selector = !(selector & ~0x3); /* 0000-0003 are null */
	int ret;

	if (is_vm86_segment(vcpu, seg) || !is_protmode(vcpu))
		return kvm_load_realmode_segment(vcpu, selector, seg);

	/* NULL selector is not valid for TR, CS and SS */
	if ((seg == VCPU_SREG_CS || seg == VCPU_SREG_SS || seg == VCPU_SREG_TR)
	    && null_selector)
		goto exception;

	/* TR should be in GDT only */
	if (seg == VCPU_SREG_TR && (selector & (1 << 2)))
		goto exception;

	ret = load_guest_segment_descriptor(vcpu, selector, &seg_desc);
	if (ret)
		return ret;

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
	return 0;
exception:
#ifdef XXX
	kvm_queue_exception_e(vcpu, err_vec, err_code);
#endif /*XXX*/
	return 1;
}

static void save_state_to_tss32(struct kvm_vcpu *vcpu,
				struct tss_segment_32 *tss)
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

static void kvm_load_segment_selector(struct kvm_vcpu *vcpu, uint16_t sel, int seg)
{
	struct kvm_segment kvm_seg;
	kvm_get_segment(vcpu, &kvm_seg, seg);
	kvm_seg.selector = sel;
	kvm_set_segment(vcpu, &kvm_seg, seg);
}

static int load_state_from_tss32(struct kvm_vcpu *vcpu,
				  struct tss_segment_32 *tss)
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
	if (kvm_load_segment_descriptor(vcpu, tss->ldt_selector, VCPU_SREG_LDTR))
		return 1;

	if (kvm_load_segment_descriptor(vcpu, tss->es, VCPU_SREG_ES))
		return 1;

	if (kvm_load_segment_descriptor(vcpu, tss->cs, VCPU_SREG_CS))
		return 1;

	if (kvm_load_segment_descriptor(vcpu, tss->ss, VCPU_SREG_SS))
		return 1;

	if (kvm_load_segment_descriptor(vcpu, tss->ds, VCPU_SREG_DS))
		return 1;

	if (kvm_load_segment_descriptor(vcpu, tss->fs, VCPU_SREG_FS))
		return 1;

	if (kvm_load_segment_descriptor(vcpu, tss->gs, VCPU_SREG_GS))
		return 1;
	return 0;
}

static void save_state_to_tss16(struct kvm_vcpu *vcpu,
				struct tss_segment_16 *tss)
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

static int load_state_from_tss16(struct kvm_vcpu *vcpu,
				 struct tss_segment_16 *tss)
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
		return 1;

	if (kvm_load_segment_descriptor(vcpu, tss->es, VCPU_SREG_ES))
		return 1;

	if (kvm_load_segment_descriptor(vcpu, tss->cs, VCPU_SREG_CS))
		return 1;

	if (kvm_load_segment_descriptor(vcpu, tss->ss, VCPU_SREG_SS))
		return 1;

	if (kvm_load_segment_descriptor(vcpu, tss->ds, VCPU_SREG_DS))
		return 1;
	return 0;
}

int kvm_read_guest(struct kvm *kvm, gpa_t gpa, void *data, unsigned long len)
{
	gfn_t gfn = gpa >> PAGESHIFT;
	int seg;
	int offset = offset_in_page(gpa);
	int ret;

	while ((seg = next_segment(len, offset)) != 0) {
		ret = kvm_read_guest_page(kvm, gfn, data, offset, seg);
		if (ret < 0)
			return ret;
		offset = 0;
		len -= seg;
		data += seg;
		++gfn;
	}
	return 0;
}

static int kvm_task_switch_16(struct kvm_vcpu *vcpu, uint16_t tss_selector,
			      uint16_t old_tss_sel, uint32_t old_tss_base,
			      struct desc_struct *nseg_desc)
{
	struct tss_segment_16 tss_segment_16;
	int ret = 0;

	if (kvm_read_guest(vcpu->kvm, old_tss_base, &tss_segment_16,
			   sizeof tss_segment_16))
		goto out;

	save_state_to_tss16(vcpu, &tss_segment_16);

	if (kvm_write_guest(vcpu->kvm, old_tss_base, &tss_segment_16,
			    sizeof tss_segment_16))
		goto out;

#ifdef XXX
	if (kvm_read_guest(vcpu->kvm, get_tss_base_addr_read(vcpu, nseg_desc),
			   &tss_segment_16, sizeof tss_segment_16))
		goto out;
#endif /*XXX*/

	if (old_tss_sel != 0xffff) {
		tss_segment_16.prev_task_link = old_tss_sel;
#ifdef XXX
		if (kvm_write_guest(vcpu->kvm,
				    get_tss_base_addr_write(vcpu, nseg_desc),
				    &tss_segment_16.prev_task_link,
				    sizeof tss_segment_16.prev_task_link))
			goto out;
#endif /*XXX*/
	}

	if (load_state_from_tss16(vcpu, &tss_segment_16))
		goto out;

	ret = 1;
out:
	return ret;
}

static int kvm_task_switch_32(struct kvm_vcpu *vcpu, uint16_t tss_selector,
		       uint16_t old_tss_sel, uint32_t old_tss_base,
		       struct desc_struct *nseg_desc)
{
	struct tss_segment_32 tss_segment_32;
	int ret = 0;

	if (kvm_read_guest(vcpu->kvm, old_tss_base, &tss_segment_32,
			   sizeof tss_segment_32))
		goto out;

	save_state_to_tss32(vcpu, &tss_segment_32);

	if (kvm_write_guest(vcpu->kvm, old_tss_base, &tss_segment_32,
			    sizeof tss_segment_32))
		goto out;

#ifdef XXX
	if (kvm_read_guest(vcpu->kvm, get_tss_base_addr_read(vcpu, nseg_desc),
			   &tss_segment_32, sizeof tss_segment_32))
		goto out;
#endif /*XXX*/

	if (old_tss_sel != 0xffff) {
		tss_segment_32.prev_task_link = old_tss_sel;

#ifdef XXX
		if (kvm_write_guest(vcpu->kvm,
				    get_tss_base_addr_write(vcpu, nseg_desc),
				    &tss_segment_32.prev_task_link,
				    sizeof tss_segment_32.prev_task_link))
			goto out;
#endif /*XXX*/
	}

	if (load_state_from_tss32(vcpu, &tss_segment_32))
		goto out;

	ret = 1;
out:
	return ret;
}

static uint64_t vmx_get_segment_base(struct kvm_vcpu *vcpu, int seg)
{
	struct kvm_vmx_segment_field *sf = &kvm_vmx_segment_fields[seg];

	return vmcs_readl(sf->base);
}

static unsigned long get_segment_base(struct kvm_vcpu *vcpu, int seg)
{
	return kvm_x86_ops->get_segment_base(vcpu, seg);
}

int kvm_task_switch(struct kvm_vcpu *vcpu, uint16_t tss_selector, int reason)
{
	struct kvm_segment tr_seg;
	struct desc_struct cseg_desc;
	struct desc_struct nseg_desc;
	int ret = 0;
	uint32_t old_tss_base = get_segment_base(vcpu, VCPU_SREG_TR);
	uint16_t old_tss_sel = get_segment_selector(vcpu, VCPU_SREG_TR);
	uint32_t desc_limit;

#ifdef XXX
	old_tss_base = kvm_mmu_gva_to_gpa_write(vcpu, old_tss_base, NULL);
#endif /*XXX*/

	/* FIXME: Handle errors. Failure to read either TSS or their
	 * descriptors should generate a pagefault.
	 */
	if (load_guest_segment_descriptor(vcpu, tss_selector, &nseg_desc))
		goto out;

	if (load_guest_segment_descriptor(vcpu, old_tss_sel, &cseg_desc))
		goto out;

	if (reason != TASK_SWITCH_IRET) {
		int cpl;

		cpl = kvm_x86_ops->get_cpl(vcpu);
		if ((tss_selector & 3) > nseg_desc.c.b.dpl || cpl > nseg_desc.c.b.dpl) {
#ifdef XXX
			kvm_queue_exception_e(vcpu, GP_VECTOR, 0);
#endif /*XXX*/
			return 1;
		}
	}

	desc_limit = get_desc_limit(&nseg_desc);
	if (!nseg_desc.c.b.p ||
	    ((desc_limit < 0x67 && (nseg_desc.c.b.type & 8)) ||
	     desc_limit < 0x2b)) {
#ifdef XXX
		kvm_queue_exception_e(vcpu, TS_VECTOR, tss_selector & 0xfffc);
#endif /*XXX*/
		return 1;
	}

	if (reason == TASK_SWITCH_IRET || reason == TASK_SWITCH_JMP) {
		cseg_desc.c.b.type &= ~(1 << 1); //clear the B flag
		save_guest_segment_descriptor(vcpu, old_tss_sel, &cseg_desc);
	}

	if (reason == TASK_SWITCH_IRET) {
		uint32_t eflags = kvm_get_rflags(vcpu);
		kvm_set_rflags(vcpu, eflags & ~X86_EFLAGS_NT);
	}

	/* set back link to prev task only if NT bit is set in eflags
	   note that old_tss_sel is not used afetr this point */
	if (reason != TASK_SWITCH_CALL && reason != TASK_SWITCH_GATE)
		old_tss_sel = 0xffff;

	if (nseg_desc.c.b.type & 8)
		ret = kvm_task_switch_32(vcpu, tss_selector, old_tss_sel,
					 old_tss_base, &nseg_desc);
	else
		ret = kvm_task_switch_16(vcpu, tss_selector, old_tss_sel,
					 old_tss_base, &nseg_desc);

	if (reason == TASK_SWITCH_CALL || reason == TASK_SWITCH_GATE) {
		uint32_t eflags = kvm_get_rflags(vcpu);
		kvm_set_rflags(vcpu, eflags | X86_EFLAGS_NT);
	}

	if (reason != TASK_SWITCH_IRET) {
		nseg_desc.c.b.type |= (1 << 1);
		save_guest_segment_descriptor(vcpu, tss_selector,
					      &nseg_desc);
	}

	kvm_x86_ops->set_cr0(vcpu, kvm_read_cr0(vcpu) | X86_CR0_TS);
	seg_desct_to_kvm_desct(&nseg_desc, tss_selector, &tr_seg);
	tr_seg.type = 11;
	kvm_set_segment(vcpu, &tr_seg, VCPU_SREG_TR);
out:
	return ret;
}

static int handle_task_switch(struct kvm_vcpu *vcpu)
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
#ifdef XXX
			if (cpu_has_virtual_nmis())
				vmcs_set_bits(GUEST_INTERRUPTIBILITY_INFO,
					      GUEST_INTR_STATE_NMI);
#endif
			break;
		case INTR_TYPE_EXT_INTR:
		case INTR_TYPE_SOFT_INTR:
#ifdef XXX
			kvm_clear_interrupt_queue(vcpu);
#endif /*XXX*/
			break;
		case INTR_TYPE_HARD_EXCEPTION:
		case INTR_TYPE_SOFT_EXCEPTION:
#ifdef XXX
			kvm_clear_exception_queue(vcpu);
#endif /*XXX*/
			break;
		default:
			break;
		}
	}
	tss_selector = exit_qualification;
#ifdef XXX
	if (!idt_v || (type != INTR_TYPE_HARD_EXCEPTION &&
		       type != INTR_TYPE_EXT_INTR &&
		       type != INTR_TYPE_NMI_INTR))
		skip_emulated_instruction(vcpu);
#endif /*XXX*/

	if (!kvm_task_switch(vcpu, tss_selector, reason))
		return 0;

	/* clear all local breakpoint enable flags */
	vmcs_writel(GUEST_DR7, vmcs_readl(GUEST_DR7) & ~55);

	/*
	 * TODO: What about debug traps on tss switch?
	 *       Are we supposed to inject them and update dr6?
	 */

	return 1;
}

static int handle_ept_violation(struct kvm_vcpu *vcpu)
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
		return 0;
	}

	gpa = vmcs_read64(GUEST_PHYSICAL_ADDRESS);
#ifdef XXX
	trace_kvm_page_fault(gpa, exit_qualification);
	return kvm_mmu_page_fault(vcpu, gpa & PAGEMASK, 0);
#else
	return 0;
#endif
}

static int handle_ept_misconfig(struct kvm_vcpu *vcpu)
{
	uint64_t sptes[4];
	int nr_sptes, i;
	gpa_t gpa;

	gpa = vmcs_read64(GUEST_PHYSICAL_ADDRESS);

	cmn_err(CE_WARN, "EPT: Misconfiguration.\n");
	cmn_err(CE_CONT, "EPT: GPA: 0x%llx\n", gpa);
#ifdef XXX
	nr_sptes = kvm_mmu_get_spte_hierarchy(vcpu, gpa, sptes);

	for (i = PT64_ROOT_LEVEL; i > PT64_ROOT_LEVEL - nr_sptes; --i)
		ept_misconfig_inspect_spte(vcpu, sptes[i-1], i);
#endif /*XXX*/

	vcpu->run->exit_reason = KVM_EXIT_UNKNOWN;
	vcpu->run->hw.hardware_exit_reason = EXIT_REASON_EPT_MISCONFIG;

	return 0;
}

/*
 * Indicate a busy-waiting vcpu in spinlock. We do not enable the PAUSE
 * exiting, so only get here on cpu with PAUSE-Loop-Exiting.
 */
static int handle_pause(struct kvm_vcpu *vcpu)
{
#ifdef XXX
	skip_emulated_instruction(vcpu);
	kvm_vcpu_on_spin(vcpu);
#endif /*XXX*/

	return 1;
}

static int handle_invalid_op(struct kvm_vcpu *vcpu)
{
#ifdef XXX	
	kvm_queue_exception(vcpu, UD_VECTOR);
#endif /*XXX*/
	return 1;
}

static int handle_interrupt_window(struct kvm_vcpu *vcpu)
{
	uint32_t cpu_based_vm_exec_control;

	/* clear pending irq */
	cpu_based_vm_exec_control = vmcs_read32(CPU_BASED_VM_EXEC_CONTROL);
	cpu_based_vm_exec_control &= ~CPU_BASED_VIRTUAL_INTR_PENDING;
	vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, cpu_based_vm_exec_control);

#ifdef XXX
	++vcpu->stat.irq_window_exits;

	/*
	 * If the user space waits to inject interrupts, exit as soon as
	 * possible
	 */
	if (!irqchip_in_kernel(vcpu->kvm) &&
	    vcpu->run->request_interrupt_window &&
	    !kvm_cpu_has_interrupt(vcpu)) {
		vcpu->run->exit_reason = KVM_EXIT_IRQ_WINDOW_OPEN;
		return 0;
	}
#endif /*XXX*/
	return 1;
}

/*
 * The exit handlers return 1 if the exit was handled fully and guest execution
 * may resume.  Otherwise they set the kvm_run parameter to indicate what needs
 * to be done to userspace and return 0.
 */
static int (*kvm_vmx_exit_handlers[])(struct kvm_vcpu *vcpu) = {
	[EXIT_REASON_EXCEPTION_NMI]           = handle_exception,
	[EXIT_REASON_EXTERNAL_INTERRUPT]      = handle_external_interrupt,
	[EXIT_REASON_TRIPLE_FAULT]            = handle_triple_fault,
	[EXIT_REASON_NMI_WINDOW]	      = handle_nmi_window,
	[EXIT_REASON_IO_INSTRUCTION]          = handle_io,
	[EXIT_REASON_CR_ACCESS]               = handle_cr,
	[EXIT_REASON_DR_ACCESS]               = handle_dr,
	[EXIT_REASON_CPUID]                   = handle_cpuid,
	[EXIT_REASON_MSR_READ]                = handle_rdmsr,
	[EXIT_REASON_MSR_WRITE]               = handle_wrmsr,
	[EXIT_REASON_PENDING_INTERRUPT]       = handle_interrupt_window,
	[EXIT_REASON_HLT]                     = handle_halt,
	[EXIT_REASON_INVLPG]		      = handle_invlpg,
	[EXIT_REASON_VMCALL]                  = handle_vmcall,
	[EXIT_REASON_VMCLEAR]	              = handle_vmx_insn,
	[EXIT_REASON_VMLAUNCH]                = handle_vmx_insn,
	[EXIT_REASON_VMPTRLD]                 = handle_vmx_insn,
	[EXIT_REASON_VMPTRST]                 = handle_vmx_insn,
	[EXIT_REASON_VMREAD]                  = handle_vmx_insn,
	[EXIT_REASON_VMRESUME]                = handle_vmx_insn,
	[EXIT_REASON_VMWRITE]                 = handle_vmx_insn,
	[EXIT_REASON_VMOFF]                   = handle_vmx_insn,
	[EXIT_REASON_VMON]                    = handle_vmx_insn,
	[EXIT_REASON_TPR_BELOW_THRESHOLD]     = handle_tpr_below_threshold,
	[EXIT_REASON_APIC_ACCESS]             = handle_apic_access,
	[EXIT_REASON_WBINVD]                  = handle_wbinvd,
	[EXIT_REASON_TASK_SWITCH]             = handle_task_switch,
	[EXIT_REASON_MCE_DURING_VMENTRY]      = handle_machine_check,
	[EXIT_REASON_EPT_VIOLATION]	      = handle_ept_violation,
	[EXIT_REASON_EPT_MISCONFIG]           = handle_ept_misconfig,
	[EXIT_REASON_PAUSE_INSTRUCTION]       = handle_pause,
	[EXIT_REASON_MWAIT_INSTRUCTION]	      = handle_invalid_op,
	[EXIT_REASON_MONITOR_INSTRUCTION]     = handle_invalid_op,
};

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
		return 0;
	}

	if ((vectoring_info & VECTORING_INFO_VALID_MASK) &&
			(exit_reason != EXIT_REASON_EXCEPTION_NMI &&
			exit_reason != EXIT_REASON_EPT_VIOLATION &&
			exit_reason != EXIT_REASON_TASK_SWITCH))
		cmn_err(CE_WARN, "%s: unexpected, valid vectoring info "
		       "(0x%x) and exit reason is 0x%x\n",
		       __func__, vectoring_info, exit_reason);

#ifdef XXX
	if (unlikely(!cpu_has_virtual_nmis() && vmx->soft_vnmi_blocked)) {
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
#endif /*XXX*/

	if (exit_reason < kvm_vmx_max_exit_handlers
	    && kvm_vmx_exit_handlers[exit_reason])
		return kvm_vmx_exit_handlers[exit_reason](vcpu);
	else {
		vcpu->run->exit_reason = KVM_EXIT_UNKNOWN;
		vcpu->run->hw.hardware_exit_reason = exit_reason;
	}
	return 0;
}

static inline void kvm_guest_exit(void)
{
#ifdef XXX
	account_system_vtime(current);
	current->flags &= ~PF_VCPU;
#endif /*XXX*/
}

static inline void kvm_guest_enter(void)
{
#ifdef XXX
	account_system_vtime(current);
	current->flags |= PF_VCPU;
#endif /*XXX*/
}

int mmu_topup_memory_caches(struct kvm_vcpu *vcpu);

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

static inline int kvm_mmu_reload(struct kvm_vcpu *vcpu)
{
	if (vcpu->arch.mmu.root_hpa != INVALID_PAGE)
		return 0;

	return kvm_mmu_load(vcpu);
}

static int vcpu_enter_guest(struct kvm_vcpu *vcpu)
{
	int r;

	int req_int_win = !irqchip_in_kernel(vcpu->kvm) &&
		vcpu->run->request_interrupt_window;

	if (vcpu->requests)
		if (test_and_clear_bit(KVM_REQ_MMU_RELOAD, &vcpu->requests))
			kvm_mmu_unload(vcpu);

	r = kvm_mmu_reload(vcpu);
	if (r)
		goto out;
	if (vcpu->requests) {
		if (test_and_clear_bit(KVM_REQ_MIGRATE_TIMER, &vcpu->requests))
			__kvm_migrate_timers(vcpu);
		if (test_and_clear_bit(KVM_REQ_KVMCLOCK_UPDATE, &vcpu->requests))
			kvm_write_guest_time(vcpu);
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
#ifdef XXX
	if (vcpu->fpu_active)
		kvm_load_guest_fpu(vcpu);
#endif /*XXX*/
	kpreempt_disable();

	BT_CLEAR(&vcpu->requests, KVM_REQ_KICK);
#ifdef XXX
	smp_mb__after_clear_bit();
#endif /*XXX*/

	if (vcpu->requests /*XXX || need_resched() || signal_pending(current)*/) {
		BT_SET(&vcpu->requests, KVM_REQ_KICK);
		kpreempt_enable();
		r = 1;
		goto out;
	}
#ifdef XXX
	inject_pending_event(vcpu);

	/* enable NMI/IRQ window open exits if needed */
	if (vcpu->arch.nmi_pending)
		kvm_x86_ops->enable_nmi_window(vcpu);
	else if (kvm_cpu_has_interrupt(vcpu) || req_int_win)
		kvm_x86_ops->enable_irq_window(vcpu);

	if (kvm_lapic_enabled(vcpu)) {
		update_cr8_intercept(vcpu);
#ifdef XXX
		kvm_lapic_sync_to_vapic(vcpu);
#endif /*XXX*/
	}

	srcu_read_unlock(&vcpu->kvm->srcu, vcpu->srcu_idx);
#endif /*XXX*/
	kvm_guest_enter();

#ifdef XXX
	if (unlikely(vcpu->arch.switch_db_regs)) {
		set_debugreg(0, 7);
		set_debugreg(vcpu->arch.eff_db[0], 0);
		set_debugreg(vcpu->arch.eff_db[1], 1);
		set_debugreg(vcpu->arch.eff_db[2], 2);
		set_debugreg(vcpu->arch.eff_db[3], 3);
	}

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
#endif /*XXX*/
	BT_SET(&vcpu->requests, KVM_REQ_KICK);

#ifdef XXX
	++vcpu->stat.exits;
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

	kvm_lapic_sync_from_vapic(vcpu);
#endif /*XXX*/
	r = kvm_x86_ops->handle_exit(vcpu);
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
#ifdef XXX
	else
		kvm_run->ready_for_interrupt_injection =
			kvm_arch_interrupt_allowed(vcpu) &&
			!kvm_cpu_has_interrupt(vcpu) &&
			!kvm_event_needs_reinjection(vcpu);
#endif /*XXX*/
}

/*
 * The vCPU has executed a HLT instruction with in-kernel mode enabled.
 */
void kvm_vcpu_block(struct kvm_vcpu *vcpu)
{
#ifdef XXX
	DEFINE_WAIT(wait);

	for (;;) {
		prepare_to_wait(&vcpu->wq, &wait, TASK_INTERRUPTIBLE);

		if (kvm_arch_vcpu_runnable(vcpu)) {
			set_bit(KVM_REQ_UNHALT, &vcpu->requests);
			break;
		}
		if (kvm_cpu_has_pending_timer(vcpu))
			break;
		if (signal_pending(current))
			break;

		schedule();
	}

	finish_wait(&vcpu->wq, &wait);
#endif /*XXX*/
}

static void vapic_enter(struct kvm_vcpu *vcpu)
{
#ifdef XXX
	struct kvm_lapic *apic = vcpu->arch.apic;
	struct page *page;

	if (!apic || !apic->vapic_addr)
		return;

	page = gfn_to_page(vcpu->kvm, apic->vapic_addr >> PAGESHIFT);

	vcpu->arch.apic->vapic_page = page;
#endif /*XXX*/
}

extern int kvm_apic_id(struct kvm_lapic *apic);

static void vapic_exit(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;
	int idx;
#ifdef XXX
	if (!apic || !apic->vapic_addr)
#endif /*XXX*/
		return;
#ifdef XXX
	idx = srcu_read_lock(&vcpu->kvm->srcu);
	kvm_release_page_dirty(apic->vapic_page);
	mark_page_dirty(vcpu->kvm, apic->vapic_addr >> PAGESHIFT);
	srcu_read_unlock(&vcpu->kvm->srcu, idx);
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
#ifdef XXX
	update_divide_count(apic);
	atomic_set(&apic->lapic_timer.pending, 0);
	if (kvm_vcpu_is_bsp(vcpu))
		vcpu->arch.apic_base |= MSR_IA32_APICBASE_BSP;
	apic_update_ppr(apic);
#endif /*XXX*/

	vcpu->arch.apic_arb_prio = 0;

	cmn_err(CE_NOTE, "%s: vcpu=%p, id=%d, base_msr= 0x%016 PRIx64 base_address=0x%0lx.\n",
		__func__, vcpu, kvm_apic_id(apic), vcpu->arch.apic_base, apic->base_address);
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
#endif /*XXX*/
	vapic_enter(vcpu);

	r = 1;
	while (r > 0) {
		if (vcpu->arch.mp_state == KVM_MP_STATE_RUNNABLE)
			r = vcpu_enter_guest(vcpu);
		else {
#ifdef XXX
			srcu_read_unlock(&kvm->srcu, vcpu->srcu_idx);
#endif /*XXX*/
			kvm_vcpu_block(vcpu);
#ifdef XXX
			vcpu->srcu_idx = srcu_read_lock(&kvm->srcu);
#endif /*XXX*/
			/*
			 * XXX - the following should use a bitset_t
			 * and do bitset_atomic_test_and_del().
			 * but I am lazy, and will get to it later
			 */
			if (BT_TEST(&vcpu->requests, KVM_REQ_UNHALT))
			{
				BT_CLEAR(&vcpu->requests, KVM_REQ_UNHALT);
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

		if (r <= 0)
			break;

#ifdef XXX
		clear_bit(KVM_REQ_PENDING_TIMER, &vcpu->requests);
		if (kvm_cpu_has_pending_timer(vcpu))
			kvm_inject_pending_timer_irqs(vcpu);
		if (dm_request_for_irq_injection(vcpu)) {
			r = -EINTR;
			vcpu->run->exit_reason = KVM_EXIT_INTR;
			++vcpu->stat.request_irq_exits;
		}

		if (signal_pending(current)) {
			r = -EINTR;
			vcpu->run->exit_reason = KVM_EXIT_INTR;
			++vcpu->stat.signal_exits;
		}
		if (need_resched()) {
			srcu_read_unlock(&kvm->srcu, vcpu->srcu_idx);
			kvm_resched(vcpu);
			vcpu->srcu_idx = srcu_read_lock(&kvm->srcu);
		}
#endif /*XXX*/
	}
#ifdef XXX
	srcu_read_unlock(&kvm->srcu, vcpu->srcu_idx);
#endif /*XXX*/
	post_kvm_run_save(vcpu);
	vapic_exit(vcpu);
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
		BT_CLEAR(&vcpu->requests, KVM_REQ_UNHALT);
		r = -EAGAIN;
		goto out;
	}

	/* re-sync apic's tpr */
	if (!irqchip_in_kernel(vcpu->kvm))
		kvm_set_cr8(vcpu, kvm_run->cr8);


	if (vcpu->arch.pio.cur_count) {
#ifdef XXX
		vcpu->srcu_idx = srcu_read_lock(&vcpu->kvm->srcu);
		r = complete_pio(vcpu);
		srcu_read_unlock(&vcpu->kvm->srcu, vcpu->srcu_idx);
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
		r = emulate_instruction(vcpu, vcpu->arch.mmio_fault_cr2, 0,
					EMULTYPE_NO_DECODE);
		srcu_read_unlock(&vcpu->kvm->srcu, vcpu->srcu_idx);
		if (r == EMULATE_DO_MMIO) {
			/*
			 * Read-modify-write.  Back to userspace.
			 */
			r = 0;
			goto out;
		}
#endif /*XXX*/
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

static int
kvm_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *cred_p, int *rval_p)
{
	int rval = DDI_SUCCESS;
	volatile int x;  /* XXX - dtrace was not getting fbt return probe */

	switch(cmd) {
	case KVM_GET_API_VERSION:
		cmn_err(CE_NOTE, "kvm_ioctl: KVM_GET_API_VERSION");
		if (arg != NULL) {
			rval = EINVAL;
			break;
		}
		*rval_p = KVM_API_VERSION;
		break;
	case KVM_CREATE_VM:
		if (arg == NULL) {
			rval = EINVAL;
			break;
		}
		rval = kvm_dev_ioctl_create_vm(arg, mode);
		break;
	case KVM_RUN: {
		struct kvm_run_ioc kvm_run_ioc;
		struct kvm *kvmp;
		struct kvm_vcpu *vcpu;

		if (!arg) {
			rval = EINVAL;
			break;
		}
		
		if (ddi_copyin((caddr_t)arg, &kvm_run_ioc, sizeof kvm_run_ioc, mode)) {
			rval = EFAULT;
			break;
		}

		kvmp = find_kvm_id(kvm_run_ioc.kvm_kvmid);
		if (kvmp == NULL) {
			rval = EINVAL;
			break;
		}
		if (!kvmp || kvm_run_ioc.kvm_cpu_index >= kvmp->online_vcpus) {
			rval = EINVAL;
			break;
		}
		vcpu = kvmp->vcpus[kvm_run_ioc.kvm_cpu_index];
		
		rval = kvm_arch_vcpu_ioctl_run(vcpu, vcpu->run);
		break;
	}
	case KVM_CHECK_EXTENSION:
		rval = kvm_dev_ioctl_check_extension_generic(arg, rval_p);
		break;
	case KVM_GET_MSRS: {
		struct kvm_msrs_ioc kvm_msrs_ioc;
		struct kvm_msrs kvm_msrs;
		struct kvm *kvmp;
		struct kvm_vcpu *vcpu;
		struct kvm_msr_entry *entries;
		unsigned size;
		int n;

		if (ddi_copyin((const void *)arg, &kvm_msrs_ioc,
			       sizeof(kvm_msrs_ioc), mode) != 0) {
			rval = EFAULT;
			break;
		}
		kvmp = find_kvm_id(kvm_msrs_ioc.kvm_kvmid);
		rval = EINVAL;
		if (kvmp == NULL)
			break;
		if (!kvmp || kvm_msrs_ioc.kvm_cpu_index >= kvmp->online_vcpus)
			break;

		vcpu = kvmp->vcpus[kvm_msrs_ioc.kvm_cpu_index];

		if (ddi_copyin(kvm_msrs_ioc.kvm_msrs, &kvm_msrs, sizeof(kvm_msrs), mode)) {
			rval = EFAULT;
			break;
		}

		if (kvm_msrs.nmsrs >= MAX_IO_MSRS) {
			rval = E2BIG;
			break;
		}
		
		size = sizeof(struct kvm_msr_entry) * kvm_msrs.nmsrs;
		entries = (struct kvm_msr_entry *) kmem_alloc(size, KM_SLEEP);
		if (!entries) {
			rval = ENOMEM;
			break;
		}

		if (ddi_copyin((caddr_t)(((uint64_t)kvm_msrs_ioc.kvm_msrs)+(sizeof (struct kvm_msrs))), entries, size, mode)) {
			kmem_free(entries, size);
			rval = EFAULT;
			break;
		}

		rval = n = __msr_io(vcpu, &kvm_msrs, entries, kvm_get_msr);

		if (rval < 0) {
			kmem_free(entries, size);
			rval = EINVAL;
			break;
		}

		rval = ddi_copyout(entries, (caddr_t)(((uint64_t)kvm_msrs_ioc.kvm_msrs)+(sizeof (struct kvm_msrs))), size, mode);
		kmem_free(entries, size);
		
		*rval_p = n;

		break;
	}

	case KVM_SET_MSRS: {
		struct kvm_msrs_ioc kvm_msrs_ioc;
		struct kvm_msrs kvm_msrs;
		struct kvm *kvmp;
		struct kvm_vcpu *vcpu;
		struct kvm_msr_entry *entries;
		unsigned size;
		int n;

		if (ddi_copyin((const void *)arg, &kvm_msrs_ioc,
			       sizeof(kvm_msrs_ioc), mode) != 0) {
			rval = EFAULT;
			break;
		}

		rval = EINVAL;
		kvmp = find_kvm_id(kvm_msrs_ioc.kvm_kvmid);
		if (kvmp == NULL)
			break;
		if (!kvmp || kvm_msrs_ioc.kvm_cpu_index >= kvmp->online_vcpus)
			break;

		vcpu = kvmp->vcpus[kvm_msrs_ioc.kvm_cpu_index];

		if (ddi_copyin(kvm_msrs_ioc.kvm_msrs, &kvm_msrs, sizeof(kvm_msrs), mode)) {
			rval = EFAULT;
			break;
		}
		
		if (kvm_msrs.nmsrs >= MAX_IO_MSRS) {
			rval = E2BIG;
			break;
		}

		size = sizeof(struct kvm_msr_entry) * kvm_msrs.nmsrs;
		entries = (struct kvm_msr_entry *)kmem_alloc(size, KM_SLEEP);
		if (!entries) {
			rval = ENOMEM;
			break;
		}

		if (ddi_copyin((caddr_t)(((uint64_t)kvm_msrs_ioc.kvm_msrs)+(sizeof (struct kvm_msrs))), entries, size, mode)) {
			kmem_free(entries, size);
			rval = EFAULT;
			break;
		}

		rval = n = __msr_io(vcpu, &kvm_msrs, entries, do_set_msr);

		if (rval < 0) {
			kmem_free(entries, size);
			rval = EINVAL;
			break;
		}
		kmem_free(entries, size);
		*rval_p = n;
		break;
	}

 	case KVM_CREATE_VCPU: {
		struct kvm_vcpu_ioc kvm_vcpu;
		struct kvm *kvmp;
		
		if (ddi_copyin((const void *)arg, &kvm_vcpu,
			       sizeof(kvm_vcpu), mode) != 0) {
			rval = EFAULT;
			break;
		}

		rval = EINVAL;
		kvmp = find_kvm_id(kvm_vcpu.kvmid);
		if (kvmp == NULL)
			break;

 		rval = kvm_vm_ioctl_create_vcpu(kvmp, kvm_vcpu.id, &kvm_vcpu, rval_p); 
 		if (rval != 0) {
			rval = EINVAL;
			break;
		}
		
		if (ddi_copyout(&kvm_vcpu, (void *)arg,
				sizeof(kvm_vcpu), mode) != 0)
			rval = EFAULT;
 		break; 
	}

 	case KVM_SET_USER_MEMORY_REGION: {
		struct kvm_set_user_memory_ioc kvmioc;
		struct kvm *kvmp;
		
		if (ddi_copyin((const void *)arg, &kvmioc,
			       sizeof(kvmioc), mode) != 0) {
			rval = EFAULT;
			break;
		}

		kvmp = find_kvm_id(kvmioc.kvmid);
		if (kvmp == NULL) {
			rval = EINVAL;
			break;
		}

 		rval = kvm_vm_ioctl_set_memory_region(kvmp, &kvmioc.kvm_userspace_map, 1); 
 		if (rval != 0) {
			rval = EINVAL;
			break;
		}
 		break; 
	}
	case KVM_GET_SUPPORTED_CPUID: {
		struct kvm_cpuid2 *cpuid_arg = (struct kvm_cpuid2 *)arg;
		struct kvm_cpuid2 cpuid;

		if (ddi_copyin(cpuid_arg, &cpuid, sizeof (cpuid), mode)) {
			rval = EFAULT;
			break;
		}
		rval = kvm_dev_ioctl_get_supported_cpuid(&cpuid,
						      cpuid_arg->entries, mode);
		if (rval)
			break;

		if (ddi_copyout(&cpuid, cpuid_arg, sizeof (cpuid), mode))
			rval = EFAULT;
		break;
	}

	case KVM_GET_MSR_INDEX_LIST: {
		struct kvm_msr_list *user_msr_list = (struct kvm_msr_list *)arg;
		struct kvm_msr_list msr_list;
		unsigned n;

		if (ddi_copyin(user_msr_list, &msr_list, sizeof msr_list, mode)) {
			rval = EFAULT;
			break;
		}

		n = msr_list.nmsrs;
		msr_list.nmsrs = num_msrs_to_save + ARRAY_SIZE(emulated_msrs);
		if (ddi_copyout(&msr_list, user_msr_list, sizeof msr_list, mode)) {
			rval = EFAULT;
			break;
		}
		if (n < msr_list.nmsrs) {
			rval = E2BIG;
			break;
		}
		rval = EFAULT;
		if (ddi_copyout(&msrs_to_save, user_msr_list->indices, 
				num_msrs_to_save * sizeof(uint32_t), mode))
			break;
		if (ddi_copyout(&emulated_msrs,
				user_msr_list->indices + num_msrs_to_save,
				ARRAY_SIZE(emulated_msrs) * sizeof(uint32_t), mode))
			break;
		rval = 0;
		*rval_p = 0;
		break;
	}
	case KVM_GET_REGS: {
		struct kvm_regs_ioc kvm_regs_ioc;
		struct kvm *kvmp;
		struct kvm_vcpu *vcpu;

		if (ddi_copyin((caddr_t)arg, &kvm_regs_ioc, sizeof (kvm_regs_ioc), mode)) {
			rval = EFAULT;
			break;
		}

		kvmp = find_kvm_id(kvm_regs_ioc.kvm_kvmid);

		if (!kvmp || kvm_regs_ioc.kvm_cpu_index >= kvmp->online_vcpus) {
			rval = EINVAL;
			break;
		}

		vcpu = kvmp->vcpus[kvm_regs_ioc.kvm_cpu_index];
		
		rval = kvm_arch_vcpu_ioctl_get_regs(vcpu, &kvm_regs_ioc.kvm_regs);
		if (rval) {
			rval = EINVAL;
			break;
		}
		if (ddi_copyout(&kvm_regs_ioc, (caddr_t)arg, sizeof(kvm_regs_ioc), mode))
			rval = EFAULT;
		*rval_p = 0;
		break;
	}
	case KVM_SET_REGS: {
		struct kvm_regs_ioc kvm_regs_ioc;
		struct kvm *kvmp;
		struct kvm_vcpu *vcpu;

		if (ddi_copyin((caddr_t)arg, &kvm_regs_ioc, sizeof (kvm_regs_ioc), mode)) {
			rval = EFAULT;
			break;
		}

		kvmp = find_kvm_id(kvm_regs_ioc.kvm_kvmid);
		if (!kvmp || kvm_regs_ioc.kvm_cpu_index >= kvmp->online_vcpus) {
			rval = EINVAL;
			break;
		}

		vcpu = kvmp->vcpus[kvm_regs_ioc.kvm_cpu_index];

		cmn_err(CE_NOTE, "KVM_SET_REGS: rax = %lx, rbx = %lx, rcx = %lx, rdx = %lx\n",
			kvm_regs_ioc.kvm_regs.rax, kvm_regs_ioc.kvm_regs.rbx, kvm_regs_ioc.kvm_regs.rcx, kvm_regs_ioc.kvm_regs.rdx);

		rval = kvm_arch_vcpu_ioctl_set_regs(vcpu, &kvm_regs_ioc.kvm_regs);
		if (rval)
			rval = EINVAL;
		*rval_p = 0;
		break;
	}
	case KVM_GET_FPU: {
		struct kvm_fpu_ioc kvm_fpu_ioc;
		struct kvm *kvmp;
		struct kvm_vcpu *vcpu;

		if (ddi_copyin((caddr_t)arg, &kvm_fpu_ioc, sizeof(kvm_fpu_ioc), mode)) {
			rval = EFAULT;
			break;
		}

		kvmp = find_kvm_id(kvm_fpu_ioc.kvm_kvmid);
		if (!kvmp || kvm_fpu_ioc.kvm_cpu_index >= kvmp->online_vcpus) {
			rval = EINVAL;
			break;
		}

		vcpu = kvmp->vcpus[kvm_fpu_ioc.kvm_cpu_index];

		rval = kvm_arch_vcpu_ioctl_get_fpu(vcpu, &kvm_fpu_ioc.fpu);
		if (rval) {
			rval = EINVAL;
			break;
		}

		if (ddi_copyout(&kvm_fpu_ioc, (caddr_t)arg, sizeof(struct kvm_fpu), mode))
			rval = EFAULT;

		*rval_p = 0;
		break;
	}
	case KVM_SET_FPU: {
		struct kvm_fpu_ioc kvm_fpu_ioc;
		struct kvm *kvmp;
		struct kvm_vcpu *vcpu;

		if (ddi_copyin((caddr_t)arg, &kvm_fpu_ioc, sizeof(kvm_fpu_ioc), mode)) {
			rval = EFAULT;
			break;
		}

		kvmp = find_kvm_id(kvm_fpu_ioc.kvm_kvmid);
		if (!kvmp || kvm_fpu_ioc.kvm_cpu_index >= kvmp->online_vcpus) {
			rval = EINVAL;
			break;
		}

		vcpu = kvmp->vcpus[kvm_fpu_ioc.kvm_cpu_index];

		rval = kvm_arch_vcpu_ioctl_set_fpu(vcpu, &kvm_fpu_ioc.fpu);
		if (rval)
			rval = EINVAL;
		*rval_p = 0;
		break;
	}
	case KVM_GET_SREGS: {
		struct kvm_sregs_ioc kvm_sregs_ioc;
		struct kvm *kvmp;
		struct kvm_vcpu *vcpu;

		if (ddi_copyin((caddr_t)arg, &kvm_sregs_ioc, sizeof (kvm_sregs_ioc), mode)) {
			rval = EFAULT;
			break;
		}

		kvmp = find_kvm_id(kvm_sregs_ioc.kvm_kvmid);
		if (!kvmp || kvm_sregs_ioc.kvm_cpu_index >= kvmp->online_vcpus) {
			rval = EINVAL;
			break;
		}

		vcpu = kvmp->vcpus[kvm_sregs_ioc.kvm_cpu_index];
		
		rval = kvm_arch_vcpu_ioctl_get_sregs(vcpu, &kvm_sregs_ioc.sregs);
		if (rval) {
			rval = EINVAL;
			break;
		}
		if (ddi_copyout(&kvm_sregs_ioc, (caddr_t)arg, sizeof(kvm_sregs_ioc), mode))
			rval = EFAULT;
		*rval_p = 0;
		break;
	}
	case KVM_SET_SREGS: {
		struct kvm_sregs_ioc kvm_sregs_ioc;
		struct kvm *kvmp;
		struct kvm_vcpu *vcpu;

		if (ddi_copyin((caddr_t)arg, &kvm_sregs_ioc, sizeof (kvm_sregs_ioc), mode)) {
			rval = EFAULT;
			break;
		}

		kvmp = find_kvm_id(kvm_sregs_ioc.kvm_kvmid);
		if (!kvmp || kvm_sregs_ioc.kvm_cpu_index >= kvmp->online_vcpus) {
			rval = EINVAL;
			break;
		}

		vcpu = kvmp->vcpus[kvm_sregs_ioc.kvm_cpu_index];
		
		rval = kvm_arch_vcpu_ioctl_set_sregs(vcpu, &kvm_sregs_ioc.sregs);
		if (rval)
			rval = EINVAL;
		*rval_p = 0;
		break;
	}	
	case KVM_SET_CPUID2: {
		struct kvm_cpuid2_ioc cpuid_ioc;
		struct kvm_cpuid2 cpuid_data;
		struct kvm_vcpu *vcpu;

		if (ddi_copyin((const char *)arg, &cpuid_ioc, sizeof cpuid_ioc, mode)) {
			rval = EFAULT;
			break;
		}
		if (cpuid_ioc.kvm_vcpu_addr == NULL) {
			rval = EINVAL;
			break;
		}

		vcpu = (struct kvm_vcpu *)(cpuid_ioc.kvm_vcpu_addr);

		if (ddi_copyin((const char *)(cpuid_ioc.cpuid_data), (char *)&cpuid_data,
			       sizeof(cpuid_data), mode)) {
			rval = EFAULT;
			break;
		}
		rval = kvm_vcpu_ioctl_set_cpuid2(vcpu, &cpuid_data,
						 cpuid_data.entries, mode);
		if (rval)
			rval = EINVAL;
		break;
	}

	case KVM_GET_CPUID2: {
		struct kvm_cpuid2_ioc cpuid_ioc;
		struct kvm_cpuid2 cpuid_data;
		struct kvm_vcpu *vcpu;

		if (ddi_copyin((const char *)arg, &cpuid_ioc, sizeof cpuid_ioc, mode)) {
			rval = EFAULT;
			break;
		}

		if (cpuid_ioc.kvm_vcpu_addr == NULL) {
			rval = EINVAL;
			break;
		}

		vcpu = (struct kvm_vcpu *)cpuid_ioc.kvm_vcpu_addr;

		if (ddi_copyin((const char *)(cpuid_ioc.cpuid_data), (char *)&cpuid_data,
			       sizeof(cpuid_data), mode)) {
			rval = EFAULT;
			break;
		}

		rval = kvm_vcpu_ioctl_get_cpuid2(vcpu, &cpuid_data,
						 cpuid_data.entries, mode);
		if (rval) {
			rval = EINVAL;
			break;
		}

		if (ddi_copyout(&cpuid_ioc, (char *)arg, sizeof cpuid_ioc, mode))
			rval = EFAULT;
		break;
	}

	case KVM_GET_VCPU_MMAP_SIZE:
		if (arg != NULL) {
			rval = EINVAL;
			break;
		}
		*rval_p = ptob(1);
		break;
	case KVM_SET_TSS_ADDR:
	{
		struct kvm_tss kvm_tss;
		struct kvm *kvmp;
		if (ddi_copyin((const void *)arg, &kvm_tss,
			       sizeof(kvm_tss), mode) != 0) {
			rval = EFAULT;
			break;
		}

		kvmp = find_kvm_id(kvm_tss.kvmid);
		if (kvmp == NULL) {
			rval = EINVAL;
			break;
		}
		rval = kvm_vm_ioctl_set_tss_addr(kvmp, kvm_tss.addr);
		break;
	}
	default:
		rval = EINVAL;  /* x64, others may do other things... */
	}

	x = 10;  /*XXX do something...*/
	if (*rval_p == -1)
		return (EINVAL);
	return (rval);
}

static int
kvm_devmap(dev_t dev, devmap_cookie_t dhp, offset_t off,
		      size_t len, size_t *maplen, uint_t model)
{
	return (ENOTSUP);
}

