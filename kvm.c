
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
#include "kvm.h"

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

	.prepare_guest_switch = nulldev /*vmx_save_host_state*/,
	.vcpu_load = vmx_vcpu_load,
	.vcpu_put = vmx_vcpu_put,

	.set_guest_debug = nulldev /*set_guest_debug*/,
	.get_msr = nulldev /*vmx_get_msr*/,
	.set_msr = nulldev /*vmx_set_msr*/,
	.get_segment_base = nulldev /*vmx_get_segment_base*/,
	.get_segment = nulldev /*vmx_get_segment*/,
	.set_segment = nulldev /*vmx_set_segment*/,
	.get_cpl = nulldev /*vmx_get_cpl*/,
	.get_cs_db_l_bits = nulldev /*vmx_get_cs_db_l_bits*/,
	.decache_cr0_guest_bits = nulldev /*vmx_decache_cr0_guest_bits*/,
	.decache_cr4_guest_bits = nulldev /*vmx_decache_cr4_guest_bits*/,
	.set_cr0 = vmx_set_cr0,
	.set_cr3 = nulldev /*vmx_set_cr3*/,
	.set_cr4 = vmx_set_cr4,
	.set_efer = nulldev /*vmx_set_efer*/,
	.get_idt = nulldev /*vmx_get_idt*/,
	.set_idt = nulldev /*vmx_set_idt*/,
	.get_gdt = nulldev /*vmx_get_gdt*/,
	.set_gdt = nulldev /*vmx_set_gdt*/,
	.cache_reg = nulldev /*vmx_cache_reg*/,
	.get_rflags = nulldev /*vmx_get_rflags*/,
	.set_rflags = nulldev /*vmx_set_rflags*/,
	.fpu_activate = nulldev /*vmx_fpu_activate*/,
	.fpu_deactivate = nulldev /*vmx_fpu_deactivate*/,

	.tlb_flush = nulldev /*vmx_flush_tlb*/,

	.run = nulldev /*vmx_vcpu_run*/,
	.handle_exit = nulldev /*vmx_handle_exit*/,
	.skip_emulated_instruction = nulldev /*skip_emulated_instruction*/,
	.set_interrupt_shadow = nulldev /*vmx_set_interrupt_shadow*/,
	.get_interrupt_shadow = nulldev /*vmx_get_interrupt_shadow*/,
	.patch_hypercall = nulldev /*vmx_patch_hypercall*/,
	.set_irq = nulldev /*vmx_inject_irq*/,
	.set_nmi = nulldev /*vmx_inject_nmi*/,
	.queue_exception = nulldev /*vmx_queue_exception*/,
	.interrupt_allowed = nulldev /*vmx_interrupt_allowed*/,
	.nmi_allowed = nulldev /*vmx_nmi_allowed*/,
	.get_nmi_mask = nulldev /*vmx_get_nmi_mask*/,
	.set_nmi_mask = nulldev /*vmx_set_nmi_mask*/,
	.enable_nmi_window = nulldev /*enable_nmi_window*/,
	.enable_irq_window = nulldev /*enable_irq_window*/,
	.update_cr8_intercept = nulldev /*update_cr8_intercept*/,

	.set_tss_addr = vmx_set_tss_addr,
	.get_tdp_level = nulldev /*get_ept_level*/,
	.get_mt_mask = nulldev /*vmx_get_mt_mask*/,

	.exit_reasons_str = nulldev /*vmx_exit_reasons_str*/,
	.get_lpage_level = nulldev /*vmx_get_lpage_level*/,

	.cpuid_update = nulldev /*vmx_cpuid_update*/,

	.rdtscp_supported = nulldev /*vmx_rdtscp_supported*/,
};

struct kvm_x86_ops *kvm_x86_ops;

/*
 * In linux, there is a separate vmx kernel module from the kvm driver.
 * That may be a good idea, but we're going to do everything in
 * the kvm driver, for now.
 * The call to vmx_init() in _init() is done when the vmx module
 * is loaded on linux.
 */

struct vmcs **vmxarea;  /* 1 per cpu */

static int alloc_kvm_area(void)
{
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

static int setup_vmcs_config(struct vmcs_config *vmcs_conf)
{
	uint32_t vmx_msr_low, vmx_msr_high;
	uint32_t min, opt, min2, opt2;
	uint32_t _pin_based_exec_control = 0;
	uint32_t _cpu_based_exec_control = 0;
	uint32_t _cpu_based_2nd_exec_control = 0;
	uint32_t _vmexit_control = 0;
	uint32_t _vmentry_control = 0;

#ifdef XXX
	min = PIN_BASED_EXT_INTR_MASK | PIN_BASED_NMI_EXITING;
	opt = PIN_BASED_VIRTUAL_NMIS;
	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_PINBASED_CTLS,
				&_pin_based_exec_control) < 0)
		return -EIO;

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
				&_cpu_based_exec_control) < 0)
		return -EIO;
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
					&_cpu_based_2nd_exec_control) < 0)
			return -EIO;
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
				&_vmexit_control) < 0)
		return -EIO;

	min = 0;
	opt = VM_ENTRY_LOAD_IA32_PAT;
	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_ENTRY_CTLS,
				&_vmentry_control) < 0)
		return -EIO;
#endif /*XXX*/

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
#ifdef XXX
	vmcs_conf->order = get_order(vmcs_config.size);
#endif
	vmcs_conf->revision_id = vmx_msr_low;

#ifdef XXX
	vmcs_conf->pin_based_exec_ctrl = _pin_based_exec_control;
	vmcs_conf->cpu_based_exec_ctrl = _cpu_based_exec_control;
	vmcs_conf->cpu_based_2nd_exec_ctrl = _cpu_based_2nd_exec_control;
	vmcs_conf->vmexit_ctrl         = _vmexit_control;
	vmcs_conf->vmentry_ctrl        = _vmentry_control;
#endif
	return 0;
}

static int vmx_hardware_setup(void)
{

	if (setup_vmcs_config(&vmcs_config) < 0)
		return EIO;
#ifdef XXX
	if (boot_cpu_has(X86_FEATURE_NX))
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
#endif /*XXX*/
	return alloc_kvm_area();
}

int kvm_arch_hardware_setup(void)
{
	return kvm_x86_ops->hardware_setup();
}

int kvm_mmu_module_init(void)
{
#ifdef XXX
	pte_chain_cache = kmem_cache_create("kvm_pte_chain",
					    sizeof(struct kvm_pte_chain),
					    0, 0, NULL);
	if (!pte_chain_cache)
		goto nomem;
	rmap_desc_cache = kmem_cache_create("kvm_rmap_desc",
					    sizeof(struct kvm_rmap_desc),
					    0, 0, NULL);
	if (!rmap_desc_cache)
		goto nomem;

	mmu_page_header_cache = kmem_cache_create("kvm_mmu_page_header",
						  sizeof(struct kvm_mmu_page),
						  0, 0, NULL);
	if (!mmu_page_header_cache)
		goto nomem;

	register_shrinker(&mmu_shrinker);

	return 0;

nomem:
	mmu_destroy_caches();
	return -ENOMEM;
#else
	return DDI_SUCCESS;
#endif /*XXX*/
}

int kvm_arch_init(void *opaque)
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

#ifdef XXX
	kvm_init_msr_list();

	kvm_x86_ops = ops;
	kvm_mmu_set_nonpresent_ptes(0ull, 0ull);
	kvm_mmu_set_base_ptes(PT_PRESENT_MASK);
	kvm_mmu_set_mask_ptes(PT_USER_MASK, PT_ACCESSED_MASK,
			PT_DIRTY_MASK, PT64_NX_MASK, 0);


	kvm_timer_init();
#endif

	return 0;

out:
	return r;
}

int kvm_init(void *opaque, unsigned int vcpu_size)
{
	int r;
	int cpu;

	r = kvm_arch_init(opaque);

	if (r != DDI_SUCCESS)
		return (r);
#ifdef XXX
	if (r)
		goto out_fail;

	bad_page = alloc_page(GFP_KERNEL | __GFP_ZERO);

	if (bad_page == NULL) {
		r = -ENOMEM;
		goto out;
	}

	bad_pfn = page_to_pfn(bad_page);

	if (!zalloc_cpumask_var(&cpus_hardware_enabled, GFP_KERNEL)) {
		r = -ENOMEM;
		goto out_free_0;
	}

#endif /*XXX*/

	r = kvm_arch_hardware_setup();
	return (r);

#ifdef XXX
	if (r < 0)
		goto out_free_0a;

	for_each_online_cpu(cpu) {
		smp_call_function_single(cpu,
				kvm_arch_check_processor_compat,
				&r, 1);
		if (r < 0)
			goto out_free_1;
	}

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

	/* A kmem cache lets us meet the alignment requirements of fx_save. */
	kvm_vcpu_cache = kmem_cache_create("kvm_vcpu", vcpu_size,
					   __alignof__(struct kvm_vcpu),
					   0, NULL);
	if (!kvm_vcpu_cache) {
		r = -ENOMEM;
		goto out_free_5;
	}

	kvm_chardev_ops.owner = module;
	kvm_vm_fops.owner = module;
	kvm_vcpu_fops.owner = module;

	r = misc_register(&kvm_dev);
	if (r) {
		printk(KERN_ERR "kvm: misc device register failed\n");
		goto out_free;
	}

	kvm_preempt_ops.sched_in = kvm_sched_in;
	kvm_preempt_ops.sched_out = kvm_sched_out;

	kvm_init_debug();

	return 0;

out_free:
	kmem_cache_destroy(kvm_vcpu_cache);
out_free_5:
	sysdev_unregister(&kvm_sysdev);
out_free_4:
	sysdev_class_unregister(&kvm_sysdev_class);
out_free_3:
	unregister_reboot_notifier(&kvm_reboot_notifier);
	unregister_cpu_notifier(&kvm_cpu_notifier);
out_free_2:
out_free_1:
	kvm_arch_hardware_unsetup();
out_free_0a:
	free_cpumask_var(cpus_hardware_enabled);
out_free_0:
	__free_page(bad_page);
out:
	kvm_arch_exit();
out_fail:
	return r;
#endif /*XXX*/
}

extern unsigned long *vmx_io_bitmap_a;
extern unsigned long *vmx_io_bitmap_b;
extern unsigned long *vmx_msr_bitmap_legacy;
extern unsigned long *vmx_msr_bitmap_longmode;

static void __vmx_disable_intercept_for_msr(unsigned long *msr_bitmap, uint32_t msr)
{
#ifdef XXX
	int f = sizeof(unsigned long);

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
#endif /*XXX*/
}

static void vmx_disable_intercept_for_msr(uint32_t msr, int longmode_only)
{
	if (!longmode_only)
		__vmx_disable_intercept_for_msr(vmx_msr_bitmap_legacy, msr);
	__vmx_disable_intercept_for_msr(vmx_msr_bitmap_longmode, msr);
}

static int vmx_init(void)
{
	int r, i;
#ifdef XXX
	rdmsrl_safe(MSR_EFER, &host_efer);

	for (i = 0; i < NR_VMX_MSR; ++i)
		kvm_define_shared_msr(i, vmx_msr_index[i]);
#endif /*XXX*/

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
		r = ENOMEM;
		goto out2;
	}

	/*
	 * Allow direct access to the PC debug port (it is often used for I/O
	 * delays, but the vmexits simply slow things down).
	 */
	memset(vmx_io_bitmap_a, 0xff, PAGESIZE);
	BT_CLEAR(vmx_io_bitmap_a, 0x80);

	memset(vmx_io_bitmap_b, 0xff, PAGESIZE);

	memset(vmx_msr_bitmap_legacy, 0xff, PAGESIZE);
	memset(vmx_msr_bitmap_longmode, 0xff, PAGESIZE);

#ifdef XXX
	set_bit(0, vmx_vpid_bitmap); /* 0 is reserved for host */
#endif /*XXX*/

	r = kvm_init(&vmx_x86_ops, sizeof(struct vcpu_vmx));

	if (r)
		goto out3;

	vmx_disable_intercept_for_msr(MSR_FS_BASE, 0);
	vmx_disable_intercept_for_msr(MSR_GS_BASE, 0);
	vmx_disable_intercept_for_msr(MSR_KERNEL_GS_BASE, 1);
	vmx_disable_intercept_for_msr(MSR_IA32_SYSENTER_CS, 0);
	vmx_disable_intercept_for_msr(MSR_IA32_SYSENTER_ESP, 0);
	vmx_disable_intercept_for_msr(MSR_IA32_SYSENTER_EIP, 0);

#ifdef XXX
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

	mutex_init(&kvm_lock, NULL, MUTEX_DRIVER, 0);  /* XXX */
	kvm_x86_ops = &vmx_x86_ops;
	if ((r = vmx_init()) != DDI_SUCCESS) {
		mutex_destroy(&kvm_lock);
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
#endif

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

static uint64_t shadow_trap_nonpresent_pte;
static uint64_t shadow_notrap_nonpresent_pte;

extern pfn_t hat_getpfnum(struct hat *hat, caddr_t);

#ifdef XXX

static inline struct kvm_mmu_page *
page_header(hpa_t shadow_page)
{
	struct page *page = pfn_to_page(shadow_page >> PAGESHIFT);

	return (struct kvm_mmu_page *)page_private(page);
}

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

	if (find_first_bit(sp->unsync_child_bitmap, 512) == 512)
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

void
kvm_arch_flush_shadow(struct kvm *kvm)
{
	kvm_mmu_zap_all(kvm);
	kvm_reload_remote_mmus(kvm);
}

#ENDIF /*XXX*/

static void kvm_mmu_notifier_release(struct mmu_notifier *mn,
				     struct mm_struct *mm)
{
	struct kvm *kvm = mmu_notifier_to_kvm(mn);
	int idx;
#ifdef XXX
	idx = srcu_read_lock(&kvm->srcu);
	kvm_arch_flush_shadow(kvm);
	srcu_read_unlock(&kvm->srcu, idx);
#endif /*XXX*/
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
#endif
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

#ifdef XXX
	/* for the time being, assume that address space will only grow */
	/* larger.  The following code will be added later. */

	/*
	 * If we set the number of mmu pages to be smaller be than the
	 * number of actived pages , we must to free some mmu pages before we
	 * change the value
	 */

	if (used_pages > kvm_nr_mmu_pages) {
		while (used_pages > kvm_nr_mmu_pages &&
			!list_empty(&kvm->arch.active_mmu_pages)) {
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
			printk(KERN_WARNING
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

	/* all calls to cpuid_count() should be made on the same cpu */
	/* XXX - right now, system panics at ddi_exit_critical() */
	/* XXX - to run everything on same cpu, bind qemu at startup */
	/*ddic = ddi_enter_critical(); */
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
}

#undef F

static int kvm_dev_ioctl_get_supported_cpuid(struct kvm_cpuid2 *cpuid,
					     struct kvm_cpuid_entry2  *entries,
					     int mode)
{
	struct kvm_cpuid_entry2 *cpuid_entries;
	int limit, nent = 0, r = E2BIG;
	uint32_t func;

	if (cpuid->nent < 1)
		goto out;
	if (cpuid->nent > KVM_MAX_CPUID_ENTRIES)
		cpuid->nent = KVM_MAX_CPUID_ENTRIES;
	r = ENOMEM;
	cpuid_entries = kmem_alloc(sizeof(struct kvm_cpuid_entry2) * cpuid->nent, KM_SLEEP);
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
	kmem_free(cpuid_entries, sizeof(struct kvm_cpuid_entry2) * cpuid->nent);
out:
	return r;
}

struct vcpu_vmx *to_vmx(struct kvm_vcpu *vcpu)
{
	return container_of(vcpu, struct vcpu_vmx, vcpu);
}

#define __ex(x) __kvm_handle_fault_on_reboot(x)


void vmcs_clear(struct vmcs *vmcs)
{
	unsigned char error;
	uint64_t phys_addr = (hat_getpfnum(kas.a_hat, (char *)vmcs)<<PAGESHIFT)|((uint64_t)vmcs&PAGEOFFSET);

	asm volatile (__ex(ASM_VMX_VMCLEAR_RAX) "\n\tsetna %0\n"
		      : "=g"(error) : "a"(&phys_addr), "m"(phys_addr)
		      : "cc", "memory");
	if (error)
		cmn_err(CE_PANIC, "kvm: vmclear fail: %p/%llx\n",
		       vmcs, phys_addr);
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


void vmcs_writel(unsigned long field, unsigned long value)
{
	unsigned char error;

	asm volatile (ASM_VMX_VMWRITE_RAX_RDX "\n\tsetna %0"
		       : "=q"(error) : "a"(value), "d"(field) : "cc");
#ifdef XXX
	if (unlikely(error))
		vmwrite_error(field, value);
#endif
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

void vmcs_write64(unsigned long field, uint64_t value)
{
	vmcs_writel(field, value);
#ifndef CONFIG_X86_64
	asm volatile ("");
	vmcs_writel(field+1, value >> 32);
#endif
}

/*
 * Switches to specified vcpu, until a matching vcpu_put(), but assumes
 * vcpu mutex is already taken.
 */
void vmx_vcpu_load(struct kvm_vcpu *vcpu, int cpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	uint64_t phys_addr = (hat_getpfnum(kas.a_hat, (char *)vmx->vmcs)<<PAGESHIFT)|((uint64_t)(vmx->vmcs)&0xfff);
	uint64_t tsc_this, delta, new_offset;

	if (vcpu->cpu != cpu) {
		vcpu_clear(vmx);
#ifdef XXX
		kvm_migrate_timers(vcpu);
#endif /*XXX*/
		BT_SET(&vcpu->requests, KVM_REQ_TLB_FLUSH);
#ifdef XXX
		local_irq_disable();
		list_add(&vmx->local_vcpus_link,
			 &per_cpu(vcpus_on_cpu, cpu));
		local_irq_enable();
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

static inline int is_long_mode(struct kvm_vcpu *vcpu)
{
#ifdef CONFIG_X86_64
	return vcpu->arch.efer & EFER_LMA;
#else
	return 0;
#endif
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
#ifdef XXX
		local_irq_save(flags);
#endif /*XXX*/
		kvm_load_gs(vmx->host_state.gs_sel);
#ifdef CONFIG_X86_64
		wrmsrl(MSR_GS_BASE, vmcs_readl(HOST_GS_BASE));
#endif
#ifdef XXX
		local_irq_restore(flags);
#endif /*XXX*/
	}
	reload_tss();
#ifdef CONFIG_X86_64
	if (is_long_mode(&vmx->vcpu)) {
		rdmsrl(MSR_KERNEL_GS_BASE, vmx->msr_guest_kernel_gs_base);
		wrmsrl(MSR_KERNEL_GS_BASE, vmx->msr_host_kernel_gs_base);
	}
#endif
}

void vmx_vcpu_put(struct kvm_vcpu *vcpu)
{
	__vmx_load_host_state(to_vmx(vcpu));
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

void kvm_apic_set_version(struct kvm_vcpu *vcpu)
{
#ifdef XXX
	struct kvm_lapic *apic = vcpu->arch.apic;
	struct kvm_cpuid_entry2 *feat;
	uint32_t v = APIC_VERSION;

	if (!irqchip_in_kernel(vcpu->kvm))
		return;

	feat = kvm_find_cpuid_entry(apic->vcpu, 0x1, 0);
	if (feat && (feat->ecx & (1 << (X86_FEATURE_X2APIC & 31))))
		v |= APIC_LVR_DIRECTED_EOI;
	apic_set_reg(apic, APIC_LVR, v);
#endif /*XXX*/
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

static int
kvm_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *cred_p, int *rval_p)
{
	int rval = EINVAL;

	switch(cmd) {
	case KVM_GET_API_VERSION:
		cmn_err(CE_NOTE, "kvm_ioctl: KVM_GET_API_VERSION");
		if (arg != NULL)
			return (rval);
		*rval_p = KVM_API_VERSION;
		cmn_err(CE_NOTE, "kvm_ioctl: set rval_p to %d\n", *rval_p);
		rval = DDI_SUCCESS;
		break;
	case KVM_CREATE_VM:
		if (arg == NULL)
			return (rval);
		rval = kvm_dev_ioctl_create_vm(arg, mode);
		return (rval);
	case KVM_CHECK_EXTENSION:
		rval = kvm_dev_ioctl_check_extension_generic(arg, rval_p);
		if (rval != DDI_SUCCESS)
			return (rval);
		break;
 	case KVM_CREATE_VCPU: {
		struct kvm_vcpu_ioc kvm_vcpu;
		struct kvm *kvmp;
		
		if (ddi_copyin((const void *)arg, &kvm_vcpu,
			       sizeof(kvm_vcpu), mode) != 0)
			return (EFAULT);

		kvmp = find_kvm_id(kvm_vcpu.kvmid);
		if (kvmp == NULL)
			return(EINVAL);

 		rval = kvm_vm_ioctl_create_vcpu(kvmp, kvm_vcpu.id, &kvm_vcpu, rval_p); 
 		if (rval != 0) 
			return (rval); 
		if (ddi_copyout(&kvm_vcpu, (void *)arg,
				sizeof(kvm_vcpu), mode) != 0)
			return EFAULT;
 		break; 
	}

 	case KVM_SET_USER_MEMORY_REGION: {
		struct kvm_set_user_memory_ioc kvmioc;
		struct kvm *kvmp;
		
		if (ddi_copyin((const void *)arg, &kvmioc,
			       sizeof(kvmioc), mode) != 0)
			return (EFAULT);

		kvmp = find_kvm_id(kvmioc.kvmid);
		if (kvmp == NULL)
			return(EINVAL);

 		rval = kvm_vm_ioctl_set_memory_region(kvmp, &kvmioc.kvm_userspace_map, 1); 
 		if (rval != 0) 
			return (rval); 
 		break; 
	}
	case KVM_GET_SUPPORTED_CPUID: {
		struct kvm_cpuid2 *cpuid_arg = (struct kvm_cpuid2 *)arg;
		struct kvm_cpuid2 cpuid;

		if (ddi_copyin(cpuid_arg, &cpuid, sizeof (cpuid), mode))
			return (EFAULT);
		rval = kvm_dev_ioctl_get_supported_cpuid(&cpuid,
						      cpuid_arg->entries, mode);
		if (rval)
			return (rval);

		if (ddi_copyout(&cpuid, cpuid_arg, sizeof (cpuid), mode))
			return (EFAULT);
		break;
	}

	case KVM_SET_CPUID2: {
		struct kvm_cpuid2_ioc cpuid_ioc;
		struct kvm_cpuid2 cpuid_data;
		struct kvm_vcpu *vcpu;

		rval = EFAULT;
		if (ddi_copyin((const char *)arg, &cpuid_ioc, sizeof cpuid_ioc, mode))
			return (EFAULT);
		if (cpuid_ioc.kvm_vcpu_addr == NULL)
			return (EINVAL);

		vcpu = (struct kvm_vcpu *)(cpuid_ioc.kvm_vcpu_addr);

		if (ddi_copyin((const char *)(cpuid_ioc.cpuid_data), (char *)&cpuid_data,
			       sizeof(cpuid_data), mode))
			return (EFAULT);
		rval = kvm_vcpu_ioctl_set_cpuid2(vcpu, &cpuid_data,
						 cpuid_data.entries, mode);
		if (rval)
			return (rval);
		break;
	}

	case KVM_GET_CPUID2: {
		struct kvm_cpuid2_ioc cpuid_ioc;
		struct kvm_cpuid2 cpuid_data;
		struct kvm_vcpu *vcpu;

		rval = EFAULT;
		if (ddi_copyin((const char *)arg, &cpuid_ioc, sizeof cpuid_ioc, mode))
			return (EFAULT);

		if (cpuid_ioc.kvm_vcpu_addr == NULL)
			return (EINVAL);

		vcpu = (struct kvm_vcpu *)cpuid_ioc.kvm_vcpu_addr;

		if (ddi_copyin((const char *)(cpuid_ioc.cpuid_data), (char *)&cpuid_data,
			       sizeof(cpuid_data), mode))
			return (EFAULT);

		rval = kvm_vcpu_ioctl_get_cpuid2(vcpu, &cpuid_data,
						 cpuid_data.entries, mode);
		if (rval)
			return (rval);
		rval = EFAULT;
		if (ddi_copyout(&cpuid_ioc, (char *)arg, sizeof cpuid_ioc, mode))
			return (EFAULT);
		rval = 0;
		break;
	}

	case KVM_GET_VCPU_MMAP_SIZE:
		if (arg != NULL)
			return (rval);
		*rval_p = ptob(1);
		break;
	case KVM_SET_TSS_ADDR:
	{
		struct kvm_tss kvm_tss;
		struct kvm *kvmp;
		if (ddi_copyin((const void *)arg, &kvm_tss,
			       sizeof(kvm_tss), mode) != 0)
			return (EFAULT);

		kvmp = find_kvm_id(kvm_tss.kvmid);
		if (kvmp == NULL)
			return(EINVAL);
		rval = kvm_vm_ioctl_set_tss_addr(kvmp, kvm_tss.addr);
		if (rval != DDI_SUCCESS)
			return (rval);
	}
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

