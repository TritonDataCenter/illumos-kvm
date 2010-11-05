
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
#include <sys/thread.h>
#include <sys/cpuvar.h>
#include <vm/hat_i86.h>

#include "msr-index.h"
#include "msr.h"
#include "vmx.h"
#include "processor-flags.h"
#include "apicdef.h"
#include "kvm_host.h"

#define PER_CPU_ATTRIBUTES
#define PER_CPU_DEF_ATTRIBUTES
#define PER_CPU_BASE_SECTION ".data"
#include "percpu-defs.h"
#include "kvm.h"

extern struct vmcs **vmxarea;

static int vcpuid;

unsigned long segment_base(uint16_t selector)
{
	struct descriptor_table gdt;
	struct desc_struct *d;
	unsigned long table_base;
	unsigned long v;

	if (selector == 0)
		return 0;

	kvm_get_gdt(&gdt);
	table_base = gdt.base;

	if (selector & 4) {           /* from ldt */
		uint16_t ldt_selector = kvm_read_ldt();

		table_base = segment_base(ldt_selector);
	}
	d = (struct desc_struct *)(table_base + (selector & ~7));
	v = get_desc_base(d);

#ifdef CONFIG_X86_64
	if (d->c.b.s == 0 && (d->c.b.type == 2 || d->c.b.type == 9 || d->c.b.type == 11))
		v |= ((unsigned long)((struct ldttss_desc64 *)d)->base3) << 32;
#endif

	return v;
}


struct  kvm *
kvm_arch_create_vm(void)
{
	struct kvm *kvm = kmem_zalloc(sizeof(struct kvm), KM_SLEEP);

	if (!kvm)
		return NULL;

	kvm->arch.aliases = kmem_zalloc(sizeof(struct kvm_mem_aliases), KM_SLEEP);
	if (!kvm->arch.aliases) {
		kmem_free(kvm, sizeof(struct kvm));
		return NULL;
	}

	list_create(&kvm->arch.active_mmu_pages, sizeof(struct kvm_mmu_page),
		    offsetof(struct kvm_mmu_page, link));

	list_create(&kvm->arch.assigned_dev_head, sizeof(struct kvm_assigned_dev_kernel),
		    offsetof(struct kvm_assigned_dev_kernel, list));

	/* Reserve bit 0 of irq_sources_bitmap for userspace irq source */
	kvm->arch.irq_sources_bitmap |= KVM_USERSPACE_IRQ_SOURCE_ID;

	/* XXX - original is rdtscll() */
	kvm->arch.vm_init_tsc = (uint64_t)gethrtime(); 

	return kvm;
}

#ifdef IOMMU

paddr_t
iommu_iova_to_phys(struct iommu_domain *domain,
			       unsigned long iova)
{
	return iommu_ops->iova_to_phys(domain, iova);
}

static void kvm_iommu_put_pages(struct kvm *kvm,
				gfn_t base_gfn, unsigned long npages)
{
	gfn_t gfn = base_gfn;
	pfn_t pfn;
	struct iommu_domain *domain = kvm->arch.iommu_domain;
	unsigned long i;
	u64 phys;

	/* check if iommu exists and in use */
	if (!domain)
		return;

	for (i = 0; i < npages; i++) {
		phys = iommu_iova_to_phys(domain, gfn_to_gpa(gfn));
		pfn = phys >> PAGESHIFT;
		kvm_release_pfn_clean(pfn);
		gfn++;
	}

	iommu_unmap_range(domain, gfn_to_gpa(base_gfn), PAGE_SIZE * npages);
}

static int
kvm_iommu_unmap_memslots(struct kvm *kvm)
{
	int i;
	struct kvm_memslots *slots;

	slots = kvm->memslots;

	for (i = 0; i < slots->nmemslots; i++) {
		kvm_iommu_put_pages(kvm, slots->memslots[i].base_gfn,
				    slots->memslots[i].npages);
	}

	return 0;
}

int
kvm_iommu_unmap_guest(struct kvm *kvm)
{
	struct iommu_domain *domain = kvm->arch.iommu_domain;

	/* check if iommu exists and in use */
	if (!domain)
		return 0;

	kvm_iommu_unmap_memslots(kvm);
	iommu_domain_free(domain);
	return 0;
}
#endif /*IOMMU*/

void
kvm_arch_destroy_vm(struct kvm *kvm)
{
	if (!kvm)
		return;  /* nothing to do here */

#ifdef IOMMU
	kvm_iommu_unmap_guest(kvm);
#endif /*IOMMU*/
#ifdef PIT /* i8254 programmable interrupt timer support */
	kvm_free_pit(kvm);
#endif /*PIT*/
#ifdef VPIC
	kmem_free(kvm->arch.vpic);
	kfree(kvm->arch.vioapic);
#endif /*VPIC*/
#ifdef XXX
	kvm_free_vcpus(kvm);
	kvm_free_physmem(kvm);
#endif
#ifdef APIC
	if (kvm->arch.apic_access_page)
		put_page(kvm->arch.apic_access_page);
	if (kvm->arch.ept_identity_pagetable)
		put_page(kvm->arch.ept_identity_pagetable);
#endif /*APIC*/
#if defined(CONFIG_MMU_NOTIFIER) && defined(KVM_ARCH_WANT_MMU_NOTIFIER)
	cleanup_srcu_struct(&kvm->srcu);
#endif /*CONFIG_MMU_NOTIFIER && KVM_ARCH_WANT_MMU_NOTIFIER*/
	kmem_free(kvm->arch.aliases, sizeof (struct kvm_mem_aliases));
	kmem_free(kvm, sizeof(struct kvm));
}

extern int getcr4(void);
extern void setcr4(ulong_t val);
extern int getcr0(void);
extern ulong_t getcr3(void);
extern pfn_t hat_getpfnum(struct hat *hat, caddr_t);

#define X86_CR4_VMXE	0x00002000 /* enable VMX virtualization */
#define MSR_IA32_FEATURE_CONTROL        0x0000003a

#define FEATURE_CONTROL_LOCKED		(1<<0)
#define FEATURE_CONTROL_VMXON_ENABLED	(1<<2)

#define ASM_VMX_VMXON_RAX         ".byte 0xf3, 0x0f, 0xc7, 0x30"

extern pfn_t hat_getpfnum(hat_t *hat, caddr_t addr);

struct vmcs_config vmcs_config;

int
vmx_hardware_enable(void *garbage)
{
	int cpu = curthread->t_cpu->cpu_seqid;
	pfn_t pfn;
	uint64_t old;
#ifdef XXX
	uint64_t phys_addr = kvtop(per_cpu(vmxarea, cpu));
#else
	uint64_t phys_addr;
	pfn = hat_getpfnum(kas.a_hat, (caddr_t)vmxarea[cpu]);
	phys_addr = ((uint64_t)pfn << PAGESHIFT)|((uint64_t)vmxarea[cpu] & PAGEOFFSET);
#endif

	((struct vmcs *)(vmxarea[cpu]))->revision_id = vmcs_config.revision_id;

	if (getcr4() & X86_CR4_VMXE)
		return DDI_FAILURE;

#ifdef XXX
	INIT_LIST_HEAD(&per_cpu(vcpus_on_cpu, cpu));
#endif
	rdmsrl(MSR_IA32_FEATURE_CONTROL, old);
	if ((old & (FEATURE_CONTROL_LOCKED |
		    FEATURE_CONTROL_VMXON_ENABLED))
	    != (FEATURE_CONTROL_LOCKED |
		FEATURE_CONTROL_VMXON_ENABLED))
		/* enable and lock */
		wrmsrl(MSR_IA32_FEATURE_CONTROL, old |
		       FEATURE_CONTROL_LOCKED |
		       FEATURE_CONTROL_VMXON_ENABLED);
	setcr4(getcr4() | X86_CR4_VMXE); /* FIXME: not cpu hotplug safe */
	asm volatile (ASM_VMX_VMXON_RAX
		      : : "a"(&phys_addr), "m"(phys_addr)
		      : "memory", "cc");

#ifdef XXX
	ept_sync_global();
#endif /*XXX*/

	return 0;
}

int kvm_arch_hardware_enable(void *garbage)
{
#ifdef LATER
	/*
	 * Since this may be called from a hotplug notifcation,
	 * we can't get the CPU frequency directly.
	 */
	if (!boot_cpu_has(X86_FEATURE_CONSTANT_TSC)) {
		int cpu = raw_smp_processor_id();
		per_cpu(cpu_tsc_khz, cpu) = 0;
	}

	kvm_shared_msr_cpu_online();
#endif

	return vmx_hardware_enable(garbage);
}

void kvm_arch_hardware_disable(void *garbage)
{
#ifdef XXX
	hardware_disable(garbage);
#endif /*XXX*/
#if defined(CONFIG_MMU_NOTIFIER) && defined(KVM_ARCH_WANT_MMU_NOTIFIER)
	drop_user_return_notifiers(garbage);
#endif /*CONFIG_MMU_NOTIFIER && KVM_ARCH_WANT_MMU_NOTIFIER*/
}

int
kvm_dev_ioctl_check_extension(long ext, int *rval_p)
{
	int r;

	switch (ext) {
	case KVM_CAP_IRQCHIP:
	case KVM_CAP_HLT:
	case KVM_CAP_MMU_SHADOW_CACHE_CONTROL:
	case KVM_CAP_SET_TSS_ADDR:
	case KVM_CAP_EXT_CPUID:
	case KVM_CAP_CLOCKSOURCE:
	case KVM_CAP_PIT:
	case KVM_CAP_NOP_IO_DELAY:
	case KVM_CAP_MP_STATE:
	case KVM_CAP_SYNC_MMU:
	case KVM_CAP_REINJECT_CONTROL:
	case KVM_CAP_IRQ_INJECT_STATUS:
	case KVM_CAP_ASSIGN_DEV_IRQ:
	case KVM_CAP_IRQFD:
	case KVM_CAP_IOEVENTFD:
	case KVM_CAP_PIT2:
	case KVM_CAP_PIT_STATE2:
	case KVM_CAP_SET_IDENTITY_MAP_ADDR:
	case KVM_CAP_XEN_HVM:
	case KVM_CAP_ADJUST_CLOCK:
	case KVM_CAP_VCPU_EVENTS:
	case KVM_CAP_HYPERV:
	case KVM_CAP_HYPERV_VAPIC:
	case KVM_CAP_HYPERV_SPIN:
	case KVM_CAP_PCI_SEGMENT:
	case KVM_CAP_X86_ROBUST_SINGLESTEP:
		*rval_p = 1;
		r = DDI_SUCCESS;
		break;
	case KVM_CAP_COALESCED_MMIO:
#ifdef KVM_COALESCED_MMIO_PAGE_OFFSET
		*rval_p = KVM_COALESCED_MMIO_PAGE_OFFSET;
		r = DDI_SUCCESS;
		break;
#else
		r = EINVAL;
		break;
#endif/*KVM_COALESCED_MMIO_PAGE_OFFSET*/
	case KVM_CAP_VAPIC:
#ifdef XXX
		*rval_p = !kvm_x86_ops->cpu_has_accelerated_tpr();
		r = DDI_SUCCESS;
#else
		r = EINVAL;
#endif /*XXX*/
		break;
	case KVM_CAP_NR_VCPUS:
		*rval_p = KVM_MAX_VCPUS;
		r = DDI_SUCCESS;
		break;
	case KVM_CAP_NR_MEMSLOTS:
		*rval_p = KVM_MEMORY_SLOTS;
		r = DDI_SUCCESS;
		break;
	case KVM_CAP_PV_MMU:	/* obsolete */
		r = EINVAL;
		break;
	case KVM_CAP_IOMMU:
#ifdef XXX
		*rval_p = iommu_found();
		r = DDI_SUCCESS;
#else
		r = EINVAL;
#endif /*XXX*/
		break;
	case KVM_CAP_MCE:
		*rval_p = KVM_MAX_MCE_BANKS;
		r = DDI_SUCCESS;
		break;
	default:
		r = EINVAL;
		break;
	}
	return r;
}

static inline struct kvm_pic *pic_irqchip(struct kvm *kvm)
{
	return kvm->arch.vpic;
}

static inline int irqchip_in_kernel(struct kvm *kvm)
{
	int ret;

	ret = (pic_irqchip(kvm) != NULL);
#ifdef XXX
	smp_rmb();
#endif /*XXX*/
	return ret;
}

int
kvm_arch_vcpu_init(struct kvm_vcpu *vcpu)
{
	void *page;
	struct kvm *kvm;
	int r;

	kvm = vcpu->kvm;

	vcpu->arch.mmu.root_hpa = INVALID_PAGE;
#ifdef XXX
	if (!irqchip_in_kernel(kvm) || kvm_vcpu_is_bsp(vcpu))
#endif
		vcpu->arch.mp_state = KVM_MP_STATE_RUNNABLE;
#ifdef XXX
	else
		vcpu->arch.mp_state = KVM_MP_STATE_UNINITIALIZED;
#endif
	page = kmem_zalloc(PAGESIZE, KM_SLEEP);
	if (!page) {
		r = ENOMEM;
		goto fail;
	}
	vcpu->arch.pio_data = page;

#ifdef XXX
	r = kvm_mmu_create(vcpu);
	if (r < 0)
		goto fail_free_pio_data;

	if (irqchip_in_kernel(kvm)) {
		r = kvm_create_lapic(vcpu);
		if (r < 0)
			goto fail_mmu_destroy;
	}
#endif /*XXX*/
	vcpu->arch.mce_banks = kmem_zalloc(KVM_MAX_MCE_BANKS * sizeof(uint64_t) * 4,
				       KM_SLEEP);
	if (!vcpu->arch.mce_banks) {
		r = ENOMEM;
		goto fail_free_lapic;
	}
	vcpu->arch.mcg_cap = KVM_MAX_MCE_BANKS;

	return 0;
fail_free_lapic:
#ifdef XXX
	kvm_free_lapic(vcpu);
#endif /*XXX*/
fail_mmu_destroy:
#ifdef XXX
	kvm_mmu_destroy(vcpu);
#endif /*XXX*/
fail_free_pio_data:
	kmem_free(page, PAGESIZE);
	vcpu->arch.pio_data = 0;
fail:
	return r;
}

int
kvm_vcpu_init(struct kvm_vcpu *vcpu, struct kvm *kvm, struct kvm_vcpu_ioc *arg, unsigned id)
{
	struct kvm_run *kvm_run;
	int r;

	mutex_init(&vcpu->mutex, NULL, MUTEX_DRIVER, 0);
	vcpu->cpu = -1;
	vcpu->kvm = kvm;
	vcpu->vcpu_id = id;
#ifdef NOTNOW
	init_waitqueue_head(&vcpu->wq);
#endif
	/* XXX the following assumes returned address is page aligned */
	kvm_run = (struct kvm_run *)kmem_zalloc(PAGESIZE, KM_SLEEP);
	if (!kvm_run) {
		r = ENOMEM;
		goto fail;
	}
	vcpu->run = kvm_run;
	arg->kvm_run_addr = (hat_getpfnum(kas.a_hat, (char *)kvm_run)<<PAGESHIFT)|((uint64_t)kvm_run&PAGEOFFSET);
	arg->kvm_vcpu_addr = (uint64_t)vcpu;

	r = kvm_arch_vcpu_init(vcpu);
	if (r != 0)
		goto fail_free_run;
	return 0;

fail_free_run:
	kmem_free(kvm_run, PAGESIZE);
	vcpu->run = 0;
fail:
	return r;
}

/*
 * For pages for which vmx needs physical addresses,
 * linux allocates pages from an area that maps virtual
 * addresses 1-1 with physical memory.  In this way,
 * translating virtual to physical just involves subtracting
 * the start of the area from the virtual address.
 * This solaris version uses kmem_alloc, so there is no
 * direct mapping of virtual to physical.  We'll change this
 * later if performance is an issue.  For now, we'll use
 * hat_getpfnum() to do the conversion.  Also note that
 * we're assuming 64-bit address space (we won't run on
 * 32-bit hardware).
 */

uint64_t
kvm_va2pa(caddr_t va)
{
	uint64_t pa;

	pa = (hat_getpfnum(kas.a_hat, va)<<PAGESHIFT)|((uint64_t)va&PAGEOFFSET);
	return (pa);
}

unsigned long *vmx_io_bitmap_a;
unsigned long *vmx_io_bitmap_b;
unsigned long *vmx_msr_bitmap_legacy;
unsigned long *vmx_msr_bitmap_longmode;

extern void vmcs_writel(unsigned long field, unsigned long value);
static void vmcs_write16(unsigned long field, uint16_t value)
{
	vmcs_writel(field, value);
}

static void vmcs_write32(unsigned long field, uint32_t value)
{
	vmcs_writel(field, value);
}

static void vmcs_write64(unsigned long field, uint64_t value)
{
	vmcs_writel(field, value);
#ifndef CONFIG_X86_64
	asm volatile ("");
	vmcs_writel(field+1, value >> 32);
#endif
}

extern unsigned long vmcs_readl(unsigned long field);


/*
 * Sets up the vmcs for emulated real mode.
 */
static int vmx_vcpu_setup(struct vcpu_vmx *vmx)
{
	uint32_t host_sysenter_cs, msr_low, msr_high;
	uint32_t junk;
	uint64_t host_pat, tsc_this, tsc_base;
	unsigned long a;
	struct descriptor_table dt;
	int i;
	unsigned long kvm_vmx_return;
	uint32_t exec_control;

#ifdef XXX
	/* I/O */
	vmcs_write64(IO_BITMAP_A, kvm_va2pa((caddr_t)vmx_io_bitmap_a));
	vmcs_write64(IO_BITMAP_B, kvm_va2pa((caddr_t)vmx_io_bitmap_b));

	if (cpu_has_vmx_msr_bitmap())
		vmcs_write64(MSR_BITMAP, kvm_pa2va(vmx_msr_bitmap_legacy));

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
	vmcs_write32(CR3_TARGET_COUNT, 0);           /* 22.2.1 */

	vmcs_writel(HOST_CR0, getcr0());  /* 22.2.3 */
	vmcs_writel(HOST_CR4, getcr4());  /* 22.2.3, 22.2.5 */
	vmcs_writel(HOST_CR3, getcr3());  /* 22.2.3  FIXME: shadow tables */

	vmcs_write16(HOST_CS_SELECTOR, __KERNEL_CS);  /* 22.2.4 */
	vmcs_write16(HOST_DS_SELECTOR, __KERNEL_DS);  /* 22.2.4 */
	vmcs_write16(HOST_ES_SELECTOR, __KERNEL_DS);  /* 22.2.4 */
	vmcs_write16(HOST_FS_SELECTOR, kvm_read_fs());    /* 22.2.4 */
	vmcs_write16(HOST_GS_SELECTOR, kvm_read_gs());    /* 22.2.4 */
	vmcs_write16(HOST_SS_SELECTOR, __KERNEL_DS);  /* 22.2.4 */
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
#endif /*XXX*/
	return 0;
}

extern void vmcs_clear(struct vmcs *vmcs);
extern void vmx_vcpu_load(struct kvm_vcpu *vcpu, int cpu);
extern void vmx_vcpu_put(struct kvm_vcpu *vcpu);

struct kvm_vcpu *
vmx_create_vcpu(struct kvm *kvm, struct kvm_vcpu_ioc *arg, unsigned int id)
{
	int err;
	struct vcpu_vmx *vmx = kmem_zalloc(sizeof (struct vcpu_vmx), KM_SLEEP);
	int cpu;

	if (!vmx)
		return NULL;
#ifdef NOTNOW
	allocate_vpid(vmx);
#endif /*NOTNOW*/
	err = kvm_vcpu_init(&vmx->vcpu, kvm, arg, id);
	if (err) {
#ifdef NOTNOW
		goto free_vcpu;
#else
		kmem_free(vmx, sizeof(struct vcpu_vmx));
		return NULL;
	}
#endif /*NOTNOW*/

	vmx->guest_msrs = kmem_alloc(PAGESIZE, KM_SLEEP);
	if (!vmx->guest_msrs) {
		return NULL;  /* XXX - need cleanup here */
	}

	vmx->vmcs = kmem_zalloc(PAGESIZE, KM_SLEEP);
	if (!vmx->vmcs)
		return NULL;


	kpreempt_disable();

	cpu = curthread->t_cpu->cpu_seqid;

	cmn_err(CE_NOTE, "vmcs revision_id = %x\n", vmcs_config.revision_id);
	vmx->vmcs->revision_id = vmcs_config.revision_id;

	vmcs_clear(vmx->vmcs);

	err = vmx_vcpu_setup(vmx);

	vmx_vcpu_load(&vmx->vcpu, cpu);

	vmx_vcpu_put(&vmx->vcpu);
	kpreempt_enable();
	if (err)
		vmx->vmcs = NULL;
#ifdef NOTNOW
	if (vm_need_virtualize_apic_accesses(kvm))
		if (alloc_apic_access_page(kvm) != 0)
			goto free_vmcs;

	if (enable_ept) {
		if (!kvm->arch.ept_identity_map_addr)
			kvm->arch.ept_identity_map_addr =
				VMX_EPT_IDENTITY_PAGETABLE_ADDR;
		if (alloc_identity_pagetable(kvm) != 0)
			goto free_vmcs;
	}

#endif /*NOTNOW*/
	return &vmx->vcpu;

#ifdef XXX
free_vmcs:
	free_vmcs(vmx->vmcs);
free_msrs:
	kfree(vmx->guest_msrs);
uninit_vcpu:
	kvm_vcpu_uninit(&vmx->vcpu);
free_vcpu:
	kmem_cache_free(kvm_vcpu_cache, vmx);
	return NULL;
#endif /*XXX*/
}

struct kvm_vcpu *
kvm_arch_vcpu_create(struct kvm *kvm, struct kvm_vcpu_ioc *arg, unsigned int id)
{
	/* for right now, assume always on x86 */
	/* later, if needed, we'll add something here */
	/* to call architecture dependent routine */
	return vmx_create_vcpu(kvm, arg, id);
}

extern struct vcpu_vmx *to_vmx(struct kvm_vcpu *vcpu);


static int enable_ept = 1;
static void update_exception_bitmap(struct kvm_vcpu *vcpu)
{
	uint32_t eb;

	eb = (1u << PF_VECTOR) | (1u << UD_VECTOR) | (1u << MC_VECTOR) |
	     (1u << NM_VECTOR) | (1u << DB_VECTOR);
#ifdef XXX
	if ((vcpu->guest_debug &
	     (KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP)) ==
	    (KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP))
		eb |= 1u << BP_VECTOR;
#endif /*XXX*/
	if (to_vmx(vcpu)->rmode.vm86_active)
		eb = ~0;
	if (enable_ept)
		eb &= ~(1u << PF_VECTOR); /* bypass_guest_pf = 0 */
	if (vcpu->fpu_active)
		eb &= ~(1u << NM_VECTOR);
	vmcs_write32(EXCEPTION_BITMAP, eb);
}

static inline uint32_t apic_get_reg(struct kvm_lapic *apic, int reg_off)
{
	return *((uint32_t *) (apic->regs + reg_off));
}
static inline void apic_set_reg(struct kvm_lapic *apic, int reg_off, uint32_t val)
{
	*((uint32_t *) (apic->regs + reg_off)) = val;
}

static inline int kvm_apic_id(struct kvm_lapic *apic)
{
	return (apic_get_reg(apic, APIC_ID) >> 24) & 0xff;
}

static inline int apic_x2apic_mode(struct kvm_lapic *apic)
{
	return apic->vcpu->arch.apic_base & X2APIC_ENABLE;
}

void kvm_lapic_set_base(struct kvm_vcpu *vcpu, uint64_t value)
{
	struct kvm_lapic *apic = vcpu->arch.apic;

	if (!apic) {
		value |= MSR_IA32_APICBASE_BSP;
		vcpu->arch.apic_base = value;
		return;
	}

#ifdef XXX
	if (!kvm_vcpu_is_bsp(apic->vcpu))
		value &= ~MSR_IA32_APICBASE_BSP;
#endif /*XXX*/

	vcpu->arch.apic_base = value;
	if (apic_x2apic_mode(apic)) {
		uint32_t id = kvm_apic_id(apic);
		uint32_t ldr = ((id & ~0xf) << 16) | (1 << (id & 0xf));
		apic_set_reg(apic, APIC_LDR, ldr);
	}
	apic->base_address = apic->vcpu->arch.apic_base &
			     MSR_IA32_APICBASE_BASE;

}

uint64_t kvm_get_apic_base(struct kvm_vcpu *vcpu)
{
	if (irqchip_in_kernel(vcpu->kvm))
		return vcpu->arch.apic_base;
	else
		return vcpu->arch.apic_base;
}


void kvm_set_apic_base(struct kvm_vcpu *vcpu, uint64_t data)
{
	/* TODO: reserve bits check */
	if (irqchip_in_kernel(vcpu->kvm))
		kvm_lapic_set_base(vcpu, data);
	else
		vcpu->arch.apic_base = data;
}

void kvm_set_cr8(struct kvm_vcpu *vcpu, unsigned long cr8)
{
	if (cr8 & CR8_RESERVED_BITS) {
		kvm_inject_gp(vcpu, 0);
		return;
	}
#ifdef XXX
	if (irqchip_in_kernel(vcpu->kvm))
		kvm_lapic_set_tpr(vcpu, cr8);
	else
#endif /*XXX*/
		vcpu->arch.cr8 = cr8;
}

static int is_paging(struct kvm_vcpu *vcpu)
{
#ifdef XXX	
	return kvm_getcr0_bits(vcpu, X86_CR0_PG);
#else
	return 0;
#endif /*XXX*/
}

void vmx_set_cr4(struct kvm_vcpu *vcpu, unsigned long cr4)
{
	unsigned long hw_cr4 = cr4 | (to_vmx(vcpu)->rmode.vm86_active ?
		    KVM_RMODE_VM_CR4_ALWAYS_ON : KVM_PMODE_VM_CR4_ALWAYS_ON);

	vcpu->arch.cr4 = cr4;
	if (enable_ept) {
		if (!is_paging(vcpu)) {
			hw_cr4 &= ~X86_CR4_PAE;
			hw_cr4 |= X86_CR4_PSE;
		} else if (!(cr4 & X86_CR4_PAE)) {
			hw_cr4 &= ~X86_CR4_PAE;
		}
	}

	vmcs_writel(CR4_READ_SHADOW, cr4);
	vmcs_writel(GUEST_CR4, hw_cr4);
}

void vmx_set_cr0(struct kvm_vcpu *vcpu, unsigned long cr0)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	unsigned long hw_cr0;
#ifdef XXX
	if (enable_unrestricted_guest)
		hw_cr0 = (cr0 & ~KVM_GUEST_CR0_MASK_UNRESTRICTED_GUEST)
			| KVM_VM_CR0_ALWAYS_ON_UNRESTRICTED_GUEST;
	else
#endif /*XXX*/
		hw_cr0 = (cr0 & ~KVM_GUEST_CR0_MASK) | KVM_VM_CR0_ALWAYS_ON;

#ifdef XXX
	if (vmx->rmode.vm86_active && (cr0 & X86_CR0_PE))
		enter_pmode(vcpu);

	if (!vmx->rmode.vm86_active && !(cr0 & X86_CR0_PE))
		enter_rmode(vcpu);
#endif /*XXX*/

#ifdef CONFIG_X86_64
	if (vcpu->arch.efer & EFER_LME) {
#ifdef XXX
		if (!is_paging(vcpu) && (cr0 & X86_CR0_PG))
			enter_lmode(vcpu);
		if (is_paging(vcpu) && !(cr0 & X86_CR0_PG))
			exit_lmode(vcpu);
#endif /*XXX*/
	}
#endif

#ifdef XXX
	if (enable_ept)
		ept_update_paging_mode_cr0(&hw_cr0, cr0, vcpu);
#endif /*XXX*/

	if (!vcpu->fpu_active)
		hw_cr0 |= X86_CR0_TS | X86_CR0_MP;

	vmcs_writel(CR0_READ_SHADOW, cr0);
	vmcs_writel(GUEST_CR0, hw_cr0);
	vcpu->arch.cr0 = cr0;
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

static void seg_setup(int seg)
{
	struct kvm_vmx_segment_field *sf = &kvm_vmx_segment_fields[seg];
	unsigned int ar;

	vmcs_write16(sf->selector, 0);
	vmcs_writel(sf->base, 0);
	vmcs_write32(sf->limit, 0xffff);
#ifdef XXX
	if (enable_unrestricted_guest) {
		ar = 0x93;
		if (seg == VCPU_SREG_CS)
			ar |= 0x08; /* code segment */
	} else
#endif /*XXX*/
		ar = 0xf3;

	vmcs_write32(sf->ar_bytes, ar);
}

int vmx_vcpu_reset(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = (struct vcpu_vmx *)to_vmx(vcpu);
	uint64_t msr;
	int ret, idx;

	vcpu->arch.regs_avail = ~((1 << VCPU_REGS_RIP) | (1 << VCPU_REGS_RSP));
#ifdef XXX
	idx = srcu_read_lock(&vcpu->kvm->srcu);

	if (!init_rmode(vmx->vcpu.kvm)) {
		ret = -ENOMEM;
		goto out;
	}
#endif
	vmx->rmode.vm86_active = 0;

	vmx->soft_vnmi_blocked = 0;

	vmx->vcpu.arch.regs[VCPU_REGS_RDX] = get_rdx_init_val();
	kvm_set_cr8(&vmx->vcpu, 0);
	msr = 0xfee00000 | MSR_IA32_APICBASE_ENABLE;
#ifdef XXX
	if (kvm_vcpu_is_bsp(&vmx->vcpu))
		msr |= MSR_IA32_APICBASE_BSP;
#endif /*XXX*/
	kvm_set_apic_base(&vmx->vcpu, msr);

#ifdef XXX
	fx_init(&vmx->vcpu);
#endif /*XXX*/

	seg_setup(VCPU_SREG_CS);
	/*
	 * GUEST_CS_BASE should really be 0xffff0000, but VT vm86 mode
	 * insists on having GUEST_CS_BASE == GUEST_CS_SELECTOR << 4.  Sigh.
	 */
#ifdef XXX
	if (kvm_vcpu_is_bsp(&vmx->vcpu)) {
		vmcs_write16(GUEST_CS_SELECTOR, 0xf000);
		vmcs_writel(GUEST_CS_BASE, 0x000f0000);
	} else {
#endif /*XXX*/
		vmcs_write16(GUEST_CS_SELECTOR, vmx->vcpu.arch.sipi_vector << 8);
		vmcs_writel(GUEST_CS_BASE, vmx->vcpu.arch.sipi_vector << 12);
#ifdef XXX
	}
#endif /*XXX*/
	seg_setup(VCPU_SREG_DS);
	seg_setup(VCPU_SREG_ES);
	seg_setup(VCPU_SREG_FS);
	seg_setup(VCPU_SREG_GS);
	seg_setup(VCPU_SREG_SS);

	vmcs_write16(GUEST_TR_SELECTOR, 0);
	vmcs_writel(GUEST_TR_BASE, 0);
	vmcs_write32(GUEST_TR_LIMIT, 0xffff);
	vmcs_write32(GUEST_TR_AR_BYTES, 0x008b);

	vmcs_write16(GUEST_LDTR_SELECTOR, 0);
	vmcs_writel(GUEST_LDTR_BASE, 0);
	vmcs_write32(GUEST_LDTR_LIMIT, 0xffff);
	vmcs_write32(GUEST_LDTR_AR_BYTES, 0x00082);

	vmcs_write32(GUEST_SYSENTER_CS, 0);
	vmcs_writel(GUEST_SYSENTER_ESP, 0);
	vmcs_writel(GUEST_SYSENTER_EIP, 0);

	vmcs_writel(GUEST_RFLAGS, 0x02);
#ifdef XXX
	if (kvm_vcpu_is_bsp(&vmx->vcpu))
		kvm_rip_write(vcpu, 0xfff0);
	else
		kvm_rip_write(vcpu, 0);

	kvm_register_write(vcpu, VCPU_REGS_RSP, 0);
#endif /*XXX*/
	vmcs_writel(GUEST_DR7, 0x400);

	vmcs_writel(GUEST_GDTR_BASE, 0);
	vmcs_write32(GUEST_GDTR_LIMIT, 0xffff);

	vmcs_writel(GUEST_IDTR_BASE, 0);
	vmcs_write32(GUEST_IDTR_LIMIT, 0xffff);

	vmcs_write32(GUEST_ACTIVITY_STATE, 0);
	vmcs_write32(GUEST_INTERRUPTIBILITY_INFO, 0);
	vmcs_write32(GUEST_PENDING_DBG_EXCEPTIONS, 0);

	/* Special registers */
	vmcs_write64(GUEST_IA32_DEBUGCTL, 0);

#ifdef XXX
	setup_msrs(vmx);
#endif /*XXX*/

	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, 0);  /* 22.2.1 */

#ifdef XXX
	if (cpu_has_vmx_tpr_shadow()) {
		vmcs_write64(VIRTUAL_APIC_PAGE_ADDR, 0);
		if (vm_need_tpr_shadow(vmx->vcpu.kvm))
			vmcs_write64(VIRTUAL_APIC_PAGE_ADDR,
				page_to_phys(vmx->vcpu.arch.apic->regs_page));
		vmcs_write32(TPR_THRESHOLD, 0);
	}

	if (vm_need_virtualize_apic_accesses(vmx->vcpu.kvm))
		vmcs_write64(APIC_ACCESS_ADDR,
			     page_to_phys(vmx->vcpu.kvm->arch.apic_access_page));
#endif /*XXX*/
	if (vmx->vpid != 0)
		vmcs_write16(VIRTUAL_PROCESSOR_ID, vmx->vpid);

	vmx->vcpu.arch.cr0 = X86_CR0_NW | X86_CR0_CD | X86_CR0_ET;
#ifdef XXX
	vmx_set_cr0(&vmx->vcpu, kvm_read_cr0(vcpu)); /* enter rmode */
#endif /*XXX*/
	vmx_set_cr4(&vmx->vcpu, 0);
#ifdef XXX
	vmx_set_efer(&vmx->vcpu, 0);
	vmx_fpu_activate(&vmx->vcpu);
#endif /*XXX*/
	update_exception_bitmap(&vmx->vcpu);

#ifdef XXX
	vpid_sync_vcpu_all(vmx);
#endif /*XXX*/

	ret = 0;

	/* HACK: Don't enable emulation on guest boot/reset */
	vmx->emulation_required = 0;

out:
#ifdef XXX
	srcu_read_unlock(&vcpu->kvm->srcu, idx);
#endif /*XXX*/
	return ret;
}

int kvm_arch_vcpu_reset(struct kvm_vcpu *vcpu)
{
	vcpu->arch.nmi_pending = 0;
	vcpu->arch.nmi_injected = 0;

	vcpu->arch.switch_db_regs = 0;
	memset(vcpu->arch.db, 0, sizeof(vcpu->arch.db));
#ifdef XXX
	vcpu->arch.dr6 = DR6_FIXED_1;
	vcpu->arch.dr7 = DR7_FIXED_1;
#endif /*XXX*/
	/*	return kvm_x86_ops->vcpu_reset(vcpu);*/
	return vmx_vcpu_reset(vcpu);
}

extern void vcpu_load(struct kvm_vcpu *vcpu);

static int init_kvm_mmu(struct kvm_vcpu *vcpu)
{
	vcpu->arch.update_pte.pfn = -1; /* bad_pfn */

#ifdef XXX
	if (tdp_enabled)
		return init_kvm_tdp_mmu(vcpu);
	else
		return init_kvm_softmmu(vcpu);
#else
	return 0;
#endif /*XXX*/
}

int kvm_mmu_setup(struct kvm_vcpu *vcpu)
{
	ASSERT(vcpu);

	return init_kvm_mmu(vcpu);
}

int
kvm_arch_vcpu_setup(struct kvm_vcpu *vcpu)
{
	int r;

#ifdef XXX
	/* We do fxsave: this must be aligned. */
	BUG_ON((unsigned long)&vcpu->arch.host_fx_image & 0xF);
#endif

	vcpu->arch.mtrr_state.have_fixed = 1;
	vcpu_load(vcpu);
	r = kvm_arch_vcpu_reset(vcpu);
	if (r == 0)
		r = kvm_mmu_setup(vcpu);
	vcpu_put(vcpu);
	if (r < 0)
		goto free_vcpu;

	return 0;
free_vcpu:
#ifdef XXX
	kvm_x86_ops->vcpu_free(vcpu);
#endif
	return r;
}

/*
 * Creates some virtual cpus.  Good luck creating more than one.
 */
int
kvm_vm_ioctl_create_vcpu(struct kvm *kvm, int32_t id, struct kvm_vcpu_ioc *arg, int *rval_p)
{
	int r;
	struct kvm_vcpu *vcpu, *v;

	vcpu = kvm_arch_vcpu_create(kvm, arg, id);
	if (vcpu == NULL)
		return EINVAL;

#ifdef XXX
	preempt_notifier_init(&vcpu->preempt_notifier, &kvm_preempt_ops);
#endif

	r = kvm_arch_vcpu_setup(vcpu);
	if (r)
		return r;

#ifdef NOTNOW

	mutex_lock(&kvm->lock);
	if (atomic_read(&kvm->online_vcpus) == KVM_MAX_VCPUS) {
		r = -EINVAL;
		goto vcpu_destroy;
	}

	kvm_for_each_vcpu(r, v, kvm)
		if (v->vcpu_id == id) {
			r = -EEXIST;
			goto vcpu_destroy;
		}

	BUG_ON(kvm->vcpus[atomic_read(&kvm->online_vcpus)]);

	/* Now it's all set up, let userspace reach it */
	kvm_get_kvm(kvm);
#endif /*NOTNOW*/
	*rval_p = vcpuid++;  /* guarantee unique id */

	/* XXX need to protect online_vcpus */
	kvm->vcpus[kvm->online_vcpus] = vcpu;

#ifdef NOTNOW
	smp_wmb();
	atomic_inc(&kvm->online_vcpus);

#ifdef CONFIG_KVM_APIC_ARCHITECTURE
	if (kvm->bsp_vcpu_id == id)
		kvm->bsp_vcpu = vcpu;
#endif

	mutex_unlock(&kvm->lock);
#endif /*NOTNOW*/
	return r;

vcpu_destroy:
#ifdef NOTNOW
	mutex_unlock(&kvm->lock);
	kvm_arch_vcpu_destroy(vcpu);
#endif /*NOTNOW*/
	return r;
}

extern int largepages_enabled;

int kvm_arch_prepare_memory_region(struct kvm *kvm,
				struct kvm_memory_slot *memslot,
				struct kvm_memory_slot old,
				struct kvm_userspace_memory_region *mem,
				int user_alloc)
{
#ifdef XXX
	int npages = memslot->npages;

	/*To keep backward compatibility with older userspace,
	 *x86 needs to hanlde !user_alloc case.
	 */
	if (!user_alloc) {
		if (npages && !old.rmap) {
			unsigned long userspace_addr;
			down_write(&current->mm->mmap_sem);
			userspace_addr = do_mmap(NULL, 0,
						 npages * PAGE_SIZE,
						 PROT_READ | PROT_WRITE,
						 MAP_PRIVATE | MAP_ANONYMOUS,
						 0);
			up_write(&current->mm->mmap_sem);

			if (IS_ERR((void *)userspace_addr))
				return PTR_ERR((void *)userspace_addr);

			memslot->userspace_addr = userspace_addr;
		}
	}

#endif /*XXX*/
	return 0;
}

/*
 * Allocate some memory and give it an address in the guest physical address
 * space.
 *
 * Discontiguous memory is allowed, mostly for framebuffers.
 *
 * Must be called holding mmap_sem for write.
 */

extern void kvm_arch_commit_memory_region(struct kvm *kvm,
				struct kvm_userspace_memory_region *mem,
				struct kvm_memory_slot old,
					  int user_alloc);

extern int __kvm_set_memory_region(struct kvm *kvm,
			    struct kvm_userspace_memory_region *mem,
				   int user_alloc);

extern int kvm_set_memory_region(struct kvm *kvm,
			  struct kvm_userspace_memory_region *mem,
				 int user_alloc);

int kvm_vm_ioctl_set_memory_region(struct kvm *kvm,
				   struct
				   kvm_userspace_memory_region *mem,
				   int user_alloc)
{
	if (mem->slot >= KVM_MEMORY_SLOTS)
		return EINVAL;
	return kvm_set_memory_region(kvm, mem, user_alloc);
}

long
kvm_vm_ioctl(struct kvm *kvmp, unsigned int ioctl, unsigned long arg, int mode)
{
	void *argp = (void  *)arg;
	int r;
	proc_t *p;

	if (drv_getparm(UPROCP, &p) != 0)
		cmn_err(CE_PANIC, "Cannot get proc_t for current process\n");

	cmn_err(CE_NOTE, "kvm_vm_ioctl: cmd = %x\n", ioctl);
	cmn_err(CE_CONT, "kvm_vm_ioctl: KVM_SET_USER_MEMORY_REGION = %x\n",
		KVM_SET_USER_MEMORY_REGION);
	if (kvmp->mm != p->p_as)
		return EIO;
	switch (ioctl) {
#ifdef NOTNOW
	case KVM_GET_DIRTY_LOG: {
		struct kvm_dirty_log log;

		r = -EFAULT;
		if (copy_from_user(&log, argp, sizeof log))
			goto out;
		r = kvm_vm_ioctl_get_dirty_log(kvmp, &log);
		if (r)
			goto out;
		break;
	}

#ifdef KVM_COALESCED_MMIO_PAGE_OFFSET
	case KVM_REGISTER_COALESCED_MMIO: {
		struct kvm_coalesced_mmio_zone zone;
		r = EFAULT;
		if (copyin(argp, &zone, sizeof zone))
			goto out;
		r = ENXIO;
		r = kvm_vm_ioctl_register_coalesced_mmio(kvmp, &zone);
		if (r)
			goto out;
		r = 0;
		break;
	}
	case KVM_UNREGISTER_COALESCED_MMIO: {
		struct kvm_coalesced_mmio_zone zone;
		r = EFAULT;
		if (copyin(argp, &zone, sizeof zone))
			goto out;
		r = ENXIO;
		r = kvm_vm_ioctl_unregister_coalesced_mmio(kvmp, &zone);
		if (r)
			goto out;
		r = 0;
		break;
	}
#endif

	case KVM_IRQFD: {
		struct kvm_irqfd data;

		r = -EFAULT;
		if (copy_from_user(&data, argp, sizeof data))
			goto out;
		r = kvm_irqfd(kvmp, data.fd, data.gsi, data.flags);
		break;
	}
	case KVM_IOEVENTFD: {
		struct kvm_ioeventfd data;

		r = -EFAULT;
		if (copy_from_user(&data, argp, sizeof data))
			goto out;
		r = kvm_ioeventfd(kvmp, &data);
		break;
	}
#endif /*NOTNOW*/
#ifdef CONFIG_KVM_APIC_ARCHITECTURE
	case KVM_SET_BOOT_CPU_ID:
		r = 0;
		mutex_lock(&kvmp->lock);
		if (atomic_read(&kvmp->online_vcpus) != 0)
			r = -EBUSY;
		else
			kvmp->bsp_vcpu_id = arg;
		mutex_unlock(&kvmp->lock);
		break;
#endif
#ifdef NOTNOW
	default:
		r = kvm_arch_vm_ioctl(filp, ioctl, arg);
		if (r == -ENOTTY)
			r = kvm_vm_ioctl_assigned_device(kvmp, ioctl, arg);
#endif /*NOTNOW*/
	}

out:
	return r;
}
