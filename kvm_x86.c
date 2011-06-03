
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
#include <sys/segments.h>
#include <sys/mman.h>
#include <sys/mach_mmu.h>
#include <sys/int_limits.h>
#include <sys/x_call.h>

#include "msr-index.h"
#include "msr.h"
#include "vmx.h"
#include "processor-flags.h"
#include "apicdef.h"
#include "kvm_types.h"
#include "kvm_host.h"
#include "kvm_x86host.h"
#include "kvm_iodev.h"

#define	PER_CPU_ATTRIBUTES
#define	PER_CPU_DEF_ATTRIBUTES
#define	PER_CPU_BASE_SECTION ".data"
#include "percpu-defs.h"
#include "coalesced_mmio.h"
#include "kvm.h"
#include "kvm_ioapic.h"
#include "irq.h"
#include "kvm_i8254.h"
#include "kvm_lapic.h"

#undef DEBUG

extern struct vmcs **vmxarea;

static int vcpuid;
extern uint64_t native_read_msr_safe(unsigned int msr, int *err);
extern int native_write_msr_safe(unsigned int msr, unsigned low, unsigned high);

extern unsigned long find_first_zero_bit(const unsigned long *addr,
    unsigned long size);
extern uint32_t vmcs_read32(unsigned long field);
extern uint16_t vmcs_read16(unsigned long field);
extern ulong kvm_read_cr4(struct kvm_vcpu *vcpu);
extern void kvm_rip_write(struct kvm_vcpu *vcpu, unsigned long val);
extern int kvm_is_mmio_pfn(pfn_t pfn);
extern ulong kvm_read_cr4_bits(struct kvm_vcpu *vcpu, ulong mask);
extern int is_long_mode(struct kvm_vcpu *vcpu);
extern void kvm_mmu_unload(struct kvm_vcpu *);
extern void kvm_free_physmem_slot(struct kvm_memory_slot *,
    struct kvm_memory_slot *);

unsigned long
segment_base(uint16_t selector)
{
	struct descriptor_table gdt;
	struct desc_struct *d;
	unsigned long table_base;
	unsigned long v;

	if (selector == 0)
		return (0);

	kvm_get_gdt(&gdt);
	table_base = gdt.base;

	if (selector & 4) {		/* from ldt */
		uint16_t ldt_selector = kvm_read_ldt();

		table_base = segment_base(ldt_selector);
	}
	d = (struct desc_struct *)(table_base + (selector & ~7));
	v = get_desc_base(d);

#ifdef CONFIG_X86_64
	if (d->c.b.s == 0 &&
	    (d->c.b.type == 2 || d->c.b.type == 9 || d->c.b.type == 11))
		v |= ((unsigned long)((struct ldttss_desc64 *)d)->base3) << 32;
#endif

	return (v);
}


struct  kvm *
kvm_arch_create_vm(void)
{
	struct kvm *kvm = kmem_zalloc(sizeof (struct kvm), KM_SLEEP);

	if (!kvm)
		return (NULL);

	if ((kvm->arch.aliases =
	    kmem_zalloc(sizeof (struct kvm_mem_aliases), KM_SLEEP)) == NULL) {
		kmem_free(kvm, sizeof (struct kvm));
		return (NULL);
	}

	list_create(&kvm->arch.active_mmu_pages, sizeof (struct kvm_mmu_page),
	    offsetof(struct kvm_mmu_page, link));

	list_create(&kvm->arch.assigned_dev_head,
	    sizeof (struct kvm_assigned_dev_kernel),
	    offsetof(struct kvm_assigned_dev_kernel, list));

	/* Reserve bit 0 of irq_sources_bitmap for userspace irq source */
	set_bit(KVM_USERSPACE_IRQ_SOURCE_ID, &kvm->arch.irq_sources_bitmap);

	/* XXX - original is rdtscll() */
	kvm->arch.vm_init_tsc = (uint64_t)gethrtime();

	return (kvm);
}

inline gpa_t
gfn_to_gpa(gfn_t gfn)
{
	return ((gpa_t)gfn << PAGESHIFT);
}

page_t *pfn_to_page(pfn_t pfn);

void
kvm_release_pfn_clean(pfn_t pfn)
{
#ifdef XXX
	if (!kvm_is_mmio_pfn(pfn))
		put_page(pfn_to_page(pfn));
#else
	XXX_KVM_PROBE;
#endif
}

#ifdef IOMMU

paddr_t
iommu_iova_to_phys(struct iommu_domain *domain, unsigned long iova)
{
	return (iommu_ops->iova_to_phys(domain, iova));
}


static void kvm_iommu_put_pages(struct kvm *kvm,
				gfn_t base_gfn, unsigned long npages)
{
	gfn_t gfn = base_gfn;
	pfn_t pfn;
	struct iommu_domain *domain = kvm->arch.iommu_domain;
	unsigned long i;
	uint64_t phys;

	/* check if iommu exists and in use */
	if (!domain)
		return;

	for (i = 0; i < npages; i++) {
		phys = iommu_iova_to_phys(domain, gfn_to_gpa(gfn));
		pfn = phys >> PAGESHIFT;
		kvm_release_pfn_clean(pfn);
		gfn++;
	}

	iommu_unmap_range(domain, gfn_to_gpa(base_gfn), PAGESIZE * npages);
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

	return (0);
}

int
kvm_iommu_unmap_guest(struct kvm *kvm)
{
	struct iommu_domain *domain = kvm->arch.iommu_domain;

	/* check if iommu exists and in use */
	if (!domain)
		return (0);

	kvm_iommu_unmap_memslots(kvm);
	iommu_domain_free(domain);
	return (0);
}
#endif /* IOMMU */

static void
kvm_unload_vcpu_mmu(struct kvm_vcpu *vcpu)
{
	vcpu_load(vcpu);
	kvm_mmu_unload(vcpu);
	vcpu_put(vcpu);
}

static void
kvm_free_vcpus(struct kvm *kvmp)
{
	int ii, maxcpus;

	maxcpus = kvmp->online_vcpus;
	XXX_KVM_SYNC_PROBE;
	for (ii = 0; ii < maxcpus; ii++)
		kvm_unload_vcpu_mmu(kvmp->vcpus[ii]);

	for (ii = 0; ii < maxcpus; ii++)
		kvm_arch_vcpu_free(kvmp->vcpus[ii]);

	mutex_enter(&kvmp->lock);
	for (ii = 0; ii < maxcpus; ii++)
		kvmp->vcpus[ii] = NULL;
	kvmp->online_vcpus = 0;
	mutex_exit(&kvmp->lock);
}

/*
 * This function exists because of a difference in methodologies from our
 * ancestor. With our ancestors, there is no imputus to clean up lists and
 * mutexes. This is unfortunate, because they seem to even have debug kernels
 * which would seemingly check for these kinds of things. But because in the
 * common case mutex_exit is currently a #define to do {} while(0), it seems
 * that they just ignore this.
 *
 * This leads to the following behavior: during our time we create a lot of
 * auxillary structs potentially related to pits, apics, etc. Tearing down these
 * structures relies on having the correct locks, etc. However
 * kvm_arch_destroy_vm() is designed to be the final death blow, i.e. it's doing
 * the kmem_free. Logically these auxillary structures need to be freed and
 * dealt with before we go back and do the rest of the tear down related to the
 * device.
 */
void
kvm_arch_destroy_vm_comps(struct kvm *kvmp)
{
	if (kvmp == NULL)

#ifdef IOMMU
	kvm_iommu_unmap_guest(kvmp);
#else
	XXX_KVM_PROBE;
#endif /* IOMMU */
	kvm_free_pit(kvmp);
	kvm_free_vcpus(kvmp);
	kvm_free_physmem(kvmp);
#ifdef XXX
#ifdef APIC
	if (kvm->arch.apic_access_page)
		put_page(kvm->arch.apic_access_page);
	if (kvm->arch.ept_identity_pagetable)
		put_page(kvm->arch.ept_identity_pagetable);
#endif /* APIC */
#else
	XXX_KVM_PROBE;
#endif /* XXX */
#if defined(CONFIG_MMU_NOTIFIER) && defined(KVM_ARCH_WANT_MMU_NOTIFIER)
	cleanup_srcu_struct(&kvm->srcu);
#endif /* CONFIG_MMU_NOTIFIER && KVM_ARCH_WANT_MMU_NOTIFIER */
}

void
kvm_arch_destroy_vm(struct kvm *kvmp)
{
	if (kvmp == NULL)
		return;  /* nothing to do here */

	if (kvmp->arch.aliases) {
		kmem_free(kvmp->arch.aliases, sizeof (struct kvm_mem_aliases));
		kvmp->arch.aliases = NULL;
	}
	kmem_free(kvmp, sizeof (struct kvm));
}

extern int getcr4(void);
extern void setcr4(ulong_t val);
extern int getcr0(void);
extern ulong_t getcr3(void);
extern pfn_t hat_getpfnum(struct hat *hat, caddr_t);

#define	X86_CR4_VMXE	0x00002000 /* enable VMX virtualization */
#define	MSR_IA32_FEATURE_CONTROL	0x0000003a

#define	FEATURE_CONTROL_LOCKED		(1<<0)
#define	FEATURE_CONTROL_VMXON_ENABLED	(1<<2)

#define	ASM_VMX_VMXON_RAX		".byte 0xf3, 0x0f, 0xc7, 0x30"

extern uint64_t shadow_trap_nonpresent_pte;
extern uint64_t shadow_notrap_nonpresent_pte;
extern uint64_t shadow_base_present_pte;
extern uint64_t shadow_nx_mask;
extern uint64_t shadow_x_mask;	/* mutual exclusive with nx_mask */
extern uint64_t shadow_user_mask;
extern uint64_t shadow_accessed_mask;
extern uint64_t shadow_dirty_mask;

extern pfn_t hat_getpfnum(hat_t *hat, caddr_t addr);
extern inline void ept_sync_global(void);
extern uint64_t *vmxarea_pa;
extern list_t **vcpus_on_cpu;


extern struct vcpu_vmx *to_vmx(struct kvm_vcpu *vcpu);
extern void vmcs_writel(unsigned long field, unsigned long value);
extern unsigned long vmcs_readl(unsigned long field);


extern void kvm_shared_msr_cpu_online(void);

int
kvm_arch_hardware_enable(void *garbage)
{
#ifdef XXX
	/*
	 * Since this may be called from a hotplug notifcation,
	 * we can't get the CPU frequency directly.
	 */
	if (!boot_cpu_has(X86_FEATURE_CONSTANT_TSC)) {
		int cpu = raw_smp_processor_id();
		per_cpu(cpu_tsc_khz, cpu) = 0;
	}
#else
	XXX_KVM_PROBE;
#endif
	kvm_shared_msr_cpu_online();

	return (kvm_x86_ops->hardware_enable(garbage));
}

void
kvm_arch_hardware_disable(void *garbage)
{
	kvm_x86_ops->hardware_disable(garbage);
#if defined(CONFIG_MMU_NOTIFIER) && defined(KVM_ARCH_WANT_MMU_NOTIFIER)
	drop_user_return_notifiers(garbage);
#endif
}

static inline int
iommu_found(void)
{
	return (0);
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
#endif
	case KVM_CAP_VAPIC:
		*rval_p = !kvm_x86_ops->cpu_has_accelerated_tpr();
		r = DDI_SUCCESS;
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
		*rval_p = iommu_found();
		r = DDI_SUCCESS;
		break;
	case KVM_CAP_MCE:
		*rval_p = KVM_MAX_MCE_BANKS;
		r = DDI_SUCCESS;
		break;
	default:
		r = EINVAL;
		break;
	}

	return (r);
}

int
irqchip_in_kernel(struct kvm *kvm)
{
	int ret;

	ret = (pic_irqchip(kvm) != NULL);
#ifdef XXX
	smp_rmb();
#else
	XXX_KVM_SYNC_PROBE;
#endif
	return (ret);
}

extern page_t *alloc_page(size_t size, int flag);
extern caddr_t page_address(page_t *page);



static inline int
apic_x2apic_mode(struct kvm_lapic *apic)
{
	return (apic->vcpu->arch.apic_base & X2APIC_ENABLE);
}

extern unsigned long kvm_rip_read(struct kvm_vcpu *vcpu);

inline static int
kvm_is_dm_lowest_prio(struct kvm_lapic_irq *irq)
{
#ifdef CONFIG_IA64
	return (irq->delivery_mode ==
		(IOSAPIC_LOWEST_PRIORITY << IOSAPIC_DELIVERY_SHIFT));
#else
	return (irq->delivery_mode == APIC_DM_LOWEST);
#endif
}

void
kvm_inject_nmi(struct kvm_vcpu *vcpu)
{
	vcpu->arch.nmi_pending = 1;
}

int
kvm_irq_delivery_to_apic(struct kvm *kvm, struct kvm_lapic *src,
    struct kvm_lapic_irq *irq)
{
	int i, r = -1;
	struct kvm_vcpu *vcpu, *lowest = NULL;

	if (irq->dest_mode == 0 && irq->dest_id == 0xff &&
	    kvm_is_dm_lowest_prio(irq))
		cmn_err(CE_NOTE, "kvm: apic: phys broadcast and lowest prio\n");

	kvm_for_each_vcpu(i, vcpu, kvm) {
		if (!kvm_apic_present(vcpu))
			continue;

		if (!kvm_apic_match_dest(vcpu, src, irq->shorthand,
		    irq->dest_id, irq->dest_mode))
			continue;

		if (!kvm_is_dm_lowest_prio(irq)) {
			if (r < 0)
				r = 0;
			r += kvm_apic_set_irq(vcpu, irq);
		} else {
			if (!lowest)
				lowest = vcpu;
			else if (kvm_apic_compare_prio(vcpu, lowest) < 0)
				lowest = vcpu;
		}
	}
	if (lowest)
		r = kvm_apic_set_irq(lowest, irq);

	return (r);
}

static int
ioapic_deliver(struct kvm_ioapic *ioapic, int irq)
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
		/*
		 * need to read apic_id from apic regiest since
		 * it can be rewritten
		 */
		irqe.dest_id = ioapic->kvm->bsp_vcpu->vcpu_id;
	}
#endif
	return (kvm_irq_delivery_to_apic(ioapic->kvm, NULL, &irqe));
}

static int
ioapic_service(struct kvm_ioapic *ioapic, unsigned int idx)
{
	union kvm_ioapic_redirect_entry *pent;
	int injected = -1;

	pent = &ioapic->redirtbl[idx];

	if (!pent->fields.mask) {
		injected = ioapic_deliver(ioapic, idx);
		if (injected && pent->fields.trig_mode == IOAPIC_LEVEL_TRIG)
			pent->fields.remote_irr = 1;
	}
	return (injected);
}

static void
__kvm_ioapic_update_eoi(struct kvm_ioapic *ioapic, int vector, int trigger_mode)
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

extern void kvm_timer_fire(void *);

extern int kvm_vcpu_is_bsp(struct kvm_vcpu *vcpu);

int
kvm_arch_vcpu_init(struct kvm_vcpu *vcpu)
{
	page_t *page;
	struct kvm *kvm;
	int r;

	kvm = vcpu->kvm;

	vcpu->arch.mmu.root_hpa = INVALID_PAGE;

	if (!irqchip_in_kernel(kvm) || kvm_vcpu_is_bsp(vcpu))
		vcpu->arch.mp_state = KVM_MP_STATE_RUNNABLE;
	else
		vcpu->arch.mp_state = KVM_MP_STATE_UNINITIALIZED;

	/*
	 * page = alloc_page(PAGESIZE, KM_SLEEP);
	 * if (!page) {
	 *	r = ENOMEM;
	 *	goto fail;
	 * }
	 * vcpu->arch.pio_data = page_address(page);
	 */
	vcpu->arch.pio_data = (caddr_t)vcpu->run +
	    (KVM_PIO_PAGE_OFFSET * PAGESIZE);

	r = kvm_mmu_create(vcpu);
	if (r < 0)
		goto fail;

	if (irqchip_in_kernel(kvm)) {
		r = kvm_create_lapic(vcpu);
		if (r < 0)
			goto fail_mmu_destroy;
	}

	vcpu->arch.mce_banks = kmem_zalloc(KVM_MAX_MCE_BANKS *
	    sizeof (uint64_t) * 4, KM_SLEEP);

	if (!vcpu->arch.mce_banks) {
		r = ENOMEM;
		goto fail_free_lapic;
	}

	vcpu->arch.mcg_cap = KVM_MAX_MCE_BANKS;

	return (0);
fail_free_lapic:
	kvm_free_lapic(vcpu);
fail_mmu_destroy:
	kvm_mmu_destroy(vcpu);
fail:
	return (r);
}

void
kvm_arch_vcpu_uninit(struct kvm_vcpu *vcpu)
{
	kmem_free(vcpu->arch.mce_banks, sizeof (uint64_t) * 4 *
	    KVM_MAX_MCE_BANKS);
	kvm_free_lapic(vcpu);
	kvm_mmu_destroy(vcpu);
}

static int coalesced_mmio_write(struct kvm_io_device *this,
				gpa_t addr, int len, const void *val);
static void coalesced_mmio_destructor(struct kvm_io_device *this);

static const struct kvm_io_device_ops coalesced_mmio_ops = {
	.write		= coalesced_mmio_write,
	.destructor	= coalesced_mmio_destructor,
};

int
kvm_vcpu_init(struct kvm_vcpu *vcpu, struct kvm *kvm, unsigned id)
{
	int r;

	mutex_init(&vcpu->mutex, NULL, MUTEX_DRIVER, 0);
	vcpu->cpu = -1;
	vcpu->kvm = kvm;
	vcpu->vcpu_id = id;
#ifdef XXX
	init_waitqueue_head(&vcpu->wq);
#else
	XXX_KVM_PROBE;
#endif
	vcpu->run = ddi_umem_alloc(PAGESIZE * 2, DDI_UMEM_SLEEP, &vcpu->cookie);

	r = kvm_arch_vcpu_init(vcpu);

	if (r != 0) {
		vcpu->run = NULL;
		ddi_umem_free(vcpu->cookie);
		return (r);
	}

	return (0);
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

#ifdef XXX_KVM_DECLARATION
unsigned long *vmx_io_bitmap_a;
unsigned long *vmx_io_bitmap_b;
unsigned long *vmx_msr_bitmap_legacy;
unsigned long *vmx_msr_bitmap_longmode;
#else
/* make these arrays to try to force into low 4GB memory... */
/* also need to be aligned... */
__attribute__((__aligned__(PAGESIZE)))unsigned long
    vmx_io_bitmap_a[PAGESIZE / sizeof (unsigned long)];
__attribute__((__aligned__(PAGESIZE)))unsigned long
    vmx_io_bitmap_b[PAGESIZE / sizeof (unsigned long)];
__attribute__((__aligned__(PAGESIZE)))unsigned long
    vmx_msr_bitmap_legacy[PAGESIZE / sizeof (unsigned long)];
__attribute__((__aligned__(PAGESIZE)))unsigned long
    vmx_msr_bitmap_longmode[PAGESIZE / sizeof (unsigned long)];
#endif

static void
vmcs_write16(unsigned long field, uint16_t value)
{
	vmcs_writel(field, value);
}

static void
vmcs_write32(unsigned long field, uint32_t value)
{
	vmcs_writel(field, value);
}

static void
vmcs_write64(unsigned long field, uint64_t value)
{
	vmcs_writel(field, value);
#ifndef CONFIG_X86_64
	/*CSTYLED*/
	__asm__ volatile ("");
	vmcs_writel(field+1, value >> 32);
#endif
}

extern int enable_ept;
extern int enable_unrestricted_guest;
extern int emulate_invalid_guest_state;

extern void vmcs_clear(uint64_t vmcs_pa);
extern void vmx_vcpu_load(struct kvm_vcpu *vcpu, int cpu);
extern void vmx_vcpu_put(struct kvm_vcpu *vcpu);

extern int vmx_vcpu_setup(struct vcpu_vmx *vmx);
extern int enable_vpid;

extern ulong_t *vmx_vpid_bitmap;
extern kmutex_t vmx_vpid_lock;

extern page_t *gfn_to_page(struct kvm *kvm, gfn_t gfn);

struct kvm_vcpu *
kvm_arch_vcpu_create(struct kvm *kvm, unsigned int id)
{
	char buf[32];
	struct kvm_vcpu *vcpu;
	kstat_t *kstat;

	(void) snprintf(buf, sizeof (buf), "vcpu-%d", kvm->kvmid);

	if ((kstat = kstat_create("kvm", id, buf, "misc", KSTAT_TYPE_NAMED,
	    sizeof (kvm_vcpu_stats_t) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL)) == NULL) {
		return (NULL);
	}

	vcpu = kvm_x86_ops->vcpu_create(kvm, id);

	if (vcpu == NULL) {
		kstat_delete(kstat);
		return (NULL);
	}

	vcpu->kvcpu_kstat = kstat;
	vcpu->kvcpu_kstat->ks_data = &vcpu->kvcpu_stats;

	KVM_VCPU_KSTAT_INIT(vcpu, kvmvs_id, "id");
	vcpu->kvcpu_stats.kvmvs_id.value.ui64 = kvm->kvmid;

	KVM_VCPU_KSTAT_INIT(vcpu, kvmvs_id, "pid");
	vcpu->kvcpu_stats.kvmvs_id.value.ui64 = kvm->kvm_pid;

	KVM_VCPU_KSTAT_INIT(vcpu, kvmvs_nmi_injections, "nmi-injections");
	KVM_VCPU_KSTAT_INIT(vcpu, kvmvs_irq_injections, "irq-injections");
	KVM_VCPU_KSTAT_INIT(vcpu, kvmvs_fpu_reload, "fpu-reload");
	KVM_VCPU_KSTAT_INIT(vcpu, kvmvs_host_state_reload, "host-state-reload");
	KVM_VCPU_KSTAT_INIT(vcpu, kvmvs_insn_emulation, "insn-emulation");
	KVM_VCPU_KSTAT_INIT(vcpu, kvmvs_insn_emulation_fail,
	    "inst-emulation-fail");
	KVM_VCPU_KSTAT_INIT(vcpu, kvmvs_exits, "exits");
	KVM_VCPU_KSTAT_INIT(vcpu, kvmvs_halt_exits, "halt-exits");
	KVM_VCPU_KSTAT_INIT(vcpu, kvmvs_irq_exits, "irq-exits");
	KVM_VCPU_KSTAT_INIT(vcpu, kvmvs_io_exits, "io-exits");
	KVM_VCPU_KSTAT_INIT(vcpu, kvmvs_mmio_exits, "mmio-exits");
	KVM_VCPU_KSTAT_INIT(vcpu, kvmvs_nmi_window_exits, "nmi-window-exits");
	KVM_VCPU_KSTAT_INIT(vcpu, kvmvs_irq_window_exits, "irq-window-exits");
	KVM_VCPU_KSTAT_INIT(vcpu, kvmvs_request_irq_exits, "request-irq-exits");
	KVM_VCPU_KSTAT_INIT(vcpu, kvmvs_signal_exits, "signal-exits");
	KVM_VCPU_KSTAT_INIT(vcpu, kvmvs_halt_wakeup, "halt-wakeup");
	KVM_VCPU_KSTAT_INIT(vcpu, kvmvs_invlpg, "invlpg");
	KVM_VCPU_KSTAT_INIT(vcpu, kvmvs_pf_guest, "pf-guest");
	KVM_VCPU_KSTAT_INIT(vcpu, kvmvs_pf_fixed, "pf-fixed");
	KVM_VCPU_KSTAT_INIT(vcpu, kvmvs_hypercalls, "hypercalls");

	kstat_install(vcpu->kvcpu_kstat);

	return (vcpu);
}

void
kvm_arch_vcpu_free(struct kvm_vcpu *vcpu)
{
	if (vcpu->arch.time_page) {
		/* XXX We aren't doing anything with the time page */
		XXX_KVM_PROBE;
		vcpu->arch.time_page = NULL;
	}

	if (vcpu->kvcpu_kstat != NULL)
		kstat_delete(vcpu->kvcpu_kstat);

	kvm_x86_ops->vcpu_free(vcpu);
}


uint64_t
kvm_get_apic_base(struct kvm_vcpu *vcpu)
{
	if (irqchip_in_kernel(vcpu->kvm))
		return (vcpu->arch.apic_base);
	else
		return (vcpu->arch.apic_base);
}

void
kvm_set_apic_base(struct kvm_vcpu *vcpu, uint64_t data)
{
	/* TODO: reserve bits check */
	if (irqchip_in_kernel(vcpu->kvm))
		kvm_lapic_set_base(vcpu, data);
	else
		vcpu->arch.apic_base = data;
}

void
kvm_set_cr8(struct kvm_vcpu *vcpu, unsigned long cr8)
{
	if (cr8 & CR8_RESERVED_BITS) {
		kvm_inject_gp(vcpu, 0);
		return;
	}

	if (irqchip_in_kernel(vcpu->kvm))
		kvm_lapic_set_tpr(vcpu, cr8);
	else
		vcpu->arch.cr8 = cr8;
}

extern inline ulong kvm_read_cr0_bits(struct kvm_vcpu *vcpu, ulong mask);

int
is_paging(struct kvm_vcpu *vcpu)
{
	return (kvm_read_cr0_bits(vcpu, X86_CR0_PG));
}


extern void vmx_set_efer(struct kvm_vcpu *vcpu, uint64_t efer);


extern int kvm_write_guest_page(struct kvm *kvm,
    gfn_t gfn, const void *data, int offset, int len);

unsigned long empty_zero_page[PAGESIZE / sizeof (unsigned long)];

int
kvm_clear_guest_page(struct kvm *kvm, gfn_t gfn, int offset, int len)
{
	return (kvm_write_guest_page(kvm, gfn, empty_zero_page, offset, len));
}

extern void kvm_register_write(struct kvm_vcpu *vcpu,
    enum kvm_reg reg, unsigned long val);
extern ulong kvm_read_cr0(struct kvm_vcpu *vcpu);
extern void setup_msrs(struct vcpu_vmx *vmx);

void
fx_init(struct kvm_vcpu *vcpu)
{
	unsigned after_mxcsr_mask;
#ifdef XXX
	/*
	 * Touch the fpu the first time in non atomic context as if
	 * this is the first fpu instruction the exception handler
	 * will fire before the instruction returns and it'll have to
	 * allocate ram with GFP_KERNEL.
	 */
	if (!used_math())
#else
	XXX_KVM_PROBE;
#endif
		kvm_fx_save(&vcpu->arch.host_fx_image);

	/* Initialize guest FPU by resetting ours and saving into guest's */
	kpreempt_disable();
	kvm_fx_save(&vcpu->arch.host_fx_image);
	kvm_fx_finit();
	kvm_fx_save(&vcpu->arch.guest_fx_image);
	kvm_fx_restore(&vcpu->arch.host_fx_image);
	kpreempt_enable();

	vcpu->arch.cr0 |= X86_CR0_ET;
	after_mxcsr_mask = offsetof(struct i387_fxsave_struct, st_space);
	vcpu->arch.guest_fx_image.mxcsr = 0x1f80;
	memset((void *)((uintptr_t)&vcpu->arch.guest_fx_image +
	    after_mxcsr_mask), 0, sizeof (struct i387_fxsave_struct) -
	    after_mxcsr_mask);
}

extern inline void vpid_sync_vcpu_all(struct vcpu_vmx *vmx);
extern void vmx_fpu_activate(struct kvm_vcpu *vcpu);
extern inline int vm_need_tpr_shadow(struct kvm *kvm);
extern inline int cpu_has_vmx_tpr_shadow(void);



int
kvm_arch_vcpu_reset(struct kvm_vcpu *vcpu)
{
	vcpu->arch.nmi_pending = 0;
	vcpu->arch.nmi_injected = 0;

	vcpu->arch.switch_db_regs = 0;
	memset(vcpu->arch.db, 0, sizeof (vcpu->arch.db));
	vcpu->arch.dr6 = DR6_FIXED_1;
	vcpu->arch.dr7 = DR7_FIXED_1;

	return (kvm_x86_ops->vcpu_reset(vcpu));
}

extern void vcpu_load(struct kvm_vcpu *vcpu);






gfn_t unalias_gfn(struct kvm *kvm, gfn_t gfn);
extern struct kvm_memory_slot *gfn_to_memslot_unaliased(struct kvm *kvm,
    gfn_t gfn);

struct kvm_memory_slot *
gfn_to_memslot(struct kvm *kvm, gfn_t gfn)
{
	gfn = unalias_gfn(kvm, gfn);
	return (gfn_to_memslot_unaliased(kvm, gfn));
}

unsigned long
kvm_host_page_size(struct kvm *kvm, gfn_t gfn)
{
	struct vm_area_struct *vma;
	unsigned long addr, size;

	size = PAGESIZE;

	addr = gfn_to_hva(kvm, gfn);
	if (kvm_is_error_hva(addr))
		return (PAGESIZE);

#ifdef XXX
	down_read(&current->mm->mmap_sem);
	vma = find_vma(current->mm, addr);
	if (!vma)
		goto out;

	size = vma_kernel_pagesize(vma);

out:
	up_read(&current->mm->mmap_sem);
	return (size);
#else
	XXX_KVM_PROBE;
	return (PAGESIZE);
#endif
}


extern page_t *bad_page;
extern inline void get_page(page_t *page);

static pfn_t
hva_to_pfn(struct kvm *kvm, unsigned long addr)
{
	page_t page[1];
	int npages;
	pfn_t pfn;
	proc_t *procp = ttoproc(curthread);
	struct as *as = procp->p_as;

#ifdef XXX

	npages = get_user_pages_fast(addr, 1, 1, page);

	if (unlikely(npages != 1)) {
		struct vm_area_struct *vma;

		down_read(&current->mm->mmap_sem);
		vma = find_vma(current->mm, addr);

		if (vma == NULL || addr < vma->vm_start ||
		    !(vma->vm_flags & VM_PFNMAP)) {
			up_read(&current->mm->mmap_sem);
			get_page(bad_page);
			return (page_to_pfn(bad_page));
		}

		pfn = ((addr - vma->vm_start) >> PAGESHIFT) + vma->vm_pgoff;
		up_read(&current->mm->mmap_sem);
		BUG_ON(!kvm_is_mmio_pfn(pfn));
	} else
		pfn = page_to_pfn(page[0]);
#else
	XXX_KVM_PROBE;
	if (addr < kernelbase)
		pfn = hat_getpfnum(as->a_hat, (caddr_t)addr);
	else
		pfn = hat_getpfnum(kas.a_hat, (caddr_t)addr);
#endif
	return (pfn);
}

pfn_t
gfn_to_pfn(struct kvm *kvm, gfn_t gfn)
{
	unsigned long addr;
	pfn_t pfn;

	addr = gfn_to_hva(kvm, gfn);

	if (kvm_is_error_hva(addr)) {
		get_page(bad_page);
		return (page_to_pfn(bad_page));
	}

	pfn = hva_to_pfn(kvm, addr);

	return (pfn);
}

extern pfn_t bad_pfn;

int
is_error_pfn(pfn_t pfn)
{
	return (pfn == bad_pfn);
}



extern struct kvm_mmu_page *page_header(kvm_t *, hpa_t);



extern inline unsigned long bad_hva(void);
extern page_t *page_numtopp_nolock(pfn_t pfn);

page_t *
pfn_to_page(pfn_t pfn)
{
	return (page_numtopp_nolock(pfn));
}

void
kvm_set_pfn_accessed(struct kvm *kvm, pfn_t pfn)
{
#ifdef XXX
	if (!kvm_is_mmio_pfn(pfn))
		mark_page_accessed(pfn_to_page(pfn));
#else
	XXX_KVM_PROBE;
#endif
}


void
kvm_set_pfn_dirty(pfn_t pfn)
{
#ifdef XXX
	if (!kvm_is_mmio_pfn(pfn)) {
		struct page *page = pfn_to_page(pfn);
		if (!PageReserved(page))
			SetPageDirty(page); /* XXX - not defined in linux?! */
	}
#else
	XXX_KVM_PROBE;
#endif
}


extern int is_writable_pte(unsigned long pte);


int
memslot_id(struct kvm *kvm, gfn_t gfn)
{
	int i;
#ifdef XXX_KVM_DECLARATION
	struct kvm_memslots *slots = rcu_dereference(kvm->memslots);
#else
	struct kvm_memslots *slots = kvm->memslots;
#endif
	struct kvm_memory_slot *memslot = NULL;

	gfn = unalias_gfn(kvm, gfn);
	for (i = 0; i < slots->nmemslots; ++i) {
		memslot = &slots->memslots[i];

		if (gfn >= memslot->base_gfn &&
		    gfn < memslot->base_gfn + memslot->npages)
			break;
	}

	return (memslot - slots->memslots);
}

void
kvm_release_pfn_dirty(pfn_t pfn)
{
	kvm_set_pfn_dirty(pfn);
	kvm_release_pfn_clean(pfn);
}

int
cpuid_maxphyaddr(struct kvm_vcpu *vcpu)
{
	return (36);  /* from linux.  number of bits, perhaps? */
}


int
kvm_read_guest_atomic(struct kvm *kvm, gpa_t gpa, void *data, unsigned long len)
{
	int r;
	unsigned long addr;
	gfn_t gfn = gpa >> PAGESHIFT;
	int offset = offset_in_page(gpa);

	addr = gfn_to_hva(kvm, gfn);
	if (kvm_is_error_hva(addr))
		return (-EFAULT);

#ifdef XXX
	pagefault_disable();
#else
	XXX_KVM_PROBE;
#endif

	r = copyin((caddr_t)addr + offset, data, len);
#ifdef XXX
	pagefault_enable();
#else
	XXX_KVM_PROBE;
#endif
	if (r)
		return (-EFAULT);

	return (0);
}

extern void kvm_xcall(processorid_t cpu, kvm_xcall_t func, void *arg);
extern int kvm_xcall_func(kvm_xcall_t func, void *arg);

static void
ack_flush(void *_completed)
{
}

extern int kvm_xcall_func(kvm_xcall_t func, void *arg);

int
make_all_cpus_request(struct kvm *kvm, unsigned int req)
{
	int i;
	cpuset_t set;
	processorid_t me, cpu;
#ifdef XXX_KVM_DECLARATION
	cpumask_var_t cpus;
#endif
	int called = 0;
	struct kvm_vcpu *vcpu;

	CPUSET_ZERO(set);

	mutex_enter(&kvm->requests_lock);
	me = curthread->t_cpu->cpu_id;
	for (i = 0; i < 1; i++) {
		vcpu = kvm->vcpus[i];
		if (!vcpu)
			break;
		if (test_and_set_bit(req, &vcpu->requests))
			continue;
		cpu = vcpu->cpu;
		if (cpu != -1 && cpu != me)
			CPUSET_ADD(set, cpu);
	}
	if (CPUSET_ISNULL(set))
		kvm_xcall(KVM_CPUALL, ack_flush, NULL);
	else {
		kpreempt_disable();
		xc_sync((xc_arg_t) ack_flush, (xc_arg_t) NULL,
			0, CPUSET2BV(set), (xc_func_t) kvm_xcall_func);
		kpreempt_enable();
	}
	mutex_exit(&kvm->requests_lock);
	called = 1;

	return (called);
}

void
kvm_flush_remote_tlbs(struct kvm *kvm)
{
	if (make_all_cpus_request(kvm, KVM_REQ_TLB_FLUSH))
		KVM_KSTAT_INC(kvm, kvmks_remote_tlb_flush);
}

inline uint64_t
kvm_pdptr_read(struct kvm_vcpu *vcpu, int index)
{
	if (!test_bit(VCPU_EXREG_PDPTR,
	    (unsigned long *)&vcpu->arch.regs_avail)) {
		kvm_x86_ops->cache_reg(vcpu, VCPU_EXREG_PDPTR);
	}

	return (vcpu->arch.pdptrs[index]);
}


gfn_t
unalias_gfn(struct kvm *kvm, gfn_t gfn)
{
	int i;
	struct kvm_mem_alias *alias;
	struct kvm_mem_aliases *aliases;

	/* XXX need protection */
	aliases = kvm->arch.aliases;

	for (i = 0; i < aliases->naliases; ++i) {
		alias = &aliases->aliases[i];
		if (gfn >= alias->base_gfn &&
		    gfn < alias->base_gfn + alias->npages)
			return (alias->target_gfn + gfn - alias->base_gfn);
	}
	return (gfn);
}

int
is_pse(struct kvm_vcpu *vcpu)
{
	return (kvm_read_cr4_bits(vcpu, X86_CR4_PSE));
}

void
kvm_get_pfn(struct kvm_vcpu *vcpu, pfn_t pfn)
{
	if (!kvm_is_mmio_pfn(pfn))
		get_page(pfn_to_page(pfn));
}

int
kvm_arch_vcpu_setup(struct kvm_vcpu *vcpu)
{
	int r;

#ifdef XXX
	/* We do fxsave: this must be aligned. */
	BUG_ON((unsigned long)&vcpu->arch.host_fx_image & 0xF);
#else
	XXX_KVM_PROBE;
#endif

	vcpu->arch.mtrr_state.have_fixed = 1;
	vcpu_load(vcpu);

	r = kvm_arch_vcpu_reset(vcpu);
	if (r == 0)
		r = kvm_mmu_setup(vcpu);
	vcpu_put(vcpu);
	if (r < 0)
		goto free_vcpu;

	return (0);
free_vcpu:
#ifdef XXX
	kvm_x86_ops->vcpu_free(vcpu);
#else
	XXX_KVM_PROBE;
#endif

	return (r);
}

void
kvm_get_kvm(struct kvm *kvm)
{
	atomic_inc_32(&kvm->users_count);
}

/*
 * Creates some virtual cpus.  Good luck creating more than one.
 */
int
kvm_vm_ioctl_create_vcpu(struct kvm *kvm, int32_t id, int *rval_p)
{
	int r, i;
	struct kvm_vcpu *vcpu, *v;

	vcpu = kvm_arch_vcpu_create(kvm, id);
	if (vcpu == NULL)
		return (EINVAL);

#ifdef XXX
	preempt_notifier_init(&vcpu->preempt_notifier, &kvm_preempt_ops);
#else
	XXX_KVM_PROBE;
#endif

	r = kvm_arch_vcpu_setup(vcpu);
	if (r)
		return (r);

	mutex_enter(&kvm->lock);

#ifdef XXX
	if (atomic_read(&kvm->online_vcpus) == KVM_MAX_VCPUS) {
#else
	XXX_KVM_SYNC_PROBE;
	if (kvm->online_vcpus == KVM_MAX_VCPUS) {
#endif
		r = EINVAL;
		goto vcpu_destroy;
	}

	/* kvm_for_each_vcpu(r, v, kvm) */
	for (i = 0; i < kvm->online_vcpus; i++) {
		v = kvm->vcpus[i];
		if (v->vcpu_id == id) {
			r = -EEXIST;
			goto vcpu_destroy;
		}
	}

	/* BUG_ON(kvm->vcpus[atomic_read(&kvm->online_vcpus)]); */

	/* Now it's all set up, let userspace reach it */
	kvm_get_kvm(kvm);

	*rval_p = kvm->online_vcpus;  /* guarantee unique id */
	vcpu->vcpu_id = *rval_p;

	/* XXX need to protect online_vcpus */
	kvm->vcpus[kvm->online_vcpus] = vcpu;

#ifdef XXX
	smp_wmb();
#else
	XXX_KVM_SYNC_PROBE;
#endif
	atomic_inc_32(&kvm->online_vcpus);

#ifdef CONFIG_KVM_APIC_ARCHITECTURE
	if (kvm->bsp_vcpu_id == id)
		kvm->bsp_vcpu = vcpu;
#endif

	mutex_exit(&kvm->lock);
	return (r);

vcpu_destroy:
#ifdef XXX
	mutex_exit(&kvm->lock);
	kvm_arch_vcpu_destroy(vcpu);
#else
	XXX_KVM_PROBE;
#endif
	return (r);
}

extern int largepages_enabled;

extern caddr_t smmap64(caddr_t addr, size_t len, int prot, int flags,
    int fd, off_t pos);

int kvm_arch_prepare_memory_region(struct kvm *kvm,
    struct kvm_memory_slot *memslot, struct kvm_memory_slot old,
    struct kvm_userspace_memory_region *mem, int user_alloc)
{
	unsigned int npages = memslot->npages;
	uint64_t i;

	/*
	 * To keep backward compatibility with older userspace, x86 needs to
	 * handle !user_alloc case.
	 */
	if (!user_alloc) {
		if (npages && !old.rmap) {
#ifdef XXX
			unsigned long userspace_addr;

			down_write(&current->mm->mmap_sem);
			userspace_addr = do_mmap(NULL, 0, npages * PAGESIZE,
			    PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
			    0);
			up_write(&current->mm->mmap_sem);

			if (IS_ERR((void *)userspace_addr))
				return (PTR_ERR((void *)userspace_addr));
#else
			int rval;
			caddr_t userspace_addr = NULL;

			XXX_KVM_PROBE;

			userspace_addr = smmap64(NULL,
			    (size_t)(npages * PAGESIZE),
			    PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON,
			    -1, 0);

			/*
			 * the mmap sets up the mapping, but there are no pages
			 * allocated. Code sets up the shadow page tables
			 * before the pages are allocated, so there are invalid
			 * pages in the map.  We'll touch the pages so they get
			 * allocated here.
			 */
			for (i = 0; i < npages; i++) {
				if (copyout(empty_zero_page, userspace_addr +
				    (i * PAGESIZE), sizeof (empty_zero_page))) {
					cmn_err(CE_WARN, "could not copy to "
					    "mmap page\n");
				}
			}
#endif

			memslot->userspace_addr =
			    (unsigned long)userspace_addr;
		}
	}

	return (0);
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
    struct kvm_userspace_memory_region *mem, struct kvm_memory_slot old,
    int user_alloc);

extern int __kvm_set_memory_region(struct kvm *kvm,
    struct kvm_userspace_memory_region *mem, int user_alloc);

extern int kvm_set_memory_region(struct kvm *kvm,
    struct kvm_userspace_memory_region *mem, int user_alloc);

int
kvm_vm_ioctl_set_memory_region(struct kvm *kvm,
    struct kvm_userspace_memory_region *mem, int user_alloc)
{
	if (mem->slot >= KVM_MEMORY_SLOTS)
		return (EINVAL);

	return (kvm_set_memory_region(kvm, mem, user_alloc));
}

static inline struct kvm_coalesced_mmio_dev *
to_mmio(struct kvm_io_device *dev)
{
#ifdef XXX
	return (container_of(dev, struct kvm_coalesced_mmio_dev, dev));
#else
	XXX_KVM_PROBE;
	return ((struct kvm_coalesced_mmio_dev *)dev);
#endif
}

static int
coalesced_mmio_in_range(struct kvm_coalesced_mmio_dev *dev, gpa_t addr, int len)
{
	struct kvm_coalesced_mmio_zone *zone;
	struct kvm_coalesced_mmio_ring *ring;
	unsigned avail;
	int i;

	/* Are we able to batch it ? */

	/*
	 * last is the first free entry
	 * check if we don't meet the first used entry
	 * there is always one unused entry in the buffer
	 */
	ring = dev->kvm->coalesced_mmio_ring;
	avail = (ring->first - ring->last - 1) % KVM_COALESCED_MMIO_MAX;
	if (avail < KVM_MAX_VCPUS) {
		/* full */
		return (0);
	}

	/* is it in a batchable area ? */

	for (i = 0; i < dev->nb_zones; i++) {
		zone = &dev->zone[i];

		/*
		 * (addr,len) is fully included in (zone->addr, zone->size)
		 */
		if (zone->addr <= addr && addr + len <= zone->addr + zone->size)
			return (1);
	}
	return (0);
}

/* Caller must hold slots_lock. */
int
kvm_io_bus_register_dev(struct kvm *kvm,
    enum kvm_bus bus_idx, struct kvm_io_device *dev)
{
	struct kvm_io_bus *new_bus, *bus;

	bus = kvm->buses[bus_idx];
	if (bus->dev_count > NR_IOBUS_DEVS-1)
		return (-ENOSPC);

	new_bus = kmem_zalloc(sizeof (struct kvm_io_bus), KM_SLEEP);
	if (!new_bus)
		return (-ENOMEM);
	memcpy(new_bus, bus, sizeof (struct kvm_io_bus));
	new_bus->devs[new_bus->dev_count++] = dev;
#ifdef XXX
	rcu_assign_pointer(kvm->buses[bus_idx], new_bus);
	synchronize_srcu_expedited(&kvm->srcu);
#else
	XXX_KVM_PROBE;
	kvm->buses[bus_idx] = new_bus;
#endif
	if (bus)
		kmem_free(bus, sizeof (struct kvm_io_bus));

	return (0);
}

/* Caller must hold slots_lock. */
int
kvm_io_bus_unregister_dev(struct kvm *kvm,
    enum kvm_bus bus_idx, struct kvm_io_device *dev)
{
	int i, r;
	struct kvm_io_bus *new_bus, *bus;

	new_bus = kmem_zalloc(sizeof (struct kvm_io_bus), KM_SLEEP);
	if (!new_bus)
		return (-ENOMEM);

	bus = kvm->buses[bus_idx];
	memcpy(new_bus, bus, sizeof (struct kvm_io_bus));

	r = -ENOENT;
	for (i = 0; i < new_bus->dev_count; i++) {
		if (new_bus->devs[i] == dev) {
			r = 0;
			new_bus->devs[i] = new_bus->devs[--new_bus->dev_count];
			break;
		}
	}

	if (r) {
		kmem_free(new_bus, sizeof (struct kvm_io_bus));
		return (r);
	}

#ifdef XXX
	rcu_assign_pointer(kvm->buses[bus_idx], new_bus);
	synchronize_srcu_expedited(&kvm->srcu);
#else
	XXX_KVM_SYNC_PROBE;
	kvm->buses[bus_idx] = new_bus;
#endif
	kmem_free(bus, sizeof (struct kvm_io_bus));
	return (r);
}

static int
coalesced_mmio_write(struct kvm_io_device *this, gpa_t addr,
    int len, const void *val)
{
	struct kvm_coalesced_mmio_dev *dev = to_mmio(this);
	struct kvm_coalesced_mmio_ring *ring = dev->kvm->coalesced_mmio_ring;
	if (!coalesced_mmio_in_range(dev, addr, len))
		return (-EOPNOTSUPP);

	mutex_enter(&dev->lock);

	/* copy data in first free entry of the ring */

	ring->coalesced_mmio[ring->last].phys_addr = addr;
	ring->coalesced_mmio[ring->last].len = len;
	memcpy(ring->coalesced_mmio[ring->last].data, val, len);
#ifdef XXX
	smp_wmb();
#else
	XXX_KVM_SYNC_PROBE;
#endif
	ring->last = (ring->last + 1) % KVM_COALESCED_MMIO_MAX;
	mutex_exit(&dev->lock);
	return (0);
}

/*
 * We used to free the struct that contained us. We don't do that any more. It's
 * just wrong in this case.
 */
static void
coalesced_mmio_destructor(struct kvm_io_device *this)
{
}

int
kvm_coalesced_mmio_init(struct kvm *kvm)
{
	struct kvm_coalesced_mmio_dev *dev;
	page_t *page;
	int ret;

	kvm->coalesced_mmio_ring =
	    ddi_umem_alloc(PAGESIZE, DDI_UMEM_SLEEP, &kvm->mmio_cookie);

	ret = -ENOMEM;
	dev = kmem_zalloc(sizeof (struct kvm_coalesced_mmio_dev), KM_SLEEP);
	if (!dev)
		goto out_free_page;
	mutex_init(&dev->lock, NULL, MUTEX_DRIVER, 0);
	kvm_iodevice_init(&dev->dev, &coalesced_mmio_ops);
	dev->kvm = kvm;
	kvm->coalesced_mmio_dev = dev;

	mutex_enter(&kvm->slots_lock);
	ret = kvm_io_bus_register_dev(kvm, KVM_MMIO_BUS, &dev->dev);
	mutex_exit(&kvm->slots_lock);
	if (ret < 0)
		goto out_free_dev;

	return (ret);

out_free_dev:
	kmem_free(dev, sizeof (struct kvm_coalesced_mmio_dev));
out_free_page:
#ifdef XXX
	kmem_free(page, PAGESIZE);
#else
	XXX_KVM_PROBE;
#endif
	ddi_umem_free(kvm->mmio_cookie);
	return (ret);
}

void
kvm_coalesced_mmio_free(struct kvm *kvmp)
{
	struct kvm_coalesced_mmio_dev *dev = kvmp->coalesced_mmio_dev;
	mutex_destroy(&dev->lock);
	mutex_enter(&kvmp->slots_lock);
	kvm_io_bus_unregister_dev(kvmp, KVM_MMIO_BUS, &dev->dev);
	mutex_exit(&kvmp->slots_lock);
	kvm_iodevice_destructor(&dev->dev);
	kmem_free(dev, sizeof (struct kvm_coalesced_mmio_dev));
	if (kvmp->coalesced_mmio_ring)
		ddi_umem_free(kvmp->mmio_cookie);
}

int
kvm_vm_ioctl_register_coalesced_mmio(struct kvm *kvm,
    struct kvm_coalesced_mmio_zone *zone)
{
	struct kvm_coalesced_mmio_dev *dev = kvm->coalesced_mmio_dev;

	if (dev == NULL)
		return (-EINVAL);

	mutex_enter(&kvm->slots_lock);
	if (dev->nb_zones >= KVM_COALESCED_MMIO_ZONE_MAX) {
		mutex_exit(&kvm->slots_lock);
		return (-ENOBUFS);
	}

	bcopy(zone, &dev->zone[dev->nb_zones],
	    sizeof (struct kvm_coalesced_mmio_zone));
	dev->nb_zones++;

	mutex_exit(&kvm->slots_lock);
	return (0);
}

int
kvm_vm_ioctl_unregister_coalesced_mmio(struct kvm *kvm,
    struct kvm_coalesced_mmio_zone *zone)
{
	int i;
	struct kvm_coalesced_mmio_dev *dev = kvm->coalesced_mmio_dev;
	struct kvm_coalesced_mmio_zone *z;

	if (dev == NULL)
		return (-EINVAL);

	mutex_enter(&kvm->slots_lock);

	i = dev->nb_zones;
	while (i) {
		z = &dev->zone[i - 1];

		/*
		 * Unregister all zones included in (zone->addr, zone->size)
		 */
		if (zone->addr <= z->addr &&
		    z->addr + z->size <= zone->addr + zone->size) {
			dev->nb_zones--;
			*z = dev->zone[dev->nb_zones];
		}
		i--;
	}

	mutex_exit(&kvm->slots_lock);

	return (0);
}

long
kvm_vm_ioctl(struct kvm *kvmp, unsigned int ioctl, unsigned long arg, int mode)
{
	void *argp = (void  *)arg;
	int r;
	proc_t *p;

	if (kvmp->mm != curproc->p_as)
		return (EIO);

	switch (ioctl) {
#ifdef KVM_COALESCED_MMIO_PAGE_OFFSET
	case KVM_REGISTER_COALESCED_MMIO: {
		struct kvm_coalesced_mmio_zone zone;
		r = EFAULT;
		if (copyin(argp, &zone, sizeof (zone)))
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
		if (copyin(argp, &zone, sizeof (zone)))
			goto out;
		r = ENXIO;
		r = kvm_vm_ioctl_unregister_coalesced_mmio(kvmp, &zone);
		if (r)
			goto out;
		r = 0;
		break;
	}
#endif
#ifdef XXX_KVM_DECLARATION
	case KVM_IRQFD: {
		struct kvm_irqfd data;

		if (ddi_copyin(argp, &data, sizeof (data), mode))
			return (EFAULT);
		r = kvm_irqfd(kvmp, data.fd, data.gsi, data.flags);
		break;
	}

	case KVM_IOEVENTFD: {
		struct kvm_ioeventfd data;

		r = -EFAULT;
		if (copy_from_user(&data, argp, sizeof (data)))
			goto out;
		r = kvm_ioeventfd(kvmp, &data);
		break;
	}
#endif

	default:
		return (EINVAL);
	}

out:
	return (r);
}

int
kvm_arch_vcpu_runnable(struct kvm_vcpu *vcpu)
{
	return (vcpu->arch.mp_state == KVM_MP_STATE_RUNNABLE ||
	    vcpu->arch.mp_state == KVM_MP_STATE_SIPI_RECEIVED ||
	    vcpu->arch.nmi_pending ||
	    (kvm_arch_interrupt_allowed(vcpu) && kvm_cpu_has_interrupt(vcpu)));
}

void
kvm_free_physmem(struct kvm *kvm)
{
	int ii;
	struct kvm_memslots *slots = kvm->memslots;

	for (ii = 0; ii < slots->nmemslots; ii++)
		kvm_free_physmem_slot(&slots->memslots[ii], NULL);

	kmem_free(kvm->memslots, sizeof (struct kvm_memslots));
}
