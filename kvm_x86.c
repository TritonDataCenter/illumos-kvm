
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

#include "kvm.h"

struct vmcs *vmxarea;

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
		pfn = phys >> PAGE_SHIFT;
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
extern uint64_t xrdmsr(uint_t r);
extern void xwrmsr(uint_t r, const uint64_t val);
extern pfn_t hat_getpfnum(struct hat *hat, caddr_t);

#define X86_CR4_VMXE	0x00002000 /* enable VMX virtualization */
#define MSR_IA32_FEATURE_CONTROL        0x0000003a

#define FEATURE_CONTROL_LOCKED		(1<<0)
#define FEATURE_CONTROL_VMXON_ENABLED	(1<<2)

#define ASM_VMX_VMXON_RAX         ".byte 0xf3, 0x0f, 0xc7, 0x30"

static int
hardware_enable(void *garbage)
{
	int cpu = curthread->t_cpu->cpu_id;
#ifdef XXX
	uint64_t phys_addr = kvtop(per_cpu(vmxarea, cpu));
#else
	uint64_t phys_addr = hat_getpfnum(kas.a_hat, (char *)vmxarea)<<PAGESHIFT;  /*XXX, this can't be right... */
#endif
	uint64_t old;

	if (getcr4() & X86_CR4_VMXE)
		return DDI_FAILURE;

#ifdef XXX
	INIT_LIST_HEAD(&per_cpu(vcpus_on_cpu, cpu));
#endif
	old = xrdmsr(MSR_IA32_FEATURE_CONTROL);  /* XXX - not sure this is correct */
	if ((old & (FEATURE_CONTROL_LOCKED |
		    FEATURE_CONTROL_VMXON_ENABLED))
	    != (FEATURE_CONTROL_LOCKED |
		FEATURE_CONTROL_VMXON_ENABLED))
		/* enable and lock */
		xwrmsr(MSR_IA32_FEATURE_CONTROL, old |
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

	return hardware_enable(garbage);
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
