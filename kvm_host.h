#ifndef __KVM_HOST_H
#define __KVM_HOST_H

/*
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#ifdef XXX
#include <linux/types.h>
#include <linux/hardirq.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/preempt.h>
#include <linux/msi.h>
#include <asm/signal.h>

#include <linux/kvm.h>
#include <linux/kvm_para.h>

#endif /*XXX*/

#include "kvm_types.h"

#define KVM_MEMORY_SLOTS 32  /* XXX assumes x86 */
#define KVM_PRIVATE_MEM_SLOTS 4 /* XXX assumes x86 */
#define TSS_PRIVATE_MEMSLOT			(KVM_MEMORY_SLOTS + 0)
#define APIC_ACCESS_PAGE_PRIVATE_MEMSLOT	(KVM_MEMORY_SLOTS + 1)
#define IDENTITY_PAGETABLE_PRIVATE_MEMSLOT	(KVM_MEMORY_SLOTS + 2)

#include "kvm_x86host.h"

/*
 * vcpu->requests bit members
 */
#define KVM_REQ_TLB_FLUSH          0
#define KVM_REQ_MIGRATE_TIMER      1
#define KVM_REQ_REPORT_TPR_ACCESS  2
#define KVM_REQ_MMU_RELOAD         3
#define KVM_REQ_TRIPLE_FAULT       4
#define KVM_REQ_PENDING_TIMER      5
#define KVM_REQ_UNHALT             6
#define KVM_REQ_MMU_SYNC           7
#define KVM_REQ_KVMCLOCK_UPDATE    8
#define KVM_REQ_KICK               9
#define KVM_REQ_DEACTIVATE_FPU    10

#define KVM_USERSPACE_IRQ_SOURCE_ID	0

struct kvm;
struct kvm_vcpu;
extern struct kmem_cache *kvm_vcpu_cache;


void kvm_vcpu_uninit(struct kvm_vcpu *vcpu);

void vcpu_load(struct kvm_vcpu *vcpu);
void vcpu_put(struct kvm_vcpu *vcpu);

#ifdef XXX
int kvm_init(void *opaque, unsigned int vcpu_size,
		  struct module *module);
void kvm_exit(void);
#endif /*XXX*/

void kvm_get_kvm(struct kvm *kvm);
void kvm_put_kvm(struct kvm *kvm);

#define HPA_MSB ((sizeof(hpa_t) * 8) - 1)
#define HPA_ERR_MASK ((hpa_t)1 << HPA_MSB)
static int is_error_hpa(hpa_t hpa) { return hpa >> HPA_MSB; }
page_t gva_to_page(struct kvm_vcpu *vcpu, gva_t gva);

extern page_t *bad_page;
extern pfn_t bad_pfn;

/* For vcpu->arch.iommu_flags */
#define KVM_IOMMU_CACHE_COHERENCY	0x1


#ifdef XXX
static void kvm_guest_enter(void)
{
	account_system_vtime(current);
	current->flags |= PF_VCPU;
}

static void kvm_guest_exit(void)
{
	account_system_vtime(current);
	current->flags &= ~PF_VCPU;
}

gpa_t gfn_to_gpa(gfn_t gfn)
{
	return (gpa_t)gfn << PAGESHIFT;
}

static hpa_t pfn_to_hpa(pfn_t pfn)
{
	return (hpa_t)pfn << PAGESHIFT;
}

static void kvm_migrate_timers(struct kvm_vcpu *vcpu)
{
	set_bit(KVM_REQ_MIGRATE_TIMER, &vcpu->requests);
}

#endif /*XXX*/

enum kvm_stat_kind {
	KVM_STAT_VM,
	KVM_STAT_VCPU,
};

typedef struct kvm_stats_debugfs_item {
	const char *name;
	int offset;
	enum kvm_stat_kind kind;
	struct dentry *dentry;
} kvm_stats_debugfs_item_t;
extern struct kvm_stats_debugfs_item debugfs_entries[];
extern struct dentry *kvm_debugfs_dir;

#ifdef XXX
#ifdef KVM_ARCH_WANT_MMU_NOTIFIER
static int mmu_notifier_retry(struct kvm_vcpu *vcpu, unsigned long mmu_seq)
{
	if (unlikely(vcpu->kvm->mmu_notifier_count))
		return 1;
	/*
	 * Both reads happen under the mmu_lock and both values are
	 * modified under mmu_lock, so there's no need of smb_rmb()
	 * here in between, otherwise mmu_notifier_count should be
	 * read before mmu_notifier_seq, see
	 * mmu_notifier_invalidate_range_end write side.
	 */
	if (vcpu->kvm->mmu_notifier_seq != mmu_seq)
		return 1;
	return 0;
}
#endif
#endif /*XXX*/

#ifndef KVM_ARCH_HAS_UNALIAS_INSTANTIATION
#define unalias_gfn_instantiation unalias_gfn
#endif

#undef CONFIG_HAVE_KVM_EVENTFD

#ifdef CONFIG_HAVE_KVM_EVENTFD

void kvm_eventfd_init(struct kvm *kvm);
int kvm_irqfd(struct kvm *kvm, int fd, int gsi, int flags);
void kvm_irqfd_release(struct kvm *kvm);
int kvm_ioeventfd(struct kvm *kvm, struct kvm_ioeventfd *args);

#else

static void kvm_eventfd_init(struct kvm *kvm) {}
static int kvm_irqfd(struct kvm *kvm, int fd, int gsi, int flags)
{
	return -EINVAL;
}

static void kvm_irqfd_release(struct kvm *kvm) {}
#ifdef XXX
static int kvm_ioeventfd(struct kvm *kvm, struct kvm_ioeventfd *args)
{
	return -ENOSYS;
}
#endif /*XXX*/
#endif /* CONFIG_HAVE_KVM_EVENTFD */

#ifdef __KVM_HAVE_DEVICE_ASSIGNMENT

long kvm_vm_ioctl_assigned_device(struct kvm *kvm, unsigned ioctl,
				  unsigned long arg);

#else

static long kvm_vm_ioctl_assigned_device(struct kvm *kvm, unsigned ioctl,
						unsigned long arg)
{
	return -ENOTTY;
}

#endif

#endif

