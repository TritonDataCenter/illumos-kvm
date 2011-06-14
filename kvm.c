
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
#include <sys/machparam.h>
#include <asm/cpu.h>

#include "kvm_bitops.h"
#include "kvm_vmx.h"
#include "msr-index.h"
#include "msr.h"
#include "irqflags.h"
#include "kvm_host.h"
#include "kvm_lapic.h"
#include "processor-flags.h"
#include "kvm_cpuid.h"
#include "hyperv.h"
#include "kvm_apicdef.h"
#include "kvm_iodev.h"
#include "kvm.h"
#include "kvm_x86impl.h"
#include "kvm_irq.h"
#include "kvm_tss.h"
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
	struct kvm *kds_kvmp;		/* pointer to underlying VM */
	struct kvm_vcpu *kds_vcpu;	/* pointer to VCPU */
} kvm_devstate_t;

/*
 * Globals
 */
page_t *bad_page;
void *bad_page_kma;
pfn_t bad_pfn;

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
static int kvmid;		/* monotonically increasing, unique per vm */
static int largepages_enabled = 1;
static cpuset_t cpus_hardware_enabled;
static volatile uint32_t hardware_enable_failed;
static int kvm_usage_count;
static list_t vm_list;
static kmutex_t kvm_lock;
static int ignore_msrs = 0;
static unsigned long empty_zero_page[PAGESIZE / sizeof (unsigned long)];

int
kvm_xcall_func(kvm_xcall_t func, void *arg)
{
	if (func != NULL)
		(*func)(arg);

	return (0);
}

void
kvm_xcall(processorid_t cpu, kvm_xcall_t func, void *arg)
{
	cpuset_t set;

	CPUSET_ZERO(set);

	if (cpu == KVM_CPUALL) {
		CPUSET_ALL(set);
	} else {
		CPUSET_ADD(set, cpu);
	}

	kpreempt_disable();
	xc_sync((xc_arg_t)func, (xc_arg_t)arg, 0, CPUSET2BV(set),
		(xc_func_t) kvm_xcall_func);
	kpreempt_enable();
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

void
kvm_migrate_timers(struct kvm_vcpu *vcpu)
{
	set_bit(KVM_REQ_MIGRATE_TIMER, &vcpu->requests);
}

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

struct kvm_vcpu *
kvm_get_vcpu(struct kvm *kvm, int i)
{
#ifdef XXX
	smp_rmb();
#else
	XXX_KVM_PROBE;
#endif
	return (kvm->vcpus[i]);
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

static void
ack_flush(void *_completed)
{
}

int
make_all_cpus_request(struct kvm *kvm, unsigned int req)
{
	int i;
	cpuset_t set;
	processorid_t me, cpu;
	struct kvm_vcpu *vcpu;

	CPUSET_ZERO(set);

	mutex_enter(&kvm->requests_lock);
	me = curthread->t_cpu->cpu_id;
	for (i = 0; i < kvm->online_vcpus; i++) {
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

	return (1);
}

void
kvm_flush_remote_tlbs(struct kvm *kvm)
{
	if (make_all_cpus_request(kvm, KVM_REQ_TLB_FLUSH))
		KVM_KSTAT_INC(kvm, kvmks_remote_tlb_flush);
}

void
kvm_reload_remote_mmus(struct kvm *kvm)
{
	make_all_cpus_request(kvm, KVM_REQ_MMU_RELOAD);
}

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

void
kvm_vcpu_uninit(struct kvm_vcpu *vcpu)
{
	kvm_arch_vcpu_uninit(vcpu);
	ddi_umem_free(vcpu->cookie);
}

/*
 * Note if we want to implement the kvm mmu notifier components than the
 * following two functions will need to be readdressed.
 */
static int kvm_init_mmu_notifier(struct kvm *kvm)
{
	return (0);
}

static void
kvm_fini_mmu_notifier(struct kvm *kvm)
{
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

	kvm_arch_flush_shadow(kvmp);  /* clean up shadow page tables */

	kvm_arch_destroy_vm_comps(kvmp);
	kvm_free_irq_routing(kvmp);
	kvm_destroy_pic(kvmp);
	kvm_ioapic_destroy(kvmp);
	kvm_coalesced_mmio_free(kvmp);

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

	/*
	 * These lists are contained by the pic. However, the pic isn't
	 */
	list_destroy(&kvmp->irq_ack_notifier_list);
	list_destroy(&kvmp->mask_notifier_list);

	kvm_arch_destroy_vm(kvmp);
}

static struct kvm *
kvm_create_vm(void)
{
	int rval = 0;
	int i;
	struct kvm *kvmp = kvm_arch_create_vm();

	if (kvmp == NULL)
		return (NULL);

	list_create(&kvmp->mask_notifier_list,
		    sizeof (struct kvm_irq_mask_notifier),
		    offsetof(struct kvm_irq_mask_notifier, link));
	list_create(&kvmp->irq_ack_notifier_list,
		    sizeof (struct kvm_irq_ack_notifier),
		    offsetof(struct kvm_irq_ack_notifier, link));

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

	kvm_coalesced_mmio_init(kvmp);

	return (kvmp);
}

/*
 * Free any memory in @free but not in @dont.
 */
static void
kvm_free_physmem_slot(struct kvm_memory_slot *free,
    struct kvm_memory_slot *dont)
{
	int i;

	if (!dont || free->rmap != dont->rmap)
		kmem_free(free->rmap, free->npages * sizeof (struct page *));

	if ((!dont || free->dirty_bitmap != dont->dirty_bitmap) &&
	    free->dirty_bitmap)
		kmem_free(free->dirty_bitmap, free->dirty_bitmap_sz);

	for (i = 0; i < KVM_NR_PAGE_SIZES - 1; ++i) {
		if ((!dont || free->lpage_info[i] != dont->lpage_info[i]) &&
		    free->lpage_info[i]) {
			kmem_free(free->lpage_info[i], free->lpage_info_sz[i]);
			free->lpage_info[i] = NULL;
		}
	}

	free->npages = 0;
	free->dirty_bitmap = NULL;
	free->rmap = NULL;
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

void
kvm_get_kvm(struct kvm *kvm)
{
	atomic_inc_32(&kvm->users_count);
}

unsigned long
kvm_dirty_bitmap_bytes(struct kvm_memory_slot *memslot)
{
	return (BT_SIZEOFMAP(memslot->npages));
}

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
		new.lpage_info_sz[i] = lpages * sizeof (*new.lpage_info[i]);

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
		new.dirty_bitmap_sz = dirty_bytes;

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

int
kvm_vm_ioctl_set_memory_region(struct kvm *kvm,
    struct kvm_userspace_memory_region *mem, int user_alloc)
{
	if (mem->slot >= KVM_MEMORY_SLOTS)
		return (EINVAL);

	return (kvm_set_memory_region(kvm, mem, user_alloc));
}

void
kvm_disable_largepages(void)
{
	largepages_enabled = 0;
}

int
is_error_pfn(pfn_t pfn)
{
	return (pfn == bad_pfn);
}

static unsigned long
bad_hva(void)
{
	return (PAGEOFFSET);
}

int
kvm_is_error_hva(unsigned long addr)
{
	return (addr == bad_hva());
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

struct kvm_memory_slot *
gfn_to_memslot(struct kvm *kvm, gfn_t gfn)
{
	gfn = unalias_gfn(kvm, gfn);
	return (gfn_to_memslot_unaliased(kvm, gfn));
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
kvm_release_pfn_clean(pfn_t pfn)
{
#ifdef XXX
	if (!kvm_is_mmio_pfn(pfn))
		put_page(pfn_to_page(pfn));
#else
	XXX_KVM_PROBE;
#endif
}

void
kvm_release_page_dirty(page_t *page)
{
	kvm_release_pfn_dirty(page_to_pfn(page));
}

void
kvm_release_pfn_dirty(pfn_t pfn)
{
	kvm_set_pfn_dirty(pfn);
	kvm_release_pfn_clean(pfn);
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
kvm_get_pfn(struct kvm_vcpu *vcpu, pfn_t pfn)
{
	if (!kvm_is_mmio_pfn(pfn))
		get_page(pfn_to_page(pfn));
}

static int
next_segment(unsigned long len, int offset)
{
	if (len > PAGESIZE - offset)
		return (PAGESIZE - offset);
	else
		return (len);
}

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

int
kvm_clear_guest_page(struct kvm *kvm, gfn_t gfn, int offset, int len)
{
	return (kvm_write_guest_page(kvm, gfn, empty_zero_page, offset, len));
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
kvm_vcpu_is_bsp(struct kvm_vcpu *vcpu)
{
	return (vcpu->kvm->bsp_vcpu_id == vcpu->vcpu_id);
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

/*
 * Creates some virtual cpus.  Good luck creating more than one.
 */
int
kvm_vm_ioctl_create_vcpu(struct kvm *kvm, uint32_t id, int *rval_p)
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

	if (kvm->bsp_vcpu_id == id)
		kvm->bsp_vcpu = vcpu;

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

int
kvm_dev_ioctl_check_extension_generic(long arg, int *rv)
{
	switch (arg) {
	case KVM_CAP_USER_MEMORY:
	case KVM_CAP_DESTROY_MEMORY_REGION_WORKS:
	case KVM_CAP_JOIN_MEMORY_REGIONS_WORKS:
	case KVM_CAP_SET_BOOT_CPU_ID:
	case KVM_CAP_INTERNAL_ERROR_DATA:
		*rv = 1;
		return (DDI_SUCCESS);
	case KVM_CAP_IRQ_ROUTING:
		*rv = KVM_MAX_IRQ_ROUTES;
		return (DDI_SUCCESS);
	default:
		break;
	}
	return (kvm_dev_ioctl_check_extension(arg, rv));
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

void
hardware_disable(void *junk)
{
	int cpu = curthread->t_cpu->cpu_id;

	if (!CPU_IN_SET(cpus_hardware_enabled, cpu))
		return;

	CPUSET_DEL(cpus_hardware_enabled, cpu);
	kvm_arch_hardware_disable(NULL);
}

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

int
kvm_init(void *opaque)
{
	int r;
	int cpu;

	r = kvm_arch_init(opaque);

	if (r != DDI_SUCCESS)
		return (r);

	bad_page = alloc_page(KM_SLEEP, &bad_page_kma);
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
	kmem_free(bad_page_kma, PAGESIZE);
out:
#ifdef XXX
	kvm_arch_exit();
#else
	XXX_KVM_PROBE;
#endif
out_fail:
	return (r);
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

int
zero_constructor(void *buf, void *arg, int tags)
{
	bzero(buf, (size_t)arg);
	return (0);
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

	mutex_init(&kvm_lock, NULL, MUTEX_DRIVER, 0);
	if (vmx_init() != DDI_SUCCESS) {
		ddi_soft_state_fini(&kvm_state);
		ddi_remove_minor_node(dip, NULL);
		mutex_destroy(&kvm_lock);
		return (DDI_FAILURE);
	}

	if (hardware_enable_all() != 0) {
		ddi_soft_state_fini(&kvm_state);
		ddi_remove_minor_node(dip, NULL);
		mutex_destroy(&kvm_lock);
		vmx_fini();
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
	kvm_arch_hardware_unsetup();
	kvm_arch_exit();
	kmem_free(bad_page_kma, PAGESIZE);

	vmx_fini();
	mutex_destroy(&kvm_lock);
	ddi_soft_state_fini(&kvm_state);

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
			int (*func)(kvm_t *, void *, int *, intptr_t);

			if ((kvmp = ksp->kds_kvmp) == NULL) {
				kmem_free(buf, ioctl->size);
				return (EINVAL);
			}

			func = (int(*)(kvm_t *, void *, int *,
			    intptr_t))ioctl->func;
			rval = func(kvmp, buf, rv, arg);
		} else {
			kvm_vcpu_t *vcpu;
			int (*func)(kvm_vcpu_t *, void *, int *, intptr_t);

			if ((vcpu = ksp->kds_vcpu) == NULL) {
				kmem_free(buf, ioctl->size);
				return (EINVAL);
			}

			func = (int(*)(kvm_vcpu_t *, void *, int *,
			    intptr_t))ioctl->func;
			rval = func(vcpu, buf, rv, arg);
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

	case KVM_GET_MSR_INDEX_LIST: {
		rval = kvm_vm_ioctl_get_msr_index_list(NULL, arg);
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

	case KVM_SET_BOOT_CPU_ID: {
		struct kvm *kvmp;

		if ((kvmp = ksp->kds_kvmp) == NULL) {
			rval = EINVAL;
			break;
		}

		if (arg >= KVM_MAX_VCPUS) {
			rval = EINVAL;
			break;
		}

		mutex_enter(&kvmp->lock);
		if (kvmp->online_vcpus != 0) {
			rval = EBUSY;
			break;
		} else {
			kvmp->bsp_vcpu_id = arg;
			*rv = kvmp->bsp_vcpu_id;
		}

		mutex_exit(&kvmp->lock);
		break;
	}

	case KVM_REGISTER_COALESCED_MMIO: {
		struct kvm *kvmp;
		struct kvm_coalesced_mmio_zone *zone;
		size_t sz = sizeof (struct kvm_coalesced_mmio_zone);

		zone = kmem_zalloc(sz, KM_SLEEP);

		if (copyin(argp, zone, sz) != 0) {
			kmem_free(zone, sz);
			rval = EFAULT;
			break;
		}

		if ((kvmp = ksp->kds_kvmp) == NULL) {
			rval = EINVAL;
			kmem_free(zone, sz);
			break;
		}

		rval = kvm_vm_ioctl_register_coalesced_mmio(kvmp, zone);

		kmem_free(zone, sz);
		break;
	}

	case KVM_UNREGISTER_COALESCED_MMIO: {
		struct kvm_coalesced_mmio_zone *zone;
		struct kvm *kvmp;
		size_t sz = sizeof (struct kvm_coalesced_mmio_zone);

		zone = kmem_zalloc(sz, KM_SLEEP);

		if (copyin(argp, zone, sz) != 0) {
			kmem_free(zone, sz);
			break;
		}

		if ((kvmp = ksp->kds_kvmp) == NULL) {
			kmem_free(zone, sz);
			rval = EINVAL;
			break;
		}

		rval = kvm_vm_ioctl_unregister_coalesced_mmio(kvmp, zone);

		kmem_free(zone, sz);
		break;
	}
#ifdef KVM_CAP_IRQ_ROUTING
	case KVM_SET_GSI_ROUTING: {
		struct kvm_irq_routing *route;
		struct kvm *kvmp;
		struct kvm_irq_routing_entry *entries;
		uint32_t nroutes;
		size_t sz = sizeof (kvm_irq_routing_t) + KVM_MAX_IRQ_ROUTES *
		    sizeof (struct kvm_irq_routing_entry);

		/*
		 * Note the route must be allocated on the heap. The sizeof
		 * (kvm_kirq_routing) is approximately 0xc038 currently.
		 */
		route = kmem_zalloc(sz, KM_SLEEP);

		/*
		 * copyin the number of routes, then copyin the routes
		 * themselves.
		 */
		if (copyin(argp, &nroutes, sizeof (nroutes)) != 0) {
			kmem_free(route, sz);
			rval = EFAULT;
			break;
		}

		if (nroutes <= 0) {
			kmem_free(route, sz);
			rval = EINVAL;
			break;
		}

		if (copyin(argp, route,
		    sizeof (struct kvm_irq_routing) + (nroutes - 1) *
		    sizeof (struct kvm_irq_routing_entry)) != 0) {
			kmem_free(route, sz);
			rval = EFAULT;
			break;
		}

		if ((kvmp = ksp->kds_kvmp) == NULL) {
			kmem_free(route, sz);
			rval = EINVAL;
			break;
		}

		if (route->nr >= KVM_MAX_IRQ_ROUTES || route->flags) {
			kmem_free(route, sz);
			rval = EINVAL;
			break;
		}

		rval = kvm_set_irq_routing(kvmp, route->entries,
		    route->nr, route->flags);
		kmem_free(route, sz);
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

static struct modldrv modldrv = {
	&mod_driverops,
	"kvm driver v0.1",
	&kvm_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	{ &modldrv, NULL }
};

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
/* END CSTYLED */
