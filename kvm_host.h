/*
 * This work is licensed under the terms of the GNU GPL, version 2. See the
 * COPYING file in the top-level directory.
 *
 * Copyright 2011 various Linux Kernel contributors.
 * Copyright 2018 Joyent, Inc.
 */

#ifndef __KVM_HOST_H
#define	__KVM_HOST_H

#include <sys/types.h>
#include <sys/list.h>
#include <sys/mutex.h>
#include <sys/sunddi.h>

#include "kvm_types.h"
#include "kvm_impl.h"
#include "kvm_x86host.h"

#define	NSEC_PER_MSEC 1000000L
#define	NSEC_PER_SEC 1000000000L

#define	BITS_PER_LONG	(sizeof (unsigned long) * 8)

/*
 * vcpu->requests bit members
 */
#define	KVM_REQ_TLB_FLUSH		0
#define	KVM_REQ_REPORT_TPR_ACCESS	2
#define	KVM_REQ_MMU_RELOAD		3
#define	KVM_REQ_TRIPLE_FAULT		4
#define	KVM_REQ_PENDING_TIMER		5
#define	KVM_REQ_UNHALT			6
#define	KVM_REQ_MMU_SYNC		7
#define	KVM_REQ_KVMCLOCK_UPDATE		8
#define	KVM_REQ_KICK			9
#define	KVM_REQ_DEACTIVATE_FPU		10

#define	KVM_USERSPACE_IRQ_SOURCE_ID	0

struct kvm;
struct kvm_vcpu;

typedef struct kvm_user_return_notifier {
	void (*on_user_return)(struct kvm_vcpu *,
	    struct kvm_user_return_notifier *);
} kvm_user_return_notifier_t;

extern void kvm_user_return_notifier_register(struct kvm_vcpu *,
    struct kvm_user_return_notifier *);
extern void kvm_user_return_notifier_unregister(struct kvm_vcpu *,
    struct kvm_user_return_notifier *);
extern void kvm_fire_urn(struct kvm_vcpu *);

#define	KVM_NR_SHARED_MSRS 16

typedef struct kvm_shared_msrs_global {
	int nr;
	uint32_t msrs[KVM_NR_SHARED_MSRS];
} kvm_shared_msrs_global_t;

typedef struct kvm_shared_msrs {
	struct kvm_user_return_notifier urn;
	int registered;
	uint_t host_saved;
	struct kvm_shared_msr_values {
		uint64_t host;
		uint64_t curr;
	} values[KVM_NR_SHARED_MSRS];
} kvm_shared_msrs_t;

/*
 * It would be nice to use something smarter than a linear search, TBD...
 * Thankfully we dont expect many devices to register (famous last words :),
 * so until then it will suffice.  At least its abstracted so we can change
 * in one place.
 */
typedef struct kvm_io_bus {
	int			dev_count;
#define	NR_IOBUS_DEVS 200
	struct kvm_io_device	*devs[NR_IOBUS_DEVS];
} kvm_io_bus_t;

enum kvm_bus {
	KVM_MMIO_BUS,
	KVM_PIO_BUS,
	KVM_NR_BUSES
};

extern int kvm_io_bus_write(struct kvm *, enum kvm_bus, gpa_t,
    int, const void *);
extern int kvm_io_bus_read(struct kvm *, enum kvm_bus, gpa_t, int,
    void *);
extern int kvm_io_bus_register_dev(struct kvm *, enum kvm_bus,
    struct kvm_io_device *);
extern int kvm_io_bus_unregister_dev(struct kvm *, enum kvm_bus,
    struct kvm_io_device *);

#define	KVM_MAX_IRQ_ROUTES 1024

#define	KVM_RINGBUF_NENTRIES	512

#define	KVM_RINGBUF_TAG_CTXSAVE		1
#define	KVM_RINGBUF_TAG_CTXRESTORE	2
#define	KVM_RINGBUF_TAG_VMPTRLD		3
#define	KVM_RINGBUF_TAG_VCPUMIGRATE	4
#define	KVM_RINGBUF_TAG_VCPUCLEAR	5
#define	KVM_RINGBUF_TAG_VCPULOAD	6
#define	KVM_RINGBUF_TAG_VCPUPUT		7
#define	KVM_RINGBUF_TAG_RELOAD		8
#define	KVM_RINGBUF_TAG_EMUFAIL0	9
#define	KVM_RINGBUF_TAG_EMUFAIL1	10
#define	KVM_RINGBUF_TAG_EMUFAIL2	11
#define	KVM_RINGBUF_TAG_EMUXADD		12
#define	KVM_RINGBUF_TAG_MAX		12

typedef struct kvm_ringbuf_entry {
	uint32_t kvmre_tag;			/* tag for this entry */
	uint32_t kvmre_cpuid;			/* CPU of entry */
	uint64_t kvmre_thread;			/* thread for entry */
	uint64_t kvmre_tsc;			/* TSC at time of entry */
	uint64_t kvmre_payload;			/* payload for this entry */
} kvm_ringbuf_entry_t;

typedef struct kvm_ringbuf {
	kvm_ringbuf_entry_t kvmr_buf[KVM_RINGBUF_NENTRIES]; /* ring buffer */
	kvm_ringbuf_entry_t kvmr_taglast[KVM_RINGBUF_TAG_MAX + 1];
	uint32_t kvmr_tagcount[KVM_RINGBUF_TAG_MAX + 1]; /* count of tags */
	uint32_t kvmr_ent;			/* current entry */
} kvm_ringbuf_t;

extern void kvm_ringbuf_record(kvm_ringbuf_t *, uint32_t, uint64_t);

typedef struct kvm_vcpu {
	struct kvm *kvm;
	int vcpu_id;
	kmutex_t mutex;
	int   cpu;
	struct kvm_run *run;
	unsigned long requests;
	unsigned long guest_debug;
	int srcu_idx;

	int fpu_active;
	int guest_fpu_loaded;

	kmutex_t kvcpu_kick_lock;
	kcondvar_t kvcpu_kick_cv;
	kvm_vcpu_stats_t kvcpu_stats;
	kstat_t *kvcpu_kstat;
	kvm_ringbuf_t kvcpu_ringbuf;
	int sigset_active;
	sigset_t sigset;
	int mmio_needed;
	int mmio_read_completed;
	int mmio_is_write;
	int mmio_size;
	unsigned char mmio_data[8];
	gpa_t mmio_phys_addr;
	struct kvm_vcpu_arch arch;
	ddi_umem_cookie_t cookie;
	struct kvm_user_return_notifier *urn;
} kvm_vcpu_t;

typedef struct kvm_memory_slot {
	gfn_t base_gfn;
	unsigned long npages;
	unsigned long flags;
	unsigned long *rmap;
	unsigned long *dirty_bitmap;
	size_t dirty_bitmap_sz;
	struct {
		unsigned long rmap_pde;
		int write_count;
	} *lpage_info[KVM_NR_PAGE_SIZES];
	size_t lpage_info_sz[KVM_NR_PAGE_SIZES];
	unsigned long userspace_addr;
	int user_alloc;
} kvm_memory_slot_t;

unsigned long kvm_dirty_bitmap_bytes(struct kvm_memory_slot *memslot);

typedef struct kvm_kernel_irq_routing_entry {
	uint32_t gsi;
	uint32_t type;
	int (*set)(struct kvm_kernel_irq_routing_entry *e,
	    struct kvm *kvm, int irq_source_id, int level);
	union {
		struct {
			unsigned irqchip;
			unsigned pin;
		} irqchip;
		struct msi_msg msi;
	};
	struct list_node link;
} kvm_kernel_irq_routing_entry_t;

typedef struct kvm_irq_routing_table {
	int chip[KVM_NR_IRQCHIPS][KVM_IOAPIC_NUM_PINS];
	struct kvm_kernel_irq_routing_entry *rt_entries;
	uint32_t nr_rt_entries;
	/*
	 * Array indexed by gsi. Each entry contains list of irq chips
	 * the gsi is connected to.
	 */
	list_t map[KVM_MAX_IRQ_ROUTES+1];
} kvm_irq_routing_table_t;

typedef struct kvm_memslots {
	int nmemslots;
	struct kvm_memory_slot memslots[KVM_MEMORY_SLOTS +
					KVM_PRIVATE_MEM_SLOTS];
} kvm_memslots_t;

typedef struct kvm {
	kmutex_t mmu_lock;
	kmutex_t requests_lock;
	kmutex_t slots_lock;
	struct kvm_memslots *memslots;
	kmutex_t memslots_lock; /* linux uses rcu for this */
	/* the following was a read-copy update mechanism */
	/* we'll use a reader-writer lock, for now */
	krwlock_t kvm_rwlock;
	uint32_t bsp_vcpu_id;
	struct kvm_vcpu *bsp_vcpu;
	struct kvm_vcpu *vcpus[KVM_MAX_VCPUS];
	volatile int online_vcpus;
	struct list_node vm_list;
	kmutex_t lock;
	struct kvm_io_bus *buses[KVM_NR_BUSES];
	kmutex_t buses_lock;
	struct kstat *kvm_kstat;
	kvm_stats_t kvm_stats;
	struct kvm_arch arch;
	volatile int users_count;
	struct kvm_coalesced_mmio_dev *coalesced_mmio_dev;
	struct kvm_coalesced_mmio_ring *coalesced_mmio_ring;
	ddi_umem_cookie_t mmio_cookie;

	kmutex_t irq_lock;
	struct kvm_irq_routing_table *irq_routing;
	int irq_routing_sz;
	list_t mask_notifier_list;
	list_t irq_ack_notifier_list;

	int kvmid;  /* unique identifier for this kvm */
	int kvm_clones;
	pid_t kvm_pid;			/* pid associated with this kvm */
	kmutex_t kvm_avllock;
	avl_tree_t kvm_avlmp;		/* avl tree for mmu to page_t mapping */
} kvm_t;


extern struct kvm_vcpu *kvm_get_vcpu(struct kvm *kvm, int i);

#define	kvm_for_each_vcpu(idx, vcpup, kvm) \
	for (idx = 0, vcpup = kvm_get_vcpu(kvm, idx); \
	    idx < kvm->online_vcpus && vcpup; /* XXX - need protection */ \
	    vcpup = kvm_get_vcpu(kvm, ++idx))

extern int kvm_vcpu_init(struct kvm_vcpu *, struct kvm *, unsigned);
extern void kvm_vcpu_uninit(struct kvm_vcpu *);

extern void vcpu_load(struct kvm_vcpu *);
extern void vcpu_put(struct kvm_vcpu *);

extern int kvm_init(void *);
extern void kvm_exit(void);

extern void kvm_get_kvm(struct kvm *);
extern void kvm_put_kvm(struct kvm *);

#define	HPA_MSB ((sizeof (hpa_t) * 8) - 1)
#define	HPA_ERR_MASK ((hpa_t)1 << HPA_MSB)
static int is_error_hpa(hpa_t hpa) { return hpa >> HPA_MSB; }

extern page_t *bad_page;
extern void *bad_page_kma;
extern pfn_t bad_pfn;

extern int is_error_page(struct page *);
extern int is_error_pfn(pfn_t);
extern int kvm_is_error_hva(unsigned long);

extern int kvm_set_memory_region(struct kvm *,
    struct kvm_userspace_memory_region *, int);
extern int __kvm_set_memory_region(struct kvm *,
    struct kvm_userspace_memory_region *, int);
extern int kvm_arch_prepare_memory_region(struct kvm *,
    struct kvm_memory_slot *, struct kvm_memory_slot,
    struct kvm_userspace_memory_region *, int);
extern void kvm_arch_commit_memory_region(struct kvm *,
    struct kvm_userspace_memory_region *,
    struct kvm_memory_slot, int);

extern void kvm_disable_largepages(void);
extern void kvm_arch_flush_shadow(struct kvm *);
extern gfn_t unalias_gfn(struct kvm *, gfn_t);
extern gfn_t unalias_gfn_instantiation(struct kvm *, gfn_t);

extern page_t *gfn_to_page(struct kvm *, gfn_t);
extern unsigned long gfn_to_hva(struct kvm *, gfn_t);
extern void kvm_release_page_clean(struct page *);
extern void kvm_release_page_dirty(struct page *);
extern void kvm_set_page_dirty(struct page *);
extern void kvm_set_page_accessed(struct page *);

extern pfn_t gfn_to_pfn(struct kvm *, gfn_t);
extern pfn_t gfn_to_pfn_memslot(struct kvm *,
    struct kvm_memory_slot *, gfn_t);
extern int memslot_id(struct kvm *, gfn_t);
extern void kvm_release_pfn_dirty(pfn_t);
extern void kvm_release_pfn_clean(pfn_t);
extern void kvm_set_pfn_dirty(pfn_t);
extern void kvm_set_pfn_accessed(struct kvm *, pfn_t);
extern void kvm_get_pfn(struct kvm_vcpu *, pfn_t);

extern int kvm_read_guest_page(struct kvm *, gfn_t, void *, int, int);
extern int kvm_read_guest_atomic(struct kvm *, gpa_t, void *, unsigned long);
extern int kvm_read_guest(struct kvm *, gpa_t, void *, unsigned long);
extern int kvm_read_guest_virt_helper(gva_t, void *, unsigned int,
    struct kvm_vcpu *, uint32_t, uint32_t *);
extern int kvm_write_guest_page(struct kvm *, gfn_t, const void *, int, int);
extern int kvm_write_guest(struct kvm *, gpa_t, const void *, unsigned long);
extern int kvm_clear_guest_page(struct kvm *, gfn_t, int, int);
extern int kvm_clear_guest(struct kvm *, gpa_t, unsigned long);
extern struct kvm_memory_slot *gfn_to_memslot(struct kvm *, gfn_t);
extern int kvm_is_visible_gfn(struct kvm *, gfn_t);
extern unsigned long kvm_host_page_size(struct kvm *, gfn_t);
extern void mark_page_dirty(struct kvm *, gfn_t);

extern void kvm_vcpu_block(struct kvm_vcpu *);
extern void kvm_vcpu_on_spin(struct kvm_vcpu *);
extern void kvm_resched(struct kvm_vcpu *);
extern void kvm_load_guest_fpu(struct kvm_vcpu *);
extern void kvm_put_guest_fpu(struct kvm_vcpu *);
extern void kvm_flush_remote_tlbs(struct kvm *);
extern void kvm_reload_remote_mmus(struct kvm *);

extern long kvm_arch_dev_ioctl(struct file *, unsigned int, unsigned long);
extern long kvm_arch_vcpu_ioctl(struct file *, unsigned int, unsigned long);
extern int kvm_dev_ioctl_check_extension(long, int *);
extern int kvm_get_dirty_log(struct kvm *, struct kvm_dirty_log *, int *);
extern int kvm_vm_ioctl_get_dirty_log(struct kvm *, struct kvm_dirty_log *);

extern int kvm_vm_ioctl_get_msr_index_list(struct kvm *, uintptr_t);
extern int kvm_vm_ioctl_set_memory_region(struct kvm *,
    struct kvm_userspace_memory_region *, int);
extern int kvm_vm_ioctl_set_tss_addr(struct kvm *, uintptr_t);
extern int kvm_vm_ioctl_get_irqchip(struct kvm *, struct kvm_irqchip *);
extern int kvm_vm_ioctl_set_irqchip(struct kvm *, struct kvm_irqchip *);

extern int kvm_arch_vcpu_ioctl_get_fpu(struct kvm_vcpu *, struct kvm_fpu *);
extern int kvm_arch_vcpu_ioctl_set_fpu(struct kvm_vcpu *, struct kvm_fpu *);

extern int kvm_arch_vcpu_ioctl_get_regs(struct kvm_vcpu *, struct kvm_regs *);
extern int kvm_arch_vcpu_ioctl_set_regs(struct kvm_vcpu *, struct kvm_regs *);
extern int kvm_arch_vcpu_ioctl_get_sregs(struct kvm_vcpu *, struct kvm_sregs *);
extern int kvm_arch_vcpu_ioctl_set_sregs(struct kvm_vcpu *, struct kvm_sregs *);
extern int kvm_arch_vcpu_ioctl_get_mpstate(struct kvm_vcpu *,
    struct kvm_mp_state *);
extern int kvm_arch_vcpu_ioctl_set_mpstate(struct kvm_vcpu *,
    struct kvm_mp_state *);
extern int kvm_arch_vcpu_ioctl_set_guest_debug(struct kvm_vcpu *,
    struct kvm_guest_debug *);
extern int kvm_arch_vcpu_ioctl_run(struct kvm_vcpu *);

extern int kvm_vcpu_ioctl_get_msrs(struct kvm_vcpu *, struct kvm_msrs *, int *);
extern int kvm_vcpu_ioctl_set_msrs(struct kvm_vcpu *, struct kvm_msrs *, int *);
extern int kvm_vcpu_ioctl_x86_setup_mce(struct kvm_vcpu *, uint64_t *);
extern int kvm_vcpu_ioctl_get_cpuid2(struct kvm_vcpu *, struct kvm_cpuid2 *);
extern int kvm_vcpu_ioctl_set_cpuid2(struct kvm_vcpu *, struct kvm_cpuid2 *,
    int *, intptr_t);
extern int kvm_vcpu_ioctl_get_lapic(struct kvm_vcpu *,
    struct kvm_lapic_state *);
extern int kvm_vcpu_ioctl_set_lapic(struct kvm_vcpu *,
    struct kvm_lapic_state *);
extern int kvm_vcpu_ioctl_x86_get_vcpu_events(struct kvm_vcpu *,
    struct kvm_vcpu_events *);
extern int kvm_vcpu_ioctl_x86_set_vcpu_events(struct kvm_vcpu *,
    struct kvm_vcpu_events *);
extern int kvm_vcpu_ioctl_interrupt(struct kvm_vcpu *, struct kvm_interrupt *);
extern int kvm_vcpu_ioctl_nmi(struct kvm_vcpu *);
extern int kvm_vm_ioctl_get_pit2(struct kvm *, struct kvm_pit_state2 *);
extern int kvm_vm_ioctl_set_pit2(struct kvm *, struct kvm_pit_state2 *);
extern int kvm_vm_ioctl_set_identity_map_addr(struct kvm *, uint64_t);
extern int kvm_dev_ioctl_get_supported_cpuid(struct kvm_cpuid2 *,
    struct kvm_cpuid_entry2 *);

extern int kvm_arch_init(void *);
extern void kvm_arch_exit(void);

extern int kvm_arch_vcpu_init(struct kvm_vcpu *);
extern void kvm_arch_vcpu_uninit(struct kvm_vcpu *);

extern void kvm_arch_vcpu_free(struct kvm_vcpu *);
extern void kvm_arch_vcpu_load(struct kvm_vcpu *, int);
extern void kvm_arch_vcpu_put(struct kvm_vcpu *);
extern struct kvm_vcpu * kvm_arch_vcpu_create(struct kvm *, unsigned int);
extern int kvm_arch_vcpu_setup(struct kvm_vcpu *);
extern void kvm_arch_vcpu_destroy(struct kvm_vcpu *);

extern int kvm_arch_vcpu_reset(struct kvm_vcpu *);
extern int kvm_arch_hardware_setup(void);
extern void kvm_arch_hardware_unsetup(void);
extern void kvm_arch_check_processor_compat(void *);
extern int kvm_arch_vcpu_runnable(struct kvm_vcpu *);

extern void kvm_free_physmem(struct kvm *);

extern struct  kvm *kvm_arch_create_vm(void);
extern void kvm_arch_destroy_vm(struct kvm *);
extern void kvm_arch_destroy_vm_comps(struct kvm *);
extern void kvm_free_all_assigned_devices(struct kvm *);
extern void kvm_arch_sync_events(struct kvm *);

extern int kvm_cpu_has_pending_timer(struct kvm_vcpu *);
extern void kvm_vcpu_kick(struct kvm_vcpu *);

extern int kvm_is_mmio_pfn(pfn_t);

typedef struct kvm_irq_ack_notifier {
	list_t link;
	unsigned gsi;
	void (*irq_acked)(struct kvm_irq_ack_notifier *kian);
} kvm_irq_ack_notifier_t;

#define	KVM_ASSIGNED_MSIX_PENDING		0x1
typedef struct kvm_guest_msix_entry {
	uint32_t vector;
	unsigned short entry;
	unsigned short flags;
} kvm_guest_msix_entry_t;

typedef struct kvm_assigned_dev_kernel {
	struct kvm_irq_ack_notifier ack_notifier;
	list_t interrupt_work;
	list_t list;
	int assigned_dev_id;
	int host_segnr;
	int host_busnr;
	int host_devfn;
	unsigned int entries_nr;
	int host_irq;
	unsigned char host_irq_disabled;
	struct msix_entry *host_msix_entries;
	int guest_irq;
	struct kvm_guest_msix_entry *guest_msix_entries;
	unsigned long irq_requested_type;
	int irq_source_id;
	int flags;
	struct pci_dev *dev;
	struct kvm *kvm;
	kmutex_t assigned_dev_lock;
} kvm_assigned_dev_kernel_t;

typedef struct kvm_irq_mask_notifier {
	void (*func)(struct kvm_irq_mask_notifier *kimn, int masked);
	int irq;
	struct list_node link;
} kvm_irq_mask_notifier_t;

extern void kvm_register_irq_mask_notifier(struct kvm *, int,
    struct kvm_irq_mask_notifier *);
extern void kvm_unregister_irq_mask_notifier(struct kvm *, int,
    struct kvm_irq_mask_notifier *);
extern void kvm_fire_mask_notifiers(struct kvm *, int, int);

extern int kvm_set_irq(struct kvm *, int, uint32_t, int);
extern void kvm_notify_acked_irq(struct kvm *, unsigned, unsigned);
extern void kvm_register_irq_ack_notifier(struct kvm *,
    struct kvm_irq_ack_notifier *);
extern void kvm_unregister_irq_ack_notifier(struct kvm *,
    struct kvm_irq_ack_notifier *);
extern int kvm_request_irq_source_id(struct kvm *);
extern void kvm_free_irq_source_id(struct kvm *, int);

/* For vcpu->arch.iommu_flags */
#define	KVM_IOMMU_CACHE_COHERENCY	0x1

extern void kvm_guest_enter(struct kvm_vcpu *);
extern void kvm_guest_exit(struct kvm_vcpu *);

#ifndef KVM_ARCH_HAS_UNALIAS_INSTANTIATION
#define	unalias_gfn_instantiation unalias_gfn
#endif

extern int kvm_setup_default_irq_routing(struct kvm *);
extern int kvm_set_irq_routing(struct kvm *,
    const struct kvm_irq_routing_entry *,
    unsigned, unsigned);
extern void kvm_free_irq_routing(struct kvm *);

extern int kvm_vcpu_is_bsp(struct kvm_vcpu *);

extern void kvm_sigprocmask(int how, sigset_t *, sigset_t *);

#define	offset_in_page(p)	((unsigned long)(p) & ~PAGEMASK)

#define	page_to_pfn(page) (page->p_pagenum)

/* LDT or TSS descriptor in the GDT. 16 bytes. */
struct ldttss_desc64 {
	unsigned short limit0;
	unsigned short base0;
	unsigned base1 : 8, type : 5, dpl : 2, p : 1;
	unsigned limit1 : 4, zero0 : 3, g : 1, base2 : 8;
	uint32_t base3;
	uint32_t zero1;
} __attribute__((packed));

typedef struct ldttss_desc64 ldttss_desc64_t;

#endif /* __KVM_HOST_H */
