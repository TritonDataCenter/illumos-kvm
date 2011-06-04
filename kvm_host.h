/*
 * This work is licensed under the terms of the GNU GPL, version 2. See the
 * COPYING file in the top-level directory.
 */

#ifndef __KVM_HOST_H
#define __KVM_HOST_H

#include <sys/types.h>
#include <sys/list.h>
#include <sys/mutex.h>
#include <sys/sunddi.h>

#include "kvm_types.h"
#include "kvm_impl.h"
#include "kvm_x86host.h"

/*
 * XXX Do these really belong here?
 */
#define NSEC_PER_MSEC 1000000L
#define NSEC_PER_SEC 1000000000L

#define	BITS_PER_LONG	(sizeof (unsigned long) * 8)

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

/*
 * It would be nice to use something smarter than a linear search, TBD...
 * Thankfully we dont expect many devices to register (famous last words :),
 * so until then it will suffice.  At least its abstracted so we can change
 * in one place.
 */
typedef struct kvm_io_bus {
	int                   dev_count;
#define NR_IOBUS_DEVS 200
	struct kvm_io_device *devs[NR_IOBUS_DEVS];
} kvm_io_bus_t;

enum kvm_bus {
	KVM_MMIO_BUS,
	KVM_PIO_BUS,
	KVM_NR_BUSES
};

int kvm_io_bus_write(struct kvm *kvm, enum kvm_bus bus_idx, gpa_t addr,
		     int len, const void *val);
int kvm_io_bus_read(struct kvm *kvm, enum kvm_bus bus_idx, gpa_t addr, int len,
		    void *val);
int kvm_io_bus_register_dev(struct kvm *kvm, enum kvm_bus bus_idx,
			    struct kvm_io_device *dev);
int kvm_io_bus_unregister_dev(struct kvm *kvm, enum kvm_bus bus_idx,
			      struct kvm_io_device *dev);

#define KVM_MAX_IRQ_ROUTES 1024

typedef struct kvm_vcpu {
	struct kvm *kvm;
#ifdef CONFIG_PREEMPT_NOTIFIERS
	struct preempt_notifier preempt_notifier;
#endif
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

	int sigset_active;
	sigset_t sigset;

  /*#ifdef CONFIG_HAS_IOMEM*/
	int mmio_needed;
	int mmio_read_completed;
	int mmio_is_write;
	int mmio_size;
	unsigned char mmio_data[8];
	gpa_t mmio_phys_addr;
  /*#endif*/

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
       struct {
               unsigned long rmap_pde;
               int write_count;
       } *lpage_info[KVM_NR_PAGE_SIZES];
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
	struct as *mm; /* userspace tied to this vm */
	struct kvm_memslots *memslots;
	/* the following was a read-copy update mechanism */
	/* we'll use a reader-writer lock, for now */
	krwlock_t kvm_rwlock;
#ifdef CONFIG_KVM_APIC_ARCHITECTURE
	uint32_t bsp_vcpu_id;
	struct kvm_vcpu *bsp_vcpu;
#endif
	struct kvm_vcpu *vcpus[KVM_MAX_VCPUS];
	volatile int online_vcpus;
	struct list_node vm_list;
	kmutex_t lock;
	struct kvm_io_bus *buses[KVM_NR_BUSES];
#ifdef CONFIG_HAVE_KVM_EVENTFD
	struct {
		kmutex_t        lock;
		struct list_head  items;
	} irqfds;
	struct list_head ioeventfds;
#endif
	struct kstat *kvm_kstat;
	kvm_stats_t kvm_stats;
	struct kvm_arch arch;
	volatile int users_count;
#ifdef KVM_COALESCED_MMIO_PAGE_OFFSET
	struct kvm_coalesced_mmio_dev *coalesced_mmio_dev;
	struct kvm_coalesced_mmio_ring *coalesced_mmio_ring;
	ddi_umem_cookie_t mmio_cookie;
#endif

	kmutex_t irq_lock;
#ifdef CONFIG_HAVE_KVM_IRQCHIP
	struct kvm_irq_routing_table *irq_routing;
	list_t mask_notifier_list;
	list_t irq_ack_notifier_list;
#endif

#if defined(KVM_ARCH_WANT_MMU_NOTIFIER)  && defined(CONFIG_MMU_NOTIFIER)
	struct mmu_notifier mmu_notifier;
	unsigned long mmu_notifier_seq;
	long mmu_notifier_count;
#endif
	int kvmid;  /* unique identifier for this kvm */
	int kvm_clones;
	pid_t kvm_pid;			/* pid associated with this kvm */
	kmutex_t kvm_avllock;
	avl_tree_t kvm_avlmp;		/* avl tree for mmu to page_t mapping */
} kvm_t;


extern struct kvm_vcpu *kvm_get_vcpu(struct kvm *kvm, int i);

#define kvm_for_each_vcpu(idx, vcpup, kvm) \
	for (idx = 0, vcpup = kvm_get_vcpu(kvm, idx); \
	     idx < kvm->online_vcpus && vcpup; /* XXX - need protection */ \
	     vcpup = kvm_get_vcpu(kvm, ++idx))

int kvm_vcpu_init(struct kvm_vcpu *, struct kvm *, unsigned);
void kvm_vcpu_uninit(struct kvm_vcpu *vcpu);

void vcpu_load(struct kvm_vcpu *vcpu);
void vcpu_put(struct kvm_vcpu *vcpu);


int kvm_init(void *opaque, unsigned int vcpu_size);
void kvm_exit(void);

void kvm_get_kvm(struct kvm *kvm);
void kvm_put_kvm(struct kvm *kvm);

#define HPA_MSB ((sizeof(hpa_t) * 8) - 1)
#define HPA_ERR_MASK ((hpa_t)1 << HPA_MSB)
static int is_error_hpa(hpa_t hpa) { return hpa >> HPA_MSB; }

extern page_t *bad_page;
extern pfn_t bad_pfn;

int is_error_page(struct page *page);
int is_error_pfn(pfn_t pfn);
int kvm_is_error_hva(unsigned long addr);

int kvm_set_memory_region(struct kvm *kvm,
			  struct kvm_userspace_memory_region *mem,
			  int user_alloc);
int __kvm_set_memory_region(struct kvm *kvm,
			    struct kvm_userspace_memory_region *mem,
			    int user_alloc);
int kvm_arch_prepare_memory_region(struct kvm *kvm,
				struct kvm_memory_slot *memslot,
				struct kvm_memory_slot old,
				struct kvm_userspace_memory_region *mem,
				int user_alloc);
void kvm_arch_commit_memory_region(struct kvm *kvm,
				struct kvm_userspace_memory_region *mem,
				struct kvm_memory_slot old,
				int user_alloc);

void kvm_disable_largepages(void);
void kvm_arch_flush_shadow(struct kvm *kvm);
gfn_t unalias_gfn(struct kvm *kvm, gfn_t gfn);
gfn_t unalias_gfn_instantiation(struct kvm *kvm, gfn_t gfn);

page_t *gfn_to_page(struct kvm *kvm, gfn_t gfn);
unsigned long gfn_to_hva(struct kvm *kvm, gfn_t gfn);
void kvm_release_page_clean(struct page *page);
void kvm_release_page_dirty(struct page *page);
void kvm_set_page_dirty(struct page *page);
void kvm_set_page_accessed(struct page *page);

pfn_t gfn_to_pfn(struct kvm *kvm, gfn_t gfn);
pfn_t gfn_to_pfn_memslot(struct kvm *kvm,
			 struct kvm_memory_slot *slot, gfn_t gfn);
int memslot_id(struct kvm *kvm, gfn_t gfn);
void kvm_release_pfn_dirty(pfn_t);
void kvm_release_pfn_clean(pfn_t);
void kvm_set_pfn_dirty(pfn_t);
void kvm_set_pfn_accessed(struct kvm *, pfn_t);
void kvm_get_pfn(struct kvm_vcpu *vcpu, pfn_t pfn);

int kvm_read_guest_page(struct kvm *kvm, gfn_t gfn, void *data, int offset,
			int len);
int kvm_read_guest_atomic(struct kvm *kvm, gpa_t gpa, void *data,
			  unsigned long len);
int kvm_read_guest(struct kvm *kvm, gpa_t gpa, void *data, unsigned long len);
int kvm_write_guest_page(struct kvm *kvm, gfn_t gfn, const void *data,
			 int offset, int len);
int kvm_write_guest(struct kvm *kvm, gpa_t gpa, const void *data,
		    unsigned long len);
int kvm_clear_guest_page(struct kvm *kvm, gfn_t gfn, int offset, int len);
int kvm_clear_guest(struct kvm *kvm, gpa_t gpa, unsigned long len);
struct kvm_memory_slot *gfn_to_memslot(struct kvm *kvm, gfn_t gfn);
int kvm_is_visible_gfn(struct kvm *kvm, gfn_t gfn);
unsigned long kvm_host_page_size(struct kvm *kvm, gfn_t gfn);
void mark_page_dirty(struct kvm *kvm, gfn_t gfn);

void kvm_vcpu_block(struct kvm_vcpu *vcpu);
void kvm_vcpu_on_spin(struct kvm_vcpu *vcpu);
void kvm_resched(struct kvm_vcpu *vcpu);
void kvm_load_guest_fpu(struct kvm_vcpu *vcpu);
void kvm_put_guest_fpu(struct kvm_vcpu *vcpu);
void kvm_flush_remote_tlbs(struct kvm *kvm);
void kvm_reload_remote_mmus(struct kvm *kvm);

long kvm_arch_dev_ioctl(struct file *filp,
			unsigned int ioctl, unsigned long arg);
long kvm_arch_vcpu_ioctl(struct file *filp,
			 unsigned int ioctl, unsigned long arg);
extern int kvm_dev_ioctl_check_extension(long ext, int *rv);
int kvm_get_dirty_log(struct kvm *kvm,
			struct kvm_dirty_log *log, int *is_dirty);
int kvm_vm_ioctl_get_dirty_log(struct kvm *kvm,
				struct kvm_dirty_log *log);

int kvm_vm_ioctl_set_memory_region(struct kvm *kvm,
				   struct
				   kvm_userspace_memory_region *mem,
				   int user_alloc);
long kvm_arch_vm_ioctl(struct file *filp,
		       unsigned int ioctl, unsigned long arg);

int kvm_arch_vcpu_ioctl_get_fpu(struct kvm_vcpu *vcpu, struct kvm_fpu *fpu);
int kvm_arch_vcpu_ioctl_set_fpu(struct kvm_vcpu *vcpu, struct kvm_fpu *fpu);

int kvm_arch_vcpu_ioctl_get_regs(struct kvm_vcpu *vcpu, struct kvm_regs *regs);
int kvm_arch_vcpu_ioctl_set_regs(struct kvm_vcpu *vcpu, struct kvm_regs *regs);
int kvm_arch_vcpu_ioctl_get_sregs(struct kvm_vcpu *vcpu,
				  struct kvm_sregs *sregs);
int kvm_arch_vcpu_ioctl_set_sregs(struct kvm_vcpu *vcpu,
				  struct kvm_sregs *sregs);
int kvm_arch_vcpu_ioctl_get_mpstate(struct kvm_vcpu *vcpu,
				    struct kvm_mp_state *mp_state);
int kvm_arch_vcpu_ioctl_set_mpstate(struct kvm_vcpu *vcpu,
				    struct kvm_mp_state *mp_state);
int kvm_arch_vcpu_ioctl_set_guest_debug(struct kvm_vcpu *vcpu,
					struct kvm_guest_debug *dbg);
int kvm_arch_vcpu_ioctl_run(struct kvm_vcpu *vcpu);

int kvm_arch_init(void *opaque);
void kvm_arch_exit(void);

int kvm_arch_vcpu_init(struct kvm_vcpu *vcpu);
void kvm_arch_vcpu_uninit(struct kvm_vcpu *vcpu);

void kvm_arch_vcpu_free(struct kvm_vcpu *vcpu);
void kvm_arch_vcpu_load(struct kvm_vcpu *vcpu, int cpu);
void kvm_arch_vcpu_put(struct kvm_vcpu *vcpu);
int kvm_arch_vcpu_setup(struct kvm_vcpu *vcpu);
void kvm_arch_vcpu_destroy(struct kvm_vcpu *vcpu);

int kvm_arch_vcpu_reset(struct kvm_vcpu *vcpu);
int kvm_arch_hardware_enable(void *garbage);
void kvm_arch_hardware_disable(void *garbage);
int kvm_arch_hardware_setup(void);
void kvm_arch_hardware_unsetup(void);
void kvm_arch_check_processor_compat(void *rtn);
int kvm_arch_vcpu_runnable(struct kvm_vcpu *vcpu);

void kvm_free_physmem(struct kvm *kvm);

struct  kvm *kvm_arch_create_vm(void);
void kvm_arch_destroy_vm(struct kvm *kvm);
void kvm_arch_destroy_vm_comps(struct kvm *kvm);
void kvm_free_all_assigned_devices(struct kvm *kvm);
void kvm_arch_sync_events(struct kvm *kvm);

int kvm_cpu_has_pending_timer(struct kvm_vcpu *vcpu);
void kvm_vcpu_kick(struct kvm_vcpu *vcpu);

extern int kvm_is_mmio_pfn(pfn_t pfn);

typedef struct kvm_irq_ack_notifier {
	list_t link;
	unsigned gsi;
	void (*irq_acked)(struct kvm_irq_ack_notifier *kian);
} kvm_irq_ack_notifier_t;

#define KVM_ASSIGNED_MSIX_PENDING		0x1
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

void kvm_register_irq_mask_notifier(struct kvm *kvm, int irq,
				    struct kvm_irq_mask_notifier *kimn);
void kvm_unregister_irq_mask_notifier(struct kvm *kvm, int irq,
				      struct kvm_irq_mask_notifier *kimn);
void kvm_fire_mask_notifiers(struct kvm *kvm, int irq, int mask);

int kvm_set_irq(struct kvm *kvm, int irq_source_id, uint32_t irq, int level);
void kvm_notify_acked_irq(struct kvm *kvm, unsigned irqchip, unsigned pin);
void kvm_register_irq_ack_notifier(struct kvm *kvm,
				   struct kvm_irq_ack_notifier *kian);
void kvm_unregister_irq_ack_notifier(struct kvm *kvm,
				   struct kvm_irq_ack_notifier *kian);
int kvm_request_irq_source_id(struct kvm *kvm);
void kvm_free_irq_source_id(struct kvm *kvm, int irq_source_id);

/* For vcpu->arch.iommu_flags */
#define KVM_IOMMU_CACHE_COHERENCY	0x1

int kvm_iommu_map_pages(struct kvm *kvm, struct kvm_memory_slot *slot);
int kvm_iommu_map_guest(struct kvm *kvm);
int kvm_iommu_unmap_guest(struct kvm *kvm);
int kvm_assign_device(struct kvm *kvm,
		      struct kvm_assigned_dev_kernel *assigned_dev);
int kvm_deassign_device(struct kvm *kvm,
			struct kvm_assigned_dev_kernel *assigned_dev);

void kvm_guest_enter(void);
void kvm_guest_exit(void);
void kvm_migrate_timers(struct kvm_vcpu *vcpu);

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

#ifndef KVM_ARCH_HAS_UNALIAS_INSTANTIATION
#define unalias_gfn_instantiation unalias_gfn
#endif

#ifdef CONFIG_HAVE_KVM_IRQCHIP

int kvm_setup_default_irq_routing(struct kvm *kvm);
int kvm_set_irq_routing(struct kvm *kvm,
			const struct kvm_irq_routing_entry *entries,
			unsigned nr,
			unsigned flags);
void kvm_free_irq_routing(struct kvm *kvm);

#else

static void kvm_free_irq_routing(struct kvm *kvm) {}

#endif /*CONFIG_HAVE_KVM_IRQCHIP*/

#ifdef	CONFIG_KVM_APIC_ARCHITECTURE
extern int kvm_vcpu_is_bsp(struct kvm_vcpu *);
#endif

void kvm_sigprocmask(int how, sigset_t *, sigset_t *);

/*
 * XXX Is this really necessary? There really isn't another way to do it?
 */
#define offset_in_page(p)	((unsigned long)(p) & ~PAGEMASK)

/* borrowed liberally from linux... */

#define MAX_IO_MSRS 256
#define CR0_RESERVED_BITS						\
	(~(unsigned long)(X86_CR0_PE | X86_CR0_MP | X86_CR0_EM | X86_CR0_TS \
			  | X86_CR0_ET | X86_CR0_NE | X86_CR0_WP | X86_CR0_AM \
			  | X86_CR0_NW | X86_CR0_CD | X86_CR0_PG))
#define CR4_RESERVED_BITS						\
	(~(unsigned long)(X86_CR4_VME | X86_CR4_PVI | X86_CR4_TSD | X86_CR4_DE\
			  | X86_CR4_PSE | X86_CR4_PAE | X86_CR4_MCE	\
			  | X86_CR4_PGE | X86_CR4_PCE | X86_CR4_OSFXSR	\
			  | X86_CR4_OSXMMEXCPT | X86_CR4_VMXE))

#define CR8_RESERVED_BITS (~(unsigned long)X86_CR8_TPR)

#define MCG_CTL_P		(1ULL<<8)    /* MCG_CTL register available */
#define KVM_MAX_MCE_BANKS 32
#define KVM_MCE_CAP_SUPPORTED MCG_CTL_P
#define page_to_pfn(page) (page->p_pagenum)


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
