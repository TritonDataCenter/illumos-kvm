#ifndef SOLARIS_KVM_H
#define SOLARIS_KVM_H

#include <sys/list.h>
#include <sys/types.h>
#include <sys/kstat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sdt.h>
#include <sys/avl.h>
#undef _ASM  /* cyclic.h expects this not defined */
#include <sys/cyclic.h>
#define _ASM
#include <sys/atomic.h>
#include "kvm_types.h"

#define XXX_KVM_PROBE DTRACE_PROBE2(kvm__xxx, \
	char *, __FILE__, int, __LINE__)
#define XXX_KVM_SYNC_PROBE DTRACE_PROBE2(kvm__xxx__sync, \
	char *, __FILE__, int, __LINE__)

#define KVM_CPUALL -1
typedef void (*kvm_xcall_t)(void *);

#ifdef _KERNEL
#include "bitops.h"
#ifdef CONFIG_MMU_NOTIFIER
#include "mmu_notifier.h"
#endif /*CONFIG_MMU_NOTIFIER*/
#endif /*_KERNEL*/

#define KVM_API_VERSION 12   /* same as linux (for qemu compatability...) */

#ifndef offsetof
#define offsetof(s, m) ((size_t)(&((s *)0)->m))
#endif

#define offset_in_page(p)	((unsigned long)(p) & ~PAGEMASK)

#define PT_WRITABLE_SHIFT 1
#define PT_PRESENT_MASK (1ULL << 0)
#define PT64_BASE_ADDR_MASK (((1ULL << 52) - 1) & ~(uint64_t)(PAGESIZE-1))
#define PT_WRITABLE_MASK (1ULL << PT_WRITABLE_SHIFT)
#define PT_USER_MASK (1ULL << 2)
#define ACC_EXEC_MASK    1
#define ACC_WRITE_MASK   PT_WRITABLE_MASK
#define ACC_USER_MASK    PT_USER_MASK
#define ACC_ALL          (ACC_EXEC_MASK | ACC_WRITE_MASK | ACC_USER_MASK)

#define PT64_PT_BITS 9
#define PT64_ENT_PER_PAGE (1 << PT64_PT_BITS)
#define PT32_PT_BITS 10
#define PT32_ENT_PER_PAGE (1 << PT32_PT_BITS)

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

#define KVM_MAX_VCPUS 64

#ifdef _KERNEL
#define MCG_CTL_P		(1ULL<<8)    /* MCG_CTL register available */
#endif /*_KERNEL*/

#define KVM_MAX_MCE_BANKS 32
#define KVM_MCE_CAP_SUPPORTED MCG_CTL_P

#define KVM_GUEST_CR0_MASK_UNRESTRICTED_GUEST				\
	(X86_CR0_WP | X86_CR0_NE | X86_CR0_NW | X86_CR0_CD)
#define KVM_GUEST_CR0_MASK						\
	(KVM_GUEST_CR0_MASK_UNRESTRICTED_GUEST | X86_CR0_PG | X86_CR0_PE)
#define KVM_VM_CR0_ALWAYS_ON_UNRESTRICTED_GUEST				\
	(X86_CR0_WP | X86_CR0_NE)
#define KVM_VM_CR0_ALWAYS_ON						\
	(KVM_VM_CR0_ALWAYS_ON_UNRESTRICTED_GUEST | X86_CR0_PG | X86_CR0_PE)
#define KVM_CR4_GUEST_OWNED_BITS				      \
	(X86_CR4_PVI | X86_CR4_DE | X86_CR4_PCE | X86_CR4_OSFXSR      \
	 | X86_CR4_OSXMMEXCPT)

#define KVM_PMODE_VM_CR4_ALWAYS_ON (X86_CR4_PAE | X86_CR4_VMXE)
#define KVM_RMODE_VM_CR4_ALWAYS_ON (X86_CR4_VME | X86_CR4_PAE | X86_CR4_VMXE)

#define RMODE_GUEST_OWNED_EFLAGS_BITS (~(X86_EFLAGS_IOPL | X86_EFLAGS_VM))

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
#define KVM_VMX_DEFAULT_PLE_GAP    41
#define KVM_VMX_DEFAULT_PLE_WINDOW 4096


#ifdef __ASSEMBLY__
# define __IA64_UL(x)		(x)
# define __IA64_UL_CONST(x)	x

#else
# define __IA64_UL(x)		((unsigned long)(x))
# define __IA64_UL_CONST(x)	x##UL
#endif

/*
 * This must match KVM_IA64_VCPU_STACK_{SHIFT,SIZE} arch/ia64/include/asm/kvm.h
 */
#define KVM_STK_SHIFT		16
#define KVM_STK_OFFSET		(__IA64_UL_CONST(1)<< KVM_STK_SHIFT)

#define KVM_VM_STRUCT_SHIFT	19
#define KVM_VM_STRUCT_SIZE	(__IA64_UL_CONST(1) << KVM_VM_STRUCT_SHIFT)

#define KVM_MEM_DIRY_LOG_SHIFT	19
#define KVM_MEM_DIRTY_LOG_SIZE (__IA64_UL_CONST(1) << KVM_MEM_DIRY_LOG_SHIFT)


#define KVM_VM_BUFFER_BASE (KVM_VMM_BASE + VMM_SIZE)
#define KVM_VM_BUFFER_SIZE (__IA64_UL_CONST(8)<<20)

/*
 * kvm guest's data area looks as follow:
 *
 *            +----------------------+	-------	KVM_VM_DATA_SIZE
 *	      |	    vcpu[n]'s data   |	 |     ___________________KVM_STK_OFFSET
 *     	      |			     |	 |    /			  |
 *     	      |	       ..........    |	 |   /vcpu's struct&stack |
 *     	      |	       ..........    |	 |  /---------------------|---- 0
 *	      |	    vcpu[5]'s data   |	 | /	   vpd		  |
 *	      |	    vcpu[4]'s data   |	 |/-----------------------|
 *	      |	    vcpu[3]'s data   |	 /	   vtlb		  |
 *	      |	    vcpu[2]'s data   |	/|------------------------|
 *	      |	    vcpu[1]'s data   |/  |	   vhpt		  |
 *	      |	    vcpu[0]'s data   |____________________________|
 *            +----------------------+	 |
 *	      |	   memory dirty log  |	 |
 *            +----------------------+	 |
 *	      |	   vm's data struct  |	 |
 *            +----------------------+	 |
 *	      |			     |	 |
 *	      |			     |	 |
 *	      |			     |	 |
 *	      |			     |	 |
 *	      |			     |	 |
 *	      |			     |	 |
 *	      |			     |	 |
 *	      |	  vm's p2m table  |	 |
 *	      |			     |	 |
 *            |			     |	 |
 *	      |			     |	 |  |
 * vm's data->|			     |   |  |
 *	      +----------------------+ ------- 0
 * To support large memory, needs to increase the size of p2m.
 * To support more vcpus, needs to ensure it has enough space to
 * hold vcpus' data.
 */

#define KVM_VM_DATA_SHIFT	26
#define KVM_VM_DATA_SIZE	(__IA64_UL_CONST(1) << KVM_VM_DATA_SHIFT)
#define KVM_VM_DATA_BASE	(KVM_VMM_BASE + KVM_VM_DATA_SIZE)

#define KVM_P2M_BASE		KVM_VM_DATA_BASE
#define KVM_P2M_SIZE		(__IA64_UL_CONST(24) << 20)

/*Define the max vcpus and memory for Guests.*/
#define KVM_MAX_MEM_SIZE (KVM_P2M_SIZE >> 3 << PAGESHIFT)

#define VMM_LOG_LEN 256

#define VHPT_SHIFT		16
#define VHPT_SIZE		(__IA64_UL_CONST(1) << VHPT_SHIFT)
#define VHPT_NUM_ENTRIES	(__IA64_UL_CONST(1) << (VHPT_SHIFT-5))

#define VTLB_SHIFT		16
#define VTLB_SIZE		(__IA64_UL_CONST(1) << VTLB_SHIFT)
#define VTLB_NUM_ENTRIES	(1UL << (VHPT_SHIFT-5))

#define VPD_SHIFT		16
#define VPD_SIZE		(__IA64_UL_CONST(1) << VPD_SHIFT)

#define VCPU_STRUCT_SHIFT	16
#define VCPU_STRUCT_SIZE	(__IA64_UL_CONST(1) << VCPU_STRUCT_SHIFT)

#define KVM_NR_PAGE_SIZES	3  /* XXX assumes x86 */

#ifdef _KERNEL
typedef struct kvm_vcpu_data {
	char vcpu_vhpt[VHPT_SIZE];
	char vcpu_vtlb[VTLB_SIZE];
	char vcpu_vpd[VPD_SIZE];
	char vcpu_struct[VCPU_STRUCT_SIZE];
} kvm_vcpu_data_t;

typedef struct kvm_vm_data {
	char kvm_p2m[KVM_P2M_SIZE];
	char kvm_vm_struct[KVM_VM_STRUCT_SIZE];
	char kvm_mem_dirty_log[KVM_MEM_DIRTY_LOG_SIZE];
	struct kvm_vcpu_data vcpu_data[KVM_MAX_VCPUS];
} kvm_vm_data_t;

/*
 * We don't want allocation failures within the mmu code, so we preallocate
 * enough memory for a single page fault in a cache.
 */


#define KVM_NR_DB_REGS	4

/*
 * fxsave fpu state.  Taken from x86_64/processor.h.  To be killed when
 * we have asm/x86/processor.h
 */
typedef struct fxsave {
	uint16_t	cwd;
	uint16_t	swd;
	uint16_t	twd;
	uint16_t	fop;
	uint64_t	rip;
	uint64_t	rdp;
	uint32_t	mxcsr;
	uint32_t	mxcsr_mask;
	uint32_t	st_space[32];	/* 8*16 bytes for each FP-reg = 128 bytes */
#ifdef CONFIG_X86_64
	uint32_t	xmm_space[64];	/* 16*16 bytes for each XMM-reg = 256 bytes */
#else
	uint32_t	xmm_space[32];	/* 8*16 bytes for each XMM-reg = 128 bytes */
#endif
} fxsave_t;

#endif /*_KERNEL*/

#define KVM_MAX_CPUID_ENTRIES 40

#define KVM_POSSIBLE_CR0_GUEST_BITS X86_CR0_TS
#define KVM_POSSIBLE_CR4_GUEST_BITS				  \
	(X86_CR4_PVI | X86_CR4_DE | X86_CR4_PCE | X86_CR4_OSFXSR  \
	 | X86_CR4_OSXMMEXCPT | X86_CR4_PGE)


#ifndef CONFIG_X86_64
#define mod_64(x, y) ((x) - (y) * div64_u64(x, y))
#else
#define mod_64(x, y) ((x) % (y))
#endif

#ifdef _KERNEL
#include "kvm_emulate.h"


#endif /*_KERNEL*/

#define	APIC_LDR	0xD0

#define APIC_LVT_NUM			6
/* 14 is the version for Xeon and Pentium 8.4.8*/
#define APIC_VERSION			(0x14UL | ((APIC_LVT_NUM - 1) << 16))
#define LAPIC_MMIO_LENGTH		(1 << 12)
/* followed define is not in apicdef.h */
#define APIC_SHORT_MASK			0xc0000
#define APIC_DEST_NOSHORT		0x0
#define APIC_DEST_MASK			0x800
#define MAX_APIC_VECTOR			256

#define KVM_IOAPIC_NUM_PINS  24

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))
#endif /*ARRAY_SIZE*/

#define LVT_MASK	\
	(APIC_LVT_MASKED | APIC_SEND_PENDING | APIC_VECTOR_MASK)

#define LINT_MASK	\
	(LVT_MASK | APIC_MODE_MASK | APIC_INPUT_POLARITY | \
	 APIC_LVT_REMOTE_IRR | APIC_LVT_LEVEL_TRIGGER)

#ifdef _KERNEL

typedef struct kvm_timer {
#ifdef XXX
	struct hrtimer timer;
#else
	cyclic_id_t kvm_cyclic_id;
	cyc_handler_t kvm_cyc_handler;
	cyc_time_t kvm_cyc_when;
	int active;
	int intervals;
	hrtime_t start;
#endif /*XXX*/
	int64_t period; 				/* unit: ns */
	int pending;			/* accumulated triggered timers */
	int reinject;
	struct kvm_timer_ops *t_ops;
	struct kvm *kvm;
	struct kvm_vcpu *vcpu;
} kvm_timer_t;

typedef struct kvm_timer_ops {
        int (*is_periodic)(struct kvm_timer *);
} kvm_timer_ops_t;

typedef struct kvm_lapic {
	unsigned long base_address;
	struct kvm_io_device dev;
	struct kvm_timer lapic_timer;
	uint32_t divide_count;
	struct kvm_vcpu *vcpu;
	int irr_pending;
	void *regs;
	gpa_t vapic_addr;
	page_t *vapic_page;
} kvm_lapic_t;

struct vcpu_vmx;
struct kvm_user_return_notifier;

typedef struct kvm_vcpu_stats {
	kstat_named_t kvmvs_id;			/* instance of associated kvm */
	kstat_named_t kvmvs_nmi_injections;	/* number of NMI injections */
	kstat_named_t kvmvs_irq_injections;	/* number of IRQ injections */
	kstat_named_t kvmvs_fpu_reload;		/* number of FPU reloads */
	kstat_named_t kvmvs_host_state_reload;	/* host state (re)loads */
	kstat_named_t kvmvs_insn_emulation;	/* instruction emulation */
	kstat_named_t kvmvs_insn_emulation_fail; /* emulation failures */
	kstat_named_t kvmvs_exits; 		/* total VM exits */
	kstat_named_t kvmvs_halt_exits; 	/* exits due to HLT */
	kstat_named_t kvmvs_irq_exits; 		/* exits due to IRQ */
	kstat_named_t kvmvs_io_exits; 		/* exits due to I/O instrn */
	kstat_named_t kvmvs_mmio_exits; 	/* exits due to mem mppd I/O */
	kstat_named_t kvmvs_nmi_window_exits; 	/* exits due to NMI window */
	kstat_named_t kvmvs_irq_window_exits; 	/* exits due to IRQ window */
	kstat_named_t kvmvs_request_irq_exits; 	/* exits due to requested IRQ */
	kstat_named_t kvmvs_signal_exits; 	/* exits due to pending sig */
	kstat_named_t kvmvs_halt_wakeup; 	/* wakeups from HLT */
	kstat_named_t kvmvs_invlpg; 		/* INVLPG instructions */
	kstat_named_t kvmvs_pf_guest;		/* injected guest pagefaults */
	kstat_named_t kvmvs_pf_fixed; 		/* fixed pagefaults */
	kstat_named_t kvmvs_hypercalls; 	/* hypercalls (VMCALL instrn) */
} kvm_vcpu_stats_t;

#define KVM_VCPU_KSTAT_INIT(vcpu, field, name) \
	kstat_named_init(&((vcpu)->kvcpu_stats.field), name, KSTAT_DATA_UINT64);

#define KVM_VCPU_KSTAT_INC(vcpu, field) \
	(vcpu)->kvcpu_stats.field.value.ui64++;

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

#define KVM_NR_SHARED_MSRS 16

typedef struct kvm_shared_msrs_global {
	int nr;
	uint32_t msrs[KVM_NR_SHARED_MSRS];
} kvm_shared_msrs_global_t;

typedef struct kvm_user_return_notifier {
	void (*on_user_return)(struct kvm_vcpu *,
	    struct kvm_user_return_notifier *);
} kvm_user_return_notifier_t;

typedef struct kvm_shared_msrs {
	struct kvm_user_return_notifier urn;
	int registered;
	struct kvm_shared_msr_values {
		uint64_t host;
		uint64_t curr;
	} values[KVM_NR_SHARED_MSRS];
} kvm_shared_msrs_t;

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


typedef struct kvm_memslots {
	int nmemslots;
	struct kvm_memory_slot memslots[KVM_MEMORY_SLOTS +
					KVM_PRIVATE_MEM_SLOTS];
} kvm_memslots_t;

#endif /*_KERNEL*/

#ifdef x86


#define KVM_ALIAS_SLOTS 4

#define KVM_HPAGE_SHIFT(x)	(PAGESHIFT + (((x) - 1) * 9))
#define KVM_HPAGE_MASK(x)	(~(KVM_HPAGE_SIZE(x) - 1))
#define KVM_PAGES_PER_HPAGE(x)	(KVM_HPAGE_SIZE(x) / PAGESIZE)

#define DE_VECTOR 0
#define DB_VECTOR 1
#define BP_VECTOR 3
#define OF_VECTOR 4
#define BR_VECTOR 5
#define UD_VECTOR 6
#define NM_VECTOR 7
#define DF_VECTOR 8
#define TS_VECTOR 10
#define NP_VECTOR 11
#define SS_VECTOR 12
#define GP_VECTOR 13
#define PF_VECTOR 14
#define MF_VECTOR 16
#define MC_VECTOR 18

#define SELECTOR_TI_MASK (1 << 2)
#define SELECTOR_RPL_MASK 0x03

#define IOPL_SHIFT 12

#define KVM_ALIAS_SLOTS 4

#define KVM_PERMILLE_MMU_PAGES 20
#define KVM_MIN_ALLOC_MMU_PAGES 64
#define KVM_MMU_HASH_SHIFT 10
#define KVM_NUM_MMU_PAGES (1 << KVM_MMU_HASH_SHIFT)
#define KVM_MIN_FREE_MMU_PAGES 5
#define KVM_REFILL_PAGES 25

#define KVM_NR_FIXED_MTRR_REGION 88
#define KVM_NR_VAR_MTRR 8

#ifdef _KERNEL
extern kmutex_t kvm_lock;
extern list_t vm_list;
#endif /*_KERNEL*/

#define KVM_USERSPACE_IRQ_SOURCE_ID	0

/*
 * Extension capability list.
 */
#define KVM_CAP_IRQCHIP	  0
#define KVM_CAP_HLT	  1
#define KVM_CAP_MMU_SHADOW_CACHE_CONTROL 2
#define KVM_CAP_USER_MEMORY 3
#define KVM_CAP_SET_TSS_ADDR 4
#define KVM_CAP_VAPIC 6
#define KVM_CAP_EXT_CPUID 7
#define KVM_CAP_CLOCKSOURCE 8
#define KVM_CAP_NR_VCPUS 9       /* returns max vcpus per vm */
#define KVM_CAP_NR_MEMSLOTS 10   /* returns max memory slots per vm */
#define KVM_CAP_PIT 11
#define KVM_CAP_NOP_IO_DELAY 12
#define KVM_CAP_PV_MMU 13
#define KVM_CAP_MP_STATE 14
#define KVM_CAP_COALESCED_MMIO 15
#define KVM_CAP_SYNC_MMU 16  /* Changes to host mmap are reflected in guest */
#ifdef __KVM_HAVE_DEVICE_ASSIGNMENT
#define KVM_CAP_DEVICE_ASSIGNMENT 17
#endif
#define KVM_CAP_IOMMU 18

/* For vcpu->arch.iommu_flags */
#define KVM_IOMMU_CACHE_COHERENCY	0x1

#ifdef __KVM_HAVE_MSI
#define KVM_CAP_DEVICE_MSI 20
#endif
/* Bug in KVM_SET_USER_MEMORY_REGION fixed: */
#define KVM_CAP_DESTROY_MEMORY_REGION_WORKS 21
#ifdef __KVM_HAVE_USER_NMI
#define KVM_CAP_USER_NMI 22
#endif
#ifdef __KVM_HAVE_GUEST_DEBUG
#define KVM_CAP_SET_GUEST_DEBUG 23
#endif
#define KVM_CAP_REINJECT_CONTROL 24
#ifdef __KVM_HAVE_IOAPIC
#define KVM_CAP_IRQ_ROUTING 25
#endif
#define KVM_CAP_IRQ_INJECT_STATUS 26
#ifdef __KVM_HAVE_DEVICE_ASSIGNMENT
#define KVM_CAP_DEVICE_DEASSIGNMENT 27
#endif
#ifdef __KVM_HAVE_MSIX
#define KVM_CAP_DEVICE_MSIX 28
#endif
#define KVM_CAP_ASSIGN_DEV_IRQ 29
/* Another bug in KVM_SET_USER_MEMORY_REGION fixed: */
#define KVM_CAP_JOIN_MEMORY_REGIONS_WORKS 30
#define KVM_CAP_MCE 31
#define KVM_CAP_IRQFD 32
#define KVM_CAP_PIT2 33
#define KVM_CAP_SET_BOOT_CPU_ID 34
#define KVM_CAP_PIT_STATE2 35
#define KVM_CAP_IOEVENTFD 36
#define KVM_CAP_SET_IDENTITY_MAP_ADDR 37
#define KVM_CAP_XEN_HVM 38
#define KVM_CAP_ADJUST_CLOCK 39
#define KVM_CAP_INTERNAL_ERROR_DATA 40
#define KVM_CAP_VCPU_EVENTS 41
#define KVM_CAP_S390_PSW 42
#define KVM_CAP_PPC_SEGSTATE 43
#define KVM_CAP_HYPERV 44
#define KVM_CAP_HYPERV_VAPIC 45
#define KVM_CAP_HYPERV_SPIN 46
#define KVM_CAP_PCI_SEGMENT 47
#define KVM_CAP_X86_ROBUST_SINGLESTEP 51

#define KVM_IRQCHIP_PIC_MASTER   0
#define KVM_IRQCHIP_PIC_SLAVE    1
#define KVM_IRQCHIP_IOAPIC       2
#define KVM_NR_IRQCHIPS          3

/* for KVM_GET_IRQCHIP and KVM_SET_IRQCHIP */
typedef struct kvm_pic_state {
	uint8_t last_irr;	/* edge detection */
	uint8_t irr;		/* interrupt request register */
	uint8_t imr;		/* interrupt mask register */
	uint8_t isr;		/* interrupt service register */
	uint8_t priority_add;	/* highest irq priority */
	uint8_t irq_base;
	uint8_t read_reg_select;
	uint8_t poll;
	uint8_t special_mask;
	uint8_t init_state;
	uint8_t auto_eoi;
	uint8_t rotate_on_auto_eoi;
	uint8_t special_fully_nested_mode;
	uint8_t init4;		/* true if 4 byte init */
	uint8_t elcr;		/* PIIX edge/trigger selection */
	uint8_t elcr_mask;
} kvm_pic_state_t;

#define KVM_IOAPIC_NUM_PINS  24
typedef struct kvm_ioapic_state {
	uint64_t base_address;
	uint32_t ioregsel;
	uint32_t id;
	uint32_t irr;
	uint32_t pad;
	union {
		uint64_t bits;
		struct {
			uint8_t vector;
			uint8_t delivery_mode:3;
			uint8_t dest_mode:1;
			uint8_t delivery_status:1;
			uint8_t polarity:1;
			uint8_t remote_irr:1;
			uint8_t trig_mode:1;
			uint8_t mask:1;
			uint8_t reserve:7;
			uint8_t reserved[4];
			uint8_t dest_id;
		} fields;
	} redirtbl[KVM_IOAPIC_NUM_PINS];
} kvm_ioapic_state_t;

typedef struct kvm_irqchip {
	uint32_t chip_id;
	uint32_t pad;
        union {
		char dummy[512];  /* reserving space */
		struct kvm_pic_state pic;
		struct kvm_ioapic_state ioapic;
	} chip;
} kvm_irqchip_t;

/* for KVM_CREATE_PIT2 */
typedef struct kvm_pit_config {
	uint32_t flags;
	uint32_t pad[15];
} kvm_pit_config_t;

/* for KVM_GET_REGS and KVM_SET_REGS */
typedef struct kvm_regs {
	/* out (KVM_GET_REGS) / in (KVM_SET_REGS) */
        uint64_t rax, rbx, rcx, rdx;
	uint64_t rsi, rdi, rsp, rbp;
	uint64_t r8,  r9,  r10, r11;
	uint64_t r12, r13, r14, r15;
	uint64_t rip, rflags;
} kvm_regs_t;

typedef struct kvm_mp_state {
	uint32_t mp_state;
} kvm_mp_state_t;

/* for KVM_GET_LAPIC and KVM_SET_LAPIC */
#define KVM_APIC_REG_SIZE 0x400
typedef struct kvm_lapic_state {
	char regs[KVM_APIC_REG_SIZE];
} kvm_lapic_state_t;

typedef struct kvm_dtable {
	uint64_t base;
	unsigned short limit;
	unsigned short padding[3];
} kvm_dtable_t;

/* Architectural interrupt line count. */
#define KVM_NR_INTERRUPTS 256


typedef struct kvm_vmx_segment_field {
	unsigned selector;
	unsigned base;
	unsigned limit;
	unsigned ar_bytes;
} kvm_vmx_segment_field_t;

/* for KVM_GET_SREGS and KVM_SET_SREGS */
typedef struct kvm_sregs {
	/* out (KVM_GET_SREGS) / in (KVM_SET_SREGS) */
	struct kvm_segment cs, ds, es, fs, gs, ss;
	struct kvm_segment tr, ldt;
	struct kvm_dtable gdt, idt;
	uint64_t cr0, cr2, cr3, cr4, cr8;
	uint64_t efer;
	uint64_t apic_base;
	unsigned long interrupt_bitmap[(KVM_NR_INTERRUPTS + (64-1)) / 64]; /*XXX 64 = bits in unsigned long*/
} kvm_sregs_t;

/* When set in flags, include corresponding fields on KVM_SET_VCPU_EVENTS */
#define KVM_VCPUEVENT_VALID_NMI_PENDING	0x00000001
#define KVM_VCPUEVENT_VALID_SIPI_VECTOR	0x00000002

/* for KVM_GET/SET_VCPU_EVENTS */
typedef struct kvm_vcpu_events {
	struct {
		unsigned char injected;
		unsigned char nr;
		unsigned char has_error_code;
		unsigned char pad;
		uint32_t error_code;
	} exception;
	struct {
		unsigned char injected;
		unsigned char nr;
		unsigned char soft;
		unsigned char pad;
	} interrupt;
	struct {
		unsigned char injected;
		unsigned char pending;
		unsigned char masked;
		unsigned char pad;
	} nmi;
	uint32_t sipi_vector;
	uint32_t flags;
	uint32_t reserved[10];
} kvm_vcpu_events_t;

#define KVM_CAP_IRQ_ROUTING 25

#ifdef KVM_CAP_IRQ_ROUTING
typedef struct kvm_irq_routing_irqchip {
	uint32_t irqchip;
	uint32_t pin;
} kvm_irq_routing_irqchip_t;

/*
 * Shift/mask fields for msi address
 */

#define MSI_ADDR_BASE_HI		0
#define MSI_ADDR_BASE_LO		0xfee00000

#define MSI_ADDR_DEST_MODE_SHIFT	2
#define  MSI_ADDR_DEST_MODE_PHYSICAL	(0 << MSI_ADDR_DEST_MODE_SHIFT)
#define	 MSI_ADDR_DEST_MODE_LOGICAL	(1 << MSI_ADDR_DEST_MODE_SHIFT)

#define MSI_ADDR_REDIRECTION_SHIFT	3
#define  MSI_ADDR_REDIRECTION_CPU	(0 << MSI_ADDR_REDIRECTION_SHIFT)
					/* dedicated cpu */
#define  MSI_ADDR_REDIRECTION_LOWPRI	(1 << MSI_ADDR_REDIRECTION_SHIFT)
					/* lowest priority */

#define MSI_ADDR_DEST_ID_SHIFT		12
#define	 MSI_ADDR_DEST_ID_MASK		0x00ffff0
#define  MSI_ADDR_DEST_ID(dest)		(((dest) << MSI_ADDR_DEST_ID_SHIFT) & \
					 MSI_ADDR_DEST_ID_MASK)
#define MSI_ADDR_EXT_DEST_ID(dest)	((dest) & 0xffffff00)

#define MSI_ADDR_IR_EXT_INT		(1 << 4)
#define MSI_ADDR_IR_SHV			(1 << 3)
#define MSI_ADDR_IR_INDEX1(index)	((index & 0x8000) >> 13)
#define MSI_ADDR_IR_INDEX2(index)	((index & 0x7fff) << 5)
#define MSI_DATA_VECTOR_SHIFT		0
#define  MSI_DATA_VECTOR_MASK		0x000000ff
#define	 MSI_DATA_VECTOR(v)		(((v) << MSI_DATA_VECTOR_SHIFT) & \
					 MSI_DATA_VECTOR_MASK)
#define MSI_DATA_TRIGGER_SHIFT		15
#define  MSI_DATA_TRIGGER_EDGE		(0 << MSI_DATA_TRIGGER_SHIFT)
#define  MSI_DATA_TRIGGER_LEVEL		(1 << MSI_DATA_TRIGGER_SHIFT)

typedef struct kvm_irq_routing_msi {
	uint32_t address_lo;
	uint32_t address_hi;
	uint32_t data;
	uint32_t pad;
} kvm_irq_routing_msi_t;

/* gsi routing entry types */
#define KVM_IRQ_ROUTING_IRQCHIP 1
#define KVM_IRQ_ROUTING_MSI 2

typedef struct kvm_irq_routing_entry {
	uint32_t gsi;
	uint32_t type;
	uint32_t flags;
	uint32_t pad;
	union {
		struct kvm_irq_routing_irqchip irqchip;
		struct kvm_irq_routing_msi msi;
		uint32_t pad[8];
	} u;
} kvm_irq_routing_entry_t;

typedef struct kvm_irq_routing {
	uint32_t nr;
	uint32_t flags;
	struct kvm_irq_routing_entry entries[1];
} kvm_irq_routing_t;

#endif

#define KVM_MAX_MCE_BANKS 32
#define KVM_MCE_CAP_SUPPORTED MCG_CTL_P


struct kvm_vcpu;
struct kvm;

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

#ifndef container_of
/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:	the pointer to the member.
 * @type:	the type of the container struct this is embedded in.
 * @member:	the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})
#endif /*container_of*/

#define PT64_ROOT_LEVEL 4
#define PT32_ROOT_LEVEL 2
#define PT32E_ROOT_LEVEL 3

#define PT_PDPE_LEVEL 3
#define PT_DIRECTORY_LEVEL 2
#define PT_PAGE_TABLE_LEVEL 1

#define KVM_PAGE_ARRAY_NR 16

/* Avoid include hell */
#define NMI_VECTOR 0x02


typedef struct kvm_mmu_pages {
	struct mmu_page_and_offset {
		struct kvm_mmu_page *sp;
		unsigned int idx;
	} page[KVM_PAGE_ARRAY_NR];
	unsigned int nr;
} kvm_mmu_pages_t;

typedef struct mmu_page_path {
	struct kvm_mmu_page *parent[PT64_ROOT_LEVEL-1];
	unsigned int idx[PT64_ROOT_LEVEL-1];
} mmu_page_path_t;

/*
 * Save the original ist values for checking stack pointers during debugging
 */
typedef struct orig_ist {
	unsigned long		ist[7];
} orig_ist_t;

#define	MXCSR_DEFAULT		0x1f80

typedef struct i387_fsave_struct {
	uint32_t			cwd;	/* FPU Control Word		*/
	uint32_t			swd;	/* FPU Status Word		*/
	uint32_t			twd;	/* FPU Tag Word			*/
	uint32_t			fip;	/* FPU IP Offset		*/
	uint32_t			fcs;	/* FPU IP Selector		*/
	uint32_t			foo;	/* FPU Operand Pointer Offset	*/
	uint32_t			fos;	/* FPU Operand Pointer Selector	*/

	/* 8*10 bytes for each FP-reg = 80 bytes:			*/
	uint32_t			st_space[20];

	/* Software status information [not touched by FSAVE ]:		*/
	uint32_t			status;
} i387_fsave_struct_t;


typedef struct i387_soft_struct {
	uint32_t			cwd;
	uint32_t			swd;
	uint32_t			twd;
	uint32_t			fip;
	uint32_t			fcs;
	uint32_t			foo;
	uint32_t			fos;
	/* 8*10 bytes for each FP-reg = 80 bytes: */
	uint32_t			st_space[20];
	unsigned char			ftop;
	unsigned char			changed;
	unsigned char			lookahead;
	unsigned char			no_update;
	unsigned char			rm;
	unsigned char			alimit;
	struct math_emu_info	*info;
	uint32_t			entry_eip;
} i387_soft_struct_t;

#define KVM_CPUID_FLAG_SIGNIFCANT_INDEX 1
#define KVM_CPUID_FLAG_STATEFUL_FUNC    2
#define KVM_CPUID_FLAG_STATE_READ_NEXT  4


/* for KVM_GET_FPU and KVM_SET_FPU */
typedef struct kvm_fpu {
	unsigned char  fpr[8][16];
	unsigned short fcw;
	unsigned short fsw;
	unsigned char  ftwx;  /* in fxsave format */
	unsigned char  pad1;
	unsigned short last_opcode;
	uint64_t last_ip;
	uint64_t last_dp;
	unsigned char  xmm[16][16];
	uint32_t mxcsr;
	uint32_t pad2;
} kvm_fpu_t;

typedef struct kvm_msr_entry {
	uint32_t index;
	uint32_t reserved;
	uint64_t data;
} kvm_msr_entry_t;

/* for KVM_GET_MSRS and KVM_SET_MSRS */
typedef struct kvm_msrs {
	uint32_t nmsrs; /* number of msrs in entries */
	uint32_t pad;

	struct kvm_msr_entry entries[100];
} kvm_msrs_t;

/* for KVM_GET_MSR_INDEX_LIST */
typedef struct kvm_msr_list {
	uint32_t nmsrs; /* number of msrs in entries */
	uint32_t indices[1];
} kvm_msr_list_t;

typedef struct kvm_cpuid_entry {
	uint32_t function;
	uint32_t eax;
	uint32_t ebx;
	uint32_t ecx;
	uint32_t edx;
	uint32_t padding;
} kvm_cpuid_entry_t;

/* for KVM_SET_CPUID */
typedef struct kvm_cpuid {
	uint32_t nent;
	uint32_t padding;
	struct kvm_cpuid_entry entries[100];
} kvm_cpuid_t;

/* for KVM_GET_PIT and KVM_SET_PIT */
typedef struct kvm_pit_channel_state {
	uint32_t count; /* can be 65536 */
	uint16_t latched_count;
	uint8_t count_latched;
	uint8_t status_latched;
	uint8_t status;
	uint8_t read_state;
	uint8_t write_state;
	uint8_t write_latch;
	uint8_t rw_mode;
	uint8_t mode;
	uint8_t bcd;
	uint8_t gate;
	int64_t count_load_time;
} kvm_pit_channel_state_t;

typedef struct kvm_debug_exit_arch {
	uint32_t exception;
	uint32_t pad;
	uint64_t pc;
	uint64_t dr6;
	uint64_t dr7;
} kvm_debug_exit_arch_t;

#define KVM_GUESTDBG_USE_SW_BP		0x00010000
#define KVM_GUESTDBG_USE_HW_BP		0x00020000
#define KVM_GUESTDBG_INJECT_DB		0x00040000
#define KVM_GUESTDBG_INJECT_BP		0x00080000

#ifdef XXX
/* for KVM_SET_GUEST_DEBUG */
typedef struct kvm_guest_debug_arch {
	uint64_t debugreg[8];
} kvm_guest_debug_arch_t;
#endif /*XXX*/

typedef struct kvm_pit_state {
	struct kvm_pit_channel_state channels[3];
} kvm_pit_state_t;

#define KVM_PIT_FLAGS_HPET_LEGACY  0x00000001

typedef struct kvm_pit_state2 {
	struct kvm_pit_channel_state channels[3];
	uint32_t flags;
	uint32_t reserved[9];
} kvm_pit_state2_t;

typedef struct kvm_reinject_control {
	uint8_t pit_reinject;
	uint8_t reserved[31];
} kvm_reinject_control_t;


/* for KVM_SET_CPUID2 */
typedef struct kvm_cpuid2 {
	uint32_t nent;
	uint32_t padding;
	struct kvm_cpuid_entry2 entries[100];
} kvm_cpuid2_t;

#define X86_SHADOW_INT_MOV_SS  1
#define X86_SHADOW_INT_STI     2


struct pvclock_wall_clock {
	uint32_t   version;
	uint32_t   sec;
	uint32_t   nsec;
} __attribute__((__packed__));

typedef struct pvclock_wall_clock pvclock_wall_clock_t;

typedef struct msi_msg {
	uint32_t	address_lo;	/* low 32 bits of msi message address */
	uint32_t	address_hi;	/* high 32 bits of msi message address */
	uint32_t	data;		/* 16 bits of msi message data */
} msi_msg_t;


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

/*#ifdef __KVM_HAVE_IOAPIC*/

#define KVM_MAX_IRQ_ROUTES 1024

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

typedef struct kvm_kirq_routing {
	uint32_t nr;
	uint32_t flags;
	struct kvm_irq_routing_entry entries[KVM_MAX_IRQ_ROUTES+1];
} kvm_kirq_routing_t;

/*#endif  __KVM_HAVE_IOAPIC*/

#define MTRRphysBase_MSR(reg) (0x200 + 2 * (reg))
#define MTRRphysMask_MSR(reg) (0x200 + 2 * (reg) + 1)

#endif /*x86*/

#ifdef _KERNEL

typedef struct kvm_shadow_walk_iterator {
	uint64_t addr;
	hpa_t shadow_addr;
	uint64_t *sptep;
	int level;
	unsigned index;
} kvm_shadow_walk_iterator_t;

extern void shadow_walk_init(struct kvm_shadow_walk_iterator *iterator,
			     struct kvm_vcpu *vcpu, uint64_t addr);
extern int shadow_walk_okay(struct kvm_shadow_walk_iterator *iterator, struct kvm_vcpu *vcpu);
extern void shadow_walk_next(struct kvm_shadow_walk_iterator *iterator);

#define for_each_shadow_entry(_vcpu, _addr, _walker)    \
	for (shadow_walk_init(&(_walker), _vcpu, _addr);	\
	     shadow_walk_okay(&(_walker), _vcpu);			\
	     shadow_walk_next(&(_walker)))

enum kvm_bus {
	KVM_MMIO_BUS,
	KVM_PIO_BUS,
	KVM_NR_BUSES
};

typedef struct kvm_stats {
	kstat_named_t kvmks_pid;		/* PID of opening process */
	kstat_named_t kvmks_mmu_pte_write;	/* page table entry writes */
	kstat_named_t kvmks_mmu_pte_zapped;	/* zapped page table entries */
	kstat_named_t kvmks_mmu_pte_updated;	/* page table entry updates */
	kstat_named_t kvmks_mmu_flooded;	/* # of pages flooded */
	kstat_named_t kvmks_mmu_cache_miss;	/* misses in page cache */
	kstat_named_t kvmks_mmu_recycled;	/* recycles from free list */
	kstat_named_t kvmks_remote_tlb_flush;	/* remote TLB flushes */
	kstat_named_t kvmks_lpages;		/* large pages in use */
} kvm_stats_t;

#define KVM_KSTAT_INIT(kvmp, field, name) \
	kstat_named_init(&((kvmp)->kvm_stats.field), name, KSTAT_DATA_UINT64);

#define KVM_KSTAT_INC(kvmp, field) \
	(kvmp)->kvm_stats.field.value.ui64++;

#define KVM_KSTAT_DEC(kvmp, field) \
	(kvmp)->kvm_stats.field.value.ui64--;

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
#endif /*_KERNEL*/

#define KVM_EXIT_UNKNOWN          0
#define KVM_EXIT_EXCEPTION        1
#define KVM_EXIT_IO               2
#define KVM_EXIT_HYPERCALL        3
#define KVM_EXIT_DEBUG            4
#define KVM_EXIT_HLT              5
#define KVM_EXIT_MMIO             6
#define KVM_EXIT_IRQ_WINDOW_OPEN  7
#define KVM_EXIT_SHUTDOWN         8
#define KVM_EXIT_FAIL_ENTRY       9
#define KVM_EXIT_INTR             10
#define KVM_EXIT_SET_TPR          11
#define KVM_EXIT_TPR_ACCESS       12
#define KVM_EXIT_S390_SIEIC       13
#define KVM_EXIT_S390_RESET       14
#define KVM_EXIT_DCR              15
#define KVM_EXIT_NMI              16
#define KVM_EXIT_INTERNAL_ERROR   17

/* For KVM_EXIT_INTERNAL_ERROR */
#define KVM_INTERNAL_ERROR_EMULATION 1
#define KVM_INTERNAL_ERROR_SIMUL_EX 2

/* for KVM_RUN, returned by mmap(vcpu_fd, offset=0) */
typedef struct kvm_run {
	/* in */
	unsigned char request_interrupt_window;
	unsigned char padding1[7];

	/* out */
	uint32_t exit_reason;
	unsigned char ready_for_interrupt_injection;
	unsigned char if_flag;
	unsigned char padding2[2];

	/* in (pre_kvm_run), out (post_kvm_run) */
	uint64_t cr8;
	uint64_t apic_base;

#ifdef __KVM_S390
	/* the processor status word for s390 */
	uint64_t psw_mask; /* psw upper half */
	uint64_t psw_addr; /* psw lower half */
#endif
	union {
		/*
		 * As a temporary hack, we set the PFNs for programmed I/O and
		 * memory-mapped I/O upon initialization to allow them to be
		 * mmap'd after the kvm_run structure.
		 */
                struct {
                        uint64_t xxx_pio_paddr;
                        uint64_t xxx_mmio_paddr;
                } xxx_paddrs;
	
		/* KVM_EXIT_UNKNOWN */
		struct {
			uint64_t hardware_exit_reason;
		} hw;
		/* KVM_EXIT_FAIL_ENTRY */
		struct {
			uint64_t hardware_entry_failure_reason;
		} fail_entry;
		/* KVM_EXIT_EXCEPTION */
		struct {
			uint32_t exception;
			uint32_t error_code;
		} ex;
		/* KVM_EXIT_IO */
		struct {
#define KVM_EXIT_IO_IN  0
#define KVM_EXIT_IO_OUT 1
			unsigned char direction;
			unsigned char size; /* bytes */
			unsigned short port;
			uint32_t count;
			uint64_t data_offset; /* relative to kvm_run start */
		} io;
		struct {
			struct kvm_debug_exit_arch arch;
		} debug;
		/* KVM_EXIT_MMIO */
		struct {
			uint64_t phys_addr;
			unsigned char  data[8];
			uint32_t len;
			unsigned char  is_write;
		} mmio;
		/* KVM_EXIT_HYPERCALL */
		struct {
			uint64_t nr;
			uint64_t args[6];
			uint64_t ret;
			uint32_t longmode;
			uint32_t pad;
		} hypercall;
		/* KVM_EXIT_TPR_ACCESS */
		struct {
			uint64_t rip;
			uint32_t is_write;
			uint32_t pad;
		} tpr_access;
		/* KVM_EXIT_S390_SIEIC */
		struct {
			unsigned char icptcode;
			unsigned short ipa;
			uint32_t ipb;
		} s390_sieic;
		/* KVM_EXIT_S390_RESET */
#define KVM_S390_RESET_POR       1
#define KVM_S390_RESET_CLEAR     2
#define KVM_S390_RESET_SUBSYSTEM 4
#define KVM_S390_RESET_CPU_INIT  8
#define KVM_S390_RESET_IPL       16
		uint64_t s390_reset_flags;
		/* KVM_EXIT_DCR */
		struct {
			uint32_t dcrn;
			uint32_t data;
			unsigned char  is_write;
		} dcr;
		struct {
			uint32_t suberror;
			/* Available with KVM_CAP_INTERNAL_ERROR_DATA: */
			uint32_t ndata;
			uint64_t data[16];
		} internal;
		/* Fix the size of the union. */
		char padding[256];
	};
} kvm_run_t;

/* the following is directly copied from ioctl.h on linux */
#ifndef _ASM_GENERIC_IOCTL_H
#define _ASM_GENERIC_IOCTL_H

/* ioctl command encoding: 32 bits total, command in lower 16 bits,
 * size of the parameter structure in the lower 14 bits of the
 * upper 16 bits.
 * Encoding the size of the parameter structure in the ioctl request
 * is useful for catching programs compiled with old versions
 * and to avoid overwriting user space outside the user buffer area.
 * The highest 2 bits are reserved for indicating the ``access mode''.
 * NOTE: This limits the max parameter size to 16kB -1 !
 */

/*
 * The following is for compatibility across the various Linux
 * platforms.  The generic ioctl numbering scheme doesn't really enforce
 * a type field.  De facto, however, the top 8 bits of the lower 16
 * bits are indeed used as a type field, so we might just as well make
 * this explicit here.  Please be sure to use the decoding macros
 * below from now on.
 */
#define _IOC_NRBITS	8
#define _IOC_TYPEBITS	8

/*
 * Let any architecture override either of the following before
 * including this file.
 */

#ifndef _IOC_SIZEBITS
# define _IOC_SIZEBITS	14
#endif

#ifndef _IOC_DIRBITS
# define _IOC_DIRBITS	2
#endif

#define _IOC_NRMASK	((1 << _IOC_NRBITS)-1)
#define _IOC_TYPEMASK	((1 << _IOC_TYPEBITS)-1)
#define _IOC_SIZEMASK	((1 << _IOC_SIZEBITS)-1)
#define _IOC_DIRMASK	((1 << _IOC_DIRBITS)-1)

#define _IOC_NRSHIFT	0
#define _IOC_TYPESHIFT	(_IOC_NRSHIFT+_IOC_NRBITS)
#define _IOC_SIZESHIFT	(_IOC_TYPESHIFT+_IOC_TYPEBITS)
#define _IOC_DIRSHIFT	(_IOC_SIZESHIFT+_IOC_SIZEBITS)

/*
 * Direction bits, which any architecture can choose to override
 * before including this file.
 */

#ifndef _IOC_NONE
# define _IOC_NONE	0U
#endif

#ifndef _IOC_WRITE
# define _IOC_WRITE	1U
#endif

#ifndef _IOC_READ
# define _IOC_READ	2U
#endif

#define _IOC(dir,type,nr,size) \
	(((dir)  << _IOC_DIRSHIFT) | \
	 ((type) << _IOC_TYPESHIFT) | \
	 ((nr)   << _IOC_NRSHIFT) | \
	 ((size) << _IOC_SIZESHIFT))

#ifdef XXX
#ifdef _KERNEL

/* provoke compile error for invalid uses of size argument */
extern unsigned int __invalid_size_argument_for_IOC;
#define _IOC_TYPECHECK(t) \
	((sizeof(t) == sizeof(t[1]) && \
	  sizeof(t) < (1 << _IOC_SIZEBITS)) ? \
	  sizeof(t) : __invalid_size_argument_for_IOC)
#else
#define _IOC_TYPECHECK(t) (sizeof(t))
#endif /*_KERNEL*/
#else /*XXX*/

#define _IOC_TYPECHECK(t) (sizeof(t))

static void native_load_tr_desc(void)
{
	__asm__ volatile("ltr %w0"::"q" (KTSS_SEL));
}

#define load_TR_desc() native_load_tr_desc()

#endif /*XXX*/


#ifdef XXX
#define _IOR(type,nr,size)	_IOC(_IOC_READ,(type),(nr),(_IOC_TYPECHECK(size)))
#define _IOW(type,nr,size)	_IOC(_IOC_WRITE,(type),(nr),(_IOC_TYPECHECK(size)))
#define _IOWR(type,nr,size)	_IOC(_IOC_READ|_IOC_WRITE,(type),(nr),(_IOC_TYPECHECK(size)))
#define _IOR_BAD(type,nr,size)	_IOC(_IOC_READ,(type),(nr),sizeof(size))
#define _IOW_BAD(type,nr,size)	_IOC(_IOC_WRITE,(type),(nr),sizeof(size))
#define _IOWR_BAD(type,nr,size)	_IOC(_IOC_READ|_IOC_WRITE,(type),(nr),sizeof(size))
#endif /*XXX*/
/* used to decode ioctl numbers.. */
#define _IOC_DIR(nr)		(((nr) >> _IOC_DIRSHIFT) & _IOC_DIRMASK)
#define _IOC_TYPE(nr)		(((nr) >> _IOC_TYPESHIFT) & _IOC_TYPEMASK)
#define _IOC_NR(nr)		(((nr) >> _IOC_NRSHIFT) & _IOC_NRMASK)
#define _IOC_SIZE(nr)		(((nr) >> _IOC_SIZESHIFT) & _IOC_SIZEMASK)

#define IOCSIZE_MASK	(_IOC_SIZEMASK << _IOC_SIZESHIFT)
#define IOCSIZE_SHIFT	(_IOC_SIZESHIFT)

#endif /* _ASM_GENERIC_IOCTL_H */

/* ioctl commands */

#define KVMIO 0xAE

/* x86 MCE */
typedef struct kvm_x86_mce {
	uint64_t status;
	uint64_t addr;
	uint64_t misc;
	uint64_t mcg_status;
	uint8_t bank;
	uint8_t pad1[7];
	uint64_t pad2[3];
} kvm_x86_mce_t;

typedef struct kvm_clock_data {
	uint64_t clock;
	uint32_t flags;
	uint32_t pad[9];
} kvm_clock_data_t;

/* for KVM_SET_SIGNAL_MASK */
typedef struct kvm_signal_mask {
	uint32_t len;
	uint8_t  sigset[1];
} kvm_signal_mask_t;

typedef struct kvm_set_boot_cpu_id_ioc {
	int id;
} kvm_set_boot_cpu_id_ioc_t;

/*
 * ioctls for vcpu fds
 */
#define KVM_RUN                   _IO(KVMIO,   0x80)
#define KVM_GET_REGS              _IOR(KVMIO,  0x81, struct kvm_regs)
#define KVM_SET_REGS              _IOW(KVMIO,  0x82, struct kvm_regs)
#define KVM_GET_SREGS             _IOR(KVMIO,  0x83, struct kvm_sregs)
#define KVM_SET_SREGS             _IOW(KVMIO,  0x84, struct kvm_sregs)
#define KVM_INTERRUPT             _IOW(KVMIO,  0x86, struct kvm_interrupt)
#define KVM_SET_CPUID             _IOW(KVMIO,  0x8a, struct kvm_cpuid)
#define KVM_SET_SIGNAL_MASK       _IOW(KVMIO,  0x8b, struct kvm_signal_mask)
#define KVM_GET_FPU               _IOR(KVMIO,  0x8c, struct kvm_fpu)
#define KVM_SET_FPU               _IOW(KVMIO,  0x8d, struct kvm_fpu)
#define KVM_GET_MSRS              _IOWR(KVMIO, 0x88, struct kvm_msrs)
#define KVM_SET_MSRS              _IOW(KVMIO,  0x89, struct kvm_msrs)
#define KVM_GET_LAPIC             _IOR(KVMIO,  0x8e, struct kvm_lapic_state)
#define KVM_SET_LAPIC             _IOW(KVMIO,  0x8f, struct kvm_lapic_state)
#define KVM_GET_MP_STATE          _IOR(KVMIO,  0x98, struct kvm_mp_state)
#define KVM_SET_MP_STATE          _IOW(KVMIO,  0x99, struct kvm_mp_state)
/* MCE for x86 */
#define KVM_X86_SETUP_MCE         _IOW(KVMIO,  0x9c, uint64_t)
#define KVM_X86_GET_MCE_CAP_SUPPORTED _IOR(KVMIO,  0x9d, uint64_t)
#define KVM_X86_SET_MCE           _IOW(KVMIO,  0x9e, struct kvm_x86_mce)

#define KVM_REINJECT_CONTROL      _IO(KVMIO,   0x71)
#define KVM_SET_BOOT_CPU_ID       _IO(KVMIO,   0x78)

#define KVM_SET_CLOCK             _IOW(KVMIO,  0x7b, struct kvm_clock_data)
#define KVM_GET_CLOCK             _IOR(KVMIO,  0x7c, struct kvm_clock_data)

/* Available with KVM_CAP_VCPU_EVENTS */
#define KVM_GET_VCPU_EVENTS       _IOR(KVMIO,  0x9f, struct kvm_vcpu_events)
#define KVM_SET_VCPU_EVENTS       _IOW(KVMIO,  0xa0, struct kvm_vcpu_events)
/* Available with KVM_CAP_PIT_STATE2 */
#define KVM_GET_PIT2              _IOR(KVMIO,  0x9f, struct kvm_pit_state2)
#define KVM_SET_PIT2              _IOW(KVMIO,  0xa0, struct kvm_pit_state2)



/*
 * ioctls for /dev/kvm fds:
 */
#define KVM_GET_API_VERSION       _IO(KVMIO,   0x00)
#define KVM_CREATE_VM             _IO(KVMIO,   0x01) /* returns a VM fd */
#define KVM_DESTROY_VM		  _IO(KVMIO,   0x0a)
#define KVM_CLONE                 _IO(KVMIO,   0x20)
#define KVM_NET_QUEUE             _IO(KVMIO,   0x21)

#define KVM_GET_MSR_INDEX_LIST    _IOWR(KVMIO, 0x02, struct kvm_msr_list)

#define KVM_S390_ENABLE_SIE       _IO(KVMIO,   0x06)

#define KVM_GET_VCPU_MMAP_SIZE    _IO(KVMIO,   0x04) /* in bytes */

#define KVM_GET_SUPPORTED_CPUID   _IOWR(KVMIO, 0x05, struct kvm_cpuid2)

/* for KVM_IRQ_LINE */
typedef struct kvm_irq_level {
	/*
	 * ACPI gsi notion of irq.
	 * For IA-64 (APIC model) IOAPIC0: irq 0-23; IOAPIC1: irq 24-47..
	 * For X86 (standard AT mode) PIC0/1: irq 0-15. IOAPIC0: 0-23..
	 */
	union {
		uint32_t irq;
		int32_t status;
	};
	uint32_t level;
} kvm_irq_level_t;

typedef struct kvm_irq_level_ioc {
	struct kvm_irq_level event;
} kvm_irq_level_ioc_t;

/*
 * for KVM_SET_IDENTITY_MAP_ADDR
 */

typedef struct kvm_id_map_addr {
	int pad;
	uint64_t addr;
} kvm_id_map_addr_t;

/* for KVM_SET_IDENTITY_MAP_ADDR */
typedef struct kvm_id_map_addr_ioc {
	uint64_t ident_addr;
} kvm_id_map_addr_ioc_t;


/*
 * ioctls for VM fds
 */

/*
 * KVM_CREATE_VCPU receives as a parameter the vcpu slot, and returns
 * a vcpu fd.
 */
#define KVM_CREATE_VCPU           _IO(KVMIO,   0x41)
#define KVM_GET_DIRTY_LOG         _IOW(KVMIO,  0x42, struct kvm_dirty_log)
#define KVM_SET_NR_MMU_PAGES      _IO(KVMIO,   0x44)
#define KVM_GET_NR_MMU_PAGES      _IO(KVMIO,   0x45)
#define KVM_SET_TSS_ADDR          _IO(KVMIO,   0x47)
#define KVM_SET_IDENTITY_MAP_ADDR _IOW(KVMIO,  0x48, struct kvm_id_map_addr_ioc)
/* Device model IOC */
#define KVM_CREATE_IRQCHIP        _IO(KVMIO,   0x60)
#define KVM_IRQ_LINE              _IOW(KVMIO,  0x61, struct kvm_irq_level_ioc)
#define KVM_IRQ_LINE_STATUS       _IOWR(KVMIO, 0x67, struct kvm_irq_level_ioc)
#define KVM_GET_IRQCHIP           _IOWR(KVMIO, 0x62, struct kvm_irqchip)
#define KVM_SET_IRQCHIP           _IOR(KVMIO,  0x63, struct kvm_irqchip)

#define KVM_PIT_SPEAKER_DUMMY     1

#define KVM_CREATE_PIT            _IO(KVMIO,   0x64)
#define KVM_GET_PIT               _IOWR(KVMIO, 0x65, struct kvm_pit_state)
#define KVM_SET_PIT               _IOR(KVMIO,  0x66, struct kvm_pit_state)
#define KVM_CREATE_PIT2		  _IOW(KVMIO,  0x77, struct kvm_pit_config)

#define KVM_REGISTER_COALESCED_MMIO \
			_IOW(KVMIO,  0x67, struct kvm_coalesced_mmio_zone_ioc)
#define KVM_UNREGISTER_COALESCED_MMIO \
			_IOW(KVMIO,  0x68, struct kvm_coalesced_mmio_zone_ioc)

#define KVM_SET_GSI_ROUTING       _IOW(KVMIO,  0x6a, struct kvm_kirq_routing)

/*
 * Check if a kvm extension is available.  Argument is extension number,
 * return is 1 (yes) or 0 (no, sorry).
 */
#define KVM_CHECK_EXTENSION       _IO(KVMIO,   0x03)

typedef struct vmcs_config {
	int size;
	int order;
	uint32_t revision_id;
	uint32_t pin_based_exec_ctrl;
	uint32_t cpu_based_exec_ctrl;
	uint32_t cpu_based_2nd_exec_ctrl;
	uint32_t vmexit_ctrl;
	uint32_t vmentry_ctrl;
} vmcs_config_t;

#define RMAP_EXT 4

typedef struct kvm_rmap_desc {
	uint64_t *sptes[RMAP_EXT];
	struct kvm_rmap_desc *more;
} kvm_rmap_desc_t;


typedef struct vmx_capability {
	uint32_t ept;
	uint32_t vpid;
} vmx_capability_t;

typedef struct vmcs {
	uint32_t revision_id;
	uint32_t abort;
	char data[1];  /* size is read from MSR */
} vmcs_t;

/* for KVM_INTERRUPT */
typedef struct kvm_interrupt {
	/* in */
	uint32_t irq;
} kvm_interrupt_t;

/* for KVM_GET_DIRTY_LOG */
typedef struct kvm_dirty_log {
	uint32_t slot;
	uint32_t padding1;
	union {
		void  *dirty_bitmap; /* one bit per page */
		uint64_t padding2;
	}v;
} kvm_dirty_log_t;

typedef struct kvm_coalesced_mmio {
	uint64_t phys_addr;
	uint32_t len;
	uint32_t pad;
	unsigned char  data[8];
} kvm_coalesced_mmio_t;

typedef struct kvm_coalesced_mmio_ring {
	uint32_t first, last;
	struct kvm_coalesced_mmio coalesced_mmio[1];
} kvm_coalesced_mmio_ring_t;

#define KVM_COALESCED_MMIO_MAX \
	((PAGESIZE - sizeof(struct kvm_coalesced_mmio_ring)) / \
	 sizeof(struct kvm_coalesced_mmio))

/* for KVM_SET_VAPIC_ADDR */
typedef struct kvm_vapic_addr {
	uint64_t vapic_addr;
} kvm_vapic_addr_t;

/* for KVM_SET_MP_STATE */
#define KVM_MP_STATE_RUNNABLE          0
#define KVM_MP_STATE_UNINITIALIZED     1
#define KVM_MP_STATE_INIT_RECEIVED     2
#define KVM_MP_STATE_HALTED            3
#define KVM_MP_STATE_SIPI_RECEIVED     4

/* for KVM_TPR_ACCESS_REPORTING */
typedef struct kvm_tpr_access_ctl {
	uint32_t enabled;
	uint32_t flags;
	uint32_t reserved[8];
} kvm_tpr_access_ctl_t;

typedef struct kvm_tpr_acl_ioc {
	struct kvm_tpr_access_ctl tac;
	int kvm_id;
	int cpu_index;
} kvm_tpr_acl_ioc_t;

#define KVM_SET_CPUID2            _IOW(KVMIO,  0x90, struct kvm_cpuid2)
#define KVM_GET_CPUID2            _IOWR(KVMIO, 0x91, struct kvm_cpuid2)
/* Available with KVM_CAP_VAPIC */
#define KVM_TPR_ACCESS_REPORTING  _IOWR(KVMIO, 0x92, struct kvm_tpr_acl_ioc)
/* Available with KVM_CAP_VAPIC */
#define KVM_SET_VAPIC_ADDR        _IOW(KVMIO,  0x93, struct kvm_vapic_addr)

#define APIC_BUS_CYCLE_NS 1
#define NSEC_PER_MSEC 1000000L
#define NSEC_PER_SEC 1000000000L

/* for kvm_memory_region::flags */
#define KVM_MEM_LOG_DIRTY_PAGES  1UL
#define KVM_MEMSLOT_INVALID      (1UL << 1)


/* for KVM_CREATE_MEMORY_REGION */
typedef struct kvm_memory_region {
	uint32_t slot;
	uint32_t flags;
	uint64_t guest_phys_addr;
	uint64_t memory_size; /* bytes */
} kvm_memory_region_t;

/* for KVM_SET_USER_MEMORY_REGION */
typedef struct kvm_userspace_memory_region {
	uint32_t slot;
	uint32_t flags;
	uint64_t guest_phys_addr;
	uint64_t memory_size; /* bytes */
	uint64_t userspace_addr; /* start of the userspace allocated memory */
} kvm_userspace_memory_region_t;

#ifndef XXX
#define KVM_SET_USER_MEMORY_REGION _IOW(KVMIO, 0x46, \
					struct kvm_userspace_memory_region)
#else
#define KVM_SET_USER_MEMORY_REGION _IOW(KVMIO, 0x46, \
					struct kvm_set_user_memory_ioc)
#endif /*XXX*/

/* for KVM_SET_TSS_ADDR ioctl */
typedef struct kvm_tss {
	uint64_t addr; /* in */
} kvm_tss_t;

/* for KVM_CREATE_VCPU */
typedef struct kvm_vcpu_ioc {
	uint32_t id;  /*IN*/
	uint64_t kvm_run_addr; /*OUT*/
	uint64_t kvm_vcpu_addr; /* OUT, id is not unique across VMs */
} kvm_vcpu_ioc_t;



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

typedef struct shared_msr_entry {
	unsigned index;
	uint64_t data;
	uint64_t mask;
} shared_msr_entry_t;

#ifdef _KERNEL
typedef struct vcpu_vmx {
	struct kvm_vcpu       vcpu;
	list_t      local_vcpus_link;
	unsigned long         host_rsp;
	int                   launched;
	unsigned char                    fail;
	uint32_t                   idt_vectoring_info;
	struct shared_msr_entry *guest_msrs;
	int                   nmsrs;
	int                   save_nmsrs;
#ifdef CONFIG_X86_64
	uint64_t 		      msr_host_kernel_gs_base;
	uint64_t 		      msr_guest_kernel_gs_base;
#endif
	struct vmcs          *vmcs;
	uint64_t	vmcs_pa;  /* physical address of vmcs for this vmx */

	struct {
		int           loaded;
		unsigned short           fs_sel, gs_sel, ldt_sel;
		int           gs_ldt_reload_needed;
		int           fs_reload_needed;
	} host_state;
	struct {
		int vm86_active;
		ulong save_rflags;
		struct kvm_save_segment {
			unsigned short selector;
			unsigned long base;
			uint32_t limit;
			uint32_t ar;
		} tr, es, ds, fs, gs;
		struct {
			char pending;
			unsigned char vector;
			unsigned rip;
		} irq;
	} rmode;
	int vpid;
	char emulation_required;

	/* Support for vnmi-less CPUs */
	int soft_vnmi_blocked;
	time_t entry_time;
	int64_t vnmi_blocked_time;
	uint32_t exit_reason;

	char rdtscp_enabled;
} vcpu_vmx_t;

#define kvm_for_each_vcpu(idx, vcpup, kvm) \
	for (idx = 0, vcpup = kvm_get_vcpu(kvm, idx); \
	     idx < kvm->online_vcpus && vcpup; /* XXX - need protection */ \
	     vcpup = kvm_get_vcpu(kvm, ++idx))

extern struct kvm_vcpu *kvm_get_vcpu(struct kvm *kvm, int i);

typedef struct kvm_irq_mask_notifier {
	void (*func)(struct kvm_irq_mask_notifier *kimn, int masked);
	int irq;
	struct list_node link;
} kvm_irq_mask_notifier_t;

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


#ifdef __KVM_HAVE_IOAPIC
void kvm_get_intr_delivery_bitmask(struct kvm_ioapic *ioapic,
				   union kvm_ioapic_redirect_entry *entry,
				   unsigned long *deliver_bitmask);
#endif
int kvm_set_irq(struct kvm *kvm, int irq_source_id, uint32_t irq, int level);
void kvm_notify_acked_irq(struct kvm *kvm, unsigned irqchip, unsigned pin);
void kvm_register_irq_ack_notifier(struct kvm *kvm,
				   struct kvm_irq_ack_notifier *kian);
void kvm_unregister_irq_ack_notifier(struct kvm *kvm,
				   struct kvm_irq_ack_notifier *kian);
int kvm_request_irq_source_id(struct kvm *kvm);
void kvm_free_irq_source_id(struct kvm *kvm, int irq_source_id);

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

typedef struct kvm_kpit_channel_state {
	uint32_t count; /* can be 65536 */
	uint16_t latched_count;
	uint8_t count_latched;
	uint8_t status_latched;
	uint8_t status;
	uint8_t read_state;
	uint8_t write_state;
	uint8_t write_latch;
	uint8_t rw_mode;
	uint8_t mode;
	uint8_t bcd; /* not supported */
	uint8_t gate; /* timer start */
	hrtime_t count_load_time;
} kvm_kpit_channel_state_t;

typedef struct kvm_kpit_state {
	struct kvm_kpit_channel_state channels[3];
	uint32_t flags;
	struct kvm_timer pit_timer;
	int is_periodic;
	uint32_t    speaker_data_on;
	kmutex_t lock;
	struct kvm_pit *pit;
	kmutex_t inject_lock;
	unsigned long irq_ack;
	struct kvm_irq_ack_notifier irq_ack_notifier;
} kvm_kpit_state_t;

typedef struct kvm_pit {
	unsigned long base_addresss;
	struct kvm_io_device dev;
	struct kvm_io_device speaker_dev;
	struct kvm *kvm;
	struct kvm_kpit_state pit_state;
	int irq_source_id;
	struct kvm_irq_mask_notifier mask_notifier;
} kvm_pit_t;

#define KVM_PIT_BASE_ADDRESS	    0x40
#define KVM_SPEAKER_BASE_ADDRESS    0x61
#define KVM_PIT_MEM_LENGTH	    4
#define KVM_PIT_FREQ		    1193181
#define KVM_MAX_PIT_INTR_INTERVAL   HZ / 100
#define KVM_PIT_CHANNEL_MASK	    0x3

#define RW_STATE_LSB 1
#define RW_STATE_MSB 2
#define RW_STATE_WORD0 3
#define RW_STATE_WORD1 4

#define page_to_pfn(page) (page->p_pagenum)

#ifdef XXX
#define __ex(x) __kvm_handle_fault_on_reboot(x)
#endif /*XXX*/

#ifdef CONFIG_PREEMPT_NOTIFIERS
#ifdef XXX

struct preempt_notifier;

/**
 * preempt_ops - notifiers called when a task is preempted and rescheduled
 * @sched_in: we're about to be rescheduled:
 *    notifier: struct preempt_notifier for the task being scheduled
 *    cpu:  cpu we're scheduled on
 * @sched_out: we've just been preempted
 *    notifier: struct preempt_notifier for the task being preempted
 *    next: the task that's kicking us out
 *
 * Please note that sched_in and out are called under different
 * contexts.  sched_out is called with rq lock held and irq disabled
 * while sched_in is called without rq lock and irq enabled.  This
 * difference is intentional and depended upon by its users.
 */
typedef struct preempt_ops {
	void (*sched_in)(struct preempt_notifier *notifier, int cpu);
	void (*sched_out)(struct preempt_notifier *notifier,
			  struct task_struct *next);
} preempt_ops_t;

/**
 * preempt_notifier - key for installing preemption notifiers
 * @link: internal use
 * @ops: defines the notifier functions to be called
 *
 * Usually used in conjunction with container_of().
 */
typedef struct preempt_notifier {
	struct hlist_node link;
	struct preempt_ops *ops;
} preempt_notifier_t;

void preempt_notifier_register(struct preempt_notifier *notifier);
void preempt_notifier_unregister(struct preempt_notifier *notifier);
void preempt_notifier_init(struct preempt_notifier *notifier,
    struct preempt_ops *ops);

#endif /*XXX*/
#endif /*CONFIG_PREEMPT_NOTIFIERS*/
typedef struct cpuid_data {
        struct kvm_cpuid2 cpuid;
        struct kvm_cpuid_entry2 entries[100];
} __attribute__((packed)) cpuid_data;

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

int kvm_io_bus_write(struct kvm *kvm, enum kvm_bus bus_idx, gpa_t addr,
		     int len, const void *val);
int kvm_io_bus_read(struct kvm *kvm, enum kvm_bus bus_idx, gpa_t addr, int len,
		    void *val);
int kvm_io_bus_register_dev(struct kvm *kvm, enum kvm_bus bus_idx,
			    struct kvm_io_device *dev);
int kvm_io_bus_unregister_dev(struct kvm *kvm, enum kvm_bus bus_idx,
			      struct kvm_io_device *dev);

unsigned long kvm_dirty_bitmap_bytes(struct kvm_memory_slot *memslot);

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

int is_error_page(struct page *page);
int is_error_pfn(pfn_t pfn);
int kvm_is_error_hva(unsigned long addr);
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

#ifdef XXX
int kvm_arch_vcpu_ioctl_translate(struct kvm_vcpu *vcpu,
				    struct kvm_translation *tr);
#endif /*XXX*/

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

void kvm_vcpu_uninit(struct kvm_vcpu *);

struct  kvm *kvm_arch_create_vm(void);
void kvm_arch_destroy_vm(struct kvm *kvm);
void kvm_arch_destroy_vm_comps(struct kvm *kvm);
void kvm_free_all_assigned_devices(struct kvm *kvm);
void kvm_arch_sync_events(struct kvm *kvm);

int kvm_cpu_has_pending_timer(struct kvm_vcpu *vcpu);
void kvm_vcpu_kick(struct kvm_vcpu *vcpu);
void kvm_timer_fire(void *);

void kvm_sigprocmask(int how, sigset_t *, sigset_t *);

void kvm_register_irq_mask_notifier(struct kvm *kvm, int irq,
				    struct kvm_irq_mask_notifier *kimn);
void kvm_unregister_irq_mask_notifier(struct kvm *kvm, int irq,
				      struct kvm_irq_mask_notifier *kimn);
void kvm_fire_mask_notifiers(struct kvm *kvm, int irq, int mask);

extern int irqchip_in_kernel(struct kvm *kvm);
extern void kvm_inject_nmi(struct kvm_vcpu *);

int kvm_iommu_map_pages(struct kvm *kvm, struct kvm_memory_slot *slot);
int kvm_iommu_map_guest(struct kvm *kvm);
int kvm_iommu_unmap_guest(struct kvm *kvm);
int kvm_assign_device(struct kvm *kvm,
		      struct kvm_assigned_dev_kernel *assigned_dev);
int kvm_deassign_device(struct kvm *kvm,
			struct kvm_assigned_dev_kernel *assigned_dev);

extern unsigned long kvm_rip_read(struct kvm_vcpu *);
extern int kvm_vcpu_is_bsp(struct kvm_vcpu *);

extern struct kvm_cpuid_entry2 *kvm_find_cpuid_entry(struct kvm_vcpu *vcpu,
    uint32_t function, uint32_t index);

#define for_each_unsync_children(bitmap, idx)		\
	for (idx = bt_getlowbit(bitmap, 0, 512);	\
	     idx < 512;					\
	     idx = bt_getlowbit(bitmap, idx+1, 512))

#define PT_PAGE_SIZE_MASK (1ULL << 7)

#define	BITS_PER_LONG	(sizeof (unsigned long) * 8)

#define	MSR_EFER		0xc0000080 /* extended feature register */

#define	KVM_TRACE1(name, type1, arg1)					\
	DTRACE_PROBE1(kvm__##name, type1, arg1);

#define	KVM_TRACE2(name, type1, arg1, type2, arg2)			\
	DTRACE_PROBE2(kvm__##name, type1, arg1, type2, arg2);

#define	KVM_TRACE3(name, type1, arg1, type2, arg2, type3, arg3)		\
	DTRACE_PROBE3(kvm__##name, type1, arg1, type2, arg2, type3, arg3);

#define	KVM_TRACE4(name, type1, arg1, type2, arg2, type3, arg3,		\
	    type4, arg4)						\
	DTRACE_PROBE4(kvm__##name, type1, arg1, type2, arg2, 		\
	    type3, arg3, type4, arg4);

#define	KVM_TRACE5(name, type1, arg1, type2, arg2, type3, arg3,		\
	    type4, arg4, type5, arg5)					\
	DTRACE_PROBE5(kvm__##name, type1, arg1, type2, arg2, 		\
	    type3, arg3, type4, arg4, type5, arg5);

#define	KVM_TRACE6(name, type1, arg1, type2, arg2, type3, arg3,		\
	    type4, arg4, type5, arg5, type6, arg6)			\
	DTRACE_PROBE6(kvm__##name, type1, arg1, type2, arg2, 		\
	    type3, arg3, type4, arg4, type5, arg5, type6, arg6);

#endif
#endif /*SOLARIS_KVM_H*/
