
#include <sys/list.h>
#include <sys/types.h>
#include <sys/kstat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/bitmap.h>

#define KVM_API_VERSION 12   /* same as linux (for qemu compatability...) */

#ifndef offsetof
#define offsetof(s, m) ((size_t)(&((s *)0)->m))
#endif

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

enum kvm_bus {
	KVM_MMIO_BUS,
	KVM_PIO_BUS,
	KVM_NR_BUSES
};

struct kvm_vcpu_data {
	char vcpu_vhpt[VHPT_SIZE];
	char vcpu_vtlb[VTLB_SIZE];
	char vcpu_vpd[VPD_SIZE];
	char vcpu_struct[VCPU_STRUCT_SIZE];
};

struct kvm_vm_data {
	char kvm_p2m[KVM_P2M_SIZE];
	char kvm_vm_struct[KVM_VM_STRUCT_SIZE];
	char kvm_mem_dirty_log[KVM_MEM_DIRTY_LOG_SIZE];
	struct kvm_vcpu_data vcpu_data[KVM_MAX_VCPUS];
};

/*
 * Address types:
 *
 *  gva - guest virtual address
 *  gpa - guest physical address
 *  gfn - guest frame number
 *  hva - host virtual address
 *  hpa - host physical address
 *  hfn - host frame number
 */

typedef unsigned long  gva_t;
typedef uint64_t       gpa_t;
typedef unsigned long  gfn_t;

typedef unsigned long  hva_t;
typedef uint64_t       hpa_t;
typedef unsigned long  hfn_t;

/*
 * kvm_mmu_page_role, below, is defined as:
 *
 *   bits 0:3 - total guest paging levels (2-4, or zero for real mode)
 *   bits 4:7 - page table level for this shadow (1-4)
 *   bits 8:9 - page table quadrant for 2-level guests
 *   bit   16 - direct mapping of virtual to physical mapping at gfn
 *              used for real mode and two-dimensional paging
 *   bits 17:19 - common access permissions for all ptes in this shadow page
 */
union kvm_mmu_page_role {
	unsigned word;
	struct {
		unsigned glevels:4;
		unsigned level:4;
		unsigned quadrant:2;
		unsigned pad_for_nice_hex_output:6;
		unsigned direct:1;
		unsigned access:3;
		unsigned invalid:1;
		unsigned cr4_pge:1;
		unsigned nxe:1;
	}w;
};


/*
 * x86 supports 3 paging modes (4-level 64-bit, 3-level 64-bit, and 2-level
 * 32-bit).  The kvm_mmu structure abstracts the details of the current mmu
 * mode.
 */

struct kvm_vcpu;
struct kvm_mmu_page;

struct kvm_mmu {
	void (*new_cr3)(struct kvm_vcpu *vcpu);
	int (*page_fault)(struct kvm_vcpu *vcpu, gva_t gva, uint32_t err);
	void (*free)(struct kvm_vcpu *vcpu);
	gpa_t (*gva_to_gpa)(struct kvm_vcpu *vcpu, gva_t gva, uint32_t access,
			    uint32_t *error);
	void (*prefetch_page)(struct kvm_vcpu *vcpu,
			      struct kvm_mmu_page *page);
	int (*sync_page)(struct kvm_vcpu *vcpu,
			 struct kvm_mmu_page *sp);
	void (*invlpg)(struct kvm_vcpu *vcpu, gva_t gva);
	hpa_t root_hpa;
	int root_level;
	int shadow_root_level;
	union kvm_mmu_page_role base_role;

	uint64_t *pae_root;
	uint64_t rsvd_bits_mask[2][4];
};

struct kvm_pv_mmu_op_buffer {
	void *ptr;
	unsigned len;
	unsigned processed;
	char pad[2];
	char buf[512];  /* XXX aligned */
};

/*
 * We don't want allocation failures within the mmu code, so we preallocate
 * enough memory for a single page fault in a cache.
 */
#define KVM_NR_MEM_OBJS 40

#define KVM_NR_DB_REGS	4

struct kvm_mmu_memory_cache {
	int nobjs;
	void *objects[KVM_NR_MEM_OBJS];
};

/* Type, address-of, and value of an instruction's operand. */
struct operand {
	enum { OP_REG, OP_MEM, OP_IMM, OP_NONE } type;
	unsigned int bytes;
	unsigned long val, orig_val, *ptr;
};

struct i387_fxsave_struct {
	unsigned short			cwd; /* Control Word			*/
	unsigned short			swd; /* Status Word			*/
	unsigned short			twd; /* Tag Word			*/
	unsigned short			fop; /* Last Instruction Opcode		*/
	union {
		struct {
			uint64_t	rip; /* Instruction Pointer		*/
			uint64_t	rdp; /* Data Pointer			*/
		}v1;
		struct {
			uint32_t	fip; /* FPU IP Offset			*/
			uint32_t	fcs; /* FPU IP Selector			*/
			uint32_t	foo; /* FPU Operand Offset		*/
			uint32_t	fos; /* FPU Operand Selector		*/
		}v2;
	}v12;
	uint32_t			mxcsr;		/* MXCSR Register State */
	uint32_t			mxcsr_mask;	/* MXCSR Mask		*/

	/* 8*16 bytes for each FP-reg = 128 bytes:			*/
	uint32_t			st_space[32];

	/* 16*16 bytes for each XMM-reg = 256 bytes:			*/
	uint32_t			xmm_space[64];

	uint32_t			padding[12];

	union {
		uint32_t		padding1[12];
		uint32_t		sw_reserved[12];
	}v3;

} __attribute__((aligned(16)));

struct kvm_pio_request {
	unsigned long count;
	int cur_count;
	gva_t guest_gva;
	int in;
	int port;
	int size;
	int string;
	int down;
	int rep;
};

#define KVM_MAX_CPUID_ENTRIES 40
enum kvm_reg {
	VCPU_REGS_RAX = 0,
	VCPU_REGS_RCX = 1,
	VCPU_REGS_RDX = 2,
	VCPU_REGS_RBX = 3,
	VCPU_REGS_RSP = 4,
	VCPU_REGS_RBP = 5,
	VCPU_REGS_RSI = 6,
	VCPU_REGS_RDI = 7,
#ifdef CONFIG_X86_64
	VCPU_REGS_R8 = 8,
	VCPU_REGS_R9 = 9,
	VCPU_REGS_R10 = 10,
	VCPU_REGS_R11 = 11,
	VCPU_REGS_R12 = 12,
	VCPU_REGS_R13 = 13,
	VCPU_REGS_R14 = 14,
	VCPU_REGS_R15 = 15,
#endif
	VCPU_REGS_RIP,
	NR_VCPU_REGS
};

enum kvm_reg_ex {
	VCPU_EXREG_PDPTR = NR_VCPU_REGS,
};

struct kvm_cpuid_entry2 {
	uint32_t function;
	uint32_t index;
	uint32_t flags;
	uint32_t eax;
	uint32_t ebx;
	uint32_t ecx;
	uint32_t edx;
	uint32_t padding[3];
};

struct fetch_cache {
	unsigned char data[15];
	unsigned long start;
	unsigned long end;
};

struct decode_cache {
	unsigned char twobyte;
	unsigned char b;
	unsigned char lock_prefix;
	unsigned char rep_prefix;
	unsigned char op_bytes;
	unsigned char ad_bytes;
	unsigned char rex_prefix;
	struct operand src;
	struct operand src2;
	struct operand dst;
	unsigned char has_seg_override;
	unsigned char seg_override;
	unsigned int d;
	unsigned long regs[NR_VCPU_REGS];
	unsigned long eip, eip_orig;
	/* modrm */
	unsigned char modrm;
	unsigned char modrm_mod;
	unsigned char modrm_reg;
	unsigned char modrm_rm;
	unsigned char use_modrm_ea;
	unsigned char rip_relative;
	unsigned long modrm_ea;
	void *modrm_ptr;
	unsigned long modrm_val;
	struct fetch_cache fetch;
};


struct x86_emulate_ctxt {
	/* Register state before/after emulation. */
	struct kvm_vcpu *vcpu;

	unsigned long eflags;
	/* Emulated execution mode, represented by an X86EMUL_MODE value. */
	int mode;
	uint32_t cs_base;

	/* interruptibility state, as a result of execution of STI or MOV SS */
	int interruptibility;

	/* decode cache */
	struct decode_cache decode;
};

/*
 * These structs MUST NOT be changed.
 * They are the ABI between hypervisor and guest OS.
 * Both Xen and KVM are using this.
 *
 * pvclock_vcpu_time_info holds the system time and the tsc timestamp
 * of the last update. So the guest can use the tsc delta to get a
 * more precise system time.  There is one per virtual cpu.
 *
 * pvclock_wall_clock references the point in time when the system
 * time was zero (usually boot time), thus the guest calculates the
 * current wall clock by adding the system time.
 *
 * Protocol for the "version" fields is: hypervisor raises it (making
 * it uneven) before it starts updating the fields and raises it again
 * (making it even) when it is done.  Thus the guest can make sure the
 * time values it got are consistent by checking the version before
 * and after reading them.
 */

struct pvclock_vcpu_time_info {
	uint32_t   version;
	uint32_t   pad0;
	uint64_t   tsc_timestamp;
	uint64_t   system_time;
	uint32_t   tsc_to_system_mul;
	char    tsc_shift;
	unsigned char    pad[3];
} __attribute__((__packed__)); /* 32 bytes */

/* In the Intel processor's MTRR interface, the MTRR type is always held in
   an 8 bit field: */
typedef unsigned char mtrr_type;

#define MTRR_NUM_FIXED_RANGES 88
#define MTRR_MAX_VAR_RANGES 256

struct mtrr_var_range {
	uint32_t base_lo;
	uint32_t base_hi;
	uint32_t mask_lo;
	uint32_t mask_hi;
};

struct mtrr_state_type {
	struct mtrr_var_range var_ranges[MTRR_MAX_VAR_RANGES];
	mtrr_type fixed_ranges[MTRR_NUM_FIXED_RANGES];
	unsigned char enabled;
	unsigned char have_fixed;
	mtrr_type def_type;
};

#define	APIC_LDR	0xD0

struct kvm_lapic {
	unsigned long base_address;
#ifdef XXX
	struct kvm_io_device dev;
	struct kvm_timer lapic_timer;
#endif /*XXX*/
	uint32_t divide_count;
	struct kvm_vcpu *vcpu;
	int irr_pending;
	/* page is not page_t of solaris, but equivalent */
	struct page *regs_page;
	void *regs;
	gpa_t vapic_addr;
	struct page *vapic_page;
};

struct kvm_vcpu_arch {
	uint64_t host_tsc;
	/*
	 * rip and regs accesses must go through
	 * kvm_{register,rip}_{read,write} functions.
	 */
	unsigned long regs[NR_VCPU_REGS];
	uint32_t regs_avail;
	uint32_t regs_dirty;

	unsigned long cr0;
	unsigned long cr0_guest_owned_bits;
	unsigned long cr2;
	unsigned long cr3;
	unsigned long cr4;
	unsigned long cr4_guest_owned_bits;
	unsigned long cr8;
	uint32_t hflags;
	uint64_t pdptrs[4]; /* pae */
	uint64_t efer;
	uint64_t apic_base;
	struct kvm_lapic *apic;    /* kernel irqchip context */
	int32_t apic_arb_prio;
	int mp_state;
	int sipi_vector;
	uint64_t ia32_misc_enable_msr;
	char tpr_access_reporting;

	struct kvm_mmu mmu;
	/* only needed in kvm_pv_mmu_op() path, but it's hot so
	 * put it here to avoid allocation */
	struct kvm_pv_mmu_op_buffer mmu_op_buffer;

	struct kvm_mmu_memory_cache mmu_pte_chain_cache;
	struct kvm_mmu_memory_cache mmu_rmap_desc_cache;
	struct kvm_mmu_memory_cache mmu_page_cache;
	struct kvm_mmu_memory_cache mmu_page_header_cache;

	gfn_t last_pt_write_gfn;
	int   last_pt_write_count;
	uint64_t  *last_pte_updated;
	gfn_t last_pte_gfn;

	struct {
		gfn_t gfn;	/* presumed gfn during guest pte update */
		pfn_t pfn;	/* pfn corresponding to that gfn */
		unsigned long mmu_seq;
	} update_pte;

	struct i387_fxsave_struct host_fx_image;
	struct i387_fxsave_struct guest_fx_image;

	gva_t mmio_fault_cr2;
	struct kvm_pio_request pio;
	void *pio_data;

	unsigned char event_exit_inst_len;

	struct kvm_queued_exception {
		char pending;
		char has_error_code;
		unsigned char nr;
		uint32_t error_code;
	} exception;

	struct kvm_queued_interrupt {
		char pending;
		char soft;
		unsigned char nr;
	} interrupt;

	int halt_request; /* real mode on Intel only */

	int cpuid_nent;
	struct kvm_cpuid_entry2 cpuid_entries[KVM_MAX_CPUID_ENTRIES];
	/* emulate context */

	struct x86_emulate_ctxt emulate_ctxt;

	gpa_t time;
	struct pvclock_vcpu_time_info hv_clock;
	unsigned int hv_clock_tsc_khz;
	unsigned int time_offset;
	struct page *time_page;

	char nmi_pending;
	char nmi_injected;

	struct mtrr_state_type mtrr_state;
	uint32_t pat;

	int switch_db_regs;
	unsigned long db[KVM_NR_DB_REGS];
	unsigned long dr6;
	unsigned long dr7;
	unsigned long eff_db[KVM_NR_DB_REGS];

	uint64_t mcg_cap;
	uint64_t mcg_status;
	uint64_t mcg_ctl;
	uint64_t *mce_banks;

	/* used for guest single stepping over the given code position */
	unsigned short singlestep_cs;
	unsigned long singlestep_rip;
	/* fields used by HYPER-V emulation */
	uint64_t hv_vapic;
};

struct kvm_vcpu {
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
#ifdef NOTNOW
	wait_queue_head_t wq;
#endif /*NOTNOW*/
	int sigset_active;
	sigset_t sigset;
	struct kstat stat;

#ifdef CONFIG_HAS_IOMEM
	int mmio_needed;
	int mmio_read_completed;
	int mmio_is_write;
	int mmio_size;
	unsigned char mmio_data[8];
	gpa_t mmio_phys_addr;
#endif

	struct kvm_vcpu_arch arch;
};

struct kvm_memory_slot {
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
};

#define KVM_MEMORY_SLOTS 32  /* XXX assumes x86 */
#define KVM_PRIVATE_MEM_SLOTS 4 /* XXX assumes x86 */
#define TSS_PRIVATE_MEMSLOT			(KVM_MEMORY_SLOTS + 0)
#define APIC_ACCESS_PAGE_PRIVATE_MEMSLOT	(KVM_MEMORY_SLOTS + 1)
#define IDENTITY_PAGETABLE_PRIVATE_MEMSLOT	(KVM_MEMORY_SLOTS + 2)


struct kvm_memslots {
	int nmemslots;
	struct kvm_memory_slot memslots[KVM_MEMORY_SLOTS +
					KVM_PRIVATE_MEM_SLOTS];
};


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

extern kmutex_t kvm_lock;
extern list_t vm_list;

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

/* for KVM_GET_REGS and KVM_SET_REGS */
struct kvm_regs {
	/* out (KVM_GET_REGS) / in (KVM_SET_REGS) */
        uint64_t rax, rbx, rcx, rdx;
	uint64_t rsi, rdi, rsp, rbp;
	uint64_t r8,  r9,  r10, r11;
	uint64_t r12, r13, r14, r15;
	uint64_t rip, rflags;
};

/* for KVM_GET_LAPIC and KVM_SET_LAPIC */
#define KVM_APIC_REG_SIZE 0x400
struct kvm_lapic_state {
	char regs[KVM_APIC_REG_SIZE];
};

struct kvm_segment {
	uint64_t base;
	uint32_t limit;
	unsigned short selector;
	unsigned char  type;
	unsigned char  present, dpl, db, s, l, g, avl;
	unsigned char  unusable;
	unsigned char  padding;
};

struct kvm_dtable {
	uint64_t base;
	unsigned short limit;
	unsigned short padding[3];
};

/* Architectural interrupt line count. */
#define KVM_NR_INTERRUPTS 256


/* for KVM_GET_SREGS and KVM_SET_SREGS */
struct kvm_sregs {
	/* out (KVM_GET_SREGS) / in (KVM_SET_SREGS) */
	struct kvm_segment cs, ds, es, fs, gs, ss;
	struct kvm_segment tr, ldt;
	struct kvm_dtable gdt, idt;
	uint64_t cr0, cr2, cr3, cr4, cr8;
	uint64_t efer;
	uint64_t apic_base;
	uint64_t interrupt_bitmap[(KVM_NR_INTERRUPTS + 63) / 64];
};

/* When set in flags, include corresponding fields on KVM_SET_VCPU_EVENTS */
#define KVM_VCPUEVENT_VALID_NMI_PENDING	0x00000001
#define KVM_VCPUEVENT_VALID_SIPI_VECTOR	0x00000002

/* for KVM_GET/SET_VCPU_EVENTS */
struct kvm_vcpu_events {
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
};

#ifdef KVM_CAP_IRQ_ROUTING
struct kvm_irq_routing_irqchip {
	uint32_t irqchip;
	uint32_t pin;
};

struct kvm_irq_routing_msi {
	uint32_t address_lo;
	uint32_t address_hi;
	uint32_t data;
	uint32_t pad;
};

/* gsi routing entry types */
#define KVM_IRQ_ROUTING_IRQCHIP 1
#define KVM_IRQ_ROUTING_MSI 2

struct kvm_irq_routing_entry {
	uint32_t gsi;
	uint32_t type;
	uint32_t flags;
	uint32_t pad;
	union {
		struct kvm_irq_routing_irqchip irqchip;
		struct kvm_irq_routing_msi msi;
		uint32_t pad[8];
	} u;
};

struct kvm_irq_routing {
	uint32_t nr;
	uint32_t flags;
	struct kvm_irq_routing_entry entries[0];
};

#endif

#define KVM_MAX_MCE_BANKS 32
#define KVM_MCE_CAP_SUPPORTED MCG_CTL_P

struct kvm_vcpu;
struct kvm;

struct kvm_irq_ack_notifier {
	list_t link;
	unsigned gsi;
	void (*irq_acked)(struct kvm_irq_ack_notifier *kian);
};

#define KVM_ASSIGNED_MSIX_PENDING		0x1
struct kvm_guest_msix_entry {
	uint32_t vector;
	unsigned short entry;
	unsigned short flags;
};

struct kvm_assigned_dev_kernel {
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
};

#define NR_PTE_CHAIN_ENTRIES 5

struct kvm_pte_chain {
	uint64_t *parent_ptes[NR_PTE_CHAIN_ENTRIES];
	list_t link;
};

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


struct kvm_mmu_page {
	struct list_node link;
	struct list_node hash_link;

	struct list_node oos_link;

	/*
	 * The following two entries are used to key the shadow page in the
	 * hash table.
	 */
	gfn_t gfn;
	union kvm_mmu_page_role role;

	uint64_t *spt;
	/* hold the gfn of each spte inside spt */
	gfn_t *gfns;
	/*
	 * One bit set per slot which has memory
	 * in this shadow page.
	 */
	unsigned long slot_bitmap[BT_BITOUL(KVM_MEMORY_SLOTS + KVM_PRIVATE_MEM_SLOTS)];
	int multimapped;         /* More than one parent_pte? */
	int root_count;          /* Currently serving as active root */
	char unsync;
	unsigned int unsync_children;
	union {
		uint64_t *parent_pte;               /* !multimapped */
		list_t parent_ptes; /* hash list, multimapped, kvm_pte_chain */
	}v;
	unsigned long unsync_child_bitmap[BT_BITOUL(512)];
};

#define PT64_ROOT_LEVEL 4
#define PT32_ROOT_LEVEL 2
#define PT32E_ROOT_LEVEL 3

#define PT_PDPE_LEVEL 3
#define PT_DIRECTORY_LEVEL 2
#define PT_PAGE_TABLE_LEVEL 1

#define KVM_PAGE_ARRAY_NR 16

struct kvm_mmu_pages {
	struct mmu_page_and_offset {
		struct kvm_mmu_page *sp;
		unsigned int idx;
	} page[KVM_PAGE_ARRAY_NR];
	unsigned int nr;
};

struct mmu_page_path {
	struct kvm_mmu_page *parent[PT64_ROOT_LEVEL-1];
	unsigned int idx[PT64_ROOT_LEVEL-1];
};

/*
 * Save the original ist values for checking stack pointers during debugging
 */
struct orig_ist {
	unsigned long		ist[7];
};

#define	MXCSR_DEFAULT		0x1f80

struct i387_fsave_struct {
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
};


struct i387_soft_struct {
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
};

#define KVM_CPUID_FLAG_SIGNIFCANT_INDEX 1
#define KVM_CPUID_FLAG_STATEFUL_FUNC    2
#define KVM_CPUID_FLAG_STATE_READ_NEXT  4

/* for KVM_GET_FPU and KVM_SET_FPU */
struct kvm_fpu {
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
};


struct kvm_msr_entry {
	uint32_t index;
	uint32_t reserved;
	uint64_t data;
};

/* for KVM_GET_MSRS and KVM_SET_MSRS */
struct kvm_msrs {
	uint32_t nmsrs; /* number of msrs in entries */
	uint32_t pad;

	struct kvm_msr_entry entries[1];
};

/* for KVM_GET_MSR_INDEX_LIST */
struct kvm_msr_list {
	uint32_t nmsrs; /* number of msrs in entries */
	uint32_t indices[1];
};

struct kvm_debug_exit_arch {
	uint32_t exception;
	uint32_t pad;
	uint64_t pc;
	uint64_t dr6;
	uint64_t dr7;
};


/* for KVM_SET_CPUID2 */
struct kvm_cpuid2 {
	uint32_t nent;
	uint32_t padding;
	struct kvm_cpuid_entry2 entries[1];
};


#define X86_SHADOW_INT_MOV_SS  1
#define X86_SHADOW_INT_STI     2


struct pvclock_wall_clock {
	uint32_t   version;
	uint32_t   sec;
	uint32_t   nsec;
} __attribute__((__packed__));



#define MTRRphysBase_MSR(reg) (0x200 + 2 * (reg))
#define MTRRphysMask_MSR(reg) (0x200 + 2 * (reg) + 1)


struct kvm_mem_alias {
	gfn_t base_gfn;
	unsigned long npages;
	gfn_t target_gfn;
#define KVM_ALIAS_INVALID     1UL
	unsigned long flags;
};

#define KVM_ARCH_HAS_UNALIAS_INSTANTIATION

struct kvm_mem_aliases {
	struct kvm_mem_alias aliases[KVM_ALIAS_SLOTS];
	int naliases;
};

struct kvm_xen_hvm_config {
	uint32_t flags;
	uint32_t msr;
	uint64_t blob_addr_32;
	uint64_t blob_addr_64;
	unsigned char blob_size_32;
	unsigned char blob_size_64;
	unsigned char pad2[30];
};

struct kvm_arch {
	struct kvm_mem_aliases *aliases;

	unsigned int n_free_mmu_pages;
	unsigned int n_requested_mmu_pages;
	unsigned int n_alloc_mmu_pages;
	list_t mmu_page_hash[KVM_NUM_MMU_PAGES];
	/*
	 * Hash table of struct kvm_mmu_page.
	 */
	list_t active_mmu_pages;
	list_t assigned_dev_head;
	struct iommu_domain *iommu_domain;
	int iommu_flags;
	struct kvm_pic *vpic;
	struct kvm_ioapic *vioapic;
	struct kvm_pit *vpit;
	int vapics_in_nmi_mode;

	unsigned int tss_addr;
	struct page *apic_access_page;

	gpa_t wall_clock;

	struct page *ept_identity_pagetable;
	char ept_identity_pagetable_done;
	gpa_t ept_identity_map_addr;

	unsigned long irq_sources_bitmap;
	uint64_t vm_init_tsc;
	int64_t kvmclock_offset;

	struct kvm_xen_hvm_config xen_hvm_config;

	/* fields used by HYPER-V emulation */
	uint64_t hv_guest_os_id;
	uint64_t hv_hypercall;
};

#endif /*x86*/

struct kvm {
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
	struct kstat kvm_kstat;
	struct kvm_arch arch;
	volatile int users_count;
#ifdef KVM_COALESCED_MMIO_PAGE_OFFSET
	struct kvm_coalesced_mmio_dev *coalesced_mmio_dev;
	struct kvm_coalesced_mmio_ring *coalesced_mmio_ring;
#endif

	kmutex_t irq_lock;
#ifdef CONFIG_HAVE_KVM_IRQCHIP
	struct kvm_irq_routing_table *irq_routing;
	list_t mask_notifier_list;
	list_t irq_ack_notifier_list;
#endif

#ifdef XXX
#ifdef KVM_ARCH_WANT_MMU_NOTIFIER
	struct mmu_notifier mmu_notifier;
	unsigned long mmu_notifier_seq;
	long mmu_notifier_count;
#endif
#endif /*XXX*/
	int kvmid;  /* unique identifier for this kvm */
};

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
struct kvm_run {
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
};

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
#endif
#else /*XXX*/

#define _IOC_TYPECHECK(t) (sizeof(t))

#define GDT_ENTRY_TSS 8	/* needs two entries */

static inline void native_load_tr_desc(void)
{
	asm volatile("ltr %w0"::"q" (GDT_ENTRY_TSS*8));
}

#define load_TR_desc() native_load_tr_desc()

#endif



#define _IOR(type,nr,size)	_IOC(_IOC_READ,(type),(nr),(_IOC_TYPECHECK(size)))
#define _IOW(type,nr,size)	_IOC(_IOC_WRITE,(type),(nr),(_IOC_TYPECHECK(size)))
#define _IOWR(type,nr,size)	_IOC(_IOC_READ|_IOC_WRITE,(type),(nr),(_IOC_TYPECHECK(size)))
#define _IOR_BAD(type,nr,size)	_IOC(_IOC_READ,(type),(nr),sizeof(size))
#define _IOW_BAD(type,nr,size)	_IOC(_IOC_WRITE,(type),(nr),sizeof(size))
#define _IOWR_BAD(type,nr,size)	_IOC(_IOC_READ|_IOC_WRITE,(type),(nr),sizeof(size))

/* used to decode ioctl numbers.. */
#define _IOC_DIR(nr)		(((nr) >> _IOC_DIRSHIFT) & _IOC_DIRMASK)
#define _IOC_TYPE(nr)		(((nr) >> _IOC_TYPESHIFT) & _IOC_TYPEMASK)
#define _IOC_NR(nr)		(((nr) >> _IOC_NRSHIFT) & _IOC_NRMASK)
#define _IOC_SIZE(nr)		(((nr) >> _IOC_SIZESHIFT) & _IOC_SIZEMASK)

#define IOCSIZE_MASK	(_IOC_SIZEMASK << _IOC_SIZESHIFT)
#define IOCSIZE_SHIFT	(_IOC_SIZESHIFT)

#endif /* _ASM_GENERIC_IOCTL_H */

/* ioctl commands */
/* these need to match user level qemu ioctl calls */
#undef _IO  /* need to match what qemu passes in */
            /* probably better to change in qemu, but easier here */
#define _IO(x, y)	((x<<8)|y)  /* original is in /usr/include/sys/ioccom.h */
#define KVMIO 0xAE

/*
 * ioctls for vcpu fds
 */
#define KVM_RUN                   _IO(KVMIO,   0x80)
#define KVM_GET_REGS              _IOR(KVMIO,  0x81, struct kvm_regs)
#define KVM_SET_REGS              _IOW(KVMIO,  0x82, struct kvm_regs)
#define KVM_GET_SREGS             _IOR(KVMIO,  0x83, struct kvm_sregs)
#define KVM_SET_SREGS             _IOW(KVMIO,  0x84, struct kvm_sregs)
#define KVM_INTERRUPT             _IOW(KVMIO,  0x86, struct kvm_interrupt)
#define KVM_GET_FPU               _IOR(KVMIO,  0x8c, struct kvm_fpu)
#define KVM_SET_FPU               _IOW(KVMIO,  0x8d, struct kvm_fpu)
#define KVM_GET_MSRS              _IOWR(KVMIO, 0x88, struct kvm_msrs)
#define KVM_SET_MSRS              _IOW(KVMIO,  0x89, struct kvm_msrs)
#define KVM_GET_MP_STATE          _IOR(KVMIO,  0x98, struct kvm_mp_state)
#define KVM_SET_MP_STATE          _IOW(KVMIO,  0x99, struct kvm_mp_state)
/* Available with KVM_CAP_VCPU_EVENTS */
#define KVM_GET_VCPU_EVENTS       _IOR(KVMIO,  0x9f, struct kvm_vcpu_events)
#define KVM_SET_VCPU_EVENTS       _IOW(KVMIO,  0xa0, struct kvm_vcpu_events)


/*
 * ioctls for /dev/kvm fds:
 */
#define KVM_GET_API_VERSION       _IO(KVMIO,   0x00)
#define KVM_CREATE_VM             _IO(KVMIO,   0x01) /* returns a VM fd */
#define KVM_DESTROY_VM		  _IO(KVMIO,   0x0a)
#define KVM_GET_MSR_INDEX_LIST    _IOWR(KVMIO, 0x02, struct kvm_msr_list)

#define KVM_S390_ENABLE_SIE       _IO(KVMIO,   0x06)

#define KVM_GET_VCPU_MMAP_SIZE    _IO(KVMIO,   0x04) /* in bytes */

#define KVM_GET_SUPPORTED_CPUID   _IOWR(KVMIO, 0x05, struct kvm_cpuid2)

/*
 * ioctls for VM fds
 */

/*
 * KVM_CREATE_VCPU receives as a parameter the vcpu slot, and returns
 * a vcpu fd.
 */
#define KVM_CREATE_VCPU           _IO(KVMIO,   0x41)
#define KVM_GET_DIRTY_LOG         _IOW(KVMIO,  0x42, struct kvm_dirty_log)

#define KVM_SET_TSS_ADDR          _IO(KVMIO,   0x47)
#define KVM_REGISTER_COALESCED_MMIO \
			_IOW(KVMIO,  0x67, struct kvm_coalesced_mmio_zone)
#define KVM_UNREGISTER_COALESCED_MMIO \
			_IOW(KVMIO,  0x68, struct kvm_coalesced_mmio_zone)


/*
 * Check if a kvm extension is available.  Argument is extension number,
 * return is 1 (yes) or 0 (no, sorry).
 */
#define KVM_CHECK_EXTENSION       _IO(KVMIO,   0x03)

struct vmcs_config {
	int size;
	int order;
	uint32_t revision_id;
	uint32_t pin_based_exec_ctrl;
	uint32_t cpu_based_exec_ctrl;
	uint32_t cpu_based_2nd_exec_ctrl;
	uint32_t vmexit_ctrl;
	uint32_t vmentry_ctrl;
};
struct vmcs {
	uint32_t revision_id;
	uint32_t abort;
	char data[1];  /* size is read from MSR */
};

/* for KVM_INTERRUPT */
struct kvm_interrupt {
	/* in */
	uint32_t irq;
};

/* for KVM_GET_DIRTY_LOG */
struct kvm_dirty_log {
	uint32_t slot;
	uint32_t padding1;
	union {
		void  *dirty_bitmap; /* one bit per page */
		uint64_t padding2;
	}v;
};

/* for KVM_REGISTER_COALESCED_MMIO / KVM_UNREGISTER_COALESCED_MMIO */

struct kvm_coalesced_mmio_zone {
	uint64_t addr;
	uint32_t size;
	uint32_t pad;
};

struct kvm_coalesced_mmio {
	uint64_t phys_addr;
	uint32_t len;
	uint32_t pad;
	unsigned char  data[8];
};

struct kvm_coalesced_mmio_ring {
	uint32_t first, last;
	struct kvm_coalesced_mmio coalesced_mmio[1];
};

#define KVM_COALESCED_MMIO_MAX \
	((PAGESIZE - sizeof(struct kvm_coalesced_mmio_ring)) / \
	 sizeof(struct kvm_coalesced_mmio))


/* for KVM_SET_MP_STATE */

#define KVM_MP_STATE_RUNNABLE          0
#define KVM_MP_STATE_UNINITIALIZED     1
#define KVM_MP_STATE_INIT_RECEIVED     2
#define KVM_MP_STATE_HALTED            3
#define KVM_MP_STATE_SIPI_RECEIVED     4

struct kvm_mp_state {
	uint32_t mp_state;
};

#define KVM_SET_CPUID2            _IOW(KVMIO,  0x90, struct kvm_cpuid2)
#define KVM_GET_CPUID2            _IOWR(KVMIO, 0x91, struct kvm_cpuid2)

/* for kvm_memory_region::flags */
#define KVM_MEM_LOG_DIRTY_PAGES  1UL
#define KVM_MEMSLOT_INVALID      (1UL << 1)


/* for KVM_CREATE_MEMORY_REGION */
struct kvm_memory_region {
	uint32_t slot;
	uint32_t flags;
	uint64_t guest_phys_addr;
	uint64_t memory_size; /* bytes */
};

/* for KVM_SET_USER_MEMORY_REGION */
struct kvm_userspace_memory_region {
	uint32_t slot;
	uint32_t flags;
	uint64_t guest_phys_addr;
	uint64_t memory_size; /* bytes */
	uint64_t userspace_addr; /* start of the userspace allocated memory */
};

/* for KVM_SET_USER_MEMORY_REGION */
struct kvm_set_user_memory_ioc {
	struct kvm_userspace_memory_region kvm_userspace_map;
	int32_t kvmid;
	int32_t pad;
};

#ifdef XXX
#define KVM_SET_USER_MEMORY_REGION _IOW(KVMIO, 0x46, \
					struct kvm_userspace_memory_region)
#else
#define KVM_SET_USER_MEMORY_REGION _IOW(KVMIO, 0x46, \
					struct kvm_set_user_memory_ioc)
#endif /*XXX*/

/* for KVM_SET_TSS_ADDR ioctl */
struct kvm_tss {
	uint32_t addr;
	int kvmid;
};

/* for KVM_CREATE_VCPU */
struct kvm_vcpu_ioc {
	uint32_t id;  /*IN*/
	int32_t kvmid;
	uint64_t kvm_run_addr; /*OUT*/
	uint64_t kvm_vcpu_addr; /* OUT, id is not unique across VMs */
};


/* for KVM_SET_CPUID2/KVM_GET_CPUID2 */
struct kvm_cpuid2_ioc {
	struct cpuid_data *cpuid_data;
	uint64_t kvm_vcpu_addr;
};

/* LDT or TSS descriptor in the GDT. 16 bytes. */
struct ldttss_desc64 {
	unsigned short limit0;
	unsigned short base0;
	unsigned base1 : 8, type : 5, dpl : 2, p : 1;
	unsigned limit1 : 4, zero0 : 3, g : 1, base2 : 8;
	uint32_t base3;
	uint32_t zero1;
} __attribute__((packed));

struct vcpu_vmx {
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
};

#ifdef _KERNEL

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
struct preempt_ops {
	void (*sched_in)(struct preempt_notifier *notifier, int cpu);
	void (*sched_out)(struct preempt_notifier *notifier,
			  struct task_struct *next);
};

/**
 * preempt_notifier - key for installing preemption notifiers
 * @link: internal use
 * @ops: defines the notifier functions to be called
 *
 * Usually used in conjunction with container_of().
 */
struct preempt_notifier {
	struct hlist_node link;
	struct preempt_ops *ops;
};

void preempt_notifier_register(struct preempt_notifier *notifier);
void preempt_notifier_unregister(struct preempt_notifier *notifier);

static inline void preempt_notifier_init(struct preempt_notifier *notifier,
				     struct preempt_ops *ops)
{
	INIT_HLIST_NODE(&notifier->link);
	notifier->ops = ops;
}

#endif /*XXX*/
#endif /*CONFIG_PREEMPT_NOTIFIERS*/
struct cpuid_data {
        struct kvm_cpuid2 cpuid;
        struct kvm_cpuid_entry2 entries[100];
} __attribute__((packed)) cpuid_data;

static inline unsigned long kvm_dirty_bitmap_bytes(struct kvm_memory_slot *memslot)
{
	/* XXX */
	/* 	return ALIGN(memslot->npages, BITS_PER_LONG) / 8; */
	return ((BT_BITOUL(memslot->npages)) / 8);
}

#define for_each_unsync_children(bitmap, idx)		\
	for (idx = bt_getlowbit(bitmap, 0, 512);	\
	     idx < 512;					\
	     idx = bt_getlowbit(bitmap, idx+1, 512))

#define PT_PAGE_SIZE_MASK (1ULL << 7)

#define INVALID_PAGE (~(hpa_t)0)

struct kvm_x86_ops {
	int (*cpu_has_kvm_support)(void);          /* __init */
	int (*disabled_by_bios)(void);             /* __init */
	int (*hardware_enable)(void *dummy);
	void (*hardware_disable)(void *dummy);
	void (*check_processor_compatibility)(void *rtn);
	int (*hardware_setup)(void);               /* __init */
	void (*hardware_unsetup)(void);            /* __exit */
	int (*cpu_has_accelerated_tpr)(void);
	void (*cpuid_update)(struct kvm_vcpu *vcpu);

	/* Create, but do not attach this VCPU */
	struct kvm_vcpu *(*vcpu_create)(struct kvm *kvm, unsigned id);
	void (*vcpu_free)(struct kvm_vcpu *vcpu);
	int (*vcpu_reset)(struct kvm_vcpu *vcpu);

	void (*prepare_guest_switch)(struct kvm_vcpu *vcpu);
	void (*vcpu_load)(struct kvm_vcpu *vcpu, int cpu);
	void (*vcpu_put)(struct kvm_vcpu *vcpu);
	void (*set_guest_debug)(struct kvm_vcpu *vcpu,
#ifdef XXX
				struct kvm_guest_debug *dbg);
#else
	void *dbg);
#endif

	int (*get_msr)(struct kvm_vcpu *vcpu, uint32_t msr_index, uint64_t *pdata);
	int (*set_msr)(struct kvm_vcpu *vcpu, uint32_t msr_index, uint64_t data);
	uint64_t (*get_segment_base)(struct kvm_vcpu *vcpu, int seg);
	void (*get_segment)(struct kvm_vcpu *vcpu,
			    struct kvm_segment *var, int seg);
	int (*get_cpl)(struct kvm_vcpu *vcpu);
	void (*set_segment)(struct kvm_vcpu *vcpu,
			    struct kvm_segment *var, int seg);
	void (*get_cs_db_l_bits)(struct kvm_vcpu *vcpu, int *db, int *l);
	void (*decache_cr0_guest_bits)(struct kvm_vcpu *vcpu);
	void (*decache_cr4_guest_bits)(struct kvm_vcpu *vcpu);
	void (*set_cr0)(struct kvm_vcpu *vcpu, unsigned long cr0);
	void (*set_cr3)(struct kvm_vcpu *vcpu, unsigned long cr3);
	void (*set_cr4)(struct kvm_vcpu *vcpu, unsigned long cr4);
	void (*set_efer)(struct kvm_vcpu *vcpu, uint64_t efer);
	void (*get_idt)(struct kvm_vcpu *vcpu, struct descriptor_table *dt);
	void (*set_idt)(struct kvm_vcpu *vcpu, struct descriptor_table *dt);
	void (*get_gdt)(struct kvm_vcpu *vcpu, struct descriptor_table *dt);
	void (*set_gdt)(struct kvm_vcpu *vcpu, struct descriptor_table *dt);
	int (*get_dr)(struct kvm_vcpu *vcpu, int dr, unsigned long *dest);
	int (*set_dr)(struct kvm_vcpu *vcpu, int dr, unsigned long value);
	void (*cache_reg)(struct kvm_vcpu *vcpu, enum kvm_reg reg);
	unsigned long (*get_rflags)(struct kvm_vcpu *vcpu);
	void (*set_rflags)(struct kvm_vcpu *vcpu, unsigned long rflags);
	void (*fpu_activate)(struct kvm_vcpu *vcpu);
	void (*fpu_deactivate)(struct kvm_vcpu *vcpu);

	void (*tlb_flush)(struct kvm_vcpu *vcpu);

	void (*run)(struct kvm_vcpu *vcpu);
	int (*handle_exit)(struct kvm_vcpu *vcpu);
	void (*skip_emulated_instruction)(struct kvm_vcpu *vcpu);
	void (*set_interrupt_shadow)(struct kvm_vcpu *vcpu, int mask);
	uint32_t (*get_interrupt_shadow)(struct kvm_vcpu *vcpu, int mask);
	void (*patch_hypercall)(struct kvm_vcpu *vcpu,
				unsigned char *hypercall_addr);
	void (*set_irq)(struct kvm_vcpu *vcpu);
	void (*set_nmi)(struct kvm_vcpu *vcpu);
	void (*queue_exception)(struct kvm_vcpu *vcpu, unsigned nr,
				int has_error_code, uint32_t error_code);
	int (*interrupt_allowed)(struct kvm_vcpu *vcpu);
	int (*nmi_allowed)(struct kvm_vcpu *vcpu);
	int (*get_nmi_mask)(struct kvm_vcpu *vcpu);
	void (*set_nmi_mask)(struct kvm_vcpu *vcpu, int masked);
	void (*enable_nmi_window)(struct kvm_vcpu *vcpu);
	void (*enable_irq_window)(struct kvm_vcpu *vcpu);
	void (*update_cr8_intercept)(struct kvm_vcpu *vcpu, int tpr, int irr);
	int (*set_tss_addr)(struct kvm *kvm, unsigned int addr);
	int (*get_tdp_level)(void);
	uint64_t (*get_mt_mask)(struct kvm_vcpu *vcpu, gfn_t gfn, int is_mmio);
	int (*get_lpage_level)(void);
	int (*rdtscp_supported)(void);

	const struct trace_print_flags *exit_reasons_str;
};

#endif

