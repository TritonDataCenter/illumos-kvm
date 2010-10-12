
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
#define KVM_MAX_VCPUS	(KVM_VM_DATA_SIZE - KVM_P2M_SIZE - KVM_VM_STRUCT_SIZE -\
			KVM_MEM_DIRTY_LOG_SIZE) / sizeof(struct kvm_vcpu_data)
#define KVM_MAX_MEM_SIZE (KVM_P2M_SIZE >> 3 << PAGE_SHIFT)

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

struct kvm_memslots {
	int nmemslots;
	struct kvm_memory_slot memslots[KVM_MEMORY_SLOTS +
					KVM_PRIVATE_MEM_SLOTS];
};


#ifdef x86

#define KVM_ALIAS_SLOTS 4

#define KVM_HPAGE_SHIFT(x)	(PAGE_SHIFT + (((x) - 1) * 9))
#define KVM_HPAGE_SIZE(x)	(1UL << KVM_HPAGE_SHIFT(x))
#define KVM_HPAGE_MASK(x)	(~(KVM_HPAGE_SIZE(x) - 1))
#define KVM_PAGES_PER_HPAGE(x)	(KVM_HPAGE_SIZE(x) / PAGE_SIZE)

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
#define KVM_MAX_CPUID_ENTRIES 40
#define KVM_NR_FIXED_MTRR_REGION 88
#define KVM_NR_VAR_MTRR 8

extern kmutex_t kvm_lock;
extern list_t vm_list;

#define KVM_USERSPACE_IRQ_SOURCE_ID	0

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

enum {
	VCPU_SREG_ES,
	VCPU_SREG_CS,
	VCPU_SREG_SS,
	VCPU_SREG_DS,
	VCPU_SREG_FS,
	VCPU_SREG_GS,
	VCPU_SREG_TR,
	VCPU_SREG_LDTR,
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

#define NR_PTE_CHAIN_ENTRIES 5

struct kvm_pte_chain {
	uint64_t *parent_ptes[NR_PTE_CHAIN_ENTRIES];
	list_t link;
};

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

struct kvm_mmu_page {
	list_t link;
	list_t hash_link;

	list_t oos_link;

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

struct kvm_pv_mmu_op_buffer {
	void *ptr;
	unsigned len;
	unsigned processed;
	char pad[2];
	char buf[512];  /* XXX aligned */
};

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

/*
 * x86 supports 3 paging modes (4-level 64-bit, 3-level 64-bit, and 2-level
 * 32-bit).  The kvm_mmu structure abstracts the details of the current mmu
 * mode.
 */
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
/* Type, address-of, and value of an instruction's operand. */
struct operand {
	enum { OP_REG, OP_MEM, OP_IMM, OP_NONE } type;
	unsigned int bytes;
	unsigned long val, orig_val, *ptr;
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

#define X86_SHADOW_INT_MOV_SS  1
#define X86_SHADOW_INT_STI     2

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

struct pvclock_wall_clock {
	uint32_t   version;
	uint32_t   sec;
	uint32_t   nsec;
} __attribute__((__packed__));

struct mtrr_var_range {
	uint32_t base_lo;
	uint32_t base_hi;
	uint32_t mask_lo;
	uint32_t mask_hi;
};

/* In the Intel processor's MTRR interface, the MTRR type is always held in
   an 8 bit field: */
typedef unsigned char mtrr_type;

#define MTRR_NUM_FIXED_RANGES 88
#define MTRR_MAX_VAR_RANGES 256

struct mtrr_state_type {
	struct mtrr_var_range var_ranges[MTRR_MAX_VAR_RANGES];
	mtrr_type fixed_ranges[MTRR_NUM_FIXED_RANGES];
	unsigned char enabled;
	unsigned char have_fixed;
	mtrr_type def_type;
};

#define MTRRphysBase_MSR(reg) (0x200 + 2 * (reg))
#define MTRRphysMask_MSR(reg) (0x200 + 2 * (reg) + 1)

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
	list_t vm_list;
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

#ifdef KVM_ARCH_WANT_MMU_NOTIFIER
	struct mmu_notifier mmu_notifier;
	unsigned long mmu_notifier_seq;
	long mmu_notifier_count;
#endif
};

struct kvm_vcpu {
	struct kvm *kvm;
#ifdef CONFIG_PREEMPT_NOTIFIERS
	struct preempt_notifier preempt_notifier;
#endif
	int vcpu_id;
	struct mutex mutex;
	int   cpu;
	struct kvm_run *run;
	unsigned long requests;
	unsigned long guest_debug;
	int srcu_idx;

	int fpu_active;
	int guest_fpu_loaded;
	kmutex_t wqmp;
	kcondvar_t wq;
	int sigset_active;
	sigset_t sigset;
	struct kstat kvm_vcpu_stat;

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

#ifdef __KERNEL__
/* provoke compile error for invalid uses of size argument */
extern unsigned int __invalid_size_argument_for_IOC;
#define _IOC_TYPECHECK(t) \
	((sizeof(t) == sizeof(t[1]) && \
	  sizeof(t) < (1 << _IOC_SIZEBITS)) ? \
	  sizeof(t) : __invalid_size_argument_for_IOC)
#else
#define _IOC_TYPECHECK(t) (sizeof(t))
#endif

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

#define KVMIO 0xAE

/*
 * ioctls for /dev/kvm fds:
 */
#define KVM_GET_API_VERSION       _IO(KVMIO,   0x00)
#define KVM_CREATE_VM             _IO(KVMIO,   0x01) /* returns a VM fd */
#define KVM_GET_MSR_INDEX_LIST    _IOWR(KVMIO, 0x02, struct kvm_msr_list)

#define KVM_S390_ENABLE_SIE       _IO(KVMIO,   0x06)

#define KVM_GET_VCPU_MMAP_SIZE    _IO(KVMIO,   0x04) /* in bytes */

/*
 * Check if a kvm extension is available.  Argument is extension number,
 * return is 1 (yes) or 0 (no, sorry).
 */
#define KVM_CHECK_EXTENSION       _IO(KVMIO,   0x03)

struct vmcs {
	uint32_t revision_id;
	uint32_t abort;
	char data[0];  /* size is read from MSR */
};
