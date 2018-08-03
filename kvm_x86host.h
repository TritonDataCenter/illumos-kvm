/*
 * GPL HEADER START
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * GPL HEADER END
 *
 * Copyright 2011 various Linux Kernel contributors.
 * Copyright 2018 Joyent, Inc.
 */

#ifndef __KVM_X86_HOST_H
#define	__KVM_X86_HOST_H

#include <sys/types.h>
#include <sys/list.h>
#include <sys/mutex.h>
#include <sys/avl.h>
#include <sys/bitmap.h>
#include <vm/page.h>
#include <sys/pte.h>
#include <sys/regset.h>
#include <sys/hma.h>

#include "kvm.h"
#include "kvm_types.h"

#ifndef offsetof
#define	offsetof(s, m) ((size_t)(&((s *)0)->m))
#endif

#define	MCG_CTL_P		(1ULL<<8)    /* MCG_CTL register available */
#define	KVM_MAX_MCE_BANKS 32
#define	KVM_MCE_CAP_SUPPORTED MCG_CTL_P

#define	KVM_MAX_VCPUS	64
#define	KVM_MEMORY_SLOTS	32
/* memory slots that are not exposted to userspace */
#define	KVM_PRIVATE_MEM_SLOTS 4 /* x86 specific */

#define	KVM_PIO_PAGE_OFFSET	1
#define	KVM_COALESCED_MMIO_PAGE_OFFSET	2
#define	KVM_VCPU_MMAP_LENGTH	3

#define	CR3_PAE_RESERVED_BITS ((X86_CR3_PWT | X86_CR3_PCD) - 1)
#define	CR3_NONPAE_RESERVED_BITS ((PAGESIZE-1) & ~(X86_CR3_PWT | X86_CR3_PCD))
#define	CR3_L_MODE_RESERVED_BITS (CR3_NONPAE_RESERVED_BITS |	\
    0xFFFFFF0000000000ULL)

#define	INVALID_PAGE (~(hpa_t)0)
#define	UNMAPPED_GVA (~(gpa_t)0)

/* KVM Hugepage definitions for x86 */
#define	KVM_NR_PAGE_SIZES	3
#define	KVM_HPAGE_SHIFT(x)	(PAGESHIFT + (((x) - 1) * 9))
#define	KVM_HPAGE_SIZE(x)	(1UL << KVM_HPAGE_SHIFT(x))
#define	KVM_HPAGE_MASK(x)	(~(KVM_HPAGE_SIZE(x) - 1))
#define	KVM_PAGES_PER_HPAGE(x)	(KVM_HPAGE_SIZE(x) / PAGESIZE)

#define	DE_VECTOR 0
#define	DB_VECTOR 1
#define	BP_VECTOR 3
#define	OF_VECTOR 4
#define	BR_VECTOR 5
#define	UD_VECTOR 6
#define	NM_VECTOR 7
#define	DF_VECTOR 8
#define	TS_VECTOR 10
#define	NP_VECTOR 11
#define	SS_VECTOR 12
#define	GP_VECTOR 13
#define	PF_VECTOR 14
#define	MF_VECTOR 16
#define	AC_VECTOR 17
#define	MC_VECTOR 18

#define	SELECTOR_TI_MASK (1 << 2)
#define	SELECTOR_RPL_MASK 0x03

#define	IOPL_SHIFT 12

#define	KVM_ALIAS_SLOTS 4

#define	KVM_PERMILLE_MMU_PAGES 20
#define	KVM_MIN_ALLOC_MMU_PAGES 64
#define	KVM_MMU_HASH_SHIFT 10
#define	KVM_NUM_MMU_PAGES (1 << KVM_MMU_HASH_SHIFT)
#define	KVM_MIN_FREE_MMU_PAGES 5
#define	KVM_REFILL_PAGES 25
#define	KVM_MAX_CPUID_ENTRIES 40
#define	KVM_NR_FIXED_MTRR_REGION 88
#define	KVM_NR_VAR_MTRR 8

struct kvm_vcpu;
struct kvm;

enum kvm_reg {
	VCPU_REGS_RAX = 0,
	VCPU_REGS_RCX = 1,
	VCPU_REGS_RDX = 2,
	VCPU_REGS_RBX = 3,
	VCPU_REGS_RSP = 4,
	VCPU_REGS_RBP = 5,
	VCPU_REGS_RSI = 6,
	VCPU_REGS_RDI = 7,
	VCPU_REGS_R8 = 8,
	VCPU_REGS_R9 = 9,
	VCPU_REGS_R10 = 10,
	VCPU_REGS_R11 = 11,
	VCPU_REGS_R12 = 12,
	VCPU_REGS_R13 = 13,
	VCPU_REGS_R14 = 14,
	VCPU_REGS_R15 = 15,
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

#include "kvm_emulate.h"

#define	KVM_NR_MEM_OBJS 40

#define	KVM_NR_DB_REGS	4

#define	DR6_BD		(1 << 13)
#define	DR6_BS		(1 << 14)
#define	DR6_FIXED_1	0xffff0ff0
#define	DR6_VOLATILE	0x0000e00f

#define	DR7_BP_EN_MASK	0x000000ff
#define	DR7_GE		(1 << 9)
#define	DR7_GD		(1 << 13)
#define	DR7_FIXED_1	0x00000400
#define	DR7_VOLATILE	0xffff23ff

/*
 * We don't want allocation failures within the mmu code, so we preallocate
 * enough memory for a single page fault in a cache.
 */
#define	KVM_NR_MEM_OBJS 40

struct kvm_objects {
	void *kma_object;
	void *kpm_object;
};

typedef struct kvm_mmu_memory_cache {
	int nobjs;  /* current number free in cache */
	struct kvm_objects objects[KVM_NR_MEM_OBJS];
} kvm_mmu_memory_cache_t;

#define	NR_PTE_CHAIN_ENTRIES 5

typedef struct kvm_pte_chain {
	uint64_t *parent_ptes[NR_PTE_CHAIN_ENTRIES];
	struct list_node link;
} kvm_pte_chain_t;

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
		unsigned cr0_wp:1;
	};
};

typedef struct kvm_mmu_page {
	avl_node_t kmp_avlnode;
	struct list_node link;
	struct list_node hash_link;

	struct list_node oos_link;

	hpa_t hpa;
	/*
	 * The following two entries are used to key the shadow page in the
	 * hash table.
	 */
	gfn_t gfn;
	union kvm_mmu_page_role role;

	uint64_t *spt;
	char *sptkma;
	uintptr_t kmp_avlspt;
	/* hold the gfn of each spte inside spt */
	gfn_t *gfns;
	char *gfnskma;
	/*
	 * One bit set per slot which has memory
	 * in this shadow page.
	 */
	unsigned long slot_bitmap[BT_BITOUL(KVM_MEMORY_SLOTS +
	    KVM_PRIVATE_MEM_SLOTS)];
	int multimapped;	/* More than one parent_pte? */
	int root_count;		/* Currently serving as active root */
	int unsync;
	unsigned int unsync_children;
	union {
		uint64_t *parent_pte;	/* !multimapped */
		list_t parent_ptes;	/* multimapped, kvm_pte_chain */
	};
	struct kvm_vcpu *vcpu;  /* needed for free */
	unsigned long unsync_child_bitmap[BT_BITOUL(512)];
} kvm_mmu_page_t;

typedef struct kvm_pv_mmu_op_buffer {
	void *ptr;
	unsigned len;
	unsigned processed;
	char pad[2];
	char buf[512];
} kvm_pv_mmu_op_buffer_t;

typedef struct kvm_pio_request {
	unsigned long count;
	int cur_count;
	gva_t guest_gva;
	int in;
	int port;
	int size;
	int string;
	int down;
	int rep;
} kvm_pio_request_t;

/*
 * x86 supports 3 paging modes (4-level 64-bit, 3-level 64-bit, and 2-level
 * 32-bit).  The kvm_mmu structure abstracts the details of the current mmu
 * mode.
 */
typedef struct kvm_mmu {
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
	void *alloc_pae_root;
	uint64_t rsvd_bits_mask[2][4];
} kvm_mmu_t;

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

struct pvclock_wall_clock {
	uint32_t   version;
	uint32_t   sec;
	uint32_t   nsec;
} __attribute__((__packed__));

typedef struct pvclock_wall_clock pvclock_wall_clock_t;

struct pvclock_vcpu_time_info {
	uint32_t   version;
	uint32_t   pad0;
	uint64_t   tsc_timestamp;
	uint64_t   system_time;
	uint32_t   tsc_to_system_mul;
	char    tsc_shift;
	unsigned char    flags;
	unsigned char    pad[2];
} __attribute__((__packed__)); /* 32 bytes */

typedef struct pvclock_vcpu_time_info pvclock_vcpu_time_info_t;

/* Values for pvclock_vcpu_time_info_t`flags: */
#define PVCLOCK_TSC_STABLE_BIT  (1 << 0)

typedef struct msi_msg {
	uint32_t	address_lo;	/* low 32 bits of msi msg. address */
	uint32_t	address_hi;	/* high 32 bits of msi msg. address */
	uint32_t	data;		/* 16 bits of msi msg. data */
} msi_msg_t;

/*
 * In the Intel processor's MTRR interface, the MTRR type is always held in an 8
 * bit field:
 */
typedef unsigned char mtrr_type;

#define	MTRR_NUM_FIXED_RANGES 88
#define	MTRR_MAX_VAR_RANGES 256

typedef struct mtrr_var_range {
	uint32_t base_lo;
	uint32_t base_hi;
	uint32_t mask_lo;
	uint32_t mask_hi;
} mtrr_var_range_t;

typedef struct mtrr_state_type {
	struct mtrr_var_range var_ranges[MTRR_MAX_VAR_RANGES];
	mtrr_type fixed_ranges[MTRR_NUM_FIXED_RANGES];
	unsigned char enabled;
	unsigned char have_fixed;
	mtrr_type def_type;
} mtrr_state_type_t;

typedef struct kvm_vcpu_arch {
	uint64_t tsc_offset;
	/*
	 * rip and regs accesses must go through
	 * kvm_{register,rip}_{read,write} functions.
	 */
	unsigned long regs[NR_VCPU_REGS];
	uint64_t regs_avail;
	uint64_t regs_dirty;

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
	int tpr_access_reporting;

	struct kvm_mmu mmu;
	/*
	 * only needed in kvm_pv_mmu_op() path, but it's hot so
	 * put it here to avoid allocation
	 */
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

	hma_fpu_t *guest_fpu;

	gva_t mmio_fault_cr2;
	struct kvm_pio_request pio;
	void *pio_data;

	uint8_t event_exit_inst_len;

	struct kvm_queued_exception {
		int pending;
		int has_error_code;
		uint8_t nr;
		uint32_t error_code;
	} exception;

	struct kvm_queued_interrupt {
		int pending;
		int soft;
		uint8_t nr;
	} interrupt;

	int halt_request; /* real mode on Intel only */

	int cpuid_nent;
	struct kvm_cpuid_entry2 cpuid_entries[KVM_MAX_CPUID_ENTRIES];
	/* emulate context */

	struct x86_emulate_ctxt emulate_ctxt;

	gpa_t time_addr;
	gpa_t time_val;
	hrtime_t time_update;

	int nmi_pending;
	int nmi_injected;

	struct mtrr_state_type mtrr_state;
	uint64_t pat;

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
	uint16_t singlestep_cs;
	unsigned long singlestep_rip;
	/* fields used by HYPER-V emulation */
	uint64_t hv_vapic;
} kvm_vcpu_arch_t;

typedef struct kvm_mem_alias {
	gfn_t base_gfn;
	unsigned long npages;
	gfn_t target_gfn;
#define	KVM_ALIAS_INVALID	1UL
	unsigned long flags;
} kvm_mem_alias_t;

#define	KVM_ARCH_HAS_UNALIAS_INSTANTIATION

typedef struct kvm_mem_aliases {
	struct kvm_mem_alias aliases[KVM_ALIAS_SLOTS];
	int naliases;
} kvm_mem_aliases_t;

typedef struct kvm_xen_hvm_config {
	uint32_t flags;
	uint32_t msr;
	uint64_t blob_addr_32;
	uint64_t blob_addr_64;
	unsigned char blob_size_32;
	unsigned char blob_size_64;
	unsigned char pad2[30];
} kvm_xen_hvm_config_t;

typedef struct kvm_arch {
	struct kvm_mem_aliases *aliases;

	unsigned int n_free_mmu_pages;
	unsigned int n_requested_mmu_pages;
	unsigned int n_alloc_mmu_pages;
	list_t mmu_page_hash[KVM_NUM_MMU_PAGES];
	/*
	 * Hash table of struct kvm_mmu_page.
	 */
	list_t active_mmu_pages;  /* list of all kvm_mmu_page */
	list_t assigned_dev_head;
	struct iommu_domain *iommu_domain;
	int iommu_flags;
	struct kvm_pic *vpic;
	struct kvm_ioapic *vioapic;
	struct kvm_pit *vpit;
	int vapics_in_nmi_mode;

	uint64_t tss_addr;
	page_t *apic_access_page;

	gpa_t wall_clock;

	page_t *ept_identity_pagetable;
	int ept_identity_pagetable_done;
	gpa_t ept_identity_map_addr;

	unsigned long irq_sources_bitmap;
	uint64_t tsc_offset;

	struct timespec boot_wallclock;
	hrtime_t boot_hrtime;

	struct kvm_xen_hvm_config xen_hvm_config;

	uint8_t need_xcr0;
	uint64_t host_xcr0;

	/* fields used by HYPER-V emulation */
	uint64_t hv_guest_os_id;
	uint64_t hv_hypercall;
} kvm_arch_t;

typedef struct kvm_vm_stat {
	uint32_t mmu_shadow_zapped;
	uint32_t mmu_pte_write;
	uint32_t mmu_pte_updated;
	uint32_t mmu_pde_zapped;
	uint32_t mmu_flooded;
	uint32_t mmu_recycled;
	uint32_t mmu_cache_miss;
	uint32_t mmu_unsync;
	uint32_t remote_tlb_flush;
	uint32_t lpages;
} kvm_vm_stat_t;

typedef struct kvm_vcpu_stat {
	uint32_t pf_fixed;
	uint32_t pf_guest;
	uint32_t tlb_flush;
	uint32_t invlpg;

	uint32_t exits;
	uint32_t io_exits;
	uint32_t mmio_exits;
	uint32_t signal_exits;
	uint32_t irq_window_exits;
	uint32_t nmi_window_exits;
	uint32_t halt_exits;
	uint32_t halt_wakeup;
	uint32_t request_irq_exits;
	uint32_t irq_exits;
	uint32_t host_state_reload;
	uint32_t efer_reload;
	uint32_t fpu_reload;
	uint32_t insn_emulation;
	uint32_t insn_emulation_fail;
	uint32_t hypercalls;
	uint32_t irq_injections;
	uint32_t nmi_injections;
} kvm_vcpu_stat_t;

struct descriptor_table {
	unsigned short limit;
	unsigned long base;
} __attribute__((packed));

typedef struct descriptor_table descriptor_table_t;

typedef struct kvm_x86_ops {
	int (*cpu_has_kvm_support)(void);
	int (*disabled_by_bios)(void);
	int (*hardware_enable)(void *);
	void (*hardware_disable)(void *);
	void (*check_processor_compatibility)(void *);
	int (*hardware_setup)(void);
	void (*hardware_unsetup)(void);
	int (*cpu_has_accelerated_tpr)(void);
	void (*cpuid_update)(struct kvm_vcpu *);

	/* Create, but do not attach this VCPU */
	struct kvm_vcpu *(*vcpu_create)(struct kvm *, unsigned);
	void (*vcpu_free)(struct kvm_vcpu *vcpu);
	int (*vcpu_reset)(struct kvm_vcpu *vcpu);

	void (*prepare_guest_switch)(struct kvm_vcpu *);
	void (*vcpu_load)(struct kvm_vcpu *, int);
	void (*vcpu_put)(struct kvm_vcpu *);

	void (*set_guest_debug)(struct kvm_vcpu *, struct kvm_guest_debug *);
	int (*get_msr)(struct kvm_vcpu *, uint32_t, uint64_t *);
	int (*set_msr)(struct kvm_vcpu *, uint32_t, uint64_t);
	uint64_t (*get_segment_base)(struct kvm_vcpu *, int);
	void (*get_segment)(struct kvm_vcpu *, struct kvm_segment *, int);
	int (*get_cpl)(struct kvm_vcpu *);
	void (*set_segment)(struct kvm_vcpu *, struct kvm_segment *, int);
	void (*get_cs_db_l_bits)(struct kvm_vcpu *, int *, int *);
	void (*decache_cr0_guest_bits)(struct kvm_vcpu *);
	void (*decache_cr4_guest_bits)(struct kvm_vcpu *);
	void (*set_cr0)(struct kvm_vcpu *, unsigned long);
	void (*set_cr3)(struct kvm_vcpu *, unsigned long);
	void (*set_cr4)(struct kvm_vcpu *, unsigned long);
	void (*set_efer)(struct kvm_vcpu *, uint64_t);
	void (*get_idt)(struct kvm_vcpu *, struct descriptor_table *);
	void (*set_idt)(struct kvm_vcpu *, struct descriptor_table *);
	void (*get_gdt)(struct kvm_vcpu *, struct descriptor_table *);
	void (*set_gdt)(struct kvm_vcpu *, struct descriptor_table *);
	int (*get_dr)(struct kvm_vcpu *, int, unsigned long *);
	int (*set_dr)(struct kvm_vcpu *, int, unsigned long);
	void (*cache_reg)(struct kvm_vcpu *, enum kvm_reg);
	unsigned long (*get_rflags)(struct kvm_vcpu *);
	void (*set_rflags)(struct kvm_vcpu *, unsigned long);
	void (*fpu_activate)(struct kvm_vcpu *);
	void (*fpu_deactivate)(struct kvm_vcpu *);

	void (*tlb_flush)(struct kvm_vcpu *);

	void (*run)(struct kvm_vcpu *);
	int (*handle_exit)(struct kvm_vcpu *);
	void (*skip_emulated_instruction)(struct kvm_vcpu *);
	void (*set_interrupt_shadow)(struct kvm_vcpu *, int);
	uint32_t (*get_interrupt_shadow)(struct kvm_vcpu *, int);
	void (*patch_hypercall)(struct kvm_vcpu *, unsigned char *);
	void (*set_irq)(struct kvm_vcpu *);
	void (*set_nmi)(struct kvm_vcpu *);
	void (*queue_exception)(struct kvm_vcpu *, unsigned, int, uint32_t);
	int (*interrupt_allowed)(struct kvm_vcpu *);
	int (*nmi_allowed)(struct kvm_vcpu *);
	int (*get_nmi_mask)(struct kvm_vcpu *);
	void (*set_nmi_mask)(struct kvm_vcpu *, int);
	void (*enable_nmi_window)(struct kvm_vcpu *);
	void (*enable_irq_window)(struct kvm_vcpu *);
	void (*update_cr8_intercept)(struct kvm_vcpu *, int, int);
	int (*set_tss_addr)(struct kvm *, uintptr_t);
	int (*get_tdp_level)(void);
	uint64_t (*get_mt_mask)(struct kvm_vcpu *, gfn_t, int);
	int (*get_lpage_level)(void);
	int (*rdtscp_supported)(void);
	const struct trace_print_flags *exit_reasons_str;
} kvm_x86_ops_t;

extern struct kvm_x86_ops *kvm_x86_ops;

extern int kvm_mmu_module_init(void);
extern void kvm_mmu_module_exit(void);

extern void kvm_mmu_destroy(struct kvm_vcpu *);
extern int kvm_mmu_create(struct kvm_vcpu *);
extern int kvm_mmu_setup(struct kvm_vcpu *);
extern void kvm_mmu_set_nonpresent_ptes(uint64_t, uint64_t);
extern void kvm_mmu_set_base_ptes(uint64_t);
extern void kvm_mmu_set_mask_ptes(uint64_t, uint64_t, uint64_t, uint64_t,
    uint64_t);

extern int kvm_mmu_reset_context(struct kvm_vcpu *);
extern void kvm_mmu_slot_remove_write_access(struct kvm *, int);
extern void kvm_mmu_zap_all(struct kvm *);
unsigned int kvm_mmu_calculate_mmu_pages(struct kvm *);
extern void kvm_mmu_change_mmu_pages(struct kvm *, unsigned int);

extern int load_pdptrs(struct kvm_vcpu *, unsigned long);

extern int emulator_write_phys(struct kvm_vcpu *, gpa_t, const void *, int);
extern int kvm_pv_mmu_op(struct kvm_vcpu *, unsigned long, gpa_t,
    unsigned long *);
extern uint8_t kvm_get_guest_memory_type(struct kvm_vcpu *, gfn_t);

extern int tdp_enabled;

enum emulation_result {
	EMULATE_DONE,		/* no further processing */
	EMULATE_DO_MMIO,	/* kvm_run filled with mmio request */
	EMULATE_FAIL,		/* can't emulate this instruction */
};

#define	EMULTYPE_NO_DECODE	    (1 << 0)
#define	EMULTYPE_TRAP_UD	    (1 << 1)
#define	EMULTYPE_SKIP		    (1 << 2)

extern int emulate_instruction(struct kvm_vcpu *, unsigned long, uint16_t, int);
extern void kvm_report_emulation_failure(struct kvm_vcpu *, const char *);
extern void realmode_lgdt(struct kvm_vcpu *, uint16_t, unsigned long);
extern void realmode_lidt(struct kvm_vcpu *, uint16_t, unsigned long);
extern void realmode_lmsw(struct kvm_vcpu *, unsigned long, unsigned long *);

extern unsigned long realmode_get_cr(struct kvm_vcpu *, int);
extern void realmode_set_cr(struct kvm_vcpu *, int, unsigned long,
    unsigned long *);
extern void kvm_enable_efer_bits(uint64_t);
extern int kvm_get_msr(struct kvm_vcpu *, uint32_t, uint64_t *);
extern int kvm_set_msr(struct kvm_vcpu *, uint32_t, uint64_t);

extern int kvm_emulate_pio(struct kvm_vcpu *, int, int, unsigned);
extern int kvm_emulate_pio_string(struct kvm_vcpu *, int, int, unsigned long,
    int, gva_t, int, unsigned);
extern void kvm_emulate_cpuid(struct kvm_vcpu *);
extern int kvm_emulate_halt(struct kvm_vcpu *);
extern int emulate_invlpg(struct kvm_vcpu *, gva_t);
extern int emulate_clts(struct kvm_vcpu *);
extern int emulator_get_dr(struct x86_emulate_ctxt *, int, unsigned long *);
extern int emulator_set_dr(struct x86_emulate_ctxt *, int, unsigned long);

extern void kvm_get_segment(struct kvm_vcpu *, struct kvm_segment *, int);
extern int kvm_load_segment_descriptor(struct kvm_vcpu *, uint16_t, int);

extern int kvm_task_switch(struct kvm_vcpu *, uint16_t, int);

extern void kvm_set_cr0(struct kvm_vcpu *, unsigned long);
extern void kvm_set_cr3(struct kvm_vcpu *, unsigned long);
extern void kvm_set_cr4(struct kvm_vcpu *, unsigned long);
extern void kvm_set_cr8(struct kvm_vcpu *, unsigned long);
extern unsigned long kvm_get_cr8(struct kvm_vcpu *);
extern void kvm_lmsw(struct kvm_vcpu *, unsigned long);

extern int kvm_get_msr_common(struct kvm_vcpu *, uint32_t, uint64_t *);
extern int kvm_set_msr_common(struct kvm_vcpu *, uint32_t, uint64_t);

extern unsigned long kvm_get_rflags(struct kvm_vcpu *);
extern void kvm_set_rflags(struct kvm_vcpu *, unsigned long);

extern void kvm_queue_exception(struct kvm_vcpu *, unsigned);
extern void kvm_queue_exception_e(struct kvm_vcpu *, unsigned, uint32_t);
extern void kvm_inject_page_fault(struct kvm_vcpu *, unsigned long, uint32_t);
extern int kvm_require_cpl(struct kvm_vcpu *, int);

extern int kvm_pic_set_irq(void *, int, int);

extern void kvm_inject_nmi(struct kvm_vcpu *);

extern void fx_init(struct kvm_vcpu *);

extern int emulator_write_emulated(unsigned long, const void *, unsigned int,
    struct kvm_vcpu *);

/*
 * FIXME: Accessing the desc_struct through its fields is more elegant,
 * and should be the one valid thing to do. However, a lot of open code
 * still touches the a and b accessors, and doing this allow us to do it
 * incrementally. We keep the signature as a struct, rather than an union,
 * so we can get rid of it transparently in the future -- glommer
 */
/* 8 byte segment descriptor */
struct desc_struct {
	union {
		struct {
			unsigned int a;
			unsigned int b;
		}a;
		struct {
			unsigned short limit0;
			unsigned short base0;
			unsigned base1: 8, type: 4, s: 1, dpl: 2, p: 1;
			unsigned limit: 4, avl: 1, l: 1, d: 1, g: 1, base2: 8;
		}b;
	}c;
} __attribute__((packed));

extern unsigned long segment_base(uint16_t);

extern void kvm_mmu_flush_tlb(struct kvm_vcpu *);
extern void kvm_mmu_pte_write(struct kvm_vcpu *, gpa_t, const uint8_t *, int,
    int);
extern int kvm_mmu_unprotect_page_virt(struct kvm_vcpu *, gva_t);
extern void __kvm_mmu_free_some_pages(struct kvm_vcpu *);
extern int kvm_mmu_load(struct kvm_vcpu *);
extern void kvm_mmu_unload(struct kvm_vcpu *);
extern void kvm_mmu_sync_roots(struct kvm_vcpu *);
extern gpa_t kvm_mmu_gva_to_gpa_read(struct kvm_vcpu *, gva_t, uint32_t *);
extern gpa_t kvm_mmu_gva_to_gpa_fetch(struct kvm_vcpu *, gva_t, uint32_t *);
extern gpa_t kvm_mmu_gva_to_gpa_write(struct kvm_vcpu *, gva_t, uint32_t *);
extern gpa_t kvm_mmu_gva_to_gpa_system(struct kvm_vcpu *, gva_t, uint32_t *);

extern int kvm_emulate_hypercall(struct kvm_vcpu *);

extern int kvm_fix_hypercall(struct kvm_vcpu *);

extern int kvm_mmu_page_fault(struct kvm_vcpu *, gva_t, uint32_t);
extern void kvm_mmu_invlpg(struct kvm_vcpu *, gva_t);

extern void kvm_enable_tdp(void);
extern void kvm_disable_tdp(void);

extern int load_pdptrs(struct kvm_vcpu *, unsigned long);
extern int complete_pio(struct kvm_vcpu *);
extern int kvm_check_iopl(struct kvm_vcpu *);

extern struct kvm_memory_slot *gfn_to_memslot_unaliased(struct kvm *, gfn_t);

extern struct kvm_mmu_page *page_header(struct kvm *, hpa_t);

extern unsigned short kvm_read_fs(void);
extern unsigned short kvm_read_gs(void);
extern unsigned short kvm_read_ldt(void);
extern void kvm_load_fs(unsigned short);
extern void kvm_load_gs(unsigned short);
extern void kvm_load_ldt(unsigned short);
extern void kvm_get_idt(struct descriptor_table *);
extern void kvm_get_gdt(struct descriptor_table *);
extern unsigned long find_first_zero_bit(const unsigned long *, unsigned long);

extern unsigned long kvm_read_tr_base(void);

extern unsigned long read_msr(unsigned long);

extern uint32_t get_rdx_init_val(void);

extern void kvm_inject_gp(struct kvm_vcpu *, uint32_t);

#define	TSS_IOPB_BASE_OFFSET 0x66
#define	TSS_BASE_SIZE 0x68
#define	TSS_IOPB_SIZE (65536 / 8)
#define	TSS_REDIRECTION_SIZE (256 / 8)
#define	RMODE_TSS_SIZE							\
	(TSS_BASE_SIZE + TSS_REDIRECTION_SIZE + TSS_IOPB_SIZE + 1)

enum {
	TASK_SWITCH_CALL = 0,
	TASK_SWITCH_IRET = 1,
	TASK_SWITCH_JMP = 2,
	TASK_SWITCH_GATE = 3,
};

#define	HF_GIF_MASK		(1 << 0)
#define	HF_HIF_MASK		(1 << 1)
#define	HF_VINTR_MASK		(1 << 2)
#define	HF_NMI_MASK		(1 << 3)
#define	HF_IRET_MASK		(1 << 4)

/*
 * These definitions used to exist in asm.h. However because most of the file
 * was unnecessary, they have been moved into here.
 */
#define	__ASM_FORM(x)	" " #x " "

#define	__ASM_SEL(a, b) __ASM_FORM(b)

#define	__ASM_SIZE(inst)	__ASM_SEL(inst##l, inst##q)
#define	_ASM_PTR	__ASM_SEL(.long, .quad)

/*
 * Hardware virtualization extension instructions may fault if a
 * reboot turns off virtualization while processes are running.
 * Trap the fault and ignore the instruction if that happens.
 */

#define	__kvm_handle_fault_on_reboot(insn) \
	"666: " insn "\n\t" \
	".pushsection .fixup, \"ax\" \n" \
	"667: \n\t" \
	__ASM_SIZE(push) " $666b \n\t"	      \
	".popsection \n\t" \
	".pushsection __ex_table, \"a\" \n\t" \
	_ASM_PTR " 666b, 667b \n\t" \
	".popsection \n\t"

int kvm_unmap_hva(struct kvm *kvm, unsigned long hva);
int kvm_age_hva(struct kvm *kvm, unsigned long hva);
void kvm_set_spte_hva(struct kvm *kvm, unsigned long hva, pte_t pte);
int cpuid_maxphyaddr(struct kvm_vcpu *vcpu);
int kvm_cpu_has_interrupt(struct kvm_vcpu *vcpu);
int kvm_arch_interrupt_allowed(struct kvm_vcpu *vcpu);
int kvm_cpu_get_interrupt(struct kvm_vcpu *v);

void kvm_define_shared_msr(unsigned index, uint32_t msr);
void kvm_set_shared_msr(struct kvm_vcpu *, unsigned index, uint64_t val,
    uint64_t mask);

#define	NMI_VECTOR 0x02

#endif
