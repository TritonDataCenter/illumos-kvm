/*
 * Kernel-based Virtual Machine driver for Linux
 *
 * This module enables machines with Intel VT-x extensions to run virtual
 * machines without emulation or binary translation.
 *
 * Copyright (C) 2006 Qumranet, Inc.
 *
 * Authors:
 *   Avi Kivity   <avi@qumranet.com>
 *   Yaniv Kamay  <yaniv@qumranet.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Copyright 2019 Joyent, Inc.
 */

#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/mach_mmu.h>
#include <asm/cpu.h>
#include <sys/x86_archext.h>
#include <sys/xc_levels.h>
#include <sys/machsystm.h>
#include <sys/hma.h>

#include "kvm_bitops.h"
#include "kvm_msr.h"
#include "kvm_cpuid.h"
#include "kvm_impl.h"
#include "kvm_x86impl.h"
#include "kvm_cache_regs.h"
#include "kvm_host.h"
#include "kvm_iodev.h"
#include "kvm_irq.h"
#include "kvm_mmu.h"
#include "kvm_vmx.h"


/*
 * Globals
 */

#define	VMX_NR_VPIDS				(1 << 16)
static int bypass_guest_pf = 1;
static int enable_vpid = 1;
static int flexpriority_enabled = 1;
static int enable_ept = 1;
static int kvm_vmx_ept_required = 1;
static int enable_unrestricted_guest = 1;
static int emulate_invalid_guest_state = 0;
static kmem_cache_t *kvm_vcpu_cache;

#ifdef XXX_KVM_DECLARATION
static unsigned long *vmx_io_bitmap_a;
static unsigned long *vmx_io_bitmap_b;
static unsigned long *vmx_msr_bitmap_legacy;
static unsigned long *vmx_msr_bitmap_longmode;
#else
/* make these arrays to try to force into low 4GB memory... */
/* also need to be aligned... */
__attribute__((__aligned__(PAGESIZE)))static unsigned long
    vmx_io_bitmap_a[PAGESIZE / sizeof (unsigned long)];
__attribute__((__aligned__(PAGESIZE)))static unsigned long
    vmx_io_bitmap_b[PAGESIZE / sizeof (unsigned long)];
__attribute__((__aligned__(PAGESIZE)))static unsigned long
    vmx_msr_bitmap_legacy[PAGESIZE / sizeof (unsigned long)];
__attribute__((__aligned__(PAGESIZE)))static unsigned long
    vmx_msr_bitmap_longmode[PAGESIZE / sizeof (unsigned long)];
#endif

static uintptr_t vmx_io_bitmap_a_pa;
static uintptr_t vmx_io_bitmap_b_pa;
static uintptr_t vmx_msr_bitmap_legacy_pa;
static uintptr_t vmx_msr_bitmap_longmode_pa;

static int vmx_has_kvm_support_override = 0;

#define	KVM_GUEST_CR0_MASK_UNRESTRICTED_GUEST				\
	(X86_CR0_WP | X86_CR0_NE | X86_CR0_NW | X86_CR0_CD)
#define	KVM_GUEST_CR0_MASK						\
	(KVM_GUEST_CR0_MASK_UNRESTRICTED_GUEST | X86_CR0_PG | X86_CR0_PE)
#define	KVM_VM_CR0_ALWAYS_ON_UNRESTRICTED_GUEST				\
	(X86_CR0_WP | X86_CR0_NE)
#define	KVM_VM_CR0_ALWAYS_ON						\
	(KVM_VM_CR0_ALWAYS_ON_UNRESTRICTED_GUEST | X86_CR0_PG | X86_CR0_PE)
#define	KVM_CR4_GUEST_OWNED_BITS				      \
	(X86_CR4_PVI | X86_CR4_DE | X86_CR4_PCE | X86_CR4_OSFXSR      \
	| X86_CR4_OSXMMEXCPT)

#define	KVM_PMODE_VM_CR4_ALWAYS_ON (X86_CR4_PAE | X86_CR4_VMXE)
#define	KVM_RMODE_VM_CR4_ALWAYS_ON (X86_CR4_VME | X86_CR4_PAE | X86_CR4_VMXE)

#define	RMODE_GUEST_OWNED_EFLAGS_BITS (~(X86_EFLAGS_IOPL | X86_EFLAGS_VM))

#define	__ex(x) __kvm_handle_fault_on_reboot(x)

#define	page_to_phys(page) (page->p_pagenum << PAGESHIFT)

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
#define	KVM_VMX_DEFAULT_PLE_GAP		41
#define	KVM_VMX_DEFAULT_PLE_WINDOW	4096

static int ple_gap = KVM_VMX_DEFAULT_PLE_GAP;
static int ple_window = KVM_VMX_DEFAULT_PLE_WINDOW;

typedef struct vmcs {
	uint32_t revision_id;
	uint32_t abort;
	char data[1];  /* size is read from MSR */
} vmcs_t;

typedef struct shared_msr_entry {
	unsigned index;
	uint64_t data;
	uint64_t mask;
} shared_msr_entry_t;

typedef struct vcpu_vmx {
	struct kvm_vcpu		vcpu;
	struct list_node	local_vcpus_link;
	unsigned long		host_rsp;
	int			launched;
	unsigned char		fail;
	uint32_t		idt_vectoring_info;
	struct shared_msr_entry	*guest_msrs;
	int			nmsrs;
	int			save_nmsrs;
	uint64_t		msr_host_kernel_gs_base;
	uint64_t		msr_guest_kernel_gs_base;
	struct vmcs		*vmcs;
	uint64_t		vmcs_pa; /* physical address of vmx's vmcs */
	struct {
		int		loaded;
		unsigned short	fs_sel, gs_sel, ldt_sel;
		int		gs_ldt_reload_needed;
		int		fs_reload_needed;
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
	int cpu_lastrun;
	char emulation_required;

	/* Support for vnmi-less CPUs */
	int soft_vnmi_blocked;
	time_t entry_time;
	int64_t vnmi_blocked_time;
	uint32_t exit_reason;

	char rdtscp_enabled;
} vcpu_vmx_t;

static struct vcpu_vmx *
to_vmx(struct kvm_vcpu *vcpu)
{
	return ((struct vcpu_vmx *)((uintptr_t)vcpu -
	    offsetof(struct vcpu_vmx, vcpu)));
}

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

typedef struct vmx_capability {
	uint32_t ept;
	uint32_t vpid;
} vmx_capability_t;

#define	VMX_SEGMENT_FIELD(seg)					\
	[VCPU_SREG_##seg] = {                                   \
		.selector = GUEST_##seg##_SELECTOR,		\
		.base = GUEST_##seg##_BASE,		   	\
		.limit = GUEST_##seg##_LIMIT,		   	\
		.ar_bytes = GUEST_##seg##_AR_BYTES,	   	\
	}

typedef struct kvm_vmx_segment_field {
	unsigned selector;
	unsigned base;
	unsigned limit;
	unsigned ar_bytes;
} kvm_vmx_segment_field_t;


struct kvm_vmx_segment_field kvm_vmx_segment_fields[] = {
	VMX_SEGMENT_FIELD(CS),
	VMX_SEGMENT_FIELD(DS),
	VMX_SEGMENT_FIELD(ES),
	VMX_SEGMENT_FIELD(FS),
	VMX_SEGMENT_FIELD(GS),
	VMX_SEGMENT_FIELD(SS),
	VMX_SEGMENT_FIELD(TR),
	VMX_SEGMENT_FIELD(LDTR),
};

static vmcs_config_t vmcs_config;
static vmx_capability_t vmx_capability;
static uint64_t host_efer;

static void ept_save_pdptrs(struct kvm_vcpu *);

/*
 * Keep MSR_K6_STAR at the end, as setup_msrs() will try to optimize it
 * away by decrementing the array size.
 */
static const uint32_t vmx_msr_index[] = {
	MSR_SYSCALL_MASK, MSR_LSTAR, MSR_CSTAR,
	MSR_EFER, MSR_TSC_AUX, MSR_K6_STAR,
};

#define	NR_VMX_MSR ARRAY_SIZE(vmx_msr_index)

static void
native_load_tr_desc(void)
{
	__asm__ volatile("ltr %w0"::"q" (KTSS_SEL));
}

#define	load_TR_desc() native_load_tr_desc()


static int
is_page_fault(uint32_t intr_info)
{
	return ((intr_info & (INTR_INFO_INTR_TYPE_MASK | INTR_INFO_VECTOR_MASK |
	    INTR_INFO_VALID_MASK)) == (INTR_TYPE_HARD_EXCEPTION |
	    PF_VECTOR | INTR_INFO_VALID_MASK));
}

static int
is_no_device(uint32_t intr_info)
{
	return ((intr_info & (INTR_INFO_INTR_TYPE_MASK | INTR_INFO_VECTOR_MASK |
	    INTR_INFO_VALID_MASK)) == (INTR_TYPE_HARD_EXCEPTION | NM_VECTOR |
	    INTR_INFO_VALID_MASK));
}

static int
is_invalid_opcode(uint32_t intr_info)
{
	return ((intr_info & (INTR_INFO_INTR_TYPE_MASK | INTR_INFO_VECTOR_MASK |
	    INTR_INFO_VALID_MASK)) == (INTR_TYPE_HARD_EXCEPTION | UD_VECTOR |
	    INTR_INFO_VALID_MASK));
}

static int
is_external_interrupt(uint32_t intr_info)
{
	return ((intr_info & (INTR_INFO_INTR_TYPE_MASK |
	    INTR_INFO_VALID_MASK)) == (INTR_TYPE_EXT_INTR |
	    INTR_INFO_VALID_MASK));
}

static int
is_machine_check(uint32_t intr_info)
{
	return (intr_info & (INTR_INFO_INTR_TYPE_MASK | INTR_INFO_VECTOR_MASK |
	    INTR_INFO_VALID_MASK)) == (INTR_TYPE_HARD_EXCEPTION |
	    MC_VECTOR | INTR_INFO_VALID_MASK);
}

static int
cpu_has_vmx_msr_bitmap(void)
{
	return (vmcs_config.cpu_based_exec_ctrl & CPU_BASED_USE_MSR_BITMAPS);
}

static int
cpu_has_vmx_tpr_shadow(void)
{
	return (vmcs_config.cpu_based_exec_ctrl & CPU_BASED_TPR_SHADOW);
}

static int
vm_need_tpr_shadow(struct kvm *kvm)
{
	return ((cpu_has_vmx_tpr_shadow()) && (irqchip_in_kernel(kvm)));
}

static int
cpu_has_secondary_exec_ctrls(void)
{
	return (vmcs_config.cpu_based_exec_ctrl &
	    CPU_BASED_ACTIVATE_SECONDARY_CONTROLS);
}

static int
cpu_has_vmx_virtualize_apic_accesses(void)
{
	return (vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES);
}

static int
cpu_has_vmx_flexpriority(void)
{
	return (cpu_has_vmx_tpr_shadow() &&
		cpu_has_vmx_virtualize_apic_accesses());
}

static int
cpu_has_vmx_ept_execute_only(void)
{
	return (!!(vmx_capability.ept & VMX_EPT_EXECUTE_ONLY_BIT));
}

static int
cpu_has_vmx_ept_2m_page(void)
{
	return (!!(vmx_capability.ept & VMX_EPT_2MB_PAGE_BIT));
}

static int
cpu_has_vmx_ept_1g_page(void)
{
	return (!!(vmx_capability.ept & VMX_EPT_1GB_PAGE_BIT));
}

static int
cpu_has_vmx_invept_context(void)
{
	return (!!(vmx_capability.ept & VMX_EPT_EXTENT_CONTEXT_BIT));
}

static int
cpu_has_vmx_invept_global(void)
{
	return (!!(vmx_capability.ept & VMX_EPT_EXTENT_GLOBAL_BIT));
}

static int
cpu_has_vmx_ept(void)
{
	return (vmcs_config.cpu_based_2nd_exec_ctrl &
	    SECONDARY_EXEC_ENABLE_EPT);
}

static int
cpu_has_vmx_unrestricted_guest(void)
{
	return (vmcs_config.cpu_based_2nd_exec_ctrl &
	    SECONDARY_EXEC_UNRESTRICTED_GUEST);
}

static int
cpu_has_vmx_ple(void)
{
	return (vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_PAUSE_LOOP_EXITING);
}

static int
vm_need_virtualize_apic_accesses(struct kvm *kvm)
{
	return (flexpriority_enabled && irqchip_in_kernel(kvm));
}

static inline int
cpu_has_vmx_vpid(void)
{
	return (vmcs_config.cpu_based_2nd_exec_ctrl &
	    SECONDARY_EXEC_ENABLE_VPID);
}

static int
cpu_has_vmx_rdtscp(void)
{
	return (vmcs_config.cpu_based_2nd_exec_ctrl & SECONDARY_EXEC_RDTSCP);
}

static int
cpu_has_virtual_nmis(void)
{
	return (vmcs_config.pin_based_exec_ctrl & PIN_BASED_VIRTUAL_NMIS);
}

static int
report_flexpriority(void)
{
	return (flexpriority_enabled);
}

static int
__find_msr_index(struct vcpu_vmx *vmx, uint32_t msr)
{
	int i;

	for (i = 0; i < vmx->nmsrs; i++) {
		if (vmx_msr_index[vmx->guest_msrs[i].index] == msr)
			return (i);
	}

	return (-1);
}

/* XXX These used to have an __ex around them, maybe add it back? */
static inline void
__invvpid(int ext, uint16_t vpid, gva_t gva)
{
	struct {
		uint64_t vpid:16;
		uint64_t rsvd:48;
		uint64_t gva;
	} operand = { vpid, 0, gva };

	KVM_TRACE2(vmx__invvpid, int, vpid, uint64_t, gva);

	/* BEGIN CSTYLED */
	__asm__ volatile (ASM_VMX_INVVPID
		  /* CF==1 or ZF==1 --> rc = -1 */
		  "; ja 1f ; ud2 ; 1:"
		  : : "a"(&operand), "c"(ext) : "cc", "memory");
	/* END CSTYLED */
}

static inline void
__invept(int ext, uint64_t eptp, gpa_t gpa)
{
	struct {
		uint64_t eptp, gpa;
	} operand = {eptp, gpa};

	KVM_TRACE2(vmx__invept, uint64_t, eptp, uint64_t, gpa);

	/* BEGIN CSTYLED */
	__asm__ volatile (ASM_VMX_INVEPT
			/* CF==1 or ZF==1 --> rc = -1 */
			"; ja 1f ; ud2 ; 1:\n"
			: : "a" (&operand), "c" (ext) : "cc", "memory");
	/* END CSTYLED */
}

static struct shared_msr_entry *
find_msr_entry(struct vcpu_vmx *vmx, uint32_t msr)
{
	int i;

	i = __find_msr_index(vmx, msr);
	if (i >= 0)
		return (&vmx->guest_msrs[i]);

	return (NULL);
}


static void
vmcs_load(uint64_t vmcs_pa)
{
	uint8_t error;

	KVM_TRACE1(vmx__vmptrld, uint64_t, vmcs_pa);

	/*CSTYLED*/
	__asm__ volatile (ASM_VMX_VMPTRLD_RAX "; setna %0"
	    : "=g"(error) : "a"(&vmcs_pa), "m"(vmcs_pa)
	    : "cc", "memory");

	if (error)
		cmn_err(CE_PANIC, "kvm: vmptrld fail: %lx\n", vmcs_pa);
}

static void
vmcs_clear(uint64_t vmcs_pa)
{
	unsigned char error;

	KVM_TRACE1(vmx__vmclear, uint64_t, vmcs_pa);

	/*CSTYLED*/
	__asm__ volatile (__ex(ASM_VMX_VMCLEAR_RAX) "\n\tsetna %0\n"
	    : "=g"(error) : "a"(&vmcs_pa), "m"(vmcs_pa)
	    : "cc", "memory");

	if (error)
		cmn_err(CE_PANIC, "kvm: vmclear fail: %lx\n", vmcs_pa);
}

static void
vpid_sync_vcpu_all(struct vcpu_vmx *vmx)
{
	if (vmx->vpid == 0)
		return;

	__invvpid(VMX_VPID_EXTENT_SINGLE_CONTEXT, vmx->vpid, 0);
}

static void
ept_sync_global(void)
{
	if (cpu_has_vmx_invept_global())
		__invept(VMX_EPT_EXTENT_GLOBAL, 0, 0);
}

static void
ept_sync_context(uint64_t eptp)
{
	if (enable_ept) {
		if (cpu_has_vmx_invept_context())
			__invept(VMX_EPT_EXTENT_CONTEXT, eptp, 0);
		else
			ept_sync_global();
	}
}

static unsigned long
vmcs_readl(unsigned long field)
{
	unsigned long value;

	/*CSTYLED*/
	__asm__ volatile (ASM_VMX_VMREAD_RDX_RAX
	    : "=a"(value) : "d"(field) : "cc");

	KVM_TRACE2(vmx__vmread, long, field, long, value);

	return (value);
}

static uint16_t
vmcs_read16(unsigned long field)
{
	return (vmcs_readl(field));
}

static uint32_t
vmcs_read32(unsigned long field)
{
	return (vmcs_readl(field));
}

static uint64_t
vmcs_read64(unsigned long field)
{
	return (vmcs_readl(field));
}

static void
vmwrite_error(unsigned long field, unsigned long value)
{
	cmn_err(CE_WARN, "vmwrite error: reg %lx value %lx (err %x)\n",
	    field, value, vmcs_read32(VM_INSTRUCTION_ERROR));
}

static void
__vmwrite(unsigned long field, unsigned long value)
{
	uint8_t err = 0;

	/*CSTYLED*/
	__asm__ volatile ( ASM_VMX_VMWRITE_RAX_RDX "\n\t" "setna %0"
	    /* XXX: CF==1 or ZF==1 --> crash (ud2) */
	    /* "ja 1f ; ud2 ; 1:\n" */
	    : "=q"(err) : "a" (value), "d" (field)
	    : "cc", "memory");

	KVM_TRACE3(vmx__vmwrite, long, field,
	    long, value, uint8_t, err);

	/* XXX the following should be ifdef debug... */
	if (err) {
#ifdef XXX
		vmcs_read32(VM_INSTRUCTION_ERROR);
		cmn_err(CE_WARN, "_vmwrite: error writing %lx to %lx: "
		    "error number = %d\n", value, field, err & 0xff);
#else
		XXX_KVM_PROBE;
#endif
	}
}

/* XXX Should be static! */
void
vmcs_writel(unsigned long field, unsigned long value)
{
	unsigned char error = 0;
#ifndef XXX
	/*CSTYLED*/
	__asm__ volatile (ASM_VMX_VMWRITE_RAX_RDX "\n\tsetna %0"
	    : "=q"(error) : "a"(value), "d"(field) : "cc");

	if ((error))
		vmwrite_error(field, value);
#else
	XXX_KVM_PROBE;
	__vmwrite(field, value);
#endif
}

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
}

static void
vmcs_clear_bits(unsigned long field, uint32_t mask)
{
	vmcs_writel(field, vmcs_readl(field) & ~mask);
}

static void
vmcs_set_bits(unsigned long field, uint32_t mask)
{
	vmcs_writel(field, vmcs_readl(field) | mask);
}

static void
update_exception_bitmap(struct kvm_vcpu *vcpu)
{
	uint32_t eb;

	eb = (1u << PF_VECTOR) | (1u << UD_VECTOR) | (1u << MC_VECTOR) |
	    (1u << NM_VECTOR) | (1u << DB_VECTOR) | (1u <<AC_VECTOR);

#ifndef XXX
	if ((vcpu->guest_debug &
	    (KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP)) ==
	    (KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP))
		eb |= 1u << BP_VECTOR;
#endif
	if (to_vmx(vcpu)->rmode.vm86_active)
		eb = ~0;
	if (enable_ept)
		eb &= ~(1u << PF_VECTOR); /* bypass_guest_pf = 0 */
	if (vcpu->fpu_active)
		eb &= ~(1u << NM_VECTOR);
	vmcs_write32(EXCEPTION_BITMAP, eb);
}


static void
reload_tss(void)
{
	/*
	 * VT restores TR but not its size.  Useless.
	 */
	struct descriptor_table gdt;
	struct desc_struct *descs;

	kvm_get_gdt(&gdt);
	descs = (void *)gdt.base;
	descs[GDT_KTSS].c.b.type = 9; /* available TSS */
	load_TR_desc();
}

static int
update_transition_efer(struct vcpu_vmx *vmx, int efer_offset)
{
	uint64_t guest_efer;
	uint64_t ignore_bits;

	guest_efer = vmx->vcpu.arch.efer;

	/*
	 * NX is emulated; LMA and LME handled by hardware; SCE meaninless
	 * outside long mode
	 */
	ignore_bits = EFER_NX | EFER_SCE;
	ignore_bits |= EFER_LMA | EFER_LME;
	/* SCE is meaningful only in long mode on Intel */
	if (guest_efer & EFER_LMA)
		ignore_bits &= ~(uint64_t)EFER_SCE;
	guest_efer &= ~ignore_bits;
	guest_efer |= host_efer & ignore_bits;
	vmx->guest_msrs[efer_offset].data = guest_efer;
	vmx->guest_msrs[efer_offset].mask = ~ignore_bits;

	return (1);
}

static void
vmx_save_host_state(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	int i;

	if (vmx->host_state.loaded)
		return;

	vmx->host_state.loaded = 1;
	/*
	 * Set host fs and gs selectors.  Unfortunately, 22.2.3 does not
	 * allow segment selectors with cpl > 0 or ti == 1.
	 */
	vmx->host_state.ldt_sel = kvm_read_ldt();
	vmx->host_state.gs_ldt_reload_needed = vmx->host_state.ldt_sel;
	vmx->host_state.fs_sel = kvm_read_fs();
	if (!(vmx->host_state.fs_sel & 7)) {
		vmcs_write16(HOST_FS_SELECTOR, vmx->host_state.fs_sel);
		vmx->host_state.fs_reload_needed = 0;
	} else {
		vmcs_write16(HOST_FS_SELECTOR, 0);
		vmx->host_state.fs_reload_needed = 1;
	}
	vmx->host_state.gs_sel = kvm_read_gs();
	if (!(vmx->host_state.gs_sel & 7))
		vmcs_write16(HOST_GS_SELECTOR, vmx->host_state.gs_sel);
	else {
		vmcs_write16(HOST_GS_SELECTOR, 0);
		vmx->host_state.gs_ldt_reload_needed = 1;
	}

	vmcs_writel(HOST_FS_BASE, read_msr(MSR_FS_BASE));
	vmcs_writel(HOST_GS_BASE, read_msr(MSR_GS_BASE));

	if (is_long_mode(&vmx->vcpu)) {
		rdmsrl(MSR_KERNEL_GS_BASE, vmx->msr_host_kernel_gs_base);
		wrmsrl(MSR_KERNEL_GS_BASE, vmx->msr_guest_kernel_gs_base);
	}

	for (i = 0; i < vmx->save_nmsrs; i++) {
		kvm_set_shared_msr(vcpu, vmx->guest_msrs[i].index,
		    vmx->guest_msrs[i].data, vmx->guest_msrs[i].mask);
	}
}

static void
__vmx_load_host_state(struct vcpu_vmx *vmx)
{
	unsigned long flags;

	if (!vmx->host_state.loaded)
		return;

	KVM_VCPU_KSTAT_INC(&vmx->vcpu, kvmvs_host_state_reload);

	vmx->host_state.loaded = 0;
	if (vmx->host_state.fs_reload_needed)
		kvm_load_fs(vmx->host_state.fs_sel);
	if (vmx->host_state.gs_ldt_reload_needed) {
		unsigned long gsbase;

		kvm_load_ldt(vmx->host_state.ldt_sel);
		/*
		 * Reloading %gs effectively zeroes the upper 32 bits of the gs
		 * base, so we need to restore our own value after the load. As
		 * %gs is essentially corrupt in between this load and the
		 * update of gsbase, then, we must be careful not to take an FBT
		 * trap. We do this by marking the two functions as untraceable:
		 * they have a dtrace_ prefix, which DTrace knows to ignore.
		 */
		cli();
		gsbase = vmcs_readl(HOST_GS_BASE);
		kvm_load_gs(vmx->host_state.gs_sel);
		wrmsrl(MSR_GS_BASE, gsbase);
		sti();
	}
	reload_tss();

	if (is_long_mode(&vmx->vcpu)) {
		rdmsrl(MSR_KERNEL_GS_BASE, vmx->msr_guest_kernel_gs_base);
		wrmsrl(MSR_KERNEL_GS_BASE, vmx->msr_host_kernel_gs_base);
	}

	reset_gdtr_limit();
}

static void
vmx_load_host_state(struct vcpu_vmx *vmx)
{
	kpreempt_disable();
	__vmx_load_host_state(vmx);
	kpreempt_enable();
}


/*
 * Switches to specified vcpu, until a matching vcpu_put(), but assumes
 * vcpu mutex is already taken.
 */
static void
vmx_vcpu_load(struct kvm_vcpu *vcpu, int cpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	vmcs_load(vmx->vmcs_pa);
	vcpu->cpu = cpu;

	/*
	 * Load per-CPU context into the VMCS if this vCPU previously ran on a
	 * different host CPU.
	 */
	if (vmx->cpu_lastrun != cpu) {
		struct descriptor_table dt;
		unsigned long sysenter_esp;

		kvm_ringbuf_record(&vcpu->kvcpu_ringbuf,
		    KVM_RINGBUF_TAG_VCPUMIGRATE, cpu);

		set_bit(KVM_REQ_TLB_FLUSH, &vcpu->requests);

		/*
		 * We have a per-CPU TSS, GDT, IDT and GSBASE -- so we reset
		 * these in the VMCS when switching CPUs.
		 */
		vmcs_writel(HOST_TR_BASE, kvm_read_tr_base()); /* 22.2.4 */
		kvm_get_gdt(&dt);
		vmcs_writel(HOST_GDTR_BASE, dt.base);   /* 22.2.4 */
		vmcs_writel(HOST_GS_BASE, read_msr(MSR_GS_BASE));
		kvm_get_idt(&dt);
		vmcs_writel(HOST_IDTR_BASE, dt.base);

		rdmsrl(MSR_IA32_SYSENTER_ESP, sysenter_esp);
		vmcs_writel(HOST_IA32_SYSENTER_ESP, sysenter_esp); /* 22.2.3 */

		/* We also have a per-CPU %cr3 if we're using kpti */
		vmcs_writel(HOST_CR3, read_cr3());  /* 22.2.3 */

		/*
		 * Make sure that the TSC_OFFSET reflects both this CPU's tick
		 * delta and the guest's TSC offset.
		 */
		vmcs_write64(TSC_OFFSET, tsc_gethrtime_tick_delta() +
		    vcpu->arch.tsc_offset);

		vmx->cpu_lastrun = cpu;
	}
}

static void
vmx_vcpu_put(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	__vmx_load_host_state(vmx);
	vmcs_clear(vmx->vmcs_pa);
	vcpu->cpu = -1;

	/*
	 * Having VMCLEARed the VMCS, a subsequent VM entry must use VMLAUNCH
	 * rather than VMRESUME.
	 */
	vmx->launched = 0;
}

static void
vmx_fpu_activate(struct kvm_vcpu *vcpu)
{
	ulong cr0;

	if (vcpu->fpu_active)
		return;

	vcpu->fpu_active = 1;
	cr0 = vmcs_readl(GUEST_CR0);
	cr0 &= ~(X86_CR0_TS | X86_CR0_MP);
	cr0 |= kvm_read_cr0_bits(vcpu, X86_CR0_TS | X86_CR0_MP);
	vmcs_writel(GUEST_CR0, cr0);
	update_exception_bitmap(vcpu);
	vcpu->arch.cr0_guest_owned_bits = X86_CR0_TS;
	vmcs_writel(CR0_GUEST_HOST_MASK, ~vcpu->arch.cr0_guest_owned_bits);
}

static void vmx_decache_cr0_guest_bits(struct kvm_vcpu *);

static void
vmx_fpu_deactivate(struct kvm_vcpu *vcpu)
{
	vmx_decache_cr0_guest_bits(vcpu);
	vmcs_set_bits(GUEST_CR0, X86_CR0_TS | X86_CR0_MP);
	update_exception_bitmap(vcpu);
	vcpu->arch.cr0_guest_owned_bits = 0;
	vmcs_writel(CR0_GUEST_HOST_MASK, ~vcpu->arch.cr0_guest_owned_bits);
	vmcs_writel(CR0_READ_SHADOW, vcpu->arch.cr0);
}

static unsigned long
vmx_get_rflags(struct kvm_vcpu *vcpu)
{
	unsigned long rflags, save_rflags;

	rflags = vmcs_readl(GUEST_RFLAGS);
	if (to_vmx(vcpu)->rmode.vm86_active) {
		rflags &= RMODE_GUEST_OWNED_EFLAGS_BITS;
		save_rflags = to_vmx(vcpu)->rmode.save_rflags;
		rflags |= save_rflags & ~RMODE_GUEST_OWNED_EFLAGS_BITS;
	}

	return (rflags);
}

static void
vmx_set_rflags(struct kvm_vcpu *vcpu, unsigned long rflags)
{
	if (to_vmx(vcpu)->rmode.vm86_active) {
		to_vmx(vcpu)->rmode.save_rflags = rflags;
		rflags |= X86_EFLAGS_IOPL | X86_EFLAGS_VM;
	}

	vmcs_writel(GUEST_RFLAGS, rflags);
}

static uint32_t
vmx_get_interrupt_shadow(struct kvm_vcpu *vcpu, int mask)
{
	uint32_t interruptibility = vmcs_read32(GUEST_INTERRUPTIBILITY_INFO);
	int ret = 0;

	if (interruptibility & GUEST_INTR_STATE_STI)
		ret |= X86_SHADOW_INT_STI;
	if (interruptibility & GUEST_INTR_STATE_MOV_SS)
		ret |= X86_SHADOW_INT_MOV_SS;

	return (ret & mask);
}

static void
vmx_set_interrupt_shadow(struct kvm_vcpu *vcpu, int mask)
{
	uint32_t old = vmcs_read32(GUEST_INTERRUPTIBILITY_INFO);
	uint32_t interruptibility = old;

	interruptibility &= ~(GUEST_INTR_STATE_STI | GUEST_INTR_STATE_MOV_SS);

	if (mask & X86_SHADOW_INT_MOV_SS)
		interruptibility |= GUEST_INTR_STATE_MOV_SS;
	if (mask & X86_SHADOW_INT_STI)
		interruptibility |= GUEST_INTR_STATE_STI;

	if ((interruptibility != old))
		vmcs_write32(GUEST_INTERRUPTIBILITY_INFO, interruptibility);
}

static void
skip_emulated_instruction(struct kvm_vcpu *vcpu)
{
	unsigned long rip;

	rip = kvm_rip_read(vcpu);
	rip += vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
	kvm_rip_write(vcpu, rip);

	/* skipping an emulated instruction also counts */
	vmx_set_interrupt_shadow(vcpu, 0);
}

static void
vmx_queue_exception(struct kvm_vcpu *vcpu, unsigned nr,
    int has_error_code, uint32_t error_code)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	uint32_t intr_info = nr | INTR_INFO_VALID_MASK;

	if (has_error_code) {
		vmcs_write32(VM_ENTRY_EXCEPTION_ERROR_CODE, error_code);
		intr_info |= INTR_INFO_DELIVER_CODE_MASK;
	}

	if (vmx->rmode.vm86_active) {
		vmx->rmode.irq.pending = 1;
		vmx->rmode.irq.vector = nr;
		vmx->rmode.irq.rip = kvm_rip_read(vcpu);
		if (kvm_exception_is_soft(nr))
			vmx->rmode.irq.rip +=
				vmx->vcpu.arch.event_exit_inst_len;
		intr_info |= INTR_TYPE_SOFT_INTR;
		vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, intr_info);
		vmcs_write32(VM_ENTRY_INSTRUCTION_LEN, 1);
		kvm_rip_write(vcpu, vmx->rmode.irq.rip - 1);
		return;
	}

	if (kvm_exception_is_soft(nr)) {
		vmcs_write32(VM_ENTRY_INSTRUCTION_LEN,
		    vmx->vcpu.arch.event_exit_inst_len);
		intr_info |= INTR_TYPE_SOFT_EXCEPTION;
	} else
		intr_info |= INTR_TYPE_HARD_EXCEPTION;

	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, intr_info);
}

static int
vmx_rdtscp_supported(void)
{
	return (cpu_has_vmx_rdtscp());
}

/*
 * Swap MSR entry in host/guest MSR entry array.
 */
static void
move_msr_up(struct vcpu_vmx *vmx, int from, int to)
{
	struct shared_msr_entry tmp;

	tmp = vmx->guest_msrs[to];
	vmx->guest_msrs[to] = vmx->guest_msrs[from];
	vmx->guest_msrs[from] = tmp;
}


/*
 * Set up the vmcs to automatically save and restore system
 * msrs.  Don't touch the 64-bit msrs if the guest is in legacy
 * mode, as fiddling with msrs is very expensive.
 */
static void
setup_msrs(struct vcpu_vmx *vmx)
{
	int save_nmsrs, index;

	vmx_load_host_state(vmx);
	save_nmsrs = 0;
	if (is_long_mode(&vmx->vcpu)) {
		index = __find_msr_index(vmx, MSR_SYSCALL_MASK);
		if (index >= 0)
			move_msr_up(vmx, index, save_nmsrs++);
		index = __find_msr_index(vmx, MSR_LSTAR);
		if (index >= 0)
			move_msr_up(vmx, index, save_nmsrs++);
		index = __find_msr_index(vmx, MSR_CSTAR);
		if (index >= 0)
			move_msr_up(vmx, index, save_nmsrs++);
		index = __find_msr_index(vmx, MSR_TSC_AUX);
		if (index >= 0 && vmx->rdtscp_enabled)
			move_msr_up(vmx, index, save_nmsrs++);
		/*
		 * MSR_K6_STAR is only needed on long mode guests, and only
		 * if efer.sce is enabled.
		 */
		index = __find_msr_index(vmx, MSR_K6_STAR);
		if ((index >= 0) && (vmx->vcpu.arch.efer & EFER_SCE))
			move_msr_up(vmx, index, save_nmsrs++);
	}

	index = __find_msr_index(vmx, MSR_EFER);
	if (index >= 0 && update_transition_efer(vmx, index))
		move_msr_up(vmx, index, save_nmsrs++);

	vmx->save_nmsrs = save_nmsrs;

	if (cpu_has_vmx_msr_bitmap()) {
		uintptr_t msr_bitmap;

		if (is_long_mode(&vmx->vcpu))
			msr_bitmap = vmx_msr_bitmap_longmode_pa;
		else
			msr_bitmap = vmx_msr_bitmap_legacy_pa;

		vmcs_write64(MSR_BITMAP, msr_bitmap);
	}
}

/*
 * reads and returns guest's timestamp counter "register"
 * guest_tsc = host_tsc + tsc_offset    -- 21.3
 */
static uint64_t
guest_read_tsc(void)
{
	uint64_t host_tsc, tsc_offset;

	rdtscll(host_tsc);
	tsc_offset = vmcs_read64(TSC_OFFSET);
	return (host_tsc + tsc_offset);
}

/*
 * writes 'guest_tsc' into guest's timestamp counter "register"
 * guest_tsc = host_tsc + tsc_offset ==> tsc_offset = guest_tsc - host_tsc
 */
static void
guest_write_tsc(struct kvm_vcpu *vcpu, uint64_t guest_tsc)
{
	uint64_t delta = tsc_gethrtime_tick_delta(), now;

	/*
	 * Read the TSC and true it up based on our tick delta.
	 */
	rdtscll(now);
	now += delta;

	/*
	 * We can now determine the difference between the guest's TSC and the
	 * host's TSC in a CPU-neutral sense (that is, without regard to the
	 * CPU's tick delta); this is what we will store as the guest's offset,
	 * recalculating the TSC_OFFSET whenever we store it.
	 */
	vcpu->arch.tsc_offset = guest_tsc - now;

	/*
	 * The value that will store as the actual TSC_OFFSET is the CPU's
	 * tick delta plus the guest's absolute tick offset.
	 */
	vmcs_write64(TSC_OFFSET, delta + vcpu->arch.tsc_offset);
}

/*
 * Reads an msr value (of 'msr_index') into 'pdata'.
 * Returns 0 on success, non-0 otherwise.
 * Assumes vcpu_load() was already called.
 */
static int
vmx_get_msr(struct kvm_vcpu *vcpu, uint32_t msr_index, uint64_t *pdata)
{
	uint64_t data;
	struct shared_msr_entry *msr;

	if (!pdata) {
		cmn_err(CE_WARN, "BUG: get_msr called with NULL pdata\n");
		return (EINVAL);
	}

	switch (msr_index) {
	case MSR_FS_BASE:
		data = vmcs_readl(GUEST_FS_BASE);
		break;
	case MSR_GS_BASE:
		data = vmcs_readl(GUEST_GS_BASE);
		break;
	case MSR_KERNEL_GS_BASE:
		vmx_load_host_state(to_vmx(vcpu));
		data = to_vmx(vcpu)->msr_guest_kernel_gs_base;
		break;
	case MSR_EFER:
		return (kvm_get_msr_common(vcpu, msr_index, pdata));
	case MSR_IA32_TSC:
		data = guest_read_tsc();
		break;
	case MSR_IA32_SYSENTER_CS:
		data = vmcs_read32(GUEST_SYSENTER_CS);
		break;
	case MSR_IA32_SYSENTER_EIP:
		data = vmcs_readl(GUEST_SYSENTER_EIP);
		break;
	case MSR_IA32_SYSENTER_ESP:
		data = vmcs_readl(GUEST_SYSENTER_ESP);
		break;
	case MSR_TSC_AUX:
		if (!to_vmx(vcpu)->rdtscp_enabled)
			return (1);
		/* Otherwise falls through */
	default:
		vmx_load_host_state(to_vmx(vcpu));
		msr = find_msr_entry(to_vmx(vcpu), msr_index);
		if (msr) {
			vmx_load_host_state(to_vmx(vcpu));
			data = msr->data;
			break;
		}
		return (kvm_get_msr_common(vcpu, msr_index, pdata));
	}

	*pdata = data;

	return (0);
}

/*
 * Writes msr value into into the appropriate "register".
 * Returns 0 on success, non-0 otherwise.
 * Assumes vcpu_load() was already called.
 */
static int
vmx_set_msr(struct kvm_vcpu *vcpu, uint32_t msr_index, uint64_t data)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct shared_msr_entry *msr;
	uint64_t host_tsc;
	int ret = 0;

	switch (msr_index) {
	case MSR_EFER:
		vmx_load_host_state(vmx);
		ret = kvm_set_msr_common(vcpu, msr_index, data);
		break;
	case MSR_FS_BASE:
		vmcs_writel(GUEST_FS_BASE, data);
		break;
	case MSR_GS_BASE:
		vmcs_writel(GUEST_GS_BASE, data);
		break;
	case MSR_KERNEL_GS_BASE:
		vmx_load_host_state(vmx);
		vmx->msr_guest_kernel_gs_base = data;
		break;
	case MSR_IA32_SYSENTER_CS:
		vmcs_write32(GUEST_SYSENTER_CS, data);
		break;
	case MSR_IA32_SYSENTER_EIP:
		vmcs_writel(GUEST_SYSENTER_EIP, data);
		break;
	case MSR_IA32_SYSENTER_ESP:
		vmcs_writel(GUEST_SYSENTER_ESP, data);
		break;
	case MSR_IA32_TSC:
		guest_write_tsc(vcpu, data);
		break;
	case MSR_IA32_CR_PAT:
		if (vmcs_config.vmentry_ctrl & VM_ENTRY_LOAD_IA32_PAT) {
			vmcs_write64(GUEST_IA32_PAT, data);
			vcpu->arch.pat = data;
			break;
		}
		ret = kvm_set_msr_common(vcpu, msr_index, data);
		break;
	case MSR_TSC_AUX:
		if (!vmx->rdtscp_enabled)
			return (1);
		/* Check reserved bit, higher 32 bits should be zero */
		if ((data >> 32) != 0)
			return (1);
		/* Otherwise falls through */
	default:
		msr = find_msr_entry(vmx, msr_index);
		if (msr) {
			vmx_load_host_state(vmx);
			msr->data = data;
			break;
		}
		ret = kvm_set_msr_common(vcpu, msr_index, data);
	}

	return (ret);
}

static void
vmx_cache_reg(struct kvm_vcpu *vcpu, enum kvm_reg reg)
{
	__set_bit(reg, (unsigned long *)&vcpu->arch.regs_avail);

	switch (reg) {
	case VCPU_REGS_RSP:
		vcpu->arch.regs[VCPU_REGS_RSP] = vmcs_readl(GUEST_RSP);
		break;
	case VCPU_REGS_RIP:
		vcpu->arch.regs[VCPU_REGS_RIP] = vmcs_readl(GUEST_RIP);
		break;
	case VCPU_EXREG_PDPTR:
		if (enable_ept)
			ept_save_pdptrs(vcpu);
		break;
	default:
		break;
	}
}

static void
set_guest_debug(struct kvm_vcpu *vcpu, struct kvm_guest_debug *dbg)
{
	if (vcpu->guest_debug & KVM_GUESTDBG_USE_HW_BP)
		vmcs_writel(GUEST_DR7, dbg->arch.debugreg[7]);
	else
		vmcs_writel(GUEST_DR7, vcpu->arch.dr7);

	update_exception_bitmap(vcpu);
}

/* BEGIN CSTYLED */
#ifndef X86FSET_VMX
#error X86FSET_VMX is not defined, likely because you are building against \
an illumos (set by $KERNEL_SOURCE in the Makefile) that does not include \
the fix for issue #1347; pull latest illumos and re-build.
#endif
/* END CSTYLED */

static int
vmx_has_kvm_support(void)
{
	if (vmx_has_kvm_support_override)
		return (vmx_has_kvm_support_override > 0 ? 0 : -1);

	if (is_x86_feature(x86_featureset, X86FSET_VMX))
		return (0);

	return (-1);
}

static int
vmx_disabled_by_bios(void)
{
	uint64_t msr;

	rdmsrl(MSR_IA32_FEATURE_CONTROL, msr);
	return (msr & (FEATURE_CONTROL_LOCKED |
	    FEATURE_CONTROL_VMXON_ENABLED))
	    == FEATURE_CONTROL_LOCKED;
	/* locked but not enabled */
}

static int
adjust_vmx_controls(uint32_t ctl_min, uint32_t ctl_opt,
    uint32_t msr, uint32_t *result)
{
	uint32_t vmx_msr_low, vmx_msr_high;
	uint32_t ctl = ctl_min | ctl_opt;

	rdmsr(msr, vmx_msr_low, vmx_msr_high);

	ctl &= vmx_msr_high; /* bit == 0 in high word ==> must be zero */
	ctl |= vmx_msr_low;  /* bit == 1 in low word  ==> must be one  */

	/* Ensure minimum (required) set of control bits are supported. */
	if (ctl_min & ~ctl)
		return (EIO);

	*result = ctl;
	return (DDI_SUCCESS);
}

/* Pure 2^n version of get_order */
static inline int
get_order(unsigned long size)
{
	int order;

	size = (size - 1) >> (PAGESHIFT - 1);
	order = -1;
	do {
		size >>= 1;
		order++;
	} while (size);

	return (order);
}

static int
setup_vmcs_config(struct vmcs_config *vmcs_conf)
{
	uint32_t vmx_msr_low, vmx_msr_high;
	uint32_t min, opt, min2, opt2;
	uint32_t _pin_based_exec_control = 0;
	uint32_t _cpu_based_exec_control = 0;
	uint32_t _cpu_based_2nd_exec_control = 0;
	uint32_t _vmexit_control = 0;
	uint32_t _vmentry_control = 0;
	uint32_t ept, vpid;

	min = PIN_BASED_EXT_INTR_MASK | PIN_BASED_NMI_EXITING;
	opt = PIN_BASED_VIRTUAL_NMIS;
	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_PINBASED_CTLS,
	    &_pin_based_exec_control) != DDI_SUCCESS)
		return (EIO);

	min = CPU_BASED_HLT_EXITING |
	    CPU_BASED_CR8_LOAD_EXITING |
	    CPU_BASED_CR8_STORE_EXITING |
	    CPU_BASED_CR3_LOAD_EXITING |
	    CPU_BASED_CR3_STORE_EXITING |
	    CPU_BASED_USE_IO_BITMAPS |
	    CPU_BASED_MOV_DR_EXITING |
	    CPU_BASED_USE_TSC_OFFSETING |
	    CPU_BASED_MWAIT_EXITING |
	    CPU_BASED_MONITOR_EXITING |
	    CPU_BASED_INVLPG_EXITING;

	opt = CPU_BASED_TPR_SHADOW |
	    CPU_BASED_USE_MSR_BITMAPS |
	    CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;

	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_PROCBASED_CTLS,
	    &_cpu_based_exec_control) != DDI_SUCCESS)
		return (EIO);

	if ((_cpu_based_exec_control & CPU_BASED_TPR_SHADOW))
		_cpu_based_exec_control &= ~CPU_BASED_CR8_LOAD_EXITING &
		    ~CPU_BASED_CR8_STORE_EXITING;

	if (_cpu_based_exec_control & CPU_BASED_ACTIVATE_SECONDARY_CONTROLS) {
		min2 = 0;
		opt2 = SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES |
		    SECONDARY_EXEC_WBINVD_EXITING |
		    SECONDARY_EXEC_ENABLE_VPID |
		    SECONDARY_EXEC_ENABLE_EPT |
		    SECONDARY_EXEC_UNRESTRICTED_GUEST |
		    SECONDARY_EXEC_PAUSE_LOOP_EXITING |
		    SECONDARY_EXEC_RDTSCP;

		if (adjust_vmx_controls(min2, opt2,
		    MSR_IA32_VMX_PROCBASED_CTLS2,
		    &_cpu_based_2nd_exec_control) != DDI_SUCCESS)
			return (EIO);
	}

	if (_cpu_based_2nd_exec_control & SECONDARY_EXEC_ENABLE_EPT) {
		/*
		 * CR3 accesses and invlpg don't need to cause VM Exits when EPT
		 * enabled
		 */
		_cpu_based_exec_control &= ~(CPU_BASED_CR3_LOAD_EXITING |
		    CPU_BASED_CR3_STORE_EXITING | CPU_BASED_INVLPG_EXITING);
		rdmsr(MSR_IA32_VMX_EPT_VPID_CAP, vmx_capability.ept,
		    vmx_capability.vpid);
	}

	min = VM_EXIT_HOST_ADDR_SPACE_SIZE;

	opt = VM_EXIT_SAVE_IA32_PAT | VM_EXIT_LOAD_IA32_PAT;
	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_EXIT_CTLS,
	    &_vmexit_control) != DDI_SUCCESS)
		return (EIO);

	min = 0;
	opt = VM_ENTRY_LOAD_IA32_PAT;
	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_ENTRY_CTLS,
	    &_vmentry_control) != DDI_SUCCESS)
		return (EIO);

	rdmsr(MSR_IA32_VMX_BASIC, vmx_msr_low, vmx_msr_high);

	/* IA-32 SDM Vol 3B: VMCS size is never greater than 4kB. */
	if ((vmx_msr_high & 0x1fff) > PAGESIZE)
		return (EIO);

	/* IA-32 SDM Vol 3B: 64-bit CPUs always have VMX_BASIC_MSR[48]==0. */
	if (vmx_msr_high & (1u<<16))
		return (EIO);

	/* Require Write-Back (WB) memory type for VMCS accesses. */
	if (((vmx_msr_high >> 18) & 15) != 6)
		return (EIO);

	vmcs_conf->size = vmx_msr_high & 0x1fff;
	vmcs_conf->order = get_order(vmcs_config.size);
	vmcs_conf->revision_id = vmx_msr_low;

	vmcs_conf->pin_based_exec_ctrl = _pin_based_exec_control;
	vmcs_conf->cpu_based_exec_ctrl = _cpu_based_exec_control;
	vmcs_conf->cpu_based_2nd_exec_ctrl = _cpu_based_2nd_exec_control;
	vmcs_conf->vmexit_ctrl = _vmexit_control;
	vmcs_conf->vmentry_ctrl = _vmentry_control;

	return (0);
}

static int
vmx_hardware_setup(void)
{
	if (setup_vmcs_config(&vmcs_config) != DDI_SUCCESS)
		return (EIO);

	if (is_x86_feature(x86_featureset, X86FSET_NX))
		kvm_enable_efer_bits(EFER_NX);

	if (!cpu_has_vmx_vpid())
		enable_vpid = 0;

	if (!cpu_has_vmx_ept()) {
		if (kvm_vmx_ept_required) {
			cmn_err(CE_WARN, "kvm: insufficient hardware support "
			    "(lacking EPT)\n");
			return (EIO);
		}

		enable_ept = 0;
		enable_unrestricted_guest = 0;
	}

	if (!cpu_has_vmx_unrestricted_guest())
		enable_unrestricted_guest = 0;
	if (!cpu_has_vmx_flexpriority())
		flexpriority_enabled = 0;

	if (!cpu_has_vmx_tpr_shadow())
		kvm_x86_ops->update_cr8_intercept = NULL;

	if (enable_ept && !cpu_has_vmx_ept_2m_page())
		kvm_disable_largepages();

	if (!cpu_has_vmx_ple())
		ple_gap = 0;

	return (0);
}

static void
fix_pmode_dataseg(int seg, struct kvm_save_segment *save)
{
	struct kvm_vmx_segment_field *sf = &kvm_vmx_segment_fields[seg];

	if (vmcs_readl(sf->base) == save->base && (save->base & AR_S_MASK)) {
		vmcs_write16(sf->selector, save->selector);
		vmcs_writel(sf->base, save->base);
		vmcs_write32(sf->limit, save->limit);
		vmcs_write32(sf->ar_bytes, save->ar);
	} else {
		uint32_t dpl = (vmcs_read16(sf->selector) & SELECTOR_RPL_MASK)
			<< AR_DPL_SHIFT;
		vmcs_write32(sf->ar_bytes, 0x93 | dpl);
	}
}

static void enter_pmode(struct kvm_vcpu *vcpu)
{
	unsigned long flags;
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	vmx->emulation_required = 1;
	vmx->rmode.vm86_active = 0;

	vmcs_writel(GUEST_TR_BASE, vmx->rmode.tr.base);
	vmcs_write32(GUEST_TR_LIMIT, vmx->rmode.tr.limit);
	vmcs_write32(GUEST_TR_AR_BYTES, vmx->rmode.tr.ar);

	flags = vmcs_readl(GUEST_RFLAGS);
	flags &= RMODE_GUEST_OWNED_EFLAGS_BITS;
	flags |= vmx->rmode.save_rflags & ~RMODE_GUEST_OWNED_EFLAGS_BITS;
	vmcs_writel(GUEST_RFLAGS, flags);

	vmcs_writel(GUEST_CR4, (vmcs_readl(GUEST_CR4) & ~X86_CR4_VME) |
			(vmcs_readl(CR4_READ_SHADOW) & X86_CR4_VME));

	update_exception_bitmap(vcpu);

	if (emulate_invalid_guest_state)
		return;

	fix_pmode_dataseg(VCPU_SREG_ES, &vmx->rmode.es);
	fix_pmode_dataseg(VCPU_SREG_DS, &vmx->rmode.ds);
	fix_pmode_dataseg(VCPU_SREG_GS, &vmx->rmode.gs);
	fix_pmode_dataseg(VCPU_SREG_FS, &vmx->rmode.fs);

	vmcs_write16(GUEST_SS_SELECTOR, 0);
	vmcs_write32(GUEST_SS_AR_BYTES, 0x93);

	vmcs_write16(GUEST_CS_SELECTOR,
	    vmcs_read16(GUEST_CS_SELECTOR) & ~SELECTOR_RPL_MASK);
	vmcs_write32(GUEST_CS_AR_BYTES, 0x9b);
}

static gva_t
rmode_tss_base(struct kvm *kvm)
{
	if (!kvm->arch.tss_addr) {
		struct kvm_memslots *slots;
		gfn_t base_gfn;

		mutex_enter(&kvm->memslots_lock);
		slots = kvm->memslots;

		base_gfn = kvm->memslots->memslots[0].base_gfn +
		    kvm->memslots->memslots[0].npages - 3;
		mutex_exit(&kvm->memslots_lock);
		return (base_gfn << PAGESHIFT);
	}

	return (kvm->arch.tss_addr);
}

static void
fix_rmode_seg(int seg, struct kvm_save_segment *save)
{
	struct kvm_vmx_segment_field *sf = &kvm_vmx_segment_fields[seg];

	save->selector = vmcs_read16(sf->selector);
	save->base = vmcs_readl(sf->base);
	save->limit = vmcs_read32(sf->limit);
	save->ar = vmcs_read32(sf->ar_bytes);
	vmcs_write16(sf->selector, save->base >> 4);
	vmcs_write32(sf->base, save->base & 0xfffff);
	vmcs_write32(sf->limit, 0xffff);
	vmcs_write32(sf->ar_bytes, 0xf3);
}

static int init_rmode(struct kvm *);

static void
enter_rmode(struct kvm_vcpu *vcpu)
{
	unsigned long flags;
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	if (enable_unrestricted_guest)
		return;

	vmx->emulation_required = 1;
	vmx->rmode.vm86_active = 1;

	vmx->rmode.tr.base = vmcs_readl(GUEST_TR_BASE);
	vmcs_writel(GUEST_TR_BASE, rmode_tss_base(vcpu->kvm));

	vmx->rmode.tr.limit = vmcs_read32(GUEST_TR_LIMIT);
	vmcs_write32(GUEST_TR_LIMIT, RMODE_TSS_SIZE - 1);

	vmx->rmode.tr.ar = vmcs_read32(GUEST_TR_AR_BYTES);
	vmcs_write32(GUEST_TR_AR_BYTES, 0x008b);

	flags = vmcs_readl(GUEST_RFLAGS);
	vmx->rmode.save_rflags = flags;

	flags |= X86_EFLAGS_IOPL | X86_EFLAGS_VM;

	vmcs_writel(GUEST_RFLAGS, flags);
	vmcs_writel(GUEST_CR4, vmcs_readl(GUEST_CR4) | X86_CR4_VME);
	update_exception_bitmap(vcpu);

	if (emulate_invalid_guest_state)
		goto continue_rmode;

	vmcs_write16(GUEST_SS_SELECTOR, vmcs_readl(GUEST_SS_BASE) >> 4);
	vmcs_write32(GUEST_SS_LIMIT, 0xffff);
	vmcs_write32(GUEST_SS_AR_BYTES, 0xf3);

	vmcs_write32(GUEST_CS_AR_BYTES, 0xf3);
	vmcs_write32(GUEST_CS_LIMIT, 0xffff);
	if (vmcs_readl(GUEST_CS_BASE) == 0xffff0000)
		vmcs_writel(GUEST_CS_BASE, 0xf0000);
	vmcs_write16(GUEST_CS_SELECTOR, vmcs_readl(GUEST_CS_BASE) >> 4);

	fix_rmode_seg(VCPU_SREG_ES, &vmx->rmode.es);
	fix_rmode_seg(VCPU_SREG_DS, &vmx->rmode.ds);
	fix_rmode_seg(VCPU_SREG_GS, &vmx->rmode.gs);
	fix_rmode_seg(VCPU_SREG_FS, &vmx->rmode.fs);

continue_rmode:
	kvm_mmu_reset_context(vcpu);
	init_rmode(vcpu->kvm);
}

static void
vmx_set_efer(struct kvm_vcpu *vcpu, uint64_t efer)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct shared_msr_entry *msr = find_msr_entry(vmx, MSR_EFER);

	if (!msr)
		return;

	/*
	 * Force kernel_gs_base reloading before EFER changes, as control
	 * of this msr depends on is_long_mode().
	 */
	vmx_load_host_state(to_vmx(vcpu));
	vcpu->arch.efer = efer;
	if (efer & EFER_LMA) {
		vmcs_write32(VM_ENTRY_CONTROLS,
		    vmcs_read32(VM_ENTRY_CONTROLS) | VM_ENTRY_IA32E_MODE);
		msr->data = efer;
	} else {
		vmcs_write32(VM_ENTRY_CONTROLS,
		    vmcs_read32(VM_ENTRY_CONTROLS) & ~VM_ENTRY_IA32E_MODE);

		msr->data = efer & ~EFER_LME;
	}

	setup_msrs(vmx);
}

static void
enter_lmode(struct kvm_vcpu *vcpu)
{
	uint32_t guest_tr_ar;

	guest_tr_ar = vmcs_read32(GUEST_TR_AR_BYTES);
	if ((guest_tr_ar & AR_TYPE_MASK) != AR_TYPE_BUSY_64_TSS) {
		cmn_err(CE_CONT, "!%s: tss fixup for long mode. \n",
		    __func__);
		vmcs_write32(GUEST_TR_AR_BYTES,
		    (guest_tr_ar & ~AR_TYPE_MASK) | AR_TYPE_BUSY_64_TSS);
	}
	vcpu->arch.efer |= EFER_LMA;
	vmx_set_efer(vcpu, vcpu->arch.efer);
}

static void
exit_lmode(struct kvm_vcpu *vcpu)
{
	vcpu->arch.efer &= ~EFER_LMA;

	vmcs_write32(VM_ENTRY_CONTROLS,
	    vmcs_read32(VM_ENTRY_CONTROLS) & ~VM_ENTRY_IA32E_MODE);
}

static uint64_t construct_eptp(unsigned long);

static void
vmx_flush_tlb(struct kvm_vcpu *vcpu)
{
	vpid_sync_vcpu_all(to_vmx(vcpu));
	if (enable_ept)
		ept_sync_context(construct_eptp(vcpu->arch.mmu.root_hpa));
}

static void
vmx_decache_cr0_guest_bits(struct kvm_vcpu *vcpu)
{
	ulong cr0_guest_owned_bits = vcpu->arch.cr0_guest_owned_bits;

	vcpu->arch.cr0 &= ~cr0_guest_owned_bits;
	vcpu->arch.cr0 |= vmcs_readl(GUEST_CR0) & cr0_guest_owned_bits;
}

static void
vmx_decache_cr4_guest_bits(struct kvm_vcpu *vcpu)
{
	ulong cr4_guest_owned_bits = vcpu->arch.cr4_guest_owned_bits;

	vcpu->arch.cr4 &= ~cr4_guest_owned_bits;
	vcpu->arch.cr4 |= vmcs_readl(GUEST_CR4) & cr4_guest_owned_bits;
}

static void
ept_load_pdptrs(struct kvm_vcpu *vcpu)
{
	if (!test_bit(VCPU_EXREG_PDPTR,
	    (unsigned long *)&vcpu->arch.regs_dirty))
		return;

	if (is_paging(vcpu) && is_pae(vcpu) && !is_long_mode(vcpu)) {
		vmcs_write64(GUEST_PDPTR0, vcpu->arch.pdptrs[0]);
		vmcs_write64(GUEST_PDPTR1, vcpu->arch.pdptrs[1]);
		vmcs_write64(GUEST_PDPTR2, vcpu->arch.pdptrs[2]);
		vmcs_write64(GUEST_PDPTR3, vcpu->arch.pdptrs[3]);
	}
}

static void
ept_save_pdptrs(struct kvm_vcpu *vcpu)
{
	if (is_paging(vcpu) && is_pae(vcpu) && !is_long_mode(vcpu)) {
		vcpu->arch.pdptrs[0] = vmcs_read64(GUEST_PDPTR0);
		vcpu->arch.pdptrs[1] = vmcs_read64(GUEST_PDPTR1);
		vcpu->arch.pdptrs[2] = vmcs_read64(GUEST_PDPTR2);
		vcpu->arch.pdptrs[3] = vmcs_read64(GUEST_PDPTR3);
	}

	__set_bit(VCPU_EXREG_PDPTR, (unsigned long *)&vcpu->arch.regs_avail);
	__set_bit(VCPU_EXREG_PDPTR, (unsigned long *)&vcpu->arch.regs_dirty);
}

static void vmx_set_cr4(struct kvm_vcpu *, unsigned long);

static void
ept_update_paging_mode_cr0(unsigned long *hw_cr0,
    unsigned long cr0, struct kvm_vcpu *vcpu)
{
	if (!(cr0 & X86_CR0_PG)) {
		/* From paging/starting to nonpaging */
		vmcs_write32(CPU_BASED_VM_EXEC_CONTROL,
		    vmcs_read32(CPU_BASED_VM_EXEC_CONTROL) |
		    (CPU_BASED_CR3_LOAD_EXITING |
		    CPU_BASED_CR3_STORE_EXITING));
		vcpu->arch.cr0 = cr0;
		vmx_set_cr4(vcpu, kvm_read_cr4(vcpu));
	} else if (!is_paging(vcpu)) {
		/* From nonpaging to paging */
		vmcs_write32(CPU_BASED_VM_EXEC_CONTROL,
		    vmcs_read32(CPU_BASED_VM_EXEC_CONTROL) &
		    ~(CPU_BASED_CR3_LOAD_EXITING |
		    CPU_BASED_CR3_STORE_EXITING));
		vcpu->arch.cr0 = cr0;
		vmx_set_cr4(vcpu, kvm_read_cr4(vcpu));
	}

	if (!(cr0 & X86_CR0_WP))
		*hw_cr0 &= ~X86_CR0_WP;
}

static void
vmx_set_cr0(struct kvm_vcpu *vcpu, unsigned long cr0)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	unsigned long hw_cr0;

	if (enable_unrestricted_guest) {
		hw_cr0 = (cr0 & ~KVM_GUEST_CR0_MASK_UNRESTRICTED_GUEST) |
		    KVM_VM_CR0_ALWAYS_ON_UNRESTRICTED_GUEST;
	} else {
		hw_cr0 = (cr0 & ~KVM_GUEST_CR0_MASK) | KVM_VM_CR0_ALWAYS_ON;
	}

	if (vmx->rmode.vm86_active && (cr0 & X86_CR0_PE))
		enter_pmode(vcpu);

	if (!vmx->rmode.vm86_active && !(cr0 & X86_CR0_PE))
		enter_rmode(vcpu);

	if (vcpu->arch.efer & EFER_LME) {
		if (!is_paging(vcpu) && (cr0 & X86_CR0_PG))
			enter_lmode(vcpu);
		if (is_paging(vcpu) && !(cr0 & X86_CR0_PG))
			exit_lmode(vcpu);
	}

	if (enable_ept)
		ept_update_paging_mode_cr0(&hw_cr0, cr0, vcpu);

	if (!vcpu->fpu_active)
		hw_cr0 |= X86_CR0_TS | X86_CR0_MP;

	vmcs_writel(CR0_READ_SHADOW, cr0);
	vmcs_writel(GUEST_CR0, hw_cr0);
	vcpu->arch.cr0 = cr0;
}

static uint64_t
construct_eptp(unsigned long root_hpa)
{
	uint64_t eptp;

	/* TODO write the value reading from MSR */
	eptp = VMX_EPT_DEFAULT_MT |
		VMX_EPT_DEFAULT_GAW << VMX_EPT_GAW_EPTP_SHIFT;
	eptp |= (root_hpa & PAGEMASK);

	return (eptp);
}

static void
vmx_set_cr3(struct kvm_vcpu *vcpu, unsigned long cr3)
{
	unsigned long guest_cr3;
	uint64_t eptp;

	guest_cr3 = cr3;

	if (enable_ept) {
		eptp = construct_eptp(cr3);
		vmcs_write64(EPT_POINTER, eptp);
		guest_cr3 = is_paging(vcpu) ?
		    vcpu->arch.cr3 : vcpu->kvm->arch.ept_identity_map_addr;
		ept_load_pdptrs(vcpu);
	}

	vmx_flush_tlb(vcpu);
	vmcs_writel(GUEST_CR3, guest_cr3);
}

static void
vmx_set_cr4(struct kvm_vcpu *vcpu, unsigned long cr4)
{
	unsigned long hw_cr4 = cr4 | (to_vmx(vcpu)->rmode.vm86_active ?
	    KVM_RMODE_VM_CR4_ALWAYS_ON : KVM_PMODE_VM_CR4_ALWAYS_ON);

	vcpu->arch.cr4 = cr4;
	if (enable_ept) {
		if (!is_paging(vcpu)) {
			hw_cr4 &= ~X86_CR4_PAE;
			hw_cr4 |= X86_CR4_PSE;
		} else if (!(cr4 & X86_CR4_PAE)) {
			hw_cr4 &= ~X86_CR4_PAE;
		}
	}

	vmcs_writel(CR4_READ_SHADOW, cr4);
	vmcs_writel(GUEST_CR4, hw_cr4);
}

static uint64_t
vmx_get_segment_base(struct kvm_vcpu *vcpu, int seg)
{
	struct kvm_vmx_segment_field *sf = &kvm_vmx_segment_fields[seg];

	return (vmcs_readl(sf->base));
}

static void
vmx_get_segment(struct kvm_vcpu *vcpu,
    struct kvm_segment *var, int seg)
{
	struct kvm_vmx_segment_field *sf = &kvm_vmx_segment_fields[seg];
	uint32_t ar;

	var->base = vmcs_readl(sf->base);
	var->limit = vmcs_read32(sf->limit);
	var->selector = vmcs_read16(sf->selector);
	ar = vmcs_read32(sf->ar_bytes);

	if ((ar & AR_UNUSABLE_MASK) && !emulate_invalid_guest_state)
		ar = 0;
	var->type = ar & 15;
	var->s = (ar >> 4) & 1;
	var->dpl = (ar >> 5) & 3;
	var->present = (ar >> 7) & 1;
	var->avl = (ar >> 12) & 1;
	var->l = (ar >> 13) & 1;
	var->db = (ar >> 14) & 1;
	var->g = (ar >> 15) & 1;
	var->unusable = (ar >> 16) & 1;
}


static int
vmx_get_cpl(struct kvm_vcpu *vcpu)
{
	if (!is_protmode(vcpu))
		return (0);

	if (vmx_get_rflags(vcpu) & X86_EFLAGS_VM) /* if virtual 8086 */
		return (3);

	return (vmcs_read16(GUEST_CS_SELECTOR) & 3);
}

static uint32_t
vmx_segment_access_rights(struct kvm_segment *var)
{
	uint32_t ar;

	if (var->unusable)
		ar = 1 << 16;
	else {
		ar = var->type & 15;
		ar |= (var->s & 1) << 4;
		ar |= (var->dpl & 3) << 5;
		ar |= (var->present & 1) << 7;
		ar |= (var->avl & 1) << 12;
		ar |= (var->l & 1) << 13;
		ar |= (var->db & 1) << 14;
		ar |= (var->g & 1) << 15;
	}
	if (ar == 0) /* a 0 value means unusable */
		ar = AR_UNUSABLE_MASK;

	return (ar);
}

static void
vmx_set_segment(struct kvm_vcpu *vcpu, struct kvm_segment *var, int seg)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct kvm_vmx_segment_field *sf = &kvm_vmx_segment_fields[seg];
	uint32_t ar;

	if (vmx->rmode.vm86_active && seg == VCPU_SREG_TR) {
		vmx->rmode.tr.selector = var->selector;
		vmx->rmode.tr.base = var->base;
		vmx->rmode.tr.limit = var->limit;
		vmx->rmode.tr.ar = vmx_segment_access_rights(var);
		return;
	}
	vmcs_writel(sf->base, var->base);
	vmcs_write32(sf->limit, var->limit);
	vmcs_write16(sf->selector, var->selector);
	if (vmx->rmode.vm86_active && var->s) {
		/*
		 * Hack real-mode segments into vm86 compatibility.
		 */
		if (var->base == 0xffff0000 && var->selector == 0xf000)
			vmcs_writel(sf->base, 0xf0000);
		ar = 0xf3;
	} else
		ar = vmx_segment_access_rights(var);


	/*
	 *   Fix the "Accessed" bit in AR field of segment registers for older
	 * qemu binaries.
	 *   IA32 arch specifies that at the time of processor reset the
	 * "Accessed" bit in the AR field of segment registers is 1. And qemu
	 * is setting it to 0 in the usedland code. This causes invalid guest
	 * state vmexit when "unrestricted guest" mode is turned on.
	 *    Fix for this setup issue in cpu_reset is being pushed in the qemu
	 * tree. Newer qemu binaries with that qemu fix would not need this
	 * kvm hack.
	 */
	if (enable_unrestricted_guest && (seg != VCPU_SREG_LDTR))
		ar |= 0x1; /* Accessed */

	vmcs_write32(sf->ar_bytes, ar);
}

static void
vmx_get_cs_db_l_bits(struct kvm_vcpu *vcpu, int *db, int *l)
{
	uint32_t ar = vmcs_read32(GUEST_CS_AR_BYTES);

	*db = (ar >> 14) & 1;
	*l = (ar >> 13) & 1;
}

static void
vmx_get_idt(struct kvm_vcpu *vcpu, struct descriptor_table *dt)
{
	dt->limit = vmcs_read32(GUEST_IDTR_LIMIT);
	dt->base = vmcs_readl(GUEST_IDTR_BASE);
}

static void
vmx_set_idt(struct kvm_vcpu *vcpu, struct descriptor_table *dt)
{
	vmcs_write32(GUEST_IDTR_LIMIT, dt->limit);
	vmcs_writel(GUEST_IDTR_BASE, dt->base);
}

static void
vmx_get_gdt(struct kvm_vcpu *vcpu, struct descriptor_table *dt)
{
	dt->limit = vmcs_read32(GUEST_GDTR_LIMIT);
	dt->base = vmcs_readl(GUEST_GDTR_BASE);
}

static void
vmx_set_gdt(struct kvm_vcpu *vcpu, struct descriptor_table *dt)
{
	vmcs_write32(GUEST_GDTR_LIMIT, dt->limit);
	vmcs_writel(GUEST_GDTR_BASE, dt->base);
}

static int
rmode_segment_valid(struct kvm_vcpu *vcpu, int seg)
{
	struct kvm_segment var;
	uint32_t ar;

	vmx_get_segment(vcpu, &var, seg);
	ar = vmx_segment_access_rights(&var);

	if (var.base != (var.selector << 4))
		return (0);
	if (var.limit != 0xffff)
		return (0);
	if (ar != 0xf3)
		return (0);

	return (1);
}

static int
code_segment_valid(struct kvm_vcpu *vcpu)
{
	struct kvm_segment cs;
	unsigned int cs_rpl;

	vmx_get_segment(vcpu, &cs, VCPU_SREG_CS);
	cs_rpl = cs.selector & SELECTOR_RPL_MASK;

	if (cs.unusable)
		return (0);
	if (~cs.type & (AR_TYPE_CODE_MASK|AR_TYPE_ACCESSES_MASK))
		return (0);
	if (!cs.s)
		return (0);

	if (cs.type & AR_TYPE_WRITEABLE_MASK) {
		if (cs.dpl > cs_rpl)
			return (0);
	} else {
		if (cs.dpl != cs_rpl)
			return (0);
	}

	if (!cs.present)
		return (0);

	/*
	 * TODO: Add Reserved field check, this'll require a new member in the
	 * kvm_segment_field structure
	 */
	return (1);
}

static int
stack_segment_valid(struct kvm_vcpu *vcpu)
{
	struct kvm_segment ss;
	unsigned int ss_rpl;

	vmx_get_segment(vcpu, &ss, VCPU_SREG_SS);
	ss_rpl = ss.selector & SELECTOR_RPL_MASK;

	if (ss.unusable)
		return (1);
	if (ss.type != 3 && ss.type != 7)
		return (0);
	if (!ss.s)
		return (0);
	if (ss.dpl != ss_rpl) /* DPL != RPL */
		return (0);
	if (!ss.present)
		return (0);

	return (1);
}

static int
data_segment_valid(struct kvm_vcpu *vcpu, int seg)
{
	struct kvm_segment var;
	unsigned int rpl;

	vmx_get_segment(vcpu, &var, seg);
	rpl = var.selector & SELECTOR_RPL_MASK;

	if (var.unusable)
		return (1);

	if (!var.s)
		return (0);

	if (!var.present)
		return (0);

	if (~var.type & (AR_TYPE_CODE_MASK|AR_TYPE_WRITEABLE_MASK)) {
		if (var.dpl < rpl) /* DPL < RPL */
			return (0);
	}

	/*
	 * TODO: Add other members to kvm_segment_field to allow checking for
	 * other access rights flags
	 */
	return (1);
}

static int
tr_valid(struct kvm_vcpu *vcpu)
{
	struct kvm_segment tr;

	vmx_get_segment(vcpu, &tr, VCPU_SREG_TR);

	if (tr.unusable)
		return (0);
	if (tr.selector & SELECTOR_TI_MASK)	/* TI = 1 */
		return (0);
	if (tr.type != 3 && tr.type != 11)
		return (0);	/* TODO: Check if guest is in IA32e mode */
	if (!tr.present)
		return (0);

	return (1);
}

static int
ldtr_valid(struct kvm_vcpu *vcpu)
{
	struct kvm_segment ldtr;

	vmx_get_segment(vcpu, &ldtr, VCPU_SREG_LDTR);

	if (ldtr.unusable)
		return (1);
	if (ldtr.selector & SELECTOR_TI_MASK)	/* TI = 1 */
		return (0);
	if (ldtr.type != 2)
		return (0);
	if (!ldtr.present)
		return (0);

	return (1);
}

static int
cs_ss_rpl_check(struct kvm_vcpu *vcpu)
{
	struct kvm_segment cs, ss;

	vmx_get_segment(vcpu, &cs, VCPU_SREG_CS);
	vmx_get_segment(vcpu, &ss, VCPU_SREG_SS);

	return ((cs.selector & SELECTOR_RPL_MASK) ==
	    (ss.selector & SELECTOR_RPL_MASK));
}

/*
 * Check if guest state is valid. Returns true if valid, false if
 * not.
 * We assume that registers are always usable
 */
static int
guest_state_valid(struct kvm_vcpu *vcpu)
{
	if (!is_protmode(vcpu)) {
		/* real mode guest state checks */
		if (!rmode_segment_valid(vcpu, VCPU_SREG_CS))
			return (0);
		if (!rmode_segment_valid(vcpu, VCPU_SREG_SS))
			return (0);
		if (!rmode_segment_valid(vcpu, VCPU_SREG_DS))
			return (0);
		if (!rmode_segment_valid(vcpu, VCPU_SREG_ES))
			return (0);
		if (!rmode_segment_valid(vcpu, VCPU_SREG_FS))
			return (0);
		if (!rmode_segment_valid(vcpu, VCPU_SREG_GS))
			return (0);
	} else {
		/* protected mode guest state checks */
		if (!cs_ss_rpl_check(vcpu))
			return (0);
		if (!code_segment_valid(vcpu))
			return (0);
		if (!stack_segment_valid(vcpu))
			return (0);
		if (!data_segment_valid(vcpu, VCPU_SREG_DS))
			return (0);
		if (!data_segment_valid(vcpu, VCPU_SREG_ES))
			return (0);
		if (!data_segment_valid(vcpu, VCPU_SREG_FS))
			return (0);
		if (!data_segment_valid(vcpu, VCPU_SREG_GS))
			return (0);
		if (!tr_valid(vcpu))
			return (0);
		if (!ldtr_valid(vcpu))
			return (0);
	}

	/*
	 * TODO:
	 * - Add checks on RIP
	 * - Add checks on RFLAGS
	 */

	return (1);
}

static int
init_rmode_tss(struct kvm *kvm)
{
	gfn_t fn = rmode_tss_base(kvm) >> PAGESHIFT;
	uint16_t data = 0;
	int ret = 0;
	int r;

	r = kvm_clear_guest_page(kvm, fn, 0, PAGESIZE);
	if (r < 0)
		goto out;
	data = TSS_BASE_SIZE + TSS_REDIRECTION_SIZE;
	r = kvm_write_guest_page(kvm, fn++, &data,
	    TSS_IOPB_BASE_OFFSET, sizeof (uint16_t));

	if (r < 0)
		goto out;
	r = kvm_clear_guest_page(kvm, fn++, 0, PAGESIZE);
	if (r < 0)
		goto out;
	r = kvm_clear_guest_page(kvm, fn, 0, PAGESIZE);
	if (r < 0)
		goto out;
	data = ~0;
	r = kvm_write_guest_page(kvm, fn, &data,
	    RMODE_TSS_SIZE - 2 * PAGESIZE - 1, sizeof (uint8_t));

	if (r < 0)
		goto out;

	ret = 1;
out:
	return (ret);
}


static int
init_rmode_identity_map(struct kvm *kvm)
{
	int i, r, ret;
	pfn_t identity_map_pfn;
	uint32_t tmp;

	if (!enable_ept)
		return (1);
	if ((!kvm->arch.ept_identity_pagetable)) {
		cmn_err(CE_WARN, "EPT: identity-mapping pagetable "
		    "haven't been allocated!\n");
		return (0);
	}
	if ((kvm->arch.ept_identity_pagetable_done))
		return (1);

	ret = 0;
	identity_map_pfn = kvm->arch.ept_identity_map_addr >> PAGESHIFT;
	r = kvm_clear_guest_page(kvm, identity_map_pfn, 0, PAGESIZE);
	if (r < 0)
		goto out;

	/* Set up identity-mapping pagetable for EPT in real mode */
	for (i = 0; i < PT32_ENT_PER_PAGE; i++) {
		tmp = (i << 22) + (PT_VALID | PT_WRITABLE | PT_USER |
		    PT_REF | PT_MOD | PT_PAGESIZE);

		r = kvm_write_guest_page(kvm, identity_map_pfn,
		    &tmp, i * sizeof (tmp), sizeof (tmp));

		if (r < 0)
			goto out;
	}
	kvm->arch.ept_identity_pagetable_done = 1;
	ret = 1;
out:
	return (ret);
}

static void
seg_setup(int seg)
{
	struct kvm_vmx_segment_field *sf = &kvm_vmx_segment_fields[seg];
	unsigned int ar;

	vmcs_write16(sf->selector, 0);
	vmcs_writel(sf->base, 0);
	vmcs_write32(sf->limit, 0xffff);

	if (enable_unrestricted_guest) {
		ar = 0x93;
		if (seg == VCPU_SREG_CS)
			ar |= 0x08; /* code segment */
	} else
		ar = 0xf3;

	vmcs_write32(sf->ar_bytes, ar);
}

static int
alloc_apic_access_page(struct kvm *kvm)
{
	struct kvm_userspace_memory_region kvm_userspace_mem;
	int r = 0;

	memset(&kvm_userspace_mem, 0,
	    sizeof (struct kvm_userspace_memory_region));

	mutex_enter(&kvm->slots_lock);
	if (kvm->arch.apic_access_page)
		goto out;
	kvm_userspace_mem.slot = APIC_ACCESS_PAGE_PRIVATE_MEMSLOT;
	kvm_userspace_mem.flags = 0;
	kvm_userspace_mem.guest_phys_addr = 0xfee00000ULL;
	kvm_userspace_mem.memory_size = PAGESIZE;
	r = __kvm_set_memory_region(kvm, &kvm_userspace_mem, 0);
	if (r)
		goto out;

	kvm->arch.apic_access_page = gfn_to_page(kvm, 0xfee00);
out:
	mutex_exit(&kvm->slots_lock);
	return (r);
}

static int
alloc_identity_pagetable(struct kvm *kvm)
{
	struct kvm_userspace_memory_region kvm_userspace_mem;
	int r = 0;

	mutex_enter(&kvm->slots_lock);
	if (kvm->arch.ept_identity_pagetable)
		goto out;
	kvm_userspace_mem.slot = IDENTITY_PAGETABLE_PRIVATE_MEMSLOT;
	kvm_userspace_mem.flags = 0;
	kvm_userspace_mem.guest_phys_addr =
		kvm->arch.ept_identity_map_addr;
	kvm_userspace_mem.memory_size = PAGESIZE;

	kvm_userspace_mem.userspace_addr = 0;
	r = __kvm_set_memory_region(kvm, &kvm_userspace_mem, 0);
	if (r)
		goto out;

	kvm->arch.ept_identity_pagetable = gfn_to_page(kvm,
			kvm->arch.ept_identity_map_addr >> PAGESHIFT);
out:
	mutex_exit(&kvm->slots_lock);
	return (r);
}

static void
allocate_vpid(struct vcpu_vmx *vmx)
{
	int vpid;

	vmx->vpid = 0;
	if (!enable_vpid)
		return;

	vmx->vpid = hma_vmx_vpid_alloc();
}

static void
__vmx_disable_intercept_for_msr(unsigned long *msr_bitmap, uint32_t msr)
{
	int f = sizeof (unsigned long);

	if (!cpu_has_vmx_msr_bitmap())
		return;

	/*
	 * See Intel PRM Vol. 3, 20.6.9 (MSR-Bitmap Address). Early manuals
	 * have the write-low and read-high bitmap offsets the wrong way round.
	 * We can control MSRs 0x00000000-0x00001fff and 0xc0000000-0xc0001fff.
	 */
	if (msr <= 0x1fff) {
		__clear_bit(msr, msr_bitmap + 0x000 / f); /* read-low */
		__clear_bit(msr, msr_bitmap + 0x800 / f); /* write-low */
	} else if ((msr >= 0xc0000000) && (msr <= 0xc0001fff)) {
		msr &= 0x1fff;
		__clear_bit(msr, msr_bitmap + 0x400 / f); /* read-high */
		__clear_bit(msr, msr_bitmap + 0xc00 / f); /* write-high */
	}
}

static void
vmx_disable_intercept_for_msr(uint32_t msr, int longmode_only)
{
	if (!longmode_only)
		__vmx_disable_intercept_for_msr(vmx_msr_bitmap_legacy, msr);
	__vmx_disable_intercept_for_msr(vmx_msr_bitmap_longmode, msr);
}

/*
 * Sets up the vmcs for emulated real mode.
 */
static void
vmx_vcpu_setup(struct vcpu_vmx *vmx)
{
	uint32_t host_sysenter_cs, msr_low, msr_high;
	uint32_t junk;
	uint64_t host_pat;
	volatile uint64_t a;
	struct descriptor_table dt;
	int i;
	unsigned long kvm_vmx_return;
	uint32_t exec_control;

	/* I/O */
	vmcs_write64(IO_BITMAP_A, vmx_io_bitmap_a_pa);
	vmcs_write64(IO_BITMAP_B, vmx_io_bitmap_b_pa);

	if (cpu_has_vmx_msr_bitmap()) {
		vmcs_write64(MSR_BITMAP, vmx_msr_bitmap_legacy_pa);
	}

	vmcs_write64(VMCS_LINK_POINTER, -1ull); /* 22.3.1.5 */

	/* Control */
	vmcs_write32(PIN_BASED_VM_EXEC_CONTROL,
		vmcs_config.pin_based_exec_ctrl);

	exec_control = vmcs_config.cpu_based_exec_ctrl;
	if (!vm_need_tpr_shadow(vmx->vcpu.kvm)) {
		exec_control &= ~CPU_BASED_TPR_SHADOW;
		exec_control |= CPU_BASED_CR8_STORE_EXITING |
				CPU_BASED_CR8_LOAD_EXITING;
	}

	if (!enable_ept)
		exec_control |= CPU_BASED_CR3_STORE_EXITING |
				CPU_BASED_CR3_LOAD_EXITING  |
				CPU_BASED_INVLPG_EXITING;
	vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, exec_control);

	if (cpu_has_secondary_exec_ctrls()) {
		exec_control = vmcs_config.cpu_based_2nd_exec_ctrl;
		if (!vm_need_virtualize_apic_accesses(vmx->vcpu.kvm))
			exec_control &=
				~SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES;
		if (vmx->vpid == 0)
			exec_control &= ~SECONDARY_EXEC_ENABLE_VPID;
		if (!enable_ept) {
			exec_control &= ~SECONDARY_EXEC_ENABLE_EPT;
			enable_unrestricted_guest = 0;
		}
		if (!enable_unrestricted_guest)
			exec_control &= ~SECONDARY_EXEC_UNRESTRICTED_GUEST;

		if (!ple_gap)
			exec_control &= ~SECONDARY_EXEC_PAUSE_LOOP_EXITING;
		vmcs_write32(SECONDARY_VM_EXEC_CONTROL, exec_control);
	}

	if (ple_gap) {
		vmcs_write32(PLE_GAP, ple_gap);
		vmcs_write32(PLE_WINDOW, ple_window);
	}

	vmcs_write32(PAGE_FAULT_ERROR_CODE_MASK, !!bypass_guest_pf);
	vmcs_write32(PAGE_FAULT_ERROR_CODE_MATCH, !!bypass_guest_pf);
	vmcs_write32(CR3_TARGET_COUNT, 0);	/* 22.2.1 */

	vmcs_writel(HOST_CR0, read_cr0());  /* 22.2.3 */
	vmcs_writel(HOST_CR4, read_cr4());  /* 22.2.3, 22.2.5 */
	vmcs_writel(HOST_CR3, read_cr3());  /* 22.2.3  FIXME: shadow tables */

	vmcs_write16(HOST_CS_SELECTOR, KCS_SEL);  /* 22.2.4 */
#ifndef XXX
	vmcs_write16(HOST_DS_SELECTOR, KDS_SEL);  /* 22.2.4 */
	vmcs_write16(HOST_ES_SELECTOR, KDS_SEL);  /* 22.2.4 */
	vmcs_write16(HOST_FS_SELECTOR, kvm_read_fs());    /* 22.2.4 */
	vmcs_write16(HOST_GS_SELECTOR, kvm_read_gs());    /* 22.2.4 */

#else
	XXX_KVM_PROBE;
	vmcs_write16(HOST_DS_SELECTOR, 0x4b);  /* 22.2.4 */
	vmcs_write16(HOST_ES_SELECTOR, 0x4b);  /* 22.2.4 */
	vmcs_write16(HOST_FS_SELECTOR, 0);    /* 22.2.4 */
	vmcs_write16(HOST_GS_SELECTOR, 0);    /* 22.2.4 */
#endif
	vmcs_write16(HOST_SS_SELECTOR, KDS_SEL);  /* 22.2.4 */

	rdmsrl(MSR_FS_BASE, a);
	vmcs_writel(HOST_FS_BASE, a); /* 22.2.4 */
	rdmsrl(MSR_GS_BASE, a);
	vmcs_writel(HOST_GS_BASE, a); /* 22.2.4 */

	vmcs_write16(HOST_TR_SELECTOR, KTSS_SEL);  /* 22.2.4 */

	kvm_get_idt(&dt);
	vmcs_writel(HOST_IDTR_BASE, dt.base);   /* 22.2.4 */

	__asm__("mov $.Lkvm_vmx_return, %0" : "=r"(kvm_vmx_return));
	vmcs_writel(HOST_RIP, kvm_vmx_return); /* 22.2.5 */
	vmcs_write32(VM_EXIT_MSR_STORE_COUNT, 0);
	vmcs_write32(VM_EXIT_MSR_LOAD_COUNT, 0);
	vmcs_write32(VM_ENTRY_MSR_LOAD_COUNT, 0);

	rdmsr(MSR_IA32_SYSENTER_CS, host_sysenter_cs, junk);
	vmcs_write32(HOST_IA32_SYSENTER_CS, host_sysenter_cs);
	rdmsrl(MSR_IA32_SYSENTER_ESP, a);
	vmcs_writel(HOST_IA32_SYSENTER_ESP, a);   /* 22.2.3 */
	rdmsrl(MSR_IA32_SYSENTER_EIP, a);
	vmcs_writel(HOST_IA32_SYSENTER_EIP, a);   /* 22.2.3 */

	if (vmcs_config.vmexit_ctrl & VM_EXIT_LOAD_IA32_PAT) {
		rdmsr(MSR_IA32_CR_PAT, msr_low, msr_high);
		host_pat = msr_low | ((uint64_t) msr_high << 32);
		vmcs_write64(HOST_IA32_PAT, host_pat);
	}
	if (vmcs_config.vmentry_ctrl & VM_ENTRY_LOAD_IA32_PAT) {
		rdmsr(MSR_IA32_CR_PAT, msr_low, msr_high);
		host_pat = msr_low | ((uint64_t) msr_high << 32);
		/* Write the default value follow host pat */
		vmcs_write64(GUEST_IA32_PAT, host_pat);
		/* Keep arch.pat sync with GUEST_IA32_PAT */
		vmx->vcpu.arch.pat = host_pat;
	}

	for (i = 0; i < NR_VMX_MSR; ++i) {
		uint32_t index = vmx_msr_index[i];
		uint32_t data_low, data_high;
		int j = vmx->nmsrs;

		if (rdmsr_safe(index, &data_low, &data_high) < 0)
			continue;
		if (wrmsr_safe(index, data_low, data_high) < 0)
			continue;
		vmx->guest_msrs[j].index = i;
		vmx->guest_msrs[j].data = 0;
		vmx->guest_msrs[j].mask = -1ull;
		++vmx->nmsrs;
	}

	vmcs_write32(VM_EXIT_CONTROLS, vmcs_config.vmexit_ctrl);

	/* 22.2.1, 20.8.1 */
	vmcs_write32(VM_ENTRY_CONTROLS, vmcs_config.vmentry_ctrl);

	vmcs_writel(CR0_GUEST_HOST_MASK, ~0UL);
	vmx->vcpu.arch.cr4_guest_owned_bits = KVM_CR4_GUEST_OWNED_BITS;
	if (enable_ept)
		vmx->vcpu.arch.cr4_guest_owned_bits |= X86_CR4_PGE;
	vmcs_writel(CR4_GUEST_HOST_MASK, ~vmx->vcpu.arch.cr4_guest_owned_bits);

	if (vmx->vcpu.kvm->arch.tsc_offset == 0) {
		/*
		 * If we are the first VCPU initialized, initialize our guest's
		 * view of the TSC to 0, and then store the derived TSC offset
		 * to be used for any subsequent VCPUs.
		 */
		guest_write_tsc(&vmx->vcpu, 0);
		vmx->vcpu.kvm->arch.tsc_offset = vmx->vcpu.arch.tsc_offset;
	} else {
		/*
		 * If a VCPU has already been initialized, we'll use its
		 * derived TSC offset to assure that our TSCs are (by default
		 * and to the best of our ability) in sync.
		 */
		vmx->vcpu.arch.tsc_offset = vmx->vcpu.kvm->arch.tsc_offset;
		vmcs_write64(TSC_OFFSET, tsc_gethrtime_tick_delta() +
		    vmx->vcpu.arch.tsc_offset);
	}
}

static int
init_rmode(struct kvm *kvm)
{
	if (!init_rmode_tss(kvm))
		return (0);

	if (!init_rmode_identity_map(kvm))
		return (0);

	return (1);
}

static int
vmx_vcpu_reset(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	uint64_t msr;
	int ret, idx;
	page_t *ptp;

	vcpu->arch.regs_avail = ~((1 << VCPU_REGS_RIP) | (1 << VCPU_REGS_RSP));

	if (!init_rmode(vmx->vcpu.kvm)) {
		ret = -ENOMEM;
		goto out;
	}

	vmx->rmode.vm86_active = 0;
	vmx->soft_vnmi_blocked = 0;

	vmx->vcpu.arch.regs[VCPU_REGS_RDX] = get_rdx_init_val();
	kvm_set_cr8(&vmx->vcpu, 0);
	msr = 0xfee00000 | MSR_IA32_APICBASE_ENABLE;

	if (kvm_vcpu_is_bsp(&vmx->vcpu))
		msr |= MSR_IA32_APICBASE_BSP;

	kvm_set_apic_base(&vmx->vcpu, msr);

	fx_init(&vmx->vcpu);

	seg_setup(VCPU_SREG_CS);
	/*
	 * GUEST_CS_BASE should really be 0xffff0000, but VT vm86 mode
	 * insists on having GUEST_CS_BASE == GUEST_CS_SELECTOR << 4.  Sigh.
	 */
	if (kvm_vcpu_is_bsp(&vmx->vcpu)) {
		vmcs_write16(GUEST_CS_SELECTOR, 0xf000);
#ifndef XXX
		vmcs_writel(GUEST_CS_BASE, 0x000f0000);
#else
		vmcs_writel(GUEST_CS_BASE, 0xffff0000);
#endif
	} else {
		vmcs_write16(GUEST_CS_SELECTOR,
		    vmx->vcpu.arch.sipi_vector << 8);
		vmcs_writel(GUEST_CS_BASE, vmx->vcpu.arch.sipi_vector << 12);
	}

	seg_setup(VCPU_SREG_DS);
	seg_setup(VCPU_SREG_ES);
	seg_setup(VCPU_SREG_FS);
	seg_setup(VCPU_SREG_GS);
	seg_setup(VCPU_SREG_SS);

	vmcs_write16(GUEST_TR_SELECTOR, 0);
	vmcs_writel(GUEST_TR_BASE, 0);
	vmcs_write32(GUEST_TR_LIMIT, 0xffff);
	vmcs_write32(GUEST_TR_AR_BYTES, 0x008b);

	vmcs_write16(GUEST_LDTR_SELECTOR, 0);
	vmcs_writel(GUEST_LDTR_BASE, 0);
	vmcs_write32(GUEST_LDTR_LIMIT, 0xffff);
	vmcs_write32(GUEST_LDTR_AR_BYTES, 0x00082);

	vmcs_write32(GUEST_SYSENTER_CS, 0);
	vmcs_writel(GUEST_SYSENTER_ESP, 0);
	vmcs_writel(GUEST_SYSENTER_EIP, 0);

	vmcs_writel(GUEST_RFLAGS, 0x02);

	if (kvm_vcpu_is_bsp(&vmx->vcpu))
		kvm_rip_write(vcpu, 0xfff0);
	else
		kvm_rip_write(vcpu, 0);

	kvm_register_write(vcpu, VCPU_REGS_RSP, 0);

	vmcs_writel(GUEST_DR7, 0x400);

	vmcs_writel(GUEST_GDTR_BASE, 0);
	vmcs_write32(GUEST_GDTR_LIMIT, 0xffff);

	vmcs_writel(GUEST_IDTR_BASE, 0);
	vmcs_write32(GUEST_IDTR_LIMIT, 0xffff);

	vmcs_write32(GUEST_ACTIVITY_STATE, 0);
	vmcs_write32(GUEST_INTERRUPTIBILITY_INFO, 0);
	vmcs_write32(GUEST_PENDING_DBG_EXCEPTIONS, 0);

	/* Special registers */
	vmcs_write64(GUEST_IA32_DEBUGCTL, 0);

	setup_msrs(vmx);

	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, 0);  /* 22.2.1 */

	if (cpu_has_vmx_tpr_shadow()) {
		vmcs_write64(VIRTUAL_APIC_PAGE_ADDR, 0);
		if (vm_need_tpr_shadow(vmx->vcpu.kvm)) {
			ptp = page_numtopp_nolock(hat_getpfnum(kas.a_hat,
			    vmx->vcpu.arch.apic->regs));
			vmcs_write64(VIRTUAL_APIC_PAGE_ADDR, page_to_phys(ptp));
		}

		vmcs_write32(TPR_THRESHOLD, 0);
	}


	if (vm_need_virtualize_apic_accesses(vmx->vcpu.kvm)) {
		vmcs_write64(APIC_ACCESS_ADDR,
		    page_to_phys(vmx->vcpu.kvm->arch.apic_access_page));
	}

	if (vmx->vpid != 0)
		vmcs_write16(VIRTUAL_PROCESSOR_ID, vmx->vpid);

	vmx->vcpu.arch.cr0 = X86_CR0_NW | X86_CR0_CD | X86_CR0_ET;
	vmx_set_cr0(&vmx->vcpu, kvm_read_cr0(vcpu)); /* enter rmode */
	vmx_set_cr4(&vmx->vcpu, 0);
	vmx_set_efer(&vmx->vcpu, 0);

	vmx_fpu_activate(&vmx->vcpu);
	update_exception_bitmap(&vmx->vcpu);
	vpid_sync_vcpu_all(vmx);

	ret = 0;

	/* HACK: Don't enable emulation on guest boot/reset */
	vmx->emulation_required = 0;

out:
	return (ret);
}

static void
enable_irq_window(struct kvm_vcpu *vcpu)
{
	uint32_t cpu_based_vm_exec_control;

	cpu_based_vm_exec_control = vmcs_read32(CPU_BASED_VM_EXEC_CONTROL);
	cpu_based_vm_exec_control |= CPU_BASED_VIRTUAL_INTR_PENDING;
	vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, cpu_based_vm_exec_control);
}

static void
enable_nmi_window(struct kvm_vcpu *vcpu)
{
	uint32_t cpu_based_vm_exec_control;

	if (!cpu_has_virtual_nmis()) {
		enable_irq_window(vcpu);
		return;
	}

	cpu_based_vm_exec_control = vmcs_read32(CPU_BASED_VM_EXEC_CONTROL);
	cpu_based_vm_exec_control |= CPU_BASED_VIRTUAL_NMI_PENDING;
	vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, cpu_based_vm_exec_control);
}

static void
vmx_inject_irq(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	uint32_t intr;
	int irq = vcpu->arch.interrupt.nr;

	KVM_TRACE1(inj__virq, int, irq);
	KVM_VCPU_KSTAT_INC(vcpu, kvmvs_irq_injections);

	if (vmx->rmode.vm86_active) {
		vmx->rmode.irq.pending = 1;
		vmx->rmode.irq.vector = irq;
		vmx->rmode.irq.rip = kvm_rip_read(vcpu);
		if (vcpu->arch.interrupt.soft)
			vmx->rmode.irq.rip +=
				vmx->vcpu.arch.event_exit_inst_len;
		vmcs_write32(VM_ENTRY_INTR_INFO_FIELD,
		    irq | INTR_TYPE_SOFT_INTR | INTR_INFO_VALID_MASK);
		vmcs_write32(VM_ENTRY_INSTRUCTION_LEN, 1);
		kvm_rip_write(vcpu, vmx->rmode.irq.rip - 1);
		return;
	}
	intr = irq | INTR_INFO_VALID_MASK;
	if (vcpu->arch.interrupt.soft) {
		intr |= INTR_TYPE_SOFT_INTR;
		vmcs_write32(VM_ENTRY_INSTRUCTION_LEN,
		    vmx->vcpu.arch.event_exit_inst_len);
	} else
		intr |= INTR_TYPE_EXT_INTR;

	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, intr);
}

static void
vmx_inject_nmi(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	if (!cpu_has_virtual_nmis()) {
		/*
		 * Tracking the NMI-blocked state in software is built upon
		 * finding the next open IRQ window. This, in turn, depends on
		 * well-behaving guests: They have to keep IRQs disabled at
		 * least as long as the NMI handler runs. Otherwise we may
		 * cause NMI nesting, maybe breaking the guest. But as this is
		 * highly unlikely, we can live with the residual risk.
		 */
		vmx->soft_vnmi_blocked = 1;
		vmx->vnmi_blocked_time = 0;
	}

	KVM_VCPU_KSTAT_INC(vcpu, kvmvs_nmi_injections);

	if (vmx->rmode.vm86_active) {
		vmx->rmode.irq.pending = 1;
		vmx->rmode.irq.vector = NMI_VECTOR;
		vmx->rmode.irq.rip = kvm_rip_read(vcpu);
		vmcs_write32(VM_ENTRY_INTR_INFO_FIELD,
		    NMI_VECTOR | INTR_TYPE_SOFT_INTR |
		    INTR_INFO_VALID_MASK);
		vmcs_write32(VM_ENTRY_INSTRUCTION_LEN, 1);
		kvm_rip_write(vcpu, vmx->rmode.irq.rip - 1);
		return;
	}
	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD,
	    INTR_TYPE_NMI_INTR | INTR_INFO_VALID_MASK | NMI_VECTOR);
}

static int
vmx_nmi_allowed(struct kvm_vcpu *vcpu)
{
	if (!cpu_has_virtual_nmis() && to_vmx(vcpu)->soft_vnmi_blocked)
		return (0);

	return (!(vmcs_read32(GUEST_INTERRUPTIBILITY_INFO) &
	    (GUEST_INTR_STATE_MOV_SS | GUEST_INTR_STATE_NMI)));
}

static int
vmx_get_nmi_mask(struct kvm_vcpu *vcpu)
{
	if (!cpu_has_virtual_nmis())
		return (to_vmx(vcpu)->soft_vnmi_blocked);
	else
		return (!!(vmcs_read32(GUEST_INTERRUPTIBILITY_INFO) &
		    GUEST_INTR_STATE_NMI));
}

static void
vmx_set_nmi_mask(struct kvm_vcpu *vcpu, int masked)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	if (!cpu_has_virtual_nmis()) {
		if (vmx->soft_vnmi_blocked != masked) {
			vmx->soft_vnmi_blocked = masked;
			vmx->vnmi_blocked_time = 0;
		}

		return;
	} else {
		if (masked) {
			vmcs_set_bits(GUEST_INTERRUPTIBILITY_INFO,
			    GUEST_INTR_STATE_NMI);
		} else {
			vmcs_clear_bits(GUEST_INTERRUPTIBILITY_INFO,
			    GUEST_INTR_STATE_NMI);
		}
	}
}

static int
vmx_interrupt_allowed(struct kvm_vcpu *vcpu)
{
	return ((vmcs_readl(GUEST_RFLAGS) & X86_EFLAGS_IF) &&
	    !(vmcs_read32(GUEST_INTERRUPTIBILITY_INFO) &
	    (GUEST_INTR_STATE_STI | GUEST_INTR_STATE_MOV_SS)));
}

static int
vmx_set_tss_addr(struct kvm *kvmp, uintptr_t addr)
{
	int ret;

	struct kvm_userspace_memory_region tss_mem = {
		.slot = TSS_PRIVATE_MEMSLOT,
		.guest_phys_addr = addr,
		.memory_size = PAGESIZE * 3,
		.flags = 0,
	};

	ret = kvm_set_memory_region(kvmp, &tss_mem, 0);

	if (ret)
		return (ret);

	kvmp->arch.tss_addr = addr;

	return (DDI_SUCCESS);
}

static int
handle_rmode_exception(struct kvm_vcpu *vcpu, int vec, uint32_t err_code)
{
	/*
	 * Instruction with address size override prefix opcode 0x67
	 * Cause the #SS fault with 0 error code in VM86 mode.
	 */
	if (((vec == GP_VECTOR) || (vec == SS_VECTOR)) && err_code == 0) {
		if (emulate_instruction(vcpu, 0, 0, 0) == EMULATE_DONE)
			return (1);
	}

	/*
	 * Forward all other exceptions that are valid in real mode.
	 * FIXME: Breaks guest debugging in real mode, needs to be fixed with
	 * the required debugging infrastructure rework.
	 */
	switch (vec) {
	case DB_VECTOR:
		if (vcpu->guest_debug &
		    (KVM_GUESTDBG_SINGLESTEP | KVM_GUESTDBG_USE_HW_BP)) {
			return (0);
		}

		kvm_queue_exception(vcpu, vec);
		return (1);

	case BP_VECTOR:
		/*
		 * Update instruction length as we may reinject the exception
		 * from user space while in guest debugging mode.
		 */
		to_vmx(vcpu)->vcpu.arch.event_exit_inst_len =
		    vmcs_read32(VM_EXIT_INSTRUCTION_LEN);

		if (vcpu->guest_debug & KVM_GUESTDBG_USE_SW_BP)
			return (0);
		/* fall through */

	case DE_VECTOR:
	case OF_VECTOR:
	case BR_VECTOR:
	case UD_VECTOR:
	case DF_VECTOR:
	case SS_VECTOR:
	case GP_VECTOR:
	case MF_VECTOR:
		kvm_queue_exception(vcpu, vec);
		return (1);
	}

	return (0);
}

/*
 * Trigger machine check on the host. We assume all the MSRs are already set up
 * by the CPU and that we still run on the same CPU as the MCE occurred on.
 * We pass a fake environment to the machine check handler because we want
 * the guest to be always treated like user space, no matter what context
 * it used internally.
 */
static void kvm_machine_check(void)
{
#if defined(CONFIG_X86_MCE)
	struct pt_regs regs = {
		.cs = 3, /* Fake ring 3 no matter what the guest ran on */
		.flags = X86_EFLAGS_IF,
	};

	do_machine_check(&regs, 0);
#endif
}

static int
handle_machine_check(struct kvm_vcpu *vcpu)
{
	/* already handled by vcpu_run */
	return (1);
}

/*
 * The guest has exited.  See if we can fix it or if we need userspace
 * assistance.
 */
static int
handle_exception(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct kvm_run *kvm_run = vcpu->run;
	uint32_t intr_info, ex_no, error_code;
	unsigned long cr2, rip, dr6;
	uint32_t vect_info;
	enum emulation_result er;

	vect_info = vmx->idt_vectoring_info;
	intr_info = vmcs_read32(VM_EXIT_INTR_INFO);

	if (is_machine_check(intr_info))
		return (handle_machine_check(vcpu));

	if ((vect_info & VECTORING_INFO_VALID_MASK) &&
	    !is_page_fault(intr_info)) {
		vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
		vcpu->run->internal.suberror = KVM_INTERNAL_ERROR_SIMUL_EX;
		vcpu->run->internal.ndata = 2;
		vcpu->run->internal.data[0] = vect_info;
		vcpu->run->internal.data[1] = intr_info;
		return (0);
	}

	if ((intr_info & INTR_INFO_INTR_TYPE_MASK) == INTR_TYPE_NMI_INTR)
		return (1);  /* already handled by vmx_vcpu_run() */

	if (is_no_device(intr_info)) {
		vmx_fpu_activate(vcpu);
		return (1);
	}

	if (is_invalid_opcode(intr_info)) {
		er = emulate_instruction(vcpu, 0, 0, EMULTYPE_TRAP_UD);
		if (er != EMULATE_DONE)
			kvm_queue_exception(vcpu, UD_VECTOR);
		return (1);
	}

	error_code = 0;
	rip = kvm_rip_read(vcpu);

	if (intr_info & INTR_INFO_DELIVER_CODE_MASK)
		error_code = vmcs_read32(VM_EXIT_INTR_ERROR_CODE);

	if (is_page_fault(intr_info)) {
		/* EPT won't cause page fault directly */
		if (enable_ept)
			cmn_err(CE_PANIC, "page fault with ept enabled\n");
		cr2 = vmcs_readl(EXIT_QUALIFICATION);

		KVM_TRACE2(page__fault, uintptr_t, cr2, uint32_t, error_code);

		if (kvm_event_needs_reinjection(vcpu))
			kvm_mmu_unprotect_page_virt(vcpu, cr2);
		return (kvm_mmu_page_fault(vcpu, cr2, error_code));
	}

	if (vmx->rmode.vm86_active && handle_rmode_exception(vcpu,
	    intr_info & INTR_INFO_VECTOR_MASK, error_code)) {
		if (vcpu->arch.halt_request) {
			vcpu->arch.halt_request = 0;
			return (kvm_emulate_halt(vcpu));
		}
		return (1);
	}

	ex_no = intr_info & INTR_INFO_VECTOR_MASK;
	switch (ex_no) {
	case DB_VECTOR:
		dr6 = vmcs_readl(EXIT_QUALIFICATION);
		if (!(vcpu->guest_debug &
		    (KVM_GUESTDBG_SINGLESTEP | KVM_GUESTDBG_USE_HW_BP))) {
			vcpu->arch.dr6 = dr6 | DR6_FIXED_1;
			kvm_queue_exception(vcpu, DB_VECTOR);
			return (1);
		}

		kvm_run->debug.arch.dr6 = dr6 | DR6_FIXED_1;
		kvm_run->debug.arch.dr7 = vmcs_readl(GUEST_DR7);
		/* fall through */
	case BP_VECTOR:
		/*
		 * Update instruction length as we may reinject #BP from
		 * user space while in guest debugging mode. Reading it for
		 * #DB as well causes no harm, it is not used in that case.
		 */
		vmx->vcpu.arch.event_exit_inst_len =
			vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
		kvm_run->exit_reason = KVM_EXIT_DEBUG;
		kvm_run->debug.arch.pc = vmcs_readl(GUEST_CS_BASE) + rip;
		kvm_run->debug.arch.exception = ex_no;
		break;
	case AC_VECTOR:
		kvm_queue_exception_e(vcpu, AC_VECTOR, error_code);
		return (1);
	default:
		kvm_run->exit_reason = KVM_EXIT_EXCEPTION;
		kvm_run->ex.exception = ex_no;
		kvm_run->ex.error_code = error_code;
		break;
	}

	return (0);
}

static int
handle_external_interrupt(struct kvm_vcpu *vcpu)
{
	KVM_VCPU_KSTAT_INC(vcpu, kvmvs_irq_exits);
	if (CPU->cpu_runrun || CPU->cpu_kprunrun) {
		vcpu->run->exit_reason = KVM_EXIT_INTR;
		vcpu->run->hw.hardware_exit_reason =
		    EXIT_REASON_EXTERNAL_INTERRUPT;
		return (0);
	} else {
		return (1);
	}
}

static int
handle_triple_fault(struct kvm_vcpu *vcpu)
{
	vcpu->run->exit_reason = KVM_EXIT_SHUTDOWN;
	return (0);
}

static int
handle_io(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qualification;
	int size, in, string;
	unsigned port;

	KVM_VCPU_KSTAT_INC(vcpu, kvmvs_io_exits);

	exit_qualification = vmcs_readl(EXIT_QUALIFICATION);
	string = (exit_qualification & 16) != 0;

	if (string) {
		if (emulate_instruction(vcpu, 0, 0, 0) == EMULATE_DO_MMIO)
			return (0);
		return (1);
	}

	size = (exit_qualification & 7) + 1;
	in = (exit_qualification & 8) != 0;
	port = exit_qualification >> 16;
	skip_emulated_instruction(vcpu);

	return (kvm_emulate_pio(vcpu, in, size, port));
}

static void
vmx_patch_hypercall(struct kvm_vcpu *vcpu, unsigned char *hypercall)
{
	/*
	 * Patch in the VMCALL instruction:
	 */
	hypercall[0] = 0x0f;
	hypercall[1] = 0x01;
	hypercall[2] = 0xc1;
}

static int
handle_cr(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qualification, val;
	int cr;
	int reg;

	exit_qualification = vmcs_readl(EXIT_QUALIFICATION);
	cr = exit_qualification & 15;
	reg = (exit_qualification >> 8) & 15;
	KVM_TRACE3(cr, int, cr, int, reg, int, (exit_qualification >> 4) & 3);
	switch ((exit_qualification >> 4) & 3) {
	case 0: /* mov to cr */
		val = kvm_register_read(vcpu, reg);
		KVM_TRACE2(cr__write, int, cr, unsigned long, val);

		switch (cr) {
		case 0:
			kvm_set_cr0(vcpu, val);
			skip_emulated_instruction(vcpu);
			return (1);
		case 3:
			kvm_set_cr3(vcpu, val);
			skip_emulated_instruction(vcpu);
			return (1);
		case 4:
			kvm_set_cr4(vcpu, val);
			skip_emulated_instruction(vcpu);
			return (1);
		case 8: {
			uint8_t cr8_prev = kvm_get_cr8(vcpu);
			uint8_t cr8 = kvm_register_read(vcpu, reg);
			kvm_set_cr8(vcpu, cr8);
			skip_emulated_instruction(vcpu);

			if (irqchip_in_kernel(vcpu->kvm))
				return (1);

			if (cr8_prev <= cr8)
				return (1);

			vcpu->run->exit_reason = KVM_EXIT_SET_TPR;
			return (0);
		}
		};

		break;

	case 2: /* clts */
		vmx_set_cr0(vcpu, kvm_read_cr0_bits(vcpu, ~X86_CR0_TS));
		KVM_TRACE2(cr__write, int, 0,
		    unsigned long, kvm_read_cr0(vcpu));

		skip_emulated_instruction(vcpu);
		vmx_fpu_activate(vcpu);
		return (1);
	case 1: /* mov from cr */
		switch (cr) {
		case 3:
			kvm_register_write(vcpu, reg, vcpu->arch.cr3);
			KVM_TRACE2(cr__read, int, cr,
			    unsigned long, vcpu->arch.cr3);
			skip_emulated_instruction(vcpu);
			return (1);
		case 8:
			val = kvm_get_cr8(vcpu);
			kvm_register_write(vcpu, reg, val);
			KVM_TRACE2(cr__read, int, cr, unsigned long, val);
			skip_emulated_instruction(vcpu);
			return (1);
		}
		break;
	case 3: /* lmsw */
		val = (exit_qualification >> LMSW_SOURCE_DATA_SHIFT) & 0x0f;
		KVM_TRACE2(cr__write, int, 0, unsigned long,
		    (kvm_read_cr0(vcpu) & ~0xful) | val);
		kvm_lmsw(vcpu, val);

		skip_emulated_instruction(vcpu);
		return (1);
	default:
		break;
	}
	vcpu->run->exit_reason = 0;
	cmn_err(CE_WARN, "unhandled control register: op %d cr %d\n",
	    (int)(exit_qualification >> 4) & 3, cr);

	return (0);
}

static int
check_dr_alias(struct kvm_vcpu *vcpu)
{
	if (kvm_read_cr4_bits(vcpu, X86_CR4_DE)) {
		kvm_queue_exception(vcpu, UD_VECTOR);
		return (-1);
	}

	return (0);
}

static int
handle_dr(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qualification;
	unsigned long val;
	int dr, reg;

	/* Do not handle if the CPL > 0, will trigger GP on re-entry */
	if (!kvm_require_cpl(vcpu, 0))
		return (1);

	dr = vmcs_readl(GUEST_DR7);

	if (dr & DR7_GD) {
		/*
		 * As the vm-exit takes precedence over the debug trap, we
		 * need to emulate the latter, either for the host or the
		 * guest debugging itself.
		 */
		if (vcpu->guest_debug & KVM_GUESTDBG_USE_HW_BP) {
			vcpu->run->debug.arch.dr6 = vcpu->arch.dr6;
			vcpu->run->debug.arch.dr7 = dr;
			vcpu->run->debug.arch.pc =
				vmcs_readl(GUEST_CS_BASE) +
				vmcs_readl(GUEST_RIP);
			vcpu->run->debug.arch.exception = DB_VECTOR;
			vcpu->run->exit_reason = KVM_EXIT_DEBUG;
			return (0);
		} else {
			vcpu->arch.dr7 &= ~DR7_GD;
			vcpu->arch.dr6 |= DR6_BD;
			vmcs_writel(GUEST_DR7, vcpu->arch.dr7);
			kvm_queue_exception(vcpu, DB_VECTOR);
			return (1);
		}
	}

	exit_qualification = vmcs_readl(EXIT_QUALIFICATION);
	dr = exit_qualification & DEBUG_REG_ACCESS_NUM;
	reg = DEBUG_REG_ACCESS_REG(exit_qualification);
	if (exit_qualification & TYPE_MOV_FROM_DR) {
		switch (dr) {
		case 0 ... 3:
			val = vcpu->arch.db[dr];
			break;
		case 4:
			if (check_dr_alias(vcpu) < 0)
				return (1);
			/* fall through */
		case 6:
			val = vcpu->arch.dr6;
			break;
		case 5:
			if (check_dr_alias(vcpu) < 0)
				return (1);
			/* fall through */
		default: /* 7 */
			val = vcpu->arch.dr7;
			break;
		}
		kvm_register_write(vcpu, reg, val);
	} else {
		val = vcpu->arch.regs[reg];
		switch (dr) {
		case 0 ... 3:
			vcpu->arch.db[dr] = val;
			if (!(vcpu->guest_debug & KVM_GUESTDBG_USE_HW_BP))
				vcpu->arch.eff_db[dr] = val;
			break;
		case 4:
			if (check_dr_alias(vcpu) < 0)
				return (1);
			/* fall through */
		case 6:
			if (val & 0xffffffff00000000ULL) {
				kvm_inject_gp(vcpu, 0);
				return (1);
			}
			vcpu->arch.dr6 = (val & DR6_VOLATILE) | DR6_FIXED_1;
			break;
		case 5:
			if (check_dr_alias(vcpu) < 0)
				return (1);
			/* fall through */
		default: /* 7 */
			if (val & 0xffffffff00000000ULL) {
				kvm_inject_gp(vcpu, 0);
				return (1);
			}
			vcpu->arch.dr7 = (val & DR7_VOLATILE) | DR7_FIXED_1;

			if (!(vcpu->guest_debug & KVM_GUESTDBG_USE_HW_BP)) {
				vmcs_writel(GUEST_DR7, vcpu->arch.dr7);
				vcpu->arch.switch_db_regs =
					(val & DR7_BP_EN_MASK);

			}
			break;
		}
	}
	skip_emulated_instruction(vcpu);
	return (1);
}

static int
handle_cpuid(struct kvm_vcpu *vcpu)
{
	kvm_emulate_cpuid(vcpu);
	return (1);
}

static int
handle_rdmsr(struct kvm_vcpu *vcpu)
{
	uint32_t ecx = vcpu->arch.regs[VCPU_REGS_RCX];
	uint64_t data;

	if (vmx_get_msr(vcpu, ecx, &data)) {
		KVM_TRACE1(msr__read__ex, uint32_t, ecx);
		kvm_inject_gp(vcpu, 0);
		return (1);
	}

	KVM_TRACE2(msr__read, uint32_t, ecx, uint64_t, data);

	/* FIXME: handling of bits 32:63 of rax, rdx */
	vcpu->arch.regs[VCPU_REGS_RAX] = data & -1u;
	vcpu->arch.regs[VCPU_REGS_RDX] = (data >> 32) & -1u;
	skip_emulated_instruction(vcpu);
	return (1);
}

static int
handle_wrmsr(struct kvm_vcpu *vcpu)
{
	uint32_t ecx = vcpu->arch.regs[VCPU_REGS_RCX];
	uint64_t data = (vcpu->arch.regs[VCPU_REGS_RAX] & -1u) |
	    ((uint64_t)(vcpu->arch.regs[VCPU_REGS_RDX] & -1u) << 32);

	if (vmx_set_msr(vcpu, ecx, data) != 0) {
		KVM_TRACE2(msr__write__ex, uint32_t, ecx, uint64_t, data);
		kvm_inject_gp(vcpu, 0);
		return (1);
	}

	KVM_TRACE2(msr__write, uint32_t, ecx, uint64_t, data);
	skip_emulated_instruction(vcpu);
	return (1);
}

static int
handle_tpr_below_threshold(struct kvm_vcpu *vcpu)
{
	return (1);
}

static int
handle_interrupt_window(struct kvm_vcpu *vcpu)
{
	uint32_t cpu_based_vm_exec_control;

	/* clear pending irq */
	cpu_based_vm_exec_control = vmcs_read32(CPU_BASED_VM_EXEC_CONTROL);
	cpu_based_vm_exec_control &= ~CPU_BASED_VIRTUAL_INTR_PENDING;
	vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, cpu_based_vm_exec_control);

	KVM_VCPU_KSTAT_INC(vcpu, kvmvs_irq_window_exits);

	/*
	 * If the user space waits to inject interrupts, exit as soon as
	 * possible
	 */
	if (!irqchip_in_kernel(vcpu->kvm) &&
	    vcpu->run->request_interrupt_window &&
	    !kvm_cpu_has_interrupt(vcpu)) {
		vcpu->run->exit_reason = KVM_EXIT_IRQ_WINDOW_OPEN;
		return (0);
	}
	return (1);
}

static int
handle_halt(struct kvm_vcpu *vcpu)
{
	skip_emulated_instruction(vcpu);
	return (kvm_emulate_halt(vcpu));
}

static int
handle_vmcall(struct kvm_vcpu *vcpu)
{
	skip_emulated_instruction(vcpu);
	kvm_emulate_hypercall(vcpu);
	return (1);
}

static int
handle_vmx_insn(struct kvm_vcpu *vcpu)
{
	kvm_queue_exception(vcpu, UD_VECTOR);
	return (1);
}

static int
handle_invlpg(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qualification = vmcs_readl(EXIT_QUALIFICATION);

	kvm_mmu_invlpg(vcpu, exit_qualification);
	skip_emulated_instruction(vcpu);
	return (1);
}

static int
handle_wbinvd(struct kvm_vcpu *vcpu)
{
	skip_emulated_instruction(vcpu);
	/* TODO: Add support for VT-d/pass-through device */
	return (1);
}

static int
handle_apic_access(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qualification;
	enum emulation_result er;
	unsigned long offset;

	exit_qualification = vmcs_readl(EXIT_QUALIFICATION);
	offset = exit_qualification & 0xffful;

	er = emulate_instruction(vcpu, 0, 0, 0);

	if (er !=  EMULATE_DONE) {
		cmn_err(CE_PANIC, "Fail to handle apic access vmexit! "
		    "Offset is 0x%lx\n", offset);
	}

	return (1);
}

static int
handle_task_switch(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	unsigned long exit_qualification;
	uint16_t tss_selector;
	int reason, type, idt_v;

	idt_v = (vmx->idt_vectoring_info & VECTORING_INFO_VALID_MASK);
	type = (vmx->idt_vectoring_info & VECTORING_INFO_TYPE_MASK);
	exit_qualification = vmcs_readl(EXIT_QUALIFICATION);

	reason = (uint32_t)exit_qualification >> 30;
	if (reason == TASK_SWITCH_GATE && idt_v) {
		switch (type) {
		case INTR_TYPE_NMI_INTR:
			vcpu->arch.nmi_injected = 0;
			if (cpu_has_virtual_nmis()) {
				vmcs_set_bits(GUEST_INTERRUPTIBILITY_INFO,
				    GUEST_INTR_STATE_NMI);
			}
			break;
		case INTR_TYPE_EXT_INTR:
		case INTR_TYPE_SOFT_INTR:
			kvm_clear_interrupt_queue(vcpu);
			break;
		case INTR_TYPE_HARD_EXCEPTION:
		case INTR_TYPE_SOFT_EXCEPTION:
			kvm_clear_exception_queue(vcpu);
			break;
		default:
			break;
		}
	}
	tss_selector = exit_qualification;

	if (!idt_v || (type != INTR_TYPE_HARD_EXCEPTION &&
	    type != INTR_TYPE_EXT_INTR && type != INTR_TYPE_NMI_INTR))
		skip_emulated_instruction(vcpu);

	if (!kvm_task_switch(vcpu, tss_selector, reason))
		return (0);

	/* clear all local breakpoint enable flags */
	vmcs_writel(GUEST_DR7, vmcs_readl(GUEST_DR7) & ~55);

	/*
	 * TODO: What about debug traps on tss switch?
	 * Are we supposed to inject them and update dr6?
	 */

	return (1);
}

static int
handle_ept_violation(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qualification;
	gpa_t gpa;
	int gla_validity;

	exit_qualification = vmcs_readl(EXIT_QUALIFICATION);

	if (exit_qualification & (1 << 6)) {
		cmn_err(CE_PANIC, "EPT: GPA exceeds GAW!\n");
	}

	gla_validity = (exit_qualification >> 7) & 0x3;
	if (gla_validity != 0x3 && gla_validity != 0x1 && gla_validity != 0) {
		cmn_err(CE_WARN, "EPT: Handling EPT violation failed!\n");
		cmn_err(CE_CONT, "EPT: GPA: 0x%lx, GVA: 0x%lx\n",
			(long unsigned int)vmcs_read64(GUEST_PHYSICAL_ADDRESS),
			vmcs_readl(GUEST_LINEAR_ADDRESS));
		cmn_err(CE_PANIC, "EPT: Exit qualification is 0x%lx\n",
			(long unsigned int)exit_qualification);
		vcpu->run->exit_reason = KVM_EXIT_UNKNOWN;
		vcpu->run->hw.hardware_exit_reason = EXIT_REASON_EPT_VIOLATION;
		return (0);
	}

	gpa = vmcs_read64(GUEST_PHYSICAL_ADDRESS);
	KVM_TRACE2(page__fault, gpa_t, gpa, unsigned long, exit_qualification);

	return (kvm_mmu_page_fault(vcpu, gpa & PAGEMASK, 0));
}

/* XXX - The following assumes we're running on the maximum sized box... */
#define	MAX_PHYSMEM_BITS 46
static uint64_t
ept_rsvd_mask(uint64_t spte, int level)
{
	int i;
	uint64_t mask = 0;

#ifdef XXX
	for (i = 51; i > boot_cpu_data.x86_phys_bits; i--)
		mask |= (1ULL << i);
#else
	XXX_KVM_PROBE;
	for (i = 51; i > MAX_PHYSMEM_BITS; i--)
		mask |= (1ULL << i);
#endif

	if (level > 2)
		/* bits 7:3 reserved */
		mask |= 0xf8;
	else if (level == 2) {
		if (spte & (1ULL << 7))
			/* 2MB ref, bits 20:12 reserved */
			mask |= 0x1ff000;
		else
			/* bits 6:3 reserved */
			mask |= 0x78;
	}

	return (mask);
}


static void
ept_misconfig_inspect_spte(struct kvm_vcpu *vcpu, uint64_t spte, int level)
{
	cmn_err(CE_WARN, "%s: spte 0x%lx level %d\n", __func__, spte, level);

	/* 010b (write-only) */
	if ((spte & 0x7) == 0x2)
		cmn_err(CE_CONT, "!%s: spte is write-only\n", __func__);

	/* 110b (write/execute) */
	if ((spte & 0x7) == 0x6)
		cmn_err(CE_CONT, "!%s: spte is write-execute\n", __func__);

	/* 100b (execute-only) and value not supported by logical processor */
	if (!cpu_has_vmx_ept_execute_only()) {
		if ((spte & 0x7) == 0x4)
			cmn_err(CE_CONT,
			    "!%s: spte is execute-only\n", __func__);
	}

	/* not 000b */
	if ((spte & 0x7)) {
		uint64_t rsvd_bits = spte & ept_rsvd_mask(spte, level);

		if (rsvd_bits != 0) {
			cmn_err(CE_CONT, "!%s: rsvd_bits = 0x%lx\n",
			    __func__, rsvd_bits);
		}

		if (level == 1 || (level == 2 && (spte & (1ULL << 7)))) {
			uint64_t ept_mem_type = (spte & 0x38) >> 3;

			if (ept_mem_type == 2 || ept_mem_type == 3 ||
			    ept_mem_type == 7) {
				cmn_err(CE_CONT, "!%s: ept_mem_type=0x%lx\n",
						__func__, ept_mem_type);
			}
		}
	}
}

static int
handle_ept_misconfig(struct kvm_vcpu *vcpu)
{
	uint64_t sptes[4];
	int nr_sptes, i;
	gpa_t gpa;

	gpa = vmcs_read64(GUEST_PHYSICAL_ADDRESS);

	cmn_err(CE_WARN, "EPT: Misconfiguration.\n");
	cmn_err(CE_CONT, "!EPT: GPA: 0x%lx\n", gpa);
	nr_sptes = kvm_mmu_get_spte_hierarchy(vcpu, gpa, sptes);

	for (i = PT64_ROOT_LEVEL; i > PT64_ROOT_LEVEL - nr_sptes; --i)
		ept_misconfig_inspect_spte(vcpu, sptes[i-1], i);

	vcpu->run->exit_reason = KVM_EXIT_UNKNOWN;
	vcpu->run->hw.hardware_exit_reason = EXIT_REASON_EPT_MISCONFIG;

	return (0);
}

static int
handle_nmi_window(struct kvm_vcpu *vcpu)
{
	uint32_t cpu_based_vm_exec_control;

	/* clear pending NMI */
	cpu_based_vm_exec_control = vmcs_read32(CPU_BASED_VM_EXEC_CONTROL);
	cpu_based_vm_exec_control &= ~CPU_BASED_VIRTUAL_NMI_PENDING;
	vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, cpu_based_vm_exec_control);

	KVM_VCPU_KSTAT_INC(vcpu, kvmvs_nmi_window_exits);

	return (1);
}


static int handle_invalid_guest_state(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	enum emulation_result err = EMULATE_DONE;
	int ret = 1;

	while (!guest_state_valid(vcpu)) {
		err = emulate_instruction(vcpu, 0, 0, 0);

		if (err == EMULATE_DO_MMIO) {
			ret = 0;
			goto out;
		}

		if (err != EMULATE_DONE) {
			vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
			vcpu->run->internal.suberror =
			    KVM_INTERNAL_ERROR_EMULATION;
			vcpu->run->internal.ndata = 0;
			ret = 0;
			goto out;
		}

#ifdef XXX
		if ((current))
			goto out;
#else
		XXX_KVM_PROBE;
#endif
	}

	vmx->emulation_required = 0;
out:
	return (ret);
}

/*
 * Indicate a busy-waiting vcpu in spinlock. We do not enable the PAUSE
 * exiting, so only get here on cpu with PAUSE-Loop-Exiting.
 */
static int
handle_pause(struct kvm_vcpu *vcpu)
{
	skip_emulated_instruction(vcpu);
#ifdef XXX
	kvm_vcpu_on_spin(vcpu);
#else
	XXX_KVM_PROBE;
#endif
	return (1);
}

static int
handle_invalid_op(struct kvm_vcpu *vcpu)
{
	kvm_queue_exception(vcpu, UD_VECTOR);
	return (1);
}

/*
 * The exit handlers return 1 if the exit was handled fully and guest execution
 * may resume.  Otherwise they set the kvm_run parameter to indicate what needs
 * to be done to userspace and return 0.
 */
static int (*kvm_vmx_exit_handlers[])(struct kvm_vcpu *vcpu) = {
	[EXIT_REASON_EXCEPTION_NMI]		= handle_exception,
	[EXIT_REASON_EXTERNAL_INTERRUPT]	= handle_external_interrupt,
	[EXIT_REASON_TRIPLE_FAULT]		= handle_triple_fault,
	[EXIT_REASON_NMI_WINDOW]		= handle_nmi_window,
	[EXIT_REASON_IO_INSTRUCTION]		= handle_io,
	[EXIT_REASON_CR_ACCESS]			= handle_cr,
	[EXIT_REASON_DR_ACCESS]			= handle_dr,
	[EXIT_REASON_CPUID]			= handle_cpuid,
	[EXIT_REASON_MSR_READ]			= handle_rdmsr,
	[EXIT_REASON_MSR_WRITE]			= handle_wrmsr,
	[EXIT_REASON_PENDING_INTERRUPT]		= handle_interrupt_window,
	[EXIT_REASON_HLT]			= handle_halt,
	[EXIT_REASON_INVLPG]			= handle_invlpg,
	[EXIT_REASON_VMCALL]			= handle_vmcall,
	[EXIT_REASON_VMCLEAR]			= handle_vmx_insn,
	[EXIT_REASON_VMLAUNCH]			= handle_vmx_insn,
	[EXIT_REASON_VMPTRLD]			= handle_vmx_insn,
	[EXIT_REASON_VMPTRST]			= handle_vmx_insn,
	[EXIT_REASON_VMREAD]			= handle_vmx_insn,
	[EXIT_REASON_VMRESUME]			= handle_vmx_insn,
	[EXIT_REASON_VMWRITE]			= handle_vmx_insn,
	[EXIT_REASON_VMOFF]			= handle_vmx_insn,
	[EXIT_REASON_VMON]			= handle_vmx_insn,
	[EXIT_REASON_TPR_BELOW_THRESHOLD]	= handle_tpr_below_threshold,
	[EXIT_REASON_APIC_ACCESS]		= handle_apic_access,
	[EXIT_REASON_WBINVD]			= handle_wbinvd,
	[EXIT_REASON_TASK_SWITCH]		= handle_task_switch,
	[EXIT_REASON_MCE_DURING_VMENTRY]	= handle_machine_check,
	[EXIT_REASON_EPT_VIOLATION]		= handle_ept_violation,
	[EXIT_REASON_EPT_MISCONFIG]		= handle_ept_misconfig,
	[EXIT_REASON_PAUSE_INSTRUCTION]		= handle_pause,
	[EXIT_REASON_MWAIT_INSTRUCTION]		= handle_invalid_op,
	[EXIT_REASON_MONITOR_INSTRUCTION]	= handle_invalid_op,
};

static const int kvm_vmx_max_exit_handlers =
	ARRAY_SIZE(kvm_vmx_exit_handlers);

/*
 * The guest has exited.  See if we can fix it or if we need userspace
 * assistance.
 */
static int
vmx_handle_exit(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	uint32_t exit_reason = vmx->exit_reason;
	uint32_t vectoring_info = vmx->idt_vectoring_info;
	int rval;
	unsigned long rip;

	/* Always read the guest rip when exiting */
	rip = vmcs_readl(GUEST_RIP);
	KVM_TRACE2(vexit, unsigned long, rip, uint32_t, exit_reason);

	/* If guest state is invalid, start emulating */
	if (vmx->emulation_required && emulate_invalid_guest_state)
		return (handle_invalid_guest_state(vcpu));

	/*
	 * Access CR3 don't cause VMExit in paging mode, so we need
	 * to sync with guest real CR3.
	 */
	if (enable_ept && is_paging(vcpu))
		vcpu->arch.cr3 = vmcs_readl(GUEST_CR3);

	if (vmx->fail) {
		vcpu->run->exit_reason = KVM_EXIT_FAIL_ENTRY;
		vcpu->run->fail_entry.hardware_entry_failure_reason
			= vmcs_read32(VM_INSTRUCTION_ERROR);

		return (0);
	}

	if ((vectoring_info & VECTORING_INFO_VALID_MASK) &&
	    (exit_reason != EXIT_REASON_EXCEPTION_NMI &&
	    exit_reason != EXIT_REASON_EPT_VIOLATION &&
	    exit_reason != EXIT_REASON_TASK_SWITCH)) {
		cmn_err(CE_WARN, "%s: unexpected, valid vectoring info "
		    "(0x%x) and exit reason is 0x%x\n",
		    __func__, vectoring_info, exit_reason);
	}

	if (!cpu_has_virtual_nmis() && vmx->soft_vnmi_blocked) {
		if (vmx_interrupt_allowed(vcpu)) {
			vmx->soft_vnmi_blocked = 0;
		} else if (vmx->vnmi_blocked_time > 1000000000LL &&
		    vcpu->arch.nmi_pending) {
			/*
			 * This CPU don't support us in finding the end of an
			 * NMI-blocked window if the guest runs with IRQs
			 * disabled. So we pull the trigger after 1 s of
			 * futile waiting, but inform the user about this.
			 */
			cmn_err(CE_WARN, "%s: Breaking out of NMI-blocked "
			    "state on VCPU %d after 1 s timeout\n",
			    __func__, vcpu->vcpu_id);
			vmx->soft_vnmi_blocked = 0;
		}
	}

	if (exit_reason < kvm_vmx_max_exit_handlers &&
	    kvm_vmx_exit_handlers[exit_reason]) {
		rval = kvm_vmx_exit_handlers[exit_reason](vcpu);
		return (rval);
	} else {
		vcpu->run->exit_reason = KVM_EXIT_UNKNOWN;
		vcpu->run->hw.hardware_exit_reason = exit_reason;
	}

	return (0);
}

static void
vmx_update_cr8_intercept(struct kvm_vcpu *vcpu, int tpr, int irr)
{
	if (irr == -1 || tpr < irr) {
		vmcs_write32(TPR_THRESHOLD, 0);
		return;
	}

	vmcs_write32(TPR_THRESHOLD, irr);
}

static void
vmx_complete_interrupts(struct vcpu_vmx *vmx)
{
	uint32_t exit_intr_info;
	uint32_t idt_vectoring_info = vmx->idt_vectoring_info;
	int unblock_nmi;
	uint8_t vector;
	int type;
	int idtv_info_valid;

	exit_intr_info = vmcs_read32(VM_EXIT_INTR_INFO);

	vmx->exit_reason = vmcs_read32(VM_EXIT_REASON);

	/* Handle machine checks before interrupts are enabled */
	if ((vmx->exit_reason == EXIT_REASON_MCE_DURING_VMENTRY) ||
	    (vmx->exit_reason == EXIT_REASON_EXCEPTION_NMI &&
	    is_machine_check(exit_intr_info)))
		kvm_machine_check();

	/* We need to handle NMIs before interrupts are enabled */
	if ((exit_intr_info & INTR_INFO_INTR_TYPE_MASK) == INTR_TYPE_NMI_INTR &&
	    (exit_intr_info & INTR_INFO_VALID_MASK))
		__asm__("int $2");

	idtv_info_valid = idt_vectoring_info & VECTORING_INFO_VALID_MASK;

	if (cpu_has_virtual_nmis()) {
		unblock_nmi = (exit_intr_info & INTR_INFO_UNBLOCK_NMI) != 0;
		vector = exit_intr_info & INTR_INFO_VECTOR_MASK;
		/*
		 * SDM 3: 27.7.1.2 (September 2008)
		 * Re-set bit "block by NMI" before VM entry if vmexit caused by
		 * a guest IRET fault.
		 * SDM 3: 23.2.2 (September 2008)
		 * Bit 12 is undefined in any of the following cases:
		 *  If the VM exit sets the valid bit in the IDT-vectoring
		 *   information field.
		 *  If the VM exit is due to a double fault.
		 */
		if ((exit_intr_info & INTR_INFO_VALID_MASK) && unblock_nmi &&
		    vector != DF_VECTOR && !idtv_info_valid)
			vmcs_set_bits(GUEST_INTERRUPTIBILITY_INFO,
			    GUEST_INTR_STATE_NMI);
	} else if (vmx->soft_vnmi_blocked) {
#ifdef XXX
		vmx->vnmi_blocked_time +=
			ktime_to_ns(ktime_sub(ktime_get(), vmx->entry_time));
#else
		vmx->vnmi_blocked_time +=
			gethrtime() - vmx->entry_time;
		XXX_KVM_PROBE;
#endif
	}

	vmx->vcpu.arch.nmi_injected = 0;
	kvm_clear_exception_queue(&vmx->vcpu);
	kvm_clear_interrupt_queue(&vmx->vcpu);

	if (!idtv_info_valid)
		return;

	vector = idt_vectoring_info & VECTORING_INFO_VECTOR_MASK;
	type = idt_vectoring_info & VECTORING_INFO_TYPE_MASK;

	switch (type) {
	case INTR_TYPE_NMI_INTR:
		vmx->vcpu.arch.nmi_injected = 1;
		/*
		 * SDM 3: 27.7.1.2 (September 2008)
		 * Clear bit "block by NMI" before VM entry if a NMI
		 * delivery faulted.
		 */
		vmcs_clear_bits(GUEST_INTERRUPTIBILITY_INFO,
				GUEST_INTR_STATE_NMI);
		break;
	case INTR_TYPE_SOFT_EXCEPTION:
		vmx->vcpu.arch.event_exit_inst_len =
			vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
		/* fall through */
	case INTR_TYPE_HARD_EXCEPTION:
		if (idt_vectoring_info & VECTORING_INFO_DELIVER_CODE_MASK) {
			uint32_t err = vmcs_read32(IDT_VECTORING_ERROR_CODE);
			kvm_queue_exception_e(&vmx->vcpu, vector, err);
		} else
			kvm_queue_exception(&vmx->vcpu, vector);
		break;
	case INTR_TYPE_SOFT_INTR:
		vmx->vcpu.arch.event_exit_inst_len =
			vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
		/* fall through */
	case INTR_TYPE_EXT_INTR:
		kvm_queue_interrupt(&vmx->vcpu, vector,
			type == INTR_TYPE_SOFT_INTR);
		break;
	default:
		break;
	}
}

/*
 * Failure to inject an interrupt should give us the information
 * in IDT_VECTORING_INFO_FIELD.  However, if the failure occurs
 * when fetching the interrupt redirection bitmap in the real-mode
 * tss, this doesn't happen.  So we do it ourselves.
 */
static void
fixup_rmode_irq(struct vcpu_vmx *vmx)
{
	vmx->rmode.irq.pending = 0;
	if (kvm_rip_read(&vmx->vcpu) + 1 != vmx->rmode.irq.rip)
		return;

	kvm_rip_write(&vmx->vcpu, vmx->rmode.irq.rip);
	if (vmx->idt_vectoring_info & VECTORING_INFO_VALID_MASK) {
		vmx->idt_vectoring_info &= ~VECTORING_INFO_TYPE_MASK;
		vmx->idt_vectoring_info |= INTR_TYPE_EXT_INTR;
		return;
	}

	vmx->idt_vectoring_info = VECTORING_INFO_VALID_MASK |
	    INTR_TYPE_EXT_INTR | vmx->rmode.irq.vector;
}

static void
vmx_vcpu_run(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	/* Record the guest's net vcpu time for enforced NMI injections. */
	if (!cpu_has_virtual_nmis() && vmx->soft_vnmi_blocked)
		vmx->entry_time = gethrtime();

	/*
	 * Don't enter VMX if guest state is invalid, let the exit handler
	 * start emulation until we arrive back to a valid state
	 */
	if (vmx->emulation_required && emulate_invalid_guest_state)
		return;

	if (test_bit(VCPU_REGS_RSP, (unsigned long *)&vcpu->arch.regs_dirty))
		vmcs_writel(GUEST_RSP, vcpu->arch.regs[VCPU_REGS_RSP]);
	if (test_bit(VCPU_REGS_RIP, (unsigned long *)&vcpu->arch.regs_dirty))
		vmcs_writel(GUEST_RIP, vcpu->arch.regs[VCPU_REGS_RIP]);

	KVM_TRACE1(vrun, unsigned long, vcpu->arch.regs[VCPU_REGS_RIP]);

	/*
	 * When single-stepping over STI and MOV SS, we must clear the
	 * corresponding interruptibility bits in the guest state. Otherwise
	 * vmentry fails as it then expects bit 14 (BS) in pending debug
	 * exceptions being set, but that's not correct for the guest debugging
	 * case.
	 */
	if (vcpu->guest_debug & KVM_GUESTDBG_SINGLESTEP)
		vmx_set_interrupt_shadow(vcpu, 0);

	/*
	 * Loading guest fpu may have cleared host cr0.ts
	 */
	vmcs_writel(HOST_CR0, read_cr0());

	if (vmx->launched) {
		KVM_TRACE1(vmx__vmresume, struct vcpu_vmx *, vmx);
	} else {
		KVM_TRACE1(vmx__vmlaunch, struct vcpu_vmx *, vmx);
	}

	__asm__(
	    /* Store host registers */
	    "push %%rdx; push %%rbp;"
	    "push %%rcx \n\t"
	    "cmp %%rsp, %c[host_rsp](%0) \n\t"
	    "je 1f \n\t"
	    "mov %%rsp, %c[host_rsp](%0) \n\t"
	    __ex(ASM_VMX_VMWRITE_RSP_RDX) "\n\t"
	    "1: \n\t"
	    /* Reload cr2 if changed */
	    "mov %c[cr2](%0), %%rax \n\t"
	    "mov %%cr2, %%rdx \n\t"
	    "cmp %%rax, %%rdx \n\t"
	    "je 2f \n\t"
	    "mov %%rax, %%cr2 \n\t"
	    "2: \n\t"
	    /* Check if vmlaunch of vmresume is needed */
	    "cmpl $0, %c[launched](%0) \n\t"
	    /* Load guest registers.  Don't clobber flags. */
	    "mov %c[rax](%0), %%rax \n\t"
	    "mov %c[rbx](%0), %%rbx \n\t"
	    "mov %c[rdx](%0), %%rdx \n\t"
	    "mov %c[rsi](%0), %%rsi \n\t"
	    "mov %c[rdi](%0), %%rdi \n\t"
	    "mov %c[rbp](%0), %%rbp \n\t"
	    "mov %c[r8](%0),  %%r8  \n\t"
	    "mov %c[r9](%0),  %%r9  \n\t"
	    "mov %c[r10](%0), %%r10 \n\t"
	    "mov %c[r11](%0), %%r11 \n\t"
	    "mov %c[r12](%0), %%r12 \n\t"
	    "mov %c[r13](%0), %%r13 \n\t"
	    "mov %c[r14](%0), %%r14 \n\t"
	    "mov %c[r15](%0), %%r15 \n\t"
	    "mov %c[rcx](%0), %%rcx \n\t" /* kills %0 (ecx) */

	    /* Enter guest mode */
	    "jne .Llaunched \n\t"
	    __ex(ASM_VMX_VMLAUNCH) "\n\t"
	    "jmp .Lkvm_vmx_return \n\t"
	    ".Llaunched: " __ex(ASM_VMX_VMRESUME) "\n\t"
	    ".Lkvm_vmx_return: "
	    /* Save guest registers, load host registers, keep flags */
	    "xchg %0,     (%%rsp) \n\t"
	    "mov %%rax, %c[rax](%0) \n\t"
	    "mov %%rbx, %c[rbx](%0) \n\t"
	    "pushq (%%rsp); popq %c[rcx](%0) \n\t"
	    "mov %%rdx, %c[rdx](%0) \n\t"
	    "mov %%rsi, %c[rsi](%0) \n\t"
	    "mov %%rdi, %c[rdi](%0) \n\t"
	    "mov %%rbp, %c[rbp](%0) \n\t"
	    "mov %%r8,  %c[r8](%0) \n\t"
	    "mov %%r9,  %c[r9](%0) \n\t"
	    "mov %%r10, %c[r10](%0) \n\t"
	    "mov %%r11, %c[r11](%0) \n\t"
	    "mov %%r12, %c[r12](%0) \n\t"
	    "mov %%r13, %c[r13](%0) \n\t"
	    "mov %%r14, %c[r14](%0) \n\t"
	    "mov %%r15, %c[r15](%0) \n\t"
	    "mov %%cr2, %%rax   \n\t"
	    "mov %%rax, %c[cr2](%0) \n\t"

	    "pop  %%rbp; pop  %%rbp; pop  %%rdx \n\t"
	    "setbe %c[fail](%0) \n\t"
	    : : "c"(vmx), "d"((unsigned long)HOST_RSP),
	    [launched]"i"(offsetof(struct vcpu_vmx, launched)),
	    [fail]"i"(offsetof(struct vcpu_vmx, fail)),
	    [host_rsp]"i"(offsetof(struct vcpu_vmx, host_rsp)),
	    [rax]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RAX])),
	    [rbx]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RBX])),
	    [rcx]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RCX])),
	    [rdx]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RDX])),
	    [rsi]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RSI])),
	    [rdi]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RDI])),
	    [rbp]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RBP])),
	    [r8]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R8])),
	    [r9]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R9])),
	    [r10]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R10])),
	    [r11]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R11])),
	    [r12]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R12])),
	    [r13]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R13])),
	    [r14]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R14])),
	    [r15]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R15])),
	    [cr2]"i"(offsetof(struct vcpu_vmx, vcpu.arch.cr2))
	    : "cc", "memory"
	    /*CSTYLED*/
	    , "rbx", "rdi", "rsi"
	    /*CSTYLED*/
	    , "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
	/*CSTYLED*/
	);

	vcpu->arch.regs_avail = ~((1 << VCPU_REGS_RIP) |
	    (1 << VCPU_REGS_RSP) | (1 << VCPU_EXREG_PDPTR));
	vcpu->arch.regs_dirty = 0;

	vmx->idt_vectoring_info = vmcs_read32(IDT_VECTORING_INFO_FIELD);

	if (vmx->rmode.irq.pending)
		fixup_rmode_irq(vmx);

#ifdef XXX
	__asm__("mov %0, %%ds; mov %0, %%es" :
	    : "r"SEL_GDT(GDT_UDATA, SEL_UPL));
#else
	XXX_KVM_PROBE;
	__asm__("mov %0, %%ds; mov %0, %%es" : : "r"KDS_SEL);
#endif
	vmx->launched = 1;

	vmx_complete_interrupts(vmx);
}

static void
vmx_destroy_vcpu(struct kvm_vcpu *vcpu)
{
	vcpu_vmx_t *vmx = to_vmx(vcpu);

	if (vmx->vmcs != NULL) {
		kmem_free(vmx->vmcs, PAGESIZE);
		vmx->vmcs = NULL;
	}
	if (vmx->guest_msrs != NULL)
		kmem_free(vmx->guest_msrs, PAGESIZE);
	kvm_vcpu_uninit(vcpu);
	if (vmx->vpid != 0) {
		hma_vmx_vpid_free(vmx->vpid);
	}
	kmem_cache_free(kvm_vcpu_cache, vmx);
}

struct kvm_vcpu *
vmx_create_vcpu(struct kvm *kvm, unsigned int id)
{
	struct vcpu_vmx *vmx = kmem_cache_alloc(kvm_vcpu_cache, KM_SLEEP);
	int err;

	if (!vmx)
		return (NULL);

	bzero(vmx, sizeof (struct vcpu_vmx));
	vmx->cpu_lastrun = -1;

	allocate_vpid(vmx);
	err = kvm_vcpu_init(&vmx->vcpu, kvm, id);
	if (err) {
		kmem_cache_free(kvm_vcpu_cache, vmx);
		return (NULL);
	}

	vmx->guest_msrs = kmem_zalloc(PAGESIZE, KM_SLEEP);
	vmx->vmcs = kmem_zalloc(PAGESIZE, KM_SLEEP);

	vmx->vmcs_pa = kvm_va2pa((caddr_t)vmx->vmcs);
	vmx->vmcs->revision_id = vmcs_config.revision_id;
	cmn_err(CE_CONT, "!vmcs revision_id = %x\n", vmcs_config.revision_id);

	/*
	 * Without the protection of save/restore ctxops, kpreempt_disable is
	 * only effective if none of the code in the critical section
	 * voluntarily goes off-cpu (such as blocking for a lock).
	 */
	kpreempt_disable();
	vmx_vcpu_load(&vmx->vcpu, CPU->cpu_seqid);
	vmx_vcpu_setup(vmx);
	vmx_vcpu_put(&vmx->vcpu);
	kpreempt_enable();

	if (vm_need_virtualize_apic_accesses(kvm)) {
		if (alloc_apic_access_page(kvm) != 0)
			goto free_vmcs;
	}

	if (enable_ept) {
		if (!kvm->arch.ept_identity_map_addr)
			kvm->arch.ept_identity_map_addr =
				VMX_EPT_IDENTITY_PAGETABLE_ADDR;
		if (alloc_identity_pagetable(kvm) != 0)
			goto free_vmcs;
	}

	return (&vmx->vcpu);

free_vmcs:
	kmem_free(vmx->vmcs, PAGESIZE);
	vmx->vmcs = 0;
	kmem_free(vmx->guest_msrs, PAGESIZE);
	kvm_vcpu_uninit(&vmx->vcpu);
	kmem_cache_free(kvm_vcpu_cache, vmx);
	return (NULL);
}

static void
vmx_check_processor_compat(void *rtn)
{
	struct vmcs_config vmcs_conf;

	if (setup_vmcs_config(&vmcs_conf) < 0)
		*(int *)rtn |= EIO;
	if (memcmp(&vmcs_config, &vmcs_conf, sizeof (struct vmcs_config))
	    != 0) {
		cmn_err(CE_WARN, "kvm: CPU %d feature inconsistency!\n",
			curthread->t_cpu->cpu_id);
		*(int *)rtn |= EIO;
	}
}

static int
get_ept_level(void)
{
	return (VMX_EPT_DEFAULT_GAW + 1);
}

static uint64_t
vmx_get_mt_mask(struct kvm_vcpu *vcpu, gfn_t gfn, int is_mmio)
{
	/*
	 * For VT-d and EPT combination
	 * 1. MMIO: always map as UC
	 * 2. EPT with VT-d:
	 *   a. VT-d without snooping control feature: can't guarantee the
	 *	result, try to trust guest.
	 *   b. VT-d with snooping control feature: snooping control feature of
	 *	VT-d engine can guarantee the cache correctness. Just set it
	 *	to WB to keep consistent with host. So the same as item 3.
	 * 3. EPT without VT-d: always map as WB and set IPAT=1 to keep
	 *    consistent with host MTRR
	 */
	if (is_mmio)
		return (MTRR_TYPE_UNCACHABLE << VMX_EPT_MT_EPTE_SHIFT);

	if (vcpu->kvm->arch.iommu_domain &&
	    !(vcpu->kvm->arch.iommu_flags & KVM_IOMMU_CACHE_COHERENCY)) {
		return (kvm_get_guest_memory_type(vcpu, gfn) <<
		    VMX_EPT_MT_EPTE_SHIFT);
	}

	return ((MTRR_TYPE_WRBACK << VMX_EPT_MT_EPTE_SHIFT) | VMX_EPT_IPAT_BIT);
}

#define	_ER(x) { EXIT_REASON_##x, #x }

struct trace_print_flags {
	unsigned long		mask;
	const char		*name;
};

static const struct trace_print_flags vmx_exit_reasons_str[] = {
	_ER(EXCEPTION_NMI),
	_ER(EXTERNAL_INTERRUPT),
	_ER(TRIPLE_FAULT),
	_ER(PENDING_INTERRUPT),
	_ER(NMI_WINDOW),
	_ER(TASK_SWITCH),
	_ER(CPUID),
	_ER(HLT),
	_ER(INVLPG),
	_ER(RDPMC),
	_ER(RDTSC),
	_ER(VMCALL),
	_ER(VMCLEAR),
	_ER(VMLAUNCH),
	_ER(VMPTRLD),
	_ER(VMPTRST),
	_ER(VMREAD),
	_ER(VMRESUME),
	_ER(VMWRITE),
	_ER(VMOFF),
	_ER(VMON),
	_ER(CR_ACCESS),
	_ER(DR_ACCESS),
	_ER(IO_INSTRUCTION),
	_ER(MSR_READ),
	_ER(MSR_WRITE),
	_ER(MWAIT_INSTRUCTION),
	_ER(MONITOR_INSTRUCTION),
	_ER(PAUSE_INSTRUCTION),
	_ER(MCE_DURING_VMENTRY),
	_ER(TPR_BELOW_THRESHOLD),
	_ER(APIC_ACCESS),
	_ER(EPT_VIOLATION),
	_ER(EPT_MISCONFIG),
	_ER(WBINVD),
	{ -1, NULL }
};

#undef _ER

static int
vmx_get_lpage_level(void)
{
	if (enable_ept && !cpu_has_vmx_ept_1g_page())
		return (PT_DIRECTORY_LEVEL);
	else
		/* For shadow and EPT supported 1GB page */
		return (PT_PDPE_LEVEL);
}

static void
vmx_cpuid_update(struct kvm_vcpu *vcpu)
{
	struct kvm_cpuid_entry2 *best;
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	uint32_t exec_control;

	vmx->rdtscp_enabled = 0;

	if (vmx_rdtscp_supported()) {
		exec_control = vmcs_read32(SECONDARY_VM_EXEC_CONTROL);
		if (exec_control & SECONDARY_EXEC_RDTSCP) {
			best = kvm_find_cpuid_entry(vcpu, 0x80000001, 0);
			if (best && (best->edx & bit(X86_FEATURE_RDTSCP)))
				vmx->rdtscp_enabled = 1;
			else {
				exec_control &= ~SECONDARY_EXEC_RDTSCP;
				vmcs_write32(SECONDARY_VM_EXEC_CONTROL,
						exec_control);
			}
		}
	}
}

struct kvm_x86_ops vmx_x86_ops = {
	.cpu_has_kvm_support = vmx_has_kvm_support,
	.disabled_by_bios = vmx_disabled_by_bios,

	.check_processor_compatibility = vmx_check_processor_compat,

	.hardware_setup = vmx_hardware_setup,

	.cpu_has_accelerated_tpr = report_flexpriority,
	.vcpu_create = vmx_create_vcpu,
	.vcpu_free = vmx_destroy_vcpu, /* XXX */
	.vcpu_reset = vmx_vcpu_reset,

	.prepare_guest_switch = vmx_save_host_state,
	.vcpu_load = vmx_vcpu_load,
	.vcpu_put = vmx_vcpu_put,

	.set_guest_debug = set_guest_debug,
	.get_msr = vmx_get_msr,
	.set_msr = vmx_set_msr,
	.get_segment_base = vmx_get_segment_base,
	.get_segment = vmx_get_segment,
	.set_segment = vmx_set_segment,
	.get_cpl = vmx_get_cpl,
	.get_cs_db_l_bits = vmx_get_cs_db_l_bits,
	.decache_cr0_guest_bits = vmx_decache_cr0_guest_bits,
	.decache_cr4_guest_bits = vmx_decache_cr4_guest_bits,
	.set_cr0 = vmx_set_cr0,
	.set_cr3 = vmx_set_cr3,
	.set_cr4 = vmx_set_cr4,
	.set_efer = vmx_set_efer,
	.get_idt = vmx_get_idt,
	.set_idt = vmx_set_idt,
	.get_gdt = vmx_get_gdt,
	.set_gdt = vmx_set_gdt,
	.cache_reg = vmx_cache_reg,
	.get_rflags = vmx_get_rflags,
	.set_rflags = vmx_set_rflags,
	.fpu_activate = vmx_fpu_activate,
	.fpu_deactivate = vmx_fpu_deactivate,

	.tlb_flush = vmx_flush_tlb,

	.run = vmx_vcpu_run,
	.handle_exit = vmx_handle_exit,
	.skip_emulated_instruction = skip_emulated_instruction,
	.set_interrupt_shadow = vmx_set_interrupt_shadow,
	.get_interrupt_shadow = vmx_get_interrupt_shadow,
	.patch_hypercall = vmx_patch_hypercall,
	.set_irq = vmx_inject_irq,
	.set_nmi = vmx_inject_nmi,
	.queue_exception = vmx_queue_exception,
	.interrupt_allowed = vmx_interrupt_allowed,
	.nmi_allowed = vmx_nmi_allowed,
	.get_nmi_mask = vmx_get_nmi_mask,
	.set_nmi_mask = vmx_set_nmi_mask,
	.enable_nmi_window = enable_nmi_window,
	.enable_irq_window = enable_irq_window,
	.update_cr8_intercept = vmx_update_cr8_intercept,

	.set_tss_addr = vmx_set_tss_addr,
	.get_tdp_level = get_ept_level,
	.get_mt_mask = vmx_get_mt_mask,

	.exit_reasons_str = vmx_exit_reasons_str,

	.get_lpage_level = vmx_get_lpage_level,

	.cpuid_update = vmx_cpuid_update,

	.rdtscp_supported = vmx_rdtscp_supported
};

int
vmx_init(void)
{
	int r, i;

	rdmsrl_safe(MSR_EFER, (unsigned long long *)&host_efer);

	for (i = 0; i < NR_VMX_MSR; ++i)
		kvm_define_shared_msr(i, vmx_msr_index[i]);

	/* A kmem cache lets us meet the alignment requirements of fx_save. */
	kvm_vcpu_cache = kmem_cache_create("kvm_vcpu", sizeof (struct vcpu_vmx),
	    (size_t)PAGESIZE,
	    zero_constructor, NULL, NULL, (void *)(sizeof (struct vcpu_vmx)),
	    NULL, 0);

	if (kvm_vcpu_cache == NULL) {
		r = ENOMEM;
		goto out;
	}

	/*
	 * Allow direct access to the PC debug port (it is often used for I/O
	 * delays, but the vmexits simply slow things down).
	 */
	memset(vmx_io_bitmap_a, 0xff, PAGESIZE);
	clear_bit(0x80, vmx_io_bitmap_a);

	memset(vmx_io_bitmap_b, 0xff, PAGESIZE);

	memset(vmx_msr_bitmap_legacy, 0xff, PAGESIZE);
	memset(vmx_msr_bitmap_longmode, 0xff, PAGESIZE);

	/*
	 * Cache PAs of these elements so they need not be looked up when in
	 * the sensitive context preceding a VMCS write.
	 */
	vmx_io_bitmap_a_pa = kvm_va2pa((caddr_t)vmx_io_bitmap_a);
	vmx_io_bitmap_b_pa = kvm_va2pa((caddr_t)vmx_io_bitmap_b);
	vmx_msr_bitmap_legacy_pa = kvm_va2pa((caddr_t)vmx_msr_bitmap_legacy);
	vmx_msr_bitmap_longmode_pa =
	    kvm_va2pa((caddr_t)vmx_msr_bitmap_longmode);

	r = kvm_init(&vmx_x86_ops);

	if (r)
		goto out;

	vmx_disable_intercept_for_msr(MSR_FS_BASE, 0);
	vmx_disable_intercept_for_msr(MSR_GS_BASE, 0);
	vmx_disable_intercept_for_msr(MSR_KERNEL_GS_BASE, 1);
	vmx_disable_intercept_for_msr(MSR_IA32_SYSENTER_CS, 0);
	vmx_disable_intercept_for_msr(MSR_IA32_SYSENTER_ESP, 0);
	vmx_disable_intercept_for_msr(MSR_IA32_SYSENTER_EIP, 0);

	if (enable_ept) {
		bypass_guest_pf = 0;
		kvm_mmu_set_base_ptes(VMX_EPT_READABLE_MASK |
			VMX_EPT_WRITABLE_MASK);
		kvm_mmu_set_mask_ptes(0ull, 0ull, 0ull, 0ull,
				VMX_EPT_EXECUTABLE_MASK);
		kvm_enable_tdp();
	} else
		kvm_disable_tdp();

	if (bypass_guest_pf)
		kvm_mmu_set_nonpresent_ptes(~0xffeull, 0ull);

	return (0);


out:
	kmem_cache_destroy(kvm_vcpu_cache);

	return (r);
}

void
vmx_fini(void)
{
	kmem_cache_destroy(kvm_vcpu_cache);
}
