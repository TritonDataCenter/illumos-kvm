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
 * Copyright 2019 Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/mutex.h>
#include <sys/ksynch.h>
#include <sys/condvar_impl.h>
#include <sys/ddi.h>
#include <sys/regset.h>
#include <sys/fp.h>
#include <sys/tss.h>
#include <sys/x86_archext.h>
#include <sys/controlregs.h>
#include <sys/smt.h>
#include <sys/machsystm.h>

#include <vm/page.h>
#include <vm/hat.h>

#include <asm/cpu.h>

#include "kvm_bitops.h"
#include "kvm_vmx.h"
#include "msr-index.h"
#include "kvm_msr.h"
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
#include "kvm_ioapic.h"
#include "kvm_coalesced_mmio.h"
#include "kvm_i8254.h"
#include "kvm_mmu.h"
#include "kvm_cache_regs.h"
#include "kvm_para.h"

extern caddr_t smmap64(caddr_t addr, size_t len, int prot, int flags,
    int fd, off_t pos);
extern int memcntl(caddr_t, size_t, int, caddr_t, int, int);
extern int lwp_sigmask(int, uint_t, uint_t, uint_t, uint_t);
extern uint64_t cpu_freq_hz;

static unsigned long empty_zero_page[PAGESIZE / sizeof (unsigned long)];
static uint64_t cpu_tsc_khz;

/*
 * Globals
 */
struct kvm_x86_ops *kvm_x86_ops;
int ignore_msrs = 0;

#define	MAX_IO_MSRS 256
#define	CR0_RESERVED_BITS						\
	(~(unsigned long)(X86_CR0_PE | X86_CR0_MP | X86_CR0_EM | X86_CR0_TS \
	    | X86_CR0_ET | X86_CR0_NE | X86_CR0_WP | X86_CR0_AM \
	    | X86_CR0_NW | X86_CR0_CD | X86_CR0_PG))
#define	CR4_RESERVED_BITS						\
	(~(unsigned long)(X86_CR4_VME | X86_CR4_PVI | X86_CR4_TSD | X86_CR4_DE\
	    | X86_CR4_PSE | X86_CR4_PAE | X86_CR4_MCE	\
	    | X86_CR4_PGE | X86_CR4_PCE | X86_CR4_OSFXSR	\
	    | X86_CR4_OSXMMEXCPT | X86_CR4_VMXE))

#define	CR8_RESERVED_BITS (~(unsigned long)X86_CR8_TPR)

/*
 * EFER defaults:
 * - enable syscall per default because its emulated by KVM
 * - enable LME and LMA per default on 64 bit KVM
 */
static uint64_t efer_reserved_bits = 0xfffffffffffffafeULL;

static void update_cr8_intercept(struct kvm_vcpu *);
static struct kvm_shared_msrs_global shared_msrs_global;
static struct kvm_shared_msrs *shared_msrs;

void
kvm_sigprocmask(int how, sigset_t *setp, sigset_t *osetp)
{
	k_sigset_t kset;

	ASSERT(how == SIG_SETMASK);
	ASSERT(setp != NULL);

	sigutok(setp, &kset);

	if (osetp != NULL)
		sigktou(&curthread->t_hold, osetp);

	(void) lwp_sigmask(SIG_SETMASK,
	    kset.__sigbits[0], kset.__sigbits[1], kset.__sigbits[2], 0);
}

static void
kvm_on_user_return(struct kvm_vcpu *vcpu, struct kvm_user_return_notifier *urn)
{
	unsigned slot;
	struct kvm_shared_msrs *locals =
	    (struct kvm_shared_msrs *)(((caddr_t)urn) -
		offsetof(struct kvm_shared_msrs, urn));
	struct kvm_shared_msr_values *values;

	for (slot = 0; slot < shared_msrs_global.nr; ++slot) {
		values = &locals->values[slot];
		if (values->host != values->curr) {
			wrmsrl(shared_msrs_global.msrs[slot], values->host);
			values->curr = values->host;
		}
	}
	locals->registered = 0;
	/*
	 * As the on-user-return handler indicates that this thread is either
	 * returning to userspace or going off-cpu, the host MSR values should
	 * be queried again prior to the next VM entry.
	 */
	locals->host_saved = 0;
	kvm_user_return_notifier_unregister(vcpu, urn);
}

void
kvm_define_shared_msr(unsigned slot, uint32_t msr)
{
	if (slot >= shared_msrs_global.nr)
		shared_msrs_global.nr = slot + 1;
	shared_msrs_global.msrs[slot] = msr;

	/* we need ensured the shared_msr_global have been updated */
	smp_wmb();
}

void
kvm_set_shared_msr(struct kvm_vcpu *vcpu, unsigned slot, uint64_t value,
    uint64_t mask)
{
	struct kvm_shared_msrs *smsr = &shared_msrs[CPU->cpu_id];
	const uint32_t msr = shared_msrs_global.msrs[slot];
	const uint_t slot_bit = 1 << slot;

	ASSERT(slot < KVM_NR_SHARED_MSRS);

	/* Preserve host MSR values prior to loading the guest data. */
	if ((smsr->host_saved & slot_bit) == 0) {
		uint64_t temp;

		rdmsrl_safe(msr, (unsigned long long *)&temp);
		smsr->values[slot].host = temp;
		smsr->values[slot].curr = temp;
		smsr->host_saved |= slot_bit;
	}

	if (((value ^ smsr->values[slot].curr) & mask) == 0)
		return;

	smsr->values[slot].curr = value;
	wrmsrl(msr, value);

	if (!smsr->registered) {
		smsr->urn.on_user_return = kvm_on_user_return;
		kvm_user_return_notifier_register(vcpu, &smsr->urn);
		smsr->registered = 1;
	}
}

unsigned long
segment_base(uint16_t selector)
{
	struct descriptor_table gdt;
	struct desc_struct *d;
	unsigned long table_base;
	unsigned long v;

	if (selector == 0)
		return (0);

	kvm_get_gdt(&gdt);
	table_base = gdt.base;

	if (selector & 4) {		/* from ldt */
		uint16_t ldt_selector = kvm_read_ldt();

		table_base = segment_base(ldt_selector);
	}
	d = (struct desc_struct *)(table_base + (selector & ~7));
	v = get_desc_base(d);

	if (d->c.b.s == 0 &&
	    (d->c.b.type == 2 || d->c.b.type == 9 || d->c.b.type == 11))
		v |= ((unsigned long)((struct ldttss_desc64 *)d)->base3) << 32;

	return (v);
}

uint64_t
kvm_get_apic_base(struct kvm_vcpu *vcpu)
{
	if (irqchip_in_kernel(vcpu->kvm))
		return (vcpu->arch.apic_base);
	else
		return (vcpu->arch.apic_base);
}

void
kvm_set_apic_base(struct kvm_vcpu *vcpu, uint64_t data)
{
	/* TODO: reserve bits check */
	if (irqchip_in_kernel(vcpu->kvm))
		kvm_lapic_set_base(vcpu, data);
	else
		vcpu->arch.apic_base = data;
}

#define	EXCPT_BENIGN		0
#define	EXCPT_CONTRIBUTORY	1
#define	EXCPT_PF		2

static int
exception_class(int vector)
{
	switch (vector) {
	case PF_VECTOR:
		return (EXCPT_PF);
	case DE_VECTOR:
	case TS_VECTOR:
	case NP_VECTOR:
	case SS_VECTOR:
	case GP_VECTOR:
		return (EXCPT_CONTRIBUTORY);
	default:
		break;
	}

	return (EXCPT_BENIGN);
}

static void
kvm_multiple_exception(struct kvm_vcpu *vcpu,
    unsigned nr, int has_error, uint32_t error_code)
{
	uint32_t prev_nr;
	int class1, class2;

	if (!vcpu->arch.exception.pending) {
queue:
		vcpu->arch.exception.pending = 1;
		vcpu->arch.exception.has_error_code = has_error;
		vcpu->arch.exception.nr = nr;
		vcpu->arch.exception.error_code = error_code;
		return;
	}

	/* to check exception */
	prev_nr = vcpu->arch.exception.nr;
	if (prev_nr == DF_VECTOR) {
		/* triple fault -> shutdown */
		set_bit(KVM_REQ_TRIPLE_FAULT, &vcpu->requests);
		return;
	}
	class1 = exception_class(prev_nr);
	class2 = exception_class(nr);
	if ((class1 == EXCPT_CONTRIBUTORY && class2 == EXCPT_CONTRIBUTORY) ||
	    (class1 == EXCPT_PF && class2 != EXCPT_BENIGN)) {
		/* generate double fault per SDM Table 5-5 */
		vcpu->arch.exception.pending = 1;
		vcpu->arch.exception.has_error_code = 1;
		vcpu->arch.exception.nr = DF_VECTOR;
		vcpu->arch.exception.error_code = 0;
	} else {
		/*
		 * replace previous exception with a new one in a hope
		 * that instruction re-execution will regenerate lost
		 * exception
		 */
		goto queue;
	}
}

void
kvm_queue_exception(struct kvm_vcpu *vcpu, unsigned nr)
{
	kvm_multiple_exception(vcpu, nr, 0, 0);
}

void
kvm_inject_page_fault(struct kvm_vcpu *vcpu, unsigned long addr,
    uint32_t error_code)
{
	KVM_VCPU_KSTAT_INC(vcpu, kvmvs_pf_guest);
	vcpu->arch.cr2 = addr;
	kvm_queue_exception_e(vcpu, PF_VECTOR, error_code);
}

void
kvm_inject_nmi(struct kvm_vcpu *vcpu)
{
	vcpu->arch.nmi_pending = 1;
}

void
kvm_inject_gp(struct kvm_vcpu *vcpu, uint32_t error_code)
{
	kvm_queue_exception_e(vcpu, GP_VECTOR, error_code);
}

void
kvm_queue_exception_e(struct kvm_vcpu *vcpu, unsigned nr, uint32_t error_code)
{
	kvm_multiple_exception(vcpu, nr, 1, error_code);
}

/*
 * Checks if cpl <= required_cpl; if true, return true.  Otherwise queue
 * a #GP and return false.
 */
int
kvm_require_cpl(struct kvm_vcpu *vcpu, int required_cpl)
{
	if (kvm_x86_ops->get_cpl(vcpu) <= required_cpl)
		return (1);
	kvm_queue_exception_e(vcpu, GP_VECTOR, 0);
	return (0);
}

/*
 * Load the pae pdptrs.  Return true is they are all valid.
 */
int
load_pdptrs(struct kvm_vcpu *vcpu, unsigned long cr3)
{
	gfn_t pdpt_gfn = cr3 >> PAGESHIFT;
	unsigned offset = ((cr3 & (PAGESIZE-1)) >> 5) << 2;
	int i;
	int ret;
	uint64_t pdpte[ARRAY_SIZE(vcpu->arch.pdptrs)];

	ret = kvm_read_guest_page(vcpu->kvm, pdpt_gfn,
	    pdpte, offset * sizeof (uint64_t), sizeof (pdpte));

	if (ret < 0) {
		ret = 0;
		goto out;
	}

	for (i = 0; i < ARRAY_SIZE(pdpte); i++) {
		if (is_present_gpte(pdpte[i]) &&
		    (pdpte[i] & vcpu->arch.mmu.rsvd_bits_mask[0][2])) {
			ret = 0;
			goto out;
		}
	}
	ret = 1;

	memcpy(vcpu->arch.pdptrs, pdpte, sizeof (vcpu->arch.pdptrs));
	__set_bit(VCPU_EXREG_PDPTR, (unsigned long *)&vcpu->arch.regs_avail);
	__set_bit(VCPU_EXREG_PDPTR, (unsigned long *)&vcpu->arch.regs_dirty);
out:
	return (ret);
}

static int
pdptrs_changed(struct kvm_vcpu *vcpu)
{
	uint64_t pdpte[ARRAY_SIZE(vcpu->arch.pdptrs)];

	if (is_long_mode(vcpu) || !is_pae(vcpu))
		return (0);

	if (!test_bit(VCPU_EXREG_PDPTR,
	    (unsigned long *)&vcpu->arch.regs_avail)) {
		return (1);
	}

	if (kvm_read_guest(vcpu->kvm, vcpu->arch.cr3 & ~31u,
	    pdpte, sizeof (pdpte)) < 0)
		return (1);

	return (memcmp(pdpte, vcpu->arch.pdptrs, sizeof (pdpte)) != 0);
}

void
kvm_set_cr0(struct kvm_vcpu *vcpu, unsigned long cr0)
{
	cr0 |= X86_CR0_ET;

	if (cr0 & 0xffffffff00000000UL) {
		kvm_inject_gp(vcpu, 0);
		return;
	}

	cr0 &= ~CR0_RESERVED_BITS;

	if ((cr0 & X86_CR0_NW) && !(cr0 & X86_CR0_CD)) {
		kvm_inject_gp(vcpu, 0);
		return;
	}

	if ((cr0 & X86_CR0_PG) && !(cr0 & X86_CR0_PE)) {
		kvm_inject_gp(vcpu, 0);
		return;
	}

	if (!is_paging(vcpu) && (cr0 & X86_CR0_PG)) {

		if ((vcpu->arch.efer & EFER_LME)) {
			int cs_db, cs_l;

			if (!is_pae(vcpu)) {
				kvm_inject_gp(vcpu, 0);
				return;
			}

			kvm_x86_ops->get_cs_db_l_bits(vcpu, &cs_db, &cs_l);
			if (cs_l) {
				kvm_inject_gp(vcpu, 0);
				return;

			}
		} else

		if (is_pae(vcpu) && !load_pdptrs(vcpu, vcpu->arch.cr3)) {
			kvm_inject_gp(vcpu, 0);
			return;
		}

	}

	kvm_x86_ops->set_cr0(vcpu, cr0);
	vcpu->arch.cr0 = cr0;
	kvm_mmu_reset_context(vcpu);
}

void
kvm_lmsw(struct kvm_vcpu *vcpu, unsigned long msw)
{
	kvm_set_cr0(vcpu, kvm_read_cr0_bits(vcpu, ~0x0eul) | (msw & 0x0f));
}

void
kvm_set_cr4(struct kvm_vcpu *vcpu, unsigned long cr4)
{
	unsigned long old_cr4 = kvm_read_cr4(vcpu);
	unsigned long pdptr_bits = X86_CR4_PGE | X86_CR4_PSE | X86_CR4_PAE;

	if (cr4 & CR4_RESERVED_BITS) {
		kvm_inject_gp(vcpu, 0);
		return;
	}

	if (is_long_mode(vcpu)) {
		if (!(cr4 & X86_CR4_PAE)) {
			kvm_inject_gp(vcpu, 0);
			return;
		}
	} else if (is_paging(vcpu) && (cr4 & X86_CR4_PAE) &&
	    ((cr4 ^ old_cr4) & pdptr_bits) &&
	    !load_pdptrs(vcpu, vcpu->arch.cr3)) {
		kvm_inject_gp(vcpu, 0);
		return;
	}

	if (cr4 & X86_CR4_VMXE) {
		kvm_inject_gp(vcpu, 0);
		return;
	}

	kvm_x86_ops->set_cr4(vcpu, cr4);
	vcpu->arch.cr4 = cr4;
	vcpu->arch.mmu.base_role.cr4_pge = (cr4 & X86_CR4_PGE) && !tdp_enabled;
	kvm_mmu_reset_context(vcpu);
}

void
kvm_set_cr3(struct kvm_vcpu *vcpu, unsigned long cr3)
{
	if (cr3 == vcpu->arch.cr3 && !pdptrs_changed(vcpu)) {
		kvm_mmu_sync_roots(vcpu);
		kvm_mmu_flush_tlb(vcpu);
		return;
	}

	if (is_long_mode(vcpu)) {
		if (cr3 & CR3_L_MODE_RESERVED_BITS) {
			kvm_inject_gp(vcpu, 0);
			return;
		}
	} else {
		if (is_pae(vcpu)) {
			if (cr3 & CR3_PAE_RESERVED_BITS) {
				kvm_inject_gp(vcpu, 0);
				return;
			}
			if (is_paging(vcpu) && !load_pdptrs(vcpu, cr3)) {
				kvm_inject_gp(vcpu, 0);
				return;
			}
		}
		/*
		 * We don't check reserved bits in nonpae mode, because
		 * this isn't enforced, and VMware depends on this.
		 */
	}

	/*
	 * Does the new cr3 value map to physical memory? (Note, we
	 * catch an invalid cr3 even in real-mode, because it would
	 * cause trouble later on when we turn on paging anyway.)
	 *
	 * A real CPU would silently accept an invalid cr3 and would
	 * attempt to use it - with largely undefined (and often hard
	 * to debug) behavior on the guest side.
	 */
	if ((!gfn_to_memslot(vcpu->kvm, cr3 >> PAGESHIFT)))
		kvm_inject_gp(vcpu, 0);
	else {
		vcpu->arch.cr3 = cr3;
		vcpu->arch.mmu.new_cr3(vcpu);
	}
}

void
kvm_set_cr8(struct kvm_vcpu *vcpu, unsigned long cr8)
{
	if (cr8 & CR8_RESERVED_BITS) {
		kvm_inject_gp(vcpu, 0);
		return;
	}

	if (irqchip_in_kernel(vcpu->kvm))
		kvm_lapic_set_tpr(vcpu, cr8);
	else
		vcpu->arch.cr8 = cr8;
}

unsigned long
kvm_get_cr8(struct kvm_vcpu *vcpu)
{
	if (irqchip_in_kernel(vcpu->kvm)) {
		return (kvm_lapic_get_cr8(vcpu));
	} else {
		return (vcpu->arch.cr8);
	}
}

/*
 * List of msr numbers which we expose to userspace through KVM_GET_MSRS
 * and KVM_SET_MSRS, and KVM_GET_MSR_INDEX_LIST.
 *
 * This list is modified at module load time to reflect the
 * capabilities of the host cpu. This capabilities test skips MSRs that are
 * kvm-specific. Those are put in the beginning of the list.
 */


#define	KVM_SAVE_MSRS_BEGIN	5
static uint32_t msrs_to_save[] = {
	MSR_KVM_SYSTEM_TIME, MSR_KVM_WALL_CLOCK,
	HV_X64_MSR_GUEST_OS_ID, HV_X64_MSR_HYPERCALL,
	HV_X64_MSR_APIC_ASSIST_PAGE,
	MSR_IA32_SYSENTER_CS, MSR_IA32_SYSENTER_ESP, MSR_IA32_SYSENTER_EIP,
	MSR_K6_STAR,
	MSR_CSTAR, MSR_KERNEL_GS_BASE, MSR_SYSCALL_MASK, MSR_LSTAR,
	MSR_IA32_TSC, MSR_IA32_PERF_STATUS, MSR_IA32_CR_PAT, MSR_VM_HSAVE_PA
};

static unsigned num_msrs_to_save;

static uint32_t emulated_msrs[] = {
	MSR_IA32_MISC_ENABLE,
};

static int
set_efer(struct kvm_vcpu *vcpu, uint64_t efer)
{
	if (efer & efer_reserved_bits)
		return (1);

	if (is_paging(vcpu) &&
	    (vcpu->arch.efer & EFER_LME) != (efer & EFER_LME)) {
		return (1);
	}

	if (efer & EFER_FFXSR) {
		struct kvm_cpuid_entry2 *feat;

		feat = kvm_find_cpuid_entry(vcpu, 0x80000001, 0);
		if (!feat || !(feat->edx & bit(X86_FEATURE_FXSR_OPT)))
			return (1);
	}

	if (efer & EFER_SVME) {
		struct kvm_cpuid_entry2 *feat;

		feat = kvm_find_cpuid_entry(vcpu, 0x80000001, 0);
		if (!feat || !(feat->ecx & bit(X86_FEATURE_SVM)))
			return (1);
	}

	efer &= ~EFER_LMA;
	efer |= vcpu->arch.efer & EFER_LMA;

	kvm_x86_ops->set_efer(vcpu, efer);

	vcpu->arch.efer = efer;

	vcpu->arch.mmu.base_role.nxe = (efer & EFER_NX) && !tdp_enabled;
	kvm_mmu_reset_context(vcpu);

	return (0);
}

void
kvm_enable_efer_bits(uint64_t mask)
{
	efer_reserved_bits &= ~mask;
}

/*
 * Writes msr value into into the appropriate "register".
 * Returns 0 on success, non-0 otherwise.
 * Assumes vcpu_load() was already called.
 */
int
kvm_set_msr(struct kvm_vcpu *vcpu, uint32_t msr_index, uint64_t data)
{
	return (kvm_x86_ops->set_msr(vcpu, msr_index, data));
}

/*
 * Adapt set_msr() to msr_io()'s calling convention
 */
static int
do_set_msr(struct kvm_vcpu *vcpu, unsigned index, uint64_t *data)
{
	return (kvm_set_msr(vcpu, index, *data));
}

static void
kvm_write_wall_clock(struct kvm *kvm, gpa_t wall_clock)
{
	uint32_t version;
	struct pvclock_wall_clock wc;
	timespec_t ts;

	if (!wall_clock)
		return;

	if (kvm_read_guest(kvm, wall_clock, &version, sizeof (version)) != 0)
		return;

	if (version & 1)
		version++;	/* first time write, random junk */

	version++;

	kvm_write_guest(kvm, wall_clock, &version, sizeof (version));

	/* Use recorded time at VM creation */
	wc.sec = kvm->arch.boot_wallclock.tv_sec;
	wc.nsec = kvm->arch.boot_wallclock.tv_nsec;
	wc.version = version;

	kvm_write_guest(kvm, wall_clock, &wc, sizeof (wc));

	version++;
	kvm_write_guest(kvm, wall_clock, &version, sizeof (version));
}

static uint32_t
div_frac(uint32_t dividend, uint32_t divisor)
{
	uint32_t quotient, remainder;

	/*
	 * Don't try to replace with do_div(), this one calculates
	 * "(dividend << 32) / divisor"
	 */
	__asm__("divl %4"
		: "=a" (quotient), "=d" (remainder)
		: "0" (0), "1" (dividend), "r" (divisor));

	return (quotient);
}

static void
kvm_write_guest_time(struct kvm_vcpu *v)
{
	struct kvm_vcpu_arch *vcpu = &v->arch;
	page_t *page;
	struct pvclock_vcpu_time_info *pvclock;
	hrtime_t hrt;
	uint64_t tsc;
	uint32_t scale, version;
	uint8_t shift;

	if (vcpu->time_addr == 0)
		return;

	page = gfn_to_page(v->kvm, vcpu->time_addr >> PAGESHIFT);
	if (page == bad_page) {
		vcpu->time_addr = 0;
		return;
	}
	pvclock = (void *)((uintptr_t)page_address(page) +
	    offset_in_page(vcpu->time_addr));
	version = pvclock->version;

	/*
	 * A note from Linux upstream about the role of the 'version' field in
	 * the pvclock_vcpu_time_info structure:
	 *
	 * This VCPU is paused, but it's legal for a guest to read another
	 * VCPU's kvmclock, so we really have to follow the specification where
	 * it says that version is odd if data is being modified, and even
	 * after it is consistent.
	 */
	if (version & 1) {
		/* uninitialized state with update bit set */
		version += 2;
	} else {
		/* indicate update in progress */
		version++;
	}
	pvclock->version = version;

	membar_producer();

	hrt = tsc_gethrtime_params(&tsc, &scale, &shift);
	pvclock->tsc_timestamp = tsc + vcpu->tsc_offset;
	pvclock->system_time = hrt - v->kvm->arch.boot_hrtime;
	pvclock->tsc_to_system_mul = scale;
	pvclock->tsc_shift = shift;
	pvclock->flags = PVCLOCK_TSC_STABLE_BIT;

	membar_producer();

	/* indicate update finished */
	pvclock->version = version + 1;
	vcpu->time_update = hrt;

	kvm_release_page_dirty(page);
	mark_page_dirty(v->kvm, vcpu->time_addr >> PAGESHIFT);
}

/*
 * In the upstream Linux KVM, routine updates to pvclock data are throttled to
 * a 100ms interval.  We use that value as well.
 */
#define	KVMCLOCK_UPDATE_INTERVAL	(100000000U) /* 100ms in ns */

static int
kvm_request_guest_time_update(struct kvm_vcpu *v, boolean_t force)
{
	struct kvm_vcpu_arch *vcpu = &v->arch;

	if (vcpu->time_addr == 0)
		return (0);

	/*
	 * If this is not a forced or first update request, check to see if a
	 * reasonable (and somewhat arbitrary) amount of time has passed. If
	 * the last update was recent, skip the pvclock update request to keep
	 * the write rate down.
	 */
	if (!force || vcpu->time_update != 0) {
		hrtime_t hrt;

		hrt = gethrtime();
		if ((hrt - vcpu->time_update) < KVMCLOCK_UPDATE_INTERVAL)
			return (0);
	}

	set_bit(KVM_REQ_KVMCLOCK_UPDATE, &v->requests);

	return (1);
}

static int
msr_mtrr_valid(unsigned msr)
{
	switch (msr) {
	case 0x200 ... 0x200 + 2 * KVM_NR_VAR_MTRR - 1:
	case MSR_MTRRfix64K_00000:
	case MSR_MTRRfix16K_80000:
	case MSR_MTRRfix16K_A0000:
	case MSR_MTRRfix4K_C0000:
	case MSR_MTRRfix4K_C8000:
	case MSR_MTRRfix4K_D0000:
	case MSR_MTRRfix4K_D8000:
	case MSR_MTRRfix4K_E0000:
	case MSR_MTRRfix4K_E8000:
	case MSR_MTRRfix4K_F0000:
	case MSR_MTRRfix4K_F8000:
	case MSR_MTRRdefType:
	case MSR_IA32_CR_PAT:
		return (1);
	case 0x2f8:
		return (1);
	}

	return (0);
}

static int
valid_pat_type(unsigned t)
{
	return (t < 8 && (1 << t) & 0xf3); /* 0, 1, 4, 5, 6, 7 */
}

static int
valid_mtrr_type(unsigned t)
{
	return (t < 8 && (1 << t) & 0x73); /* 0, 1, 4, 5, 6 */
}

static int
mtrr_valid(struct kvm_vcpu *vcpu, uint32_t msr, uint64_t data)
{
	int i;

	if (!msr_mtrr_valid(msr))
		return (0);

	if (msr == MSR_IA32_CR_PAT) {
		for (i = 0; i < 8; i++)
			if (!valid_pat_type((data >> (i * 8)) & 0xff))
				return (0);
		return (1);
	} else if (msr == MSR_MTRRdefType) {
		if (data & ~0xcff)
			return (0);
		return (valid_mtrr_type(data & 0xff));
	} else if (msr >= MSR_MTRRfix64K_00000 && msr <= MSR_MTRRfix4K_F8000) {
		for (i = 0; i < 8; i++)
			if (!valid_mtrr_type((data >> (i * 8)) & 0xff))
				return (0);
		return (1);
	}

	/* variable MTRRs */
	return (valid_mtrr_type(data & 0xff));
}

static int
set_msr_mtrr(struct kvm_vcpu *vcpu, uint32_t msr, uint64_t data)
{
	struct mtrr_state_type *state = &vcpu->arch.mtrr_state;

	uint64_t *p = (uint64_t *)&state->fixed_ranges;

	if (!mtrr_valid(vcpu, msr, data))
		return (1);

	if (msr == MSR_MTRRdefType) {
		state->def_type = data;
		state->enabled = (data & 0xc00) >> 10;
	} else if (msr == MSR_MTRRfix64K_00000)
		p[0] = data;
	else if (msr == MSR_MTRRfix16K_80000 || msr == MSR_MTRRfix16K_A0000)
		p[1 + msr - MSR_MTRRfix16K_80000] = data;
	else if (msr >= MSR_MTRRfix4K_C0000 && msr <= MSR_MTRRfix4K_F8000)
		p[3 + msr - MSR_MTRRfix4K_C0000] = data;
	else if (msr == MSR_IA32_CR_PAT)
		vcpu->arch.pat = data;
	else {	/* Variable MTRRs */
		int idx, is_mtrr_mask;
		uint64_t *pt;

		idx = (msr - 0x200) / 2;
		is_mtrr_mask = msr - 0x200 - 2 * idx;

		if (!is_mtrr_mask) {
			pt = (uint64_t *)&state->var_ranges[idx].base_lo;
		} else {
			pt = (uint64_t *)&state->var_ranges[idx].mask_lo;
		}

		*pt = data;
	}

	kvm_mmu_reset_context(vcpu);

	return (0);
}

static int
set_msr_mce(struct kvm_vcpu *vcpu, uint32_t msr, uint64_t data)
{
	uint64_t mcg_cap = vcpu->arch.mcg_cap;
	unsigned bank_num = mcg_cap & 0xff;

	switch (msr) {
	case MSR_IA32_MCG_STATUS:
		vcpu->arch.mcg_status = data;
		break;
	case MSR_IA32_MCG_CTL:
		if (!(mcg_cap & MCG_CTL_P))
			return (1);
		if (data != 0 && data != ~(uint64_t)0)
			return (-1);
		vcpu->arch.mcg_ctl = data;
		break;
	default:
		if (msr >= MSR_IA32_MC0_CTL &&
		    msr < MSR_IA32_MC0_CTL + 4 * bank_num) {
			uint32_t offset = msr - MSR_IA32_MC0_CTL;
			/*
			 * only 0 or all 1s can be written to IA32_MCi_CTL
			 * some Linux kernels though clear bit 10 in bank 4 to
			 * workaround a BIOS/GART TBL issue on AMD K8s, ignore
			 * this to avoid an uncatched #GP in the guest
			 */
			if ((offset & 0x3) == 0 &&
			    data != 0 && (data | (1 << 10)) != ~(uint64_t)0)
				return (-1);
			vcpu->arch.mce_banks[offset] = data;
			break;
		}
		return (1);
	}
	return (0);
}

static int
xen_hvm_config(struct kvm_vcpu *vcpu, uint64_t data)
{
	struct kvm *kvm = vcpu->kvm;
	int lm = is_long_mode(vcpu);
	uint8_t *blob_addr = lm ?
	    (uint8_t *)(long)kvm->arch.xen_hvm_config.blob_addr_64 :
	    (uint8_t *)(long)kvm->arch.xen_hvm_config.blob_addr_32;
	uint8_t blob_size = lm ?
	    kvm->arch.xen_hvm_config.blob_size_64 :
	    kvm->arch.xen_hvm_config.blob_size_32;
	uint32_t page_num = data & ~PAGEMASK;
	uint64_t page_addr = data & PAGEMASK;
	uint8_t *page;
	int r;

	r = E2BIG;
	if (page_num >= blob_size)
		goto out;
	r = ENOMEM;
	page = kmem_alloc(PAGESIZE, KM_SLEEP);
	r = EFAULT;
	if (copyin(blob_addr + (page_num * PAGESIZE), page, PAGESIZE))
		goto out_free;
	if (kvm_write_guest(kvm, page_addr, page, PAGESIZE))
		goto out_free;
	r = 0;
out_free:
	kmem_free(page, PAGESIZE);
out:
	return (r);
}


static int
kvm_hv_hypercall_enabled(struct kvm *kvm)
{
	return (kvm->arch.hv_hypercall & HV_X64_MSR_HYPERCALL_ENABLE);
}

static int
kvm_hv_msr_partition_wide(uint32_t msr)
{
	int r = 0;
	switch (msr) {
	case HV_X64_MSR_GUEST_OS_ID:
	case HV_X64_MSR_HYPERCALL:
		r = 1;
		break;
	}

	return (r);
}

static int
set_msr_hyperv_pw(struct kvm_vcpu *vcpu, uint32_t msr, uint64_t data)
{
	struct kvm *kvm = vcpu->kvm;

	switch (msr) {
	case HV_X64_MSR_GUEST_OS_ID:
		kvm->arch.hv_guest_os_id = data;
		/* setting guest os id to zero disables hypercall page */
		if (!kvm->arch.hv_guest_os_id)
			kvm->arch.hv_hypercall &= ~HV_X64_MSR_HYPERCALL_ENABLE;
		break;
	case HV_X64_MSR_HYPERCALL: {
		uint64_t gfn;
		unsigned long addr;
		uint8_t instructions[4];

		/* if guest os id is not set hypercall should remain disabled */
		if (!kvm->arch.hv_guest_os_id)
			break;
		if (!(data & HV_X64_MSR_HYPERCALL_ENABLE)) {
			kvm->arch.hv_hypercall = data;
			break;
		}
		gfn = data >> HV_X64_MSR_HYPERCALL_PAGE_ADDRESS_SHIFT;
		addr = gfn_to_hva(kvm, gfn);
		if (kvm_is_error_hva(addr))
			return (1);
		kvm_x86_ops->patch_hypercall(vcpu, instructions);
		((unsigned char *)instructions)[3] = 0xc3; /* ret */
		if (copyout(instructions, (caddr_t)addr, 4))
			return (1);
		kvm->arch.hv_hypercall = data;
		break;
	}
	default:
		cmn_err(CE_WARN, "HYPER-V unimplemented wrmsr: 0x%x "
		    "data 0x%lx\n", msr, data);
		return (1);
	}

	return (0);
}

static int
clear_user(void *addr, unsigned long size)
{
	caddr_t ka;
	int rval = 0;

	ka = kmem_zalloc(size, KM_SLEEP);
	rval = copyout(ka, addr, size);
	kmem_free(ka, size);

	return (rval);
}

static int
set_msr_hyperv(struct kvm_vcpu *vcpu, uint32_t msr, uint64_t data)
{
	switch (msr) {
	case HV_X64_MSR_APIC_ASSIST_PAGE: {
		unsigned long addr;

		if (!(data & HV_X64_MSR_APIC_ASSIST_PAGE_ENABLE)) {
			vcpu->arch.hv_vapic = data;
			break;
		}

		addr = gfn_to_hva(vcpu->kvm,
		    data >> HV_X64_MSR_APIC_ASSIST_PAGE_ADDRESS_SHIFT);

		if (kvm_is_error_hva(addr))
			return (1);

		if (clear_user((void *)addr, PAGESIZE))
			return (1);

		vcpu->arch.hv_vapic = data;
		break;
	}

	case HV_X64_MSR_EOI:
		return (kvm_hv_vapic_msr_write(vcpu, APIC_EOI, data));
	case HV_X64_MSR_ICR:
		return (kvm_hv_vapic_msr_write(vcpu, APIC_ICR, data));
	case HV_X64_MSR_TPR:
		return (kvm_hv_vapic_msr_write(vcpu, APIC_TASKPRI, data));

	default:
		cmn_err(CE_WARN, "HYPER-V unimplemented wrmsr: 0x%x "
		    "data 0x%lx\n", msr, data);
		return (1);
	}

	return (0);
}

int
kvm_set_msr_common(struct kvm_vcpu *vcpu, uint32_t msr, uint64_t data)
{
	switch (msr) {
	case MSR_EFER:
		return (set_efer(vcpu, data));
	case MSR_K7_HWCR:
		data &= ~(uint64_t)0x40; /* ignore flush filter disable */
		if (data != 0) {
			cmn_err(CE_CONT,
			    "!unimplemented HWCR wrmsr: 0x%lx\n", data);
			return (1);
		}
		break;
	case MSR_FAM10H_MMIO_CONF_BASE:
		if (data != 0) {
			cmn_err(CE_CONT, "!unimplemented MMIO_CONF_BASE wrmsr: "
				"0x%lx\n", data);
			return (1);
		}
		break;
	case MSR_AMD64_NB_CFG:
		break;
	case MSR_IA32_DEBUGCTLMSR:
		if (!data) {
			/* We support the non-activated case already */
			break;
		} else if (data & ~(DEBUGCTLMSR_LBR | DEBUGCTLMSR_BTF)) {
			/*
			 * Values other than LBR and BTF are vendor-specific,
			 * thus reserved and should throw a #GP
			 */
			return (1);
		}
		cmn_err(CE_CONT, "!%s: MSR_IA32_DEBUGCTLMSR 0x%lx, nop\n",
			__func__, data);
		break;
	case MSR_IA32_UCODE_REV:
	case MSR_IA32_UCODE_WRITE:
	case MSR_VM_HSAVE_PA:
	case MSR_AMD64_PATCH_LOADER:
		break;
	case 0x200 ... 0x2ff:
		return (set_msr_mtrr(vcpu, msr, data));
	case MSR_IA32_APICBASE:
		kvm_set_apic_base(vcpu, data);
		break;
	case APIC_BASE_MSR ... APIC_BASE_MSR + 0x3ff:
		return (kvm_x2apic_msr_write(vcpu, msr, data));
	case MSR_IA32_MISC_ENABLE:
		vcpu->arch.ia32_misc_enable_msr = data;
		break;

	case MSR_KVM_WALL_CLOCK:
	case MSR_KVM_WALL_CLOCK_NEW:
		vcpu->kvm->arch.wall_clock = data;
		kvm_write_wall_clock(vcpu->kvm, data);
		break;
	case MSR_KVM_SYSTEM_TIME:
	case MSR_KVM_SYSTEM_TIME_NEW:
	{
		vcpu->arch.time_addr = 0;
		vcpu->arch.time_val = data;

		/* nothing further to do if disabled */
		if ((data & 1) == 0)
			break;

		/* insist that the time output be confined to a single page */
		data &= ~1UL;
		if (((data & PAGEOFFSET) +
		    sizeof (struct pvclock_vcpu_time_info)) > PAGESIZE) {
			break;
		}

		vcpu->arch.time_addr = data;
		kvm_request_guest_time_update(vcpu, B_TRUE);
		break;
	}

	case MSR_IA32_MCG_CTL:
	case MSR_IA32_MCG_STATUS:
	case MSR_IA32_MC0_CTL ... MSR_IA32_MC0_CTL + 4 * KVM_MAX_MCE_BANKS - 1:
		return (set_msr_mce(vcpu, msr, data));

	/*
	 * Performance counters are not protected by a CPUID bit, so we should
	 * check all of them in the generic path for the sake of cross vendor
	 * migration. Writing a zero into the event select MSRs disables them,
	 * which we perfectly emulate ;-). Any other value should be at least
	 * reported, some guests depend on them.
	 */
	case MSR_P6_EVNTSEL0:
	case MSR_P6_EVNTSEL1:
	case MSR_K7_EVNTSEL0:
	case MSR_K7_EVNTSEL1:
	case MSR_K7_EVNTSEL2:
	case MSR_K7_EVNTSEL3:
		if (data != 0)
			cmn_err(CE_CONT, "!unimplemented perfctr wrmsr: "
				"0x%x data 0x%lx\n", msr, data);
		break;
	/*
	 * at least RHEL 4 unconditionally writes to the perfctr registers,
	 * so we ignore writes to make it happy.
	 */
	case MSR_P6_PERFCTR0:
	case MSR_P6_PERFCTR1:
	case MSR_K7_PERFCTR0:
	case MSR_K7_PERFCTR1:
	case MSR_K7_PERFCTR2:
	case MSR_K7_PERFCTR3:
		cmn_err(CE_CONT, "!unimplemented perfctr wrmsr: "
			"0x%x data 0x%lx\n", msr, data);
		break;
	case HV_X64_MSR_GUEST_OS_ID ... HV_X64_MSR_SINT15:
		if (kvm_hv_msr_partition_wide(msr)) {
			int r;
			mutex_enter(&vcpu->kvm->lock);
			r = set_msr_hyperv_pw(vcpu, msr, data);
			mutex_exit(&vcpu->kvm->lock);
			return (r);
		} else
			return (set_msr_hyperv(vcpu, msr, data));
		break;
	default:
		if (msr && (msr == vcpu->kvm->arch.xen_hvm_config.msr))
			return (xen_hvm_config(vcpu, data));
		if (!ignore_msrs) {
			cmn_err(CE_CONT, "!unhandled wrmsr: 0x%x data %lx\n",
				msr, data);
			return (1);
		} else {
			cmn_err(CE_CONT, "!ignored wrmsr: 0x%x data %lx\n",
				msr, data);
			break;
		}
	}

	return (0);
}

/*
 * Reads an msr value (of 'msr_index') into 'pdata'.
 * Returns 0 on success, non-0 otherwise.
 * Assumes vcpu_load() was already called.
 */
int
kvm_get_msr(struct kvm_vcpu *vcpu, uint32_t msr_index, uint64_t *pdata)
{
	return (kvm_x86_ops->get_msr(vcpu, msr_index, pdata));
}

static int
get_msr_mtrr(struct kvm_vcpu *vcpu, uint32_t msr, uint64_t *pdata)
{
	struct mtrr_state_type *state = &vcpu->arch.mtrr_state;
	uint64_t *p = (uint64_t *)&state->fixed_ranges;

	if (!msr_mtrr_valid(msr))
		return (1);

	if (msr == MSR_MTRRdefType)
		*pdata = vcpu->arch.mtrr_state.def_type +
		    (vcpu->arch.mtrr_state.enabled << 10);
	else if (msr == MSR_MTRRfix64K_00000)
		*pdata = p[0];
	else if (msr == MSR_MTRRfix16K_80000 || msr == MSR_MTRRfix16K_A0000)
		*pdata = p[1 + msr - MSR_MTRRfix16K_80000];
	else if (msr >= MSR_MTRRfix4K_C0000 && msr <= MSR_MTRRfix4K_F8000)
		*pdata = p[3 + msr - MSR_MTRRfix4K_C0000];
	else if (msr == MSR_IA32_CR_PAT)
		*pdata = vcpu->arch.pat;
	else {	/* Variable MTRRs */
		int idx, is_mtrr_mask;
		uint64_t *pt;

		idx = (msr - 0x200) / 2;
		is_mtrr_mask = msr - 0x200 - 2 * idx;
		if (!is_mtrr_mask) {
			pt = (uint64_t *)&state->var_ranges[idx].base_lo;
		} else {
			pt = (uint64_t *)&state->var_ranges[idx].mask_lo;
		}

		*pdata = *pt;
	}

	return (0);
}

static int
get_msr_mce(struct kvm_vcpu *vcpu, uint32_t msr, uint64_t *pdata)
{
	uint64_t data;
	uint64_t mcg_cap = vcpu->arch.mcg_cap;
	unsigned bank_num = mcg_cap & 0xff;

	switch (msr) {
	case MSR_IA32_P5_MC_ADDR:
	case MSR_IA32_P5_MC_TYPE:
		data = 0;
		break;
	case MSR_IA32_MCG_CAP:
		data = vcpu->arch.mcg_cap;
		break;
	case MSR_IA32_MCG_CTL:
		if (!(mcg_cap & MCG_CTL_P))
			return (1);
		data = vcpu->arch.mcg_ctl;
		break;
	case MSR_IA32_MCG_STATUS:
		data = vcpu->arch.mcg_status;
		break;
	default:
		if (msr >= MSR_IA32_MC0_CTL &&
		    msr < MSR_IA32_MC0_CTL + 4 * bank_num) {
			uint32_t offset = msr - MSR_IA32_MC0_CTL;
			data = vcpu->arch.mce_banks[offset];
			break;
		}
		return (1);
	}
	*pdata = data;
	return (0);
}

static int
get_msr_hyperv_pw(struct kvm_vcpu *vcpu, uint32_t msr, uint64_t *pdata)
{
	uint64_t data = 0;
	struct kvm *kvm = vcpu->kvm;

	switch (msr) {
	case HV_X64_MSR_GUEST_OS_ID:
		data = kvm->arch.hv_guest_os_id;
		break;
	case HV_X64_MSR_HYPERCALL:
		data = kvm->arch.hv_hypercall;
		break;
	default:
		cmn_err(CE_WARN, "Hyper-V unhandled rdmsr: 0x%x\n", msr);
		return (1);
	}

	*pdata = data;

	return (0);
}

static int
get_msr_hyperv(struct kvm_vcpu *vcpu, uint32_t msr, uint64_t *pdata)
{
	uint64_t data = 0;

	switch (msr) {
	case HV_X64_MSR_VP_INDEX: {
		int r;
		struct kvm_vcpu *v;
		kvm_for_each_vcpu(r, v, vcpu->kvm)
			if (v == vcpu)
				data = r;
		break;
	}
	case HV_X64_MSR_EOI:
		return (kvm_hv_vapic_msr_read(vcpu, APIC_EOI, pdata));
	case HV_X64_MSR_ICR:
		return (kvm_hv_vapic_msr_read(vcpu, APIC_ICR, pdata));
	case HV_X64_MSR_TPR:
		return (kvm_hv_vapic_msr_read(vcpu, APIC_TASKPRI, pdata));
	default:
		cmn_err(CE_WARN, "Hyper-V unhandled rdmsr: 0x%x\n", msr);
		return (1);
	}

	*pdata = data;
	return (0);
}

int
kvm_get_msr_common(struct kvm_vcpu *vcpu, uint32_t msr, uint64_t *pdata)
{
	uint64_t data;

	switch (msr) {
	case MSR_IA32_PLATFORM_ID:
	case MSR_IA32_UCODE_REV:
	case MSR_IA32_EBL_CR_POWERON:
	case MSR_IA32_DEBUGCTLMSR:
	case MSR_IA32_LASTBRANCHFROMIP:
	case MSR_IA32_LASTBRANCHTOIP:
	case MSR_IA32_LASTINTFROMIP:
	case MSR_IA32_LASTINTTOIP:
	case MSR_K8_SYSCFG:
	case MSR_K7_HWCR:
	case MSR_VM_HSAVE_PA:
	case MSR_P6_PERFCTR0:
	case MSR_P6_PERFCTR1:
	case MSR_P6_EVNTSEL0:
	case MSR_P6_EVNTSEL1:
	case MSR_K7_EVNTSEL0:
	case MSR_K7_PERFCTR0:
	case MSR_K8_INT_PENDING_MSG:
	case MSR_AMD64_NB_CFG:
	case MSR_FAM10H_MMIO_CONF_BASE:
		data = 0;
		break;
	case MSR_MTRRcap:
		data = 0x500 | KVM_NR_VAR_MTRR;
		break;
	case 0x200 ... 0x2ff:
		return (get_msr_mtrr(vcpu, msr, pdata));
	case 0xcd: /* fsb frequency */
		data = 3;
		break;
	case MSR_IA32_APICBASE:
		data = kvm_get_apic_base(vcpu);
		break;
	case APIC_BASE_MSR ... APIC_BASE_MSR + 0x3ff:
		return (kvm_x2apic_msr_read(vcpu, msr, pdata));
		break;
	case MSR_IA32_MISC_ENABLE:
		data = vcpu->arch.ia32_misc_enable_msr;
		break;
	case MSR_IA32_PERF_STATUS:
		/* TSC increment by tick */
		data = 1000ULL;
		/* CPU multiplier */
		data |= (((uint64_t)4ULL) << 40);
		break;
	case MSR_EFER:
		data = vcpu->arch.efer;
		break;
	case MSR_KVM_WALL_CLOCK:
	case MSR_KVM_WALL_CLOCK_NEW:
		data = vcpu->kvm->arch.wall_clock;
		break;
	case MSR_KVM_SYSTEM_TIME:
	case MSR_KVM_SYSTEM_TIME_NEW:
		data = vcpu->arch.time_val;
		break;
	case MSR_IA32_P5_MC_ADDR:
	case MSR_IA32_P5_MC_TYPE:
	case MSR_IA32_MCG_CAP:
	case MSR_IA32_MCG_CTL:
	case MSR_IA32_MCG_STATUS:
	case MSR_IA32_MC0_CTL ... MSR_IA32_MC0_CTL + 4 * KVM_MAX_MCE_BANKS - 1:
		return (get_msr_mce(vcpu, msr, pdata));
	case HV_X64_MSR_GUEST_OS_ID ... HV_X64_MSR_SINT15:
		if (kvm_hv_msr_partition_wide(msr)) {
			int r;
			mutex_enter(&vcpu->kvm->lock);
			r = get_msr_hyperv_pw(vcpu, msr, pdata);
			mutex_exit(&vcpu->kvm->lock);
			return (r);
		} else
			return (get_msr_hyperv(vcpu, msr, pdata));
		break;
	default:
		if (!ignore_msrs) {
			cmn_err(CE_CONT, "!unhandled rdmsr: 0x%x\n", msr);
			return (1);
		} else {
			cmn_err(CE_CONT, "!ignored rdmsr: 0x%x\n", msr);
			data = 0;
		}
		break;
	}
	*pdata = data;

	return (0);
}

/*
 * Read or write a bunch of msrs. All parameters are kernel addresses.
 *
 * @return number of msrs set successfully.
 */
static int
__msr_io(struct kvm_vcpu *vcpu, struct kvm_msrs *msrs,
    struct kvm_msr_entry *entries, int (*do_msr)(struct kvm_vcpu *vcpu,
    unsigned index, uint64_t *data))
{
	int i, idx;

	vcpu_load(vcpu);

	for (i = 0; i < msrs->nmsrs; i++) {
		if (do_msr(vcpu, entries[i].index, &entries[i].data))
			break;
	}

	vcpu_put(vcpu);

	return (i);
}

int
kvm_vcpu_ioctl_get_msrs(struct kvm_vcpu *vcpu, struct kvm_msrs *msrs, int *rv)
{
	int r;

	if (msrs->nmsrs >= MAX_IO_MSRS)
		return (-E2BIG);

	if ((r = __msr_io(vcpu, msrs, msrs->entries, kvm_get_msr)) < 0)
		return (r);

	*rv = r;

	return (0);
}

int
kvm_vcpu_ioctl_set_msrs(struct kvm_vcpu *vcpu, struct kvm_msrs *msrs, int *rv)
{
	int r;

	if (msrs->nmsrs >= MAX_IO_MSRS)
		return (-E2BIG);

	if ((r = __msr_io(vcpu, msrs, msrs->entries, do_set_msr)) < 0)
		return (-EINVAL);

	*rv = r;

	return (0);
}

int
kvm_dev_ioctl_check_extension(long ext, int *rval_p)
{
	int r;

	switch (ext) {
	case KVM_CAP_IRQCHIP:
	case KVM_CAP_HLT:
	case KVM_CAP_MMU_SHADOW_CACHE_CONTROL:
	case KVM_CAP_SET_TSS_ADDR:
	case KVM_CAP_EXT_CPUID:
	case KVM_CAP_CLOCKSOURCE:
	case KVM_CAP_PIT:
	case KVM_CAP_NOP_IO_DELAY:
	case KVM_CAP_MP_STATE:
	case KVM_CAP_SYNC_MMU:
	case KVM_CAP_REINJECT_CONTROL:
	case KVM_CAP_IRQ_INJECT_STATUS:
	case KVM_CAP_ASSIGN_DEV_IRQ:
	case KVM_CAP_IOEVENTFD:
	case KVM_CAP_PIT2:
	case KVM_CAP_PIT_STATE2:
	case KVM_CAP_SET_IDENTITY_MAP_ADDR:
	case KVM_CAP_XEN_HVM:
	case KVM_CAP_ADJUST_CLOCK:
	case KVM_CAP_VCPU_EVENTS:
	case KVM_CAP_HYPERV:
	case KVM_CAP_HYPERV_VAPIC:
	case KVM_CAP_HYPERV_SPIN:
	case KVM_CAP_PCI_SEGMENT:
	case KVM_CAP_X86_ROBUST_SINGLESTEP:
		*rval_p = 1;
		r = DDI_SUCCESS;
		break;
	case KVM_CAP_COALESCED_MMIO:
		*rval_p = KVM_COALESCED_MMIO_PAGE_OFFSET;
		r = DDI_SUCCESS;
		break;
	case KVM_CAP_VAPIC:
		*rval_p = !kvm_x86_ops->cpu_has_accelerated_tpr();
		r = DDI_SUCCESS;
		break;
	case KVM_CAP_NR_VCPUS:
		*rval_p = KVM_MAX_VCPUS;
		r = DDI_SUCCESS;
		break;
	case KVM_CAP_NR_MEMSLOTS:
		*rval_p = KVM_MEMORY_SLOTS;
		r = DDI_SUCCESS;
		break;
	case KVM_CAP_PV_MMU:	/* obsolete */
		r = EINVAL;
		break;
	case KVM_CAP_IOMMU:
		*rval_p = 0;
		r = DDI_SUCCESS;
		break;
	case KVM_CAP_MCE:
		*rval_p = KVM_MAX_MCE_BANKS;
		r = DDI_SUCCESS;
		break;
	default:
		r = EINVAL;
		break;
	}

	return (r);
}

void
kvm_arch_vcpu_load(struct kvm_vcpu *vcpu, int cpu)
{
	kvm_x86_ops->vcpu_load(vcpu, cpu);
	kvm_request_guest_time_update(vcpu, B_FALSE);
}

void
kvm_arch_vcpu_put(struct kvm_vcpu *vcpu)
{
	kvm_put_guest_fpu(vcpu);

	kvm_x86_ops->vcpu_put(vcpu);
}

static int
is_efer_nx(void)
{
	unsigned long long efer = 0;

	rdmsrl_safe(MSR_EFER, &efer);
	return (efer & EFER_NX);
}

int
kvm_vcpu_ioctl_set_cpuid2(struct kvm_vcpu *vcpu, struct kvm_cpuid2 *cpuid,
    int *rv, intptr_t arg)
{
	struct kvm_cpuid2 *id;

	id = (void *)arg;

	if (cpuid->nent > KVM_MAX_CPUID_ENTRIES)
		return (E2BIG);

	if (copyin(id->entries, vcpu->arch.cpuid_entries,
	    cpuid->nent * sizeof (struct kvm_cpuid_entry2)) < 0)
		return (EFAULT);

	vcpu_load(vcpu);
	vcpu->arch.cpuid_nent = cpuid->nent;
	kvm_apic_set_version(vcpu);
	kvm_x86_ops->cpuid_update(vcpu);
	vcpu_put(vcpu);

	return (0);
}

int
kvm_vcpu_ioctl_get_cpuid2(struct kvm_vcpu *vcpu, struct kvm_cpuid2 *cpuid)
{
	int r;
	struct kvm_cpuid_entry2 *entries = cpuid->entries;

	vcpu_load(vcpu);

	cpuid->nent = vcpu->arch.cpuid_nent;

	if (cpuid->nent < vcpu->arch.cpuid_nent) {
		vcpu_put(vcpu);
		return (E2BIG);
	}

	bcopy(&vcpu->arch.cpuid_entries, cpuid->entries,
	    vcpu->arch.cpuid_nent * sizeof (struct kvm_cpuid_entry2));

	vcpu_put(vcpu);

	return (0);
}

static inline void native_cpuid(unsigned int *eax, unsigned int *ebx,
				unsigned int *ecx, unsigned int *edx)
{
	/* ecx is often an input as well as an output. */
	__asm__ volatile("cpuid"
	    : "=a" (*eax),
	    "=b" (*ebx),
	    "=c" (*ecx),
	    "=d" (*edx)
	    : "0" (*eax), "2" (*ecx));
}

#define	__cpuid			native_cpuid

/* Some CPUID calls want 'count' to be placed in ecx */
static inline void
cpuid_count(unsigned int op, int count, unsigned int *eax, unsigned int *ebx,
    unsigned int *ecx, unsigned int *edx)
{
	*eax = op;
	*ecx = count;
	__cpuid(eax, ebx, ecx, edx);
}

static void
do_cpuid_1_ent(kvm_cpuid_entry2_t *entry, uint32_t function, uint32_t index)
{
	entry->function = function;
	entry->index = index;
	cpuid_count(entry->function, entry->index,
		    &entry->eax, &entry->ebx, &entry->ecx, &entry->edx);
	entry->flags = 0;
}


#define	F(x) bit(X86_FEATURE_##x)

static void
do_cpuid_ent(struct kvm_cpuid_entry2 *entry, uint32_t function,
    uint32_t index, int *nent, int maxnent)
{
	unsigned int ddic;
	unsigned f_nx = is_efer_nx() ? F(NX) : 0;
	unsigned f_gbpages = (kvm_x86_ops->get_lpage_level() == PT_PDPE_LEVEL)
				? F(GBPAGES) : 0;
	unsigned f_lm = F(LM);
	unsigned f_rdtscp = kvm_x86_ops->rdtscp_supported() ? F(RDTSCP) : 0;

	/* cpuid 1.edx */
	const uint32_t kvm_supported_word0_x86_features =
		F(FPU) | F(VME) | F(DE) | F(PSE) |
		F(TSC) | F(MSR) | F(PAE) | F(MCE) |
		F(CX8) | F(APIC) | 0 /* Reserved */ | F(SEP) |
		F(MTRR) | F(PGE) | F(MCA) | F(CMOV) |
		F(PAT) | F(PSE36) | 0 /* PSN */ | F(CLFLSH) |
		0 /* Reserved, DS, ACPI */ | F(MMX) |
		F(FXSR) | F(XMM) | F(XMM2) | F(SELFSNOOP) |
		0 /* HTT, TM, Reserved, PBE */;
	/* cpuid 0x80000001.edx */
	const uint32_t kvm_supported_word1_x86_features =
		F(FPU) | F(VME) | F(DE) | F(PSE) |
		F(TSC) | F(MSR) | F(PAE) | F(MCE) |
		F(CX8) | F(APIC) | 0 /* Reserved */ | F(SYSCALL) |
		F(MTRR) | F(PGE) | F(MCA) | F(CMOV) |
		F(PAT) | F(PSE36) | 0 /* Reserved */ |
		f_nx | 0 /* Reserved */ | F(MMXEXT) | F(MMX) |
		F(FXSR) | F(FXSR_OPT) | f_gbpages | f_rdtscp |
		0 /* Reserved */ | f_lm | F(3DNOWEXT) | F(3DNOW);
	/* cpuid 1.ecx */
	const uint32_t kvm_supported_word4_x86_features =
		F(XMM3) | 0 /* Reserved, DTES64, MONITOR */ |
		0 /* DS-CPL, VMX, SMX, EST */ |
		0 /* TM2 */ | F(SSSE3) | 0 /* CNXT-ID */ | 0 /* Reserved */ |
		0 /* Reserved */ | F(CX16) | 0 /* xTPR Update, PDCM */ |
		0 /* Reserved, DCA */ | F(XMM4_1) |
		F(XMM4_2) | F(X2APIC) | F(MOVBE) | F(POPCNT) |
		0 /* Reserved, XSAVE, OSXSAVE */ | F(AES) |
		0 /* AVX, Reserved */;
	/* cpuid 0x80000001.ecx */
	const uint32_t kvm_supported_word6_x86_features =
		F(LAHF_LM) | F(CMP_LEGACY) | F(SVM) | 0 /* ExtApicSpace */ |
		F(CR8_LEGACY) | F(ABM) | F(SSE4A) | F(MISALIGNSSE) |
		F(3DNOWPREFETCH) | 0 /* OSVW */ | 0 /* IBS */ | F(SSE5) |
		0 /* SKINIT */ | 0 /* WDT */;

	/*
	 * Keep us from migrating between cpuid calls.
	 */
	kpreempt_disable();

	do_cpuid_1_ent(entry, function, index);
	++*nent;

	switch (function) {
	case 0:
		entry->eax = min(entry->eax, (uint32_t)0xb);
		break;
	case 1:
		entry->edx &= kvm_supported_word0_x86_features;
		entry->ecx &= kvm_supported_word4_x86_features;
		/*
		 * we support x2apic emulation even if host does not support
		 * it since we emulate x2apic in software
		 */
		entry->ecx |= F(X2APIC);
		break;
	/*
	 * function 2 entries are STATEFUL. That is, repeated cpuid commands
	 * may return different values. This forces us to get_cpu() before
	 * issuing the first command, and also to emulate this annoying behavior
	 * in kvm_emulate_cpuid() using KVM_CPUID_FLAG_STATE_READ_NEXT
	 */
	case 2: {
		int t, times = entry->eax & 0xff;

		entry->flags |= KVM_CPUID_FLAG_STATEFUL_FUNC;
		entry->flags |= KVM_CPUID_FLAG_STATE_READ_NEXT;
		for (t = 1; t < times && *nent < maxnent; ++t) {
			do_cpuid_1_ent(&entry[t], function, 0);
			entry[t].flags |= KVM_CPUID_FLAG_STATEFUL_FUNC;
			++*nent;
		}
		break;
	}
	/* function 4 and 0xb have additional index. */
	case 4: {
		int i, cache_type;

		entry->flags |= KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
		/* read more entries until cache_type is zero */
		for (i = 1; *nent < maxnent; ++i) {
			cache_type = entry[i - 1].eax & 0x1f;
			if (!cache_type)
				break;
			do_cpuid_1_ent(&entry[i], function, i);
			entry[i].flags |= KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
			++*nent;
		}
		break;
	}
	case 0xb: {
		int i, level_type;

		entry->flags |= KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
		/* read more entries until level_type is zero */
		for (i = 1; *nent < maxnent; ++i) {
			level_type = entry[i - 1].ecx & 0xff00;
			if (!level_type)
				break;
			do_cpuid_1_ent(&entry[i], function, i);
			entry[i].flags |= KVM_CPUID_FLAG_SIGNIFCANT_INDEX;
			++*nent;
		}
		break;
	}
	case 0x80000000:
		entry->eax = min(entry->eax, 0x8000001a);
		break;
	case 0x80000001:
		entry->edx &= kvm_supported_word1_x86_features;
		entry->ecx &= kvm_supported_word6_x86_features;
		break;
	}

	kpreempt_enable();
}

#undef F

int
kvm_dev_ioctl_get_supported_cpuid(struct kvm_cpuid2 *cpuid,
    struct kvm_cpuid_entry2  *entries)
{
	struct kvm_cpuid_entry2 *cpuid_entries;
	int limit, nent = 0, r = E2BIG;
	uint32_t func;
	int allocsize = 0;

	if (cpuid->nent < 1)
		goto out;
	if (cpuid->nent > KVM_MAX_CPUID_ENTRIES)
		cpuid->nent = KVM_MAX_CPUID_ENTRIES;
	r = ENOMEM;
	allocsize = sizeof (struct kvm_cpuid_entry2) * cpuid->nent;
	cpuid_entries = kmem_zalloc(allocsize, KM_SLEEP);

	do_cpuid_ent(&cpuid_entries[0], 0, 0, &nent, cpuid->nent);
	limit = cpuid_entries[0].eax;
	for (func = 1; func <= limit && nent < cpuid->nent; ++func)
		do_cpuid_ent(&cpuid_entries[nent], func, 0, &nent, cpuid->nent);

	r = E2BIG;
	if (nent >= cpuid->nent)
		goto out_free;

	do_cpuid_ent(&cpuid_entries[nent], 0x80000000, 0, &nent, cpuid->nent);
	limit = cpuid_entries[nent - 1].eax;
	for (func = 0x80000001; func <= limit && nent < cpuid->nent; ++func)
		do_cpuid_ent(&cpuid_entries[nent], func, 0, &nent, cpuid->nent);
	r = E2BIG;
	if (nent >= cpuid->nent)
		goto out_free;

	r = EFAULT;
	if (copyout(cpuid_entries, entries,
	    nent * sizeof (kvm_cpuid_entry2_t)))
		goto out_free;

	cpuid->nent = nent;
	r = 0;

out_free:
	kmem_free(cpuid_entries, allocsize);
out:
	return (r);
}

int
kvm_vcpu_ioctl_get_lapic(struct kvm_vcpu *vcpu, struct kvm_lapic_state *s)
{
	vcpu_load(vcpu);
	bcopy(vcpu->arch.apic->regs, s->regs, sizeof (*s));
	vcpu_put(vcpu);

	return (0);
}

int
kvm_vcpu_ioctl_set_lapic(struct kvm_vcpu *vcpu, struct kvm_lapic_state *s)
{
	vcpu_load(vcpu);
	bcopy(s->regs, vcpu->arch.apic->regs, sizeof (*s));
	kvm_apic_post_state_restore(vcpu);
	update_cr8_intercept(vcpu);
	vcpu_put(vcpu);

	return (0);
}

int
kvm_vcpu_ioctl_interrupt(struct kvm_vcpu *vcpu, struct kvm_interrupt *irq)
{
	if (irq->irq < 0 || irq->irq >= 256)
		return (-EINVAL);

	if (irqchip_in_kernel(vcpu->kvm))
		return (-ENXIO);

	vcpu_load(vcpu);

	kvm_queue_interrupt(vcpu, irq->irq, 0);

	vcpu_put(vcpu);

	return (0);
}

int
kvm_vcpu_ioctl_nmi(struct kvm_vcpu *vcpu)
{
	vcpu_load(vcpu);
	kvm_inject_nmi(vcpu);
	vcpu_put(vcpu);

	return (0);
}

int
kvm_vcpu_ioctl_x86_setup_mce(struct kvm_vcpu *vcpu, uint64_t *mcg_capp)
{
	int rval;
	uint64_t mcg_cap = *mcg_capp;
	unsigned bank_num = mcg_cap & 0xff, bank;

	vcpu_load(vcpu);
	rval = -EINVAL;
	if (!bank_num || bank_num >= KVM_MAX_MCE_BANKS)
		goto out;
	if (mcg_cap & ~(KVM_MCE_CAP_SUPPORTED | 0xff | 0xff0000))
		goto out;
	rval = 0;
	vcpu->arch.mcg_cap = mcg_cap;
	/* Init IA32_MCG_CTL to all 1s */
	if (mcg_cap & MCG_CTL_P)
		vcpu->arch.mcg_ctl = ~(uint64_t)0;
	/* Init IA32_MCi_CTL to all 1s */
	for (bank = 0; bank < bank_num; bank++)
		vcpu->arch.mce_banks[bank * 4] = ~(uint64_t)0;
out:
	vcpu_put(vcpu);
	return (rval);
}

int
kvm_vcpu_ioctl_x86_get_vcpu_events(struct kvm_vcpu *vcpu,
    struct kvm_vcpu_events *events)
{
	vcpu_load(vcpu);

	events->exception.injected = vcpu->arch.exception.pending;
	events->exception.nr = vcpu->arch.exception.nr;
	events->exception.has_error_code = vcpu->arch.exception.has_error_code;
	events->exception.error_code = vcpu->arch.exception.error_code;

	events->interrupt.injected = vcpu->arch.interrupt.pending;
	events->interrupt.nr = vcpu->arch.interrupt.nr;
	events->interrupt.soft = vcpu->arch.interrupt.soft;

	events->nmi.injected = vcpu->arch.nmi_injected;
	events->nmi.pending = vcpu->arch.nmi_pending;
	events->nmi.masked = kvm_x86_ops->get_nmi_mask(vcpu);

	events->sipi_vector = vcpu->arch.sipi_vector;

	events->flags = (KVM_VCPUEVENT_VALID_NMI_PENDING |
	    KVM_VCPUEVENT_VALID_SIPI_VECTOR);

	vcpu_put(vcpu);

	return (0);
}

int
kvm_vcpu_ioctl_x86_set_vcpu_events(struct kvm_vcpu *vcpu,
    struct kvm_vcpu_events *events)
{
	if (events->flags & ~(KVM_VCPUEVENT_VALID_NMI_PENDING |
	    KVM_VCPUEVENT_VALID_SIPI_VECTOR))
		return (-EINVAL);

	vcpu_load(vcpu);

	vcpu->arch.exception.pending = events->exception.injected;
	vcpu->arch.exception.nr = events->exception.nr;
	vcpu->arch.exception.has_error_code = events->exception.has_error_code;
	vcpu->arch.exception.error_code = events->exception.error_code;

	vcpu->arch.interrupt.pending = events->interrupt.injected;
	vcpu->arch.interrupt.nr = events->interrupt.nr;
	vcpu->arch.interrupt.soft = events->interrupt.soft;

	if (vcpu->arch.interrupt.pending && irqchip_in_kernel(vcpu->kvm))
		kvm_pic_clear_isr_ack(vcpu->kvm);

	vcpu->arch.nmi_injected = events->nmi.injected;

	if (events->flags & KVM_VCPUEVENT_VALID_NMI_PENDING)
		vcpu->arch.nmi_pending = events->nmi.pending;

	kvm_x86_ops->set_nmi_mask(vcpu, events->nmi.masked);

	if (events->flags & KVM_VCPUEVENT_VALID_SIPI_VECTOR)
		vcpu->arch.sipi_vector = events->sipi_vector;

	vcpu_put(vcpu);

	return (0);
}

int
kvm_vm_ioctl_set_tss_addr(struct kvm *kvmp, uintptr_t addr)
{
	return (kvm_x86_ops->set_tss_addr(kvmp, addr));
}

int
kvm_vm_ioctl_set_identity_map_addr(struct kvm *kvm, uint64_t ident_addr)
{
	kvm->arch.ept_identity_map_addr = ident_addr;
	return (0);
}

gfn_t
unalias_gfn_instantiation(struct kvm *kvm, gfn_t gfn)
{
	int i;
	struct kvm_mem_alias *alias;
	struct kvm_mem_aliases *aliases;
#ifdef XXX
	aliases = rcu_dereference(kvm->arch.aliases);
#else
	XXX_KVM_SYNC_PROBE;
	aliases = kvm->arch.aliases;
#endif

	for (i = 0; i < aliases->naliases; i++) {
		alias = &aliases->aliases[i];
		if (alias->flags & KVM_ALIAS_INVALID)
			continue;
		if (gfn >= alias->base_gfn &&
		    gfn < alias->base_gfn + alias->npages)
			return (alias->target_gfn + gfn - alias->base_gfn);
	}

	return (gfn);
}

gfn_t
unalias_gfn(struct kvm *kvm, gfn_t gfn)
{
	int i;
	struct kvm_mem_alias *alias;
	struct kvm_mem_aliases *aliases;

	/* XXX need protection */
	aliases = kvm->arch.aliases;

	for (i = 0; i < aliases->naliases; ++i) {
		alias = &aliases->aliases[i];
		if (gfn >= alias->base_gfn &&
		    gfn < alias->base_gfn + alias->npages)
			return (alias->target_gfn + gfn - alias->base_gfn);
	}
	return (gfn);
}

int
kvm_vm_ioctl_get_irqchip(struct kvm *kvm, struct kvm_irqchip *chip)
{
	int r;

	r = 0;
	switch (chip->chip_id) {
	case KVM_IRQCHIP_PIC_MASTER:
		memcpy(&chip->chip.pic, &pic_irqchip(kvm)->pics[0],
		    sizeof (struct kvm_pic_state));
		break;
	case KVM_IRQCHIP_PIC_SLAVE:
		memcpy(&chip->chip.pic, &pic_irqchip(kvm)->pics[1],
		    sizeof (struct kvm_pic_state));
		break;
	case KVM_IRQCHIP_IOAPIC:
		r = kvm_get_ioapic(kvm, &chip->chip.ioapic);
		break;
	default:
		r = EINVAL;
		break;
	}

	return (r);
}

int
kvm_vm_ioctl_set_irqchip(struct kvm *kvm, struct kvm_irqchip *chip)
{
	int r;

	r = 0;

	switch (chip->chip_id) {
	case KVM_IRQCHIP_PIC_MASTER:
		mutex_enter(&pic_irqchip(kvm)->lock);
		memcpy(&pic_irqchip(kvm)->pics[0], &chip->chip.pic,
		    sizeof (struct kvm_pic_state));
		mutex_exit(&pic_irqchip(kvm)->lock);
		break;
	case KVM_IRQCHIP_PIC_SLAVE:
		mutex_enter(&pic_irqchip(kvm)->lock);
		memcpy(&pic_irqchip(kvm)->pics[1], &chip->chip.pic,
		    sizeof (struct kvm_pic_state));
		mutex_exit(&pic_irqchip(kvm)->lock);
		break;
	case KVM_IRQCHIP_IOAPIC:
		r = kvm_set_ioapic(kvm, &chip->chip.ioapic);
		break;
	default:
		r = EINVAL;
		break;
	}

	kvm_pic_update_irq(pic_irqchip(kvm));

	return (r);
}

int
kvm_vm_ioctl_get_pit2(struct kvm *kvm, struct kvm_pit_state2 *ps)
{
	struct kvm_pit *vpit = kvm->arch.vpit;

	mutex_enter(&vpit->pit_state.lock);
	memcpy(ps->channels, &vpit->pit_state.channels, sizeof (ps->channels));
	ps->flags = vpit->pit_state.flags;
	mutex_exit(&vpit->pit_state.lock);

	return (0);
}

int
kvm_vm_ioctl_set_pit2(struct kvm *kvm, struct kvm_pit_state2 *ps)
{
	boolean_t prev_legacy, cur_legacy, start = B_FALSE;
	struct kvm_pit *vpit = kvm->arch.vpit;

	mutex_enter(&vpit->pit_state.lock);
	prev_legacy = vpit->pit_state.flags & KVM_PIT_FLAGS_HPET_LEGACY;
	cur_legacy = ps->flags & KVM_PIT_FLAGS_HPET_LEGACY;

	if (!prev_legacy && cur_legacy)
		start = B_TRUE;

	memcpy(&vpit->pit_state.channels, &ps->channels,
	    sizeof (vpit->pit_state.channels));

	vpit->pit_state.flags = ps->flags;
	kvm_pit_load_count(kvm, 0, vpit->pit_state.channels[0].count, start);

	mutex_exit(&vpit->pit_state.lock);

	return (0);
}

/* TODO: As Pascal would say, we can do better */
int
kvm_vm_ioctl_get_msr_index_list(struct kvm *kvm, uintptr_t arg)
{

	struct kvm_msr_list *user_msr_list = (struct kvm_msr_list *)arg;
	struct kvm_msr_list *msr_list;
	size_t sz = sizeof (struct kvm_msr_list);
	unsigned n;

	msr_list = kmem_zalloc(sz, KM_SLEEP);

	if (copyin(user_msr_list, msr_list, sz) != 0) {
		kmem_free(msr_list, sz);
		return (EFAULT);
	}

	n = msr_list->nmsrs;
	msr_list->nmsrs = num_msrs_to_save + ARRAY_SIZE(emulated_msrs);

	if (copyout(msr_list, user_msr_list, sz) != 0) {
		kmem_free(msr_list, sz);
		return (EFAULT);
	}

	if (n < msr_list->nmsrs) {
		kmem_free(msr_list, sz);
		return (E2BIG);
	}

	if (copyout(&msrs_to_save, user_msr_list->indices,
	    num_msrs_to_save * sizeof (uint32_t))) {
		kmem_free(msr_list, sz);
		return (EFAULT);
	}

	if (copyout(&emulated_msrs, user_msr_list->indices +
	    num_msrs_to_save, ARRAY_SIZE(emulated_msrs) *
	    sizeof (uint32_t)) != 0) {
		kmem_free(msr_list, sz);
		return (EFAULT);
	}

	kmem_free(msr_list, sz);

	return (0);
}

/*
 * Get (and clear) the dirty memory log for a memory slot.
 */
int
kvm_vm_ioctl_get_dirty_log(struct kvm *kvm, struct kvm_dirty_log *log)
{
	int r, i;
	struct kvm_memory_slot *memslot;
	unsigned long n;
	unsigned long is_dirty = 0;
	unsigned long *dirty_bitmap = NULL;

	mutex_enter(&kvm->slots_lock);

	r = EINVAL;
	if (log->slot >= KVM_MEMORY_SLOTS)
		goto out;

	memslot = &kvm->memslots->memslots[log->slot];
	r = ENOENT;
	if (!memslot->dirty_bitmap)
		goto out;

	n = kvm_dirty_bitmap_bytes(memslot);

	dirty_bitmap = kmem_alloc(n, KM_SLEEP);
	memset(dirty_bitmap, 0, n);

	for (i = 0; !is_dirty && i < n / sizeof (long); i++)
		is_dirty = memslot->dirty_bitmap[i];

	/* If nothing is dirty, don't bother messing with page tables. */
	if (is_dirty) {
		struct kvm_memslots *slots, *old_slots;

		mutex_enter(&kvm->mmu_lock);
		kvm_mmu_slot_remove_write_access(kvm, log->slot);
		mutex_exit(&kvm->mmu_lock);

		slots = kmem_zalloc(sizeof (struct kvm_memslots), KM_SLEEP);
		if (!slots)
			goto out_free;

		memcpy(slots, kvm->memslots, sizeof (struct kvm_memslots));
		slots->memslots[log->slot].dirty_bitmap = dirty_bitmap;

		mutex_enter(&kvm->memslots_lock);
		old_slots = kvm->memslots;
		kvm->memslots = slots;
		mutex_exit(&kvm->memslots_lock);
		dirty_bitmap = old_slots->memslots[log->slot].dirty_bitmap;
		kmem_free(old_slots, sizeof (struct kvm_memslots));
	}

	r = 0;
	if (copyout(dirty_bitmap, log->dirty_bitmap, n) != 0)
		r = EFAULT;
out_free:
	kmem_free(dirty_bitmap, n);
out:
	mutex_exit(&kvm->slots_lock);
	return (r);
}

static void
kvm_init_msr_list(void)
{
	uint32_t dummy[2];
	unsigned i, j;

	/* skip the first msrs in the list. KVM-specific */
	for (i = j = KVM_SAVE_MSRS_BEGIN; i < ARRAY_SIZE(msrs_to_save); i++) {
		if (rdmsr_safe(msrs_to_save[i], &dummy[0], &dummy[1]) < 0)
			continue;
		if (j < i)
			msrs_to_save[j] = msrs_to_save[i];
		j++;
	}
	num_msrs_to_save = j;
}

static int
vcpu_mmio_write(struct kvm_vcpu *vcpu, gpa_t addr, int len, const void *v)
{
	if (vcpu->arch.apic &&
	    !kvm_iodevice_write(&vcpu->arch.apic->dev, addr, len, v))
		return (0);

	return (kvm_io_bus_write(vcpu->kvm, KVM_MMIO_BUS, addr, len, v));
}

static int
vcpu_mmio_read(struct kvm_vcpu *vcpu, gpa_t addr, int len, void *v)
{
	if (vcpu->arch.apic &&
	    !kvm_iodevice_read(&vcpu->arch.apic->dev, addr, len, v))
		return (0);

	return (kvm_io_bus_read(vcpu->kvm, KVM_MMIO_BUS, addr, len, v));
}

gpa_t
kvm_mmu_gva_to_gpa_read(struct kvm_vcpu *vcpu, gva_t gva, uint32_t *error)
{
	uint32_t access = (kvm_x86_ops->get_cpl(vcpu) == 3) ?
	    PFERR_USER_MASK : 0;

	return (vcpu->arch.mmu.gva_to_gpa(vcpu, gva, access, error));
}

gpa_t
kvm_mmu_gva_to_gpa_write(struct kvm_vcpu *vcpu, gva_t gva, uint32_t *error)
{
	uint32_t access = (kvm_x86_ops->get_cpl(vcpu) == 3) ?
	    PFERR_USER_MASK : 0;

	access |= PFERR_WRITE_MASK;

	return (vcpu->arch.mmu.gva_to_gpa(vcpu, gva, access, error));
}

/* used for instruction fetching */
static int
kvm_fetch_guest_virt(gva_t addr, void *val, unsigned int bytes,
    struct kvm_vcpu *vcpu, uint32_t *error)
{
	uint32_t access = (kvm_x86_ops->get_cpl(vcpu) == 3) ?
	    PFERR_USER_MASK : 0;

	return (kvm_read_guest_virt_helper(addr, val, bytes, vcpu,
	    access | PFERR_FETCH_MASK, error));
}

static int
kvm_read_guest_virt(gva_t addr, void *val, unsigned int bytes,
    struct kvm_vcpu *vcpu, uint32_t *error)
{
	uint32_t access = (kvm_x86_ops->get_cpl(vcpu) == 3) ?
	    PFERR_USER_MASK : 0;

	return (kvm_read_guest_virt_helper(addr, val,
	    bytes, vcpu, access, error));
}

static int
kvm_read_guest_virt_system(gva_t addr, void *val, unsigned int bytes,
    struct kvm_vcpu *vcpu, uint32_t *error)
{
	return (kvm_read_guest_virt_helper(addr, val, bytes, vcpu, 0, error));
}

static int
kvm_write_guest_virt(gva_t addr, void *val, unsigned int bytes,
    struct kvm_vcpu *vcpu, uint32_t *error)
{
	uintptr_t data = (uintptr_t)val;

	while (bytes) {
		gpa_t gpa = kvm_mmu_gva_to_gpa_write(vcpu, addr, error);
		unsigned offset = addr & (PAGESIZE-1);
		unsigned towrite = min(bytes, (unsigned)PAGESIZE - offset);
		int ret;

		if (gpa == UNMAPPED_GVA)
			return (X86EMUL_PROPAGATE_FAULT);

		if (kvm_write_guest(vcpu->kvm, gpa, (void *)data, towrite) < 0)
			return (X86EMUL_UNHANDLEABLE);

		bytes -= towrite;
		data += towrite;
		addr += towrite;
	}

	return (0);
}

static int
emulator_read_emulated(unsigned long addr, void *val,
    unsigned int bytes, struct kvm_vcpu *vcpu)
{
	gpa_t gpa;
	uint32_t error_code;

	if (vcpu->mmio_read_completed) {
		memcpy(val, vcpu->mmio_data, bytes);
		KVM_TRACE3(mmio__read, unsigned int, bytes, uintptr_t,
		    vcpu->mmio_phys_addr, uint64_t, *(uint64_t *)val);

		vcpu->mmio_read_completed = 0;
		return (X86EMUL_CONTINUE);
	}

	gpa = kvm_mmu_gva_to_gpa_read(vcpu, addr, &error_code);

	if (gpa == UNMAPPED_GVA) {
		kvm_inject_page_fault(vcpu, addr, error_code);
		return (X86EMUL_PROPAGATE_FAULT);
	}

	/* For APIC access vmexit */
	if ((gpa & PAGEMASK) == APIC_DEFAULT_PHYS_BASE)
		goto mmio;

	if (kvm_read_guest_virt(addr, val,
	    bytes, vcpu, NULL) == X86EMUL_CONTINUE)
		return (X86EMUL_CONTINUE);

mmio:
	/*
	 * Is this MMIO handled locally?
	 */
	if (!vcpu_mmio_read(vcpu, gpa, bytes, val)) {
		KVM_TRACE3(mmio__read, unsigned int, bytes, uintptr_t, gpa,
		    uint64_t, *(uint64_t *)val);
		return (X86EMUL_CONTINUE);
	}

	KVM_TRACE2(mmio__read__unsatisfied, unsigned int, bytes,
	    uintptr_t, gpa);

	vcpu->mmio_needed = 1;
	vcpu->mmio_phys_addr = gpa;
	vcpu->mmio_size = bytes;
	vcpu->mmio_is_write = 0;

	return (X86EMUL_UNHANDLEABLE);
}

int
emulator_write_phys(struct kvm_vcpu *vcpu, gpa_t gpa,
    const void *val, int bytes)
{
	int ret;

	ret = kvm_write_guest(vcpu->kvm, gpa, val, bytes);

	if (ret < 0)
		return (0);

	kvm_mmu_pte_write(vcpu, gpa, val, bytes, 1);

	return (1);
}

static int
emulator_write_emulated_onepage(unsigned long addr, const void *val,
    unsigned int bytes, struct kvm_vcpu *vcpu)
{
	gpa_t gpa;
	uint32_t error_code;

	gpa = kvm_mmu_gva_to_gpa_write(vcpu, addr, &error_code);

	if (gpa == UNMAPPED_GVA) {
		kvm_inject_page_fault(vcpu, addr, error_code);
		return (X86EMUL_PROPAGATE_FAULT);
	}

	/* For APIC access vmexit */
	if ((gpa & PAGEMASK) == APIC_DEFAULT_PHYS_BASE)
		goto mmio;

	if (emulator_write_phys(vcpu, gpa, val, bytes))
		return (X86EMUL_CONTINUE);

mmio:
	KVM_TRACE3(mmio__write, unsigned int, bytes, uintptr_t, gpa,
	    uint64_t, *(uint64_t *)val);

	/*
	 * Is this MMIO handled locally?
	 */
	if (!vcpu_mmio_write(vcpu, gpa, bytes, val))
		return (X86EMUL_CONTINUE);

	vcpu->mmio_needed = 1;
	vcpu->mmio_phys_addr = gpa;
	vcpu->mmio_size = bytes;
	vcpu->mmio_is_write = 1;
	memcpy(vcpu->mmio_data, val, bytes);

	return (X86EMUL_CONTINUE);
}

int
emulator_write_emulated(unsigned long addr, const void *val,
    unsigned int bytes, struct kvm_vcpu *vcpu)
{
	uintptr_t data = (uintptr_t)val;

	/* Crossing a page boundary? */
	if (((addr + bytes - 1) ^ addr) & PAGEMASK) {
		int rc, now;

		now = -addr & ~PAGEMASK;
		rc = emulator_write_emulated_onepage(addr,
		    (void *)data, now, vcpu);

		if (rc != X86EMUL_CONTINUE)
			return (rc);

		addr += now;
		data += now;
		bytes -= now;
	}

	return (emulator_write_emulated_onepage(addr, val, bytes, vcpu));
}

static int
emulator_cmpxchg_emulated(unsigned long addr, const void *old,
    const void *new, unsigned int bytes, struct kvm_vcpu *vcpu)
{
	cmn_err(CE_WARN, "kvm: emulating exchange as write\n");
	return (emulator_write_emulated(addr, new, bytes, vcpu));
}

static unsigned long
get_segment_base(struct kvm_vcpu *vcpu, int seg)
{
	return (kvm_x86_ops->get_segment_base(vcpu, seg));
}

void
kvm_report_emulation_failure(struct kvm_vcpu *vcpu, const char *context)
{
	uint64_t ops, ctx = (uint64_t)context;
	unsigned long rip = kvm_rip_read(vcpu);
	unsigned long rip_linear;

	rip_linear = rip + get_segment_base(vcpu, VCPU_SREG_CS);

	kvm_read_guest_virt(rip_linear, &ops, 8, vcpu, NULL);

	kvm_ringbuf_record(&vcpu->kvcpu_ringbuf, KVM_RINGBUF_TAG_EMUFAIL0, ctx);
	kvm_ringbuf_record(&vcpu->kvcpu_ringbuf, KVM_RINGBUF_TAG_EMUFAIL1, rip);
	kvm_ringbuf_record(&vcpu->kvcpu_ringbuf, KVM_RINGBUF_TAG_EMUFAIL2, ops);
}

static struct x86_emulate_ops emulate_ops = {
	.read_std		= kvm_read_guest_virt_system,
	.fetch			= kvm_fetch_guest_virt,
	.read_emulated		= emulator_read_emulated,
	.write_emulated		= emulator_write_emulated,
	.cmpxchg_emulated	= emulator_cmpxchg_emulated,
};

static void
cache_all_regs(struct kvm_vcpu *vcpu)
{
	kvm_register_read(vcpu, VCPU_REGS_RAX);
	kvm_register_read(vcpu, VCPU_REGS_RSP);
	kvm_register_read(vcpu, VCPU_REGS_RIP);
	vcpu->arch.regs_dirty = ~0;
}

int
emulate_instruction(struct kvm_vcpu *vcpu, unsigned long cr2,
    uint16_t error_code, int emulation_type)
{
	int r, shadow_mask;
	struct decode_cache *c;
	struct kvm_run *run = vcpu->run;
	char *ctx = NULL;

	kvm_clear_exception_queue(vcpu);
	vcpu->arch.mmio_fault_cr2 = cr2;

	/*
	 * TODO: fix emulate.c to use guest_read/write_register
	 * instead of direct ->regs accesses, can save hundred cycles
	 * on Intel for instructions that don't read/change RSP, for
	 * for example.
	 */
	cache_all_regs(vcpu);

	vcpu->mmio_is_write = 0;
	vcpu->arch.pio.string = 0;

	if (!(emulation_type & EMULTYPE_NO_DECODE)) {
		int cs_db, cs_l;
		kvm_x86_ops->get_cs_db_l_bits(vcpu, &cs_db, &cs_l);

		vcpu->arch.emulate_ctxt.vcpu = vcpu;
		vcpu->arch.emulate_ctxt.eflags = kvm_get_rflags(vcpu);
		vcpu->arch.emulate_ctxt.mode = (!is_protmode(vcpu)) ?
		    X86EMUL_MODE_REAL :
		    (vcpu->arch.emulate_ctxt.eflags & X86_EFLAGS_VM) ?
		    X86EMUL_MODE_VM86 : cs_l ? X86EMUL_MODE_PROT64 :
		    cs_db ? X86EMUL_MODE_PROT32 : X86EMUL_MODE_PROT16;

		r = x86_decode_insn(&vcpu->arch.emulate_ctxt, &emulate_ops);

		/*
		 * Only allow emulation of specific instructions on #UD
		 * (namely VMMCALL, sysenter, sysexit, syscall)
		 */
		c = &vcpu->arch.emulate_ctxt.decode;
		if (emulation_type & EMULTYPE_TRAP_UD) {
			if (!c->twobyte) {
				ctx = "non-twobyte";
				goto fail;
			}

			switch (c->b) {
			case 0x01: /* VMMCALL */
				if (c->modrm_mod != 3 || c->modrm_rm != 1) {
					ctx = "vmmcall";
					goto fail;
				}

				break;
			case 0x34: /* sysenter */
			case 0x35: /* sysexit */
				if (c->modrm_mod != 0 || c->modrm_rm != 0) {
					ctx = "sysenter/sysexit";
					goto fail;
				}

				break;
			case 0x05: /* syscall */
				if (c->modrm_mod != 0 || c->modrm_rm != 0) {
					ctx = "syscall";
					goto fail;
				}

				break;
			default:
				ctx = "unknown";
				goto fail;
			}

			if (!(c->modrm_reg == 0 || c->modrm_reg == 3)) {
				ctx = "modcrm";
				goto fail;
			}
		}

		KVM_VCPU_KSTAT_INC(vcpu, kvmvs_insn_emulation);

		if (r)  {
			KVM_VCPU_KSTAT_INC(vcpu, kvmvs_insn_emulation_fail);

			if (kvm_mmu_unprotect_page_virt(vcpu, cr2))
				return (EMULATE_DONE);

			ctx = "decode";
			goto fail;
		}
	}

	if (emulation_type & EMULTYPE_SKIP) {
		kvm_rip_write(vcpu, vcpu->arch.emulate_ctxt.decode.eip);
		return (EMULATE_DONE);
	}

	r = x86_emulate_insn(&vcpu->arch.emulate_ctxt, &emulate_ops);
	shadow_mask = vcpu->arch.emulate_ctxt.interruptibility;

	if (r == 0)
		kvm_x86_ops->set_interrupt_shadow(vcpu, shadow_mask);

	if (vcpu->arch.pio.string)
		return (EMULATE_DO_MMIO);

	if ((r || vcpu->mmio_is_write) && run) {
		run->exit_reason = KVM_EXIT_MMIO;
		run->mmio.phys_addr = vcpu->mmio_phys_addr;
		memcpy(run->mmio.data, vcpu->mmio_data, 8);
		run->mmio.len = vcpu->mmio_size;
		run->mmio.is_write = vcpu->mmio_is_write;
	}

	if (r) {
		if (kvm_mmu_unprotect_page_virt(vcpu, cr2))
			return (EMULATE_DONE);

		if (!vcpu->mmio_needed) {
			ctx = "mmio";
			goto fail;
		}

		return (EMULATE_DO_MMIO);
	}

	kvm_set_rflags(vcpu, vcpu->arch.emulate_ctxt.eflags);

	if (vcpu->mmio_is_write) {
		vcpu->mmio_needed = 0;
		return (EMULATE_DO_MMIO);
	}

	return (EMULATE_DONE);

fail:
	kvm_report_emulation_failure(vcpu, ctx != NULL ? ctx : "????");
	return (EMULATE_FAIL);
}

static int
pio_copy_data(struct kvm_vcpu *vcpu)
{
	void *p = vcpu->arch.pio_data;
	gva_t q = vcpu->arch.pio.guest_gva;
	unsigned bytes;
	int ret;
	uint32_t error_code;

	bytes = vcpu->arch.pio.size * vcpu->arch.pio.cur_count;

	if (vcpu->arch.pio.in)
		ret = kvm_write_guest_virt(q, p, bytes, vcpu, &error_code);
	else
		ret = kvm_read_guest_virt(q, p, bytes, vcpu, &error_code);

	if (ret == X86EMUL_PROPAGATE_FAULT)
		kvm_inject_page_fault(vcpu, q, error_code);

	return (ret);
}

int
complete_pio(struct kvm_vcpu *vcpu)
{
	struct kvm_pio_request *io = &vcpu->arch.pio;
	long delta;
	int r;
	unsigned long val;

	if (!io->string) {
		if (io->in) {
			val = kvm_register_read(vcpu, VCPU_REGS_RAX);
			memcpy(&val, vcpu->arch.pio_data, io->size);
			kvm_register_write(vcpu, VCPU_REGS_RAX, val);
		}
	} else {
		if (io->in) {
			r = pio_copy_data(vcpu);
			if (r)
				goto out;
		}

		delta = 1;
		if (io->rep) {
			delta *= io->cur_count;
			/*
			 * The size of the register should really depend on
			 * current address size.
			 */
			val = kvm_register_read(vcpu, VCPU_REGS_RCX);
			val -= delta;
			kvm_register_write(vcpu, VCPU_REGS_RCX, val);
		}
		if (io->down)
			delta = -delta;
		delta *= io->size;
		if (io->in) {
			val = kvm_register_read(vcpu, VCPU_REGS_RDI);
			val += delta;
			kvm_register_write(vcpu, VCPU_REGS_RDI, val);
		} else {
			val = kvm_register_read(vcpu, VCPU_REGS_RSI);
			val += delta;
			kvm_register_write(vcpu, VCPU_REGS_RSI, val);
		}
	}
out:
	io->count -= io->cur_count;
	io->cur_count = 0;

	return (0);
}

static int
kernel_pio(struct kvm_vcpu *vcpu, void *pd)
{
	/* TODO: String I/O for in kernel device */
	int r;

	if (vcpu->arch.pio.in) {
		r = kvm_io_bus_read(vcpu->kvm, KVM_PIO_BUS, vcpu->arch.pio.port,
		    vcpu->arch.pio.size, pd);
	} else {
		r = kvm_io_bus_write(vcpu->kvm, KVM_PIO_BUS,
		    vcpu->arch.pio.port, vcpu->arch.pio.size, pd);
	}

	return (r);
}

int
kvm_emulate_pio(struct kvm_vcpu *vcpu, int in, int size, unsigned port)
{
	unsigned long val;

	DTRACE_PROBE4(kvm__pio, int, !in, unsigned, port, int, size,
	    unsigned long, 1)

	vcpu->run->exit_reason = KVM_EXIT_IO;
	vcpu->run->io.direction = in ? KVM_EXIT_IO_IN : KVM_EXIT_IO_OUT;
	vcpu->run->io.size = vcpu->arch.pio.size = size;
	vcpu->run->io.data_offset = KVM_PIO_PAGE_OFFSET * PAGESIZE;
	vcpu->run->io.count = vcpu->arch.pio.count =
	    vcpu->arch.pio.cur_count = 1;
	vcpu->run->io.port = vcpu->arch.pio.port = port;
	vcpu->arch.pio.in = in;
	vcpu->arch.pio.string = 0;
	vcpu->arch.pio.down = 0;
	vcpu->arch.pio.rep = 0;

	if (!vcpu->arch.pio.in) {
		val = kvm_register_read(vcpu, VCPU_REGS_RAX);
		memcpy(vcpu->arch.pio_data, &val, 4);
	}

	if (!kernel_pio(vcpu, vcpu->arch.pio_data)) {
		complete_pio(vcpu);
		return (1);
	}

	return (0);
}

void
kvm_timer_fire(void *arg)
{
	struct kvm_timer *timer = (struct kvm_timer *)arg;
	struct kvm_vcpu *vcpu = timer->vcpu;

	if (vcpu == NULL)
		return;

	mutex_enter(&vcpu->kvcpu_kick_lock);

	if (timer->reinject || !timer->pending) {
		atomic_add_32((volatile uint32_t *)&timer->pending, 1);
		set_bit(KVM_REQ_PENDING_TIMER, &vcpu->requests);
	}

	timer->intervals++;

	cv_broadcast(&vcpu->kvcpu_kick_cv);
	mutex_exit(&vcpu->kvcpu_kick_lock);
}

static void
kvm_timer_init(void)
{
	int cpu;

	/*
	 * We assume a constant time stamp counter increment rate, which
	 * is true for all CPUs that support hardware virtualization
	 * extensions.
	 */
	cpu_tsc_khz = (cpu_freq_hz / 1000);
}

int
kvm_arch_init(void *opaque)
{
	int r;
	struct kvm_x86_ops *ops = (struct kvm_x86_ops *)opaque;

	if (ops->cpu_has_kvm_support()) {
		cmn_err(CE_WARN, "kvm: no hardware support\n");
		r = ENOTSUP;
		goto out;
	}
	if (ops->disabled_by_bios()) {
		cmn_err(CE_WARN, "kvm: disabled by bios\n");
		r = ENOTSUP;
		goto out;
	}

	r = kvm_mmu_module_init();
	if (r)
		goto out;

	kvm_init_msr_list();

	kvm_x86_ops = ops;
	kvm_mmu_set_nonpresent_ptes(0ull, 0ull);
	kvm_mmu_set_base_ptes(PT_PRESENT_MASK);
	kvm_mmu_set_mask_ptes(PT_USER_MASK, PT_ACCESSED_MASK,
	    PT_DIRTY_MASK, PT64_NX_MASK, 0);

	kvm_timer_init();

	return (0);

out:
	return (r);
}

int
kvm_emulate_halt(struct kvm_vcpu *vcpu)
{
	KVM_VCPU_KSTAT_INC(vcpu, kvmvs_halt_exits);

	if (irqchip_in_kernel(vcpu->kvm)) {
		vcpu->arch.mp_state = KVM_MP_STATE_HALTED;
		return (1);
	} else {
		vcpu->run->exit_reason = KVM_EXIT_HLT;
		return (0);
	}
}

int
kvm_hv_hypercall(struct kvm_vcpu *vcpu)
{
	uint64_t param, ingpa, outgpa, ret;
	uint16_t code, rep_idx, rep_cnt, res = HV_STATUS_SUCCESS, rep_done = 0;
	int fast, longmode;
	int cs_db, cs_l;

	/*
	 * hypercall generates UD from non zero cpl and real mode
	 * per HYPER-V spec
	 */
	if (kvm_x86_ops->get_cpl(vcpu) != 0 || !is_protmode(vcpu)) {
		kvm_queue_exception(vcpu, UD_VECTOR);
		return (0);
	}

	kvm_x86_ops->get_cs_db_l_bits(vcpu, &cs_db, &cs_l);
	longmode = is_long_mode(vcpu) && cs_l == 1;

	if (!longmode) {
		param = ((uint64_t)kvm_register_read(vcpu,
		    VCPU_REGS_RDX) << 32) | (kvm_register_read(vcpu,
		    VCPU_REGS_RAX) & 0xffffffff);

		ingpa = ((uint64_t)kvm_register_read(vcpu,
		    VCPU_REGS_RBX) << 32) | (kvm_register_read(vcpu,
		    VCPU_REGS_RCX) & 0xffffffff);

		outgpa = ((uint64_t)kvm_register_read(vcpu,
		    VCPU_REGS_RDI) << 32) | (kvm_register_read(vcpu,
		    VCPU_REGS_RSI) & 0xffffffff);
	} else {
		param = kvm_register_read(vcpu, VCPU_REGS_RCX);
		ingpa = kvm_register_read(vcpu, VCPU_REGS_RDX);
		outgpa = kvm_register_read(vcpu, VCPU_REGS_R8);
	}

	code = param & 0xffff;
	fast = (param >> 16) & 0x1;
	rep_cnt = (param >> 32) & 0xfff;
	rep_idx = (param >> 48) & 0xfff;

	KVM_TRACE6(hv__hypercall, uintptr_t, code, uintptr_t, fast,
	    uintptr_t, rep_cnt, uintptr_t, rep_idx, uintptr_t, ingpa,
	    uintptr_t, outgpa);

	switch (code) {
	case HV_X64_HV_NOTIFY_LONG_SPIN_WAIT:
#ifdef XXX
		kvm_vcpu_on_spin(vcpu);
#else
		XXX_KVM_PROBE;
#endif
		break;
	default:
		res = HV_STATUS_INVALID_HYPERCALL_CODE;
		break;
	}

	ret = res | (((uint64_t)rep_done & 0xfff) << 32);

	if (longmode) {
		kvm_register_write(vcpu, VCPU_REGS_RAX, ret);
	} else {
		kvm_register_write(vcpu, VCPU_REGS_RDX, ret >> 32);
		kvm_register_write(vcpu, VCPU_REGS_RAX, ret & 0xffffffff);
	}

	return (1);
}

#define	KVM_HC_VAPIC_POLL_IRQ		1
#define	KVM_HC_MMU_OP			2

int
kvm_emulate_hypercall(struct kvm_vcpu *vcpu)
{
	unsigned long nr, a0, a1, a2, a3, ret;
	int r = 1;

	if (kvm_hv_hypercall_enabled(vcpu->kvm))
		return (kvm_hv_hypercall(vcpu));

	nr = kvm_register_read(vcpu, VCPU_REGS_RAX);
	a0 = kvm_register_read(vcpu, VCPU_REGS_RBX);
	a1 = kvm_register_read(vcpu, VCPU_REGS_RCX);
	a2 = kvm_register_read(vcpu, VCPU_REGS_RDX);
	a3 = kvm_register_read(vcpu, VCPU_REGS_RSI);

	KVM_TRACE5(hypercall, uintptr_t, nr, uintptr_t, a0, uintptr_t, a1,
	    uintptr_t, a2, uintptr_t, a3);

	if (!is_long_mode(vcpu)) {
		nr &= 0xFFFFFFFF;
		a0 &= 0xFFFFFFFF;
		a1 &= 0xFFFFFFFF;
		a2 &= 0xFFFFFFFF;
		a3 &= 0xFFFFFFFF;
	}

	if (kvm_x86_ops->get_cpl(vcpu) != 0) {
		ret = -EPERM;
		goto out;
	}

	switch (nr) {
	case KVM_HC_VAPIC_POLL_IRQ:
		ret = 0;
		break;
	case KVM_HC_MMU_OP:
		ret = -ENOSYS;
		break;
	default:
		ret = -ENOSYS;
		break;
	}
out:
	kvm_register_write(vcpu, VCPU_REGS_RAX, ret);

	KVM_VCPU_KSTAT_INC(vcpu, kvmvs_hypercalls);

	return (r);
}

static int
move_to_next_stateful_cpuid_entry(struct kvm_vcpu *vcpu, int i)
{
	struct kvm_cpuid_entry2 *e = &vcpu->arch.cpuid_entries[i];
	int j, nent = vcpu->arch.cpuid_nent;

	e->flags &= ~KVM_CPUID_FLAG_STATE_READ_NEXT;
	/* when no next entry is found, the current entry[i] is reselected */
	for (j = i + 1; ; j = (j + 1) % nent) {
		struct kvm_cpuid_entry2 *ej = &vcpu->arch.cpuid_entries[j];
		if (ej->function == e->function) {
			ej->flags |= KVM_CPUID_FLAG_STATE_READ_NEXT;
			return (j);
		}
	}

	return (0); /* silence gcc, even though control never reaches here */
}

/*
 * find an entry with matching function, matching index (if needed), and that
 * should be read next (if it's stateful)
 */
static int
is_matching_cpuid_entry(struct kvm_cpuid_entry2 *e,
    uint32_t function, uint32_t index)
{
	if (e->function != function)
		return (0);
	if ((e->flags & KVM_CPUID_FLAG_SIGNIFCANT_INDEX) && e->index != index)
		return (0);
	if ((e->flags & KVM_CPUID_FLAG_STATEFUL_FUNC) &&
	    !(e->flags & KVM_CPUID_FLAG_STATE_READ_NEXT))
		return (0);
	return (1);
}

struct kvm_cpuid_entry2 *
kvm_find_cpuid_entry(struct kvm_vcpu *vcpu, uint32_t function, uint32_t index)
{
	int i;
	struct kvm_cpuid_entry2 *best = NULL;

	for (i = 0; i < vcpu->arch.cpuid_nent; ++i) {
		struct kvm_cpuid_entry2 *e;

		e = &vcpu->arch.cpuid_entries[i];
		if (is_matching_cpuid_entry(e, function, index)) {
			if (e->flags & KVM_CPUID_FLAG_STATEFUL_FUNC)
				move_to_next_stateful_cpuid_entry(vcpu, i);
			best = e;
			break;
		}
		/*
		 * Both basic or both extended?
		 */
		if (((e->function ^ function) & 0x80000000) == 0)
			if (!best || e->function > best->function)
				best = e;
	}

	return (best);
}

int
cpuid_maxphyaddr(struct kvm_vcpu *vcpu)
{
	struct kvm_cpuid_entry2 *best;

	if ((best = kvm_find_cpuid_entry(vcpu, 0x80000008, 0)) != NULL)
		return (best->eax & 0xff);

	return (36);
}

void
kvm_emulate_cpuid(struct kvm_vcpu *vcpu)
{
	uint32_t function, index;
	struct kvm_cpuid_entry2 *best;

	function = kvm_register_read(vcpu, VCPU_REGS_RAX);
	index = kvm_register_read(vcpu, VCPU_REGS_RCX);
	kvm_register_write(vcpu, VCPU_REGS_RAX, 0);
	kvm_register_write(vcpu, VCPU_REGS_RBX, 0);
	kvm_register_write(vcpu, VCPU_REGS_RCX, 0);
	kvm_register_write(vcpu, VCPU_REGS_RDX, 0);
	best = kvm_find_cpuid_entry(vcpu, function, index);
	if (best) {
		kvm_register_write(vcpu, VCPU_REGS_RAX, best->eax);
		kvm_register_write(vcpu, VCPU_REGS_RBX, best->ebx);
		kvm_register_write(vcpu, VCPU_REGS_RCX, best->ecx);
		kvm_register_write(vcpu, VCPU_REGS_RDX, best->edx);
	}
	kvm_x86_ops->skip_emulated_instruction(vcpu);
}

static int
dm_request_for_irq_injection(struct kvm_vcpu *vcpu)
{
	return (!irqchip_in_kernel(vcpu->kvm) &&
	    !kvm_cpu_has_interrupt(vcpu) &&
	    vcpu->run->request_interrupt_window &&
	    kvm_arch_interrupt_allowed(vcpu));
}

static void
post_kvm_run_save(struct kvm_vcpu *vcpu)
{
	struct kvm_run *kvm_run = vcpu->run;

	kvm_run->if_flag = (kvm_get_rflags(vcpu) & X86_EFLAGS_IF) != 0;
	kvm_run->cr8 = kvm_get_cr8(vcpu);
	kvm_run->apic_base = kvm_get_apic_base(vcpu);
	if (irqchip_in_kernel(vcpu->kvm))
		kvm_run->ready_for_interrupt_injection = 1;
	else
		kvm_run->ready_for_interrupt_injection =
			kvm_arch_interrupt_allowed(vcpu) &&
			!kvm_cpu_has_interrupt(vcpu) &&
			!kvm_event_needs_reinjection(vcpu);
}

static void
vapic_enter(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;
	page_t *page;

	if (!apic || !apic->vapic_addr)
		return;

	page = gfn_to_page(vcpu->kvm, apic->vapic_addr >> PAGESHIFT);

	vcpu->arch.apic->vapic_page = page;
}

static void
vapic_exit(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;
	int idx;

	if (!apic || !apic->vapic_addr)
		return;

	kvm_release_page_dirty(apic->vapic_page);
	mark_page_dirty(vcpu->kvm, apic->vapic_addr >> PAGESHIFT);
}

static void
update_cr8_intercept(struct kvm_vcpu *vcpu)
{
	int max_irr, tpr;

	if (!kvm_x86_ops->update_cr8_intercept)
		return;

	if (!vcpu->arch.apic)
		return;
	if (!vcpu->arch.apic->vapic_addr)
		max_irr = kvm_lapic_find_highest_irr(vcpu);
	else
		max_irr = -1;

	if (max_irr != -1)
		max_irr >>= 4;
	tpr = kvm_lapic_get_cr8(vcpu);

	kvm_x86_ops->update_cr8_intercept(vcpu, tpr, max_irr);
}

static void
inject_pending_event(struct kvm_vcpu *vcpu)
{
	/* try to reinject previous events if any */
	if (vcpu->arch.exception.pending) {
		kvm_x86_ops->queue_exception(vcpu, vcpu->arch.exception.nr,
		    vcpu->arch.exception.has_error_code,
		    vcpu->arch.exception.error_code);
		return;
	}

	if (vcpu->arch.nmi_injected) {
		kvm_x86_ops->set_nmi(vcpu);
		return;
	}

	if (vcpu->arch.interrupt.pending) {
		kvm_x86_ops->set_irq(vcpu);
		return;
	}

	/* try to inject new event if pending */
	if (vcpu->arch.nmi_pending) {
		if (kvm_x86_ops->nmi_allowed(vcpu)) {
			vcpu->arch.nmi_pending = 0;
			vcpu->arch.nmi_injected = 1;
			kvm_x86_ops->set_nmi(vcpu);
		}
	} else if (kvm_cpu_has_interrupt(vcpu)) {
		if (kvm_x86_ops->interrupt_allowed(vcpu)) {
			kvm_queue_interrupt(vcpu, kvm_cpu_get_interrupt(vcpu),
					    0);
			kvm_x86_ops->set_irq(vcpu);
		}
	}
}

static inline unsigned long
native_get_debugreg(int regno)
{
	unsigned long val = 0;	/* Damn you, gcc! */

	switch (regno) {
	case 0:
		__asm__("mov %%db0, %0" :"=r" (val));
		break;
	case 1:
		__asm__("mov %%db1, %0" :"=r" (val));
		break;
	case 2:
		__asm__("mov %%db2, %0" :"=r" (val));
		break;
	case 3:
		__asm__("mov %%db3, %0" :"=r" (val));
		break;
	case 6:
		__asm__("mov %%db6, %0" :"=r" (val));
		break;
	case 7:
		__asm__("mov %%db7, %0" :"=r" (val));
		break;
	default:
		cmn_err(CE_WARN, "kvm: invalid debug register retrieval, "
		    "regno =  %d\n", regno);
	}

	return (val);
}

static inline void
native_set_debugreg(int regno, unsigned long value)
{
	switch (regno) {
	case 0:
		__asm__("mov %0, %%db0"	::"r" (value));
		break;
	case 1:
		__asm__("mov %0, %%db1"	::"r" (value));
		break;
	case 2:
		__asm__("mov %0, %%db2"	::"r" (value));
		break;
	case 3:
		__asm__("mov %0, %%db3"	::"r" (value));
		break;
	case 6:
		__asm__("mov %0, %%db6"	::"r" (value));
		break;
	case 7:
		__asm__("mov %0, %%db7"	::"r" (value));
		break;
	default:
		cmn_err(CE_WARN, "kvm: invalid debug register set, "
		    "regno =  %d\n", regno);
	}
}

/*
 * These special macros can be used to get or set a debugging register
 */
#define	get_debugreg(var, register)				\
	(var) = native_get_debugreg(register)
#define	set_debugreg(value, register)				\
	native_set_debugreg(register, value)

static int
vcpu_enter_guest(struct kvm_vcpu *vcpu)
{
	int r;
	int req_int_win = !irqchip_in_kernel(vcpu->kvm) &&
	    vcpu->run->request_interrupt_window;

	if (vcpu->requests) {
		if (test_and_clear_bit(KVM_REQ_MMU_RELOAD, &vcpu->requests))
			kvm_mmu_unload(vcpu);
	}

	r = kvm_mmu_reload(vcpu);

	if (r)
		goto out;

	if (vcpu->requests) {
		if (test_and_clear_bit(KVM_REQ_KVMCLOCK_UPDATE,
		    &vcpu->requests)) {
			kvm_write_guest_time(vcpu);
		}

		if (test_and_clear_bit(KVM_REQ_MMU_SYNC, &vcpu->requests))
			kvm_mmu_sync_roots(vcpu);

		if (test_and_clear_bit(KVM_REQ_TLB_FLUSH, &vcpu->requests))
			kvm_x86_ops->tlb_flush(vcpu);

		if (test_and_clear_bit(KVM_REQ_REPORT_TPR_ACCESS,
		    &vcpu->requests)) {
			vcpu->run->exit_reason = KVM_EXIT_TPR_ACCESS;
			r = 0;
			goto out;
		}

		if (test_and_clear_bit(KVM_REQ_TRIPLE_FAULT, &vcpu->requests)) {
			vcpu->run->exit_reason = KVM_EXIT_SHUTDOWN;
			r = 0;
			goto out;
		}

		if (test_and_clear_bit(KVM_REQ_DEACTIVATE_FPU,
		    &vcpu->requests)) {
			vcpu->fpu_active = 0;
			kvm_x86_ops->fpu_deactivate(vcpu);
		}
	}

	/*
	 * There are some narrow circumstances in which the event injection
	 * process might sleep on a lock.  Since its logic does not require
	 * guest-switch preparation or FPU data, complete the injection now
	 * before entering the kpreempt-disabled critical section.
	 */
	inject_pending_event(vcpu);

	kpreempt_disable();
	kvm_x86_ops->prepare_guest_switch(vcpu);
	if (vcpu->fpu_active)
		kvm_load_guest_fpu(vcpu);

	clear_bit(KVM_REQ_KICK, &vcpu->requests);

	if (vcpu->requests || issig(JUSTLOOKING)) {
		set_bit(KVM_REQ_KICK, &vcpu->requests);
		kpreempt_enable();
		r = 1;
		goto out;
	}

	cli();

	if ((r = smt_acquire()) != 1) {
		set_bit(KVM_REQ_KICK, &vcpu->requests);
		sti();
		/*
		 * We were racing for a core against another VM's VCPU thread,
		 * and we lost.  In this case, we want to ask the dispatcher to
		 * migrate us to a core where we have a better chance of winning
		 * smt_acquire().  But unlike bhyve, we don't stay affined
		 * during the whole VCPU operation, so we immediately clear
		 * affinity.
		 */
		if (r == -1) {
			thread_affinity_set(curthread, CPU_BEST);
			thread_affinity_clear(curthread);
		}
		kpreempt_enable();
		r = 1;
		goto out;
	}

	/* enable NMI/IRQ window open exits if needed */
	if (vcpu->arch.nmi_pending)
		kvm_x86_ops->enable_nmi_window(vcpu);
	else if (kvm_cpu_has_interrupt(vcpu) || req_int_win)
		kvm_x86_ops->enable_irq_window(vcpu);

	if (kvm_lapic_enabled(vcpu)) {
		update_cr8_intercept(vcpu);
		kvm_lapic_sync_to_vapic(vcpu);
	}

	kvm_guest_enter(vcpu);

	if (vcpu->arch.switch_db_regs) {
		set_debugreg(0, 7);
		set_debugreg(vcpu->arch.eff_db[0], 0);
		set_debugreg(vcpu->arch.eff_db[1], 1);
		set_debugreg(vcpu->arch.eff_db[2], 2);
		set_debugreg(vcpu->arch.eff_db[3], 3);
	}

	KVM_TRACE1(vm__entry, int, vcpu->vcpu_id);

	kvm_x86_ops->run(vcpu);

	smt_release();

#ifdef XXX
	/*
	 * If the guest has used debug registers, at least dr7
	 * will be disabled while returning to the host.
	 * If we don't have active breakpoints in the host, we don't
	 * care about the messed up debug address registers. But if
	 * we have some of them active, restore the old state.
	 */
	if (hw_breakpoint_active())
		hw_breakpoint_restore();
#else
	XXX_KVM_PROBE;
#endif
	set_bit(KVM_REQ_KICK, &vcpu->requests);

	sti();

	KVM_VCPU_KSTAT_INC(vcpu, kvmvs_exits);
	kvm_guest_exit(vcpu);

	kpreempt_enable();
	kvm_lapic_sync_from_vapic(vcpu);
	r = kvm_x86_ops->handle_exit(vcpu);

out:
	return (r);
}

static int
__vcpu_run(struct kvm_vcpu *vcpu)
{
	int r;
	struct kvm *kvm = vcpu->kvm;

	if (!(curthread->t_schedflag & TS_VCPU))
		smt_mark_as_vcpu();

	if (vcpu->arch.mp_state == KVM_MP_STATE_SIPI_RECEIVED) {
		cmn_err(CE_CONT, "!vcpu %d received sipi with vector # %x\n",
		    vcpu->vcpu_id, vcpu->arch.sipi_vector);
		kvm_lapic_reset(vcpu);
		r = kvm_arch_vcpu_reset(vcpu);
		if (r)
			return (r);
		vcpu->arch.mp_state = KVM_MP_STATE_RUNNABLE;
	}

	vapic_enter(vcpu);

	r = 1;
	while (r > 0) {
		if (vcpu->arch.mp_state == KVM_MP_STATE_RUNNABLE)
			r = vcpu_enter_guest(vcpu);
		else {
			kvm_vcpu_block(vcpu);

			if (test_and_clear_bit(KVM_REQ_UNHALT,
			    &vcpu->requests)) {
				switch (vcpu->arch.mp_state) {
				case KVM_MP_STATE_HALTED:
					vcpu->arch.mp_state =
					    KVM_MP_STATE_RUNNABLE;
				case KVM_MP_STATE_RUNNABLE:
					break;
				case KVM_MP_STATE_SIPI_RECEIVED:
				default:
					r = -EINTR;
					break;
				}
			}
		}

		KVM_TRACE3(vcpu__run, char *, __FILE__, int, __LINE__, int, r);
		if (r <= 0)
			break;

		clear_bit(KVM_REQ_PENDING_TIMER, &vcpu->requests);
		if (kvm_cpu_has_pending_timer(vcpu)) {
			KVM_TRACE3(vcpu__run, char *, __FILE__, int, __LINE__,
			    uint64_t, vcpu);
			kvm_inject_pending_timer_irqs(vcpu);
		}

		if (dm_request_for_irq_injection(vcpu)) {
			r = -EINTR;
			KVM_TRACE3(vcpu__run, char *, __FILE__, int, __LINE__,
			    uint64_t, vcpu);
			vcpu->run->exit_reason = KVM_EXIT_INTR;
			KVM_VCPU_KSTAT_INC(vcpu, kvmvs_irq_exits);
		}

		if (issig(JUSTLOOKING)) {
			r = -EINTR;
			KVM_TRACE3(vcpu__run, char *, __FILE__, int, __LINE__,
			    uint64_t, vcpu);
			vcpu->run->exit_reason = KVM_EXIT_INTR;
			KVM_VCPU_KSTAT_INC(vcpu, kvmvs_signal_exits);
		}
	}

	KVM_TRACE3(vcpu__run, char *, __FILE__, int, __LINE__,
	    uint64_t, vcpu);
	post_kvm_run_save(vcpu);
	vapic_exit(vcpu);

	return (r);
}

int
kvm_arch_vcpu_ioctl_run(struct kvm_vcpu *vcpu)
{
	int r;
	sigset_t sigsaved;
	struct kvm_run *kvm_run = vcpu->run;

	vcpu_load(vcpu);

	if (vcpu->sigset_active)
		kvm_sigprocmask(SIG_SETMASK, &vcpu->sigset, &sigsaved);

	if (vcpu->arch.mp_state == KVM_MP_STATE_UNINITIALIZED) {
		kvm_vcpu_block(vcpu);
		clear_bit(KVM_REQ_UNHALT, &vcpu->requests);
		r = -EAGAIN;
		goto out;
	}

	/* re-sync apic's tpr */
	if (!irqchip_in_kernel(vcpu->kvm))
		kvm_set_cr8(vcpu, kvm_run->cr8);

	if (vcpu->arch.pio.cur_count) {
		if ((r = complete_pio(vcpu)) != 0)
			goto out;
	}

	if (vcpu->mmio_needed) {
		memcpy(vcpu->mmio_data, kvm_run->mmio.data, 8);
		vcpu->mmio_read_completed = 1;
		vcpu->mmio_needed = 0;

		r = emulate_instruction(vcpu,
		    vcpu->arch.mmio_fault_cr2, 0, EMULTYPE_NO_DECODE);

		if (r == EMULATE_DO_MMIO) {
			/*
			 * Read-modify-write.  Back to userspace.
			 */
			r = 0;
			goto out;
		}
	}

	if (kvm_run->exit_reason == KVM_EXIT_HYPERCALL)
		kvm_register_write(vcpu, VCPU_REGS_RAX, kvm_run->hypercall.ret);

	r = __vcpu_run(vcpu);

out:
	if (vcpu->sigset_active)
		kvm_sigprocmask(SIG_SETMASK, &sigsaved, NULL);

	vcpu_put(vcpu);
	return (r);
}

int
kvm_arch_vcpu_ioctl_get_regs(struct kvm_vcpu *vcpu, struct kvm_regs *regs)
{
	vcpu_load(vcpu);

	regs->rax = kvm_register_read(vcpu, VCPU_REGS_RAX);
	regs->rbx = kvm_register_read(vcpu, VCPU_REGS_RBX);
	regs->rcx = kvm_register_read(vcpu, VCPU_REGS_RCX);
	regs->rdx = kvm_register_read(vcpu, VCPU_REGS_RDX);
	regs->rsi = kvm_register_read(vcpu, VCPU_REGS_RSI);
	regs->rdi = kvm_register_read(vcpu, VCPU_REGS_RDI);
	regs->rsp = kvm_register_read(vcpu, VCPU_REGS_RSP);
	regs->rbp = kvm_register_read(vcpu, VCPU_REGS_RBP);
	regs->r8 = kvm_register_read(vcpu, VCPU_REGS_R8);
	regs->r9 = kvm_register_read(vcpu, VCPU_REGS_R9);
	regs->r10 = kvm_register_read(vcpu, VCPU_REGS_R10);
	regs->r11 = kvm_register_read(vcpu, VCPU_REGS_R11);
	regs->r12 = kvm_register_read(vcpu, VCPU_REGS_R12);
	regs->r13 = kvm_register_read(vcpu, VCPU_REGS_R13);
	regs->r14 = kvm_register_read(vcpu, VCPU_REGS_R14);
	regs->r15 = kvm_register_read(vcpu, VCPU_REGS_R15);

	regs->rip = kvm_rip_read(vcpu);
	regs->rflags = kvm_get_rflags(vcpu);

	vcpu_put(vcpu);

	return (0);
}

int
kvm_arch_vcpu_ioctl_set_regs(struct kvm_vcpu *vcpu, struct kvm_regs *regs)
{
	vcpu_load(vcpu);

	kvm_register_write(vcpu, VCPU_REGS_RAX, regs->rax);
	kvm_register_write(vcpu, VCPU_REGS_RBX, regs->rbx);
	kvm_register_write(vcpu, VCPU_REGS_RCX, regs->rcx);
	kvm_register_write(vcpu, VCPU_REGS_RDX, regs->rdx);
	kvm_register_write(vcpu, VCPU_REGS_RSI, regs->rsi);
	kvm_register_write(vcpu, VCPU_REGS_RDI, regs->rdi);
	kvm_register_write(vcpu, VCPU_REGS_RSP, regs->rsp);
	kvm_register_write(vcpu, VCPU_REGS_RBP, regs->rbp);
	kvm_register_write(vcpu, VCPU_REGS_R8, regs->r8);
	kvm_register_write(vcpu, VCPU_REGS_R9, regs->r9);
	kvm_register_write(vcpu, VCPU_REGS_R10, regs->r10);
	kvm_register_write(vcpu, VCPU_REGS_R11, regs->r11);
	kvm_register_write(vcpu, VCPU_REGS_R12, regs->r12);
	kvm_register_write(vcpu, VCPU_REGS_R13, regs->r13);
	kvm_register_write(vcpu, VCPU_REGS_R14, regs->r14);
	kvm_register_write(vcpu, VCPU_REGS_R15, regs->r15);

	kvm_rip_write(vcpu, regs->rip);
	kvm_set_rflags(vcpu, regs->rflags);

	vcpu->arch.exception.pending = 0;

	vcpu_put(vcpu);

	return (0);
}

void
kvm_get_segment(struct kvm_vcpu *vcpu, struct kvm_segment *var, int seg)
{
	kvm_x86_ops->get_segment(vcpu, var, seg);
}

int
kvm_arch_vcpu_ioctl_get_sregs(struct kvm_vcpu *vcpu, struct kvm_sregs *sregs)
{
	struct descriptor_table dt;

	vcpu_load(vcpu);

	kvm_get_segment(vcpu, &sregs->cs, VCPU_SREG_CS);
	kvm_get_segment(vcpu, &sregs->ds, VCPU_SREG_DS);
	kvm_get_segment(vcpu, &sregs->es, VCPU_SREG_ES);
	kvm_get_segment(vcpu, &sregs->fs, VCPU_SREG_FS);
	kvm_get_segment(vcpu, &sregs->gs, VCPU_SREG_GS);
	kvm_get_segment(vcpu, &sregs->ss, VCPU_SREG_SS);

	kvm_get_segment(vcpu, &sregs->tr, VCPU_SREG_TR);
	kvm_get_segment(vcpu, &sregs->ldt, VCPU_SREG_LDTR);

	kvm_x86_ops->get_idt(vcpu, &dt);
	sregs->idt.limit = dt.limit;
	sregs->idt.base = dt.base;
	kvm_x86_ops->get_gdt(vcpu, &dt);
	sregs->gdt.limit = dt.limit;
	sregs->gdt.base = dt.base;

	sregs->cr0 = kvm_read_cr0(vcpu);
	sregs->cr2 = vcpu->arch.cr2;
	sregs->cr3 = vcpu->arch.cr3;
	sregs->cr4 = kvm_read_cr4(vcpu);
	sregs->cr8 = kvm_get_cr8(vcpu);
	sregs->efer = vcpu->arch.efer;
	sregs->apic_base = kvm_get_apic_base(vcpu);

	memset(sregs->interrupt_bitmap, 0, sizeof (sregs->interrupt_bitmap));

	if (vcpu->arch.interrupt.pending && !vcpu->arch.interrupt.soft) {
		set_bit(vcpu->arch.interrupt.nr,
			(unsigned long *)sregs->interrupt_bitmap);
	}

	vcpu_put(vcpu);

	return (0);
}

int
kvm_arch_vcpu_ioctl_get_mpstate(struct kvm_vcpu *vcpu,
    struct kvm_mp_state *mp_state)
{
	vcpu_load(vcpu);
	mp_state->mp_state = vcpu->arch.mp_state;
	vcpu_put(vcpu);
	return (0);
}

int
kvm_arch_vcpu_ioctl_set_mpstate(struct kvm_vcpu *vcpu,
    struct kvm_mp_state *mp_state)
{
	vcpu_load(vcpu);
	vcpu->arch.mp_state = mp_state->mp_state;
	vcpu_put(vcpu);
	return (0);
}

static void
kvm_set_segment(struct kvm_vcpu *vcpu,
			struct kvm_segment *var, int seg)
{
	kvm_x86_ops->set_segment(vcpu, var, seg);
}

static void
seg_desct_to_kvm_desct(struct desc_struct *seg_desc, uint16_t selector,
    struct kvm_segment *kvm_desct)
{
	kvm_desct->base = get_desc_base(seg_desc);
	kvm_desct->limit = get_desc_limit(seg_desc);
	if (seg_desc->c.b.g) {
		kvm_desct->limit <<= 12;
		kvm_desct->limit |= 0xfff;
	}
	kvm_desct->selector = selector;
	kvm_desct->type = seg_desc->c.b.type;
	kvm_desct->present = seg_desc->c.b.p;
	kvm_desct->dpl = seg_desc->c.b.dpl;
	kvm_desct->db = seg_desc->c.b.d;
	kvm_desct->s = seg_desc->c.b.s;
	kvm_desct->l = seg_desc->c.b.l;
	kvm_desct->g = seg_desc->c.b.g;
	kvm_desct->avl = seg_desc->c.b.avl;
	if (!selector)
		kvm_desct->unusable = 1;
	else
		kvm_desct->unusable = 0;
	kvm_desct->padding = 0;
}

static void
get_segment_descriptor_dtable(struct kvm_vcpu *vcpu, uint16_t selector,
    struct descriptor_table *dtable)
{
	if (selector & 1 << 2) {
		struct kvm_segment kvm_seg;

		kvm_get_segment(vcpu, &kvm_seg, VCPU_SREG_LDTR);

		if (kvm_seg.unusable)
			dtable->limit = 0;
		else
			dtable->limit = kvm_seg.limit;
		dtable->base = kvm_seg.base;
	} else
		kvm_x86_ops->get_gdt(vcpu, dtable);
}

/* allowed just for 8 bytes segments */
static int
load_guest_segment_descriptor(struct kvm_vcpu *vcpu, uint16_t selector,
    struct desc_struct *seg_desc)
{
	struct descriptor_table dtable;
	uint16_t index = selector >> 3;
	int ret;
	uint32_t err;
	gva_t addr;

	get_segment_descriptor_dtable(vcpu, selector, &dtable);

	if (dtable.limit < index * 8 + 7) {
		kvm_queue_exception_e(vcpu, GP_VECTOR, selector & 0xfffc);
		return (1);
	}

	addr = dtable.base + index * 8;
	ret = kvm_read_guest_virt_system(addr, seg_desc, sizeof (*seg_desc),
	    vcpu,  &err);

	if (ret == 1)
		kvm_inject_page_fault(vcpu, addr, err);

	return (ret);
}

/* allowed just for 8 bytes segments */
static int
save_guest_segment_descriptor(struct kvm_vcpu *vcpu, uint16_t selector,
    struct desc_struct *seg_desc)
{
	struct descriptor_table dtable;
	uint16_t index = selector >> 3;

	get_segment_descriptor_dtable(vcpu, selector, &dtable);

	if (dtable.limit < index * 8 + 7)
		return (1);

	return kvm_write_guest_virt(dtable.base + index * 8, seg_desc,
	    sizeof (*seg_desc), vcpu, NULL);
}

static gpa_t
get_tss_base_addr_write(struct kvm_vcpu *vcpu, struct desc_struct *seg_desc)
{
	uint32_t base_addr = get_desc_base(seg_desc);

	return (kvm_mmu_gva_to_gpa_write(vcpu, base_addr, NULL));
}

static gpa_t
get_tss_base_addr_read(struct kvm_vcpu *vcpu, struct desc_struct *seg_desc)
{
	uint32_t base_addr = get_desc_base(seg_desc);

	return (kvm_mmu_gva_to_gpa_read(vcpu, base_addr, NULL));
}

static uint16_t
get_segment_selector(struct kvm_vcpu *vcpu, int seg)
{
	struct kvm_segment kvm_seg;

	kvm_get_segment(vcpu, &kvm_seg, seg);

	return (kvm_seg.selector);
}

static int
kvm_load_realmode_segment(struct kvm_vcpu *vcpu, uint16_t selector, int seg)
{
	struct kvm_segment segvar = {
		.base = selector << 4,
		.limit = 0xffff,
		.selector = selector,
		.type = 3,
		.present = 1,
		.dpl = 3,
		.db = 0,
		.s = 1,
		.l = 0,
		.g = 0,
		.avl = 0,
		.unusable = 0,
	};
	kvm_x86_ops->set_segment(vcpu, &segvar, seg);
	return (0);
}

static int
is_vm86_segment(struct kvm_vcpu *vcpu, int seg)
{
	return (seg != VCPU_SREG_LDTR) && (seg != VCPU_SREG_TR) &&
	    (kvm_get_rflags(vcpu) & X86_EFLAGS_VM);
}

int
kvm_load_segment_descriptor(struct kvm_vcpu *vcpu, uint16_t selector, int seg)
{
	struct kvm_segment kvm_seg;
	struct desc_struct seg_desc;
	uint8_t dpl, rpl, cpl;
	unsigned err_vec = GP_VECTOR;
	uint32_t err_code = 0;
	int null_selector = !(selector & ~0x3); /* 0000-0003 are null */
	int ret;

	if (is_vm86_segment(vcpu, seg) || !is_protmode(vcpu))
		return (kvm_load_realmode_segment(vcpu, selector, seg));

	/* NULL selector is not valid for TR, CS and SS */
	if ((seg == VCPU_SREG_CS || seg == VCPU_SREG_SS ||
	    seg == VCPU_SREG_TR) && null_selector)
		goto exception;

	/* TR should be in GDT only */
	if (seg == VCPU_SREG_TR && (selector & (1 << 2)))
		goto exception;

	ret = load_guest_segment_descriptor(vcpu, selector, &seg_desc);

	if (ret)
		return (ret);

	seg_desct_to_kvm_desct(&seg_desc, selector, &kvm_seg);

	if (null_selector) { /* for NULL selector skip all following checks */
		kvm_seg.unusable = 1;
		goto load;
	}

	err_code = selector & 0xfffc;
	err_vec = GP_VECTOR;

	/* can't load system descriptor into segment selecor */
	if (seg <= VCPU_SREG_GS && !kvm_seg.s)
		goto exception;

	if (!kvm_seg.present) {
		err_vec = (seg == VCPU_SREG_SS) ? SS_VECTOR : NP_VECTOR;
		goto exception;
	}

	rpl = selector & 3;
	dpl = kvm_seg.dpl;
	cpl = kvm_x86_ops->get_cpl(vcpu);

	switch (seg) {
	case VCPU_SREG_SS:
		/*
		 * segment is not a writable data segment or segment
		 * selector's RPL != CPL or segment selector's RPL != CPL
		 */
		if (rpl != cpl || (kvm_seg.type & 0xa) != 0x2 || dpl != cpl)
			goto exception;
		break;
	case VCPU_SREG_CS:
		if (!(kvm_seg.type & 8))
			goto exception;

		if (kvm_seg.type & 4) {
			/* conforming */
			if (dpl > cpl)
				goto exception;
		} else {
			/* nonconforming */
			if (rpl > cpl || dpl != cpl)
				goto exception;
		}
		/* CS(RPL) <- CPL */
		selector = (selector & 0xfffc) | cpl;
		break;
	case VCPU_SREG_TR:
		if (kvm_seg.s || (kvm_seg.type != 1 && kvm_seg.type != 9))
			goto exception;
		break;
	case VCPU_SREG_LDTR:
		if (kvm_seg.s || kvm_seg.type != 2)
			goto exception;
		break;
	default: /*  DS, ES, FS, or GS */
		/*
		 * segment is not a data or readable code segment or
		 * ((segment is a data or nonconforming code segment)
		 * and (both RPL and CPL > DPL))
		 */
		if ((kvm_seg.type & 0xa) == 0x8 ||
		    (((kvm_seg.type & 0xc) != 0xc) && (rpl > dpl && cpl > dpl)))
			goto exception;
		break;
	}

	if (!kvm_seg.unusable && kvm_seg.s) {
		/* mark segment as accessed */
		kvm_seg.type |= 1;
		seg_desc.c.b.type |= 1;
		save_guest_segment_descriptor(vcpu, selector, &seg_desc);
	}
load:
	kvm_set_segment(vcpu, &kvm_seg, seg);
	return (0);
exception:
	kvm_queue_exception_e(vcpu, err_vec, err_code);
	return (1);

}

static void
save_state_to_tss32(struct kvm_vcpu *vcpu, struct tss32 *tss)
{
	tss->tss_cr3 = vcpu->arch.cr3;
	tss->tss_eip = kvm_rip_read(vcpu);
	tss->tss_eflags = kvm_get_rflags(vcpu);
	tss->tss_eax = kvm_register_read(vcpu, VCPU_REGS_RAX);
	tss->tss_ecx = kvm_register_read(vcpu, VCPU_REGS_RCX);
	tss->tss_edx = kvm_register_read(vcpu, VCPU_REGS_RDX);
	tss->tss_ebx = kvm_register_read(vcpu, VCPU_REGS_RBX);
	tss->tss_esp = kvm_register_read(vcpu, VCPU_REGS_RSP);
	tss->tss_ebp = kvm_register_read(vcpu, VCPU_REGS_RBP);
	tss->tss_esi = kvm_register_read(vcpu, VCPU_REGS_RSI);
	tss->tss_edi = kvm_register_read(vcpu, VCPU_REGS_RDI);
	tss->tss_es = get_segment_selector(vcpu, VCPU_SREG_ES);
	tss->tss_cs = get_segment_selector(vcpu, VCPU_SREG_CS);
	tss->tss_ss = get_segment_selector(vcpu, VCPU_SREG_SS);
	tss->tss_ds = get_segment_selector(vcpu, VCPU_SREG_DS);
	tss->tss_fs = get_segment_selector(vcpu, VCPU_SREG_FS);
	tss->tss_gs = get_segment_selector(vcpu, VCPU_SREG_GS);
	tss->tss_ldt = get_segment_selector(vcpu, VCPU_SREG_LDTR);
}

static void
kvm_load_segment_selector(struct kvm_vcpu *vcpu, uint16_t sel, int seg)
{
	struct kvm_segment kvm_seg;
	kvm_get_segment(vcpu, &kvm_seg, seg);
	kvm_seg.selector = sel;
	kvm_set_segment(vcpu, &kvm_seg, seg);
}

static int
load_state_from_tss32(struct kvm_vcpu *vcpu, struct tss32 *tss)
{
	kvm_set_cr3(vcpu, tss->tss_cr3);

	kvm_rip_write(vcpu, tss->tss_eip);
	kvm_set_rflags(vcpu, tss->tss_eflags | 2);

	kvm_register_write(vcpu, VCPU_REGS_RAX, tss->tss_eax);
	kvm_register_write(vcpu, VCPU_REGS_RCX, tss->tss_ecx);
	kvm_register_write(vcpu, VCPU_REGS_RDX, tss->tss_edx);
	kvm_register_write(vcpu, VCPU_REGS_RBX, tss->tss_ebx);
	kvm_register_write(vcpu, VCPU_REGS_RSP, tss->tss_esp);
	kvm_register_write(vcpu, VCPU_REGS_RBP, tss->tss_ebp);
	kvm_register_write(vcpu, VCPU_REGS_RSI, tss->tss_esi);
	kvm_register_write(vcpu, VCPU_REGS_RDI, tss->tss_edi);

	/*
	 * SDM says that segment selectors are loaded before segment
	 * descriptors
	 */
	kvm_load_segment_selector(vcpu, tss->tss_ldt, VCPU_SREG_LDTR);
	kvm_load_segment_selector(vcpu, tss->tss_es, VCPU_SREG_ES);
	kvm_load_segment_selector(vcpu, tss->tss_cs, VCPU_SREG_CS);
	kvm_load_segment_selector(vcpu, tss->tss_ss, VCPU_SREG_SS);
	kvm_load_segment_selector(vcpu, tss->tss_ds, VCPU_SREG_DS);
	kvm_load_segment_selector(vcpu, tss->tss_fs, VCPU_SREG_FS);
	kvm_load_segment_selector(vcpu, tss->tss_gs, VCPU_SREG_GS);

	/*
	 * Now load segment descriptors. If fault happenes at this stage
	 * it is handled in a context of new task
	 */
	if (kvm_load_segment_descriptor(vcpu,
	    tss->tss_ldt, VCPU_SREG_LDTR))
		return (1);

	if (kvm_load_segment_descriptor(vcpu, tss->tss_es, VCPU_SREG_ES))
		return (1);

	if (kvm_load_segment_descriptor(vcpu, tss->tss_cs, VCPU_SREG_CS))
		return (1);

	if (kvm_load_segment_descriptor(vcpu, tss->tss_ss, VCPU_SREG_SS))
		return (1);

	if (kvm_load_segment_descriptor(vcpu, tss->tss_ds, VCPU_SREG_DS))
		return (1);

	if (kvm_load_segment_descriptor(vcpu, tss->tss_fs, VCPU_SREG_FS))
		return (1);

	if (kvm_load_segment_descriptor(vcpu, tss->tss_gs, VCPU_SREG_GS))
		return (1);

	return (0);
}

static void
save_state_to_tss16(struct kvm_vcpu *vcpu, struct tss16 *tss)
{
	tss->tss_ip = kvm_rip_read(vcpu);
	tss->tss_flag = kvm_get_rflags(vcpu);
	tss->tss_ax = kvm_register_read(vcpu, VCPU_REGS_RAX);
	tss->tss_cx = kvm_register_read(vcpu, VCPU_REGS_RCX);
	tss->tss_dx = kvm_register_read(vcpu, VCPU_REGS_RDX);
	tss->tss_bx = kvm_register_read(vcpu, VCPU_REGS_RBX);
	tss->tss_sp = kvm_register_read(vcpu, VCPU_REGS_RSP);
	tss->tss_bp = kvm_register_read(vcpu, VCPU_REGS_RBP);
	tss->tss_si = kvm_register_read(vcpu, VCPU_REGS_RSI);
	tss->tss_di = kvm_register_read(vcpu, VCPU_REGS_RDI);

	tss->tss_es = get_segment_selector(vcpu, VCPU_SREG_ES);
	tss->tss_cs = get_segment_selector(vcpu, VCPU_SREG_CS);
	tss->tss_ss = get_segment_selector(vcpu, VCPU_SREG_SS);
	tss->tss_ds = get_segment_selector(vcpu, VCPU_SREG_DS);
	tss->tss_ldt = get_segment_selector(vcpu, VCPU_SREG_LDTR);
}

static int
load_state_from_tss16(struct kvm_vcpu *vcpu, struct tss16 *tss)
{
	kvm_rip_write(vcpu, tss->tss_ip);
	kvm_set_rflags(vcpu, tss->tss_flag | 2);
	kvm_register_write(vcpu, VCPU_REGS_RAX, tss->tss_ax);
	kvm_register_write(vcpu, VCPU_REGS_RCX, tss->tss_cx);
	kvm_register_write(vcpu, VCPU_REGS_RDX, tss->tss_dx);
	kvm_register_write(vcpu, VCPU_REGS_RBX, tss->tss_bx);
	kvm_register_write(vcpu, VCPU_REGS_RSP, tss->tss_sp);
	kvm_register_write(vcpu, VCPU_REGS_RBP, tss->tss_bp);
	kvm_register_write(vcpu, VCPU_REGS_RSI, tss->tss_si);
	kvm_register_write(vcpu, VCPU_REGS_RDI, tss->tss_di);

	/*
	 * SDM says that segment selectors are loaded before segment
	 * descriptors
	 */
	kvm_load_segment_selector(vcpu, tss->tss_ldt, VCPU_SREG_LDTR);
	kvm_load_segment_selector(vcpu, tss->tss_es, VCPU_SREG_ES);
	kvm_load_segment_selector(vcpu, tss->tss_cs, VCPU_SREG_CS);
	kvm_load_segment_selector(vcpu, tss->tss_ss, VCPU_SREG_SS);
	kvm_load_segment_selector(vcpu, tss->tss_ds, VCPU_SREG_DS);

	/*
	 * Now load segment descriptors. If fault happenes at this stage
	 * it is handled in a context of new task
	 */
	if (kvm_load_segment_descriptor(vcpu, tss->tss_ldt, VCPU_SREG_LDTR))
		return (1);

	if (kvm_load_segment_descriptor(vcpu, tss->tss_es, VCPU_SREG_ES))
		return (1);

	if (kvm_load_segment_descriptor(vcpu, tss->tss_cs, VCPU_SREG_CS))
		return (1);

	if (kvm_load_segment_descriptor(vcpu, tss->tss_ss, VCPU_SREG_SS))
		return (1);

	if (kvm_load_segment_descriptor(vcpu, tss->tss_ds, VCPU_SREG_DS))
		return (1);

	return (0);
}

static int
kvm_task_switch_16(struct kvm_vcpu *vcpu, uint16_t tss_selector,
    uint16_t old_tss_sel, uint32_t old_tss_base, struct desc_struct *nseg_desc)
{
	struct tss16 tss16;
	int ret = 0;

	if (kvm_read_guest(vcpu->kvm, old_tss_base,
	    &tss16, sizeof (tss16)))
		goto out;

	save_state_to_tss16(vcpu, &tss16);

	if (kvm_write_guest(vcpu->kvm, old_tss_base,
	    &tss16, sizeof (tss16)))
		goto out;

	if (kvm_read_guest(vcpu->kvm, get_tss_base_addr_read(vcpu, nseg_desc),
	    &tss16, sizeof (tss16)))
		goto out;

	if (old_tss_sel != 0xffff) {
		tss16.tss_link = old_tss_sel;

		if (kvm_write_guest(vcpu->kvm, get_tss_base_addr_write(vcpu,
		    nseg_desc), &tss16.tss_link,
		    sizeof (tss16.tss_link)))
			goto out;
	}

	if (load_state_from_tss16(vcpu, &tss16))
		goto out;

	ret = 1;
out:
	return (ret);
}

static int
kvm_task_switch_32(struct kvm_vcpu *vcpu, uint16_t tss_selector,
    uint16_t old_tss_sel, uint32_t old_tss_base, struct desc_struct *nseg_desc)
{
	struct tss32 tss32;
	int ret = 0;

	if (kvm_read_guest(vcpu->kvm, old_tss_base,
	    &tss32, sizeof (tss32)))
		goto out;

	save_state_to_tss32(vcpu, &tss32);

	if (kvm_write_guest(vcpu->kvm, old_tss_base,
	    &tss32, sizeof (tss32)))
		goto out;

	if (kvm_read_guest(vcpu->kvm, get_tss_base_addr_read(vcpu, nseg_desc),
	    &tss32, sizeof (tss32)))
		goto out;

	if (old_tss_sel != 0xffff) {
		tss32.tss_link = old_tss_sel;

		if (kvm_write_guest(vcpu->kvm, get_tss_base_addr_write(vcpu,
		    nseg_desc), &tss32.tss_link,
		    sizeof (tss32.tss_link)))
			goto out;
	}

	if (load_state_from_tss32(vcpu, &tss32))
		goto out;

	ret = 1;
out:
	return (ret);
}

int
kvm_task_switch(struct kvm_vcpu *vcpu, uint16_t tss_selector, int reason)
{
	struct kvm_segment tr_seg;
	struct desc_struct cseg_desc;
	struct desc_struct nseg_desc;
	int ret = 0;
	uint32_t old_tss_base = get_segment_base(vcpu, VCPU_SREG_TR);
	uint16_t old_tss_sel = get_segment_selector(vcpu, VCPU_SREG_TR);
	uint32_t desc_limit;

	old_tss_base = kvm_mmu_gva_to_gpa_write(vcpu, old_tss_base, NULL);

	/*
	 * FIXME: Handle errors. Failure to read either TSS or their
	 * descriptors should generate a pagefault.
	 */
	if (load_guest_segment_descriptor(vcpu, tss_selector, &nseg_desc))
		goto out;

	if (load_guest_segment_descriptor(vcpu, old_tss_sel, &cseg_desc))
		goto out;

	if (reason != TASK_SWITCH_IRET) {
		int cpl;

		cpl = kvm_x86_ops->get_cpl(vcpu);
		if ((tss_selector & 3) > nseg_desc.c.b.dpl ||
		    cpl > nseg_desc.c.b.dpl) {
			kvm_queue_exception_e(vcpu, GP_VECTOR, 0);
			return (1);
		}
	}

	desc_limit = get_desc_limit(&nseg_desc);

	if (!nseg_desc.c.b.p || ((desc_limit < 0x67 &&
	    (nseg_desc.c.b.type & 8)) || desc_limit < 0x2b)) {
		kvm_queue_exception_e(vcpu, TS_VECTOR, tss_selector & 0xfffc);
		return (1);
	}

	if (reason == TASK_SWITCH_IRET || reason == TASK_SWITCH_JMP) {
		cseg_desc.c.b.type &= ~(1 << 1); // clear the B flag
		save_guest_segment_descriptor(vcpu, old_tss_sel, &cseg_desc);
	}

	if (reason == TASK_SWITCH_IRET) {
		uint32_t eflags = kvm_get_rflags(vcpu);
		kvm_set_rflags(vcpu, eflags & ~X86_EFLAGS_NT);
	}

	/*
	 * set back link to prev task only if NT bit is set in eflags
	 * note that old_tss_sel is not used afetr this point
	 */
	if (reason != TASK_SWITCH_CALL && reason != TASK_SWITCH_GATE)
		old_tss_sel = 0xffff;

	if (nseg_desc.c.b.type & 8) {
		ret = kvm_task_switch_32(vcpu, tss_selector, old_tss_sel,
		    old_tss_base, &nseg_desc);
	} else {
		ret = kvm_task_switch_16(vcpu, tss_selector, old_tss_sel,
		    old_tss_base, &nseg_desc);
	}

	if (reason == TASK_SWITCH_CALL || reason == TASK_SWITCH_GATE) {
		uint32_t eflags = kvm_get_rflags(vcpu);
		kvm_set_rflags(vcpu, eflags | X86_EFLAGS_NT);
	}

	if (reason != TASK_SWITCH_IRET) {
		nseg_desc.c.b.type |= (1 << 1);
		save_guest_segment_descriptor(vcpu, tss_selector, &nseg_desc);
	}

	kvm_x86_ops->set_cr0(vcpu, kvm_read_cr0(vcpu) | X86_CR0_TS);
	seg_desct_to_kvm_desct(&nseg_desc, tss_selector, &tr_seg);
	tr_seg.type = 11;
	kvm_set_segment(vcpu, &tr_seg, VCPU_SREG_TR);
out:
	return (ret);
}

static unsigned long
find_next_bit(const unsigned long *addr,
    unsigned long size, unsigned long offset)
{
	const unsigned long *p = addr + (offset/64);
	unsigned long result = offset & ~(64-1);
	unsigned long tmp;

	if (offset >= size)
		return (size);

	size -= result;
	offset %= 64;

	if (offset) {
		tmp = *(p++);
		tmp &= (~0UL << offset);
		if (size < 64)
			goto found_first;
		if (tmp)
			goto found_middle;
		size -= 64;
		result += 64;
	}
	while (size & ~(64-1)) {
		if ((tmp = *(p++)))
			goto found_middle;
		result += 64;
		size -= 64;
	}

	if (!size)
		return (result);
	tmp = *p;

found_first:
	tmp &= (~0UL >> (64 - size));
	if (tmp == 0UL)		/* Are any bits set? */
		return (result + size);	/* Nope. */
found_middle:
	return (result + __ffs(tmp));
}

int
kvm_arch_vcpu_ioctl_set_sregs(struct kvm_vcpu *vcpu, struct kvm_sregs *sregs)
{
	int mmu_reset_needed = 0;
	int pending_vec, max_bits;
	struct descriptor_table dt;

	vcpu_load(vcpu);

	dt.limit = sregs->idt.limit;
	dt.base = sregs->idt.base;
	kvm_x86_ops->set_idt(vcpu, &dt);
	dt.limit = sregs->gdt.limit;
	dt.base = sregs->gdt.base;
	kvm_x86_ops->set_gdt(vcpu, &dt);

	vcpu->arch.cr2 = sregs->cr2;
	mmu_reset_needed |= vcpu->arch.cr3 != sregs->cr3;
	vcpu->arch.cr3 = sregs->cr3;

	kvm_set_cr8(vcpu, sregs->cr8);

	mmu_reset_needed |= vcpu->arch.efer != sregs->efer;
	kvm_x86_ops->set_efer(vcpu, sregs->efer);
	kvm_set_apic_base(vcpu, sregs->apic_base);

	mmu_reset_needed |= kvm_read_cr0(vcpu) != sregs->cr0;
	kvm_x86_ops->set_cr0(vcpu, sregs->cr0);
	vcpu->arch.cr0 = sregs->cr0;

	mmu_reset_needed |= kvm_read_cr4(vcpu) != sregs->cr4;
	kvm_x86_ops->set_cr4(vcpu, sregs->cr4);

	if (!is_long_mode(vcpu) && is_pae(vcpu)) {
		load_pdptrs(vcpu, vcpu->arch.cr3);
		mmu_reset_needed = 1;
	}

	if (mmu_reset_needed)
		kvm_mmu_reset_context(vcpu);

	max_bits = (sizeof (sregs->interrupt_bitmap)) << 3;
	pending_vec =
	    find_next_bit((const unsigned long *)sregs->interrupt_bitmap,
	    max_bits, 0);

	if (pending_vec < max_bits) {
		kvm_queue_interrupt(vcpu, pending_vec, 0);
		if (irqchip_in_kernel(vcpu->kvm))
			kvm_pic_clear_isr_ack(vcpu->kvm);
	}

	kvm_set_segment(vcpu, &sregs->cs, VCPU_SREG_CS);
	kvm_set_segment(vcpu, &sregs->ds, VCPU_SREG_DS);
	kvm_set_segment(vcpu, &sregs->es, VCPU_SREG_ES);
	kvm_set_segment(vcpu, &sregs->fs, VCPU_SREG_FS);
	kvm_set_segment(vcpu, &sregs->gs, VCPU_SREG_GS);
	kvm_set_segment(vcpu, &sregs->ss, VCPU_SREG_SS);

	kvm_set_segment(vcpu, &sregs->tr, VCPU_SREG_TR);
	kvm_set_segment(vcpu, &sregs->ldt, VCPU_SREG_LDTR);

	update_cr8_intercept(vcpu);

	/* Older userspace won't unhalt the vcpu on reset. */
	if (kvm_vcpu_is_bsp(vcpu) && kvm_rip_read(vcpu) == 0xfff0 &&
	    sregs->cs.selector == 0xf000 && sregs->cs.base == 0xffff0000 &&
	    !is_protmode(vcpu))
		vcpu->arch.mp_state = KVM_MP_STATE_RUNNABLE;

	vcpu_put(vcpu);

	return (0);
}

int
kvm_arch_vcpu_ioctl_get_fpu(struct kvm_vcpu *vcpu, struct kvm_fpu *fpu)
{
	struct fxsave_state fxsave;

	vcpu_load(vcpu);

	hma_fpu_get_fxsave_state(vcpu->arch.guest_fpu, &fxsave);

	memcpy(fpu->fpr, fxsave.fx_st, 128);
	fpu->fcw = fxsave.fx_fcw;
	fpu->fsw = fxsave.fx_fsw;
	fpu->ftwx = fxsave.fx_fctw;
	fpu->last_opcode = fxsave.fx_fop;
	fpu->last_ip = fxsave.fx_rip;
	fpu->last_dp = fxsave.fx_rdp;
	memcpy(fpu->xmm, fxsave.fx_xmm, sizeof (fxsave.fx_xmm));
	fpu->mxcsr = fxsave.fx_mxcsr;

	vcpu_put(vcpu);

	return (0);
}

int
kvm_arch_vcpu_ioctl_set_fpu(struct kvm_vcpu *vcpu, struct kvm_fpu *fpu)
{
	int ret;
	struct fxsave_state fxsave;

	bzero(&fxsave, sizeof (struct fxsave_state));
	vcpu_load(vcpu);

	memcpy(fxsave.fx_st, fpu->fpr, 128);
	fxsave.fx_fcw = fpu->fcw;
	fxsave.fx_fsw = fpu->fsw;
	fxsave.fx_fctw = fpu->ftwx;
	fxsave.fx_fop = fpu->last_opcode;
	fxsave.fx_rip = fpu->last_ip;
	fxsave.fx_rdp = fpu->last_dp;
	memcpy(fxsave.fx_xmm, fpu->xmm, sizeof (fxsave.fx_xmm));
	fxsave.fx_mxcsr = fpu->mxcsr;

	ret = hma_fpu_set_fxsave_state(vcpu->arch.guest_fpu, &fxsave);

	vcpu_put(vcpu);

	return (ret);
}

void
fx_init(struct kvm_vcpu *vcpu)
{
	vcpu->arch.cr0 |= X86_CR0_ET;
	hma_fpu_init(vcpu->arch.guest_fpu);
}

void
kvm_load_guest_fpu(struct kvm_vcpu *vcpu)
{
	if (vcpu->guest_fpu_loaded)
		return;

	vcpu->guest_fpu_loaded = 1;
	hma_fpu_start_guest(vcpu->arch.guest_fpu);
	if (vcpu->kvm->arch.need_xcr0) {
		set_xcr(XFEATURE_ENABLED_MASK, XFEATURE_LEGACY_FP);
	}
	KVM_TRACE1(fpu, int, 1);
}

void
kvm_put_guest_fpu(struct kvm_vcpu *vcpu)
{
	if (!vcpu->guest_fpu_loaded)
		return;

	vcpu->guest_fpu_loaded = 0;
	if (vcpu->kvm->arch.need_xcr0) {
		set_xcr(XFEATURE_ENABLED_MASK, vcpu->kvm->arch.host_xcr0);
	}
	hma_fpu_stop_guest(vcpu->arch.guest_fpu);
	KVM_VCPU_KSTAT_INC(vcpu, kvmvs_fpu_reload);
	set_bit(KVM_REQ_DEACTIVATE_FPU, &vcpu->requests);
}

void
kvm_arch_vcpu_free(struct kvm_vcpu *vcpu)
{
	if (vcpu->kvcpu_kstat != NULL)
		kstat_delete(vcpu->kvcpu_kstat);

	hma_fpu_free(vcpu->arch.guest_fpu);

	kvm_x86_ops->vcpu_free(vcpu);
}

struct kvm_vcpu *
kvm_arch_vcpu_create(struct kvm *kvm, unsigned int id)
{
	char buf[32];
	struct kvm_vcpu *vcpu;
	kstat_t *kstat;

	(void) snprintf(buf, sizeof (buf), "vcpu-%d", kvm->kvmid);

	if ((kstat = kstat_create_zone("kvm", id, buf, "misc", KSTAT_TYPE_NAMED,
	    sizeof (kvm_vcpu_stats_t) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL, GLOBAL_ZONEID)) == NULL) {
		return (NULL);
	}

	vcpu = kvm_x86_ops->vcpu_create(kvm, id);

	if (vcpu == NULL) {
		kstat_delete(kstat);
		return (NULL);
	}

	vcpu->arch.guest_fpu = hma_fpu_alloc(KM_SLEEP);

	vcpu->kvcpu_kstat = kstat;
	vcpu->kvcpu_kstat->ks_data = &vcpu->kvcpu_stats;
	vcpu->kvcpu_kstat->ks_data_size +=
	    strlen(curproc->p_zone->zone_name) + 1;

	KVM_VCPU_KSTAT_INIT(vcpu, kvmvs_id, "id");
	vcpu->kvcpu_stats.kvmvs_id.value.ui64 = kvm->kvmid;

	KVM_VCPU_KSTAT_INIT(vcpu, kvmvs_id, "pid");
	vcpu->kvcpu_stats.kvmvs_id.value.ui64 = kvm->kvm_pid;

	KVM_VCPU_KSTAT_INIT(vcpu, kvmvs_nmi_injections, "nmi-injections");
	KVM_VCPU_KSTAT_INIT(vcpu, kvmvs_irq_injections, "irq-injections");
	KVM_VCPU_KSTAT_INIT(vcpu, kvmvs_fpu_reload, "fpu-reload");
	KVM_VCPU_KSTAT_INIT(vcpu, kvmvs_host_state_reload, "host-state-reload");
	KVM_VCPU_KSTAT_INIT(vcpu, kvmvs_insn_emulation, "insn-emulation");
	KVM_VCPU_KSTAT_INIT(vcpu, kvmvs_insn_emulation_fail,
	    "inst-emulation-fail");
	KVM_VCPU_KSTAT_INIT(vcpu, kvmvs_exits, "exits");
	KVM_VCPU_KSTAT_INIT(vcpu, kvmvs_halt_exits, "halt-exits");
	KVM_VCPU_KSTAT_INIT(vcpu, kvmvs_irq_exits, "irq-exits");
	KVM_VCPU_KSTAT_INIT(vcpu, kvmvs_io_exits, "io-exits");
	KVM_VCPU_KSTAT_INIT(vcpu, kvmvs_mmio_exits, "mmio-exits");
	KVM_VCPU_KSTAT_INIT(vcpu, kvmvs_nmi_window_exits, "nmi-window-exits");
	KVM_VCPU_KSTAT_INIT(vcpu, kvmvs_irq_window_exits, "irq-window-exits");
	KVM_VCPU_KSTAT_INIT(vcpu, kvmvs_request_irq_exits, "request-irq-exits");
	KVM_VCPU_KSTAT_INIT(vcpu, kvmvs_signal_exits, "signal-exits");
	KVM_VCPU_KSTAT_INIT(vcpu, kvmvs_halt_wakeup, "halt-wakeup");
	KVM_VCPU_KSTAT_INIT(vcpu, kvmvs_invlpg, "invlpg");
	KVM_VCPU_KSTAT_INIT(vcpu, kvmvs_pf_guest, "pf-guest");
	KVM_VCPU_KSTAT_INIT(vcpu, kvmvs_pf_fixed, "pf-fixed");
	KVM_VCPU_KSTAT_INIT(vcpu, kvmvs_hypercalls, "hypercalls");
	kstat_named_init(&(vcpu->kvcpu_stats.kvmvs_zonename), "zonename",
	    KSTAT_DATA_STRING);
	kstat_named_setstr(&(vcpu->kvcpu_stats.kvmvs_zonename),
	    curproc->p_zone->zone_name);

	kstat_install(vcpu->kvcpu_kstat);

	return (vcpu);
}

int
kvm_arch_vcpu_setup(struct kvm_vcpu *vcpu)
{
	int r;

	vcpu->arch.mtrr_state.have_fixed = 1;
	vcpu_load(vcpu);

	r = kvm_arch_vcpu_reset(vcpu);
	if (r == 0)
		r = kvm_mmu_setup(vcpu);

	vcpu_put(vcpu);
	if (r < 0)
		goto free_vcpu;

	return (0);
free_vcpu:
#ifdef XXX
	kvm_x86_ops->vcpu_free(vcpu);
#else
	XXX_KVM_PROBE;
#endif

	return (r);
}

int
kvm_arch_vcpu_reset(struct kvm_vcpu *vcpu)
{
	vcpu->arch.nmi_pending = 0;
	vcpu->arch.nmi_injected = 0;

	vcpu->arch.switch_db_regs = 0;
	memset(vcpu->arch.db, 0, sizeof (vcpu->arch.db));
	vcpu->arch.dr6 = DR6_FIXED_1;
	vcpu->arch.dr7 = DR7_FIXED_1;

	return (kvm_x86_ops->vcpu_reset(vcpu));
}

int
kvm_arch_hardware_setup(void)
{
	int res;

	res = kvm_x86_ops->hardware_setup();
	if (res == 0) {
		shared_msrs = kmem_zalloc(
		    ncpus * sizeof (struct kvm_shared_msrs), KM_SLEEP);
	}
	return (res);
}

void
kvm_arch_hardware_unsetup(void)
{
	kmem_free(shared_msrs, ncpus * sizeof (struct kvm_shared_msrs));
	shared_msrs = NULL;
}

void
kvm_arch_exit(void)
{
	kvm_mmu_destroy_caches();
}

void
kvm_arch_check_processor_compat(void *rtn)
{
	kvm_x86_ops->check_processor_compatibility(rtn);
}

int
kvm_arch_vcpu_init(struct kvm_vcpu *vcpu)
{
	page_t *page;
	struct kvm *kvm;
	int r;

	kvm = vcpu->kvm;

	vcpu->arch.mmu.root_hpa = INVALID_PAGE;

	if (!irqchip_in_kernel(kvm) || kvm_vcpu_is_bsp(vcpu))
		vcpu->arch.mp_state = KVM_MP_STATE_RUNNABLE;
	else
		vcpu->arch.mp_state = KVM_MP_STATE_UNINITIALIZED;

	/*
	 * page = alloc_page(PAGESIZE, KM_SLEEP);
	 * if (!page) {
	 *	r = ENOMEM;
	 *	goto fail;
	 * }
	 * vcpu->arch.pio_data = page_address(page);
	 */
	vcpu->arch.pio_data = (caddr_t)vcpu->run +
	    (KVM_PIO_PAGE_OFFSET * PAGESIZE);

	r = kvm_mmu_create(vcpu);
	if (r < 0)
		goto fail;

	if (irqchip_in_kernel(kvm)) {
		r = kvm_create_lapic(vcpu);
		if (r < 0)
			goto fail_mmu_destroy;
	}

	vcpu->arch.mce_banks = kmem_zalloc(KVM_MAX_MCE_BANKS *
	    sizeof (uint64_t) * 4, KM_SLEEP);

	if (!vcpu->arch.mce_banks) {
		r = ENOMEM;
		goto fail_free_lapic;
	}

	vcpu->arch.mcg_cap = KVM_MAX_MCE_BANKS;

	return (0);
fail_free_lapic:
	kvm_free_lapic(vcpu);
fail_mmu_destroy:
	kvm_mmu_destroy(vcpu);
fail:
	return (r);
}

void
kvm_arch_vcpu_uninit(struct kvm_vcpu *vcpu)
{
	kmem_free(vcpu->arch.mce_banks, sizeof (uint64_t) * 4 *
	    KVM_MAX_MCE_BANKS);
	kvm_free_lapic(vcpu);
	kvm_mmu_destroy(vcpu);
}

struct kvm *
kvm_arch_create_vm(void)
{
	struct kvm *kvm = kmem_zalloc(sizeof (struct kvm), KM_SLEEP);

	if (!kvm)
		return (NULL);

	if ((kvm->arch.aliases =
	    kmem_zalloc(sizeof (struct kvm_mem_aliases), KM_SLEEP)) == NULL) {
		kmem_free(kvm, sizeof (struct kvm));
		return (NULL);
	}

	list_create(&kvm->arch.active_mmu_pages, sizeof (struct kvm_mmu_page),
	    offsetof(struct kvm_mmu_page, link));

	list_create(&kvm->arch.assigned_dev_head,
	    sizeof (struct kvm_assigned_dev_kernel),
	    offsetof(struct kvm_assigned_dev_kernel, list));

	/* Reserve bit 0 of irq_sources_bitmap for userspace irq source */
	set_bit(KVM_USERSPACE_IRQ_SOURCE_ID, &kvm->arch.irq_sources_bitmap);

	if ((native_read_cr4() & CR4_OSXSAVE) != 0) {
		kvm->arch.need_xcr0 = 1;
		kvm->arch.host_xcr0 = get_xcr(XFEATURE_ENABLED_MASK);
	} else {
		kvm->arch.need_xcr0 = 0;
		kvm->arch.host_xcr0 = 0;
	}

	/* Record time at boot (creation) */
	gethrestime(&kvm->arch.boot_wallclock);

	return (kvm);
}

static void
kvm_unload_vcpu_mmu(struct kvm_vcpu *vcpu)
{
	vcpu_load(vcpu);
	kvm_mmu_unload(vcpu);
	vcpu_put(vcpu);
}

static void
kvm_free_vcpus(struct kvm *kvmp)
{
	int ii, maxcpus;

	maxcpus = kvmp->online_vcpus;

	for (ii = 0; ii < maxcpus; ii++)
		kvm_unload_vcpu_mmu(kvmp->vcpus[ii]);

	for (ii = 0; ii < maxcpus; ii++)
		kvm_arch_vcpu_free(kvmp->vcpus[ii]);

	mutex_enter(&kvmp->lock);
	for (ii = 0; ii < maxcpus; ii++)
		kvmp->vcpus[ii] = NULL;
	kvmp->online_vcpus = 0;
	mutex_exit(&kvmp->lock);
}

/*
 * This function exists because of a difference in methodologies from our
 * ancestor. With our ancestors, there is no imputus to clean up lists and
 * mutexes. This is unfortunate, because they seem to even have debug kernels
 * which would seemingly check for these kinds of things. But because in the
 * common case mutex_exit is currently a #define to do {} while(0), it seems
 * that they just ignore this.
 *
 * This leads to the following behavior: during our time we create a lot of
 * auxillary structs potentially related to pits, apics, etc. Tearing down these
 * structures relies on having the correct locks, etc. However
 * kvm_arch_destroy_vm() is designed to be the final death blow, i.e. it's doing
 * the kmem_free. Logically these auxillary structures need to be freed and
 * dealt with before we go back and do the rest of the tear down related to the
 * device.
 */
void
kvm_arch_destroy_vm_comps(struct kvm *kvmp)
{
	if (kvmp == NULL)
		return;

	kvm_free_pit(kvmp);
	kvm_free_vcpus(kvmp);
	kvm_free_physmem(kvmp);
#ifdef XXX
#ifdef APIC
	if (kvm->arch.apic_access_page)
		put_page(kvm->arch.apic_access_page);
	if (kvm->arch.ept_identity_pagetable)
		put_page(kvm->arch.ept_identity_pagetable);
#endif /* APIC */
#else
	XXX_KVM_PROBE;
#endif /* XXX */
}

void
kvm_arch_destroy_vm(struct kvm *kvmp)
{
	if (kvmp == NULL)
		return;  /* nothing to do here */

	if (kvmp->arch.aliases) {
		kmem_free(kvmp->arch.aliases, sizeof (struct kvm_mem_aliases));
		kvmp->arch.aliases = NULL;
	}
	kmem_free(kvmp, sizeof (struct kvm));
}

int
kvm_arch_prepare_memory_region(struct kvm *kvm,
    struct kvm_memory_slot *memslot, struct kvm_memory_slot old,
    struct kvm_userspace_memory_region *mem, int user_alloc)
{
	unsigned int npages = memslot->npages;
	uint64_t i;

	/*
	 * To keep backward compatibility with older userspace, x86 needs to
	 * handle !user_alloc case.
	 */
	if (!user_alloc) {
		if (npages && !old.rmap) {
			caddr_t userspace_addr = NULL;

			userspace_addr = smmap64(NULL,
			    (size_t)(npages * PAGESIZE),
			    PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON,
			    -1, 0);

			/*
			 * the mmap sets up the mapping, but there are no pages
			 * allocated. Code sets up the shadow page tables
			 * before the pages are allocated, so there are invalid
			 * pages in the map.  We'll touch the pages so they get
			 * allocated here.
			 */
			i = memcntl(userspace_addr, (size_t)(npages * PAGESIZE),
				    MC_LOCK, 0, PROT_READ | PROT_WRITE, 0);
			if (i != 0)
				return (i);
			for (i = 0; i < npages; i++) {
				if (copyout(empty_zero_page, userspace_addr +
				    (i * PAGESIZE), sizeof (empty_zero_page))) {
					cmn_err(CE_WARN, "could not copy to "
					    "mmap page\n");
				}
			}

			memslot->userspace_addr =
			    (unsigned long)userspace_addr;
		}
	}

	return (0);
}

void
kvm_arch_commit_memory_region(struct kvm *kvm,
    struct kvm_userspace_memory_region *mem, struct kvm_memory_slot old,
    int user_alloc)
{

	int npages = mem->memory_size >> PAGESHIFT;

	if (!user_alloc && !old.user_alloc && old.rmap && !npages) {
		int ret = 0;

		/* see comment in kvm_arch_prepare_memory_region */
		kmem_free((caddr_t)old.userspace_addr, old.npages * PAGESIZE);

		if (ret < 0) {
			cmn_err(CE_WARN, "kvm_vm_ioctl_set_memory_region: "
			    "failed to munmap memory\n");
		}
	}

	mutex_enter(&kvm->mmu_lock);
	if (!kvm->arch.n_requested_mmu_pages) {
		unsigned int nr_mmu_pages = kvm_mmu_calculate_mmu_pages(kvm);
		kvm_mmu_change_mmu_pages(kvm, nr_mmu_pages);
	}

	kvm_mmu_slot_remove_write_access(kvm, mem->slot);
	mutex_exit(&kvm->mmu_lock);
}

void
kvm_arch_flush_shadow(struct kvm *kvm)
{
	kvm_mmu_zap_all(kvm);
	kvm_reload_remote_mmus(kvm);
}

int
kvm_arch_vcpu_runnable(struct kvm_vcpu *vcpu)
{
	return (vcpu->arch.mp_state == KVM_MP_STATE_RUNNABLE ||
	    vcpu->arch.mp_state == KVM_MP_STATE_SIPI_RECEIVED ||
	    vcpu->arch.nmi_pending ||
	    (kvm_arch_interrupt_allowed(vcpu) && kvm_cpu_has_interrupt(vcpu)));
}

void
kvm_vcpu_kick(struct kvm_vcpu *vcpu)
{
	processorid_t cpu = vcpu->cpu;

	mutex_enter(&vcpu->kvcpu_kick_lock);

	if (CV_HAS_WAITERS(&vcpu->kvcpu_kick_cv))
		KVM_VCPU_KSTAT_INC(vcpu, kvmvs_halt_wakeup);

	cv_broadcast(&vcpu->kvcpu_kick_cv);
	mutex_exit(&vcpu->kvcpu_kick_lock);

	if (cpu != CPU->cpu_id && cpu != -1) {
		if (!test_and_set_bit(KVM_REQ_KICK, &vcpu->requests)) {
			/*
			 * If we haven't already kicked this VCPU, we'll poke
			 * the the CPU on which it's running.  (This will serve
			 * to induce a VM exit.)
			 */
			poke_cpu(cpu);
		}
	}
}

int
kvm_arch_interrupt_allowed(struct kvm_vcpu *vcpu)
{
	return (kvm_x86_ops->interrupt_allowed(vcpu));
}

unsigned long
kvm_get_rflags(struct kvm_vcpu *vcpu)
{
	unsigned long rflags;

	rflags = kvm_x86_ops->get_rflags(vcpu);

	if (vcpu->guest_debug & KVM_GUESTDBG_SINGLESTEP)
		rflags &= ~(unsigned long)(X86_EFLAGS_TF | X86_EFLAGS_RF);

	return (rflags);
}

void
kvm_set_rflags(struct kvm_vcpu *vcpu, unsigned long rflags)
{
	if (vcpu->guest_debug & KVM_GUESTDBG_SINGLESTEP &&
	    vcpu->arch.singlestep_cs == get_segment_selector(vcpu,
	    VCPU_SREG_CS) && vcpu->arch.singlestep_rip == kvm_rip_read(vcpu)) {
		rflags |= X86_EFLAGS_TF | X86_EFLAGS_RF;
	}

	kvm_x86_ops->set_rflags(vcpu, rflags);
}

gpa_t
gfn_to_gpa(gfn_t gfn)
{
	return ((gpa_t)gfn << PAGESHIFT);
}

/*
 * For pages for which vmx needs physical addresses,
 * linux allocates pages from an area that maps virtual
 * addresses 1-1 with physical memory.  In this way,
 * translating virtual to physical just involves subtracting
 * the start of the area from the virtual address.
 * This solaris version uses kmem_alloc, so there is no
 * direct mapping of virtual to physical.  We'll change this
 * later if performance is an issue.  For now, we'll use
 * hat_getpfnum() to do the conversion.  Also note that
 * we're assuming 64-bit address space (we won't run on
 * 32-bit hardware).
 */
uint64_t
kvm_va2pa(caddr_t va)
{
	uint64_t pa;

	pa = (hat_getpfnum(kas.a_hat, va)<<PAGESHIFT)|((uint64_t)va&PAGEOFFSET);
	return (pa);
}

uint32_t
get_rdx_init_val(void)
{
	return (0x600); /* P6 family */
}

unsigned long long
native_read_msr(unsigned int msr)
{
	DECLARE_ARGS(val, low, high);

	__asm__ volatile("rdmsr" : EAX_EDX_RET(val, low, high) : "c" (msr));
	return (EAX_EDX_VAL(val, low, high));
}

/* See __vmx_load_host_state(). */
#pragma weak native_write_msr = dtrace_native_write_msr
void
dtrace_native_write_msr(unsigned int msr, unsigned low, unsigned high)
{
	__asm__ volatile("wrmsr" : : "c" (msr),
	    "a"(low), "d" (high) : "memory");
}

unsigned long long
__native_read_tsc(void)
{
	DECLARE_ARGS(val, low, high);

	__asm__ volatile("rdtsc" : EAX_EDX_RET(val, low, high));

	return (EAX_EDX_VAL(val, low, high));
}

unsigned long long
native_read_pmc(int counter)
{
	DECLARE_ARGS(val, low, high);

	__asm__ volatile("rdpmc" : EAX_EDX_RET(val, low, high) : "c" (counter));
	return (EAX_EDX_VAL(val, low, high));
}

int
wrmsr_safe(unsigned msr, unsigned low, unsigned high)
{
	return (native_write_msr_safe(msr, low, high));
}

int
rdmsrl_safe(unsigned msr, unsigned long long *p)
{
	int err;

	*p = native_read_msr_safe(msr, &err);
	return (err);
}

unsigned long
read_msr(unsigned long msr)
{
	uint64_t value;

	rdmsrl(msr, value);
	return (value);
}

uint64_t
native_read_msr_safe(unsigned int msr, int *err)
{
	DECLARE_ARGS(val, low, high);
	uint64_t ret = 0;
	on_trap_data_t otd;

	if (on_trap(&otd, OT_DATA_ACCESS) == 0) {
		ret = native_read_msr(msr);
		*err = 0;
	} else {
		*err = EINVAL;
	}
	no_trap();

	return (ret);
}

/* Can be uninlined because referenced by paravirt */
int
native_write_msr_safe(unsigned int msr, unsigned low, unsigned high)
{
	int err = 0;
	on_trap_data_t otd;

	if (on_trap(&otd, OT_DATA_ACCESS) == 0) {
		native_write_msr(msr, low, high);
	} else {
		err = EINVAL;
	}
	no_trap();

	return (err);
}

unsigned long
kvm_read_tr_base(void)
{
	unsigned short tr;
	__asm__("str %0" : "=g"(tr));
	return (segment_base(tr));
}

unsigned short
kvm_read_fs(void)
{
	unsigned short seg;
	__asm__("mov %%fs, %0" : "=g"(seg));
	return (seg);
}

unsigned short
kvm_read_gs(void)
{
	unsigned short seg;
	__asm__("mov %%gs, %0" : "=g"(seg));
	return (seg);
}

unsigned short
kvm_read_ldt(void)
{
	unsigned short ldt;
	__asm__("sldt %0" : "=g"(ldt));
	return (ldt);
}

void
kvm_load_fs(unsigned short sel)
{
	__asm__("mov %0, %%fs" : : "rm"(sel));
}

/* See __vmx_load_host_state(). */
#pragma weak kvm_load_gs = dtrace_kvm_load_gs
void
dtrace_kvm_load_gs(unsigned short sel)
{
	__asm__("mov %0, %%gs" : : "rm"(sel));
}

void
kvm_load_ldt(unsigned short sel)
{
	__asm__("lldt %0" : : "rm"(sel));
}


void
kvm_get_idt(struct descriptor_table *table)
{
	__asm__("sidt %0" : "=m"(*table));
}

void
kvm_get_gdt(struct descriptor_table *table)
{
	__asm__("sgdt %0" : "=m"(*table));
}

/*
 * Volatile isn't enough to prevent the compiler from reordering the
 * read/write functions for the control registers and messing everything up.
 * A memory clobber would solve the problem, but would prevent reordering of
 * all loads stores around it, which can hurt performance. Solution is to
 * use a variable and mimic reads and writes to it to enforce serialization
 */
static unsigned long __force_order;

unsigned long
native_read_cr0(void)
{
	unsigned long val;
	__asm__ volatile("mov %%cr0,%0\n\t" : "=r" (val), "=m" (__force_order));
	return (val);
}

unsigned long
native_read_cr4(void)
{
	unsigned long val;
	__asm__ volatile("mov %%cr4,%0\n\t" : "=r" (val), "=m" (__force_order));
	return (val);
}

unsigned long
native_read_cr3(void)
{
	unsigned long val;
	__asm__ volatile("mov %%cr3,%0\n\t" : "=r" (val), "=m" (__force_order));
	return (val);
}

unsigned long
get_desc_limit(const struct desc_struct *desc)
{
	return (desc->c.b.limit0 | (desc->c.b.limit << 16));
}

unsigned long
get_desc_base(const struct desc_struct *desc)
{
	return (unsigned)(desc->c.b.base0 | ((desc->c.b.base1) << 16) |
	    ((desc->c.b.base2) << 24));
}

void
kvm_clear_exception_queue(struct kvm_vcpu *vcpu)
{
	vcpu->arch.exception.pending = 0;
}

void
kvm_queue_interrupt(struct kvm_vcpu *vcpu, uint8_t vector, int soft)
{
	vcpu->arch.interrupt.pending = 1;
	vcpu->arch.interrupt.soft = soft;
	vcpu->arch.interrupt.nr = vector;
}

void
kvm_clear_interrupt_queue(struct kvm_vcpu *vcpu)
{
	vcpu->arch.interrupt.pending = 0;
}

int
kvm_event_needs_reinjection(struct kvm_vcpu *vcpu)
{
	return (vcpu->arch.exception.pending || vcpu->arch.interrupt.pending ||
	    vcpu->arch.nmi_injected);
}

int
kvm_exception_is_soft(unsigned int nr)
{
	return (nr == BP_VECTOR) || (nr == OF_VECTOR);
}

int
is_protmode(struct kvm_vcpu *vcpu)
{
	return (kvm_read_cr0_bits(vcpu, X86_CR0_PE));
}

int
is_long_mode(struct kvm_vcpu *vcpu)
{
	return (vcpu->arch.efer & EFER_LMA);
}

int
is_pae(struct kvm_vcpu *vcpu)
{
	return (kvm_read_cr4_bits(vcpu, X86_CR4_PAE));
}

int
is_pse(struct kvm_vcpu *vcpu)
{
	return (kvm_read_cr4_bits(vcpu, X86_CR4_PSE));
}

int
is_paging(struct kvm_vcpu *vcpu)
{
	return (kvm_read_cr0_bits(vcpu, X86_CR0_PG));
}

uint32_t
bit(int bitno)
{
	return (1 << (bitno & 31));
}
