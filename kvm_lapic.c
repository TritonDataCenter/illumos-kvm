/*
 * Local APIC virtualization
 *
 * Copyright (C) 2006 Qumranet, Inc.
 * Copyright (C) 2007 Novell
 * Copyright (C) 2007 Intel
 *
 * Authors:
 *   Dor Laor <dor.laor@qumranet.com>
 *   Gregory Haskins <ghaskins@novell.com>
 *   Yaozu (Eddie) Dong <eddie.dong@intel.com>
 *
 * Based on Xen 3.1 code, Copyright (c) 2004, Intel Corporation.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Copyright (c) 2012 Joyent, Inc. All rights reserved.
 */
#include <sys/types.h>
#include <sys/atomic.h>

#include "kvm_bitops.h"
#include "kvm_msr.h"
#include "kvm_apicdef.h"
#include "kvm_cpuid.h"
#include "kvm_x86host.h"
#include "kvm_x86impl.h"
#include "kvm_lapic.h"
#include "kvm_ioapic.h"
#include "kvm_irq.h"

static int __apic_accept_irq(struct kvm_lapic *, int, int, int, int);

#define	APIC_BUS_CYCLE_NS 1
#define	APIC_LDR	0xD0

#define	LAPIC_MMIO_LENGTH		(1 << 12)
/* followed define is not in apicdef.h */
#define	APIC_SHORT_MASK			0xc0000
#define	APIC_DEST_NOSHORT		0x0
#define	APIC_DEST_MASK			0x800
#define	MAX_APIC_VECTOR			256


#define	LVT_MASK	\
	(APIC_LVT_MASKED | APIC_SEND_PENDING | APIC_VECTOR_MASK)

#define	LINT_MASK	\
	(LVT_MASK | APIC_MODE_MASK | APIC_INPUT_POLARITY | \
	APIC_LVT_REMOTE_IRR | APIC_LVT_LEVEL_TRIGGER)

#define	VEC_POS(v) ((v) & (32 - 1))
#define	REG_POS(v) (((v) >> 5) << 4)


uint32_t
apic_get_reg(struct kvm_lapic *apic, int reg_off)
{
	return (*((uint32_t *)((uintptr_t)apic->regs + reg_off)));
}

void
apic_set_reg(struct kvm_lapic *apic, int reg_off, uint32_t val)
{
	*((uint32_t *)((uintptr_t)apic->regs + reg_off)) = val;
}

static int
apic_test_and_set_vector(int vec, caddr_t bitmap)
{
	return (test_and_set_bit(VEC_POS(vec), (unsigned long *)(bitmap +
	    REG_POS(vec))));
}

static int
apic_test_and_clear_vector(int vec, caddr_t bitmap)
{
	return (test_and_clear_bit(VEC_POS(vec),
	    (unsigned long *)(bitmap + REG_POS(vec))));
}

void
apic_set_vector(int vec, caddr_t bitmap)
{
	set_bit(VEC_POS(vec), (unsigned long *)(bitmap + REG_POS(vec)));
}

void
apic_clear_vector(int vec, caddr_t bitmap)
{
	clear_bit(VEC_POS(vec), (unsigned long *)(bitmap + REG_POS(vec)));
}

int
apic_hw_enabled(struct kvm_lapic *apic)
{
	return ((apic)->vcpu->arch.apic_base & MSR_IA32_APICBASE_ENABLE);
}

int
apic_sw_enabled(struct kvm_lapic *apic)
{
	return (apic_get_reg(apic, APIC_SPIV) & APIC_SPIV_APIC_ENABLED);
}

int
apic_enabled(struct kvm_lapic *apic)
{
	return (apic_sw_enabled(apic) && apic_hw_enabled(apic));
}

int
kvm_apic_id(struct kvm_lapic *apic)
{
	return ((apic_get_reg(apic, APIC_ID) >> 24) & 0xff);
}

static int
apic_lvt_enabled(struct kvm_lapic *apic, int lvt_type)
{
	return (!(apic_get_reg(apic, lvt_type) & APIC_LVT_MASKED));
}

static int
apic_lvtt_period(struct kvm_lapic *apic)
{
	return (apic_get_reg(apic, APIC_LVTT) & APIC_LVT_TIMER_PERIODIC);
}

static int
apic_lvt_nmi_mode(uint32_t lvt_val)
{
	return ((lvt_val & (APIC_MODE_MASK | APIC_LVT_MASKED)) == APIC_DM_NMI);
}

void
kvm_apic_set_version(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;
	struct kvm_cpuid_entry2 *feat;
	uint32_t v = APIC_VERSION;

	if (!irqchip_in_kernel(vcpu->kvm))
		return;

	feat = kvm_find_cpuid_entry(apic->vcpu, 0x1, 0);
	if (feat && (feat->ecx & (1 << (X86_FEATURE_X2APIC & 31))))
		v |= APIC_LVR_DIRECTED_EOI;
	apic_set_reg(apic, APIC_LVR, v);
}

static int
apic_x2apic_mode(struct kvm_lapic *apic)
{
	return (apic->vcpu->arch.apic_base & X2APIC_ENABLE);
}

static unsigned int apic_lvt_mask[APIC_LVT_NUM] = {
	LVT_MASK | APIC_LVT_TIMER_PERIODIC,	/* LVTT */
	LVT_MASK | APIC_MODE_MASK,	/* LVTTHMR */
	LVT_MASK | APIC_MODE_MASK,	/* LVTPC */
	LINT_MASK, LINT_MASK,	/* LVT0-1 */
	LVT_MASK		/* LVTERR */
};

static int
fls(int x)
{
	int r = 32;

	if (!x)
		return (0);

	if (!(x & 0xffff0000u)) {
		x <<= 16;
		r -= 16;
	}
	if (!(x & 0xff000000u)) {
		x <<= 8;
		r -= 8;
	}
	if (!(x & 0xf0000000u)) {
		x <<= 4;
		r -= 4;
	}
	if (!(x & 0xc0000000u)) {
		x <<= 2;
		r -= 2;
	}
	if (!(x & 0x80000000u)) {
		x <<= 1;
		r -= 1;
	}

	return (r);
}

static int
find_highest_vector(void *bitmap)
{
	uint32_t *word = bitmap;
	int word_offset = MAX_APIC_VECTOR >> 5;

	while ((word_offset != 0) && (word[(--word_offset) << 2] == 0))
		continue;

	if (!word_offset && !word[0])
		return (-1);
	else
		return (fls(word[word_offset << 2]) - 1 + (word_offset << 5));
}

static int
apic_test_and_set_irr(int vec, struct kvm_lapic *apic)
{
	apic->irr_pending = 1;
	return (apic_test_and_set_vector(vec, (void *)((uintptr_t)apic->regs +
	    APIC_IRR)));
}

static int
apic_search_irr(struct kvm_lapic *apic)
{
	return (find_highest_vector((void *)((uintptr_t)apic->regs +
	    APIC_IRR)));
}

static int
apic_find_highest_irr(struct kvm_lapic *apic)
{
	int result;

	if (!apic->irr_pending)
		return (-1);

	result = apic_search_irr(apic);
	ASSERT(result == -1 || result >= 16);

	return (result);
}

static void
apic_clear_irr(int vec, struct kvm_lapic *apic)
{
	apic->irr_pending = 0;
	apic_clear_vector(vec, (void *)((uintptr_t)apic->regs + APIC_IRR));
	if (apic_search_irr(apic) != -1)
		apic->irr_pending = 1;
}

int
kvm_lapic_find_highest_irr(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;
	int highest_irr;

	/*
	 * This may race with setting of irr in __apic_accept_irq() and
	 * value returned may be wrong, but kvm_vcpu_kick() in __apic_accept_irq
	 * will cause vmexit immediately and the value will be recalculated
	 * on the next vmentry.
	 */
	if (!apic)
		return (0);

	highest_irr = apic_find_highest_irr(apic);

	return (highest_irr);
}

int
kvm_apic_set_irq(struct kvm_vcpu *vcpu, struct kvm_lapic_irq *irq)
{
	struct kvm_lapic *apic = vcpu->arch.apic;

	return (__apic_accept_irq(apic, irq->delivery_mode, irq->vector,
	    irq->level, irq->trig_mode));
}

int
apic_find_highest_isr(struct kvm_lapic *apic)
{
	int ret;

	ret = find_highest_vector((void *)((uintptr_t)apic->regs + APIC_ISR));
	ASSERT(ret == -1 || ret >= 16);

	return (ret);
}

void
apic_update_ppr(struct kvm_lapic *apic)
{
	uint32_t tpr, isrv, ppr;
	int isr;

	tpr = apic_get_reg(apic, APIC_TASKPRI);
	isr = apic_find_highest_isr(apic);
	isrv = (isr != -1) ? isr : 0;

	if ((tpr & 0xf0) >= (isrv & 0xf0))
		ppr = tpr & 0xff;
	else
		ppr = isrv & 0xf0;

	apic_set_reg(apic, APIC_PROCPRI, ppr);
}

void
apic_set_tpr(struct kvm_lapic *apic, uint32_t tpr)
{
	apic_set_reg(apic, APIC_TASKPRI, tpr);
	apic_update_ppr(apic);
}

int
kvm_apic_match_physical_addr(struct kvm_lapic *apic, uint16_t dest)
{
	return (dest == 0xff || kvm_apic_id(apic) == dest);
}

int
kvm_apic_match_logical_addr(struct kvm_lapic *apic, uint8_t mda)
{
	int result = 0;
	uint32_t logical_id;

	if (apic_x2apic_mode(apic)) {
		logical_id = apic_get_reg(apic, APIC_LDR);
		return (logical_id & mda);
	}

	logical_id = GET_APIC_LOGICAL_ID(apic_get_reg(apic, APIC_LDR));

	switch (apic_get_reg(apic, APIC_DFR)) {
	case APIC_DFR_FLAT:
		if (logical_id & mda)
			result = 1;
		break;
	case APIC_DFR_CLUSTER:
		if (((logical_id >> 4) == (mda >> 0x4)) &&
		    (logical_id & mda & 0xf))
			result = 1;
		break;
	default:
		cmn_err(CE_WARN, "Bad DFR vcpu %d: %08x\n",
		    apic->vcpu->vcpu_id, apic_get_reg(apic, APIC_DFR));
		break;
	}

	return (result);
}

int
kvm_apic_match_dest(struct kvm_vcpu *vcpu, struct kvm_lapic *source,
    int short_hand, int dest, int dest_mode)
{
	int result = 0;
	struct kvm_lapic *target = vcpu->arch.apic;

	ASSERT(target != NULL);
	switch (short_hand) {
	case APIC_DEST_NOSHORT:
		if (dest_mode == 0)
			/* Physical mode. */
			result = kvm_apic_match_physical_addr(target, dest);
		else
			/* Logical mode. */
			result = kvm_apic_match_logical_addr(target, dest);
		break;
	case APIC_DEST_SELF:
		result = (target == source);
		break;
	case APIC_DEST_ALLINC:
		result = 1;
		break;
	case APIC_DEST_ALLBUT:
		result = (target != source);
		break;
	default:
		cmn_err(CE_WARN, "Bad dest shorthand value %x\n", short_hand);
		break;
	}

	return (result);
}

/*
 * Add a pending IRQ into lapic.
 * Return 1 if successfully added and 0 if discarded.
 */
static int
__apic_accept_irq(struct kvm_lapic *apic, int delivery_mode,
    int vector, int level, int trig_mode)
{
	int result = 0;
	struct kvm_vcpu *vcpu = apic->vcpu;

	switch (delivery_mode) {
	case APIC_DM_LOWEST:
		vcpu->arch.apic_arb_prio++;
	case APIC_DM_FIXED:
		/* FIXME add logic for vcpu on reset */
		if (!apic_enabled(apic))
			break;

		if (trig_mode) {
			apic_set_vector(vector, (void *)((uintptr_t)apic->regs +
			    APIC_TMR));
		} else
			apic_clear_vector(vector,
			    (void *)((uintptr_t)apic->regs + APIC_TMR));

		result = !apic_test_and_set_irr(vector, apic);
		if (!result) {
			break;
		}

		kvm_vcpu_kick(vcpu);
		break;

	case APIC_DM_REMRD:
		break;

	case APIC_DM_SMI:
		break;

	case APIC_DM_NMI:
		result = 1;
		kvm_inject_nmi(vcpu);
		kvm_vcpu_kick(vcpu);
		break;

	case APIC_DM_INIT:
		if (level) {
			result = 1;
			vcpu->arch.mp_state = KVM_MP_STATE_INIT_RECEIVED;
			kvm_vcpu_kick(vcpu);
		}
		break;

	case APIC_DM_STARTUP:
		if (vcpu->arch.mp_state == KVM_MP_STATE_INIT_RECEIVED) {
			result = 1;
			vcpu->arch.sipi_vector = vector;
			vcpu->arch.mp_state = KVM_MP_STATE_SIPI_RECEIVED;
			kvm_vcpu_kick(vcpu);
		}
		break;

	case APIC_DM_EXTINT:
		/*
		 * Should only be called by kvm_apic_local_deliver() with LVT0,
		 * before NMI watchdog was enabled. Already handled by
		 * kvm_apic_accept_pic_intr().
		 */
		break;

	default:
		break;
	}

	return (result);
}

int
kvm_apic_compare_prio(struct kvm_vcpu *vcpu1, struct kvm_vcpu *vcpu2)
{
	return (vcpu1->arch.apic_arb_prio - vcpu2->arch.apic_arb_prio);
}

static void
apic_set_eoi(struct kvm_lapic *apic)
{
	int vector = apic_find_highest_isr(apic);
	int trigger_mode;
	/*
	 * Not every write EOI will has corresponding ISR,
	 * one example is when Kernel check timer on setup_IO_APIC
	 */
	if (vector == -1)
		return;

	apic_clear_vector(vector, (void *)((uintptr_t)apic->regs + APIC_ISR));
	apic_update_ppr(apic);

	if (apic_test_and_clear_vector(vector, (void *)((uintptr_t)apic->regs +
	    APIC_TMR)))
		trigger_mode = IOAPIC_LEVEL_TRIG;
	else
		trigger_mode = IOAPIC_EDGE_TRIG;
	if (!(apic_get_reg(apic, APIC_SPIV) & APIC_SPIV_DIRECTED_EOI))
		kvm_ioapic_update_eoi(apic->vcpu->kvm, vector, trigger_mode);
}

static void
apic_send_ipi(struct kvm_lapic *apic)
{
	uint32_t icr_low = apic_get_reg(apic, APIC_ICR);
	uint32_t icr_high = apic_get_reg(apic, APIC_ICR2);
	struct kvm_lapic_irq irq;

	irq.vector = icr_low & APIC_VECTOR_MASK;
	irq.delivery_mode = icr_low & APIC_MODE_MASK;
	irq.dest_mode = icr_low & APIC_DEST_MASK;
	irq.level = icr_low & APIC_INT_ASSERT;
	irq.trig_mode = icr_low & APIC_INT_LEVELTRIG;
	irq.shorthand = icr_low & APIC_SHORT_MASK;
	if (apic_x2apic_mode(apic))
		irq.dest_id = icr_high;
	else
		irq.dest_id = GET_APIC_DEST_FIELD(icr_high);

	KVM_TRACE2(apic__ipi, uint32_t, icr_low, uint32_t, irq.dest_id);
	kvm_irq_delivery_to_apic(apic->vcpu->kvm, apic, &irq);
}

static uint32_t
apic_get_tmcct(struct kvm_lapic *apic)
{
	hrtime_t now, remaining, elapsed;
	uint32_t tmcct;

	VERIFY(apic != NULL);

	/* if initial count is 0, current count should also be 0 */
	if (apic_get_reg(apic, APIC_TMICT) == 0)
		return (0);

	now = gethrtime();
	elapsed = now - apic->lapic_timer.start -
	    apic->lapic_timer.period * apic->lapic_timer.intervals;
	remaining = apic->lapic_timer.period - elapsed;

	if (remaining < 0)
		remaining = 0;

	remaining = remaining % apic->lapic_timer.period;
	tmcct = remaining / (APIC_BUS_CYCLE_NS * apic->divide_count);

	return (tmcct);
}

static void
__report_tpr_access(struct kvm_lapic *apic, int write)
{
	struct kvm_vcpu *vcpu = apic->vcpu;
	struct kvm_run *run = vcpu->run;

	set_bit(KVM_REQ_REPORT_TPR_ACCESS, &vcpu->requests);
	run->tpr_access.rip = kvm_rip_read(vcpu);
	run->tpr_access.is_write = write;
}

static void
report_tpr_access(struct kvm_lapic *apic, int write)
{
	if (apic->vcpu->arch.tpr_access_reporting)
		__report_tpr_access(apic, write);
}

static uint32_t
__apic_read(struct kvm_lapic *apic, unsigned int offset)
{
	uint32_t val = 0;

	if (offset >= LAPIC_MMIO_LENGTH)
		return (0);

	switch (offset) {
	case APIC_ID:
		if (apic_x2apic_mode(apic))
			val = kvm_apic_id(apic);
		else
			val = kvm_apic_id(apic) << 24;
		break;
	case APIC_ARBPRI:
		cmn_err(CE_WARN, "Access APIC ARBPRI register "
		    "which is for P6\n");
		break;

	case APIC_TMCCT:	/* Timer CCR */
		val = apic_get_tmcct(apic);
		break;

	case APIC_TASKPRI:
		report_tpr_access(apic, 0);
		/* fall thru */
	default:
		apic_update_ppr(apic);
		val = apic_get_reg(apic, offset);
		break;
	}

	return (val);
}

static struct kvm_lapic *
to_lapic(struct kvm_io_device *dev)
{
	return ((struct kvm_lapic *)((uintptr_t)dev -
	    offsetof(struct kvm_lapic, dev)));
}

int
apic_reg_read(struct kvm_lapic *apic, uint32_t offset, int len, void *data)
{
	unsigned char alignment = offset & 0xf;
	uint32_t result;
	/* this bitmask has a bit cleared for each reserver register */
	static const uint64_t rmask = 0x43ff01ffffffe70cULL;

	if ((alignment + len) > 4) {
		return (1);
	}

	if (offset > 0x3f0 || !(rmask & (1ULL << (offset >> 4)))) {
		return (1);
	}

	result = __apic_read(apic, offset & ~0xf);
	KVM_TRACE2(apic__read, uint32_t, offset, uint32_t, result);

	switch (len) {
	case 1:
	case 2:
	case 4:
		memcpy(data, (char *)&result + alignment, len);
		break;
	default:
		cmn_err(CE_WARN, "Local APIC read with len = %x, "
		    "should be 1,2, or 4 instead\n", len);
		break;
	}

	return (0);
}

static int
apic_mmio_in_range(struct kvm_lapic *apic, gpa_t addr)
{
	return (apic_hw_enabled(apic) &&
	    addr >= apic->base_address &&
	    addr < apic->base_address + LAPIC_MMIO_LENGTH);
}

static int
apic_mmio_read(struct kvm_io_device *this, gpa_t address, int len, void *data)
{
	struct kvm_lapic *apic = to_lapic(this);
	uint32_t offset = address - apic->base_address;

	if (!apic_mmio_in_range(apic, address))
		return (-EOPNOTSUPP);

	apic_reg_read(apic, offset, len, data);

	return (0);
}

void
update_divide_count(struct kvm_lapic *apic)
{
	uint32_t tmp1, tmp2, tdcr;

	tdcr = apic_get_reg(apic, APIC_TDCR);
	tmp1 = tdcr & 0xf;
	tmp2 = ((tmp1 & 0x3) | ((tmp1 & 0x8) >> 1)) + 1;
	apic->divide_count = 0x1 << (tmp2 & 0x7);
}

void
start_apic_timer(struct kvm_lapic *apic)
{
	hrtime_t now = gethrtime(), when;
	struct kvm_timer *timer = &apic->lapic_timer;

	timer->period = (uint64_t)apic_get_reg(apic, APIC_TMICT) *
	    APIC_BUS_CYCLE_NS * apic->divide_count;

	if (timer->active) {
		if (timer->period != 0 && !apic_lvtt_period(apic) &&
		    timer->kvm_cyc_when.cyt_interval == CY_INFINITY) {
			/*
			 * If we were a one-shot timer and we remain a
			 * one-shot timer, we will cyclic_reprogram() instead
			 * of horsing around with removing and re-adding
			 * the cyclic.
			 */
			timer->start = gethrtime();
			timer->kvm_cyc_when.cyt_when = when =
			    timer->start + timer->period;
			timer->intervals = 0;
			cyclic_reprogram(timer->kvm_cyclic_id, when);
			return;
		}

		mutex_enter(&cpu_lock);
		cyclic_remove(timer->kvm_cyclic_id);
		timer->active = 0;
		mutex_exit(&cpu_lock);
	}

	if (!timer->period)
		return;

	mutex_enter(&cpu_lock);

	timer->start = gethrtime();

	/*
	 * Do not allow the guest to program periodic timers with small
	 * interval, since the hrtimers are not throttled by the host
	 * scheduler.
	 *
	 * If it is a one shot, we want to program it differently.
	 */
	if (apic_lvtt_period(apic)) {
		if (timer->period < NSEC_PER_MSEC / 2)
			timer->period = NSEC_PER_MSEC / 2;
		timer->kvm_cyc_when.cyt_when = 0;
		timer->kvm_cyc_when.cyt_interval = timer->period;
	} else {
		timer->kvm_cyc_when.cyt_when = timer->start + timer->period;
		timer->kvm_cyc_when.cyt_interval = CY_INFINITY;
	}

	timer->kvm_cyclic_id =
	    cyclic_add(&timer->kvm_cyc_handler, &timer->kvm_cyc_when);
	timer->active = 1;
	timer->intervals = 0;
	mutex_exit(&cpu_lock);
}

static void
apic_manage_nmi_watchdog(struct kvm_lapic *apic, uint32_t lvt0_val)
{
	int nmi_wd_enabled = apic_lvt_nmi_mode(apic_get_reg(apic, APIC_LVT0));

	if (apic_lvt_nmi_mode(lvt0_val)) {
		if (!nmi_wd_enabled)
			apic->vcpu->kvm->arch.vapics_in_nmi_mode++;
	} else if (nmi_wd_enabled)
		apic->vcpu->kvm->arch.vapics_in_nmi_mode--;
}

int
apic_reg_write(struct kvm_lapic *apic, uint32_t reg, uint32_t val)
{
	int ret = 0;

	KVM_TRACE2(apic__write, uint32_t, reg, uint32_t, val);

	switch (reg) {
	case APIC_ID:		/* Local APIC ID */
		if (!apic_x2apic_mode(apic))
			apic_set_reg(apic, APIC_ID, val);
		else
			ret = 1;
		break;

	case APIC_TASKPRI:
		report_tpr_access(apic, 1);
		apic_set_tpr(apic, val & 0xff);
		break;

	case APIC_EOI:
		apic_set_eoi(apic);
		break;

	case APIC_LDR:
		if (!apic_x2apic_mode(apic))
			apic_set_reg(apic, APIC_LDR, val & APIC_LDR_MASK);
		else
			ret = 1;
		break;

	case APIC_DFR:
		if (!apic_x2apic_mode(apic))
			apic_set_reg(apic, APIC_DFR, val | 0x0FFFFFFF);
		else
			ret = 1;
		break;

	case APIC_SPIV: {
		uint32_t mask = 0x3ff;
		if (apic_get_reg(apic, APIC_LVR) & APIC_LVR_DIRECTED_EOI)
			mask |= APIC_SPIV_DIRECTED_EOI;
		apic_set_reg(apic, APIC_SPIV, val & mask);
		if (!(val & APIC_SPIV_APIC_ENABLED)) {
			int i;
			uint32_t lvt_val;

			for (i = 0; i < APIC_LVT_NUM; i++) {
				lvt_val = apic_get_reg(apic,
				    APIC_LVTT + 0x10 * i);
				apic_set_reg(apic, APIC_LVTT + 0x10 * i,
				    lvt_val | APIC_LVT_MASKED);
			}
			apic->lapic_timer.pending = 0;
		}
		break;
	}
	case APIC_ICR:
		/* No delay here, so we always clear the pending bit */
		apic_set_reg(apic, APIC_ICR, val & ~(1 << 12));
		apic_send_ipi(apic);
		break;

	case APIC_ICR2:
		if (!apic_x2apic_mode(apic))
			val &= 0xff000000;
		apic_set_reg(apic, APIC_ICR2, val);
		break;

	case APIC_LVT0:
		apic_manage_nmi_watchdog(apic, val);
	case APIC_LVTT:
	case APIC_LVTTHMR:
	case APIC_LVTPC:
	case APIC_LVT1:
	case APIC_LVTERR:
		/* TODO: Check vector */
		if (!apic_sw_enabled(apic))
			val |= APIC_LVT_MASKED;

		val &= apic_lvt_mask[(reg - APIC_LVTT) >> 4];
		apic_set_reg(apic, reg, val);

		break;

	case APIC_TMICT:
		apic_set_reg(apic, APIC_TMICT, val);
		start_apic_timer(apic);
		break;

	case APIC_TDCR:
		if (val & 4)
			cmn_err(CE_WARN, "KVM_WRITE:TDCR %x\n", val);
		apic_set_reg(apic, APIC_TDCR, val);
		update_divide_count(apic);
		break;

	case APIC_ESR:
		if (apic_x2apic_mode(apic) && val != 0) {
			cmn_err(CE_WARN, "KVM_WRITE:ESR not zero %x\n", val);
			ret = 1;
		}
		break;

	case APIC_SELF_IPI:
		if (apic_x2apic_mode(apic)) {
			apic_reg_write(apic, APIC_ICR, 0x40000 | (val & 0xff));
		} else
			ret = 1;
		break;
	default:
		ret = 1;
		break;
	}

	return (ret);
}

static int
apic_mmio_write(struct kvm_io_device *this,
    gpa_t address, int len, const void *data)
{
	struct kvm_lapic *apic = to_lapic(this);
	unsigned int offset = address - apic->base_address;
	uint32_t val;

	if (!apic_mmio_in_range(apic, address))
		return (-EOPNOTSUPP);

	/*
	 * APIC register must be aligned on 128-bits boundary.
	 * 32/64/128 bits registers must be accessed thru 32 bits.
	 * Refer SDM 8.4.1
	 */
	if (len != 4 || (offset & 0xf)) {
		/* Don't shout loud, $infamous_os would cause only noise. */
		return (0);
	}

	val = *(uint32_t *)data;

	apic_reg_write(apic, offset & 0xff0, val);

	return (0);
}

void
kvm_free_lapic(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;
	if (apic == NULL)
		return;

	mutex_enter(&cpu_lock);
	if (apic->lapic_timer.active)
		cyclic_remove(apic->lapic_timer.kvm_cyclic_id);
	mutex_exit(&cpu_lock);

	if (apic->regs)
		kmem_free(apic->regs, PAGESIZE);

	kmem_free(vcpu->arch.apic, sizeof (struct kvm_lapic));
}

/*
 * Local APIC interface.
 */
void
kvm_lapic_set_tpr(struct kvm_vcpu *vcpu, unsigned long cr8)
{
	struct kvm_lapic *apic = vcpu->arch.apic;

	if (!apic)
		return;

	apic_set_tpr(apic, ((cr8 & 0x0f) << 4) |
	    (apic_get_reg(apic, APIC_TASKPRI) & 4));
}

uint64_t
kvm_lapic_get_cr8(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;
	uint64_t tpr;

	if (apic == NULL)
		return (0);

	tpr = (uint64_t)apic_get_reg(apic, APIC_TASKPRI);

	return ((tpr & 0xf0) >> 4);
}

void
kvm_lapic_set_base(struct kvm_vcpu *vcpu, uint64_t value)
{
	struct kvm_lapic *apic = vcpu->arch.apic;

	if (!apic) {
		value |= MSR_IA32_APICBASE_BSP;
		vcpu->arch.apic_base = value;
		return;
	}

	if (!kvm_vcpu_is_bsp(apic->vcpu))
		value &= ~MSR_IA32_APICBASE_BSP;

	vcpu->arch.apic_base = value;
	if (apic_x2apic_mode(apic)) {
		uint32_t id = kvm_apic_id(apic);
		uint32_t ldr = ((id & ~0xf) << 16) | (1 << (id & 0xf));
		apic_set_reg(apic, APIC_LDR, ldr);
	}

	apic->base_address = apic->vcpu->arch.apic_base &
	    MSR_IA32_APICBASE_BASE;
}

void
kvm_lapic_reset(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic;
	int i;

	ASSERT(vcpu);
	apic = vcpu->arch.apic;
	ASSERT(apic != NULL);

	/* Stop the timer in case it's a reset to an active apic */
	mutex_enter(&cpu_lock);
	if (apic->lapic_timer.active) {
		cyclic_remove(apic->lapic_timer.kvm_cyclic_id);
		apic->lapic_timer.active = 0;
	}
	mutex_exit(&cpu_lock);

	apic_set_reg(apic, APIC_ID, vcpu->vcpu_id << 24);
	kvm_apic_set_version(apic->vcpu);

	for (i = 0; i < APIC_LVT_NUM; i++)
		apic_set_reg(apic, APIC_LVTT + 0x10 * i, APIC_LVT_MASKED);

	apic_set_reg(apic, APIC_LVT0,
	    SET_APIC_DELIVERY_MODE(0, APIC_MODE_EXTINT));

	apic_set_reg(apic, APIC_DFR, 0xffffffffU);
	apic_set_reg(apic, APIC_SPIV, 0xff);
	apic_set_reg(apic, APIC_TASKPRI, 0);
	apic_set_reg(apic, APIC_LDR, 0);
	apic_set_reg(apic, APIC_ESR, 0);
	apic_set_reg(apic, APIC_ICR, 0);
	apic_set_reg(apic, APIC_ICR2, 0);
	apic_set_reg(apic, APIC_TDCR, 0);
	apic_set_reg(apic, APIC_TMICT, 0);
	for (i = 0; i < 8; i++) {
		apic_set_reg(apic, APIC_IRR + 0x10 * i, 0);
		apic_set_reg(apic, APIC_ISR + 0x10 * i, 0);
		apic_set_reg(apic, APIC_TMR + 0x10 * i, 0);
	}
	apic->irr_pending = 0;
	update_divide_count(apic);
	apic->lapic_timer.pending = 0;

	if (kvm_vcpu_is_bsp(vcpu))
		vcpu->arch.apic_base |= MSR_IA32_APICBASE_BSP;
	apic_update_ppr(apic);

	vcpu->arch.apic_arb_prio = 0;

	cmn_err(CE_CONT, "!%s: vcpu=%p, id=%d, base_msr= %lx PRIx64 "
	    "base_address=%lx\n", __func__, vcpu, kvm_apic_id(apic),
	    vcpu->arch.apic_base, apic->base_address);
}

int
kvm_apic_present(struct kvm_vcpu *vcpu)
{
	return (vcpu->arch.apic && apic_hw_enabled(vcpu->arch.apic));
}

int
kvm_lapic_enabled(struct kvm_vcpu *vcpu)
{
	return (kvm_apic_present(vcpu) && apic_sw_enabled(vcpu->arch.apic));
}

/*
 * APIC timer interface
 */
static int
lapic_is_periodic(struct kvm_timer *ktimer)
{
	struct kvm_lapic *apic = (struct kvm_lapic *)((caddr_t)ktimer -
	    offsetof(struct kvm_lapic, lapic_timer));

	return (apic_lvtt_period(apic));
}

int
apic_has_pending_timer(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *lapic = vcpu->arch.apic;

	if (lapic && apic_enabled(lapic) && apic_lvt_enabled(lapic, APIC_LVTT))
		return (lapic->lapic_timer.pending);

	return (0);
}

static int
kvm_apic_local_deliver(struct kvm_lapic *apic, int lvt_type)
{
	uint32_t reg = apic_get_reg(apic, lvt_type);
	int vector, mode, trig_mode;

	if (apic_hw_enabled(apic) && !(reg & APIC_LVT_MASKED)) {
		vector = reg & APIC_VECTOR_MASK;
		mode = reg & APIC_MODE_MASK;
		trig_mode = reg & APIC_LVT_LEVEL_TRIGGER;
		return (__apic_accept_irq(apic, mode, vector, 1, trig_mode));
	}
	return (0);
}

void
kvm_apic_nmi_wd_deliver(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;

	if (apic)
		kvm_apic_local_deliver(apic, APIC_LVT0);
}

static struct kvm_timer_ops lapic_timer_ops = {
	.is_periodic = lapic_is_periodic,
};

static const struct kvm_io_device_ops apic_mmio_ops = {
	.read	= apic_mmio_read,
	.write	= apic_mmio_write,
};

int
kvm_create_lapic(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic;

	ASSERT(vcpu != NULL);

	apic = kmem_zalloc(sizeof (*apic), KM_SLEEP);
	if (!apic)
		goto nomem;

	vcpu->arch.apic = apic;

	apic->regs = kmem_zalloc(PAGESIZE, KM_SLEEP);
	memset(apic->regs, 0, PAGESIZE);
	apic->vcpu = vcpu;

	apic->lapic_timer.kvm_cyc_handler.cyh_func = kvm_timer_fire;
	apic->lapic_timer.kvm_cyc_handler.cyh_arg = &apic->lapic_timer;
	apic->lapic_timer.kvm_cyc_handler.cyh_level = CY_LOW_LEVEL;
	apic->lapic_timer.active = 0;

	apic->lapic_timer.t_ops = &lapic_timer_ops;
	apic->lapic_timer.kvm = vcpu->kvm;
	apic->lapic_timer.vcpu = vcpu;

	apic->base_address = APIC_DEFAULT_PHYS_BASE;
	vcpu->arch.apic_base = APIC_DEFAULT_PHYS_BASE;

	kvm_lapic_reset(vcpu);
	kvm_iodevice_init(&apic->dev, &apic_mmio_ops);
	apic->dev.lapic = apic;

	return (0);
nomem_free_apic:
	if (apic)
		kmem_free(apic, sizeof (struct kvm_lapic));
nomem:
	return (-ENOMEM);
}

int
kvm_apic_has_interrupt(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;
	int highest_irr;

	if (!apic || !apic_enabled(apic))
		return (-1);

	apic_update_ppr(apic);
	highest_irr = apic_find_highest_irr(apic);
	if ((highest_irr == -1) ||
	    ((highest_irr & 0xF0) <= apic_get_reg(apic, APIC_PROCPRI)))
		return (-1);

	return (highest_irr);
}

int
kvm_apic_accept_pic_intr(struct kvm_vcpu *vcpu)
{
	uint32_t lvt0 = apic_get_reg(vcpu->arch.apic, APIC_LVT0);
	int r = 0;

	if (kvm_vcpu_is_bsp(vcpu)) {
		if (!apic_hw_enabled(vcpu->arch.apic))
			r = 1;
		if ((lvt0 & APIC_LVT_MASKED) == 0 &&
		    GET_APIC_DELIVERY_MODE(lvt0) == APIC_MODE_EXTINT)
			r = 1;
	}

	return (r);
}

void
kvm_inject_apic_timer_irqs(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;

	if (apic && apic->lapic_timer.pending > 0) {
		if (kvm_apic_local_deliver(apic, APIC_LVTT))
			atomic_dec_32((volatile uint32_t *)&apic->
			    lapic_timer.pending);
	}
}

int
kvm_get_apic_interrupt(struct kvm_vcpu *vcpu)
{
	int vector = kvm_apic_has_interrupt(vcpu);
	struct kvm_lapic *apic = vcpu->arch.apic;

	if (vector == -1)
		return (-1);

	apic_set_vector(vector, (void *)((uintptr_t)apic->regs + APIC_ISR));
	apic_update_ppr(apic);
	apic_clear_irr(vector, apic);

	return (vector);
}

void
kvm_apic_post_state_restore(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;

	apic->base_address = vcpu->arch.apic_base &
	    MSR_IA32_APICBASE_BASE;
	kvm_apic_set_version(vcpu);

	apic_update_ppr(apic);
	update_divide_count(apic);
	start_apic_timer(apic);

	apic->irr_pending = 1;
}

void
kvm_lapic_sync_from_vapic(struct kvm_vcpu *vcpu)
{
	uint32_t data;
	void *vapic;

	if (!irqchip_in_kernel(vcpu->kvm) || !vcpu->arch.apic->vapic_addr)
		return;

	vapic = page_address(vcpu->arch.apic->vapic_page);

	data = *(uint32_t *)((uintptr_t)vapic +
	    offset_in_page(vcpu->arch.apic->vapic_addr));

	apic_set_tpr(vcpu->arch.apic, data & 0xff);
}

void
kvm_lapic_sync_to_vapic(struct kvm_vcpu *vcpu)
{
	uint32_t data, tpr;
	int max_irr, max_isr;
	struct kvm_lapic *apic;
	void *vapic;

	if (!irqchip_in_kernel(vcpu->kvm) || !vcpu->arch.apic->vapic_addr)
		return;

	apic = vcpu->arch.apic;
	tpr = apic_get_reg(apic, APIC_TASKPRI) & 0xff;
	max_irr = apic_find_highest_irr(apic);
	if (max_irr < 0)
		max_irr = 0;
	max_isr = apic_find_highest_isr(apic);
	if (max_isr < 0)
		max_isr = 0;
	data = (tpr & 0xff) | ((max_isr & 0xf0) << 8) | (max_irr << 24);

	vapic = page_address(vcpu->arch.apic->vapic_page);

	*(uint32_t *)((uintptr_t)vapic +
	    offset_in_page(vcpu->arch.apic->vapic_addr)) = data;
}

int
kvm_lapic_set_vapic_addr(struct kvm_vcpu *vcpu, struct kvm_vapic_addr *va)
{
	if (!irqchip_in_kernel(vcpu->kvm))
		return (EINVAL);

	vcpu->arch.apic->vapic_addr = va->vapic_addr;

	return (0);
}

int
kvm_x2apic_msr_write(struct kvm_vcpu *vcpu, uint32_t msr, uint64_t data)
{
	struct kvm_lapic *apic = vcpu->arch.apic;
	uint32_t reg = (msr - APIC_BASE_MSR) << 4;

	if (!irqchip_in_kernel(vcpu->kvm) || !apic_x2apic_mode(apic))
		return (1);

	/* if this is ICR write vector before command */
	if (msr == 0x830)
		apic_reg_write(apic, APIC_ICR2, (uint32_t)(data >> 32));

	return (apic_reg_write(apic, reg, (uint32_t)data));
}

int
kvm_x2apic_msr_read(struct kvm_vcpu *vcpu, uint32_t msr, uint64_t *data)
{
	struct kvm_lapic *apic = vcpu->arch.apic;
	uint32_t reg = (msr - APIC_BASE_MSR) << 4, low, high = 0;

	if (!irqchip_in_kernel(vcpu->kvm) || !apic_x2apic_mode(apic))
		return (1);

	if (apic_reg_read(apic, reg, 4, &low))
		return (1);

	if (msr == 0x830)
		apic_reg_read(apic, APIC_ICR2, 4, &high);

	*data = (((uint64_t)high) << 32) | low;

	return (0);
}

int
kvm_hv_vapic_msr_write(struct kvm_vcpu *vcpu, uint32_t reg, uint64_t data)
{
	struct kvm_lapic *apic = vcpu->arch.apic;

	if (!irqchip_in_kernel(vcpu->kvm))
		return (1);

	/* if this is ICR write vector before command */
	if (reg == APIC_ICR)
		apic_reg_write(apic, APIC_ICR2, (uint32_t)(data >> 32));

	return (apic_reg_write(apic, reg, (uint32_t)data));
}

int
kvm_hv_vapic_msr_read(struct kvm_vcpu *vcpu, uint32_t reg, uint64_t *data)
{
	struct kvm_lapic *apic = vcpu->arch.apic;
	uint32_t low, high = 0;

	if (!irqchip_in_kernel(vcpu->kvm))
		return (1);

	if (apic_reg_read(apic, reg, 4, &low))
		return (1);

	if (reg == APIC_ICR)
		apic_reg_read(apic, APIC_ICR2, 4, &high);

	*data = (((uint64_t)high) << 32) | low;

	return (0);
}
