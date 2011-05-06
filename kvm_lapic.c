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
 * Ported to illumos by Joyent.
 * Copyright 2011 Joyent, Inc. All rights reserved.
 */

#include <sys/atomic.h>

/*
 * XXX Need proper header files!
 */
#include "msr.h"
#include "irqflags.h"
#include "kvm_host.h"
#include "kvm_x86host.h"
#include "iodev.h"
#include "kvm.h"
#include "apicdef.h"
#include "irq.h"

extern uint32_t apic_get_reg(struct kvm_lapic *, int);
extern int apic_enabled(struct kvm_lapic *);
extern int apic_hw_enabled(struct kvm_lapic *);
extern int __apic_accept_irq(struct kvm_lapic *, int, int, int, int);
extern caddr_t page_address(page_t *);

static int
apic_lvt_enabled(struct kvm_lapic *apic, int lvt_type)
{
	return (!(apic_get_reg(apic, lvt_type) & APIC_LVT_MASKED));
}

int
apic_has_pending_timer(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *lapic = vcpu->arch.apic;

#ifdef XXX
	if (lapic && apic_enabled(lapic) && apic_lvt_enabled(lapic, APIC_LVTT))
		return (atomic_read(&lapic->lapic_timer.pending));
#else
	XXX_KVM_SYNC_PROBE;
	if (lapic && apic_enabled(lapic) && apic_lvt_enabled(lapic, APIC_LVTT))
		return (lapic->lapic_timer.pending);
#endif

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
kvm_inject_apic_timer_irqs(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;

#ifdef XXX
	if (apic && atomic_read(&apic->lapic_timer.pending) > 0) {
		if (kvm_apic_local_deliver(apic, APIC_LVTT))
			atomic_dec(&apic->lapic_timer.pending);
	}
#else
	XXX_KVM_SYNC_PROBE;
	if (apic && apic->lapic_timer.pending > 0) {
		if (kvm_apic_local_deliver(apic, APIC_LVTT))
			atomic_dec_32(&apic->lapic_timer.pending);
	}
#endif
}

void
kvm_apic_nmi_wd_deliver(struct kvm_vcpu *vcpu)
{
	struct kvm_lapic *apic = vcpu->arch.apic;

	if (apic)
		kvm_apic_local_deliver(apic, APIC_LVT0);
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
