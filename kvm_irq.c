/*
 * irq.c: API for in kernel interrupt controller
 * Copyright (c) 2007, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 * Authors:
 *   Yaozu (Eddie) Dong <Eddie.dong@intel.com>
 *
 * Ported to illumos by Joyent.
 * Copyright 2011 Joyent, Inc. All rights reserved.
 */

/*
 * XXX These header includes are really broken
 */
#include "msr.h"
#include "irqflags.h"
#include "kvm_host.h"
#include "kvm_x86host.h"
#include "iodev.h"
#include "kvm.h"
#include "irq.h"
#include "ioapic.h"

/* XXX This should never exist */
extern int irqchip_in_kernel(struct kvm *);

/*
 * check if there are pending timer events
 * to be processed.
 */
int
kvm_cpu_has_pending_timer(struct kvm_vcpu *vcpu)
{
	int ret;

	ret = pit_has_pending_timer(vcpu);
	ret |= apic_has_pending_timer(vcpu);

	return (ret);
}

void
kvm_inject_pending_timer_irqs(struct kvm_vcpu *vcpu)
{
	kvm_inject_apic_timer_irqs(vcpu);
	kvm_inject_pit_timer_irqs(vcpu);
	/* TODO: PIT, RTC etc. */
}

void
kvm_free_irq_source_id(struct kvm *kvm, int irq_source_id)
{
	int i;

	ASSERT(irq_source_id != KVM_USERSPACE_IRQ_SOURCE_ID);

	mutex_enter(&kvm->irq_lock);
	if (irq_source_id < 0 ||
	    irq_source_id >= BITS_PER_LONG) {
#ifdef XXX
		printk(KERN_ERR "kvm: IRQ source ID out of range!\n");
#else
		XXX_KVM_PROBE;
#endif
		goto unlock;
	}
	clear_bit(irq_source_id, &kvm->arch.irq_sources_bitmap);
	if (!irqchip_in_kernel(kvm))
		goto unlock;

	for (i = 0; i < KVM_IOAPIC_NUM_PINS; i++) {
		clear_bit(irq_source_id, &kvm->arch.vioapic->irq_states[i]);
		if (i >= 16)
			continue;
#ifdef CONFIG_X86
		clear_bit(irq_source_id, &pic_irqchip(kvm)->irq_states[i]);
#endif
	}
unlock:
	mutex_exit(&kvm->irq_lock);
}

void
__kvm_migrate_timers(struct kvm_vcpu *vcpu)
{
	__kvm_migrate_apic_timer(vcpu);
	__kvm_migrate_pit_timer(vcpu);
}
