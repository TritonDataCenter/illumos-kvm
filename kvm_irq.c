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
 * Copyright 2011 Joyent, Inc. All rights reserved.
 */

#include "kvm_host.h"
#include "kvm_i8254.h"
#include "kvm_irq.h"

struct kvm_pic *
pic_irqchip(struct kvm *kvm)
{
	return (kvm->arch.vpic);
}

int
irqchip_in_kernel(struct kvm *kvm)
{
	int ret;

	ret = (pic_irqchip(kvm) != NULL);
	smp_rmb();
	return (ret);
}

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

/*
 * check if there is pending interrupt without intack.
 */
int
kvm_cpu_has_interrupt(struct kvm_vcpu *v)
{
	struct kvm_pic *s;

	if (!irqchip_in_kernel(v->kvm))
		return (v->arch.interrupt.pending);

	if (kvm_apic_has_interrupt(v) == -1) {	/* LAPIC */
		if (kvm_apic_accept_pic_intr(v)) {
			s = pic_irqchip(v->kvm);	/* PIC */
			return (s->output);
		} else
			return (0);
	}
	return (1);
}

/*
 * Read pending interrupt vector and intack.
 */
int
kvm_cpu_get_interrupt(struct kvm_vcpu *v)
{
	struct kvm_pic *s;
	int vector;

	if (!irqchip_in_kernel(v->kvm))
		return (v->arch.interrupt.nr);

	vector = kvm_get_apic_interrupt(v);	/* APIC */
	if (vector == -1) {
		if (kvm_apic_accept_pic_intr(v)) {
			s = pic_irqchip(v->kvm);
			s->output = 0;		/* PIC */
			vector = kvm_pic_read_irq(v->kvm);
		}
	}

	return (vector);
}

void
kvm_inject_pending_timer_irqs(struct kvm_vcpu *vcpu)
{
	kvm_inject_apic_timer_irqs(vcpu);
	kvm_inject_pit_timer_irqs(vcpu);
	/* TODO: PIT, RTC etc. */
}
