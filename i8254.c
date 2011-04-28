/*
 * 8253/8254 interval timer emulation
 *
 * Copyright (c) 2003-2004 Fabrice Bellard
 * Copyright (c) 2006 Intel Corporation
 * Copyright (c) 2007 Keir Fraser, XenSource Inc
 * Copyright (c) 2008 Intel Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * Authors:
 *   Sheng Yang <sheng.yang@intel.com>
 *   Based on QEMU and Xen.
 *
 * This has been ported to illumos by Joyent.
 * Copyright 2011 Joyent, Inc. All rights reserved.
 */

/*
 * XXX Need proper header files!
 */
#include "msr.h"
#include "irqflags.h"
#include "kvm_host.h"
#include "kvm_x86host.h"
#include "iodev.h"
#include "kvm.h"
#include "irq.h"

extern int kvm_vcpu_is_bsp(struct kvm_vcpu *vcpu);

int
pit_has_pending_timer(struct kvm_vcpu *vcpu)
{
	struct kvm_pit *pit = vcpu->kvm->arch.vpit;

#ifdef XXX
	if (pit && kvm_vcpu_is_bsp(vcpu) && pit->pit_state.irq_ack)
		return (atomic_read(&pit->pit_state.pit_timer.pending));
#else
	XXX_KVM_SYNC_PROBE;
	if (pit && kvm_vcpu_is_bsp(vcpu) && pit->pit_state.irq_ack)
		return (pit->pit_state.pit_timer.pending);
#endif
	return (0);
}

static void
__inject_pit_timer_intr(struct kvm *kvm)
{
	struct kvm_vcpu *vcpu;
	int i;

	kvm_set_irq(kvm, kvm->arch.vpit->irq_source_id, 0, 1);
	kvm_set_irq(kvm, kvm->arch.vpit->irq_source_id, 0, 0);

	/*
	 * Provides NMI watchdog support via Virtual Wire mode.
	 * The route is: PIT -> PIC -> LVT0 in NMI mode.
	 *
	 * Note: Our Virtual Wire implementation is simplified, only
	 * propagating PIT interrupts to all VCPUs when they have set
	 * LVT0 to NMI delivery. Other PIC interrupts are just sent to
	 * VCPU0, and only if its LVT0 is in EXTINT mode.
	 */
	if (kvm->arch.vapics_in_nmi_mode > 0)
		kvm_for_each_vcpu(i, vcpu, kvm)
			kvm_apic_nmi_wd_deliver(vcpu);
}

void
kvm_inject_pit_timer_irqs(struct kvm_vcpu *vcpu)
{
	struct kvm_pit *pit = vcpu->kvm->arch.vpit;
	struct kvm *kvm = vcpu->kvm;
	struct kvm_kpit_state *ps;

	if (pit) {
		int inject = 0;
		ps = &pit->pit_state;

		/*
		 * Try to inject pending interrupts when
		 * last one has been acked.
		 */
#ifdef XXX
		raw_spin_lock(&ps->inject_lock);
		if (atomic_read(&ps->pit_timer.pending) && ps->irq_ack) {
			ps->irq_ack = 0;
			inject = 1;
		}
		raw_spin_unlock(&ps->inject_lock);
#else
		XXX_KVM_SYNC_PROBE;
		mutex_enter(&ps->inject_lock);
		if (&ps->pit_timer.pending && ps->irq_ack) {
			ps->irq_ack = 0;
			inject = 1;
		}
		mutex_exit(&ps->inject_lock);
#endif
		if (inject)
			__inject_pit_timer_intr(kvm);
	}
}

void
kvm_free_pit(struct kvm *kvmp)
{
	struct kvm_timer *kptp;

	if (kvmp->arch.vpit == NULL)
		return;

	mutex_enter(&kvmp->arch.vpit->pit_state.lock);
	kvm_unregister_irq_mask_notifier(kvmp, 0,
	    &kvmp->arch.vpit->mask_notifier);
	kvm_unregister_irq_ack_notifier(kvmp,
	    &kvmp->arch.vpit->pit_state.irq_ack_notifier);
	mutex_exit(&kvmp->arch.vpit->pit_state.lock);

	mutex_enter(&cpu_lock);
	kptp = &kvmp->arch.vpit->pit_state.pit_timer;
	if (kptp->active)
		cyclic_remove(kptp->kvm_cyclic_id);
	mutex_exit(&cpu_lock);
	mutex_destroy(&kvmp->arch.vpit->pit_state.lock);
	kvm_free_irq_source_id(kvmp, kvmp->arch.vpit->irq_source_id);
	kmem_free(kvmp->arch.vpit, sizeof (struct kvm_pit));
	kvmp->arch.vpit = NULL;
}
