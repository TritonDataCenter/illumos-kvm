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

void kvm_inject_pending_timer_irqs(struct kvm_vcpu *vcpu)
{
	kvm_inject_apic_timer_irqs(vcpu);
	kvm_inject_pit_timer_irqs(vcpu);
	/* TODO: PIT, RTC etc. */
}
