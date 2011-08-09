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
 * Copyright 2011 Joyent, Inc. All Rights Reserved.
 */

#ifndef __KVM_TIMER_H__
#define	__KVM_TIMER_H__

#include <sys/types.h>
#include <sys/cyclic.h>

typedef struct kvm_timer {
	cyclic_id_t kvm_cyclic_id;
	cyc_handler_t kvm_cyc_handler;
	cyc_time_t kvm_cyc_when;
	int active;
	int intervals;
	hrtime_t start;
	int64_t period; 		/* unit: ns */
	int pending;			/* accumulated triggered timers */
	int reinject;
	struct kvm_timer_ops *t_ops;
	struct kvm *kvm;
	struct kvm_vcpu *vcpu;
} kvm_timer_t;

typedef struct kvm_timer_ops {
	int (*is_periodic)(struct kvm_timer *);
} kvm_timer_ops_t;

extern void kvm_timer_fire(void *);

#endif
