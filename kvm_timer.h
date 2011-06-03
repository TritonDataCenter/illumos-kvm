/*
 * Ported from Linux by Joyent.
 * Copyright 2011 Joyent, Inc.
 */

#ifndef __KVM_TIMER_H__
#define __KVM_TIMER_H__

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
