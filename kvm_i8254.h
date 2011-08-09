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

#ifndef __KVM_I8254_H
#define	__KVM_I8254_H

#include "kvm_iodev.h"
#include "kvm_timer.h"

typedef struct kvm_kpit_channel_state {
	uint32_t count; /* can be 65536 */
	uint16_t latched_count;
	uint8_t count_latched;
	uint8_t status_latched;
	uint8_t status;
	uint8_t read_state;
	uint8_t write_state;
	uint8_t write_latch;
	uint8_t rw_mode;
	uint8_t mode;
	uint8_t bcd; /* not supported */
	uint8_t gate; /* timer start */
	hrtime_t count_load_time;
} kvm_kpit_channel_state_t;

typedef struct kvm_kpit_state {
	struct kvm_kpit_channel_state channels[3];
	uint32_t flags;
	struct kvm_timer pit_timer;
	int is_periodic;
	uint32_t    speaker_data_on;
	kmutex_t lock;
	struct kvm_pit *pit;
	kmutex_t inject_lock;
	unsigned long irq_ack;
	struct kvm_irq_ack_notifier irq_ack_notifier;
} kvm_kpit_state_t;

typedef struct kvm_pit {
	unsigned long base_addresss;
	struct kvm_io_device dev;
	struct kvm_io_device speaker_dev;
	struct kvm *kvm;
	struct kvm_kpit_state pit_state;
	int irq_source_id;
	struct kvm_irq_mask_notifier mask_notifier;
} kvm_pit_t;

#define	KVM_PIT_BASE_ADDRESS	    0x40
#define	KVM_SPEAKER_BASE_ADDRESS    0x61
#define	KVM_PIT_MEM_LENGTH	    4
#define	KVM_PIT_FREQ		    1193181
#define	KVM_MAX_PIT_INTR_INTERVAL   HZ / 100
#define	KVM_PIT_CHANNEL_MASK	    0x3

extern void kvm_inject_pit_timer_irqs(struct kvm_vcpu *);
extern void kvm_pit_load_count(struct kvm *, int, uint32_t, boolean_t);
extern struct kvm_pit *kvm_create_pit(struct kvm *, uint32_t);
extern void kvm_free_pit(struct kvm *);
extern void kvm_pit_reset(struct kvm_pit *);

#endif
