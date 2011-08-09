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

#ifndef __KVM_TYPES_H__
#define	__KVM_TYPES_H__

#include <sys/stdint.h>

/*
 * Address types:
 *
 *  gva - guest virtual address
 *  gpa - guest physical address
 *  gfn - guest frame number
 *  hva - host virtual address
 *  hpa - host physical address
 *  hfn - host frame number
 */

typedef unsigned long	gva_t;
typedef uint64_t	gpa_t;
typedef unsigned long	gfn_t;

typedef unsigned long	hva_t;
typedef uint64_t	hpa_t;
typedef unsigned long	hfn_t;

union kvm_ioapic_redirect_entry {
	uint64_t bits;
	struct {
		uint8_t vector;
		uint8_t delivery_mode:3;
		uint8_t dest_mode:1;
		uint8_t delivery_status:1;
		uint8_t polarity:1;
		uint8_t remote_irr:1;
		uint8_t trig_mode:1;
		uint8_t mask:1;
		uint8_t reserve:7;
		uint8_t reserved[4];
		uint8_t dest_id;
	} fields;
};

typedef struct kvm_lapic_irq {
	uint32_t vector;
	uint32_t delivery_mode;
	uint32_t dest_mode;
	uint32_t level;
	uint32_t trig_mode;
	uint32_t shorthand;
	uint32_t dest_id;
} kvm_lapic_irq_t;

#endif /* __KVM_TYPES_H__ */
