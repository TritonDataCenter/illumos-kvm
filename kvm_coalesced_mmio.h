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
 */
#ifndef __KVM_COALESCED_MMIO_H__
#define	__KVM_COALESCED_MMIO_H__

/*
 * KVM coalesced MMIO
 *
 * Copyright (c) 2008 Bull S.A.S.
 *
 *  Author: Laurent Vivier <Laurent.Vivier@bull.net>
 *
 * Copyright (c) 2011 Joyent, Inc.
 *
 */
#include <sys/mutex.h>

#include "kvm_iodev.h"

#define	KVM_COALESCED_MMIO_ZONE_MAX 100

/* for KVM_REGISTER_COALESCED_MMIO / KVM_UNREGISTER_COALESCED_MMIO */

typedef struct kvm_coalesced_mmio_dev {
	struct kvm_io_device dev;
	struct kvm *kvm;
	kmutex_t lock;
	int nb_zones;
	struct kvm_coalesced_mmio_zone zone[KVM_COALESCED_MMIO_ZONE_MAX];
} kvm_coalesced_mmio_dev_t;

extern int kvm_coalesced_mmio_init(struct kvm *);
extern void kvm_coalesced_mmio_free(struct kvm *);
extern int kvm_vm_ioctl_register_coalesced_mmio(struct kvm *,
    struct kvm_coalesced_mmio_zone *);
extern int kvm_vm_ioctl_unregister_coalesced_mmio(struct kvm *,
    struct kvm_coalesced_mmio_zone *);

#endif /* __KVM_COALESCED_MMIO_H__ */
