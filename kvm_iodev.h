/*
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
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright 2011 various Linux Kernel contributors.
 * Copyright 2011 Joyent, Inc. All Rights Reserved.
 */

#ifndef __KVM_IODEV_H__
#define	__KVM_IODEV_H__

#include "kvm_types.h"

struct kvm_io_device;

/*
 * kvm_io_device_ops are called under kvm slots_lock.
 * read and write handlers return 0 if the transaction has been handled,
 * or non-zero to have it passed to the next device.
 */
typedef struct kvm_io_device_ops {
	int (*read)(struct kvm_io_device *, gpa_t, int, void *);
	int (*write)(struct kvm_io_device *, gpa_t, int, const void *);
	void (*destructor)(struct kvm_io_device *);
} kvm_io_device_ops_t;


typedef struct kvm_io_device {
	struct kvm_lapic *lapic;
	const struct kvm_io_device_ops *ops;
} kvm_io_device_t;

extern void kvm_iodevice_init(struct kvm_io_device *,
    const struct kvm_io_device_ops *);

extern int kvm_iodevice_read(struct kvm_io_device *,
    gpa_t, int, void *);

extern int kvm_iodevice_write(struct kvm_io_device *,
    gpa_t, int, const void *);

extern void kvm_iodevice_destructor(struct kvm_io_device *);

#endif /* __KVM_IODEV_H__ */
