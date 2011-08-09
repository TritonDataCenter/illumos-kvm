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

#include "kvm_iodev.h"
#include <sys/errno.h>

void
kvm_iodevice_init(struct kvm_io_device *dev,
    const struct kvm_io_device_ops *ops)
{
	dev->ops = ops;
}

int
kvm_iodevice_read(struct kvm_io_device *dev,
    gpa_t addr, int l, void *v)
{
	return (dev->ops->read ? dev->ops->read(dev, addr, l, v) : -EOPNOTSUPP);
}

int
kvm_iodevice_write(struct kvm_io_device *dev,
    gpa_t addr, int l, const void *v)
{
	return (dev->ops->write ? dev->ops->write(dev, addr, l, v) :
	    -EOPNOTSUPP);
}

void
kvm_iodevice_destructor(struct kvm_io_device *dev)
{
	if (dev->ops->destructor)
		dev->ops->destructor(dev);
}
