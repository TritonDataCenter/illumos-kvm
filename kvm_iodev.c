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
 */
/*
 * Copyright 2011, Joyent Inc. All Rights Reserved.
 */

/*
 * XXX Everytime I do this I die a bit more inside ~ rm
 * Please save me from header file hell!
 */
#include "vmx.h"
#include "msr.h"
#include "kvm_host.h"
#include "kvm_x86host.h"
#include "iodev.h"
#include "kvm.h"

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
