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
 * Copyright 2011 Joyent, Inc. All rights reserved.
 */

#include <sys/debug.h>
#include <sys/mutex.h>

#include "kvm_host.h"
#include "kvm_irq.h"
#include "kvm_i8254.h"

#define	mod_64(x, y) ((x) % (y))

#define	RW_STATE_LSB 1
#define	RW_STATE_MSB 2
#define	RW_STATE_WORD0 3
#define	RW_STATE_WORD1 4

static uint64_t
muldiv64(uint64_t a, uint32_t b, uint32_t c)
{
	union {
		uint64_t ll;
		struct {
			uint32_t low, high;
		} l;
	} u, res;
	uint64_t rl, rh;

	u.ll = a;
	rl = (uint64_t)u.l.low * (uint64_t)b;
	rh = (uint64_t)u.l.high * (uint64_t)b;
	rh += (rl >> 32);
	res.l.high = rh/c;
	res.l.low = ((mod_64(rh, c) << 32) + (rl & 0xffffffff))/ c;

	return (res.ll);
}

static void
pit_set_gate(struct kvm *kvm, int channel, uint32_t val)
{
	struct kvm_kpit_channel_state *c =
	    &kvm->arch.vpit->pit_state.channels[channel];

	ASSERT(mutex_owned(&kvm->arch.vpit->pit_state.lock));

	switch (c->mode) {
	default:
	case 0:
	case 4:
		/* just disable/enable counting */
		break;
	case 1:
	case 2:
	case 3:
	case 5:
		/* Restart counting on rising edge. */
		if (c->gate < val)
			c->count_load_time = gethrtime();
		break;
	}

	c->gate = val;
}

static int
pit_get_gate(struct kvm *kvm, int channel)
{
	ASSERT(mutex_owned(&kvm->arch.vpit->pit_state.lock));

	return (kvm->arch.vpit->pit_state.channels[channel].gate);
}

static int64_t
__kpit_elapsed(struct kvm *kvm)
{
	int64_t elapsed;
	hrtime_t remaining, now;
	struct kvm_kpit_state *ps = &kvm->arch.vpit->pit_state;

	if (!ps->pit_timer.period)
		return (0);

	/*
	 * The Counter does not stop when it reaches zero. In
	 * Modes 0, 1, 4, and 5 the Counter ``wraps around'' to
	 * the highest count, either FFFF hex for binary counting
	 * or 9999 for BCD counting, and continues counting.
	 * Modes 2 and 3 are periodic; the Counter reloads
	 * itself with the initial count and continues counting
	 * from there.
	 */
	now = gethrtime();
	elapsed = now - ps->pit_timer.start -
	    ps->pit_timer.period * ps->pit_timer.intervals;
	remaining = ps->pit_timer.period - elapsed;
	elapsed = mod_64(elapsed, ps->pit_timer.period);

	return (elapsed);
}

static int64_t
kpit_elapsed(struct kvm *kvm, struct kvm_kpit_channel_state *c, int channel)
{
	if (channel == 0)
		return (__kpit_elapsed(kvm));

	return (gethrtime() - c->count_load_time);
}

static int
pit_get_count(struct kvm *kvm, int channel)
{
	struct kvm_kpit_channel_state *c =
	    &kvm->arch.vpit->pit_state.channels[channel];
	int64_t d, t;
	int counter;

	ASSERT(mutex_owned(&kvm->arch.vpit->pit_state.lock));

	t = kpit_elapsed(kvm, c, channel);
	d = muldiv64(t, KVM_PIT_FREQ, NSEC_PER_SEC);

	switch (c->mode) {
	case 0:
	case 1:
	case 4:
	case 5:
		counter = (c->count - d) & 0xffff;
		break;
	case 3:
		/* may be incorrect for odd counts */
		counter = c->count - (mod_64((2 * d), c->count));
		break;
	default:
		counter = c->count - mod_64(d, c->count);
		break;
	}

	return (counter);
}

static int
pit_get_out(struct kvm *kvm, int channel)
{
	struct kvm_kpit_channel_state *c =
	    &kvm->arch.vpit->pit_state.channels[channel];
	int64_t d, t;
	int out;

	ASSERT(mutex_owned(&kvm->arch.vpit->pit_state.lock));

	t = kpit_elapsed(kvm, c, channel);
	d = muldiv64(t, KVM_PIT_FREQ, NSEC_PER_SEC);

	switch (c->mode) {
	default:
	case 0:
		out = (d >= c->count);
		break;
	case 1:
		out = (d < c->count);
		break;
	case 2:
		out = ((mod_64(d, c->count) == 0) && (d != 0));
		break;
	case 3:
		out = (mod_64(d, c->count) < ((c->count + 1) >> 1));
		break;
	case 4:
	case 5:
		out = (d == c->count);
		break;
	}

	return (out);
}

static void
pit_latch_count(struct kvm *kvm, int channel)
{
	struct kvm_kpit_channel_state *c =
	    &kvm->arch.vpit->pit_state.channels[channel];

	ASSERT(mutex_owned(&kvm->arch.vpit->pit_state.lock));

	if (!c->count_latched) {
		c->latched_count = pit_get_count(kvm, channel);
		c->count_latched = c->rw_mode;
	}
}

static void
pit_latch_status(struct kvm *kvm, int channel)
{
	struct kvm_kpit_channel_state *c =
	    &kvm->arch.vpit->pit_state.channels[channel];

	ASSERT(mutex_owned(&kvm->arch.vpit->pit_state.lock));

	if (!c->status_latched) {
		/* TODO: Return NULL COUNT (bit 6). */
		c->status = ((pit_get_out(kvm, channel) << 7) |
		    (c->rw_mode << 4) | (c->mode << 1) | c->bcd);
		c->status_latched = 1;
	}
}

int
pit_has_pending_timer(struct kvm_vcpu *vcpu)
{
	struct kvm_pit *pit = vcpu->kvm->arch.vpit;

	if (pit && kvm_vcpu_is_bsp(vcpu) && pit->pit_state.irq_ack)
		return (pit->pit_state.pit_timer.pending);

	return (0);
}

static void
kvm_pit_ack_irq(struct kvm_irq_ack_notifier *kian)
{
	struct kvm_kpit_state *ps = (struct kvm_kpit_state *)(((caddr_t)kian) -
	    offsetof(struct kvm_kpit_state, irq_ack_notifier));
	mutex_enter(&ps->inject_lock);
	if (--ps->pit_timer.pending < 0)
		ps->pit_timer.pending++;
	ps->irq_ack = 1;
	mutex_exit(&ps->inject_lock);
}

static void
destroy_pit_timer(struct kvm_timer *pt)
{
	mutex_enter(&cpu_lock);

	if (pt->active) {
		cyclic_remove(pt->kvm_cyclic_id);
		pt->active = 0;
	}

	mutex_exit(&cpu_lock);
}

static int
kpit_is_periodic(struct kvm_timer *ktimer)
{
	struct kvm_kpit_state *ps = (struct kvm_kpit_state *)
	    (((caddr_t)ktimer) - offsetof(struct kvm_kpit_state, pit_timer));

	return (ps->is_periodic);
}

static struct kvm_timer_ops kpit_ops = {
	.is_periodic = kpit_is_periodic,
};

static void
create_pit_timer(struct kvm_kpit_state *ps, uint32_t val, int is_period)
{
	struct kvm_timer *pt = &ps->pit_timer;
	int64_t interval;

	interval = muldiv64(val, NSEC_PER_SEC, KVM_PIT_FREQ);

	mutex_enter(&cpu_lock);

	/* TODO The new value only affected after the retriggered */
	if (pt->active) {
		cyclic_remove(pt->kvm_cyclic_id);
		pt->active = 0;
	}
	pt->period = interval;
	ps->is_periodic = is_period;

	pt->kvm_cyc_handler.cyh_func = kvm_timer_fire;
	pt->kvm_cyc_handler.cyh_level = CY_LOW_LEVEL;
	pt->kvm_cyc_handler.cyh_arg = pt;
	pt->t_ops = &kpit_ops;
	pt->kvm = ps->pit->kvm;
	pt->vcpu = pt->kvm->bsp_vcpu;

	pt->pending = 0;
	ps->irq_ack = 1;
	pt->start = gethrtime();

	if (is_period) {
		pt->kvm_cyc_when.cyt_when = pt->start + pt->period;
		pt->kvm_cyc_when.cyt_interval = pt->period;
	} else {
		pt->kvm_cyc_when.cyt_when = pt->start + pt->period;
		pt->kvm_cyc_when.cyt_when = CY_INFINITY;
	}

	pt->kvm_cyclic_id = cyclic_add(&pt->kvm_cyc_handler, &pt->kvm_cyc_when);
	pt->intervals = 0;
	pt->active = 1;
	mutex_exit(&cpu_lock);
}

static void
pit_load_count(struct kvm *kvm, int channel, uint32_t val)
{
	struct kvm_kpit_state *ps = &kvm->arch.vpit->pit_state;

	ASSERT(mutex_owned(&ps->lock));

	/*
	 * The largest possible initial count is 0; this is equivalent
	 * to 216 for binary counting and 104 for BCD counting.
	 */
	if (val == 0)
		val = 0x10000;

	ps->channels[channel].count = val;

	if (channel != 0) {
		ps->channels[channel].count_load_time = gethrtime();
		return;
	}

	/*
	 * Two types of timer
	 * mode 1 is one shot, mode 2 is period, otherwise del timer
	 */
	switch (ps->channels[0].mode) {
	case 0:
	case 1:
		/* FIXME: enhance mode 4 precision */
	case 4:
		if (!(ps->flags & KVM_PIT_FLAGS_HPET_LEGACY))
			create_pit_timer(ps, val, 0);
		break;
	case 2:
	case 3:
		if (!(ps->flags & KVM_PIT_FLAGS_HPET_LEGACY))
			create_pit_timer(ps, val, 1);
		break;
	default:
		destroy_pit_timer(&ps->pit_timer);
	}
}

void
kvm_pit_load_count(struct kvm *kvm, int channel,
    uint32_t val, boolean_t hpet_legacy_start)
{
	uint8_t saved_mode;

	if (hpet_legacy_start) {
		/*
		 * Save existing mode for later reenablement.
		 */
		saved_mode = kvm->arch.vpit->pit_state.channels[0].mode;

		/*
		 * Set the mode to 0xff to disable the timer.
		 */
		kvm->arch.vpit->pit_state.channels[0].mode = 0xff;
		pit_load_count(kvm, channel, val);

		kvm->arch.vpit->pit_state.channels[0].mode = saved_mode;
	} else {
		pit_load_count(kvm, channel, val);
	}
}

static struct kvm_pit *
dev_to_pit(struct kvm_io_device *dev)
{
	return ((struct kvm_pit *)(((caddr_t)dev) -
	    offsetof(struct kvm_pit, dev)));
}

static struct kvm_pit *
speaker_to_pit(struct kvm_io_device *dev)
{
	struct kvm_pit *pit = (struct kvm_pit *)(((caddr_t)dev) -
	    offsetof(struct kvm_pit, speaker_dev));

	return (pit);
}

static int
pit_in_range(gpa_t addr)
{
	return ((addr >= KVM_PIT_BASE_ADDRESS) &&
	    (addr < KVM_PIT_BASE_ADDRESS + KVM_PIT_MEM_LENGTH));
}

static int
pit_ioport_write(struct kvm_io_device *this,
    gpa_t addr, int len, const void *data)
{
	struct kvm_pit *pit = dev_to_pit(this);
	struct kvm_kpit_state *pit_state = &pit->pit_state;
	struct kvm *kvm = pit->kvm;
	int channel, access;
	struct kvm_kpit_channel_state *s;
	uint32_t val = *(uint32_t *) data;

	if (!pit_in_range(addr))
		return (-EOPNOTSUPP);

	val  &= 0xff;
	addr &= KVM_PIT_CHANNEL_MASK;

	mutex_enter(&pit_state->lock);

	if (addr == 3) {
		channel = val >> 6;
		if (channel == 3) {
			/* Read-Back Command. */
			for (channel = 0; channel < 3; channel++) {
				s = &pit_state->channels[channel];
				if (val & (2 << channel)) {
					if (!(val & 0x20))
						pit_latch_count(kvm, channel);
					if (!(val & 0x10))
						pit_latch_status(kvm, channel);
				}
			}
		} else {
			/* Select Counter <channel>. */
			s = &pit_state->channels[channel];
			access = (val >> 4) & KVM_PIT_CHANNEL_MASK;
			if (access == 0) {
				pit_latch_count(kvm, channel);
			} else {
				s->rw_mode = access;
				s->read_state = access;
				s->write_state = access;
				s->mode = (val >> 1) & 7;
				if (s->mode > 5)
					s->mode -= 4;
				s->bcd = val & 1;
			}
		}
	} else {
		/* Write Count. */
		s = &pit_state->channels[addr];
		switch (s->write_state) {
		default:
		case RW_STATE_LSB:
			pit_load_count(kvm, addr, val);
			break;
		case RW_STATE_MSB:
			pit_load_count(kvm, addr, val << 8);
			break;
		case RW_STATE_WORD0:
			s->write_latch = val;
			s->write_state = RW_STATE_WORD1;
			break;
		case RW_STATE_WORD1:
			pit_load_count(kvm, addr, s->write_latch | (val << 8));
			s->write_state = RW_STATE_WORD0;
			break;
		}
	}

	mutex_exit(&pit_state->lock);
	return (0);
}

static int
pit_ioport_read(struct kvm_io_device *this, gpa_t addr, int len, void *data)
{
	struct kvm_pit *pit = dev_to_pit(this);
	struct kvm_kpit_state *pit_state = &pit->pit_state;
	struct kvm *kvm = pit->kvm;
	int ret, count;
	struct kvm_kpit_channel_state *s;

	if (!pit_in_range(addr))
		return (-EOPNOTSUPP);

	addr &= KVM_PIT_CHANNEL_MASK;
	if (addr == 3)
		return (0);

	s = &pit_state->channels[addr];

	mutex_enter(&pit_state->lock);

	if (s->status_latched) {
		s->status_latched = 0;
		ret = s->status;
	} else if (s->count_latched) {
		switch (s->count_latched) {
		default:
		case RW_STATE_LSB:
			ret = s->latched_count & 0xff;
			s->count_latched = 0;
			break;
		case RW_STATE_MSB:
			ret = s->latched_count >> 8;
			s->count_latched = 0;
			break;
		case RW_STATE_WORD0:
			ret = s->latched_count & 0xff;
			s->count_latched = RW_STATE_MSB;
			break;
		}
	} else {
		switch (s->read_state) {
		default:
		case RW_STATE_LSB:
			count = pit_get_count(kvm, addr);
			ret = count & 0xff;
			break;
		case RW_STATE_MSB:
			count = pit_get_count(kvm, addr);
			ret = (count >> 8) & 0xff;
			break;
		case RW_STATE_WORD0:
			count = pit_get_count(kvm, addr);
			ret = count & 0xff;
			s->read_state = RW_STATE_WORD1;
			break;
		case RW_STATE_WORD1:
			count = pit_get_count(kvm, addr);
			ret = (count >> 8) & 0xff;
			s->read_state = RW_STATE_WORD0;
			break;
		}
	}

	if (len > sizeof (ret))
		len = sizeof (ret);

	memcpy(data, (char *)&ret, len);

	mutex_exit(&pit_state->lock);

	return (0);
}

static int
speaker_ioport_write(struct kvm_io_device *this, gpa_t addr, int len,
    const void *data)
{
	struct kvm_pit *pit = speaker_to_pit(this);
	struct kvm_kpit_state *pit_state = &pit->pit_state;
	struct kvm *kvm = pit->kvm;
	uint32_t val = *(uint32_t *) data;

	if (addr != KVM_SPEAKER_BASE_ADDRESS)
		return (-EOPNOTSUPP);

	mutex_enter(&pit_state->lock);
	pit_state->speaker_data_on = (val >> 1) & 1;
	pit_set_gate(kvm, 2, val & 1);
	mutex_exit(&pit_state->lock);

	return (0);
}

static int
speaker_ioport_read(struct kvm_io_device *this, gpa_t addr, int len, void *data)
{
	struct kvm_pit *pit = speaker_to_pit(this);
	struct kvm_kpit_state *pit_state = &pit->pit_state;
	struct kvm *kvm = pit->kvm;
	unsigned int refresh_clock;
	int ret;

	if (addr != KVM_SPEAKER_BASE_ADDRESS)
		return (-EOPNOTSUPP);

	/* Refresh clock toggles at about 15us. We approximate as 2^14ns. */
	refresh_clock = ((unsigned int)gethrtime() >> 14) & 1;

	mutex_enter(&pit_state->lock);
	ret = ((pit_state->speaker_data_on << 1) | pit_get_gate(kvm, 2) |
	    (pit_get_out(kvm, 2) << 5) | (refresh_clock << 4));

	if (len > sizeof (ret))
		len = sizeof (ret);

	memcpy(data, (char *)&ret, len);
	mutex_exit(&pit_state->lock);
	return (0);
}

void
kvm_pit_reset(struct kvm_pit *pit)
{
	int i;
	struct kvm_kpit_channel_state *c;

	mutex_enter(&pit->pit_state.lock);
	pit->pit_state.flags = 0;
	for (i = 0; i < 3; i++) {
		c = &pit->pit_state.channels[i];
		c->mode = 0xff;
		c->gate = (i != 2);
		pit_load_count(pit->kvm, i, 0);
	}
	mutex_exit(&pit->pit_state.lock);

	pit->pit_state.pit_timer.pending =  0;
	pit->pit_state.irq_ack = 1;
}

static void
pit_mask_notifer(struct kvm_irq_mask_notifier *kimn, int mask)
{
	struct kvm_pit *pit = (struct kvm_pit *)(((caddr_t)kimn) -
	    offsetof(struct kvm_pit, mask_notifier));

	if (!mask) {
		pit->pit_state.pit_timer.pending = 0;
		pit->pit_state.irq_ack = 1;
	}
}

static const struct kvm_io_device_ops pit_dev_ops = {
	.read	= pit_ioport_read,
	.write	= pit_ioport_write,
};

static const struct kvm_io_device_ops speaker_dev_ops = {
	.read	= speaker_ioport_read,
	.write	= speaker_ioport_write,
};

/* Caller must hold slots_lock */
struct kvm_pit *
kvm_create_pit(struct kvm *kvm, uint32_t flags)
{
	struct kvm_pit *pit;
	struct kvm_kpit_state *pit_state;
	int ret;

	pit = kmem_zalloc(sizeof (struct kvm_pit), KM_SLEEP);

	pit->irq_source_id = kvm_request_irq_source_id(kvm);

	if (pit->irq_source_id < 0) {
		kmem_free(pit, sizeof (struct kvm_pit));
		return (NULL);
	}

	mutex_init(&pit->pit_state.lock, NULL, MUTEX_DRIVER, 0);
	mutex_enter(&pit->pit_state.lock);
	mutex_init(&pit->pit_state.inject_lock, NULL, MUTEX_DRIVER, 0);

	kvm->arch.vpit = pit;
	pit->kvm = kvm;

	pit_state = &pit->pit_state;
	pit_state->pit = pit;

	pit_state->irq_ack_notifier.gsi = 0;
	pit_state->irq_ack_notifier.irq_acked = kvm_pit_ack_irq;

	kvm_register_irq_ack_notifier(kvm, &pit_state->irq_ack_notifier);

	pit_state->pit_timer.reinject = 1;
	pit_state->pit_timer.active = 0;

	mutex_exit(&pit->pit_state.lock);

	kvm_pit_reset(pit);

	pit->mask_notifier.func = pit_mask_notifer;
	kvm_register_irq_mask_notifier(kvm, 0, &pit->mask_notifier);

	kvm_iodevice_init(&pit->dev, &pit_dev_ops);
	ret = kvm_io_bus_register_dev(kvm, KVM_PIO_BUS, &pit->dev);
	if (ret < 0)
		goto fail;

	if (flags & KVM_PIT_SPEAKER_DUMMY) {
		kvm_iodevice_init(&pit->speaker_dev, &speaker_dev_ops);
		ret = kvm_io_bus_register_dev(kvm,
		    KVM_PIO_BUS, &pit->speaker_dev);

		if (ret < 0)
			goto fail_unregister;
	}

	return (pit);

fail_unregister:
	kvm_io_bus_unregister_dev(kvm, KVM_PIO_BUS, &pit->dev);
fail:
	kvm_unregister_irq_mask_notifier(kvm, 0, &pit->mask_notifier);
	kvm_unregister_irq_ack_notifier(kvm, &pit_state->irq_ack_notifier);
	kvm_free_irq_source_id(kvm, pit->irq_source_id);
	kmem_free(pit, sizeof (struct kvm_pit));
	return (NULL);
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
		mutex_enter(&ps->inject_lock);
		if (ps->pit_timer.pending && ps->irq_ack) {
			ps->irq_ack = 0;
			inject = 1;
		}
		mutex_exit(&ps->inject_lock);

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
