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
 * Originally implemented on Linux:
 * Copyright (C) 2006 Qumranet, Inc.
 *
 * Authors:
 *   Avi Kivity   <avi@qumranet.com>
 *   Yaniv Kamay  <yaniv@qumranet.com>
 *
 * Ported to illumos by Joyent
 * Copyright 2019 Joyent, Inc.
 *
 * Authors:
 *   Max Bruning	<max@joyent.com>
 *   Bryan Cantrill	<bryan@joyent.com>
 *   Robert Mustacchi	<rm@joyent.com>
 */

/*
 * KVM -- Kernel Virtual Machine Driver
 * ------------------------------------
 *
 * The kvm driver's purpose it to provide an interface for accelerating virtual
 * machines. To that end the kernel implements and provides emulation for
 * various pieces of hardware. The kernel also interacts directly with
 * extensions to the x86 instruction set via VT-x and related technologies on
 * Intel processors. The system is designed to support SVM (now marketed as
 * AMD-V); however, it is not currently implemented in the illumos version. KVM
 * does not provide all the pieces necessary for vitalization, nor is that a
 * part of its design.
 *
 * KVM is a psuedo-device presented to userland as a character device. Consumers
 * open the device and interact primarily through ioctl(2) and mmap(2).
 *
 * General Theory
 * --------------
 *
 * A consumer will open up the KVM driver and perform ioctls to set up initial
 * state and create virtual CPUs (VCPU). To run a specific VCPU an ioctl is
 * performed. When the ioctl occurs we use the instruction set extensions to try
 * and run that CPU in the current thread. This is run for as long as possible
 * until an instruction that needs to be emulated by the host, e.g. a write to
 * emulated hardware, or some external event brings us out e.g. an interrupt,
 * the schedular descheduling the thread, etc.. Each VCPU is modeled as a
 * thread.  The KVM driver notes the exit reason and either handles it and
 * emulates it or returns to the guest to handle it. This loop generally follows
 * this flowchart:
 *
 *
 *       Userland                        Kernel
 *                         |
 *    |-----------|        |
 *    | VCPU_RUN  |--------|-----------------|
 *    | ioctl(2)  |        |                 |
 *    |-----------|        |                \|/
 *          ^              |            |---------|
 *          |              |            | Run CPU |
 *          |              |       |--->| for the |
 *          |              |       |    |  guest  |
 *          |              |       |    |---------|
 *          |              |       |         |
 *          |              |       |         |
 *          |              |       |         |
 *          |              |       |         | Stop execution of
 *          |              |       |         | guest
 *          |              |       |         |------------|
 *          |              |  |---------|                 |
 *          |              |  |  Handle |                 |
 *          |              |  |  guest  |                \|/
 *          |              |  |  exit   |               /   \
 *     |---------|         |  |---------|             /       \
 *     |  Handle |         |       ^                /  Can the  \
 *     |  guest  |         |       |--------------/ Kernel handle \
 *     |  exit   |         |           Yes        \   the exit    /
 *     |---------|         |                        \  reason?  /
 *          ^              |                          \       /
 *          |              |                            \   /
 *          |              |                              |
 *          |              |                              | No
 *          |--------------|------------------------------|
 *                         |
 *
 * The data regarding the state of the VCPU and of the overall virtual machine
 * is available via mmap(2) of the file descriptor corresponding to the VCPU of
 * interest.
 *
 * All the memory for the guest is handled in the userspace of the guest. This
 * includes mapping in the BIOS, the program text for the guest, and providing
 * devices. To communicate about this information, get and set kernel device
 * state, and interact in various ways,
 *
 * Kernel Emulated and Assisted Hardware
 * -------------------------------------
 *
 * CPUs
 *
 * Intel and AMD provide hardware acceleration that allows for a CPU to run in
 * various execution and addressing modes:
 *   + Real Mode - 8086 style 16-bit operands and 20-bit addressing
 *   + Protected Mode - 80286 style 32-bit operands and addressing and Virtual
 *   			Memory
 *   + Protected Mode with PAE - Physical Address Extensions to allow 36-bits of
 *				 addressing for physical memory. Only 32-bits of
 *				 addressing for virtual memory are available.
 *
 *   + Long Mode - amd64 style 64-bit operands and 64-bit virtual addressing.
 *		   Currently only 48 bits of physical memory can be addressed.
 *
 *   + System Management mode is unsupported and untested. It may work. It may
 *     cause a panic.
 *
 * Other Hardware
 *
 * The kernel emulates various pieces of additional hardware that are necessary
 * for an x86 system to function. These include:
 *
 *   + i8254 PIT - Intel Programmable Interval Timer
 *   + i8259 PIC - Intel Programmable Interrupt Controller
 *   + Modern APIC architecture consisting of:
 *      - Local APIC
 *      - I/O APIC
 *   + IRQ routing table
 *   + MMU - Memory Management Unit
 *
 * The following diagram shows how the different pieces of emulated hardware fit
 * together. An arrow pointing to something denotes that the pointed to item is
 * contained within the object.
 *
 *                                 Up to KVM_MAX_VCPUS (64) cpus
 *
 *                                         |---------|     |-------|
 *           |-------------|               | Virtual |     | Local |    Per
 *           |             |-------------->| CPU #n  |     | APIC  |<-- VCPU
 *           |   Virtual   |               |---------|     |-------|     |
 *           |   Machine   |                               ^            \|/
 *           |             |-------------->|---------|-----|     |-------------|
 *           |-------------|               | Virtual |           | Registers   |
 *              | | | | |                  | CPU #0  |---------->|             |
 *              | | | | |                  |---------|           | RAX,RIP,ETC |
 *              | | | | |                                        | CR0,CR4,ETC |
 *              | | | | |                                        | CPUID,ETC   |
 *              | | | | |                                        |-------------|
 *              | | | | |
 *              | | | | |
 *              | | | | |
 *              | | | | |
 * |-------|    | | | | |                           |-------------------------|
 * | i8254 |<---| | | | |                           |                         |
 * |  PIT  |      | | | |                           |    Memory Management    |
 * |-------|      | | | |-------------------------->|          Unit           |
 *                | | | |                           |           &&            |
 *                | | | |  |--------------|         |    Shadow Page Table    |
 * |-------|      | | | |->| Input/Output |         |                         |
 * | i8259 |<-----| |      |     APIC     |         |-------------------------|
 * |  PIC  |       \|/     |--------------|
 * |-------|   |---------|
 *             |   IRQ   |
 *             | Routing |
 *             |  Table  |
 *             |---------|
 *
 *
 * Internal Code Layout and Design
 * -------------------------------
 *
 * The KVM code can be broken down into the following broad sections:
 *
 *    + Device driver entry points
 *    + Generic code and driver entry points
 *    + x86 and architecture specific code
 *    + Hardware emulation specific code
 *    + Host CPU specific code
 *
 * Host CPU Specific Code
 *
 * Both Intel and AMD provide a means for accelerating guest operation, VT-X
 * (VMX) and SVM (AMD-V) respectively. However, the instructions, design, and
 * means of interacting with each are different. To get around this there is a
 * generic vector of operations which are implemented by both subsystems. The
 * rest of the code base references these operations via the vector. As a part
 * of attach(9E), the system dynamically determines whether the system
 * should use the VMX or SVM operations.
 *
 * The operations vector is entitled kvm_x86_ops. It's functions are:
 * TODO Functions and descriptions, though there may be too many
 *
 *
 * Hardware Emulation Specific Code
 *
 * Various pieces of hardware are emulated by the kernel in the KVM module as
 * described previously. These are accessed in several ways:
 *
 *    + Userland performs ioctl(2)s to get and set state
 *    + Guests perform PIO to devices
 *    + Guests write to memory locations that correspond to devices
 *
 * To handle memory mapped devices in the guest there is an internal notion of
 * an I/O device. There is an internal notion of an I/O bus. Devices can be
 * registered onto the bus. Currently two buses exist. One for programmed I/O
 * devices and another for memory mapped devices.
 *
 * Code related to IRQs is primairly contained within kvm_irq.c and
 * kvm_irq_conn.c. To facilitate and provide a more generic IRQ system there are
 * two useful sets of notifiers. The notifiers fire a callback when the
 * specified event occurs.  Currently there are two notifiers:
 *
 *
 *    + IRQ Mask Notifier: This fires its callback when an IRQ has been masked
 *			   by an operation.
 *    + IRQ Ack Notifier: This fires its callback when an IRQ has been
 *			  acknowledged.
 *
 * The hardware emulation code is broken down across the following files:
 *
 *    + i8254 PIT implementation: kvm_i8254.c and kvm_i8254.h
 *    + i8259 PIC implementation: kvm_i8259.c
 *    + I/O APIC Implementation: kvm_ioapic.c and kvm_ioapic.h
 *    + Local APIC Implementation: kvm_lapic.c and kvm_lapic.h
 *    + Memory Management Unit: kvm_mmu.c, kvm_mmu.h, and kvm_paging_tmpl.h
 *
 * x86 and Architecture Specific Code
 *
 * The code specific to x86 that is not device specific is broken across two
 * files. The first is kvm_x86.c. This contains most of the x86 specific
 * logic, calls into the CPU specific vector of operations, and serves as a
 * gateway to some device specific portions and memory management code.
 *
 * The other main piece of this is kvm_emulate.c. This file contains code
 * that cannot be handled by the CPU specific instructions and instead need to
 * be handled by kvm, for example an inb or outb instruction.
 *
 * Generic Code
 *
 * The code that is not specific to devices or to x86 specifically can be found
 * in kvm.c. This includes code that interacts directly with different parts of
 * the rest of the kernel; the scheduler, cross calls, etc.
 *
 * Device Driver Entry Points
 *
 * The KVM driver is a psuedo-device that presents as a character device. All of
 * the necessary entry points and related pieces of infrastructure are all
 * located in kvm.c. This includes all of the logic related to open(2),
 * close(2), mmap(2), ioctl(2), and the other necessary driver entry points.
 *
 * Interactions between Userland and the Kernel
 * --------------------------------------------
 *
 * -Opening and cloning / VCPUs
 * -The mmap(2) related pieces.
 * -The general ioctl->arch->x86_ops->vmx
 *
 * Timers and Cyclics
 * ------------------
 *
 * -Timers mapping to cyclics
 *
 * Memory Management
 * -----------------
 *
 * -Current memory model / assumptions (i.e. can't be paged)
 * -Use of kpm
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/uio.h>
#include <sys/buf.h>
#include <sys/modctl.h>
#include <sys/open.h>
#include <sys/kmem.h>
#include <sys/poll.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/atomic.h>
#include <sys/spl.h>
#include <sys/cpuvar.h>
#include <sys/segments.h>
#include <sys/cred.h>
#include <sys/devops.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/vm.h>
#include <sys/proc.h>
#include <vm/seg_kpm.h>
#include <sys/avl.h>
#include <sys/condvar_impl.h>
#include <sys/file.h>
#include <sys/vnode.h>
#include <sys/strsubr.h>
#include <sys/stream.h>
#include <sys/machparam.h>
#include <sys/xc_levels.h>
#include <asm/cpu.h>
#include <sys/id_space.h>
#include <sys/hma.h>

#include "kvm_bitops.h"
#include "kvm_vmx.h"
#include "msr-index.h"
#include "kvm_msr.h"
#include "kvm_host.h"
#include "kvm_lapic.h"
#include "processor-flags.h"
#include "hyperv.h"
#include "kvm_apicdef.h"
#include "kvm_iodev.h"
#include "kvm.h"
#include "kvm_x86impl.h"
#include "kvm_irq.h"
#include "kvm_ioapic.h"
#include "kvm_coalesced_mmio.h"
#include "kvm_i8254.h"
#include "kvm_mmu.h"
#include "kvm_cache_regs.h"

#undef DEBUG

/*
 * The entire state of the kvm device.
 */
typedef struct {
	struct kvm *kds_kvmp;		/* pointer to underlying VM */
	struct kvm_vcpu *kds_vcpu;	/* pointer to VCPU */
} kvm_devstate_t;

/*
 * Globals
 */
page_t *bad_page = NULL;
void *bad_page_kma = NULL;
pfn_t bad_pfn = PFN_INVALID;

/*
 * Tunables
 */
static int kvm_hiwat = 0x1000000;

#define	KVM_MINOR_BASE	0
#define	KVM_MINOR_INSTS	1

/*
 * Internal driver-wide values
 */
static void *kvm_state;		/* DDI state */
static id_space_t *kvm_minors;	/* minor number arena */
static dev_info_t *kvm_dip;	/* global devinfo hanlde */
static hma_reg_t *kvm_hma_reg;
static int kvmid;		/* monotonically increasing, unique per vm */
static int largepages_enabled = 1;
static uint_t kvm_usage_count;
static list_t vm_list;
static kmutex_t kvm_lock;
static int ignore_msrs = 0;
static unsigned long empty_zero_page[PAGESIZE / sizeof (unsigned long)];

int
kvm_xcall_func(kvm_xcall_t func, void *arg)
{
	if (func != NULL)
		(*func)(arg);

	return (0);
}

void
kvm_xcall(processorid_t cpu, kvm_xcall_t func, void *arg)
{
	cpuset_t set;

	CPUSET_ZERO(set);

	if (cpu == KVM_CPUALL) {
		CPUSET_ALL(set);
	} else {
		CPUSET_ADD(set, cpu);
	}

	kpreempt_disable();
	xc_sync((xc_arg_t)func, (xc_arg_t)arg, 0, CPUSET2BV(set),
		(xc_func_t) kvm_xcall_func);
	kpreempt_enable();
}

void
kvm_user_return_notifier_register(struct kvm_vcpu *vcpu,
    struct kvm_user_return_notifier *urn)
{
	vcpu->urn = urn;
}

void
kvm_user_return_notifier_unregister(struct kvm_vcpu *vcpu,
    struct kvm_user_return_notifier *urn)
{
	vcpu->urn = NULL;
}

void
kvm_fire_urn(struct kvm_vcpu *vcpu)
{
	if (vcpu->urn)
		vcpu->urn->on_user_return(vcpu, vcpu->urn);
}

void
kvm_ringbuf_record(kvm_ringbuf_t *ringbuf, uint32_t tag, uint64_t payload)
{
	kvm_ringbuf_entry_t *ent = &ringbuf->kvmr_buf[ringbuf->kvmr_ent++ &
	    (KVM_RINGBUF_NENTRIES - 1)];
	int id = curthread->t_cpu->cpu_id;
	hrtime_t tsc = gethrtime_unscaled();

	ent->kvmre_tag = tag;
	ent->kvmre_cpuid = id;
	ent->kvmre_thread = (uintptr_t)curthread;
	ent->kvmre_tsc = tsc;
	ent->kvmre_payload = payload;

	ent = &ringbuf->kvmr_taglast[tag];
	ent->kvmre_tag = tag;
	ent->kvmre_cpuid = id;
	ent->kvmre_thread = (uintptr_t)curthread;
	ent->kvmre_tsc = tsc;
	ent->kvmre_payload = payload;

	ringbuf->kvmr_tagcount[tag]++;
}

/*
 * Called when we've been asked to save our context. i.e. we're being swapped
 * out.
 */
static void
kvm_ctx_save(void *arg)
{
	struct kvm_vcpu *vcpu = arg;

	kvm_ringbuf_record(&vcpu->kvcpu_ringbuf,
	    KVM_RINGBUF_TAG_CTXSAVE, vcpu->cpu);
	kvm_arch_vcpu_put(vcpu);
	kvm_fire_urn(vcpu);
}

/*
 * Called when we're being asked to restore our context. i.e. we're returning
 * from being swapped out.
 */
static void
kvm_ctx_restore(void *arg)
{
	struct kvm_vcpu *vcpu = arg;
	const int cpu = CPU->cpu_id;

	kvm_ringbuf_record(&vcpu->kvcpu_ringbuf,
	    KVM_RINGBUF_TAG_CTXRESTORE, vcpu->cpu);
	kvm_arch_vcpu_load(vcpu, cpu);
}

inline int
kvm_is_mmio_pfn(pfn_t pfn)
{
	return (pfn == PFN_INVALID);
}

/*
 * Switches to specified vcpu, until a matching vcpu_put()
 */
void
vcpu_load(struct kvm_vcpu *vcpu)
{
	struct ctxop *ctx = installctx_preallocate();
	mutex_enter(&vcpu->mutex);

	kpreempt_disable();
	installctx(curthread, vcpu, kvm_ctx_save, kvm_ctx_restore, NULL,
	    NULL, NULL, NULL, ctx);

	kvm_arch_vcpu_load(vcpu, CPU->cpu_id);
	kvm_ringbuf_record(&vcpu->kvcpu_ringbuf,
	    KVM_RINGBUF_TAG_VCPULOAD, vcpu->cpu);
	kpreempt_enable();
}

struct kvm_vcpu *
kvm_get_vcpu(struct kvm *kvm, int i)
{
	smp_rmb();
	return (kvm->vcpus[i]);
}

void
vcpu_put(struct kvm_vcpu *vcpu)
{
	int cpu;

	kpreempt_disable();
	cpu = vcpu->cpu;
	kvm_arch_vcpu_put(vcpu);
	kvm_fire_urn(vcpu);
	removectx(curthread, vcpu, kvm_ctx_save, kvm_ctx_restore, NULL,
	    NULL, NULL, NULL);
	kvm_ringbuf_record(&vcpu->kvcpu_ringbuf, KVM_RINGBUF_TAG_VCPUPUT, cpu);
	kpreempt_enable();
	mutex_exit(&vcpu->mutex);
}

int
make_all_cpus_request(struct kvm *kvm, unsigned int req)
{
	int i;
	processorid_t me, cpu;
	struct kvm_vcpu *vcpu;

	mutex_enter(&kvm->requests_lock);

	kpreempt_disable();
	me = curthread->t_cpu->cpu_id;
	for (i = 0; i < kvm->online_vcpus; i++) {
		vcpu = kvm->vcpus[i];
		if (!vcpu)
			break;
		if (test_and_set_bit(req, &vcpu->requests))
			continue;
		cpu = vcpu->cpu;
		if (cpu != -1 && cpu != me)
			poke_cpu(cpu);
	}

	kpreempt_enable();

	mutex_exit(&kvm->requests_lock);

	return (1);
}

void
kvm_flush_remote_tlbs(struct kvm *kvm)
{
	if (make_all_cpus_request(kvm, KVM_REQ_TLB_FLUSH))
		KVM_KSTAT_INC(kvm, kvmks_remote_tlb_flush);
}

void
kvm_reload_remote_mmus(struct kvm *kvm)
{
	make_all_cpus_request(kvm, KVM_REQ_MMU_RELOAD);
}

int
kvm_vcpu_init(struct kvm_vcpu *vcpu, struct kvm *kvm, unsigned id)
{
	int r;

	mutex_init(&vcpu->mutex, NULL, MUTEX_DRIVER, 0);
	vcpu->cpu = -1;
	vcpu->kvm = kvm;
	vcpu->vcpu_id = id;
	vcpu->run = ddi_umem_alloc(PAGESIZE * 2, DDI_UMEM_SLEEP, &vcpu->cookie);

	r = kvm_arch_vcpu_init(vcpu);

	if (r != 0) {
		vcpu->run = NULL;
		ddi_umem_free(vcpu->cookie);
		return (r);
	}

	return (0);
}

void
kvm_vcpu_uninit(struct kvm_vcpu *vcpu)
{
	kvm_arch_vcpu_uninit(vcpu);
	ddi_umem_free(vcpu->cookie);
}

/*
 * Note if we want to implement the kvm mmu notifier components than the
 * following two functions will need to be readdressed.
 */
static int kvm_init_mmu_notifier(struct kvm *kvm)
{
	return (0);
}

static void
kvm_fini_mmu_notifier(struct kvm *kvm)
{
}

static void
kvm_destroy_vm(struct kvm *kvmp)
{
	int ii;

	if (kvmp == NULL)
		return;

	if (kvmp->kvm_kstat != NULL)
		kstat_delete(kvmp->kvm_kstat);

	kvm_arch_flush_shadow(kvmp);  /* clean up shadow page tables */

	kvm_arch_destroy_vm_comps(kvmp);
	kvm_free_irq_routing(kvmp);
	kvm_destroy_pic(kvmp);
	kvm_ioapic_destroy(kvmp);
	kvm_coalesced_mmio_free(kvmp);

	list_remove(&vm_list, kvmp);
	avl_destroy(&kvmp->kvm_avlmp);
	mutex_destroy(&kvmp->kvm_avllock);
	mutex_destroy(&kvmp->memslots_lock);
	mutex_destroy(&kvmp->slots_lock);
	mutex_destroy(&kvmp->irq_lock);
	mutex_destroy(&kvmp->lock);
	mutex_destroy(&kvmp->requests_lock);
	mutex_destroy(&kvmp->mmu_lock);
	mutex_destroy(&kvmp->buses_lock);
	kvm_fini_mmu_notifier(kvmp);

	for (ii = 0; ii < KVM_NR_BUSES; ii++)
		kmem_free(kvmp->buses[ii], sizeof (struct kvm_io_bus));

	rw_destroy(&kvmp->kvm_rwlock);

	/*
	 * These lists are contained by the pic. However, the pic isn't
	 */
	list_destroy(&kvmp->irq_ack_notifier_list);
	list_destroy(&kvmp->mask_notifier_list);

	kvm_arch_destroy_vm(kvmp);
}

static struct kvm *
kvm_create_vm(void)
{
	int rval = 0;
	int i;
	struct kvm *kvmp = kvm_arch_create_vm();

	if (kvmp == NULL)
		return (NULL);

	list_create(&kvmp->mask_notifier_list,
		    sizeof (struct kvm_irq_mask_notifier),
		    offsetof(struct kvm_irq_mask_notifier, link));
	list_create(&kvmp->irq_ack_notifier_list,
		    sizeof (struct kvm_irq_ack_notifier),
		    offsetof(struct kvm_irq_ack_notifier, link));

	kvmp->memslots = kmem_zalloc(sizeof (struct kvm_memslots), KM_SLEEP);

	rw_init(&kvmp->kvm_rwlock, NULL, RW_DRIVER, NULL);

	for (i = 0; i < KVM_NR_BUSES; i++) {
		kvmp->buses[i] =
		    kmem_zalloc(sizeof (struct kvm_io_bus), KM_SLEEP);
	}

	rval = kvm_init_mmu_notifier(kvmp);

	if (rval != DDI_SUCCESS) {
		rw_destroy(&kvmp->kvm_rwlock);
		kvm_arch_destroy_vm(kvmp);
		return (NULL);
	}

	mutex_init(&kvmp->mmu_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&kvmp->requests_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&kvmp->lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&kvmp->memslots_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&kvmp->irq_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&kvmp->slots_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&kvmp->kvm_avllock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&kvmp->buses_lock, NULL, MUTEX_DRIVER, NULL);
	avl_create(&kvmp->kvm_avlmp, kvm_avlmmucmp, sizeof (kvm_mmu_page_t),
	    offsetof(kvm_mmu_page_t, kmp_avlnode));

	mutex_enter(&kvm_lock);
	kvmp->kvmid = kvmid++;
	kvmp->users_count = 1;
	list_insert_tail(&vm_list, kvmp);
	mutex_exit(&kvm_lock);

	if ((kvmp->kvm_kstat = kstat_create_zone("kvm", kvmp->kvmid, "vm",
	    "misc", KSTAT_TYPE_NAMED, sizeof (kvm_stats_t) /
	    sizeof (kstat_named_t), KSTAT_FLAG_VIRTUAL, GLOBAL_ZONEID)) ==
	    NULL) {
		kvm_destroy_vm(kvmp);
		return (NULL);
	}

	kvmp->kvm_kstat->ks_data = &kvmp->kvm_stats;
	kvmp->kvm_kstat->ks_data_size +=
	    strlen(curproc->p_zone->zone_name) + 1;

	KVM_KSTAT_INIT(kvmp, kvmks_pid, "pid");
	kvmp->kvm_stats.kvmks_pid.value.ui64 = kvmp->kvm_pid = curproc->p_pid;

	KVM_KSTAT_INIT(kvmp, kvmks_mmu_pte_write, "mmu-pte-write");
	KVM_KSTAT_INIT(kvmp, kvmks_mmu_pte_updated, "mmu-pte-updated");
	KVM_KSTAT_INIT(kvmp, kvmks_mmu_pte_zapped, "mmu-pte-zapped");
	KVM_KSTAT_INIT(kvmp, kvmks_mmu_flooded, "mmu-flooded");
	KVM_KSTAT_INIT(kvmp, kvmks_mmu_cache_miss, "mmu-cache-miss");
	KVM_KSTAT_INIT(kvmp, kvmks_mmu_recycled, "mmu-recycled");
	KVM_KSTAT_INIT(kvmp, kvmks_remote_tlb_flush, "remote-tlb-flush");
	KVM_KSTAT_INIT(kvmp, kvmks_lpages, "lpages");
	KVM_KSTAT_INIT(kvmp, kvmks_mmu_unsync_page, "mmu-unsync-page");
	kstat_named_init(&(kvmp->kvm_stats.kvmks_zonename), "zonename",
	    KSTAT_DATA_STRING);
	kstat_named_setstr(&(kvmp->kvm_stats.kvmks_zonename),
	    curproc->p_zone->zone_name);

	kstat_install(kvmp->kvm_kstat);

	kvm_coalesced_mmio_init(kvmp);

	return (kvmp);
}

/*
 * Free any memory in @free but not in @dont.
 */
static void
kvm_free_physmem_slot(struct kvm_memory_slot *free,
    struct kvm_memory_slot *dont)
{
	int i;

	if (!dont || free->rmap != dont->rmap)
		kmem_free(free->rmap, free->npages * sizeof (struct page *));

	if ((!dont || free->dirty_bitmap != dont->dirty_bitmap) &&
	    free->dirty_bitmap)
		kmem_free(free->dirty_bitmap, free->dirty_bitmap_sz);

	for (i = 0; i < KVM_NR_PAGE_SIZES - 1; ++i) {
		if ((!dont || free->lpage_info[i] != dont->lpage_info[i]) &&
		    free->lpage_info[i]) {
			kmem_free(free->lpage_info[i], free->lpage_info_sz[i]);
			free->lpage_info[i] = NULL;
		}
	}

	free->npages = 0;
	free->dirty_bitmap = NULL;
	free->rmap = NULL;
}

void
kvm_free_physmem(struct kvm *kvm)
{
	int ii;
	struct kvm_memslots *slots = kvm->memslots;

	for (ii = 0; ii < slots->nmemslots; ii++)
		kvm_free_physmem_slot(&slots->memslots[ii], NULL);

	kmem_free(kvm->memslots, sizeof (struct kvm_memslots));
}

void
kvm_get_kvm(struct kvm *kvm)
{
	atomic_inc_32((volatile uint32_t *)&kvm->users_count);
}

unsigned long
kvm_dirty_bitmap_bytes(struct kvm_memory_slot *memslot)
{
	return (BT_SIZEOFMAP(memslot->npages));
}

/*
 * Allocate some memory and give it an address in the guest physical address
 * space.
 *
 * Discontiguous memory is allowed, mostly for framebuffers.
 *
 * Must be called holding mmap_sem for write.
 */
int
__kvm_set_memory_region(struct kvm *kvmp,
    struct kvm_userspace_memory_region *mem, int user_alloc)
{
	int r, flush_shadow = 0;
	gfn_t base_gfn;
	unsigned long npages;
	unsigned long i;
	struct kvm_memory_slot *memslot;
	struct kvm_memory_slot old, new;
	struct kvm_memslots *slots, *old_memslots;

	r = EINVAL;
	/* General sanity checks */
	if (mem->memory_size & (PAGESIZE - 1))
		goto out;
	if (mem->guest_phys_addr & (PAGESIZE - 1))
		goto out;
	if (user_alloc && (mem->userspace_addr & (PAGESIZE - 1)))
		goto out;
	if (mem->slot >= KVM_MEMORY_SLOTS + KVM_PRIVATE_MEM_SLOTS)
		goto out;
	if (mem->guest_phys_addr + mem->memory_size < mem->guest_phys_addr)
		goto out;

	memslot = &kvmp->memslots->memslots[mem->slot];
	base_gfn = mem->guest_phys_addr >> PAGESHIFT;
	npages = mem->memory_size >> PAGESHIFT;

	if (!npages)
		mem->flags &= ~KVM_MEM_LOG_DIRTY_PAGES;

	new = old = *memslot;

	new.base_gfn = base_gfn;
	new.npages = npages;
	new.flags = mem->flags;

	/* Disallow changing a memory slot's size. */
	r = EINVAL;
	if (npages && old.npages && npages != old.npages)
		goto out_free;

	/* Check for overlaps */
	r = EEXIST;
	for (i = 0; i < KVM_MEMORY_SLOTS; ++i) {
		struct kvm_memory_slot *s = &kvmp->memslots->memslots[i];

		if (s == memslot || !s->npages)
			continue;
		if (!((base_gfn + npages <= s->base_gfn) ||
		    (base_gfn >= s->base_gfn + s->npages)))
			goto out_free;
	}

	/* Free page dirty bitmap if unneeded */
	if (!(new.flags & KVM_MEM_LOG_DIRTY_PAGES))
		new.dirty_bitmap = NULL;

	r = ENOMEM;

	/* Allocate if a slot is being created */
	if (npages && !new.rmap) {
		new.rmap =
		    kmem_zalloc(npages * sizeof (struct page *), KM_SLEEP);

		new.user_alloc = user_alloc;
		new.userspace_addr = mem->userspace_addr;
	}

	if (!npages)
		goto skip_lpage;

	for (i = 0; i < KVM_NR_PAGE_SIZES - 1; ++i) {
		unsigned long ugfn;
		unsigned long j;
		int lpages;
		int level = i + 2;

		/* Avoid unused variable warning if no large pages */
		(void) level;

		if (new.lpage_info[i])
			continue;

		lpages = 1 + (base_gfn + npages - 1) /
		    KVM_PAGES_PER_HPAGE(level);
		lpages -= base_gfn / KVM_PAGES_PER_HPAGE(level);

		new.lpage_info[i] =
		    kmem_zalloc(lpages * sizeof (*new.lpage_info[i]), KM_SLEEP);
		new.lpage_info_sz[i] = lpages * sizeof (*new.lpage_info[i]);

		if (base_gfn % KVM_PAGES_PER_HPAGE(level))
			new.lpage_info[i][0].write_count = 1;
		if ((base_gfn+npages) % KVM_PAGES_PER_HPAGE(level))
			new.lpage_info[i][lpages - 1].write_count = 1;
		ugfn = new.userspace_addr >> PAGESHIFT;
		/*
		 * If the gfn and userspace address are not aligned wrt each
		 * other, or if explicitly asked to, disable large page
		 * support for this slot
		 */
		if ((base_gfn ^ ugfn) & (KVM_PAGES_PER_HPAGE(level) - 1) ||
		    !largepages_enabled)
			for (j = 0; j < lpages; ++j)
				new.lpage_info[i][j].write_count = 1;
	}

skip_lpage:

	/* Allocate page dirty bitmap if needed */
	if ((new.flags & KVM_MEM_LOG_DIRTY_PAGES) && !new.dirty_bitmap) {
		unsigned long dirty_bytes = kvm_dirty_bitmap_bytes(&new);

		new.dirty_bitmap = kmem_zalloc(dirty_bytes, KM_SLEEP);
		new.dirty_bitmap_sz = dirty_bytes;

		/* destroy any largepage mappings for dirty tracking */
		if (old.npages)
			flush_shadow = 1;
	}

	if (!npages) {
		r = ENOMEM;
		slots = kmem_zalloc(sizeof (kvm_memslots_t), KM_SLEEP);
		memcpy(slots, kvmp->memslots, sizeof (kvm_memslots_t));
		if (mem->slot >= slots->nmemslots)
			slots->nmemslots = mem->slot + 1;
		slots->memslots[mem->slot].flags |= KVM_MEMSLOT_INVALID;

		mutex_enter(&kvmp->memslots_lock);
		old_memslots = kvmp->memslots;
		kvmp->memslots = slots;
		mutex_exit(&kvmp->memslots_lock);

		/*
		 * From this point no new shadow pages pointing to a deleted
		 * memslot will be created.
		 *
		 * validation of sp->gfn happens in:
		 * 	- gfn_to_hva (kvm_read_guest, gfn_to_pfn)
		 * 	- kvm_is_visible_gfn (mmu_check_roots)
		 */
		kvm_arch_flush_shadow(kvmp);
		kmem_free(old_memslots, sizeof (struct kvm_memslots));
	}

	r = kvm_arch_prepare_memory_region(kvmp, &new, old, mem, user_alloc);
	if (r)
		goto out_free;

	r = ENOMEM;
	slots = kmem_zalloc(sizeof (kvm_memslots_t), KM_SLEEP);
	memcpy(slots, kvmp->memslots, sizeof (kvm_memslots_t));

	if (mem->slot >= slots->nmemslots)
		slots->nmemslots = mem->slot + 1;

	/* actual memory is freed via old in kvm_free_physmem_slot below */
	if (!npages) {
		new.rmap = NULL;
		new.dirty_bitmap = NULL;
		for (i = 0; i < KVM_NR_PAGE_SIZES - 1; ++i)
			new.lpage_info[i] = NULL;
	}

	slots->memslots[mem->slot] = new;
	mutex_enter(&kvmp->memslots_lock);
	old_memslots = kvmp->memslots;
	kvmp->memslots = slots;
	mutex_exit(&kvmp->memslots_lock);

	kvm_arch_commit_memory_region(kvmp, mem, old, user_alloc);

	mutex_enter(&kvmp->memslots_lock);
	kvm_free_physmem_slot(&old, &new);
	mutex_exit(&kvmp->memslots_lock);

	kmem_free(old_memslots, sizeof (struct kvm_memslots));

	if (flush_shadow)
		kvm_arch_flush_shadow(kvmp);

	return (DDI_SUCCESS);

out_free:
	kvm_free_physmem_slot(&new, &old);
out:
	return (r);
}

int
kvm_set_memory_region(kvm_t *kvm,
    kvm_userspace_memory_region_t *mem, int user_alloc)
{
	int r;

	mutex_enter(&kvm->slots_lock);
	r = __kvm_set_memory_region(kvm, mem, user_alloc);
	mutex_exit(&kvm->slots_lock);

	return (r);
}

int
kvm_vm_ioctl_set_memory_region(struct kvm *kvm,
    struct kvm_userspace_memory_region *mem, int user_alloc)
{
	if (mem->slot >= KVM_MEMORY_SLOTS)
		return (EINVAL);

	return (kvm_set_memory_region(kvm, mem, user_alloc));
}

void
kvm_disable_largepages(void)
{
	largepages_enabled = 0;
}

int
is_error_pfn(pfn_t pfn)
{
	return (pfn == bad_pfn || pfn == PFN_INVALID);
}

static unsigned long
bad_hva(void)
{
	return (PAGEOFFSET);
}

int
kvm_is_error_hva(unsigned long addr)
{
	return (addr == bad_hva());
}

struct kvm_memory_slot *
gfn_to_memslot_unaliased(struct kvm *kvm, gfn_t gfn)
{
	int i;
	struct kvm_memslots *slots;

	mutex_enter(&kvm->memslots_lock);
	slots = kvm->memslots;

	for (i = 0; i < slots->nmemslots; ++i) {
		struct kvm_memory_slot *memslot = &slots->memslots[i];

		if (gfn >= memslot->base_gfn &&
		    gfn < memslot->base_gfn + memslot->npages) {
			mutex_exit(&kvm->memslots_lock);
			return (memslot);
		}
	}
	mutex_exit(&kvm->memslots_lock);
	return (NULL);
}

struct kvm_memory_slot *
gfn_to_memslot(struct kvm *kvm, gfn_t gfn)
{
	gfn = unalias_gfn(kvm, gfn);
	return (gfn_to_memslot_unaliased(kvm, gfn));
}

int
kvm_is_visible_gfn(struct kvm *kvm, gfn_t gfn)
{
	struct kvm_memslots *slots;
	int i;

	gfn = unalias_gfn_instantiation(kvm, gfn);

	mutex_enter(&kvm->memslots_lock);
	slots = kvm->memslots;

	for (i = 0; i < KVM_MEMORY_SLOTS; ++i) {
		struct kvm_memory_slot *memslot = &slots->memslots[i];

		if (memslot->flags & KVM_MEMSLOT_INVALID)
			continue;

		if (gfn >= memslot->base_gfn &&
		    gfn < memslot->base_gfn + memslot->npages) {
			mutex_exit(&kvm->memslots_lock);
			return (1);
		}
	}

	mutex_exit(&kvm->memslots_lock);
	return (0);
}

unsigned long
kvm_host_page_size(struct kvm *kvm, gfn_t gfn)
{
	return (PAGESIZE);
}

int
memslot_id(struct kvm *kvm, gfn_t gfn)
{
	int i;
	struct kvm_memslots *slots;
	struct kvm_memory_slot *memslot = NULL;

	gfn = unalias_gfn(kvm, gfn);

	mutex_enter(&kvm->memslots_lock);
	slots = kvm->memslots;
	for (i = 0; i < slots->nmemslots; ++i) {
		memslot = &slots->memslots[i];

		if (gfn >= memslot->base_gfn &&
		    gfn < memslot->base_gfn + memslot->npages)
			break;
	}

	mutex_exit(&kvm->memslots_lock);
	return (memslot - slots->memslots);
}

unsigned long
gfn_to_hva(struct kvm *kvm, gfn_t gfn)
{
	struct kvm_memory_slot *slot;

	gfn = unalias_gfn_instantiation(kvm, gfn);
	slot = gfn_to_memslot_unaliased(kvm, gfn);
	if (!slot || slot->flags & KVM_MEMSLOT_INVALID)
		return (bad_hva());

	return (slot->userspace_addr + (gfn - slot->base_gfn) * PAGESIZE);
}

static pfn_t
hva_to_pfn(struct kvm *kvm, unsigned long addr)
{
	page_t page[1];
	int npages;
	pfn_t pfn;
	proc_t *procp = ttoproc(curthread);
	struct as *as = procp->p_as;

	if (addr < kernelbase)
		pfn = hat_getpfnum(as->a_hat, (caddr_t)addr);
	else
		pfn = hat_getpfnum(kas.a_hat, (caddr_t)addr);

	return (pfn);
}

pfn_t
gfn_to_pfn(struct kvm *kvm, gfn_t gfn)
{
	unsigned long addr;
	pfn_t pfn;

	addr = gfn_to_hva(kvm, gfn);

	if (kvm_is_error_hva(addr)) {
		get_page(bad_page);
		return (page_to_pfn(bad_page));
	}

	pfn = hva_to_pfn(kvm, addr);

	return (pfn);
}

page_t *
gfn_to_page(struct kvm *kvm, gfn_t gfn)
{
	pfn_t pfn = gfn_to_pfn(kvm, gfn);

	if (!kvm_is_mmio_pfn(pfn))
		return (pfn_to_page(pfn));

	get_page(bad_page);
	return (bad_page);
}

void
kvm_release_pfn_clean(pfn_t pfn)
{
	/*
	 * If we start paging guest memory, we may need something here.
	 */
}

void
kvm_release_page_dirty(page_t *page)
{
	kvm_release_pfn_dirty(page_to_pfn(page));
}

void
kvm_release_pfn_dirty(pfn_t pfn)
{
	kvm_set_pfn_dirty(pfn);
	kvm_release_pfn_clean(pfn);
}

void
kvm_set_pfn_dirty(pfn_t pfn)
{
}

void
kvm_set_pfn_accessed(struct kvm *kvm, pfn_t pfn)
{
}

void
kvm_get_pfn(struct kvm_vcpu *vcpu, pfn_t pfn)
{
	if (!kvm_is_mmio_pfn(pfn))
		get_page(pfn_to_page(pfn));
}

static int
next_segment(unsigned long len, int offset)
{
	if (len > PAGESIZE - offset)
		return (PAGESIZE - offset);
	else
		return (len);
}

int
kvm_read_guest_page(struct kvm *kvm, gfn_t gfn, void *data, int offset, int len)
{
	int r = 0;
	unsigned long addr;

	addr = gfn_to_hva(kvm, gfn);

	if (kvm_is_error_hva(addr))
		return (-EFAULT);

	if (addr >= kernelbase) {
		bcopy((caddr_t)(addr + offset), data, len);
	} else {
		r = copyin((caddr_t)(addr + offset), data, len);
	}

	if (r)
		return (-EFAULT);

	return (0);
}

int
kvm_read_guest(struct kvm *kvm, gpa_t gpa, void *data, unsigned long len)
{
	gfn_t gfn = gpa >> PAGESHIFT;
	int seg;
	int offset = offset_in_page(gpa);
	int ret;
	uintptr_t dp = (uintptr_t)data;

	while ((seg = next_segment(len, offset)) != 0) {
		ret = kvm_read_guest_page(kvm, gfn, (void *)dp, offset, seg);
		if (ret < 0)
			return (ret);
		offset = 0;
		len -= seg;
		dp += seg;
		++gfn;
	}
	return (0);
}

int
kvm_read_guest_atomic(struct kvm *kvm, gpa_t gpa, void *data, unsigned long len)
{
	int r;
	unsigned long addr;
	gfn_t gfn = gpa >> PAGESHIFT;
	int offset = offset_in_page(gpa);

	addr = gfn_to_hva(kvm, gfn);
	if (kvm_is_error_hva(addr))
		return (-EFAULT);

	r = copyin((caddr_t)addr + offset, data, len);
	if (r)
		return (-EFAULT);

	return (0);
}

int
kvm_write_guest_page(struct kvm *kvm,
    gfn_t gfn, const void *data, int offset, int len)
{
	int r = 0;
	unsigned long addr;

	addr = gfn_to_hva(kvm, gfn);

	if (kvm_is_error_hva(addr))
		return (-EFAULT);

	if (addr >= kernelbase) {
		bcopy(data, (caddr_t)(addr + offset), len);
	} else {
		r = copyout(data, (caddr_t)(addr + offset), len);
	}

	if (r)
		return (-EFAULT);

	mark_page_dirty(kvm, gfn);
	return (0);
}

int
kvm_write_guest(struct kvm *kvm, gpa_t gpa, const void *data, unsigned long len)
{
	gfn_t gfn = gpa >> PAGESHIFT;
	int seg;
	int offset = offset_in_page(gpa);
	int ret;
	uintptr_t dp = (uintptr_t)data;

	while ((seg = next_segment(len, offset)) != 0) {
		ret = kvm_write_guest_page(kvm, gfn, (void *)dp, offset, seg);
		if (ret < 0)
			return (ret);
		offset = 0;
		len -= seg;
		dp += seg;
		++gfn;
	}

	return (0);
}

int
kvm_clear_guest_page(struct kvm *kvm, gfn_t gfn, int offset, int len)
{
	return (kvm_write_guest_page(kvm, gfn, empty_zero_page, offset, len));
}

void
mark_page_dirty(struct kvm *kvm, gfn_t gfn)
{
	struct kvm_memory_slot *memslot;

	gfn = unalias_gfn(kvm, gfn);
	memslot = gfn_to_memslot_unaliased(kvm, gfn);

	if (memslot && memslot->dirty_bitmap) {
		unsigned long rel_gfn = gfn - memslot->base_gfn;
		unsigned long *p = memslot->dirty_bitmap + rel_gfn / 64;
		int offset = rel_gfn % 64;

		/* avoid RMW */
		if (!test_bit(offset, p))
			__set_bit(offset, p);
	}
}

int
kvm_vcpu_is_bsp(struct kvm_vcpu *vcpu)
{
	return (vcpu->kvm->bsp_vcpu_id == vcpu->vcpu_id);
}

/*
 * The vCPU has executed a HLT instruction with in-kernel mode enabled.
 */
void
kvm_vcpu_block(struct kvm_vcpu *vcpu)
{
	for (;;) {
		mutex_enter(&vcpu->kvcpu_kick_lock);

		if (kvm_arch_vcpu_runnable(vcpu)) {
			set_bit(KVM_REQ_UNHALT, &vcpu->requests);
			mutex_exit(&vcpu->kvcpu_kick_lock);
			break;
		}

		if (issig(JUSTLOOKING)) {
			mutex_exit(&vcpu->kvcpu_kick_lock);
			break;
		}

		if (kvm_cpu_has_pending_timer(vcpu)) {
			mutex_exit(&vcpu->kvcpu_kick_lock);
			break;
		}

		(void) cv_wait_sig_swap(&vcpu->kvcpu_kick_cv,
		    &vcpu->kvcpu_kick_lock);

		mutex_exit(&vcpu->kvcpu_kick_lock);
	}
}

/*
 * Creates some virtual cpus.  Good luck creating more than one.
 */
int
kvm_vm_ioctl_create_vcpu(struct kvm *kvm, uint32_t id, int *rval_p)
{
	int r, i;
	struct kvm_vcpu *vcpu, *v;

	vcpu = kvm_arch_vcpu_create(kvm, id);
	if (vcpu == NULL)
		return (EINVAL);

	r = kvm_arch_vcpu_setup(vcpu);
	if (r) {
		kvm_arch_vcpu_free(vcpu);
		return (r);
	}

	mutex_enter(&kvm->lock);

	if (kvm->online_vcpus == KVM_MAX_VCPUS) {
		r = EINVAL;
		goto vcpu_destroy;
	}

	/* kvm_for_each_vcpu(r, v, kvm) */
	for (i = 0; i < kvm->online_vcpus; i++) {
		v = kvm->vcpus[i];
		if (v->vcpu_id == id) {
			r = -EEXIST;
			goto vcpu_destroy;
		}
	}

	/* BUG_ON(kvm->vcpus[atomic_read(&kvm->online_vcpus)]); */

	/* Now it's all set up, let userspace reach it */
	kvm_get_kvm(kvm);

	*rval_p = kvm->online_vcpus;  /* guarantee unique id */
	vcpu->vcpu_id = *rval_p;

	kvm->vcpus[kvm->online_vcpus] = vcpu;

	smp_wmb();

	atomic_inc_32((volatile uint32_t *)&kvm->online_vcpus);

	if (kvm->bsp_vcpu_id == id)
		kvm->bsp_vcpu = vcpu;

	mutex_exit(&kvm->lock);
	return (r);

vcpu_destroy:
	kvm_arch_vcpu_free(vcpu);
	mutex_exit(&kvm->lock);
	return (r);
}

static int
kvm_vcpu_ioctl_set_sigmask(struct kvm_vcpu *vcpu, sigset_t *sigset)
{
	if (sigset) {
		vcpu->sigset_active = 1;
		vcpu->sigset = *sigset;
	} else
		vcpu->sigset_active = 0;

	return (0);
}

static int
kvm_dev_ioctl_create_vm(kvm_devstate_t *ksp, intptr_t arg, int *rv)
{
	if (ksp->kds_kvmp != NULL)
		return (EINVAL);

	ksp->kds_kvmp = kvm_create_vm();

	if (ksp->kds_kvmp == NULL) {
		cmn_err(CE_WARN, "Could not create new vm\n");
		return (EIO);
	}
	*rv = ksp->kds_kvmp->kvmid;
	return (DDI_SUCCESS);
}

int
kvm_dev_ioctl_check_extension_generic(long arg, int *rv)
{
	switch (arg) {
	case KVM_CAP_USER_MEMORY:
	case KVM_CAP_DESTROY_MEMORY_REGION_WORKS:
	case KVM_CAP_JOIN_MEMORY_REGIONS_WORKS:
	case KVM_CAP_SET_BOOT_CPU_ID:
	case KVM_CAP_INTERNAL_ERROR_DATA:
		*rv = 1;
		return (DDI_SUCCESS);
	case KVM_CAP_IRQ_ROUTING:
		*rv = KVM_MAX_IRQ_ROUTES;
		return (DDI_SUCCESS);
	default:
		break;
	}
	return (kvm_dev_ioctl_check_extension(arg, rv));
}






/* kvm_io_bus_write - called under kvm->slots_lock */
int
kvm_io_bus_write(struct kvm *kvm, enum kvm_bus bus_idx, gpa_t addr,
    int len, const void *val)
{
	int i;
	struct kvm_io_bus *bus;

	mutex_enter(&kvm->buses_lock);
	bus = kvm->buses[bus_idx];

	for (i = 0; i < bus->dev_count; i++) {
		if (!kvm_iodevice_write(bus->devs[i], addr, len, val)) {
			mutex_exit(&kvm->buses_lock);
			return (0);
		}
	}
	mutex_exit(&kvm->buses_lock);

	return (-EOPNOTSUPP);
}

/* kvm_io_bus_read - called under kvm->slots_lock */
int
kvm_io_bus_read(struct kvm *kvm, enum kvm_bus bus_idx, gpa_t addr,
    int len, void *val)
{
	int i;
	struct kvm_io_bus *bus;

	mutex_enter(&kvm->buses_lock);
	bus = kvm->buses[bus_idx];
	for (i = 0; i < bus->dev_count; i++) {
		if (!kvm_iodevice_read(bus->devs[i], addr, len, val)) {
			mutex_exit(&kvm->buses_lock);
			return (0);
		}
	}
	mutex_exit(&kvm->buses_lock);

	return (-EOPNOTSUPP);
}

/* Caller must hold slots_lock. */
int
kvm_io_bus_register_dev(struct kvm *kvm,
    enum kvm_bus bus_idx, struct kvm_io_device *dev)
{
	struct kvm_io_bus *new_bus, *bus;

	new_bus = kmem_zalloc(sizeof (struct kvm_io_bus), KM_SLEEP);
	if (!new_bus)
		return (-ENOMEM);

	mutex_enter(&kvm->buses_lock);
	bus = kvm->buses[bus_idx];
	if (bus->dev_count > NR_IOBUS_DEVS-1) {
		mutex_exit(&kvm->buses_lock);
		kmem_free(new_bus, sizeof (struct kvm_io_bus));
		return (-ENOSPC);
	}

	memcpy(new_bus, bus, sizeof (struct kvm_io_bus));
	new_bus->devs[new_bus->dev_count++] = dev;

	kvm->buses[bus_idx] = new_bus;
	mutex_exit(&kvm->buses_lock);

	if (bus)
		kmem_free(bus, sizeof (struct kvm_io_bus));

	return (0);
}

/* Caller must hold slots_lock. */
int
kvm_io_bus_unregister_dev(struct kvm *kvm,
    enum kvm_bus bus_idx, struct kvm_io_device *dev)
{
	int i, r;
	struct kvm_io_bus *new_bus, *bus;

	new_bus = kmem_zalloc(sizeof (struct kvm_io_bus), KM_SLEEP);
	if (!new_bus)
		return (-ENOMEM);

	mutex_enter(&kvm->buses_lock);
	bus = kvm->buses[bus_idx];
	memcpy(new_bus, bus, sizeof (struct kvm_io_bus));

	r = -ENOENT;
	for (i = 0; i < new_bus->dev_count; i++) {
		if (new_bus->devs[i] == dev) {
			r = 0;
			new_bus->devs[i] = new_bus->devs[--new_bus->dev_count];
			break;
		}
	}

	if (r) {
		mutex_exit(&kvm->buses_lock);
		kmem_free(new_bus, sizeof (struct kvm_io_bus));
		return (r);
	}

	kvm->buses[bus_idx] = new_bus;
	mutex_exit(&kvm->buses_lock);

	kmem_free(bus, sizeof (struct kvm_io_bus));
	return (r);
}

int
kvm_init(void *opaque)
{
	int r;
	int cpu;

	r = kvm_arch_init(opaque);

	if (r != DDI_SUCCESS)
		return (r);

	bad_page = alloc_page(KM_SLEEP, &bad_page_kma);
	bad_pfn = bad_page->p_pagenum;

	r = kvm_arch_hardware_setup();

	if (r != DDI_SUCCESS)
		goto out_free;

	r = 0;
	kvm_xcall(KVM_CPUALL, kvm_arch_check_processor_compat, &r);
	if (r < 0)
		goto out_free_1;

	return (0);

out_free_1:
	kvm_arch_hardware_unsetup();
out_free:
	kmem_free(bad_page_kma, PAGESIZE);
	bad_page_kma = NULL;
	bad_page = NULL;
	bad_pfn = PFN_INVALID;
out:
	kvm_arch_exit();
out_fail:
	return (r);
}


void
kvm_guest_exit(struct kvm_vcpu *vcpu)
{
	KVM_TRACE1(guest__exit, struct kvm_vcpu *, vcpu);
}

void
kvm_guest_enter(struct kvm_vcpu *vcpu)
{
	KVM_TRACE1(guest__entry, struct kvm_vcpu *, vcpu);
}

/*
 * Find the first cleared bit in a memory region.
 */
unsigned long
find_first_zero_bit(const unsigned long *addr, unsigned long size)
{
	const unsigned long *p = addr;
	unsigned long result = 0;
	unsigned long tmp;

	while (size & ~(64-1)) {
		if (~(tmp = *(p++)))
			goto found;
		result += 64;
		size -= 64;
	}
	if (!size)
		return (result);

	tmp = (*p) | (~0UL << size);
	if (tmp == ~0UL)	/* Are any bits zero? */
		return (result + size);	/* Nope. */
found:
	return (result + ffz(tmp));
}

int
zero_constructor(void *buf, void *arg, int tags)
{
	bzero(buf, (size_t)arg);
	return (0);
}

static const char *kvm_hma_ident = "SmartOS KVM";

static boolean_t
kvm_hvm_init(void)
{
	hma_reg_t *reg;

	ASSERT(MUTEX_HELD(&kvm_lock));

	if ((reg = hma_register(kvm_hma_ident)) == NULL) {
		return (B_FALSE);
	}
	if (vmx_init() != DDI_SUCCESS) {
		hma_unregister(reg);
		return (B_FALSE);
	}

	kvm_hma_reg = reg;
	return (B_TRUE);
}

static void
kvm_hvm_fini(void)
{
	ASSERT(MUTEX_HELD(&kvm_lock));
	ASSERT(kvm_usage_count == 0);
	ASSERT3P(kvm_hma_reg, !=, NULL);

	kvm_arch_hardware_unsetup();
	vmx_fini();

	/*
	 * The bad_page_kma allocation is made during kvm_init, which is called
	 * via the HVM-specific functions (such as vmx_init.
	 */
	kmem_free(bad_page_kma, PAGESIZE);
	bad_page_kma = NULL;
	bad_page = NULL;
	bad_pfn = PFN_INVALID;

	kvm_arch_exit();

	hma_unregister(kvm_hma_reg);
	kvm_hma_reg = NULL;
}

static boolean_t
kvm_hvm_incr(void)
{
	ASSERT(MUTEX_NOT_HELD(&kvm_lock));

	mutex_enter(&kvm_lock);
	if (kvm_usage_count == 0) {
		if (!kvm_hvm_init()) {
			mutex_exit(&kvm_lock);
			return (B_FALSE);
		}
	}
	VERIFY(kvm_usage_count != UINT_MAX);
	kvm_usage_count++;
	mutex_exit(&kvm_lock);

	return (B_TRUE);
}

static void
kvm_hvm_decr(void)
{
	ASSERT(MUTEX_HELD(&kvm_lock));
	VERIFY(kvm_usage_count > 0);

	kvm_usage_count--;
	if (kvm_usage_count == 0) {
		kvm_hvm_fini();
	}
}

static int
kvm_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	if (kpm_enable == 0) {
		cmn_err(CE_WARN, "kvm: kpm_enable must be true\n");
		return (DDI_FAILURE);
	}

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	if (kvm_dip != NULL)
		return (DDI_FAILURE);

	if (ddi_soft_state_init(&kvm_state, sizeof (kvm_devstate_t), 1) != 0)
		return (DDI_FAILURE);

	if (ddi_create_minor_node(dip, "kvm", S_IFCHR, KVM_MINOR_BASE,
	    DDI_PSEUDO, 0) == DDI_FAILURE) {
		ddi_soft_state_fini(&kvm_state);
		return (DDI_FAILURE);
	}

	mutex_init(&kvm_lock, NULL, MUTEX_DRIVER, 0);

	list_create(&vm_list, sizeof (struct kvm),
	    offsetof(struct kvm, vm_list));
	kvm_minors = id_space_create("kvm_minor", KVM_MINOR_INSTS, INT32_MAX);

	kvm_dip = dip;
	ddi_report_dev(dip);

	return (DDI_SUCCESS);
}

static int
kvm_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	VERIFY(kvm_dip != NULL && kvm_dip == dip);
	VERIFY(kvm_usage_count == 0);

	ddi_prop_remove_all(dip);
	ddi_remove_minor_node(dip, NULL);
	list_destroy(&vm_list);
	id_space_destroy(kvm_minors);
	kvm_dip = NULL;

	mutex_destroy(&kvm_lock);
	ddi_soft_state_fini(&kvm_state);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
kvm_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	kvm_devstate_t *rsp;
	int error = DDI_FAILURE;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = kvm_dip;
		break;

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)((uint64_t)getminor((dev_t)arg));
		error = DDI_SUCCESS;
		break;

	default:
		break;
	}

	return (error);
}

/*ARGSUSED*/
static int
kvm_open(dev_t *devp, int flag, int otype, cred_t *credp)
{
	minor_t minor;
	kvm_devstate_t *ksp;

	if (flag & FEXCL || flag & FNDELAY)
		return (EINVAL);
	if (otype != OTYP_CHR)
		return (EINVAL);
	if (!(flag & FREAD && flag & FWRITE))
		return (EINVAL);

	if (getminor(*devp) != KVM_MINOR_BASE)
		return (ENXIO);

	minor = id_alloc(kvm_minors);
	if (ddi_soft_state_zalloc(kvm_state, minor) != 0) {
		id_free(kvm_minors, minor);
		return (ENXIO);
	}
	if (!kvm_hvm_incr()) {
		ddi_soft_state_free(kvm_state, minor);
		id_free(kvm_minors, minor);
		return (ENXIO);
	}

	*devp = makedevice(getmajor(*devp), minor);
	ksp = ddi_get_soft_state(kvm_state, minor);
	VERIFY(ksp != NULL);

	return (0);
}

/*ARGSUSED*/
static int
kvm_close(dev_t dev, int flag, int otyp, cred_t *cred)
{
	kvm_devstate_t *ksp;
	minor_t minor = getminor(dev);
	kvm_t *kvmp;

	VERIFY(getminor(dev) != KVM_MINOR_BASE);
	ksp = ddi_get_soft_state(kvm_state, minor);

	mutex_enter(&kvm_lock);
	if ((kvmp = ksp->kds_kvmp) != NULL) {
		if (kvmp->kvm_clones > 0) {
			kvmp->kvm_clones--;
		} else {
			kvm_destroy_vm(kvmp);
		}
	}
	kvm_hvm_decr();
	mutex_exit(&kvm_lock);

	ddi_soft_state_free(kvm_state, minor);
	id_free(kvm_minors, minor);

	return (0);
}

static int
kvm_ioctl(dev_t dev, int cmd, intptr_t arg, int md, cred_t *cr, int *rv)
{
	int rval = DDI_SUCCESS;
	minor_t minor;
	kvm_devstate_t *ksp;
	void *argp = (void *)arg;
	struct kvm_pit_config pit;

	minor = getminor(dev);
	ksp = ddi_get_soft_state(kvm_state, minor);
	if (ksp == NULL)
		return (ENXIO);

	struct {
		int cmd;		/* command */
		void *func;		/* function to call */
		size_t size;		/* size of user-level structure */
		boolean_t copyout;	/* boolean: copy out after func */
		boolean_t vmwide;	/* boolean: ioctl is not per-VCPU */
	} *ioctl, ioctltab[] = {
		{ KVM_RUN, kvm_arch_vcpu_ioctl_run },
		{ KVM_X86_SETUP_MCE, kvm_vcpu_ioctl_x86_setup_mce,
		    sizeof (uint64_t) },
		{ KVM_GET_MSRS, kvm_vcpu_ioctl_get_msrs,
		    sizeof (struct kvm_msrs), B_TRUE },
		{ KVM_SET_MSRS, kvm_vcpu_ioctl_set_msrs,
		    sizeof (struct kvm_msrs) },
		{ KVM_GET_MP_STATE, kvm_arch_vcpu_ioctl_get_mpstate,
		    sizeof (struct kvm_mp_state), B_TRUE },
		{ KVM_SET_MP_STATE, kvm_arch_vcpu_ioctl_set_mpstate,
		    sizeof (struct kvm_mp_state) },
		{ KVM_GET_REGS, kvm_arch_vcpu_ioctl_get_regs,
		    sizeof (struct kvm_regs), B_TRUE },
		{ KVM_SET_REGS, kvm_arch_vcpu_ioctl_set_regs,
		    sizeof (struct kvm_regs) },
		{ KVM_GET_SREGS, kvm_arch_vcpu_ioctl_get_sregs,
		    sizeof (struct kvm_sregs), B_TRUE },
		{ KVM_SET_SREGS, kvm_arch_vcpu_ioctl_set_sregs,
		    sizeof (struct kvm_sregs) },
		{ KVM_GET_FPU, kvm_arch_vcpu_ioctl_get_fpu,
		    sizeof (struct kvm_fpu), B_TRUE },
		{ KVM_SET_FPU, kvm_arch_vcpu_ioctl_set_fpu,
		    sizeof (struct kvm_fpu) },
		{ KVM_GET_CPUID2, kvm_vcpu_ioctl_get_cpuid2,
		    sizeof (struct kvm_cpuid2), B_TRUE },
		{ KVM_SET_CPUID2, kvm_vcpu_ioctl_set_cpuid2,
		    sizeof (struct kvm_cpuid2) },
		{ KVM_GET_LAPIC, kvm_vcpu_ioctl_get_lapic,
		    sizeof (struct kvm_lapic_state), B_TRUE },
		{ KVM_SET_LAPIC, kvm_vcpu_ioctl_set_lapic,
		    sizeof (struct kvm_lapic_state) },
		{ KVM_GET_VCPU_EVENTS, kvm_vcpu_ioctl_x86_get_vcpu_events,
		    sizeof (struct kvm_vcpu_events), B_TRUE },
		{ KVM_SET_VCPU_EVENTS, kvm_vcpu_ioctl_x86_set_vcpu_events,
		    sizeof (struct kvm_vcpu_events) },
		{ KVM_INTERRUPT, kvm_vcpu_ioctl_interrupt,
		    sizeof (struct kvm_interrupt) },
		{ KVM_SET_VAPIC_ADDR, kvm_lapic_set_vapic_addr,
		    sizeof (struct kvm_vapic_addr) },
		{ KVM_GET_PIT2, kvm_vm_ioctl_get_pit2,
		    sizeof (struct kvm_pit_state2), B_TRUE, B_TRUE },
		{ KVM_SET_PIT2, kvm_vm_ioctl_set_pit2,
		    sizeof (struct kvm_pit_state2), B_FALSE, B_TRUE },
		{ 0, NULL }
	};

	for (ioctl = &ioctltab[0]; ioctl->func != NULL; ioctl++) {
		caddr_t buf = NULL;

		if (ioctl->cmd != cmd)
			continue;

		if (ioctl->size != 0) {
			buf = kmem_alloc(ioctl->size, KM_SLEEP);

			if (copyin(argp, buf, ioctl->size) != 0) {
				kmem_free(buf, ioctl->size);
				return (EFAULT);
			}
		}

		if (ioctl->vmwide) {
			kvm_t *kvmp;
			int (*func)(kvm_t *, void *, int *, intptr_t);

			if ((kvmp = ksp->kds_kvmp) == NULL) {
				kmem_free(buf, ioctl->size);
				return (EINVAL);
			}

			func = (int(*)(kvm_t *, void *, int *,
			    intptr_t))ioctl->func;
			rval = func(kvmp, buf, rv, arg);
		} else {
			kvm_vcpu_t *vcpu;
			int (*func)(kvm_vcpu_t *, void *, int *, intptr_t);

			if ((vcpu = ksp->kds_vcpu) == NULL) {
				kmem_free(buf, ioctl->size);
				return (EINVAL);
			}

			func = (int(*)(kvm_vcpu_t *, void *, int *,
			    intptr_t))ioctl->func;
			rval = func(vcpu, buf, rv, arg);
		}

		if (rval == 0 && ioctl->size != 0 && ioctl->copyout) {
			if (copyout(buf, argp, ioctl->size) != 0) {
				kmem_free(buf, ioctl->size);
				return (EFAULT);
			}
		}

		kmem_free(buf, ioctl->size);

		return (rval < 0 ? -rval : rval);
	}

	switch (cmd) {
	case KVM_GET_API_VERSION:
		if (arg != (intptr_t)NULL) {
			rval = EINVAL;
			break;
		}
		*rv = KVM_API_VERSION;
		break;

	case KVM_CREATE_VM:
		if (arg != (intptr_t)NULL) {
			rval = EINVAL;
			break;
		}

		rval = kvm_dev_ioctl_create_vm(ksp, arg, rv);
		break;

	case KVM_CLONE: {
		dev_t parent = arg;
		kvm_devstate_t *clone;
		struct kvm *kvmp;

		/*
		 * We are not allowed to clone another open if we have created
		 * a virtual machine or virtual CPU with this open.
		 */
		if (ksp->kds_kvmp != NULL || ksp->kds_vcpu != NULL) {
			rval = EBUSY;
			break;
		}

		if (getmajor(parent) != getmajor(dev)) {
			rval = ENODEV;
			break;
		}

		minor = getminor(parent);

		mutex_enter(&kvm_lock);

		if ((clone = ddi_get_soft_state(kvm_state, minor)) == NULL) {
			mutex_exit(&kvm_lock);
			rval = EINVAL;
			break;
		}

		if ((kvmp = clone->kds_kvmp) == NULL) {
			mutex_exit(&kvm_lock);
			rval = ESRCH;
			break;
		}

		kvmp->kvm_clones++;
		ksp->kds_kvmp = kvmp;

		mutex_exit(&kvm_lock);
		break;
	}

	case KVM_CHECK_EXTENSION:
		rval = kvm_dev_ioctl_check_extension_generic(arg, rv);
		break;

	case KVM_GET_VCPU_MMAP_SIZE:
		if (arg != (intptr_t)NULL) {
			rval = EINVAL;
			break;
		}
		*rv = ptob(KVM_VCPU_MMAP_LENGTH);
		break;

	case KVM_CREATE_PIT2:
		if (copyin(argp, &pit, sizeof (struct kvm_pit_config)) != 0) {
			rval = EFAULT;
			break;
		}
		/*FALLTHROUGH*/

	case KVM_CREATE_PIT: {
		struct kvm *kvmp;

		if ((kvmp = ksp->kds_kvmp) == NULL) {
			rval = EINVAL;
			break;
		}

		if (cmd == KVM_CREATE_PIT) {
			pit.flags = KVM_PIT_SPEAKER_DUMMY;
		} else {
			ASSERT(cmd == KVM_CREATE_PIT2);
		}

		mutex_enter(&kvmp->slots_lock);

		if (kvmp->arch.vpit != NULL) {
			rval = EEXIST;
		} else if ((kvmp->arch.vpit = kvm_create_pit(kvmp,
		    pit.flags)) == NULL) {
			rval = ENOMEM;
		}

		mutex_exit(&kvmp->slots_lock);
		break;
	}

	case KVM_CREATE_IRQCHIP: {
		struct kvm_pic *vpic;
		struct kvm *kvmp;

		if ((kvmp = ksp->kds_kvmp) == NULL) {
			rval = EINVAL;
			break;
		}

		mutex_enter(&kvmp->lock);
		rval = EEXIST;
		if (kvmp->arch.vpic)
			goto create_irqchip_unlock;
		rval = ENOMEM;
		vpic = kvm_create_pic(kvmp);
		if (vpic) {
			rval = kvm_ioapic_init(kvmp);
			if (rval) {
				kvm_io_bus_unregister_dev(kvmp,
				    KVM_PIO_BUS, &vpic->dev);
				goto create_irqchip_unlock;
			}
		} else
			goto create_irqchip_unlock;

		smp_wmb();
		kvmp->arch.vpic = vpic;
		smp_wmb();

		rval = kvm_setup_default_irq_routing(kvmp);
		if (rval) {
			mutex_enter(&kvmp->irq_lock);
			kvm_ioapic_destroy(kvmp);
			kvm_destroy_pic(kvmp);
			mutex_exit(&kvmp->irq_lock);
		}
	create_irqchip_unlock:
		mutex_exit(&kvmp->lock);
		break;
	}

	case KVM_X86_GET_MCE_CAP_SUPPORTED: {
		uint64_t mce_cap = KVM_MCE_CAP_SUPPORTED;

		if (copyout(&mce_cap, argp, sizeof (mce_cap)))
			rval = EFAULT;

		break;
	}

	case KVM_SET_IDENTITY_MAP_ADDR: {
		uint64_t addr;

		if (ksp->kds_kvmp == NULL) {
			rval = EINVAL;
			break;
		}

		if (copyin((void *)arg, &addr, sizeof (uint64_t)) != 0) {
			rval = EFAULT;
			break;
		}

		rval = kvm_vm_ioctl_set_identity_map_addr(ksp->kds_kvmp, addr);

		*rv = 0;
		break;
	}

	case KVM_GET_MSR_INDEX_LIST: {
		rval = kvm_vm_ioctl_get_msr_index_list(NULL, arg);
		*rv = 0;
		break;
	}
	case KVM_CREATE_VCPU: {
		uint32_t id = (uintptr_t)arg;
		struct kvm *kvmp;
		struct kvm_vcpu *vcpu;

		if ((kvmp = ksp->kds_kvmp) == NULL) {
			rval = EINVAL;
			break;
		}

		if (ksp->kds_vcpu != NULL) {
			rval = EEXIST;
			break;
		}

		rval = kvm_vm_ioctl_create_vcpu(ksp->kds_kvmp, id, rv);

		if (rval == 0) {
			ksp->kds_vcpu = kvmp->vcpus[id];
			ASSERT(ksp->kds_vcpu != NULL);
		}

		break;
	}

	case KVM_SET_USER_MEMORY_REGION: {
		struct kvm_userspace_memory_region map;
		struct kvm *kvmp;

		if (copyin(argp, &map, sizeof (map)) != 0) {
			rval = EFAULT;
			break;
		}

		if ((kvmp = ksp->kds_kvmp) == NULL) {
			rval = EINVAL;
			break;
		}

		rval = kvm_vm_ioctl_set_memory_region(kvmp, &map, 1);
		break;
	}

	case KVM_GET_SUPPORTED_CPUID: {
		struct kvm_cpuid2 *cpuid_arg = (struct kvm_cpuid2 *)arg;
		struct kvm_cpuid2 *cpuid;

		cpuid = kmem_zalloc(sizeof (struct kvm_cpuid2), KM_SLEEP);

		if (copyin(argp, cpuid, sizeof (struct kvm_cpuid2)) != 0) {
			kmem_free(cpuid, sizeof (struct kvm_cpuid2));
			rval = EFAULT;
			break;
		}

		if ((rval = kvm_dev_ioctl_get_supported_cpuid(cpuid,
		    cpuid_arg->entries)) != 0) {
			kmem_free(cpuid, sizeof (struct kvm_cpuid2));
			break;
		}

		if (copyout(&cpuid->nent, cpuid_arg, sizeof (int)))
			rval = EFAULT;

		kmem_free(cpuid, sizeof (struct kvm_cpuid2));
		break;
	}
	case KVM_SET_SIGNAL_MASK: {
		struct kvm_signal_mask *sigmask = argp;
		struct kvm_signal_mask kvm_sigmask;
		sigset_t sigset;
		struct kvm_vcpu *vcpu;

		if ((vcpu = ksp->kds_vcpu) == NULL) {
			rval = EINVAL;
			break;
		}

		if (argp == NULL) {
			rval = kvm_vcpu_ioctl_set_sigmask(vcpu, NULL);
			break;
		}

		if (copyin(argp, &kvm_sigmask, sizeof (kvm_sigmask)) != 0) {
			rval = EFAULT;
			break;
		}

		if (kvm_sigmask.len != sizeof (sigset)) {
			rval = EINVAL;
			break;
		}

		if (copyin(sigmask->sigset, &sigset, sizeof (sigset)) != 0) {
			rval = EINVAL;
			break;
		}

		rval = kvm_vcpu_ioctl_set_sigmask(vcpu, &sigset);
		break;
	}

	case KVM_SET_TSS_ADDR: {

		if (ksp->kds_kvmp == NULL) {
			rval = EINVAL;
			break;
		}

		rval = kvm_vm_ioctl_set_tss_addr(ksp->kds_kvmp, arg);
		break;
	}

	case KVM_SET_BOOT_CPU_ID: {
		struct kvm *kvmp;

		if ((kvmp = ksp->kds_kvmp) == NULL) {
			rval = EINVAL;
			break;
		}

		if (arg >= KVM_MAX_VCPUS) {
			rval = EINVAL;
			break;
		}

		mutex_enter(&kvmp->lock);
		if (kvmp->online_vcpus != 0) {
			rval = EBUSY;
			break;
		} else {
			kvmp->bsp_vcpu_id = arg;
			*rv = kvmp->bsp_vcpu_id;
		}

		mutex_exit(&kvmp->lock);
		break;
	}

	case KVM_REGISTER_COALESCED_MMIO: {
		struct kvm *kvmp;
		struct kvm_coalesced_mmio_zone *zone;
		size_t sz = sizeof (struct kvm_coalesced_mmio_zone);

		zone = kmem_zalloc(sz, KM_SLEEP);

		if (copyin(argp, zone, sz) != 0) {
			kmem_free(zone, sz);
			rval = EFAULT;
			break;
		}

		if ((kvmp = ksp->kds_kvmp) == NULL) {
			rval = EINVAL;
			kmem_free(zone, sz);
			break;
		}

		rval = kvm_vm_ioctl_register_coalesced_mmio(kvmp, zone);

		kmem_free(zone, sz);
		break;
	}

	case KVM_UNREGISTER_COALESCED_MMIO: {
		struct kvm_coalesced_mmio_zone *zone;
		struct kvm *kvmp;
		size_t sz = sizeof (struct kvm_coalesced_mmio_zone);

		zone = kmem_zalloc(sz, KM_SLEEP);

		if (copyin(argp, zone, sz) != 0) {
			kmem_free(zone, sz);
			break;
		}

		if ((kvmp = ksp->kds_kvmp) == NULL) {
			kmem_free(zone, sz);
			rval = EINVAL;
			break;
		}

		rval = kvm_vm_ioctl_unregister_coalesced_mmio(kvmp, zone);

		kmem_free(zone, sz);
		break;
	}
#ifdef KVM_CAP_IRQ_ROUTING
	case KVM_SET_GSI_ROUTING: {
		struct kvm_irq_routing *route;
		struct kvm *kvmp;
		struct kvm_irq_routing_entry *entries;
		uint32_t nroutes;
		size_t sz = sizeof (kvm_irq_routing_t) + KVM_MAX_IRQ_ROUTES *
		    sizeof (struct kvm_irq_routing_entry);

		/*
		 * Note the route must be allocated on the heap. The sizeof
		 * (kvm_kirq_routing) is approximately 0xc038 currently.
		 */
		route = kmem_zalloc(sz, KM_SLEEP);

		/*
		 * copyin the number of routes, then copyin the routes
		 * themselves.
		 */
		if (copyin(argp, &nroutes, sizeof (nroutes)) != 0) {
			kmem_free(route, sz);
			rval = EFAULT;
			break;
		}

		if (nroutes <= 0) {
			kmem_free(route, sz);
			rval = EINVAL;
			break;
		}

		if (copyin(argp, route,
		    sizeof (struct kvm_irq_routing) + (nroutes - 1) *
		    sizeof (struct kvm_irq_routing_entry)) != 0) {
			kmem_free(route, sz);
			rval = EFAULT;
			break;
		}

		if ((kvmp = ksp->kds_kvmp) == NULL) {
			kmem_free(route, sz);
			rval = EINVAL;
			break;
		}

		if (route->nr >= KVM_MAX_IRQ_ROUTES || route->flags) {
			kmem_free(route, sz);
			rval = EINVAL;
			break;
		}

		rval = kvm_set_irq_routing(kvmp, route->entries,
		    route->nr, route->flags);
		kmem_free(route, sz);
		*rv = 0;
		break;
	}
#endif /* KVM_CAP_IRQ_ROUTING */
	case KVM_IRQ_LINE_STATUS:
	case KVM_IRQ_LINE: {
		struct kvm_irq_level level;
		struct kvm *kvmp;
		size_t sz = sizeof (struct kvm_irq_level);
		int32_t status;

		if (copyin(argp, &level, sz) != 0) {
			rval = EFAULT;
			break;
		}

		if ((kvmp = ksp->kds_kvmp) == NULL) {
			rval = EINVAL;
			break;
		}

		if (!irqchip_in_kernel(kvmp)) {
			rval = ENXIO;
			break;
		}

		status = kvm_set_irq(kvmp, KVM_USERSPACE_IRQ_SOURCE_ID,
		    level.irq, level.level);

		if (cmd == KVM_IRQ_LINE_STATUS) {
			level.status = status;

			if (copyout(&level, argp, sz) != 0) {
				rval = EFAULT;
				break;
			}
		}

		break;
	}

	case KVM_GET_IRQCHIP: {
		struct kvm *kvmp;
		struct kvm_irqchip chip;
		size_t sz = sizeof (struct kvm_irqchip);
		/* 0: PIC master, 1: PIC slave, 2: IOAPIC */

		if ((kvmp = ksp->kds_kvmp) == NULL) {
			rval = EINVAL;
			break;
		}

		if (!irqchip_in_kernel(kvmp)) {
			rval = ENXIO;
			break;
		}

		rval = kvm_vm_ioctl_get_irqchip(kvmp, &chip);

		if (rval == 0 && copyout(&chip, argp, sz) != 0) {
			rval = EFAULT;
			break;
		}

		break;
	}

	case KVM_SET_IRQCHIP: {
		struct kvm *kvmp;
		struct kvm_irqchip chip;
		size_t sz = sizeof (struct kvm_irqchip);
		/* 0: PIC master, 1: PIC slave, 2: IOAPIC */

		if ((kvmp = ksp->kds_kvmp) == NULL) {
			rval = EINVAL;
			break;
		}

		if (copyin(argp, &chip, sizeof (struct kvm_irqchip)) != 0) {
			rval = EFAULT;
			break;
		}

		if (!irqchip_in_kernel(kvmp)) {
			rval = ENXIO;
			break;
		}

		rval = kvm_vm_ioctl_set_irqchip(kvmp, &chip);
		break;
	}
	case KVM_GET_DIRTY_LOG: {
		struct kvm_dirty_log log;
		struct kvm *kvmp;

		if ((kvmp = ksp->kds_kvmp) == NULL) {
			rval = EINVAL;
			break;
		}

		if (copyin(argp, &log, sizeof (struct kvm_dirty_log)) != 0) {
			rval = EFAULT;
			break;
		}

		rval = kvm_vm_ioctl_get_dirty_log(kvmp, &log);
		break;
	}
	case KVM_NMI: {

		if (ksp->kds_kvmp == NULL) {
			rval = EINVAL;
			break;
		}

		if (ksp->kds_vcpu == NULL) {
			rval = EINVAL;
			break;
		}

		rval = kvm_vcpu_ioctl_nmi(ksp->kds_vcpu);
		break;
	}
	default:
		KVM_TRACE1(bad__ioctl, int, cmd);
		rval = EINVAL;  /* x64, others may do other things... */
	}

	if (*rv == -1)
		return (EINVAL);

	return (rval < 0 ? -rval : rval);
}

/* BEGIN CSTYLED */

/*
 * mmap(2), segmap(9E), and devmap(9E)
 *
 * Users call mmap(2). For each call to mmap(2) there is a corresponding call to
 * segmap(9E). segmap(9E) is responsible for making sure that the various
 * requests in the mmap call make sense from the question of protection,
 * offsets, lengths, etc. It then ends by calling the ddi_devmap_segmap() which
 * is what is responsible for making all of the actual mappings.
 *
 * The devmap entry point is called a variable number of times. It is called a
 * number of times until all the maplen values equal the original length of the
 * requested mapping. This allows us to make several different mappings by not
 * honoring the full requested mapping the first time. Each subsequent time it
 * is called with an updated offset and length.
 */


/*
 * We can only create one mapping per dhp. We know whether this is the first
 * time or the second time in based on the requested offset / length. If we only
 * have one page worth, then it's always looking for the shared mmio page. If it
 * is asking for KVM_VCPU_MMAP_LENGTH pages, then it's asking for the shared
 * vcpu pages.
 */
static int
kvm_devmap(dev_t dev, devmap_cookie_t dhp, offset_t off, size_t len,
    size_t *maplen, uint_t model)
{
	int res;
	minor_t instance;
	kvm_devstate_t *ksp;
	kvm_vcpu_t *vcpu;

	instance = getminor(dev);
	ksp = ddi_get_soft_state(kvm_state, instance);
	if (ksp == NULL)
		return (ENXIO);

	/*
	 * Enforce that only 64-bit guests are allowed.
	 */
	if (ddi_model_convert_from(model) == DDI_MODEL_ILP32)
		return (EINVAL);

	/* Double check for betrayl */
	if (ksp->kds_kvmp == NULL)
		return (EINVAL);

	if (ksp->kds_vcpu == NULL)
		return (EINVAL);

	vcpu = ksp->kds_vcpu;

	if (len == PAGESIZE) {
		res = devmap_umem_setup(dhp, kvm_dip, NULL,
		    ksp->kds_kvmp->mmio_cookie, 0, len, PROT_READ | PROT_WRITE |
		    PROT_USER, DEVMAP_DEFAULTS, NULL);
		*maplen = len;
		return (res);
	}

	res = devmap_umem_setup(dhp, kvm_dip, NULL, vcpu->cookie, 0,
	    PAGESIZE*2, PROT_READ | PROT_WRITE | PROT_USER, DEVMAP_DEFAULTS,
	    NULL);

	*maplen = PAGESIZE * 2;

	return (res);
}

/*
 * We determine which vcpu we're trying to mmap in based upon the file
 * descriptor that is used. For a given vcpu n the offset to specify it is
 * n*KVM_VCPU_MMAP_LENGTH. Thus the first vcpu is at offset 0.
 */
static int
kvm_segmap(dev_t dev, off_t off, struct as *asp, caddr_t *addrp, off_t len,
    unsigned int prot, unsigned int maxprot, unsigned int flags,
    cred_t *credp)
{
	kvm_devstate_t *ksp;
	off_t poff;

	if ((ksp = ddi_get_soft_state(kvm_state, getminor(dev))) == NULL)
		return (ENXIO);

	if (prot & PROT_EXEC)
		return (EINVAL);

	if (!(prot & PROT_USER))
	    return (EINVAL);

	if (len != ptob(KVM_VCPU_MMAP_LENGTH))
		return (EINVAL);

	/*
	 * Verify that we have a VCPU
	 */
	if (ksp->kds_vcpu == NULL)
		return (EINVAL);

	/*
	 * We only allow mmaping at a specific cpu
	 */
	if (off != 0)
		return (EINVAL);

	return (ddi_devmap_segmap(dev, off, asp, addrp, len, prot, maxprot,
	    flags, credp));
}


static struct cb_ops kvm_cb_ops = {
	kvm_open,
	kvm_close,	/* close */
	nodev,
	nodev,
	nodev,		/* dump */
	nodev,		/* read */
	nodev,		/* write */
	kvm_ioctl,
	kvm_devmap,
	nodev,		/* mmap */
	kvm_segmap,	/* segmap */
	nochpoll,	/* poll */
	ddi_prop_op,
	NULL,
	D_NEW | D_MP | D_DEVMAP
};

static struct dev_ops kvm_ops = {
	DEVO_REV,
	0,
	kvm_getinfo,
	nulldev,	/* identify */
	nulldev,	/* probe */
	kvm_attach,
	kvm_detach,
	nodev,		/* reset */
	&kvm_cb_ops,
	(struct bus_ops *)0
};

static struct modldrv modldrv = {
	&mod_driverops,
	"kvm driver v0.1",
	&kvm_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	{ &modldrv, NULL }
};

int
_init(void)
{

	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
/* END CSTYLED */
