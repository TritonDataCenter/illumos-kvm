/*
 * Copyright (c) 2011, Joyent, Inc. All rights reserved.
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
#include <sys/mdb_modapi.h>

#include "msr.h"
#include "kvm_vmx.h"
#include "kvm_iodev.h"
#include "kvm_host.h"
#include "kvm_x86host.h"
#include "kvm.h"

int
kvm_mdb_memory_slot_init(mdb_walk_state_t *wsp)
{
	struct kvm_memslots *memslots;
	struct kvm kvm;
	uintptr_t addr;

	if (wsp->walk_addr == NULL) {
		mdb_warn("kvm_memory_slot does not support global walks");
		return (WALK_ERR);
	}

	if (mdb_vread(&kvm, sizeof (kvm), wsp->walk_addr) == -1) {
		mdb_warn("couldn't read kvm at %p", wsp->walk_addr);
		return (DCMD_ERR);
	}

	addr = (uintptr_t)kvm.memslots;
	memslots = mdb_alloc(sizeof (struct kvm_memslots), UM_SLEEP | UM_GC);

	if (mdb_vread(memslots, sizeof (struct kvm_memslots), addr) == -1) {
		mdb_warn("couldn't read memslots at %p", addr);
		return (DCMD_ERR);
	}

	wsp->walk_addr = addr + offsetof(struct kvm_memslots, memslots);
	wsp->walk_arg = 0;
	wsp->walk_data = memslots;

	return (WALK_NEXT);
}

int
kvm_mdb_memory_slot_step(mdb_walk_state_t *wsp)
{
	struct kvm_memslots *memslots = wsp->walk_data;
	uintptr_t ndx = (uintptr_t)wsp->walk_arg;

	if (ndx >= KVM_MEMORY_SLOTS)
		return (WALK_DONE);

	wsp->walk_arg = (void *)(ndx + 1);

	return (wsp->walk_callback(wsp->walk_addr +
	    ndx * sizeof (struct kvm_memory_slot), &memslots->memslots[ndx],
	    wsp->walk_cbdata));
}

int
kvm_mdb_mem_alias_init(mdb_walk_state_t *wsp)
{
	struct kvm_mem_aliases *aliases;
	struct kvm kvm;
	uintptr_t addr;

	if (wsp->walk_addr == NULL) {
		mdb_warn("kvm_mem_alias does not support global walks");
		return (WALK_ERR);
	}

	if (mdb_vread(&kvm, sizeof (kvm), wsp->walk_addr) == -1) {
		mdb_warn("couldn't read kvm at %p", wsp->walk_addr);
		return (DCMD_ERR);
	}

	addr = (uintptr_t)kvm.arch.aliases;
	aliases = mdb_alloc(sizeof (struct kvm_mem_aliases), UM_SLEEP | UM_GC);

	if (mdb_vread(aliases, sizeof (struct kvm_mem_aliases), addr) == -1) {
		mdb_warn("couldn't read aliases at %p", addr);
		return (DCMD_ERR);
	}

	wsp->walk_addr = addr + offsetof(struct kvm_mem_aliases, aliases);
	wsp->walk_arg = 0;
	wsp->walk_data = aliases;

	return (WALK_NEXT);
}

int
kvm_mdb_mem_alias_step(mdb_walk_state_t *wsp)
{
	struct kvm_mem_aliases *aliases = wsp->walk_data;
	uintptr_t ndx = (uintptr_t)wsp->walk_arg;

	if (ndx >= aliases->naliases)
		return (WALK_DONE);

	wsp->walk_arg = (void *)(ndx + 1);

	return (wsp->walk_callback(wsp->walk_addr +
	    ndx * sizeof (struct kvm_mem_alias), &aliases->aliases[ndx],
	    wsp->walk_cbdata));
}

static int
kvm_mdb_gpa2qva_walk_alias(uintptr_t addr,
    const struct kvm_mem_alias *alias, uintptr_t *gfn)
{
	if (alias->flags & KVM_ALIAS_INVALID)
		return (WALK_NEXT);

	if (*gfn < alias->base_gfn || *gfn >= alias->base_gfn + alias->npages)
		return (WALK_NEXT);

	*gfn = alias->target_gfn + *gfn - alias->base_gfn;

	return (WALK_DONE);
}

static int
kvm_mdb_gpa2qva_walk_slot(uintptr_t addr,
    const struct kvm_memory_slot *memslot, uintptr_t *gpa)
{
	uintptr_t gfn = *gpa >> PAGESHIFT;

	if (gfn < memslot->base_gfn)
		return (WALK_NEXT);

	if (gfn >= memslot->base_gfn + memslot->npages)
		return (WALK_NEXT);

	mdb_printf("%p\n", memslot->userspace_addr +
	    ((gfn - memslot->base_gfn) << PAGESHIFT) + (*gpa & PAGEOFFSET));

	*gpa = -1;

	return (WALK_DONE);
}

static int
kvm_mdb_gpa2qva(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct kvm kvm;
	uintptr_t gpa = addr, gfn, kaddr;
	int i;

	if (!(flags & DCMD_ADDRSPEC) || argc < 1)
		return (DCMD_USAGE);

	switch (argv[0].a_type) {
	case MDB_TYPE_STRING:
		kaddr = mdb_strtoull(argv[0].a_un.a_str);
		break;

	case MDB_TYPE_IMMEDIATE:
		kaddr = argv[0].a_un.a_val;
		break;

	default:
		return (DCMD_USAGE);
	}

	if (mdb_vread(&kvm, sizeof (kvm), kaddr) == -1) {
		mdb_warn("couldn't read kvm at %p", kaddr);
		return (DCMD_ERR);
	}

	gfn = gpa >> PAGESHIFT;

	/*
	 * First unalias our guest PFN...
	 */
	if (mdb_pwalk("kvm_mem_alias",
	    (mdb_walk_cb_t)kvm_mdb_gpa2qva_walk_alias, &gfn, kaddr) == -1) {
		mdb_warn("failed to walk 'kvm_memory_slot' for %p", kaddr);
		return (DCMD_ERR);
	}

	gpa = (gfn << PAGESHIFT) | (gpa & PAGEOFFSET);

	/*
	 * Now walk memory slots looking for a match.
	 */
	if (mdb_pwalk("kvm_memory_slot",
	    (mdb_walk_cb_t)kvm_mdb_gpa2qva_walk_slot, &gpa, kaddr) == -1) {
		mdb_warn("failed to walk 'kvm_memory_slot' for %p", kaddr);
		return (DCMD_ERR);
	}

	if (gpa != -1) {
		mdb_warn("0x%p is unknown for kvm 0x%p", addr, kaddr);
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

static int
kvm_mdb_gsiroutes(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct kvm kvm;
	struct kvm_irq_routing_table *table;
	int ii, jj;

	if (argc > 1)
		return (DCMD_USAGE);

	if (mdb_vread(&kvm, sizeof (struct kvm), addr) == -1) {
		mdb_warn("couldn't read kvm at %p", addr);
		return (DCMD_ERR);
	}

	table = mdb_alloc(sizeof (struct kvm_irq_routing_table),
	    UM_SLEEP | UM_GC);

	if (mdb_vread(table, sizeof (struct kvm_irq_routing_table),
	    (uintptr_t)kvm.irq_routing) == -1) {
		mdb_warn("couldn't read kvm irq routing table at %p",
		    kvm.irq_routing);
		return (DCMD_ERR);
	}

	if (DCMD_HDRSPEC(flags))
		mdb_printf("%s %7s %5s\n", "CHIP", "PORT", "GSI");

	for (ii = 0; ii < KVM_NR_IRQCHIPS; ii++) {
		for (jj = 0; jj < KVM_IOAPIC_NUM_PINS; jj++)
			mdb_printf("%3d %7d    0x%x\n", ii, jj,
			    table->chip[ii][jj]);
	}

	return (DCMD_OK);
}

static int
kvm_mdb_kvm_walk_init(mdb_walk_state_t *wsp)
{
	list_t list;
	GElf_Sym sym;
	if (wsp->walk_addr != NULL) {
		mdb_warn("kvm does not support non-global walks\n");
		return (WALK_ERR);
	}

	if (mdb_lookup_by_name("vm_list", &sym) != 0) {
		mdb_warn("unable to locate vm_list\n");
		return (WALK_ERR);
	}

	wsp->walk_addr = sym.st_value;

	if (mdb_vread(&list, sizeof (list_t), wsp->walk_addr) == -1) {
		mdb_warn("failed to read vm_list\n");
		return (WALK_ERR);
	}

	if (mdb_layered_walk("list", wsp) == -1) {
		mdb_warn("failed to walk 'list'\n");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

static int
kvm_mdb_kvm_walk_step(mdb_walk_state_t *wsp)
{
	return (wsp->walk_callback(wsp->walk_addr, wsp->walk_layer,
	    wsp->walk_cbdata));
}

static const mdb_dcmd_t dcmds[] = {
	{ "kvm_gpa2qva", "?[address of kvm]", "translate a guest physical "
	    "to a QEMU virtual address", kvm_mdb_gpa2qva },
	{ "kvm_gsiroutes", NULL, "print out the global system "
	    "interrupt (GSI) routing table", kvm_mdb_gsiroutes },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "kvm_memory_slot", "walk kvm_memory_slot structures for a given kvm",
	    kvm_mdb_memory_slot_init, kvm_mdb_memory_slot_step },
	{ "kvm_mem_alias", "walk kvm_mem_alias structures for a given kvm",
	    kvm_mdb_mem_alias_init, kvm_mdb_mem_alias_step },
	{ "kvm", "walk all the kvm structures",
	    kvm_mdb_kvm_walk_init, kvm_mdb_kvm_walk_step },
	{ NULL }
};

static const mdb_modinfo_t modinfo = { MDB_API_VERSION, dcmds, walkers };

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
