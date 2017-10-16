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
 * Copyright 2017 Joyent, Inc.
 * Copyright 2011 Joshua M. Clulow <josh@sysmgr.org>
 * Copyright 2011 Richard Lowe
 */

#include <sys/sysmacros.h>

#include "kvm_bitops.h"
#include "kvm_cache_regs.h"
#include "kvm_x86impl.h"
#include "kvm_host.h"
#include "kvm_mmu.h"
#include "msr-index.h"

/*
 * When setting this variable to true it enables Two-Dimensional-Paging
 * where the hardware walks 2 page tables:
 * 1. the guest-virtual to guest-physical
 * 2. while doing 1. it walks guest-physical to host-physical
 * If the hardware supports that we don't need to do shadow paging.
 */
int tdp_enabled = 0;

static int oos_shadow = 1;

#define	virt_to_page(addr) pfn_to_page(hat_getpfnum(kas.a_hat, addr))

#define	PT_FIRST_AVAIL_BITS_SHIFT 9
#define	PT64_SECOND_AVAIL_BITS_SHIFT 52

#define	VALID_PAGE(x) ((x) != INVALID_PAGE)

#define	PT64_LEVEL_BITS 9

#define	PT64_LEVEL_SHIFT(level) \
		(PAGESHIFT + (level - 1) * PT64_LEVEL_BITS)

#define	PT64_LEVEL_MASK(level) \
		(((1ULL << PT64_LEVEL_BITS) - 1) << PT64_LEVEL_SHIFT(level))

#define	PT64_INDEX(address, level)\
	(((address) >> PT64_LEVEL_SHIFT(level)) & ((1 << PT64_LEVEL_BITS) - 1))

#define	PT32_LEVEL_BITS 10

#define	PT32_LEVEL_SHIFT(level) \
	(PAGESHIFT + (level - 1) * PT32_LEVEL_BITS)

#define	PT32_LEVEL_MASK(level) \
	(((1ULL << PT32_LEVEL_BITS) - 1) << PT32_LEVEL_SHIFT(level))

#define	PT32_LVL_OFFSET_MASK(level) (PT32_BASE_ADDR_MASK & \
	((1ULL << (PAGESHIFT + (((level) - 1) * PT32_LEVEL_BITS))) - 1))


#define	PT32_INDEX(address, level) \
	(((address) >> PT32_LEVEL_SHIFT(level)) & ((1 << PT32_LEVEL_BITS) - 1))


#define	PT64_BASE_ADDR_MASK (((1ULL << 52) - 1) & ~(uint64_t)(PAGESIZE-1))

#define	PT64_DIR_BASE_ADDR_MASK \
	(PT64_BASE_ADDR_MASK & ~((1ULL << (PAGESHIFT + PT64_LEVEL_BITS)) - 1))

#define	PT64_LVL_ADDR_MASK(level) \
	(PT64_BASE_ADDR_MASK & \
	~((1ULL << (PAGESHIFT + (((level) - 1) * PT64_LEVEL_BITS))) - 1))

#define	PT64_LVL_OFFSET_MASK(level) (PT64_BASE_ADDR_MASK & \
	((1ULL << (PAGESHIFT + (((level) - 1) * PT64_LEVEL_BITS))) - 1))

#define	PT32_BASE_ADDR_MASK PAGEMASK

#define	PT32_DIR_BASE_ADDR_MASK \
	(PAGEMASK & ~((1ULL << (PAGESHIFT + PT32_LEVEL_BITS)) - 1))

#define	PT32_LVL_ADDR_MASK(level) (PAGEMASK & \
	~((1ULL << (PAGESHIFT + (((level) - 1) * PT32_LEVEL_BITS))) - 1))

#define	PT64_PERM_MASK (PT_PRESENT_MASK | PT_WRITABLE_MASK | PT_USER_MASK \
	| PT64_NX_MASK)

#define	RMAP_EXT 4

#define	ACC_EXEC_MASK    1
#define	ACC_WRITE_MASK   PT_WRITABLE_MASK
#define	ACC_USER_MASK    PT_USER_MASK
#define	ACC_ALL		(ACC_EXEC_MASK | ACC_WRITE_MASK | ACC_USER_MASK)

#define	SPTE_HOST_WRITEABLE (1ULL << PT_FIRST_AVAIL_BITS_SHIFT)

#define	SHADOW_PT_INDEX(addr, level) PT64_INDEX(addr, level)

typedef struct kvm_rmap_desc {
	uint64_t *sptes[RMAP_EXT];
	struct kvm_rmap_desc *more;
} kvm_rmap_desc_t;

typedef struct kvm_shadow_walk_iterator {
	uint64_t addr;
	hpa_t shadow_addr;
	uint64_t *sptep;
	int level;
	unsigned index;
} kvm_shadow_walk_iterator_t;

#define	for_each_shadow_entry(_vcpu, _addr, _walker)    \
	for (shadow_walk_init(&(_walker), _vcpu, _addr);	\
	    shadow_walk_okay(&(_walker), _vcpu);		\
	    shadow_walk_next(&(_walker)))

typedef int (*mmu_parent_walk_fn) (struct kvm_vcpu *, struct kvm_mmu_page *);

struct kmem_cache *pte_chain_cache;
struct kmem_cache *rmap_desc_cache;
struct kmem_cache *mmu_page_header_cache;

static uint64_t shadow_trap_nonpresent_pte;
static uint64_t shadow_notrap_nonpresent_pte;
static uint64_t shadow_base_present_pte;
static uint64_t shadow_nx_mask;
static uint64_t shadow_x_mask;	/* mutual exclusive with nx_mask */
static uint64_t shadow_user_mask;
static uint64_t shadow_accessed_mask;
static uint64_t shadow_dirty_mask;

static uint64_t
rsvd_bits(int s, int e)
{
	return (((1ULL << (e - s + 1)) - 1) << s);
}

void
kvm_mmu_set_nonpresent_ptes(uint64_t trap_pte, uint64_t notrap_pte)
{
	shadow_trap_nonpresent_pte = trap_pte;
	shadow_notrap_nonpresent_pte = notrap_pte;
}

void
kvm_mmu_set_base_ptes(uint64_t base_pte)
{
	shadow_base_present_pte = base_pte;
}

void
kvm_mmu_set_mask_ptes(uint64_t user_mask, uint64_t accessed_mask,
    uint64_t dirty_mask, uint64_t nx_mask, uint64_t x_mask)
{
	shadow_user_mask = user_mask;
	shadow_accessed_mask = accessed_mask;
	shadow_dirty_mask = dirty_mask;
	shadow_nx_mask = nx_mask;
	shadow_x_mask = x_mask;
}

static int
is_write_protection(struct kvm_vcpu *vcpu)
{
	return (kvm_read_cr0_bits(vcpu, X86_CR0_WP));
}

static int
is_cpuid_PSE36(void)
{
	return (1);
}

static int
is_nx(struct kvm_vcpu *vcpu)
{
	return (vcpu->arch.efer & EFER_NX);
}

static int
is_shadow_present_pte(uint64_t pte)
{
	return (pte != shadow_trap_nonpresent_pte &&
	    pte != shadow_notrap_nonpresent_pte);
}

static int
is_large_pte(uint64_t pte)
{
	return (pte & PT_PAGE_SIZE_MASK);
}

static int
is_writable_pte(unsigned long pte)
{
	return (pte & PT_WRITABLE_MASK);
}

static int
is_dirty_gpte(unsigned long pte)
{
	return (pte & PT_DIRTY_MASK);
}

static int
is_rmap_spte(uint64_t pte)
{
	return (is_shadow_present_pte(pte));
}

static int
is_last_spte(uint64_t pte, int level)
{
	if (level == PT_PAGE_TABLE_LEVEL)
		return (1);
	if (is_large_pte(pte))
		return (1);
	return (0);
}

static pfn_t
spte_to_pfn(uint64_t pte)
{
	return ((pte & PT64_BASE_ADDR_MASK) >> PAGESHIFT);
}

static gfn_t
pse36_gfn_delta(uint32_t gpte)
{
	int shift = 32 - PT32_DIR_PSE36_SHIFT - PAGESHIFT;

	return ((gpte & PT32_DIR_PSE36_MASK) << shift);
}

static void
__set_spte(uint64_t *sptep, uint64_t spte)
{
	*sptep = spte;
}

static int
mmu_topup_memory_cache(struct kvm_mmu_memory_cache *cache,
    struct kmem_cache *base_cache, int min)
{
	caddr_t obj;

	if (cache->nobjs >= min)
		return (0);
	while (cache->nobjs < ARRAY_SIZE(cache->objects)) {
		obj = kmem_cache_alloc(base_cache, KM_SLEEP);
		cache->objects[cache->nobjs].kma_object = obj;
		cache->objects[cache->nobjs++].kpm_object = NULL;
	}
	return (0);
}

static int
mmu_topup_memory_cache_page(struct kvm_mmu_memory_cache *cache, int min)
{
	page_t *page;

	if (cache->nobjs >= min)
		return (0);

	while (cache->nobjs < ARRAY_SIZE(cache->objects)) {
		page = alloc_page(KM_SLEEP,
		    &cache->objects[cache->nobjs].kma_object);
		if (!page)
			return (-ENOMEM);

		cache->objects[cache->nobjs++].kpm_object = page_address(page);
	}

	return (0);
}

static int
mmu_topup_memory_caches(struct kvm_vcpu *vcpu)
{
	int r = 0;

	r = mmu_topup_memory_cache(&vcpu->arch.mmu_pte_chain_cache,
	    pte_chain_cache, 4);

	if (r)
		goto out;

	r = mmu_topup_memory_cache(&vcpu->arch.mmu_rmap_desc_cache,
	    rmap_desc_cache, 4);

	if (r)
		goto out;

	r = mmu_topup_memory_cache_page(&vcpu->arch.mmu_page_cache, 8);

	if (r)
		goto out;

	r = mmu_topup_memory_cache(&vcpu->arch.mmu_page_header_cache,
	    mmu_page_header_cache, 4);

out:
	return (r);
}

static void *
mmu_memory_cache_alloc(struct kvm_mmu_memory_cache *mc, size_t size)
{
	if (mc->objects[--mc->nobjs].kpm_object)
		return (mc->objects[mc->nobjs].kpm_object);
	else
		return (mc->objects[mc->nobjs].kma_object);
}

static struct kvm_objects
mmu_memory_page_cache_alloc(struct kvm_mmu_memory_cache *mc, size_t size)
{
	return (mc->objects[--mc->nobjs]);
}

static struct kvm_pte_chain *
mmu_alloc_pte_chain(struct kvm_vcpu *vcpu)
{
	return (mmu_memory_cache_alloc(&vcpu->arch.mmu_pte_chain_cache,
	    sizeof (struct kvm_pte_chain)));
}

static void
mmu_free_pte_chain(struct kvm_pte_chain *pc)
{
	kmem_cache_free(pte_chain_cache, pc);
}

static struct kvm_rmap_desc *
mmu_alloc_rmap_desc(struct kvm_vcpu *vcpu)
{
	return (mmu_memory_cache_alloc(&vcpu->arch.mmu_rmap_desc_cache,
	    sizeof (struct kvm_rmap_desc)));
}

static void
mmu_free_rmap_desc(struct kvm_rmap_desc *rd)
{
	kmem_cache_free(rmap_desc_cache, rd);
}

/*
 * Return the pointer to the largepage write count for a given
 * gfn, handling slots that are not large page aligned.
 */
int *
slot_largepage_idx(gfn_t gfn, struct kvm_memory_slot *slot, int level)
{
	unsigned long idx;

	idx = (gfn / KVM_PAGES_PER_HPAGE(level)) -
	    (slot->base_gfn / KVM_PAGES_PER_HPAGE(level));
	return (&slot->lpage_info[level - 2][idx].write_count);
}

static void
account_shadowed(struct kvm *kvm, gfn_t gfn)
{
	struct kvm_memory_slot *slot;
	int *write_count;
	int i;

	gfn = unalias_gfn(kvm, gfn);

	slot = gfn_to_memslot_unaliased(kvm, gfn);
	for (i = PT_DIRECTORY_LEVEL;
		i < PT_PAGE_TABLE_LEVEL + KVM_NR_PAGE_SIZES; ++i) {
			write_count = slot_largepage_idx(gfn, slot, i);
			*write_count += 1;
	}
}

static void unaccount_shadowed(struct kvm *kvm, gfn_t gfn)
{
	struct kvm_memory_slot *slot;
	int *write_count;
	int i;

	gfn = unalias_gfn(kvm, gfn);
	for (i = PT_DIRECTORY_LEVEL;
		i < PT_PAGE_TABLE_LEVEL + KVM_NR_PAGE_SIZES; ++i) {
			slot = gfn_to_memslot_unaliased(kvm, gfn);
			write_count = slot_largepage_idx(gfn, slot, i);
			*write_count -= 1;
			if (*write_count < 0)
				cmn_err(CE_WARN,
				"unaccount_shadowed: *write_count = %d (< 0)\n",
				*write_count);
	}
}

static int
has_wrprotected_page(struct kvm *kvm, gfn_t gfn, int level)
{
	struct kvm_memory_slot *slot;
	int *largepage_idx;

	gfn = unalias_gfn(kvm, gfn);
	slot = gfn_to_memslot_unaliased(kvm, gfn);

	if (slot) {
		largepage_idx = slot_largepage_idx(gfn, slot, level);
		return (*largepage_idx);
	}

	return (1);
}

static int
host_mapping_level(struct kvm *kvm, gfn_t gfn)
{
	unsigned long page_size;
	int i, ret = 0;

	page_size = kvm_host_page_size(kvm, gfn);

	for (i = PT_PAGE_TABLE_LEVEL;
	    i < (PT_PAGE_TABLE_LEVEL + KVM_NR_PAGE_SIZES); ++i) {
		if (page_size >= KVM_HPAGE_SIZE(i))
			ret = i;
		else
			break;
	}

	return (ret);
}

static int
mapping_level(struct kvm_vcpu *vcpu, gfn_t large_gfn)
{
	struct kvm_memory_slot *slot;
	int host_level, level, max_level;

	slot = gfn_to_memslot(vcpu->kvm, large_gfn);
	if (slot && slot->dirty_bitmap)
		return (PT_PAGE_TABLE_LEVEL);

	host_level = host_mapping_level(vcpu->kvm, large_gfn);

	if (host_level == PT_PAGE_TABLE_LEVEL)
		return (host_level);

	max_level = kvm_x86_ops->get_lpage_level() < host_level ?
		kvm_x86_ops->get_lpage_level() : host_level;

	for (level = PT_DIRECTORY_LEVEL; level <= max_level; ++level)
		if (has_wrprotected_page(vcpu->kvm, large_gfn, level))
			break;

	return (level - 1);
}

/*
 * Take gfn and return the reverse mapping to it.
 * Note: gfn must be unaliased before this function get called
 */
static unsigned long *
gfn_to_rmap(struct kvm *kvm, gfn_t gfn, int level)
{
	struct kvm_memory_slot *slot;
	unsigned long idx;

	slot = gfn_to_memslot(kvm, gfn);
	if (level == PT_PAGE_TABLE_LEVEL)
	    return (&slot->rmap[gfn - slot->base_gfn]);

	idx = (gfn / KVM_PAGES_PER_HPAGE(level)) -
	    (slot->base_gfn / KVM_PAGES_PER_HPAGE(level));

	return (&slot->lpage_info[level - 2][idx].rmap_pde);
}

/*
 * Reverse mapping data structures:
 *
 * If rmapp bit zero is zero, then rmapp point to the shadw page table entry
 * that points to page_address(page).
 *
 * If rmapp bit zero is one, (then rmap & ~1) points to a struct kvm_rmap_desc
 * containing more mappings.
 *
 * Returns the number of rmap entries before the spte was added or zero if
 * the spte was not added.
 *
 */
static int
rmap_add(struct kvm_vcpu *vcpu, uint64_t *spte, gfn_t gfn)
{
	struct kvm_mmu_page *sp;
	struct kvm_rmap_desc *desc;
	unsigned long *rmapp;
	int i, count = 0;

	if (!is_rmap_spte(*spte))
		return (count);

	gfn = unalias_gfn(vcpu->kvm, gfn);
	sp = page_header(vcpu->kvm, kvm_va2pa((caddr_t)spte));
	sp->gfns[spte - sp->spt] = gfn;
	rmapp = gfn_to_rmap(vcpu->kvm, gfn, sp->role.level);
	if (!*rmapp) {
		*rmapp = (unsigned long)spte;
	} else if (!(*rmapp & 1)) {
		desc = mmu_alloc_rmap_desc(vcpu);
		desc->sptes[0] = (uint64_t *)*rmapp;
		desc->sptes[1] = spte;
		*rmapp = (unsigned long)desc | 1;
	} else {
		desc = (struct kvm_rmap_desc *)(*rmapp & ~1ul);
		while (desc->sptes[RMAP_EXT-1] && desc->more) {
			desc = desc->more;
			count += RMAP_EXT;
		}
		if (desc->sptes[RMAP_EXT-1]) {
			desc->more = mmu_alloc_rmap_desc(vcpu);
			desc = desc->more;
		}
		for (i = 0; desc->sptes[i]; i++)
			continue;
		desc->sptes[i] = spte;
	}
	return (count);
}

static void
rmap_desc_remove_entry(unsigned long *rmapp, struct kvm_rmap_desc *desc,
    int i, struct kvm_rmap_desc *prev_desc)
{
	int j;

	for (j = RMAP_EXT - 1; !desc->sptes[j] && j > i; --j)
		continue;

	desc->sptes[i] = desc->sptes[j];
	desc->sptes[j] = NULL;

	if (j != 0)
		return;
	if (!prev_desc && !desc->more) {
		*rmapp = (unsigned long)desc->sptes[0];
	} else {
		if (prev_desc)
			prev_desc->more = desc->more;
		else
			*rmapp = (unsigned long)desc->more | 1;
	}

	mmu_free_rmap_desc(desc);
}

static void
rmap_remove(struct kvm *kvm, uint64_t *spte)
{
	struct kvm_rmap_desc *desc;
	struct kvm_rmap_desc *prev_desc;
	struct kvm_mmu_page *sp;
	pfn_t pfn;
	unsigned long *rmapp;
	int i;

	if (!is_rmap_spte(*spte))
		return;
	sp = page_header(kvm, kvm_va2pa((caddr_t)spte));
	pfn = spte_to_pfn(*spte);
	if (*spte & shadow_accessed_mask)
		kvm_set_pfn_accessed(kvm, pfn);
	if (is_writable_pte(*spte))
		kvm_set_pfn_dirty(pfn);
	rmapp = gfn_to_rmap(kvm, sp->gfns[spte - sp->spt], sp->role.level);
	if (!*rmapp) {
		panic("rmap_remove: %p %lx 0->BUG\n", spte, *spte);
	} else if (!(*rmapp & 1)) {
		if ((uint64_t *)*rmapp != spte) {
			panic("rmap_remove:  %p %lx 1->BUG\n", spte, *spte);
		}
		*rmapp = 0;
	} else {
		desc = (struct kvm_rmap_desc *)(*rmapp & ~1ul);
		prev_desc = NULL;
		while (desc) {
			for (i = 0; i < RMAP_EXT && desc->sptes[i]; i++) {
				if (desc->sptes[i] == spte) {
					rmap_desc_remove_entry(rmapp,
					    desc, i, prev_desc);
					return;
				}
			}

			prev_desc = desc;
			desc = desc->more;
		}
		panic("rmap_remove: %p %lx many->many\n", spte, *spte);
	}
}

static uint64_t *
rmap_next(struct kvm *kvm, unsigned long *rmapp, uint64_t *spte)
{
	struct kvm_rmap_desc *desc;
	struct kvm_rmap_desc *prev_desc;
	uint64_t *prev_spte;
	int i;

	if (!*rmapp)
		return (NULL);
	else if (!(*rmapp & 1)) {
		if (!spte)
			return ((uint64_t *)*rmapp);
		return (NULL);
	}

	desc = (struct kvm_rmap_desc *)(*rmapp & ~1ul);
	prev_desc = NULL;
	prev_spte = NULL;
	while (desc) {
		for (i = 0; i < RMAP_EXT && desc->sptes[i]; ++i) {
			if (prev_spte == spte)
				return (desc->sptes[i]);
			prev_spte = desc->sptes[i];
		}
		desc = desc->more;
	}

	return (NULL);
}

static int
rmap_write_protect(struct kvm *kvm, uint64_t gfn)
{
	unsigned long *rmapp;
	uint64_t *spte;
	int i, write_protected = 0;

	gfn = unalias_gfn(kvm, gfn);
	rmapp = gfn_to_rmap(kvm, gfn, PT_PAGE_TABLE_LEVEL);

	spte = rmap_next(kvm, rmapp, NULL);
	while (spte) {
		ASSERT(spte);
		ASSERT(*spte & PT_PRESENT_MASK);
		if (is_writable_pte(*spte)) {
			__set_spte(spte, *spte & ~PT_WRITABLE_MASK);
			write_protected = 1;
		}
		spte = rmap_next(kvm, rmapp, spte);
	}
	if (write_protected) {
		pfn_t pfn;

		spte = rmap_next(kvm, rmapp, NULL);
		pfn = spte_to_pfn(*spte);
		kvm_set_pfn_dirty(pfn);
	}

	/* check for huge page mappings */
	for (i = PT_DIRECTORY_LEVEL;
	    i < PT_PAGE_TABLE_LEVEL + KVM_NR_PAGE_SIZES; i++) {
		rmapp = gfn_to_rmap(kvm, gfn, i);
		spte = rmap_next(kvm, rmapp, NULL);
		while (spte) {
			ASSERT(spte);
			ASSERT(*spte & PT_PRESENT_MASK);
			ASSERT((*spte & (PT_PAGE_SIZE_MASK|PT_PRESENT_MASK)) ==
			    (PT_PAGE_SIZE_MASK|PT_PRESENT_MASK));

			if (is_writable_pte(*spte)) {
				rmap_remove(kvm, spte);
				KVM_KSTAT_DEC(kvm, kvmks_lpages);
				__set_spte(spte, shadow_trap_nonpresent_pte);
				spte = NULL;
				write_protected = 1;
			}
			spte = rmap_next(kvm, rmapp, spte);
		}
	}

	return (write_protected);
}

static void
kvm_mmu_free_page(struct kvm *kvm, struct kvm_mmu_page *sp)
{
	kmem_free(sp->sptkma, PAGESIZE);
	kmem_free(sp->gfnskma, PAGESIZE);

	mutex_enter(&kvm->kvm_avllock);
	avl_remove(&kvm->kvm_avlmp, sp);
	mutex_exit(&kvm->kvm_avllock);
	list_remove(&kvm->arch.active_mmu_pages, sp);
	kmem_cache_free(mmu_page_header_cache, sp);
	++kvm->arch.n_free_mmu_pages;
}

static unsigned
kvm_page_table_hashfn(gfn_t gfn)
{
	return (gfn & ((1 << KVM_MMU_HASH_SHIFT) - 1));
}

static void
bitmap_zero(unsigned long *dst, int nbits)
{
	int len = BITS_TO_LONGS(nbits) * sizeof (unsigned long);
	memset(dst, 0, len);
}

static struct kvm_mmu_page *
kvm_mmu_alloc_page(struct kvm_vcpu *vcpu, uint64_t *parent_pte)
{
	struct kvm_mmu_page *sp;
	struct kvm_objects kobj;

	sp = mmu_memory_cache_alloc(&vcpu->arch.mmu_page_header_cache,
	    sizeof (*sp));
	kobj = mmu_memory_page_cache_alloc(&vcpu->arch.mmu_page_cache,
	    PAGESIZE);
	sp->spt = kobj.kpm_object;
	sp->sptkma = kobj.kma_object;
	kobj = mmu_memory_page_cache_alloc(&vcpu->arch.mmu_page_cache,
	    PAGESIZE);
	sp->gfns = kobj.kpm_object;
	sp->gfnskma = kobj.kma_object;
	sp->kmp_avlspt = (uintptr_t)virt_to_page((caddr_t)sp->spt);
	sp->vcpu = vcpu;

	mutex_enter(&vcpu->kvm->kvm_avllock);
	avl_add(&vcpu->kvm->kvm_avlmp, sp);
	mutex_exit(&vcpu->kvm->kvm_avllock);

	list_insert_head(&vcpu->kvm->arch.active_mmu_pages, sp);

	bitmap_zero(sp->slot_bitmap, KVM_MEMORY_SLOTS + KVM_PRIVATE_MEM_SLOTS);
	sp->multimapped = 0;
	sp->parent_pte = parent_pte;
	--vcpu->kvm->arch.n_free_mmu_pages;
	return (sp);
}

static void
mmu_page_remove_parent_pte(struct kvm_mmu_page *sp, uint64_t *parent_pte)
{
	struct kvm_pte_chain *pte_chain;
	struct list_t *node;
	int i;

	if (!sp->multimapped) {
		sp->parent_pte = NULL;
		return;
	}

	for (pte_chain = list_head(&sp->parent_ptes); pte_chain != NULL;
	    pte_chain = list_next(&sp->parent_ptes, pte_chain)) {
		for (i = 0; i < NR_PTE_CHAIN_ENTRIES; ++i) {
			if (!pte_chain->parent_ptes[i])
				break;
			if (pte_chain->parent_ptes[i] != parent_pte)
				continue;
			while (i + 1 < NR_PTE_CHAIN_ENTRIES &&
			    pte_chain->parent_ptes[i + 1]) {
				pte_chain->parent_ptes[i] =
				    pte_chain->parent_ptes[i + 1];
				i++;
			}
			pte_chain->parent_ptes[i] = NULL;
			if (i == 0) {
				list_remove(&sp->parent_ptes, pte_chain);
				mmu_free_pte_chain(pte_chain);
				if (list_is_empty(&sp->parent_ptes)) {
					sp->multimapped = 0;
					sp->parent_pte = NULL;
				}
			}
			return;
		}
	}
	panic("We shouldn't make it here\n");
}

static void
mmu_page_add_parent_pte(struct kvm_vcpu *vcpu,
    struct kvm_mmu_page *sp, uint64_t *parent_pte)
{
	struct kvm_pte_chain *pte_chain;
	struct hlist_node *node;
	int i;

	if (!parent_pte)
		return;
	if (!sp->multimapped) {
		uint64_t *old = sp->parent_pte;

		if (!old) {
			sp->parent_pte = parent_pte;
			return;
		}
		sp->multimapped = 1;
		pte_chain = mmu_alloc_pte_chain(vcpu);
		list_create(&sp->parent_ptes, sizeof (struct kvm_pte_chain),
			    offsetof(struct kvm_pte_chain, link));
		list_insert_head(&sp->parent_ptes, pte_chain);
		pte_chain->parent_ptes[0] = old;
	}

	for (pte_chain = list_head(&sp->parent_ptes); pte_chain != NULL;
	    pte_chain = list_next(&sp->parent_ptes, pte_chain)) {
		if (pte_chain->parent_ptes[NR_PTE_CHAIN_ENTRIES-1])
			continue;
		for (i = 0; i < NR_PTE_CHAIN_ENTRIES; ++i) {
			if (!pte_chain->parent_ptes[i]) {
				pte_chain->parent_ptes[i] = parent_pte;
				return;
			}
		}
	}

	pte_chain = mmu_alloc_pte_chain(vcpu);
	list_insert_head(&sp->parent_ptes, pte_chain);
	pte_chain->parent_ptes[0] = parent_pte;
}

static void
mmu_parent_walk(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp,
    mmu_parent_walk_fn fn)
{
	struct kvm_pte_chain *pte_chain;
	struct hlist_node *node;
	struct kvm_mmu_page *parent_sp;
	int i;

	if (!sp->multimapped && sp->parent_pte) {
		parent_sp = page_header(vcpu->kvm,
		    kvm_va2pa((caddr_t)sp->parent_pte));

		fn(vcpu, parent_sp);
		mmu_parent_walk(vcpu, parent_sp, fn);
		return;
	}

	for (pte_chain = list_head(&sp->parent_ptes); pte_chain != NULL;
	    pte_chain = list_next(&sp->parent_ptes, pte_chain)) {
		for (i = 0; i < NR_PTE_CHAIN_ENTRIES; ++i) {
			if (!pte_chain->parent_ptes[i])
				break;

			parent_sp = page_header(vcpu->kvm, kvm_va2pa(
			    (caddr_t)pte_chain->parent_ptes[i]));
			fn(vcpu, parent_sp);
			mmu_parent_walk(vcpu, parent_sp, fn);
		}
	}
}

static void
kvm_mmu_update_unsync_bitmap(uint64_t *spte, struct kvm *kvm)
{
	unsigned int index;
	struct kvm_mmu_page *sp = page_header(kvm, kvm_va2pa((caddr_t)spte));

	index = spte - sp->spt;
	if (!__test_and_set_bit(index, sp->unsync_child_bitmap))
		sp->unsync_children++;
}

static void
kvm_mmu_update_parents_unsync(struct kvm_mmu_page *sp, struct kvm *kvm)
{
	struct kvm_pte_chain *pte_chain;
	int i;

	if (!sp->parent_pte)
		return;

	if (!sp->multimapped) {
		kvm_mmu_update_unsync_bitmap(sp->parent_pte, kvm);
		return;
	}

	for (pte_chain = list_head(&sp->parent_ptes); pte_chain != NULL;
	    pte_chain = list_next(&sp->parent_ptes, pte_chain)) {
		for (i = 0; i < NR_PTE_CHAIN_ENTRIES; ++i) {
			if (!pte_chain->parent_ptes[i])
				break;
			kvm_mmu_update_unsync_bitmap(pte_chain->parent_ptes[i],
			    kvm);
		}
	}
}

static int
unsync_walk_fn(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp)
{
	kvm_mmu_update_parents_unsync(sp, vcpu->kvm);
	return (1);
}

void
kvm_mmu_mark_parents_unsync(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp)
{
	mmu_parent_walk(vcpu, sp, unsync_walk_fn);
	kvm_mmu_update_parents_unsync(sp, vcpu->kvm);
}

static void
nonpaging_prefetch_page(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp)
{
	int i;

	for (i = 0; i < PT64_ENT_PER_PAGE; ++i)
		sp->spt[i] = shadow_trap_nonpresent_pte;
}

static int
nonpaging_sync_page(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp)
{
	return (1);
}

static void
nonpaging_invlpg(struct kvm_vcpu *vcpu, gva_t gva)
{}

#define	KVM_PAGE_ARRAY_NR 16

typedef struct kvm_mmu_pages {
	struct mmu_page_and_offset {
		struct kvm_mmu_page *sp;
		unsigned int idx;
	} page[KVM_PAGE_ARRAY_NR];
	unsigned int nr;
} kvm_mmu_pages_t;

#define	for_each_unsync_children(bitmap, idx)		\
	for (idx = bt_getlowbit(bitmap, 0, 511);	\
	    (idx != -1) && (idx < 512);			\
	    idx = bt_getlowbit(bitmap, idx+1, 511))

static int
mmu_pages_add(struct kvm_mmu_pages *pvec, struct kvm_mmu_page *sp, int idx)
{
	int i;

	if (sp->unsync) {
		for (i = 0; i < pvec->nr; i++) {
			if (pvec->page[i].sp == sp)
				return (0);
		}
	}

	pvec->page[pvec->nr].sp = sp;
	pvec->page[pvec->nr].idx = idx;
	pvec->nr++;

	return (pvec->nr == KVM_PAGE_ARRAY_NR);
}

static int
__mmu_unsync_walk(struct kvm_mmu_page *sp, struct kvm_mmu_pages *pvec,
    struct kvm *kvm)
{
	int i, ret, nr_unsync_leaf = 0;

	for_each_unsync_children(sp->unsync_child_bitmap, i) {
		uint64_t ent = sp->spt[i];

		if (is_shadow_present_pte(ent) && !is_large_pte(ent)) {
			struct kvm_mmu_page *child;
			child = page_header(kvm, ent & PT64_BASE_ADDR_MASK);

			if (child->unsync_children) {
				if (mmu_pages_add(pvec, child, i))
					return (-ENOSPC);
				ret = __mmu_unsync_walk(child, pvec, kvm);
				if (!ret) {
					__clear_bit(i, sp->unsync_child_bitmap);
				} else if (ret > 0)
					nr_unsync_leaf += ret;
				else
					return (ret);
			}

			if (child->unsync) {
				nr_unsync_leaf++;
				if (mmu_pages_add(pvec, child, i))
					return (-ENOSPC);
			}
		}
	}

	if (bt_getlowbit(sp->unsync_child_bitmap, 0, 511) == -1)
		sp->unsync_children = 0;

	return (nr_unsync_leaf);
}

static int
mmu_unsync_walk(struct kvm_mmu_page *sp,
    struct kvm_mmu_pages *pvec, struct kvm *kvm)
{
	if (!sp->unsync_children)
		return (0);

	mmu_pages_add(pvec, sp, 0);
	return (__mmu_unsync_walk(sp, pvec, kvm));
}

static struct kvm_mmu_page *
kvm_mmu_lookup_page(struct kvm *kvm, gfn_t gfn)
{
	unsigned index;
	list_t *bucket;
	struct kvm_mmu_page *sp;

	index = kvm_page_table_hashfn(gfn);
	bucket = &kvm->arch.mmu_page_hash[index];
	for (sp = list_head(bucket); sp; sp = list_next(bucket, sp)) {
		if (sp->gfn == gfn && !sp->role.direct &&
		    !sp->role.invalid) {
			return (sp);
		}
	}

	return (NULL);
}


static void
kvm_unlink_unsync_page(struct kvm *kvm, struct kvm_mmu_page *sp)
{
	sp->unsync = 0;
	KVM_KSTAT_DEC(kvm, kvmks_mmu_unsync_page);
}


static int kvm_mmu_zap_page(struct kvm *, struct kvm_mmu_page *);

static int
kvm_sync_page(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp)
{
	if (sp->role.glevels != vcpu->arch.mmu.root_level) {
		kvm_mmu_zap_page(vcpu->kvm, sp);
		return (1);
	}

	KVM_TRACE1(mmu__sync__page, struct kvm_mmu_page *, sp);

	if (rmap_write_protect(vcpu->kvm, sp->gfn))
		kvm_flush_remote_tlbs(vcpu->kvm);
	kvm_unlink_unsync_page(vcpu->kvm, sp);
	if (vcpu->arch.mmu.sync_page(vcpu, sp)) {
		kvm_mmu_zap_page(vcpu->kvm, sp);
		return (1);
	}

	kvm_mmu_flush_tlb(vcpu);
	return (0);
}

typedef struct mmu_page_path {
	struct kvm_mmu_page *parent[PT64_ROOT_LEVEL-1];
	unsigned int idx[PT64_ROOT_LEVEL-1];
} mmu_page_path_t;

#define	for_each_sp(pvec, sp, parents, i)				\
		for (i = mmu_pages_next(&pvec, &parents, -1),		\
			sp = pvec.page[i].sp;				\
			/*CSTYLED*/					\
			i < pvec.nr && ({ sp = pvec.page[i].sp; 1; });	\
			i = mmu_pages_next(&pvec, &parents, i))

static int
mmu_pages_next(struct kvm_mmu_pages *pvec, struct mmu_page_path *parents, int i)
{
	int n;

	for (n = i + 1; n < pvec->nr; n++) {
		struct kvm_mmu_page *sp = pvec->page[n].sp;

		if (sp->role.level == PT_PAGE_TABLE_LEVEL) {
			parents->idx[0] = pvec->page[n].idx;
			return (n);
		}

		parents->parent[sp->role.level-2] = sp;
		parents->idx[sp->role.level-1] = pvec->page[n].idx;
	}

	return (n);
}

static void
mmu_pages_clear_parents(struct mmu_page_path *parents)
{
	struct kvm_mmu_page *sp;
	unsigned int level = 0;

	do {
		unsigned int idx = parents->idx[level];

		sp = parents->parent[level];
		if (!sp)
			return;

		--sp->unsync_children;
		if ((int)sp->unsync_children < 0)
			cmn_err(CE_WARN,
			    "mmu_pages_clear_parents: unsync_children (%d)\n",
			    (int)sp->unsync_children);
		__clear_bit(idx, sp->unsync_child_bitmap);
		level++;
	} while (level < PT64_ROOT_LEVEL-1 && !sp->unsync_children);
}

static void
kvm_mmu_pages_init(struct kvm_mmu_page *parent, struct mmu_page_path *parents,
    struct kvm_mmu_pages *pvec)
{
	parents->parent[parent->role.level-1] = NULL;
	pvec->nr = 0;
}

static void
mmu_sync_children(struct kvm_vcpu *vcpu, struct kvm_mmu_page *parent)
{
	int i;
	struct kvm_mmu_page *sp;
	struct mmu_page_path parents;
	struct kvm_mmu_pages pages;

	kvm_mmu_pages_init(parent, &parents, &pages);
	while (mmu_unsync_walk(parent, &pages, vcpu->kvm)) {
		int protected = 0;

		for_each_sp(pages, sp, parents, i)
			protected |= rmap_write_protect(vcpu->kvm, sp->gfn);

		if (protected)
			kvm_flush_remote_tlbs(vcpu->kvm);

		for_each_sp(pages, sp, parents, i) {
			kvm_sync_page(vcpu, sp);
			mmu_pages_clear_parents(&parents);
		}
		mutex_enter(&vcpu->kvm->mmu_lock);
		kvm_mmu_pages_init(parent, &parents, &pages);
		mutex_exit(&vcpu->kvm->mmu_lock);
	}
}

struct kvm_mmu_page *
kvm_mmu_get_page(struct kvm_vcpu *vcpu, gfn_t gfn, gva_t gaddr, unsigned level,
    int direct, unsigned access, uint64_t *parent_pte)
{
	union kvm_mmu_page_role role;
	unsigned index;
	unsigned quadrant;
	list_t *bucket;
	struct kvm_mmu_page *sp, *nsp = NULL;
	struct hlist_node *node, *tmp;

	role = vcpu->arch.mmu.base_role;
	role.level = level;
	role.direct = direct;
	role.access = access;

	if (vcpu->arch.mmu.root_level <= PT32_ROOT_LEVEL) {
		quadrant = gaddr >> (PAGESHIFT + (PT64_PT_BITS * level));
		quadrant &= (1 << ((PT32_PT_BITS - PT64_PT_BITS) * level)) - 1;
		role.quadrant = quadrant;
	}

	index = kvm_page_table_hashfn(gfn);
	bucket = &vcpu->kvm->arch.mmu_page_hash[index];

	for (sp = list_head(bucket); sp != NULL; sp = nsp) {
		nsp = list_next(bucket, sp);
		if (sp->gfn == gfn) {
			if (sp->unsync)
				if (kvm_sync_page(vcpu, sp))
					continue;

			if (sp->role.word != role.word)
				continue;

			mmu_page_add_parent_pte(vcpu, sp, parent_pte);
			if (sp->unsync_children) {
				set_bit(KVM_REQ_MMU_SYNC, &vcpu->requests);
				kvm_mmu_mark_parents_unsync(vcpu, sp);
			}
			return (sp);
		}
	}

	KVM_KSTAT_INC(vcpu->kvm, kvmks_mmu_cache_miss);
	sp = kvm_mmu_alloc_page(vcpu, parent_pte);

	if (!sp)
		return (sp);

	sp->gfn = gfn;
	sp->role = role;
	list_insert_head(bucket, sp);
	if (!direct) {
		if (rmap_write_protect(vcpu->kvm, gfn))
			kvm_flush_remote_tlbs(vcpu->kvm);
		account_shadowed(vcpu->kvm, gfn);
	}

	if (shadow_trap_nonpresent_pte != shadow_notrap_nonpresent_pte)
		vcpu->arch.mmu.prefetch_page(vcpu, sp);
	else
		nonpaging_prefetch_page(vcpu, sp);

	KVM_TRACE1(mmu__get__page, struct kvm_mmu_page *, sp);

	return (sp);
}

static void
shadow_walk_init(struct kvm_shadow_walk_iterator *iterator,
    struct kvm_vcpu *vcpu, uint64_t addr)
{
	iterator->addr = addr;
	iterator->shadow_addr = vcpu->arch.mmu.root_hpa;
	iterator->level = vcpu->arch.mmu.shadow_root_level;
	if (iterator->level == PT32E_ROOT_LEVEL) {
		iterator->shadow_addr =
		    vcpu->arch.mmu.pae_root[(addr >> 30) & 3];
		iterator->shadow_addr &= PT64_BASE_ADDR_MASK;
		--iterator->level;
		if (!iterator->shadow_addr)
			iterator->level = 0;
	}
}

static int
shadow_walk_okay(struct kvm_shadow_walk_iterator *iterator,
    struct kvm_vcpu *vcpu)
{
	if (iterator->level < PT_PAGE_TABLE_LEVEL)
		return (0);

	if (iterator->level == PT_PAGE_TABLE_LEVEL) {
		if (is_large_pte(*iterator->sptep))
			return (0);
	}

	iterator->index = SHADOW_PT_INDEX(iterator->addr, iterator->level);
	iterator->sptep =
	    (uint64_t *)page_address(pfn_to_page((iterator->shadow_addr) >>
	    PAGESHIFT)) + iterator->index;

	return (1);
}

static void
shadow_walk_next(struct kvm_shadow_walk_iterator *iterator)
{
	iterator->shadow_addr = *iterator->sptep & PT64_BASE_ADDR_MASK;
	--iterator->level;
}

static void
kvm_mmu_page_unlink_children(struct kvm *kvm, struct kvm_mmu_page *sp)
{
	unsigned i;
	uint64_t *pt;
	uint64_t ent;

	pt = sp->spt;

	for (i = 0; i < PT64_ENT_PER_PAGE; ++i) {
		ent = pt[i];

		if (is_shadow_present_pte(ent)) {
			if (!is_last_spte(ent, sp->role.level)) {
				ent &= PT64_BASE_ADDR_MASK;
				mmu_page_remove_parent_pte(page_header(kvm,
				    ent), &pt[i]);
			} else {
				rmap_remove(kvm, &pt[i]);
			}
		}
		pt[i] = shadow_trap_nonpresent_pte;
	}
}

static void
kvm_mmu_put_page(struct kvm_mmu_page *sp, uint64_t *parent_pte)
{
	mmu_page_remove_parent_pte(sp, parent_pte);
}

static void
kvm_mmu_reset_last_pte_updated(struct kvm *kvm)
{
	int i;
	struct kvm_vcpu *vcpu;

	kvm_for_each_vcpu(i, vcpu, kvm)
		vcpu->arch.last_pte_updated = NULL;
}

static void
kvm_mmu_unlink_parents(struct kvm *kvm, struct kvm_mmu_page *sp)
{
	uint64_t *parent_pte;

	while (sp->multimapped || sp->parent_pte) {
		if (!sp->multimapped)
			parent_pte = sp->parent_pte;
		else {
			struct kvm_pte_chain *chain;

			chain = list_head(&sp->parent_ptes);

			parent_pte = chain->parent_ptes[0];
		}

		kvm_mmu_put_page(sp, parent_pte);
		__set_spte(parent_pte, shadow_trap_nonpresent_pte);
	}
}

static int
mmu_zap_unsync_children(struct kvm *kvm, struct kvm_mmu_page *parent)
{
	int i, zapped = 0;
	struct mmu_page_path parents;
	struct kvm_mmu_pages pages;

	if (parent->role.level == PT_PAGE_TABLE_LEVEL)
		return (0);

	kvm_mmu_pages_init(parent, &parents, &pages);
	while (mmu_unsync_walk(parent, &pages, kvm)) {
		struct kvm_mmu_page *sp;

		for_each_sp(pages, sp, parents, i) {
			kvm_mmu_zap_page(kvm, sp);
			mmu_pages_clear_parents(&parents);
			zapped++;
		}
		kvm_mmu_pages_init(parent, &parents, &pages);
	}

	return (zapped);
}

static int
kvm_mmu_zap_page(struct kvm *kvm, struct kvm_mmu_page *sp)
{
	int ret;

	ret = mmu_zap_unsync_children(kvm, sp);
	kvm_mmu_page_unlink_children(kvm, sp);
	kvm_mmu_unlink_parents(kvm, sp);
	kvm_flush_remote_tlbs(kvm);

	if (!sp->role.invalid && !sp->role.direct)
		unaccount_shadowed(kvm, sp->gfn);

	if (sp->unsync)
		kvm_unlink_unsync_page(kvm, sp);

	if (!sp->root_count) {
		sp->hash_link.list_prev->list_next = sp->hash_link.list_next;
		sp->hash_link.list_next->list_prev = sp->hash_link.list_prev;
		sp->hash_link.list_prev = 0;
		sp->hash_link.list_next = 0;
		kvm_mmu_free_page(kvm, sp);
	} else {
		sp->role.invalid = 1;
		list_remove(&kvm->arch.active_mmu_pages, sp);
		list_insert_head(&kvm->arch.active_mmu_pages, sp);
		kvm_reload_remote_mmus(kvm);
	}
	kvm_mmu_reset_last_pte_updated(kvm);

	return (ret);
}

/*
 * Changing the number of mmu pages allocated to the vm
 * Note: if kvm_nr_mmu_pages is too small, you will get dead lock
 */
void
kvm_mmu_change_mmu_pages(struct kvm *kvm, unsigned int kvm_nr_mmu_pages)
{
	int used_pages;

	used_pages = kvm->arch.n_alloc_mmu_pages - kvm->arch.n_free_mmu_pages;
	used_pages = MAX(0, used_pages);

	/* for the time being, assume that address space will only grow */
	/* larger.  The following code will be added later. */

	/*
	 * If we set the number of mmu pages to be smaller be than the
	 * number of actived pages , we must to free some mmu pages before we
	 * change the value
	 */

	if (used_pages > kvm_nr_mmu_pages) {
		while (used_pages > kvm_nr_mmu_pages &&
			!list_is_empty(&kvm->arch.active_mmu_pages)) {
			struct kvm_mmu_page *page;

			page = (struct kvm_mmu_page *)
			    list_tail(&kvm->arch.active_mmu_pages);

			/* page removed by kvm_mmu_zap_page */
			used_pages -= kvm_mmu_zap_page(kvm, page);
			used_pages--;
		}
		kvm_nr_mmu_pages = used_pages;
		kvm->arch.n_free_mmu_pages = 0;
	} else {
		kvm->arch.n_free_mmu_pages +=
		    kvm_nr_mmu_pages - kvm->arch.n_alloc_mmu_pages;
	}

	kvm->arch.n_alloc_mmu_pages = kvm_nr_mmu_pages;
}

static int
kvm_mmu_unprotect_page(struct kvm *kvm, gfn_t gfn)
{
	unsigned index;
	list_t *bucket;
	struct kvm_mmu_page *sp, *nsp = NULL;
	int r;

	r = 0;
	index = kvm_page_table_hashfn(gfn);
	bucket = &kvm->arch.mmu_page_hash[index];

	for (sp = list_head(bucket); sp; sp = nsp) {
		/* preserve link to next node in case we free this one */
		nsp = list_next(bucket, sp);

		if (sp->gfn == gfn && !sp->role.direct) {
			r = 1;
			if (kvm_mmu_zap_page(kvm, sp))
				nsp = list_head(bucket);
		}
	}
	return (r);
}

static void
page_header_update_slot(struct kvm *kvm, void *pte, gfn_t gfn)
{
	int slot = memslot_id(kvm, gfn);
	struct kvm_mmu_page *sp = page_header(kvm, kvm_va2pa(pte));

	__set_bit(slot, sp->slot_bitmap);
}

static void
mmu_convert_notrap(struct kvm_mmu_page *sp)
{
	int i;
	uint64_t *pt = sp->spt;

	if (shadow_trap_nonpresent_pte == shadow_notrap_nonpresent_pte)
		return;

	for (i = 0; i < PT64_ENT_PER_PAGE; ++i) {
		if (pt[i] == shadow_notrap_nonpresent_pte)
			__set_spte(&pt[i], shadow_trap_nonpresent_pte);
	}
}

static int
get_mtrr_type(struct mtrr_state_type *mtrr_state, uint64_t start, uint64_t end)
{
	int i;
	uint64_t base, mask;
	uint8_t prev_match, curr_match;
	int num_var_ranges = KVM_NR_VAR_MTRR;

	if (!mtrr_state->enabled)
		return (0xFF);

	/* Make end inclusive end, instead of exclusive */
	end--;

	/* Look in fixed ranges. Just return the type as per start */
	if (mtrr_state->have_fixed && (start < 0x100000)) {
		int idx;

		if (start < 0x80000) {
			idx = 0;
			idx += (start >> 16);
			return (mtrr_state->fixed_ranges[idx]);
		} else if (start < 0xC0000) {
			idx = 1 * 8;
			idx += ((start - 0x80000) >> 14);
			return (mtrr_state->fixed_ranges[idx]);
		} else if (start < 0x1000000) {
			idx = 3 * 8;
			idx += ((start - 0xC0000) >> 12);
			return (mtrr_state->fixed_ranges[idx]);
		}
	}

	/*
	 * Look in variable ranges
	 * Look of multiple ranges matching this address and pick type
	 * as per MTRR precedence
	 */
	if (!(mtrr_state->enabled & 2))
		return (mtrr_state->def_type);

	prev_match = 0xFF;
	for (i = 0; i < num_var_ranges; ++i) {
		unsigned short start_state, end_state;

		if (!(mtrr_state->var_ranges[i].mask_lo & (1 << 11)))
			continue;

		base = (((uint64_t)mtrr_state->var_ranges[i].base_hi) << 32) +
		    (mtrr_state->var_ranges[i].base_lo & PAGEMASK);
		mask = (((uint64_t)mtrr_state->var_ranges[i].mask_hi) << 32) +
		    (mtrr_state->var_ranges[i].mask_lo & PAGEMASK);

		start_state = ((start & mask) == (base & mask));
		end_state = ((end & mask) == (base & mask));
		if (start_state != end_state)
			return (0xFE);

		if ((start & mask) != (base & mask))
			continue;

		curr_match = mtrr_state->var_ranges[i].base_lo & 0xff;
		if (prev_match == 0xFF) {
			prev_match = curr_match;
			continue;
		}

		if (prev_match == MTRR_TYPE_UNCACHABLE ||
		    curr_match == MTRR_TYPE_UNCACHABLE)
			return (MTRR_TYPE_UNCACHABLE);

		if ((prev_match == MTRR_TYPE_WRBACK &&
		    curr_match == MTRR_TYPE_WRTHROUGH) ||
		    (prev_match == MTRR_TYPE_WRTHROUGH &&
		    curr_match == MTRR_TYPE_WRBACK)) {
			prev_match = MTRR_TYPE_WRTHROUGH;
			curr_match = MTRR_TYPE_WRTHROUGH;
		}

		if (prev_match != curr_match)
			return (MTRR_TYPE_UNCACHABLE);
	}

	if (prev_match != 0xFF)
		return (prev_match);

	return (mtrr_state->def_type);
}

uint8_t
kvm_get_guest_memory_type(struct kvm_vcpu *vcpu, gfn_t gfn)
{
	uint8_t mtrr;

	mtrr = get_mtrr_type(&vcpu->arch.mtrr_state,
	    gfn << PAGESHIFT, (gfn << PAGESHIFT) + PAGESIZE);
	if (mtrr == 0xfe || mtrr == 0xff)
		mtrr = MTRR_TYPE_WRBACK;
	return (mtrr);
}

static int
kvm_unsync_page(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp)
{
	unsigned index;
	list_t *bucket;
	struct kvm_mmu_page *s;

	index = kvm_page_table_hashfn(sp->gfn);
	bucket = &vcpu->kvm->arch.mmu_page_hash[index];
	/* don't unsync if pagetable is shadowed with multiple roles */
	/* XXX - need protection here(?) */
	for (s = list_head(bucket); s; s = list_next(bucket, s)) {
		if (s->gfn != sp->gfn || s->role.direct)
			continue;
		if (s->role.word != sp->role.word)
			return (1);
	}
	KVM_KSTAT_INC(vcpu->kvm, kvmks_mmu_unsync_page);
	sp->unsync = 1;

	kvm_mmu_mark_parents_unsync(vcpu, sp);

	mmu_convert_notrap(sp);
	return (0);
}

static int
mmu_need_write_protect(struct kvm_vcpu *vcpu, gfn_t gfn, int can_unsync)
{
	struct kvm_mmu_page *shadow;

	shadow = kvm_mmu_lookup_page(vcpu->kvm, gfn);
	if (shadow) {
		if (shadow->role.level != PT_PAGE_TABLE_LEVEL)
			return (1);
		if (shadow->unsync)
			return (0);
		if (can_unsync && oos_shadow)
			return (kvm_unsync_page(vcpu, shadow));
		return (1);
	}
	return (0);
}

static int
set_spte(struct kvm_vcpu *vcpu, uint64_t *sptep, unsigned pte_access,
    int user_fault, int write_fault, int dirty, int level, gfn_t gfn,
    pfn_t pfn, int speculative, int can_unsync, int reset_host_protection)
{
	uint64_t spte;
	int ret = 0;

	/*
	 * We don't set the accessed bit, since we sometimes want to see
	 * whether the guest actually used the pte (in order to detect
	 * demand paging).
	 */
	spte = shadow_base_present_pte | shadow_dirty_mask;
	if (!speculative)
		spte |= shadow_accessed_mask;
	if (!dirty)
		pte_access &= ~ACC_WRITE_MASK;
	if (pte_access & ACC_EXEC_MASK)
		spte |= shadow_x_mask;
	else
		spte |= shadow_nx_mask;
	if (pte_access & ACC_USER_MASK)
		spte |= shadow_user_mask;
	if (level > PT_PAGE_TABLE_LEVEL)
		spte |= PT_PAGE_SIZE_MASK;
	if (tdp_enabled)
		spte |= kvm_x86_ops->get_mt_mask(vcpu, gfn,
			kvm_is_mmio_pfn(pfn));

	if (reset_host_protection)
		spte |= SPTE_HOST_WRITEABLE;

	spte |= (uint64_t)pfn << PAGESHIFT;

	if ((pte_access & ACC_WRITE_MASK) ||
	    (write_fault && !is_write_protection(vcpu) && !user_fault)) {

		if (level > PT_PAGE_TABLE_LEVEL &&
		    has_wrprotected_page(vcpu->kvm, gfn, level)) {
			ret = 1;
			spte = shadow_trap_nonpresent_pte;
			goto set_pte;
		}

		spte |= PT_WRITABLE_MASK;

		if (!tdp_enabled && !(pte_access & ACC_WRITE_MASK))
			spte &= ~PT_USER_MASK;

		/*
		 * Optimization: for pte sync, if spte was writable the hash
		 * lookup is unnecessary (and expensive). Write protection
		 * is responsibility of mmu_get_page / kvm_sync_page.
		 * Same reasoning can be applied to dirty page accounting.
		 */
		if (!can_unsync && is_writable_pte(*sptep))
			goto set_pte;

		if (mmu_need_write_protect(vcpu, gfn, can_unsync)) {
			ret = 1;
			pte_access &= ~ACC_WRITE_MASK;
			if (is_writable_pte(spte))
				spte &= ~PT_WRITABLE_MASK;
		}
	}

	if (pte_access & ACC_WRITE_MASK)
		mark_page_dirty(vcpu->kvm, gfn);

set_pte:
	__set_spte(sptep, spte);

	return (ret);
}

static int
kvm_unmap_rmapp(struct kvm *kvm, unsigned long *rmapp,
		unsigned long data)
{
	uint64_t *spte;
	int need_tlb_flush = 0;

	while ((spte = rmap_next(kvm, rmapp, NULL))) {
		if (!(*spte & PT_PRESENT_MASK)) {
			cmn_err(CE_PANIC,
				"kvm_unmap_rmapp: spte = %p, *spte = %lx\n",
				spte, *spte);
		}
		rmap_remove(kvm, spte);
		__set_spte(spte, shadow_trap_nonpresent_pte);
		need_tlb_flush = 1;
	}
	return (need_tlb_flush);
}

#define	RMAP_RECYCLE_THRESHOLD	1000

static void
rmap_recycle(struct kvm_vcpu *vcpu, uint64_t *spte, gfn_t gfn)
{
	unsigned long *rmapp;
	struct kvm_mmu_page *sp;

	sp = page_header(vcpu->kvm, kvm_va2pa((caddr_t)spte));

	gfn = unalias_gfn(vcpu->kvm, gfn);
	rmapp = gfn_to_rmap(vcpu->kvm, gfn, sp->role.level);

	kvm_unmap_rmapp(vcpu->kvm, rmapp, 0);
	kvm_flush_remote_tlbs(vcpu->kvm);
}

static void
mmu_set_spte(struct kvm_vcpu *vcpu, uint64_t *sptep, unsigned pt_access,
    unsigned pte_access, int user_fault, int write_fault, int dirty,
    int *ptwrite, int level, gfn_t gfn, pfn_t pfn, int speculative,
    int reset_host_protection)
{
	int was_rmapped = 0;
	int was_writable = is_writable_pte(*sptep);
	int rmap_count;

	if (is_rmap_spte(*sptep)) {
		/*
		 * If we overwrite a PTE page pointer with a 2MB PMD, unlink
		 * the parent of the now unreachable PTE.
		 */
		if (level > PT_PAGE_TABLE_LEVEL &&
		    !is_large_pte(*sptep)) {
			struct kvm_mmu_page *child;
			uint64_t pte = *sptep;

			child = page_header(vcpu->kvm,
			    pte & PT64_BASE_ADDR_MASK);
			mmu_page_remove_parent_pte(child, sptep);
			__set_spte(sptep, shadow_trap_nonpresent_pte);
			kvm_flush_remote_tlbs(vcpu->kvm);
		} else if (pfn != spte_to_pfn(*sptep)) {
			rmap_remove(vcpu->kvm, sptep);
			__set_spte(sptep, shadow_trap_nonpresent_pte);
			kvm_flush_remote_tlbs(vcpu->kvm);
		} else
			was_rmapped = 1;
	}

	if (set_spte(vcpu, sptep, pte_access, user_fault, write_fault,
	    dirty, level, gfn, pfn, speculative, 1, reset_host_protection)) {
		if (write_fault)
			*ptwrite = 1;
		kvm_x86_ops->tlb_flush(vcpu);
	}

	if (!was_rmapped && is_large_pte(*sptep))
		KVM_KSTAT_INC(vcpu->kvm, kvmks_lpages);

	page_header_update_slot(vcpu->kvm, sptep, gfn);
	if (!was_rmapped) {
		rmap_count = rmap_add(vcpu, sptep, gfn);
		kvm_release_pfn_clean(pfn);
		if (rmap_count > RMAP_RECYCLE_THRESHOLD)
			rmap_recycle(vcpu, sptep, gfn);
	} else {
		if (was_writable)
			kvm_release_pfn_dirty(pfn);
		else
			kvm_release_pfn_clean(pfn);
	}
	if (speculative) {
		vcpu->arch.last_pte_updated = sptep;
		vcpu->arch.last_pte_gfn = gfn;
	}
}

static void
nonpaging_new_cr3(struct kvm_vcpu *vcpu)
{
}

static int
__direct_map(struct kvm_vcpu *vcpu, gpa_t v, int write,
    int level, gfn_t gfn, pfn_t pfn)
{
	struct kvm_shadow_walk_iterator iterator;
	struct kvm_mmu_page *sp;
	int pt_write = 0;
	gfn_t pseudo_gfn;

	for_each_shadow_entry(vcpu, (uint64_t)gfn << PAGESHIFT, iterator) {
		if (iterator.level == level) {
			mmu_set_spte(vcpu, iterator.sptep, ACC_ALL, ACC_ALL,
			    0, write, 1, &pt_write, level, gfn, pfn, 0, 1);
			KVM_VCPU_KSTAT_INC(vcpu, kvmvs_pf_fixed);
			break;
		}

		if (*iterator.sptep == shadow_trap_nonpresent_pte) {
			pseudo_gfn = (iterator.addr &
			    PT64_DIR_BASE_ADDR_MASK) >> PAGESHIFT;

			sp = kvm_mmu_get_page(vcpu, pseudo_gfn, iterator.addr,
			    iterator.level - 1, 1, ACC_ALL, iterator.sptep);

			if (!sp) {
				cmn_err(CE_WARN, "nonpaging_map: ENOMEM\n");
				kvm_release_pfn_clean(pfn);
				return (-ENOMEM);
			}

			__set_spte(iterator.sptep, kvm_va2pa((caddr_t)sp->spt) |
			    PT_PRESENT_MASK | PT_WRITABLE_MASK |
			    shadow_user_mask | shadow_x_mask);
		}
	}

	return (pt_write);
}

static int
nonpaging_map(struct kvm_vcpu *vcpu, gva_t v, int write, gfn_t gfn)
{
	int r;
	int level;
	pfn_t pfn;

	level = mapping_level(vcpu, gfn);

	/*
	 * This path builds a PAE pagetable - so we can map 2mb pages at
	 * maximum. Therefore check if the level is larger than that.
	 */
	if (level > PT_DIRECTORY_LEVEL)
		level = PT_DIRECTORY_LEVEL;

	gfn &= ~(KVM_PAGES_PER_HPAGE(level) - 1);

	smp_rmb();
	pfn = gfn_to_pfn(vcpu->kvm, gfn);

	/* mmio */
	if (is_error_pfn(pfn)) {
		kvm_release_pfn_clean(pfn);
		return (1);
	}

	mutex_enter(&vcpu->kvm->mmu_lock);
	kvm_mmu_free_some_pages(vcpu);
	r = __direct_map(vcpu, v, write, level, gfn, pfn);
	mutex_exit(&vcpu->kvm->mmu_lock);

	return (r);

out_unlock:
	mutex_exit(&vcpu->kvm->mmu_lock);
	kvm_release_pfn_clean(pfn);
	return (0);
}

static void
mmu_free_roots(struct kvm_vcpu *vcpu)
{
	int i;
	struct kvm_mmu_page *sp;

	if (!VALID_PAGE(vcpu->arch.mmu.root_hpa))
		return;

	mutex_enter(&vcpu->kvm->mmu_lock);
	if (vcpu->arch.mmu.shadow_root_level == PT64_ROOT_LEVEL) {
		hpa_t root = vcpu->arch.mmu.root_hpa;

		sp = page_header(vcpu->kvm, root);
		--sp->root_count;
		if (!sp->root_count && sp->role.invalid)
			kvm_mmu_zap_page(vcpu->kvm, sp);
		vcpu->arch.mmu.root_hpa = INVALID_PAGE;
		mutex_exit(&vcpu->kvm->mmu_lock);
		return;
	}

	for (i = 0; i < 4; i++) {
		hpa_t root = vcpu->arch.mmu.pae_root[i];

		if (root) {
			root &= PT64_BASE_ADDR_MASK;
			sp = page_header(vcpu->kvm, root);
			--sp->root_count;
			if (!sp->root_count && sp->role.invalid)
				kvm_mmu_zap_page(vcpu->kvm, sp);
		}
		vcpu->arch.mmu.pae_root[i] = INVALID_PAGE;
	}
	mutex_exit(&vcpu->kvm->mmu_lock);
	vcpu->arch.mmu.root_hpa = INVALID_PAGE;
}

static int
mmu_check_root(struct kvm_vcpu *vcpu, gfn_t root_gfn)
{
	int ret = 0;

	if (!kvm_is_visible_gfn(vcpu->kvm, root_gfn)) {
		set_bit(KVM_REQ_TRIPLE_FAULT, &vcpu->requests);
		ret = 1;
	}

	return (ret);
}

static int
mmu_alloc_roots(struct kvm_vcpu *vcpu)
{
	int i;
	gfn_t root_gfn;
	struct kvm_mmu_page *sp;
	int direct = 0;
	uint64_t pdptr;

	root_gfn = vcpu->arch.cr3 >> PAGESHIFT;

	if (vcpu->arch.mmu.shadow_root_level == PT64_ROOT_LEVEL) {
		hpa_t root = vcpu->arch.mmu.root_hpa;

		ASSERT(!VALID_PAGE(root));
		if (tdp_enabled)
			direct = 1;
		if (mmu_check_root(vcpu, root_gfn))
			return (1);

		mutex_enter(&vcpu->kvm->mmu_lock);
		sp = kvm_mmu_get_page(vcpu, root_gfn, 0, PT64_ROOT_LEVEL,
		    direct, ACC_ALL, NULL);
		root = kvm_va2pa((caddr_t)sp->spt);

		++sp->root_count;
		mutex_exit(&vcpu->kvm->mmu_lock);
		vcpu->arch.mmu.root_hpa = root;
		return (0);
	}
	direct = !is_paging(vcpu);
	if (tdp_enabled)
		direct = 1;
	for (i = 0; i < 4; ++i) {
		hpa_t root = vcpu->arch.mmu.pae_root[i];

		ASSERT(!VALID_PAGE(root));
		if (vcpu->arch.mmu.root_level == PT32E_ROOT_LEVEL) {
			pdptr = kvm_pdptr_read(vcpu, i);

			if (!is_present_gpte(pdptr)) {
				vcpu->arch.mmu.pae_root[i] = 0;
				continue;
			}
			root_gfn = pdptr >> PAGESHIFT;
		} else if (vcpu->arch.mmu.root_level == 0)
			root_gfn = 0;
		if (mmu_check_root(vcpu, root_gfn))
			return (1);

		mutex_enter(&vcpu->kvm->mmu_lock);
		sp = kvm_mmu_get_page(vcpu, root_gfn, i << 30,
			    PT32_ROOT_LEVEL, direct, ACC_ALL, NULL);
		root = kvm_va2pa((caddr_t)sp->spt);
		++sp->root_count;
		mutex_exit(&vcpu->kvm->mmu_lock);

		vcpu->arch.mmu.pae_root[i] = root | PT_PRESENT_MASK;
	}
	vcpu->arch.mmu.root_hpa = kvm_va2pa((caddr_t)vcpu->arch.mmu.pae_root);

	return (0);
}

static void
mmu_sync_roots(struct kvm_vcpu *vcpu)
{
	int i;
	struct kvm_mmu_page *sp;

	if (!VALID_PAGE(vcpu->arch.mmu.root_hpa))
		return;

	if (vcpu->arch.mmu.shadow_root_level == PT64_ROOT_LEVEL) {
		hpa_t root = vcpu->arch.mmu.root_hpa;
		sp = page_header(vcpu->kvm, root);
		mmu_sync_children(vcpu, sp);
		return;
	}

	for (i = 0; i < 4; i++) {
		hpa_t root = vcpu->arch.mmu.pae_root[i];

		if (root && VALID_PAGE(root)) {
			root &= PT64_BASE_ADDR_MASK;
			sp = page_header(vcpu->kvm, root);
			mmu_sync_children(vcpu, sp);
		}
	}
}

void
kvm_mmu_sync_roots(struct kvm_vcpu *vcpu)
{
	mutex_enter(&vcpu->kvm->mmu_lock);
	mmu_sync_roots(vcpu);
	mutex_exit(&vcpu->kvm->mmu_lock);
}

static gpa_t
nonpaging_gva_to_gpa(struct kvm_vcpu *vcpu, gva_t vaddr,
    uint32_t access, uint32_t *error)
{
	if (error)
		*error = 0;
	return (vaddr);
}

static int
nonpaging_page_fault(struct kvm_vcpu *vcpu, gva_t gva, uint32_t error_code)
{
	gfn_t gfn;
	int r;

	r = mmu_topup_memory_caches(vcpu);
	if (r)
		return (r);

	ASSERT(vcpu);
	ASSERT(VALID_PAGE(vcpu->arch.mmu.root_hpa));

	gfn = gva >> PAGESHIFT;

	return (nonpaging_map(vcpu, gva & PAGEMASK,
	    error_code & PFERR_WRITE_MASK, gfn));
}

static int
tdp_page_fault(struct kvm_vcpu *vcpu, gva_t gpa, uint32_t error_code)
{
	pfn_t pfn;
	int r;
	int level;
	gfn_t gfn = gpa >> PAGESHIFT;

	ASSERT(vcpu);
	ASSERT(VALID_PAGE(vcpu->arch.mmu.root_hpa));

	r = mmu_topup_memory_caches(vcpu);
	if (r)
		return (r);

	level = mapping_level(vcpu, gfn);

	gfn &= ~(KVM_PAGES_PER_HPAGE(level) - 1);

	smp_rmb();
	pfn = gfn_to_pfn(vcpu->kvm, gfn);
	if (is_error_pfn(pfn)) {
		kvm_release_pfn_clean(pfn);
		return (1);
	}
	mutex_enter(&vcpu->kvm->mmu_lock);

	kvm_mmu_free_some_pages(vcpu);
	r = __direct_map(vcpu, gpa,
	    error_code & PFERR_WRITE_MASK, level, gfn, pfn);
	mutex_exit(&vcpu->kvm->mmu_lock);

	return (r);

out_unlock:
	mutex_exit(&vcpu->kvm->mmu_lock);
	kvm_release_pfn_clean(pfn);

	return (0);
}

static void
nonpaging_free(struct kvm_vcpu *vcpu)
{
	mmu_free_roots(vcpu);
}

static int
nonpaging_init_context(struct kvm_vcpu *vcpu)
{
	struct kvm_mmu *context = &vcpu->arch.mmu;

	context->new_cr3 = nonpaging_new_cr3;
	context->page_fault = nonpaging_page_fault;
	context->gva_to_gpa = nonpaging_gva_to_gpa;
	context->free = nonpaging_free;
	context->prefetch_page = nonpaging_prefetch_page;
	context->sync_page = nonpaging_sync_page;
	context->invlpg = nonpaging_invlpg;
	context->root_level = 0;
	context->shadow_root_level = PT32E_ROOT_LEVEL;
	context->root_hpa = INVALID_PAGE;

	return (0);
}

void
kvm_mmu_flush_tlb(struct kvm_vcpu *vcpu)
{
	kvm_x86_ops->tlb_flush(vcpu);
}

static void
paging_new_cr3(struct kvm_vcpu *vcpu)
{
	cmn_err(CE_CONT, "!%s: cr3 %lx\n", __func__, vcpu->arch.cr3);
	mmu_free_roots(vcpu);
}

static void
inject_page_fault(struct kvm_vcpu *vcpu, uint64_t addr, uint32_t err_code)
{
	kvm_inject_page_fault(vcpu, addr, err_code);
}

static void
paging_free(struct kvm_vcpu *vcpu)
{
	nonpaging_free(vcpu);
}

static int
is_rsvd_bits_set(struct kvm_vcpu *vcpu, uint64_t gpte, int level)
{
	int bit7;

	bit7 = (gpte >> 7) & 1;
	return ((gpte & vcpu->arch.mmu.rsvd_bits_mask[bit7][level - 1]) != 0);
}

#define	PTTYPE 64
#include "kvm_paging_tmpl.h"
#undef PTTYPE

#define	PTTYPE 32
#include "kvm_paging_tmpl.h"
#undef PTTYPE

static void
reset_rsvds_bits_mask(struct kvm_vcpu *vcpu, int level)
{
	struct kvm_mmu *context = &vcpu->arch.mmu;
	int maxphyaddr = cpuid_maxphyaddr(vcpu);
	uint64_t exb_bit_rsvd = 0;

	if (!is_nx(vcpu))
		exb_bit_rsvd = rsvd_bits(63, 63);
	switch (level) {
	case PT32_ROOT_LEVEL:
		/* no rsvd bits for 2 level 4K page table entries */
		context->rsvd_bits_mask[0][1] = 0;
		context->rsvd_bits_mask[0][0] = 0;
		if (is_cpuid_PSE36())
			/* 36bits PSE 4MB page */
			context->rsvd_bits_mask[1][1] = rsvd_bits(17, 21);
		else
			/* 32 bits PSE 4MB page */
			context->rsvd_bits_mask[1][1] = rsvd_bits(13, 21);
		context->rsvd_bits_mask[1][0] = context->rsvd_bits_mask[1][0];
		break;
	case PT32E_ROOT_LEVEL:
		context->rsvd_bits_mask[0][2] =
			rsvd_bits(maxphyaddr, 63) |
			rsvd_bits(7, 8) | rsvd_bits(1, 2);	/* PDPTE */
		context->rsvd_bits_mask[0][1] = exb_bit_rsvd |
			rsvd_bits(maxphyaddr, 62);	/* PDE */
		context->rsvd_bits_mask[0][0] = exb_bit_rsvd |
			rsvd_bits(maxphyaddr, 62); 	/* PTE */
		context->rsvd_bits_mask[1][1] = exb_bit_rsvd |
			rsvd_bits(maxphyaddr, 62) |
			rsvd_bits(13, 20);		/* large page */
		context->rsvd_bits_mask[1][0] = context->rsvd_bits_mask[1][0];
		break;
	case PT64_ROOT_LEVEL:
		context->rsvd_bits_mask[0][3] = exb_bit_rsvd |
			rsvd_bits(maxphyaddr, 51) | rsvd_bits(7, 8);
		context->rsvd_bits_mask[0][2] = exb_bit_rsvd |
			rsvd_bits(maxphyaddr, 51) | rsvd_bits(7, 8);
		context->rsvd_bits_mask[0][1] = exb_bit_rsvd |
			rsvd_bits(maxphyaddr, 51);
		context->rsvd_bits_mask[0][0] = exb_bit_rsvd |
			rsvd_bits(maxphyaddr, 51);
		context->rsvd_bits_mask[1][3] = context->rsvd_bits_mask[0][3];
		context->rsvd_bits_mask[1][2] = exb_bit_rsvd |
			rsvd_bits(maxphyaddr, 51) |
			rsvd_bits(13, 29);
		context->rsvd_bits_mask[1][1] = exb_bit_rsvd |
			rsvd_bits(maxphyaddr, 51) |
			rsvd_bits(13, 20);		/* large page */
		context->rsvd_bits_mask[1][0] = context->rsvd_bits_mask[1][0];
		break;
	}
}

static int
paging64_init_context_common(struct kvm_vcpu *vcpu, int level)
{
	struct kvm_mmu *context = &vcpu->arch.mmu;

	ASSERT(is_pae(vcpu));
	context->new_cr3 = paging_new_cr3;
	context->page_fault = paging64_page_fault;
	context->gva_to_gpa = paging64_gva_to_gpa;
	context->prefetch_page = paging64_prefetch_page;
	context->sync_page = paging64_sync_page;
	context->invlpg = paging64_invlpg;
	context->free = paging_free;
	context->root_level = level;
	context->shadow_root_level = level;
	context->root_hpa = INVALID_PAGE;

	return (0);
}

static int
paging64_init_context(struct kvm_vcpu *vcpu)
{
	reset_rsvds_bits_mask(vcpu, PT64_ROOT_LEVEL);
	return (paging64_init_context_common(vcpu, PT64_ROOT_LEVEL));
}

static int
paging32_init_context(struct kvm_vcpu *vcpu)
{
	struct kvm_mmu *context = &vcpu->arch.mmu;

	reset_rsvds_bits_mask(vcpu, PT32_ROOT_LEVEL);
	context->new_cr3 = paging_new_cr3;
	context->page_fault = paging32_page_fault;
	context->gva_to_gpa = paging32_gva_to_gpa;
	context->free = paging_free;
	context->prefetch_page = paging32_prefetch_page;
	context->sync_page = paging32_sync_page;
	context->invlpg = paging32_invlpg;
	context->root_level = PT32_ROOT_LEVEL;
	context->shadow_root_level = PT32E_ROOT_LEVEL;
	context->root_hpa = INVALID_PAGE;

	return (0);
}

static int
paging32E_init_context(struct kvm_vcpu *vcpu)
{
	reset_rsvds_bits_mask(vcpu, PT32E_ROOT_LEVEL);
	return (paging64_init_context_common(vcpu, PT32E_ROOT_LEVEL));
}

static int
init_kvm_tdp_mmu(struct kvm_vcpu *vcpu)
{
	struct kvm_mmu *context = &vcpu->arch.mmu;

	context->new_cr3 = nonpaging_new_cr3;
	context->page_fault = tdp_page_fault;
	context->free = nonpaging_free;
	context->prefetch_page = nonpaging_prefetch_page;
	context->sync_page = nonpaging_sync_page;
	context->invlpg = nonpaging_invlpg;
	context->shadow_root_level = kvm_x86_ops->get_tdp_level();
	context->root_hpa = INVALID_PAGE;

	if (!is_paging(vcpu)) {
		context->gva_to_gpa = nonpaging_gva_to_gpa;
		context->root_level = 0;
	} else if (is_long_mode(vcpu)) {
		reset_rsvds_bits_mask(vcpu, PT64_ROOT_LEVEL);
		context->gva_to_gpa = paging64_gva_to_gpa;
		context->root_level = PT64_ROOT_LEVEL;
	} else if (is_pae(vcpu)) {
		reset_rsvds_bits_mask(vcpu, PT32E_ROOT_LEVEL);
		context->gva_to_gpa = paging64_gva_to_gpa;
		context->root_level = PT32E_ROOT_LEVEL;
	} else {
		reset_rsvds_bits_mask(vcpu, PT32_ROOT_LEVEL);
		context->gva_to_gpa = paging32_gva_to_gpa;
		context->root_level = PT32_ROOT_LEVEL;
	}

	return (0);
}

static int
init_kvm_softmmu(struct kvm_vcpu *vcpu)
{
	int r;

	ASSERT(vcpu);
	ASSERT(!VALID_PAGE(vcpu->arch.mmu.root_hpa));

	if (!is_paging(vcpu))
		r = nonpaging_init_context(vcpu);
	else if (is_long_mode(vcpu))
		r = paging64_init_context(vcpu);
	else if (is_pae(vcpu))
		r = paging32E_init_context(vcpu);
	else
		r = paging32_init_context(vcpu);

	vcpu->arch.mmu.base_role.glevels = vcpu->arch.mmu.root_level;
	vcpu->arch.mmu.base_role.cr0_wp = is_write_protection(vcpu);

	return (r);
}

static int
init_kvm_mmu(struct kvm_vcpu *vcpu)
{
	vcpu->arch.update_pte.pfn = -1; /* bad_pfn */

	if (tdp_enabled)
		return (init_kvm_tdp_mmu(vcpu));
	else
		return (init_kvm_softmmu(vcpu));

	return (0);
}

static void
destroy_kvm_mmu(struct kvm_vcpu *vcpu)
{
	ASSERT(vcpu);
	if (VALID_PAGE(vcpu->arch.mmu.root_hpa)) {
		vcpu->arch.mmu.free(vcpu);
		vcpu->arch.mmu.root_hpa = INVALID_PAGE;
	}
}

int
kvm_mmu_reset_context(struct kvm_vcpu *vcpu)
{
	destroy_kvm_mmu(vcpu);
	return (init_kvm_mmu(vcpu));
}

int
kvm_mmu_load(struct kvm_vcpu *vcpu)
{
	int r;

	r = mmu_topup_memory_caches(vcpu);
	if (r)
		goto out;
	mutex_enter(&vcpu->kvm->mmu_lock);
	kvm_mmu_free_some_pages(vcpu);
	mutex_exit(&vcpu->kvm->mmu_lock);

	r = mmu_alloc_roots(vcpu);

	mutex_enter(&vcpu->kvm->mmu_lock);
	mmu_sync_roots(vcpu);
	mutex_exit(&vcpu->kvm->mmu_lock);
	if (r)
		goto out;

	/*
	 * set_cr3() should ensure TLB has been flushed
	 */
	kvm_x86_ops->set_cr3(vcpu, vcpu->arch.mmu.root_hpa);
out:
	return (r);
}


void
kvm_mmu_unload(struct kvm_vcpu *vcpu)
{
	mmu_free_roots(vcpu);
}

static void
mmu_pte_write_zap_pte(struct kvm_vcpu *vcpu,
    struct kvm_mmu_page *sp, uint64_t *spte)
{
	uint64_t pte;
	struct kvm_mmu_page *child;

	pte = *spte;

	if (is_shadow_present_pte(pte)) {
		if (is_last_spte(pte, sp->role.level)) {
			rmap_remove(vcpu->kvm, spte);
		} else {
			child = page_header(vcpu->kvm,
			    pte & PT64_BASE_ADDR_MASK);
			mmu_page_remove_parent_pte(child, spte);
		}
	}
	__set_spte(spte, shadow_trap_nonpresent_pte);

	if (is_large_pte(pte))
		KVM_KSTAT_DEC(vcpu->kvm, kvmks_lpages);
}

static void
mmu_pte_write_new_pte(struct kvm_vcpu *vcpu, struct kvm_mmu_page *sp,
    uint64_t *spte, const void *new)
{
	if (sp->role.level != PT_PAGE_TABLE_LEVEL) {
		KVM_KSTAT_INC(vcpu->kvm, kvmks_mmu_pte_zapped);
		return;
	}

	KVM_KSTAT_INC(vcpu->kvm, kvmks_mmu_pte_updated);

	if (sp->role.glevels == PT32_ROOT_LEVEL)
		paging32_update_pte(vcpu, sp, spte, new);
	else
		paging64_update_pte(vcpu, sp, spte, new);
}

static int
need_remote_flush(uint64_t old, uint64_t new)
{
	if (!is_shadow_present_pte(old))
		return (0);
	if (!is_shadow_present_pte(new))
		return (1);
	if ((old ^ new) & PT64_BASE_ADDR_MASK)
		return (1);
	old ^= PT64_NX_MASK;
	new ^= PT64_NX_MASK;
	return ((old & ~new & PT64_PERM_MASK) != 0);
}

static void
mmu_pte_write_flush_tlb(struct kvm_vcpu *vcpu, uint64_t old, uint64_t new)
{
	if (need_remote_flush(old, new))
		kvm_flush_remote_tlbs(vcpu->kvm);
	else
		kvm_mmu_flush_tlb(vcpu);
}

static int
last_updated_pte_accessed(struct kvm_vcpu *vcpu)
{
	uint64_t *spte = vcpu->arch.last_pte_updated;

	return (!!(spte && (*spte & shadow_accessed_mask)));
}

static void
mmu_guess_page_from_pte_write(struct kvm_vcpu *vcpu, gpa_t gpa,
    const uint8_t *new, int bytes)
{
	gfn_t gfn;
	int r;
	uint64_t gpte = 0;
	pfn_t pfn;

	if (bytes != 4 && bytes != 8)
		return;

	/*
	 * Assume that the pte write on a page table of the same type
	 * as the current vcpu paging mode.  This is nearly always true
	 * (might be false while changing modes).  Note it is verified later
	 * by update_pte().
	 */
	if (is_pae(vcpu)) {
		/* Handle a 32-bit guest writing two halves of a 64-bit gpte */
		if ((bytes == 4) && (gpa % 4 == 0)) {
			r = kvm_read_guest(vcpu->kvm,
			    gpa & ~(uint64_t)7, &gpte, 8);

			if (r)
				return;
			memcpy((void *)((uintptr_t)&gpte + (gpa % 8)), new, 4);
		} else if ((bytes == 8) && (gpa % 8 == 0)) {
			memcpy((void *)&gpte, new, 8);
		}
	} else {
		if ((bytes == 4) && (gpa % 4 == 0))
			memcpy((void *)&gpte, new, 4);
	}
	if (!is_present_gpte(gpte))
		return;

	gfn = (gpte & PT64_BASE_ADDR_MASK) >> PAGESHIFT;

	smp_rmb();
	pfn = gfn_to_pfn(vcpu->kvm, gfn);

	if (is_error_pfn(pfn)) {
		kvm_release_pfn_clean(pfn);
		return;
	}
	vcpu->arch.update_pte.gfn = gfn;
	vcpu->arch.update_pte.pfn = pfn;
}

static void
kvm_mmu_access_page(struct kvm_vcpu *vcpu, gfn_t gfn)
{
	uint64_t *spte = vcpu->arch.last_pte_updated;

	if (spte && vcpu->arch.last_pte_gfn == gfn && shadow_accessed_mask &&
	    !(*spte & shadow_accessed_mask) && is_shadow_present_pte(*spte))
		set_bit(PT_ACCESSED_SHIFT, (unsigned long *)spte);
}

void
kvm_mmu_pte_write(struct kvm_vcpu *vcpu, gpa_t gpa,
    const uint8_t *new, int bytes, int guest_initiated)
{
	gfn_t gfn = gpa >> PAGESHIFT;
	struct kvm_mmu_page *sp, *nsp = NULL;
	list_t *bucket;
	unsigned index;
	uint64_t entry, gentry;
	uint64_t *spte;
	unsigned offset = offset_in_page(gpa);
	unsigned pte_size;
	unsigned page_offset;
	unsigned misaligned;
	unsigned quadrant;
	int level;
	int flooded = 0;
	int npte;
	int r;

	mmu_guess_page_from_pte_write(vcpu, gpa, new, bytes);
	mutex_enter(&vcpu->kvm->mmu_lock);
	kvm_mmu_access_page(vcpu, gfn);
	kvm_mmu_free_some_pages(vcpu);
	KVM_KSTAT_INC(vcpu->kvm, kvmks_mmu_pte_write);

	if (guest_initiated) {
		if (gfn == vcpu->arch.last_pt_write_gfn &&
		    !last_updated_pte_accessed(vcpu)) {
			++vcpu->arch.last_pt_write_count;
			if (vcpu->arch.last_pt_write_count >= 3)
				flooded = 1;
		} else {
			vcpu->arch.last_pt_write_gfn = gfn;
			vcpu->arch.last_pt_write_count = 1;
			vcpu->arch.last_pte_updated = NULL;
		}
	}
	index = kvm_page_table_hashfn(gfn);
	bucket = &vcpu->kvm->arch.mmu_page_hash[index];

	for (sp = list_head(bucket); sp; sp = nsp) {
		/*
		 * Keep next list node pointer as we may free the current one
		 */
		nsp = list_next(bucket, sp);

		if (sp->gfn != gfn || sp->role.direct || sp->role.invalid)
			continue;

		pte_size = sp->role.glevels == PT32_ROOT_LEVEL ? 4 : 8;
		misaligned = (offset ^ (offset + bytes - 1)) & ~(pte_size - 1);
		misaligned |= bytes < 4;
		if (misaligned || flooded) {
			/*
			 * Misaligned accesses are too much trouble to fix
			 * up; also, they usually indicate a page is not used
			 * as a page table.
			 *
			 * If we're seeing too many writes to a page,
			 * it may no longer be a page table, or we may be
			 * forking, in which case it is better to unmap the
			 * page.
			 */
			if (kvm_mmu_zap_page(vcpu->kvm, sp)) {
				/*
				 * kvm_mmu_zap_page() freed page(s) from
				 * somewhere in the list, so start walking
				 * again from the head.
				 */
				nsp = list_head(bucket);
			}
			KVM_KSTAT_INC(vcpu->kvm, kvmks_mmu_flooded);
			continue;
		}
		page_offset = offset;
		level = sp->role.level;
		npte = 1;
		if (sp->role.glevels == PT32_ROOT_LEVEL) {
			page_offset <<= 1;	/* 32->64 */
			/*
			 * A 32-bit pde maps 4MB while the shadow pdes map
			 * only 2MB.  So we need to double the offset again
			 * and zap two pdes instead of one.
			 */
			if (level == PT32_ROOT_LEVEL) {
				page_offset &= ~7; /* kill rounding error */
				page_offset <<= 1;
				npte = 2;
			}
			quadrant = page_offset >> PAGESHIFT;
			page_offset &= ~PAGEMASK;
			if (quadrant != sp->role.quadrant)
				continue;
		}

		spte = &sp->spt[page_offset / sizeof (*spte)];

		if ((gpa & (pte_size - 1)) || (bytes < pte_size)) {
			gentry = 0;
			r = kvm_read_guest_atomic(vcpu->kvm,
			    gpa & ~(uint64_t)(pte_size - 1), &gentry, pte_size);
			new = (const void *)&gentry;
			if (r < 0)
				new = NULL;
		}

		while (npte--) {
			entry = *spte;
			mmu_pte_write_zap_pte(vcpu, sp, spte);
			if (new)
				mmu_pte_write_new_pte(vcpu, sp, spte, new);
			mmu_pte_write_flush_tlb(vcpu, entry, *spte);
			++spte;
		}
	}

	KVM_TRACE1(mmu__audit__post__pte, struct kvm_vcpu *, vcpu);
	mutex_exit(&vcpu->kvm->mmu_lock);

	if (!is_error_pfn(vcpu->arch.update_pte.pfn)) {
		kvm_release_pfn_clean(vcpu->arch.update_pte.pfn);
		vcpu->arch.update_pte.pfn = bad_pfn;
	}
}

int
kvm_mmu_unprotect_page_virt(struct kvm_vcpu *vcpu, gva_t gva)
{
	gpa_t gpa;
	int r;

	if (tdp_enabled)
		return (0);

	gpa = kvm_mmu_gva_to_gpa_read(vcpu, gva, NULL);

	mutex_enter(&vcpu->kvm->mmu_lock);
	r = kvm_mmu_unprotect_page(vcpu->kvm, gpa >> PAGESHIFT);
	mutex_exit(&vcpu->kvm->mmu_lock);

	return (r);
}

void
__kvm_mmu_free_some_pages(struct kvm_vcpu *vcpu)
{
	while (vcpu->kvm->arch.n_free_mmu_pages < KVM_REFILL_PAGES &&
	    !list_is_empty(&vcpu->kvm->arch.active_mmu_pages)) {
		struct kvm_mmu_page *sp;

		sp = list_tail(&vcpu->kvm->arch.active_mmu_pages);
		kvm_mmu_zap_page(vcpu->kvm, sp);
		KVM_KSTAT_INC(vcpu->kvm, kvmks_mmu_recycled);
	}
}

int
kvm_mmu_page_fault(struct kvm_vcpu *vcpu, gva_t cr2, uint32_t error_code)
{
	int r;
	enum emulation_result er;

	if ((r = vcpu->arch.mmu.page_fault(vcpu, cr2, error_code)) < 0)
		return (r);

	if (r == 0)
		return (1);

	if ((r = mmu_topup_memory_caches(vcpu)) != 0)
		return (r);

	er = emulate_instruction(vcpu, cr2, error_code, 0);

	switch (er) {
	case EMULATE_DONE:
		return (1);

	case EMULATE_DO_MMIO:
		KVM_VCPU_KSTAT_INC(vcpu, kvmvs_mmio_exits);
		return (0);

	case EMULATE_FAIL:
		vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
		vcpu->run->internal.suberror = KVM_INTERNAL_ERROR_EMULATION;
		vcpu->run->internal.ndata = 0;
		return (0);
	default:
		panic("kvm_mmu_page_fault: unknown return "
		    "from emulate_instruction: %x\n", er);
	}

	return (0);
}

void
kvm_mmu_invlpg(struct kvm_vcpu *vcpu, gva_t gva)
{
	vcpu->arch.mmu.invlpg(vcpu, gva);
	kvm_mmu_flush_tlb(vcpu);
	KVM_VCPU_KSTAT_INC(vcpu, kvmvs_invlpg);
}

void
kvm_enable_tdp(void)
{
	tdp_enabled = 1;
}

void
kvm_disable_tdp(void)
{
	tdp_enabled = 0;
}

static int
alloc_mmu_pages(struct kvm_vcpu *vcpu)
{
	page_t *page;
	int i;

	ASSERT(vcpu);

	/*
	 * When emulating 32-bit mode, cr3 is only 32 bits even on x86_64.
	 * Therefore we need to allocate shadow page tables in the first
	 * 4GB of memory, which happens to fit the DMA32 zone.
	 * XXX - for right now, ignore DMA32.  need to use ddi_dma_mem_alloc
	 * to address this issue...
	 * XXX - also, don't need to allocate a full page, we'll look
	 * at htable_t later on solaris.
	 */
	page = alloc_page(KM_SLEEP, &vcpu->arch.mmu.alloc_pae_root);
	if (!page)
		return (-ENOMEM);

	vcpu->arch.mmu.pae_root = (uint64_t *)page_address(page);

	for (i = 0; i < 4; ++i)
		vcpu->arch.mmu.pae_root[i] = INVALID_PAGE;

	return (0);
}

int
kvm_mmu_create(struct kvm_vcpu *vcpu)
{
	int i;

	ASSERT(vcpu);
	ASSERT(!VALID_PAGE(vcpu->arch.mmu.root_hpa));

	/*
	 * We'll initialize hash lists here
	 */

	for (i = 0; i < KVM_NUM_MMU_PAGES; i++)
		list_create(&vcpu->kvm->arch.mmu_page_hash[i],
		    sizeof (struct kvm_mmu_page),
		    offsetof(struct kvm_mmu_page, hash_link));

	return (alloc_mmu_pages(vcpu));
}

int
kvm_mmu_setup(struct kvm_vcpu *vcpu)
{
	ASSERT(vcpu);

	return (init_kvm_mmu(vcpu));
}

static void
free_mmu_pages(struct kvm_vcpu *vcpu)
{
	kmem_free(vcpu->arch.mmu.alloc_pae_root, PAGESIZE);
}

static void
mmu_free_memory_cache(struct kvm_mmu_memory_cache *mc, struct kmem_cache *cp)
{
	while (mc->nobjs)
		kmem_cache_free(cp, mc->objects[--mc->nobjs].kma_object);
}

static void
mmu_free_memory_cache_page(struct kvm_mmu_memory_cache *mc)
{
	while (mc->nobjs)
		kmem_free(mc->objects[--mc->nobjs].kma_object, PAGESIZE);
}

static void
mmu_free_memory_caches(struct kvm_vcpu *vcpu)
{
	mmu_free_memory_cache(&vcpu->arch.mmu_pte_chain_cache, pte_chain_cache);
	mmu_free_memory_cache(&vcpu->arch.mmu_rmap_desc_cache, rmap_desc_cache);
	mmu_free_memory_cache_page(&vcpu->arch.mmu_page_cache);
	mmu_free_memory_cache(&vcpu->arch.mmu_page_header_cache,
	    mmu_page_header_cache);
}

void
kvm_mmu_destroy(struct kvm_vcpu *vcpu)
{
	ASSERT(vcpu);

	destroy_kvm_mmu(vcpu);
	free_mmu_pages(vcpu);
	mmu_free_memory_caches(vcpu);
}

void
kvm_mmu_slot_remove_write_access(struct kvm *kvm, int slot)
{
	struct kvm_mmu_page *sp;

	for (sp = list_head(&kvm->arch.active_mmu_pages);
	    sp != NULL; sp = list_next(&kvm->arch.active_mmu_pages, sp)) {
		int i;
		uint64_t *pt;

		if (!test_bit(slot, sp->slot_bitmap))
			continue;

		pt = sp->spt;
		for (i = 0; i < PT64_ENT_PER_PAGE; i++) {
			/* avoid RMW */
			if (pt[i] & PT_WRITABLE_MASK)
				pt[i] &= ~PT_WRITABLE_MASK;
		}
	}
	kvm_flush_remote_tlbs(kvm);
}

void
kvm_mmu_zap_all(struct kvm *kvm)
{
	struct kvm_mmu_page *sp, *nsp;

	/*
	 * In the following loop, sp may be freed and deleted
	 * from the list indirectly from kvm_mmu_zap_page.
	 * So we hold onto the next element before zapping.
	 */
	mutex_enter(&kvm->mmu_lock);

	for (sp = list_head(&kvm->arch.active_mmu_pages);
	    sp != NULL; sp = nsp) {
		nsp = list_next(&kvm->arch.active_mmu_pages, sp);

		if (kvm_mmu_zap_page(kvm, sp))
			nsp = list_head(&kvm->arch.active_mmu_pages);
	}

	mutex_exit(&kvm->mmu_lock);
	kvm_flush_remote_tlbs(kvm);
}

void
kvm_mmu_destroy_caches(void)
{
	if (pte_chain_cache)
		kmem_cache_destroy(pte_chain_cache);
	if (rmap_desc_cache)
		kmem_cache_destroy(rmap_desc_cache);
	if (mmu_page_header_cache)
		kmem_cache_destroy(mmu_page_header_cache);
}

int
kvm_mmu_module_init(void)
{
	if ((pte_chain_cache = kmem_cache_create("kvm_pte_chain",
	    sizeof (struct kvm_pte_chain), 0, zero_constructor, NULL, NULL,
	    (void *)sizeof (struct kvm_pte_chain), NULL, 0)) == NULL)
		goto nomem;

	if ((rmap_desc_cache = kmem_cache_create("kvm_rmap_desc",
	    sizeof (struct kvm_rmap_desc), 0, zero_constructor, NULL, NULL,
	    (void *)sizeof (struct kvm_rmap_desc), NULL, 0)) == NULL)
		goto nomem;

	if ((mmu_page_header_cache = kmem_cache_create("kvm_mmu_page_header",
	    sizeof (struct kvm_mmu_page), 0, zero_constructor, NULL, NULL,
	    (void *)sizeof (struct kvm_mmu_page), NULL, 0)) == NULL)
		goto nomem;

	return (0);

nomem:
	kvm_mmu_destroy_caches();
	return (ENOMEM);
}

/*
 * Caculate mmu pages needed for kvm.
 */
unsigned int
kvm_mmu_calculate_mmu_pages(struct kvm *kvm)
{
	int i;
	unsigned int nr_mmu_pages;
	unsigned int  nr_pages = 0;
	struct kvm_memslots *slots;

	mutex_enter(&kvm->memslots_lock);
	slots = kvm->memslots;
	for (i = 0; i < slots->nmemslots; i++)
		nr_pages += slots->memslots[i].npages;
	mutex_exit(&kvm->memslots_lock);
	nr_mmu_pages = nr_pages * KVM_PERMILLE_MMU_PAGES / 1000;
	nr_mmu_pages = MAX(nr_mmu_pages, (unsigned int)KVM_MIN_ALLOC_MMU_PAGES);

	return (nr_mmu_pages);
}

int
kvm_mmu_get_spte_hierarchy(struct kvm_vcpu *vcpu,
    uint64_t addr, uint64_t sptes[4])
{
	struct kvm_shadow_walk_iterator iterator;
	int nr_sptes = 0;

	mutex_enter(&vcpu->kvm->mmu_lock);
	for_each_shadow_entry(vcpu, addr, iterator) {
		sptes[iterator.level - 1] = *iterator.sptep;
		nr_sptes++;
		if (!is_shadow_present_pte(*iterator.sptep))
			break;
	}
	mutex_exit(&vcpu->kvm->mmu_lock);

	return (nr_sptes);
}

void
kvm_mmu_free_some_pages(struct kvm_vcpu *vcpu)
{
	if (vcpu->kvm->arch.n_free_mmu_pages < KVM_MIN_FREE_MMU_PAGES)
		__kvm_mmu_free_some_pages(vcpu);
}

int
kvm_mmu_reload(struct kvm_vcpu *vcpu)
{
	if (vcpu->arch.mmu.root_hpa != INVALID_PAGE)
		return (0);

	return (kvm_mmu_load(vcpu));
}

int
is_present_gpte(unsigned long pte)
{
	return (pte & PT_PRESENT_MASK);
}

static struct kvm_mmu_page *
page_private(kvm_t *kvmp, page_t *page)
{
	kvm_mmu_page_t mp, *res;
	mp.kmp_avlspt = (uintptr_t)page;
	mutex_enter(&kvmp->kvm_avllock);
	res = avl_find(&kvmp->kvm_avlmp, &mp, NULL);
	mutex_exit(&kvmp->kvm_avllock);
	ASSERT(res != NULL);
	return (res);
}

struct kvm_mmu_page *
page_header(kvm_t *kvmp, hpa_t shadow_page)
{
	return (page_private(kvmp, pfn_to_page(shadow_page >> PAGESHIFT)));
}

int
kvm_avlmmucmp(const void *arg1, const void *arg2)
{
	const kvm_mmu_page_t *mp1 = arg1;
	const kvm_mmu_page_t *mp2 = arg2;
	if (mp1->kmp_avlspt > mp2->kmp_avlspt)
		return (1);
	if (mp1->kmp_avlspt < mp2->kmp_avlspt)
		return (-1);
	ASSERT(mp1->kmp_avlspt == mp2->kmp_avlspt);
	return (0);
}

inline page_t *
compound_head(page_t *page)
{
	return (page);
}

inline void
get_page(page_t *page)
{
	page = compound_head(page);
}

page_t *
pfn_to_page(pfn_t pfn)
{
	return (page_numtopp_nolock(pfn));
}

page_t *
alloc_page(int flag, void **kma_addr)
{
	caddr_t page_addr;
	pfn_t pfn;
	page_t *pp;

	if ((page_addr = kmem_zalloc(PAGESIZE, flag)) == NULL)
		return ((page_t *)NULL);

	*kma_addr = page_addr;
	pp = page_numtopp_nolock(hat_getpfnum(kas.a_hat, page_addr));
	return (pp);
}

/*
 * Often times we have pages that correspond to addresses that are in a users
 * virtual address space. Rather than trying to constantly map them in and out
 * of our address space we instead go through and use the kpm segment to
 * facilitate this for us. This always returns an address that is always in the
 * kernel's virtual address space.
 */
caddr_t
page_address(page_t *page)
{
	return (hat_kpm_mapin_pfn(page->p_pagenum));
}
