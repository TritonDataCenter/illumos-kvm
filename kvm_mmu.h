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
 */

#ifndef __KVM_X86_MMU_H
#define	__KVM_X86_MMU_H

#include <sys/stdint.h>

struct kvm_vcpu;

#define	PT64_PT_BITS 9
#define	PT64_ENT_PER_PAGE (1 << PT64_PT_BITS)
#define	PT32_PT_BITS 10
#define	PT32_ENT_PER_PAGE (1 << PT32_PT_BITS)

#define	PT_WRITABLE_SHIFT 1

#define	PT_PRESENT_MASK (1ULL << 0)
#define	PT_WRITABLE_MASK (1ULL << PT_WRITABLE_SHIFT)
#define	PT_USER_MASK (1ULL << 2)
#define	PT_PWT_MASK (1ULL << 3)
#define	PT_PCD_MASK (1ULL << 4)
#define	PT_ACCESSED_SHIFT 5
#define	PT_ACCESSED_MASK (1ULL << PT_ACCESSED_SHIFT)
#define	PT_DIRTY_MASK (1ULL << 6)
#define	PT_PAGE_SIZE_MASK (1ULL << 7)
#define	PT_PAT_MASK (1ULL << 7)
#define	PT_GLOBAL_MASK (1ULL << 8)
#define	PT64_NX_SHIFT 63
#define	PT64_NX_MASK (1ULL << PT64_NX_SHIFT)

#define	PT_PAT_SHIFT 7
#define	PT_DIR_PAT_SHIFT 12
#define	PT_DIR_PAT_MASK (1ULL << PT_DIR_PAT_SHIFT)

#define	PT32_DIR_PSE36_SIZE 4
#define	PT32_DIR_PSE36_SHIFT 13
#define	PT32_DIR_PSE36_MASK \
	(((1ULL << PT32_DIR_PSE36_SIZE) - 1) << PT32_DIR_PSE36_SHIFT)

#define	PT64_ROOT_LEVEL 4
#define	PT32_ROOT_LEVEL 2
#define	PT32E_ROOT_LEVEL 3

#define	PT_PDPE_LEVEL 3
#define	PT_DIRECTORY_LEVEL 2
#define	PT_PAGE_TABLE_LEVEL 1

#define	PFERR_PRESENT_MASK (1U << 0)
#define	PFERR_WRITE_MASK (1U << 1)
#define	PFERR_USER_MASK (1U << 2)
#define	PFERR_RSVD_MASK (1U << 3)
#define	PFERR_FETCH_MASK (1U << 4)

#define	MTRR_TYPE_UNCACHABLE	0
#define	MTRR_TYPE_WRCOMB	1
#define	MTRR_TYPE_WRTHROUGH	4
#define	MTRR_TYPE_WRPROT	5
#define	MTRR_TYPE_WRBACK	6
#define	MTRR_NUM_TYPES		7


extern int kvm_mmu_get_spte_hierarchy(struct kvm_vcpu *,
    uint64_t, uint64_t[4]);
extern void kvm_mmu_free_some_pages(struct kvm_vcpu *);
extern int kvm_mmu_reload(struct kvm_vcpu *);
extern int is_present_gpte(unsigned long);
extern int kvm_avlmmucmp(const void *, const void *);
extern void kvm_mmu_destroy_caches(void);

#endif
