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
#ifndef __TSS_SEGMENT_H
#define	__TSS_SEGMENT_H

#include <sys/stdint.h>
#include <sys/tss.h>

/*
 * uts/intel/sys/tss.h now exposes the following definitions. In the past, it
 * only exposed the single architecture specific tss structure depending on what
 * you were compiling for. When the tss.h changes finally gets upstreamed, this
 * file can be deleted and the includes replaced with <sys/tss.h> instead of
 * kvm_tss.h.
 */

#ifdef _NEED_KVM_TSS

struct tss32 {
	uint16_t	tss_link;	/* 16-bit prior TSS selector */
	uint16_t	tss_rsvd0;	/* reserved, ignored */
	uint32_t	tss_esp0;
	uint16_t	tss_ss0;
	uint16_t	tss_rsvd1;	/* reserved, ignored */
	uint32_t	tss_esp1;
	uint16_t	tss_ss1;
	uint16_t	tss_rsvd2;	/* reserved, ignored */
	uint32_t	tss_esp2;
	uint16_t	tss_ss2;
	uint16_t	tss_rsvd3;	/* reserved, ignored */
	uint32_t	tss_cr3;
	uint32_t	tss_eip;
	uint32_t	tss_eflags;
	uint32_t	tss_eax;
	uint32_t	tss_ecx;
	uint32_t	tss_edx;
	uint32_t	tss_ebx;
	uint32_t	tss_esp;
	uint32_t	tss_ebp;
	uint32_t	tss_esi;
	uint32_t	tss_edi;
	uint16_t	tss_es;
	uint16_t	tss_rsvd4;	/* reserved, ignored */
	uint16_t	tss_cs;
	uint16_t	tss_rsvd5;	/* reserved, ignored */
	uint16_t	tss_ss;
	uint16_t	tss_rsvd6;	/* reserved, ignored */
	uint16_t	tss_ds;
	uint16_t	tss_rsvd7;	/* reserved, ignored */
	uint16_t	tss_fs;
	uint16_t	tss_rsvd8;	/* reserved, ignored */
	uint16_t	tss_gs;
	uint16_t	tss_rsvd9;	/* reserved, ignored */
	uint16_t	tss_ldt;
	uint16_t	tss_rsvd10;	/* reserved, ignored */
	uint16_t	tss_rsvd11;	/* reserved, ignored */
	uint16_t	tss_bitmapbase;	/* io permission bitmap base address */
};

/*
 * Based on data from Intel Manual 3a, Intel 64 and IA-32 Architectures Software
 * Developer’s Manual Volume 3A: System Programming Guide, Part 1, Section 7.6
 */
struct tss16 {
	uint16_t	tss_link;
	uint16_t	tss_sp0;
	uint16_t	tss_ss0;
	uint16_t	tss_sp1;
	uint16_t	tss_ss1;
	uint16_t	tss_sp2;
	uint16_t	tss_ss2;
	uint16_t	tss_ip;
	uint16_t	tss_flag;
	uint16_t	tss_ax;
	uint16_t	tss_cx;
	uint16_t	tss_dx;
	uint16_t	tss_bx;
	uint16_t	tss_sp;
	uint16_t	tss_bp;
	uint16_t	tss_si;
	uint16_t	tss_di;
	uint16_t	tss_es;
	uint16_t	tss_cs;
	uint16_t	tss_ss;
	uint16_t	tss_ds;
	uint16_t	tss_ldt;
};

#endif /* _HAVE_KVM_TSS */

#endif
