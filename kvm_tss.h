#ifndef __TSS_SEGMENT_H
#define	__TSS_SEGMENT_H

#include <sys/stdint.h>

typedef struct tss_segment_32 {
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
} tss_segment_32_t;

/*
 * Based on data from Intel Manual 3a, Intel 64 and IA-32 Architectures Software
 * Developer’s Manual Volume 3A: System Programming Guide, Part 1, Section 7.6
 */
typedef struct tss_segment_16 {
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
} tss_segment_16_t;

#endif
