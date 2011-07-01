#ifndef __TSS_SEGMENT_H
#define	__TSS_SEGMENT_H

typedef struct tss_segment_32 {
	uint16_t	prev_task_link;	/* 16-bit prior TSS selector */
	uint16_t	rsvd0;	/* reserved, ignored */
	uint32_t	esp0;
	uint16_t	ss0;
	uint16_t	rsvd1;	/* reserved, ignored */
	uint32_t	esp1;
	uint16_t	ss1;
	uint16_t	rsvd2;	/* reserved, ignored */
	uint32_t	esp2;
	uint16_t	ss2;
	uint16_t	rsvd3;	/* reserved, ignored */
	uint32_t	cr3;
	uint32_t	eip;
	uint32_t	eflags;
	uint32_t	eax;
	uint32_t	ecx;
	uint32_t	edx;
	uint32_t	ebx;
	uint32_t	esp;
	uint32_t	ebp;
	uint32_t	esi;
	uint32_t	edi;
	uint16_t	es;
	uint16_t	rsvd4;	/* reserved, ignored */
	uint16_t	cs;
	uint16_t	rsvd5;	/* reserved, ignored */
	uint16_t	ss;
	uint16_t	rsvd6;	/* reserved, ignored */
	uint16_t	ds;
	uint16_t	rsvd7;	/* reserved, ignored */
	uint16_t	fs;
	uint16_t	rsvd8;	/* reserved, ignored */
	uint16_t	gs;
	uint16_t	rsvd9;	/* reserved, ignored */
	uint16_t	ldt_selector;
	uint16_t	rsvd10;	/* reserved, ignored */
	uint16_t	rsvd11;	/* reserved, ignored */
	uint16_t	io_map;	/* io permission bitmap base address */
} tss_segment_32_t;

typedef struct tss_segment_16 {
	uint16_t prev_task_link;
	uint16_t sp0;
	uint16_t ss0;
	uint16_t sp1;
	uint16_t ss1;
	uint16_t sp2;
	uint16_t ss2;
	uint16_t ip;
	uint16_t flag;
	uint16_t ax;
	uint16_t cx;
	uint16_t dx;
	uint16_t bx;
	uint16_t sp;
	uint16_t bp;
	uint16_t si;
	uint16_t di;
	uint16_t es;
	uint16_t cs;
	uint16_t ss;
	uint16_t ds;
	uint16_t ldt;
} tss_segment_16_t;

#endif
