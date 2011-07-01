#ifndef __TSS_SEGMENT_H
#define	__TSS_SEGMENT_H

typedef struct tss_segment_32 {
	uint32_t prev_task_link;
	uint32_t esp0;
	uint32_t ss0;
	uint32_t esp1;
	uint32_t ss1;
	uint32_t esp2;
	uint32_t ss2;
	uint32_t cr3;
	uint32_t eip;
	uint32_t eflags;
	uint32_t eax;
	uint32_t ecx;
	uint32_t edx;
	uint32_t ebx;
	uint32_t esp;
	uint32_t ebp;
	uint32_t esi;
	uint32_t edi;
	uint32_t es;
	uint32_t cs;
	uint32_t ss;
	uint32_t ds;
	uint32_t fs;
	uint32_t gs;
	uint32_t ldt_selector;
	uint16_t t;
	uint16_t io_map;
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
