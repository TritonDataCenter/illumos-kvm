#!/usr/sbin/dtrace -Zs

#pragma D option quiet

inline int CR0 = 0;
inline int CR3 = 3;
inline int CR4 = 4;
inline int CR8 = 8;

inline int CR_REASON_MOV_TO = 0;
inline int CR_REASON_CLTS = 2;
inline int CR_REASON_MOV_FROM = 1;
inline int CR_REASON_LMSW = 3;

inline string strcr[int32_t r] =
    r == CR0 ? "CR0" :
    r == CR3 ? "CR3" :
    r == CR4 ? "CR4" :
    r == CR8 ? "CR8" :
    "<unknown>";

inline string strcrop[int32_t r] =
    r == CR_REASON_MOV_TO ? "mov to cr" :
    r == CR_REASON_CLTS ? "clts" :
    r == CR_REASON_MOV_FROM ? "mov from cr" :
    r == CR_REASON_LMSW ? "lmsw" :
    "<unknown>";


/*
 * arg0: which cr reg
 * arg2: exit qual
 */
kvm-cr
{
	@[strcrop[arg2], strcr[arg0]] = count();
}

tick-10sec
{
	printf("%-15s %-12s %8s\n", "OPERATION", "REGISTER", "COUNT");
	printa("%15s %12s %@8d\n", @);
	printf("\n");
}

