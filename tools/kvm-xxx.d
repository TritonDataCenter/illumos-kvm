#!/usr/sbin/dtrace -Zs

#pragma D option quiet

kvm-xxx
{
	@[stringof(arg0), arg1] = count();
}

tick-10sec
{
	printa("%20s %8d %@8d\n", @);
}
