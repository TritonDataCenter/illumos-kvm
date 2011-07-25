/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2011 Joyent Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <devfsadm.h>
#include <strings.h>
#include <stdio.h>
#include <sys/dtrace.h>

static int devfs_kvm_ln(di_minor_t minor, di_node_t node);

/*
 * The amount of documentation for this format is unsurprisingly limited. There
 * is probably a better match that we could do. This is modeled off of the
 * misc_link_i386.c things that we are matching. Like xsvc and its ilk we look
 * for most ddi_psuedo devices and look for node names that are kvm.
 */
static devfsadm_create_t devfs_kvm_create_cbt[] = {
	{ "pseudo", "ddi_pseudo", NULL, TYPE_EXACT, ILEVEL_0, devfs_kvm_ln }
};

DEVFSADM_CREATE_INIT_V0(devfs_kvm_create_cbt);

static int
devfs_kvm_ln(di_minor_t minor, di_node_t node)
{
	char *mn;

	if (strcmp(di_node_name(node), "kvm") != 0)
		return (DEVFSADM_CONTINUE);

	mn = di_minor_name(minor);
	if (mn == NULL)
		return (DEVFSADM_CONTINUE);

	(void) devfsadm_mklink(mn, node, minor, 0);
	return (DEVFSADM_CONTINUE);
}
