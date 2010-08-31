/*
 * Kernel Virtual Machine (ala Linux KVM) pseudo-device.
 * Provides access to hardware accelerated virtual CPUs.
 *
 * Copyright (c) 2010 Joyent Inc., All Rights Reserved.
 *
 */

#include <sys/devops.h>  /* used by dev_ops */
#include <sys/conf.h>    /* used by dev_ops and cb_ops */
#include <sys/modctl.h>  /* used by modlinkage, modldrv, _init, _info, and _fini */
#include <sys/types.h>   /* used by open, close, read, write, prop_op, and ddi_prop_op */
#include <sys/file.h>    /* used by open, close */
#include <sys/errno.h>   /* used by open, close, read, write */
#include <sys/open.h>    /* used by open, close, read, write */
#include <sys/cred.h>    /* used by open, close, read */
#include <sys/uio.h>     /* used by read */
#include <sys/stat.h>    /* defines S_IFCHR used by ddi_create_minor_node */
#include <sys/cmn_err.h> /* used by all entry points for this driver */
#include <sys/ddi.h>     /* used by all entry points for this driver */
#include <sys/sunddi.h>  /* used by all entry points for this driver */

#include "kvm.h"

static int kvm_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int kvm_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int kvm_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **resultp);
static int kvm_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
  int flags, char *name, caddr_t valuep, int *lengthp);
static int kvm_open(dev_t *devp, int flag, int otyp, cred_t *cred);
static int kvm_close(dev_t dev, int flag, int otyp, cred_t *cred);
static int kvm_read(dev_t dev, struct uio *uiop, cred_t *credp);
static int kvm_write(dev_t dev, struct uio *uiop, cred_t *credp);

/* cb_ops structure */
static struct cb_ops kvm_cb_ops = {
  kvm_open,
  kvm_close,
  nodev,              /* no strategy - nodev returns ENXIO */
  nodev,              /* no print */
  nodev,              /* no dump */
  kvm_read,
  kvm_write,
  nodev,              /* no ioctl */
  nodev,              /* no devmap */
  nodev,              /* no mmap */
  nodev,              /* no segmap */
  nochpoll,           /* returns ENXIO for non-pollable devices */
  kvm_prop_op,
  NULL,               /* streamtab struct; if not NULL, all above fields are ignored */
  D_NEW | D_MP,       /* compatibility flags: see conf.h */
  CB_REV,             /* cb_ops revision number */
  nodev,              /* no aread */
  nodev               /* no awrite */
};

/* dev_ops structure */
static struct dev_ops kvm_dev_ops = {
  DEVO_REV,
  0,                         /* reference count */
  kvm_getinfo,               /* getinfo(9E) */
  nulldev,                   /* no identify(9E) - nulldev returns 0 */
  nulldev,                   /* no probe(9E) */
  kvm_attach,
  kvm_detach,
  nodev,                     /* no reset - nodev returns ENXIO */
  &kvm_cb_ops,
  (struct bus_ops *)NULL,
  nodev,                     /* no power(9E) */
  ddi_quiesce_not_needed,    /* no quiesce(9E) */
};

/* modldrv structure */
static struct modldrv md = {
  &mod_driverops,     /* Type of module. This is a driver. */
  "kvm driver",       /* Name of the module. */
  &kvm_dev_ops
};

/* modlinkage structure */
static struct modlinkage ml = {
  MODREV_1,
  &md,
  NULL
};

/* dev_info structure */
dev_info_t *kvm_dip;  /* keep track of one instance */


/* Loadable module configuration entry points */
int
_init(void)
{
  cmn_err(CE_NOTE, "Inside _init");
  return(mod_install(&ml));
}


int
_info(struct modinfo *modinfop)
{
  cmn_err(CE_NOTE, "Inside _info");
  return(mod_info(&ml, modinfop));
}


int
_fini(void)
{
  cmn_err(CE_NOTE, "Inside _fini");
  return(mod_remove(&ml));
}


/* Device configuration entry points */
static int
kvm_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
  cmn_err(CE_NOTE, "Inside kvm_attach");
  switch(cmd) {
    case DDI_ATTACH:
      kvm_dip = dip;
      if (ddi_create_minor_node(dip, "0", S_IFCHR, ddi_get_instance(dip), DDI_PSEUDO,0) != DDI_SUCCESS) {
          cmn_err(CE_NOTE, "%s%d: attach: could not add character node.", "kvm", 0);
          return(DDI_FAILURE);
      } else
          return DDI_SUCCESS;
    default:
      return DDI_FAILURE;
  }
}


static int
kvm_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
  cmn_err(CE_NOTE, "Inside kvm_detach");
  switch(cmd) {
    case DDI_DETACH:
      kvm_dip = 0;
      ddi_remove_minor_node(dip, NULL);
      return DDI_SUCCESS;
    default:
      return DDI_FAILURE;
  }
}


static int
kvm_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **resultp)
{
  cmn_err(CE_NOTE, "Inside kvm_getinfo");
  switch(cmd) {
    case DDI_INFO_DEVT2DEVINFO:
      *resultp = kvm_dip;
      return DDI_SUCCESS;
    case DDI_INFO_DEVT2INSTANCE:
      *resultp = 0;
      return DDI_SUCCESS;
    default:
      return DDI_FAILURE;
  }
}


/* Main entry points */
static int
kvm_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
    int flags, char *name, caddr_t valuep, int *lengthp)
{
  cmn_err(CE_NOTE, "Inside kvm_prop_op");
  return(ddi_prop_op(dev,dip,prop_op,flags,name,valuep,lengthp));
}


static int
kvm_open(dev_t *devp, int flag, int otyp, cred_t *cred)
{
  cmn_err(CE_NOTE, "Inside kvm_open");
  return DDI_SUCCESS;
}


static int
kvm_close(dev_t dev, int flag, int otyp, cred_t *cred)
{
  cmn_err(CE_NOTE, "Inside kvm_close");
  return DDI_SUCCESS;
}


static int
kvm_read(dev_t dev, struct uio *uiop, cred_t *credp)
{
  cmn_err(CE_NOTE, "Inside kvm_read");
  return DDI_SUCCESS;
}


static int
kvm_write(dev_t dev, struct uio *uiop, cred_t *credp)
{
  cmn_err(CE_NOTE, "Inside kvm_write");
  return DDI_SUCCESS;
}
