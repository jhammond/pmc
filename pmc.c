/*
 * pmc.c
 *
 * x86 PMC MSR access device
 *
 * This device is accessed by lseek() to the appropriate register number
 * and then read/write in chunks of 8 bytes.
 *
 * This driver uses /dev/cpu/%d/pmc where %d is the minor number, and on
 * an SMP box will direct the access to CPU %d.
 */
#include <linux/module.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/fcntl.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/smp.h>
#include <linux/smp_lock.h>
#include <linux/major.h>
#include <linux/device.h>
#include <linux/cpu.h>
#include <linux/notifier.h>
#include <linux/rbtree.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/uaccess.h>
#include <asm/system.h>

#define MODULE_NAME "pmc"
#define PMC_DEVICE_NAME "pmc"

typedef u32 msr_t;
typedef u64 val_t;
#define NR_VALS_PER_BUF (PAGE_SIZE / sizeof(val_t))

struct pmc_access_policy_entry {
  struct rb_node ae_node;
  msr_t ae_begin, ae_end;
  val_t ae_wr_mask; /* Allowed bits. */
};

struct pmc_access_policy {
  struct rb_root ap_root;
};

struct pmc_cmd_info {
  int ci_dir;
  msr_t ci_reg;
  val_t *ci_val_buf;
  size_t ci_nr_vals;
  ssize_t ci_rc;
};

struct pmc_device {
  struct cdev d_cdev;
  struct pmc_access_policy d_access_policy;
};

static int pmc_quiet = 0;
module_param_named(quiet, pmc_quiet, bool, 0644);
MODULE_PARM_DESC(quiet, "quietly mask out disallowed bits on write");

static unsigned int pmc_major;
static struct class *pmc_class;
static DEFINE_PER_CPU(struct pmc_device *, pmc_device_vec);

struct smp_cpuid_info {
  u32 reg, eax, ebx, ecx, edx;
};

static void smp_cpuid_func(void *info)
{
  struct smp_cpuid_info *ci = info;
  cpuid(ci->reg, &ci->eax, &ci->ebx, &ci->ecx, &ci->edx);
}

static inline int
smp_cpuid(int cpu, int reg, u32 *eax, u32 *ebx, u32 *ecx, u32 *edx)
{
  struct smp_cpuid_info ci = { .reg = reg };
  int err = smp_call_function_single(cpu, &smp_cpuid_func, &ci, 1, 1);
  if (err)
    return err;

  *eax = ci.eax;
  *ebx = ci.ebx;
  *ecx = ci.ecx;
  *edx = ci.edx;

  return 0;
}

static void enable_cr4_pce(void *info)
{
  unsigned long cr4 = read_cr4();
  cr4 |= X86_CR4_PCE;
  write_cr4(cr4);
}

static inline int
rw_msr_safe(int dir, msr_t reg, val_t *val)
{
  int err;
  u32 lo, hi;

  if (dir == READ) {
    err = rdmsr_safe(reg, &lo, &hi);
    if (!err)
      *val = lo | ((u64) hi << 32);
  } else {
    lo = *val;
    hi = *val >> 32;
    err = wrmsr_safe(reg, lo, hi);
  }

  if (err)
    err = -EIO;

  return err;
}

static void pmc_cmd_func(void *info)
{
  struct pmc_cmd_info *ci = info;
  int dir = ci->ci_dir;
  msr_t reg = ci->ci_reg;
  val_t *val_buf = ci->ci_val_buf;
  size_t nr_vals = ci->ci_nr_vals;
  ssize_t nr, err = 0;

  for (nr = 0; nr < nr_vals; nr++) {
    err = rw_msr_safe(dir, reg + nr, &val_buf[nr]);
    if (err)
      break;
  }

  ci->ci_rc = nr > 0 ? nr : err;
}

static int pmc_access_policy_add(struct pmc_access_policy *ap,
                                 msr_t begin, msr_t end, val_t mask)
{
  struct rb_node **link = &ap->ap_root.rb_node, *parent = NULL;
  struct pmc_access_policy_entry *ae;

  if (begin >= end)
    return 0;

  while (*link != NULL) {
    ae = rb_entry(*link, struct pmc_access_policy_entry, ae_node);
    parent = *link;

    if (begin < ae->ae_begin)
      link = &((*link)->rb_left);
    else if (begin > ae->ae_begin)
      link = &((*link)->rb_right);
    else
      return -EINVAL;
  }
  /* TODO Allow overwrite. */
  /* TODO Need to check for intersection. */
  /* TODO Merge. */
  ae = kmalloc(sizeof(*ae), GFP_KERNEL);
  if (ae == NULL)
    return -ENOMEM;

  ae->ae_begin = begin;
  ae->ae_end = end;
  ae->ae_wr_mask = mask;
  rb_link_node(&ae->ae_node, parent, link);
  rb_insert_color(&ae->ae_node, &ap->ap_root);

  return 0;
}

#define AP(b,n,m) do {                                          \
    err = pmc_access_policy_add(ap, (b), (b) + (n), (m));       \
    if (err)                                                    \
      goto out;                                                 \
  } while (0)

int amd_access_policy_init(struct pmc_access_policy *ap, int cpu, struct cpuinfo_x86 *x)
{
  int err = 0;
  unsigned int nr_ctrs = 0, nr_ext_ctrs = 0, nr_nb_ctrs = 0;
  unsigned int i;

  /* TODO What is the CPUID for the 10h counters? */

  if (x->x86 >= 0x10) /* XXX? */
    nr_ctrs = 4;

#define AMD_PERF_CTL0 0xC001000
#define AMD_PERF_CTL1 0xC001001
#define AMD_PERF_CTL2 0xC001002
#define AMD_PERF_CTL3 0xC001004
#define AMD_PERF_CTR0 0xC0010004
#define AMD_PERF_CTR1 0xC0010005
#define AMD_PERF_CTR2 0xC0010006
#define AMD_PERF_CTR3 0xC0010007
#define AMD_PERF_CTL_BITS 0x00000000FFCFFFFF

  AP(AMD_PERF_CTL0, nr_ctrs, AMD_PERF_CTL_BITS);
  AP(AMD_PERF_CTR0, nr_ctrs, -1);

  /* For the Opteron Interlagos systems (and later?), there are six
     performance monitor control MSRs for each core

     MSRC001_020[A,8,6,4,2,0] Performance Event Select (PERF_CTL[5:0])

     With six corresponding performance monitor count MSRs for each core

     MSRC001_020[B,9,7,5,3,1] Performance Event Counter (PERF_CTR[5:0])

     Note that these are interleaved in MSR address instead of
     contiguous as in the earlier Opterons.

     It looks like we should use the same mask on the user's request
     as on the earlier Opterons.

     Support for the core performance counters PerfCtr4-5 is indicated
     by CPUID Fn8000_0001_ECX[PerfCtrExtCore] = 1.

     CPUID Fn8000_0001_ECX[PerfCtrExtNB] = 1 indicates support for the
     four architecturally defined northbridge performance counters.

     TODO Bits PerfCtrExtCore and PerfCtrExtNB are not in my copy of
     the CPUID manual. */

  if (x->x86 == 0x15) { /* ??? */
    nr_ext_ctrs = 6;
    nr_nb_ctrs = 4;
  }

#define AMD_EXT_PERF_CTL0 0xC0010200
#define AMD_EXT_PERF_CTL1 0xC0010202
#define AMD_EXT_PERF_CTL2 0xC0010204
#define AMD_EXT_PERF_CTL3 0xC0010206
#define AMD_EXT_PERF_CTL4 0xC0010208
#define AMD_EXT_PERF_CTL5 0xC001020A

#define AMD_EXT_PERF_CTR0 0xC0010201
#define AMD_EXT_PERF_CTR1 0xC0010203
#define AMD_EXT_PERF_CTR2 0xC0010205
#define AMD_EXT_PERF_CTR3 0xC0010207
#define AMD_EXT_PERF_CTR4 0xC0010209
#define AMD_EXT_PERF_CTR5 0xC001020B

  for (i = 0; i < nr_ext_ctrs; i++) {
    AP(AMD_EXT_PERF_CTL0 + 2 * i, 1, AMD_PERF_CTL_BITS);
    AP(AMD_EXT_PERF_CTR0 + 2 * i, 1, -1);
  }

  /* The Interlagos (and later?) Opterons have separate control MSRs
     for the four Northbridge performance counters.

     MSRC001_024[6,4,2,0] Northbridge Performance Event Select (NB_PERF_CTL[3:0])

     With corresponding performance monitor count MSRs

     MSRC001_024[7,5,3,1] Northbridge Performance Event Counter (NB_PERF_CTR[3:0])

     The bit fields are slightly different for the NB performance
     monitor control MSRs, with the following reserved bit fields

     63:36, 31:23, 21, 20 (int), 19:16 */

#define AMD_NB_PERF_CTL0 0xC0010240
#define AMD_NB_PERF_CTL1 0xC0010242
#define AMD_NB_PERF_CTL2 0xC0010244
#define AMD_NB_PERF_CTL3 0xC0010246

#define AMD_NB_PERF_CTR0 0xC0010241
#define AMD_NB_PERF_CTR1 0xC0010243
#define AMD_NB_PERF_CTR2 0xC0010245
#define AMD_NB_PERF_CTR3 0xC0010247

#define AMD_NB_PERF_CTL_BITS 0x0000000F0040FFFF

  for (i = 0; i < nr_nb_ctrs; i++) {
    AP(AMD_NB_PERF_CTL0 + 2 * i, 1, AMD_NB_PERF_CTL_BITS);
    AP(AMD_NB_PERF_CTR0 + 2 * i, 1, -1);
  }

 out:
  return err;
}

int
intel_access_policy_init(struct pmc_access_policy *ap, int cpu, struct cpuinfo_x86 *x)
{
  int err, ver;
  unsigned int i, nr_ctrs, nr_fixed_ctrs, fixed_ctr_width;
  unsigned int nr_uncore_ctrs, uncore_ctr_width;
  val_t fixed_ctr_ctrl_bits, global_bits;
  u32 eax, ebx, ecx, edx;

  err = smp_cpuid(cpu, 0x0A, &eax, &ebx, &ecx, &edx);
  if (err)
    goto out;

  ver = eax & 0xFF;
  if (ver < 1)
    goto out;

  /* IA32_PMCx MSRs start at address 0C1H and occupy a contiguous
     block of MSR address space; the number of MSRs per logical
     processor is reported using CPUID.0AH:EAX[15:8]. IA32_PERFEVTSELx
     MSRs start at address 186H and occupy a contiguous block of MSR
     address space. Each performance event select register is paired
     with a corresponding performance counter in the 0C1H address
     block.
  */

#define IA32_PMC0 0x0C1
#define IA32_PMC1 0x0C2
#define IA32_PMC2 0x0C3
#define IA32_PMC3 0x0C4
#define IA32_PMC4 0x0C5
#define IA32_PMC5 0x0C6
#define IA32_PMC6 0x0C7
#define IA32_PMC7 0x0C8

#define IA32_PERFEVTSEL0 0x186
#define IA32_PERFEVTSEL1 0x187
#define IA32_PERFEVTSEL2 0x188
#define IA32_PERFEVTSEL3 0x189
#define IA32_PERFEVTSEL4 0x18A
#define IA32_PERFEVTSEL5 0x18B
#define IA32_PERFEVTSEL6 0x18C
#define IA32_PERFEVTSEL7 0x18D

#define IA32_FIXED_CTR0 0x309 /* Instr_Retired.Any, CPUID.0AH: EDX[4:0] > 0 */
#define IA32_FIXED_CTR1 0x30A /* CPU_CLK_Unhalted.Core, CPUID.0AH: EDX[4:0] > 1 */
#define IA32_FIXED_CTR2 0x30B /* CPU_CLK_Unhalted.Ref, CPUID.0AH: EDX[4:0] > 2 */
#define IA32_FIXED_CTR_CTRL 0x38D /* CPUID.0AH: EAX[7:0] > 1 */
#define IA32_PERF_GLOBAL_STATUS 0x38E
#define IA32_PERF_GLOBAL_CTRL 0x38F
#define IA32_PERF_GLOBAL_OVF_CTRL 0x390

  /* TODO Version 3 adds ANY (21) bit to ESR. */
#define IA32_PERFEVTSEL_BITS 0x00000000FFCFFFFF /* CHECKME */

  nr_ctrs = (eax >> 8) & 0xFF;
  AP(IA32_PMC0, nr_ctrs, -1);
  AP(IA32_PERFEVTSEL0, nr_ctrs, IA32_PERFEVTSEL_BITS);

  if (ver < 2)
    goto out;

  nr_fixed_ctrs = edx & 0x1F;
  fixed_ctr_width = (edx >> 5) & 0xFF;
  AP(IA32_FIXED_CTR0, nr_fixed_ctrs, (1UL << fixed_ctr_width) - 1);

  /* TODO Version 3 adds ANY bits to FIXED_CTR_CTRL. */
  fixed_ctr_ctrl_bits = 0;
  for (i = 0; i < nr_fixed_ctrs; i++)
    fixed_ctr_ctrl_bits |= 0x3 << (4 * i);

  AP(IA32_FIXED_CTR_CTRL, 1, fixed_ctr_ctrl_bits);

  global_bits = 0;
  for (i = 0; i < nr_ctrs; i++)
    global_bits |= 1 << i;
  for (i = 0; i < nr_fixed_ctrs; i++)
    global_bits |= 1 << (32 + i);

  AP(IA32_PERF_GLOBAL_CTRL, 1, global_bits);
  AP(IA32_PERF_GLOBAL_STATUS, 1, 1UL << 63); /* CHG */
  AP(IA32_PERF_GLOBAL_OVF_CTRL, 1, global_bits | (1UL << 63));

  if (ver < 3)
    goto out;

  /* Test for uncore counters.  In the Intel Xeon Processors 5500 and
     3400 Series.  These also apply to Core i7 and i5 processor family
     CPUID signature of 06_1AH, 06_1EH and 06_1FH. */
  /* Also 2C. */

  if (x->x86 != 6)
    goto out;

  switch (x->x86_model) {
  default:
    goto out;
  case 0x1A:
  case 0x1E:
  case 0x1F:
  case 0x2C: /* CHECKME. */
    nr_uncore_ctrs = 8;
    uncore_ctr_width = 48;
    break;
  }

  /* Stupid intel keeps changing the section numbers of 3B.  See the
     section called "Uncore Performance Monitoring Management
     Facility." */

  /* Uncore PMCs start at 0x3B0 and are contiguous. */
#define MSR_UNCORE_PERF_GLOBAL_CTRL     0x391
#define MSR_UNCORE_PERF_GLOBAL_STATUS   0x392 /* Overflow bits for PC{0..7}, FC0, PMI, CHG. */
#define MSR_UNCORE_PERF_GLOBAL_OVF_CTRL 0x393 /* Write to clear status bits. */
#define MSR_UNCORE_FIXED_CTR0           0x394 /* Uncore clock. */
#define MSR_UNCORE_FIXED_CTR_CTRL       0x395
#define MSR_UNCORE_ADDR_OPCODE_MATCH    0x396

#define MSR_UNCORE_PMC0 0x3B0
#define MSR_UNCORE_PMC1 0x3B1
#define MSR_UNCORE_PMC2 0x3B2
#define MSR_UNCORE_PMC3 0x3B3
#define MSR_UNCORE_PMC4 0x3B4
#define MSR_UNCORE_PMC5 0x3B5
#define MSR_UNCORE_PMC6 0x3B6
#define MSR_UNCORE_PMC7 0x3B7

#define MSR_UNCORE_PERFEVTSEL0 0x3C0
#define MSR_UNCORE_PERFEVTSEL1 0x3C1
#define MSR_UNCORE_PERFEVTSEL2 0x3C2
#define MSR_UNCORE_PERFEVTSEL3 0x3C3
#define MSR_UNCORE_PERFEVTSEL4 0x3C4
#define MSR_UNCORE_PERFEVTSEL5 0x3C5
#define MSR_UNCORE_PERFEVTSEL6 0x3C6
#define MSR_UNCORE_PERFEVTSEL7 0x3C7

  AP(MSR_UNCORE_PERF_GLOBAL_CTRL, 1, 0x00000001000000FF); /* EN_PC{0..7}, EN_FC0 */
  AP(MSR_UNCORE_PERF_GLOBAL_STATUS, 1, 0x8000000000000000); /* CHG */
  AP(MSR_UNCORE_PERF_GLOBAL_OVF_CTRL, 1, 0x80000001000000FF); /* CLR_OVF_{PC{0..7},_FC0,_CHG} */
  AP(MSR_UNCORE_FIXED_CTR_CTRL, 1, 0x1); /* EN */
  AP(MSR_UNCORE_PMC0, nr_uncore_ctrs, (1UL << uncore_ctr_width) - 1); 
  AP(MSR_UNCORE_PERFEVTSEL0, nr_uncore_ctrs, 0x00000000FFC6FFFF);

 out:
  return 0;
}

int pmc_access_policy_init(struct pmc_access_policy *ap, int cpu)
{
  struct cpuinfo_x86 *x;

  ap->ap_root = RB_ROOT;

  if (cpu >= NR_CPUS || !cpu_online(cpu))
    return -ENXIO;

  x = &(cpu_data)[cpu];
  if (!cpu_has(x, X86_FEATURE_MSR))
    return 0; /* MSR not supported. */

  if (x->x86_vendor == X86_VENDOR_AMD)
    return amd_access_policy_init(ap, cpu, x);
  else if (x->x86_vendor == X86_VENDOR_INTEL)
    return intel_access_policy_init(ap, cpu, x);
  else
    printk(KERN_WARNING"%s: cpu %d, unrecognized vendor %d\n",
	   MODULE_NAME, cpu, (int) x->x86_vendor);

  return 0;
}

static inline struct pmc_access_policy_entry *
ae_next(const struct pmc_access_policy_entry *ae)
{
  struct rb_node *node = rb_next((struct rb_node *) &ae->ae_node);

  return (node != NULL) ?
    container_of(node, struct pmc_access_policy_entry, ae_node) :
    NULL;
}

static ssize_t
pmc_access_check(const struct pmc_access_policy *ap, struct pmc_cmd_info *ci)
{
  int dir = ci->ci_dir;
  val_t *val_buf = ci->ci_val_buf;
  size_t nr_vals = ci->ci_nr_vals;
  ssize_t err = 0;

  const struct rb_node *node = ap->ap_root.rb_node;
  const struct pmc_access_policy_entry *lb = NULL, *ae;
  msr_t reg_begin, reg_end, reg, brk;

  if (nr_vals == 0)
    return 0;

  reg = reg_begin = ci->ci_reg;
  reg_end = reg_begin + nr_vals;

  while (node != NULL) {
    ae = container_of(node, const struct pmc_access_policy_entry, ae_node);

    if (ae->ae_begin <= reg_begin)
      lb = ae;

    if (ae->ae_begin < reg_begin)
      node = node->rb_right;
    else if (ae->ae_begin > reg_begin)
      node = node->rb_left;
    else
      break;
  }

  for (ae = lb; reg < reg_end && ae != NULL; ae = ae_next(ae)) {
    if (reg < ae->ae_begin)
      goto out;

    brk = min_t(msr_t, ae->ae_end, reg_end);
    if (dir == READ) {
      reg = brk;
      continue;
    }

    for (; reg < brk; reg++) {
      if (pmc_quiet) {
	val_buf[reg - reg_begin] &= ae->ae_wr_mask;
      } else if (val_buf[reg - reg_begin] & ~ae->ae_wr_mask) {
	err = -EINVAL;
	goto out;
      }
    }
  }

 out:
  if (err == 0 && reg < reg_end)
    err = -EPERM;

  if (err != 0)
    reg = reg_begin;

  ci->ci_nr_vals = reg - reg_begin;

  return err;
}

/* File operations. */

static loff_t pmc_llseek(struct file *file, loff_t offset, int whence)
{
  loff_t ret;

  if (offset % sizeof(val_t) != 0)
    return -EINVAL;

  mutex_lock(&file->f_dentry->d_inode->i_mutex);
  switch (whence) {
  case 0:
    file->f_pos = offset;
    ret = file->f_pos;
    break;
  case 1:
    file->f_pos += offset;
    ret = file->f_pos;
    break;
  default:
    ret = -EINVAL;
    break;
  }
  mutex_unlock(&file->f_dentry->d_inode->i_mutex);

  return ret;
}

static ssize_t
pmc_rw(struct file *file, int dir, char __user *buf, size_t count, loff_t *pos)
{
  struct inode *inode = file->f_dentry->d_inode;
  int cpu = iminor(inode);
  struct pmc_device *pd = container_of(inode->i_cdev, struct pmc_device, d_cdev);
  val_t *val_buf = file->private_data;
  size_t nr_requested = count / sizeof(val_t);
  size_t nr_done = 0;
  ssize_t err = 0;

  if (count % sizeof(val_t) != 0)
    return -EINVAL; /* Better errno? */

  mutex_lock(&inode->i_mutex);

  while (nr_done < nr_requested) {
    struct pmc_cmd_info ci = {
      .ci_dir = dir,
      .ci_reg = *pos / sizeof(val_t),
      .ci_val_buf = val_buf,
      .ci_nr_vals = min_t(size_t, nr_requested - nr_done, NR_VALS_PER_BUF),
    };

    if (dir == WRITE &&
        copy_from_user(ci.ci_val_buf,
                       buf + nr_done * sizeof(val_t),
                       ci.ci_nr_vals * sizeof(val_t))) {
      err = -EFAULT;
      break;
    }

    err = pmc_access_check(&pd->d_access_policy, &ci);
    if (err)
      break;

    err = smp_call_function_single(cpu, &pmc_cmd_func, &ci, 1, 1);
    if (err)
      break;

    if (ci.ci_rc <= 0) {
      err = ci.ci_rc;
      break;
    }

    if (dir == READ &&
        copy_to_user(buf + nr_done * sizeof(val_t),
                     val_buf, ci.ci_rc * sizeof(val_t))) {
      err = -EFAULT;
      break;
    }

    nr_done += ci.ci_rc;
    *pos += ci.ci_rc * sizeof(val_t);
  }

  mutex_unlock(&inode->i_mutex);

  return nr_done > 0 ? nr_done * sizeof(val_t) : err;
}

static ssize_t
pmc_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
  return pmc_rw(file, READ, buf, count, pos);
}

static ssize_t
pmc_write(struct file *file, const char __user *buf, size_t count, loff_t *pos)
{
  return pmc_rw(file, WRITE, (char __user *) buf, count, pos);
}

static int pmc_open(struct inode *inode, struct file *file)
{
  unsigned int cpu = iminor(file->f_dentry->d_inode);
  val_t *val_buf = NULL;

  if (cpu >= NR_CPUS || !cpu_online(cpu))
    return -ENXIO; /* No such CPU. */

  if (per_cpu(pmc_device_vec, cpu) == NULL)
    return -ENXIO;

  val_buf = kmalloc(NR_VALS_PER_BUF * sizeof(val_t), GFP_KERNEL);
  if (val_buf == NULL)
    return -ENOMEM;

  file->private_data = val_buf;

  /* XXX AMD and Intel or just AMD? */
  /* Enable rdpmc on cpu. */
  smp_call_function_single(cpu, &enable_cr4_pce, NULL, 1, 1);

  return 0;
}

static int pmc_release(struct inode *inode, struct file *file)
{
  kfree(file->private_data);
  return 0;
}

static struct file_operations pmc_file_operations = {
  .owner = THIS_MODULE,
  .llseek = &pmc_llseek,
  .read = &pmc_read,
  .write = &pmc_write,
  .open = &pmc_open,
  .release = &pmc_release,
};

static int pmc_device_create(struct class *class, int major, int cpu)
{
  struct pmc_device *pd;
  int err;
  struct device *dev;

  pd = kzalloc(sizeof(*pd), GFP_KERNEL);
  if (pd == NULL)
    return -ENOMEM;

  cdev_init(&pd->d_cdev, &pmc_file_operations);
  pd->d_cdev.owner = THIS_MODULE;
  err = pmc_access_policy_init(&pd->d_access_policy, cpu);
  if (err) {
    kfree(pd);
    return err;
  }

  err = cdev_add(&pd->d_cdev, MKDEV(major, cpu), 1);
  if (err) {
    kfree(pd);
    return err;
  }

  dev = device_create(class, NULL /* parent */,
		      MKDEV(major, cpu), "%s%d", PMC_DEVICE_NAME, cpu);
  if (IS_ERR(dev)) {
    err = PTR_ERR(dev);
    cdev_del(&pd->d_cdev);
    kfree(pd);
    return err;
  }

  per_cpu(pmc_device_vec, cpu) = pd;

  return 0;
}

void pmc_device_destroy(struct class *class, int major, int cpu)
{
  struct pmc_device *pd = per_cpu(pmc_device_vec, cpu);

  if (pd == NULL)
    return;

  device_destroy(class, pd->d_cdev.dev);
  cdev_del(&pd->d_cdev);
  kfree(pd);

  per_cpu(pmc_device_vec, cpu) = NULL;
}

#ifdef CONFIG_HOTPLUG_CPU
static int pmc_class_cpu_callback(struct notifier_block *nb,
                                  unsigned long action, void *data)
{
  unsigned int cpu = (unsigned long) data;

  switch (action) {
  case CPU_ONLINE:
    pmc_device_create(pmc_class, pmc_major, cpu);
    break;
  case CPU_DEAD:
    pmc_device_destroy(pmc_class, pmc_major, cpu);
    break;
  }

  return NOTIFY_OK;
}

static struct notifier_block __cpuinitdata pmc_class_cpu_notifier =
{
  .notifier_call = pmc_class_cpu_callback,
};
#endif

static void pmc_cleanup(void)
{
  int cpu;

  unregister_hotcpu_notifier(&pmc_class_cpu_notifier);

  if (pmc_major != 0 && pmc_class != NULL)
    for_each_online_cpu(cpu)
      pmc_device_destroy(pmc_class, pmc_major, cpu);

  if (pmc_class != NULL)
    class_destroy(pmc_class);

  if (pmc_major != 0)
    unregister_chrdev_region(MKDEV(pmc_major, 0), num_possible_cpus());
}

static int __init pmc_init(void)
{
  int err, cpu, nr_cpus = num_possible_cpus();
  dev_t dev;

  err = alloc_chrdev_region(&dev, 0, nr_cpus, PMC_DEVICE_NAME);
  if (err < 0) {
    printk(KERN_ERR "%s: cannot allocate char device region: %d\n",
	   MODULE_NAME, err);
    goto fail;
  }

  pmc_major = MAJOR(dev);

  pmc_class = class_create(THIS_MODULE, PMC_DEVICE_NAME);
  if (IS_ERR(pmc_class)) {
    printk(KERN_ERR "%s: cannot create device class: %d\n",
	   MODULE_NAME, err);
    err = PTR_ERR(pmc_class);
    goto fail;
  }

  for_each_online_cpu(cpu) {
    err = pmc_device_create(pmc_class, pmc_major, cpu);
    if (err != 0)
      goto fail;
  }

  register_hotcpu_notifier(&pmc_class_cpu_notifier);

  return 0;

 fail:
  pmc_cleanup();
  return err;
}

static void __exit pmc_exit(void)
{
  pmc_cleanup();
}

module_init(pmc_init);
module_exit(pmc_exit)

MODULE_AUTHOR("John L. Hammond <jhammond@tacc.utexas.edu>");
MODULE_DESCRIPTION("x86 generic PMC driver");
MODULE_LICENSE("GPL");
