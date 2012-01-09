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
#include <linux/poll.h>
#include <linux/smp.h>
#include <linux/smp_lock.h>
#include <linux/major.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cpu.h>
#include <linux/notifier.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/uaccess.h>
#include <asm/system.h>

#define PMC_MAJOR 0
typedef u32 msr_t;
typedef u64 val_t;
#define NR_VALS_PER_BUF (PAGE_SIZE / sizeof(val_t))

/* XXX Entries must be sorted. */
/* TODO Quiet mode, automatically clear bad bits. */

static struct class *pmc_class;

static inline int
rw_msr_safe(int dir, msr_t reg, val_t *val)
{
  int err;
  u32 lo, hi;

  if (dir == READ) {
    err = rdmsr_safe(reg, lo, hi);
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

struct pmc_access_policy_entry {
  msr_t ae_begin, ae_end;
  val_t ae_wr_mask;
};

struct pmc_access_policy {
  struct pmc_access_policy_entry *ap_entries;
  size_t ap_nr_entries;
};

struct pmc_cmd_info {
  const struct pmc_access_policy *ci_access_policy;
  int ci_dir;
  msr_t ci_reg;
  val_t *ci_val_buf;
  size_t ci_nr_vals;
  ssize_t ci_rc;
};

struct pmc_dev {
  struct cdev pd_cdev;
  struct pmc_access_policy *pd_access_policy;
};

static void enable_cr4_pce_func(void *ignored)
{
  unsigned long cr4 = read_cr4();
  cr4 |= X86_CR4_PCE;
  write_cr4(cr4);
}

static void pmc_cmd_func(void *info)
{
  struct pmc_cmd_info *ci = info;
  const struct pmc_access_policy *ap = ci->ci_access_policy;
  int dir = ci->ci_dir;
  val_t *val_buf = ci->ci_val_buf;
  size_t nr_vals = ci->ci_nr_vals;
  ssize_t nr = 0, err = 0;
  size_t i = 0;

  while (nr < nr_vals && i < ap->ap_nr_entries) {
    const struct pmc_access_policy_entry *ae = &ap->ap_entries[i];
    msr_t reg = ci->ci_reg + nr;

    if (reg < ae->ae_begin)
      break;

    if (!(reg < ae->ae_end)) {
      i++;
      continue; /* Try next entry. */
    }

    if (dir == WRITE && (val_buf[nr] & ae->ae_wr_mask)) {
      err = -EINVAL;
      break;
    }

    err = rw_msr_safe(dir, reg, &val_buf[nr]);
    if (err)
      break;

    nr++;
  }

  if (nr == 0 && nr_vals > 0)
    /* Reached end of policy entry list without a match. */
    err = -EPERM;

  ci->ci_rc = nr > 0 ? nr : err;
}

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
pmc_transfer(struct file *file, int dir, char __user *buf, size_t count, loff_t *pos)
{
  struct inode *inode = file->f_dentry->d_inode;
  int cpu = iminor(inode);
  struct pmc_dev *dev = container_of(inode->i_cdev, struct pmc_dev, pd_cdev);
  val_t *val_buf = file->private_data;
  size_t nr_vals_requested = count / sizeof(val_t);
  size_t nr_vals_done = 0;
  ssize_t err = 0;

  if (count % sizeof(val_t) != 0)
    return -EINVAL; /* Better errno? */

  mutex_lock(&inode->i_mutex);

  while (nr_vals_done < nr_vals_requested) {
    struct pmc_cmd_info ci = {
      .ci_access_policy = dev->pd_access_policy,
      .ci_dir = dir,
      .ci_reg = *pos / sizeof(val_t),
      .ci_val_buf = val_buf,
      .ci_nr_vals = MIN(nr_vals_requested - nr_vals_done, NR_VALS_PER_BUF),
    };

    if (dir == WRITE &&
        copy_from_user(val_buf, buf + nr_vals_done * sizeof(val_t),
                       ci.ci_nr_vals)) {
      err = -EFAULT;
      break;
    }

    err = smp_call_function_single(cpu, &pmc_cmd_func, &ci, 1, 1);
    if (err)
      break;

    if (ci.ci_rc < 0) {
      err = ci.ci_rc;
      break;
    }

    if (dir == READ &&
        copy_to_user(buf + nr_vals_done * sizeof(val_t),
                     val_buf, ci.ci_rc * sizeof(val_t))) {
      err = -EFAULT;
      break;
    }

    nr_vals_done += ci.ci_rc;
    *pos += ci.ci_rc * sizeof(val_t);
  }

  mutex_unlock(&inode->i_mutex);

  return nr_vals_done > 0 ? nr_vals_done * sizeof(val_t) : err;
}

static ssize_t
pmc_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
  return rpm_transfer(file, READ, buf, count, pos);
}

static ssize_t
pmc_write(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
  return rpm_transfer(file, WRITE, (char __user *) buf, count, pos);
}

static int pmc_open(struct inode *inode, struct file *file)
{
  unsigned int cpu = iminor(file->f_dentry->d_inode);
  struct cpuinfo_x86 *info;
  val_t *val_buf = NULL;

  /* TODO cr4. */

  if (cpu >= NR_CPUS || !cpu_online(cpu))
    return -ENXIO;	/* No such CPU */

  info = &(cpu_data)[cpu];
  if (!cpu_has(info, X86_FEATURE_MSR))
    return -EIO;	/* MSR not supported */

  val_buf = kmalloc(NR_VALS_PER_BUF * sizeof(val_t), GFP_KERNEL);
  if (val_buf == NULL)
    return -ENOMEM;

  file->private_data = val_buf;

  return 0;
}

/*
 * File operations we support
 */
static cstruct file_operations pmc_fops = {
  .owner = THIS_MODULE,
  .llseek = pmc_llseek,
  .read = pmc_read,
  .write = pmc_write,
  .open = pmc_open,
};

static int pmc_class_device_create(int cpu)
{
  int err = 0;
  struct class_device *dev;

  dev = class_device_create(pmc_class, NULL, MKDEV(PMC_MAJOR, cpu), NULL, "pmc%d", cpu);
  if (IS_ERR(dev))
    err = PTR_ERR(dev);

  return err;
}

#ifdef CONFIG_HOTPLUG_CPU
static int pmc_class_cpu_callback(struct notifier_block *nb,
                                  unsigned long action, void *data)
{
  unsigned int cpu = (unsigned long) data;

  switch (action) {
  case CPU_ONLINE:
    pmc_class_device_create(cpu);
    break;
  case CPU_DEAD:
    class_device_destroy(pmc_class, MKDEV(PMC_MAJOR, cpu));
    break;
  }

  return NOTIFY_OK;
}

static struct notifier_block __cpuinitdata pmc_class_cpu_notifier =
{
  .notifier_call = pmc_class_cpu_callback,
};
#endif

static int __init pmc_init(void)
{
  int cpu, err;

  if (register_chrdev(PMC_MAJOR, "cpu/pmc", &pmc_fops)) {
    printk(KERN_ERR "pmc: unable to get major %d for pmc\n",
           PMC_MAJOR);
    err = -EBUSY;
    goto out;
  }

  pmc_class = class_create(THIS_MODULE, "pmc");
  if (IS_ERR(pmc_class)) {
    err = PTR_ERR(pmc_class);
    goto out_chrdev;
  }

  for_each_online_cpu(cpu) {
    err = pmc_class_device_create(cpu);
    if (err != 0)
      goto out_class;
  }

  register_hotcpu_notifier(&pmc_class_cpu_notifier);

  err = 0;
  goto out;

 out_class:
  for_each_online_cpu(cpu)
    class_device_destroy(pmc_class, MKDEV(PMC_MAJOR, cpu));

  class_destroy(pmc_class);

 out_chrdev:
  unregister_chrdev(PMC_MAJOR, "cpu/pmc");

 out:
  return err;
}

static void __exit pmc_exit(void)
{
  int cpu;

  for_each_online_cpu(cpu)
    class_device_destroy(pmc_class, MKDEV(PMC_MAJOR, cpu));

  class_destroy(pmc_class);
  unregister_chrdev(PMC_MAJOR, "cpu/msr");
  unregister_hotcpu_notifier(&pmc_class_cpu_notifier);
}

module_init(pmc_init);
module_exit(pmc_exit)

MODULE_AUTHOR("John L. Hammond <jhammond@tacc.utexas.edu>");
MODULE_DESCRIPTION("x86 generic PMC driver");
MODULE_LICENSE("GPL");
