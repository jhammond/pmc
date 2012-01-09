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
/* #include <linux/poll.h> */
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/smp.h>
#include <linux/smp_lock.h>
#include <linux/major.h>
#include <linux/device.h>
#include <linux/cpu.h>
#include <linux/notifier.h>
#include <linux/list.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/uaccess.h>
#include <asm/system.h>

#define PMC_MAJOR 0
#define PMC_DEVICE_NAME "pmc"
#define MODULE_NAME "pmc"

typedef u32 msr_t;
typedef u64 val_t;
#define NR_VALS_PER_BUF (PAGE_SIZE / sizeof(val_t))

/* XXX Entries must be sorted. */
/* TODO Quiet mode, automatically clear bad bits. */

struct pmc_access_policy_entry {
  msr_t ae_begin, ae_end;
  val_t ae_wr_mask;
};

struct pmc_access_policy {
  const struct pmc_access_policy_entry *ap_entries;
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

struct pmc_device {
  struct cdev d_cdev;
  const struct pmc_access_policy *d_access_policy;
};

static const struct pmc_access_policy PMC_ACCESS_POLICY_NONE;

static unsigned int pmc_major;
static struct class *pmc_class;
static DEFINE_PER_CPU(struct pmc_device *, pmc_device_vec);

static void enable_cr4_pce(void)
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
  const struct pmc_access_policy *ap = ci->ci_access_policy;
  int dir = ci->ci_dir;
  val_t *val_buf = ci->ci_val_buf;
  size_t nr_vals = ci->ci_nr_vals;
  ssize_t nr = 0, err = 0;
  size_t i = 0;

  enable_cr4_pce();

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
pmc_rw(struct file *file, int dir, char __user *buf, size_t count, loff_t *pos)
{
  struct inode *inode = file->f_dentry->d_inode;
  int cpu = iminor(inode);
  struct pmc_device *pd = container_of(inode->i_cdev, struct pmc_device, d_cdev);
  val_t *val_buf = file->private_data;
  size_t nr_vals_requested = count / sizeof(val_t);
  size_t nr_vals_done = 0;
  ssize_t err = 0;

  if (count % sizeof(val_t) != 0)
    return -EINVAL; /* Better errno? */

  mutex_lock(&inode->i_mutex);

  while (nr_vals_done < nr_vals_requested) {
    struct pmc_cmd_info ci = {
      .ci_access_policy = pd->d_access_policy,
      .ci_dir = dir,
      .ci_reg = *pos / sizeof(val_t),
      .ci_val_buf = val_buf,
      .ci_nr_vals = min_t(size_t, nr_vals_requested - nr_vals_done, NR_VALS_PER_BUF),
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

#define PMC_ACCESS_POLICY(ents...) \
  ((static const struct pmc_access_policy) {				\
    .ae_entries = { ##ents },						\
      .ae_nr_entries = sizeof((struct pmc_access_policy_entry []) { ##ents }) / \
	 sizeof(((struct pmc_access_policy_entry []) { ##ents })[0])	\
	 })

static const struct pmc_access_policy *pmc_access_policy_lookup(int cpu)
{
  const struct pmc_access_policy *ap = &pmc_access_policy_none;
  struct cpuinfo_x86 *x;

  if (cpu >= NR_CPUS || !cpu_online(cpu))
    return ap;

  x = &(cpu_data)[cpu];
  if (!cpu_has(x, X86_FEATURE_MSR))
    return ap; /* MSR not supported. */

  if (x->x86_vendor == X86_VENDOR_AMD) {
    if (x->x86 == 0x10)
      /* Opteron. */
      return &PMC_ACCESS_POLICY(
	  { .ae_begin = 0xC0010000, ae_end = 0xC0010004, .ae_wr_mask = 0xFFFFFCF000380000 },
	  { .ae_begin = 0xC0010004, ae_end = 0xC0010008 });

  } else if (x->x86_vendor == X86_VENDOR_INTEL) {
  }

  return ap;
}

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
  ps->d_access_policy = pmc_device_access_policy_lookup(cpu);

  err = cdev_add(&pd->d_cdev, MKDEV(major, cpu), 1);
  if (err) {
    kfree(pd);
    return err;
  }

  dev = device_create(class, NULL /* no parent */,
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
