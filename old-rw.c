#if 0
static ssize_t
pmc_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
  struct inode *inode = file->f_dentry->d_inode;
  int cpu = iminor(inode);
  struct pmc_dev *dev = container_of(inode->i_cdev, struct pmc_dev, pd_cdev);
  val_t *val_buf = file->private_data;
  size_t nr_vals_requested = count / sizeof(val_t);
  size_t nr_vals_read = 0;
  ssize_t err = 0;

  if (count % sizeof(val_t) != 0)
    return -EINVAL; /* Better errno? */

  mutex_lock(&inode->i_mutex);

  while (nr_vals_read < nr_vals_requested) {
    struct pmc_cmd_info ci = {
      .ci_access_policy = dev->pd_access_policy,
      .ci_dir = READ,
      .ci_reg = *pos / sizeof(val_t),
      .ci_val_buf = val_buf,
      .ci_nr_vals = MIN(nr_vals_requested - nr_vals_read, NR_VALS_PER_BUF),
    };

    err = smp_call_function_single(cpu, &pmc_cmd_func, &ci, 1, 1);
    if (err)
      break;

    if (ci.ci_rc < 0) {
      err = ci.ci_rc;
      break;
    }

    if (copy_to_user(buf + nr_vals_read * sizeof(val_t),
                     val_buf, ci.ci_rc * sizeof(val_t))) {
      err = -EFAULT;
      break;
    }

    nr_vals_read += ci.ci_rc;
    *pos += ci.ci_rc * sizeof(val_t);
  }

  mutex_unlock(&inode->i_mutex);

  return nr_vals_read > 0 ? nr_vals_read * sizeof(val_t) : err;
}

static ssize_t
pmc_write(struct file *file, const char __user *buf, size_t count, loff_t *pos)
{
  /* TODO Fixup cr4. */
  struct inode *inode = file->f_dentry->d_inode;
  int cpu = iminor(inode);
  struct pmc_dev *dev = container_of(inode->i_cdev, struct pmc_dev, pd_cdev);
  val_t *val_buf = file->private_data;
  size_t nr_vals_requested = count / sizeof(val_t);
  size_t nr_vals_written = 0;
  ssize_t err = 0;

  if (count % sizeof(val_t) != 0)
    return -EINVAL; /* Better errno? */

  mutex_lock(&inode->i_mutex);

  while (nr_vals_written < nr_vals_requested) {
    struct pmc_cmd_info ci = {
      .ci_access_policy = dev->pd_access_policy,
      .ci_dir = WRITE,
      .ci_reg = *pos / sizeof(val_t),
      .ci_val_buf = val_buf,
      .ci_nr_vals = MIN(nr_vals_requested - nr_vals_written, NR_VALS_PER_BUF),
    };

    if (copy_from_user(val_buf, buf + nr_vals_written * sizeof(val_t),
                       ci.ci_nr_vals)) {
      err = -EFAULT;
      break;
    }

    err = smp_call_function_single(cpu, &pmc_cmd_func, &ci, 1, 1);
    if (err)
      break;

    if (ci->ci_rc < 0) {
      err = ci->ci_rc;
      break;
    }

    nr_vals_written += ci->ci_rc;
    *pos += ci->ci_rc * sizeof(val_t);
  }

  mutex_unlock(&inode->i_mutex);

  return nr_vals_read > 0 ? nr_vals_read * sizeof(val_t) : err;
}
#endif


