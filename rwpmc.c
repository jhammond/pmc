#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <getopt.h>
#include <sys/mman.h>
#include <sys/types.h>
#include "msrs.h"

#define READ 0
#define WRITE 1

#define ERROR(fmt, args...) \
  fprintf(stderr, "%s: " fmt, program_invocation_short_name, ##args)

#define FATAL(fmt, args...) do {					\
    ERROR(fmt, ##args);							\
    exit(1);								\
  } while (0)


#ifdef DEBUG
#define TRACE ERROR
#else
#define TRACE(fmt, args...) ((void) 0)
#endif

typedef uint32_t msr_t;
typedef uint64_t val_t; 

#define PRI_MSR "0x%08X"

static int lastcpu(void) /* Don't have sched_getcpu(). */
{
  int cpu = -1;
  const char *path = "/proc/self/stat";

  FILE *file = fopen(path, "r");
  if (file == NULL) {
    ERROR("cannot open `%s': %m\n", path);
    goto out;
  }

  if (fscanf(file,
	     "%*d %*s %*c "
	     "%*d %*d %*d %*d %*d %*d %*d %*d %*d %*d "
	     "%*d %*d %*d %*d %*d %*d %*d %*d %*d %*d "
	     "%*d %*d %*d %*d %*d %*d %*d %*d %*d %*d "
	     "%*d %*d %*d %*d %*d %*d %d", &cpu) != 1)
    cpu = -1;

 out:
  if (file != NULL)
    fclose(file);

  TRACE("cpu %d\n", cpu);

  if (cpu < 0)
    errno = ENOENT;

  return cpu;
}

int raw_output = 0;
int base = 0;

const struct msr_table_ent {
  const char *m_name;
  msr_t m_msr;
} msr_table[] = {
#include "msr_table.def"
};

int msr_search_cmp(const void *v_key, const void *v_ent)
{
  const char *key = v_key;
  const struct msr_table_ent *ent = v_ent;
  return strcasecmp(key, ent->m_name);
}

int parse_msr(msr_t *msr, const char *str, char **end)
{
  if (isalpha(*str)) {
    char *key;
    struct msr_table_ent *mte;

    *end = (char *) str;
    while (isalnum(**end) || **end == '_')
      (*end)++;

    key = strndup(str, *end - str);
    TRACE("key `%s'\n", key);

    mte = bsearch(key, msr_table, sizeof(msr_table) / sizeof(msr_table[0]), 
		  sizeof(msr_table[0]), &msr_search_cmp);
    free(key);

    if (mte != NULL) {
      *msr = mte->m_msr;
      return 0;
    }
  }

  errno = 0;
  *msr = strtoul(str, end, base);
  if (errno != 0 || *end == str)
    return -1;

  return 0;
}

int read_msr_range(int fd, msr_t msr0, msr_t msr1)
{
  size_t nr_vals, i;
  ssize_t rc;
  val_t *val_buf;

  if (msr1 <= msr0)
    return 0;

  nr_vals = msr1 - msr0;
  val_buf = malloc(nr_vals * sizeof(val_t));
  if (val_buf == NULL)
    FATAL("out of memory\n");

  rc = pread(fd, val_buf, nr_vals * sizeof(val_t), msr0 * sizeof(val_t));
  if (rc < 0) {
    ERROR("error reading MSR range "PRI_MSR" to "PRI_MSR": %m\n",
	  msr0, msr1);
    goto out;
  } else if (rc < nr_vals * sizeof(val_t)) {
    ERROR("short read on MSR range "PRI_MSR" to "PRI_MSR", rc %zd\n",
	  msr0, msr1, rc);
    rc = -1;
    goto out;
  } else {
    TRACE("read "PRI_MSR" to "PRI_MSR": Success\n", msr0, msr1);
  }

  if (raw_output) {
    write(1, val_buf, nr_vals * sizeof(val_t));
  } else {
    for (i = 0; i < nr_vals; i++) {
      if (base == 16)
	printf("%016llx\n", (unsigned long long) val_buf[i]);
      else
	printf("%016lld\n", (unsigned long long) val_buf[i]);
    }
  }

 out:
  free(val_buf);

  return rc;
}

int write_msr_range(int fd, msr_t msr0, msr_t msr1, val_t val)
{
  size_t nr_vals, i;
  ssize_t rc;
  val_t *val_buf;

  if (msr1 <= msr0)
    return 0;

  nr_vals = msr1 - msr0;
  val_buf = malloc(nr_vals * sizeof(val_t));
  if (val_buf == NULL)
    FATAL("out of memory\n");

  for (i = 0; i < nr_vals; i++)
    val_buf[i] = val;

  rc = pwrite(fd, val_buf, nr_vals * sizeof(val_t), msr0 * sizeof(val_t));
  if (rc < 0) {
    ERROR("error writing MSR range "PRI_MSR" to "PRI_MSR": %m\n",
	  msr0, msr1);
  } else if (rc < nr_vals * sizeof(val_t)) {
    ERROR("short write on MSR range "PRI_MSR" to "PRI_MSR", rc %zd\n",
	  msr0, msr1, rc);
    rc = -1;
  } else {
    TRACE("write "PRI_MSR" to "PRI_MSR", val 0x%016llx: Success\n",
	  msr0, msr1, (unsigned long long) val);
  }

  free(val_buf);

  return rc;
}

int write_msr_spec(int fd, const char *spec)
{
  int rc = 0;
  char *cpy, *str, *end, *val_str;
  msr_t msr0, msr1;
  val_t val;

  cpy = val_str = strdup(spec);
  str = strsep(&val_str, ":");
  if (str == NULL || val_str == NULL)
    goto err;

  errno = 0;
  val = strtoull(val_str, &end, base);
  if (errno != 0 || end == val_str)
    goto err;

  while (*str != 0) {
    while (*str == ',')
      str++;

    if (parse_msr(&msr0, str, &end) < 0)
      goto err;

    if (str == end)
      break;

    if (strncmp(end, "..", 2) == 0) {
      str = end + 2;
      if (parse_msr(&msr1, str, &end) < 0)
	goto err;
      msr1 += 1;
    } else {
      msr1 = msr0 + 1;
    }

    if (write_msr_range(fd, msr0, msr1, val) < 0)
      return -1;

    str = end;
  }

  if (0) {
  err:
    ERROR("invalid MSR write spec `%s'\n", spec);
    rc = -1;
  }

  free(cpy);
  return rc;
}

int read_msr_spec(int fd, const char *spec)
{
  int rc = 0;
  char *str, *end;
  msr_t msr0, msr1;

  str = strdup(spec);

  while (*str != 0) {
    while (*str == ',')
      str++;

    if (parse_msr(&msr0, str, &end) < 0)
      goto err;

    if (str == end)
      break;

    if (strncmp(end, "..", 2) == 0) {
      str = end + 2;
      if (parse_msr(&msr1, str, &end) < 0)
	goto err;
    } else {
      msr1 = msr0 + 1;
    }

    if (read_msr_range(fd, msr0, msr1) < 0)
      return -1;

    str = end;
  }

  if (0) {
  err:
    ERROR("invalid MSR read spec `%s'\n", spec);
    rc = -1;
  }

  return rc;
}

void usage(int status)
{
  fprintf(status == 0 ? stdout : stderr,
	  "Usage: %s [OPTIONS]... DIR MSR[:VAL]...\n"
	  "Read and write performance MSR using /dev/pmcN.\n\n"
	  " DIR one of [rRwW] to read or write memory\n"
	  " MSR the MSR to access.\n"
	  " VAL the value to write.\n\n"
	  "OPTIONS: \n"
	  " -b, --base=NUM   use base-NUM for args, output\n"
	  " -c, --cpu=CPU    access MSRs on CPU (default current)\n"
	  " -p, --path=PATH  use PATH instead on /dev/pmcN\n"
	  " -r, --raw        write binary output\n",
	  program_invocation_short_name);
  exit(status);
}

int main(int argc, char* argv[])
{
  int rc = 0;
  int cpu = -1;
  const char *path = NULL;
  char path_buf[80];

  struct option opts[] = {
    { "base", 1, NULL, 'b' },
    { "cpu", 1, NULL, 'c' },
    { "help", 0, NULL, 'h' },
    { "path", 1, NULL, 'p' },
    { "raw", 0, NULL, 'r' },
    { NULL,    0, NULL,  0  },
  };

  int c;
  while ((c = getopt_long(argc, argv, "b:c:hp:r", opts, 0)) != -1) {
    switch (c) {
    case 'b':
      base = atoi(optarg);
      break;
    case 'c':
      cpu = atoi(optarg);
      break;
    case 'h':
      usage(0);
      break;
    case 'p':
      path = optarg;
      break;
    case 'r':
      raw_output = 1;
      break;
    }
  }

  if (argc - optind < 1)
    usage(1);

  int dir = (tolower(argv[optind][0]) == 'r') ? READ : WRITE;

  if (path == NULL) {
    if (cpu < 0)
      cpu = lastcpu();

    if (cpu < 0)
      FATAL("cannot get cpu: %m\n");

    snprintf(path_buf, sizeof(path_buf), "/dev/pmc%d", cpu);
    path = path_buf;
  }

  int fd = open(path, dir == READ ? O_RDONLY : O_WRONLY);
  if (fd < 0)
    FATAL("cannot open `%s': %m\n", path);

  int i;
  for (i = optind + 1; i < argc && rc == 0; i++) {
    if (dir == READ)
      rc = read_msr_spec(fd, argv[i]);
    else
      rc = write_msr_spec(fd, argv[i]);
  }

  close(fd);

  return rc == 0 ? 0 : 1;
}
