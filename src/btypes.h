#ifndef VTYPES_H
#define VTYPES_H

typedef long WORD;

struct __old_kernel_stat {
  unsigned short st_dev;
  unsigned short st_ino;
  unsigned short st_mode;
  unsigned short st_nlink;
  unsigned short st_uid;
  unsigned short st_gid;
  unsigned short st_rdev;
  unsigned long  st_size;
  unsigned long  st_atime;
  unsigned long  st_mtime;
  unsigned long  st_ctime;
};

typedef unsigned short umode_t;

#endif
