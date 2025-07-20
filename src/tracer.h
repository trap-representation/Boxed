#ifndef TRACER_H
#define TRACER_H

#include "errors.h"

struct descs_s {
  int val;
  int eval;
  char *iden;
  mode_t mode;
  size_t pos;
  struct lock_s {
    _Bool status;
    int op;
    off_t size;
    pid_t by;
  } lock;
  pid_t openedby;
};
  
enum error_e trace(pid_t tracee, _Bool is_root_proc, struct descs_s *parent_desc);

#endif
