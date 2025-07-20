#define _GNU_SOURCE

#include "btypes.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <linux/types.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <linux/limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>

#include "tracer.h"
#include "syscalls.h"
#include "config.h"

#define IFBAD_RETURN(arg) { enum error_e _err = arg; if (_err != ERR_SUCCESS) return _err; }

#define SYSRET(arg, err) err = arg; if (err == -1) err = -errno;

struct descs_s *dp = NULL;

/* *_descs functions need to be rewritten for improved efficiency,
   but these should do it for now */

static enum error_e init_descs(struct descs_s **dsc, struct descs_s *from, pid_t tracee) {
  if ((*dsc = malloc(MAX_DESCS * sizeof(**dsc))) == NULL) {
    return ERR_MALLOC;
  }

  if (from == NULL) {
    for (size_t i = 0; i < MAX_DESCS; i++) {
      (*dsc)[i].val = -1;
      (*dsc)[i].eval = -1;
      (*dsc)[i].iden = NULL;
      (*dsc)[i].mode = 0;
      (*dsc)[i].lock = (struct lock_s) {0, 0, 0, 0};
      (*dsc)[i].openedby = tracee;
    }
  }
  else {
    memcpy(*dsc, from, MAX_DESCS * sizeof(**dsc));
  }

  return ERR_SUCCESS;
}

static ssize_t search_in_descs(int d) {
  for (size_t i = 0; i < MAX_DESCS; i++) {
    if (dp[i].val == d) {
      return d;
    }
  }

  return -1;
}

static enum error_e add_to_descs(char *name, int d, mode_t mode, int ed) {
  for (size_t i = 0; i < MAX_DESCS; i++) {
    if (dp[i].val == -1) {
      if ((dp[i].iden = malloc(strlen(name))) == NULL) {
	return ERR_MALLOC;
      }

      strncpy(dp[i].iden, name, strlen(name));
      dp[i].val = d;
      dp[i].eval = ed;
      dp[i].mode = mode;
      return ERR_SUCCESS;
    }
  }

  return ERR_FILLED_DESCS;
}

static void del_from_descs(size_t d, pid_t tracee) {
  ssize_t l = search_in_descs(d);

  if (l == -1) return;

  if (dp[l].openedby == tracee) {
    dp[l].val = -1;

    free(dp[l].iden);
    dp[l].iden = NULL;

    dp[l].mode = 0;
  }
}

static void clean_descs(pid_t tracee) {
  if (dp) {
    for (size_t i = 0; i < MAX_DESCS; i++) {
      if (dp[i].openedby == tracee) {
	close(dp[i].eval);
	free(dp[i].iden);
      }
    }
  }
}

static enum error_e wait_syscall(pid_t tracee) {
  if (ptrace(PTRACE_SYSCALL, tracee, NULL, NULL) == -1) {
    return ERR_PTRACE_SYSCALL;
  }

  int wstatus;
  if (waitpid(tracee, &wstatus, 0) == -1) {
    return ERR_WAITPID;
  }

  if (WIFEXITED(wstatus)) {
    return ERR_TERMINATED;
  }
  else if (WIFSIGNALED(wstatus)) {
    return ERR_KILLED;
  }
  else if (wstatus >> 8 == (SIGTRAP | (PTRACE_EVENT_FORK << 8))) {
    return ERR_EFORK;
  }
  else if (wstatus >> 8 == (SIGTRAP | (PTRACE_EVENT_CLONE << 8))) {
    return ERR_ECLONE;
  }
  else if (wstatus >> 8 == (SIGTRAP | (PTRACE_EVENT_VFORK << 8))) {
    return ERR_EVFORK;
  }

  return ERR_SUCCESS;
}

static enum error_e set_regs(struct user_regs_struct user_regs, pid_t tracee) {
  if (ptrace(PTRACE_SETREGS, tracee, NULL, &user_regs) == -1) {
    return ERR_PTRACE_SETREGS;
  }

  return ERR_SUCCESS;
}

static void *get_text(void *addr, size_t len, pid_t tracee) {
  char *text;
  if (len < sizeof(WORD)) {
    text = malloc(len);

    if (text == NULL) {
      return NULL;
    }

    WORD s = ptrace(PTRACE_PEEKTEXT, tracee, (char *) addr, NULL);

    if (errno) {
      return NULL;
    }

    memcpy(text, &s, len);
  }
  else {
    text = malloc(len);

    if (text == NULL) {
      return NULL;
    }

    size_t at;

    for (at = 0; at <= len - (len % sizeof(WORD)) /* align
						     backwards */
	   - sizeof(WORD) /* subtract sizeof(WORD) as we are reading
			     sizeof(WORD) bytes at a time */; at += sizeof(WORD)) {
      WORD s = ptrace(PTRACE_PEEKTEXT, tracee, (char *) addr + at, NULL);

      if (errno) {
	return NULL;
      }

      memcpy(&text[at], &s, sizeof(WORD));
    }

    size_t last = len - (len % sizeof(WORD)) - 1;

    WORD s = ptrace(PTRACE_PEEKTEXT, tracee, (char *) addr + last, NULL);

    if (errno) {
      return NULL;
    }

    memcpy(&text[last], &s, sizeof(WORD));
  }

  return text;
}

static void *get_ntext(void *addr, pid_t tracee) {
  size_t tsz = 1;

  char *text = malloc(tsz);
  
  if (text == NULL) {
    return NULL;
  }

  while (1) {
    WORD s = ptrace(PTRACE_PEEKTEXT, tracee, (char *) addr + (tsz - 1), NULL);

    if (errno) {
      return NULL;
    }

    text[tsz - 1] = *(char *) &s;

    if (*(char *) &s == '\0') return text;

    tsz++;

    if ((text = realloc(text, tsz)) == NULL) {
      return NULL;
    }
  }
}

static enum error_e write_to_tracee(void *b, size_t bsz, void *addr, pid_t tracee) {
  if (bsz < sizeof(WORD)) {
    WORD s = ptrace(PTRACE_PEEKTEXT, tracee, addr, NULL);

    if (errno) {
      return ERR_PTRACE_PEEKTEXT;
    }

    memcpy(&s, b, bsz);

    if (ptrace(PTRACE_POKETEXT, tracee, addr, (void *) s) == -1) {
      return ERR_PTRACE_POKETEXT;
    }
  }
  else {
    for (size_t i = 0; i + sizeof(WORD) <= bsz; i++) {
      /* PTRACE_POKETEXT takes the data to be poked as the "value"
	 in the pointer itself, that's why the ugly
	 casts; these are non-conforming */
      if (ptrace(PTRACE_POKETEXT, tracee, (char *) addr + i, (void *) *(WORD *) ((char *) b + i)) == -1) {
	return ERR_PTRACE_POKETEXT;
      }
    }
  }

  return ERR_SUCCESS;
}

static _Bool is_open(int fd) {
  if (search_in_descs(fd) != -1) {
    return 1;
  }

  return 0;
}

static _Bool is_dir(int dfd) {
  if (!is_open(dfd)) {
    return 0;
  }

  ssize_t dl;
  if ((dl = search_in_descs(dfd)) == -1) {
    return -1;
  }

  struct stat st;
  if (stat(dp[dl].iden, &st) == -1) {
    return -1;
  }

  if (!S_ISDIR(st.st_mode)) {
    return 0;
  }

  return 1;
}

static int get_efd(int fd) {
  int efd = search_in_descs(fd);
  if (efd == -1) {
    return -1;
  }

  return dp[efd].eval;
}

static _Bool in_sandbox(char *abspath) {
  char sbxpath[PATH_MAX + 1];

  if (realpath("sbx", sbxpath) == NULL) {
    return 0;
  }

  if (strncmp(sbxpath, abspath, strlen(sbxpath)) == 0) {
    return 1;
  }

  return 0;
}

static char *get_sbxpath(char *filename, int dfd) {
  char *floc;
  while ((floc = strrchr(filename, '/')) != NULL) {
    *floc = '\0';
    if (strlen(floc + 1) < 1) {
      continue;
    }

    break;
  }

  if (floc == NULL) floc = filename; else floc++;

  size_t pathsz = PATH_MAX + strlen("sbx") + 1;
  char *sbxpath = malloc(pathsz);

  if (sbxpath == NULL) {
    return NULL;
  }

  for (size_t i = 0; i < pathsz; i++) {
    sbxpath[i] = '\0';
  }

  if (dfd != AT_FDCWD && dfd != -1) {
    ssize_t d;
    if ((d = search_in_descs(dfd)) == -1) {
      return NULL;
    }

    char dirabspath[PATH_MAX + 1] = {0};
    strncpy(dirabspath, dp[d].iden, PATH_MAX); /* even if dp[d].iden
						  is > PATH_MAX
						  characters long,
						  dirabspath is set
						  to all 0, so
						  it will always
						  have a null term-
						  inator at the
						  end */
    strncat(dirabspath, filename, PATH_MAX - strlen(dirabspath));

    if (realpath(dirabspath, sbxpath) == NULL) {
      return NULL;
    }

    if(!in_sandbox(sbxpath)) { /* this means that the filepath
				  is trying to .. at the root
			       */
      strncpy(sbxpath, "sbx/", PATH_MAX);
    }
  }
  else {
    strncpy(sbxpath, "sbx", PATH_MAX);

    if (floc == filename) {
      filename = ".";
    }

    if (realpath(filename, &sbxpath[strlen(sbxpath)]) == NULL) {
      return NULL;
    }
  }

  strncat(sbxpath, "/", PATH_MAX - strlen(sbxpath));
  strncat(sbxpath, floc, PATH_MAX - strlen(sbxpath));

  return sbxpath;
}

static int sbx_openat(int dfd, char *filename, int flags, umode_t mode) {
  int r;
  char *sbxpath;

  if (flags & AT_EMPTY_PATH && filename[0] == '\0') {
    if (!is_open(dfd)) {
      return -EBADF;
    }

    sbxpath = dp[search_in_descs(dfd)].iden;

    SYSRET(openat(get_efd(dfd), "", flags, mode), r);
  }
  else {
    if (filename[0] != '/' && dfd != AT_FDCWD) {
      if (!is_open(dfd)) {
	return -EBADF;
      }

      if (!is_dir(dfd)) {
	return -ENOTDIR;
      }
    }

    if (filename[0] == '/') dfd = -1;

    if ((sbxpath = get_sbxpath(filename, dfd)) == NULL) {
      return -ENOMEM;
    }

    SYSRET(openat(AT_FDCWD, sbxpath, flags, mode), r);
  }

  if (add_to_descs(sbxpath, r, mode, r) != ERR_SUCCESS) {
    return -ENOMEM;
  }

  return r;
}

static int sbx_open(char *filename, int flags, umode_t mode) {
  char *sbxpath;
  if ((sbxpath = get_sbxpath(filename, -1)) == NULL) {
    return -ENOMEM;
  }

  int r;
  SYSRET(open(sbxpath, flags, mode), r);

  free(sbxpath);

  if (add_to_descs(sbxpath, r, mode, r) != ERR_SUCCESS) {
    return -ENOMEM;
  }

  return r;
}

static int sbx_read(unsigned int fd, char *buf, size_t count, pid_t tracee) {
  if (!is_open(fd)) {
    return -EBADF;
  }

  char *b = malloc(count);
  if (b == NULL) {
    return -EIO;
  }

  int r;
  SYSRET(read(get_efd(fd), b, count), r);

  if (r < 0) {
    return r;
  }

  if (write_to_tracee(b, r, buf, tracee) != ERR_SUCCESS) {
    return -EIO;
  }

  return r;
}

static int sbx_write(unsigned int fd, char *buf, size_t count, pid_t tracee) {
  if (!is_open(fd)) {
    return -1;
  }

  char *text = get_text(buf, count, tracee);

  if (text == NULL) {
    return -EIO;
  }

  int r;
  SYSRET(write(get_efd(fd), text, count), r);

  if (r < 0) {
    return r;
  }

  free(text);

  return r;
}

static int sbx_close(unsigned int fd, pid_t tracee) {
  if (!is_open(fd)) {
    return -EBADF;
  }

  del_from_descs(fd, tracee);

  if (fd == 0 || fd == 1 || fd == 2) { /* we cannot close these
					  because we are using them;
					  just simulate instead */
    return 0;
  }
  else {
    int r;
    SYSRET(close(fd), r);
    return r;
  }
}

static int sbx_fstat(unsigned int fd, struct __old_kernel_stat *statbuf, pid_t tracee) {
  if (!is_open(fd)) {
    return -EBADF;
  }

  struct stat b;
  int r;
  SYSRET(fstat(get_efd(fd), &b), r);

  if (write_to_tracee(&b, sizeof(b), statbuf, tracee) != ERR_SUCCESS) {
    return -EFAULT;
  }

  return r;
}

static int sbx_lstat(char *filename, struct __old_kernel_stat *statbuf, pid_t tracee) {
  char *sbxpath;
  if ((sbxpath = get_sbxpath(filename, -1)) == NULL) {
    return -ENOMEM;
  }

  struct stat b;
  int r;
  SYSRET(lstat(sbxpath, &b), r);

  free(sbxpath);

  if (write_to_tracee(&b, sizeof(b), statbuf, tracee) != ERR_SUCCESS) {
    return -EFAULT;
  }

  return r;
}

static int sbx_stat(char *filename, struct __old_kernel_stat *statbuf, pid_t tracee) {
  char *sbxpath;
  if ((sbxpath = get_sbxpath(filename, -1)) == NULL) {
    return -ENOMEM;
  }

  struct stat b;
  int r;
  SYSRET(stat(sbxpath, &b), r);

  free(sbxpath);

  if (write_to_tracee(&b, sizeof(b), statbuf, tracee) != ERR_SUCCESS) {
    return -EFAULT;
  }

  return r;
}

static int sbx_poll(struct pollfd *ufds, unsigned int nfds, long timeout_msecs, pid_t tracee) {
  struct pollfd *fds = get_text(ufds, nfds * sizeof(*ufds), tracee);

  if (fds == NULL) {
    return -ENOMEM;
  }

  for (unsigned int i = 0; i < nfds; i++) {
    fds[i].fd = get_efd(fds[i].fd);
  }

  int r;
  SYSRET(poll(fds, nfds, timeout_msecs), r);

  if (write_to_tracee(fds, nfds * sizeof(*ufds), ufds, tracee)) {
    free(fds);
    return -EFAULT;
  }

  free(fds);

  return r;
}

static int sbx_lseek(unsigned int fd, off_t offset, unsigned int whence) {
  if (!is_open(fd)) {
    return -EBADF;
  }

  int r;
  SYSRET(lseek(get_efd(fd), offset, whence), r);

  return r;
}

static int sbx_newfstatat(int dfd, char *filename, struct stat *statbuf, int flag, pid_t tracee) {
  int r;
  struct stat b;

  if (flag & AT_EMPTY_PATH && filename[0] == '\0') {
    if (!is_open(dfd)) {
      return -EBADF;
    }

    SYSRET(fstatat(get_efd(dfd), "", &b, flag), r);
  }
  else {
    char *sbxpath;

    if (filename[0] != '/' && dfd != AT_FDCWD) {
      if (!is_open(dfd)) {
	return -EBADF;
      }

      if (!is_dir(dfd)) {
	return -ENOTDIR;
      }
    }

    if (filename[0] == '/') dfd = -1;

    if ((sbxpath = get_sbxpath(filename, dfd)) == NULL) {
      return -1;
    }

    SYSRET(fstatat(AT_FDCWD, sbxpath, &b, flag), r);

    free(sbxpath);
  }

  if (write_to_tracee(&b, sizeof(b), statbuf, tracee) != ERR_SUCCESS) {
    return -EFAULT;
  }

  return r;
}

static enum error_e setnoop(struct user_regs_struct user_regs, pid_t tracee) {
  user_regs.orig_rax = GETPID;
  IFBAD_RETURN(set_regs(user_regs, tracee));
  return ERR_SUCCESS;
}

static enum error_e _trace(unsigned long long int sc, struct user_regs_struct user_regs, pid_t tracee, enum state_e st) {
  static unsigned long long int last_ret;

  if (st == STATE_ENTRY) {
    switch (sc) {
    case OPENAT:
      {
	IFBAD_RETURN(setnoop(user_regs, tracee));

	char *filename = get_ntext((void *) user_regs.rsi, tracee);
	if (filename == NULL) {
	  return ERR_PTRACE_PEEKTEXT;
	}

	last_ret = sbx_openat(user_regs.rdi, filename, user_regs.rdx, user_regs.r10);

	free(filename);

	break;
      }

    case READ:
      {
	IFBAD_RETURN(setnoop(user_regs, tracee));

	last_ret = sbx_read(user_regs.rdi, (char *) user_regs.rsi, user_regs.rdx, tracee);

	break;
      }

    case WRITE:
      {
	IFBAD_RETURN(setnoop(user_regs, tracee));

	last_ret = sbx_write(user_regs.rdi, (char *) user_regs.rsi, user_regs.rdx, tracee);

	break;
      }

    case OPEN:
      {
	IFBAD_RETURN(setnoop(user_regs, tracee));

	char *filename = get_ntext((void *) user_regs.rdi, tracee);
	if (filename == NULL) {
	  return ERR_PTRACE_PEEKTEXT;
	}

	last_ret = sbx_open(filename, user_regs.rsi, user_regs.rdx);

	free(filename);

	break;
      }

    case CLOSE:
      {
	IFBAD_RETURN(setnoop(user_regs, tracee));

	last_ret = sbx_close(user_regs.rdi, tracee);

	break;
      }

    case STAT:
      {
	IFBAD_RETURN(setnoop(user_regs, tracee));

	char *filename = get_ntext((void *) user_regs.rdi, tracee);
	if (filename == NULL) {
	  return ERR_PTRACE_PEEKTEXT;
	}

	last_ret = sbx_stat(filename, (struct __old_kernel_stat *) user_regs.rsi, tracee);

	free(filename);

	break;
      }

    case FSTAT:
      {
	IFBAD_RETURN(setnoop(user_regs, tracee));

	last_ret = sbx_fstat(user_regs.rdi, (struct __old_kernel_stat *) user_regs.rsi, tracee);

	break;
      }

    
    case LSTAT:
      {
	IFBAD_RETURN(setnoop(user_regs, tracee));

	char *filename = get_ntext((void *) user_regs.rdi, tracee);
	if (filename == NULL) {
	  return ERR_PTRACE_PEEKTEXT;
	}

	last_ret = sbx_lstat(filename, (struct __old_kernel_stat *) user_regs.rsi, tracee);

	free(filename);

	break;
      }

    case POLL:
      {
	last_ret = sbx_poll((struct pollfd *) user_regs.rdi, user_regs.rsi, user_regs.rdx, tracee);

	break;
      }

    case LSEEK:
      {
	IFBAD_RETURN(setnoop(user_regs, tracee));

	last_ret = sbx_lseek(user_regs.rdi, user_regs.rsi, user_regs.rdx);

	break;
      }

    case NEWFSTATAT:
      {
	IFBAD_RETURN(setnoop(user_regs, tracee));

	char *filename = get_ntext((void *) user_regs.rsi, tracee);
	if (filename == NULL) {
	  return ERR_PTRACE_PEEKTEXT;
	}

	last_ret = sbx_newfstatat(user_regs.rdi, filename, (struct stat *) user_regs.rdx, user_regs.r10, tracee);

	free(filename);

	break;
      }
    }
  }
  else {
    switch (sc) {
    case READ: case WRITE: case OPEN: case CLOSE: case STAT: case FSTAT: case LSTAT: case POLL: case OPENAT: case NEWFSTATAT:
      {
	user_regs.rax = last_ret;
	IFBAD_RETURN(set_regs(user_regs, tracee));
	break;
      }
    }
  }

  return ERR_SUCCESS;
}

enum error_e trace(pid_t tracee, _Bool is_root_proc, struct descs_s *parent_desc) {
  struct descs_s *dsc;

  if (waitpid(tracee, NULL, 0) == -1) {
    return ERR_WAITPID;
  }
  if (ptrace(PTRACE_SETOPTIONS, tracee, 0, PTRACE_O_EXITKILL | PTRACE_O_TRACEFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEVFORK) == -1) {
    return ERR_PTRACE_SETOPTIONS;
  }

  enum error_e r;

  IFBAD_RETURN(init_descs(&dsc, parent_desc, tracee));
  dp = dsc;

  /* children inherit opened fds from the parent, so we don't need to
     open these fds if the tracee is not the root process */
  if (is_root_proc) {
    /* isolate stdin, stdout, and stderr for the tracee */
    int eval = open("sbx/proc/self/fd/0", O_RDONLY);
    if (eval == -1) { r = ERR_OPENSTDIN; goto cleanup; }
    r = add_to_descs("sbx/proc/self/fd/0", 0, O_RDONLY, eval);
    if (r) goto cleanup;

    eval = open("sbx/proc/self/fd/1", O_WRONLY);
    if (eval == -1) { r = ERR_OPENSTDOUT; goto cleanup; }
  
    r = add_to_descs("sbx/proc/self/fd/1", 1, O_WRONLY, eval);
    if (r) goto cleanup;

    eval = open("sbx/proc/self/fd/2", O_WRONLY);
    if (eval == -1) { r = ERR_OPENSTDERR; goto cleanup; }
    r = add_to_descs("sbx/proc/self/fd/2", 2, O_WRONLY, eval);
    if (r) goto cleanup;
  }

  while (1) {
    /* syscall entry */

    r = wait_syscall(tracee);

    if (r == ERR_WAITPID || r == ERR_TERMINATED) {
      goto cleanup;
    }

    struct user_regs_struct user_regs;
    if (ptrace(PTRACE_GETREGS, tracee, NULL, &user_regs) == -1) {
      r = ERR_PTRACE_GETREGS;
      goto cleanup;
    }

    unsigned long long int sc = user_regs.orig_rax;

    IFBAD_RETURN(_trace(sc, user_regs, tracee, STATE_ENTRY));

    /* syscall exit */

    r = wait_syscall(tracee);

    if (r == ERR_WAITPID || r == ERR_TERMINATED) {
      goto cleanup;
    }
    else if (r == ERR_EFORK || r == ERR_EVFORK || r == ERR_ECLONE) {
      long ch_tracee;

      if (ptrace(PTRACE_GETEVENTMSG, tracee, NULL, &ch_tracee) == -1) {
	r = ERR_PTRACE_GETEVENTMSG;
	goto cleanup;
      }

      trace(ch_tracee, 0, dsc);

      dp = dsc;
    }
    else {
      if (ptrace(PTRACE_GETREGS, tracee, NULL, &user_regs) == -1) {
	r = ERR_PTRACE_GETREGS;
	goto cleanup;
      }

      r = _trace(sc, user_regs, tracee, STATE_EXIT);

      if (r) goto cleanup;
    }
  }

 cleanup:
  clean_descs(tracee);

  return r;
}
