#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <linux/limits.h>
#include <fcntl.h>
#include <unistd.h>

#include "tracer.h"
#include "syscalls.h"
#include "config.h"
#include "btypes.h"

#define IFBAD_RETURN(arg) { enum error _err = arg; if (_err != ERR_SUCCESS) return _err; }

enum state {
  STATE_ENTRY,
  STATE_EXIT
};

struct descs {
  int val;
  char *iden;
  mode_t mode;
} *dp;

/* *_descs functions need to be rewritten for improve efficiency;
   but these should do it for now */

static enum error init_descs(void) {
  if ((dp = malloc(MAX_DESCS * sizeof(*dp))) == NULL) {
    return ERR_MALLOC;
  }

  for (size_t i = 0; i < MAX_DESCS; i++) {
    dp[i].val = -1;
    dp[i].iden = NULL;
    dp[i].mode = 0;
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

static enum error add_to_descs(char *name, int d, mode_t mode) {
  for (size_t i = 0; i < MAX_DESCS; i++) {
    if (dp[i].val == -1) {
      if ((dp[i].iden = malloc(strlen(name))) == NULL) {
	return ERR_MALLOC;
      }

      strncpy(dp[i].iden, name, strlen(name));
      dp[i].val = d;
      dp[i].mode = mode;
      return ERR_SUCCESS;
    }
  }

  return ERR_FILLED_DESCS;
}

static void del_from_descs(size_t d) {
  ssize_t l = search_in_descs(d);

  if (l == -1) return;

  dp[l].val = -1;

  free(dp[l].iden);
  dp[l].iden = NULL;

  dp[l].mode = 0;
}

static enum error wait_syscall(pid_t tracee) {
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
  else if(WIFSIGNALED(wstatus)) {
    return ERR_KILLED;
  }

  return ERR_SUCCESS;
}

static enum error set(struct user_regs_struct user_regs, pid_t tracee) {
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

static enum error write_to_tracee(void *b, size_t bsz, void *addr, pid_t tracee) {
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

static int sbx_openat(int dfd, char *filename, int flags, mode_t mode) {
  if (!is_dir(dfd) && dfd != AT_FDCWD) {
    return -1;
  }

  char *sbxpath;
  if ((sbxpath = get_sbxpath(filename, dfd)) == NULL) {
    return -1;
  }

  int r = open(sbxpath, flags, mode);

  free(sbxpath);

  IFBAD_RETURN(add_to_descs(sbxpath, r, mode));

  return r;
}

static int sbx_open(char *filename, int flags, mode_t mode) {
  char *sbxpath;
  if ((sbxpath = get_sbxpath(filename, -1)) == NULL) {
    return -1;
  }

  int r = open(sbxpath, flags, mode);

  free(sbxpath);

  IFBAD_RETURN(add_to_descs(sbxpath, r, mode));

  return r;
}

static int sbx_read(unsigned int fd, void *buf, size_t count, pid_t tracee) {
  if (!is_open(fd)) {
    return -1;
  }

  char *b = malloc(count);
  if (b == NULL) {
    return -1;
  }

  int r;
  if ((r = read(fd, b, count)) == -1) {
    return -1;
  }

  if (write_to_tracee(b, r, buf, tracee) != ERR_SUCCESS) {
    return -1;
  }

  return r;
}

static int sbx_write(unsigned int fd, void *buf, size_t count, pid_t tracee) {
  if (!is_open(fd)) {
    return -1;
  }

  char *text = get_text(buf, count, tracee);

  if (text == NULL) {
    return -1;
  }

  int r =  write(fd, text, count);

  free(text);

  return r;
}

static int sbx_close(unsigned int fd) {
  if (!is_open(fd)) {
    return -1;
  }

  del_from_descs(fd);

  if (fd == 0 || fd == 1 || fd == 2) { /* we cannot close these
					  because we are using them;
					  just simulate instead */
    return 0;
  }
  else {
    return close(fd);
  }
}

static int sbx_stat(char *filename, struct stat *statbuf, pid_t tracee) {
  char *sbxpath;
  if ((sbxpath = get_sbxpath(filename, -1)) == NULL) {
    return -1;
  }

  struct stat b;
  int r = stat(sbxpath, &b);

  free(sbxpath);

  if (write_to_tracee(&b, sizeof(b), statbuf, tracee) != ERR_SUCCESS) {
    return -1;
  }

  return r;
}

static int sbx_newfstatat(int dfd, char *filename, struct stat *statbuf, int flag, pid_t tracee) {
  int r;
  struct stat b;

  if (flag & AT_EMPTY_PATH && filename[0] == '\0') {
    if (!is_open(dfd)) {
      return -1;
    }

    r = fstatat(dfd, "", &b, flag);
  }
  else {
    char *sbxpath;

    if (!is_dir(dfd) && dfd != AT_FDCWD) {
      return -1;
    }

    if ((sbxpath = get_sbxpath(filename, dfd)) == NULL) {
      return -1;
    }

    r = fstatat(AT_FDCWD, sbxpath, &b, flag);

    free(sbxpath);
  }

  if (write_to_tracee(&b, sizeof(b), statbuf, tracee) != ERR_SUCCESS) {
    return -1;
  }

  return r;
}

static enum error setnoop(struct user_regs_struct user_regs, pid_t tracee) {
  user_regs.orig_rax = GETPID;
  IFBAD_RETURN(set(user_regs, tracee));
  return ERR_SUCCESS;
}

static enum error _trace(unsigned long long int sc, struct user_regs_struct user_regs, pid_t tracee, enum state st) {
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

	last_ret = sbx_read(user_regs.rdi, (void *) user_regs.rsi, user_regs.rdx, tracee);

	break;
      }

    case WRITE:
      {
	IFBAD_RETURN(setnoop(user_regs, tracee));

	last_ret = sbx_write(user_regs.rdi, (void *) user_regs.rsi, user_regs.rdx, tracee);

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

	last_ret = sbx_close(user_regs.rdi);

	break;
      }

    case STAT:
      {
	IFBAD_RETURN(setnoop(user_regs, tracee));

	char *filename = get_ntext((void *) user_regs.rdi, tracee);
	if (filename == NULL) {
	  return ERR_PTRACE_PEEKTEXT;
	}

	last_ret = sbx_stat(filename, (struct stat *) user_regs.rsi, tracee);

	free(filename);

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
    case READ: case OPENAT: case WRITE: case OPEN: case CLOSE: case STAT: case NEWFSTATAT:
      {
	user_regs.rax = last_ret;
	IFBAD_RETURN(set(user_regs, tracee));
	break;
      }
    }
  }

  return ERR_SUCCESS;
}

enum error trace(pid_t tracee) {
  if (waitpid(tracee, NULL, 0) == -1) {
    return ERR_WAITPID;
  }
  if (ptrace(PTRACE_SETOPTIONS, tracee, 0, PTRACE_O_EXITKILL) == -1) {
    return ERR_PTRACE_SETOPTIONS;
  }

  enum error r;

  IFBAD_RETURN(init_descs());
  IFBAD_RETURN(add_to_descs("/proc/self/fd/0", 0, O_RDONLY));
  IFBAD_RETURN(add_to_descs("/proc/self/fd/1", 1, O_WRONLY));
  IFBAD_RETURN(add_to_descs("/proc/self/fd/2", 2, O_WRONLY));

  while (1) {
    /* entry */

    r = wait_syscall(tracee);

    if (r == ERR_WAITPID || r == ERR_TERMINATED) {
      return r;
    }

    struct user_regs_struct user_regs;
    if (ptrace(PTRACE_GETREGS, tracee, NULL, &user_regs) == -1) {
      return ERR_PTRACE_GETREGS;
    }

    unsigned long long int sc = user_regs.orig_rax;

    IFBAD_RETURN(_trace(sc, user_regs, tracee, STATE_ENTRY));

    /* exit */

    r = wait_syscall(tracee);

    if (r == ERR_WAITPID || r == ERR_TERMINATED) {
      return r;
    }

    if (ptrace(PTRACE_GETREGS, tracee, NULL, &user_regs) == -1) {
      return ERR_PTRACE_GETREGS;
    }

    IFBAD_RETURN(_trace(sc, user_regs, tracee, STATE_EXIT));
  }

  return r;
}
