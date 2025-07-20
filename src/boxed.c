/*
    Boxed, a Linux Intel 64 sandbox
    Copyright (C) 2025  Somdipto Chakraborty

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "errors.h"
#include "tracer.h"

int main(int argc, char *argv[]) {
  if (argc < 2) {
    fprintf(stderr, "usage:\n"
	 "path args...\n");
    return ERR_TOOFEWARGS;
  }

  pid_t tracee = fork();

  if (tracee == -1) {
    return ERR_FORK;
  }
  else if (tracee == 0) {
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
      return ERR_PTRACE_TRACEME;
    }

    execvp(argv[1], &argv[2]);
    return ERR_EXECVP;
  }
  else {
    return trace(tracee, 1, NULL);
  }
}
