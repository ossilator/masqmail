/* This a snippet I found in sourceforge. I just changed the identing
   style to my own and deleted the main function.  */

#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>

#include "peopen.h"

FILE* peidopen(const char	*command,
	       const char	*type,
	       char *const envp [],
	       int *ret_pid,
	       uid_t uid, gid_t gid
	     )
{
  enum { Read, Write } mode;
  int pipe_fd [2];
  pid_t pid;
    
  if (command == NULL || type == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (strcmp (type, "r")) {
    if (strcmp (type, "w")) {
      errno = EINVAL;
      return NULL;
    } else
      mode = Write;
  } else
    mode = Read;

  if (pipe (pipe_fd) == -1)
    return NULL;

  switch (pid = fork ()) {
  case 0: /* child thread */

    {
      int i, max_fd = sysconf(_SC_OPEN_MAX);
      
      if(max_fd <= 0) max_fd = 64;
      for(i = 0; i < max_fd; i++)
	if((i != pipe_fd[0]) && (i != pipe_fd[1])) close(i);
    }
    if (close (pipe_fd [mode == Read ? 0 : 1]) != -1 &&
	dup2 (pipe_fd [mode == Read ? 1 : 0], mode == Read ? STDOUT_FILENO : STDIN_FILENO) != -1) {
      char *argv [] = { "/bin/sh", "-c", (char*) command, NULL };

      if(uid >= 0) seteuid(0);
      if(gid >= 0) setgid(gid);
      if(uid >= 0) setuid(uid);
      /*
      if(gid >= 0) setegid(gid);
      if(uid >= 0) seteuid(uid);
      */
      execve (*argv, argv, envp);
    }
	    
    _exit (errno);
	    
  default: /* parent thread */
    *ret_pid = pid;
    close (pipe_fd [mode == Read ? 1 : 0]);
    return fdopen (pipe_fd [mode == Read ? 0 : 1], type);
	    
  case -1:
    close (pipe_fd [0]);
    close (pipe_fd [1]);
    return NULL;
  }
}

FILE* peopen(const char	*command,
	     const char	*type,
	     char *const envp [],
	     int *ret_pid
	     )
{
  return peidopen(command, type, envp, ret_pid, -1 ,-1);
}
