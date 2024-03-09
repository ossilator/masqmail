#include <stdio.h>
#include <unistd.h>

FILE *peopen(const char *command, const char *type, char *const envp[], int *ret_pid);
