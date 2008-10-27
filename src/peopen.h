FILE *peopen(const char *command, const char *type, char *const envp[], int *ret_pid);

FILE *peidopen(const char *command, const char *type, char *const envp[], int *ret_pid, uid_t uid, gid_t gid);
