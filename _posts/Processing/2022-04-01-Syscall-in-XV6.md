# Files

# sys_n132

Related Files: `syscall.h`, `syscall.c`, `sysproc.c`, `usys.S`, and `user.h`.

In order to add a new syscall, we need to add a new definition in `syscall.h`.
```C
...
#define SYS_close  21
#define SYS_n132   22
```
And add the new syscall to the syscall function_ptr lists in `syscall.c`. This's the first time I see this kind of initialization. 
```c
static int (*syscalls[])(void) = {
[SYS_fork]    sys_fork,
[SYS_exit]    sys_exit,
[SYS_wait]    sys_wait,
[SYS_pipe]    sys_pipe,
[SYS_read]    sys_read,
[SYS_kill]    sys_kill,
[SYS_exec]    sys_exec,
[SYS_fstat]   sys_fstat,
[SYS_chdir]   sys_chdir,
[SYS_dup]     sys_dup,
[SYS_getpid]  sys_getpid,
[SYS_sbrk]    sys_sbrk,
[SYS_sleep]   sys_sleep,
[SYS_uptime]  sys_uptime,
[SYS_open]    sys_open,
[SYS_write]   sys_write,
[SYS_mknod]   sys_mknod,
[SYS_unlink]  sys_unlink,
[SYS_link]    sys_link,
[SYS_mkdir]   sys_mkdir,
[SYS_close]   sys_close,
};
```

This is a function ptr list and the number in `[]` declares the index of the syscall and the value is the function address. The syscall would not take any parameter and would return a int. It takes parameters from the stack. This feature is a little different from Linux. For linux, x32/x64 syscall would take the parameters from the registers.

In order to register the entrance, we need to declare the function and add our syscall to this list.
```c
extern int sys_n132(void);
static int (*syscalls[])(void) = {
...
[SYS_close]   sys_close,
[SYS_n132]    sys_n132,
};
```
The next step is coding the `sys_n132`, to really implement our syscall. The bussiness logics for all the syscalls are in `sysproc.c`. 

```C
int sys_n132(void)
{
  return 0x132;
}
```

After that, we need to give a interface to the users. Declare the function in `user.h` and `usys.S`.


```c
//user.h
...
int uptime(void);
int n132(void);
...
//usys.S
...
SYSCALL(uptime)
SYSCALL(n132)
```


Compile the testcode and the system.

```c
//TestCode
#include "types.h"
#include "user.h"
#include "stat.h"
int main(void) 
{
printf(1, "%d\n", n132());
exit();
}
```



