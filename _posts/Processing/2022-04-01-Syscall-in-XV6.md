# sycall

In this section we would review the syscall from both high level and low level!
Also, we would also go through other similar mechanisms, such as the interupt, to have a more clear view of the operation system. Let's start from something simple, adding a system call.

# sys_n132

In this section, we gonna add a new syscall SYS_n132 to the xv6 system! We need to moddify the source code There are 5 related Files: `syscall.h`, `syscall.c`, `sysproc.c`, `usys.S`, and `user.h`.

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
exit(1);
}
```


# How does the system works

We can trigger a syscall by using some user space interfaces, such as exit. 

```c
//TestCode
#include "types.h"
#include "user.h"
#include "stat.h"
int main(void) 
{
printf(1, "%d\n", n132());
exit(1);
}
```

Take this program as an example, it would trigger 3 syscalls, `SYS_n132`, `SYS_write` and `SYS_exit`. We can see the syscall in asm code.

```c
.text:00000000 ; int __cdecl main(int argc, const char **argv, const char **envp)
.text:00000000                 public main
.text:00000000 main            proc near
.text:00000000
.text:00000000 argc            = dword ptr  8
.text:00000000 argv            = dword ptr  0Ch
.text:00000000 envp            = dword ptr  10h
.text:00000000
.text:00000000                 lea     ecx, [esp+4]
.text:00000004                 and     esp, 0FFFFFFF0h
.text:00000007                 push    dword ptr [ecx-4]
.text:0000000A                 push    ebp
.text:0000000B                 mov     ebp, esp
.text:0000000D                 push    ecx
.text:0000000E                 sub     esp, 4
.text:00000011                 call    n132
.text:00000016                 sub     esp, 4
.text:00000019                 push    eax
.text:0000001A                 push    offset fmt      ; fmt
.text:0000001F                 push    1               ; fd
.text:00000021                 call    printf
.text:00000026                 call    exit
...
.text:00000322                 public n132
.text:00000322 n132            proc near               ; CODE XREF: main+11↑p
.text:00000322                 mov     eax, 16h
.text:00000327                 int     40h             ; Hard disk - Relocated Floppy Handler (original INT 13h)
.text:00000329                 retn
.text:00000329 n132            endp
```

At `.text+0x11`, we are going to call `n132` function, it's the user-space-interface of the real syscall. And the user space would use the interupts to jump to the kernel. As you can see in the above code, it's `INT 40h`. It calls interrupt 0x40's handle.

You can see the definitions of all the traps and interupts in `trap.h`, like the syscall:

`#define T_SYSCALL       64      // system call`

Also, we know the timers implemented in hardware keep the OS running by interrupting periodically. That would interrupt the current running process and allows other process to use the CPU by function `wakeup` so that the sleeping processes would be runnable.
```c
  ...
  switch(tf->trapno){
  case T_IRQ0 + IRQ_TIMER:
    if(cpuid() == 0){
      acquire(&tickslock);
      ticks++;
      wakeup(&ticks);
      release(&tickslock);
    }
    lapiceoi();
    break;
  ...
```