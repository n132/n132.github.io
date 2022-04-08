---
title: "XV6: Syscall and Scheduler"
date: 2022-04-01 12:09:21
tags: 
layout: default
---

# Syscall

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


# Strace the syscall

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

Also, we know the timers implemented in hardware keep the OS running by interrupting periodically to handle kinds of interrupts, such as the `int 0x40`.

```S
#include "mmu.h"

  # vectors.S sends all traps here.
.globl alltraps
alltraps:
  # Build trap frame.
  pushl %ds
  pushl %es
  pushl %fs
  pushl %gs
  pushal
  
  # Set up data segments.
  movw $(SEG_KDATA<<3), %ax
  movw %ax, %ds
  movw %ax, %es

  # Call trap(tf), where tf=%esp
  pushl %esp
  call trap
  addl $4, %esp

  # Return falls through to trapret...
.globl trapret
trapret:
  popal
  popl %gs
  popl %fs
  popl %es
  popl %ds
  addl $0x8, %esp  # trapno and errcode
  iret

```

It uses `alltraps` to as the entry of the handle and you can find its source code in `trapasm.S`. It would firstly store the trap frame for furture returning and it would set the data segement to the kernel data segement's address to accomplish the context switch. After that, it calls trap to really heandle the interupts. Btw, you can find the return part in `trapret` it reverses the options we did at the first part of `alltraps` to switch the context back to the user space.

```c
//trap.c
void
trap(struct trapframe *tf)
{
  if(tf->trapno == T_SYSCALL){
    if(myproc()->killed)
      exit();
    myproc()->tf = tf;
    syscall();
    if(myproc()->killed)
      exit();
    return;
  }

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
  case T_IRQ0 + IRQ_IDE:
    ideintr();
    lapiceoi();
    break;
  case T_IRQ0 + IRQ_IDE+1:
    // Bochs generates spurious IDE1 interrupts.
    break;
  case T_IRQ0 + IRQ_KBD:
    kbdintr();
    lapiceoi();
    break;
...
```

The `trap` function would handle not only the `syscalls`, but other kinds of trap/interupts, such as the keyborad actions and timer interupts. For the syscall, it would call `syscall` to process the syscall and you can find the source code in `syscall.c`. It takes the paremeters from the tf(`trapfram`) and choose the corresponding function. Aftrer finishing the tasks, it store return value in the tf's eax and return back to `syscall()`, `trap()`, and `alltraps` and use the stored trapfram to recover user space context.

So far, the whole procedure of the syscall finished.

---

# scheduler

In the `boot` part, the CPU would start their work by running the `scheduler`. We can find the source code of this function in `proc.c`. This piece of code is super important. It would be run so many times very second. 
```c
void
scheduler(void)
{
  struct proc *p;
  struct cpu *c = mycpu();
  c->proc = 0;
  
  for(;;){
    // Enable interrupts on this processor.
    sti();

    // Loop over process table looking for process to run.
    acquire(&ptable.lock);
    for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
      if(p->state != RUNNABLE)
        continue;

      // Switch to chosen process.  It is the process's job
      // to release ptable.lock and then reacquire it
      // before jumping back to us.
      c->proc = p;
      switchuvm(p);
      p->state = RUNNING;

      swtch(&(c->scheduler), p->context);
      switchkvm();

      // Process is done running for now.
      // It should have changed its p->state before coming back.
      c->proc = 0;
    }
    release(&ptable.lock);

  }
}
```

It has a infinit loop and in each loop, it check every process in the `ptable` (process table) until it finds a runnable one. After that, the scheduler use `switchuvm` to load the context from user space. And use `swtch` to run the process. 

I find an intersting fact about the `swtch`, it can't return by itself. The process return to the scheduler by call it again with different parameters `(&p->context, mycpu()->scheduler)`! 


```s
# Context switch
#
#   void swtch(struct context **old, struct context *new);
# 
# Save the current registers on the stack, creating
# a struct context, and save its address in *old.
# Switch stacks to new and pop previously-saved registers.

.globl swtch
swtch:
  movl 4(%esp), %eax
  movl 8(%esp), %edx

  # Save old callee-saved registers
  pushl %ebp
  pushl %ebx
  pushl %esi
  pushl %edi

  # Switch stacks
  movl %esp, (%eax)
  movl %edx, %esp

  # Load new callee-saved registers
  popl %edi
  popl %esi
  popl %ebx
  popl %ebp
  ret

```

The source code of `swtch` is in `swtch.S`, and it's quite simple but elegant. The first 2 lines would load the parameters to `eax` and `edx`. And the following 4 instructions would save current registers. After that, the `swtch` siwtch the stack by `movl %edx, %esp` (We did store the second parameter in the `edx`). The use 4 `pop` to pop out the new process's registers. If every process follow this convention, store the registers on stack in order, the `swtch` could switch from different process!


As we known, not excatly, there are 4 main types of states of a process, including `RUNNABLE`, `RUNNING`, `SLEEPING`, and `ZOMBIE`. The shceduler would run the runnable process, aka changing `RUNNABLE` to `RUNNING`. And there are some other simple transitions which I didn't take a not about:
1.  `sleep` would change `RUNNING` to `SLEEPING`
2.  `exit` would change `RUNNING` to `ZOMBIE`
3.  `awake` would change `SLEEPING` to `RUNNABLE`

So far, we still didn't talk about the last transition.
That's the transition from `RUNNING` to `RUNABLE`. Some process would be stopped by the CPU forcibly. More specificlly, the timer would send an `IRQ_TIMER` interupt and the CPU would use the `TRAP` function to handle it.

```c
  // Force process to give up CPU on clock tick.
  // If interrupts were on while locks held, would need to check nlock.
  if(myproc() && myproc()->state == RUNNING &&
     tf->trapno == T_IRQ0+IRQ_TIMER)
    yield();
```

The `yield` function is a wrapper of `sched` and `sched` is a wrapper of `swtch` in deed.

```c
//porc.c
// Give up the CPU for one scheduling round.
void
yield(void)
{
  acquire(&ptable.lock);  //DOC: yieldlock
  myproc()->state = RUNNABLE;
  sched();
  release(&ptable.lock);
}
// Enter scheduler.  Must hold only ptable.lock
// and have changed proc->state. Saves and restores
// intena because intena is a property of this
// kernel thread, not this CPU. It should
// be proc->intena and proc->ncli, but that would
// break in the few places where a lock is held but
// there's no process.
void
sched(void)
{
  int intena;
  struct proc *p = myproc();

  if(!holding(&ptable.lock))
    panic("sched ptable.lock");
  if(mycpu()->ncli != 1)
    panic("sched locks");
  if(p->state == RUNNING)
    panic("sched running");
  if(readeflags()&FL_IF)
    panic("sched interruptible");
  intena = mycpu()->intena;
  swtch(&p->context, mycpu()->scheduler);
  mycpu()->intena = intena;
}

```

In above code, the `yield` function changes the state of the process and dives into the `sched` function. And the `sched` function would call `swtch` to give the control back to the `scheduler` after some verbose checks. 

That totally makes sense!

# Process Switching

Trace the process switching.

1. Process A
2. Timer Interupt
3. alltraps()
4. trap() 
5. yield()
6. swtch()
7. scheduler()
8. swtch()
9. yeild()
10. trap()
11. alltraps()
12. Process B
