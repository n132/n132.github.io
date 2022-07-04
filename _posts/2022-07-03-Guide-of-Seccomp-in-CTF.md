---
title: "Guide-of-CTF-Seccomp"
date: 2022-07-03 18:52:21
tags: 
layout: default
---

# 0x00 Prologue
Last weekend, I met a sandbox challenge, s2, on gctf-2022. However, I can't solve it because I don't know the stories about the seccomp. I would go through BPF in this passage.

If you are a pwner, you probably know seccomp. It's common used in pwn challenge for meny purposes.

First, it could be used to require the folks run complex instruction rather than hitting one_gadget. For this purpose, the BPF would allow some basic syscalls, such as read, write and open. Most time, it would be a allowed-syscall-list. This type of challenge doesn't require people to have additional knowleged about seccomp and it focuses on the challenge itself. 

The second type of challenge would focus on a specific syscall. The challenge author wants to introduce a specific syscall to the people and (s)he would forbid (part of) basic syscalls such as execve, open, ... And the filter would be like a blacklist. From this type of challenges, I learned tremendous interesting syscalls and I'll just introduce some of them in this passage.

The third type of challenge would focus more on the BPF/Seccomp itself. It would give a wrong configured filter so it's more like a sandbox escaping challenge rather than a pwn challenge. We would go through kinds of basic escaping skills. 


The fourth type is different from traditional CTF pwn challenge, it would implement another layer, for example a monitor, to mimic the real seccomp in the kernel. And we are seposed to write a binary to escape from the sandbox(the monitor). It's hard to see this type of challenge because it require tremendous work to build a sandbox. The most typical one is s2 in googlectf 2022. This challenge is also the original reasons why I wrote this passage. I know little abotu seccom before gctf 2022 and I spent two days on challenge. Although I didn't solve it, I learned a lot and it worth a write up.

This passage would focus on seccomp itself and would simply talk about the bypass solution for every type. Also, I provided one challenge for every type:

| Type | Challenges|
|--|--|
|0x1| [orw][0], [NaiveHeap][4] |
|0x2| [sbnote][3], [sycall kit][5] |
|0x3| [steak][6], [babypf][7]|
|0x4| This passage |

# 0x01 Seccomp


This section would have a short intro to seccomp by showing you how to build a seccomp sandbox. 

`https://man7.org/linux/man-pages/man2/seccomp.2.html`

If you run `man 2 seccomp`, you would get the man page of the wrapper of syscall seccomp and it's one of the baisc interfaces to the user space.

I hated verbose man page, but I found that's exact the most percise info that I should start with. It would include introduction for different arguments and recent new features that you can hardly find in old summary passages. In addition, there are plenty of samples which could be used to create some test cases. A main reason, for what I can't solve S2, is I didn't read the man page. If I read it, it's not hard to connect ioctl and seccomp.

okay, let's come back to the seccomp,

`int seccomp(unsigned int operation, unsigned int flags, void *args);`

There are four supported operations: SECCOMP_SET_MODE_STRICT, SECCOMP_SET_MODE_FILTER, SECCOMP_GET_ACTION_AVAIL, and SECCOMP_GET_NOTIF_SIZES. 

| Operation | Desc | Value |
|--| --| --|
| SECCOMP_SET_MODE_STRICT | only allow read, write, and exit | 0x0
| SECCOMP_SET_MODE_FILTER | apply provided BPF in args  | 0x1
| SECCOMP_GET_ACTION_AVAIL | Test to see if an action is supported by the kernel. | 0x2
| SECCOMP_GET_NOTIF_SIZES | Get the sizes of the seccomp user-space notification structures.  | 0x3


The most significant one is `SECCOMP_SET_MODE_FILTER`, we can use it to apply our filter. However, you can't run `syscall(__NR_seccomp,SECCOMP_SET_MODE_FILTER,0,&prog);` without setting `no_new_privs`. There is a sample to apply ORW(open read write) filter.


```c++
// g++ ./orw.cc -o ./orw
#include <seccomp.h>
#include <unistd.h>
#include <syscall.h>
#include <iostream>
#include <sys/prctl.h>
#include <linux/filter.h>

using namespace std;

// struct sock_filter {	/* Filter block */
// 	__u16	code;   /* Actual filter code */
// 	__u8	jt;	/* Jump true */
// 	__u8	jf;	/* Jump false */
// 	__u32	k;      /* Generic multiuse field */
// };
// struct sock_fprog {	/* Required for SO_ATTACH_FILTER. */
// 	unsigned short		len;	/* Number of filter blocks */
// 	struct sock_filter *filter;
// };

int main(){
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_open, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_read, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_write, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    };
    struct sock_fprog prog = {
        .len = sizeof(filter) / sizeof(filter[0]),
        .filter = filter,
    };
    // set no_new_privs, or it would return  EACCES:
    // The caller did not have the CAP_SYS_ADMIN capability in
    // its user namespace, or had not set no_new_privs before
    // using SECCOMP_SET_MODE_FILTER.
    syscall(__NR_prctl,PR_SET_NO_NEW_PRIVS, 1,0,0,0);

    // Apply the filter. 
    syscall(__NR_seccomp,SECCOMP_SET_MODE_FILTER,0,&prog);
    
    syscall(__NR_write,1,"Read, write, and exit are avaliable\n",37);
    // Fork is forbidden 
    fork();
}
```
`no_new_privs` is crucial, you can find more detailed description in [the manual page of prctl][8].  I'll talk about this later in this passage. todo: more details

As you can see, I wrote a filter and applied it. It's actually a vulenrabily sandbox. Anyways, let's use [seccomp-tools][1] dump the filter. 

```s
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000000  A = sys_number
 0001: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0003
 0002: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0003: 0x15 0x00 0x01 0x00000000  if (A != read) goto 0005
 0004: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0005: 0x15 0x00 0x01 0x00000001  if (A != write) goto 0007
 0006: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0007: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
```

With seccomp-tools, we could see the bpf code clearly. Berkeley Packet Filter(in seccomp) is a technology used to analysis the syscalls. It's like a kind of small program and our syscall number is its inputs. As a result, the small bpf program would tell us if this syscall is allowed to be executed. 

According to the above code, bpf would take our syscall number and judge if it's one of (open, read and write). If it's one of them, the process is killed by `SIGSYS`.

Also, we can only use prctl to create a seccomp sandbox.

```c
#include <unistd.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <syscall.h>
int main(void){
	struct sock_filter filter[] = {
        {0x20,0x00,0x00,0x00000000},
        {0x15,0x00,0x01,0x00000002},
        {0x06,0x00,0x00,0x7fff0000},
        {0x15,0x00,0x01,0x00000000},
        {0x06,0x00,0x00,0x7fff0000},
        {0x15,0x00,0x01,0x00000001},
        {0x06,0x00,0x00,0x7fff0000},
        {0x06,0x00,0x00,0x80000000},
	};
    struct sock_fprog prog = {
        .len = sizeof(filter) / sizeof(filter[0]),
        .filter = filter,
    };
    syscall(__NR_prctl,PR_SET_NO_NEW_PRIVS,1,0,0,0);
    // Apply the filter.
	syscall(__NR_prctl,PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&prog);
    // Fork is forbidden 
    fork();
	return 0;
}
```

Above code is actually almost same as the previous program, as I got the filter from the dumped data of `seccomp-tools`. The only difference is that we use `__NR_prctl` rather than `__NR_seccomp` to create the sandbox.

These two program are quite simple and straitforward but as I said, the above code is vulnerabile don't use it in your program <3. Now we know the what's seccomp and how to use seccomp to create syscall filter. 

## More high_level samples

The following code create a seccomp sandbox which only allows SYS_write. It use several functions in seccomp library, including "seccomp_init", "seccomp_rule_add", "seccomp_load". 
```c
//gcc -no-pie --static simple_syscall_seccomp.c -o simple_syscall_seccomp -lseccomp
#include <unistd.h>
#include <seccomp.h>
#include <linux/seccomp.h>
#include <syscall.h>
int main(void){
	scmp_filter_ctx ctx;
	ctx = seccomp_init(SCMP_ACT_KILL);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, __NR_write, 0);
	seccomp_load(ctx);
	syscall(1,1,"n132\n",5);
	return 0;
}
```
By running strace we could get the following result and find it's actually similar to our simple program in previous section.

> Tip: seccmp lib would use malloc and free while prctl doesn't

```s
...
seccomp(SECCOMP_GET_ACTION_AVAIL, 0, [SECCOMP_RET_LOG]) = 0
seccomp(SECCOMP_GET_ACTION_AVAIL, 0, [SECCOMP_RET_KILL_PROCESS]) = 0
seccomp(SECCOMP_GET_NOTIF_SIZES, 0, 0x7ffecbd0fc92) = 0
prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)  = 0
seccomp(SECCOMP_SET_MODE_FILTER, 0, {len=8, filter=0xf92840}) = 0
...
```

In addition, people would also use prctl to create a seccomp sandbox. However, it's also the same as creating a sandbox with syscall prctl which we talked in previous section.

```c
//gcc ./main -o main
#include <unistd.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
int main(void){
	prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0);
	struct sock_filter sfi[] = {
		{0x20,0x00,0x00,0x00000004},
		{0x15,0x00,0x09,0xc000003e},
		{0x20,0x00,0x00,0x00000000},
		{0x35,0x07,0x00,0x40000000},
		{0x15,0x06,0x00,0x0000003b},
		{0x15,0x00,0x04,0x00000001},
		{0x20,0x00,0x00,0x00000024},
		{0x15,0x00,0x02,0x00000000},
		{0x20,0x00,0x00,0x00000020},
		{0x15,0x01,0x00,0x00000010},
		{0x06,0x00,0x00,0x7fff0000},
		{0x06,0x00,0x00,0x00000000}
	};
	struct sock_fprog sfp = {12,sfi};
	prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&sfp);
	//...
	return 0;
}
```

# 0x02 Seccomp in CTF

We have learned the basic usage of seccomp and there still are some specical features left, I decide to left it until we meet related challenges. For my experience of CTF pwning, as I said in prologue, I think there are mainly four types of seccomp challenges and we would quickly go through these tyeps to reach today's main topic (s2).

## Type 1

The main purpose of this type of challenges is asking for more advanced controling of the binary rather than exploiting with one_gadget. And this type of challenge would include a whiltelist of syscalls.  There are several tricks that we can use to bypass seccomp and achive more advanced control of the binary:

- Shellcode to ORW
- ROP to ORW
- Use seccontext to exploit and run our ROPCHAIN/Shellcode to ORW 

## Type 2

The main purpose of this type of introduce some syscalls to people and this type of challenge would include a blacklist of syscalls. 


I list some known syscalls:

| syscall | usage |
|--| --|
| openat, execveat | Could be used to replace open/execve |
| (p)read(v), (p)write(v) | Could be used to replace read/write |
| process_vm_readv / process_vm_writev | Modify other process' mem, which may lead vul in another process |
| prlimit64 | Limit the resource of a process, which may lead vul in another process | 

Code:
```c
#include <stdio.h>
#include <seccomp.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/uio.h>

int main(int argc, char *argv[])
{
    char buf0[0x10]={};
    char buf1[0x10]={};
    struct iovec iov[2];
    iov[0].iov_base = buf0;
    iov[0].iov_len = 0x10;
    iov[1].iov_base = buf1;
    iov[1].iov_len = 0x10;
    int f=  openat(0,"/mnt/c/Users/n132/Desktop/sd/flag",0);
    readv(f, iov, 2);
    writev(1,iov,2);
}
```

By the way, if there is no write we could use side-channel attack to leak the flag:

```asm
// read(0,buf,0x100);
	lea rax,[buf]
	xor rbx,rbx
	mov rbx, byte ptr[buf]
	cmp rbx, 0x30
INFI_LOOP:
	je INFI_LOOP
	hlt
```

## Type 3

In this type of challenges, inproper filters are applied to the program so we could escape from the sandbox. To two triks bypass inproper filters.

* Retf to X86 from X64
* x32 ABI


```s
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x11 0xc000003e  if (A != ARCH_X86_64) goto 0019
```

If the filter doesn't check the arch as the above rules, we could jump to x86 mode with `retf` and call x86 syscall to bypass the filter:

```s
	; p64(retf)+p32(0x23)+p32(addr)
    mov eax,offset .orw
    mov rbx,0x2300000000
    xor rax,rbx
    push rax
    retf 
```

If the filter doesn't check if the syscall larger than 0x40000000, we could use x32 ABI to bypass the filter
```s
 line  CODE  JT   JF      K
=================================
...
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x0f 0x00 0x40000000  if (A >= 0x40000000) goto 0019
-----
A = 0x40000000 + sys_read 
syscall(A,x,x,x);
```

## Type 4


# 0x03 challenge S2

## Intro
It's a challenge based on [sandboxed-api@google][2], which is a c/c++ library. With this library, we can create our sandbox policy and apply to a executor(a program). While running, the sandbox would monitor the syscalls of sandboxee(the running progress in sandbox). 

The following code is the source code of the challenge and in this challenge, our goal is writing a program and use it read a file in the sandbox with limited syscalls.


```c++
...
int main() {
    ...
  int fd = ReadBinary();
  std::string path = absl::StrCat("/proc/", getpid(), "/fd/", fd);
  auto policy = sandbox2::PolicyBuilder()
    .AllowStaticStartup()
    .AllowFork()
    .AllowSyscalls({
      __NR_seccomp,
      __NR_ioctl,
    })
    .AllowExit()
    .AddFile(sapi::file_util::fileops::MakeAbsolute("flag", sapi::file_util::fileops::GetCWD()))
    .AddDirectory("/dev")
    .AddDirectory("/proc")
    .AllowUnrestrictedNetworking()
    .BuildOrDie();
  std::vector<std::string> args = {"sol"};
  auto executor = std::make_unique<sandbox2::Executor>(path, args);
  sandbox2::Sandbox2 sandbox(std::move(executor), std::move(policy));
  sandbox2::Result result = sandbox.Run();
  if (result.final_status() != sandbox2::Result::OK) {
    warnx("Sandbox2 failed: %s", result.ToString().c_str());
  }
}
```

In main function, the program would read binary from users and run the program with the sandbox policy.  As you can see, it's quite simple. We don't even have some basic syscalls, such as open, read, and write. However, we have some extra syscalls to help us escape from the sandbox, including fork, clone, seccomp, ioctl. It's actually a great hint of the challenge but I didn't notice that. 

## Background Knowledge

It's known that we can't use `SYS_seccomp` to change applied bpf rules. 


# Tricks


[0]: https://pwnable.tw/challenge/#2
[1]: https://github.com/david942j/seccomp-tools
[2]: https://github.com/google/sandboxed-api
[3]: https://n132.github.io/2022/03/24/sbnote.html
[4]: https://n132.github.io/2021/10/01/NaiveHeap.html
[5]: https://ctftime.org/writeup/18792
[6]: https://n132.github.io/2018/11/25/NUCA-Steak.html
[7]: https://github.com/yvrctf/2015/tree/master/babyplaypenfence
[8]: https://man7.org/linux/man-pages/man2/prctl.2.html