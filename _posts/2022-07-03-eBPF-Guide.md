---
title: "CTF-eBPF-Guide"
date: 2022-07-03 18:52:21
tags: 
layout: default
---

# 0x00 Prologue
Last weekend, I met a sandbox challenge, s2, on gctf-2022. However, I can't solve it because I don't know the stories about the seccomp. I would go through eBPF in this passage.

If you are a pwner, you probably know seccomp. It's common used in pwn challenge for meny purposes.

First, it could be used to require the folks run complex instruction rather than hitting one_gadget. For this purpose, the eBPF would allow some basic syscalls, such as read, write and open. Most time, it would be a allowed-syscall-list. This type of challenge doesn't require people to have additional knowleged about seccomp and it focuses on the challenge itself. 

The second type of challenge would focus on a specific syscall. The challenge author wants to introduce a specific syscall to the people and (s)he would forbid (part of) basic syscalls such as execve, open, ... And the filter would be like a blacklist. From this type of challenges, I learned tremendous interesting syscalls and I'll just introduce some of them in this passage.

The third type of challenge would focus more on the eBPF/Seccomp itself. It would give a wrong configured filter so it's more like a sandbox escaping challenge rather than a pwn challenge. There are kinds of basic escaping skills 

* The First challenge is the most typical one

| Type | Challenges|
|--|--|
|0x1| [pwnable.tw-orw][0], [0CTF-NaiveHeap][4] |
|0x2| [sbnote][3] |
|0x3| orw|
|0x1| orw|

# 0x01 Seccomp
If you run `man 2 seccomp`, you would get the man page of the wrapper of syscall seccomp and it's one of the baisc interfaces to the user space.

`int seccomp(unsigned int operation, unsigned int flags, void *args);`

There are four supported operations: SECCOMP_SET_MODE_STRICT, SECCOMP_SET_MODE_FILTER, SECCOMP_GET_ACTION_AVAIL, and SECCOMP_GET_NOTIF_SIZES. 

| Operation | Desc | Value |
|--| --| --|
| SECCOMP_SET_MODE_STRICT | only allow read, write, and exit | 0x0
| SECCOMP_SET_MODE_FILTER | apply provided eBPF in args  | 0x1
| SECCOMP_GET_ACTION_AVAIL | Test to see if an action is supported by the kernel. | 0x2
| SECCOMP_GET_NOTIF_SIZES | Get the sizes of the seccomp user-space notification structures.  | 0x3


The most significant one is `SECCOMP_SET_MODE_FILTER`, it's used to 


## seccomp-tools
[seccomp-tools][1] is a good tool to dump the seccomp rules.

```sh
seccomp-tools dump ./vul
```

# 0x02 Seccomp in CTF

 
# Examples
I'll write the examples in more basic ways to learn more details about seccomp. 
## 
```c++
#include <seccomp.h>
#include <unistd.h>
#include <syscall.h>
#include <iostream>
using namespace std;

int main(){
    // STRICT MODE 
    syscall(__NR_seccomp,SECCOMP_SET_MODE_STRICT,0,0);
    syscall(__NR_write,1,"Read, write, and exit are avaliable\n",37);
    char buf[0x10]={};
    syscall(__NR_read,0,buf,0xf);
    syscall(__NR_write,1,"But fork is forbidden\n",23);
    fork();
}
```
## linux/seccomp
```python
//gcc -g simple_syscall_seccomp.c -o simple_syscall_seccomp -lseccomp
#include <unistd.h>
#include <seccomp.h>
#include <linux/seccomp.h>

int main(void){
	scmp_filter_ctx ctx;
	ctx = seccomp_init(SCMP_ACT_KILL);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 0);
	seccomp_load(ctx);

	char * filename = "/bin/sh";
	char * argv[] = {"/bin/sh",NULL};
	char * envp[] = {NULL};
	write(1,"Shell Test\n",24);
	syscall(59,filename,argv,envp);//execve
	return 0;
}
```

## prctl

Struction of filter:
```c
struct sock_filter {	/* Filter block */
	__u16	code;   /* Actual filter code */
	__u8	jt;	/* Jump true */
	__u8	jf;	/* Jump false */
	__u32	k;      /* Generic multiuse field */
};
struct sock_fprog {	/* Required for SO_ATTACH_FILTER. */
	unsigned short		len;	/* Number of filter blocks */
	struct sock_filter *filter;
};
```

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
	
	char * filename = "/bin/sh";
	char * argv[] = {"/bin/sh",NULL};
	char * envp[] = {NULL};
	write(1,"i will give you a shell\n",24);
	write(1,"1234567812345678",0x10);
	syscall(0x4000003b,filename,argv,envp);//execve
	return 0;
}
```

# Typical filters
> Tip: seccmp uses malloc/free while prctl doesn't

## orw + mprotect
```c
	//orw + exit_group + mprotect
	prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0);
	struct sock_filter sfi[] = {
	{0x20,0x00,0x00,0x00000004},
	{0x15,0x00,0x0a,0xc000003e},
	{0x20,0x00,0x00,0x00000000},
	{0x35,0x00,0x01,0x40000000},
	{0x15,0x00,0x07,0xffffffff},
	{0x15,0x05,0x00,0x00000000},
	{0x15,0x04,0x00,0x00000001},
	{0x15,0x03,0x00,0x00000002},
	{0x15,0x02,0x00,0x00000003},
	{0x15,0x01,0x00,0x0000000a},
	{0x15,0x00,0x01,0x000000e7},
	{0x06,0x00,0x00,0x7fff0000},
	{0x06,0x00,0x00,0x00000000}
	};
	struct sock_fprog sfp = {13,sfi};
	prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&sfp);
```

## orw
```c
//gcc -g simple_syscall_seccomp.c -o simple_syscall_seccomp -lseccomp
#include <unistd.h>
#include <seccomp.h>
#include <linux/seccomp.h>
int main(void){
	scmp_filter_ctx ctx;
	ctx = seccomp_init(SCMP_ACT_KILL);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
	seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
	seccomp_load(ctx);

	char * filename = "/bin/sh";
	char * argv[] = {"/bin/sh",NULL};
	char * envp[] = {NULL};
	write(1,"i will give you a shell\n",24);
	syscall(59,filename,argv,envp);//execve
	return 0;
}
```

# challenge S2

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

It's known that we can't use `SYS_seccomp` to change applied ebpf rules. 

[0]: https://pwnable.tw/challenge/#2
[1]: https://github.com/david942j/seccomp-tools
[2]: https://github.com/google/sandboxed-api
[3]: https://n132.github.io/2022/03/24/sbnote.html
[4]: https://n132.github.io/2021/10/01/NaiveHeap.html