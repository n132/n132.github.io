---
title: "eBPF-Guide"
date: 2022-07-03 18:52:21
tags: 
layout: default
---

# 0x00 Prologue
Last weekend, I met a sandbox challenge, s2, on gctf-2022. However, I can't solve it because I don't know the stories about the seccomp. I would go through eBPF in this passage.


# 0x01 Related tools

## seccomp-tools
[seccomp-tools][1] is a good tool to dump the seccomp rules.

```sh
seccomp-tools dump ./vul
```

# 0x02 Seccomp in CTF

 
# Examples

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

It's known that we can't use `SYS_seccomp` to change applied ebpf rules. and 


[1]: https://github.com/david942j/seccomp-tools
[2]: https://github.com/google/sandboxed-api