---
title: "Kernel Pwn: How to compile Kernel Module?"
date: 2023-09-29 18:58:21
tags: 
layout: default
---
# TL;DR

- Compile kernel (https://mirrors.edge.kernel.org/pub/linux/kernel/) (Enable loadable module support)
- Compile Kernel Module
- Compile busybox to generate filesystem (https://busybox.net/downloads/)（Static Linked, Create Init）


# 0x00 Prologue

I am not familiar with linux kernel so it's hard to tell the size of a structure when playing the challenges. Some of the structures would have different sizes in different versions. It's painful to remember all of them. Thus, I decided to compile a kernel module to print the size of the structs when it's needed.


To compile a kernel module and run it on a specific linux kernel, we need:


- Linux Kernel: bzimage
- Filesystem: rootfs.cpio
- Qemu Script: run.sh


I generate this cheatsheet according to [CTF-Wiki][2]

# 0x01 Compile Linux Kernel


First, we should know the kernel version we want to compile. Normally, we can just run the challenge and run `uname -a` to get the kernel version and go to [this][1] website to download the same version of the kernel.

```sh
wget https://mirrors.edge.kernel.org/pub/linux/kernel/v5.x/linux-5.14.16.tar.gz
tar xvf ./linux-5.14.16.tar.gz
cd linux-5.14.16/
make menuconfig
make -j`nproc`
```

Then, we need to config it and compile it with the above commands. To make compiling faster, I only selected "Enable loadable module support". 


> (Optional) If you want to debug the kernel with symbols you can also select "Kernel Hacking -> Compile-time checks and compiler options -> Compile the kernel with debug info"


After compiling the kernel, you can find the `bzimage` file at `arch/x86/boot/bzImage`.

# 0x02 Compile Debug Kernel Module

To compile a kernel module, we need the source code of the module and the make file as follows.


The template of kernel module source code(`n132.c`):
```c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/msg.h>
MODULE_LICENSE("Dual BSD/GPL");
static int ko_n132_init(void)
{
    struct msg_msg p;
    printk("n132>\n%d\n",sizeof(p));
    return 0;
}
static void ko_n132_exit(void)
{
    printk("Bye Bye~\n");
}
module_init(ko_n132_init);
module_exit(ko_n132_exit);
```

Makefile:
```makefile
obj-m += ko_n132.o

KDIR =/root/KCP/linux-5.14.16/
all:
        $(MAKE) -C $(KDIR) M=$(PWD) modules
clean:
        rm -rf *.o *.ko *.mod.* *.symvers *.order
```

After executing `make`, you'll get the kernel module `ko_n132.ko`.


# 0x03 Build FileSystem

To build a file system, we need to config and compile busybox by following commands. Also, if you don't want to prepare shared libraries, you can select `Settings-> Build Options-> Build static binary (no shared libs)`

```sh
wget wget https://busybox.net/downloads/busybox-1.32.1.tar.bz2
tar xvf ./busybox-1.32.1.tar.bz2
cd busybox-1.32.1
make menuconfig
make -j`nproc`
make install
cd _install
mkdir -p proc sys dev etc
touch init
chmod +x init
```

The following script is a template for `/init` file.
```bash
#!/bin/sh
echo "[---------------[n132]---------------]"
mkdir /tmp
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev
mount -t debugfs none /sys/kernel/debug
mount -t tmpfs none /tmp
echo -e "Boot took $(cut -d' ' -f1 /proc/uptime) seconds"
setsid /bin/cttyhack setuidgid 0 /bin/sh
poweroff -f
```

Then, we can move the kernel module we compiled to the file system and pack it with cpio:

```sh
find . | cpio -o --format=newc > ../rootfs.cpio
```

# 0x03 Qemu Script

Run the following template you'll get a shell of your compiled linux kernel.

```sh
qemu-system-x86_64 \
  -m 2G \
  -initrd  ./rootfs.cpio \
  -kernel ./bzImage -nographic \
  -monitor /dev/null -s \
  -append "kpti=1 +smep +smap nokaslr root=/dev/ram rw console=ttyS0 oops=panic panic=0 init=/init quiet"
```


After getting the shell, you can run `/sbin/insmod ko_n132.ko && dmesg` to check the size of `struct msg_msg`.


# 0x04 pahole

I got a tool to get all the structures' size while reading other's article: `https://manpages.ubuntu.com/manpages/impish/man1/pahole.1.html`.

You can install and use it by 
```bash
apt install pahole
pahole < bzImage > SS
```

By default, it's shows x64 version of result and you can also set `--header elf32_hdr` to get the result of x32 version.

# 0x03 Epilogue

This is a cheat sheet for kernel module compilation.


[1]: https://mirrors.edge.kernel.org/pub/linux/kernel/
[2]: https://ctf-wiki.org/pwn/linux/kernel-mode/environment/readme/


