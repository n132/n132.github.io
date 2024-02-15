---
layout: page
title: Kernel
permalink: /kernel/
---
Kernel Cheatsheet


# vmlinux

- Using `gdb vmlinux` to debug the kernel makes life easier
- If you compile the kernel with keeping debug symbols, you'll find vmlinux at the root of source directory


# extract-vmlinux

- [extract-vmlinux][5] is a tool that extract vmlinux from bzImage.
- Usgae: `extract-vmlinux ./bzImage > vmlinux.raw`

# vmlinux-to-elf


- A [tool][6] to recover symbols from `kallsyms`
- Installation: `pip3 install --upgrade git+https://github.com/marin-m/vmlinux-to-elf`
- Usage: `vmlinux-to-elf ./vmlinux.raw vmlinux`


# Compile Kernel
If there is an error for 
`make[3]: *** No rule to make target 'debian/canonical-certs.pem', needed by 'certs/x509_certificate_list'.  Stop.`

```
#
# Certificates for signature checking
#
CONFIG_MODULE_SIG_KEY="certs/signing_key.pem"
CONFIG_SYSTEM_TRUSTED_KEYRING=y
CONFIG_SYSTEM_TRUSTED_KEYS=""
CONFIG_SYSTEM_EXTRA_CERTIFICATE=y
CONFIG_SYSTEM_EXTRA_CERTIFICATE_SIZE=4096
CONFIG_SECONDARY_TRUSTED_KEYRING=y
CONFIG_SYSTEM_BLACKLIST_KEYRING=y
CONFIG_SYSTEM_BLACKLIST_HASH_LIST=""
CONFIG_SYSTEM_REVOCATION_LIST=y
CONFIG_SYSTEM_REVOCATION_KEYS=""
# end of Certificates for signature checking
```

# Depress Filesystem

```bash
#!/binsh
mkdir fs
cd fs
cpio -idmv < ../rootfs.cpio
touch exp.c 
cd ..
code .
```

# Prepare Run Script: x.sh

```bash
#!/bin/sh
gcc ./fs/exp.c -masm=intel -o ./fs/exp -lx -lpthread --static -w &&\
echo "[+] Compile - Done" &&\
cd ./fs &&\
find . | cpio -o --format=newc > ../rootfs.cpio &&\
cd .. &&\
echo "[+] Filesystem - Done" &&\
echo "[...] run.sh" &&\
./run.sh
```

> Tip: Remove `exec` in the script to make IO easier

# Template
```
#include "libx.h"
int main(){
    puts("n132>>");
}
```
# libx

`https://github.com/n132/libx/tree/main`


# ret2usr
```
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
```
# Run
```
#!/bin/sh
qemu-system-x86_64 \
    -m 64M \
    -nographic \
    -kernel ./bzImage \
    -initrd  ./rootfs.img \
    -append "root=/dev/ram rw console=ttyS0 oops=panic panic=1 kalsr" \
    -smp cores=2,threads=1 \
    -cpu kvm64

```

# init
```
#!/bin/sh
echo "N132 - INIT SCRIPT"
mkdir /tmp
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev
mount -t debugfs none /sys/kernel/debug
mount -t tmpfs none /tmp
insmod /pwn.ko
echo -e "Boot took $(cut -d' ' -f1 /proc/uptime) seconds"
setsid /bin/cttyhack setuidgid 0 /bin/sh
poweroff -f
```

# Compile-the-Testcase
```s
obj-m += <name>.o

KDIR =/home/n132/Desktop/kernel/linux-5.4.98/

all:
    $(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
    rm -rf *.o *.ko *.mod.* *.symvers *.order
```

# Filesystem
```s
wget https://busybox.net/downloads/busybox-1.32.1.tar.bz2
cd busybox-1.32.1
make -j8 bzImage
make install
cd _install
mkdir -p  proc sys dev etc/init.d
vim init
chmod +x ./init
cd /home/n132/Desktop/kernel
cp -r ./busybox-1.32.1/_install .
```

[5]: https://github.com/torvalds/linux/blob/master/scripts/extract-vmlinux
[6]: https://github.com/marin-m/vmlinux-to-elf