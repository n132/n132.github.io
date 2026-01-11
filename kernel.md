---
layout: page
title: Kernel
permalink: /kernel
---
Intro-level Kernel Cheatsheet

# Local Enviroment for Testing

Kzone: https://github.com/n132/KZone.git

# Exploitation Library

Libx: `https://github.com/n132/libx.git`


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


# CPIO Filesystem 

```bash
#!/binsh
mkdir fs
cd fs
cpio -idmv < ../rootfs.cpio
touch exp.c 
cd ..
code .
```

# Run Script Wrapper

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

# fs-init
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

# Submitter

- disable shell echoing: `stty -echo`

```py
from pwn import *


EXPLOIT_PATH = '/tmp/exploit'

SERVER = "dicec.tf"
PORT = 32069

SHELL_PROMPT = '$ '


def get_splitted_encoded_exploit():
    split_every = 256
    # Change the name to your exploit path
    with open('./fs/exp', 'rb') as exploit_file:
        exploit = base64.b64encode(exploit_file.read())
    return [exploit[i:i+split_every] for i in range(0, len(exploit), split_every)]


def upload_exploit(sh):
    chunks_sent = 0
    splitted_exploit = get_splitted_encoded_exploit()
    for exploit_chunk in splitted_exploit:
        print(f'[*] Sending a chunk ({chunks_sent}/{len(splitted_exploit)})')
        sh.sendlineafter(
            SHELL_PROMPT, f'echo {exploit_chunk.decode()} | base64 -d >> {EXPLOIT_PATH}')
        chunks_sent += 1

r = remote(SERVER, PORT)
# r = process("./run.sh")
upload_exploit(r)
# # When finished, your exploit will be in /tmp directory. Good luck.
r.sendline(b"cd /tmp")
# r.sendline(b"gunzip /exploit.gz")
r.recvuntil(b"/tmp $")
r.sendline("ls -a")
print(r.recvline())
print(r.recvline())
# print(r.recvline())
r.interactive()
```


[5]: https://github.com/torvalds/linux/blob/master/scripts/extract-vmlinux
[6]: https://github.com/marin-m/vmlinux-to-elf