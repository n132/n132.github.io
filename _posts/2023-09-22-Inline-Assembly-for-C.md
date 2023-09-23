---
title: "Inline Assembly for C"
date: 2023-09-2 20:56:12
tags: 
layout: default
---
# TL;DR

Use the C language function `asm`` to write shellcode. 

This article is a part of my cheat sheet.

# 0x00 Prologue
Two weeks ago, I used c language to talk to the target vulnerable binary and executed the sent shellcode to get a shell. But I feel it's verbose to use Python to generate the shell code. So I read several articles about writing ASM in c language.

# 0x01 Resource

http://brieflyx.me/2019/linux-tools/gcc-in-ctf/

# 0x02 Why not ATT

I am not familiar with ATT syntax since I spent most of my time on gdb which shows Intel syntax.
So I write everything in Intel syntax. The following example doesn't include any library and implement `orw` and `shell`. 

# 0x03 Example 

```c
// gcc -nostdlib ./main.c -o ./main  -e entry
asm(
    "entry:\n"
    "call main\n"
);

int shell();
int write(int fd,char*buf,long size);
int read(int fd,char*buf,long size);
int open(char *path,long mod);

int main(){
    char buf[0x10]={0};
    write(1,"Enter \"n132\" to spawn a shell:\n",31);
    read(0,buf,0x10);
    if(buf[0]=='n' && buf[1]=='1' && buf[2]=='3' && buf[3]=='2')
        shell();
    return 0;
}
asm(
    "shell:\n"
    ".intel_syntax noprefix;\n"
    "mov rdi,0x68732f6e69622f\n"
    "push rdi\n"
    "mov rdi,rsp\n"
    "xor rsi,rsi\n"
    "xor rdx,rdx\n"
    "mov rax,0x3b\n"
    "syscall\n"
    "ret\n"
    ".att_syntax prefix;"
);
asm(
    "open:\n"
    ".intel_syntax noprefix;\n"
    "mov rax,2\n"
    "syscall\n"
    "ret\n"
    ".att_syntax prefix;"
);
asm(
    "read:\n"
    ".intel_syntax noprefix;\n"
    "mov rax,0\n"
    "syscall\n"
    "ret\n"
    ".att_syntax prefix;"
);
asm(
    "write:\n"
    ".intel_syntax noprefix;\n"
    "mov rax,1\n"
    "syscall\n"
    "ret\n"
    ".att_syntax prefix;"
);
```