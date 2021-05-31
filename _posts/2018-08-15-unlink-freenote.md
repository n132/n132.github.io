---
title: unlink_freenote
date: 2018-08-15 13:43:30
tags: pwn heap
layout: post
---
a problem about unlink
freenote
general way to use unlink
<!--more-->
# unlink()
[souce]

```c
#define unlink(AV, P, BK, FD) {                                            
    if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))      
      malloc_printerr ("corrupted size vs. prev_size");                              
    FD = P->fd;                                                                      
    BK = P->bk;                                                                      
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))                      
      malloc_printerr ("corrupted double-linked list");                              
    else {                                                                      
        FD->bk = BK;                                                              
        BK->fd = FD;                                                              
        if (!in_smallbin_range (chunksize_nomask (P))                              
            && __builtin_expect (P->fd_nextsize != NULL, 0)) {                      
            if (__builtin_expect (P->fd_nextsize->bk_nextsize != P, 0)              
                || __builtin_expect (P->bk_nextsize->fd_nextsize != P, 0))    
              malloc_printerr ("corrupted double-linked list (not small)");   
            if (FD->fd_nextsize == NULL) {                                      
                if (P->fd_nextsize == P)                                      
                  FD->fd_nextsize = FD->bk_nextsize = FD;                      
                else {                                                              
                    FD->fd_nextsize = P->fd_nextsize;                              
                    FD->bk_nextsize = P->bk_nextsize;                              
                    P->fd_nextsize->bk_nextsize = FD;                              
                    P->bk_nextsize->fd_nextsize = FD;                              
                  }                                                              
              } else {                                                              
                P->fd_nextsize->bk_nextsize = P->bk_nextsize;                      
                P->bk_nextsize->fd_nextsize = P->fd_nextsize;                      
              }                                                                      
          }                                                                      
      }                                                                              
}
```
CHECK 1:
```c
if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))      
      malloc_printerr ("corrupted size vs. prev_size"); 
```
检查自己的size位和nextchunk的prevsize是否相等
CHECK 2:
```c
if (__builtin_expect (FD->bk != P || BK->fd != P, 0))                      
      malloc_printerr ("corrupted double-linked list"); 
``` 
错误时报：corrupted double-linked list
检查FD->bk和 BK->fd的值是否为P（chunk address）
绕过可以通过
FD<-(&P-0x18)
BK<-(&P-0x10)
## REST:
余下部分关于smallbin和largebin的情况日后遇到再细看

## 常见调用
最常见调用的unlink的地方可能是free一个chunk之后发现其相邻chunk已经被free时:
```arm
    if (!prev_inuse(p)) {
      prevsize = prev_size (p);
      size += prevsize;
      p = chunk_at_offset(p, -((long) prevsize));
      unlink(av, p, bck, fwd);
    }
    if (nextchunk != av->top) {
      /* get and clear inuse bit */
      nextinuse = inuse_bit_at_offset(nextchunk, nextsize);
      /* consolidate forward */
      if (!nextinuse) {
        unlink(av, nextchunk, bck, fwd);
        size += nextsize;
      } else
```
源码大意是检查当前的prev_inuse位如果前一个chunk未在使用那么就调用unlink()

检查下一个chunk是不是topchunk如果不是那么就检查下一个chunk的nextchunk的pre_inuse 位

这里注意如果是向前合并chunk那么是unkink(,pre_chunk,,)
向后合并是unlink(,next_chunk,,)

unlink
## 0x00 Unsorted BIN ATK
大致流程
* free 后没有将 ptr 置为0
* 可以先malloc一些chunk然后free掉 但是他们的指针依旧指向原来位置
* malloc一个较大的chunk在里面伪造3个chunk
    第一个假装已经被free，注意size，fd，bk
    第二个还未被free，注意presize，size
    第三个未被free，注意size
    第四个未被free，注意size（如果直接可以构造到topchunk那就不需要第四个如果需要构造第四个的话为了防止unlink的第二次检查要构造size）
* 得到ptr指向&ptr-0x18
* 改写ptr
* 改写ptr指向位置的实现不可描述的目的
## 0x01 

## sample freenote is coming

[souce]:https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#_M/unlink