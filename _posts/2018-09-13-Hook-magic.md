---
title: Hook_magic
date: 2018-09-13 21:52:37
tags: pwn basic
layout: default
---
how hook works
<!--more-->
# Hook's Magic
粗浅的理解，可能理解不对的地方很多。

最近遇到好多题通过hook来跳shell，好处是只要泄露了libc并且有任意写的能力就可以将one_gadget写入libc中的__malloc_hook(例)在调用malloc的时候就会跳到one_gadget。

## 0x00 What's Hooks?
libc中的hook机制，主要用于内存分配，它就像无处不在的钩子一样，一旦设置好了 hook，我们就可以在内存分配的地方随心所欲地做我们想做的事情。(摘自别人博客)

上源码------>
malloc.c
```c
void *
__libc_malloc (size_t bytes)
{
  mstate ar_ptr;
  void *victim;
  void *(*hook) (size_t, const void *)
    = atomic_forced_read (__malloc_hook);
  if (__builtin_expect (hook != NULL, 0))
    return (*hook)(bytes, RETURN_ADDRESS (0));
....
....
```
之前只知道malloc的主要实现在int_malloc，事实上会先检查是否存在hook如果存在hook那么执行hook指向的函数.

由于c基础太差 这里插入一些关于函数指针的内容

## 0x01 函数指针
函数指针，指向函数的指针定义方法如下

返回类型 (*函数指针名称)(参数类型,参数类型,参数类型，…);

看起来和函数的定义方法相似只是要在指针名称前加一个*

```c
#include<stdio.h>
void (*p)(int a);
void add(int a) 
{
	printf("%d\n",a+1);
}
int main()
{
	add(11);
	p=add;
	p(12);
}
```
然后我们上gdb查看一下实现
```c
   0x40054b <main>:	push   rbp
   0x40054c <main+1>:	mov    rbp,rsp
   0x40054f <main+4>:	mov    edi,0xb
=> 0x400554 <main+9>:	call   0x400526 <add>
   0x400559 <main+14>:	mov    QWORD PTR [rip+0x200adc],0x400526        # 0x601040 <p>
   0x400564 <main+25>:	mov    rax,QWORD PTR [rip+0x200ad5]        # 0x601040 <p>
   0x40056b <main+32>:	mov    edi,0xc
   0x400570 <main+37>:	call   rax

```
看罢还是很好理解的 只是赋值形式初见 一时还看不顺眼。

## 0x02 How Hooks Works
hook在glibc/malloc/malloc.c中的定义
```c
/* Hooks for debugging and user-defined versions. */
extern void (*__free_hook) (void *__ptr, const void *);
extern void *(*__malloc_hook)(size_t __size, const void *);
extern void *(*__realloc_hook)(void *__ptr, size_t __size, const void *);
extern void *(*__memalign_hook)(size_t __alignment, size_t __size, const void *);
extern void (*__after_morecore_hook) (void);
```
在没调用malloc之前__malloc_hook->malloc_hook_ini

```c
static void *
malloc_hook_ini (size_t sz, const void *caller)
{
  __malloc_hook = NULL;
  ptmalloc_init ();
  return __libc_malloc (sz);
}
```
从malloc_hook_ini中看到调用一次后将__malloc_hook置0为并返回____libc_malloc(sz)

所以只要将hook指向的地址改写就可以jump改写后的地址