---
title: string&vector
date: 2019-03-08 14:03:34
tags:
---
c++一点不会...初级学起..
<!--more-->
# String
环境
```sh
➜  string g++ --version
g++ (Ubuntu 5.4.0-6ubuntu1~16.04.11) 5.4.0 20160609
Copyright (C) 2015 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.  There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

➜  string /lib/x86_64-linux-gnu/libc-2.23.so 
GNU C Library (Ubuntu GLIBC 2.23-0ubuntu11) stable release version 2.23, by Roland McGrath et al.
Copyright (C) 2016 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.
Compiled by GNU CC version 5.4.0 20160609.
Available extensions:
	crypt add-on version 2.1 by Michael Glad and others
	GNU Libidn by Simon Josefsson
	Native POSIX Threads Library by Ulrich Drepper et al
	BIND-8.2.3-T5B
libc ABIs: UNIQUE IFUNC
For bug reporting instructions, please see:
<https://bugs.launchpad.net/ubuntu/+source/glibc/+bugs>.
➜  string 
```
//之前c++的课...没学好做起题来贼难受...现在自己摸索一下..过程不写了直接写结果.看源码c++还不适应...先不看...
`string s;`声明一个string的实例s
```python
n132>>> p sizeof(string)
$4 = 0x20
```
没输入东西前长这样
```python
n132>>> x/8gx 0x6022e0
0x6022e0 <b[abi:cxx11]>:	0x00000000006022f0	0x0000000000000000
0x6022f0 <b[abi:cxx11]+16>:	0x0000000000000000	0x0000000000000000
```
输入1-15字节时
```python
n132>>> x/8gx 0x6022e0
0x6022e0 <b[abi:cxx11]>:	0x00000000006022f0	0x000000000000000c
0x6022f0 <b[abi:cxx11]+16>:	0x7265696e7265696e	0x000000007265696e
```
输入16-30字节时
```python
n132>>> x/8gx 0x6022e0
0x6022e0 <b[abi:cxx11]>:	0x0000000000615030	0x000000000000001b
0x6022f0 <b[abi:cxx11]+16>:	0x000000000000001e	0x0041412441414241
0x602300 <std::__ioinit>:	0x0000000000000000	0x0000000000000000
0x602310:	0x0000000000000000	0x0000000000000000
n132>>> x/8gx 0x0000000000615030
0x615030:	0x4173414125414141	0x6e41412441414241
0x615040:	0x41412d4141434141	0x0000000000414128
```
...
虽然没看源码,结合材料得到以下.
```s
第一个域指向value,第二个域表示string的size或者说是length

* 当string的length小于等于15时第三四个域用来储存string内容

* 当string的length大于15时改用heap来储存内容,第三个域表示当前chunk可以储存的阈值capcity.

阈值变化: 15->30->60->120->...

ps:由于输入长字符串时发现fastbin中有一些装着部分字符串的chunk,估计string可能是用尝试的办法..不过这看起来有些蠢..有朝一日去读读源码
···
n132>>> heapinfo
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x615020 --> 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x615050 --> 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
(0x90)     fastbin[7]: 0x0
(0xa0)     fastbin[8]: 0x0
(0xb0)     fastbin[9]: 0x0
                  top: 0x615130 (size : 0x1fed0) 
       last_remainder: 0x0 (size : 0x0) 
            unsortbin: 0x0
n132>>> searchmem 0x615020
Searching for '0x615020' in: None ranges
Found 2 results, display max 2 items:
libc : 0x7ffff7a4f920 --> 0x615020 --> 0x0 
libc : 0x7ffff7a4fb30 --> 0x615020 --> 0x0 
···
悬空指针但是没有memset为0
```

# vector
维克托？
```python
n132>>> p nier
$8 = std::vector of length 1, capacity 2 = {"1"}
n132>>> p sizeof(nier)
$9 = 0x18
```
大小是0x18字节
三个域分别是:_M_start表示起始地址,_M_finish表示结束地址,_M_end_of_storage表示当前chunk最大储存地址末端.

* push_back(a):
向vector尾部加a.
如果空间不够会malloac一个新的chunk完成数据拷贝后free掉原来的chunk(也没用memset为0)

所以加着加着就会出现一堆被free掉的chunk
```python
n132>>> heapinfo
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x615c10 --> 0x0
```
* pop_back()
仅减少_M_finish调用destuctor不做delete




---








