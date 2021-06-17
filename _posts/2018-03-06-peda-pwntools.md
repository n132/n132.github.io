---
title: peda_pwntools
date: 2018-03-06 16:00:30
tags: basic
layout: post

---
pedap_wntools
<!--more-->

好久没看pwn
罪过罪过
安心学习安心学习

之前很多东西都忘记了今天重新温习了一下

1.peda安装
	git clone https://github.com/longld/peda.git ~/peda
	echo "source ~/peda/peda.py" >> ~/.gdbinit
2.pwntools安装
	pip install pwntools

3.gdb-peda
	
	http://blog.csdn.net/water_cow/article/details/7214054
	

	gdb a.out#调试a.out
	finish#结束当前函数
	n#next
	s#step
	c#continue
	b#break
		tbreak#一次后失效的断点
		delete/disable/enable  breakpoint 1#删除/禁用/允许 指定编号的断点
		break if#条件断点，满足特定条件后才会中断
				 break 46 if testsize==100
	start#start
	r#run
	k#kill
	q#quit
	p#print
	i#info
		info break：显示断点信息，下面断点部分详述。
		(gdb)info break
		info local：显示当前函数中的局部变量信息。
		(gdb)info local
		info var：系那是所有的全局和静态变量名称。
		(gdb)info var
		info func：显示所有的函数名称。
		(gdb)info func
		info prog：显示被调试程序的执行状态。
		(gdb)info prog
		info files：显示被调试文件的详细信息。
		(gdb)info files
		whatis：显示变量的类型 
		如程序中定义struct timeval var；
		(gdb) whatis var 
		type = struct timeval
		ptype：比whatis的功能更强，它可以提供一个结构的定义
	set args#设定传递给程序的参数
	pattc#生成有规律的字符串 如pattc 100

	

4.pwntools：
	r = remote('ip or 域名', 端口)#链接
	r = process("./test")#本地调试
	r.sendline()#send+换行
	r.recv()#接受
	r.interactive()#交互
	gdb.attach(r)#用gdb调试
	asm(shellcraft.sh())#asm将字符串转为机器码
	p32/p64()#打包 为32位或者64位 p换成u为解包
	cyclic()
	#Cyclic pattern 生成有规律的字符串与gdb中的patt相似
	#例如：cyclic(100) cyclic_find(0x12313212) cyclic_find("avc")
	shellcraft.sh()#简单的shellcode 通常与asm()一起使用
