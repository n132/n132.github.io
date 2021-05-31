---
title: Magic-of-int
date: 2018-03-09 15:53:24
tags: pwn
layout: post
---
整数异常
<!--more-->
3.3.2 整数的异常
CTFALLINONE 3.3.2 摘记
关于整数的异常情况主要有三种：
	溢出
	只有有符号数才会发生溢出。有符号数最高位表示符号，在两正或两负相
	加时，有可能改变符号位的值，产生溢出
	溢出标志 OF 可检测有符号数的溢出
	回绕
	无符号数 0-1 时会变成最大的数，如 1 字节的无符号数会变为 255 ，
	而 255+1 会变成最小数 0 。
	进位标志 CF 可检测无符号数的回绕
	截断
	将一个较大宽度的数存入一个宽度小的操作数中，高位发生截断
看到这里感觉这些并没什么用...too young too simple

漏洞多发函数：
	memcpy() && strncpy()
	第三个参数size_t n
	//typedef unsigned int size_t;

漏洞示例：
ex1_溢出：
	char buf[80];
	void vulnerable() {
	int len = read_int_from_network();
	char *p = read_string_from_network();
	if (len > 80)
	{
	error("length too large: bad dog, no cookie for you!");
	return;
	}
	memcpy(buf, p, len);
	}
在这里可以看到len是int 对len有个判断限制80个字节但是负数显然小于80
如果攻击者给 len 赋于了一个负数，则可以绕过 if 语
句的检测，而执行到 memcpy() 的时候，由于第三个参数是 size_t 类型，负
数 len 会被转换为一个无符号整型，它可能是一个非常大的正数，从而复制了大
量的内容到 buf 中，引发了缓冲区溢出。

ex2_回绕：
	void vulnerable() {
	size_t len;
	// int len;
	char* buf;
	len = read_int_from_network();
	buf = malloc(len + 5);
	read(fd, buf, len);
	...
	}

上面是memcpy多开了很多空间这里因为len是无符号数可以通过回绕来控制只分配少量空间而写入大量数据造成缓冲区溢出
ex3_截断：
	void main(int argc, char *argv[]) {
	unsigned short int total;
	total = strlen(argv[1]) + strlen(argv[2]) + 1;
	char *buf = (char *)malloc(total);
	strcpy(buf, argv[1]);
	strcat(buf, argv[2]);
	...
	}
这里是先计算两个串长度和然后开辟空间后先复制第一个串然后将第二个串拼接在第一个后面
这里可以构造两个串长度导致其和+1大于short表示范围then在过少的空间写入大量数据造成溢出

程序中 strlen() 返回类型是 size_t ，却被存储在无符号字符串类型
中，任意超过无符号字符串最大上限值（256 字节）的数据都会导致截断异常。当
密码长度为 261 时，截断后值变为 5，成功绕过了 if 的判断，导致栈溢出。