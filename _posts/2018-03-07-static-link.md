---
title: static link
date: 2018-03-07 20:09:50
tags: basic
layout: post
---
静态链接
<!--more-->

以下为个人理解与一些问题



静态链接：
	静态链接是由链接器在链接时将库的内容加入到可执行程序中的做法。链接器是一个独立程序，将一个或多个库或目标文件（先前由编译器或汇编器生成）链接到一块生成可执行程序。--百科

	
现有两个文件
a.c
	extern int shared;
	int main(int argc, char** argv)
	{
	    int a = 100;
	    swap(&a, &shared);
	    return 0;
	}

b.c
	int shared = 1;
	void swap(int* a, int* b)
	{
		*a ^= *b ^= *a ^= *b;
	}


目前主要是将相同性质的段分在一起比如a的text和b的text合在一起，a的data和b的data合在一起......

下面是a，b，ab的段结构
a：
![](/ao.png)
b：
![](/bo.png)
ab：
![](/ab.png)
在链接结束之后显然a,b,ab的实际位置是已经确定了
假设share在b中相对data段的offset是100
那么share在ab中相对data(b)的offset也应该是100
swap可以以此类推

现有两种重定位类型：
R_386_32:S+A
R_386_PC32:S+A-P
A=保存在被修正位置的值（像是a.o中share的假的地址）
P=被修正的位置（ab中要被修正的位置）
S=符号的实际地址


![](/ar.png)

所以share处要填的地址应该
=
S+A

假设share实际地址是3000
在a.o中可以知道A=0
所以S+A=3000
(
这里我就不太好理解了
A是如何确定的呢？
我猜测可能是A是在a.o中相对所在段的offset
那么S应该不是实际地址应该是a.o的data段在ab中的offset
水平有限。。。望各位指点
)

swape处要填的地址应该
X=S+A-P
原因是：
在a.o中
	share=A+S（此处s理解为偏移量）
在ab中
	share=P+X=P+S+A-P=A+S

//完了自己都感觉一头雾水
//晚点找个明白人问问

总而言之连接器通过某种方法精确地定位到了ab中的符号
......强行解释一波

晚点弄明白再改....
q1：单独编译a.c时是如何确定share，swap的A
q2：如何在ab之中定位到s，但是如果定位到s为什么不直接用s
q3：p，s如何通过重定位表得出：例如是否info的高24位表示符号表的中下标也就是可以确定是哪一个符号，由此得出实际地址？