---
title: Outset_OF_LLVM
date: 2019-11-15 14:39:13
tags: VM
---
LLVM
<!--more-->
# Prologue
最近遇到比较多的LLVM 于是乎我就学习了下.水一篇，主要是过程中不停查资料终于搞懂了这个是什么东西.
# What's LLVM
> WIKI:LLVM是一个自由软件项目，它是一种编译器基础设施，以C++写成，包含一系列模块化的编译器组件和工具链，用来开发编译器前端和后端。它是为了任意一种编程语言而写成的程序，利用虚拟技术创造出编译时期、链接时期、运行时期以及“闲置时期”的最优化。

虽然我读了之后还是没有明白他是个啥不过大概就是用来开发编译器用的一些工具,他的名字最早来源于`Low Level Virtual Machine`

> WIKI:LLVM的命名最早源自于底层虚拟机（Low Level Virtual Machine）的首字母缩写[4]，由于这个项目的范围并不局限于创建一个虚拟机，这个缩写导致了广泛的疑惑。LLVM开始成长之后，成为众多编译工具及低级工具技术的统称，使得这个名字变得更不贴切，开发者因而决定放弃这个缩写的意涵[5]，现今LLVM已单纯成为一个品牌，适用于LLVM下的所有项目，包含LLVM中介码（LLVM IR）、LLVM调试工具、LLVM C++标准库等。因LLVM对产业的贡献，计算机协会于2012年将ACM软件系统奖授与维克拉姆·艾夫、克里斯·拉特纳及Evan Cheng.

可以看出这东西其实是一大堆工具技术的项目总称.主要的贡献是对开发编译器或者中间代码生成器的推动作用

他的优点是开源，还有就是有好的IR语言。IR是`Intermediate Representation`中间表示语言什么的.
防止以后遇到这里附上他的IR语言的[官方手册][0]

# LLVM & CLANG
看完了上面和网上的一些资料...事实上我还是对`LLVM`一点头绪都没有..于是我就想着动手使用一下这个东西..看看有什么用..于是就开始了编译安装`LLVM`编译工具集和和常用的一个基于`LLVM`的编译器前端`Clang`,编译器前端还是比较好理解的像是`gdb`那种东西差不多这里就不多说了贴个[Clang's WIKI][1]
然后就开始编译..

[此处][2]是`llvm`官网上`clang`和一些其他的`compiler`的对比。

如果没有版本需求直接`Ubuntu`上`sudo apt-get install clang & sudo apt-get install llvm`就行了
就行了不用编译...我在mac上试着编译了一下...用了5个小时左右(目前还在编译)...

## 源码编译Clang
这里直接贴上从[ctf-all-in-one][3]上抄的代码...我是早上的时候不知道从哪里找的教程反正目前都5个小时左右了还没有报错..应该是能成了下面的那个过程不知道能不能成功编译.
```sh
$ svn co http://llvm.org/svn/llvm-project/llvm/trunk llvm
$ cd llvm/tools
$ svn co http://llvm.org/svn/llvm-project/cfe/trunk clang
$ svn co http://llvm.org/svn/llvm-project/lld/trunk lld # optional
$ svn co http://llvm.org/svn/llvm-project/polly/trunk polly # optional
$ cd clang/tools
$ svn co http://llvm.org/svn/llvm-project/clang-tools-extra/trunk extra # optional
$ cd ../../../.. && cd llvm/projects
$ svn co http://llvm.org/svn/llvm-project/compiler-rt/trunk compiler-rt # optional
$ svn co http://llvm.org/svn/llvm-project/openmp/trunk openmp # optional
$ svn co http://llvm.org/svn/llvm-project/libcxx/trunk libcxx # optional
$ svn co http://llvm.org/svn/llvm-project/libcxxabi/trunk libcxxabi # optional
$ svn co http://llvm.org/svn/llvm-project/test-suite/trunk test-suite # optional
$ cd ../.. && cd llvm
$
$ mkdir build && cd build
$ cmake -G Ninja ../
$ cmake --build .
$ cmake --build . --target install
```

简而言之就是`check out`了`LLVM`的和`clang`的一些代码然后编译安装一下...
有上网经验的我们来说应该难度不大。上面的如果报错了换一个..总有一个适合你/狗头.


## 几个名次间的关系
开始时还是比较难受的对这几个东西不太了解搞不清楚是什么..现在有点搞清楚了简单地说就是 `Clang+LLVM`和`GCC`差不多是一个编译器.而`Clang`是编译前端其后端是依靠`LLVM`的一些工具/组件。`LLVM`不只是可以用作`Clang`的后端还可以干很多其他的事情。


## 编译过程

有博主的[这篇文章][4]写的比较细致,我目前只大致了解了一下clang的编译过程。




# REFERENCE
```python
LLVM-WIKI: https://zh.wikipedia.org/wiki/LLVM 
LLVM: http://llvm.org
CTF_ALL_IN_ONE: https://firmianay.gitbooks.io/ctf-all-in-one/doc/5.6.1_clang.html

```

[0]: http://llvm.org/docs/LangRef.html
[1]: https://zh.wikipedia.org/wiki/Clang
[2]: http://clang.llvm.org/comparison.html
[3]: https://firmianay.gitbooks.io/ctf-all-in-one/doc/5.6.1_clang.html
[4]: http://www.alonemonkey.com/2016/12/21/learning-llvm/#%E5%9B%9B%E3%80%81%E5%8F%AF%E4%BB%A5%E7%94%A8Clang%E5%81%9A%E4%BB%80%E4%B9%88%EF%BC%9F
