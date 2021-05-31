---
title: mips-environ
date: 2020-04-09 14:22:22
tags: mips
---
All you need to start learning mips : 介绍，编译，反编译，调试。
<!--more-->
# 介绍
这里的mips不是*million instruction per second*，
是**Microprocessor without interlocked piped stages**.是一种CPU架构
也称指令集架构，指令集就比较好理解通俗可以看成指令的集合像是x86的话有mov/add....之类的一些指令。
指令集是存储在CPU内部，对CPU运算进行指导和优化的硬程序，CPU的运行执行的就是指令集。
讲汇编的时候老师好像有说过定长指令与不定长指令还有精简啥的，定长不定长指的是指令的长度是不是固定的例如
不定长的x86架构:
`nop`是一个字节但是`int 0x80`就是2个字节  
定长的mips架构
`nop`是4个字节还有不管是啥都是四个字节.
龙芯中央处理器用的是MIPS.
研究不同架构需要触类旁通，今天弄了mips不能下次弄arm就从头再来，主要就是那一套东西，编译环境，反编译器（不一定有，没有的话自己看汇编），调试环境...
但是为了学个mips总不能去搞一颗龙芯...(淘宝了一下还真有卖龙芯主机...)
于是就需要交叉编译（cross-compilation）环境，也就是在我们x86的环境下编译mips，arm之类的环境；反编译就看有没有人已经搞过了网上找找看大家用的都是什么，实在没人搞过要么看汇编要么硬核一点自己写一个；调试环境的话qemu大法好！

我的环境是dcoker的library/ubuntu:16.04.

# 交叉编译环境
## buildroot
之前arm的环境用的是`arm-linux-gcc`这次我谷歌了一下mips交叉编译环境前面一排都是`buildroot`的。
> Buildroot主要意图用于小型或嵌入式系统，它们基于各种计算机体系结构和指令集之上，包括x86、ARM、MIPS和PowerPC。Buildroot可以自动建造所需要的交叉编译工具链，创建根文件系统，编译一个Linux内核映像，并为目标嵌入式系统生成引导装载器，它还可以进行这些独立步骤的任何组合。--wiki

于是我就去搞了个`buildroot`过程挺顺利的没有任何报错，只是我的小霸王跑了3个小时左右才搞完。
下载配置
```s
wget http://buildroot.uclibc.org/downloads/snapshots/buildroot-snapshot.tar.bz2
tar -jxvf buildroot-snapshot.tar.bz2
cd buildroot
sudo apt-get install libncurses-dev patch texinfo bison flex
make clean
make menuconfig
```
配置的时候有两个需要改的
1. Target Architecture 改成 MIPS little endian
2. Toolchain 改成自己的linux版本(unname -a可以看)

完了保存一下就可以开始编译了.一个`sudo make`下去就跑了半天...
编译好的东西放在`output`文件夹下
可以把路径加到.bashrc里面去`PATH=$PATH:/root/buildroot/output/host/bin/`
可以测试一下随便写个main.c之后`mipsel-linux-gcc ./main.c -o main`就可以得到基于mips架构的binary.

然后我在buildroot上弄了n**个小时都没有弄好docker-chroot之后的buildroot编译环境
## mips(el)-linux-gnu
这个就比较方便了直接apt安装 docker+chroot之后只要把/usr目录下的`mips(el)-linux-gnu`还有`/usr/bin`移动一下就可以了
```s
sudo apt-get install linux-libc-dev-mipsel-cross 
sudo apt-get install libc6-mipsel-cross libc6-dev-mipsel-cross
sudo apt-get install binutils-mipsel-linux-gnu gcc-mipsel-linux-gnu
sudo apt-get install g++-mipsel-linux-gnu
```

# 反编译器
## retdec
问了下同队的逆向师傅@apeng一般用的是`retdec`
**CTF all in one**上的安装教程还是那么简明高效.
依赖
`sudo apt-get install build-essential cmake coreutils wget bc graphviz upx flex bison zlib1g-dev libtinfo-dev autoconf pkg-config m4 libtool`
项目连同子模块
`git clone --recursive https://github.com/avast-tl/retdec`
cmake的时候搞个空目录`/usr/local/retdec`。cmake版本不够高自己去升级一下。没啥需求不用自己去编译直接覆盖删掉原来的就可以了
```
cd ~
wget https://cmake.org/files/v3.13/cmake-3.13.0-Linux-x86_64.tar.gz
tar -xzvf cmake-3.13.0-Linux-x86_64.tar.gz
sudo ln -sf /root/cmake-3.13.0-Linux-x86_64/bin/*  /usr/bin/
```
之后编译retdec
```
cd retdec
mkdir build && cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local/retdec
make && sudo make install
```
我到`[  5%] Performing build step for 'yaramod-project'`的时候报错
```s
[  5%] Performing build step for 'yaramod-project'
CMake Error at /home/n132/Desktop/retdec/build/external/src/yaramod-project-stamp/yaramod-project-build-Release.cmake:16 (message):
  Command failed: 2

   'make'

  See also

    /home/n132/Desktop/retdec/build/external/src/yaramod-project-stamp/yaramod-project-build-*.log


deps/yaramod/CMakeFiles/yaramod-project.dir/build.make:111: recipe for target 'external/src/yaramod-project-stamp/yaramod-project-build' failed
make[2]: *** [external/src/yaramod-project-stamp/yaramod-project-build] Error 1
CMakeFiles/Makefile2:493: recipe for target 'deps/yaramod/CMakeFiles/yaramod-project.dir/all' failed
make[1]: *** [deps/yaramod/CMakeFiles/yaramod-project.dir/all] Error 2
Makefile:129: recipe for target 'all' failed
make: *** [all] Error 2
➜  build git:(master) cat     /home/n132/Desktop/retdec/build/external/src/yaramod-project-stamp/yaramod-project-build-*.log
In file included from /home/n132/Desktop/retdec/build/external/src/yaramod-project/include/yaramod/types/expression.h:14:0,
                 from /home/n132/Desktop/retdec/build/external/src/yaramod-project/include/yaramod/builder/yara_expression_builder.h:12,
                 from /home/n132/Desktop/retdec/build/external/src/yaramod-project/src/builder/yara_expression_builder.cpp:7:
/home/n132/Desktop/retdec/build/external/src/yaramod-project/include/yaramod/utils/visitor_result.h:10:19: fatal error: variant: No such file or directory
compilation terminated.
make[5]: *** [src/CMakeFiles/yaramod.dir/builder/yara_expression_builder.cpp.o] Error 1
make[4]: *** [src/CMakeFiles/yaramod.dir/all] Error 2
make[3]: *** [all] Error 2
[ 18%] Built target re2-dep
[ 37%] Built target fmt-dep
[ 39%] Building CXX object src/CMakeFiles/yaramod.dir/builder/yara_expression_builder.cpp.o
src/CMakeFiles/yaramod.dir/build.make:62: recipe for target 'src/CMakeFiles/yaramod.dir/builder/yara_expression_builder.cpp.o' failed
CMakeFiles/Makefile2:253: recipe for target 'src/CMakeFiles/yaramod.dir/all' failed
Makefile:129: recipe for target 'all' failed
```
查了半天没找到如何解决就直接放弃了改装Ghidra了。
## Ghidra
装了半天retdec装不好我一气之下搞了个Ghidra...
[link][1]
下载解压运行一气呵成(jdk版本不够的升级到11参见[这里][2])
```s
# https://www.cyberpunk.rs/ghidra-software-reverse-engineering-framework
Linux / OS X
Download the zip file.
Extract the .tar.gz file to your desired location:
$ tar -xvf <JDK_dist.tar.gz> 
Open ~/.bashrc with editor of your choice and add the following to the PATH variable:
export PATH=<path of extracted JDK dir>/bin:$PATH 
Save file and restart all open terminals.
Note:  To force Ghidra to launch with a specific version of Java, set the  JAVA_HOME_OVERRIDE  property the support/launch.properties file.
```
mips是有decompiler的. 
![Ghidra-decompiler](/images/Ghidra-decompiler.png)

# 调试环境
和arm类似用的是qemu还有gdb-multiarch

Installation：
```
sudo apt-get install qemu binfmt-support qemu-user-static
sudo apt-get install gdb-multiarch
```

Debug：
开个132132端口 -L指定ld/lib
```
qemu-mipsel -g 132132 -L /root/buildroot/output/target/ ./main
```
之后开启gdb来连
```
gdb-multiarch ./main
target remote 127.0.0.1:132132
```
这里最好用gef或者pwndbg，如果使用peda可能出现显示问题。
![pwndbg](/images/debug-pwndbg.png)

# pwntools
调试模版从[@m4x][3]那边抄的
```python
from pwn import *
c=["qemu-mipsel","-g","1024","-L","/root/buildroot/output/target/","./pwn")
p = process(c)
```

# summary
至此，环境相关的都搞好了。
除了Ghidra我是装在vmware里面的其他的东西都是装在dcoker的library/ubuntu:16.04.
不想慢慢编译的师傅可以直接`docker pull n132/pwn:mips`.


[1]: https://www.cyberpunk.rs/ghidra-software-reverse-engineering-framework
[2]: https://blog.csdn.net/zy00000000001/article/details/70138811
[3]: http://m4x.fun/post/how-2-pwn-an-arm-binary/



