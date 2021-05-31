---
title: 'kernel:Outset'
date: 2019-07-14 21:25:18
tags: kernel
---
环境搭建即熟悉...
<!--more-->
# prologue
本来是在学V8的可是因为一些事情需要先放一放v8...
# OutLine
本次日志包含.
* 准备工作:[CTF-wiki/basic][5]学习了一下`linux kernel pwn`的基础知识
* 参照文萱的[linux kernel 爬坑记录][1]和[hackedbylh's linux kernel pwn notes][2]完成初步环境搭建.
* 参考[Edvison][6](gdb and qemu）内核调试设置
* 参考[CTF ALL in ONE][4]自己尝试了写一个`Loadable Kernel Module`跑起来.
# 内核安装与编译
**别在docker上搞！**...我个傻子因为不知道docker和KVM(虽然现在也不咋懂)...在docker上瞎搞了半天
因为原来做题的机子搞不定就重新拉了一个16.04从头开始,发现存储空间炸了.....（**20G不够建议30G**）
* 装个zsh
```python
apt install git wget zsh
wget https://github.com/robbyrussell/oh-my-zsh/raw/master/tools/install.sh -O - | sh
chsh -s /bin/zsh
```
* 装一下libssl-dev:`sudo apt-get install libssl-dev`
* 安装qemu
`sudo apt-get install qemu qemu-system`
* 下载内核源码(https://mirrors.edge.kernel.org/pub/linux/kernel)(防止出各种错误我选了4.4.11)
* 解压配置编译
```python
tar -xvf ./linux-4.4.11.tar.gz
cd linux-4.4.11/
sudo apt-get install libncurses5-dev build-essential kernel-package
sudo make menuconfig
```
其中的配置按照:(我没有找到Processor type and features里的Paravirtualized guest support)
```
配置一些选项，主要就是：

KernelHacking –>

选中Compile the kernel with debug info
选中Compile the kernel with frame pointers
选中KGDB:kernel debugging with remote gdb，其下的全部都选中。
Processor type and features–>

去掉Paravirtualized guest support
KernelHacking–>

去掉Write protect kernel read-only data structures（否则不能用软件断点）
```
之后编译(*make的时候比较慢最好多配几个核心 调整-jn*)
`sudo make -j4 && sudo make all && sudo make modules`
# 构建文件系统
内核还需搭配文件系统,看了比较多的是用`busybox`来构建文件系统.
这里摘抄一下[@hackedbylh][3]编译`busybox`的过程
版本号可以改成新的.
```c
cd ..
wget https://busybox.net/downloads/busybox-1.29.3.tar.bz2 
tar -jxvf busybox-1.29.3.tar.bz2
cd busybox-1.29.3
make menuconfig  
```
make menuconfig 设置按照:
```c
Busybox Settings -> Build Options -> Build Busybox as a static binary 编译成 静态文件

关闭下面两个选项

Linux System Utilities -> [] Support mounting NFS file system 网络文件系统
Networking Utilities -> [] inetd (Internet超级服务器)
```
`make install`编译.编译目标文件会出现在`.../busybox-1.29.3/_install/`里
创建基本的目录与初始化脚本.
```c
cd _install
mkdir proc sys dev etc etc/init.d
vim etc/init.d/rcS
chmod +x etc/init.d/rcS
```
其中`etc/init.d/rcS`内容为
```sh
#!/bin/sh
mount -t proc none /proc
mount -t sysfs none /sys
/sbin/mdev -s
```
如果上述过程没毛病的话在`_install`下创建文件系统映像
`find . | cpio -o --format=newc > ../rootfs.img`

然后就可以跑起来了记得之前先关机勾选(Virtual Macgine Setting -> Processors -> Virtualization engine 的`Vitualize Intel Vt-x/EPT or AMD-V/RVI`)

`qemu-system-x86_64 -kernel /home/n132/Desktop/linux-4.4.11/arch/x86_64/boot/bzImage -initrd /home/n132/busybox-1.29.3/rootfs.img -append "console=ttyS0 root=/dev/ram rdinit=/sbin/init" -cpu kvm64,+smep --nographic -gdb tcp::1234`

摘抄一下几个选项的意思:(来源于[@hackedbylh][3])
```c
-cpu kvm64,+smep,+smap 设置 CPU的安全选项， 这里开启了 smap 和 smep

-kernel 设置内核 bzImage 文件的路径

-initrd 设置刚刚利用 busybox 创建的 rootfs.img ，作为内核启动的文件系统

-gdb tcp::1234 设置 gdb 的调试端口 为 1234
```

如果一切正常的话就可以得到以一个终端.

# 内核调试
这是一个比较简单的方法.使用`qemu`和`gdb`
之前跑内核的时候是在`qemu-system-x86_64`命令中加了 `-gdb tcp::1234`这样就可以用`gdb`通过1234端口调试内核.
通过下面命令load符号
`gdb ~/Desktop/linux-4.4.11/vmlinux`
之后只要remote上1234就可以调试.(有warning的话就照着warning上说的把相应设置放到`.gdb_init`里)
```c
target remote :1234
```
# 编写 Loadable Kernel Module
这部分主要参照[CTF ALL IN ONE][4].
hello.c
```c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

static int hello_init(void)
{
        printk(KERN_ALERT "Hello module!\n");
        return 0;
}

static void hello_exit(void)
{
        printk(KERN_ALERT "Goodbye module!\n");
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("A simple module.");
```
..今天先到这.

[1]: https://s3cunda.github.io/%E5%AD%A6%E4%B9%A0%E8%AE%B0%E5%BD%95/2018/09/21/linux-kernel-%E7%88%AC%E5%9D%91%E8%AE%B0%E5%BD%95.html
[2]: https://xz.aliyun.com/t/2306?accounttraceid=cdb0b6b9-d7d0-49a2-a5b2-b1c8814c0405
[3]: https://xz.aliyun.com/t/2306#toc-6
[4]: https://github.com/firmianay/CTF-All-In-One/blob/master/doc/4.1_linux_kernel_debug.md
[5]: https://ctf-wiki.github.io/ctf-wiki/pwn/linux/kernel/basic_knowledge-zh/
[6]: https://xz.aliyun.com/t/2024
