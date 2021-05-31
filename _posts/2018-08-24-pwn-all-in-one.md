---
title: pwn all in one
date: 2018-08-24 14:18:27
tags: updating pwn
layout: post
---
关于 pwn 的一些知识点
目前还只是目录状态准备在未来3个月完善。
<!--more-->

## 遇到输入control c break在input
## gdb call
## gdb souce+脚本
## gdb + struct

    +struct 空白处d
    +域 end处d
    +change size d
    use it y
    先编译 .so
    然后加到bin里

    或者家家souce
## 遇事不觉sleep
    很多时候read和我们的send存在某种玄学关系，感觉错误不知道在哪sleep()一下就可能解决了。
## souce
https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/elf.h

## SROP
sigretfram

## stack pivot
    控制esp
## tls
    fork 的canary都是一样
    archprctl
## maclloc顺序
    fast
    small
    unsorted 尾部取出 并且查看剩余大小
        如果剩下还可用那么 切分且剩余返回unsorted
        如果小于minisize 那么不返回给用户将其放入small/large bin中便利下一个chunk
    large bin
        查看有没有chunk
            有，找到满足需求最小的块，切分并且返回，把剩余块放入unsorted
            失败
        失败，再次遍历small/largebin
    topchunk
    mmap
## free
    fastbin
        直接放入，不改变在一个chunk的pre inuse
    mmap
        用munmap回收
    check pre chunk
        not use
            合并
    check next chunk
        topchunk
            合并
        freechunk
            合并
    unsortedbin

	## 常见漏洞
		over flow
            写掉bf去malloc任意位置
		uaf
			指针置0
			memset000000
		double free
			关注 检查
			结合unlink
		Off by one
			3种常见套路
## fastbin atk
    检查：
        利用存在地址

    利用：
        overwrite GOT
        Overwrite main_arena
        overwite hooks
## unsorted atk
    ===>global_max_fast
## smallbin atk
    Link
## large bin atk
    Link
## malloc——printer--->调用malloc
    Link
## free_hook =>system
## malloc_hook =>one_gadgets
## 利用malloc_peinterer 实现one-gadget
    execve("/bin/sh",rsp+0x50,environ)
    [rsp+0x50]==nul
## nisalignment 伪造size
## fastbinatk
    在main arena 写size
    改写topchunk ptr
