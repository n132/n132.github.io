---
title: Extract_Firmware
date: 2021-02-26 22:11:45
tags:
layout: post
---

Use binwalk to extract NETGEAR firmware
<!--more-->

# Prologue

Use binwalk to extract NETGEAR firmware

# What's Firmware?

- In computing, firmware is a specific class of computer software that provides the low-level control for a device's specific hardware.Firmware can either provide a standardized operating environment for more complex device software (allowing more hardware-independence), or, for less complex devices, act as the device's complete operating system, performing all control, monitoring and data manipulation functions. — wiki

# Why need to extract?

The file we got is compressed so that we need to revert it to some we are familiar with, such as exe file and ELF file.

# Tools

Firmware (I get the example from "[www.netgear.com](http://www.netgear.com/)") 

binwalk

# TRX

# Extract

we can use binwalk to analyze the structure of .chk file.

```bash
> $ binwalk ./R4500_V1.0.0.4_1.0.3.chk

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
58            0x3A            TRX firmware header, little endian, image size: 8609792 bytes, CRC32: 0x484C8BD7, flags: 0x0, version: 1, header size: 28 bytes, loader offset: 0x1C, linux kernel offset: 0x14A2D0, rootfs offset: 0x0
86            0x56            LZMA compressed data, properties: 0x5D, dictionary size: 65536 bytes, uncompressed size: 3874949 bytes
1352458       0x14A30A        Squashfs filesystem, little endian, non-standard signature, version 3.0, size: 7253493 bytes, 853 inodes, blocksize: 65536 bytes, created: 2012-05-03 06:00:38
```

The result shows that there is a header, LZMA compressed data, and a Squashfs filesystem.

It seems that we can extract the filesystem by -Me

`binwalk -Me ./R4500_V1.0.0.4_1.0.3.ch`

However, I find there is nothing in `squashfs-root`

Someone meets the same problem on [xz][1] and gives a solution that we can extract `.squashf` to get the filesystem.

Before that, some [tools][2] are needed: firmware-mod-kit.

We can install it by:

```bash
git clone https://github.com/mirror/firmware-mod-kit.git
cd firmware-mod-kit/src
./configure
make
```

And extract the filesystem by:

```bash
cd firmware-mod-kit
./unsquashfs_all.sh ../R4500_V1.0.0.4_1.0.3/_R4500_V1.0.0.4_1.0.3.chk.extracted/14A30A.squashfs
```

# Ref

[Reverse engineering my router's firmware with binwalk](https://embeddedbits.org/reverse-engineering-router-firmware-with-binwalk/)

[1] [https://xz.aliyun.com/t/5468](https://xz.aliyun.com/t/5468)

[2] [https://github.com/mirror/firmware-mod-kit](https://github.com/mirror/firmware-mod-kit)