---
title: "Why is it so slow to debug kernel pwn challenges on WSL?"
date: 2023-09-23 20:56:12
tags: 
layout: post
---
# TL;DR

WSL mounts the Windows filesystem on `/mnt` so operation related to your host filesystem would be slower.

Packing the filesystem for pwn challenges includes lots of R/W operations, which enlarge the lagging.

The solution is moving the challenge out of `/mnt/`. 

# 0x00 Prologue
I am a Windows fan and use Windows as my 
While practicing kernel pwn challenges, I feel it's so slow to repack the filesystem. I didn't do lots of kernel challenges so that influenced little to me. However, I started practicing pwn challenges and the slow speed influenced my hacking experience. Today, I was 
reproducing a challenge and noticed the repacking takes about 60sec. That means every modification on 
the exploit source code would take me more than 1min to compile. That debugging is super painful for me so I asked my friend for the solution of that. Nevertheless, his response shocked me...

# 0x01 What's wrong with WSL?

He said it's very smooth to recape the filesystem for him and on his computer the repacking only takes less than 1 second. Then, I noticed that it's not a problem for all kernel pwners but only me.
Since my friend uses Linux on his host, I guess it could be WSL's problem. I tested on my VMware Linux and found it only takes 1.5 seconds, which costs 1/40 of WSL!

I cursed WSL so hard for wasting my time in around a thousand times of kernel challenge debugging and decided to take my friend's advice to try Ubuntu. I did download and install Ubuntu on my second SSD card but Ubuntu's bad support to NVIDIA GPU stopped me: My laptop can not connect to any monitor because the drivers for my GPU don't work. I spent 3 hours reading and trying all the solutions I found on the Internet to fix the issue. Even though I have 6 years of Linux-using experience, I didn't fix it. At that time, I reminded my ex, Windows. It's so smooth to use, most time, I don't need to worry about driver issues and I can find the solution online in 3 minutes since there are many more Windows users. After recalling these beautiful moments with Windows, I turned off the Ubuntu and opened my old buddy. 

# 0x02 It's not WSL's Fault

```sh
dd if=/dev/zero of=/tmp/xxx bs=1M count=20000
```

I first used the above command to test the disk read and write speed on wsl and found it's not slow at all(2G/s) I googled related questions about WSL with the keywords: "WSL", "cpio", "slow".  But the most results are actually several years ago and they are talking about WSL1. So I considered if it's not WSL's fault but mine.

At that moment, I got the reason, that's because my work directory is on my host's filesystem which is mounted at `/mnt/`. So I moved the work directory to the home directory and ran the same command. As soon as I released the enter key, the result appeared! 

I got the reason! The mounted filesystem is slower than WSL's original filesystem. The lagging is hard to be noticed for one operation but Packing the filesystem for pwn challenges includes lots of R/W operations, which enlarge the lagging.

The solution is quite simple, just one command: move the working directory out of `/mnt`. Tonight, I regret what I did to WSL. I am guilty.

# 0x03 Epilogue

This article is just a story. I told the whole story in a humorous tone. Don't be too serious about which system should people use. They have their own advantages and different people have different needs. I am not saying Windows is the best and Linux sucks. I actually use all of them(as well as OSX).





