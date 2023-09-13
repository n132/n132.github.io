---
title: "Debug User a Space Program in Qemu"
date: 2023-09-12 21:58:12
tags: 
layout: default
---

# 0x00 TLDR

**Solution:** `gdbserver` + `qemu hostfwd`

**Guide:** https://github.com/n132/n132Tools/blob/main/Kernel/QemuUserspaceDebugging.md

## 0x01 Problem

This article provides a feasible, simple, and generic way to debug a user space program in a `qemu` virtual machine.

For example:

- We have a `userspace` challenge running on a `qemu` virtual machine.
- We exploited the challenge locally but failed due to inconsistencies between our local stack and the remote stack.
- The challenge author provides everything in a Docker image to ensure you can replicate the same challenge on your machine.

A real-world example is the `wall sina` challenge from HITCON 2023. I'll discuss the solution based on this challenge. This particular challenge is more complex than the situation described above, as it actually runs `chroot` to create another layer in the `qemu` machine. However, the solution remains consistent with the general problem.

## 0x02 Solution

`gdbserver` + `qemu hostfwd`

I used `gdbserver` on the `qemu` virtual machine and employed `net user,hostfwd=tcp::9999-:9999` to export port `9999` from the `qemu` virtual machine.

This setup allows me to debug within the Docker container or perform another layer of data transfer between Docker containers. The first solution is straightforward as we can change the base image to another more feature-rich operating system to ensure we can install the tools we need. The second solution is also quite simple; we just add one more parameter before starting the Docker container.

![Debugging](/Figures/QemuDebug/Debugging.png)

## 0x03 Details

1. Download a static version of `gdbserver`.
2. Modify the `init` file for the `qemu` machine to enable a reverse shell.
3. Repack the filesystem.
4. Edit `run.sh` to expose port `9999` for QEMU: `net nic -net user,hostfwd=tcp::9999-:9999`.
5. Modify the `docker-compose` configuration.

## 0x04 Epilogue

While this method seems straightforward, I spent a considerable amount of time on it because I had limited knowledge of `qemu`. I would also like to thank Kyle for teaching me how to forward data within a `qemu` machine.