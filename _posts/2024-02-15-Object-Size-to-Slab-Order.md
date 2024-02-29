---
title: "Kernel: Compute Slab Order from Object Size"
date: 2024-02-15 22:34:39
tags: 
layout: default
---

# Prologue

While performing page level fengshui in linux kernel, I don’t know how to get the the order number of one object. 

For exmaple, we know the size of struct so we know how large the object is but we don’t know how many pages the linux kernel heap manager gonna allocate when we run out of all objects. We gonna solve this question…

# Get the answer

The short answer is `cat /proc/slabinfo` and you’ll see how many pages that a specific slab gonna use.

# How do we compute that?

It mainly depends on your CPU-core/threads numbers. If the order is not too large, Kernel tries to keep at least `4*(core_num+1)` objects in one slab. For exmaple if you have 2 cores, kernel would like to keep at lease 12 objects in the slab. So we gonna have two pages (Order==1) for kmalloc-512, since order==0 can only store 8 objects. If we only have 1 core, Slab malloc-512 gonna allocate order 0 pages.

The source code is in [`calculate_order`][1].


[1]: https://elixir.bootlin.com/linux/latest/C/ident/calculate_order