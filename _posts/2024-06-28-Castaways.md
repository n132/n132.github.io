---
title: "Heap Overflow to cross Caches: Cache of Castaways (corCTF 2022)"
date: 2024-06-28 13:33:00
tags: 
layout: default
---

# 0x00 Introduction
To practice kernel exploitation, I plan to solve old CTF challenges and learn different skills from others. Before doing this challenge, I already know cross cache attack from [IPS][1]. But when I applied the same method to this challenge, I found it's difficult to perform cross page when the target allocation is noisy.


# 0x01 Challenge

[Attachment][2]

This is a kernel challenge from corCTF 2022. 

You can also check the [write-up][3] from the challenge authors.

Reversing and bug discovery are trivial in this challenge. It's like the normal userspace heap challenges. There are two options to manipulate the kernel heap objects: `add` and `edit`. In `add` there is a simple 6 bytes heap overflow. 
Considering the size of objects (0x200) and `FREELIST_HARDENED`, we can't use a 6-byte overflow to modify freelist. Moreover, this challenge created a new `kmem_cache` so we have to do cross pape (it's called cross cache in the original write-up, but I prefer to call it cross page to show the difference between it and the UAF-cross-cache technique). Also, I have to mention that this challenge also applied `CONFIG_HARDENED_USERCOPY` which should disable the `cross-page` technique. However, this challenge first copied the data from userspace to the kernel stack and then copied it from the kernel stack to heap objects, which enabled the `cross-page` technique.

So we mainly have two ways to attack
- cross page overflow to modify metadata -> for example, `creds->uid`
- cross page to modify pointers to create -> for example, `seq_file->op->signle_start`

In the second way, we don't need leak but a little brute force. I didn't try but learned from @zolutal that kernel code is not very random.

# 0x02 Ideal Senario

We have a vulnerable page next to a cred page. Then we use `edit` to overflow the first 6 bytes of cred then we become root!

Tip: Considering the first 4 bytes for creds is `usage` we'd better overwrite it with non-zero values. In practice, I would like to overwrite it with a large number, such as 0x132, since I found if we set it to 1/0, we may faill on some cases (e.g., when it's 1, we can't seteuid).

However, it's not as simple as ideal case since noise. They come from two reasons:
- The cred allocation is not atomic
- Enviroment: Fengshui / Noisy background





# 0x05 Exploitation


# Epilogue




[1]: https://n132.github.io/2024/02/29/IPS-Cross-Slab-Attack.html
[2]: https://github.com/Crusaders-of-Rust/corCTF-2022-public-challenge-archive/tree/master/pwn/cache-of-castaways
[3]: https://www.willsroot.io/2022/08/reviving-exploits-against-cred-struct.html
[4]: https://github.com/sefcom/RetSpill/blob/main/igni/chain_builder.py#L97
[6]: https://elixir.bootlin.com/linux/latest/source/include/linux/msg.h#L9
[7]: https://elixir.bootlin.com/linux/latest/source/ipc/msgutil.c#L37
[8]: https://n132.github.io/2024/02/09/IPS.html
