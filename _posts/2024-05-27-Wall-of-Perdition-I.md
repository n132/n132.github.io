---
title: "Wall of Perdition-I: Desgin Msgmsg Arbitrary Read based on UAF"
date: 2024-05-27 17:37:00
tags: 
layout: default
---

# 0x00 Introduction
To practice kernel exploitation, I plan to solve old CTF challenges and learn different skills from others. Basically, I'll try to solve it by myself and then learn others' solutions. This is the first challenge for this serial, hope it's not the last one. 



# 0x01 Challenge

[Attachment][1]

This is a kernel challenge from corCTF 2021. 

You can also check the [write-up][2] from the challenge authors.

Recersing is kind of verbose of this challenge, if you don't want to do that just check the source code from the authors' writeup. 

Basic information of the kernel: 
```f
KASLR, FG-KASLR, SMEP, SMAP, KPTI
CONFIG_STATIC_USERMODEHELPER+CONFIG_STATIC_USERMODEHELPER_PATH=''
```

The challenge is using SLAB instead of SLUB so freelist hijacking is much more complex. There are several basical features in the challenge kernel model: `add_rule`, `delete_rule`, `edit_rule`, and `dup_rule`. Each `rule` is a 0x40 heap object:

```c
typedef struct
{
    char iface[16];
    char name[16];
    uint32_t ip;
    uint32_t netmask;
    uint16_t proto;
    uint16_t port;
    uint8_t action;
    uint8_t is_duplicated;
} rule_t;
```

We can control most parts of the object by `add/edit`_ing the rules. The vulnerability is in `delete_rule`, which `kfree` the target objects without zero_ing the duplicated pointers. Based on this, we can create a UAF pointer by `dup_rule(0,0)` and `delete_rule(0,0)`.


I devided the whole write-up to three parts and each part solves an individual problem I encountered.

- [Arbitrary Address Read][3]
- [Hijack the Control Flow][4]
- [Bypass FG-KASLR][5]


# 0x02 Leak







[1]: TODO
[2]: https://syst3mfailure.io/wall-of-perdition/
[3]: TODO
[4]: TODO
[5]: TODO