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

- Arbitrary Address Read
- Hijack the Control Flow and ROP
- Bypass FG-KASLR


# 0x02 Arbitrary Address Read

When we are attacking small-size objects, we may not have good candidates to leak. The most common objects used to leak is [struct msg_msg][6] and [struct msg_msgseg][7]


```c
struct msg_msg {
	struct list_head m_list;
	long m_type;
	size_t m_ts;		/* message text size */
	struct msg_msgseg *next;
	void *security;
	/* the actual message follows immediately */
};

struct msg_msgseg {
	struct msg_msgseg *next;
	/* the next part of the message follows immediately */
};
```

I also talked the basic usages of `msg_msg` in [IPS][8]. We know that there are limits while using `msg_msg` and `msg_msgseg` to leak: 
- `msg_msg`: If we can't partially write the `next` pointer, we may point `next` to an invalid address. 
- `msg_msgseg`: In the case of `UAF-Refill`, if we can't find an object starts with 0x8 zero bytes. The broken chain will lead to a crash.


For this challenge, there is no `read` freature. And the `UAF-Write` can't partially write the metadata. Also, for `msg_msgseg`, if it's larger than 0x1ff, we can use `sk_buff`. However, due to the objection size(0x40) limit, I didn't find a good object including 8 zero bytes at the head. 

Nevertheless, I found the challenge allows arbitrary write for freed objects, which means we are able to create 8 zero bytes! 
Utilizing the linked-list pointers in `struct msg_msg`. I got a way to leak current some heap pointers:

![msg_msg Link and Leak](/Figures/WallofPerdition/msg_msgLink.png)

## Msgmsg Link and Leak Steps
- 1. Assume the size of our target objects are 0x40
- 2. UAF the target object to create a 0x40 UAF slot 
- 3. Create a `0xfd0+0x38` `msg_msg` object to make sure its `msg_msgseg` refills the freed target object in previous step 
- 4. UAF free the target object again to create a 0x40 UAF slot at the same place as the second step
- 5. Refill with `msg_msg` struct(in a new `msg_msg` queue)
- 6. The `msg_msg` struct we created in previous step is a fake `msg_msgseq` of the `msg_msg` struct we created in step 3
- 7. Prepare another UAF slot by attacking the challenge vulnerability again
- 8. Append a new `msg_msg` struct to the `msg queue` we created in step 5. 
- 9. The `msg_msg` struct in step 8 will refill the slot we created in step 7
- 10. To avoid crash while leaking, we UAF free the slot we created in step 7 then refill it with objects start with 8 zero bytes (e.g., msg_msgseg)
- 11. So we can do msg_peek on the msg_msg struct created in step 3 we can leak the meta data of the `msg_msg` struct we created in step 3

![Step 1-3](/Figures/WallofPerdition/msg_msgLink_step_1-3.png)

![Step 4](/Figures/WallofPerdition/msg_msgLink_step_4.png)

![Step 5-9](/Figures/WallofPerdition/msg_msgLink_step_5-9.png)

![Step 10-11](/Figures/WallofPerdition/msg_msgLink_step_10-11.png)

## Arbitrary Address Read

With the Link and Leak skill in previous section, we are able to leak the data on the blue msg_msg struct, including a heap pointer to the red `msg_msgseg`(fake) object, which is also a `msg_msg` object on the blue `msg_msg` queue. So we can UAF-Write(edit-rule in the challenge) the red `msg_msgseg` object to fake a msg_msgseg. With this primitive, we can leak almost all the address space as long as there is 8 zero bytes before the stuff we want to leak (their offset should be less than 0xff8). Therefore, we can leak some kernel code segment pointers to compute `kernel.text`.


# 0x03 Hijack the Control Flow and ROP

After leaking the addresses, it's hijack the `$RIP` with UAF-Write. I chose the `ops` pointer in the `pipe_buffer` object:

- I created a UAF slot and refill with `pipe_buffer`
- Use UAF Write(edit-rule in the challenge) to set the `ops` pointer to kernel heap area
- Spray to hit the pointer we set in the previous setp
- Operate the `pipe` to trigger the Control Flow Hijacking

However, the kernel in this challenge is kind of small (4.0M) comparing to normal kernel bzImage. The kernel booting is very fast but we can find less gadgets to gain more control(ROP). By searching the keyword, `rsp` I didn't find any working gadgets like `push rsi; pop rsp` or `mov rsp, [rsi+<num>]`. After trying other gadgets for long time, I have to learn some new skills from Kyle to bridge the gap (`RIP Control -> ROP`): [RetSpill][3].

The basical idea is we have our userspace date on stack while doing syscalls. I tained all the registers and found they are at the bottom of the stack segment, which means we can use the gadgets `add rsp, <num>; ret` to pivot the stack. However, I can't find a useful gadget in the kernel. There are only 20 gadgets close to the target area but none of them works: the best one in them can only increase the stack `~0xd0` bytes which is far way from our target `~0x140` bytes.


At the time when I though this idea doesn't work, I got the idea of using `ret <num>` to nudge the stack. Since the compilers usually uses `rbp` instead of `rsp` to locate the variables on the stack, the mis-alignment should not crash! After searching such gadgets, I found much more gadgets than `add rsp, <num>`. (~20 vs. 200+). The idea of retSpill is really cool and the skill to use `ret <num>` makes it much stronger! Also, what a coincidence, `ret` is in the name of `retSpill`!

# 0x04 



[1]: TODO
[2]: https://syst3mfailure.io/wall-of-perdition/
[3]: https://dl.acm.org/doi/abs/10.1145/3576915.3623220
[6]: https://elixir.bootlin.com/linux/latest/source/include/linux/msg.h#L9
[7]: https://elixir.bootlin.com/linux/latest/source/ipc/msgutil.c#L37
[8]: https://n132.github.io/2024/02/09/IPS.html