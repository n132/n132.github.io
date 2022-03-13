# Prologue
I only know some basic properties of the thread. In order to get a good grade in this weekend's quiz, i plan to have a quick look about the threads. That would include the properties, the management and I may dive deep to the kernel threads.

# Which part of memory would the threads share?
CSAPP: 
> multiple threads run in the context of a single process and thus share the entire contents of the process virtual address space, including its code data, heap, shared libraries, and open files.

They almost share every thing but the context. Context includes stack and registers. 

I am really curious about the memory layout of the process. So I debug it with gdb. And have a more real image of the threads.

```C
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<pthread.h>
void n132()
{
	int f = open("./n132");
	char buf[0x100];
    getchar();
	read(3,buf,0x3);
	write(1,buf,0x3);
}
int main()
{
	pthread_t tid;
	pthread_create(&tid,NULL,n132, NULL);
	pthread_join(tid,NULL);

	char buf[0x100];
	read(3,buf,0x3);
	write(1,buf,0x3);
	exit(0);
}

```

That's the source code of my demo. I create a thread to read the content of a file named "n132". And the main thread would also read date from the same file descriptor. By debugging the program, we could not only check if these two threads use the same fd but also explore the memory layout in gdb.

First, we compile it and run it to check the result.
```s
$ gcc ./main.c -o main -lpthread
$ cat ./n132
123456
$ ./main
123456#
```
The result is not "123123" but "123456". That means the main thread and the subthread share one fd. 

Then in gdb, we can check the memory layout. In gdb, we can use `info thread` to check the current threads and we can use "thread 2" to switch to another thread.

In my gdb, I see that the value of `$rsp` is `0x7ffff7da7d10`. And I check it in `vmmap`.
```S
gdb-peda$ vmmap 0x7ffff7da7d10
Start              End                Perm	Name
0x00007ffff75a9000 0x00007ffff7dac000 rw-p	mapped
gdb-peda$ vmmap
Start              End                Perm	Name
0x0000555555554000 0x0000555555555000 r--p	/threads/main
0x0000555555555000 0x0000555555556000 r-xp	/threads/main
0x0000555555556000 0x0000555555557000 r--p	/threads/main
0x0000555555557000 0x0000555555558000 r--p	/threads/main
0x0000555555558000 0x0000555555559000 rw-p	/threads/main
0x0000555555559000 0x000055555557a000 rw-p	[heap]
0x00007ffff0000000 0x00007ffff0021000 rw-p	mapped
0x00007ffff0021000 0x00007ffff4000000 ---p	mapped
0x00007ffff75a8000 0x00007ffff75a9000 ---p	mapped
0x00007ffff75a9000 0x00007ffff7dac000 rw-p	mapped
0x00007ffff7dac000 0x00007ffff7dd1000 r--p	/usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007ffff7dd1000 0x00007ffff7f49000 r-xp	/usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007ffff7f49000 0x00007ffff7f93000 r--p	/usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007ffff7f93000 0x00007ffff7f94000 ---p	/usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007ffff7f94000 0x00007ffff7f97000 r--p	/usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007ffff7f97000 0x00007ffff7f9a000 rw-p	/usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007ffff7f9a000 0x00007ffff7f9e000 rw-p	mapped
0x00007ffff7f9e000 0x00007ffff7fa5000 r--p	/usr/lib/x86_64-linux-gnu/libpthread-2.31.so
0x00007ffff7fa5000 0x00007ffff7fb6000 r-xp	/usr/lib/x86_64-linux-gnu/libpthread-2.31.so
0x00007ffff7fb6000 0x00007ffff7fbb000 r--p	/usr/lib/x86_64-linux-gnu/libpthread-2.31.so
0x00007ffff7fbb000 0x00007ffff7fbc000 r--p	/usr/lib/x86_64-linux-gnu/libpthread-2.31.so
0x00007ffff7fbc000 0x00007ffff7fbd000 rw-p	/usr/lib/x86_64-linux-gnu/libpthread-2.31.so
0x00007ffff7fbd000 0x00007ffff7fc3000 rw-p	mapped
0x00007ffff7fc9000 0x00007ffff7fcd000 r--p	[vvar]
0x00007ffff7fcd000 0x00007ffff7fcf000 r-xp	[vdso]
0x00007ffff7fcf000 0x00007ffff7fd0000 r--p	/usr/lib/x86_64-linux-gnu/ld-2.31.so
0x00007ffff7fd0000 0x00007ffff7ff3000 r-xp	/usr/lib/x86_64-linux-gnu/ld-2.31.so
0x00007ffff7ff3000 0x00007ffff7ffb000 r--p	/usr/lib/x86_64-linux-gnu/ld-2.31.so
0x00007ffff7ffc000 0x00007ffff7ffd000 r--p	/usr/lib/x86_64-linux-gnu/ld-2.31.so
0x00007ffff7ffd000 0x00007ffff7ffe000 rw-p	/usr/lib/x86_64-linux-gnu/ld-2.31.so
0x00007ffff7ffe000 0x00007ffff7fff000 rw-p	mapped
0x00007ffffffde000 0x00007ffffffff000 rw-p	[stack]
0xffffffffff600000 0xffffffffff601000 r-xp	[vsyscall]
```
As we can see, the stack of the new thread is in a mapped section. That makes sense. We do need more space for new stack. So lets try to access the the subthread's stack from another thread I know this looks meaningless, just want to confirm if we have some special protection to the thread stack.


```c
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<pthread.h>
char *P=0;
void n132()
{
	int f = open("./n132");
	char buf[0x10];
	read(f,buf,0x3);
	P = buf;
	while(1);
}
int main()
{
	pthread_t tid;
	pthread_create(&tid,NULL,n132, NULL);
	//pthread_join(tid,NULL);

	while(!P);
	write(1,P,0x30);
	exit(0);
}
```

I compile and run my second demo and find that works and they do share the whole memory space. 

```s
$ gcc -w ./main.c -o main -lpthread
$ ./main
123GR...
```

That's interesting. I guess there may be some important struct in sub-thread's stack which would store the regs of the thread. Regs is enouth cuz the stack is just the memory between $rsp and $rbp. And I am really interested in the management of threads. If I have enough time I would dive into the kernel and analyse the code of that part!

For the question of this section. Which part of memory would the threads share? The answer is the whole memory space!
# What's kernel threads?

# What's the difference between threads in kernel space and in user space? 


# How to manage the threads in user space?

# How to manage the threads in kernel space?

# How can the threads improve the efficiency?