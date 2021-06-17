---
title: Driller_Installation
date: 2020-03-04 21:53:30
tags:
---
Document the steps...
<!--more-->
# prologue
2020/03/04
装这东西装了好几天,这里提供一下安装步骤主要目的为:
`Fuzzing with Shellphuzz`.
环境为`ubuntu 16.04` 的虚拟机
(这台虚拟机就用来跑`Shellphuzz`所以我就没用虚拟环境大家可以就实际情况使用.
(有些时候会卡住需要开代理,反正我发现开代理会更快..
# 其他教程
主要推荐[@GRIMM][1]
一篇够了写的很好...我看了多家的失败无数次...
# pre Install
1. 安装一些可能用到的软件包..
```
sudo apt-get install build-essential gcc-multilib libtool automake autoconf bison debootstrap debian-archive-keyring libtool-bin python3-dev libffi-dev virtualenvwrapper git wget 
sudo apt-get install build-essential gcc-multilib libtool automake autoconf bison debootstrap debian-archive-keyring libtool-bin
sudo apt-get build-dep qemu
```

2. 更新你的python为3.7..更新pip3 因为我原先的3.5对于解释类型的语法不知为何认为是语法错误...我升级python到3.7解决了问题,还有就是pip3更新,我pip3更新到了`pip 20.0.2`完成了安装.

# AFL
这个源码安装应该没啥毛病,可以试试

```sh
cd 
mkdir driller
cd driller
wget http://lcamtuf.coredump.cx/afl/releases/afl-2.52b.tgz
tar xf afl-2.52b.tgz
cd afl-2.52b
sudo make
cd qemu_mode
wget -O patches/memfd.diff https://salsa.debian.org/qemu-team/qemu/raw/ubuntu-bionic-2.11/debian/patches/ubuntu/lp1753826-memfd-fix-configure-test.patch
sed -i '/syscall.diff/a patch -p1 <../patches/memfd.diff || exit 1' build_qemu_support.sh
./build_qemu_support.sh
```

# Driller
本来看一些其他教程发现各种玄学报错加上相关解决文章较少最后:`git+`真香.
(环境专门用来跑driller的最好开个虚拟环境..
(在装的时候比较慢尝试开个代理.
```sh

cd ～/driller
pip3 install git+https://github.com/angr/archinfo
pip3 install git+https://github.com/angr/cle
pip3 install git+https://github.com/angr/claripy
pip3 install git+https://github.com/angr/angr
pip3 install git+https://github.com/angr/tracer
pip3 install git+https://github.com/shellphish/driller
```

# Shellphuzz
照着项目上说的安装就可以了.
```sh
pip3 install git+https://github.com/shellphish/shellphish-afl
pip3 install git+https://github.com/shellphish/fuzzer
```


# Run
这时候编译一下测试
```c
#include <stdio.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
  char buffer[6] = {0};
  int i;
  int *null = 0;

  read(0, buffer, 6);
  if (buffer[0] == '7' && buffer[1] == '/' && buffer[2] == '4'
      && buffer[3] == '2' && buffer[4] == 'a' && buffer[5] == '8') {
    i = *null;
  }

  puts("No problem");
}
```
正常编译就行
```sh
cd ~/driller
gcc -o buggy buggy.c
```
就是一个输入特定值会`crash`的程序.(应该是一个segfault.取地址为0的值

## fuzz with AFL

```sh
cd ~/driller
mkdir -p workdir/input
echo 'sth' > workdir/input/seed1
echo core | sudo tee /proc/sys/kernel/core_pattern
afl-2.52b/afl-fuzz -M fuzzer-master -i workdir/input/ -o workdir/output/ -Q ./buggy
```
之后就会出现AFL的工作界面,但是CRASH出得慢这时候需要driller来帮一下.

## fuzz with driller
这里使用一下run_driller.py
```python
#!/usr/bin/env python

import errno
import os
import os.path
import sys
import time

from driller import Driller


def save_input(content, dest_dir, count):
    """Saves a new input to a file where AFL can find it.

    File will be named id:XXXXXX,driller (where XXXXXX is the current value of
    count) and placed in dest_dir.
    """
    name = 'id:%06d,driller' % count
    with open(os.path.join(dest_dir, name), 'wb') as destfile:
        destfile.write(content)


def main():
    if len(sys.argv) != 3:
        print('Usage: %s <binary> <fuzzer_output_dir>' % sys.argv[0])
        sys.exit(1)

    _, binary, fuzzer_dir = sys.argv

    # Figure out directories and inputs
    with open(os.path.join(fuzzer_dir, 'fuzz_bitmap'), 'rb') as bitmap_file:
        fuzzer_bitmap = bitmap_file.read()
    source_dir = os.path.join(fuzzer_dir, 'queue')
    dest_dir = os.path.join(fuzzer_dir, '..', 'driller', 'queue')

    # Make sure destination exists
    try:
        os.makedirs(dest_dir)
    except os.error as e:
        if e.errno != errno.EEXIST:
            raise

    seen = set()  # Keeps track of source files already drilled
    count = len(os.listdir(dest_dir))  # Helps us name outputs correctly

    # Repeat forever in case AFL finds something new
    while True:
        # Go through all of the files AFL has generated, but only once each
        for source_name in os.listdir(source_dir):
            if source_name in seen or not source_name.startswith('id:'):
                continue
            seen.add(source_name)
            with open(os.path.join(source_dir, source_name), 'rb') as seedfile:
                seed = seedfile.read()

            print('Drilling input: %s' % seed)
            for _, new_input in Driller(binary, seed, fuzzer_bitmap).drill_generator():
                save_input(new_input, dest_dir, count)
                count += 1

            # Try a larger input too because Driller won't do it for you
            seed = seed + b'0000'
            print('Drilling input: %s' % seed)
            for _, new_input in Driller(binary, seed, fuzzer_bitmap).drill_generator():
                save_input(new_input, dest_dir, count)
                count += 1
        time.sleep(10)

if __name__ == '__main__':
    main()
```
`python3 run_driller.py ./buggy workdir/output/fuzzer-master`
这时候等下出crash了就可以在crash文件夹内找到造成crash的输入了.
## fuzz with shellphuzz
`shellphuzz -d 1 -c 1 -w workdir/shellphuzz/ -C --length-extension 4 ./buggy`
如果运行正常的话等他结束后就可以在下面文件夹找到造成crash的输入了.
`～/driller/workdir/shellphuzz/buggy/sync/fuzzer-master/crashes`
跑着跑着说找不到`afl-fuzz`啥的我不知道出错原因是什么我直接把`~/.local/bin/`里面要用的全部拷过去就能跑了.
res:
```sh
➜  crashes cat id:000000,sig:11,sync:driller,src:000016
7/42a8%
```

## Reference
[Guided-fuzzing-with-driller][1]


[1]: https://blog.grimm-co.com/post/guided-fuzzing-with-driller/

