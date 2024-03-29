---
title: How to compile a glibc
date: 2018-04-30 21:30:19
tags: basic
layout: post
---

装libc困难重重从早上装到了晚上
解决问题的能力还需要提高
过程中学到了很多解决问题的办法
见识了很多share 解决办法 帮忙解决问题的师傅


<!--more-->
# Prologue
  发现Ubuntu16.04编译libc 2.23不！会！报！错！
  如果想锻炼自己解决问题能力的可以在kali上编译.
  我发现于编译完3个月后...
  by the way ubuntu 做pwn真的好用.

# Linux 编译 LIBC 

## 0x01 Begin 
    需要低版本的libc学习heap利用技巧
    老潘说可以下一个libc自己编译
    于是乎 开始了5.1爬坑之旅
    在过程中发现百度上关于这方面遇到问题之后的solution太少
    谷歌上也没有比较详尽全面的教程。
    于是记录一下自己在kali下 编译libc 的过程
## 0x02 prepare
Time ： 2018-04-30
Linux版本信息：
```c
    Linux Nine 4.6.0-kali1-amd64 #1 SMP Debian 4.6.4-1kali1 (2016-07-21) x86_64 GNU/Linux
```
Info for glibc-2.23：
    下载地址===>[http://ftp.gnu.org/gnu/glibc/glibc-2.23.tar.gz][1]
Other libc：
    其他版本的libc[http://ftp.gnu.org/gnu/glibc/][2]

## 0x03 Install
```c
cd
mkdir libc && cd libc
wget http://ftp.gnu.org/gnu/glibc/glibc-2.23.tar.gz
tar -xf glibc-2.23.tar.gz
cd glibc-2.23/
mkdir build && cd build
#下载并解压libc 创建build目录 并进入 
```
然后我们来设置一些编译的选项：
x64的
```
CFLAGS="-g -g3 -ggdb -gdwarf-4 -Og"
CXXFLAGS="-g -g3 -ggdb -gdwarf-4 -Og"
../configure --prefix=/path/to/install
```
x32的
```
CC="gcc -m32" CXX="g++ -m32" \
CFLAGS="-g -g3 -ggdb -gdwarf-4 -Og" \
CXXFLAGS="-g -g3 -ggdb -gdwarf-4 -Og" \
../configure --prefix=/path/to/install --host=i686-linux-gnu
```

![图片来自winesap的社课](/18-4-30-1.png)

然后我们开始make
```
make&&make install
```
如果没问题那就不需要看下面部分了
巴特 一般会遇到问题
下面是我在make过程中遇到的若干问题
前面6个问题是在安装x64时候遇到的



### 0x00 括号缺失
```
setenv.c: In function '__unsetenv':
setenv.c:279:6: error: suggest explicit braces to avoid ambiguous 'else' [-Werror=parentheses]
   if (ep != NULL)
      ^
cc1: all warnings being treated as errors
../o-iterator.mk:9: recipe for target '/builddir/build/BUILD/glibc-arm-linux-gnu-2.23/build-arm-linux-gnu-glibc/stdlib/setenv.o' failed
make[2]: *** [/builddir/build/BUILD/glibc-arm-linux-gnu-2.23/build-arm-linux-gnu-glibc/stdlib/setenv.o] Error 1
make[2]: *** Waiting for unfinished jobs....
make[2]: Leaving directory '/builddir/build/BUILD/glibc-arm-linux-gnu-2.23/glibc-2.23/stdlib'
Makefile:214: recipe for target 'stdlib/subdir_lib' failed
make[1]: *** [stdlib/subdir_lib] Error 2
make[1]: Leaving directory '/builddir/build/BUILD/glibc-arm-linux-gnu-2.23/glibc-2.23'
Makefile:9: recipe for target 'all' failed
make: *** [all] Error 2
```
reason：
```
glibc-2.23/nis/nis_call.c与
glibc-2.23/stdlib/setenv.c
大括号缺失
```
solution：[https://bugzilla.redhat.com/show_bug.cgi?id=1312963#c5][3]
```
diff -up glibc-arm-linux-gnu-2.23/glibc-2.23/nis/nis_call.c.gcc61 glibc-arm-linux-gnu-2.23/glibc-2.23/nis/nis_call.c
--- glibc-arm-linux-gnu-2.23/glibc-2.23/nis/nis_call.c.gcc61	2016-02-18 18:54:00.000000000 +0100
+++ glibc-arm-linux-gnu-2.23/glibc-2.23/nis/nis_call.c	2016-05-19 18:44:24.288550322 +0200
@@ -680,6 +680,7 @@ nis_server_cache_add (const_nis_name nam
   /* Choose which entry should be evicted from the cache.  */
   loc = &nis_server_cache[0];
   if (*loc != NULL)
+  {
     for (i = 1; i < 16; ++i)
       if (nis_server_cache[i] == NULL)
 	{
@@ -690,6 +691,7 @@ nis_server_cache_add (const_nis_name nam
 	       || ((*loc)->uses == nis_server_cache[i]->uses
 		   && (*loc)->expires > nis_server_cache[i]->expires))
 	loc = &nis_server_cache[i];
+  }
   old = *loc;
   *loc = new;
 
diff -up glibc-arm-linux-gnu-2.23/glibc-2.23/stdlib/setenv.c.gcc61 glibc-arm-linux-gnu-2.23/glibc-2.23/stdlib/setenv.c
--- glibc-arm-linux-gnu-2.23/glibc-2.23/stdlib/setenv.c.gcc61	2016-02-18 18:54:00.000000000 +0100
+++ glibc-arm-linux-gnu-2.23/glibc-2.23/stdlib/setenv.c	2016-05-19 18:41:09.778640989 +0200
@@ -277,6 +277,7 @@ unsetenv (const char *name)
 
   ep = __environ;
   if (ep != NULL)
+  {
     while (*ep != NULL)
       if (!strncmp (*ep, name, len) && (*ep)[len] == '=')
 	{
@@ -290,6 +291,7 @@ unsetenv (const char *name)
 	}
       else
 	++ep;
+  }
 
   UNLOCK;
```
### 0x01 .symver on common symbols
```
/tmp/cc8lsExU.s: Error: symbol `loc1@GLIBC_2.2.5' can't be versioned to common symbol
/tmp/cc8lsExU.s: Error: symbol `loc2@GLIBC_2.2.5' can't be versioned to common symbol
/tmp/cc8lsExU.s: Error: symbol `locs@GLIBC_2.2.5' can't be versioned to common symbol
```
reason：
```
symver is used on common symbol
```
solution:[https://patchwork.ozlabs.org/patch/780067/][4]
```
diff --git a/misc/regexp.c b/misc/regexp.c
index 19d76c0..9017bc1 100644
--- a/misc/regexp.c
+++ b/misc/regexp.c
@@ -29,14 +29,17 @@ 
 
 #if SHLIB_COMPAT (libc, GLIBC_2_0, GLIBC_2_23)
 
-/* Define the variables used for the interface.  */
-char *loc1;
-char *loc2;
+#include <stdlib.h>	/* Get NULL.  */
+
+/* Define the variables used for the interface.  Avoid .symver on common
+   symbol, which just creates a new common symbol, not an alias.  */
+char *loc1 = NULL;
+char *loc2 = NULL;
 compat_symbol (libc, loc1, loc1, GLIBC_2_0);
 compat_symbol (libc, loc2, loc2, GLIBC_2_0);
 
 /* Although we do not support the use we define this variable as well.  */
-char *locs;
+char *locs = NULL;
 compat_symbol (libc, locs, locs, GLIBC_2_0);
```
### 0x02 Fix warnings from latest GCC
```
../sysdeps/ieee754/dbl-64/e_pow.c: In function ‘checkint’:
../sysdeps/ieee754/dbl-64/e_pow.c:469:13: error: << in boolean context, did you mean '<' ? [-Werror=int-in-bool-context]
       if (n << (k - 20))
           ~~^~~~~~~~~~~
../sysdeps/ieee754/dbl-64/e_pow.c:471:17: error: << in boolean context, did you mean '<' ? [-Werror=int-in-bool-context]
       return (n << (k - 21)) ? -1 : 1;
              ~~~^~~~~~~~~~~~
../sysdeps/ieee754/dbl-64/e_pow.c:477:9: error: << in boolean context, did you mean '<' ? [-Werror=int-in-bool-context]
   if (m << (k + 12))
       ~~^~~~~~~~~~~
../sysdeps/ieee754/dbl-64/e_pow.c:479:13: error: << in boolean context, did you mean '<' ? [-Werror=int-in-bool-context]
   return (m << (k + 11)) ? -1 : 1;
          ~~~^~~~~~~~~~~~
cc1: all warnings being treated as errors
```
reason:
```
文件/sysdeps/ieee754/dbl-64/e_pow.c中
对n=0没有检测 在if判断中加上！=0即可解决
```
solution:[https://patchwork.ozlabs.org/patch/680578/][5]
```
diff --git a/sysdeps/ieee754/dbl-64/e_pow.c b/sysdeps/ieee754/dbl-64/e_pow.c
index 663fa39..bd758b5 100644
--- a/sysdeps/ieee754/dbl-64/e_pow.c
+++ b/sysdeps/ieee754/dbl-64/e_pow.c
@@ -466,15 +466,15 @@  checkint (double x)
     return (n & 1) ? -1 : 1;	/* odd or even */
   if (k > 20)
     {
-      if (n << (k - 20))
+      if (n << (k - 20) != 0)
 	return 0;		/* if not integer */
-      return (n << (k - 21)) ? -1 : 1;
+      return (n << (k - 21) != 0) ? -1 : 1;
     }
   if (n)
     return 0;			/*if  not integer */
   if (k == 20)
     return (m & 1) ? -1 : 1;
-  if (m << (k + 12))
+  if (m << (k + 12) != 0)
     return 0;
-  return (m << (k + 11)) ? -1 : 1;
+  return (m << (k + 11) != 0) ? -1 : 1;
 }
```
### 0x003 sunrpc/rpc_parse.c
```
[ALL  ]      rpc_parse.c: In function 'get_prog_declaration':
[ERROR]      rpc_parse.c:543:23: error: '%d' directive writing between 1 and 10 bytes into a region of size 7 [-Werror=format-overflow=]
[ALL  ]           sprintf (name, "%s%d", ARGNAME, num); /* default name of argument */
[ALL  ]                             ^~
[ALL  ]      rpc_parse.c:543:20: note: directive argument in the range [1, 2147483647]
[ALL  ]           sprintf (name, "%s%d", ARGNAME, num); /* default name of argument */
[ALL  ]                          ^~~~~~
[ALL  ]      rpc_parse.c:543:5: note: 'sprintf' output between 5 and 14 bytes into a destination of size 10
[ALL  ]           sprintf (name, "%s%d", ARGNAME, num); /* default name of argument */
[ALL  ]           ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
[ALL  ]      cc1: all warnings being treated as errors
[ERROR]      make[3]: *** [/Volumes/OSXElCapitan/Users/mrdekk/casesafe/.build/x86_64-ubuntu16.04-linux-gnu/build/build-libc-final/multilib/sunrpc/rpc_parse.o] Error 1
[ERROR]      make[3]: *** Waiting for unfinished jobs....
[ERROR]      make[2]: *** [sunrpc/others] Error 2
[ERROR]      make[1]: *** [all] Error 2
```
这个还有下个问题的solution从MrDekk的blog上得到
solution：
```
--- a/sunrpc/rpc_parse.c
+++ b/sunrpc/rpc_parse.c
@@ -521,7 +521,7 @@ static void
 get_prog_declaration (declaration * dec, defkind dkind, int num /* arg number */ )
 {
   token tok;
-  char name[10];		/* argument name */
+  char name[MAXLINESIZE];		/* argument name */
 
   if (dkind == DEF_PROGRAM)
     {
```
### 0x004 nis/nss_nisplus/nisplus-alias.c
```
nss_nisplus/nisplus-alias.c:300:12: error: argument 1 null where non-null expected [-Werror=nonnull]
[ERROR]      nss_nisplus/nisplus-alias.c:303:39: error: '%s' directive argument is null [-Werror=format-truncation=]
[ERROR]      make[3]: *** [/Volumes/OSXElCapitan/Users/mrdekk/casesafe/.build/x86_64-ubuntu16.04-linux-gnu/build/build-libc-final/multilib/nis/nisplus-alias.os] Error 1
[ERROR]      make[3]: *** Waiting for unfinished jobs....
[ERROR]      make[2]: *** [nis/others] Error 2
[ERROR]      make[1]: *** [all] Error 2
```
solution:
```
diff --git a/nis/nss_nisplus/nisplus-alias.c b/nis/nss_nisplus/nisplus-alias.c
index 7f698b4e6d..509ace1f83 100644
--- a/nis/nss_nisplus/nisplus-alias.c
+++ b/nis/nss_nisplus/nisplus-alias.c
@@ -297,10 +297,10 @@  _nss_nisplus_getaliasbyname_r (const char *name, struct aliasent *alias,
       return NSS_STATUS_UNAVAIL;
     }
 
-  char buf[strlen (name) + 9 + tablename_len];
+  char buf[tablename_len + 9];
   int olderr = errno;
 
-  snprintf (buf, sizeof (buf), "[name=%s],%s", name, tablename_val);
+  snprintf (buf, sizeof (buf), "[name=],%s", tablename_val);
 
   nis_result *result = nis_list (buf, FOLLOW_PATH | FOLLOW_LINKS, NULL, NULL);
```
### 0x005 {安装目录}/etc/ld.so.conf 缺失
```
遇到时候忘记记录
```
reason:
```
{安装目录}/etc/ld.so.conf 缺失
```
solution:
```
cd /etc/
touch ld.so.conf
```
### 0x006 警告
```
In file included from regex.c:67:0:
regexec.c: In function ‘check_node_accept_bytes’:
regexec.c:3856:29: error: ‘extra’ may be used uninitialized in this function [-Werror=maybe-uninitialized]
        const unsigned char *coll_sym = extra + cset->coll_syms[i];
                             ^~~~~~~~
cc1: all warnings being treated as errors
../o-iterator.mk:9: recipe for target '/root/libc/glibc-2.23/build/posix/regex.o' failed
make[2]: *** [/root/libc/glibc-2.23/build/posix/regex.o] Error 1
make[2]: Leaving directory '/root/libc/glibc-2.23/posix'
Makefile:214: recipe for target 'posix/subdir_lib' failed
make[1]: *** [posix/subdir_lib] Error 2
make[1]: Leaving directory '/root/libc/glibc-2.23'
Makefile:9: recipe for target 'all' failed
make: *** [all] Error 2
```
reason:
```
cc1: all warnings being treated as errors
警告并报错退出编译，这是由于设置了警告提示
```
solution:
```
CC="gcc -m32" CXX="g++ -m32" \
CFLAGS="-g -g3 -ggdb -gdwarf-4 -Og -Wno-error" \
CXXFLAGS="-g -g3 -ggdb -gdwarf-4 -Og" \
../configure --prefix=/path/to/install --host=i686-linux-gnu

更改CFLAGS 增加-Wno-error
```

## 0x03 End
装libc困难重重从早上装到了晚上
解决问题的能力还需要提高
过程中学到了很多解决问题的办法
见识了很多share 解决办法 帮忙解决问题的师傅

在此记录 希望能帮到你。

  [1]: http://ftp.gnu.org/gnu/glibc/glibc-2.23.tar.gz
  [2]: http://ftp.gnu.org/gnu/glibc/
  [3]: https://bugzilla.redhat.com/show_bug.cgi?id=1312963#c5
  [4]: https://patchwork.ozlabs.org/patch/780067/
  [5]: https://patchwork.ozlabs.org/patch/680578/