---
title: Papers-Fuzzing
date: 2020-03-15 14:12:37
tags: Papers
---
Fuzzing: Hack, Art, and Science  (CACM 2020)
<!--more-->
# abstract
> This article presents an overview of these techniques, starting with simple techniques used in the early fuzzing days, and then progressively moving on to more sophisticated techniques. I also discuss the strengths and limita- tions of each technique.

文章主要讲的是一些概述性的内容以及一些方法，同时介绍这些方法的优势以及短板.

# Blackbox Fuzzing
> In practice, the effectiveness of blackbox random fuzzing crucially depends on a diverse set of well-formed seed inputs to start the fuzzing process. 

黑盒测试,文中举了个例子简单来说就是random产生输入...然后把输入喂给程序..能不能找到洞就看天意了.
这种形式的fuzz主要决定fuzz质量的的是seed-inputs的多样和质量.

# Grammar-Based Fuzzing

> Blackbox random fuzzing provides a simple fuzzing baseline, but its effectiveness is limited: the probability of generating new interesting inputs is low.35 This is especially true when fuzzing applications with structured input formats, like XML or JSON dialects: randomly fuzzing inputs in these formats is likely to break key structural properties of the input, which the application will quickly detect in a first lexical analysis and then discard, hence exercising little of the application code.

看完上面的黑盒测试我感觉那种依靠原始种子的方法有点玄.万一像菜单题一样输入格式有限制呢...那不是挖到明年都挖不到...然后反正我想到的问题总有人已遇到了他们就提出了一个叫做基于语法的fuzzing.

主要就是前面那种黑盒测试就像是抓瞎,产生有用的输入宛若大海捞针而且有些程序对输入是有要求的,就像是有些程序需要输入一张图片,你图片的格式总要满足一下吧.于是就有了这种基于语法的fuzzing.

这类的fuzzing也有不同的派别. 

## input grammar-based

最开始是类似于这种的(文中的figure3)
```s
1 ...
2 s_string(“POST /api/blog/ HTTP/1.2 “); 3 s_string(“Content-Length: “);
4 s_blocksize_string(“blockA”, 2);
5 s_block_start(“blockA”);
6 s_string(“{body:”);
7 s_string_variable(“XXX”);
8 s_string(“}”);
9 s_block_end(“blockA”);
10 ...
```
就是人先给写好不变的部分然后变化的部分由fuzzer产生这样就初步地解决了fuzz可能跑了半天事实上第一个if都过不去的结果
例如
```c
read(0,request,0x400);
if(!strncmp(request,"POST ",5))
{
....    
}
```
但是这种方法仔细一想不太对劲呀 这不是每个程序都需要人给他写个语法吗? 效率有点低,而且你人去分析他的程序流程这不是相当于已经动用人力去挖洞了吗...咱可是21世纪了...不能依然使用落后的人力...

## input model-based
文中说到
> in effect, the program encodes the grammar
我这里猜可能是上面那种方法被很多人用来挖洞或者盗版软件横行之后加壳流行起来.然后程序被加密了所以上面的基于语法的就不太好用了..(只是我的猜测...anyway.反正就是不好用了
然后就进化了,有了一种叫做`model-based`的模式,其中有`test generation algorithms`看名字是用来产生`test date`这种模式就是相当于我们不用去根据固定的语法结构产生测试样例了而是用样例产生算法根据已有的几个输入为`model`来产生测试样例.

> Test generation algorithms used in model-based testing often try to generate a minimum number of tests covering, every state and transition of a finite-state machine model in order to generate test suites that are as small as possible

大概就是状态是有限的你的输入只要能走到所有状态,这个样例产生算法就会高效地产生样例.我这里拿菜单题来加深理解(不知道我理解的对不对

```c
menu()
int cmd=get_cmd()
switch(cmd)
{
    case 1 :
        add();
        break;
    case 2 :
        del();
        break;
}
```
假设我输入一个 样例像是 '1\n2\n1\n' 然后就会基于我的121产生各种各样的测试样例 111 112 122 之类的说不定就撞到了一个`double-free`呢.

反正这个算法主要就是在样例产生上做了文章能做到从你的样例来更有效的产生样例,基于模型(样例),而不是基于语法.

> How to automatically learn input grammars from input samples for fuzzing purposes is another recent line of research. For instance, context-free grammars can be learned from input examples using custom generalization steps, or using a dynamic taint analysis of the program under test in order to determine how the program processes its inputs. Statistical machine-learning techniques based on neural networks can also be used to learn probabilistic input grammars.While promising, the use of machine learning for grammar-based fuzzing is still preliminary and not widely used today.

接下来这一段我感觉和我现在的听闻挺像的...就是看看各种新技术看看能不能在样例生成上有没有用武之地： `machine-learning` `neural networks` 这几个词现在还是热门哈.

对应的,文章也提及如果要从`examples`中学习就需要知道`how the program processes is inputs`

看起来确实是挺牛的，但是目前还是有挺大局限的文中给出了几个限制点.

> Unfortunately, grammar-based fuzzing is only as good as the in-put grammar being used, and writing input grammars by hand is laborious, time consuming, and error-prone. Because the process of writing grammars is so open-ended and there are so many possibilities for fuzzing rules (what and how to fuzz), when to stop editing a grammar further is another practical issue.

1. writing input grammars by hand is laborious, time consuming, and error-prone
2. when to stop editing a grammar further

大概就是说现在的"智能"还不够"智能"比较依赖人工的`input`还有就是不知道某一个方向"变"到什么时候够了.

# Whitebox Fuzzing
> Starting with a well-formed input, whitebox fuzzing14 consists of symbolically executing the program under test dynamically, gathering constraints on inputs from conditional branches encountered along the execution. The collected constraints are then systematically negated one-by-one and solved with a constraint solver, whose solutions are mapped to new inputs that exercise different program execution paths. This process is repeated using systematic search techniques that attempt to sweep through all (in practice, many) feasible execution paths of the program while checking simultaneously many properties (like buffer overflows) using a runtime checker.

这里的白盒看起来更像是结合了`symbolically execution`的fuzz.目的在于探索更多独特的路径以找到可能的漏洞。

> Whitebox fuzzing can generate inputs that exercise more code than other approaches because it is more precise.

用上了符号执行之后好处是更加精准.(还有就是路径覆盖率高
弱点也和符号执行有关就是程序不能太复杂或者一些库函数没要好好处理的话就进去出不来了.

接下来花了好几段讲SAGE我就没怎么看跳过了.

接下来介绍其他方法的我就直接list一下:
Greybox fuzzing\Hybrid fuzzing\Portfolio approaches
# conclusion 

> Is fuzzing a hack, an art, or a science? It is a bit of all three. Blackbox fuzzing is a simple hack but can be remark- ably effective in finding bugs in appli- cations that have never been fuzzed. Grammar-based fuzzing extends it to an arta form by allowing the user’s creativity and expertise to guide fuzz- ing. Whitebox fuzzing leverages ad- vances in computer science research on program verification, and explores how and when fuzzing can be math- ematically “sound and complete” in a proof-theoretic sense.


# epilogue
本文没有介绍具体设计或者细节的内容但是介绍了目前常见的tec.对目前fuzz的分类以及发展有了初步的了解.