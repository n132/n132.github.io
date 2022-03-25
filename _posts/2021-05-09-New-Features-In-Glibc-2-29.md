---
title: New_Features_In_Glibc-2.29
date: 2021-05-09 11:39:42
tags:
layout: default
---
New Features In Glibc-2.29
<!--more-->
# Prologue

好久没有做题了，快要跟不上时代了，快点学下新libc（已经旧了）的特性，相比2.27来说2.29保护加的不多。

# New Protection: Key

glibc-2.29中对tatche中的chunk增加了一个字段，key。

```cpp
//https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#2904
typedef struct tcache_entry
{
  struct tcache_entry *next;
  /* This field exists to detect double frees.  */
  struct tcache_perthread_struct *key;
} tcache_entry;
```

这个key是因为原本tcache中的 `double free`太简单了，没有任何检查。

检查相关的代码在 `_int_free` 中

```cpp
//https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#4193
#if USE_TCACHE
  {
    size_t tc_idx = csize2tidx (size);
    if (tcache != NULL && tc_idx < mp_.tcache_bins)
      {
        /* Check to see if it's already in the tcache.  */
        tcache_entry *e = (tcache_entry *) chunk2mem (p);
        /* This test succeeds on double free.  However, we don't 100%
           trust it (it also matches random payload data at a 1 in
           2^<size_t> chance), so verify it's not an unlikely
           coincidence before aborting.  */
        if (__glibc_unlikely (e->key == tcache))
          {
            tcache_entry *tmp;
            LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
            for (tmp = tcache->entries[tc_idx];
                 tmp;
                 tmp = tmp->next)
              if (tmp == e)
                malloc_printerr ("free(): double free detected in tcache 2");
            /* If we get here, it was a coincidence.  We've wasted a
               few cycles, but don't abort.  */
          }
        if (tcache->counts[tc_idx] < mp_.tcache_count)
          {
            tcache_put (p, tc_idx);
            return;
          }
      }
  }
#endif
```

流程也比较简洁，free一个chunk时看下其key是否为 `tcache` 如果是的话那就接着检查 `tcache->entries[tc_idx]` 里面有没有目前的这个chunk，有的话报错。

所以绕过也比较简单，可以通过以下两个方法。

# Bypass

出发  `malloc_printerr ("free(): double free detected in tcache 2");` 的条件有两个，如下：

1. `e->key == tcache`
2. `for (tmp = tcache->entries[tc_idx];tmp;tmp = tmp->next) if (tmp == e)`

所以要想在free的时候不会被detect可以通过修改chunk的`key` 或者 `chunk size`

具体情况不同题目有不同的方法，这里推荐可以坐下pwnable.tw的Re-alloc很有趣的一题。

# Reference

[1]: [https://zhuanlan.zhihu.com/p/136983333](https://zhuanlan.zhihu.com/p/136983333)

[2]: [https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#5611](https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#5611)