---
title: How do free&malloc work
date: 2021-06-26 14:53:19
tags: 
layout: default
---
How do free&malloc work
<!--more-->
# 0:

This passage is a record while analyzing the source code of glibc-2.29.

# free

*Complete errs  are shown in the next section.*

## __libc_free

`strong_alias (__libc_free, __free) strong_alias (__libc_free, free)`

- check __free_hook's value ( Jmp if NZ)
- check if mmapped (to process if Yes)
- other cases: call _int_free

## _int_free

- check *`invalid pointer`* & *`invalid size`*
- tcach process (`double free detected in tcache 2`)
- fast bin process (`invalid next size (fast)` & `double free or corruption (fasttop)` & `invalid fastbin entry (free)`)
- unsorted bin process
    - checks
        - `double free or corruption (top)`
        - `double free or corruption (out)`
        - `double free or corruption (!prev)`
        - `free(): invalid next size (normal)`
    - consolidation backward & forward (`corrupted size vs. prev_size while consolidating`)
    - link in unsorted bin (`free(): corrupted unsorted chunks`)
- check  after-consolidate-size
    - if large enough, do `malloc_consolidate`

# malloc

*Complete errs  are shown in the next section.*

## __libc_malloc

- check `__malloc_hook` ( Jmp if NZ)
- tcache process
- other cases: call `_int_malloc`

## _int_malloc

- fast bin process
    - check victim's size (`memory corruption (fast)`)
    - stash fast bin (**`No size check in this process`**)
- small bin process (if `smallbin[idx] → bk≠ itself` )
    - double link check(`smallbin double linked list corrupted`)
    - unlink victim
    - stash small bin(**`No unlink check in this process`**)
- if size > small bin max call `malloc_consolidate`
- unsorted bin process
    - check (`invalid size (unsorted)` & `invalid next size (unsorted)` & `mismatching next->prev_size (unsorted)` & `unsorted double linked list corrupted` & `invalid next->prev_inuse (unsorted)`)
    - if larger: split the last remainder and return
    - double link check`(corrupted unsorted chunks 3`)
    - if fit: stash unsorted bin and set `return_cached`=1 || return the fit one
    - if smaller: unlink unsorted bin & link into bins(**`No unlink check in this process`**)
    - if `return_cached`=1, return one `tcachechunk`
- large bin process
    - get a large bin chunk that has the same `idx`
        - if larger: split + link the remainder into unsorted bin(`corrupted unsorted chunks`)
    - get a large bin chunk that has `idx`+1,`idx`+2,`idx`+3 .... (`corrupted unsorted chunks 2`)
- use top chunk
    - check `corrupted top size`
    - split top chunk
    - if can't fit: use `sysmalloc`

# Error print list

```python
# 12 for free
malloc_printerr ("free(): invalid pointer");
malloc_printerr ("free(): invalid size");
malloc_printerr ("free(): double free detected in tcache 2");
malloc_printerr ("free(): invalid next size (fast)");
malloc_printerr ("double free or corruption (fasttop)");
malloc_printerr ("invalid fastbin entry (free)");
malloc_printerr ("double free or corruption (top)");
malloc_printerr ("double free or corruption (out)");
malloc_printerr ("double free or corruption (!prev)");
malloc_printerr ("free(): invalid next size (normal)");
malloc_printerr ("corrupted size vs. prev_size while consolidating");
malloc_printerr ("free(): corrupted unsorted chunks");
# 9 for malloc
malloc_printerr ("malloc(): memory corruption (fast)");
malloc_printerr ("malloc(): smallbin double linked list corrupted");
malloc_printerr ("malloc(): invalid size (unsorted)");
malloc_printerr ("malloc(): invalid next size (unsorted)");
malloc_printerr ("malloc(): mismatching next->prev_size (unsorted)");
malloc_printerr ("malloc(): unsorted double linked list corrupted");
malloc_printerr ("malloc(): invalid next->prev_inuse (unsorted)");
malloc_printerr ("malloc(): corrupted unsorted chunks 3");
malloc_printerr ("malloc(): corrupted unsorted chunks");
```