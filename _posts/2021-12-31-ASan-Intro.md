---
title: Address Sanitize Intro
date: 2021-12-31 10:22:19
tags: Fuzz
layout: default
---
Address Sanitize
<!--more-->
# Prologue

The document of Address Sanitizer is amazzzzzing, this passage is personal note about the doc.

[AddressSanitizer · google/sanitizers Wiki](https://github.com/google/sanitizers/wiki/AddressSanitizer)

# Intro

It’s project from google, named `AddressSanitizer ASan`.

- Use after free / dangling pointer dereference
- Heap / Stack / Global buffer overflow
- ...

# Algorithm

Hook `malloc` and `free` in run-time. `Poising` the address around `malloc`-ed chunk and `quarantine` the `free` -ed chunks.  When accessing the memory, it would check if the address is poisoned.(This should be very fast because `ASan` calls the `IsPoisoned` function millions of times)

## Implementation

- Divide the memory into two parts: `Mem` and `Shadow`, the `shadow` documents the poisoned bytes. `MemToShadow` transforms the address to corresponding `shadow` memory and `ShadowIsPoisoned` would check if the `red zone` is modified.
- `ASan` maps 8 bytes in Mem into 1 byte in Shadow, `Shadow = (Mem >> 3) + 0x7fff8000` we have three party (`HighMem, Shadow, LowMem`)(informal)
- Report the errors by function `ReportError` : copy failure address to `rax` and get access type + size from encoded byte (instruction).

# Stack (Official Example)

```c
void foo() {
  char a[8];
  ...
  return;
}
//----------------------------------
void foo() {
  char redzone1[32];  // 32-byte aligned
  char a[8];          // 32-byte aligned
  char redzone2[24];
  char redzone3[32];  // 32-byte aligned
  int  *shadow_base = MemToShadow(redzone1);
  shadow_base[0] = 0xffffffff;  // poison redzone1
  shadow_base[1] = 0xffffff00;  // poison redzone2, unpoison 'a'
  shadow_base[2] = 0xffffffff;  // poison redzone3
  ...
  shadow_base[0] = shadow_base[1] = shadow_base[2] = 0; // unpoison all
  return;
}
```

Basically, `ASan` uses 32bytes aligned and adds `red-zone` before & after the stack variables.

(I think the reason of “32” is the alignment: 32/8=4byte in shadow.)

As we mentioned above, `SAn` would perform the check while accessing the data.

```c
 # long load8(long *a) { return *a; }
0000000000000030 <load8>:
  30:	48 89 f8             	mov    %rdi,%rax
  33:	48 c1 e8 03          	shr    $0x3,%rax
  37:	80 b8 00 80 ff 7f 00 	cmpb   $0x0,0x7fff8000(%rax)
  3e:	75 04                	jne    44 <load8+0x14>
  40:	48 8b 07             	mov    (%rdi),%rax   <<<<<< original load
  43:	c3                   	retq   
  44:	52                   	push   %rdx
  45:	e8 00 00 00 00       	callq  __asan_report_load8
//--------------------
# int  load4(int *a)  { return *a; }
0000000000000000 <load4>:
   0:	48 89 f8             	mov    %rdi,%rax
   3:	48 89 fa             	mov    %rdi,%rdx
   6:	48 c1 e8 03          	shr    $0x3,%rax
   a:	83 e2 07             	and    $0x7,%edx
   d:	0f b6 80 00 80 ff 7f 	movzbl 0x7fff8000(%rax),%eax
  14:	83 c2 03             	add    $0x3,%edx
  17:	38 c2                	cmp    %al,%dl
  19:	7d 03                	jge    1e <load4+0x1e>
  1b:	8b 07                	mov    (%rdi),%eax    <<<<<< original load
  1d:	c3                   	retq   
  1e:	84 c0                	test   %al,%al
  20:	74 f9                	je     1b <load4+0x1b>
  22:	50                   	push   %rax
  23:	e8 00 00 00 00       	callq  __asan_report_load4
```

   

`SAn` would convert `Mem` address to `Shadow` address and check the value of `Shadow` memory: 0x00 means the memory is regular memory so that the program could use it.

# Heap

`malloc` and `free` is replaced and `_asan_report_load8` is used to report the errors.

`malloc` would get a chunk with `red-zones` around it. `free` would quarantine the free-ed chunk so that the `uaf` could be detected.