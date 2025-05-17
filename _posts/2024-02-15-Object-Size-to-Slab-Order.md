---
title: "Kernel: Compute Slab Order from Object Size"
date: 2024-02-15 22:34:39
tags: 
layout: post
---
# Prologue

While performing page level fengshui in linux kernel, I don’t know how to get the the order number of one object.

For exmaple, we know the size of struct so we know how large the object is but we don’t know how many pages the linux kernel heap manager gonna allocate when we run out of all objects. We gonna solve this question…

# Get the answer

The short answer is `cat /proc/slabinfo` and you’ll see how many pages that a specific slab gonna use.

# How do we compute that?

It mainly depends on your CPU-core/threads numbers. If the order is not too large, Kernel tries to keep at least `4*(math.floor(log2(X))+1)` objects in one slab. For exmaple, if you have 2 cores, kernel would like to keep at lease 8 objects in the slab. And the corresponding size is the `min_objects` to compute the order:


```python
static inline unsigned int calc_slab_order(unsigned int size,
		unsigned int min_order, unsigned int max_order,
		unsigned int fract_leftover)
{
	unsigned int order;

	for (order = min_order; order <= max_order; order++) {

		unsigned int slab_size = (unsigned int)PAGE_SIZE << order;
		unsigned int rem;

		rem = slab_size % size;

		if (rem <= slab_size / fract_leftover)
			break;
	}

	return order;

```

The final order is related to other parts of the function, too much code to read and I am too lazy to understand all of them so the best way is just reset the core number of qemu and then get a mapping from core number to order of a specific size.

The source code is [here][1].

[1]: https://elixir.bootlin.com/linux/latest/C/ident/calculate_order
