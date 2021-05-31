---
layout: page
title: About
permalink: /about/
---

```python
from pwn import *
context.log_level='debug'
context.arch='male'
def whoami():
    print "I am n132"
    print "A master student in NYU(2021 Sep.->)"
p=remote("y0un9n132@gmail.com")
p.interactive("n132>>>")
```
