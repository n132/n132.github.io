---
title: 'Angr_Examples'
date: 2020-02-17 22:48:23
tags: Angr
---
Angr Examples
<!--more-->
# prologue
Try all the [official examples][1] to learn to use Angr.
# crackme0x00a
an easy example for Symbolic Execution.
```python
import angr
p=angr.Project("./crackme0x00a")
s=p.factory.simgr()
s.explore(find = lambda aim: "Co" in aim.posix.dumps(1))
print s.found[0].posix.dumps(0)
#output:g00dJ0B!
``` 
# r100
simple mapping of string.
```python
import angr
project = angr.Project('./r100')

@project.hook(0x400849)
def print_flag(state):
    print("F:", state.posix.dumps(0))
    project.terminate_execution()

project.execute()
```

# issue
usage of `memory.store()`
```python
import angr
import claripy
p=angr.Project("./issue")
n=claripy.BVS("n",8)
s=p.factory.entry_state(add_options={"SYMBOLIC_WRITE_ADDRESSES"})
s.memory.store(0x804a021,n)
sim=p.factory.simgr(s)
sim.explore(find=0x80484DB,avoid=0x80484ED)
print sim.found[0].solver.eval(n)
```
# baby-re
[link][3]

# very_success
It is a challenge about PE.
We need to use hooks or `memset` to avoid calling windows-api.
The most important parts are fixing the argument and  fixing the stack.
```python
import angr
import claripy
p=angr.Project('./very_success',auto_load_libs=False)
Ent=0x040105F
l=40
s=p.factory.blank_state(addr=Ent)
flag=claripy.BVS("flag",l*8)
s.memory.store(0x0402159,flag)
s.mem[s.regs.esp+8:].dword=l#len
s.mem[s.regs.esp+4:].dword=0x0402159#addr
s.mem[s.regs.esp:].dword=0x04010e4#

sim=p.factory.simgr(s)
sim.explore(find=0x040106B,avoid=0x0401072)
assert(len(sim.found)==1)
fd=sim.found[0]
print fd.solver.eval(flag,cast_to=bytes)
```

# angrybird
[link][4]

# unbreakable-enterprise-product-activation
I did not get the flag at first, I did not add `128>flag>31 ` to the solver.
```python
# ~=2s
# CTF{0The1Quick2Brown3Fox4Jumped5Over6The7Lazy8Fox9}@@@@@@@@@@@@@@@@
import angr
p=angr.Project('./UEP')
s=p.factory.blank_state(addr=0x4005BD)
flag=[s.solver.BVS("flag_%d"%x,8) for x in range(0x43)]
for x in range(0x43):
	s.mem[0x6042C0+x].byte=flag[x]
for x in flag:
	s.add_constraints(s.solver.And(x >= 32,x<=127))
sim=p.factory.simgr(s)
sim.active[0].options.add(angr.options.LAZY_SOLVES)
import time
t=time.time()
sim.explore(find=0x400724,avoid=0x400850)
print time.time()-t
print sim.found[0].solver.eval(sim.found[0].memory.load(0x6042C0,8*0x43),cast_to=bytes).strip('\0')
```
# Epilogue
Record these examples for getting familiar with angr.

[1]: https://github.com/angr/angr-doc/tree/master/Angr-examples
[3]: https://n132.github.io/2020/02/20/2020-02-20-Angry-and-Grin-I/
[4]: https://n132.github.io/2020/02/22/2020-02-22-codegate-2017-angrybird/