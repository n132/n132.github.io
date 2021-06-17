---
title: 'Angr_Examples_Baby_re'
date: 2020-02-20 22:04:52
tags: Angr
---
Know more about Angr through One challenge.
<!--more-->
# baby-re
binary:[defcon2016quals baby-re][0]
# Analysis
lots of anti-debug code in CheckSolution :`jmp .+02 ??`
IDA_python_script:
```python
buf_start=0x00000000004006EB
buf_tail=0x0000000004025E0
data=get_bytes(buf_start,buf_tail)
new_code=re.sub(r'\xeb\x02.{2}',r'\xeb\x02\x00\x00',data)
patch_bytes(buf_start,new_code)
```
...Then you would find that the func `checksolution` may be solved by Z3...So just write+run the script and wait the coming of result.

# Raw Code
```python
import angr
import time
import re
p=angr.Project("./baby-re")
sim=p.factory.simgr()
start_time=time.time()
sim.explore(find= lambda s: "The flag is" in s.posix.dumps(1))
res=sim.found[0].posix.dumps(0)
res=re.findall(r"[0-9]{10}",res)
flag=""
for x in res:
	flag+=chr(int(x))
print flag
print str(time.time()-start_time)
# ➜  C2 python exp.py
# WARNING | 2020-02-19 21:35:51,220 | angr.analyses.disassembly_utils | Your version of capstone does not support MIPS instruction groups.
# Math is hard!
# 439.322295189
```

but .. It would take too much time on some impossiblely accessful states.
we can abound all the impossible nodes by `sim.one_active.options.add(angr.options.LAZY_SOLVES)`.
# LAZY_SOLVES
```python
import re
p=angr.Project("./baby-re")
sim=p.factory.simgr()
sim.active[0].options.add(angr.options.LAZY_SOLVES)
start_time=time.time()
sim.explore(find= lambda s: "The flag is" in s.posix.dumps(1))
res=sim.found[0].posix.dumps(0)
res=re.findall(r"[0-9]{10}",res)
flag=""
for x in res:
	flag+=chr(int(x))
print flag
print str(time.time()-start_time)
# ➜  C2 python exp.py
# WARNING | 2020-02-19 22:21:47,540 | angr.analyses.disassembly_utils | Your version of capstone does not support MIPS instruction groups.
# Math is hard!
# 19.5499899387
```
439s->19s,amazing progress!
and I have noticed that we can use hooks to make it much more faster.
# hook
so I tried to imitate the [example-style-hook][2]. 
```python
import angr
import time
import re
import claripy
p=angr.Project("./baby-re",auto_load_libs=False)
flag_buf = [claripy.BVS("flag_%d" % x,32) for x in range(13)]
class do_scanf(angr.SimProcedure):
	def run(self,fmt,ptr):
		self.state.mem[ptr].dword = flag_buf[self.state.globals['idx']]
		self.state.globals['idx']+=1
p.hook_symbol('__isoc99_scanf',do_scanf(),replace=True)
sim=p.factory.simgr()
sim.active[0].globals['idx']=0;
sim.active[0].options.add(angr.options.LAZY_SOLVES)
start_time=time.time()
sim.explore(find= lambda s: "The flag is" in s.posix.dumps(1))
res=sim.found[0].posix.dumps(1)
print res[-14:]
print str(time.time()-start_time)
# WARNING | 2020-02-20 06:37:13,211 | angr.analyses.disassembly_utils | Your version of capstone does not support MIPS instruction groups.
# Math is hard!

# 11.3965950012
```
# procedure
I reset the `sim.explore` to make my script run faster (3.8s)!
`sm.explore(find=0x4028E9, avoid=0x402941)` and there is my script
```python
import angr
import time
import re
import claripy
p=angr.Project("./baby-re",auto_load_libs=False)
flag_buf = [claripy.BVS("flag_%d" % x,32) for x in range(13)]
class do_scanf(angr.SimProcedure):
	def run(self,fmt,ptr):
		self.state.mem[ptr].dword = flag_buf[self.state.globals['idx']]
		self.state.globals['idx']+=1
p.hook_symbol('__isoc99_scanf',do_scanf(),replace=True)
sim=p.factory.simgr()
sim.active[0].globals['idx']=0
sim.active[0].options.add(angr.options.LAZY_SOLVES)
start_time=time.time()
sim.explore(find=0x4028E9, avoid=0x402941)
flag=''
print str(time.time()-start_time)
for x in range(13):
	flag+=chr(sim.found[0].solver.eval(flag_buf[x]))
print flag
# ➜  C2 python eax.py
# WARNING | 2020-02-20 06:56:41,482 | angr.analyses.disassembly_utils | Your version of capstone does not support MIPS instruction groups.
# 3.53259587288
# Math is hard!
```
Generally,We can take re-challenge as differrent parts, each part can be seen as a independent logical branch.It will be much more faster to use `sim.explore(find = AddrA,avoid = AddrB)` rather than find an specific string.


# Mem_Set
However, I think it may be faster to avoid scanf.

I found it can't find the flag if I started from `p.blank_state(0x4028D9)`
I would try to fix my script after learn more about angr state/entry_state...but useless. I forgive to set the data on the stack and regs.
```python
import angr
import time
p=angr.Project("./baby-re",auto_load_libs=False)
class n132_printf(angr.SimProcedure):
	def run(self,fmt,ptr):
		self.state.rax=1
class n132_scanf(angr.SimProcedure):
	def run(self,fmt,ptr):
		self.state.rax=1
		#self.state.mem[ptr].dword=flag[self.state.globals['idx']]
		#self.state.globals['idx']+=1
class n132_fflush(angr.SimProcedure):
	def run(self,ptr):
		self.state.rax=1
p.hook_symbol("__isoc99_scanf",n132_scanf(),replace=True)
p.hook_symbol("fflush",n132_fflush(),replace=True)
p.hook_symbol("printf",n132_printf(),replace=True)

s=p.factory.entry_state()
while(s.addr!=0x0000000004028D9):
	succ=s.step()
	s=succ.successors[0]

flag = [s.solver.BVS("flag_%d"%x,32) for x in range(13)]
for x in range(13):
	s.mem[s.regs.rsp+x*4].dword=flag[x]

sim=p.factory.simgr(s)
sim.active[0].options.add(angr.options.LAZY_SOLVES)
start_time=time.time()
sim.explore(find=0x4028E9, avoid=0x402941)
print time.time()-start_time
assert len(sim.found)==1
fff=''
for x in range(13):
	fff+=chr(sim.found[0].solver.eval(flag[x]))
print fff
# WARNING | 2020-02-22 21:22:30,241 | angr.analyses.disassembly_utils | Your version of capstone does not support MIPS instruction groups.
# 3.77617692947
# Math is hard!
```  

# epilogue

The most efficient way seems to be `hook`+**start from the entry**.


[0]: https://github.com/n132/Watermalon/tree/master/Angr-examples/C2