---
title: Driller_Part2
date: 2020-03-26 14:13:50
tags: Angr
---
经过对Driller的学习发现之前的理解不够深入,于是学习了更多相关的知识后总结一下
<!--more-->
# prelogue
Driller的第二篇,主要就driller工作的原理作更一步的理解,之前同时也发现那一篇的一些错误...懒得改了...

driller是基于angr的上篇中有需要关于一些其他库的函数没有去了解导致对整体的了解有些许偏差。

去github的 **angr** 项目下看发现其实angr并不是只有`angr/angr`一个孤立的`repositories`而是有许多其他库对`angr`以及衍生的工具起到辅助作用的，自然`driller`离不开这些库。在安装driller和angr过程中或者在开头的`import`环节就可以看到有:`tracer`,`cle`,`clar`,`pyvex`...
还有就是angr之前只是去使用它并没有去理解其源码这次会对其的`technique`部分`加大力度`.
# tracer
> This package is in a bit of a complicated transition phase - it originally housed the concolic tracing helpers for angr, but those pieces of code have since been merged into angr proper.

readme里给出的信息不多所以主要看看`driller`使用了`tracer`相关的哪些功能.于是乎我就在driller包里grep了一下发现只有`driller_main.py`使用了`tracer`主要使用了

```s
➜  driller cat * | grep tracer              
cat: __pycache__: Is a directory
import tracer
        Symbolically step down a path with a tracer, trying to concretize inputs for unencountered
        # initialize the tracer
        r = tracer.qemu_runner.QEMURunner(self.binary, self.input, argv=self.argv)
            p.simos.syscall_library.update(angr.SIM_LIBRARIES['cgcabi_tracer'])
➜  driller cat ./driller_main.py|grep "r\\."
l = logging.getLogger("driller.driller")
        # Redis channel identifier.
        # The driller core, which is now an exploration technique in angr.
        r = tracer.qemu_runner.QEMURunner(self.binary, self.input, argv=self.argv)
        p = angr.Project(self.binary)
        if p.loader.main_object.os == 'cgc':
            p.simos.syscall_library.update(angr.SIM_LIBRARIES['cgcabi_tracer'])
            s = p.factory.entry_state(stdin=angr.SimFileStream, flag_page=r.magic, mode='tracing')
            s = p.factory.full_init_state(stdin=angr.SimFileStream, mode='tracing')
        s.preconstrainer.preconstrain_file(self.input, s.posix.stdin, True)
        simgr = p.factory.simulation_manager(s, save_unsat=True, hierarchy=False, save_unconstrained=r.crash_mode)
        t = angr.exploration_techniques.Tracer(trace=r.trace, crash_addr=r.crash_addr, copy_states=True)
        self._core = angr.exploration_techniques.DrillerCore(trace=r.trace)
        simgr.use_technique(t)
        simgr.use_technique(angr.exploration_techniques.Oppologist())
        simgr.use_technique(self._core)
        self._set_concretizations(simgr.one_active)
        l.debug("Drilling into %r.", self.input)
        l.debug("Input is %r.", self.input)
        while simgr.active and simgr.one_active.globals['trace_idx'] < len(r.trace) - 1:
            simgr.step()
            print(simgr.active)
            if 'diverted' not in simgr.stashes:
            while simgr.diverted:
                state = simgr.diverted.pop(0)
            state.options.remove(angr.options.LAZY_SOLVES)
        while len(simgr.active) and accumulated < 1024:
            simgr.step()
            accumulated = steps * (len(simgr.active) + len(simgr.deadended))
        simgr.stash(from_stash='deadended', to_stash='active')
        for dumpable in simgr.active:
        if state.project.loader.main_object.os == 'cgc':
        generated = state.solver.eval(generated, cast_to=bytes)
```
1. r = tracer.qemu_runner.QEMURunner(self.binary, self.input, argv=self.argv)
2. r.magic r.crash_mode r.crash_addr
3. r.trace

其中1是创建了一个关于QEMURunner的tracer对象`r`之后使用了`r`的magic/crash_mode/crash_addr/tracer属性

其中crash_addr可以通过使用发现是如果引发crash就是crash触发的地址.

其中的`r.trace`通过查看发现是充满地址的`[list]`对比程序之后会发现是控制流图的路径。

这个`tracer`发现还是挺好用的可以直接用来复现漏洞.
```python
In [26]: for x in r.trace: 
    ...:     if(x<0x4000000000): 
    ...:         print(hex(x)) 
    ...:                                                                        
0x4003e0
0x4003c0
0x400500
0x400390
0x4003a5
0x400531
....
```
用法很简单直接将payload作为输入创建一个`QEMURunner`就行了.`r=tracer.qemu_runner.QEMURunner(binary,input,args)`
搞完tracer之后就来看看与之相关的**angr_technique**了
# angr_technique
首先得先说一下**angr_technique**同过`use_technique`来使用.
use_technique函数位于文件`sim_manager.py`中
```python
    def use_technique(self, tech):
        """
        Use an exploration technique with this SimulationManager.
        Techniques can be found in :mod:`angr.exploration_techniques`.
        :param tech:    An ExplorationTechnique object that contains code to modify
                        this SimulationManager's behavior.
        :type tech:     ExplorationTechnique
        :return:        The technique that was added, for convenience
        """
        if not isinstance(tech, ExplorationTechnique):
            raise SimulationManagerError
        # XXX: as promised
        tech.project = self._project
        tech.setup(self)
        HookSet.install_hooks(self, **tech._get_hooks())
        self._techniques.append(tech)
        return tech
```
这里可以看到主要操作就是`tech.setup(self)`+`hook`
再看看`_get_hooks`是咋样的
```python
#exploration_techniques/__init__.py#L63
    _hook_list = ('step', 'filter', 'selector', 'step_state', 'successors')

    def _get_hooks(self):
        return {name: getattr(self, name) for name in self._hook_list if self._is_overriden(name)}
```
这里看到如果有的话是可以hook掉step/successors的.
# angr/exploration_techniques/tracer.py
前面稍微使用了一下tracer现在来看看angr相关的technique[tracer.py][2].700多行我就不一一细看，主要看看setup函数。
```python
        simgr.populate('missed', [])
        simgr.populate('traced', [])
        simgr.populate('crashed', [])
```
前三行新增了3个新的stashes.
然后检查一下pic-Whether this object is position-independen 
这里采用的从头开始比是直接减如果剩下的是整页的那就当是偏移了.
```python
        for idx, addr in enumerate(self._trace):
            if self.project.loader.main_object.pic:
                if ((addr - self.project.entry) & 0xfff) == 0 and (idx == 0 or abs(self._trace[idx-1] - addr) > 0x100000):
                    break
            else:
                if addr == self.project.entry:
                    break
```
**pylint doesn't know jack shit**仿佛看到了老哥因为报错白忙了半天。

```python
        # step to entry point
        while self._trace and self._trace[idx] != simgr.one_active.addr + self._current_slide:
            simgr.step(extra_stop_points={self._trace[idx] - self._current_slide})
            if len(simgr.active) == 0:
                raise AngrTracerError("Could not step to the first address of the trace - simgr is empty")
            elif len(simgr.active) > 1:
                raise AngrTracerError("Could not step to the first address of the trace - state split")
            simgr.drop(stash='unsat')
```
step下个断点然后跑到入口点。

这里还需要注意一下`step_state`这个在会配合driller
主要就是将state放入`missed`的那部分代码其他太麻烦我也没仔细看。
```python
succs_dict['missed'] = [s for s in sat_succs if s is not succ]

succs_dict['missed'] = [s for s in succs if s is not succ]
```
succ的定义是`succ = self._pick_correct_successor(sat_succs)`这个pick函数如下
```python
#https://github.com/angr/angr/blob/d79af102c3030923d1ed1a801c0c18a1d46e6a1d/angr/exploration_techniques/tracer.py#L339
def _pick_correct_successor(self, succs):
        # there's been a branch of some sort. Try to identify which state stayed on the trace.
        assert len(succs) > 0
        idx = succs[0].globals['trace_idx']

        res = []
        for succ in succs:
            try:
                if self._compare_addr(self._trace[idx + 1], succ.addr):
                    res.append(succ)
            except AngrTracerError:
                pass
...
```
这个注释说的比较清楚了`there's been a branch of some sort. Try to identify which state stayed on the trace.`

然后结合上面的`not in`来看大致意思是找出在tracer中没有出现但是在angr的step时出现的状态标为`missed`,也就是因为一个input只能走一个branch的一条路径但是符号执行可以detect不同的路径所以将多探测到的那条标识为`missed`在后面的`driller_core`也会涉及相关内容.
# exploration_techniques/driller_core.py
比较短主要的有两个函数一个是setup一个是step
setup里面是直接保存了tracer的trace在encounters里.
step里面就有点东西了.
```python
        simgr.step(stash=stash, **kwargs)

        # Mimic AFL's indexing scheme.
        if 'missed' in simgr.stashes and simgr.missed:
        ....
```
在step之后就检查missed状态
通过对比hit（btw 简单来说bitmap是afl里面的东西用来表示当前发现的块通过比较前后的loc可以确定是否发现新的块）确定发现divert之后就添加到stash['diverted'].
```python
                cur_loc = state.addr
                cur_loc = (cur_loc >> 4) ^ (cur_loc << 8)
                cur_loc &= len(self.fuzz_bitmap) - 1

                hit = bool(self.fuzz_bitmap[cur_loc ^ prev_loc] ^ 0xff)
                ...
                ...
                 simgr.stashes['diverted'].append(state)

```
# How Driller WORKS
主要讲过程的是用shellphuzz启动的过程.

![流程](/images/Driller_procedure.png)
## driller_callback()
Shellphuzz 通过 调用Driller的回调函数driller_callback来调用driller,相关代码在Shellphuzz中
local_callback.py/driller_callback 
主要有一个类LocalCallback 以及两个函数_run_drill与main
## class LocalCallbac
### 属性
self._already_drilled_inputs : 已经drill过的input是一个set
self.num_workers : 子进程数
self._running_workers: 一个list里面放着再跑的`worker`的pid
self._worker_timeout : 默认600秒自杀时间
self._length_extension : 长度拓展,防止程序一直下不去.例如初始化输入只有4个字节。（目前根据尝试猜测的：angr认为input长度为4就没有尝试拓展就可能卡在一开始）
### 方法
kill(): 通过os.kill杀掉_running中的所有子进程。
_queue_files(): 返回list列出指定fuzzer的queue文件夹下除了.state内内容的样例 通俗点说就是queue内样例
driller_callback(): 
	1. 更新一波_running_workers
	2. 获得一波queue并去掉之中已经有worker的样例
	3. 如果还有空闲的worker且有没有被drill过的样例那就_run_drill干他。
## _run_drill
花里胡哨地设置好参数一个subprocess.Popen启动子进程调用main
## main
花里胡哨地设置好参数again然后创建driller/queue工作目录 创建driller.Driller对象之后获得新input写入文件。
## drill_generator
设置好alarm之后调用_drill_input()
## _drill_input
_drill_input可以说是核心部分其思想也很简单主要就是step()遇到divert就求解。但是其中涉及好几个问题
0. drill是如何实现识别divert的。
1. drill是每一个input都从initstate开始的吗？
2. 如果上面的问题的回答是肯定的那么如何保证drill不会每次都在第一个divert停下来？
先分析源码看看问题能不能迎刃而解。

（源码中有个`self.redis `我尝试魔改了一下源码在各个时候输出这个东西发现一直都是none不知是还未完成还是需要特殊参数或者是一个接口？之后的分析中暂时不考虑）

> Symbolically step down a path with a tracer, trying to concretize inputs for unencountered state transitions.

简介就是：这个函数通过`Symbolically step`+`tracer` 来找一些没有遇到过的状态。

简化过程如下:

1. 初始化一个tracer
2. 创建一个angr Project
3. 有指定hook的话，完成hook
4. 创建state stdin指定 mode指定
5. preconstrain stdin 为当前输入
6. 创建simulation manager
7. 使用了tracer，oppologist ,drillercore的technique.
8. 疯狂step直到发现biverted
9. 弹出state尝试求解，如果satisfied那就yield出去，之后继续尝试往后随便跑几下尝试求解有的话yield出去。
## _writeout
直接上源码
```python
    def _writeout(self, prev_addr, state):
        generated = state.posix.stdin.load(0, state.posix.stdin.pos)
        generated = state.solver.eval(generated, cast_to=bytes)

        key = (len(generated), prev_addr, state.addr)

        # Checks here to see if the generation is worth writing to disk.
        # If we generate too many inputs which are not really different we'll seriously slow down AFL.
        if self._in_catalogue(*key):
            self._core.encounters.remove((prev_addr, state.addr))
            return None

        else:
            self._add_to_catalogue(*key)

        l.debug("[%s] dumping input for %#x -> %#x.", self.identifier, prev_addr, state.addr)

        self._generated.add((key, generated))

        if self.redis:
            # Publish it out in real-time so that inputs get there immediately.
            channel = self.identifier + '-generated'

            self.redis.publish(channel, pickle.dumps({'meta': key, 'data': generated, "tag": self.tag}))

        else:
            l.debug("Generated: %s", binascii.hexlify(generated))

        return (key, generated)
```
可以看到前面几行就是一个简单的求解当前状态组成一个set:`(length,prev_addr,cur_addr)`。
之后判断是否之前已经出现过。
最后的那个redis判断(大多情况下不开redis不用管)...应该就是记录到一个数据库之类的东西。
所以可以把`_writeout`看成求解然后看看是不是之前求过了没有就返回约束求解后的值。
## _symbolic_explorer_stub
```python
    def _symbolic_explorer_stub(self, state):
        print(sys._getframe(0).f_code.co_name)
        # Create a new simulation manager and step it forward up to 1024
        # accumulated active states or steps.
        steps = 0
        accumulated = 1

        p = state.project
        state = state.copy()
        try:
            state.options.remove(angr.options.LAZY_SOLVES)
        except KeyError:
            pass
        simgr = p.factory.simulation_manager(state, hierarchy=False)

        l.debug("[%s] started symbolic exploration at %s.", self.identifier, time.ctime())

        while len(simgr.active) and accumulated < 1024:

            simgr.step()
            steps += 1

            # Dump all inputs.
            accumulated = steps * (len(simgr.active) + len(simgr.deadended))

        l.debug("[%s] stopped symbolic exploration at %s.", self.identifier, time.ctime())
        print(simgr.stashes)
        print(self.identifier)
        # DO NOT think this is the same as using only the deadended stashes. this merges deadended and active
        simgr.stash(from_stash='deadended', to_stash='active')
        for dumpable in simgr.active:
            try:
                if dumpable.satisfiable():
                    w = self._writeout(dumpable.history.bbl_addrs[-1], dumpable)
                    if w is not None:
                        yield w

            # If the state we're trying to dump wasn't actually satisfiable.
            except IndexError:
                pass
```
这个函数是copy了一份['diverted']中的state之后跑一会直到`steps * (len(simgr.active) + len(simgr.deadended))>=1024`然后尝试求解`deadended`和`active`的状态.

致此基本流程已经叙述完毕

# Tips
用的py3.7的话跑的时候一直有个collections的warning可以通过下面的fix弄好。
`https://github.com/pysmt/pysmt/pull/562/files`

# Q&A

Q: Driller 是如何识别branch的？
A: 具体的实现部分在`exploration_techniques/tracer.py`中,利用qemu的模拟执行(tracer.trace)和angr符号执行跑的结果对比，多出来的块就有可能是branch。

# epilogue
整体看下来driller单个的代码量不是特别大但是其实是集合了一套东西像是angr和tracer等这些的理解我粗粗读完一遍源码还是不够的。但是对整体运作的流程还是可以略知一二。





[1]: https://github.com/angr/angr/blob/master/angr/sim_manager.py
[2]: https://github.com/angr/angr/blob/master/angr/exploration_techniques/tracer.py

