---
title: "Slow Syzkalls Locator"
date: 2025-12-20 19:51:12
tags: 
layout: post
---
<!---more-->

# 📑 Prologue

When using syzkaller there are many syzkalls; we want to avoid slow ones, so we need to locate them. This post shows how to solve the following problem:

Assuming we have downloaded a corpus, we want to obtain a list of syzkalls that are slow.


# tl;dr

https://github.com/n132/slow-syzkall-locator

# 🏔️ High-level methods

The execution time of a syzkall can vary because of state or arguments. This post describes a practical approach. We don't consider arguments or state, but only try to find an approximate way to estimate how long a syzkall will take. (It's hard to get a precise time for a single call unless we modify lower-level components such as the kernel.)

- Write a program that runs syz-execprog for each syzprog and times them.
- Modify the syz-execprog source code so it measures the execution time of each program.

The first method is time-consuming since setting up the environment takes about 3 seconds. Considering the corpus usually includes more than 10K syzprogs, the first method would take too long (10,000 * 4 = 80,000 seconds, which is more than 20 hours). So I chose the second method.


# 🗡️ Modifications to syz-execprog

It's Vibe-coded and the modified syz-execprog prints the execution time of each syz program.

```diff
diff --git a/tools/syz-execprog/execprog.go b/tools/syz-execprog/execprog.go
index d243514..0b5069c 100644
--- a/tools/syz-execprog/execprog.go
+++ b/tools/syz-execprog/execprog.go
@@ -12,6 +12,7 @@ import (
 	"fmt"
 	"math/rand"
 	"os"
+	"path/filepath"
 	"runtime"
 	"strings"
 	"sync"
@@ -138,7 +139,7 @@ func main() {
 		exec |= flatrpc.ExecFlagDedupCover
 	}
 
-	progs := loadPrograms(target, flag.Args())
+	progs, progFiles := loadPrograms(target, flag.Args())
 	if *flagGlob == "" && !*flagStress && len(progs) == 0 {
 		flag.Usage()
 		os.Exit(1)
@@ -148,6 +149,7 @@ func main() {
 		target:    target,
 		done:      done,
 		progs:     progs,
+		progFiles: progFiles,
 		globs:     strings.Split(*flagGlob, ":"),
 		rs:        rand.NewSource(time.Now().UnixNano()),
 		coverFile: *flagCoverFile,
@@ -192,6 +194,7 @@ type Context struct {
 	target      *prog.Target
 	done        func()
 	progs       []*prog.Prog
+	progFiles   []string // filename for each program
 	globs       []string
 	defaultOpts flatrpc.ExecOpts
 	choiceTable *prog.ChoiceTable
@@ -208,6 +211,8 @@ type Context struct {
 	completed   atomic.Uint64
 	resultIndex atomic.Int64
 	lastPrint   time.Time
+	startTimes  sync.Map // map[*queue.Request]time.Time
+	progNames   sync.Map // map[*queue.Request]string (program filename)
 }
 
 func (ctx *Context) machineChecked(features flatrpc.Feature, syscalls map[*prog.Syscall]bool) queue.Source {
@@ -232,14 +237,21 @@ func (ctx *Context) Next() *queue.Request {
 		return req
 	}
 	var p *prog.Prog
+	var progName string
 	if ctx.stress {
 		p = ctx.createStressProg()
+		progName = "stress-generated"
 	} else {
 		idx := ctx.getProgramIndex()
 		if idx < 0 {
 			return nil
 		}
 		p = ctx.progs[idx]
+		if idx < len(ctx.progFiles) {
+			progName = ctx.progFiles[idx]
+		} else {
+			progName = fmt.Sprintf("program-%d", idx)
+		}
 	}
 	if ctx.output {
 		data := p.Serialize()
@@ -256,6 +268,9 @@ func (ctx *Context) Next() *queue.Request {
 	} else if ctx.signal || ctx.coverFile != "" {
 		req.ExecOpts.ExecFlags |= flatrpc.ExecFlagCollectSignal | flatrpc.ExecFlagCollectCover
 	}
+	// Record start time and program name for this request
+	ctx.startTimes.Store(req, time.Now())
+	ctx.progNames.Store(req, progName)
 	req.OnDone(ctx.Done)
 	return req
 }
@@ -280,6 +295,16 @@ func (ctx *Context) doneGlob(req *queue.Request, res *queue.Result) bool {
 }
 
 func (ctx *Context) Done(req *queue.Request, res *queue.Result) bool {
+	// Calculate execution time and get program name
+	var elapsed time.Duration
+	if startTime, ok := ctx.startTimes.LoadAndDelete(req); ok {
+		elapsed = time.Since(startTime.(time.Time))
+	}
+	progName := "unknown"
+	if name, ok := ctx.progNames.LoadAndDelete(req); ok {
+		progName = name.(string)
+	}
+
 	if res.Info != nil {
 		ctx.printCallResults(res.Info)
 		if ctx.hints {
@@ -289,7 +314,13 @@ func (ctx *Context) Done(req *queue.Request, res *queue.Result) bool {
 			ctx.dumpCoverage(res.Info)
 		}
 	}
+
+	// Print execution time with program name
 	completed := int(ctx.completed.Add(1))
+	ctx.logMu.Lock()
+	log.Logf(0, "program %d [%s] completed in %v", completed, progName, elapsed)
+	ctx.logMu.Unlock()
+
 	if ctx.repeat > 0 && completed >= len(ctx.progs)*ctx.repeat {
 		ctx.done()
 	}
@@ -396,13 +427,39 @@ func (ctx *Context) createStressProg() *prog.Prog {
 	return p
 }
 
-func loadPrograms(target *prog.Target, files []string) []*prog.Prog {
+func loadPrograms(target *prog.Target, files []string) ([]*prog.Prog, []string) {
 	var progs []*prog.Prog
+	var progFiles []string
 	mode := prog.NonStrict
 	if *flagUnsafe {
 		mode = prog.NonStrictUnsafe
 	}
+
+	// Expand directories to files
+	var expandedFiles []string
 	for _, fn := range files {
+		info, err := os.Stat(fn)
+		if err != nil {
+			log.Fatalf("failed to stat %v: %v", fn, err)
+		}
+		if info.IsDir() {
+			// Read all files in directory
+			entries, err := os.ReadDir(fn)
+			if err != nil {
+				log.Fatalf("failed to read directory %v: %v", fn, err)
+			}
+			for _, entry := range entries {
+				if !entry.IsDir() {
+					expandedFiles = append(expandedFiles, filepath.Join(fn, entry.Name()))
+				}
+			}
+			log.Logf(0, "found %v files in directory %v", len(entries), fn)
+		} else {
+			expandedFiles = append(expandedFiles, fn)
+		}
+	}
+
+	for _, fn := range expandedFiles {
 		if corpus, err := db.Open(fn, false); err == nil {
 			for _, rec := range corpus.Records {
 				p, err := target.Deserialize(rec.Val, mode)
@@ -410,6 +467,7 @@ func loadPrograms(target *prog.Target, files []string) []*prog.Prog {
 					continue
 				}
 				progs = append(progs, p)
+				progFiles = append(progFiles, fn)
 			}
 			continue
 		}
@@ -419,8 +477,9 @@ func loadPrograms(target *prog.Target, files []string) []*prog.Prog {
 		}
 		for _, entry := range target.ParseLog(data, mode) {
 			progs = append(progs, entry.P)
+			progFiles = append(progFiles, fn)
 		}
 	}
 	log.Logf(0, "parsed %v programs", len(progs))
-	return progs
+	return progs, progFiles
 }
```


# 🚀 Compile the tool

```sh
make -j`nproc`
sudo ./syz-execprog -executor=./syz-executor -procs=1 -repeat=1 /tmp/corpus
```

# 🎮 Extract the slow syzkalls

After obtaining the log file, we use the following script to estimate the execution time of each syzkall:

```py
#!/usr/bin/env python3
"""
Parse execprog timing log and compute per-syscall execution times.
"""
import re
from pathlib import Path
from collections import defaultdict


def parse_log_line(line: str) -> tuple[str, float] | None:
    """
    Parse a log line like:
    2025/12/20 18:51:09 program 1 [/tmp/corpus/00036251...] completed in 43.79081ms

    Returns: (filepath, time_in_seconds) or None if parsing fails
    """
    # Match pattern: program N [filepath] completed in TIME
    pattern = r'program \d+ \[([^\]]+)\] completed in ([\d.]+)(ms|µs|s)'
    match = re.search(pattern, line)
    if not match:
        return None

    filepath = match.group(1)
    time_value = float(match.group(2))
    time_unit = match.group(3)

    # Convert to seconds
    if time_unit == 'ms':
        time_seconds = time_value / 1000.0
    elif time_unit == 'µs':
        time_seconds = time_value / 1000000.0
    else:  # 's'
        time_seconds = time_value

    return filepath, time_seconds


def parse_syscalls(path: Path) -> list[str]:
    """Extract syscall names from a syzkaller program file."""
    syscalls = []
    try:
        with open(path, 'r') as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue

                # Syscalls can appear in two forms:
                # 1. With assignment: r0 = syz_init_net_socket$802154_raw(0x24, ...)
                # 2. Direct call: openat(0xffffffffffffff9c, ...)
                #                 read$dsp(r0, ...)

                # Try to match assignment form first
                match = re.match(r'^r\d+\s*=\s*([\w$]+)\s*\(', line)
                if match:
                    syscalls.append(match.group(1))
                else:
                    # Try direct call form
                    match = re.match(r'^([\w$]+)\s*\(', line)
                    if match:
                        syscalls.append(match.group(1))
    except Exception as e:
        print(f"[WARN] Failed to parse {path}: {e}")

    return syscalls


def main():
    import sys

    if len(sys.argv) < 2:
        print("Usage: ./analyze_timing.py <log_file>")
        sys.exit(1)

    log_file = Path(sys.argv[1])
    if not log_file.exists():
        print(f"Error: Log file {log_file} not found")
        sys.exit(1)

    # Parse log file
    prog_times = {}  # filepath -> time in seconds
    print(f"Parsing log file: {log_file}")

    with open(log_file, 'r') as f:
        for line in f:
            result = parse_log_line(line)
            if result:
                filepath, time_sec = result
                prog_times[filepath] = time_sec

    print(f"Found {len(prog_times)} program execution times\n")

    # Compute per-syscall times
    syscall_times = defaultdict(float)   # syscall -> total time
    syscall_counts = defaultdict(int)    # syscall -> count
    prog_results = []  # (time, filename) for ranking

    for filepath, time_sec in prog_times.items():
        path = Path(filepath)
        prog_results.append((time_sec, path.name))

        # Parse syscalls from the program file
        syscalls = parse_syscalls(path)

        if not syscalls:
            print(f"[WARN] No syscalls found in {path.name}")
            continue

        # Distribute time equally among syscalls in the program
        time_per_syscall = time_sec / len(syscalls)

        for syscall in syscalls:
            syscall_times[syscall] += time_per_syscall
            syscall_counts[syscall] += 1

    # Rank programs by execution time
    prog_results.sort()

    print("=" * 80)
    print("=== Programs ranked by execution time (fastest first) ===")
    print("=" * 80)
    for time_sec, name in prog_results[:20]:  # Show top 20
        print(f"{time_sec:10.6f} s  {name}")

    if len(prog_results) > 20:
        print(f"... and {len(prog_results) - 20} more")

    # Compute average time per syscall
    syscall_avg_times = {}
    for syscall, total_time in syscall_times.items():
        count = syscall_counts[syscall]
        syscall_avg_times[syscall] = total_time / count if count > 0 else 0

    # Rank syscalls by average time
    syscall_ranking = sorted(syscall_avg_times.items(), key=lambda x: x[1], reverse=True)

    print("\n" + "=" * 80)
    print("=== Syscalls ranked by average time (slowest first) ===")
    print("=" * 80)
    print(f"{'Syscall':<40} {'Avg Time (s)':>15} {'Count':>10} {'Total Time (s)':>15}")
    print("-" * 80)

    for syscall, avg_time in syscall_ranking:
        count = syscall_counts[syscall]
        total_time = syscall_times[syscall]
        print(f"{syscall:<40} {avg_time:>15.6f} {count:>10} {total_time:>15.6f}")

    # Summary statistics
    print("\n" + "=" * 80)
    print("=== Summary ===")
    print("=" * 80)
    print(f"Total programs analyzed: {len(prog_times)}")
    print(f"Total unique syscalls: {len(syscall_times)}")
    print(f"Total execution time: {sum(prog_times.values()):.3f} s")
    print(f"Average time per program: {sum(prog_times.values())/len(prog_times):.6f} s")


if __name__ == "__main__":
    main()
```

